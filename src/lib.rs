//!
//! Two existing projects were used as inspiration for this library:
//! * [pwnat](https://github.com/samyk/pwnat) UDP tunneling between devices behind NAT without third-party
//! * [ping](https://github.com/rana/ping) Rust implementation of `ping`

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;
use anyhow::{anyhow,Result};
use bytes::{Bytes, BytesMut};
use gethostname::gethostname;
use local_ip_address::local_ip;
use log::{debug, info};
use network_types::ip::IpProto;
use zerocopy::{transmute_ref, Immutable, IntoBytes};
use crate::Role::{Initiator, Listener};

const MSG_MAX_LEN: usize = 1024;
const IPHDR_SIZE: usize = 20;
const VERSION_IHL: u8 = 0x45;
const IPDEFTTL: u8 = 64;

#[derive(Eq,PartialEq)]
pub enum Role {
    Listener,
    Initiator,
}

#[repr(C)]
#[derive(Debug,Default, IntoBytes, Immutable)]
struct IpHeader {
    version_ihl: u8,
    type_of_service: u8,
    total_length: u16,

    identification: u16,
    flags_fragment: u16,

    time_to_live: u8,
    protocol: u8,
    header_checksum: u16,

    source_address: u32,

    destination_address: u32,
}

impl IpHeader {
    pub fn as_slice(&self) -> &[u8; size_of::<IpHeader>()] {
        transmute_ref!(self)
    }
}

#[repr(C)]
#[derive(Debug,Default,IntoBytes,Immutable)]
struct IcmpBody {
    icmp_type: u8,
    icmp_code: u8,
    checksum: u16,
    identification: u16,
    sequence_number: u16,
}

impl IcmpBody {
    pub fn as_slice(&self) -> &[u8; size_of::<IcmpBody>()] {
        transmute_ref!(self)
    }
}

#[derive(Default)]
struct IcmpPacket {
    ip_header: IpHeader,
    icmp_body: IcmpBody,
}

#[derive(Debug)]
struct RawSocket {}
impl RawSocket {
    fn new() -> Self {
        RawSocket {}
    }
    fn send(&self, _buf: &[u8]) -> io::Result<usize> {
        todo!("Implement send")
    }
}

struct Client {
    id: u16,
    udp_sock: RawSocket,
    tcp_sock: RawSocket,
    connected: bool,
    keepalive: Duration,
    udp2tcp: [u8;MSG_MAX_LEN],
    udp2tcp_len: usize,
    udp2tcp_state: usize,
    tcp2udp: [u8;MSG_MAX_LEN],
    tcp2udp_len: usize,
    tcp2udp_state: usize,
    tcp2udp_timeout: Duration,
    resend_count: usize,
}

trait Ipv4AddrExt {
    fn from_str_ext(s: &str) -> Result<Ipv4Addr>;
}

impl Ipv4AddrExt for Ipv4Addr {
    fn from_str_ext(s: &str) -> Result<Ipv4Addr> {
        Ipv4Addr::from_str(s).map_err(|e| anyhow!("{e}: {s:?}"))
    }
}

pub fn udp_puncher(role: Role) -> Result<()> {
    info!("UDP-puncher");
    debug!("MSG_MAX_LEN: {MSG_MAX_LEN:?}");
    let fake_addr = Ipv4Addr::from_str_ext("3.3.3.3")?;
    let _port = "2222";
    let host = gethostname().into_string().map_err(|e|anyhow!("{:?}", e))?;
    debug!("Host: {host:?}");
    let host_ip = local_ipv4()?;
    debug!("Host IP: {host_ip:?}");

    let (src_addr, dest_addr) = match role {
        Listener => (fake_addr, Ipv4Addr::from(0u32)),
        Initiator => (host_ip, fake_addr),
    };


    let _clients: Vec<Client> = Vec::new();
    let rsrc = host_ip;
    debug!("Rsrc: {:?}, {:?}", &rsrc, &host);


    let listen_socket = RawSocket::new();
    debug!("List socket: {listen_socket:?}");

    let icmp_socket = RawSocket::new();
    debug!("ICMP socket: {icmp_socket:?}");

    let interval = Duration::from_millis(5000);

    loop {
        send_icmp(&icmp_socket, &rsrc, src_addr, dest_addr, Listener)?;
        std::thread::sleep(interval);
    }
}

fn local_ipv4() -> Result<Ipv4Addr> {
    let ip = local_ip()?;
    if let IpAddr::V4(ipv4_addr) = ip {
        return Ok(ipv4_addr);
    }
    Err(anyhow!("Not an IPv4 address: {ip:?}"))
}

fn send_icmp(socket: &RawSocket, rsrc: &Ipv4Addr, dest_addr: Ipv4Addr, src_addr: Ipv4Addr, role: Role) -> Result<()> {
    debug!("Sending ICMP packet: {rsrc:?} -> {dest_addr:?}");
    let mut packet_length = size_of::<IcmpPacket>() as u16;
    if role != Listener {
        packet_length *= 2;
    }
    let mut icmp_packet: IcmpPacket = Default::default();
    icmp_packet.ip_header.version_ihl = VERSION_IHL;
    icmp_packet.ip_header.type_of_service = 0;
    icmp_packet.ip_header.total_length = htons(packet_length);
    icmp_packet.ip_header.identification = htons(1); // kernel sets proper value htons(ip_id_counter);
    icmp_packet.ip_header.flags_fragment = 0;
    icmp_packet.ip_header.time_to_live = IPDEFTTL;
    icmp_packet.ip_header.protocol = IpProto::Icmp as u8;
    icmp_packet.ip_header.header_checksum = 0;
    icmp_packet.ip_header.source_address = htonl(rsrc.to_bits());
    icmp_packet.ip_header.destination_address = htonl(dest_addr.to_bits());

    let header_checksum = check_sum(icmp_packet.ip_header.as_bytes());
    debug!("Header checksum: {:#4X}", header_checksum);
    icmp_packet.ip_header.header_checksum = htons(header_checksum);

    let header = icmp_packet.ip_header.as_bytes();

    icmp_packet.icmp_body.icmp_type = match role {
        Listener => 8,  // ICMP echo request
        Initiator => 11, // ICMP time exceeded
    };

    icmp_packet.icmp_body.icmp_code = 0;
    icmp_packet.icmp_body.identification = 0;
    icmp_packet.icmp_body.sequence_number = 0;
    icmp_packet.icmp_body.checksum = 0;

    let mut body = BytesMut::with_capacity(packet_length as usize - size_of::<IpHeader>());
    let body_bytes = icmp_packet.icmp_body.as_bytes();
    body.extend_from_slice(body_bytes.as_ref());
    let mut more_body_bytes = BytesMut::with_capacity(size_of::<IcmpPacket>());

    if role == Initiator {
        debug!("Create fake original: {dest_addr:?} -> {src_addr:?}");
        let mut fake_original: IcmpPacket = Default::default();
        fake_original.ip_header.version_ihl = VERSION_IHL;
        fake_original.ip_header.type_of_service = 0;
        fake_original.ip_header.total_length = htons((size_of::<IcmpPacket>() as u16) << 8);
        fake_original.ip_header.identification = htons(1); // kernel sets proper value htons(ip_id_counter);
        fake_original.ip_header.flags_fragment = 0;
        fake_original.ip_header.time_to_live = 1; // real TTL would be 1 on a time exceeded packet
        fake_original.ip_header.protocol = IpProto::Icmp as u8;
        fake_original.ip_header.header_checksum = 0; // maybe the kernel helps us out..?
        fake_original.ip_header.source_address = htonl(dest_addr.to_bits());
        fake_original.ip_header.destination_address = htonl(src_addr.to_bits());

        fake_original.icmp_body.icmp_type = 8;  // ICMP echo request
        fake_original.icmp_body.icmp_code = 0;
        fake_original.icmp_body.identification = 0;
        fake_original.icmp_body.sequence_number = 0;
        fake_original.icmp_body.checksum = 0;
        let (header_checksum, body_checksum) = {
            let fake_original_header = fake_original.ip_header.as_bytes();
            let fake_original_body = fake_original.icmp_body.as_bytes();
            (check_sum(fake_original_header), check_sum(fake_original_body))
        };
        debug!("Fake original checksums: [ header: {header_checksum:#4X}, body: {body_checksum:#4X} ]");
        fake_original.ip_header.header_checksum = htons(header_checksum);
        fake_original.icmp_body.checksum = htons(body_checksum);
        more_body_bytes.extend_from_slice(fake_original.ip_header.as_bytes());
        more_body_bytes.extend_from_slice(fake_original.icmp_body.as_bytes());
        body.extend_from_slice(&more_body_bytes);
    }
    let body_checksum = check_sum(body.as_ref());
    debug!("body checksum: {:#4X}", body_checksum);
    icmp_packet.icmp_body.checksum = htons(body_checksum);

    let mut body = BytesMut::with_capacity(packet_length as usize - size_of::<IpHeader>());
    body.extend_from_slice(icmp_packet.icmp_body.as_bytes());
    body.extend_from_slice(&more_body_bytes);

    let mut message = BytesMut::with_capacity(packet_length as usize);
    message.extend_from_slice(header.as_ref());
    message.extend_from_slice(body.as_ref());
    let message = message.freeze();
    debug("Sending ICMP packet", &message);
    let signature = ((header_checksum as u32) << 16) | body_checksum as u32;
    socket.send(message.as_ref()).map_err(|e| anyhow!("Error sending {signature:#8X}: {e}"))?;
    Ok(())
}

fn debug<S: Into<String>>(label: S, bytes: &Bytes) {
    let buf = bytes.as_ref();
    let mut iter = buf.iter();
    let mut cursor = 0;
    let mut end = false;
    debug!("{}: [", label.into());
    loop {
        let mut line = format!("  {cursor:#4X}:");
        for _ in 0..16 {
            if let Some(byte) = iter.next() {
                let part = format!(" {byte:02X}");
                line.push_str(&part);
                cursor += 1;
            } else {
                end = true;
                break;
            }
        }
        debug!("{}", line);
        if end {
            break;
        }
    }
    debug!("]");
}

fn check_sum(packet_bytes: &[u8]) -> u16 {
    let mut  it = packet_bytes.into_iter();
    let mut sum = 0;
    loop {
        if let Some(msb) = it.next() {
            if let Some(lsb) = it.next() {
                let short: u16 = ((msb.clone() as u16) << 8) + lsb.clone() as u16;
                sum += short;
                continue;
            }
        }
        break;
    }
    sum ^ 0xFFFF
}

/// Converts a value from host byte order to network byte order.
#[inline]
fn htons(hostshort: u16) -> u16 {
    hostshort.to_be()
}
/// Converts a value from host byte order to network byte order.
#[inline]
fn htonl(hostlong: u32) -> u32 {
    hostlong.to_be()
}
