//!
//! Two existing projects were used as inspiration for this library:
//! * [pwnat](https://github.com/samyk/pwnat) UDP tunneling between devices behind NAT without third-party
//! * [ping](https://github.com/rana/ping) Rust implementation of `ping`

use std::mem;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;
use anyhow::{anyhow,Result};
use bytes::{Bytes, BytesMut};
use errno::errno;
use gethostname::gethostname;
use local_ip_address::local_ip;
use log::{debug, info};
use network_types::ip::IpProto;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use zerocopy::{Immutable, IntoBytes};
use crate::Role::{Initiator, Listener};

const MSG_MAX_LEN: usize = 1024;
const VERSION_IHL: u8 = 0x45;
const IPDEFTTL: u8 = 64;

#[derive(Eq,PartialEq)]
pub enum Role {
    Listener,
    Initiator(Vec<String>),
}

impl Role {
    fn code(&self) -> String {
        match self {
            Listener => "listener".to_string(),
            Initiator(_) => "initiator".to_string(),
        }
    }
    fn interval(&self) -> Duration {
        match self {
            Listener => Duration::from_millis(5100),
            Initiator(_) => Duration::from_millis(4900),
        }
    }
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

#[repr(C)]
#[derive(Debug,Default,IntoBytes,Immutable)]
struct IcmpBody {
    icmp_type: u8,
    icmp_code: u8,
    checksum: u16,
    identification: u16,
    sequence_number: u16,
}

#[derive(Default)]
struct IcmpPacket {
    ip_header: IpHeader,
    icmp_body: IcmpBody,
}

struct Peer {
    id: u16,
    udp_sock: Socket,
    tcp_sock: Socket,
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
    let role_code = role.code();
    info!("{role_code}: UDP-puncher");
    debug!("{role_code}: MSG_MAX_LEN: {MSG_MAX_LEN:?}");
    let fake_ip = Ipv4Addr::from_str_ext("3.3.3.3")?;
    let _port = "2222";
    let host = gethostname().into_string().map_err(|e|anyhow!("{:?}", e))?;
    debug!("{role_code}: Host: {host:?}");

    let _peers: Vec<Peer> = Vec::new();

    let source_ip = local_ipv4()?;
    debug!("{role_code}: Source IP: {source_ip:?}, {host:?}");

    let listen_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    debug!("{role_code}: Listen socket FD: {:?}", listen_socket.as_raw_fd());

    let interval = role.interval();

    let raw_protocol = Protocol::from(255);
    let icmp_socket = Socket::new(Domain::IPV4, Type::RAW, Some(raw_protocol))?;
    icmp_socket.set_read_timeout(Some(interval))?;
    debug!("{role_code}: ICMP socket FD: {:?}", icmp_socket.as_raw_fd());

    if let Initiator(remotes) = role {
        let mut remote_ips = vec![];
        for remote in remotes {
            remote_ips.push(Ipv4Addr::from_str(&remote)?)
        }
        loop {
            for remote_ip in &remote_ips {
                debug!("{role_code}: remote_ip: {remote_ip:?}");
                send_icmp(&icmp_socket, &source_ip, *remote_ip, Some(fake_ip))?;
            }
            sleep(interval);
        }
    } else {
        loop {
            send_icmp(&icmp_socket, &source_ip, fake_ip, None)?;
            receive_connection(&icmp_socket)?;
        }
    }
}

fn local_ipv4() -> Result<Ipv4Addr> {
    let ip = local_ip()?;
    if let IpAddr::V4(ipv4_addr) = ip {
        return Ok(ipv4_addr);
    }
    Err(anyhow!("Not an IPv4 address: {ip:?}"))
}

fn send_icmp(socket: &Socket, source: &Ipv4Addr, destination: Ipv4Addr, fake: Option<Ipv4Addr>) -> Result<()> {
    let label = if fake.is_some() {
        format!("initiator({destination})")
    } else {
        "listener".to_string()
    };
    debug!("{label}: Sending ICMP packet: {source:?} -> {destination:?}");
    let mut packet_length = size_of::<IcmpPacket>() as u16;
    if fake.is_some() {
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
    icmp_packet.ip_header.source_address = htonl(source.to_bits());
    icmp_packet.ip_header.destination_address = htonl(destination.to_bits());

    let header_checksum = check_sum(icmp_packet.ip_header.as_bytes());
    debug!("{label}: Header checksum: {:#4X}", header_checksum);
    icmp_packet.ip_header.header_checksum = htons(header_checksum);

    let header = icmp_packet.ip_header.as_bytes();

    icmp_packet.icmp_body.icmp_type = if fake.is_none() {
        8  // ICMP echo request
    } else {
        11 // ICMP time exceeded
    };

    icmp_packet.icmp_body.icmp_code = 0;
    icmp_packet.icmp_body.identification = 0;
    icmp_packet.icmp_body.sequence_number = 0;
    icmp_packet.icmp_body.checksum = 0;

    let mut body = BytesMut::with_capacity(packet_length as usize - size_of::<IpHeader>());
    let body_bytes = icmp_packet.icmp_body.as_bytes();
    body.extend_from_slice(body_bytes.as_ref());
    let mut more_body_bytes = BytesMut::with_capacity(size_of::<IcmpPacket>());

    if let Some(fake_ip) = fake {
        debug!("{label}: Create fake original: {destination:?} -> {fake:?}");
        let mut fake_original: IcmpPacket = Default::default();
        fake_original.ip_header.version_ihl = VERSION_IHL;
        fake_original.ip_header.type_of_service = 0;
        fake_original.ip_header.total_length = htons((size_of::<IcmpPacket>() as u16) << 8);
        fake_original.ip_header.identification = htons(1); // kernel sets proper value htons(ip_id_counter);
        fake_original.ip_header.flags_fragment = 0;
        fake_original.ip_header.time_to_live = 1; // real TTL would be 1 on a time exceeded packet
        fake_original.ip_header.protocol = IpProto::Icmp as u8;
        fake_original.ip_header.header_checksum = 0; // maybe the kernel helps us out..?
        fake_original.ip_header.source_address = htonl(destination.to_bits());
        fake_original.ip_header.destination_address = htonl(fake_ip.to_bits());

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
        debug!("{label}: Fake original checksums: [ header: {header_checksum:#4X}, body: {body_checksum:#4X} ]");
        fake_original.ip_header.header_checksum = htons(header_checksum);
        fake_original.icmp_body.checksum = htons(body_checksum);
        more_body_bytes.extend_from_slice(fake_original.ip_header.as_bytes());
        more_body_bytes.extend_from_slice(fake_original.icmp_body.as_bytes());
        body.extend_from_slice(&more_body_bytes);
    }
    let body_checksum = check_sum(body.as_ref());
    debug!("{label}: body checksum: {:#4X}", body_checksum);
    icmp_packet.icmp_body.checksum = htons(body_checksum);

    let mut body = BytesMut::with_capacity(packet_length as usize - size_of::<IpHeader>());
    body.extend_from_slice(icmp_packet.icmp_body.as_bytes());
    body.extend_from_slice(&more_body_bytes);
    debug!("{label}: Verify body checksum: {:#4X}", check_sum(body.as_ref()));

    let mut message = BytesMut::with_capacity(packet_length as usize);
    message.extend_from_slice(header.as_ref());
    message.extend_from_slice(body.as_ref());
    let message = message.freeze();
    debug(label + ": Sending ICMP packet", &message);
    let signature = ((header_checksum as u32) << 16) | body_checksum as u32;
    let sock_addr_v4 = SocketAddrV4::new(destination, 2222);
    let sock_addr = SockAddr::from(sock_addr_v4);
    socket.send_to(message.as_ref(), &sock_addr).map_err(|e| anyhow!("Error sending {signature:#8X}: {e}"))?;
    Ok(())
}

fn receive_connection(socket: &Socket) -> Result<()> {
    let mut maybe_uninit: [MaybeUninit<u8>; MSG_MAX_LEN] = [const { MaybeUninit::uninit() }; MSG_MAX_LEN ];
    let size = socket.recv(& mut maybe_uninit);
    match size {
        Ok(size) => {
            debug!("listener: Received ICMP packet");
            if size > 0 {
                unsafe {
                    let buffer = mem::transmute::<_, [u8; MSG_MAX_LEN]>(maybe_uninit);
                    let mut bytes = BytesMut::new();
                    bytes.extend_from_slice(&buffer[1..size]);
                    debug("listener: Received ICMP packet", &bytes.freeze());
                }
            }
            Ok(())
        },
        Err(e) => {
            let err = errno().0;
            if err == 11 {
                debug!("No packet");
                Ok(())
            } else {
                Err(anyhow!("Error receiving ICMP packet: {e}: {err}"))
            }
        }
    }
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
    let mut sum = 0u32;
    loop {
        if let Some(msb) = it.next() {
            if let Some(lsb) = it.next() {
                let short: u16 = ((msb.clone() as u16) << 8) + lsb.clone() as u16;
                sum += short as u32;
                continue;
            }
        }
        break;
    }
    let ones_complement = (sum & 0xFFFF) + (sum >> 16);
    (ones_complement ^ 0xFFFF) as u16
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
