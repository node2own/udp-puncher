//!
//! Two existing projects were used as inspiration for this library:
//! * [pwnat](https://github.com/samyk/pwnat) UDP tunneling between devices behind NAT without third-party
//! * [ping](https://github.com/rana/ping) Rust implementation of `ping`

use std::io;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::{anyhow,Result};
use gethostname::gethostname;
use log::{debug, info};
use mio::event::Source;
use mio::{Interest as InterestMio, Registry, Token};
use mio::unix::SourceFd;
use socket2::{Socket, Domain, Type, Protocol};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time;

const MSG_MAX_LEN: usize = 1024;

struct Client {
    id: u16,
    udp_sock: UdpSocket,
    tcp_sock: TcpStream,
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

pub async fn udp_puncher() -> Result<()> {
    info!("UDP-puncher");
    debug!("MSG_MAX_LEN: {MSG_MAX_LEN:?}");
    let dest_addr = UdpSocket::bind("3.3.3.3:0").await?;
    let port = "2222";
    let host = gethostname().into_string().map_err(|e|anyhow!("{:?}", e))?;

    let mut clients: Vec<Client> = Vec::new();
    let address_string = host + ":" + port;
    let rsrc = UdpSocket::bind(address_string.clone()).await?;
    debug!("Listening on UDP: {:?}, {:?}", &rsrc, &address_string);

    let udp_from = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    let listen_socket = IcmpSocketTokio::new()?;
    debug!("List socket: {listen_socket:?}");

    let raw_protocol = Protocol::from(255);
    let icmp_socket = IcmpSocketMio::new(Some(raw_protocol))?;
    debug!("ICMP socket: {icmp_socket:?}");

    let mut periodic = time::interval(Duration::from_millis(5000));

    loop {
        tokio::select! {
            _ = periodic.tick() => {
                debug!("periodic tick");
                send_icmp(&icmp_socket).await;
            }
        }
    }
}

async fn send_icmp(_socket: &IcmpSocketMio) {
    debug!("Sending ICMP packet");
}

/// An ICMP socket used with low-level `mio` events.
///
/// Modeled on [mio::UdpSocket](https://github.com/tokio-rs/mio/blob/4b42d28ddcaa461811aa2effb4d63be302d1a3d7/src/net/udp.rs#L91).
///
/// See [RFC 792](https://www.rfc-editor.org/rfc/rfc792.html) for more details about ICMP.
#[derive(Debug)]
pub struct IcmpSocketMio {
    sck: Socket,
}

impl IcmpSocketMio {
    /// `new` creates an IcmpSocketMio.
    ///
    /// `new` creates a raw system socket which is non-blocking.
    ///
    /// Calling `new` requires root permission for the
    /// raw network capability `CAP_NET_RAW` to open a raw socket.
    ///
    /// `new` returns a "no permission" error if `CAP_NET_RAW` is unavailable.
    pub fn new(protocol: Option<Protocol>) -> io::Result<Self> {
        let sck = Socket::new(Domain::IPV4, Type::RAW, protocol)?;

        // Set non-blocking before connect()
        sck.set_nonblocking(true)?;

        Ok(Self { sck: sck })
    }

    /// Connect the ICMP socket with a destination IPv4 address.
    ///
    /// Used by the `send` and `recv` functions.
    pub fn connect(&self, ip: Ipv4Addr) -> io::Result<()> {
        // Create a socket address
        let adr = SocketAddr::new(IpAddr::V4(ip), 0);

        self.sck.connect(&adr.into())
    }

    /// Send data to the socket and remote address.
    ///
    /// Ensure `connect` was called once before calling `send`.
    ///
    /// Returns the number of bytes sent; or, an error.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.sck.send(buf)
    }

    /// Receive data from the socket and remote address.
    ///
    /// Ensure `connect` was called once before calling `recv`.
    ///
    /// Returns the number of bytes received; or, an error.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // Simper to call `read` than `recv`.
        // `recv` requires cumbersome, unsafe casting with MaybeUninit.
        (&self.sck).read(buf)

        // Avoid using ugly MaybeUninit with `recv`
        // let buf2 = &mut [0u8; PKT_BUF_SIZE];
        // let buf3 = unsafe { buf2 as *mut [u8] };
        // let buf4 = unsafe { buf3 as *mut [MaybeUninit<u8>] };
        // let buf5 = unsafe { &mut *buf4 };
    }
}

// Implement Source for the `mio` crate.
impl Source for IcmpSocketMio {
    fn register(&mut self, poll: &Registry, token: Token, interest: InterestMio) -> io::Result<()> {
        SourceFd(&self.as_raw_fd()).register(poll, token, interest)
    }

    fn reregister(
        &mut self,
        poll: &Registry,
        token: Token,
        interest: InterestMio,
    ) -> io::Result<()> {
        SourceFd(&self.as_raw_fd()).reregister(poll, token, interest)
    }

    fn deregister(&mut self, poll: &Registry) -> io::Result<()> {
        SourceFd(&self.as_raw_fd()).deregister(poll)
    }
}

// Implement AsRawFd for the `mio` crate.
impl AsRawFd for IcmpSocketMio {
    fn as_raw_fd(&self) -> RawFd {
        self.sck.as_raw_fd()
    }
}

/// An ICMP socket used with `tokio` events.
#[derive(Debug,Clone)]
pub struct IcmpSocketTokio {
    sck: Arc<AsyncFd<IcmpSocketMio>>,
}

impl IcmpSocketTokio {
    /// `new` creates an IcmpSocketTokio.
    ///
    /// `new` creates a raw system socket which is non-blocking.
    ///
    /// Calling `new` requires root permission for the
    /// raw network capability `CAP_NET_RAW` to open a raw socket.
    ///
    /// `new` returns a "no permission" error if `CAP_NET_RAW` is unavailable.
    pub fn new() -> io::Result<Self> {
        let mio_sck = IcmpSocketMio::new(Some(Protocol::ICMPV4))?;
        let fd_mio_sck = AsyncFd::new(mio_sck)?;
        Ok(Self {
            sck: Arc::new(fd_mio_sck),
        })
    }

    /// Connect the ICMP socket with a destination IPv4 address.
    ///
    /// Used by the `send` and `recv` functions.
    ///
    /// Pattern based on [tokio::net::UdpSocket.connect](https://github.com/tokio-rs/tokio/blob/b31f1a4662e708596fe9cd89853a153b62ec056b/tokio/src/net/udp.rs#L339).
    pub async fn connect(&self, ip: Ipv4Addr) -> io::Result<()> {
        self.sck.get_ref().connect(ip)
    }

    /// Send data to the socket and remote address.
    ///
    /// Ensure `connect` was called once before calling `send`.
    ///
    /// Returns the number of bytes sent; or, an error.
    ///
    /// Pattern is based on [tokio::net::UdpSocket.send](https://github.com/tokio-rs/tokio/blob/b31f1a4662e708596fe9cd89853a153b62ec056b/tokio/src/net/udp.rs#L556).
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.sck
            .async_io(Interest::WRITABLE, |sck| sck.send(buf))
            .await
    }

    /// Receive data from the socket and remote address.
    ///
    /// Ensure `connect` was called once before calling `recv`.
    ///
    /// Returns the number of bytes received; or, an error.
    ///
    /// Pattern is based on [tokio::net::UdpSocket.recv](https://github.com/tokio-rs/tokio/blob/b31f1a4662e708596fe9cd89853a153b62ec056b/tokio/src/net/udp.rs#L776).
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.sck
            .async_io(Interest::READABLE, |sck| sck.recv(buf))
            .await
    }

    /// Send a ping echo message.
    pub async fn send_ping(&self, id: u16, seq: u16) -> io::Result<SeqTme> {
        let buf_tx = create_echo_pkt(id, seq);

        let res = match self
            .sck
            .async_io(Interest::WRITABLE, |sck| sck.send(&buf_tx))
            .await
        {
            Err(e) => Err(e),
            Ok(cnt_tx) => {
                let tme = Instant::now();
                assert_eq!(cnt_tx, PKT_BUF_SIZE);
                Ok(SeqTme { seq, tme })
            }
        };

        res
    }

    /// Receive a ping echo reply message.
    pub async fn recv_ping(&self) -> io::Result<SeqTme> {
        let mut buf_rx = [0u8; PKT_BUF_SIZE];

        let res = match self
            .sck
            .async_io(Interest::READABLE, |sck| sck.recv(&mut buf_rx))
            .await
        {
            Err(e) => Err(e),
            Ok(cnt_rx) => {
                let tme = Instant::now();
                let seq = read_seq_from_echo_pkt(buf_rx);
                assert_eq!(cnt_rx, PKT_BUF_SIZE);
                Ok(SeqTme { seq, tme })
            }
        };

        res
    }
}

/// A ping sequence number and time.
#[derive(Debug)]
pub struct SeqTme {
    seq: u16,
    tme: Instant,
}

/// An ICMP header type indicating the message is an Echo request.
const HDR_TYP_ECHO: u8 = 8;
/// An ICMP header configuration indicating the Echo message contains an id and sequence number.
const HDR_CFG_ECHO: u8 = 0;
/// The size of an ICMP packet buffer in bytes.
///
/// The buffer is header-only, and doesn't have a payload.
const PKT_BUF_SIZE: usize = 28;
/// An echo packet identifier.
const PKT_ID: u16 = 1;

/// Writes an ICMP message header checksum.
///
/// See [RFC 792](https://datatracker.ietf.org/doc/html/rfc792) for details.
//
// From https://github.com/jcgruenhage/tokio-icmp-echo/blob/e7d7b0b113c659f29d03d0533eec04d27384e153/src/packet/icmp.rs
// TODO: SWITCH TO PUBLIC CRATE FOR IP CHECKSUM
fn write_checksum(buf: &mut [u8]) {
    let mut sum = 0u32;
    for word in buf.chunks(2) {
        let mut part = u16::from(word[0]) << 8;
        if word.len() > 1 {
            part += u16::from(word[1]);
        }
        sum = sum.wrapping_add(u32::from(part));
    }

    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    let sum = !sum as u16;

    buf[2] = (sum >> 8) as u8;
    buf[3] = (sum & 0xff) as u8;
}

/// Create an echo request packet.
pub fn create_echo_pkt(id: u16, seq: u16) -> [u8; PKT_BUF_SIZE] {
    // Create an echo message
    let mut buf = [0u8; PKT_BUF_SIZE];
    buf[0] = HDR_TYP_ECHO;
    buf[1] = HDR_CFG_ECHO;
    // buf[2] will contain the checksum
    // buf[3] will contain the checksum
    buf[4] = (id >> 8) as u8;
    buf[5] = id as u8;
    buf[6] = (seq >> 8) as u8;
    buf[7] = seq as u8;
    // Payload is intentionally empty

    // Write the message header's checksum
    write_checksum(&mut buf);

    buf
}

/// Reads the sequence number from the echo reply message buffer.
pub fn read_seq_from_echo_pkt(buf: [u8; PKT_BUF_SIZE]) -> u16 {
    let a = unsafe { *(buf[26..].as_ptr() as *const [u8; 2]) };
    u16::from_be_bytes(a)
}
