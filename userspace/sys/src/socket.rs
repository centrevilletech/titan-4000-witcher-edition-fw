//! Sockets std cannot open: `AF_PACKET` control and send sockets, an unbound
//! IPv6 datagram socket that only holds multicast memberships, and a raw
//! ICMPv6 socket. `SocketExt` adds the socket options the keeper sets to any
//! socket, std's included.

use std::io;
use std::mem;
use std::net::Ipv6Addr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::ptr;

use libc::{c_int, sock_filter};

use crate::{cvt, cvt_len};

/// `sll_pkttype` of a frame this host sent (`PACKET_OUTGOING`).
const PACKET_OUTGOING: u8 = 4;

/// An open socket, closed when dropped.
#[derive(Debug)]
pub struct Socket(OwnedFd);

/// Where a received frame came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkPeer {
    packet_type: u8,
    address_len: u8,
    address: [u8; 8],
}

impl LinkPeer {
    /// The frame is one this host sent (`PACKET_OUTGOING`).
    pub fn outgoing(&self) -> bool {
        self.packet_type == PACKET_OUTGOING
    }

    /// The frame's Ethernet source, when the link address is one.
    pub fn mac(&self) -> Option<[u8; 6]> {
        (self.address_len >= 6).then(|| {
            let mut mac = [0; 6];
            mac.copy_from_slice(&self.address[..6]);
            mac
        })
    }
}

impl Socket {
    /// `socket(2)`, with any `SOCK_*` flags in `kind`.
    fn open(domain: c_int, kind: c_int, protocol: c_int) -> io::Result<Self> {
        // SAFETY: `socket` takes only integers and returns a new descriptor or -1.
        let fd = cvt(unsafe { libc::socket(domain, kind, protocol) })?;
        // SAFETY: `fd` was just returned by `socket`, so it is open and nothing else owns it.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self(owned))
    }

    /// A non-blocking `AF_PACKET` `SOCK_DGRAM` socket for protocol 0. It
    /// receives nothing until `bind_link` names one EtherType, so it never
    /// taps all traffic, and the kernel writes the Ethernet header of what it
    /// sends.
    pub fn packet_datagram() -> io::Result<Self> {
        Self::open(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    }

    /// A blocking `AF_PACKET` `SOCK_RAW` socket for protocol 0, which sends
    /// frames that carry their own Ethernet header.
    pub fn packet_raw() -> io::Result<Self> {
        Self::open(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0)
    }

    /// An unbound `AF_INET6` datagram socket.
    pub fn ipv6_datagram() -> io::Result<Self> {
        Self::open(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0)
    }

    /// A raw ICMPv6 socket, closed across `exec` like the others.
    pub fn icmpv6_raw() -> io::Result<Self> {
        Self::open(libc::AF_INET6, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::IPPROTO_ICMPV6)
    }

    /// Receive only EtherType `protocol` from interface `ifindex`.
    pub fn bind_link(&self, ifindex: i32, protocol: u16) -> io::Result<()> {
        let address = link_address(ifindex, protocol, None);
        // SAFETY: `address` is a live `sockaddr_ll` and the length passed is its size.
        let rc = unsafe {
            libc::bind(
                self.0.as_raw_fd(),
                ptr::from_ref(&address).cast(),
                length_of::<libc::sockaddr_ll>(),
            )
        };
        cvt(rc).map(drop)
    }

    /// Bind to `address` on the link `scope_id` names.
    pub fn bind_ipv6(&self, address: Ipv6Addr, scope_id: u32) -> io::Result<()> {
        let address = ipv6_address(address, scope_id);
        // SAFETY: `address` is a live `sockaddr_in6` and the length passed is its size.
        let rc = unsafe {
            libc::bind(
                self.0.as_raw_fd(),
                ptr::from_ref(&address).cast(),
                length_of::<libc::sockaddr_in6>(),
            )
        };
        cvt(rc).map(drop)
    }

    /// Receive one frame into `buf`: how many bytes were copied (a longer
    /// frame is cut short) and where it came from. An empty non-blocking
    /// socket returns `ErrorKind::WouldBlock`.
    pub fn recv_link(&self, buf: &mut [u8]) -> io::Result<(usize, LinkPeer)> {
        let mut from = libc::sockaddr_ll {
            sll_family: 0,
            sll_protocol: 0,
            sll_ifindex: 0,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let mut from_len = length_of::<libc::sockaddr_ll>();
        // SAFETY: `buf` is writable for `buf.len()` bytes and `from` for `from_len`
        // bytes, and the kernel writes no more than either.
        let received = unsafe {
            libc::recvfrom(
                self.0.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                ptr::from_mut(&mut from).cast(),
                &mut from_len,
            )
        };
        let received = cvt_len(received)?;
        let peer = LinkPeer {
            packet_type: from.sll_pkttype,
            address_len: from.sll_halen,
            address: from.sll_addr,
        };
        Ok((received, peer))
    }

    /// Send `data` out interface `ifindex` to hardware address `dest`, as
    /// EtherType `protocol`: how many bytes were sent.
    pub fn send_link(
        &self,
        data: &[u8],
        ifindex: i32,
        protocol: u16,
        dest: [u8; 6],
    ) -> io::Result<usize> {
        let to = link_address(ifindex, protocol, Some(dest));
        // SAFETY: `data` is readable for `data.len()` bytes, and `to` is a live
        // `sockaddr_ll` of the length passed.
        let sent = unsafe {
            libc::sendto(
                self.0.as_raw_fd(),
                data.as_ptr().cast(),
                data.len(),
                0,
                ptr::from_ref(&to).cast(),
                length_of::<libc::sockaddr_ll>(),
            )
        };
        cvt_len(sent)
    }

    /// Send `data` to `dest` on the link `scope_id` names: how many bytes
    /// were sent.
    pub fn send_ipv6(&self, data: &[u8], dest: Ipv6Addr, scope_id: u32) -> io::Result<usize> {
        let to = ipv6_address(dest, scope_id);
        // SAFETY: `data` is readable for `data.len()` bytes, and `to` is a live
        // `sockaddr_in6` of the length passed.
        let sent = unsafe {
            libc::sendto(
                self.0.as_raw_fd(),
                data.as_ptr().cast(),
                data.len(),
                0,
                ptr::from_ref(&to).cast(),
                length_of::<libc::sockaddr_in6>(),
            )
        };
        cvt_len(sent)
    }
}

impl AsFd for Socket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// The socket options the keeper sets, on any socket.
pub trait SocketExt: AsFd {
    /// `SO_MARK`: tag everything this socket sends, for traffic control.
    fn set_mark(&self, mark: u32) -> io::Result<()> {
        set_option(self.as_fd(), libc::SOL_SOCKET, libc::SO_MARK, &(mark as c_int))
    }

    /// `SO_RCVBUF`, which the kernel doubles.
    fn set_recv_buffer(&self, bytes: c_int) -> io::Result<()> {
        set_option(self.as_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF, &bytes)
    }

    /// `SO_BINDTODEVICE`: send and receive only through interface `name`.
    fn bind_to_device(&self, name: &str) -> io::Result<()> {
        let length = libc::socklen_t::try_from(name.len())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `name` is readable for `length` bytes, and the kernel reads at
        // most that many.
        let rc = unsafe {
            libc::setsockopt(
                self.as_fd().as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                name.as_ptr().cast(),
                length,
            )
        };
        cvt(rc).map(drop)
    }

    /// `SO_ATTACH_FILTER`: run the classic BPF `program` on each packet before
    /// it is queued on this socket.
    fn attach_filter(&self, program: &[sock_filter]) -> io::Result<()> {
        let len = u16::try_from(program.len())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // The kernel copies the program while attaching it and never writes
        // through this pointer.
        let fprog = libc::sock_fprog {
            len,
            filter: program.as_ptr().cast_mut(),
        };
        set_option(self.as_fd(), libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &fprog)
    }

    /// `IPV6_ADD_MEMBERSHIP` of `group` on interface `ifindex`.
    fn join_ipv6_multicast(&self, group: Ipv6Addr, ifindex: u32) -> io::Result<()> {
        let request = libc::ipv6_mreq {
            ipv6mr_multiaddr: libc::in6_addr {
                s6_addr: group.octets(),
            },
            ipv6mr_interface: ifindex,
        };
        set_option(self.as_fd(), libc::IPPROTO_IPV6, libc::IPV6_ADD_MEMBERSHIP, &request)
    }

    /// `IPV6_MULTICAST_HOPS`.
    fn set_ipv6_multicast_hops(&self, hops: c_int) -> io::Result<()> {
        set_option(self.as_fd(), libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS, &hops)
    }

    /// `IPV6_MULTICAST_IF`.
    fn set_ipv6_multicast_if(&self, ifindex: c_int) -> io::Result<()> {
        set_option(self.as_fd(), libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF, &ifindex)
    }
}

impl<T: AsFd + ?Sized> SocketExt for T {}

/// `setsockopt` with a plain value the kernel reads `size_of::<T>()` bytes of.
/// Only this module calls it, with the option's own C type.
fn set_option<T>(fd: BorrowedFd<'_>, level: c_int, name: c_int, value: &T) -> io::Result<()> {
    // SAFETY: `value` is a live `T`, readable for the length passed, and
    // `setsockopt` only reads it.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            ptr::from_ref(value).cast(),
            length_of::<T>(),
        )
    };
    cvt(rc).map(drop)
}

/// The size of a socket address or option, which is a few dozen bytes.
fn length_of<T>() -> libc::socklen_t {
    mem::size_of::<T>() as libc::socklen_t
}

/// A `sockaddr_ll` for interface `ifindex` and EtherType `protocol` (host
/// order), with `mac` as its hardware address when there is one.
fn link_address(ifindex: i32, protocol: u16, mac: Option<[u8; 6]>) -> libc::sockaddr_ll {
    let mut sll_addr = [0; 8];
    let mut sll_halen = 0;
    if let Some(mac) = mac {
        sll_addr[..6].copy_from_slice(&mac);
        sll_halen = 6;
    }
    libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as libc::c_ushort,
        sll_protocol: protocol.to_be(),
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen,
        sll_addr,
    }
}

/// A `sockaddr_in6` for `address` on the link `scope_id` names.
fn ipv6_address(address: Ipv6Addr, scope_id: u32) -> libc::sockaddr_in6 {
    libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: address.octets(),
        },
        sin6_scope_id: scope_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;

    fn loopback_index() -> i32 {
        std::fs::read_to_string("/sys/class/net/lo/ifindex")
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    #[test]
    fn an_attached_filter_runs_on_every_datagram() {
        let (tx, rx) = UnixDatagram::pair().unwrap();
        rx.set_nonblocking(true).unwrap();
        // BPF_RET | BPF_K with 0: keep no byte of any packet.
        let drop_all = [sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0,
        }];
        rx.attach_filter(&drop_all).unwrap();
        tx.send(b"x").unwrap();
        let mut buf = [0; 8];
        assert_eq!(rx.recv(&mut buf).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        let err = rx.attach_filter(&[]).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    }

    #[test]
    fn a_device_binding_must_name_a_real_interface() {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        match udp.bind_to_device("lo") {
            // Kernels before 5.7 need CAP_NET_RAW for this.
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => return,
            other => other.unwrap(),
        }
        let other = UdpSocket::bind("127.0.0.1:0").unwrap();
        let err = other.bind_to_device("witcher-none0").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENODEV));
    }

    #[test]
    fn a_multicast_hop_limit_past_255_is_refused() {
        let Ok(socket) = Socket::ipv6_datagram() else {
            return; // No IPv6 on this host.
        };
        socket.set_ipv6_multicast_hops(255).unwrap();
        let err = socket.set_ipv6_multicast_hops(256).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    }

    #[test]
    fn a_frame_sent_on_loopback_reaches_a_socket_bound_to_its_ethertype() {
        // Packet sockets need CAP_NET_RAW, which CI's root has.
        let Ok(rx) = Socket::packet_datagram() else {
            return;
        };
        let tx = Socket::packet_datagram().unwrap();
        let lo = loopback_index();
        // IEEE 802 local experimental EtherType 1.
        let protocol = 0x88b5;
        rx.bind_link(lo, protocol).unwrap();
        assert_eq!(tx.send_link(b"witcher", lo, protocol, [0; 6]).unwrap(), 7);
        let ready = crate::poll::wait_readable(&[Some(rx.as_fd())], Duration::from_secs(2)).unwrap();
        assert_eq!(ready, 1);
        let mut buf = [0; 64];
        let (len, peer) = rx.recv_link(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"witcher");
        assert!(!peer.outgoing());
        assert_eq!(peer.mac(), Some([0; 6]));
        let err = rx.recv_link(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn a_peer_without_a_six_byte_address_has_no_mac() {
        let peer = LinkPeer {
            packet_type: PACKET_OUTGOING,
            address_len: 0,
            address: [1; 8],
        };
        assert!(peer.outgoing());
        assert_eq!(peer.mac(), None);
        let host = LinkPeer {
            packet_type: 0,
            address_len: 6,
            address: [2, 0, 0, 0, 1, 1, 9, 9],
        };
        assert!(!host.outgoing());
        assert_eq!(host.mac(), Some([2, 0, 0, 0, 1, 1]));
    }
}
