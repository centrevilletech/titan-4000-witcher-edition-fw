//! Classic BPF for protocol-specific cooked packet sockets bound to `br0`.
//! Offsets start at the network header.
//!
//! Each socket binds to one EtherType (`ETH_P_ARP`, `ETH_P_IP`, or `ETH_P_IPV6`
//! when prefix delegation is enabled) on the bridge master, never `ETH_P_ALL`.
//! That keeps `ptype_all` empty so the kernel never runs `dev_queue_xmit_nit`
//! on transmit, and bridge-forwarded customer traffic never enters `ptype_base`.
use libc::sock_filter;
use std::os::fd::BorrowedFd;
use titan_sys::socket::SocketExt;

const LOAD_HALF: u16 = 0x28;
const LOAD_BYTE: u16 = 0x30;
const LOAD_LEN: u16 = 0x80;
const LOAD_X_IHL: u16 = 0xb1;
const LOAD_IND_HALF: u16 = 0x48;
const JMP_JEQ: u16 = 0x15;
const JMP_JGE: u16 = 0x35;
const JMP_JSET: u16 = 0x45;
const RETURN: u16 = 0x06;

fn op(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

/// ARP replies (opcode 2, at least 28 bytes).
fn arp_program() -> Vec<sock_filter> {
    vec![
        op(LOAD_LEN, 0),
        jump(JMP_JGE, 28, 0, 3),
        op(LOAD_HALF, 6),
        jump(JMP_JEQ, 2, 0, 1),
        op(RETURN, 2048),
        op(RETURN, 0),
    ]
}

/// Non-fragmented IPv4 UDP packets to DHCP server port 67 (including IPv4 options).
fn ipv4_dhcp_program() -> Vec<sock_filter> {
    vec![
        op(LOAD_BYTE, 9),
        jump(JMP_JEQ, 17, 0, 6),
        op(LOAD_HALF, 6),
        jump(JMP_JSET, 0x1fff, 4, 0),
        op(LOAD_X_IHL, 0),    // X = IPv4 header length in bytes
        op(LOAD_IND_HALF, 2), // halfword at X + 2 (UDP destination port)
        jump(JMP_JEQ, 67, 0, 1),
        op(RETURN, 2048),
        op(RETURN, 0),
    ]
}

/// ICMPv6 control frames and DHCPv6 server requests (UDP port 547).
/// In steady state (`sniff == false`), core router advertisements (type 134)
/// are dropped in the kernel too.
fn ipv6_program(sniff: bool) -> Vec<sock_filter> {
    if sniff {
        vec![
            op(LOAD_BYTE, 6),
            jump(JMP_JEQ, 58, 5, 0),
            jump(JMP_JEQ, 17, 0, 5),
            op(LOAD_LEN, 0),
            jump(JMP_JGE, 44, 0, 3),
            op(LOAD_HALF, 42),
            jump(JMP_JEQ, 547, 0, 1),
            op(RETURN, 2048),
            op(RETURN, 0),
        ]
    } else {
        vec![
            op(LOAD_BYTE, 6),
            jump(JMP_JEQ, 58, 0, 4),
            op(LOAD_LEN, 0),
            jump(JMP_JGE, 41, 0, 8),
            op(LOAD_BYTE, 40),
            jump(JMP_JEQ, 134, 6, 5),
            jump(JMP_JEQ, 17, 0, 5),
            op(LOAD_LEN, 0),
            jump(JMP_JGE, 44, 0, 3),
            op(LOAD_HALF, 42),
            jump(JMP_JEQ, 547, 0, 1),
            op(RETURN, 2048),
            op(RETURN, 0),
        ]
    }
}

pub fn install_arp(fd: BorrowedFd<'_>) -> Result<(), String> {
    attach(fd, &arp_program())
}

pub fn install_ipv4_dhcp(fd: BorrowedFd<'_>) -> Result<(), String> {
    attach(fd, &ipv4_dhcp_program())
}

pub fn install_ipv6(fd: BorrowedFd<'_>, sniff: bool) -> Result<(), String> {
    attach(fd, &ipv6_program(sniff))
}

fn attach(fd: BorrowedFd<'_>, code: &[sock_filter]) -> Result<(), String> {
    fd.attach_filter(code)
        .map_err(|err| format!("attach packet filter: {err}"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io;
    use std::os::{fd::AsFd, unix::net::UnixDatagram};

    // Execute the real Linux socket filter for the given protocol socket.
    pub(crate) fn captured(packet: &[u8], protocol: i32, sniff: bool) -> Vec<u8> {
        let (tx, rx) = UnixDatagram::pair().unwrap();
        let code = match protocol {
            libc::ETH_P_ARP => arp_program(),
            libc::ETH_P_IP => ipv4_dhcp_program(),
            libc::ETH_P_IPV6 => ipv6_program(sniff),
            other => panic!("unexpected protocol {other:#x}"),
        };
        attach(rx.as_fd(), &code).unwrap();
        rx.set_nonblocking(true).unwrap();
        tx.send(packet).unwrap();
        let mut buf = [0; 2048];
        match rx.recv(&mut buf) {
            Ok(n) => buf[..n].to_vec(),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Vec::new(),
            Err(err) => panic!("{err}"),
        }
    }

    #[test]
    fn receives_arp_replies_and_drops_requests() {
        let mut arp = [0u8; 28];
        arp[7] = 2; // ARP reply
        assert_eq!(captured(&arp, libc::ETH_P_ARP, false), arp);
        arp[7] = 1; // ARP request
        assert!(captured(&arp, libc::ETH_P_ARP, false).is_empty());
        assert!(captured(&[0u8; 27], libc::ETH_P_ARP, false).is_empty());
    }

    #[test]
    fn receives_dhcp_including_ipv4_options_and_drops_other_ipv4() {
        for ihl in [5, 6, 15] {
            let mut p = [0; 400];
            p[0] = 0x40 | ihl;
            p[9] = 17;
            p[usize::from(ihl) * 4 + 3] = 67;
            assert_eq!(captured(&p, libc::ETH_P_IP, false), p);
            // Non-initial IPv4 fragment is rejected.
            p[7] = 1;
            assert!(captured(&p, libc::ETH_P_IP, false).is_empty());
            p[7] = 0;
            // TCP traffic (for example local management HTTP/SSH) is rejected.
            p[9] = 6;
            assert!(captured(&p, libc::ETH_P_IP, false).is_empty());
        }
    }

    #[test]
    fn preserves_control_bodies_and_dhcpv6_and_skips_steady_ra() {
        let mut p = [0; 128];
        p[0] = 0x60;
        p[8..24].fill(0x44);
        p[6] = 58;
        for kind in [133, 135, 136] {
            p[40] = kind;
            assert_eq!(captured(&p, libc::ETH_P_IPV6, false), p);
            assert_eq!(captured(&p, libc::ETH_P_IPV6, true), p);
        }
        p[40] = 134;
        assert!(captured(&p, libc::ETH_P_IPV6, false).is_empty());
        assert_eq!(captured(&p, libc::ETH_P_IPV6, true), p);

        p[6] = 17;
        p[42..44].copy_from_slice(&547u16.to_be_bytes());
        assert_eq!(captured(&p, libc::ETH_P_IPV6, false), p);
        p[24..40].fill(0x55);
        assert_eq!(captured(&p, libc::ETH_P_IPV6, false), p);
    }

    #[test]
    fn bulk_ipv6_from_the_router_stays_in_the_kernel() {
        let mut p = [0; 128];
        p[0] = 0x60;
        p[8..24].fill(0x44);
        for next in [0, 6, 17, 44, 59] {
            p[6] = next;
            assert!(
                captured(&p, libc::ETH_P_IPV6, false).is_empty(),
                "next header {next}"
            );
        }
        p[6] = 17;
        p[42..44].copy_from_slice(&546u16.to_be_bytes());
        assert!(captured(&p, libc::ETH_P_IPV6, false).is_empty());
    }
}
