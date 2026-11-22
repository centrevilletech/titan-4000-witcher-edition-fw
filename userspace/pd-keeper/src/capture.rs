//! Classic BPF for a cooked packet socket. Offsets start at the network header.
use libc::sock_filter;
use std::{io, mem};

const PROTOCOL: u32 = (-4096i32) as u32;
const PACKET_TYPE: u32 = PROTOCOL + 4;
const LOAD_WORD: u16 = 0x20;
const LOAD_BYTE: u16 = 0x30;
const LOAD_HALF: u16 = 0x28;
const RETURN: u16 = 0x06;

fn op(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn equal(k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter {
        code: 0x15,
        jt,
        jf,
        k,
    }
}

fn program(sniff: bool) -> Vec<sock_filter> {
    let mut code = vec![op(LOAD_WORD, PACKET_TYPE)];
    if sniff {
        // The only outbound frame needed during startup is a core RA.
        code.extend([
            equal(4, 0, 8),
            op(LOAD_WORD, PROTOCOL),
            equal(libc::ETH_P_IPV6 as u32, 0, 4),
            op(LOAD_BYTE, 6),
            equal(58, 0, 2),
            op(LOAD_BYTE, 40),
            equal(134, 1, 0),
            op(RETURN, 0),
            op(RETURN, 2048),
        ]);
    } else {
        code.extend([equal(4, 0, 1), op(RETURN, 0)]);
    }
    code.extend([
        op(LOAD_WORD, PROTOCOL),
        equal(libc::ETH_P_ARP as u32, 0, 1),
        op(RETURN, 2048),
        equal(libc::ETH_P_IP as u32, 0, 7),
        op(LOAD_BYTE, 9),
        equal(17, 0, 4),
        op(0xb1, 0), // X = IPv4 header length in bytes
        op(0x48, 2), // halfword at X + 2 (UDP destination)
        equal(67, 0, 1),
        op(RETURN, 2048),
        op(RETURN, 0),
        equal(libc::ETH_P_IPV6 as u32, 1, 0),
        op(RETURN, 0),
        op(LOAD_BYTE, 6),
        equal(58, 5, 0),
        equal(17, 0, 5),
        op(0x80, 0), // packet length
        sock_filter {
            code: 0x35,
            jt: 0,
            jf: 3,
            k: 44,
        },
        op(LOAD_HALF, 42),
        equal(547, 0, 1),
        op(RETURN, 2048),
        // Any next-header, including fragments, can prove delegated liveness.
        op(RETURN, 40),
    ]);
    code
}

pub fn install(fd: libc::c_int, sniff: bool) -> Result<(), String> {
    attach(fd, &mut program(sniff))
}

fn attach(fd: libc::c_int, code: &mut [sock_filter]) -> Result<(), String> {
    let filter = libc::sock_fprog {
        len: code.len() as u16,
        filter: code.as_mut_ptr(),
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&filter as *const libc::sock_fprog).cast(),
            mem::size_of_val(&filter) as _,
        )
    };
    if rc < 0 {
        return Err(format!(
            "attach packet filter: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::{fd::AsRawFd, unix::net::UnixDatagram};

    // Execute the real Linux socket filter, substituting just the two packet
    // metadata loads that an AF_UNIX test datagram doesn't have.
    pub(crate) fn captured(packet: &[u8], protocol: i32, outgoing: bool, sniff: bool) -> Vec<u8> {
        let (tx, rx) = UnixDatagram::pair().unwrap();
        let mut code = program(sniff);
        for ins in &mut code {
            if ins.code == LOAD_WORD && ins.k == PROTOCOL {
                *ins = op(0, protocol as u32);
            } else if ins.code == LOAD_WORD && ins.k == PACKET_TYPE {
                *ins = op(0, if outgoing { 4 } else { 0 });
            }
        }
        attach(rx.as_raw_fd(), &mut code).unwrap();
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
    fn receives_arp_and_dhcp_including_ipv4_options() {
        let arp = [0; 28];
        assert_eq!(captured(&arp, libc::ETH_P_ARP, false, false), arp);
        for ihl in [5, 6, 15] {
            let mut p = [0; 400];
            p[0] = 0x40 | ihl;
            p[9] = 17;
            p[usize::from(ihl) * 4 + 3] = 67;
            assert_eq!(captured(&p, libc::ETH_P_IP, false, false), p);
            p[9] = 6;
            assert!(captured(&p, libc::ETH_P_IP, false, false).is_empty());
        }
    }

    #[test]
    fn preserves_control_bodies_and_dhcpv6() {
        let mut p = [0; 128];
        p[0] = 0x60;
        p[8..24].fill(0x44);
        p[6] = 58;
        for kind in [133, 134, 135, 136] {
            p[40] = kind;
            assert_eq!(captured(&p, libc::ETH_P_IPV6, false, false), p);
            assert!(captured(&p, libc::ETH_P_IPV6, true, false).is_empty());
            assert_eq!(
                !captured(&p, libc::ETH_P_IPV6, true, true).is_empty(),
                kind == 134
            );
        }
        p[6] = 17;
        p[42..44].copy_from_slice(&547u16.to_be_bytes());
        assert_eq!(captured(&p, libc::ETH_P_IPV6, false, false), p);
        // A renew to a unicast server address is captured the same way: the
        // filter reads the port, never the destination.
        p[24..40].fill(0x55);
        assert_eq!(captured(&p, libc::ETH_P_IPV6, false, false), p);
    }

    #[test]
    fn bulk_ipv6_from_the_router_stays_in_the_kernel() {
        // Upload data and download ACKs. Each one copied to the keeper cost a
        // clone, a wakeup and a read: several percent of the CPU at 100 Mbps.
        let mut p = [0; 128];
        p[0] = 0x60;
        p[8..24].fill(0x44);
        for next in [0, 6, 17, 44, 59] {
            p[6] = next;
            assert!(
                captured(&p, libc::ETH_P_IPV6, false, false).is_empty(),
                "next header {next}"
            );
        }
        // UDP to any other port, including the DHCPv6 client port.
        p[6] = 17;
        p[42..44].copy_from_slice(&546u16.to_be_bytes());
        assert!(captured(&p, libc::ETH_P_IPV6, false, false).is_empty());
    }
}
