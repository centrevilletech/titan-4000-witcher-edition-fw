//! The packets the keeper builds and reads on the customer port: router
//! advertisements, DHCPv6 replies, Ethernet frames, and the classification of
//! captured IPv6 control traffic. No I/O.

use titan_pd_model::dhcpv6::{self, client_mac};
use titan_pd_model::prefix::Block;
use titan_pd_model::ra::{self, Advertisement};

pub(super) struct Event {
    pub(super) kind: Class,
    pub(super) outgoing: bool,
    /// The Ethernet source of an inbound frame.
    pub(super) source_mac: Option<[u8; 6]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Class {
    Other,
    RouterSolicit,
    NeighbourForUs,
    /// Neighbour solicitation for fe80::1. Counts only after we delegated to that MAC.
    RouterProbe {
        source_mac: Option<[u8; 6]>,
    },
    DelegatedTraffic,
    RouterAdvertisement {
        prefixes: Vec<Block>,
        source_mac: Option<[u8; 6]>,
    },
    DhcpV6 {
        source_mac: Option<[u8; 6]>,
        source: [u8; 16],
        payload: Vec<u8>,
    },
}

pub(super) fn classify_ipv6(packet: &[u8], delegated: Option<Block>, our: Option<[u8; 16]>) -> Class {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return Class::Other;
    }
    let mut source = [0u8; 16];
    source.copy_from_slice(&packet[8..24]);
    if delegated.is_some_and(|block| block.contains(&source)) {
        return Class::DelegatedTraffic;
    }
    if packet[6] == 58 && packet.len() >= 48 {
        let icmp = &packet[40..];
        return match icmp[0] {
            133 => Class::RouterSolicit,
            135 if our.is_some_and(|ours| icmp.len() >= 24 && icmp[8..24] == ours) => {
                Class::NeighbourForUs
            }
            135 if icmp.len() >= 24 && icmp[8..24] == fe80_1() => {
                Class::RouterProbe { source_mac: None }
            }
            134 => Class::RouterAdvertisement {
                prefixes: ra::prefixes_of(icmp),
                source_mac: slla(icmp),
            },
            _ => Class::Other,
        };
    }
    if packet[6] == 17 && packet.len() >= 48 {
        let dest = u16::from_be_bytes([packet[42], packet[43]]);
        if dest == 547 {
            return Class::DhcpV6 {
                source_mac: None,
                source,
                payload: packet[48..].to_vec(),
            };
        }
    }
    Class::Other
}

fn slla(icmp: &[u8]) -> Option<[u8; 6]> {
    if icmp.len() < 16 {
        return None;
    }
    let mut rest = &icmp[16..];
    while rest.len() >= 8 {
        let len = rest[1] as usize * 8;
        if len < 8 || rest.len() < len {
            break;
        }
        if rest[0] == 1 && len >= 8 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&rest[2..8]);
            return Some(mac);
        }
        rest = &rest[len..];
    }
    None
}

/// DHCP discover or request on the customer port. Other DHCP messages are ignored.
pub(super) fn dhcp_client_mac(packet: &[u8]) -> Option<[u8; 6]> {
    if packet.len() < 240 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < 20 || packet.len() < ihl + 8 + 240 || packet[9] != 17 {
        return None;
    }
    let udp = &packet[ihl..];
    let dest = u16::from_be_bytes([udp[2], udp[3]]);
    if dest != 67 {
        return None;
    }
    let dhcp = &udp[8..];
    if dhcp[0] != 1 {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&dhcp[28..34]);
    if mac == [0; 6] {
        return None;
    }
    let mut options = &dhcp[240..];
    while options.len() >= 2 {
        let (code, len) = (options[0], options[1] as usize);
        if code == 255 {
            break;
        }
        if options.len() < 2 + len {
            break;
        }
        if code == 53 && len == 1 && (options[2] == 1 || options[2] == 3) {
            return Some(mac);
        }
        options = &options[2 + len..];
    }
    None
}

pub(super) fn client_mac_of(payload: &[u8]) -> Option<[u8; 6]> {
    dhcpv6::parse(payload).and_then(|message| client_mac(&message.client_id))
}

pub(super) fn prefixes_advert(prefixes: &[Block], mac: [u8; 6], withdraw: bool) -> Vec<u8> {
    let advert = if withdraw {
        Advertisement::withdraw(prefixes.to_vec(), mac)
    } else {
        Advertisement::for_block(prefixes[0], mac)
    };
    ra::emit(&advert)
}

pub(super) fn ra_packet(src: [u8; 16], mut icmp: Vec<u8>) -> Vec<u8> {
    let dest = ff02_1();
    let sum = checksum(&src, &dest, 58, &icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    ipv6_packet(src, dest, 255, 58, &icmp)
}

pub(super) fn udp_packet(src: [u8; 16], dest: [u8; 16], payload: &[u8]) -> Vec<u8> {
    let mut udp = vec![0u8; 8 + payload.len()];
    let length = (udp.len() as u16).to_be_bytes();
    udp[0..2].copy_from_slice(&547u16.to_be_bytes());
    udp[2..4].copy_from_slice(&546u16.to_be_bytes());
    udp[4..6].copy_from_slice(&length);
    udp[8..].copy_from_slice(payload);
    let sum = checksum(&src, &dest, 17, &udp);
    udp[6..8].copy_from_slice(&sum.to_be_bytes());
    ipv6_packet(src, dest, 64, 17, &udp)
}

fn ipv6_packet(src: [u8; 16], dest: [u8; 16], hop: u8, next: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 40 + payload.len()];
    packet[0] = 0x60;
    let len = payload.len() as u16;
    packet[4..6].copy_from_slice(&len.to_be_bytes());
    packet[6] = next;
    packet[7] = hop;
    packet[8..24].copy_from_slice(&src);
    packet[24..40].copy_from_slice(&dest);
    packet[40..].copy_from_slice(payload);
    packet
}

fn checksum(src: &[u8; 16], dest: &[u8; 16], next: u8, body: &[u8]) -> u16 {
    let mut sum = 0u32;
    let add = |sum: &mut u32, bytes: &[u8]| {
        let mut index = 0;
        while index + 1 < bytes.len() {
            *sum += u16::from_be_bytes([bytes[index], bytes[index + 1]]) as u32;
            index += 2;
        }
        if index < bytes.len() {
            *sum += (bytes[index] as u32) << 8;
        }
    };
    add(&mut sum, src);
    add(&mut sum, dest);
    add(&mut sum, &(body.len() as u32).to_be_bytes());
    sum += u32::from(next);
    add(&mut sum, body);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(super) fn fe80_1() -> [u8; 16] {
    let mut addr = [0u8; 16];
    addr[0] = 0xfe;
    addr[1] = 0x80;
    addr[15] = 1;
    addr
}

fn ff02_1() -> [u8; 16] {
    let mut addr = [0u8; 16];
    addr[0] = 0xff;
    addr[1] = 0x02;
    addr[15] = 1;
    addr
}

pub(super) fn all_nodes_mac() -> [u8; 6] {
    [0x33, 0x33, 0x00, 0x00, 0x00, 0x01]
}

pub(super) fn ethernet_frame(dest: [u8; 6], source: [u8; 6], packet: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + packet.len());
    frame.extend_from_slice(&dest);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(packet);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;
    use titan_pd_model::prefix::parse_pinned;

    fn sample_ra() -> Vec<u8> {
        let link = parse_pinned("2001:db8:ff:d100::/64").unwrap().link64();
        let icmp = ra::emit(&Advertisement::for_block(
            link,
            [0x02, 0x00, 0x00, 0x00, 0x01, 0x01],
        ));
        ra_packet(fe80_1(), icmp)
    }

    #[test]
    fn an_advertisement_uses_the_core_router_identity() {
        let block = parse_pinned("2001:db8:f0:9700::/56").unwrap();
        let mac = [0x02, 0x00, 0x00, 0x00, 0x01, 0x01];
        let packet = ra_packet(
            fe80_1(),
            ra::emit(&Advertisement::for_block(block.link64(), mac)),
        );
        let frame = ethernet_frame(all_nodes_mac(), mac, &packet);
        assert_eq!(&frame[6..12], &mac);
        assert_eq!(&frame[22..38], &fe80_1());
        assert!(frame.ends_with(&mac));
    }

    #[test]
    fn an_advertisement_checksum_verifies_and_names_the_link() {
        let packet = sample_ra();
        assert_eq!(
            packet[7], 255,
            "a router ignores an advertisement whose hop limit is not 255"
        );
        let mut icmp = packet[40..].to_vec();
        let mut src = [0u8; 16];
        let mut dest = [0u8; 16];
        src.copy_from_slice(&packet[8..24]);
        dest.copy_from_slice(&packet[24..40]);
        let carried = u16::from_be_bytes([icmp[2], icmp[3]]);
        icmp[2] = 0;
        icmp[3] = 0;
        assert_eq!(checksum(&src, &dest, 58, &icmp), carried);
        let packet = crate::capture::tests::captured(&packet, libc::ETH_P_IPV6, true);
        assert_eq!(classify_ipv6(&packet, None, None), {
            let prefixes = ra::prefixes_of(&packet[40..]);
            Class::RouterAdvertisement {
                prefixes,
                source_mac: Some([0x02, 0x00, 0x00, 0x00, 0x01, 0x01]),
            }
        });
    }
}
