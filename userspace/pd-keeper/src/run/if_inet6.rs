//! Reads of `/proc/net/if_inet6`: a link-local address, the bearer's
//! delegated block, and an interface's addresses as `ip -6 addr` prints them.

use std::fs;
use std::net::Ipv6Addr;

use titan_pd_model::prefix::Block;

use crate::command::command_stdout;

pub(super) fn link_local(text: &str, dev: &str) -> Option<[u8; 16]> {
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let addr = parts.next()?;
        let _index = parts.next()?;
        let _prefix = parts.next()?;
        let scope = parts.next()?;
        let _flags = parts.next()?;
        let name = parts.next()?;
        if name == dev && scope == "20" {
            return parse_hex_addr(addr);
        }
    }
    None
}

// ip's rtnetlink dump and /proc may enumerate multiple prefixes in different
// orders. Preserve the original choice during that uncommon attach transition.
pub(super) fn live_prefix(dev: &str) -> Option<Block> {
    if let Ok(text) = fs::read_to_string("/proc/net/if_inet6") {
        let mut blocks = global_prefixes(&text, dev);
        let first = blocks.next()?;
        if blocks.all(|block| block == first) {
            return Some(first);
        }
    }
    command_stdout("ip", &["-6", "addr", "show", "dev", dev])
        .lines()
        .find_map(|line| {
            let address = line.trim().strip_prefix("inet6 ")?;
            if !address.contains("scope global") {
                return None;
            }
            let ip: Ipv6Addr = address
                .split_whitespace()
                .next()?
                .strip_suffix("/64")?
                .parse()
                .ok()?;
            Some(Block::containing_56(ip.octets()))
        })
}

fn global_prefixes<'a>(text: &'a str, dev: &'a str) -> impl Iterator<Item = Block> + 'a {
    text.lines().filter_map(move |line| {
        let mut parts = line.split_whitespace();
        let addr = parts.next()?;
        let prefix = parts.nth(1)?;
        let scope = parts.next()?;
        let name = parts.nth(1)?;
        if name == dev && scope == "00" && prefix == "40" {
            parse_hex_addr(addr).map(Block::containing_56)
        } else {
            None
        }
    })
}

fn parse_hex_addr(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 {
        return None;
    }
    let mut addr = [0u8; 16];
    for (index, byte) in addr.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(addr)
}

/// Format `dev`'s IPv6 addresses from `/proc/net/if_inet6` in the same
/// `inet6 <addr>/<prefix> scope <scope>` shape that `mgmt::plan` consumes,
/// avoiding an `ip -6 addr show` fork.
pub(super) fn proc_if_inet6_addrs(dev: &str) -> String {
    match fs::read_to_string("/proc/net/if_inet6") {
        Ok(text) => proc_if_inet6_addrs_from(&text, dev),
        Err(_) => command_stdout("ip", &["-6", "addr", "show", "dev", dev]),
    }
}

fn proc_if_inet6_addrs_from(text: &str, dev: &str) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(addr_hex), Some(_index), Some(prefix_hex), Some(scope_hex), Some(_flags), Some(name)) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            continue;
        };
        if name != dev {
            continue;
        }
        let Some(octets) = parse_hex_addr(addr_hex) else {
            continue;
        };
        let prefix = u8::from_str_radix(prefix_hex, 16).unwrap_or(128);
        let scope = match scope_hex {
            "00" => "global",
            "20" => "link",
            "10" => "host",
            _ => "other",
        };
        let addr = Ipv6Addr::from(octets);
        let _ = writeln!(out, "    inet6 {addr}/{prefix} scope {scope}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use titan_pd_model::mgmt;

    use crate::run::addrs_global_text;
    use crate::run::packet::dhcp_client_mac;

    #[test]
    fn the_bearer_line_and_a_dhcp_discover_parse() {
        let text = "fe800000000000000000000000000001 02 40 20 80 wan\n20010db800ffd30000000000000000d4 02 40 00 80 wan";
        assert_eq!(
            global_prefixes(text, "wan").next().unwrap().to_string(),
            "2001:db8:ff:d300::/56"
        );
        let mut packet = vec![0u8; 282];
        packet[0] = 0x45;
        packet[9] = 17;
        packet[22] = 0;
        packet[23] = 67;
        packet[28] = 1;
        packet[56..62].copy_from_slice(&[0x24, 0x2f, 0xd0, 0xb8, 0xf1, 0x9d]);
        packet[268] = 53;
        packet[269] = 1;
        packet[270] = 1;
        packet[271] = 255;
        assert_eq!(
            dhcp_client_mac(&packet),
            Some([0x24, 0x2f, 0xd0, 0xb8, 0xf1, 0x9d])
        );
    }

    #[test]
    fn proc_if_inet6_formats_global_and_link_local_for_mgmt_plan() {
        let proc = "\
fe8000000000000002005efffe400001 05 40 20 80 lte0pdn0
20010db800e0009702005efffe400001 05 40 00 80 lte0pdn0
20010db800e000970000000000000001 02 40 00 80 br0
";
        let mgmt_addrs = proc_if_inet6_addrs_from(proc, "lte0pdn0");
        let iid = mgmt::parse_iid("200:5eff:fe40:1").unwrap();
        assert!(mgmt::global_up(iid, &mgmt_addrs));
        assert_eq!(
            addrs_global_text(&mgmt_addrs).as_deref(),
            Some("2001:db8:e0:97:200:5eff:fe40:1")
        );
        let bridge_addrs = proc_if_inet6_addrs_from(proc, "br0");
        let global: Ipv6Addr = "2001:db8:e0:97:200:5eff:fe40:1".parse().unwrap();
        assert_eq!(
            mgmt::bridge_globals_in_prefix(&bridge_addrs, global),
            vec!["2001:db8:e0:97::1".parse::<Ipv6Addr>().unwrap()]
        );
    }
}
