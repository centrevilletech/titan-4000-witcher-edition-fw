//! The IPv4 main routing table, as the model reads it.

use std::fs;
use std::net::Ipv4Addr;

use crate::command::command_stdout;

// The main table, without spawning ip on every tick.
pub(super) fn main_routes() -> String {
    fs::read_to_string("/proc/net/route")
        .map(|text| ipv4_routes(&text))
        .unwrap_or_else(|_| command_stdout("ip", &["route"]))
}

// The model consumes the two forms printed by ip route. The proc file
// prints network-order addresses as native-endian hex integers.
fn ipv4_routes(text: &str) -> String {
    use std::fmt::Write;
    let mut routes = String::new();
    for row in text.lines().skip(1) {
        let mut fields = row.split_whitespace();
        let (Some(dev), Some(dest), Some(gw), Some(flags), Some(mask)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.nth(3),
        ) else {
            continue;
        };
        let (Ok(dest), Ok(gw), Ok(flags), Ok(mask)) = (
            u32::from_str_radix(dest, 16),
            u32::from_str_radix(gw, 16),
            u32::from_str_radix(flags, 16),
            u32::from_str_radix(mask, 16),
        ) else {
            continue;
        };
        if flags & 0x201 != 1 || dev == "*" {
            continue;
        }
        if mask == u32::MAX && gw == 0 {
            let addr = Ipv4Addr::from(dest.to_ne_bytes());
            let _ = writeln!(routes, "{addr} dev {dev}");
        } else if mask == 0 && dest == 0 && flags & 2 != 0 {
            let addr = Ipv4Addr::from(gw.to_ne_bytes());
            let _ = writeln!(routes, "default via {addr} dev {dev}");
        }
    }
    routes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_routes_preserve_direct_hosts_and_gateway_defaults() {
        let encode = |octets| format!("{:08X}", u32::from_ne_bytes(octets));
        let host_ip = std::net::Ipv4Addr::from([192, 0, 2, 9]);
        let gw_ip = std::net::Ipv4Addr::from([192, 0, 2, 1]);
        let host = encode(host_ip.octets());
        let gw = encode(gw_ip.octets());
        let text = format!(
            "Iface Destination Gateway Flags RefCnt Use Metric Mask\n\
            br0 {host} 00000000 0005 0 0 0 FFFFFFFF\n\
            wan 00000000 {gw} 0003 0 0 2 00000000\n\
            wan {host} {gw} 0007 0 0 0 FFFFFFFF\n\
            br0 {host} 00000000 0205 0 0 0 FFFFFFFF\n"
        );
        assert_eq!(
            ipv4_routes(&text),
            format!("{host_ip} dev br0\ndefault via {gw_ip} dev wan\n")
        );
    }
}
