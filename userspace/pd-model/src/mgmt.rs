//! IPv6 on the management bearer (`lte0pdn0`, APN ue-mgmt).
//!
//! IP passthrough moves the modem's external device to the customer bearer.
//! The modem records the interface identifier the core assigned, and it installs
//! that identifier and solicits only on the external bearer. `lte0pdn0` keeps
//! the MAC link-local, the solicitation does not match, and the /64 never
//! arrives. A unit whose stored identifier happens to be its own MAC still
//! comes up. Installing the assigned link-local and soliciting from it is
//! enough: the kernel accepts the advertisement, and the modem learns the
//! prefix on `lte0pdn0`.

use std::net::Ipv6Addr;

pub const MGMT_DEV: &str = "lte0pdn0";

/// The 64-bit interface identifier from `LTE: lte0pdn0 set interface id`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Iid(pub [u8; 8]);

impl Iid {
    /// Four hextets, no leading zeros, suitable for `fe80::` and for the cache file.
    pub fn token(self) -> String {
        format!(
            "{:x}:{:x}:{:x}:{:x}",
            u16::from_be_bytes([self.0[0], self.0[1]]),
            u16::from_be_bytes([self.0[2], self.0[3]]),
            u16::from_be_bytes([self.0[4], self.0[5]]),
            u16::from_be_bytes([self.0[6], self.0[7]])
        )
    }

    pub fn link_local(self) -> Ipv6Addr {
        let mut octets = [0u8; 16];
        octets[0] = 0xfe;
        octets[1] = 0x80;
        octets[8..].copy_from_slice(&self.0);
        Ipv6Addr::from(octets)
    }

    /// True when `addr` was formed from this identifier.
    pub fn matches(self, addr: Ipv6Addr) -> bool {
        addr.octets()[8..] == self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Forwarding is on, so accept_ra must be 2 or Linux stops taking advertisements.
    AcceptAdvertisements,
    AddLinkLocal(Ipv6Addr),
    Solicit(Ipv6Addr),
    /// Unit-originated IPv6 has to leave on the management bearer. Metric 1
    /// beats the customer-bearer default (metric 20). Bridged customer frames
    /// do not use this route.
    PreferManagementDefault,
}

/// Last interface identifier the modem logged for `lte0pdn0`.
pub fn assigned_iid(dmesg: &str) -> Option<Iid> {
    let mut found = None;
    for line in dmesg.lines() {
        let Some(rest) = line.split("lte0pdn0").nth(1) else {
            continue;
        };
        let Some(at) = rest.find("set interface id:") else {
            continue;
        };
        let token = rest[at + "set interface id:".len()..]
            .split_whitespace()
            .next()
            .unwrap_or("");
        if let Some(iid) = parse_iid(token) {
            found = Some(iid);
        }
    }
    found
}

pub fn parse_iid(text: &str) -> Option<Iid> {
    let groups: Vec<&str> = text.split(':').collect();
    if groups.len() != 4 {
        return None;
    }
    let mut bytes = [0u8; 8];
    for (index, group) in groups.iter().enumerate() {
        if group.is_empty() || group.len() > 4 {
            return None;
        }
        let value = u16::from_str_radix(group, 16).ok()?;
        bytes[index * 2] = (value >> 8) as u8;
        bytes[index * 2 + 1] = (value & 0xff) as u8;
    }
    Some(Iid(bytes))
}

/// What to do on one pass. Empty means the management global is up and preferred.
pub fn plan(iid: Iid, addrs: &str, accept_ra: &str, routes: &str) -> Vec<Step> {
    let mut steps = Vec::new();
    if accept_ra.trim() != "2" {
        steps.push(Step::AcceptAdvertisements);
    }
    let local = iid.link_local();
    if !addrs_of(addrs).any(|addr| addr == local) {
        steps.push(Step::AddLinkLocal(local));
    }
    if !global_up(iid, addrs) {
        steps.push(Step::Solicit(local));
        return steps;
    }
    if !management_default_preferred(routes) {
        steps.push(Step::PreferManagementDefault);
    }
    steps
}

pub fn global_up(iid: Iid, addrs: &str) -> bool {
    addrs_of(addrs).any(|addr| !is_link_local(addr) && iid.matches(addr))
}

fn management_default_preferred(routes: &str) -> bool {
    routes.lines().any(|line| {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("default") {
            return false;
        }
        if !line.contains("via fe80::1") || !line.contains("dev lte0pdn0") {
            return false;
        }
        metric_of(line).unwrap_or(1024) < 20
    })
}

fn metric_of(line: &str) -> Option<u32> {
    let mut parts = line.split_whitespace();
    while let Some(word) = parts.next() {
        if word == "metric" {
            return parts.next()?.parse().ok();
        }
    }
    None
}

fn addrs_of(dump: &str) -> impl Iterator<Item = Ipv6Addr> + '_ {
    dump.split_whitespace().filter_map(|word| {
        let bare = word.split('/').next()?;
        bare.parse().ok()
    })
}

fn is_link_local(addr: Ipv6Addr) -> bool {
    let o = addr.octets();
    o[0] == 0xfe && (o[1] & 0xc0) == 0x80
}

/// Drop a `nameserver ::` line. The vendor resolver rewrite inserts one when
/// the management advertisement is learned, and lookups then try it first.
pub fn without_zero_nameserver(text: &str) -> Option<String> {
    let mut changed = false;
    let mut out = String::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some("nameserver")
            && parts
                .next()
                .and_then(|addr| addr.parse::<Ipv6Addr>().ok())
                .is_some_and(|addr| addr.is_unspecified())
        {
            changed = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    changed.then_some(out)
}

/// Global addresses sitting on the customer bridge inside the management /64.
/// The vendor stack copies the prefix onto br0 with a placeholder identifier
/// (`a:b:c:d`). Those addresses belong on `lte0pdn0` only.
pub fn bridge_globals_in_prefix(dump: &str, mgmt_global: Ipv6Addr) -> Vec<Ipv6Addr> {
    let prefix = &mgmt_global.octets()[..8];
    let mut found = Vec::new();
    for addr in addrs_of(dump) {
        if is_link_local(addr) || addr.octets()[..8] != *prefix {
            continue;
        }
        found.push(addr);
    }
    found
}

/// Router Solicitation, source link-layer option included. Checksum left at 0;
/// the kernel fills it on an ICMPv6 raw socket.
pub fn solicitation(mac: [u8; 6]) -> [u8; 16] {
    let mut packet = [0u8; 16];
    packet[0] = 133;
    packet[8] = 1;
    packet[9] = 1;
    packet[10..16].copy_from_slice(&mac);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    const DMESG: &str = "\
LTE: lte0pdn0(0x0) set interface id: 0200:5eff:fe40:0001 eps_id=5
LTE: set apn type lte0pdn0(0x10) eps_id=5 172.20.0.152 ::200:5eff:fe40:1
LTE: lte0pdn1(0x0) set interface id: 200:5eff:fe40:3 eps_id=6
ndisc_send_rs(lte0pdn1) fe80::200:5eff:fe40:3->ff02::2
";

    const MAC_ONLY: &str = "\
7: lte0pdn0: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500
    inet6 fe80::200:5eff:fe40:2/64 scope link
";

    const UP: &str = "\
7: lte0pdn0: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500
    inet6 2001:db8:e0:97:200:5eff:fe40:1/64 scope global dynamic
    inet6 fe80::200:5eff:fe40:1/64 scope link nodad
    inet6 fe80::200:5eff:fe40:2/64 scope link
";

    #[test]
    fn the_management_id_is_not_the_customer_bearer_id() {
        let iid = assigned_iid(DMESG).unwrap();
        assert_eq!(iid.link_local().to_string(), "fe80::200:5eff:fe40:1");
    }

    #[test]
    fn a_later_management_id_replaces_the_earlier_one() {
        let text =
            format!("{DMESG}\nLTE: lte0pdn0(0x0) set interface id: 200:5eff:fe40:2 eps_id=5\n");
        assert_eq!(
            assigned_iid(&text).unwrap().link_local().to_string(),
            "fe80::200:5eff:fe40:2"
        );
    }

    #[test]
    fn a_missing_global_adds_the_assigned_link_local_and_solicits() {
        let iid = assigned_iid(DMESG).unwrap();
        let steps = plan(
            iid,
            MAC_ONLY,
            "1\n",
            "default via fe80::1 dev lte0pdn1 metric 20\n",
        );
        assert_eq!(
            steps,
            vec![
                Step::AcceptAdvertisements,
                Step::AddLinkLocal("fe80::200:5eff:fe40:1".parse().unwrap()),
                Step::Solicit("fe80::200:5eff:fe40:1".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn an_up_bearer_is_left_alone_when_its_default_is_already_preferred() {
        let iid = assigned_iid(DMESG).unwrap();
        let routes = "\
default via fe80::1 dev lte0pdn0 metric 1
default via fe80::1 dev lte0pdn1 metric 20
";
        assert!(plan(iid, UP, "2", routes).is_empty());
        assert!(global_up(iid, UP));
    }

    #[test]
    fn an_up_bearer_whose_default_still_prefers_the_customer_pdn_is_corrected() {
        let iid = assigned_iid(DMESG).unwrap();
        let steps = plan(iid, UP, "2", "default via fe80::1 dev lte0pdn1 metric 20\n");
        assert_eq!(steps, vec![Step::PreferManagementDefault]);
    }

    #[test]
    fn a_zero_nameserver_is_removed_and_a_real_one_stays() {
        let text = "\
nameserver 0:0:0:0:0:0:0:0
search local
nameserver 2001:db8:ef:ffff::1
nameserver 192.0.2.53
";
        let cleaned = without_zero_nameserver(text).unwrap();
        assert!(!cleaned.contains("0:0:0:0"));
        assert!(cleaned.contains("2001:db8:ef:ffff::1"));
        assert!(without_zero_nameserver(&cleaned).is_none());
    }

    #[test]
    fn the_placeholder_on_the_bridge_is_in_the_management_prefix() {
        let global: Ipv6Addr = "2001:db8:e0:97:200:5eff:fe40:1".parse().unwrap();
        let dump = "\
28: br0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet6 2001:db8:e0:97:a:b:c:d/128 scope global
    inet6 fe80::200:5eff:fe40:2/64 scope link
";
        assert_eq!(
            bridge_globals_in_prefix(dump, global),
            vec!["2001:db8:e0:97:a:b:c:d".parse::<Ipv6Addr>().unwrap()]
        );
    }

    #[test]
    fn the_solicitation_names_the_management_mac() {
        let mac = [0x44, 0x6f, 0xd8, 0x80, 0x11, 0xde];
        let packet = solicitation(mac);
        assert_eq!(packet[0], 133);
        assert_eq!(&packet[10..16], &mac);
    }
}
