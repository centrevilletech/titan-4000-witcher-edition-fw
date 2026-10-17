//! IPv4 passthrough repair that does not depend on the vendor passthrough flag.
//!
//! On this firmware `ucfg get config lan br passthru` is 0 while the customer
//! bearer is bridged, so the overlay's DHCP restart and flood scoping never run.
//! The bearer address is a host route on br0, not an address on lte0pdn1. Before
//! that route exists the stock server offers 10.1.1.100. A discover from a new
//! MAC has to be able to take the single address without a reboot.

use std::net::Ipv4Addr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhcpConf {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
    pub max_leases: u32,
    pub router: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub lease: u32,
    pub interface: String,
    /// Vendor replies include this. A repair must not drop it.
    pub dns: Option<Ipv4Addr>,
    /// Vendor `remaining yes`. Kept across a repair.
    pub remaining_yes: bool,
}

pub fn host_route_on(routes: &str, dev: &str) -> Option<Ipv4Addr> {
    for line in routes.lines() {
        let mut parts = line.split_whitespace();
        let Some(dest) = parts.next() else { continue };
        if parts.next() != Some("dev") || parts.next() != Some(dev) || dest.contains('/') {
            continue;
        }
        let Ok(addr) = dest.parse::<Ipv4Addr>() else {
            continue;
        };
        // A re-attach can leave an unrelated public host route on br0.
        // The customer bearer is the 172.20 address, never the management one.
        if !is_customer_ipv4(addr) {
            continue;
        }
        return Some(addr);
    }
    None
}

pub fn default_via(routes: &str, dev: &str) -> Option<Ipv4Addr> {
    for line in routes.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.first() == Some(&"default")
            && parts.get(1) == Some(&"via")
            && parts.get(3) == Some(&"dev")
            && parts.get(4) == Some(&dev)
        {
            return parts[2].parse().ok();
        }
    }
    None
}

fn is_lan(addr: Ipv4Addr) -> bool {
    let [a, b, _, _] = addr.octets();
    a == 10 || (a == 192 && b == 168) || a == 127
}

fn is_customer_ipv4(addr: Ipv4Addr) -> bool {
    let [a, b, c, d] = addr.octets();
    a == 172 && b == 20 && !(c == 0 && d == 152)
}

pub fn parse_conf(text: &str) -> Option<DhcpConf> {
    let mut conf = DhcpConf {
        start: Ipv4Addr::UNSPECIFIED,
        end: Ipv4Addr::UNSPECIFIED,
        max_leases: 1,
        router: Ipv4Addr::UNSPECIFIED,
        mask: Ipv4Addr::UNSPECIFIED,
        lease: 120,
        interface: "br0:9".into(),
        dns: None,
        remaining_yes: true,
    };
    let mut saw_start = false;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let key = parts.next()?;
        match key {
            "start" => {
                conf.start = parts.next()?.parse().ok()?;
                saw_start = true;
            }
            "end" => conf.end = parts.next()?.parse().ok()?,
            "max_leases" => conf.max_leases = parts.next()?.parse().ok()?,
            "interface" => conf.interface = parts.next()?.to_owned(),
            "remaining" => conf.remaining_yes = parts.next()? != "no",
            "option" => match parts.next()? {
                "router" => conf.router = parts.next()?.parse().ok()?,
                "subnet" => conf.mask = parts.next()?.parse().ok()?,
                "lease" => conf.lease = parts.next()?.parse().ok()?,
                "dns" => conf.dns = parts.next()?.parse().ok(),
                _ => {}
            },
            _ => {}
        }
    }
    saw_start.then_some(conf)
}

pub fn render_conf(conf: &DhcpConf) -> String {
    let mut text = format!(
        "\
pidfile /var/run/udhcpd.pid
start {start}
end {end}
max_leases {max}
interface {iface}
remaining {remaining}
auto_time 5
lease_file /tmp/udhcpd.leases
option subnet {mask}
option router {router}
option lease {lease}
",
        start = conf.start,
        end = conf.end,
        max = conf.max_leases.max(8),
        iface = conf.interface,
        remaining = if conf.remaining_yes { "yes" } else { "no" },
        mask = conf.mask,
        router = conf.router,
        lease = conf.lease,
    );
    if let Some(dns) = conf.dns {
        text.push_str(&format!("option dns {dns}\n"));
    }
    text
}

/// What the running server should be offering, once the bearer route exists.
pub fn repaired(existing: &DhcpConf, bearer: Ipv4Addr, gateway: Ipv4Addr) -> DhcpConf {
    let mut conf = existing.clone();
    conf.start = bearer;
    conf.end = bearer;
    conf.max_leases = conf.max_leases.max(8);
    if conf.interface.is_empty() {
        conf.interface = "br0:9".into();
    }
    let router_was_unusable = !usable_gateway(conf.router, bearer);
    if router_was_unusable {
        conf.router = gateway;
    }
    if router_was_unusable || !same_subnet(bearer, conf.router, conf.mask) {
        conf.mask = mask_covering(bearer, conf.router);
    }
    conf
}

pub fn needs_repair(existing: &DhcpConf, bearer: Ipv4Addr, gateway: Ipv4Addr) -> bool {
    &repaired(existing, bearer, gateway) != existing
}

/// A gateway the customer router can use. The bearer address itself is not one,
/// and neither is the 10.1.1.1 alias.
pub fn usable_gateway(addr: Ipv4Addr, bearer: Ipv4Addr) -> bool {
    addr != Ipv4Addr::UNSPECIFIED && addr != bearer && !is_lan(addr)
}

/// What IPv4 passthrough should do on this observation.
///
/// `discover` is the client MAC of a DHCP discover or request seen on the
/// customer port. The lease file holds one binding; a different MAC has to be
/// able to take the address without a reboot of the unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv4Plan {
    pub stop_lan_offer: bool,
    pub rewrite: Option<String>,
    pub clear_lease: bool,
    pub reason: String,
}

pub fn plan_maintenance(
    conf_text: &str,
    routes: &str,
    lease: &[u8],
    discover: Option<[u8; 6]>,
    cooldown_elapsed: bool,
) -> Option<Ipv4Plan> {
    let conf = parse_conf(conf_text)?;
    let bearer = host_route_on(routes, "br0");
    if offers_lan(&conf) && bearer.is_none() {
        return Some(Ipv4Plan {
            stop_lan_offer: true,
            rewrite: None,
            clear_lease: false,
            reason: "udhcpd would offer a LAN address before the bearer route exists".into(),
        });
    }
    let mut plan = Ipv4Plan {
        stop_lan_offer: false,
        rewrite: None,
        clear_lease: false,
        reason: String::new(),
    };
    if let Some(bearer) = bearer {
        let gateway = default_via(routes, "lte0pdn1")
            .filter(|gateway| usable_gateway(*gateway, bearer))
            .or_else(|| usable_gateway(conf.router, bearer).then_some(conf.router));
        if let Some(gateway) = gateway {
            if needs_repair(&conf, bearer, gateway) {
                plan.rewrite = Some(render_conf(&repaired(&conf, bearer, gateway)));
                // A lease for the old bearer must not survive a redial.
                plan.clear_lease = conf.start != bearer;
                plan.reason = format!("passthrough DHCP must offer {bearer} via {gateway}");
            }
        }
    }
    if cooldown_elapsed {
        if let Some(seen) = discover {
            let held = lease_macs(lease);
            if !held.is_empty() && !held.contains(&seen) {
                plan.clear_lease = true;
                let why = format!(
                    "DHCP from {} replaces the lease held by {}",
                    mac_text(seen),
                    held.iter()
                        .map(|mac| mac_text(*mac))
                        .collect::<Vec<_>>()
                        .join(",")
                );
                if plan.reason.is_empty() {
                    plan.reason = why;
                } else {
                    plan.reason = format!("{}; {why}", plan.reason);
                }
            }
        }
    }
    (plan.stop_lan_offer || plan.rewrite.is_some() || plan.clear_lease).then_some(plan)
}

/// Restart a missing customer DHCP daemon only with an already-correct offer
/// and a live bearer route. Silence, no LTE, and a Wi-Fi config are not faults.
pub fn restart_missing_server(conf_text: &str, routes: &str, running: bool) -> Option<Ipv4Plan> {
    if running {
        return None;
    }
    let conf = parse_conf(conf_text)?;
    if conf.interface != "br0" && conf.interface != "br0:9" {
        return None;
    }
    let bearer = host_route_on(routes, "br0")?;
    if !usable_gateway(conf.router, bearer) || needs_repair(&conf, bearer, conf.router) {
        return None;
    }
    Some(Ipv4Plan {
        stop_lan_offer: false,
        rewrite: Some(render_conf(&conf)),
        clear_lease: false,
        reason: "customer DHCP daemon is absent; restoring the current bearer offer".into(),
    })
}

pub fn mac_text(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, mask: Ipv4Addr) -> bool {
    let (a, b, mask) = (u32::from(a), u32::from(b), u32::from(mask));
    mask != 0 && a & mask == b & mask
}

fn mask_covering(bearer: Ipv4Addr, gateway: Ipv4Addr) -> Ipv4Addr {
    for mask in [0xffff_fff0, 0xffff_ff00, 0xffff_0000] {
        let mask = Ipv4Addr::from(mask);
        if same_subnet(bearer, gateway, mask) {
            return mask;
        }
    }
    Ipv4Addr::from(0xffff_ff00)
}

/// BusyBox 1.21 writes an 8-byte big-endian timestamp and then 36-byte
/// records: remaining time, IPv4, MAC, a 20-byte hostname, and 2 bytes of pad.
/// A file of whole records and no timestamp has the MAC at offset 8.
/// The MAC is not at offset 12 of a 44-byte file; that is the IPv4 address.
pub fn lease_macs(bytes: &[u8]) -> Vec<[u8; 6]> {
    let Some(start) = lease_mac_offset(bytes) else {
        return Vec::new();
    };
    let mut macs = Vec::new();
    let mut offset = start;
    while offset + 6 <= bytes.len() {
        let mut mac = [0; 6];
        mac.copy_from_slice(&bytes[offset..offset + 6]);
        if mac != [0; 6] {
            macs.push(mac);
        }
        offset += 36;
    }
    macs
}

pub fn lease_mac(bytes: &[u8]) -> Option<[u8; 6]> {
    lease_macs(bytes).into_iter().next()
}

fn lease_mac_offset(bytes: &[u8]) -> Option<usize> {
    if bytes.len() >= 44 && (bytes.len() - 8) % 36 == 0 {
        Some(16)
    } else if bytes.len() >= 36 && bytes.len() % 36 == 0 {
        Some(8)
    } else {
        None
    }
}

pub fn offers_lan(conf: &DhcpConf) -> bool {
    is_lan(conf.start)
}

/// BusyBox ebtables on this firmware rejects a protocol name (`udp`) and
/// accepts the number. 17 is UDP. These rules never match lte0pdn0.
pub fn flood_commands() -> &'static [&'static str] {
    &[
        "-D FORWARD -o lte0pdn1 -p IPv4 --ip-proto 17 --ip-dport 67 -j DROP",
        "-A FORWARD -o lte0pdn1 -p IPv4 --ip-proto 17 --ip-dport 67 -j DROP",
        "-D FORWARD -o lte0pdn1 -p IPv4 --ip-proto 17 --ip-dport 68 -j DROP",
        "-A FORWARD -o lte0pdn1 -p IPv4 --ip-proto 17 --ip-dport 68 -j DROP",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTES: &str = "\
default via 172.20.0.1 dev lte0pdn0
172.20.0.152 dev lte0pdn0 scope link
172.20.64.152 dev br0 scope link
10.1.1.0/24 dev br0 proto kernel scope link
";

    const CONF: &str = "\
start 172.20.64.152
end 172.20.64.152
max_leases 1
interface br0:9
option subnet 255.255.255.240
option router 172.20.64.151
option lease 120
";

    #[test]
    fn the_bearer_route_is_not_the_lan_or_the_management_address() {
        assert_eq!(
            host_route_on(ROUTES, "br0"),
            Some(Ipv4Addr::new(172, 20, 64, 152))
        );
        let with_public = format!("34.98.109.46 dev br0 scope link\n{ROUTES}");
        assert_eq!(
            host_route_on(&with_public, "br0"),
            Some(Ipv4Addr::new(172, 20, 64, 152))
        );
        assert_eq!(
            default_via(ROUTES, "lte0pdn0"),
            Some(Ipv4Addr::new(172, 20, 0, 1))
        );
    }

    #[test]
    fn a_lan_offer_is_replaced_and_a_correct_offer_is_only_widened() {
        let lan = parse_conf("start 10.1.1.100\nend 10.1.1.200\nmax_leases 50\ninterface br0\noption subnet 255.255.255.0\noption router 10.1.1.1\noption lease 86400\n").unwrap();
        assert!(offers_lan(&lan));
        let fixed = repaired(
            &lan,
            Ipv4Addr::new(172, 20, 64, 152),
            Ipv4Addr::new(172, 20, 64, 151),
        );
        assert_eq!(fixed.start, Ipv4Addr::new(172, 20, 64, 152));
        assert_eq!(fixed.router, Ipv4Addr::new(172, 20, 64, 151));
        assert_eq!(fixed.mask, Ipv4Addr::new(255, 255, 255, 240));
        let current = parse_conf(CONF).unwrap();
        let widened = repaired(&current, current.start, current.router);
        assert_eq!(widened.start, current.start);
        assert_eq!(widened.mask, current.mask);
        assert!(widened.max_leases >= 8);
        assert!(needs_repair(&current, current.start, current.router));
        assert!(!needs_repair(&widened, current.start, current.router));
    }

    #[test]
    fn the_lease_file_yields_the_router_mac_and_flood_rules_spare_management() {
        // Captured from udhcpd on the bench: timestamp, remaining time,
        // 172.20.64.152, then the router MAC. Reading offset 12 yields the address.
        let bytes = [
            0x00, 0x00, 0x00, 0x00, 0x6a, 0xbf, 0xd1, 0x0b, 0x00, 0x00, 0x00, 0x72, 0xac, 0x14,
            0x40, 0x98, 0x24, 0x2f, 0xd0, 0xb8, 0xf1, 0x9d, b'H', b'X', b'2', b'2', b'0', 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(bytes.len(), 44);
        assert_eq!(
            lease_mac(&bytes),
            Some([0x24, 0x2f, 0xd0, 0xb8, 0xf1, 0x9d])
        );
        assert!(lease_mac(&[0u8; 8]).is_none());
        let mut bare = [0u8; 36];
        bare[8..14].copy_from_slice(&[0x24, 0x2f, 0xd0, 0xb8, 0xf1, 0x9d]);
        assert_eq!(lease_mac(&bare), Some([0x24, 0x2f, 0xd0, 0xb8, 0xf1, 0x9d]));
        let rules = flood_commands().join("\n");
        assert!(rules.contains("--ip-proto 17"));
        assert!(rules.contains("dport 67"));
        assert!(!rules.contains("ip-protocol"));
        assert!(!rules.contains("lte0pdn0"));
    }

    #[test]
    fn a_repair_keeps_dns_and_a_new_mac_clears_the_single_lease() {
        let conf = "\
start 172.20.64.152
end 172.20.64.152
max_leases 1
interface br0:9
remaining yes
option subnet 255.255.255.240
option router 172.20.64.151
option lease 120
option dns 100.126.0.49
";
        let routes = "\
default via 172.20.64.151 dev lte0pdn1
172.20.64.152 dev br0 scope link
";
        let plan = plan_maintenance(conf, routes, &[], None, true).unwrap();
        let rewritten = plan.rewrite.unwrap();
        assert!(rewritten.contains("option dns 100.126.0.49"));
        assert!(rewritten.contains("remaining yes"));
        assert!(rewritten.contains("max_leases 8"));
        assert!(!plan.clear_lease);
        let mut lease = [0u8; 44];
        lease[16..22].copy_from_slice(&[0x24, 0x2f, 0xd0, 0xb8, 0xf1, 0x9d]);
        let again =
            plan_maintenance(conf, routes, &lease, Some([0x02, 0, 0, 0, 0, 1]), true).unwrap();
        assert!(again.clear_lease);
        assert!(again.reason.contains("02:00:00:00:00:01"));
        let same = plan_maintenance(
            conf,
            routes,
            &lease,
            Some([0x24, 0x2f, 0xd0, 0xb8, 0xf1, 0x9d]),
            true,
        )
        .unwrap();
        assert!(!same.clear_lease);
        let quiet =
            plan_maintenance(conf, routes, &lease, Some([0x02, 0, 0, 0, 0, 1]), false).unwrap();
        assert!(!quiet.clear_lease, "a lease clear waits out the cooldown");
        let early = "start 10.1.1.100\nend 10.1.1.200\ninterface br0\noption subnet 255.255.255.0\noption router 10.1.1.1\noption lease 86400\n";
        let stopped = plan_maintenance(
            early,
            "10.1.1.0/24 dev br0 proto kernel scope link\n",
            &[],
            None,
            true,
        )
        .unwrap();
        assert!(stopped.stop_lan_offer);
        assert!(stopped.rewrite.is_none());
    }
    #[test]
    fn absent_dhcp_is_restarted_only_for_a_valid_current_bearer() {
        let conf = CONF.replace("max_leases 1", "max_leases 8");
        assert!(restart_missing_server(&conf, ROUTES, true).is_none());
        assert!(restart_missing_server(&conf, "", false).is_none());
        assert!(restart_missing_server(CONF, ROUTES, false).is_none());
        assert!(restart_missing_server(&conf.replace("br0:9", "ra0"), ROUTES, false).is_none());
        let plan = restart_missing_server(&conf, ROUTES, false).unwrap();
        assert!(!plan.clear_lease);
        assert!(!plan.stop_lan_offer);
        assert!(plan.rewrite.unwrap().contains("start 172.20.64.152"));
    }

    #[test]
    fn a_new_bearer_clears_the_previous_address_lease() {
        let routes = "172.20.64.153 dev br0 scope link\ndefault via 172.20.64.151 dev lte0pdn1\n";
        let plan = plan_maintenance(CONF, routes, &[], None, true).unwrap();
        assert!(plan.clear_lease);
        assert!(plan.rewrite.unwrap().contains("start 172.20.64.153"));
    }
}
