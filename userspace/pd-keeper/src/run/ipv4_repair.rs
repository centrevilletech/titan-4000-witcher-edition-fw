//! IPv4 passthrough repair: the DHCP offer for the bearer, the DHCP flood
//! rules, and the local ARP check that repairs DHCP and then renegotiates the
//! customer port. See `titan_pd_model::ipv4` and `titan_pd_model::ipv4_health`.

use std::fs;
use std::net::IpAddr;
use std::process::Command;

use titan_pd_model::health::Decision;
use titan_pd_model::ipv4::{self, Ipv4Plan};
use titan_pd_model::ipv4_health::{self, Action as Ipv4Action, Peer, Traffic};
use titan_sys::ifaddrs::InterfaceAddrs;

use crate::clock::unix_now;
use crate::command::command_stdout;
use crate::files::read_file;
use crate::netdev::{carrier_up, interface_index, interface_mac, rx_packets};

use super::{BRIDGE, CUSTOMER, Keeper, link_recovery};
use super::routes::main_routes;
use super::udhcpd::{customer_dhcp_pids, spawn_udhcpd, stop_customer_udhcpd};
use super::wire::send_marked_frame;

/// Seconds between steady-state checks of the DHCP ebtables flood rules.
/// Firewall restarts and bearer changes trigger an immediate check.
const FLOOD_INTERVAL: u64 = 300;
/// Seconds between rtnetlink refreshes of br0's probe IPv4 address.
const PROBE_ADDR_EVERY: u64 = 10;
/// Seconds the IPv4 check keeps its router through an unreadable lease file.
pub(super) const PEER_HOLD: u64 = 8;

impl Keeper {
    fn bridge_probe_address_cached(
        &mut self,
        bearer: std::net::Ipv4Addr,
    ) -> Option<std::net::Ipv4Addr> {
        if let Some((at, cached_bearer, addr)) = self.probe_addr_cache {
            if cached_bearer == bearer
                && addr.is_some()
                && self.now.saturating_sub(at) < PROBE_ADDR_EVERY
            {
                return addr;
            }
        }
        let addr = bridge_probe_address(bearer);
        self.probe_addr_cache = Some((self.now, bearer, addr));
        addr
    }

    fn assigned_address(&mut self, external: bool) -> Option<std::net::Ipv4Addr> {
        if !external || !self.bridged || !self.passthrough {
            self.assigned_at = None;
            return None;
        }
        if let Some((at, dev, addr)) = &self.assigned_at {
            if *at == self.now && dev == &self.bearer {
                return *addr;
            }
        }
        let snapshot = if std::env::var_os("TITAN_NVRAM_CACHE").is_none() {
            self.read_nvram_cache().map(|bytes| bytes.to_vec())
        } else {
            fs::read("/tmp/nvram.cfg").ok()
        };
        let addr = snapshot.and_then(|snapshot| {
            let ports = fs::read_dir("/sys/class/net/br0/brif")
                .ok()?
                .map(|entry| entry.ok()?.file_name().into_string().ok())
                .collect::<Option<Vec<_>>>()?;
            ipv4::data_assignment(&snapshot, &ports, &self.bearer)
        });
        self.assigned_at = Some((self.now, self.bearer.clone(), addr));
        addr
    }

    pub(super) fn maintain_ipv4(&mut self, routes: &str) {
        // Reap a daemon that exited on its own before considering a restart.
        if let Some(child) = &mut self.dhcp_child {
            if !matches!(child.try_wait(), Ok(None)) {
                self.dhcp_child = None;
            }
        }
        let bearer_changed = self.flood_bearer != self.bearer;
        if self.last_flood == 0
            || bearer_changed
            || self.now.saturating_sub(self.last_flood) >= FLOOD_INTERVAL
        {
            let first = self.last_flood == 0 && self.flood_bearer.is_empty();
            let already_present = !first
                && !bearer_changed
                && flood_rules_present(&ebtables_list_forward(), &self.bearer);
            if already_present {
                self.last_flood = self.now;
            } else {
                let mut failed = None;
                for line in ipv4::flood_commands(&self.bearer) {
                    if let Err(err) = ebtables(&line) {
                        failed = Some(err);
                    }
                }
                self.last_flood = self.now;
                self.flood_bearer = self.bearer.clone();
                if let Some(err) = failed {
                    self.note(&format!("DHCP flood rules were not installed: {err}"));
                } else if first {
                    self.note("scoped DHCP so discover and offers stay off the customer bearer");
                }
            }
        }
        let conf = read_file("/tmp/udhcpd.conf");
        let lease = fs::read("/tmp/udhcpd.leases").unwrap_or_default();
        // Every DHCP change waits out a cooldown, including repeated vendor
        // rewrites, so a broken server cannot become a restart storm. Stopping
        // a LAN offer has its own clock: it must not delay the offer for a
        // bearer that comes back a few seconds later.
        let cooldown = self.dhcp_gate.restart_ready(self.now);
        if !self.dhcp_gate.any_ready(self.now) {
            return;
        }
        // A new router's discover seen during the cooldown waits for it.
        let discover = take_discover(&mut self.discover, cooldown);
        let bearer = self.bearer.clone();
        let external = ipv4::parse_conf(&conf).is_some_and(|offer| ipv4::needs_assignment(offer.start));
        let assigned = self.assigned_address(external);
        let plan = ipv4::plan_with_assignment(&conf, routes, &lease, discover, cooldown, &bearer, assigned)
            .or_else(|| {
                if !cooldown || self.now.saturating_sub(self.last_dhcp_probe) < 5 {
                    return None;
                }
                self.last_dhcp_probe = self.now;
                let running = self.customer_dhcp_running();
                ipv4::restart_with_assignment(&conf, routes, running, assigned)
            });
        let Some(plan) = plan else {
            return;
        };
        if !self.dhcp_gate.allows(self.now, &plan) {
            return;
        }
        // A validated external offer already exists on disk. Start the missing
        // server on that exact file without rewriting it or stopping another PID.
        if external && !plan.clear_lease && plan.rewrite.is_some() {
            if self.dhcp_child.is_some() || read_file("/tmp/udhcpd.conf") != conf {
                return;
            }
            self.assigned_at = None;
            let current = self.assigned_address(true);
            let current_routes = main_routes();
            if current != assigned
                || ipv4::restart_with_assignment(&conf, &current_routes, false, current).is_none()
            {
                return;
            }
            let Ok(ps) = Command::new("ps").output() else { return };
            let listing = String::from_utf8_lossy(&ps.stdout);
            if !ps.status.success() || listing.trim().is_empty() || !customer_dhcp_pids(&listing).is_empty() {
                return;
            }
            self.dhcp_gate.record(self.now, &plan);
            match spawn_udhcpd() {
                Ok(child) => {
                    self.dhcp_child = Some(child);
                    self.note("udhcpd restarted on the unchanged offer for the assigned data PDN");
                }
                Err(err) => self.note(&format!("udhcpd did not restart for the assigned data PDN: {err}")),
            }
            return;
        }
        // While the bearer route is absent the stock server offers a LAN
        // address. Killing it on every 200 ms tick fills the log and the
        // process table.
        self.apply_ipv4(&plan);
    }

    fn apply_ipv4(&mut self, plan: &Ipv4Plan) {
        self.note(&plan.reason);
        if plan.stop_lan_offer {
            stop_customer_udhcpd();
            self.dhcp_gate.record(self.now, plan);
            return;
        }
        if let Some(text) = &plan.rewrite {
            // Never an empty or unreadable offer: udhcpd would not start, and
            // nothing could rebuild it from that file.
            if ipv4::parse_conf(text).is_none() {
                self.note("did not rewrite /tmp/udhcpd.conf: the new offer is empty or unreadable");
                return;
            }
            // Whole or not at all, so no reader sees half a file.
            let temporary = "/tmp/udhcpd.conf.witcher";
            if fs::write(temporary, text).is_err() || fs::rename(temporary, "/tmp/udhcpd.conf").is_err() {
                let _ = fs::remove_file(temporary);
                self.note("could not rewrite /tmp/udhcpd.conf");
                return;
            }
        }
        if plan.clear_lease {
            let _ = fs::remove_file("/tmp/udhcpd.leases");
        }
        if plan.rewrite.is_some() || plan.clear_lease {
            stop_customer_udhcpd();
            match spawn_udhcpd() {
                Ok(child) => {
                    self.dhcp_child = Some(child);
                    self.note("udhcpd restarted for the current bearer");
                }
                Err(err) => self.note(&format!("udhcpd did not restart: {err}")),
            }
            self.dhcp_gate.record(self.now, plan);
        }
    }

    pub(super) fn maintain_ipv4_link(&mut self, routes: &str) {
        if self.now == self.last_ipv4_check {
            return;
        }
        self.last_ipv4_check = self.now;
        let bearer = self.bearer.clone();
        let conf_text = read_file("/tmp/udhcpd.conf");
        let links_up = carrier_up(CUSTOMER) && carrier_up(&bearer);
        if !links_up {
            // A cable or LTE outage: the router needs a new baseline after it.
            self.ipv4_watch.reset();
        }
        let mut gateway = None;
        let mut hold_previous = self.ipv4_peer
            .is_none_or(|(peer, _)| !ipv4::needs_assignment(peer.address));
        let peer = (|| {
            if !links_up {
                return None;
            }
            let conf = ipv4::parse_conf(&conf_text)?;
            if (conf.interface != "br0:9" && conf.interface != BRIDGE) || !conf.remaining_yes {
                return None;
            }
            let external = ipv4::needs_assignment(conf.start);
            let assigned = self.assigned_address(external);
            let route = ipv4::offer_route(&conf, routes, assigned);
            if external {
                hold_previous = route.is_some()
                    && self.ipv4_peer.is_some_and(|(peer, _)| Some(peer.address) == route)
                    && self.ipv4_gateway == Some(conf.router);
            }
            let bearer = route?;
            if conf.start != bearer
                || conf.end != bearer
                || !ipv4::usable_gateway(conf.router, bearer)
            {
                return None;
            }
            let mac =
                ipv4_health::leased_mac(&fs::read("/tmp/udhcpd.leases").ok()?, bearer, unix_now())?;
            let local_mac = interface_mac(CUSTOMER)?;
            if local_mac == mac {
                return None;
            }
            let local_address = self.bridge_probe_address_cached(bearer)?;
            gateway = Some(conf.router);
            Some(Peer {
                address: bearer,
                mac,
                local_address,
                local_mac,
            })
        })();
        // The vendor's Wi-Fi udhcpd shares the customer server's lease file
        // and writes its own empty list over it every 30 s. The customer
        // server writes the lease back within its 5 s `auto_time`. Without
        // this hold the check started over every 30 s and could not count
        // three misses.
        let peer = match peer {
            Some(peer) => {
                self.ipv4_peer = Some((peer, self.now));
                self.ipv4_gateway = gateway;
                self.ipv4_conf_good = Some(conf_text.clone());
                Some(peer)
            }
            None if links_up && hold_previous => self
                .ipv4_peer
                .filter(|(_, seen)| self.now.saturating_sub(*seen) <= PEER_HOLD)
                .map(|(peer, _)| peer),
            None => {
                self.ipv4_peer = None;
                self.ipv4_gateway = None;
                None
            }
        };
        // The DHCP lease and gateway can arm the existing driver-MAC repair.
        // Public APNs have not qualified the separate Ethernet PHY recovery.
        let phy_peer = peer.filter(|p| !ipv4::needs_assignment(p.address));
        match self.ipv4_watch.tick(self.now, phy_peer) {
            Ipv4Action::Hold => {}
            Ipv4Action::Probe(peer) => {
                self.eth_rx.sample(self.now, rx_packets(CUSTOMER));
                let result = interface_index(CUSTOMER)
                    .ok_or_else(|| "eth0 is unavailable".to_owned())
                    .and_then(|index| send_marked_frame(index, &ipv4_health::probe(peer)));
                if let Err(err) = result {
                    self.ipv4_watch.send_failed(self.now);
                    self.note(&format!(
                        "IPv4 ARP probe could not be sent; recovery disarmed: {err}"
                    ));
                }
            }
            Ipv4Action::RepairDhcp => {
                self.note("IPv4 router missed three local ARP checks with LTE and Ethernet up; repairing DHCP first");
                // The router may be held through an unreadable offer, for
                // example while rcinit rewrites the file. Write back the whole
                // offer last read for this router, never what is there now.
                let text = phy_peer.and_then(|peer| {
                    ipv4::repair_text(&conf_text, self.ipv4_conf_good.as_deref(), peer.address)
                });
                match text {
                    Some(text) if self.dhcp_gate.restart_ready(self.now) => {
                        self.apply_ipv4(&Ipv4Plan {
                            stop_lan_offer: false,
                            rewrite: Some(text),
                            clear_lease: false,
                            reason:
                                "refreshing the current DHCP offer after local IPv4 reachability failed"
                                    .into(),
                        });
                    }
                    Some(_) => {}
                    None => self.note("DHCP repair skipped: no whole offer for this router to write back"),
                }
            }
            Ipv4Action::Renegotiate => {
                // Checked before the budget is spent: a router that stopped
                // answering ARP but still sends traffic keeps its link.
                match self.eth_rx.traffic(self.now, rx_packets(CUSTOMER)) {
                    Traffic::Quiet => {}
                    Traffic::Busy { frames, secs } => {
                        self.note(&format!("IPv4 Ethernet renegotiation skipped: the router sent {frames} frames in the last {secs} s, so the link is carrying traffic"));
                        return;
                    }
                    Traffic::Unknown => {
                        self.note("IPv4 Ethernet renegotiation skipped: the eth0 receive counter could not be measured, and a link is never cut on a guess");
                        return;
                    }
                }
                let before = self.health.clone();
                let decision = self.health.request_link_recovery(self.now);
                // Persist before touching the link; a supervisor restart must
                // not erase the shared IPv4/IPv6 action budget.
                if !self.save_budget() {
                    self.health = before;
                    self.note("IPv4 link recovery skipped: cannot persist the action budget");
                    return;
                }
                if matches!(decision, Decision::LinkDrop { .. }) {
                    let (program, args) = link_recovery();
                    self.note("IPv4 router still misses ARP after DHCP repair; requesting one Ethernet renegotiation");
                    match Command::new(program).args(args).status() {
                        Ok(status) if status.success() => self.note("IPv4 Ethernet renegotiation requested; waiting for a new successful ARP baseline"),
                        _ => self.note("IPv4 Ethernet renegotiation command failed; automatic retries are disarmed"),
                    }
                } else {
                    self.note(
                        "IPv4 Ethernet recovery skipped: shared port action budget is exhausted",
                    );
                }
            }
        }
    }
}

// Probe from an address actually owned by the bridge. Never claim the
// customer's bearer or the EPC gateway's address/MAC.
fn bridge_probe_address(bearer: std::net::Ipv4Addr) -> Option<std::net::Ipv4Addr> {
    // getifaddrs dumps addresses over rtnetlink and includes labeled aliases.
    let addrs = InterfaceAddrs::read().ok()?;
    addrs
        .iter()
        .filter(|addr| addr.is_on(BRIDGE))
        .find_map(|addr| match addr.addr {
            IpAddr::V4(ip)
                if !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback() && ip != bearer =>
            {
                Some(ip)
            }
            _ => None,
        })
}

fn ebtables_list_forward() -> String {
    let program = std::env::var("TITAN_EBTABLES").unwrap_or_else(|_| "/usr/bin/ebtables".into());
    command_stdout(&program, &["-L", "FORWARD"])
}

fn has_flag_pair(tokens: &[&str], flag: &str, expected: &[&str]) -> bool {
    tokens
        .windows(2)
        .any(|pair| pair[0] == flag && expected.contains(&pair[1]))
}

/// True when `ebtables -L FORWARD` already carries both DHCP flood drop rules
/// for `bearer` (ports 67 and 68). Handles both `ebtables -L` canonicalized
/// `udp` and numeric `17`.
fn flood_rules_present(listing: &str, bearer: &str) -> bool {
    let mut has_67 = false;
    let mut has_68 = false;
    for line in listing.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if !has_flag_pair(&tokens, "-o", &[bearer])
            || !has_flag_pair(&tokens, "-p", &["IPv4"])
            || !has_flag_pair(&tokens, "--ip-proto", &["17", "udp"])
            || !has_flag_pair(&tokens, "-j", &["DROP"])
        {
            continue;
        }
        if has_flag_pair(&tokens, "--ip-dport", &["67"]) {
            has_67 = true;
        }
        if has_flag_pair(&tokens, "--ip-dport", &["68"]) {
            has_68 = true;
        }
    }
    has_67 && has_68
}

fn ebtables(args: &str) -> Result<(), String> {
    let program = std::env::var("TITAN_EBTABLES").unwrap_or_else(|_| "/usr/bin/ebtables".into());
    let output = Command::new(program)
        .args(args.split_whitespace())
        .output()
        .map_err(|err| err.to_string())?;
    if output.status.success() || args.starts_with("-D") {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&output.stderr);
    if err.to_lowercase().contains("exists") {
        Ok(())
    } else {
        Err(err.trim().into())
    }
}

/// The DHCP discover the next plan may act on. During the cooldown it stays
/// in the slot: taking it then lost a new router's discover.
fn take_discover(slot: &mut Option<[u8; 6]>, cooldown_elapsed: bool) -> Option<[u8; 6]> {
    if cooldown_elapsed { slot.take() } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_discover_seen_during_the_dhcp_cooldown_waits_for_it() {
        let mac = [0x02, 0, 0, 0, 0, 0x0b];
        let mut slot = Some(mac);
        assert_eq!(take_discover(&mut slot, false), None);
        assert_eq!(slot, Some(mac));
        assert_eq!(take_discover(&mut slot, true), Some(mac));
        assert_eq!(slot, None);
    }

    #[test]
    fn flood_rules_match_both_numeric_and_canonical_ebtables_listings() {
        let canonical = "\
Bridge table: filter

Bridge chain: FORWARD, entries: 2, policy: ACCEPT
-p IPv4 -o lte0pdn2 --ip-proto udp --ip-dport 67 -j DROP
-p IPv4 -o lte0pdn2 --ip-proto udp --ip-dport 68 -j DROP
";
        assert!(flood_rules_present(canonical, "lte0pdn2"));
        assert!(!flood_rules_present(canonical, "lte0pdn1"));
        let stub = concat!(
            "Bridge table: filter\n\n",
            "Bridge chain: FORWARD, entries: 2, policy: ACCEPT\n",
            "-o lte0pdn1 -p IPv4 --ip-proto 17 --ip-dport 67 -j DROP \n",
            "-o lte0pdn1 -p IPv4 --ip-proto 17 --ip-dport 68 -j DROP \n",
        );
        assert!(flood_rules_present(stub, "lte0pdn1"));
        let missing_68 = "-o lte0pdn1 -p IPv4 --ip-proto 17 --ip-dport 67 -j DROP \n";
        assert!(!flood_rules_present(missing_68, "lte0pdn1"));
    }
}
