//! IPv6 prefix delegation on the customer port: answering router
//! solicitations and DHCPv6 from the pinned block behind the port filter,
//! the router's health and the delegation it holds. See
//! `titan_pd_model::health`, `titan_pd_model::ra` and `titan_pd_model::dhcpv6`.

use std::fs;
use std::process::Command;
use std::time::Duration;

use titan_pd_model::config::{self, Config, Report};
use titan_pd_model::dhcpv6;
use titan_pd_model::filter;
use titan_pd_model::health::{self, Decision, Phase, View};
use titan_pd_model::ipv4;
use titan_pd_model::ipv4_health::Traffic;
use titan_pd_model::prefix::Block;
use titan_pd_model::ra::{self, Advertisement};

use crate::log;
use crate::clock::{monotonic, unix_now};
use crate::files::read_file;
use crate::netdev::{carrier_up, interface_index, interface_mac, rx_packets};
use crate::paths::state_dir;

use super::{BRIDGE, CUSTOMER, Keeper, tc_apply};
use super::budget::link_recovery;
use super::if_inet6::{link_local, live_prefix};
use super::packet::{Class, all_nodes_mac, client_mac_of, ethernet_frame, fe80_1, prefixes_advert, ra_packet, udp_packet};
use super::wire::{ControlSockets, send_marked_frame};

const RA_INTERVAL: u64 = 45;
const SNIFF_SECS: u64 = 3;
const SERVE_RETRY: u64 = 60;
/// Seconds between two samples of eth0's receive counter for IPv6 health.
const LINK_SAMPLE: u64 = 5;
/// eth0 down this long may be a router swap: the old router's IPv6 history
/// and delegation hold no longer apply. Our own renegotiation is shorter.
const ROUTER_SWAP_SECS: u64 = 10;
/// Source link-layer address of the core's router advertisement on this EPC.
/// Data frames have to be addressed to this MAC so the bridge forwards them
/// out lte0pdn1. Addressing them to eth0 makes the bridge deliver them locally.
pub(super) const CORE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x01, 0x01];

#[derive(Default)]
struct Sniff {
    prefixes: Vec<Block>,
    source_mac: Option<[u8; 6]>,
}

impl Keeper {
    /// Prefix delegation for this tick, once the saved setting is loaded:
    /// serve the pinned block or stop, advertise, check the router's health
    /// and publish the report.
    pub(super) fn maintain_delegation(&mut self, loaded: Result<Option<Config>, String>) {
        let config = match loaded {
            Ok(config) => {
                self.logged_unreadable = false;
                config
            }
            Err(err) => {
                if self.serving {
                    self.stop_serving("the saved setting could not be read");
                }
                if !self.logged_unreadable {
                    self.note(&format!("saved setting is unreadable ({err}); not serving and not changing the IP family"));
                    self.logged_unreadable = true;
                }
                self.publish(
                    &Report::default(),
                    "The saved setting could not be read. It was not treated as Off.",
                );
                return;
            }
        };
        let Some(config) = config else {
            if self.serving {
                self.stop_serving("the saved setting is gone");
            }
            self.publish(
                &Report::default(),
                "IPv6 prefix delegation has not been saved. The IP family is unchanged.",
            );
            return;
        };
        if !config.enabled {
            if self.serving {
                self.stop_serving("prefix delegation is off");
            }
            self.publish(
                &Report::default(),
                "IPv6 prefix delegation is off. The customer bearer is IPv4.",
            );
            return;
        };

        let bearer = self.bearer.clone();
        let live = live_prefix(&bearer);
        let pinned = match ensure_pin(&config, live) {
            Ok(block) => block,
            Err(err) => {
                if self.serving {
                    self.stop_serving(&err);
                }
                self.note(&err);
                let mut report = self.report(live, None, false, &err);
                report.mismatch = err;
                self.publish(&report, &report.mismatch.clone());
                return;
            }
        };
        let Some(block) = pinned else {
            if self.serving {
                self.stop_serving("waiting for the first attach to learn the block");
            }
            self.publish(
                &self.report(
                    live,
                    None,
                    false,
                    "On, with no pin yet. Waiting for the first attach.",
                ),
                "On, with no pin yet. Waiting for the first attach.",
            );
            return;
        };
        if let Some(live_block) = live {
            if live_block != block {
                let message = format!(
                    "The core handed {live_block} and the pin is {block}. Delegation is stopped and the old block is not being served."
                );
                if self.serving {
                    self.stop_serving(&message);
                }
                self.clear_delegation();
                self.note(&message);
                let mut report = self.report(live, Some(block), false, &message);
                report.mismatch = message.clone();
                self.publish(&report, &message);
                return;
            }
        }

        let carrier = carrier_up(CUSTOMER);
        self.note_eth0_carrier(carrier);
        // After 18 h the vendor SDK removes the bridged bearer's own address
        // for the rest of the session. Bridged with carrier, it still carries
        // the delegated prefix.
        let lte = bearer_up(live.is_some(), self.bridged, carrier_up(&bearer));
        if !self.serving && self.now >= self.serve_retry_at {
            if let Err(err) = self.start_serving(block) {
                self.serve_retry_at = self.now + SERVE_RETRY;
                self.note(&format!("not serving: {err}. Retrying in {SERVE_RETRY}s so a filter failure cannot loop."));
            }
        }
        if self.solicit_pending && self.serving {
            self.solicit_pending = false;
            self.send_advertisement(block, "router solicitation");
        } else if self.serving && carrier && self.now.saturating_sub(self.last_ra) >= RA_INTERVAL {
            self.send_advertisement(block, "periodic router advertisement");
        }
        // A delegated router probes fe80::1 slower than the 45s silence
        // window. While its prefix is still inside the valid lifetime, that
        // gap is not a failure and must not drop the Ethernet link.
        let held = delegation_current(
            self.delegated_mac.map(|mac| (mac, self.delegated_at)),
            self.now,
        );
        // Frames from the router stand in for the bulk IPv6 the port filter
        // no longer copies out, and a busy link is never dropped.
        let rx = rx_packets(CUSTOMER);
        if self.link_rx_at.ready(self.now, LINK_SAMPLE) {
            self.link_rx.sample(self.now, rx);
        }
        let traffic = self.link_rx.traffic(self.now, rx);
        let busy = matches!(traffic, Traffic::Busy { .. });
        let before = self.health.clone();
        let decision = self.health.tick(&View {
            now: self.now,
            carrier_up: carrier,
            lte_up: lte,
            prefix_ok: true,
            serving: self.serving,
            router_seen: self.router_seen || held || busy,
            ipv6_router_heard: self.ipv6_router.is_some(),
            link_quiet: traffic == Traffic::Quiet,
        });
        self.router_seen = false;
        if matches!(decision, Decision::LinkDrop { .. }) && !self.save_budget() {
            // Spend nothing that could not be recorded.
            self.health = before;
            self.note("Ethernet recovery skipped: cannot persist the shared action budget");
        } else {
            self.act(decision, block);
        }
        if self.saved_budget != Some(self.budget_tuple()) {
            self.save_budget();
        }
        let recent = self.now.saturating_sub(self.last_router) < health::SILENCE_SECS
            || self.now.saturating_sub(self.health.phase_since) < health::SILENCE_SECS;
        let healthy = self.serving && carrier && recent;
        let detail = if !carrier {
            "Ethernet link is down. The keeper is not treating that as a router failure.".into()
        } else if !self.serving {
            "Not answering yet.".into()
        } else if !lte {
            "Answering from the pinned block. The LTE bearer is down, so delegated traffic cannot flow yet.".into()
        } else if healthy {
            "Router has a current advertisement and the delegated prefix matches the pin.".into()
        } else {
            format!("Router looks quiet. {}", health::decision_reason(decision))
        };
        self.publish(&self.report(live, Some(block), healthy, &detail), &detail);
    }

    fn act(&mut self, decision: Decision, block: Block) {
        match decision {
            Decision::Hold | Decision::StopServing => {}
            Decision::Reannounce => {
                if self.serving {
                    self.send_advertisement(block, health::decision_reason(decision));
                }
            }
            Decision::Restart => {
                self.note(health::decision_reason(decision));
                if let Err(err) = self.reinstall_filter() {
                    self.stop_serving(&format!("responder restart failed: {err}"));
                    self.serve_retry_at = self.now + SERVE_RETRY;
                } else {
                    self.send_advertisement(block, health::decision_reason(decision));
                }
            }
            Decision::LinkDrop { repeats } => {
                // The caller saved the budget first. `ip link set eth0 down` does not make this router solicit.
                // A burst of renegotiations left it silent. One does, and the
                // solicitation is answered in this same loop. `repeats` is the
                // budget step (1, then 8, then 20), not a repeat count.
                let (program, args) = link_recovery();
                self.note(&format!(
                    "{} (one {program} renegotiation of eth0; budget step {repeats}; this is not an LTE re-attach)",
                    health::decision_reason(decision)
                ));
                let _ = crate::command::output(Command::new(program).args(args));
                self.now = monotonic();
                self.note("Ethernet renegotiation requested");
            }
            Decision::BudgetSpent => self.note(health::decision_reason(decision)),
        }
    }

    fn start_serving(&mut self, block: Block) -> Result<(), String> {
        self.ensure_sockets(true)?;
        let sniffed = self.sniff_core_ra()?;
        self.reinstall_filter()?;
        self.hold_sysctl();
        let prefixes = if sniffed.prefixes.is_empty() {
            vec![block.link64()]
        } else {
            sniffed.prefixes
        };
        let source = sniffed.source_mac.unwrap_or(CORE_MAC);
        self.core_mac = source;
        self.send_raw(
            all_nodes_mac(),
            &ra_packet(fe80_1(), prefixes_advert(&prefixes, source, true)),
            "withdraw the core router before advertising our own",
        );
        // An earlier advertisement used br0's link-local and eth0's MAC. Frames
        // to that MAC are not bridged to the bearer, so withdraw it once.
        if let Some(own) = link_local(&read_file("/proc/net/if_inet6"), BRIDGE) {
            let mac = interface_mac(CUSTOMER).unwrap_or([0; 6]);
            if mac != [0; 6] {
                let icmp = ra::emit(&Advertisement::withdraw(vec![block.link64()], mac));
                self.send_raw(
                    all_nodes_mac(),
                    &ra_packet(own, icmp),
                    "withdraw the advertisement that named the bridge MAC",
                );
            }
        }
        self.serving = true;
        self.health.phase = Phase::Idle;
        self.health.phase_since = self.now;
        self.last_ra = 0;
        self.send_advertisement(block, "started answering from the pinned block");
        Ok(())
    }

    fn reinstall_filter(&self) -> Result<(), String> {
        // The init script kills this process without removing the qdisc, and
        // prio creates a child on band 3 by itself. `qdisc add` of the
        // blackhole then returns EEXIST. Take the old root off first.
        // ENOENT means the port is already on the built-in pfifo_fast.
        // The install that follows is the only configuration we advertise
        // behind, so a failed install still ends on pfifo_fast.
        let _ = tc_apply(&filter::remove(CUSTOMER));
        match tc_apply(&filter::install(CUSTOMER)) {
            Ok(()) => Ok(()),
            Err(err) => {
                let _ = tc_apply(&filter::remove(CUSTOMER));
                Err(err)
            }
        }
    }

    pub(super) fn stop_serving(&mut self, why: &str) {
        if self.serving {
            self.note(&format!("stopped answering: {why}"));
        }
        let _ = tc_apply(&filter::remove(CUSTOMER));
        self.restore_sysctl();
        self.serving = false;
        self.health.phase = Phase::Idle;
        self.health.phase_since = self.now;
    }

    fn send_advertisement(&mut self, block: Block, why: &str) {
        // Source fe80::1 and the core's MAC. The SMF answers neighbour
        // discovery for that address from the bearer side, and the bridge
        // forwards frames addressed to that MAC out lte0pdn1. Sourcing the
        // advertisement from br0 makes the router send those frames to eth0,
        // where the bridge keeps them.
        let mac = self.core_mac;
        let packet = ra_packet(
            fe80_1(),
            ra::emit(&Advertisement::for_block(block.link64(), mac)),
        );
        let frame = ethernet_frame(all_nodes_mac(), mac, &packet);
        let ifindex = interface_index(CUSTOMER).unwrap_or(0);
        match send_marked_frame(ifindex, &frame) {
            Ok(()) => self.note(why),
            Err(err) => self.note(&format!("send failed ({why}): {err}")),
        }
        self.last_ra = self.now;
    }

    fn send_raw(&mut self, dest_mac: [u8; 6], packet: &[u8], why: &str) {
        let Some(sockets) = self.sockets.as_ref() else {
            self.note(&format!(
                "did not send ({why}): customer port socket is closed"
            ));
            return;
        };
        let ifindex = interface_index(CUSTOMER).unwrap_or(0);
        match sockets.send_ipv6(ifindex, dest_mac, packet) {
            Ok(()) => self.note(why),
            Err(err) => self.note(&format!("send failed ({why}): {err}")),
        }
    }

    fn sniff_core_ra(&mut self) -> Result<Sniff, String> {
        self.ensure_sockets(true)?;
        let ipv6 = self
            .sockets
            .as_ref()
            .and_then(ControlSockets::ipv6_fd)
            .ok_or("IPv6 control socket is not open")?;
        crate::capture::install_ipv6(ipv6, true)?;
        let mut found = Sniff::default();
        let deadline = monotonic() + SNIFF_SECS;
        while monotonic() < deadline {
            self.now = monotonic();
            self.maintain_cbrs_gate();
            for event in self.collect_ipv6() {
                if let Class::RouterAdvertisement {
                    prefixes,
                    source_mac,
                } = event.kind
                {
                    if (event.outgoing || found.prefixes.is_empty()) && !prefixes.is_empty() {
                        found.prefixes = prefixes;
                        found.source_mac = source_mac;
                    }
                }
            }
            let ipv6 = self.sockets.as_ref().and_then(ControlSockets::ipv6_fd);
            let _ = titan_sys::poll::wait_readable(&[ipv6], Duration::from_millis(200));
        }
        if found.prefixes.is_empty() {
            self.note("no core advertisement seen before the filter; withdrawing the link prefix");
        } else {
            self.note(&format!(
                "core advertisement carried {}; withdrawing it from fe80::1",
                found.prefixes[0]
            ));
        }
        let restore = if let Some(ipv6) = self.sockets.as_ref().and_then(ControlSockets::ipv6_fd) {
            crate::capture::install_ipv6(ipv6, false)
        } else {
            Ok(())
        };
        let _ = self.collect_ipv6();
        restore?;
        Ok(found)
    }

    pub(super) fn drain(&mut self) {
        self.drain_arp();
        self.drain_dhcp();
        let events = self.collect_ipv6();
        if events.is_empty() {
            return;
        }
        let block = self.serving_block();
        for event in events {
            if event.outgoing || event.source_mac == Some(self.core_mac) {
                continue;
            }
            // Any IPv6 the router sends us shows it speaks IPv6.
            if !matches!(event.kind, Class::Other | Class::RouterAdvertisement { .. }) {
                self.ipv6_router = event.source_mac.or(self.ipv6_router);
            }
            match event.kind {
                Class::RouterSolicit => {
                    self.router_seen = true;
                    self.last_router = self.now;
                    self.solicit_pending = true;
                }
                Class::NeighbourForUs | Class::DelegatedTraffic => {
                    self.router_seen = true;
                    self.last_router = self.now;
                }
                Class::RouterProbe { source_mac } => {
                    if probe_keeps_delegation(
                        source_mac,
                        self.delegated_mac.map(|mac| (mac, self.delegated_at)),
                        self.now,
                    ) {
                        self.router_seen = true;
                        self.last_router = self.now;
                        self.note("router is probing fe80::1 and its delegation is still current");
                    } else if probe_ends_delegation(source_mac, self.delegated_mac) {
                        // Another router, with no prefix, is on the port. The
                        // old delegation must not keep the health check quiet.
                        self.delegated_mac = None;
                        self.note("a router with no delegation is probing fe80::1; the earlier delegation no longer holds the health check");
                    }
                }
                Class::DhcpV6 {
                    source_mac,
                    source,
                    payload,
                } => {
                    self.router_seen = true;
                    self.last_router = self.now;
                    if let Some(mac) = client_mac_of(&payload).or(source_mac) {
                        self.router_mac = ipv4::mac_text(mac);
                    }
                    if let Some(block) = block {
                        self.reply_dhcp(source_mac, source, &payload, block);
                    }
                }
                Class::RouterAdvertisement { .. } | Class::Other => {}
            }
        }
    }

    fn reply_dhcp(&mut self, mac: Option<[u8; 6]>, source: [u8; 16], payload: &[u8], block: Block) {
        let duid = server_duid();
        let Some(reply) = dhcpv6::respond(payload, &duid, block) else {
            return;
        };
        let Some(mac) = mac.or_else(|| client_mac_of(payload)) else {
            self.note("DHCPv6 request had no client MAC; not answering on a second path");
            return;
        };
        let Some(src) = link_local(&read_file("/proc/net/if_inet6"), BRIDGE) else {
            self.note("DHCPv6 request arrived before br0 had a link-local address");
            return;
        };
        let packet = udp_packet(src, source, &reply);
        self.delegated_mac = Some(mac);
        self.delegated_at = self.now;
        self.router_mac = ipv4::mac_text(mac);
        self.save_delegation();
        self.send_raw(mac, &packet, "DHCPv6 reply from the pinned block");
    }

    pub(super) fn serving_block(&mut self) -> Option<Block> {
        if !self.serving {
            return None;
        }
        let config = self.load_config_cached().ok().flatten()?;
        config.pinned_block().ok().flatten()
    }

    fn hold_sysctl(&mut self) {
        for path in [
            "/proc/sys/net/ipv6/conf/all/send_redirects",
            "/proc/sys/net/ipv6/conf/br0/send_redirects",
            "/proc/sys/net/ipv6/conf/eth0/send_redirects",
            "/proc/sys/net/ipv6/conf/br0/accept_ra",
            "/proc/sys/net/ipv6/conf/eth0/accept_ra",
        ] {
            if self.saved_sysctl.iter().any(|(saved, _)| saved == path) {
                continue;
            }
            if let Ok(previous) = fs::read_to_string(path) {
                self.saved_sysctl.push((path.into(), previous));
                let _ = fs::write(path, "0\n");
            }
        }
    }

    fn restore_sysctl(&mut self) {
        for (path, previous) in self.saved_sysctl.drain(..) {
            let _ = fs::write(path, previous);
        }
    }

    /// eth0 down long enough for a router swap: the old router's IPv6 history
    /// and delegation hold no longer apply. Our own renegotiation is shorter.
    fn note_eth0_carrier(&mut self, carrier: bool) {
        if carrier {
            self.eth0_down_since = None;
            return;
        }
        let since = *self.eth0_down_since.get_or_insert(self.now);
        if self.now.saturating_sub(since) >= ROUTER_SWAP_SECS {
            self.ipv6_router = None;
            self.delegated_mac = None;
        }
    }

    /// The router named in the status after a restart. The saved time is
    /// wall-clock and says nothing this boot's monotonic clock can use, so no
    /// delegation hold comes back: the router's next DHCPv6 makes a new one.
    pub(super) fn load_delegation(&mut self) {
        let Some((mac, _at)) = parse_delegation(&read_file(state_dir().join("router.txt"))) else {
            return;
        };
        self.router_mac = ipv4::mac_text(mac);
    }

    fn save_delegation(&self) {
        let Some(mac) = self.delegated_mac else {
            return;
        };
        let path = state_dir().join("router.txt");
        // The wall-clock time, for a person reading the file.
        let text = format_delegation(mac, unix_now());
        if read_file(&path) != text {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(path, text);
        }
    }

    fn clear_delegation(&mut self) {
        self.delegated_mac = None;
        self.delegated_at = 0;
        let path = state_dir().join("router.txt");
        if path.exists() {
            let _ = fs::remove_file(path);
        }
    }
}

fn ensure_pin(config: &Config, live: Option<Block>) -> Result<Option<Block>, String> {
    match config.pinned_block() {
        Ok(Some(block)) => Ok(Some(block)),
        Ok(None) => {
            let Some(live) = live else {
                return Ok(None);
            };
            let mut updated = config.clone();
            updated.pinned = Some(live.to_string());
            updated.pin_source = "learned".into();
            config::store_config(&state_dir().join("config.json"), &updated)
                .map_err(|err| format!("could not pin the block learned from the bearer: {err}"))?;
            log(&format!(
                "learned {live} from the first attach and pinned it"
            ));
            Ok(Some(live))
        }
        Err(err) => Err(format!("pinned block cannot be used: {err}")),
    }
}

fn server_duid() -> Vec<u8> {
    let mac = interface_mac(CUSTOMER).unwrap_or([0x44, 0x6f, 0xd8, 0x80, 0x11, 0xde]);
    let mut duid = vec![0, 3, 0, 1];
    duid.extend_from_slice(&mac);
    duid
}

fn format_delegation(mac: [u8; 6], at: u64) -> String {
    format!("mac={}\ndelegated_at={at}\n", ipv4::mac_text(mac))
}

fn parse_delegation(text: &str) -> Option<([u8; 6], u64)> {
    let mut mac = None;
    let mut at = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "mac" => mac = parse_mac(value.trim()),
            "delegated_at" => at = value.trim().parse().ok(),
            _ => {}
        }
    }
    Some((mac?, at?))
}

fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = text.split(':');
    for byte in &mut mac {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(mac)
}

/// A probe for fe80::1 is the router we delegated to, still inside the prefix
/// lifetime. Any other MAC is a router that has not taken the pin.
fn delegation_current(saved: Option<([u8; 6], u64)>, now: u64) -> bool {
    let Some((_, at)) = saved else {
        return false;
    };
    now.saturating_sub(at) < u64::from(titan_pd_model::dhcpv6::VALID)
}

fn probe_keeps_delegation(probe: Option<[u8; 6]>, saved: Option<([u8; 6], u64)>, now: u64) -> bool {
    let (Some(probe), Some((mac, at))) = (probe, saved) else {
        return false;
    };
    probe == mac && now.saturating_sub(at) < u64::from(titan_pd_model::dhcpv6::VALID)
}

/// Whether the customer bearer can carry delegated traffic: carrier, and
/// either its own global address or a place in the LAN bridge. The vendor
/// SDK removes a bridged bearer's own address after 18 h and it never comes
/// back in that session; up to v1.0.12 that turned IPv6 health off.
fn bearer_up(own_prefix: bool, bridged: bool, carrier: bool) -> bool {
    carrier && (own_prefix || bridged)
}

/// A neighbour probe for fe80::1 from a router other than the one we
/// delegated to: that router has no prefix (the stuck-prefix case), and the
/// earlier delegation must not keep the health check quiet for two hours.
fn probe_ends_delegation(probe: Option<[u8; 6]>, delegated: Option<[u8; 6]>) -> bool {
    matches!((probe, delegated), (Some(probe), Some(mac)) if probe != mac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use titan_pd_model::prefix::parse_pinned;

    use crate::run::packet::classify_ipv6;

    #[test]
    fn delegated_traffic_and_a_solicit_are_the_router_and_a_foreign_neighbour_is_not() {
        let block = parse_pinned("2001:db8:ff:d300::/64").unwrap();
        let mut traffic = vec![0u8; 40];
        traffic[0] = 0x60;
        traffic[8..24].copy_from_slice(&block.delegated57().addr);
        traffic[23] = 1;
        // Bulk IPv6 stays in the kernel; the port's receive counter stands in.
        assert!(crate::capture::tests::captured(&traffic, libc::ETH_P_IPV6, false).is_empty());
        // ICMPv6 from the delegated prefix, a host behind the router answering
        // a ping, is still captured and still counts.
        let mut echo = vec![0u8; 48];
        echo[0] = 0x60;
        echo[6] = 58;
        echo[8..24].copy_from_slice(&block.delegated57().addr);
        echo[23] = 1;
        echo[40] = 129;
        let echo = crate::capture::tests::captured(&echo, libc::ETH_P_IPV6, false);
        assert!(matches!(
            classify_ipv6(&echo, Some(block.delegated57()), None),
            Class::DelegatedTraffic
        ));
        let mut solicit = vec![0u8; 48];
        solicit[0] = 0x60;
        solicit[6] = 58;
        solicit[40] = 133;
        assert_eq!(classify_ipv6(&solicit, None, None), Class::RouterSolicit);
        let ours =
            link_local("fe80000000000000466fd8fffe8011de 02 40 20 80 br0\n", BRIDGE).unwrap();
        let mut neighbour = vec![0u8; 64];
        neighbour[0] = 0x60;
        neighbour[6] = 58;
        neighbour[40] = 135;
        neighbour[48..64].copy_from_slice(&fe80_1());
        assert_eq!(
            classify_ipv6(&neighbour, None, Some(ours)),
            Class::RouterProbe { source_mac: None }
        );
        let mac = [0x24, 0x2f, 0xd0, 0xb8, 0xf1, 0x9d];
        let other = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        assert!(probe_keeps_delegation(
            Some(mac),
            Some((mac, 1_000)),
            1_000 + 7_199
        ));
        assert!(!probe_keeps_delegation(
            Some(mac),
            Some((mac, 1_000)),
            1_000 + u64::from(titan_pd_model::dhcpv6::VALID)
        ));
        assert!(!probe_keeps_delegation(
            Some(other),
            Some((mac, 1_000)),
            1_100
        ));
        assert!(!probe_keeps_delegation(Some(mac), None, 1_100));
        assert!(delegation_current(Some((mac, 1_000)), 1_000 + 7_199));
        assert!(!delegation_current(None, 1_100));
        assert_eq!(
            parse_delegation(&format_delegation(mac, 1_790_958_442)),
            Some((mac, 1_790_958_442))
        );
        neighbour[48..64].copy_from_slice(&ours);
        assert_eq!(
            classify_ipv6(&neighbour, None, Some(ours)),
            Class::NeighbourForUs
        );
    }

    #[test]
    fn the_bearer_stays_up_after_the_vendor_flushes_its_address() {
        // Eighteen hours into a session the vendor SDK removes the bridged
        // bearer's own global address, and it never comes back. The bearer
        // still carries the delegated prefix.
        assert!(bearer_up(false, true, true));
        assert!(bearer_up(true, false, true));
        assert!(bearer_up(true, true, true));
        assert!(!bearer_up(true, true, false));
        assert!(!bearer_up(false, false, true));
    }

    #[test]
    fn a_probe_from_another_router_ends_the_delegation_hold() {
        let delegated = [0x02, 0, 0, 0, 0, 0x0a];
        let other = [0x02, 0, 0, 0, 0, 0x0b];
        assert!(probe_ends_delegation(Some(other), Some(delegated)));
        assert!(!probe_ends_delegation(Some(delegated), Some(delegated)));
        assert!(!probe_ends_delegation(None, Some(delegated)));
        assert!(!probe_ends_delegation(Some(other), None));
    }
}
