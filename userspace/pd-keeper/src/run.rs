//! Wire loop for the prefix keeper.
//!
//! The Titan answers router solicitations and DHCPv6 from the pinned block on
//! eth0, and a filter on that port drops the core's advertisements and DHCPv6
//! replies. The router therefore hears one server, including while LTE is down
//! or still dialling. Sends are injected on eth0 so they are not bridged back
//! up the bearer. IPv4 passthrough repair runs in the same process even when
//! prefix delegation is off. Management IPv6 is brought up on lte0pdn0 from
//! the modem's assigned interface identifier, including when delegation is off.

use std::fs;
use std::io::{self, ErrorKind};
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use std::os::unix::process::CommandExt;
use titan_pd_model::config::{self, Config, Report};
use titan_pd_model::dhcpv6::{self, client_mac};
use titan_pd_model::filter;
use titan_pd_model::health::{self, Decision, Health, Phase, View};
use titan_pd_model::ipv4::{self, Ipv4Plan};
use titan_pd_model::ipv4_health::{self, Action as Ipv4Action, Peer};
use titan_pd_model::mgmt::{self, Step};
use titan_pd_model::prefix::Block;
use titan_pd_model::ra::{self, Advertisement};

use crate::log;

const CUSTOMER: &str = "eth0";
const BRIDGE: &str = "br0";
const BEARER: &str = "lte0pdn1";
const RA_INTERVAL: u64 = 45;
const SNIFF_SECS: u64 = 3;
const SERVE_RETRY: u64 = 60;
const FLOOD_INTERVAL: u64 = 30;
const DHCP_COOLDOWN: u64 = 15;
const MGMT_EVERY: u64 = 10;
const MGMT_LOG_EVERY: u64 = 60;

const SO_MARK: libc::c_int = 36;
const PACKET_OUTGOING: u8 = 4;
/// Source link-layer address of the core's router advertisement on this EPC.
/// Data frames have to be addressed to this MAC so the bridge forwards them
/// out lte0pdn1. Addressing them to eth0 makes the bridge deliver them locally.
const CORE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x01, 0x01];

struct Packet {
    fd: libc::c_int,
}

impl Drop for Packet {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
            self.fd = -1;
        }
    }
}

struct Keeper {
    packet: Option<Packet>,
    serving: bool,
    health: Health,
    now: u64,
    last_ra: u64,
    last_router: u64,
    last_dhcp_restart: u64,
    last_dhcp_probe: u64,
    ipv4_watch: ipv4_health::Watch,
    last_ipv4_check: u64,
    dhcp_child: Option<std::process::Child>,
    last_flood: u64,
    serve_retry_at: u64,
    router_seen: bool,
    solicit_pending: bool,
    discover: Option<[u8; 6]>,
    router_mac: String,
    /// Ethernet source we last handed a prefix, and the unix time of that reply.
    /// A later neighbour probe for fe80::1 from this MAC is the router staying
    /// up. A probe from anyone else is the stuck-prefix case and does not count.
    delegated_mac: Option<[u8; 6]>,
    delegated_at: u64,
    last_action: String,
    last_action_at: u64,
    logged_idle: bool,
    logged_unreadable: bool,
    passthrough: bool,
    core_mac: [u8; 6],
    saved_sysctl: Vec<(String, String)>,
    last_logged: String,
    last_logged_at: u64,
    last_mgmt: u64,
    last_mgmt_log: u64,
    mgmt_up_logged: bool,
}

pub fn serve() -> Result<(), String> {
    log("keeper started");
    let mut keeper = Keeper::new();
    keeper.load_budget();
    keeper.load_delegation();
    loop {
        keeper.now = monotonic();
        if let Err(err) = keeper.tick() {
            keeper.note(&format!("tick failed: {err}"));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

pub fn tc_apply(lines: &[String]) -> Result<(), String> {
    let program = std::env::var("TITAN_TC").unwrap_or_else(|_| "tc".into());
    for line in lines {
        let output = Command::new(&program)
            .args(line.split_whitespace())
            .output()
            .map_err(|err| format!("tc {line}: {err}"))?;
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(format!("tc {line}: {}", err.trim()));
        }
    }
    Ok(())
}

impl Keeper {
    fn new() -> Self {
        Self {
            packet: None,
            serving: false,
            health: Health::default(),
            now: 0,
            last_ra: 0,
            last_router: 0,
            last_dhcp_restart: 0,
            last_dhcp_probe: 0,
            ipv4_watch: ipv4_health::Watch::default(),
            last_ipv4_check: 0,
            dhcp_child: None,
            last_flood: 0,
            serve_retry_at: 0,
            router_seen: false,
            solicit_pending: false,
            discover: None,
            router_mac: String::new(),
            delegated_mac: None,
            delegated_at: 0,
            last_action: String::new(),
            last_action_at: 0,
            logged_idle: false,
            logged_unreadable: false,
            passthrough: false,
            core_mac: CORE_MAC,
            saved_sysctl: Vec::new(),
            last_logged: String::new(),
            last_logged_at: 0,
            last_mgmt: 0,
            last_mgmt_log: 0,
            mgmt_up_logged: false,
        }
    }

    fn tick(&mut self) -> Result<(), String> {
        self.maintain_mgmt_v6();
        self.passthrough = passthrough_now();
        if !self.passthrough {
            self.ipv4_watch.reset();
            if self.serving {
                self.stop_serving("left IP passthrough");
            }
            if !self.logged_idle {
                self.note(
                    "idle: not IP passthrough, so prefix delegation and the DHCP repair stay off",
                );
                self.logged_idle = true;
            }
            self.publish(
                &Report::default(),
                "IPv6 prefix delegation stays off outside IP passthrough",
            );
            thread::sleep(Duration::from_secs(1));
            return Ok(());
        }
        self.logged_idle = false;
        self.ensure_packet()?;
        self.drain();
        self.maintain_ipv4();
        self.maintain_ipv4_link();

        let loaded = config::load_config(&state_dir().join("config.json"));
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
                return Ok(());
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
            return Ok(());
        };
        if !config.enabled {
            if self.serving {
                self.stop_serving("prefix delegation is off");
            }
            self.publish(
                &Report::default(),
                "IPv6 prefix delegation is off. The customer bearer is IPv4.",
            );
            return Ok(());
        };

        let live = global_prefix(&command_stdout(
            "ip",
            &["-6", "addr", "show", "dev", BEARER],
        ));
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
                return Ok(());
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
            return Ok(());
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
                return Ok(());
            }
        }

        let carrier = carrier_up(CUSTOMER);
        let lte = live.is_some() && carrier_up(BEARER);
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
            unix_now(),
        );
        let decision = self.health.tick(&View {
            now: self.now,
            carrier_up: carrier,
            lte_up: lte,
            prefix_ok: true,
            serving: self.serving,
            router_seen: self.router_seen || held,
        });
        self.router_seen = false;
        self.act(decision, block);
        self.save_budget();
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
        Ok(())
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
                if !self.save_budget() {
                    self.note("Ethernet recovery skipped: cannot persist the shared action budget");
                    return;
                }
                // `ip link set eth0 down` does not make this router solicit.
                // A burst of renegotiations left it silent. One does, and the
                // solicitation is answered in this same loop. `repeats` is the
                // budget step (1, then 8, then 20), not a repeat count.
                let (program, args) = link_recovery();
                self.note(&format!(
                    "{} (one {program} renegotiation of eth0; budget step {repeats}; this is not an LTE re-attach)",
                    health::decision_reason(decision)
                ));
                let _ = Command::new(program).args(args).status();
                self.now = monotonic();
                self.note("Ethernet renegotiation requested");
            }
            Decision::BudgetSpent => self.note(health::decision_reason(decision)),
        }
    }

    fn start_serving(&mut self, block: Block) -> Result<(), String> {
        self.ensure_packet()?;
        let sniffed = self.sniff_core_ra();
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

    fn stop_serving(&mut self, why: &str) {
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
        let Some(socket) = self.packet.as_ref() else {
            self.note(&format!(
                "did not send ({why}): customer port socket is closed"
            ));
            return;
        };
        let ifindex = interface_index(CUSTOMER).unwrap_or(0);
        match send_ipv6(socket.fd, ifindex, dest_mac, packet) {
            Ok(()) => self.note(why),
            Err(err) => self.note(&format!("send failed ({why}): {err}")),
        }
    }

    fn sniff_core_ra(&mut self) -> Sniff {
        let mut found = Sniff::default();
        let deadline = monotonic() + SNIFF_SECS;
        while monotonic() < deadline {
            for event in self.collect() {
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
            thread::sleep(Duration::from_millis(50));
        }
        if found.prefixes.is_empty() {
            self.note("no core advertisement seen before the filter; withdrawing the link prefix");
        } else {
            self.note(&format!(
                "core advertisement carried {}; withdrawing it from fe80::1",
                found.prefixes[0]
            ));
        }
        found
    }

    fn ensure_packet(&mut self) -> Result<(), String> {
        if self.packet.is_some() {
            return Ok(());
        }
        let ifindex = interface_index(CUSTOMER).ok_or("eth0 has no interface index")?;
        let fd = open_packet(ifindex)?;
        self.packet = Some(Packet { fd });
        Ok(())
    }

    fn drain(&mut self) {
        let block = self.serving_block();
        for event in self.collect() {
            if event.outgoing {
                continue;
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
                        unix_now(),
                    ) {
                        self.router_seen = true;
                        self.last_router = self.now;
                        self.note("router is probing fe80::1 and its delegation is still current");
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

    fn collect(&mut self) -> Vec<Event> {
        let Some(socket) = self.packet.as_ref() else {
            return Vec::new();
        };
        let fd = socket.fd;
        let our = link_local(&read_file("/proc/net/if_inet6"), BRIDGE);
        let delegated = self.serving_block().map(|block| block.delegated57());
        let mut events = Vec::new();
        loop {
            let mut buf = [0u8; 2048];
            let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            let n = unsafe {
                libc::recvfrom(
                    fd,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    0,
                    (&mut addr as *mut libc::sockaddr_ll).cast(),
                    &mut len,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::Interrupted {
                    break;
                }
                break;
            }
            let packet = &buf[..n as usize];
            let outgoing = addr.sll_pkttype == PACKET_OUTGOING;
            let protocol = u16::from_be(addr.sll_protocol);
            if protocol == libc::ETH_P_ARP as u16 && !outgoing && addr.sll_halen >= 6 {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&addr.sll_addr[..6]);
                if self.ipv4_watch.reply(self.now, packet, mac) {
                    self.note("IPv4 router answered local ARP; automatic recovery is armed");
                }
                continue;
            }
            if protocol == libc::ETH_P_IP as u16 {
                if !outgoing {
                    if let Some(mac) = dhcp_client_mac(packet) {
                        self.discover = Some(mac);
                    }
                }
                continue;
            }
            if protocol != libc::ETH_P_IPV6 as u16 {
                continue;
            }
            let mut kind = classify_ipv6(packet, delegated, our);
            let mac = (addr.sll_halen >= 6).then(|| {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&addr.sll_addr[..6]);
                mac
            });
            match kind {
                Class::DhcpV6 {
                    source, payload, ..
                } => {
                    kind = Class::DhcpV6 {
                        source_mac: mac,
                        source,
                        payload,
                    };
                }
                Class::RouterProbe { .. } => {
                    kind = Class::RouterProbe { source_mac: mac };
                }
                _ => {}
            }
            events.push(Event { kind, outgoing });
        }
        events
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
        self.delegated_at = unix_now();
        self.router_mac = ipv4::mac_text(mac);
        self.save_delegation();
        self.send_raw(mac, &packet, "DHCPv6 reply from the pinned block");
    }

    fn serving_block(&self) -> Option<Block> {
        if !self.serving {
            return None;
        }
        let config = config::load_config(&state_dir().join("config.json"))
            .ok()
            .flatten()?;
        config.pinned_block().ok().flatten()
    }

    fn maintain_ipv4(&mut self) {
        // Reap a daemon that exited on its own before considering a restart.
        if let Some(child) = &mut self.dhcp_child {
            if !matches!(child.try_wait(), Ok(None)) {
                self.dhcp_child = None;
            }
        }
        if self.now.saturating_sub(self.last_flood) >= FLOOD_INTERVAL {
            let first = self.last_flood == 0;
            let mut failed = None;
            for line in ipv4::flood_commands() {
                if let Err(err) = ebtables(line) {
                    failed = Some(err);
                }
            }
            self.last_flood = self.now;
            if let Some(err) = failed {
                self.note(&format!("DHCP flood rules were not installed: {err}"));
            } else if first {
                self.note("scoped DHCP so discover and offers stay off the customer bearer");
            }
        }
        let routes = command_stdout("ip", &["route"]);
        let conf = read_file("/tmp/udhcpd.conf");
        let lease = fs::read("/tmp/udhcpd.leases").unwrap_or_default();
        let discover = self.discover.take();
        let cooldown = self.now.saturating_sub(self.last_dhcp_restart) >= DHCP_COOLDOWN;
        // All DHCP mutations share the cooldown, including repeated vendor
        // rewrites. Do not turn a broken server into a process/restart storm.
        if !cooldown {
            return;
        }
        let plan =
            ipv4::plan_maintenance(&conf, &routes, &lease, discover, cooldown).or_else(|| {
                if self.now.saturating_sub(self.last_dhcp_probe) < 5 {
                    return None;
                }
                self.last_dhcp_probe = self.now;
                let running = !customer_dhcp_pids(&command_stdout("ps", &[])).is_empty();
                ipv4::restart_missing_server(&conf, &routes, running)
            });
        let Some(plan) = plan else {
            return;
        };
        // While the bearer route is absent the stock server offers a LAN
        // address. Killing it on every 200 ms tick fills the log and the
        // process table.
        self.apply_ipv4(&plan);
    }

    fn apply_ipv4(&mut self, plan: &Ipv4Plan) {
        self.note(&plan.reason);
        if plan.stop_lan_offer {
            stop_customer_udhcpd();
            self.last_dhcp_restart = self.now;
            return;
        }
        if let Some(text) = &plan.rewrite {
            if fs::write("/tmp/udhcpd.conf", text).is_err() {
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
            self.last_dhcp_restart = self.now;
        }
    }

    fn maintain_ipv4_link(&mut self) {
        if self.now == self.last_ipv4_check {
            return;
        }
        self.last_ipv4_check = self.now;
        let conf_text = read_file("/tmp/udhcpd.conf");
        let peer = (|| {
            if !carrier_up(CUSTOMER) || !carrier_up(BEARER) {
                return None;
            }
            let conf = ipv4::parse_conf(&conf_text)?;
            if (conf.interface != "br0:9" && conf.interface != BRIDGE) || !conf.remaining_yes {
                return None;
            }
            let bearer = ipv4::host_route_on(&command_stdout("ip", &["route"]), BRIDGE)?;
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
            let local_address = bridge_probe_address(
                &command_stdout("ip", &["-4", "-o", "addr", "show", "dev", BRIDGE]),
                bearer,
            )?;
            Some(Peer {
                address: bearer,
                mac,
                local_address,
                local_mac,
            })
        })();
        match self.ipv4_watch.tick(self.now, peer) {
            Ipv4Action::Hold => {}
            Ipv4Action::Probe(peer) => {
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
                if self.now.saturating_sub(self.last_dhcp_restart) >= DHCP_COOLDOWN {
                    self.apply_ipv4(&Ipv4Plan {
                        stop_lan_offer: false,
                        rewrite: Some(conf_text),
                        clear_lease: false,
                        reason:
                            "refreshing the current DHCP offer after local IPv4 reachability failed"
                                .into(),
                    });
                }
            }
            Ipv4Action::Renegotiate => {
                let decision = self.health.request_link_recovery(self.now);
                // Persist before touching the link; a supervisor restart must
                // not erase the shared IPv4/IPv6 action budget.
                if !self.save_budget() {
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

    /// Install the core-assigned interface id on ue-mgmt and solicit from it.
    /// Runs in NAT and in passthrough, whether or not prefix delegation is on.
    fn maintain_mgmt_v6(&mut self) {
        if self.now.saturating_sub(self.last_mgmt) < MGMT_EVERY && self.last_mgmt != 0 {
            return;
        }
        self.last_mgmt = self.now;
        if !carrier_up(mgmt::MGMT_DEV) {
            return;
        }
        let dmesg = command_stdout("dmesg", &[]);
        let iid = match mgmt::assigned_iid(&dmesg).or_else(|| cached_mgmt_iid()) {
            Some(iid) => iid,
            None => return,
        };
        if mgmt::assigned_iid(&dmesg).is_some() {
            let _ = fs::write(
                state_dir().join("mgmt-iid.txt"),
                format!("{}\n", iid.token()),
            );
        }
        let addrs = command_stdout("ip", &["-6", "addr", "show", "dev", mgmt::MGMT_DEV]);
        let accept = read_file("/proc/sys/net/ipv6/conf/lte0pdn0/accept_ra");
        let routes = command_stdout("ip", &["-6", "route", "show"]);
        let up = mgmt::global_up(iid, &addrs);
        let steps = mgmt::plan(iid, &addrs, &accept, &routes);
        if up && !self.mgmt_up_logged {
            self.note(&format!(
                "ue-mgmt ipv6 is up ({})",
                addrs_global_text(&addrs).unwrap_or_else(|| iid.link_local().to_string())
            ));
            self.mgmt_up_logged = true;
        }
        if up {
            self.scrub_mgmt_off_lan(&addrs);
        }
        if !up {
            self.mgmt_up_logged = false;
            if self.now.saturating_sub(self.last_mgmt_log) >= MGMT_LOG_EVERY {
                self.note(&format!(
                    "ue-mgmt has no global; soliciting from {} so the assigned prefix can come up",
                    iid.link_local()
                ));
                self.last_mgmt_log = self.now;
            }
        }
        for step in steps {
            if let Err(err) = self.apply_mgmt(step) {
                self.note(&format!("ue-mgmt ipv6: {err}"));
            }
        }
    }

    fn apply_mgmt(&self, step: Step) -> Result<(), String> {
        match step {
            Step::AcceptAdvertisements => {
                fs::write("/proc/sys/net/ipv6/conf/lte0pdn0/accept_ra", "2\n")
                    .map_err(|err| format!("accept_ra: {err}"))
            }
            Step::AddLinkLocal(addr) => {
                let spec = format!("{addr}/64");
                match run_status(
                    "ip",
                    &["-6", "addr", "add", &spec, "dev", mgmt::MGMT_DEV, "nodad"],
                ) {
                    Err(err) if err.contains("exists") => Ok(()),
                    other => other,
                }
            }
            Step::Solicit(addr) => solicit_mgmt(addr),
            Step::PreferManagementDefault => run_status(
                "ip",
                &[
                    "-6",
                    "route",
                    "replace",
                    "default",
                    "via",
                    "fe80::1",
                    "dev",
                    mgmt::MGMT_DEV,
                    "metric",
                    "1",
                ],
            ),
        }
    }

    /// The vendor IPv6 hook treats a learned management prefix as a LAN prefix.
    fn scrub_mgmt_off_lan(&mut self, mgmt_addrs: &str) {
        let Some(global) = addrs_global_text(mgmt_addrs).and_then(|text| text.parse().ok()) else {
            return;
        };
        for path in ["/var/config/resolv.conf", "/etc/resolv.conf"] {
            let current = read_file(path);
            let Some(cleaned) = mgmt::without_zero_nameserver(&current) else {
                continue;
            };
            if fs::write(path, &cleaned).is_ok() {
                self.note("removed the unspecified IPv6 nameserver from resolv.conf");
            }
        }
        let bridge = command_stdout("ip", &["-6", "addr", "show", "dev", BRIDGE]);
        for addr in mgmt::bridge_globals_in_prefix(&bridge, global) {
            let spec = format!("{addr}/128");
            match run_status("ip", &["-6", "addr", "del", &spec, "dev", BRIDGE]) {
                Ok(()) => self.note(&format!(
                    "removed {addr} from the customer bridge; it is the management prefix"
                )),
                Err(err) => self.note(&format!("could not remove {addr} from the bridge: {err}")),
            }
        }
    }

    fn report(
        &self,
        live: Option<Block>,
        pin: Option<Block>,
        healthy: bool,
        detail: &str,
    ) -> Report {
        Report {
            bearer_prefix: live
                .map(|block| block.link64().to_string())
                .unwrap_or_default(),
            delegated_prefix: pin
                .map(|block| block.delegated57().to_string())
                .unwrap_or_default(),
            router_mac: self.router_mac.clone(),
            healthy,
            detail: detail.into(),
            last_action: self.last_action.clone(),
            last_action_at: self.last_action_at.to_string(),
            serving: self.serving,
            mismatch: String::new(),
        }
    }

    fn publish(&self, report: &Report, detail: &str) {
        let mut report = report.clone();
        // Report::default() already carries "Keeper has not reported yet".
        // A caller that passes a real line must replace that placeholder.
        report.detail = published_detail(&report.detail, detail);
        // IPv4 recovery still has useful actions to report when IPv6 is off.
        report.last_action = self.last_action.clone();
        report.last_action_at = self.last_action_at.to_string();
        let path = state_dir().join("status.json");
        if config::load_report(&path).as_ref() != Some(&report) {
            let _ = config::store_report(&path, &report);
        }
    }

    fn note(&mut self, line: &str) {
        // The loop is 200 ms. An unchanged failure must not fill the log, but a
        // periodic advertisement and a real action are recorded every time.
        let always = [
            "periodic router advertisement",
            "router solicitation",
            "link drop",
            "learned ",
            "stopped answering",
            "withdraw",
            "DHCPv6",
            "udhcpd",
            "IPv4 router answered",
        ]
        .iter()
        .any(|part| line.contains(part));
        let repeat = line == self.last_logged && self.now.saturating_sub(self.last_logged_at) < 60;
        if !repeat || always {
            self.last_action_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            self.last_logged = line.to_owned();
            self.last_logged_at = self.now;
            log(line);
        }
        self.last_action = line.to_owned();
    }

    fn load_delegation(&mut self) {
        let Some((mac, at)) = parse_delegation(&read_file(
            &state_dir().join("router.txt").to_string_lossy(),
        )) else {
            return;
        };
        self.delegated_mac = Some(mac);
        self.delegated_at = at;
        self.router_mac = ipv4::mac_text(mac);
    }

    fn save_delegation(&self) {
        let Some(mac) = self.delegated_mac else {
            return;
        };
        let path = state_dir().join("router.txt");
        let text = format_delegation(mac, self.delegated_at);
        if read_file(&path.to_string_lossy()) != text {
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

    fn load_budget(&mut self) {
        let text = read_file(&state_dir().join("budget.txt").to_string_lossy());
        for line in text.lines() {
            if let Some((key, value)) = line.split_once('=') {
                let Ok(value) = value.trim().parse::<u64>() else {
                    continue;
                };
                match key.trim() {
                    "link_drops" => {
                        self.health.link_drops = u32::try_from(value).unwrap_or(u32::MAX)
                    }
                    "window_start" => self.health.window_start = value,
                    "quiet_until" => self.health.quiet_until = value,
                    _ => {}
                }
            }
        }
    }

    fn save_budget(&self) -> bool {
        let path = state_dir().join("budget.txt");
        let text = format!(
            "link_drops={}\nwindow_start={}\nquiet_until={}\n",
            self.health.link_drops, self.health.window_start, self.health.quiet_until
        );
        if read_file(&path.to_string_lossy()) != text {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let temporary = path.with_extension("new");
            let saved = (|| -> io::Result<()> {
                fs::write(&temporary, &text)?;
                fs::File::open(&temporary)?.sync_all()?;
                fs::rename(&temporary, &path)?;
                fs::File::open(
                    path.parent()
                        .ok_or_else(|| io::Error::other("no budget directory"))?,
                )?
                .sync_all()
            })();
            if saved.is_err() {
                return false;
            }
        }
        read_file(&path.to_string_lossy()) == text
    }
}

// Probe from an address actually owned by the bridge. Never claim the
// customer's bearer or the EPC gateway's address/MAC.
fn bridge_probe_address(text: &str, bearer: std::net::Ipv4Addr) -> Option<std::net::Ipv4Addr> {
    text.lines().find_map(|line| {
        let words: Vec<_> = line.split_whitespace().collect();
        let i = words.iter().position(|word| *word == "inet")?;
        let ip: std::net::Ipv4Addr = words.get(i + 1)?.split('/').next()?.parse().ok()?;
        (!ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback() && ip != bearer)
            .then_some(ip)
    })
}

struct Event {
    kind: Class,
    outgoing: bool,
}

#[derive(Default)]
struct Sniff {
    prefixes: Vec<Block>,
    source_mac: Option<[u8; 6]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Class {
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

fn classify_ipv6(packet: &[u8], delegated: Option<Block>, our: Option<[u8; 16]>) -> Class {
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
pub fn dhcp_client_mac(packet: &[u8]) -> Option<[u8; 6]> {
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

fn client_mac_of(payload: &[u8]) -> Option<[u8; 6]> {
    dhcpv6::parse(payload).and_then(|message| client_mac(&message.client_id))
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

fn prefixes_advert(prefixes: &[Block], mac: [u8; 6], withdraw: bool) -> Vec<u8> {
    let advert = if withdraw {
        Advertisement::withdraw(prefixes.to_vec(), mac)
    } else {
        Advertisement::for_block(prefixes[0], mac)
    };
    ra::emit(&advert)
}

fn ra_packet(src: [u8; 16], mut icmp: Vec<u8>) -> Vec<u8> {
    let dest = ff02_1();
    let sum = checksum(&src, &dest, 58, &icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    ipv6_packet(src, dest, 255, 58, &icmp)
}

fn udp_packet(src: [u8; 16], dest: [u8; 16], payload: &[u8]) -> Vec<u8> {
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

fn open_packet(ifindex: i32) -> Result<libc::c_int, String> {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        return Err(format!(
            "customer port socket: {}",
            io::Error::last_os_error()
        ));
    }
    if let Err(err) = setsockopt_int(fd, libc::SOL_SOCKET, SO_MARK, filter::MARK as i32) {
        unsafe { libc::close(fd) };
        return Err(err);
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags >= 0 {
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as libc::sa_family_t;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = ifindex;
    let bound = unsafe {
        libc::bind(
            fd,
            (&addr as *const libc::sockaddr_ll).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if bound != 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(format!("bind customer port: {err}"));
    }
    Ok(fd)
}

fn send_ipv6(
    fd: libc::c_int,
    ifindex: i32,
    dest_mac: [u8; 6],
    packet: &[u8],
) -> Result<(), String> {
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as libc::sa_family_t;
    addr.sll_protocol = (libc::ETH_P_IPV6 as u16).to_be();
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    addr.sll_addr[..6].copy_from_slice(&dest_mac);
    let sent = unsafe {
        libc::sendto(
            fd,
            packet.as_ptr().cast(),
            packet.len(),
            0,
            (&addr as *const libc::sockaddr_ll).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if sent == packet.len() as isize {
        Ok(())
    } else {
        Err(io::Error::last_os_error().to_string())
    }
}

fn setsockopt_int(
    fd: libc::c_int,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> Result<(), String> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().to_string())
    }
}

fn server_duid() -> Vec<u8> {
    let mac = interface_mac(CUSTOMER).unwrap_or([0x44, 0x6f, 0xd8, 0x80, 0x11, 0xde]);
    let mut duid = vec![0, 3, 0, 1];
    duid.extend_from_slice(&mac);
    duid
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

fn fe80_1() -> [u8; 16] {
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

fn all_nodes_mac() -> [u8; 6] {
    [0x33, 0x33, 0x00, 0x00, 0x00, 0x01]
}

/// What a link-drop budget step runs. One PHY renegotiation. Not a burst,
/// and not an administrative carrier down, which this router ignores.
fn link_recovery() -> (&'static str, &'static [&'static str]) {
    ("mii-tool", &["-r", CUSTOMER])
}

fn ethernet_frame(dest: [u8; 6], source: [u8; 6], packet: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + packet.len());
    frame.extend_from_slice(&dest);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(packet);
    frame
}

/// SOCK_RAW so the Ethernet source can be the core's MAC. The receive socket
/// stays SOCK_DGRAM. The mark lets this advertisement through our own filter.
fn send_marked_frame(ifindex: i32, frame: &[u8]) -> Result<(), String> {
    if frame.len() < 14 {
        return Err("Ethernet frame is truncated".into());
    }
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        return Err(format!("raw send socket: {}", io::Error::last_os_error()));
    }
    let marked = setsockopt_int(fd, libc::SOL_SOCKET, SO_MARK, filter::MARK as i32);
    let result = marked.and_then(|_| {
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as libc::sa_family_t;
        addr.sll_protocol = u16::from_be_bytes([frame[12], frame[13]]).to_be();
        addr.sll_ifindex = ifindex;
        addr.sll_halen = 6;
        if frame.len() >= 6 {
            addr.sll_addr[..6].copy_from_slice(&frame[..6]);
        }
        let sent = unsafe {
            libc::sendto(
                fd,
                frame.as_ptr().cast(),
                frame.len(),
                0,
                (&addr as *const libc::sockaddr_ll).cast(),
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if sent == frame.len() as isize {
            Ok(())
        } else {
            Err(io::Error::last_os_error().to_string())
        }
    });
    unsafe { libc::close(fd) };
    result
}

pub fn link_local(text: &str, dev: &str) -> Option<[u8; 16]> {
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

pub fn global_prefix(text: &str) -> Option<Block> {
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("inet6 ") else {
            continue;
        };
        if !rest.contains("scope global") {
            continue;
        }
        let Some((addr, len)) = rest.split_whitespace().next()?.split_once('/') else {
            continue;
        };
        if len != "64" {
            continue;
        }
        let Ok(addr) = addr.parse::<Ipv6Addr>() else {
            continue;
        };
        return Some(Block::containing_56(addr.octets()));
    }
    None
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

fn interface_mac(dev: &str) -> Option<[u8; 6]> {
    let text = read_file(&format!("/sys/class/net/{dev}/address"));
    let mut mac = [0u8; 6];
    let parts: Vec<_> = text.trim().split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    for (index, part) in parts.iter().enumerate() {
        mac[index] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

fn interface_index(dev: &str) -> Option<i32> {
    read_file(&format!("/sys/class/net/{dev}/ifindex"))
        .trim()
        .parse()
        .ok()
}

fn carrier_up(dev: &str) -> bool {
    read_file(&format!("/sys/class/net/{dev}/carrier")).trim() == "1"
}

fn passthrough_now() -> bool {
    if std::path::Path::new(&format!("/sys/class/net/br0/brif/{BEARER}")).exists() {
        return true;
    }
    let output = command_stdout("nvram_get", &["0", "router_disable"]);
    output.rsplit(':').next().unwrap_or("").trim() == "1"
}

fn published_detail(existing: &str, argument: &str) -> String {
    if argument.is_empty() {
        existing.to_owned()
    } else {
        argument.to_owned()
    }
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

/// PIDs of the customer DHCP server. The wifi server is also named udhcpd, and
/// `killall udhcpd` would stop that one too.
fn customer_dhcp_pids(listing: &str) -> Vec<i32> {
    listing
        .lines()
        .filter_map(|line| {
            if !line.contains("udhcpd -f /tmp/udhcpd.conf") {
                return None;
            }
            line.split_whitespace().next()?.parse().ok()
        })
        .collect()
}

fn stop_customer_udhcpd() {
    let pids = customer_dhcp_pids(&command_stdout("ps", &[]));
    for pid in &pids {
        let _ = Command::new("kill").arg(pid.to_string()).status();
    }
    // setsid does not reparent the server, so the keeper must wait for it.
    // An unreaped restart every minute fills the process table with zombies.
    let deadline = std::time::Instant::now() + Duration::from_millis(200);
    let mut left = pids;
    while !left.is_empty() && std::time::Instant::now() < deadline {
        left.retain(|pid| unsafe { libc::waitpid(*pid, std::ptr::null_mut(), libc::WNOHANG) } == 0);
        if !left.is_empty() {
            thread::sleep(Duration::from_millis(20));
        }
    }
}

fn spawn_udhcpd() -> Result<std::process::Child, String> {
    let mut child = Command::new("/usr/sbin/udhcpd");
    child
        .args(["-f", "/tmp/udhcpd.conf"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        child.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    child.spawn().map_err(|err| err.to_string())
}

fn cached_mgmt_iid() -> Option<mgmt::Iid> {
    let text = fs::read_to_string(state_dir().join("mgmt-iid.txt")).unwrap_or_default();
    mgmt::parse_iid(text.trim())
}

fn addrs_global_text(dump: &str) -> Option<String> {
    dump.split_whitespace().find_map(|word| {
        let bare = word.split('/').next()?;
        let addr: Ipv6Addr = bare.parse().ok()?;
        let octets = addr.octets();
        let link_local = octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80;
        if link_local {
            None
        } else {
            Some(addr.to_string())
        }
    })
}

fn run_status(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| err.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&output.stderr);
        Err(format!("{program} {}: {}", args.join(" "), err.trim()))
    }
}

fn read_mac(dev: &str) -> Result<[u8; 6], String> {
    let text = fs::read_to_string(format!("/sys/class/net/{dev}/address"))
        .map_err(|err| err.to_string())?;
    let mut mac = [0u8; 6];
    let parts: Vec<&str> = text.trim().split(':').collect();
    if parts.len() != 6 {
        return Err(format!("bad mac on {dev}"));
    }
    for (index, part) in parts.iter().enumerate() {
        mac[index] = u8::from_str_radix(part, 16).map_err(|err| err.to_string())?;
    }
    Ok(mac)
}

fn solicit_mgmt(src: Ipv6Addr) -> Result<(), String> {
    let mac = read_mac(mgmt::MGMT_DEV)?;
    let ifindex = interface_index(mgmt::MGMT_DEV).ok_or("lte0pdn0 has no interface index")?;
    let packet = mgmt::solicitation(mac);
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6) };
    if fd < 0 {
        return Err(format!("socket: {}", io::Error::last_os_error()));
    }
    // Closed when this function returns, including on the error paths below.
    let _close = Packet { fd };
    let mut local: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    local.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    local.sin6_addr.s6_addr = src.octets();
    local.sin6_scope_id = ifindex as u32;
    let bound = unsafe {
        libc::bind(
            fd,
            (&local as *const libc::sockaddr_in6).cast(),
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return Err(format!("bind: {}", io::Error::last_os_error()));
    }
    let name = std::ffi::CString::new(mgmt::MGMT_DEV).map_err(|err| err.to_string())?;
    let device = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if device < 0 {
        return Err(format!("bind to device: {}", io::Error::last_os_error()));
    }
    let hops: libc::c_int = 255;
    let hops_set = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_HOPS,
            (&hops as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if hops_set < 0 {
        return Err(format!("hop limit: {}", io::Error::last_os_error()));
    }
    let index: libc::c_int = ifindex;
    let iface_set = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_IF,
            (&index as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if iface_set < 0 {
        return Err(format!(
            "multicast interface: {}",
            io::Error::last_os_error()
        ));
    }
    let mut dest: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    dest.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    dest.sin6_scope_id = ifindex as u32;
    dest.sin6_addr.s6_addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2).octets();
    let sent = unsafe {
        libc::sendto(
            fd,
            packet.as_ptr().cast(),
            packet.len(),
            0,
            (&dest as *const libc::sockaddr_in6).cast(),
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(format!(
            "router solicitation: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn command_stdout(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default()
}

fn read_file(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn monotonic() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64
}

fn state_dir() -> PathBuf {
    titan_pd_model::config::default_state_dir()
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
    fn a_real_status_line_replaces_the_placeholder() {
        assert_eq!(
            published_detail(
                "Keeper has not reported yet",
                "IPv6 prefix delegation has not been saved. The IP family is unchanged.",
            ),
            "IPv6 prefix delegation has not been saved. The IP family is unchanged."
        );
        assert_eq!(published_detail("already specific", ""), "already specific");
    }

    #[test]
    fn the_wifi_dhcp_server_is_not_the_customer_one() {
        let listing = "\
  5721 root      1928 S    udhcpd -f /tmp/udhcpd.conf
  5723 root      1928 S    udhcpd -f /tmp/udhcpd_wifi.conf
  388 root      2672 S    /bin/sh -c grep udhcpd.conf
";
        assert_eq!(customer_dhcp_pids(listing), vec![5721]);
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
        assert_eq!(classify_ipv6(&packet, None, None), {
            let prefixes = ra::prefixes_of(&packet[40..]);
            Class::RouterAdvertisement {
                prefixes,
                source_mac: Some([0x02, 0x00, 0x00, 0x00, 0x01, 0x01]),
            }
        });
    }

    #[test]
    fn delegated_traffic_and_a_solicit_are_the_router_and_a_foreign_neighbour_is_not() {
        let block = parse_pinned("2001:db8:ff:d300::/64").unwrap();
        let mut traffic = vec![0u8; 40];
        traffic[0] = 0x60;
        traffic[8..24].copy_from_slice(&block.delegated57().addr);
        traffic[23] = 1;
        assert!(matches!(
            classify_ipv6(&traffic, Some(block.delegated57()), None),
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
    fn link_recovery_is_one_renegotiation() {
        let (program, args) = link_recovery();
        assert_eq!(program, "mii-tool");
        assert_eq!(args, ["-r", "eth0"]);
    }

    #[test]
    fn the_bearer_line_and_a_dhcp_discover_parse() {
        let text = "inet6 2001:db8:ff:d300::d4/64 scope global \ninet6 fe80::1/64 scope link\n";
        assert_eq!(
            global_prefix(text).unwrap().to_string(),
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
}
