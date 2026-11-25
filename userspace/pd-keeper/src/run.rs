//! Wire loop for the prefix keeper.
//!
//! The Titan answers router solicitations and DHCPv6 from the pinned block on
//! eth0, and a filter on that port drops the core's advertisements and DHCPv6
//! replies. The router therefore hears one server, including while LTE is down
//! or still dialling. Sends are injected on eth0 so they are not bridged back
//! up the bearer. IPv4 passthrough repair runs in the same process even when
//! prefix delegation is off. Management IPv6 is brought up on lte0pdn0 from
//! the modem's assigned interface identifier, including when delegation is off.
//! In passthrough it also puts back the vendor SNAT rule for the unit's own
//! SAS traffic when a vendor firewall restart removes it. Once management IPv6
//! is up it stops the kernel from processing any further advertisement on
//! lte0pdn0. In passthrough it follows the kernel log and undoes the vendor
//! kernel making a management bearer its external device, which is what makes
//! a unit deaf. In every mode it reboots a unit that stays attached but hears
//! nothing through the core. In passthrough it also puts the LTE driver's
//! downlink MAC back on the router when the unit starts forwarding IPv6 (see
//! `titan_pd_model::driver_mac`). In every mode it stops the Ethernet MAC from
//! sending 802.3x PAUSE frames to the customer router (see
//! `titan_pd_model::ethernet`). In every mode it drops customer IPv6 to and
//! from LTE while the unit holds no SAS grant, which the vendor does for IPv4
//! only (see `titan_pd_model::cbrs_gate`). On a boot that loaded a staged
//! modem firmware image it confirms the boot, or puts stock firmware back (see
//! `titan_pd_model::tk_boot`), and after the confirm writes the operator's
//! modem feature flags (see `titan_pd_model::tk_flags`). In every mode it
//! loads a staged download clamp when its config asks for one (see
//! `titan_pd_model::qctrl`).

use std::fs;
use std::io::{self, ErrorKind};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

use titan_pd_model::cbrs_gate;
use titan_pd_model::config::{self, Config, Report};
use titan_pd_model::deaf;
use titan_pd_model::dhcpv6;
use titan_pd_model::driver_mac;
use titan_pd_model::ethernet;
use titan_pd_model::extdev;
use titan_pd_model::filter;
use titan_pd_model::health::{self, Decision, Health, Phase, View};
use titan_pd_model::host_mac;
use titan_pd_model::ipv4;
use titan_pd_model::ipv4_health::{self, Peer, Traffic};
use titan_pd_model::mgmt;
use titan_pd_model::prefix::Block;
use titan_pd_model::ra::{self, Advertisement};
use titan_pd_model::sas_nat;
use titan_pd_model::tk_boot::{self, Action as TkAction};
use titan_pd_model::tk_flags;
use titan_pd_model::wear::{self, Route};

use crate::{cpu_trims_io, fastpath_io, log, log_ram, nvram, tk_flags_io};
use crate::clock::{monotonic, unix_now};
use crate::command::command_stdout;
use crate::files::read_file;
use crate::netdev::{carrier_up, interface_index, interface_mac, rx_packets};
use crate::paths::state_dir;

use self::budget::link_recovery;
use self::carrier::CarrierWatch;
use self::clamp::QctrlWatch;
use self::if_inet6::{link_local, live_prefix};
use self::kmsg::KernelLog;
use self::mgmt_v6::mgmt_address_up;
use self::packet::{Class, all_nodes_mac, client_mac_of, ethernet_frame, fe80_1, prefixes_advert, ra_packet, udp_packet};
use self::routes::main_routes;
use self::sas::FileTail;
use self::watchdog::{DeafProbe, spawn_pings};
use self::wire::{ControlSockets, send_ipv6, send_marked_frame};

mod budget;
mod carrier;
mod clamp;
mod flow;
mod gate;
mod if_inet6;
mod ipv4_repair;
mod kmsg;
mod mac;
mod mgmt_v6;
mod mode;
mod packet;
mod routes;
mod sas;
mod udhcpd;
mod watchdog;
mod wire;

pub use self::mgmt_v6::solicit_once;

const CUSTOMER: &str = "eth0";
const BRIDGE: &str = "br0";
/// The customer bearer when neither the bridge nor the vendor names one.
const DEFAULT_BEARER: &str = "lte0pdn1";
/// Seconds between reads of `tk/config` for flag changes.
const TK_FLAGS_CONFIG_EVERY: u64 = 15;
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
const CORE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x01, 0x01];

type FileFingerprint = (u64, u64, i64, i64);

struct Keeper {
    sockets: Option<ControlSockets>,
    serving: bool,
    health: Health,
    now: u64,
    last_sec_tick: Option<u64>,
    cached_routes: String,
    nvram_cache: Option<(u64, Vec<u8>)>,
    config_cache: Option<(Option<FileFingerprint>, Result<Option<Config>, String>)>,
    saved_budget: Option<(u32, u64, u64)>,
    probe_addr_cache: Option<(u64, std::net::Ipv4Addr, Option<std::net::Ipv4Addr>)>,
    last_ra: u64,
    last_router: u64,
    dhcp_gate: ipv4::DhcpGate,
    last_dhcp_probe: u64,
    ipv4_watch: ipv4_health::Watch,
    /// The customer port's receive counter at recent ARP probes.
    eth_rx: ipv4_health::Activity,
    last_ipv4_check: u64,
    // Read the dynamic PDN snapshot at most once per second per bearer.
    assigned_at: Option<(u64, String, Option<std::net::Ipv4Addr>)>,
    sas_watch: sas_nat::Watch,
    last_sas_check: Option<u64>,
    dhcp_child: Option<std::process::Child>,
    last_flood: u64,
    flood_bearer: String,
    serve_retry_at: u64,
    router_seen: bool,
    solicit_pending: bool,
    discover: Option<[u8; 6]>,
    router_mac: String,
    /// Ethernet source we last handed a prefix, and the monotonic time of that
    /// reply. A later neighbour probe for fe80::1 from this MAC is the router
    /// staying up. A probe from anyone else is the stuck-prefix case: it does
    /// not count, and it ends this hold. Up to v1.0.12 this was the wall clock,
    /// so the NTP step at boot (2013 to 2026) ended a fresh hold at once.
    delegated_mac: Option<[u8; 6]>,
    delegated_at: u64,
    /// The customer port's receive counter, sampled every `LINK_SAMPLE` s for
    /// the IPv6 health check. Bulk IPv6 is no longer read from the port.
    link_rx: ipv4_health::Activity,
    link_rx_at: Option<u64>,
    /// The MAC of the last IPv6 control packet from the router (solicitation,
    /// neighbour probe or DHCPv6). Forgotten when eth0 stays down long enough
    /// for a router swap.
    ipv6_router: Option<[u8; 6]>,
    eth0_down_since: Option<u64>,
    /// The last DHCP offer that named the IPv4 router, for a repair.
    ipv4_conf_good: Option<String>,
    /// `rcinit`'s log, for the lines that come right before a firewall restart.
    rcinit_log: FileTail,
    rcinit_read_at: Option<u64>,
    last_action: String,
    last_action_at: u64,
    logged_idle: bool,
    logged_unreadable: bool,
    passthrough: bool,
    core_mac: [u8; 6],
    saved_sysctl: Vec<(String, String)>,
    /// Which lines reach the flash log (see `titan_pd_model::wear`).
    notes: wear::Notes,
    /// The last report written to RAM, and to flash.
    status_ram: Option<Report>,
    status_flash: Option<Report>,
    status_gate: wear::FlashGate,
    /// When the vendor ping watchdog line was last written.
    vendor_watchdog_logged: Option<u64>,
    last_mgmt: u64,
    last_mgmt_log: u64,
    mgmt_up_logged: bool,
    mgmt_iid: Option<mgmt::Iid>,
    mgmt_klog_checked: bool,
    mgmt_settled: bool,
    last_mgmt_route_verify: u64,
    deaf_watch: deaf::Watch,
    deaf_probe: Option<DeafProbe>,
    deaf_secs: u64,
    last_deaf_round: Option<u64>,
    reboot_asked_at: Option<u64>,
    reboot_forced: bool,
    /// The bearer bridged to the customer port, or the vendor's data bearer.
    bearer: String,
    mode_checked: Option<u64>,
    /// The customer bearer is a port of the LAN bridge right now.
    bridged: bool,
    /// Since when, without a break.
    bridged_since: Option<u64>,
    /// The last router the IPv4 check could name, and when.
    ipv4_peer: Option<(Peer, u64)>,
    kernel_log: Option<KernelLog>,
    ext_watch: extdev::Watch,
    /// The DHCP gateway handed to the router, read with the IPv4 peer.
    ipv4_gateway: Option<std::net::Ipv4Addr>,
    driver_watch: driver_mac::Watch,
    /// Corrections since the last log line, and when that line was written.
    driver_fixes: u32,
    driver_logged_at: Option<u64>,
    /// The vendor kernel's IPv4 host MAC, read from its log and kept on the
    /// router that holds the customer lease. See `titan_pd_model::host_mac`.
    host_mac_watch: host_mac::Watch,
    host_mac_logged_at: Option<u64>,
    flow_watch: ethernet::Watch,
    flow_checked: Option<u64>,
    /// The kernel log was read to its end once, so a flow control report
    /// read after that was printed after the keeper's own command.
    kmsg_drained: bool,
    /// `kern eth -fc` ran and its report has not been read yet.
    flow_pending: bool,
    flow_logged: bool,
    flow_failed_logged: bool,
    flow_stock_logged: bool,
    /// Customer IPv6 while there is no SAS grant (see `titan_pd_model::cbrs_gate`).
    cbrs_gate: cbrs_gate::Watch,
    /// Active Band 48 carriers vs held SAS grants (see `titan_pd_model::carrier_watch`).
    carrier_watch: CarrierWatch,
    /// The boot hook's status was read.
    tk_checked: bool,
    /// Pending confirm for a boot that loaded a staged modem firmware image.
    tk_confirm: Option<tk_boot::Confirm>,
    tk_probe: Option<DeafProbe>,
    tk_last_round: Option<u64>,
    /// The boot hook's status, read once at start.
    tk_status: tk_boot::BootStatus,
    /// Modem feature flags after a confirmed staged boot (see
    /// `titan_pd_model::tk_flags`), and the DM session running for them.
    tk_flags: Option<tk_flags::Control>,
    tk_flags_job: Option<(std::thread::JoinHandle<(tk_flags::Outcome, bool)>, tk_flags::Plan)>,
    tk_flags_config_at: Option<u64>,
    tk_flags_refused: Vec<String>,
    tk_flags_config_hands_off: bool,
    /// The kernel log showed a modem firmware load after the keeper started.
    modem_restart_seen: bool,
    /// The staged download clamp (see `titan_pd_model::qctrl`).
    qctrl: QctrlWatch,
    /// The staged passthrough bridge fast path (see `titan_pd_model::fastpath`).
    fastpath: fastpath_io::Watch,
    /// The opt-in CPU trims (see `titan_pd_model::cpu_trims`).
    cpu_trims: cpu_trims_io::Watch,
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
        keeper.wait_next();
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
            sockets: None,
            serving: false,
            health: Health::default(),
            now: 0,
            last_sec_tick: None,
            cached_routes: String::new(),
            nvram_cache: None,
            config_cache: None,
            saved_budget: None,
            probe_addr_cache: None,
            last_ra: 0,
            last_router: 0,
            dhcp_gate: ipv4::DhcpGate::default(),
            last_dhcp_probe: 0,
            ipv4_watch: ipv4_health::Watch::default(),
            eth_rx: ipv4_health::Activity::default(),
            last_ipv4_check: 0,
            assigned_at: None,
            sas_watch: sas_nat::Watch::default(),
            last_sas_check: None,
            dhcp_child: None,
            last_flood: 0,
            flood_bearer: String::new(),
            serve_retry_at: 0,
            router_seen: false,
            solicit_pending: false,
            discover: None,
            router_mac: String::new(),
            delegated_mac: None,
            delegated_at: 0,
            link_rx: ipv4_health::Activity::default(),
            link_rx_at: None,
            ipv6_router: None,
            eth0_down_since: None,
            ipv4_conf_good: None,
            rcinit_log: FileTail::new(
                std::env::var_os("TITAN_RCINIT_LOG")
                    .map_or_else(|| PathBuf::from("/tmp/rcinit.log"), PathBuf::from),
            ),
            rcinit_read_at: None,
            last_action: String::new(),
            last_action_at: 0,
            logged_idle: false,
            logged_unreadable: false,
            passthrough: false,
            core_mac: CORE_MAC,
            saved_sysctl: Vec::new(),
            notes: wear::Notes::default(),
            status_ram: None,
            status_flash: None,
            status_gate: wear::FlashGate::default(),
            vendor_watchdog_logged: None,
            last_mgmt: 0,
            last_mgmt_log: 0,
            mgmt_up_logged: false,
            mgmt_iid: None,
            mgmt_klog_checked: false,
            mgmt_settled: false,
            last_mgmt_route_verify: 0,
            deaf_watch: deaf::Watch::default(),
            deaf_probe: None,
            deaf_secs: deaf::DEAF_SECS,
            last_deaf_round: None,
            reboot_asked_at: None,
            reboot_forced: false,
            bearer: DEFAULT_BEARER.to_owned(),
            mode_checked: None,
            bridged: false,
            bridged_since: None,
            ipv4_peer: None,
            kernel_log: KernelLog::open(),
            ext_watch: extdev::Watch::default(),
            ipv4_gateway: None,
            driver_watch: driver_mac::Watch::default(),
            driver_fixes: 0,
            driver_logged_at: None,
            host_mac_watch: host_mac::Watch::default(),
            host_mac_logged_at: None,
            flow_watch: ethernet::Watch::default(),
            flow_checked: None,
            kmsg_drained: false,
            flow_pending: false,
            flow_logged: false,
            flow_failed_logged: false,
            flow_stock_logged: false,
            cbrs_gate: cbrs_gate::Watch::default(),
            carrier_watch: CarrierWatch::new(),
            tk_checked: false,
            tk_confirm: None,
            tk_probe: None,
            tk_last_round: None,
            tk_status: tk_boot::BootStatus::default(),
            tk_flags: None,
            tk_flags_job: None,
            tk_flags_config_at: None,
            tk_flags_refused: Vec::new(),
            tk_flags_config_hands_off: false,
            modem_restart_seen: false,
            qctrl: QctrlWatch::default(),
            fastpath: fastpath_io::Watch::default(),
            cpu_trims: cpu_trims_io::Watch::default(),
        }
    }

    /// Block in `poll()` on the control sockets and real kernel log device so
    /// control frames and kernel events wake the keeper immediately while idle
    /// steady state wakes only once per second.
    fn wait_next(&self) {
        let fast = self.deaf_probe.is_some()
            || self.tk_probe.is_some()
            || (self.kernel_log.is_some() && !self.kmsg_drained);
        let timeout = Duration::from_millis(if fast { 200 } else { 1000 });
        let sockets = self.sockets.as_ref();
        let fds: [Option<BorrowedFd<'_>>; 4] = [
            sockets.map(|sockets| sockets.arp.as_fd()),
            sockets.map(|sockets| sockets.dhcp.as_fd()),
            sockets
                .and_then(|sockets| sockets.ipv6.as_ref())
                .map(|ipv6| ipv6.packet.as_fd()),
            self.kernel_log
                .as_ref()
                .filter(|klog| klog.is_pollable())
                .map(|klog| klog.as_fd()),
        ];
        if fds.iter().all(Option::is_none) {
            thread::sleep(timeout);
            return;
        }
        if titan_sys::poll::wait_readable(&fds, timeout)
            .is_err_and(|err| err.kind() != ErrorKind::Interrupted)
        {
            thread::sleep(Duration::from_millis(200));
        }
    }

    fn read_nvram_cache(&mut self) -> Option<&[u8]> {
        let refresh = self.nvram_cache.as_ref().is_none_or(|(at, _)| *at != self.now);
        if refresh {
            self.nvram_cache = fs::read(nvram::cache_path()).ok().map(|bytes| (self.now, bytes));
        }
        self.nvram_cache.as_ref().map(|(_, bytes)| bytes.as_slice())
    }

    /// Reads one key from the cached `/tmp/nvram.cfg` in-process, formatted the
    /// same way as `nvram_get 0 <key>`. Falls back to `nvram_get` only when the
    /// key is absent from the cache file (for example in host tests with stubs).
    fn nvram_get_cached(&mut self, key: &str) -> String {
        if let Some(cache) = self.read_nvram_cache() {
            if let Some(value) = nvram::get_from_cache(cache, key) {
                return value;
            }
        }
        command_stdout("nvram_get", &["0", key])
    }

    fn load_config_cached(&mut self) -> Result<Option<Config>, String> {
        let path = state_dir().join("config.json");
        let fp = fs::metadata(&path).ok().map(|meta| {
            (
                meta.ino(),
                meta.len(),
                meta.mtime(),
                meta.mtime_nsec(),
            )
        });
        if let Some((cached_fp, cached_result)) = &self.config_cache {
            if *cached_fp == fp {
                return cached_result.clone();
            }
        }
        let loaded = config::load_config(&path).map_err(|err| err.to_string());
        self.config_cache = Some((fp, loaded.clone()));
        loaded
    }

    fn tick(&mut self) -> Result<(), String> {
        let new_second = self.last_sec_tick != Some(self.now);
        if new_second {
            self.last_sec_tick = Some(self.now);
            self.refresh_mode();
        }
        // First, and in every mode: nothing below may delay it.
        self.maintain_cbrs_gate();
        self.maintain_carrier_watch();
        self.maintain_external_dev();
        self.maintain_flow_control();
        self.maintain_deaf_watchdog();
        self.maintain_tk_confirm();
        self.maintain_tk_flags();
        self.maintain_qctrl();
        self.maintain_fastpath();
        self.maintain_cpu_trims();
        self.maintain_mgmt_v6();
        if !self.passthrough {
            self.sockets = None;
            self.ipv4_watch.reset();
            self.ipv4_peer = None;
            self.sas_watch.reset();
            self.driver_watch.reset();
            self.host_mac_watch.reset_attempts();
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
            return Ok(());
        }
        self.logged_idle = false;
        let loaded = self.load_config_cached();
        let want_ipv6 = matches!(&loaded, Ok(Some(cfg)) if cfg.enabled);
        self.ensure_sockets(want_ipv6)?;
        self.drain();
        if new_second || self.cached_routes.is_empty() {
            // Both guards must see the same main-table snapshot on this second.
            self.cached_routes = main_routes();
        }
        let routes = self.cached_routes.clone();
        if new_second || self.discover.is_some() {
            self.maintain_ipv4(&routes);
        }
        if new_second {
            self.maintain_ipv4_link(&routes);
            self.maintain_driver_mac();
            self.maintain_host_mac();
            self.maintain_sas_nat(&routes);
        }

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
        if self
            .link_rx_at
            .is_none_or(|at| self.now.saturating_sub(at) >= LINK_SAMPLE)
        {
            self.link_rx.sample(self.now, rx);
            self.link_rx_at = Some(self.now);
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
                // The caller saved the budget first. `ip link set eth0 down` does not make this router solicit.
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
        let Some(sockets) = self.sockets.as_ref() else {
            self.note(&format!(
                "did not send ({why}): customer port socket is closed"
            ));
            return;
        };
        let ifindex = interface_index(CUSTOMER).unwrap_or(0);
        match send_ipv6(&sockets.tx_ipv6, ifindex, dest_mac, packet) {
            Ok(()) => self.note(why),
            Err(err) => self.note(&format!("send failed ({why}): {err}")),
        }
    }

    fn sniff_core_ra(&mut self) -> Result<Sniff, String> {
        self.ensure_sockets(true)?;
        {
            let ipv6 = self
                .sockets
                .as_ref()
                .and_then(|sockets| sockets.ipv6.as_ref())
                .ok_or("IPv6 control socket is not open")?;
            crate::capture::install_ipv6(ipv6.packet.as_fd(), true)?;
        }
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
            let ipv6 = self
                .sockets
                .as_ref()
                .and_then(|sockets| sockets.ipv6.as_ref())
                .map(|ipv6| ipv6.packet.as_fd());
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
        let restore = if let Some(ipv6) = self.sockets.as_ref().and_then(|s| s.ipv6.as_ref()) {
            crate::capture::install_ipv6(ipv6.packet.as_fd(), false)
        } else {
            Ok(())
        };
        let _ = self.collect_ipv6();
        restore?;
        Ok(found)
    }

    fn drain(&mut self) {
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

    fn serving_block(&mut self) -> Option<Block> {
        if !self.serving {
            return None;
        }
        let config = self.load_config_cached().ok().flatten()?;
        config.pinned_block().ok().flatten()
    }

    /// Runs in NAT and in passthrough. See `titan_pd_model::tk_boot`. Nothing
    /// arms unless the boot hook staged a modem firmware image this boot.
    fn maintain_tk_confirm(&mut self) {
        if !self.tk_checked {
            self.tk_checked = true;
            let status = tk_boot::parse_status(&read_file(&tk_status_path()));
            if let Some(line) = tk_boot::describe(&status) {
                self.note(&line);
            }
            let decided = fs::metadata(tk_result_path()).is_ok();
            self.tk_confirm = tk_boot::Confirm::arm(&status, self.now, decided);
            self.tk_status = status.clone();
            // A keeper that restarts after the confirm takes the flags over.
            match tk_flags::armed_sha(&status, &read_file(&tk_result_path())) {
                Some(sha) => self.arm_tk_flags(&sha),
                None => {
                    let reason = if status.staged.is_some() {
                        "waiting for the boot confirm"
                    } else {
                        "stock modem firmware: no flag writes"
                    };
                    let _ = fs::write(tk_flags_status_path(), tk_flags::idle_status(reason, self.now));
                }
            }
            let left = self
                .tk_confirm
                .as_ref()
                .map(|confirm| confirm.deadline.saturating_sub(self.now));
            if let Some(left) = left {
                self.note(&format!(
                    "tk boot confirm armed: without a management answer through the core in {left} s the keeper quarantines this image and reboots onto stock modem firmware"
                ));
            }
        }
        if self.tk_confirm.is_none() || self.reboot_asked_at.is_some() {
            return;
        }
        if let Some(mut probe) = self.tk_probe.take() {
            let mut heard = false;
            let mut running = false;
            for child in probe.children.iter_mut() {
                match child.try_wait() {
                    Ok(Some(status)) => heard |= status.success(),
                    Ok(None) => running = true,
                    Err(_) => {}
                }
            }
            let timed_out = self.now.saturating_sub(probe.started) >= tk_boot::PROBE_TIMEOUT;
            if !heard && running && !timed_out {
                self.tk_probe = Some(probe);
                return;
            }
            for child in probe.children.iter_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
            self.tk_round(Some(heard));
            return;
        }
        if self
            .tk_last_round
            .is_some_and(|last| self.now.saturating_sub(last) < tk_boot::PROBE_EVERY)
        {
            return;
        }
        self.tk_last_round = Some(self.now);
        let targets = self.tk_targets();
        let children = spawn_pings(&targets);
        if children.is_empty() {
            self.tk_round(None);
            return;
        }
        self.tk_probe = Some(DeafProbe {
            children,
            started: self.now,
        });
    }

    fn tk_round(&mut self, heard: Option<bool>) {
        let Some(mut confirm) = self.tk_confirm.take() else {
            return;
        };
        match confirm.observe(self.now, mgmt_address_up(), heard) {
            TkAction::Hold => self.tk_confirm = Some(confirm),
            TkAction::Confirmed => self.tk_confirmed(&confirm.sha),
            TkAction::Rollback => self.tk_rollback(&confirm.sha),
        }
    }

    fn tk_confirmed(&mut self, sha: &str) {
        self.tk_confirmed_record(sha);
        // Only now, and only for the image the hook staged, may flags be written.
        if let Some(armed) = tk_flags::armed_sha(&self.tk_status, &format!("confirmed={sha}\n")) {
            self.arm_tk_flags(&armed);
        }
    }

    fn tk_confirmed_record(&mut self, sha: &str) {
        let _ = fs::write(tk_result_path(), format!("confirmed={sha}\n"));
        let short = tk_boot::short(sha);
        let Some(dir) = tk_dir() else {
            self.note(&format!(
                "tk boot confirmed: modem firmware {short} answered through the core, but the persistent volume is not mounted; its strike stays counted"
            ));
            return;
        };
        let cleared = write_atomic(&dir.join("strikes"), tk_boot::format_strikes(0).as_bytes());
        let _ = write_atomic(&dir.join("confirmed"), format!("sha256={sha}\n").as_bytes());
        if cleared {
            self.note(&format!(
                "tk boot confirmed: modem firmware {short} answered through the core; strikes cleared"
            ));
        } else {
            self.note(&format!(
                "tk boot confirmed: modem firmware {short} answered through the core, but the strike count could not be cleared"
            ));
        }
    }

    /// Quarantine the image and reboot onto stock firmware, but only once a
    /// read-back shows the boot hook will refuse it: a reboot without that
    /// record could load the same image again.
    fn tk_rollback(&mut self, sha: &str) {
        let _ = fs::write(tk_result_path(), format!("rollback={sha}\n"));
        let short = tk_boot::short(sha);
        let secs = tk_boot::CONFIRM_SECS;
        let Some(dir) = tk_dir() else {
            self.note(&format!(
                "tk boot confirm: no management answer within {secs} s of loading modem firmware {short}, but the persistent volume is not mounted; not rebooting"
            ));
            return;
        };
        let quarantine = dir.join("quarantine");
        let strikes = dir.join("strikes");
        let listed = tk_boot::add_quarantine(&read_file(&quarantine), sha);
        let _ = write_atomic(&quarantine, listed.as_bytes());
        let _ = write_atomic(&strikes, tk_boot::format_strikes(tk_boot::STRIKE_LIMIT).as_bytes());
        let recorded = tk_boot::refused(
            tk_boot::parse_strikes(&read_file(&strikes)),
            &tk_boot::parse_quarantine(&read_file(&quarantine)),
            sha,
        );
        if !recorded {
            self.note(&format!(
                "tk boot confirm: no management answer within {secs} s of loading modem firmware {short}, and the quarantine could not be recorded; not rebooting"
            ));
            return;
        }
        self.note(&format!(
            "tk boot confirm: no management answer within {secs} s of loading modem firmware {short}; quarantined it, rebooting onto stock modem firmware"
        ));
        self.request_reboot();
    }

    /// Start the flag writes for a confirmed staged boot. The words and values
    /// come from `wm=` lines in `tk/config`.
    fn arm_tk_flags(&mut self, sha: &str) {
        if self.tk_flags.is_some() {
            return;
        }
        let short = tk_boot::short(sha).to_owned();
        let Some(dir) = tk_dir() else {
            self.note(&format!(
                "tk flags: modem firmware {short} confirmed, but the persistent volume is not mounted; no flag writes"
            ));
            let _ = fs::write(
                tk_flags_status_path(),
                tk_flags::idle_status("the persistent volume is not mounted", self.now),
            );
            return;
        };
        let text = read_file(dir.join("config"));
        let parsed = tk_flags::parse_writes(&text);
        self.note_tk_flags_refused(&parsed);
        self.tk_flags_config_hands_off = parsed.hands_off;
        let wanted = tk_flags::wanted(&text, &[]);
        let mut control = tk_flags::Control::new_with_ack(wanted.clone(), parsed.hold_ack, self.now);
        let hands_off = self.tk_flags_hands_off_reason();
        if let Some(reason) = hands_off.as_deref() {
            let (_, line) = control.set_hands_off(Some(reason), self.now);
            if let Some(line) = line {
                self.note(&line);
            }
            let _ = fs::write(tk_flags_status_path(), control.status(self.now));
        } else if wanted.is_empty() {
            let _ = fs::write(
                tk_flags_status_path(),
                tk_flags::idle_status("no wm= lines in tk/config", self.now),
            );
        } else {
            self.note(&format!(
                "tk flags: modem firmware {short} confirmed; writing {} once the patch magic shows",
                tk_flags::list(&wanted)
            ));
            let _ = fs::write(tk_flags_status_path(), control.status(self.now));
        }
        self.tk_flags = Some(control);
        self.tk_flags_config_at = Some(self.now);
    }

    fn tk_flags_hands_off_reason(&self) -> Option<String> {
        if self.tk_flags_config_hands_off {
            return Some("manage=off in tk/config".into());
        }
        let marker = tk_flags_hands_off_path();
        if std::path::Path::new(&marker).exists() {
            return Some(marker);
        }
        None
    }

    fn note_tk_flags_refused(&mut self, parsed: &tk_flags::Parsed) {
        if parsed.refused == self.tk_flags_refused {
            return;
        }
        for (line, reason) in &parsed.refused_reasons {
            self.note(&format!(
                "tk flags: ignored {line:?} in tk/config: {reason}"
            ));
        }
        self.tk_flags_refused = parsed.refused.clone();
    }

    /// Run the DM sessions for the flags, one at a time, on their own thread.
    /// Nothing runs unless `arm_tk_flags` made a `Control`.
    fn maintain_tk_flags(&mut self) {
        let mut lines: Vec<String> = Vec::new();
        let mut changed = false;
        if self
            .tk_flags_job
            .as_ref()
            .is_some_and(|(job, _)| job.is_finished())
        {
            if let Some((job, plan)) = self.tk_flags_job.take() {
                let (outcome, sent) = job.join().unwrap_or((tk_flags::Outcome::NoReply, false));
                if let Some(control) = self.tk_flags.as_mut() {
                    lines.extend(control.finished(self.now, &plan, &outcome, sent));
                    changed = true;
                }
            }
        }
        let restarted = std::mem::take(&mut self.modem_restart_seen);
        if self.tk_flags.is_none() {
            return;
        }
        // The operator may change tk/config: read it again now and then. A
        // missing file means off; a read error changes nothing.
        let mut config_text = None;
        if self
            .tk_flags_config_at
            .is_none_or(|at| self.now.saturating_sub(at) >= TK_FLAGS_CONFIG_EVERY)
        {
            self.tk_flags_config_at = Some(self.now);
            if let Some(dir) = tk_dir() {
                config_text = match fs::read_to_string(dir.join("config")) {
                    Ok(text) => Some(text),
                    Err(err) if err.kind() == ErrorKind::NotFound => Some(String::new()),
                    Err(_) => None,
                };
            }
        }
        let parsed_config = config_text.as_deref().map(tk_flags::parse_writes);
        if let Some(parsed) = &parsed_config {
            self.note_tk_flags_refused(parsed);
            self.tk_flags_config_hands_off = parsed.hands_off;
        }
        let hands_off = self.tk_flags_hands_off_reason();
        let busy = self.tk_flags_job.is_some() || self.reboot_asked_at.is_some();
        let mut spawned = None;
        if let Some(control) = self.tk_flags.as_mut() {
            let (ho_changed, ho_line) = control.set_hands_off(hands_off.as_deref(), self.now);
            if ho_changed {
                changed = true;
            }
            lines.extend(ho_line);
            if restarted {
                lines.push(control.modem_restarted(self.now));
                changed = true;
            }
            if let (Some(text), Some(parsed)) = (&config_text, &parsed_config) {
                let wanted = tk_flags::wanted(text, control.wanted());
                if let Some(line) = control.set_wanted_with_ack(wanted, parsed.hold_ack, self.now) {
                    lines.push(line);
                    changed = true;
                }
            }
            if !busy {
                if let Some(plan) = control.due(self.now) {
                    match tk_flags_io::spawn(plan.clone()) {
                        Some(job) => spawned = Some((job, plan)),
                        None => {
                            let outcome = tk_flags::Outcome::NoReply;
                            lines.extend(control.finished(self.now, &plan, &outcome, false));
                            changed = true;
                        }
                    }
                }
            }
        }
        if spawned.is_some() {
            self.tk_flags_job = spawned;
        }
        let status = if changed {
            self.tk_flags.as_ref().map(|control| {
                if control.state() == tk_flags::State::HandsOff {
                    control.status(self.now)
                } else if control.wanted().is_empty() {
                    tk_flags::idle_status("no wm= lines in tk/config", self.now)
                } else {
                    control.status(self.now)
                }
            })
        } else {
            None
        };
        for line in lines {
            self.note(&line);
        }
        if let Some(status) = status {
            let _ = fs::write(tk_flags_status_path(), status);
        }
    }

    /// Load and maintain the staged passthrough bridge fast path after the
    /// download clamp (see `titan_pd_model::fastpath`).
    fn maintain_fastpath(&mut self) {
        let now = self.now;
        let passthrough = self.passthrough;
        let qctrl_waiting = self.qctrl.waiting;
        let cache = nvram::cache_path();
        let mut lines = Vec::new();
        self.fastpath
            .maintain(now, passthrough, qctrl_waiting, &cache, |line| {
                lines.push(line.to_owned());
            });
        for line in lines {
            self.note(&line);
        }
    }

    /// Pace the vendor LED loop and set `ksoftirqd/0`'s priority as
    /// `cpu-trims/config` says. Runs in every mode, once a second.
    fn maintain_cpu_trims(&mut self) {
        let now = self.now;
        let cache = nvram::cache_path();
        let mut lines = Vec::new();
        self.cpu_trims.maintain(now, &cache, |line| {
            lines.push(line.to_owned());
        });
        for line in lines {
            self.note(&line);
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

    /// The live report goes to RAM on every change. The web service reads the
    /// flash copy, which is rewritten only when it differs, at most once a
    /// minute; a change inside that minute lands when the minute is up.
    fn publish(&mut self, report: &Report, detail: &str) {
        let mut report = report.clone();
        // Report::default() already carries "Keeper has not reported yet".
        // A caller that passes a real line must replace that placeholder.
        report.detail = published_detail(&report.detail, detail);
        // IPv4 recovery still has useful actions to report when IPv6 is off.
        report.last_action = self.last_action.clone();
        report.last_action_at = self.last_action_at.to_string();
        if self.status_ram.as_ref() != Some(&report) {
            let _ = config::store_report(&crate::paths::runtime_dir().join("status.json"), &report);
            self.status_ram = Some(report.clone());
        }
        let differs = self.status_flash.as_ref() != Some(&report);
        if !self.status_gate.ready(self.now, differs) {
            return;
        }
        let path = state_dir().join("status.json");
        if config::load_report(&path).as_ref() == Some(&report) {
            // Already there, for example after a keeper restart.
            self.status_flash = Some(report);
            return;
        }
        self.status_gate.wrote(self.now);
        if config::store_report(&path, &report).is_ok() {
            self.status_flash = Some(report);
        }
    }

    fn note(&mut self, line: &str) {
        // The loop is 200 ms. An unchanged failure must not fill the log, but a
        // real action is recorded every time. Routine lines stay in RAM.
        match self.notes.route(line, self.now) {
            Route::Ram => {
                log_ram(line);
                return;
            }
            Route::Flash => {
                self.last_action_at = unix_now();
                log(line);
            }
            Route::Skip => {}
        }
        self.last_action = line.to_owned();
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
    fn load_delegation(&mut self) {
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

    /// The tk config's own targets, else the deaf watchdog's.
    fn tk_targets(&mut self) -> Vec<std::net::IpAddr> {
        let config = tk_dir()
            .map(|dir| read_file(dir.join("config")))
            .unwrap_or_default();
        let own = tk_boot::parse_targets(&config);
        if !own.is_empty() {
            return own;
        }
        let settings = deaf::parse_settings(&read_file(state_dir().join("watchdog.conf")));
        let bearer_dns = if settings.targets.is_empty() {
            self.nvram_get_cached("wan_get_dns")
        } else {
            String::new()
        };
        deaf::targets(&settings, &bearer_dns)
    }
}

#[derive(Default)]
struct Sniff {
    prefixes: Vec<Block>,
    source_mac: Option<[u8; 6]>,
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

fn tk_status_path() -> String {
    std::env::var("TITAN_TK_STATUS").unwrap_or_else(|_| "/var/run/witcher-tk.status".into())
}

/// Written once a keeper process confirmed or rolled back this boot.
fn tk_result_path() -> String {
    std::env::var("TITAN_TK_RESULT").unwrap_or_else(|_| "/var/run/witcher-tk.result".into())
}

/// The flag writes' status, in RAM.
fn tk_flags_status_path() -> String {
    std::env::var("TITAN_TK_FLAGS").unwrap_or_else(|_| "/var/run/witcher-tk.flags".into())
}

/// Optional bench/maintenance marker file that pauses all modem console
/// sessions until removed.
fn tk_flags_hands_off_path() -> String {
    std::env::var("TITAN_TK_HANDS_OFF").unwrap_or_else(|_| "/var/run/witcher-tk.hands-off".into())
}

/// The boot hook's files on the persistent volume, only while it is mounted.
fn tk_dir() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("TITAN_TK_DIR") {
        return Some(PathBuf::from(path));
    }
    config::persistent_volume_mounted().then(|| PathBuf::from("/mnt/titan-api/tk"))
}

/// Write through a synced temporary file, then sync the directory, so a power
/// cut leaves the old record or the new one.
fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> bool {
    use std::io::Write;
    let temp = path.with_extension("tmp");
    let written = (|| -> io::Result<()> {
        let mut file = fs::File::create(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        if let Some(parent) = path.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    written.is_ok()
}

fn published_detail(existing: &str, argument: &str) -> String {
    if argument.is_empty() {
        existing.to_owned()
    } else {
        argument.to_owned()
    }
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
