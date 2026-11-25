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
use std::net::{IpAddr, Ipv6Addr};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use titan_pd_model::cbrs_gate;
use titan_pd_model::config::{self, Config, Report};
use titan_pd_model::deaf::{self, Action as DeafAction};
use titan_pd_model::dhcpv6;
use titan_pd_model::driver_mac::{self, Action as DriverAction};
use titan_pd_model::ethernet;
use titan_pd_model::extdev;
use titan_pd_model::filter;
use titan_pd_model::health::{self, Decision, Health, Phase, View};
use titan_pd_model::host_mac::{self, Action as HostMacAction};
use titan_pd_model::ipv4;
use titan_pd_model::ipv4_health::{self, Peer, Traffic};
use titan_pd_model::mgmt::{self, Step};
use titan_pd_model::prefix::Block;
use titan_pd_model::qctrl::{self, Loaded as QctrlLoaded};
use titan_pd_model::ra::{self, Advertisement};
use titan_pd_model::sas_nat::{self, Action as SasAction};
use titan_pd_model::tk_boot::{self, Action as TkAction};
use titan_pd_model::tk_flags;
use titan_pd_model::wear::{self, Route};
use titan_sys::ifaddrs::InterfaceAddrs;
use titan_sys::socket::{Socket, SocketExt};

use crate::{cpu_trims_io, fastpath_io, log, log_ram, nvram, qctrl_io, tk_flags_io};
use crate::clock::{monotonic, unix_now};
use crate::command::{command_stdout, run_status};
use crate::files::read_file;
use crate::netdev::{carrier_up, interface_index, interface_mac, read_mac, rx_packets};
use crate::paths::state_dir;

use self::carrier::CarrierWatch;
use self::if_inet6::{link_local, live_prefix, proc_if_inet6_addrs};
use self::ipv4_repair::PEER_HOLD;
use self::kmsg::{KernelLog, kernel_messages};
use self::packet::{Class, all_nodes_mac, client_mac_of, ethernet_frame, fe80_1, prefixes_advert, ra_packet, udp_packet};
use self::routes::main_routes;
use self::wire::{ControlSockets, send_ipv6, send_marked_frame};

mod carrier;
mod flow;
mod gate;
mod if_inet6;
mod ipv4_repair;
mod kmsg;
mod mode;
mod packet;
mod routes;
mod udhcpd;
mod wire;

const CUSTOMER: &str = "eth0";
const BRIDGE: &str = "br0";
/// The customer bearer when neither the bridge nor the vendor names one.
const DEFAULT_BEARER: &str = "lte0pdn1";
/// Seconds between reads of `tk/config` for flag changes.
const TK_FLAGS_CONFIG_EVERY: u64 = 15;
const RA_INTERVAL: u64 = 45;
const SNIFF_SECS: u64 = 3;
const SERVE_RETRY: u64 = 60;
/// Seconds between safety re-checks of `ip -6 route` once management IPv6 has settled.
const MGMT_ROUTE_VERIFY: u64 = 300;
const MGMT_EVERY: u64 = 10;
/// Seconds between two samples of eth0's receive counter for IPv6 health.
const LINK_SAMPLE: u64 = 5;
/// eth0 down this long may be a router swap: the old router's IPv6 history
/// and delegation hold no longer apply. Our own renegotiation is shorter.
const ROUTER_SWAP_SECS: u64 = 10;
const MGMT_LOG_EVERY: u64 = 60;
/// A plain `reboot` that has not ended this process after this long is forced.
const REBOOT_FORCE_AFTER: u64 = 45;
/// After the forced attempt also fails, go back to watching.
const REBOOT_GIVE_UP_AFTER: u64 = 120;

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

/// The download clamp's progress this boot.
#[derive(Default)]
struct QctrlWatch {
    checked_at: Option<u64>,
    /// The customer port and the management bearer were both up since then.
    up_since: Option<u64>,
    /// The last status, so the file and the log change only on news.
    shown: String,
    /// True while configured with a non-zero mode and still waiting to load.
    waiting: bool,
    /// A load failed for this config. It is not retried until the config changes.
    failed_for: Option<qctrl::Config>,
    refused_logged: Vec<String>,
}

/// One round of pings, collected on later ticks so the wire loop keeps running.
struct DeafProbe {
    children: Vec<std::process::Child>,
    started: u64,
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

    fn budget_tuple(&self) -> (u32, u64, u64) {
        (
            self.health.link_drops,
            self.health.window_start,
            self.health.quiet_until,
        )
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

    /// In passthrough the unit forwards no IPv6. When it starts to, the LTE
    /// driver is sending the router's downlink to the unit, and the router's
    /// own ARP request, sent out the bearer, puts the driver back. See
    /// `titan_pd_model::driver_mac`.
    fn maintain_driver_mac(&mut self) {
        let path = std::env::var("TITAN_SNMP6").unwrap_or_else(|_| "/proc/net/snmp6".into());
        let count = driver_mac::forwarded(&read_file(&path));
        let peer = self
            .ipv4_peer
            .filter(|(_, seen)| self.now.saturating_sub(*seen) <= PEER_HOLD)
            .map(|(peer, _)| peer);
        let gateway = self.ipv4_gateway;
        let ready = self.passthrough && self.bridged && peer.is_some() && gateway.is_some();
        match self.driver_watch.tick(self.now, count, ready) {
            DriverAction::Hold => {}
            DriverAction::Correct => {
                let (Some(peer), Some(gateway)) = (peer, gateway) else {
                    return;
                };
                let frame = driver_mac::correction(peer.mac, peer.address, gateway);
                let bearer = self.bearer.clone();
                let sent = interface_index(&bearer)
                    .ok_or_else(|| format!("{bearer} is unavailable"))
                    .and_then(|index| send_marked_frame(index, &frame));
                match sent {
                    Ok(()) => {
                        self.driver_fixes += 1;
                        // keeper.log is on flash: one line a minute at most.
                        if self
                            .driver_logged_at
                            .is_none_or(|at| self.now.saturating_sub(at) >= 60)
                        {
                            self.note(&format!(
                                "the unit was forwarding the router's IPv6, so the LTE driver had the wrong downlink MAC; sent the router's ARP ({} {}) out {bearer} to put it back ({} time(s) since the last note)",
                                ipv4::mac_text(peer.mac),
                                peer.address,
                                self.driver_fixes
                            ));
                            self.driver_fixes = 0;
                            self.driver_logged_at = Some(self.now);
                        }
                    }
                    Err(err) => self.note(&format!("LTE driver MAC correction could not be sent: {err}")),
                }
            }
            DriverAction::GiveUp => self.note(&format!(
                "the unit keeps forwarding IPv6 after {} corrections; something else routes through it. Pausing the LTE driver MAC correction for {} s",
                driver_mac::TRIES,
                driver_mac::PAUSE
            )),
        }
    }

    /// The vendor kernel addresses the bearer's IPv4 to one MAC it learns once
    /// per boot, so after a router swap the new router got no IPv4 until a
    /// reboot. Point it at the router that holds the customer DHCP lease with
    /// the vendor's own command. See `titan_pd_model::host_mac`.
    fn maintain_host_mac(&mut self) {
        let router = self
            .ipv4_peer
            .filter(|(_, seen)| self.now.saturating_sub(*seen) <= PEER_HOLD)
            .map(|(peer, _)| peer.mac);
        let ready = self.passthrough && self.bridged && self.kmsg_drained;
        // Nothing to compare on most ticks: skip the sysfs reads then.
        let settled = !ready
            || router.is_none()
            || self.host_mac_watch.stored().is_some_and(|stored| Some(stored.mac) == router);
        let own: Vec<[u8; 6]> = if settled {
            Vec::new()
        } else {
            [CUSTOMER, BRIDGE, self.bearer.as_str()]
                .into_iter()
                .filter_map(interface_mac)
                .collect()
        };
        match self.host_mac_watch.decide(self.now, ready, router, &own) {
            HostMacAction::Hold => {}
            HostMacAction::Point { hostif, from, to } => {
                let (program, args) = host_mac::command(&hostif, to);
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                let result = run_status(program, &args);
                // keeper.log is on flash: one line a minute at most.
                if self
                    .host_mac_logged_at
                    .is_some_and(|at| self.now.saturating_sub(at) < 60)
                {
                    return;
                }
                self.host_mac_logged_at = Some(self.now);
                let to = ipv4::mac_text(to);
                match result {
                    Ok(()) => {
                        let from = from.map_or_else(|| "a MAC its log no longer shows".to_owned(), ipv4::mac_text);
                        self.note(&format!(
                            "router swap: the vendor kernel addressed customer IPv4 to {from}; pointed it at {to}, the router that holds the DHCP lease (kern netif hmac {hostif})"
                        ));
                    }
                    Err(err) => self.note(&format!(
                        "router swap: could not point the vendor kernel's IPv4 host MAC at {to}: {err}"
                    )),
                }
            }
            HostMacAction::GiveUp { to } => self.note(&format!(
                "router swap: the kernel log still does not show {} as the IPv4 host MAC after {} commands; trying again in {} s",
                ipv4::mac_text(to),
                host_mac::TRIES,
                host_mac::PAUSE
            )),
        }
    }

    /// Keep the vendor SNAT rule for the unit's own SAS traffic. A vendor
    /// firewall restart after a handover removes it, and in this build nothing
    /// else puts it back. Restores only after missing checks in a row, checked
    /// every 10 s, or every second for 30 s after a PDN comes up, a vendor log
    /// line that comes before a firewall restart, or any missing check.
    fn maintain_sas_nat(&mut self, routes: &str) {
        self.follow_rcinit_log();
        let interval = self.sas_watch.interval(self.now);
        if self
            .last_sas_check
            .is_some_and(|last| self.now.saturating_sub(last) < interval)
        {
            return;
        }
        self.last_sas_check = Some(self.now);
        let local_ip = self.nvram_get_cached("lan_management_ipaddr");
        let data_ip = self.nvram_get_cached("pdn_data_ipaddr");
        let snat = sas_nat::needed(&local_ip, &data_ip, routes);
        let present = snat.and_then(|snat| {
            sas_nat::present(
                &command_stdout("iptables", &["-t", "nat", "-S", "POSTROUTING"]),
                snat,
            )
        });
        let SasAction::Restore(snat) = self.sas_watch.observe(self.now, snat, present) else {
            return;
        };
        let when = if self.sas_watch.bursting(self.now) {
            "missing for 2 s in a row"
        } else {
            "missing twice in a row"
        };
        self.note(&format!(
            "SAS NAT rule {when}; restoring SNAT from {} to {} so the SAS client can reach the SAS",
            snat.local, snat.bearer
        ));
        for (program, args) in sas_nat::restore_commands(snat) {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            if let Err(err) = run_status(program, &args) {
                self.note(&format!(
                    "SAS NAT restore failed; retrying in {} s: {err}",
                    sas_nat::RETRY
                ));
                return;
            }
        }
        // Read it back at once. rcinit can flush the table again within a
        // second, before the next check; a restore seen working may repeat
        // after 5 s instead of waiting a minute.
        let back = sas_nat::present(
            &command_stdout("iptables", &["-t", "nat", "-S", "POSTROUTING"]),
            snat,
        );
        if back == Some(true) {
            self.sas_watch.confirm();
            self.note("SAS NAT rule restored");
        } else {
            self.note("SAS NAT rule restored, but it was not in the table when read back");
        }
    }

    /// `rcinit` logs `CBRS LTE Freq changed !` (an in-connection carrier
    /// change) or `Restart service=[cbrs]` just before it rebuilds its
    /// firewall and flushes the SAS SNAT rule. Neither PDN goes down, so the
    /// kernel log has no line for it. Read once a second.
    fn follow_rcinit_log(&mut self) {
        if self.rcinit_read_at == Some(self.now) {
            return;
        }
        self.rcinit_read_at = Some(self.now);
        if self
            .rcinit_log
            .lines()
            .iter()
            .any(|line| sas_nat::firewall_restart(line))
        {
            self.sas_watch.burst(self.now);
            self.last_flood = 0;
        }
    }

    /// Reboot a unit that stays attached but hears nothing through the core.
    /// Runs in NAT and in passthrough. See `titan_pd_model::deaf`.
    fn maintain_deaf_watchdog(&mut self) {
        if let Some(asked) = self.reboot_asked_at {
            let waited = self.now.saturating_sub(asked);
            if !self.reboot_forced && waited >= REBOOT_FORCE_AFTER {
                self.reboot_forced = true;
                log("watchdog reboot did not happen; forcing it");
                let _ = Command::new(reboot_program()).arg("-f").status();
            } else if self.reboot_forced && waited >= REBOOT_GIVE_UP_AFTER {
                self.reboot_asked_at = None;
                self.reboot_forced = false;
                self.deaf_watch = deaf::Watch::default();
                log("the forced watchdog reboot did not happen either; watching again");
            }
            return;
        }
        if let Some(mut probe) = self.deaf_probe.take() {
            let mut heard = false;
            let mut running = false;
            for child in probe.children.iter_mut() {
                match child.try_wait() {
                    Ok(Some(status)) => heard |= status.success(),
                    Ok(None) => running = true,
                    Err(_) => {}
                }
            }
            let timed_out = self.now.saturating_sub(probe.started) >= deaf::PROBE_TIMEOUT;
            if !heard && running && !timed_out {
                self.deaf_probe = Some(probe);
                return;
            }
            for child in probe.children.iter_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
            self.deaf_round(Some(heard));
            return;
        }
        if self
            .last_deaf_round
            .is_some_and(|last| self.now.saturating_sub(last) < deaf::PROBE_EVERY)
        {
            return;
        }
        self.last_deaf_round = Some(self.now);
        let settings = deaf::parse_settings(&read_file(state_dir().join("watchdog.conf")));
        self.deaf_secs = settings.deaf_secs;
        self.maintain_vendor_watchdog(&settings);
        if !settings.enabled {
            self.deaf_round(None);
            return;
        }
        let bearer_dns = if settings.targets.is_empty() {
            self.nvram_get_cached("wan_get_dns")
        } else {
            String::new()
        };
        let targets = deaf::targets(&settings, &bearer_dns);
        let children = spawn_pings(&targets);
        if children.is_empty() {
            self.deaf_round(None);
            return;
        }
        self.deaf_probe = Some(DeafProbe {
            children,
            started: self.now,
        });
    }

    /// Run one watchdog, not two. The vendor's (`ucid`, nvram `detection_enable`)
    /// reboots after about 110 s without its ping target and has no backoff, so
    /// two setting saves in a row can reboot the unit. `ucid` reads the flag from
    /// the RAM cache every 15 s, so clearing it there is enough and nothing is
    /// committed to flash. An operator who turns this watchdog off keeps the
    /// vendor setting as saved.
    fn maintain_vendor_watchdog(&mut self, settings: &deaf::Settings) {
        let value = self
            .read_nvram_cache()
            .and_then(|cache| deaf::nvram_field(cache, "detection_enable"))
            .map(str::to_owned);
        if !deaf::vendor_watchdog_must_stop(settings, value.as_deref()) {
            return;
        }
        let was = value.as_deref().unwrap_or("").trim().to_owned();
        let done = crate::nvram::set("detection_enable", "0").is_ok();
        // Something that keeps turning it back on must not fill the flash log.
        let quiet = self
            .vendor_watchdog_logged
            .is_some_and(|at| self.now.saturating_sub(at) < 3600);
        if quiet {
            return;
        }
        self.vendor_watchdog_logged = Some(self.now);
        if done {
            self.note(&format!(
                "vendor ping watchdog: turned off in RAM for this boot (detection_enable was {was}); the keeper's deaf watchdog covers this unit"
            ));
        } else {
            self.note("vendor ping watchdog: could not turn it off; two watchdogs may reboot this unit");
        }
    }

    fn deaf_round(&mut self, heard: Option<bool>) {
        // A guarded radio cycle deliberately interrupts the management bearer.
        if crate::radio::transition_in_progress(self.now) {
            self.deaf_watch = deaf::Watch::default();
            return;
        }
        let attached = deaf::attached(&self.nvram_get_cached("sqns_connection_mediaState"));
        let path = state_dir().join("watchdog-strikes.txt");
        let strikes = deaf::parse_strikes(&read_file(&path));
        match self
            .deaf_watch
            .observe(self.now, attached, heard, self.deaf_secs, strikes)
        {
            DeafAction::Hold => {}
            DeafAction::Armed => self.note(&format!(
                "deaf watchdog armed: a target answered through the core; {} s of silence while attached will reboot the unit",
                deaf::required_silence(self.deaf_secs, strikes)
            )),
            DeafAction::Silent => {
                self.note("deaf watchdog: attached, but no target answered this round");
                if self.passthrough {
                    // The known cause of a deaf passthrough unit needs no reboot.
                    self.note(
                        "deaf watchdog: trying the passthrough repair first (external device and management MAC)",
                    );
                    self.repair_external_dev(mgmt::MGMT_DEV);
                }
            }
            DeafAction::Recovered { silent_for } => self.note(&format!(
                "deaf watchdog: answers are back after {silent_for} s of silence"
            )),
            DeafAction::ClearStrikes => {
                if store_strikes(&path, 0) {
                    self.note("deaf watchdog: an hour of answers; earlier reboots are forgotten");
                } else {
                    // Ask again next round rather than keep the old count all boot.
                    self.deaf_watch.clear_failed();
                }
            }
            DeafAction::Reboot { silent_for } => {
                store_strikes(&path, strikes.saturating_add(1));
                self.note(&format!(
                    "deaf watchdog: attached but nothing heard through the core for {silent_for} s; rebooting (reboot {} in a row)",
                    strikes.saturating_add(1)
                ));
                self.request_reboot();
            }
        }
    }

    /// A watchdog reboot. `maintain_deaf_watchdog` forces it if it does not
    /// happen.
    fn request_reboot(&mut self) {
        titan_sys::kernel::sync();
        self.reboot_asked_at = Some(self.now);
        self.reboot_forced = false;
        let _ = Command::new(reboot_program())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
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

    /// Load the staged download clamp once the customer port and LTE are up,
    /// and keep its mode as `qctrl/config` says. Runs in every mode.
    fn maintain_qctrl(&mut self) {
        if self
            .qctrl
            .checked_at
            .is_some_and(|at| self.now.saturating_sub(at) < qctrl::CHECK_EVERY)
        {
            return;
        }
        self.qctrl.checked_at = Some(self.now);
        let Some(dir) = qctrl_io::staged_dir() else {
            self.qctrl_status("off", "the persistent volume is not mounted", &qctrl::Config::default());
            return;
        };
        let config = qctrl::parse_config(&read_file(dir.join("config")));
        if config.refused != self.qctrl.refused_logged {
            for line in &config.refused {
                self.note(&format!(
                    "download clamp: ignored {line:?} in qctrl/config (allowed: mode=0|2|3|6, trough_ms=0..40, target_ms=4..80, ack_adapt=0|1, ctrl_v3=0|1, ack_ms=1..10, ack_segs=2..32, ack_min_kbps=0..100000)"
                ));
            }
            self.qctrl.refused_logged = config.refused.clone();
        }
        let up = carrier_up(CUSTOMER) && (config.mode == 0 || mgmt_address_up());
        if !up {
            self.qctrl.up_since = None;
        } else if self.qctrl.up_since.is_none() {
            self.qctrl.up_since = Some(self.now);
        }
        let proc_text = read_file(&qctrl_io::proc_path());
        let mut proc_fresh = true;
        match qctrl::loaded(&read_file(&qctrl_io::modules_path()), &proc_text) {
            QctrlLoaded::Other(name) => {
                let (state, detail) = if config.mode == 0 {
                    ("off", format!("mode 0; another clamp module is loaded ({name})"))
                } else {
                    ("failed", format!("another clamp module is loaded ({name}); not loading {}", qctrl::MODULE))
                };
                self.qctrl_status(state, &detail, &config);
                return;
            }
            QctrlLoaded::None => {
                if config.mode == 0 {
                    self.qctrl_status("off", "mode 0 or no qctrl/config", &config);
                    return;
                }
                if !qctrl::settled(self.qctrl.up_since, self.now) {
                    self.qctrl_status(
                        "waiting",
                        &format!("for the customer port and LTE to stay up {} s", qctrl::SETTLE_SECS),
                        &config,
                    );
                    return;
                }
                if self.qctrl.failed_for.as_ref() == Some(&config) {
                    return;
                }
                if let Err(err) = qctrl_io::stage(&dir).and_then(|path| qctrl_io::insmod(&path)) {
                    self.qctrl.failed_for = Some(config.clone());
                    self.qctrl_status("failed", &format!("not loaded: {err}"), &config);
                    return;
                }
                self.note(&format!("download clamp: loaded {} from the staged copy", qctrl::VERSION_LINE));
                proc_fresh = false;
            }
            QctrlLoaded::Ours => {}
        }
        let mut proc = if proc_fresh {
            qctrl::parse_proc(&proc_text)
        } else {
            qctrl::parse_proc(&read_file(&qctrl_io::proc_path()))
        };
        if !proc.ours {
            self.qctrl.failed_for = Some(config.clone());
            self.qctrl_status(
                "failed",
                &format!("/proc/titan_qctrl does not show {}", qctrl::VERSION_LINE),
                &config,
            );
            return;
        }
        if !qctrl::matches(&config, &proc) {
            if let Err(err) = qctrl_io::write_proc(&qctrl::proc_writes(&config)) {
                self.qctrl_status("failed", &err, &config);
                return;
            }
            proc = qctrl::parse_proc(&read_file(&qctrl_io::proc_path()));
        }
        if !qctrl::matches(&config, &proc) {
            let shown = proc.mode.map_or_else(|| "nothing".to_owned(), |m| m.to_string());
            self.qctrl_status(
                "failed",
                &format!("mode {} did not read back (shows {shown})", config.mode),
                &config,
            );
            return;
        }
        let state = if config.mode == 0 { "off" } else { "applied" };
        let detail = format!(
            "mode {} read back from /proc/titan_qctrl{}{}{}{}{}{}{}",
            config.mode,
            config.trough_ms.map_or_else(String::new, |ms| format!(", trough_ms {ms}")),
            config.target_ms.map_or_else(String::new, |ms| format!(", target_ms {ms}")),
            config.ack_adapt.map_or_else(String::new, |v| format!(", ack_adapt {v}")),
            config.ctrl_v3.map_or_else(String::new, |v| format!(", ctrl_v3 {v}")),
            config.ack_ms.map_or_else(String::new, |ms| format!(", ack_ms {ms}")),
            config.ack_segs.map_or_else(String::new, |s| format!(", ack_segs {s}")),
            config.ack_min_kbps.map_or_else(String::new, |k| format!(", ack_min_kbps {k}"))
        );
        self.qctrl_status(state, &detail, &config);
    }

    /// Write the clamp status file and log the change. A unit that never
    /// staged a clamp logs nothing.
    fn qctrl_status(&mut self, state: &str, detail: &str, config: &qctrl::Config) {
        self.qctrl.waiting = state == "waiting";
        let key = format!("{state}: {detail}");
        if key == self.qctrl.shown {
            return;
        }
        let quiet = state == "off" && self.qctrl.shown.is_empty();
        self.qctrl.shown = key;
        let _ = fs::write(qctrl_io::status_path(), qctrl::status(state, detail, config, self.now));
        if !quiet {
            self.note(&format!("download clamp {state}: {detail}"));
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

    /// Install the core-assigned interface id on ue-mgmt and solicit from it.
    /// Runs in NAT and in passthrough, whether or not prefix delegation is on.
    fn maintain_mgmt_v6(&mut self) {
        if self.now.saturating_sub(self.last_mgmt) < MGMT_EVERY && self.last_mgmt != 0 {
            return;
        }
        self.last_mgmt = self.now;
        if !carrier_up(mgmt::MGMT_DEV) {
            self.mgmt_settled = false;
            return;
        }
        // An IPv4-only bearer: the modem turns IPv6 off here, and no address can be added.
        if read_file("/proc/sys/net/ipv6/conf/lte0pdn0/disable_ipv6").trim() == "1" {
            self.mgmt_settled = false;
            return;
        }
        if !self.mgmt_klog_checked || self.kernel_log.is_none() {
            self.mgmt_klog_checked = true;
            if let Some(iid) = mgmt::assigned_iid(&kernel_messages()) {
                self.mgmt_iid = Some(iid);
            }
        }
        let assigned = self.mgmt_iid;
        let cached = cached_mgmt_iid();
        let iid = match assigned.or(cached) {
            Some(iid) => iid,
            None => return,
        };
        if assigned.is_some() && assigned != cached {
            let _ = fs::write(
                state_dir().join("mgmt-iid.txt"),
                format!("{}\n", iid.token()),
            );
        }
        let addrs = proc_if_inet6_addrs(mgmt::MGMT_DEV);
        let accept = read_file("/proc/sys/net/ipv6/conf/lte0pdn0/accept_ra");
        let up = mgmt::global_up(iid, &addrs);
        if self.mgmt_settled
            && up
            && accept.trim() == "0"
            && self.now.saturating_sub(self.last_mgmt_route_verify) < MGMT_ROUTE_VERIFY
        {
            self.scrub_mgmt_off_lan(&addrs);
            return;
        }
        let routes = command_stdout("ip", &["-6", "route", "show"]);
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
            self.mgmt_settled = false;
            if self.now.saturating_sub(self.last_mgmt_log) >= MGMT_LOG_EVERY {
                self.note(&format!(
                    "ue-mgmt has no global; soliciting from {} so the assigned prefix can come up",
                    iid.link_local()
                ));
                self.last_mgmt_log = self.now;
            }
        }
        if steps.is_empty() && up && accept.trim() == "0" {
            self.mgmt_settled = true;
            self.last_mgmt_route_verify = self.now;
            return;
        }
        self.mgmt_settled = false;
        for step in steps {
            if step == Step::IgnoreAdvertisements {
                self.note(
                    "ue-mgmt ipv6: closing lte0pdn0 to further router advertisements (accept_ra=0)",
                );
            }
            if matches!(step, Step::DropKeptDefault(_)) {
                self.note(
                    "ue-mgmt ipv6: removing the permanent default so the kernel can take the advertisement",
                );
            }
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
            Step::IgnoreAdvertisements => {
                fs::write("/proc/sys/net/ipv6/conf/lte0pdn0/accept_ra", "0\n")
                    .map_err(|err| format!("accept_ra: {err}"))
            }
            Step::KeepLearnedDefault(metric) => {
                // `replace` turns the learned route into a plain one with no
                // expiry. On this kernel a duplicate `add` leaves the expiry.
                let metric = metric.to_string();
                run_status(
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
                        &metric,
                    ],
                )
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
            Step::DropKeptDefault(metric) => {
                let metric = metric.to_string();
                run_status(
                    "ip",
                    &[
                        "-6",
                        "route",
                        "del",
                        "default",
                        "via",
                        "fe80::1",
                        "dev",
                        mgmt::MGMT_DEV,
                        "metric",
                        &metric,
                    ],
                )
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
        let bridge = proc_if_inet6_addrs(BRIDGE);
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

    fn load_budget(&mut self) {
        let text = read_file(state_dir().join("budget.txt"));
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

    fn save_budget(&mut self) -> bool {
        let path = state_dir().join("budget.txt");
        let text = format!(
            "link_drops={}\nwindow_start={}\nquiet_until={}\n",
            self.health.link_drops, self.health.window_start, self.health.quiet_until
        );
        if read_file(&path) != text {
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
        let ok = read_file(&path) == text;
        if ok {
            self.saved_budget = Some(self.budget_tuple());
        }
        ok
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

/// What a link-drop budget step runs. One PHY renegotiation. Not a burst,
/// and not an administrative carrier down, which this router ignores.
fn link_recovery() -> (&'static str, &'static [&'static str]) {
    ("mii-tool", &["-r", CUSTOMER])
}

fn reboot_program() -> String {
    std::env::var("TITAN_REBOOT").unwrap_or_else(|_| "reboot".into())
}

/// One ping to each target, collected on later ticks.
fn spawn_pings(targets: &[std::net::IpAddr]) -> Vec<std::process::Child> {
    targets
        .iter()
        .filter_map(|target| {
            let program = if target.is_ipv6() { "ping6" } else { "ping" };
            let address = target.to_string();
            Command::new(std::env::var("TITAN_PING").unwrap_or_else(|_| program.into()))
                .args(["-c", "1", "-W", "4", address.as_str()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .ok()
        })
        .collect()
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

/// The management bearer has an IPv4 or global IPv6 address (checked via
/// rtnetlink `getifaddrs` without spawning `ip`).
fn mgmt_address_up() -> bool {
    if !carrier_up(mgmt::MGMT_DEV) {
        return false;
    }
    let Ok(addrs) = InterfaceAddrs::read() else {
        return command_stdout("ip", &["addr", "show", "dev", mgmt::MGMT_DEV])
            .lines()
            .map(str::trim)
            .any(|line| {
                line.starts_with("inet ")
                    || (line.starts_with("inet6 ") && line.contains("scope global"))
            });
    };
    addrs
        .iter()
        .filter(|addr| addr.is_on(mgmt::MGMT_DEV))
        .any(|addr| match addr.addr {
            IpAddr::V4(_) => true,
            IpAddr::V6(ip) => {
                let o = ip.octets();
                let link_local = o[0] == 0xfe && (o[1] & 0xc0) == 0x80;
                !link_local && !ip.is_loopback() && !ip.is_unspecified()
            }
        })
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

/// Write the strike count through a temporary file, so a power cut cannot
/// leave a torn record.
fn store_strikes(path: &std::path::Path, strikes: u32) -> bool {
    let temp = path.with_extension("tmp");
    fs::write(&temp, deaf::format_strikes(strikes)).is_ok() && fs::rename(&temp, path).is_ok()
}

fn published_detail(existing: &str, argument: &str) -> String {
    if argument.is_empty() {
        existing.to_owned()
    } else {
        argument.to_owned()
    }
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

/// Diagnostic: one router solicitation on the management bearer, from the
/// core-assigned link-local. Changes no setting.
pub fn solicit_once() -> Result<Ipv6Addr, String> {
    let dmesg = command_stdout("dmesg", &[]);
    let iid = mgmt::assigned_iid(&dmesg)
        .or_else(cached_mgmt_iid)
        .ok_or("the modem has not reported an interface identifier for lte0pdn0")?;
    let source = iid.link_local();
    solicit_mgmt(source)?;
    Ok(source)
}

fn solicit_mgmt(src: Ipv6Addr) -> Result<(), String> {
    let mac = read_mac(mgmt::MGMT_DEV)?;
    let ifindex = interface_index(mgmt::MGMT_DEV).ok_or("lte0pdn0 has no interface index")?;
    let packet = mgmt::solicitation(mac);
    // Closed when this function returns, including on the error paths below.
    let socket = Socket::icmpv6_raw().map_err(|err| format!("socket: {err}"))?;
    let scope = ifindex as u32;
    socket
        .bind_ipv6(src, scope)
        .map_err(|err| format!("bind: {err}"))?;
    socket
        .bind_to_device(mgmt::MGMT_DEV)
        .map_err(|err| format!("bind to device: {err}"))?;
    socket
        .set_ipv6_multicast_hops(255)
        .map_err(|err| format!("hop limit: {err}"))?;
    socket
        .set_ipv6_multicast_if(ifindex)
        .map_err(|err| format!("multicast interface: {err}"))?;
    let all_routers = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
    socket
        .send_ipv6(&packet, all_routers, scope)
        .map_err(|err| format!("router solicitation: {err}"))?;
    Ok(())
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

/// Bytes read from a vendor log per call, so a large backlog cannot stall a tick.
const TAIL_READ: u64 = 64 * 1024;

/// A vendor log file, read from where the keeper left off. Lines already in
/// the file when it is first opened are history and are skipped. `rcinit`
/// caps its log at 64 KB and then starts it again empty, so a file shorter
/// than the offset is read from the start.
struct FileTail {
    path: PathBuf,
    offset: Option<u64>,
    pending: Vec<u8>,
}

impl FileTail {
    fn new(path: PathBuf) -> Self {
        let mut tail = Self {
            path,
            offset: None,
            pending: Vec::new(),
        };
        let _ = tail.lines();
        tail
    }

    /// Complete lines added since the last call.
    fn lines(&mut self) -> Vec<String> {
        use std::io::{Read, Seek, SeekFrom};
        let Ok(mut file) = fs::File::open(&self.path) else {
            return Vec::new();
        };
        let Ok(len) = file.metadata().map(|meta| meta.len()) else {
            return Vec::new();
        };
        let start = match self.offset {
            None => {
                self.offset = Some(len);
                return Vec::new();
            }
            Some(at) if len < at => {
                self.pending.clear();
                0
            }
            Some(at) => at,
        };
        if len == start {
            self.offset = Some(len);
            return Vec::new();
        }
        let mut chunk = Vec::new();
        if file.seek(SeekFrom::Start(start)).is_err()
            || (&mut file).take(TAIL_READ).read_to_end(&mut chunk).is_err()
        {
            return Vec::new();
        }
        self.offset = Some(start + chunk.len() as u64);
        self.pending.extend_from_slice(&chunk);
        let mut lines = Vec::new();
        while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=end).collect();
            lines.push(String::from_utf8_lossy(&line).trim_end().to_owned());
        }
        if self.pending.len() > 16 * 1024 {
            self.pending.clear();
        }
        lines
    }
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
    fn link_recovery_is_one_renegotiation() {
        let (program, args) = link_recovery();
        assert_eq!(program, "mii-tool");
        assert_eq!(args, ["-r", "eth0"]);
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

    #[test]
    fn a_vendor_log_is_followed_from_its_end_and_again_after_a_reset() {
        use std::io::Write;
        let path = std::env::temp_dir().join(format!("witcher-tail-{}", std::process::id()));
        fs::write(&path, " 4:00:00 >|service.c 500 >|   info >| CBRS LTE Freq changed !\n").unwrap();
        let mut tail = FileTail::new(path.clone());
        // What was there before the keeper started is history.
        assert!(tail.lines().is_empty());
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        write!(file, " 4:58:41 >|service.c 500 >|   info >| CBRS LTE").unwrap();
        assert!(tail.lines().is_empty(), "half a line waits for the rest");
        writeln!(file, " Freq changed !").unwrap();
        assert_eq!(
            tail.lines(),
            vec![" 4:58:41 >|service.c 500 >|   info >| CBRS LTE Freq changed !".to_owned()]
        );
        assert!(tail.lines().is_empty());
        // rcinit caps its log at 64 KB and then starts it again empty.
        fs::write(&path, " 0:00:01 >|service.c 528 >|   info >| Restart service=[cbrs]\n").unwrap();
        assert_eq!(
            tail.lines(),
            vec![" 0:00:01 >|service.c 528 >|   info >| Restart service=[cbrs]".to_owned()]
        );
        let _ = fs::remove_file(&path);
    }

}
