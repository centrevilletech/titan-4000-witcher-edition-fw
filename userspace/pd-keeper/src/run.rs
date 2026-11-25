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
//! loads the download clamp, on by default since v1.0.17 (see
//! `titan_pd_model::qctrl`), and in passthrough the fast path (see
//! `titan_pd_model::fastpath`). `/mnt/titan-api/latency/config` turns the
//! modem words, the clamp and the fast path off (see
//! `titan_pd_model::switches`).
//!
//! This module holds the `Keeper` state and the loop: `tick` runs each part
//! in turn and `wait_next` sleeps until a control frame, a kernel log line or
//! the next second. Each part lives in a submodule as an `impl Keeper` block:
//!
//! - `delegation`: IPv6 prefix delegation, with `packet` (building and
//!   classifying packets), `wire` (the packet sockets) and `if_inet6`
//! - `ipv4_repair`: the IPv4 passthrough repair, with `routes` and `udhcpd`
//! - `budget`: the Ethernet action budget both share
//! - `mode`, `kmsg`, `flow`, `mac`, `sas`, `gate`, `carrier`: the bearer
//!   mode, the kernel log and what follows it, 802.3x flow control, the MAC
//!   repairs, the SAS NAT rule, the CBRS gate and the carrier watch
//! - `watchdog`, `tk`, `clamp`, `mgmt_v6`: the deaf watchdog, the staged
//!   modem firmware's boot confirm and flags, the download clamp and
//!   management IPv6
//! - `latency`: the off switches for the modem words, the clamp and the
//!   fast path

use std::fs;
use std::io::ErrorKind;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::process::Command;
use std::thread;
use std::time::Duration;

use titan_pd_model::cbrs_gate;
use titan_pd_model::config::{self, Config, Report};
use titan_pd_model::deaf;
use titan_pd_model::driver_mac;
use titan_pd_model::ethernet;
use titan_pd_model::extdev;
use titan_pd_model::health::Health;
use titan_pd_model::host_mac;
use titan_pd_model::ipv4;
use titan_pd_model::ipv4_health::{self, Peer};
use titan_pd_model::mgmt;
use titan_pd_model::pace::Pace;
use titan_pd_model::prefix::Block;
use titan_pd_model::sas_nat;
use titan_pd_model::tk_boot;
use titan_pd_model::tk_flags;
use titan_pd_model::wear::{self, Route};

use crate::{cpu_trims_io, fastpath_io, log, log_ram, nvram};
use crate::clock::{monotonic, unix_now};
use crate::command::command_stdout;
use crate::paths::{env_or, env_path_or, state_dir};

use self::carrier::CarrierWatch;
use self::clamp::QctrlWatch;
use self::delegation::CORE_MAC;
use self::kmsg::KernelLog;
use self::latency::SwitchWatch;
use self::routes::main_routes;
use self::sas::FileTail;
use self::watchdog::PingRound;
use self::wire::ControlSockets;

mod budget;
mod carrier;
mod clamp;
mod delegation;
mod flow;
mod gate;
mod if_inet6;
mod ipv4_repair;
mod kmsg;
mod latency;
mod mac;
mod mgmt_v6;
mod mode;
mod packet;
mod radio_reboot;
pub(crate) mod reboot;
mod routes;
mod sas;
mod tk;
mod udhcpd;
mod watchdog;
mod wire;

pub use self::mgmt_v6::solicit_once;

const CUSTOMER: &str = "eth0";
const BRIDGE: &str = "br0";
/// The customer bearer when neither the bridge nor the vendor names one.
const DEFAULT_BEARER: &str = "lte0pdn1";
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
    last_sas_check: Pace,
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
    link_rx_at: Pace,
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
    vendor_watchdog_logged: Pace,
    last_mgmt: u64,
    last_mgmt_log: u64,
    mgmt_up_logged: bool,
    mgmt_iid: Option<mgmt::Iid>,
    mgmt_klog_checked: bool,
    mgmt_settled: bool,
    last_mgmt_route_verify: u64,
    deaf_watch: deaf::Watch,
    deaf_probe: Option<PingRound>,
    deaf_secs: u64,
    last_deaf_round: Pace,
    reboot_asked_at: Option<u64>,
    reboot_forced: bool,
    /// Something answered through the core this boot (`reboot::Kind`'s gate).
    heard_this_boot: bool,
    /// Why the deaf watchdog's due reboot waits, once noted.
    deaf_reboot_held: Option<String>,
    /// Why the radio profile guard's restart waits, once noted.
    radio_reboot_held: Option<String>,
    /// The bearer bridged to the customer port, or the vendor's data bearer.
    bearer: String,
    mode_checked: Pace,
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
    driver_logged_at: Pace,
    /// The vendor kernel's IPv4 host MAC, read from its log and kept on the
    /// router that holds the customer lease. See `titan_pd_model::host_mac`.
    host_mac_watch: host_mac::Watch,
    host_mac_logged_at: Pace,
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
    tk_probe: Option<PingRound>,
    tk_last_round: Pace,
    /// The boot hook's status, read once at start.
    tk_status: tk_boot::BootStatus,
    /// The boot confirm's times (`tk_boot::Timing`) and this firmware build
    /// (`tk_boot::firmware_id`), read once.
    tk_timing: tk_boot::Timing,
    tk_firmware: String,
    /// The last line about a tk reboot that waits, so it is noted once.
    tk_hold_noted: Option<String>,
    /// A recorded rollback's reboot an earlier keeper process did not finish.
    tk_away_owed: bool,
    /// The reboot back onto this image after a verdict (`tk_verdict`).
    tk_back_owed: Option<String>,
    /// The default image's modem crashed this boot (stock firmware runs).
    tk_crashed: bool,
    /// When this boot's image confirmed, for its crash count to clear.
    tk_confirmed_at: Option<u64>,
    /// Modem feature flags after a confirmed staged boot (see
    /// `titan_pd_model::tk_flags`), and the DM session running for them.
    tk_flags: Option<tk_flags::Control>,
    tk_flags_job: Option<(std::thread::JoinHandle<(tk_flags::Outcome, bool)>, tk_flags::Plan)>,
    tk_flags_config_at: Pace,
    tk_flags_refused: Vec<String>,
    tk_flags_config_hands_off: bool,
    /// The kernel log showed a modem firmware load after the keeper started.
    modem_restart_seen: bool,
    /// The latency switches (see `titan_pd_model::switches`).
    switches: SwitchWatch,
    /// The download clamp (see `titan_pd_model::qctrl`).
    qctrl: QctrlWatch,
    /// The passthrough bridge fast path (see `titan_pd_model::fastpath`).
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
    let program = env_or("TITAN_TC", "tc");
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
            last_sas_check: Pace::default(),
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
            link_rx_at: Pace::default(),
            ipv6_router: None,
            eth0_down_since: None,
            ipv4_conf_good: None,
            rcinit_log: FileTail::new(env_path_or("TITAN_RCINIT_LOG", "/tmp/rcinit.log")),
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
            vendor_watchdog_logged: Pace::default(),
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
            last_deaf_round: Pace::default(),
            reboot_asked_at: None,
            reboot_forced: false,
            heard_this_boot: false,
            deaf_reboot_held: None,
            radio_reboot_held: None,
            bearer: DEFAULT_BEARER.to_owned(),
            mode_checked: Pace::default(),
            bridged: false,
            bridged_since: None,
            ipv4_peer: None,
            kernel_log: KernelLog::open(),
            ext_watch: extdev::Watch::default(),
            ipv4_gateway: None,
            driver_watch: driver_mac::Watch::default(),
            driver_fixes: 0,
            driver_logged_at: Pace::default(),
            host_mac_watch: host_mac::Watch::default(),
            host_mac_logged_at: Pace::default(),
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
            tk_last_round: Pace::default(),
            tk_status: tk_boot::BootStatus::default(),
            tk_timing: tk_boot::Timing::default(),
            tk_firmware: String::new(),
            tk_hold_noted: None,
            tk_away_owed: false,
            tk_back_owed: None,
            tk_crashed: false,
            tk_confirmed_at: None,
            tk_flags: None,
            tk_flags_job: None,
            tk_flags_config_at: Pace::default(),
            tk_flags_refused: Vec::new(),
            tk_flags_config_hands_off: false,
            modem_restart_seen: false,
            switches: SwitchWatch::default(),
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
        let [arp, dhcp, ipv6] = self
            .sockets
            .as_ref()
            .map_or([None; 3], ControlSockets::receivers);
        let kernel_log = self
            .kernel_log
            .as_ref()
            .filter(|klog| klog.is_pollable())
            .map(|klog| klog.as_fd());
        let fds = [arp, dhcp, ipv6, kernel_log];
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
        self.maintain_radio_reboot();
        self.maintain_switches();
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
        self.maintain_delegation(loaded);
        Ok(())
    }

    /// Load and maintain the passthrough bridge fast path after the download
    /// clamp (see `titan_pd_model::fastpath`).
    fn maintain_fastpath(&mut self) {
        let now = self.now;
        let passthrough = self.passthrough;
        let qctrl_waiting = self.qctrl.waiting;
        let switch_on = self.switches.now.fastpath;
        let cache = nvram::cache_path();
        let mut lines = Vec::new();
        self.fastpath
            .maintain(now, passthrough, qctrl_waiting, switch_on, &cache, |line| {
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

}

fn published_detail(existing: &str, argument: &str) -> String {
    if argument.is_empty() {
        existing.to_owned()
    } else {
        argument.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

}
