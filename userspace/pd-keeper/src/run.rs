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
use std::io::ErrorKind;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
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
use titan_pd_model::prefix::Block;
use titan_pd_model::sas_nat;
use titan_pd_model::tk_boot::{self, Action as TkAction};
use titan_pd_model::tk_flags;
use titan_pd_model::wear::{self, Route};

use crate::{cpu_trims_io, fastpath_io, log, log_ram, nvram, tk_flags_io};
use crate::clock::{monotonic, unix_now};
use crate::command::command_stdout;
use crate::files::{read_file, write_durably};
use crate::paths::{env_or, env_path_or, state_dir};

use self::carrier::CarrierWatch;
use self::clamp::QctrlWatch;
use self::delegation::CORE_MAC;
use self::kmsg::KernelLog;
use self::mgmt_v6::mgmt_address_up;
use self::routes::main_routes;
use self::sas::FileTail;
use self::watchdog::{DeafProbe, spawn_pings};
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
    write_durably(path, &path.with_extension("tmp"), bytes).is_ok()
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
