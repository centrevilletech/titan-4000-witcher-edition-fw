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
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use std::os::unix::process::CommandExt;
use titan_pd_model::cbrs_gate::{self, Step as GateStep, Tool as GateTool};
use titan_pd_model::config::{self, Config, Report};
use titan_pd_model::deaf::{self, Action as DeafAction};
use titan_pd_model::dhcpv6::{self, client_mac};
use titan_pd_model::driver_mac::{self, Action as DriverAction};
use titan_pd_model::ethernet;
use titan_pd_model::extdev::{self, Action as ExtAction};
use titan_pd_model::filter;
use titan_pd_model::health::{self, Decision, Health, Phase, View};
use titan_pd_model::ipv4::{self, Ipv4Plan};
use titan_pd_model::ipv4_health::{self, Action as Ipv4Action, Armed, Peer, Traffic};
use titan_pd_model::mgmt::{self, Step};
use titan_pd_model::prefix::Block;
use titan_pd_model::ra::{self, Advertisement};
use titan_pd_model::sas_nat::{self, Action as SasAction};
use titan_pd_model::qctrl::{self, Loaded as QctrlLoaded};
use titan_pd_model::tk_boot::{self, Action as TkAction};
use titan_pd_model::tk_flags;
use titan_pd_model::wear::{self, Route};

use crate::{log, log_ram, qctrl_io, tk_flags_io};

const CUSTOMER: &str = "eth0";
const BRIDGE: &str = "br0";
/// The customer bearer when neither the bridge nor the vendor names one.
const DEFAULT_BEARER: &str = "lte0pdn1";
/// How often the vendor mode is asked when the bridge has no LTE port.
const MODE_EVERY: u64 = 5;
/// Kernel log records read per tick, so a long backlog cannot stall the loop.
const KMSG_PER_TICK: usize = 1024;
/// Seconds between reads of `tk/config` for flag changes.
const TK_FLAGS_CONFIG_EVERY: u64 = 15;
const RA_INTERVAL: u64 = 45;
const SNIFF_SECS: u64 = 3;
const SERVE_RETRY: u64 = 60;
const FLOOD_INTERVAL: u64 = 30;
/// Seconds the IPv4 check keeps its router through an unreadable lease file.
const PEER_HOLD: u64 = 8;
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
    /// The kernel log showed a modem firmware load after the keeper started.
    modem_restart_seen: bool,
    /// The staged download clamp (see `titan_pd_model::qctrl`).
    qctrl: QctrlWatch,
}

/// The download clamp's progress this boot.
#[derive(Default)]
struct QctrlWatch {
    checked_at: Option<u64>,
    /// The customer port and the management bearer were both up since then.
    up_since: Option<u64>,
    /// The last status, so the file and the log change only on news.
    shown: String,
    /// A load failed for this config. It is not retried until the config changes.
    failed_for: Option<qctrl::Config>,
    refused_logged: Vec<String>,
}

/// One round of pings, collected on later ticks so the wire loop keeps running.
struct DeafProbe {
    children: Vec<std::process::Child>,
    started: u64,
}

/// The kernel log, read without blocking. `/dev/kmsg` hands out one record per
/// read, starting with the oldest one still held, so the first ticks replay
/// what happened before the keeper started.
struct KernelLog {
    fd: libc::c_int,
    pending: Vec<u8>,
}

impl KernelLog {
    fn open() -> Option<Self> {
        if let Ok(path) = std::env::var("TITAN_KMSG") {
            return Self::open_path(&path);
        }
        Self::open_path("/dev/kmsg").or_else(|| {
            // The vendor image ships no /dev/kmsg node. Character device 1,11
            // is the kernel log on Linux, so make one in RAM.
            let node = "/tmp/titan-kmsg";
            let name = std::ffi::CString::new(node).ok()?;
            let device: libc::dev_t = (1 << 8) | 11;
            unsafe { libc::mknod(name.as_ptr(), libc::S_IFCHR | 0o600, device) };
            Self::open_path(node)
        })
    }

    fn open_path(path: &str) -> Option<Self> {
        let path = std::ffi::CString::new(path).ok()?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        (fd >= 0).then(|| Self {
            fd,
            pending: Vec::new(),
        })
    }

    /// Complete lines that have arrived since the last call, and whether the
    /// log was read to its end. At start the backlog takes a few ticks.
    fn lines(&mut self) -> (Vec<String>, bool) {
        let mut lines = Vec::new();
        let mut buf = [0u8; 4096];
        let mut drained = false;
        for _ in 0..KMSG_PER_TICK {
            let read = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
            if read > 0 {
                self.pending.extend_from_slice(&buf[..read as usize]);
                while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
                    let line: Vec<u8> = self.pending.drain(..=end).collect();
                    lines.push(String::from_utf8_lossy(&line).trim_end().to_owned());
                }
                if self.pending.len() > 16 * 1024 {
                    self.pending.clear();
                }
                continue;
            }
            if read == 0 {
                drained = true;
                break;
            }
            match io::Error::last_os_error().raw_os_error() {
                // Records were overwritten before they were read. The next read resumes.
                Some(libc::EPIPE) | Some(libc::EINTR) => continue,
                // Nothing more for now (EAGAIN), or a log that cannot be read.
                _ => {
                    drained = true;
                    break;
                }
            }
        }
        (lines, drained)
    }
}

impl Drop for KernelLog {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
            self.fd = -1;
        }
    }
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
            flow_watch: ethernet::Watch::default(),
            flow_checked: None,
            kmsg_drained: false,
            flow_pending: false,
            flow_logged: false,
            flow_failed_logged: false,
            flow_stock_logged: false,
            cbrs_gate: cbrs_gate::Watch::default(),
            tk_checked: false,
            tk_confirm: None,
            tk_probe: None,
            tk_last_round: None,
            tk_status: tk_boot::BootStatus::default(),
            tk_flags: None,
            tk_flags_job: None,
            tk_flags_config_at: None,
            tk_flags_refused: Vec::new(),
            modem_restart_seen: false,
            qctrl: QctrlWatch::default(),
        }
    }

    fn tick(&mut self) -> Result<(), String> {
        self.refresh_mode();
        // First, and in every mode: nothing below may delay it.
        self.maintain_cbrs_gate();
        self.maintain_external_dev();
        self.maintain_flow_control();
        self.maintain_deaf_watchdog();
        self.maintain_tk_confirm();
        self.maintain_tk_flags();
        self.maintain_qctrl();
        self.maintain_mgmt_v6();
        if !self.passthrough {
            self.packet = None;
            self.ipv4_watch.reset();
            self.ipv4_peer = None;
            self.sas_watch.reset();
            self.driver_watch.reset();
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
        // Both guards must see the same main-table snapshot on this tick.
        let routes = main_routes();
        self.maintain_ipv4(&routes);
        self.maintain_ipv4_link(&routes);
        self.maintain_driver_mac();
        self.maintain_sas_nat(&routes);

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
        self.ensure_packet()?;
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

    fn sniff_core_ra(&mut self) -> Result<Sniff, String> {
        let ifindex = interface_index(CUSTOMER).ok_or("eth0 has no interface index")?;
        let sniff = open_packet(ifindex, true)?;
        self.packet = Some(sniff);
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
        let steady = open_packet(ifindex, false);
        self.packet = None;
        self.packet = Some(steady?);
        Ok(found)
    }

    fn ensure_packet(&mut self) -> Result<(), String> {
        if self.packet.is_some() {
            return Ok(());
        }
        let ifindex = interface_index(CUSTOMER).ok_or("eth0 has no interface index")?;
        self.packet = Some(open_packet(ifindex, false)?);
        Ok(())
    }

    fn drain(&mut self) {
        let block = self.serving_block();
        for event in self.collect() {
            if event.outgoing {
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
                match self.ipv4_watch.reply(self.now, packet, mac) {
                    Some(Armed::First) => {
                        self.note("IPv4 router answered local ARP; automatic recovery is armed")
                    }
                    // The same router after a cable or LTE outage: routine,
                    // so the RAM log only.
                    Some(Armed::Again) => log_ram(
                        "IPv4 router answered local ARP again; automatic recovery is armed",
                    ),
                    None => {}
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
            let source_mac = (!outgoing).then_some(mac).flatten();
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
            events.push(Event {
                kind,
                outgoing,
                source_mac,
            });
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
        self.delegated_at = self.now;
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
        let read = || {
            let snapshot = fs::read("/tmp/nvram.cfg").ok()?;
            let ports = fs::read_dir("/sys/class/net/br0/brif").ok()?
                .map(|entry| entry.ok()?.file_name().into_string().ok())
                .collect::<Option<Vec<_>>>()?;
            ipv4::data_assignment(&snapshot, &ports, &self.bearer)
        };
        let addr = read();
        self.assigned_at = Some((self.now, self.bearer.clone(), addr));
        addr
    }

    fn maintain_ipv4(&mut self, routes: &str) {
        // Reap a daemon that exited on its own before considering a restart.
        if let Some(child) = &mut self.dhcp_child {
            if !matches!(child.try_wait(), Ok(None)) {
                self.dhcp_child = None;
            }
        }
        if self.now.saturating_sub(self.last_flood) >= FLOOD_INTERVAL {
            let first = self.last_flood == 0;
            let mut failed = None;
            for line in ipv4::flood_commands(&self.bearer) {
                if let Err(err) = ebtables(&line) {
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
                let running = !customer_dhcp_pids(&command_stdout("ps", &[])).is_empty();
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

    fn maintain_ipv4_link(&mut self, routes: &str) {
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
            let local_address = bridge_probe_address(bearer)?;
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
        let snat = sas_nat::needed(
            &command_stdout("nvram_get", &["0", "lan_management_ipaddr"]),
            &command_stdout("nvram_get", &["0", "pdn_data_ipaddr"]),
            routes,
        );
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
        }
    }

    /// Drop customer IPv6 to and from LTE while the unit holds no SAS grant.
    /// The vendor stops only IPv4 then, and bridged IPv6 never reaches
    /// ip6tables. Reads the grant every second; while the gate is closed it
    /// also puts back rules a vendor firewall restart flushed. See
    /// `titan_pd_model::cbrs_gate`.
    fn maintain_cbrs_gate(&mut self) {
        if !self.cbrs_gate.due(self.now) {
            return;
        }
        let cache = fs::read(nvram_cache()).ok();
        let gate = cbrs_gate::decide(cache.as_deref());
        let (step, line) = self.cbrs_gate.observe(self.now, &gate);
        let changed = line.is_some();
        if let Some(line) = line {
            self.note(&line);
        }
        let failed = match step {
            GateStep::Hold => return,
            GateStep::Close => {
                let (added, failed) = cbrs_gate::close(&mut gate_command);
                if added > 0 && !changed {
                    self.note(&format!(
                        "CBRS gate rules put back: a vendor firewall restart removed {added} of {}",
                        cbrs_gate::RULES.len()
                    ));
                }
                failed
            }
            GateStep::Open => {
                let (cleanup, failed) = cbrs_gate::open(&mut gate_command);
                self.cbrs_gate.cleaned(self.now, cleanup);
                failed
            }
        };
        for err in failed {
            self.note(&format!("CBRS gate: {err}"));
        }
    }

    /// Which bearer carries the customer, and whether it is bridged to the
    /// LAN port. The bridge answers both without a fork. Only when it has no
    /// LTE port is the vendor asked, and then at most every `MODE_EVERY` s.
    fn refresh_mode(&mut self) {
        let ports: Vec<String> = fs::read_dir("/sys/class/net/br0/brif")
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        if let Some(port) = extdev::bridged_bearer(ports.iter().map(String::as_str)) {
            self.bearer = port;
            self.passthrough = true;
            self.bridged = true;
            if self.bridged_since.is_none() {
                self.bridged_since = Some(self.now);
                // The vendor adds the SAS SNAT rule during this setup and its
                // firewall restarts can drop it again. Check it every second.
                self.sas_watch.burst(self.now);
            }
            self.mode_checked = None;
            return;
        }
        self.bridged = false;
        self.bridged_since = None;
        if self
            .mode_checked
            .is_some_and(|last| self.now.saturating_sub(last) < MODE_EVERY)
        {
            return;
        }
        self.mode_checked = Some(self.now);
        // A failed or empty read keeps the last mode. Taking it for NAT stopped
        // the responder and removed the port filter, and the SQM under it.
        if let Some(mode) = vendor_passthrough(&command_stdout("nvram_get", &["0", "router_disable"])) {
            self.passthrough = mode;
        }
        let named = command_stdout("nvram_get", &["0", "pdn_data_ifname"]);
        let named = named.rsplit(':').next().unwrap_or("").trim();
        if extdev::is_lte_bearer(named) {
            self.bearer = named.to_owned();
        }
    }

    /// Follow the kernel log for the vendor kernel's external device, and in
    /// passthrough undo it being left on a management bearer. See
    /// `titan_pd_model::extdev`.
    fn maintain_external_dev(&mut self) {
        let (lines, drained) = match self.kernel_log.as_mut() {
            Some(log) => log.lines(),
            None => return,
        };
        // Lines before the first full read are the boot backlog.
        let live = self.kmsg_drained;
        for line in lines {
            if live && tk_flags::modem_loaded(&line) {
                self.modem_restart_seen = true;
            }
            if let Some(event) = extdev::parse(&line) {
                self.ext_watch.note(event);
            }
            match sas_nat::pdn_up(&line) {
                Some(dev) if dev == mgmt::MGMT_DEV => {
                    self.sas_watch.burst(self.now);
                    // Bring management IPv6 up on this tick, not up to 10 s later.
                    self.last_mgmt = 0;
                }
                Some(_) => self.sas_watch.burst(self.now),
                None if sas_nat::firewall_restart(&line) => self.sas_watch.burst(self.now),
                None => {}
            }
            if let Some(efc) = ethernet::efc(&line) {
                self.flow_report(efc);
            }
        }
        self.kmsg_drained |= drained;
        // `bridged` is how the keeper knows the vendor's bearer setup is over.
        let ready = self.passthrough && self.bridged && drained;
        let settled = self
            .bridged_since
            .is_some_and(|since| self.now.saturating_sub(since) >= extdev::SETTLE);
        let customer = self.bearer.clone();
        if let ExtAction::Repair(dev) = self.ext_watch.decide(self.now, ready, settled, &customer) {
            self.note(&format!(
                "external device guard: the vendor kernel left {dev} as its external device in IP passthrough; clearing it and restoring the bearer's own MAC"
            ));
            self.repair_external_dev(&dev);
            // Close the management bearer to advertisements now, so a second
            // one cannot set the external device again before the next check.
            self.last_mgmt = 0;
        }
    }

    /// Clear 802.3x hardware flow control on eth0 when the keeper starts and
    /// each time eth0 gets its carrier back. See `titan_pd_model::ethernet`.
    fn maintain_flow_control(&mut self) {
        if self.flow_checked == Some(self.now) {
            return;
        }
        // Wait for the kernel log backlog, so an old report is not taken for
        // the answer to this command. Without a kernel log, go ahead.
        if self.kernel_log.is_some() && !self.kmsg_drained {
            return;
        }
        self.flow_checked = Some(self.now);
        if !self.flow_watch.tick(carrier_up(CUSTOMER)) {
            return;
        }
        if ethernet::stock_requested(&read_file(&state_dir().join("ethernet.conf").to_string_lossy())) {
            if !self.flow_stock_logged {
                self.note("ethernet.conf asks for flow_control=stock; leaving the vendor's 802.3x setting on eth0");
                self.flow_stock_logged = true;
            }
            return;
        }
        match run_status(ethernet::PROGRAM, &ethernet::DISABLE) {
            Ok(()) => self.flow_pending = self.kernel_log.is_some(),
            Err(err) => {
                if !self.flow_failed_logged {
                    self.note(&format!("could not turn off 802.3x PAUSE on eth0; trying again when eth0 next comes up: {err}"));
                    self.flow_failed_logged = true;
                }
            }
        }
    }

    /// The kernel's flow control report. One line per outcome per run, since
    /// keeper.log is on flash.
    fn flow_report(&mut self, efc: bool) {
        if !self.flow_pending {
            return;
        }
        self.flow_pending = false;
        if !efc && !self.flow_logged {
            self.note("eth0 no longer sends 802.3x PAUSE frames to the router (kern eth -fc; the kernel reports efc=0). The keeper does this again each time eth0 comes back up");
            self.flow_logged = true;
        } else if efc && !self.flow_failed_logged {
            self.note("kern eth -fc ran but the kernel still reports efc=1 on eth0; leaving it");
            self.flow_failed_logged = true;
        }
    }

    /// `kern netif extdev <dev> down`, then the bearer's own MAC. Both leave a
    /// healthy unit unchanged.
    fn repair_external_dev(&mut self, dev: &str) {
        let Some(mac) = interface_mac(dev) else {
            self.note(&format!(
                "external device guard: {dev} has no MAC to restore"
            ));
            return;
        };
        for (program, args) in extdev::repair_commands(dev, &ipv4::mac_text(mac)) {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            if let Err(err) = run_status(program, &args) {
                self.note(&format!("external device guard: {err}"));
            }
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
        let settings = deaf::parse_settings(&read_file(
            &state_dir().join("watchdog.conf").to_string_lossy(),
        ));
        self.deaf_secs = settings.deaf_secs;
        self.maintain_vendor_watchdog(&settings);
        if !settings.enabled {
            self.deaf_round(None);
            return;
        }
        let bearer_dns = if settings.targets.is_empty() {
            command_stdout("nvram_get", &["0", "wan_get_dns"])
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
        let cache = fs::read(nvram_cache()).unwrap_or_default();
        let value = deaf::nvram_field(&cache, "detection_enable");
        if !deaf::vendor_watchdog_must_stop(settings, value) {
            return;
        }
        let was = value.unwrap_or("").trim().to_owned();
        let done = crate::nvram_set("detection_enable", "0").is_ok();
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
        let attached = deaf::attached(&command_stdout(
            "nvram_get",
            &["0", "sqns_connection_mediaState"],
        ));
        let path = state_dir().join("watchdog-strikes.txt");
        let strikes = deaf::parse_strikes(&read_file(&path.to_string_lossy()));
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
        unsafe { libc::sync() };
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
        let children = spawn_pings(&tk_targets());
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
        let listed = tk_boot::add_quarantine(&read_file(&quarantine.to_string_lossy()), sha);
        let _ = write_atomic(&quarantine, listed.as_bytes());
        let _ = write_atomic(&strikes, tk_boot::format_strikes(tk_boot::STRIKE_LIMIT).as_bytes());
        let recorded = tk_boot::refused(
            tk_boot::parse_strikes(&read_file(&strikes.to_string_lossy())),
            &tk_boot::parse_quarantine(&read_file(&quarantine.to_string_lossy())),
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
        let text = read_file(&dir.join("config").to_string_lossy());
        self.note_tk_flags_refused(&text);
        let wanted = tk_flags::wanted(&text, &[]);
        if wanted.is_empty() {
            let _ = fs::write(
                tk_flags_status_path(),
                tk_flags::idle_status("no wm= lines in tk/config", self.now),
            );
        } else {
            self.note(&format!(
                "tk flags: modem firmware {short} confirmed; writing {} once the patch magic shows",
                tk_flags::list(&wanted)
            ));
        }
        let control = tk_flags::Control::new(wanted, self.now);
        if !control.wanted().is_empty() {
            let _ = fs::write(tk_flags_status_path(), control.status(self.now));
        }
        self.tk_flags = Some(control);
        self.tk_flags_config_at = Some(self.now);
    }

    fn note_tk_flags_refused(&mut self, config: &str) {
        let refused = tk_flags::parse_writes(config).refused;
        if refused == self.tk_flags_refused {
            return;
        }
        for line in &refused {
            self.note(&format!(
                "tk flags: ignored {line:?} in tk/config: only wm=0x84f93008:<0..0x200> and wm=0x847ed604:<bits 0x15> are allowed"
            ));
        }
        self.tk_flags_refused = refused;
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
        if let Some(text) = &config_text {
            self.note_tk_flags_refused(text);
        }
        let busy = self.tk_flags_job.is_some() || self.reboot_asked_at.is_some();
        let mut spawned = None;
        if let Some(control) = self.tk_flags.as_mut() {
            if restarted {
                lines.push(control.modem_restarted(self.now));
                changed = true;
            }
            if let Some(text) = &config_text {
                let wanted = tk_flags::wanted(text, control.wanted());
                if let Some(line) = control.set_wanted(wanted, self.now) {
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
                if control.wanted().is_empty() {
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
        let config = qctrl::parse_config(&read_file(&dir.join("config").to_string_lossy()));
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
            }
            QctrlLoaded::Ours => {}
        }
        let proc = qctrl::parse_proc(&read_file(&qctrl_io::proc_path()));
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
        }
        let proc = qctrl::parse_proc(&read_file(&qctrl_io::proc_path()));
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
        // An IPv4-only bearer: the modem turns IPv6 off here, and no address can be added.
        if read_file("/proc/sys/net/ipv6/conf/lte0pdn0/disable_ipv6").trim() == "1" {
            return;
        }
        let assigned = mgmt::assigned_iid(&kernel_messages());
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
            let _ = config::store_report(&crate::runtime().join("status.json"), &report);
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
        let Some((mac, _at)) = parse_delegation(&read_file(
            &state_dir().join("router.txt").to_string_lossy(),
        )) else {
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
fn bridge_probe_address(bearer: std::net::Ipv4Addr) -> Option<std::net::Ipv4Addr> {
    // getifaddrs dumps addresses over rtnetlink and includes labeled aliases.
    let mut head = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let mut entry = head;
    let mut result = None;
    while !entry.is_null() {
        let interface = unsafe { &*entry };
        entry = interface.ifa_next;
        if interface.ifa_addr.is_null()
            || interface.ifa_name.is_null()
            || unsafe { (*interface.ifa_addr).sa_family as i32 } != libc::AF_INET
        {
            continue;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(interface.ifa_name) }.to_bytes();
        if name.split(|&c| c == b':').next() != Some(BRIDGE.as_bytes()) {
            continue;
        }
        let addr = unsafe { &*interface.ifa_addr.cast::<libc::sockaddr_in>() };
        let ip = std::net::Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
        if !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback() && ip != bearer {
            result = Some(ip);
            break;
        }
    }
    unsafe { libc::freeifaddrs(head) };
    result
}

// The main table, without spawning ip on every tick.
fn main_routes() -> String {
    fs::read_to_string("/proc/net/route")
        .map(|text| ipv4_routes(&text))
        .unwrap_or_else(|_| command_stdout("ip", &["route"]))
}

// The model consumes the two forms printed by ip route. The proc file
// prints network-order addresses as native-endian hex integers.
fn ipv4_routes(text: &str) -> String {
    use std::{fmt::Write, net::Ipv4Addr};
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

struct Event {
    kind: Class,
    outgoing: bool,
    /// The Ethernet source of an inbound frame.
    source_mac: Option<[u8; 6]>,
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

fn open_packet(ifindex: i32, sniff: bool) -> Result<Packet, String> {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(format!(
            "customer port socket: {}",
            io::Error::last_os_error()
        ));
    }
    let socket = Packet { fd };
    setsockopt_int(fd, libc::SOL_SOCKET, SO_MARK, filter::MARK as i32)?;
    crate::capture::install(fd, sniff)?;
    if !sniff {
        // Kernels with PACKET_IGNORE_OUTGOING skip the tap before cloning.
        // Older kernels still apply the direction check in the socket filter.
        let _ = setsockopt_int(fd, libc::SOL_PACKET, 23, 1);
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
        return Err(format!("bind customer port: {err}"));
    }
    Ok(socket)
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
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
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

// ip's rtnetlink dump and /proc may enumerate multiple prefixes in different
// orders. Preserve the original choice during that uncommon attach transition.
fn live_prefix(dev: &str) -> Option<Block> {
    if let Ok(text) = fs::read_to_string("/proc/net/if_inet6") {
        let mut blocks = global_prefixes(&text, dev);
        let first = blocks.next()?;
        if blocks.all(|block| block == first) {
            return Some(first);
        }
    }
    command_stdout("ip", &["-6", "addr", "show", "dev", dev])
        .lines()
        .find_map(|line| {
            let address = line.trim().strip_prefix("inet6 ")?;
            if !address.contains("scope global") {
                return None;
            }
            let ip: Ipv6Addr = address
                .split_whitespace()
                .next()?
                .strip_suffix("/64")?
                .parse()
                .ok()?;
            Some(Block::containing_56(ip.octets()))
        })
}

fn global_prefixes<'a>(text: &'a str, dev: &'a str) -> impl Iterator<Item = Block> + 'a {
    text.lines().filter_map(move |line| {
        let mut parts = line.split_whitespace();
        let addr = parts.next()?;
        let prefix = parts.nth(1)?;
        let scope = parts.next()?;
        let name = parts.nth(1)?;
        if name == dev && scope == "00" && prefix == "40" {
            parse_hex_addr(addr).map(Block::containing_56)
        } else {
            None
        }
    })
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

/// Frames received on `dev` since boot. `None` when the counter is unreadable.
fn rx_packets(dev: &str) -> Option<u64> {
    read_file(&format!("/sys/class/net/{dev}/statistics/rx_packets"))
        .trim()
        .parse()
        .ok()
}

fn carrier_up(dev: &str) -> bool {
    read_file(&format!("/sys/class/net/{dev}/carrier")).trim() == "1"
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

/// The boot hook's files on the persistent volume, only while it is mounted.
fn tk_dir() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("TITAN_TK_DIR") {
        return Some(PathBuf::from(path));
    }
    config::persistent_volume_mounted().then(|| PathBuf::from("/mnt/titan-api/tk"))
}

/// The tk config's own targets, else the deaf watchdog's.
fn tk_targets() -> Vec<std::net::IpAddr> {
    let config = tk_dir()
        .map(|dir| read_file(&dir.join("config").to_string_lossy()))
        .unwrap_or_default();
    let own = tk_boot::parse_targets(&config);
    if !own.is_empty() {
        return own;
    }
    let settings = deaf::parse_settings(&read_file(
        &state_dir().join("watchdog.conf").to_string_lossy(),
    ));
    let bearer_dns = if settings.targets.is_empty() {
        command_stdout("nvram_get", &["0", "wan_get_dns"])
    } else {
        String::new()
    };
    deaf::targets(&settings, &bearer_dns)
}

/// The management bearer has an IPv4 or global IPv6 address.
fn mgmt_address_up() -> bool {
    carrier_up(mgmt::MGMT_DEV)
        && command_stdout("ip", &["addr", "show", "dev", mgmt::MGMT_DEV])
            .lines()
            .map(str::trim)
            .any(|line| line.starts_with("inet ") || (line.starts_with("inet6 ") && line.contains("scope global")))
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

/// One ebtables or ip6tables command for the CBRS gate: its output when it
/// exits 0.
fn gate_command(tool: GateTool, args: &[&str]) -> Result<String, String> {
    let program = match tool {
        GateTool::Ebtables => {
            std::env::var("TITAN_EBTABLES").unwrap_or_else(|_| "/usr/bin/ebtables".into())
        }
        GateTool::Ip6tables => {
            std::env::var("TITAN_IP6TABLES").unwrap_or_else(|_| "ip6tables".into())
        }
    };
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| err.to_string())?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let err = String::from_utf8_lossy(&output.stderr);
    let err = err.trim();
    Err(if err.is_empty() { output.status.to_string() } else { err.to_owned() })
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

// SYSLOG_ACTION_SIZE_BUFFER and READ_ALL leave the ring and other readers alone.
fn kernel_messages() -> String {
    let size = unsafe { libc::klogctl(10, std::ptr::null_mut(), 0) };
    if (1..=4 * 1024 * 1024).contains(&size) {
        let mut buffer = vec![0; size as usize];
        let n = unsafe { libc::klogctl(3, buffer.as_mut_ptr().cast(), size) };
        if n >= 0 {
            return String::from_utf8_lossy(&buffer[..n as usize]).into_owned();
        }
    }
    command_stdout("dmesg", &[])
}

/// The vendor's RAM configuration cache.
fn nvram_cache() -> PathBuf {
    std::env::var_os("TITAN_NVRAM_CACHE").map_or_else(|| PathBuf::from("/tmp/nvram.cfg"), PathBuf::from)
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

pub(super) fn monotonic() -> u64 {
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

/// Whether the customer bearer can carry delegated traffic: carrier, and
/// either its own global address or a place in the LAN bridge. The vendor
/// SDK removes a bridged bearer's own address after 18 h and it never comes
/// back in that session; up to v1.0.12 that turned IPv6 health off.
fn bearer_up(own_prefix: bool, bridged: bool, carrier: bool) -> bool {
    carrier && (own_prefix || bridged)
}

/// `nvram_get 0 router_disable`: `Some(true)` for passthrough, `Some(false)`
/// for NAT, `None` for a failed or empty read.
fn vendor_passthrough(output: &str) -> Option<bool> {
    if !output.contains(':') {
        return None;
    }
    match output.rsplit(':').next().unwrap_or("").trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

/// A neighbour probe for fe80::1 from a router other than the one we
/// delegated to: that router has no prefix (the stuck-prefix case), and the
/// earlier delegation must not keep the health check quiet for two hours.
fn probe_ends_delegation(probe: Option<[u8; 6]>, delegated: Option<[u8; 6]>) -> bool {
    matches!((probe, delegated), (Some(probe), Some(mac)) if probe != mac)
}

/// The DHCP discover the next plan may act on. During the cooldown it stays
/// in the slot: taking it then lost a new router's discover.
fn take_discover(slot: &mut Option<[u8; 6]>, cooldown_elapsed: bool) -> Option<[u8; 6]> {
    if cooldown_elapsed { slot.take() } else { None }
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
        let packet = crate::capture::tests::captured(&packet, libc::ETH_P_IPV6, true, true);
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
        // Bulk IPv6 stays in the kernel; the port's receive counter stands in.
        assert!(crate::capture::tests::captured(&traffic, libc::ETH_P_IPV6, false, false).is_empty());
        // ICMPv6 from the delegated prefix, a host behind the router answering
        // a ping, is still captured and still counts.
        let mut echo = vec![0u8; 48];
        echo[0] = 0x60;
        echo[6] = 58;
        echo[8..24].copy_from_slice(&block.delegated57().addr);
        echo[23] = 1;
        echo[40] = 129;
        let echo = crate::capture::tests::captured(&echo, libc::ETH_P_IPV6, false, false);
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

    #[test]
    fn the_bearer_line_and_a_dhcp_discover_parse() {
        let text = "fe800000000000000000000000000001 02 40 20 80 wan\n20010db800ffd30000000000000000d4 02 40 00 80 wan";
        assert_eq!(
            global_prefixes(text, "wan").next().unwrap().to_string(),
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
    fn an_unreadable_vendor_mode_keeps_the_last_one() {
        assert_eq!(vendor_passthrough("nvram_get success: 1\n"), Some(true));
        assert_eq!(vendor_passthrough("nvram_get success: 0\n"), Some(false));
        assert_eq!(vendor_passthrough("nvram_get success: \n"), None);
        assert_eq!(vendor_passthrough(""), None);
        assert_eq!(vendor_passthrough("nvram_get failed\n"), None);
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
    fn a_discover_seen_during_the_dhcp_cooldown_waits_for_it() {
        let mac = [0x02, 0, 0, 0, 0, 0x0b];
        let mut slot = Some(mac);
        assert_eq!(take_discover(&mut slot, false), None);
        assert_eq!(slot, Some(mac));
        assert_eq!(take_discover(&mut slot, true), Some(mac));
        assert_eq!(slot, None);
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
