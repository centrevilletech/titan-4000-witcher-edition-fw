//! The download clamp: the `titan_qctrl` kernel module (v0.3-q3).
//!
//! Under a full download the tower queue fills and ping rises to about 300 ms.
//! The module sits on the bridge between the customer bearer and the
//! customer port and shrinks the TCP receive window the customer's devices
//! advertise, so the senders keep only a short queue at the tower. Bench
//! (2026-11-22): ping during a full download about 310 ms down to 50 ms, for
//! about 8 % less peak speed. v0.3-q3 adds opt-in adaptive safe ACK thinning
//! (`ack_adapt`) and low-burst window control (`ctrl_v3`), both off by default
//! so the default code path matches v0.2-o1b. See docs/download-clamp.md.
//!
//! Since v1.0.17 the module is in the firmware image and on by default, in
//! `DEFAULT_MODE`. An operator's `/mnt/titan-api/qctrl/config` sets other
//! modes and knobs, and `clamp=off` in the latency switches turns it off
//! (`effective`). The keeper:
//! - loads it only when the effective mode is not 0, once the customer port
//!   and the customer bearer have been up for `SETTLE_SECS`, and tries a
//!   failed load again after a wait that doubles (`retry::MODULES`);
//! - loads only bytes that match the digest built into the keeper
//!   (`device/qctrl/SHA256SUMS`): a copy staged in `/mnt/titan-api/qctrl/`
//!   when there is one, else the image's, from a private copy in RAM;
//! - never loads it while any other `qctrl` module is loaded;
//! - writes the knobs, then the mode, to `/proc/titan_qctrl` and reads them back.
//!
//! The module starts in mode 0 (observe only). Mode 0 later turns it back to
//! pass-through without unloading it.
use crate::switches::Source;

/// The first line of `/proc/titan_qctrl` for the allowed build.
pub const VERSION_LINE: &str = "titan_qctrl v0.3-q3";
/// The module's name in `/proc/modules`.
pub const MODULE: &str = "titan_qctrl";
/// The file in the staging directory and in the manifest.
pub const FILE: &str = "titan_qctrl.ko";
/// Modes the keeper sets: 0 off, 2 receive-window clamp, 3 clamp plus ACK
/// thinning, 6 clamp plus downlink ECN. These are the bench-tested arms. Bit 8
/// (drop UDP) stays off.
pub const MODES: [u32; 4] = [0, 2, 3, 6];
/// The clamp mode of a unit with no `qctrl/config`, and the one line to
/// change it: 3 is the receive-window clamp plus ACK thinning (Josh, for
/// v1.0.17), 2 the clamp alone, 0 leaves the clamp off unless an operator
/// turns it on. It must be one of `MODES`.
pub const DEFAULT_MODE: u32 = 3;
/// Seconds the customer port and the customer bearer stay up before a load.
pub const SETTLE_SECS: u64 = 30;
/// Seconds between config and `/proc` checks.
pub const CHECK_EVERY: u64 = 15;
/// The module's own limits.
pub const TROUGH_MAX: u32 = 40;
pub const TARGET_MIN: u32 = 4;
pub const TARGET_MAX: u32 = 80;
pub const ACK_MS_MIN: u32 = 1;
pub const ACK_MS_MAX: u32 = 10;
pub const ACK_SEGS_MIN: u32 = 2;
pub const ACK_SEGS_MAX: u32 = 32;
pub const ACK_MIN_KBPS_MAX: u32 = 100_000;

/// `/mnt/titan-api/qctrl/config`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub mode: u32,
    pub trough_ms: Option<u32>,
    pub target_ms: Option<u32>,
    pub ack_adapt: Option<u32>,
    pub ctrl_v3: Option<u32>,
    pub ack_ms: Option<u32>,
    pub ack_segs: Option<u32>,
    pub ack_min_kbps: Option<u32>,
    /// Lines that were not used, as written.
    pub refused: Vec<String>,
}

fn plain(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > 6 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// `mode=N`, `trough_ms=N`, `target_ms=N`, `ack_adapt=0|1`, `ctrl_v3=0|1`,
/// `ack_ms=N`, `ack_segs=N`, `ack_min_kbps=N`, plain decimal, `#` comments.
/// The last line for a key wins. A bad `mode` line leaves the clamp off; a bad
/// knob line leaves the module default.
pub fn parse_config(text: &str) -> Config {
    let mut config = Config::default();
    for raw in text.lines() {
        let line: String = raw
            .split('#')
            .next()
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            config.refused.push(raw.trim().to_owned());
            continue;
        };
        let value = plain(value);
        let ok = match (key, value) {
            ("mode", Some(mode)) if MODES.contains(&mode) => {
                config.mode = mode;
                true
            }
            ("mode", _) => {
                config.mode = 0;
                false
            }
            ("trough_ms", Some(ms)) if ms <= TROUGH_MAX => {
                config.trough_ms = Some(ms);
                true
            }
            ("target_ms", Some(ms)) if (TARGET_MIN..=TARGET_MAX).contains(&ms) => {
                config.target_ms = Some(ms);
                true
            }
            ("ack_adapt", Some(v)) if v <= 1 => {
                config.ack_adapt = Some(v);
                true
            }
            ("ctrl_v3", Some(v)) if v <= 1 => {
                config.ctrl_v3 = Some(v);
                true
            }
            ("ack_ms", Some(ms)) if (ACK_MS_MIN..=ACK_MS_MAX).contains(&ms) => {
                config.ack_ms = Some(ms);
                true
            }
            ("ack_segs", Some(segs)) if (ACK_SEGS_MIN..=ACK_SEGS_MAX).contains(&segs) => {
                config.ack_segs = Some(segs);
                true
            }
            ("ack_min_kbps", Some(kbps)) if kbps <= ACK_MIN_KBPS_MAX => {
                config.ack_min_kbps = Some(kbps);
                true
            }
            _ => false,
        };
        if !ok {
            config.refused.push(raw.trim().to_owned());
        }
    }
    config
}

/// The settings the keeper keeps, and where they came from:
/// - `clamp=off` in the latency switches: mode 0;
/// - the operator's `qctrl/config` (`staged`) when there is one;
/// - else `DEFAULT_MODE` with the module's own knobs, unless CAKE shapes
///   traffic (`cake_shaping`): only a radio profile's `sqm` action installs
///   it, and the clamp has not been tested beside it, so the default stands
///   aside while it is there and comes back when it is gone.
pub fn effective(switch_on: bool, staged: Option<&str>, cake: bool) -> (Config, Source) {
    if !switch_on {
        return (Config::default(), Source::Off);
    }
    if let Some(text) = staged {
        return (parse_config(text), Source::Operator);
    }
    if cake {
        return (Config::default(), Source::Aside("CAKE shapes downloads (radio profile sqm)"));
    }
    (Config { mode: DEFAULT_MODE, ..Config::default() }, Source::Default)
}

/// A CAKE qdisc is installed, from `/proc/modules`. Every qdisc holds a
/// reference to its module from creation to destruction (Linux 3.10
/// `qdisc_lookup_ops` and `qdisc_destroy`), so `sch_cake`'s use count, the
/// third field, is the number of CAKE qdiscs. Reverting a radio profile's
/// `sqm` removes them but leaves the module loaded, at 0. A count that
/// cannot be read counts as in use.
pub fn cake_shaping(modules: &str) -> bool {
    modules.lines().any(|line| {
        let mut fields = line.split_whitespace();
        fields.next() == Some("sch_cake") && fields.nth(1) != Some("0")
    })
}

/// What `/proc/titan_qctrl` shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Proc {
    /// The first line names the allowed build.
    pub ours: bool,
    pub mode: Option<u32>,
    pub trough_ms: Option<u32>,
    pub target_ms: Option<u32>,
    pub ack_adapt: Option<u32>,
    pub ctrl_v3: Option<u32>,
    pub ack_ms: Option<u32>,
    pub ack_segs: Option<u32>,
    pub ack_min_kbps: Option<u32>,
}

pub fn parse_proc(text: &str) -> Proc {
    let mut proc = Proc {
        ours: text.lines().next().is_some_and(|line| {
            line.split_whitespace()
                .take(2)
                .collect::<Vec<_>>()
                .join(" ")
                == VERSION_LINE
        }),
        ..Proc::default()
    };
    for word in text.split_whitespace() {
        if let Some(hex) = word.strip_prefix("mode=0x") {
            proc.mode = proc.mode.or_else(|| u32::from_str_radix(hex, 16).ok());
        } else if let Some(ms) = word.strip_prefix("trough_ms=") {
            proc.trough_ms = proc.trough_ms.or_else(|| ms.parse().ok());
        } else if let Some(ms) = word.strip_prefix("target_q_ms=") {
            proc.target_ms = proc.target_ms.or_else(|| ms.parse().ok());
        } else if let Some(v) = word.strip_prefix("ack_adapt=") {
            proc.ack_adapt = proc.ack_adapt.or_else(|| v.parse().ok());
        } else if let Some(v) = word.strip_prefix("ctrl_v3=") {
            proc.ctrl_v3 = proc.ctrl_v3.or_else(|| v.parse().ok());
        } else if let Some(ms) = word.strip_prefix("ack_ms=") {
            proc.ack_ms = proc.ack_ms.or_else(|| ms.parse().ok());
        } else if let Some(segs) = word.strip_prefix("ack_segs=") {
            proc.ack_segs = proc.ack_segs.or_else(|| segs.parse().ok());
        } else if let Some(kbps) = word.strip_prefix("ack_min_kbps=") {
            proc.ack_min_kbps = proc.ack_min_kbps.or_else(|| kbps.parse().ok());
        }
    }
    proc
}

/// Lines for `/proc/titan_qctrl`, one write each: the knobs first, the mode
/// last, so the clamp starts with the operator's settings.
pub fn proc_writes(config: &Config) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(ms) = config.trough_ms {
        lines.push(format!("trough_ms {ms}\n"));
    }
    if let Some(ms) = config.target_ms {
        lines.push(format!("target_ms {ms}\n"));
    }
    if let Some(v) = config.ack_adapt {
        lines.push(format!("ack_adapt {v}\n"));
    }
    if let Some(v) = config.ctrl_v3 {
        lines.push(format!("ctrl_v3 {v}\n"));
    }
    if let Some(ms) = config.ack_ms {
        lines.push(format!("ack_ms {ms}\n"));
    }
    if let Some(segs) = config.ack_segs {
        lines.push(format!("ack_segs {segs}\n"));
    }
    if let Some(kbps) = config.ack_min_kbps {
        lines.push(format!("ack_min_kbps {kbps}\n"));
    }
    lines.push(format!("mode {}\n", config.mode));
    lines
}

/// `/proc` shows what the config asks for. A knob the config leaves out is
/// not checked.
pub fn matches(config: &Config, proc: &Proc) -> bool {
    proc.ours
        && proc.mode == Some(config.mode)
        && config.trough_ms.is_none_or(|ms| proc.trough_ms == Some(ms))
        && config.target_ms.is_none_or(|ms| proc.target_ms == Some(ms))
        && config.ack_adapt.is_none_or(|v| proc.ack_adapt == Some(v))
        && config.ctrl_v3.is_none_or(|v| proc.ctrl_v3 == Some(v))
        && config.ack_ms.is_none_or(|ms| proc.ack_ms == Some(ms))
        && config.ack_segs.is_none_or(|segs| proc.ack_segs == Some(segs))
        && config
            .ack_min_kbps
            .is_none_or(|kbps| proc.ack_min_kbps == Some(kbps))
}

/// Which clamp module is loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Loaded {
    None,
    /// `titan_qctrl` with the allowed version line.
    Ours,
    /// Any other module with `qctrl` in its name, or a `titan_qctrl` that
    /// shows another version. The keeper never loads beside it.
    Other(String),
}

/// From `/proc/modules` and `/proc/titan_qctrl` (empty when absent).
pub fn loaded(modules: &str, proc_text: &str) -> Loaded {
    let names: Vec<&str> = modules
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| name.contains("qctrl"))
        .collect();
    let ours = parse_proc(proc_text).ours;
    if let Some(other) = names.iter().find(|name| **name != MODULE) {
        return Loaded::Other((*other).to_owned());
    }
    match (names.is_empty(), proc_text.trim().is_empty()) {
        (true, true) => Loaded::None,
        (false, _) if ours => Loaded::Ours,
        (true, false) if ours => Loaded::Other("a /proc/titan_qctrl with no module".into()),
        _ => {
            let first = proc_text.lines().next().unwrap_or("").trim();
            let shown = if first.is_empty() {
                "no /proc/titan_qctrl".to_owned()
            } else {
                first.to_owned()
            };
            Loaded::Other(format!("{MODULE} ({shown})"))
        }
    }
}

/// The customer port and the management bearer have been up long enough.
/// `up_since` is the keeper's monotonic second both were first seen up.
pub fn settled(up_since: Option<u64>, now: u64) -> bool {
    up_since.is_some_and(|since| now.saturating_sub(since) >= SETTLE_SECS)
}

/// `/var/run/witcher-qctrl.status`.
pub fn status(state: &str, detail: &str, config: &Config, now: u64) -> String {
    let knob = |v: Option<u32>| v.map_or_else(|| "default".to_owned(), |v| v.to_string());
    format!(
        "state={state}\ndetail={detail}\nmode={}\ntrough_ms={}\ntarget_ms={}\nack_adapt={}\nctrl_v3={}\nupdated={now}\n",
        config.mode,
        knob(config.trough_ms),
        knob(config.target_ms),
        knob(config.ack_adapt),
        knob(config.ctrl_v3)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // As printed by v0.3-q3 (first lines of qctrl_proc_show).
    const PROC: &str = "titan_qctrl v0.3-q3 (NF_BR_FORWARD prio=+100)\nmode=0x2 (ack_thin=0 rwnd_clamp=1 dl_ecn=0 udp_drop=0)\nparams: target_q_ms=40 hold_us=2500 max_ack_span=8192 phy_cap_kbps=0\n        qsrc=0 slack_ms=10 floor_pct=30 drain=1 probe=1 trough_ms=4 rtt_target_ms=15 ecn_ms=20 wfix_kb=0 rttlaw=0\n        ack_adapt=0 ctrl_v3=0 ack_ms=6 ack_segs=18 ack_min_kbps=2000\nstate:  c_hat_kbps=0 rate100_kbps=0 free_kbps=0 dl_kbps=0 ul_kbps=0 udp_dl_kbps=0\n        ctl_active=0 w_kb=0 n_ctl=0 active_bulk=0 inflight_kb=0 release_ticks=0\n        dq_est_ms=0 q_src=0 q_owd_ms=-1 q_rtt_ms=-1 q_bias_ms=0 owd_flows=0 sat_ticks=0 trough100_ms=-1 busy_ticks=0\n";
    const MODULES: &str =
        "titan_qctrl 47104 0 - Live 0x7f0b4000\nsch_cake 31676 0 - Live 0x7f0a0000\n";

    #[test]
    fn the_config_turns_on_only_bench_tested_modes() {
        let config = parse_config(
            "# download clamp\nmode=2\ntrough_ms = 8 # bursty uplink\ntarget_ms=40\n",
        );
        assert_eq!(
            config,
            Config {
                mode: 2,
                trough_ms: Some(8),
                target_ms: Some(40),
                ..Config::default()
            }
        );
        assert_eq!(parse_config("").mode, 0);
        for mode in [
            "mode=8", "mode=10", "mode=15", "mode=16", "mode=0x2", "mode=-2", "mode=two", "mode=",
        ] {
            let config = parse_config(&format!("mode=2\n{mode}\n"));
            assert_eq!(config.mode, 0, "{mode}");
            assert_eq!(config.refused, vec![mode.to_owned()]);
        }
        for mode in MODES {
            assert_eq!(parse_config(&format!("mode={mode}\n")).mode, mode);
        }
    }

    #[test]
    fn on_by_default_unless_switched_off_configured_or_beside_cake() {
        assert!(MODES.contains(&DEFAULT_MODE), "the default must be a bench-tested mode");
        let (config, source) = effective(true, None, false);
        assert_eq!((config.mode, source), (DEFAULT_MODE, Source::Default));
        assert_eq!(config, Config { mode: DEFAULT_MODE, ..Config::default() }, "the module's own knobs");
        // The switch turns it off, whatever the operator's file says.
        assert_eq!(effective(false, Some("mode=2\n"), false), (Config::default(), Source::Off));
        assert_eq!(effective(false, None, false).0.mode, 0);
        // An operator's file wins over the default, mode=0 included, and CAKE does not matter then.
        let (config, source) = effective(true, Some("mode=2\ntrough_ms=8\n"), true);
        assert_eq!((config.mode, config.trough_ms, source), (2, Some(8), Source::Operator));
        assert_eq!(effective(true, Some("mode=0\n"), false).0.mode, 0);
        assert_eq!(effective(true, Some(""), false).0.mode, 0, "an empty file is the operator's: off");
        // The default stands aside while a radio profile's CAKE shapes downloads.
        let (config, source) = effective(true, None, true);
        assert_eq!(config.mode, 0);
        assert!(matches!(source, Source::Aside(_)));
    }

    #[test]
    fn the_default_stands_aside_only_while_a_cake_qdisc_is_installed() {
        let with = |cake: &str| format!("titan_qctrl 47104 0 - Live 0x7f0b4000\n{cake}");
        // A radio profile's sqm installs CAKE on lte0pdn2 and eth0: two qdiscs.
        assert!(cake_shaping(&with("sch_cake 31676 2 - Live 0x7f0a0000\n")));
        assert!(cake_shaping(&with("sch_cake 31676 1 - Live 0x7f0a0000\n")));
        // Reverted or removed: the qdiscs are gone and the module stays loaded
        // at 0. v1.0.17 read this as CAKE and kept the clamp at mode 0 until
        // the next reboot, so the unit had neither.
        let reverted = with("sch_cake 31676 0 - Live 0x7f0a0000\n");
        assert!(!cake_shaping(&reverted));
        assert_eq!(effective(true, None, cake_shaping(&reverted)).0.mode, DEFAULT_MODE);
        assert!(!cake_shaping(MODULES), "MODULES has sch_cake loaded with no qdisc");
        // Never loaded, or another module whose name only starts the same.
        assert!(!cake_shaping(&with("")));
        assert!(!cake_shaping(&with("sch_cake_old 1 3 - Live 0x0\n")));
        // A count that cannot be read keeps the clamp aside, as before.
        assert!(cake_shaping(&with("sch_cake 31676 - - Live 0x7f0a0000\n")));
        assert!(cake_shaping(&with("sch_cake 31676\n")));
    }

    #[test]
    fn knobs_stay_inside_the_module_limits() {
        let config = parse_config(
            "mode=2\ntrough_ms=41\ntarget_ms=3\ntarget_ms=81\nack_adapt=2\nctrl_v3=2\nack_ms=0\nack_ms=11\nack_segs=1\nack_segs=33\nack_min_kbps=100001\nqsrc=2\nnonsense\n",
        );
        assert_eq!(config.mode, 2);
        assert_eq!(config.trough_ms, None);
        assert_eq!(config.target_ms, None);
        assert_eq!(config.ack_adapt, None);
        assert_eq!(config.ctrl_v3, None);
        assert_eq!(config.ack_ms, None);
        assert_eq!(config.ack_segs, None);
        assert_eq!(config.ack_min_kbps, None);
        assert_eq!(
            config.refused,
            vec![
                "trough_ms=41",
                "target_ms=3",
                "target_ms=81",
                "ack_adapt=2",
                "ctrl_v3=2",
                "ack_ms=0",
                "ack_ms=11",
                "ack_segs=1",
                "ack_segs=33",
                "ack_min_kbps=100001",
                "qsrc=2",
                "nonsense"
            ]
        );
        let config = parse_config(
            "trough_ms=0\ntarget_ms=4\ntarget_ms=80\nack_adapt=1\nctrl_v3=1\nack_ms=1\nack_ms=10\nack_segs=2\nack_segs=32\nack_min_kbps=100000\n",
        );
        assert_eq!(
            (
                config.trough_ms,
                config.target_ms,
                config.ack_adapt,
                config.ctrl_v3,
                config.ack_ms,
                config.ack_segs,
                config.ack_min_kbps
            ),
            (
                Some(0),
                Some(80),
                Some(1),
                Some(1),
                Some(10),
                Some(32),
                Some(100_000)
            )
        );
    }

    #[test]
    fn proc_writes_put_the_mode_last() {
        let config = parse_config(
            "mode=3\ntrough_ms=8\ntarget_ms=40\nack_adapt=1\nctrl_v3=1\nack_ms=5\nack_segs=14\nack_min_kbps=4000\n",
        );
        assert_eq!(
            proc_writes(&config),
            vec![
                "trough_ms 8\n",
                "target_ms 40\n",
                "ack_adapt 1\n",
                "ctrl_v3 1\n",
                "ack_ms 5\n",
                "ack_segs 14\n",
                "ack_min_kbps 4000\n",
                "mode 3\n"
            ]
        );
        assert_eq!(proc_writes(&Config::default()), vec!["mode 0\n"]);
    }

    #[test]
    fn proc_reads_back_mode_and_knobs() {
        let proc = parse_proc(PROC);
        assert_eq!(
            proc,
            Proc {
                ours: true,
                mode: Some(2),
                trough_ms: Some(4),
                target_ms: Some(40),
                ack_adapt: Some(0),
                ctrl_v3: Some(0),
                ack_ms: Some(6),
                ack_segs: Some(18),
                ack_min_kbps: Some(2000),
            }
        );
        // `rtt_target_ms=15` and `trough100_ms=-1` are other values.
        assert!(matches(
            &parse_config("mode=2\ntrough_ms=4\ntarget_ms=40\nack_adapt=0\nctrl_v3=0\n"),
            &proc
        ));
        assert!(matches(&parse_config("mode=2\n"), &proc));
        assert!(!matches(&parse_config("mode=2\ntrough_ms=8\n"), &proc));
        assert!(!matches(&parse_config("mode=3\n"), &proc));
        assert!(!matches(&parse_config("mode=2\ntarget_ms=15\n"), &proc));
        assert!(!matches(&parse_config("mode=2\nack_adapt=1\n"), &proc));
        assert!(!matches(&parse_config("mode=2\nctrl_v3=1\n"), &proc));
        let o1b = PROC.replace("v0.3-q3", "v0.2-o1b");
        assert!(!parse_proc(&o1b).ours);
        assert!(!matches(&parse_config("mode=2\n"), &parse_proc(&o1b)));
        assert!(!parse_proc("").ours);
        assert_eq!(parse_proc("mode=0xc (x)\n").mode, Some(12));
    }

    #[test]
    fn never_beside_another_clamp_module() {
        assert_eq!(
            loaded("sch_cake 31676 0 - Live 0x7f0a0000\n", ""),
            Loaded::None
        );
        assert_eq!(loaded("", ""), Loaded::None);
        assert_eq!(loaded(MODULES, PROC), Loaded::Ours);
        assert_eq!(
            loaded(MODULES, &PROC.replace("v0.3-q3", "v0.2-o1b")),
            Loaded::Other("titan_qctrl (titan_qctrl v0.2-o1b (NF_BR_FORWARD prio=+100))".into())
        );
        assert_eq!(
            loaded(MODULES, ""),
            Loaded::Other("titan_qctrl (no /proc/titan_qctrl)".into())
        );
        assert_eq!(
            loaded("titan_qctrl_y6 47104 0 - Live 0x7f0b4000\n", ""),
            Loaded::Other("titan_qctrl_y6".into())
        );
        assert_eq!(
            loaded(&format!("{MODULES}qctrl_test 100 0 - Live 0x0\n"), PROC),
            Loaded::Other("qctrl_test".into())
        );
        assert!(matches!(loaded("", PROC), Loaded::Other(_)));
    }

    #[test]
    fn loading_waits_for_a_settled_link() {
        assert!(!settled(None, 1000));
        assert!(!settled(Some(100), 100 + SETTLE_SECS - 1));
        assert!(settled(Some(100), 100 + SETTLE_SECS));
        assert!(!settled(Some(200), 100));
    }

    #[test]
    fn the_status_names_mode_and_knobs() {
        let text = status(
            "applied",
            "mode 3 read back",
            &parse_config("mode=3\ntrough_ms=8\nack_adapt=1\nctrl_v3=1\n"),
            77,
        );
        assert_eq!(
            text,
            "state=applied\ndetail=mode 3 read back\nmode=3\ntrough_ms=8\ntarget_ms=default\nack_adapt=1\nctrl_v3=1\nupdated=77\n"
        );
    }
}
