//! The download clamp: the `titan_qctrl` kernel module (v0.2-o1b).
//!
//! Under a full download the tower queue fills and ping rises to about 300 ms.
//! The module sits on the bridge between the customer bearer and the
//! customer port and shrinks the TCP receive window the customer's devices
//! advertise, so the senders keep only a short queue at the tower. Bench
//! (2026-11-22): ping during a full download about 310 ms down to 50 ms, for
//! about 8 % less peak speed. See docs/download-clamp.md.
//!
//! The image has no room for it, so an operator stages the module per unit
//! in `/mnt/titan-api/qctrl/` with a `config`. The keeper:
//! - loads it only when `config` asks for a mode other than 0, once the
//!   customer port and the management bearer have been up for `SETTLE_SECS`;
//! - loads only bytes that match the digest built into the keeper
//!   (`device/qctrl/SHA256SUMS`), from a private copy in RAM;
//! - never loads it while any other `qctrl` module is loaded;
//! - writes the knobs, then the mode, to `/proc/titan_qctrl` and reads them back.
//!
//! The module starts in mode 0 (observe only). Mode 0 later turns it back to
//! pass-through without unloading it.

/// The first line of `/proc/titan_qctrl` for the allowed build.
pub const VERSION_LINE: &str = "titan_qctrl v0.2-o1b";
/// The module's name in `/proc/modules`.
pub const MODULE: &str = "titan_qctrl";
/// The file in the staging directory and in the manifest.
pub const FILE: &str = "titan_qctrl.ko";
/// Modes the keeper sets: 0 off, 2 receive-window clamp, 3 clamp plus ACK
/// thinning, 6 clamp plus downlink ECN. These are the bench-tested arms. Bit 8
/// (drop UDP) stays off.
pub const MODES: [u32; 4] = [0, 2, 3, 6];
/// Seconds the customer port and the management bearer stay up before a load.
pub const SETTLE_SECS: u64 = 30;
/// Seconds between config and `/proc` checks.
pub const CHECK_EVERY: u64 = 15;
/// The module's own limits.
pub const TROUGH_MAX: u32 = 40;
pub const TARGET_MIN: u32 = 4;
pub const TARGET_MAX: u32 = 80;

/// `/mnt/titan-api/qctrl/config`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub mode: u32,
    pub trough_ms: Option<u32>,
    pub target_ms: Option<u32>,
    /// Lines that were not used, as written.
    pub refused: Vec<String>,
}

fn plain(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > 5 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// `mode=N`, `trough_ms=N`, `target_ms=N`, plain decimal, `#` comments. The
/// last line for a key wins. A bad `mode` line leaves the clamp off; a bad
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
            _ => false,
        };
        if !ok {
            config.refused.push(raw.trim().to_owned());
        }
    }
    config
}

/// What `/proc/titan_qctrl` shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Proc {
    /// The first line names the allowed build.
    pub ours: bool,
    pub mode: Option<u32>,
    pub trough_ms: Option<u32>,
    pub target_ms: Option<u32>,
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
        "state={state}\ndetail={detail}\nmode={}\ntrough_ms={}\ntarget_ms={}\nupdated={now}\n",
        config.mode,
        knob(config.trough_ms),
        knob(config.target_ms)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // As printed by v0.2-o1b (first lines of qctrl_proc_show).
    const PROC: &str = "titan_qctrl v0.2-o1b (NF_BR_FORWARD prio=+100)\nmode=0x2 (ack_thin=0 rwnd_clamp=1 dl_ecn=0 udp_drop=0)\nparams: target_q_ms=40 hold_us=2500 max_ack_span=8192 phy_cap_kbps=0\n        qsrc=0 slack_ms=10 floor_pct=30 drain=1 probe=1 trough_ms=4 rtt_target_ms=15 ecn_ms=20 wfix_kb=0 rttlaw=0\nstate:  c_hat_kbps=0 rate100_kbps=0 free_kbps=0 dl_kbps=0 ul_kbps=0 udp_dl_kbps=0\n        ctl_active=0 w_kb=0 n_ctl=0 active_bulk=0 inflight_kb=0 release_ticks=0\n        dq_est_ms=0 q_src=0 q_owd_ms=-1 q_rtt_ms=-1 q_bias_ms=0 owd_flows=0 sat_ticks=0 trough100_ms=-1 busy_ticks=0\n";
    const MODULES: &str =
        "titan_qctrl 47104 0 - Live 0x7f0b4000\nsch_cake 31676 0 - Live 0x7f0a0000\n";

    #[test]
    fn the_config_turns_on_only_bench_tested_modes() {
        let config =
            parse_config("# download clamp\nmode=2\ntrough_ms = 8 # bursty uplink\ntarget_ms=40\n");
        assert_eq!(
            config,
            Config {
                mode: 2,
                trough_ms: Some(8),
                target_ms: Some(40),
                refused: vec![]
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
    fn knobs_stay_inside_the_module_limits() {
        let config =
            parse_config("mode=2\ntrough_ms=41\ntarget_ms=3\ntarget_ms=81\nqsrc=2\nnonsense\n");
        assert_eq!(config.mode, 2);
        assert_eq!(config.trough_ms, None);
        assert_eq!(config.target_ms, None);
        assert_eq!(
            config.refused,
            vec![
                "trough_ms=41",
                "target_ms=3",
                "target_ms=81",
                "qsrc=2",
                "nonsense"
            ]
        );
        let config = parse_config("trough_ms=0\ntarget_ms=4\ntarget_ms=80\n");
        assert_eq!((config.trough_ms, config.target_ms), (Some(0), Some(80)));
    }

    #[test]
    fn proc_writes_put_the_mode_last() {
        let config = parse_config("mode=2\ntrough_ms=8\ntarget_ms=40\n");
        assert_eq!(
            proc_writes(&config),
            vec!["trough_ms 8\n", "target_ms 40\n", "mode 2\n"]
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
                target_ms: Some(40)
            }
        );
        // `rtt_target_ms=15` and `trough100_ms=-1` are other values.
        assert!(matches(
            &parse_config("mode=2\ntrough_ms=4\ntarget_ms=40\n"),
            &proc
        ));
        assert!(matches(&parse_config("mode=2\n"), &proc));
        assert!(!matches(&parse_config("mode=2\ntrough_ms=8\n"), &proc));
        assert!(!matches(&parse_config("mode=3\n"), &proc));
        assert!(!matches(&parse_config("mode=2\ntarget_ms=15\n"), &proc));
        let y6 = PROC.replace("v0.2-o1b", "v0.1-y6");
        assert!(!parse_proc(&y6).ours);
        assert!(!matches(&parse_config("mode=2\n"), &parse_proc(&y6)));
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
            loaded(MODULES, &PROC.replace("v0.2-o1b", "v0.1-y6")),
            Loaded::Other("titan_qctrl (titan_qctrl v0.1-y6 (NF_BR_FORWARD prio=+100))".into())
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
            "mode 2 read back",
            &parse_config("mode=2\ntrough_ms=8\n"),
            77,
        );
        assert_eq!(
            text,
            "state=applied\ndetail=mode 2 read back\nmode=2\ntrough_ms=8\ntarget_ms=default\nupdated=77\n"
        );
    }
}
