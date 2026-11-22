//! Confirm a boot that loaded a staged modem firmware image (tk), or put stock
//! firmware back.
//!
//! `witcher-tk-stage pre` (in `overlay/etc/init.d`) loads an operator-staged
//! image at boot only when it passes every check. It counts a strike on the
//! persistent volume before the load and writes what it did to
//! `/var/run/witcher-tk.status`. This module decides, from that status and
//! from pings through the core, whether the boot is confirmed or must go back
//! to stock firmware. See docs/tk-boot-loader.md.
//!
//! Guards:
//! - It arms only on a boot the hook says it staged. On a stock boot, or with
//!   no status at all, the keeper never reboots for this reason.
//! - An address on the management bearer plus one answer through the core
//!   confirms the boot. The keeper then clears the strike count.
//! - No confirm within `CONFIRM_SECS` of the load, after at least `MIN_ROUNDS`
//!   probe rounds by this keeper process: quarantine the image's hash, set the
//!   strike count to the limit, and reboot once onto stock firmware. The keeper
//!   reboots only after reading back a record that makes the hook refuse the
//!   image, so the same failure cannot repeat.
//! - A keeper that restarts after a confirm or rollback does not judge the
//!   boot again (`/var/run/witcher-tk.result`).
//! - Even with no keeper at all, the strike count stops the hook after
//!   `STRIKE_LIMIT` staged boots without a confirm.
use std::net::IpAddr;

/// Seconds after the load for the management bearer to answer.
pub const CONFIRM_SECS: u64 = 300;
/// Staged boots without a confirm before the hook keeps stock firmware.
pub const STRIKE_LIMIT: u32 = 2;
/// Seconds between probe rounds while a confirm is pending.
pub const PROBE_EVERY: u64 = 15;
/// A round with no answer after this long counts as silence.
pub const PROBE_TIMEOUT: u64 = 6;
/// Probe rounds this keeper process must run before it may roll back, so a
/// keeper that restarts late still looks before it acts.
pub const MIN_ROUNDS: u32 = 2;
const MAX_TARGETS: usize = 4;

/// Where the N4 modem image keeps its patch magic, read with `vm 0x847ed600 4`.
pub const MAGIC_ADDR: u32 = 0x847e_d600;
/// `4e 34 56 32`, "N4V2".
pub const MAGIC: [u8; 4] = *b"N4V2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The modem printed `read from fs`: it loaded the staged image.
    Fs,
    /// The modem printed `read from nand`.
    Nand,
    Unknown,
}

/// `/var/run/witcher-tk.status`, written by the boot hook.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BootStatus {
    /// The image's SHA-256, when the hook staged one.
    pub staged: Option<String>,
    /// Why the hook kept stock firmware.
    pub reason: String,
    pub strikes: Option<u32>,
    /// `/proc/uptime` seconds when `modprobe modem` returned.
    pub loaded_at: Option<u64>,
    pub source: Option<Source>,
    /// The hook took the image back out of `/lib/firmware`.
    pub firmware_clean: Option<bool>,
}

pub fn valid_sha(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn parse_status(text: &str) -> BootStatus {
    let mut status = BootStatus::default();
    let mut state = String::new();
    let mut sha = String::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "state" => state = value.to_owned(),
            "sha256" => sha = value.to_ascii_lowercase(),
            "reason" => status.reason = value.to_owned(),
            "strikes" => status.strikes = value.parse().ok(),
            "loaded_at" => status.loaded_at = value.parse().ok(),
            "source" => {
                status.source = Some(match value {
                    "fs" => Source::Fs,
                    "nand" => Source::Nand,
                    _ => Source::Unknown,
                })
            }
            "firmware" => {
                status.firmware_clean = match value {
                    "clean" => Some(true),
                    "dirty" => Some(false),
                    _ => None,
                }
            }
            _ => {}
        }
    }
    if state == "staged" && valid_sha(&sha) {
        status.staged = Some(sha);
    }
    status
}

/// One keeper log line for the boot, or `None` when the hook had nothing to do.
pub fn describe(status: &BootStatus) -> Option<String> {
    if let Some(sha) = &status.staged {
        let source = match status.source {
            Some(Source::Fs) => "the modem read it from /lib/firmware",
            Some(Source::Nand) => "but the modem read NAND",
            _ => "the modem did not say where it read from",
        };
        let firmware = match status.firmware_clean {
            Some(true) => "",
            Some(false) => "; it could NOT be removed from /lib/firmware",
            None => "; the hook did not report removing it from /lib/firmware",
        };
        let strikes = status
            .strikes
            .map_or_else(|| "?".to_owned(), |n| n.to_string());
        return Some(format!(
            "tk boot: loaded staged modem firmware {} (strike {strikes} of {STRIKE_LIMIT}); {source}{firmware}",
            short(sha)
        ));
    }
    match status.reason.as_str() {
        "" | "off" | "no-volume" => None,
        reason => Some(format!("tk boot: stock modem firmware ({reason})")),
    }
}

pub fn short(sha: &str) -> &str {
    sha.get(..12).unwrap_or(sha)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Hold,
    Confirmed,
    Rollback,
}

/// A pending boot confirm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Confirm {
    pub sha: String,
    /// Keeper monotonic seconds.
    pub deadline: u64,
    rounds: u32,
}

impl Confirm {
    /// `now` is the keeper's monotonic clock in seconds since boot, the clock
    /// `loaded_at` comes from. `decided` is true when a keeper process already
    /// confirmed or rolled back this boot.
    pub fn arm(status: &BootStatus, now: u64, decided: bool) -> Option<Self> {
        if decided {
            return None;
        }
        let sha = status.staged.clone()?;
        let base = status.loaded_at.filter(|at| *at <= now).unwrap_or(now);
        Some(Self {
            sha,
            deadline: base.saturating_add(CONFIRM_SECS),
            rounds: 0,
        })
    }

    /// One finished probe round. `mgmt_up` is an address on the management
    /// bearer. `heard` is `None` when no probe could run (no targets yet,
    /// which is what a modem that never attaches looks like).
    pub fn observe(&mut self, now: u64, mgmt_up: bool, heard: Option<bool>) -> Action {
        if mgmt_up && heard == Some(true) {
            return Action::Confirmed;
        }
        self.rounds = self.rounds.saturating_add(1);
        if now >= self.deadline && self.rounds >= MIN_ROUNDS {
            Action::Rollback
        } else {
            Action::Hold
        }
    }
}

/// The value after `key=` on the last line that starts with it, with comments
/// and spaces removed. The boot hook reads the files the same way.
fn value(text: &str, key: &str) -> Option<String> {
    let mut found = None;
    for line in text.lines() {
        if let Some(rest) = line
            .strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
        {
            found = Some(rest);
        }
    }
    let raw = found?;
    let raw = raw.split('#').next().unwrap_or("");
    Some(raw.chars().filter(|c| !c.is_whitespace()).collect())
}

/// `strikes=N`. `None` for a missing or unreadable count.
pub fn parse_strikes(text: &str) -> Option<u32> {
    let value = value(text, "strikes")?;
    if value.is_empty() || value.len() > 3 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

pub fn format_strikes(strikes: u32) -> String {
    format!("strikes={strikes}\n")
}

/// Hashes in the quarantine file: one per line, comments allowed.
pub fn parse_quarantine(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| {
            line.split('#')
                .next()
                .unwrap_or("")
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .to_ascii_lowercase()
        })
        .filter(|line| valid_sha(line))
        .collect()
}

/// The quarantine file with `sha` added. Existing lines stay as they are.
pub fn add_quarantine(existing: &str, sha: &str) -> String {
    let sha = sha.to_ascii_lowercase();
    if parse_quarantine(existing).contains(&sha) {
        return existing.to_owned();
    }
    let mut text = existing.to_owned();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&sha);
    text.push('\n');
    text
}

/// The hook will keep stock firmware next boot instead of staging `sha`.
pub fn refused(strikes: Option<u32>, quarantine: &[String], sha: &str) -> bool {
    strikes.is_some_and(|n| n >= STRIKE_LIMIT)
        || quarantine.iter().any(|q| q.eq_ignore_ascii_case(sha))
}

/// `target=<address>` lines in the tk config: where the boot confirm pings.
/// Without them the keeper uses the deaf watchdog's targets.
pub fn parse_targets(config: &str) -> Vec<IpAddr> {
    let mut found = Vec::new();
    for line in config.lines() {
        let Some(rest) = line.strip_prefix("target=") else {
            continue;
        };
        let text = rest.split('#').next().unwrap_or("").trim();
        let Ok(addr) = text.parse::<IpAddr>() else {
            continue;
        };
        if !addr.is_unspecified()
            && !addr.is_loopback()
            && !found.contains(&addr)
            && found.len() < MAX_TARGETS
        {
            found.push(addr);
        }
    }
    found
}

/// What `witcher-tk-stage pre` decides for an image that passed its file
/// checks: the reference for its strike and quarantine rules.
/// `strikes` is `Some(0)` when there is no strike file and `None` when the
/// file cannot be read. `scripts/test-tk-stage.py` runs the hook itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boot {
    Stage { strike: u32 },
    Stock(&'static str),
}

pub fn hook_decision(
    enabled: bool,
    strikes: Option<u32>,
    allowed: bool,
    quarantined: bool,
) -> Boot {
    if !enabled {
        return Boot::Stock("off");
    }
    let Some(strikes) = strikes else {
        return Boot::Stock("strikes-unreadable");
    };
    if strikes >= STRIKE_LIMIT {
        return Boot::Stock("strikes");
    }
    if !allowed {
        return Boot::Stock("not-allowed");
    }
    if quarantined {
        return Boot::Stock("quarantined");
    }
    Boot::Stage {
        strike: strikes + 1,
    }
}

fn strip_escapes(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// The bytes the modem console's `vm <addr> <len>` printed for `addr`
/// (`0x847ED600 | 4e 34 56 32 ...`).
pub fn vm_bytes(output: &str, addr: u32) -> Option<Vec<u8>> {
    let want = format!("0x{addr:08x}");
    for line in output.lines() {
        let line = strip_escapes(line);
        let Some((head, rest)) = line.split_once('|') else {
            continue;
        };
        if !head.trim().eq_ignore_ascii_case(&want) {
            continue;
        }
        let bytes: Vec<u8> = rest
            .split_whitespace()
            .map_while(|word| {
                if word.len() == 2 {
                    u8::from_str_radix(word, 16).ok()
                } else {
                    None
                }
            })
            .collect();
        return Some(bytes);
    }
    None
}

/// A modem feature flag may be written (`wm`) only when `vm 0x847ed600 4`
/// reads back the patch magic. Stock firmware keeps other data there, so a
/// write would corrupt it. Nothing in this firmware writes flags yet; any
/// later feature control must pass this first.
pub fn flag_writes_allowed(vm_output: &str) -> bool {
    vm_bytes(vm_output, MAGIC_ADDR).is_some_and(|bytes| bytes.len() >= 4 && bytes[..4] == MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "8c0a073fe1a07c4d3a0e1a79be6a58cd5898bde761ba54eeb800e00465d4903e";
    const B: &str = "555362d9c050862ac462017df54cbcedc00b0963454b332438d70bbef70f82ea";

    fn staged(loaded_at: u64) -> BootStatus {
        parse_status(&format!(
            "state=staged\nsha256={}\nstrikes=1\nloaded_at={loaded_at}\nsource=fs\nfirmware=clean\n",
            A.to_uppercase()
        ))
    }

    #[test]
    fn the_status_names_the_staged_image() {
        let status = staged(17);
        assert_eq!(status.staged.as_deref(), Some(A));
        assert_eq!(status.strikes, Some(1));
        assert_eq!(status.loaded_at, Some(17));
        assert_eq!(status.source, Some(Source::Fs));
        assert_eq!(status.firmware_clean, Some(true));
        let line = describe(&status).unwrap();
        assert!(
            line.contains("8c0a073fe1a0") && line.contains("strike 1 of 2"),
            "{line}"
        );
    }

    #[test]
    fn a_stock_or_damaged_status_names_no_image() {
        let cases: Vec<String> = vec![
            String::new(),
            "state=stock\nreason=off\n".into(),
            "state=stock\nreason=strikes\nsha256=\n".into(),
            "state=staged\n".into(),
            format!("state=staged\nsha256={}\n", &A[..63]),
            format!("state=staged\nsha256={}z\n", &A[..63]),
            format!("state=stock\nsha256={A}\n"),
        ];
        for text in &cases {
            assert_eq!(parse_status(text).staged, None, "{text:?}");
        }
        assert_eq!(describe(&parse_status("state=stock\nreason=off\n")), None);
        assert_eq!(
            describe(&parse_status("state=stock\nreason=no-volume\n")),
            None
        );
        assert_eq!(
            describe(&parse_status("state=stock\nreason=quarantined\n")).as_deref(),
            Some("tk boot: stock modem firmware (quarantined)")
        );
    }

    #[test]
    fn nothing_arms_without_a_staged_image() {
        let mut never = 0;
        for text in [
            "",
            "state=stock\nreason=off\n",
            "garbage",
            "state=stock\nreason=strikes\n",
        ] {
            if Confirm::arm(&parse_status(text), 1000, false).is_some() {
                never += 1;
            }
        }
        assert_eq!(never, 0);
        // Already confirmed or rolled back by an earlier keeper process.
        assert_eq!(Confirm::arm(&staged(17), 1000, true), None);
    }

    #[test]
    fn the_window_counts_from_the_load() {
        assert_eq!(
            Confirm::arm(&staged(17), 90, false).unwrap().deadline,
            17 + CONFIRM_SECS
        );
        // No load time, or one from a clock ahead of ours: count from now.
        let mut status = staged(17);
        status.loaded_at = None;
        assert_eq!(
            Confirm::arm(&status, 90, false).unwrap().deadline,
            90 + CONFIRM_SECS
        );
        assert_eq!(
            Confirm::arm(&staged(500), 90, false).unwrap().deadline,
            90 + CONFIRM_SECS
        );
    }

    #[test]
    fn an_answer_with_a_management_address_confirms() {
        let mut confirm = Confirm::arm(&staged(17), 60, false).unwrap();
        assert_eq!(confirm.observe(60, false, None), Action::Hold);
        assert_eq!(confirm.observe(75, false, Some(true)), Action::Hold);
        assert_eq!(confirm.observe(90, true, Some(false)), Action::Hold);
        assert_eq!(confirm.observe(105, true, Some(true)), Action::Confirmed);
        // An answer that lands after the window still confirms.
        let mut late = Confirm::arm(&staged(17), 60, false).unwrap();
        assert_eq!(late.observe(400, true, Some(true)), Action::Confirmed);
    }

    #[test]
    fn silence_until_the_window_ends_rolls_back() {
        let mut confirm = Confirm::arm(&staged(17), 60, false).unwrap();
        let mut now = 60;
        while now < 17 + CONFIRM_SECS {
            assert_eq!(
                confirm.observe(now, true, Some(false)),
                Action::Hold,
                "{now}"
            );
            now += PROBE_EVERY;
        }
        assert_eq!(confirm.observe(now, true, Some(false)), Action::Rollback);
        // A modem that never attaches has no targets and no address.
        let mut dead = Confirm::arm(&staged(17), 60, false).unwrap();
        let mut now = 60;
        let action = loop {
            let action = dead.observe(now, false, None);
            if action != Action::Hold {
                break action;
            }
            now += PROBE_EVERY;
        };
        assert_eq!(action, Action::Rollback);
        assert!(now >= 17 + CONFIRM_SECS);
    }

    #[test]
    fn a_keeper_that_starts_late_looks_twice_first() {
        let mut confirm = Confirm::arm(&staged(17), 900, false).unwrap();
        assert_eq!(confirm.observe(900, false, None), Action::Hold);
        assert_eq!(confirm.observe(915, false, None), Action::Rollback);
        let mut confirm = Confirm::arm(&staged(17), 900, false).unwrap();
        assert_eq!(confirm.observe(900, false, None), Action::Hold);
        assert_eq!(confirm.observe(915, true, Some(true)), Action::Confirmed);
    }

    #[test]
    fn strike_counts_read_like_the_hook() {
        assert_eq!(parse_strikes("strikes=1\n"), Some(1));
        assert_eq!(parse_strikes("strikes=0\nstrikes= 2 # by hand\n"), Some(2));
        for bad in [
            "",
            "strikes=\n",
            "strikes=lots\n",
            "strikes=-1\n",
            "strikes=1000\n",
            " strikes=1\n",
        ] {
            assert_eq!(parse_strikes(bad), None, "{bad:?}");
        }
        assert_eq!(
            parse_strikes(&format_strikes(STRIKE_LIMIT)),
            Some(STRIKE_LIMIT)
        );
    }

    #[test]
    fn quarantine_adds_once_and_keeps_other_lines() {
        let one = add_quarantine("", A);
        assert_eq!(one, format!("{A}\n"));
        assert_eq!(add_quarantine(&one, &A.to_uppercase()), one);
        let two = add_quarantine(&format!("# bench\n{B}"), A);
        assert_eq!(two, format!("# bench\n{B}\n{A}\n"));
        assert_eq!(parse_quarantine(&two), vec![B.to_owned(), A.to_owned()]);
        assert_eq!(
            parse_quarantine("junk\n# comment\n\n"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn refusal_follows_either_record() {
        assert!(!refused(Some(1), &[], A));
        assert!(!refused(None, &[B.to_owned()], A));
        assert!(refused(Some(STRIKE_LIMIT), &[], A));
        assert!(refused(Some(0), &[A.to_owned()], A));
    }

    #[test]
    fn confirm_targets_come_from_the_config() {
        let targets = parse_targets(
            "enabled=1\ntarget=192.0.2.9\ntarget=192.0.2.9\ntarget=2001:db8::9 # core\ntarget=0.0.0.0\ntarget=127.0.0.1\ntarget=nope\n",
        );
        assert_eq!(
            targets,
            vec![
                "192.0.2.9".parse::<IpAddr>().unwrap(),
                "2001:db8::9".parse().unwrap()
            ]
        );
        assert!(parse_targets("enabled=1\n").is_empty());
    }

    #[test]
    fn the_hook_rules() {
        assert_eq!(
            hook_decision(false, Some(0), true, false),
            Boot::Stock("off")
        );
        assert_eq!(
            hook_decision(true, None, true, false),
            Boot::Stock("strikes-unreadable")
        );
        assert_eq!(
            hook_decision(true, Some(0), true, false),
            Boot::Stage { strike: 1 }
        );
        assert_eq!(
            hook_decision(true, Some(1), true, false),
            Boot::Stage { strike: 2 }
        );
        assert_eq!(
            hook_decision(true, Some(2), true, false),
            Boot::Stock("strikes")
        );
        assert_eq!(
            hook_decision(true, Some(0), false, false),
            Boot::Stock("not-allowed")
        );
        assert_eq!(
            hook_decision(true, Some(0), true, true),
            Boot::Stock("quarantined")
        );
    }

    /// Boots a unit whose staged image never answers. Returns how many boots
    /// loaded it and how many reboots the keeper asked for.
    fn failing_image(boots: u32, keeper_writes: bool) -> (u32, u32) {
        let mut strikes = 0;
        let mut quarantine: Vec<String> = Vec::new();
        let (mut loaded, mut reboots) = (0, 0);
        for _ in 0..boots {
            let Boot::Stage { strike } = hook_decision(
                true,
                Some(strikes),
                true,
                quarantine.contains(&A.to_owned()),
            ) else {
                continue;
            };
            strikes = strike;
            loaded += 1;
            let mut confirm = Confirm::arm(&staged(17), 60, false).unwrap();
            let mut now = 60;
            while confirm.observe(now, false, None) == Action::Hold {
                now += PROBE_EVERY;
            }
            if keeper_writes {
                quarantine = parse_quarantine(&add_quarantine("", A));
                strikes = STRIKE_LIMIT;
            }
            if refused(Some(strikes), &quarantine, A) {
                reboots += 1;
            }
            // Without a record the keeper does not reboot; a power cycle does.
        }
        (loaded, reboots)
    }

    #[test]
    fn a_failing_image_loads_once_and_reboots_once() {
        assert_eq!(failing_image(10, true), (1, 1));
    }

    #[test]
    fn a_failing_image_stops_at_the_strike_limit_even_if_the_keeper_cannot_write() {
        let (loaded, reboots) = failing_image(10, false);
        assert_eq!(loaded, STRIKE_LIMIT);
        assert!(reboots <= 1, "{reboots}");
    }

    #[test]
    fn a_confirmed_image_keeps_loading() {
        let mut strikes = 0;
        for _ in 0..10 {
            let Boot::Stage { strike } = hook_decision(true, Some(strikes), true, false) else {
                panic!("a confirmed image was refused");
            };
            assert_eq!(strike, 1);
            let mut confirm = Confirm::arm(&staged(17), 60, false).unwrap();
            assert_eq!(confirm.observe(120, true, Some(true)), Action::Confirmed);
            strikes = parse_strikes(&format_strikes(0)).unwrap();
        }
    }

    #[test]
    fn flag_writes_need_the_patch_magic() {
        let n4 = "\u{1b}[0m0x847ED600 | 4e 34 56 32 00 00 00 00\n";
        assert!(flag_writes_allowed(n4));
        assert!(flag_writes_allowed("0x847ed600 | 4e 34 56 32\n"));
        assert_eq!(
            vm_bytes(n4, MAGIC_ADDR),
            Some(vec![0x4e, 0x34, 0x56, 0x32, 0, 0, 0, 0])
        );
        for stock in [
            "",
            "0x847ED600 | 00 b5 4f f0\n",
            "0x847ED600 | 4e 34 56\n",
            "0x847ED604 | 4e 34 56 32\n",
            "0x847ED600 4e 34 56 32\n",
            "0x847ED600 | 4e 34 56 33\n",
        ] {
            assert!(!flag_writes_allowed(stock), "{stock:?}");
        }
    }
}
