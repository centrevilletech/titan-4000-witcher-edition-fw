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
//! - Only time with a cell in view counts against the image (v1.0.17): the
//!   modem attached, or measuring a cell (`cell_seen`). After `CONFIRM_SECS`
//!   of that without an answer, and at least `MIN_ROUNDS` probe rounds by
//!   this keeper process, the image is compared with stock firmware (a
//!   rollback). Time with no cell in view is waiting for the network, not a
//!   failure: only `SEARCH_SECS` of it in a row asks for one comparison, which
//!   catches an image that breaks cell search.
//! - A rollback quarantines the image's hash, sets the strike count to the
//!   limit and reboots once onto stock firmware. The keeper reboots only
//!   after reading back a record that makes the hook refuse the image, so the
//!   same failure cannot repeat.
//! - A keeper that restarts after a confirm or rollback does not judge the
//!   boot again (`/var/run/witcher-tk.result`).
//! - Even with no keeper at all, the strike count stops the hook after
//!   `STRIKE_LIMIT` staged boots without a confirm.
//! - Every reboot the keeper starts asks `reboot_hold` first: none while the
//!   SAS CPAS window (`CPAS_QUIET`) is open, and none with the clock unset on
//!   a boot that heard an answer through the core. A rollback that must wait
//!   records nothing and keeps watching, so an answer meanwhile still
//!   confirms the image.
use std::net::IpAddr;

use crate::carrier_watch::{QuietWindow, parse_quiet_window};

/// Seconds with a cell in view but no answer through the core before the
/// image is compared with stock firmware.
pub const CONFIRM_SECS: u64 = 300;
/// Seconds in a row with no cell in view (the modem searching) before one
/// comparison with stock firmware.
pub const SEARCH_SECS: u64 = 1800;
/// While the image waits for the network after a network verdict
/// (`tk_verdict`), the seconds before it may be compared once more: the
/// recheck for an image whose failure an outage hid.
pub const RECHECK_SECS: u64 = 86_400;
/// The most one gap between probe rounds adds to a clock, so a keeper that
/// was paused does not count the pause.
const MAX_STEP: u64 = 60;
/// Seconds the image must run without a modem crash before its crash count
/// is history (`tk_verdict::Verdict::healthy`).
pub const CRASH_CLEAR_SECS: u64 = 86_400;
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

/// The SAS CPAS window, 06:45 to 10:15 UTC with a margin: no new grants are
/// issued in it, so a reboot then can leave a unit without grants for hours.
pub const CPAS_QUIET: QuietWindow = QuietWindow { start_min: 6 * 60 + 45, end_min: 10 * 60 + 15 };
/// Wall clock seconds before which the clock is not set (2026-01-01). The
/// vendor boots with a 2013 date until the network sets it.
pub const CLOCK_SET_AFTER: u64 = 1_767_225_600;

/// The window a rollback reboot waits out: `CPAS_QUIET`, another
/// `HH:MM-HH:MM` (tests), or none for an empty text.
pub fn quiet_window(text: Option<&str>) -> Option<QuietWindow> {
    match text {
        None => Some(CPAS_QUIET),
        Some("") => None,
        Some(text) => parse_quiet_window(text).or(Some(CPAS_QUIET)),
    }
}

/// Why a reboot the keeper wants must wait, or `None` when it may go now.
/// Every reboot the keeper starts asks: the boot confirm's, the verdict's and
/// the deaf watchdog's. In the SAS CPAS window no new grants are issued, so a
/// reboot then can leave the unit without one for hours.
///
/// - The clock is set: the window decides.
/// - The clock is unset and the unit may hold a grant (`may_hold_grant`:
///   something answered through the core this boot, or the vendor cache
///   shows a grant held): the reboot waits for the clock.
/// - The clock is unset and neither: the unit has had no data path and shows
///   no grant, and its clock cannot be set (the Titan has no battery clock
///   and boots at 2013 until NTP sets it). Waiting would strand an image that
///   breaks the data path, so it goes.
pub fn reboot_hold(window: Option<QuietWindow>, wall: u64, may_hold_grant: bool) -> Option<&'static str> {
    if wall >= CLOCK_SET_AFTER {
        window
            .is_some_and(|w| w.contains(wall))
            .then_some("the SAS CPAS window is open")
    } else {
        may_hold_grant.then_some("the clock is not set yet")
    }
}

/// Times the boot confirm uses. Tests shorten them with
/// `TITAN_TK_CONFIRM_SECS`, `TITAN_TK_SEARCH_SECS`, `TITAN_TK_RECHECK_SECS`
/// and `TITAN_TK_PROBE_EVERY`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    pub confirm: u64,
    pub search: u64,
    pub recheck: u64,
    pub probe_every: u64,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            confirm: CONFIRM_SECS,
            search: SEARCH_SECS,
            recheck: RECHECK_SECS,
            probe_every: PROBE_EVERY,
        }
    }
}

impl Timing {
    /// The defaults, with any override `get` returns. A missing, unreadable
    /// or zero value keeps the default.
    pub fn with(get: impl Fn(&str) -> Option<String>) -> Self {
        let read = |name: &str, fallback: u64| {
            get(name)
                .and_then(|value| value.trim().parse::<u64>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(fallback)
        };
        let base = Self::default();
        Self {
            confirm: read("TITAN_TK_CONFIRM_SECS", base.confirm),
            search: read("TITAN_TK_SEARCH_SECS", base.search),
            recheck: read("TITAN_TK_RECHECK_SECS", base.recheck),
            probe_every: read("TITAN_TK_PROBE_EVERY", base.probe_every),
        }
    }
}

/// The modem sees a cell: attached, or measuring one. `media` is
/// `sqns_connection_mediaState` (as stored or as `nvram_get` prints it) and
/// `rsrp` is `sqns_radio_RSRP`, hundredths of a dBm per carrier. A value
/// inside -140 to -20 dBm is a measured cell; searching leaves it empty.
pub fn cell_seen(media: &str, rsrp: &str) -> bool {
    let media = media.rsplit(':').next().unwrap_or("").trim();
    if matches!(media, "ATTACHED" | "CONNECTED") {
        return true;
    }
    rsrp.split(',')
        .any(|field| field.trim().parse::<i64>().is_ok_and(|value| (-14_000..=-2_000).contains(&value)))
}

/// A short id of the running firmware build: the first 16 hex digits of the
/// SHA-256 of `/etc/witcher-release`, `unknown` without one. The boot hook
/// computes the same with `sha256sum`. Strikes, rollbacks and quarantines
/// recorded by another build no longer apply (`tk_default::plan`).
pub fn firmware_id(release: &[u8]) -> String {
    if release.is_empty() {
        return "unknown".to_owned();
    }
    let hex = crate::sha256::hex(&crate::sha256::digest(release));
    hex.get(..16).unwrap_or(&hex).to_owned()
}

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
    /// What the default image's build did this boot (`tk_default`): `built`,
    /// `cached`, `operator`, or the reason it kept stock firmware.
    pub build: Option<String>,
    /// Seconds the hook spent on that step.
    pub build_secs: Option<u64>,
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
            "build" if !value.is_empty() => status.build = Some(value.to_owned()),
            "build_secs" => status.build_secs = value.parse().ok(),
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
    let line = describe_load(status)?;
    Some(match (status.build.as_deref(), status.build_secs) {
        (Some("built"), secs) => {
            let took = secs.map_or_else(String::new, |s| format!(" in {s} s"));
            format!("{line}; the boot hook built the default modem image{took} from this unit's stock firmware")
        }
        _ => line,
    })
}

fn describe_load(status: &BootStatus) -> Option<String> {
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

/// Why a comparison with stock firmware is due.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// A cell in view for `Timing::confirm` seconds without an answer (on a
    /// stock boot: no answer within that long of the load).
    Blind,
    /// No cell in view for `Timing::search` seconds in a row.
    Search,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Hold,
    Confirmed,
    Rollback(Why),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// The staged image's boot.
    Image,
    /// A stock boot judging the last rollback (`tk_verdict`): no answer by
    /// `deadline`, keeper monotonic seconds, means stock failed as well.
    Stock { deadline: u64 },
}

/// A pending boot confirm, or a stock boot's judging watch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Confirm {
    pub sha: String,
    /// The image waits for the network: its last rollback was the network's
    /// (`tk_verdict`). It is compared again only after `Timing::recheck`.
    pub waiting: bool,
    mode: Mode,
    timing: Timing,
    armed_at: u64,
    rounds: u32,
    last: Option<u64>,
    /// Seconds with a cell in view and no answer.
    blind: u64,
    /// The first round of the current run with no cell in view.
    searching_since: Option<u64>,
}

impl Confirm {
    /// `now` is the keeper's monotonic clock in seconds since boot. `decided`
    /// is true when a keeper process already confirmed or rolled back this
    /// boot. The clocks count from this keeper's rounds, so time before the
    /// keeper started never counts against the image.
    pub fn arm(status: &BootStatus, now: u64, decided: bool, timing: Timing, waiting: bool) -> Option<Self> {
        if decided {
            return None;
        }
        Some(Self {
            sha: status.staged.clone()?,
            waiting,
            mode: Mode::Image,
            timing,
            armed_at: now,
            rounds: 0,
            last: None,
            blind: 0,
            searching_since: None,
        })
    }

    /// The watch on a stock boot after a rollback of `sha` (`tk_verdict`):
    /// `Confirmed` means stock firmware answered within `Timing::confirm` of
    /// its load, `Rollback` that it did not either.
    pub fn watch(sha: &str, loaded_at: Option<u64>, now: u64, timing: Timing) -> Self {
        let base = loaded_at.filter(|at| *at <= now).unwrap_or(now);
        Self {
            sha: sha.to_ascii_lowercase(),
            waiting: false,
            mode: Mode::Stock {
                deadline: base.saturating_add(timing.confirm),
            },
            timing,
            armed_at: now,
            rounds: 0,
            last: None,
            blind: 0,
            searching_since: None,
        }
    }

    /// One finished probe round. `mgmt_up` is an address on the management
    /// bearer. `heard` is `None` when no probe could run (no targets yet,
    /// which is what a modem that never attaches looks like). `cell` is
    /// `cell_seen` for this round. A due rollback stays due round after round
    /// until an answer confirms instead.
    pub fn observe(&mut self, now: u64, mgmt_up: bool, heard: Option<bool>, cell: bool) -> Action {
        if mgmt_up && heard == Some(true) {
            return Action::Confirmed;
        }
        self.rounds = self.rounds.saturating_add(1);
        let step = self.last.map_or(0, |last| now.saturating_sub(last).min(MAX_STEP));
        self.last = Some(now);
        if let Mode::Stock { deadline } = self.mode {
            return if now >= deadline && self.rounds >= MIN_ROUNDS {
                Action::Rollback(Why::Blind)
            } else {
                Action::Hold
            };
        }
        if cell {
            self.blind = self.blind.saturating_add(step);
            self.searching_since = None;
        } else if self.searching_since.is_none() {
            self.searching_since = Some(now);
        }
        if self.rounds < MIN_ROUNDS || (self.waiting && now.saturating_sub(self.armed_at) < self.timing.recheck) {
            return Action::Hold;
        }
        if self.blind >= self.timing.confirm {
            return Action::Rollback(Why::Blind);
        }
        match self.searching_since {
            Some(since) if now.saturating_sub(since) >= self.timing.search => Action::Rollback(Why::Search),
            _ => Action::Hold,
        }
    }

    /// A round skipped because the radio guard is cycling the radio on
    /// purpose: no clock runs for the time since the last round, and a stock
    /// watch's deadline moves on by as much.
    pub fn pause(&mut self, now: u64) {
        let step = self.last.map_or(0, |last| now.saturating_sub(last).min(MAX_STEP));
        self.last = Some(now);
        if let Mode::Stock { deadline } = &mut self.mode {
            *deadline = deadline.saturating_add(step);
        }
        if let Some(since) = &mut self.searching_since {
            *since = since.saturating_add(step);
        }
    }

    /// Seconds with a cell in view and no answer so far.
    pub fn blind_secs(&self) -> u64 {
        self.blind
    }

    /// A stock boot's judging watch, not an image's confirm.
    pub fn judging(&self) -> bool {
        matches!(self.mode, Mode::Stock { .. })
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

/// `strikes=N` and the firmware build that counted them (`firmware_id`).
pub fn format_strikes(strikes: u32, firmware: &str) -> String {
    format!("strikes={strikes}\nfirmware={firmware}\n")
}

/// The firmware build a strikes file names; `None` for one written before
/// v1.0.17 (or by hand).
pub fn strikes_firmware(text: &str) -> Option<String> {
    value(text, "firmware").filter(|id| !id.is_empty())
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

/// The quarantine file without `sha`. Other lines stay as they are.
pub fn remove_quarantine(existing: &str, sha: &str) -> String {
    let mut text = String::new();
    for line in existing.lines() {
        let listed = parse_quarantine(line).first().is_some_and(|q| q.eq_ignore_ascii_case(sha));
        if !listed {
            text.push_str(line);
            text.push('\n');
        }
    }
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

/// The line without terminal colour sequences.
pub fn strip_escapes(line: &str) -> String {
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
    fn a_quarantine_line_comes_off_and_the_others_stay() {
        let text = format!("# keeper\n{A}\n{} # bench\n", B.to_uppercase());
        assert_eq!(remove_quarantine(&text, B), format!("# keeper\n{A}\n"));
        assert_eq!(remove_quarantine(&text, A), format!("# keeper\n{} # bench\n", B.to_uppercase()));
        assert_eq!(remove_quarantine(&add_quarantine("", A), A), "");
        assert_eq!(parse_quarantine(&remove_quarantine(&text, "ff")), parse_quarantine(&text));
    }

    #[test]
    fn every_keeper_reboot_waits_out_the_cpas_window_and_for_a_set_clock() {
        let day = 1_795_305_600; // 2026-11-22T00:00:00Z
        let at = |h: u64, m: u64| day + h * 3600 + m * 60;
        let cpas = quiet_window(None);
        assert_eq!(cpas, Some(CPAS_QUIET));
        for heard in [false, true] {
            assert_eq!(reboot_hold(cpas, at(6, 44), heard), None);
            assert_eq!(reboot_hold(cpas, at(6, 45), heard), Some("the SAS CPAS window is open"));
            assert_eq!(reboot_hold(cpas, at(10, 14), heard), Some("the SAS CPAS window is open"));
            assert_eq!(reboot_hold(cpas, at(10, 15), heard), None);
            assert_eq!(reboot_hold(cpas, at(23, 0), heard), None);
        }
        // A 2013 clock on a boot that heard an answer: it may hold a grant,
        // so it waits for the clock. One that heard nothing holds none.
        let early = 1_370_000_000 + 7 * 3600;
        assert_eq!(reboot_hold(cpas, early, true), Some("the clock is not set yet"));
        assert_eq!(reboot_hold(cpas, early, false), None);
        assert_eq!(reboot_hold(quiet_window(Some("")), at(8, 0), true), None);
        assert!(reboot_hold(quiet_window(Some("23:00-01:00")), at(0, 30), false).is_some());
        assert_eq!(quiet_window(Some("nonsense")), Some(CPAS_QUIET));
    }

    #[test]
    fn a_cell_is_an_attach_or_a_measured_rsrp() {
        assert!(cell_seen("nvram_get success: ATTACHED\n", ""));
        assert!(cell_seen("CONNECTED", ""));
        assert!(cell_seen("CONNECTING", "-10790"));
        assert!(cell_seen("DISCONNECTED", ",-11250"));
        for searching in [("DISCONNECTED", ""), ("Not Searching", ""), ("", "0"), ("CONNECTING", "-32768"), ("", "garbage")] {
            assert!(!cell_seen(searching.0, searching.1), "{searching:?}");
        }
        // The id of a firmware build, and of none.
        assert_eq!(firmware_id(b""), "unknown");
        let id = firmware_id(b"{\"version\":\"1.0.17\"}\n");
        assert_eq!(id.len(), 16);
        assert_ne!(id, firmware_id(b"{\"version\":\"1.0.18\"}\n"));
        let timing = Timing::with(|name| (name == "TITAN_TK_SEARCH_SECS").then(|| "40".to_owned()));
        assert_eq!((timing.confirm, timing.search), (CONFIRM_SECS, 40));
        assert_eq!(Timing::with(|_| Some("0".to_owned())), Timing::default());
    }

    #[test]
    fn the_log_line_says_when_the_hook_built_the_default_image() {
        let mut status = staged(40);
        status.build = Some("built".into());
        status.build_secs = Some(19);
        let line = describe(&status).unwrap();
        assert!(line.ends_with("; the boot hook built the default modem image in 19 s from this unit's stock firmware"), "{line}");
        let text = format!("state=staged\nsha256={A}\nbuild=cached\nbuild_secs=1\n");
        assert!(!describe(&parse_status(&text)).unwrap().contains("built"));
        let mismatch = parse_status("state=stock\nreason=stock-mismatch\nbuild=stock-mismatch\nbuild_secs=2\n");
        assert_eq!((mismatch.build.as_deref(), mismatch.build_secs), (Some("stock-mismatch"), Some(2)));
        assert_eq!(describe(&mismatch).as_deref(), Some("tk boot: stock modem firmware (stock-mismatch)"));
        assert_eq!(parse_status("build=\n").build, None);
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
            if Confirm::arm(&parse_status(text), 1000, false, Timing::default(), false).is_some() {
                never += 1;
            }
        }
        assert_eq!(never, 0);
        // Already confirmed or rolled back by an earlier keeper process.
        assert_eq!(Confirm::arm(&staged(17), 1000, true, Timing::default(), false), None);
    }

    /// Rounds every `PROBE_EVERY` from `start` until an action other than
    /// `Hold`; `cell` and `heard` say what each round sees.
    fn run(confirm: &mut Confirm, start: u64, until: u64, cell: impl Fn(u64) -> bool) -> (Action, u64) {
        let mut now = start;
        while now <= until {
            let action = confirm.observe(now, cell(now), Some(false), cell(now));
            if action != Action::Hold {
                return (action, now);
            }
            now += PROBE_EVERY;
        }
        (Action::Hold, now)
    }

    fn image(now: u64) -> Confirm {
        Confirm::arm(&staged(17), now, false, Timing::default(), false).unwrap()
    }

    #[test]
    fn an_answer_with_a_management_address_confirms() {
        let mut confirm = image(60);
        assert_eq!(confirm.observe(60, false, None, true), Action::Hold);
        assert_eq!(confirm.observe(75, false, Some(true), true), Action::Hold);
        assert_eq!(confirm.observe(90, true, Some(false), true), Action::Hold);
        assert_eq!(confirm.observe(105, true, Some(true), true), Action::Confirmed);
        // An answer that lands after a rollback fell due still confirms.
        let mut late = image(60);
        let (due, now) = run(&mut late, 60, 10_000, |_| true);
        assert_eq!(due, Action::Rollback(Why::Blind));
        assert_eq!(late.observe(now + PROBE_EVERY, true, Some(true), true), Action::Confirmed);
    }

    #[test]
    fn only_time_with_a_cell_in_view_counts_against_the_image() {
        // A cell in view and no answer: compared after CONFIRM_SECS of it,
        // counted from this keeper's rounds.
        let (action, now) = run(&mut image(60), 60, 10_000, |_| true);
        assert_eq!(action, Action::Rollback(Why::Blind));
        assert_eq!(now, 60 + CONFIRM_SECS);
        // A tower that is down: no cell, so nothing counts until 30 minutes
        // in a row of searching ask for one comparison.
        let (action, now) = run(&mut image(60), 60, 100_000, |_| false);
        assert_eq!(action, Action::Rollback(Why::Search));
        assert_eq!(now, 60 + SEARCH_SECS);
        // A tower that flaps: a cell every few minutes resets the search, and
        // only the minutes with the cell count toward the blind clock.
        let mut flapping = image(60);
        let (action, now) = run(&mut flapping, 60, 100_000, |now| (now / 60) % 10 == 0);
        assert_eq!(action, Action::Rollback(Why::Blind));
        assert!(now > 60 + 8 * CONFIRM_SECS, "{now}");
        // A keeper paused for an hour counts a minute of it at most.
        let mut paused = image(60);
        assert_eq!(paused.observe(60, true, Some(false), true), Action::Hold);
        assert_eq!(paused.observe(3660, true, Some(false), true), Action::Hold);
        assert_eq!(paused.blind_secs(), 60);
    }

    #[test]
    fn an_image_waiting_for_the_network_is_compared_again_only_after_the_recheck() {
        let mut waiting = Confirm::arm(&staged(17), 60, false, Timing::default(), true).unwrap();
        // Hours of a cell and no answer (a core outage) or of no cell: held.
        let (action, _) = run(&mut waiting, 60, 60 + RECHECK_SECS - PROBE_EVERY, |now| now % 7200 < 3600);
        assert_eq!(action, Action::Hold);
        let (action, now) = run(&mut waiting, 60 + RECHECK_SECS, 60 + RECHECK_SECS + 3600, |_| true);
        assert!(matches!(action, Action::Rollback(_)), "{action:?}");
        assert_eq!(now, 60 + RECHECK_SECS);
        // An answer ends the wait at any time.
        let mut waiting = Confirm::arm(&staged(17), 60, false, Timing::default(), true).unwrap();
        assert_eq!(waiting.observe(5000, true, Some(true), true), Action::Confirmed);
    }

    #[test]
    fn a_stock_watch_counts_from_the_load_whatever_the_cell() {
        let watch = Confirm::watch(&A.to_uppercase(), Some(40), 100, Timing::default());
        assert_eq!(watch.sha, A);
        assert!(watch.judging() && !image(60).judging());
        for cell in [false, true] {
            let mut watch = Confirm::watch(A, Some(40), 100, Timing::default());
            let (action, now) = run(&mut watch, 100, 10_000, |_| cell);
            assert_eq!(action, Action::Rollback(Why::Blind));
            assert!(now >= 40 + CONFIRM_SECS && now < 40 + CONFIRM_SECS + PROBE_EVERY, "{now}");
        }
        // A load time ahead of the keeper's clock counts from now.
        let mut ahead = Confirm::watch(A, Some(500), 100, Timing::default());
        assert_eq!(run(&mut ahead, 100, 10_000, |_| false).1, 100 + CONFIRM_SECS);
        let mut answered = Confirm::watch(A, Some(40), 100, Timing::default());
        assert_eq!(answered.observe(110, true, Some(true), false), Action::Confirmed);
    }

    #[test]
    fn the_radio_guards_own_radio_cycles_stop_every_clock() {
        // A cell and no answer, but the radio guard cycles the radio for
        // most of it: those rounds count nothing.
        let mut confirm = image(60);
        let mut now = 60;
        while now < 60 + 10 * CONFIRM_SECS {
            let action = if (now / 100) % 4 == 0 {
                confirm.observe(now, true, Some(false), true)
            } else {
                confirm.pause(now);
                Action::Hold
            };
            if action != Action::Hold {
                break;
            }
            now += PROBE_EVERY;
        }
        assert!(now > 60 + 3 * CONFIRM_SECS, "{now}: paused time counted");
        // A stock watch's deadline moves on by the paused time.
        let mut watch = Confirm::watch(A, Some(100), 100, Timing::default());
        for t in (100..=400).step_by(PROBE_EVERY as usize) {
            watch.pause(t);
        }
        assert_eq!(watch.observe(415, false, None, false), Action::Hold);
        assert_eq!(watch.observe(430, false, None, false), Action::Hold);
        assert_eq!(watch.observe(100 + CONFIRM_SECS + 300, false, None, false), Action::Rollback(Why::Blind));
    }

    #[test]
    fn a_keeper_that_starts_late_looks_twice_first() {
        let mut watch = Confirm::watch(A, Some(17), 900, Timing::default());
        assert_eq!(watch.observe(900, false, None, false), Action::Hold);
        assert_eq!(watch.observe(915, false, None, false), Action::Rollback(Why::Blind));
        let mut confirm = image(900);
        assert_eq!(confirm.observe(900, false, None, true), Action::Hold);
        assert_eq!(confirm.observe(915, true, Some(true), true), Action::Confirmed);
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
            parse_strikes(&format_strikes(STRIKE_LIMIT, "0123456789abcdef")),
            Some(STRIKE_LIMIT)
        );
        // The build that counted them; none before v1.0.17.
        assert_eq!(
            strikes_firmware(&format_strikes(1, "0123456789abcdef")).as_deref(),
            Some("0123456789abcdef")
        );
        assert_eq!(strikes_firmware("strikes=2\n"), None);
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
            let mut confirm = image(60);
            let mut now = 60;
            while confirm.observe(now, true, Some(false), true) == Action::Hold {
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
            let mut confirm = image(60);
            assert_eq!(confirm.observe(120, true, Some(true), true), Action::Confirmed);
            strikes = parse_strikes(&format_strikes(0, "f")).unwrap();
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
