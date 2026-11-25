//! Watch active Band 48 transmit carriers against held SAS grants.
//!
//! The vendor SAS client asks for grants covering the main carrier (PCell) and
//! the uplink SCell. `rcinit` sends a new channel mask only after a re-attach
//! that it sees ("LTE pdn changed"), or more than 60 s after a PCell change
//! (`ucid` handover hook). When the tower adds or swaps an uplink SCell inside
//! an active connection, nothing notifies `rcinit` or `cbrs_fsm`, so the radio
//! can transmit on an ungranted 20 MHz channel for hours.
//!
//! Carrier watch runs in the keeper at most once per second:
//! - Computes the transmit carrier spans (PCell + uplink SCell) from
//!   `/tmp/nvram.cfg` using the vendor's 5 MHz rounding.
//! - Reads authorized grants incrementally from `/mnt/cbrslog0.txt` (lines
//!   with three `()` groups whose transmit expiry is in the future).
//! - Debounces an uncovered carrier for `debounce_secs` (default 3 s) so a
//!   normal re-grant or torn nvram read never triggers it.
//! - Acts according to `/mnt/titan-api/carrier-watch/config`:
//!   - `mode=log` (default with no file): log and update status file only.
//!   - `mode=off`: do nothing and log nothing.
//!   - `mode=regrant`: outside the CPAS quiet window (`quiet_utc=06:45-10:00`),
//!     with a sane wall clock, rate limits (1 per 5 min, 6 per 24 h, backoff
//!     after failure), `cbrs_mode_grant=1`, and `rc_signal_done=1`, runs the
//!     same sequence `ucid` uses (`sqns_network_cbrs=1` + SIGUSR1 to `rcinit`)
//!     and waits up to 180 s for coverage.
//! - A unit with no SAS/CBRS mode logs nothing.

use std::collections::BTreeMap;
use std::fmt;

use crate::nvram::field as nvram_field;

/// Seconds between carrier-watch checks.
pub const INTERVAL: u64 = 1;
/// Seconds between reloads of `carrier-watch/config`.
pub const CONFIG_EVERY: u64 = 5;
/// Consecutive uncovered seconds before entering `uncovered`.
pub const DEFAULT_DEBOUNCE_SECS: u64 = 3;
/// Minimum and maximum configurable debounce seconds.
pub const MIN_DEBOUNCE_SECS: u64 = 1;
pub const MAX_DEBOUNCE_SECS: u64 = 60;
/// Maximum seconds to wait for coverage after forcing a re-grant.
pub const REGRANT_TIMEOUT_SECS: u64 = 180;
/// Minimum seconds between two forced re-grants.
pub const MIN_REGRANT_INTERVAL_SECS: u64 = 300;
/// Maximum backoff after consecutive failed forced re-grants.
pub const MAX_BACKOFF_SECS: u64 = 3600;
/// Maximum forced re-grants allowed in any 24-hour window.
pub const MAX_REGRANTS_PER_DAY: usize = 6;
/// Seconds in one day.
pub const DAY_SECS: u64 = 86_400;
/// Seconds between repeated quiet-window log reminders.
pub const QUIET_LOG_EVERY_SECS: u64 = 600;
/// Earliest wall-clock epoch considered sane (2024-01-01T00:00:00Z).
/// The Titan boots at 2013-06-20 until NTP sets the clock.
pub const SANE_EPOCH: u64 = 1_704_067_200;

/// Default CPAS quiet window: 06:45-10:00 UTC.
pub const DEFAULT_QUIET_START_MIN: u16 = 6 * 60 + 45;
pub const DEFAULT_QUIET_END_MIN: u16 = 10 * 60;

/// Band 48 (3550-3700 MHz) limits.
pub const BAND48_EARFCN_MIN: u32 = 55_240;
pub const BAND48_EARFCN_MAX: u32 = 56_739;
pub const BAND48_LOW_KHZ: u64 = 3_550_000;
pub const BAND48_HIGH_KHZ: u64 = 3_700_000;
pub const DEFAULT_BW_KHZ: u64 = 20_000;

/// A frequency span in Hz.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub low_hz: u64,
    pub high_hz: u64,
}

impl Span {
    pub const fn mhz(low_mhz: u64, high_mhz: u64) -> Self {
        Self {
            low_hz: low_mhz * 1_000_000,
            high_hz: high_mhz * 1_000_000,
        }
    }

    /// True when `self` lies completely inside `grant`.
    pub fn inside(self, grant: Span) -> bool {
        self.low_hz >= grant.low_hz && self.high_hz <= grant.high_hz
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.low_hz % 1_000_000 == 0 && self.high_hz % 1_000_000 == 0 {
            write!(f, "{}-{}", self.low_hz / 1_000_000, self.high_hz / 1_000_000)
        } else {
            write!(f, "{}-{}Hz", self.low_hz, self.high_hz)
        }
    }
}

/// Compute a 5 MHz-rounded CBRS span from centre frequency and bandwidth in kHz,
/// matching `rcinit`'s `cbrs_lte_change` rounding (`0x155cc..0x15684`).
pub fn span_from_khz(centre_khz: u64, bw_khz: u64) -> Option<Span> {
    if !(BAND48_LOW_KHZ..=BAND48_HIGH_KHZ).contains(&centre_khz) || bw_khz == 0 {
        return None;
    }
    let bw_mhz = (bw_khz / 1000).max(5);
    let low_khz = centre_khz.checked_sub(bw_khz / 2)?;
    let low_mhz = ((low_khz + 2_500) / 5_000) * 5;
    let high_mhz = low_mhz + bw_mhz;
    Some(Span::mhz(low_mhz, high_mhz))
}

/// Compute a Band 48 span from an EARFCN (55240..=56739) and bandwidth in kHz.
/// Band 48: f = 3550 + (earfcn - 55240) / 10 MHz.
pub fn span_from_earfcn(earfcn: u32, bw_khz: u64) -> Option<Span> {
    if !(BAND48_EARFCN_MIN..=BAND48_EARFCN_MAX).contains(&earfcn) {
        return None;
    }
    let centre_khz = BAND48_LOW_KHZ + u64::from(earfcn - BAND48_EARFCN_MIN) * 100;
    span_from_khz(centre_khz, bw_khz)
}

/// Compute a Band 48 span from the vendor's 100 kHz frequency value (e.g.
/// `36898` = 3689.8 MHz) and bandwidth in kHz (e.g. `20000` = 20 MHz).
pub fn span_from_freq_100khz(freq_100khz: u32, bw_khz: u64) -> Option<Span> {
    let centre_khz = u64::from(freq_100khz) * 100;
    span_from_khz(centre_khz, bw_khz)
}

fn parse_u32_clean(text: &str) -> Option<u32> {
    let t = text.trim();
    if t.is_empty() || t == "-" {
        return None;
    }
    t.parse().ok()
}

fn parse_bw_khz(value: Option<&str>) -> Option<u64> {
    let raw = parse_u32_clean(value?)? as u64;
    if raw == 0 {
        return None;
    }
    // NVRAM bandwidth keys are in kHz (20000), while uplinkScc uses MHz (20).
    let khz = if raw <= 100 { raw * 1000 } else { raw };
    (5_000..=100_000).contains(&khz).then_some(khz)
}

/// Parse `sqns_connection_uplinkScc`, which has the form
/// `freq,pusch,prach,pucch,bw:55440,-55,-55,-55,20` when active, and is empty
/// or `-` when no uplink SCell is configured.
pub fn parse_uplink_scc(value: &str) -> Option<(u32, u64)> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "-" || trimmed.eq_ignore_ascii_case("none") {
        return None;
    }
    let data = trimmed.split_once(':').map_or(trimmed, |(_, rest)| rest);
    let entry = data.split(';').next().unwrap_or(data).trim();
    let mut parts = entry.split(',');
    let earfcn = parse_u32_clean(parts.next()?)?;
    if !(BAND48_EARFCN_MIN..=BAND48_EARFCN_MAX).contains(&earfcn) {
        return None;
    }
    let bw_khz = parts
        .nth(3)
        .and_then(|s| parse_bw_khz(Some(s)))
        .unwrap_or(DEFAULT_BW_KHZ);
    Some((earfcn, bw_khz))
}

/// Radio and CBRS keys extracted from one read of `/tmp/nvram.cfg`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NvramView {
    /// True when this unit appears to run Band 48 CBRS/SAS mode.
    pub cbrs_present: bool,
    /// `cbrs_mode_grant`: `Some(true)` for `"1"`, `Some(false)` for `"0"`.
    pub cbrs_mode_grant: Option<bool>,
    /// `cbrs_grant_state`: `Some(0|1|2)`.
    pub cbrs_grant_state: Option<u8>,
    /// True when `rc_signal_done` reads `"1"`.
    pub rc_signal_done: bool,
    /// Rounded PCell transmit span, if on Band 48.
    pub pcell: Option<Span>,
    /// Rounded uplink SCell transmit span, if active on Band 48.
    pub ulscc: Option<Span>,
}

/// Extract CBRS and carrier keys from `/tmp/nvram.cfg`.
pub fn read_nvram(cache: &[u8]) -> NvramView {
    let band = nvram_field(cache, "sqns_radio_band").map(str::trim);
    if let Some(b) = band {
        if !b.is_empty() && b != "-" && b != "48" {
            return NvramView::default();
        }
    }
    let mode_grant = match nvram_field(cache, "cbrs_mode_grant").map(str::trim) {
        Some("1") => Some(true),
        Some("0") => Some(false),
        _ => None,
    };
    let grant_state = nvram_field(cache, "cbrs_grant_state")
        .map(str::trim)
        .and_then(|s| s.parse::<u8>().ok());
    let rc_signal_done = nvram_field(cache, "rc_signal_done").map(str::trim) == Some("1");

    let dl_bw = parse_bw_khz(nvram_field(cache, "sqns_radio_bandwidthDl")).unwrap_or(DEFAULT_BW_KHZ);
    let pcell = nvram_field(cache, "sqns_radio_earfcnDl")
        .and_then(parse_u32_clean)
        .and_then(|e| span_from_earfcn(e, dl_bw))
        .or_else(|| {
            nvram_field(cache, "sqns_radio_freqDl")
                .and_then(parse_u32_clean)
                .and_then(|f| span_from_freq_100khz(f, dl_bw))
        });

    let ulscc = nvram_field(cache, "sqns_connection_uplinkScc")
        .and_then(parse_uplink_scc)
        .and_then(|(earfcn, bw)| span_from_earfcn(earfcn, bw))
        .or_else(|| {
            let freq = nvram_field(cache, "cbrs_radio_freqUl").and_then(parse_u32_clean)?;
            if freq == 0 {
                return None;
            }
            let ul_bw =
                parse_bw_khz(nvram_field(cache, "cbrs_radio_bandwidthUl")).unwrap_or(DEFAULT_BW_KHZ);
            span_from_freq_100khz(freq, ul_bw)
        });

    NvramView {
        cbrs_present: mode_grant.is_some(),
        cbrs_mode_grant: mode_grant,
        cbrs_grant_state: grant_state,
        rc_signal_done,
        pcell,
        ulscc,
    }
}

/// True when the wall clock is past `SANE_EPOCH` (not the Titan's 2013 boot
/// clock).
pub fn clock_sane(wall_now: u64) -> bool {
    wall_now >= SANE_EPOCH
}

/// Parse an ISO-8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`) to Unix seconds.
pub fn parse_utc_rfc3339(text: &str) -> Option<u64> {
    if !text.is_ascii() {
        return None;
    }
    let b = text.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let year: i64 = text[0..4].parse().ok()?;
    let month: u32 = text[5..7].parse().ok()?;
    let day: u32 = text[8..10].parse().ok()?;
    let hour: u64 = text[11..13].parse().ok()?;
    let min: u64 = text[14..16].parse().ok()?;
    let sec: u64 = text[17..19].parse().ok()?;
    if year < 1970 || !(1..=12).contains(&month) || day == 0 || hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if day > max_day {
        return None;
    }
    // Howard Hinnant's days_from_civil (days since 1970-01-01).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as u64;
    let m = month as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + u64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + (doe as i64) - 719_468;
    if days < 0 {
        return None;
    }
    Some((days as u64) * DAY_SECS + hour * 3600 + min * 60 + sec)
}

/// One authorized SAS grant parsed from `/mnt/cbrslog0.txt`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub index: u8,
    pub span: Span,
    pub eirp: i32,
    pub grant_expiry: u64,
    pub tx_expiry: u64,
}

/// Parse one `=<idx>(<n>):...` grant line from `/mnt/cbrslog0.txt`.
///
/// Returns:
/// - `None` if `line` is not a grant status line.
/// - `Some((idx, Some(grant)))` if the line has three valid `()` groups
///   (authorized grant).
/// - `Some((idx, None))` if the line has fewer than three `()` groups (not
///   authorized, e.g. inquiry, granted-before-heartbeat, or relinquished).
pub fn parse_grant_line(line: &str) -> Option<(u8, Option<Grant>)> {
    let rest = line.strip_prefix('=')?;
    let (idx_str, after_idx) = rest.split_once('(')?;
    if idx_str.is_empty() || !idx_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let index: u8 = idx_str.parse().ok()?;
    let (count_str, after_colon) = after_idx.split_once("):")?;
    if count_str.is_empty() || !count_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut groups: Vec<&str> = Vec::with_capacity(3);
    let mut cursor = after_colon;
    while let Some(open) = cursor.strip_prefix('(') {
        let Some((inside, next)) = open.split_once(')') else {
            // Truncated or malformed trailing group.
            return Some((index, None));
        };
        groups.push(inside);
        cursor = next;
    }
    if groups.len() < 3 || !cursor.is_empty() {
        return Some((index, None));
    }
    // Group 1: <lowHz>-<highHz>:<eirp>
    let Some((range_str, eirp_str)) = groups[0].split_once(':') else {
        return Some((index, None));
    };
    let Some((low_str, high_str)) = range_str.split_once('-') else {
        return Some((index, None));
    };
    let (Ok(low_hz), Ok(high_hz), Ok(eirp)) = (
        low_str.parse::<u64>(),
        high_str.parse::<u64>(),
        eirp_str.parse::<i32>(),
    ) else {
        return Some((index, None));
    };
    if low_hz >= high_hz {
        return Some((index, None));
    }
    // Group 2: <hb_interval>:<grant_expiry>
    let Some((hb_str, grant_exp_str)) = groups[1].split_once(':') else {
        return Some((index, None));
    };
    if hb_str.parse::<u64>().is_err() {
        return Some((index, None));
    }
    let Some(grant_expiry) = parse_utc_rfc3339(grant_exp_str) else {
        return Some((index, None));
    };
    // Group 3: <transmit_expiry>
    let Some(tx_expiry) = parse_utc_rfc3339(groups[2]) else {
        return Some((index, None));
    };
    Some((
        index,
        Some(Grant {
            index,
            span: Span { low_hz, high_hz },
            eirp,
            grant_expiry,
            tx_expiry,
        }),
    ))
}

/// True for a `cbrs_fsm` log entry header like
/// `2026-11-22 06:54:27 UTC (L1/P0/R1/G2)`.
fn is_timestamp_header(line: &str) -> bool {
    let b = line.as_bytes();
    b.len() >= 25
        && b[0..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit)
        && b[10] == b' '
        && b[11..13].iter().all(u8::is_ascii_digit)
        && b[13] == b':'
        && b[14..16].iter().all(u8::is_ascii_digit)
        && b[16] == b':'
        && b[17..19].iter().all(u8::is_ascii_digit)
        && &b[19..25] == b" UTC ("
}

/// Incremental parser for `/mnt/cbrslog0.txt`.
///
/// Every event block written by `cbrs_fsm` starts with a UTC timestamp header,
/// lists all current grant slots (`=0(...)`, optionally `=1(...)`), and ends
/// with an event line (`=(CBRS): ...` or a JSON error body). Buffering each
/// block until its first non-grant line prevents a half-written block from
/// flickering and ensures a dropped slot (e.g. moving from 2 grants to 1
/// contiguous 40 MHz grant, or deregistering) never leaves stale grants behind.
/// Bare `=<idx>(<n>):...` lines without timestamp headers also update slots
/// directly.
#[derive(Clone, Debug, Default)]
pub struct LogParser {
    slots: BTreeMap<u8, Grant>,
    pending_block: Option<BTreeMap<u8, Grant>>,
    seen_any: bool,
}

impl LogParser {
    pub fn push_line(&mut self, raw: &str) {
        let line = raw.trim();
        if line.is_empty() {
            return;
        }
        if is_timestamp_header(line) {
            if let Some(block) = self.pending_block.take() {
                self.slots = block;
            }
            self.pending_block = Some(BTreeMap::new());
            self.seen_any = true;
            return;
        }
        if let Some((index, maybe_grant)) = parse_grant_line(line) {
            self.seen_any = true;
            let target = self.pending_block.as_mut().unwrap_or(&mut self.slots);
            match maybe_grant {
                Some(grant) => {
                    target.insert(index, grant);
                }
                None => {
                    target.remove(&index);
                }
            }
            return;
        }
        if line.starts_with("=(CBRS):") {
            self.seen_any = true;
        }
        if let Some(block) = self.pending_block.take() {
            self.slots = block;
        }
    }

    /// Call when `/mnt/cbrslog0.txt` rotates or truncates. Discards any
    /// half-written block from the previous file while keeping the last known
    /// grants until the new file emits a complete entry.
    pub fn on_rotate(&mut self) {
        self.pending_block = None;
    }

    /// True once at least one recognized `cbrs_fsm` line has been parsed.
    pub fn seen(&self) -> bool {
        self.seen_any
    }

    /// Currently held authorized grants, excluding expired grants (when the
    /// wall clock is sane) and any dry-run hidden grant index.
    pub fn active_grants(&self, wall_now: u64, hide_grant: Option<u8>) -> Vec<Grant> {
        let check_expiry = clock_sane(wall_now);
        self.slots
            .values()
            .filter(|g| hide_grant != Some(g.index))
            .filter(|g| !check_expiry || g.tx_expiry > wall_now)
            .cloned()
            .collect()
    }
}

/// Operating policy from `/mnt/titan-api/carrier-watch/config`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    Off,
    #[default]
    Log,
    Regrant,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Log => "log",
            Mode::Regrant => "regrant",
        }
    }
}

/// Daily UTC quiet window (e.g. `06:45-10:00` for Google SAS CPAS).
/// `start_min` is inclusive, `end_min` is exclusive. When `start_min > end_min`
/// the window crosses midnight UTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuietWindow {
    pub start_min: u16,
    pub end_min: u16,
}

impl Default for QuietWindow {
    fn default() -> Self {
        Self {
            start_min: DEFAULT_QUIET_START_MIN,
            end_min: DEFAULT_QUIET_END_MIN,
        }
    }
}

impl QuietWindow {
    pub fn contains(self, wall_now: u64) -> bool {
        let min = ((wall_now % DAY_SECS) / 60) as u16;
        if self.start_min < self.end_min {
            min >= self.start_min && min < self.end_min
        } else {
            min >= self.start_min || min < self.end_min
        }
    }
}

impl fmt::Display for QuietWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02}:{:02}-{:02}:{:02}",
            self.start_min / 60,
            self.start_min % 60,
            self.end_min / 60,
            self.end_min % 60
        )
    }
}

fn parse_hhmm(text: &str, allow_24: bool) -> Option<u16> {
    let (h_str, m_str) = text.split_once(':')?;
    if h_str.len() != 2 || m_str.len() != 2 {
        return None;
    }
    let h: u16 = h_str.parse().ok()?;
    let m: u16 = m_str.parse().ok()?;
    if allow_24 && h == 24 && m == 0 {
        return Some(24 * 60);
    }
    if h > 23 || m > 59 {
        return None;
    }
    Some(h * 60 + m)
}

pub fn parse_quiet_window(text: &str) -> Option<QuietWindow> {
    let (start_s, end_s) = text.split_once('-')?;
    let start_min = parse_hhmm(start_s, false)?;
    let end_min = parse_hhmm(end_s, true)?;
    if start_min == end_min {
        return None;
    }
    Some(QuietWindow { start_min, end_min })
}

/// `/mnt/titan-api/carrier-watch/config`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub mode: Mode,
    pub quiet_utc: Option<QuietWindow>,
    pub debounce_secs: u64,
    /// Dry-run test option: hides one grant slot from the comparator and
    /// suppresses forced re-grants so the comparator can be verified live
    /// without dropping grants or transmitting on a new channel.
    pub hide_grant: Option<u8>,
    /// Lines ignored during parsing, as written.
    pub refused: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Log,
            quiet_utc: Some(QuietWindow::default()),
            debounce_secs: DEFAULT_DEBOUNCE_SECS,
            hide_grant: None,
            refused: Vec::new(),
        }
    }
}

/// Parse `/mnt/titan-api/carrier-watch/config`.
///
/// Keys:
/// - `mode=off|log|regrant` (default `log`; an invalid value resets to `log`).
/// - `quiet_utc=HH:MM-HH:MM` (default `06:45-10:00`; empty `quiet_utc=` disables).
/// - `debounce_secs=N` (1..=60, default 3).
/// - `hide_grant=N` (0..=7, or empty/`none`; dry-run test hook).
pub fn parse_config(text: &str) -> Config {
    let mut cfg = Config::default();
    for raw in text.lines() {
        let stripped = raw.split('#').next().unwrap_or("").trim();
        if stripped.is_empty() {
            continue;
        }
        let Some((key, value)) = stripped.split_once('=') else {
            cfg.refused.push(raw.trim().to_owned());
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        let ok = match key {
            "mode" => match value {
                "off" => {
                    cfg.mode = Mode::Off;
                    true
                }
                "log" => {
                    cfg.mode = Mode::Log;
                    true
                }
                "regrant" => {
                    cfg.mode = Mode::Regrant;
                    true
                }
                _ => {
                    cfg.mode = Mode::Log;
                    false
                }
            },
            "quiet_utc" => {
                if value.is_empty() {
                    cfg.quiet_utc = None;
                    true
                } else if let Some(win) = parse_quiet_window(value) {
                    cfg.quiet_utc = Some(win);
                    true
                } else {
                    false
                }
            }
            "debounce_secs" => match value.parse::<u64>() {
                Ok(n) if (MIN_DEBOUNCE_SECS..=MAX_DEBOUNCE_SECS).contains(&n) => {
                    cfg.debounce_secs = n;
                    true
                }
                _ => false,
            },
            "hide_grant" => {
                if value.is_empty() || value == "none" {
                    cfg.hide_grant = None;
                    true
                } else if let Ok(idx) = value.parse::<u8>() {
                    if idx <= 7 {
                        cfg.hide_grant = Some(idx);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => false,
        };
        if !ok {
            cfg.refused.push(raw.trim().to_owned());
        }
    }
    cfg
}

/// State machine phase.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum State {
    Off,
    #[default]
    Inactive,
    Waiting,
    Covered,
    Uncovered,
    RegrantPending {
        since: u64,
    },
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Off => "off",
            State::Inactive => "inactive",
            State::Waiting => "waiting",
            State::Covered => "covered",
            State::Uncovered => "uncovered",
            State::RegrantPending { .. } => "regrant-pending",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Action {
    #[default]
    None,
    ForceRegrant,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub action: Action,
    pub logs: Vec<String>,
}

/// Carrier-watch state machine. All `now` parameters are monotonic seconds;
/// `wall_now` is UTC Unix seconds.
#[derive(Clone, Debug, Default)]
pub struct Watch {
    next_tick: u64,
    state: State,
    uncovered_ticks: u64,
    recent_regrants: Vec<u64>,
    next_allowed_at: u64,
    consecutive_failures: u32,
    last_quiet_log: Option<u64>,
    last_block_reason: Option<String>,
    last_action: String,
    uncovered_events: u64,
    regrants_triggered: u64,
    regrants_succeeded: u64,
    regrants_failed: u64,
    // Last snapshot for status reporting.
    last_pcell: Option<Span>,
    last_ulscc: Option<Span>,
    last_grants: Vec<(u8, Span)>,
    last_mode_grant: Option<bool>,
}

fn format_grants(grants: &[(u8, Span)]) -> String {
    if grants.is_empty() {
        return "none".to_owned();
    }
    grants
        .iter()
        .map(|(i, s)| format!("{i}:{s}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_span(span: Option<Span>) -> String {
    span.map_or_else(|| "none".to_owned(), |s| s.to_string())
}

fn missing_carriers(pcell: Option<Span>, ulscc: Option<Span>, grants: &[Grant]) -> Vec<String> {
    let covered = |span: Span| grants.iter().any(|g| span.inside(g.span));
    let mut missing = Vec::new();
    if let Some(p) = pcell {
        if !covered(p) {
            missing.push(format!("pcell={p}"));
        }
    }
    if let Some(u) = ulscc {
        if !covered(u) {
            missing.push(format!("ulscc={u}"));
        }
    }
    missing
}

fn backoff_for_failures(consecutive_failures: u32) -> u64 {
    let shift = consecutive_failures.min(4);
    (MIN_REGRANT_INTERVAL_SECS << shift).min(MAX_BACKOFF_SECS)
}

impl Watch {
    pub fn due(&self, now: u64) -> bool {
        now >= self.next_tick
    }

    pub fn state(&self) -> State {
        self.state
    }

    fn prune_day(&mut self, now: u64) {
        self.recent_regrants
            .retain(|ts| now.saturating_sub(*ts) < DAY_SECS);
    }

    /// Advance the state machine by one tick.
    pub fn observe(
        &mut self,
        now: u64,
        wall_now: u64,
        config: &Config,
        nvram: &NvramView,
        log_seen: bool,
        grants: &[Grant],
    ) -> Outcome {
        self.next_tick = now + INTERVAL;
        self.prune_day(now);
        self.last_pcell = nvram.pcell;
        self.last_ulscc = nvram.ulscc;
        self.last_grants = grants.iter().map(|g| (g.index, g.span)).collect();
        self.last_mode_grant = nvram.cbrs_mode_grant;

        let mut out = Outcome::default();

        if config.mode == Mode::Off {
            self.state = State::Off;
            self.uncovered_ticks = 0;
            self.last_quiet_log = None;
            self.last_block_reason = None;
            return out;
        }

        // A unit with no SAS/CBRS mode at all (or no Band 48 carriers or no
        // cbrslog yet) stays inactive and logs nothing.
        let has_carrier = nvram.pcell.is_some() || nvram.ulscc.is_some();
        if !nvram.cbrs_present || !has_carrier || !log_seen {
            if let State::RegrantPending { since } = self.state {
                // Keep waiting for a pending re-grant if carriers temporarily
                // vanish mid-reattach, until timeout.
                if now.saturating_sub(since) >= REGRANT_TIMEOUT_SECS {
                    self.record_timeout(now, &mut out, "carriers absent");
                    self.state = State::Inactive;
                }
                return out;
            }
            self.state = State::Inactive;
            self.uncovered_ticks = 0;
            self.last_quiet_log = None;
            self.last_block_reason = None;
            return out;
        }

        // Vendor is currently re-granting (`cbrs_mode_grant=0`).
        if nvram.cbrs_mode_grant != Some(true) {
            if let State::RegrantPending { since } = self.state {
                if now.saturating_sub(since) >= REGRANT_TIMEOUT_SECS {
                    self.record_timeout(now, &mut out, "cbrs_mode_grant=0");
                    self.state = State::Waiting;
                }
                return out;
            }
            self.state = State::Waiting;
            self.uncovered_ticks = 0;
            self.last_quiet_log = None;
            self.last_block_reason = None;
            return out;
        }

        // `cbrs_mode_grant == 1` and at least one Band 48 transmit carrier.
        let missing = missing_carriers(nvram.pcell, nvram.ulscc, grants);
        if missing.is_empty() {
            self.uncovered_ticks = 0;
            self.last_quiet_log = None;
            self.last_block_reason = None;
            match self.state {
                State::RegrantPending { since } => {
                    let took = now.saturating_sub(since);
                    self.regrants_succeeded += 1;
                    self.consecutive_failures = 0;
                    self.state = State::Covered;
                    let msg = format!(
                        "carrier watch: re-grant succeeded in {took}s (pcell={}, ulscc={}, grants={})",
                        format_span(nvram.pcell),
                        format_span(nvram.ulscc),
                        format_grants(&self.last_grants)
                    );
                    self.last_action = format!("re-grant succeeded in {took}s");
                    out.logs.push(msg);
                }
                State::Uncovered => {
                    self.state = State::Covered;
                    let msg = format!(
                        "carrier watch: covered again (pcell={}, ulscc={}, grants={})",
                        format_span(nvram.pcell),
                        format_span(nvram.ulscc),
                        format_grants(&self.last_grants)
                    );
                    self.last_action = "covered again".to_owned();
                    out.logs.push(msg);
                }
                _ => {
                    self.state = State::Covered;
                }
            }
            return out;
        }

        // At least one transmit carrier is outside held authorized grants.
        let missing_desc = missing.join(" ");
        if let State::RegrantPending { since } = self.state {
            if now.saturating_sub(since) >= REGRANT_TIMEOUT_SECS {
                self.record_timeout(now, &mut out, &missing_desc);
                self.state = State::Uncovered;
                self.uncovered_ticks = config.debounce_secs;
            }
            return out;
        }

        self.uncovered_ticks = self.uncovered_ticks.saturating_add(1);
        if self.uncovered_ticks < config.debounce_secs {
            return out;
        }

        let entered_uncovered = self.state != State::Uncovered;
        let dry = config
            .hide_grant
            .map_or_else(String::new, |idx| format!(" dry-run hide_grant={idx}"));
        let transition_prefix = format!(
            "{missing_desc}; grants={}; mode={}{dry}",
            format_grants(&self.last_grants),
            config.mode.as_str()
        );
        if entered_uncovered {
            self.state = State::Uncovered;
            self.uncovered_events += 1;
            self.last_quiet_log = None;
            self.last_block_reason = None;
            self.last_action = format!("uncovered ({missing_desc})");
        }

        if config.mode != Mode::Regrant {
            if entered_uncovered {
                out.logs
                    .push(format!("carrier watch: uncovered ({transition_prefix})"));
            }
            return out;
        }

        // Dry-run hide_grant never forces a re-grant.
        if let Some(idx) = config.hide_grant {
            self.log_uncovered_block(
                &mut out,
                entered_uncovered,
                &transition_prefix,
                "dry-run",
                &format!("dry-run hide_grant={idx}, not forcing re-grant"),
            );
            return out;
        }

        // Wall clock must be sane before trusting transmit expiry or UTC quiet window.
        if !clock_sane(wall_now) {
            self.log_uncovered_block(
                &mut out,
                entered_uncovered,
                &transition_prefix,
                "clock",
                "clock not sane, waiting",
            );
            return out;
        }

        // CPAS quiet window.
        if config.quiet_utc.is_some_and(|w| w.contains(wall_now)) {
            if entered_uncovered {
                self.last_quiet_log = Some(now);
                self.last_action = "quiet window, waiting".to_owned();
                out.logs.push(format!(
                    "carrier watch: uncovered ({transition_prefix}; quiet window, waiting)"
                ));
            } else if self
                .last_quiet_log
                .is_none_or(|at| now.saturating_sub(at) >= QUIET_LOG_EVERY_SECS)
            {
                self.last_quiet_log = Some(now);
                self.last_action = "quiet window, waiting".to_owned();
                out.logs
                    .push("carrier watch: uncovered, quiet window, waiting".to_owned());
            }
            return out;
        }
        self.last_quiet_log = None;

        // Per-day rate limit.
        if self.recent_regrants.len() >= MAX_REGRANTS_PER_DAY {
            self.log_uncovered_block(
                &mut out,
                entered_uncovered,
                &transition_prefix,
                "daily-limit",
                &format!(
                    "daily re-grant limit reached ({}/{MAX_REGRANTS_PER_DAY}), waiting",
                    self.recent_regrants.len()
                ),
            );
            return out;
        }

        // Cooldown / failure backoff.
        if now < self.next_allowed_at {
            let wait = self.next_allowed_at - now;
            self.log_uncovered_block(
                &mut out,
                entered_uncovered,
                &transition_prefix,
                "cooldown",
                &format!("rate-limited, next re-grant in {wait}s"),
            );
            return out;
        }

        // Wait until `rcinit` is idle (`rc_signal_done=1`).
        if !nvram.rc_signal_done {
            self.log_uncovered_block(
                &mut out,
                entered_uncovered,
                &transition_prefix,
                "rc-busy",
                "waiting for rc_signal_done=1",
            );
            return out;
        }

        // All guards passed: trigger the vendor re-grant sequence.
        if entered_uncovered {
            out.logs
                .push(format!("carrier watch: uncovered ({transition_prefix})"));
        }
        self.state = State::RegrantPending { since: now };
        self.regrants_triggered += 1;
        self.recent_regrants.push(now);
        self.next_allowed_at = now + MIN_REGRANT_INTERVAL_SECS;
        self.last_block_reason = None;
        let today = self.recent_regrants.len();
        self.last_action = format!("forcing re-grant ({missing_desc})");
        out.logs.push(format!(
            "carrier watch: forcing re-grant ({missing_desc}; rc_signal_done=1; today={today}/{MAX_REGRANTS_PER_DAY})"
        ));
        out.action = Action::ForceRegrant;
        out
    }

    fn record_timeout(&mut self, now: u64, out: &mut Outcome, detail: &str) {
        let took = match self.state {
            State::RegrantPending { since } => now.saturating_sub(since),
            _ => REGRANT_TIMEOUT_SECS,
        };
        self.regrants_failed += 1;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let backoff = backoff_for_failures(self.consecutive_failures);
        self.next_allowed_at = now + backoff;
        self.last_block_reason = None;
        self.last_action = format!("re-grant timed out after {took}s");
        out.logs.push(format!(
            "carrier watch: re-grant timed out after {took}s ({detail}; backoff {backoff}s)"
        ));
    }

    /// Record a local failure to dispatch `nvram_set` or `SIGUSR1` to `rcinit`.
    pub fn regrant_dispatch_failed(&mut self, now: u64, err: &str) -> String {
        self.regrants_failed += 1;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let backoff = backoff_for_failures(self.consecutive_failures);
        self.next_allowed_at = now + backoff;
        self.state = State::Uncovered;
        self.last_block_reason = None;
        self.last_action = format!("re-grant trigger failed ({err})");
        format!("carrier watch: re-grant trigger failed ({err}); backoff {backoff}s")
    }

    fn log_uncovered_block(
        &mut self,
        out: &mut Outcome,
        entered_uncovered: bool,
        transition_prefix: &str,
        key: &str,
        detail: &str,
    ) {
        if entered_uncovered {
            self.last_block_reason = Some(key.to_owned());
            self.last_action = format!("uncovered, {detail}");
            out.logs.push(format!(
                "carrier watch: uncovered ({transition_prefix}; {detail})"
            ));
        } else if self.last_block_reason.as_deref() != Some(key) {
            self.last_block_reason = Some(key.to_owned());
            self.last_action = format!("uncovered, {detail}");
            out.logs.push(format!("carrier watch: uncovered, {detail}"));
        }
    }

    /// Stable status body (without `updated=`) for change detection.
    pub fn status_body(&self, config: &Config) -> String {
        let quiet = config
            .quiet_utc
            .map_or_else(|| "off".to_owned(), |w| w.to_string());
        let mg = match self.last_mode_grant {
            Some(true) => "1",
            Some(false) => "0",
            None => "unset",
        };
        let hide = config
            .hide_grant
            .map_or_else(|| "none".to_owned(), |idx| idx.to_string());
        let last = if self.last_action.is_empty() {
            "none"
        } else {
            &self.last_action
        };
        format!(
            "state={}\nmode={}\nquiet_utc={quiet}\ncbrs_mode_grant={mg}\npcell={}\nulscc={}\ngrants={}\nhide_grant={hide}\nlast_action={last}\nuncovered_events={}\nregrants_triggered={}\nregrants_succeeded={}\nregrants_failed={}\nregrants_today={}\n",
            self.state.as_str(),
            config.mode.as_str(),
            format_span(self.last_pcell),
            format_span(self.last_ulscc),
            format_grants(&self.last_grants),
            self.uncovered_events,
            self.regrants_triggered,
            self.regrants_succeeded,
            self.regrants_failed,
            self.recent_regrants.len(),
        )
    }

    /// Full text for `/var/run/witcher-carrier.status`.
    pub fn status_text(&self, config: &Config, now: u64) -> String {
        format!("{}updated={now}\n", self.status_body(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WALL_OK: u64 = 1_795_320_000; // 2026-11-22T04:00:00Z (outside quiet window)

    fn utc(s: &str) -> u64 {
        parse_utc_rfc3339(s).expect("valid utc")
    }

    fn nvram_bytes(lines: &[&str]) -> Vec<u8> {
        let mut buf = Vec::new();
        for line in lines {
            buf.extend_from_slice(line.as_bytes());
            buf.push(0);
        }
        buf
    }

    fn make_grant(index: u8, lo_mhz: u64, hi_mhz: u64, tx_expiry: u64) -> Grant {
        Grant {
            index,
            span: Span::mhz(lo_mhz, hi_mhz),
            eirp: 27,
            grant_expiry: tx_expiry + 86_400,
            tx_expiry,
        }
    }

    #[test]
    fn band48_frequency_math_and_5mhz_rounding() {
        // Real bench EARFCNs: c9=56638 (3689.8 -> 3680-3700), c5=55440 (3560-3580),
        // c6=56440 (3660-3680), c12=56040 (3620-3640), plus 55840 (3600-3620).
        assert_eq!(span_from_earfcn(56638, 20_000), Some(Span::mhz(3680, 3700)));
        assert_eq!(span_from_earfcn(55440, 20_000), Some(Span::mhz(3560, 3580)));
        assert_eq!(span_from_earfcn(56440, 20_000), Some(Span::mhz(3660, 3680)));
        assert_eq!(span_from_earfcn(56040, 20_000), Some(Span::mhz(3620, 3640)));
        assert_eq!(span_from_earfcn(55840, 20_000), Some(Span::mhz(3600, 3620)));
        // 100 kHz frequency form (sqns_radio_freqDl=36898, cbrs_radio_freqUl=35700).
        assert_eq!(
            span_from_freq_100khz(36898, 20_000),
            Some(Span::mhz(3680, 3700))
        );
        assert_eq!(
            span_from_freq_100khz(35700, 20_000),
            Some(Span::mhz(3560, 3580))
        );
        // 10 MHz and 15 MHz channels.
        assert_eq!(span_from_earfcn(55290, 10_000), Some(Span::mhz(3550, 3560)));
        assert_eq!(span_from_khz(3_557_500, 15_000), Some(Span::mhz(3550, 3565)));
        // Non-Band 48 EARFCN or frequency is ignored.
        assert_eq!(span_from_earfcn(55239, 20_000), None);
        assert_eq!(span_from_earfcn(56740, 20_000), None);
        assert_eq!(span_from_freq_100khz(21200, 20_000), None);
        assert_eq!(span_from_earfcn(55440, 0), None);
    }

    #[test]
    fn nvram_carrier_parsing_covers_real_and_empty_shapes() {
        // Exact 04:21 UTC incident snapshot from the bench.
        let raw = nvram_bytes(&[
            "sqns_radio_band=48",
            "sqns_radio_earfcnDl=56638",
            "sqns_radio_freqDl=36898",
            "sqns_radio_bandwidthDl=20000",
            "sqns_connection_uplinkScc=freq,pusch,prach,pucch,bw:55440,-55,-55,-55,20",
            "cbrs_mode_grant=1",
            "cbrs_grant_state=2",
            "rc_signal_done=1",
        ]);
        let view = read_nvram(&raw);
        assert!(view.cbrs_present);
        assert_eq!(view.cbrs_mode_grant, Some(true));
        assert_eq!(view.cbrs_grant_state, Some(2));
        assert!(view.rc_signal_done);
        assert_eq!(view.pcell, Some(Span::mhz(3680, 3700)));
        assert_eq!(view.ulscc, Some(Span::mhz(3560, 3580)));

        // Empty / `-` uplinkScc with cbrs_radio_freqUl=0 -> no UL SCell.
        for empty in ["", "-", "none"] {
            let raw = nvram_bytes(&[
                "sqns_radio_earfcnDl=56638",
                &format!("sqns_connection_uplinkScc={empty}"),
                "cbrs_radio_freqUl=0",
                "cbrs_mode_grant=1",
            ]);
            let view = read_nvram(&raw);
            assert_eq!(view.pcell, Some(Span::mhz(3680, 3700)));
            assert_eq!(view.ulscc, None, "empty={empty}");
        }

        // Fallback to sqns_radio_freqDl and cbrs_radio_freqUl/bandwidthUl.
        let raw = nvram_bytes(&[
            "sqns_radio_freqDl=36898",
            "sqns_radio_bandwidthDl=20000",
            "cbrs_radio_freqUl=35700",
            "cbrs_radio_bandwidthUl=20000",
            "cbrs_mode_grant=1",
        ]);
        let view = read_nvram(&raw);
        assert_eq!(view.pcell, Some(Span::mhz(3680, 3700)));
        assert_eq!(view.ulscc, Some(Span::mhz(3560, 3580)));

        // Non-CBRS band or missing cbrs_mode_grant -> not present.
        let raw = nvram_bytes(&["sqns_radio_band=4", "cbrs_mode_grant=1"]);
        assert!(!read_nvram(&raw).cbrs_present);
        let raw = nvram_bytes(&["sqns_radio_earfcnDl=56638"]);
        assert!(!read_nvram(&raw).cbrs_present);
    }

    #[test]
    fn utc_rfc3339_parsing() {
        assert_eq!(parse_utc_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_utc_rfc3339("2024-01-01T00:00:00Z"), Some(SANE_EPOCH));
        assert_eq!(
            parse_utc_rfc3339("2026-11-22T12:54:24Z"),
            Some(1_795_352_064)
        );
        // Leap day 2024 valid, 2025 invalid.
        assert!(parse_utc_rfc3339("2024-02-29T00:00:00Z").is_some());
        assert_eq!(parse_utc_rfc3339("2025-02-29T00:00:00Z"), None);
        assert_eq!(parse_utc_rfc3339("not-a-timestamp"), None);
    }

    #[test]
    fn log_parser_handles_real_lines_blocks_rotation_and_expiry() {
        let mut p = LogParser::default();
        assert!(!p.seen());
        // Partial leading fragment from a cut log is ignored.
        p.push_line("esponseCode = 0)");
        assert!(!p.seen());

        // Real 2-grant authorized block.
        let sample = "\
2026-11-22 06:54:27 UTC (L1/P0/R1/G2)
=0(1):(3620000000-3640000000:27)(1800:2027-11-22T06:54:22Z)(2026-11-22T12:54:24Z)
=1(1):(3680000000-3700000000:27)(1800:2027-11-22T06:54:26Z)(2026-11-22T12:54:28Z)
=(CBRS): Heartbeat1 Success!(responseCode = 0)
";
        for line in sample.lines() {
            p.push_line(line);
        }
        assert!(p.seen());
        let t_ok = utc("2026-11-22T07:00:00Z");
        let grants = p.active_grants(t_ok, None);
        assert_eq!(grants.len(), 2);
        assert_eq!(grants[0].span, Span::mhz(3620, 3640));
        assert_eq!(grants[1].span, Span::mhz(3680, 3700));

        // Dry-run hide_grant=1 hides slot 1 only.
        let hidden = p.active_grants(t_ok, Some(1));
        assert_eq!(hidden.len(), 1);
        assert_eq!(hidden[0].index, 0);

        // Expired grant: transmit expiry in the past is treated as not held.
        let t_mid = utc("2026-11-22T12:54:25Z");
        let grants = p.active_grants(t_mid, None);
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].index, 1);

        let t_after = utc("2026-11-22T12:54:28Z");
        assert!(p.active_grants(t_after, None).is_empty());

        // Half-written block does not drop currently held grants.
        p.push_line("2026-11-22 06:55:00 UTC (L1/P0/R1/G2)");
        p.push_line("=0(1):(3560000000-3580000000:27)(1800:2027-11-22T06:54:22Z)(2026-11-22T12:55:00Z)");
        assert_eq!(p.active_grants(t_ok, None).len(), 2);

        // Rotation discards the half-written block and keeps last committed grants.
        p.on_rotate();
        assert_eq!(p.active_grants(t_ok, None).len(), 2);

        // Transition to a single 40 MHz contiguous grant drops stale slot 1.
        for line in [
            "2026-11-22 06:56:00 UTC (L1/P0/R1/G2)",
            "=0(1):(3660000000-3700000000:27)(1800:2027-11-22T06:56:00Z)(2026-11-22T12:56:00Z)",
            "=(CBRS): Open Radio Traffic Channel.",
        ] {
            p.push_line(line);
        }
        let grants = p.active_grants(t_ok, None);
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].span, Span::mhz(3660, 3700));

        // Fewer than 3 groups (relinquished / granted-only) is not authorized.
        for line in [
            "2026-11-22 06:57:00 UTC (L1/P0/R1/G1)",
            "=0(1):(3660000000-3700000000:27)(1800:2027-11-22T06:56:00Z)",
            "=1(1):(3560000000-3580000000:27)",
            "=(CBRS): Grant0 Success!(responseCode = 0)",
        ] {
            p.push_line(line);
        }
        assert!(p.active_grants(t_ok, None).is_empty());

        // Truncated 3rd group (no closing paren) is not authorized.
        assert_eq!(
            parse_grant_line(
                "=0(1):(3560000000-3580000000:27)(1800:2027-11-22T06:56:00Z)(2026-11-22T12:56"
            ),
            Some((0, None))
        );
    }

    #[test]
    fn config_parsing_and_quiet_window_across_midnight() {
        // Default with empty file: log mode, 06:45-10:00 UTC quiet window.
        let def = parse_config("");
        assert_eq!(def.mode, Mode::Log);
        assert_eq!(
            def.quiet_utc,
            Some(QuietWindow {
                start_min: 6 * 60 + 45,
                end_min: 10 * 60
            })
        );
        assert_eq!(def.debounce_secs, 3);
        assert_eq!(def.hide_grant, None);
        assert!(def.refused.is_empty());

        // Empty quiet_utc disables the quiet window.
        let cfg = parse_config("# bench test\nmode=regrant\nquiet_utc=\ndebounce_secs=5\n");
        assert_eq!(cfg.mode, Mode::Regrant);
        assert_eq!(cfg.quiet_utc, None);
        assert_eq!(cfg.debounce_secs, 5);
        assert!(cfg.refused.is_empty());

        // Invalid mode falls back to log, never regrant.
        let cfg = parse_config("mode=regrant\nmode=bogus\nhide_grant=1\nunknown=1\n");
        assert_eq!(cfg.mode, Mode::Log);
        assert_eq!(cfg.hide_grant, Some(1));
        assert_eq!(cfg.refused, vec!["mode=bogus", "unknown=1"]);

        // Default quiet window boundaries (06:45-10:00 UTC).
        let w = QuietWindow::default();
        assert!(!w.contains(utc("2026-11-22T06:44:59Z")));
        assert!(w.contains(utc("2026-11-22T06:45:00Z")));
        assert!(w.contains(utc("2026-11-22T09:59:59Z")));
        assert!(!w.contains(utc("2026-11-22T10:00:00Z")));

        // Quiet window crossing midnight (23:30-01:15 UTC).
        let night = parse_quiet_window("23:30-01:15").unwrap();
        assert!(!night.contains(utc("2026-11-22T23:29:59Z")));
        assert!(night.contains(utc("2026-11-22T23:30:00Z")));
        assert!(night.contains(utc("2026-11-23T00:00:00Z")));
        assert!(night.contains(utc("2026-11-23T01:14:59Z")));
        assert!(!night.contains(utc("2026-11-23T01:15:00Z")));
        assert_eq!(parse_quiet_window("08:00-08:00"), None);
    }

    #[test]
    fn debounce_and_cbrs_mode_grant_zero_suppression() {
        let mut w = Watch::default();
        let cfg = Config {
            mode: Mode::Regrant,
            quiet_utc: None,
            ..Config::default()
        };
        let nvram = NvramView {
            cbrs_present: true,
            cbrs_mode_grant: Some(true),
            cbrs_grant_state: Some(2),
            rc_signal_done: true,
            pcell: Some(Span::mhz(3680, 3700)),
            ulscc: Some(Span::mhz(3560, 3580)),
        };
        let grants = vec![
            make_grant(0, 3620, 3640, WALL_OK + 3600),
            make_grant(1, 3680, 3700, WALL_OK + 3600),
        ];

        // 2 uncovered ticks are below the 3 s debounce: no transition, no action.
        assert_eq!(w.observe(10, WALL_OK, &cfg, &nvram, true, &grants).action, Action::None);
        assert_eq!(w.observe(11, WALL_OK, &cfg, &nvram, true, &grants).action, Action::None);
        assert_ne!(w.state(), State::Uncovered);

        // cbrs_mode_grant=0 resets debounce and suppresses action.
        let mut vendor_regrant = nvram.clone();
        vendor_regrant.cbrs_mode_grant = Some(false);
        let out = w.observe(12, WALL_OK, &cfg, &vendor_regrant, true, &grants);
        assert_eq!(out.action, Action::None);
        assert!(out.logs.is_empty());
        assert_eq!(w.state(), State::Waiting);

        // Back to cbrs_mode_grant=1 needs 3 fresh ticks before acting.
        assert_eq!(w.observe(13, WALL_OK, &cfg, &nvram, true, &grants).action, Action::None);
        assert_eq!(w.observe(14, WALL_OK, &cfg, &nvram, true, &grants).action, Action::None);
        let out = w.observe(15, WALL_OK, &cfg, &nvram, true, &grants);
        assert_eq!(out.action, Action::ForceRegrant);
        assert_eq!(w.state(), State::RegrantPending { since: 15 });
        assert!(out.logs.iter().all(|l| l.starts_with("carrier watch")));

        // While re-granting, cbrs_mode_grant drops to 0 and returns to 1 with new grants.
        let out = w.observe(20, WALL_OK + 5, &cfg, &vendor_regrant, true, &[]);
        assert_eq!(out.action, Action::None);
        assert_eq!(w.state(), State::RegrantPending { since: 15 });

        let fixed_grants = vec![
            make_grant(0, 3560, 3580, WALL_OK + 3600),
            make_grant(1, 3680, 3700, WALL_OK + 3600),
        ];
        let out = w.observe(66, WALL_OK + 51, &cfg, &nvram, true, &fixed_grants);
        assert_eq!(out.action, Action::None);
        assert_eq!(w.state(), State::Covered);
        assert!(out.logs[0].contains("re-grant succeeded in 51s"), "{:?}", out.logs);
    }

    #[test]
    fn quiet_window_blocks_regrant_and_logs_every_10_minutes() {
        let mut w = Watch::default();
        let cfg = Config {
            mode: Mode::Regrant,
            ..Config::default()
        };
        let nvram = NvramView {
            cbrs_present: true,
            cbrs_mode_grant: Some(true),
            cbrs_grant_state: Some(2),
            rc_signal_done: true,
            pcell: Some(Span::mhz(3680, 3700)),
            ulscc: Some(Span::mhz(3560, 3580)),
        };
        let grants = vec![make_grant(0, 3680, 3700, utc("2026-11-22T15:00:00Z"))];
        let t_quiet = utc("2026-11-22T07:00:00Z");

        w.observe(1, t_quiet, &cfg, &nvram, true, &grants);
        w.observe(2, t_quiet + 1, &cfg, &nvram, true, &grants);
        let out = w.observe(3, t_quiet + 2, &cfg, &nvram, true, &grants);
        assert_eq!(out.action, Action::None);
        assert_eq!(out.logs.len(), 1, "transition must log once: {:?}", out.logs);
        assert!(
            out.logs[0].starts_with("carrier watch: uncovered (")
                && out.logs[0].contains("quiet window, waiting"),
            "{:?}",
            out.logs
        );

        // 9 minutes later: silent.
        let out = w.observe(3 + 540, t_quiet + 542, &cfg, &nvram, true, &grants);
        assert_eq!(out.action, Action::None);
        assert!(out.logs.is_empty());

        // 10 minutes later: one reminder.
        let out = w.observe(3 + 600, t_quiet + 602, &cfg, &nvram, true, &grants);
        assert_eq!(out.action, Action::None);
        assert_eq!(
            out.logs,
            vec!["carrier watch: uncovered, quiet window, waiting"]
        );

        // At 10:00:00 UTC (window end): fires immediately.
        let t_end = utc("2026-11-22T10:00:00Z");
        let out = w.observe(3 + 10_800, t_end, &cfg, &nvram, true, &grants);
        assert_eq!(out.action, Action::ForceRegrant);
    }

    #[test]
    fn rate_limits_backoff_clock_sanity_and_rc_signal_done() {
        let mut w = Watch::default();
        let cfg = Config {
            mode: Mode::Regrant,
            quiet_utc: None,
            debounce_secs: 1,
            hide_grant: None,
            refused: vec![],
        };
        let mut nvram = NvramView {
            cbrs_present: true,
            cbrs_mode_grant: Some(true),
            cbrs_grant_state: Some(2),
            rc_signal_done: false,
            pcell: Some(Span::mhz(3680, 3700)),
            ulscc: Some(Span::mhz(3560, 3580)),
        };
        let bad = vec![make_grant(0, 3680, 3700, WALL_OK + 100_000)];
        let good = vec![
            make_grant(0, 3560, 3580, WALL_OK + 100_000),
            make_grant(1, 3680, 3700, WALL_OK + 100_000),
        ];

        // Unsane 2013 clock blocks re-grant (logged once on transition).
        let out = w.observe(10, 1_371_700_000, &cfg, &nvram, true, &bad);
        assert_eq!(out.action, Action::None);
        assert_eq!(out.logs.len(), 1, "{:?}", out.logs);
        assert!(out.logs[0].contains("clock not sane"), "{:?}", out.logs);

        // Sane clock, but rc_signal_done=0: waits until it reads 1.
        let out = w.observe(11, WALL_OK, &cfg, &nvram, true, &bad);
        assert_eq!(out.action, Action::None);
        assert_eq!(out.logs.len(), 1, "{:?}", out.logs);
        assert!(out.logs[0].contains("rc_signal_done=1"), "{:?}", out.logs);

        nvram.rc_signal_done = true;
        let out = w.observe(12, WALL_OK + 1, &cfg, &nvram, true, &bad);
        assert_eq!(out.action, Action::ForceRegrant);

        // Timeout after 180 s triggers 10-minute backoff (600 s).
        assert_eq!(
            w.observe(12 + 179, WALL_OK + 180, &cfg, &nvram, true, &bad).action,
            Action::None
        );
        let out = w.observe(12 + 180, WALL_OK + 181, &cfg, &nvram, true, &bad);
        assert_eq!(out.action, Action::None);
        assert!(out.logs[0].contains("timed out after 180s"), "{:?}", out.logs);
        // Inside 600 s backoff: blocked.
        let out = w.observe(12 + 180 + 599, WALL_OK + 780, &cfg, &nvram, true, &bad);
        assert_eq!(out.action, Action::None);
        // At +600 s: allowed again.
        let out = w.observe(12 + 180 + 600, WALL_OK + 781, &cfg, &nvram, true, &bad);
        assert_eq!(out.action, Action::ForceRegrant);

        // Recover, then exhaust the 6-per-day limit (we already used 2).
        let mut t = 12 + 180 + 600 + 20;
        w.observe(t, WALL_OK + 1000, &cfg, &nvram, true, &good);
        for _ in 0..4 {
            t += MIN_REGRANT_INTERVAL_SECS;
            let out = w.observe(t, WALL_OK + 1000 + t, &cfg, &nvram, true, &bad);
            assert_eq!(out.action, Action::ForceRegrant);
            t += 10;
            w.observe(t, WALL_OK + 1000 + t, &cfg, &nvram, true, &good);
        }
        // 7th attempt within 24 h is blocked.
        t += MIN_REGRANT_INTERVAL_SECS;
        let out = w.observe(t, WALL_OK + 1000 + t, &cfg, &nvram, true, &bad);
        assert_eq!(out.action, Action::None);
        assert!(out.logs.iter().any(|l| l.contains("daily re-grant limit")));

        // Once the oldest re-grant is 24 h old, one slot opens up.
        t = 12 + DAY_SECS;
        let out = w.observe(t, WALL_OK + 1000 + t, &cfg, &nvram, true, &bad);
        assert_eq!(out.action, Action::ForceRegrant);
    }

    #[test]
    fn non_cbrs_unit_and_dry_run_hide_grant_behave_safely() {
        let mut w = Watch::default();
        let cfg = Config::default();
        // Unit without CBRS mode logs nothing.
        let out = w.observe(1, WALL_OK, &cfg, &NvramView::default(), false, &[]);
        assert_eq!(out.action, Action::None);
        assert!(out.logs.is_empty());
        assert_eq!(w.state(), State::Inactive);

        // Dry-run hide_grant never forces a re-grant even with mode=regrant.
        let dry_cfg = parse_config("mode=regrant\nquiet_utc=\ndebounce_secs=1\nhide_grant=1\n");
        let nvram = NvramView {
            cbrs_present: true,
            cbrs_mode_grant: Some(true),
            cbrs_grant_state: Some(2),
            rc_signal_done: true,
            pcell: Some(Span::mhz(3680, 3700)),
            ulscc: Some(Span::mhz(3560, 3580)),
        };
        let grants = vec![make_grant(0, 3680, 3700, WALL_OK + 3600)];
        let out = w.observe(10, WALL_OK, &dry_cfg, &nvram, true, &grants);
        assert_eq!(out.action, Action::None);
        assert_eq!(w.state(), State::Uncovered);
        assert_eq!(out.logs.len(), 1, "transition must log once: {:?}", out.logs);
        assert!(
            out.logs[0].contains("dry-run hide_grant=1")
                && out.logs[0].contains("not forcing re-grant"),
            "{:?}",
            out.logs
        );
        // Next tick while still uncovered and dry-run: silent.
        let out2 = w.observe(11, WALL_OK + 1, &dry_cfg, &nvram, true, &grants);
        assert!(out2.logs.is_empty(), "{:?}", out2.logs);
    }
}
