//! Picking the carrier combination: which primary cell, and how many carriers.
//!
//! Bench, 2026-11-24 (one unit, one Nokia sector, four 20 MHz band 48 carriers):
//! the same unit measured 126.78/7.78 Mbps with c6 as primary and three
//! carriers, and 132.94/6.52 Mbps with 16 ms ping on c5 with two. Earlier the
//! same pair reached 14 to 15 Mbps up when the unit sat 5 dB closer in path
//! loss. Which combination wins depends on the unit's aim, the other users of
//! each carrier and the time of day, so the picker measures instead of
//! guessing from signal readings.
//!
//! A survey visits every combination ("arm") the operator lists. Each visit is
//! one radio cycle through the existing nudge: radio off, carrier cap, PCell
//! lock, radio on, attach, lock cleared at once. The tower still picks the
//! secondary carriers. Then the picker waits for SAS grants that cover the new
//! primary and uplink secondary carrier, and measures:
//!
//! - download: the probe server sends a UDP burst above any carrier rate to the
//!   management bearer, and the keeper reads the bearer's receive counter. No
//!   payload reaches user space, so the single-core CPU does not cap the
//!   result (a TCP download through `wget` read 53 Mbps where the burst read
//!   133 to 145 Mbps on the same bearer).
//! - upload: the keeper sends a paced UDP burst and the server counts what
//!   arrives.
//! - idle round trip: five pings over the management bearer.
//!
//! The best arm by `download + ul_weight x upload` is held; the arm the unit
//! is on keeps its place unless another beats it by `SWITCH_MARGIN_PCT`.
//!
//! Guards: no radio cycle in the SAS coordination window (CPAS, 07:00 to 10:00
//! UTC, with 30 minutes either side), none outside the operator's survey
//! window, none while the SAS grant is not held, none while the customer moves
//! traffic, at most one survey per `survey_hours` (24 or more), and a held arm
//! that the unit left is re-applied at most once per `HOLD_SPACING`.

use crate::radio::Cell;
use serde::{Deserialize, Serialize};
use std::net::SocketAddrV4;

/// One combination the operator lets the picker try: a primary cell held by a
/// nudge during the attach, and a carrier cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Arm {
    pub earfcn: u32,
    pub pci: u16,
    pub carriers: u8,
}

impl Arm {
    pub fn cell(&self) -> Cell {
        Cell {
            earfcn: self.earfcn,
            pci: self.pci,
        }
    }
}

pub const MIN_ARMS: usize = 2;
pub const MAX_ARMS: usize = 6;
pub const DEFAULT_SURVEY_HOURS: u16 = 72;
pub const MIN_SURVEY_HOURS: u16 = 24;
pub const MAX_SURVEY_HOURS: u16 = 336;
pub const DEFAULT_UL_WEIGHT: u8 = 4;
pub const MAX_UL_WEIGHT: u8 = 20;
/// Default survey window, UTC minutes: early morning in the US after CPAS.
pub const DEFAULT_WINDOW: (u16, u16) = (10 * 60 + 45, 12 * 60 + 30);
/// CPAS (07:00 to 10:00 UTC) with 30 minutes either side. New grants are not
/// issued in it, and a carrier change gives back every grant.
pub const NO_CYCLE: (u16, u16) = (6 * 60 + 30, 10 * 60 + 30);
/// A held arm the unit has left is re-applied at most this often.
pub const HOLD_SPACING: u64 = 6 * 3600;
/// After an attach on a new arm, wait this long for covering SAS grants.
pub const GRANT_WAIT: u64 = 600;
/// After the grants, let the tower settle the secondary carriers.
pub const SETTLE: u64 = 15;
/// The customer is idle below this rate (each direction) for `IDLE_SECS`.
pub const IDLE_KBPS: u64 = 2000;
pub const IDLE_SECS: u64 = 120;
/// Another arm must beat the arm the unit is on by this much to move it.
pub const SWITCH_MARGIN_PCT: u64 = 5;
pub const DL_BURST_MS: u32 = 3000;
/// Above any 3- or 4-carrier band 48 rate on TDD configuration 2.
pub const DL_OFFER_KBPS: u32 = 300_000;
pub const UL_BURST_MS: u32 = 3000;
/// Above a 2-carrier uplink on TDD configuration 2 (about 30 Mbps).
pub const UL_OFFER_KBPS: u32 = 45_000;
pub const PROBE_MAGIC: &str = "WITCHER-PROBE 1";

const BAND48_EARFCN: std::ops::RangeInclusive<u32> = 55_240..=56_739;

/// `HH:MM-HH:MM` in UTC, as minutes of the day. A window may wrap midnight.
pub fn parse_window(text: &str) -> Option<(u16, u16)> {
    let (a, b) = text.split_once('-')?;
    let window = (parse_hhmm(a)?, parse_hhmm(b)?);
    (window.0 != window.1).then_some(window)
}

fn parse_hhmm(text: &str) -> Option<u16> {
    let (h, m) = text.trim().split_once(':')?;
    let (h, m): (u16, u16) = (h.parse().ok()?, m.parse().ok()?);
    (h < 24 && m < 60 && text.trim().len() == 5).then_some(h * 60 + m)
}

/// Whether `minute` (0..1440) lies in `[start, end)`, wrapping midnight.
pub fn in_window(minute: u16, (start, end): (u16, u16)) -> bool {
    if start < end {
        (start..end).contains(&minute)
    } else {
        minute >= start || minute < end
    }
}

/// Whether two windows share any minute.
pub fn overlaps(a: (u16, u16), b: (u16, u16)) -> bool {
    (0..1440).any(|m| in_window(m, a) && in_window(m, b))
}

/// The operator's settings, checked. `None` when out of range.
pub fn validate(
    arms: &[Arm],
    probe: SocketAddrV4,
    survey_hours: Option<u16>,
    window: Option<&str>,
    ul_weight: Option<u8>,
) -> bool {
    let probe_ok = !matches!(probe.ip().octets()[0], 0 | 127 | 224..=255)
        && !probe.ip().is_link_local()
        && probe.port() != 0;
    let arms_ok = (MIN_ARMS..=MAX_ARMS).contains(&arms.len())
        && arms.iter().all(|a| {
            BAND48_EARFCN.contains(&a.earfcn) && a.pci <= 503 && (1..=4).contains(&a.carriers)
        })
        && arms
            .iter()
            .enumerate()
            .all(|(i, a)| arms[..i].iter().all(|b| b != a));
    let window_ok = match window {
        None => true,
        Some(text) => parse_window(text).is_some_and(|w| !overlaps(w, NO_CYCLE)),
    };
    probe_ok
        && arms_ok
        && window_ok
        && survey_hours.is_none_or(|h| (MIN_SURVEY_HOURS..=MAX_SURVEY_HOURS).contains(&h))
        && ul_weight.is_none_or(|w| w <= MAX_UL_WEIGHT)
}

/// A band 48 transmit span in Hz from an EARFCN, with `rcinit`'s 5 MHz
/// rounding of the lower edge (`cbrs_lte_change`), as the grant request uses.
pub fn span(earfcn: u32, bw_khz: u64) -> Option<(u64, u64)> {
    if !BAND48_EARFCN.contains(&earfcn) || !(5_000..=20_000).contains(&bw_khz) {
        return None;
    }
    let centre_khz = 3_550_000 + u64::from(earfcn - 55_240) * 100;
    let low_khz = centre_khz - bw_khz / 2;
    let low_mhz = (low_khz + 2_500) / 5_000 * 5;
    Some((low_mhz * 1_000_000, (low_mhz + bw_khz / 1000) * 1_000_000))
}

/// Grants as the vendor SAS client writes them to `/mnt/cbrslog0.txt`:
/// `=<i>(<n>):(<low_hz>-<high_hz>:<eirp>)(...)(...)`. The last line for each
/// grant index is current.
pub fn grants(log: &str) -> Vec<(u64, u64)> {
    let mut latest: Vec<(u8, (u64, u64))> = Vec::new();
    for line in log.lines() {
        let Some(rest) = line.trim().strip_prefix('=') else {
            continue;
        };
        let Some(index) = rest.chars().next().and_then(|c| c.to_digit(10)) else {
            continue;
        };
        let Some((_, after)) = rest.split_once("):(") else {
            continue;
        };
        let Some((range, _)) = after.split_once(':') else {
            continue;
        };
        let Some((low, high)) = range.split_once('-') else {
            continue;
        };
        let (Ok(low), Ok(high)) = (low.parse::<u64>(), high.parse::<u64>()) else {
            continue;
        };
        if low >= high || after.matches('(').count() < 2 {
            continue;
        }
        let index = index as u8;
        latest.retain(|(i, _)| *i != index);
        latest.push((index, (low, high)));
    }
    latest.into_iter().map(|(_, span)| span).collect()
}

/// Whether the primary and the uplink secondary carrier both sit inside
/// current grants.
pub fn covered(pcell: u32, ul_scc: Option<u32>, bw_khz: u64, grants: &[(u64, u64)]) -> bool {
    let inside = |earfcn: u32| {
        span(earfcn, bw_khz).is_some_and(|(lo, hi)| grants.iter().any(|(gl, gh)| lo >= *gl && hi <= *gh))
    };
    inside(pcell) && ul_scc.is_none_or(inside)
}

/// The delivered rate of a burst in kbit/s: the median of the interval rates
/// between consecutive counter samples `(seconds, bytes)` that start at least
/// half a second after `start` (the queue fills first) and end by `end`.
pub fn burst_kbps(samples: &[(f64, u64)], start: f64, end: f64) -> Option<u32> {
    let mut rates: Vec<f64> = samples
        .windows(2)
        .filter(|w| w[0].0 >= start + 0.5 && w[1].0 <= end && w[1].0 > w[0].0 && w[1].1 >= w[0].1)
        .map(|w| (w[1].1 - w[0].1) as f64 * 8.0 / (w[1].0 - w[0].0) / 1000.0)
        .collect();
    if rates.len() < 5 {
        return None;
    }
    rates.sort_by(f64::total_cmp);
    Some(rates[rates.len() / 2].round() as u32)
}

/// What one visit to an arm measured.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Measure {
    pub arm: usize,
    /// Where the unit attached. A visit the tower moved elsewhere is kept for
    /// the record but never chosen.
    pub pcell: Cell,
    pub carriers: u8,
    pub ul_scc: Option<u32>,
    pub sinr_db: Option<i32>,
    pub rsrp_dbm: Option<i32>,
    pub dl_kbps: u32,
    pub ul_kbps: u32,
    pub rtt_ms: Option<u32>,
    /// Unix time of the measurement.
    pub at: u64,
}

impl Measure {
    /// The visit ran on the arm it was meant for: its primary, within its cap.
    pub fn held(&self, arms: &[Arm]) -> bool {
        arms.get(self.arm)
            .is_some_and(|a| a.cell() == self.pcell && self.carriers <= a.carriers && self.carriers >= 1)
    }
}

pub fn score(m: &Measure, ul_weight: u8) -> u64 {
    u64::from(m.dl_kbps) + u64::from(ul_weight) * u64::from(m.ul_kbps)
}

/// The arm to hold after a survey. Only visits that held their arm count. The
/// arm the unit is on stays unless another scores `SWITCH_MARGIN_PCT` higher.
/// Between two scores within 2 %, the lower round trip wins.
pub fn choose(arms: &[Arm], results: &[Measure], current: Option<usize>, ul_weight: u8) -> Option<usize> {
    let valid: Vec<&Measure> = results.iter().filter(|m| m.held(arms) && m.dl_kbps > 0).collect();
    let best = valid.iter().copied().reduce(|a, b| {
        let (sa, sb) = (score(a, ul_weight), score(b, ul_weight));
        let close = sa.abs_diff(sb) * 50 <= sa.max(sb);
        let rtt = |m: &Measure| m.rtt_ms.unwrap_or(u32::MAX);
        if (close && rtt(b) < rtt(a)) || (!close && sb > sa) { b } else { a }
    })?;
    let stay = current.and_then(|c| valid.iter().find(|m| m.arm == c));
    match stay {
        Some(here) if score(best, ul_weight) * 100 < score(here, ul_weight) * (100 + SWITCH_MARGIN_PCT) => Some(here.arm),
        _ => Some(best.arm),
    }
}

/// Which arm the attach matches: the arm on this primary whose cap equals the
/// carrier count, else the smallest cap above it.
pub fn arm_of(arms: &[Arm], pcell: Cell, carriers: u8) -> Option<usize> {
    let on = |i: &usize| arms[*i].cell() == pcell && carriers >= 1 && carriers <= arms[*i].carriers;
    (0..arms.len())
        .filter(on)
        .min_by_key(|i| (arms[*i].carriers != carriers, arms[*i].carriers))
}

/// The next arm a survey visits: the one the unit is on first (no cycle),
/// then the others in the operator's order.
pub fn next_arm(arms: &[Arm], done: &[usize], current: Option<usize>) -> Option<usize> {
    current
        .filter(|c| *c < arms.len() && !done.contains(c))
        .or_else(|| (0..arms.len()).find(|i| !done.contains(i)))
}

/// Everything a radio cycle for the picker needs to see, read fresh.
#[derive(Clone, Copy, Debug)]
pub struct Gate {
    pub minute_utc: u16,
    pub window: (u16, u16),
    /// The operator asked for a survey now: the window does not apply.
    pub forced: bool,
    pub attached: bool,
    pub mode_grant: bool,
    pub grant_state: u8,
    pub idle: bool,
}

/// Whether the picker may cycle the radio now, or why not. The SAS
/// coordination window, the grant and the customer always apply.
pub fn cycle_gate(g: Gate) -> Result<(), &'static str> {
    if in_window(g.minute_utc, NO_CYCLE) {
        return Err("SAS coordination window");
    }
    if !g.forced && !in_window(g.minute_utc, g.window) {
        return Err("outside the survey window");
    }
    if !g.attached {
        return Err("not attached");
    }
    if !g.mode_grant || g.grant_state != 2 {
        return Err("SAS grant not held");
    }
    if !g.idle {
        return Err("customer traffic");
    }
    Ok(())
}

/// Idle when every rate sample in the last `IDLE_SECS` stays under
/// `IDLE_KBPS`. `samples` are `(seconds, rx_bytes, tx_bytes)` of the customer
/// bearer, oldest first.
pub fn idle(samples: &[(u64, u64, u64)], now: u64) -> bool {
    let recent: Vec<_> = samples.iter().filter(|s| now.saturating_sub(s.0) <= IDLE_SECS).collect();
    if recent.len() < 2 || now.saturating_sub(recent[0].0) + 10 < IDLE_SECS {
        return false;
    }
    recent.windows(2).all(|w| {
        let dt = w[1].0.saturating_sub(w[0].0).max(1);
        let kbps = |a: u64, b: u64| b.saturating_sub(a) * 8 / dt / 1000;
        kbps(w[0].1, w[1].1) < IDLE_KBPS && kbps(w[0].2, w[1].2) < IDLE_KBPS
    })
}

/// The probe server's control protocol, one line each way.
pub fn dl_request(ms: u32, kbps: u32, udp_port: u16) -> String {
    format!("{PROBE_MAGIC} DL {ms} {kbps} {udp_port}\n")
}

pub fn ul_request(ms: u32) -> String {
    format!("{PROBE_MAGIC} UL {ms}\n")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// `OK` before a download burst; `OK <udp_port>` to send an upload to.
    Ok(Option<u16>),
    /// `DONE <bytes_sent>` after a download burst.
    Done(u64),
    /// `RESULT <bytes> <first_to_last_ms>` after an upload burst.
    Counted { bytes: u64, span_ms: u32 },
    Refused(String),
}

pub fn parse_reply(line: &str) -> Option<Reply> {
    let mut words = line.split_whitespace();
    match words.next()? {
        "OK" => match words.next() {
            None => Some(Reply::Ok(None)),
            Some(p) => p.parse().ok().filter(|p| *p != 0).map(|p| Reply::Ok(Some(p))),
        },
        "DONE" => words.next()?.parse().ok().map(Reply::Done),
        "RESULT" => {
            let bytes = words.next()?.parse().ok()?;
            let span_ms = words.next()?.parse().ok()?;
            Some(Reply::Counted { bytes, span_ms })
        }
        "ERR" => Some(Reply::Refused(words.collect::<Vec<_>>().join(" "))),
        _ => None,
    }
}

/// An upload rate from the server's count, when the span is long enough to
/// mean something.
pub fn ul_kbps(bytes: u64, span_ms: u32) -> Option<u32> {
    (span_ms >= 1000).then(|| u32::try_from(bytes * 8 / u64::from(span_ms)).unwrap_or(u32::MAX))
}

/// `round-trip min/avg/max = 14.2/16.0/19.9 ms` from BusyBox ping.
pub fn ping_avg_ms(output: &str) -> Option<u32> {
    let stats = output.lines().find(|l| l.contains("min/avg/max"))?;
    let values = stats.split('=').nth(1)?.trim();
    let avg: f64 = values.split('/').nth(1)?.trim().parse().ok()?;
    Some(avg.round() as u32)
}

/// The uplink secondary carrier's EARFCN from `sqns_connection_uplinkScc`
/// (`freq,pusch,prach,pucch,bw:56638,-55,-55,-55,20`). `-` or empty: none.
pub fn ul_scc(value: &str) -> Option<u32> {
    let data = value.trim().split_once(':').map_or(value.trim(), |(_, rest)| rest);
    let earfcn: u32 = data.split(',').next()?.trim().parse().ok()?;
    BAND48_EARFCN.contains(&earfcn).then_some(earfcn)
}

/// The first comma field of a vendor reading in hundredths, rounded:
/// `-11160,-11510` is -112.
pub fn hundredths(value: &str) -> Option<i32> {
    let v: i32 = value.split(',').next()?.trim().parse().ok()?;
    Some((f64::from(v) / 100.0).round() as i32)
}

/// What the picker keeps on the persistent volume.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Record {
    /// The arms this record was measured with; a changed list starts over.
    pub arms: Vec<Arm>,
    pub chosen: Option<usize>,
    /// Unix time the last survey finished.
    pub surveyed_at: Option<u64>,
    pub results: Vec<Measure>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const C5: Arm = Arm { earfcn: 55440, pci: 199, carriers: 2 };
    const C6: Arm = Arm { earfcn: 56440, pci: 208, carriers: 3 };
    const C9: Arm = Arm { earfcn: 56638, pci: 217, carriers: 2 };

    fn probe() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 5310)
    }

    fn measure(arm: usize, a: Arm, dl: u32, ul: u32, rtt: Option<u32>) -> Measure {
        Measure {
            arm,
            pcell: a.cell(),
            carriers: a.carriers,
            ul_scc: None,
            sinr_db: Some(11),
            rsrp_dbm: Some(-110),
            dl_kbps: dl,
            ul_kbps: ul,
            rtt_ms: rtt,
            at: 1,
        }
    }

    #[test]
    fn windows_parse_wrap_and_never_touch_cpas() {
        assert_eq!(parse_window("10:45-12:30"), Some((645, 750)));
        assert_eq!(parse_window("22:00-02:00"), Some((1320, 120)));
        for bad in ["10:45", "10:45-10:45", "24:00-01:00", "1:00-02:00", "10:61-11:00"] {
            assert_eq!(parse_window(bad), None, "{bad}");
        }
        assert!(in_window(1430, (1320, 120)) && in_window(60, (1320, 120)));
        assert!(!in_window(120, (1320, 120)));
        assert!(overlaps((360, 420), NO_CYCLE));
        assert!(!overlaps((645, 750), NO_CYCLE));
        assert!(!validate(&[C5, C6], probe(), None, Some("06:00-07:00"), None));
        assert!(!validate(&[C5, C6], probe(), None, Some("23:00-07:00"), None));
        assert!(validate(&[C5, C6], probe(), None, Some("23:00-06:30"), None));
    }

    #[test]
    fn settings_are_bounded() {
        assert!(validate(&[C5, C6, C9], probe(), Some(24), None, Some(4)));
        assert!(!validate(&[C5], probe(), None, None, None));
        assert!(!validate(&[C5, C5], probe(), None, None, None));
        assert!(!validate(&[C5, Arm { earfcn: 55239, ..C6 }], probe(), None, None, None));
        assert!(!validate(&[C5, Arm { pci: 504, ..C6 }], probe(), None, None, None));
        assert!(!validate(&[C5, Arm { carriers: 5, ..C6 }], probe(), None, None, None));
        assert!(!validate(&[C5, C6], probe(), Some(23), None, None));
        assert!(!validate(&[C5, C6], probe(), None, None, Some(21)));
        assert!(!validate(&[C5, C6], SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5310), None, None, None));
        assert!(!validate(&[C5, C6], SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 0), None, None, None));
        assert!(!validate(&[C5, C6, C9, C5, C6, C9, C5], probe(), None, None, None));
    }

    #[test]
    fn spans_follow_rcinit_rounding_and_grants_cover_them() {
        assert_eq!(span(55440, 20_000), Some((3_560_000_000, 3_580_000_000)));
        // 3689.8 MHz centre: the lower edge rounds to 3680 MHz.
        assert_eq!(span(56638, 20_000), Some((3_680_000_000, 3_700_000_000)));
        assert_eq!(span(55239, 20_000), None);
        let log = "\
=0(1):(3620000000-3640000000:27)(1800:2027-11-24T18:11:06Z)(2026-11-25T00:11:08Z)
=1(1):(3660000000-3680000000:27)(1800:2027-11-24T18:11:10Z)(2026-11-25T00:11:12Z)
noise
=0(1):(3560000000-3580000000:27)(1800:2027-11-24T18:59:39Z)(2026-11-25T00:59:41Z)
=1(1):(3680000000-3700000000:27)(1800:2027-11-24T18:59:43Z)(2026-11-25T00:59:45Z)
";
        let g = grants(log);
        assert_eq!(g, vec![(3_560_000_000, 3_580_000_000), (3_680_000_000, 3_700_000_000)]);
        assert!(covered(55440, Some(56638), 20_000, &g));
        assert!(covered(55440, None, 20_000, &g));
        assert!(!covered(56440, Some(56638), 20_000, &g));
        assert!(!covered(55440, Some(56040), 20_000, &g));
        assert!(!covered(55440, None, 20_000, &[]));
    }

    #[test]
    fn burst_rate_is_the_median_after_the_queue_fills() {
        // 0.1 s samples at 140 Mbps from 0.3 s to 3.0 s, slow before and after.
        let mut s = vec![];
        let mut bytes = 0u64;
        for i in 0..40 {
            let t = f64::from(i) * 0.1;
            s.push((t, bytes));
            let mbps = if (3..30).contains(&i) { 140.0 } else { 5.0 };
            bytes += (mbps * 1e6 / 8.0 * 0.1) as u64;
        }
        assert_eq!(burst_kbps(&s, 0.0, 3.6), Some(140_000));
        assert_eq!(burst_kbps(&s[..6], 0.0, 3.6), None);
        assert_eq!(burst_kbps(&[(0.0, 10), (1.0, 5)], 0.0, 3.0), None);
    }

    #[test]
    fn the_best_held_arm_wins_with_margin_and_round_trip_tiebreak() {
        let arms = [C5, C6, C9];
        let results = vec![
            measure(0, C5, 132_940, 6_520, Some(16)),
            measure(1, C6, 126_780, 7_780, Some(19)),
            measure(2, C9, 103_000, 8_000, Some(18)),
        ];
        // ul_weight 4: 159.0 vs 157.9 vs 135.0 (Mbps-equivalent).
        assert_eq!(choose(&arms, &results, None, 4), Some(0));
        // From C6, C5 is only 0.7 % better: stay.
        assert_eq!(choose(&arms, &results, Some(1), 4), Some(1));
        // Upload weighted 20x: C6 scores 282.4 against 263.3 for C5 and 263.0
        // for C9, more than the margin, so it moves the unit off C5.
        assert_eq!(choose(&arms, &results, Some(0), 20), Some(1));
        // Within 2 %: the lower round trip wins.
        let close = vec![measure(0, C5, 100_000, 0, Some(20)), measure(1, C6, 101_000, 0, Some(15))];
        assert_eq!(choose(&arms, &close, None, 0), Some(1));
    }

    #[test]
    fn a_visit_the_tower_moved_elsewhere_never_wins() {
        let arms = [C5, C6];
        let mut moved = measure(0, C5, 200_000, 20_000, Some(10));
        moved.pcell = C6.cell();
        let results = vec![moved, measure(1, C6, 100_000, 5_000, Some(20))];
        assert_eq!(choose(&arms, &results, None, 4), Some(1));
        let mut over = measure(0, C5, 200_000, 20_000, Some(10));
        over.carriers = 3;
        assert!(!over.held(&arms));
        assert_eq!(choose(&arms, &[], None, 4), None);
    }

    #[test]
    fn the_attach_maps_to_an_arm_and_surveys_start_where_the_unit_is() {
        let arms = [C5, Arm { carriers: 3, ..C5 }, C6];
        assert_eq!(arm_of(&arms, C5.cell(), 2), Some(0));
        assert_eq!(arm_of(&arms, C5.cell(), 3), Some(1));
        assert_eq!(arm_of(&arms, C5.cell(), 1), Some(0));
        assert_eq!(arm_of(&arms, C6.cell(), 4), None);
        assert_eq!(arm_of(&arms, C9.cell(), 2), None);
        assert_eq!(next_arm(&arms, &[], Some(2)), Some(2));
        assert_eq!(next_arm(&arms, &[2], Some(2)), Some(0));
        assert_eq!(next_arm(&arms, &[0, 2], None), Some(1));
        assert_eq!(next_arm(&arms, &[0, 1, 2], Some(1)), None);
    }

    #[test]
    fn a_cycle_needs_the_window_the_grant_and_a_quiet_customer() {
        let ok = Gate {
            minute_utc: 11 * 60,
            window: DEFAULT_WINDOW,
            forced: false,
            attached: true,
            mode_grant: true,
            grant_state: 2,
            idle: true,
        };
        assert_eq!(cycle_gate(ok), Ok(()));
        let no = |g: Gate| cycle_gate(g).unwrap_err();
        assert_eq!(no(Gate { minute_utc: 8 * 60, forced: true, ..ok }), "SAS coordination window");
        assert_eq!(no(Gate { minute_utc: 6 * 60 + 30, forced: true, ..ok }), "SAS coordination window");
        assert_eq!(no(Gate { minute_utc: 19 * 60, ..ok }), "outside the survey window");
        assert_eq!(cycle_gate(Gate { minute_utc: 19 * 60, forced: true, ..ok }), Ok(()));
        assert_eq!(no(Gate { attached: false, ..ok }), "not attached");
        assert_eq!(no(Gate { mode_grant: false, ..ok }), "SAS grant not held");
        assert_eq!(no(Gate { grant_state: 1, ..ok }), "SAS grant not held");
        assert_eq!(no(Gate { idle: false, ..ok }), "customer traffic");
    }

    #[test]
    fn idle_needs_two_quiet_minutes_of_samples() {
        let quiet: Vec<_> = (0..=24).map(|i| (i * 5, i * 5 * 1000, i * 5 * 500)).collect();
        assert!(idle(&quiet, 120));
        assert!(!idle(&quiet[..10], 45));
        let mut busy = quiet.clone();
        busy[20].1 += 5_000_000;
        assert!(!idle(&busy, 120));
        assert!(!idle(&[], 120));
    }

    #[test]
    fn the_probe_protocol_round_trips() {
        assert_eq!(dl_request(3000, 300_000, 40123), "WITCHER-PROBE 1 DL 3000 300000 40123\n");
        assert_eq!(ul_request(3000), "WITCHER-PROBE 1 UL 3000\n");
        assert_eq!(parse_reply("OK\n"), Some(Reply::Ok(None)));
        assert_eq!(parse_reply("OK 41000"), Some(Reply::Ok(Some(41000))));
        assert_eq!(parse_reply("OK 0"), None);
        assert_eq!(parse_reply("DONE 112500000"), Some(Reply::Done(112_500_000)));
        assert_eq!(parse_reply("RESULT 5000000 2950"), Some(Reply::Counted { bytes: 5_000_000, span_ms: 2950 }));
        assert_eq!(parse_reply("ERR busy"), Some(Reply::Refused("busy".into())));
        assert_eq!(parse_reply("HELLO"), None);
        assert_eq!(ul_kbps(5_000_000, 2950), Some(13_559));
        assert_eq!(ul_kbps(5_000_000, 999), None);
        assert_eq!(ping_avg_ms("5 packets\nround-trip min/avg/max = 14.2/16.4/19.9 ms\n"), Some(16));
        assert_eq!(ping_avg_ms("100% packet loss"), None);
    }

    #[test]
    fn vendor_readings_parse() {
        assert_eq!(ul_scc("freq,pusch,prach,pucch,bw:56638,-55,-55,-55,20"), Some(56638));
        assert_eq!(ul_scc("-"), None);
        assert_eq!(ul_scc(""), None);
        assert_eq!(ul_scc("freq,pusch,prach,pucch,bw:1,-55,-55,-55,20"), None);
        assert_eq!(hundredths("-11160,-11510,-11320"), Some(-112));
        assert_eq!(hundredths("1100,1100"), Some(11));
        assert_eq!(hundredths("x"), None);
    }
}
