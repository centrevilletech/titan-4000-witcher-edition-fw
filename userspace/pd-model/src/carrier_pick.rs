//! Picking the carrier combination: which primary cell, and how many carriers.
//!
//! Bench, 2026-11-24 (one unit, one Nokia sector, four 20 MHz band 48 carriers):
//! the same unit measured 126.78/7.78 Mbps with c6 as primary and three
//! carriers, and 132.94/6.52 Mbps with 16 ms ping on c5 with two. Upload was
//! power-limited on both: each carrier sat near 23 dBm. Which combination wins
//! depends on the unit's aim, the other users of each carrier and the time of
//! day, so the picker visits each combination ("arm") the operator lists and
//! scores it there. It needs no server.
//!
//! A visit is one radio cycle through the existing nudge: radio off, carrier
//! cap, PCell lock, radio on, attach, lock cleared at once. The tower still
//! picks the secondary carriers. After SAS grants cover the new primary and
//! uplink secondary carrier, the picker scores the arm:
//!
//! - download, estimated: every serving carrier's SINR as the modem reports it
//!   in that arm, the weaker receive branch of each (rank 2 runs at its pace),
//!   through `dl_estimate_kbps`. The Titan cannot measure its own
//!   download without a sender: its CPU caps a local TCP download near 53 Mbps.
//!   The estimate matched UDP bursts from the core on the bench: 128 Mbps for
//!   c5 (11 dB) with c9 (15 dB) against 130.7 measured, 180 Mbps for c6
//!   (10 dB) with c9 (15 dB) and c5 (12 dB) against 176.8, and 150 Mbps for c6
//!   (9 dB) with c9 and c12 at their weaker branches (11, 12 dB) against 148
//!   to 150. The same combination read 202 with the first branch only, and the
//!   eNB's own counters put c9 at 43 Mbps while its branches read 18 and 11.
//! - upload, measured: a 20 s UDP burst to the discard port of the profile's
//!   management probe, the operator's own ping responder. The packets cross the
//!   radio and the probe drops them. The rate is the modem's own upload report
//!   (`sqns_radio_ulThroughput`), which refreshes about every 6.5 s and read
//!   13.8 Mbps where the far end counted 11.2 to 12.2 Mbps of payload: every
//!   arm gets the same bias, so the ranking holds. The burst stops when the
//!   customer starts moving traffic (`busy`), and that arm waits to be
//!   measured again.
//! - idle round trip: five pings to the same responder.
//!
//! The best arm by `download + ul_weight x upload` is held; the arm the unit
//! is on keeps its place unless another beats it by `SWITCH_MARGIN_PCT`.
//!
//! Guards: no radio cycle in the SAS coordination window (`NO_CYCLE`: the
//! CPAS window every keeper reboot waits out, 06:45 to 10:15 UTC, with 15
//! minutes either side) or with the clock unset, none outside the operator's
//! survey window, none while the SAS grant is not held, none while the
//! customer moves traffic, at most one survey per `survey_hours` (24 or more),
//! a held arm that the unit left re-applied at most once per `HOLD_SPACING`,
//! and at most `radio_guard::CYCLE_CAP` cycles a day.
//!
//! A visit that no covering grant reaches within `GRANT_WAIT` goes straight
//! back to where the unit was before it, which held its grants then. That
//! way back has no grant to protect, so it waits only for the keeper's reboot
//! window (`tk_boot::CPAS_QUIET`, without the margin), the clock and the
//! daily cap, never for a grant (v1.0.17; before, the grant gate kept a unit
//! on an arm the SAS would not grant).

use crate::radio::Cell;
use crate::radio_guard::CYCLE_MARGIN_MIN;
use crate::tk_boot::CPAS_QUIET;
use serde::{Deserialize, Serialize};

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
/// The CPAS window every keeper reboot waits out (`tk_boot::CPAS_QUIET`,
/// 06:45 to 10:15 UTC) with `radio_guard::CYCLE_MARGIN_MIN` either side:
/// 06:30 to 10:30. New grants are not issued in it, and a carrier change gives
/// back every grant. A survey window may not touch it, and every radio cycle
/// waits it out (`radio_guard::cycle_hold`, the same window).
pub const NO_CYCLE: (u16, u16) = (
    CPAS_QUIET.start_min - CYCLE_MARGIN_MIN,
    CPAS_QUIET.end_min + CYCLE_MARGIN_MIN,
);
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
/// The upload burst: long enough for at least two fresh modem reports.
pub const UL_BURST_SECS: u64 = 20;
/// Above a 2-carrier uplink on TDD configuration 2 (about 30 Mbps).
pub const UL_OFFER_KBPS: u32 = 45_000;
/// The discard port on the management probe.
pub const UL_SINK_PORT: u16 = 9;
/// The measurement worker's error when the customer starts moving traffic
/// during the upload burst. The burst stops at once and the guard measures
/// that arm again once the customer is idle.
pub const CUSTOMER_BUSY: &str = "customer traffic during the measurement";

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
pub fn validate(arms: &[Arm], survey_hours: Option<u16>, window: Option<&str>, ul_weight: Option<u8>) -> bool {
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
    arms_ok
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

/// Per-layer download capacity of one carrier in kbit/s, for SINR from -10 to
/// 40 dB: `10.7 MHz x min(log2(1 + snr / 2.9), 7.4 bit/s/Hz)`. A table keeps
/// soft-float `pow` and `log2` out of the ARM build;
/// `the_capacity_table_is_the_model` recomputes it.
const PER_LAYER_KBPS: [u32; 51] = [
    523, 656, 821, 1027, 1282, 1598, 1986, 2461, 3039, 3737, //
    4573, 5566, 6731, 8082, 9631, 11383, 13338, 15493, 17838, 20359, //
    23040, 25863, 28812, 31867, 35013, 38236, 41521, 44858, 48238, 51653, //
    55095, 58560, 62042, 65540, 69049, 72567, 76092, 79180, 79180, 79180, //
    79180, 79180, 79180, 79180, 79180, 79180, 79180, 79180, 79180, 79180, //
    79180,
];

/// Download capacity of one 20 MHz band 48 carrier on TDD configuration 2
/// (special subframe 7) at `sinr_db`, with `layers` spatial layers, in kbit/s.
/// Shannon with a 4.6 dB implementation gap per layer, capped at 256QAM, over
/// 10.7 MHz of effective bandwidth (the downlink share of the frame and the
/// control and reference overhead). Fitted on the bench, 2026-11-24 (see the
/// module notes); one unit, so treat it as a ranking tool, not a promise.
pub fn carrier_kbps(sinr_db: i32, layers: u8) -> u32 {
    let i = usize::try_from(sinr_db.clamp(-10, 40) + 10).unwrap_or(0);
    PER_LAYER_KBPS[i] * u32::from(layers.clamp(1, 4))
}

/// The arm's download estimate: the sum over its serving carriers.
pub fn dl_estimate_kbps(sinr_db: &[i32], layers: u8) -> u32 {
    sinr_db.iter().map(|s| carrier_kbps(*s, layers)).sum()
}

/// SINR of each secondary carrier from `sqns_connection_downlinkSccEx`, a
/// header (`dl_mcs,dl_freq,bw,...,sinr,...,cinr,...:`) and `;`-separated
/// entries. Each SCell has two receive branches and `cinr` lists both
/// (`18.0/11.0`); the `sinr` column repeats the first. Rank 2 needs both
/// streams, so the weaker branch sets the rate: on the bench (2026-11-24) the
/// eNB's per-UE MAC peak on c9 was 43 Mbps while it read `18.0/11.0`, close to
/// the model at 11 dB and far from it at 18. Falls back to `sinr` without
/// `cinr`.
pub fn scc_sinr_db(value: &str) -> Vec<i32> {
    let Some((header, data)) = value.split_once(':') else {
        return vec![];
    };
    let cols: Vec<&str> = header.split(',').map(str::trim).collect();
    let cinr = cols.iter().position(|h| *h == "cinr");
    let sinr = cols.iter().position(|h| *h == "sinr");
    if cinr.is_none() && sinr.is_none() {
        return vec![];
    }
    data.split(';')
        .filter_map(|entry| {
            let fields: Vec<&str> = entry.split(',').collect();
            let weakest = cinr.and_then(|c| fields.get(c)).and_then(|v| {
                v.split('/').filter_map(|x| x.trim().parse::<f64>().ok()).reduce(f64::min)
            });
            weakest.or_else(|| sinr.and_then(|c| fields.get(c)?.trim().parse::<f64>().ok()))
        })
        .map(|v| v.round() as i32)
        .collect()
}

/// The middle of `v` once sorted (the upper middle of an even count).
pub fn median<T: Ord + Copy>(v: &[T]) -> Option<T> {
    let mut v = v.to_vec();
    v.sort_unstable();
    v.get(v.len() / 2).copied()
}

/// Each serving carrier's SINR from the samples a visit took once a second:
/// the primary's median, then the median of each secondary position, up to
/// `carriers - 1` of them. A position no sample reported is left out.
pub fn serving_sinr(pcell: &[i32], scc: &[Vec<i32>], carriers: u8) -> Option<Vec<i32>> {
    let mut out = vec![median(pcell)?];
    for i in 0..usize::from(carriers.saturating_sub(1)) {
        let at: Vec<i32> = scc.iter().filter_map(|s| s.get(i).copied()).collect();
        if let Some(m) = median(&at) {
            out.push(m);
        }
    }
    Some(out)
}

/// The upload rate from the modem's own reports during a burst: the highest
/// report taken after the burst started that differs from the one before it.
/// `samples` are `(seconds, bits_per_second)`; `None` without a fresh report.
pub fn ul_from_reports(samples: &[(f64, u64)], start: f64) -> Option<u32> {
    let before = samples.iter().rev().find(|s| s.0 < start).map(|s| s.1);
    samples
        .iter()
        .filter(|s| s.0 >= start && Some(s.1) != before)
        .map(|s| s.1)
        .max()
        .map(|bps| u32::try_from(bps / 1000).unwrap_or(u32::MAX))
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
    /// Download estimate from the serving carriers' SINR (`dl_estimate_kbps`).
    pub dl_kbps: u32,
    /// Upload as the modem reported it during the burst.
    pub ul_kbps: u32,
    pub rtt_ms: Option<u32>,
    /// SINR of each secondary carrier, as the estimate used it.
    #[serde(default)]
    pub scc_sinr_db: Vec<i32>,
    /// The modem's own high-water marks (`sqns_radio_dlMaxThroughput`,
    /// `sqns_radio_ulMaxThroughput`) at the end of the visit, for the record.
    #[serde(default)]
    pub dl_max_kbps: Option<u32>,
    #[serde(default)]
    pub ul_max_kbps: Option<u32>,
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
    /// Why a radio cycle must wait now (`radio_guard::cycle_hold`): the SAS
    /// CPAS window (`NO_CYCLE`) or an unset clock.
    pub hold: Option<&'static str>,
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
/// coordination window, the clock, the grant and the customer always apply.
pub fn cycle_gate(g: Gate) -> Result<(), &'static str> {
    if let Some(why) = g.hold {
        return Err(why);
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

/// Whether the customer bearer moved `IDLE_KBPS` or more either way between
/// two `(rx_bytes, tx_bytes)` readings `millis` apart.
pub fn busy(before: (u64, u64), after: (u64, u64), millis: u64) -> bool {
    let kbps = |a: u64, b: u64| b.saturating_sub(a) * 8 / millis.max(1);
    kbps(before.0, after.0) >= IDLE_KBPS || kbps(before.1, after.1) >= IDLE_KBPS
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

/// The weakest comma field of a vendor reading in hundredths, rounded: the
/// primary cell's SINR lists one value per receive branch (`900,1000` is 9),
/// and rank 2 runs at the weaker one's pace (see `scc_sinr_db`).
pub fn weakest_hundredths(value: &str) -> Option<i32> {
    let v = value.split(',').filter_map(|f| f.trim().parse::<i32>().ok()).min()?;
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

    const C5: Arm = Arm { earfcn: 55440, pci: 199, carriers: 2 };
    const C6: Arm = Arm { earfcn: 56440, pci: 208, carriers: 3 };
    const C9: Arm = Arm { earfcn: 56638, pci: 217, carriers: 2 };

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
            scc_sinr_db: vec![],
            dl_max_kbps: None,
            ul_max_kbps: None,
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
        assert!(!validate(&[C5, C6], None, Some("06:00-07:00"), None));
        assert!(!validate(&[C5, C6], None, Some("23:00-07:00"), None));
        assert!(validate(&[C5, C6], None, Some("23:00-06:30"), None));
    }

    #[test]
    fn settings_are_bounded() {
        assert!(validate(&[C5, C6, C9], Some(24), None, Some(4)));
        assert!(!validate(&[C5], None, None, None));
        assert!(!validate(&[C5, C5], None, None, None));
        assert!(!validate(&[C5, Arm { earfcn: 55239, ..C6 }], None, None, None));
        assert!(!validate(&[C5, Arm { pci: 504, ..C6 }], None, None, None));
        assert!(!validate(&[C5, Arm { carriers: 5, ..C6 }], None, None, None));
        assert!(!validate(&[C5, C6], Some(23), None, None));
        assert!(!validate(&[C5, C6], None, None, Some(21)));
        assert!(!validate(&[C5, C6, C9, C5, C6, C9, C5], None, None, None));
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
    fn the_download_model_matches_the_bench() {
        // c5 at 11 dB with c9 at 15 dB, 2 layers: 130.7 Mbps measured.
        let two = dl_estimate_kbps(&[11, 15], 2);
        assert!((120_000..=140_000).contains(&two), "{two}");
        // c6 at 10 dB with c9 at 15 and c5 at 12: 176.8 Mbps measured.
        let three = dl_estimate_kbps(&[10, 15, 12], 2);
        assert!((170_000..=190_000).contains(&three), "{three}");
        // c6 PCell at 9 dB with c9 and c12 at their weaker branches, 11 and 12 dB:
        // UDP floods from the core got 148 to 150 Mbps (2026-11-24 22:39 UTC).
        let weak = dl_estimate_kbps(&[9, 11, 12], 2);
        assert!((140_000..=160_000).contains(&weak), "{weak}");
        // A single carrier at 14 dB: 66 to 75 Mbps on the bench (2026-11-22).
        let one = dl_estimate_kbps(&[14], 2);
        assert!((60_000..=78_000).contains(&one), "{one}");
        // More signal or more layers never lower it; 256QAM caps each carrier.
        assert!(carrier_kbps(20, 2) > carrier_kbps(15, 2));
        assert!(carrier_kbps(15, 4) > carrier_kbps(15, 2));
        assert_eq!(carrier_kbps(40, 2), carrier_kbps(60, 2));
        assert_eq!(dl_estimate_kbps(&[], 2), 0);
    }

    #[test]
    fn the_capacity_table_is_the_model() {
        for (i, kbps) in PER_LAYER_KBPS.iter().enumerate() {
            let snr = 10f64.powf((i as f64 - 10.0) / 10.0);
            let per_layer = (1.0 + snr / 2.9).log2().min(7.4);
            assert_eq!(*kbps, (10.7 * per_layer * 1000.0).round() as u32, "{} dB", i as i32 - 10);
        }
        assert_eq!(carrier_kbps(-30, 2), carrier_kbps(-10, 2));
        assert_eq!(carrier_kbps(11, 0), carrier_kbps(11, 1));
    }

    #[test]
    fn visit_samples_reduce_to_one_sinr_per_carrier() {
        assert_eq!(median(&[3, 1, 2]), Some(2));
        assert_eq!(median(&[4, 1, 3, 2]), Some(3));
        assert_eq!(median::<u8>(&[]), None);
        // One noisy sample neither lifts nor sinks a carrier.
        let scc = vec![vec![15, 12], vec![15, 12], vec![30, 2], vec![14]];
        assert_eq!(serving_sinr(&[10, 10, 25], &scc, 3), Some(vec![10, 15, 12]));
        // A cap of two keeps one secondary; extra reported ones are ignored.
        assert_eq!(serving_sinr(&[10], &scc, 2), Some(vec![10, 15]));
        assert_eq!(serving_sinr(&[10], &[], 3), Some(vec![10]));
        assert_eq!(serving_sinr(&[], &scc, 3), None);
    }

    #[test]
    fn secondary_sinr_and_modem_upload_reports_parse() {
        let scc = "dl_mcs,dl_freq,bw,rssi,rsrp,rsrq,sinr,tx_power,pci,cinr,cell_id,mcc,mnc:\
0,3689.0,20,-86.0/-83.0,-112.0/-109.0,-6.0/-6.0,16,14,217,16.0/17.0,-,901,70;\
0,3570.0,20,-89.0/-85.0,-116.0/-111.0,-6.0/-5.0,11,-,199,11.0/16.0,-,901,70";
        assert_eq!(scc_sinr_db(scc), vec![16, 11]);
        // The bench at 22:39 UTC: c9 read 18.0/11.0 and c12 12.0/12.0; the weaker branch counts.
        let split = "dl_mcs,dl_freq,bw,rssi,rsrp,rsrq,sinr,tx_power,pci,cinr,cell_id,mcc,mnc:\
0,3689.0,20,-83.0/-88.0,-110.0/-116.0,-6.0/-8.0,18,-,217,18.0/11.0,-,901,70;\
0,3630.0,20,-81.0/-86.0,-107.0/-113.0,-6.0/-6.0,12,-,190,12.0/12.0,-,901,70";
        assert_eq!(scc_sinr_db(split), vec![11, 12]);
        // Without a cinr column the sinr column still works.
        assert_eq!(scc_sinr_db("dl_mcs,sinr:0,14;0,9"), vec![14, 9]);
        assert_eq!(weakest_hundredths("900,1000"), Some(9));
        assert_eq!(weakest_hundredths("1300"), Some(13));
        assert_eq!(weakest_hundredths("-"), None);
        assert_eq!(scc_sinr_db("-"), Vec::<i32>::new());
        assert_eq!(scc_sinr_db("a,b:1,2"), Vec::<i32>::new());
        // The bench burst: one stale report, then 4.7 and 13.8 Mbps.
        let reports = [(0.0, 636_256), (1.0, 4_749_352), (7.5, 13_840_816), (8.0, 13_840_816)];
        assert_eq!(ul_from_reports(&reports, 0.5), Some(13_840));
        // Nothing fresh after the burst started: no reading.
        assert_eq!(ul_from_reports(&[(0.0, 636_256), (5.0, 636_256)], 0.5), None);
        assert_eq!(ul_from_reports(&[], 0.0), None);
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
            hold: None,
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
        // The CPAS window and the clock come from the shared reboot gate.
        let day = 1_795_305_600; // 2026-11-22 00:00 UTC
        let held = |minute: u64| crate::radio_guard::cycle_hold(Some(CPAS_QUIET), day + minute * 60);
        let cpas = "the SAS CPAS window is open";
        assert_eq!(no(Gate { hold: held(8 * 60), minute_utc: 8 * 60, forced: true, ..ok }), cpas);
        assert_eq!(no(Gate { hold: held(6 * 60 + 30), minute_utc: 6 * 60 + 30, forced: true, ..ok }), cpas);
        assert_eq!(held(6 * 60 + 29), None);
        assert_eq!(held(10 * 60 + 30), None);
        assert_eq!(no(Gate { hold: crate::radio_guard::cycle_hold(Some(CPAS_QUIET), 1_000), ..ok }), "the clock is not set yet");
        assert_eq!(
            crate::radio_guard::cycle_window(Some(CPAS_QUIET)).map(|w| (w.start_min, w.end_min)),
            Some(NO_CYCLE)
        );
        assert_eq!(NO_CYCLE, (6 * 60 + 30, 10 * 60 + 30));
        // A full survey of the most arms and the return to the chosen one fit
        // the daily cap of radio cycles.
        assert!(MAX_ARMS + 1 < crate::radio_guard::CYCLE_CAP);
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
    fn customer_traffic_stops_a_burst() {
        // 2 Mbps either way in one second is the customer, not background.
        assert!(busy((0, 0), (250_000, 0), 1000));
        assert!(busy((0, 0), (0, 250_000), 1000));
        assert!(!busy((0, 0), (249_000, 249_000), 1000));
        assert!(!busy((0, 0), (300_000, 0), 1500));
        // A counter that went backwards (an interface reset) is no traffic.
        assert!(!busy((500_000, 500_000), (0, 0), 1000));
        // A zero interval does not divide by zero.
        assert!(!busy((0, 0), (1, 0), 0));
    }

    #[test]
    fn ping_averages_parse() {
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
