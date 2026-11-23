//! Band 48 frequency ranges and the vendor channel mask.
//!
//! The vendor `rcinit` describes the carriers the modem transmits on as a
//! 32-bit mask: bit 31 is 3550 to 3555 MHz and each lower bit is the next
//! 5 MHz. The SAS speaks in hertz. This module converts between the two and
//! does the range arithmetic the grant manager needs.
use std::fmt;

pub const BAND_LOW: u64 = 3_550_000_000;
pub const BAND_HIGH: u64 = 3_700_000_000;
pub const STEP: u64 = 5_000_000;
const SLOTS: u32 = 30;

/// A frequency range in hertz. `low` is always below `high`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Range {
    pub low: u64,
    pub high: u64,
}

impl fmt::Display for Range {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "{}-{} MHz",
            self.low / 1_000_000,
            self.high / 1_000_000
        )
    }
}

impl Range {
    /// A range inside the band. Nothing outside 3550 to 3700 MHz is ever
    /// requested from the SAS.
    pub fn new(low: u64, high: u64) -> Option<Self> {
        (low < high && low >= BAND_LOW && high <= BAND_HIGH).then_some(Self { low, high })
    }

    /// A range given in whole megahertz, for tests and configuration.
    pub fn mhz(low: u64, high: u64) -> Option<Self> {
        Self::new(low * 1_000_000, high * 1_000_000)
    }

    /// The carrier `rcinit` reads from nvram: the centre in units of 100 kHz
    /// (`sqns_radio_freqDl`) and the width in kHz (`sqns_radio_bandwidthDl`).
    /// The edges move outward to the 5 MHz grid, so the grant always covers
    /// the whole carrier.
    pub fn from_carrier(centre_100khz: u64, width_khz: u64) -> Option<Self> {
        if centre_100khz == 0 || width_khz == 0 {
            return None;
        }
        let centre = centre_100khz.checked_mul(100_000)?;
        let half = width_khz.checked_mul(500)?;
        let low = centre.checked_sub(half)?;
        let high = centre.checked_add(half)?;
        if low < BAND_LOW || high > BAND_HIGH {
            return None;
        }
        let low = BAND_LOW + (low - BAND_LOW) / STEP * STEP;
        let high = BAND_LOW + (high - BAND_LOW).div_ceil(STEP) * STEP;
        Self::new(low, high)
    }

    pub fn width(self) -> u64 {
        self.high - self.low
    }

    pub fn overlaps(self, other: Range) -> bool {
        self.low < other.high && other.low < self.high
    }

    pub fn contains(self, other: Range) -> bool {
        self.low <= other.low && other.high <= self.high
    }
}

/// The ranges a vendor mask names, lowest first, with touching slots merged.
pub fn from_mask(mask: u32) -> Vec<Range> {
    let mut ranges: Vec<Range> = Vec::new();
    for slot in 0..SLOTS {
        if mask & (1 << (31 - slot)) == 0 {
            continue;
        }
        let low = BAND_LOW + u64::from(slot) * STEP;
        match ranges.last_mut() {
            Some(last) if last.high == low => last.high = low + STEP,
            _ => ranges.push(Range {
                low,
                high: low + STEP,
            }),
        }
    }
    ranges
}

/// The vendor mask for a set of ranges. A slot is set when any part of it is
/// in a range.
pub fn to_mask(ranges: &[Range]) -> u32 {
    let mut mask = 0;
    for slot in 0..SLOTS {
        let low = BAND_LOW + u64::from(slot) * STEP;
        let cell = Range {
            low,
            high: low + STEP,
        };
        if ranges.iter().any(|range| range.overlaps(cell)) {
            mask |= 1 << (31 - slot);
        }
    }
    mask
}

/// Sorted, with overlapping and touching ranges merged.
pub fn normalise(ranges: &[Range]) -> Vec<Range> {
    let mut sorted = ranges.to_vec();
    sorted.sort();
    let mut merged: Vec<Range> = Vec::new();
    for range in sorted {
        match merged.last_mut() {
            Some(last) if range.low <= last.high => last.high = last.high.max(range.high),
            _ => merged.push(range),
        }
    }
    merged
}

/// The parts of `want` that no range in `have` covers.
pub fn subtract(want: &[Range], have: &[Range]) -> Vec<Range> {
    let have = normalise(have);
    let mut missing = Vec::new();
    for range in normalise(want) {
        let mut low = range.low;
        for held in &have {
            if held.high <= low || held.low >= range.high {
                continue;
            }
            if held.low > low {
                missing.push(Range {
                    low,
                    high: held.low,
                });
            }
            low = low.max(held.high);
        }
        if low < range.high {
            missing.push(Range {
                low,
                high: range.high,
            });
        }
    }
    missing
}

/// Whether the ranges in `have` together cover all of `want`.
pub fn covered(want: Range, have: &[Range]) -> bool {
    subtract(&[want], have).is_empty()
}

/// `range` cut into pieces no wider than `max`, from the low edge up.
pub fn split(range: Range, max: u64) -> Vec<Range> {
    if max == 0 {
        return vec![range];
    }
    let mut pieces = Vec::new();
    let mut low = range.low;
    while low < range.high {
        let high = (low + max).min(range.high);
        pieces.push(Range { low, high });
        low = high;
    }
    pieces
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mhz(low: u64, high: u64) -> Range {
        Range::mhz(low, high).unwrap()
    }

    #[test]
    fn the_vendor_masks_seen_in_the_field_decode() {
        assert_eq!(from_mask(0x3C00_0000), vec![mhz(3560, 3580)]);
        assert_eq!(from_mask(0x0000_03C0), vec![mhz(3660, 3680)]);
        assert_eq!(
            from_mask(0x3C00_003C),
            vec![mhz(3560, 3580), mhz(3680, 3700)]
        );
        assert_eq!(from_mask(0x0000_03FC), vec![mhz(3660, 3700)]);
        assert_eq!(from_mask(0), Vec::new());
    }

    #[test]
    fn a_mask_survives_a_round_trip() {
        for mask in [0x3C00_0000_u32, 0x3C00_03C0, 0x0000_03FC, 0x8000_0004] {
            assert_eq!(to_mask(&from_mask(mask)), mask);
        }
    }

    #[test]
    fn an_nvram_carrier_becomes_a_range() {
        assert_eq!(Range::from_carrier(35700, 20000), Some(mhz(3560, 3580)));
        assert_eq!(Range::from_carrier(36900, 20000), Some(mhz(3680, 3700)));
        assert_eq!(Range::from_carrier(0, 20000), None);
        assert_eq!(Range::from_carrier(37000, 20000), None);
        // A carrier off the 5 MHz grid is covered whole.
        assert_eq!(Range::from_carrier(35653, 10000), Some(mhz(3560, 3575)));
    }

    #[test]
    fn subtraction_leaves_only_the_uncovered_parts() {
        let want = [mhz(3660, 3700)];
        assert_eq!(subtract(&want, &[mhz(3660, 3680)]), vec![mhz(3680, 3700)]);
        assert_eq!(
            subtract(&want, &[mhz(3670, 3690)]),
            vec![mhz(3660, 3670), mhz(3690, 3700)]
        );
        assert!(subtract(&want, &[mhz(3660, 3680), mhz(3680, 3700)]).is_empty());
        assert_eq!(subtract(&want, &[]), vec![mhz(3660, 3700)]);
    }

    #[test]
    fn two_touching_grants_cover_one_wide_carrier_pair() {
        assert!(covered(
            mhz(3660, 3700),
            &[mhz(3680, 3700), mhz(3660, 3680)]
        ));
        assert!(!covered(mhz(3660, 3700), &[mhz(3660, 3680)]));
    }

    #[test]
    fn a_wide_run_splits_from_the_low_edge() {
        assert_eq!(
            split(mhz(3660, 3700), 20_000_000),
            vec![mhz(3660, 3680), mhz(3680, 3700)]
        );
        assert_eq!(split(mhz(3560, 3580), 20_000_000), vec![mhz(3560, 3580)]);
        assert_eq!(
            split(mhz(3560, 3590), 20_000_000),
            vec![mhz(3560, 3580), mhz(3580, 3590)]
        );
    }

    #[test]
    fn nothing_outside_the_band_is_a_range() {
        assert!(Range::mhz(3540, 3560).is_none());
        assert!(Range::mhz(3690, 3710).is_none());
        assert!(Range::mhz(3600, 3600).is_none());
    }
}
