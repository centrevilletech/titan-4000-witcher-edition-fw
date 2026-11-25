//! The keeper's own reboots, capped (v1.0.17).
//!
//! Every reboot the keeper starts (the boot confirm's rollback, the verdict's
//! return to the image, the retry after stock answered, the deaf watchdog's)
//! is recorded in `keeper-reboots` on the persistent volume, and at most
//! `CAP` may fall in `WINDOW` seconds. A reboot that moves the unit onto
//! stock firmware, or the deaf watchdog's, needs two free slots; a reboot
//! back onto the image needs one. So the last slot is always there for the
//! way back: the cap can stop the keeper rebooting, but never strand the
//! unit on stock firmware. Once the cap is reached the keeper logs and
//! waits.
//!
//! The Titan has no battery clock: it boots at 2013 until NTP sets the time.
//! A reboot recorded without a set clock carries no time. Once a later boot
//! has a set clock it gets that boot's start, a time after the real one, so
//! it leaves the window late rather than early. With the clock unset every
//! entry counts.

/// Keeper reboots allowed in `WINDOW`.
pub const CAP: usize = 4;
/// Seconds of the window.
pub const WINDOW: u64 = 86_400;
/// Free slots a reboot onto stock firmware (or the deaf watchdog's) needs:
/// itself and the way back.
pub const SLOTS_AWAY: usize = 2;
/// Free slots a reboot back onto the image needs.
pub const SLOTS_BACK: usize = 1;
/// Entries kept in the file.
const KEPT: usize = 16;

/// One keeper reboot: when (Unix seconds, 0 when the clock was unset) and
/// why (one word).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub wall: u64,
    pub why: String,
}

/// One `<wall> <why>` per line. Damaged lines are dropped.
pub fn parse(text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let wall = words.next()?.parse().ok()?;
            let why = words.next().unwrap_or("reboot").to_owned();
            Some(Entry { wall, why })
        })
        .collect()
}

pub fn render(entries: &[Entry]) -> String {
    let skip = entries.len().saturating_sub(KEPT);
    entries[skip..]
        .iter()
        .map(|entry| format!("{} {}\n", entry.wall, entry.why))
        .collect()
}

fn clock_set(wall: u64) -> bool {
    wall >= crate::tk_boot::CLOCK_SET_AFTER
}

/// The entries as this boot can judge them. With the clock set, entries
/// without a time get `boot_start` (this boot's start: they happened before
/// it), and entries older than the window go. With the clock unset nothing
/// changes.
pub fn settle(entries: &[Entry], wall: u64, boot_start: u64) -> Vec<Entry> {
    if !clock_set(wall) {
        return entries.to_vec();
    }
    entries
        .iter()
        .map(|entry| Entry {
            wall: if clock_set(entry.wall) { entry.wall } else { boot_start },
            why: entry.why.clone(),
        })
        .filter(|entry| wall.saturating_sub(entry.wall) < WINDOW)
        .collect()
}

/// Reboots that count against the cap now: every one with the clock unset,
/// else those inside the window.
pub fn recent(entries: &[Entry], wall: u64) -> usize {
    if !clock_set(wall) {
        return entries.len();
    }
    entries
        .iter()
        .filter(|entry| !clock_set(entry.wall) || wall.saturating_sub(entry.wall) < WINDOW)
        .count()
}

/// Whether a reboot that needs `slots` free ones may go now.
pub fn allows(entries: &[Entry], wall: u64, slots: usize) -> bool {
    CAP.saturating_sub(recent(entries, wall)) >= slots
}

/// The file with one more reboot.
pub fn record(entries: &[Entry], wall: u64, why: &str) -> String {
    let mut next = entries.to_vec();
    next.push(Entry {
        wall: if clock_set(wall) { wall } else { 0 },
        why: why.to_owned(),
    });
    render(&next)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOON: u64 = 1_795_305_600 + 12 * 3600;
    const EARLY: u64 = 1_370_000_000;

    fn file(entries: &[(u64, &str)]) -> Vec<Entry> {
        entries
            .iter()
            .map(|(wall, why)| Entry {
                wall: *wall,
                why: (*why).to_owned(),
            })
            .collect()
    }

    #[test]
    fn the_way_back_to_the_image_always_has_a_slot() {
        let mut entries = Vec::new();
        // An outage: away to stock, back to the image. A second outage the
        // same day: away again needs two free, so it goes; then back.
        for (why, slots) in [("rollback", SLOTS_AWAY), ("return", SLOTS_BACK), ("rollback", SLOTS_AWAY), ("return", SLOTS_BACK)] {
            assert!(allows(&entries, NOON, slots), "{why}");
            entries = parse(&record(&entries, NOON, why));
        }
        // Full: no more trips away (or deaf reboots), and a return would
        // have had its slot.
        assert!(!allows(&entries, NOON, SLOTS_AWAY) && !allows(&entries, NOON, SLOTS_BACK));
        // A bad image: away, retry, away, and the slot for the way back is
        // still free if stock fails to answer.
        let bad = file(&[(NOON, "rollback"), (NOON, "retry")]);
        assert!(allows(&bad, NOON, SLOTS_AWAY));
        let bad = parse(&record(&bad, NOON, "rollback"));
        assert!(allows(&bad, NOON, SLOTS_BACK) && !allows(&bad, NOON, SLOTS_AWAY));
    }

    #[test]
    fn reboots_leave_the_window_after_a_day() {
        let entries = file(&[(NOON - WINDOW, "deaf"), (NOON - 3600, "rollback"), (NOON - 60, "return")]);
        assert_eq!(recent(&entries, NOON), 2);
        assert_eq!(settle(&entries, NOON, NOON - 600).len(), 2);
    }

    #[test]
    fn without_a_clock_every_reboot_counts_and_keeps_no_time() {
        let entries = file(&[(NOON - 2 * WINDOW, "deaf")]);
        assert_eq!(recent(&entries, EARLY), 1);
        assert_eq!(settle(&entries, EARLY, 0), entries);
        let recorded = parse(&record(&entries, EARLY + 50, "rollback"));
        assert_eq!(recorded[1], Entry { wall: 0, why: "rollback".into() });
        // A later boot with a set clock dates it at its own start, which is
        // after the reboot: it stays in the window a little longer.
        let settled = settle(&recorded, NOON, NOON - 300);
        assert_eq!(settled, file(&[(NOON - 300, "rollback")]));
        assert_eq!(recent(&settled, NOON + WINDOW - 301), 1);
        assert_eq!(recent(&settled, NOON + WINDOW - 300), 0);
    }

    #[test]
    fn the_file_keeps_its_last_entries_and_drops_damage() {
        let many: Vec<Entry> = (0..40).map(|i| Entry { wall: NOON + i, why: "deaf".into() }).collect();
        let kept = parse(&render(&many));
        assert_eq!(kept.len(), 16);
        assert_eq!(kept[0].wall, NOON + 24);
        assert_eq!(parse("x y\n\n123\n456 rollback extra\n"), file(&[(123, "reboot"), (456, "rollback")]));
    }
}
