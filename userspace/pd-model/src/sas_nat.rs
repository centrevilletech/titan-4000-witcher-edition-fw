//! The unit's own SAS traffic in IP passthrough.
//!
//! In passthrough the vendor `rcinit` routes the SAS host out `br0` from the
//! LAN management address and adds one rule so the replies come back:
//! `iptables -t nat -I POSTROUTING -s <lan_management_ipaddr> -j SNAT --to
//! <pdn_data_ipaddr>`. About a minute after any LTE handover the vendor
//! restarts its firewall, and that drops the rule. Stock firmware gets it back
//! because Block Channel signals `rcinit` to rebuild the bridge, which this
//! build stubs out. So after a handover to a new channel nothing restores it,
//! and the SAS client retries until a reboot or a SAS save.
//!
//! The keeper restores the same rule the way `rcinit` would: `kern natq act 0`
//! (the bridge mode `rcinit` sets for passthrough), then the SNAT rule. It does
//! not touch forwarding, grants or the SAS client.
//!
//! Right after a PDN comes up the normal pace is too slow. The vendor SAS
//! client sends its two relinquishments about 6 and 12 s after the radio
//! connects. With a check every 10 s and two misses needed, the rule could be
//! missing for up to 20 s, so both failed, the old grants stayed at the SAS,
//! and the next grant request got 401 (7 of 28 bench channel changes, each
//! 46 to 65 s instead of about 12 s). So for `BURST` seconds after the keeper
//! sees a PDN come up, or the customer bearer join the bridge, it checks every
//! second. The other guards stay: no rule is needed unless the bearer is
//! bridged, an unreadable table is not a miss, and misses must run in a row
//! across `BURST_SPAN` seconds, longer than a vendor rebuild.
use std::net::Ipv4Addr;

pub const INTERVAL: u64 = 10;
/// The vendor rebuild flushes the table and adds the rule back within about a
/// second. One missing check can be the middle of that rebuild; two in a row,
/// ten seconds apart, is not.
const MISSES: u8 = 2;
/// At most one restore attempt a minute, so a failing command cannot loop.
pub const RETRY: u64 = 60;
/// Seconds of one-second checks after a PDN comes up.
pub const BURST: u64 = 30;
pub const BURST_INTERVAL: u64 = 1;
/// In a burst the misses in a row must span at least this many seconds (three
/// checks), so a vendor rebuild still in progress is never a miss run.
const BURST_SPAN: u64 = 2;
/// In a burst, a restore that was seen in the table afterwards may be followed
/// by another this soon, because the vendor can flush the table again during
/// bearer setup. A restore never seen in the table still waits `RETRY`.
const BURST_RETRY: u64 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snat {
    /// `lan_management_ipaddr`, the source of the unit's own traffic on br0.
    pub local: Ipv4Addr,
    /// `pdn_data_ipaddr`, the customer bearer the SAS replies come back to.
    pub bearer: Ipv4Addr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Hold,
    Restore(Snat),
}

#[derive(Default)]
pub struct Watch {
    snat: Option<Snat>,
    misses: u8,
    /// When the current run of misses started.
    first_miss: u64,
    /// The last restore, and whether the rule was in the table after it.
    restored: Option<(u64, bool)>,
    /// One-second checks run until this time.
    burst_until: Option<u64>,
}

impl Watch {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// A PDN came up, or the customer bearer joined the bridge: check every
    /// second for the next `BURST` seconds.
    pub fn burst(&mut self, now: u64) {
        let until = now + BURST;
        self.burst_until = Some(self.burst_until.map_or(until, |old| old.max(until)));
    }

    pub fn bursting(&self, now: u64) -> bool {
        self.burst_until.is_some_and(|until| now < until)
    }

    /// Seconds the caller waits between checks.
    pub fn interval(&self, now: u64) -> u64 {
        if self.bursting(now) {
            BURST_INTERVAL
        } else {
            INTERVAL
        }
    }

    /// One check, made every `interval()` seconds by the caller. `snat` is the
    /// rule this unit needs now, or `None` when it needs none. `present` is
    /// `None` when the nat table could not be read; that is not a miss.
    pub fn observe(&mut self, now: u64, snat: Option<Snat>, present: Option<bool>) -> Action {
        if self.snat != snat {
            // A new rule starts over. The burst belongs to the bearer setup
            // that changed it, so it carries on.
            *self = Self { burst_until: self.burst_until, ..Self::default() };
            self.snat = snat;
        }
        let Some(snat) = snat else {
            return Action::Hold;
        };
        match present {
            None => return Action::Hold,
            Some(true) => {
                self.misses = 0;
                if let Some((_, seen)) = &mut self.restored {
                    *seen = true;
                }
                return Action::Hold;
            }
            Some(false) => {
                if self.misses == 0 {
                    self.first_miss = now;
                }
                self.misses = self.misses.saturating_add(1);
            }
        }
        let burst = self.bursting(now);
        let missing = if burst {
            self.misses >= MISSES && now.saturating_sub(self.first_miss) >= BURST_SPAN
        } else {
            self.misses >= MISSES
        };
        let wait = match self.restored {
            Some((at, seen)) => {
                let window = if burst && seen { BURST_RETRY } else { RETRY };
                now < at + window
            }
            None => false,
        };
        if !missing || wait {
            return Action::Hold;
        }
        self.misses = 0;
        self.restored = Some((now, false));
        Action::Restore(snat)
    }
}

/// The interface of a kernel log line that says a PDN came up:
/// `LTE: set apn type lte0pdn2(0x1) eps_id=6 <IPv4> <IPv6>`. `/dev/kmsg`
/// records carry a `level,sequence,time,flags;` prefix; `dmesg` lines do not.
pub fn pdn_up(line: &str) -> Option<&str> {
    let rest = crate::extdev::message(line).strip_prefix("LTE: set apn type ")?;
    let dev = rest.split(|c: char| c == '(' || c.is_whitespace()).next()?;
    crate::extdev::is_lte_bearer(dev).then_some(dev)
}

/// The value printed by `nvram_get 0 <key>` (`nvram_get success: <value>`).
fn nvram_value(output: &str) -> &str {
    output.rsplit(':').next().unwrap_or("").trim()
}

/// The rule the vendor would hold, from the same nvram keys `rcinit` reads.
/// Only while the data bearer is bridged: its host route sits on `br0`.
pub fn needed(local: &str, bearer: &str, routes: &str) -> Option<Snat> {
    let local: Ipv4Addr = nvram_value(local).parse().ok()?;
    let bearer: Ipv4Addr = nvram_value(bearer).parse().ok()?;
    if local.is_unspecified() || bearer.is_unspecified() || local == bearer {
        return None;
    }
    let target = bearer.to_string();
    let bridged = routes.lines().any(|line| {
        let mut parts = line.split_whitespace();
        parts.next() == Some(target.as_str())
            && parts.next() == Some("dev")
            && parts.next() == Some("br0")
    });
    bridged.then_some(Snat { local, bearer })
}

/// Whether `iptables -t nat -S POSTROUTING` holds the vendor rule. `None` when
/// the text is not a listing of that chain, for example a failed command.
pub fn present(listing: &str, snat: Snat) -> Option<bool> {
    if !listing
        .lines()
        .any(|line| line.trim_start().starts_with("-P POSTROUTING"))
    {
        return None;
    }
    let local = snat.local.to_string();
    let host = format!("{local}/32");
    let bearer = snat.bearer.to_string();
    Some(listing.lines().any(|line| {
        let words: Vec<&str> = line.split_whitespace().collect();
        matches!(
            words.as_slice(),
            ["-A", "POSTROUTING", "-s", source, "-j", "SNAT", "--to-source", target]
                if (*source == host || *source == local) && *target == bearer
        )
    }))
}

/// The commands `rcinit` runs for this rule in passthrough, in its order.
pub fn restore_commands(snat: Snat) -> [(&'static str, Vec<String>); 2] {
    [
        ("kern", ["natq", "act", "0"].map(String::from).to_vec()),
        (
            "iptables",
            vec![
                "-t".into(),
                "nat".into(),
                "-I".into(),
                "POSTROUTING".into(),
                "-s".into(),
                snat.local.to_string(),
                "-j".into(),
                "SNAT".into(),
                "--to-source".into(),
                snat.bearer.to_string(),
            ],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTES: &str = "default dev lte0pdn0  scope link \n10.1.1.0/24 dev br0  proto kernel  scope link  src 10.1.1.1 \n34.98.109.46 dev br0  scope link \n172.20.64.94 dev br0  scope link \n";
    const VENDOR: &str =
        "-P POSTROUTING ACCEPT\n-A POSTROUTING -s 10.1.1.1/32 -j SNAT --to-source 172.20.64.94\n";
    const FLUSHED: &str = "-P POSTROUTING ACCEPT\n";

    fn snat() -> Snat {
        Snat {
            local: Ipv4Addr::new(10, 1, 1, 1),
            bearer: Ipv4Addr::new(172, 20, 64, 94),
        }
    }

    #[test]
    fn needed_reads_vendor_nvram_and_requires_the_bridged_bearer() {
        let local = "nvram_get success: 10.1.1.1\n";
        let bearer = "nvram_get success: 172.20.64.94\n";
        assert_eq!(needed(local, bearer, ROUTES), Some(snat()));
        // Before attach, or after the bearer moves, there is no br0 host route.
        assert_eq!(
            needed(local, bearer, "10.1.1.0/24 dev br0 scope link\n"),
            None
        );
        assert_eq!(
            needed(local, bearer, "172.20.64.94 dev lte0pdn1 scope link\n"),
            None
        );
        assert_eq!(
            needed(local, bearer, "172.20.64.94/32 dev br0 scope link\n"),
            None
        );
        assert_eq!(needed(local, "nvram_get success: \n", ROUTES), None);
        assert_eq!(needed(local, "nvram_get success: 0.0.0.0\n", ROUTES), None);
        assert_eq!(needed("", bearer, ROUTES), None);
        assert_eq!(needed(bearer, bearer, ROUTES), None);
    }

    #[test]
    fn present_matches_only_the_vendor_rule() {
        assert_eq!(present(VENDOR, snat()), Some(true));
        assert_eq!(present(FLUSHED, snat()), Some(false));
        let bare =
            "-P POSTROUTING ACCEPT\n-A POSTROUTING -s 10.1.1.1 -j SNAT --to-source 172.20.64.94\n";
        assert_eq!(present(bare, snat()), Some(true));
        for other in [
            "-A POSTROUTING -s 10.1.1.1/32 -j SNAT --to-source 172.20.64.95",
            "-A POSTROUTING -s 10.1.1.2/32 -j SNAT --to-source 172.20.64.94",
            "-A POSTROUTING -s 10.1.1.1/32 -d 1.1.1.1/32 -j SNAT --to-source 172.20.64.94",
            "-A POSTROUTING -s 10.1.1.1/32 -j MASQUERADE",
            "-A PREROUTING -s 10.1.1.1/32 -j SNAT --to-source 172.20.64.94",
        ] {
            let listing = format!("-P POSTROUTING ACCEPT\n{other}\n");
            assert_eq!(present(&listing, snat()), Some(false), "{other}");
        }
        // A failed or empty read is unknown, never a miss.
        assert_eq!(present("", snat()), None);
        assert_eq!(
            present("iptables: No chain/target/match by that name.\n", snat()),
            None
        );
    }

    #[test]
    fn two_misses_in_a_row_restore_once() {
        let mut w = Watch::default();
        assert_eq!(w.observe(100, Some(snat()), Some(false)), Action::Hold);
        assert_eq!(
            w.observe(110, Some(snat()), Some(false)),
            Action::Restore(snat())
        );
        // Still missing: wait out the retry window, then try again.
        assert_eq!(w.observe(120, Some(snat()), Some(false)), Action::Hold);
        assert_eq!(w.observe(160, Some(snat()), Some(false)), Action::Hold);
        assert_eq!(
            w.observe(170, Some(snat()), Some(false)),
            Action::Restore(snat())
        );
    }

    #[test]
    fn a_vendor_rebuild_seen_mid_flush_is_not_a_miss_run() {
        let mut w = Watch::default();
        for t in (0..1000).step_by(10) {
            let present = t % 20 != 0;
            assert_eq!(w.observe(t, Some(snat()), Some(present)), Action::Hold);
        }
    }

    #[test]
    fn unreadable_table_ineligible_unit_or_new_bearer_never_acts_early() {
        let mut w = Watch::default();
        for t in (0..1000).step_by(10) {
            assert_eq!(w.observe(t, Some(snat()), None), Action::Hold);
            assert_eq!(w.observe(t, None, Some(false)), Action::Hold);
        }
        assert_eq!(w.observe(1000, Some(snat()), Some(false)), Action::Hold);
        let mut moved = snat();
        moved.bearer = Ipv4Addr::new(172, 20, 64, 95);
        assert_eq!(w.observe(1010, Some(moved), Some(false)), Action::Hold);
        assert_eq!(
            w.observe(1020, Some(moved), Some(false)),
            Action::Restore(moved)
        );
    }

    #[test]
    fn a_burst_checks_every_second_for_thirty_seconds() {
        let mut w = Watch::default();
        assert_eq!(w.interval(500), INTERVAL);
        w.burst(500);
        assert!(w.bursting(500));
        assert_eq!(w.interval(500), 1);
        assert_eq!(w.interval(529), 1);
        assert!(!w.bursting(530));
        assert_eq!(w.interval(530), INTERVAL);
        // A second PDN extends it from the later event.
        w.burst(520);
        assert_eq!(w.interval(549), 1);
        assert_eq!(w.interval(550), INTERVAL);
    }

    #[test]
    fn in_a_burst_a_flush_is_restored_after_two_seconds_of_misses() {
        let mut w = Watch::default();
        w.burst(100);
        assert_eq!(w.observe(100, Some(snat()), Some(true)), Action::Hold);
        // Flushed at 101. Two misses one second apart can still be a vendor
        // rebuild in progress; the third, two seconds after the first, is not.
        assert_eq!(w.observe(101, Some(snat()), Some(false)), Action::Hold);
        assert_eq!(w.observe(102, Some(snat()), Some(false)), Action::Hold);
        assert_eq!(w.observe(103, Some(snat()), Some(false)), Action::Restore(snat()));
        // A rebuild that puts the rule back between checks resets the run.
        let mut v = Watch::default();
        v.burst(100);
        assert_eq!(v.observe(101, Some(snat()), Some(false)), Action::Hold);
        assert_eq!(v.observe(102, Some(snat()), Some(true)), Action::Hold);
        assert_eq!(v.observe(103, Some(snat()), Some(false)), Action::Hold);
        assert_eq!(v.observe(104, Some(snat()), Some(false)), Action::Hold);
        assert_eq!(v.observe(105, Some(snat()), Some(false)), Action::Restore(snat()));
    }

    #[test]
    fn in_a_burst_a_working_restore_may_repeat_and_a_failing_one_waits_a_minute() {
        let mut w = Watch::default();
        w.burst(100);
        for t in 100..102 {
            assert_eq!(w.observe(t, Some(snat()), Some(false)), Action::Hold);
        }
        assert_eq!(w.observe(102, Some(snat()), Some(false)), Action::Restore(snat()));
        // The rule is back, then the vendor flushes the table again.
        assert_eq!(w.observe(103, Some(snat()), Some(true)), Action::Hold);
        for t in 104..106 {
            assert_eq!(w.observe(t, Some(snat()), Some(false)), Action::Hold);
        }
        // Misses span two seconds at 106, but only four have passed since the
        // last restore.
        assert_eq!(w.observe(106, Some(snat()), Some(false)), Action::Hold);
        assert_eq!(w.observe(107, Some(snat()), Some(false)), Action::Restore(snat()));
        // This restore never shows up in the table: the next waits RETRY.
        for t in 108..167 {
            assert_eq!(w.observe(t, Some(snat()), Some(false)), Action::Hold, "{t}");
        }
        assert_eq!(w.observe(167, Some(snat()), Some(false)), Action::Restore(snat()));
    }

    #[test]
    fn outside_a_burst_the_ten_second_rule_is_unchanged() {
        let mut w = Watch::default();
        w.burst(0);
        // The burst is over long before these checks.
        assert_eq!(w.observe(100, Some(snat()), Some(false)), Action::Hold);
        assert_eq!(w.observe(110, Some(snat()), Some(false)), Action::Restore(snat()));
        // Seen working, then flushed again: still one restore a minute.
        assert_eq!(w.observe(120, Some(snat()), Some(true)), Action::Hold);
        assert_eq!(w.observe(130, Some(snat()), Some(false)), Action::Hold);
        assert_eq!(w.observe(140, Some(snat()), Some(false)), Action::Hold);
        assert_eq!(w.observe(170, Some(snat()), Some(false)), Action::Restore(snat()));
    }

    #[test]
    fn a_burst_keeps_every_other_guard() {
        let mut w = Watch::default();
        w.burst(0);
        for t in 0..30 {
            // No bridged bearer, or an unreadable table: never a restore.
            assert_eq!(w.observe(t, None, Some(false)), Action::Hold);
            assert_eq!(w.observe(t, Some(snat()), None), Action::Hold);
        }
        // A new bearer address starts the miss count over but keeps the burst.
        let mut moved = snat();
        moved.bearer = Ipv4Addr::new(192, 0, 2, 7);
        let mut v = Watch::default();
        v.burst(0);
        assert_eq!(v.observe(1, Some(snat()), Some(false)), Action::Hold);
        assert_eq!(v.observe(2, Some(snat()), Some(false)), Action::Hold);
        assert_eq!(v.observe(3, Some(moved), Some(false)), Action::Hold);
        assert!(v.bursting(3));
        assert_eq!(v.observe(4, Some(moved), Some(false)), Action::Hold);
        assert_eq!(v.observe(5, Some(moved), Some(false)), Action::Restore(moved));
        // A reset (the unit left passthrough) ends the burst.
        v.reset();
        assert!(!v.bursting(6));
    }

    #[test]
    fn a_pdn_up_line_names_its_bearer() {
        let line = "LTE: set apn type lte0pdn2(0x1) eps_id=6 192.0.2.7 2001:db8::7";
        assert_eq!(pdn_up(line), Some("lte0pdn2"));
        assert_eq!(pdn_up(&format!("6,812,15196123,-;{line}")), Some("lte0pdn2"));
        assert_eq!(pdn_up("LTE: set apn type lte0pdn0 eps_id=5"), Some("lte0pdn0"));
        assert_eq!(pdn_up("LTE: lte0pdn1(0x0) set interface id: 200:5eff:fe40:3 eps_id=6"), None);
        assert_eq!(pdn_up("LTE: set apn type eth0(0x1)"), None);
        assert_eq!(pdn_up("set external_dev: lte0pdn0 ipv6 mask=50"), None);
        assert_eq!(pdn_up(""), None);
    }

    #[test]
    fn restore_runs_the_vendor_commands_in_vendor_order() {
        let [(kern, kern_args), (iptables, iptables_args)] = restore_commands(snat());
        assert_eq!((kern, kern_args.join(" ").as_str()), ("kern", "natq act 0"));
        assert_eq!(iptables, "iptables");
        assert_eq!(
            iptables_args.join(" "),
            "-t nat -I POSTROUTING -s 10.1.1.1 -j SNAT --to-source 172.20.64.94"
        );
    }
}
