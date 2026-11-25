//! Whether a rollback of the default modem image was the image's fault or
//! the network's (v1.0.17).
//!
//! The boot confirm (`tk_boot::Confirm`) compares an image with stock
//! firmware (a rollback) after a cell was in view for `CONFIRM_SECS` without
//! an answer through the core, or after `SEARCH_SECS` of no cell at all. A
//! tower, core or backhaul outage, a missing SAS grant or targets that do not
//! answer look the same from the image's side, so for the default image the
//! quarantine a rollback records is provisional, and no network condition
//! can keep the unit off the image:
//!
//! - The rollback writes `pending=1` in `tk/verdict` beside the quarantine
//!   and `strikes=2`, so the next boot is stock.
//! - That stock boot is watched the same way. When stock firmware gets no
//!   answer either, the network failed, not the image: the keeper takes the
//!   image out of quarantine, writes `strikes=0`, records `outage=1` and
//!   reboots straight back onto the image, which then waits for the network
//!   as stock would. While `outage=1` the image is not compared again until
//!   it confirms (only a recheck after `tk_boot::RECHECK_SECS`), so one
//!   outage costs at most one image -> stock -> image cycle.
//! - When stock firmware answers, the image failed where stock did not: one
//!   genuine failure. Below `GENUINE_LIMIT` the network is known to be up, so
//!   the keeper takes the image out of quarantine and reboots to try it again
//!   at once. A tower that came back between the image's watch and stock's
//!   then confirms, and a confirmed boot clears the count. At the limit the
//!   quarantine sticks until an operator presses Retry (Network → Latency),
//!   or until the image or the firmware build changes.
//! - Boots of the image that end before their confirm decides anything (a
//!   power cut, a crash, a reboot by hand) leave the strikes at the limit and
//!   no rollback recorded. The next stock boot records them as one rollback
//!   (`stopped`) and judges it the same way.
//!
//! Every record names the firmware build that wrote it (`firmware`). A
//! record, quarantine or strike count from another build, or for another
//! image, no longer applies; the boot hook clears it (`tk_default::plan`).
//! The keeper's reboots all pass its reboot gate (CPAS window, clock, a cap
//! per day). A record the keeper cannot read never clears a quarantine.
//!
//! The web service builds a copy of this module to show the record; both
//! copies run these tests.

/// Genuine failures of one image, with no confirmed boot between them,
/// before its quarantine sticks.
pub const GENUINE_LIMIT: u32 = 2;

/// `tk/verdict`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Verdict {
    /// The image the counts are for (its gzip SHA-256).
    pub gzip: String,
    /// The firmware build that wrote the record (`tk_boot::firmware_id`).
    pub firmware: String,
    /// Rollbacks after which stock firmware answered, since the image's last
    /// confirmed boot.
    pub genuine: u32,
    /// Rollbacks after which stock firmware got no answer either.
    pub network: u32,
    /// A rollback waits for a stock boot to judge it.
    pub pending: bool,
    /// The last verdict was the network's: the image waits for the network
    /// and is not compared again until it confirms.
    pub outage: bool,
}

/// What a stock boot made of the pending rollback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Judgement {
    /// Stock firmware got no answer either: back to the image at once.
    Network,
    /// Stock firmware answered: the image's `count`th failure. At
    /// `GENUINE_LIMIT` the quarantine sticks.
    Genuine { count: u32, sticks: bool },
}

impl Judgement {
    /// The quarantine comes off and the keeper reboots onto the image at
    /// once: after a network verdict, or a genuine failure below the limit.
    pub fn back_to_image(self) -> bool {
        !matches!(self, Judgement::Genuine { sticks: true, .. })
    }
}

impl Verdict {
    /// An unreadable count counts as the limit, and an unreadable `pending`
    /// or `outage` as no: a damaged record keeps the quarantine.
    pub fn parse(text: &str) -> Self {
        let mut verdict = Self::default();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim();
            match key.trim() {
                "gzip" => verdict.gzip = value.to_ascii_lowercase(),
                "firmware" => verdict.firmware = value.to_owned(),
                "genuine" => verdict.genuine = value.parse().unwrap_or(GENUINE_LIMIT),
                "network" => verdict.network = value.parse().unwrap_or(0),
                "pending" => verdict.pending = value == "1",
                "outage" => verdict.outage = value == "1",
                _ => {}
            }
        }
        verdict
    }

    pub fn render(&self) -> String {
        format!(
            "gzip={}\nfirmware={}\ngenuine={}\nnetwork={}\npending={}\noutage={}\n",
            self.gzip,
            self.firmware,
            self.genuine,
            self.network,
            u8::from(self.pending),
            u8::from(self.outage)
        )
    }

    /// The record is about `sha` and was written by this firmware build.
    pub fn applies(&self, sha: &str, firmware: &str) -> bool {
        self.gzip.eq_ignore_ascii_case(sha) && self.firmware == firmware
    }

    /// The record keeps `sha` off this boot: a rollback waits for its stock
    /// verdict, or the quarantine stuck.
    pub fn holds(&self, sha: &str, firmware: &str) -> bool {
        self.applies(sha, firmware) && (self.pending || self.sticks())
    }

    /// `sha` waits for the network: its last verdict was the network's.
    pub fn waits_for_network(&self, sha: &str, firmware: &str) -> bool {
        self.applies(sha, firmware) && self.outage
    }

    /// The record after a rollback of `sha` by this firmware build: its
    /// counts carry over, and another image's or build's are dropped.
    pub fn rolled_back(&self, sha: &str, firmware: &str) -> Self {
        let mut next = if self.applies(sha, firmware) {
            self.clone()
        } else {
            Self {
                gzip: sha.to_ascii_lowercase(),
                firmware: firmware.to_owned(),
                ..Self::default()
            }
        };
        next.pending = true;
        next.outage = false;
        next
    }

    /// `sha` confirmed a boot: nothing waits any more, and the image works on
    /// this unit, so its earlier failures were not its own. The genuine count
    /// starts again; the network count is history.
    pub fn confirmed(&self, sha: &str) -> Self {
        let mut next = self.clone();
        if next.gzip.eq_ignore_ascii_case(sha) {
            next.pending = false;
            next.genuine = 0;
            next.outage = false;
        }
        next
    }

    /// A stock boot's judgement of the pending rollback. `answered`: stock
    /// firmware got an answer through the core within the confirm window.
    pub fn judge(&self, answered: bool) -> (Self, Judgement) {
        let mut next = self.clone();
        next.pending = false;
        let judgement = if answered {
            next.genuine = next.genuine.saturating_add(1);
            next.outage = false;
            Judgement::Genuine {
                count: next.genuine,
                sticks: next.genuine >= GENUINE_LIMIT,
            }
        } else {
            next.network = next.network.saturating_add(1);
            next.outage = true;
            Judgement::Network
        };
        (next, judgement)
    }

    /// The image's quarantine sticks until an operator retries it, or the
    /// image or the firmware build changes.
    pub fn sticks(&self) -> bool {
        self.genuine >= GENUINE_LIMIT
    }

    /// A stock boot found the strikes for `sha`, the default image, at the
    /// limit with no rollback recorded: its boots ended before their confirm
    /// decided anything. The record that makes this boot judge them as one
    /// rollback, or `None` when there is nothing to judge: the strikes are
    /// below the limit, a rollback already waits, or the image is quarantined
    /// already (an earlier record stands, stuck or not).
    pub fn stopped(&self, sha: &str, firmware: &str, at_limit: bool, quarantined: bool) -> Option<Self> {
        let stuck = self.applies(sha, firmware) && self.sticks();
        (at_limit && !quarantined && !self.pending && !stuck).then(|| self.rolled_back(sha, firmware))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE: &str = "3348aa361c4689c4ff18b647a03bfa55cea36bc6675059cd9995e591592e40bb";
    const BUILD: &str = "0123456789abcdef";

    #[test]
    fn a_tower_outage_never_counts_against_the_image() {
        let mut verdict = Verdict::default();
        for outage in 1..=5 {
            verdict = verdict.rolled_back(IMAGE, BUILD);
            assert!(verdict.pending && verdict.holds(IMAGE, BUILD));
            let (next, judgement) = verdict.judge(false);
            assert_eq!(judgement, Judgement::Network);
            assert!(judgement.back_to_image(), "straight back to the image");
            assert_eq!(
                (next.genuine, next.network, next.pending, next.outage),
                (0, outage, false, true)
            );
            assert!(next.waits_for_network(IMAGE, BUILD) && !next.holds(IMAGE, BUILD));
            verdict = next;
        }
        assert!(!verdict.sticks());
        // The image answers once the network is back: the wait is over.
        let back = verdict.confirmed(IMAGE);
        assert!(!back.outage && !back.waits_for_network(IMAGE, BUILD));
    }

    #[test]
    fn a_bad_image_sticks_after_two_failures_where_stock_answered() {
        let (once, first) = Verdict::default().rolled_back(IMAGE, BUILD).judge(true);
        assert_eq!(
            first,
            Judgement::Genuine {
                count: 1,
                sticks: false
            }
        );
        assert!(first.back_to_image(), "one failure: tried again at once");
        assert!(!once.holds(IMAGE, BUILD) && !once.outage);
        let (twice, second) = once.rolled_back(IMAGE, BUILD).judge(true);
        assert_eq!(
            second,
            Judgement::Genuine {
                count: 2,
                sticks: true
            }
        );
        assert!(!second.back_to_image());
        assert!(twice.sticks() && twice.holds(IMAGE, BUILD));
        // The tower was back by stock's watch but not by the image's (a site
        // power cut): the retry confirms and the failure is forgotten.
        let retried = once.confirmed(IMAGE);
        assert_eq!((retried.genuine, retried.pending), (0, false));
        assert_eq!(
            retried.rolled_back(IMAGE, BUILD).judge(true).1,
            Judgement::Genuine {
                count: 1,
                sticks: false
            }
        );
    }

    #[test]
    fn another_image_or_firmware_build_starts_its_own_count() {
        let (stuck, _) = Verdict::default()
            .rolled_back(IMAGE, BUILD)
            .judge(true)
            .0
            .rolled_back(IMAGE, BUILD)
            .judge(true);
        assert!(stuck.holds(IMAGE, BUILD));
        // A new firmware build, or another image: the record no longer holds
        // anything back, and a rollback starts afresh.
        assert!(!stuck.holds(IMAGE, "fedcba9876543210"));
        assert!(!stuck.holds(&"ab".repeat(32), BUILD));
        let fresh = stuck.rolled_back(IMAGE, "fedcba9876543210");
        assert_eq!(
            fresh,
            Verdict {
                gzip: IMAGE.into(),
                firmware: "fedcba9876543210".into(),
                genuine: 0,
                network: 0,
                pending: true,
                outage: false
            }
        );
        assert_eq!(Verdict::parse(&fresh.render()), fresh);
    }

    #[test]
    fn a_damaged_record_keeps_the_quarantine() {
        let damaged = Verdict::parse(&format!("gzip={IMAGE}\nfirmware={BUILD}\ngenuine=x\npending=1\n"));
        assert!(damaged.sticks() && damaged.holds(IMAGE, BUILD));
        let unsure = Verdict::parse(&format!("gzip={IMAGE}\nfirmware={BUILD}\npending=yes\noutage=yes\n"));
        assert!(!unsure.pending && !unsure.outage);
        assert_eq!(Verdict::parse(""), Verdict::default());
        // A v1.0.17 record from before `firmware=` names no build: it applies
        // to none, so the hook clears it.
        assert!(!Verdict::parse(&format!("gzip={IMAGE}\ngenuine=2\n")).holds(IMAGE, BUILD));
        // Confirming another image leaves this one's rollback waiting.
        let new = Verdict::default().rolled_back(IMAGE, BUILD);
        assert!(new.confirmed(&"cd".repeat(32)).pending);
        assert!(!new.confirmed(&IMAGE.to_uppercase()).pending);
    }

    #[test]
    fn boots_cut_short_before_their_confirm_are_judged_as_one_rollback() {
        let once = Verdict {
            gzip: IMAGE.into(),
            firmware: BUILD.into(),
            genuine: 1,
            network: 2,
            pending: false,
            outage: true,
        };
        // Two boots died after their strikes: one rollback, counts kept.
        let recorded = once.stopped(IMAGE, BUILD, true, false).expect("judged");
        assert_eq!(
            recorded,
            Verdict {
                pending: true,
                outage: false,
                ..once.clone()
            }
        );
        assert_eq!(recorded.judge(false).1, Judgement::Network);
        // Nothing to judge: below the limit, already waiting, or quarantined
        // already (a record whose verdict could not be written stays put).
        assert_eq!(once.stopped(IMAGE, BUILD, false, false), None);
        assert_eq!(recorded.stopped(IMAGE, BUILD, true, false), None);
        assert_eq!(once.stopped(IMAGE, BUILD, true, true), None);
        // A stuck image stays stuck, but another image starts afresh.
        let (stuck, _) = recorded.judge(true);
        let (stuck, _) = stuck.rolled_back(IMAGE, BUILD).judge(true);
        assert!(stuck.sticks());
        assert_eq!(stuck.stopped(IMAGE, BUILD, true, false), None);
        let other = "cd".repeat(32);
        assert_eq!(
            stuck.stopped(&other, BUILD, true, false),
            Some(Verdict::default().rolled_back(&other, BUILD))
        );
    }
}
