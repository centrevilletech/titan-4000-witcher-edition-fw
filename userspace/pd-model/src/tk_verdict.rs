//! Whether a rollback of the default modem image was the image's fault or
//! the network's (v1.0.17).
//!
//! The boot confirm (`tk_boot::Confirm`) rolls an image back when the modem
//! gets no answer through the core within `CONFIRM_SECS`. A tower outage or a
//! site power cut at boot looks the same, so for the default image the
//! quarantine it records is provisional:
//!
//! - The rollback writes `pending=1` in `tk/verdict` beside the quarantine
//!   and `strikes=2`, so the next boot is stock, as before.
//! - That stock boot is watched the same way. When stock firmware gets no
//!   answer either, the network failed, not the image. The keeper takes the
//!   image out of quarantine and writes `strikes=0`, and a later boot loads
//!   it again (`network` counts these).
//! - When stock firmware answers, the image failed where stock did not: one
//!   genuine failure. Below `GENUINE_LIMIT` the network is known to be up, so
//!   the keeper takes the image out of quarantine and reboots to try it again
//!   at once (`Judgement::retests`). A tower that came back between the
//!   image's watch and stock's (a site power cut: the image's 300 s ran out
//!   before the tower was up) then confirms, and a confirmed boot clears the
//!   count. At the limit the quarantine sticks until an operator presses Retry
//!   (Network → Latency).
//! - Boots of the image that end before their confirm decides anything (a
//!   power cut, a crash, a reboot by hand) leave the strikes at the limit and
//!   no rollback recorded. The next stock boot records them as one rollback
//!   (`stopped`) and judges it the same way, so a flapping power supply
//!   cannot keep a good image off either.
//!
//! A network failure forces no reboot: that retry waits for a boot that
//! happens anyway. The reboot to retry after stock firmware answered waits
//! until the clock is set and the SAS CPAS window is over, and comes at most
//! once between confirmed boots of the image. The strike before every load,
//! the build cap and the CPAS-aware rollback reboot are unchanged. A record
//! the keeper cannot read never clears a quarantine.
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
    /// Rollbacks after which stock firmware answered, since the image's last
    /// confirmed boot.
    pub genuine: u32,
    /// Rollbacks after which stock firmware got no answer either.
    pub network: u32,
    /// A rollback waits for a stock boot to judge it.
    pub pending: bool,
}

/// What a stock boot made of the pending rollback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Judgement {
    /// Stock firmware got no answer either: try the image again later.
    Network,
    /// Stock firmware answered: the image's `count`th failure. At
    /// `GENUINE_LIMIT` the quarantine sticks.
    Genuine { count: u32, sticks: bool },
}

impl Judgement {
    /// The quarantine comes off for a later boot.
    pub fn retries(self) -> bool {
        !matches!(self, Judgement::Genuine { sticks: true, .. })
    }

    /// Stock firmware answered, so the network is up now: reboot to try the
    /// image again at once rather than at some later boot, which could meet
    /// the next outage.
    pub fn retests(self) -> bool {
        matches!(self, Judgement::Genuine { sticks: false, .. })
    }
}

impl Verdict {
    /// An unreadable count counts as the limit, and an unreadable `pending`
    /// as no: a damaged record keeps the quarantine.
    pub fn parse(text: &str) -> Self {
        let mut verdict = Self::default();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim();
            match key.trim() {
                "gzip" => verdict.gzip = value.to_ascii_lowercase(),
                "genuine" => verdict.genuine = value.parse().unwrap_or(GENUINE_LIMIT),
                "network" => verdict.network = value.parse().unwrap_or(0),
                "pending" => verdict.pending = value == "1",
                _ => {}
            }
        }
        verdict
    }

    pub fn render(&self) -> String {
        format!(
            "gzip={}\ngenuine={}\nnetwork={}\npending={}\n",
            self.gzip,
            self.genuine,
            self.network,
            u8::from(self.pending)
        )
    }

    /// The record after a rollback of `sha`: its counts carry over, and any
    /// other image's are dropped.
    pub fn rolled_back(&self, sha: &str) -> Self {
        let sha = sha.to_ascii_lowercase();
        let mut next = if self.gzip == sha {
            self.clone()
        } else {
            Self {
                gzip: sha,
                ..Self::default()
            }
        };
        next.pending = true;
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
            Judgement::Genuine {
                count: next.genuine,
                sticks: next.genuine >= GENUINE_LIMIT,
            }
        } else {
            next.network = next.network.saturating_add(1);
            Judgement::Network
        };
        (next, judgement)
    }

    /// The image's quarantine sticks until an operator retries it.
    pub fn sticks(&self) -> bool {
        self.genuine >= GENUINE_LIMIT
    }

    /// A stock boot found the strikes for `sha`, the default image, at the
    /// limit with no rollback recorded: its boots ended before their confirm
    /// decided anything. The record that makes this boot judge them as one
    /// rollback, or `None` when there is nothing to judge: the strikes are
    /// below the limit, a rollback already waits, or the image is quarantined
    /// already (an earlier record stands, stuck or not).
    pub fn stopped(&self, sha: &str, at_limit: bool, quarantined: bool) -> Option<Self> {
        let stuck = self.gzip.eq_ignore_ascii_case(sha) && self.sticks();
        (at_limit && !quarantined && !self.pending && !stuck).then(|| self.rolled_back(sha))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE: &str = "3348aa361c4689c4ff18b647a03bfa55cea36bc6675059cd9995e591592e40bb";

    #[test]
    fn a_tower_outage_never_counts_against_the_image() {
        let mut verdict = Verdict::default();
        for outage in 1..=5 {
            verdict = verdict.rolled_back(IMAGE);
            assert!(verdict.pending);
            let (next, judgement) = verdict.judge(false);
            assert_eq!(judgement, Judgement::Network);
            assert!(judgement.retries() && !judgement.retests(), "no reboot");
            assert_eq!(
                (next.genuine, next.network, next.pending),
                (0, outage, false)
            );
            verdict = next;
        }
        assert!(!verdict.sticks());
    }

    #[test]
    fn a_bad_image_sticks_after_two_failures_where_stock_answered() {
        let (once, first) = Verdict::default().rolled_back(IMAGE).judge(true);
        assert_eq!(
            first,
            Judgement::Genuine {
                count: 1,
                sticks: false
            }
        );
        assert!(
            first.retries() && first.retests(),
            "one failure: tried again at once"
        );
        let (twice, second) = once.rolled_back(IMAGE).judge(true);
        assert_eq!(
            second,
            Judgement::Genuine {
                count: 2,
                sticks: true
            }
        );
        assert!(!second.retries() && !second.retests());
        assert!(twice.sticks());
        // The tower was back by stock's watch but not by the image's (a site
        // power cut): the retry confirms and the failure is forgotten.
        let retried = once.confirmed(IMAGE);
        assert_eq!((retried.genuine, retried.pending), (0, false));
        assert_eq!(
            retried.rolled_back(IMAGE).judge(true).1,
            Judgement::Genuine {
                count: 1,
                sticks: false
            }
        );
    }

    #[test]
    fn another_image_starts_its_own_count_and_a_damaged_record_keeps_the_quarantine() {
        let old = Verdict {
            gzip: "ab".repeat(32),
            genuine: 1,
            network: 3,
            pending: false,
        };
        let new = old.rolled_back(IMAGE);
        assert_eq!(
            new,
            Verdict {
                gzip: IMAGE.into(),
                genuine: 0,
                network: 0,
                pending: true
            }
        );
        assert_eq!(Verdict::parse(&new.render()), new);
        let damaged = Verdict::parse(&format!("gzip={IMAGE}\ngenuine=x\npending=1\n"));
        assert!(damaged.sticks());
        assert!(!Verdict::parse(&format!("gzip={IMAGE}\npending=yes\n")).pending);
        assert_eq!(Verdict::parse(""), Verdict::default());
        // Confirming another image leaves this one's rollback waiting.
        assert!(new.confirmed(&"cd".repeat(32)).pending);
        assert!(!new.confirmed(&IMAGE.to_uppercase()).pending);
    }

    #[test]
    fn boots_cut_short_before_their_confirm_are_judged_as_one_rollback() {
        let once = Verdict {
            gzip: IMAGE.into(),
            genuine: 1,
            network: 2,
            pending: false,
        };
        // Two boots died after their strikes: one rollback, counts kept.
        let recorded = once.stopped(IMAGE, true, false).expect("judged");
        assert_eq!(
            recorded,
            Verdict {
                pending: true,
                ..once.clone()
            }
        );
        assert_eq!(recorded.judge(false).1, Judgement::Network);
        // Nothing to judge: below the limit, already waiting, or quarantined
        // already (a record whose verdict could not be written stays put).
        assert_eq!(once.stopped(IMAGE, false, false), None);
        assert_eq!(recorded.stopped(IMAGE, true, false), None);
        assert_eq!(once.stopped(IMAGE, true, true), None);
        // A stuck image stays stuck, but another image starts afresh.
        let (stuck, _) = recorded.judge(true);
        assert!(stuck.sticks());
        assert_eq!(stuck.stopped(IMAGE, true, false), None);
        let other = "cd".repeat(32);
        assert_eq!(
            stuck.stopped(&other, true, false),
            Some(Verdict::default().rolled_back(&other))
        );
    }
}
