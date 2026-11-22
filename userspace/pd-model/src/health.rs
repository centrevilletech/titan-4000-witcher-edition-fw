//! When the router looks unhealthy, and what to do about it.
//!
//! Escalation is re-announce, then restart our own responders, then a real
//! Ethernet link drop. It never re-attaches LTE. A link drop is spent from a
//! budget so a silent router cannot make the keeper flap the port forever.
//! Silence while LTE is down, or while the cable is unplugged, is not a
//! downstream failure, and the escalation starts over when both are back.
//! A live block that is not the pinned block stops service instead of
//! advertising a stale prefix.
//!
//! A link that carries traffic is never dropped, and neither is the link of a
//! router that has not spoken IPv6 since it was plugged in. Before v1.0.13 an
//! IPv4-only router behind a unit with delegation on lost its link three times
//! an hour, and a clock step at boot could drop a busy link. The step that was
//! due waits, without spending the budget, until the link is quiet.

pub const SILENCE_SECS: u64 = 45;
pub const REANNOUNCE_WAIT: u64 = 20;
pub const RESTART_WAIT: u64 = 30;
pub const LINK_DROP_WAIT: u64 = 90;
pub const MAX_LINK_DROPS: u32 = 3;
pub const WINDOW_SECS: u64 = 3600;
pub const BACKOFF_SECS: u64 = 900;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Reannounce,
    Restart,
    LinkDrop,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Health {
    pub phase: Phase,
    pub phase_since: u64,
    pub link_drops: u32,
    pub window_start: u64,
    pub quiet_until: u64,
}

impl Default for Health {
    fn default() -> Self {
        Self {
            phase: Phase::Idle,
            phase_since: 0,
            link_drops: 0,
            window_start: 0,
            quiet_until: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct View {
    pub now: u64,
    pub carrier_up: bool,
    pub lte_up: bool,
    /// False only when a live bearer /56 is present and it is not the pin.
    pub prefix_ok: bool,
    pub serving: bool,
    /// RS, DHCPv6, neighbour solicitation for us, a packet from the delegated
    /// prefix, a delegation still inside its lifetime, or a busy customer port.
    pub router_seen: bool,
    /// The router has sent IPv6 (a solicitation, a neighbour probe or DHCPv6)
    /// since it was last plugged in. A router that never speaks IPv6 gains
    /// nothing from a responder restart or a link drop.
    pub ipv6_router_heard: bool,
    /// The customer port's receive counter shows an idle link. An unreadable
    /// counter is not quiet: a link is never cut on a guess.
    pub link_quiet: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Hold,
    Reannounce,
    Restart,
    LinkDrop { repeats: u32 },
    StopServing,
    BudgetSpent,
}

impl Health {
    pub fn tick(&mut self, view: &View) -> Decision {
        self.refresh_window(view.now);
        if !view.prefix_ok {
            self.phase = Phase::Idle;
            self.phase_since = view.now;
            return Decision::StopServing;
        }
        // A radio or cable outage is not the router's fault. The escalation
        // starts over, so LTE coming back does not drop the link 30 s later.
        if !view.carrier_up || !view.lte_up {
            self.phase = Phase::Idle;
            self.phase_since = view.now;
            return Decision::Hold;
        }
        if view.router_seen {
            self.phase = Phase::Idle;
            self.phase_since = view.now;
            self.quiet_until = 0;
            return Decision::Hold;
        }
        if !view.serving {
            return Decision::Reannounce;
        }
        if view.now < self.quiet_until {
            // Same reboot case: a quiet-until from the previous clock is not a
            // backoff earned in this one.
            if self.quiet_until.saturating_sub(view.now) > BACKOFF_SECS {
                self.quiet_until = 0;
            } else {
                return Decision::Hold;
            }
        }
        let waited = view.now.saturating_sub(self.phase_since);
        match self.phase {
            Phase::Idle if waited >= SILENCE_SECS => {
                self.begin(Phase::Reannounce, view.now, Decision::Reannounce)
            }
            // Our responders serve IPv6 only. A router that never spoke it
            // gains nothing from a restart.
            Phase::Reannounce if waited >= REANNOUNCE_WAIT && view.ipv6_router_heard => {
                self.begin(Phase::Restart, view.now, Decision::Restart)
            }
            Phase::Restart if waited >= RESTART_WAIT => self.drop_quiet_link(view),
            Phase::LinkDrop if waited >= LINK_DROP_WAIT => self.drop_quiet_link(view),
            _ => Decision::Hold,
        }
    }

    /// The link drop that is due, only on a quiet link of a router that has
    /// spoken IPv6. Otherwise it waits, and no budget is spent.
    fn drop_quiet_link(&mut self, view: &View) -> Decision {
        if view.ipv6_router_heard && view.link_quiet {
            self.drop_link(view.now)
        } else {
            Decision::Hold
        }
    }

    fn refresh_window(&mut self, now: u64) {
        if self.window_start == 0 {
            self.window_start = now;
        } else if now < self.window_start || now.saturating_sub(self.window_start) >= WINDOW_SECS {
            self.window_start = now;
            self.link_drops = 0;
        }
        if self.quiet_until.saturating_sub(now) > BACKOFF_SECS {
            self.quiet_until = 0;
        }
    }

    /// IPv4 and IPv6 spend the same physical-port recovery budget. The IPv6
    /// escalation keeps its own step: an IPv4 recovery is not a step of it.
    pub fn request_link_recovery(&mut self, now: u64) -> Decision {
        self.refresh_window(now);
        if now < self.quiet_until {
            return Decision::BudgetSpent;
        }
        let (phase, since) = (self.phase, self.phase_since);
        let decision = self.drop_link(now);
        self.phase = phase;
        self.phase_since = since;
        decision
    }

    fn begin(&mut self, phase: Phase, now: u64, decision: Decision) -> Decision {
        self.phase = phase;
        self.phase_since = now;
        decision
    }

    fn drop_link(&mut self, now: u64) -> Decision {
        if self.link_drops >= MAX_LINK_DROPS {
            self.quiet_until = now + BACKOFF_SECS;
            self.phase = Phase::Idle;
            self.phase_since = now;
            return Decision::BudgetSpent;
        }
        let repeats = match self.link_drops {
            0 => 1,
            1 => 8,
            _ => 20,
        };
        self.link_drops += 1;
        self.phase = Phase::LinkDrop;
        self.phase_since = now;
        Decision::LinkDrop { repeats }
    }
}

pub fn decision_reason(decision: Decision) -> &'static str {
    match decision {
        Decision::Hold => "no action",
        Decision::Reannounce => "re-announce the prefix; the router has gone quiet",
        Decision::Restart => "restart responders; a re-announce did not restore the router",
        Decision::LinkDrop { .. } => "drop the Ethernet link; the router still looks down",
        Decision::StopServing => "stop serving; the live block is not the pinned block",
        Decision::BudgetSpent => "link-drop budget spent; waiting before trying again",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(now: u64) -> View {
        View {
            now,
            carrier_up: true,
            lte_up: true,
            prefix_ok: true,
            serving: true,
            router_seen: false,
            ipv6_router_heard: true,
            link_quiet: true,
        }
    }

    #[test]
    fn silence_escalates_and_then_stops_for_the_budget() {
        let mut health = Health::default();
        assert_eq!(health.tick(&view(10)), Decision::Hold);
        assert_eq!(health.tick(&view(10 + SILENCE_SECS)), Decision::Reannounce);
        assert_eq!(
            health.tick(&view(10 + SILENCE_SECS + REANNOUNCE_WAIT)),
            Decision::Restart
        );
        let dropped = 10 + SILENCE_SECS + REANNOUNCE_WAIT + RESTART_WAIT;
        assert_eq!(
            health.tick(&view(dropped)),
            Decision::LinkDrop { repeats: 1 }
        );
        assert_eq!(
            health.tick(&view(dropped + LINK_DROP_WAIT)),
            Decision::LinkDrop { repeats: 8 }
        );
        assert_eq!(
            health.tick(&view(dropped + 2 * LINK_DROP_WAIT)),
            Decision::LinkDrop { repeats: 20 }
        );
        assert_eq!(
            health.tick(&view(dropped + 3 * LINK_DROP_WAIT)),
            Decision::BudgetSpent
        );
        assert_eq!(
            health.tick(&view(dropped + 3 * LINK_DROP_WAIT + 1)),
            Decision::Hold
        );
        assert_eq!(health.link_drops, MAX_LINK_DROPS);
    }

    #[test]
    fn lte_down_carrier_down_and_a_mismatch_do_not_drop_the_link() {
        let mut health = Health::default();
        let mut down = view(1000);
        down.lte_up = false;
        assert_eq!(health.tick(&down), Decision::Hold);
        down.lte_up = true;
        down.carrier_up = false;
        assert_eq!(health.tick(&down), Decision::Hold);
        down.carrier_up = true;
        down.prefix_ok = false;
        assert_eq!(health.tick(&down), Decision::StopServing);
        assert_eq!(health.link_drops, 0);
        assert_eq!(health.phase, Phase::Idle);
    }

    #[test]
    fn a_router_sign_resets_the_step_and_not_the_budget() {
        let mut health = Health {
            phase: Phase::Restart,
            phase_since: 0,
            link_drops: 2,
            window_start: 0,
            quiet_until: 0,
        };
        let mut seen = view(50);
        seen.router_seen = true;
        assert_eq!(health.tick(&seen), Decision::Hold);
        assert_eq!(health.phase, Phase::Idle);
        assert_eq!(health.link_drops, 2);
    }

    #[test]
    fn a_rebooted_clock_does_not_keep_the_previous_budget() {
        let mut health = Health {
            phase: Phase::Idle,
            phase_since: 0,
            link_drops: MAX_LINK_DROPS,
            window_start: 500_000,
            quiet_until: 500_000,
        };
        assert_eq!(health.tick(&view(30)), Decision::Hold);
        assert_eq!(health.link_drops, 0);
        assert_eq!(health.quiet_until, 0);
        assert_eq!(health.window_start, 30);
    }

    #[test]
    fn not_serving_asks_for_an_announcement_without_dropping_the_link() {
        let mut health = Health::default();
        let mut starting = view(5);
        starting.serving = false;
        assert_eq!(health.tick(&starting), Decision::Reannounce);
        assert_eq!(health.link_drops, 0);
    }
    #[test]
    fn ipv4_requests_share_the_existing_port_budget() {
        let mut health = Health::default();
        for t in [100, 200, 300] {
            assert!(matches!(
                health.request_link_recovery(t),
                Decision::LinkDrop { .. }
            ));
        }
        assert_eq!(health.request_link_recovery(400), Decision::BudgetSpent);
        assert_eq!(health.request_link_recovery(500), Decision::BudgetSpent);
        assert_eq!(health.link_drops, 3);
        assert!(matches!(
            health.request_link_recovery(3800),
            Decision::LinkDrop { .. }
        ));
        assert_eq!(health.link_drops, 1);
    }

    #[test]
    fn a_link_that_carries_traffic_is_never_dropped() {
        let mut health = Health::default();
        let busy = |now| View {
            link_quiet: false,
            ..view(now)
        };
        assert_eq!(health.tick(&busy(10)), Decision::Hold);
        assert_eq!(health.tick(&busy(10 + SILENCE_SECS)), Decision::Reannounce);
        assert_eq!(
            health.tick(&busy(10 + SILENCE_SECS + REANNOUNCE_WAIT)),
            Decision::Restart
        );
        for t in (10 + SILENCE_SECS + REANNOUNCE_WAIT + 1)..2000 {
            assert_eq!(health.tick(&busy(t)), Decision::Hold, "{t}");
        }
        assert_eq!(health.link_drops, 0);
        // The link goes quiet, and the step that was due runs.
        assert_eq!(health.tick(&view(2000)), Decision::LinkDrop { repeats: 1 });
    }

    #[test]
    fn a_router_that_never_spoke_ipv6_is_neither_restarted_nor_dropped() {
        let mut health = Health::default();
        let v4_only = |now| View {
            ipv6_router_heard: false,
            ..view(now)
        };
        assert_eq!(health.tick(&v4_only(0)), Decision::Hold);
        assert_eq!(health.tick(&v4_only(SILENCE_SECS)), Decision::Reannounce);
        for t in (SILENCE_SECS + 1)..5000 {
            assert_eq!(health.tick(&v4_only(t)), Decision::Hold, "{t}");
        }
        assert_eq!(health.link_drops, 0);
    }

    #[test]
    fn an_ipv4_link_recovery_leaves_the_ipv6_step_alone() {
        let mut health = Health {
            phase_since: 100,
            ..Health::default()
        };
        assert_eq!(health.tick(&view(100)), Decision::Hold);
        assert!(matches!(
            health.request_link_recovery(105),
            Decision::LinkDrop { .. }
        ));
        assert_eq!(health.link_drops, 1);
        assert_eq!(health.phase, Phase::Idle);
        // IPv6 silence still begins at the first step, not at a link drop.
        assert_eq!(
            health.tick(&view(100 + SILENCE_SECS)),
            Decision::Reannounce
        );
    }

    #[test]
    fn an_outage_restarts_the_escalation_from_the_first_step() {
        let mut health = Health {
            phase_since: 100,
            ..Health::default()
        };
        assert_eq!(health.tick(&view(100)), Decision::Hold);
        assert_eq!(health.tick(&view(100 + SILENCE_SECS)), Decision::Reannounce);
        assert_eq!(
            health.tick(&view(100 + SILENCE_SECS + REANNOUNCE_WAIT)),
            Decision::Restart
        );
        for t in 170..200 {
            let down = View {
                lte_up: false,
                ..view(t)
            };
            assert_eq!(health.tick(&down), Decision::Hold);
        }
        assert_eq!(health.phase, Phase::Idle);
        // LTE is back at 200. The restart step was due, but the escalation
        // starts over: first a re-announce after the usual silence.
        assert_eq!(health.tick(&view(200)), Decision::Hold);
        assert_eq!(health.tick(&view(199 + RESTART_WAIT)), Decision::Hold);
        assert_eq!(
            health.tick(&view(199 + SILENCE_SECS)),
            Decision::Reannounce
        );
    }
}
