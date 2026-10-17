//! When the router looks unhealthy, and what to do about it.
//!
//! Escalation is re-announce, then restart our own responders, then a real
//! Ethernet link drop. It never re-attaches LTE. A link drop is spent from a
//! budget so a silent router cannot make the keeper flap the port forever.
//! Silence while LTE is down, or while the cable is unplugged, is not a
//! downstream failure. A live block that is not the pinned block stops
//! service instead of advertising a stale prefix.

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
    /// RS, DHCPv6, neighbour solicitation for us, or a packet from the delegated prefix.
    pub router_seen: bool,
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
        // A radio or cable outage is not the router's fault, and the step
        // clock restarts so LTE coming back does not immediately drop the link.
        if !view.carrier_up || !view.lte_up {
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
            Phase::Reannounce if waited >= REANNOUNCE_WAIT => {
                self.begin(Phase::Restart, view.now, Decision::Restart)
            }
            Phase::Restart if waited >= RESTART_WAIT => self.drop_link(view.now),
            Phase::LinkDrop if waited >= LINK_DROP_WAIT => self.drop_link(view.now),
            _ => Decision::Hold,
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

    /// IPv4 and IPv6 spend the same physical-port recovery budget.
    pub fn request_link_recovery(&mut self, now: u64) -> Decision {
        self.refresh_window(now);
        if now < self.quiet_until {
            return Decision::BudgetSpent;
        }
        self.drop_link(now)
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
}
