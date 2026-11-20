//! The vendor kernel's "external device" in IP passthrough.
//!
//! This is the fault behind a Titan that stays attached but goes deaf. It was
//! reproduced and repaired on a bench unit on 2026-11-20.
//!
//! The vendor kernel keeps one "external device" for its hardware forwarding
//! path. In NAT mode that is the LTE bearer. In IP passthrough `rcinit` ends
//! bearer setup with `kern netif extdev lte0pdn0 down`, and the kernel log
//! shows `external_dev=NULL`.
//!
//! Whenever Linux processes a router advertisement prefix (or an IPv4 address
//! change) on the management bearer, the kernel sets the external device again:
//! `set external_dev: lte0pdn0 ipv6 mask=50`. Later nothing clears it, and two
//! things follow:
//!
//! 1. Customer IPv4 through the bridge stops at once.
//! 2. At the next DHCP or ARP from the customer router, the LTE driver stores
//!    that router's MAC as the destination address of the management bearer.
//!    Downlink frames on `lte0pdn0` then carry a MAC that is not the
//!    interface's own, Linux drops them as `PACKET_OTHERHOST`, and the unit
//!    hears nothing on its own addresses. A re-attach does not undo this.
//!
//! Both are undone without a reboot: clear the external device, then set the
//! bearer's MAC to itself, which makes the driver store its own address again.
//! Both commands change nothing on a healthy unit.
//!
//! The keeper follows the kernel log. When the external device stays set for
//! `GRACE` seconds while the customer bearer is a port of the LAN bridge, it
//! repairs.
//!
//! The bridge is the test for "bearer setup is over". At every attach the
//! kernel sets the external device first, and `rcinit` clears it only when it
//! puts the customer bearer into the bridge, 10 to 20 seconds later (measured
//! on two boots and one re-attach, 2026-11-20). On a detach the bearer leaves
//! the bridge again. A guard that counted from the `set` line fired in the
//! middle of that setup every time.

/// Seconds the external device may stay set once the keeper is ready to act.
/// `rcinit` clears it 0.1 to 0.2 s after the bridge port appears.
pub const GRACE: u64 = 3;
/// The grace once the bridge has been in place for `SETTLE` seconds. By then
/// bearer setup is long over and nothing else clears the external device, so
/// every second of waiting is a second without customer IPv4 (3.1 s measured
/// with `GRACE` alone).
pub const SETTLED_GRACE: u64 = 1;
/// Seconds the customer bearer has to be a bridge port before the short grace
/// applies.
pub const SETTLE: u64 = 10;
/// At most one repair per this many seconds.
pub const RETRY: u64 = 10;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// `set external_dev: <dev> ...`
    Set(String),
    /// `external_dev=NULL`
    Cleared,
}

/// The message of one kernel log line. `/dev/kmsg` records carry a
/// `level,sequence,time,flags;` prefix. `dmesg` output does not.
fn message(line: &str) -> &str {
    if let Some((head, rest)) = line.split_once(';') {
        let looks_like_prefix = head.contains(',')
            && head
                .chars()
                .all(|c| c.is_ascii_digit() || c == ',' || c == '-');
        if looks_like_prefix {
            return rest.trim();
        }
    }
    line.trim()
}

/// A kernel log line that changes the external device, if it is one.
pub fn parse(line: &str) -> Option<Event> {
    let text = message(line);
    if text == "external_dev=NULL" {
        return Some(Event::Cleared);
    }
    let rest = text.strip_prefix("set external_dev:")?;
    let dev = rest.split_whitespace().next()?;
    is_lte_bearer(dev).then(|| Event::Set(dev.to_owned()))
}

/// `lte0pdn0` to `lte0pdn15`.
pub fn is_lte_bearer(name: &str) -> bool {
    name.strip_prefix("lte0pdn")
        .is_some_and(|rest| !rest.is_empty() && rest.len() <= 2 && rest.bytes().all(|b| b.is_ascii_digit()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Hold,
    /// Clear the external device and restore this bearer's own MAC.
    Repair(String),
}

#[derive(Default)]
pub struct Watch {
    dev: Option<String>,
    /// The first tick at which the keeper was ready and saw `dev` set.
    since: Option<u64>,
    retry_at: u64,
}

impl Watch {
    /// Feed one event, in log order. The time an old line was read says
    /// nothing about when it happened, so events carry no time.
    pub fn note(&mut self, event: Event) {
        match event {
            Event::Set(dev) => {
                if self.dev.as_deref() != Some(dev.as_str()) {
                    self.since = None;
                }
                self.dev = Some(dev);
            }
            Event::Cleared => {
                self.dev = None;
                self.since = None;
            }
        }
    }

    /// The bearer the kernel currently treats as external, if any.
    pub fn external(&self) -> Option<&str> {
        self.dev.as_deref()
    }

    /// Once per tick. `ready` means all of: IP passthrough, the customer
    /// bearer is a port of the LAN bridge, and the kernel log has been read to
    /// its end. `settled` means it has been a bridge port for `SETTLE`
    /// seconds. `customer` is that bearer. The keeper never touches it: its
    /// stored MAC has to be the router's.
    pub fn decide(&mut self, now: u64, ready: bool, settled: bool, customer: &str) -> Action {
        let Some(dev) = self.dev.clone() else {
            return Action::Hold;
        };
        if !ready || dev == customer {
            self.since = None;
            return Action::Hold;
        }
        let since = *self.since.get_or_insert(now);
        let grace = if settled { SETTLED_GRACE } else { GRACE };
        if now.saturating_sub(since) < grace || now < self.retry_at {
            return Action::Hold;
        }
        self.retry_at = now + RETRY;
        Action::Repair(dev)
    }
}

/// The two repair commands, in order. `mac` is the bearer's own address from
/// `/sys/class/net/<dev>/address`.
pub fn repair_commands(dev: &str, mac: &str) -> [(&'static str, Vec<String>); 2] {
    [
        (
            "kern",
            vec!["netif".into(), "extdev".into(), dev.into(), "down".into()],
        ),
        (
            "ip",
            vec![
                "link".into(),
                "set".into(),
                "dev".into(),
                dev.into(),
                "address".into(),
                mac.into(),
            ],
        ),
    ]
}

/// The LTE port of the customer bridge, from the names in
/// `/sys/class/net/br0/brif`. The lowest-numbered one if there are several.
pub fn bridged_bearer<'a>(ports: impl Iterator<Item = &'a str>) -> Option<String> {
    let mut found: Vec<&str> = ports.filter(|name| is_lte_bearer(name)).collect();
    found.sort_by_key(|name| name["lte0pdn".len()..].parse::<u8>().unwrap_or(u8::MAX));
    found.first().map(|name| (*name).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_log_lines_are_read_with_and_without_the_kmsg_prefix() {
        assert_eq!(
            parse("6,4615,107494000,-;set external_dev: lte0pdn0 ipv6 mask=50"),
            Some(Event::Set("lte0pdn0".into()))
        );
        assert_eq!(
            parse("set external_dev: lte0pdn0 ipv4 mask=50"),
            Some(Event::Set("lte0pdn0".into()))
        );
        assert_eq!(parse("4,4632,1,-;external_dev=NULL"), Some(Event::Cleared));
        assert_eq!(parse("external_dev=NULL\n"), Some(Event::Cleared));
        // A clear of one family is followed by its own set line. It is not the end state.
        assert_eq!(parse("clear external_dev: lte0pdn0 ipv4 mask=40"), None);
        assert_eq!(parse("set external_dev: eth0 ipv4 mask=50"), None);
        assert_eq!(parse("V6Q: [3] up ipv6: 2001:db8::1(lte0pdn0)"), None);
        assert_eq!(parse(" SUBSYSTEM=net; set external_dev: lte0pdn0"), None);
    }

    #[test]
    fn bearer_setup_is_left_alone_until_the_bridge_is_built() {
        // Measured on a re-attach: set at attach, bridge port 17 s later,
        // the vendor's own clear 0.1 s after that.
        let mut watch = Watch::default();
        watch.note(Event::Set("lte0pdn0".into()));
        for now in 100..117 {
            assert_eq!(watch.decide(now, false, false, "lte0pdn2"), Action::Hold);
        }
        // The bridge port is there. The count starts now, not at the set line.
        assert_eq!(watch.decide(117, true, false, "lte0pdn2"), Action::Hold);
        watch.note(Event::Cleared);
        assert_eq!(watch.decide(118, true, false, "lte0pdn2"), Action::Hold);
        assert_eq!(watch.decide(500, true, false, "lte0pdn2"), Action::Hold);
        assert_eq!(watch.external(), None);
    }

    #[test]
    fn old_lines_replayed_at_start_do_not_count_as_waiting_time() {
        let mut watch = Watch::default();
        // Read while still behind in the log: not ready.
        watch.note(Event::Set("lte0pdn0".into()));
        assert_eq!(watch.decide(50, false, false, "lte0pdn2"), Action::Hold);
        assert_eq!(watch.decide(90, false, false, "lte0pdn2"), Action::Hold);
        // Caught up and still set: the full grace runs from here.
        assert_eq!(watch.decide(91, true, false, "lte0pdn2"), Action::Hold);
        assert_eq!(watch.decide(91 + GRACE - 1, true, false, "lte0pdn2"), Action::Hold);
        assert_eq!(
            watch.decide(91 + GRACE, true, false, "lte0pdn2"),
            Action::Repair("lte0pdn0".into())
        );
    }

    #[test]
    fn an_external_device_left_set_in_passthrough_is_repaired_once_per_retry() {
        let mut watch = Watch::default();
        watch.note(Event::Set("lte0pdn0".into()));
        assert_eq!(watch.decide(100, true, false, "lte0pdn2"), Action::Hold);
        // The same device set again (the IPv4 line after the IPv6 one) keeps the first time.
        watch.note(Event::Set("lte0pdn0".into()));
        assert_eq!(watch.decide(101, true, false, "lte0pdn2"), Action::Hold);
        assert_eq!(
            watch.decide(100 + GRACE, true, false, "lte0pdn2"),
            Action::Repair("lte0pdn0".into())
        );
        assert_eq!(watch.decide(100 + GRACE + 1, true, false, "lte0pdn2"), Action::Hold);
        // The repair command's own log line clears the state.
        watch.note(Event::Cleared);
        assert_eq!(watch.decide(500, true, false, "lte0pdn2"), Action::Hold);
        // If the log line never came, it tries again after the retry time.
        watch.note(Event::Set("lte0pdn0".into()));
        assert_eq!(watch.decide(600, true, false, "lte0pdn2"), Action::Hold);
        assert_eq!(
            watch.decide(600 + GRACE, true, false, "lte0pdn2"),
            Action::Repair("lte0pdn0".into())
        );
        assert_eq!(watch.decide(600 + GRACE + 5, true, false, "lte0pdn2"), Action::Hold);
        assert_eq!(
            watch.decide(600 + GRACE + RETRY, true, false, "lte0pdn2"),
            Action::Repair("lte0pdn0".into())
        );
    }

    #[test]
    fn a_detach_in_the_middle_of_the_grace_starts_the_count_again() {
        let mut watch = Watch::default();
        watch.note(Event::Set("lte0pdn0".into()));
        assert_eq!(watch.decide(100, true, false, "lte0pdn2"), Action::Hold);
        // The customer bearer left the bridge.
        assert_eq!(watch.decide(101, false, false, "lte0pdn2"), Action::Hold);
        assert_eq!(watch.decide(100 + GRACE, true, false, "lte0pdn2"), Action::Hold);
        assert_eq!(
            watch.decide(100 + 2 * GRACE, true, false, "lte0pdn2"),
            Action::Repair("lte0pdn0".into())
        );
    }

    #[test]
    fn a_settled_bridge_gets_the_short_grace() {
        let mut watch = Watch::default();
        watch.note(Event::Set("lte0pdn0".into()));
        assert_eq!(watch.decide(5000, true, true, "lte0pdn2"), Action::Hold);
        assert_eq!(
            watch.decide(5000 + SETTLED_GRACE, true, true, "lte0pdn2"),
            Action::Repair("lte0pdn0".into())
        );
        // Not ready still means hold, settled or not.
        let mut watch = Watch::default();
        watch.note(Event::Set("lte0pdn0".into()));
        for now in 5000..5100 {
            assert_eq!(watch.decide(now, false, true, "lte0pdn2"), Action::Hold);
        }
    }

    #[test]
    fn nat_mode_and_the_customer_bearer_are_never_touched() {
        let mut watch = Watch::default();
        watch.note(Event::Set("lte0pdn0".into()));
        for now in 100..900 {
            assert_eq!(watch.decide(now, false, false, "lte0pdn2"), Action::Hold);
        }
        let mut watch = Watch::default();
        watch.note(Event::Set("lte0pdn2".into()));
        for now in 100..900 {
            assert_eq!(watch.decide(now, true, false, "lte0pdn2"), Action::Hold);
        }
    }

    #[test]
    fn the_repair_is_the_vendor_clear_then_the_bearers_own_mac() {
        let commands = repair_commands("lte0pdn0", "44:6f:d8:80:13:21");
        assert_eq!(commands[0].0, "kern");
        assert_eq!(commands[0].1.join(" "), "netif extdev lte0pdn0 down");
        assert_eq!(commands[1].0, "ip");
        assert_eq!(
            commands[1].1.join(" "),
            "link set dev lte0pdn0 address 44:6f:d8:80:13:21"
        );
    }

    #[test]
    fn the_customer_bearer_is_the_lte_port_of_the_bridge() {
        assert_eq!(
            bridged_bearer(["eth0", "lte0pdn2"].into_iter()),
            Some("lte0pdn2".into())
        );
        assert_eq!(
            bridged_bearer(["lte0pdn10", "eth0", "lte0pdn1"].into_iter()),
            Some("lte0pdn1".into())
        );
        assert_eq!(bridged_bearer(["eth0", "wlan0"].into_iter()), None);
        assert!(is_lte_bearer("lte0pdn0"));
        assert!(is_lte_bearer("lte0pdn15"));
        assert!(!is_lte_bearer("lte0pdn"));
        assert!(!is_lte_bearer("lte0pdn2x"));
        assert!(!is_lte_bearer("lte0pdn123"));
    }
}
