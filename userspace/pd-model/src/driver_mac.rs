//! Keep the LTE driver's downlink MAC on the customer router in IP passthrough.
//!
//! The vendor LTE driver writes a destination MAC on every downlink IPv6 frame
//! of the customer bearer. It learns that MAC from the ARP requests it answers
//! on the bearer, whoever sends them. About a minute after a handover the
//! vendor restarts its firewall, and the unit itself then ARPs for the SAS host
//! (`<sas ip> dev br0 scope link`) from its own MAC. From that moment the driver
//! sends the customer's IPv6 to the unit instead of the router, and it stays
//! that way until the router's next ARP. IPv4 keeps working. Proven on the
//! bench Titan 2026-11-21: outages of 3 to 30 s on demand, up to 2 minutes in
//! the field.
//!
//! In passthrough the unit forwards no IPv6 of its own, so a rise in the
//! kernel's `Ip6OutForwDatagrams` means the driver has the wrong MAC. One ARP
//! request from the router's MAC, sent out the bearer, puts it back. The router
//! only sees the driver's ARP reply, which matches what it already knows.

use std::net::Ipv4Addr;

/// Seconds between two corrections.
pub const GAP: u64 = 2;
/// A rise this long after the last one starts a new episode.
pub const QUIET: u64 = 10;
/// Corrections in one episode before the keeper stops trying for a while.
pub const TRIES: u32 = 8;
/// How long it then waits.
pub const PAUSE: u64 = 120;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Hold,
    /// Send the router's ARP to the driver now.
    Correct,
    /// The unit keeps forwarding after `TRIES` corrections. Something else is
    /// routing through it; stop for `PAUSE`.
    GiveUp,
}

#[derive(Default, Debug)]
pub struct Watch {
    last_count: Option<u64>,
    last_rise: Option<u64>,
    last_sent: Option<u64>,
    tries: u32,
    paused_until: u64,
}

impl Watch {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// `count` is the kernel's forwarded-datagram total, `ready` means IP
    /// passthrough with the customer bearer bridged and the router known.
    pub fn tick(&mut self, now: u64, count: Option<u64>, ready: bool) -> Action {
        let Some(count) = count else {
            return Action::Hold;
        };
        let previous = self.last_count.replace(count);
        if !ready {
            self.tries = 0;
            self.last_rise = None;
            return Action::Hold;
        }
        // The first reading is only a baseline; a smaller one is a reset.
        let Some(previous) = previous else {
            return Action::Hold;
        };
        if count <= previous {
            return Action::Hold;
        }
        if self
            .last_rise
            .is_none_or(|rise| now.saturating_sub(rise) > QUIET)
        {
            self.tries = 0;
        }
        self.last_rise = Some(now);
        if now < self.paused_until {
            return Action::Hold;
        }
        if self
            .last_sent
            .is_some_and(|sent| now.saturating_sub(sent) < GAP)
        {
            return Action::Hold;
        }
        if self.tries >= TRIES {
            self.tries = 0;
            self.paused_until = now + PAUSE;
            return Action::GiveUp;
        }
        self.tries += 1;
        self.last_sent = Some(now);
        Action::Correct
    }
}

/// `Ip6OutForwDatagrams` from `/proc/net/snmp6`.
pub fn forwarded(snmp6: &str) -> Option<u64> {
    snmp6.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next()? == "Ip6OutForwDatagrams")
            .then(|| fields.next()?.parse().ok())
            .flatten()
    })
}

/// Broadcast ARP request from the router: who has `gateway`, tell
/// `router_ip` at `router_mac`. The same frame the router sends itself.
pub fn correction(router_mac: [u8; 6], router_ip: Ipv4Addr, gateway: Ipv4Addr) -> Vec<u8> {
    let mut frame = Vec::with_capacity(42);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&router_mac);
    frame.extend_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
    frame.extend_from_slice(&router_mac);
    frame.extend_from_slice(&router_ip.octets());
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(&gateway.octets());
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNMP6: &str = "Ip6InReceives                   \t 7\nIp6OutForwDatagrams             \t42\nIp6InDelivers  9\n";

    #[test]
    fn the_forwarded_count_parses() {
        assert_eq!(forwarded(SNMP6), Some(42));
        assert_eq!(forwarded("Ip6InReceives 7\n"), None);
        assert_eq!(forwarded(""), None);
    }

    #[test]
    fn the_correction_is_the_routers_own_arp_request() {
        let mac = [0x22, 0x98, 0x5f, 0x3a, 0xbd, 0x7b];
        let frame = correction(mac, "172.20.64.34".parse().unwrap(), "172.20.64.33".parse().unwrap());
        assert_eq!(frame.len(), 42);
        assert_eq!(frame[..6], [0xff; 6]);
        assert_eq!(frame[6..12], mac);
        assert_eq!(frame[12..14], [8, 6]);
        assert_eq!(frame[20..22], [0, 1], "request");
        assert_eq!(frame[22..28], mac, "sender MAC");
        assert_eq!(frame[28..32], [172, 20, 64, 34], "sender IP");
        assert_eq!(frame[32..38], [0; 6]);
        assert_eq!(frame[38..42], [172, 20, 64, 33], "target IP");
    }

    #[test]
    fn a_rise_while_ready_corrects_once_per_gap() {
        let mut watch = Watch::default();
        assert_eq!(watch.tick(100, Some(5), true), Action::Hold, "baseline");
        assert_eq!(watch.tick(100, Some(5), true), Action::Hold);
        assert_eq!(watch.tick(101, Some(7), true), Action::Correct);
        assert_eq!(watch.tick(101, Some(9), true), Action::Hold, "inside the gap");
        assert_eq!(watch.tick(102, Some(9), true), Action::Hold, "no rise");
        assert_eq!(watch.tick(103, Some(10), true), Action::Correct);
    }

    #[test]
    fn nothing_happens_outside_passthrough_or_on_a_counter_reset() {
        let mut watch = Watch::default();
        watch.tick(10, Some(5), false);
        assert_eq!(watch.tick(11, Some(50), false), Action::Hold);
        assert_eq!(watch.tick(12, Some(51), true), Action::Correct);
        assert_eq!(watch.tick(20, Some(3), true), Action::Hold, "smaller count");
        assert_eq!(watch.tick(21, None, true), Action::Hold);
    }

    #[test]
    fn steady_forwarding_gives_up_then_tries_again_after_the_pause() {
        let mut watch = Watch::default();
        let mut count = 0;
        watch.tick(0, Some(count), true);
        let mut corrections = 0;
        let mut gave_up_at = None;
        for now in 1..200 {
            count += 3;
            match watch.tick(now, Some(count), true) {
                Action::Correct => corrections += 1,
                Action::GiveUp => {
                    gave_up_at = Some(now);
                    break;
                }
                Action::Hold => {}
            }
        }
        assert_eq!(corrections, TRIES);
        let gave_up_at = gave_up_at.expect("gives up");
        for now in gave_up_at + 1..gave_up_at + PAUSE {
            count += 3;
            assert_eq!(watch.tick(now, Some(count), true), Action::Hold, "paused at {now}");
        }
        count += 3;
        assert_eq!(watch.tick(gave_up_at + PAUSE, Some(count), true), Action::Correct);
    }

    #[test]
    fn a_quiet_spell_starts_a_new_episode() {
        let mut watch = Watch::default();
        let mut count = 0;
        watch.tick(0, Some(count), true);
        for round in 0..3u64 {
            let start = 1 + round * 100;
            for now in start..start + 2 * (TRIES as u64 - 1) {
                count += 1;
                assert_ne!(watch.tick(now, Some(count), true), Action::GiveUp, "round {round} at {now}");
            }
        }
    }
}
