//! The vendor kernel's IPv4 host MAC in IP passthrough, and router swaps.
//!
//! In IP passthrough the vendor kernel (`netif_enqueue`, `net_mode` 2) writes
//! one stored MAC as the destination of every IPv4 frame it hands to the LAN
//! from the customer bearer, the LTE driver's ARP answers for the gateway
//! included. It learns that MAC from the first eth0 frame after boot, logs
//! `usb0 set host mac: <mac>`, and sets a learned flag that only an eth0 probe
//! or remove clears (`netif_set_host_mac` 0x8026f1c0, flag `gdm_net_if+0x2aa`).
//! IPv6 does not go through it: the LTE driver addresses IPv6 to the MAC of
//! the last ARP request it answered (see `driver_mac`).
//!
//! So after a router swap the unit kept sending IPv4 to the old router. The new
//! router got its DHCP lease and IPv6, but no answer for its gateway, until the
//! Titan rebooted. Found on the bench on 2026-11-24 with a laptop in place of
//! the bench router: the driver answered each of the laptop's ARP requests for
//! the gateway, and the kernel addressed every answer to the old router.
//!
//! The vendor's own command sets the stored MAC: `kern netif hmac <hostif>
//! <mac>` (`kern_netif`, then `netif_set_dev_mac` 0x8026f16c). It logs the same
//! line. The keeper follows the stored MAC in the kernel log and points it at
//! the router that holds the customer DHCP lease whenever the two differ.

use crate::ipv4::mac_text;

/// The host interface name the vendor kernel stores (`gdm_net_if+0x284`),
/// used until the kernel log names it.
pub const DEFAULT_HOSTIF: &str = "usb0";
/// Seconds between two commands for the same router.
pub const GAP: u64 = 5;
/// Commands for one router before a pause. Each one the kernel takes logs the
/// stored MAC, so more than one means the log line did not come.
pub const TRIES: u32 = 4;
/// Seconds to wait after `TRIES` commands that changed nothing in the log.
pub const PAUSE: u64 = 120;

/// The MAC the vendor kernel addresses IPv4 to, and its host interface name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stored {
    pub hostif: String,
    pub mac: [u8; 6],
}

/// `usb0 set host mac: 22:98:5f:3a:bd:7b`, with or without a `/dev/kmsg`
/// prefix.
pub fn parse(line: &str) -> Option<Stored> {
    let (hostif, mac) = crate::extdev::message(line).split_once(" set host mac: ")?;
    let hostif = hostif.trim();
    let usable_name = !hostif.is_empty()
        && hostif.len() <= 15
        && hostif.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.');
    if !usable_name {
        return None;
    }
    Some(Stored {
        hostif: hostif.to_owned(),
        mac: parse_mac(mac.trim())?,
    })
}

fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = text.split(':');
    for byte in &mut mac {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 2 {
            return None;
        }
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    parts.next().is_none().then_some(mac)
}

/// The vendor command that stores `mac` as the IPv4 host MAC.
pub fn command(hostif: &str, mac: [u8; 6]) -> (&'static str, Vec<String>) {
    (
        "kern",
        vec!["netif".into(), "hmac".into(), hostif.into(), mac_text(mac)],
    )
}

/// A unicast MAC that is not all zeros.
fn usable(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Hold,
    /// Run `command(hostif, to)`. `from` is the stored MAC, if the log named it.
    Point {
        hostif: String,
        from: Option<[u8; 6]>,
        to: [u8; 6],
    },
    /// `TRIES` commands for this router left the stored MAC unchanged.
    GiveUp { to: [u8; 6] },
}

#[derive(Default, Debug)]
pub struct Watch {
    stored: Option<Stored>,
    target: Option<[u8; 6]>,
    tries: u32,
    last_sent: Option<u64>,
    paused_until: u64,
}

impl Watch {
    /// A `set host mac` line from the kernel log. The last one is current.
    pub fn note(&mut self, stored: Stored) {
        self.stored = Some(stored);
    }

    pub fn stored(&self) -> Option<&Stored> {
        self.stored.as_ref()
    }

    /// Forget the attempts, not the stored MAC: that is the kernel's state.
    pub fn reset_attempts(&mut self) {
        self.target = None;
        self.tries = 0;
        self.last_sent = None;
        self.paused_until = 0;
    }

    /// `ready`: IP passthrough with the bearer in the bridge, and the boot
    /// backlog of the kernel log read, so `stored` is the latest. `router`:
    /// the MAC that holds the customer DHCP lease. `own`: the unit's own MACs,
    /// never a target.
    pub fn decide(&mut self, now: u64, ready: bool, router: Option<[u8; 6]>, own: &[[u8; 6]]) -> Action {
        let Some(router) = router.filter(|mac| ready && usable(*mac) && !own.contains(mac)) else {
            self.reset_attempts();
            return Action::Hold;
        };
        if self.stored.as_ref().is_some_and(|stored| stored.mac == router) {
            self.reset_attempts();
            return Action::Hold;
        }
        if self.target != Some(router) {
            self.reset_attempts();
            self.target = Some(router);
        }
        if now < self.paused_until {
            return Action::Hold;
        }
        if self.last_sent.is_some_and(|sent| now.saturating_sub(sent) < GAP) {
            return Action::Hold;
        }
        if self.tries >= TRIES {
            self.tries = 0;
            self.last_sent = None;
            self.paused_until = now.saturating_add(PAUSE);
            return Action::GiveUp { to: router };
        }
        self.tries += 1;
        self.last_sent = Some(now);
        Action::Point {
            hostif: self
                .stored
                .as_ref()
                .map_or(DEFAULT_HOSTIF, |stored| stored.hostif.as_str())
                .to_owned(),
            from: self.stored.as_ref().map(|stored| stored.mac),
            to: router,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: [u8; 6] = [0x22, 0x98, 0x5f, 0x3a, 0xbd, 0x7b];
    const NEW: [u8; 6] = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x01];
    const UNIT: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x13, 0x21];

    fn stored(mac: [u8; 6]) -> Stored {
        Stored { hostif: "usb0".into(), mac }
    }

    #[test]
    fn the_kernel_line_parses_with_and_without_the_kmsg_prefix() {
        assert_eq!(parse("usb0 set host mac: 22:98:5f:3a:bd:7b"), Some(stored(OLD)));
        assert_eq!(parse("6,1234,65790000,-;usb0 set host mac: 22:98:5f:3a:bd:7b"), Some(stored(OLD)));
        assert_eq!(parse("  eth9 set host mac: 02:00:5e:10:00:01\n"), Some(Stored { hostif: "eth9".into(), mac: NEW }));
    }

    #[test]
    fn other_lines_and_broken_macs_do_not_parse() {
        assert_eq!(parse("external_dev=NULL"), None);
        assert_eq!(parse("usb0 set host mac: 22:98:5f:3a:bd"), None);
        assert_eq!(parse("usb0 set host mac: 22:98:5f:3a:bd:7b:01"), None);
        assert_eq!(parse("usb0 set host mac: 22:98:5f:3a:bd:zz"), None);
        assert_eq!(parse(" set host mac: 22:98:5f:3a:bd:7b"), None);
        assert_eq!(parse("a b set host mac: 22:98:5f:3a:bd:7b"), None);
    }

    #[test]
    fn the_command_is_the_vendors_hmac() {
        assert_eq!(
            command("usb0", NEW),
            ("kern", vec!["netif".into(), "hmac".into(), "usb0".into(), "02:00:5e:10:00:01".into()])
        );
    }

    #[test]
    fn a_new_router_moves_the_stored_mac_once() {
        let mut watch = Watch::default();
        watch.note(stored(OLD));
        assert_eq!(
            watch.decide(10, true, Some(NEW), &[UNIT]),
            Action::Point { hostif: "usb0".into(), from: Some(OLD), to: NEW }
        );
        // The kernel logs the new MAC: nothing more to do.
        watch.note(stored(NEW));
        assert_eq!(watch.decide(11, true, Some(NEW), &[UNIT]), Action::Hold);
        assert_eq!(watch.decide(30, true, Some(NEW), &[UNIT]), Action::Hold);
    }

    #[test]
    fn the_same_router_needs_nothing() {
        let mut watch = Watch::default();
        watch.note(stored(OLD));
        assert_eq!(watch.decide(10, true, Some(OLD), &[UNIT]), Action::Hold);
    }

    #[test]
    fn nothing_happens_before_the_keeper_is_ready_or_without_a_lease() {
        let mut watch = Watch::default();
        watch.note(stored(OLD));
        assert_eq!(watch.decide(10, false, Some(NEW), &[UNIT]), Action::Hold);
        assert_eq!(watch.decide(11, true, None, &[UNIT]), Action::Hold);
    }

    #[test]
    fn never_the_units_own_mac_or_a_group_or_zero_mac() {
        let mut watch = Watch::default();
        watch.note(stored(OLD));
        assert_eq!(watch.decide(10, true, Some(UNIT), &[UNIT]), Action::Hold);
        assert_eq!(watch.decide(11, true, Some([0xff; 6]), &[UNIT]), Action::Hold);
        assert_eq!(watch.decide(12, true, Some([0x01, 0, 0x5e, 0, 0, 1]), &[UNIT]), Action::Hold);
        assert_eq!(watch.decide(13, true, Some([0; 6]), &[UNIT]), Action::Hold);
    }

    #[test]
    fn an_unknown_stored_mac_is_set_once_on_the_default_host_interface() {
        let mut watch = Watch::default();
        assert_eq!(
            watch.decide(10, true, Some(NEW), &[UNIT]),
            Action::Point { hostif: DEFAULT_HOSTIF.into(), from: None, to: NEW }
        );
        watch.note(stored(NEW));
        assert_eq!(watch.decide(20, true, Some(NEW), &[UNIT]), Action::Hold);
    }

    #[test]
    fn retries_are_spaced_then_pause_when_the_log_never_confirms() {
        let mut watch = Watch::default();
        watch.note(stored(OLD));
        let mut sent = Vec::new();
        for now in 0..(GAP * u64::from(TRIES) + 3) {
            if let Action::Point { .. } = watch.decide(now, true, Some(NEW), &[UNIT]) {
                sent.push(now);
            }
        }
        assert_eq!(sent, (0..u64::from(TRIES)).map(|n| n * GAP).collect::<Vec<_>>());
        let give_up_at = GAP * u64::from(TRIES);
        let mut watch_again = Watch::default();
        watch_again.note(stored(OLD));
        for n in 0..u64::from(TRIES) {
            assert!(matches!(watch_again.decide(n * GAP, true, Some(NEW), &[UNIT]), Action::Point { .. }));
        }
        assert_eq!(watch_again.decide(give_up_at, true, Some(NEW), &[UNIT]), Action::GiveUp { to: NEW });
        assert_eq!(watch_again.decide(give_up_at + PAUSE - 1, true, Some(NEW), &[UNIT]), Action::Hold);
        assert!(matches!(
            watch_again.decide(give_up_at + PAUSE, true, Some(NEW), &[UNIT]),
            Action::Point { .. }
        ));
    }

    #[test]
    fn a_different_router_starts_its_own_attempts() {
        let mut watch = Watch::default();
        watch.note(stored(OLD));
        for n in 0..u64::from(TRIES) {
            assert!(matches!(watch.decide(n * GAP, true, Some(NEW), &[UNIT]), Action::Point { .. }));
        }
        let third = [0x02, 0, 0, 0, 0, 0x03];
        assert_eq!(
            watch.decide(GAP * u64::from(TRIES), true, Some(third), &[UNIT]),
            Action::Point { hostif: "usb0".into(), from: Some(OLD), to: third }
        );
    }

    #[test]
    fn the_last_kernel_line_wins() {
        let mut watch = Watch::default();
        watch.note(stored(NEW));
        watch.note(stored(OLD));
        assert_eq!(watch.stored(), Some(&stored(OLD)));
        assert!(matches!(watch.decide(1, true, Some(NEW), &[UNIT]), Action::Point { from: Some(OLD), .. }));
    }
}
