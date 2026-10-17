//! Local IPv4 reachability recovery, independent of IPv6 and internet hosts.
//! A peer must first answer our ARP checks. Three missed replies trigger DHCP
//! repair; three more trigger one PHY renegotiation. Another renegotiation
//! requires a new successful baseline. The caller owns the shared port budget.
use std::net::Ipv4Addr;

pub const INTERVAL: u64 = 10;
pub const TIMEOUT: u64 = 3;
const MISSES: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    pub address: Ipv4Addr,
    pub mac: [u8; 6],
    pub local_address: Ipv4Addr,
    pub local_mac: [u8; 6],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Hold,
    Probe(Peer),
    RepairDhcp,
    Renegotiate,
}

#[derive(Default)]
pub struct Watch {
    peer: Option<Peer>,
    pending: Option<u64>,
    next: u64,
    armed: bool,
    misses: u8,
    repaired: bool,
}

impl Watch {
    pub fn reset(&mut self) {
        *self = Self::default();
    }
    pub fn tick(&mut self, now: u64, peer: Option<Peer>) -> Action {
        if self.peer != peer {
            self.reset();
            self.peer = peer;
            self.next = now + INTERVAL;
        }
        let Some(peer) = peer else {
            return Action::Hold;
        };
        if let Some(sent) = self.pending {
            if now.saturating_sub(sent) < TIMEOUT {
                return Action::Hold;
            }
            self.pending = None;
            if self.armed {
                self.misses += 1;
            }
            if self.misses >= MISSES {
                self.misses = 0;
                self.next = now + INTERVAL;
                if !self.repaired {
                    self.repaired = true;
                    return Action::RepairDhcp;
                }
                // A permanently silent peer cannot flap the link repeatedly.
                self.armed = false;
                self.repaired = false;
                self.next = now + 60;
                return Action::Renegotiate;
            }
        }
        if now < self.next {
            return Action::Hold;
        }
        self.pending = Some(now);
        self.next = now + INTERVAL;
        Action::Probe(peer)
    }
    pub fn send_failed(&mut self, now: u64) {
        self.pending = None;
        self.next = now + INTERVAL;
        // Local inability to send is not evidence of a failed router.
        self.armed = false;
        self.misses = 0;
        self.repaired = false;
    }
    pub fn reply(&mut self, now: u64, packet: &[u8], source_mac: [u8; 6]) -> bool {
        let (Some(peer), Some(sent)) = (self.peer, self.pending) else {
            return false;
        };
        if now.saturating_sub(sent) > TIMEOUT || source_mac != peer.mac || !is_reply(packet, peer) {
            return false;
        }
        let first = !self.armed;
        self.pending = None;
        self.armed = true;
        self.misses = 0;
        self.repaired = false;
        first
    }
}

// RFC 826 Ethernet/IPv4 ARP. Use the Titan's own address/MAC, never impersonate
// the EPC gateway. Send only to the known downstream MAC on eth0.
pub fn probe(peer: Peer) -> Vec<u8> {
    let mut frame = Vec::with_capacity(42);
    frame.extend_from_slice(&peer.mac);
    frame.extend_from_slice(&peer.local_mac);
    frame.extend_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
    frame.extend_from_slice(&peer.local_mac);
    frame.extend_from_slice(&peer.local_address.octets());
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(&peer.address.octets());
    frame
}

pub fn is_reply(packet: &[u8], peer: Peer) -> bool {
    packet.len() >= 28
        && packet[..8] == [0, 1, 8, 0, 6, 4, 0, 2]
        && packet[8..14] == peer.mac
        && packet[14..18] == peer.address.octets()
        && packet[18..24] == peer.local_mac
        && packet[24..28] == peer.local_address.octets()
}

/// Exactly one live lease for this bearer. Ambiguous clients do not arm a
/// disruptive action. BusyBox stores seconds remaining plus a file timestamp.
pub fn leased_mac(bytes: &[u8], address: Ipv4Addr, now: u64) -> Option<[u8; 6]> {
    if bytes.len() < 44 || (bytes.len() - 8) % 36 != 0 {
        return None;
    }
    let saved = u64::from_be_bytes(bytes[..8].try_into().ok()?);
    if now < saved {
        return None;
    }
    let mut found = None;
    for entry in bytes[8..].chunks_exact(36) {
        let remaining = u32::from_be_bytes(entry[..4].try_into().ok()?) as u64;
        if remaining <= now - saved || entry[4..8] != address.octets() {
            continue;
        }
        let mac: [u8; 6] = entry[8..14].try_into().ok()?;
        if mac == [0; 6] || mac[0] & 1 != 0 {
            continue;
        }
        if found.is_some_and(|other| other != mac) {
            return None;
        }
        found = Some(mac);
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    fn peer() -> Peer {
        Peer {
            address: Ipv4Addr::new(172, 20, 64, 152),
            mac: [2, 0, 0, 0, 0, 1],
            local_address: Ipv4Addr::new(10, 1, 1, 1),
            local_mac: [2, 0, 0, 0, 0, 2],
        }
    }
    fn reply(p: Peer) -> Vec<u8> {
        let mut b = vec![0, 1, 8, 0, 6, 4, 0, 2];
        b.extend(p.mac);
        b.extend(p.address.octets());
        b.extend(p.local_mac);
        b.extend(p.local_address.octets());
        b
    }
    fn armed() -> Watch {
        let mut w = Watch::default();
        assert_eq!(w.tick(0, Some(peer())), Action::Hold);
        assert_eq!(w.tick(10, Some(peer())), Action::Probe(peer()));
        assert!(w.reply(11, &reply(peer()), peer().mac));
        w
    }
    #[test]
    fn idle_router_answering_arp_is_never_bounced() {
        let mut w = armed();
        for t in (20..10000).step_by(10) {
            assert_eq!(w.tick(t, Some(peer())), Action::Probe(peer()));
            w.reply(t + 1, &reply(peer()), peer().mac);
        }
    }
    #[test]
    fn never_responsive_router_is_not_armed() {
        let mut w = Watch::default();
        for t in 0..10000 {
            assert!(matches!(
                w.tick(t, Some(peer())),
                Action::Hold | Action::Probe(_)
            ));
        }
    }
    #[test]
    fn repeated_failure_repairs_then_renegotiates_once() {
        let mut w = armed();
        let mut actions = vec![];
        for t in 12..10000 {
            let a = w.tick(t, Some(peer()));
            if matches!(a, Action::RepairDhcp | Action::Renegotiate) {
                actions.push(a);
            }
        }
        assert_eq!(actions, vec![Action::RepairDhcp, Action::Renegotiate]);
    }
    #[test]
    fn recovery_cable_lte_or_peer_change_resets_escalation() {
        let mut w = armed();
        for t in 12..44 {
            w.tick(t, Some(peer()));
        }
        assert_eq!(w.tick(44, None), Action::Hold);
        for t in 45..200 {
            assert!(matches!(
                w.tick(t, Some(peer())),
                Action::Hold | Action::Probe(_)
            ));
        }
        let mut changed = peer();
        changed.mac[5] = 3;
        for t in 200..400 {
            assert!(matches!(
                w.tick(t, Some(changed)),
                Action::Hold | Action::Probe(_)
            ));
        }
    }
    #[test]
    fn wrong_late_or_unsolicited_replies_never_arm() {
        let mut w = Watch::default();
        w.tick(0, Some(peer()));
        assert!(!w.reply(1, &reply(peer()), peer().mac));
        w.tick(10, Some(peer()));
        let mut bad = reply(peer());
        bad[14] ^= 1;
        assert!(!w.reply(11, &bad, peer().mac));
        assert!(!w.reply(11, &reply(peer()), [2, 0, 0, 0, 0, 9]));
        assert!(!w.reply(14, &reply(peer()), peer().mac));
    }
    #[test]
    fn send_failure_never_counts_as_peer_failure() {
        let mut w = armed();
        w.tick(20, Some(peer()));
        w.send_failed(20);
        for t in 21..1000 {
            assert!(matches!(
                w.tick(t, Some(peer())),
                Action::Hold | Action::Probe(_)
            ));
        }
    }
    #[test]
    fn probe_uses_our_identity_and_reply_checks_every_field() {
        let p = peer();
        let f = probe(p);
        assert_eq!(f.len(), 42);
        assert_eq!(&f[..6], &p.mac);
        assert_eq!(&f[22..28], &p.local_mac);
        assert_eq!(&f[28..32], &p.local_address.octets());
        let b = reply(p);
        assert!(is_reply(&b, p));
        for i in 0..28 {
            let mut bad = b.clone();
            bad[i] ^= 1;
            assert!(!is_reply(&bad, p));
        }
        assert!(!is_reply(&b[..27], p));
    }
    #[test]
    fn lease_selection_rejects_expired_wrong_address_and_ambiguity() {
        let mut b = 100u64.to_be_bytes().to_vec();
        let mut e = 120u32.to_be_bytes().to_vec();
        e.extend(peer().address.octets());
        e.extend(peer().mac);
        e.resize(36, 0);
        b.extend(&e);
        assert_eq!(leased_mac(&b, peer().address, 101), Some(peer().mac));
        assert_eq!(leased_mac(&b, peer().address, 220), None);
        assert_eq!(leased_mac(&b, peer().address, 99), None);
        assert_eq!(leased_mac(&b, Ipv4Addr::LOCALHOST, 101), None);
        e[13] = 9;
        b.extend(e);
        assert_eq!(leased_mac(&b, peer().address, 101), None);
    }
}
