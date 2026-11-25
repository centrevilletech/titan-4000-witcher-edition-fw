//! Sign-in attempt limits, per source address.
//!
//! The web service and the recovery page count sign-in attempts before they
//! check the password, so a guesser learns little per minute. One bucket for
//! every client let anyone who could reach the page lock out the owner for as
//! long as they kept trying, and the README opens management on public
//! addresses. Now:
//!
//! - Each source has its own budget: an IPv4 address, or an IPv6 /64 (one host
//!   can use any address in its /64).
//! - Sources on the open Internet also share one budget, so a crowd of
//!   addresses guesses no faster than a few. Local sources (private and CGNAT
//!   IPv4, link-local, unique local IPv6, loopback) never count against it,
//!   so nothing on the Internet can lock out the owner on the LAN or the
//!   management APN.
//!
//! Nothing is kept on flash: every limit is a sliding window in RAM. The
//! table of sources is bounded; a source pushed out of it just starts again
//! with a full budget.
//!
//! The web service builds a copy of this module; both copies run these tests.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Sources remembered at once.
pub const MAX_SOURCES: usize = 256;

/// One source's budget key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    V4([u8; 4]),
    /// The /64 prefix.
    V6([u8; 8]),
    /// No address known (a test, or a transport that does not say).
    Unknown,
}

fn key(source: Option<IpAddr>) -> Key {
    match source.map(canonical) {
        Some(IpAddr::V4(v4)) => Key::V4(v4.octets()),
        Some(IpAddr::V6(v6)) => Key::V6(v6.octets()[..8].try_into().unwrap()),
        None => Key::Unknown,
    }
}

/// IPv4-mapped IPv6 addresses as the IPv4 address they carry.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// Whether `ip` cannot come from the open Internet.
pub fn local(ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || (a == 100 && b & 0xc0 == 64)
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback() || first & 0xffc0 == 0xfe80 || first & 0xfe00 == 0xfc00
        }
    }
}

/// Sliding-window limits on sign-in attempts.
#[derive(Debug)]
pub struct Throttle {
    per_source: usize,
    shared: usize,
    window: Duration,
    sources: BTreeMap<Key, Vec<Instant>>,
    public: Vec<Instant>,
}

impl Throttle {
    /// `per_source` attempts per source and `shared` attempts across all
    /// Internet sources, each per `window`.
    pub fn new(per_source: usize, shared: usize, window: Duration) -> Self {
        Self {
            per_source,
            shared,
            window,
            sources: BTreeMap::new(),
            public: Vec::new(),
        }
    }

    /// Whether an attempt from `source` may go ahead at `now`. An admitted
    /// attempt is counted; a refused one is not, so a refused client never
    /// pushes its own wait further out.
    pub fn admit(&mut self, source: Option<IpAddr>, now: Instant) -> bool {
        let window = self.window;
        let fresh = |times: &mut Vec<Instant>| times.retain(|t| now.duration_since(*t) < window);
        let shared = !source.is_some_and(local);
        fresh(&mut self.public);
        if shared && self.public.len() >= self.shared {
            return false;
        }
        let key = key(source);
        if !self.sources.contains_key(&key) && self.sources.len() >= MAX_SOURCES {
            self.sources.retain(|_, times| {
                fresh(times);
                !times.is_empty()
            });
            if self.sources.len() >= MAX_SOURCES {
                let oldest = self
                    .sources
                    .iter()
                    .min_by_key(|(_, times)| times.last().copied())
                    .map(|(key, _)| *key);
                if let Some(oldest) = oldest {
                    self.sources.remove(&oldest);
                }
            }
        }
        let times = self.sources.entry(key).or_default();
        fresh(times);
        if times.len() >= self.per_source {
            return false;
        }
        times.push(now);
        if shared {
            self.public.push(now);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    fn ip(text: &str) -> Option<IpAddr> {
        Some(text.parse().unwrap())
    }

    #[test]
    fn one_source_cannot_lock_out_another() {
        let mut t = Throttle::new(10, 30, MINUTE);
        let now = Instant::now();
        for _ in 0..10 {
            assert!(t.admit(ip("203.0.113.5"), now));
        }
        // A bot keeps hammering; its own budget is spent, nobody else's.
        for _ in 0..100 {
            assert!(!t.admit(ip("203.0.113.5"), now));
        }
        assert!(t.admit(ip("192.168.0.10"), now), "the owner on the LAN");
        assert!(
            t.admit(ip("198.51.100.7"), now),
            "the owner on the Internet"
        );
    }

    #[test]
    fn a_source_gets_its_budget_back_after_the_window() {
        let mut t = Throttle::new(5, 15, MINUTE);
        let start = Instant::now();
        for _ in 0..5 {
            assert!(t.admit(ip("192.168.0.10"), start));
        }
        assert!(!t.admit(ip("192.168.0.10"), start + Duration::from_secs(59)));
        assert!(t.admit(ip("192.168.0.10"), start + MINUTE));
    }

    #[test]
    fn internet_sources_share_a_budget_that_local_sources_never_touch() {
        let mut t = Throttle::new(10, 30, MINUTE);
        let now = Instant::now();
        for n in 0..30 {
            assert!(t.admit(ip(&format!("203.0.113.{n}")), now));
        }
        assert!(
            !t.admit(ip("198.51.100.1"), now),
            "a crowd guesses no faster"
        );
        for local in [
            "192.168.0.10",
            "10.20.30.40",
            "100.72.1.2",
            "fe80::1",
            "fd00::5",
            "127.0.0.1",
        ] {
            assert!(t.admit(ip(local), now), "{local}");
        }
        assert!(!t.admit(None, now), "an unknown source is not local");
    }

    #[test]
    fn an_ipv6_host_is_one_source_and_mapped_ipv4_is_ipv4() {
        let mut t = Throttle::new(2, 30, MINUTE);
        let now = Instant::now();
        assert!(t.admit(ip("2001:db8:1:2::1"), now));
        assert!(t.admit(ip("2001:db8:1:2::ffff"), now));
        assert!(!t.admit(ip("2001:db8:1:2:abcd::9"), now), "same /64");
        assert!(t.admit(ip("2001:db8:1:3::1"), now), "another /64");
        assert!(t.admit(ip("::ffff:192.0.2.1"), now));
        assert!(t.admit(ip("192.0.2.1"), now));
        assert!(!t.admit(ip("192.0.2.1"), now));
    }

    #[test]
    fn the_table_stays_bounded_and_never_locks_anyone_out() {
        let mut t = Throttle::new(1, usize::MAX, MINUTE);
        let now = Instant::now();
        assert!(t.admit(ip("192.168.0.10"), now));
        for n in 0..10_000u32 {
            // A new /64 each time.
            let (high, low) = ((n >> 16) as u16, n as u16);
            let source = std::net::Ipv6Addr::new(0x2001, 0xdb8, high, low, 0, 0, 0, 1);
            assert!(t.admit(Some(IpAddr::V6(source)), now));
        }
        assert!(t.sources.len() <= MAX_SOURCES);
        // Pushed out of the table, the owner starts again with a full budget.
        assert!(t.admit(ip("192.168.0.10"), now));
    }

    #[test]
    fn local_addresses() {
        for text in [
            "10.0.0.1",
            "172.16.5.4",
            "192.168.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "169.254.1.1",
            "127.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:10.1.1.1",
        ] {
            assert!(local(text.parse().unwrap()), "{text}");
        }
        for text in [
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.1",
            "172.32.0.1",
            "2001:db8::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(!local(text.parse().unwrap()), "{text}");
        }
    }
}
