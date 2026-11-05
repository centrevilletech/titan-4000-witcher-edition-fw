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
use std::net::Ipv4Addr;

pub const INTERVAL: u64 = 10;
/// The vendor rebuild flushes the table and adds the rule back within about a
/// second. One missing check can be the middle of that rebuild; two in a row,
/// ten seconds apart, is not.
const MISSES: u8 = 2;
/// At most one restore attempt a minute, so a failing command cannot loop.
pub const RETRY: u64 = 60;

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
    retry_at: u64,
}

impl Watch {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// One check, made every `INTERVAL` seconds by the caller. `snat` is the
    /// rule this unit needs now, or `None` when it needs none. `present` is
    /// `None` when the nat table could not be read; that is not a miss.
    pub fn observe(&mut self, now: u64, snat: Option<Snat>, present: Option<bool>) -> Action {
        if self.snat != snat {
            self.reset();
            self.snat = snat;
        }
        let Some(snat) = snat else {
            return Action::Hold;
        };
        match present {
            None => return Action::Hold,
            Some(true) => {
                self.misses = 0;
                return Action::Hold;
            }
            Some(false) => self.misses = self.misses.saturating_add(1),
        }
        if self.misses < MISSES || now < self.retry_at {
            return Action::Hold;
        }
        self.misses = 0;
        self.retry_at = now + RETRY;
        Action::Restore(snat)
    }
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
