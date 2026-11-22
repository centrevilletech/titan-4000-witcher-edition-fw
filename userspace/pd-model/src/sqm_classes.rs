//! Traffic classes for the opt-in in-Titan CAKE (Stage 1, no new modules).
//!
//! CAKE runs `diffserv4` in both directions: Bulk, Best Effort, Video and
//! Voice tins. A packet's DSCP picks its tin, unless `skb->priority` names the
//! CAKE qdisc (`<handle>:<1..4>`), which CAKE checks first. Most customer
//! apps send DSCP 0, so these filters set `skb->priority` for traffic that
//! should not wait behind a download:
//!
//! | Order | Match | Tin |
//! | --- | --- | --- |
//! | 1 | TCP | left to DSCP (leaves the filter list at once) |
//! | 2 | ICMP, ICMPv6 | Voice |
//! | 3 | UDP 443 (QUIC), 80, 1194 and 51820 (VPNs) | left to DSCP |
//! | 4 | DNS (53) and NTP (123) | Voice |
//! | 5 | Game and voice ports: 3074, 27015-27050, 50000-50019 | Voice |
//! | 6 | Call and meeting video: 3478-3481, 8801-8810, 19302-19309, 50020-50059 | Video |
//! | 7 | Any other UDP of 255 bytes or less (IPv6: payload) | Voice |
//!
//! Ports match as source or destination. QUIC and VPNs are left out of the
//! size rule, so one flow is never split across two tins. Voice may use up to
//! a quarter of the rate and Video half before they lose their priority.
//!
//! The filters use the kernel's built-in `cls_u32` and `act_skbedit`. They
//! change only `skb->priority`: no packet edits, and CAKE keeps hashing flows
//! and hosts as before. u32 reads ports at fixed offsets, so an IPv4 packet
//! with IP options or an IPv6 packet with extension headers falls through to
//! its DSCP.

/// The tins as `skb->priority` minor numbers in `diffserv4`.
pub const VOICE: u8 = 4;
pub const VIDEO: u8 = 3;

const SKIP_PORTS: &[(u16, u16)] = &[(443, 443), (80, 80), (1194, 1194), (51820, 51820)];
const NAME_TIME_PORTS: &[(u16, u16)] = &[(53, 53), (123, 123)];
const GAME_PORTS: &[(u16, u16)] = &[(3074, 3074), (27015, 27050), (50000, 50019)];
const VIDEO_PORTS: &[(u16, u16)] = &[(3478, 3481), (8801, 8810), (19302, 19309), (50020, 50059)];

/// Filter priorities in use: IPv4 rules, then IPv6 rules. A priority holds
/// one protocol only on this kernel.
pub const PRIOS: [(&str, u16); 14] = [
    ("ip", 1),
    ("ip", 2),
    ("ip", 3),
    ("ip", 4),
    ("ip", 5),
    ("ip", 6),
    ("ip", 7),
    ("ipv6", 11),
    ("ipv6", 12),
    ("ipv6", 13),
    ("ipv6", 14),
    ("ipv6", 15),
    ("ipv6", 16),
    ("ipv6", 17),
];

/// The smallest set of `(value, mask)` pairs that matches exactly the ports
/// `lo..=hi`. u32 compares masked values, so a range is a set of aligned
/// power-of-two blocks.
pub fn port_masks(lo: u16, hi: u16) -> Vec<(u16, u16)> {
    let mut out = Vec::new();
    let (mut start, end) = (u32::from(lo), u32::from(hi));
    while start <= end {
        // The largest aligned block that starts here and stays in range.
        let mut size = if start == 0 { 1 << 16 } else { 1u32 << start.trailing_zeros() };
        while start + size - 1 > end {
            size >>= 1;
        }
        out.push((start as u16, (!(size - 1) & 0xffff) as u16));
        start += size;
    }
    out
}

/// `tc -batch` lines that install the classes on one CAKE qdisc.
pub fn batch(dev: &str, handle: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for (family, base, l4) in [("ip", 0u16, "ip"), ("ipv6", 10, "ip6")] {
        let mut add = |prio: u16, matches: String, tin: Option<u8>| {
            let priority = tin.map_or_else(|| "0:0".to_owned(), |tin| format!("{handle}:{tin}"));
            lines.push(format!(
                "filter add dev {dev} parent {handle}: protocol {family} prio {} u32 {matches} action skbedit priority {priority} ok",
                base + prio
            ));
        };
        add(1, format!("match {l4} protocol 6 0xff"), None);
        let icmp = if l4 == "ip" { 1 } else { 58 };
        add(2, format!("match {l4} protocol {icmp} 0xff"), Some(VOICE));
        for (prio, ports, tin) in [
            (3, SKIP_PORTS, None),
            (4, NAME_TIME_PORTS, Some(VOICE)),
            (5, GAME_PORTS, Some(VOICE)),
            (6, VIDEO_PORTS, Some(VIDEO)),
        ] {
            for &(lo, hi) in ports {
                for (value, mask) in port_masks(lo, hi) {
                    for side in ["dport", "sport"] {
                        add(
                            prio,
                            format!("match {l4} protocol 17 0xff match {l4} {side} {value} 0x{mask:04x}"),
                            tin,
                        );
                    }
                }
            }
        }
        // IPv4 total length or IPv6 payload length of 255 bytes or less.
        let length = if l4 == "ip" { 2 } else { 4 };
        add(
            7,
            format!("match {l4} protocol 17 0xff match u16 0x0000 0xff00 at {length}"),
            Some(VOICE),
        );
    }
    lines
}

/// `tc -force -batch` lines that remove every class filter from one qdisc.
/// A priority that is not there only fails its own line.
pub fn removal(dev: &str, handle: &str) -> Vec<String> {
    PRIOS
        .iter()
        .map(|(family, prio)| format!("filter del dev {dev} parent {handle}: protocol {family} prio {prio}"))
        .collect()
}

/// How many classifier actions `tc filter show` lists: one per filter.
pub fn installed(listing: &str) -> usize {
    listing.matches("skbedit").count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn covered(masks: &[(u16, u16)]) -> Vec<u16> {
        (0..=u16::MAX)
            .filter(|port| masks.iter().any(|(value, mask)| port & mask == *value))
            .collect()
    }

    #[test]
    fn port_ranges_become_exact_aligned_blocks() {
        assert_eq!(port_masks(53, 53), [(53, 0xffff)]);
        assert_eq!(port_masks(50000, 50019), [(50000, 0xfff0), (50016, 0xfffc)]);
        assert_eq!(port_masks(3478, 3481), [(3478, 0xfffe), (3480, 0xfffe)]);
        assert_eq!(port_masks(0, u16::MAX), [(0, 0)]);
        for &(lo, hi) in SKIP_PORTS.iter().chain(NAME_TIME_PORTS).chain(GAME_PORTS).chain(VIDEO_PORTS) {
            let masks = port_masks(lo, hi);
            assert_eq!(covered(&masks), (lo..=hi).collect::<Vec<_>>(), "{lo}-{hi}");
            for (value, mask) in masks {
                assert_eq!(value & mask, value, "an unaligned block in {lo}-{hi}");
            }
        }
    }

    #[test]
    fn the_class_ranges_do_not_overlap() {
        let groups = [SKIP_PORTS, NAME_TIME_PORTS, GAME_PORTS, VIDEO_PORTS];
        for (i, a) in groups.iter().enumerate() {
            for b in &groups[i + 1..] {
                for &(alo, ahi) in a.iter() {
                    for &(blo, bhi) in b.iter() {
                        assert!(ahi < blo || bhi < alo, "{alo}-{ahi} overlaps {blo}-{bhi}");
                    }
                }
            }
        }
    }

    #[test]
    fn the_batch_sets_only_the_priority_in_rule_order() {
        let lines = batch("lte0pdn2", "ca01");
        assert_eq!(
            lines[0],
            "filter add dev lte0pdn2 parent ca01: protocol ip prio 1 u32 match ip protocol 6 0xff action skbedit priority 0:0 ok"
        );
        assert_eq!(
            lines[1],
            "filter add dev lte0pdn2 parent ca01: protocol ip prio 2 u32 match ip protocol 1 0xff action skbedit priority ca01:4 ok"
        );
        assert!(lines.contains(&"filter add dev lte0pdn2 parent ca01: protocol ip prio 3 u32 match ip protocol 17 0xff match ip sport 443 0xffff action skbedit priority 0:0 ok".to_owned()));
        assert!(lines.contains(&"filter add dev lte0pdn2 parent ca01: protocol ip prio 6 u32 match ip protocol 17 0xff match ip dport 8804 0xfffc action skbedit priority ca01:3 ok".to_owned()));
        assert!(lines.contains(&"filter add dev lte0pdn2 parent ca01: protocol ip prio 7 u32 match ip protocol 17 0xff match u16 0x0000 0xff00 at 2 action skbedit priority ca01:4 ok".to_owned()));
        assert!(lines.contains(&"filter add dev lte0pdn2 parent ca01: protocol ipv6 prio 12 u32 match ip6 protocol 58 0xff action skbedit priority ca01:4 ok".to_owned()));
        assert!(lines.contains(&"filter add dev lte0pdn2 parent ca01: protocol ipv6 prio 17 u32 match ip6 protocol 17 0xff match u16 0x0000 0xff00 at 4 action skbedit priority ca01:4 ok".to_owned()));
        // Priorities rise with the table order, IPv4 before IPv6, and every
        // priority used is one cleanup knows.
        let prio = |line: &str| -> u16 {
            line.split_whitespace().skip_while(|w| *w != "prio").nth(1).unwrap().parse().unwrap()
        };
        assert!(lines.windows(2).all(|pair| prio(&pair[0]) <= prio(&pair[1])));
        for line in &lines {
            let family = if line.contains("protocol ipv6 ") { "ipv6" } else { "ip" };
            assert!(PRIOS.contains(&(family, prio(line))), "{line}");
            assert!(!line.contains("flowid") && !line.contains("classid"), "CAKE must keep its own hashing");
            assert!(line.ends_with(" ok"));
        }
        // Downlink uses its own handle in every tin priority.
        let down = batch("eth0", "ca02");
        assert_eq!(down.len(), lines.len());
        assert!(down.iter().all(|l| !l.contains("ca01")));
        assert!(down.iter().any(|l| l.contains("priority ca02:3")));
        // Two directions of the same table: as many IPv4 as IPv6 rules.
        let v6 = lines.iter().filter(|l| l.contains("protocol ipv6 ")).count();
        assert_eq!(v6 * 2, lines.len());
    }

    #[test]
    fn removal_names_every_priority_and_counting_reads_actions() {
        let lines = removal("eth0", "ca02");
        assert_eq!(lines.len(), PRIOS.len());
        assert_eq!(lines[0], "filter del dev eth0 parent ca02: protocol ip prio 1");
        assert_eq!(lines[13], "filter del dev eth0 parent ca02: protocol ipv6 prio 17");
        let listing = "filter parent ca01: protocol ip pref 1 u32 fh 800: ht divisor 1\n\
filter parent ca01: protocol ip pref 1 u32 fh 800::800 order 2048 key ht 800 bkt 0 terminal flowid ???\n  match 00060000/00ff0000 at 8\n\taction order 1: skbedit  priority :0 ok\n\t index 1 ref 1 bind 1\n\
filter parent ca01: protocol ip pref 2 u32 fh 801::800 order 2048 key ht 801 bkt 0 terminal flowid ???\n  match 00010000/00ff0000 at 8\n\taction order 1: skbedit  priority ca01:4 ok\n";
        assert_eq!(installed(listing), 2);
        assert_eq!(installed(""), 0);
    }
}
