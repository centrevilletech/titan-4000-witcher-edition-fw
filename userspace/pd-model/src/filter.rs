//! Keep the core's router advertisements and DHCPv6 replies off the customer port.
//!
//! The modem still has to see the core's advertisement, because that is how it
//! learns the /64. The filter is on eth0 egress. Packets we send are marked and
//! pass; forwarded advertisements and server replies are dropped, so the router
//! hears one answer. Customer traffic matches neither rule.
//!
//! iproute2-ss150210 on this firmware has no `gact` action, and a u32 filter
//! with `handle N:` is rejected. A prio qdisc sends ordinary traffic to band 1.
//! The core's answers are classified onto band 2, whose qdisc is a blackhole.
//! Deleting the root qdisc restores the built-in pfifo_fast. Naming pfifo_fast
//! in a replace command returns ENOENT.

pub const MARK: u32 = 0x7064;

pub fn install(dev: &str) -> Vec<String> {
    let priomap = "1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1";
    vec![
        format!("qdisc replace dev {dev} root handle 1: prio bands 3 priomap {priomap}"),
        format!("qdisc replace dev {dev} parent 1:3 handle 30: blackhole"),
        format!(
            "filter add dev {dev} parent 1:0 protocol ipv6 prio 1 u32 match mark {MARK:#x} 0xffffffff flowid 1:2"
        ),
        format!(
            "filter add dev {dev} parent 1:0 protocol ipv6 prio 2 u32 match u8 58 0xff at 6 match u8 134 0xff at 40 flowid 1:3"
        ),
        format!(
            "filter add dev {dev} parent 1:0 protocol ipv6 prio 3 u32 match u8 17 0xff at 6 match u16 546 0xffff at 42 flowid 1:3"
        ),
    ]
}

pub fn remove(dev: &str) -> Vec<String> {
    vec![format!("qdisc del dev {dev} root")]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn our_packets_pass_and_the_cores_answers_are_dropped() {
        let lines = install("eth0");
        assert!(lines[1].contains("qdisc replace"));
        assert!(lines[1].contains("blackhole"));
        assert!(lines[2].contains("match mark 0x7064"));
        assert!(lines[2].contains("flowid 1:2"));
        assert!(lines[2].contains("prio 1 "));
        assert!(lines[3].contains("prio 2 "));
        assert!(lines[3].contains("flowid 1:3"));
        assert!(lines[4].contains("prio 3 "));
        assert!(
            lines[3].contains("u8 134 0xff at 40"),
            "ICMPv6 router advertisement"
        );
        assert!(lines[4].contains("u16 546"), "DHCPv6 server replies");
        let joined = lines.join("\n");
        assert!(!joined.contains("gact"));
        assert!(!lines[2].contains("handle"));
        assert!(!lines[3].contains("handle"));
        assert!(!lines[4].contains("handle"));
        assert!(!joined.contains("lte0pdn0"));
        assert_eq!(remove("eth0"), vec!["qdisc del dev eth0 root".to_owned()]);
    }
}
