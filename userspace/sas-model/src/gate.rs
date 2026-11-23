//! The customer-traffic gate.
//!
//! This client keeps customer traffic from crossing the unit while any
//! carrier the unit transmits on lacks SAS authorization. The stock client
//! relies on one routed-IPv4 rule that `rcinit` adds when it rebuilds its
//! firewall. This gate is one chain of our own in each table that forwards
//! customer packets: `iptables` and `ip6tables` for routed traffic,
//! `ebtables` for the passthrough bridge. It follows grant state directly,
//! not firewall rebuilds. The unit's own traffic (SAS, management) is never
//! forwarded, so it stays open.
//!
//! Closed means the chains exist and drop. Open means they are gone, so an
//! open gate costs nothing per packet and needs no polling.

pub const CHAIN: &str = "WITCHER_SAS_GATE";

/// A program and its arguments.
pub type Command = (&'static str, Vec<String>);

fn command(program: &'static str, args: &[&str]) -> Command {
    (program, args.iter().map(|arg| (*arg).to_string()).collect())
}

/// Commands that close the gate. Each one may fail when its effect is already
/// in place, so they are safe to run again.
pub fn close_commands() -> Vec<Command> {
    let mut commands = Vec::new();
    for program in ["iptables", "ip6tables"] {
        commands.push(command(program, &["-N", CHAIN]));
        commands.push(command(program, &["-F", CHAIN]));
        commands.push(command(program, &["-A", CHAIN, "-j", "DROP"]));
        commands.push(command(program, &["-D", "FORWARD", "-j", CHAIN]));
        commands.push(command(program, &["-I", "FORWARD", "1", "-j", CHAIN]));
    }
    commands.push(command("ebtables", &["-N", CHAIN, "-P", "RETURN"]));
    commands.push(command("ebtables", &["-F", CHAIN]));
    commands.push(command(
        "ebtables",
        &["-A", CHAIN, "-p", "IPv4", "-j", "DROP"],
    ));
    commands.push(command(
        "ebtables",
        &["-A", CHAIN, "-p", "IPv6", "-j", "DROP"],
    ));
    commands.push(command("ebtables", &["-D", "FORWARD", "-j", CHAIN]));
    commands.push(command("ebtables", &["-I", "FORWARD", "1", "-j", CHAIN]));
    commands
}

/// Commands that open the gate again.
pub fn open_commands() -> Vec<Command> {
    let mut commands = Vec::new();
    for program in ["iptables", "ip6tables", "ebtables"] {
        commands.push(command(program, &["-D", "FORWARD", "-j", CHAIN]));
        commands.push(command(program, &["-F", CHAIN]));
        commands.push(command(program, &["-X", CHAIN]));
    }
    commands
}

/// Whether a `-S FORWARD` listing (iptables or ip6tables) or an
/// `ebtables -L FORWARD` listing sends packets to the gate first. `None` when
/// the text is not a listing of that chain.
pub fn closed_in(listing: &str) -> Option<bool> {
    let rules: Vec<&str> = listing
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.starts_with("-A FORWARD") || line.starts_with("-j ") || line.starts_with("-p ")
        })
        .collect();
    let is_listing = listing.lines().any(|line| {
        let line = line.trim();
        line.starts_with("-P FORWARD") || line.starts_with("Bridge chain: FORWARD")
    });
    if !is_listing {
        return None;
    }
    Some(
        rules
            .first()
            .is_some_and(|rule| rule.split_whitespace().last() == Some(CHAIN)),
    )
}

/// The modem transmit limit in dBm for a grant of `max_eirp` dBm/MHz, by the
/// vendor's own Start Channel formula. It never exceeds 26.
pub fn transmit_limit(max_eirp: f64, cyclic_delay_diversity: bool, enable_max: bool) -> i64 {
    let bonus = if cyclic_delay_diversity && enable_max {
        3.0
    } else {
        0.0
    };
    let limit = (max_eirp - 4.0 + bonus).floor();
    if limit >= 26.0 {
        26
    } else if limit <= -40.0 {
        -40
    } else {
        limit as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gate_closes_every_forwarding_table() {
        let commands = close_commands();
        for program in ["iptables", "ip6tables", "ebtables"] {
            assert!(commands.iter().any(|(name, args)| *name == program
                && args.iter().any(|arg| arg == "-I")
                && args.last().map(String::as_str) == Some(CHAIN)));
        }
        let bridge: Vec<&Command> = commands
            .iter()
            .filter(|(name, args)| *name == "ebtables" && args.contains(&"DROP".to_string()))
            .collect();
        assert_eq!(bridge.len(), 2);
    }

    #[test]
    fn opening_removes_what_closing_added() {
        let commands = open_commands();
        assert_eq!(commands.len(), 9);
        assert!(
            commands
                .iter()
                .all(|(_, args)| args.contains(&CHAIN.to_string()))
        );
    }

    #[test]
    fn a_listing_shows_whether_the_gate_is_first() {
        let closed =
            "-P FORWARD ACCEPT\n-A FORWARD -j WITCHER_SAS_GATE\n-A FORWARD -p tcp -j TCPMSS\n";
        let behind =
            "-P FORWARD ACCEPT\n-A FORWARD -p tcp -j TCPMSS\n-A FORWARD -j WITCHER_SAS_GATE\n";
        let open = "-P FORWARD ACCEPT\n-A FORWARD -p tcp -j TCPMSS\n";
        assert_eq!(closed_in(closed), Some(true));
        assert_eq!(closed_in(behind), Some(false));
        assert_eq!(closed_in(open), Some(false));
        assert_eq!(closed_in("iptables: command not found"), None);
        let bridge = "Bridge chain: FORWARD, entries: 1, policy: ACCEPT\n-j WITCHER_SAS_GATE\n";
        assert_eq!(closed_in(bridge), Some(true));
        assert_eq!(
            closed_in("Bridge chain: FORWARD, entries: 0, policy: ACCEPT\n"),
            Some(false)
        );
    }

    #[test]
    fn the_transmit_limit_follows_the_vendor_formula() {
        assert_eq!(transmit_limit(27.0, true, true), 26);
        assert_eq!(transmit_limit(27.0, false, true), 23);
        assert_eq!(transmit_limit(20.0, true, true), 19);
        assert_eq!(transmit_limit(37.0, true, true), 26);
    }
}
