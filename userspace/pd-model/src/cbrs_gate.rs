//! Customer IPv6 while the unit holds no SAS grant.
//!
//! The vendor stops customer traffic without a grant with one IPv4 rule. On
//! Band 48 with `cbrs_mode_grant=0`, each vendor firewall rebuild in `rcinit`
//! runs `iptables -I FORWARD -j DROP` (plus a DHCP accept). The radio stays
//! attached and keeps sending: the modem power limit stays at 26 dBm and
//! nothing suspends the bearer. Nothing does the same for IPv6:
//!
//! - `rcinit` writes `0` to `bridge-nf-call-ip6tables`, so bridged IPv6 in
//!   passthrough never reaches ip6tables.
//! - The vendor IPv6 firewall (`ip6tables-restore /tmp/.ip6t`) has no grant
//!   rule.
//!
//! So a passthrough unit with no grant keeps forwarding the customer router's
//! IPv6 both ways over the air, and with prefix delegation that is the whole
//! customer LAN.
//!
//! The keeper closes the gap. While the unit has no grant it holds four DROP
//! rules for forwarded IPv6 to and from any LTE bearer:
//!
//! - ebtables FORWARD, `-p IPv6 -i lte0pdn+` and `-p IPv6 -o lte0pdn+`, for
//!   bridged IPv6 in passthrough. `-p IPv6` is the Ethernet type, so it needs
//!   no `ebt_ip6` module (the unit has none).
//! - ip6tables FORWARD, `-i lte0pdn+` and `-o lte0pdn+`, for IPv6 the unit
//!   routes, as in NAT mode.
//!
//! FORWARD never sees the unit's own traffic. SAS, management, NTP and the
//! keeper's own router advertisements and DHCPv6 replies are local, so they
//! use INPUT and OUTPUT or skip the bridge.
//!
//! "Held" means `cbrs_mode_grant=1` and `cbrs_grant_state=2`, the test the
//! radio profile already uses. `cbrs_mode_grant` is the key the vendor IPv4
//! rule follows. Witcher's Block Channel patch stops the SAS client from
//! clearing it at transmit expiry and before a relinquish, but the client
//! still sets `cbrs_grant_state` to 1 or 0 then. So the second key closes the
//! gate in those cases too. This Titan is a Band 48 unit only, so unlike
//! `rcinit` the gate does not check the band: a torn read of the band must
//! never open it.
//!
//! The gate fails closed. A cache it cannot read, a key that is missing or a
//! value it does not know counts as no grant. The vendor rewrites the cache in
//! place under a lock the keeper does not take, so a read can be torn. A
//! clear "no grant" closes the gate at once. A read with a missing key or an
//! odd value closes it once a read at least a second later still says no.
//!
//! Every vendor firewall restart flushes both tables (`ebtables -F`,
//! `ip6tables -F`). So while the gate is closed the keeper reads both chains
//! every second and puts back what is missing.

use crate::nvram::field as nvram_field;

/// Seconds between two reads of the grant.
pub const INTERVAL: u64 = 1;
/// While open and clean, seconds between two checks that no rule is left.
pub const VERIFY: u64 = 300;
/// While open, seconds before a cleanup that could not finish runs again.
pub const RETRY: u64 = 10;
/// An unclear "no grant" closes the gate only when a read at least this many
/// clock seconds later still says no. The clock counts whole seconds, so 2
/// means at least one real second between the two reads.
pub const CONFIRM: u64 = 2;
/// Most copies of one rule a single cleanup deletes.
pub const DELETE_TRIES: usize = 8;
/// Every vendor LTE bearer, as an interface wildcard both tools accept.
pub const BEARERS: &str = "lte0pdn+";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tool {
    Ebtables,
    Ip6tables,
}

pub const TOOLS: [Tool; 2] = [Tool::Ebtables, Tool::Ip6tables];

impl Tool {
    pub fn name(self) -> &'static str {
        match self {
            Tool::Ebtables => "ebtables",
            Tool::Ip6tables => "ip6tables",
        }
    }

    /// Lists the FORWARD chain.
    pub fn list_args(self) -> [&'static str; 2] {
        match self {
            Tool::Ebtables => ["-L", "FORWARD"],
            Tool::Ip6tables => ["-S", "FORWARD"],
        }
    }

    /// Whether `listing` is a listing of this tool's FORWARD chain.
    fn listed(self, listing: &str) -> bool {
        listing.lines().map(str::trim_start).any(|line| match self {
            Tool::Ebtables => line.starts_with("Bridge chain: FORWARD,"),
            Tool::Ip6tables => line.starts_with("-P FORWARD "),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Way {
    /// From an LTE bearer: downlink.
    In,
    /// To an LTE bearer: uplink, which the radio would send.
    Out,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub tool: Tool,
    pub way: Way,
}

pub const RULES: [Rule; 4] = [
    Rule { tool: Tool::Ebtables, way: Way::Out },
    Rule { tool: Tool::Ebtables, way: Way::In },
    Rule { tool: Tool::Ip6tables, way: Way::Out },
    Rule { tool: Tool::Ip6tables, way: Way::In },
];

impl Rule {
    /// The match and target, in the order `ebtables -L` and `ip6tables -S`
    /// print them.
    fn spec(self) -> Vec<&'static str> {
        let flag = match self.way {
            Way::In => "-i",
            Way::Out => "-o",
        };
        match self.tool {
            Tool::Ebtables => vec!["-p", "IPv6", flag, BEARERS, "-j", "DROP"],
            Tool::Ip6tables => vec![flag, BEARERS, "-j", "DROP"],
        }
    }

    /// First in the chain, ahead of any vendor or Witcher accept.
    pub fn insert_args(self) -> Vec<&'static str> {
        let mut args = vec!["-I", "FORWARD", "1"];
        args.extend(self.spec());
        args
    }

    /// Deletes one copy.
    pub fn delete_args(self) -> Vec<&'static str> {
        let mut args = vec!["-D", "FORWARD"];
        args.extend(self.spec());
        args
    }

    /// Copies of this rule in a listing of its tool's FORWARD chain. `None`
    /// when the text is not such a listing, for example a failed command.
    pub fn count(self, listing: &str) -> Option<usize> {
        if !self.tool.listed(listing) {
            return None;
        }
        let want = self.spec();
        Some(
            listing
                .lines()
                .filter(|line| {
                    let words: Vec<&str> = line.split_whitespace().collect();
                    let words = match words.as_slice() {
                        ["-A", "FORWARD", rest @ ..] => rest,
                        // ebtables -L prints a rule with no chain name.
                        all if self.tool == Tool::Ebtables => all,
                        _ => return false,
                    };
                    words.len() == want.len()
                        && words.iter().zip(&want).all(|(got, want)| same_word(got, want))
                })
                .count(),
        )
    }
}

/// ebtables prints the Ethernet type by its `/etc/ethertypes` name, or in hex
/// when that file lacks it.
fn same_word(got: &str, want: &str) -> bool {
    if want == "IPv6" {
        got.eq_ignore_ascii_case("IPv6") || got.eq_ignore_ascii_case("0x86dd")
    } else {
        got == want
    }
}

pub fn rules(tool: Tool) -> impl Iterator<Item = Rule> {
    RULES.into_iter().filter(move |rule| rule.tool == tool)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gate {
    /// Customer IPv6 may forward.
    Open(String),
    /// Customer IPv6 must not forward. `clear` is false when the read itself
    /// may be at fault: a cache that could not be read, a missing key or a
    /// value the gate does not know, as in a read that raced a rewrite.
    Closed { why: String, clear: bool },
}

/// The gate for one read of the vendor RAM cache (`/tmp/nvram.cfg`).
pub fn decide(cache: Option<&[u8]>) -> Gate {
    let Some(cache) = cache else {
        return Gate::Closed {
            why: "the vendor RAM settings could not be read".into(),
            clear: false,
        };
    };
    let mode = nvram_field(cache, "cbrs_mode_grant").map(str::trim);
    let state = nvram_field(cache, "cbrs_grant_state").map(str::trim);
    if mode == Some("1") && state == Some("2") {
        return Gate::Open("SAS grant held".into());
    }
    let clear = matches!(mode, Some("0" | "1")) && matches!(state, Some("0" | "1" | "2"));
    Gate::Closed {
        why: format!(
            "no SAS grant (cbrs_mode_grant={}, cbrs_grant_state={})",
            shown(mode),
            shown(state)
        ),
        clear,
    }
}

fn shown(value: Option<&str>) -> &str {
    match value {
        None => "unset",
        Some("") => "empty",
        Some(value) => value,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Nothing to do this round.
    Hold,
    /// Make sure every rule is in place (`close`).
    Close,
    /// Remove every rule (`open`), then report with `Watch::cleaned`.
    Open,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cleanup {
    /// Both chains were read and held no rule.
    Clean,
    /// Copies were deleted. The next round reads the chains again.
    Removed,
    /// A chain could not be read or a delete failed.
    Failed,
}

/// When the keeper reads the grant, and what it must do after each read.
pub struct Watch {
    next: u64,
    /// The state the keeper last acted on. `None` before the first.
    closed: Option<bool>,
    /// Since when every read has been an unclear "no grant" that has not
    /// closed the gate yet.
    doubt_since: Option<u64>,
    /// A rule may be in a table: at start (a keeper restart can leave them)
    /// and from every close until a cleanup finds none.
    dirty: bool,
    next_clean: u64,
}

impl Default for Watch {
    fn default() -> Self {
        Self { next: 0, closed: None, doubt_since: None, dirty: true, next_clean: 0 }
    }
}

impl Watch {
    pub fn due(&self, now: u64) -> bool {
        now >= self.next
    }

    /// One read. Returns the step, and a line to log when the gate changes.
    pub fn observe(&mut self, now: u64, gate: &Gate) -> (Step, Option<String>) {
        self.next = now + INTERVAL;
        match gate {
            Gate::Closed { why, clear } => {
                if !clear && self.closed != Some(true) {
                    let since = *self.doubt_since.get_or_insert(now);
                    if now < since + CONFIRM {
                        return (Step::Hold, None);
                    }
                }
                self.doubt_since = None;
                self.dirty = true;
                let line = (self.closed != Some(true)).then(|| {
                    format!("CBRS gate closed: {why}; dropping customer IPv6 to and from LTE")
                });
                self.closed = Some(true);
                (Step::Close, line)
            }
            Gate::Open(why) => {
                self.doubt_since = None;
                let line = (self.closed != Some(false))
                    .then(|| format!("CBRS gate open: {why}; customer IPv6 may forward"));
                if self.closed != Some(false) {
                    self.next_clean = now;
                }
                self.closed = Some(false);
                if now >= self.next_clean {
                    (Step::Open, line)
                } else {
                    (Step::Hold, line)
                }
            }
        }
    }

    /// The result of an `Open` step.
    pub fn cleaned(&mut self, now: u64, cleanup: Cleanup) {
        self.dirty = cleanup != Cleanup::Clean;
        self.next_clean = now
            + match cleanup {
                Cleanup::Clean => VERIFY,
                Cleanup::Removed => INTERVAL,
                Cleanup::Failed => RETRY,
            };
    }

    /// A rule may still be in a table.
    pub fn dirty(&self) -> bool {
        self.dirty
    }
}

/// Puts in place every rule its chain lacks. `run` runs one command of a tool
/// and returns its output when it exits 0. A chain that cannot be read still
/// gets every rule (fail closed): one delete first, so copies cannot pile up
/// one a second. Returns how many missing rules a listing showed and the
/// keeper added, and one line per failure.
pub fn close(run: &mut impl FnMut(Tool, &[&str]) -> Result<String, String>) -> (usize, Vec<String>) {
    let mut added = 0;
    let mut failed = Vec::new();
    for tool in TOOLS {
        let listing = run(tool, &tool.list_args()[..]).ok();
        let readable = listing.as_deref().is_some_and(|text| tool.listed(text));
        if !readable {
            failed.push(format!(
                "{} {} could not be read; adding the rules anyway",
                tool.name(),
                tool.list_args().join(" ")
            ));
        }
        for rule in rules(tool) {
            let copies = listing.as_deref().and_then(|text| rule.count(text));
            if copies.is_some_and(|n| n > 0) {
                continue;
            }
            if copies.is_none() {
                let _ = run(tool, &rule.delete_args()[..]);
            }
            let args = rule.insert_args();
            match run(tool, &args[..]) {
                Ok(_) => {
                    if copies.is_some() {
                        added += 1;
                    }
                }
                Err(err) => failed.push(format!("{} {} failed: {err}", tool.name(), args.join(" "))),
            }
        }
    }
    (added, failed)
}

/// Removes every copy of every rule. When a chain cannot be read, it deletes
/// until the tool reports none left, and reports `Failed` so the keeper tries
/// again later.
pub fn open(run: &mut impl FnMut(Tool, &[&str]) -> Result<String, String>) -> (Cleanup, Vec<String>) {
    let mut cleanup = Cleanup::Clean;
    let mut failed = Vec::new();
    for tool in TOOLS {
        let listing = run(tool, &tool.list_args()[..]).ok();
        let readable = listing.as_deref().is_some_and(|text| tool.listed(text));
        if !readable {
            cleanup = Cleanup::Failed;
            failed.push(format!("{} {} could not be read", tool.name(), tool.list_args().join(" ")));
        }
        for rule in rules(tool) {
            let copies = listing.as_deref().and_then(|text| rule.count(text));
            if copies == Some(0) {
                continue;
            }
            let args = rule.delete_args();
            for _ in 0..copies.unwrap_or(DELETE_TRIES).min(DELETE_TRIES) {
                match run(tool, &args[..]) {
                    Ok(_) => {
                        if cleanup == Cleanup::Clean {
                            cleanup = Cleanup::Removed;
                        }
                    }
                    Err(err) => {
                        // With no listing, the tool saying "no such rule" is
                        // the expected end.
                        if copies.is_some() {
                            cleanup = Cleanup::Failed;
                            failed.push(format!("{} {} failed: {err}", tool.name(), args.join(" ")));
                        }
                        break;
                    }
                }
            }
        }
    }
    (cleanup, failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELD: &[u8] = b"lan_management_ipaddr=10.1.1.1\0cbrs_mode_grant=1\0cbrs_grant_state=2\0sqns_radio_band=48\0";

    fn cache(mode: &str, state: &str) -> Vec<u8> {
        format!("router_disable=1\0cbrs_mode_grant={mode}\0cbrs_grant_state={state}\0").into_bytes()
    }

    fn closed(gate: &Gate) -> Option<bool> {
        match gate {
            Gate::Open(_) => None,
            Gate::Closed { clear, .. } => Some(*clear),
        }
    }

    #[test]
    fn only_an_authorized_grant_opens_the_gate() {
        assert_eq!(decide(Some(HELD)), Gate::Open("SAS grant held".into()));
        assert_eq!(decide(Some(b"cbrs_mode_grant=1\ncbrs_grant_state=2\n")), Gate::Open("SAS grant held".into()));
        assert_eq!(decide(Some(b"cbrs_mode_grant= 1 \0cbrs_grant_state=2\n\0")), Gate::Open("SAS grant held".into()));
        // The vendor rule's key: no grant after a re-attach or carrier change.
        assert_eq!(closed(&decide(Some(&cache("0", "2")))), Some(true));
        assert_eq!(closed(&decide(Some(&cache("0", "0")))), Some(true));
        // Transmit expiry or a 501 with Witcher's Block Channel patch: the
        // mode key stays 1, the grant state drops to 1.
        assert_eq!(closed(&decide(Some(&cache("1", "1")))), Some(true));
        // A relinquish or a new grant request.
        assert_eq!(closed(&decide(Some(&cache("1", "0")))), Some(true));
    }

    #[test]
    fn anything_unreadable_closes_but_only_after_a_second_read() {
        assert_eq!(closed(&decide(None)), Some(false));
        assert_eq!(closed(&decide(Some(b""))), Some(false));
        assert_eq!(closed(&decide(Some(b"cbrs_mode_grant=1\0"))), Some(false));
        assert_eq!(closed(&decide(Some(b"cbrs_grant_state=2\0"))), Some(false));
        assert_eq!(closed(&decide(Some(&cache("", "2")))), Some(false));
        assert_eq!(closed(&decide(Some(&cache("1", "22")))), Some(false));
        assert_eq!(closed(&decide(Some(&cache("yes", "2")))), Some(false));
        // A longer key is not the key.
        assert_eq!(closed(&decide(Some(b"cbrs_mode_grant_x=1\0cbrs_grant_state_x=2\0"))), Some(false));
        // A torn read that ends mid-record.
        assert_eq!(closed(&decide(Some(b"cbrs_mode_grant=1\0cbrs_grant_sta"))), Some(false));
        let Gate::Closed { why, .. } = decide(Some(b"cbrs_mode_grant=0\0")) else { panic!() };
        assert_eq!(why, "no SAS grant (cbrs_mode_grant=0, cbrs_grant_state=unset)");
    }

    #[test]
    fn the_band_never_opens_the_gate() {
        let other = b"sqns_radio_band=4\0cbrs_mode_grant=0\0cbrs_grant_state=0\0";
        assert_eq!(closed(&decide(Some(other))), Some(true));
    }

    #[test]
    fn rules_drop_forwarded_ipv6_both_ways_on_every_bearer() {
        let text: Vec<String> = RULES
            .iter()
            .map(|rule| format!("{} {}", rule.tool.name(), rule.insert_args().join(" ")))
            .collect();
        assert_eq!(
            text,
            [
                "ebtables -I FORWARD 1 -p IPv6 -o lte0pdn+ -j DROP",
                "ebtables -I FORWARD 1 -p IPv6 -i lte0pdn+ -j DROP",
                "ip6tables -I FORWARD 1 -o lte0pdn+ -j DROP",
                "ip6tables -I FORWARD 1 -i lte0pdn+ -j DROP",
            ]
        );
        assert_eq!(RULES[0].delete_args().join(" "), "-D FORWARD -p IPv6 -o lte0pdn+ -j DROP");
        assert_eq!(RULES[3].delete_args().join(" "), "-D FORWARD -i lte0pdn+ -j DROP");
        assert_eq!(Tool::Ebtables.list_args(), ["-L", "FORWARD"]);
        assert_eq!(Tool::Ip6tables.list_args(), ["-S", "FORWARD"]);
        // No rule touches INPUT, OUTPUT, the management bearer by name, or the
        // customer port.
        for rule in RULES {
            for args in [rule.insert_args(), rule.delete_args()] {
                assert!(args.contains(&"FORWARD"));
                for word in ["INPUT", "OUTPUT", "lte0pdn0", "eth0", "br0"] {
                    assert!(!args.contains(&word), "{args:?}");
                }
            }
        }
    }

    // `ebtables -L FORWARD` from ebtables v2.0.10-4: one line per rule, each
    // ending in a space, the chain name not repeated.
    const EBT: &str = "Bridge table: filter\n\nBridge chain: FORWARD, entries: 5, policy: ACCEPT\n\
        -p IPv6 -i lte0pdn+ -j DROP \n\
        -p IPv6 -o lte0pdn+ -j DROP \n\
        -p IPv4 -o lte0pdn2 --ip-proto udp --ip-dport 67 -j DROP \n\
        -d 33:33:0:0:0:16 -o lte0pdn2 -j DROP \n\
        -p IPv6 -i lte0pdn+ -j DROP \n";

    #[test]
    fn ebtables_listing_counts_only_the_gate_rules() {
        let [out, inward, ..] = RULES;
        assert_eq!(out.count(EBT), Some(1));
        assert_eq!(inward.count(EBT), Some(2));
        let empty = "Bridge table: filter\n\nBridge chain: FORWARD, entries: 0, policy: ACCEPT\n";
        assert_eq!(out.count(empty), Some(0));
        // Without /etc/ethertypes the type prints in hex.
        let hex = format!("{empty}-p 0x86dd -o lte0pdn+ -j DROP \n");
        assert_eq!(out.count(&hex), Some(1));
        for other in [
            "-p IPv6 -o lte0pdn2 -j DROP",
            "-p IPv4 -o lte0pdn+ -j DROP",
            "-p IPv6 -o lte0pdn+ -j ACCEPT",
            "-p ! IPv6 -o lte0pdn+ -j DROP",
            "-p IPv6 -o ! lte0pdn+ -j DROP",
            "-p IPv6 -o lte0pdn+ --logical-out br0 -j DROP",
            "-p IPv6 -i lte0pdn+ -j DROP",
            "-o lte0pdn+ -j DROP",
        ] {
            assert_eq!(out.count(&format!("{empty}{other} \n")), Some(0), "{other}");
        }
        // Another chain, an error or nothing is not a listing.
        assert_eq!(out.count("Bridge table: filter\n\nBridge chain: INPUT, entries: 1, policy: ACCEPT\n-p IPv6 -o lte0pdn+ -j DROP \n"), None);
        assert_eq!(out.count("ebtables: No chain/target/match by that name.\n"), None);
        assert_eq!(out.count(""), None);
        // An ip6tables listing is not an ebtables one.
        assert_eq!(out.count("-P FORWARD ACCEPT\n-A FORWARD -o lte0pdn+ -j DROP\n"), None);
    }

    const IP6: &str = "-P FORWARD ACCEPT\n\
        -A FORWARD -o lte0pdn+ -j DROP\n\
        -A FORWARD -m rt --rt-type 0 -j DROP\n\
        -A FORWARD -o lte0pdn+ -j DROP\n";

    #[test]
    fn ip6tables_listing_counts_only_the_gate_rules() {
        let [.., out, inward] = RULES;
        assert_eq!(out.count(IP6), Some(2));
        assert_eq!(inward.count(IP6), Some(0));
        for other in [
            "-A FORWARD -o lte0pdn0 -j DROP",
            "-A FORWARD -o lte0pdn+ -j ACCEPT",
            "-A FORWARD -o lte0pdn+ -p tcp -j DROP",
            "-A FORWARD ! -o lte0pdn+ -j DROP",
            "-A INPUT -o lte0pdn+ -j DROP",
            "-A OUTPUT -o lte0pdn+ -j DROP",
            "-o lte0pdn+ -j DROP",
        ] {
            assert_eq!(out.count(&format!("-P FORWARD ACCEPT\n{other}\n")), Some(0), "{other}");
        }
        assert_eq!(out.count("ip6tables: No chain/target/match by that name.\n"), None);
        assert_eq!(out.count("-P INPUT ACCEPT\n-A INPUT -o lte0pdn+ -j DROP\n"), None);
        assert_eq!(out.count(""), None);
        assert_eq!(out.count(EBT), None);
    }

    /// Both FORWARD chains, printed and edited the way the real tools do.
    #[derive(Default)]
    struct Fake {
        ebt: Vec<String>,
        ip6: Vec<String>,
        /// Tools whose every command fails, as when the program is missing.
        broken: Vec<Tool>,
        /// Tools whose listing fails but whose edits work.
        unlisted: Vec<Tool>,
        log: Vec<String>,
    }

    impl Fake {
        fn run(&mut self, tool: Tool, args: &[&str]) -> Result<String, String> {
            self.log.push(format!("{} {}", tool.name(), args.join(" ")));
            if self.broken.contains(&tool) {
                return Err("not found".into());
            }
            let chain = match tool {
                Tool::Ebtables => &mut self.ebt,
                Tool::Ip6tables => &mut self.ip6,
            };
            match args {
                ["-L", "FORWARD"] if tool == Tool::Ebtables && !self.unlisted.contains(&tool) => {
                    let mut text = format!(
                        "Bridge table: filter\n\nBridge chain: FORWARD, entries: {}, policy: ACCEPT\n",
                        chain.len()
                    );
                    for rule in chain.iter() {
                        text.push_str(rule);
                        text.push_str(" \n");
                    }
                    Ok(text)
                }
                ["-S", "FORWARD"] if tool == Tool::Ip6tables && !self.unlisted.contains(&tool) => {
                    let mut text = "-P FORWARD ACCEPT\n".to_owned();
                    for rule in chain.iter() {
                        text.push_str(&format!("-A FORWARD {rule}\n"));
                    }
                    Ok(text)
                }
                ["-I", "FORWARD", "1", spec @ ..] => {
                    chain.insert(0, spec.join(" "));
                    Ok(String::new())
                }
                ["-D", "FORWARD", spec @ ..] => {
                    let spec = spec.join(" ");
                    match chain.iter().position(|rule| *rule == spec) {
                        Some(at) => {
                            chain.remove(at);
                            Ok(String::new())
                        }
                        None => Err("Sorry, rule does not exist.".into()),
                    }
                }
                _ => Err(format!("unexpected: {args:?}")),
            }
        }

        fn gate_rules(&self) -> usize {
            self.ebt.iter().chain(&self.ip6).filter(|rule| rule.contains("lte0pdn+")).count()
        }
    }

    fn close_on(fake: &mut Fake) -> (usize, Vec<String>) {
        close(&mut |tool, args: &[&str]| fake.run(tool, args))
    }

    fn open_on(fake: &mut Fake) -> (Cleanup, Vec<String>) {
        open(&mut |tool, args: &[&str]| fake.run(tool, args))
    }

    #[test]
    fn close_adds_what_is_missing_ahead_of_other_rules_and_nothing_twice() {
        let mut fake = Fake {
            ebt: vec!["-p IPv4 -o lte0pdn2 --ip-proto udp --ip-dport 67 -j DROP".into()],
            ip6: vec!["-m rt --rt-type 0 -j DROP".into()],
            ..Fake::default()
        };
        assert_eq!(close_on(&mut fake), (4, vec![]));
        assert_eq!(fake.gate_rules(), 4);
        assert!(fake.ebt[0].starts_with("-p IPv6") && fake.ebt[1].starts_with("-p IPv6"));
        assert!(fake.ip6[0].contains("lte0pdn+") && fake.ip6[1].contains("lte0pdn+"));
        // A second round reads both chains and adds nothing.
        fake.log.clear();
        assert_eq!(close_on(&mut fake), (0, vec![]));
        assert_eq!(fake.log, ["ebtables -L FORWARD", "ip6tables -S FORWARD"]);
        // A vendor firewall restart flushes both tables. The next round puts
        // the rules back.
        fake.ebt.clear();
        fake.ip6.retain(|rule| !rule.contains("lte0pdn+"));
        assert_eq!(close_on(&mut fake), (4, vec![]));
        assert_eq!(fake.gate_rules(), 4);
        // One rule gone: only that one comes back.
        fake.ip6.remove(0);
        assert_eq!(close_on(&mut fake), (1, vec![]));
        assert_eq!(fake.gate_rules(), 4);
    }

    #[test]
    fn close_fails_closed_when_a_chain_cannot_be_read() {
        let mut fake = Fake { unlisted: vec![Tool::Ebtables], ..Fake::default() };
        let unread = vec!["ebtables -L FORWARD could not be read; adding the rules anyway".to_owned()];
        // Only the listed chain counts as added, but both get the rules.
        assert_eq!(close_on(&mut fake), (2, unread.clone()));
        assert_eq!(fake.gate_rules(), 4);
        // It cannot tell the rules are there, so it adds them again, each
        // after one delete: one copy each, never a pile.
        for _ in 0..5 {
            assert_eq!(close_on(&mut fake), (0, unread.clone()));
        }
        assert_eq!(fake.ebt.len(), 2);
        assert_eq!(fake.gate_rules(), 4);
        fake.unlisted.clear();
        assert_eq!(open_on(&mut fake), (Cleanup::Removed, vec![]));
        assert_eq!(fake.gate_rules(), 0);
        assert_eq!(open_on(&mut fake), (Cleanup::Clean, vec![]));
    }

    #[test]
    fn close_reports_each_rule_it_could_not_add() {
        let mut fake = Fake { broken: vec![Tool::Ip6tables], ..Fake::default() };
        let (added, failed) = close_on(&mut fake);
        assert_eq!(added, 2);
        assert_eq!(
            failed,
            [
                "ip6tables -S FORWARD could not be read; adding the rules anyway",
                "ip6tables -I FORWARD 1 -o lte0pdn+ -j DROP failed: not found",
                "ip6tables -I FORWARD 1 -i lte0pdn+ -j DROP failed: not found",
            ]
        );
        // Bridged IPv6 is still blocked.
        assert_eq!(fake.ebt.len(), 2);
    }

    #[test]
    fn open_removes_every_copy_and_leaves_other_rules() {
        let mut fake = Fake::default();
        close_on(&mut fake);
        fake.ebt.push("-p IPv4 -o lte0pdn2 --ip-proto udp --ip-dport 68 -j DROP".into());
        fake.ip6.insert(0, "-o lte0pdn+ -j DROP".into());
        fake.ip6.push("-m rt --rt-type 0 -j DROP".into());
        assert_eq!(open_on(&mut fake), (Cleanup::Removed, vec![]));
        assert_eq!(fake.gate_rules(), 0);
        assert_eq!(fake.ebt, ["-p IPv4 -o lte0pdn2 --ip-proto udp --ip-dport 68 -j DROP"]);
        assert_eq!(fake.ip6, ["-m rt --rt-type 0 -j DROP"]);
        // The confirming round reads both chains and deletes nothing.
        fake.log.clear();
        assert_eq!(open_on(&mut fake), (Cleanup::Clean, vec![]));
        assert_eq!(fake.log, ["ebtables -L FORWARD", "ip6tables -S FORWARD"]);
    }

    #[test]
    fn open_without_a_listing_deletes_until_none_are_left_and_retries_later() {
        let mut fake = Fake::default();
        close_on(&mut fake);
        fake.ip6.insert(0, "-i lte0pdn+ -j DROP".into());
        fake.unlisted = vec![Tool::Ip6tables];
        let (cleanup, failed) = open_on(&mut fake);
        assert_eq!(cleanup, Cleanup::Failed);
        assert_eq!(failed, ["ip6tables -S FORWARD could not be read"]);
        assert_eq!(fake.gate_rules(), 0);
        // A tool that is missing altogether is a failure, never a loop.
        let mut gone = Fake { broken: vec![Tool::Ebtables, Tool::Ip6tables], ..Fake::default() };
        let (cleanup, _) = open_on(&mut gone);
        assert_eq!(cleanup, Cleanup::Failed);
        assert_eq!(gone.log.len(), 2 + RULES.len());
    }

    #[test]
    fn open_reports_a_listed_copy_it_could_not_delete() {
        let mut fake = Fake::default();
        close_on(&mut fake);
        let (cleanup, failed) = open(&mut |tool, args: &[&str]| {
            if args[0] == "-D" && tool == Tool::Ebtables {
                return Err("locked".into());
            }
            fake.run(tool, args)
        });
        assert_eq!(cleanup, Cleanup::Failed);
        assert_eq!(failed.len(), 2);
        assert!(failed[0].starts_with("ebtables -D FORWARD -p IPv6 -o lte0pdn+ -j DROP failed"));
    }

    fn no(clear: bool) -> Gate {
        Gate::Closed { why: "no SAS grant (cbrs_mode_grant=0, cbrs_grant_state=0)".into(), clear }
    }

    fn held() -> Gate {
        Gate::Open("SAS grant held".into())
    }

    #[test]
    fn the_grant_is_read_every_second() {
        let mut w = Watch::default();
        assert!(w.due(0));
        w.observe(10, &held());
        assert!(!w.due(10));
        assert!(w.due(11));
    }

    #[test]
    fn a_clear_loss_closes_at_once_and_rechecks_every_second() {
        let mut w = Watch::default();
        let (step, line) = w.observe(100, &no(true));
        assert_eq!(step, Step::Close);
        assert_eq!(
            line.as_deref(),
            Some("CBRS gate closed: no SAS grant (cbrs_mode_grant=0, cbrs_grant_state=0); dropping customer IPv6 to and from LTE")
        );
        assert!(w.dirty());
        for t in 101..110 {
            assert_eq!(w.observe(t, &no(true)), (Step::Close, None));
        }
    }

    #[test]
    fn an_unclear_read_closes_only_when_the_next_read_agrees() {
        let mut w = Watch::default();
        w.observe(0, &held());
        w.cleaned(0, Cleanup::Clean);
        // One torn read between two good ones changes nothing.
        assert_eq!(w.observe(1, &no(false)), (Step::Hold, None));
        assert_eq!(w.observe(2, &held()), (Step::Hold, None));
        // Two unclear reads one clock second apart can be 0.1 s apart in real
        // time: still no. The read two clock seconds after the first closes.
        assert_eq!(w.observe(3, &no(false)), (Step::Hold, None));
        assert_eq!(w.observe(4, &no(false)), (Step::Hold, None));
        let (step, line) = w.observe(5, &no(false));
        assert_eq!(step, Step::Close);
        assert!(line.is_some());
        // Once closed, an unclear read keeps it closed.
        assert_eq!(w.observe(6, &no(false)), (Step::Close, None));
        // At start, an unclear read waits for confirmation too.
        let mut v = Watch::default();
        assert_eq!(v.observe(0, &no(false)), (Step::Hold, None));
        assert_eq!(v.observe(1, &no(false)), (Step::Hold, None));
        assert_eq!(v.observe(2, &no(false)).0, Step::Close);
        // A clear loss never waits, even in the middle of a doubt.
        let mut u = Watch::default();
        u.observe(0, &held());
        assert_eq!(u.observe(1, &no(false)), (Step::Hold, None));
        assert_eq!(u.observe(2, &no(true)).0, Step::Close);
    }

    #[test]
    fn a_grant_opens_at_once_then_checks_rarely() {
        let mut w = Watch::default();
        w.observe(0, &no(true));
        let (step, line) = w.observe(1, &held());
        assert_eq!(step, Step::Open);
        assert_eq!(line.as_deref(), Some("CBRS gate open: SAS grant held; customer IPv6 may forward"));
        w.cleaned(1, Cleanup::Removed);
        assert!(w.dirty());
        assert_eq!(w.observe(2, &held()), (Step::Open, None));
        w.cleaned(2, Cleanup::Clean);
        assert!(!w.dirty());
        for t in 3..2 + VERIFY {
            assert_eq!(w.observe(t, &held()), (Step::Hold, None), "{t}");
        }
        assert_eq!(w.observe(2 + VERIFY, &held()), (Step::Open, None));
        // A cleanup that could not finish waits RETRY.
        w.cleaned(2 + VERIFY, Cleanup::Failed);
        assert_eq!(w.observe(3 + VERIFY, &held()), (Step::Hold, None));
        assert_eq!(w.observe(2 + VERIFY + RETRY, &held()), (Step::Open, None));
    }

    #[test]
    fn a_restarted_keeper_cleans_up_first_and_a_new_loss_always_closes() {
        let mut w = Watch::default();
        assert!(w.dirty());
        let (step, line) = w.observe(0, &held());
        assert_eq!(step, Step::Open);
        assert!(line.is_some());
        w.cleaned(0, Cleanup::Clean);
        // The grant goes while the gate waits to verify: it closes at once.
        assert_eq!(w.observe(1, &no(true)).0, Step::Close);
        // And opens at once when the grant is back, whatever the verify timer.
        assert_eq!(w.observe(2, &held()).0, Step::Open);
    }
}
