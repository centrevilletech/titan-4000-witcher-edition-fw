//! Wire format and read-backs for volatile settings on the band 48 modem.
//!
//! Bench findings (2026-11-22) set the rules here:
//! - A carrier cap (`AT%GCACTRL=3,N`) takes effect only at the next attach,
//!   and the tower can still add a carrier during a connection. The cap is
//!   re-checked after each attach and periodically, never assumed.
//! - A re-attach that changes the carrier set makes the vendor SAS client
//!   give back every grant. Applying or removing a profile never cycles the
//!   radio. Only an opt-in enforcement cycle may, at most once per
//!   `cycle_hours`, and only while the grant is held.
//! - A PCell lock is only a nudge for that one cycle. It is always cleared
//!   with `AT%GLOCKPCELL=1,0,0` (`AT%GLOCKPCELL=0` returns ERROR).
use crate::carrier_pick::{self, Arm};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    mem::discriminant,
    net::{Ipv4Addr, SocketAddrV4},
};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u8,
    /// A ping responder reachable through the management bearer.
    pub management_probe: Option<Ipv4Addr>,
    pub actions: Vec<Action>,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            version: 1,
            management_probe: None,
            actions: vec![],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cell {
    pub earfcn: u32,
    pub pci: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    CarrierAggregation {
        carriers: u8,
        /// Opt-in: re-attach to enforce the cap at most once per this many
        /// hours. Absent means the radio is never cycled for the cap.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cycle_hours: Option<u16>,
        /// Opt-in: hold this primary cell only during an enforcement cycle.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nudge: Option<Cell>,
    },
    Sqm {
        upload_kbit: u32,
        download_kbit: u32,
    },
    /// Survey the listed combinations and hold the best. See
    /// `titan_pd_model::carrier_pick`. Replaces `carrier_aggregation`.
    CarrierPick {
        arms: Vec<Arm>,
        /// The probe server, reached through the management bearer.
        probe: SocketAddrV4,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        survey_hours: Option<u16>,
        /// `HH:MM-HH:MM` UTC. It may not touch the SAS coordination window.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        window_utc: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ul_weight: Option<u8>,
    },
}

/// The picker's settings with defaults filled in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Picker {
    pub arms: Vec<Arm>,
    pub probe: SocketAddrV4,
    pub survey_hours: u16,
    pub window: (u16, u16),
    pub ul_weight: u8,
}

/// Shortest allowed spacing of enforcement cycles.
pub const MIN_CYCLE_HOURS: u16 = 6;
/// The tower must hold the extra carrier this long before a cycle.
pub const OVER_CAP_GRACE: u64 = 300;
/// Clears a PCell lock. `AT%GLOCKPCELL=0` returns ERROR and does nothing.
pub const PCELL_CLEAR: &str = "AT%GLOCKPCELL=1,0,0";
pub const PCELL_QUERY: &str = "AT%GLOCKPCELL?";

impl Profile {
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > 4096 {
            return Err("profile exceeds 4096 bytes");
        }
        let profile: Self = serde_json::from_slice(bytes).map_err(|_| "invalid profile syntax")?;
        if profile.version != 1 {
            return Err("unsupported profile version");
        }
        if !profile.actions.is_empty()
            && !profile.management_probe.is_some_and(|ip| {
                !matches!(ip.octets()[0], 0 | 127 | 224..=255) && !ip.is_link_local()
            })
        {
            return Err("enabled profile needs a unicast management probe");
        }
        let mut kinds = HashSet::new();
        let has = |want: fn(&Action) -> bool| profile.actions.iter().any(want);
        if has(|a| matches!(a, Action::CarrierAggregation { .. }))
            && has(|a| matches!(a, Action::CarrierPick { .. }))
        {
            return Err("carrier_pick replaces carrier_aggregation");
        }
        for action in &profile.actions {
            if !kinds.insert(discriminant(action)) {
                return Err("duplicate action");
            }
            let ok = match action {
                Action::CarrierAggregation {
                    carriers,
                    cycle_hours,
                    nudge,
                } => {
                    (1..=4).contains(carriers)
                        && cycle_hours.is_none_or(|h| (MIN_CYCLE_HOURS..=168).contains(&h))
                        && nudge.is_none_or(|c| {
                            cycle_hours.is_some()
                                && (55240..=56739).contains(&c.earfcn)
                                && c.pci <= 503
                        })
                }
                Action::Sqm {
                    upload_kbit,
                    download_kbit,
                } => (64..=50000).contains(upload_kbit) && (64..=250000).contains(download_kbit),
                Action::CarrierPick {
                    arms,
                    probe,
                    survey_hours,
                    window_utc,
                    ul_weight,
                } => carrier_pick::validate(arms, *probe, *survey_hours, window_utc.as_deref(), *ul_weight),
            };
            if !ok {
                return Err("action outside supported range");
            }
        }
        Ok(profile)
    }

    /// The carrier cap and its enforcement settings, when configured.
    pub fn carrier_cap(&self) -> Option<(u8, Option<u16>, Option<Cell>)> {
        self.actions.iter().find_map(|a| match a {
            Action::CarrierAggregation {
                carriers,
                cycle_hours,
                nudge,
            } => Some((*carriers, *cycle_hours, *nudge)),
            Action::Sqm { .. } | Action::CarrierPick { .. } => None,
        })
    }

    /// The carrier picker, when configured.
    pub fn picker(&self) -> Option<Picker> {
        self.actions.iter().find_map(|a| match a {
            Action::CarrierPick {
                arms,
                probe,
                survey_hours,
                window_utc,
                ul_weight,
            } => Some(Picker {
                arms: arms.clone(),
                probe: *probe,
                survey_hours: survey_hours.unwrap_or(carrier_pick::DEFAULT_SURVEY_HOURS),
                window: window_utc
                    .as_deref()
                    .and_then(carrier_pick::parse_window)
                    .unwrap_or(carrier_pick::DEFAULT_WINDOW),
                ul_weight: ul_weight.unwrap_or(carrier_pick::DEFAULT_UL_WEIGHT),
            }),
            _ => None,
        })
    }
}

impl Action {
    pub fn query(&self) -> Option<&'static str> {
        match self {
            Self::CarrierAggregation { .. } => Some("AT%GCACTRL?"),
            Self::Sqm { .. } | Self::CarrierPick { .. } => None,
        }
    }
    pub fn command(&self, stock: bool) -> Option<String> {
        match self {
            Self::CarrierAggregation { carriers, .. } => Some(match (stock, *carriers) {
                (true, _) => "AT%GCACTRL=3,4".into(),
                (_, 1) => "AT%GCACTRL=0".into(),
                _ => format!("AT%GCACTRL=3,{carriers}"),
            }),
            Self::Sqm { .. } | Self::CarrierPick { .. } => None,
        }
    }

    pub fn matches_reply(&self, reply: &str, stock: bool) -> bool {
        reply
            .lines()
            .any(|line| self.matches_line(&clean(line), stock))
    }

    fn matches_line(&self, line: &str, stock: bool) -> bool {
        match self {
            Self::CarrierAggregation { carriers, .. } => {
                let n = if stock { 4 } else { u32::from(*carriers) };
                let mode = if n == 1 { 0 } else { 3 };
                matches!(fields(line,"%GCACTRL:").as_deref(),Some([m,_,_,count]) if *m==mode && *count==n)
            }
            Self::Sqm { .. } | Self::CarrierPick { .. } => false,
        }
    }
}

pub fn pcell_lock(cell: Cell) -> String {
    format!("AT%GLOCKPCELL=1,{},{}", cell.earfcn, cell.pci)
}

/// `%GLOCKPCELL: 0` after a clear; `%GLOCKPCELL: 1, <earfcn>, <pci>` locked.
pub fn pcell_state(reply: &str) -> Option<Option<Cell>> {
    reply.lines().find_map(|s| match fields(&clean(s), "%GLOCKPCELL:")?.as_slice() {
        [0, ..] => Some(None),
        [1, earfcn, pci, ..] => Some(Some(Cell {
            earfcn: *earfcn,
            pci: u16::try_from(*pci).ok()?,
        })),
        _ => None,
    })
}

/// Serving carriers from `sqns_connection_sccInfo`: `-` with no secondary
/// carrier, otherwise `pci,earfcn,bw` entries separated by `:`.
pub fn carriers(scc_info: &str) -> Option<u8> {
    let text = scc_info.trim();
    if text == "-" {
        return Some(1);
    }
    let mut n = 1u8;
    for entry in text.split(':') {
        let parts: Vec<_> = entry.split(',').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.trim().parse::<u32>().is_err()) {
            return None;
        }
        n = n.checked_add(1)?;
    }
    Some(n)
}

/// What an enforcement cycle needs to see. Every value is read fresh.
#[derive(Clone, Copy, Debug)]
pub struct Gate<'a> {
    pub cap: u8,
    pub cycle_hours: Option<u16>,
    pub carriers: Option<u8>,
    pub attached: bool,
    /// Monotonic second the unit was first seen over the cap, still over.
    pub over_since: Option<u64>,
    /// Monotonic second of the last cycle (0 = boot).
    pub last_cycle: u64,
    pub now: u64,
    pub mode_grant: &'a str,
    pub grant_state: &'a str,
}

/// Whether one enforcement re-attach may run now, or why not.
pub fn cycle_gate(g: Gate) -> Result<(), &'static str> {
    let Some(hours) = g.cycle_hours else {
        return Err("radio cycles are off");
    };
    if !g.attached {
        return Err("not attached");
    }
    let Some(n) = g.carriers else {
        return Err("carrier state unreadable");
    };
    if n <= g.cap {
        return Err("within the carrier cap");
    }
    if !g
        .over_since
        .is_some_and(|t| g.now.saturating_sub(t) >= OVER_CAP_GRACE)
    {
        return Err("over the cap for less than 5 minutes");
    }
    if g.now.saturating_sub(g.last_cycle) < u64::from(hours.max(MIN_CYCLE_HOURS)) * 3600 {
        return Err("rate limit");
    }
    // A cycle that changes the carrier set gives back every grant. Never
    // start one unless the grant is fully held.
    if g.mode_grant != "1" || g.grant_state != "2" {
        return Err("SAS grant not held");
    }
    Ok(())
}

fn fields(line: &str, key: &str) -> Option<Vec<u32>> {
    line.strip_prefix(key)?
        .split(',')
        .map(|s| s.trim().parse().ok())
        .collect()
}

fn clean(line: &str) -> String {
    line.replace("\x1b[32m", "")
        .replace("\x1b[0m", "")
        .trim_start()
        .trim_start_matches("DM>")
        .trim()
        .to_string()
}

pub fn failures(reply: &str) -> Option<u32> {
    reply.lines().find_map(|s| {
        let line = clean(s);
        let (key, value) = line.split_once(':')?;
        (key.trim() == "- Reconfig Failure")
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

/// Count two failures even when they straddle adjacent sampling intervals.
pub fn storm(delta: u32, previous: Option<u64>, now: u64) -> bool {
    delta >= 2 || (delta == 1 && previous.is_some_and(|t| now.saturating_sub(t) <= 60))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn probe() -> serde_json::Value {
        serde_json::json!({"version":1,"actions":[],"management_probe":Ipv4Addr::from(0xc0000201u32)})
    }
    fn parse_actions(actions: serde_json::Value) -> Result<Profile, &'static str> {
        let mut p = probe();
        p["actions"] = actions;
        Profile::parse(&serde_json::to_vec(&p).unwrap())
    }

    #[test]
    fn profiles_are_closed_and_bounded() {
        assert_eq!(
            Profile::parse(br#"{"version":1,"actions":[]}"#),
            Ok(Profile::default())
        );
        for bad in [
            r#"{"kind":"raw","cmd":"AT"}"#,
            r#"{"kind":"carrier_aggregation","carriers":5}"#,
            r#"{"kind":"carrier_aggregation","carriers":2,"extra":0}"#,
            r#"{"kind":"carrier_aggregation","carriers":2,"cycle_hours":1}"#,
            r#"{"kind":"carrier_aggregation","carriers":2,"cycle_hours":169}"#,
            r#"{"kind":"carrier_aggregation","carriers":2,"nudge":{"earfcn":55440,"pci":199}}"#,
            r#"{"kind":"carrier_aggregation","carriers":2,"cycle_hours":6,"nudge":{"earfcn":55239,"pci":0}}"#,
            r#"{"kind":"carrier_aggregation","carriers":2,"cycle_hours":6,"nudge":{"earfcn":55440,"pci":504}}"#,
            r#"{"kind":"sqm","upload_kbit":0,"download_kbit":1000}"#,
            // Removed after the bench study: never accepted again.
            r#"{"kind":"lock_pcell","earfcn":55440,"pci":199}"#,
            r#"{"kind":"buffer_margin","kb":1}"#,
            r#"{"kind":"mmse_dse","enabled":false}"#,
            r#"{"kind":"ca_dl_layers","layers":2}"#,
        ] {
            let action = serde_json::from_str::<serde_json::Value>(bad).unwrap();
            assert!(parse_actions(serde_json::json!([action])).is_err(), "{bad}");
        }
        for bad in [
            r#"{"version":2,"actions":[]}"#,
            r#"{"version":1,"actions":[{"kind":"carrier_aggregation","carriers":2}]}"#,
        ] {
            assert!(Profile::parse(bad.as_bytes()).is_err());
        }
    }

    #[test]
    fn accepted_actions_round_trip_and_duplicates_fail() {
        let mut profile = Profile {
            version: 1,
            management_probe: Some(Ipv4Addr::from(0xc0000201u32)),
            actions: vec![
                Action::CarrierAggregation {
                    carriers: 2,
                    cycle_hours: Some(12),
                    nudge: Some(Cell {
                        earfcn: 55440,
                        pci: 199,
                    }),
                },
                Action::Sqm {
                    upload_kbit: 9000,
                    download_kbit: 90000,
                },
            ],
        };
        assert_eq!(
            Profile::parse(&serde_json::to_vec(&profile).unwrap()).unwrap(),
            profile
        );
        assert_eq!(
            profile.actions[0].command(false).as_deref(),
            Some("AT%GCACTRL=3,2")
        );
        assert_eq!(
            profile.actions[0].command(true).as_deref(),
            Some("AT%GCACTRL=3,4")
        );
        assert_eq!(
            profile.carrier_cap(),
            Some((2, Some(12), Some(Cell { earfcn: 55440, pci: 199 })))
        );
        let plain = parse_actions(serde_json::json!([{"kind":"carrier_aggregation","carriers":1}]))
            .unwrap();
        assert_eq!(plain.actions[0].command(false).as_deref(), Some("AT%GCACTRL=0"));
        assert_eq!(plain.carrier_cap(), Some((1, None, None)));
        profile.actions.push(Action::CarrierAggregation {
            carriers: 3,
            cycle_hours: None,
            nudge: None,
        });
        assert!(Profile::parse(&serde_json::to_vec(&profile).unwrap()).is_err());
    }

    #[test]
    fn the_picker_parses_with_defaults_and_replaces_the_cap() {
        let pick = serde_json::json!({"kind":"carrier_pick","probe":"192.0.2.10:5310","arms":[
            {"earfcn":55440,"pci":199,"carriers":2},{"earfcn":56440,"pci":208,"carriers":3}]});
        let p = parse_actions(serde_json::json!([pick.clone()])).unwrap();
        let picker = p.picker().unwrap();
        assert_eq!(picker.arms.len(), 2);
        assert_eq!(picker.survey_hours, carrier_pick::DEFAULT_SURVEY_HOURS);
        assert_eq!(picker.window, carrier_pick::DEFAULT_WINDOW);
        assert_eq!(picker.ul_weight, carrier_pick::DEFAULT_UL_WEIGHT);
        assert_eq!(p.carrier_cap(), None);
        assert_eq!(p.actions[0].query(), None);
        assert_eq!(p.actions[0].command(true), None);
        let both = serde_json::json!([pick.clone(), {"kind":"carrier_aggregation","carriers":2}]);
        assert_eq!(parse_actions(both), Err("carrier_pick replaces carrier_aggregation"));
        let mut cpas = pick.clone();
        cpas["window_utc"] = "06:00-08:00".into();
        assert!(parse_actions(serde_json::json!([cpas])).is_err());
        let mut tuned = pick;
        tuned["window_utc"] = "19:00-23:30".into();
        tuned["survey_hours"] = 24.into();
        tuned["ul_weight"] = 8.into();
        let t = parse_actions(serde_json::json!([tuned])).unwrap().picker().unwrap();
        assert_eq!((t.window, t.survey_hours, t.ul_weight), ((1140, 1410), 24, 8));
        assert_eq!(
            Profile::parse(&serde_json::to_vec(&parse_actions(serde_json::json!([]))
                .unwrap()).unwrap()).unwrap().picker(),
            None
        );
    }

    #[test]
    fn storm_crosses_sample_boundaries() {
        assert!(storm(2, None, 30));
        assert!(storm(1, Some(30), 90));
        assert!(!storm(1, Some(30), 91));
        assert!(!storm(0, Some(30), 31));
    }

    #[test]
    fn reads_values_instead_of_command_echoes() {
        let one = Action::CarrierAggregation {
            carriers: 1,
            cycle_hours: None,
            nudge: None,
        };
        let two = Action::CarrierAggregation {
            carriers: 2,
            cycle_hours: None,
            nudge: None,
        };
        assert!(one.matches_reply("%GCACTRL: 0, 4, 3, 1", false));
        assert!(!two.matches_reply("AT%GCACTRL=3,2\nOK", false));
        assert!(two.matches_reply("%GCACTRL: 3, 4, 3, 2", false));
        assert!(two.matches_reply("%GCACTRL: 3, 4, 3, 4", true));
        assert_eq!(
            failures("\x1b[32m      - Reconfig Failure   : 42\r\n\x1b[0m"),
            Some(42)
        );
        assert_eq!(failures("Reestablishment : 42"), None);
    }

    #[test]
    fn pcell_lock_reads_back_and_clears_with_the_working_command() {
        let cell = Cell {
            earfcn: 55440,
            pci: 199,
        };
        assert_eq!(pcell_lock(cell), "AT%GLOCKPCELL=1,55440,199");
        assert_eq!(PCELL_CLEAR, "AT%GLOCKPCELL=1,0,0");
        assert_eq!(pcell_state("AT%GLOCKPCELL?\n%GLOCKPCELL: 0\nOK"), Some(None));
        assert_eq!(pcell_state("%GLOCKPCELL: 1, 55440, 199"), Some(Some(cell)));
        assert_eq!(pcell_state("ERROR"), None);
    }

    #[test]
    fn carrier_count_follows_the_vendor_snapshot() {
        assert_eq!(carriers("-"), Some(1));
        assert_eq!(carriers("217,56638,20"), Some(2));
        assert_eq!(carriers("217,56638,20:208,56440,20"), Some(3));
        assert_eq!(carriers(""), None);
        assert_eq!(carriers("217,56638"), None);
        assert_eq!(carriers("x,56638,20"), None);
    }

    #[test]
    fn enforcement_needs_opt_in_time_over_cap_spacing_and_a_held_grant() {
        let ok = Gate {
            cap: 2,
            cycle_hours: Some(6),
            carriers: Some(3),
            attached: true,
            over_since: Some(1000),
            last_cycle: 0,
            now: 6 * 3600 + 1000,
            mode_grant: "1",
            grant_state: "2",
        };
        assert_eq!(cycle_gate(ok), Ok(()));
        let no = |g: Gate| cycle_gate(g).unwrap_err();
        assert_eq!(no(Gate { cycle_hours: None, ..ok }), "radio cycles are off");
        assert_eq!(no(Gate { attached: false, ..ok }), "not attached");
        assert_eq!(no(Gate { carriers: None, ..ok }), "carrier state unreadable");
        assert_eq!(no(Gate { carriers: Some(2), ..ok }), "within the carrier cap");
        assert_eq!(
            no(Gate { over_since: Some(ok.now - OVER_CAP_GRACE + 1), ..ok }),
            "over the cap for less than 5 minutes"
        );
        assert_eq!(no(Gate { over_since: None, ..ok }), "over the cap for less than 5 minutes");
        assert_eq!(no(Gate { last_cycle: 1001, ..ok }), "rate limit");
        assert_eq!(no(Gate { now: 6 * 3600 - 1, over_since: Some(0), ..ok }), "rate limit");
        assert_eq!(no(Gate { mode_grant: "0", ..ok }), "SAS grant not held");
        assert_eq!(no(Gate { grant_state: "1", ..ok }), "SAS grant not held");
    }
}
