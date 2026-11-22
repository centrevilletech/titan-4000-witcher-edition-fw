//! The grant manager: what to ask the SAS, when, and whether customer
//! traffic may flow.
//!
//! The engine does no I/O. The daemon feeds it radio events, SAS answers and
//! clock ticks, and carries out the actions it returns. `now` is a monotonic
//! clock in seconds, so a step of the wall clock changes nothing. `wall` is
//! Unix time and is used only for what the SAS states in wall time.
//!
//! Rules it keeps (see `docs/sas-client.md`):
//!
//! 1. The gate is open only while every carrier in use lies inside grants
//!    that are Authorized with transmit expiry still ahead.
//! 2. A grant is used only after a successful heartbeat for it.
//! 3. A suspended grant is kept and heartbeated. It is never traded for a
//!    new one, and a problem on one carrier never drops another's grant.
//! 4. When a carrier in use has lost its authorization and 60 seconds since
//!    transmit expiry are nearly up, the radio leaves that carrier.
//! 5. Nothing here re-registers or deregisters because of a grant error.
use serde_json::{Value, json};

use crate::band::{self, Range};
use crate::proto::{self, Item, Kind};

/// How long a TCP connection to the SAS may take.
pub const CONNECT_TIMEOUT: u64 = 10;
/// How long the first try of a call waits for its answer. Real Grant answers
/// take 3 to 6 seconds and inquiries up to 16.
pub const ANSWER_TIMEOUT: u64 = 30;
/// A Grant call that timed out waits longer next time, up to this.
pub const ANSWER_TIMEOUT_MAX: u64 = 120;
/// After a radio command, how long to wait for the radio to come back before
/// trying again.
const REJOIN_WAIT: u64 = 300;
const HEARTBEAT_RETRY: [u64; 4] = [30, 60, 120, 300];
const GRANT_RETRY: [u64; 5] = [5, 10, 20, 40, 60];
const REGISTER_RETRY: [u64; 4] = [60, 300, 900, 3600];
const ORPHAN_TRIES: u32 = 3;

#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    /// The widest single grant to ask for, in hertz. A wider run of carriers
    /// is split from its low edge.
    pub max_grant_width: u64,
    /// The power to ask for, in dBm/MHz, unless the SAS suggested less.
    pub max_eirp: f64,
    /// How long a grant is kept after its range was last in use, in seconds.
    pub retain_idle: u64,
    /// The most grants to hold at once.
    pub max_grants: usize,
    /// Extra ranges to hold grants for even when not in use. Empty unless the
    /// operator has decided to hold the serving sector's other carriers.
    pub standby: Vec<Range>,
    /// The share of the heartbeat interval to wait between heartbeats.
    pub heartbeat_percent: u64,
    /// Leave an unauthorized carrier this many seconds before the 60 second
    /// limit, to leave room for the modem to act.
    pub leave_margin: u64,
    /// Seconds to stay away after leaving, per attempt.
    pub rejoin_backoff: Vec<u64>,
    /// After rejoining, how long a heartbeat may take to restore
    /// authorization before the radio leaves again.
    pub probe_window: u64,
    /// When above zero: leave a carrier that has had no authorized grant for
    /// this long after the radio came up on it. Zero keeps the vendor
    /// behavior of staying attached while a first grant is pending.
    pub handshake_limit: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_grant_width: 20_000_000,
            max_eirp: 27.0,
            retain_idle: 86_400,
            max_grants: 8,
            standby: Vec::new(),
            heartbeat_percent: 80,
            leave_margin: 15,
            rejoin_backoff: vec![900, 1800, 3600],
            probe_window: 20,
            handshake_limit: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantState {
    /// Held, but not usable until a heartbeat succeeds.
    Granted,
    Authorized,
    /// The SAS answered 501. Kept and heartbeated until it clears.
    Suspended,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Grant {
    pub id: String,
    pub range: Range,
    pub max_eirp: f64,
    pub state: GrantState,
    pub interval: u64,
    /// Unix seconds, as the SAS stated them. Zero when unknown.
    pub grant_expire: u64,
    pub transmit_expire: u64,
    /// The monotonic second at which the right to transmit ends or ended.
    deadline: Option<u64>,
    next_heartbeat: u64,
    failures: u32,
    suspensions: u32,
    pub reason: String,
    last_used: u64,
    relinquish: bool,
}

impl Grant {
    pub fn usable(&self, now: u64) -> bool {
        self.state == GrantState::Authorized && self.deadline.is_some_and(|end| end > now)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Gate {
    Closed,
    /// `max_eirp` is the lowest power any grant in use allows, in dBm/MHz.
    Open {
        max_eirp: f64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RadioCommand {
    /// Leave the main carrier: its authorization is gone.
    LeavePrimary,
    /// Stop using the uplink secondary carrier: its authorization is gone.
    DropUplink,
    /// Try the carrier again.
    Rejoin,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub id: u64,
    pub kind: Kind,
    pub body: String,
    pub connect_timeout: u64,
    pub answer_timeout: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Answer {
    pub items: Vec<Item>,
    /// The SAS's clock from the HTTP `Date` header, when present.
    pub server_time: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// No connection: the SAS never saw the request.
    Connect,
    /// Sent, but no answer in time. The SAS may still have acted on it.
    Timeout,
    /// An answer that is not a usable SAS message.
    Malformed(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Input {
    Tick,
    /// The LTE connection is up on these carriers. `uplink` is the secondary
    /// carrier the unit also transmits on, if any.
    Online {
        primary: Range,
        uplink: Option<Range>,
    },
    Offline,
    Reply {
        id: u64,
        result: Result<Answer, Failure>,
    },
    /// Hand back: close the gate, relinquish, deregister.
    Stop,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    Send(Request),
    Gate(Gate),
    Radio(RadioCommand),
    /// State to keep across a reboot.
    Persist(String),
    Log(String),
    /// Not registered, and this build has no registration request to send.
    CannotRegister,
    Stopped,
}

#[derive(Clone, Debug, PartialEq)]
enum Subject {
    None,
    Range(Range, f64),
    Grant(String),
}

#[derive(Clone, Debug)]
struct Flight {
    id: u64,
    kind: Kind,
    subjects: Vec<Subject>,
    sent_at: u64,
    limit: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Orphan {
    id: String,
    tries: u32,
    retry_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stand {
    None,
    Down { until: u64, attempt: usize },
    Probing { deadline: u64, attempt: usize },
}

pub struct Engine {
    policy: Policy,
    registration: Option<Value>,
    cbsd: Option<String>,
    grants: Vec<Grant>,
    orphans: Vec<Orphan>,
    online: bool,
    primary: Option<Range>,
    uplink: Option<Range>,
    in_use_since: u64,
    /// Ranges whose authorization ended, with the monotonic second it ended.
    ended: Vec<(Range, u64)>,
    /// Ranges the SAS refused, and when to ask again.
    denied: Vec<(Range, u64)>,
    /// Lower power the SAS suggested for a range.
    hints: Vec<(Range, f64)>,
    inquiry_due: bool,
    inquiry_at: u64,
    flight: Option<Flight>,
    next_id: u64,
    gate: Gate,
    register_at: u64,
    register_failures: u32,
    grant_at: u64,
    grant_failures: u32,
    grant_timeout: u64,
    relinquish_at: u64,
    stand: Stand,
    stopping: bool,
    stopped: bool,
    told_cannot_register: bool,
    dirty: bool,
}

fn retry(table: &[u64], failures: u32) -> u64 {
    let index = (failures.saturating_sub(1) as usize).min(table.len().saturating_sub(1));
    table.get(index).copied().unwrap_or(60)
}

/// How soon to heartbeat a suspended grant again. Interference calculations
/// take the SAS seconds to minutes, so those are checked quickly at first.
/// Other suspensions last hours, and the grant must be kept meanwhile.
fn suspension_delay(reason: &str, count: u32, interval: u64) -> u64 {
    if reason
        .to_ascii_lowercase()
        .contains("interference calculations")
    {
        return match count {
            0 | 1 => 5,
            2 => 10,
            3 => 20,
            _ => 60,
        };
    }
    300_u64.min(interval.max(1))
}

impl Engine {
    /// `registration` is the unit's registration request object, or `None`
    /// when this unit must not register by itself. `cbsd` is a CBSD ID the
    /// SAS already issued, for taking over a registered unit.
    pub fn new(policy: Policy, registration: Option<Value>, cbsd: Option<String>) -> Self {
        Self {
            policy,
            registration,
            cbsd,
            grants: Vec::new(),
            orphans: Vec::new(),
            online: false,
            primary: None,
            uplink: None,
            in_use_since: 0,
            ended: Vec::new(),
            denied: Vec::new(),
            hints: Vec::new(),
            inquiry_due: false,
            inquiry_at: 0,
            flight: None,
            next_id: 1,
            gate: Gate::Closed,
            register_at: 0,
            register_failures: 0,
            grant_at: 0,
            grant_failures: 0,
            grant_timeout: ANSWER_TIMEOUT,
            relinquish_at: 0,
            stand: Stand::None,
            stopping: false,
            stopped: false,
            told_cannot_register: false,
            dirty: false,
        }
    }

    /// Bring back the grants saved before a reboot. None of them is usable
    /// until its next heartbeat succeeds.
    pub fn restore(&mut self, saved: &str, now: u64) -> Result<usize, String> {
        let value: Value =
            serde_json::from_str(saved).map_err(|err| format!("saved state is not JSON: {err}"))?;
        if value.get("version").and_then(Value::as_u64) != Some(1) {
            return Err("saved state has an unknown version".into());
        }
        if let Some(cbsd) = value.get("cbsdId").and_then(Value::as_str) {
            self.cbsd = Some(cbsd.to_string());
        }
        let mut restored = 0;
        for entry in value
            .get("grants")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let id = entry.get("id").and_then(Value::as_str);
            let low = entry.get("low").and_then(Value::as_u64);
            let high = entry.get("high").and_then(Value::as_u64);
            let (Some(id), Some(low), Some(high)) = (id, low, high) else {
                continue;
            };
            let Some(range) = Range::new(low, high) else {
                continue;
            };
            if self
                .grants
                .iter()
                .any(|grant| grant.id == id || grant.range.overlaps(range))
            {
                continue;
            }
            self.grants.push(Grant {
                id: id.to_string(),
                range,
                max_eirp: entry
                    .get("maxEirp")
                    .and_then(Value::as_f64)
                    .unwrap_or(self.policy.max_eirp)
                    .min(self.policy.max_eirp),
                state: GrantState::Granted,
                interval: entry.get("interval").and_then(Value::as_u64).unwrap_or(60),
                grant_expire: entry
                    .get("grantExpire")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                transmit_expire: 0,
                deadline: None,
                next_heartbeat: now,
                failures: 0,
                suspensions: 0,
                reason: String::new(),
                last_used: now,
                relinquish: false,
            });
            restored += 1;
        }
        Ok(restored)
    }

    fn snapshot(&self) -> String {
        let grants: Vec<Value> = self
            .grants
            .iter()
            .filter(|grant| !grant.relinquish)
            .map(|grant| {
                json!({
                    "id": grant.id,
                    "low": grant.range.low,
                    "high": grant.range.high,
                    "maxEirp": grant.max_eirp,
                    "interval": grant.interval,
                    "grantExpire": grant.grant_expire,
                })
            })
            .collect();
        json!({ "version": 1, "cbsdId": self.cbsd, "grants": grants }).to_string()
    }

    pub fn gate(&self) -> Gate {
        self.gate
    }

    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    pub fn registered(&self) -> bool {
        self.cbsd.is_some()
    }

    pub fn stopped(&self) -> bool {
        self.stopped
    }

    /// The carriers the unit transmits on now.
    pub fn in_use(&self) -> Vec<Range> {
        if !self.online {
            return Vec::new();
        }
        let ranges: Vec<Range> = self
            .primary
            .iter()
            .chain(self.uplink.iter())
            .copied()
            .collect();
        band::normalise(&ranges)
    }

    /// A summary for the status file. It holds no secret.
    pub fn status(&self, now: u64) -> Value {
        let grants: Vec<Value> = self
            .grants
            .iter()
            .map(|grant| {
                json!({
                    "range": grant.range.to_string(),
                    "state": match grant.state {
                        GrantState::Granted => "granted",
                        GrantState::Authorized if grant.usable(now) => "authorized",
                        GrantState::Authorized => "expired",
                        GrantState::Suspended => "suspended",
                    },
                    "maxEirp": grant.max_eirp,
                    "heartbeatInterval": grant.interval,
                    "transmitExpire": proto::format_utc(grant.transmit_expire),
                    "secondsLeft": grant.deadline.map(|end| end.saturating_sub(now)),
                    "nextHeartbeatIn": grant.next_heartbeat.saturating_sub(now),
                    "reason": grant.reason,
                })
            })
            .collect();
        json!({
            "registered": self.cbsd.is_some(),
            "online": self.online,
            "inUse": self.in_use().iter().map(Range::to_string).collect::<Vec<_>>(),
            "gate": match self.gate { Gate::Closed => "closed", Gate::Open { .. } => "open" },
            "standDown": match self.stand {
                Stand::None => "no",
                Stand::Down { .. } => "away",
                Stand::Probing { .. } => "probing",
            },
            "grants": grants,
            "orphans": self.orphans.len(),
            "callInFlight": self.flight.as_ref().map(|flight| flight.kind.method()),
        })
    }

    /// The next monotonic second at which a tick can change anything. The
    /// daemon sleeps until then unless an event arrives first.
    pub fn next_wake(&self, now: u64) -> u64 {
        // While anything is unsettled, look again within a minute whatever
        // the timers say.
        let unsettled = self.stand != Stand::None
            || !self.orphans.is_empty()
            || (self.online && self.gate == Gate::Closed);
        let mut wake = now + if unsettled { 60 } else { 3600 };
        // A time already past was dealt with by the step that just ran.
        let mut consider = |at: u64| {
            if at > now && at < wake {
                wake = at;
            }
        };
        if let Some(flight) = &self.flight {
            consider(flight.sent_at + flight.limit);
        }
        for grant in &self.grants {
            if let Some(end) = grant.deadline {
                consider(end);
                consider(end + 60 - self.policy.leave_margin.min(60));
            }
            if self.online {
                consider(grant.next_heartbeat);
            }
        }
        for (_, end) in &self.ended {
            consider(end + 60 - self.policy.leave_margin.min(60));
        }
        match self.stand {
            Stand::None => {}
            Stand::Down { until, .. } => consider(until),
            Stand::Probing { deadline, .. } => consider(deadline),
        }
        if self.online {
            for (_, until) in &self.denied {
                consider(*until);
            }
            for orphan in &self.orphans {
                consider(orphan.retry_at);
            }
            let used = self.in_use();
            let wanted =
                !self.missing(&used).is_empty() || !self.missing(&self.policy.standby).is_empty();
            if wanted || self.stopping {
                consider(self.grant_at.max(now + 1));
            }
            for grant in &self.grants {
                if grant.relinquish {
                    consider(self.relinquish_at.max(now + 1));
                } else if !used
                    .iter()
                    .chain(self.policy.standby.iter())
                    .any(|carrier| carrier.overlaps(grant.range))
                {
                    consider(grant.last_used + self.policy.retain_idle + 1);
                }
            }
            if self.cbsd.is_none() {
                consider(self.register_at);
            }
            if self.inquiry_due {
                consider(self.inquiry_at);
            }
            if self.policy.handshake_limit > 0 {
                consider(self.in_use_since + self.policy.handshake_limit);
            }
        }
        wake.max(now + 1)
    }

    pub fn step(&mut self, now: u64, wall: u64, input: Input) -> Vec<Action> {
        let mut out = Vec::new();
        match input {
            Input::Tick => {}
            Input::Online { primary, uplink } => self.on_online(now, primary, uplink, &mut out),
            Input::Offline => {
                if self.online {
                    out.push(Action::Log("radio offline".into()));
                }
                self.online = false;
            }
            Input::Reply { id, result } => self.on_reply(now, wall, id, result, &mut out),
            Input::Stop => {
                if !self.stopping {
                    self.stopping = true;
                    out.push(Action::Log("stopping: gate closed, grants go back".into()));
                    for grant in &mut self.grants {
                        grant.relinquish = true;
                    }
                }
            }
        }
        self.expire(now, &mut out);
        self.settle_gate(now, &mut out);
        self.stand_down(now, &mut out);
        self.dispatch(now, wall, &mut out);
        if self.dirty {
            self.dirty = false;
            out.push(Action::Persist(self.snapshot()));
        }
        out
    }

    fn on_online(
        &mut self,
        now: u64,
        primary: Range,
        uplink: Option<Range>,
        out: &mut Vec<Action>,
    ) {
        let uplink = uplink.filter(|range| !primary.contains(*range));
        let changed = !self.online || self.primary != Some(primary) || self.uplink != uplink;
        self.online = true;
        self.primary = Some(primary);
        self.uplink = uplink;
        let used = self.in_use();
        if changed {
            self.in_use_since = now;
            let second = uplink
                .map(|range| format!(" and {range}"))
                .unwrap_or_default();
            out.push(Action::Log(format!("radio online on {primary}{second}")));
            self.ended
                .retain(|(range, _)| used.iter().any(|carrier| carrier.overlaps(*range)));
        }
        for grant in &mut self.grants {
            if used.iter().any(|carrier| carrier.overlaps(grant.range)) {
                grant.last_used = now;
                if !grant.usable(now) {
                    grant.next_heartbeat = grant.next_heartbeat.min(now);
                }
            }
        }
        if let Stand::Down { attempt, .. } | Stand::Probing { attempt, .. } = self.stand {
            self.stand = Stand::Probing {
                deadline: now + self.policy.probe_window,
                attempt,
            };
        }
    }

    /// Transmit expiry: an Authorized grant whose time has run out is only
    /// Granted again. Heartbeats go on.
    fn expire(&mut self, now: u64, out: &mut Vec<Action>) {
        for grant in &mut self.grants {
            if grant.state == GrantState::Authorized && !grant.usable(now) {
                grant.state = GrantState::Granted;
                out.push(Action::Log(format!(
                    "transmit authority ended on {} with no heartbeat answer",
                    grant.range
                )));
            }
        }
        self.denied.retain(|(_, until)| *until > now);
    }

    fn usable_ranges(&self, now: u64) -> Vec<Range> {
        self.grants
            .iter()
            .filter(|grant| grant.usable(now) && !grant.relinquish)
            .map(|grant| grant.range)
            .collect()
    }

    fn wanted_gate(&self, now: u64) -> Gate {
        if self.stopping || !self.online {
            return Gate::Closed;
        }
        let used = self.in_use();
        let usable = self.usable_ranges(now);
        if used.is_empty() || used.iter().any(|carrier| !band::covered(*carrier, &usable)) {
            return Gate::Closed;
        }
        let max_eirp = self
            .grants
            .iter()
            .filter(|grant| {
                grant.usable(now) && used.iter().any(|carrier| carrier.overlaps(grant.range))
            })
            .map(|grant| grant.max_eirp)
            .fold(self.policy.max_eirp, f64::min);
        Gate::Open { max_eirp }
    }

    fn settle_gate(&mut self, now: u64, out: &mut Vec<Action>) {
        let wanted = self.wanted_gate(now);
        if wanted != self.gate {
            self.gate = wanted;
            out.push(Action::Log(match wanted {
                Gate::Closed => "customer traffic gate closed".into(),
                Gate::Open { max_eirp } => {
                    format!("customer traffic gate open, {max_eirp} dBm/MHz")
                }
            }));
            out.push(Action::Gate(wanted));
        }
        if wanted != Gate::Closed {
            self.ended.clear();
            self.stand = Stand::None;
        }
    }

    /// A carrier in use whose authorization the SAS took away or let run
    /// out, with the monotonic second by which the radio must be off it.
    fn trouble(&self, now: u64) -> Option<(Range, u64)> {
        let usable = self.usable_ranges(now);
        let mut worst: Option<(Range, u64)> = None;
        for carrier in self.in_use() {
            if band::covered(carrier, &usable) {
                continue;
            }
            let from_grants = self
                .grants
                .iter()
                .filter(|grant| grant.range.overlaps(carrier) && !grant.usable(now))
                .filter_map(|grant| grant.deadline);
            let from_ended = self
                .ended
                .iter()
                .filter(|(range, _)| range.overlaps(carrier))
                .map(|(_, end)| *end);
            let mut limit = from_grants.chain(from_ended).min().map(|end| end + 60);
            if self.policy.handshake_limit > 0 {
                let handshake = self.in_use_since + self.policy.handshake_limit;
                limit = Some(limit.map_or(handshake, |known| known.min(handshake)));
            }
            if let Some(limit) = limit {
                if worst.is_none_or(|(_, known)| limit < known) {
                    worst = Some((carrier, limit));
                }
            }
        }
        worst
    }

    fn leave(&mut self, now: u64, carrier: Range, attempt: usize, out: &mut Vec<Action>) {
        let primary = self.primary.is_some_and(|range| range.overlaps(carrier));
        let command = if primary {
            RadioCommand::LeavePrimary
        } else {
            RadioCommand::DropUplink
        };
        let backoff = &self.policy.rejoin_backoff;
        let wait = backoff
            .get(attempt.min(backoff.len().saturating_sub(1)))
            .copied()
            .unwrap_or(900);
        out.push(Action::Log(format!(
            "no authorization for {carrier}: leaving it, next try in {wait} s"
        )));
        out.push(Action::Radio(command));
        self.stand = Stand::Down {
            until: now + wait,
            attempt,
        };
    }

    fn stand_down(&mut self, now: u64, out: &mut Vec<Action>) {
        if self.stopping {
            return;
        }
        match self.stand {
            Stand::None => {
                if !self.online {
                    return;
                }
                if let Some((carrier, limit)) = self.trouble(now) {
                    if now + self.policy.leave_margin >= limit {
                        self.leave(now, carrier, 0, out);
                    }
                }
            }
            Stand::Down { until, attempt } => {
                if now < until {
                    return;
                }
                if self.online {
                    self.stand = Stand::Probing {
                        deadline: now + self.policy.probe_window,
                        attempt,
                    };
                } else {
                    out.push(Action::Log("trying the carrier again".into()));
                    out.push(Action::Radio(RadioCommand::Rejoin));
                    self.stand = Stand::Probing {
                        deadline: now + REJOIN_WAIT,
                        attempt,
                    };
                }
            }
            Stand::Probing { deadline, attempt } => {
                if now < deadline {
                    return;
                }
                if !self.online {
                    self.stand = Stand::None;
                    return;
                }
                match self.trouble(now) {
                    Some((carrier, _)) => self.leave(now, carrier, attempt + 1, out),
                    None => self.stand = Stand::None,
                }
            }
        }
    }

    fn send(
        &mut self,
        now: u64,
        kind: Kind,
        items: Vec<Value>,
        subjects: Vec<Subject>,
        answer_timeout: u64,
        out: &mut Vec<Action>,
    ) {
        let id = self.next_id;
        self.next_id += 1;
        self.flight = Some(Flight {
            id,
            kind,
            subjects,
            sent_at: now,
            limit: CONNECT_TIMEOUT + answer_timeout + 15,
        });
        out.push(Action::Send(Request {
            id,
            kind,
            body: proto::envelope(kind, items),
            connect_timeout: CONNECT_TIMEOUT,
            answer_timeout,
        }));
    }

    /// The parts of `ranges` with no grant of any state and no recent
    /// refusal, cut to the widest grant allowed.
    fn missing(&self, ranges: &[Range]) -> Vec<Range> {
        let mut held: Vec<Range> = self.grants.iter().map(|grant| grant.range).collect();
        held.extend(self.denied.iter().map(|(range, _)| *range));
        band::subtract(ranges, &held)
            .into_iter()
            .flat_map(|range| band::split(range, self.policy.max_grant_width))
            .collect()
    }

    fn eirp_for(&self, range: Range) -> f64 {
        self.hints
            .iter()
            .filter(|(hinted, _)| hinted.overlaps(range))
            .map(|(_, eirp)| *eirp)
            .fold(self.policy.max_eirp, f64::min)
    }

    fn dispatch(&mut self, now: u64, wall: u64, out: &mut Vec<Action>) {
        if self.stopped {
            return;
        }
        if let Some(flight) = &self.flight {
            if now < flight.sent_at + flight.limit {
                return;
            }
            // The daemon never answered. Treat it as a lost call.
            let id = flight.id;
            self.on_reply(now, wall, id, Err(Failure::Timeout), out);
        }
        if !self.online {
            if self.stopping {
                // No path to the SAS. The grants lapse there on their own.
                self.finish_stop(out);
            }
            return;
        }
        let Some(cbsd) = self.cbsd.clone() else {
            self.register(now, out);
            return;
        };

        // 1. Grants that must go back: 502, hand back, and grants the SAS
        //    holds that this client does not know.
        if now >= self.relinquish_at {
            let mut subjects: Vec<Subject> = self
                .grants
                .iter()
                .filter(|grant| grant.relinquish)
                .map(|grant| Subject::Grant(grant.id.clone()))
                .collect();
            subjects.extend(
                self.orphans
                    .iter()
                    .filter(|orphan| orphan.retry_at <= now)
                    .map(|orphan| Subject::Grant(orphan.id.clone())),
            );
            if !subjects.is_empty() {
                let items = subjects
                    .iter()
                    .map(|subject| match subject {
                        Subject::Grant(id) => proto::relinquishment_item(&cbsd, id),
                        _ => Value::Null,
                    })
                    .collect();
                self.send(
                    now,
                    Kind::Relinquishment,
                    items,
                    subjects,
                    ANSWER_TIMEOUT,
                    out,
                );
                return;
            }
        }
        if self.stopping {
            if self.grants.is_empty() && self.orphans.is_empty() {
                let items = vec![proto::deregistration_item(&cbsd)];
                self.send(
                    now,
                    Kind::Deregistration,
                    items,
                    vec![Subject::None],
                    ANSWER_TIMEOUT,
                    out,
                );
            }
            return;
        }

        let used = self.in_use();
        let due = |grant: &Grant| !grant.relinquish && grant.next_heartbeat <= now;
        let urgent = self
            .grants
            .iter()
            .any(|grant| due(grant) && used.iter().any(|carrier| carrier.overlaps(grant.range)));
        let missing_used = self.missing(&used);

        // 2. A heartbeat for a carrier in use comes first: it is what opens
        //    or keeps open the gate.
        if urgent {
            self.heartbeat(now, wall, &cbsd, out);
            return;
        }
        // 3. A grant for a carrier in use that has none.
        if !missing_used.is_empty() && now >= self.grant_at {
            if self.inquiry_due && now >= self.inquiry_at {
                let items = vec![proto::inquiry_item(&cbsd, &missing_used)];
                self.send(
                    now,
                    Kind::SpectrumInquiry,
                    items,
                    vec![Subject::None],
                    45,
                    out,
                );
            } else {
                self.request_grants(now, &cbsd, &missing_used, out);
            }
            return;
        }
        // 4. Heartbeats for grants held in reserve.
        if self.grants.iter().any(|grant| due(grant)) {
            self.heartbeat(now, wall, &cbsd, out);
            return;
        }
        // 5. Grants for standby ranges, when the operator asked for them.
        if !self.policy.standby.is_empty() && now >= self.grant_at {
            let room = self.policy.max_grants.saturating_sub(self.grants.len());
            let mut pieces = self.missing(&self.policy.standby);
            pieces.truncate(room);
            if !pieces.is_empty() {
                self.request_grants(now, &cbsd, &pieces, out);
                return;
            }
        }
        // 6. Give back grants nothing has used for a long time.
        self.retire_idle(now, &used);
    }

    fn register(&mut self, now: u64, out: &mut Vec<Action>) {
        if self.stopping {
            self.finish_stop(out);
            return;
        }
        let Some(registration) = self.registration.clone() else {
            if !self.told_cannot_register {
                self.told_cannot_register = true;
                out.push(Action::Log(
                    "not registered and no registration request to send".into(),
                ));
                out.push(Action::CannotRegister);
            }
            return;
        };
        if now >= self.register_at {
            self.send(
                now,
                Kind::Registration,
                vec![registration],
                vec![Subject::None],
                ANSWER_TIMEOUT,
                out,
            );
        }
    }

    fn heartbeat(&mut self, now: u64, wall: u64, cbsd: &str, out: &mut Vec<Action>) {
        let mut items = Vec::new();
        let mut subjects = Vec::new();
        for grant in &self.grants {
            // Grants due soon ride along, so all of them share one call.
            if grant.relinquish || grant.next_heartbeat > now + grant.interval / 5 {
                continue;
            }
            let renew = grant.grant_expire > 0 && grant.grant_expire < wall + 2 * 86_400;
            items.push(proto::heartbeat_item(
                cbsd,
                &grant.id,
                grant.usable(now),
                renew,
            ));
            subjects.push(Subject::Grant(grant.id.clone()));
        }
        if !items.is_empty() {
            self.send(now, Kind::Heartbeat, items, subjects, ANSWER_TIMEOUT, out);
        }
    }

    fn request_grants(&mut self, now: u64, cbsd: &str, pieces: &[Range], out: &mut Vec<Action>) {
        let mut items = Vec::new();
        let mut subjects = Vec::new();
        for piece in pieces {
            let eirp = self.eirp_for(*piece);
            items.push(proto::grant_item(cbsd, *piece, eirp));
            subjects.push(Subject::Range(*piece, eirp));
        }
        let timeout = self.grant_timeout;
        self.send(now, Kind::Grant, items, subjects, timeout, out);
    }

    fn retire_idle(&mut self, now: u64, used: &[Range]) {
        let standby = self.policy.standby.clone();
        let needed = |grant: &Grant| {
            used.iter()
                .chain(standby.iter())
                .any(|range| range.overlaps(grant.range))
        };
        let over = self.grants.len() > self.policy.max_grants;
        let retain = self.policy.retain_idle;
        let mut oldest: Option<usize> = None;
        for (index, grant) in self.grants.iter().enumerate() {
            if needed(grant) || grant.relinquish {
                continue;
            }
            let stale = now.saturating_sub(grant.last_used) > retain;
            if (stale || over)
                && oldest.is_none_or(|known| grant.last_used < self.grants[known].last_used)
            {
                oldest = Some(index);
            }
        }
        if let Some(index) = oldest {
            // The radio is not on this range, so there is nothing to stop
            // before the relinquishment goes out on the next pass.
            self.grants[index].relinquish = true;
        }
    }

    fn finish_stop(&mut self, out: &mut Vec<Action>) {
        if !self.stopped {
            self.stopped = true;
            self.grants.clear();
            self.orphans.clear();
            self.cbsd = None;
            out.push(Action::Persist(self.snapshot()));
            out.push(Action::Stopped);
        }
    }

    /// The SAS no longer knows this CBSD, or told it to stop.
    fn unregistered(&mut self, now: u64, wait: u64, cease: bool, why: &str, out: &mut Vec<Action>) {
        out.push(Action::Log(format!("registration lost: {why}")));
        if cease {
            for grant in &self.grants {
                self.ended.push((grant.range, now));
            }
        }
        self.grants.clear();
        self.orphans.clear();
        self.cbsd = None;
        self.register_at = now + wait;
        self.told_cannot_register = false;
        self.dirty = true;
    }

    fn on_reply(
        &mut self,
        now: u64,
        wall: u64,
        id: u64,
        result: Result<Answer, Failure>,
        out: &mut Vec<Action>,
    ) {
        let Some(flight) = self.flight.take_if(|flight| flight.id == id) else {
            out.push(Action::Log(format!(
                "dropped an answer to call {id}: not waiting for it"
            )));
            return;
        };
        let result = result.and_then(|answer| {
            if answer.items.len() == flight.subjects.len() {
                Ok(answer)
            } else {
                Err(Failure::Malformed(format!(
                    "{} answers to {} requests",
                    answer.items.len(),
                    flight.subjects.len()
                )))
            }
        });
        let answer = match result {
            Ok(answer) => answer,
            Err(failure) => {
                self.on_failure(now, &flight, &failure, out);
                return;
            }
        };
        // Transmit expiry is measured against the SAS's own clock when the
        // answer carries it, and from the moment the request left, which can
        // only make the deadline early. Without it, the unit's clock is used.
        let (clock, base) = match answer.server_time {
            Some(server) => (server, flight.sent_at),
            None => (wall, now),
        };
        for (item, subject) in answer.items.iter().zip(flight.subjects.iter()) {
            let names_cbsd = item
                .data
                .iter()
                .any(|name| name.eq_ignore_ascii_case("cbsdId"));
            match item.code {
                proto::DEREGISTER => {
                    self.unregistered(now, 60, true, "the SAS deregistered the unit (105)", out);
                    return;
                }
                proto::BLACKLISTED => {
                    self.unregistered(now, 3600, true, "the SAS has barred the unit (101)", out);
                    return;
                }
                proto::INVALID_VALUE if names_cbsd && flight.kind != Kind::Registration => {
                    self.unregistered(
                        now,
                        5,
                        false,
                        "the SAS does not know the CBSD ID (103)",
                        out,
                    );
                    return;
                }
                _ => {}
            }
            match flight.kind {
                Kind::Registration => self.on_registration(now, item, out),
                Kind::SpectrumInquiry => self.on_inquiry(now, item, out),
                Kind::Grant => self.on_grant(now, item, subject, out),
                Kind::Heartbeat => self.on_heartbeat(now, clock, base, item, subject, out),
                Kind::Relinquishment => self.on_relinquishment(now, item, subject, out),
                Kind::Deregistration => {
                    out.push(Action::Log(format!(
                        "deregistration answered {}",
                        item.code
                    )));
                    self.finish_stop(out);
                }
            }
        }
    }

    fn on_failure(&mut self, now: u64, flight: &Flight, failure: &Failure, out: &mut Vec<Action>) {
        let what = match failure {
            Failure::Connect => "no connection to the SAS".to_string(),
            Failure::Timeout => "no answer from the SAS in time".to_string(),
            Failure::Malformed(why) => format!("unusable answer ({why})"),
        };
        out.push(Action::Log(format!(
            "{} failed: {what}",
            flight.kind.method()
        )));
        match flight.kind {
            Kind::Registration => {
                self.register_failures += 1;
                self.register_at = now + retry(&REGISTER_RETRY, self.register_failures);
            }
            Kind::SpectrumInquiry => self.inquiry_at = now + 30,
            Kind::Grant => {
                if *failure == Failure::Timeout {
                    // The SAS may have made the grant. Ask again at once and
                    // wait longer. If it did, the answer is a 401 that names
                    // it, and that grant goes back before the next try.
                    self.grant_timeout = (self.grant_timeout * 2).min(ANSWER_TIMEOUT_MAX);
                    self.grant_at = now + 2;
                } else {
                    self.grant_failures += 1;
                    self.grant_at = now + retry(&GRANT_RETRY, self.grant_failures);
                }
            }
            Kind::Heartbeat => {
                for subject in &flight.subjects {
                    let Subject::Grant(id) = subject else {
                        continue;
                    };
                    if let Some(grant) = self.grants.iter_mut().find(|grant| grant.id == *id) {
                        grant.failures += 1;
                        grant.next_heartbeat = now + retry(&HEARTBEAT_RETRY, grant.failures);
                    }
                }
            }
            Kind::Relinquishment => {
                self.relinquish_at = now + 30;
                for orphan in &mut self.orphans {
                    if flight.subjects.contains(&Subject::Grant(orphan.id.clone())) {
                        orphan.tries += 1;
                        orphan.retry_at = now + 30;
                    }
                }
                self.orphans.retain(|orphan| orphan.tries < ORPHAN_TRIES);
            }
            Kind::Deregistration => self.finish_stop(out),
        }
    }

    fn on_registration(&mut self, now: u64, item: &Item, out: &mut Vec<Action>) {
        match (item.code, &item.cbsd_id) {
            (proto::SUCCESS, Some(cbsd)) => {
                out.push(Action::Log("registration succeeded".into()));
                self.cbsd = Some(cbsd.clone());
                self.register_failures = 0;
                self.dirty = true;
            }
            _ => {
                self.register_failures += 1;
                let wait = retry(&REGISTER_RETRY, self.register_failures);
                self.register_at = now + wait;
                out.push(Action::Log(format!(
                    "registration answered {} ({}), next try in {wait} s",
                    item.code, item.message
                )));
            }
        }
    }

    fn on_inquiry(&mut self, now: u64, item: &Item, out: &mut Vec<Action>) {
        if item.code != proto::SUCCESS {
            self.inquiry_at = now + 60;
            out.push(Action::Log(format!(
                "spectrum inquiry answered {}",
                item.code
            )));
            return;
        }
        self.inquiry_due = false;
        self.hints = item.available.clone();
        let offered: Vec<Range> = item.available.iter().map(|(range, _)| *range).collect();
        for piece in self.missing(&self.in_use()) {
            if !band::covered(piece, &offered) {
                out.push(Action::Log(format!(
                    "the SAS offers no spectrum on {piece}"
                )));
                self.denied.push((piece, now + 600));
                self.inquiry_due = true;
                self.inquiry_at = now + 600;
            }
        }
        self.grant_at = now;
    }

    fn on_grant(&mut self, now: u64, item: &Item, subject: &Subject, out: &mut Vec<Action>) {
        let Subject::Range(range, eirp) = subject else {
            return;
        };
        let (range, eirp) = (*range, *eirp);
        self.grant_timeout = ANSWER_TIMEOUT;
        match (item.code, &item.grant_id) {
            (proto::SUCCESS, Some(id)) => {
                out.push(Action::Log(format!("grant for {range} at {eirp} dBm/MHz")));
                self.grant_failures = 0;
                self.grants.push(Grant {
                    id: id.clone(),
                    range,
                    max_eirp: eirp,
                    state: GrantState::Granted,
                    interval: item.heartbeat_interval.unwrap_or(60),
                    grant_expire: item.grant_expire.unwrap_or(0),
                    transmit_expire: 0,
                    deadline: None,
                    next_heartbeat: now,
                    failures: 0,
                    suspensions: 0,
                    reason: String::new(),
                    last_used: now,
                    relinquish: false,
                });
                self.dirty = true;
            }
            (proto::GRANT_CONFLICT, _) => {
                // The SAS holds a grant this client does not know, usually
                // from a call whose answer was lost. Give back exactly that
                // grant and ask again. Never deregister for this.
                let mut unknown = 0;
                for id in &item.data {
                    let held = self.grants.iter().any(|grant| grant.id == *id);
                    let queued = self.orphans.iter().any(|orphan| orphan.id == *id);
                    if !held && !queued {
                        self.orphans.push(Orphan {
                            id: id.clone(),
                            tries: 0,
                            retry_at: now,
                        });
                        unknown += 1;
                    }
                }
                out.push(Action::Log(format!(
                    "grant for {range} conflicts with {unknown} grant(s) the SAS still holds"
                )));
                if unknown == 0 {
                    self.grant_failures += 1;
                    self.grant_at = now + retry(&GRANT_RETRY, self.grant_failures).max(60);
                } else {
                    self.relinquish_at = now;
                    self.grant_at = now;
                }
            }
            (proto::INTERFERENCE, _) => {
                out.push(Action::Log(format!(
                    "the SAS refused {range}: interference (400)"
                )));
                if let Some(hint) = item.suggestion {
                    self.hints.push(hint);
                }
                self.denied.push((range, now + 1800));
                self.inquiry_due = true;
                self.inquiry_at = now;
            }
            (proto::UNSUPPORTED_SPECTRUM, _) => {
                out.push(Action::Log(format!(
                    "the SAS refused {range}: outside the band (300)"
                )));
                self.denied.push((range, now + 86_400));
            }
            (code, _) => {
                self.grant_failures += 1;
                let wait = retry(&GRANT_RETRY, self.grant_failures).max(30);
                self.denied.push((range, now + wait));
                out.push(Action::Log(format!(
                    "grant for {range} answered {code} ({}), next try in {wait} s",
                    item.message
                )));
            }
        }
    }

    fn on_heartbeat(
        &mut self,
        now: u64,
        clock: u64,
        base: u64,
        item: &Item,
        subject: &Subject,
        out: &mut Vec<Action>,
    ) {
        let Subject::Grant(id) = subject else {
            return;
        };
        let Some(index) = self.grants.iter().position(|grant| grant.id == *id) else {
            return;
        };
        let percent = self.policy.heartbeat_percent.clamp(10, 100);
        let life = item.transmit_expire.map(|end| end.saturating_sub(clock));
        let range = self.grants[index].range;
        match item.code {
            proto::SUCCESS if life.is_some() => {
                let life = life.unwrap_or(0);
                let grant = &mut self.grants[index];
                if grant.state != GrantState::Authorized {
                    out.push(Action::Log(format!("{range} authorized for {life} s")));
                }
                grant.state = GrantState::Authorized;
                grant.deadline = Some(base + life);
                grant.transmit_expire = item.transmit_expire.unwrap_or(0);
                if let Some(interval) = item.heartbeat_interval {
                    grant.interval = interval.max(1);
                }
                if let Some(expire) = item.grant_expire {
                    grant.grant_expire = expire;
                }
                grant.failures = 0;
                grant.suspensions = 0;
                grant.reason.clear();
                let mut wait = (grant.interval * percent / 100).max(1);
                if life > 180 {
                    // Always try again before the right to transmit runs out.
                    wait = wait.min(life - 90);
                }
                grant.next_heartbeat = now + wait;
            }
            proto::SUSPENDED_GRANT => {
                let grant = &mut self.grants[index];
                grant.state = GrantState::Suspended;
                grant.deadline = Some(base + life.unwrap_or(0));
                grant.transmit_expire = item.transmit_expire.unwrap_or(0);
                if let Some(interval) = item.heartbeat_interval {
                    grant.interval = interval.max(1);
                }
                grant.suspensions += 1;
                grant.failures = 0;
                grant.reason = item.message.clone();
                let wait = suspension_delay(&grant.reason, grant.suspensions, grant.interval);
                grant.next_heartbeat = now + wait;
                out.push(Action::Log(format!(
                    "{range} suspended ({}): grant kept, next heartbeat in {wait} s",
                    item.message
                )));
            }
            proto::TERMINATED_GRANT => {
                let end = base + life.unwrap_or(0);
                self.ended.push((range, end.min(now)));
                self.grants.remove(index);
                self.dirty = true;
                match item.suggestion {
                    Some((suggested, eirp)) if suggested.overlaps(range) => {
                        out.push(Action::Log(format!(
                            "{range} terminated: the SAS suggests {eirp} dBm/MHz"
                        )));
                        self.hints.retain(|(hinted, _)| !hinted.overlaps(range));
                        self.hints.push((suggested, eirp));
                        self.grant_at = now;
                    }
                    _ => {
                        out.push(Action::Log(format!(
                            "{range} terminated ({})",
                            item.message
                        )));
                        self.denied.push((range, now + 30));
                        self.inquiry_due = true;
                        self.inquiry_at = now + 30;
                    }
                }
            }
            proto::UNSYNC_OP_PARAM => {
                out.push(Action::Log(format!(
                    "{range} out of step with the SAS (502): giving it back"
                )));
                let grant = &mut self.grants[index];
                grant.state = GrantState::Granted;
                grant.relinquish = true;
                self.ended.push((range, now));
                self.relinquish_at = now;
                self.dirty = true;
            }
            proto::INVALID_VALUE => {
                out.push(Action::Log(format!(
                    "the SAS does not know the grant for {range} (103)"
                )));
                self.ended.push((range, now));
                self.grants.remove(index);
                self.dirty = true;
            }
            code => {
                let grant = &mut self.grants[index];
                grant.failures += 1;
                let wait = retry(&HEARTBEAT_RETRY, grant.failures);
                grant.next_heartbeat = now + wait;
                out.push(Action::Log(format!(
                    "heartbeat for {range} answered {code} ({}), next try in {wait} s",
                    item.message
                )));
            }
        }
    }

    fn on_relinquishment(
        &mut self,
        now: u64,
        item: &Item,
        subject: &Subject,
        out: &mut Vec<Action>,
    ) {
        let Subject::Grant(id) = subject else {
            return;
        };
        // Any answer but a retry request means the SAS no longer holds it.
        if item.code == proto::SUCCESS || item.code == proto::INVALID_VALUE {
            if let Some(index) = self.grants.iter().position(|grant| grant.id == *id) {
                out.push(Action::Log(format!(
                    "gave back the grant for {}",
                    self.grants[index].range
                )));
                self.grants.remove(index);
                self.dirty = true;
            }
            self.orphans.retain(|orphan| orphan.id != *id);
            return;
        }
        out.push(Action::Log(format!(
            "relinquishment answered {}",
            item.code
        )));
        self.relinquish_at = now + 30;
        for orphan in &mut self.orphans {
            if orphan.id == *id {
                orphan.tries += 1;
                orphan.retry_at = now + 30;
            }
        }
        self.orphans.retain(|orphan| orphan.tries < ORPHAN_TRIES);
    }
}
