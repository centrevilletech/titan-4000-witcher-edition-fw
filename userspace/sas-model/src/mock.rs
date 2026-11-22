//! A pretend SAS and a simulated unit, for tests and for shadow mode.
//!
//! `MockSas` keeps the SAS's side of the truth: which grants exist and until
//! when each may transmit. It can be told to misbehave the ways the real one
//! has: go silent, answer late, act on a request and lose the answer, suspend
//! or terminate a grant, or forget the unit.
//!
//! `Sim` runs an `Engine` against it on a virtual clock, one second at a
//! time, and checks after every second that the gate is never open while the
//! SAS says a carrier in use is not authorized.
use serde_json::{Value, json};

use crate::band::{self, Range};
use crate::engine::{Action, Answer, Engine, Failure, Gate, Input, Policy, RadioCommand, Request};
use crate::proto::{self, Kind};

pub const CBSD: &str = "MOCK-FCC/0001";

#[derive(Clone, Debug, PartialEq)]
pub enum Fault {
    /// The connection fails. The SAS never sees the request.
    Unreachable,
    /// The SAS acts on the request, and the answer never arrives.
    Swallow,
    /// The SAS acts on the request and answers this many seconds later.
    Slow(u64),
    /// The SAS answers every object with this code and does nothing else.
    Code(i64, String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    Answer { body: String, delay: u64 },
    NoAnswer,
    Refused,
}

#[derive(Clone, Debug, PartialEq)]
struct Held {
    id: String,
    range: Range,
    authorized: bool,
    /// True wall time until which this grant may transmit.
    transmit_until: u64,
    suspended: u32,
    reason: String,
    terminated: Option<Option<f64>>,
    out_of_step: bool,
}

pub struct MockSas {
    pub registered: bool,
    pub heartbeat_interval: u64,
    pub transmit_life: u64,
    /// Seconds a normal answer takes.
    pub latency: u64,
    /// Ranges the SAS will not offer or grant.
    pub unavailable: Vec<Range>,
    grants: Vec<Held>,
    faults: Vec<(Kind, Fault)>,
    next: u64,
    /// Every request that reached the SAS: true wall time and kind.
    pub seen: Vec<(u64, Kind)>,
}

impl Default for MockSas {
    fn default() -> Self {
        Self {
            registered: false,
            heartbeat_interval: 1800,
            transmit_life: 21_600,
            latency: 1,
            unavailable: Vec::new(),
            grants: Vec::new(),
            faults: Vec::new(),
            next: 1,
            seen: Vec::new(),
        }
    }
}

fn response(code: i64, message: &str, data: &[String]) -> Value {
    let mut response = json!({ "responseCode": code });
    if !message.is_empty() {
        response["responseMessage"] = Value::String(message.to_string());
    }
    if !data.is_empty() {
        response["responseData"] = json!(data);
    }
    response
}

fn requested_range(item: &Value) -> Option<Range> {
    let range = item.get("operationParam")?.get("operationFrequencyRange")?;
    Range::new(
        range.get("lowFrequency")?.as_u64()?,
        range.get("highFrequency")?.as_u64()?,
    )
}

impl MockSas {
    /// The next request of this kind meets this fault. Faults queue in order.
    pub fn fault(&mut self, kind: Kind, fault: Fault) {
        self.faults.push((kind, fault));
    }

    pub fn faults(&mut self, kind: Kind, fault: Fault, count: usize) {
        for _ in 0..count {
            self.fault(kind, fault.clone());
        }
    }

    pub fn clear_faults(&mut self) {
        self.faults.clear();
    }

    /// The next `count` heartbeats for grants on `range` answer 501.
    pub fn suspend(&mut self, range: Range, count: u32, reason: &str) {
        for grant in &mut self.grants {
            if grant.range.overlaps(range) {
                grant.suspended = count;
                grant.reason = reason.to_string();
            }
        }
    }

    /// The next heartbeat for grants on `range` answers 500, with a
    /// suggested power when `suggest` is set.
    pub fn terminate(&mut self, range: Range, suggest: Option<f64>) {
        for grant in &mut self.grants {
            if grant.range.overlaps(range) {
                grant.terminated = Some(suggest);
            }
        }
    }

    /// The next heartbeat for grants on `range` answers 502.
    pub fn unsync(&mut self, range: Range) {
        for grant in &mut self.grants {
            if grant.range.overlaps(range) {
                grant.out_of_step = true;
            }
        }
    }

    /// The SAS loses the registration and every grant.
    pub fn forget(&mut self) {
        self.registered = false;
        self.grants.clear();
    }

    /// A grant the client does not know about, as a lost answer leaves.
    pub fn plant(&mut self, range: Range) -> String {
        self.registered = true;
        self.create(range)
    }

    fn create(&mut self, range: Range) -> String {
        let id = format!("{CBSD}/{}", self.next);
        self.next += 1;
        self.grants.push(Held {
            id: id.clone(),
            range,
            authorized: false,
            transmit_until: 0,
            suspended: 0,
            reason: String::new(),
            terminated: None,
            out_of_step: false,
        });
        id
    }

    pub fn grant_count(&self) -> usize {
        self.grants.len()
    }

    pub fn holds(&self, range: Range) -> bool {
        let held: Vec<Range> = self.grants.iter().map(|grant| grant.range).collect();
        band::covered(range, &held)
    }

    /// The SAS's own view: may the unit transmit on all of `range` now?
    pub fn authorized(&self, range: Range, wall: u64) -> bool {
        let held: Vec<Range> = self
            .grants
            .iter()
            .filter(|grant| grant.authorized && grant.transmit_until > wall)
            .map(|grant| grant.range)
            .collect();
        band::covered(range, &held)
    }

    pub fn count(&self, kind: Kind) -> usize {
        self.seen.iter().filter(|(_, seen)| *seen == kind).count()
    }

    fn take_fault(&mut self, kind: Kind) -> Option<Fault> {
        let index = self.faults.iter().position(|(wanted, _)| *wanted == kind)?;
        Some(self.faults.remove(index).1)
    }

    pub fn handle(&mut self, wall: u64, kind: Kind, body: &str) -> Outcome {
        let fault = self.take_fault(kind);
        if fault == Some(Fault::Unreachable) {
            return Outcome::Refused;
        }
        self.seen.push((wall, kind));
        let request: Value = match serde_json::from_str(body) {
            Ok(value) => value,
            Err(_) => return Outcome::NoAnswer,
        };
        let Some(items) = request.get(kind.request_key()).and_then(Value::as_array) else {
            return Outcome::NoAnswer;
        };
        if let Some(Fault::Code(code, message)) = &fault {
            let answers: Vec<Value> = items
                .iter()
                .map(|_| json!({ "response": response(*code, message, &[]) }))
                .collect();
            return self.answer(kind, answers, self.latency);
        }
        let answers: Vec<Value> = items
            .iter()
            .map(|item| self.process(wall, kind, item))
            .collect();
        match fault {
            Some(Fault::Swallow) => Outcome::NoAnswer,
            Some(Fault::Slow(delay)) => self.answer(kind, answers, delay),
            _ => self.answer(kind, answers, self.latency),
        }
    }

    fn answer(&self, kind: Kind, answers: Vec<Value>, delay: u64) -> Outcome {
        let mut body = serde_json::Map::new();
        body.insert(kind.response_key(), Value::Array(answers));
        Outcome::Answer {
            body: Value::Object(body).to_string(),
            delay,
        }
    }

    fn process(&mut self, wall: u64, kind: Kind, item: &Value) -> Value {
        if kind == Kind::Registration {
            self.registered = true;
            return json!({ "cbsdId": CBSD, "response": response(0, "", &[]) });
        }
        let known = item.get("cbsdId").and_then(Value::as_str) == Some(CBSD) && self.registered;
        if !known {
            return json!({ "response": response(103, "unknown CBSD", &["cbsdId".to_string()]) });
        }
        let grant_id = item.get("grantId").and_then(Value::as_str).unwrap_or("");
        let index = self.grants.iter().position(|grant| grant.id == grant_id);
        match kind {
            Kind::Registration => Value::Null,
            Kind::SpectrumInquiry => {
                let mut channels = Vec::new();
                let mut low = band::BAND_LOW;
                while low < band::BAND_HIGH {
                    let channel = Range {
                        low,
                        high: low + 10_000_000,
                    };
                    if !self.unavailable.iter().any(|range| range.overlaps(channel)) {
                        channels.push(json!({
                            "frequencyRange": { "lowFrequency": channel.low, "highFrequency": channel.high },
                            "channelType": "GAA",
                            "ruleApplied": "FCC_PART_96",
                            "maxEirp": 27,
                        }));
                    }
                    low += 10_000_000;
                }
                json!({ "cbsdId": CBSD, "availableChannel": channels, "response": response(0, "", &[]) })
            }
            Kind::Grant => {
                let Some(range) = requested_range(item) else {
                    return json!({ "cbsdId": CBSD, "response": response(102, "no range", &[]) });
                };
                if self
                    .unavailable
                    .iter()
                    .any(|blocked| blocked.overlaps(range))
                {
                    return json!({ "cbsdId": CBSD, "response": response(400, "interference", &[]) });
                }
                let conflicts: Vec<String> = self
                    .grants
                    .iter()
                    .filter(|grant| grant.range.overlaps(range))
                    .map(|grant| grant.id.clone())
                    .collect();
                if !conflicts.is_empty() {
                    let message = "Existing grant overlaps with the requested frequency range";
                    return json!({ "cbsdId": CBSD, "response": response(401, message, &conflicts) });
                }
                let id = self.create(range);
                json!({
                    "cbsdId": CBSD,
                    "grantId": id,
                    "grantExpireTime": proto::format_utc(wall + 365 * 86_400),
                    "heartbeatInterval": self.heartbeat_interval,
                    "channelType": "GAA",
                    "response": response(0, "", &[]),
                })
            }
            Kind::Heartbeat => {
                let Some(index) = index else {
                    return json!({
                        "cbsdId": CBSD,
                        "grantId": grant_id,
                        "response": response(103, "unknown grant", &["grantId".to_string()]),
                    });
                };
                let claims_authorized =
                    item.get("operationState").and_then(Value::as_str) == Some("AUTHORIZED");
                let now_text = proto::format_utc(wall);
                if let Some(suggest) = self.grants[index].terminated {
                    let grant = self.grants.remove(index);
                    let mut answer = json!({
                        "cbsdId": CBSD,
                        "grantId": grant.id,
                        "transmitExpireTime": now_text,
                        "response": response(500, "terminated", &[]),
                    });
                    if let Some(eirp) = suggest {
                        answer["operationParam"] = json!({
                            "maxEirp": eirp,
                            "operationFrequencyRange": {
                                "lowFrequency": grant.range.low,
                                "highFrequency": grant.range.high,
                            },
                        });
                    }
                    return answer;
                }
                let grant = &mut self.grants[index];
                let stale = claims_authorized && !(grant.authorized && grant.transmit_until > wall);
                if grant.out_of_step || stale {
                    grant.out_of_step = false;
                    grant.authorized = false;
                    grant.transmit_until = wall;
                    return json!({
                        "cbsdId": CBSD,
                        "grantId": grant.id,
                        "transmitExpireTime": now_text,
                        "response": response(502, "out of sync", &[]),
                    });
                }
                if grant.suspended > 0 {
                    grant.suspended -= 1;
                    grant.authorized = false;
                    grant.transmit_until = wall;
                    return json!({
                        "cbsdId": CBSD,
                        "grantId": grant.id,
                        "transmitExpireTime": now_text,
                        "heartbeatInterval": self.heartbeat_interval,
                        "response": response(501, &grant.reason, &[]),
                    });
                }
                grant.authorized = true;
                grant.transmit_until = wall + self.transmit_life;
                json!({
                    "cbsdId": CBSD,
                    "grantId": grant.id,
                    "transmitExpireTime": proto::format_utc(grant.transmit_until),
                    "heartbeatInterval": self.heartbeat_interval,
                    "response": response(0, "", &[]),
                })
            }
            Kind::Relinquishment => match index {
                Some(index) => {
                    self.grants.remove(index);
                    json!({ "cbsdId": CBSD, "grantId": grant_id, "response": response(0, "", &[]) })
                }
                None => json!({
                    "cbsdId": CBSD,
                    "grantId": grant_id,
                    "response": response(103, "unknown grant", &["grantId".to_string()]),
                }),
            },
            Kind::Deregistration => {
                self.forget();
                json!({ "cbsdId": CBSD, "response": response(0, "", &[]) })
            }
        }
    }
}

/// An engine, a mock SAS and a virtual clock.
pub struct Sim {
    pub engine: Engine,
    pub sas: MockSas,
    /// Monotonic seconds.
    pub now: u64,
    /// True wall time, the SAS's clock.
    pub wall: u64,
    /// How far the unit's own clock is from the truth, in seconds.
    pub clock_error: i64,
    pending: Vec<(u64, u64, Result<Answer, Failure>)>,
    radio_events: Vec<(u64, bool)>,
    carriers: Option<(Range, Option<Range>)>,
    online: bool,
    pub gate: Gate,
    pub gate_changes: Vec<(u64, Gate)>,
    pub radio_commands: Vec<(u64, RadioCommand)>,
    pub sent: Vec<(u64, Kind)>,
    pub saved: Option<String>,
    pub log: Vec<String>,
    pub cannot_register: bool,
    pub stopped: bool,
    /// Seconds the gate was closed while the radio was up.
    pub closed_seconds: u64,
    /// Seconds the gate was open while the SAS said no. Must stay empty.
    pub violations: Vec<String>,
    /// Whether the simulated modem obeys radio commands.
    pub radio_obeys: bool,
    /// Seconds an answer may take to reach the unit before an open gate
    /// counts as a violation.
    pub grace: u64,
    unauthorized_run: u64,
}

pub const START_WALL: u64 = 1_795_330_844;

impl Sim {
    pub fn new(engine: Engine) -> Self {
        Self {
            engine,
            sas: MockSas::default(),
            now: 1000,
            wall: START_WALL,
            clock_error: 0,
            pending: Vec::new(),
            radio_events: Vec::new(),
            carriers: None,
            online: false,
            gate: Gate::Closed,
            gate_changes: Vec::new(),
            radio_commands: Vec::new(),
            sent: Vec::new(),
            saved: None,
            log: Vec::new(),
            cannot_register: false,
            stopped: false,
            closed_seconds: 0,
            violations: Vec::new(),
            radio_obeys: true,
            grace: 3,
            unauthorized_run: 0,
        }
    }

    /// A unit that the SAS already knows, as at a takeover.
    pub fn registered(policy: Policy) -> Self {
        let mut sim = Self::new(Engine::new(policy, None, Some(CBSD.to_string())));
        sim.sas.registered = true;
        sim
    }

    fn unit_wall(&self) -> u64 {
        self.wall.saturating_add_signed(self.clock_error)
    }

    pub fn online(&mut self, primary: Range, uplink: Option<Range>) {
        self.carriers = Some((primary, uplink));
        self.online = true;
        self.feed(Input::Online { primary, uplink });
    }

    pub fn offline(&mut self) {
        self.online = false;
        self.feed(Input::Offline);
    }

    pub fn stop(&mut self) {
        self.feed(Input::Stop);
    }

    pub fn open(&self) -> bool {
        self.gate != Gate::Closed
    }

    pub fn count(&self, kind: Kind) -> usize {
        self.sent.iter().filter(|(_, sent)| *sent == kind).count()
    }

    pub fn commands(&self, command: RadioCommand) -> usize {
        self.radio_commands
            .iter()
            .filter(|(_, sent)| *sent == command)
            .count()
    }

    pub fn run(&mut self, seconds: u64) {
        for _ in 0..seconds {
            self.now += 1;
            self.wall += 1;
            let now = self.now;
            let mut due = Vec::new();
            self.pending.retain(|entry| {
                if entry.0 <= now {
                    due.push((entry.1, entry.2.clone()));
                    false
                } else {
                    true
                }
            });
            for (id, result) in due {
                self.feed(Input::Reply { id, result });
            }
            let mut radio = Vec::new();
            self.radio_events.retain(|entry| {
                if entry.0 <= now {
                    radio.push(entry.1);
                    false
                } else {
                    true
                }
            });
            for up in radio {
                match (up, self.carriers) {
                    (true, Some((primary, uplink))) => self.online(primary, uplink),
                    _ => self.offline(),
                }
            }
            self.feed(Input::Tick);
            self.check();
        }
    }

    /// Run until the gate opens, at most `limit` seconds. Returns the
    /// seconds it took, or `None`.
    pub fn run_until_open(&mut self, limit: u64) -> Option<u64> {
        for second in 0..=limit {
            if self.open() {
                return Some(second);
            }
            self.run(1);
        }
        None
    }

    fn check(&mut self) {
        let Some((primary, uplink)) = self.carriers else {
            return;
        };
        if !self.online {
            return;
        }
        if self.gate == Gate::Closed {
            self.closed_seconds += 1;
            self.unauthorized_run = 0;
            return;
        }
        // The SAS changes its mind when it handles a heartbeat. The unit
        // learns of it when the answer lands, `grace` seconds later at most.
        let refused = [Some(primary), uplink]
            .into_iter()
            .flatten()
            .find(|carrier| !self.sas.authorized(*carrier, self.wall));
        match refused {
            Some(carrier) => {
                self.unauthorized_run += 1;
                if self.unauthorized_run > self.grace {
                    self.violations.push(format!(
                        "second {}: gate open with no SAS authorization on {carrier}",
                        self.now
                    ));
                }
            }
            None => self.unauthorized_run = 0,
        }
    }

    fn feed(&mut self, input: Input) {
        let (now, wall) = (self.now, self.unit_wall());
        let actions = self.engine.step(now, wall, input);
        for action in actions {
            match action {
                Action::Send(request) => self.send(request),
                Action::Gate(gate) => {
                    self.gate = gate;
                    self.gate_changes.push((self.now, gate));
                }
                Action::Radio(command) => {
                    self.radio_commands.push((self.now, command));
                    if self.radio_obeys {
                        match command {
                            RadioCommand::LeavePrimary => {
                                self.radio_events.push((self.now + 2, false))
                            }
                            RadioCommand::DropUplink => {
                                if let Some((primary, _)) = self.carriers {
                                    self.carriers = Some((primary, None));
                                }
                                self.radio_events.push((self.now + 2, false));
                                self.radio_events.push((self.now + 8, true));
                            }
                            RadioCommand::Rejoin => self.radio_events.push((self.now + 10, true)),
                        }
                    }
                }
                Action::Persist(state) => self.saved = Some(state),
                Action::Log(line) => self.log.push(format!("{} {line}", self.now)),
                Action::CannotRegister => self.cannot_register = true,
                Action::Stopped => self.stopped = true,
            }
        }
    }

    fn send(&mut self, request: Request) {
        self.sent.push((self.now, request.kind));
        let wall = self.wall;
        let result = match self.sas.handle(wall, request.kind, &request.body) {
            Outcome::Refused => (self.now + request.connect_timeout, Err(Failure::Connect)),
            Outcome::NoAnswer => (self.now + request.answer_timeout, Err(Failure::Timeout)),
            Outcome::Answer { delay, .. } if delay > request.answer_timeout => {
                (self.now + request.answer_timeout, Err(Failure::Timeout))
            }
            Outcome::Answer { body, delay } => {
                let answer = proto::parse(request.kind, &body)
                    .map(|items| Answer {
                        items,
                        server_time: Some(self.wall + delay),
                    })
                    .map_err(Failure::Malformed);
                (self.now + delay, answer)
            }
        };
        self.pending.push((result.0, request.id, result.1));
    }
}
