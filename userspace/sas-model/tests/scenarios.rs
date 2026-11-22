//! The SAS behaviors that have taken customers offline, replayed against the
//! grant manager. Every scenario also checks, second by second, that the
//! gate was never open while the mock SAS said a carrier was not authorized.
use serde_json::{Value, json};
use witcher_sas_model::band::Range;
use witcher_sas_model::engine::{Action, Engine, Gate, Input, Policy, RadioCommand};
use witcher_sas_model::mock::{CBSD, Fault, Sim};
use witcher_sas_model::proto::Kind;
use witcher_sas_model::registration::{self, Options, Stored};

fn mhz(low: u64, high: u64) -> Range {
    Range::mhz(low, high).unwrap()
}

fn c5() -> Range {
    mhz(3560, 3580)
}
fn c12() -> Range {
    mhz(3620, 3640)
}
fn c6() -> Range {
    mhz(3660, 3680)
}
fn c9() -> Range {
    mhz(3680, 3700)
}

/// A registered unit with open traffic on c5 and c9.
fn up_with(policy: Policy) -> Sim {
    let mut sim = Sim::registered(policy);
    sim.online(c5(), Some(c9()));
    let took = sim.run_until_open(30).expect("the gate opens");
    assert!(took <= 10, "first authorization took {took} s");
    sim
}

fn up() -> Sim {
    up_with(Policy::default())
}

fn clean(sim: &Sim) {
    assert!(sim.violations.is_empty(), "{:?}", sim.violations.first());
}

#[test]
fn a_day_of_normal_service_is_one_grant_call_and_batched_heartbeats() {
    let mut sim = up();
    sim.run(86_400);
    clean(&sim);
    assert!(sim.open());
    assert_eq!(sim.gate_changes.len(), 1, "the gate never closed");
    assert_eq!(sim.count(Kind::Grant), 1, "both carriers in one call");
    assert_eq!(sim.count(Kind::Registration), 0);
    assert_eq!(sim.count(Kind::SpectrumInquiry), 0);
    assert_eq!(sim.count(Kind::Relinquishment), 0);
    // One call per 24 minutes carries both grants: about 60 a day.
    let heartbeats = sim.count(Kind::Heartbeat);
    assert!(
        (55..=66).contains(&heartbeats),
        "{heartbeats} heartbeat calls"
    );
    assert_eq!(sim.sas.grant_count(), 2);
    assert_eq!(sim.sas.renewals, 0, "a year-long grant is not renewed daily");
}

#[test]
fn a_carrier_change_adds_one_grant_and_drops_none() {
    let mut sim = up();
    sim.online(c5(), Some(c6()));
    assert!(!sim.open(), "no traffic on a carrier with no grant");
    let took = sim.run_until_open(30).expect("the gate reopens");
    assert!(took <= 10, "took {took} s");
    assert_eq!(sim.count(Kind::Grant), 2);
    assert_eq!(sim.count(Kind::Relinquishment), 0);
    assert!(sim.sas.holds(c9()), "the idle grant is kept");
    // Back to the old carrier: its grant is still authorized, so nothing
    // closes and nothing is asked.
    sim.run(600);
    sim.online(c5(), Some(c9()));
    assert!(sim.open());
    sim.run(60);
    assert_eq!(sim.count(Kind::Grant), 2);
    assert_eq!(sim.gate_changes.len(), 3);
    clean(&sim);
}

#[test]
fn twenty_carrier_flaps_cost_seconds_not_minutes() {
    let mut sim = up();
    for round in 0..20 {
        let uplink = if round % 2 == 0 { c6() } else { c9() };
        sim.online(c5(), Some(uplink));
        sim.run(120);
    }
    clean(&sim);
    assert!(sim.open());
    assert_eq!(sim.count(Kind::Grant), 2);
    assert_eq!(sim.count(Kind::Relinquishment), 0);
    assert_eq!(sim.count(Kind::Registration), 0);
    assert!(sim.closed_seconds <= 15, "{} s closed", sim.closed_seconds);
}

#[test]
fn a_reattach_on_the_same_carriers_reopens_at_once_and_idle_time_sends_nothing() {
    let mut sim = up();
    sim.offline();
    assert!(!sim.open());
    let sent = sim.sent.len();
    sim.run(4000);
    assert_eq!(sim.sent.len(), sent, "no path to the SAS while detached");
    sim.online(c5(), Some(c9()));
    assert!(
        sim.open(),
        "grants are still authorized, no SAS call is needed"
    );
    sim.run(30);
    assert_eq!(sim.count(Kind::Grant), 1);
    clean(&sim);
}

#[test]
fn a_slow_grant_answer_is_waited_for() {
    let mut sim = up();
    sim.sas.fault(Kind::Grant, Fault::Slow(20));
    sim.online(c5(), Some(c6()));
    let took = sim.run_until_open(60).expect("the gate reopens");
    assert!((20..=30).contains(&took), "took {took} s");
    assert_eq!(sim.count(Kind::Grant), 2, "no retry, no conflict");
    assert_eq!(sim.count(Kind::Relinquishment), 0);
    assert_eq!(sim.count(Kind::Registration), 0);
    clean(&sim);
}

#[test]
fn a_sas_that_acts_but_never_answers_does_not_cause_a_deregistration() {
    let mut sim = up();
    sim.sas.faults(Kind::Grant, Fault::Swallow, 3);
    sim.online(c5(), Some(c6()));
    sim.run(200);
    assert!(
        !sim.open(),
        "still waiting, and still not transmitting customer traffic"
    );
    assert!(
        sim.sas.authorized(c5(), sim.wall),
        "the other grant is untouched"
    );
    let took = sim
        .run_until_open(300)
        .expect("the gate reopens once the SAS answers");
    assert!(took <= 120, "took {took} more seconds");
    // The lost answer left a grant at the SAS. Exactly that one went back.
    assert_eq!(sim.count(Kind::Relinquishment), 1);
    assert_eq!(sim.count(Kind::Registration), 0);
    assert_eq!(sim.count(Kind::Deregistration), 0);
    assert_eq!(sim.sas.grant_count(), 3);
    assert!(sim.radio_commands.is_empty());
    clean(&sim);
}

#[test]
fn an_unreachable_sas_changes_nothing_until_it_answers() {
    let mut sim = up();
    sim.sas.faults(Kind::Grant, Fault::Unreachable, 4);
    sim.online(c5(), Some(c6()));
    let took = sim.run_until_open(300).expect("the gate reopens");
    assert!(took <= 150, "took {took} s");
    assert_eq!(sim.count(Kind::Relinquishment), 0);
    assert_eq!(sim.count(Kind::Registration), 0);
    clean(&sim);
}

#[test]
fn grants_left_by_another_client_are_given_back_one_by_one() {
    let mut sim = Sim::registered(Policy::default());
    let left = sim.sas.plant(mhz(3660, 3700));
    assert!(left.starts_with(CBSD));
    sim.sas.plant(c5());
    sim.online(c5(), Some(c9()));
    let took = sim.run_until_open(30).expect("the gate opens");
    assert!(took <= 10, "took {took} s");
    assert_eq!(sim.count(Kind::Relinquishment), 1, "one call names both");
    assert_eq!(sim.count(Kind::Grant), 2);
    assert_eq!(sim.count(Kind::Registration), 0);
    assert_eq!(sim.count(Kind::Deregistration), 0);
    assert_eq!(sim.sas.grant_count(), 2);
    assert!(!sim.sas.holds(c6()), "the old wide grant is gone");
    clean(&sim);
}

#[test]
fn a_short_suspension_closes_the_gate_and_keeps_the_grant() {
    let mut sim = up();
    sim.sas
        .suspend(c5(), 2, "Interference Calculations Pending");
    sim.run(1600);
    clean(&sim);
    assert!(sim.open(), "authorized again once the SAS finished");
    assert_eq!(sim.gate_changes.len(), 3, "closed once, reopened once");
    assert!(
        (5..=35).contains(&sim.closed_seconds),
        "{} s closed",
        sim.closed_seconds
    );
    assert_eq!(sim.count(Kind::Relinquishment), 0);
    assert_eq!(sim.count(Kind::Grant), 1, "no new grant was asked for");
    assert_eq!(sim.count(Kind::Registration), 0);
    assert!(sim.radio_commands.is_empty(), "no detach, no cell block");
}

#[test]
fn a_long_suspension_takes_the_radio_off_the_carrier_within_a_minute() {
    let mut sim = up();
    sim.sas.suspend(c5(), 10_000, "IAP Pending");
    sim.run(1500);
    assert!(!sim.open());
    let closed_at = sim.gate_changes.last().expect("a gate change").0;
    let (left_at, command) = sim.radio_commands[0];
    assert_eq!(command, RadioCommand::LeavePrimary);
    assert!(
        left_at >= closed_at && left_at <= closed_at + 60,
        "left after {} s",
        left_at - closed_at
    );
    sim.run(7200);
    assert!(
        sim.commands(RadioCommand::LeavePrimary) >= 2,
        "each failed probe leaves again"
    );
    assert!(sim.commands(RadioCommand::Rejoin) >= 1);
    assert_eq!(
        sim.count(Kind::Relinquishment),
        0,
        "the suspended grant is kept"
    );
    assert_eq!(sim.count(Kind::Grant), 1);
    assert_eq!(sim.count(Kind::Registration), 0);
    assert!(sim.sas.holds(c5()));
    assert!(!sim.open());
    // The suspension ends. The next probe finds it and service returns.
    sim.sas.suspend(c5(), 0, "");
    assert!(sim.run_until_open(4000).is_some());
    assert_eq!(sim.count(Kind::Grant), 1);
    clean(&sim);
}

#[test]
fn a_suspended_uplink_carrier_does_not_take_the_main_carrier_down() {
    let mut sim = up();
    sim.sas.suspend(c9(), 10_000, "IAP Pending");
    sim.run(1700);
    assert_eq!(sim.commands(RadioCommand::DropUplink), 1);
    assert_eq!(sim.commands(RadioCommand::LeavePrimary), 0);
    assert!(sim.open(), "service continues on the main carrier alone");
    assert!(sim.sas.holds(c9()), "the suspended grant is kept for later");
    assert_eq!(sim.count(Kind::Relinquishment), 0);
    clean(&sim);
}

#[test]
fn a_terminated_grant_with_a_suggestion_is_asked_for_again_at_that_power() {
    let mut sim = up();
    sim.sas.terminate(c5(), Some(20.0));
    sim.run(1600);
    clean(&sim);
    assert_eq!(sim.gate, Gate::Open { max_eirp: 20.0 });
    assert_eq!(sim.count(Kind::Grant), 2);
    assert_eq!(sim.count(Kind::SpectrumInquiry), 0);
    assert!(sim.radio_commands.is_empty());
    assert!(sim.closed_seconds <= 10, "{} s closed", sim.closed_seconds);
}

#[test]
fn a_terminated_grant_with_no_suggestion_goes_through_an_inquiry() {
    let mut sim = up();
    sim.sas.terminate(c9(), None);
    sim.run(1600);
    clean(&sim);
    assert!(sim.open());
    assert_eq!(sim.count(Kind::SpectrumInquiry), 1);
    assert_eq!(sim.count(Kind::Grant), 2);
    assert_eq!(sim.count(Kind::Registration), 0);
    assert!(
        sim.sas.authorized(c5(), sim.wall),
        "the other carrier's grant was never touched"
    );
}

#[test]
fn an_out_of_step_grant_is_given_back_and_replaced() {
    let mut sim = up();
    sim.sas.unsync(c9());
    sim.run(1600);
    clean(&sim);
    assert!(sim.open());
    assert_eq!(sim.count(Kind::Relinquishment), 1);
    assert_eq!(sim.count(Kind::Grant), 2);
    assert_eq!(sim.count(Kind::Registration), 0);
    assert!(sim.radio_commands.is_empty());
}

#[test]
fn transmit_expiry_is_enforced_when_the_sas_goes_dark() {
    let mut sim = up();
    let authorized_at = sim.now;
    sim.sas.faults(Kind::Heartbeat, Fault::Unreachable, 100_000);
    sim.run(8 * 3600);
    clean(&sim);
    assert!(!sim.open());
    assert_eq!(sim.gate_changes.len(), 2);
    let closed_at = sim.gate_changes[1].0;
    let held = closed_at - authorized_at;
    assert!(
        (21_000..=21_600).contains(&held),
        "open for {held} s after the last heartbeat"
    );
    let (left_at, command) = sim.radio_commands[0];
    assert_eq!(command, RadioCommand::LeavePrimary);
    assert!(
        left_at > closed_at && left_at <= closed_at + 60,
        "left {} s after expiry",
        left_at - closed_at
    );
    assert_eq!(sim.count(Kind::Registration), 0);
    assert_eq!(sim.count(Kind::Deregistration), 0);
    assert_eq!(sim.count(Kind::Relinquishment), 0);
}

#[test]
fn a_clock_jump_changes_nothing() {
    let mut sim = up();
    sim.clock_error = 3600;
    sim.run(3000);
    sim.clock_error = -86_400;
    sim.run(3000);
    sim.clock_error = 400 * 86_400;
    sim.run(3000);
    clean(&sim);
    assert!(sim.open());
    assert_eq!(sim.gate_changes.len(), 1);
    assert_eq!(sim.count(Kind::Registration), 0);
    assert_eq!(sim.count(Kind::Deregistration), 0);
    assert_eq!(sim.count(Kind::Relinquishment), 0);
    assert_eq!(sim.count(Kind::Grant), 1);
}

#[test]
fn grants_survive_a_reboot_but_wait_for_a_heartbeat() {
    let mut before = up();
    before.run(100);
    let saved = before.saved.clone().expect("state was saved");
    assert!(!saved.contains("deadline"));
    let mut engine = Engine::new(Policy::default(), None, None);
    assert_eq!(engine.restore(&saved, 50), Ok(2));
    assert!(engine.registered());
    let mut after = Sim::new(engine);
    after.wall = before.wall + 90;
    after.sas = before.sas;
    after.online(c5(), Some(c9()));
    assert!(!after.open(), "a saved grant is not authorization");
    let took = after.run_until_open(30).expect("the gate opens");
    assert!(took <= 5, "took {took} s");
    assert_eq!(after.count(Kind::Grant), 0);
    assert_eq!(after.count(Kind::Registration), 0);
    assert_eq!(after.count(Kind::Heartbeat), 1);
    clean(&after);
}

#[test]
fn a_saved_state_that_is_damaged_is_refused() {
    let mut engine = Engine::new(Policy::default(), None, None);
    assert!(engine.restore("not json", 0).is_err());
    assert!(engine.restore(r#"{"version":3}"#, 0).is_err());
    let unbound = r#"{"version":1,"cbsdId":"x","grants":[]}"#;
    assert!(engine.restore(unbound, 0).is_err(), "no SAS address saved");
    let odd = r#"{"version":2,"cbsdId":"x","grants":[{"id":"a","low":1,"high":2},{"id":"b"}]}"#;
    assert_eq!(engine.restore(odd, 0), Ok(0));
}

#[test]
fn a_deregistration_by_the_sas_stops_everything_then_registers_again() {
    let registration = json!({ "userId": "u", "fccId": "MOCK-FCC", "cbsdSerialNumber": "0001" });
    let mut sim = Sim::new(Engine::new(Policy::default(), Some(registration), None));
    sim.online(c5(), Some(c9()));
    assert!(sim.run_until_open(30).is_some());
    assert_eq!(sim.count(Kind::Registration), 1);
    sim.sas
        .fault(Kind::Heartbeat, Fault::Code(105, "deregistered".into()));
    sim.run(1500);
    assert!(!sim.open());
    assert_eq!(
        sim.commands(RadioCommand::LeavePrimary),
        1,
        "cease all transmissions"
    );
    assert!(sim.run_until_open(1200).is_some(), "back after the wait");
    assert_eq!(sim.count(Kind::Registration), 2);
    clean(&sim);
}

#[test]
fn a_unit_that_cannot_register_says_so_and_stays_closed() {
    let mut sim = up();
    sim.sas.forget();
    sim.run(1600);
    assert!(sim.cannot_register);
    assert!(!sim.open());
    assert_eq!(sim.count(Kind::Registration), 0);
}

#[test]
fn a_hand_back_closes_the_gate_before_anything_is_given_up() {
    let mut sim = up();
    sim.stop();
    assert!(!sim.open(), "closed in the same step");
    sim.run(10);
    assert!(sim.stopped);
    assert_eq!(sim.count(Kind::Relinquishment), 1);
    assert_eq!(sim.count(Kind::Deregistration), 1);
    assert_eq!(sim.sas.grant_count(), 0);
    assert!(!sim.sas.registered);
    clean(&sim);
}

#[test]
fn standby_grants_make_a_move_to_a_new_carrier_free() {
    let policy = Policy {
        standby: vec![c12(), c6()],
        ..Policy::default()
    };
    let mut sim = up_with(policy);
    sim.run(60);
    assert_eq!(sim.sas.grant_count(), 4);
    assert_eq!(sim.count(Kind::Grant), 2, "in use first, then standby");
    sim.online(c12(), Some(c6()));
    assert!(sim.open(), "already authorized on the new carriers");
    sim.run(3000);
    assert_eq!(sim.gate_changes.len(), 1);
    assert_eq!(sim.count(Kind::Grant), 2);
    clean(&sim);
}

#[test]
fn a_grant_nothing_has_used_for_the_retention_time_goes_back() {
    let policy = Policy {
        retain_idle: 3600,
        ..Policy::default()
    };
    let mut sim = up_with(policy);
    sim.online(c5(), Some(c6()));
    sim.run(1800);
    assert!(sim.sas.holds(c9()));
    sim.run(3600);
    assert!(!sim.sas.holds(c9()));
    assert_eq!(sim.count(Kind::Relinquishment), 1);
    assert!(sim.open());
    clean(&sim);
}

#[test]
fn the_handshake_limit_is_off_unless_the_operator_sets_it() {
    let mut patient = Sim::registered(Policy::default());
    patient.sas.faults(Kind::Grant, Fault::Swallow, 10_000);
    patient.online(c5(), None);
    patient.run(3600);
    assert!(patient.radio_commands.is_empty());
    assert!(!patient.open());

    let policy = Policy {
        handshake_limit: 120,
        ..Policy::default()
    };
    let mut strict = Sim::registered(policy);
    strict.sas.faults(Kind::Grant, Fault::Swallow, 10_000);
    strict.online(c5(), None);
    strict.run(130);
    assert_eq!(strict.commands(RadioCommand::LeavePrimary), 1);
}

#[test]
fn a_call_the_daemon_never_answers_is_treated_as_lost() {
    let mut engine = Engine::new(Policy::default(), None, Some(CBSD.to_string()));
    let sends = |actions: &[Action]| {
        actions
            .iter()
            .filter(|action| matches!(action, Action::Send(_)))
            .count()
    };
    let first = engine.step(
        100,
        0,
        Input::Online {
            primary: c5(),
            uplink: None,
        },
    );
    assert_eq!(sends(&first), 1);
    assert_eq!(
        sends(&engine.step(120, 0, Input::Tick)),
        0,
        "one call at a time"
    );
    // Connect time, answer time and a margin have passed: the call is lost.
    assert_eq!(sends(&engine.step(155, 0, Input::Tick)), 0);
    assert_eq!(
        sends(&engine.step(158, 0, Input::Tick)),
        1,
        "and is made again"
    );
}

#[test]
fn the_engine_says_when_it_next_needs_a_tick() {
    let mut sim = up();
    sim.run(5);
    let wake = sim.engine.next_wake(sim.now);
    assert!(
        wake > sim.now + 1000,
        "idle until the next heartbeat, not polling"
    );
    assert!(wake <= sim.now + 1440);
}

// ---- Any FCC-authorized SAS, not only the one in use today ----

const SAS_A: &str = "https://sas-a.example/v1.2";
const SAS_B: &str = "https://sas-b.example/v1.2";

fn stored_unit() -> Stored {
    Stored {
        user_id: "test-account".into(),
        fcc_id: "MOCK-FCC".into(),
        serial: "0001".into(),
        single_step: "0".into(),
        category: "B".into(),
        cpi_file: None,
    }
}

fn built_registration() -> Value {
    registration::build(&stored_unit(), &Options::default()).expect("complete unit data")
}

/// A unit with registration data and a CBSD ID the vendor client left.
fn takeover(policy: Policy, adopted: &str) -> Sim {
    let engine = Engine::new(policy, Some(built_registration()), Some(adopted.to_string()));
    let mut sim = Sim::new(engine);
    sim.sas.registered = true;
    sim
}

fn logged(sim: &Sim, text: &str) -> bool {
    sim.log.iter().any(|line| line.contains(text))
}

#[test]
fn a_new_sas_gets_a_registration_built_from_the_unit() {
    let mut sim = Sim::new(Engine::new(Policy::default(), Some(built_registration()), None));
    sim.online(c5(), Some(c9()));
    assert!(sim.run_until_open(30).is_some());
    assert_eq!(sim.count(Kind::Registration), 1);
    let sent = &sim.sas.registrations[0];
    assert_eq!(sent["userId"], "test-account");
    assert_eq!(sent["fccId"], "MOCK-FCC");
    assert_eq!(sent["cbsdSerialNumber"], "0001");
    assert!(sent.get("measCapability").is_none(), "no capability claimed");
    assert!(sent.get("installationParam").is_none(), "nothing made up");
    clean(&sim);
}

#[test]
fn registration_answers_are_read_by_code() {
    let mut sim = Sim::new(Engine::new(Policy::default(), Some(built_registration()), None));
    sim.sas
        .fault(Kind::Registration, Fault::Code(200, String::new()));
    sim.online(c5(), None);
    sim.run(30);
    assert!(!sim.open());
    assert!(logged(&sim, "pending"), "{:?}", sim.log);
    assert_eq!(sim.engine.status(sim.now)["lastRegistrationCode"], 200);
    let took = sim.run_until_open(120).expect("the next try succeeds");
    assert!(took >= 20, "waited {took} s before the next try");
    assert_eq!(sim.count(Kind::Registration), 2);
    assert_eq!(sim.engine.status(sim.now)["lastRegistrationCode"], 0);
    clean(&sim);
}

#[test]
fn a_unit_with_no_complete_registration_data_fails_closed() {
    let incomplete = Stored {
        fcc_id: String::new(),
        ..stored_unit()
    };
    assert!(registration::build(&incomplete, &Options::default()).is_err());
    let mut sim = Sim::new(Engine::new(Policy::default(), None, None));
    sim.online(c5(), None);
    sim.run(60);
    assert!(sim.cannot_register);
    assert!(!sim.open());
    assert_eq!(sim.count(Kind::Registration), 0);
    assert!(sim.sent.is_empty(), "nothing goes to the SAS");
}

#[test]
fn a_vendor_cbsd_id_the_new_sas_does_not_know_is_dropped_even_without_a_name() {
    // The new SAS answers 103 but does not name cbsdId, which TS-0016 allows.
    let mut sim = takeover(Policy::default(), "OLD-SAS/0001");
    sim.sas
        .fault(Kind::Grant, Fault::Code(103, "invalid".into()));
    sim.online(c5(), Some(c9()));
    let took = sim.run_until_open(60).expect("registers, then opens");
    assert!(took <= 20, "took {took} s");
    assert_eq!(sim.count(Kind::Registration), 1);
    assert_eq!(sim.engine.status(sim.now)["cbsdConfirmed"], true);
    clean(&sim);
}

#[test]
fn a_confirmed_cbsd_id_survives_an_unnamed_103() {
    let mut sim = up();
    sim.sas
        .fault(Kind::Grant, Fault::Code(103, "invalid".into()));
    sim.online(c5(), Some(c6()));
    assert!(sim.run_until_open(120).is_some());
    assert_eq!(sim.count(Kind::Registration), 0, "no registration for a grant error");
    clean(&sim);
}

#[test]
fn saved_state_from_another_sas_starts_clean() {
    let mut before = takeover(Policy::default(), CBSD);
    before.engine.bind(SAS_A, "test-account");
    before.online(c5(), Some(c9()));
    assert!(before.run_until_open(30).is_some());
    before.run(100);
    let saved = before.saved.clone().expect("state was saved");
    let state: Value = serde_json::from_str(&saved).unwrap();
    assert_eq!(state["sasUrl"], SAS_A);
    assert_eq!(state["cbsdId"], CBSD);

    // Same SAS and account: the grants come back.
    let mut same = Engine::new(Policy::default(), Some(built_registration()), None);
    same.bind(SAS_A, "test-account");
    assert_eq!(same.restore(&saved, 50), Ok(2));
    assert!(same.registered());

    // Another SAS: nothing comes back and the unit registers there.
    let mut moved = Engine::new(Policy::default(), Some(built_registration()), None);
    moved.bind(SAS_B, "test-account");
    assert!(moved.restore(&saved, 50).is_err());
    assert!(!moved.registered());
    assert!(moved.grants().is_empty());
    let mut after = Sim::new(moved);
    after.online(c5(), Some(c9()));
    assert!(after.run_until_open(30).is_some());
    assert_eq!(after.count(Kind::Registration), 1);
    assert_eq!(after.count(Kind::Heartbeat), 1, "no heartbeat for an old grant");

    // Another account at the same SAS also starts clean.
    let mut other = Engine::new(Policy::default(), None, None);
    other.bind(SAS_A, "other-account");
    assert!(other.restore(&saved, 50).is_err());
}

#[test]
fn an_unproven_cbsd_id_is_not_saved() {
    let mut sim = takeover(Policy::default(), "OLD-SAS/0001");
    sim.engine.bind(SAS_B, "test-account");
    sim.sas.faults(Kind::Grant, Fault::Unreachable, 1000);
    sim.online(c5(), None);
    sim.run(300);
    if let Some(saved) = &sim.saved {
        let state: Value = serde_json::from_str(saved).unwrap();
        assert!(state["cbsdId"].is_null());
    }
    assert_eq!(sim.engine.status(sim.now)["cbsdConfirmed"], false);
}

fn suspended_closed_seconds(message: &str) -> u64 {
    let mut sim = up();
    sim.sas.suspend(c5(), 2, message);
    sim.run(1600);
    clean(&sim);
    assert!(sim.open());
    assert_eq!(sim.count(Kind::Grant), 1);
    assert!(sim.radio_commands.is_empty());
    sim.closed_seconds
}

#[test]
fn a_suspension_is_handled_the_same_whatever_the_sas_says() {
    let google = suspended_closed_seconds("Interference Calculations Pending");
    let other = suspended_closed_seconds("Calculating");
    let silent = suspended_closed_seconds("");
    assert!((5..=35).contains(&silent), "{silent} s closed");
    assert_eq!(google, other);
    assert_eq!(google, silent);
}

#[test]
fn quick_heartbeats_of_a_suspended_grant_never_postpone_leaving() {
    let mut sim = up();
    sim.sas.suspend(c5(), 10_000, "");
    sim.run(1500);
    assert!(!sim.open());
    let closed_at = sim.gate_changes.last().expect("a gate change").0;
    let (left_at, command) = sim.radio_commands[0];
    assert_eq!(command, RadioCommand::LeavePrimary);
    assert!(
        left_at >= closed_at && left_at <= closed_at + 60,
        "left after {} s",
        left_at - closed_at
    );
    assert_eq!(sim.count(Kind::Relinquishment), 0, "the grant is kept");
    clean(&sim);
}

#[test]
fn a_conflict_the_sas_never_names_ends_in_one_new_registration() {
    let mut sim = takeover(Policy::default(), CBSD);
    sim.sas.name_conflicts = false;
    sim.sas.plant(c9());
    sim.online(c5(), Some(c9()));
    sim.run(30);
    assert!(!sim.open(), "no grant on c9 yet");
    let took = sim.run_until_open(600).expect("open after the new registration");
    assert!(took <= 300, "took {took} s");
    assert_eq!(sim.count(Kind::Registration), 1);
    assert_eq!(sim.count(Kind::Deregistration), 0);
    assert_eq!(sim.sas.grant_count(), 2);
    assert!(logged(&sim, "does not name"));
    clean(&sim);

    // Another one soon after does not register again: that range waits.
    sim.sas.plant(c6());
    sim.online(c5(), Some(c6()));
    sim.run(900);
    assert_eq!(sim.count(Kind::Registration), 1, "at most one per six hours");
    assert!(!sim.open());
    clean(&sim);
}

#[test]
fn an_unnamed_conflict_on_a_standby_range_registers_nothing() {
    let policy = Policy {
        standby: vec![c12()],
        ..Policy::default()
    };
    let mut sim = takeover(policy, CBSD);
    sim.sas.name_conflicts = false;
    sim.sas.plant(c12());
    sim.online(c5(), Some(c9()));
    assert!(sim.run_until_open(30).is_some());
    sim.run(4000);
    assert!(sim.open());
    assert_eq!(sim.count(Kind::Registration), 0);
    clean(&sim);
}

#[test]
fn a_busy_sas_gets_the_time_it_asks_for() {
    let mut sim = up();
    sim.sas.fault(Kind::Grant, Fault::Busy(Some(90)));
    sim.online(c5(), Some(c6()));
    let first = sim.now;
    let took = sim.run_until_open(300).expect("the gate reopens");
    assert!(took >= 90, "asked again after {took} s");
    let grants: Vec<u64> = sim
        .sent
        .iter()
        .filter(|(_, kind)| *kind == Kind::Grant)
        .map(|(at, _)| *at)
        .collect();
    assert_eq!(grants.len(), 3, "first grant, busy, then the retry");
    assert!(grants[2] >= first + 90);
    assert_eq!(sim.count(Kind::Registration), 0);
    assert_eq!(sim.count(Kind::Relinquishment), 0);
    clean(&sim);
}

#[test]
fn a_busy_hold_never_outlasts_the_right_to_transmit() {
    // Transmit expiry 30 minutes after each heartbeat, and a server that
    // asks for a day's wait on the first heartbeat.
    let mut sim = Sim::registered(Policy::default());
    sim.sas.transmit_life = 1800;
    sim.online(c5(), Some(c9()));
    assert!(sim.run_until_open(30).is_some());
    sim.sas.faults(Kind::Heartbeat, Fault::Busy(Some(86_400)), 1);
    sim.run(4 * 3600);
    clean(&sim);
    assert!(sim.open(), "a heartbeat got through before expiry");
    assert_eq!(sim.gate_changes.len(), 1);
}

#[test]
fn a_sas_that_reads_one_object_per_call_still_serves_both_carriers() {
    let mut sim = Sim::registered(Policy::default());
    sim.sas.single_only = true;
    sim.online(c5(), Some(c9()));
    let took = sim.run_until_open(60).expect("the gate opens");
    assert!(took <= 30, "took {took} s");
    assert!(logged(&sim, "one object per call"));
    assert_eq!(sim.engine.status(sim.now)["oneObjectPerCall"], true);
    sim.run(86_400);
    assert!(sim.open());
    assert_eq!(sim.gate_changes.len(), 1);
    assert_eq!(sim.sas.grant_count(), 2);
    clean(&sim);

    let quiet = Policy {
        batch: false,
        ..Policy::default()
    };
    let mut set = Sim::registered(quiet);
    set.sas.single_only = true;
    set.online(c5(), Some(c9()));
    assert!(set.run_until_open(30).is_some());
    assert!(!logged(&set, "did not take"), "never sent a batch");
    clean(&set);
}

#[test]
fn a_short_grant_is_renewed_before_it_ends_and_not_on_every_heartbeat() {
    let mut sim = Sim::registered(Policy::default());
    sim.sas.grant_life = 48 * 3600;
    sim.online(c5(), Some(c9()));
    assert!(sim.run_until_open(30).is_some());
    sim.run(86_400);
    assert_eq!(sim.sas.renewals, 0, "no renewal in the first day of 48 h");
    // A unit clock far off changes nothing: renewal uses the SAS's clock.
    sim.clock_error = 400 * 86_400;
    sim.run(4 * 86_400);
    clean(&sim);
    assert!(sim.open());
    assert_eq!(sim.gate_changes.len(), 1, "never expired");
    assert_eq!(sim.count(Kind::Grant), 1, "the same two grants all along");
    let heartbeats = sim.count(Kind::Heartbeat);
    assert!(
        (2..=12).contains(&sim.sas.renewals),
        "{} renewal objects in {heartbeats} heartbeat calls",
        sim.sas.renewals
    );
}

#[test]
fn the_sas_asking_for_measurements_gets_none() {
    let mut sim = Sim::registered(Policy::default());
    sim.sas.meas_report_config = vec!["RECEIVED_POWER_WITH_GRANT".to_string()];
    sim.online(c5(), Some(c9()));
    assert!(sim.run_until_open(30).is_some());
    sim.run(7200);
    assert!(sim.open());
    assert_eq!(sim.sas.meas_reports, 0, "no made-up measurement");
    assert_eq!(
        sim.engine.status(sim.now)["measReportRequested"],
        json!(["RECEIVED_POWER_WITH_GRANT"])
    );
    let notes = sim
        .log
        .iter()
        .filter(|line| line.contains("makes none"))
        .count();
    assert_eq!(notes, 1, "said once, not on every answer");
    clean(&sim);
}
