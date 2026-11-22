//! The SAS behaviors that have taken customers offline, replayed against the
//! grant manager. Every scenario also checks, second by second, that the
//! gate was never open while the mock SAS said a carrier was not authorized.
use serde_json::json;
use witcher_sas_model::band::Range;
use witcher_sas_model::engine::{Action, Engine, Gate, Input, Policy, RadioCommand};
use witcher_sas_model::mock::{CBSD, Fault, Sim};
use witcher_sas_model::proto::Kind;

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
    assert!(engine.restore(r#"{"version":2}"#, 0).is_err());
    let odd = r#"{"version":1,"cbsdId":"x","grants":[{"id":"a","low":1,"high":2},{"id":"b"}]}"#;
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
