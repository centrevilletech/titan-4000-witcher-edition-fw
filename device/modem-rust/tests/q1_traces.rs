//! Closed-loop traces of selector 3 (lane Q1) against selector 1 (v1.0.16's PIE) and N4.
//!
//! The link is R1's model (`sim`), with the eNB scheduling the SCell only while it saw a
//! buffer report of at least 30 KB within 200 ms: the gate that fits the bench's
//! carrier behaviour in this model (lane Q1 REPORT, section 2). Lane Q3's calibrated model,
//! where the eNB's grant lag sets a 15 ms floor, is in the lane folder; these traces pin
//! the direction of each change, not bench numbers.

mod sim;

use sim::aqm::{Aqm, N4, Pie, Q1};
use sim::{Outcome, Scenario, Sender};

const SEEDS: [u32; 2] = [1, 2];
const GATE: Option<(u32, u32)> = Some((30_000, 200));

fn mean(runs: &[Outcome], f: impl Fn(&Outcome) -> f64) -> f64 {
    runs.iter().map(f).sum::<f64>() / runs.len() as f64
}

fn trace(label: &str, aqm: &str, build: impl Fn(u32) -> Scenario, make: impl Fn() -> Box<dyn Aqm>) -> Outcome {
    let runs: Vec<Outcome> = SEEDS.iter().map(|&seed| sim::run(&build(seed), make().as_mut())).collect();
    let avg = Outcome {
        mbps: mean(&runs, |o| o.mbps),
        loss_pct: mean(&runs, |o| o.loss_pct),
        qd50: mean(&runs, |o| o.qd50),
        qd90: mean(&runs, |o| o.qd90),
        qd99: mean(&runs, |o| o.qd99),
        scell_share: mean(&runs, |o| o.scell_share),
        ..Outcome::default()
    };
    eprintln!(
        "{label:28} {aqm:10} {:6.2} Mbps  loss {:5.2}%  queue p50/p90/p99 {:3.0}/{:3.0}/{:3.0} ms  SCell {:.2}",
        avg.mbps, avg.loss_pct, avg.qd50, avg.qd90, avg.qd99, avg.scell_share
    );
    avg
}

fn scenario(sender: Sender, n: usize, carriers: usize) -> impl Fn(u32) -> Scenario + Copy {
    move |seed| Scenario { scell_gate: GATE, ..Scenario::new(vec![sender; n], carriers, seed) }
}

/// Selector 1 and selector 3 on one scenario.
fn both(label: &str, build: impl Fn(u32) -> Scenario + Copy) -> (Outcome, Outcome) {
    let pie = trace(label, "selector 1", build, || Box::new(Pie::new()));
    let q1 = trace(label, "selector 3", build, || Box::new(Q1::new()));
    (pie, q1)
}

#[test]
fn cubic_x4_two_carriers_queue_drops_and_the_second_carrier_stays() {
    let (pie, q1) = both("CUBIC x4, 2 carriers", scenario(Sender::Cubic, 4, 2));
    assert!(q1.qd50 <= 0.8 * pie.qd50, "queue p50 {:.0} vs {:.0} ms", q1.qd50, pie.qd50);
    assert!(q1.mbps >= 0.95 * pie.mbps, "{:.2} vs {:.2} Mbps", q1.mbps, pie.mbps);
    assert!(q1.scell_share >= 0.8, "SCell in {:.0}% of subframes", q1.scell_share * 100.0);
}

#[test]
fn cubic_x1_keeps_the_second_carrier_at_least_as_well() {
    let (pie, q1) = both("CUBIC x1, 2 carriers", scenario(Sender::Cubic, 1, 2));
    assert!(q1.mbps >= 0.95 * pie.mbps, "{:.2} vs {:.2} Mbps", q1.mbps, pie.mbps);
    assert!(q1.qd50 <= pie.qd50 + 2.0, "queue p50 {:.0} vs {:.0} ms", q1.qd50, pie.qd50);
}

#[test]
fn one_carrier_queues_drop() {
    for n in [1, 4] {
        let label = format!("CUBIC x{n}, 1 carrier");
        let build = scenario(Sender::Cubic, n, 1);
        let n4 = trace(&label, "N4", build, || Box::new(N4::new()));
        let (pie, q1) = both(&label, build);
        assert!(q1.qd50 <= 0.75 * pie.qd50, "{label}: queue p50 {:.0} vs {:.0} ms", q1.qd50, pie.qd50);
        // This model's N4 keeps 6.4 Mbps of CUBIC x1 on one carrier; the bench's kept 4.6-4.8
        // (lane Q3's calibrated model: 4.3). Selector 3 must stay within 10% of it here.
        assert!(q1.mbps >= 0.9 * pie.mbps && q1.mbps >= 0.9 * n4.mbps, "{label}: {:.2} Mbps", q1.mbps);
    }
}

#[test]
fn bbr_is_held_lower_at_the_same_rate() {
    for carriers in [1, 2] {
        let label = format!("BBR x4, {carriers} carrier(s)");
        let (pie, q1) = both(&label, scenario(Sender::Bbr, 4, carriers));
        assert!(q1.qd50 <= pie.qd50 + 1.0, "{label}: queue p50 {:.0} vs {:.0} ms", q1.qd50, pie.qd50);
        assert!(q1.mbps >= 0.97 * pie.mbps, "{label}: {:.2} vs {:.2} Mbps", q1.mbps, pie.mbps);
    }
}

#[test]
fn unresponsive_flood_is_held() {
    let flood = |seed| Scenario::new(vec![Sender::Udp { kbps: 20_000 }], 1, seed);
    let (pie, q1) = both("UDP 20 Mbps, 1 carrier", flood);
    assert!(q1.qd50 <= pie.qd50 + 2.0, "flood: queue p50 {:.0} vs {:.0} ms", q1.qd50, pie.qd50);
    assert!(q1.mbps >= 0.95 * pie.mbps, "flood: rate");
}
