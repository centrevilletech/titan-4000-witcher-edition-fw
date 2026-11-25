//! Closed-loop traces: CUBIC and BBR on one and two uplink carriers, before and after
//! the overload latch.
//!
//! "Before" is the bench state of 2026-11-25: M1's ceiling (`max(50 KB, 10 x G_ema)`,
//! here `max(50 KB, 50 ms)` at TDD config 2) and its 2% budget, which is this crate
//! with `ceiling_burst_pkts = 0`. "After" is the shipped defaults. N4 v2 (selector 0)
//! shows what PIE replaced.
//!
//! What the bench found and these reproduce:
//! - BBR (4 flows, one carrier) sat on the ceiling: 1,438 ceiling drops against 54 PIE
//!   drops in 20 s, queue p50 63 ms. On two carriers it held ~38 ms where N4 held ~22.
//! - CUBIC on PIE doubled N4's throughput on two carriers. Its queue and drops must not
//!   change.

mod sim;

use sim::aqm::{Aqm, N4, Pie};
use sim::{Outcome, Scenario, Sender};

const SEEDS: [u32; 2] = [1, 2];

fn mean(runs: &[Outcome], f: impl Fn(&Outcome) -> f64) -> f64 {
    runs.iter().map(f).sum::<f64>() / runs.len() as f64
}

/// Seed-averaged outcome of one scenario under a fresh AQM per seed.
fn trace(label: &str, aqm: &str, build: impl Fn(u32) -> Scenario, make: impl Fn() -> Box<dyn Aqm>) -> Outcome {
    let runs: Vec<Outcome> = SEEDS.iter().map(|&seed| sim::run(&build(seed), make().as_mut())).collect();
    let flows = runs[0].per_flow_mbps.len();
    let avg = Outcome {
        mbps: mean(&runs, |o| o.mbps),
        loss_pct: mean(&runs, |o| o.loss_pct),
        qd50: mean(&runs, |o| o.qd50),
        qd90: mean(&runs, |o| o.qd90),
        qd99: mean(&runs, |o| o.qd99),
        qd_max: mean(&runs, |o| o.qd_max),
        probe50: mean(&runs, |o| o.probe50),
        aqm_drops: mean(&runs, |o| f64::from(o.aqm_drops)) as u32,
        ceiling_drops: mean(&runs, |o| f64::from(o.ceiling_drops)) as u32,
        rto: mean(&runs, |o| f64::from(o.rto)) as u32,
        scell_share: mean(&runs, |o| o.scell_share),
        per_flow_mbps: (0..flows).map(|i| mean(&runs, |o| o.per_flow_mbps[i])).collect(),
    };
    eprintln!(
        "{label:24} {aqm:7} {:6.2} Mbps  loss {:5.2}%  queue p50/p90/p99 {:3.0}/{:3.0}/{:3.0} ms  \
         drops PIE {:5} ceiling {:5}  RTO {:2}  SCell {:.2}",
        avg.mbps, avg.loss_pct, avg.qd50, avg.qd90, avg.qd99, avg.aqm_drops, avg.ceiling_drops, avg.rto, avg.scell_share
    );
    avg
}

fn before_after(label: &str, build: impl Fn(u32) -> Scenario + Copy) -> (Outcome, Outcome) {
    let before = trace(label, "before", build, || Box::new(Pie::without_latch()));
    let after = trace(label, "after", build, || Box::new(Pie::new()));
    (before, after)
}

fn flows(sender: Sender, n: usize, carriers: usize) -> impl Fn(u32) -> Scenario + Copy {
    move |seed| Scenario::new(vec![sender; n], carriers, seed)
}

/// CUBIC must not notice the change: same rate, same queue.
fn assert_unchanged(label: &str, before: &Outcome, after: &Outcome) {
    assert!(after.mbps >= before.mbps * 0.98, "{label}: {:.2} Mbps < 98% of {:.2}", after.mbps, before.mbps);
    assert!((after.qd50 - before.qd50).abs() <= 4.0, "{label}: queue p50 {:.0} vs {:.0} ms", after.qd50, before.qd50);
    assert!(after.qd99 <= before.qd99 + 8.0, "{label}: queue p99 {:.0} vs {:.0} ms", after.qd99, before.qd99);
}

/// BBR must come off the ceiling to near the target, at the same rate.
fn assert_off_the_ceiling(label: &str, before: &Outcome, after: &Outcome) {
    assert!(after.mbps >= before.mbps * 0.97, "{label}: {:.2} Mbps < 97% of {:.2}", after.mbps, before.mbps);
    assert!(after.qd50 <= before.qd50 * 0.6, "{label}: queue p50 {:.0} not below 60% of {:.0} ms", after.qd50, before.qd50);
    assert!(after.qd50 <= 32.0, "{label}: queue p50 {:.0} ms is not near the 14 ms target", after.qd50);
    assert!(
        after.ceiling_drops * 4 <= before.ceiling_drops,
        "{label}: ceiling drops {} not below a quarter of {}",
        after.ceiling_drops,
        before.ceiling_drops
    );
    assert!(
        before.ceiling_drops > 5 * before.aqm_drops,
        "{label}: before, the ceiling should do the dropping ({} vs {} PIE)",
        before.ceiling_drops,
        before.aqm_drops
    );
}

#[test]
fn bbr_x4_comes_off_the_ceiling_on_one_and_two_carriers() {
    for carriers in [1, 2] {
        let label = format!("BBR x4, {carriers} carrier(s)");
        let (before, after) = before_after(&label, flows(Sender::Bbr, 4, carriers));
        assert_off_the_ceiling(&label, &before, &after);
    }
}

#[test]
fn bbr_x1_is_no_worse() {
    for carriers in [1, 2] {
        let label = format!("BBR x1, {carriers} carrier(s)");
        let (before, after) = before_after(&label, flows(Sender::Bbr, 1, carriers));
        assert!(after.mbps >= before.mbps * 0.97, "{label}: rate");
        assert!(after.qd50 <= before.qd50 + 2.0, "{label}: queue p50 {:.0} vs {:.0} ms", after.qd50, before.qd50);
    }
}

#[test]
fn cubic_is_unchanged_on_one_and_two_carriers() {
    for (n, carriers) in [(1, 1), (1, 2), (4, 1), (4, 2), (8, 2)] {
        let label = format!("CUBIC x{n}, {carriers} carrier(s)");
        let (before, after) = before_after(&label, flows(Sender::Cubic, n, carriers));
        assert_unchanged(&label, &before, &after);
    }
}

#[test]
fn cubic_keeps_pie_win_over_n4() {
    // Single-flow CUBIC on two carriers: N4's paced drops halve it (bench 5.17 vs 8.23).
    let one = flows(Sender::Cubic, 1, 2);
    let n4 = trace("CUBIC x1, 2 carriers", "N4", one, || Box::new(N4::new()));
    let pie = trace("CUBIC x1, 2 carriers", "after", one, || Box::new(Pie::new()));
    assert!(pie.mbps >= 1.5 * n4.mbps, "PIE {:.2} vs N4 {:.2} Mbps", pie.mbps, n4.mbps);

    // With the eNB scheduling the SCell only on a big buffer report, N4's short queue
    // loses the second carrier and PIE keeps it (bench: 6.6-7.3 vs 13.6-14.6 Mbps).
    let gated = |seed| Scenario { scell_gate: Some((40_000, 200)), ..Scenario::new(vec![Sender::Cubic; 4], 2, seed) };
    let n4 = trace("CUBIC x4, gated SCell", "N4", gated, || Box::new(N4::new()));
    let (before, after) = before_after("CUBIC x4, gated SCell", gated);
    assert_unchanged("CUBIC x4, gated SCell", &before, &after);
    assert!(after.mbps >= 1.5 * n4.mbps, "gated: PIE {:.2} vs N4 {:.2} Mbps", after.mbps, n4.mbps);
    assert!(after.scell_share >= 0.8, "gated: SCell used in {:.0}% of subframes", after.scell_share * 100.0);
}

#[test]
fn losing_a_carrier_mid_run() {
    let cubic = |seed| Scenario { scell_off_at: Some(10_000), ..Scenario::new(vec![Sender::Cubic; 4], 2, seed) };
    let (before, after) = before_after("CUBIC x4, SCell lost", cubic);
    assert_unchanged("CUBIC x4, SCell lost", &before, &after);
    let bbr = |seed| Scenario { scell_off_at: Some(10_000), ..Scenario::new(vec![Sender::Bbr; 4], 2, seed) };
    let (before, after) = before_after("BBR x4, SCell lost", bbr);
    assert!(after.mbps >= before.mbps * 0.97, "BBR, SCell lost: rate");
    assert!(after.qd50 <= before.qd50 * 0.6, "BBR, SCell lost: queue p50 {:.0} vs {:.0} ms", after.qd50, before.qd50);
}

#[test]
fn unresponsive_flood_is_held_near_target() {
    let flood = |seed| Scenario::new(vec![Sender::Udp { kbps: 20_000 }], 1, seed);
    let (before, after) = before_after("UDP 20 Mbps, 1 carrier", flood);
    assert!(after.qd50 <= before.qd50 * 0.6, "flood: queue p50 {:.0} vs {:.0} ms", after.qd50, before.qd50);
    assert!(after.mbps >= before.mbps * 0.95, "flood: rate");
}
