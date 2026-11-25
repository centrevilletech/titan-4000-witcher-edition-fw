//! The controller, one packet at a time.

use witcher_modem_aqm::block::M1Block;
use witcher_modem_aqm::pie::{Arrival, Decision, IDLE_RESET_MS, P_SCALE};

const BIG: u32 = 1380;
/// N4's grant EWMA for one carrier: 5,850 B per TTI = 1,170 B/ms at TDD config 2.
const ONE_CARRIER: u32 = 5850;

fn ipv4(tos: u8) -> [u8; 40] {
    let mut h = [0u8; 40];
    h[0] = 0x45;
    h[1] = tos;
    h
}

fn arrival(len: u32, now: u32, queue_bytes: u32) -> Arrival {
    Arrival { len, now, queue_bytes, g_ema: ONE_CARRIER, min_len: 600 }
}

/// A block that has been congested for a while: no burst allowance left.
fn congested() -> M1Block {
    let b = M1Block::new();
    b.burst_ms.set(0);
    b.last_update_tti.set(1000);
    b
}

#[test]
fn small_packets_are_never_dropped_or_marked() {
    let b = congested();
    b.prob_q24.set(P_SCALE);
    b.overload.set(1);
    for queue in [0, 15_000, 60_000, 250_000, 4_000_000] {
        for len in [128, 228, 400, 599] {
            for tos in [0, 1, 2] {
                let mut h = ipv4(tos);
                let d = b.decide(arrival(len, 1005, queue), &mut h);
                assert!(matches!(d, Decision::Enqueue | Decision::SparedSmall), "{len} B at {queue} B: {d:?}");
                assert_eq!(h, ipv4(tos), "header touched");
            }
        }
    }
    assert!(b.count(Decision::SparedSmall) > 0);
    assert_eq!(b.count(Decision::Drop) + b.count(Decision::Ceiling) + b.count(Decision::Mark), 0);
}

#[test]
fn the_burst_allowance_absorbs_line_rate_bursts_and_harq_pauses() {
    let b = M1Block::new();
    let mut drops = 0;
    for cycle in 0..40u32 {
        let start = 1000 + cycle * 120;
        for k in 0..10 {
            drops += u32::from(b.decide(arrival(BIG, start + 1, 14_000 + k * BIG), &mut ipv4(0)).is_drop());
        }
        for dt in (25..110).step_by(15) {
            drops += u32::from(b.decide(arrival(BIG, start + dt, 2000), &mut ipv4(0)).is_drop());
        }
    }
    assert_eq!(drops, 0);
    assert!(b.count(Decision::SparedBurst) > 0);
}

#[test]
fn ecn_capable_packets_are_marked_below_the_ceiling() {
    let b = M1Block::new();
    let (mut marks, mut drops) = (0, 0);
    for t in 1..=600 {
        let mut h = ipv4(0x02);
        match b.decide(arrival(BIG, 1000 + t, 32_000), &mut h) {
            Decision::Mark => {
                marks += 1;
                assert_eq!(h[1] & 3, 3);
            }
            d if d.is_drop() => drops += 1,
            _ => {}
        }
    }
    assert!(marks > 0);
    assert_eq!(drops, 0);
}

#[test]
fn the_ceiling_is_the_larger_of_its_floor_and_its_time_at_the_drain_rate() {
    let b = M1Block::new();
    // One carrier: 1,170 B/ms x 50 ms = 58,500 B > the 50,000 B floor.
    assert_eq!(b.ceiling_bytes(b.drain_rate_bpms(ONE_CARRIER)), 58_500);
    // A stale grant estimate after idle: the 500 B/ms rate floor, so the byte floor holds.
    assert_eq!(b.ceiling_bytes(b.drain_rate_bpms(370)), 50_000);
    // Two carriers.
    assert_eq!(b.ceiling_bytes(b.drain_rate_bpms(11_000)), 110_000);
    // M1's rule was max(50 KB, 10 x G_ema): the same at TDD config 2.
    for g in [5850, 9000, 11_000] {
        assert!(b.ceiling_bytes(b.drain_rate_bpms(g)).abs_diff(50_000.max(10 * g)) <= 50);
    }
    // TDD config 1 has twice the uplink subframes.
    b.ul_subframes_per_frame.set(4);
    assert_eq!(b.drain_rate_bpms(ONE_CARRIER), 2340);
    // A zero ceiling (zero floor and zero time) means none.
    b.ceiling_floor_bytes.set(0);
    b.ceiling_ms.set(0);
    assert_eq!(b.decide(arrival(BIG, 1000, 4_000_000), &mut ipv4(0)), Decision::SparedBurst);
}

#[test]
fn ceiling_drops_spend_tokens_and_an_empty_bucket_lifts_the_budget() {
    let b = congested();
    let full = 64 << 24;
    assert_eq!(b.tokens_q24.get(), full);
    for i in 1..=63 {
        assert_eq!(b.decide(arrival(BIG, 1001, 200_000), &mut ipv4(0)), Decision::Ceiling);
        assert_eq!(b.tokens_q24.get(), full - i * P_SCALE);
        assert_eq!(b.overload.get(), 0);
    }
    b.decide(arrival(BIG, 1001, 200_000), &mut ipv4(0));
    assert_eq!((b.overload.get(), b.overloads.get()), (1, 1), "the 64th drop empties the bucket");

    // In overload the control law may take p past the 2% budget...
    let mut now = 1001;
    for _ in 0..40 {
        now += 15;
        b.decide(arrival(BIG, now, 45_000), &mut ipv4(0));
    }
    assert!(b.prob_q24.get() > b.budget(), "p {} stuck at the budget", b.prob_q24.get());
    assert!(b.overload_updates.get() > 0);

    // ...and the overload ends once the queue is short and p decays under the budget.
    while b.overload.get() == 1 {
        now += 15;
        b.decide(arrival(BIG, now, 2000), &mut ipv4(0));
        assert!(now < 10_000, "overload never ended");
    }
    assert!(b.prob_q24.get() < b.budget());
}

#[test]
fn packets_under_the_ceiling_refill_the_bucket_at_the_budget_rate() {
    let b = congested();
    b.tokens_q24.set(0);
    let per_packet = b.budget();
    b.decide(arrival(BIG, 1001, 10_000), &mut ipv4(0));
    assert_eq!(b.tokens_q24.get(), per_packet);
    for _ in 0..10_000 {
        b.decide(arrival(BIG, 1001, 10_000), &mut ipv4(0));
    }
    assert_eq!(b.tokens_q24.get(), 64 << 24, "capped at the depth");
}

#[test]
fn without_the_latch_the_budget_always_holds() {
    let b = congested();
    b.ceiling_burst_pkts.set(0);
    let mut now = 1000;
    for _ in 0..5000 {
        now += 1;
        b.decide(arrival(BIG, now, 120_000), &mut ipv4(0));
    }
    assert_eq!(b.overloads.get(), 0);
    assert!(b.prob_q24.get() <= b.budget());
    assert!(b.count(Decision::Ceiling) > 4000);
}

#[test]
fn a_zero_or_full_budget_means_plain_rfc_8033() {
    let b = M1Block::new();
    assert_eq!(b.budget(), P_SCALE / 50);
    b.drop_budget_q24.set(0);
    assert_eq!(b.budget(), P_SCALE);
    b.drop_budget_q24.set(u32::MAX);
    assert_eq!(b.budget(), P_SCALE);
}

#[test]
fn an_idle_gap_resets_the_controller() {
    let b = congested();
    b.prob_q24.set(P_SCALE / 4);
    b.overload.set(1);
    b.tokens_q24.set(0);
    b.decide(arrival(BIG, 1000 + IDLE_RESET_MS + 1, 1000), &mut ipv4(0));
    assert_eq!(b.prob_q24.get(), 0);
    assert_eq!(b.overload.get(), 0);
    assert_eq!(b.tokens_q24.get(), 64 << 24);
    assert_eq!(b.burst_ms.get(), 55);
    assert_eq!(b.rearms.get(), 1);
}

#[test]
fn every_packet_is_counted_once_by_kind() {
    let b = M1Block::new();
    let mut now = 1000;
    for i in 0..3000u32 {
        now += 1 + i % 3;
        let queue = (i * 7919) % 90_000;
        let len = [128, 700, 1380][i as usize % 3];
        b.decide(arrival(len, now, queue), &mut ipv4([0, 1, 2][i as usize % 3]));
    }
    let enqueued = b.count(Decision::Enqueue);
    let dropped = b.count(Decision::Drop) + b.count(Decision::Ceiling);
    assert_eq!(enqueued + dropped, b.seen.get());
    assert!(b.count(Decision::Mark) + b.count(Decision::SparedSmall) + b.count(Decision::SparedBurst) <= enqueued);
}

#[test]
fn any_word_the_console_can_write_is_safe() {
    // Overflow checks are on in host tests: no tunable or state value may trip them.
    let extremes = [0, 1, 2, 255, 256, 0x7fff_ffff, 0x8000_0000, u32::MAX];
    let mut now = 1000u32;
    for (i, &v) in extremes.iter().cycle().take(extremes.len() * 23).enumerate() {
        let b = M1Block::new();
        let word = match i % 23 {
            0 => &b.target_ms,
            1 => &b.t_update_ms,
            2 => &b.max_burst_ms,
            3 => &b.alpha_q10,
            4 => &b.beta_q10,
            5 => &b.min_rate_bpms,
            6 => &b.ceiling_floor_bytes,
            7 => &b.ecn_max_prob_q24,
            8 => &b.mtu_bytes,
            9 => &b.flags,
            10 => &b.drop_budget_q24,
            11 => &b.ceiling_ms,
            12 => &b.ul_subframes_per_frame,
            13 => &b.ceiling_burst_pkts,
            14 => &b.prob_q24,
            15 => &b.accu_q24,
            16 => &b.qdelay_old_us,
            17 => &b.burst_ms,
            18 => &b.last_update_tti,
            19 => &b.rng,
            20 => &b.overload,
            21 => &b.tokens_q24,
            _ => &b.seen,
        };
        word.set(v);
        for k in 0..200u32 {
            now = now.wrapping_add(k % 20);
            let queue = [0, 30_000, 200_000, u32::MAX][k as usize % 4];
            let g_ema = [0, 370, ONE_CARRIER, u32::MAX][k as usize % 4];
            let len = [0, 599, BIG, u32::MAX][k as usize % 4];
            let mut h = ipv4((k % 4) as u8);
            b.decide(Arrival { len, now, queue_bytes: queue, g_ema, min_len: 600 }, &mut h);
        }
    }
}
