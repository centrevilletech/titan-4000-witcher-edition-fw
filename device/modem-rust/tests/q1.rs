//! Selector 3 (lane Q1), one packet at a time: CoDel on the queue, the second-carrier
//! floor, the flow count, the capacity estimate and the PIE backstop.

use witcher_modem_aqm::block::{M1Block, Word};
use witcher_modem_aqm::codel::{MAX_COUNT, isqrt, spacing};
use witcher_modem_aqm::flows::{count, flow_bit};
use witcher_modem_aqm::pie::{Arrival, Decision, P_SCALE};
use witcher_modem_aqm::q1::FLOW_WINDOW_MS;

const BIG: u32 = 1380;
/// N4's grant EWMA on one carrier (1,170 B/ms at TDD config 2) and on two.
const ONE_CARRIER: u32 = 5850;
const TWO_CARRIERS: u32 = 11_000;

/// An IPv4 TCP header from source port `sport`, ECN bits `tos`.
fn tcp(sport: u16, tos: u8) -> [u8; 44] {
    let mut h = [0u8; 44];
    h[0] = 0x45;
    h[1] = tos;
    h[9] = 6;
    h[12..16].copy_from_slice(&[192, 0, 2, 1]);
    h[16..20].copy_from_slice(&[198, 51, 100, 1]);
    h[20..22].copy_from_slice(&sport.to_be_bytes());
    h[22..24].copy_from_slice(&5299u16.to_be_bytes());
    h
}

fn arrival(len: u32, now: u32, queue_bytes: u32, g_ema: u32) -> Arrival {
    Arrival { len, now, queue_bytes, g_ema, min_len: 600 }
}

/// One packet as hook 4 drives selector 3: the periodic update if due, then the decision.
fn step(b: &M1Block, arrival: Arrival, ip: &mut [u8]) -> Decision {
    b.q1_tick(&arrival);
    b.decide_q1(arrival, ip)
}

fn decide(b: &M1Block, len: u32, now: u32, queue: u32, g_ema: u32, sport: u16) -> Decision {
    step(b, arrival(len, now, queue, g_ema), &mut tcp(sport, 0))
}

/// A block past its burst allowance whose first update has run at `now` on one carrier.
fn settled(now: u32) -> M1Block {
    let b = M1Block::new();
    decide(&b, BIG, now, 1000, ONE_CARRIER, 40_000);
    b.burst_ms.set(0);
    b
}

#[test]
fn small_packets_are_never_dropped_or_marked() {
    let b = settled(1000);
    b.prob_q24.set(P_SCALE);
    b.q1_codel_state.set(3);
    for (i, queue) in [0, 15_000, 60_000, 250_000, 4_000_000].into_iter().enumerate() {
        for len in [128, 228, 400, 599] {
            for tos in [0, 1, 2] {
                let mut h = tcp(40_000, tos);
                let d = step(&b, arrival(len, 1001 + i as u32, queue, ONE_CARRIER), &mut h);
                assert!(matches!(d, Decision::Enqueue | Decision::SparedSmall), "{len} B at {queue} B: {d:?}");
                assert_eq!(h, tcp(40_000, tos), "header touched");
            }
        }
    }
    assert_eq!(b.count(Decision::Drop) + b.count(Decision::Ceiling) + b.count(Decision::Mark), 0);
}

#[test]
fn one_carrier_target_is_target_ms_at_capacity() {
    let b = settled(1000);
    assert_eq!(b.q1_target_bytes.get(), 8 * 1170);
    assert_eq!(b.q1_two_cc.get(), 0, "two-carrier mode boots off and needs a two-carrier grant");
}

#[test]
fn codel_waits_a_whole_interval_then_spaces_its_signals() {
    let b = settled(1000);
    let above = b.q1_target_bytes.get() + 4000;
    let mut signals = Vec::new();
    for t in 1001..1300 {
        if decide(&b, BIG, t, above, ONE_CARRIER, 40_000).is_drop() {
            signals.push(t);
        }
    }
    assert_eq!(signals.first(), Some(&1041), "first signal after the 40 ms interval");
    // Then interval / isqrt(n) after the n-th signal, in whole ms: n = 2, 3 -> 40, n = 4 -> 20.
    let gaps: Vec<u32> = signals.windows(2).map(|w| w[1] - w[0]).take(4).collect();
    assert_eq!(gaps, [40, 40, 40, 20], "integer square roots 1, 1, 2 of counts 2, 3, 4");
    assert_eq!(b.q1_codel_drops.get(), signals.len() as u32);
    // Under the target the dropping state ends at once.
    assert!(!decide(&b, BIG, 1300, b.q1_target_bytes.get(), ONE_CARRIER, 40_000).is_drop());
    assert_eq!(b.q1_codel_state.get(), 0);
}

#[test]
fn a_dropping_state_that_ended_recently_resumes_near_its_rate() {
    let b = settled(1000);
    let above = b.q1_target_bytes.get() + 4000;
    let mut t = 1001;
    while b.q1_count.get() < 9 {
        decide(&b, BIG, t, above, ONE_CARRIER, 40_000);
        t += 1;
    }
    decide(&b, BIG, t, 1000, ONE_CARRIER, 40_000);
    for t in t + 1..t + 200 {
        decide(&b, BIG, t, above, ONE_CARRIER, 40_000);
        if b.q1_codel_state.get() & 2 != 0 {
            break;
        }
    }
    assert!(b.q1_count.get() > 1, "count restarted at {}", b.q1_count.get());
}

#[test]
fn ecn_capable_packets_are_marked_by_codel() {
    let b = settled(1000);
    let above = b.q1_target_bytes.get() + 4000;
    let mut marks = 0;
    for t in 1001..1200 {
        let mut h = tcp(40_000, 2);
        match step(&b, arrival(BIG, t, above, ONE_CARRIER), &mut h) {
            Decision::Mark => {
                marks += 1;
                assert_eq!(h[1] & 3, 3);
            }
            d => assert!(!d.is_drop(), "ECT dropped below the ceiling"),
        }
    }
    assert!(marks > 0 && b.q1_codel_marks.get() > 0);
}

#[test]
fn the_floor_follows_the_flow_count_while_two_carriers_are_in_use() {
    let b = M1Block::new();
    assert_eq!(b.q1_floor(1), 32_000);
    assert_eq!(b.q1_floor(2), 24_000);
    assert_eq!(b.q1_floor(4), 18_000);
    assert_eq!(b.q1_floor(32), 16_000);
    assert_eq!(b.q1_floor(0), 32_000, "an empty window counts as one flow");

    // Two carriers: one flow for a window, then four.
    let now = |k: u32| 1000 + k * 5;
    for k in 0..40 {
        decide(&b, BIG, now(k), 5000, TWO_CARRIERS, 40_000);
    }
    assert_eq!((b.q1_two_cc.get(), b.q1_flows.get()), (1, 1));
    assert_eq!(b.q1_target_bytes.get(), 32_000);
    for k in 40..100 {
        decide(&b, BIG, now(k), 5000, TWO_CARRIERS, 40_000 + (k % 4) as u16);
    }
    assert_eq!(b.q1_flows.get(), 4);
    assert_eq!(b.q1_target_bytes.get(), 18_000.max(8 * 2200));

    // The carrier goes: the floor ends after the hold.
    let mut k = 100;
    while b.q1_two_cc.get() == 1 {
        decide(&b, BIG, now(k), 5000, ONE_CARRIER, 40_000);
        k += 1;
        assert!(now(k) < 1000 + 600 + 2000 + 100, "two-carrier mode outlived its hold");
    }
    assert!(b.q1_target_bytes.get() < 16_000);
}

#[test]
fn the_capacity_decays_toward_the_current_grant() {
    let b = M1Block::new();
    decide(&b, BIG, 1000, 0, TWO_CARRIERS, 40_000);
    assert_eq!(b.q1_capacity.get(), TWO_CARRIERS);
    let mut t = 1000;
    for _ in 0..400 {
        t += 15;
        decide(&b, BIG, t, 0, ONE_CARRIER, 40_000);
    }
    assert_eq!(b.q1_capacity.get(), ONE_CARRIER, "decays to the current EWMA, never below it");
}

#[test]
fn the_backstop_holds_traffic_that_ignores_codel() {
    // A sender that never backs off: 2x the one-carrier drain.
    let b = settled(1000);
    let (mut q, mut t, mut late) = (0u32, 1000u32, Vec::new());
    for ms in 0..4000u32 {
        t += 1;
        for k in 0..2 {
            if !decide(&b, BIG, t, q, ONE_CARRIER, 40_000 + k).is_drop() {
                q += BIG;
            }
        }
        if ms % 5 == 0 {
            q = q.saturating_sub(5 * 1170);
        }
        if ms > 2000 {
            late.push(q);
        }
    }
    late.sort_unstable();
    let p50_ms = late[late.len() / 2] / 1170;
    assert!(p50_ms <= 20, "queue p50 {p50_ms} ms");
    assert!(b.prob_q24.get() > P_SCALE / 5, "backstop p {}", b.prob_q24.get());
}

#[test]
fn the_periodic_update_runs_every_t_update_ms() {
    let b = M1Block::new();
    let mut ticks = 0;
    for t in 1000..1100 {
        let a = arrival(BIG, t, 1000, ONE_CARRIER);
        ticks += u32::from(b.q1_tick(&a));
        b.decide_q1(a, &mut tcp(40_000, 0));
    }
    // The first packet (an idle restart) and then every 15 ms.
    assert_eq!(ticks, 1 + 99 / 15);
}

#[test]
fn the_backstop_never_acts_at_or_under_the_target() {
    let b = settled(1000);
    b.prob_q24.set(P_SCALE);
    b.accu_q24.set(P_SCALE * 4);
    let target = b.q1_target_bytes.get();
    for t in 1001..1014 {
        assert_eq!(decide(&b, BIG, t, target, ONE_CARRIER, 40_000), Decision::Enqueue);
    }
    assert!(decide(&b, BIG, 1014, target + 4000, ONE_CARRIER, 40_000).is_drop());
}

/// Every selector-3 word, and the shared words selector 3 reads.
fn words(b: &M1Block) -> [&Word; 26] {
    [
        &b.q1_target_ms, &b.q1_interval_ms, &b.q1_floor_bytes, &b.q1_floor_one_bytes, &b.q1_two_cc_g_ema,
        &b.q1_two_cc_hold_ms, &b.q1_backstop_q8, &b.q1_capacity, &b.q1_two_cc_tti, &b.q1_flow_bits,
        &b.q1_flow_tti, &b.q1_flows, &b.q1_target_bytes, &b.q1_codel_state, &b.q1_first_above_tti,
        &b.q1_drop_next_tti, &b.q1_count, &b.q1_lastcount, &b.q1_two_cc, &b.t_update_ms, &b.mtu_bytes,
        &b.ul_subframes_per_frame, &b.min_rate_bpms, &b.ceiling_ms, &b.ceiling_floor_bytes, &b.prob_q24,
    ]
}

#[test]
fn every_tunable_and_state_word_is_safe_at_its_extremes() {
    for i in 0..words(&M1Block::new()).len() {
        for v in [0, 1, 2, 1 << 31, u32::MAX - 1, u32::MAX] {
            let b = M1Block::new();
            words(&b)[i].set(v);
            for (k, t) in [0, 1, 15, 16, 1000, 1001, u32::MAX - 20, u32::MAX, 3].into_iter().enumerate() {
                for queue in [0, 3000, 40_000, u32::MAX] {
                    for g in [0, ONE_CARRIER, u32::MAX] {
                        decide(&b, BIG, t, queue, g, 40_000 + k as u16);
                        decide(&b, 100, t, queue, g, 40_000);
                    }
                }
            }
        }
    }
}

#[test]
fn isqrt_is_the_floor_of_the_square_root_up_to_max_count() {
    for n in 0..=MAX_COUNT {
        let r = isqrt(n);
        assert!(r * r <= n && (r + 1) * (r + 1) > n, "isqrt({n}) = {r}");
    }
    assert_eq!(isqrt(u32::MAX), isqrt(MAX_COUNT), "clamped");
    assert_eq!(spacing(40, 0), 40);
    assert_eq!(spacing(40, 1), 40);
    assert_eq!(spacing(40, 4), 20);
    assert_eq!(spacing(40, MAX_COUNT), 1);
    assert_eq!(spacing(1, 100), 1, "never under 1 ms");
}

#[test]
fn flows_hash_on_addresses_and_ports() {
    let a = flow_bit(&tcp(40_000, 0));
    assert_eq!(a.count_ones(), 1);
    assert_eq!(a, flow_bit(&tcp(40_000, 2)), "the ECN bits are not part of the key");
    let four: u32 = (0..4).map(|k| flow_bit(&tcp(40_000 + k, 0))).fold(0, |x, y| x | y);
    assert_eq!(count(four), 4, "four consecutive source ports land in four buckets");
    assert_eq!(count(0), 1);
    assert_eq!(flow_bit(&[0x45; 10]), flow_bit(&[]), "a short header keys on nothing");
    let mut icmp = tcp(40_000, 0);
    icmp[9] = 1;
    let mut other = icmp;
    other[20] ^= 0xff;
    assert_eq!(flow_bit(&icmp), flow_bit(&other), "ICMP's first word is not a port");
}

#[test]
fn the_flow_window_is_a_tenth_of_a_second() {
    assert_eq!(FLOW_WINDOW_MS, 100);
}
