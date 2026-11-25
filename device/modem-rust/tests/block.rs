//! The control block is an ABI: the DM console, the keeper (lane R2) and the image
//! builder (lane R3) key on these offsets, defaults, magic and version.

use core::mem::{offset_of, size_of};

use witcher_modem_aqm::block::{M1Block, MAGIC, SELECTOR_MAX, SELECTOR_N4, SELECTOR_Q1, VERSION, Word};
use witcher_modem_aqm::pie::Decision;

type Accessor = fn(&M1Block) -> &Word;

/// Every single word: name, offset, boot value, accessor. (The 6 decision counters at
/// `0x64` are an array, checked separately.) M1's and R1's words keep their offsets and
/// defaults; lane Q1's fill `0xac..0x100`, which R1 left reserved and zero.
const ABI: [(&str, usize, u32, Accessor); 58] = [
    ("magic", 0x00, MAGIC, |b| &b.magic),
    ("version", 0x04, VERSION, |b| &b.version),
    ("selector", 0x08, SELECTOR_N4, |b| &b.selector),
    ("target_ms", 0x0c, 14, |b| &b.target_ms),
    ("t_update_ms", 0x10, 15, |b| &b.t_update_ms),
    ("max_burst_ms", 0x14, 55, |b| &b.max_burst_ms),
    ("alpha_q10", 0x18, 256, |b| &b.alpha_q10),
    ("beta_q10", 0x1c, 2560, |b| &b.beta_q10),
    ("min_rate_bpms", 0x20, 500, |b| &b.min_rate_bpms),
    ("ceiling_floor_bytes", 0x24, 50_000, |b| &b.ceiling_floor_bytes),
    ("ecn_max_prob_q24", 0x28, 1_677_722, |b| &b.ecn_max_prob_q24),
    ("mtu_bytes", 0x2c, 1380, |b| &b.mtu_bytes),
    ("flags", 0x30, 3, |b| &b.flags),
    ("drop_budget_q24", 0x34, 335_544, |b| &b.drop_budget_q24),
    ("ceiling_ms", 0x38, 50, |b| &b.ceiling_ms),
    ("ul_subframes_per_frame", 0x3c, 2, |b| &b.ul_subframes_per_frame),
    ("prob_q24", 0x40, 0, |b| &b.prob_q24),
    ("accu_q24", 0x44, 0, |b| &b.accu_q24),
    ("qdelay_us", 0x48, 0, |b| &b.qdelay_us),
    ("qdelay_old_us", 0x4c, 0, |b| &b.qdelay_old_us),
    ("burst_ms", 0x50, 55, |b| &b.burst_ms),
    ("last_update_tti", 0x54, 0, |b| &b.last_update_tti),
    ("rate_bpms", 0x58, 0, |b| &b.rate_bpms),
    ("rng", 0x5c, 0x1357_2468, |b| &b.rng),
    ("seen", 0x60, 0, |b| &b.seen),
    ("updates", 0x7c, 0, |b| &b.updates),
    ("max_qdelay_us", 0x80, 0, |b| &b.max_qdelay_us),
    ("max_prob_q24", 0x84, 0, |b| &b.max_prob_q24),
    ("bypassed", 0x88, 0, |b| &b.bypassed),
    ("rearms", 0x8c, 0, |b| &b.rearms),
    ("pdcp_hol_ms", 0x90, 0, |b| &b.pdcp_hol_ms),
    ("pdcp_max_hol_ms", 0x94, 0, |b| &b.pdcp_max_hol_ms),
    ("ceiling_burst_pkts", 0x98, 64, |b| &b.ceiling_burst_pkts),
    ("overload", 0x9c, 0, |b| &b.overload),
    ("tokens_q24", 0xa0, 64 << 24, |b| &b.tokens_q24),
    ("overloads", 0xa4, 0, |b| &b.overloads),
    ("overload_updates", 0xa8, 0, |b| &b.overload_updates),
    ("q1_target_ms", 0xac, 8, |b| &b.q1_target_ms),
    ("q1_interval_ms", 0xb0, 40, |b| &b.q1_interval_ms),
    ("q1_floor_bytes", 0xb4, 16_000, |b| &b.q1_floor_bytes),
    ("q1_floor_one_bytes", 0xb8, 32_000, |b| &b.q1_floor_one_bytes),
    ("q1_two_cc_g_ema", 0xbc, 8000, |b| &b.q1_two_cc_g_ema),
    ("q1_two_cc_hold_ms", 0xc0, 2000, |b| &b.q1_two_cc_hold_ms),
    ("q1_backstop_q8", 0xc4, 384, |b| &b.q1_backstop_q8),
    ("q1_capacity", 0xc8, 0, |b| &b.q1_capacity),
    ("q1_two_cc_tti", 0xcc, 0, |b| &b.q1_two_cc_tti),
    ("q1_flow_bits", 0xd0, 0, |b| &b.q1_flow_bits),
    ("q1_flow_tti", 0xd4, 0, |b| &b.q1_flow_tti),
    ("q1_flows", 0xd8, 1, |b| &b.q1_flows),
    ("q1_target_bytes", 0xdc, 0, |b| &b.q1_target_bytes),
    ("q1_codel_state", 0xe0, 0, |b| &b.q1_codel_state),
    ("q1_first_above_tti", 0xe4, 0, |b| &b.q1_first_above_tti),
    ("q1_drop_next_tti", 0xe8, 0, |b| &b.q1_drop_next_tti),
    ("q1_count", 0xec, 0, |b| &b.q1_count),
    ("q1_lastcount", 0xf0, 0, |b| &b.q1_lastcount),
    ("q1_codel_drops", 0xf4, 0, |b| &b.q1_codel_drops),
    ("q1_codel_marks", 0xf8, 0, |b| &b.q1_codel_marks),
    ("q1_two_cc", 0xfc, 0, |b| &b.q1_two_cc),
];

fn offset(block: &M1Block, word: &Word) -> usize {
    word as *const Word as usize - block as *const M1Block as usize
}

#[test]
fn every_word_sits_at_its_published_offset() {
    assert_eq!(size_of::<M1Block>(), 256);
    let block = M1Block::new();
    for (name, at, _, word) in ABI {
        assert_eq!(offset(&block, word(&block)), at, "{name}");
    }
    assert_eq!(offset_of!(M1Block, decisions), 0x64);
    // Every word is on the list once: 58 named words and the 6 counters fill the block.
    let mut offsets: Vec<usize> = ABI.iter().map(|w| w.1).collect();
    offsets.extend((0..6).map(|i| 0x64 + 4 * i));
    offsets.sort_unstable();
    assert_eq!(offsets, (0..64).map(|i| 4 * i).collect::<Vec<_>>());
}

#[test]
fn m1_counters_keep_their_offsets_as_one_array() {
    // Lane M1's layout (version 0x2026_1125) had six named counters here; the bench
    // scripts read them. The array is indexed by `Decision`.
    let d = offset_of!(M1Block, decisions);
    for (decision, m1_offset) in [
        (Decision::Enqueue, 0x64),     // c_pie_enq
        (Decision::Drop, 0x68),        // c_pie_drop
        (Decision::Mark, 0x6c),        // c_pie_mark
        (Decision::Ceiling, 0x70),     // c_pie_hard_drop
        (Decision::SparedSmall, 0x74), // c_pie_spared_small
        (Decision::SparedBurst, 0x78), // c_pie_spared_burst
    ] {
        assert_eq!(d + 4 * decision as usize, m1_offset, "{decision:?}");
    }
}

#[test]
fn boot_image_is_off_with_the_published_defaults() {
    let block = M1Block::new();
    for (name, at, boot, word) in ABI {
        assert_eq!(word(&block).get(), boot, "{name} at {at:#04x}");
    }
    assert!(block.decisions.iter().all(|w| w.get() == 0));
    assert_eq!(block.selector.get(), SELECTOR_N4, "must boot to N4 v2");
    assert_eq!(block.q1_two_cc.get(), 0, "two-carrier mode must boot off");
}

#[test]
fn selector_three_is_q1_and_the_largest_the_hook_acts_on() {
    assert_eq!(SELECTOR_Q1, 3);
    assert_eq!(SELECTOR_MAX, SELECTOR_Q1);
}

#[test]
fn identity_words_are_m1pi_and_a_new_version() {
    assert_eq!(MAGIC.to_be_bytes(), *b"M1PI");
    assert_eq!(VERSION, 0x2026_1127);
    for older in [0x2026_1125, 0x2026_1126] {
        assert_ne!(VERSION, older, "the layout changed, so the version must too");
    }
}
