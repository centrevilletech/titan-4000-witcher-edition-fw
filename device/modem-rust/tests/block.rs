//! The control block is an ABI: the DM console, the keeper (lane R2) and the image
//! builder (lane R3) key on these offsets, defaults, magic and version.

use core::mem::{offset_of, size_of};

use witcher_modem_aqm::block::{M1Block, MAGIC, SELECTOR_N4, VERSION, Word};
use witcher_modem_aqm::pie::Decision;

type Accessor = fn(&M1Block) -> &Word;

/// Every single word: name, offset, boot value, accessor. (The 6 decision counters at
/// `0x64` and the 21 reserved words at `0xac` are arrays, checked separately.)
const ABI: [(&str, usize, u32, Accessor); 37] = [
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
    assert_eq!(offset_of!(M1Block, reserved), 0xac);
    assert_eq!(size_of::<[Word; 21]>(), 0x100 - 0xac);
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
    assert!(block.reserved.iter().all(|w| w.get() == 0));
    assert_eq!(block.selector.get(), SELECTOR_N4, "must boot to N4 v2");
}

#[test]
fn identity_words_are_m1pi_and_a_new_version() {
    assert_eq!(MAGIC.to_be_bytes(), *b"M1PI");
    assert_ne!(VERSION, 0x2026_1125, "the layout changed, so the version must too");
}
