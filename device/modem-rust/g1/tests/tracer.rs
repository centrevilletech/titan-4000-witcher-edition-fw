use core::mem::{offset_of, size_of};

use modem_atlas::mac::{MAC_LCID_LONG_BSR, MAC_LCID_SHORT_BSR, MAC_LCID_TRUNCATED_BSR};
use witcher_modem_g1::block::{
    AF_ALLOW_UNSEEN, AF_BOTH_STALL, AF_PCELL_DROP, AF_SCELL_DROP, ENABLE_ON, FREEZE_BOTH_STALL,
    FREEZE_NONE, FREEZE_PCELL_DROP, FREEZE_SCELL_DROP, G1Block, MAGIC, NewTxEvent, RECORD_SIZE,
    RING_BASE, RING_MASK, RING_SLOTS, RetxEvent, SrEvent, TtiEndInput, VERSION,
};
use witcher_modem_g1::record::{BsrFormat, EventKind, PhrSample, TraceRecord};

#[test]
fn layout_and_boot_defaults() {
    assert_eq!(size_of::<TraceRecord>(), 32);
    assert_eq!(offset_of!(TraceRecord, tti_ms), 0x00);
    assert_eq!(offset_of!(TraceRecord, air_sti), 0x04);
    assert_eq!(offset_of!(TraceRecord, flags0), 0x06);
    assert_eq!(offset_of!(TraceRecord, flags1), 0x07);
    assert_eq!(offset_of!(TraceRecord, tbs_bytes), 0x08);
    assert_eq!(offset_of!(TraceRecord, used_or_retx), 0x0a);
    assert_eq!(offset_of!(TraceRecord, bsr_trig), 0x0c);
    assert_eq!(offset_of!(TraceRecord, bsr_ce), 0x0d);
    assert_eq!(offset_of!(TraceRecord, phr_cc0_ph_v), 0x10);
    assert_eq!(offset_of!(TraceRecord, phr_cc0_pcmax), 0x11);
    assert_eq!(offset_of!(TraceRecord, phr_cc1_ph_v), 0x12);
    assert_eq!(offset_of!(TraceRecord, phr_cc1_pcmax), 0x13);
    assert_eq!(offset_of!(TraceRecord, ring1_bytes), 0x14);
    assert_eq!(offset_of!(TraceRecord, rlc_bo_bytes), 0x18);
    assert_eq!(offset_of!(TraceRecord, seq), 0x1c);

    assert_eq!(size_of::<G1Block>(), 128);
    assert_eq!(offset_of!(G1Block, magic), 0x00);
    assert_eq!(offset_of!(G1Block, version), 0x04);
    assert_eq!(offset_of!(G1Block, enable), 0x08);
    assert_eq!(offset_of!(G1Block, freeze), 0x0c);
    assert_eq!(offset_of!(G1Block, ring_base), 0x10);
    assert_eq!(offset_of!(G1Block, ring_slots), 0x14);
    assert_eq!(offset_of!(G1Block, record_size), 0x18);
    assert_eq!(offset_of!(G1Block, wr_idx), 0x1c);
    assert_eq!(offset_of!(G1Block, af_mode), 0x20);
    assert_eq!(offset_of!(G1Block, snap_ce_buf), 0x68);
    assert_eq!(offset_of!(G1Block, snap_bsr_trig), 0x6c);
    assert_eq!(offset_of!(G1Block, snap_phr_evt), 0x70);

    let blk = G1Block::boot_default();
    assert_eq!(blk.magic, MAGIC);
    assert_eq!(blk.version, VERSION);
    assert_eq!(blk.enable, 0);
    assert_eq!(blk.freeze, FREEZE_NONE);
    assert_eq!(blk.af_mode, 0);
    assert_eq!(blk.ring_base, RING_BASE);
    assert_eq!(blk.ring_slots, RING_SLOTS);
    assert_eq!(blk.record_size, RECORD_SIZE);
    assert!(!blk.is_recording());
}

#[test]
fn enable_unknown_values_and_freeze_stop_recording() {
    let mut blk = G1Block::boot_default();
    let sample = NewTxEvent {
        tti_ms: 1000,
        air_sti: 5002,
        cc: 0,
        hq_id: 0,
        ext_bsr_mode: false,
        ce_mask: 0x02,
        has_trailing_pad: false,
        bsr_lcid: MAC_LCID_SHORT_BSR,
        bsr_is_padding: false,
        tbs_bytes: 6792,
        used_bytes: 6792,
        bsr_ce: [0xf5, 0, 0],
        phr_cc0: PhrSample::ABSENT,
        phr_cc1: PhrSample::ABSENT,
        ring1_bytes: 20_000,
        rlc_bo_bytes: 4_000,
    };

    // Boot default (0) and any unknown values mean off.
    for val in [0u32, 2, 3, 7, 0xffff_ffff] {
        blk.enable = val;
        assert!(!blk.is_recording());
        assert!(blk.record_newtx(sample).is_none());
        assert_eq!(blk.wr_idx, 0);
    }

    blk.enable = ENABLE_ON;
    assert!(blk.is_recording());
    let (slot, rec) = blk.record_newtx(sample).expect("recorded");
    assert_eq!(slot, 0);
    assert_eq!(rec.seq, 0);
    assert_eq!(blk.wr_idx, 1);

    // Freeze stops further writes.
    blk.freeze = 1;
    assert!(!blk.is_recording());
    assert!(blk.record_newtx(sample).is_none());
    assert_eq!(blk.wr_idx, 1);
}

#[test]
fn newtx_retx_sr_record_packing_and_wrap() {
    let mut blk = G1Block::boot_default();
    blk.enable = ENABLE_ON;
    blk.snap_bsr_trig = 0x12; // Regular BSR
    blk.snap_phr_evt = 0x01;

    let (slot0, r0) = blk
        .record_newtx(NewTxEvent {
            tti_ms: 5005,
            air_sti: 1237,
            cc: 1,
            hq_id: 1,
            ext_bsr_mode: true,
            ce_mask: 0x0a, // BSR + ExtPHR
            has_trailing_pad: true,
            bsr_lcid: MAC_LCID_LONG_BSR,
            bsr_is_padding: false,
            tbs_bytes: 6792,
            used_bytes: 5356,
            bsr_ce: [0x00, 0x00, 0x2a],
            phr_cc0: PhrSample {
                active: true,
                virtual_phr: false,
                ph: 38,
                pcmax: 53,
            },
            phr_cc1: PhrSample {
                active: true,
                virtual_phr: true,
                ph: 41,
                pcmax: 0xff,
            },
            ring1_bytes: 18_000,
            rlc_bo_bytes: 2_416,
        })
        .unwrap();
    assert_eq!(slot0, 0);
    assert_eq!(r0.kind(), EventKind::NewTx as u8);
    assert_eq!(r0.cc(), 1);
    assert_eq!(r0.hq_id(), 1);
    assert!(r0.ext_bsr());
    assert_eq!(r0.flags1 & 0x1f, 0x0a);
    assert_eq!((r0.flags1 >> 5) & 1, 1);
    assert_eq!((r0.flags1 >> 6) & 3, BsrFormat::Long as u8);
    assert_eq!(r0.tbs_bytes, 6792);
    assert_eq!(r0.used_or_retx, 5356);
    assert_eq!(r0.bsr_trig, 0x52); // 0x12 | (1 << 6)
    assert_eq!(r0.bsr_ce, [0x00, 0x00, 0x2a]);
    assert_eq!(r0.phr_cc0_ph_v, 0x80 | 38);
    assert_eq!(r0.phr_cc0_pcmax, 53);
    assert_eq!(r0.phr_cc1_ph_v, 0x80 | 0x40 | 41);
    assert_eq!(r0.phr_cc1_pcmax, 0xff);
    // Regular PHR carries no Pcmax,c: sentinel 0xff must stay 0xff (not masked to 0x3f).
    let reg_phr = PhrSample {
        active: true,
        virtual_phr: false,
        ph: 25,
        pcmax: 0xff,
    };
    assert_eq!(reg_phr.pack_ph_v(), 0x80 | 25);
    assert_eq!(reg_phr.pack_pcmax(), 0xff);
    assert_eq!(blk.cnt_newtx_cc1, 1);
    assert_eq!(blk.cnt_bsr, 1);
    assert_eq!(blk.cnt_phr, 1);

    let (slot1, r1) = blk
        .record_retx(RetxEvent {
            tti_ms: 5015,
            air_sti: 1247,
            cc: 0,
            hq_id: 1,
            adaptive: false,
            tbs_bytes: 6792,
            mcs: 24,
            tx_nb: 2,
            rv: 3,
            ring1_bytes: 19_000,
            rlc_bo_bytes: 3_000,
        })
        .unwrap();
    assert_eq!(slot1, 1);
    assert_eq!(r1.kind(), EventKind::NonAdaptRetx as u8);
    assert_eq!(r1.used_or_retx, TraceRecord::pack_retx_meta(24, 2, 3));
    assert_eq!(blk.cnt_retx, 1);

    let (slot2, r2) = blk
        .record_sr(SrEvent {
            tti_ms: 5020,
            air_sti: 1252,
            sr_counter: 1,
            bsr_trigger_mask: 0x12,
            ring1_bytes: 1_500,
            rlc_bo_bytes: 0,
        })
        .unwrap();
    assert_eq!(slot2, 2);
    assert_eq!(r2.kind(), EventKind::PucchSr as u8);
    assert_eq!(r2.tbs_bytes, 1);
    assert_eq!(blk.cnt_sr, 1);

    // Wrap around at RING_SLOTS.
    blk.wr_idx = RING_SLOTS + 5;
    let (slot_w, rw) = blk
        .record_sr(SrEvent {
            tti_ms: 9999,
            air_sti: 0,
            sr_counter: 2,
            bsr_trigger_mask: 0x14,
            ring1_bytes: 0,
            rlc_bo_bytes: 0,
        })
        .unwrap();
    assert_eq!(slot_w, (5 & RING_MASK) as usize);
    assert_eq!(rw.seq, RING_SLOTS + 5);
    assert_eq!(BsrFormat::from_lcid(MAC_LCID_TRUNCATED_BSR), BsrFormat::Truncated);
}

#[test]
fn autofreeze_scell_drop_with_post_tail() {
    let mut blk = G1Block::boot_default();
    blk.enable = ENABLE_ON;
    blk.af_mode = AF_SCELL_DROP | AF_PCELL_DROP;
    blk.af_tti_thresh = 3;
    blk.af_bo_thresh = 16_000;
    blk.af_post_events = 2;

    // First, SCell has never been seen -> PCell-only grants must NOT trigger.
    for i in 0..5 {
        blk.on_tti_end(TtiEndInput {
            tti_ms: 100 + i * 5,
            air_sti: (100 + i * 5) as u16,
            hq0: 0,
            hq1: 0xff,
            ul_ca_configured: true,
            ring1_bytes: 20_000,
            rlc_bo_bytes: 4_000,
        });
    }
    assert_eq!(blk.freeze, FREEZE_NONE);
    assert_eq!(blk.af_trigger_reason, FREEZE_NONE);

    // Now both CCs active -> SCell seen!
    blk.on_tti_end(TtiEndInput {
        tti_ms: 130,
        air_sti: 130,
        hq0: 0,
        hq1: 0,
        ul_ca_configured: true,
        ring1_bytes: 20_000,
        rlc_bo_bytes: 4_000,
    });
    assert_eq!(blk.cc_seen_mask, 3);

    // SCell drops for 3 consecutive grant-TTIs while BO >= 16 KB.
    for i in 1..=3 {
        blk.on_tti_end(TtiEndInput {
            tti_ms: 130 + i * 5,
            air_sti: (130 + i * 5) as u16,
            hq0: 1,
            hq1: 0xff,
            ul_ca_configured: true,
            ring1_bytes: 20_000,
            rlc_bo_bytes: 4_000,
        });
    }
    assert_eq!(blk.af_trigger_reason, FREEZE_SCELL_DROP);
    assert_eq!(blk.af_post_countdown, 2);
    assert_eq!(blk.freeze, FREEZE_NONE);

    // Record 2 post-trigger events; 2nd event latches freeze!
    let sr = SrEvent {
        tti_ms: 150,
        air_sti: 150,
        sr_counter: 1,
        bsr_trigger_mask: 0x12,
        ring1_bytes: 20_000,
        rlc_bo_bytes: 4_000,
    };
    assert!(blk.record_sr(sr).is_some());
    assert_eq!(blk.freeze, FREEZE_NONE);
    assert!(blk.record_sr(sr).is_some());
    assert_eq!(blk.freeze, FREEZE_SCELL_DROP);
    assert!(blk.record_sr(sr).is_none());
}

#[test]
fn autofreeze_pcell_drop_and_both_stall() {
    // PCell drop with immediate freeze (`af_post_events = 0`).
    let mut blk = G1Block::boot_default();
    blk.enable = ENABLE_ON;
    blk.af_mode = AF_PCELL_DROP | AF_ALLOW_UNSEEN;
    blk.af_tti_thresh = 2;
    blk.af_bo_thresh = 10_000;
    blk.af_post_events = 0;

    for i in 0..2 {
        blk.on_tti_end(TtiEndInput {
            tti_ms: 200 + i * 5,
            air_sti: (200 + i * 5) as u16,
            hq0: 0xff,
            hq1: 0,
            ul_ca_configured: true,
            ring1_bytes: 12_000,
            rlc_bo_bytes: 0,
        });
    }
    assert_eq!(blk.freeze, FREEZE_PCELL_DROP);

    // Both-CC stall (`af_tti_thresh * 5` ms with no grant on either CC).
    let mut blk2 = G1Block::boot_default();
    blk2.enable = ENABLE_ON;
    blk2.af_mode = AF_BOTH_STALL;
    blk2.af_tti_thresh = 4; // 20 ms
    blk2.af_bo_thresh = 8_000;
    blk2.af_post_events = 0;
    blk2.on_tti_end(TtiEndInput {
        tti_ms: 1000,
        air_sti: 1000,
        hq0: 0,
        hq1: 0xff,
        ul_ca_configured: true,
        ring1_bytes: 10_000,
        rlc_bo_bytes: 0,
    });
    blk2.on_tti_end(TtiEndInput {
        tti_ms: 1019,
        air_sti: 1019,
        hq0: 0xff,
        hq1: 0xff,
        ul_ca_configured: true,
        ring1_bytes: 10_000,
        rlc_bo_bytes: 0,
    });
    assert_eq!(blk2.freeze, FREEZE_NONE);
    blk2.on_tti_end(TtiEndInput {
        tti_ms: 1020,
        air_sti: 1020,
        hq0: 0xff,
        hq1: 0xff,
        ul_ca_configured: true,
        ring1_bytes: 10_000,
        rlc_bo_bytes: 0,
    });
    assert_eq!(blk2.freeze, FREEZE_BOTH_STALL);
}
