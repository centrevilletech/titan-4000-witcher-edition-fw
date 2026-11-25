//! Per-flow sparse/bulk classifier, Ring-1 drain tracker, active-bulk collision immunity,
//! and global 100 ms Ring-0 promotion budget (`n5.s` Hook A).
//!
//! Optimized over `n5.s`:
//! - Defers `hold_ms` and `rate_bpms` loads until a path actually needs them (saving
//!   redundant loads on sparse-promotion and empty-slot paths).
//! - Avoids re-reading `entry.bulk_until` after clean-slot initialization.
//! - Uses `ldrd`/`strd` pairing naturally on adjacent counters and hold words.

#![forbid(unsafe_code)]

use modem_atlas::patches::{N5FlowEntry, N5State};

use crate::parse::{ParsedPacket, parse_and_hash};
use crate::state::{
    BUCKET_QUIET_RESET_MS, BUDGET_FLOOR_B, BUDGET_WINDOW_MS, DEFAULT_BUDGET_PCT, DEFAULT_BURST_B,
    DEFAULT_HOLD_MS, DEFAULT_R0_MAX_PKTS, DEFAULT_RATE_BPMS, default_nz,
};

/// Routing decision returned by [`classify_packet`].
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FlowDecision {
    /// Exit A (`0x847e_d53c`): stock `<= 127 B` Ring-0 path with `cmp r4, #127` flags.
    StockR0 = 0,
    /// Ring 1: Exit B (`0x847e_d52e`) if `pkt_len <= 127`, else N4 AQM (`0x847e_d414`).
    ToRing1 = 1,
    /// Exit C (`0x842d_a24a`): promote sparse packet directly into Ring 0 (`r2 = rbc.ring0`).
    Promote = 2,
}

/// Update per-bearer monotonic Ring-1 dequeue sequence and return `r1_occ`.
///
/// The updated monotonic sequence is stored in `st.r1_deq_seq[bearer_idx & 7]` and
/// loaded lazily only on bulk-hold or collision paths (freeing a register across parsing).
#[inline(always)]
pub fn update_r1_tracker<F1>(st: &mut N5State, bearer_idx: usize, read_ring1: F1) -> u32
where
    F1: FnOnce() -> Option<(u16, u16)>,
{
    let idx = bearer_idx & 7;
    let Some((raw_wr, raw_rd)) = read_ring1() else {
        return 0;
    };
    let cur_wr = (raw_wr & 0x0fff) as u32;
    let cur_rd = (raw_rd & 0x0fff) as u32;
    let r1_occ = cur_wr.wrapping_sub(cur_rd) & 0x0fff;
    let prev_rd = st.last_r1_rd[idx] as u32;
    let delta_deq = cur_rd.wrapping_sub(prev_rd) & 0x0fff;
    st.last_r1_rd[idx] = cur_rd as u16;
    st.r1_deq_seq[idx] = st.r1_deq_seq[idx].wrapping_add(delta_deq);
    r1_occ
}

/// Signed 32-bit comparison matching ARMv7 `subs r0, a, b; bge`.
#[inline(always)]
const fn signed_ge(a: u32, b: u32) -> bool {
    (a as i32) >= (b as i32)
}

/// Non-zero wrapping value matching `cmp #0; it eq; moveq #1`.
#[inline(always)]
const fn nonzero(v: u32) -> u32 {
    if v == 0 { 1 } else { v }
}

/// Initialize or cleanly evict a flow table bucket for `my_tag`.
#[inline(always)]
fn reset_slot(entry: &mut N5FlowEntry, my_tag: u16, now_tti: u32) {
    entry.tag = my_tag;
    entry.level = 0;
    entry.last_tti = now_tti;
    entry.bulk_until = 0;
    entry.r1_drain = 0;
}

/// Arm or refresh a flow bucket's bulk hold timer and Ring-1 drain target.
#[inline(always)]
fn refresh_bulk_r1(st: &mut N5State, bucket: usize, bidx: usize, now_tti: u32, r1_occ: u32) {
    let hold_ms = default_nz(st.hold_ms, DEFAULT_HOLD_MS);
    let cur_seq = st.r1_deq_seq[bidx];
    let entry = &mut st.flow_tbl[bucket];
    entry.bulk_until = nonzero(now_tti.wrapping_add(hold_ms));
    entry.r1_drain = nonzero(cur_seq.wrapping_add(r1_occ).wrapping_add(1));
}

/// Decay an entry's leaky-bucket byte level according to elapsed time and `rate_bpms`.
#[inline(always)]
fn decay_level(entry: &N5FlowEntry, now_tti: u32, rate_bpms: u32) -> u32 {
    let dt = now_tti.wrapping_sub(entry.last_tti);
    if dt >= BUCKET_QUIET_RESET_MS {
        return 0;
    }
    let rate = default_nz(rate_bpms, DEFAULT_RATE_BPMS);
    let drain = dt.wrapping_mul(rate);
    (entry.level as u32).saturating_sub(drain)
}

/// Execute N5 Hook A (`n5_flow_classify`) when `N5_FLAGS & 1 != 0`.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn classify_packet<F1, F0, FG>(
    st: &mut N5State,
    bearer_idx: u8,
    read_ring1: F1,
    ip: &[u8],
    pkt_len: u32,
    now_tti: u32,
    read_ring0_occ: F0,
    read_g_ema: FG,
) -> FlowDecision
where
    F1: FnOnce() -> Option<(u16, u16)>,
    F0: FnOnce() -> Option<u32>,
    FG: FnOnce() -> u32,
{
    st.c_seen = st.c_seen.wrapping_add(1);

    let bidx = (bearer_idx & 7) as usize;
    let r1_occ = update_r1_tracker(st, bidx, read_ring1);

    let (hash, is_first_frag) = match parse_and_hash(ip, pkt_len, bidx as u32) {
        ParsedPacket::BadHdr => {
            st.c_bad_hdr = st.c_bad_hdr.wrapping_add(1);
            return FlowDecision::ToRing1;
        }
        ParsedPacket::StockR0 => {
            st.c_stock_r0 = st.c_stock_r0.wrapping_add(1);
            return FlowDecision::StockR0;
        }
        ParsedPacket::Flow {
            hash,
            is_first_frag,
        } => (hash, is_first_frag),
    };

    let bucket = (hash & 63) as usize;
    let raw_tag = ((hash >> 6) & 0xffff) as u16;
    let my_tag = if raw_tag == 0 { 1 } else { raw_tag };

    // Step 3: Flow table lookup, collision handling, and leaky-bucket decay.
    let e_tag = st.flow_tbl[bucket].tag;
    let (level, bulk_until) = if e_tag == my_tag {
        let rate_bpms = st.rate_bpms;
        let lvl = decay_level(&st.flow_tbl[bucket], now_tti, rate_bpms);
        (lvl, st.flow_tbl[bucket].bulk_until)
    } else if e_tag == 0 {
        reset_slot(&mut st.flow_tbl[bucket], my_tag, now_tti);
        (0, 0)
    } else {
        // Hash bucket collision: never evict an active or undrained bulk flow.
        st.c_evictions = st.c_evictions.wrapping_add(1);
        let e_bulk_until = st.flow_tbl[bucket].bulk_until;
        if e_bulk_until != 0 {
            let e_r1_drain = st.flow_tbl[bucket].r1_drain;
            if e_r1_drain != 0 && r1_occ != 0 && !signed_ge(st.r1_deq_seq[bidx], e_r1_drain) {
                st.c_r1_nonempty_hold = st.c_r1_nonempty_hold.wrapping_add(1);
                st.c_held_bulk = st.c_held_bulk.wrapping_add(1);
                return FlowDecision::ToRing1;
            }
            if !signed_ge(now_tti, e_bulk_until) {
                st.c_held_bulk = st.c_held_bulk.wrapping_add(1);
                return FlowDecision::ToRing1;
            }
            // Expired & drained bulk entry -> clean evict.
            reset_slot(&mut st.flow_tbl[bucket], my_tag, now_tti);
            (0, 0)
        } else {
            // Existing entry is sparse: clean evict if quiet >= hold_ms, else preserve decayed level.
            let hold_ms = default_nz(st.hold_ms, DEFAULT_HOLD_MS);
            let dt = now_tti.wrapping_sub(st.flow_tbl[bucket].last_tti);
            if dt >= hold_ms {
                reset_slot(&mut st.flow_tbl[bucket], my_tag, now_tti);
                (0, 0)
            } else {
                let rate_bpms = st.rate_bpms;
                st.flow_tbl[bucket].tag = my_tag;
                (decay_level(&st.flow_tbl[bucket], now_tti, rate_bpms), 0)
            }
        }
    };

    // Charge every packet of every size into the bucket (saturate at 65,535).
    let new_level = level.wrapping_add(pkt_len).min(0xffff);
    st.flow_tbl[bucket].level = new_level as u16;
    st.flow_tbl[bucket].last_tti = now_tti;

    // First IPv4 fragment must stay in Ring 1 and mark the flow bulk.
    if is_first_frag {
        st.c_marked_bulk = st.c_marked_bulk.wrapping_add(1);
        refresh_bulk_r1(st, bucket, bidx, now_tti, r1_occ);
        return FlowDecision::ToRing1;
    }

    // Check existing bulk hold / Ring-1 drain guard (skip memory reload when already known 0).
    if bulk_until != 0 {
        let e_r1_drain = st.flow_tbl[bucket].r1_drain;
        if e_r1_drain != 0 {
            if r1_occ != 0 && !signed_ge(st.r1_deq_seq[bidx], e_r1_drain) {
                st.c_r1_nonempty_hold = st.c_r1_nonempty_hold.wrapping_add(1);
                st.c_held_bulk = st.c_held_bulk.wrapping_add(1);
                refresh_bulk_r1(st, bucket, bidx, now_tti, r1_occ);
                return FlowDecision::ToRing1;
            }
            st.flow_tbl[bucket].r1_drain = 0;
        }
        if !signed_ge(now_tti, bulk_until) {
            st.c_held_bulk = st.c_held_bulk.wrapping_add(1);
            refresh_bulk_r1(st, bucket, bidx, now_tti, r1_occ);
            return FlowDecision::ToRing1;
        }
        st.flow_tbl[bucket].bulk_until = 0;
    }

    // Compare new_level against sparse burst allowance.
    let burst_b = default_nz(st.burst_b, DEFAULT_BURST_B);
    if new_level > burst_b {
        st.c_marked_bulk = st.c_marked_bulk.wrapping_add(1);
        refresh_bulk_r1(st, bucket, bidx, now_tti, r1_occ);
        return FlowDecision::ToRing1;
    }

    // Step 4: Sparse flow! Check Ring-0 occupancy and global 100 ms byte budget.
    let r0_max = default_nz(st.r0_max_pkts, DEFAULT_R0_MAX_PKTS);
    let r0_ok = match read_ring0_occ() {
        Some(cnt) => cnt < r0_max,
        None => false,
    };
    if !r0_ok {
        st.c_refused_bud = st.c_refused_bud.wrapping_add(1);
        refresh_bulk_r1(st, bucket, bidx, now_tti, r1_occ);
        return FlowDecision::ToRing1;
    }

    if now_tti.wrapping_sub(st.bud_win_tti) >= BUDGET_WINDOW_MS {
        st.bud_win_tti = now_tti;
        st.bud_used = 0;
    }

    let cap = if st.budget_fixed != 0 {
        st.budget_fixed
    } else {
        let g_fifth = read_g_ema().wrapping_mul(13_107) >> 16;
        let pct = default_nz(st.budget_pct, DEFAULT_BUDGET_PCT);
        g_fifth.wrapping_mul(pct).max(BUDGET_FLOOR_B)
    };
    st.last_bud_cap = cap;

    let used_next = st.bud_used.wrapping_add(pkt_len);
    if used_next > cap {
        st.c_refused_bud = st.c_refused_bud.wrapping_add(1);
        refresh_bulk_r1(st, bucket, bidx, now_tti, r1_occ);
        return FlowDecision::ToRing1;
    }

    st.bud_used = used_next;
    st.c_promo_pkts = st.c_promo_pkts.wrapping_add(1);
    st.c_promo_bytes = st.c_promo_bytes.wrapping_add(pkt_len);
    FlowDecision::Promote
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::boot_n5_state;

    fn udp_ipv4(src: u32, dst: u32, sport: u16, dport: u16, len: u16) -> Vec<u8> {
        let mut buf = vec![0u8; len as usize];
        buf[0] = 0x45;
        buf[2..4].copy_from_slice(&len.to_be_bytes());
        buf[9] = 17;
        buf[12..16].copy_from_slice(&src.to_be_bytes());
        buf[16..20].copy_from_slice(&dst.to_be_bytes());
        buf[20..22].copy_from_slice(&sport.to_be_bytes());
        buf[22..24].copy_from_slice(&dport.to_be_bytes());
        buf
    }

    #[test]
    fn sparse_promotes_and_bulk_holds_until_r1_drains_and_hold_expires() {
        let mut st = boot_n5_state();
        st.flags = 1;

        let p_big = udp_ipv4(0x0a00_0020, 0xc000_0202, 42000, 443, 1300);
        assert_eq!(
            classify_packet(&mut st, 0, || Some((10, 0)), &p_big, 1300, 1000, || Some(0), || 9062),
            FlowDecision::Promote
        );
        assert_eq!(
            classify_packet(&mut st, 0, || Some((10, 0)), &p_big, 1300, 1001, || Some(0), || 9062),
            FlowDecision::Promote
        );
        assert_eq!(
            classify_packet(&mut st, 0, || Some((10, 0)), &p_big, 1300, 1002, || Some(0), || 9062),
            FlowDecision::ToRing1
        );
        assert_eq!(st.c_marked_bulk, 1);

        let p_small = udp_ipv4(0x0a00_0020, 0xc000_0202, 42000, 443, 200);
        assert_eq!(
            classify_packet(&mut st, 0, || Some((11, 5)), &p_small, 200, 1605, || Some(0), || 9062),
            FlowDecision::ToRing1
        );
        assert_eq!(st.c_r1_nonempty_hold, 1);

        assert_eq!(
            classify_packet(&mut st, 0, || Some((50, 33)), &p_small, 200, 2200, || Some(0), || 9062),
            FlowDecision::Promote
        );
    }

    #[test]
    fn budget_refusal_arms_bulk_hold_to_prevent_reordering() {
        let mut st = boot_n5_state();
        st.flags = 1;
        st.budget_fixed = 500;
        let p600 = udp_ipv4(0x0a00_0001, 0x0101_0101, 10000, 443, 600);
        assert_eq!(
            classify_packet(&mut st, 0, || Some((0, 0)), &p600, 600, 1000, || Some(0), || 9000),
            FlowDecision::ToRing1
        );
        assert_eq!(st.c_refused_bud, 1);

        st.budget_fixed = 100_000;
        let p100 = udp_ipv4(0x0a00_0001, 0x0101_0101, 10000, 443, 100);
        assert_eq!(
            classify_packet(&mut st, 0, || Some((0, 0)), &p100, 100, 1150, || Some(0), || 9000),
            FlowDecision::ToRing1
        );
        assert_eq!(st.c_held_bulk, 1);
    }
}
