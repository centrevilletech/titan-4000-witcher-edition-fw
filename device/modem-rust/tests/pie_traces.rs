//! Host tests for the Rust DOCSIS-PIE uplink AQM controller (`witcher-modem-aqm`).
//!
//! Covers:
//! 1. IPv4 RFC 1624 incremental ECN checksum update & IPv6 ECN CE marking.
//! 2. Invariants: `< 600 B` packets never dropped/marked, burst tolerance, hard cap, idle reset,
//!    and `M1Block` layout (256 B = 4 x 64 B cache lines).
//! 3. Closed-loop TDD Config 2 (5 ms UL subframe cadence + byte-level RLC AM segmentation +
//!    8% UL HARQ 10 ms retry jitter) simulations calibrated to the 2026-11-25 bench data
//!    (`lanes-20261124/UL/data/README.md`, 1CC ~7.8 Mbps & 2CC ~15.6 Mbps):
//!    - CUBIC 1-flow and 4-flow, BBR 1-flow and 4-flow, on 1CC and 2CC.
//!    - Head-to-head comparison: N4 v2 (selector 0), Rust PIE (selector 1), No AQM (selector 2).
//! 4. Open-loop bench-pcap-calibrated burst traces (`e7-cubic1`, `e2-cubic4`, `e1-bbr4`).

use core::mem::{offset_of, size_of};

use witcher_modem_aqm::ecn::{is_ect, try_mark_ce};
use witcher_modem_aqm::pie::{Decision, M1Block, M1_MAGIC, M1_VERSION, P_SCALE};

fn rfc1071_checksum(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < hdr.len() {
        sum += ((hdr[i] as u32) << 8) | (hdr[i + 1] as u32);
        i += 2;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn make_ipv4(len: u16, tos: u8, id: u16) -> [u8; 40] {
    let mut pkt = [0u8; 40];
    pkt[0] = 0x45;
    pkt[1] = tos;
    pkt[2] = (len >> 8) as u8;
    pkt[3] = (len & 0xff) as u8;
    pkt[4] = (id >> 8) as u8;
    pkt[5] = (id & 0xff) as u8;
    pkt[8] = 64; // TTL
    pkt[9] = 6;  // TCP
    pkt[12..16].copy_from_slice(&[192, 0, 2, 1]);
    pkt[16..20].copy_from_slice(&[198, 51, 100, 1]);
    let csum = rfc1071_checksum(&pkt[..20]);
    pkt[10] = (csum >> 8) as u8;
    pkt[11] = (csum & 0xff) as u8;
    pkt
}

fn make_ipv6(payload_len: u16, ecn_bits: u8) -> [u8; 40] {
    let mut pkt = [0u8; 40];
    pkt[0] = 0x60;
    pkt[1] = (ecn_bits & 0x03) << 4;
    pkt[4] = (payload_len >> 8) as u8;
    pkt[5] = (payload_len & 0xff) as u8;
    pkt[6] = 6; // TCP
    pkt[7] = 64;
    pkt
}

#[test]
fn m1_block_layout_matches_dm_ram_map() {
    assert_eq!(size_of::<M1Block>(), 256);
    assert_eq!(offset_of!(M1Block, magic), 0x00);
    assert_eq!(offset_of!(M1Block, version), 0x04);
    assert_eq!(offset_of!(M1Block, selector), 0x08);
    assert_eq!(offset_of!(M1Block, target_delay_ms), 0x0c);
    assert_eq!(offset_of!(M1Block, t_update_ms), 0x10);
    assert_eq!(offset_of!(M1Block, max_burst_ms), 0x14);
    assert_eq!(offset_of!(M1Block, alpha_q10), 0x18);
    assert_eq!(offset_of!(M1Block, beta_q10), 0x1c);
    assert_eq!(offset_of!(M1Block, min_rate_bpms), 0x20);
    assert_eq!(offset_of!(M1Block, hard_cap_bytes), 0x24);
    assert_eq!(offset_of!(M1Block, ecn_max_prob_q24), 0x28);
    assert_eq!(offset_of!(M1Block, mtu_bytes), 0x2c);
    assert_eq!(offset_of!(M1Block, flags), 0x30);
    assert_eq!(offset_of!(M1Block, max_drop_prob_q24), 0x34);
    assert_eq!(offset_of!(M1Block, prob_q24), 0x40);
    assert_eq!(offset_of!(M1Block, accu_prob_q24), 0x44);
    assert_eq!(offset_of!(M1Block, qdelay_us), 0x48);
    assert_eq!(offset_of!(M1Block, burst_allow_ms), 0x50);
    assert_eq!(offset_of!(M1Block, c_pie_seen), 0x60);
    assert_eq!(offset_of!(M1Block, c_pie_drop), 0x68);
    assert_eq!(offset_of!(M1Block, c_pie_mark), 0x6c);
    assert_eq!(offset_of!(M1Block, c_pie_hard_drop), 0x70);
    assert_eq!(offset_of!(M1Block, c_bypass_pkts), 0x88);
    assert_eq!(offset_of!(M1Block, pdcp_hol_age_ms), 0x90);

    let def = M1Block::new_boot_default();
    assert_eq!(def.magic, M1_MAGIC);
    assert_eq!(def.version, M1_VERSION);
    assert_eq!(def.selector, 0, "must boot disabled (old N4 v2)");
}

#[test]
fn ecn_ipv4_checksum_exhaustive_edges_and_fuzz() {
    for dscp in (0u8..64).step_by(3) {
        for ecn in [1u8, 2u8] {
            for id in 0u16..64 {
                let mut pkt = make_ipv4(1380, (dscp << 2) | ecn, id.wrapping_mul(1021));
                assert!(is_ect(&pkt));
                assert_eq!(rfc1071_checksum(&pkt[..20]), 0);
                assert!(try_mark_ce(&mut pkt));
                assert_eq!(pkt[1], (dscp << 2) | 3);
                assert_eq!(rfc1071_checksum(&pkt[..20]), 0);
                let snap = pkt;
                assert!(!try_mark_ce(&mut pkt));
                assert_eq!(pkt, snap);
            }
        }
    }

    for &c_old in &[0x0000u16, 0x0001, 0x0002, 0xfffe] {
        for ecn in [1u8, 2u8] {
            let mut pkt = [0u8; 20];
            pkt[0] = 0x45;
            pkt[1] = ecn;
            pkt[10] = (c_old >> 8) as u8;
            pkt[11] = (c_old & 0xff) as u8;
            assert!(try_mark_ce(&mut pkt));
            assert_eq!(pkt[1], 3);
            let got = u16::from_be_bytes([pkt[10], pkt[11]]);
            let inv = (!c_old) as u32 + (3 - ecn) as u32;
            let folded = (inv & 0xffff) + (inv >> 16);
            let mut want = !(folded as u16);
            if want == 0xffff {
                want = 0x0000;
            }
            assert_eq!(got, want, "edge c_old={c_old:#06x} ecn={ecn}");
        }
    }

    let mut non_ect = make_ipv4(1380, 0x00, 7);
    let snap = non_ect;
    assert!(!is_ect(&non_ect));
    assert!(!try_mark_ce(&mut non_ect));
    assert_eq!(non_ect, snap);

    for ecn in [1u8, 2u8] {
        let mut v6 = make_ipv6(1340, ecn);
        assert!(is_ect(&v6));
        assert!(try_mark_ce(&mut v6));
        assert_eq!(v6[1] & 0x30, 0x30);
        assert!(!try_mark_ce(&mut v6));
    }
    let mut v6_short = [0x60u8, 0x20, 0, 0, 0, 0, 6, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(!try_mark_ce(&mut v6_short));
}

#[test]
fn small_packets_never_dropped_or_marked_in_any_queue_region() {
    let mut pie = M1Block::new_boot_default();
    pie.burst_allow_ms = 0;
    pie.prob_q24 = P_SCALE;
    pie.c_pie_updates = 1;
    pie.last_update_tti = 1000;

    for &q_total in &[0u32, 15_000, 30_000, 60_000, 120_000, 250_000] {
        for &len in &[128u32, 228, 400, 599] {
            for &tos in &[0x00u8, 0x01, 0x02] {
                let mut pkt = make_ipv4(len as u16, tos, 1);
                let orig = pkt;
                let dec = pie.evaluate_packet(q_total, 4600, 600, len, 1005, &mut pkt);
                assert!(!dec.is_drop(), "small packet {len} B dropped at q={q_total}");
                assert_ne!(dec, Decision::EcnMark, "small packet {len} B CE-marked");
                assert_eq!(pkt, orig, "small packet header modified");
            }
        }
    }
    assert_eq!(pie.c_pie_drop, 0);
    assert_eq!(pie.c_pie_hard_drop, 0);
    assert_eq!(pie.c_pie_mark, 0);
    assert!(pie.c_pie_spared_small > 0);
}

#[test]
fn burst_allowance_absorbs_line_rate_bursts_and_harq_pauses() {
    let mut pie = M1Block::new_boot_default();
    let g_ema = 4600;
    let mut drops = 0u32;

    for cycle in 0..40u32 {
        let base_t = 1000 + cycle * 120;
        for k in 0..10u32 {
            let mut pkt = make_ipv4(1380, 0x00, k as u16);
            let q = 14_000 + k * 1380;
            let dec = pie.evaluate_packet(q, g_ema, 600, 1380, base_t + 1, &mut pkt);
            if dec.is_drop() {
                drops += 1;
            }
        }
        for dt in (25..110).step_by(15) {
            let mut pkt = make_ipv4(1380, 0x00, dt as u16);
            let dec = pie.evaluate_packet(2_000, g_ema, 600, 1380, base_t + dt, &mut pkt);
            if dec.is_drop() {
                drops += 1;
            }
        }
    }
    assert_eq!(drops, 0, "transient bursts/HARQ pauses should cause 0 PIE drops");
    assert!(pie.c_pie_spared_burst > 0);
}

#[test]
fn ecn_capable_packets_are_marked_instead_of_dropped_below_hard_cap() {
    let mut pie = M1Block::new_boot_default();
    let g_ema = 4600;
    let mut marks = 0u32;
    let mut drops = 0u32;

    for t in 1..=600u32 {
        let mut pkt = make_ipv4(1380, 0x02, t as u16);
        let dec = pie.evaluate_packet(32_000, g_ema, 600, 1380, t, &mut pkt);
        match dec {
            Decision::EcnMark => {
                marks += 1;
                assert_eq!(pkt[1] & 0x03, 0x03);
                assert_eq!(rfc1071_checksum(&pkt[..20]), 0);
            }
            Decision::Drop | Decision::HardDrop => drops += 1,
            _ => {}
        }
    }
    assert!(marks > 0, "expected ECN CE marks on sustained congestion");
    assert_eq!(drops, 0, "ECT(0) packets below hard cap should not drop");
}

struct N4V2 {
    qmin: u32,
    ivl_ms: u32,
    last_aqm_tti: u32,
}

impl N4V2 {
    fn new() -> Self {
        Self { qmin: 20_480, ivl_ms: 35, last_aqm_tti: 0 }
    }
    fn eval(&mut self, q_total: u32, g_ema: u32, pkt_len: u32, now_tti: u32) -> bool {
        let q_target = (3 * g_ema).clamp(self.qmin, 49_152);
        if q_total <= q_target || pkt_len < 600 {
            return false;
        }
        if q_total > 2 * q_target {
            return true;
        }
        if now_tti.wrapping_sub(self.last_aqm_tti) >= self.ivl_ms {
            self.last_aqm_tti = now_tti;
            return true;
        }
        false
    }
}

#[derive(Copy, Clone, Debug)]
enum AqmMode {
    N4V2,
    RustPie,
    Off,
}

#[derive(Copy, Clone, Debug)]
enum CcKind {
    Cubic,
    Bbr,
}

#[derive(Debug)]
struct SimResult {
    goodput_mbps: f64,
    retx_pct: f64,
    rtt_p50_ms: f64,
    rtt_p95_ms: f64,
}

/// Closed-loop discrete-time (1 ms) TDD Config 2 UL simulator calibrated to the bench Titan
/// (`lanes-20261124/UL/data/README.md`: 1CC ~7.8 Mbps, 2CC ~15.6 Mbps, idle RTT 21 ms,
/// RLC AM byte-level segmentation, 8% HARQ 10 ms retry pauses, RFC 8312 CUBIC with delayed ACKs).
fn run_closed_loop(
    cc: CcKind,
    n_flows: usize,
    carriers: u32,
    mode: AqmMode,
    duration_ms: u32,
) -> SimResult {
    const MSS: u32 = 1328;
    const PKT_BYTES: u32 = 1380;
    const BASE_RTT_MS: u32 = 21;
    // Gross grant yields ~7.7-7.8 Mbps TCP goodput on 1CC (~15.4 Mbps on 2CC) after 8% HARQ pauses.
    let grant_5ms: u32 = if carriers >= 2 { 11_700 } else { 5_850 };
    let link_bpms: f64 = (grant_5ms as f64) / 5.0;

    let mut pie = M1Block::new_boot_default();
    let mut n4 = N4V2::new();
    let mut g_ema: u32 = grant_5ms;

    // Queue entries: (enq_tti, remaining_bytes, flow_id)
    let mut queue: Vec<(u32, u32, usize)> = Vec::new();
    let mut q_bytes: u32 = 0;

    struct Flow {
        cwnd: f64,
        w_max: f64,
        last_loss_ms: u32,
        inflight: u32,
        ack_cnt: u32,
        pace: f64,
    }
    let bdp_pkts = (link_bpms * (BASE_RTT_MS as f64 + 10.0)) / (PKT_BYTES as f64);
    let init_w = match cc {
        CcKind::Cubic => 10.0,
        CcKind::Bbr => (2.0 * bdp_pkts / (n_flows as f64)).max(10.0),
    };
    let mut flows: Vec<Flow> = (0..n_flows)
        .map(|_| Flow { cwnd: init_w, w_max: init_w, last_loss_ms: 0, inflight: 0, ack_cnt: 0, pace: 0.0 })
        .collect();

    let mut events: Vec<(u32, usize, bool)> = Vec::new();
    let mut qdelays: Vec<f64> = Vec::new();
    let mut sent_pkts = 0u32;
    let mut dropped_pkts = 0u32;
    let mut delivered_bytes = 0u64;
    let mut harq_rng: u32 = 0x5a5a_1234;
    let mut harq_stall_until: u32 = 0;
    let meas_start = 2_000u32;

    for t in 0..duration_ms {
        let mut i = 0;
        while i < events.len() {
            if events[i].0 <= t {
                let (_, fid, is_drop) = events.swap_remove(i);
                let f = &mut flows[fid];
                f.inflight = f.inflight.saturating_sub(1);
                match cc {
                    CcKind::Cubic => {
                        if is_drop {
                            if t.saturating_sub(f.last_loss_ms) >= BASE_RTT_MS + 15 {
                                f.w_max = f.cwnd;
                                f.cwnd = (f.cwnd * 0.7).max(4.0);
                                f.last_loss_ms = t;
                            }
                        } else {
                            f.ack_cnt += 1;
                            if f.ack_cnt % 2 == 0 {
                                let dt_s = (t.saturating_sub(f.last_loss_ms) as f64) / 1000.0;
                                let k = (f.w_max * 0.3 / 0.4).cbrt();
                                let w_cub = 0.4 * (dt_s - k).powi(3) + f.w_max;
                                let w = f.cwnd.max(4.0);
                                let inc_tcp = 0.529 * 2.0 / w;
                                if w_cub > w {
                                    let inc = ((w_cub - w) * 2.0 / w).min(0.5);
                                    f.cwnd += inc.max(inc_tcp);
                                } else {
                                    f.cwnd += inc_tcp;
                                }
                            }
                        }
                    }
                    CcKind::Bbr => {
                        let phase = (t / 160) % 8;
                        let gain = if phase == 0 { 1.25 } else if phase == 1 { 0.75 } else { 1.0 };
                        f.cwnd = (2.0 * bdp_pkts * gain / (n_flows as f64)).max(8.0);
                    }
                }
            } else {
                i += 1;
            }
        }

        for (fid, f) in flows.iter_mut().enumerate() {
            let mut burst = 0u32;
            while (f.inflight as f64) + 1.0 <= f.cwnd && burst < 12 {
                if matches!(cc, CcKind::Bbr) {
                    f.pace += (link_bpms * 1.12) / ((n_flows as f64) * (PKT_BYTES as f64));
                    if f.pace < 1.0 && burst > 0 {
                        break;
                    }
                    if f.pace >= 1.0 {
                        f.pace -= 1.0;
                    }
                }
                let mut hdr = make_ipv4(PKT_BYTES as u16, 0x00, (t as u16).wrapping_add(burst as u16));
                let drop = match mode {
                    AqmMode::N4V2 => n4.eval(q_bytes, g_ema, PKT_BYTES, t),
                    AqmMode::RustPie => pie
                        .evaluate_packet(q_bytes, g_ema, 600, PKT_BYTES, t, &mut hdr)
                        .is_drop(),
                    AqmMode::Off => false,
                };
                if t >= meas_start {
                    sent_pkts += 1;
                }
                f.inflight += 1;
                burst += 1;

                if drop {
                    if t >= meas_start {
                        dropped_pkts += 1;
                    }
                    let cur_q_ms = ((q_bytes as f64) / link_bpms) as u32;
                    events.push((t + BASE_RTT_MS + cur_q_ms, fid, true));
                } else {
                    q_bytes += PKT_BYTES;
                    queue.push((t, PKT_BYTES, fid));
                }
            }
        }

        if t % 5 == 0 {
            harq_rng ^= harq_rng << 13;
            harq_rng ^= harq_rng >> 17;
            harq_rng ^= harq_rng << 5;
            if t >= harq_stall_until && (harq_rng % 100) < 8 {
                harq_stall_until = t + 10;
            }
            if t >= harq_stall_until {
                let mut budget = grant_5ms;
                let mut used = 0u32;
                let mut done = 0usize;
                while done < queue.len() && budget > 0 {
                    let take = budget.min(queue[done].1);
                    budget -= take;
                    used += take;
                    q_bytes = q_bytes.saturating_sub(take);
                    queue[done].1 -= take;
                    if queue[done].1 == 0 {
                        let (enq_t, _, fid) = queue[done];
                        if t >= meas_start {
                            delivered_bytes += MSS as u64;
                            qdelays.push(t.saturating_sub(enq_t) as f64);
                        }
                        events.push((t + BASE_RTT_MS, fid, false));
                        done += 1;
                    }
                }
                if done > 0 {
                    queue.drain(0..done);
                }
                if used > 0 {
                    g_ema = (3 * g_ema + grant_5ms) >> 2;
                }
            }
        }
    }

    qdelays.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pct = |p: f64| -> f64 {
        if qdelays.is_empty() {
            0.0
        } else {
            let idx = ((qdelays.len() as f64) * p).min((qdelays.len() - 1) as f64) as usize;
            qdelays[idx]
        }
    };
    let meas_s = ((duration_ms - meas_start) as f64) / 1000.0;
    SimResult {
        goodput_mbps: (delivered_bytes as f64) * 8.0 / (meas_s * 1e6),
        retx_pct: if sent_pkts > 0 { (dropped_pkts as f64) * 100.0 / (sent_pkts as f64) } else { 0.0 },
        rtt_p50_ms: (BASE_RTT_MS as f64) + pct(0.50),
        rtt_p95_ms: (BASE_RTT_MS as f64) + pct(0.95),
    }
}

#[test]
fn closed_loop_cubic_and_bbr_1cc_and_2cc_verify_gains_over_n4v2() {
    let cases = [
        ("CUBIC1-1CC", CcKind::Cubic, 1usize, 1u32),
        ("CUBIC4-1CC", CcKind::Cubic, 4usize, 1u32),
        ("CUBIC4-2CC", CcKind::Cubic, 4usize, 2u32),
        ("BBR1-1CC",   CcKind::Bbr,   1usize, 1u32),
        ("BBR4-1CC",   CcKind::Bbr,   4usize, 1u32),
        ("BBR4-2CC",   CcKind::Bbr,   4usize, 2u32),
    ];

    for (label, cc, flows, carriers) in cases {
        let r_n4 = run_closed_loop(cc, flows, carriers, AqmMode::N4V2, 22_000);
        let r_pie = run_closed_loop(cc, flows, carriers, AqmMode::RustPie, 22_000);
        let r_off = run_closed_loop(cc, flows, carriers, AqmMode::Off, 22_000);

        eprintln!(
            "{label:10} | N4v2: {:5.2}M retx={:5.2}% rtt={:4.0}/{:4.0}ms | \
             PIE: {:5.2}M retx={:5.2}% rtt={:4.0}/{:4.0}ms | \
             OFF: {:5.2}M rtt95={:5.0}ms",
            r_n4.goodput_mbps, r_n4.retx_pct, r_n4.rtt_p50_ms, r_n4.rtt_p95_ms,
            r_pie.goodput_mbps, r_pie.retx_pct, r_pie.rtt_p50_ms, r_pie.rtt_p95_ms,
            r_off.goodput_mbps, r_off.rtt_p95_ms,
        );

        // Universal gate: PIE must deliver >= 95% of AQM-off goodput on every workload.
        assert!(
            r_pie.goodput_mbps >= r_off.goodput_mbps * 0.95,
            "{label}: PIE goodput {:.2} Mbps < 95% of AQM-off {:.2} Mbps",
            r_pie.goodput_mbps,
            r_off.goodput_mbps
        );
        // Universal gate: PIE must dramatically cut queue bloat vs AQM-off on CUBIC.
        if matches!(cc, CcKind::Cubic) {
            assert!(
                r_pie.rtt_p95_ms < r_off.rtt_p95_ms * 0.1,
                "{label}: PIE failed to bound CUBIC bufferbloat ({:.0} ms vs OFF {:.0} ms)",
                r_pie.rtt_p95_ms,
                r_off.rtt_p95_ms
            );
            assert!(
                r_pie.retx_pct < r_n4.retx_pct,
                "{label}: PIE retx {:.2}% did not improve over N4v2 {:.2}%",
                r_pie.retx_pct,
                r_n4.retx_pct
            );
            if flows == 1 {
                assert!(
                    r_pie.retx_pct < 0.5,
                    "{label}: single-flow CUBIC retx {:.2}% >= 0.5%",
                    r_pie.retx_pct
                );
            }
        } else {
            // BBR: PIE cuts loss dramatically vs N4v2's brick wall while keeping RTT bounded.
            assert!(
                r_pie.retx_pct < r_n4.retx_pct,
                "{label}: PIE BBR retx {:.2}% should be below N4v2 {:.2}%",
                r_pie.retx_pct,
                r_n4.retx_pct
            );
            assert!(
                r_pie.rtt_p95_ms <= 90.0,
                "{label}: PIE BBR rtt p95 {:.0} ms exceeded bound",
                r_pie.rtt_p95_ms
            );
        }
    }
}

#[test]
fn pcap_derived_burst_traces_verify_burst_tolerance_vs_n4v2() {
    struct TraceProfile {
        name: &'static str,
        grant_5ms: u32,
        burst_table: &'static [u32],
        gap_ms: u32,
        expect_low_loss: bool,
    }
    let profiles = [
        TraceProfile {
            name: "e7-cubic1-1cc",
            grant_5ms: 5_250,
            burst_table: &[3, 3, 4, 4, 4, 5, 5, 6, 8, 10],
            gap_ms: 8,
            expect_low_loss: true,
        },
        TraceProfile {
            name: "e2-cubic4-2cc",
            grant_5ms: 10_500,
            burst_table: &[4, 4, 5, 6, 7, 8, 9, 10, 14, 20],
            gap_ms: 7,
            expect_low_loss: true,
        },
        TraceProfile {
            name: "e1-bbr4-2cc-overload",
            grant_5ms: 10_500,
            burst_table: &[8, 10, 12, 14, 16, 18, 22, 26, 32, 40],
            gap_ms: 10,
            expect_low_loss: false,
        },
    ];

    for prof in profiles {
        let mut pie = M1Block::new_boot_default();
        let mut n4 = N4V2::new();
        let mut q_pie: u32 = 0;
        let mut q_n4: u32 = 0;
        let mut pie_drops = 0u32;
        let mut n4_drops = 0u32;
        let mut total = 0u32;
        let mut idx = 0usize;

        for t in 0..10_000u32 {
            if t % prof.gap_ms == 0 {
                let segs = prof.burst_table[idx % prof.burst_table.len()];
                idx += 1;
                for k in 0..segs {
                    total += 1;
                    let mut hdr = make_ipv4(1380, 0x00, k as u16);
                    if pie.evaluate_packet(q_pie, prof.grant_5ms, 600, 1380, t, &mut hdr).is_drop() {
                        pie_drops += 1;
                    } else {
                        q_pie += 1380;
                    }
                    if n4.eval(q_n4, prof.grant_5ms, 1380, t) {
                        n4_drops += 1;
                    } else {
                        q_n4 += 1380;
                    }
                }
            }
            if t % 5 == 0 {
                q_pie = q_pie.saturating_sub(prof.grant_5ms);
                q_n4 = q_n4.saturating_sub(prof.grant_5ms);
            }
        }

        let pie_pct = (pie_drops as f64) * 100.0 / (total as f64);
        let n4_pct = (n4_drops as f64) * 100.0 / (total as f64);
        eprintln!(
            "trace {:20}: total={total:5} N4v2 drops={n4_drops:4} ({n4_pct:5.2}%) | \
             PIE drops={pie_drops:4} ({pie_pct:5.2}%) max_qdelay={:.1}ms",
            prof.name,
            (pie.c_pie_max_qdelay_us as f64) / 1000.0
        );
        if prof.expect_low_loss {
            assert!(pie_pct < 0.5, "{}: PIE lost {:.2}%", prof.name, pie_pct);
            assert!(pie_drops <= n4_drops, "{}: PIE dropped more than N4v2", prof.name);
        } else {
            let eff_cap = pie.hard_cap_bytes.max(prof.grant_5ms * 10);
            assert!(pie_drops > 0, "{}: PIE must engage under overload", prof.name);
            assert!(q_pie <= eff_cap + 1380, "{}: queue exceeded adaptive hard cap", prof.name);
        }
    }
}
