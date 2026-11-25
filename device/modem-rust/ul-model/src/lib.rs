//! Pure-Rust, `no_std`-friendly, `#![forbid(unsafe_code)]` behavioural model of the
//! Titan 4000 GDM7243A post-Ring-1 uplink stack (`tk.bin` V1.6.0.P0):
//!
//! - [`pdcp`]: `do_tc` 250 ms cap, `l2_proc_pdcp_ul` staging cap & `/1500` vs byte-accurate
//!   admission, Ring 0 priority, `PdcpUlSduWindow`, LLCE0 64-desc 2-slot batching & post-HARQ
//!   harvest, `discardTimer`, and `pdcp_ul_proc_drb_cnf`.
//! - [`rlc`]: `RlcAmUlGenPdu` (STATUS > RETX > New-TX), `rlc_can_fit` 1.5 B LI concatenation &
//!   segmentation, `ProcessPduRetx` (`RETX_COUNT`/`maxRetxThreshold`), `rlc_ul_am_proc_status_rpt`,
//!   `rlc_poll_check` + `pollPDU`/`pollByte`, `t-PollRetransmit` empty-buffer-only expiry, and
//!   `-2 ms` timer subtraction.
//! - [`bsr`]: `get_rlc_cur_bo`, `rlc_upd_cur_bo` (stock vs N4 `TRUE_BO`), and `SearchMacUlBoIdx`.
//! - [`sim`]: 1 ms TDD Config 2 (`DSUDDDSUDD`) end-to-end uplink simulator producing stage-by-stage
//!   latency budgets across Ring 1, LLCE0, PDCP/RLC staging, TDD alignment, HARQ, and RLC retx.

#![no_std]
#![forbid(unsafe_code)]

pub mod bsr;
pub mod pdcp;
pub mod rlc;
pub mod sim;

#[cfg(test)]
mod tests {
    use crate::bsr::{BearerBoSnapshot, calc_lcg_bo, get_rlc_cur_bo, search_bsr_idx};
    use crate::pdcp::{
        IngressPkt, PdcpConfig, PdcpUlState, do_tc_stock_cap, do_tc_tuned_cap,
    };
    use crate::rlc::{
        GeneratedPduKind, RlcAmConfig, RlcAmUlState, rlc_can_fit, rlc_timer_effective_ms,
    };
    use crate::sim::{LinkConfig, UplinkSim, pdcp_cfg_v1_0_16};
    use modem_atlas::l2::{
        DO_TC_CAP_HIGH, DO_TC_CAP_LOW, DO_TC_CAP_MID, RLC_MODE_AM, RLC_MODE_TM, RLC_MODE_UM,
    };

    #[test]
    fn do_tc_stock_tiers_match_disassembly() {
        assert_eq!(do_tc_stock_cap(0), DO_TC_CAP_LOW);
        assert_eq!(do_tc_stock_cap(8 << 15), DO_TC_CAP_LOW);
        assert_eq!(do_tc_stock_cap((8 << 15) + 32_767), DO_TC_CAP_LOW);
        assert_eq!(do_tc_stock_cap(9 << 15), DO_TC_CAP_MID);
        assert_eq!(do_tc_stock_cap(32 << 15), DO_TC_CAP_MID);
        assert_eq!(do_tc_stock_cap((32 << 15) + 32_767), DO_TC_CAP_MID);
        assert_eq!(do_tc_stock_cap(33 << 15), DO_TC_CAP_HIGH);
        assert_eq!(do_tc_stock_cap(100 << 15), DO_TC_CAP_HIGH);

        // Tuned do_tc cap targets N ms clamped to [cap_min, cap_max]
        // 250 KB / 250 ms = 1 KB/ms -> 8 ms = 8192 B
        assert_eq!(do_tc_tuned_cap(250_000, 8, 6_144, 12_288), 8_000);
        assert_eq!(do_tc_tuned_cap(50_000, 8, 6_144, 12_288), 6_144);
        assert_eq!(do_tc_tuned_cap(600_000, 8, 6_144, 12_288), 12_288);
    }

    #[test]
    fn pdcp_ring0_priority_and_staging_quantization() {
        let mut pdcp = PdcpUlState::new(pdcp_cfg_v1_0_16(false));
        pdcp.grant_ema_bytes = 5_000; // cap = clamp(9096, 8192, 12288) = 9096 B

        // Enqueue 2 small Ring 0 ACKs + 10 bulk 1480 B Ring 1 packets
        for i in 0..2 {
            assert!(pdcp.enqueue_ring0(IngressPkt {
                id: i + 1,
                ip_len: 52,
                ring_enqueue_ms: 10,
            }));
        }
        for i in 0..10 {
            assert!(pdcp.enqueue_ring1(IngressPkt {
                id: i + 100,
                ip_len: 1480,
                ring_enqueue_ms: 10,
            }));
        }

        // cur_bo = (2 << 6) = 128; headroom = 9096 - 128 = 8968; 8968 / 1500 = 5 pkts
        let sub = pdcp.proc_pdcp_ul(10);
        assert_eq!(sub.ring0_submitted, 2);
        assert_eq!(sub.ring1_submitted, 5);
        assert_eq!(sub.effective_limit, 9_096);
        assert!(sub.batch_kicked);
        assert_eq!(pdcp.pdcp_to_rlc_cnt, 0); // Not yet harvested!

        // Harvest at t = 11 ms (post-HARQ 1 ms)
        let harv = pdcp.harvest_llce(11);
        assert_eq!(harv.harvested_pkts, 7);
        assert_eq!(harv.harvested_bytes, 2 * 54 + 5 * 1482);
        assert_eq!(pdcp.pdcp_to_rlc_cnt, 7);
        assert_eq!(pdcp.pdcp_rlc_hdr_bo, 14);
        assert_eq!(pdcp.pdcp_rlc_tx_bo, 7_518);
    }

    #[test]
    fn pdcp_byte_accurate_staging_eliminates_small_packet_stall() {
        // With headroom = 1400 B and 200 B packets in Ring 1:
        // stock /1500 submits 0 packets; byte-accurate submits 6 packets (6 * 202 = 1212 B)!
        let mut stock = PdcpUlState::new(pdcp_cfg_v1_0_16(false));
        let mut accurate = PdcpUlState::new(pdcp_cfg_v1_0_16(true));
        stock.grant_ema_bytes = 4_096; // cap = 8192
        accurate.grant_ema_bytes = 4_096;
        stock.pdcp_rlc_tx_bo = 6_800; // headroom = 1392 B (< 1500!)
        accurate.pdcp_rlc_tx_bo = 6_800;

        for i in 0..8 {
            let p = IngressPkt {
                id: i + 1,
                ip_len: 200,
                ring_enqueue_ms: 5,
            };
            stock.enqueue_ring1(p);
            accurate.enqueue_ring1(p);
        }

        let s_res = stock.proc_pdcp_ul(5);
        let a_res = accurate.proc_pdcp_ul(5);
        assert_eq!(s_res.ring1_submitted, 0);
        assert_eq!(a_res.ring1_submitted, 6);
    }

    #[test]
    fn pdcp_discard_timer_and_untransmitted_removal() {
        let mut pdcp = PdcpUlState::new(PdcpConfig {
            discard_timer_ms: 100,
            ..PdcpConfig::default()
        });
        for i in 0..3 {
            pdcp.enqueue_ring1(IngressPkt {
                id: i + 1,
                ip_len: 1000,
                ring_enqueue_ms: 10,
            });
        }
        pdcp.proc_pdcp_ul(11); // stored timestamp = 11 & !1 = 10
        pdcp.harvest_llce(12);
        assert_eq!(pdcp.pdcp_to_rlc_cnt, 3);
        assert_eq!(pdcp.pdcp_rlc_tx_bo, 3 * 1002);

        // At t = 109 ms: age = 99 < 100 -> nothing discarded
        assert_eq!(pdcp.proc_discard_timer(109).count, 0);

        // At t = 110 ms: age = 100 >= 100 -> all 3 marked and removed from pdcp_to_rlc
        let disc = pdcp.proc_discard_timer(110);
        assert_eq!(disc.count, 3);
        assert_eq!(disc.first_sn, 0);
        assert_eq!(disc.last_sn, 2);
        let removed = pdcp.discard_untransmitted(disc);
        assert_eq!(removed, 3);
        assert_eq!(pdcp.pdcp_to_rlc_cnt, 0);
        assert_eq!(pdcp.pdcp_rlc_tx_bo, 0);
        assert_eq!(pdcp.sdu_win_active, 0);
        assert_eq!(pdcp.pdcp_ul_oldest_sn, 3);
    }

    #[test]
    fn rlc_can_fit_and_timer_offset_match_disassembly() {
        assert_eq!(rlc_can_fit(0, 100, 2), 1);
        assert_eq!(rlc_can_fit(1, 100, 2), 0);
        assert_eq!(rlc_can_fit(99, 100, 2), 0);
        assert_eq!(rlc_can_fit(100, 100, 2), 1);
        assert_eq!(rlc_can_fit(102, 100, 2), 1);
        assert_eq!(rlc_can_fit(103, 100, 2), 2);
        assert_eq!(rlc_can_fit(101, 100, 1), 1);
        assert_eq!(rlc_can_fit(102, 100, 1), 2);

        assert_eq!(rlc_timer_effective_ms(120, 2), 118);
        assert_eq!(rlc_timer_effective_ms(5, 2), 3);
        assert_eq!(rlc_timer_effective_ms(2, 2), 2);
        assert_eq!(rlc_timer_effective_ms(120, 0), 120);
    }

    #[test]
    fn rlc_am_gen_pdu_segmentation_concatenation_poll_status_and_retx() {
        let mut pdcp = PdcpUlState::new(PdcpConfig::default());
        let mut rlc = RlcAmUlState::new(RlcAmConfig {
            poll_pdu: 2,
            poll_byte: 50_000,
            t_poll_retx_ms: 45,
            ..RlcAmConfig::default()
        });

        // Submit 2 SDUs of 1000 B IP (+2 B PDCP = 1002 B each)
        for i in 0..2 {
            pdcp.enqueue_ring1(IngressPkt {
                id: i + 1,
                ip_len: 1000,
                ring_enqueue_ms: 0,
            });
        }
        pdcp.proc_pdcp_ul(0);
        pdcp.harvest_llce(1);
        rlc.notify_pdcp_bo(&pdcp);
        assert_eq!(rlc.rlc_am_newtx_bo, 2004);

        // Grant 1: 603 B -> payload_budget = 600 B -> segments SDU 0 (600 B sent, 402 B rem)
        let g1 = rlc.gen_pdu(&mut pdcp, 603, 2);
        assert_eq!(g1.pdu_count, 1);
        assert_eq!(g1.pdus[0].kind, GeneratedPduKind::NewTx);
        assert_eq!(g1.pdus[0].sn, 0);
        assert_eq!(g1.pdus[0].size, 602); // 2 B hdr + 600 B data
        assert!(!g1.pdus[0].poll_bit); // 1 PDU < pollPDU(2), BO != 0
        assert_eq!(rlc.cur_sdu_rem, 402);
        assert_eq!(rlc.rlc_am_newtx_bo, 1404);
        assert_eq!(rlc.vt_s, 1);

        // Grant 2: 2000 B -> concatenates remaining 402 B of SDU 0 + LI(2 B) + 1002 B of SDU 1
        let g2 = rlc.gen_pdu(&mut pdcp, 2000, 7);
        assert_eq!(g2.pdu_count, 1);
        assert_eq!(g2.pdus[0].sn, 1);
        assert_eq!(g2.pdus[0].size, 2 + 2 + 402 + 1002); // 1408 B
        assert!(g2.pdus[0].poll_bit); // empty buffer + pollPDU(2) reached!
        assert!(g2.started_poll_retx_tmr);
        assert_eq!(rlc.poll_sn, 1);
        assert_eq!(rlc.poll_retx_tmr_expiry_ms, 7 + 43); // 45 - 2 ms quirk!
        assert_eq!(rlc.rlc_am_newtx_bo, 0);

        // Peer STATUS: ACK_SN = 2, NACK SN = 0 -> enqueues SN 0 for RETX and stops poll timer
        let st = rlc.proc_status_rpt(&mut pdcp, 2, &[0]);
        assert!(st.stopped_poll_retx_tmr);
        assert_eq!(st.nacked_rlc_pdus, 1);
        assert_eq!(rlc.vt_a, 0);
        assert_eq!(rlc.retx_cnt, 1);
        assert_eq!(rlc.rlc_am_retx_bo, 600);

        // Grant 3: 300 B (< 603 B) -> re-segments SN 0!
        let g3 = rlc.gen_pdu(&mut pdcp, 300, 12);
        assert_eq!(g3.pdu_count, 1);
        assert_eq!(g3.pdus[0].kind, GeneratedPduKind::RetxSeg);
        assert_eq!(g3.pdus[0].sn, 0);
        assert_eq!(g3.pdus[0].so, 0);
        assert!(!g3.pdus[0].is_last_seg);
        assert_eq!(g3.pdus[0].data_bytes, 295); // 300 - 4(hdr) - 1(mac)

        // Grant 4: 400 B -> finishes SN 0 retx segment
        let g4 = rlc.gen_pdu(&mut pdcp, 400, 17);
        assert_eq!(g4.pdus[0].kind, GeneratedPduKind::RetxSeg);
        assert_eq!(g4.pdus[0].so, 295);
        assert!(g4.pdus[0].is_last_seg);
        assert_eq!(rlc.retx_cnt, 0);
        assert_eq!(rlc.rlc_am_retx_bo, 0);

        // STATUS ACK_SN = 2 clears VT(A) -> 2 and confirms both PDCP SDUs
        let st2 = rlc.proc_status_rpt(&mut pdcp, 2, &[]);
        assert_eq!(rlc.vt_a, 2);
        assert_eq!(rlc.ul_am_free_win_slots, 512);
        assert_eq!(st2.confirmed_pdcp_sdus, 2);
        assert_eq!(pdcp.sdu_win_active, 0);
    }

    #[test]
    fn poll_retx_expire_only_fires_when_both_buffers_empty() {
        let mut pdcp = PdcpUlState::new(PdcpConfig::default());
        let mut rlc = RlcAmUlState::new(RlcAmConfig {
            poll_pdu: 1,
            t_poll_retx_ms: 40,
            ..RlcAmConfig::default()
        });
        for i in 0..2 {
            pdcp.enqueue_ring1(IngressPkt {
                id: i + 1,
                ip_len: 500,
                ring_enqueue_ms: 0,
            });
        }
        pdcp.proc_pdcp_ul(0);
        pdcp.harvest_llce(1);
        rlc.notify_pdcp_bo(&pdcp);

        // Send only 505 B -> SDU 1 still sitting in rlc_am_newtx_bo > 0, poll timer armed at t=2
        let g = rlc.gen_pdu(&mut pdcp, 505, 2);
        assert!(g.started_poll_retx_tmr);
        assert!(rlc.rlc_am_newtx_bo > 0);

        // Timer expires at t = 40 (2 + 38), but newtx_bo != 0 -> MUST NOT enqueue retx!
        assert!(!rlc.tick_poll_retx_timer(40));
        assert_eq!(rlc.retx_cnt, 0);
        assert!(!rlc.poll_trigger);

        // Now drain remaining SDU -> both buffers 0 -> next expiry re-enqueues VT(A) and sets poll!
        let _ = rlc.gen_pdu(&mut pdcp, 1000, 42);
        assert_eq!(rlc.rlc_am_newtx_bo, 0);
        assert_eq!(rlc.rlc_am_retx_bo, 0);
        assert!(rlc.tick_poll_retx_timer(80));
        assert_eq!(rlc.retx_cnt, 1);
        assert!(rlc.poll_trigger);
    }

    #[test]
    fn bsr_calculation_matches_stock_and_n4_true_bo() {
        let b = BearerBoSnapshot {
            rlc_mode: RLC_MODE_AM,
            active: true,
            lcg_id: 3,
            rlc_tm_bo: 0,
            rlc_status_bo: 4,
            rlc_am_newtx_bo: 8_000,
            rlc_am_retx_bo: 1_500,
            pdcp_rlc_hdr_bo: 12,
            rlc_reest_hdr_bo: 0,
            retx_hdr_bo: 2,
            am_extra_hdr_bo: 1,
            ring_pending_bytes: 20_000,
            bo_margin_bytes: 320,
        };
        let cur = get_rlc_cur_bo(&b);
        assert_eq!(cur.data_bo, 9_504);
        assert_eq!(cur.hdr_bo, 15);

        let stock_bo = calc_lcg_bo(&[b], [0; 4], true, false);
        assert_eq!(stock_bo[3], 9_504 + 15 + 320);

        let n4_bo = calc_lcg_bo(&[b], [0; 4], true, true);
        assert_eq!(n4_bo[3], 9_504 + 15 + 320 + 20_000);

        // UM and TM modes
        let um = BearerBoSnapshot {
            rlc_mode: RLC_MODE_UM,
            rlc_am_retx_bo: 400,
            pdcp_rlc_hdr_bo: 6,
            ..b
        };
        assert_eq!(get_rlc_cur_bo(&um).data_bo, 400);
        assert_eq!(get_rlc_cur_bo(&um).hdr_bo, 6);

        let tm = BearerBoSnapshot {
            rlc_mode: RLC_MODE_TM,
            rlc_tm_bo: 77,
            ..b
        };
        assert_eq!(get_rlc_cur_bo(&tm).data_bo, 77);
        assert_eq!(get_rlc_cur_bo(&tm).hdr_bo, 0);

        assert_eq!(search_bsr_idx(0, false), 0);
        assert_eq!(search_bsr_idx(stock_bo[3], false), 45); // 9839 -> <= 10432 (idx 45)
        assert_eq!(search_bsr_idx(n4_bo[3], false), 52); // 29839 -> <= 33832 (idx 52)
    }

    #[test]
    fn tdd_cfg2_latency_budget_matches_stock_vs_v1_0_16() {
        // 1CC 8 Mbps PHY (~5000 B per 5 ms UL TTI), 10% BLER, saturated source (zero Ring 1 target)
        let link_1cc = LinkConfig {
            num_ccs: 1,
            grant_bytes_per_cc: 5_000,
            harq_bler_permille: 100,
            ..LinkConfig::default()
        };

        let mut sim_stock = UplinkSim::new(PdcpConfig::default(), RlcAmConfig::default(), link_1cc);
        let stock = sim_stock.run(1500, 300);

        let mut sim_v16 = UplinkSim::new(pdcp_cfg_v1_0_16(false), RlcAmConfig::default(), link_1cc);
        let v16 = sim_v16.run(1500, 300);

        // Stock 32 KB cap holds ~3x larger staging queue than v1.0.16's 9 KB cap!
        assert!(stock.mean_staging_bytes > 20_000);
        assert!(v16.mean_staging_bytes < 10_000);
        assert!(stock.post_ring1.p50_ms > v16.post_ring1.p50_ms + 15);
        assert!(v16.delivered_pkts > 500);
        assert!(v16.throughput_kbps > 6_500);
    }
}
