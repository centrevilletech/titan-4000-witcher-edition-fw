/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_ufq_sim.c - Deterministic userspace unit tests and packet-level LTE
 * TDD Config 2 + N4 modem simulator for ufq_core.h.
 *
 * Tests:
 *   1. Sparse-flow fast-pass overtakes bulk queue with 0 ms host wait.
 *   2. Bulk DRR fairness across 4 equal flows (Jain's fairness index > 0.98).
 *   3. CoDel drops/ECN-marks only bulk flows, never sparse flows.
 *   4. Hard fail-safe flushes all queued packets and enters mode=0 pass-through.
 *   5. Stale/frozen modem RAM (50-600 ms CPU1 L1 D-cache non-eviction) never
 *      stalls forwarding or collapses throughput.
 *   6. Full LTE TDD Config 2 (200 UL TTIs/s, 14.5 Mbps, 3GPP BSR table,
 *      N4 PDCP cap + AQM v2 + grant hold, 4 TCP bulk streams + 228 B ping
 *      + DNS + VoIP/game): baseline N4 vs titan_ufq mode 1 & mode 3.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

#include "ufq_core.h"

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg); \
        return 1; \
    } \
} while (0)

/* ---------- Simple packet descriptor for unit tests ---------- */
struct sim_pkt {
    u32 id;
    u32 flow_id;
    u32 len;
    u32 gen_us;
    u32 mod_enq_us;
    u32 tx_us;
    u8  is_sparse;
    u8  ecn_capable;
    u8  ecn_marked;
    u8  dropped;
    u8  delivered;
};

/* ---------- Unit Test 1: Sparse overtakes bulk ---------- */
struct t1_ctx {
    u32 order[64];
    u32 n;
    u32 drops;
};
static void t1_deliver(void *c, void *pkt, void *okfn)
{
    struct t1_ctx *ctx = (struct t1_ctx *)c;
    struct sim_pkt *p = (struct sim_pkt *)pkt;
    (void)okfn;
    if (ctx->n < 64)
        ctx->order[ctx->n++] = p->id;
    p->delivered = 1;
}
static void t1_drop(void *c, void *pkt)
{
    struct t1_ctx *ctx = (struct t1_ctx *)c;
    struct sim_pkt *p = (struct sim_pkt *)pkt;
    p->dropped = 1;
    ctx->drops++;
}
static int t1_mark_ecn(void *c, void *pkt)
{
    struct sim_pkt *p = (struct sim_pkt *)pkt;
    (void)c;
    if (p->ecn_capable) {
        p->ecn_marked = 1;
        return 1;
    }
    return 0;
}
static const struct ufq_ops t1_ops = { t1_deliver, t1_drop, t1_mark_ecn };

static int test_sparse_overtakes_bulk(void)
{
    struct ufq_state st;
    struct ufq_modem_sample ms;
    struct t1_ctx ctx;
    struct sim_pkt pkts[20];
    u32 i;

    memset(&st, 0, sizeof(st));
    memset(&ms, 0, sizeof(ms));
    memset(&ctx, 0, sizeof(ctx));
    memset(pkts, 0, sizeof(pkts));

    ufq_init(&st, 100000u);
    st.mode = UFQ_MODE_ENABLE;

    /* Modem currently at BQL limit -> bulk must wait, sparse can bypass */
    ms.ram_valid = 1;
    ms.active_drbs = 1;
    ms.n4_present = 1;
    ms.n4_g_ema = 9062;
    ms.gipc_ch1_out = 10;
    ms.rbc_rlc_bytes = 15000;
    ms.knl_ms = 100;
    ufq_update_modem(&st, &ms, 100000u);

    /* Enqueue 10 bulk packets (flow 5) -> flow 5 starts in new_flows for 1 quantum,
     * then demotes to old_flows. First force bulk flow into old_flows by giving it
     * one prior dequeue, then fill modem to BQL limit. */
    ms.rbc_rlc_bytes = 2000;
    ms.knl_ms = 101;
    ufq_update_modem(&st, &ms, 101000u);
    pkts[0].id = 100; pkts[0].len = 1514;
    pkts[1].id = 101; pkts[1].len = 1514;
    ufq_enqueue(&st, 5, &pkts[0], NULL, 1514, 0, 0, 101000u, &t1_ops, &ctx);
    ufq_enqueue(&st, 5, &pkts[1], NULL, 1514, 0, 0, 101000u, &t1_ops, &ctx);
    ufq_drain(&st, 101000u, &t1_ops, &ctx); /* drains pkts[0], demotes flow 5 to old_flows */

    /* Now modem is at BQL limit (~15 KB): queue 8 bulk pkts on flow 5.
     * Flow 5 consumes 1 quantum (1 pkt) on new_flows, then demotes to old_flows
     * and the remaining 7 bulk packets wait behind the BQL gate. */
    ms.rbc_rlc_bytes = st.bql_limit + 500u;
    ms.knl_ms = 102;
    ufq_update_modem(&st, &ms, 102000u);
    for (i = 2; i < 10; i++) {
        pkts[i].id = 100 + i;
        pkts[i].len = 1500;
        ufq_enqueue(&st, 5, &pkts[i], NULL, 1500, 0, 0, 102000u, &t1_ops, &ctx);
    }
    ufq_drain(&st, 102000u, &t1_ops, &ctx);
    CHECK(st.total_pkts >= 7, "bulk packets should be held while modem >= bql_limit");

    /* Now a 228-byte sparse ping arrives on flow 19! */
    pkts[10].id = 999;
    pkts[10].len = 228;
    pkts[10].is_sparse = 1;
    ufq_enqueue(&st, 19, &pkts[10], NULL, 228, 0, 1, 102500u, &t1_ops, &ctx);
    ufq_drain(&st, 102500u, &t1_ops, &ctx);

    CHECK(pkts[10].delivered == 1, "sparse 228 B ping must immediately overtake held bulk");
    CHECK(ctx.order[ctx.n - 1] == 999, "sparse ping must be delivered immediately");
    CHECK(ctx.drops == 0, "zero drops expected");
    printf("PASS test_sparse_overtakes_bulk (held_bulk=%u, sparse_deq=%u)\n",
           st.total_pkts, st.stat_deq_sparse);
    return 0;
}

/* ---------- Unit Test 2: DRR bulk fairness across 4 flows ---------- */
struct t2_ctx {
    u64 flow_bytes[4];
    u32 drops;
};
static void t2_deliver(void *c, void *pkt, void *okfn)
{
    struct t2_ctx *ctx = (struct t2_ctx *)c;
    struct sim_pkt *p = (struct sim_pkt *)pkt;
    (void)okfn;
    ctx->flow_bytes[p->flow_id] += p->len;
    free(p);
}
static void t2_drop(void *c, void *pkt)
{
    struct t2_ctx *ctx = (struct t2_ctx *)c;
    ctx->drops++;
    free(pkt);
}
static const struct ufq_ops t2_ops = { t2_deliver, t2_drop, NULL };

static int test_drr_fairness(void)
{
    struct ufq_state st;
    struct ufq_modem_sample ms;
    struct t2_ctx ctx;
    u32 t_ms, f, i;
    double sum = 0.0, sum2 = 0.0, jain;
    const u16 fids[4] = { 3, 17, 31, 49 };
    const u32 lens[4] = { 1500, 1500, 750, 1500 }; /* flow 2 sends smaller pkts -> still byte-fair! */

    memset(&st, 0, sizeof(st));
    memset(&ms, 0, sizeof(ms));
    memset(&ctx, 0, sizeof(ctx));

    ufq_init(&st, 0);
    st.mode = UFQ_MODE_ENABLE;
    st.codel_target_us = 500000u; /* disable CoDel during pure DRR fairness check */

    ms.ram_valid = 1;
    ms.active_drbs = 1;
    ms.n4_present = 1;
    ms.n4_g_ema = 9000;
    ms.gipc_ch1_out = 4;

    for (t_ms = 1; t_ms <= 500; t_ms++) {
        u32 now = t_ms * 1000u;
        /* Keep all 4 bulk flows heavily backlogged */
        for (f = 0; f < 4; f++) {
            for (i = 0; i < 4; i++) {
                struct sim_pkt *p = (struct sim_pkt *)calloc(1, sizeof(*p));
                p->flow_id = f;
                p->len = lens[f];
                ufq_enqueue(&st, fids[f], p, NULL, p->len, 0, 0, now, &t2_ops, &ctx);
            }
        }
        /* Modem drains ~1800 B/ms */
        ms.knl_ms = t_ms;
        ms.rbc_rlc_bytes = (st.q_est_bytes > 1800u) ? (st.q_est_bytes - 1800u) : 0u;
        ufq_update_modem(&st, &ms, now);
        ufq_drain(&st, now, &t2_ops, &ctx);
    }
    ufq_flush_all(&st, &t2_ops, &ctx, 0);

    for (f = 0; f < 4; f++) {
        double b = (double)ctx.flow_bytes[f];
        sum += b;
        sum2 += b * b;
    }
    jain = (sum * sum) / (4.0 * sum2);
    CHECK(jain > 0.98, "DRR Jain fairness across 4 bulk flows must exceed 0.98");
    printf("PASS test_drr_fairness (bytes=[%llu,%llu,%llu,%llu], jain=%.4f)\n",
           (unsigned long long)ctx.flow_bytes[0], (unsigned long long)ctx.flow_bytes[1],
           (unsigned long long)ctx.flow_bytes[2], (unsigned long long)ctx.flow_bytes[3], jain);
    return 0;
}

/* ---------- Unit Test 3: CoDel drops/ECN-marks only bulk, never sparse ---------- */
struct t3_ctx {
    u32 sparse_deliv, sparse_drop, sparse_ecn;
    u32 bulk_deliv, bulk_drop, bulk_ecn;
};
static void t3_deliver(void *c, void *pkt, void *okfn)
{
    struct t3_ctx *ctx = (struct t3_ctx *)c;
    struct sim_pkt *p = (struct sim_pkt *)pkt;
    (void)okfn;
    if (p->is_sparse) {
        ctx->sparse_deliv++;
        if (p->ecn_marked) ctx->sparse_ecn++;
    } else {
        ctx->bulk_deliv++;
        if (p->ecn_marked) ctx->bulk_ecn++;
    }
    free(p);
}
static void t3_drop(void *c, void *pkt)
{
    struct t3_ctx *ctx = (struct t3_ctx *)c;
    struct sim_pkt *p = (struct sim_pkt *)pkt;
    if (p->is_sparse) ctx->sparse_drop++;
    else ctx->bulk_drop++;
    free(p);
}
static int t3_mark_ecn(void *c, void *pkt)
{
    struct sim_pkt *p = (struct sim_pkt *)pkt;
    (void)c;
    if (p->ecn_capable) { p->ecn_marked = 1; return 1; }
    return 0;
}
static const struct ufq_ops t3_ops = { t3_deliver, t3_drop, t3_mark_ecn };

static int test_codel_bulk_only(u32 mode)
{
    struct ufq_state st;
    struct ufq_modem_sample ms;
    struct t3_ctx ctx;
    u32 t_ms, i;

    memset(&st, 0, sizeof(st));
    memset(&ms, 0, sizeof(ms));
    memset(&ctx, 0, sizeof(ctx));

    ufq_init(&st, 0);
    st.mode = mode;

    ms.ram_valid = 1;
    ms.active_drbs = 1;
    ms.n4_present = 1;
    ms.n4_g_ema = 9000;
    ms.gipc_ch1_out = 8;

    for (t_ms = 1; t_ms <= 600; t_ms++) {
        u32 now = t_ms * 1000u;
        /* Push 2 bulk packets/ms (3000 B/ms > 1800 B/ms link -> builds persistent bulk queue) */
        for (i = 0; i < 2; i++) {
            struct sim_pkt *p = (struct sim_pkt *)calloc(1, sizeof(*p));
            p->len = 1500;
            p->is_sparse = 0;
            p->ecn_capable = (mode & UFQ_MODE_ECN) ? 1 : 0;
            ufq_enqueue(&st, 7, p, NULL, p->len, p->ecn_capable, 0, now, &t3_ops, &ctx);
        }
        /* Push 1 sparse 228 B ping every 20 ms on flow 22 */
        if (t_ms % 20 == 0) {
            struct sim_pkt *p = (struct sim_pkt *)calloc(1, sizeof(*p));
            p->len = 228;
            p->is_sparse = 1;
            p->ecn_capable = 1;
            ufq_enqueue(&st, 22, p, NULL, p->len, 1, 1, now, &t3_ops, &ctx);
        }
        ms.knl_ms = t_ms;
        ms.rbc_rlc_bytes = (st.q_est_bytes > 1800u) ? (st.q_est_bytes - 1800u) : 0u;
        ufq_update_modem(&st, &ms, now);
        ufq_drain(&st, now, &t3_ops, &ctx);
    }
    ufq_flush_all(&st, &t3_ops, &ctx, 0);

    CHECK(ctx.sparse_deliv == 30, "every sparse packet must be delivered");
    CHECK(ctx.sparse_drop == 0, "sparse packets must suffer 0 drops");
    CHECK(ctx.sparse_ecn == 0, "sparse packets must never be ECN-marked");
    if (mode & UFQ_MODE_ECN) {
        CHECK(st.stat_codel_ecn > 0, "CoDel must ECN-mark ECT bulk flow in mode 3");
    } else {
        CHECK(st.stat_codel_drop > 0, "CoDel must drop bulk flow in mode 1");
    }
    printf("PASS test_codel_bulk_only (mode=%u, sparse=%u/%u drop=%u, codel_drop=%u codel_ecn=%u)\n",
           mode, ctx.sparse_deliv, 30u, ctx.sparse_drop, st.stat_codel_drop, st.stat_codel_ecn);
    return 0;
}

/* ---------- Unit Test 4: Hard fail-safe on stalled release timer ---------- */
static int test_failsafe_stall(void)
{
    struct ufq_state st;
    struct ufq_modem_sample ms;
    struct t1_ctx ctx;
    struct sim_pkt pkts[10];
    u32 i;

    memset(&st, 0, sizeof(st));
    memset(&ms, 0, sizeof(ms));
    memset(&ctx, 0, sizeof(ctx));
    memset(pkts, 0, sizeof(pkts));

    ufq_init(&st, 1000000u);
    st.mode = UFQ_MODE_ENABLE;
    st.failsafe_ms = 200u;

    /* Put modem way above bql_limit + sparse_headroom so nothing can release */
    ms.ram_valid = 1;
    ms.active_drbs = 1;
    ms.gipc_ch1_out = 50;
    ms.rbc_rlc_bytes = 200000;
    ms.knl_ms = 1000;
    ufq_update_modem(&st, &ms, 1000000u);

    for (i = 0; i < 6; i++) {
        pkts[i].id = i + 1;
        pkts[i].len = 1500;
        ufq_enqueue(&st, 10, &pkts[i], NULL, 1500, 0, 0, 1000000u, &t1_ops, &ctx);
    }
    ufq_drain(&st, 1000000u, &t1_ops, &ctx);
    CHECK(st.total_pkts == 6, "packets should be queued initially");
    CHECK(st.failsafe_tripped == 0, "failsafe should not trip yet");

    /* Simulate 260 ms elapsed with zero forward progress -> fail-safe must fire */
    ufq_drain(&st, 1260000u, &t1_ops, &ctx);
    CHECK(st.failsafe_tripped == 1, "failsafe must trip after stall > failsafe_ms");
    CHECK(st.mode == UFQ_MODE_OFF, "failsafe must drop to mode=0 pass-through");
    CHECK(st.total_pkts == 0, "failsafe must drain queue completely");
    CHECK(ctx.n == 6 && ctx.drops == 0, "failsafe must forward all queued pkts without loss");
    printf("PASS test_failsafe_stall (flushed=%u, mode=%u, stat_failsafe=%u)\n",
           ctx.n, st.mode, st.stat_failsafe);
    return 0;
}

/* ---------- Unit Test 5: Frozen/stale CPU1 modem RAM never stalls ---------- */
static int test_stale_modem_ram(void)
{
    struct ufq_state st;
    struct ufq_modem_sample ms;
    struct t2_ctx ctx;
    u32 t_ms;

    memset(&st, 0, sizeof(st));
    memset(&ms, 0, sizeof(ms));
    memset(&ctx, 0, sizeof(ctx));

    ufq_init(&st, 0);
    st.mode = UFQ_MODE_ENABLE;

    /* Modem RAM freezes at 30 KB (above bql_limit!) for 300 ms while gipc_ch1_out > 0 */
    ms.ram_valid = 1;
    ms.active_drbs = 1;
    ms.n4_present = 1;
    ms.n4_g_ema = 9000;
    ms.gipc_ch1_out = 5;
    ms.rbc_rlc_bytes = 30000;
    ms.knl_ms = 500;
    ufq_update_modem(&st, &ms, 1000u);

    for (t_ms = 2; t_ms <= 300; t_ms++) {
        u32 now = t_ms * 1000u;
        struct sim_pkt *p = (struct sim_pkt *)calloc(1, sizeof(*p));
        p->flow_id = 0;
        p->len = 1400;
        ufq_enqueue(&st, 4, p, NULL, 1400, 0, 0, now, &t2_ops, &ctx);
        /* Note: ms is completely frozen (same rbc_rlc_bytes=30000, same knl_ms=500) */
        ufq_update_modem(&st, &ms, now);
        ufq_drain(&st, now, &t2_ops, &ctx);
    }
    ufq_flush_all(&st, &t2_ops, &ctx, 0);

    CHECK(st.failsafe_tripped == 0, "stale modem RAM must not stall or trip failsafe");
    CHECK(st.stat_ram_stale > 200, "stale detector must recognize frozen RAM");
    CHECK(ctx.flow_bytes[0] > 350000, "local decay must keep forwarding near link rate");
    printf("PASS test_stale_modem_ram (forwarded=%llu B, stale_ticks=%u, failsafe=%u)\n",
           (unsigned long long)ctx.flow_bytes[0], st.stat_ram_stale, st.failsafe_tripped);
    return 0;
}

/* ==========================================================================
 * Test 6: Packet-Level LTE TDD Config 2 + N4 Modem + 4-Flow TCP + Sparse Sim
 *
 * Faithfully models the bench environment:
 *   - Band 48 2CC TDD Config 2: 1 UL TTI every 5 ms (200 UL TTIs/s)
 *   - Peak UL capacity: 14.5 Mbps = 9,062 B per 5 ms UL TTI
 *   - 3GPP TS 36.321 BSR table + 10 ms BSR->grant scheduling feedback delay
 *   - N4 modem: Ring 0 (<= 127 B) + Ring 1 (FIFO) + PDCP/RLC cap (16,384 B)
 *     + N4 AQM v2 (Q_target = 3 * G_ema = 27.2 KB, hard drop > 2 * Q_target,
 *       paced 1 drop/35 ms in between on pkts >= 600 B) + bo_margin = 0x140
 *   - Base RTT (idle with grant hold): 15.5 ms + TDD alignment [0..5 ms] -> ~18 ms p50
 *   - 10% UL BLER adding +10 ms 1st HARQ retx (explains bench p95 ~28-30 ms idle)
 *   - Non-coherent CPU1 RAM cache jitter (0..4 ms staleness under active load)
 *   - Traffic: 4 bulk TCP Reno/CUBIC-like upload streams + 228 B ping every 50 ms
 *     + 300 B game/VoIP every 20 ms + 512 B DNS every 250 ms
 * ========================================================================== */

static u32 bsr_table_upper(u32 bo)
{
    /* 3GPP TS 36.321 Table 6.1.3.1-1 upper bounds (bytes) */
    static const u32 tbl[64] = {
        0, 10, 12, 14, 17, 19, 22, 26, 31, 36, 42, 49, 57, 67, 78, 91,
        107, 125, 146, 171, 200, 234, 274, 321, 376, 440, 515, 603, 706, 826, 967, 1132,
        1326, 1552, 1817, 2127, 2490, 2915, 3413, 3995, 4677, 5476, 6411, 7505, 8787, 10287,
        12043, 14099, 16507, 19325, 22624, 26487, 31009, 36304, 42502, 49759, 58255, 68201,
        79846, 93479, 109439, 128125, 150000, 300000
    };
    u32 i;
    for (i = 0; i < 64; i++) {
        if (bo <= tbl[i])
            return tbl[i];
    }
    return 300000u;
}

#define MODEM_Q_CAP 512

struct modem_pkt {
    u32 len;
    u32 gen_us;
    u32 flow_idx;
    u8  is_sparse;
    u8  ecn_capable;
    u8  ecn_marked;
};

struct modem_ring {
    struct modem_pkt q[MODEM_Q_CAP];
    u32 head, tail, count, bytes;
};

static int ring_push(struct modem_ring *r, struct modem_pkt p)
{
    if (r->count >= MODEM_Q_CAP)
        return 0;
    r->q[r->tail] = p;
    r->tail = (r->tail + 1u) % MODEM_Q_CAP;
    r->count++;
    r->bytes += p.len;
    return 1;
}

static int ring_pop(struct modem_ring *r, struct modem_pkt *out)
{
    if (r->count == 0)
        return 0;
    *out = r->q[r->head];
    r->head = (r->head + 1u) % MODEM_Q_CAP;
    r->count--;
    r->bytes -= out->len;
    return 1;
}

struct tcp_flow_sim {
    double cwnd_bytes;
    u32    inflight_bytes;
    u32    next_ack_drop_us;
    u64    acked_bytes;
    u32    last_reduce_us;
};

struct lte_sim_ctx {
    struct modem_ring ring0;
    struct modem_ring ring1;
    struct modem_ring pdcp;
    u32 g_ema;
    u32 last_aqm_ms;
    u32 pdcp_lim;
    u32 bsr_pipe[2];      /* 2-TTI (10 ms) BSR -> DCI-0 -> PUSCH delay */
    u32 grant_cap_bytes;  /* 9062 B/TTI = 14.5 Mbps */
    u32 bo_margin;        /* 0x140 = 320 B */
    u32 rng;
    u64 total_ul_bytes;
    u32 n4_drops;
    u32 sparse_sent;
    u32 sparse_rx;
    u32 ping_count;
    double ping_rtts_ms[2000];
    struct tcp_flow_sim tcp[4];
    /* Cached (possibly stale) snapshot seen by Linux */
    u32 vis_ring_b;
    u32 vis_rlc_b;
    u32 vis_knl_ms;
    u32 vis_g_ema;
    u32 gipc_out;
    /* In-flight RLC AM ack release ring (50 ms t-StatusProhibit) */
    u32 rlc_ack_due_ms[64];
    u32 rlc_ack_pkts[64];
};

static u32 sim_rand(struct lte_sim_ctx *m)
{
    m->rng = m->rng * 1664525u + 1013904223u;
    return m->rng;
}

/* Modem receives one packet from Linux (N4 hook 4 + stock Ring0/Ring1) */
static void modem_rx_from_linux(struct lte_sim_ctx *m, struct modem_pkt p, u32 now_ms)
{
    u32 q_tot = m->ring0.bytes + m->ring1.bytes + m->pdcp.bytes;
    u32 q_target = m->g_ema * 3u;
    if (q_target < 20480u) q_target = 20480u;
    if (q_target > 49152u) q_target = 49152u;

    /* N4 AQM v2: only packets >= 600 B eligible */
    if (p.len >= 600u && q_tot > q_target) {
        if (q_tot > q_target * 2u) {
            m->n4_drops++;
            /* Notify sender of loss after 1 RTT */
            if (!p.is_sparse && p.flow_idx < 4) {
                struct tcp_flow_sim *tf = &m->tcp[p.flow_idx];
                if (tf->inflight_bytes >= p.len) tf->inflight_bytes -= p.len;
                if (now_ms * 1000u - tf->last_reduce_us > 25000u) {
                    tf->cwnd_bytes *= 0.7;
                    if (tf->cwnd_bytes < 4500.0) tf->cwnd_bytes = 4500.0;
                    tf->last_reduce_us = now_ms * 1000u;
                }
            }
            return;
        } else if (now_ms - m->last_aqm_ms >= 35u) {
            m->last_aqm_ms = now_ms;
            m->n4_drops++;
            if (!p.is_sparse && p.flow_idx < 4) {
                struct tcp_flow_sim *tf = &m->tcp[p.flow_idx];
                if (tf->inflight_bytes >= p.len) tf->inflight_bytes -= p.len;
                if (now_ms * 1000u - tf->last_reduce_us > 25000u) {
                    tf->cwnd_bytes *= 0.7;
                    if (tf->cwnd_bytes < 4500.0) tf->cwnd_bytes = 4500.0;
                    tf->last_reduce_us = now_ms * 1000u;
                }
            }
            return;
        }
    }

    /* Stock gipc_rx_loop: only <= 127 B goes to Ring 0; 228 B ping goes to Ring 1 */
    if (p.len <= 127u) {
        if (ring_push(&m->ring0, p))
            m->gipc_out++;
    } else {
        if (ring_push(&m->ring1, p))
            m->gipc_out++;
    }
}

/* Modem refills PDCP/RLC from Ring 0 then Ring 1 up to N4 pdcp_lim */
static void modem_refill_pdcp(struct lte_sim_ctx *m)
{
    u32 lim = m->g_ema + 4096u;
    if (lim < 16384u) lim = 16384u;
    if (lim > 24576u) lim = 24576u;
    m->pdcp_lim = lim;

    while (m->pdcp.bytes < lim) {
        struct modem_pkt p;
        if (ring_pop(&m->ring0, &p)) {
            ring_push(&m->pdcp, p);
        } else if (ring_pop(&m->ring1, &p)) {
            ring_push(&m->pdcp, p);
        } else {
            break;
        }
    }
}

static void lte_deliver_cb(void *ctx, void *pkt, void *okfn)
{
    struct lte_sim_ctx *m = (struct lte_sim_ctx *)ctx;
    struct modem_pkt *p = (struct modem_pkt *)pkt;
    u32 now_ms = (u32)(uintptr_t)okfn;
    modem_rx_from_linux(m, *p, now_ms);
    modem_refill_pdcp(m);
    free(p);
}

static void lte_drop_cb(void *ctx, void *pkt)
{
    struct lte_sim_ctx *m = (struct lte_sim_ctx *)ctx;
    struct modem_pkt *p = (struct modem_pkt *)pkt;
    if (!p->is_sparse && p->flow_idx < 4) {
        struct tcp_flow_sim *tf = &m->tcp[p->flow_idx];
        if (tf->inflight_bytes >= p->len) tf->inflight_bytes -= p->len;
        if (m->vis_knl_ms * 1000u - tf->last_reduce_us > 25000u) {
            tf->cwnd_bytes *= 0.7;
            if (tf->cwnd_bytes < 4500.0) tf->cwnd_bytes = 4500.0;
            tf->last_reduce_us = m->vis_knl_ms * 1000u;
        }
    }
    free(p);
}

static int lte_ecn_cb(void *ctx, void *pkt)
{
    struct lte_sim_ctx *m = (struct lte_sim_ctx *)ctx;
    struct modem_pkt *p = (struct modem_pkt *)pkt;
    if (!p->ecn_capable)
        return 0;
    p->ecn_marked = 1;
    if (!p->is_sparse && p->flow_idx < 4) {
        struct tcp_flow_sim *tf = &m->tcp[p->flow_idx];
        if (m->vis_knl_ms * 1000u - tf->last_reduce_us > 25000u) {
            tf->cwnd_bytes *= 0.7;
            if (tf->cwnd_bytes < 4500.0) tf->cwnd_bytes = 4500.0;
            tf->last_reduce_us = m->vis_knl_ms * 1000u;
        }
    }
    return 1;
}

static const struct ufq_ops lte_ops = { lte_deliver_cb, lte_drop_cb, lte_ecn_cb };

static int cmp_double(const void *a, const void *b)
{
    double da = *(const double *)a, db = *(const double *)b;
    return (da < db) ? -1 : (da > db) ? 1 : 0;
}

struct sim_result {
    double mbps;
    double p50_ms;
    double p95_ms;
    double max_ms;
    u32    sparse_lost;
    u32    codel_drops;
    u32    codel_ecn;
    u32    n4_drops;
    double jain;
};

static struct sim_result run_lte_scenario(u32 ufq_mode, u32 bql_mult_q4, u32 ecn_flows)
{
    struct ufq_state st;
    struct lte_sim_ctx m;
    struct ufq_modem_sample ms;
    struct sim_result res;
    u32 t_ms, f, i;
    const u32 sim_ms = 20000u; /* 20 s run (matching bench 20 s upload) */
    const u32 warmup_ms = 2000u;

    memset(&st, 0, sizeof(st));
    memset(&m, 0, sizeof(m));
    memset(&ms, 0, sizeof(ms));
    memset(&res, 0, sizeof(res));

    ufq_init(&st, 0);
    st.mode = ufq_mode;
    st.bql_mult_q4 = bql_mult_q4;

    m.grant_cap_bytes = 9062u; /* 14.5 Mbps on 200 UL TTIs/s */
    m.g_ema = 9062u;
    m.bo_margin = 0x140u;
    m.bsr_pipe[0] = 9062u;
    m.bsr_pipe[1] = 9062u;
    m.rng = 0x12345678u;

    for (f = 0; f < 4; f++) {
        m.tcp[f].cwnd_bytes = 15000.0;
    }

    for (t_ms = 1; t_ms <= sim_ms; t_ms++) {
        u32 now_us = t_ms * 1000u;

        /* 1. Release RLC AM ACKed IRBs (50 ms t-StatusProhibit) */
        for (i = 0; i < 64; i++) {
            if (m.rlc_ack_pkts[i] > 0 && m.rlc_ack_due_ms[i] <= t_ms) {
                if (m.gipc_out >= m.rlc_ack_pkts[i])
                    m.gipc_out -= m.rlc_ack_pkts[i];
                else
                    m.gipc_out = 0;
                m.rlc_ack_pkts[i] = 0;
            }
        }

        /* 2. UL TTI every 5 ms (TDD Config 2: SF 2 and SF 7) */
        if (t_ms % 5u == 0u) {
            u32 grant = m.bsr_pipe[0];
            u32 sent_this_tti = 0;
            u32 pkts_sent = 0;
            u32 rem_bo, next_grant;

            modem_refill_pdcp(&m);
            while (m.pdcp.count > 0 && sent_this_tti + m.pdcp.q[m.pdcp.head].len <= grant) {
                struct modem_pkt p;
                ring_pop(&m.pdcp, &p);
                sent_this_tti += p.len;
                pkts_sent++;
                if (t_ms > warmup_ms)
                    m.total_ul_bytes += p.len;

                if (p.is_sparse) {
                    /* Compute full ping RTT: queue wait + 15.5 ms base + 10% HARQ (+10 ms) */
                    double wait_ms = (double)(now_us - p.gen_us) / 1000.0;
                    double harq_ms = ((sim_rand(&m) % 100u) < 10u) ? 10.0 : 0.0;
                    double jitter_ms = ((double)(sim_rand(&m) % 200u) / 100.0) - 1.0;
                    double rtt = 15.5 + wait_ms + harq_ms + jitter_ms;
                    if (t_ms > warmup_ms && p.len == 228u && m.ping_count < 2000u) {
                        m.ping_rtts_ms[m.ping_count++] = rtt;
                    }
                    m.sparse_rx++;
                } else if (p.flow_idx < 4) {
                    struct tcp_flow_sim *tf = &m.tcp[p.flow_idx];
                    if (tf->inflight_bytes >= p.len)
                        tf->inflight_bytes -= p.len;
                    if (t_ms > warmup_ms)
                        tf->acked_bytes += p.len;
                    /* CUBIC/Reno gentle cwnd growth */
                    tf->cwnd_bytes += (1448.0 * 1448.0) / (tf->cwnd_bytes > 1448.0 ? tf->cwnd_bytes : 1448.0);
                    if (tf->cwnd_bytes > 180000.0)
                        tf->cwnd_bytes = 180000.0;
                }
            }
            /* Record RLC AM ACK release 50 ms later */
            if (pkts_sent > 0) {
                u32 slot = (t_ms / 5u) & 63u;
                m.rlc_ack_due_ms[slot] = t_ms + 50u;
                m.rlc_ack_pkts[slot] += pkts_sent;
            }
            /* Update N4 G_ema (EWMA of TB size) */
            if (sent_this_tti > 0)
                m.g_ema = (m.g_ema * 7u + grant) >> 3;

            /* Build BSR from REMAINING buffer after TB + bo_margin (3GPP TS 36.321) */
            modem_refill_pdcp(&m);
            rem_bo = m.ring0.bytes + m.ring1.bytes + m.pdcp.bytes + m.bo_margin;
            /* eNB grants min(link_cap, BSR_upper(rem_bo) + small eNB over-allocation 15%) */
            next_grant = bsr_table_upper(rem_bo);
            next_grant = (next_grant * 115u) / 100u;
            if (next_grant > m.grant_cap_bytes)
                next_grant = m.grant_cap_bytes;
            if (next_grant < 400u)
                next_grant = 400u; /* grant hold standing floor */

            m.bsr_pipe[0] = m.bsr_pipe[1];
            m.bsr_pipe[1] = next_grant;
        }

        /* 3. Simulate CPU1 non-coherent L1 D-cache eviction (70% chance fresh each ms under load) */
        if ((sim_rand(&m) % 100u) < 70u) {
            m.vis_ring_b = m.ring0.bytes + m.ring1.bytes;
            m.vis_rlc_b  = m.pdcp.bytes;
            m.vis_knl_ms = t_ms;
            m.vis_g_ema  = m.g_ema;
        }

        ms.ram_valid      = 1;
        ms.active_drbs    = 1;
        ms.n4_present     = 1;
        ms.rbc_ring_bytes = m.vis_ring_b;
        ms.rbc_rlc_bytes  = m.vis_rlc_b;
        ms.mac_ul_bo      = m.vis_ring_b + m.vis_rlc_b;
        ms.knl_ms         = m.vis_knl_ms;
        ms.n4_g_ema       = m.vis_g_ema;
        ms.gipc_ch1_out   = (u16)m.gipc_out;

        ufq_update_modem(&st, &ms, now_us);

        /* 4. Generate 4 bulk TCP upload flows */
        for (f = 0; f < 4; f++) {
            struct tcp_flow_sim *tf = &m.tcp[f];
            u32 burst = 0;
            while (tf->inflight_bytes + 1500u <= (u32)tf->cwnd_bytes && burst < 4u) {
                struct modem_pkt *p = (struct modem_pkt *)calloc(1, sizeof(*p));
                p->len = 1500u;
                p->gen_us = now_us;
                p->flow_idx = f;
                p->is_sparse = 0;
                p->ecn_capable = ecn_flows ? 1u : 0u;
                tf->inflight_bytes += 1500u;
                burst++;

                if (ufq_mode == UFQ_MODE_OFF) {
                    modem_rx_from_linux(&m, *p, t_ms);
                    modem_refill_pdcp(&m);
                    free(p);
                } else {
                    u16 fid = (u16)(10u + f * 7u);
                    ufq_enqueue(&st, fid, p, (void *)(uintptr_t)t_ms, 1500u,
                                p->ecn_capable, 0, now_us, &lte_ops, &m);
                }
            }
        }

        /* 5. Generate sparse traffic:
         *    - 228 B ping every 53 ms (non-harmonic with 5 ms TDD -> uniform phase!)
         *    - 300 B game/VoIP packet every 23 ms
         *    - 512 B DNS/TLS packet every 251 ms */
        if (t_ms % 53u == 0u) {
            struct modem_pkt *p = (struct modem_pkt *)calloc(1, sizeof(*p));
            /* Random sub-ms arrival offset [0..999 us] */
            u32 sub_us = sim_rand(&m) % 1000u;
            p->len = 228u;
            p->gen_us = now_us + sub_us;
            p->flow_idx = 10;
            p->is_sparse = 1;
            m.sparse_sent++;
            if (ufq_mode == UFQ_MODE_OFF) {
                modem_rx_from_linux(&m, *p, t_ms);
                modem_refill_pdcp(&m);
                free(p);
            } else {
                ufq_enqueue(&st, 41u, p, (void *)(uintptr_t)t_ms, 228u, 0, 1,
                            now_us, &lte_ops, &m);
            }
        }
        if (t_ms % 23u == 0u) {
            struct modem_pkt *p = (struct modem_pkt *)calloc(1, sizeof(*p));
            p->len = 300u;
            p->gen_us = now_us;
            p->flow_idx = 11;
            p->is_sparse = 1;
            m.sparse_sent++;
            if (ufq_mode == UFQ_MODE_OFF) {
                modem_rx_from_linux(&m, *p, t_ms);
                modem_refill_pdcp(&m);
                free(p);
            } else {
                ufq_enqueue(&st, 42u, p, (void *)(uintptr_t)t_ms, 300u, 0, 0,
                            now_us, &lte_ops, &m);
            }
        }
        if (t_ms % 251u == 0u) {
            struct modem_pkt *p = (struct modem_pkt *)calloc(1, sizeof(*p));
            p->len = 512u;
            p->gen_us = now_us;
            p->flow_idx = 12;
            p->is_sparse = 1;
            m.sparse_sent++;
            if (ufq_mode == UFQ_MODE_OFF) {
                modem_rx_from_linux(&m, *p, t_ms);
                modem_refill_pdcp(&m);
                free(p);
            } else {
                ufq_enqueue(&st, 43u, p, (void *)(uintptr_t)t_ms, 512u, 0, 0,
                            now_us, &lte_ops, &m);
            }
        }

        /* 6. 1 ms host release timer */
        if (ufq_mode != UFQ_MODE_OFF) {
            ufq_drain(&st, now_us, &lte_ops, &m);
        }
    }

    ufq_flush_all(&st, &lte_ops, &m, 0);

    qsort(m.ping_rtts_ms, m.ping_count, sizeof(double), cmp_double);
    res.mbps = ((double)m.total_ul_bytes * 8.0) / ((double)(sim_ms - warmup_ms) * 1000.0);
    if (m.ping_count > 0) {
        res.p50_ms = m.ping_rtts_ms[(u32)(0.50 * (m.ping_count - 1))];
        res.p95_ms = m.ping_rtts_ms[(u32)(0.95 * (m.ping_count - 1))];
        res.max_ms = m.ping_rtts_ms[m.ping_count - 1];
    }
    res.sparse_lost = (m.sparse_sent > m.sparse_rx + 2u) ? (m.sparse_sent - m.sparse_rx - 2u) : 0u;
    res.codel_drops = st.stat_codel_drop;
    res.codel_ecn   = st.stat_codel_ecn;
    res.n4_drops    = m.n4_drops;

    {
        double s = 0.0, s2 = 0.0;
        for (f = 0; f < 4; f++) {
            double b = (double)m.tcp[f].acked_bytes;
            s += b; s2 += b * b;
        }
        res.jain = (s2 > 0.0) ? ((s * s) / (4.0 * s2)) : 1.0;
    }
    return res;
}

int main(void)
{
    struct sim_result base, ufq1, ufq3;
    double loss_pct1, loss_pct3;

    if (test_sparse_overtakes_bulk() != 0) return 1;
    if (test_drr_fairness() != 0) return 1;
    if (test_codel_bulk_only(UFQ_MODE_ENABLE) != 0) return 1;
    if (test_codel_bulk_only(UFQ_MODE_ENABLE | UFQ_MODE_ECN) != 0) return 1;
    if (test_failsafe_stall() != 0) return 1;
    if (test_stale_modem_ram() != 0) return 1;

    base = run_lte_scenario(UFQ_MODE_OFF, UFQ_DEF_BQL_MULT_Q4, 0);
    ufq1 = run_lte_scenario(UFQ_MODE_ENABLE, UFQ_DEF_BQL_MULT_Q4, 0);
    ufq3 = run_lte_scenario(UFQ_MODE_ENABLE | UFQ_MODE_ECN, UFQ_DEF_BQL_MULT_Q4, 1);

    loss_pct1 = 100.0 * (base.mbps - ufq1.mbps) / base.mbps;
    loss_pct3 = 100.0 * (base.mbps - ufq3.mbps) / base.mbps;

    printf("SIM baseline (N4 only):  ul=%.2f Mbps  ping p50=%.1f ms  p95=%.1f ms  max=%.1f ms  n4_drops=%u  jain=%.3f\n",
           base.mbps, base.p50_ms, base.p95_ms, base.max_ms, base.n4_drops, base.jain);
    printf("SIM titan_ufq mode 1:    ul=%.2f Mbps (loss %.2f%%)  ping p50=%.1f ms  p95=%.1f ms  max=%.1f ms  sparse_lost=%u  codel_drop=%u  n4_drops=%u  jain=%.3f\n",
           ufq1.mbps, loss_pct1, ufq1.p50_ms, ufq1.p95_ms, ufq1.max_ms,
           ufq1.sparse_lost, ufq1.codel_drops, ufq1.n4_drops, ufq1.jain);
    printf("SIM titan_ufq mode 3:    ul=%.2f Mbps (loss %.2f%%)  ping p50=%.1f ms  p95=%.1f ms  max=%.1f ms  sparse_lost=%u  codel_ecn=%u  n4_drops=%u  jain=%.3f\n",
           ufq3.mbps, loss_pct3, ufq3.p50_ms, ufq3.p95_ms, ufq3.max_ms,
           ufq3.sparse_lost, ufq3.codel_ecn, ufq3.n4_drops, ufq3.jain);

    {
        /* Sensitivity sweep across bql_mult_q4 for documentation */
        const u32 mults[4] = { 24u, 26u, 28u, 30u };
        u32 k;
        for (k = 0; k < 4; k++) {
            struct sim_result r = run_lte_scenario(UFQ_MODE_ENABLE, mults[k], 0);
            double lp = 100.0 * (base.mbps - r.mbps) / base.mbps;
            printf("SWEEP bql_mult_q4=%u (%.3fx): ul=%.2f Mbps (loss %.2f%%) p50=%.1f ms p95=%.1f ms max=%.1f ms\n",
                   mults[k], (double)mults[k] / 16.0, r.mbps, lp, r.p50_ms, r.p95_ms, r.max_ms);
        }
    }

    CHECK(ufq1.p50_ms <= 23.0, "mode 1 ping p50 must be <= 23.0 ms");
    CHECK(ufq1.p95_ms <= 35.0, "mode 1 ping p95 must be <= 35.0 ms");
    CHECK(loss_pct1 <= 3.0,    "mode 1 UL throughput loss must be <= 3.0%");
    CHECK(ufq1.sparse_lost == 0, "mode 1 sparse loss must be 0");
    CHECK(ufq1.jain >= 0.95,   "mode 1 bulk fairness must be >= 0.95");

    CHECK(ufq3.p50_ms <= 23.0, "mode 3 ping p50 must be <= 23.0 ms");
    CHECK(ufq3.p95_ms <= 35.0, "mode 3 ping p95 must be <= 35.0 ms");
    CHECK(loss_pct3 <= 3.0,    "mode 3 UL throughput loss must be <= 3.0%");
    CHECK(ufq3.sparse_lost == 0, "mode 3 sparse loss must be 0");

    printf("ALL UFQ SELF-TESTS AND LTE SIMULATIONS PASSED\n");
    return 0;
}
