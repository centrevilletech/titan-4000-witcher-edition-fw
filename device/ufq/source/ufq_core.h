/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright 2026 Centreville Tech, LLC. Uplink flow queue core for Titan 4000 Witcher Edition. */
/*
 * ufq_core.h - Per-flow DRR + sparse-flow fast-pass + bulk-only CoDel +
 * hybrid modem-backlog BQL ("BQL for the modem").
 *
 * Shared verbatim between titan_ufq.c (Linux 3.10.0-uc0 kernel module) and
 * test_ufq_sim.c (userspace self-test and LTE TDD Config 2 simulator).
 * Zero dynamic allocation; bounded O(1) packet path.
 */
#ifndef TITAN_UFQ_CORE_H
#define TITAN_UFQ_CORE_H

#define UFQ_NUM_FLOWS        64u   /* power of 2 */
#define UFQ_FLOW_MASK        (UFQ_NUM_FLOWS - 1u)
#define UFQ_MAX_PKTS         256u  /* static packet descriptor pool */
#define UFQ_NIL              0xffffu

/* Mode bitmask */
#define UFQ_MODE_OFF         0u    /* strict pass-through (default at load) */
#define UFQ_MODE_ENABLE      1u    /* FQ + sparse fast-pass + modem BQL + bulk CoDel */
#define UFQ_MODE_ECN         2u    /* mark ECT bulk pkts CE instead of dropping */
#define UFQ_MODE_NO_RAM      4u    /* ignore modem RAM (use GIPC + local rate only) */
#define UFQ_MODE_MAX         7u

/* Flow list membership */
#define UFQ_LIST_NONE        0u
#define UFQ_LIST_NEW         1u    /* sparse-flow fast-pass list */
#define UFQ_LIST_OLD         2u    /* bulk DRR list (CoDel active) */

/* Default parameters */
#define UFQ_DEF_QUANTUM          1500u   /* L3 MTU at NF_BR_FORWARD (1 full bulk pkt demotes to old_flows) */
#define UFQ_DEF_CODEL_TARGET_US  5000u   /* 5 ms CoDel target */
#define UFQ_DEF_CODEL_INTVL_US   100000u /* 100 ms CoDel interval */
#define UFQ_DEF_BQL_MULT_Q4      28u     /* 1.75 x G_ema (~15.9 KB at 14.5 Mbps; BSR-safe + <23 ms p50) */
#define UFQ_DEF_BQL_MIN_B        12288u  /* 12 KB floor (prevents BSR collapse) */
#define UFQ_DEF_BQL_MAX_B        36864u  /* 36 KB cap */
#define UFQ_DEF_SPARSE_HEADROOM  16384u  /* sparse bypass headroom above bql_limit */
#define UFQ_DEF_FAILSAFE_MS      250u    /* hard fail-safe if queued with no progress */
#define UFQ_DEF_TTI_MS           5u      /* TDD Config 2 UL period (200 UL TTIs/s) */
#define UFQ_DEF_RATE_BPMS        1800u   /* initial prior: ~14.4 Mbps = 1800 B/ms */
#define UFQ_MIN_RATE_BPMS        128u    /* 1.0 Mbps floor (prevents stall) */
#define UFQ_MAX_RATE_BPMS        15000u  /* 120 Mbps cap */
#define UFQ_MAX_BURST_PER_DRAIN  24u     /* bound per-call softirq work */

/* Snapshot of modem/driver signals passed into ufq_update_modem() */
struct ufq_modem_sample {
    u32 rbc_ring_bytes;   /* sum of active AM DRB rbc+0x130 */
    u32 rbc_rlc_bytes;    /* sum of active AM DRB rbc+0x10c */
    u32 mac_ul_bo;        /* VA_MAC_UL_BO 0x84d62c70 */
    u32 knl_ms;           /* TTI_CLK_VA   0x84a1f860 */
    u32 n4_g_ema;         /* N4 ST_G_EMA  0x847ed62c (0 if N4 absent) */
    u32 n4_q_true;        /* N4 ST_LAST_Q_TRUE 0x847ed654 */
    u16 gipc_ch1_out;     /* SCU-coherent gipc+0x8c outstanding TX IRBs */
    u8  active_drbs;      /* number of active AM DRB slots found */
    u8  n4_present;       /* 1 if N4/N3R magic matched */
    u8  ram_valid;        /* 1 if ioremap succeeded and !(mode & NO_RAM) */
};

struct ufq_pkt_slot {
    void *pkt;
    void *okfn;
    u32   len;
    u32   enq_us;
    u16   next;
    u8    ecn_capable;    /* 1 if ECT(0) or ECT(1) */
    u8    never_drop;     /* 1 for ICMPv6 ND, DHCP, tiny control */
};

struct ufq_flow {
    u16  head;
    u16  tail;
    u16  q_pkts;
    u16  list_next;
    u16  list_prev;
    u32  q_bytes;
    s32  deficit;
    u8   list_id;         /* UFQ_LIST_NONE / NEW / OLD */
    /* Per-flow CoDel state (RFC 8289, bulk old_flows only) */
    u8   codel_dropping;
    u16  codel_count;
    u32  codel_first_above_us;
    u32  codel_drop_next_us;
    u32  codel_last_count;
};

struct ufq_list {
    u16 head;
    u16 tail;
    u16 count;
};

struct ufq_ops {
    void (*deliver)(void *ctx, void *pkt, void *okfn);
    void (*drop)(void *ctx, void *pkt);
    int  (*mark_ecn)(void *ctx, void *pkt); /* returns 1 if marked CE */
};

struct ufq_state {
    u32 mode;
    u32 failsafe_tripped;

    /* Tunables */
    u32 quantum;
    u32 codel_target_us;
    u32 codel_interval_us;
    u32 bql_mult_q4;       /* bql_limit = (g_bytes * bql_mult_q4) >> 4 */
    u32 bql_min_bytes;
    u32 bql_max_bytes;
    u32 sparse_headroom;
    u32 failsafe_ms;
    u32 tti_ms;
    u32 pace_enable;
    u32 pace_gain_q4;      /* default 24 = 1.5x rate_bpms during late-TTI refill */
    u32 tti_hold_us;       /* post-TTI bulk holdoff (us) to keep Q_modem < 1 TTI early */
    u32 max_pkts;          /* <= UFQ_MAX_PKTS */

    /* Modem backlog & rate estimator */
    u32 q_est_bytes;       /* fused local + modem backlog estimate */
    u32 q_raw_last;        /* last raw rbc_ring + rbc_rlc */
    u32 q_raw_prev_anchor; /* previous q_raw when changed */
    u32 mac_bo_last;
    u32 knl_ms_last;
    u32 n4_g_ema_last;
    u16 gipc_out_last;
    u8  active_drbs_last;
    u8  n4_present_last;

    u32 g_bytes;           /* estimated bytes per UL TTI */
    u32 bql_limit;         /* bulk release threshold in bytes */
    u32 rate_bpms;         /* smoothed UL delivery rate in bytes/ms */
    s32 pace_budget;       /* paced bulk release token bucket in bytes */

    /* Timestamps (monotonic microseconds, wraps safely via unsigned diff) */
    u32 last_update_us;
    u32 last_fresh_us;
    u32 last_tti_drain_us;
    u32 last_progress_us;
    u32 win_start_us;
    u32 win_released_bytes;
    u32 win_q_start_bytes;
    u32 win_busy_us;

    /* Queues and descriptor pool */
    struct ufq_flow     flows[UFQ_NUM_FLOWS];
    struct ufq_pkt_slot slots[UFQ_MAX_PKTS];
    struct ufq_list     new_flows;
    struct ufq_list     old_flows;
    u16                 free_head;
    u16                 total_pkts;
    u32                 total_bytes;

    /* Telemetry counters */
    u32 stat_enq_pkts;
    u32 stat_deq_sparse;
    u32 stat_deq_bulk;
    u32 stat_codel_drop;
    u32 stat_codel_ecn;
    u32 stat_overlimit_drop;
    u32 stat_passthrough;
    u32 stat_ram_fresh;
    u32 stat_ram_stale;
    u32 stat_gipc_zero_snap;
    u32 stat_failsafe;
    u32 stat_netdev_drop;
    u32 stat_max_q_pkts;
    u32 stat_max_q_bytes;
};

static inline u32 ufq_isqrt32(u32 n)
{
    u32 x = n;
    u32 c = 0;
    u32 d = 1u << 30;
    while (d > x)
        d >>= 2;
    while (d != 0u) {
        if (x >= c + d) {
            x -= c + d;
            c = (c >> 1) + d;
        } else {
            c >>= 1;
        }
        d >>= 2;
    }
    return c ? c : 1u;
}

static inline u32 ufq_hash_5tuple(u8 proto, u32 saddr, u32 daddr, u16 sport, u16 dport)
{
    u32 h = 0x811c9dc5u;
    h ^= (u32)proto;                    h *= 0x01000193u;
    h ^= saddr;                         h *= 0x01000193u;
    h ^= daddr;                         h *= 0x01000193u;
    h ^= ((u32)sport << 16) | dport;    h *= 0x01000193u;
    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    return h & UFQ_FLOW_MASK;
}

static inline void ufq_list_init(struct ufq_list *l)
{
    l->head = UFQ_NIL;
    l->tail = UFQ_NIL;
    l->count = 0;
}

static inline void ufq_list_push_tail(struct ufq_state *st, struct ufq_list *l, u16 fid, u8 list_id)
{
    struct ufq_flow *f = &st->flows[fid];
    f->list_id = list_id;
    f->list_next = UFQ_NIL;
    f->list_prev = l->tail;
    if (l->tail != UFQ_NIL)
        st->flows[l->tail].list_next = fid;
    else
        l->head = fid;
    l->tail = fid;
    l->count++;
}

static inline void ufq_list_remove(struct ufq_state *st, struct ufq_list *l, u16 fid)
{
    struct ufq_flow *f = &st->flows[fid];
    if (f->list_prev != UFQ_NIL)
        st->flows[f->list_prev].list_next = f->list_next;
    else
        l->head = f->list_next;
    if (f->list_next != UFQ_NIL)
        st->flows[f->list_next].list_prev = f->list_prev;
    else
        l->tail = f->list_prev;
    f->list_next = UFQ_NIL;
    f->list_prev = UFQ_NIL;
    f->list_id = UFQ_LIST_NONE;
    if (l->count > 0)
        l->count--;
}

static inline void ufq_init(struct ufq_state *st, u32 now_us)
{
    u32 i;
    /* Caller zeros *st or we initialize every field explicitly */
    st->mode              = UFQ_MODE_OFF;
    st->failsafe_tripped  = 0;

    st->quantum           = UFQ_DEF_QUANTUM;
    st->codel_target_us   = UFQ_DEF_CODEL_TARGET_US;
    st->codel_interval_us = UFQ_DEF_CODEL_INTVL_US;
    st->bql_mult_q4       = UFQ_DEF_BQL_MULT_Q4;
    st->bql_min_bytes     = UFQ_DEF_BQL_MIN_B;
    st->bql_max_bytes     = UFQ_DEF_BQL_MAX_B;
    st->sparse_headroom   = UFQ_DEF_SPARSE_HEADROOM;
    st->failsafe_ms       = UFQ_DEF_FAILSAFE_MS;
    st->tti_ms            = UFQ_DEF_TTI_MS;
    st->pace_enable       = 1u;    /* smooth refill across 5 ms UL TTI */
    st->pace_gain_q4      = 24u;   /* 1.5x refills 1 TTI cleanly after short post-TTI holdoff */
    st->tti_hold_us       = 1200u; /* 1.2 ms post-TTI bulk holdoff keeps Q_modem < 1 TTI early */
    st->max_pkts          = UFQ_MAX_PKTS;

    st->q_est_bytes       = 0;
    st->q_raw_last        = 0;
    st->q_raw_prev_anchor = 0;
    st->mac_bo_last       = 0;
    st->knl_ms_last       = 0;
    st->n4_g_ema_last     = 0;
    st->gipc_out_last     = 0;
    st->active_drbs_last  = 0;
    st->n4_present_last   = 0;

    st->rate_bpms         = UFQ_DEF_RATE_BPMS;
    st->g_bytes           = UFQ_DEF_RATE_BPMS * UFQ_DEF_TTI_MS;
    st->bql_limit         = (st->g_bytes * st->bql_mult_q4) >> 4;
    st->pace_budget       = (s32)UFQ_DEF_QUANTUM * 2;

    st->last_update_us    = now_us;
    st->last_fresh_us     = now_us;
    st->last_tti_drain_us = now_us - 100000u;
    st->last_progress_us  = now_us;
    st->win_start_us      = now_us;
    st->win_released_bytes = 0;
    st->win_q_start_bytes = 0;
    st->win_busy_us       = 0;

    ufq_list_init(&st->new_flows);
    ufq_list_init(&st->old_flows);

    for (i = 0; i < UFQ_NUM_FLOWS; i++) {
        st->flows[i].head = UFQ_NIL;
        st->flows[i].tail = UFQ_NIL;
        st->flows[i].q_pkts = 0;
        st->flows[i].list_next = UFQ_NIL;
        st->flows[i].list_prev = UFQ_NIL;
        st->flows[i].q_bytes = 0;
        st->flows[i].deficit = 0;
        st->flows[i].list_id = UFQ_LIST_NONE;
        st->flows[i].codel_dropping = 0;
        st->flows[i].codel_count = 0;
        st->flows[i].codel_first_above_us = 0;
        st->flows[i].codel_drop_next_us = 0;
        st->flows[i].codel_last_count = 0;
    }

    for (i = 0; i < UFQ_MAX_PKTS; i++) {
        st->slots[i].pkt = NULL;
        st->slots[i].okfn = NULL;
        st->slots[i].len = 0;
        st->slots[i].enq_us = 0;
        st->slots[i].next = (i + 1u < UFQ_MAX_PKTS) ? (u16)(i + 1u) : UFQ_NIL;
        st->slots[i].ecn_capable = 0;
        st->slots[i].never_drop = 0;
    }
    st->free_head   = 0;
    st->total_pkts  = 0;
    st->total_bytes = 0;

    st->stat_enq_pkts       = 0;
    st->stat_deq_sparse     = 0;
    st->stat_deq_bulk       = 0;
    st->stat_codel_drop     = 0;
    st->stat_codel_ecn      = 0;
    st->stat_overlimit_drop = 0;
    st->stat_passthrough    = 0;
    st->stat_ram_fresh      = 0;
    st->stat_ram_stale      = 0;
    st->stat_gipc_zero_snap = 0;
    st->stat_failsafe       = 0;
    st->stat_netdev_drop    = 0;
    st->stat_max_q_pkts     = 0;
    st->stat_max_q_bytes    = 0;
}

static inline u16 ufq_alloc_slot(struct ufq_state *st)
{
    u16 idx = st->free_head;
    if (idx == UFQ_NIL)
        return UFQ_NIL;
    st->free_head = st->slots[idx].next;
    st->slots[idx].next = UFQ_NIL;
    return idx;
}

static inline void ufq_free_slot(struct ufq_state *st, u16 idx)
{
    st->slots[idx].pkt = NULL;
    st->slots[idx].okfn = NULL;
    st->slots[idx].next = st->free_head;
    st->free_head = idx;
}

static inline void ufq_flow_push(struct ufq_state *st, u16 fid, u16 sidx)
{
    struct ufq_flow *f = &st->flows[fid];
    st->slots[sidx].next = UFQ_NIL;
    if (f->tail != UFQ_NIL)
        st->slots[f->tail].next = sidx;
    else
        f->head = sidx;
    f->tail = sidx;
    f->q_pkts++;
    f->q_bytes += st->slots[sidx].len;
    st->total_pkts++;
    st->total_bytes += st->slots[sidx].len;
    if (st->total_pkts > st->stat_max_q_pkts)
        st->stat_max_q_pkts = st->total_pkts;
    if (st->total_bytes > st->stat_max_q_bytes)
        st->stat_max_q_bytes = st->total_bytes;
}

static inline u16 ufq_flow_pop(struct ufq_state *st, u16 fid)
{
    struct ufq_flow *f = &st->flows[fid];
    u16 sidx = f->head;
    if (sidx == UFQ_NIL)
        return UFQ_NIL;
    f->head = st->slots[sidx].next;
    if (f->head == UFQ_NIL)
        f->tail = UFQ_NIL;
    st->slots[sidx].next = UFQ_NIL;
    if (f->q_pkts > 0)
        f->q_pkts--;
    if (f->q_bytes >= st->slots[sidx].len)
        f->q_bytes -= st->slots[sidx].len;
    else
        f->q_bytes = 0;
    if (st->total_pkts > 0)
        st->total_pkts--;
    if (st->total_bytes >= st->slots[sidx].len)
        st->total_bytes -= st->slots[sidx].len;
    else
        st->total_bytes = 0;
    return sidx;
}

/* Flush every queued packet in priority order (sparse first, then bulk) */
static inline void ufq_flush_all(struct ufq_state *st,
                                 const struct ufq_ops *ops,
                                 void *ctx,
                                 int deliver)
{
    u32 pass;
    for (pass = 0; pass < 2u; pass++) {
        struct ufq_list *lst = (pass == 0u) ? &st->new_flows : &st->old_flows;
        while (lst->head != UFQ_NIL) {
            u16 fid = lst->head;
            struct ufq_flow *f = &st->flows[fid];
            ufq_list_remove(st, lst, fid);
            while (f->head != UFQ_NIL) {
                u16 sidx = ufq_flow_pop(st, fid);
                void *pkt = st->slots[sidx].pkt;
                void *okfn = st->slots[sidx].okfn;
                ufq_free_slot(st, sidx);
                if (pkt) {
                    if (deliver)
                        ops->deliver(ctx, pkt, okfn);
                    else
                        ops->drop(ctx, pkt);
                }
            }
            f->codel_dropping = 0;
            f->codel_first_above_us = 0;
        }
    }
    /* Defensive sweep in case any flow became detached from lists */
    {
        u32 i;
        for (i = 0; i < UFQ_NUM_FLOWS; i++) {
            struct ufq_flow *f = &st->flows[i];
            while (f->head != UFQ_NIL) {
                u16 sidx = ufq_flow_pop(st, (u16)i);
                void *pkt = st->slots[sidx].pkt;
                void *okfn = st->slots[sidx].okfn;
                ufq_free_slot(st, sidx);
                if (pkt) {
                    if (deliver)
                        ops->deliver(ctx, pkt, okfn);
                    else
                        ops->drop(ctx, pkt);
                }
            }
            f->list_id = UFQ_LIST_NONE;
            f->list_next = UFQ_NIL;
            f->list_prev = UFQ_NIL;
            f->codel_dropping = 0;
            f->codel_first_above_us = 0;
        }
    }
    st->total_pkts = 0;
    st->total_bytes = 0;
}

static inline void ufq_trip_failsafe(struct ufq_state *st,
                                     const struct ufq_ops *ops,
                                     void *ctx)
{
    st->failsafe_tripped = 1u;
    st->mode = UFQ_MODE_OFF;
    st->stat_failsafe++;
    ufq_flush_all(st, ops, ctx, 1);
}

/*
 * Update fused modem backlog estimate (q_est_bytes), UL grant size (g_bytes),
 * dynamic BQL limit (bql_limit), and paced refill budget.
 */
static inline void ufq_update_modem(struct ufq_state *st,
                                    const struct ufq_modem_sample *s,
                                    u32 now_us)
{
    u32 dt_us = now_us - st->last_update_us;
    u32 q_raw;
    u32 drain_b;
    u32 win_dt;
    u32 pace_cap;

    if (dt_us > 1000000u)
        dt_us = 1000000u; /* clamp after long idle */
    st->last_update_us = now_us;

    /* 1. Continuous local decay of projected modem backlog (no 64-bit div) */
    drain_b = (u32)(((u64)st->rate_bpms * (u64)dt_us) >> 10);
    if (drain_b >= st->q_est_bytes)
        st->q_est_bytes = 0;
    else
        st->q_est_bytes -= drain_b;

    /* Refill paced bulk token bucket smoothly across the 5 ms UL TTI.
     * Do not hoard burst credit while blocked at bql_limit, so post-TTI
     * refill starts smoothly (keeping Q_modem < 1 TTI for the first ~2 ms
     * so arriving sparse flows catch the very next UL TTI). */
    if (st->pace_enable) {
        u32 pace_rate = (st->rate_bpms * st->pace_gain_q4) >> 4;
        u32 add_b;
        if (pace_rate < UFQ_MIN_RATE_BPMS)
            pace_rate = UFQ_MIN_RATE_BPMS;
        add_b = (u32)(((u64)pace_rate * (u64)dt_us) >> 10);
        if (st->q_est_bytes >= st->bql_limit) {
            pace_cap = 0u;
        } else {
            pace_cap = st->g_bytes >> 1;
            if (pace_cap < st->quantum * 2u)
                pace_cap = st->quantum * 2u;
        }
        st->pace_budget += (s32)add_b;
        if (st->pace_budget > (s32)pace_cap)
            st->pace_budget = (s32)pace_cap;
    }

    if (st->total_pkts > 0 || st->q_est_bytes > 2048u)
        st->win_busy_us += dt_us;

    /* Store telemetry */
    st->gipc_out_last    = s->gipc_ch1_out;
    st->active_drbs_last = s->active_drbs;
    st->n4_present_last  = s->n4_present;
    if (s->n4_present && s->n4_g_ema >= 1000u && s->n4_g_ema <= 65536u)
        st->n4_g_ema_last = s->n4_g_ema;

    q_raw = s->rbc_ring_bytes + s->rbc_rlc_bytes;
    if (s->active_drbs == 0 && s->mac_ul_bo <= 0x400000u)
        q_raw = s->mac_ul_bo;

    /* 2. SCU-coherent empty detector: 0 in-flight GIPC IRBs => modem is guaranteed empty */
    if (s->gipc_ch1_out == 0) {
        if (st->q_est_bytes > 0)
            st->stat_gipc_zero_snap++;
        st->q_est_bytes = 0;
        st->q_raw_last = q_raw;
        st->mac_bo_last = s->mac_ul_bo;
        st->knl_ms_last = s->knl_ms;
    } else if (s->ram_valid && !(st->mode & UFQ_MODE_NO_RAM) &&
               (s->active_drbs > 0 || s->mac_ul_bo <= 0x400000u)) {
        /* 3. Change-triggered modem RAM anchoring (handles CPU1 non-coherent WB-WA cache) */
        int q_changed = (q_raw != st->q_raw_last);
        int any_changed = q_changed ||
                          (s->knl_ms != st->knl_ms_last) ||
                          (s->mac_ul_bo != st->mac_bo_last);

        if (any_changed) {
            st->stat_ram_fresh++;
            st->last_fresh_us = now_us;
            st->q_raw_last = q_raw;
            st->mac_bo_last = s->mac_ul_bo;
            st->knl_ms_last = s->knl_ms;

            if (q_changed) {
                /* Detect UL TTI MAC TB drain (sudden >= 3 KB drop in modem BO) */
                if (st->q_raw_prev_anchor > q_raw + 3000u)
                    st->last_tti_drain_us = now_us;
                /* Fresh cache eviction of rbc: snap directly to ground truth */
                st->q_est_bytes = q_raw;
                st->q_raw_prev_anchor = q_raw;
            } else if (q_raw < st->q_est_bytes) {
                /* Modem clock moved and rbc reads lower than projection: snap down */
                st->q_est_bytes = q_raw;
            } else {
                /* Modem clock moved and rbc reads higher: blend gently */
                st->q_est_bytes = (st->q_est_bytes + q_raw) >> 1;
            }
        } else if ((u32)(now_us - st->last_fresh_us) > 10000u) {
            /* Cache line stale (> 10 ms unchanged): ignore stale q_raw, rely on local decay */
            st->stat_ram_stale++;
        }
    }

    /* 4. Self-clocked UL delivery rate estimator (every ~50 ms when busy) */
    win_dt = now_us - st->win_start_us;
    if (win_dt >= 50000u) {
        if (st->win_busy_us >= 15000u && st->win_released_bytes > 0) {
            u32 gross = st->win_released_bytes + st->win_q_start_bytes;
            if (gross > st->q_est_bytes) {
                u32 delivered = gross - st->q_est_bytes;
                u32 win_ms = win_dt >> 10;
                u32 sample_bpms = win_ms ? (delivered / win_ms) : UFQ_MIN_RATE_BPMS;
                if (sample_bpms < UFQ_MIN_RATE_BPMS)
                    sample_bpms = UFQ_MIN_RATE_BPMS;
                if (sample_bpms > UFQ_MAX_RATE_BPMS)
                    sample_bpms = UFQ_MAX_RATE_BPMS;
                st->rate_bpms = (st->rate_bpms * 3u + sample_bpms) >> 2;
            }
        }
        st->win_start_us       = now_us;
        st->win_released_bytes = 0;
        st->win_q_start_bytes  = st->q_est_bytes;
        st->win_busy_us        = 0;
    }

    /* 5. Dynamic per-TTI grant size & BQL limit (zero static rate needed) */
    if (s->ram_valid && !(st->mode & UFQ_MODE_NO_RAM) &&
        s->n4_present && st->n4_g_ema_last >= 1000u && st->n4_g_ema_last <= 65536u) {
        st->g_bytes = st->n4_g_ema_last;
        /* Keep rate_bpms aligned when N4 G_ema is available */
        {
            u32 n4_bpms = st->n4_g_ema_last / (st->tti_ms ? st->tti_ms : 5u);
            if (n4_bpms >= UFQ_MIN_RATE_BPMS && n4_bpms <= UFQ_MAX_RATE_BPMS)
                st->rate_bpms = (st->rate_bpms * 3u + n4_bpms) >> 2;
        }
    } else {
        st->g_bytes = st->rate_bpms * (st->tti_ms ? st->tti_ms : 5u);
    }

    st->bql_limit = (st->g_bytes * st->bql_mult_q4) >> 4;
    if (st->bql_limit < st->bql_min_bytes)
        st->bql_limit = st->bql_min_bytes;
    if (st->bql_limit > st->bql_max_bytes)
        st->bql_limit = st->bql_max_bytes;
}

/* Drop head packet from the fattest bulk flow when global queue is full */
static inline void ufq_drop_fattest(struct ufq_state *st,
                                    const struct ufq_ops *ops,
                                    void *ctx)
{
    u32 i;
    u16 best_fid = UFQ_NIL;
    u32 best_bytes = 0;
    for (i = 0; i < UFQ_NUM_FLOWS; i++) {
        struct ufq_flow *f = &st->flows[i];
        if (f->q_pkts == 0)
            continue;
        /* Prefer fattest old_flow; only touch new_flow if no old_flow has packets */
        if (f->q_bytes > best_bytes &&
            (f->list_id == UFQ_LIST_OLD || best_fid == UFQ_NIL ||
             st->flows[best_fid].list_id != UFQ_LIST_OLD)) {
            best_bytes = f->q_bytes;
            best_fid = (u16)i;
        }
    }
    if (best_fid != UFQ_NIL) {
        u16 sidx = ufq_flow_pop(st, best_fid);
        if (sidx != UFQ_NIL) {
            void *pkt = st->slots[sidx].pkt;
            ufq_free_slot(st, sidx);
            if (pkt)
                ops->drop(ctx, pkt);
            st->stat_overlimit_drop++;
        }
    }
}

/* Enqueue one packet into its hashed flow queue */
static inline int ufq_enqueue(struct ufq_state *st,
                              u16 fid,
                              void *pkt,
                              void *okfn,
                              u32 len,
                              u8 ecn_capable,
                              u8 never_drop,
                              u32 now_us,
                              const struct ufq_ops *ops,
                              void *ctx)
{
    u16 sidx;
    struct ufq_flow *f;

    if (fid >= UFQ_NUM_FLOWS)
        fid &= UFQ_FLOW_MASK;

    /* Hard cap on queued packets: evict from fattest bulk flow */
    while (st->total_pkts >= st->max_pkts || st->free_head == UFQ_NIL) {
        if (st->total_pkts == 0) {
            /* Free list exhausted with total_pkts == 0 -> invariant broken! */
            ufq_trip_failsafe(st, ops, ctx);
            return -1;
        }
        ufq_drop_fattest(st, ops, ctx);
    }

    sidx = ufq_alloc_slot(st);
    if (sidx == UFQ_NIL) {
        ufq_trip_failsafe(st, ops, ctx);
        return -1;
    }

    st->slots[sidx].pkt         = pkt;
    st->slots[sidx].okfn        = okfn;
    st->slots[sidx].len         = len;
    st->slots[sidx].enq_us      = now_us;
    st->slots[sidx].ecn_capable = ecn_capable;
    st->slots[sidx].never_drop  = never_drop;

    if (st->total_pkts == 0)
        st->last_progress_us = now_us;

    f = &st->flows[fid];
    ufq_flow_push(st, fid, sidx);
    st->stat_enq_pkts++;

    /* RFC 8290: newly active flow joins new_flows (sparse-flow fast-pass!) */
    if (f->list_id == UFQ_LIST_NONE) {
        f->deficit = (s32)st->quantum;
        ufq_list_push_tail(st, &st->new_flows, fid, UFQ_LIST_NEW);
    }
    return 0;
}

/*
 * Per-flow CoDel (RFC 8289) evaluated ONLY on old_flows (bulk flows).
 * Returns 1 if packet should be dropped, 0 if packet should be transmitted
 * (possibly after ECN-CE marking).
 */
static inline int ufq_codel_should_drop(struct ufq_state *st,
                                        struct ufq_flow *f,
                                        struct ufq_pkt_slot *slot,
                                        u32 now_us,
                                        const struct ufq_ops *ops,
                                        void *ctx)
{
    u32 sojourn_us = now_us - slot->enq_us;
    int ok_to_drop = 0;

    /* Never drop tiny packets (<128 B), never_drop control pkts, or the last pkt of a flow */
    if (slot->never_drop || slot->len < 128u || f->q_pkts == 0) {
        f->codel_first_above_us = 0;
        return 0;
    }

    if (sojourn_us < st->codel_target_us) {
        f->codel_first_above_us = 0;
    } else {
        if (f->codel_first_above_us == 0) {
            f->codel_first_above_us = now_us + st->codel_interval_us;
        } else if ((s32)(now_us - f->codel_first_above_us) >= 0) {
            ok_to_drop = 1;
        }
    }

    if (f->codel_dropping) {
        if (!ok_to_drop) {
            f->codel_dropping = 0;
            return 0;
        }
        if ((s32)(now_us - f->codel_drop_next_us) >= 0) {
            /* ECN-CE mark instead of drop if enabled and packet is ECT */
            if ((st->mode & UFQ_MODE_ECN) && slot->ecn_capable &&
                sojourn_us < st->codel_interval_us * 2u && ops->mark_ecn) {
                if (ops->mark_ecn(ctx, slot->pkt)) {
                    f->codel_count++;
                    f->codel_drop_next_us = now_us +
                        (st->codel_interval_us / ufq_isqrt32(f->codel_count));
                    st->stat_codel_ecn++;
                    return 0;
                }
            }
            f->codel_count++;
            f->codel_drop_next_us = now_us +
                (st->codel_interval_us / ufq_isqrt32(f->codel_count));
            st->stat_codel_drop++;
            return 1;
        }
        return 0;
    } else if (ok_to_drop) {
        /* Enter dropping state */
        u32 delta = f->codel_count - f->codel_last_count;
        if (delta > 1u && (s32)(now_us - f->codel_drop_next_us) < (s32)(st->codel_interval_us * 16u)) {
            f->codel_count = (u16)(delta);
        } else {
            f->codel_count = 1u;
        }
        f->codel_last_count = f->codel_count;
        f->codel_dropping = 1u;
        f->codel_drop_next_us = now_us +
            (st->codel_interval_us / ufq_isqrt32(f->codel_count));

        if ((st->mode & UFQ_MODE_ECN) && slot->ecn_capable &&
            sojourn_us < st->codel_interval_us * 2u && ops->mark_ecn) {
            if (ops->mark_ecn(ctx, slot->pkt)) {
                st->stat_codel_ecn++;
                return 0;
            }
        }
        st->stat_codel_drop++;
        return 1;
    }
    return 0;
}

/* Check hard fail-safe (stalled release timer or zero forward progress) */
static inline int ufq_check_failsafe(struct ufq_state *st,
                                     u32 now_us,
                                     const struct ufq_ops *ops,
                                     void *ctx)
{
    if (st->total_pkts > 0 && st->failsafe_ms > 0) {
        u32 stall_us = now_us - st->last_progress_us;
        if (stall_us > st->failsafe_ms * 1000u) {
            ufq_trip_failsafe(st, ops, ctx);
            return 1;
        }
    }
    return 0;
}

/*
 * Drain eligible packets from host FQ into the modem.
 * - Sparse flows (new_flows) are released immediately up to bql_limit + sparse_headroom.
 * - Bulk flows (old_flows) are released via DRR + CoDel only while q_est < bql_limit
 *   and (paced budget > 0 or q_est < low-water anti-starvation threshold).
 * Returns number of packets delivered to the modem.
 */
static inline u32 ufq_drain(struct ufq_state *st,
                            u32 now_us,
                            const struct ufq_ops *ops,
                            void *ctx)
{
    u32 delivered = 0;
    u32 loop_guard = 0;
    u32 low_water = (st->g_bytes * 6u) >> 4; /* 0.375 * G_ema emergency anti-starvation floor */

    if (ufq_check_failsafe(st, now_us, ops, ctx))
        return 0;

    while (delivered < UFQ_MAX_BURST_PER_DRAIN && loop_guard < 512u) {
        int have_sparse = (st->new_flows.head != UFQ_NIL);
        int can_sparse = have_sparse &&
                         (st->q_est_bytes < st->bql_limit + st->sparse_headroom);
        int in_tti_hold = (st->tti_hold_us > 0) &&
                          (st->q_est_bytes >= low_water) &&
                          ((u32)(now_us - st->last_tti_drain_us) < st->tti_hold_us);
        int can_bulk = (st->old_flows.head != UFQ_NIL) &&
                       !in_tti_hold &&
                       (st->q_est_bytes < st->bql_limit) &&
                       (!st->pace_enable || st->pace_budget > 0 || st->q_est_bytes < low_water);

        loop_guard++;

        /* 1. Sparse-flow fast-pass (new_flows) always preempts bulk */
        if (can_sparse) {
            u16 fid = st->new_flows.head;
            struct ufq_flow *f = &st->flows[fid];

            if (f->head == UFQ_NIL) {
                /* RFC 8290: empty new_flow moves to old_flows before deactivating */
                ufq_list_remove(st, &st->new_flows, fid);
                ufq_list_push_tail(st, &st->old_flows, fid, UFQ_LIST_OLD);
                continue;
            }
            if (f->deficit <= 0) {
                f->deficit += (s32)st->quantum;
                ufq_list_remove(st, &st->new_flows, fid);
                ufq_list_push_tail(st, &st->old_flows, fid, UFQ_LIST_OLD);
                continue;
            }
            {
                u16 sidx = ufq_flow_pop(st, fid);
                u32 plen = st->slots[sidx].len;
                void *pkt = st->slots[sidx].pkt;
                void *okfn = st->slots[sidx].okfn;
                ufq_free_slot(st, sidx);

                f->deficit -= (s32)plen;
                /* If sparse flow ran out of deficit, demote to old_flows */
                if (f->deficit <= 0) {
                    f->deficit += (s32)st->quantum;
                    ufq_list_remove(st, &st->new_flows, fid);
                    ufq_list_push_tail(st, &st->old_flows, fid, UFQ_LIST_OLD);
                } else if (f->head == UFQ_NIL) {
                    ufq_list_remove(st, &st->new_flows, fid);
                    ufq_list_push_tail(st, &st->old_flows, fid, UFQ_LIST_OLD);
                }

                st->q_est_bytes += plen;
                st->win_released_bytes += plen;
                st->last_progress_us = now_us;
                st->stat_deq_sparse++;
                delivered++;
                if (pkt)
                    ops->deliver(ctx, pkt, okfn);
                continue;
            }
        }

        /* 2. Bulk DRR + CoDel (old_flows) */
        if (can_bulk) {
            u16 fid = st->old_flows.head;
            struct ufq_flow *f = &st->flows[fid];

            if (f->head == UFQ_NIL) {
                /* Empty old_flow deactivates: next arrival gets sparse fast-pass */
                ufq_list_remove(st, &st->old_flows, fid);
                f->codel_dropping = 0;
                f->codel_first_above_us = 0;
                continue;
            }
            if (f->deficit <= 0) {
                f->deficit += (s32)st->quantum;
                ufq_list_remove(st, &st->old_flows, fid);
                ufq_list_push_tail(st, &st->old_flows, fid, UFQ_LIST_OLD);
                continue;
            }
            {
                u16 sidx = ufq_flow_pop(st, fid);
                struct ufq_pkt_slot snap = st->slots[sidx];
                ufq_free_slot(st, sidx);

                if (ufq_codel_should_drop(st, f, &snap, now_us, ops, ctx)) {
                    if (snap.pkt)
                        ops->drop(ctx, snap.pkt);
                    /* Charge drop slightly or keep deficit so bulk doesn't spin */
                    continue;
                }

                f->deficit -= (s32)snap.len;
                if (f->deficit <= 0) {
                    f->deficit += (s32)st->quantum;
                    ufq_list_remove(st, &st->old_flows, fid);
                    ufq_list_push_tail(st, &st->old_flows, fid, UFQ_LIST_OLD);
                }

                st->q_est_bytes += snap.len;
                st->win_released_bytes += snap.len;
                if (st->pace_enable)
                    st->pace_budget -= (s32)snap.len;
                st->last_progress_us = now_us;
                st->stat_deq_bulk++;
                delivered++;
                if (snap.pkt)
                    ops->deliver(ctx, snap.pkt, snap.okfn);
                continue;
            }
        }

        /* Neither sparse nor bulk can release right now */
        break;
    }

    return delivered;
}

#endif /* TITAN_UFQ_CORE_H */
