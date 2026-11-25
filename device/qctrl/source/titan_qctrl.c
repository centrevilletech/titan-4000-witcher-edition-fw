/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright 2026 Centreville Tech, LLC. Kernel module for Titan 4000 Witcher Edition; see device/qctrl/README.md. */
/*
 * titan_qctrl.c — UE-Side Downlink Queue Controller & TDD Uplink ACK Coalescer
 * for Global Telecom Titan 4000 (GDM7243AP, Linux 3.10.0-uc0, UP ARMv7).
 *
 * Y6 REVIEW BUILD (2026-11-22). Every change from lane R's original
 * (ue-study/R/titan_qctrl.c, sha256 315c3507...) is marked "Y6". The review
 * and the reason for each change are in ue-study/Y6/report.md.
 *
 * Hook point: NFPROTO_BRIDGE / NF_BR_FORWARD, priority +100.
 * Y6 correction: bridged IPv4 on this unit DOES go through iptables and
 * conntrack (global /proc/sys/net/bridge/bridge-nf-call-iptables=1 is OR'd
 * with the per-bridge flag, see br_nf_pre_routing 0x8035815c). For IPv4 this
 * hook therefore runs from br_nf_forward_finish (nf_hook_slow thresh 1) after
 * iptables FORWARD; for IPv6 it runs straight from __br_forward. Both paths
 * call it exactly once per packet with okfn = br_forward_finish.
 *
 * Default on insmod: mode=0 (OBSERVE-ONLY; zero packet modification or delay).
 * Runtime control & telemetry: /proc/titan_qctrl
 *   echo "mode <0..31>"      (1=ACK-thin, 2=RWND-clamp, 4=DL-ECN, 8=UDP-drop, 16=UL-clamp)
 *   echo "target_ms <ms>"    (target eNB queue delay, default 12 ms)
 *   echo "ul_target_ms <ms>" (Q2: modem queue the upload clamp allows, 0..40, default 8)
 *   echo "hold_us <us>"      (max ACK coalesce hold, default 2500 us)
 *   echo "ack_span <bytes>"  (max bytes per coalesced ACK, default 8192 B)
 *   echo "phy <kbps>"        (optional PHY DL ceiling; 0 = off, else 4000..1000000)
 *   echo "reset"             (reset stats & controller state)
 * Y6: values must be plain decimal; "mode 0x3", "mode 31" or overflowing
 * numbers are now rejected instead of silently parsed/masked.
 *
 * Y6 time unit: every "*_us" quantity in this file is 1.024 us (raw
 * ktime_ns >> 10). See now_us().
 *
 * O1b CONTROLLER BUILD (2026-11-22). Every change from the Y6 build
 * (Y6/R/titan_qctrl.c, sha256 of the .ko 7d69a7ae...) is marked "O1b".
 * Report: ue-study/O1b/report.md. The Y6 bench run (exp/o1-qctrl-test1)
 * collapsed to 5 to 7 Mbps in mode 2 because:
 *   1. the queue signal was smoothed RTT minus the MINIMUM RTT. On this LTE
 *      link the RTT with an EMPTY tower queue spans 13 to 57 ms (ping min,
 *      p50 33, p95 57 under b1/b2), so "queue" read 10 to 20 ms with no queue;
 *   2. the window was c_hat x (rtt_min + u) with u <= 30 ms. A window has to
 *      cover the MEAN cycle time (about 33 ms) to fill the link, so even a
 *      perfect c_hat under-filled it;
 *   3. the Kalman filter took every 20 ms delivered rate as a capacity sample
 *      once "queue" > 5 ms, so clamp-limited delivery pulled c_hat down,
 *      which tightened the clamp again (death spiral to the 4 Mbps floor).
 * O1b replaces the sizing with:
 *   - a queue signal from the SERVER's TCP timestamp clock (one-way delay of
 *     DL data minus its windowed minimum). UL ACK scheduling jitter is not in
 *     it. RTT min-filter signal as fallback and as an upper-bound check;
 *   - one total window W for all clampable bulk flows, moved by a
 *     multiplicative loop toward target_ms of queue (no base-RTT model);
 *   - c_hat that only falls when a queue is proven for 100 ms;
 *   - a floor tied to the unclamped rate, a starvation fail-safe (release),
 *     a fail-open when no queue signal exists, upward probes and a short
 *     periodic drain that refreshes the delay baselines.
 *
 * Q2 UPLOAD CLAMP (v0.4, 2026-11-25). Mode bit 4 (16) clamps the receive
 * window in the server's ACKs (lte0pdn2 -> eth0) of every upload flow, so each
 * customer sender keeps at most about ul_target_ms of data queued in the modem
 * (Ring 1 and PDCP staging, which Linux cannot see). The law is in
 * ulclamp_core.h (shared with the host tests); this file feeds it uplink data
 * and downlink ACKs, rewrites the window, and runs its tick. With bit 4 clear
 * the download paths below are unchanged; the upload estimates still run so
 * /proc shows them and they are warm when the bit is set. titan_k1fp calls
 * this hook for fast-path downlink packets, so the clamp also covers them.
 */

#include "titan_k310_abi.h"
#include "ulclamp_core.h"

/* ---------- Module metadata matching stock 3.10.0-uc0 ELF ABI ---------- */
int init_module(void);
void cleanup_module(void);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"), aligned(4))) = {
    .name = "titan_qctrl",
    .init = init_module,
    .exit = cleanup_module,
};

static const char __mod_license[]  __attribute__((section(".modinfo"), used)) = "license=GPL";
static const char __mod_depends[]  __attribute__((section(".modinfo"), used)) = "depends=";
static const char __mod_vermagic[] __attribute__((section(".modinfo"), used)) =
    "vermagic=3.10.0-uc0 mod_unload ARMv7 ";

/* ---------- Feature bitmask & tuning defaults ---------- */
#define MODE_ACK_THIN   (1u << 0)
#define MODE_RWND_CLAMP (1u << 1)
#define MODE_DL_ECN     (1u << 2)
#define MODE_UDP_DROP   (1u << 3)
#define MODE_UL_CLAMP   (1u << 4)                   /* Q2: upload window clamp */
#define MODE_ALL        0x1fu

#define FLOW_BUCKETS    128
#define FLOW_WAYS       2
#define FLOW_SLOTS      (FLOW_BUCKETS * FLOW_WAYS)  /* 256 flows, ~32 KB BSS */
#define CTRL_TICK_US    20000u                      /* 20 ms = 4 TDD half-frames */
#define DEFAULT_MSS     1348u                       /* MTU 1400 - 20 IPv4 - 32 TCP+TS */
#define HOLD_ANOMALY_US 20000u                      /* Y6: no legit deadline is >20 ms out */

/* O1b: controller constants (ticks are CTRL_TICK_US = 20 ms) */
#define NONE32            0xffffffffu
#define NO_CLAMP          0xffffffffu               /* compute_flow_rwnd_target(): leave window alone */
#define RATE_RING         5u                        /* 5 ticks = 100 ms delivered-rate window */
#define RTT_WIN_TICKS     5u                        /* RTT min-filter window = 100 ms (two buckets) */
#define OWD_CHECK_US      244141u                   /* 250 ms before a server clock is trusted */
#define OWD_REANCHOR_US   7812500u                  /* re-anchor every 8 s (keeps deltas small) */
#define OWD_EPOCH_US      15625000u                 /* 16 s min-filter epoch (two buckets) */
#define OWD_RETRY_US      1953125u                  /* 2 s before a rejected clock is re-tested */
#define OWD_MAX_RETRY     5u
#define OWD_DRIFT_MS      25u
#define Q_MAX_MS          1000u
#define QVALID_TICKS      12u                       /* 240 ms without a queue sample = no signal */
#define DRAIN_PERIOD_TICKS 400u                     /* 8 s */
#define DRAIN_TICKS       3u                        /* 60 ms at 5/8 window */
#define DRAIN_SETTLE_TICKS 8u                      /* > 100 ms window + a cycle */
#define PROBE_PERIOD_TICKS 50u                      /* at most one probe per second */
#define PROBE_EVAL_TICKS  6u                        /* judge a probe 120 ms after it starts */
#define STARVE_TICKS      75u                       /* 1.5 s of starvation -> release */
#define RELEASE_TICKS     150u                      /* 3 s unclamped after a fail-safe release */
#define IDLE_RESEED_TICKS 100u                      /* 2 s without bulk flows -> re-seed W */
#define FLOOR_RTT_MS      30u
#define W_CEIL_BYTES      (32u << 20)
#define Q_BIAS_MAX_MS     25u
#define BUSY_US           4883u                     /* 5 ms: 100 ms minimum above this = link busy */

/* Q3 (v0.3-q3): opt-in adaptive ACK thinning & low-burst fast-trough control */
#define DRAIN_PERIOD_V3    600u                     /* 12 s between gentle drains */
#define RECOV_COOLDOWN_US  244141u                  /* 250 ms no-thinning cooldown after SACK/dupACK */
#define DEAD_FLOW_US       146484u                  /* 150 ms without DL data -> drop from n_ctl */
#define ACK_ADAPT_MIN_TOT  30000u                   /* 30 Mbps total DL floor (never thin degraded 25M link) */
#define ACK_ADAPT_SS_BYTES 262144u                  /* 256 KB slow-start bypass for adaptive thinning */
#define THIN_BACKOFF_BASE  500u                     /* 10 s base global backoff after rate drop */
#define THIN_FLOW_BO_US    9765625u                 /* 10 s per-flow backoff after per-flow rate drop */

enum { OWD_NONE = 0, OWD_CHECK = 1, OWD_OK = 2, OWD_BAD = 3 };

/* TCP flags */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

/* ---------- Minimal helpers (no libc / no 64-bit div) ---------- */
static inline int seq_gt(u32 a, u32 b)  { return (s32)(a - b) > 0; }
static inline int seq_ge(u32 a, u32 b)  { return (s32)(a - b) >= 0; }
static inline int seq_lt(u32 a, u32 b)  { return (s32)(a - b) < 0; }

static inline int is_dev_lte(const struct net_device *d)
{
    return d && d->name[0] == 'l' && d->name[1] == 't' && d->name[2] == 'e' &&
           d->name[3] == '0' && d->name[4] == 'p' && d->name[5] == 'd' &&
           d->name[6] == 'n' && d->name[7] == '2' && d->name[8] == '\0';
}

static inline int is_dev_eth0(const struct net_device *d)
{
    return d && d->name[0] == 'e' && d->name[1] == 't' && d->name[2] == 'h' &&
           d->name[3] == '0' && d->name[4] == '\0';
}

/*
 * Y6 FIX (time base). The original computed ticks = (u32)(ns >> 10) and then
 * returned ticks * 1.0234 truncated to 32 bits. The truncation happens BEFORE
 * the scaling, so every 2^42 ns (4398 s = 73.3 min of uptime) the result
 * jumped BACKWARD by ~100.7 s. Held-ACK deadlines that straddled the jump then
 * looked ~100 s in the future (stuck ACKs, sender RTOs), and every flow
 * looked 4e9 us idle (all flow state wiped). On the bench unit the jumps fall
 * at uptime 4398 s, 8796 s, 13194 s, 17592 s, ...
 *
 * Now: one unit = 1.024 us = (ns >> 10), which wraps cleanly modulo 2^32, so
 * every (u32)(a - b) difference below 2^31 units (36 min) is exact. All
 * constants keep their microsecond names; they are 2.4 % "slow", which is
 * irrelevant for these heuristics. hrtimers are armed with US_TO_NS() so the
 * timer and the deadlines use the same unit.
 */
static inline u32 now_us(void)
{
    u64 ns = (u64)ktime_get().tv64;
    return ((u32)(ns >> 32) << 22) | ((u32)ns >> 10);
}
#define US_TO_NS(us) ((s64)((u64)(us) << 10))

/* O1b: exact ms -> 1.024 us units (976.5625 per ms); valid for ms <= 274877 */
static inline u32 ms_to_units(u32 ms) { return (ms * 15625u) >> 4; }
/* O1b: 1.024 us units -> ms (x 0.0010223, -0.2 %); valid for every u32 */
static inline u32 units_to_ms(u32 u)  { return ((u >> 6) * 67u) >> 10; }

/* RFC 1624 incremental 16-bit IPv4 header checksum update */
static inline void csum_replace2_ip4(u8 *iph, u16 old16_be, u16 new16_be)
{
    u16 *chk = (u16 *)(iph + 10);
    u32 sum = (~ntohs(*chk)) & 0xffffu;
    sum += (~ntohs(old16_be)) & 0xffffu;
    sum += ntohs(new16_be);
    sum = (sum & 0xffffu) + (sum >> 16);
    sum = (sum & 0xffffu) + (sum >> 16);
    *chk = htons((u16)(~sum));
}

/* ---------- Per-flow state (256 fixed slots, zero hot-path malloc) ---------- */
struct flow_entry {
    u32 key_hash;          /* full 32-bit flow fingerprint (0 = unused) */
    u32 ip_cli;            /* IPv4 client addr (or xor-fold of IPv6) */
    u32 ip_srv;            /* IPv4 server addr (or xor-fold of IPv6) */
    u16 port_cli;
    u16 port_srv;
    u8  is_v6;
    u8  wscale_cli;        /* client's advertised rcv_wscale (0..14) */
    u8  wscale_valid;      /* 1 ONLY if both SYN and SYN-ACK WSopt observed */
    u8  syn_ws_seen;       /* client sent WSopt in SYN */

    u16 mss;
    u16 last_win_sent;     /* last raw 16-bit window sent on UL */
    u32 max_right_edge;    /* max(ack_seq + rwnd_sent) — never retract! */
    u32 last_ack_sent;     /* last UL ack_seq actually transmitted */
    u32 last_ul_seq;       /* last UL seq seen (detect pure dup/re-seq) */

    /* Passive WAN RTT measurement (UL TSval -> DL TSecr, SYN->SYN-ACK, edge) */
    u32 syn_ts_us;
    u8  syn_pending;
    u8  ts_probe_active;
    u8  edge_probe_active;
    u8  is_bulk;
    u8  edge_valid;        /* Y6: replaces the max_right_edge==0 sentinel */
    u8  _pad0[3];
    u32 ts_probe_val;      /* UL TSval waiting for DL TSecr */
    u32 ts_probe_us;       /* timestamp when UL TSval left Titan */
    u32 edge_probe_seq;    /* right edge waiting for DL seq > edge */
    u32 edge_probe_us;
    u32 rtt_us;            /* latest smoothed WAN RTT */
    u32 rtt_min_us;        /* windowed base WAN RTT (min of this + last epoch) */
    u32 rtt_min_next_us;   /* Y6: min of the current 45 s epoch */
    u32 rtt_min_ts_us;     /* when the current epoch started */
    u32 rtt_sample_ts_us;  /* last valid RTT sample time */

    /* Activity / byte tracking */
    u32 dl_bytes_total;    /* saturating counter for slow-start bypass */
    u32 dl_bytes_epoch;    /* DL bytes in current 20 ms tick */
    u32 dl_rate_kbps;      /* EWMA flow DL rate */
    u32 last_seen_us;
    u32 recent_ack_us;
    u16 recent_acks_10ms;

    /* 1-slot TDD ACK coalescer (NF_STOLEN) */
    struct sk_buff *held_ack;
    int (*held_okfn)(struct sk_buff *);
    u32 held_ack_seq;
    u32 held_deadline_us;

    /* O1b: RTT probe arming on the FIRST UL ACK that carries a new TSval
     * (removes the up-to-one-tick early bias of the Y6 probe). */
    u32 last_ul_tsval;
    u8  ul_ts_valid;
    /* O1b: one-way delay from the server TSval clock */
    u8  owd_state;         /* OWD_NONE / CHECK / OK / BAD */
    u8  owd_retries;
    s8  owd_drift_sign;
    u8  owd_drift_strikes;
    u8  owd_have;          /* owd_base_next holds a value */
    u8  owd_prev_valid;    /* owd_prev_min holds a value */
    u8  _pad1;
    u32 owd_t0;            /* hook time of the anchor packet */
    u32 owd_ts0;           /* server TSval of the anchor packet */
    s32 owd_base;          /* min(previous epoch, current epoch) of owd_rel */
    s32 owd_base_next;     /* min of the current epoch */
    s32 owd_prev_min;      /* min of the last finished epoch (drift check) */
    u32 owd_epoch_ts;
    u32 q_sum;             /* per-tick sum of queue samples (units) */
    u32 q_cnt;
    /* O1b: RTT min filter (two 100 ms buckets) and mean cycle time */
    u32 rtt_win_min;
    u32 rtt_win_min_prev;
    u32 rtt_avg_us;        /* EWMA 1/8 of RTT samples = mean ACK->data cycle */

    /* Q3 (v0.3): adaptive ACK thinning & fast dead-flow eviction */
    u32 last_dl_data_us;       /* last DL payload packet arrival */
    u32 recov_until_us;        /* no thinning while (now - recov_until_us) < 0 */
    u32 thin_backoff_until_us; /* per-flow thinning backoff deadline */
    u32 thin_ref_kbps;         /* flow rate snapshot when thinning engaged */
    u16 thin_drop_ticks;       /* consecutive ticks flow dropped under thinning */
    u8  thin_active_flow;      /* flow thinned at least one ACK this tick */
    u8  _pad2;

    /* Q2 (v0.4): upload clamp state (ulclamp_core.h) */
    struct ulc_flow ul;
};

/* ---------- Global controller & telemetry state ---------- */
static struct {
    /* Runtime parameters (writable via /proc/titan_qctrl) */
    volatile u32 mode;             /* default 0 = observe-only! */
    volatile u32 unloading;
    u32 target_q_ms;               /* default 12 ms */
    u32 hold_us;                   /* default 2500 us */
    u32 max_ack_span;              /* default 8192 B (~6 MSS) */
    u32 phy_cap_kbps;              /* 0 = unset, else PHY upper bound */
    u32 prev_phy_cap_kbps;

    /* O1b: saturation-gated capacity estimate (kbps). Rises with the 100 ms
     * delivered rate; falls ONLY after a queue was proven for 100 ms. */
    u32 c_hat_kbps;                /* initial 65000 kbps */
    u32 dq_est_ms;                 /* smoothed tower queue delay (ms, = q_s_u) */
    u32 rtt_base_global_ms;        /* telemetry: min RTT over clampable bulk flows */
    u32 p_ecn_q10;                 /* ECN/drop prob in [0..1024] */
    u32 ecn_accum;
    u32 drop_accum;

    /* O1b: window controller */
    u32 w_bytes;                   /* total window for clampable bulk flows */
    u32 ctl_active;                /* 1 = windows are being clamped */
    u32 q_raw_s_u;                 /* smoothed queue delay before bias (units) */
    u32 q_s_u;                     /* q_raw_s_u - q_bias_u (units) */
    u32 q_owd_u, q_rtt_u;          /* last tick's raw values (NONE32 = none) */
    u32 q_src;                     /* 0 none, 1 server-clock OWD, 2 RTT */
    u32 q_bias_u;                  /* learned by successful probes, decays */
    u32 q_age;                     /* ticks since the last queue sample */
    u32 q_force;                   /* /proc qsrc: 0 auto, 1 OWD only, 2 RTT only */
    u32 rtt_slack_ms;              /* RTT fallback: noise allowance */
    u32 floor_pct;                 /* W floor as % of free_kbps over FLOOR_RTT_MS */
    u32 sat_ticks;                 /* consecutive ticks with queue >= target/2 */
    u32 free_kbps;                 /* unclamped reference rate (decays) */
    u32 rate100_kbps;              /* delivered rate over the last 100 ms */
    u32 ring_bytes[RATE_RING];
    u32 ring_ms[RATE_RING];
    u32 ring_idx;
    u32 rtt_cycle_ms;              /* mean cycle time over clampable bulk flows */
    u32 inflight_est;              /* rate100 x rtt_cycle (bytes, Little's law) */
    u32 n_ctl;                     /* clampable bulk flows */
    u32 w_sum_ms;                  /* sum of their weights (cycle ms) */
    u32 owd_flows;                 /* flows that gave an OWD queue sample */
    u32 tick_count;
    u32 rtt_win_cnt;
    u32 qh_tot;                    /* this tick: OWD samples of bulk flows */
    u32 q_trough_u;                /* this tick: min OWD queue sample of bulk flows */
    u32 last_trough_u;             /* last tick's minimum (telemetry, NONE32 = none) */
    u32 tr_ring[RATE_RING];        /* last 5 tick minimums (NONE32 = none) */
    u32 tr_idx;
    u32 win_trough_u;              /* sliding 100 ms minimum (NONE32 = none) */
    u32 busy_ticks;                /* consecutive ticks with win_trough_u >= 2 ms */
    u32 trough_ms;                 /* /proc trough_ms: standing-queue target (default 4) */
    u32 rtt_target_ms;             /* /proc rtt_target_ms: mean-queue target in RTT mode (15) */
    u32 ecn_ms;                    /* /proc ecn_ms: ECN / UDP-drop ramp start (20) */
    u32 w_fix_bytes;               /* /proc wfix_kb: fixed total window (0 = controller) */
    u32 bulk_ticks;                /* consecutive ticks with clampable bulk flows */
    u32 drain_enable, drain_left, drain_settle, drain_next;
    u32 probe_enable, probe_state, probe_due, probe_rate_pre, probe_w_saved, probe_q_raw;
    u32 starve_ticks, release_left, idle_ticks;
    u32 cut_ref_w, cut_ref_until;  /* cuts limited to 25 % per cycle */
    u32 rtt_law;                   /* /proc rttlaw: RTT mode uses 0 trough law, 1 mean law */
    u32 clamped_last;

    /* 20 ms epoch accumulators */
    u32 last_tick_us;
    u32 epoch_dl_bytes;
    u32 epoch_ul_bytes;
    u32 epoch_udp_dl_bytes;
    u32 last_dl_kbps;
    u32 last_ul_kbps;
    u32 last_udp_dl_kbps;
    u32 active_bulk_flows;
    u32 held_count;
    u32 timer_pending;             /* Y6: an hrtimer/tasklet expiry is outstanding */

    /* Telemetry counters */
    u32 stat_dl_pkts;
    u32 stat_ul_pkts;
    u32 stat_acks_seen;
    u32 stat_acks_thinned;
    u32 stat_acks_flushed_timer;
    u32 stat_acks_flushed_span;
    u32 stat_acks_flushed_event;
    u32 stat_acks_flushed_wd;      /* Y6: released by the 20 ms tick watchdog */
    u32 stat_acks_dropped_netdev;  /* Y6: dropped because their out-device went down */
    u32 stat_ctx_skipped;          /* Y6: hook called from hard-IRQ / IRQs-off context */
    u32 stat_rwnd_clamped;
    u32 stat_ecn_marked;
    u32 stat_udp_dropped;
    u32 stat_rtt_samples;
    u32 stat_owd_ok;               /* O1b: server clocks accepted */
    u32 stat_owd_bad;              /* O1b: server clocks rejected (rate or drift) */
    u32 stat_sat_updates;          /* O1b: c_hat lowered under a proven queue */
    u32 stat_probe_win, stat_probe_fail;
    u32 stat_drains;
    u32 stat_failsafe;
    u32 stat_seeds;
    u32 stat_active_ticks;         /* O1b: ticks with the clamp active */
    u32 stat_q_ms_sum;             /* O1b: sum of dq_est_ms over active ticks */

    /* Q3 (v0.3): opt-in knobs (all 0 = exact v0.2-o1b behavior) & telemetry */
    u32 ack_adapt;                 /* /proc ack_adapt: 0 v0.2-o1b, 1 adaptive safe thinning */
    u32 ctrl_v3;                   /* /proc ctrl_v3:   0 v0.2-o1b, 1 low-burst fast-trough */
    u32 ack_ms;                    /* /proc ack_ms:    1..10 ms per-flow ACK time budget (def 6) */
    u32 ack_segs;                  /* /proc ack_segs:  2..32 per-flow ACK seg budget (def 18) */
    u32 ack_min_kbps;              /* /proc ack_min_kbps: per-flow rate floor (def 2000) */
    u32 prev_n_ctl;                /* previous tick n_ctl (suppresses join-split false backoff) */
    u32 win_trough3_u;             /* 3-tick (60 ms) sliding OWD trough minimum */
    u32 empty_ticks;               /* consecutive ticks with win_trough_u == 0 (fast recovery) */
    u32 pre_thin_kbps;             /* EWMA delivered rate while not thinning */
    u32 thin_ref_kbps;             /* reference rate when adaptive thinning started */
    u32 thin_armed;                /* 1 while adaptive thinning is active */
    u32 thin_drop_ticks;           /* consecutive ticks rate fell >18% under thinning */
    u32 thin_backoff_ticks;        /* global backoff countdown (ticks) */
    u32 thin_strikes;              /* consecutive global thinning backoffs */
    u32 thinned_last;              /* stat_acks_thinned at previous tick */
    u32 stat_thin_backoff;         /* adaptive thinning rate-drop backoffs */
    u32 stat_thin_bypass_recov;    /* ACKs bypassed: SACK / dupACK / recovery cooldown */
    u32 stat_thin_bypass_rate;     /* ACKs bypassed: slow-start / rate floor / backoff */
    u32 stat_thin_bypass_win;      /* ACKs bypassed: clamp window opening */

    struct ulc ul;                 /* Q2 (v0.4): upload clamp knobs, estimates, counters */

    struct flow_entry flows[FLOW_SLOTS];
} g;

static struct tasklet_hrtimer g_flush_timer;   /* Y6: now 8-byte aligned (abi.h) */
static struct nf_hook_ops     g_nf_ops;
static struct notifier_block  g_netdev_nb;     /* Y6 */
static struct proc_dir_entry *g_proc_ent;

/* ---------- Flow table hash (2-way set-associative, zero locks on UP softirq) ---------- */
static inline u32 flow_hash(u32 a, u32 b, u16 pa, u16 pb, u8 v6)
{
    u32 h = a ^ (b * 2654435761u) ^ (((u32)pa << 16) | pb) ^ ((u32)v6 << 24);
    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    return h ? h : 1u;
}

static void flow_release_held(struct flow_entry *f, u32 *counter);

static struct flow_entry *flow_lookup_or_alloc(u32 ip_cli, u32 ip_srv,
                                               u16 port_cli, u16 port_srv,
                                               u8 is_v6, u32 now, int create)
{
    u32 h = flow_hash(ip_cli, ip_srv, port_cli, port_srv, is_v6);
    u32 base = (h & (FLOW_BUCKETS - 1)) * FLOW_WAYS;
    struct flow_entry *f0 = &g.flows[base];
    struct flow_entry *f1 = &g.flows[base + 1];
    struct flow_entry *victim;

    if (f0->key_hash == h && f0->ip_cli == ip_cli && f0->ip_srv == ip_srv &&
        f0->port_cli == port_cli && f0->port_srv == port_srv && f0->is_v6 == is_v6)
        return f0;
    if (f1->key_hash == h && f1->ip_cli == ip_cli && f1->ip_srv == ip_srv &&
        f1->port_cli == port_cli && f1->port_srv == port_srv && f1->is_v6 == is_v6)
        return f1;

    if (!create)
        return NULL;

    /* Pick unused or older slot (never evict a slot holding an skb unless forced) */
    if (f0->key_hash == 0)
        victim = f0;
    else if (f1->key_hash == 0)
        victim = f1;
    else if (f0->held_ack && !f1->held_ack)
        victim = f1;
    else if (f1->held_ack && !f0->held_ack)
        victim = f0;
    else
        victim = ((s32)(f0->last_seen_us - f1->last_seen_us) <= 0) ? f0 : f1;

    /* Flush any held ACK before recycling slot */
    if (victim->held_ack)
        flow_release_held(victim, &g.stat_acks_flushed_event);

    /* Y6: __builtin_memset instead of a u32* store loop (strict-aliasing safe) */
    __builtin_memset(victim, 0, sizeof(*victim));
    victim->key_hash = h;
    victim->ip_cli = ip_cli;
    victim->ip_srv = ip_srv;
    victim->port_cli = port_cli;
    victim->port_srv = port_srv;
    victim->is_v6 = is_v6;
    victim->mss = DEFAULT_MSS;
    victim->last_seen_us = now;
    victim->last_dl_data_us = now;
    victim->recov_until_us = now;
    victim->thin_backoff_until_us = now;
    return victim;
}

/* ---------- Release (forward) a held ACK ---------- */
static void flow_release_held(struct flow_entry *f, u32 *counter)
{
    struct sk_buff *skb = f->held_ack;
    int (*ok)(struct sk_buff *) = f->held_okfn;
    if (!skb)
        return;
    f->held_ack = NULL;
    f->held_okfn = NULL;
    f->last_ack_sent = f->held_ack_seq;
    if (g.held_count) g.held_count--;
    if (counter) (*counter)++;
    if (ok)
        ok(skb);
    else
        consume_skb(skb);
}

static inline void flush_flow_ack(struct flow_entry *f, u32 *counter)
{
    flow_release_held(f, counter);
}

/* Y6: the only place that arms the timer from the packet path. */
static inline void flush_timer_arm(u32 delay_us)
{
    g.timer_pending = 1;
    hrtimer_start(&g_flush_timer.timer, ktime_set_ns(US_TO_NS(delay_us)),
                  HRTIMER_MODE_REL);
}

/* Softirq tasklet_hrtimer callback (HI_SOFTIRQ): drains expired held ACKs */
static int flush_timer_cb(struct hrtimer *timer)
{
    u32 now = now_us();
    u32 next_delta_us = 0xffffffffu;
    u32 i, held = 0;

    (void)timer;
    g.timer_pending = 0;
    if (g.unloading)
        return HRTIMER_NORESTART;

    for (i = 0; i < FLOW_SLOTS; i++) {
        struct flow_entry *f = &g.flows[i];
        u32 rem;
        if (!f->held_ack)
            continue;
        rem = f->held_deadline_us - now;
        /* Y6: expired, OR a deadline that is impossibly far in the future
         * (clock anomaly) -> release now instead of re-arming for it. */
        if ((s32)rem <= 0 || rem > HOLD_ANOMALY_US) {
            flush_flow_ack(f, &g.stat_acks_flushed_timer);
        } else {
            held++;
            if (rem < next_delta_us)
                next_delta_us = rem;
        }
    }
    g.held_count = held;           /* Y6: self-heal the counter */

    if (held > 0) {
        if (next_delta_us < 250u) next_delta_us = 250u;
        flush_timer_arm(next_delta_us);
    }
    return HRTIMER_NORESTART;
}

/* ---------- Window rewrite (download clamp on uplink ACKs, upload clamp on downlink ACKs) ---------- */

/*
 * Write a new raw TCP window into the segment whose TCP header starts at
 * l4_off and fix the checksum incrementally (RFC 1624, inet_proto_csum_replace4).
 * Returns 0 when the header cannot be made writable; the original window then
 * goes out. skb_make_writable may move skb->data: callers reload any pointer
 * into the packet afterwards.
 */
static int tcp_set_window(struct sk_buff *skb, u32 l4_off, u16 old_win, u16 new_win)
{
    u8 *th;

    if (!skb_make_writable(skb, l4_off + 20u))
        return 0;
    th = skb->data + l4_off;
    th[14] = (u8)(new_win >> 8);
    th[15] = (u8)(new_win & 0xffu);
    inet_proto_csum_replace4((__sum16 *)(th + 16), skb,
                             (__be32)htons(old_win), (__be32)htons(new_win), 0);
    return 1;
}

/* Q2: the upload clamp's tick over every flow (ulclamp_core.h). The uploads'
 * ACKs wait in the downlink queue too; pass it in only when it comes from the
 * servers' clocks (q_src 1, one way): the RTT fallback would include the
 * uploads' own queue. */
static void ul_tick(u32 now)
{
    u32 i;

    g.ul.dl_queue_ms = (g.q_src == 1u) ? g.dq_est_ms : 0u;
    ulc_tick_begin(&g.ul, now);
    for (i = 0; i < FLOW_SLOTS; i++)
        if (g.flows[i].key_hash)
            ulc_tick_flow(&g.ul, &g.flows[i].ul, now);
    ulc_tick_end(&g.ul, now);
}

/* ---------- O1b: 20 ms controller (queue signal, c_hat, window loop) ---------- */

/* Weight of a flow for the RTT-fair split: its mean cycle time in ms. */
static inline u32 flow_weight_ms(const struct flow_entry *f)
{
    u32 w = f->rtt_avg_us ? units_to_ms(f->rtt_avg_us) : 35u;
    if (w < 10u)   w = 10u;
    if (w > 1000u) w = 1000u;
    return w;
}

static inline u32 w_floor_bytes(void)
{
    u32 n = g.n_ctl ? g.n_ctl : 1u;
    u32 fl = n * 5400u;
    u32 fr = ((g.free_kbps >> 3) * FLOOR_RTT_MS / 100u) * g.floor_pct;
    if (fr > fl) fl = fr;
    if (fl > W_CEIL_BYTES) fl = W_CEIL_BYTES;
    return fl;
}

static inline u32 w_ceil_bytes(void)
{
    u32 c = (g.c_hat_kbps >> 3) * 500u;     /* 500 ms at c_hat: beyond this a clamp is moot */
    u32 fl = w_floor_bytes();
    if (c > W_CEIL_BYTES) c = W_CEIL_BYTES;
    if (c < fl) c = fl;
    return c;
}

static void controller_tick(u32 now)
{
    u32 dt_us = now - g.last_tick_us;
    u32 dt_ms, dl_kbps, ul_kbps, udp_kbps;
    u32 i, bulk_cnt = 0, n_ctl = 0, w_sum = 0, owd_flows = 0;
    u32 q_owd = NONE32, q_rtt = NONE32, q_tick = 0, src = 0;
    u32 cyc_sum = 0, cyc_cnt = 0, rmin = NONE32;
    u32 target_u, rt_u, rewrites, win_roll = 0;

    if (dt_us < CTRL_TICK_US)
        return;
    /* O1b: keep the real gap (capped) so the 100 ms rate ring stays honest;
     * Y6 reset any gap > 200 ms to 20 ms. Ticks run only when packets pass,
     * so a silence of more than 2 s ends the clamp episode here (W is
     * re-seeded for the next download) instead of counting idle ticks. */
    if (dt_us > 1953125u) {
        g.ctl_active = 0;
        g.bulk_ticks = 0;
    }
    if (dt_us > 976562u)
        dt_us = 976562u;
    g.last_tick_us = now;
    g.tick_count++;
    ul_tick(now);
    dt_ms = units_to_ms(dt_us);
    if (dt_ms == 0)
        dt_ms = 1;

    /* Rates in kbps = bytes * 8 / ms (bytes per tick stay far below 2^29) */
    dl_kbps  = (g.epoch_dl_bytes * 8u) / dt_ms;
    ul_kbps  = (g.epoch_ul_bytes * 8u) / dt_ms;
    udp_kbps = (g.epoch_udp_dl_bytes * 8u) / dt_ms;
    g.ring_bytes[g.ring_idx] = g.epoch_dl_bytes;
    g.ring_ms[g.ring_idx] = dt_ms;
    if (++g.ring_idx >= RATE_RING)
        g.ring_idx = 0;
    g.epoch_dl_bytes = 0;
    g.epoch_ul_bytes = 0;
    g.epoch_udp_dl_bytes = 0;
    g.last_dl_kbps = dl_kbps;
    g.last_ul_kbps = ul_kbps;
    g.last_udp_dl_kbps = udp_kbps;
    {
        u32 sb = 0, sm = 0, k;
        for (k = 0; k < RATE_RING; k++) {
            sb += g.ring_bytes[k];
            sm += g.ring_ms[k];
        }
        if (sm == 0) sm = 1;
        g.rate100_kbps = (sb / sm) * 8u + ((sb % sm) * 8u) / sm;
    }

    if (++g.rtt_win_cnt >= RTT_WIN_TICKS) {
        g.rtt_win_cnt = 0;
        win_roll = 1;
    }

    for (i = 0; i < FLOW_SLOTS; i++) {
        struct flow_entry *f = &g.flows[i];
        u32 f_kbps;

        /* Y6 watchdog: a held ACK that is due (or has an impossible deadline)
         * is released here even if the hrtimer path failed. */
        if (f->held_ack &&
            (u32)(f->held_deadline_us - now) - 1u >= HOLD_ANOMALY_US)
            flush_flow_ack(f, &g.stat_acks_flushed_wd);

        if (!f->key_hash)
            continue;
        /* Expire stale idle flows after 30 s */
        if ((u32)(now - f->last_seen_us) > 30000000u && !f->held_ack) {
            f->key_hash = 0;
            continue;
        }
        f_kbps = (f->dl_bytes_epoch * 8u) / dt_ms;
        f->dl_bytes_epoch = 0;
        f->dl_rate_kbps = (f->dl_rate_kbps * 3u + f_kbps) >> 2;
        f->is_bulk = (f->dl_rate_kbps >= 500u && f->dl_bytes_total >= 32768u) ? 1 : 0;
        if (g.ctrl_v3 && f->is_bulk) {
            /* Q3: evict finished flows faster than 240 ms EWMA decay while never
             * evicting live flows on 16-flow or 150 ms RTT paths. */
            u32 dead_u = ms_to_units(g.rtt_cycle_ms > 75u ? g.rtt_cycle_ms * 2u : 150u);
            if (dead_u > ms_to_units(400u)) dead_u = ms_to_units(400u);
            if ((u32)(now - f->last_dl_data_us) > dead_u)
                f->is_bulk = 0;
        }
        /* Q3: per-flow adaptive thinning rate-drop guard.
         * Compares each thinned flow against its pre-thinning baseline (scaled
         * down if concurrent flow count grew, so new flows sharing the link do
         * not falsely trigger backoff). */
        if (g.ack_adapt) {
            if (f->thin_active_flow) {
                if (f->thin_ref_kbps == 0u) {
                    f->thin_ref_kbps = f->dl_rate_kbps;
                } else if (g.busy_ticks == 0u && !g.drain_left && !g.drain_settle &&
                           g.n_ctl <= g.prev_n_ctl &&
                           f->dl_rate_kbps * 100u < f->thin_ref_kbps * 45u &&
                           f->thin_ref_kbps >= g.ack_min_kbps) {
                    if (++f->thin_drop_ticks >= 25u) {
                        f->thin_backoff_until_us = now + THIN_FLOW_BO_US;
                        f->thin_drop_ticks = 0;
                        f->thin_ref_kbps = 0;
                        if (f->held_ack)
                            flush_flow_ack(f, &g.stat_acks_flushed_event);
                        g.stat_thin_backoff++;
                    }
                } else {
                    f->thin_drop_ticks = 0;
                    if (g.n_ctl > g.prev_n_ctl)
                        f->thin_ref_kbps = f->dl_rate_kbps;
                }
                f->thin_active_flow = 0;
            } else {
                f->thin_drop_ticks = 0;
                if (f->dl_rate_kbps >= g.ack_min_kbps)
                    f->thin_ref_kbps = f->thin_ref_kbps
                        ? ((f->thin_ref_kbps * 3u + f->dl_rate_kbps) >> 2)
                        : f->dl_rate_kbps;
            }
        }
        if (f->is_bulk)
            bulk_cnt++;

        if (f->is_bulk && f->wscale_valid) {
            n_ctl++;
            w_sum += flow_weight_ms(f);
            /* Server-clock queue: mean of this tick's samples; the minimum
             * across flows rejects one server's own pauses. */
            if (f->q_cnt >= 2u) {
                u32 m = f->q_sum / f->q_cnt;
                if (m < q_owd) q_owd = m;
                owd_flows++;
            }
            /* RTT queue: min of the last two 100 ms buckets minus the
             * flow's long-window minimum. */
            if (f->rtt_min_us) {
                u32 wm = f->rtt_win_min;
                if (f->rtt_win_min_prev && (!wm || f->rtt_win_min_prev < wm))
                    wm = f->rtt_win_min_prev;
                if (wm && wm >= f->rtt_min_us && wm - f->rtt_min_us < q_rtt)
                    q_rtt = wm - f->rtt_min_us;
                if (f->rtt_min_us < rmin)
                    rmin = f->rtt_min_us;
            }
            if (f->rtt_avg_us && (u32)(now - f->rtt_sample_ts_us) < 500000u) {
                cyc_sum += units_to_ms(f->rtt_avg_us);
                cyc_cnt++;
            }
        }
        f->q_sum = 0;
        f->q_cnt = 0;
        if (win_roll) {
            f->rtt_win_min_prev = f->rtt_win_min;
            f->rtt_win_min = 0;
        }
    }
    g.active_bulk_flows = bulk_cnt;
    g.prev_n_ctl = g.n_ctl;
    g.n_ctl = n_ctl;
    g.w_sum_ms = w_sum;
    g.owd_flows = owd_flows;
    if (rmin != NONE32)
        g.rtt_base_global_ms = units_to_ms(rmin);
    g.rtt_cycle_ms = cyc_cnt ? cyc_sum / cyc_cnt : 0;
    g.inflight_est = (g.rate100_kbps >> 3) * (g.rtt_cycle_ms > 2000u ? 2000u : g.rtt_cycle_ms);

    /* ---- Stage A: queue signal ---- */
    target_u = ms_to_units(g.target_q_ms);
    rt_u = ms_to_units(g.rtt_target_ms < g.target_q_ms ? g.rtt_target_ms : g.target_q_ms);
    if (rt_u == 0) rt_u = 1;
    {
        /* 100 ms minimum of the server-clock delay: HARQ head-of-line stalls
         * (BLER ~10 %, 8 ms each, in-order RLC) cover most 20 ms ticks, but
         * a 100 ms window always holds clean packets. */
        u32 tot = g.qh_tot, tr = g.q_trough_u, k, m = NONE32, have = 0;
        g.last_trough_u = (tot >= 8u) ? tr : NONE32;
        g.qh_tot = 0;
        g.q_trough_u = NONE32;
        g.tr_ring[g.tr_idx] = g.last_trough_u;
        if (++g.tr_idx >= RATE_RING)
            g.tr_idx = 0;
        for (k = 0; k < RATE_RING; k++) {
            if (g.tr_ring[k] != NONE32) {
                have++;
                if (g.tr_ring[k] < m) m = g.tr_ring[k];
            }
        }
        g.win_trough_u = (have >= 3u) ? m : NONE32;   /* need >= 60 ms of samples */
        /* Q3: 3-tick (60 ms) sliding minimum for lower control lag in ctrl_v3 */
        {
            u32 m3 = NONE32, h3 = 0, idx = g.tr_idx;
            for (k = 0; k < 3u; k++) {
                idx = (idx == 0u) ? (RATE_RING - 1u) : (idx - 1u);
                if (g.tr_ring[idx] != NONE32) {
                    h3++;
                    if (g.tr_ring[idx] < m3) m3 = g.tr_ring[idx];
                }
            }
            g.win_trough3_u = (h3 >= 2u) ? m3 : g.win_trough_u;
        }
        if (g.win_trough_u != NONE32 && g.win_trough_u >= BUSY_US) {
            if (g.busy_ticks < 0xffffu) g.busy_ticks++;
        } else {
            g.busy_ticks = 0;
        }
        if (g.win_trough_u != NONE32 && g.win_trough_u <= ms_to_units(1u)) {
            if (g.empty_ticks < 0xffffu) g.empty_ticks++;
        } else {
            g.empty_ticks = 0;
        }
    }
    /* Q3: global adaptive ACK thinning rate-drop guard */
    {
        u32 thinned_delta = g.stat_acks_thinned - g.thinned_last;
        g.thinned_last = g.stat_acks_thinned;
        if (g.ack_adapt) {
            if (g.thin_backoff_ticks) {
                g.thin_backoff_ticks--;
                g.thin_armed = 0;
                g.thin_drop_ticks = 0;
            } else if (thinned_delta > 0u) {
                if (!g.thin_armed) {
                    u32 base = (g.pre_thin_kbps > g.rate100_kbps) ? g.pre_thin_kbps : g.rate100_kbps;
                    if (g.c_hat_kbps && base > g.c_hat_kbps)
                        base = g.c_hat_kbps;
                    g.thin_armed = 1;
                    g.thin_ref_kbps = base;
                    g.thin_drop_ticks = 0;
                }
                if (g.thin_ref_kbps >= 15000u && g.busy_ticks == 0u &&
                    !g.drain_left && !g.drain_settle &&
                    (!g.ctl_active || g.bulk_ticks >= 75u) &&
                    g.rate100_kbps * 100u < g.thin_ref_kbps * 75u &&
                    (!g.c_hat_kbps || g.rate100_kbps * 100u < g.c_hat_kbps * 75u)) {
                    if (++g.thin_drop_ticks >= 25u) {
                        u32 j;
                        if (g.thin_strikes < 4u) g.thin_strikes++;
                        g.thin_backoff_ticks = THIN_BACKOFF_BASE << (g.thin_strikes > 2u ? 2u : g.thin_strikes - 1u);
                        g.thin_armed = 0;
                        g.thin_drop_ticks = 0;
                        g.stat_thin_backoff++;
                        for (j = 0; j < FLOW_SLOTS; j++)
                            flush_flow_ack(&g.flows[j], &g.stat_acks_flushed_event);
                        g.held_count = 0;
                    }
                } else {
                    g.thin_drop_ticks = 0;
                    if (g.rate100_kbps > g.thin_ref_kbps) {
                        u32 nr = (g.thin_ref_kbps * 3u + g.rate100_kbps) >> 2;
                        if (g.c_hat_kbps && nr > g.c_hat_kbps)
                            nr = g.c_hat_kbps;
                        g.thin_ref_kbps = nr;
                    }
                    if (g.thin_strikes && g.rate100_kbps * 100u >= g.thin_ref_kbps * 95u)
                        g.thin_strikes = 0;
                }
            } else {
                g.thin_armed = 0;
                g.thin_drop_ticks = 0;
                if (g.rate100_kbps > 0u)
                    g.pre_thin_kbps = (g.pre_thin_kbps * 3u + g.rate100_kbps) >> 2;
            }
        }
    }
    g.q_owd_u = q_owd;
    g.q_rtt_u = q_rtt;
    if (q_owd != NONE32 && g.q_force != 2u) {
        q_tick = q_owd;
        src = 1;
        /* OWD over-read guard: the RTT min filter can not sit far below a
         * real standing queue, so cap OWD at RTT queue + 20 ms. */
        if (q_rtt != NONE32 && g.q_force == 0u && q_tick > q_rtt + ms_to_units(20u))
            q_tick = q_rtt + ms_to_units(20u);
    } else if (q_rtt != NONE32 && g.q_force != 1u) {
        u32 slack = ms_to_units(g.rtt_slack_ms);
        q_tick = (q_rtt > slack) ? q_rtt - slack : 0;
        src = 2;
    }
    if (src) {
        u32 qmax = ms_to_units(Q_MAX_MS);
        if (q_tick > qmax) q_tick = qmax;
        g.q_src = src;
        g.q_age = 0;
        g.q_raw_s_u = (g.q_raw_s_u * 3u + q_tick) >> 2;
        q_tick = (q_tick > g.q_bias_u) ? q_tick - g.q_bias_u : 0;
    } else {
        if (g.q_age < 0xffffu) g.q_age++;
        if (g.q_age > QVALID_TICKS) g.q_src = 0;
    }
    g.q_s_u = (g.q_raw_s_u > g.q_bias_u) ? g.q_raw_s_u - g.q_bias_u : 0;
    g.q_bias_u -= g.q_bias_u >> 8;          /* forget a learned bias in ~5 s */
    g.dq_est_ms = units_to_ms(g.q_s_u);

    /* ---- Stage B: saturation-gated capacity estimate ---- */
    /* Proof of a busy link. OWD mode: over the last 100 ms no packet found
     * the queue empty (minimum >= 5 ms; an empty queue reads 0..3 ms after
     * TS quantization and TDD alignment). RTT mode: the min-filtered queue
     * stayed >= target/2 for 5 ticks. */
    if (src == 1u) {
        g.sat_ticks = g.busy_ticks;
    } else if (!g.drain_left && !g.drain_settle && src == 2u &&
               (g.rtt_law == 0u ? q_tick >= BUSY_US : q_tick * 2u >= rt_u)) {
        if (g.sat_ticks < 0xffffu) g.sat_ticks++;
    } else {
        g.sat_ticks = 0;
    }
    if (g.rate100_kbps > g.c_hat_kbps) {
        g.c_hat_kbps += (g.rate100_kbps - g.c_hat_kbps) >> 1;
    } else if (g.sat_ticks >= 1u && (src == 1u || g.sat_ticks >= RATE_RING)) {
        /* The queue was non-empty for the whole 100 ms rate window, so the
         * link was busy: the delivered rate IS the capacity. Never lower
         * c_hat from clamp-limited (queue-free) delivery. */
        u32 old = g.c_hat_kbps;
        g.c_hat_kbps = (g.c_hat_kbps + g.rate100_kbps) >> 1;
        g.stat_sat_updates++;
        /* Feed-forward: a proven drop of more than 15 % (lost SCell, fade)
         * scales W at once instead of waiting for the queue loop. */
        if (g.ctl_active && old && g.c_hat_kbps * 20u < old * 17u) {
            u32 r_q10 = ((g.c_hat_kbps >> 2) << 10) / ((old >> 2) + 1u);   /* < 1024 */
            g.w_bytes = (u32)(((u64)g.w_bytes * r_q10) >> 10);
        }
    }
    if (g.c_hat_kbps < 4000u)    g.c_hat_kbps = 4000u;
    if (g.c_hat_kbps > 1000000u) g.c_hat_kbps = 1000000u;
    if (g.phy_cap_kbps > 0 && g.c_hat_kbps > g.phy_cap_kbps)
        g.c_hat_kbps = g.phy_cap_kbps;

    /* Unclamped reference rate: learn only while no window was rewritten */
    rewrites = g.stat_rwnd_clamped - g.clamped_last;
    g.clamped_last = g.stat_rwnd_clamped;
    g.free_kbps -= g.free_kbps >> 12;       /* ~1.2 % per second */
    if ((rewrites == 0 || !g.ctl_active) && g.rate100_kbps > g.free_kbps)
        g.free_kbps = g.rate100_kbps;

    /* ---- Stage C: total-window loop ---- */
    if (!(g.mode & MODE_RWND_CLAMP)) {
        g.ctl_active = 0;
        g.release_left = 0;
        goto ecn;
    }
    if (g.release_left) {
        g.release_left--;
        g.ctl_active = 0;
        goto ecn;
    }
    if (n_ctl == 0) {
        if (g.idle_ticks < 0xffffu) g.idle_ticks++;
        if (g.idle_ticks > IDLE_RESEED_TICKS) g.ctl_active = 0;
        g.bulk_ticks = 0;
        goto ecn;
    }
    g.idle_ticks = 0;
    if (g.bulk_ticks < 0xffffu) g.bulk_ticks++;
    if (!g.q_src) {                          /* fail open: no queue signal */
        g.ctl_active = 0;
        goto ecn;
    }

    if (!g.ctl_active) {
        /* Start clamping only once the signal is trustworthy: 100 ms of bulk
         * traffic with a server-clock signal, or 1 s with only the RTT
         * fallback (lets each server clock pass its 250 ms check first, and
         * lets free_kbps learn the unclamped rate). */
        u32 cyc = g.rtt_cycle_ms ? g.rtt_cycle_ms : 40u;
        u32 qms = units_to_ms(g.q_s_u);
        u32 t_ms, seed, fl, ce, r;
        if (!((g.q_src == 1u && g.bulk_ticks >= 5u) || (g.q_src == 2u && g.bulk_ticks >= 50u)))
            goto ecn;
        /* Seed by Little's law: the best unclamped rate over the cycle time
         * minus today's queue plus a little. The loop corrects it. */
        fl = w_floor_bytes();
        ce = w_ceil_bytes();
        r = (g.rate100_kbps > g.free_kbps) ? g.rate100_kbps : g.free_kbps;
        t_ms = ((cyc > qms) ? cyc - qms : 0) + (g.target_q_ms >> 1);
        if (t_ms < 20u)   t_ms = 20u;
        if (t_ms > 1000u) t_ms = 1000u;
        seed = (r >> 3) * t_ms;
        if (seed < fl) seed = fl;
        if (seed > ce) seed = ce;
        g.w_bytes = seed;
        g.ctl_active = 1;
        g.drain_left = 0;
        g.drain_settle = 0;
        g.drain_next = g.tick_count + (g.ctrl_v3 ? DRAIN_PERIOD_V3 : DRAIN_PERIOD_TICKS);
        g.probe_state = 0;
        g.probe_due = g.tick_count + PROBE_PERIOD_TICKS;
        g.starve_ticks = 0;
        g.stat_seeds++;
        goto ecn;
    }

    if (g.drain_left) {
        if (--g.drain_left == 0)
            g.drain_settle = g.ctrl_v3 ? 4u : DRAIN_SETTLE_TICKS;
    } else if (g.drain_settle) {
        g.drain_settle--;
    } else if (g.q_src == 1u || (g.q_src == 2u && g.rtt_law == 0u)) {
        /* Trough law. The signal is what the queue never drained below:
         * the 100 ms OWD minimum (server-clock mode) or the 100..200 ms RTT
         * minimum minus slack_ms (RTT mode).
         * W = C x (cycle_without_queue + standing queue), so a standing
         * queue x ms above trough_ms is x / cycle of W too much, and an
         * emptied queue means W is short by about (c_hat - rate) / rate.
         * Each tick applies 1/16 of that step (about half a step per
         * window: the minimum lags a change by one cycle plus the window),
         * at most 6 % per tick. The mean queue is capped at target_ms
         * (latency bound) with 1/4 steps. */
        u32 used = (g.inflight_est == 0u || g.inflight_est * 2u >= g.w_bytes);
        u32 trs = g.win_trough_u;
        if (g.q_src == 2u) {
            u32 slack = ms_to_units(g.rtt_slack_ms);
            trs = (g.q_rtt_u == NONE32) ? NONE32 : (g.q_rtt_u > slack ? g.q_rtt_u - slack : 0);
        }
        if (trs != NONE32 && trs > ms_to_units(Q_MAX_MS))
            trs = ms_to_units(Q_MAX_MS);                        /* keeps << 12 below 2^32 */
        g.probe_state = 0;                                      /* probes are a mean-law tool */
        if (trs != NONE32) {
            u32 cyc_u = ms_to_units(g.rtt_cycle_ms > 20u ? (g.rtt_cycle_ms < 1000u ? g.rtt_cycle_ms : 1000u) : 20u);
            u32 tt_u = ms_to_units(g.trough_ms);
            u32 step_q12 = 0;                                   /* Newton step x 4096 */
            int up = 0;
            if (g.q_s_u > target_u) {
                step_q12 = ((g.q_s_u - target_u) << 12) / cyc_u;
                step_q12 <<= 2;                                 /* 1/4 instead of 1/16 */
            } else if (g.ctrl_v3 && g.trough_ms == 0u &&
                       trs <= ms_to_units(1u) && used &&
                       g.rate100_kbps * 100u < g.c_hat_kbps * 96u) {
                /* Q3 zero-collapse guard: trough_ms=0 with ctrl_v3 still refills
                 * when HARQ-only trough reads <=1 ms and link is under-filled. */
                u32 r = g.rate100_kbps ? g.rate100_kbps : 1u;
                step_q12 = (g.c_hat_kbps > r) ? (((g.c_hat_kbps - r) << 6) / r) << 6 : 256u;
                up = 1;
            } else if (trs >= tt_u) {
                step_q12 = ((trs - tt_u) << 12) / cyc_u;
            } else if (used) {
                u32 r = g.rate100_kbps ? g.rate100_kbps : 1u;
                u32 a1 = ((tt_u - trs) << 12) / cyc_u;
                u32 a2 = (g.c_hat_kbps > r) ? (((g.c_hat_kbps - r) << 6) / r) << 6 : 0;
                step_q12 = (a1 > a2) ? a1 : a2;
                /* Q3 fast capacity-step recovery: if the queue stayed empty
                 * (<= 1 ms trough) for >= 4 ticks, ramp W up at ~3%/tick so
                 * a 65->130 Mbps recovery completes in < 500 ms. */
                if (g.ctrl_v3 && g.empty_ticks >= 4u && step_q12 < 1920u)
                    step_q12 = 1920u;
                up = 1;
            }
            if (step_q12 > 4096u) step_q12 = 4096u;
            if (g.ctrl_v3 && up && trs <= ms_to_units(1u))
                step_q12 = (step_q12 * 3u) >> 5;                /* ~1/11 for faster refill */
            else
                step_q12 >>= 4;                                 /* 1/16 per tick */
            if (step_q12 > 246u) step_q12 = 246u;               /* max 6 % per tick */
            if (step_q12) {
                u32 d = (u32)(((u64)g.w_bytes * step_q12) >> 12);
                if (up) {
                    g.w_bytes += d;
                } else {
                    /* Never cut below the zero-queue window at 7/8 of c_hat:
                     * cuts act one cycle late (no retraction), so during a
                     * slow-start overshoot the loop would otherwise keep
                     * cutting while old data drains, and land far too low. */
                    u32 cyc = g.rtt_cycle_ms ? g.rtt_cycle_ms : 40u, qms = units_to_ms(g.q_s_u);
                    u32 noq = (cyc > qms + 10u) ? cyc - qms : 10u;
                    u32 ff = ((g.c_hat_kbps - (g.c_hat_kbps >> 3)) >> 3) * (noq > 1000u ? 1000u : noq);
                    if (g.w_bytes - d < ff)
                        d = (g.w_bytes > ff) ? g.w_bytes - ff : 0;
                    /* A cut acts one cycle late: at most 25 % per cycle. */
                    if ((s32)(g.tick_count - g.cut_ref_until) >= 0) {
                        u32 cyc_t = (g.rtt_cycle_ms ? g.rtt_cycle_ms : 40u) / 20u + 2u;
                        g.cut_ref_w = g.w_bytes;
                        g.cut_ref_until = g.tick_count + (cyc_t > 50u ? 50u : cyc_t);
                    }
                    {
                        u32 lim = g.cut_ref_w - (g.cut_ref_w >> 2);
                        if (g.w_bytes - d < lim)
                            d = (g.w_bytes > lim) ? g.w_bytes - lim : 0;
                    }
                    g.w_bytes -= d;
                }
            }
        }
        /* Periodic drain (also in this mode): empties the queue so a flow
         * that joined over a standing queue re-reads its true minimum. */
        if (g.drain_enable && (s32)(g.tick_count - g.drain_next) >= 0) {
            g.drain_left = DRAIN_TICKS;
            g.drain_next = g.tick_count + (g.ctrl_v3 ? DRAIN_PERIOD_V3 : DRAIN_PERIOD_TICKS);
            g.stat_drains++;
        }
    } else {
        /* RTT fallback (no usable server clock): mean-queue law plus probes
         * and periodic drains. */
        s32 err = (s32)rt_u - (s32)g.q_s_u;
        u32 used = (g.inflight_est == 0u || g.inflight_est * 2u >= g.w_bytes);
        if (err > 0) {
            /* Grow only while the flows use at least half of W (Little's
             * law); app-limited flows must not inflate W. */
            if (used) {
                u32 e_q8 = ((u32)err << 8) / rt_u;              /* 0..256 */
                g.w_bytes += (u32)(((u64)(g.w_bytes >> 3) * e_q8) >> 8);
            }
        } else if (err < 0) {
            u32 e_q8 = ((u32)(-err) << 8) / rt_u;
            if (e_q8 > 512u) e_q8 = 512u;                       /* max -25 % per tick */
            g.w_bytes -= (u32)(((u64)(g.w_bytes >> 3) * e_q8) >> 8);
        }

        /* Upward probe: runs only when the queue signal says "queue" but
         * the delivered rate says "headroom". A probe that raises the rate
         * >= 10 % proves the signal reads high, so learn that bias. */
        if (g.probe_enable) {
            if (g.probe_state == 0) {
                if ((s32)(g.tick_count - g.probe_due) >= 0 && used &&
                    g.q_s_u * 2u >= rt_u &&
                    g.rate100_kbps * 16u < g.c_hat_kbps * 15u) {
                    g.probe_state = 1;
                    g.probe_rate_pre = g.rate100_kbps;
                    g.probe_q_raw = g.q_raw_s_u;
                    g.probe_w_saved = g.w_bytes;
                    g.w_bytes += g.w_bytes >> 2;
                    g.probe_due = g.tick_count + PROBE_EVAL_TICKS;
                }
            } else if ((s32)(g.tick_count - g.probe_due) >= 0) {
                if (g.rate100_kbps >= g.probe_rate_pre + g.probe_rate_pre / 10u) {
                    u32 cap = ms_to_units(Q_BIAS_MAX_MS);
                    g.q_bias_u = (g.q_bias_u + g.probe_q_raw) >> 1;
                    if (g.q_bias_u > cap) g.q_bias_u = cap;
                    g.stat_probe_win++;
                } else {
                    if (g.w_bytes > g.probe_w_saved) g.w_bytes = g.probe_w_saved;
                    g.stat_probe_fail++;
                }
                g.probe_state = 0;
                g.probe_due = g.tick_count + PROBE_PERIOD_TICKS;
            }
        }

        /* Periodic drain: 60 ms at 5/8 window empties a standing queue of
         * up to ~3/8 of a cycle so every flow's delay minimum refreshes. */
        if (g.drain_enable && g.probe_state == 0 &&
            (s32)(g.tick_count - g.drain_next) >= 0) {
            g.drain_left = DRAIN_TICKS;
            g.drain_next = g.tick_count + DRAIN_PERIOD_TICKS;
            g.stat_drains++;
        }
    }
    {
        u32 fl = w_floor_bytes(), ce = w_ceil_bytes();
        if (g.w_bytes < fl) g.w_bytes = fl;
        if (g.w_bytes > ce) g.w_bytes = ce;
    }
    if (g.w_fix_bytes)                       /* bench tuning arm: fixed total window */
        g.w_bytes = g.w_fix_bytes;

    /* Fail-safe: windows are clamped and used, the rate sits under 35 % of
     * the unclamped rate, and the link is NOT proven busy (a busy link at a
     * low rate is a real capacity drop, which the loop already handles) ->
     * the clamp is starving the flows: release it for 3 s. */
    if (g.free_kbps && rewrites &&
        !((g.q_src == 1u) ? (g.busy_ticks > 0u) :
          (g.rtt_law == 0u ? g.q_s_u >= BUSY_US : g.q_s_u >= rt_u)) &&
        g.rate100_kbps * 100u < g.free_kbps * 35u &&
        (g.inflight_est == 0u || g.inflight_est * 2u >= g.w_bytes)) {
        if (++g.starve_ticks >= STARVE_TICKS) {
            g.starve_ticks = 0;
            g.release_left = RELEASE_TICKS;
            g.ctl_active = 0;
            g.stat_failsafe++;
        }
    } else {
        g.starve_ticks = 0;
    }

ecn:
    if (g.ctl_active) {                      /* bench: mean queue = q_ms_sum / active_ticks */
        g.stat_active_ticks++;
        g.stat_q_ms_sum += g.dq_est_ms;
    }
    /* ECN / non-ECN UDP drop probability in [0..1024]: ramps linearly above
     * ecn_ms (O1b: own knob; target_ms is now the mean-queue cap) */
    if (g.dq_est_ms > g.ecn_ms) {
        u32 excess = g.dq_est_ms - g.ecn_ms;
        u32 p = excess * 41u; /* ~4% per ms -> 100% at +25 ms excess */
        g.p_ecn_q10 = (p > 1024u) ? 1024u : p;
    } else {
        g.p_ecn_q10 = 0;
    }
}

/* ---------- TCP option parser (WSopt, MSS, SACK, TIMESTAMP) ---------- */
struct tcp_opts_parsed {
    u8  has_ws;
    u8  wscale;
    u8  has_mss;
    u16 mss;
    u8  has_ts;
    u32 tsval;
    u32 tsecr;
    u8  has_sack_or_unknown;
};

static void parse_tcp_opts(const u8 *opt, u32 opt_len, struct tcp_opts_parsed *out)
{
    u32 i = 0;
    out->has_ws = 0; out->wscale = 0;
    out->has_mss = 0; out->mss = 0;
    out->has_ts = 0; out->tsval = 0; out->tsecr = 0;
    out->has_sack_or_unknown = 0;

    while (i < opt_len) {
        u8 kind = opt[i];
        u8 len;
        if (kind == 0) break;             /* EOL */
        if (kind == 1) { i++; continue; } /* NOP */
        if (i + 1 >= opt_len) { out->has_sack_or_unknown = 1; break; }
        len = opt[i + 1];
        if (len < 2 || i + len > opt_len) { out->has_sack_or_unknown = 1; break; }

        if (kind == 2 && len == 4) { /* MSS */
            out->has_mss = 1;
            out->mss = ((u16)opt[i + 2] << 8) | opt[i + 3];
        } else if (kind == 3 && len == 3) { /* WSopt */
            out->has_ws = 1;
            out->wscale = opt[i + 2] > 14 ? 14 : opt[i + 2];
        } else if (kind == 8 && len == 10) { /* TIMESTAMP */
            out->has_ts = 1;
            out->tsval = ((u32)opt[i + 2] << 24) | ((u32)opt[i + 3] << 16) |
                         ((u32)opt[i + 4] << 8)  | (u32)opt[i + 5];
            out->tsecr = ((u32)opt[i + 6] << 24) | ((u32)opt[i + 7] << 16) |
                         ((u32)opt[i + 8] << 8)  | (u32)opt[i + 9];
        } else {
            /* SACK (5), SACK_PERM (4), MD5, MPTCP, etc. — never coalesce! */
            out->has_sack_or_unknown = 1;
        }
        i += len;
    }
}

/* Update flow passive WAN RTT estimate */
static inline void record_rtt_sample(struct flow_entry *f, u32 sample_us, u32 now)
{
    if (sample_us < 5000u || sample_us > 2000000u)
        return;
    g.stat_rtt_samples++;
    f->rtt_sample_ts_us = now;
    if (f->rtt_us == 0)
        f->rtt_us = sample_us;
    else
        f->rtt_us = (f->rtt_us * 3u + sample_us) >> 2;

    /* Y6: two-bucket windowed minimum. The original replaced rtt_min with the
     * FIRST sample after 45 s, so under a persistently bloated queue the base
     * RTT latched onto a loaded value. Now rtt_min = min(previous 45 s epoch,
     * current epoch). */
    if (f->rtt_min_next_us == 0 || sample_us < f->rtt_min_next_us)
        f->rtt_min_next_us = sample_us;
    if (f->rtt_min_us == 0 || sample_us < f->rtt_min_us)
        f->rtt_min_us = sample_us;
    if ((u32)(now - f->rtt_min_ts_us) > 45000000u) {
        f->rtt_min_us = f->rtt_min_next_us;
        f->rtt_min_next_us = sample_us;
        f->rtt_min_ts_us = now;
    }

    /* O1b: 100 ms min filter (queue signal fallback) and the MEAN cycle time.
     * rtt_min is only the lucky tail of a 13..57 ms distribution on this
     * link; a window has to cover the mean, not the minimum. */
    if (f->rtt_win_min == 0 || sample_us < f->rtt_win_min)
        f->rtt_win_min = sample_us;
    if (f->rtt_avg_us == 0)
        f->rtt_avg_us = sample_us;
    else
        f->rtt_avg_us = f->rtt_avg_us - (f->rtt_avg_us >> 3) + (sample_us >> 3);
}

/*
 * O1b: one-way delay of DL data on the SERVER's TCP timestamp clock.
 * owd_rel = (hook time since anchor) - (server TSval ticks since anchor), so
 * the unknown clock offset cancels and owd_rel - min(owd_rel) is the delay
 * added since the emptiest moment: the tower queue (plus any server-side
 * wait). Unlike RTT it does not contain UL ACK scheduling jitter.
 * The server clock must run at ~1 kHz (Linux >= 4.13, FreeBSD, macOS): it is
 * checked after 250 ms (0.6x..1.6x) and a 16 s epoch drift check rejects a
 * clock that walks > 25 ms per epoch twice in a row. A rejected flow falls
 * back to the RTT signal. Bounded work: no loops.
 */
static void owd_sample(struct flow_entry *f, u32 tsval, u32 now)
{
    u32 dts, dt, q;
    s32 rel;

    if (f->owd_state == OWD_NONE) {
        f->owd_t0 = now;
        f->owd_ts0 = tsval;
        f->owd_have = 0;
        f->owd_prev_valid = 0;
        f->owd_drift_strikes = 0;
        f->owd_drift_sign = 0;
        f->owd_state = OWD_CHECK;
        return;
    }
    if (f->owd_state == OWD_BAD) {
        if ((u32)(now - f->owd_t0) > OWD_RETRY_US && f->owd_retries < OWD_MAX_RETRY)
            f->owd_state = OWD_NONE;          /* re-test on the next packet */
        return;
    }
    dts = tsval - f->owd_ts0;
    dt = now - f->owd_t0;
    if ((s32)dts < 0)
        return;                               /* older TSval (reordered) */
    if (dts > 120000u || dt > 122070312u) {   /* > 120 s: idle flow, start over */
        f->owd_state = OWD_NONE;
        return;
    }
    rel = (s32)(dt - ms_to_units(dts));

    if (f->owd_state == OWD_CHECK) {
        if (!f->owd_have || rel < f->owd_base_next)
            f->owd_base_next = rel;
        f->owd_have = 1;
        if (dt >= OWD_CHECK_US) {
            u32 ex = ms_to_units(dts);
            if (ex * 5u >= dt * 3u && ex * 5u <= dt * 8u) {
                /* A flow that joins while a queue stands starts with that
                 * queue inside its minimum and under-reads; the periodic
                 * drain (every 8 s) empties the queue so its minimum snaps
                 * to the true level. (Subtracting the current estimate
                 * instead was tried and made joiners over-read 9..55 ms.) */
                f->owd_base = f->owd_base_next;
                f->owd_base_next = rel;
                f->owd_epoch_ts = now;
                f->owd_state = OWD_OK;
                g.stat_owd_ok++;
            } else {
                f->owd_state = OWD_BAD;
                f->owd_retries++;
                f->owd_t0 = now;
                g.stat_owd_bad++;
            }
        }
        return;
    }

    /* OWD_OK */
    if (dt > OWD_REANCHOR_US) {
        f->owd_t0 = now;
        f->owd_ts0 = tsval;
        f->owd_base -= rel;
        f->owd_base_next -= rel;
        f->owd_prev_min -= rel;
        rel = 0;
    }
    if (rel < f->owd_base_next)
        f->owd_base_next = rel;
    if (rel < f->owd_base)
        f->owd_base = rel;
    if ((u32)(now - f->owd_epoch_ts) > OWD_EPOCH_US) {
        /* Drift check only while clamping: under an unshaped bloat the queue
         * never empties and epoch minimums legitimately wander. */
        if (f->owd_prev_valid && g.ctl_active) {
            s32 d = f->owd_base_next - f->owd_prev_min;
            s32 lim = (s32)ms_to_units(OWD_DRIFT_MS);
            if (d > lim || d < -lim) {
                s8 sg = (d > 0) ? 1 : -1;
                if (f->owd_drift_sign == sg) {
                    if (++f->owd_drift_strikes >= 2u) {
                        f->owd_state = OWD_BAD;
                        f->owd_retries++;
                        f->owd_t0 = now;
                        g.stat_owd_bad++;
                        return;
                    }
                } else {
                    f->owd_drift_sign = sg;
                    f->owd_drift_strikes = 1;
                }
            } else {
                f->owd_drift_sign = 0;
                f->owd_drift_strikes = 0;
            }
        }
        f->owd_prev_min = f->owd_base_next;
        f->owd_prev_valid = 1;
        f->owd_base = f->owd_base_next;
        f->owd_base_next = rel;
        f->owd_epoch_ts = now;
    }
    q = (u32)(rel - f->owd_base);             /* >= 0: base <= rel above */
    if (q > ms_to_units(Q_MAX_MS))
        q = ms_to_units(Q_MAX_MS);
    /* O1b: standing-queue detector. The minimum delay over 100 ms is what
     * the queue never drained below: a packet that found the queue empty
     * (and was not held behind a HARQ retransmission) reads ~0. */
    if (f->is_bulk && g.qh_tot < 0x7fffffffu) {
        g.qh_tot++;
        if (q < g.q_trough_u)
            g.q_trough_u = q;
    }
    if (f->q_cnt < 4000u) {                   /* 4000 x 976562 < 2^32 */
        f->q_sum += q;
        f->q_cnt++;
    }
}

/* ---------- Compute target RWND (bytes) for flow f ----------
 * O1b: share of the total window W. RTT-fair split (W_f proportional to the
 * flow's cycle time gives equal rates). Returns NO_CLAMP when the controller
 * is not active (mode off, no queue signal, fail-safe release, idle). */
static u32 compute_flow_rwnd_target(const struct flow_entry *f)
{
    u32 w, share;
    u32 min_win = (u32)f->mss * 4u; /* Fast Retransmit floor: >= 4 MSS */
    if (min_win < 5400u) min_win = 5400u;

    if (!g.ctl_active || g.w_bytes == 0)
        return NO_CLAMP;
    w = g.w_bytes;
    if (g.drain_left) {
        if (g.ctrl_v3) {
            /* Q3: gentler ramped drain (3/4, 3/4, 7/8) avoids rebound bursts */
            w = (g.drain_left == 1u) ? (w - (w >> 3)) : (w - (w >> 2));
        } else {
            w = (w >> 1) + (w >> 3);          /* v0.2-o1b: 5/8 during a drain */
        }
    }

    /* Mouse / startup flows (< 64 KB) and non-bulk flows may use all of W */
    if (f->dl_bytes_total < 65536u || !f->is_bulk || g.n_ctl <= 1u) {
        share = w;
    } else if (g.w_sum_ms) {
        u32 frac_q16 = (flow_weight_ms(f) << 16) / g.w_sum_ms;
        if (frac_q16 > 65536u) frac_q16 = 65536u;
        share = (u32)(((u64)w * frac_q16) >> 16);
    } else {
        share = w / g.n_ctl;
    }
    if (share < min_win)
        share = min_win;
    return share;
}

/* ---------- Main NF_BR_FORWARD Hook body (sees BOTH DL and UL) ---------- */
static unsigned int qctrl_hook_body(struct sk_buff *skb,
                                    const struct net_device *in,
                                    const struct net_device *out,
                                    int (*okfn)(struct sk_buff *))
{
    int is_dl, is_ul;
    u16 proto;
    u8 *l3;
    u32 l3_len, ip_tot_len, l4_off, l4_proto;
    u32 ip_src, ip_dst;
    u8 is_v6 = 0, ecn_bits = 0;
    u32 now;

    if (unlikely(g.unloading || !skb || !in || !out))
        return NF_ACCEPT;

    is_dl = is_dev_lte(in) && is_dev_eth0(out);
    is_ul = !is_dl && is_dev_eth0(in) && is_dev_lte(out);
    if (!is_dl && !is_ul)
        return NF_ACCEPT;

    proto = ntohs(skb->protocol);
    if (proto != ETH_P_IP && proto != ETH_P_IPV6)
        return NF_ACCEPT;

    now = now_us();
    if ((u32)(now - g.last_tick_us) >= CTRL_TICK_US)
        controller_tick(now);

    if (is_dl) {
        g.stat_dl_pkts++;
        g.epoch_dl_bytes += skb->len;
    } else {
        g.stat_ul_pkts++;
        g.epoch_ul_bytes += skb->len;
    }

    /* Linear header check (IPv4 >= 20, IPv6 >= 40) */
    l3_len = skb->len - skb->data_len;
    l3 = skb->data;
    if (proto == ETH_P_IP) {
        if (l3_len < 20u || (l3[0] >> 4) != 4)
            return NF_ACCEPT;
        l4_off = (u32)(l3[0] & 0x0fu) * 4u;
        ip_tot_len = ((u32)l3[2] << 8) | l3[3];
        if (l4_off < 20u || ip_tot_len < l4_off || ip_tot_len > skb->len)
            return NF_ACCEPT;
        /* Ignore fragmented IPv4 packets */
        if (((((u16)l3[6] << 8) | l3[7]) & 0x3fffu) != 0)
            return NF_ACCEPT;
        ecn_bits = l3[1] & 0x03u;
        l4_proto = l3[9];
        ip_src = ((u32)l3[12] << 24) | ((u32)l3[13] << 16) | ((u32)l3[14] << 8) | l3[15];
        ip_dst = ((u32)l3[16] << 24) | ((u32)l3[17] << 16) | ((u32)l3[18] << 8) | l3[19];
    } else {
        is_v6 = 1;
        if (l3_len < 40u || (l3[0] >> 4) != 6)
            return NF_ACCEPT;
        l4_off = 40u;
        ip_tot_len = 40u + (((u32)l3[4] << 8) | l3[5]);
        if (ip_tot_len > skb->len)
            return NF_ACCEPT;
        ecn_bits = (l3[1] >> 4) & 0x03u;
        l4_proto = l3[6];
        /* Fold 128-bit IPv6 addresses into 32-bit hash keys */
        ip_src = (((u32)l3[8]  << 24) | ((u32)l3[9]  << 16) | ((u32)l3[10] << 8) | l3[11]) ^
                 (((u32)l3[12] << 24) | ((u32)l3[13] << 16) | ((u32)l3[14] << 8) | l3[15]) ^
                 (((u32)l3[16] << 24) | ((u32)l3[17] << 16) | ((u32)l3[18] << 8) | l3[19]) ^
                 (((u32)l3[20] << 24) | ((u32)l3[21] << 16) | ((u32)l3[22] << 8) | l3[23]);
        ip_dst = (((u32)l3[24] << 24) | ((u32)l3[25] << 16) | ((u32)l3[26] << 8) | l3[27]) ^
                 (((u32)l3[28] << 24) | ((u32)l3[29] << 16) | ((u32)l3[30] << 8) | l3[31]) ^
                 (((u32)l3[32] << 24) | ((u32)l3[33] << 16) | ((u32)l3[34] << 8) | l3[35]) ^
                 (((u32)l3[36] << 24) | ((u32)l3[37] << 16) | ((u32)l3[38] << 8) | l3[39]);
    }

    /* ---------------- DOWNLINK ECN-CE & NON-ECN UDP PI DROP ---------------- */
    if (is_dl && (l4_proto == 17u || l4_proto == 6u)) {
        if (l4_proto == 17u)
            g.epoch_udp_dl_bytes += skb->len;

        /* Lever Q1 (ECN-CE): mark ECT(0)=2 or ECT(1)=1 -> CE=3 on DL congestion */
        if ((g.mode & MODE_DL_ECN) && g.p_ecn_q10 > 0 &&
            (ecn_bits == 1u || ecn_bits == 2u) && ip_tot_len >= 500u) {
            g.ecn_accum += g.p_ecn_q10;
            if (g.ecn_accum >= 1024u) {
                g.ecn_accum -= 1024u;
                if (skb_make_writable(skb, is_v6 ? 4u : 12u)) {
                    l3 = skb->data; /* MUST reload after skb_make_writable! */
                    if (!is_v6) {
                        u16 old16 = ((u16)l3[0] << 8) | l3[1];
                        u16 new16;
                        l3[1] |= 0x03u;
                        new16 = ((u16)l3[0] << 8) | l3[1];
                        csum_replace2_ip4(l3, htons(old16), htons(new16));
                    } else {
                        l3[1] |= 0x30u; /* IPv6 TC ECN bits = 11 (CE) */
                    }
                    g.stat_ecn_marked++;
                }
            }
        }
        /* Lever Q2 (Non-ECN heavy UDP drop): never touch small gaming/VoIP (<500B) */
        else if ((g.mode & MODE_UDP_DROP) && l4_proto == 17u && ecn_bits == 0u &&
                 ip_tot_len >= 500u && g.dq_est_ms > g.ecn_ms + 10u &&
                 g.last_udp_dl_kbps > 2000u) {
            /* Y6: never drop replies FROM well-known service ports (DNS 53,
             * NTP 123, DHCP 67/68, DHCPv6 547 ...): a dropped >=500 B DNS
             * answer costs the customer a 1-5 s resolver timeout. QUIC/443
             * and high-port tunnels stay eligible. */
            u32 sport = 0xffffu;
            if (l3_len >= l4_off + 4u)
                sport = ((u32)l3[l4_off] << 8) | l3[l4_off + 1];
            if (sport >= 1024u || sport == 443u) {
                /* Gentle drop probability (~0.25x ECN ramp, capped ~5%) */
                u32 p_drop = g.p_ecn_q10 >> 4;
                if (p_drop > 51u) p_drop = 51u;
                g.drop_accum += p_drop;
                if (g.drop_accum >= 1024u) {
                    g.drop_accum -= 1024u;
                    g.stat_udp_dropped++;
                    return NF_DROP;
                }
            }
        }
    }

    /* Non-TCP packets are done here */
    if (l4_proto != 6u)
        return NF_ACCEPT;

    /* Ensure TCP base header (20 B) is linear */
    if (l3_len < l4_off + 20u)
        return NF_ACCEPT;

    {
        u8 *th = l3 + l4_off;
        u32 tcp_hdr_len = (u32)(th[12] >> 4) * 4u;
        u8  flags = th[13];
        u16 sport = ((u16)th[0] << 8) | th[1];
        u16 dport = ((u16)th[2] << 8) | th[3];
        u32 seq   = ((u32)th[4] << 24) | ((u32)th[5] << 16) | ((u32)th[6] << 8) | th[7];
        u32 ack   = ((u32)th[8] << 24) | ((u32)th[9] << 16) | ((u32)th[10] << 8) | th[11];
        u16 win   = ((u16)th[14] << 8) | th[15];
        u32 tcp_payload_len;
        struct tcp_opts_parsed opts;
        struct flow_entry *f;

        if (tcp_hdr_len < 20u || l4_off + tcp_hdr_len > ip_tot_len ||
            l3_len < l4_off + tcp_hdr_len)
            return NF_ACCEPT;
        tcp_payload_len = ip_tot_len - l4_off - tcp_hdr_len;
        parse_tcp_opts(th + 20, tcp_hdr_len - 20u, &opts);

        /* ---------------- DOWNLINK TCP PATH (lte0pdn2 -> eth0) ---------------- */
        if (is_dl) {
            /* Y6: do not let inbound bare SYNs / RSTs (internet scans hit every
             * customer IP) allocate slots and evict real flows. */
            int dl_create = !(flags & TCP_RST) &&
                            !((flags & TCP_SYN) && !(flags & TCP_ACK));
            f = flow_lookup_or_alloc(ip_dst, ip_src, dport, sport, is_v6, now, dl_create);
            if (!f)
                return NF_ACCEPT;
            f->last_seen_us = now;

            /* Track SYN-ACK: complete WSopt negotiation + handshake WAN RTT */
            if ((flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) {
                if (opts.has_ws && f->syn_ws_seen)
                    f->wscale_valid = 1;
                else
                    f->wscale_valid = 0;
                if (opts.has_mss && opts.mss >= 536u && opts.mss <= 1460u)
                    f->mss = opts.mss;
                if (f->syn_pending) {
                    f->syn_pending = 0;
                    record_rtt_sample(f, now - f->syn_ts_us, now);
                    /* Q2: this answers the customer's SYN seen on this flow */
                    ulc_on_synack(&f->ul, f->syn_ws_seen, opts.has_ws, opts.wscale,
                                  now - f->syn_ts_us, now);
                }
            }

            /* Accumulate DL bytes */
            if (tcp_payload_len > 0) {
                f->last_dl_data_us = now;
                f->dl_bytes_epoch += tcp_payload_len;
                if (f->dl_bytes_total < 0x7fffffffu)
                    f->dl_bytes_total += tcp_payload_len;
                /* O1b: tower queue from the server's TSval clock */
                if (opts.has_ts && f->wscale_valid)
                    owd_sample(f, opts.tsval, now);
            }

            /* Passive WAN RTT #1: UL TSval echoed in DL TSecr.
             * Y6: match TSecr >= probe (serial compare) instead of ==, because
             * with ACK thinning the probed ACK is usually superseded and the
             * server then echoes a later TSval, so == never matched. */
            if (opts.has_ts && f->ts_probe_active && opts.tsecr != 0 &&
                !seq_lt(opts.tsecr, f->ts_probe_val)) {
                f->ts_probe_active = 0;
                record_rtt_sample(f, now - f->ts_probe_us, now);
            }
            /* Passive WAN RTT #2 (fallback without TSopt): DL data goes BEYOND
             * the probed right edge (Y6: seq_gt; a segment ending exactly at
             * the old edge was already allowed by the old window). */
            if (f->edge_probe_active && tcp_payload_len > 0 &&
                seq_gt(seq + tcp_payload_len, f->edge_probe_seq)) {
                f->edge_probe_active = 0;
                record_rtt_sample(f, now - f->edge_probe_us, now);
            }

            /* Q2: this segment carries the server's receive window for the
             * customer's upload. The estimates run in every mode; the window
             * is lowered only with MODE_UL_CLAMP. */
            if ((flags & TCP_ACK) && !(flags & (TCP_SYN | TCP_RST)) &&
                (f->ul.state & ULC_S_WS)) {
                u32 target = ulc_on_dl_ack(&g.ul, &f->ul, ack, now, f->mss);
                u16 sent = (g.mode & MODE_UL_CLAMP) ?
                           ulc_raw_window(&f->ul, ack, win, target) : win;

                if (sent != win && !tcp_set_window(skb, l4_off, win, sent))
                    sent = win;
                ulc_sent(&g.ul, &f->ul, ack, win, sent);
            }
            return NF_ACCEPT;
        }

        /* ---------------- UPLINK TCP PATH (eth0 -> lte0pdn2) ---------------- */
        f = flow_lookup_or_alloc(ip_src, ip_dst, sport, dport, is_v6, now, 1);
        if (!f)
            return NF_ACCEPT;
        f->last_seen_us = now;

        /* Client SYN: record client's advertised rcv_wscale and start handshake RTT */
        if ((flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) {
            flush_flow_ack(f, &g.stat_acks_flushed_event);
            f->syn_ws_seen = opts.has_ws ? 1 : 0;
            f->wscale_cli = opts.has_ws ? opts.wscale : 0;
            f->wscale_valid = 0;
            if (opts.has_mss && opts.mss >= 536u && opts.mss <= 1460u)
                f->mss = opts.mss;
            f->syn_ts_us = now;
            f->syn_pending = 1;
            f->max_right_edge = 0;
            f->edge_valid = 0;
            f->dl_bytes_total = 0;
            /* O1b: a new connection on a reused 4-tuple starts clean */
            f->owd_state = OWD_NONE;
            f->owd_retries = 0;
            f->ul_ts_valid = 0;
            f->ts_probe_active = 0;
            f->rtt_avg_us = 0;
            f->rtt_win_min = 0;
            f->rtt_win_min_prev = 0;
            f->last_dl_data_us = now;
            f->recov_until_us = now;
            f->thin_backoff_until_us = now;
            f->thin_ref_kbps = 0;
            f->thin_drop_ticks = 0;
            f->thin_active_flow = 0;
            ulc_flow_reset(&f->ul, now);       /* Q2 */
            return NF_ACCEPT;
        }

        /* Q2: the customer's upload data (every mode, so the estimates are warm) */
        if (tcp_payload_len > 0 && !(flags & TCP_RST))
            ulc_on_ul_data(&g.ul, &f->ul, seq + tcp_payload_len, now);

        /* O1b: arm the passive RTT probe on the FIRST UL packet that carries
         * a new TSval (one probe per RTT). Y6 armed on any packet after a
         * 25 ms gap; an earlier ACK with the same TSval could then be the one
         * the server echoed, so samples read up to one TS tick short. */
        if (opts.has_ts) {
            if (!f->ts_probe_active &&
                (!f->ul_ts_valid || opts.tsval != f->last_ul_tsval)) {
                f->ts_probe_val = opts.tsval;
                f->ts_probe_us = now;
                f->ts_probe_active = 1;
            } else if (f->ts_probe_active && (u32)(now - f->ts_probe_us) > 1000000u) {
                f->ts_probe_active = 0;
            }
            f->last_ul_tsval = opts.tsval;
            f->ul_ts_valid = 1;
        } else if (f->ts_probe_active && (u32)(now - f->ts_probe_us) > 1000000u) {
            f->ts_probe_active = 0;
        }

        /* ---- Step 1: Dynamic TCP RWND Clamping (when MODE_RWND_CLAMP enabled) ---- */
        if ((g.mode & MODE_RWND_CLAMP) && (flags & TCP_ACK) &&
            !(flags & (TCP_SYN | TCP_RST)) && f->wscale_valid && win > 0) {
            u32 orig_win_bytes = ((u32)win) << f->wscale_cli;
            u32 target_bytes = compute_flow_rwnd_target(f);
            u32 safe_bytes = target_bytes;
            u32 out_bytes;
            u16 new_win_raw;

            /* RFC 1122 non-retraction guard: never move ack + rwnd backwards! */
            if (f->edge_valid && seq_gt(f->max_right_edge, ack)) {
                u32 min_no_retract = f->max_right_edge - ack;
                if (safe_bytes < min_no_retract)
                    safe_bytes = min_no_retract;
            }

            /* Never inflate above customer's advertised rwnd */
            out_bytes = (safe_bytes < orig_win_bytes) ? safe_bytes : orig_win_bytes;
            new_win_raw = (u16)((out_bytes + ((1u << f->wscale_cli) - 1u)) >> f->wscale_cli);
            if (new_win_raw == 0)
                new_win_raw = 1;
            if (new_win_raw > win)
                new_win_raw = win;

            if (new_win_raw != win) {
                if (tcp_set_window(skb, l4_off, win, new_win_raw)) {
                    l3 = skb->data;
                    th = l3 + l4_off;
                    win = new_win_raw;
                    g.stat_rwnd_clamped++;
                }
                /* Y6: if skb_make_writable failed, the ORIGINAL window goes out;
                 * the edge below is then tracked from what was really sent
                 * (the original recorded the clamped edge, which could later
                 * license a retraction). */
            }

            /* Track max right edge of what was ACTUALLY sent (Y6: after the
             * rewrite) and arm fallback RTT probe if the edge advances */
            {
                u32 new_edge = ack + (((u32)win) << f->wscale_cli);
                if (!f->edge_valid || seq_gt(new_edge, f->max_right_edge)) {
                    if (!opts.has_ts && !f->edge_probe_active && f->edge_valid &&
                        (u32)(now - f->rtt_sample_ts_us) > 30000u) {
                        f->edge_probe_seq = f->max_right_edge;
                        f->edge_probe_us = now;
                        f->edge_probe_active = 1;
                    }
                    f->max_right_edge = new_edge;
                    f->edge_valid = 1;
                }
            }
        } else if ((flags & TCP_ACK) && f->wscale_valid) {
            /* Keep right-edge tracker warm even in observe-only mode */
            u32 edge = ack + (((u32)win) << f->wscale_cli);
            if (!f->edge_valid || seq_gt(edge, f->max_right_edge)) {
                f->max_right_edge = edge;
                f->edge_valid = 1;
            }
        }

        /* ---- Step 2: TDD-Aligned CAKE-Safe Uplink TCP ACK Coalescing ---- */
        {
            int pure_ack = (tcp_payload_len == 0) &&
                           ((flags & (TCP_SYN | TCP_FIN | TCP_RST | TCP_PSH |
                                      TCP_URG | TCP_ECE | TCP_CWR)) == 0) &&
                           ((flags & TCP_ACK) != 0);
            int eligible;

            if (pure_ack) {
                g.stat_acks_seen++;
                if ((u32)(now - f->recent_ack_us) <= 10000u) {
                    if (f->recent_acks_10ms < 65000u) f->recent_acks_10ms++;
                } else {
                    f->recent_acks_10ms = 1;
                }
                f->recent_ack_us = now;
            }

            if (!(g.mode & MODE_ACK_THIN)) {
                if (f->held_ack)
                    flush_flow_ack(f, &g.stat_acks_flushed_event);
                f->last_ack_sent = ack;
                f->last_ul_seq = seq;
                f->last_win_sent = win;
                return NF_ACCEPT;
            }

            /* Strict CAKE safety predicates:
             *  - pure cumulative ACK, no SACK/unknown opts, no ECE/CWR/SYN/FIN/RST/PSH
             *  - strictly advancing ack_seq (never coalesce dupACKs -> protects Fast Retx!)
             *  - same UL seq, non-zero window, past slow-start, active flow */
            if (!g.ack_adapt) {
                /* Exact v0.2-o1b path */
                eligible = pure_ack &&
                           !opts.has_sack_or_unknown &&
                           win > 0 &&
                           f->dl_bytes_total >= 65536u &&
                           f->recent_acks_10ms >= 2u &&
                           f->last_ul_seq == seq &&
                           seq_gt(ack, f->held_ack ? f->held_ack_seq : f->last_ack_sent);
            } else {
                /* Q3 (v0.3): adaptive, safe, evenly-spaced ACK thinning */
                u32 ref_ack = f->held_ack ? f->held_ack_seq : f->last_ack_sent;
                int adv = seq_gt(ack, ref_ack);
                int in_recov = ((s32)(now - f->recov_until_us) < 0);
                int flow_bo = ((s32)(now - f->thin_backoff_until_us) < 0);
                /* Significant clamp window opening: >= 2 MSS jump (or waking from
                 * <= 4 MSS floor). Ignore 1-unit (128 B) rounding jitter. */
                u32 win_step = ((u32)(f->mss ? f->mss : DEFAULT_MSS) * 2u) >> f->wscale_cli;
                u32 win_floor = ((u32)(f->mss ? f->mss : DEFAULT_MSS) * 4u) >> f->wscale_cli;
                int clamp_open = g.ctl_active && f->wscale_valid &&
                                 ((u32)win > (u32)f->last_win_sent + (win_step ? win_step : 1u) ||
                                  (f->last_win_sent <= win_floor && win > f->last_win_sent));

                /* Latch loss-recovery cooldown on any SACK option or duplicate ACK */
                if (opts.has_sack_or_unknown ||
                    (pure_ack && ack == ref_ack && win == f->last_win_sent)) {
                    f->recov_until_us = now + RECOV_COOLDOWN_US;
                    in_recov = 1;
                }

                eligible = 0;
                if (pure_ack && win > 0 && f->last_ul_seq == seq && adv) {
                    if (in_recov) {
                        g.stat_thin_bypass_recov++;
                    } else if (clamp_open) {
                        g.stat_thin_bypass_win++;
                    } else if (g.thin_backoff_ticks || flow_bo ||
                               f->dl_bytes_total < ACK_ADAPT_SS_BYTES ||
                               f->dl_rate_kbps < g.ack_min_kbps ||
                               g.rate100_kbps < ACK_ADAPT_MIN_TOT ||
                               f->recent_acks_10ms < 2u) {
                        g.stat_thin_bypass_rate++;
                    } else {
                        eligible = 1;
                    }
                }
            }

            if (!eligible) {
                /* Preserve strict ordering: flush any held ACK before this event pkt */
                if (f->held_ack)
                    flush_flow_ack(f, &g.stat_acks_flushed_event);
                f->last_ack_sent = ack;
                f->last_ul_seq = seq;
                f->last_win_sent = win;
                return NF_ACCEPT;
            }

            /* Eligible advancing pure cumulative ACK! */
            {
                u32 span_lim = g.max_ack_span;
                u32 hold_lim = g.hold_us;

                if (g.ack_adapt) {
                    /* Per-flow segment budget K (bounded <= 1/4 of flow share,
                     * >= 4 MSS, <= 32 KB) and time budget N ms (scales gently up
                     * to 10 ms when >= 8 concurrent bulk flows share the UL ring). */
                    u32 mss = f->mss ? (u32)f->mss : DEFAULT_MSS;
                    u32 k_bytes = g.ack_segs * mss;
                    u32 eff_ms = g.ack_ms;
                    if (g.n_ctl >= 8u && eff_ms < 10u) {
                        eff_ms += (g.n_ctl >> 2);
                        if (eff_ms > 10u) eff_ms = 10u;
                    }
                    if (g.ctl_active && g.w_bytes) {
                        u32 sh = compute_flow_rwnd_target(f);
                        if (sh != NO_CLAMP && (sh >> 2) < k_bytes)
                            k_bytes = sh >> 2;
                    }
                    if (k_bytes < mss * 4u) k_bytes = mss * 4u;
                    if (k_bytes > 32768u)   k_bytes = 32768u;
                    span_lim = k_bytes;
                    hold_lim = ms_to_units(eff_ms);
                    if (hold_lim < 500u)  hold_lim = 500u;
                    if (hold_lim > 9766u) hold_lim = 9766u;
                }

                if (f->held_ack) {
                    /* Supersede & free older held ACK (0% tail-ACK loss risk!) */
                    consume_skb(f->held_ack);
                    f->held_ack = NULL;
                    f->held_okfn = NULL;
                    if (g.held_count) g.held_count--;
                    g.stat_acks_thinned++;
                    if (g.ack_adapt)
                        f->thin_active_flow = 1;

                    /* Bound sender burstiness: flush immediately once span >= span_lim */
                    if ((u32)(ack - f->last_ack_sent) >= span_lim) {
                        f->last_ack_sent = ack;
                        f->last_win_sent = win;
                        g.stat_acks_flushed_span++;
                        return NF_ACCEPT;
                    }
                    f->held_ack = skb;
                    f->held_okfn = okfn;
                    f->held_ack_seq = ack;
                    f->last_win_sent = win;
                    g.held_count++;
                    if (!g.timer_pending) {
                        u32 rem = f->held_deadline_us - now;
                        if ((s32)rem <= 0 || rem > HOLD_ANOMALY_US) rem = 250u;
                        flush_timer_arm(rem);
                    }
                    return NF_STOLEN;
                } else {
                    u32 deadline = now + hold_lim;
                    u32 arm_us = hold_lim;
                    if (g.ack_adapt && hold_lim >= 2048u) {
                        /* Stagger flow deadlines evenly across the hold window
                         * (4 phases: 0, 1/4, 2/4, 3/4 of period) while keeping
                         * every hold in [hold_lim/2 .. hold_lim] so flows flush
                         * evenly without premature 1 ms flushes or clumping. */
                        u32 grid = (hold_lim >= 4880u) ? 4096u : 2048u;
                        u32 phase = ((u32)(f - g.flows) & 3u) * (grid >> 2);
                        u32 min_t = now + (hold_lim >> 1);
                        u32 next_t = (min_t & ~(grid - 1u)) + phase;
                        if ((s32)(next_t - min_t) < 0)
                            next_t += grid;
                        if ((s32)(next_t - (now + hold_lim)) <= 0) {
                            deadline = next_t;
                            arm_us = deadline - now;
                        }
                    }
                    f->held_ack = skb;
                    f->held_okfn = okfn;
                    f->held_ack_seq = ack;
                    f->held_deadline_us = deadline;
                    f->last_win_sent = win;
                    g.held_count++;
                    if (!g.timer_pending)
                        flush_timer_arm(arm_us < 250u ? 250u : arm_us);
                    return NF_STOLEN;
                }
            }
        }
    }
}

/*
 * Y6: context guard. Today both bridge ports deliver through netif_rx
 * (gdmlte imports netif_rx; gdm_eth_probe stores netif_rx as its rx
 * function), so this hook always runs in NET_RX softirq. But the vendor
 * netif_rx (0x80259c28) can divert packets to vendor queues (netif_enqueue,
 * lcq_enqueue, ipv6q_enqueue, nat_q_enqueue) and there is a vendor kthread
 * (netif_q_thread 0x8026fd54). If a packet ever reaches the bridge from
 * process context with BH enabled, the original hook would race the flush
 * tasklet on held_ack (double free). Now: in softirq/BH-off -> run directly;
 * process context -> run under local_bh_disable(); hard-IRQ or IRQs-off ->
 * pass the packet untouched.
 */
static unsigned int qctrl_bridge_hook(unsigned int hooknum,
                                      struct sk_buff *skb,
                                      const struct net_device *in,
                                      const struct net_device *out,
                                      int (*okfn)(struct sk_buff *))
{
    u32 pc = titan_preempt_count();
    unsigned int v;

    (void)hooknum;
    if (likely((pc & TITAN_SOFTIRQ_MASK) && !(pc & TITAN_HARDIRQ_MASK)))
        return qctrl_hook_body(skb, in, out, okfn);
    if ((pc & TITAN_HARDIRQ_MASK) || titan_irqs_disabled()) {
        g.stat_ctx_skipped++;
        return NF_ACCEPT;
    }
    local_bh_disable();
    v = qctrl_hook_body(skb, in, out, okfn);
    local_bh_enable();
    return v;
}

/*
 * Y6: netdevice notifier. A held ACK keeps an skb whose skb->dev (offset
 * 0x14) is the bridge OUT port (lte0pdn2) with no device reference. If that
 * device were unregistered (or br0 torn down) while an ACK was held, the
 * later okfn() -> dev_queue_xmit() would touch freed memory. On GOING_DOWN,
 * DOWN, UNREGISTER or CHANGENAME of that device (or of any "br*" master) the
 * held ACKs are dropped (they are pure cumulative ACKs; the next ACK covers
 * them). Runs in process context under RTNL, so BH is disabled around it.
 */
static int qctrl_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
    struct net_device *dev = (struct net_device *)ptr;
    int all;
    u32 i;

    (void)nb;
    if (event != NETDEV_GOING_DOWN && event != NETDEV_DOWN &&
        event != NETDEV_UNREGISTER && event != NETDEV_CHANGENAME)
        return NOTIFY_DONE;
    if (!dev)
        return NOTIFY_DONE;
    all = (dev->name[0] == 'b' && dev->name[1] == 'r');

    local_bh_disable();
    for (i = 0; i < FLOW_SLOTS; i++) {
        struct flow_entry *f = &g.flows[i];
        struct sk_buff *skb = f->held_ack;
        if (!skb)
            continue;
        if (all || skb->dev == dev) {
            f->held_ack = NULL;
            f->held_okfn = NULL;
            if (g.held_count) g.held_count--;
            g.stat_acks_dropped_netdev++;
            consume_skb(skb);
        }
    }
    local_bh_enable();
    return NOTIFY_DONE;
}

/* ---------- /proc/titan_qctrl telemetry & live tuning ---------- */
static int qctrl_proc_show(struct seq_file *m, void *v)
{
    (void)v;
    seq_printf(m,
        "titan_qctrl v0.4 (NF_BR_FORWARD prio=+100)\n"
        "mode=0x%x (ack_thin=%u rwnd_clamp=%u dl_ecn=%u udp_drop=%u ul_clamp=%u)\n"
        "params: target_q_ms=%u hold_us=%u max_ack_span=%u phy_cap_kbps=%u\n"
        "        qsrc=%u slack_ms=%u floor_pct=%u drain=%u probe=%u trough_ms=%u rtt_target_ms=%u ecn_ms=%u wfix_kb=%u rttlaw=%u\n"
        "        ack_adapt=%u ctrl_v3=%u ack_ms=%u ack_segs=%u ack_min_kbps=%u\n"
        "state:  c_hat_kbps=%u rate100_kbps=%u free_kbps=%u dl_kbps=%u ul_kbps=%u udp_dl_kbps=%u\n"
        "        ctl_active=%u w_kb=%u n_ctl=%u active_bulk=%u inflight_kb=%u release_ticks=%u\n"
        "        dq_est_ms=%u q_src=%u q_owd_ms=%d q_rtt_ms=%d q_bias_ms=%u owd_flows=%u sat_ticks=%u trough100_ms=%d busy_ticks=%u\n"
        "        rtt_base_ms=%u rtt_cycle_ms=%u p_ecn_pct=%u held_acks=%u timer_pending=%u thin_bo_ticks=%u\n"
        "stats:  dl_pkts=%u ul_pkts=%u rtt_samples=%u owd_ok=%u owd_bad=%u\n"
        "        active_ticks=%u q_ms_sum=%u seeds=%u sat_updates=%u drains=%u\n"
        "        probe_win=%u probe_fail=%u failsafe=%u\n"
        "        acks_seen=%u acks_thinned=%u flush_timer=%u flush_span=%u flush_ev=%u\n"
        "        flush_wd=%u dropped_netdev=%u ctx_skipped=%u\n"
        "        thin_backoff=%u bypass_recov=%u bypass_rate=%u bypass_win=%u\n"
        "        rwnd_clamped=%u ecn_marked=%u udp_dropped=%u\n",
        g.mode,
        !!(g.mode & MODE_ACK_THIN), !!(g.mode & MODE_RWND_CLAMP),
        !!(g.mode & MODE_DL_ECN),   !!(g.mode & MODE_UDP_DROP),
        !!(g.mode & MODE_UL_CLAMP),
        g.target_q_ms, g.hold_us, g.max_ack_span, g.phy_cap_kbps,
        g.q_force, g.rtt_slack_ms, g.floor_pct, g.drain_enable, g.probe_enable,
        g.trough_ms, g.rtt_target_ms, g.ecn_ms, g.w_fix_bytes >> 10, g.rtt_law,
        g.ack_adapt, g.ctrl_v3, g.ack_ms, g.ack_segs, g.ack_min_kbps,
        g.c_hat_kbps, g.rate100_kbps, g.free_kbps,
        g.last_dl_kbps, g.last_ul_kbps, g.last_udp_dl_kbps,
        g.ctl_active, g.w_bytes >> 10, g.n_ctl, g.active_bulk_flows,
        g.inflight_est >> 10, g.release_left,
        g.dq_est_ms, g.q_src,
        g.q_owd_u == NONE32 ? -1 : (int)units_to_ms(g.q_owd_u),
        g.q_rtt_u == NONE32 ? -1 : (int)units_to_ms(g.q_rtt_u),
        units_to_ms(g.q_bias_u), g.owd_flows, g.sat_ticks,
        g.win_trough_u == NONE32 ? -1 : (int)units_to_ms(g.win_trough_u), g.busy_ticks,
        g.rtt_base_global_ms, g.rtt_cycle_ms,
        (g.p_ecn_q10 * 100u) >> 10, g.held_count, g.timer_pending, g.thin_backoff_ticks,
        g.stat_dl_pkts, g.stat_ul_pkts, g.stat_rtt_samples, g.stat_owd_ok, g.stat_owd_bad,
        g.stat_active_ticks, g.stat_q_ms_sum, g.stat_seeds, g.stat_sat_updates, g.stat_drains,
        g.stat_probe_win, g.stat_probe_fail, g.stat_failsafe,
        g.stat_acks_seen, g.stat_acks_thinned, g.stat_acks_flushed_timer,
        g.stat_acks_flushed_span, g.stat_acks_flushed_event,
        g.stat_acks_flushed_wd, g.stat_acks_dropped_netdev, g.stat_ctx_skipped,
        g.stat_thin_backoff, g.stat_thin_bypass_recov, g.stat_thin_bypass_rate, g.stat_thin_bypass_win,
        g.stat_rwnd_clamped, g.stat_ecn_marked, g.stat_udp_dropped);
    /* Q2: upload clamp. bw is bytes per 1024 units (1.048576 ms): x 7.63 = kbps. */
    seq_printf(m,
        "upload: ul_target_ms=%u ul_full=%u ul_dlq_ms=%u\n"
        "        ul_bw_kbps=%u ul_rtt_ms=%u ul_flows=%u ul_w_kb=%u\n"
        "        ul_acks=%u ul_clamped=%u ul_samples=%u ul_probes=%u ul_startups=%u\n",
        g.ul.target_ms, g.ul.full, g.ul.dl_queue_ms,
        (g.ul.bw * 1000u) / 131u, units_to_ms(g.ul.rtt_base), g.ul.n_active, g.ul.w_total >> 10,
        g.ul.st_acks, g.ul.st_clamped, g.ul.st_samples, g.ul.st_probes, g.ul.st_startups);
    return 0;
}

static int qctrl_proc_open(struct inode *inode, struct file *file)
{
    (void)inode;
    return single_open(file, qctrl_proc_show, NULL);
}

/* Y6: strict decimal parser: rejects overflow and trailing garbage ("0x3"). */
static int parse_u32(const char *s, u32 *val)
{
    u32 v = 0;
    int any = 0;
    while (*s == ' ' || *s == '\t' || *s == '=') s++;
    while (*s >= '0' && *s <= '9') {
        u32 d = (u32)(*s - '0');
        if (v > 429496729u || (v == 429496729u && d > 5u))
            return 0;                       /* would overflow u32 */
        v = v * 10u + d;
        s++;
        any = 1;
    }
    if (!any) return 0;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    if (*s != '\0') return 0;
    *val = v;
    return 1;
}

static int starts_with(const char *s, const char *pfx)
{
    while (*pfx) {
        if (*s++ != *pfx++) return 0;
    }
    return 1;
}

static ssize_t qctrl_proc_write(struct file *file, const char *ubuf,
                                size_t len, loff_t *ppos)
{
    char kbuf[64];
    u32 n = len < 63 ? (u32)len : 63u;
    u32 val;

    (void)file; (void)ppos;
    if (titan_copy_from_user(kbuf, ubuf, n) != 0)
        return -14; /* -EFAULT */
    kbuf[n] = '\0';

    local_bh_disable();
    if (starts_with(kbuf, "ul_target_ms") && parse_u32(kbuf + 12, &val)) {
        if (val <= ULC_TARGET_MAX_MS) g.ul.target_ms = val;           /* Q2 */
    } else if (starts_with(kbuf, "mode") && parse_u32(kbuf + 4, &val)) {
        if (val <= MODE_ALL) {              /* Y6: reject, do not mask, >15 */
            g.mode = val;
            /* Flush held ACKs immediately if ACK thinning turned off */
            if (!(g.mode & MODE_ACK_THIN)) {
                u32 i;
                for (i = 0; i < FLOW_SLOTS; i++)
                    flush_flow_ack(&g.flows[i], &g.stat_acks_flushed_event);
                g.held_count = 0;
            }
        }
    } else if (starts_with(kbuf, "target_ms") && parse_u32(kbuf + 9, &val)) {
        if (val >= 4u && val <= 80u) g.target_q_ms = val;
    } else if (starts_with(kbuf, "target") && parse_u32(kbuf + 6, &val)) {
        /* O1b: alias. "target 8" (as written in O1 section 8) was silently
         * ignored by Y6, which only knew "target_ms". */
        if (val >= 4u && val <= 80u) g.target_q_ms = val;
    } else if (starts_with(kbuf, "qsrc") && parse_u32(kbuf + 4, &val)) {
        if (val <= 2u) g.q_force = val;               /* O1b: 0 auto, 1 OWD, 2 RTT */
    } else if (starts_with(kbuf, "slack_ms") && parse_u32(kbuf + 8, &val)) {
        if (val <= 40u) g.rtt_slack_ms = val;         /* O1b: RTT fallback noise allowance */
    } else if (starts_with(kbuf, "floor_pct") && parse_u32(kbuf + 9, &val)) {
        if (val <= 90u) g.floor_pct = val;            /* O1b: W floor, % of free rate */
    } else if (starts_with(kbuf, "wfix_kb") && parse_u32(kbuf + 7, &val)) {
        if (val <= 32768u) g.w_fix_bytes = val << 10;  /* O1b: 0 = controller */
    } else if (starts_with(kbuf, "ecn_ms") && parse_u32(kbuf + 6, &val)) {
        if (val >= 4u && val <= 80u) g.ecn_ms = val;          /* O1b */
    } else if (starts_with(kbuf, "rtt_target_ms") && parse_u32(kbuf + 13, &val)) {
        if (val >= 4u && val <= 80u) g.rtt_target_ms = val;   /* O1b */
    } else if (starts_with(kbuf, "rttlaw") && parse_u32(kbuf + 6, &val)) {
        if (val <= 1u) g.rtt_law = val;               /* O1b: 0 trough law, 1 mean law */
    } else if (starts_with(kbuf, "trough_ms") && parse_u32(kbuf + 9, &val)) {
        if (val <= 40u) g.trough_ms = val;            /* O1b: standing-queue target */
    } else if (starts_with(kbuf, "drain") && parse_u32(kbuf + 5, &val)) {
        if (val <= 1u) g.drain_enable = val;          /* O1b */
    } else if (starts_with(kbuf, "probe") && parse_u32(kbuf + 5, &val)) {
        if (val <= 1u) {                              /* O1b */
            g.probe_enable = val;
            if (!val) g.probe_state = 0;
        }
    } else if (starts_with(kbuf, "hold_us") && parse_u32(kbuf + 7, &val)) {
        if (val >= 500u && val <= 8000u) {
            g.hold_us = val;
            /* Y6: re-evaluate existing deadlines promptly after a change */
            if (g.held_count)
                flush_timer_arm(250u);
        }
    } else if (starts_with(kbuf, "ack_adapt") && parse_u32(kbuf + 9, &val)) {
        if (val <= 1u) {                              /* Q3: 0 v0.2-o1b, 1 adaptive safe */
            g.ack_adapt = val;
            g.thin_backoff_ticks = 0;
            g.thin_armed = 0;
            g.thin_drop_ticks = 0;
            g.thin_strikes = 0;
            if (g.held_count)
                flush_timer_arm(250u);
        }
    } else if (starts_with(kbuf, "ctrl_v3") && parse_u32(kbuf + 7, &val)) {
        if (val <= 1u) g.ctrl_v3 = val;               /* Q3: 0 v0.2-o1b, 1 low-burst v0.3 */
    } else if (starts_with(kbuf, "ack_ms") && parse_u32(kbuf + 6, &val)) {
        if (val >= 1u && val <= 10u) {                /* Q3: per-flow time budget (ms) */
            g.ack_ms = val;
            if (g.held_count)
                flush_timer_arm(250u);
        }
    } else if (starts_with(kbuf, "ack_segs") && parse_u32(kbuf + 8, &val)) {
        if (val >= 2u && val <= 32u) g.ack_segs = val;/* Q3: per-flow seg budget */
    } else if (starts_with(kbuf, "ack_min_kbps") && parse_u32(kbuf + 12, &val)) {
        if (val <= 100000u) g.ack_min_kbps = val;     /* Q3: per-flow rate floor */
    } else if (starts_with(kbuf, "ack_span") && parse_u32(kbuf + 8, &val)) {
        if (val >= 2696u && val <= 32768u) g.max_ack_span = val;
    } else if (starts_with(kbuf, "phy") && parse_u32(kbuf + 3, &val)) {
        /* Y6: bound the PHY ceiling; "phy 1" used to pin c_hat at 1 kbps
         * and clamp every flow to the 4-MSS floor. */
        if (val == 0u || (val >= 4000u && val <= 1000000u)) {
            u32 old = g.phy_cap_kbps;
            g.phy_cap_kbps = val;
            if (old > 0 && val > 0) {
                u32 diff = (val > old) ? (val - old) : (old - val);
                if (diff > old / 5u) { /* >20% PHY step: scale c_hat and W (O1b) */
                    /* ratio in Q12; val, old <= 1e6 so (val>>6)<<12 < 2^26 */
                    u32 r_q12 = ((val >> 6) << 12) / ((old >> 6) + 1u);
                    u64 c = ((u64)g.c_hat_kbps * r_q12) >> 12;
                    u64 w = ((u64)g.w_bytes * r_q12) >> 12;
                    g.c_hat_kbps = (c > 1000000u) ? 1000000u : (u32)c;
                    if (g.c_hat_kbps < 4000u) g.c_hat_kbps = 4000u;
                    if (g.c_hat_kbps > val)   g.c_hat_kbps = val;
                    g.w_bytes = (w > W_CEIL_BYTES) ? W_CEIL_BYTES : (u32)w;
                }
            }
        }
    } else if (starts_with(kbuf, "reset")) {
        g.stat_dl_pkts = g.stat_ul_pkts = g.stat_acks_seen = 0;
        g.stat_acks_thinned = g.stat_acks_flushed_timer = 0;
        g.stat_acks_flushed_span = g.stat_acks_flushed_event = 0;
        g.stat_acks_flushed_wd = g.stat_acks_dropped_netdev = g.stat_ctx_skipped = 0;
        g.stat_rwnd_clamped = g.stat_ecn_marked = g.stat_udp_dropped = 0;
        g.stat_rtt_samples = 0;
        /* O1b: controller soft reset (re-seed on the next tick) */
        g.stat_owd_ok = g.stat_owd_bad = g.stat_sat_updates = 0;
        g.stat_probe_win = g.stat_probe_fail = g.stat_drains = 0;
        g.stat_failsafe = g.stat_seeds = 0;
        g.stat_active_ticks = g.stat_q_ms_sum = 0;
        g.stat_thin_backoff = g.stat_thin_bypass_recov = 0;
        g.stat_thin_bypass_rate = g.stat_thin_bypass_win = 0;
        g.thin_backoff_ticks = g.thin_armed = g.thin_drop_ticks = 0;
        g.thin_strikes = g.thin_ref_kbps = g.pre_thin_kbps = 0;
        g.thinned_last = 0;
        g.ul.st_acks = g.ul.st_clamped = g.ul.st_samples = g.ul.st_probes = g.ul.st_startups = 0;  /* Q2 */
        g.ctl_active = 0;
        g.release_left = 0;
        g.starve_ticks = 0;
        g.probe_state = 0;
        g.drain_left = g.drain_settle = 0;
        g.q_bias_u = 0;
    }
    local_bh_enable();
    return (ssize_t)len;
}

static const struct file_operations qctrl_proc_fops = {
    .owner   = &__this_module,
    .llseek  = seq_lseek,
    .read    = seq_read,
    .write   = qctrl_proc_write,
    .open    = qctrl_proc_open,
    .release = single_release,
};

/* ---------- Module init & cleanup ---------- */
int init_module(void)
{
    int ret;

    g.mode = 0;                  /* SAFE OBSERVE-ONLY by default! */
    g.unloading = 0;
    g.target_q_ms = 40u;         /* O1b: now the CAP on the mean queue (latency bound) */
    g.hold_us = 2500u;           /* < 5 ms TDD Config 2 UL subframe period */
    g.max_ack_span = 8192u;      /* ~6 MSS max burst per coalesced ACK */
    g.c_hat_kbps = 65000u;       /* 65 Mbps initial prior */
    g.rtt_base_global_ms = 0u;   /* O1b: telemetry only */
    g.q_owd_u = NONE32;
    g.q_rtt_u = NONE32;
    g.rtt_slack_ms = 10u;        /* O1b defaults (all tunable via /proc) */
    g.floor_pct = 30u;
    g.drain_enable = 1u;
    g.probe_enable = 1u;
    g.trough_ms = 4u;            /* O1b: keep >= 4 ms of standing queue (link never idles) */
    g.rtt_target_ms = 15u;       /* O1b: mean queue target when only the RTT signal exists */
    g.ecn_ms = 20u;              /* O1b: ECN / UDP-drop ramp starts here */
    g.q_trough_u = NONE32;
    g.last_trough_u = NONE32;
    g.win_trough_u = NONE32;
    g.win_trough3_u = NONE32;
    g.ack_adapt = 0u;            /* Q3: off by default -> exact v0.2-o1b behavior */
    g.ctrl_v3 = 0u;              /* Q3: off by default -> exact v0.2-o1b behavior */
    g.ack_ms = 6u;               /* Q3: default 6 ms per-flow ACK budget */
    g.ack_segs = 18u;            /* Q3: default 18 segs per-flow ACK budget */
    g.ack_min_kbps = 2000u;      /* Q3: default 2 Mbps per-flow floor */
    {
        u32 k;
        for (k = 0; k < RATE_RING; k++) g.tr_ring[k] = NONE32;
    }
    g.timer_pending = 0;
    g.last_tick_us = now_us();
    ulc_init(&g.ul, g.last_tick_us);   /* Q2: knobs at their defaults, nothing learned */

    tasklet_hrtimer_init(&g_flush_timer, flush_timer_cb,
                         CLOCK_MONOTONIC, HRTIMER_MODE_REL);

    g_proc_ent = proc_create_data("titan_qctrl", 0644, NULL, &qctrl_proc_fops, NULL);
    if (!g_proc_ent) {
        printk("titan_qctrl: failed to create /proc/titan_qctrl\n");
        return -12; /* -ENOMEM */
    }

    /* Y6: notifier first, so no ACK can ever be held without it */
    g_netdev_nb.notifier_call = qctrl_netdev_event;
    g_netdev_nb.priority = 0;
    ret = register_netdevice_notifier(&g_netdev_nb);
    if (ret != 0) {
        remove_proc_entry("titan_qctrl", NULL);
        printk("titan_qctrl: register_netdevice_notifier failed (%d)\n", ret);
        return ret;
    }

    g_nf_ops.hook     = qctrl_bridge_hook;
    g_nf_ops.owner    = &__this_module;
    g_nf_ops.pf       = NFPROTO_BRIDGE;
    g_nf_ops.hooknum  = NF_BR_FORWARD;
    g_nf_ops.priority = 100;     /* AFTER ebtables filter (-200) and br_netfilter (-1/0) */

    ret = nf_register_hook(&g_nf_ops);
    if (ret != 0) {
        unregister_netdevice_notifier(&g_netdev_nb);
        remove_proc_entry("titan_qctrl", NULL);
        printk("titan_qctrl: nf_register_hook failed (%d)\n", ret);
        return ret;
    }

    printk("titan_qctrl: loaded (v0.4) in observe-only mode (mode=0); control via /proc/titan_qctrl\n");
    return 0;
}

void cleanup_module(void)
{
    u32 i;
    g.unloading = 1;
    nf_unregister_hook(&g_nf_ops);
    synchronize_net();
    hrtimer_cancel(&g_flush_timer.timer);
    tasklet_kill(&g_flush_timer.tasklet);

    /* Y6: FORWARD the held ACKs instead of dropping them (a dropped tail ACK
     * can cost the sender an RTO). The hook is gone, so nothing new is held;
     * the netdev notifier is still registered, so no held skb can point at a
     * dead device here. */
    local_bh_disable();
    for (i = 0; i < FLOW_SLOTS; i++)
        flush_flow_ack(&g.flows[i], &g.stat_acks_flushed_event);
    g.held_count = 0;
    local_bh_enable();

    unregister_netdevice_notifier(&g_netdev_nb);
    remove_proc_entry("titan_qctrl", NULL);
    printk("titan_qctrl: unloaded cleanly\n");
}
