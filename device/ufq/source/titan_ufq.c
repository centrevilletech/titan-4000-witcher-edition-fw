/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright 2026 Centreville Tech, LLC. Kernel module for Titan 4000 Witcher Edition; see device/ufq/README.md. */
/*
 * titan_ufq.c - Host uplink flow queue with modem backpressure ("BQL for the
 * modem") for the Global Telecom Titan 4000 (GDM7243AP, Linux 3.10.0-uc0 UP).
 *
 * Sits on NFPROTO_BRIDGE / NF_BR_FORWARD at priority +150 (after titan_qctrl
 * at +100) on customer uplink frames (eth0 -> lte0pdn*).
 *
 * Design:
 *   - Default mode=0 at insmod: strict pass-through (zero packet delay/drops),
 *     live telemetry readable via /proc/titan_ufq.
 *   - Mode 1 (FQ + BQL + bulk CoDel drop) / Mode 3 (+ ECN-CE on bulk ECT):
 *     per-flow DRR with RFC 8290 sparse-flow fast-pass (new_flows preempts
 *     old_flows; zero DSCP marking required) and per-flow RFC 8289 CoDel on
 *     bulk flows only.
 *   - Backpressure: reads modem RLC/PDCP bearer occupancy (0x84dd59d8, 8 slots),
 *     MAC UL BO (0x84d62c70), modem 1 ms clock (0x84a1f860), and N4 state
 *     (0x847ed600) read-only via __arm_ioremap, fused with SCU-coherent Linux
 *     gipc ch1 outstanding count (&gipc + 0x8c) and local decay so CPU1
 *     non-coherent L1 D-cache staleness can never stall forwarding.
 *   - Never maps or touches AFC MMIO (0x14110000) or 1 Hz stats (0x84af11e0).
 *   - Hard fail-safe: if queued packets make no forward progress for
 *     failsafe_ms (default 250 ms) or an internal invariant fails, flushes
 *     all packets and switches to mode=0 pass-through.
 */
#include "titan_k310_abi.h"
#include "ufq_core.h"

/* ---------- ELF .modinfo & struct module (exact Linux 3.10.0-uc0 layout) ---------- */
int init_module(void);
void cleanup_module(void);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"), aligned(4))) = {
    .name = "titan_ufq",
    .init = init_module,
    .exit = cleanup_module,
};

static const char __modinfo_vermagic[] __attribute__((section(".modinfo"), used)) =
    "vermagic=3.10.0-uc0 mod_unload ARMv7 ";
static const char __modinfo_license[] __attribute__((section(".modinfo"), used)) =
    "license=GPL";
static const char __modinfo_desc[] __attribute__((section(".modinfo"), used)) =
    "description=Titan 4000 Uplink Flow Queue with Modem Backpressure (v0.1)";
static const char __modinfo_author[] __attribute__((section(".modinfo"), used)) =
    "author=Centreville Tech LLC";
static const char __modinfo_depends[] __attribute__((section(".modinfo"), used)) =
    "depends=";

/* ---------- Read-only modem RAM addresses (proven in tk.bin V1.6.0.P0) ---------- */
#define MODEM_N4_PAGE      0x847ed000UL
#define MODEM_N4_OFF       0x600u        /* 0x847ed600: N4/N3R state block */
#define MODEM_N4_MAGIC_N4  0x4e345632u   /* "N4V2" */
#define MODEM_N4_MAGIC_N3R 0x4e335231u   /* "N3R1" */
#define MODEM_N4_G_EMA     0x2cu
#define MODEM_N4_Q_TRUE    0x54u

#define MODEM_KNL_PAGE     0x84a1f000UL
#define MODEM_KNL_OFF      0x860u        /* 0x84a1f860: 1 ms TTI clock */

#define MODEM_MAC_PAGE     0x84d62000UL
#define MODEM_MAC_BO_OFF   0xc70u        /* 0x84d62c70: MAC UL BO */

#define MODEM_RBC_PAGE     0x84dd5000UL
#define MODEM_RBC_SIZE     0x3000u       /* covers 0x84dd59d8 .. 0x84dd6c18 */
#define MODEM_RBC_OFF      0x9d8u        /* 0x84dd59d8: rbc[0] */
#define MODEM_RBC_STRIDE   0x248u
#define MODEM_RBC_SLOTS    8u
#define MODEM_RBC_ACTIVE   0x11u         /* u8: 1 = active */
#define MODEM_RBC_MODE     0x15u         /* u8: 3 = AM DRB */
#define MODEM_RBC_RLC_BO   0x10cu        /* u32: RLC TX BO */
#define MODEM_RBC_RING_BO  0x130u        /* u32: Ring0+Ring1+cipher pending */
#define MODEM_BO_SANITY    0x400000u     /* 4 MB sanity cap */

/* Linux-side SCU-coherent gipc channel 1 (IPC_CH_LTE_SDU) outstanding IRBs */
#define GIPC_CH1_OUT_OFF   0x8cu         /* &gipc + 0x0c + 1*0x68 + 0x18 */

/* Release timer cadence (1 ms, matching HZ=1000 without hrtimers) */
#define UFQ_TIMER_NS       1000000LL

/* ---------- Global module state ---------- */
static struct ufq_state       g_ufq;
static struct nf_hook_ops     g_nf_ops;
static struct notifier_block  g_netdev_nb;
static struct tasklet_hrtimer g_drain_timer;
static struct proc_dir_entry *g_proc_ent;

static volatile u8 *g_va_n4;
static volatile u8 *g_va_knl;
static volatile u8 *g_va_mac;
static volatile u8 *g_va_rbc;

static u32 g_unloading;
static u32 g_timer_pending;
static u32 g_in_drain;
static u32 g_stat_ul_seen;
static u32 g_stat_nonip_pass;
static u32 g_stat_ctx_skipped;
static u32 g_stat_timer_fires;

/* ---------- Helpers ---------- */
static inline u32 now_us(void)
{
    ktime_t kt = ktime_get();
    /* >> 10 gives 1.024 us units (avoid 64-bit division in softirq) */
    return (u32)((u64)kt.tv64 >> 10);
}

static inline int is_dev_eth0(const struct net_device *d)
{
    return d && d->name[0] == 'e' && d->name[1] == 't' &&
           d->name[2] == 'h' && d->name[3] == '0';
}

static inline int is_dev_lte(const struct net_device *d)
{
    return d && d->name[0] == 'l' && d->name[1] == 't' &&
           d->name[2] == 'e' && d->name[3] == '0' &&
           d->name[4] == 'p' && d->name[5] == 'd' && d->name[6] == 'n';
}

static inline u32 rd32(const volatile u8 *base, u32 off)
{
    return *(const volatile u32 *)(base + off);
}

static inline u8 rd8(const volatile u8 *base, u32 off)
{
    return *(const volatile u8 *)(base + off);
}

/* Incremental IPv4 header checksum update for 16-bit word replacement */
static inline void csum_replace2_ip4(u8 *iph, __be16 old_w, __be16 new_w)
{
    u32 sum = ((u32)iph[10] << 8) | iph[11];
    u32 o = ntohs(old_w);
    u32 n = ntohs(new_w);
    sum = (~sum & 0xffffu) + (~o & 0xffffu) + n;
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    sum = ~sum & 0xffffu;
    iph[10] = (u8)(sum >> 8);
    iph[11] = (u8)(sum & 0xffu);
}

/* ---------- Read-only modem + GIPC sampler ---------- */
static void sample_modem(struct ufq_modem_sample *s)
{
    u32 i;

    s->rbc_ring_bytes = 0;
    s->rbc_rlc_bytes  = 0;
    s->mac_ul_bo      = 0;
    s->knl_ms         = 0;
    s->n4_g_ema       = 0;
    s->n4_q_true      = 0;
    s->active_drbs    = 0;
    s->n4_present     = 0;
    s->ram_valid      = 0;

    /* 1. SCU-coherent Linux gipc ch1 outstanding IRB count */
    s->gipc_ch1_out = *(const volatile u16 *)(gipc + GIPC_CH1_OUT_OFF);

    if ((g_ufq.mode & UFQ_MODE_NO_RAM) || !g_va_rbc || !g_va_mac || !g_va_knl)
        return;

    titan_dmb();
    s->ram_valid = 1u;
    s->knl_ms    = rd32(g_va_knl, MODEM_KNL_OFF);
    s->mac_ul_bo = rd32(g_va_mac, MODEM_MAC_BO_OFF);
    if (s->mac_ul_bo > MODEM_BO_SANITY)
        s->mac_ul_bo = 0;

    if (g_va_n4) {
        u32 magic = rd32(g_va_n4, MODEM_N4_OFF);
        if (magic == MODEM_N4_MAGIC_N4 || magic == MODEM_N4_MAGIC_N3R) {
            s->n4_present = 1u;
            s->n4_g_ema   = rd32(g_va_n4, MODEM_N4_OFF + MODEM_N4_G_EMA);
            s->n4_q_true  = rd32(g_va_n4, MODEM_N4_OFF + MODEM_N4_Q_TRUE);
        }
    }

    for (i = 0; i < MODEM_RBC_SLOTS; i++) {
        u32 off = MODEM_RBC_OFF + i * MODEM_RBC_STRIDE;
        if (rd8(g_va_rbc, off + MODEM_RBC_ACTIVE) == 1u &&
            rd8(g_va_rbc, off + MODEM_RBC_MODE) == 3u) {
            u32 r_ring = rd32(g_va_rbc, off + MODEM_RBC_RING_BO);
            u32 r_rlc  = rd32(g_va_rbc, off + MODEM_RBC_RLC_BO);
            if (r_ring <= MODEM_BO_SANITY && r_rlc <= MODEM_BO_SANITY) {
                s->rbc_ring_bytes += r_ring;
                s->rbc_rlc_bytes  += r_rlc;
                s->active_drbs++;
            }
        }
    }
}

/* ---------- ufq_core callbacks ---------- */
static void ufq_cb_deliver(void *ctx, void *pkt, void *okfn)
{
    struct sk_buff *skb = (struct sk_buff *)pkt;
    int (*fn)(struct sk_buff *) = (int (*)(struct sk_buff *))okfn;
    (void)ctx;
    if (skb && fn)
        fn(skb);
    else if (skb)
        consume_skb(skb);
}

static void ufq_cb_drop(void *ctx, void *pkt)
{
    struct sk_buff *skb = (struct sk_buff *)pkt;
    (void)ctx;
    if (skb)
        kfree_skb(skb);
}

static int ufq_cb_mark_ecn(void *ctx, void *pkt)
{
    struct sk_buff *skb = (struct sk_buff *)pkt;
    u16 proto;
    u32 l3_len;
    u8 *l3;

    (void)ctx;
    if (!skb)
        return 0;
    proto = ntohs(skb->protocol);
    l3_len = skb->len - skb->data_len;
    if (proto == ETH_P_IP) {
        if (l3_len < 20u)
            return 0;
        if (!skb_make_writable(skb, 12u))
            return 0;
        l3 = skb->data;
        if ((l3[1] & 0x03u) != 1u && (l3[1] & 0x03u) != 2u)
            return 0;
        {
            u16 old16 = ((u16)l3[0] << 8) | l3[1];
            u16 new16;
            l3[1] |= 0x03u;
            new16 = ((u16)l3[0] << 8) | l3[1];
            csum_replace2_ip4(l3, htons(old16), htons(new16));
        }
        return 1;
    } else if (proto == ETH_P_IPV6) {
        if (l3_len < 40u)
            return 0;
        if (!skb_make_writable(skb, 4u))
            return 0;
        l3 = skb->data;
        {
            u8 ecn = (l3[1] >> 4) & 0x03u;
            if (ecn != 1u && ecn != 2u)
                return 0;
            l3[1] |= 0x30u;
        }
        return 1;
    }
    return 0;
}

static const struct ufq_ops g_ufq_ops = {
    .deliver  = ufq_cb_deliver,
    .drop     = ufq_cb_drop,
    .mark_ecn = ufq_cb_mark_ecn,
};

static inline void drain_timer_arm(void)
{
    if (!g_timer_pending && !g_unloading) {
        g_timer_pending = 1u;
        hrtimer_start(&g_drain_timer.timer, ktime_set_ns(UFQ_TIMER_NS), HRTIMER_MODE_REL);
    }
}

/* ---------- 1 ms release tasklet_hrtimer callback ---------- */
static int drain_timer_cb(struct hrtimer *timer)
{
    struct ufq_modem_sample samp;
    u32 now;

    (void)timer;
    g_timer_pending = 0u;
    g_stat_timer_fires++;

    if (unlikely(g_unloading))
        return HRTIMER_NORESTART;

    if (g_in_drain) {
        if (g_ufq.total_pkts > 0)
            drain_timer_arm();
        return HRTIMER_NORESTART;
    }

    g_in_drain = 1u;
    now = now_us();
    sample_modem(&samp);
    ufq_update_modem(&g_ufq, &samp, now);

    if (g_ufq.mode == UFQ_MODE_OFF) {
        if (g_ufq.total_pkts > 0)
            ufq_flush_all(&g_ufq, &g_ufq_ops, NULL, 1);
    } else if (g_ufq.total_pkts > 0) {
        ufq_drain(&g_ufq, now, &g_ufq_ops, NULL);
    }
    g_in_drain = 0u;

    if (g_ufq.total_pkts > 0 && !g_unloading)
        drain_timer_arm();

    return HRTIMER_NORESTART;
}

/* ---------- Packet classification (IPv4/IPv6 5-tuple, zero DSCP needed) ---------- */
static int classify_skb(const struct sk_buff *skb,
                        u16 *out_fid,
                        u8 *out_ecn,
                        u8 *out_never_drop)
{
    u16 proto = ntohs(skb->protocol);
    u32 l3_len = skb->len - skb->data_len;
    const u8 *l3 = skb->data;
    u32 l4_off, ip_tot_len;
    u8 l4_proto;
    u32 saddr, daddr;
    u16 sport = 0, dport = 0;
    u8 ecn = 0, nd = 0;

    if (proto == ETH_P_IP) {
        if (l3_len < 20u || (l3[0] >> 4) != 4u)
            return 0;
        l4_off = (u32)(l3[0] & 0x0fu) * 4u;
        ip_tot_len = ((u32)l3[2] << 8) | l3[3];
        if (l4_off < 20u || ip_tot_len < l4_off || ip_tot_len > skb->len)
            return 0;
        ecn = l3[1] & 0x03u;
        l4_proto = l3[9];
        saddr = ((u32)l3[12] << 24) | ((u32)l3[13] << 16) | ((u32)l3[14] << 8) | l3[15];
        daddr = ((u32)l3[16] << 24) | ((u32)l3[17] << 16) | ((u32)l3[18] << 8) | l3[19];

        /* Fragmented IPv4: hash on 3-tuple only */
        if (((((u16)l3[6] << 8) | l3[7]) & 0x3fffu) == 0 && l3_len >= l4_off + 4u) {
            if (l4_proto == 6u || l4_proto == 17u) {
                sport = ((u16)l3[l4_off] << 8) | l3[l4_off + 1];
                dport = ((u16)l3[l4_off + 2] << 8) | l3[l4_off + 3];
                if (l4_proto == 17u && (sport == 67u || sport == 68u || dport == 67u || dport == 68u))
                    nd = 1u;
            } else if (l4_proto == 1u) {
                /* ICMP: type/code in sport, id in dport if echo */
                sport = ((u16)l3[l4_off] << 8) | l3[l4_off + 1];
                if (l3_len >= l4_off + 6u)
                    dport = ((u16)l3[l4_off + 4] << 8) | l3[l4_off + 5];
                nd = 1u;
            }
        }
    } else if (proto == ETH_P_IPV6) {
        if (l3_len < 40u || (l3[0] >> 4) != 6u)
            return 0;
        l4_off = 40u;
        ip_tot_len = 40u + (((u32)l3[4] << 8) | l3[5]);
        if (ip_tot_len > skb->len)
            return 0;
        ecn = (l3[1] >> 4) & 0x03u;
        l4_proto = l3[6];
        saddr = (((u32)l3[8]  << 24) | ((u32)l3[9]  << 16) | ((u32)l3[10] << 8) | l3[11]) ^
                (((u32)l3[12] << 24) | ((u32)l3[13] << 16) | ((u32)l3[14] << 8) | l3[15]) ^
                (((u32)l3[16] << 24) | ((u32)l3[17] << 16) | ((u32)l3[18] << 8) | l3[19]) ^
                (((u32)l3[20] << 24) | ((u32)l3[21] << 16) | ((u32)l3[22] << 8) | l3[23]);
        daddr = (((u32)l3[24] << 24) | ((u32)l3[25] << 16) | ((u32)l3[26] << 8) | l3[27]) ^
                (((u32)l3[28] << 24) | ((u32)l3[29] << 16) | ((u32)l3[30] << 8) | l3[31]) ^
                (((u32)l3[32] << 24) | ((u32)l3[33] << 16) | ((u32)l3[34] << 8) | l3[35]) ^
                (((u32)l3[36] << 24) | ((u32)l3[37] << 16) | ((u32)l3[38] << 8) | l3[39]);

        if (l3_len >= l4_off + 4u) {
            if (l4_proto == 6u || l4_proto == 17u) {
                sport = ((u16)l3[l4_off] << 8) | l3[l4_off + 1];
                dport = ((u16)l3[l4_off + 2] << 8) | l3[l4_off + 3];
                if (l4_proto == 17u && (sport == 546u || sport == 547u || dport == 546u || dport == 547u))
                    nd = 1u;
            } else if (l4_proto == 58u) {
                /* ICMPv6 (ping + Neighbor Discovery): never drop */
                sport = ((u16)l3[l4_off] << 8) | l3[l4_off + 1];
                if (l3_len >= l4_off + 6u)
                    dport = ((u16)l3[l4_off + 4] << 8) | l3[l4_off + 5];
                nd = 1u;
            }
        }
    } else {
        return 0;
    }

    *out_fid        = (u16)ufq_hash_5tuple(l4_proto, saddr, daddr, sport, dport);
    *out_ecn        = (ecn == 1u || ecn == 2u) ? 1u : 0u;
    *out_never_drop = nd;
    return 1;
}

/* ---------- Main NF_BR_FORWARD hook body ---------- */
static unsigned int ufq_hook_body(struct sk_buff *skb,
                                  const struct net_device *in,
                                  const struct net_device *out,
                                  int (*okfn)(struct sk_buff *))
{
    struct ufq_modem_sample samp;
    u32 now;
    u16 fid;
    u8 ecn_cap, never_drop;

    if (unlikely(g_unloading || !skb || !in || !out || !okfn))
        return NF_ACCEPT;

    if (!is_dev_eth0(in) || !is_dev_lte(out))
        return NF_ACCEPT;

    g_stat_ul_seen++;
    now = now_us();

    /* Keep passive telemetry live even in mode=0 pass-through */
    if (!(g_ufq.mode & UFQ_MODE_ENABLE) || g_ufq.failsafe_tripped || g_in_drain) {
        if ((u32)(now - g_ufq.last_update_us) >= 10000u) {
            sample_modem(&samp);
            ufq_update_modem(&g_ufq, &samp, now);
        }
        g_ufq.stat_passthrough++;
        return NF_ACCEPT;
    }

    /* Non-IP (ARP, etc.) passes straight through immediately */
    if (!classify_skb(skb, &fid, &ecn_cap, &never_drop)) {
        g_stat_nonip_pass++;
        return NF_ACCEPT;
    }

    g_in_drain = 1u;
    sample_modem(&samp);
    ufq_update_modem(&g_ufq, &samp, now);

    if (ufq_check_failsafe(&g_ufq, now, &g_ufq_ops, NULL)) {
        g_in_drain = 0u;
        return NF_ACCEPT;
    }

    /* Fast path: queue empty, modem below BQL limit, and packet fits immediately */
    if (ufq_enqueue(&g_ufq, fid, skb, (void *)okfn, skb->len,
                    ecn_cap, never_drop, now, &g_ufq_ops, NULL) != 0) {
        /* Fail-safe tripped inside enqueue; pass current packet untouched */
        g_in_drain = 0u;
        return NF_ACCEPT;
    }

    ufq_drain(&g_ufq, now, &g_ufq_ops, NULL);
    g_in_drain = 0u;

    if (g_ufq.total_pkts > 0)
        drain_timer_arm();

    return NF_STOLEN;
}

/* Context guard matching titan_qctrl.c (Y6 safety rule) */
static unsigned int ufq_bridge_hook(unsigned int hooknum,
                                    struct sk_buff *skb,
                                    const struct net_device *in,
                                    const struct net_device *out,
                                    int (*okfn)(struct sk_buff *))
{
    u32 pc = titan_preempt_count();
    unsigned int v;

    (void)hooknum;
    if (likely((pc & TITAN_SOFTIRQ_MASK) && !(pc & TITAN_HARDIRQ_MASK)))
        return ufq_hook_body(skb, in, out, okfn);
    if ((pc & TITAN_HARDIRQ_MASK) || titan_irqs_disabled()) {
        g_stat_ctx_skipped++;
        return NF_ACCEPT;
    }
    local_bh_disable();
    v = ufq_hook_body(skb, in, out, okfn);
    local_bh_enable();
    return v;
}

/* Netdevice notifier: drop queued skbs if target lte0pdn* or br* goes down */
static int ufq_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr)
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

    all = (dev->name[0] == 'b' && dev->name[1] == 'r') || is_dev_lte(dev);
    if (!all)
        return NOTIFY_DONE;

    local_bh_disable();
    for (i = 0; i < UFQ_NUM_FLOWS; i++) {
        struct ufq_flow *f = &g_ufq.flows[i];
        while (f->head != UFQ_NIL) {
            u16 sidx = ufq_flow_pop(&g_ufq, (u16)i);
            struct sk_buff *skb = (struct sk_buff *)g_ufq.slots[sidx].pkt;
            ufq_free_slot(&g_ufq, sidx);
            if (skb) {
                consume_skb(skb);
                g_ufq.stat_netdev_drop++;
            }
        }
        if (f->list_id == UFQ_LIST_NEW)
            ufq_list_remove(&g_ufq, &g_ufq.new_flows, (u16)i);
        else if (f->list_id == UFQ_LIST_OLD)
            ufq_list_remove(&g_ufq, &g_ufq.old_flows, (u16)i);
        f->codel_dropping = 0;
        f->codel_first_above_us = 0;
    }
    local_bh_enable();
    return NOTIFY_DONE;
}

/* ---------- /proc/titan_ufq telemetry & live tuning ---------- */
static int ufq_proc_show(struct seq_file *m, void *v)
{
    struct ufq_modem_sample samp;

    (void)v;
    local_bh_disable();
    sample_modem(&samp);
    local_bh_enable();

    seq_printf(m,
        "titan_ufq v0.1 (NF_BR_FORWARD prio=+150)\n"
        "mode=0x%x (enable=%u ecn=%u no_ram=%u failsafe_tripped=%u)\n"
        "params: bql_mult_q4=%u bql_min_kb=%u bql_max_kb=%u sparse_headroom_kb=%u\n"
        "        codel_target_ms=%u codel_interval_ms=%u quantum=%u pace=%u pace_gain_q4=%u\n"
        "        tti_ms=%u tti_hold_us=%u failsafe_ms=%u max_pkts=%u\n"
        "modem:  ram_valid=%u n4_present=%u active_drbs=%u gipc_ch1_out=%u\n"
        "        rbc_ring_b=%u rbc_rlc_b=%u mac_ul_bo=%u knl_ms=%u n4_g_ema=%u n4_q_true=%u\n"
        "state:  q_est_b=%u bql_limit_b=%u g_bytes=%u rate_kbps=%u pace_budget_b=%d\n"
        "        q_pkts=%u q_bytes=%u new_flows=%u old_flows=%u timer_pending=%u\n"
        "stats:  ul_seen=%u passthrough=%u nonip_pass=%u enq_pkts=%u\n"
        "        deq_sparse=%u deq_bulk=%u codel_drop=%u codel_ecn=%u overlimit_drop=%u\n"
        "        ram_fresh=%u ram_stale=%u gipc_zero_snap=%u timer_fires=%u\n"
        "        failsafe=%u netdev_drop=%u ctx_skipped=%u max_q_pkts=%u max_q_bytes=%u\n",
        g_ufq.mode,
        !!(g_ufq.mode & UFQ_MODE_ENABLE),
        !!(g_ufq.mode & UFQ_MODE_ECN),
        !!(g_ufq.mode & UFQ_MODE_NO_RAM),
        g_ufq.failsafe_tripped,
        g_ufq.bql_mult_q4,
        g_ufq.bql_min_bytes >> 10,
        g_ufq.bql_max_bytes >> 10,
        g_ufq.sparse_headroom >> 10,
        g_ufq.codel_target_us / 1000u,
        g_ufq.codel_interval_us / 1000u,
        g_ufq.quantum,
        g_ufq.pace_enable,
        g_ufq.pace_gain_q4,
        g_ufq.tti_ms,
        g_ufq.tti_hold_us,
        g_ufq.failsafe_ms,
        g_ufq.max_pkts,
        samp.ram_valid,
        samp.n4_present,
        samp.active_drbs,
        samp.gipc_ch1_out,
        samp.rbc_ring_bytes,
        samp.rbc_rlc_bytes,
        samp.mac_ul_bo,
        samp.knl_ms,
        samp.n4_g_ema,
        samp.n4_q_true,
        g_ufq.q_est_bytes,
        g_ufq.bql_limit,
        g_ufq.g_bytes,
        g_ufq.rate_bpms * 8u,
        g_ufq.pace_budget,
        g_ufq.total_pkts,
        g_ufq.total_bytes,
        g_ufq.new_flows.count,
        g_ufq.old_flows.count,
        g_timer_pending,
        g_stat_ul_seen,
        g_ufq.stat_passthrough,
        g_stat_nonip_pass,
        g_ufq.stat_enq_pkts,
        g_ufq.stat_deq_sparse,
        g_ufq.stat_deq_bulk,
        g_ufq.stat_codel_drop,
        g_ufq.stat_codel_ecn,
        g_ufq.stat_overlimit_drop,
        g_ufq.stat_ram_fresh,
        g_ufq.stat_ram_stale,
        g_ufq.stat_gipc_zero_snap,
        g_stat_timer_fires,
        g_ufq.stat_failsafe,
        g_ufq.stat_netdev_drop,
        g_stat_ctx_skipped,
        g_ufq.stat_max_q_pkts,
        g_ufq.stat_max_q_bytes);
    return 0;
}

static int ufq_proc_open(struct inode *inode, struct file *file)
{
    (void)inode;
    return single_open(file, ufq_proc_show, NULL);
}

static int parse_u32(const char *s, u32 *val)
{
    u32 v = 0;
    int any = 0;
    while (*s == ' ' || *s == '\t' || *s == '=') s++;
    while (*s >= '0' && *s <= '9') {
        u32 d = (u32)(*s - '0');
        if (v > 429496729u || (v == 429496729u && d > 5u))
            return 0;
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

static ssize_t ufq_proc_write(struct file *file, const char *ubuf,
                              size_t len, loff_t *ppos)
{
    char kbuf[64];
    u32 n = len < 63u ? (u32)len : 63u;
    u32 val;

    (void)file; (void)ppos;
    if (titan_copy_from_user(kbuf, ubuf, n) != 0)
        return -14; /* -EFAULT */
    kbuf[n] = '\0';

    local_bh_disable();
    if (starts_with(kbuf, "mode") && parse_u32(kbuf + 4, &val)) {
        if (val <= UFQ_MODE_MAX) {
            g_ufq.mode = val;
            g_ufq.failsafe_tripped = 0;
            g_ufq.last_progress_us = now_us();
            if (!(val & UFQ_MODE_ENABLE) && g_ufq.total_pkts > 0) {
                g_in_drain = 1u;
                ufq_flush_all(&g_ufq, &g_ufq_ops, NULL, 1);
                g_in_drain = 0u;
            }
        }
    } else if (starts_with(kbuf, "bql_mult_q4") && parse_u32(kbuf + 11, &val)) {
        if (val >= 12u && val <= 64u) g_ufq.bql_mult_q4 = val;
    } else if (starts_with(kbuf, "bql_min_kb") && parse_u32(kbuf + 10, &val)) {
        if (val >= 4u && val <= 64u) g_ufq.bql_min_bytes = val << 10;
    } else if (starts_with(kbuf, "bql_max_kb") && parse_u32(kbuf + 10, &val)) {
        if (val >= 8u && val <= 128u) g_ufq.bql_max_bytes = val << 10;
    } else if (starts_with(kbuf, "sparse_headroom_kb") && parse_u32(kbuf + 18, &val)) {
        if (val >= 2u && val <= 64u) g_ufq.sparse_headroom = val << 10;
    } else if (starts_with(kbuf, "codel_target_ms") && parse_u32(kbuf + 15, &val)) {
        if (val >= 2u && val <= 50u) g_ufq.codel_target_us = val * 1000u;
    } else if (starts_with(kbuf, "codel_interval_ms") && parse_u32(kbuf + 17, &val)) {
        if (val >= 20u && val <= 500u) g_ufq.codel_interval_us = val * 1000u;
    } else if (starts_with(kbuf, "quantum") && parse_u32(kbuf + 7, &val)) {
        if (val >= 512u && val <= 4096u) g_ufq.quantum = val;
    } else if (starts_with(kbuf, "pace_gain_q4") && parse_u32(kbuf + 12, &val)) {
        if (val >= 16u && val <= 32u) g_ufq.pace_gain_q4 = val;
    } else if (starts_with(kbuf, "pace") && parse_u32(kbuf + 4, &val)) {
        if (val <= 1u) g_ufq.pace_enable = val;
    } else if (starts_with(kbuf, "tti_hold_us") && parse_u32(kbuf + 11, &val)) {
        if (val <= 4000u) g_ufq.tti_hold_us = val;
    } else if (starts_with(kbuf, "tti_ms") && parse_u32(kbuf + 6, &val)) {
        if (val >= 1u && val <= 20u) g_ufq.tti_ms = val;
    } else if (starts_with(kbuf, "failsafe_ms") && parse_u32(kbuf + 11, &val)) {
        if (val >= 50u && val <= 2000u) g_ufq.failsafe_ms = val;
    } else if (starts_with(kbuf, "max_pkts") && parse_u32(kbuf + 8, &val)) {
        if (val >= 32u && val <= UFQ_MAX_PKTS) g_ufq.max_pkts = val;
    } else if (starts_with(kbuf, "reset")) {
        g_stat_ul_seen = 0;
        g_stat_nonip_pass = 0;
        g_stat_ctx_skipped = 0;
        g_stat_timer_fires = 0;
        g_ufq.stat_enq_pkts = 0;
        g_ufq.stat_deq_sparse = 0;
        g_ufq.stat_deq_bulk = 0;
        g_ufq.stat_codel_drop = 0;
        g_ufq.stat_codel_ecn = 0;
        g_ufq.stat_overlimit_drop = 0;
        g_ufq.stat_passthrough = 0;
        g_ufq.stat_ram_fresh = 0;
        g_ufq.stat_ram_stale = 0;
        g_ufq.stat_gipc_zero_snap = 0;
        g_ufq.stat_failsafe = 0;
        g_ufq.stat_netdev_drop = 0;
        g_ufq.stat_max_q_pkts = 0;
        g_ufq.stat_max_q_bytes = 0;
        g_ufq.failsafe_tripped = 0;
        g_ufq.last_progress_us = now_us();
    }
    local_bh_enable();
    return (ssize_t)len;
}

static const struct file_operations ufq_proc_fops = {
    .owner   = &__this_module,
    .llseek  = seq_lseek,
    .read    = seq_read,
    .write   = ufq_proc_write,
    .open    = ufq_proc_open,
    .release = single_release,
};

static void unmap_modem_pages(void)
{
    if (g_va_rbc) { __arm_iounmap(g_va_rbc); g_va_rbc = NULL; }
    if (g_va_mac) { __arm_iounmap(g_va_mac); g_va_mac = NULL; }
    if (g_va_knl) { __arm_iounmap(g_va_knl); g_va_knl = NULL; }
    if (g_va_n4)  { __arm_iounmap(g_va_n4);  g_va_n4  = NULL; }
}

/* ---------- Module init & cleanup ---------- */
int init_module(void)
{
    int ret;

    g_unloading = 0;
    g_timer_pending = 0;
    g_in_drain = 0;
    g_stat_ul_seen = 0;
    g_stat_nonip_pass = 0;
    g_stat_ctx_skipped = 0;
    g_stat_timer_fires = 0;

    ufq_init(&g_ufq, now_us()); /* mode=0 pass-through by default */

    /* Read-only mapping of safe modem RAM pages (never touches 0x14110000 AFC) */
    g_va_n4  = (volatile u8 *)__arm_ioremap(MODEM_N4_PAGE,  0x1000u,        MT_DEVICE);
    g_va_knl = (volatile u8 *)__arm_ioremap(MODEM_KNL_PAGE, 0x1000u,        MT_DEVICE);
    g_va_mac = (volatile u8 *)__arm_ioremap(MODEM_MAC_PAGE, 0x1000u,        MT_DEVICE);
    g_va_rbc = (volatile u8 *)__arm_ioremap(MODEM_RBC_PAGE, MODEM_RBC_SIZE, MT_DEVICE);

    tasklet_hrtimer_init(&g_drain_timer, drain_timer_cb,
                         CLOCK_MONOTONIC, HRTIMER_MODE_REL);

    g_proc_ent = proc_create_data("titan_ufq", 0644, NULL, &ufq_proc_fops, NULL);
    if (!g_proc_ent) {
        unmap_modem_pages();
        printk("titan_ufq: failed to create /proc/titan_ufq\n");
        return -12; /* -ENOMEM */
    }

    g_netdev_nb.notifier_call = ufq_netdev_event;
    g_netdev_nb.priority = 0;
    ret = register_netdevice_notifier(&g_netdev_nb);
    if (ret != 0) {
        remove_proc_entry("titan_ufq", NULL);
        unmap_modem_pages();
        printk("titan_ufq: register_netdevice_notifier failed (%d)\n", ret);
        return ret;
    }

    g_nf_ops.hook     = ufq_bridge_hook;
    g_nf_ops.owner    = &__this_module;
    g_nf_ops.pf       = NFPROTO_BRIDGE;
    g_nf_ops.hooknum  = NF_BR_FORWARD;
    g_nf_ops.priority = 150; /* after ebtables (-200), br_nf (0), titan_qctrl (+100) */

    ret = nf_register_hook(&g_nf_ops);
    if (ret != 0) {
        unregister_netdevice_notifier(&g_netdev_nb);
        remove_proc_entry("titan_ufq", NULL);
        unmap_modem_pages();
        printk("titan_ufq: nf_register_hook failed (%d)\n", ret);
        return ret;
    }

    printk("titan_ufq: loaded v0.1 in pass-through mode (mode=0); control via /proc/titan_ufq\n");
    return 0;
}

void cleanup_module(void)
{
    g_unloading = 1u;
    nf_unregister_hook(&g_nf_ops);
    synchronize_net();
    hrtimer_cancel(&g_drain_timer.timer);
    tasklet_kill(&g_drain_timer.tasklet);

    local_bh_disable();
    g_in_drain = 1u;
    ufq_flush_all(&g_ufq, &g_ufq_ops, NULL, 1);
    g_in_drain = 0u;
    local_bh_enable();

    unregister_netdevice_notifier(&g_netdev_nb);
    remove_proc_entry("titan_ufq", NULL);
    unmap_modem_pages();
    printk("titan_ufq: unloaded cleanly\n");
}
