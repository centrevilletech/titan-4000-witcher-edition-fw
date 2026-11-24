/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright 2026 Centreville Tech, LLC. Kernel module for Titan 4000 Witcher Edition; see device/fastpath/README.md. */
/*
 * titan_k1fp.c - Passthrough bridge fast path (k1fp 2.2) for the Global
 * Telecom Titan 4000 (GDM7243AP, Linux 3.10.0-uc0, UP ARMv7, PREEMPT_NONE).
 *
 * Built standalone against titan_k310_abi.h (no 3.10 kernel tree required).
 * Starts in mode 0 (OFF) on insmod.
 *
 * Modes (/proc/k1fp):
 *   mode 0 : OFF. Immediate pass-through to br_handle_frame_hook.
 *   mode 1 : OBSERVE. Classifies packets, proves flows on the stock path,
 *            and counts what would be fast-pathed without changing forwarding.
 *   mode 2 : DOWNLINK fast path (lte0pdn2 -> eth0). Uplink stays on stock.
 *   mode 3 : BOTH directions. When titan_qctrl is loaded on NF_BR_FORWARD,
 *            downlink fast-path packets invoke titan_qctrl's hook directly
 *            (so OWD/RTT/rate/ECN/UDP-drop stay exact) and uplink TCP stays
 *            on stock (so RWND clamping and ACK thinning are never bypassed).
 *
 * CBRS / SAS enforcement (both families fail closed):
 *   1. Per-flow proof: IPv4 leases are granted only at NF_INET_POST_ROUTING
 *      (NF_IP_PRI_LAST, after iptables FORWARD and SNAT). IPv6 leases are
 *      granted only at NF_BR_POST_ROUTING (NF_BR_PRI_LAST, after ebtables
 *      FORWARD and br_nf_post_routing). Vendor IPv4 FORWARD DROP and Witcher
 *      IPv6 ebtables FORWARD DROP revoke active leases within sample_ms
 *      (default 20 ms, cap 50 ms) and prevent new leases.
 *   2. Userspace grant lease: require_grant=1 by default; expires cleanly
 *      unless renewed with "grant <1..60>" while cbrs_mode_grant=1 and
 *      cbrs_grant_state=2. "grant 0" closes immediately. While the gate is
 *      closed, candidates stay on stock without renewing leases or sampling;
 *      every gate open/close transition bumps the epoch so flows re-prove
 *      fresh against the open-gate rules.
 *
 * Watchdog (no dependence on kernel log):
 *   Runs every 100 ms while mode >= 2 and checks modified/wrongport bursts
 *   in a sliding window (wd_mod per wd_mod_win_ms, default 20 per 10 s),
 *   lease mismatch storms, eth0 TX ring full persistence, TX stall, and bad
 *   ring state, dropping mode -> 0 atomically on any anomaly. Recent
 *   mismatches are captured in a bounded 16-entry header-only ring readable
 *   from /proc/k1fp after a trip and cleared by "zero".
 *
 * Device loss and re-acquire:
 *   NETDEV_UNREGISTER of eth0, lte0pdn2 or the bridge drops that pointer and
 *   its reference, sets mode 0 and counts dev_gone. It is not a watchdog
 *   trip: a modem re-attach makes the vendor scripts recreate br0 and
 *   lte0pdn2. The 1 s housekeeping work looks the missing devices up again
 *   by name under RTNL and adopts them only once eth0 and lte0pdn2 are stock
 *   ports of one bridge again (the test init_module applies), counts reacq
 *   and bumps the epoch. The mode stays 0 until userspace writes it again.
 *
 * Note: dlbypass (gdmlte live text patch) is intentionally absent so
 * the vendor netif_enqueue router-MAC rewrite is always preserved.
 */

#include "titan_k310_abi.h"
#include "k1fp_core.h"
#include "k1_fp.h"

#define K1_VERSION "titan_k1fp v2.2"

/* ---------- Module metadata matching stock 3.10.0-uc0 ELF ABI ---------- */
int init_module(void);
void cleanup_module(void);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"), aligned(4))) = {
	.name = "titan_k1fp",
	.init = init_module,
	.exit = cleanup_module,
};

static const char __mod_license[]  __attribute__((section(".modinfo"), used)) = "license=GPL";
static const char __mod_depends[]  __attribute__((section(".modinfo"), used)) = "depends=";
static const char __mod_vermagic[] __attribute__((section(".modinfo"), used)) =
	"vermagic=3.10.0-uc0 mod_unload ARMv7 ";

/* ---------- Binary-verified kernel addresses & offsets (protected by k1_fp.h) ---------- */
#define VA_GDM_NET_IF            0x8059fcb0u
#define GDM_EXTDEV_OFF           0x008u
#define GDM_EXTDEV_STOP_OFF      0x014u
#define GDM_HOSTMAC_OFF          0x2a4u
#define GDM_HOSTMAC_LEARNED_OFF  0x2aau
#define GDM_NETIFQ_OFF           0x2c4u
#define GDM_NETMODE_OFF          0x10598u

#define VA_KMON                  0x805b51a0u
#define VA_EMUL6                 0x80629a60u
#define VA_BRHOOK                0x8062e0c0u
#define BRHOOK_NR_OFF            0x3cu

#define BRP_BR_OFF               0x00u
#define BRP_DEV_OFF              0x04u
#define BRP_STATE_OFF            0x11u
#define BR_DEV_OFF               0x08u
#define VA_BR_DEV_XMIT           0x8034f4ccu
#define K1_BR_FORWARDING         3u

#define GETH_TX_DESC             0x410u
#define GETH_TX_NDESC            0x41cu
#define GETH_TX_TAIL             0x420u
#define GETH_TX_HEAD             0x424u
#define GETH_TXD_SIZE            24u
#define GETH_TASKLET             0x51cu
#define GETH_IC_SITE_OFF         0xf8u
#define GETH_IC_ORIG             0xe382220eu /* orr r2, r2, #0xe0000000 (IC|LS|FS) */
#define GETH_IC_NOIRQ            0xe3822206u /* orr r2, r2, #0x60000000 (LS|FS) */
#define K1_TX_GUARD_MS           500u
#define K1_WD_PERIOD_MS          100u

#define RD32(a) (*(volatile u32 *)(unsigned long)(a))
#define RD8(a)  (*(volatile u8  *)(unsigned long)(a))

enum { K1_TXOFF_USER = 0, K1_TXOFF_DEV, K1_TXOFF_GUARD, K1_TXOFF_RING };

struct k1_stats {
	u32 fast[2];           /* [0] DL (to LAN), [1] UL (to WAN) */
	u32 fastbytes_k[2];    /* KiB */
	u32 why[K1W__N];
	u32 fres[K1F__N];
	u32 notport, badctx, shared, gso, nonlin, nolin, localmac;
	u32 vendor, portstate, mtu, famoff, nested, ports, xmit_err;
	u32 brhold, brhold_enter;
	u32 gate_closed, would_fast;
	u32 cand_stock, granted4, granted6, brok, modified, wrongport, noconfirm, revoked;
	u32 local_deliv, local_alias;
	u32 qctrl_dl_calls, qctrl_dl_drop, qctrl_dl_stolen, qctrl_ul_stock;
	u32 wd_trips;
	u32 tx_reclaim, tx_timer, tx_off[4], tx_stallguard, tx_badring;
	u32 hk_attach, epoch_bumps;
	u32 f4[2], f6[2], fudp[2];
	u32 wf4[2], wf6[2], wfudp[2];
};

static struct {
	struct net_device *lan, *wan, *br;
	rx_handler_func_t *orig_rx;
	int (*br_push_xmit)(struct sk_buff *);
	int lan_hooked, wan_hooked;
	u8  in_hold;
	/* config */
	int mode;              /* 0=off, 1=observe, 2=dl, 3=both */
	int require_grant, v4, v6;
	u32 lease_j, sample_j;
	u32 grant_until;
	int grant_set;
	u32 epoch, seed;
	volatile int unloading;
	int nports, ports_ok;
	/* device loss and re-acquire; not cleared by "zero" */
	u32 dev_gone, reacq;
	/* watchdog */
	struct k1_wd_cfg wd_cfg;
	struct k1_wd_state wd;
	int wd_last_reason;
	u32 wd_last_j;
	struct timer_list wdtimer;
	/* optional eth0 txirq (default 0) */
	int tx_on, tx_drain;
	u32 tx_drain_head, tx_last_j;
	struct k1_txguard txg;
	u32 *tx_site;
	void (*tx_tasklet_fn)(unsigned long);
	struct timer_list txtimer;
	int last_err_tx;
	u8  tx_pin;
	int pins;
	/* proof, diagnostic ring & stats */
	struct k1_pend pend;
	struct k1_diag_ring diag;
	struct k1_stats st;
} g;

static struct k1_tbl *tbl;
static struct delayed_work hk_work;
static struct proc_dir_entry *k1_proc;

static void k1_epoch_bump(void)
{
	unsigned long flags = titan_irq_save();
	g.epoch++;
	g.st.epoch_bumps++;
	titan_irq_restore(flags);
}

/* ---------- SHA-256 kernel function fingerprints ---------- */

static int k1_fp_sha256_check(const char *name, unsigned long va, u32 len, const u8 want[32])
{
	struct k1_sha256_ctx ctx;
	u8 buf[64], got[32];
	u32 off = 0;

	k1_sha256_init(&ctx);
	while (off < len) {
		u32 chunk = len - off;
		if (chunk > sizeof(buf))
			chunk = sizeof(buf);
		if (probe_kernel_read(buf, (const void *)(va + off), chunk)) {
			printk(KERN_ERR "k1fp: %s: cannot read %08lx\n", name, va + off);
			return -EFAULT;
		}
		k1_sha256_update(&ctx, buf, chunk);
		off += chunk;
	}
	k1_sha256_final(&ctx, got);
	if (memcmp(got, want, 32) != 0) {
		printk(KERN_ERR "k1fp: %s SHA-256 mismatch at %08lx (%u bytes)\n", name, va, len);
		return -ENODEV;
	}
	return 0;
}

static int k1_sym_check(const char *name, unsigned long want)
{
	unsigned long a = kallsyms_lookup_name(name);

	if (a != want) {
		printk(KERN_ERR "k1fp: kallsyms %s = %08lx, expected %08lx\n", name, a, want);
		return -ENODEV;
	}
	return 0;
}

static int k1_fp_core(void)
{
	int r;

	if ((unsigned long)netif_rx != FP_NETIF_RX_VA) {
		printk(KERN_ERR "k1fp: netif_rx = %08lx, expected %08x\n",
		       (unsigned long)netif_rx, FP_NETIF_RX_VA);
		return -ENODEV;
	}
	r = k1_fp_sha256_check("netif_rx", FP_NETIF_RX_VA, FP_NETIF_RX_LEN, fp_netif_rx_sha256);
	if (!r)
		r = k1_fp_sha256_check("netif_enqueue", FP_NETIF_ENQUEUE_VA,
				       FP_NETIF_ENQUEUE_LEN, fp_netif_enqueue_sha256);
	if (!r)
		r = k1_fp_sha256_check("br_handle_frame", FP_BR_HANDLE_FRAME_VA,
				       FP_BR_HANDLE_FRAME_LEN, fp_br_handle_frame_sha256);
	if (!r)
		r = k1_fp_sha256_check("br_handle_frame_hook", FP_BR_HANDLE_FRAME_HOOK_VA,
				       FP_BR_HANDLE_FRAME_HOOK_LEN, fp_br_handle_frame_hook_sha256);
	if (!r)
		r = k1_fp_sha256_check("br_add_if", FP_BR_ADD_IF_VA,
				       FP_BR_ADD_IF_LEN, fp_br_add_if_sha256);
	if (!r)
		r = k1_fp_sha256_check("br_dev_queue_push_xmit", FP_BR_DEV_QUEUE_PUSH_XMIT_VA,
				       FP_BR_DEV_QUEUE_PUSH_XMIT_LEN, fp_br_dev_queue_push_xmit_sha256);
	if (!r)
		r = k1_fp_sha256_check("gdm_eth_start_xmit", FP_GDM_ETH_START_XMIT_VA,
				       FP_GDM_ETH_START_XMIT_LEN, fp_gdm_eth_start_xmit_sha256);
	if (!r)
		r = k1_fp_sha256_check("gdm_eth_finish_xmit_tasklet",
				       FP_GDM_ETH_FINISH_XMIT_TASKLET_VA,
				       FP_GDM_ETH_FINISH_XMIT_TASKLET_LEN,
				       fp_gdm_eth_finish_xmit_tasklet_sha256);
	if (!r)
		r = k1_sym_check("br_handle_frame", FP_BR_HANDLE_FRAME_VA);
	if (!r)
		r = k1_sym_check("br_handle_frame_hook", FP_BR_HANDLE_FRAME_HOOK_VA);
	if (!r)
		r = k1_sym_check("br_add_if", FP_BR_ADD_IF_VA);
	if (!r)
		r = k1_sym_check("br_dev_xmit", VA_BR_DEV_XMIT);
	if (!r)
		r = k1_sym_check("br_dev_queue_push_xmit", FP_BR_DEV_QUEUE_PUSH_XMIT_VA);
	if (!r)
		r = k1_sym_check("gdm_eth_start_xmit", FP_GDM_ETH_START_XMIT_VA);
	if (!r)
		r = k1_sym_check("gdm_eth_finish_xmit_tasklet", FP_GDM_ETH_FINISH_XMIT_TASKLET_VA);
	return r;
}

/* ---------- Live titan_qctrl discovery on NF_BR_FORWARD (RCU-safe) ---------- */

/*
 * Walks nf_hooks[NFPROTO_BRIDGE][NF_BR_FORWARD] from the tail (priority +100
 * sits at the tail after ebtables -200 and br_netfilter -1). Called only inside
 * softirq / BH-off (RCU read-side critical section); titan_qctrl calls
 * nf_unregister_hook() + synchronize_net() before freeing module memory, so
 * the returned hook pointer is always live for the duration of this call.
 */
static inline nf_hookfn *k1_find_qctrl_hook(void)
{
	struct list_head *head = &nf_hooks[NFPROTO_BRIDGE][NF_BR_FORWARD];
	struct list_head *pos;

	for (pos = head->prev; pos != head; pos = pos->prev) {
		struct nf_hook_ops *ops = container_of(pos, struct nf_hook_ops, list);
		if (ops->owner && memcmp(ops->owner->name, "titan_qctrl", 12) == 0)
			return ops->hook;
	}
	return NULL;
}

/* ---------- Vendor gates & TX ring helpers ---------- */

static inline int k1_bridge_vendor_idle(int family)
{
	if (RD32(VA_KMON + 0x14u))
		return 0;
	if (family == 6 && (RD32(VA_EMUL6) & 0x8000u))
		return 0;
	return 1;
}

static inline int k1_brhook_hold(void)
{
	int h = k1_hold_step(RD32(VA_GDM_NET_IF + GDM_EXTDEV_STOP_OFF),
			     RD32(VA_BRHOOK + BRHOOK_NR_OFF), &g.in_hold);

	if (likely(h == K1H_NONE))
		return 0;
	if (h == K1H_ENTER) {
		k1_epoch_bump();
		g.st.brhold_enter++;
	}
	g.st.brhold++;
	return 1;
}

static inline int k1_port_fwd(const struct net_device *d)
{
	void *p;

	if (!(d->priv_flags & IFF_BRIDGE_PORT))
		return 0;
	p = d->rx_handler_data;
	return p && RD8((unsigned long)p + BRP_STATE_OFF) == K1_BR_FORWARDING;
}

static inline int k1_gate_open(u32 now)
{
	if (!g.require_grant)
		return 1;
	return g.grant_set && k1_before(now, g.grant_until);
}

static inline int k1_tx_running(const struct net_device *d)
{
	return d && (d->flags & IFF_UP) && netif_running(d);
}

static inline int k1_tx_live(const struct net_device *d)
{
	return k1_tx_running(d) && netif_carrier_ok(d);
}

/* 1 = tail descriptor in use, 0 = free, -1 = ring not as expected */
static int k1_tx_tail_used(const struct net_device *d)
{
	unsigned long base = RD32((unsigned long)d + GETH_TX_DESC);
	u32 n = RD32((unsigned long)d + GETH_TX_NDESC);
	u32 tail = RD32((unsigned long)d + GETH_TX_TAIL);
	const volatile u32 *desc;

	if (!base || !n || n > 4096u || tail >= n ||
	    RD32((unsigned long)d + GETH_TX_HEAD) >= n)
		return -1;
	desc = (const volatile u32 *)(base + tail * GETH_TXD_SIZE);
	return k1_txd_used(desc[0], desc[1]);
}

/* ---------- Watchdog (drops mode -> 0 on anomaly) ---------- */

static int k1_tx_off(int reason);

/* Call with BH off (softirq or local_bh_disable). */
static void k1_wd_trip(int reason)
{
	if (g.mode >= K1_MODE_DL) {
		g.mode = K1_MODE_OFF;
		g.wd.armed = 0;
		g.wd_last_reason = reason;
		g.wd_last_j = (u32)jiffies;
		g.st.wd_trips++;
		k1_epoch_bump();
	}
	if (g.tx_on && (reason == K1_WD_TXSTALL || reason == K1_WD_BADRING))
		k1_tx_off(reason == K1_WD_BADRING ? K1_TXOFF_RING : K1_TXOFF_GUARD);
}

static void k1_wdtimer_fn(unsigned long data)
{
	struct net_device *d = g.lan;
	int live, used = 0, bad_ring = 0, ring_full = 0, stopped = 0, trip;
	u32 tail = 0;

	(void)data;
	if (g.unloading || g.mode < K1_MODE_DL)
		return;
	live = k1_tx_live(d);
	if (live) {
		used = k1_tx_tail_used(d);
		if (used < 0) {
			bad_ring = 1;
		} else {
			u32 head = RD32((unsigned long)d + GETH_TX_HEAD);
			tail = RD32((unsigned long)d + GETH_TX_TAIL);
			ring_full = (used > 0) && (head == tail);
			stopped = netif_queue_stopped(d);
		}
	}
	trip = k1_wd_tick(&g.wd, &g.wd_cfg, 1, live, bad_ring, ring_full, stopped, tail,
			  g.st.modified, g.st.wrongport, g.st.fres[K1F_MISMATCH], K1_WD_PERIOD_MS);
	if (trip != K1_WD_NONE) {
		k1_wd_trip(trip);
		return;
	}
	if (!g.unloading && g.mode >= K1_MODE_DL)
		mod_timer(&g.wdtimer, jiffies + msecs_to_jiffies(K1_WD_PERIOD_MS));
}

/* ---------- Feature 1: Fast path ---------- */

static inline void k1_famcount(u32 *v4, u32 *v6, u32 *udp, const struct k1_pkt *p, int dir)
{
	if (p->family == 4)
		v4[dir]++;
	else
		v6[dir]++;
	if (p->proto == 17)
		udp[dir]++;
}

static rx_handler_result_t k1_rx(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct net_device *in = skb->dev, *out;
	struct k1_pkt pkt;
	struct k1_flow *f;
	nf_hookfn *qctrl_fn;
	const u8 *eth;
	u32 outidx, now, why, pc;
	int r, dir, pol, qctrl_active;
	rx_handler_result_t res;

	/* Mode 0 (OFF) or unloading: zero-overhead pass-through */
	if (unlikely(g.mode == K1_MODE_OFF || g.unloading))
		return g.orig_rx(pskb);

	/* Require softirq context with IRQs enabled (matches titan_qctrl Y6 guard) */
	pc = titan_preempt_count();
	if (unlikely(!(pc & TITAN_SOFTIRQ_MASK) || (pc & TITAN_HARDIRQ_MASK) ||
		     titan_irqs_disabled())) {
		g.st.badctx++;
		goto stock;
	}

	if (in == g.wan) {
		out = g.lan; outidx = 1; dir = 0;
	} else if (in == g.lan) {
		out = g.wan; outidx = 2; dir = 1;
	} else {
		g.st.notport++;
		goto stock;
	}
	if (unlikely(!out || !g.br))
		goto stock;
	if (unlikely(!g.ports_ok)) {
		g.st.ports++;
		goto stock;
	}
	/* Mode 2 (DL only): uplink skips all fast-path parsing and proof */
	if (g.mode == K1_MODE_DL && dir != 0)
		goto stock;

	if (k1_brhook_hold())
		goto stock;

	/* Never touch shared, loopback, VLAN-tagged, GSO/GRO, or non-linear skbs */
	if (skb->users != 1 || skb_pkt_type(skb) == PACKET_LOOPBACK || skb_vlan_present(skb)) {
		g.st.shared++;
		goto stock;
	}
	if (unlikely(skb->data_len != 0)) {
		g.st.nonlin++;
		goto stock;
	}
	if (unlikely(skb_is_gso(skb))) {
		g.st.gso++;
		goto stock;
	}
	eth = skb->mac_header;
	if (unlikely(!eth || (u32)(skb->data - eth) != ETH_HLEN)) {
		g.st.nolin++;
		goto stock;
	}
	why = (u32)k1_parse(eth, skb_headlen(skb) + ETH_HLEN, skb->len, outidx, &pkt);
	if (why) {
		g.st.why[why]++;
		goto stock;
	}
	if ((pkt.family == 4 && !g.v4) || (pkt.family == 6 && !g.v6)) {
		g.st.famoff++;
		goto stock;
	}

	/* Check live titan_qctrl hook on NF_BR_FORWARD */
	qctrl_fn = k1_find_qctrl_hook();
	qctrl_active = qctrl_fn != NULL;
	pol = k1_mode_dir_policy(g.mode, dir, pkt.proto, qctrl_active);
	if (pol == K1P_OFF)
		goto stock;
	if (pol == K1P_QCTRL_STOCK) {
		/* UL TCP while titan_qctrl is loaded: stay on stock so RWND clamp
		 * and ACK thinning run natively and never trigger false modified counts. */
		g.st.qctrl_ul_stock++;
		goto stock;
	}

	pkt.mark = skb->mark;
	pkt.prio = skb->priority;

	/* Frames addressed to any unit interface MAC stay on stock (local delivery) */
	if (ether_addr_equal(eth, g.br->dev_addr) ||
	    ether_addr_equal(eth, in->dev_addr) ||
	    ether_addr_equal(eth, out->dev_addr)) {
		g.st.localmac++;
		goto stock;
	}
	if (!k1_bridge_vendor_idle(pkt.family)) {
		g.st.vendor++;
		goto stock;
	}
	if (!k1_port_fwd(in) || !k1_port_fwd(out) || !netif_running(out)) {
		g.st.portstate++;
		goto stock;
	}
	if (pkt.l3len > out->mtu) {
		g.st.mtu++;
		goto stock;
	}
	if (unlikely(g.pend.active)) {
		g.st.nested++;
		goto stock;
	}

	now = (u32)jiffies;
	/* Gate closed (no SAS grant): stay on stock without renewing leases or
	 * running comparator proofs against closed-gate firewall churn. Gate
	 * transitions bump g.epoch so every flow re-proves fresh once open. */
	if (!k1_gate_open(now)) {
		g.st.gate_closed++;
		goto stock;
	}
	r = k1_fast_check(tbl, &pkt, now, g.epoch, g.sample_j, g.seed, &f);
	if (r == K1F_FAST) {
		if (pol == K1P_OBSERVE) {
			g.st.would_fast++;
			k1_famcount(g.st.wf4, g.st.wf6, g.st.wfudp, &pkt, dir);
			goto stock_cand;
		}
		/* IPv4: trim Ethernet padding just as br_parse_ip_options does */
		if (pkt.family == 4 && skb->len > pkt.l3len)
			skb_trim_linear(skb, pkt.l3len);
		skb_clear_csum_complete(skb);
		skb->dev = out;

		/* Downlink with titan_qctrl loaded: invoke qctrl's NF_BR_FORWARD
		 * hook directly so it observes 100% of DL bytes, timestamps, OWD,
		 * RTT, ECN marking, and UDP drop while skipping bridge/netfilter. */
		if (dir == 0 && qctrl_fn) {
			unsigned int verdict;
			g.st.qctrl_dl_calls++;
			verdict = qctrl_fn(NF_BR_FORWARD, skb, in, out, g.br_push_xmit);
			if (verdict == NF_DROP) {
				g.st.qctrl_dl_drop++;
				kfree_skb(skb);
				return RX_HANDLER_CONSUMED;
			}
			if (verdict == NF_STOLEN) {
				g.st.qctrl_dl_stolen++;
				return RX_HANDLER_CONSUMED;
			}
			if (unlikely(skb->data < skb->head + ETH_HLEN)) {
				g.st.xmit_err++;
				kfree_skb(skb);
				return RX_HANDLER_CONSUMED;
			}
		}

		g.st.fast[dir]++;
		g.st.fastbytes_k[dir] += (skb->len + ETH_HLEN) >> 10;
		k1_famcount(g.st.f4, g.st.f6, g.st.fudp, &pkt, dir);
		skb_push(skb, ETH_HLEN);
		if (unlikely(dev_queue_xmit(skb) != 0))
			g.st.xmit_err++;
		return RX_HANDLER_CONSUMED;
	}
	g.st.fres[r]++;

stock_cand:
	g.st.cand_stock++;
	k1_pend_begin(&g.pend, skb, outidx, &pkt, eth, f && r != K1F_NOLEASE && r != K1F_STALE);
	res = g.orig_rx(pskb);
	if (!g.pend.granted && !g.pend.cancelled)
		g.st.noconfirm++;
	if (k1_pend_end(&g.pend, tbl, (u32)jiffies, g.seed))
		g.st.revoked++;
	return res;

stock:
	return g.orig_rx(pskb);
}

static inline u32 k1_outidx(const struct net_device *d)
{
	if (d == g.lan)
		return 1;
	if (d == g.wan)
		return 2;
	return 0;
}

static inline void k1_check_mod_trip(void)
{
	int trip = k1_wd_check_mod(&g.wd, &g.wd_cfg, g.mode >= K1_MODE_DL,
				   g.st.modified, g.st.wrongport);

	if (trip != K1_WD_NONE)
		k1_wd_trip(trip);
}

/*
 * Cancel g.pend before local delivery (br_pass_frame_up -> netif_receive_skb).
 * Without this, a locally delivered skb (such as a reverse-SNATed SAS reply)
 * can be freed in tcp_v4_rcv() and immediately re-allocated from the UP SLUB
 * skbuff_head_cache LIFO freelist for the unit's synchronous reply, causing
 * k1_br_post() on br_dev_xmit() to match g.pend.skb by pointer equality.
 */
static unsigned int k1_br_local_in(unsigned int hooknum, struct sk_buff *skb,
				   const struct net_device *in, const struct net_device *out,
				   int (*okfn)(struct sk_buff *))
{
	(void)hooknum; (void)in; (void)out; (void)okfn;
	if (unlikely(g.pend.active && skb == g.pend.skb)) {
		if (k1_pend_cancel(&g.pend, skb))
			g.st.local_deliv++;
	}
	return NF_ACCEPT;
}

/*
 * Belt-and-suspenders guard on NF_BR_LOCAL_OUT (__br_deliver): locally
 * originated frames never enter __br_forward, so any match with g.pend.skb
 * here is guaranteed to be a SLUB pointer alias from an earlier drop/free.
 */
static unsigned int k1_br_local_out(unsigned int hooknum, struct sk_buff *skb,
				    const struct net_device *in, const struct net_device *out,
				    int (*okfn)(struct sk_buff *))
{
	(void)hooknum; (void)in; (void)out; (void)okfn;
	if (unlikely(g.pend.active && skb == g.pend.skb)) {
		if (k1_pend_cancel(&g.pend, skb))
			g.st.local_alias++;
	}
	return NF_ACCEPT;
}

static unsigned int k1_br_post(unsigned int hooknum, struct sk_buff *skb,
			       const struct net_device *in, const struct net_device *out,
			       int (*okfn)(struct sk_buff *))
{
	const u8 *eth;
	u32 outidx, lin;
	int r;

	(void)hooknum; (void)in; (void)okfn;
	if (likely(!g.pend.active) || skb != g.pend.skb)
		return NF_ACCEPT;
	eth = skb->mac_header;
	outidx = k1_outidx(out);
	lin = (eth && skb->data >= eth) ? (skb_headlen(skb) + (u32)(skb->data - eth)) : 0u;
	r = k1_stage_br(&g.pend, tbl, skb, outidx, eth, lin, skb->priority, skb->mark,
			(u32)jiffies, g.epoch, g.lease_j, g.sample_j, g.seed);
	if (r == K1S_BROK) {
		g.st.brok++;
	} else if (r == K1S_MODIFIED) {
		g.st.modified++;
		k1_diag_record(&g.diag, &g.pend, (u32)jiffies, K1_STG_BR_POST,
			       (u8)r, outidx, eth, lin, skb->priority, skb->mark);
		k1_check_mod_trip();
	} else if (r == K1S_WRONGPORT) {
		g.st.wrongport++;
		k1_diag_record(&g.diag, &g.pend, (u32)jiffies, K1_STG_BR_POST,
			       (u8)r, outidx, eth, lin, skb->priority, skb->mark);
		k1_check_mod_trip();
	}
	return NF_ACCEPT;
}

static unsigned int k1_br_last(unsigned int hooknum, struct sk_buff *skb,
			       const struct net_device *in, const struct net_device *out,
			       int (*okfn)(struct sk_buff *))
{
	const u8 *eth;
	u32 outidx, lin;
	int r;

	(void)hooknum; (void)in; (void)okfn;
	if (likely(!g.pend.active) || skb != g.pend.skb)
		return NF_ACCEPT;
	eth = skb->mac_header;
	outidx = k1_outidx(out);
	lin = (eth && skb->data >= eth) ? (skb_headlen(skb) + (u32)(skb->data - eth)) : 0u;
	r = k1_stage_br_last(&g.pend, tbl, skb, outidx, eth, lin, skb->priority, skb->mark,
			     (u32)jiffies, g.epoch, g.lease_j, g.sample_j, g.seed);
	if (r == K1S_GRANTED) {
		g.st.granted6++;
	} else if (r == K1S_MODIFIED) {
		g.st.modified++;
		k1_diag_record(&g.diag, &g.pend, (u32)jiffies, K1_STG_BR_LAST,
			       (u8)r, outidx, eth, lin, skb->priority, skb->mark);
		k1_check_mod_trip();
	} else if (r == K1S_WRONGPORT) {
		g.st.wrongport++;
		k1_diag_record(&g.diag, &g.pend, (u32)jiffies, K1_STG_BR_LAST,
			       (u8)r, outidx, eth, lin, skb->priority, skb->mark);
		k1_check_mod_trip();
	}
	return NF_ACCEPT;
}

static unsigned int k1_ip4_post(unsigned int hooknum, struct sk_buff *skb,
				const struct net_device *in, const struct net_device *out,
				int (*okfn)(struct sk_buff *))
{
	const u8 *eth;
	u32 outidx, lin;
	int r;

	(void)hooknum; (void)in; (void)out; (void)okfn;
	if (likely(!g.pend.active) || skb != g.pend.skb)
		return NF_ACCEPT;
	eth = skb->mac_header;
	outidx = k1_outidx(skb->dev);
	lin = (eth && skb->data >= eth) ? (skb_headlen(skb) + (u32)(skb->data - eth)) : 0u;
	r = k1_stage_ip4(&g.pend, tbl, skb, outidx, eth, lin, skb->priority, skb->mark,
			 (u32)jiffies, g.epoch, g.lease_j, g.sample_j, g.seed);
	if (r == K1S_GRANTED) {
		g.st.granted4++;
	} else if (r == K1S_MODIFIED) {
		g.st.modified++;
		k1_diag_record(&g.diag, &g.pend, (u32)jiffies, K1_STG_IP4_POST,
			       (u8)r, outidx, eth, lin, skb->priority, skb->mark);
		k1_check_mod_trip();
	} else if (r == K1S_WRONGPORT) {
		g.st.wrongport++;
		k1_diag_record(&g.diag, &g.pend, (u32)jiffies, K1_STG_IP4_POST,
			       (u8)r, outidx, eth, lin, skb->priority, skb->mark);
		k1_check_mod_trip();
	}
	return NF_ACCEPT;
}

static struct nf_hook_ops k1_ops[5] = {
	{
		.hook = k1_br_local_in,
		.owner = &__this_module,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_BR_LOCAL_IN,
		.priority = NF_BR_PRI_FIRST,
	},
	{
		.hook = k1_br_local_out,
		.owner = &__this_module,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_BR_LOCAL_OUT,
		.priority = NF_BR_PRI_FIRST,
	},
	{
		.hook = k1_br_post,
		.owner = &__this_module,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_BR_POST_ROUTING,
		.priority = NF_BR_PRI_NAT_SRC + 1,
	},
	{
		.hook = k1_br_last,
		.owner = &__this_module,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_BR_POST_ROUTING,
		.priority = NF_BR_PRI_LAST,
	},
	{
		.hook = k1_ip4_post,
		.owner = &__this_module,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
};

/* ---------- Bridge port hook management (under RTNL) ---------- */

static int k1_try_hook(struct net_device *d)
{
	void *p;
	u32 br;

	if (!d || !g.br)
		return 0;
	if (d->rx_handler == k1_rx)
		return 1;
	if (d->rx_handler != g.orig_rx || !(d->priv_flags & IFF_BRIDGE_PORT))
		return 0;
	p = d->rx_handler_data;
	if (!p || RD32((unsigned long)p + BRP_DEV_OFF) != (u32)(unsigned long)d)
		return 0;
	br = RD32((unsigned long)p + BRP_BR_OFF);
	if (br != (u32)(unsigned long)netdev_priv_ptr(g.br) ||
	    (void *)(unsigned long)RD32(br + BR_DEV_OFF) != g.br)
		return 0;
	d->rx_handler = k1_rx;
	barrier();
	k1_epoch_bump();
	g.st.hk_attach++;
	return 1;
}

static void k1_unhook(struct net_device *d)
{
	if (d && d->rx_handler == k1_rx) {
		d->rx_handler = g.orig_rx;
		barrier();
	}
}

static int k1_count_ports(void)
{
	struct list_head *pos;
	u32 br;
	int n = 0;

	if (!g.br)
		return -1;
	br = (u32)(unsigned long)netdev_priv_ptr(g.br);
	for (pos = init_net.dev_base_head.next; pos != &init_net.dev_base_head; pos = pos->next) {
		struct net_device *d = container_of(pos, struct net_device, dev_list);
		void *p;

		if (!(d->priv_flags & IFF_BRIDGE_PORT))
			continue;
		p = d->rx_handler_data;
		if (p && RD32((unsigned long)p + BRP_BR_OFF) == br)
			n++;
	}
	return n;
}

static void k1_ports_update(void)
{
	int n = k1_count_ports(), ok = (n == 2);

	if (n != g.nports || ok != g.ports_ok)
		k1_epoch_bump();
	g.nports = n;
	g.ports_ok = ok;
}

/*
 * A bridge port in the state br_add_if leaves it, or NULL. With quiet == 0
 * it logs why not (init_module).
 */
static void *k1_stock_port(struct net_device *d, int quiet)
{
	unsigned long h = (unsigned long)d->rx_handler;
	void *p;

	if (h != (unsigned long)g.orig_rx) {
		if (!quiet)
			printk(KERN_ERR "k1fp: %s rx_handler = %08lx, expected %08x\n",
			       d->name, h, FP_BR_HANDLE_FRAME_HOOK_VA);
		return NULL;
	}
	if (!(d->priv_flags & IFF_BRIDGE_PORT)) {
		if (!quiet)
			printk(KERN_ERR "k1fp: %s priv_flags = %08x, IFF_BRIDGE_PORT not set\n",
			       d->name, d->priv_flags);
		return NULL;
	}
	p = d->rx_handler_data;
	if (!p) {
		if (!quiet)
			printk(KERN_ERR "k1fp: %s rx_handler_data is NULL\n", d->name);
		return NULL;
	}
	if (RD32((unsigned long)p + BRP_DEV_OFF) != (u32)(unsigned long)d) {
		if (!quiet)
			printk(KERN_ERR "k1fp: %s bridge port dev mismatch\n", d->name);
		return NULL;
	}
	if (!RD32((unsigned long)p + BRP_BR_OFF)) {
		if (!quiet)
			printk(KERN_ERR "k1fp: %s bridge port has no bridge\n", d->name);
		return NULL;
	}
	return p;
}

/* The bridge device both ports belong to, or NULL. */
static struct net_device *k1_port_bridge(void *pl, void *pw, int quiet)
{
	u32 brl = RD32((unsigned long)pl + BRP_BR_OFF);
	u32 brw = RD32((unsigned long)pw + BRP_BR_OFF);
	struct net_device *bd;

	if (brl != brw) {
		if (!quiet)
			printk(KERN_ERR "k1fp: eth0 and lte0pdn2 are on different bridges\n");
		return NULL;
	}
	bd = (struct net_device *)(unsigned long)RD32(brl + BR_DEV_OFF);
	if (!bd || (u32)(unsigned long)netdev_priv_ptr(bd) != brl) {
		if (!quiet)
			printk(KERN_ERR "k1fp: bridge dev mismatch\n");
		return NULL;
	}
	if (!bd->netdev_ops || (unsigned long)bd->netdev_ops->ndo_start_xmit != VA_BR_DEV_XMIT) {
		if (!quiet)
			printk(KERN_ERR "k1fp: %s is not a bridge device\n", bd->name);
		return NULL;
	}
	return bd;
}

/*
 * Under RTNL. Look up by name the devices NETDEV_UNREGISTER took away, and
 * adopt them once the shape is one init_module would accept. A device the
 * module still holds may carry k1_rx as its handler; k1_try_hook checked its
 * port data when it put the handler there.
 *
 * RTNL makes this safe against a concurrent unregister: a device leaves the
 * name table before its NETDEV_UNREGISTER, both under RTNL, so a device found
 * here is registered, and its later unregister reaches k1_netdev_event, which
 * drops the reference taken here.
 */
static void k1_reacquire(void)
{
	struct net_device *l = g.lan, *w = g.wan, *nl = NULL, *nw = NULL, *bd = NULL;
	struct k1_reacq_in in;
	void *pl = NULL, *pw = NULL;
	u32 plan;

	if (l && w && g.br)
		return;
	memset(&in, 0, sizeof(in));
	in.have_lan = l != NULL;
	in.have_wan = w != NULL;
	in.have_br = g.br != NULL;
	if (!l)
		l = nl = dev_get_by_name(&init_net, "eth0");
	if (!w)
		w = nw = dev_get_by_name(&init_net, "lte0pdn2");
	in.lan_found = nl != NULL;
	in.wan_found = nw != NULL;
	if (l && w) {
		pl = (l->rx_handler == k1_rx && (l->priv_flags & IFF_BRIDGE_PORT)) ?
			l->rx_handler_data : k1_stock_port(l, 1);
		pw = (w->rx_handler == k1_rx && (w->priv_flags & IFF_BRIDGE_PORT)) ?
			w->rx_handler_data : k1_stock_port(w, 1);
		in.lan_port = pl != NULL;
		in.wan_port = pw != NULL;
		if (pl && pw) {
			in.same_br = RD32((unsigned long)pl + BRP_BR_OFF) ==
				     RD32((unsigned long)pw + BRP_BR_OFF);
			bd = k1_port_bridge(pl, pw, 1);
			in.br_valid = bd != NULL;
			in.br_matches_held = bd && bd == g.br;
		}
	}
	plan = k1_reacq_plan(&in);
	if (!plan) {
		if (nl)
			dev_put(nl);
		if (nw)
			dev_put(nw);
		return;
	}
	if (plan & K1RA_BR)
		dev_hold(bd);
	local_bh_disable();
	g.mode = K1_MODE_OFF;
	g.wd.armed = 0;
	if (plan & K1RA_LAN)
		g.lan = nl;
	if (plan & K1RA_WAN)
		g.wan = nw;
	if (plan & K1RA_BR)
		g.br = bd;
	g.reacq++;
	local_bh_enable();
	k1_epoch_bump();
	printk(KERN_INFO "k1fp: re-acquired%s%s%s, mode=0 (off)\n",
	       (plan & K1RA_LAN) ? " eth0" : "", (plan & K1RA_WAN) ? " lte0pdn2" : "",
	       (plan & K1RA_BR) ? " bridge" : "");
}

static void k1_hk(struct work_struct *w)
{
	(void)w;
	if (g.unloading)
		return;
	rtnl_lock();
	k1_reacquire();
	g.lan_hooked = k1_try_hook(g.lan);
	g.wan_hooked = k1_try_hook(g.wan);
	k1_ports_update();
	rtnl_unlock();
	if (!g.unloading)
		k1_schedule_delayed_work(&hk_work, HZ);
}

static int k1_netdev_event(struct notifier_block *nb, unsigned long ev, void *ptr)
{
	struct net_device *d = (struct net_device *)ptr;

	(void)nb;
	if (g.unloading)
		return NOTIFY_DONE;
	if (ev == NETDEV_JOIN) {
		g.ports_ok = 0;
		k1_epoch_bump();
	}
	if (d != g.lan && d != g.wan && d != g.br)
		return NOTIFY_DONE;
	switch (ev) {
	case NETDEV_UNREGISTER:
		if (d == g.lan)
			k1_tx_off(K1_TXOFF_DEV);
		if (d == g.br) {
			k1_unhook(g.lan);
			k1_unhook(g.wan);
		} else {
			k1_unhook(d);
		}
		/* Not a watchdog trip: a modem re-attach recreates br0 and
		 * lte0pdn2. Mode 0 until userspace sets it again. */
		local_bh_disable();
		g.mode = K1_MODE_OFF;
		g.wd.armed = 0;
		g.dev_gone++;
		if (d == g.lan)
			g.lan = NULL;
		else if (d == g.wan)
			g.wan = NULL;
		else if (d == g.br)
			g.br = NULL;
		local_bh_enable();
		k1_ports_update();
		k1_epoch_bump();
		dev_put(d);
		break;
	case NETDEV_GOING_DOWN:
		if (d == g.lan)
			k1_tx_off(K1_TXOFF_DEV);
		k1_epoch_bump();
		break;
	case NETDEV_UP:
	case NETDEV_DOWN:
	case NETDEV_CHANGE:
	case NETDEV_CHANGEADDR:
	case NETDEV_CHANGEMTU:
	case NETDEV_CHANGENAME:
	case NETDEV_JOIN:
		k1_epoch_bump();
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block k1_nb = { .notifier_call = k1_netdev_event };

/* ---------- Optional eth0 TX IRQ mitigation (default OFF, K1R F1/F6/F12 fixed) ---------- */

static void k1_pin(u8 *pin)
{
	if (*pin)
		return;
	__module_get(&__this_module);
	*pin = 1;
	g.pins++;
}

static void k1_unpin(u8 *pin)
{
	if (!*pin)
		return;
	*pin = 0;
	g.pins--;
	module_put(&__this_module);
}

static int k1_patch_word(u32 *site, u32 expect, u32 val)
{
	unsigned long flags;
	u32 cur;
	int r;

	if (probe_kernel_read(&cur, site, 4))
		return -EFAULT;
	if (cur != expect)
		return -EBUSY;
	flags = titan_irq_save();
	r = (int)probe_kernel_write(site, &val, 4);
	k1_flush_icache_range((unsigned long)site, (unsigned long)site + 4);
	titan_irq_restore(flags);
	if (r)
		return r;
	if (probe_kernel_read(&cur, site, 4) || cur != val)
		return -EIO;
	return 0;
}

static int k1_restore_word(u32 *site, u32 ours, u32 orig)
{
	u32 cur;

	if (probe_kernel_read(&cur, site, 4))
		return -EFAULT;
	if (cur == orig)
		return 0;
	if (cur != ours)
		return -EBUSY;
	return k1_patch_word(site, ours, orig);
}

static void k1_tx_reclaim(int force)
{
	struct net_device *d = g.lan;
	int used;

	if (!k1_tx_live(d))
		return;
	used = k1_tx_tail_used(d);
	if (used < 0) {
		g.st.tx_badring++;
		return;
	}
	if (force || k1_tx_need_reclaim(used, netif_queue_stopped(d))) {
		g.st.tx_reclaim++;
		g.tx_tasklet_fn((unsigned long)d);
	}
}

static int k1_tx_off(int reason)
{
	struct net_device *d = g.lan;
	int r;

	local_bh_disable();
	if (!g.tx_on) {
		local_bh_enable();
		return 0;
	}
	r = k1_restore_word(g.tx_site, GETH_IC_NOIRQ, GETH_IC_ORIG);
	if (r) {
		g.last_err_tx = r;
		local_bh_enable();
		printk(KERN_ERR "k1fp: txirq off (reason %d) restore failed: %d\n", reason, r);
		return r;
	}
	g.tx_on = 0;
	g.tx_drain = 1;
	g.tx_drain_head = k1_tx_running(d) ? RD32((unsigned long)d + GETH_TX_HEAD) : 0;
	g.st.tx_off[reason]++;
	k1_tx_reclaim(1);
	mod_timer(&g.txtimer, jiffies + 1);
	local_bh_enable();
	return 0;
}

static void k1_txtimer_fn(unsigned long data)
{
	struct net_device *d = g.lan;
	u32 now = (u32)jiffies, el = now - g.tx_last_j;
	int run, live, stopped = 0, used = 0;

	(void)data;
	g.tx_last_j = now;
	g.st.tx_timer++;
	if (!g.tx_on && !g.tx_drain)
		return;
	k1_tx_reclaim(0);
	run = k1_tx_running(d);
	live = run && netif_carrier_ok(d);
	if (run) {
		stopped = netif_queue_stopped(d);
		used = k1_tx_tail_used(d);
	}
	if (g.tx_on && used < 0) {
		k1_tx_off(K1_TXOFF_RING);
	} else if (g.tx_on &&
		   k1_tx_guard_step(&g.txg, live,
				    live && used > 0 &&
				    RD32((unsigned long)d + GETH_TX_HEAD) ==
				    RD32((unsigned long)d + GETH_TX_TAIL),
				    live ? RD32((unsigned long)d + GETH_TX_TAIL) : 0,
				    jiffies_to_msecs(el), K1_TX_GUARD_MS)) {
		g.st.tx_stallguard++;
		k1_tx_off(K1_TXOFF_GUARD);
	}
	if (g.tx_drain &&
	    (used < 0 ||
	     k1_tx_drained(run, run ? RD32((unsigned long)d + GETH_TX_HEAD) : 0,
			   g.tx_drain_head, used > 0, stopped))) {
		g.tx_drain = 0;
		k1_unpin(&g.tx_pin);
		return;
	}
	mod_timer(&g.txtimer, jiffies + ((live && k1_tx_need_reclaim(used > 0, stopped)) ? 1 : 4));
}

static int k1_tx_on(void)
{
	struct net_device *d = g.lan;
	int r;

	if (g.tx_on)
		return 0;
	if (!d || !d->netdev_ops)
		return -ENODEV;
	if ((unsigned long)d->netdev_ops->ndo_start_xmit != FP_GDM_ETH_START_XMIT_VA)
		return -ENODEV;
	if (RD32((unsigned long)d + GETH_TASKLET + 0x0cu) != FP_GDM_ETH_FINISH_XMIT_TASKLET_VA ||
	    RD32((unsigned long)d + GETH_TASKLET + 0x10u) != (u32)(unsigned long)d)
		return -ENODEV;
	if (!k1_tx_live(d))
		return -ENETDOWN;
	if (k1_tx_tail_used(d) < 0)
		return -ENODEV;
	g.tx_tasklet_fn = (void (*)(unsigned long))FP_GDM_ETH_FINISH_XMIT_TASKLET_VA;
	g.tx_site = (u32 *)(FP_GDM_ETH_START_XMIT_VA + GETH_IC_SITE_OFF);
	local_bh_disable();
	r = k1_patch_word(g.tx_site, GETH_IC_ORIG, GETH_IC_NOIRQ);
	if (!r) {
		k1_pin(&g.tx_pin);
		g.tx_on = 1;
		g.tx_drain = 0;
		memset(&g.txg, 0, sizeof(g.txg));
		g.tx_last_j = (u32)jiffies;
		mod_timer(&g.txtimer, jiffies + 1);
	}
	local_bh_enable();
	return r;
}

/* ---------- /proc/k1fp ---------- */

static const char *k1_port_name(u8 idx)
{
	if (idx == 1u)
		return "eth0";
	if (idx == 2u)
		return "lte0pdn2";
	return "other";
}

static const char *k1_stage_name(u8 stg)
{
	if (stg == K1_STG_BR_POST)
		return "br_post";
	if (stg == K1_STG_BR_LAST)
		return "br_last";
	if (stg == K1_STG_IP4_POST)
		return "ip4_post";
	return "unknown";
}

static void k1_show_diff(struct seq_file *m, u16 mask)
{
	static const struct {
		u16 bit;
		const char *name;
	} bits[] = {
		{ K1D_PORT,   "port" },
		{ K1D_SHORT,  "short" },
		{ K1D_PRIO,   "prio" },
		{ K1D_MARK,   "mark" },
		{ K1D_DMAC,   "dmac" },
		{ K1D_SMAC,   "smac" },
		{ K1D_ETYPE,  "etype" },
		{ K1D_L3TOS,  "l3tos" },
		{ K1D_L3LEN,  "l3len" },
		{ K1D_L3TTL,  "l3ttl" },
		{ K1D_L3CSUM, "l3csum" },
		{ K1D_L3ADDR, "l3addr" },
		{ K1D_L4PORT, "l4port" },
		{ K1D_L4HDR,  "l4hdr" },
	};
	unsigned int i;
	int first = 1;

	if (!mask) {
		seq_puts(m, "none");
		return;
	}
	for (i = 0; i < ARRAY_SIZE(bits); i++) {
		if (mask & bits[i].bit) {
			if (!first)
				seq_puts(m, ",");
			seq_puts(m, bits[i].name);
			first = 0;
		}
	}
}

static void k1_show_hex(struct seq_file *m, const u8 *buf, u8 len)
{
	unsigned int i;

	for (i = 0; i < len; i++)
		seq_printf(m, "%02x", buf[i]);
}

static void k1_show_diag(struct seq_file *m, u32 now)
{
	u32 total = g.diag.total;
	u32 count = total < K1_DIAG_RING ? total : K1_DIAG_RING;
	u32 start = total - count;
	u32 k;

	seq_printf(m, "diag: entries=%u total=%u\n", count, total);
	for (k = 0; k < count; k++) {
		const struct k1_diag_ent *e = &g.diag.e[(start + k) & (K1_DIAG_RING - 1u)];
		const char *in_name = e->dir == 0u ? "lte0pdn2" : "eth0";

		seq_printf(m, "diag[%u]: age_ms=%u t_ms=%u dir=%s stage=%s reason=%s in=%s exp=%s got=%s fam=%u proto=%u diff=",
			   k, jiffies_to_msecs(now - e->jiffies), jiffies_to_msecs(e->jiffies),
			   e->dir == 0u ? "dl" : "ul",
			   k1_stage_name(e->stage),
			   e->reason == K1S_WRONGPORT ? "wrongport" : "modified",
			   in_name, k1_port_name(e->exp_port), k1_port_name(e->got_port),
			   e->family, e->proto);
		k1_show_diff(m, e->diff_mask);
		seq_printf(m, " prio=%u->%u mark=%u->%u\n",
			   e->prio_pre, e->prio_post, e->mark_pre, e->mark_post);
		seq_printf(m, "  pre(%u)=", e->pre_len);
		k1_show_hex(m, e->pre, e->pre_len);
		seq_printf(m, " post(%u)=", e->post_len);
		k1_show_hex(m, e->post, e->post_len);
		seq_puts(m, "\n");
	}
}

static int k1_show(struct seq_file *m, void *v)
{
	u32 now = (u32)jiffies;
	struct net_device *d;
	int i, run, qctrl_present;
	u8 mac[6];
	static const char *const wn[K1W__N] = {
		"ok", "short", "mcast_mac", "src_mac", "etype", "v4hdr", "v4frag",
		"v4len", "v4addr", "v4csum", "v6hdr", "v6len", "v6addr",
		"l4proto", "tcpflags", "udpport"
	};
	static const char *const fn[K1F__N] = {
		"fast", "nolease", "stale", "expired", "mismatch", "sample"
	};

	(void)v;
	for (i = 0; i < 6; i++)
		mac[i] = RD8(VA_GDM_NET_IF + GDM_HOSTMAC_OFF + (u32)i);

	local_bh_disable();
	qctrl_present = k1_find_qctrl_hook() != NULL;
	d = g.lan;
	run = k1_tx_running(d);
	seq_printf(m, "%s\n", K1_VERSION);
	seq_printf(m, "mode=%d lan=%s lan_hooked=%d wan=%s wan_hooked=%d br=%s br_ports=%d ports_ok=%d\n",
		   g.mode, g.lan ? g.lan->name : "-", g.lan_hooked,
		   g.wan ? g.wan->name : "-", g.wan_hooked,
		   g.br ? g.br->name : "-", g.nports, g.ports_ok);
	seq_printf(m, "devices: dev_gone=%u reacq=%u\n", g.dev_gone, g.reacq);
	seq_printf(m, "require_grant=%d grant_left_ms=%u gate=%s v4=%d v6=%d lease_ms=%u sample_ms=%u\n",
		   g.require_grant,
		   (g.grant_set && k1_before(now, g.grant_until)) ?
		   jiffies_to_msecs(g.grant_until - now) : 0u,
		   k1_gate_open(now) ? "open" : "closed", g.v4, g.v6,
		   jiffies_to_msecs(g.lease_j), jiffies_to_msecs(g.sample_j));
	seq_printf(m, "qctrl: qctrl_present=%d qctrl_dl_calls=%u qctrl_dl_drop=%u qctrl_dl_stolen=%u qctrl_ul_stock=%u\n",
		   qctrl_present, g.st.qctrl_dl_calls, g.st.qctrl_dl_drop,
		   g.st.qctrl_dl_stolen, g.st.qctrl_ul_stock);
	seq_printf(m, "watchdog: wd_armed=%d wd_trips=%u wd_reason=%s wd_mod=%u wd_mismatch=%u wd_stall_ms=%u wd_ringfull_ms=%u wd_mod_win_ms=%u\n",
		   g.wd.armed, g.st.wd_trips, k1_wd_reason_name(g.wd_last_reason),
		   g.wd_cfg.mod_limit, g.wd_cfg.mismatch_limit,
		   g.wd_cfg.stall_ms, g.wd_cfg.ringfull_ms, g.wd_cfg.mod_win_ms);
	seq_printf(m, "safety: txirq=%d txdrain=%d dlbypass=0 pins=%d modref=%lu err_tx=%d\n",
		   g.tx_on, g.tx_drain, g.pins,
		   module_refcount(&__this_module), g.last_err_tx);
	seq_printf(m, "vendor: netifq_enabled=%u net_mode=%u host_mac_learned=%u host_mac=%02x:%02x:%02x:%02x:%02x:%02x external_dev_set=%d\n",
		   RD32(VA_GDM_NET_IF + GDM_NETIFQ_OFF), RD32(VA_GDM_NET_IF + GDM_NETMODE_OFF),
		   RD8(VA_GDM_NET_IF + GDM_HOSTMAC_LEARNED_OFF),
		   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
		   RD32(VA_GDM_NET_IF + GDM_EXTDEV_OFF) != 0);
	seq_printf(m, "brhook: external_dev_stop=%u list_nr=%u in_hold=%d held=%u holds=%u\n",
		   RD32(VA_GDM_NET_IF + GDM_EXTDEV_STOP_OFF), RD32(VA_BRHOOK + BRHOOK_NR_OFF),
		   g.in_hold, g.st.brhold, g.st.brhold_enter);
	seq_printf(m, "fast_dl=%u fast_ul=%u fast_dl_KiB=%u fast_ul_KiB=%u would_fast=%u gate_closed=%u xmit_err=%u\n",
		   g.st.fast[0], g.st.fast[1], g.st.fastbytes_k[0], g.st.fastbytes_k[1],
		   g.st.would_fast, g.st.gate_closed, g.st.xmit_err);
	seq_printf(m, "fam: f4dl=%u f4ul=%u f6dl=%u f6ul=%u fudpdl=%u fudpul=%u wf4dl=%u wf4ul=%u wf6dl=%u wf6ul=%u wfudpdl=%u wfudpul=%u\n",
		   g.st.f4[0], g.st.f4[1], g.st.f6[0], g.st.f6[1], g.st.fudp[0], g.st.fudp[1],
		   g.st.wf4[0], g.st.wf4[1], g.st.wf6[0], g.st.wf6[1], g.st.wfudp[0], g.st.wfudp[1]);
	seq_printf(m, "cand_stock=%u granted4=%u granted6=%u brok=%u modified=%u wrongport=%u noconfirm=%u revoked=%u local_deliv=%u local_alias=%u\n",
		   g.st.cand_stock, g.st.granted4, g.st.granted6, g.st.brok, g.st.modified,
		   g.st.wrongport, g.st.noconfirm, g.st.revoked,
		   g.st.local_deliv, g.st.local_alias);
	seq_puts(m, "lease:");
	for (i = 1; i < K1F__N; i++)
		seq_printf(m, " %s=%u", fn[i], g.st.fres[i]);
	seq_puts(m, "\nnotcand:");
	for (i = 1; i < K1W__N; i++)
		seq_printf(m, " %s=%u", wn[i], g.st.why[i]);
	seq_printf(m, " notport=%u badctx=%u shared=%u gso=%u nonlin=%u nolin=%u localmac=%u vendor=%u portstate=%u mtu=%u famoff=%u nested=%u ports=%u\n",
		   g.st.notport, g.st.badctx, g.st.shared, g.st.gso, g.st.nonlin, g.st.nolin,
		   g.st.localmac, g.st.vendor, g.st.portstate, g.st.mtu, g.st.famoff,
		   g.st.nested, g.st.ports);
	seq_printf(m, "tx: tx_reclaim=%u tx_timer=%u tx_off_user=%u tx_off_dev=%u tx_off_guard=%u tx_off_ring=%u tx_stallguard=%u tx_badring=%u ring_n=%u ring_head=%u ring_tail=%u ring_tail_used=%d queue_stopped=%d\n",
		   g.st.tx_reclaim, g.st.tx_timer, g.st.tx_off[K1_TXOFF_USER], g.st.tx_off[K1_TXOFF_DEV],
		   g.st.tx_off[K1_TXOFF_GUARD], g.st.tx_off[K1_TXOFF_RING], g.st.tx_stallguard,
		   g.st.tx_badring,
		   run ? RD32((unsigned long)d + GETH_TX_NDESC) : 0u,
		   run ? RD32((unsigned long)d + GETH_TX_HEAD) : 0u,
		   run ? RD32((unsigned long)d + GETH_TX_TAIL) : 0u,
		   run ? k1_tx_tail_used(d) : -2, run ? netif_queue_stopped(d) : -2);
	seq_printf(m, "table_inuse=%u evictions=%u hk_attach=%u epoch_bumps=%u epoch=%u\n",
		   tbl->inuse, tbl->evictions, g.st.hk_attach, g.st.epoch_bumps, g.epoch);
	k1_show_diag(m, now);
	local_bh_enable();
	return 0;
}

static int k1_open(struct inode *inode, struct file *file)
{
	(void)inode;
	return single_open(file, k1_show, NULL);
}

static int k1_parse_u32(const char *s, u32 *out)
{
	u32 v = 0;
	int n = 0;

	while (*s == ' ')
		s++;
	while (*s >= '0' && *s <= '9') {
		if (v > 429496728u)
			return -EINVAL;
		v = v * 10u + (u32)(*s - '0');
		s++;
		n++;
	}
	while (*s == ' ' || *s == '\n' || *s == '\r')
		s++;
	if (!n || *s)
		return -EINVAL;
	*out = v;
	return 0;
}

static void k1_set_mode(int new_mode)
{
	u32 tail = 0;

	local_bh_disable();
	if (new_mode != g.mode) {
		if (new_mode == K1_MODE_OFF) {
			g.mode = K1_MODE_OFF;
			g.wd.armed = 0;
			k1_epoch_bump();
		} else {
			g.mode = new_mode;
			k1_epoch_bump();
			if (new_mode >= K1_MODE_DL) {
				if (k1_tx_live(g.lan))
					tail = RD32((unsigned long)g.lan + GETH_TX_TAIL);
				k1_wd_arm(&g.wd, g.st.modified, g.st.wrongport,
					  g.st.fres[K1F_MISMATCH], tail);
				mod_timer(&g.wdtimer, jiffies + msecs_to_jiffies(K1_WD_PERIOD_MS));
			} else {
				g.wd.armed = 0;
			}
		}
	}
	local_bh_enable();
	if (new_mode < K1_MODE_DL)
		del_timer(&g.wdtimer);
}

static ssize_t k1_write(struct file *file, const char *ubuf, size_t len, loff_t *ppos)
{
	char buf[64];
	char *arg;
	u32 v;
	int r = 0;

	(void)file; (void)ppos;
	if (g.unloading)
		return -ENODEV;
	if (len == 0 || len >= sizeof(buf))
		return -EINVAL;
	if (titan_copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = 0;
	arg = strchr(buf, ' ');
	if (!arg) {
		if (!strcmp(buf, "flush\n") || !strcmp(buf, "flush")) {
			local_bh_disable();
			k1_flush(tbl);
			k1_epoch_bump();
			local_bh_enable();
			return (ssize_t)len;
		}
		if (!strcmp(buf, "zero\n") || !strcmp(buf, "zero")) {
			local_bh_disable();
			memset(&g.st, 0, sizeof(g.st));
			k1_diag_clear(&g.diag);
			g.wd_last_reason = K1_WD_NONE;
			if (g.wd.armed) {
				u32 tail = k1_tx_live(g.lan) ?
					RD32((unsigned long)g.lan + GETH_TX_TAIL) : 0u;
				k1_wd_arm(&g.wd, 0, 0, 0, tail);
			}
			local_bh_enable();
			return (ssize_t)len;
		}
		return -EINVAL;
	}
	*arg++ = 0;
	if (k1_parse_u32(arg, &v))
		return -EINVAL;

	if (!strcmp(buf, "mode") && v <= K1_MODE_BOTH) {
		k1_set_mode((int)v);
	} else if (!strcmp(buf, "grant") && v <= 60u) {
		u32 now;
		int was_open;
		local_bh_disable();
		now = (u32)jiffies;
		was_open = k1_gate_open(now);
		g.grant_until = now + v * HZ;
		g.grant_set = v > 0u;
		if (was_open != k1_gate_open(now))
			k1_epoch_bump();
		local_bh_enable();
	} else if (!strcmp(buf, "require_grant") && v <= 1u) {
		u32 now;
		int was_open;
		local_bh_disable();
		now = (u32)jiffies;
		was_open = k1_gate_open(now);
		g.require_grant = (int)v;
		if (was_open != k1_gate_open(now))
			k1_epoch_bump();
		local_bh_enable();
	} else if (!strcmp(buf, "v4") && v <= 1u) {
		local_bh_disable();
		g.v4 = (int)v;
		local_bh_enable();
	} else if (!strcmp(buf, "v6") && v <= 1u) {
		local_bh_disable();
		g.v6 = (int)v;
		local_bh_enable();
	} else if (!strcmp(buf, "lease_ms") && v >= 10u && v <= 1000u) {
		u32 lj = (u32)msecs_to_jiffies(v);
		local_bh_disable();
		if (lj > g.sample_j)
			g.lease_j = lj;
		else
			r = -EINVAL;
		local_bh_enable();
	} else if (!strcmp(buf, "sample_ms") && v >= 2u && v <= K1_SAMPLE_MS_MAX) {
		u32 sj = (u32)msecs_to_jiffies(v);
		local_bh_disable();
		if (sj < g.lease_j)
			g.sample_j = sj;
		else
			r = -EINVAL;
		local_bh_enable();
	} else if (!strcmp(buf, "wd_mod") && v <= 10000u) {
		local_bh_disable();
		g.wd_cfg.mod_limit = v;
		local_bh_enable();
	} else if (!strcmp(buf, "wd_mod_win_ms") && v >= 1000u && v <= 60000u) {
		local_bh_disable();
		g.wd_cfg.mod_win_ms = v;
		if (g.wd.armed) {
			g.wd.prev_mod_d = 0;
			g.wd.prev_wrg_d = 0;
			g.wd.cur_mod_base = g.st.modified;
			g.wd.cur_wrg_base = g.st.wrongport;
			g.wd.mod_elapsed_ms = 0;
		}
		local_bh_enable();
	} else if (!strcmp(buf, "wd_mismatch") && v <= 10000u) {
		local_bh_disable();
		g.wd_cfg.mismatch_limit = v;
		local_bh_enable();
	} else if (!strcmp(buf, "wd_stall_ms") && v >= 100u && v <= 5000u) {
		local_bh_disable();
		g.wd_cfg.stall_ms = v;
		local_bh_enable();
	} else if (!strcmp(buf, "wd_ringfull_ms") && v >= 100u && v <= 5000u) {
		local_bh_disable();
		g.wd_cfg.ringfull_ms = v;
		local_bh_enable();
	} else if (!strcmp(buf, "txirq") && v <= 1u) {
		int i;
		rtnl_lock();
		r = v ? k1_tx_on() : k1_tx_off(K1_TXOFF_USER);
		rtnl_unlock();
		g.last_err_tx = r;
		for (i = 0; !v && !r && g.tx_drain && i < 400; i++)
			msleep(5);
	} else if (!strcmp(buf, "dlbypass")) {
		r = -EOPNOTSUPP;
	} else {
		return -EINVAL;
	}
	return r ? r : (ssize_t)len;
}

static const struct file_operations k1_fops = {
	.owner = &__this_module,
	.open = k1_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = k1_write,
};

/* ---------- Module init / exit ---------- */

int init_module(void)
{
	struct net_device *l, *w, *bd;
	void *pl = NULL, *pw = NULL;
	int r;

	r = k1_fp_core();
	if (r) {
		printk(KERN_ERR "k1fp: kernel fingerprint check failed (%d)\n", r);
		return r;
	}
	tbl = (struct k1_tbl *)vmalloc(sizeof(*tbl));
	if (!tbl)
		return -ENOMEM;
	k1_flush(tbl);

	memset(&g, 0, sizeof(g));
	g.mode = K1_MODE_OFF;
	g.require_grant = 1;
	g.v4 = 1;
	g.v6 = 1;
	g.lease_j = (u32)msecs_to_jiffies(60);
	g.sample_j = (u32)msecs_to_jiffies(20);
	g.seed = (u32)jiffies * 2654435761u;
	g.orig_rx = (rx_handler_func_t *)FP_BR_HANDLE_FRAME_HOOK_VA;
	g.br_push_xmit = (int (*)(struct sk_buff *))FP_BR_DEV_QUEUE_PUSH_XMIT_VA;
	g.wd_cfg.mod_limit = 20u;
	g.wd_cfg.mod_win_ms = K1_WD_MOD_WIN_MS;
	g.wd_cfg.mismatch_limit = 64u;
	g.wd_cfg.stall_ms = 500u;
	g.wd_cfg.ringfull_ms = 500u;
	k1_setup_timer(&g.txtimer, k1_txtimer_fn, 0);
	k1_setup_timer(&g.wdtimer, k1_wdtimer_fn, 0);
	k1_init_delayed_work(&hk_work, k1_hk);

	l = dev_get_by_name(&init_net, "eth0");
	w = dev_get_by_name(&init_net, "lte0pdn2");
	r = -ENODEV;
	if (!l)
		printk(KERN_ERR "k1fp: no device eth0\n");
	if (!w)
		printk(KERN_ERR "k1fp: no device lte0pdn2\n");
	if (!l || !w)
		goto err_dev;

	rtnl_lock();
	bd = NULL;
	pl = k1_stock_port(l, 0);
	if (pl)
		pw = k1_stock_port(w, 0);
	if (pl && pw)
		bd = k1_port_bridge(pl, pw, 0);
	if (!bd) {
		rtnl_unlock();
		printk(KERN_ERR "k1fp: eth0 and lte0pdn2 are not ports of one bridge\n");
		goto err_dev;
	}
	g.br = bd;
	dev_hold(g.br);
	g.lan = l;
	g.wan = w;
	rtnl_unlock();

	r = nf_register_hooks(k1_ops, ARRAY_SIZE(k1_ops));
	if (r)
		goto err_br;
	r = register_netdevice_notifier(&k1_nb);
	if (r)
		goto err_nf;
	k1_proc = proc_create_data("k1fp", 0600, NULL, &k1_fops, NULL);
	if (!k1_proc) {
		r = -ENOMEM;
		goto err_nb;
	}

	rtnl_lock();
	g.lan_hooked = k1_try_hook(g.lan);
	g.wan_hooked = k1_try_hook(g.wan);
	k1_ports_update();
	rtnl_unlock();

	k1_schedule_delayed_work(&hk_work, HZ);
	printk(KERN_INFO "k1fp: loaded (%s), br=%s, mode=0 (off)\n", K1_VERSION, g.br->name);
	return 0;

err_nb:
	g.unloading = 1;
	unregister_netdevice_notifier(&k1_nb);
err_nf:
	nf_unregister_hooks(k1_ops, ARRAY_SIZE(k1_ops));
err_br:
	dev_put(g.br);
	g.lan = g.wan = g.br = NULL;
err_dev:
	if (l)
		dev_put(l);
	if (w)
		dev_put(w);
	vfree(tbl);
	return r;
}

void cleanup_module(void)
{
	int i;

	local_bh_disable();
	g.unloading = 1;
	g.mode = K1_MODE_OFF;
	g.wd.armed = 0;
	local_bh_enable();

	/* Remove /proc/k1fp first so no new writes can enter while tearing down */
	remove_proc_entry("k1fp", NULL);

	if (g.tx_on || g.tx_drain || g.pins) {
		printk(KERN_CRIT "k1fp: exit with live txirq (on=%d drain=%d pins=%d)\n",
		       g.tx_on, g.tx_drain, g.pins);
		rtnl_lock();
		if (g.tx_on && k1_tx_off(K1_TXOFF_USER))
			printk(KERN_CRIT "k1fp: could not restore gdm_eth IC bit\n");
		rtnl_unlock();
		for (i = 0; g.tx_drain && i < 400; i++)
			msleep(5);
	}

	cancel_delayed_work_sync(&hk_work);
	del_timer(&g.wdtimer);
	del_timer(&g.txtimer);

	rtnl_lock();
	k1_unhook(g.lan);
	k1_unhook(g.wan);
	rtnl_unlock();
	synchronize_net();

	nf_unregister_hooks(k1_ops, ARRAY_SIZE(k1_ops));
	unregister_netdevice_notifier(&k1_nb);

	if (g.lan)
		dev_put(g.lan);
	if (g.wan)
		dev_put(g.wan);
	if (g.br)
		dev_put(g.br);
	vfree(tbl);
	printk(KERN_INFO "k1fp: unloaded\n");
}
