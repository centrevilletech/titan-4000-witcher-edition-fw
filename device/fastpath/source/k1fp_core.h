/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright 2026 Centreville Tech, LLC. Kernel module for Titan 4000 Witcher Edition; see device/fastpath/README.md. */
/*
 * k1fp_core.h - Portable decision, classification, lease, watchdog, TX-ring,
 * and SHA-256 fingerprint logic for titan_k1fp 2.0.
 *
 * No kernel headers here. The includer must provide u8/u16/u32/u64/s32 and
 * memcmp/memcpy/memset. The same header compiles into the ARMv7 kernel module
 * and into the userspace test suite (device/fastpath/test/test_k1fp.c).
 */
#ifndef K1FP_CORE_H
#define K1FP_CORE_H

#define K1_TBL_BITS       10
#define K1_TBL_SIZE       (1u << K1_TBL_BITS)
#define K1_ETH_HLEN       14u
#define K1_HDRMAX         96u
#define K1_SAMPLE_MS_MAX  50u

/* Operating modes (0 = off at load) */
enum k1_mode {
	K1_MODE_OFF     = 0, /* immediate pass-through, no parsing or leases */
	K1_MODE_OBSERVE = 1, /* classify, prove, count would_fast; forward via stock */
	K1_MODE_DL      = 2, /* fast-path downlink (lte0pdn2 -> eth0) only */
	K1_MODE_BOTH    = 3, /* fast-path both directions (UL TCP yields to qctrl if loaded) */
};

/* Per-packet mode policy decision */
enum k1_dir_policy {
	K1P_OFF = 0,         /* mode 0 or direction not handled: skip fast path and proof */
	K1P_OBSERVE,         /* mode 1: run proof and count would_fast, never fast-path */
	K1P_FAST,            /* mode 2/3: eligible for fast path once lease + gate hold */
	K1P_QCTRL_STOCK,     /* mode 3 UL TCP while titan_qctrl is loaded: stay on stock */
};

static inline int k1_mode_dir_policy(int mode, int dir, u8 proto, int qctrl_active)
{
	if (mode == K1_MODE_OFF)
		return K1P_OFF;
	if (mode == K1_MODE_DL)
		return dir == 0 ? K1P_FAST : K1P_OFF;
	/* When titan_qctrl is loaded on NF_BR_FORWARD, UL TCP always stays on stock
	 * (in both observe mode and mode 3) so RWND clamping and ACK thinning are
	 * never bypassed and never counted as unexpected header modifications. */
	if (dir == 1 && proto == 6 && qctrl_active)
		return K1P_QCTRL_STOCK;
	if (mode == K1_MODE_OBSERVE)
		return K1P_OBSERVE;
	return K1P_FAST;
}

/* Why a packet is not a candidate (index into stats) */
enum k1_why {
	K1W_OK = 0,
	K1W_SHORT,       /* linear data too short for headers */
	K1W_MCAST_MAC,   /* group destination MAC (multicast/broadcast) */
	K1W_SRC_MAC,     /* invalid source MAC (multicast or all-zero) */
	K1W_ETYPE,       /* not IPv4/IPv6 (ARP, VLAN 802.1Q/QinQ, PPPoE, etc.) */
	K1W_V4HDR,       /* version/ihl/options or TTL == 0 */
	K1W_V4FRAG,      /* IPv4 fragment (MF or offset != 0) */
	K1W_V4LEN,       /* tot_len inconsistent with skb or L4 header */
	K1W_V4ADDR,      /* IPv4 multicast, broadcast, loopback, or unspecified */
	K1W_V4CSUM,      /* bad IPv4 header checksum */
	K1W_V6HDR,       /* version != 6, hop_limit == 0 */
	K1W_V6LEN,       /* payload_len inconsistent with skb or L4 header */
	K1W_V6ADDR,      /* IPv6 multicast, unspecified, loopback, or link-local fe80::/10 */
	K1W_L4PROTO,     /* not TCP/UDP (ICMP, ICMPv6 RS/RA/NS/NA/MLD, v6 ext headers) */
	K1W_TCPFLAGS,    /* SYN/FIN/RST or bad data offset (< 5) */
	K1W_UDPPORT,     /* DHCPv4 (67/68) or DHCPv6 (546/547) */
	K1W__N
};

struct k1_key {
	u32 w[10]; /* [0..3] saddr, [4..7] daddr, [8] ports, [9] proto|fam<<8|out<<16 */
};

struct k1_pkt {
	struct k1_key key;
	u8  macs[12];  /* dst MAC, src MAC */
	u8  dscp;      /* IPv4 TOS or IPv6 traffic class, ECN bits cleared (K1R F14) */
	u8  family;    /* 4 or 6 */
	u8  proto;     /* 6 (TCP) or 17 (UDP) */
	u8  tcpflags;
	u16 l3len;     /* IPv4 tot_len, or 40 + IPv6 payload_len */
	u16 hdrlen;    /* bytes from Ethernet header through base L4 header */
	u32 mark;      /* skb->mark on arrival (K1R F9; filled by caller) */
	u32 prio;      /* skb->priority on arrival */
};

struct k1_flow {
	struct k1_key key;
	u8  macs[12];
	u8  dscp;
	u8  valid;
	u16 pad;
	u32 mark;
	u32 prio;
	u32 epoch;
	u32 lease_exp;
	u32 sample_at;
	u32 hits;
};

struct k1_tbl {
	struct k1_flow f[K1_TBL_SIZE];
	u32 inuse;
	u32 evictions;
};

static inline int k1_before(u32 a, u32 b) { return (s32)(a - b) < 0; }
static inline u16 k1_be16(const u8 *p) { return (u16)(((u16)p[0] << 8) | p[1]); }
static inline u32 k1_be32(const u8 *p)
{
	return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}
static inline u32 k1_ld32(const u8 *p)
{
	u32 v;
	memcpy(&v, p, 4);
	return v;
}

/* RFC 1071 IPv4 header checksum check (20-byte header). Returns 1 if valid. */
static inline int k1_v4csum_ok(const u8 *iph)
{
	u32 sum = 0;
	int i;

	for (i = 0; i < 20; i += 2)
		sum += k1_be16(iph + i);
	while (sum >> 16)
		sum = (sum & 0xffffu) + (sum >> 16);
	return sum == 0xffffu;
}

static inline int k1_v4addr_special(const u8 *a)
{
	u8 first = a[0];

	/* 0.0.0.0/8 (unspecified), 127.0.0.0/8 (loopback), 224.0.0.0/4 (multicast), 240.0.0.0/4 (reserved/bcast) */
	if (first == 0u || first == 127u || first >= 224u)
		return 1;
	return 0;
}

static inline int k1_v6addr_special(const u8 *a)
{
	u32 hi0, hi1, lo0, lo1;

	/* Multicast ff00::/8 */
	if (a[0] == 0xffu)
		return 1;
	/* Link-local fe80::/10 (ND, DHCPv6, local management) */
	if (a[0] == 0xfeu && (a[1] & 0xc0u) == 0x80u)
		return 1;
	/* Unspecified :: or loopback ::1 */
	hi0 = k1_be32(a);
	hi1 = k1_be32(a + 4);
	lo0 = k1_be32(a + 8);
	lo1 = k1_be32(a + 12);
	if (hi0 == 0u && hi1 == 0u && lo0 == 0u && (lo1 == 0u || lo1 == 1u))
		return 1;
	return 0;
}

/*
 * Parse a received frame. eth = Ethernet header, lin = linear bytes from eth,
 * l3skb = skb->len at L3 (bytes after Ethernet header), outidx = 1 for LAN
 * egress, 2 for WAN egress. Returns K1W_OK for a fast-path candidate.
 */
static inline int k1_parse(const u8 *eth, u32 lin, u32 l3skb, u32 outidx,
			   struct k1_pkt *p)
{
	const u8 *l3, *l4;
	u16 etype;
	u32 l4min;

	if (lin < K1_ETH_HLEN + 20u)
		return K1W_SHORT;
	if (eth[0] & 1u)
		return K1W_MCAST_MAC;
	if ((eth[6] & 1u) ||
	    (eth[6] | eth[7] | eth[8] | eth[9] | eth[10] | eth[11]) == 0u)
		return K1W_SRC_MAC;

	memset(&p->key, 0, sizeof(p->key));
	memcpy(p->macs, eth, 12);
	etype = k1_be16(eth + 12);
	l3 = eth + K1_ETH_HLEN;

	if (etype == 0x0800u) {
		u16 tot, frag;

		if (l3[0] != 0x45u || l3[8] == 0u)
			return K1W_V4HDR;
		frag = k1_be16(l3 + 6);
		if (frag & 0x3fffu)
			return K1W_V4FRAG;
		tot = k1_be16(l3 + 2);
		if (tot > l3skb || tot < 20u + 8u)
			return K1W_V4LEN;
		if (k1_v4addr_special(l3 + 12) || k1_v4addr_special(l3 + 16))
			return K1W_V4ADDR;
		p->family = 4;
		p->proto = l3[9];
		p->dscp = l3[1] & 0xfcu;
		p->l3len = tot;
		p->key.w[0] = k1_ld32(l3 + 12);
		p->key.w[4] = k1_ld32(l3 + 16);
		l4 = l3 + 20;
	} else if (etype == 0x86ddu) {
		u16 plen;

		if (lin < K1_ETH_HLEN + 40u + 8u)
			return K1W_SHORT;
		if ((l3[0] >> 4) != 6u || l3[7] == 0u)
			return K1W_V6HDR;
		plen = k1_be16(l3 + 4);
		if ((u32)plen + 40u > l3skb || plen < 8u)
			return K1W_V6LEN;
		if (k1_v6addr_special(l3 + 8) || k1_v6addr_special(l3 + 24))
			return K1W_V6ADDR;
		p->family = 6;
		p->proto = l3[6]; /* next header: no extension headers allowed */
		p->dscp = (u8)((((l3[0] & 0x0fu) << 4) | (l3[1] >> 4)) & 0xfcu);
		p->l3len = (u16)(plen + 40u);
		memcpy(&p->key.w[0], l3 + 8, 16);
		memcpy(&p->key.w[4], l3 + 24, 16);
		l4 = l3 + 40;
	} else {
		return K1W_ETYPE;
	}

	if (p->proto == 6u)
		l4min = 20u;
	else if (p->proto == 17u)
		l4min = 8u;
	else
		return K1W_L4PROTO;

	if ((u32)(l4 - eth) + l4min > lin)
		return K1W_SHORT;
	if ((u32)(l4 - l3) + l4min > p->l3len)
		return p->family == 4 ? K1W_V4LEN : K1W_V6LEN;

	if (p->proto == 6u) {
		u8 doff = l4[12] >> 4;

		p->tcpflags = l4[13];
		if (doff < 5u || (u32)(l4 - l3) + (u32)doff * 4u > p->l3len)
			return K1W_TCPFLAGS;
		if (p->tcpflags & 0x07u) /* FIN, SYN, RST: stock path (conntrack, MSS clamp, qctrl) */
			return K1W_TCPFLAGS;
	} else {
		u16 sp = k1_be16(l4), dp = k1_be16(l4 + 2);

		p->tcpflags = 0;
		if (sp == 67u || sp == 68u || dp == 67u || dp == 68u ||
		    sp == 546u || sp == 547u || dp == 546u || dp == 547u)
			return K1W_UDPPORT;
	}

	if (p->family == 4 && !k1_v4csum_ok(l3))
		return K1W_V4CSUM;

	p->key.w[8] = k1_ld32(l4); /* sport, dport in wire order */
	p->key.w[9] = (u32)p->proto | ((u32)p->family << 8) | (outidx << 16);
	p->hdrlen = (u16)((u32)(l4 - eth) + l4min);
	p->mark = 0;
	p->prio = 0;
	return K1W_OK;
}

static inline u32 k1_rol(u32 x, int r) { return (x << r) | (x >> (32 - r)); }

static inline u32 k1_hash(const struct k1_key *k, u32 seed)
{
	u32 a = 0xdeadbeefu + seed, b = a, c = a;
	int i;

	for (i = 0; i < 9; i += 3) {
		a += k->w[i];
		b += k->w[i + 1];
		c += k->w[i + 2];
		a -= c; a ^= k1_rol(c, 4);  c += b;
		b -= a; b ^= k1_rol(a, 6);  a += c;
		c -= b; c ^= k1_rol(b, 8);  b += a;
		a -= c; a ^= k1_rol(c, 16); c += b;
		b -= a; b ^= k1_rol(a, 19); a += c;
		c -= b; c ^= k1_rol(b, 4);  b += a;
	}
	a += k->w[9];
	c ^= b; c -= k1_rol(b, 14);
	a ^= c; a -= k1_rol(c, 11);
	b ^= a; b -= k1_rol(a, 25);
	c ^= b; c -= k1_rol(b, 16);
	a ^= c; a -= k1_rol(c, 4);
	b ^= a; b -= k1_rol(a, 14);
	c ^= b; c -= k1_rol(b, 24);
	return c;
}

static inline int k1_key_eq(const struct k1_key *a, const struct k1_key *b)
{
	return memcmp(a, b, sizeof(*a)) == 0;
}

static inline struct k1_flow *k1_lookup(struct k1_tbl *t, const struct k1_key *k, u32 seed)
{
	u32 i = k1_hash(k, seed) & (K1_TBL_SIZE - 1u);

	if (t->f[i].valid && k1_key_eq(&t->f[i].key, k))
		return &t->f[i];
	i ^= 1u;
	if (t->f[i].valid && k1_key_eq(&t->f[i].key, k))
		return &t->f[i];
	return 0;
}

enum k1_fast {
	K1F_FAST = 0,
	K1F_NOLEASE,
	K1F_STALE,     /* epoch changed (device/bridge event) */
	K1F_EXPIRED,
	K1F_MISMATCH,  /* MACs, DSCP, mark or priority differ from proven packet */
	K1F_SAMPLE,    /* periodic stock-path re-proof sample */
	K1F__N
};

static inline int k1_fast_check(struct k1_tbl *t, const struct k1_pkt *p, u32 now,
				u32 epoch, u32 sample_j, u32 seed, struct k1_flow **out)
{
	struct k1_flow *f = k1_lookup(t, &p->key, seed);

	*out = f;
	if (!f)
		return K1F_NOLEASE;
	if (f->epoch != epoch)
		return K1F_STALE;
	if (!k1_before(now, f->lease_exp))
		return K1F_EXPIRED;
	if (memcmp(f->macs, p->macs, 12) != 0 || f->dscp != p->dscp ||
	    f->mark != p->mark || f->prio != p->prio)
		return K1F_MISMATCH;
	if (!k1_before(now, f->sample_at)) {
		f->sample_at = now + sample_j;
		return K1F_SAMPLE;
	}
	f->hits++;
	return K1F_FAST;
}

static inline void k1_grant(struct k1_tbl *t, const struct k1_pkt *p, u32 now, u32 epoch,
			    u32 lease_j, u32 sample_j, u32 seed)
{
	u32 i = k1_hash(&p->key, seed) & (K1_TBL_SIZE - 1u);
	struct k1_flow *f;

	if (t->f[i].valid && k1_key_eq(&t->f[i].key, &p->key)) {
		f = &t->f[i];
	} else if (t->f[i ^ 1u].valid && k1_key_eq(&t->f[i ^ 1u].key, &p->key)) {
		f = &t->f[i ^ 1u];
	} else {
		struct k1_flow *a = &t->f[i], *b = &t->f[i ^ 1u];

		if (!a->valid)
			f = a;
		else if (!b->valid)
			f = b;
		else
			f = k1_before(a->lease_exp, b->lease_exp) ? a : b;
		if (f->valid)
			t->evictions++;
		else
			t->inuse++;
		f->key = p->key;
		f->valid = 1;
		f->hits = 0;
	}
	memcpy(f->macs, p->macs, 12);
	f->dscp = p->dscp;
	f->mark = p->mark;
	f->prio = p->prio;
	f->epoch = epoch;
	f->lease_exp = now + lease_j;
	f->sample_at = now + sample_j;
}

static inline int k1_revoke(struct k1_tbl *t, const struct k1_key *k, u32 now, u32 seed)
{
	struct k1_flow *f = k1_lookup(t, k, seed);

	if (!f)
		return 0;
	f->lease_exp = now;
	return 1;
}

static inline void k1_flush(struct k1_tbl *t)
{
	memset(t, 0, sizeof(*t));
}

/* Pending stock-path proof */
struct k1_pend {
	const void *skb;
	u32 outidx;
	struct k1_pkt pkt;
	u8  hdr[K1_HDRMAX];
	u8  brok;
	u8  granted;
	u8  had_lease;
	u8  active;
};

enum k1_stage_res {
	K1S_IGNORED = 0,
	K1S_BROK,
	K1S_GRANTED,
	K1S_MODIFIED,
	K1S_WRONGPORT
};

static inline void k1_pend_begin(struct k1_pend *pd, const void *skb, u32 outidx,
				 const struct k1_pkt *p, const u8 *eth, int had_lease)
{
	pd->skb = skb;
	pd->outidx = outidx;
	pd->pkt = *p;
	memcpy(pd->hdr, eth, p->hdrlen);
	pd->brok = 0;
	pd->granted = 0;
	pd->had_lease = (u8)!!had_lease;
	pd->active = 1;
}

static inline int k1_pend_same(const struct k1_pend *pd, const u8 *eth, u32 lin,
			       u32 prio, u32 mark)
{
	if (lin < pd->pkt.hdrlen || prio != pd->pkt.prio || mark != pd->pkt.mark)
		return 0;
	if (memcmp(eth, pd->hdr, pd->pkt.hdrlen) == 0)
		return 1;
	/* Allow valid ECT(0)/ECT(1) -> CE ECN marking on downlink (e.g. titan_qctrl mode 4)
	 * while still rejecting any DSCP, TTL, MAC, IP, port, or TCP change. */
	if (pd->outidx == 1u && memcmp(eth, pd->hdr, K1_ETH_HLEN) == 0) {
		const u8 *o = pd->hdr + K1_ETH_HLEN;
		const u8 *n = eth + K1_ETH_HLEN;

		if (pd->pkt.family == 4u && pd->pkt.hdrlen >= K1_ETH_HLEN + 20u) {
			u8 oecn = o[1] & 0x03u, necn = n[1] & 0x03u;
			if ((oecn == 1u || oecn == 2u) && necn == 3u &&
			    o[0] == n[0] && (o[1] & 0xfcu) == (n[1] & 0xfcu) &&
			    memcmp(o + 2, n + 2, 8) == 0 &&
			    memcmp(o + 12, n + 12, pd->pkt.hdrlen - (K1_ETH_HLEN + 12u)) == 0 &&
			    k1_v4csum_ok(n))
				return 1;
		} else if (pd->pkt.family == 6u && pd->pkt.hdrlen >= K1_ETH_HLEN + 40u) {
			u8 oecn = (o[1] >> 4) & 0x03u, necn = (n[1] >> 4) & 0x03u;
			if ((oecn == 1u || oecn == 2u) && necn == 3u &&
			    o[0] == n[0] && (o[1] & 0xcfu) == (n[1] & 0xcfu) &&
			    memcmp(o + 2, n + 2, pd->pkt.hdrlen - (K1_ETH_HLEN + 2u)) == 0)
				return 1;
		}
	}
	return 0;
}

static inline int k1_stage_br(struct k1_pend *pd, struct k1_tbl *t, const void *skb,
			      u32 outidx, const u8 *eth, u32 lin, u32 prio, u32 mark,
			      u32 now, u32 epoch, u32 lease_j, u32 sample_j, u32 seed)
{
	(void)t; (void)now; (void)epoch; (void)lease_j; (void)sample_j; (void)seed;
	if (!pd->active || skb != pd->skb)
		return K1S_IGNORED;
	if (outidx != pd->outidx)
		return K1S_WRONGPORT;
	if (!k1_pend_same(pd, eth, lin, prio, mark))
		return K1S_MODIFIED;
	pd->brok = 1;
	return K1S_BROK;
}

static inline int k1_stage_br_last(struct k1_pend *pd, struct k1_tbl *t, const void *skb,
				   u32 outidx, const u8 *eth, u32 lin, u32 prio, u32 mark,
				   u32 now, u32 epoch, u32 lease_j, u32 sample_j, u32 seed)
{
	if (!pd->active || skb != pd->skb || pd->pkt.family != 6 || !pd->brok)
		return K1S_IGNORED;
	if (outidx != pd->outidx)
		return K1S_WRONGPORT;
	if (!k1_pend_same(pd, eth, lin, prio, mark))
		return K1S_MODIFIED;
	k1_grant(t, &pd->pkt, now, epoch, lease_j, sample_j, seed);
	pd->granted = 1;
	return K1S_GRANTED;
}

static inline int k1_stage_ip4(struct k1_pend *pd, struct k1_tbl *t, const void *skb,
			       u32 outidx, const u8 *eth, u32 lin, u32 prio, u32 mark,
			       u32 now, u32 epoch, u32 lease_j, u32 sample_j, u32 seed)
{
	if (!pd->active || skb != pd->skb || !pd->brok || pd->pkt.family != 4)
		return K1S_IGNORED;
	if (outidx != pd->outidx)
		return K1S_WRONGPORT;
	if (!k1_pend_same(pd, eth, lin, prio, mark))
		return K1S_MODIFIED;
	k1_grant(t, &pd->pkt, now, epoch, lease_j, sample_j, seed);
	pd->granted = 1;
	return K1S_GRANTED;
}

static inline int k1_pend_end(struct k1_pend *pd, struct k1_tbl *t, u32 now, u32 seed)
{
	int r = 0;

	if (!pd->active)
		return 0;
	if (!pd->granted && pd->had_lease)
		r = k1_revoke(t, &pd->pkt.key, now, seed);
	pd->active = 0;
	pd->skb = 0;
	return r;
}

/* Vendor bridge-input hold state machine */
enum k1_hold { K1H_NONE = 0, K1H_HELD, K1H_ENTER };

static inline int k1_hold_step(u32 stopped, u32 list_nr, u8 *in_hold)
{
	if (stopped || list_nr) {
		if (*in_hold)
			return K1H_HELD;
		*in_hold = 1;
		return K1H_ENTER;
	}
	if (*in_hold)
		*in_hold = 0;
	return K1H_NONE;
}

/* eth0 TX ring descriptor helpers (gdm_eth) */
#define K1_TXD_OWN 0x80000000u
#define K1_TXD_TER 0x02000000u

static inline int k1_txd_used(u32 d0, u32 d1)
{
	return (d0 & K1_TXD_OWN) || (d1 & ~K1_TXD_TER);
}

static inline int k1_tx_need_reclaim(int tail_used, int queue_stopped)
{
	return tail_used || queue_stopped;
}

static inline int k1_tx_drained(int running, u32 head, u32 drain_head, int tail_used,
				int queue_stopped)
{
	if (!running)
		return 1;
	if (head != drain_head)
		return 1;
	return !tail_used && !queue_stopped;
}

struct k1_txguard {
	u32 last_tail;
	u32 stuck_ms;
};

static inline int k1_tx_guard_step(struct k1_txguard *gd, int live, int ring_full, u32 tail,
				   u32 elapsed_ms, u32 limit_ms)
{
	if (!live || !ring_full || tail != gd->last_tail) {
		gd->last_tail = tail;
		gd->stuck_ms = 0;
		return 0;
	}
	gd->stuck_ms += elapsed_ms;
	return gd->stuck_ms >= limit_ms;
}

/*
 * Watchdog (k1fp 2.0): drops mode -> 0 on any anomaly while active (mode 2/3)
 * without relying on the kernel log.
 */
enum k1_wd_reason {
	K1_WD_NONE = 0,
	K1_WD_MODIFIED,
	K1_WD_WRONGPORT,
	K1_WD_MISMATCH,
	K1_WD_RINGFULL,
	K1_WD_TXSTALL,
	K1_WD_BADRING,
	K1_WD_DEVGONE,
};

static inline const char *k1_wd_reason_name(int r)
{
	switch (r) {
	case K1_WD_NONE:      return "none";
	case K1_WD_MODIFIED:  return "modified";
	case K1_WD_WRONGPORT: return "wrongport";
	case K1_WD_MISMATCH:  return "mismatch";
	case K1_WD_RINGFULL:  return "ring_full";
	case K1_WD_TXSTALL:   return "tx_stall";
	case K1_WD_BADRING:   return "bad_ring";
	case K1_WD_DEVGONE:   return "dev_gone";
	default:              return "unknown";
	}
}

struct k1_wd_cfg {
	u32 mod_limit;       /* modified + wrongport delta in window before trip (0 = off) */
	u32 mismatch_limit;  /* lease mismatch delta in 1 s window before trip (0 = off) */
	u32 stall_ms;        /* full ring or stopped queue with frozen tail before trip */
	u32 ringfull_ms;     /* persistent full ring (even if crawling) before trip */
};

struct k1_wd_state {
	u32 base_modified;
	u32 base_wrongport;
	u32 win_mismatch_base;
	u32 win_elapsed_ms;
	u32 last_tail;
	u32 stall_ms;
	u32 ringfull_ms;
	int armed;
};

static inline void k1_wd_arm(struct k1_wd_state *w, u32 cur_modified, u32 cur_wrongport,
			     u32 cur_mismatch, u32 cur_tail)
{
	w->base_modified = cur_modified;
	w->base_wrongport = cur_wrongport;
	w->win_mismatch_base = cur_mismatch;
	w->win_elapsed_ms = 0;
	w->last_tail = cur_tail;
	w->stall_ms = 0;
	w->ringfull_ms = 0;
	w->armed = 1;
}

static inline int k1_wd_tick(struct k1_wd_state *w, const struct k1_wd_cfg *cfg,
			     int active_mode, int eth_live, int bad_ring,
			     int ring_full, int queue_stopped, u32 tail,
			     u32 cur_modified, u32 cur_wrongport, u32 cur_mismatch,
			     u32 elapsed_ms)
{
	u32 dmod, dwrg, dmis;

	if (!active_mode || !w->armed)
		return K1_WD_NONE;

	if (eth_live && bad_ring)
		return K1_WD_BADRING;

	if (cfg->mod_limit) {
		dmod = cur_modified - w->base_modified;
		dwrg = cur_wrongport - w->base_wrongport;
		if (dmod + dwrg >= cfg->mod_limit)
			return dwrg > dmod ? K1_WD_WRONGPORT : K1_WD_MODIFIED;
	}

	if (cfg->mismatch_limit) {
		dmis = cur_mismatch - w->win_mismatch_base;
		if (dmis >= cfg->mismatch_limit)
			return K1_WD_MISMATCH;
		w->win_elapsed_ms += elapsed_ms;
		if (w->win_elapsed_ms >= 1000u) {
			w->win_elapsed_ms = 0;
			w->win_mismatch_base = cur_mismatch;
		}
	}

	if (eth_live) {
		if ((ring_full || queue_stopped) && tail == w->last_tail) {
			w->stall_ms += elapsed_ms;
			if (cfg->stall_ms && w->stall_ms >= cfg->stall_ms)
				return K1_WD_TXSTALL;
		} else {
			w->stall_ms = 0;
			w->last_tail = tail;
		}

		if (ring_full) {
			w->ringfull_ms += elapsed_ms;
			if (cfg->ringfull_ms && w->ringfull_ms >= cfg->ringfull_ms)
				return K1_WD_RINGFULL;
		} else {
			w->ringfull_ms = 0;
		}
	} else {
		w->stall_ms = 0;
		w->ringfull_ms = 0;
	}

	return K1_WD_NONE;
}

/*
 * Freestanding SHA-256 (FIPS 180-4) for byte-exact kernel function
 * fingerprinting at module init without embedding vendor machine code.
 */
struct k1_sha256_ctx {
	u32 state[8];
	u64 count;
	u8  buf[64];
};

static inline u32 k1_ror32(u32 x, int n) { return (x >> n) | (x << (32 - n)); }

static inline void k1_sha256_transform(u32 state[8], const u8 block[64])
{
	static const u32 k[64] = {
		0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
		0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
		0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
		0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
		0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
		0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
		0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
		0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
		0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
		0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
		0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
		0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
		0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
		0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
		0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
		0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
	};
	u32 w[64];
	u32 a, b, c, d, e, f, g, h;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = k1_be32(block + i * 4);
	for (i = 16; i < 64; i++) {
		u32 s0 = k1_ror32(w[i - 15], 7) ^ k1_ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
		u32 s1 = k1_ror32(w[i - 2], 17) ^ k1_ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = state[0]; b = state[1]; c = state[2]; d = state[3];
	e = state[4]; f = state[5]; g = state[6]; h = state[7];
	for (i = 0; i < 64; i++) {
		u32 S1 = k1_ror32(e, 6) ^ k1_ror32(e, 11) ^ k1_ror32(e, 25);
		u32 ch = (e & f) ^ ((~e) & g);
		u32 t1 = h + S1 + ch + k[i] + w[i];
		u32 S0 = k1_ror32(a, 2) ^ k1_ror32(a, 13) ^ k1_ror32(a, 22);
		u32 maj = (a & b) ^ (a & c) ^ (b & c);
		u32 t2 = S0 + maj;
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	state[0] += a; state[1] += b; state[2] += c; state[3] += d;
	state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static inline void k1_sha256_init(struct k1_sha256_ctx *ctx)
{
	ctx->state[0] = 0x6a09e667u; ctx->state[1] = 0xbb67ae85u;
	ctx->state[2] = 0x3c6ef372u; ctx->state[3] = 0xa54ff53au;
	ctx->state[4] = 0x510e527fu; ctx->state[5] = 0x9b05688cu;
	ctx->state[6] = 0x1f83d9abu; ctx->state[7] = 0x5be0cd19u;
	ctx->count = 0;
}

static inline void k1_sha256_update(struct k1_sha256_ctx *ctx, const u8 *data, u32 len)
{
	u32 idx = (u32)(ctx->count & 63u);

	ctx->count += len;
	if (idx && idx + len >= 64u) {
		memcpy(ctx->buf + idx, data, 64u - idx);
		k1_sha256_transform(ctx->state, ctx->buf);
		data += 64u - idx;
		len -= 64u - idx;
		idx = 0;
	}
	while (len >= 64u) {
		k1_sha256_transform(ctx->state, data);
		data += 64u;
		len -= 64u;
	}
	if (len)
		memcpy(ctx->buf + idx, data, len);
}

static inline void k1_sha256_final(struct k1_sha256_ctx *ctx, u8 out[32])
{
	u64 bits = ctx->count << 3;
	u32 idx = (u32)(ctx->count & 63u);
	u8 pad = 0x80u;
	u8 zero = 0;
	u8 lenbe[8];
	int i;

	k1_sha256_update(ctx, &pad, 1);
	idx = (idx + 1u) & 63u;
	while (idx != 56u) {
		k1_sha256_update(ctx, &zero, 1);
		idx = (idx + 1u) & 63u;
	}
	for (i = 0; i < 8; i++)
		lenbe[i] = (u8)(bits >> (56 - i * 8));
	k1_sha256_update(ctx, lenbe, 8);
	for (i = 0; i < 8; i++) {
		out[i * 4 + 0] = (u8)(ctx->state[i] >> 24);
		out[i * 4 + 1] = (u8)(ctx->state[i] >> 16);
		out[i * 4 + 2] = (u8)(ctx->state[i] >> 8);
		out[i * 4 + 3] = (u8)(ctx->state[i]);
	}
}

#endif /* K1FP_CORE_H */
