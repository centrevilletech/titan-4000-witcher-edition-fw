/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright 2026 Centreville Tech, LLC. Host test harness for titan_qctrl; see device/qctrl/README.md. */
/*
 * test_qctrl.c - host tests for titan_qctrl.c (the module source itself, compiled against
 * mock_k310.h) and its upload clamp law (ulclamp_core.h).
 *
 *   test_qctrl            run every test
 *   test_qctrl trace      print a packet-by-packet trace of a fixed mixed-traffic scenario in
 *                         modes 0, 2, 3 and 6 (download clamp, ACK thinning, ECN). run.sh
 *                         --identity compiles this against an older titan_qctrl.c and diffs the
 *                         two traces: with mode bit 4 clear, v0.4 forwards the same bytes.
 */
#include "mock_k310.h"
#ifndef QCTRL_SRC
#define QCTRL_SRC "../source/titan_qctrl.c"
#endif
#include QCTRL_SRC

#include <assert.h>
#include <stdint.h>

static int failures;
#define CHECK(c, ...) do { if (!(c)) { failures++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static struct net_device dev_lte = { "lte0pdn2" }, dev_eth = { "eth0" };

/* ---- time: the module's clock is ns >> 10 ---- */
static void set_ms(u32 ms) { mock_ns = (s64)ms * 1000000; }

/* ---- packets ---- */
struct tcp_spec {
	int v6;
	u8 src[16], dst[16];
	u16 sport, dport;
	u32 seq, ack;
	u8 flags;
	u16 win;
	int mss, ws;            /* -1: option absent */
	int ts;
	u32 tsval, tsecr;
	u32 payload;
	u8 ecn;
};

static u16 be16(const u8 *p) { return (u16)((p[0] << 8) | p[1]); }
static void put16(u8 *p, u32 v) { p[0] = (u8)(v >> 8); p[1] = (u8)v; }
static void put32(u8 *p, u32 v) { p[0] = (u8)(v >> 24); p[1] = (u8)(v >> 16); p[2] = (u8)(v >> 8); p[3] = (u8)v; }

/* One's complement sum of big-endian 16-bit words. */
static u32 sum16(const u8 *p, u32 n, u32 s)
{
	u32 i;
	for (i = 0; i + 1 < n; i += 2)
		s += be16(p + i);
	if (n & 1)
		s += (u32)p[n - 1] << 8;
	return s;
}
static u16 fold(u32 s) { while (s >> 16) s = (s & 0xffff) + (s >> 16); return (u16)s; }

/* TCP checksum over pseudo-header + segment; 0xffff when the stored checksum is right. */
static u16 tcp_verify(const struct sk_buff *skb)
{
	const u8 *ip = skb->data;
	u32 s;
	if ((ip[0] >> 4) == 4) {
		u32 ihl = (ip[0] & 15) * 4, tot = be16(ip + 2);
		s = sum16(ip + 12, 8, 0) + 6 + (tot - ihl);
		return fold(sum16(ip + ihl, tot - ihl, s));
	}
	{
		u32 plen = be16(ip + 4);
		s = sum16(ip + 8, 32, 0) + 6 + plen;
		return fold(sum16(ip + 40, plen, s));
	}
}

static struct sk_buff *mk(const struct tcp_spec *t)
{
	struct sk_buff *skb = calloc(1, sizeof(*skb));
	u8 *ip = skb->buf, *th;
	u32 l3, optlen = 0, hl, tot;
	u8 opt[40];

	if (t->mss >= 0) { opt[optlen] = 2; opt[optlen + 1] = 4; put16(opt + optlen + 2, (u32)t->mss); optlen += 4; }
	if (t->ws >= 0) { opt[optlen] = 1; opt[optlen + 1] = 3; opt[optlen + 2] = 3; opt[optlen + 3] = (u8)t->ws; optlen += 4; }
	if (t->ts) {
		opt[optlen] = 1; opt[optlen + 1] = 1; opt[optlen + 2] = 8; opt[optlen + 3] = 10;
		put32(opt + optlen + 4, t->tsval); put32(opt + optlen + 8, t->tsecr); optlen += 12;
	}
	hl = 20 + optlen;
	l3 = t->v6 ? 40 : 20;
	tot = l3 + hl + t->payload;
	if (tot > sizeof(skb->buf))
		tot = sizeof(skb->buf);   /* payload bytes beyond the buffer are not needed: len says how many */
	if (!t->v6) {
		ip[0] = 0x45; ip[1] = t->ecn; put16(ip + 2, l3 + hl + t->payload); ip[6] = 0x40; ip[8] = 64; ip[9] = 6;
		memcpy(ip + 12, t->src, 4); memcpy(ip + 16, t->dst, 4);
		put16(ip + 10, (u16)~fold(sum16(ip, 20, 0)));
		skb->protocol = htons(ETH_P_IP);
	} else {
		ip[0] = 0x60; ip[1] = (u8)(t->ecn << 4); put16(ip + 4, hl + t->payload); ip[6] = 6; ip[7] = 64;
		memcpy(ip + 8, t->src, 16); memcpy(ip + 24, t->dst, 16);
		skb->protocol = htons(ETH_P_IPV6);
	}
	th = ip + l3;
	put16(th, t->sport); put16(th + 2, t->dport); put32(th + 4, t->seq); put32(th + 8, t->ack);
	th[12] = (u8)((hl / 4) << 4); th[13] = t->flags; put16(th + 14, t->win);
	memcpy(th + 20, opt, optlen);
	skb->data = skb->buf;
	skb->len = l3 + hl + t->payload;   /* the payload is all zero, so the checksum below is exact */
	skb->data_len = 0;
	{
		u32 s = t->v6 ? sum16(ip + 8, 32, 0) + 6 + hl + t->payload : sum16(ip + 12, 8, 0) + 6 + hl + t->payload;
		put16(th + 16, (u16)~fold(sum16(th, hl, s)));
	}
	return skb;
}

static u16 skb_win(const struct sk_buff *skb)
{
	const u8 *ip = skb->data;
	u32 l3 = (ip[0] >> 4) == 4 ? (ip[0] & 15) * 4u : 40u;
	return be16(ip + l3 + 14);
}

/* okfn for released held ACKs */
static int released;
static int ok_release(struct sk_buff *skb) { released++; free(skb); return 0; }

static unsigned int hook(struct sk_buff *skb, int dl)
{
	return qctrl_bridge_hook(NF_BR_FORWARD, skb, dl ? &dev_lte : &dev_eth, dl ? &dev_eth : &dev_lte, ok_release);
}

static void proc(const char *line) { qctrl_proc_write(NULL, line, strlen(line), NULL); }
static const char *show(void)
{
	static struct seq_file m;
	m.n = 0;
	m.buf[0] = 0;
	qctrl_proc_show(&m, NULL);
	return m.buf;
}

static void fresh(void)
{
	mock_consumed = 0;
	memset(&g, 0, sizeof(g));
	mock_writable = 1;
	set_ms(1000);
	assert(init_module() == 0);
}

/* ---- a TCP connection between a customer (LAN) and a server (WAN) ---- */
struct conn {
	struct tcp_spec ul, dl;      /* templates: ul = customer -> server, dl = server -> customer */
	u32 c_seq, s_seq;            /* next sequence each side sends */
};

static void conn_init(struct conn *c, int v6, u32 id, int cws, int sws)
{
	memset(c, 0, sizeof(*c));
	c->ul.v6 = c->dl.v6 = v6;
	c->ul.src[0] = 192; c->ul.src[1] = 0; c->ul.src[2] = 2; c->ul.src[3] = (u8)id;
	c->ul.dst[0] = 198; c->ul.dst[1] = 51; c->ul.dst[2] = 100; c->ul.dst[3] = 1;
	if (v6) {
		c->ul.src[0] = 0x20; c->ul.src[1] = 0x01; c->ul.src[2] = 0x0d; c->ul.src[3] = 0xb8; c->ul.src[15] = (u8)id;
		memset(c->ul.dst, 0, 16);
		c->ul.dst[0] = 0x20; c->ul.dst[1] = 0x01; c->ul.dst[2] = 0x0d; c->ul.dst[3] = 0xb8; c->ul.dst[4] = 1; c->ul.dst[15] = 1;
	}
	memcpy(c->dl.src, c->ul.dst, 16);
	memcpy(c->dl.dst, c->ul.src, 16);
	c->ul.sport = c->dl.dport = (u16)(40000 + id);
	c->ul.dport = c->dl.sport = 5299;
	c->ul.mss = c->dl.mss = -1;
	c->ul.ws = cws;
	c->dl.ws = sws;
	c->c_seq = 1000000u * id + 7;
	c->s_seq = 3000000u * id + 11;
}

/* SYN, SYN-ACK; returns the SYN-ACK's verdict */
static void handshake(struct conn *c)
{
	struct tcp_spec t = c->ul;
	struct sk_buff *skb;
	t.flags = TCP_SYN; t.seq = c->c_seq++; t.ack = 0; t.win = 64240; t.mss = 1328; t.ts = 1;
	skb = mk(&t); CHECK(hook(skb, 0) == NF_ACCEPT, "SYN"); free(skb);
	t = c->dl;
	t.flags = TCP_SYN | TCP_ACK; t.seq = c->s_seq++; t.ack = c->c_seq; t.win = 65160; t.mss = 1328; t.ts = 1;
	skb = mk(&t); CHECK(hook(skb, 1) == NF_ACCEPT, "SYN-ACK"); free(skb);
	c->ul.ws = c->dl.ws = -1;   /* window scale only in SYNs */
}

static u32 ul_data(struct conn *c, u32 len)
{
	struct tcp_spec t = c->ul;
	struct sk_buff *skb;
	unsigned int v;
	t.flags = TCP_ACK; t.seq = c->c_seq; t.ack = c->s_seq; t.win = 2000; t.payload = len; t.ts = 1;
	skb = mk(&t);
	v = hook(skb, 0);
	CHECK(v == NF_ACCEPT, "uplink data verdict %u", v);
	free(skb);
	c->c_seq += len;
	return c->c_seq;
}

/* Server ACK up to `ack` with raw window `win`; returns the raw window that left the Titan. */
static u16 dl_ack(struct conn *c, u32 ack, u16 win, u32 *csum_ok)
{
	struct tcp_spec t = c->dl;
	struct sk_buff *skb;
	u16 w;
	t.flags = TCP_ACK; t.seq = c->s_seq; t.ack = ack; t.win = win; t.ts = 1;
	skb = mk(&t);
	CHECK(hook(skb, 1) == NF_ACCEPT, "downlink ACK verdict");
	w = skb_win(skb);
	if (csum_ok)
		*csum_ok = tcp_verify(skb) == 0xffff;
	free(skb);
	return w;
}

/*
 * A closed loop: n customer uploads share a fixed-rate link with a base round trip; the
 * customer sends whatever the advertised window allows (an unlimited cwnd, the worst case),
 * the link drains `rate_bpms` bytes per ms in order, and each byte's ACK comes back
 * `rtt_ms` after it drained. Returns the mean queue (ms) over the last half.
 */
struct loop_res { double queue_ms, mbps; int edge_back, csum_bad, raised; };

#define RING 8192u
static struct loop_res upload_loop(int n, int v6, u32 rate_bpms, u32 rtt_ms, u32 secs, u16 srv_win, int srv_ws,
				   int slow_start)
{
	u32 cwnd[8];
	struct conn c[8];
	u32 sent_hi[8], drained[8], acked[8], edge[8];
	static u32 due_t[8][RING], due_b[8][RING];
	u32 head[8] = { 0 }, tail[8] = { 0 };
	u32 t, k, delivered = 0, dlv0 = 0, t0 = 0;
	u64 qsum = 0, qn = 0;
	struct loop_res r = { 0, 0, 0, 0, 0 };
	const u32 start_ms = 2000;

	for (k = 0; k < (u32)n; k++) {
		set_ms(start_ms);
		conn_init(&c[k], v6, k + 1, 7, srv_ws);
		handshake(&c[k]);
		sent_hi[k] = drained[k] = acked[k] = c[k].c_seq;
		edge[k] = c[k].c_seq + 65160u;   /* the SYN-ACK's window: SYN windows are never scaled */
		cwnd[k] = slow_start ? 10u * 1328u : 0xfffffffu;
	}
	for (t = 0; t < secs * 1000; t++) {
		u32 queue = 0, budget = rate_bpms;
		set_ms(start_ms + t);
		/* the link drains rate_bpms per ms, shared in proportion to each flow's queue;
		 * a byte's ACK comes back rtt_ms after it drained */
		for (k = 0; k < (u32)n; k++)
			queue += sent_hi[k] - drained[k];
		for (k = 0; k < (u32)n && queue; k++) {
			u32 qk = sent_hi[k] - drained[k];
			u32 d = (u32)(((u64)budget * qk) / queue);
			if (d > qk)
				d = qk;
			if (d) {
				drained[k] += d;
				due_t[k][tail[k] % RING] = t + rtt_ms;
				due_b[k][tail[k] % RING] = drained[k];
				tail[k]++;
			}
		}
		for (k = 0; k < (u32)n; k++) {
			while (head[k] != tail[k] && due_t[k][head[k] % RING] <= t) {
				u32 a = due_b[k][head[k] % RING], ok = 0;
				u16 w;
				head[k]++;
				delivered += a - acked[k];
				if (slow_start && cwnd[k] < (64u << 20))
					cwnd[k] += a - acked[k];
				acked[k] = a;
				w = dl_ack(&c[k], a, srv_win, &ok);
				if (!ok)
					r.csum_bad++;
				if (w > srv_win)
					r.raised++;
				if ((s32)(a + ((u32)w << srv_ws) - edge[k]) <= -(s32)(1u << srv_ws))
					r.edge_back++;                      /* back by a whole scale unit */
				else if ((s32)(a + ((u32)w << srv_ws) - edge[k]) > 0)
					edge[k] = a + ((u32)w << srv_ws);
			}
		}
		/* each customer sends 1328 B segments up to its right edge and its cwnd */
		for (k = 0; k < (u32)n; k++)
			while ((s32)(edge[k] - (sent_hi[k] + 1328)) >= 0 && sent_hi[k] + 1328 - acked[k] <= cwnd[k])
				sent_hi[k] = ul_data(&c[k], 1328);
		if (t >= secs * 500) {
			u32 q = 0;
			if (!t0) {
				t0 = t;
				dlv0 = delivered;
			}
			for (k = 0; k < (u32)n; k++)
				q += sent_hi[k] - drained[k];
			qsum += q;
			qn++;
		}
	}
	r.queue_ms = qn ? (double)qsum / (double)qn / rate_bpms : 0;
	r.mbps = (double)(delivered - dlv0) * 8 / ((t - t0) * 1000.0);
	return r;
}

/* ---------------------------------------------------------------------------------- */
#ifndef TRACE_ONLY

static void test_core_units(void)
{
	struct ulc u;
	struct ulc_flow f;
	u32 now = 5u;
	ulc_init(&u, now);
	CHECK(u.target_ms == 8 && u.pulse_bytes == 0 && u.pulse_ms == 200, "defaults");
	CHECK(ulc_ms(1000) == 976562u, "ms to units");
	CHECK(ulc_rate(1000000u, 1024u) == 1000000u, "rate exact");
	CHECK(ulc_rate(0xffffffffu, 2048u) > 2000000000u, "rate large stays 32-bit");
	ulc_flow_reset(&f, now);
	/* raw window: never raises, never retracts, rounds up to the scale unit, zero stays zero */
	ulc_on_synack(&f, 1, 1, 7, 20000, now);
	CHECK(f.wscale == 7 && (f.state & ULC_S_WS), "scale");
	CHECK(f.rtt_min == 20000, "the handshake is the first RTT sample");
	CHECK(ulc_raw_window(&f, 100, 1000, ULC_NO_CLAMP) == 1000, "no clamp");
	CHECK(ulc_raw_window(&f, 100, 1000, 12800) == 100, "clamp 12800 B = 100 units");
	CHECK(ulc_raw_window(&f, 100, 1000, 12801) == 101, "round up");
	CHECK(ulc_raw_window(&f, 100, 50, 12800) == 50, "never above the server's");
	CHECK(ulc_raw_window(&f, 100, 0, 12800) == 0, "zero window untouched");
	ulc_sent(&u, &f, 100, 1000, 500);                 /* edge = 100 + 64000 */
	CHECK(ulc_raw_window(&f, 200, 1000, 128) == (64000 - 100) / 128, "holds the right edge, rounded down");
	CHECK(200 + (u32)ulc_raw_window(&f, 200, 1000, 128) * 128 > f.edge - 128, "less than one unit short of it");
	CHECK(ulc_raw_window(&f, 200, 1000, 64000) == 500, "a target past the edge rounds up");
	/* the downlink queue adds to the target: bw 1024 B/unit-ms, rtt 20000 units, target 8 ms */
	u.bw = 1024u; u.rtt_base = 20000u; u.n_active = 1u; f.rtt_min = 20000u;
	{
		u32 base = ulc_share(&u, &f, now, 1328);
		u.dl_queue_ms = 20u;
		CHECK(ulc_share(&u, &f, now, 1328) == base + ulc_ms(20u), "a 20 ms downlink queue adds 20 ms of window");
		u.dl_queue_ms = 5000u;
		CHECK(ulc_share(&u, &f, now, 1328) == ((u64)1024u * (20000u + ulc_ms(8u + ULC_DLQ_MAX_MS)) >> 10),
		      "capped at 200 ms");
		u.dl_queue_ms = 0;
	}
	ulc_on_synack(&f, 0, 1, 9, 0, now);
	CHECK(f.wscale == 0, "RFC 7323: shift only if both SYNs had the option");
	ulc_on_synack(&f, 1, 1, 15, 0, now);
	CHECK(f.wscale == 14, "shift capped at 14");
}

static void test_modes_and_knobs(void)
{
	fresh();
	CHECK(strstr(show(), "titan_qctrl v0.4 ") == show(), "version line");
	CHECK(strstr(show(), "mode=0x0 ") != NULL, "starts in mode 0");
	proc("mode 16");
	CHECK(strstr(show(), "mode=0x10 ") && strstr(show(), "ul_clamp=1)"), "mode 16");
	proc("mode 32");
	CHECK(strstr(show(), "mode=0x10 ") != NULL, "mode 32 refused");
	proc("mode 31");
	CHECK(strstr(show(), "mode=0x1f ") != NULL, "mode 31 accepted by the module");
	proc("ul_target_ms 41");
	CHECK(g.ul.target_ms == 8, "target 41 refused");
	proc("ul_target_ms 0");
	CHECK(g.ul.target_ms == 0, "target 0");
	proc("ul_target_ms 12");
	CHECK(strstr(show(), "ul_target_ms=12 ") != NULL, "target 12 shown");
	proc("ul_pulse_kb 65");
	CHECK(g.ul.pulse_bytes == 0, "pulse 65 refused");
	proc("ul_pulse_kb 32");
	CHECK(g.ul.pulse_bytes == 32768 && strstr(show(), "ul_pulse_kb=32 "), "pulse 32");
	proc("ul_pulse_ms 49");
	CHECK(g.ul.pulse_ms == 200, "pulse_ms 49 refused");
	proc("ul_pulse_ms 2001");
	CHECK(g.ul.pulse_ms == 200, "pulse_ms 2001 refused");
	proc("ul_pulse_ms 150");
	CHECK(g.ul.pulse_ms == 150, "pulse_ms 150");
	proc("ul_target_ms 0x8");
	CHECK(g.ul.target_ms == 12, "hex refused");
}

static void test_upload_clamp_converges(int v6)
{
	struct loop_res off, on;
	/* 2 KB/ms (16 Mbps), 20 ms base RTT, 4 flows, server window 4096 << 9 = 2 MB */
	fresh();
	proc("mode 2");                         /* the download clamp alone leaves uploads alone */
	off = upload_loop(4, v6, 2000, 20, 6, 4096, 9, 1);
	fresh();
	proc("ul_target_ms 8");
	proc("mode 18");
	on = upload_loop(4, v6, 2000, 20, 6, 4096, 9, 1);
	printf("  upload x4 %s: unclamped queue %.0f ms %.2f Mbps | clamp (8 ms) queue %.1f ms %.2f Mbps | %s\n",
	       v6 ? "IPv6" : "IPv4", off.queue_ms, off.mbps, on.queue_ms, on.mbps, strstr(show(), "ul_bw_kbps"));
	CHECK(off.queue_ms > 100, "without the clamp the queue is the server's window");
	CHECK(on.queue_ms > 2 && on.queue_ms < 16, "clamp holds the queue near the target (%.1f ms)", on.queue_ms);
	CHECK(on.mbps > 15.5, "the link stays full (%.2f Mbps)", on.mbps);
	CHECK(on.csum_bad == 0 && off.csum_bad == 0, "checksums stay valid");
	CHECK(on.edge_back == 0, "right edge never moves back by a scale unit");
	CHECK(on.raised == 0, "window never above the server's");
	CHECK(g.ul.st_clamped > 1000, "windows lowered (%u)", g.ul.st_clamped);
}

static void test_upload_window_dump(void)
{
	struct loop_res r;
	fresh();
	proc("mode 16");
	r = upload_loop(4, 0, 2000, 20, 6, 2048, 7, 0);   /* 256 KB each, sent at once */
	printf("  upload x4, windows dumped at once: queue %.1f ms in the last 3 s, %.2f Mbps\n", r.queue_ms, r.mbps);
	CHECK(r.queue_ms < 16 && r.mbps > 15.5, "the clamp takes over after the first edge drains");
	CHECK(r.edge_back == 0 && r.csum_bad == 0 && r.raised == 0, "edge/csum/raise");
}

static void test_upload_single_and_targets(void)
{
	u32 tg;
	double prev = 0;
	for (tg = 0; tg <= 16; tg += 8) {
		struct loop_res r;
		char line[32];
		fresh();
		snprintf(line, sizeof(line), "ul_target_ms %u", tg);
		proc(line);
		proc("mode 16");
		r = upload_loop(1, 0, 1000, 25, 6, 8192, 7, 1);
		printf("  upload x1, 8 Mbps link, 25 ms: target %2u ms -> queue %.1f ms, %.2f Mbps\n", tg, r.queue_ms, r.mbps);
		CHECK(r.mbps > 7.7, "full link at target %u (%.2f)", tg, r.mbps);
		CHECK(r.queue_ms >= prev - 0.5, "queue grows with the target");
		CHECK(r.queue_ms < tg + 8, "queue near the target %u (%.1f)", tg, r.queue_ms);
		CHECK(r.edge_back == 0 && r.csum_bad == 0 && r.raised == 0, "edge/csum/raise");
		prev = r.queue_ms;
	}
}

static void test_upload_untouched_cases(void)
{
	struct conn c;
	u32 i, ok = 0;
	u16 w;

	/* no handshake seen: the server's shift is unknown, never clamp */
	fresh();
	proc("ul_target_ms 0");
	proc("mode 16");
	conn_init(&c, 0, 9, 7, 9);
	for (i = 0; i < 400; i++) {
		set_ms(2000 + i);
		ul_data(&c, 1328);
		w = dl_ack(&c, c.c_seq - 1328 * 20, 4096, &ok);
		CHECK(w == 4096 && ok, "unknown scale: untouched");
	}
	/* zero window from the server passes */
	fresh();
	proc("mode 16");
	conn_init(&c, 0, 3, 7, 9);
	handshake(&c);
	for (i = 0; i < 300; i++) {
		set_ms(2000 + i);
		ul_data(&c, 1328);
		w = dl_ack(&c, c.c_seq - 1328 * 10, i == 250 ? 0 : 4096, &ok);
		if (i == 250)
			CHECK(w == 0, "zero window untouched");
	}
	/* skb_make_writable fails: the original window goes out and the edge follows it */
	fresh();
	proc("ul_target_ms 0");
	proc("mode 16");
	conn_init(&c, 0, 4, 7, 9);
	handshake(&c);
	for (i = 0; i < 600; i++) {
		set_ms(2000 + i);
		ul_data(&c, 1328);
		mock_writable = !(i >= 400 && i < 420);
		w = dl_ack(&c, c.c_seq - 1328 * 10, 4096, &ok);
		CHECK(ok, "checksum");
		if (i >= 400 && i < 420)
			CHECK(w == 4096, "unwritable: original window");
		if (i >= 420 && i < 430)
			CHECK(w >= 4000, "edge from the unwritable ACKs is kept (%u)", w);
	}
}

#endif /* TRACE_ONLY */

/* ---- identity trace: modes 0, 2, 3, 6, mixed traffic ---- */
static void trace_scenario(void)
{
	static const u32 modes[] = { 0, 2, 3, 6 };
	u32 mi, t, k;
	for (mi = 0; mi < 4; mi++) {
		struct conn dn[3], up[2];
		u32 h = 2166136261u;
		fresh();
		{
			char line[16];
			snprintf(line, sizeof(line), "mode %u", modes[mi]);
			proc(line);
		}
		set_ms(3000);
		for (k = 0; k < 3; k++) { conn_init(&dn[k], k == 2, 20 + k, 7, 9); handshake(&dn[k]); }
		for (k = 0; k < 2; k++) { conn_init(&up[k], k == 1, 30 + k, 7, 9); handshake(&up[k]); }
		released = 0;
		for (t = 0; t < 4000; t++) {
			set_ms(3000 + t);
			for (k = 0; k < 3; k++) {
				/* download: server data (DL, ECT(0) on flow 0), customer ACKs (UL) */
				struct tcp_spec d = dn[k].dl, a = dn[k].ul;
				struct sk_buff *skb;
				unsigned int v;
				u32 j;
				for (j = 0; j < 3; j++) {
					d.flags = TCP_ACK; d.seq = dn[k].s_seq; d.ack = dn[k].c_seq; d.win = 500; d.payload = 1328;
					/* a 0..59 ms sawtooth queue in the server's clock drives the controller */
					d.ts = 1; d.tsval = 3000 + t - (t / 7) % 60; d.tsecr = t; d.ecn = k == 0 ? 2 : 0;
					skb = mk(&d);
					v = hook(skb, 1);
					h = (h ^ v) * 16777619u;
					for (u32 b = 0; b < skb->len && b < 120; b++) h = (h ^ skb->data[b]) * 16777619u;
					if (v != NF_STOLEN) free(skb);
					dn[k].s_seq += 1328;
				}
				a.flags = TCP_ACK; a.seq = dn[k].c_seq; a.ack = dn[k].s_seq - (t % 3) * 1328; a.win = (u16)(60000 + (t % 50));
				a.ts = 1; a.tsval = t; a.tsecr = 3000 + t;
				skb = mk(&a);
				v = hook(skb, 0);
				h = (h ^ v) * 16777619u;
				for (u32 b = 0; b < skb->len && b < 120; b++) h = (h ^ skb->data[b]) * 16777619u;
				if (v != NF_STOLEN) free(skb);
			}
			for (k = 0; k < 2; k++) {
				/* upload: customer data (UL), server ACKs (DL) */
				struct sk_buff *skb;
				struct tcp_spec a = up[k].dl;
				unsigned int v;
				ul_data(&up[k], 1328);
				a.flags = TCP_ACK; a.seq = up[k].s_seq; a.ack = up[k].c_seq - 1328 * 30; a.win = 4096; a.ts = 1;
				skb = mk(&a);
				v = hook(skb, 1);
				h = (h ^ v) * 16777619u;
				for (u32 b = 0; b < skb->len && b < 120; b++) h = (h ^ skb->data[b]) * 16777619u;
				free(skb);
			}
			if (g_flush_timer.timer.armed) {
				g_flush_timer.timer.armed = 0;
				flush_timer_cb(&g_flush_timer.timer);
			}
			if (t % 500 == 499)
				printf("mode %u t %u hash %08x released %d\n", modes[mi], t, h, released);
		}
		printf("mode %u stats rwnd_clamped %u acks_thinned %u ecn_marked %u ctl_active_ticks %u owd_ok %u\n", modes[mi],
		       g.stat_rwnd_clamped, g.stat_acks_thinned, g.stat_ecn_marked, g.stat_active_ticks, g.stat_owd_ok);
		cleanup_module();   /* forwards any ACK still held */
		printf("mode %u end released %d consumed %d\n", modes[mi], released, mock_consumed);
	}
}

int main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "trace")) {
		trace_scenario();
		return 0;
	}
#ifdef TRACE_ONLY
	return 2;
#else
	test_core_units();
	test_modes_and_knobs();
	test_upload_clamp_converges(0);
	test_upload_clamp_converges(1);
	test_upload_single_and_targets();
	test_upload_window_dump();
	test_upload_untouched_cases();
	if (failures) {
		printf("FAIL: %d titan_qctrl host checks failed\n", failures);
		return 1;
	}
	printf("PASS: titan_qctrl host tests (upload clamp law, knobs, IPv4/IPv6 closed loop, checksums, right edge, untouched cases)\n");
	return 0;
#endif
}
