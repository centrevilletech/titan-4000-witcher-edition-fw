/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright 2026 Centreville Tech, LLC. Kernel module for Titan 4000 Witcher Edition; see device/qctrl/README.md. */
/*
 * ulclamp_core.h - the upload window clamp's law, shared by titan_qctrl.ko and its host tests.
 *
 * The upload queue lives in the modem (GIPC Ring 1 and PDCP/RLC staging), where Linux cannot
 * see it. But every upload flow's ACKs (server to customer) cross the Titan, so the clamp
 * bounds each upload's window by lowering the receive window in those ACKs. A flow that has
 * finished its slow start gets
 *
 *     W_f = bw / n x (rtt_f + target_ms)       (+ pulse_bytes / n for one round per pulse)
 *
 * so the n bulk uploads share the measured rate equally and each keeps about target_ms of
 * data queued in the modem, whatever its congestion control, without a single drop.
 *
 * - bw: the maximum delivery-rate sample of the last 2 s (8 slots of 250 ms). A sample is
 *   what all uploads had acknowledged over one probe's round trip, as BBR's rate samples, so
 *   it is smooth on a TDD link. A maximum keeps a clamp-limited stretch from dragging the
 *   estimate down before its window ends. With target_ms above 0 the clamp lets the rate
 *   grow by about target_ms / rtt per round, so it finds new capacity without probing.
 * - rtt_f: the flow's minimum round trip from the Titan over the last 5-10 s. The handshake
 *   (SYN to SYN-ACK, before any data queues) is the first sample.
 * - Startup: until the link is full, a flow (and every flow that has not yet delivered
 *   ULC_STARTUP_BYTES) gets twice its bytes in flight, at least 64 KB. Slow start never
 *   outgrows that, yet the right edge stays close, so the clamp can take over without
 *   waiting for a server's megabyte window to drain. The link is full at the first round
 *   trip that shows a queue (target_ms + 10 ms above the flow's minimum, as HyStart's delay
 *   exit), or once bw stops growing (under 25 % over 3 rounds, as BBR's). Leaving early only
 *   costs a few rounds of growth at target_ms / rtt per round; leaving late costs a queue.
 * - A download's tower queue delays every upload's ACKs. The module measures it from the
 *   servers' own clocks (one way, so the uploads' queue cannot feed into it) and passes it
 *   in as dl_queue_ms, which adds to every upload's target, so an upload keeps its rate
 *   while a download runs.
 * - Pulses (off by default): the Nokia eNB schedules a second uplink carrier only while the
 *   UE's buffer report is high enough. Every pulse_ms the window grows by pulse_bytes for
 *   one round, which raises the report and lets bw see the link's full rate.
 * - The right edge (ack + window) never moves back (RFC 7323 section 2.4), the window never
 *   rises above what the server advertised, and a zero window passes untouched.
 *
 * Time is the module's unit: 1.024 us (ktime ns >> 10), wrapping modulo 2^32; every
 * comparison is a signed difference. No 64-bit division (the kernel exports none) and no
 * kernel headers: the includer provides u8, u16, u32, u64, s32 and __builtin_memset.
 */
#ifndef ULCLAMP_CORE_H
#define ULCLAMP_CORE_H

#define ULC_NO_CLAMP      0xffffffffu
#define ULC_SLOTS         8u
#define ULC_SLOT_UNITS    244141u   /* 250 ms: 8 slots make the 2 s bandwidth window */
#define ULC_RTT_HALF      4882813u  /* 5 s: rtt_min covers the last 5 to 10 s */
#define ULC_PROBE_MAX     3906250u  /* 4 s: a probe older than this is dropped */
#define ULC_ACTIVE_UNITS  195313u   /* 200 ms without uplink data and nothing in flight: stopped */
#define ULC_IDLE_UNITS    976563u   /* 1 s without uplink data: stopped even with bytes in
                                       flight; 1 s with no upload: the next one starts over */
#define ULC_ROUND_MIN     39063u    /* 40 ms: shortest startup round */
#define ULC_FULL_ROUNDS   3u        /* rounds without 25 % growth that end startup */
#define ULC_EXIT_SLACK    9766u     /* 10 ms: a round trip this far over min + target ends startup */
#define ULC_STARTUP_BYTES 65536u    /* a flow joins the shared window after delivering this */
#define ULC_CEIL_BYTES    (32u << 20)
#define ULC_MIN_SEGS      4u        /* per-flow floor: 4 segments keep fast retransmit */
#define ULC_DEFAULT_MSS   1328u

/* Knob limits (the /proc writer and the keeper refuse anything else). */
#define ULC_TARGET_MAX_MS 40u
#define ULC_PULSE_MAX_KB  64u
#define ULC_PULSE_MS_MIN  50u
#define ULC_PULSE_MS_MAX  2000u
#define ULC_DLQ_MAX_MS    200u      /* largest downlink queue added to the target */

/* struct ulc_flow.state */
#define ULC_S_SNDHI  0x01u  /* snd_hi holds a sequence */
#define ULC_S_UNA    0x02u  /* una holds a sequence */
#define ULC_S_EDGE   0x04u  /* edge holds the right edge last sent */
#define ULC_S_PROBE  0x08u  /* a probe is waiting for its ACK */
#define ULC_S_ACTIVE 0x10u  /* sending: set by uplink data, cleared by the tick when it stops */
#define ULC_S_WS     0x20u  /* the handshake was seen: wscale is the server's shift */

/* One upload flow, embedded in titan_qctrl's flow entry. All zero = unused. */
struct ulc_flow {
	u32 snd_hi;     /* highest uplink sequence end the customer sent */
	u32 una;        /* highest cumulative ACK from the server */
	u32 edge;       /* right edge (ack + window) last sent to the customer */
	u32 probe_seq;  /* probe: the sequence its ACK must cover */
	u32 probe_t;    /* when the probe crossed the Titan */
	u32 probe_dlv;  /* ulc.delivered at that time */
	u32 rtt_min;    /* minimum round trip, last 5-10 s (units; 0 = none) */
	u32 rtt_next;   /* minimum of the current 5 s half */
	u32 rtt_t;      /* start of the current half */
	u32 last_ul;    /* last uplink data */
	u32 dlv;        /* bytes delivered since the transfer started (saturates) */
	u8  state;      /* ULC_S_* */
	u8  wscale;     /* the server's receive window shift (0..14), with ULC_S_WS */
	u16 _pad;
};

/* The clamp: knobs, shared estimates and counters. */
struct ulc {
	/* knobs */
	u32 target_ms;   /* queue the clamp leaves above the round trip (0..40, default 8) */
	u32 pulse_bytes; /* extra window for one round per pulse (0 = no pulses) */
	u32 pulse_ms;    /* time between pulses (50..2000) */
	/* input */
	u32 dl_queue_ms; /* the unit's downlink queue (one way, ms; 0 = none measured) */
	/* estimates */
	u32 delivered;   /* bytes acknowledged, all uploads (wraps) */
	u32 slot[ULC_SLOTS];  /* maximum rate sample per slot, bytes per 1024 units */
	u32 slot_i;
	u32 slot_t;      /* start of slot[slot_i] */
	u32 bw;          /* maximum over the slots, bytes per 1024 units (about 1.05 ms) */
	u32 rtt_base;    /* smallest rtt_min of the sending flows (units; 0 = none) */
	u32 n_active;    /* flows sharing the window (past startup) at the last tick */
	u32 full;        /* 1 once bw stopped growing: the shared window applies */
	u32 full_bw;     /* bw at the last 25 % growth */
	u32 full_cnt;    /* rounds since then */
	u32 round_t;     /* start of the current startup round */
	u32 busy_t;      /* last tick with a sending flow */
	u32 pulse_next;  /* next pulse may start */
	u32 pulse_until; /* the current pulse ends */
	u32 w_total;     /* sum of the shared windows at the last tick (telemetry) */
	/* tick accumulators */
	u32 n_next;
	u32 n_sending;
	u32 rtt_next_base;
	u32 w_next;
	/* counters */
	u32 st_acks;     /* downlink ACKs of sending flows seen */
	u32 st_clamped;  /* windows lowered */
	u32 st_samples;  /* rate samples */
	u32 st_pulses;
	u32 st_startups; /* startups begun */
};

static inline int ulc_seq_gt(u32 a, u32 b) { return (s32)(a - b) > 0; }
static inline int ulc_seq_lt(u32 a, u32 b) { return (s32)(a - b) < 0; }
static inline int ulc_before(u32 a, u32 b) { return (s32)(a - b) < 0; }

/* ms -> units (976.5625 per ms), exact for ms <= 274877. */
static inline u32 ulc_ms(u32 ms) { return (ms * 15625u) >> 4; }

static inline void ulc_init(struct ulc *g, u32 now)
{
	__builtin_memset(g, 0, sizeof(*g));
	g->target_ms = 8u;
	g->pulse_ms = 200u;
	g->slot_t = now;
	g->round_t = now;
	g->busy_t = now;
	g->pulse_next = now;
	g->pulse_until = now;
}

/* A new connection on this 4-tuple (the customer's SYN). */
static inline void ulc_flow_reset(struct ulc_flow *f, u32 now)
{
	__builtin_memset(f, 0, sizeof(*f));
	f->rtt_t = now;
	f->last_ul = now;
}

static inline void ulc_rtt_sample(struct ulc_flow *f, u32 rtt, u32 now)
{
	if (!f->rtt_min || rtt < f->rtt_min)
		f->rtt_min = rtt;
	if (!f->rtt_next || rtt < f->rtt_next)
		f->rtt_next = rtt;
	if ((u32)(now - f->rtt_t) > ULC_RTT_HALF) {
		f->rtt_min = f->rtt_next;
		f->rtt_next = rtt;
		f->rtt_t = now;
	}
}

/*
 * The server's SYN-ACK, `rtt` after the customer's SYN crossed the Titan. RFC 7323 2.2: the
 * server's shift applies only if both SYNs carried the option; otherwise the window is in
 * bytes.
 */
static inline void ulc_on_synack(struct ulc_flow *f, int client_ws, int server_ws, u32 shift, u32 rtt,
				 u32 now)
{
	f->wscale = (u8)((client_ws && server_ws) ? (shift > 14u ? 14u : shift) : 0u);
	f->state |= ULC_S_WS;
	if (rtt && rtt <= ULC_PROBE_MAX)
		ulc_rtt_sample(f, rtt, now);
}

/* An uplink data segment ending at seq_end: the flow is sending from now on (the tick clears
 * that once it stops), so not one ACK of a new transfer leaves with the server's full window.
 * A segment that advances snd_hi may start the flow's probe (never a retransmission, as
 * Karn's rule). */
static inline void ulc_on_ul_data(const struct ulc *g, struct ulc_flow *f, u32 seq_end, u32 now)
{
	f->last_ul = now;
	f->state |= ULC_S_ACTIVE;
	if (!(f->state & ULC_S_SNDHI) || ulc_seq_gt(seq_end, f->snd_hi)) {
		f->snd_hi = seq_end;
		f->state |= ULC_S_SNDHI;
		if (!(f->state & ULC_S_PROBE)) {
			f->probe_seq = seq_end;
			f->probe_t = now;
			f->probe_dlv = g->delivered;
			f->state |= ULC_S_PROBE;
		}
	}
}

/* Move to the slot that holds now, clearing the slots passed over, and refresh bw. */
static inline void ulc_roll(struct ulc *g, u32 now)
{
	u32 k, m = 0;

	if ((u32)(now - g->slot_t) >= ULC_SLOTS * ULC_SLOT_UNITS) {
		for (k = 0; k < ULC_SLOTS; k++)
			g->slot[k] = 0;
		g->slot_t = now;
	}
	while ((u32)(now - g->slot_t) >= ULC_SLOT_UNITS) {
		g->slot_t += ULC_SLOT_UNITS;
		g->slot_i = (g->slot_i + 1u) & (ULC_SLOTS - 1u);
		g->slot[g->slot_i] = 0;
	}
	for (k = 0; k < ULC_SLOTS; k++)
		if (g->slot[k] > m)
			m = g->slot[k];
	g->bw = m;
}

/* bytes over dt units -> bytes per 1024 units, in 32-bit division only. */
static inline u32 ulc_rate(u32 bytes, u32 dt)
{
	while (bytes >= (1u << 22)) {
		bytes >>= 1;
		dt >>= 1;
	}
	return dt ? (bytes << 10) / dt : 0;
}

static inline void ulc_rate_sample(struct ulc *g, u32 rate, u32 now)
{
	g->st_samples++;
	ulc_roll(g, now);
	if (rate > g->slot[g->slot_i])
		g->slot[g->slot_i] = rate;
	if (rate > g->bw)
		g->bw = rate;
}

static inline u32 ulc_inflight(const struct ulc_flow *f)
{
	return ulc_seq_gt(f->snd_hi, f->una) ? f->snd_hi - f->una : 0;
}

/* Startup: twice the bytes in flight (at least ULC_STARTUP_BYTES). Slow start never
 * outgrows it, and the right edge stays within one window of what is in flight. */
static inline u32 ulc_startup_window(const struct ulc_flow *f)
{
	u32 w = ulc_inflight(f);

	w = w > (ULC_CEIL_BYTES >> 1) ? ULC_CEIL_BYTES : w << 1;
	return w < ULC_STARTUP_BYTES ? ULC_STARTUP_BYTES : w;
}

static inline u32 ulc_dlq(const struct ulc *g)
{
	return g->dl_queue_ms < ULC_DLQ_MAX_MS ? g->dl_queue_ms : ULC_DLQ_MAX_MS;
}

/* The flow's share of the shared window (bytes), or 0 without estimates. */
static inline u32 ulc_share(const struct ulc *g, const struct ulc_flow *f, u32 now, u32 mss)
{
	u32 rtt = f->rtt_min ? f->rtt_min : g->rtt_base, n = g->n_active ? g->n_active : 1u, floor;
	u64 w;

	if (!g->bw || !rtt)
		return 0;
	w = ((u64)g->bw * (u64)(rtt + ulc_ms(g->target_ms + ulc_dlq(g)))) >> 10;
	if (g->pulse_bytes && ulc_before(now, g->pulse_until))
		w += g->pulse_bytes;
	if (w > ULC_CEIL_BYTES)
		w = ULC_CEIL_BYTES;
	w = (u32)w / n;
	floor = ULC_MIN_SEGS * (mss ? mss : ULC_DEFAULT_MSS);
	return (u32)w < floor ? floor : (u32)w;
}

/*
 * A downlink segment carrying ACK `ack` for this flow. Accounts newly acknowledged bytes,
 * closes the probe, and returns the window the flow may have in bytes: ULC_NO_CLAMP when
 * the flow is not an upload the clamp handles (no handshake seen, or not sending), the
 * startup window, or the flow's share of the shared window.
 */
static inline u32 ulc_on_dl_ack(struct ulc *g, struct ulc_flow *f, u32 ack, u32 now, u32 mss)
{
	u32 share;

	if (!(f->state & ULC_S_UNA)) {
		f->una = ack;
		f->state |= ULC_S_UNA;
	} else if (ulc_seq_gt(ack, f->una)) {
		u32 d = ack - f->una;
		g->delivered += d;
		f->dlv = (f->dlv > 0xffffffffu - d) ? 0xffffffffu : f->dlv + d;
		f->una = ack;
	}
	if ((f->state & ULC_S_PROBE) && !ulc_seq_lt(ack, f->probe_seq)) {
		u32 dt = now - f->probe_t;
		f->state &= (u8)~ULC_S_PROBE;
		if (dt && dt <= ULC_PROBE_MAX) {
			ulc_rtt_sample(f, dt, now);
			ulc_rate_sample(g, ulc_rate(g->delivered - f->probe_dlv, dt), now);
			if (!g->full && dt > f->rtt_min + ulc_ms(g->target_ms + ulc_dlq(g)) + ULC_EXIT_SLACK)
				g->full = 1;  /* a queue: the link is full */
		}
	}
	if (!(f->state & ULC_S_WS) || !(f->state & ULC_S_ACTIVE))
		return ULC_NO_CLAMP;
	g->st_acks++;
	if (!g->full || f->dlv < ULC_STARTUP_BYTES)
		return ulc_startup_window(f);
	share = ulc_share(g, f, now, mss);
	return share ? share : ulc_startup_window(f);
}

/*
 * The raw 16-bit window to send for a segment with ACK `ack` and raw window `win`, given the
 * clamp's target in bytes (ULC_NO_CLAMP leaves it alone). Never above the server's window,
 * never zero unless the server sent zero, and never behind the highest right edge already
 * sent by a scale unit or more:
 * - at or above that edge, the target rounds up (never below the target);
 * - below it, the window holds the edge and rounds down, so the advertised edge may sit up
 *   to 2^shift - 1 bytes short of it. Rounding up there would move the edge forward on
 *   every ACK that advances by less than one unit, and the window would never shrink. The
 *   server's real window is larger, so those bytes are never refused.
 */
static inline u16 ulc_raw_window(const struct ulc_flow *f, u32 ack, u16 win, u32 target)
{
	u32 shift = f->wscale, orig = (u32)win << shift, raw;
	u32 keep = ((f->state & ULC_S_EDGE) && ulc_seq_gt(f->edge, ack)) ? f->edge - ack : 0;

	if (target == ULC_NO_CLAMP || !win)
		return win;
	if (target >= keep) {
		if (target >= orig)
			return win;
		raw = (target + (1u << shift) - 1u) >> shift;
	} else {
		if (keep >= orig)
			return win;
		raw = keep >> shift;
	}
	if (!raw)
		raw = 1;
	return (u16)(raw < win ? raw : win);
}

/* Record the right edge a segment really carried (after any rewrite). */
static inline void ulc_sent(struct ulc *g, struct ulc_flow *f, u32 ack, u16 win, u16 sent)
{
	u32 e = ack + ((u32)sent << f->wscale);

	if (sent < win)
		g->st_clamped++;
	if (!(f->state & ULC_S_EDGE) || ulc_seq_gt(e, f->edge)) {
		f->edge = e;
		f->state |= ULC_S_EDGE;
	}
}

/* Controller tick: ulc_tick_begin, ulc_tick_flow for every flow, ulc_tick_end. */
static inline void ulc_tick_begin(struct ulc *g, u32 now)
{
	ulc_roll(g, now);
	g->n_next = 0;
	g->n_sending = 0;
	g->rtt_next_base = 0;
	g->w_next = 0;
}

static inline void ulc_tick_flow(struct ulc *g, struct ulc_flow *f, u32 now)
{
	u32 idle;
	int sending;

	if (!(f->state & ULC_S_SNDHI))
		return;
	idle = now - f->last_ul;
	/* A sender the clamp holds back sends nothing until ACKs open its window, so bytes in
	 * flight keep a flow sending for up to 1 s without new data; with nothing in flight it
	 * has stopped 200 ms after its last data. */
	if (!(f->state & ULC_S_UNA) || ulc_seq_gt(f->snd_hi, f->una))
		sending = idle < ULC_IDLE_UNITS;
	else
		sending = idle < ULC_ACTIVE_UNITS;
	if (sending)
		f->state |= ULC_S_ACTIVE;
	else
		f->state &= (u8)~ULC_S_ACTIVE;
	if (!sending && idle > ULC_IDLE_UNITS)
		f->dlv = 0;
	if ((f->state & ULC_S_PROBE) && (u32)(now - f->probe_t) > ULC_PROBE_MAX)
		f->state &= (u8)~ULC_S_PROBE;
	if (!sending || !(f->state & ULC_S_WS))
		return;
	g->n_sending++;
	if (f->rtt_min && (!g->rtt_next_base || f->rtt_min < g->rtt_next_base))
		g->rtt_next_base = f->rtt_min;
	if (f->dlv >= ULC_STARTUP_BYTES)
		g->n_next++;
}

static inline void ulc_tick_end(struct ulc *g, u32 now)
{
	u32 round = g->rtt_next_base > ULC_ROUND_MIN ? g->rtt_next_base : ULC_ROUND_MIN;

	g->n_active = g->n_next;
	g->rtt_base = g->rtt_next_base;
	if (g->n_sending) {
		g->busy_t = now;
	} else if ((u32)(now - g->busy_t) > ULC_IDLE_UNITS && (g->full || g->full_bw)) {
		g->full = 0;          /* the next upload starts over */
		g->full_bw = 0;
		g->full_cnt = 0;
	}
	if (g->n_sending && !g->full && (u32)(now - g->round_t) >= round) {
		g->round_t = now;
		if (!g->full_bw)
			g->st_startups++;
		if (g->bw >= g->full_bw + (g->full_bw >> 2) && g->bw) {
			g->full_bw = g->bw;
			g->full_cnt = 0;
		} else if (++g->full_cnt >= ULC_FULL_ROUNDS) {
			g->full = 1;
		}
	}
	if (g->full && g->pulse_bytes && g->n_active && g->rtt_base && !ulc_before(now, g->pulse_next)) {
		g->pulse_next = now + ulc_ms(g->pulse_ms);
		g->pulse_until = now + g->rtt_base;
		g->st_pulses++;
	}
	g->w_total = (g->full && g->n_active && g->bw && g->rtt_base) ?
		     (u32)((((u64)g->bw * (u64)(g->rtt_base + ulc_ms(g->target_ms + ulc_dlq(g)))) >> 10) &
			   0xffffffffu) : 0;
}

#endif /* ULCLAMP_CORE_H */
