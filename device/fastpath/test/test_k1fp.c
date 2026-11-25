/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_k1fp.c - Userspace unit, integration, and fuzz test suite for
 * k1fp 2.3 (device/fastpath/source/k1fp_core.h).
 *
 * Compiled and executed on the host with AddressSanitizer + UBSan via
 * device/fastpath/test/run.sh.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t  s32;

#include "../source/k1fp_core.h"

static int fails;

#define CHECK(cond, msg, ...) do { \
	if (!(cond)) { \
		fprintf(stderr, "FAIL %s:%d: " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
		fails++; \
	} \
} while (0)

static u64 rng_state = 0x9e3779b97f4a7c15ULL;
static u32 rnd(void)
{
	u64 x = rng_state;
	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	rng_state = x;
	return (u32)(x >> 32);
}

static void wr16(u8 *p, u16 v) { p[0] = (u8)(v >> 8); p[1] = (u8)v; }
static void wr32(u8 *p, u32 v)
{
	p[0] = (u8)(v >> 24); p[1] = (u8)(v >> 16);
	p[2] = (u8)(v >> 8);  p[3] = (u8)v;
}

static void ip4_fix_csum(u8 *iph)
{
	u32 sum = 0;
	int i;

	iph[10] = 0;
	iph[11] = 0;
	for (i = 0; i < 20; i += 2)
		sum += ((u16)iph[i] << 8) | iph[i + 1];
	while (sum >> 16)
		sum = (sum & 0xffffu) + (sum >> 16);
	wr16(iph + 10, (u16)(~sum));
}

static const u8 MAC_LAN[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01 };
static const u8 MAC_WAN[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02 };

static u32 mk_v4(u8 *b, u8 proto, u32 src, u32 dst, u16 sp, u16 dp,
		 u8 tcpflags, u8 tos, u16 frag, u8 ttl, u16 payload)
{
	u16 l4len = proto == 6 ? 20u : 8u;
	u16 tot = (u16)(20u + l4len + payload);

	memset(b, 0, K1_ETH_HLEN + tot);
	memcpy(b, MAC_LAN, 6);
	memcpy(b + 6, MAC_WAN, 6);
	wr16(b + 12, 0x0800u);
	b[14] = 0x45u;
	b[15] = tos;
	wr16(b + 16, tot);
	wr16(b + 20, frag);
	b[22] = ttl;
	b[23] = proto;
	wr32(b + 26, src);
	wr32(b + 30, dst);
	ip4_fix_csum(b + 14);
	wr16(b + 34, sp);
	wr16(b + 36, dp);
	if (proto == 6) {
		b[34 + 12] = 0x50u;
		b[34 + 13] = tcpflags;
	} else {
		wr16(b + 34 + 4, (u16)(8u + payload));
	}
	return K1_ETH_HLEN + tot;
}

/* Lower a TCP window and fix the checksum as titan_qctrl does (RFC 1624 eqn. 3). */
static void tcp_lower_win(u8 *th, u16 nw)
{
	u32 ow = k1_be16(th + 14), hc = k1_be16(th + 16), s;

	s = (~hc & 0xffffu) + (~ow & 0xffffu) + nw;
	s = (s & 0xffffu) + (s >> 16);
	s = (s & 0xffffu) + (s >> 16);
	wr16(th + 16, (u16)~s);
	wr16(th + 14, nw);
}

static u32 mk_v6(u8 *b, u8 nh, const u8 src[16], const u8 dst[16],
		 u16 sp, u16 dp, u8 tcpflags, u8 tc, u8 hlim, u16 payload)
{
	u16 l4len = nh == 6 ? 20u : 8u;
	u16 plen = (u16)(l4len + payload);

	memset(b, 0, K1_ETH_HLEN + 40u + plen);
	memcpy(b, MAC_LAN, 6);
	memcpy(b + 6, MAC_WAN, 6);
	wr16(b + 12, 0x86ddu);
	b[14] = (u8)(0x60u | (tc >> 4));
	b[15] = (u8)(tc << 4);
	wr16(b + 18, plen);
	b[20] = nh;
	b[21] = hlim;
	memcpy(b + 22, src, 16);
	memcpy(b + 38, dst, 16);
	wr16(b + 54, sp);
	wr16(b + 56, dp);
	if (nh == 6) {
		b[54 + 12] = 0x50u;
		b[54 + 13] = tcpflags;
	} else if (nh == 17) {
		wr16(b + 54 + 4, (u16)(8u + payload));
	}
	return K1_ETH_HLEN + 40u + plen;
}

static void test_classifier(void)
{
	u8 b[256];
	struct k1_pkt p;
	u32 n;
	/* RFC 3849 documentation IPv6 addresses (including PD delegated /64) */
	static const u8 V6_WAN[16] = { 0x20,0x01,0x0d,0xb8,0x00,0x01,0x00,0x00,0,0,0,0,0,0,0,1 };
	static const u8 V6_PD[16]  = { 0x20,0x01,0x0d,0xb8,0xca,0xfe,0x12,0x34,0,0,0,0,0,0,0,5 };
	static const u8 V6_MC[16]  = { 0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
	static const u8 V6_LL[16]  = { 0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
	static const u8 V6_UN[16]  = { 0 };
	static const u8 V6_LO[16]  = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };

	/* Valid IPv4 TCP + DF bit + ECN ECT(0) */
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x10, 0x2a, 0x4000, 64, 100);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_OK, "valid v4 tcp");
	CHECK(p.family == 4 && p.proto == 6 && p.dscp == 0x28 && p.l3len == 140 && p.hdrlen == 54,
	      "v4 tcp fields");

	/* Valid IPv4 TCP with Ethernet padding (tot_len=40, l3skb=46) */
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x10, 0, 0, 64, 0);
	CHECK(k1_parse(b, 60, 46, 1, &p) == K1W_OK && p.l3len == 40, "padded v4 tcp");

	/* Valid IPv4 UDP (DNS 53, QUIC 443, WireGuard 51820) */
	n = mk_v4(b, 17, 0xc6336401u, 0xcb007101u, 443, 51820, 0, 0, 0, 64, 60);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_OK && p.proto == 17 && p.hdrlen == 42, "valid v4 udp");

	/* Valid IPv6 TCP & UDP including IPv6 Prefix Delegation (/64) traffic */
	n = mk_v6(b, 6, V6_WAN, V6_PD, 443, 55000, 0x10, 0xb8 | 0x02, 64, 80);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_OK && p.family == 6 && p.dscp == 0xb8 && p.hdrlen == 74,
	      "valid v6 PD tcp");
	n = mk_v6(b, 17, V6_PD, V6_WAN, 55000, 443, 0, 0, 64, 40);
	CHECK(k1_parse(b, n, n - 14, 2, &p) == K1W_OK && p.family == 6 && p.proto == 17 && p.hdrlen == 62,
	      "valid v6 PD udp");

	/* K1W_SHORT */
	CHECK(k1_parse(b, 33, 19, 1, &p) == K1W_SHORT, "short eth+l3");
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x10, 0, 0, 64, 10);
	CHECK(k1_parse(b, 53, n - 14, 1, &p) == K1W_SHORT, "short v4 tcp");
	n = mk_v6(b, 6, V6_WAN, V6_PD, 443, 55000, 0x10, 0, 64, 10);
	CHECK(k1_parse(b, 73, n - 14, 1, &p) == K1W_SHORT, "short v6 tcp");

	/* K1W_MCAST_MAC (broadcast, IPv4 mcast, IPv6 mcast) */
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x10, 0, 0, 64, 10);
	memset(b, 0xff, 6);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_MCAST_MAC, "broadcast dst mac");
	b[0] = 0x01; b[1] = 0x00; b[2] = 0x5e;
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_MCAST_MAC, "mcast dst mac");

	/* K1W_SRC_MAC (multicast src MAC, all-zero src MAC) */
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x10, 0, 0, 64, 10);
	b[6] |= 1u;
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_SRC_MAC, "mcast src mac");
	memset(b + 6, 0, 6);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_SRC_MAC, "zero src mac");

	/* K1W_ETYPE (ARP, VLAN 802.1Q, QinQ 802.1ad, PPPoE) */
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x10, 0, 0, 64, 10);
	wr16(b + 12, 0x0806u); CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_ETYPE, "ARP");
	wr16(b + 12, 0x8100u); CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_ETYPE, "VLAN 802.1Q");
	wr16(b + 12, 0x88a8u); CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_ETYPE, "QinQ 802.1ad");
	wr16(b + 12, 0x8864u); CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_ETYPE, "PPPoE");

	/* K1W_V4HDR (IP options, wrong version, TTL == 0) */
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x10, 0, 0, 64, 10);
	b[14] = 0x46u; CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_V4HDR, "v4 options");
	b[14] = 0x55u; CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_V4HDR, "v4 bad ver");
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x10, 0, 0, 0, 10);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_V4HDR, "v4 ttl 0");

	/* K1W_V4FRAG */
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x10, 0, 0x2000, 64, 10);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_V4FRAG, "v4 MF");
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x10, 0, 0x0001, 64, 10);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_V4FRAG, "v4 frag off");

	/* K1W_V4LEN */
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x10, 0, 0, 64, 10);
	CHECK(k1_parse(b, n, 30, 1, &p) == K1W_V4LEN, "v4 tot > skb");
	wr16(b + 16, 36); ip4_fix_csum(b + 14);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_V4LEN, "v4 tcp tot < 40");

	/* K1W_V4ADDR (multicast, broadcast, loopback, unspecified even with unicast MAC!) */
	n = mk_v4(b, 17, 0xc6336401u, 0xe0000001u, 5000, 5000, 0, 0, 0, 64, 10);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_V4ADDR, "v4 mcast dst");
	n = mk_v4(b, 17, 0xc6336401u, 0xffffffffu, 5000, 5000, 0, 0, 0, 64, 10);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_V4ADDR, "v4 bcast dst");
	n = mk_v4(b, 17, 0x7f000001u, 0xcb007101u, 5000, 5000, 0, 0, 0, 64, 10);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_V4ADDR, "v4 loopback src");
	n = mk_v4(b, 17, 0x00000000u, 0xcb007101u, 5000, 5000, 0, 0, 0, 64, 10);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_V4ADDR, "v4 unspec src");

	/* K1W_V4CSUM */
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x10, 0, 0, 64, 10);
	b[24] ^= 0x01u;
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_V4CSUM, "v4 bad csum");

	/* K1W_V6HDR & K1W_V6LEN & K1W_V6ADDR */
	n = mk_v6(b, 6, V6_WAN, V6_PD, 443, 55000, 0x10, 0, 0, 20);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_V6HDR, "v6 hlim 0");
	n = mk_v6(b, 6, V6_WAN, V6_PD, 443, 55000, 0x10, 0, 64, 20);
	CHECK(k1_parse(b, n, 50, 1, &p) == K1W_V6LEN, "v6 plen > skb");
	n = mk_v6(b, 17, V6_WAN, V6_MC, 5000, 5000, 0, 0, 64, 10);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_V6ADDR, "v6 multicast dst");
	n = mk_v6(b, 17, V6_LL, V6_PD, 5000, 5000, 0, 0, 64, 10);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_V6ADDR, "v6 link-local src");
	n = mk_v6(b, 17, V6_UN, V6_PD, 5000, 5000, 0, 0, 64, 10);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_V6ADDR, "v6 unspec src");
	n = mk_v6(b, 17, V6_LO, V6_PD, 5000, 5000, 0, 0, 64, 10);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_V6ADDR, "v6 loopback src");

	/* K1W_L4PROTO (ICMPv4, ICMPv6 ND/RA/RS/NS/NA/MLD, IPv6 ext headers) */
	n = mk_v4(b, 1, 0xc6336401u, 0xcb007101u, 0, 0, 0, 0, 0, 64, 20);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_L4PROTO, "ICMPv4");
	n = mk_v6(b, 58, V6_WAN, V6_PD, 0, 0, 0, 0, 64, 20);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_L4PROTO, "ICMPv6");
	n = mk_v6(b, 44, V6_WAN, V6_PD, 0, 0, 0, 0, 64, 20);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_L4PROTO, "IPv6 fragment ext hdr");
	n = mk_v6(b, 0, V6_WAN, V6_PD, 0, 0, 0, 0, 64, 20);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_L4PROTO, "IPv6 hop-by-hop ext hdr");

	/* K1W_TCPFLAGS (SYN, FIN, RST, bad doff, doff > l3len) */
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x02, 0, 0, 64, 0);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_TCPFLAGS, "TCP SYN");
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x12, 0, 0, 64, 0);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_TCPFLAGS, "TCP SYN-ACK");
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x11, 0, 0, 64, 0);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_TCPFLAGS, "TCP FIN-ACK");
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x04, 0, 0, 64, 0);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_TCPFLAGS, "TCP RST");
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x10, 0, 0, 64, 0);
	b[34 + 12] = 0x40u; CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_TCPFLAGS, "TCP doff < 5");
	b[34 + 12] = 0x80u; CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_TCPFLAGS, "TCP doff > l3len");

	/* K1W_UDPPORT (DHCPv4 67/68, DHCPv6 546/547) */
	n = mk_v4(b, 17, 0xc6336401u, 0xcb007101u, 68, 67, 0, 0, 0, 64, 20);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_UDPPORT, "DHCPv4");
	n = mk_v4(b, 17, 0xc6336401u, 0xcb007101u, 67, 68, 0, 0, 0, 64, 20);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_UDPPORT, "DHCPv4 reply");
	n = mk_v6(b, 17, V6_PD, V6_WAN, 546, 547, 0, 0, 64, 20);
	CHECK(k1_parse(b, n, n - 14, 2, &p) == K1W_UDPPORT, "DHCPv6");
	n = mk_v6(b, 17, V6_WAN, V6_PD, 547, 546, 0, 0, 64, 20);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_UDPPORT, "DHCPv6 reply");
}

static void test_fuzz_parse(void)
{
	u8 buf[160];
	struct k1_pkt p;
	int i;

	for (i = 0; i < 2000000; i++) {
		u32 len = rnd() % sizeof(buf);
		u32 j;
		int w;

		for (j = 0; j + 4 <= len; j += 4) {
			u32 v = rnd();
			memcpy(buf + j, &v, 4);
		}
		for (; j < len; j++)
			buf[j] = (u8)rnd();
		if ((i & 3) == 0 && len >= 14) {
			buf[0] &= 0xfeu;
			buf[6] &= 0xfeu;
			buf[7] |= 1u;
			wr16(buf + 12, (i & 4) ? 0x86ddu : 0x0800u);
		}
		w = k1_parse(buf, len, len > 14 ? len - 14 : 0, (rnd() & 1) + 1, &p);
		CHECK(w >= 0 && w < K1W__N, "fuzz why out of range");
		if (w == K1W_OK) {
			CHECK(p.hdrlen <= K1_HDRMAX && p.hdrlen <= len, "fuzz hdrlen bounds");
			CHECK(p.family == 4 || p.family == 6, "fuzz family");
			CHECK(p.proto == 6 || p.proto == 17, "fuzz proto");
		}
	}
}

static void test_modes_and_qctrl_policy(void)
{
	/* Mode 0 (off) */
	CHECK(k1_mode_dir_policy(K1_MODE_OFF, 0, 6, 0) == K1P_OFF, "m0 dl tcp");
	CHECK(k1_mode_dir_policy(K1_MODE_OFF, 1, 17, 1) == K1P_OFF, "m0 ul udp");

	/* Mode 1 (observe): UL TCP yields to qctrl when active */
	CHECK(k1_mode_dir_policy(K1_MODE_OBSERVE, 0, 6, 0) == K1P_OBSERVE, "m1 dl tcp noq");
	CHECK(k1_mode_dir_policy(K1_MODE_OBSERVE, 1, 6, 0) == K1P_OBSERVE, "m1 ul tcp noq");
	CHECK(k1_mode_dir_policy(K1_MODE_OBSERVE, 0, 6, 1) == K1P_OBSERVE, "m1 dl tcp q");
	CHECK(k1_mode_dir_policy(K1_MODE_OBSERVE, 1, 17, 1) == K1P_OBSERVE, "m1 ul udp q");
	CHECK(k1_mode_dir_policy(K1_MODE_OBSERVE, 1, 6, 1) == K1P_QCTRL_STOCK, "m1 ul tcp q");

	/* Mode 2 (downlink only) */
	CHECK(k1_mode_dir_policy(K1_MODE_DL, 0, 6, 0) == K1P_FAST, "m2 dl tcp noq");
	CHECK(k1_mode_dir_policy(K1_MODE_DL, 0, 6, 1) == K1P_FAST, "m2 dl tcp q");
	CHECK(k1_mode_dir_policy(K1_MODE_DL, 0, 17, 1) == K1P_FAST, "m2 dl udp q");
	CHECK(k1_mode_dir_policy(K1_MODE_DL, 1, 6, 0) == K1P_OFF, "m2 ul tcp");
	CHECK(k1_mode_dir_policy(K1_MODE_DL, 1, 17, 0) == K1P_OFF, "m2 ul udp");

	/* Mode 3 (both directions) */
	CHECK(k1_mode_dir_policy(K1_MODE_BOTH, 0, 6, 0) == K1P_FAST, "m3 dl tcp noq");
	CHECK(k1_mode_dir_policy(K1_MODE_BOTH, 1, 6, 0) == K1P_FAST, "m3 ul tcp noq");
	CHECK(k1_mode_dir_policy(K1_MODE_BOTH, 0, 6, 1) == K1P_FAST, "m3 dl tcp q");
	CHECK(k1_mode_dir_policy(K1_MODE_BOTH, 1, 17, 1) == K1P_FAST, "m3 ul udp q");
	CHECK(k1_mode_dir_policy(K1_MODE_BOTH, 1, 6, 1) == K1P_QCTRL_STOCK, "m3 ul tcp q");
}

static void test_cbrs_and_proof_invariants(void)
{
	struct k1_tbl tbl;
	struct k1_pend pd;
	struct k1_pkt p;
	struct k1_flow *f;
	u8 b[256], mod[256];
	u32 n, now = 1000, seed = 0x12345678u;
	static const u8 V6_A[16] = { 0x20,0x01,0x0d,0xb8,0,0,0,1,0,0,0,0,0,0,0,1 };
	static const u8 V6_B[16] = { 0x20,0x01,0x0d,0xb8,0,0,0,2,0,0,0,0,0,0,0,2 };

	k1_flush(&tbl);
	memset(&pd, 0, sizeof(pd));

	/* 1. IPv4 CBRS grant loss (vendor iptables FORWARD DROP):
	 * Prove flow -> fast -> sample dropped before k1_ip4_post -> revoked! */
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x10, 0x02, 0, 64, 50);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_OK, "v4 parse");
	CHECK(k1_fast_check(&tbl, &p, now, 1, 20, seed, &f) == K1F_NOLEASE, "v4 nolease");
	k1_pend_begin(&pd, b, 1, &p, b, 0);
	CHECK(k1_stage_br(&pd, &tbl, b, 1, b, n, 0, 0, now, 1, 60, 20, seed) == K1S_BROK, "v4 brok");
	CHECK(k1_stage_ip4(&pd, &tbl, b, 1, b, n, 0, 0, now, 1, 60, 20, seed) == K1S_GRANTED, "v4 granted");
	CHECK(k1_pend_end(&pd, &tbl, now, seed) == 0, "v4 pend_end ok");
	CHECK(k1_fast_check(&tbl, &p, now + 5, 1, 20, seed, &f) == K1F_FAST, "v4 fast");

	/* At t = now + 20: sample triggers; vendor iptables FORWARD drops packet
	 * (k1_br_post is never reached OR k1_ip4_post is never reached). */
	CHECK(k1_fast_check(&tbl, &p, now + 20, 1, 20, seed, &f) == K1F_SAMPLE, "v4 sample");
	k1_pend_begin(&pd, b, 1, &p, b, 1);
	CHECK(k1_pend_end(&pd, &tbl, now + 20, seed) == 1, "v4 CBRS drop revokes lease");
	CHECK(k1_fast_check(&tbl, &p, now + 21, 1, 20, seed, &f) == K1F_EXPIRED, "v4 closed after revoke");

	/* 2. IPv6 CBRS grant loss (Witcher ebtables FORWARD DROP):
	 * Prove flow -> fast -> sample dropped in ebtables FORWARD before br_post/br_last -> revoked! */
	now = 2000;
	n = mk_v6(b, 6, V6_A, V6_B, 443, 55555, 0x10, 0x02, 64, 50);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_OK, "v6 parse");
	k1_pend_begin(&pd, b, 1, &p, b, 0);
	CHECK(k1_stage_br(&pd, &tbl, b, 1, b, n, 0, 0, now, 1, 60, 20, seed) == K1S_BROK, "v6 brok");
	CHECK(k1_stage_br_last(&pd, &tbl, b, 1, b, n, 0, 0, now, 1, 60, 20, seed) == K1S_GRANTED, "v6 granted");
	CHECK(k1_pend_end(&pd, &tbl, now, seed) == 0, "v6 pend_end ok");
	CHECK(k1_fast_check(&tbl, &p, now + 5, 1, 20, seed, &f) == K1F_FAST, "v6 fast");

	/* Witcher ebtables FORWARD DROP blocks sample before k1_br_post */
	CHECK(k1_fast_check(&tbl, &p, now + 20, 1, 20, seed, &f) == K1F_SAMPLE, "v6 sample");
	k1_pend_begin(&pd, b, 1, &p, b, 1);
	CHECK(k1_pend_end(&pd, &tbl, now + 20, seed) == 1, "v6 CBRS ebtables drop revokes lease");
	CHECK(k1_fast_check(&tbl, &p, now + 21, 1, 20, seed, &f) == K1F_EXPIRED, "v6 closed after revoke");

	/* Also verify mid-hook IPv6 drop (e.g. ip6tables via br_nf_post_routing between 301 and LAST) */
	now = 3000;
	k1_pend_begin(&pd, b, 1, &p, b, 0);
	CHECK(k1_stage_br(&pd, &tbl, b, 1, b, n, 0, 0, now, 1, 60, 20, seed) == K1S_BROK, "v6 brok2");
	/* dropped before k1_br_last -> no lease granted */
	CHECK(k1_pend_end(&pd, &tbl, now, seed) == 0 && !pd.granted, "v6 mid-hook drop denies lease");

	/* 3. Downlink ECN CE marking (titan_qctrl mode 4) allowed; DSCP/NAT/TTL/UL ECN rejected! */
	now = 4000;
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x10, 0x22, 0, 64, 50); /* DSCP=8, ECT(0)=2 */
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_OK, "v4 ecn parse");
	memcpy(mod, b, n);
	mod[15] |= 0x03u; /* ECT(0) -> CE */
	ip4_fix_csum(mod + 14);
	k1_pend_begin(&pd, b, 1, &p, b, 0);
	CHECK(k1_stage_br(&pd, &tbl, b, 1, mod, n, 0, 0, now, 1, 60, 20, seed) == K1S_BROK,
	      "DL v4 ECT->CE accepted");
	CHECK(k1_stage_ip4(&pd, &tbl, b, 1, mod, n, 0, 0, now, 1, 60, 20, seed) == K1S_GRANTED,
	      "DL v4 ECT->CE granted");
	k1_pend_end(&pd, &tbl, now, seed);

	/* Bad IPv4 checksum after ECN mark -> MODIFIED */
	mod[24] ^= 1u;
	k1_pend_begin(&pd, b, 1, &p, b, 0);
	CHECK(k1_stage_br(&pd, &tbl, b, 1, mod, n, 0, 0, now, 1, 60, 20, seed) == K1S_MODIFIED,
	      "DL v4 ECN bad csum rejected");
	k1_pend_end(&pd, &tbl, now, seed);

	/* DSCP rewrite -> MODIFIED */
	memcpy(mod, b, n);
	mod[15] = 0x2eu;
	ip4_fix_csum(mod + 14);
	k1_pend_begin(&pd, b, 1, &p, b, 0);
	CHECK(k1_stage_br(&pd, &tbl, b, 1, mod, n, 0, 0, now, 1, 60, 20, seed) == K1S_MODIFIED,
	      "DSCP change rejected");
	k1_pend_end(&pd, &tbl, now, seed);

	/* TCP RWND rewrite (simulating unexpected UL mangle) -> MODIFIED */
	memcpy(mod, b, n);
	mod[34 + 14] ^= 0x01u;
	k1_pend_begin(&pd, b, 2, &p, b, 0);
	CHECK(k1_stage_br(&pd, &tbl, b, 2, mod, n, 0, 0, now, 1, 60, 20, seed) == K1S_MODIFIED,
	      "TCP RWND change rejected");
	k1_pend_end(&pd, &tbl, now, seed);

	/* 3b. k1fp 2.3: titan_qctrl's upload clamp lowers the receive window of downlink ACKs.
	 *     Accepted only on downlink, only while titan_qctrl was live when the proof began,
	 *     only lower, only with a consistent checksum, and nothing else in the header. */
	now = 4500;
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 5299, 51234, 0x10, 0, 0, 64, 0); /* server ACK */
	wr16(b + 34 + 14, 0x2000u);
	wr16(b + 34 + 16, 0x5a17u);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_OK, "v4 ack parse");
	memcpy(mod, b, n);
	tcp_lower_win(mod + 34, 0x0123u);
	k1_pend_begin(&pd, b, 1, &p, b, 0);
	pd.qctrl = 1;
	CHECK(k1_stage_br(&pd, &tbl, b, 1, mod, n, 0, 0, now, 1, 60, 20, seed) == K1S_BROK,
	      "DL v4 window lowered by qctrl accepted");
	CHECK(k1_stage_ip4(&pd, &tbl, b, 1, mod, n, 0, 0, now, 1, 60, 20, seed) == K1S_GRANTED,
	      "DL v4 window lowered by qctrl granted");
	k1_pend_end(&pd, &tbl, now, seed);
	{
		u32 c4 = 0, k4;
		for (k4 = 0; k4 < 20; k4 += 2)   /* the rewrite keeps the TCP one's complement sum */
			c4 += k1_be16(b + 34 + k4) - k1_be16(mod + 34 + k4) + 0xffffu;
		CHECK(c4 % 0xffffu == 0, "qctrl rewrite keeps the TCP checksum sum");
	}
	k1_pend_begin(&pd, b, 1, &p, b, 0);      /* titan_qctrl not live: 2.2 behaviour */
	CHECK(k1_stage_br(&pd, &tbl, b, 1, mod, n, 0, 0, now, 1, 60, 20, seed) == K1S_MODIFIED,
	      "window change without qctrl rejected");
	k1_pend_end(&pd, &tbl, now, seed);
	k1_pend_begin(&pd, b, 2, &p, b, 0);      /* uplink: never */
	pd.qctrl = 1;
	CHECK(k1_stage_br(&pd, &tbl, b, 2, mod, n, 0, 0, now, 1, 60, 20, seed) == K1S_MODIFIED,
	      "UL window change rejected even with qctrl");
	k1_pend_end(&pd, &tbl, now, seed);
	memcpy(mod, b, n);
	tcp_lower_win(mod + 34, 0x2001u);         /* raised */
	k1_pend_begin(&pd, b, 1, &p, b, 0);
	pd.qctrl = 1;
	CHECK(k1_stage_br(&pd, &tbl, b, 1, mod, n, 0, 0, now, 1, 60, 20, seed) == K1S_MODIFIED,
	      "window raised rejected");
	k1_pend_end(&pd, &tbl, now, seed);
	memcpy(mod, b, n);
	wr16(mod + 34 + 14, 0x0123u);             /* lowered, checksum not fixed */
	k1_pend_begin(&pd, b, 1, &p, b, 0);
	pd.qctrl = 1;
	CHECK(k1_stage_br(&pd, &tbl, b, 1, mod, n, 0, 0, now, 1, 60, 20, seed) == K1S_MODIFIED,
	      "window lowered with a stale checksum rejected");
	k1_pend_end(&pd, &tbl, now, seed);
	memcpy(mod, b, n);
	tcp_lower_win(mod + 34, 0x0123u);
	mod[34 + 11] ^= 0x01u;                    /* and the ACK number */
	k1_pend_begin(&pd, b, 1, &p, b, 0);
	pd.qctrl = 1;
	CHECK(k1_stage_br(&pd, &tbl, b, 1, mod, n, 0, 0, now, 1, 60, 20, seed) == K1S_MODIFIED,
	      "window plus another TCP change rejected");
	k1_pend_end(&pd, &tbl, now, seed);
	memcpy(mod, b, n);
	tcp_lower_win(mod + 34, 0x0123u);
	mod[22] = 63;                             /* and the TTL */
	ip4_fix_csum(mod + 14);
	k1_pend_begin(&pd, b, 1, &p, b, 0);
	pd.qctrl = 1;
	CHECK(k1_stage_br(&pd, &tbl, b, 1, mod, n, 0, 0, now, 1, 60, 20, seed) == K1S_MODIFIED,
	      "window plus TTL change rejected");
	k1_pend_end(&pd, &tbl, now, seed);
	/* ECN CE and a lowered window together (a bidirectional flow's downlink data) */
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 5299, 51234, 0x10, 0x02, 0, 64, 40);
	wr16(b + 34 + 14, 0x4000u);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_OK, "v4 ect data parse");
	memcpy(mod, b, n);
	mod[15] |= 0x03u;
	ip4_fix_csum(mod + 14);
	tcp_lower_win(mod + 34, 0x0400u);
	k1_pend_begin(&pd, b, 1, &p, b, 0);
	pd.qctrl = 1;
	CHECK(k1_stage_br(&pd, &tbl, b, 1, mod, n, 0, 0, now, 1, 60, 20, seed) == K1S_BROK,
	      "CE mark plus lowered window accepted");
	k1_pend_end(&pd, &tbl, now, seed);
	/* IPv6 downlink ACK */
	{
		static const u8 s6[16] = { 0x20, 0x01, 0x0d, 0xb8, 1, [15] = 1 };
		static const u8 d6[16] = { 0x20, 0x01, 0x0d, 0xb8, 2, [15] = 2 };
		n = mk_v6(b, 6, s6, d6, 5299, 51234, 0x10, 0, 64, 0);
		wr16(b + 54 + 14, 0x2000u);
		CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_OK, "v6 ack parse");
		memcpy(mod, b, n);
		tcp_lower_win(mod + 54, 0x0042u);
		k1_pend_begin(&pd, b, 1, &p, b, 0);
		pd.qctrl = 1;
		CHECK(k1_stage_br(&pd, &tbl, b, 1, mod, n, 0, 0, now, 1, 60, 20, seed) == K1S_BROK,
		      "DL v6 window lowered by qctrl accepted");
		CHECK(k1_stage_br_last(&pd, &tbl, b, 1, mod, n, 0, 0, now, 1, 60, 20, seed) == K1S_GRANTED,
		      "DL v6 window lowered by qctrl granted");
		k1_pend_end(&pd, &tbl, now, seed);
	}
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x10, 0x22, 0, 64, 50);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_OK, "v4 parse again");

	/* Wrong port -> WRONGPORT */
	k1_pend_begin(&pd, b, 1, &p, b, 0);
	CHECK(k1_stage_br(&pd, &tbl, b, 2, b, n, 0, 0, now, 1, 60, 20, seed) == K1S_WRONGPORT,
	      "wrongport detected");
	k1_pend_end(&pd, &tbl, now, seed);

	/* Mark or priority change -> MODIFIED */
	k1_pend_begin(&pd, b, 1, &p, b, 0);
	CHECK(k1_stage_br(&pd, &tbl, b, 1, b, n, 0, 42, now, 1, 60, 20, seed) == K1S_MODIFIED,
	      "mark change rejected");
	k1_pend_end(&pd, &tbl, now, seed);

	/* Router MAC change -> K1F_MISMATCH -> re-proves cleanly with new MAC */
	now = 5000;
	n = mk_v4(b, 6, 0xc6336401u, 0xcb007101u, 443, 51234, 0x10, 0, 0, 64, 50);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_OK, "mac test parse");
	k1_grant(&tbl, &p, now, 1, 60, 20, seed);
	b[5] ^= 0x55u; /* router MAC changed */
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_OK, "new mac parse");
	CHECK(k1_fast_check(&tbl, &p, now + 5, 1, 20, seed, &f) == K1F_MISMATCH, "router MAC change -> mismatch");

	/* Vendor bridge hold state machine */
	{
		u8 in_hold = 0;
		CHECK(k1_hold_step(0, 0, &in_hold) == K1H_NONE && !in_hold, "hold none");
		CHECK(k1_hold_step(1, 0, &in_hold) == K1H_ENTER && in_hold, "hold enter");
		CHECK(k1_hold_step(1, 2, &in_hold) == K1H_HELD && in_hold, "hold held");
		CHECK(k1_hold_step(0, 1, &in_hold) == K1H_HELD && in_hold, "hold draining");
		CHECK(k1_hold_step(0, 0, &in_hold) == K1H_NONE && !in_hold, "hold exit");
	}

	/* Jiffies wrap around 0xffffffff -> 0 */
	now = 0xfffffffeu;
	k1_grant(&tbl, &p, now, 1, 60, 20, seed);
	CHECK(k1_fast_check(&tbl, &p, now + 10, 1, 20, seed, &f) == K1F_FAST, "wrap fast");
	CHECK(k1_fast_check(&tbl, &p, now + 20, 1, 20, seed, &f) == K1F_SAMPLE, "wrap sample");
	CHECK(k1_fast_check(&tbl, &p, now + 60, 1, 20, seed, &f) == K1F_EXPIRED, "wrap expired");

	/* 4. SKB pointer aliasing / local delivery cancellation (k1fp 2.1 root-cause regression):
	 *    Downlink SAS reply enters stock_cand, reverse-SNAT diverts to NF_BR_LOCAL_IN,
	 *    tcp_rcv_established frees skb and immediately re-allocates the exact same pointer
	 *    for the unit's outgoing SAS packet via br_dev_xmit -> br_deliver/br_flood_deliver
	 *    -> NF_BR_POST_ROUTING. Must NEVER produce K1S_WRONGPORT or K1S_MODIFIED! */
	now = 6000;
	k1_flush(&tbl);
	n = mk_v4(b, 6, 0x22626d2eu, 0xac144022u, 443, 45123, 0x10, 0, 0, 56, 0); /* 34.98.109.46 -> pdn_ip */
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_OK, "sas dl parse");
	k1_pend_begin(&pd, b, 1, &p, b, 0);
	/* Unrelated skb hitting LOCAL_IN must NOT cancel our active proof */
	CHECK(k1_pend_cancel(&pd, mod) == 0 && pd.active == 1, "unrelated skb does not cancel");
	/* Actual skb enters br_pass_frame_up (NF_BR_LOCAL_IN) -> cancels g.pend */
	CHECK(k1_pend_cancel(&pd, b) == 1 && pd.active == 0 && pd.cancelled == 1,
	      "LOCAL_IN cancels pending proof");
	/* Reused skb pointer `b` now carries outgoing 10.1.1.1 -> 34.98.109.46 out lte0pdn2 (FDB hit)
	 * and out eth0 (FDB miss -> br_flood_deliver). Both must be K1S_IGNORED. */
	mk_v4(mod, 6, 0x0a010101u, 0x22626d2eu, 45123, 443, 0x18, 0, 0, 64, 100);
	CHECK(k1_stage_br(&pd, &tbl, b, 2, mod, n, 0, 0, now, 1, 60, 20, seed) == K1S_IGNORED,
	      "reused skb on lte0pdn2 ignored (no false wrongport)");
	CHECK(k1_stage_br(&pd, &tbl, b, 1, mod, n, 0, 0, now, 1, 60, 20, seed) == K1S_IGNORED,
	      "reused skb flooded to eth0 ignored (no false modified)");
	CHECK(k1_pend_end(&pd, &tbl, now, seed) == 0 && !pd.cancelled, "no-lease cancel does not revoke");

	/* Fail-closed: if a flow HAD an active lease and turned local, k1_pend_end STILL revokes it */
	k1_grant(&tbl, &p, now, 1, 60, 20, seed);
	CHECK(k1_fast_check(&tbl, &p, now + 5, 1, 20, seed, &f) == K1F_FAST, "pre-local lease active");
	k1_pend_begin(&pd, b, 1, &p, b, 1);
	CHECK(k1_pend_cancel(&pd, b) == 1, "LOCAL_OUT/LOCAL_IN cancels leased flow");
	CHECK(k1_stage_br(&pd, &tbl, b, 2, mod, n, 0, 0, now + 5, 1, 60, 20, seed) == K1S_IGNORED,
	      "post-cancel stage ignored");
	CHECK(k1_pend_end(&pd, &tbl, now + 5, seed) == 1, "cancelled flow with lease still revoked");
	CHECK(k1_fast_check(&tbl, &p, now + 6, 1, 20, seed, &f) == K1F_EXPIRED, "lease revoked after cancel");
}

static void test_diag_ring(void)
{
	struct k1_diag_ring dr;
	struct k1_pend pd;
	struct k1_pkt p;
	u8 b[256], mod[256];
	u32 n, i;
	static const u8 V6_A[16] = { 0x20,0x01,0x0d,0xb8,0,0,0,1,0,0,0,0,0,0,0,1 };
	static const u8 V6_B[16] = { 0x20,0x01,0x0d,0xb8,0,0,0,2,0,0,0,0,0,0,0,2 };

	k1_diag_clear(&dr);
	CHECK(dr.total == 0, "diag clear total 0");

	/* IPv4 UDP with 120 bytes of secret payload: hdrlen=42 -> MUST capture at most 42 bytes! */
	n = mk_v4(b, 17, 0xc6336401u, 0xcb007101u, 53, 55000, 0, 0, 0, 64, 120);
	memset(b + 42, 0xaa, 120);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_OK && p.hdrlen == 42, "diag v4 udp parse");
	k1_pend_begin(&pd, b, 1, &p, b, 0);

	memcpy(mod, b, n);
	mod[0] ^= 0x02u; /* dmac */
	mod[15] = 0x28u; /* l3tos */
	mod[22] = 63u;   /* l3ttl */
	ip4_fix_csum(mod + 14); /* l3csum */
	mod[34] ^= 0x01u; /* l4port */
	k1_diag_record(&dr, &pd, 1000, K1_STG_BR_POST, K1S_MODIFIED, 1, mod, n, 7, 9);
	CHECK(dr.total == 1, "diag recorded 1");
	CHECK(dr.e[0].pre_len == 42 && dr.e[0].post_len == 42, "v4 udp captures 42 B (zero payload)");
	CHECK(dr.e[0].pre[42] == 0 && dr.e[0].post[42] == 0, "zero bytes past hdrlen");
	CHECK((dr.e[0].diff_mask & (K1D_DMAC | K1D_L3TOS | K1D_L3TTL | K1D_L3CSUM | K1D_L4PORT | K1D_PRIO | K1D_MARK)) ==
	      (K1D_DMAC | K1D_L3TOS | K1D_L3TTL | K1D_L3CSUM | K1D_L4PORT | K1D_PRIO | K1D_MARK),
	      "v4 diff mask exact (got 0x%x)", dr.e[0].diff_mask);
	CHECK((dr.e[0].diff_mask & (K1D_SMAC | K1D_ETYPE | K1D_L3ADDR | K1D_PORT | K1D_SHORT)) == 0,
	      "v4 diff no false bits");

	/* Wrongport + short/NULL safety */
	k1_diag_record(&dr, &pd, 1100, K1_STG_BR_POST, K1S_WRONGPORT, 2, NULL, 0, 0, 0);
	CHECK(dr.total == 2 && dr.e[1].reason == K1S_WRONGPORT && dr.e[1].post_len == 0,
	      "null eth safe");
	CHECK((dr.e[1].diff_mask & (K1D_PORT | K1D_SHORT)) == (K1D_PORT | K1D_SHORT),
	      "wrongport + short flags");

	/* IPv6 TCP (hdrlen=74 > K1_DIAG_MAX=64): capped at 64 B, still detects K1D_L4HDR in bytes 58..73 */
	n = mk_v6(b, 6, V6_A, V6_B, 443, 51234, 0x10, 0x00, 64, 80);
	CHECK(k1_parse(b, n, n - 14, 1, &p) == K1W_OK && p.hdrlen == 74, "diag v6 tcp parse");
	k1_pend_begin(&pd, b, 1, &p, b, 0);
	memcpy(mod, b, n);
	mod[14] |= 0x01u; /* TC high nibble -> K1D_L3TOS */
	mod[30] ^= 0x01u; /* src IPv6 -> K1D_L3ADDR */
	mod[68] ^= 0x01u; /* TCP window byte past 64 -> K1D_L4HDR */
	k1_diag_record(&dr, &pd, 1200, K1_STG_BR_LAST, K1S_MODIFIED, 1, mod, n, 0, 0);
	CHECK(dr.e[2].pre_len == K1_DIAG_MAX && dr.e[2].post_len == K1_DIAG_MAX, "v6 tcp capped at 64 B");
	CHECK((dr.e[2].diff_mask & (K1D_L3TOS | K1D_L3ADDR | K1D_L4HDR)) ==
	      (K1D_L3TOS | K1D_L3ADDR | K1D_L4HDR), "v6 diff detects TC, addr, and L4 past 64 B");

	/* Ring wrap-around past K1_DIAG_RING (16) */
	k1_diag_clear(&dr);
	for (i = 0; i < 25; i++)
		k1_diag_record(&dr, &pd, 2000u + i, K1_STG_IP4_POST, K1S_MODIFIED, 1, mod, n, 0, i);
	CHECK(dr.total == 25, "ring total == 25");
	for (i = 0; i < K1_DIAG_RING; i++) {
		u32 seq = (25u - K1_DIAG_RING) + i;
		const struct k1_diag_ent *e = &dr.e[seq & (K1_DIAG_RING - 1u)];
		CHECK(e->jiffies == 2000u + seq && e->mark_post == seq,
		      "ring wrap slot %u has seq %u", i, seq);
	}

	/* Cleared by zero */
	k1_diag_clear(&dr);
	CHECK(dr.total == 0 && dr.e[0].jiffies == 0 && dr.e[0].pre_len == 0, "diag cleared");
}

static void test_watchdog(void)
{
	struct k1_wd_cfg cfg = {
		.mod_limit = 20, .mod_win_ms = 10000,
		.mismatch_limit = 64, .stall_ms = 500, .ringfull_ms = 500
	};
	struct k1_wd_state w;
	u32 mod_cnt = 0;
	int i, r = K1_WD_NONE;

	/* Not active -> never trips */
	k1_wd_arm(&w, 0, 0, 0, 10);
	CHECK(k1_wd_tick(&w, &cfg, 0, 1, 1, 1, 1, 10, 999, 999, 999, 100) == K1_WD_NONE,
	      "inactive mode never trips");

	/* Modified burst inside window -> K1_WD_MODIFIED (both inline check and tick) */
	k1_wd_arm(&w, 100, 0, 0, 10);
	CHECK(k1_wd_check_mod(&w, &cfg, 1, 119, 0) == K1_WD_NONE, "inline mod below limit");
	CHECK(k1_wd_check_mod(&w, &cfg, 1, 120, 0) == K1_WD_MODIFIED, "inline mod trips");
	CHECK(k1_wd_tick(&w, &cfg, 1, 1, 0, 0, 0, 10, 119, 0, 0, 100) == K1_WD_NONE, "mod below limit");
	CHECK(k1_wd_tick(&w, &cfg, 1, 1, 0, 0, 0, 10, 120, 0, 0, 100) == K1_WD_MODIFIED, "mod trips");

	/* Boundary-straddling burst (10 before 5 s roll + 10 right after) MUST still trip */
	k1_wd_arm(&w, 0, 0, 0, 10);
	for (i = 0; i < 49; i++)
		CHECK(k1_wd_tick(&w, &cfg, 1, 1, 0, 0, 0, 10, 10, 0, 0, 100) == K1_WD_NONE, "pre-roll ok");
	/* Tick 50 rolls half-window: prev_mod_d=10, cur_mod_base=10 */
	CHECK(k1_wd_tick(&w, &cfg, 1, 1, 0, 0, 0, 10, 10, 0, 0, 100) == K1_WD_NONE, "roll tick ok");
	CHECK(k1_wd_check_mod(&w, &cfg, 1, 19, 0) == K1_WD_NONE, "straddle 19 below");
	CHECK(k1_wd_check_mod(&w, &cfg, 1, 20, 0) == K1_WD_MODIFIED, "straddle 20 trips");

	/* Sparse drip over 5 minutes (2 hits every 10 s = 60 total > 20) must NEVER trip */
	k1_wd_arm(&w, 0, 0, 0, 10);
	mod_cnt = 0;
	for (i = 0; i < 3000; i++) { /* 300 s at 100 ms ticks */
		if (i % 50 == 0)
			mod_cnt++; /* 1 hit every 5 s = 2 per 10 s window */
		r = k1_wd_tick(&w, &cfg, 1, 1, 0, 0, 0, 10, mod_cnt, 0, 0, 100);
		CHECK(r == K1_WD_NONE, "sparse drip must not trip (tick %d, total %u)", i, mod_cnt);
	}
	CHECK(mod_cnt == 60, "drip accumulated 60 total hits without tripping");

	/* Quiet decay: 15 hits, then 10 s quiet, then 15 more hits -> must NOT trip */
	k1_wd_arm(&w, 0, 0, 0, 10);
	CHECK(k1_wd_tick(&w, &cfg, 1, 1, 0, 0, 0, 10, 15, 0, 0, 100) == K1_WD_NONE, "first 15 ok");
	for (i = 0; i < 100; i++)
		CHECK(k1_wd_tick(&w, &cfg, 1, 1, 0, 0, 0, 10, 15, 0, 0, 100) == K1_WD_NONE, "quiet decay");
	CHECK(k1_wd_check_mod(&w, &cfg, 1, 30, 0) == K1_WD_NONE, "second 15 after decay ok");

	/* Wrongport burst -> K1_WD_WRONGPORT */
	k1_wd_arm(&w, 0, 5, 0, 10);
	CHECK(k1_wd_tick(&w, &cfg, 1, 1, 0, 0, 0, 10, 0, 25, 0, 100) == K1_WD_WRONGPORT, "wrongport trips");

	/* Mismatch storm inside 1 s -> K1_WD_MISMATCH */
	k1_wd_arm(&w, 0, 0, 50, 10);
	CHECK(k1_wd_tick(&w, &cfg, 1, 1, 0, 0, 0, 10, 0, 0, 113, 100) == K1_WD_NONE, "mismatch below");
	CHECK(k1_wd_tick(&w, &cfg, 1, 1, 0, 0, 0, 10, 0, 0, 114, 100) == K1_WD_MISMATCH, "mismatch trips");

	/* Slow router-MAC mismatches spread over 2 s -> must NOT trip */
	k1_wd_arm(&w, 0, 0, 0, 10);
	for (i = 1; i <= 25; i++) {
		r = k1_wd_tick(&w, &cfg, 1, 1, 0, 0, 0, 10, 0, 0, (u32)(i * 5), 100);
		CHECK(r == K1_WD_NONE, "slow mismatch must not trip (step %d)", i);
	}

	/* Frozen tail + stopped queue for 500 ms -> K1_WD_TXSTALL */
	k1_wd_arm(&w, 0, 0, 0, 42);
	for (i = 0; i < 4; i++)
		CHECK(k1_wd_tick(&w, &cfg, 1, 1, 0, 0, 1, 42, 0, 0, 0, 100) == K1_WD_NONE, "stall < 500");
	CHECK(k1_wd_tick(&w, &cfg, 1, 1, 0, 0, 1, 42, 0, 0, 0, 100) == K1_WD_TXSTALL, "stall at 500");

	/* Persistent full ring with moving tail for 500 ms -> K1_WD_RINGFULL */
	k1_wd_arm(&w, 0, 0, 0, 0);
	for (i = 1; i <= 4; i++)
		CHECK(k1_wd_tick(&w, &cfg, 1, 1, 0, 1, 0, (u32)i, 0, 0, 0, 100) == K1_WD_NONE, "full < 500");
	CHECK(k1_wd_tick(&w, &cfg, 1, 1, 0, 1, 0, 5, 0, 0, 0, 100) == K1_WD_RINGFULL, "full at 500");

	/* Bad ring -> immediate K1_WD_BADRING */
	k1_wd_arm(&w, 0, 0, 0, 0);
	CHECK(k1_wd_tick(&w, &cfg, 1, 1, 1, 0, 0, 0, 0, 0, 0, 100) == K1_WD_BADRING, "bad ring");

	/* Carrier down resets stall/ringfull counters */
	k1_wd_arm(&w, 0, 0, 0, 7);
	CHECK(k1_wd_tick(&w, &cfg, 1, 1, 0, 1, 1, 7, 0, 0, 0, 400) == K1_WD_NONE, "pre down");
	CHECK(k1_wd_tick(&w, &cfg, 1, 0, 1, 1, 1, 7, 0, 0, 0, 200) == K1_WD_NONE, "carrier down ok");
	CHECK(k1_wd_tick(&w, &cfg, 1, 1, 0, 1, 1, 7, 0, 0, 0, 400) == K1_WD_NONE, "reset after down");
}

static void test_tx_ring_model(void)
{
	/* Verify K1c F1/F6/F12 TX ring helper invariants */
	CHECK(k1_txd_used(K1_TXD_OWN, 0) == 1, "OWN bit means used");
	CHECK(k1_txd_used(0, 1500) == 1, "non-zero len means used");
	CHECK(k1_txd_used(0, K1_TXD_TER) == 0, "TER only means free");
	CHECK(k1_tx_need_reclaim(0, 1) == 1, "stopped queue needs reclaim");
	CHECK(k1_tx_need_reclaim(1, 0) == 1, "used tail needs reclaim");
	CHECK(k1_tx_need_reclaim(0, 0) == 0, "free & running -> no reclaim");
	CHECK(k1_tx_drained(0, 5, 5, 1, 1) == 1, "not running -> drained");
	CHECK(k1_tx_drained(1, 6, 5, 1, 1) == 1, "head moved -> drained");
	CHECK(k1_tx_drained(1, 5, 5, 0, 0) == 1, "empty & unstopped -> drained");
	CHECK(k1_tx_drained(1, 5, 5, 1, 0) == 0, "still in-flight -> not drained");

	{
		struct k1_txguard gd;
		memset(&gd, 0, sizeof(gd));
		CHECK(k1_tx_guard_step(&gd, 1, 1, 9, 10, 500) == 0, "guard seeds last_tail=9");
		CHECK(k1_tx_guard_step(&gd, 1, 1, 9, 499, 500) == 0, "guard < 500");
		CHECK(k1_tx_guard_step(&gd, 1, 1, 9, 1, 500) == 1, "guard trips at 500");
		CHECK(k1_tx_guard_step(&gd, 1, 1, 10, 100, 500) == 0, "tail progress resets guard");
	}
}

static void test_sha256_vectors(void)
{
	static const struct {
		const char *msg;
		const char *hex;
	} vecs[] = {
		{ "",
		  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
		{ "abc",
		  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
		{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
		{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		  "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1" },
	};
	size_t i;

	for (i = 0; i < sizeof(vecs) / sizeof(vecs[0]); i++) {
		struct k1_sha256_ctx ctx;
		u8 dig[32];
		char hex[65];
		size_t len = strlen(vecs[i].msg);
		size_t off = 0;
		int j;

		/* Feed in awkward chunk sizes (7 bytes) to exercise buffering across 64-byte boundaries */
		k1_sha256_init(&ctx);
		while (off < len) {
			u32 chunk = (u32)((len - off > 7) ? 7 : (len - off));
			k1_sha256_update(&ctx, (const u8 *)vecs[i].msg + off, chunk);
			off += chunk;
		}
		k1_sha256_final(&ctx, dig);
		for (j = 0; j < 32; j++)
			snprintf(hex + j * 2, 3, "%02x", dig[j]);
		CHECK(strcmp(hex, vecs[i].hex) == 0, "sha256 vector %zu got %s", i, hex);
	}
}

/*
 * Device re-acquire (k1fp 2.2). A small model of the module's device state:
 * NETDEV_UNREGISTER drops a pointer and sets mode 0; the 1 s housekeeping
 * pass feeds what it sees to k1_reacq_plan() and adopts what it returns.
 */
struct ra_world {
	int lan_id, wan_id, br_id;   /* registered device generation, 0 = absent */
	int lan_in, wan_in;          /* bridge generation the port belongs to, 0 = none */
	int br_is_bridge;
};
struct ra_mod {
	int lan, wan, br;            /* held generation, 0 = NULL */
	int mode;
	u32 dev_gone, reacq;
};

static void ra_unregister(struct ra_world *w, struct ra_mod *m, int which)
{
	int id = which == 0 ? w->lan_id : which == 1 ? w->wan_id : w->br_id;
	int *held = which == 0 ? &m->lan : which == 1 ? &m->wan : &m->br;

	if (which == 0) { w->lan_id = 0; w->lan_in = 0; }
	if (which == 1) { w->wan_id = 0; w->wan_in = 0; }
	if (which == 2) { w->br_id = 0; w->lan_in = 0; w->wan_in = 0; }
	if (id && *held == id) {
		*held = 0;
		m->mode = 0;
		m->dev_gone++;
	}
}

static u32 ra_hk(const struct ra_world *w, struct ra_mod *m)
{
	struct k1_reacq_in in;
	int l = m->lan ? m->lan : w->lan_id;
	int x = m->wan ? m->wan : w->wan_id;
	u32 plan;

	if (m->lan && m->wan && m->br)
		return 0;
	memset(&in, 0, sizeof(in));
	in.have_lan = m->lan != 0;
	in.have_wan = m->wan != 0;
	in.have_br = m->br != 0;
	in.lan_found = !m->lan && w->lan_id;
	in.wan_found = !m->wan && w->wan_id;
	if (l && x) {
		in.lan_port = w->lan_in != 0;
		in.wan_port = w->wan_in != 0;
		if (in.lan_port && in.wan_port) {
			in.same_br = w->lan_in == w->wan_in;
			in.br_valid = in.same_br && w->br_is_bridge && w->lan_in == w->br_id;
			in.br_matches_held = in.br_valid && m->br == w->br_id;
		}
	}
	plan = k1_reacq_plan(&in);
	if (!plan)
		return 0;
	if (plan & K1RA_LAN) m->lan = w->lan_id;
	if (plan & K1RA_WAN) m->wan = w->wan_id;
	if (plan & K1RA_BR)  m->br = w->br_id;
	m->mode = 0;
	m->reacq++;
	return plan;
}

static void test_reacquire(void)
{
	struct ra_world w = { 1, 1, 1, 1, 1, 1 };
	struct ra_mod m = { 1, 1, 1, 2, 0, 0 };
	struct k1_reacq_in in;
	u32 bits, plan;
	int gen = 1, step;

	/* Nothing missing: never a plan, whatever the other inputs say. */
	for (bits = 0; bits < 128u; bits++) {
		memset(&in, 0, sizeof(in));
		in.have_lan = in.have_wan = in.have_br = 1;
		in.lan_found = bits & 1u; in.wan_found = (bits >> 1) & 1u;
		in.lan_port = (bits >> 2) & 1u; in.wan_port = (bits >> 3) & 1u;
		in.same_br = (bits >> 4) & 1u; in.br_valid = (bits >> 5) & 1u;
		in.br_matches_held = (bits >> 6) & 1u;
		CHECK(k1_reacq_plan(&in) == 0, "plan with nothing missing (bits %u)", bits);
	}

	/* Exhaustive: a plan is exactly the missing set, and only for a shape
	 * init_module would accept that agrees with what is still held. */
	for (bits = 0; bits < 1024u; bits++) {
		u32 need = 0;
		int ok;

		memset(&in, 0, sizeof(in));
		in.have_lan = bits & 1u; in.have_wan = (bits >> 1) & 1u;
		in.have_br = (bits >> 2) & 1u;
		in.lan_found = (bits >> 3) & 1u; in.wan_found = (bits >> 4) & 1u;
		in.lan_port = (bits >> 5) & 1u; in.wan_port = (bits >> 6) & 1u;
		in.same_br = (bits >> 7) & 1u; in.br_valid = (bits >> 8) & 1u;
		in.br_matches_held = (bits >> 9) & 1u;
		if (!in.have_lan) need |= K1RA_LAN;
		if (!in.have_wan) need |= K1RA_WAN;
		if (!in.have_br)  need |= K1RA_BR;
		ok = need &&
		     (in.have_lan || in.lan_found) && (in.have_wan || in.wan_found) &&
		     in.lan_port && in.wan_port && in.same_br && in.br_valid &&
		     (!in.have_br || in.br_matches_held);
		plan = k1_reacq_plan(&in);
		CHECK(plan == (ok ? need : 0u), "plan %u for bits %u, want %u", plan, bits, ok ? need : 0u);
	}

	/* The bench case: a modem re-attach. The vendor scripts delete br0 (eth0
	 * stays registered but leaves the bridge), delete lte0pdn2, then create
	 * both again and add the ports one at a time. */
	ra_unregister(&w, &m, 2);
	CHECK(m.br == 0 && m.lan == 1 && m.mode == 0 && m.dev_gone == 1, "bridge gone");
	CHECK(ra_hk(&w, &m) == 0, "no adopt with no bridge");
	ra_unregister(&w, &m, 1);
	CHECK(m.wan == 0 && m.dev_gone == 2, "wan gone");
	CHECK(ra_hk(&w, &m) == 0, "no adopt with nothing back");
	w.br_id = 2;
	CHECK(ra_hk(&w, &m) == 0, "no adopt: empty new bridge");
	w.lan_in = 2;
	CHECK(ra_hk(&w, &m) == 0, "no adopt: only eth0 is a port");
	w.wan_id = 2;
	CHECK(ra_hk(&w, &m) == 0, "no adopt: lte0pdn2 registered but not a port");
	CHECK(m.wan == 0, "no reference kept on a half-built shape");
	w.wan_in = 2;
	CHECK(ra_hk(&w, &m) == (K1RA_WAN | K1RA_BR), "adopt lte0pdn2 and the bridge together");
	CHECK(m.lan == 1 && m.wan == 2 && m.br == 2 && m.mode == 0 && m.reacq == 1,
	      "state after re-acquire: mode stays 0");
	CHECK(ra_hk(&w, &m) == 0, "second pass is a no-op");

	/* Only the bearer is recreated; br0 stays. Adopt it only as a port of
	 * the bridge the module still holds. */
	m.mode = 2;
	ra_unregister(&w, &m, 1);
	CHECK(m.mode == 0 && m.wan == 0 && m.br == 2, "bearer gone, bridge held");
	w.wan_id = 3;
	CHECK(ra_hk(&w, &m) == 0, "new bearer not yet a port");
	w.wan_in = 7; /* a port of some other bridge */
	CHECK(ra_hk(&w, &m) == 0, "new bearer on another bridge");
	w.wan_in = 2;
	CHECK(ra_hk(&w, &m) == K1RA_WAN, "adopt the new bearer on the held bridge");
	CHECK(m.wan == 3 && m.reacq == 2, "bearer adopted");

	/* Both ports sit on something that is not a bridge device: refuse. */
	ra_unregister(&w, &m, 2);
	w.br_id = 4; w.lan_in = 4; w.wan_in = 4; w.br_is_bridge = 0;
	CHECK(ra_hk(&w, &m) == 0, "not a bridge device");
	w.br_is_bridge = 1;
	CHECK(ra_hk(&w, &m) == K1RA_BR, "bridge adopted once valid");

	/* Random churn: the module never holds a device that is not registered,
	 * never holds a mode other than 0 across a loss, and always converges
	 * within one pass once the full shape is back. */
	gen = 10;
	for (step = 0; step < 200000; step++) {
		u32 r = rnd() % 8u;

		if (r == 0) ra_unregister(&w, &m, 0);
		else if (r == 1) ra_unregister(&w, &m, 1);
		else if (r == 2) ra_unregister(&w, &m, 2);
		else if (r == 3 && !w.lan_id) w.lan_id = ++gen;
		else if (r == 4 && !w.wan_id) w.wan_id = ++gen;
		else if (r == 5 && !w.br_id) w.br_id = ++gen;
		else if (r == 6 && w.br_id && w.lan_id) w.lan_in = w.br_id;
		else if (r == 7 && w.br_id && w.wan_id) w.wan_in = w.br_id;
		if (rnd() & 1u) {
			int full = w.lan_id && w.wan_id && w.br_id &&
				   w.lan_in == w.br_id && w.wan_in == w.br_id;
			int missing = !m.lan || !m.wan || !m.br;
			int stale_br = m.br && m.br != w.br_id;

			plan = ra_hk(&w, &m);
			if (full && missing && !stale_br)
				CHECK(plan != 0 && m.lan && m.wan && m.br, "converges at step %d", step);
			if (plan)
				CHECK(m.mode == 0, "mode 0 after adopt at step %d", step);
		} else if (m.lan && m.wan && m.br && (rnd() & 3u) == 0) {
			m.mode = 2; /* userspace arms it again */
		}
		CHECK(!m.lan || m.lan == w.lan_id, "stale lan at step %d", step);
		CHECK(!m.wan || m.wan == w.wan_id, "stale wan at step %d", step);
		CHECK(!m.br || m.br == w.br_id, "stale br at step %d", step);
		CHECK(m.mode == 0 || (m.lan && m.wan && m.br), "mode %d with a device missing at step %d", m.mode, step);
		if (fails)
			break;
	}
	CHECK(m.dev_gone > 1000u && m.reacq > 100u, "churn exercised (gone %u, reacq %u)", m.dev_gone, m.reacq);
}

int main(void)
{
	test_classifier();
	test_fuzz_parse();
	test_modes_and_qctrl_policy();
	test_cbrs_and_proof_invariants();
	test_diag_ring();
	test_watchdog();
	test_tx_ring_model();
	test_reacquire();
	test_sha256_vectors();
	if (fails) {
		fprintf(stderr, "FAILED: %d check(s) failed\n", fails);
		return 1;
	}
	printf("PASS: all k1fp 2.3 host tests passed (classifier, 2M fuzz, modes/qctrl, qctrl upload window, CBRS v4+v6, local-alias, diag-ring, windowed watchdog, txring, device re-acquire, SHA-256)\n");
	return 0;
}
