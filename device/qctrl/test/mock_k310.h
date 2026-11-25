/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright 2026 Centreville Tech, LLC. Host test harness for titan_qctrl; see device/qctrl/README.md. */
/*
 * mock_k310.h - a host stand-in for titan_k310_abi.h, so test_qctrl.c can compile the module
 * source itself (#include "../source/titan_qctrl.c") and drive its hook with built packets.
 *
 * It defines TITAN_K310_ABI_H, so the real header becomes empty, and provides the same
 * names: types, the few sk_buff/net_device fields the module reads, netfilter and hrtimer
 * constants, and the kernel functions the module imports (kernel-exports.txt). The kernel
 * functions are fakes that record what the module asked for; inet_proto_csum_replace4 is
 * the kernel's algorithm, so checksum results are real.
 */
#ifndef MOCK_K310_H
#define MOCK_K310_H
#define TITAN_K310_ABI_H 1

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef signed char        s8;
typedef signed short       s16;
typedef signed int         s32;
typedef signed long long   s64;
typedef u16                __be16;
typedef u32                __be32;
typedef u16                __sum16;
/* loff_t, size_t and ssize_t come from the host libc headers */
typedef u16                umode_t;

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

static inline u16 ntohs(u16 x) { return __builtin_bswap16(x); }
static inline u16 htons(u16 x) { return __builtin_bswap16(x); }
static inline u32 ntohl(u32 x) { return __builtin_bswap32(x); }
static inline u32 htonl(u32 x) { return __builtin_bswap32(x); }

struct list_head { struct list_head *next, *prev; };

struct module {
	char name[60];
	int (*init)(void);
	void (*exit)(void);
};

typedef union { s64 tv64; } ktime_t;
static inline ktime_t ktime_set_ns(s64 ns) { ktime_t kt; kt.tv64 = ns; return kt; }

struct net_device { char name[16]; };

/* Only the fields titan_qctrl.c reads or writes. ip_summed: 0 = CHECKSUM_NONE. */
struct sk_buff {
	struct net_device *dev;
	u32 len;
	u32 data_len;
	u16 protocol;
	u8 ip_summed;
	u8 *data;
	u8 buf[256];
};

#define NF_DROP    0
#define NF_ACCEPT  1
#define NF_STOLEN  2
#define NFPROTO_BRIDGE 7
#define NF_BR_FORWARD  2
#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD

typedef unsigned int nf_hookfn(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
			       const struct net_device *out, int (*okfn)(struct sk_buff *));
struct nf_hook_ops {
	struct list_head list;
	nf_hookfn *hook;
	struct module *owner;
	u8 pf;
	unsigned int hooknum;
	int priority;
};

#define CLOCK_MONOTONIC  1
#define HRTIMER_MODE_REL 1
#define HRTIMER_NORESTART 0
struct hrtimer { int armed; };
struct tasklet_struct { int x; };
struct tasklet_hrtimer {
	struct hrtimer timer;
	struct tasklet_struct tasklet;
	int (*function)(struct hrtimer *timer);
};

struct notifier_block {
	int (*notifier_call)(struct notifier_block *nb, unsigned long event, void *ptr);
	struct notifier_block *next;
	int priority;
};
#define NETDEV_DOWN        0x0002
#define NETDEV_UNREGISTER  0x0006
#define NETDEV_GOING_DOWN  0x0009
#define NETDEV_CHANGENAME  0x000A
#define NOTIFY_DONE        0x0000

#define TITAN_SOFTIRQ_MASK 0x0000ff00u
#define TITAN_HARDIRQ_MASK 0x03ff0000u
static inline u32 titan_preempt_count(void) { return 0x100u; } /* always in softirq */
static inline int titan_irqs_disabled(void) { return 0; }

struct inode;
struct file;
struct seq_file { char buf[8192]; size_t n; };
struct proc_dir_entry { int x; };
struct file_operations {
	struct module *owner;
	loff_t (*llseek)(struct file *, loff_t, int);
	ssize_t (*read)(struct file *, char *, size_t, loff_t *);
	ssize_t (*write)(struct file *, const char *, size_t, loff_t *);
	int (*open)(struct inode *, struct file *);
	int (*release)(struct inode *, struct file *);
};

/* ---- fake kernel ---- */
static s64 mock_ns;               /* ktime_get() */
static int mock_writable = 1;     /* skb_make_writable() result */
static int mock_consumed;
static struct proc_dir_entry mock_proc;

static inline ktime_t ktime_get(void) { return ktime_set_ns(mock_ns); }
static inline int printk(const char *fmt, ...) { (void)fmt; return 0; }
static inline int nf_register_hook(struct nf_hook_ops *reg) { (void)reg; return 0; }
static inline void nf_unregister_hook(struct nf_hook_ops *reg) { (void)reg; }
static inline void synchronize_net(void) {}
static inline int skb_make_writable(struct sk_buff *skb, unsigned int len)
{
	return mock_writable && len <= skb->len;
}

/* The kernel's inet_proto_csum_replace4 for ip_summed != CHECKSUM_PARTIAL. */
static inline u32 mock_csum_add(u32 sum, const u8 *p, u32 n)
{
	u32 i;
	for (i = 0; i + 1 < n; i += 2)
		sum += (u32)p[i] | ((u32)p[i + 1] << 8);   /* little-endian words, as csum_partial */
	if (n & 1)
		sum += p[n - 1];
	return sum;
}
static inline u16 mock_fold(u32 sum)
{
	sum = (sum & 0xffffu) + (sum >> 16);
	sum = (sum & 0xffffu) + (sum >> 16);
	return (u16)sum;
}
static inline void inet_proto_csum_replace4(__sum16 *sum, struct sk_buff *skb, __be32 from, __be32 to, int pseudohdr)
{
	u32 diff[2] = { ~from, to };
	(void)skb; (void)pseudohdr;
	*sum = (u16)~mock_fold(mock_csum_add((u16)~*sum, (const u8 *)diff, 8));
}
static inline void consume_skb(struct sk_buff *skb) { mock_consumed++; free(skb); }  /* the module owns it */
static inline void local_bh_disable(void) {}
static inline void local_bh_enable(void) {}
static inline void tasklet_hrtimer_init(struct tasklet_hrtimer *t, int (*fn)(struct hrtimer *), int c, int m)
{
	(void)c; (void)m; t->function = fn;
}
static inline int hrtimer_start(struct hrtimer *timer, ktime_t tim, int mode) { (void)tim; (void)mode; timer->armed = 1; return 0; }
static inline int hrtimer_cancel(struct hrtimer *timer) { timer->armed = 0; return 0; }
static inline void tasklet_kill(struct tasklet_struct *t) { (void)t; }
static inline struct proc_dir_entry *proc_create_data(const char *name, umode_t mode, struct proc_dir_entry *parent,
						       const struct file_operations *fops, void *data)
{
	(void)name; (void)mode; (void)parent; (void)fops; (void)data;
	return &mock_proc;
}
static inline void remove_proc_entry(const char *name, struct proc_dir_entry *parent) { (void)name; (void)parent; }
static inline int single_open(struct file *f, int (*show)(struct seq_file *, void *), void *d) { (void)f; (void)show; (void)d; return 0; }
static inline int single_release(struct inode *i, struct file *f) { (void)i; (void)f; return 0; }
static inline ssize_t seq_read(struct file *f, char *b, size_t n, loff_t *p) { (void)f; (void)b; (void)n; (void)p; return 0; }
static inline loff_t seq_lseek(struct file *f, loff_t o, int w) { (void)f; (void)o; (void)w; return 0; }
static inline int seq_printf(struct seq_file *m, const char *fmt, ...)
{
	va_list ap;
	int r;
	va_start(ap, fmt);
	r = vsnprintf(m->buf + m->n, sizeof(m->buf) - m->n, fmt, ap);
	va_end(ap);
	if (r > 0)
		m->n += (size_t)r < sizeof(m->buf) - m->n ? (size_t)r : sizeof(m->buf) - m->n - 1;
	return 0;
}
static inline int register_netdevice_notifier(struct notifier_block *nb) { (void)nb; return 0; }
static inline int unregister_netdevice_notifier(struct notifier_block *nb) { (void)nb; return 0; }
static inline unsigned long titan_copy_from_user(void *to, const void *from, unsigned long n)
{
	memcpy(to, from, n);
	return 0;
}

#endif /* MOCK_K310_H */
