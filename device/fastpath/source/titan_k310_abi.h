/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright 2026 Centreville Tech, LLC. Kernel module for Titan 4000 Witcher Edition; see device/fastpath/README.md. */
/*
 * titan_k310_abi.h - Binary-verified minimal Linux 3.10.0-uc0 ARMv7 UP ABI
 * for the Titan 4000 (GDM7243AP, vermagic "3.10.0-uc0 mod_unload ARMv7 ").
 *
 * Every struct size, field offset, calling convention, and exported symbol
 * below was verified directly from the unit's Linux 3.10.0-uc0 kernel image,
 * /proc/kallsyms, and vendor modules (CONFIG_MODVERSIONS=n, CONFIG_SMP=n,
 * CONFIG_PREEMPT_NONE=y, HZ=1000, VMSPLIT_2G, soft-float ARMv7 EABI).
 */
#ifndef TITAN_FASTPATH_K310_ABI_H
#define TITAN_FASTPATH_K310_ABI_H

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
typedef unsigned int       size_t;
typedef signed int         ssize_t;
typedef s64                loff_t;
typedef u16                umode_t;

#ifndef NULL
#define NULL ((void *)0)
#endif

#define offsetof(type, member) __builtin_offsetof(type, member)
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define barrier()   __asm__ __volatile__("" : : : "memory")

#define HZ           1000u
#define ETH_HLEN     14u
#define ETH_ALEN     6u
#define ETH_P_IP     0x0800u
#define ETH_P_IPV6   0x86DDu

/* Linux errno values */
#define ENOENT       2
#define EIO          5
#define ENOMEM       12
#define EFAULT       14
#define EBUSY        16
#define ENODEV       19
#define EINVAL       22
#define ERANGE       34
#define EOPNOTSUPP   95
#define ENETDOWN     100

/* printk log levels */
#define KERN_CRIT    "\001" "2"
#define KERN_ERR     "\001" "3"
#define KERN_WARNING "\001" "4"
#define KERN_INFO    "\001" "6"

/* Kernel list_head */
struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

static inline void init_list_head(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

/*
 * struct module (size = 328 = 0x148 bytes):
 *   +0x0c: char name[60]
 *   +0xbc: int (*init)(void)
 *   +0x140: void (*exit)(void)
 */
struct module {
	u8   _pad0[0x0c];
	char name[60];
	u8   _pad1[0xbc - 0x0c - 60];
	int  (*init)(void);
	u8   _pad2[0x140 - 0xbc - 4];
	void (*exit)(void);
	u8   _pad3[0x148 - 0x140 - 4];
};
_Static_assert(sizeof(struct module) == 0x148, "struct module size != 0x148");
_Static_assert(offsetof(struct module, name) == 0x0c, "module.name != 0x0c");
_Static_assert(offsetof(struct module, init) == 0xbc, "module.init != 0xbc");
_Static_assert(offsetof(struct module, exit) == 0x140, "module.exit != 0x140");

/*
 * struct timer_list (size = 0x1c = 28 bytes, UP, no lockdep/debugobjects):
 *   +0x00: list_head entry
 *   +0x08: unsigned long expires
 *   +0x0c: void *base
 *   +0x10: void (*function)(unsigned long)
 *   +0x14: unsigned long data
 *   +0x18: int slack
 */
struct timer_list {
	struct list_head entry;
	unsigned long    expires;
	void            *base;
	void           (*function)(unsigned long);
	unsigned long    data;
	int              slack;
};
_Static_assert(sizeof(struct timer_list) == 0x1c, "timer_list size != 0x1c");
_Static_assert(offsetof(struct timer_list, function) == 0x10, "timer.function != 0x10");
_Static_assert(offsetof(struct timer_list, data) == 0x14, "timer.data != 0x14");

/*
 * struct work_struct (size = 0x10 = 16 bytes) and
 * struct delayed_work (size = 0x34 = 52 bytes):
 * Proven from init_module / k1_hk disassembly on 3.10.0-uc0.
 */
struct work_struct {
	long             data;
	struct list_head entry;
	void           (*func)(struct work_struct *work);
};
_Static_assert(sizeof(struct work_struct) == 0x10, "work_struct size != 0x10");
_Static_assert(offsetof(struct work_struct, entry) == 0x04, "work.entry != 0x04");
_Static_assert(offsetof(struct work_struct, func) == 0x0c, "work.func != 0x0c");

struct workqueue_struct;

struct delayed_work {
	struct work_struct       work;
	struct timer_list        timer;
	struct workqueue_struct *wq;
	int                      cpu;
};
_Static_assert(sizeof(struct delayed_work) == 0x34, "delayed_work size != 0x34");
_Static_assert(offsetof(struct delayed_work, timer) == 0x10, "dwork.timer != 0x10");

#define WORK_DATA_INIT_BITS   (~0x1fL) /* WORK_STRUCT_NO_POOL = 31 << 5 -> 0xffffffe0 */
#define TIMER_IRQSAFE         0x0002u
#define WORK_CPU_UNBOUND      1        /* NR_CPUS on UP */

/*
 * struct sk_buff (size = 0xd8 with GCT tail pad; never allocated or sized here):
 *   +0x14: struct net_device *dev
 *   +0x50: u32 len
 *   +0x54: u32 data_len
 *   +0x60: u32 priority
 *   +0x64: u8 flags0 (bits 2..3 = ip_summed)
 *   +0x65: u8 flags1 (bits 0..2 = pkt_type)
 *   +0x66: __be16 protocol
 *   +0x82: u16 vlan_tci (bit 12 = VLAN_TAG_PRESENT)
 *   +0x8c: u32 mark
 *   +0xa4: u8 *mac_header (pointer on 32-bit 3.10)
 *   +0xa8: u8 *tail       (pointer on 32-bit 3.10)
 *   +0xac: u8 *end        (struct skb_shared_info *)
 *   +0xb0: u8 *head
 *   +0xb4: u8 *data
 *   +0xbc: int users      (atomic_t)
 */
struct net_device;

struct sk_buff {
	struct sk_buff    *next;
	struct sk_buff    *prev;
	u8                 _pad0[0x14 - 0x08];
	struct net_device *dev;
	u8                 _pad1[0x50 - 0x18];
	u32                len;
	u32                data_len;
	u8                 _pad2[0x60 - 0x58];
	u32                priority;
	u8                 flags0;
	u8                 flags1;
	__be16             protocol;
	u8                 _pad3[0x82 - 0x68];
	u16                vlan_tci;
	u8                 _pad4[0x8c - 0x84];
	u32                mark;
	u8                 _pad5[0xa4 - 0x90];
	u8                *mac_header;
	u8                *tail;
	u8                *end;
	u8                *head;
	u8                *data;
	u8                 _pad6[0xbc - 0xb8];
	int                users;
};
_Static_assert(offsetof(struct sk_buff, dev) == 0x14, "skb.dev != 0x14");
_Static_assert(offsetof(struct sk_buff, len) == 0x50, "skb.len != 0x50");
_Static_assert(offsetof(struct sk_buff, data_len) == 0x54, "skb.data_len != 0x54");
_Static_assert(offsetof(struct sk_buff, priority) == 0x60, "skb.priority != 0x60");
_Static_assert(offsetof(struct sk_buff, flags0) == 0x64, "skb.flags0 != 0x64");
_Static_assert(offsetof(struct sk_buff, flags1) == 0x65, "skb.flags1 != 0x65");
_Static_assert(offsetof(struct sk_buff, protocol) == 0x66, "skb.protocol != 0x66");
_Static_assert(offsetof(struct sk_buff, vlan_tci) == 0x82, "skb.vlan_tci != 0x82");
_Static_assert(offsetof(struct sk_buff, mark) == 0x8c, "skb.mark != 0x8c");
_Static_assert(offsetof(struct sk_buff, mac_header) == 0xa4, "skb.mac_header != 0xa4");
_Static_assert(offsetof(struct sk_buff, tail) == 0xa8, "skb.tail != 0xa8");
_Static_assert(offsetof(struct sk_buff, end) == 0xac, "skb.end != 0xac");
_Static_assert(offsetof(struct sk_buff, head) == 0xb0, "skb.head != 0xb0");
_Static_assert(offsetof(struct sk_buff, data) == 0xb4, "skb.data != 0xb4");
_Static_assert(offsetof(struct sk_buff, users) == 0xbc, "skb.users != 0xbc");

/* skb_shared_info: gso_size at +0x02 (proven at br_dev_queue_push_xmit 0x80351008) */
struct skb_shared_info_min {
	u8  nr_frags;
	u8  tx_flags;
	u16 gso_size;
};
_Static_assert(offsetof(struct skb_shared_info_min, gso_size) == 2, "shinfo.gso_size != 2");

#define CHECKSUM_NONE         0u
#define CHECKSUM_COMPLETE     2u
#define PACKET_LOOPBACK       5u
#define VLAN_TAG_PRESENT      0x1000u

static inline u32 skb_headlen(const struct sk_buff *skb)
{
	return skb->len - skb->data_len;
}

static inline int skb_is_gso(const struct sk_buff *skb)
{
	const struct skb_shared_info_min *sh = (const struct skb_shared_info_min *)skb->end;
	return sh && sh->gso_size != 0;
}

static inline int skb_vlan_present(const struct sk_buff *skb)
{
	return (skb->vlan_tci & VLAN_TAG_PRESENT) != 0;
}

static inline u8 skb_pkt_type(const struct sk_buff *skb)
{
	return skb->flags1 & 0x07u;
}

static inline void skb_clear_csum_complete(struct sk_buff *skb)
{
	if (((skb->flags0 >> 2) & 0x03u) == CHECKSUM_COMPLETE)
		skb->flags0 &= (u8)~0x0cu; /* CHECKSUM_NONE = 0 */
}

/* Linear-only trim (caller guarantees skb->data_len == 0 and len <= skb->len) */
static inline void skb_trim_linear(struct sk_buff *skb, u32 len)
{
	if (skb->len > len) {
		skb->len = len;
		skb->tail = skb->data + len;
	}
}

/*
 * rx_handler_result_t, struct net_device_ops, struct netdev_queue, struct net_device.
 * All offsets verified against netdev_rx_handler_register, br_add_if, br_dev_xmit,
 * gdm_eth_finish_xmit_tasklet, and abi_probe.o on 3.10.0-uc0.
 */
enum rx_handler_result {
	RX_HANDLER_CONSUMED = 0,
	RX_HANDLER_ANOTHER,
	RX_HANDLER_EXACT,
	RX_HANDLER_PASS,
};
typedef enum rx_handler_result rx_handler_result_t;
typedef rx_handler_result_t rx_handler_func_t(struct sk_buff **pskb);

struct net_device_ops {
	u8   _pad0[0x10];
	int (*ndo_start_xmit)(struct sk_buff *skb, struct net_device *dev);
};
_Static_assert(offsetof(struct net_device_ops, ndo_start_xmit) == 0x10, "ndo_start_xmit != 0x10");

struct netdev_queue {
	u8            _pad0[0x3c];
	unsigned long state;
};
_Static_assert(offsetof(struct netdev_queue, state) == 0x3c, "netdev_queue.state != 0x3c");

#define IFF_UP                 0x0001u
#define IFF_BRIDGE_PORT        0x4000u
#define LINK_STATE_START_BIT   (1u << 0)
#define LINK_STATE_NOCARRIER   (1u << 2)
#define QUEUE_STATE_DRV_XOFF   (1u << 0)
#define NETDEV_PRIV_OFFSET     0x400u

struct net_device {
	char                        name[16];            /* +0x000 */
	u8                          _pad0[0x2c - 0x10];
	unsigned long               state;               /* +0x02c */
	struct list_head            dev_list;            /* +0x030 */
	u8                          _pad1[0xe8 - 0x38];
	const struct net_device_ops *netdev_ops;         /* +0x0e8 */
	u8                          _pad2[0xf4 - 0xec];
	unsigned int                flags;               /* +0x0f4 */
	unsigned int                priv_flags;          /* +0x0f8 */
	u8                          _pad3[0x104 - 0xfc];
	unsigned int                mtu;                 /* +0x104 */
	u8                          _pad4[0x190 - 0x108];
	u8                         *dev_addr;            /* +0x190 */
	rx_handler_func_t          *rx_handler;          /* +0x194 */
	void                       *rx_handler_data;     /* +0x198 */
	u8                          _pad5[0x1c0 - 0x19c];
	struct netdev_queue        *_tx;                 /* +0x1c0 */
	u8                          _pad6[0x1f8 - 0x1c4];
	int                        *pcpu_refcnt;         /* +0x1f8 */
};
_Static_assert(offsetof(struct net_device, name) == 0x00, "nd.name != 0x00");
_Static_assert(offsetof(struct net_device, state) == 0x2c, "nd.state != 0x2c");
_Static_assert(offsetof(struct net_device, dev_list) == 0x30, "nd.dev_list != 0x30");
_Static_assert(offsetof(struct net_device, netdev_ops) == 0xe8, "nd.netdev_ops != 0xe8");
_Static_assert(offsetof(struct net_device, flags) == 0xf4, "nd.flags != 0xf4");
_Static_assert(offsetof(struct net_device, priv_flags) == 0xf8, "nd.priv_flags != 0xf8");
_Static_assert(offsetof(struct net_device, mtu) == 0x104, "nd.mtu != 0x104");
_Static_assert(offsetof(struct net_device, dev_addr) == 0x190, "nd.dev_addr != 0x190");
_Static_assert(offsetof(struct net_device, rx_handler) == 0x194, "nd.rx_handler != 0x194");
_Static_assert(offsetof(struct net_device, rx_handler_data) == 0x198, "nd.rx_handler_data != 0x198");
_Static_assert(offsetof(struct net_device, _tx) == 0x1c0, "nd._tx != 0x1c0");
_Static_assert(offsetof(struct net_device, pcpu_refcnt) == 0x1f8, "nd.pcpu_refcnt != 0x1f8");

static inline void *netdev_priv_ptr(const struct net_device *d)
{
	return (void *)((unsigned long)d + NETDEV_PRIV_OFFSET);
}

static inline int netif_running(const struct net_device *d)
{
	return (d->state & LINK_STATE_START_BIT) != 0;
}

static inline int netif_carrier_ok(const struct net_device *d)
{
	return (d->state & LINK_STATE_NOCARRIER) == 0;
}

static inline int netif_queue_stopped(const struct net_device *d)
{
	return d->_tx && (d->_tx->state & QUEUE_STATE_DRV_XOFF) != 0;
}

/* struct net: dev_base_head at +0x68 (verified in k1_ports_update disassembly) */
struct net {
	u8               _pad0[0x68];
	struct list_head dev_base_head;
};
_Static_assert(offsetof(struct net, dev_base_head) == 0x68, "net.dev_base_head != 0x68");

/* Netfilter hooks */
#define NF_DROP              0u
#define NF_ACCEPT            1u
#define NF_STOLEN            2u
#define NF_QUEUE             3u
#define NF_REPEAT            4u

#define NFPROTO_IPV4         2u
#define NFPROTO_BRIDGE       7u
#define NFPROTO_NUMPROTO     13u
#define NF_MAX_HOOKS         8u

#define NF_INET_POST_ROUTING 4u
#define NF_BR_FORWARD        2u
#define NF_BR_POST_ROUTING   4u

#define NF_BR_PRI_NAT_SRC    300
#define NF_BR_PRI_LAST       2147483647
#define NF_IP_PRI_LAST       2147483647

typedef unsigned int nf_hookfn(unsigned int hooknum,
			       struct sk_buff *skb,
			       const struct net_device *in,
			       const struct net_device *out,
			       int (*okfn)(struct sk_buff *));

struct nf_hook_ops {
	struct list_head list;      /* +0x00 */
	nf_hookfn       *hook;      /* +0x08 */
	struct module   *owner;     /* +0x0c */
	u8               pf;        /* +0x10 */
	u8               _pad[3];
	unsigned int     hooknum;   /* +0x14 */
	int              priority;  /* +0x18 */
};
_Static_assert(sizeof(struct nf_hook_ops) == 0x1c, "nf_hook_ops size != 0x1c");
_Static_assert(offsetof(struct nf_hook_ops, hook) == 0x08, "nf_hook_ops.hook != 0x08");
_Static_assert(offsetof(struct nf_hook_ops, owner) == 0x0c, "nf_hook_ops.owner != 0x0c");
_Static_assert(offsetof(struct nf_hook_ops, pf) == 0x10, "nf_hook_ops.pf != 0x10");
_Static_assert(offsetof(struct nf_hook_ops, hooknum) == 0x14, "nf_hook_ops.hooknum != 0x14");
_Static_assert(offsetof(struct nf_hook_ops, priority) == 0x18, "nf_hook_ops.priority != 0x18");

/* Netdevice notifier */
struct notifier_block {
	int (*notifier_call)(struct notifier_block *nb, unsigned long event, void *ptr);
	struct notifier_block *next;
	int priority;
};
_Static_assert(sizeof(struct notifier_block) == 12, "notifier_block size != 12");

#define NETDEV_UP          0x0001u
#define NETDEV_DOWN        0x0002u
#define NETDEV_CHANGE      0x0004u
#define NETDEV_UNREGISTER  0x0006u
#define NETDEV_CHANGEMTU   0x0007u
#define NETDEV_CHANGEADDR  0x0008u
#define NETDEV_GOING_DOWN  0x0009u
#define NETDEV_CHANGENAME  0x000au
#define NETDEV_JOIN        0x0014u
#define NOTIFY_DONE        0

/* procfs / seq_file / file_operations */
struct inode;
struct file;
struct seq_file;
struct proc_dir_entry;

struct file_operations {
	struct module *owner;                                               /* +0x00 */
	loff_t (*llseek)(struct file *, loff_t, int);                       /* +0x04 */
	ssize_t (*read)(struct file *, char *, size_t, loff_t *);           /* +0x08 */
	ssize_t (*write)(struct file *, const char *, size_t, loff_t *);    /* +0x0c */
	u8 _pad1[0x2c - 0x10];
	int (*open)(struct inode *, struct file *);                         /* +0x2c */
	void *_flush;                                                       /* +0x30 */
	int (*release)(struct inode *, struct file *);                      /* +0x34 */
	u8 _pad2[0x70 - 0x38];
};
_Static_assert(offsetof(struct file_operations, llseek) == 0x04, "fops.llseek != 0x04");
_Static_assert(offsetof(struct file_operations, read) == 0x08, "fops.read != 0x08");
_Static_assert(offsetof(struct file_operations, write) == 0x0c, "fops.write != 0x0c");
_Static_assert(offsetof(struct file_operations, open) == 0x2c, "fops.open != 0x2c");
_Static_assert(offsetof(struct file_operations, release) == 0x34, "fops.release != 0x34");

/* Execution-context and IRQ helpers (ARMv7 UP, 8 KB thread_info stack) */
#define TITAN_SOFTIRQ_MASK 0x0000ff00u
#define TITAN_HARDIRQ_MASK 0x03ff0000u

static inline u32 titan_preempt_count(void)
{
	unsigned long sp;
	__asm__ __volatile__("mov %0, sp" : "=r"(sp));
	return *(volatile u32 *)((sp & ~0x1fffUL) + 4);
}

static inline int titan_irqs_disabled(void)
{
	unsigned long f;
	__asm__ __volatile__("mrs %0, cpsr" : "=r"(f) : : "memory");
	return (f & 0x80UL) != 0;
}

static inline unsigned long titan_irq_save(void)
{
	unsigned long flags;
	__asm__ __volatile__(
		"mrs %0, cpsr\n\t"
		"cpsid i"
		: "=r"(flags)
		:
		: "memory");
	return flags;
}

static inline void titan_irq_restore(unsigned long flags)
{
	__asm__ __volatile__(
		"msr cpsr_c, %0"
		:
		: "r"(flags)
		: "memory");
}

/* UP per-cpu net_device reference counting (matches init_module+0x3c8) */
static inline void dev_hold(struct net_device *d)
{
	unsigned long flags = titan_irq_save();
	(*d->pcpu_refcnt)++;
	titan_irq_restore(flags);
}

static inline void dev_put(struct net_device *d)
{
	unsigned long flags = titan_irq_save();
	(*d->pcpu_refcnt)--;
	titan_irq_restore(flags);
}

static inline int ether_addr_equal(const u8 *a, const u8 *b)
{
	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) |
		(a[3] ^ b[3]) | (a[4] ^ b[4]) | (a[5] ^ b[5])) == 0;
}

/* Exported kernel symbols (every one verified in __ksymtab of 3.10.0-uc0) */
extern volatile unsigned long jiffies;
extern struct net init_net;
extern struct workqueue_struct *system_wq;
extern struct list_head nf_hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS];

extern int printk(const char *fmt, ...);
extern unsigned long kallsyms_lookup_name(const char *name);
extern long probe_kernel_read(void *dst, const void *src, size_t size);
extern long probe_kernel_write(void *dst, const void *src, size_t size);
extern void v7_coherent_kern_range(unsigned long start, unsigned long end);
extern int netif_rx(struct sk_buff *skb);
extern int dev_queue_xmit(struct sk_buff *skb);
extern u8 *skb_push(struct sk_buff *skb, unsigned int len);
extern void kfree_skb(struct sk_buff *skb);
extern struct net_device *dev_get_by_name(struct net *net, const char *name);
extern void rtnl_lock(void);
extern void rtnl_unlock(void);
extern int nf_register_hooks(struct nf_hook_ops *reg, unsigned int n);
extern void nf_unregister_hooks(struct nf_hook_ops *reg, unsigned int n);
extern int register_netdevice_notifier(struct notifier_block *nb);
extern int unregister_netdevice_notifier(struct notifier_block *nb);
extern void synchronize_net(void);
extern void local_bh_disable(void);
extern void local_bh_enable(void);
extern void init_timer_key(struct timer_list *timer, unsigned int flags,
			   const char *name, void *key);
extern int mod_timer(struct timer_list *timer, unsigned long expires);
extern int del_timer(struct timer_list *timer);
extern void delayed_work_timer_fn(unsigned long data);
extern int queue_delayed_work_on(int cpu, struct workqueue_struct *wq,
				 struct delayed_work *dwork, unsigned long delay);
extern int cancel_delayed_work_sync(struct delayed_work *dwork);
extern unsigned long msecs_to_jiffies(const unsigned int m);
extern unsigned int jiffies_to_msecs(const unsigned long j);
extern void msleep(unsigned int msecs);
extern void __module_get(struct module *module);
extern void module_put(struct module *module);
extern unsigned long module_refcount(struct module *mod);
extern void *vmalloc(unsigned long size);
extern void vfree(const void *addr);
extern struct proc_dir_entry *proc_create_data(const char *name, umode_t mode,
					       struct proc_dir_entry *parent,
					       const struct file_operations *fops,
					       void *data);
extern void remove_proc_entry(const char *name, struct proc_dir_entry *parent);
extern int single_open(struct file *file, int (*show)(struct seq_file *, void *), void *data);
extern int single_release(struct inode *inode, struct file *file);
extern ssize_t seq_read(struct file *file, char *buf, size_t size, loff_t *ppos);
extern loff_t seq_lseek(struct file *file, loff_t offset, int whence);
extern int seq_printf(struct seq_file *m, const char *fmt, ...);
extern void seq_puts(struct seq_file *m, const char *s);
extern unsigned long __copy_from_user(void *to, const void *from, unsigned long n);
extern void *memset(void *s, int c, size_t n);
extern void *memcpy(void *dst, const void *src, size_t n);
extern int memcmp(const void *a, const void *b, size_t n);
extern int strcmp(const char *a, const char *b);
extern char *strchr(const char *s, int c);

static inline unsigned long titan_copy_from_user(void *to, const void *from, unsigned long n)
{
	unsigned long sp, addr_limit;
	__asm__("mov %0, sp" : "=r"(sp));
	addr_limit = *(unsigned long *)((sp & ~0x1fffUL) + 8);
	if ((unsigned long)from + n < (unsigned long)from ||
	    (unsigned long)from + n > addr_limit)
		return n;
	return __copy_from_user(to, from, n);
}

static inline void k1_setup_timer(struct timer_list *t, void (*fn)(unsigned long), unsigned long data)
{
	init_timer_key(t, 0, NULL, NULL);
	t->function = fn;
	t->data = data;
}

static inline void k1_init_delayed_work(struct delayed_work *dw, void (*fn)(struct work_struct *))
{
	dw->work.data = WORK_DATA_INIT_BITS;
	init_list_head(&dw->work.entry);
	dw->work.func = fn;
	init_timer_key(&dw->timer, TIMER_IRQSAFE, NULL, NULL);
	dw->timer.function = delayed_work_timer_fn;
	dw->timer.data = (unsigned long)dw;
}

static inline int k1_schedule_delayed_work(struct delayed_work *dw, unsigned long delay)
{
	return queue_delayed_work_on(WORK_CPU_UNBOUND, system_wq, dw, delay);
}

static inline void k1_flush_icache_range(unsigned long start, unsigned long end)
{
	v7_coherent_kern_range(start, end);
}

#endif /* TITAN_FASTPATH_K310_ABI_H */
