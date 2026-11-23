/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright 2026 Centreville Tech, LLC. Kernel module for Titan 4000 Witcher Edition; see device/ufq/README.md. */
/*
 * titan_k310_abi.h - Binary-verified minimal Linux 3.10.0-uc0 ARMv7 UP ABI
 * for the Titan 4000 (GDM7243AP, vermagic "3.10.0-uc0 mod_unload ARMv7 ").
 *
 * Every struct size, field offset, calling convention, and exported symbol
 * below was verified directly from F/kernel/Image, F/unit/kallsyms.txt,
 * board.ko, gdmlte.ko, modem.ko, and ebtable_filter.ko (no CONFIG_MODVERSIONS,
 * UP, non-preempt, soft-float ARMv7 EABI).
 */
#ifndef TITAN_UFQ_K310_ABI_H
#define TITAN_UFQ_K310_ABI_H

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
typedef unsigned int       size_t;
typedef signed int         ssize_t;
typedef s64                loff_t;
typedef u16                umode_t;

#ifndef NULL
#define NULL ((void *)0)
#endif

#define offsetof(type, member) __builtin_offsetof(type, member)
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

static inline u16 ntohs(u16 x) { return __builtin_bswap16(x); }
static inline u16 htons(u16 x) { return __builtin_bswap16(x); }
static inline u32 ntohl(u32 x) { return __builtin_bswap32(x); }
static inline u32 htonl(u32 x) { return __builtin_bswap32(x); }

static inline void titan_dmb(void)
{
    __asm__ __volatile__("dmb sy" : : : "memory");
}

struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

/*
 * struct module (size = 328 = 0x148 bytes, verified from board.ko & gdmlte.ko):
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
_Static_assert(sizeof(struct module) == 328, "struct module size != 328");
_Static_assert(offsetof(struct module, name) == 0x0c, "module.name != 0x0c");
_Static_assert(offsetof(struct module, init) == 0xbc, "module.init != 0xbc");
_Static_assert(offsetof(struct module, exit) == 0x140, "module.exit != 0x140");

/*
 * ktime_t: ARMv7 Linux 3.10 defines union ktime { s64 tv64; }.
 * Returned via hidden pointer in r0 on 32-bit ARM EABI (verified at
 * ktime_get 0x80063a90).
 */
typedef union {
    s64 tv64;
} ktime_t;
_Static_assert(sizeof(ktime_t) == 8, "sizeof(ktime_t) != 8");

static inline ktime_t ktime_set_ns(s64 ns)
{
    ktime_t kt;
    kt.tv64 = ns;
    return kt;
}

/* struct net_device (verified at __dev_get_by_name 0x80257b3c): +0x00 name[16] */
struct net_device {
    char name[16];
};
_Static_assert(offsetof(struct net_device, name) == 0x00, "net_device.name != 0x00");

/*
 * struct sk_buff (offsets proven from F/kernel/Image):
 *   +0x14: struct net_device *dev
 *   +0x50: unsigned int len
 *   +0x54: unsigned int data_len
 *   +0x64: u8 flags0
 *   +0x66: __be16 protocol
 *   +0xb4: u8 *data
 */
struct sk_buff {
    struct sk_buff    *next;
    struct sk_buff    *prev;
    u8                 _pad0[0x14 - 0x08];
    struct net_device *dev;
    u8                 _pad1[0x50 - 0x18];
    u32                len;
    u32                data_len;
    u8                 _pad2[0x64 - 0x58];
    u8                 flags0;
    u8                 flags1;
    __be16             protocol;
    u8                 _pad3[0x9c - 0x68];
    u32                transport_header;
    u32                network_header;
    u32                mac_header;
    u32                tail;
    u8                *end;
    u8                *head;
    u8                *data;
};
_Static_assert(offsetof(struct sk_buff, dev) == 0x14, "skb.dev != 0x14");
_Static_assert(offsetof(struct sk_buff, len) == 0x50, "skb.len != 0x50");
_Static_assert(offsetof(struct sk_buff, data_len) == 0x54, "skb.data_len != 0x54");
_Static_assert(offsetof(struct sk_buff, flags0) == 0x64, "skb.flags0 != 0x64");
_Static_assert(offsetof(struct sk_buff, protocol) == 0x66, "skb.protocol != 0x66");
_Static_assert(offsetof(struct sk_buff, data) == 0xb4, "skb.data != 0xb4");

#define NF_DROP    0
#define NF_ACCEPT  1
#define NF_STOLEN  2
#define NF_QUEUE   3
#define NF_REPEAT  4

#define NFPROTO_BRIDGE 7
#define NF_BR_PRE_ROUTING  0
#define NF_BR_LOCAL_IN     1
#define NF_BR_FORWARD      2
#define NF_BR_LOCAL_OUT    3
#define NF_BR_POST_ROUTING 4

#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD

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
_Static_assert(offsetof(struct nf_hook_ops, pf) == 0x10, "nf_hook_ops.pf != 0x10");
_Static_assert(offsetof(struct nf_hook_ops, hooknum) == 0x14, "nf_hook_ops.hooknum != 0x14");
_Static_assert(offsetof(struct nf_hook_ops, priority) == 0x18, "nf_hook_ops.priority != 0x18");

#define CLOCK_MONOTONIC  1
#define HRTIMER_MODE_ABS 0
#define HRTIMER_MODE_REL 1
#define HRTIMER_NORESTART 0
#define HRTIMER_RESTART   1

struct hrtimer {
    u8 _opaque[0x30];
} __attribute__((aligned(8)));
struct tasklet_struct {
    u8 _opaque[0x14];
};
struct tasklet_hrtimer {
    struct hrtimer        timer;                           /* +0x00 */
    struct tasklet_struct tasklet;                         /* +0x30 */
    int (*function)(struct hrtimer *timer);                /* +0x44 */
};
_Static_assert(sizeof(struct hrtimer) == 0x30, "hrtimer size != 0x30");
_Static_assert(offsetof(struct tasklet_hrtimer, tasklet) == 0x30, "tasklet != 0x30");
_Static_assert(offsetof(struct tasklet_hrtimer, function) == 0x44, "function != 0x44");
_Static_assert(sizeof(struct tasklet_hrtimer) == 0x48, "tasklet_hrtimer size != 0x48");
_Static_assert(_Alignof(struct tasklet_hrtimer) == 8, "tasklet_hrtimer must be 8-aligned");

struct notifier_block {
    int (*notifier_call)(struct notifier_block *nb, unsigned long event, void *ptr);
    struct notifier_block *next;
    int priority;
};
_Static_assert(sizeof(struct notifier_block) == 12, "notifier_block size != 12");
#define NETDEV_DOWN        0x0002
#define NETDEV_UNREGISTER  0x0006
#define NETDEV_GOING_DOWN  0x0009
#define NETDEV_CHANGENAME  0x000A
#define NOTIFY_DONE        0x0000

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
    return (f & 0x80) != 0;
}

struct inode;
struct file;
struct seq_file;
struct proc_dir_entry;

struct file_operations {
    struct module *owner;                                                       /* +0x00 */
    loff_t (*llseek)(struct file *, loff_t, int);                               /* +0x04 */
    ssize_t (*read)(struct file *, char *, size_t, loff_t *);                   /* +0x08 */
    ssize_t (*write)(struct file *, const char *, size_t, loff_t *);            /* +0x0c */
    u8 _pad1[0x2c - 0x10];
    int (*open)(struct inode *, struct file *);                                 /* +0x2c */
    void *_flush;                                                               /* +0x30 */
    int (*release)(struct inode *, struct file *);                              /* +0x34 */
    u8 _pad2[0x70 - 0x38];
};
_Static_assert(offsetof(struct file_operations, llseek) == 0x04, "fops.llseek != 0x04");
_Static_assert(offsetof(struct file_operations, read) == 0x08, "fops.read != 0x08");
_Static_assert(offsetof(struct file_operations, write) == 0x0c, "fops.write != 0x0c");
_Static_assert(offsetof(struct file_operations, open) == 0x2c, "fops.open != 0x2c");
_Static_assert(offsetof(struct file_operations, release) == 0x34, "fops.release != 0x34");

/*
 * Exported kernel symbols (verified in F/unit/kallsyms.txt __ksymtab_*):
 *   __arm_ioremap  0x8001581c (__ksymtab___arm_ioremap 0x8046b080, mtype=0 MT_DEVICE)
 *   __arm_iounmap  0x800154ec (__ksymtab___arm_iounmap 0x8046b090)
 *   gipc           0x805c8618 (__ksymtab_gipc          0x8046d498; ch1 out u16 at +0x8c)
 *   kfree_skb      0x802509d4 (__ksymtab_kfree_skb     0x8046dfd8)
 */
#define MT_DEVICE 0u
extern void *__arm_ioremap(unsigned long phys_addr, size_t size, unsigned int mtype);
extern void  __arm_iounmap(volatile void *io_addr);
extern u8    gipc[];

extern int printk(const char *fmt, ...);
extern int nf_register_hook(struct nf_hook_ops *reg);
extern void nf_unregister_hook(struct nf_hook_ops *reg);
extern void synchronize_net(void);
extern int skb_make_writable(struct sk_buff *skb, unsigned int write_len);
extern void consume_skb(struct sk_buff *skb);
extern void kfree_skb(struct sk_buff *skb);
extern void local_bh_disable(void);
extern void local_bh_enable(void);
extern ktime_t ktime_get(void);
extern void tasklet_hrtimer_init(struct tasklet_hrtimer *ttimer,
                                 int (*function)(struct hrtimer *),
                                 int which_clock, int mode);
extern int hrtimer_start(struct hrtimer *timer, ktime_t tim, int mode);
extern int hrtimer_cancel(struct hrtimer *timer);
extern void tasklet_kill(struct tasklet_struct *t);
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
extern unsigned long __copy_from_user(void *to, const void *from, unsigned long n);
extern int register_netdevice_notifier(struct notifier_block *nb);
extern int unregister_netdevice_notifier(struct notifier_block *nb);

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

#endif /* TITAN_UFQ_K310_ABI_H */
