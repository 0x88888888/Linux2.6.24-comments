/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		ROUTE - implementation of the IP router.
 *
 * Version:	$Id: route.c,v 1.103 2002/01/12 07:44:09 davem Exp $
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Linus Torvalds, <Linus.Torvalds@helsinki.fi>
 *		Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 * Fixes:
 *		Alan Cox	:	Verify area fixes.
 *		Alan Cox	:	cli() protects routing changes
 *		Rui Oliveira	:	ICMP routing table updates
 *		(rco@di.uminho.pt)	Routing table insertion and update
 *		Linus Torvalds	:	Rewrote bits to be sensible
 *		Alan Cox	:	Added BSD route gw semantics
 *		Alan Cox	:	Super /proc >4K
 *		Alan Cox	:	MTU in route table
 *		Alan Cox	: 	MSS actually. Also added the window
 *					clamper.
 *		Sam Lantinga	:	Fixed route matching in rt_del()
 *		Alan Cox	:	Routing cache support.
 *		Alan Cox	:	Removed compatibility cruft.
 *		Alan Cox	:	RTF_REJECT support.
 *		Alan Cox	:	TCP irtt support.
 *		Jonathan Naylor	:	Added Metric support.
 *	Miquel van Smoorenburg	:	BSD API fixes.
 *	Miquel van Smoorenburg	:	Metrics.
 *		Alan Cox	:	Use __u32 properly
 *		Alan Cox	:	Aligned routing errors more closely with BSD
 *					our system is still very different.
 *		Alan Cox	:	Faster /proc handling
 *	Alexey Kuznetsov	:	Massive rework to support tree based routing,
 *					routing caches and better behaviour.
 *
 *		Olaf Erb	:	irtt wasn't being copied right.
 *		Bjorn Ekwall	:	Kerneld route support.
 *		Alan Cox	:	Multicast fixed (I hope)
 * 		Pavel Krauz	:	Limited broadcast fixed
 *		Mike McLagan	:	Routing by source
 *	Alexey Kuznetsov	:	End of old history. Split to fib.c and
 *					route.c and rewritten from scratch.
 *		Andi Kleen	:	Load-limit warning messages.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year coma.
 *	Vitaly E. Lavrov	:	Race condition in ip_route_input_slow.
 *	Tobias Ringstrom	:	Uninitialized res.type in ip_route_output_slow.
 *	Vladimir V. Ivanov	:	IP rule info (flowid) is really useful.
 *		Marc Boucher	:	routing by fwmark
 *	Robert Olsson		:	Added rt_cache statistics
 *	Arnaldo C. Melo		:	Convert proc stuff to seq_file
 *	Eric Dumazet		:	hashed spinlocks and rt_check_expire() fixes.
 * 	Ilia Sotnikov		:	Ignore TOS on PMTUD and Redirect
 * 	Ilia Sotnikov		:	Removed TOS from hash calculations
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/bitops.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/bootmem.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/workqueue.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>
#include <linux/pkt_sched.h>
#include <linux/mroute.h>
#include <linux/netfilter_ipv4.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/rcupdate.h>
#include <linux/times.h>
#include <net/net_namespace.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/inetpeer.h>
#include <net/sock.h>
#include <net/ip_fib.h>
#include <net/arp.h>
#include <net/tcp.h>
#include <net/icmp.h>
#include <net/xfrm.h>
#include <net/netevent.h>
#include <net/rtnetlink.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#define RT_FL_TOS(oldflp) \
    ((u32)(oldflp->fl4_tos & (IPTOS_RT_MASK | RTO_ONLINK)))

#define IP_MAX_MTU	0xFFF0

#define RT_GC_TIMEOUT (300*HZ)

static int ip_rt_min_delay		= 2 * HZ;
static int ip_rt_max_delay		= 10 * HZ;
static int ip_rt_max_size;
static int ip_rt_gc_timeout		= RT_GC_TIMEOUT;
static int ip_rt_gc_interval		= 60 * HZ;
static int ip_rt_gc_min_interval	= HZ / 2;
static int ip_rt_redirect_number	= 9;
static int ip_rt_redirect_load		= HZ / 50;
static int ip_rt_redirect_silence	= ((HZ / 50) << (9 + 1));
static int ip_rt_error_cost		= HZ;
static int ip_rt_error_burst		= 5 * HZ;
static int ip_rt_gc_elasticity		= 8;
static int ip_rt_mtu_expires		= 10 * 60 * HZ;
static int ip_rt_min_pmtu		= 512 + 20 + 20;
static int ip_rt_min_advmss		= 256;
static int ip_rt_secret_interval	= 10 * 60 * HZ;
static unsigned long rt_deadline;

#define RTprint(a...)	printk(KERN_DEBUG a)

static struct timer_list rt_flush_timer;
static void rt_check_expire(struct work_struct *work);
static DECLARE_DELAYED_WORK(expires_work, rt_check_expire);
static struct timer_list rt_secret_timer;

/*
 *	Interface to generic destination cache.
 */

static struct dst_entry *ipv4_dst_check(struct dst_entry *dst, u32 cookie);
static void		 ipv4_dst_destroy(struct dst_entry *dst);
static void		 ipv4_dst_ifdown(struct dst_entry *dst,
					 struct net_device *dev, int how);
static struct dst_entry *ipv4_negative_advice(struct dst_entry *dst);
static void		 ipv4_link_failure(struct sk_buff *skb);
static void		 ip_rt_update_pmtu(struct dst_entry *dst, u32 mtu);
static int rt_garbage_collect(void);


static struct dst_ops ipv4_dst_ops = {
	.family =		AF_INET,
	.protocol =		__constant_htons(ETH_P_IP),
	.gc =			rt_garbage_collect,
	.check =		ipv4_dst_check,
	.destroy =		ipv4_dst_destroy,
	.ifdown =		ipv4_dst_ifdown,
	.negative_advice =	ipv4_negative_advice,
	.link_failure =		ipv4_link_failure,
	.update_pmtu =		ip_rt_update_pmtu,
	.entry_size =		sizeof(struct rtable),
};

#define ECN_OR_COST(class)	TC_PRIO_##class

const __u8 ip_tos2prio[16] = {
	TC_PRIO_BESTEFFORT,
	ECN_OR_COST(FILLER),
	TC_PRIO_BESTEFFORT,
	ECN_OR_COST(BESTEFFORT),
	TC_PRIO_BULK,
	ECN_OR_COST(BULK),
	TC_PRIO_BULK,
	ECN_OR_COST(BULK),
	TC_PRIO_INTERACTIVE,
	ECN_OR_COST(INTERACTIVE),
	TC_PRIO_INTERACTIVE,
	ECN_OR_COST(INTERACTIVE),
	TC_PRIO_INTERACTIVE_BULK,
	ECN_OR_COST(INTERACTIVE_BULK),
	TC_PRIO_INTERACTIVE_BULK,
	ECN_OR_COST(INTERACTIVE_BULK)
};


/*
 * Route cache.
 */

/* The locking scheme is rather straight forward:
 *
 * 1) Read-Copy Update protects the buckets of the central route hash.
 * 2) Only writers remove entries, and they hold the lock
 *    as they look at rtable reference counts.
 * 3) Only readers acquire references to rtable entries,
 *    they do so with atomic increments and with the
 *    lock held.
 *
 * 管理路由表项的链表
 */
struct rt_hash_bucket {
	struct rtable	*chain;
};
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK) || \
	defined(CONFIG_PROVE_LOCKING)
/*
 * Instead of using one spinlock for each rt_hash_bucket, we use a table of spinlocks
 * The size of this table is a power of two and depends on the number of CPUS.
 * (on lockdep we have a quite big spinlock_t, so keep the size down there)
 */
#ifdef CONFIG_LOCKDEP
# define RT_HASH_LOCK_SZ	256
#else
# if NR_CPUS >= 32
#  define RT_HASH_LOCK_SZ	4096
# elif NR_CPUS >= 16
#  define RT_HASH_LOCK_SZ	2048
# elif NR_CPUS >= 8
#  define RT_HASH_LOCK_SZ	1024
# elif NR_CPUS >= 4
#  define RT_HASH_LOCK_SZ	512
# else
#  define RT_HASH_LOCK_SZ	256
# endif
#endif

static spinlock_t	*rt_hash_locks;
# define rt_hash_lock_addr(slot) &rt_hash_locks[(slot) & (RT_HASH_LOCK_SZ - 1)]
# define rt_hash_lock_init()	{ \
		int i; \
		rt_hash_locks = kmalloc(sizeof(spinlock_t) * RT_HASH_LOCK_SZ, GFP_KERNEL); \
		if (!rt_hash_locks) panic("IP: failed to allocate rt_hash_locks\n"); \
		for (i = 0; i < RT_HASH_LOCK_SZ; i++) \
			spin_lock_init(&rt_hash_locks[i]); \
		}
#else
# define rt_hash_lock_addr(slot) NULL
# define rt_hash_lock_init()
#endif

//路由缓存hash表，存放rtable对象
static struct rt_hash_bucket 	*rt_hash_table;
//确定rt_hash_table中的容量
static unsigned			rt_hash_mask;
static unsigned int		rt_hash_log;
//随机值，确定rt_hash_table中的元素的分布
static unsigned int		rt_hash_rnd;

static DEFINE_PER_CPU(struct rt_cache_stat, rt_cache_stat);
#define RT_CACHE_STAT_INC(field) \
	(__raw_get_cpu_var(rt_cache_stat).field++)

static int rt_intern_hash(unsigned hash, struct rtable *rth,
				struct rtable **res);

static unsigned int rt_hash_code(u32 daddr, u32 saddr)
{
	return (jhash_2words(daddr, saddr, rt_hash_rnd)
		& rt_hash_mask);
}

#define rt_hash(daddr, saddr, idx) \
	rt_hash_code((__force u32)(__be32)(daddr),\
		     (__force u32)(__be32)(saddr) ^ ((idx) << 5))

#ifdef CONFIG_PROC_FS
struct rt_cache_iter_state {
	int bucket;
};

static struct rtable *rt_cache_get_first(struct seq_file *seq)
{
	struct rtable *r = NULL;
	struct rt_cache_iter_state *st = seq->private;

	for (st->bucket = rt_hash_mask; st->bucket >= 0; --st->bucket) {
		rcu_read_lock_bh();
		r = rt_hash_table[st->bucket].chain;
		if (r)
			break;
		rcu_read_unlock_bh();
	}
	return rcu_dereference(r);
}

static struct rtable *rt_cache_get_next(struct seq_file *seq, struct rtable *r)
{
	struct rt_cache_iter_state *st = seq->private;

	r = r->u.dst.rt_next;
	while (!r) {
		rcu_read_unlock_bh();
		if (--st->bucket < 0)
			break;
		rcu_read_lock_bh();
		r = rt_hash_table[st->bucket].chain;
	}
	return rcu_dereference(r);
}

static struct rtable *rt_cache_get_idx(struct seq_file *seq, loff_t pos)
{
	struct rtable *r = rt_cache_get_first(seq);

	if (r)
		while (pos && (r = rt_cache_get_next(seq, r)))
			--pos;
	return pos ? NULL : r;
}

static void *rt_cache_seq_start(struct seq_file *seq, loff_t *pos)
{
	return *pos ? rt_cache_get_idx(seq, *pos - 1) : SEQ_START_TOKEN;
}

static void *rt_cache_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct rtable *r = NULL;

	if (v == SEQ_START_TOKEN)
		r = rt_cache_get_first(seq);
	else
		r = rt_cache_get_next(seq, v);
	++*pos;
	return r;
}

static void rt_cache_seq_stop(struct seq_file *seq, void *v)
{
	if (v && v != SEQ_START_TOKEN)
		rcu_read_unlock_bh();
}

static int rt_cache_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_printf(seq, "%-127s\n",
			   "Iface\tDestination\tGateway \tFlags\t\tRefCnt\tUse\t"
			   "Metric\tSource\t\tMTU\tWindow\tIRTT\tTOS\tHHRef\t"
			   "HHUptod\tSpecDst");
	else {
		struct rtable *r = v;
		char temp[256];

		sprintf(temp, "%s\t%08lX\t%08lX\t%8X\t%d\t%u\t%d\t"
			      "%08lX\t%d\t%u\t%u\t%02X\t%d\t%1d\t%08X",
			r->u.dst.dev ? r->u.dst.dev->name : "*",
			(unsigned long)r->rt_dst, (unsigned long)r->rt_gateway,
			r->rt_flags, atomic_read(&r->u.dst.__refcnt),
			r->u.dst.__use, 0, (unsigned long)r->rt_src,
			(dst_metric(&r->u.dst, RTAX_ADVMSS) ?
			     (int)dst_metric(&r->u.dst, RTAX_ADVMSS) + 40 : 0),
			dst_metric(&r->u.dst, RTAX_WINDOW),
			(int)((dst_metric(&r->u.dst, RTAX_RTT) >> 3) +
			      dst_metric(&r->u.dst, RTAX_RTTVAR)),
			r->fl.fl4_tos,
			r->u.dst.hh ? atomic_read(&r->u.dst.hh->hh_refcnt) : -1,
			r->u.dst.hh ? (r->u.dst.hh->hh_output ==
				       dev_queue_xmit) : 0,
			r->rt_spec_dst);
		seq_printf(seq, "%-127s\n", temp);
	}
	return 0;
}

static const struct seq_operations rt_cache_seq_ops = {
	.start  = rt_cache_seq_start,
	.next   = rt_cache_seq_next,
	.stop   = rt_cache_seq_stop,
	.show   = rt_cache_seq_show,
};

static int rt_cache_seq_open(struct inode *inode, struct file *file)
{
	return seq_open_private(file, &rt_cache_seq_ops,
			sizeof(struct rt_cache_iter_state));
}

static const struct file_operations rt_cache_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = rt_cache_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release_private,
};


static void *rt_cpu_seq_start(struct seq_file *seq, loff_t *pos)
{
	int cpu;

	if (*pos == 0)
		return SEQ_START_TOKEN;

	for (cpu = *pos-1; cpu < NR_CPUS; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu+1;
		return &per_cpu(rt_cache_stat, cpu);
	}
	return NULL;
}

static void *rt_cpu_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	int cpu;

	for (cpu = *pos; cpu < NR_CPUS; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu+1;
		return &per_cpu(rt_cache_stat, cpu);
	}
	return NULL;

}

static void rt_cpu_seq_stop(struct seq_file *seq, void *v)
{

}

static int rt_cpu_seq_show(struct seq_file *seq, void *v)
{
	struct rt_cache_stat *st = v;

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "entries  in_hit in_slow_tot in_slow_mc in_no_route in_brd in_martian_dst in_martian_src  out_hit out_slow_tot out_slow_mc  gc_total gc_ignored gc_goal_miss gc_dst_overflow in_hlist_search out_hlist_search\n");
		return 0;
	}

	seq_printf(seq,"%08x  %08x %08x %08x %08x %08x %08x %08x "
		   " %08x %08x %08x %08x %08x %08x %08x %08x %08x \n",
		   atomic_read(&ipv4_dst_ops.entries),
		   st->in_hit,
		   st->in_slow_tot,
		   st->in_slow_mc,
		   st->in_no_route,
		   st->in_brd,
		   st->in_martian_dst,
		   st->in_martian_src,

		   st->out_hit,
		   st->out_slow_tot,
		   st->out_slow_mc,

		   st->gc_total,
		   st->gc_ignored,
		   st->gc_goal_miss,
		   st->gc_dst_overflow,
		   st->in_hlist_search,
		   st->out_hlist_search
		);
	return 0;
}

static const struct seq_operations rt_cpu_seq_ops = {
	.start  = rt_cpu_seq_start,
	.next   = rt_cpu_seq_next,
	.stop   = rt_cpu_seq_stop,
	.show   = rt_cpu_seq_show,
};


static int rt_cpu_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &rt_cpu_seq_ops);
}

static const struct file_operations rt_cpu_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = rt_cpu_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

#endif /* CONFIG_PROC_FS */

static __inline__ void rt_free(struct rtable *rt)
{
	call_rcu_bh(&rt->u.dst.rcu_head, dst_rcu_free);
}

static __inline__ void rt_drop(struct rtable *rt)
{
	ip_rt_put(rt);
	call_rcu_bh(&rt->u.dst.rcu_head, dst_rcu_free);
}

static __inline__ int rt_fast_clean(struct rtable *rth)
{
	/* Kill broadcast/multicast entries very aggresively, if they
	   collide in hash table with more useful entries */
	return (rth->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST)) &&
		rth->fl.iif && rth->u.dst.rt_next;
}

static __inline__ int rt_valuable(struct rtable *rth)
{
	return (rth->rt_flags & (RTCF_REDIRECTED | RTCF_NOTIFY)) ||
		rth->u.dst.expires;
}

static int rt_may_expire(struct rtable *rth, unsigned long tmo1, unsigned long tmo2)
{
	unsigned long age;
	int ret = 0;

	if (atomic_read(&rth->u.dst.__refcnt))
		goto out;

	ret = 1;
	if (rth->u.dst.expires &&
	    time_after_eq(jiffies, rth->u.dst.expires))
		goto out;

	age = jiffies - rth->u.dst.lastuse;
	ret = 0;
	if ((age <= tmo1 && !rt_fast_clean(rth)) ||
	    (age <= tmo2 && rt_valuable(rth)))
		goto out;
	ret = 1;
out:	return ret;
}

/* Bits of score are:
 * 31: very valuable
 * 30: not quite useless
 * 29..0: usage counter
 */
static inline u32 rt_score(struct rtable *rt)
{
	u32 score = jiffies - rt->u.dst.lastuse;

	score = ~score & ~(3<<30);

	if (rt_valuable(rt))
		score |= (1<<31);

	if (!rt->fl.iif ||
	    !(rt->rt_flags & (RTCF_BROADCAST|RTCF_MULTICAST|RTCF_LOCAL)))
		score |= (1<<30);

	return score;
}

static inline int compare_keys(struct flowi *fl1, struct flowi *fl2)
{
	return ((__force u32)((fl1->nl_u.ip4_u.daddr ^ fl2->nl_u.ip4_u.daddr) |
		(fl1->nl_u.ip4_u.saddr ^ fl2->nl_u.ip4_u.saddr)) |
		(fl1->mark ^ fl2->mark) |
		(*(u16 *)&fl1->nl_u.ip4_u.tos ^
		 *(u16 *)&fl2->nl_u.ip4_u.tos) |
		(fl1->oif ^ fl2->oif) |
		(fl1->iif ^ fl2->iif)) == 0;
}

static void rt_check_expire(struct work_struct *work)
{
	static unsigned int rover;
	unsigned int i = rover, goal;
	struct rtable *rth, **rthp;
	u64 mult;

	mult = ((u64)ip_rt_gc_interval) << rt_hash_log;
	if (ip_rt_gc_timeout > 1)
		do_div(mult, ip_rt_gc_timeout);
	//要删除goal个rtable
	goal = (unsigned int)mult;
	if (goal > rt_hash_mask)
		goal = rt_hash_mask + 1;
	
	for (; goal > 0; goal--) {
		unsigned long tmo = ip_rt_gc_timeout;

		i = (i + 1) & rt_hash_mask;
		rthp = &rt_hash_table[i].chain;

		if (need_resched())
			cond_resched();

		if (*rthp == NULL)
			continue;
		
		spin_lock_bh(rt_hash_lock_addr(i));
		
		while ((rth = *rthp) != NULL) {
			if (rth->u.dst.expires) {
				/* Entry is expired even if it is in use */
				if (time_before_eq(jiffies, rth->u.dst.expires)) {
					tmo >>= 1;
					rthp = &rth->u.dst.rt_next;
					continue;
				}
			} else if (!rt_may_expire(rth, tmo, ip_rt_gc_timeout)) {
				tmo >>= 1;
				rthp = &rth->u.dst.rt_next;
				continue;
			}

            //下一个rtable
			/* Cleanup aged off entries. */
			*rthp = rth->u.dst.rt_next;
			rt_free(rth);
		}
		spin_unlock_bh(rt_hash_lock_addr(i));
	}
	rover = i;
	schedule_delayed_work(&expires_work, ip_rt_gc_interval);
}

/* This can run from both BH and non-BH contexts, the latter
 * in the case of a forced flush event.
 *
 * devinet_sysctl_forward()
 *  inet_forward_change()
 *   rt_cache_flush()
 *    rt_run_flush(0)
 *
 * 刷新一次路由缓存
 */
static void rt_run_flush(unsigned long dummy)
{
	int i;
	struct rtable *rth, *next;

	rt_deadline = 0;

	get_random_bytes(&rt_hash_rnd, 4);

	for (i = rt_hash_mask; i >= 0; i--) {
		spin_lock_bh(rt_hash_lock_addr(i));
		
		rth = rt_hash_table[i].chain;
		if (rth)
			rt_hash_table[i].chain = NULL;
		spin_unlock_bh(rt_hash_lock_addr(i));

		for (; rth; rth = next) {
			next = rth->u.dst.rt_next;
			rt_free(rth); //释放掉
		}
	}
}

static DEFINE_SPINLOCK(rt_flush_lock);

/*
 * devinet_sysctl_forward()
 *  inet_forward_change()
 *   rt_cache_flush()
 */
void rt_cache_flush(int delay)
{
	unsigned long now = jiffies;
	int user_mode = !in_softirq();

	if (delay < 0)
		delay = ip_rt_min_delay;

	spin_lock_bh(&rt_flush_lock);

	if (del_timer(&rt_flush_timer) && delay > 0 && rt_deadline) {
		long tmo = (long)(rt_deadline - now);

		/* If flush timer is already running
		   and flush request is not immediate (delay > 0):

		   if deadline is not achieved, prolongate timer to "delay",
		   otherwise fire it at deadline time.
		 */

		if (user_mode && tmo < ip_rt_max_delay-ip_rt_min_delay)
			tmo = 0;

		if (delay > tmo)
			delay = tmo;
	}

	if (delay <= 0) {
		spin_unlock_bh(&rt_flush_lock);
		rt_run_flush(0);
		return;
	}

	if (rt_deadline == 0)
		rt_deadline = now + ip_rt_max_delay;

    //重新启动时间
	mod_timer(&rt_flush_timer, now+delay);
	spin_unlock_bh(&rt_flush_lock);
}

static void rt_secret_rebuild(unsigned long dummy)
{
	unsigned long now = jiffies;

	rt_cache_flush(0);
	mod_timer(&rt_secret_timer, now + ip_rt_secret_interval);
}

/*
   Short description of GC goals.

   We want to build algorithm, which will keep routing cache
   at some equilibrium point, when number of aged off entries
   is kept approximately equal to newly generated ones.

   Current expiration strength is variable "expire".
   We try to adjust it dynamically, so that if networking
   is idle expires is large enough to keep enough of warm entries,
   and when load increases it reduces to limit cache size.
 */

static int rt_garbage_collect(void)
{
	static unsigned long expire = RT_GC_TIMEOUT;
	static unsigned long last_gc;
	static int rover;
	static int equilibrium;
	struct rtable *rth, **rthp;
	unsigned long now = jiffies;
	int goal;

	/*
	 * Garbage collection is pretty expensive,
	 * do not make it too frequently.
	 */

	RT_CACHE_STAT_INC(gc_total);

	if (now - last_gc < ip_rt_gc_min_interval &&
	    atomic_read(&ipv4_dst_ops.entries) < ip_rt_max_size) {
		RT_CACHE_STAT_INC(gc_ignored);
		goto out;
	}

	/* Calculate number of entries, which we want to expire now. */
	goal = atomic_read(&ipv4_dst_ops.entries) -
		(ip_rt_gc_elasticity << rt_hash_log);
	if (goal <= 0) {
		if (equilibrium < ipv4_dst_ops.gc_thresh)
			equilibrium = ipv4_dst_ops.gc_thresh;
		goal = atomic_read(&ipv4_dst_ops.entries) - equilibrium;
		if (goal > 0) {
			equilibrium += min_t(unsigned int, goal / 2, rt_hash_mask + 1);
			goal = atomic_read(&ipv4_dst_ops.entries) - equilibrium;
		}
	} else {
		/* We are in dangerous area. Try to reduce cache really
		 * aggressively.
		 */
		goal = max_t(unsigned int, goal / 2, rt_hash_mask + 1);
		equilibrium = atomic_read(&ipv4_dst_ops.entries) - goal;
	}

	if (now - last_gc >= ip_rt_gc_min_interval)
		last_gc = now;

	if (goal <= 0) {
		equilibrium += goal;
		goto work_done;
	}

	do {
		int i, k;

		for (i = rt_hash_mask, k = rover; i >= 0; i--) {
			unsigned long tmo = expire;

			k = (k + 1) & rt_hash_mask;
			rthp = &rt_hash_table[k].chain;
			spin_lock_bh(rt_hash_lock_addr(k));
			while ((rth = *rthp) != NULL) {
				if (!rt_may_expire(rth, tmo, expire)) {
					tmo >>= 1;
					rthp = &rth->u.dst.rt_next;
					continue;
				}
				*rthp = rth->u.dst.rt_next;
				rt_free(rth);
				goal--;
			}
			spin_unlock_bh(rt_hash_lock_addr(k));
			if (goal <= 0)
				break;
		}
		rover = k;

		if (goal <= 0)
			goto work_done;

		/* Goal is not achieved. We stop process if:

		   - if expire reduced to zero. Otherwise, expire is halfed.
		   - if table is not full.
		   - if we are called from interrupt.
		   - jiffies check is just fallback/debug loop breaker.
		     We will not spin here for long time in any case.
		 */

		RT_CACHE_STAT_INC(gc_goal_miss);

		if (expire == 0)
			break;

		expire >>= 1;
#if RT_CACHE_DEBUG >= 2
		printk(KERN_DEBUG "expire>> %u %d %d %d\n", expire,
				atomic_read(&ipv4_dst_ops.entries), goal, i);
#endif

		if (atomic_read(&ipv4_dst_ops.entries) < ip_rt_max_size)
			goto out;
	} while (!in_softirq() && time_before_eq(jiffies, now));

	if (atomic_read(&ipv4_dst_ops.entries) < ip_rt_max_size)
		goto out;
	if (net_ratelimit())
		printk(KERN_WARNING "dst cache overflow\n");
	RT_CACHE_STAT_INC(gc_dst_overflow);
	return 1;

work_done:
	expire += ip_rt_gc_min_interval;
	if (expire > ip_rt_gc_timeout ||
	    atomic_read(&ipv4_dst_ops.entries) < ipv4_dst_ops.gc_thresh)
		expire = ip_rt_gc_timeout;
#if RT_CACHE_DEBUG >= 2
	printk(KERN_DEBUG "expire++ %u %d %d %d\n", expire,
			atomic_read(&ipv4_dst_ops.entries), goal, rover);
#endif
out:	return 0;
}

/*
 * 把新找到的路由表项插入路由缓存rt_hash_table中,并设置neighbour子系统
 *
 *  ip_rcv
 *   ip_rcv_finish
 *    ip_route_input
 *     ip_route_input_slow
 *      rt_intern_hash()
 */
static int rt_intern_hash(unsigned hash, struct rtable *rt, struct rtable **rp)
{
	struct rtable	*rth, **rthp;
	unsigned long	now;
	struct rtable *cand, **candp;
	u32 		min_score;
	int		chain_length;
	int attempts = !in_softirq();

restart:
	chain_length = 0;
	min_score = ~(u32)0;
	cand = NULL;
	candp = NULL;
	now = jiffies;

    /* 取得hash链，这里与普通的链表稍有区别，因为rthp是指向指针的指针 */
	rthp = &rt_hash_table[hash].chain;

	spin_lock_bh(rt_hash_lock_addr(hash));

    /* 遍历链，寻找缓存是否已经存在
     * 这里一个值得注意的地方，是链表的删除操作：rthp被定义成一个指向指向的指针，这主要是为了高效地操作链表        
     * 每一次遍历，rthp指向的并不是缓存链中的下一个指点，而是指向“指向下一个节点的指针(dst.rt_next)的指针”:
     * rthp = &rth->u.dst.rt_next; 这样，在删除节点时，只需要修改这个指针指向的地址，让它指向待删除的节点的
     * 即可： *rthp = rth->u.dst.rt_next;这样，就不必再保留一个“前一节点的prev指针”。
     */	
	while ((rth = *rthp) != NULL) {
		/* 关键字匹备，查看要插入的项是否存在 */
		if (compare_keys(&rth->fl, &rt->fl)) {
			/* Put it first */
		    /* 如果查找命中，则将它调到链首，这样做的理由是因为它是最近被使用，有可能会在接下来的查找中最先被使用 */
			*rthp = rth->u.dst.rt_next;
			/*
			 * Since lookup is lockfree, the deletion
			 * must be visible to another weakly ordered CPU before
			 * the insertion at the start of the hash chain.
			 */
			rcu_assign_pointer(rth->u.dst.rt_next,
					   rt_hash_table[hash].chain);
			/*
			 * Since lookup is lockfree, the update writes
			 * must be ordered for consistency on SMP.
			 */
			rcu_assign_pointer(rt_hash_table[hash].chain, rth);

            /* 更新使用计数器(不是引用计数器)和时间戳 */
			dst_use(&rth->u.dst, now);
			spin_unlock_bh(rt_hash_lock_addr(hash));

            /* 因为存在，没有必要插入了，丢弃要插入的缓存项 */
			rt_drop(rt);
			*rp = rth;
			return 0;
		}

		/* 如果对该缓存项没有引用，则尝试调用rt_score来计算应被删除的最佳候选人
		 * rt_score算计一个得分，拥有最小得分的缓存项则被记录至cand,同时使用了一个candp的理由与rthp作用类似，
		 * 在删除这个最佳删除项cand的时候，减少一个prev指针 			   
		 */
		if (!atomic_read(&rth->u.dst.__refcnt)) {
			u32 score = rt_score(rth);

			if (score <= min_score) {
				cand = rth;
				candp = rthp;
				min_score = score;
			}
		}

        /* 统计链长，主要是用于以后判断是否超过垃圾回收的阀值 */
		chain_length++;

		rthp = &rth->u.dst.rt_next;
	}

    /* 循环完hash链，没有找到匹备的缓存项，则将尝试插入，每次插入之前，都会尝试找到一个最佳的删除项cand，这样，以避免出现缓存容量的溢出 */
	if (cand) {
		/* ip_rt_gc_elasticity used to be average length of chain
		 * length, when exceeded gc becomes really aggressive.
		 *
		 * The second limit is less certain. At the moment it allows
		 * only 2 entries per bucket. We will see.
		 */
		 /* 如果找到了cand，并且当前链的长度已经超过了定义的垃圾回收的阀值，则直接调用rt_free删除之 */
		if (chain_length > ip_rt_gc_elasticity) {
			*candp = cand->u.dst.rt_next;
			rt_free(cand);
		}
	}

	/* Try to bind route to arp only if it is output
	   route or unicast forwarding path.
	 */
	/* 如果是单播中转或本地发出的报文，尝试将路由缓存与arp绑定，需要绑定的理由在于加速，这样在数据发送的时候，可以很方便地封装二层帧首部 */ 
	if (rt->rt_type == RTN_UNICAST || rt->fl.iif == 0) {
		// 设置neighbour子系统
		int err = arp_bind_neighbour(&rt->u.dst);
		/* 绑定失败 */
		if (err) {
			spin_unlock_bh(rt_hash_lock_addr(hash));
            /* 内存不足，直接丢弃，并出错返回 */
			if (err != -ENOBUFS) {
				rt_drop(rt);
				return err;
			}

			/* Neighbour tables are full and nothing
			   can be released. Try to shrink route cache,
			   it is most likely it holds some neighbour records.
			 */
			/* 否则调整垃圾收回阀值，调用rt_garbage_collect进行主动垃圾清理，并尝试重试 */ 
			if (attempts-- > 0) {
				int saved_elasticity = ip_rt_gc_elasticity;
				int saved_int = ip_rt_gc_min_interval;
				ip_rt_gc_elasticity	= 1;
				ip_rt_gc_min_interval	= 0;
				rt_garbage_collect();
				ip_rt_gc_min_interval	= saved_int;
				ip_rt_gc_elasticity	= saved_elasticity;
				goto restart;
			}

            /* 超过最大重试次数，仍旧失败 */
			if (net_ratelimit())
				printk(KERN_WARNING "Neighbour table overflow.\n");
			rt_drop(rt);
			return -ENOBUFS;
		}
	}

	rt->u.dst.rt_next = rt_hash_table[hash].chain;
#if RT_CACHE_DEBUG >= 2
	if (rt->u.dst.rt_next) {
		struct rtable *trt;
		printk(KERN_DEBUG "rt_cache @%02x: %u.%u.%u.%u", hash,
		       NIPQUAD(rt->rt_dst));
		for (trt = rt->u.dst.rt_next; trt; trt = trt->u.dst.rt_next)
			printk(" . %u.%u.%u.%u", NIPQUAD(trt->rt_dst));
		printk("\n");
	}
#endif

    // 把查找得到的路由表项信息加入路由缓存中
	rt_hash_table[hash].chain = rt;
	spin_unlock_bh(rt_hash_lock_addr(hash));
	// 设置返回参数的值
	*rp = rt;
	return 0;
}

/*
 * ip_select_ident_more()
 *  __ip_select_ident()
 *   rt_bind_peer(, create == 1)
 */
void rt_bind_peer(struct rtable *rt, int create)
{
	static DEFINE_SPINLOCK(rt_peer_lock);
	struct inet_peer *peer;

	peer = inet_getpeer(rt->rt_dst, create);

	spin_lock_bh(&rt_peer_lock);
	if (rt->peer == NULL) {
		rt->peer = peer;
		peer = NULL;
	}
	spin_unlock_bh(&rt_peer_lock);
	if (peer)
		inet_putpeer(peer);
}

/*
 * Peer allocation may fail only in serious out-of-memory conditions.  However
 * we still can generate some output.
 * Random ID selection looks a bit dangerous because we have no chances to
 * select ID being unique in a reasonable period of time.
 * But broken packet identifier may be better than no packet at all.
 *
 * ip_select_ident_more()
 *  __ip_select_ident()
 *   ip_select_fb_ident()
 */
static void ip_select_fb_ident(struct iphdr *iph)
{
	static DEFINE_SPINLOCK(ip_fb_id_lock);
	static u32 ip_fallback_id;
	u32 salt;

	spin_lock_bh(&ip_fb_id_lock);
	salt = secure_ip_id((__force __be32)ip_fallback_id ^ iph->daddr);
	iph->id = htons(salt & 0xFFFF);
	ip_fallback_id = salt;
	spin_unlock_bh(&ip_fb_id_lock);
}

/*
 * ip_select_ident_more()
 *  __ip_select_ident()
 */
void __ip_select_ident(struct iphdr *iph, struct dst_entry *dst, int more)
{
	struct rtable *rt = (struct rtable *) dst;

	if (rt) {
		if (rt->peer == NULL)
			rt_bind_peer(rt, 1);

		/* If peer is attached to destination, it is never detached,
		   so that we need not to grab a lock to dereference it.
		 */
		if (rt->peer) {
			iph->id = htons(inet_getid(rt->peer, more));
			return;
		}
	} else
		printk(KERN_DEBUG "rt_bind_peer(0) @%p\n",
		       __builtin_return_address(0));

	ip_select_fb_ident(iph);
}

static void rt_del(unsigned hash, struct rtable *rt)
{
	struct rtable **rthp;

	spin_lock_bh(rt_hash_lock_addr(hash));
	ip_rt_put(rt);
	for (rthp = &rt_hash_table[hash].chain; *rthp;
	     rthp = &(*rthp)->u.dst.rt_next)
		if (*rthp == rt) {
			*rthp = rt->u.dst.rt_next;
			rt_free(rt);
			break;
		}
	spin_unlock_bh(rt_hash_lock_addr(hash));
}

void ip_rt_redirect(__be32 old_gw, __be32 daddr, __be32 new_gw,
		    __be32 saddr, struct net_device *dev)
{
	int i, k;
	struct in_device *in_dev = in_dev_get(dev);
	struct rtable *rth, **rthp;
	__be32  skeys[2] = { saddr, 0 };
	int  ikeys[2] = { dev->ifindex, 0 };
	struct netevent_redirect netevent;

	if (!in_dev)
		return;

	if (new_gw == old_gw || !IN_DEV_RX_REDIRECTS(in_dev)
	    || MULTICAST(new_gw) || BADCLASS(new_gw) || ZERONET(new_gw))
		goto reject_redirect;

	if (!IN_DEV_SHARED_MEDIA(in_dev)) {
		if (!inet_addr_onlink(in_dev, new_gw, old_gw))
			goto reject_redirect;
		if (IN_DEV_SEC_REDIRECTS(in_dev) && ip_fib_check_default(new_gw, dev))
			goto reject_redirect;
	} else {
		if (inet_addr_type(new_gw) != RTN_UNICAST)
			goto reject_redirect;
	}

	for (i = 0; i < 2; i++) {
		for (k = 0; k < 2; k++) {
			unsigned hash = rt_hash(daddr, skeys[i], ikeys[k]);

			rthp=&rt_hash_table[hash].chain;

			rcu_read_lock();
			while ((rth = rcu_dereference(*rthp)) != NULL) {
				struct rtable *rt;

				if (rth->fl.fl4_dst != daddr ||
				    rth->fl.fl4_src != skeys[i] ||
				    rth->fl.oif != ikeys[k] ||
				    rth->fl.iif != 0) {
					rthp = &rth->u.dst.rt_next;
					continue;
				}

				if (rth->rt_dst != daddr ||
				    rth->rt_src != saddr ||
				    rth->u.dst.error ||
				    rth->rt_gateway != old_gw ||
				    rth->u.dst.dev != dev)
					break;

				dst_hold(&rth->u.dst);
				rcu_read_unlock();

				rt = dst_alloc(&ipv4_dst_ops);
				if (rt == NULL) {
					ip_rt_put(rth);
					in_dev_put(in_dev);
					return;
				}

				/* Copy all the information. */
				*rt = *rth;
				INIT_RCU_HEAD(&rt->u.dst.rcu_head);
				rt->u.dst.__use		= 1;
				atomic_set(&rt->u.dst.__refcnt, 1);
				rt->u.dst.child		= NULL;
				if (rt->u.dst.dev)
					dev_hold(rt->u.dst.dev);
				if (rt->idev)
					in_dev_hold(rt->idev);
				rt->u.dst.obsolete	= 0;
				rt->u.dst.lastuse	= jiffies;
				rt->u.dst.path		= &rt->u.dst;
				rt->u.dst.neighbour	= NULL;
				rt->u.dst.hh		= NULL;
				rt->u.dst.xfrm		= NULL;

				rt->rt_flags		|= RTCF_REDIRECTED;

				/* Gateway is different ... */
				rt->rt_gateway		= new_gw;

				/* Redirect received -> path was valid */
				dst_confirm(&rth->u.dst);

				if (rt->peer)
					atomic_inc(&rt->peer->refcnt);

				if (arp_bind_neighbour(&rt->u.dst) ||
				    !(rt->u.dst.neighbour->nud_state &
					    NUD_VALID)) {
					if (rt->u.dst.neighbour)
						neigh_event_send(rt->u.dst.neighbour, NULL);
					ip_rt_put(rth);
					rt_drop(rt);
					goto do_next;
				}

				netevent.old = &rth->u.dst;
				netevent.new = &rt->u.dst;
				call_netevent_notifiers(NETEVENT_REDIRECT,
							&netevent);

				rt_del(hash, rth);
				if (!rt_intern_hash(hash, rt, &rt))
					ip_rt_put(rt);
				goto do_next;
			}
			rcu_read_unlock();
		do_next:
			;
		}
	}
	in_dev_put(in_dev);
	return;

reject_redirect:
#ifdef CONFIG_IP_ROUTE_VERBOSE
	if (IN_DEV_LOG_MARTIANS(in_dev) && net_ratelimit())
		printk(KERN_INFO "Redirect from %u.%u.%u.%u on %s about "
			"%u.%u.%u.%u ignored.\n"
			"  Advised path = %u.%u.%u.%u -> %u.%u.%u.%u\n",
		       NIPQUAD(old_gw), dev->name, NIPQUAD(new_gw),
		       NIPQUAD(saddr), NIPQUAD(daddr));
#endif
	in_dev_put(in_dev);
}

static struct dst_entry *ipv4_negative_advice(struct dst_entry *dst)
{
	struct rtable *rt = (struct rtable*)dst;
	struct dst_entry *ret = dst;

	if (rt) {
		if (dst->obsolete) {
			ip_rt_put(rt);
			ret = NULL;
		} else if ((rt->rt_flags & RTCF_REDIRECTED) ||
			   rt->u.dst.expires) {
			unsigned hash = rt_hash(rt->fl.fl4_dst, rt->fl.fl4_src,
						rt->fl.oif);
#if RT_CACHE_DEBUG >= 1
			printk(KERN_DEBUG "ipv4_negative_advice: redirect to "
					  "%u.%u.%u.%u/%02x dropped\n",
				NIPQUAD(rt->rt_dst), rt->fl.fl4_tos);
#endif
			rt_del(hash, rt);
			ret = NULL;
		}
	}
	return ret;
}

/*
 * Algorithm:
 *	1. The first ip_rt_redirect_number redirects are sent
 *	   with exponential backoff, then we stop sending them at all,
 *	   assuming that the host ignores our redirects.
 *	2. If we did not see packets requiring redirects
 *	   during ip_rt_redirect_silence, we assume that the host
 *	   forgot redirected route and start to send redirects again.
 *
 * This algorithm is much cheaper and more intelligent than dumb load limiting
 * in icmp.c.
 *
 * NOTE. Do not forget to inhibit load limiting for redirects (redundant)
 * and "frag. need" (breaks PMTU discovery) in icmp.c.
 *
 * ip_forward()
 *  ip_rt_send_redirect()
 *
 * 发送icmp redirect包
 */

void ip_rt_send_redirect(struct sk_buff *skb)
{
	struct rtable *rt = (struct rtable*)skb->dst;
	struct in_device *in_dev = in_dev_get(rt->u.dst.dev);

	if (!in_dev)
		return;

	if (!IN_DEV_TX_REDIRECTS(in_dev))
		goto out;

	/* No redirected packets during ip_rt_redirect_silence;
	 * reset the algorithm.
	 */
	if (time_after(jiffies, rt->u.dst.rate_last + ip_rt_redirect_silence))
		rt->u.dst.rate_tokens = 0;

	/* Too many ignored redirects; do not send anything
	 * set u.dst.rate_last to the last seen redirected packet.
	 */
	if (rt->u.dst.rate_tokens >= ip_rt_redirect_number) {
		rt->u.dst.rate_last = jiffies;
		goto out;
	}

	/* Check for load limit; set rate_last to the latest sent
	 * redirect.
	 */
	if (rt->u.dst.rate_tokens == 0 ||
	    time_after(jiffies,
		       (rt->u.dst.rate_last +
			(ip_rt_redirect_load << rt->u.dst.rate_tokens)))) {
		icmp_send(skb, ICMP_REDIRECT, ICMP_REDIR_HOST, rt->rt_gateway);
		rt->u.dst.rate_last = jiffies;
		++rt->u.dst.rate_tokens;
#ifdef CONFIG_IP_ROUTE_VERBOSE
		if (IN_DEV_LOG_MARTIANS(in_dev) &&
		    rt->u.dst.rate_tokens == ip_rt_redirect_number &&
		    net_ratelimit())
			printk(KERN_WARNING "host %u.%u.%u.%u/if%d ignores "
				"redirects for %u.%u.%u.%u to %u.%u.%u.%u.\n",
				NIPQUAD(rt->rt_src), rt->rt_iif,
				NIPQUAD(rt->rt_dst), NIPQUAD(rt->rt_gateway));
#endif
	}
out:
	in_dev_put(in_dev);
}

static int ip_error(struct sk_buff *skb)
{
	struct rtable *rt = (struct rtable*)skb->dst;
	unsigned long now;
	int code;

	switch (rt->u.dst.error) {
		case EINVAL:
		default:
			goto out;
		case EHOSTUNREACH:
			code = ICMP_HOST_UNREACH;
			break;
		case ENETUNREACH:
			code = ICMP_NET_UNREACH;
			IP_INC_STATS_BH(IPSTATS_MIB_INNOROUTES);
			break;
		case EACCES:
			code = ICMP_PKT_FILTERED;
			break;
	}

	now = jiffies;
	rt->u.dst.rate_tokens += now - rt->u.dst.rate_last;
	if (rt->u.dst.rate_tokens > ip_rt_error_burst)
		rt->u.dst.rate_tokens = ip_rt_error_burst;
	rt->u.dst.rate_last = now;
	if (rt->u.dst.rate_tokens >= ip_rt_error_cost) {
		rt->u.dst.rate_tokens -= ip_rt_error_cost;
		icmp_send(skb, ICMP_DEST_UNREACH, code, 0);
	}

out:	kfree_skb(skb);
	return 0;
}

/*
 *	The last two values are not from the RFC but
 *	are needed for AMPRnet AX.25 paths.
 */

static const unsigned short mtu_plateau[] =
{32000, 17914, 8166, 4352, 2002, 1492, 576, 296, 216, 128 };

static __inline__ unsigned short guess_mtu(unsigned short old_mtu)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(mtu_plateau); i++)
		if (old_mtu > mtu_plateau[i])
			return mtu_plateau[i];
	return 68;
}

unsigned short ip_rt_frag_needed(struct iphdr *iph, unsigned short new_mtu)
{
	int i;
	unsigned short old_mtu = ntohs(iph->tot_len);
	struct rtable *rth;
	__be32  skeys[2] = { iph->saddr, 0, };
	__be32  daddr = iph->daddr;
	unsigned short est_mtu = 0;

	if (ipv4_config.no_pmtu_disc)
		return 0;

	for (i = 0; i < 2; i++) {
		unsigned hash = rt_hash(daddr, skeys[i], 0);

		rcu_read_lock();
		for (rth = rcu_dereference(rt_hash_table[hash].chain); rth;
		     rth = rcu_dereference(rth->u.dst.rt_next)) {
			if (rth->fl.fl4_dst == daddr &&
			    rth->fl.fl4_src == skeys[i] &&
			    rth->rt_dst  == daddr &&
			    rth->rt_src  == iph->saddr &&
			    rth->fl.iif == 0 &&
			    !(dst_metric_locked(&rth->u.dst, RTAX_MTU))) {
				unsigned short mtu = new_mtu;

				if (new_mtu < 68 || new_mtu >= old_mtu) {

					/* BSD 4.2 compatibility hack :-( */
					if (mtu == 0 &&
					    old_mtu >= rth->u.dst.metrics[RTAX_MTU-1] &&
					    old_mtu >= 68 + (iph->ihl << 2))
						old_mtu -= iph->ihl << 2;

					mtu = guess_mtu(old_mtu);
				}
				if (mtu <= rth->u.dst.metrics[RTAX_MTU-1]) {
					if (mtu < rth->u.dst.metrics[RTAX_MTU-1]) {
						dst_confirm(&rth->u.dst);
						if (mtu < ip_rt_min_pmtu) {
							mtu = ip_rt_min_pmtu;
							rth->u.dst.metrics[RTAX_LOCK-1] |=
								(1 << RTAX_MTU);
						}
						rth->u.dst.metrics[RTAX_MTU-1] = mtu;
						//设置dst_entry过期的时间
						dst_set_expires(&rth->u.dst,
							ip_rt_mtu_expires);
					}
					est_mtu = mtu;
				}
			}
		}
		rcu_read_unlock();
	}
	return est_mtu ? : new_mtu;
}

static void ip_rt_update_pmtu(struct dst_entry *dst, u32 mtu)
{
	if (dst->metrics[RTAX_MTU-1] > mtu && mtu >= 68 &&
	    !(dst_metric_locked(dst, RTAX_MTU))) {
		if (mtu < ip_rt_min_pmtu) {
			mtu = ip_rt_min_pmtu;
			dst->metrics[RTAX_LOCK-1] |= (1 << RTAX_MTU);
		}
		dst->metrics[RTAX_MTU-1] = mtu;
		//设置dst_entry过期的时间
		dst_set_expires(dst, ip_rt_mtu_expires);
		call_netevent_notifiers(NETEVENT_PMTU_UPDATE, dst);
	}
}

static struct dst_entry *ipv4_dst_check(struct dst_entry *dst, u32 cookie)
{
	return NULL;
}

static void ipv4_dst_destroy(struct dst_entry *dst)
{
	struct rtable *rt = (struct rtable *) dst;
	struct inet_peer *peer = rt->peer;
	struct in_device *idev = rt->idev;

	if (peer) {
		rt->peer = NULL;
		inet_putpeer(peer);
	}

	if (idev) {
		rt->idev = NULL;
		in_dev_put(idev);
	}
}

static void ipv4_dst_ifdown(struct dst_entry *dst, struct net_device *dev,
			    int how)
{
	struct rtable *rt = (struct rtable *) dst;
	struct in_device *idev = rt->idev;
	if (dev != init_net.loopback_dev && idev && idev->dev == dev) {
		struct in_device *loopback_idev = in_dev_get(init_net.loopback_dev);
		if (loopback_idev) {
			rt->idev = loopback_idev;
			in_dev_put(idev);
		}
	}
}

static void ipv4_link_failure(struct sk_buff *skb)
{
	struct rtable *rt;

	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);

	rt = (struct rtable *) skb->dst;
	if (rt)
		dst_set_expires(&rt->u.dst, 0);
}

static int ip_rt_bug(struct sk_buff *skb)
{
	printk(KERN_DEBUG "ip_rt_bug: %u.%u.%u.%u -> %u.%u.%u.%u, %s\n",
		NIPQUAD(ip_hdr(skb)->saddr), NIPQUAD(ip_hdr(skb)->daddr),
		skb->dev ? skb->dev->name : "?");
	kfree_skb(skb);
	return 0;
}

/*
   We do not cache source address of outgoing interface,
   because it is used only by IP RR, TS and SRR options,
   so that it out of fast path.

   BTW remember: "addr" is allowed to be not aligned
   in IP options!
 */

void ip_rt_get_source(u8 *addr, struct rtable *rt)
{
	__be32 src;
	struct fib_result res;

	if (rt->fl.iif == 0)
		src = rt->rt_src;
	else if (fib_lookup(&rt->fl, &res) == 0) {
		src = FIB_RES_PREFSRC(res);
		fib_res_put(&res);
	} else
		src = inet_select_addr(rt->u.dst.dev, rt->rt_gateway,
					RT_SCOPE_UNIVERSE);
	memcpy(addr, &src, 4);
}

#ifdef CONFIG_NET_CLS_ROUTE
static void set_class_tag(struct rtable *rt, u32 tag)
{
	if (!(rt->u.dst.tclassid & 0xFFFF))
		rt->u.dst.tclassid |= tag & 0xFFFF;
	if (!(rt->u.dst.tclassid & 0xFFFF0000))
		rt->u.dst.tclassid |= tag & 0xFFFF0000;
}
#endif

static void rt_set_nexthop(struct rtable *rt, struct fib_result *res, u32 itag)
{
	struct fib_info *fi = res->fi;

	if (fi) {
		if (FIB_RES_GW(*res) &&
		    FIB_RES_NH(*res).nh_scope == RT_SCOPE_LINK)
		    
		    //从路由查询结果中返回下一跳的信息
			rt->rt_gateway = FIB_RES_GW(*res);
		memcpy(rt->u.dst.metrics, fi->fib_metrics,
		       sizeof(rt->u.dst.metrics));
		if (fi->fib_mtu == 0) {
			rt->u.dst.metrics[RTAX_MTU-1] = rt->u.dst.dev->mtu;
			
			if (rt->u.dst.metrics[RTAX_LOCK-1] & (1 << RTAX_MTU) &&
			    rt->rt_gateway != rt->rt_dst &&
			    rt->u.dst.dev->mtu > 576)
				rt->u.dst.metrics[RTAX_MTU-1] = 576;
		}
#ifdef CONFIG_NET_CLS_ROUTE
		rt->u.dst.tclassid = FIB_RES_NH(*res).nh_tclassid;
#endif
	} else
		rt->u.dst.metrics[RTAX_MTU-1]= rt->u.dst.dev->mtu;

	if (rt->u.dst.metrics[RTAX_HOPLIMIT-1] == 0)
		rt->u.dst.metrics[RTAX_HOPLIMIT-1] = sysctl_ip_default_ttl;
	
	if (rt->u.dst.metrics[RTAX_MTU-1] > IP_MAX_MTU)
		rt->u.dst.metrics[RTAX_MTU-1] = IP_MAX_MTU;
	
	if (rt->u.dst.metrics[RTAX_ADVMSS-1] == 0)
		rt->u.dst.metrics[RTAX_ADVMSS-1] = max_t(unsigned int, rt->u.dst.dev->mtu - 40,
				       ip_rt_min_advmss);
	
	if (rt->u.dst.metrics[RTAX_ADVMSS-1] > 65535 - 40)
		rt->u.dst.metrics[RTAX_ADVMSS-1] = 65535 - 40;

#ifdef CONFIG_NET_CLS_ROUTE
#ifdef CONFIG_IP_MULTIPLE_TABLES
	set_class_tag(rt, fib_rules_tclass(res));
#endif
	set_class_tag(rt, itag);
#endif

    //记录路由表项类型
	rt->rt_type = res->type;
}

/*
 * ip_rcv
 *  ip_rcv_finish
 *   ip_route_input
 *    ip_route_input_mc() ,ip多播地址
 */
static int ip_route_input_mc(struct sk_buff *skb, __be32 daddr, __be32 saddr,
				u8 tos, struct net_device *dev, int our)
{
	unsigned hash;
	struct rtable *rth;
	__be32 spec_dst;
	struct in_device *in_dev = in_dev_get(dev);
	u32 itag = 0;

	/* Primary sanity checks. */

	if (in_dev == NULL)
		return -EINVAL;

	if (MULTICAST(saddr) || BADCLASS(saddr) || LOOPBACK(saddr) ||
	    skb->protocol != htons(ETH_P_IP))
		goto e_inval;

	if (ZERONET(saddr)) {
		if (!LOCAL_MCAST(daddr))
			goto e_inval;
		spec_dst = inet_select_addr(dev, 0, RT_SCOPE_LINK);
	} else if (fib_validate_source(saddr, 0, tos, 0,
					dev, &spec_dst, &itag) < 0)
		goto e_inval;

	rth = dst_alloc(&ipv4_dst_ops);
	if (!rth)
		goto e_nobufs;

    //默认是一个不好用的函数
	rth->u.dst.output= ip_rt_bug;

	atomic_set(&rth->u.dst.__refcnt, 1);
	rth->u.dst.flags= DST_HOST;
	if (IN_DEV_CONF_GET(in_dev, NOPOLICY))
		rth->u.dst.flags |= DST_NOPOLICY;
	rth->fl.fl4_dst	= daddr;
	rth->rt_dst	= daddr;
	rth->fl.fl4_tos	= tos;
	rth->fl.mark    = skb->mark;
	rth->fl.fl4_src	= saddr;
	rth->rt_src	= saddr;
#ifdef CONFIG_NET_CLS_ROUTE
	rth->u.dst.tclassid = itag;
#endif
	rth->rt_iif	=
	rth->fl.iif	= dev->ifindex;
	rth->u.dst.dev	= init_net.loopback_dev;
	dev_hold(rth->u.dst.dev);
	rth->idev	= in_dev_get(rth->u.dst.dev);
	rth->fl.oif	= 0;
	rth->rt_gateway	= daddr;
	rth->rt_spec_dst= spec_dst;
	rth->rt_type	= RTN_MULTICAST;
	rth->rt_flags	= RTCF_MULTICAST;
	
	if (our) {
		rth->u.dst.input= ip_local_deliver;
		rth->rt_flags |= RTCF_LOCAL;
	}

#ifdef CONFIG_IP_MROUTE
	if (!LOCAL_MCAST(daddr) && IN_DEV_MFORWARD(in_dev))
		rth->u.dst.input = ip_mr_input;
#endif
	RT_CACHE_STAT_INC(in_slow_mc);

	in_dev_put(in_dev);
	hash = rt_hash(daddr, saddr, dev->ifindex);
	return rt_intern_hash(hash, rth, (struct rtable**) &skb->dst);

e_nobufs:
	in_dev_put(in_dev);
	return -ENOBUFS;

e_inval:
	in_dev_put(in_dev);
	return -EINVAL;
}


static void ip_handle_martian_source(struct net_device *dev,
				     struct in_device *in_dev,
				     struct sk_buff *skb,
				     __be32 daddr,
				     __be32 saddr)
{
	RT_CACHE_STAT_INC(in_martian_src);
#ifdef CONFIG_IP_ROUTE_VERBOSE
	if (IN_DEV_LOG_MARTIANS(in_dev) && net_ratelimit()) {
		/*
		 *	RFC1812 recommendation, if source is martian,
		 *	the only hint is MAC header.
		 */
		printk(KERN_WARNING "martian source %u.%u.%u.%u from "
			"%u.%u.%u.%u, on dev %s\n",
			NIPQUAD(daddr), NIPQUAD(saddr), dev->name);
		if (dev->hard_header_len && skb_mac_header_was_set(skb)) {
			int i;
			const unsigned char *p = skb_mac_header(skb);
			printk(KERN_WARNING "ll header: ");
			for (i = 0; i < dev->hard_header_len; i++, p++) {
				printk("%02x", *p);
				if (i < (dev->hard_header_len - 1))
					printk(":");
			}
			printk("\n");
		}
	}
#endif
}

/*
 * 设置skb->dst.input = ip_forward
 *     skb->dst.output = ip_output
 * ip_rcv
 *  ip_rcv_finish
 *	 ip_route_input
 *	  ip_route_input_slow
 *	   ip_mkroute_input
 *      __mkroute_input
 */
static inline int __mkroute_input(struct sk_buff *skb,
				  struct fib_result* res,
				  struct in_device *in_dev,
				  __be32 daddr, __be32 saddr, u32 tos,
				  struct rtable **result)
{

	struct rtable *rth;
	int err;
	struct in_device *out_dev;
	unsigned flags = 0;
	__be32 spec_dst;
	u32 itag;

	/* get a working reference to the output device */
	out_dev = in_dev_get(FIB_RES_DEV(*res));
	if (out_dev == NULL) {
		if (net_ratelimit())
			printk(KERN_CRIT "Bug in ip_route_input" \
			       "_slow(). Please, report\n");
		return -EINVAL;
	}


	err = fib_validate_source(saddr, daddr, tos, FIB_RES_OIF(*res),
				  in_dev->dev, &spec_dst, &itag);
	
	if (err < 0) {
		ip_handle_martian_source(in_dev->dev, in_dev, skb, daddr,
					 saddr);

		err = -EINVAL;
		goto cleanup;
	}

	if (err)
		flags |= RTCF_DIRECTSRC;

	if (out_dev == in_dev && err && !(flags & (RTCF_NAT | RTCF_MASQ)) &&
	    (IN_DEV_SHARED_MEDIA(out_dev) ||
	     inet_addr_onlink(out_dev, saddr, FIB_RES_GW(*res))))
		flags |= RTCF_DOREDIRECT;

	if (skb->protocol != htons(ETH_P_IP)) {
		/* Not IP (i.e. ARP). Do not create route, if it is
		 * invalid for proxy arp. DNAT routes are always valid.
		 */
		if (out_dev == in_dev && !(flags & RTCF_DNAT)) {
			err = -EINVAL;
			goto cleanup;
		}
	}


    /* 为路由缓存中的路由表项分配空间，并设置IP层的操作方法 */
	rth = dst_alloc(&ipv4_dst_ops);
	if (!rth) {
		err = -ENOBUFS;
		goto cleanup;
	}

    /* 设置路由缓存中的路由表项 */
	atomic_set(&rth->u.dst.__refcnt, 1);
	rth->u.dst.flags= DST_HOST;
	if (IN_DEV_CONF_GET(in_dev, NOPOLICY))
		rth->u.dst.flags |= DST_NOPOLICY;
	if (IN_DEV_CONF_GET(out_dev, NOXFRM))
		rth->u.dst.flags |= DST_NOXFRM;
	
	rth->fl.fl4_dst	= daddr;
	rth->rt_dst	= daddr;
	rth->fl.fl4_tos	= tos;
	rth->fl.mark    = skb->mark;
	rth->fl.fl4_src	= saddr;
	rth->rt_src	= saddr;
	rth->rt_gateway	= daddr;
	//网卡id和dev对象
	rth->rt_iif 	=
		rth->fl.iif	= in_dev->dev->ifindex;
	rth->u.dst.dev	= (out_dev)->dev;
	dev_hold(rth->u.dst.dev);
	rth->idev	= in_dev_get(rth->u.dst.dev);
	rth->fl.oif 	= 0;
	rth->rt_spec_dst= spec_dst;
    /* 设置路由转发接口 */
	rth->u.dst.input = ip_forward;
	//IP层的转发接口
	rth->u.dst.output = ip_output; 

    //设置下一跳的信息
	rt_set_nexthop(rth, res, itag);

	rth->rt_flags = flags;

	*result = rth;
	err = 0;
 cleanup:
	/* release the working reference to the output device */
	in_dev_put(out_dev);
	return err;
}

/*
  *  ip_rcv
  *    ip_rcv_finish
  * 	 ip_route_input
  * 	   ip_route_input_slow
  *          ip_mkroute_input
 */
static inline int ip_mkroute_input(struct sk_buff *skb,
				   struct fib_result* res,
				   const struct flowi *fl,
				   struct in_device *in_dev,
				   __be32 daddr, __be32 saddr, u32 tos)
{
	struct rtable* rth = NULL;
	int err;
	unsigned hash;

#ifdef CONFIG_IP_ROUTE_MULTIPATH
	if (res->fi && res->fi->fib_nhs > 1 && fl->oif == 0)
		fib_select_multipath(fl, res);
#endif

	/* create a routing cache entry */
	err = __mkroute_input(skb, res, in_dev, daddr, saddr, tos, &rth);
	if (err)
		return err;

	/* put it into the cache */
	hash = rt_hash(daddr, saddr, fl->iif);
	return rt_intern_hash(hash, rth, (struct rtable**)&skb->dst);
}

/*
 *	NOTE. We drop all the packets that has local source
 *	addresses, because every properly looped back packet
 *	must have correct destination already attached by output routine.
 *  我们丢弃所有从127.0.0.1发来的包
 *
 *	Such approach solves two big problems:
 *	1. Not simplex devices are handled properly.
 *     合理解决多设备的问题
 *	2. IP spoofing attempts are filtered with 100% of guarantee.
 *     百分百过滤IP spoofing尝试
 *
 *  设置skb->dst->input= ip_local_deliver;
 *
 *  ip_rcv
 *   ip_rcv_finish
 *    ip_route_input
 *     ip_route_input_slow
 *
 *   根据内核的数据结构来建立一个新的路由 ,
 */

static int ip_route_input_slow(struct sk_buff *skb, __be32 daddr, __be32 saddr,
			       u8 tos, struct net_device *dev)
{
	struct fib_result res; //保存查找路由表得到的结果
	struct in_device *in_dev = in_dev_get(dev);
	/*
	 * 得到flowi记录,以便查询路由表
	 */
	struct flowi fl = { .nl_u = { .ip4_u =
				                   { .daddr = daddr,
					                 .saddr = saddr,
					                 .tos = tos,
					                 .scope = RT_SCOPE_UNIVERSE,
				                   } 
	                            },
			                      .mark = skb->mark,
			                      .iif = dev->ifindex 
			          };
	
	unsigned	flags = 0;
	u32		itag = 0;
	struct rtable * rth;
	unsigned	hash;
	__be32		spec_dst;
	int		err = -EINVAL;
	int		free_res = 0;

	/* IP on this device is disabled. */

	if (!in_dev)
		goto out;

	/* Check for the most weird martians, which can be not detected
	   by fib_lookup.
	 */

	if (MULTICAST(saddr) || BADCLASS(saddr) || LOOPBACK(saddr))
		goto martian_source;

	if (daddr == htonl(0xFFFFFFFF) || (saddr == 0 && daddr == 0))
		goto brd_input;

	/* Accept zero addresses only to limited broadcast;
	 * I even do not know to fix it or not. Waiting for complains :-)
	 */
	if (ZERONET(saddr))
		goto martian_source;

	if (BADCLASS(daddr) || ZERONET(daddr) || LOOPBACK(daddr))
		goto martian_destination;

	/*
	 * 前面都是通过检查包的源和目的地址的合理性来确定对不同包的处理
	 *
	 *	Now we are ready to route packet.
	 *  根据fl查询路由表，并把查询得到的结果返回到res参数中
	 *
	 * 在ip_fib.h中
	 */
	if ((err = fib_lookup(&fl, &res)) != 0) {
		if (!IN_DEV_FORWARD(in_dev))  /*没找到，先判断转发标志是否打开*/
			goto e_hostunreach;
		goto no_route;
	}
	
	/*找到路由的标志*/
	free_res = 1;

	RT_CACHE_STAT_INC(in_slow_tot);

    /*根据查找到的路由类型，分类处理*/
	if (res.type == RTN_BROADCAST)
		goto brd_input;

    /*
     * 如果数据包是给本地主机的，则需要递交到上一层协议
     */
	if (res.type == RTN_LOCAL) {
		int result;
		/*如果是发给本机的包，则验证原地址是否合法*/
		result = fib_validate_source(saddr, daddr, tos,
					     init_net.loopback_dev->ifindex,
					     dev, &spec_dst, &itag);
		if (result < 0)
			goto martian_source;
		if (result)
			flags |= RTCF_DIRECTSRC;
		spec_dst = daddr;
		goto local_input;
	}

	if (!IN_DEV_FORWARD(in_dev))
		goto e_hostunreach;
	
	if (res.type != RTN_UNICAST)
		goto martian_destination;

    /*当查到的路由类型是指向远端的主机，把此路由加入cache中*/
	err = ip_mkroute_input(skb, &res, &fl, in_dev, daddr, saddr, tos);
done:
	in_dev_put(in_dev);
	if (free_res)
		fib_res_put(&res);
out:	return err;

/*当目的地址是广播地址，或查到的路由类型是广播类型*/
brd_input:
	if (skb->protocol != htons(ETH_P_IP))
		goto e_inval;

	if (ZERONET(saddr))
		spec_dst = inet_select_addr(dev, 0, RT_SCOPE_LINK);
	else {
		err = fib_validate_source(saddr, 0, tos, 0, dev, &spec_dst,
					  &itag);
		if (err < 0)
			goto martian_source;
		if (err)
			flags |= RTCF_DIRECTSRC;
	}
	flags |= RTCF_BROADCAST;
	res.type = RTN_BROADCAST;
	RT_CACHE_STAT_INC(in_brd);

/*当查找到的路由指向本机时*/
local_input:
	/*分配缓存路由项空间，并以确定的spec_dest等信息给路由项赋值*/
	rth = dst_alloc(&ipv4_dst_ops);
	if (!rth)
		goto e_nobufs;

    /* 初始化rtable的各个成员 */
	rth->u.dst.output= ip_rt_bug;

	atomic_set(&rth->u.dst.__refcnt, 1);
	rth->u.dst.flags= DST_HOST;
	if (IN_DEV_CONF_GET(in_dev, NOPOLICY))
		rth->u.dst.flags |= DST_NOPOLICY;
	rth->fl.fl4_dst	= daddr;
	rth->rt_dst	= daddr;
	rth->fl.fl4_tos	= tos;
	rth->fl.mark    = skb->mark;
	rth->fl.fl4_src	= saddr;
	rth->rt_src	= saddr;
#ifdef CONFIG_NET_CLS_ROUTE
	rth->u.dst.tclassid = itag;
#endif
	rth->rt_iif	=
	rth->fl.iif	= dev->ifindex;
	rth->u.dst.dev	= init_net.loopback_dev;
	dev_hold(rth->u.dst.dev);
	rth->idev	= in_dev_get(rth->u.dst.dev);
	rth->rt_gateway	= daddr;
	rth->rt_spec_dst= spec_dst;
	                  /* 设置转发到上层协议的处理函数 */
	rth->u.dst.input= ip_local_deliver; 
	rth->rt_flags 	= flags|RTCF_LOCAL;
	if (res.type == RTN_UNREACHABLE) {
		rth->u.dst.input= ip_error;
		rth->u.dst.error= -err;
		rth->rt_flags 	&= ~RTCF_LOCAL;
	}
	rth->rt_type	= res.type;
	/* 计算缓存表的hash值，寻找入口 */
	hash = rt_hash(daddr, saddr, fl.iif);
	/* 调用rt_intern_hash插入路由表项 */
	err = rt_intern_hash(hash, rth, (struct rtable**)&skb->dst); 
	goto done;

/*没有查找到路由的时候，向缓存中添加一条不可达路由项*/
no_route:
	RT_CACHE_STAT_INC(in_no_route);
	spec_dst = inet_select_addr(dev, 0, RT_SCOPE_UNIVERSE);
	res.type = RTN_UNREACHABLE;
	if (err == -ESRCH)
		err = -ENETUNREACH;
	goto local_input;

	/*
	 *	Do not cache martian addresses: they should be logged (RFC1812)
	 */
martian_destination:
	RT_CACHE_STAT_INC(in_martian_dst);
#ifdef CONFIG_IP_ROUTE_VERBOSE
	if (IN_DEV_LOG_MARTIANS(in_dev) && net_ratelimit())
		printk(KERN_WARNING "martian destination %u.%u.%u.%u from "
			"%u.%u.%u.%u, dev %s\n",
			NIPQUAD(daddr), NIPQUAD(saddr), dev->name);
#endif

e_hostunreach:
	err = -EHOSTUNREACH;
	goto done;

e_inval:
	err = -EINVAL;
	goto done;

e_nobufs:
	err = -ENOBUFS;
	goto done;

martian_source:
	ip_handle_martian_source(dev, in_dev, skb, daddr, saddr);
	goto e_inval;
}

/* 查找路由 ,初始化到skb->dst
 * ip_rcv
 *  ip_rcv_finish
 *   ip_route_input
 *
 * arp_process()
 *  ip_route_input()
 */
int ip_route_input(struct sk_buff *skb, __be32 daddr, __be32 saddr,
		   u8 tos, struct net_device *dev)
{
	struct rtable * rth;
	unsigned	hash;
	int iif = dev->ifindex;

	tos &= IPTOS_RT_MASK;
	hash = rt_hash(daddr, saddr, iif);

	rcu_read_lock();
	/* 路由缓存中查找*/
	for (rth = rcu_dereference(rt_hash_table[hash].chain); rth;
	     rth = rcu_dereference(rth->u.dst.rt_next)) {
		/* dst ip和src ip，iif,之类的是否分别相等 */
		if (rth->fl.fl4_dst == daddr &&
		    rth->fl.fl4_src == saddr &&
		    rth->fl.iif == iif &&
		    rth->fl.oif == 0 &&
		    rth->fl.mark == skb->mark &&
		    rth->fl.fl4_tos == tos) { //找到
		    
		    /* 在rt_hash_table[hash]中命中，更新使用计数器和时间戳 */
			dst_use(&rth->u.dst, jiffies);
			RT_CACHE_STAT_INC(in_hit);
			rcu_read_unlock();
			/* 这里的赋值就带上skb->dst->input的赋值了 */
			skb->dst = (struct dst_entry*)rth;
			return 0;
		}
		RT_CACHE_STAT_INC(in_hlist_search);
	}
	rcu_read_unlock();

	/* Multicast recognition logic is moved from route cache to here.
	   The problem was that too many Ethernet cards have broken/missing
	   hardware multicast filters :-( As result the host on multicasting
	   network acquires a lot of useless route cache entries, sort of
	   SDR messages from all the world. Now we try to get rid of them.
	   Really, provided software IP multicast filter is organized
	   reasonably (at least, hashed), it does not result in a slowdown
	   comparing with route cache reject entries.
	   Note, that multicast routers are not affected, because
	   route cache entry is created eventually.
	 *
	 * ip层多播地址
	 */
	if (MULTICAST(daddr)) {
		struct in_device *in_dev;

		rcu_read_lock();
		if ((in_dev = __in_dev_get_rcu(dev)) != NULL) {
			int our = ip_check_mc(in_dev, daddr, saddr,
				ip_hdr(skb)->protocol);
			if (our
#ifdef CONFIG_IP_MROUTE
			    || (!LOCAL_MCAST(daddr) && IN_DEV_MFORWARD(in_dev))
#endif
			    ) {
				rcu_read_unlock();
				/*
				 * 如果是多播地址,则需要查询多播路由.
				 */
				return ip_route_input_mc(skb, daddr, saddr,
							 tos, dev, our);
			}
		}
		rcu_read_unlock();
		return -EINVAL;
	}

	/*
	 * 如果路由缓存中查找不到匹配的表项，就需要转到路由表中去查找了
	 * ip_fib_local_table, ip_fib_main_table
	 */
	return ip_route_input_slow(skb, daddr, saddr, tos, dev);
}

/*
 * ip_queue_xmit()
 *  ip_route_output_flow()
 *	 __ip_route_output_key()
 *	  ip_route_output_slow()
 *	   ip_mkroute_output()
 *      __mkroute_output()
 */
static inline int __mkroute_output(struct rtable **result,
				   struct fib_result* res,
				   const struct flowi *fl,
				   const struct flowi *oldflp,
				   struct net_device *dev_out,
				   unsigned flags)
{
	struct rtable *rth;
	struct in_device *in_dev;
	u32 tos = RT_FL_TOS(oldflp);
	int err = 0;

	if (LOOPBACK(fl->fl4_src) && !(dev_out->flags&IFF_LOOPBACK))
		return -EINVAL;

	if (fl->fl4_dst == htonl(0xFFFFFFFF))
		res->type = RTN_BROADCAST;
	else if (MULTICAST(fl->fl4_dst))
		res->type = RTN_MULTICAST;
	else if (BADCLASS(fl->fl4_dst) || ZERONET(fl->fl4_dst))
		return -EINVAL;

	if (dev_out->flags & IFF_LOOPBACK)
		flags |= RTCF_LOCAL;

	/* get work reference to inet device */
	in_dev = in_dev_get(dev_out);
	if (!in_dev)
		return -EINVAL;

	if (res->type == RTN_BROADCAST) {
		flags |= RTCF_BROADCAST | RTCF_LOCAL;
		if (res->fi) {
			fib_info_put(res->fi);
			res->fi = NULL;
		}
	} else if (res->type == RTN_MULTICAST) {
		flags |= RTCF_MULTICAST|RTCF_LOCAL;
		if (!ip_check_mc(in_dev, oldflp->fl4_dst, oldflp->fl4_src,
				 oldflp->proto))
			flags &= ~RTCF_LOCAL;
		/* If multicast route do not exist use
		   default one, but do not gateway in this case.
		   Yes, it is hack.
		 */
		if (res->fi && res->prefixlen < 4) {
			fib_info_put(res->fi);
			res->fi = NULL;
		}
	}


    // 为路由缓存中的路由表项分配空间,并设置IP层的操作方法
	rth = dst_alloc(&ipv4_dst_ops);
	if (!rth) {
		err = -ENOBUFS;
		goto cleanup;
	}

	atomic_set(&rth->u.dst.__refcnt, 1);
	rth->u.dst.flags= DST_HOST;
	if (IN_DEV_CONF_GET(in_dev, NOXFRM))
		rth->u.dst.flags |= DST_NOXFRM;
	if (IN_DEV_CONF_GET(in_dev, NOPOLICY))
		rth->u.dst.flags |= DST_NOPOLICY;

	rth->fl.fl4_dst	= oldflp->fl4_dst;
	rth->fl.fl4_tos	= tos;
	rth->fl.fl4_src	= oldflp->fl4_src;
	rth->fl.oif	= oldflp->oif;
	rth->fl.mark    = oldflp->mark;
	rth->rt_dst	= fl->fl4_dst;
	rth->rt_src	= fl->fl4_src;
	rth->rt_iif	= oldflp->oif ? : dev_out->ifindex;
	/* get references to the devices that are to be hold by the routing
	   cache entry */
	rth->u.dst.dev	= dev_out;
	dev_hold(dev_out);
	rth->idev	= in_dev_get(dev_out);
	rth->rt_gateway = fl->fl4_dst;
	rth->rt_spec_dst= fl->fl4_src;
    //设置IP层输出函数指针
	rth->u.dst.output=ip_output;

	RT_CACHE_STAT_INC(out_slow_tot);

    /*
     * 设置IP层递交函数指针
     * 如果目的地就是本计算机,则直接递交到上一层
     */ 
	if (flags & RTCF_LOCAL) {
		rth->u.dst.input = ip_local_deliver;
		rth->rt_spec_dst = fl->fl4_dst;
	}
	//广播或者多播
	if (flags & (RTCF_BROADCAST | RTCF_MULTICAST)) {
		rth->rt_spec_dst = fl->fl4_src;
		
		if (flags & RTCF_LOCAL &&
		    !(dev_out->flags & IFF_LOOPBACK)) { //不是loopback
		    
			rth->u.dst.output = ip_mc_output;
			RT_CACHE_STAT_INC(out_slow_mc);
		}
#ifdef CONFIG_IP_MROUTE
		if (res->type == RTN_MULTICAST) {
			if (IN_DEV_MFORWARD(in_dev) &&
			    !LOCAL_MCAST(oldflp->fl4_dst)) {
				rth->u.dst.input = ip_mr_input;
				rth->u.dst.output = ip_mc_output;
			}
		}
#endif
	}

    //设置下一跳
	rt_set_nexthop(rth, res, 0);

	rth->rt_flags = flags;

	*result = rth;
 cleanup:
	/* release work reference to inet device */
	in_dev_put(in_dev);

	return err;
}

/*
 * ip_queue_xmit()
 *  ip_route_output_flow()
 *   __ip_route_output_key()
 *    ip_route_output_slow()
 *     ip_mkroute_output()
 */
static inline int ip_mkroute_output(struct rtable **rp,
				    struct fib_result* res,
				    const struct flowi *fl,
				    const struct flowi *oldflp,
				    struct net_device *dev_out,
				    unsigned flags)
{
	struct rtable *rth = NULL;
	int err = __mkroute_output(&rth, res, fl, oldflp, dev_out, flags);
	unsigned hash;
	if (err == 0) {
		/*
		 * 把rth记录的路由表项内容添加到路由缓存中 
		 * 通过neighbour子系统设置的第二层的入口函数
		 */
	    
		hash = rt_hash(oldflp->fl4_dst, oldflp->fl4_src, oldflp->oif);
		err = rt_intern_hash(hash, rth, rp);
	}

	return err;
}

/*
 * Major route resolver routine.
 * 指向路由查询，把查询到的结果设置到路由缓存中。 
 *
 * ip_queue_xmit()
 *  ip_route_output_flow()
 *   __ip_route_output_key()
 *    ip_route_output_slow()
 */ 

static int ip_route_output_slow(struct rtable **rp, const struct flowi *oldflp)
{
    /*得到flowi记录，以便查询路由表*/
	u32 tos	= RT_FL_TOS(oldflp);  
	struct flowi fl = { .nl_u = { .ip4_u =
				      { .daddr = oldflp->fl4_dst,
					.saddr = oldflp->fl4_src,
					.tos = tos & IPTOS_RT_MASK,
					.scope = ((tos & RTO_ONLINK) ?
						  RT_SCOPE_LINK :
						  RT_SCOPE_UNIVERSE), /*根据这个标志，得出路由的scope*/
				      } },
			    .mark = oldflp->mark,
			    .iif = init_net.loopback_dev->ifindex, /*设备号为lo的设备号?*/
			    .oif = oldflp->oif };
	struct fib_result res;        // 用来保存查找路由表得到结果
	unsigned flags = 0;           // 路由缓存中的路由表项
	struct net_device *dev_out = NULL; // 输出设备
	int free_res = 0; 
	int err;


	res.fi		= NULL;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	res.r		= NULL;
#endif

    /*先是对源地址， 发包接口号和目的地址进行判断分类处理。下面的每一个红色跳转就是一种情况*/
	if (oldflp->fl4_src) {
		err = -EINVAL;
		if (MULTICAST(oldflp->fl4_src) ||
		    BADCLASS(oldflp->fl4_src) ||
		    ZERONET(oldflp->fl4_src))
			goto out;
		/*上面是对报文源地址的合理性检查，源地址是多播，广播或0地址时，返回错误*/

		/* It is equivalent to inet_addr_type(saddr) == RTN_LOCAL */
		dev_out = ip_dev_find(oldflp->fl4_src);
		if (dev_out == NULL)
			goto out;

		/* I removed check for oif == dev_out->oif here.
		   It was wrong for two reasons:
		   我在这里删去检查oif == dev_out->oif是否成立，因为有两个原因说明这个检查时错误的：
		   1. ip_dev_find(saddr) can return wrong iface, if saddr is
		      assigned to multiple interfaces.
		   如果源地址是一个多播接口的地址，函数ip_dev_find(net, saddr)可能返回错误的设备接口。   
		   2. Moreover, we are allowed to send packets with saddr
		      of another iface. --ANK
		   而且可以用另外设备接口的源地址发送报文   
		 */

		if (oldflp->oif == 0
		    && (MULTICAST(oldflp->fl4_dst) || oldflp->fl4_dst == htonl(0xFFFFFFFF))) {
		    /*发包接口为lo，目的地址是广播或多播时查找发包设备，ip_dev_find返回与所给定的源地址相等的第一个设备*/
			/* Special hack: user can direct multicasts
			   and limited broadcast via necessary interface
			   without fiddling with IP_MULTICAST_IF or IP_PKTINFO.
			   This hack is not just for fun, it allows
			   vic,vat and friends to work.
			   They bind socket to loopback, set ttl to zero
			   and expect that it will work.
			   From the viewpoint of routing cache they are broken,
			   because we are not allowed to build multicast path
			   with loopback source addr (look, routing cache
			   cannot know, that ttl is zero, so that packet
			   will not leave this host and route is valid).
			   Luckily, this hack is good workaround.
			 */
             /*
              * 当报文初始化的出接口为lo接口源地址不为空目的地址是多播或广播地址时，
              * 找到源地址所对应的接口重新为出接口赋值， 然后创建cache路由项
              */
			fl.oif = dev_out->ifindex;
			goto make_route;
		}
		if (dev_out)
			dev_put(dev_out);
		dev_out = NULL;
	}


	if (oldflp->oif) { /*发包设备不为空*/
		/*检测出接口是否存在*/
		dev_out = dev_get_by_index(&init_net, oldflp->oif);
		err = -ENODEV;
		if (dev_out == NULL)
			goto out;

		/* RACE: Check return value of inet_select_addr instead. */
		/*看设备是否是多地址*/
		if (__in_dev_get_rtnl(dev_out) == NULL) {
			dev_put(dev_out);
			goto out;	/* Wrong error code */
		}

		if (LOCAL_MCAST(oldflp->fl4_dst) || oldflp->fl4_dst == htonl(0xFFFFFFFF)) {
			if (!fl.fl4_src)
				fl.fl4_src = inet_select_addr(dev_out, 0,
							      RT_SCOPE_LINK);
			goto make_route;
		}
		if (!fl.fl4_src) {
			if (MULTICAST(oldflp->fl4_dst))
				fl.fl4_src = inet_select_addr(dev_out, 0,
							      fl.fl4_scope);
			else if (!oldflp->fl4_dst)
				fl.fl4_src = inet_select_addr(dev_out, 0,
							      RT_SCOPE_HOST);
		}
	}

	if (!fl.fl4_dst) {
		fl.fl4_dst = fl.fl4_src;
		if (!fl.fl4_dst)
			fl.fl4_dst = fl.fl4_src = htonl(INADDR_LOOPBACK); /*目的和源地址都是空，则赋值为lo接口地址*/
		if (dev_out)
			dev_put(dev_out);
		dev_out = init_net.loopback_dev;
		dev_hold(dev_out);
		fl.oif = init_net.loopback_dev->ifindex;
		res.type = RTN_LOCAL;
		flags |= RTCF_LOCAL;
		goto make_route;
	}

	
	/* 根据fl查找到路由表,并把查询得到结果返回到res参数中 
	 * 在ip_fib.h中
	 */
	if (fib_lookup(&fl, &res)) {
		res.fi = NULL;
		if (oldflp->oif) {
			/* Apparently, routing tables are wrong. Assume,
			   that the destination is on link.

			   WHY? DW.
			   Because we are allowed to send to iface
			   even if it has NO routes and NO assigned
			   addresses. When oif is specified, routing
			   tables are looked up with only one purpose:
			   to catch if destination is gatewayed, rather than
			   direct. Moreover, if MSG_DONTROUTE is set,
			   we send packet, ignoring both routing tables
			   and ifaddr state. --ANK


			   We could make it even if oif is unknown,
			   likely IPv6, but we do not.
			 */

			if (fl.fl4_src == 0)
				fl.fl4_src = inet_select_addr(dev_out, 0,
							      RT_SCOPE_LINK);
			res.type = RTN_UNICAST;
			goto make_route;
		}
		if (dev_out)
			dev_put(dev_out);
		err = -ENETUNREACH;
		goto out;
	}
	free_res = 1;

	if (res.type == RTN_LOCAL) {
		if (!fl.fl4_src)
			fl.fl4_src = fl.fl4_dst;
		if (dev_out)
			dev_put(dev_out);
		dev_out = init_net.loopback_dev;
		dev_hold(dev_out);
		fl.oif = dev_out->ifindex;
		if (res.fi)
			fib_info_put(res.fi);
		res.fi = NULL;
		flags |= RTCF_LOCAL;
		/*没有查到路由，并且出接口不为lo*/
		goto make_route;
	}

#ifdef CONFIG_IP_ROUTE_MULTIPATH
	if (res.fi->fib_nhs > 1 && fl.oif == 0)
		fib_select_multipath(&fl, &res);
	else
#endif
	if (!res.prefixlen && res.type == RTN_UNICAST && !fl.oif)
		fib_select_default(&fl, &res);

	if (!fl.fl4_src)
		fl.fl4_src = FIB_RES_PREFSRC(res);

	if (dev_out)
		dev_put(dev_out);
	dev_out = FIB_RES_DEV(res);
	dev_hold(dev_out);
	fl.oif = dev_out->ifindex;


    /*往cache中添加相应的路由项*/
make_route:
	err = ip_mkroute_output(rp, &res, &fl, oldflp, dev_out, flags);


	if (free_res)
		fib_res_put(&res);
	if (dev_out)
		dev_put(dev_out);
out:	return err;
}

/*
 * 根据健值查找路由表项
 *
 * 根据数据包的地址、端口、等信息得到健值，查找路由表.
 * ip_queue_xmit()
 *  ip_route_output_flow()
 *   __ip_route_output_key()
 *
 * 
 */
int __ip_route_output_key(struct rtable **rp, const struct flowi *flp)
{
	unsigned hash;
	struct rtable *rth;

    /*类似于ip_route_input,先在cache中查找路由， 找到就返回*/
	hash = rt_hash(flp->fl4_dst, flp->fl4_src, flp->oif);

	rcu_read_lock_bh();
	/*
	 * 在哈希表rt_hash_table中查找与flp匹配的路由表条目
	 * 根据目的地址、源地址、端口设备和TOS等字段判断是否匹配
	 */
	for (rth = rcu_dereference(rt_hash_table[hash].chain); rth;
		rth = rcu_dereference(rth->u.dst.rt_next)) {
			
		if (rth->fl.fl4_dst == flp->fl4_dst &&
		    rth->fl.fl4_src == flp->fl4_src &&
		    rth->fl.iif == 0 &&
		    rth->fl.oif == flp->oif &&
		    rth->fl.mark == flp->mark &&
		    !((rth->fl.fl4_tos ^ flp->fl4_tos) &
			    (IPTOS_RT_MASK | RTO_ONLINK))) {
			dst_use(&rth->u.dst, jiffies);
			RT_CACHE_STAT_INC(out_hit);
			rcu_read_unlock_bh();
			//如果匹配成功，则通过参数rp返回该条目
			*rp = rth;
			return 0;
		}
		RT_CACHE_STAT_INC(out_hlist_search);
	}
	rcu_read_unlock_bh();

    // 如果路由缓存中没有匹配成功，则到路由表中去查找
	return ip_route_output_slow(rp, flp);
}

EXPORT_SYMBOL_GPL(__ip_route_output_key);

static void ipv4_rt_blackhole_update_pmtu(struct dst_entry *dst, u32 mtu)
{
}

static struct dst_ops ipv4_dst_blackhole_ops = {
	.family			=	AF_INET,
	.protocol		=	__constant_htons(ETH_P_IP),
	.destroy		=	ipv4_dst_destroy,
	.check			=	ipv4_dst_check,
	.update_pmtu		=	ipv4_rt_blackhole_update_pmtu,
	.entry_size		=	sizeof(struct rtable),
};


static int ipv4_blackhole_output(struct sk_buff *skb)
{
	kfree_skb(skb);
	return 0;
}

static int ipv4_dst_blackhole(struct rtable **rp, struct flowi *flp, struct sock *sk)
{
	struct rtable *ort = *rp;
	struct rtable *rt = (struct rtable *)
		dst_alloc(&ipv4_dst_blackhole_ops);

	if (rt) {
		struct dst_entry *new = &rt->u.dst;

		atomic_set(&new->__refcnt, 1);
		new->__use = 1;
		new->input = ipv4_blackhole_output;
		new->output = ipv4_blackhole_output;
		memcpy(new->metrics, ort->u.dst.metrics, RTAX_MAX*sizeof(u32));

		new->dev = ort->u.dst.dev;
		if (new->dev)
			dev_hold(new->dev);

		rt->fl = ort->fl;

		rt->idev = ort->idev;
		if (rt->idev)
			in_dev_hold(rt->idev);
		rt->rt_flags = ort->rt_flags;
		rt->rt_type = ort->rt_type;
		rt->rt_dst = ort->rt_dst;
		rt->rt_src = ort->rt_src;
		rt->rt_iif = ort->rt_iif;
		rt->rt_gateway = ort->rt_gateway;
		rt->rt_spec_dst = ort->rt_spec_dst;
		rt->peer = ort->peer;
		if (rt->peer)
			atomic_inc(&rt->peer->refcnt);

		dst_free(new);
	}

	dst_release(&(*rp)->u.dst);
	*rp = rt;
	return (rt ? 0 : -ENOMEM);
}

/*
 * 路由查询,参数rp带出查询结果
 *
 * ip_queue_xmit()
 *  ip_route_output_flow()
 *
 * inet_rtm_getroute()
 *  ip_route_output_key()
 *   ip_route_output_flow()
 *
 * sys_socketcall()
 *  sys_send()
 *   sys_sendto()
 *    sock_sendmsg()
 *     __sock_sendmsg() ; socket->ops->sendmsg
 *      inet_sendmsg()
 *       udp_sendmsg()
 *        ip_route_output_flow()
 *
 * arp_process()
 *  arp_filter()
 *   ip_route_output_key()
 *    ip_route_output_flow()
 */
int ip_route_output_flow(struct rtable **rp /* 参数rp带出查询结果 */ , 
                                 struct flowi *flp, 
                                 struct sock *sk, int flags)
{
	int err;

    /*根据健值查找路由表项*/
	if ((err = __ip_route_output_key(rp, flp)) != 0)
		return err;

    /*IPSec 的处理代码*/
	if (flp->proto) {
		if (!flp->fl4_src)
			flp->fl4_src = (*rp)->rt_src;
		
		if (!flp->fl4_dst)
			flp->fl4_dst = (*rp)->rt_dst;
		
		err = __xfrm_lookup((struct dst_entry **)rp, flp, sk, flags);
		if (err == -EREMOTE)
			err = ipv4_dst_blackhole(rp, flp, sk);

		return err;
	}

	return 0;
}

EXPORT_SYMBOL_GPL(ip_route_output_flow);

/*
 * inet_rtm_getroute()
 *  ip_route_output_key()
 *
 * arp_process()
 *  arp_filter()
 *   ip_route_output_key()
 */
int ip_route_output_key(struct rtable **rp, struct flowi *flp)
{
	return ip_route_output_flow(rp, flp, NULL, 0);
}

static int rt_fill_info(struct sk_buff *skb, u32 pid, u32 seq, int event,
			int nowait, unsigned int flags)
{
	struct rtable *rt = (struct rtable*)skb->dst;
	struct rtmsg *r;
	struct nlmsghdr *nlh;
	long expires;
	u32 id = 0, ts = 0, tsage = 0, error;

	nlh = nlmsg_put(skb, pid, seq, event, sizeof(*r), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	r = nlmsg_data(nlh);
	r->rtm_family	 = AF_INET;
	r->rtm_dst_len	= 32;
	r->rtm_src_len	= 0;
	r->rtm_tos	= rt->fl.fl4_tos;
	r->rtm_table	= RT_TABLE_MAIN;
	NLA_PUT_U32(skb, RTA_TABLE, RT_TABLE_MAIN);
	r->rtm_type	= rt->rt_type;
	r->rtm_scope	= RT_SCOPE_UNIVERSE;
	r->rtm_protocol = RTPROT_UNSPEC;
	r->rtm_flags	= (rt->rt_flags & ~0xFFFF) | RTM_F_CLONED;
	if (rt->rt_flags & RTCF_NOTIFY)
		r->rtm_flags |= RTM_F_NOTIFY;

	NLA_PUT_BE32(skb, RTA_DST, rt->rt_dst);

	if (rt->fl.fl4_src) {
		r->rtm_src_len = 32;
		NLA_PUT_BE32(skb, RTA_SRC, rt->fl.fl4_src);
	}
	if (rt->u.dst.dev)
		NLA_PUT_U32(skb, RTA_OIF, rt->u.dst.dev->ifindex);
#ifdef CONFIG_NET_CLS_ROUTE
	if (rt->u.dst.tclassid)
		NLA_PUT_U32(skb, RTA_FLOW, rt->u.dst.tclassid);
#endif
	if (rt->fl.iif)
		NLA_PUT_BE32(skb, RTA_PREFSRC, rt->rt_spec_dst);
	else if (rt->rt_src != rt->fl.fl4_src)
		NLA_PUT_BE32(skb, RTA_PREFSRC, rt->rt_src);

	if (rt->rt_dst != rt->rt_gateway)
		NLA_PUT_BE32(skb, RTA_GATEWAY, rt->rt_gateway);

	if (rtnetlink_put_metrics(skb, rt->u.dst.metrics) < 0)
		goto nla_put_failure;

	error = rt->u.dst.error;
	expires = rt->u.dst.expires ? rt->u.dst.expires - jiffies : 0;
	if (rt->peer) {
		id = rt->peer->ip_id_count;
		if (rt->peer->tcp_ts_stamp) {
			ts = rt->peer->tcp_ts;
			tsage = get_seconds() - rt->peer->tcp_ts_stamp;
		}
	}

	if (rt->fl.iif) {
#ifdef CONFIG_IP_MROUTE
		__be32 dst = rt->rt_dst;

		if (MULTICAST(dst) && !LOCAL_MCAST(dst) &&
		    IPV4_DEVCONF_ALL(MC_FORWARDING)) {
			int err = ipmr_get_route(skb, r, nowait);
			if (err <= 0) {
				if (!nowait) {
					if (err == 0)
						return 0;
					goto nla_put_failure;
				} else {
					if (err == -EMSGSIZE)
						goto nla_put_failure;
					error = err;
				}
			}
		} else
#endif
			NLA_PUT_U32(skb, RTA_IIF, rt->fl.iif);
	}

	if (rtnl_put_cacheinfo(skb, &rt->u.dst, id, ts, tsage,
			       expires, error) < 0)
		goto nla_put_failure;

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static int inet_rtm_getroute(struct sk_buff *in_skb, struct nlmsghdr* nlh, void *arg)
{
	struct rtmsg *rtm;
	struct nlattr *tb[RTA_MAX+1];
	struct rtable *rt = NULL;
	__be32 dst = 0;
	__be32 src = 0;
	u32 iif;
	int err;
	struct sk_buff *skb;

	err = nlmsg_parse(nlh, sizeof(*rtm), tb, RTA_MAX, rtm_ipv4_policy);
	if (err < 0)
		goto errout;

	rtm = nlmsg_data(nlh);

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL) {
		err = -ENOBUFS;
		goto errout;
	}

	/* Reserve room for dummy headers, this skb can pass
	   through good chunk of routing engine.
	 */
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);

	/* Bugfix: need to give ip_route_input enough of an IP header to not gag. */
	ip_hdr(skb)->protocol = IPPROTO_ICMP;
	skb_reserve(skb, MAX_HEADER + sizeof(struct iphdr));

	src = tb[RTA_SRC] ? nla_get_be32(tb[RTA_SRC]) : 0;
	dst = tb[RTA_DST] ? nla_get_be32(tb[RTA_DST]) : 0;
	iif = tb[RTA_IIF] ? nla_get_u32(tb[RTA_IIF]) : 0;

	if (iif) {
		struct net_device *dev;

		dev = __dev_get_by_index(&init_net, iif);
		if (dev == NULL) {
			err = -ENODEV;
			goto errout_free;
		}

		skb->protocol	= htons(ETH_P_IP);
		skb->dev	= dev;
		local_bh_disable();
		err = ip_route_input(skb, dst, src, rtm->rtm_tos, dev);
		local_bh_enable();

		rt = (struct rtable*) skb->dst;
		if (err == 0 && rt->u.dst.error)
			err = -rt->u.dst.error;
	} else {
		struct flowi fl = {
			.nl_u = {
				.ip4_u = {
					.daddr = dst,
					.saddr = src,
					.tos = rtm->rtm_tos,
				},
			},
			.oif = tb[RTA_OIF] ? nla_get_u32(tb[RTA_OIF]) : 0,
		};
		err = ip_route_output_key(&rt, &fl);
	}

	if (err)
		goto errout_free;

	skb->dst = &rt->u.dst;
	if (rtm->rtm_flags & RTM_F_NOTIFY)
		rt->rt_flags |= RTCF_NOTIFY;

	err = rt_fill_info(skb, NETLINK_CB(in_skb).pid, nlh->nlmsg_seq,
				RTM_NEWROUTE, 0, 0);
	if (err <= 0)
		goto errout_free;

	err = rtnl_unicast(skb, NETLINK_CB(in_skb).pid);
errout:
	return err;

errout_free:
	kfree_skb(skb);
	goto errout;
}

int ip_rt_dump(struct sk_buff *skb,  struct netlink_callback *cb)
{
	struct rtable *rt;
	int h, s_h;
	int idx, s_idx;

	s_h = cb->args[0];
	if (s_h < 0)
		s_h = 0;
	s_idx = idx = cb->args[1];
	for (h = s_h; h <= rt_hash_mask; h++) {
		rcu_read_lock_bh();
		for (rt = rcu_dereference(rt_hash_table[h].chain), idx = 0; rt;
		     rt = rcu_dereference(rt->u.dst.rt_next), idx++) {
			if (idx < s_idx)
				continue;
			skb->dst = dst_clone(&rt->u.dst);
			if (rt_fill_info(skb, NETLINK_CB(cb->skb).pid,
					 cb->nlh->nlmsg_seq, RTM_NEWROUTE,
					 1, NLM_F_MULTI) <= 0) {
				dst_release(xchg(&skb->dst, NULL));
				rcu_read_unlock_bh();
				goto done;
			}
			dst_release(xchg(&skb->dst, NULL));
		}
		rcu_read_unlock_bh();
		s_idx = 0;
	}

done:
	cb->args[0] = h;
	cb->args[1] = idx;
	return skb->len;
}

void ip_rt_multicast_event(struct in_device *in_dev)
{
	rt_cache_flush(0);
}

#ifdef CONFIG_SYSCTL
static int flush_delay;

static int ipv4_sysctl_rtcache_flush(ctl_table *ctl, int write,
					struct file *filp, void __user *buffer,
					size_t *lenp, loff_t *ppos)
{
	if (write) {
		proc_dointvec(ctl, write, filp, buffer, lenp, ppos);
		rt_cache_flush(flush_delay);
		return 0;
	}

	return -EINVAL;
}

static int ipv4_sysctl_rtcache_flush_strategy(ctl_table *table,
						int __user *name,
						int nlen,
						void __user *oldval,
						size_t __user *oldlenp,
						void __user *newval,
						size_t newlen)
{
	int delay;
	if (newlen != sizeof(int))
		return -EINVAL;
	if (get_user(delay, (int __user *)newval))
		return -EFAULT;
	rt_cache_flush(delay);
	return 0;
}

ctl_table ipv4_route_table[] = {
	{
		.ctl_name 	= NET_IPV4_ROUTE_FLUSH,
		.procname	= "flush",
		.data		= &flush_delay,
		.maxlen		= sizeof(int),
		.mode		= 0200,
		.proc_handler	= &ipv4_sysctl_rtcache_flush,
		.strategy	= &ipv4_sysctl_rtcache_flush_strategy,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MIN_DELAY,
		.procname	= "min_delay",
		.data		= &ip_rt_min_delay,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MAX_DELAY,
		.procname	= "max_delay",
		.data		= &ip_rt_max_delay,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_THRESH,
		.procname	= "gc_thresh",
		.data		= &ipv4_dst_ops.gc_thresh,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MAX_SIZE,
		.procname	= "max_size",
		.data		= &ip_rt_max_size,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		/*  Deprecated. Use gc_min_interval_ms */

		.ctl_name	= NET_IPV4_ROUTE_GC_MIN_INTERVAL,
		.procname	= "gc_min_interval",
		.data		= &ip_rt_gc_min_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_MIN_INTERVAL_MS,
		.procname	= "gc_min_interval_ms",
		.data		= &ip_rt_gc_min_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_ms_jiffies,
		.strategy	= &sysctl_ms_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_TIMEOUT,
		.procname	= "gc_timeout",
		.data		= &ip_rt_gc_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_INTERVAL,
		.procname	= "gc_interval",
		.data		= &ip_rt_gc_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_REDIRECT_LOAD,
		.procname	= "redirect_load",
		.data		= &ip_rt_redirect_load,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_REDIRECT_NUMBER,
		.procname	= "redirect_number",
		.data		= &ip_rt_redirect_number,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_REDIRECT_SILENCE,
		.procname	= "redirect_silence",
		.data		= &ip_rt_redirect_silence,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_ERROR_COST,
		.procname	= "error_cost",
		.data		= &ip_rt_error_cost,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_ERROR_BURST,
		.procname	= "error_burst",
		.data		= &ip_rt_error_burst,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_ELASTICITY,
		.procname	= "gc_elasticity",
		.data		= &ip_rt_gc_elasticity,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MTU_EXPIRES,
		.procname	= "mtu_expires",
		.data		= &ip_rt_mtu_expires,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MIN_PMTU,
		.procname	= "min_pmtu",
		.data		= &ip_rt_min_pmtu,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MIN_ADVMSS,
		.procname	= "min_adv_mss",
		.data		= &ip_rt_min_advmss,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_SECRET_INTERVAL,
		.procname	= "secret_interval",
		.data		= &ip_rt_secret_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{ .ctl_name = 0 }
};
#endif

#ifdef CONFIG_NET_CLS_ROUTE
struct ip_rt_acct *ip_rt_acct;

/* This code sucks.  But you should have seen it before! --RR */

/* IP route accounting ptr for this logical cpu number. */
#define IP_RT_ACCT_CPU(i) (ip_rt_acct + i * 256)

#ifdef CONFIG_PROC_FS
static int ip_rt_acct_read(char *buffer, char **start, off_t offset,
			   int length, int *eof, void *data)
{
	unsigned int i;

	if ((offset & 3) || (length & 3))
		return -EIO;

	if (offset >= sizeof(struct ip_rt_acct) * 256) {
		*eof = 1;
		return 0;
	}

	if (offset + length >= sizeof(struct ip_rt_acct) * 256) {
		length = sizeof(struct ip_rt_acct) * 256 - offset;
		*eof = 1;
	}

	offset /= sizeof(u32);

	if (length > 0) {
		u32 *dst = (u32 *) buffer;

		*start = buffer;
		memset(dst, 0, length);

		for_each_possible_cpu(i) {
			unsigned int j;
			u32 *src = ((u32 *) IP_RT_ACCT_CPU(i)) + offset;

			for (j = 0; j < length/4; j++)
				dst[j] += src[j];
		}
	}
	return length;
}
#endif /* CONFIG_PROC_FS */
#endif /* CONFIG_NET_CLS_ROUTE */

static __initdata unsigned long rhash_entries;
static int __init set_rhash_entries(char *str)
{
	if (!str)
		return 0;
	rhash_entries = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("rhash_entries=", set_rhash_entries);


/*
 * inet_init()
 *  ip_init()
 *   ip_rt_init()
 *
 * 路由子系统初始化
 */
int __init ip_rt_init(void)
{
	int rc = 0;

	rt_hash_rnd = (int) ((num_physpages ^ (num_physpages>>8)) ^
			     (jiffies ^ (jiffies >> 7)));

#ifdef CONFIG_NET_CLS_ROUTE
	{
	int order;
	for (order = 0;
	     (PAGE_SIZE << order) < 256 * sizeof(struct ip_rt_acct) * NR_CPUS; order++)
		/* NOTHING */;
	ip_rt_acct = (struct ip_rt_acct *)__get_free_pages(GFP_KERNEL, order);
	if (!ip_rt_acct)
		panic("IP: failed to allocate ip_rt_acct\n");
	memset(ip_rt_acct, 0, PAGE_SIZE << order);
	}
#endif

	ipv4_dst_ops.kmem_cachep =
		kmem_cache_create("ip_dst_cache", sizeof(struct rtable), 0,
				  SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);

	ipv4_dst_blackhole_ops.kmem_cachep = ipv4_dst_ops.kmem_cachep;

    /*创建struct rt_hash_bucket 类型的哈希表*/
	rt_hash_table = (struct rt_hash_bucket *)
		alloc_large_system_hash("IP route cache",
					sizeof(struct rt_hash_bucket),
					rhash_entries,
					(num_physpages >= 128 * 1024) ?
					15 : 17,
					0,
					&rt_hash_log,
					&rt_hash_mask,
					0);
	
	memset(rt_hash_table, 0, (rt_hash_mask + 1) * sizeof(struct rt_hash_bucket));
	rt_hash_lock_init();

    /*垃圾回收阀值*/
	ipv4_dst_ops.gc_thresh = (rt_hash_mask + 1);
	ip_rt_max_size = (rt_hash_mask + 1) * 16;

    /*主要的初始化函数*/
	devinet_init();

	//初始化默认路由表
	ip_fib_init();

	init_timer(&rt_flush_timer);
	rt_flush_timer.function = rt_run_flush;
	init_timer(&rt_secret_timer);
	rt_secret_timer.function = rt_secret_rebuild;

	/* All the timers, started at system startup tend
	   to synchronize. Perturb it a bit.
	 */
	schedule_delayed_work(&expires_work,
		net_random() % ip_rt_gc_interval + ip_rt_gc_interval);

	rt_secret_timer.expires = jiffies + net_random() % ip_rt_secret_interval +
		ip_rt_secret_interval;
	add_timer(&rt_secret_timer);

#ifdef CONFIG_PROC_FS
	{
	struct proc_dir_entry *rtstat_pde = NULL; /* keep gcc happy */
	if (!proc_net_fops_create(&init_net, "rt_cache", S_IRUGO, &rt_cache_seq_fops) ||
	    !(rtstat_pde = create_proc_entry("rt_cache", S_IRUGO,
					     init_net.proc_net_stat))) {
		return -ENOMEM;
	}
	rtstat_pde->proc_fops = &rt_cpu_seq_fops;
	}
#ifdef CONFIG_NET_CLS_ROUTE
	create_proc_read_entry("rt_acct", 0, init_net.proc_net, ip_rt_acct_read, NULL);
#endif
#endif
#ifdef CONFIG_XFRM
	xfrm_init();
	xfrm4_init();
#endif

    /*注册rtnetlink 消息， 这里是获取路由， 在devinet_init()中还有其他三种消息*/
	rtnl_register(PF_INET, RTM_GETROUTE, inet_rtm_getroute, NULL);

	return rc;
}

EXPORT_SYMBOL(__ip_select_ident);
EXPORT_SYMBOL(ip_route_input);
EXPORT_SYMBOL(ip_route_output_key);
