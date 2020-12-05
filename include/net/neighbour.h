#ifndef _NET_NEIGHBOUR_H
#define _NET_NEIGHBOUR_H

#include <linux/neighbour.h>

/*
 *	Generic neighbour manipulation
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Alexey Kuznetsov	<kuznet@ms2.inr.ac.ru>
 *
 * 	Changes:
 *
 *	Harald Welte:		<laforge@gnumonks.org>
 *		- Add neighbour cache statistics like rtstat
 */

#include <asm/atomic.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>

#include <linux/err.h>
#include <linux/sysctl.h>
#include <net/rtnetlink.h>

#define NUD_IN_TIMER	(NUD_INCOMPLETE|NUD_REACHABLE|NUD_DELAY|NUD_PROBE)
#define NUD_VALID	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE|NUD_PROBE|NUD_STALE|NUD_DELAY)
#define NUD_CONNECTED	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE)

struct neighbour;

/*
 * 对每个邻居协议行为进行调整的一组参数
 * neighbou->parms指向neigh_parms对象
 */
struct neigh_parms
{
	struct net_device *dev;
	/*
	 * 链接到同一个协议族关联的neigh_parms实例的指针,
	 * 就是说每个neigh_table结构有他自己的neigh_parms结构列表，每个实例对应与一个配置的设备
	 */
	struct neigh_parms *next;
	
	int	(*neigh_setup)(struct neighbour *);
	void	(*neigh_cleanup)(struct neighbour *);

	//对应所属的neigh_table对象
	struct neigh_table *tbl;

	void	*sysctl_table;

	int dead; //为1，表明这个对象可以被删除了
	atomic_t refcnt;
	struct rcu_head rcu_head;

    //表示自从最近一次收到可达性证明后经过的时间
	int	base_reachable_time;
	/*
	 * 一台主机在retrans_time时间内没有收到solication请求的应答时,
	 * 就会重新发送一个solication请求
     */
	int	retrans_time;
	/*
	 * 如果一个neighbour结构在gc_staletime时间内还没有被使用过
	 * 并且没有程序引用它，那就会被删除
	 */
	int	gc_staletime;
	
	int	reachable_time;
	/*
	 * 表明一个neighbour在进入NUD_PROBE之前，在NUD_DELAY态等待了多长时间
	 */
	int	delay_probe_time;

    //arp_queue队列能容纳的元素的最大数目
	int	queue_len;

	//表示为了证实一个地址的可到达性,能发送的单播solications的数量
	int	ucast_probes;
	//是用户空间应用程序在解析一个地址时,可以发送solications的数量
	int	app_probes;
	
	int	mcast_probes;
	int	anycast_delay;
	int	proxy_delay;
	int	proxy_qlen;
	//neighbour两次更新状态时，需要经历的时间间隔
	int	locktime;
};

struct neigh_statistics
{
	unsigned long allocs;		/* number of allocated neighs */
	unsigned long destroys;		/* number of destroyed neighs */
	unsigned long hash_grows;	/* number of hash resizes */

	unsigned long res_failed;	/* nomber of failed resolutions */

	unsigned long lookups;		/* number of lookups */
	unsigned long hits;		/* number of hits (among lookups) */

	unsigned long rcv_probes_mcast;	/* number of received mcast ipv6 */
	unsigned long rcv_probes_ucast; /* number of received ucast ipv6 */

	unsigned long periodic_gc_runs;	/* number of periodic GC runs */
	unsigned long forced_gc_runs;	/* number of forced GC runs */
};

#define NEIGH_CACHE_STAT_INC(tbl, field)				\
	do {								\
		preempt_disable();					\
		(per_cpu_ptr((tbl)->stats, smp_processor_id())->field)++; \
		preempt_enable();					\
	} while (0)

/*
 * 存储计算机本地网络中的ip和硬件地址
 * neighbour对象由arp层协议创建neighbour
 *
 * 邻居子系统中的邻居项，存放在neigh_table中
 *
 * 当要向邻节点发送数据时，需要得到描述该节点的struct neighbour结构.
 * 其实neighbour结构是本地系统对邻节点的抽象描述，由ARP协议管理 
 */
struct neighbour
{
	struct neighbour	*next;     // 链接到下一个邻节点
	struct neigh_table	*tbl;      // 指向邻居表,通常是arp_tbl 或者nd_tbl
	
	struct neigh_parms	*parms;    // 控制neighbor协议行为的参数
	struct net_device		*dev;  // 网络设备
	unsigned long		used;      // 使用标志
	unsigned long		confirmed; // 确认标志 就是jiffies的值
	unsigned long		updated;   // 更新标志
	//NTF_PROXY, NTF_ROUTER
	__u8			flags;         // 标志字段
	
	//output的设置根据nud_state的情况来
	__u8			nud_state;     // 邻节点的状态
	/*
	 * L3层的地址类型,单播、广播、多播三种
	 *
	 * RTN_UNICAST, RTN_LOCAL, RTN_BROADCAST, RTN_ANYCAST, RTN_MULTICAST
	 */
	__u8			type; 
	__u8			dead; //是否是无效记录了
	atomic_t		probes; // 探测技术
	rwlock_t		lock;
	//硬件地址
	unsigned char		ha[ALIGN(MAX_ADDR_LEN, sizeof(unsigned long))];
	struct hh_cache		*hh; // 第二层协议的缓存记录
	atomic_t		refcnt;  // 

	/* 一般是指向 dev_queue_xmit 
	 * neigh->output会被设置为neigh->ops->connected_output或 neigh->ops->output，具体取决于邻居的状态
	 *
	 *　output的设置根据nud_state的情况来
	 *
	 * 这个值在arp_constructor(),dn_neigh_construct(),
	 * ndisc_constructor(), neigh_connect()
	 * neigh_flush_dev(),neigh_alloc(), neigh_suspect()
	 * shaper_neigh_setup() 中改变
	 *
	 * 在ip_finish_output2(),ip6_output_finish()中调用
	 */
	int			(*output)(struct sk_buff *skb);
	// 通常是等待发送出去的TCP、UDP数据
	struct sk_buff_head	arp_queue;
	struct timer_list	timer; //指向neigh_timer_handler的定时器指针
	/*
	 * 一组函数，用来表示和dev_queue_xmit之间的接口,L3和L2之间的接口，
	 * 不同的neighbor使用不同的neigh_ops
	 */
	struct neigh_ops	*ops;  
	u8			primary_key[0];
};

/*
 * 共有四个neigh_ops对象
 * arp_generic_ops, arp_hh_ops, arp_direct_ops, arp_broken_ops
 */
struct neigh_ops
{
    
	int			family;
	/*
	 * 发送请求报文函数
	 */
	void			(*solicit)(struct neighbour *, struct sk_buff*);
	void			(*error_report)(struct neighbour *, struct sk_buff*);
	/*
	 * 最通用的输出函数，可用于所有情况。
	 * 当ARP缓存处于NUD_REACHABLE, NUD_PERMANENT, NUD_NOARP状态时，
	 * 指向connected_output
	 */
	int			(*output)(struct sk_buff*);
	/*
	 * 指向可达邻接点发送数据的发送函数
	 */
	int			(*connected_output)(struct sk_buff*);
	/*
	 * 指向有第二层缓存记录的发送函数
	 */
	int			(*hh_output)(struct sk_buff*);
	/*
	 * 指向设备发送函数
	 */
	int			(*queue_xmit)(struct sk_buff*);
};

struct pneigh_entry
{
	struct pneigh_entry	*next;
	struct net_device		*dev;
	u8			flags;
	u8			key[0];
};

/*
 *	neighbour table manipulation
 *
 * 在Linux中，可通过二层协议直接访问的主机被称为邻节点。
 * 当要向邻节点发送数据时，需要得到描述该节点的struct neighbour结构.
 * 其实neighbour结构是本地系统对邻节点的抽象描述，由ARP协议管理
 * 
 * 全局变量neigh_tables
 *
 * neigh_table代表的是一种邻居协议的接口(比如 ARP)。
 *
 * 全局对象 arp_tbl, clip_tbl_hook, 
 * clip_tbl, dn_neigh_table, nd_tbl
 */

struct neigh_table
{
	struct neigh_table	*next;
	int			family; // 邻居协议所属地址族，ARP为AF_INET
	int			entry_size; // 邻居项结构的大小
	int			key_len;    // 健值长度
	//访问哈希表的函数
	__u32			(*hash)(const void *pkey, const struct net_device *);
	//指向创建新的节点记录的函数
	int			(*constructor)(struct neighbour *);
	//指向代理时新建邻节点记录的函数
	int			(*pconstructor)(struct pneigh_entry *);
	//指向代理的处理函数
	void			(*pdestructor)(struct pneigh_entry *);
	void			(*proxy_redo)(struct sk_buff *skb);
	char			*id;  //标志值
	struct neigh_parms	parms; // 邻节点的参数
	/* HACK. gc_* shoul follow parms without a gap! */
	int			gc_interval; // 垃圾回收间隔
	int			gc_thresh1;  // 垃圾回收阈值1
	int			gc_thresh2;  // 垃圾回收阈值2
	int			gc_thresh3;  // 垃圾回收阈值3
	
	unsigned long		last_flush; // 上次更新的时间

	//回调函数是neigh_periodic_timer
	struct timer_list 	gc_timer;   // 缓存的垃圾收集定时器
	struct timer_list 	proxy_timer; // 代理定时器
	struct sk_buff_head	proxy_queue; // 代理队列
	atomic_t		entries;  //  hash_buckets中neighbour对象的数量
	rwlock_t		lock;
	unsigned long		last_rand;    // 用于parms操作的时间记录
	struct kmem_cache		*kmem_cachep; // 内核缓存记录
	struct neigh_statistics	*stats;
	/* 同一个ip子网中的邻居项，会过期的 */
	struct neighbour	**hash_buckets;
	unsigned int		hash_mask;
	__u32			hash_rnd;
	unsigned int		hash_chain_gc;
	// 管理代理时的邻节点的哈希表,不会过期的
	struct pneigh_entry	**phash_buckets;
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry	*pde;
#endif
};

/* flags for neigh_update() */
#define NEIGH_UPDATE_F_OVERRIDE			0x00000001
#define NEIGH_UPDATE_F_WEAK_OVERRIDE		0x00000002
#define NEIGH_UPDATE_F_OVERRIDE_ISROUTER	0x00000004
#define NEIGH_UPDATE_F_ISROUTER			0x40000000
#define NEIGH_UPDATE_F_ADMIN			0x80000000

extern void			neigh_table_init(struct neigh_table *tbl);
extern void			neigh_table_init_no_netlink(struct neigh_table *tbl);
extern int			neigh_table_clear(struct neigh_table *tbl);
extern struct neighbour *	neigh_lookup(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern struct neighbour *	neigh_lookup_nodev(struct neigh_table *tbl,
						   const void *pkey);
extern struct neighbour *	neigh_create(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern void			neigh_destroy(struct neighbour *neigh);
extern int			__neigh_event_send(struct neighbour *neigh, struct sk_buff *skb);
extern int			neigh_update(struct neighbour *neigh, const u8 *lladdr, u8 new, 
					     u32 flags);
extern void			neigh_changeaddr(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_ifdown(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_resolve_output(struct sk_buff *skb);
extern int			neigh_connected_output(struct sk_buff *skb);
extern int			neigh_compat_output(struct sk_buff *skb);
extern struct neighbour 	*neigh_event_ns(struct neigh_table *tbl,
						u8 *lladdr, void *saddr,
						struct net_device *dev);

extern struct neigh_parms	*neigh_parms_alloc(struct net_device *dev, struct neigh_table *tbl);
extern void			neigh_parms_release(struct neigh_table *tbl, struct neigh_parms *parms);
extern void			neigh_parms_destroy(struct neigh_parms *parms);
extern unsigned long		neigh_rand_reach_time(unsigned long base);

extern void			pneigh_enqueue(struct neigh_table *tbl, struct neigh_parms *p,
					       struct sk_buff *skb);
extern struct pneigh_entry	*pneigh_lookup(struct neigh_table *tbl, const void *key, struct net_device *dev, int creat);
extern int			pneigh_delete(struct neigh_table *tbl, const void *key, struct net_device *dev);

extern void neigh_app_ns(struct neighbour *n);
extern void neigh_for_each(struct neigh_table *tbl, void (*cb)(struct neighbour *, void *), void *cookie);
extern void __neigh_for_each_release(struct neigh_table *tbl, int (*cb)(struct neighbour *));
extern void pneigh_for_each(struct neigh_table *tbl, void (*cb)(struct pneigh_entry *));

struct neigh_seq_state {
	struct neigh_table *tbl;
	void *(*neigh_sub_iter)(struct neigh_seq_state *state,
				struct neighbour *n, loff_t *pos);
	unsigned int bucket;
	unsigned int flags;
#define NEIGH_SEQ_NEIGH_ONLY	0x00000001
#define NEIGH_SEQ_IS_PNEIGH	0x00000002
#define NEIGH_SEQ_SKIP_NOARP	0x00000004
};
extern void *neigh_seq_start(struct seq_file *, loff_t *, struct neigh_table *, unsigned int);
extern void *neigh_seq_next(struct seq_file *, void *, loff_t *);
extern void neigh_seq_stop(struct seq_file *, void *);

extern int			neigh_sysctl_register(struct net_device *dev, 
						      struct neigh_parms *p,
						      int p_id, int pdev_id,
						      char *p_name,
						      proc_handler *proc_handler,
						      ctl_handler *strategy);
extern void			neigh_sysctl_unregister(struct neigh_parms *p);

static inline void __neigh_parms_put(struct neigh_parms *parms)
{
	atomic_dec(&parms->refcnt);
}

static inline void neigh_parms_put(struct neigh_parms *parms)
{
	if (atomic_dec_and_test(&parms->refcnt))
		neigh_parms_destroy(parms);
}

static inline struct neigh_parms *neigh_parms_clone(struct neigh_parms *parms)
{
	atomic_inc(&parms->refcnt);
	return parms;
}

/*
 *	Neighbour references
 */

static inline void neigh_release(struct neighbour *neigh)
{
	if (atomic_dec_and_test(&neigh->refcnt))
		neigh_destroy(neigh);
}

static inline struct neighbour * neigh_clone(struct neighbour *neigh)
{
	if (neigh)
		atomic_inc(&neigh->refcnt);
	return neigh;
}

#define neigh_hold(n)	atomic_inc(&(n)->refcnt)

static inline void neigh_confirm(struct neighbour *neigh)
{
	if (neigh)
		neigh->confirmed = jiffies;
}

static inline int neigh_is_connected(struct neighbour *neigh)
{
	return neigh->nud_state&NUD_CONNECTED;
}

static inline int neigh_is_valid(struct neighbour *neigh)
{
	return neigh->nud_state&NUD_VALID;
}

/*
 * neigh_resolve_output()
 *  neigh_event_send()
 */
static inline int neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	neigh->used = jiffies;
	if (!(neigh->nud_state&(NUD_CONNECTED|NUD_DELAY|NUD_PROBE)))
		return __neigh_event_send(neigh, skb);
	return 0;
}

/*
 * dst_output
 *  ip_output  ip路由转发路径
 *   ip_finish_output
 *    ip_finish_output2
 *     neigh_hh_output()
 *
 */
static inline int neigh_hh_output(struct hh_cache *hh, struct sk_buff *skb)
{
	unsigned seq;
	int hh_len;

    //循环里处理硬件头的长度对齐。这是必需的，因为某些硬件头（如IEEE 802.11 头）大于HH_DATA_MOD（16字节）
	do {
		int hh_alen;

		seq = read_seqbegin(&hh->hh_lock);
		hh_len = hh->hh_len;
		hh_alen = HH_DATA_ALIGN(hh_len);
		memcpy(skb->data - hh_alen, hh->hh_data, hh_alen);
	} while (read_seqretry(&hh->hh_lock, seq));

    // 将头数据复制到skb后，skb_push将更新skb内指向数据缓冲区的指针
	skb_push(skb, hh_len);
	return hh->hh_output(skb);  //dev_queue_xmit
}

/*
 * arp_find()
 *  __neigh_lookup()
 *
 * arp_process(tbl = arp_tbl)
 *  __neigh_lookup()
 *
 */
static inline struct neighbour *
__neigh_lookup(struct neigh_table *tbl, const void *pkey, struct net_device *dev, int creat)
{
    //查找neighbour对象
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n || !creat)
		return n;

    //创建 neighbour对象
	n = neigh_create(tbl, pkey, dev);
	return IS_ERR(n) ? NULL : n;
}

static inline struct neighbour *
__neigh_lookup_errno(struct neigh_table *tbl, const void *pkey,
  struct net_device *dev)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n)
		return n;

	return neigh_create(tbl, pkey, dev);
}

struct neighbour_cb {
	unsigned long sched_next;
	unsigned int flags;
};

#define LOCALLY_ENQUEUED 0x1

#define NEIGH_CB(skb)	((struct neighbour_cb *)(skb)->cb)

#endif
