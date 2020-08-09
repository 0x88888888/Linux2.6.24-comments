/*
 * net/dst.h	Protocol independent destination cache definitions.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 */

#ifndef _NET_DST_H
#define _NET_DST_H

#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/rcupdate.h>
#include <linux/jiffies.h>
#include <net/neighbour.h>
#include <asm/processor.h>

/*
 * 0 - no debugging messages
 * 1 - rare events and bugs (default)
 * 2 - trace mode.
 */
#define RT_CACHE_DEBUG		0

#define DST_GC_MIN	(HZ/10)
#define DST_GC_INC	(HZ/2)
#define DST_GC_MAX	(120*HZ)

/* Each dst_entry has reference count and sits in some parent list(s).
 * When it is removed from parent list, it is "freed" (dst_free).
 * After this it enters dead state (dst->obsolete > 0) and if its refcnt
 * is zero, it can be destroyed immediately, otherwise it is added
 * to gc list and garbage collector periodically checks the refcnt.
 */

struct sk_buff;

/*
 * rtable中的成员
 */
struct dst_entry
{
	struct rcu_head		rcu_head;
	struct dst_entry	*child;    // 下一级表项指针
	struct net_device       *dev;  // 输出标志
	short			error;
	short			obsolete;
	int			flags;             // 标志字段
#define DST_HOST		1
#define DST_NOXFRM		2
#define DST_NOPOLICY		4
#define DST_NOHASH		8
	unsigned long		expires;   // 超时时间

	unsigned short		header_len;	/* more space at head required */
	unsigned short		nfheader_len;	/* more non-fragment space at head required */
	unsigned short		trailer_len;	/* space to reserve at tail */

	u32			metrics[RTAX_MAX];  // 路由参数
	struct dst_entry	*path;      // 路径

	unsigned long		rate_last;	 /* 为ICMP提供的速率控制, rate limiting for ICMP */
	unsigned long		rate_tokens; /* 令牌速率控制 */

	struct neighbour	*neighbour; // 对应的neighbour子系统指针
	struct hh_cache		*hh;        // nieghbour子系统的指针
	struct xfrm_state	*xfrm;      // XFRM规则状态

	int			(*input)(struct sk_buff*); // ip_forward,ip_local_deliver,ip_error,ip_mr_input, dst_discard
	int			(*output)(struct sk_buff*); // ip_output, ip_rt_bug,ip_mc_output(在ip_mc_output中设置), dst_discard

#ifdef CONFIG_NET_CLS_ROUTE
	__u32			tclassid;       // 分类号
#endif

	struct  dst_ops	        *ops;   // 下层协议的管理接口
		
	unsigned long		lastuse;
	atomic_t		__refcnt;	/* client references	*/
	int			__use;
	union {
		struct dst_entry *next;
		struct rtable    *rt_next;
		struct rt6_info   *rt6_next;
		struct dn_route  *dn_next;
	};
	char			info[0];
};


/*
 * 向三层协议同志特定的事件，比如链路失效，每个三层协议都有这么一组函数
 */
struct dst_ops
{
	unsigned short		family;
	__be16			protocol;
	unsigned		gc_thresh;

	int			(*gc)(void);
	struct dst_entry *	(*check)(struct dst_entry *, __u32 cookie);
	void			(*destroy)(struct dst_entry *);
	void			(*ifdown)(struct dst_entry *,
					  struct net_device *dev, int how);
	struct dst_entry *	(*negative_advice)(struct dst_entry *);
	void			(*link_failure)(struct sk_buff *);
	void			(*update_pmtu)(struct dst_entry *dst, u32 mtu);
	int			entry_size;

	atomic_t		entries;
	//分配rtable
	struct kmem_cache 		*kmem_cachep;
};

#ifdef __KERNEL__

static inline u32
dst_metric(const struct dst_entry *dst, int metric)
{
	return dst->metrics[metric-1];
}

static inline u32 dst_mtu(const struct dst_entry *dst)
{
	u32 mtu = dst_metric(dst, RTAX_MTU);
	/*
	 * Alexey put it here, so ask him about it :)
	 */
	barrier();
	return mtu;
}

static inline u32
dst_allfrag(const struct dst_entry *dst)
{
	int ret = dst_metric(dst, RTAX_FEATURES) & RTAX_FEATURE_ALLFRAG;
	/* Yes, _exactly_. This is paranoia. */
	barrier();
	return ret;
}

static inline int
dst_metric_locked(struct dst_entry *dst, int metric)
{
	return dst_metric(dst, RTAX_LOCK) & (1<<metric);
}

static inline void dst_hold(struct dst_entry * dst)
{
	atomic_inc(&dst->__refcnt);
}

static inline void dst_use(struct dst_entry *dst, unsigned long time)
{
	dst_hold(dst);
	dst->__use++;
	dst->lastuse = time;
}

static inline
struct dst_entry * dst_clone(struct dst_entry * dst)
{
	if (dst)
		atomic_inc(&dst->__refcnt);
	return dst;
}

static inline
void dst_release(struct dst_entry * dst)
{
	if (dst) {
		WARN_ON(atomic_read(&dst->__refcnt) < 1);
		smp_mb__before_atomic_dec();
		atomic_dec(&dst->__refcnt);
	}
}

/* Children define the path of the packet through the
 * Linux networking.  Thus, destinations are stackable.
 */

static inline struct dst_entry *dst_pop(struct dst_entry *dst)
{
	struct dst_entry *child = dst_clone(dst->child);

	dst_release(dst);
	return child;
}

extern void * dst_alloc(struct dst_ops * ops);
extern void __dst_free(struct dst_entry * dst);
extern struct dst_entry *dst_destroy(struct dst_entry * dst);

static inline void dst_free(struct dst_entry * dst)
{
	if (dst->obsolete > 1)
		return;
	if (!atomic_read(&dst->__refcnt)) {
		dst = dst_destroy(dst);
		if (!dst)
			return;
	}
	__dst_free(dst);
}

static inline void dst_rcu_free(struct rcu_head *head)
{
	struct dst_entry *dst = container_of(head, struct dst_entry, rcu_head);
	dst_free(dst);
}

//更新dst对应的邻居dst->neighbour->confirmed时间
static inline void dst_confirm(struct dst_entry *dst)
{
	if (dst)
		neigh_confirm(dst->neighbour);
}

static inline void dst_negative_advice(struct dst_entry **dst_p)
{
	struct dst_entry * dst = *dst_p;
	if (dst && dst->ops->negative_advice)
		*dst_p = dst->ops->negative_advice(dst);
}

static inline void dst_link_failure(struct sk_buff *skb)
{
	struct dst_entry * dst = skb->dst;
	if (dst && dst->ops && dst->ops->link_failure)
		dst->ops->link_failure(skb);
}

/*
 * 设置dst_entry过期时间
 */
static inline void dst_set_expires(struct dst_entry *dst, int timeout)
{
	unsigned long expires = jiffies + timeout;

	if (expires == 0)
		expires = 1;

	if (dst->expires == 0 || time_before(expires, dst->expires))
		dst->expires = expires;
}

/* Output packet to network from transport.  
 *  ip_rcv
 *	  ip_rcv_finish
 *	    dst_input
 *		 ip_forward
 *         ip_forward_finish
 *           dst_output
 *
 * tcp_transmit_skb()
 *  ip_queue_xmit()
 *   dst_output()
 *
 *  udp_sendmsg()
 *   udp_push_pending_frames()
 *    ip_push_pending_frames()
 *     dst_output()
 *
 * sys_send()
 *  sys_sendto()
 *   sock_sendmsg()
 *    __sock_sendmsg() ; socket->ops->sendmsg
 *     inet_sendmsg()
 *      raw_sendmsg()
 *       raw_send_hdrinc()
 *        dst_output()
 * igmp和raw ip都直接使用这个函数
 */
static inline int dst_output(struct sk_buff *skb)
{
	return skb->dst->output(skb); /* 这里是函数指针是ip_output(单播)或者ip_mc_output(多播) */
}

/* Input packet from network to transport.  
 *
 * ip_rcv
 *  ip_rcv_finish
 *   dst_input
 */
static inline int dst_input(struct sk_buff *skb)
{
	int err;

	for (;;) {
		/* 这个skb->dst->input可以是ip_local_deliver (送到上层),ip_forward(路由转发) */
		err = skb->dst->input(skb);

		if (likely(err == 0))
			return err;
		/* Oh, Jamal... Seems, I will not forgive you this mess. :-) */
		if (unlikely(err != NET_XMIT_BYPASS))
			return err;
	}
}

static inline struct dst_entry *dst_check(struct dst_entry *dst, u32 cookie)
{
	if (dst->obsolete)
		dst = dst->ops->check(dst, cookie);
	return dst;
}

extern void		dst_init(void);

struct flowi;
#ifndef CONFIG_XFRM
static inline int xfrm_lookup(struct dst_entry **dst_p, struct flowi *fl,
		       struct sock *sk, int flags)
{
	return 0;
} 
static inline int __xfrm_lookup(struct dst_entry **dst_p, struct flowi *fl,
				struct sock *sk, int flags)
{
	return 0;
}
#else
extern int xfrm_lookup(struct dst_entry **dst_p, struct flowi *fl,
		       struct sock *sk, int flags);
extern int __xfrm_lookup(struct dst_entry **dst_p, struct flowi *fl,
			 struct sock *sk, int flags);
#endif
#endif

#endif /* _NET_DST_H */
