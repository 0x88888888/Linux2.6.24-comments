/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The IP fragmentation functionality.
 *
 * Version:	$Id: ip_fragment.c,v 1.59 2002/01/12 07:54:56 davem Exp $
 *
 * Authors:	Fred N. van Kempen <waltje@uWalt.NL.Mugnet.ORG>
 *		Alan Cox <Alan.Cox@linux.org>
 *
 * Fixes:
 *		Alan Cox	:	Split from ip.c , see ip_input.c for history.
 *		David S. Miller :	Begin massive cleanup...
 *		Andi Kleen	:	Add sysctls.
 *		xxxx		:	Overlapfrag bug.
 *		Ultima          :       ip_expire() kernel panic.
 *		Bill Hawes	:	Frag accounting and evictor fixes.
 *		John McDonald	:	0 length frag bug.
 *		Alexey Kuznetsov:	SMP races, threading, cleanup.
 *		Patrick McHardy :	LRU queue of frag heads for evictor.
 */

#include <linux/compiler.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/jiffies.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/inetpeer.h>
#include <net/inet_frag.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <linux/netfilter_ipv4.h>

/* NOTE. Logic of IP defragmentation is parallel to corresponding IPv6
 * code now. If you change something here, _PLEASE_ update ipv6/reassembly.c
 * as well. Or notify me, at least. --ANK
 */

int sysctl_ipfrag_max_dist __read_mostly = 64;

struct ipfrag_skb_cb
{
	struct inet_skb_parm	h;
	int			offset;
};

#define FRAG_CB(skb)	((struct ipfrag_skb_cb*)((skb)->cb))

/* Describe an entry in the "incomplete datagrams" queue.
 * 每一个即将被重新组合的ip数据报都用一个ipq对象来表示
 * 
 * ipq对象放到inet_frags中
 */
struct ipq {
	struct inet_frag_queue q;

	u32		user;
	__be32		saddr;
	__be32		daddr;
	__be16		id;
	u8		protocol;
	/*
	 * 接收最后一个分片的网络设备索引号。当分片组装失败时,用该设备发送分片组装超时ICMP出错报文，
	 * 即类型为ICMP_TIME_EXCEEDED，代码为ICMP_EXC_FRAGTIME。
	 */
	int             iif;
	/*
	 * 已接收分片的计数器。可通过对端信息块peer中的分片计数器和该分片计数器来防止DoS攻击
	 */
	unsigned int    rid;
	/*
	 * 记录发送方的一些信息。
	 */
	struct inet_peer *peer;
};

struct inet_frags_ctl ip4_frags_ctl __read_mostly = {
	/*
	 * Fragment cache limits. We will commit 256K at one time. Should we
	 * cross that limit we will prune down to 192K. This should cope with
	 * even the most extreme cases without allowing an attacker to
	 * measurably harm machine performance.
	 */
	.high_thresh	 = 256 * 1024,
	.low_thresh	 = 192 * 1024,

	/*
	 * Important NOTE! Fragment queue must be destroyed before MSL expires.
	 * RFC791 is wrong proposing to prolongate timer each fragment arrival
	 * by TTL.
	 */
	.timeout	 = IP_FRAG_TIME,
	.secret_interval = 10 * 60 * HZ,
};

static struct inet_frags ip4_frags;

int ip_frag_nqueues(void)
{
	return ip4_frags.nqueues;
}

int ip_frag_mem(void)
{
	return atomic_read(&ip4_frags.mem);
}

static int ip_frag_reasm(struct ipq *qp, struct sk_buff *prev,
			 struct net_device *dev);

struct ip4_create_arg {
	struct iphdr *iph;
	u32 user;
};

static unsigned int ipqhashfn(__be16 id, __be32 saddr, __be32 daddr, u8 prot)
{
	return jhash_3words((__force u32)id << 16 | prot,
			    (__force u32)saddr, (__force u32)daddr,
			    ip4_frags.rnd) & (INETFRAGS_HASHSZ - 1);
}

static unsigned int ip4_hashfn(struct inet_frag_queue *q)
{
	struct ipq *ipq;

	ipq = container_of(q, struct ipq, q);
	return ipqhashfn(ipq->id, ipq->saddr, ipq->daddr, ipq->protocol);
}

/*
 * ip_defrag()
 *  ip_find()
 *   inet_frag_find()
 *    ip4_frag_match()
 */
static int ip4_frag_match(struct inet_frag_queue *q, void *a)
{
	struct ipq *qp;
	struct ip4_create_arg *arg = a;

	qp = container_of(q, struct ipq, q);

	//都相等的fragment才是符合这个iph所在的 ip层fragment的
	return (qp->id == arg->iph->id &&
			qp->saddr == arg->iph->saddr &&
			qp->daddr == arg->iph->daddr &&
			qp->protocol == arg->iph->protocol &&
			qp->user == arg->user);
}

/* Memory Tracking Functions. */
static __inline__ void frag_kfree_skb(struct sk_buff *skb, int *work)
{
	if (work)
		*work -= skb->truesize;
	atomic_sub(skb->truesize, &ip4_frags.mem);
	kfree_skb(skb);
}

static void ip4_frag_init(struct inet_frag_queue *q, void *a)
{
	struct ipq *qp = container_of(q, struct ipq, q);
	struct ip4_create_arg *arg = a;

	qp->protocol = arg->iph->protocol;
	qp->id = arg->iph->id;
	qp->saddr = arg->iph->saddr;
	qp->daddr = arg->iph->daddr;
	qp->user = arg->user;
	qp->peer = sysctl_ipfrag_max_dist ?
		inet_getpeer(arg->iph->saddr, 1) : NULL;
}

static __inline__ void ip4_frag_free(struct inet_frag_queue *q)
{
	struct ipq *qp;

	qp = container_of(q, struct ipq, q);
	if (qp->peer)
		inet_putpeer(qp->peer);
}


/* Destruction primitives. */

static __inline__ void ipq_put(struct ipq *ipq)
{
	inet_frag_put(&ipq->q, &ip4_frags);
}

/* Kill ipq entry. It is not destroyed immediately,
 * because caller (and someone more) holds reference count.
 *
 * 将组装定时器超时ipq上删除
 * 
 */
static void ipq_kill(struct ipq *ipq)
{
	inet_frag_kill(&ipq->q, &ip4_frags);
}

/* Memory limiting on fragments.  Evictor trashes the oldest
 * fragment queue until we are back under the threshold.
 *
 * ip_rcv
 *  ip_rcv_finish
 *   dst_input
 *    ip_local_deliver
 *     ip_defrag()
 *      ip_evictor()
 * 
 * 删除一些fragment，控制内存使用量
 */
static void ip_evictor(void)
{
	int evicted;

	evicted = inet_frag_evictor(&ip4_frags);
	if (evicted)
		IP_ADD_STATS_BH(IPSTATS_MIB_REASMFAILS, evicted);
}

/*
 * Oops, a fragment queue timed out.  Kill it and send an ICMP reply.
 *
 * 组装超时定时器列程,当组装定时器被激活时，清除在规定时间内没有完成组装的ipq及其所有分片
 */
static void ip_expire(unsigned long arg)
{
	struct ipq *qp;

	qp = container_of((struct inet_frag_queue *) arg, struct ipq, q);

	spin_lock(&qp->q.lock);

	if (qp->q.last_in & COMPLETE)
		goto out;

	ipq_kill(qp);

	IP_INC_STATS_BH(IPSTATS_MIB_REASMTIMEOUT);
	IP_INC_STATS_BH(IPSTATS_MIB_REASMFAILS);

	if ((qp->q.last_in&FIRST_IN) && qp->q.fragments != NULL) {
		struct sk_buff *head = qp->q.fragments;
		/* Send an ICMP "Fragment Reassembly Timeout" message. */
		if ((head->dev = dev_get_by_index(&init_net, qp->iif)) != NULL) {
			icmp_send(head, ICMP_TIME_EXCEEDED, ICMP_EXC_FRAGTIME, 0);
			dev_put(head->dev);
		}
	}
out:
	spin_unlock(&qp->q.lock);
	ipq_put(qp);
}

/* Find the correct entry in the "incomplete datagrams" queue for
 * this IP datagram, and create new one, if nothing is found.
 * 
 *
 * ip_defrag()
 *  ip_find()
 *
 * 查找或者创建与iph对应的ipq对象
 */
static inline struct ipq *ip_find(struct iphdr *iph, u32 user)
{
	struct inet_frag_queue *q;
	struct ip4_create_arg arg;
	unsigned int hash;

	arg.iph = iph;
	arg.user = user;
    /* 
     * 对于IP分片来说，使用IP头部信息中的identifier，源地址，目的地址，以及协议来计算hash值。
     * 一般来说，这     四个值基本上可以保证了IP分片的队列信息的唯一性。
     * 不过由于NAT设备的使用，就有可能将不同的分片队列混在     一起。
     * 在计算hash值上，还使用ip4_frags.rnd这一随机值。
    */	
	hash = ipqhashfn(iph->id, iph->saddr, iph->daddr, iph->protocol);

	//调用ip2_frags->match() 去查找ipq
	q = inet_frag_find(&ip4_frags, &arg, hash);
	if (q == NULL)
		goto out_nomem;
	/* 内核中实际上维护的变量类型为struct ipq，需要从其成员变量q，获得原来的struct ipq类型的地址 */
	return container_of(q, struct ipq, q);

out_nomem:
	LIMIT_NETDEBUG(KERN_ERR "ip_frag_create: no memory left !\n");
	return NULL;
}

/* Is the fragment too far ahead to be part of ipq? 
 *
 * ip_defrag()
 *  ip_frag_queue()
 *   ip_frag_too_far()
 */
static inline int ip_frag_too_far(struct ipq *qp)
{
	struct inet_peer *peer = qp->peer;
	unsigned int max = sysctl_ipfrag_max_dist;
	unsigned int start, end;

	int rc;

	if (!peer || !max)
		return 0;

	start = qp->rid;
	end = atomic_inc_return(&peer->rid);
	qp->rid = end;

	rc = qp->q.fragments && (end - start) > max;

	if (rc) {
		IP_INC_STATS_BH(IPSTATS_MIB_REASMFAILS);
	}

	return rc;
}

/*
 * ip_defrag()
 *  ip_frag_queue()
 *   ip_frag_reinit()
 */
static int ip_frag_reinit(struct ipq *qp)
{
	struct sk_buff *fp;

	if (!mod_timer(&qp->q.timer, jiffies + ip4_frags_ctl.timeout)) {
		atomic_inc(&qp->q.refcnt);
		return -ETIMEDOUT;
	}

	fp = qp->q.fragments;
	do {
		struct sk_buff *xp = fp->next;
		frag_kfree_skb(fp, NULL);
		fp = xp;
	} while (fp);

	qp->q.last_in = 0;
	qp->q.len = 0;
	qp->q.meat = 0;
	qp->q.fragments = NULL;
	qp->iif = 0;

	return 0;
}

/* Add new segment to existing queue.
 * skb进入qp，或者重组
 * 
 *  ip_rcv
 *   ip_rcv_finish
 *    dst_input
 *     ip_local_deliver
 *      ip_defrag()
 *       ip_frag_queue()
 * 
 */
static int ip_frag_queue(struct ipq *qp, struct sk_buff *skb)
{
	struct sk_buff *prev, *next;
	struct net_device *dev;
	int flags, offset;
	int ihl, end;
	int err = -ENOENT;
	
    /* 分片队列已经完成或者即将被清除，都会置上INET_FRAG_COMPLETE */
	if (qp->q.last_in & COMPLETE)
		goto err;
	/*
	1. IPCB(skb)->flags只有在本机发送IPv4 fragments时被置位(在ip_fragment中置位)，
	   那么这里的检查应该是预防收到本机自己发出的IP分	   片。
	2. 关于ip_frag_too_far：该函数主要保证了来自同一个peer（相同的源地址）不会占用过多的IP分片队列。感觉，这个主要是为了防止攻击。不过如果中间设备有NAT的话，这个默认限制太小了。
	不过有NAT设备的情况下，IPv4的分片也会有其它的问题。以后也许会谈谈这个问题。
	3. 前面两个条件为真时，调用ip_frag_reinit，重新初始化该队列。出错，那么只好kill掉这个队列了。
	*/

	if (!(IPCB(skb)->flags & IPSKB_FRAG_COMPLETE) &&
	    unlikely(ip_frag_too_far(qp)) &&
	    unlikely(err = ip_frag_reinit(qp))) {
		ipq_kill(qp);
		goto err;
	}

    /* 得到分片的数据偏移量及分片标志 */
	offset = ntohs(ip_hdr(skb)->frag_off);
	flags = offset & ~IP_OFFSET;
	offset &= IP_OFFSET;
	offset <<= 3;		/* offset is in 8-byte chunks */
	ihl = ip_hdrlen(skb);

	/* Determine the position of this fragment. */
	/* 该fragment的结束位置 */
	end = offset + skb->len - ihl;
	err = -EINVAL;

	/* Is this the final fragment? */
	if ((flags & IP_MF) == 0) { /* 这是最后一个fragment了 */
		
		/* If we already have some bits beyond end
		 * or have different end, the segment is corrrupted.
		 */
        /*
        1. 末尾端要小于之前得到的总的长度，那么肯定出错了；
        2. 之前已经收到了一个最后分片，且这次判断的末端不等于之前获得的值，那么肯定出错了。
        */		 
		if (end < qp->q.len ||
		    ((qp->q.last_in & LAST_IN) && end != qp->q.len))
			goto err;
		/* 置INET_FRAG_LAST_IN标志，表示收到了最后一个分片 */
		qp->q.last_in |= LAST_IN;
		/* IP包总长度就等于end */
		qp->q.len = end;
	} else {
		if (end&7) {
            /* 说明数据长度不是8的倍数。按照协议规定，除最后一个分片外，其余的IP分片的长度必须为8                  的倍数*/
             /* 将数据长度缩短为8的倍数的长度 */			
			end &= ~7;
			if (skb->ip_summed != CHECKSUM_UNNECESSARY)
				skb->ip_summed = CHECKSUM_NONE;
		}
		
		if (end > qp->q.len) {
			/* 这次判断的末尾超过了之前的获得长度 */
			/* Some bits beyond end -> corruption. */
	        /* 
            如果之前已经获得了最后一个分片，那么总的IP长度一定为正确的值。
            结果与这次的判断不符，那么一定出错了。
            */		
			if (qp->q.last_in & LAST_IN)
				goto err;
			
			/* 更新IP总长度 */			
			qp->q.len = end;
		}
	}
	
	/* 表示空的IP数据，出错 */	
	if (end == offset)
		goto err;

	err = -ENOMEM;
	if (pskb_pull(skb, ihl) == NULL)
		goto err;

	err = pskb_trim_rcsum(skb, end - offset);
	if (err)
		goto err;

	/* Find out which fragments are in front and at the back of us
	 * in the chain of fragments so far.  We must know where to put
	 * this fragment, right?
	 *
	 * 
	 */
	prev = NULL;
	//找到skb代表的fragment该插入的位置
	for (next = qp->q.fragments; next != NULL; next = next->next) {
		if (FRAG_CB(next)->offset >= offset)
			break;	/* bingo! */
		prev = next;
	}

	/* We found where to put this one.  Check for overlap with
	 * preceding fragment, and, if needed, align things so that
	 * any overlaps are eliminated.
	 *
	 * 现在已经找到了正确的插入位置，但是可能与已有的IP分片重叠，下面需要处理重叠问题  
	 */
	if (prev) {
		int i = (FRAG_CB(prev)->offset + prev->len) - offset;

		if (i > 0) { //说明prev包含了一部分要插入的sk_buff的数据了
			offset += i; //sk_buff跳过重叠的部分
			err = -EINVAL;
		
			if (end <= offset)
				goto err;
			
			err = -ENOMEM;
			if (!pskb_pull(skb, i))
				goto err;
			if (skb->ip_summed != CHECKSUM_UNNECESSARY)
				skb->ip_summed = CHECKSUM_NONE;
		}
	}

	err = -ENOMEM;

    //列表中逐个去处理重叠
	while (next && FRAG_CB(next)->offset < end) {
		/* 与已有的后面的IP分片重叠，这里使用while循环，是因为可能与多个重叠 */
		int i = end - FRAG_CB(next)->offset; /* overlap is 'i' bytes */
        /* 如注释所说，i为重叠了的字节数 */

		if (i < next->len) {
            /* 与后面的IP分片头部重叠。那么就更新后面的IP分片的偏移即可。这时无需继续测试，可以跳出循             环 */			
			/* Eat head of the next overlapped fragment
			 * and leave the loop. The next ones cannot overlap.
			 */
			if (!pskb_pull(next, i))
				goto err;
			FRAG_CB(next)->offset += i;
			qp->q.meat -= i;
			if (next->ip_summed != CHECKSUM_UNNECESSARY)
				next->ip_summed = CHECKSUM_NONE;
			break;
		} else {
            /* 重叠部分覆盖已有的IP分片，那么可以将已有的IP分片释放， 然后继续测试下一个分片 */			
			struct sk_buff *free_it = next;

			/* Old fragment is completely overridden with
			 * new one drop it.
			 */
			next = next->next;

			if (prev)
				prev->next = next;
			else
				qp->q.fragments = next;

			qp->q.meat -= free_it->len;
			frag_kfree_skb(free_it, NULL);
		}
	}

	/* 已经处理完了重叠问题，offset为新的偏移量 */
	FRAG_CB(skb)->offset = offset;

	/* 下面的操作很简单，插入新的分片，更新分片队列的信息 */
	/* Insert this fragment in the chain of fragments. */
	skb->next = next;
	if (prev)
		prev->next = skb;
	else
		qp->q.fragments = skb;

	dev = skb->dev;
	if (dev) {
		qp->iif = dev->ifindex;
		skb->dev = NULL;
	}
	qp->q.stamp = skb->tstamp;
	qp->q.meat += skb->len; //记录下收到分片总数据量的值
	atomic_add(skb->truesize, &ip4_frags.mem);
	
	/* 偏移为0，说明是第一个分片 */	
	if (offset == 0)
		qp->q.last_in |= FIRST_IN;

    /* 
     * 如果已经收到了第一个分片和最后一个分片，
     * 且收到的IP分片的长度也等于了原始的IP长度。
     * 那么说明一切就绪，可以重组IP分片了。
    */
	if (qp->q.last_in == (FIRST_IN | LAST_IN) && qp->q.meat == qp->q.len)
		return ip_frag_reasm(qp, prev, dev); //重组

	/* IP分片还未全部收齐 */
	write_lock(&ip4_frags.lock);
	list_move_tail(&qp->q.lru_list, &ip4_frags.lru_list);
	write_unlock(&ip4_frags.lock);
	return -EINPROGRESS;

err:
	kfree_skb(skb);
	return err;
}


/*
 * Build a new IP datagram from all its fragments. 
 * 重组所有已经到期的分片
 *
 * ip_defrag()
 *  ip_frag_queue()
 *   ip_frag_reasm()
 */
static int ip_frag_reasm(struct ipq *qp, struct sk_buff *prev,
			 struct net_device *dev)
{
	struct iphdr *iph;
	
	struct sk_buff *fp, *head = qp->q.fragments;
	int len;
	int ihlen;
	int err;

	/* kill掉该IP队列 */
	ipq_kill(qp);

	/* Make the one we just received the head. */
    /* 当prev不为null时，head=prev->next，即当前收到的这个分片，
     * 也就是把刚收到的这个分片当作hea         d。当prev为null时，
     * qp->q.fragments就是刚收到的分片 
     */	
	if (prev) {
        /* 
        这里做的处理，就是将收到的该分片作为head。
        为什么一定要将刚收到的分片作为head呢？
        */		
		head = prev->next;
		fp = skb_clone(head, GFP_ATOMIC);
		if (!fp)
			goto out_nomem;

		fp->next = head->next;
		prev->next = fp;

		skb_morph(head, qp->q.fragments);
		head->next = qp->q.fragments->next;

		kfree_skb(qp->q.fragments);
		qp->q.fragments = head;
	}

	/* 
	ok，现在head肯定为刚刚收到的分片。
	大胆猜测一下用意，因为刚收到的IP分片里面的IP信息是最新的，所有选择它作为head，用于生成重组后的IP包。
	比如也许会有一些新的IP option等。
	*/

	BUG_TRAP(head != NULL);
	BUG_TRAP(FRAG_CB(head)->offset == 0);

	/* Allocate a new buffer for the datagram. */
	ihlen = ip_hdrlen(head);
	len = ihlen + qp->q.len;

	err = -E2BIG;
	if (len > 65535)
		goto out_oversize;

	/* Head of list must not be cloned. */
	if (skb_cloned(head) && pskb_expand_head(head, 0, 0, GFP_ATOMIC))
		goto out_nomem;

	/* If the first fragment is fragmented itself, we split
	 * it to two chunks: the first with data and paged part
	 * and the second, holding only fragments. */
	if (skb_shinfo(head)->frag_list) {
		struct sk_buff *clone;
		int i, plen = 0;

		if ((clone = alloc_skb(0, GFP_ATOMIC)) == NULL)
			goto out_nomem;
		clone->next = head->next;
		head->next = clone;
		skb_shinfo(clone)->frag_list = skb_shinfo(head)->frag_list;
		skb_shinfo(head)->frag_list = NULL;
		for (i=0; i<skb_shinfo(head)->nr_frags; i++)
			plen += skb_shinfo(head)->frags[i].size;
		clone->len = clone->data_len = head->data_len - plen;
		head->data_len -= clone->len;
		head->len -= clone->len;
		clone->csum = 0;
		clone->ip_summed = head->ip_summed;
		atomic_add(clone->truesize, &ip4_frags.mem);
	}

	/* 
	将后面的分片赋给head->frag_list。
	这里所做的IP分片重组，并不是真的生成一个完整的独立的IP分片，而是将后面的分片挂载到head分片的frag_li	   st上。
	*/

	skb_shinfo(head)->frag_list = head->next;
	skb_push(head, head->data - skb_network_header(head));
	atomic_sub(head->truesize, &ip4_frags.mem);

    /* 更新checksum和头分片的真实大小 */
	for (fp=head->next; fp; fp = fp->next) {
		head->data_len += fp->len;
		head->len += fp->len;
		if (head->ip_summed != fp->ip_summed)
			head->ip_summed = CHECKSUM_NONE;
		else if (head->ip_summed == CHECKSUM_COMPLETE)
			head->csum = csum_add(head->csum, fp->csum);
		head->truesize += fp->truesize;
		atomic_sub(fp->truesize, &ip4_frags.mem);
	}

	head->next = NULL;
	head->dev = dev;
	head->tstamp = qp->q.stamp;

	/* 更新新的IP header信息，并将分片从队列qp中卸载 */
	iph = ip_hdr(head);
	iph->frag_off = 0;
	iph->tot_len = htons(len);
	IP_INC_STATS_BH(IPSTATS_MIB_REASMOKS);
	qp->q.fragments = NULL;
	return 0;

out_nomem:
	LIMIT_NETDEBUG(KERN_ERR "IP: queue_glue: no memory for gluing "
			      "queue %p\n", qp);
	err = -ENOMEM;
	goto out_fail;
out_oversize:
	if (net_ratelimit())
		printk(KERN_INFO
			"Oversized IP packet from %d.%d.%d.%d.\n",
			NIPQUAD(qp->saddr));
out_fail:
	IP_INC_STATS_BH(IPSTATS_MIB_REASMFAILS);
	return err;
}

/* Process an incoming IP datagram fragment. 
 * 重组ip层数据
 * 如果分组未全部到达,就返回NULL
 *
 * ipv4_conntrack_defrag()
 *  nf_ct_ipv4_gather_frags()
 *   ip_defrag()
 *
 *  ip_rcv
 *   ip_rcv_finish
 *    dst_input
 *     ip_local_deliver
 *      ip_defrag()
 */
int ip_defrag(struct sk_buff *skb, u32 user)
{
	struct ipq *qp;

	IP_INC_STATS_BH(IPSTATS_MIB_REASMREQDS);

	/* Start by cleaning up the memory. 
	 *
     * IP分片占用的内存已经超过了设定的最高阀值，需要回收内存。
     * 这个是必不可少的。因为所以的未重组的IP分片都保存在内存中。	
	 */
	if (atomic_read(&ip4_frags.mem) > ip4_frags_ctl.high_thresh)
		ip_evictor();

	/* Lookup (or create) queue header
     * 在ip4_frags中查找符合分片id, 源地址, 目标地址，分组协议标识的ipq
	 */
	if ((qp = ip_find(ip_hdr(skb), user)) != NULL) {
		//开始重组
		int ret;

		spin_lock(&qp->q.lock);

		/* 判断是否所有的分片都到了，如果都到了，就重组完成了
         * skb会插入到qp中，或者完成重组
		*/
		ret = ip_frag_queue(qp, skb);

		spin_unlock(&qp->q.lock);
		ipq_put(qp);
		return ret;
	}

	IP_INC_STATS_BH(IPSTATS_MIB_REASMFAILS);
	kfree_skb(skb);
	return -ENOMEM;
}

/*
 * inet_init()
 *  ipfrag_init()
 */
void __init ipfrag_init(void)
{
	ip4_frags.ctl = &ip4_frags_ctl;
	ip4_frags.hashfn = ip4_hashfn;
	ip4_frags.constructor = ip4_frag_init;
	ip4_frags.destructor = ip4_frag_free;
	ip4_frags.skb_free = NULL;
	ip4_frags.qsize = sizeof(struct ipq);
	ip4_frags.match = ip4_frag_match;
	ip4_frags.frag_expire = ip_expire;
	inet_frags_init(&ip4_frags);
}

EXPORT_SYMBOL(ip_defrag);
