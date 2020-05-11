/* netfilter.c: look after the filters for various protocols.
 * Heavily influenced by the old firewall.c by David Bonn and Alan Cox.
 *
 * Thanks to Rob `CmdrTaco' Malda for not influencing this code in any
 * way.
 *
 * Rusty Russell (C)2000 -- This code is GPL.
 */
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <net/protocol.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/wait.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/proc_fs.h>
#include <linux/mutex.h>
#include <net/net_namespace.h>
#include <net/sock.h>

#include "nf_internals.h"

static DEFINE_MUTEX(afinfo_mutex);

struct nf_afinfo *nf_afinfo[NPROTO] __read_mostly;
EXPORT_SYMBOL(nf_afinfo);

int nf_register_afinfo(struct nf_afinfo *afinfo)
{
	int err;

	err = mutex_lock_interruptible(&afinfo_mutex);
	if (err < 0)
		return err;
	rcu_assign_pointer(nf_afinfo[afinfo->family], afinfo);
	mutex_unlock(&afinfo_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(nf_register_afinfo);

void nf_unregister_afinfo(struct nf_afinfo *afinfo)
{
	mutex_lock(&afinfo_mutex);
	rcu_assign_pointer(nf_afinfo[afinfo->family], NULL);
	mutex_unlock(&afinfo_mutex);
	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(nf_unregister_afinfo);

/* In this code, we can be waiting indefinitely for userspace to
 * service a packet if a hook returns NF_QUEUE.  We could keep a count
 * of skbuffs queued for userspace, and not deregister a hook unless
 * this is zero, but that sucks.  Now, we simply check when the
 * packets come back: if the hook is gone, the packet is discarded. */
struct list_head nf_hooks[NPROTO][NF_MAX_HOOKS] __read_mostly;
EXPORT_SYMBOL(nf_hooks);
static DEFINE_MUTEX(nf_hook_mutex);

/*
 * 注册netfilter 函数到nf_hooks[][]中去
 *
 * nf_register_hooks()
 *  nf_register_hook()
 */
int nf_register_hook(struct nf_hook_ops *reg)
{
	struct list_head *i;
	int err;

	err = mutex_lock_interruptible(&nf_hook_mutex);
	if (err < 0)
		return err;
	list_for_each(i, &nf_hooks[reg->pf][reg->hooknum]) {
		if (reg->priority < ((struct nf_hook_ops *)i)->priority)
			break;
	}
	list_add_rcu(&reg->list, i->prev);
	mutex_unlock(&nf_hook_mutex);
	return 0;
}
EXPORT_SYMBOL(nf_register_hook);

void nf_unregister_hook(struct nf_hook_ops *reg)
{
	mutex_lock(&nf_hook_mutex);
	list_del_rcu(&reg->list);
	mutex_unlock(&nf_hook_mutex);

	synchronize_net();
}
EXPORT_SYMBOL(nf_unregister_hook);

/*
 * arptable_filter_init()
 *  nf_register_hooks()
 * 
 * br_netfilter_init()
 *  nf_register_hooks()
 *
 * ip6table_filter_init()
 *  nf_register_hooks()
 *
 * ip6table_mangle_init()
 *  nf_register_hooks()
 *
 * ip6table_raw_init()
 *  nf_register_hooks()
 *
 * iptable_filter_init()
 *  nf_register_hooks()
 *
 * iptable_mangle_init()
 *  nf_register_hooks()
 *
 * iptable_raw_init()
 *  nf_register_hooks()
 *
 * nf_conntrack_l3proto_ipv4_init()
 *  nf_register_hooks()
 *
 * nf_conntrack_l3proto_ipv6_init()
 *  nf_register_hooks()
 *
 * nf_nat_standalone_init()
 *  nf_register_hooks()
 *
 */
int nf_register_hooks(struct nf_hook_ops *reg, unsigned int n)
{
	unsigned int i;
	int err = 0;

	for (i = 0; i < n; i++) {
		err = nf_register_hook(&reg[i]);
		if (err)
			goto err;
	}
	return err;

err:
	if (i > 0)
		nf_unregister_hooks(reg, i);
	return err;
}
EXPORT_SYMBOL(nf_register_hooks);

void nf_unregister_hooks(struct nf_hook_ops *reg, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++)
		nf_unregister_hook(&reg[i]);
}
EXPORT_SYMBOL(nf_unregister_hooks);

/* 迭代 nf_hook_ops->hook对象 
 *
 * nf_hook_thresh()
 *  nf_hook_slow()
 *   nf_iterate()
 */
unsigned int nf_iterate(struct list_head *head,
			struct sk_buff *skb,
			int hook,
			const struct net_device *indev,
			const struct net_device *outdev,
			struct list_head **i,
			int (*okfn)(struct sk_buff *),
			int hook_thresh)
{
	unsigned int verdict;

	/*
	 * The caller must not block between calls to this
	 * function because of risk of continuing from deleted element.
	 * 逐个调用hook函数
	 */
	list_for_each_continue_rcu(*i, head) {
	
		struct nf_hook_ops *elem = (struct nf_hook_ops *)*i;

		/*
		规则的优先级判断，目前从NF_HOOK到这里的优先级为INT_MIN，即最小。这种情况下，所以的规则都会被检			查。
		这个hook_thresh用于保证某些规则在某些挂载点不起作用。
		搜索NF_HOOK_THRESH关键字，可以发现对于协议NFPROTO_BRIDGE的挂载点NF_BR_PRE_ROUTING，其thr		  eash被设为1，这样保证仅部分规则起作用。
		*/
		if (hook_thresh > elem->priority)
			continue;

		/* Optimization: we don't need to hold module
		   reference here, since function can't sleep. --RR
         *  elem->hook只能返回NF_DROP(应该丢弃分组) , NF_ACCEPT, NF_STOLEN(表示分组已被修改)
         *                    NF_QUEUE(将分组置于一个队列上), NF_REPEAT, NF_STOP这些值
		 */
		verdict = elem->hook(hook, skb, indev, outdev, okfn);
		if (verdict != NF_ACCEPT) {
			/* 不等于ACCEPT，就可能直接返回判定结果 */
#ifdef CONFIG_NETFILTER_DEBUG
			if (unlikely((verdict & NF_VERDICT_MASK)
							> NF_MAX_VERDICT)) {
				NFDEBUG("Evil return from %p(%u).\n",
					elem->hook, hook);
				continue;
			}
#endif
			/* 还需要不能等于NF_REPEAT。也就是说既不能等于NF_ACCEPT和NF_REPEAT，即可直接返回判定结
			   果，无需后面的判定 */
			if (verdict != NF_REPEAT) /* 不能再调用其他netfilter函数了 */
				return verdict;
			/* 判定结果为NF_REPEAT，则重复这个规则的判定 */
			*i = (*i)->prev;
		}
	}

	/* 所有判定结果都为NF_ACCEPT，才可返回NF_ACCEPT */
	return NF_ACCEPT;
}


/* Returns 1 if okfn() needs to be executed by the caller,
 * -EPERM for NF_DROP, 0 otherwise. 
 *
 * ip_local_deliver()  NF_IP_LOCAL_IN
 * ip_rcv()  NF_IP_PRE_ROUTING
 * ip_forward()  NF_IP_FORWARD
 * 
 * ip_queue_xmit()  NF_IP_LOCAL_OUT
 * ip_output() NF_IP_POST_ROUTING
 *
 *  nf_hook_thresh()
 *   nf_hook_slow()
 */
int nf_hook_slow(int pf, unsigned int hook, struct sk_buff *skb,
		 struct net_device *indev,
		 struct net_device *outdev,
		 int (*okfn)(struct sk_buff *),
		 int hook_thresh)
{
	struct list_head *elem;
	unsigned int verdict;
	int ret = 0;

	/* We may already have this, but read-locks nest anyway */
	rcu_read_lock();

	/*
	根据协议pf和挂载点类型，取得第一个元素。
	nf_hooks为一个二维数组，其类型为一个双链表list_head。它最大行数为NFPROTO_NUMPROTO，即支持的协议		最大个数，分别为NFPROTO_UNSPEC，NFPROTO_IPV4，NFPROTO_ARP，NFPROTO_BRIDGE，NFPROTO_IPV6，N
	FPROTO_DECNET。而最大列数为NF_MAX_HOOKS，即为最大挂载点个数+1。
	
	看到这里，我来猜测一下为什么netfilter要区分协议：
	1. 通过区分协议，简化了数据包的parse过程；
	2. 指定协议，也方便用户配置。
	*/
	elem = &nf_hooks[pf][hook];
next_hook:
	/* 
	 * 会有nf_hooks[PF_INET][NF_IP_PRE_ROUTING] 
     */
	verdict = nf_iterate(&nf_hooks[pf][hook], skb, hook, indev,
			     outdev, &elem, okfn, hook_thresh);
	
	if (verdict == NF_ACCEPT || verdict == NF_STOP) {
	   /* 
        * 判定是接受或者停止
        * NF_STOP是2.6中新加入的行为，与NF_ACCEPT类似。区别就是一旦一个判定为NF_STOP,就立刻返回，不会         进行后面的判定。而NF_ACCEPT则还会继续后面的判定
        */	
		ret = 1;
		goto unlock;
	} else if (verdict == NF_DROP) {
		/* 该包需要drop */
		kfree_skb(skb);
		ret = -EPERM;
	} else if ((verdict & NF_VERDICT_MASK)  == NF_QUEUE) {
        /* 
        判定结果有enque，即将数据包传给用户空间的queue handler。
        这个的verdict被重用了。低16位被用于存储判定结果，而高16位用于存储enqueue的数量。
        */
		NFDEBUG("nf_hook: Verdict = QUEUE.\n");
		if (!nf_queue(skb, elem, pf, hook, indev, outdev, okfn,
			      verdict >> NF_VERDICT_BITS))
			goto next_hook; //只有在这个elem无效时，nf_queue才会返回0，继续下面的hook判定。
	}
unlock:
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(nf_hook_slow);


int skb_make_writable(struct sk_buff *skb, unsigned int writable_len)
{
	if (writable_len > skb->len)
		return 0;

	/* Not exclusive use of packet?  Must copy. */
	if (!skb_cloned(skb)) {
		if (writable_len <= skb_headlen(skb))
			return 1;
	} else if (skb_clone_writable(skb, writable_len))
		return 1;

	if (writable_len <= skb_headlen(skb))
		writable_len = 0;
	else
		writable_len -= skb_headlen(skb);

	return !!__pskb_pull_tail(skb, writable_len);
}
EXPORT_SYMBOL(skb_make_writable);

void nf_proto_csum_replace4(__sum16 *sum, struct sk_buff *skb,
			    __be32 from, __be32 to, int pseudohdr)
{
	__be32 diff[] = { ~from, to };
	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		*sum = csum_fold(csum_partial(diff, sizeof(diff),
				~csum_unfold(*sum)));
		if (skb->ip_summed == CHECKSUM_COMPLETE && pseudohdr)
			skb->csum = ~csum_partial(diff, sizeof(diff),
						~skb->csum);
	} else if (pseudohdr)
		*sum = ~csum_fold(csum_partial(diff, sizeof(diff),
				csum_unfold(*sum)));
}
EXPORT_SYMBOL(nf_proto_csum_replace4);

#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
/* This does not belong here, but locally generated errors need it if connection
   tracking in use: without this, connection may not be in hash table, and hence
   manufactured ICMP or RST packets will not be associated with it. */
void (*ip_ct_attach)(struct sk_buff *, struct sk_buff *);
EXPORT_SYMBOL(ip_ct_attach);

void nf_ct_attach(struct sk_buff *new, struct sk_buff *skb)
{
	void (*attach)(struct sk_buff *, struct sk_buff *);

	if (skb->nfct) {
		rcu_read_lock();
		attach = rcu_dereference(ip_ct_attach);
		if (attach)
			attach(new, skb);
		rcu_read_unlock();
	}
}
EXPORT_SYMBOL(nf_ct_attach);

void (*nf_ct_destroy)(struct nf_conntrack *);
EXPORT_SYMBOL(nf_ct_destroy);

void nf_conntrack_destroy(struct nf_conntrack *nfct)
{
	void (*destroy)(struct nf_conntrack *);

	rcu_read_lock();
	destroy = rcu_dereference(nf_ct_destroy);
	BUG_ON(destroy == NULL);
	destroy(nfct);
	rcu_read_unlock();
}
EXPORT_SYMBOL(nf_conntrack_destroy);
#endif /* CONFIG_NF_CONNTRACK */

#ifdef CONFIG_PROC_FS
struct proc_dir_entry *proc_net_netfilter;
EXPORT_SYMBOL(proc_net_netfilter);
#endif

/*
 * start_kernel()
 *  rest_init() 中调用kernel_thread()创建kernel_init线程
 *   do_basic_setup()
 *    do_initcalls() 
 *     sock_init()
 *      netfilter_init()
 */
void __init netfilter_init(void)
{
	int i, h;
	                /* 协议数量 */
	for (i = 0; i < NPROTO; i++) {
		/* 每种协议可以设置8个hook */
		for (h = 0; h < NF_MAX_HOOKS; h++)
			INIT_LIST_HEAD(&nf_hooks[i][h]);
	}

#ifdef CONFIG_PROC_FS
	proc_net_netfilter = proc_mkdir("netfilter", init_net.proc_net);
	if (!proc_net_netfilter)
		panic("cannot create netfilter proc entry");
#endif

	if (netfilter_queue_init() < 0)
		panic("cannot initialize nf_queue");
	
	if (netfilter_log_init() < 0)
		panic("cannot initialize nf_log");
	
}
