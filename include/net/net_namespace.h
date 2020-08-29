/*
 * Operations on the network namespace
 */
#ifndef __NET_NET_NAMESPACE_H
#define __NET_NET_NAMESPACE_H

#include <asm/atomic.h>
#include <linux/workqueue.h>
#include <linux/list.h>

struct proc_dir_entry;
struct net_device;
/* 网络子系统命名空间
 *
 * 系统中所有的net对象都链接到net_namespace_list
 */
struct net {
	atomic_t		count;		/* To decided when the network
						 *  namespace should be freed.
						 */
	atomic_t		use_count;	/* To track references we
						 * destroy on demand
						 */
	//链接到net_namespace_list链表上					 
	struct list_head	list;		/* 所有网络命名空间都链接在一个链表上，copy_net_ns向链表添加一个元素。 list of network namespaces */
	struct work_struct	work;		/* work struct for freeing */

	struct proc_dir_entry 	*proc_net;  /* proc文件系统中的 /proc/net */
	struct proc_dir_entry 	*proc_net_stat; /* proc文件系统中的 /proc/net/stats */
	struct proc_dir_entry 	*proc_net_root; /* proc文件系统中的 /proc/net/root */

	struct net_device       *loopback_dev;          /* 每个命名空间都可以有一个不同的回环设备.  The loopback */

	struct list_head 	dev_base_head; /* 每个命名空间所有的网络设备(net_device对象)，用这个链表链起来,链接到net_device->dev_list */
	
	struct hlist_head 	*dev_name_head; /* 同上，但是用设备name作为哈希计算参数，链接到net_device->name_hlist */
	struct hlist_head	*dev_index_head;/* 同上，但是用设备index作为哈希计算参数,链接大net_device->index_hlist */
};

#ifdef CONFIG_NET
/* Init's network namespace */
extern struct net init_net;
#define INIT_NET_NS(net_ns) .net_ns = &init_net,
#else
#define INIT_NET_NS(net_ns)
#endif

//链接到net->list上
extern struct list_head net_namespace_list;

#ifdef CONFIG_NET
extern struct net *copy_net_ns(unsigned long flags, struct net *net_ns);
#else
static inline struct net *copy_net_ns(unsigned long flags, struct net *net_ns)
{
	/* There is nothing to copy so this is a noop */
	return net_ns;
}
#endif

#ifdef CONFIG_NET_NS
extern void __put_net(struct net *net);

static inline struct net *get_net(struct net *net)
{
	atomic_inc(&net->count);
	return net;
}

static inline struct net *maybe_get_net(struct net *net)
{
	/* Used when we know struct net exists but we
	 * aren't guaranteed a previous reference count
	 * exists.  If the reference count is zero this
	 * function fails and returns NULL.
	 */
	if (!atomic_inc_not_zero(&net->count))
		net = NULL;
	return net;
}

static inline void put_net(struct net *net)
{
	if (atomic_dec_and_test(&net->count))
		__put_net(net);
}

static inline struct net *hold_net(struct net *net)
{
	atomic_inc(&net->use_count);
	return net;
}

static inline void release_net(struct net *net)
{
	atomic_dec(&net->use_count);
}
#else
static inline struct net *get_net(struct net *net)
{
	return net;
}

static inline void put_net(struct net *net)
{
}

static inline struct net *hold_net(struct net *net)
{
	return net;
}

static inline void release_net(struct net *net)
{
}

static inline struct net *maybe_get_net(struct net *net)
{
	return net;
}
#endif

#define for_each_net(VAR)				\
	list_for_each_entry(VAR, &net_namespace_list, list)

#ifdef CONFIG_NET_NS
#define __net_init
#define __net_exit
#define __net_initdata
#else
#define __net_init	__init
#define __net_exit	__exit_refok
#define __net_initdata	__initdata
#endif

/* 每当创建和删除一个网络命名空间(net)时，需要初始化或者清理一些信息 
 *
 * netlink_net_ops, dev_proc_ops, netdev_net_ops, default_device_ops
 * dev_mc_net_ops, loopback_net_ops, proc_net_ns_ops
 */
struct pernet_operations {
	struct list_head list;
	int (*init)(struct net *net);
	void (*exit)(struct net *net);
};

extern int register_pernet_subsys(struct pernet_operations *);
extern void unregister_pernet_subsys(struct pernet_operations *);
extern int register_pernet_device(struct pernet_operations *);
extern void unregister_pernet_device(struct pernet_operations *);

#endif /* __NET_NET_NAMESPACE_H */
