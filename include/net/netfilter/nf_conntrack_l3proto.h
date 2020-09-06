/*
 * Copyright (C)2003,2004 USAGI/WIDE Project
 *
 * Header for use in defining a given L3 protocol for connection tracking.
 *
 * Author:
 *	Yasuyuki Kozakai @USAGI	<yasuyuki.kozakai@toshiba.co.jp>
 *
 * Derived from include/netfilter_ipv4/ip_conntrack_protocol.h
 */

#ifndef _NF_CONNTRACK_L3PROTO_H
#define _NF_CONNTRACK_L3PROTO_H
#include <linux/netlink.h>
#include <net/netlink.h>
#include <linux/seq_file.h>
#include <net/netfilter/nf_conntrack.h>

/*
 * netfilter中conntrack功能使用这个结构,跟踪3层协议
 *
 * nf_conntrack_l3proto_ipv4 ，在nf_conntrack_l3proto_ipv4_init中注册
 */
struct nf_conntrack_l3proto
{
	/* L3 Protocol Family number. ex) PF_INET */
	u_int16_t l3proto;

	/* Protocol name */
	const char *name;

	/*
	 * Try to fill in the third arg: nhoff is offset of l3 proto
         * hdr.  Return true if possible.
     *
     * ipv4: ipv4_pkt_to_tuple
	 */
	int (*pkt_to_tuple)(const struct sk_buff *skb, unsigned int nhoff,
			    struct nf_conntrack_tuple *tuple);

	/*
	 * Invert the per-proto part of the tuple: ie. turn xmit into reply.
	 * Some packets can't be inverted: return 0 in that case.
	 *
	 * 对于一个给定的tuple结构，对其三层相关元组进行取反操作并赋值给
     * 新的tuple变量inverse
     *
     * ipv4: ipv4_invert_tuple
	 */
	int (*invert_tuple)(struct nf_conntrack_tuple *inverse,
			    const struct nf_conntrack_tuple *orig);

	/* Print out the per-protocol part of the tuple.
	 *
	 * ipv4: ipv4_print_tuple
	 */
	int (*print_tuple)(struct seq_file *s,
			   const struct nf_conntrack_tuple *);

	/* Print out the private part of the conntrack. */
    /*打印一个数据连接变量中三层相关的信息
     *
     * ipv4: ipv4_print_conntrack
	 */			   			   
	int (*print_conntrack)(struct seq_file *s, const struct nf_conn *);

	/* Returns verdict for packet, or -1 for invalid. */
	/*对数据包进行三层相关的处理，并修改数据连接相关的值*/	
	int (*packet)(struct nf_conn *conntrack,
		      const struct sk_buff *skb,
		      enum ip_conntrack_info ctinfo);

	/*
	 * Called when a new connection for this protocol found;
	 * returns TRUE if it's OK.  If so, packet() called next.
	 *
	 * 
	 * 当创建一个新的数据连接时，调用该函数进行初始化	 
	 */
	int (*new)(struct nf_conn *conntrack, const struct sk_buff *skb);

	/*
	 * Called before tracking. 
	 *	*dataoff: offset of protocol header (TCP, UDP,...) in skb
	 *	*protonum: protocol number
	 *
	 * ipv3: ipv4_get_l4proto
	 */
	int (*get_l4proto)(const struct sk_buff *skb, unsigned int nhoff,
			   unsigned int *dataoff, u_int8_t *protonum);

	int (*tuple_to_nlattr)(struct sk_buff *skb,
			       const struct nf_conntrack_tuple *t);

	int (*nlattr_to_tuple)(struct nlattr *tb[],
			       struct nf_conntrack_tuple *t);
	const struct nla_policy *nla_policy;

#ifdef CONFIG_SYSCTL
	struct ctl_table_header	*ctl_table_header;
	struct ctl_table	*ctl_table_path;
	struct ctl_table	*ctl_table;
#endif /* CONFIG_SYSCTL */

	/* Module (if any) which this is connected to. */
	struct module *me;
};

extern struct nf_conntrack_l3proto *nf_ct_l3protos[AF_MAX];

/* Protocol registration. */
extern int nf_conntrack_l3proto_register(struct nf_conntrack_l3proto *proto);
extern void nf_conntrack_l3proto_unregister(struct nf_conntrack_l3proto *proto);
extern struct nf_conntrack_l3proto *nf_ct_l3proto_find_get(u_int16_t l3proto);
extern void nf_ct_l3proto_put(struct nf_conntrack_l3proto *p);

/* Existing built-in protocols */
extern struct nf_conntrack_l3proto nf_conntrack_l3proto_generic;

static inline struct nf_conntrack_l3proto *
__nf_ct_l3proto_find(u_int16_t l3proto)
{
	if (unlikely(l3proto >= AF_MAX))
		return &nf_conntrack_l3proto_generic;
	return rcu_dereference(nf_ct_l3protos[l3proto]);
}

#endif /*_NF_CONNTRACK_L3PROTO_H*/
