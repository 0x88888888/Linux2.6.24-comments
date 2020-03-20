/*
 *	Handle incoming frames
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_input.c,v 1.10 2001/12/24 04:50:20 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netfilter_bridge.h>
#include "br_private.h"

/* Bridge group multicast address 802.1d (pg 51). */
const u8 br_group_address[ETH_ALEN] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };

static void br_pass_frame_up(struct net_bridge *br, struct sk_buff *skb)
{
	struct net_device *indev;

	br->statistics.rx_packets++;
	br->statistics.rx_bytes += skb->len;

	indev = skb->dev;
	skb->dev = br->dev;

	NF_HOOK(PF_BRIDGE, NF_BR_LOCAL_IN, skb, indev, NULL,
		netif_receive_skb);
}

/* note: already called with rcu_read_lock (preempt_disabled) 
 *
 * 
 * irq_exit()
 *  do_softirq()
 *   __do_softirq()
 *    net_rx_action()
 *     process_backlog()
 *      netif_receive_skb()
 *       handle_bridge()
 *        br_handle_frame() 
 *         br_handle_frame_finish()
 *  在br_handle_frame中判断目标地址不是本机地址，网桥则会选择将其转发出去，这里调用了br_handle_frame_finish（）函数进行数据包转发
 */
int br_handle_frame_finish(struct sk_buff *skb)
{
	const unsigned char *dest = eth_hdr(skb)->h_dest;
	struct net_bridge_port *p = rcu_dereference(skb->dev->br_port);
	struct net_bridge *br;
	struct net_bridge_fdb_entry *dst;
	struct sk_buff *skb2;

	if (!p || p->state == BR_STATE_DISABLED)
		goto drop;

	/* insert into forwarding database after filtering to avoid spoofing */
	/*
	 * 网桥进行学习,学习源MAC地址,让它与port对应,网桥是维护一张CAM表
	 */
	br = p->br;
	br_fdb_update(br, p, eth_hdr(skb)->h_source);

	if (p->state == BR_STATE_LEARNING)
		goto drop;

	/* The packet skb2 goes to the local host (NULL to skip). */
	/*
	 * 当有数据包要发给本机时,拷贝一份skb2发给本机
	 */
	skb2 = NULL;

	if (br->dev->flags & IFF_PROMISC)
		skb2 = skb;

	dst = NULL;

    /*
     * 如果是多播地址,则多播转发出去.
     */
	if (is_multicast_ether_addr(dest)) {
		br->statistics.multicast++;
		skb2 = skb;
	} else if ((dst = __br_fdb_get(br, dest)) && dst->is_local) {
		/* 这里查找CAM表,看看目标MAC地址有没有在表中,再判断是否是本机MAC地址 */
		/* 如果是本机地址，下面就不会调用br_forward,br_flood_forward，
		 * 转而调用br_pass_frame_up把数据帧传的本机的L3
		 */
		skb2 = skb;
		/* Do not forward the packet since it's local. */
		skb = NULL;
	}

    /* 复制一个副本出来 */
	if (skb2 == skb)
		skb2 = skb_clone(skb, GFP_ATOMIC);

	if (skb2) // 把数据帧传的本机的L3
		br_pass_frame_up(br, skb2);

    /* 如果不是目标MAC不是本机的MAC地址,则要将数据包转发出去 */
	if (skb) {
		if (dst) /* 如果在CAM表中查找到了目标MAC地址,则将数据包发送给对应的以太网端口 */
			br_forward(dst->dst, skb);
		else/* 否则对数据包进行洪泛 */
			br_flood_forward(br, skb);
	}

out:
	return 0;
drop:
	kfree_skb(skb);
	goto out;
}

/* note: already called with rcu_read_lock (preempt_disabled) 
 * 学习更新校正CAM表
 *
 * irq_exit()
 *  do_softirq()
 *   __do_softirq()
 *    net_rx_action()
 *     process_backlog()
 *      netif_receive_skb()
 *       handle_bridge()
 *        br_handle_frame()
 *         br_handle_local_finish()
 */
static int br_handle_local_finish(struct sk_buff *skb)
{
	struct net_bridge_port *p = rcu_dereference(skb->dev->br_port);

	if (p) /* 网桥学习校正CAM表 */
		br_fdb_update(p->br, p, eth_hdr(skb)->h_source);
	
	return 0;	 /* process further */
}

/* Does address match the link local multicast address.
 * 01:80:c2:00:00:0X
 */
static inline int is_link_local(const unsigned char *dest)
{
	__be16 *a = (__be16 *)dest;
	static const __be16 *b = (const __be16 *)br_group_address;
	static const __be16 m = __constant_cpu_to_be16(0xfff0);

	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | ((a[2] ^ b[2]) & m)) == 0;
}

/*
 * Called via br_handle_frame_hook.
 * Return NULL if skb is handled
 * note: already called with rcu_read_lock (preempt_disabled)
 *
 *
 * irq_exit()
 *  do_softirq()
 *   __do_softirq()
 *    net_rx_action()
 *     process_backlog()
 *      netif_receive_skb()
 *       handle_bridge()
 *        br_handle_frame()
 * 
 */
struct sk_buff *br_handle_frame(struct net_bridge_port *p, struct sk_buff *skb)
{
    /*
     * 包的目的地址
     */
	const unsigned char *dest = eth_hdr(skb)->h_dest;
	int (*rhook)(struct sk_buff *skb);

	if (!is_valid_ether_addr(eth_hdr(skb)->h_source))
		goto drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return NULL;

    /*
     * 判断目标地址是否是本机的自身地址,若是则暂停数据,不被设备转发出去
     * 如果是本机地址，则会先调用br_handle_local_finish()函数让网桥学习更新校正CAM表，
     * 然后让函数返回skb，这样netif_receive_skb()函数就会继续往下执行，
     * 在遍历第二条链表的时候讲数据包上传给L3.
     * 
	 */
	if (unlikely(is_link_local(dest))) {
		/* Pause frames shouldn't be passed up by driver anyway */
		if (skb->protocol == htons(ETH_P_PAUSE))
			goto drop;

		/* Process STP BPDU's through normal netif_receive_skb() path */
		if (p->br->stp_enabled != BR_NO_STP) {
			if (NF_HOOK(PF_BRIDGE, NF_BR_LOCAL_IN, skb, skb->dev,
				    NULL, br_handle_local_finish))
				return NULL;
			else
				return skb;
		}
	}

	/*
	 * 如果目标地址不是本机的，网桥则会选择将其转发出去，
	 * 这里调用了br_handle_frame_finish（）
	 */
	switch (p->state) {
	case BR_STATE_FORWARDING:
		rhook = rcu_dereference(br_should_route_hook);
		if (rhook != NULL) {
			if (rhook(skb))
				return skb;
			dest = eth_hdr(skb)->h_dest;
		}
		/* fall through */
	case BR_STATE_LEARNING:

		if (!compare_ether_addr(p->br->dev->dev_addr, dest))
			skb->pkt_type = PACKET_HOST;

		NF_HOOK(PF_BRIDGE, NF_BR_PRE_ROUTING, skb, skb->dev, NULL,
			br_handle_frame_finish);
		break;
	default:
drop:
		kfree_skb(skb);
	}
	return NULL;
}
