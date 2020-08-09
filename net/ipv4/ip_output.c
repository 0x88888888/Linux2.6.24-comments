/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) output module.
 *
 * Version:	$Id: ip_output.c,v 1.100 2002/02/01 22:01:03 davem Exp $
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <Alan.Cox@linux.org>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Hirokazu Takahashi, <taka@valinux.co.jp>
 *
 *	See ip_input.c for original log
 *
 *	Fixes:
 *		Alan Cox	:	Missing nonblock feature in ip_build_xmit.
 *		Mike Kilburn	:	htons() missing in ip_build_xmit.
 *		Bradford Johnson:	Fix faulty handling of some frames when
 *					no route is found.
 *		Alexander Demenshin:	Missing sk/skb free in ip_queue_xmit
 *					(in case if packet not accepted by
 *					output firewall rules)
 *		Mike McLagan	:	Routing by source
 *		Alexey Kuznetsov:	use new route cache
 *		Andi Kleen:		Fix broken PMTU recovery and remove
 *					some redundant tests.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year coma.
 *		Andi Kleen	: 	Replace ip_reply with ip_send_reply.
 *		Andi Kleen	:	Split fast and slow ip_build_xmit path
 *					for decreased register pressure on x86
 *					and more readibility.
 *		Marc Boucher	:	When call_out_firewall returns FW_QUEUE,
 *					silently drop skb instead of failing with -EPERM.
 *		Detlev Wengorz	:	Copy protocol for fragments.
 *		Hirokazu Takahashi:	HW checksumming for outgoing UDP
 *					datagrams.
 *		Hirokazu Takahashi:	sendfile() on UDP works now.
 */

#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/highmem.h>

#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/inetpeer.h>
#include <linux/igmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/mroute.h>
#include <linux/netlink.h>
#include <linux/tcp.h>

int sysctl_ip_default_ttl __read_mostly = IPDEFTTL;

/* Generate a checksum for an outgoing IP datagram. */
__inline__ void ip_send_check(struct iphdr *iph)
{
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}

/* dev_loopback_xmit for use with netfilter. */
static int ip_dev_loopback_xmit(struct sk_buff *newskb)
{
	skb_reset_mac_header(newskb);
	__skb_pull(newskb, skb_network_offset(newskb));
	newskb->pkt_type = PACKET_LOOPBACK;
	newskb->ip_summed = CHECKSUM_UNNECESSARY;
	BUG_TRAP(newskb->dst);
	netif_rx(newskb);
	return 0;
}

static inline int ip_select_ttl(struct inet_sock *inet, struct dst_entry *dst)
{
	int ttl = inet->uc_ttl;

	if (ttl < 0)
		ttl = dst_metric(dst, RTAX_HOPLIMIT);
	return ttl;
}

/*
 *	Add an ip header to a skbuff and send it out.
 *
 *
 * 将TCP段打包成ip数据报的方法根据TCP段类型的不同而有多种接口，
 * 其中最常用的就是ip_queue_xmit,而ip_build_and_send_pkt和ip_send_reply只有在发送特定段时才会被调用. 
 *
 * 此函数用于在TCP建立连接过程中，打包输出SYN+ACK类型的TCP段。
 *
 * 构造报文的IP头，并发送给链路层。
 *
 * tcp_v4_send_synack()
 *  ip_build_and_send_pkt()
 */
int ip_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,
			  __be32 saddr, __be32 daddr, struct ip_options *opt)
{
	struct inet_sock *inet = inet_sk(sk);
	struct rtable *rt = (struct rtable *)skb->dst;
	struct iphdr *iph;

	/* Build the IP header. */
	// 设置ip首部
	skb_push(skb, sizeof(struct iphdr) + (opt ? opt->optlen : 0));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	iph->version  = 4;
	iph->ihl      = 5;
	iph->tos      = inet->tos;
	if (ip_dont_fragment(sk, &rt->u.dst))
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	iph->ttl      = ip_select_ttl(inet, &rt->u.dst);
	iph->daddr    = rt->rt_dst;
	iph->saddr    = rt->rt_src;
	iph->protocol = sk->sk_protocol;
	iph->tot_len  = htons(skb->len);

	//确定ip部分的id
	ip_select_ident(iph, &rt->u.dst, sk);

    // 构建IP选项数据
	if (opt && opt->optlen) {
		iph->ihl += opt->optlen>>2;
		ip_options_build(skb, opt, daddr, rt, 0);
	}
	ip_send_check(iph);

    //设置QoS类别
	skb->priority = sk->sk_priority;

	/* Send it out. */
	return NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, rt->u.dst.dev,
		       dst_output);
}

EXPORT_SYMBOL_GPL(ip_build_and_send_pkt);

/*
 *  ip_rcv
 *	 ip_rcv_finish
 *    dst_input
 *     ip_forward
 *      ip_forward_finish
 *       dst_output
 *        ip_output  ip路由转发路径
 *         ip_finish_output
 *          ip_finish_output2
 *
 *  dst_output
 *   ip_output  ip路由转发路径
 *    ip_finish_output(output == ip_finish_output2)
 *      ip_fragment() 
 *       ip_finish_output2()
 *
 * tcp_transmit_skb()
 *  ip_queue_xmit()
 *   dst_output()
 *    ip_output()
 *     ip_finish_output()
 *      ip_finish_output2()
 *
 *  udp_sendmsg()
 *   udp_push_pending_frames()
 *    ip_push_pending_frames()
 *     dst_output()
 *      ip_output()
 *       ip_finish_output()
 *        ip_finish_output2()
 *
 * Ip_finish_output2()函数会将skb送到neighboring subsystem，
 * 这个子系统会经过ARP协议获得L3地址（IP地址）对应的L2的地址（MAC地址）。
 * 这样整个L3单播地址路由skb数据跟踪就结束了
 */

static inline int ip_finish_output2(struct sk_buff *skb)
{
	struct dst_entry *dst = skb->dst;
	struct rtable *rt = (struct rtable *)dst;
	struct net_device *dev = dst->dev;
	unsigned int hh_len = LL_RESERVED_SPACE(dev);

	if (rt->rt_type == RTN_MULTICAST) // 如果与此数据包关联的路由是多播类型，则使用IP_UPD_PO_STATS宏来增加 OutMcastPkts和OutMcastOctets计数
		IP_INC_STATS(IPSTATS_MIB_OUTMCASTPKTS);
	else if (rt->rt_type == RTN_BROADCAST) // 如果广播路由，则会增加OutBcastPkts和 OutBcastOctets计数。
		IP_INC_STATS(IPSTATS_MIB_OUTBCASTPKTS);

	/* Be paranoid, rather than too clever. 
	 * 检查skb是否有足够的空间容纳链路层首部。
	 * 确保skb结构有足够的空间容纳需要添加的任何链路层头,
	 * 如果空间不够，则调用 skb_realloc_headroom分配额外的空间，并且新的skb的费用（charge）记在相关的 socket上
	 */
	if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
		struct sk_buff *skb2;
        /* 没有足够的空间容纳硬件首部,分配额外的空间 */
		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
		if (skb2 == NULL) {
			kfree_skb(skb);
			return -ENOMEM;
		}
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
		kfree_skb(skb); //释放老的skb
		skb = skb2;
	}


    //如果缓存了链路层的首部,则调用neigh_hh_output输出数据报。
	if (dst->hh) /* 这里就将skb送往neighboring subsystem,经过ARP协议映射获得L3对应的L2的地址 */
		return neigh_hh_output(dst->hh, skb);
	
	else if (dst->neighbour) //存在邻居项
	    /* neigh->output会被设置为neigh->ops_connected_output或 neigh->ops->output，具体取决于邻居的状态
	     * 看 arp_hh_ops
	     */
		return dst->neighbour->output(skb); /* 这里的函数指针是dev_queue_xmit,neigh_connected_output,neigh_resolve_output */

	if (net_ratelimit())
		printk(KERN_DEBUG "ip_finish_output2: No header cache and no neighbour!\n");
	kfree_skb(skb);
	return -EINVAL;
}

static inline int ip_skb_dst_mtu(struct sk_buff *skb)
{
	struct inet_sock *inet = skb->sk ? inet_sk(skb->sk) : NULL;

	return (inet && inet->pmtudisc == IP_PMTUDISC_PROBE) ?
	       skb->dst->dev->mtu : dst_mtu(skb->dst);
}

/*
 *  ip_rcv
 *	 ip_rcv_finish
 *    dst_input
 *     ip_forward
 *      ip_forward_finish
 *       dst_output
 *        ip_output  ip路由转发路径
 *         ip_finish_output
 *
 * ip_mc_output()
 *  ip_finish_output()
 *
 * tcp_transmit_skb()
 *  ip_queue_xmit()
 *   dst_output()
 *    ip_output()
 *     ip_finish_output()
 *
 *  udp_sendmsg()
 *   udp_push_pending_frames()
 *    ip_push_pending_frames()
 *     dst_output()
 *      ip_output()
 *       ip_finish_output()
 */

static int ip_finish_output(struct sk_buff *skb)
{

#if defined(CONFIG_NETFILTER) && defined(CONFIG_XFRM)
	/* Policy lookup after SNAT yielded a new policy */
    //netfilter和IPSec相关处理, 数据包转换（XFRM）
	if (skb->dst->xfrm != NULL) {
		IPCB(skb)->flags |= IPSKB_REROUTED;
		return dst_output(skb); //加上IPSKB_REROUTED，又回去
	}
#endif
     /* 超过mtu了，需要分片 */
	if (skb->len > ip_skb_dst_mtu(skb) && !skb_is_gso(skb))
		return ip_fragment(skb, ip_finish_output2);
	else
		return ip_finish_output2(skb); //直接发出去
}

/*
 * 对于从本地输出或是需进行转发的组播报文，如果输出路由查找成功，便可以输出。
 *
 * dst_output()[dst.h中]
 *  ip_mc_output()
 */
int ip_mc_output(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	struct rtable *rt = (struct rtable*)skb->dst;
	struct net_device *dev = rt->u.dst.dev;

	/*
	 *	If the indicated interface is up and running, send the packet.
	 */
	IP_INC_STATS(IPSTATS_MIB_OUTREQUESTS);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);//设置输出报文的输出网络设置及协议
   
	/*
	 *	Multicasts are looped back for other local users
	 */

	if (rt->rt_flags&RTCF_MULTICAST) {
		if ((!sk || inet_sk(sk)->mc_loop)
#ifdef CONFIG_IP_MROUTE
		/* Small optimization: do not loopback not local frames,
		   which returned after forwarding; they will be  dropped
		   by ip_mr_input in any case.
		   Note, that local frames are looped back to be delivered
		   to local recipients.

		   This check is duplicated in ip_mr_input at the moment.
		 */
		    && ((rt->rt_flags&RTCF_LOCAL) || !(IPCB(skb)->flags&IPSKB_FORWARDED))
#endif
		) {
			struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
			if (newskb)
				NF_HOOK(PF_INET, NF_IP_POST_ROUTING, newskb, NULL,
					newskb->dev,
					ip_dev_loopback_xmit);
		}

		/* Multicasts with ttl 0 must not go beyond the host */

		if (ip_hdr(skb)->ttl == 0) {
			kfree_skb(skb);
			return 0;
		}
	}

	if (rt->rt_flags&RTCF_BROADCAST) {
		struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
		if (newskb)
			NF_HOOK(PF_INET, NF_IP_POST_ROUTING, newskb, NULL,
				newskb->dev, ip_dev_loopback_xmit);
	}

	return NF_HOOK_COND(PF_INET, NF_IP_POST_ROUTING, skb, NULL, skb->dev,
			    ip_finish_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}

/*
 * ip_rcv
 *  ip_rcv_finish
 *   dst_input
 *    ip_forward
 *     ip_forward_finish
 *      dst_output
 *       ip_output  ip路由转发路径
 *
 * tcp_transmit_skb()
 *  ip_queue_xmit()
 *   dst_output()
 *    ip_output()
 *
 *  udp_sendmsg()
 *   udp_push_pending_frames()
 *    ip_push_pending_frames()
 *     dst_output()
 *      ip_output()
 */
int ip_output(struct sk_buff *skb)
{
    //出口的net_device对象
	struct net_device *dev = skb->dst->dev;

	IP_INC_STATS(IPSTATS_MIB_OUTREQUESTS);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

    /*
     * ip_finish_output或许要给ip数据报fragment或许直接发送出去
     * 要看数据包有没有大过pmtu了
     */
	return NF_HOOK_COND(PF_INET, NF_IP_POST_ROUTING, skb, NULL, dev,
			    ip_finish_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}

/*
 * 将TCP段打包成ip数据报的方法根据TCP段类型的不同而有多种接口，
 * 其中最常用的就是ip_queue_xmit,而ip_build_and_send_pkt和ip_send_reply只有在发送特定段时才会被调用.
 *
 * tcp和sctp这类已经把分段考虑进去的协议，会调用这个函数
 * 没有把分段考虑进去的协议会调用ip_push_pending_frames来发送数据
 *
 * ip层发送数据
 *
 * tcp_transmit_skb()
 *  ip_queue_xmit()
 *
 * sctp_v4_xmit()
 *  ip_queue_xmit()
 */
int ip_queue_xmit(struct sk_buff *skb /* TCP数据报 */, int ipfragok /*待输出的数据报是否已经完成分片*/ )
{
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct ip_options *opt = inet->opt;
	struct rtable *rt;
	struct iphdr *iph;

	/* Skip all of this if the packet is already routed,
	 * f.e. by something like SCTP.
	 *
	 * 路由信息已经缓存在skb->dst上了
	 */
	rt = (struct rtable *) skb->dst;
	if (rt != NULL) /* 已经缓存路由了，直接跳到packet_routed处处理，不需要再查找路由了 */
		goto packet_routed;

	/* Make sure we can route this packet. 
	 * 检查路由是否过期
	 */
	rt = (struct rtable *)__sk_dst_check(sk, 0);
	if (rt == NULL) { //路由过期了
		__be32 daddr; 

		/* Use correct destination address if we have options. */
		daddr = inet->daddr;
		if(opt && opt->srr) //有strict source route要求
			daddr = opt->faddr; //目的地址必须是strict source route列表中的下一跳的地址

		{ //重新查找路由缓存项，如果查找到对应的路由缓存项，则将缓存项输出到传输控制块中，否则丢弃该包
			struct flowi fl = { .oif = sk->sk_bound_dev_if,
					    .nl_u = { .ip4_u =
						      { .daddr = daddr,
							.saddr = inet->saddr,
							.tos = RT_CONN_FLAGS(sk) } },
					    .proto = sk->sk_protocol,
					    .uli_u = { .ports =
						       { .sport = inet->sport,
							 .dport = inet->dport } } };

			/* If this fails, retransmit mechanism of transport layer will
			 * keep trying until route appears or the connection times
			 * itself out.
			 */
			security_sk_classify_flow(sk, &fl);

			//查询路由信息，rt带出查询结果
			if (ip_route_output_flow(&rt, &fl, sk, 0))
				goto no_route; //查找失败
		}
		//将路由缓存项输出到传输层控制块中去	，就是挂到sk->sk_dst_cache上
		sk_setup_caps(sk, &rt->u.dst);
	}
	//路由信息赋值到skb上去
	skb->dst = dst_clone(&rt->u.dst);

packet_routed:
	/* 严格路由选项检查 */
	if (opt && opt->is_strictroute && rt->rt_dst != rt->rt_gateway)
		goto no_route;

	/* OK, we know where to send it, allocate and build IP header. */
	//开始设置ip首部的各项和选项
	skb_push(skb, sizeof(struct iphdr) + (opt ? opt->optlen : 0));
	skb_reset_network_header(skb); /* 设置skb->network_header位置 */
	/* 下面设置ip头部数据 */
	iph = ip_hdr(skb);
	*((__be16 *)iph) = htons((4 << 12) | (5 << 8) | (inet->tos & 0xff));
	iph->tot_len = htons(skb->len);
	
	if (ip_dont_fragment(sk, &rt->u.dst) && !ipfragok) //不准fragment
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	
	iph->ttl      = ip_select_ttl(inet, &rt->u.dst);
	iph->protocol = sk->sk_protocol;
	iph->saddr    = rt->rt_src;
	iph->daddr    = rt->rt_dst;
	/* Transport layer set skb->h.foo itself. */

    //构建ip首部的选线
	if (opt && opt->optlen) {
		iph->ihl += opt->optlen >> 2;
		ip_options_build(skb, opt, inet->daddr, rt, 0);
	}

    //确定ip包的ID
	ip_select_ident_more(iph, &rt->u.dst, sk,
			     (skb_shinfo(skb)->gso_segs ?: 1) - 1);

	/* Add an IP checksum. 
	 * 计算ip头部的checksum
	 */
	ip_send_check(iph);

    //设置数据报的QoS类别
	skb->priority = sk->sk_priority;

	return NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, rt->u.dst.dev,
		       dst_output); //在dst_output中调用的函数指针是ip_output

no_route:
	IP_INC_STATS(IPSTATS_MIB_OUTNOROUTES);
	kfree_skb(skb);
	return -EHOSTUNREACH;
}


static void ip_copy_metadata(struct sk_buff *to, struct sk_buff *from)
{
	to->pkt_type = from->pkt_type;
	to->priority = from->priority;
	to->protocol = from->protocol;
	dst_release(to->dst);
	to->dst = dst_clone(from->dst);
	to->dev = from->dev;
	to->mark = from->mark;

	/* Copy the flags to each fragment. */
	IPCB(to)->flags = IPCB(from)->flags;

#ifdef CONFIG_NET_SCHED
	to->tc_index = from->tc_index;
#endif
	nf_copy(to, from);
#if defined(CONFIG_NETFILTER_XT_TARGET_TRACE) || \
    defined(CONFIG_NETFILTER_XT_TARGET_TRACE_MODULE)
	to->nf_trace = from->nf_trace;
#endif
#if defined(CONFIG_IP_VS) || defined(CONFIG_IP_VS_MODULE)
	to->ipvs_property = from->ipvs_property;
#endif
	skb_copy_secmark(to, from);
}

/*
 *	This IP datagram is too large to be sent in one piece.  Break it up into
 *	smaller pieces (each of size equal to IP header plus
 *	a block of the data of the original IP data part) that will yet fit in a
 *	single device frame, and queue such a frame for sending.
 * 
 *  ip数据包太大时，需要分片发送
 *
 *  ip_rcv
 *	 ip_rcv_finish
 *    dst_input
 *     ip_forward
 *      ip_forward_finish
 *       dst_output
 *        ip_output  ip路由转发路径
 *         ip_finish_output(output == ip_finish_output2)
 *          ip_fragment()
 *
 * br_nf_post_routing()
 *  br_nf_dev_queue_xmit()
 *   ip_fragment(output == br_dev_queue_push_xmit)
 *
 * tcp_transmit_skb()
 *  ip_queue_xmit()
 *   dst_output()
 *    ip_output()
 *     ip_finish_output()
 *      ip_fragment()
 *
 *  udp_sendmsg()
 *   udp_push_pending_frames()
 *    ip_push_pending_frames()
 *     dst_output()
 *      ip_output()
 *       ip_finish_output()
 *        ip_fragment()
 *
 * ip分片，然后发送出去
 */

int ip_fragment(struct sk_buff *skb, int (*output)(struct sk_buff*))
{
	struct iphdr *iph;
	int raw = 0;
	int ptr;
	struct net_device *dev;
	struct sk_buff *skb2;
	unsigned int mtu, hlen, left, len, ll_rs, pad;
	int offset;
	__be16 not_last_frag;
	//路由信息
	struct rtable *rt = (struct rtable*)skb->dst;
	int err = 0;

    //出口的设备
	dev = rt->u.dst.dev;

	/*
	 * Point into the IP datagram header.
	 * 得到IP报文头的指针
	 */

	iph = ip_hdr(skb);

	/* 禁止分片,得发送icmp消息 */
	if (unlikely((iph->frag_off & htons(IP_DF)) && !skb->local_df)) {
		IP_INC_STATS(IPSTATS_MIB_FRAGFAILS);

	    //发送不可分片icmp信息回去
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			  htonl(ip_skb_dst_mtu(skb)));
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	/*
	 *	Setup starting values.
	 */
    /* 得到IP报文头部总长度 */
	hlen = iph->ihl * 4;
	/* 这里的mtu为真正的MTU-IP报文头，即允许的最大IP数据长度 */
	mtu = dst_mtu(&rt->u.dst) - hlen;	/* Size of data space */
	/* 为这个skb_buff置上分片完成的标志 */
	IPCB(skb)->flags |= IPSKB_FRAG_COMPLETE;

	/* When frag_list is given, use it. First, check its validity:
	 * some transformers could create wrong frag_list or break existing
	 * one, it is not prohibited. In this case fall back to copying.
	 *
	 * LATER: this step can be merged to real generation of fragments,
	 * we can switch to copy when see the first bad fragment.
	 *
	 * 快速分片
	 * 4层有可能会将数据包分片。这些分片存放在skb的frag_list中
	 */
	if (skb_shinfo(skb)->frag_list) {
		struct sk_buff *frag;
		//第一个分片的长度,这个长度包括所有frag和skb中本身数据的长度
		int first_len = skb_pagelen(skb);

        /* 对第一个分片做检测。要进行快速分片，还需要对传输层传递的所有SKB做一些判断 */
		if (first_len - hlen > mtu || //有分片长度大于MTU
		    ((first_len - hlen) & 7) || //没有按8字节对齐
		    (iph->frag_off & htons(IP_MF|IP_OFFSET)) || //IP首部中的MF或片偏移不为说明SKB不是一个完整的ip数据报。
		    skb_cloned(skb)) //此SKB已经被clone了
			goto slow_path;

        /*
         * 遍历所有的分片
         */
		for (frag = skb_shinfo(skb)->frag_list; frag; frag = frag->next) {
			/* Correct geometry. */
		    /* 检查每个分片，如果有一个分片不符合要求，就只能使用slow path */
			if (frag->len > mtu ||
			    ((frag->len & 7) && frag->next) ||
			    skb_headroom(frag) < hlen)
			    goto slow_path;

			/* Partially cloned skb? */
			if (skb_shared(frag))
				goto slow_path;

			BUG_ON(frag->sk);
			if (skb->sk) {
				sock_hold(skb->sk);
				frag->sk = skb->sk;
				frag->destructor = sock_wfree;
				skb->truesize -= frag->truesize;
			}
		}

		/* Everything is OK. Generate! 
		 * 到此，for循环中的每一个frag都检查过了，
		 * 可以用fast path发送了
         * 重新设置ip头信息
		 */

		err = 0;
		offset = 0;
		/* 拿到frag list */
		frag = skb_shinfo(skb)->frag_list;
		/* 重置原来的frag list，相当于从skb_buff上取走了frag list */
		skb_shinfo(skb)->frag_list = NULL;
		skb->data_len = first_len - skb_headlen(skb);
		skb->len = first_len;
		
		//设置第一个分片首部的总长度字段和MF标志位
		iph->tot_len = htons(first_len);
		iph->frag_off = htons(IP_MF);
		ip_send_check(iph);

        /* 从第二个分片开始循环设置每个分片的skb及IP首部 */
		for (;;) {
			/* Prepare header of the next frame,
			 * before previous one went down. */
			if (frag) {
				/* 表示checksm已经算好*/
				frag->ip_summed = CHECKSUM_NONE;
                /* 设置传输层*/
				skb_reset_transport_header(frag);
				__skb_push(frag, hlen);
				/* 设置网络层 */
				skb_reset_network_header(frag);
				memcpy(skb_network_header(frag), iph, hlen);
				iph = ip_hdr(frag);
				iph->tot_len = htons(frag->len);
				ip_copy_metadata(frag, skb);
				if (offset == 0)
					ip_options_fragment(frag);
				offset += skb->len - hlen;
				iph->frag_off = htons(offset>>3);
				if (frag->next != NULL)
					iph->frag_off |= htons(IP_MF);
				/* Ready, complete checksum */
				/* 计算分片的校验和 */
				ip_send_check(iph);
			}

			/*
			 * 发送当前的分片
			 * output == ip_finish_output2,br_dev_queue_push_xmit
			*/
			err = output(skb);

			if (!err)
				IP_INC_STATS(IPSTATS_MIB_FRAGCREATES);
			if (err || !frag) //出错，前面发出去的也就发出去了，目的机器不能reassemble了
				break;

			skb = frag;
			frag = skb->next; //下一个fragment
			skb->next = NULL;
		}

		if (err == 0) {
			IP_INC_STATS(IPSTATS_MIB_FRAGOKS);
			return 0;
		}

        //fast path发送完所有的fragments，然后要free掉fragments
		while (frag) {
			skb = frag->next;
			kfree_skb(frag);
			frag = skb;
		}
		IP_INC_STATS(IPSTATS_MIB_FRAGFAILS);
		return err;
	}

slow_path: //慢速分片

    //left为所有有效数据的长度
	left = skb->len - hlen;		/* Space per frame */
	//ptr指向有效数据的起始位置(也就是待发送的位置)
	ptr = raw + hlen;		/* Where to start from */

	/* for bridged IP traffic encapsulated inside f.e. a vlan header,
	 * we need to make room for the encapsulating header
	 *
	 * 如果是桥转发基于VLAN的IP数据报，则需要获得VLAN首部长度，在后面分片skb缓存区时留下的空间，同时还需要修改MTU
	 */
	pad = nf_bridge_pad(skb);
	ll_rs = LL_RESERVED_SPACE_EXTRA(rt->u.dst.dev, pad);
	mtu -= pad;

	/*
	 *	Fragment the datagram.
	 *  对数据进行分片
	 */
    /* 得到偏移 */ 
	offset = (ntohs(iph->frag_off) & IP_OFFSET) << 3;
	/* 通过IP_MF标志位，判断是否是最后一个分片 */
	not_last_frag = iph->frag_off & htons(IP_MF);

	/*
	 *	Keep copying data until we run out.
	 */

	while (left > 0) {
		/* 计算分片长度 */
		len = left;
		/* IF: it doesn't fit, use 'mtu' - the data space left */
		if (len > mtu)
			len = mtu;
		/* IF: we are not sending upto and including the packet end
		   then align the next start on an eight byte boundary */
		if (len < left)	{
			len &= ~7;
		}
		/*
		 *	Allocate buffer.
		 */
        /* 为分片申请该分片申请一个sk_buff */
		if ((skb2 = alloc_skb(len+hlen+ll_rs, GFP_ATOMIC)) == NULL) {
			NETDEBUG(KERN_INFO "IP: frag: no memory for new fragment!\n");
			err = -ENOMEM;
			goto fail;
		}

		/*
		 *	Set up data on packet
		 */
        /* 复制skb元数据到skb2，也就是根据skb来初始化skb2拉*/
		ip_copy_metadata(skb2, skb);

		//留出L2层需要的空间
		skb_reserve(skb2, ll_rs);
		skb_put(skb2, len + hlen);
		skb_reset_network_header(skb2);
		skb2->transport_header = skb2->network_header + hlen;

		/*
		 *	Charge the memory for the fragment to any owner
		 *	it might possess
		 */

		if (skb->sk) //设置skb2->sk == skb->sk,说明数据是属于同一个套接字的
			skb_set_owner_w(skb2, skb->sk);

		/*
		 *	Copy the packet header into the new buffer.
		 *  复制数据(从L3层的头部开始)到skb2->head + skb2->network_header处
		 */

		skb_copy_from_linear_data(skb, skb_network_header(skb2), hlen);

		/*
		 *	Copy a block of the IP datagram.
		 *  复制ip层的数据到skb2->head+skb2->transport_header处
		 */
		if (skb_copy_bits(skb, ptr, skb_transport_header(skb2), len))
			BUG();
		left -= len;

		/*
		 *	Fill in the new header fields.
		 */
		 /* 填充ip层头部 */
		iph = ip_hdr(skb2);
		iph->frag_off = htons((offset >> 3));

		/* ANK: dirty, but effective trick. Upgrade options only if
		 * the segment to be fragmented was THE FIRST (otherwise,
		 * options are already fixed) and make it ONCE
		 * on the initial skb, so that all the following fragments
		 * will inherit fixed options.
		 */
		 /* 如果是第一个分片， 填充ip option */
		if (offset == 0)
			ip_options_fragment(skb);

		/*
		 *	Added AC : If we are fragmenting a fragment that's not the
		 *		   last fragment then keep MF on each bit
		 */
		 /* 设置IP_MF标志位 */
		if (left > 0 || not_last_frag) //还有数据或者不是最后一个frag
			iph->frag_off |= htons(IP_MF);
		
		ptr += len;
		offset += len;

		/*
		 *	Put this fragment into the sending queue.
		 */
		iph->tot_len = htons(len + hlen);
        /* 计算校验和 */
		ip_send_check(iph);
        /* 发送该分片 
         * output == ip_finish_output2,br_dev_queue_push_xmit
		 */ 
		err = output(skb2);
		if (err)
			goto fail;

		IP_INC_STATS(IPSTATS_MIB_FRAGCREATES);
	}
	kfree_skb(skb);
	IP_INC_STATS(IPSTATS_MIB_FRAGOKS);
	return err;

fail:
	kfree_skb(skb);
	IP_INC_STATS(IPSTATS_MIB_FRAGFAILS);
	return err;
}

EXPORT_SYMBOL(ip_fragment);

/*
 * ip_append_data()
 *  ip_ufo_append_data()
 *   skb_append_datato_frags()
 *    ip_generic_getfrag() 
 * 
 * udp,raw ip时，会调用到这里
 */
int
ip_generic_getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb)
{
	struct iovec *iov = from;

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		if (memcpy_fromiovecend(to, iov, offset, len) < 0)
			return -EFAULT;
	} else {
		__wsum csum = 0;
		if (csum_partial_copy_fromiovecend(to, iov, offset, len, &csum) < 0)
			return -EFAULT;
		skb->csum = csum_block_add(skb->csum, csum, odd);
	}
	return 0;
}

static inline __wsum
csum_page(struct page *page, int offset, int copy)
{
	char *kaddr;
	__wsum csum;
	kaddr = kmap(page);
	csum = csum_partial(kaddr + offset, copy, 0);
	kunmap(page);
	return csum;
}

/*
 * sys_socketcall()
 *  sys_send()
 *   sys_sendto()
 *    sock_sendmsg()
 *     __sock_sendmsg() ; socket->ops->sendmsg
 *      inet_sendmsg()
 *       udp_sendmsg()
 *        ip_append_data()
 *         ip_ufo_append_data()
 *
 *
 * 默认处理是创建新的page，拷贝数据，
 * 并将其链入到skb中的分片(skb_shinfo(skb)->frags)中。
 *
 * UFO(UDP Fragment Offload)是硬件网卡提供的一种特性，
 * 由内核和驱动配合完成相关功能。其目的是由网卡硬件来完成本来需要软件进行的分段(分片)操作用于提升效率和性能。
 * 如大家所知，在网络上传输的数据包不能大于mtu，当用户发送大于mtu的数据报文时，
 * 通常会在传输层(或者在特殊情况下在IP层分片，比如ip转发或ipsec时)就会按mtu大小进行分段，
 * 防止发送出去的报文大于mtu，为提升该操作的性能，新的网卡硬件基本都实现了UFO功能，
 * 可以使分段(或分片)操作在网卡硬件完成，此时用户态就可以发送长度大于mtu的包，
 * 而且不必在协议栈中进行分段(或分片)。 
 *
 * ip_ufo_append_data函数大致原理为：
 *   当硬件支持且打开了UFO、udp包大小大于mtu会进入此流程，
 *   将用户态数据拷贝拷skb中的非线性区中(即skb_shared_info->frags[]，
 *   原本用于SG)。
 *
 *
 * 当硬件支持且打开了UFO、udp包大小大于mtu会进入此流程，将用户态数据拷贝拷skb中的非线性区中(即skb_shared_info->frags[]，原本用于SG)。
 *
 *
 * ip_append_data中，如果满足ufo的条件，则进入这里处理。
 * 主要是利用了skb中的frags[]区域存放数据，该区域原本是用于SG场景的，但UFO此时也复用了这段区域。
 */
static inline int ip_ufo_append_data(struct sock *sk,
			int getfrag(void *from, char *to, int offset, int len,
			       int odd, struct sk_buff *skb),
			void *from, int length, int hh_len, int fragheaderlen,
			int transhdrlen, int mtu,unsigned int flags)
{
	struct sk_buff *skb;
	int err;

	/* There is support for UDP fragmentation offload by network
	 * device, so create one single skb packet containing complete
	 * udp datagram
	 */
	 /*从sock请求队列队尾取skb，如果为空，需要重新分配skb*/
	if ((skb = skb_peek_tail(&sk->sk_write_queue)) == NULL) {
		/*重新分配一个skb*/
		skb = sock_alloc_send_skb(sk,
			hh_len + fragheaderlen + transhdrlen + 20,
			(flags & MSG_DONTWAIT), &err);

		if (skb == NULL)
			return err;

		/* reserve space for Hardware header */
		/*留出链路层头的空间*/
		skb_reserve(skb, hh_len);

		/* create space for UDP/IP header */
		/*留出传输层和IP层头部大小的空间*/
		skb_put(skb,fragheaderlen + transhdrlen);

		/* initialize network header pointer */		
		/*初始化IP头*/
		skb_reset_network_header(skb);

		/* initialize protocol header pointer */
		/*初始化传输层头指针*/
		skb->transport_header = skb->network_header + fragheaderlen;

		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum = 0;
		sk->sk_sndmsg_off = 0;
	}

    /*向skb中添加数据, skb_shinfo(skb)->frags[]*/
	err = skb_append_datato_frags(sk,skb, getfrag, from,
			       (length - transhdrlen));
	if (!err) {
		/* specify the length of each IP datagram fragment*/
	    
		skb_shinfo(skb)->gso_size = mtu - fragheaderlen;
		/*
		 * 如果当前skb中未设置GSO标记，说明是因为length > mtu进入到这里的，需要设置GSO标记
		 */
		skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
	
	    /*将新分配的skb放入sock的发送队列中*/
		__skb_queue_tail(&sk->sk_write_queue, skb);

		return 0;
	}
	/* There is not enough support do UFO ,
	 * so follow normal path
	 */
	kfree_skb(skb);
	return err;
}

/*
 *	ip_append_data() and ip_append_page() can make one large IP datagram
 *	from many pieces of data. Each pieces will be holded on the socket
 *	until ip_push_pending_frames() is called. Each piece can be a page
 *	or non-page data.
 *
 *	Not only UDP, other transport protocols - e.g. raw sockets - can use
 *	this interface potentially.
 *
 *	LATER: length must be adjusted by pad at tail, when it is required.
 * 
 *
 * 该接口是IP层提供的UDP和RAW Socket的输出数据的接口，同时，TCP中用于发送ACK和RST报文的接口ip_send_reply最终也会调用此接口
 *  该接口的主要作用是：将数据拷贝到适合的skb(利用发送队列中现有的或新创建)中，可能有两种情况:
 *  1）放入skb的线性区(skb->data)中；
 *  2）或者放入skb_shared_info的分片(frag)中（当开启SG特性或使用UFO时，都会用到）
 *  另外，还需要考虑MTU对skb数据进行分割，为IP层的分片做准备。
 *
 * 
 *  参数getfrag可以是：
 *     ip_generic_getfrag:用于复制UDP套接口和RAW套接口的数据
 *     udplite_getfrag: 用于复制轻量级的UDP数据
 *     ip_reply_glue_bits: 用于在TCP中复制RST和ACK段的数据。
 *     icmp_glue_bits: 用于复制ICMP报文。
 *
 *
 * sys_socketcall()
 *  sys_send()
 *   sys_sendto()
 *    sock_sendmsg()
 *     __sock_sendmsg() ; socket->ops->sendmsg
 *      inet_sendmsg()
 *       udp_sendmsg()
 *        ip_append_data()
 *
 * raw_sendmsg()
 *  ip_append_data()
 *
 * ip_send_reply()
 *  ip_append_data()
 *
 * L4层协议可以多次调用ip_append_data来存储要发送的数据，而不实际传输任何东西
 *
 * 这个函数变种为ip_append_page,主要有udp协议使用
 *
 *
 * 书: ip_append_data的主要任务是创建sk_buff，为ip层数据分片做好准备.
 * 该函数根据路由查询得到的接口MTU，把超过MTU长度的数据分片保存在多个套接字缓冲区中，
 * 并插入到sk_write_queue中。对于较大的数据包，可能要循环多次
 *
 */
int ip_append_data(struct sock *sk,
		   int getfrag(void *from, char *to, int offset, int len,
			       int odd, struct sk_buff *skb) /* 函数指针,不同的传输层，函数是不一样的 */,
		   void *from, int length, int transhdrlen,
		   struct ipcm_cookie *ipc, struct rtable *rt,
		   unsigned int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;

	struct ip_options *opt = NULL;
	int hh_len;
	int exthdrlen;  //记录IPSec中扩展首部的长度
	int mtu;
	int copy; /*当前需要拷贝的数据大小。取决于skb中线性区剩余的空间大小和非线性区的大小*/
	int err;
	int offset = 0;
	unsigned int maxfraglen, fragheaderlen;
	int csummode = CHECKSUM_NONE;

	if (flags&MSG_PROBE) //并不真的传送数据，只是进行路径MTU的探测.
		return 0;

    
	if (skb_queue_empty(&sk->sk_write_queue)) { // 首次写入，输出队列为空
		/*
		 * setup for corking.
		 */
		opt = ipc->opt;
		if (opt) {  
			/* 
			 * 存在ip选项数据,要为传输控制块设置一些临时信息，将ip选项信息复制到临时控制块中去。
			 * 并设置IPCORK_OP,表示临时信息控制块中存在IP选项。
			 */
			if (inet->cork.opt == NULL) {
				// 分配opt数据空间
				inet->cork.opt = kmalloc(sizeof(struct ip_options) + 40, sk->sk_allocation);
				if (unlikely(inet->cork.opt == NULL))
					return -ENOBUFS;
			}
			//复制ip选项数据
			memcpy(inet->cork.opt, opt, sizeof(struct ip_options)+opt->optlen);
			inet->cork.flags |= IPCORK_OPT;
			inet->cork.addr = ipc->addr;
		}
		// dst引用计数+1
		dst_hold(&rt->u.dst);

		//得到用来分片的mtu值
		inet->cork.fragsize = mtu = inet->pmtudisc == IP_PMTUDISC_PROBE ?
					    rt->u.dst.dev->mtu :
					    dst_mtu(rt->u.dst.path); //dst->metrics[index]
		//路由				
		inet->cork.rt = rt;
		inet->cork.length = 0;
		/*
		 * 初始化分片位置信息:
		 * sk_sndmsg_page指向分片首地址
		 * sk_sndmsg_off是下一个分片的存放位置
		 */
		sk->sk_sndmsg_page = NULL;
		sk->sk_sndmsg_off = 0;
		
		if ((exthdrlen = rt->u.dst.header_len) != 0) {
			length += exthdrlen;
			transhdrlen += exthdrlen;
		}
		
	} else {
	   //sk->sk_write_queue队列中已经有数据
	   
	   // 如果传输控制块的输出队列不为空，则使用上次的输出路由，ip选项，以及分片长度
		rt = inet->cork.rt;
		if (inet->cork.flags & IPCORK_OPT)
			opt = inet->cork.opt;

        //书:如果不是第一个分片，则套接字缓冲区的data内容中没有头部格式信息
		transhdrlen = 0;
		exthdrlen = 0;
		//得到mtu值
		mtu = inet->cork.fragsize;
	}
	
	/*获取链路层首部的长度*/
	hh_len = LL_RESERVED_SPACE(rt->u.dst.dev);
    //获取IP首部(分片首部)的长度
	fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);
	// IP数据包中数据的最大长度，通过mtu计算，并进行8字节对齐，目的是提升计算效率
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;

    //输出的报文长度不能超过IP数据报能容纳的最大长度(64K)
	if (inet->cork.length + length > 0xFFFF - fragheaderlen) {
		ip_local_error(sk, EMSGSIZE, rt->rt_dst, inet->dport, mtu-exthdrlen);
		return -EMSGSIZE;
	}

	/*
	 * transhdrlen >0 表示这是第一个分片
	 * transhdrlen > 0 means that this is the first fragment and we wish
	 * it won't be fragmented in the future.
	 *
	 * 如果IP数据报没有分片，且输出网络设备支持硬件执行校验和，就设置CHECKSUM_PARTIAL，表示由硬件来执行校验和.
	 */
	if (transhdrlen &&
	    length + fragheaderlen <= mtu &&
	    rt->u.dst.dev->features & NETIF_F_V4_CSUM &&
	    !exthdrlen)
		csummode = CHECKSUM_PARTIAL;

	/*
	 * 累计分片数据的总长度
	 */
	inet->cork.length += length;

	/*
	 * 如果输出的是UDP数据报且需要分片，同时输出网络设备支持UDP分片卸载(UDP fragmentation offload)
	 * 则由ip_ufo_append_data进行分片输出处理。
	 */
	if (((length > mtu) && (sk->sk_protocol == IPPROTO_UDP)) &&
			(rt->u.dst.dev->features & NETIF_F_UFO)) {

	  /*
	   * 分配空间，将数据复制到skb中来
	   *
	   * UFO处理，需要满足上述几个条件，主要为:数据长度>mtu +   网卡启用UFO.
	   * 默认处理是创建新的page，拷贝数据，并将其链入到skb中的分片中(skb_shared_info,SG相关)
	   */
		err = ip_ufo_append_data(sk, getfrag, from, length, hh_len,
					 fragheaderlen, transhdrlen, mtu,
					 flags);
		if (err)
			goto error;
		return 0;
	}

	/* So, what's going on in the loop below?
	 *
	 * We use calculated fragment length to generate chained skb,
	 * each of segments is IP fragment ready for sending to network after
	 * adding appropriate IP header.
	 */

	/*
	 * 如果sk->sk_write_queue为空，是第一次分片，需要分配一个新的套接字缓冲区
	 */
	if ((skb = skb_peek_tail(&sk->sk_write_queue)) == NULL)
		goto alloc_new_skb;

    /*
     * 存在skb，且没有进入UFO流程，那么这里就要开始进行分段了，length为需要发送的数据长度
     * UDP层的分段实际是在这里完成的。当length 大于该skb中剩余的空间大小(copy)时，则需要分配新
     * 的skb中来存放length中剩余的数据，新分配的skb会也被链入sock的发送队列链表中，最后会通过
     * ip_make_skb，将sock发送链表中的skb中都链入到skb->frag_list中
     *
     * 书:把尚未插入队列的数据插入套接字发送队列中
     * length > 0 说明还有数据剩下,需要继续分片并插入队列中
     */
	while (length > 0) {
		/* Check if the remaining data fits into current packet. */
        /*计算当前skb中还能放多少数据，通过mtu-skb的数据长度计算，因为没有开启UFO，每个数据包长度不能大于mtu*/
		copy = mtu - skb->len;
        /*
         * 如果skb的剩余空间不足以存放完这次需要放入的数据长度length，则将当前skb填满即可，剩余数据留下一个skb发送
         * 其中maxfraglen是8字节对齐后的mtu。
         */		
		if (copy < length)
			copy = maxfraglen - skb->len;

        /*
         * 这里分两种情况:1.copy < 0，这表示:当前skb中的数据本身就已经大于MTU了(可能由于老版本中ip_ufo_append_data流程中UFO标记没有设置导致)，
         * 那就需要对原来的skb重新进行分段了，需要新分配skb来容纳原来skb中的数据
         * 2.copy==0，这表示当前skb不足以容纳length长度的数据，并且原来的skb中的数据已经填满了(此时数据包刚好为mtu，所以copy刚好为0)，此时
         * 需要分配新的skb来装剩下的数据，直至copy>0(表示当前skb中在装完length长度的数据后，还剩余空间，表明这已经是最后一个分段了)循环
         * 结束，以这种方式达到分段的目的。
         */		
		if (copy <= 0) { 
			// 说明mtu小于skb中的数据长度
			char *data;
			unsigned int datalen;
			unsigned int fraglen;
			unsigned int fraggap;
			unsigned int alloclen;
			struct sk_buff *skb_prev;
alloc_new_skb:
	        /*3种原因需要新分配skb: 1.原有的skb数据区空间不足2.sock的输出队列为空3.原来的skb的数据已经大于mtu了，需要重新分段*/
			skb_prev = skb;
			/*由于原有的skb数据区空间不足，而需要分配新skb，计算不足的大小*/
			if (skb_prev)
				fraggap = skb_prev->len - maxfraglen;
			else /*由于sock的输出队列为空*/
				fraggap = 0;

			/*
			 * If remaining data exceeds the mtu,
			 * we know we need more fragment(s).
			 */
			/*这次需要新分配的数据区大小length加上原来skb中不足的大小，为新skb需要分配的数据区大小*/
			datalen = length + fraggap;
            /*如果新skb需要分配的数据区大小超过了mtu，那这次还是只能分配mtu的大小，剩余数据需要通过循环分配新skb来容纳*/	
			if (datalen > mtu - fragheaderlen)
				datalen = maxfraglen - fragheaderlen;
			/*数据报分片大小需要加上IP首部的长度*/
			fraglen = datalen + fragheaderlen;
            
			/*如果设置了MSG_MORE标记，表明需要等待新数据，一直到超过mtu为止，则设置"分配空间大小"为mtu*/
			if ((flags & MSG_MORE) &&
			    !(rt->u.dst.dev->features&NETIF_F_SG))
				alloclen = mtu;
			else /*否则需要分配的空间大小为数据报分片大小*/
				alloclen = datalen + fragheaderlen;

			/* The last fragment gets additional space at tail.
			 * Note, with MSG_MORE we overallocate on fragments,
			 * because we have no idea what fragment will be
			 * the last.
			 *
			 * 为最后一个碎片分配更多的空间
			 */
			if (datalen == length + fraggap)
				alloclen += rt->u.dst.trailer_len;

            /*
             * 根据是否存在传输层首部，确定分配skb的方法:
             * 如果存在，则说明该分片为分片组中的第一个分片，那就需要考虑更多的情况，
             * 比如:发送是否超时、是否发生未处理的致命错误、
             * 发送通道是否已经关闭等；当不存在传输层首部时，说明不是第一个分片，则不需考虑这些情况。
             */
			if (transhdrlen) {
				 /*分配skb，并进行相关处理*/
				skb = sock_alloc_send_skb(sk,
						alloclen + hh_len + 15,
						(flags & MSG_DONTWAIT), &err);
			} else { /*不是第一个分片(分段)，直接分片新的skb*/
			
				skb = NULL;
				if (atomic_read(&sk->sk_wmem_alloc) <=
				    2 * sk->sk_sndbuf)
				    /*分配skb*/
					skb = sock_wmalloc(sk,
							   alloclen + hh_len + 15, 1,
							   sk->sk_allocation);
				
				if (unlikely(skb == NULL))
					err = -ENOBUFS;
			}
			if (skb == NULL)
				goto error;

			/*
			 *	Fill in the control structures
			 */
			 /*初始化skb中的相关成员*/
			skb->ip_summed = csummode;
			skb->csum = 0;
			/*留出链路层头部大小*/
			skb_reserve(skb, hh_len);

			/*
			 *	Find where to start putting bytes.
			 */
			 /*在skb中预留存放三层首部和数据的空间*/
			data = skb_put(skb, fraglen);
			/*设置IP头指针位置*/
			skb_set_network_header(skb, exthdrlen);
			/*计算传输层头部长度*/
			skb->transport_header = (skb->network_header +
						 fragheaderlen);
			/*计算数据存入的位置*/
			data += fragheaderlen;
			
            /*
             * 如果上一个skb的数据大于mtu(8字节对齐)，那么需要对其进行分段处理，即将一个skb拆开，
             * 将上一个skb中超出的数据和传输层首部并 复制到当前的skb中，并重新计算校验和。
             */
			if (fraggap) {
				skb->csum = skb_copy_and_csum_bits(
					skb_prev, maxfraglen,
					data + transhdrlen, fraggap, 0);
				/*上一个skb的校验和也需要重新计算*/
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				/*拷贝新数据后，再次移动data指针，更新数据写入的位置*/
				data += fraggap;
				/*已8字节对齐的MTU大小截取上一个skb，多余的数据已经拷贝到新的skb中了，需要截掉*/
				pskb_trim_unique(skb_prev, maxfraglen);
			}

            /*拷贝新数据到数据区*/
			copy = datalen - transhdrlen - fraggap;
			/*getfrag为传入的函数指针，udp默认为ip_generic_getfrag，用于从用户态拷贝数据到内核中(skb的数据区)*/
			if (copy > 0 && getfrag(from, data + transhdrlen, offset, copy, fraggap, skb) < 0) {
				err = -EFAULT;
				kfree_skb(skb);
				goto error;
			}

            /*更新下次拷贝相关的数据*/
			offset += copy;
			length -= datalen - fraggap;
			/*由于传输层首部已经拷贝过了，所以相关变量置0*/
			transhdrlen = 0;
			exthdrlen = 0;
			csummode = CHECKSUM_NONE;

			/*
			 * Put the packet on the pending queue.
			 */
			 /*复制完数据的skb添加到sock输出队列的末尾*/
			__skb_queue_tail(&sk->sk_write_queue, skb);
			continue;
		}

        /*如果当前skb中的剩余数据区大于要拷贝的数据长度，那说明这次要发送的数据可以直接放入当前的skb中，直接拷贝即可。*/
		if (copy > length)
			copy = length;

        /*如果硬件不支持SG(分散聚集特性，使用skb中的非线性区(shared_info))*/
		if (!(rt->u.dst.dev->features&NETIF_F_SG)) {
			unsigned int off;

			off = skb->len;

			/*将数据拷贝到skb中的线性区*/
			if (getfrag(from, skb_put(skb, copy),
					offset, copy, off, skb) < 0) {
				__skb_trim(skb, off);
				err = -EFAULT;
				goto error;
			}
		} else {
		    /*如果硬件支持SG，则将数据拷贝到skb的非线性区(shared_info)的frags[]数组指向的page中，注意:UFO时也会使用这个*/
			int i = skb_shinfo(skb)->nr_frags;
			
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i-1];
			
			struct page *page = sk->sk_sndmsg_page;
			int off = sk->sk_sndmsg_off;
			unsigned int left;

			if (page && (left = PAGE_SIZE - off) > 0) {
				
				if (copy >= left)
					copy = left;
				if (page != frag->page) {
					if (i == MAX_SKB_FRAGS) {
						err = -EMSGSIZE;
						goto error;
					}
					get_page(page);
					skb_fill_page_desc(skb, i, page, sk->sk_sndmsg_off, 0);
					frag = &skb_shinfo(skb)->frags[i];
				}
			} else if (i < MAX_SKB_FRAGS) {
				if (copy > PAGE_SIZE)
					copy = PAGE_SIZE;
				page = alloc_pages(sk->sk_allocation, 0);
				if (page == NULL)  {
					err = -ENOMEM;
					goto error;
				}
				sk->sk_sndmsg_page = page;
				sk->sk_sndmsg_off = 0;

				skb_fill_page_desc(skb, i, page, 0, 0);
				frag = &skb_shinfo(skb)->frags[i];
			} else {
				err = -EMSGSIZE;
				goto error;
			}
			
			/*拷贝数据至skb中非线性区分片(分散聚集IO页面)中*/
			if (getfrag(from, page_address(frag->page)+frag->page_offset+frag->size, offset, copy, skb->len, skb) < 0) {
				err = -EFAULT;
				goto error;
			}
			/*移动相应数据指针*/
			sk->sk_sndmsg_off += copy;
			/*增加分片大小*/
			frag->size += copy;
			/*增加skb数据相关大小*/
			skb->len += copy;
			skb->data_len += copy;
			skb->truesize += copy;
			/*增加sock发送缓存区已分配数据大小*/
			atomic_add(copy, &sk->sk_wmem_alloc);
		}
		offset += copy;
		/*length减去已经拷贝的大小，如果拷完了，则结束循环，否则继续拷贝*/
		length -= copy;
	}

	return 0;

error:
	inet->cork.length -= length;
	IP_INC_STATS(IPSTATS_MIB_OUTDISCARDS);
	return err;
}

/*
 * ip_append_page函数为ip_append_data的变种,主要有udp协议使用
 *
 * udp_sendpage()
 *  ip_append_page()
 *
 */
ssize_t	ip_append_page(struct sock *sk, struct page *page,
		       int offset, size_t size, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;
	struct rtable *rt;
	struct ip_options *opt = NULL;
	int hh_len;
	int mtu;
	int len;
	int err;
	unsigned int maxfraglen, fragheaderlen, fraggap;

	if (inet->hdrincl)
		return -EPERM;

	if (flags&MSG_PROBE)
		return 0;

	if (skb_queue_empty(&sk->sk_write_queue))
		return -EINVAL;

	rt = inet->cork.rt;
	if (inet->cork.flags & IPCORK_OPT)
		opt = inet->cork.opt;

	if (!(rt->u.dst.dev->features&NETIF_F_SG))
		return -EOPNOTSUPP;

	hh_len = LL_RESERVED_SPACE(rt->u.dst.dev);
	mtu = inet->cork.fragsize;

	fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;

	if (inet->cork.length + size > 0xFFFF - fragheaderlen) {
		ip_local_error(sk, EMSGSIZE, rt->rt_dst, inet->dport, mtu);
		return -EMSGSIZE;
	}

	if ((skb = skb_peek_tail(&sk->sk_write_queue)) == NULL)
		return -EINVAL;

	inet->cork.length += size;
	if ((sk->sk_protocol == IPPROTO_UDP) &&
	    (rt->u.dst.dev->features & NETIF_F_UFO)) {
		skb_shinfo(skb)->gso_size = mtu - fragheaderlen;
		skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
	}


	while (size > 0) {
		int i;

		if (skb_is_gso(skb))
			len = size;
		else {

			/* Check if the remaining data fits into current packet. */
			len = mtu - skb->len;
			if (len < size)
				len = maxfraglen - skb->len;
		}
		if (len <= 0) {
			struct sk_buff *skb_prev;
			int alloclen;

			skb_prev = skb;
			fraggap = skb_prev->len - maxfraglen;

			alloclen = fragheaderlen + hh_len + fraggap + 15;
			skb = sock_wmalloc(sk, alloclen, 1, sk->sk_allocation);
			if (unlikely(!skb)) {
				err = -ENOBUFS;
				goto error;
			}

			/*
			 *	Fill in the control structures
			 */
			skb->ip_summed = CHECKSUM_NONE;
			skb->csum = 0;
			skb_reserve(skb, hh_len);

			/*
			 *	Find where to start putting bytes.
			 */
			skb_put(skb, fragheaderlen + fraggap);
			skb_reset_network_header(skb);
			skb->transport_header = (skb->network_header +
						 fragheaderlen);
			if (fraggap) {
				skb->csum = skb_copy_and_csum_bits(skb_prev,
								   maxfraglen,
						    skb_transport_header(skb),
								   fraggap, 0);
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				pskb_trim_unique(skb_prev, maxfraglen);
			}

			/*
			 * Put the packet on the pending queue.
			 */
			__skb_queue_tail(&sk->sk_write_queue, skb);
			continue;
		}

		i = skb_shinfo(skb)->nr_frags;
		if (len > size)
			len = size;
		if (skb_can_coalesce(skb, i, page, offset)) {
			skb_shinfo(skb)->frags[i-1].size += len;
		} else if (i < MAX_SKB_FRAGS) {
			get_page(page);
			skb_fill_page_desc(skb, i, page, offset, len);
		} else {
			err = -EMSGSIZE;
			goto error;
		}

		if (skb->ip_summed == CHECKSUM_NONE) {
			__wsum csum;
			csum = csum_page(page, offset, len);
			skb->csum = csum_block_add(skb->csum, csum, skb->len);
		}

		skb->len += len;
		skb->data_len += len;
		skb->truesize += len;
		atomic_add(len, &sk->sk_wmem_alloc);
		offset += len;
		size -= len;
	}
	return 0;

error:
	inet->cork.length -= size;
	IP_INC_STATS(IPSTATS_MIB_OUTDISCARDS);
	return err;
}

static void ip_cork_release(struct inet_sock *inet)
{
	inet->cork.flags &= ~IPCORK_OPT;
	kfree(inet->cork.opt);
	inet->cork.opt = NULL;
	if (inet->cork.rt) {
		ip_rt_put(inet->cork.rt);
		inet->cork.rt = NULL;
	}
}

/*
 *	Combined all pending IP fragments on the socket as one IP datagram
 *	and push them out.
 *
 *  icmp_push_reply()
 *   ip_push_pending_frames()
 *
 *  ip_send_reply()
 *   ip_push_pending_frames()
 *
 *  raw_sendmsg()
 *   ip_push_pending_frames()
 *
 *  udp_sendmsg()
 *   udp_push_pending_frames()
 *    ip_push_pending_frames()
 *
 *  函数用于将该socket上的所有pending的IP分片，组成一个IP报文发送出去
 *
 * tcp和sctp这类已经把分段考虑进去的协议，会调用ip_queue_xmit函数来发送数据
 * 没有把分段考虑进去的协议会调用ip_push_pending_frames来发送数据 
 */
int ip_push_pending_frames(struct sock *sk)
{
	struct sk_buff *skb, *tmp_skb;
	struct sk_buff **tail_skb;

	//转成inet_sock对象
	struct inet_sock *inet = inet_sk(sk);
	struct ip_options *opt = NULL;

	//路由缓存
	struct rtable *rt = inet->cork.rt;
	struct iphdr *iph;
	__be16 df = 0;
	__u8 ttl;
	int err = 0;

    /* 发送队列不能为空 */
	if ((skb = __skb_dequeue(&sk->sk_write_queue)) == NULL)
		goto out;

	// 获取fraglist链表，用于存放处理后的分片
	tail_skb = &(skb_shinfo(skb)->frag_list);

	/* move skb->data to ip header from ext header */
	//如果skb的data指针不正确，则调整到ip首部处，因为接着处理的是IP数据报。
	if (skb->data < skb_network_header(skb))
		__skb_pull(skb, skb_network_offset(skb));

	/*
	 * 除去SKB中的ip首部后,链接到第一个skb的fraglist上,组成一个分片，为后续的分片做准备
	 *
	 * 将sk->sk_write_queue上所有的skb对象弹出来，放到tail_skb上去
	 */
	while ((tmp_skb = __skb_dequeue(&sk->sk_write_queue)) != NULL) {

	    //去掉ip首部
		__skb_pull(tmp_skb, skb_network_header_len(skb));

	    //链接起来
		*tail_skb = tmp_skb;
		tail_skb = &(tmp_skb->next);

		//数据总长度
		skb->len += tmp_skb->len;
		skb->data_len += tmp_skb->len;
		skb->truesize += tmp_skb->truesize;
		
		__sock_put(tmp_skb->sk);
		tmp_skb->destructor = NULL;
		tmp_skb->sk = NULL;
	}

	/* Unless user demanded real pmtu discovery (IP_PMTUDISC_DO), we allow
	 * to fragment the frame generated here. No matter, what transforms
	 * how transforms change size of the packet, it will come out.
	 *
	 * 在不启用MTU时发现时，允许对输出数据做分片
	 */
	if (inet->pmtudisc < IP_PMTUDISC_DO)
		skb->local_df = 1;

	/* DF bit is set when we want to see DF on outgoing frames.
	 * If local_df is set too, we still allow to fragment this frame
	 * locally. 
	 *
	 * 如果启用了路径MTU发现功能，或者输出数据包的长度小于MTU且本传输控制块输出的IP数据报不能分片，
	 * 则给IP首部添加禁止分片标志
	 */
	if (inet->pmtudisc >= IP_PMTUDISC_DO ||
	    (skb->len <= dst_mtu(&rt->u.dst) &&
	     ip_dont_fragment(sk, &rt->u.dst)))
		df = htons(IP_DF);

    /*
     * 如果IP选项信息已经保存到传输控制块中了，则获取ip选项信息，
     * 准备用于构建ip首部中的选项
     */
	if (inet->cork.flags & IPCORK_OPT)
		opt = inet->cork.opt;

    //获取TTL
	if (rt->rt_type == RTN_MULTICAST)
		ttl = inet->mc_ttl;
	else
		ttl = ip_select_ttl(inet, &rt->u.dst);

    //开始构建ip首部和选项信息
	iph = (struct iphdr *)skb->data;
	iph->version = 4;
	iph->ihl = 5;
	
	//构建ip option值
	if (opt) {
		iph->ihl += opt->optlen>>2;
		ip_options_build(skb, opt, inet->cork.addr, rt, 0);
	}

	//ip头部的各个值填起来
	iph->tos = inet->tos;
	iph->tot_len = htons(skb->len);
	iph->frag_off = df;
	//确定ip头部的ID
	ip_select_ident(iph, &rt->u.dst, sk);
	iph->ttl = ttl;
	iph->protocol = sk->sk_protocol;
	iph->saddr = rt->rt_src;
	iph->daddr = rt->rt_dst;
	ip_send_check(iph);

    //设置数据报的优先级和目的路由
	skb->priority = sk->sk_priority;
	skb->dst = dst_clone(&rt->u.dst);

	if (iph->protocol == IPPROTO_ICMP)
		icmp_out_count(((struct icmphdr *)
			skb_transport_header(skb))->type);

	/* Netfilter gets whole the not fragmented skb. 
	 * 发送出去
     */
	err = NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL,
		      skb->dst->dev, dst_output);
	if (err) {
		if (err > 0)
			err = inet->recverr ? net_xmit_errno(err) : 0;
		if (err)
			goto error;
	}

out:
	ip_cork_release(inet);
	return err;

error:
	IP_INC_STATS(IPSTATS_MIB_OUTDISCARDS);
	goto out;
}

/*
 *	Throw away all pending data on the socket.
 * 释放sock->sk_write_queue中的数据
 */
void ip_flush_pending_frames(struct sock *sk)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue_tail(&sk->sk_write_queue)) != NULL)
		kfree_skb(skb);

	ip_cork_release(inet_sk(sk));
}


/*
 *	Fetch data from kernel space and fill in checksum if needed.
 *
 * ip_append_data()
 *  ip_ufo_append_data()
 *   skb_append_datato_frags() 
 *    ip_reply_glue_bits()
 */
static int ip_reply_glue_bits(void *dptr, char *to, int offset,
			      int len, int odd, struct sk_buff *skb)
{
	__wsum csum;

	csum = csum_partial_copy_nocheck(dptr+offset, to, len, 0);
	skb->csum = csum_block_add(skb->csum, csum, odd);
	return 0;
}

/*
 *	Generic function to send a packet as reply to another packet.
 *	Used to send TCP resets so far. ICMP should use this function too.
 *
 *	Should run single threaded per socket because it uses the sock
 *     	structure to pass arguments.
 *
 *	LATER: switch from ip_build_xmit to ip_append_*
 * 
 * 将TCP段打包成ip数据报的方法根据TCP段类型的不同而有多种接口，
 * 其中最常用的就是ip_queue_xmit,而ip_build_and_send_pkt和ip_send_reply只有在发送特定段时才会被调用.
 *
 * 主要用于构成并输出RST和ACK段，在tcp_v4_send_reset()和tcp_v4_send_ack()中被调用
 *
 * tcp_v4_send_reset()
 *  ip_send_reply()
 *
 * tcp_v4_send_ack()
 *  ip_send_reply()
 */
void ip_send_reply(struct sock *sk, struct sk_buff *skb, struct ip_reply_arg *arg,
		   unsigned int len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct {
		struct ip_options	opt;
		char			data[40];
	} replyopts;
	struct ipcm_cookie ipc;
	__be32 daddr;
	struct rtable *rt = (struct rtable*)skb->dst;

    //从待输出的IP数据报中得到选项，用于处理源路由选项.
	if (ip_options_echo(&replyopts.opt, skb))
		return;

    //根据对方发送过来的数据报的输入路由，获取对方的IP地址.
	daddr = ipc.addr = rt->rt_src;
	ipc.opt = NULL;

    // 如果输入的IP数据报启用了源路由选项，则将得到下一跳的IP地址作为目的地址.
	if (replyopts.opt.optlen) {
		ipc.opt = &replyopts.opt;

		if (ipc.opt->srr)
			daddr = replyopts.opt.faddr;
	}

    /* 根据目的地址，源地址等查找到对方的路由。如果查找命中，则可以输出数据报，否则终止输出 */
	{
		struct flowi fl = { .oif = arg->bound_dev_if,
				    .nl_u = { .ip4_u =
					      { .daddr = daddr,
						.saddr = rt->rt_spec_dst,
						.tos = RT_TOS(ip_hdr(skb)->tos) } },
				    /* Not quite clean, but right. */
				    .uli_u = { .ports =
					       { .sport = tcp_hdr(skb)->dest,
						 .dport = tcp_hdr(skb)->source } },
				    .proto = sk->sk_protocol };
		
		security_skb_classify_flow(skb, &fl);
		//得到路由信息，存放在rt中带出来
		if (ip_route_output_key(&rt, &fl))
			return;
	}

	/* And let IP do all the hard work.

	   This chunk is not reenterable, hence spinlock.
	   Note that it uses the fact, that this function is called
	   with locally disabled BH and that sk cannot be already spinlocked.
	 */
	bh_lock_sock(sk);
	
	inet->tos = ip_hdr(skb)->tos;
	sk->sk_priority = skb->priority;
	sk->sk_protocol = ip_hdr(skb)->protocol;
	sk->sk_bound_dev_if = arg->bound_dev_if;

	/* 先将数据添加到输出队列末尾的SKB中，或将数据复制到新生成的SKB中并添加到输出队列中。 */
	ip_append_data(sk, ip_reply_glue_bits, arg->iov->iov_base, len, 0,
		       &ipc, rt, MSG_DONTWAIT);
	if ((skb = skb_peek(&sk->sk_write_queue)) != NULL) {
		if (arg->csumoffset >= 0)
			*((__sum16 *)skb_transport_header(skb) +
			  arg->csumoffset) = csum_fold(csum_add(skb->csum,
								arg->csum));
		skb->ip_summed = CHECKSUM_NONE;

		//发送出去
		ip_push_pending_frames(sk);
	}

	bh_unlock_sock(sk);

	ip_rt_put(rt);
}

/*
 * inet_init()
 *  ip_init()
 */
void __init ip_init(void)
{
    /* 初始化路由模块 */
	ip_rt_init();
	/* 对端信息管理模块 */
	inet_initpeers();

#if defined(CONFIG_IP_MULTICAST) && defined(CONFIG_PROC_FS)
    /* 组播 */
	igmp_mc_proc_init();
#endif
}

EXPORT_SYMBOL(ip_generic_getfrag);
EXPORT_SYMBOL(ip_queue_xmit);
EXPORT_SYMBOL(ip_send_check);
