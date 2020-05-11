/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for inet_sock
 *
 * Authors:	Many, reorganised here by
 * 		Arnaldo Carvalho de Melo <acme@mandriva.com>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _INET_SOCK_H
#define _INET_SOCK_H


#include <linux/string.h>
#include <linux/types.h>
#include <linux/jhash.h>

#include <net/flow.h>
#include <net/sock.h>
#include <net/request_sock.h>
#include <net/route.h>

/** struct ip_options - IP Options
 *
 * @faddr - Saved first hop address
 * @is_data - Options in __data, rather than skb
 * @is_strictroute - Strict source route
 * @srr_is_hit - Packet destination addr was our one
 * @is_changed - IP checksum more not valid
 * @rr_needaddr - Need to record addr of outgoing dev
 * @ts_needtime - Need to record timestamp
 * @ts_needaddr - Need to record addr of outgoing dev
 *
 * inet_skb_parm中存放ip_options，inet_skb_parm存放在sk_buff->cb[]中
 * 
 */
struct ip_options {
    //存在宽松或者严格源路由选项时，用来记录下一跳的IP地址。
	__be32		faddr;
	//标识IP首部中选项所占的字节数
	unsigned char	optlen;
	/* 
	 * 记录宽松源路由或者严格源路由选项在IP首部中的偏移量，
	 * 即选项的第一个字节的地址减去IP首部的第一个字节的地址。
	 */
	unsigned char	srr;
	/*
	 * 用于记录记录路径选项在IP首部中的偏移量
	 */
	unsigned char	rr;
	// 用于记录时间戳选项在IP首部中的偏移量
	unsigned char	ts;
	/*
	 * 标识IP选项是否有数据，若有则存放在__data字段起始的存储空间内，即紧跟在ip_option结构后面.
	 * 这里的数据不只是选项数据,而是整个选项内容。
	 */
	unsigned char	is_data:1,
	 /* 标识该选项时IPOPT_SSRR，而不是IPOPT_LSRR */
			is_strictroute:1,
	 /* 标识目的地址是从源路由选项选出的 */		
			srr_is_hit:1,
	 /* 标识是否修改过IP首部，如果是则需要重新计算IP首部校验和 */
			is_changed:1,
	
			rr_needaddr:1,
	 /*
	  * ts_needtime标识有IPOPT_TIMESTAMP选项，需要记录时间戳 
	  * ts_needaddr标识有IPOPT_TIMESTAMP选项，需要记录IP地址
	  */			
			ts_needtime:1,
			ts_needaddr:1;
	//标识IPOPT_RA选项。路由警告选项，表示路由器应该更仔细的检查这个数据报。
	unsigned char	router_alert;
	//用于记录商业IP安全选项在IP首部中的偏移量
	unsigned char	cipso;
	unsigned char	__pad2;
	//若选项有数据则从该字段开始，使之紧跟在ip_option结构后面，最多不能超过40B.
	unsigned char	__data[0];
};

#define optlength(opt) (sizeof(struct ip_options) + opt->optlen)

struct inet_request_sock {
	struct request_sock	req;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	u16			inet6_rsk_offset;
	/* 2 bytes hole, try to pack */
#endif
	__be32			loc_addr;
	__be32			rmt_addr;
	__be16			rmt_port;
	u16			snd_wscale : 4, 
				rcv_wscale : 4, 
				tstamp_ok  : 1,
				sack_ok	   : 1,
				wscale_ok  : 1,
				ecn_ok	   : 1,
				acked	   : 1;
	struct ip_options	*opt;
};

static inline struct inet_request_sock *inet_rsk(const struct request_sock *sk)
{
	return (struct inet_request_sock *)sk;
}

struct ip_mc_socklist;
struct ipv6_pinfo;
struct rtable;

/** struct inet_sock - representation of INET sockets
 *
 * @sk - ancestor class
 * @pinet6 - pointer to IPv6 control block
 * @daddr - Foreign IPv4 addr
 * @rcv_saddr - Bound local IPv4 addr
 * @dport - Destination port
 * @num - Local port
 * @saddr - Sending source
 * @uc_ttl - Unicast TTL
 * @sport - Source port
 * @id - ID counter for DF pkts
 * @tos - TOS
 * @mc_ttl - Multicasting TTL
 * @is_icsk - is this an inet_connection_sock?
 * @mc_index - Multicast device index
 * @mc_list - Group array
 * @cork - info to build ip hdr on each ip frag while socket is corked
 *
 * struct inet_sock为TCP/IP协议栈极为重要的结构，
 * 它要位于所有的不同sock类型的顶部。
 * 主要用于保存不同socket类型公有的特性和信息
 */
struct inet_sock {
	/* sk and pinet6 has to be the first two members of inet_sock */
	struct sock		sk;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	struct ipv6_pinfo	*pinet6;
#endif
	/* Socket demultiplex comparisons on incoming packets. */
    /* 
     * 通过与下列的值比较，可以demultiplex收到的包。
     * 通过系统调用connect，bind或setsocktopt可以设置下面的部分值。
     */
	__be32			daddr;
	__be32			rcv_saddr;
	__be16			dport;
	/* inet_num 为主机序的port,即inet_sport为其网络序格式 */
	__u16			num; //对应的sock->type ==SOCK_RAW时，num==protocol
	__be32			saddr;
	/* 用户指定的ttl值，如为-1，则使用系统默认值 */
	__s16			uc_ttl;
	__u16			cmsg_flags;
	struct ip_options	*opt;
	__be16			sport;
	__u16			id;
	__u8			tos;
	//多播ttl
	__u8			mc_ttl;
	__u8			pmtudisc;
	/* 下面这些基本上都是socket的option */
	__u8			recverr:1,
				is_icsk:1, /* 是否是connection socket*/
				freebind:1, /* 是否enable IP_FREEBIND option*/
				hdrincl:1,  /* 是否enable IP_HDRINCL option*/ 
				mc_loop:1;
	int			mc_index;    /* 多播网卡的索引 */
	__be32			mc_addr; /* 用于发送的多播地址 */
	/* 所有加入的多播组 */
	struct ip_mc_socklist	*mc_list;
	

	struct {
		unsigned int		flags;
		unsigned int		fragsize;
		struct ip_options	*opt;
		struct rtable		*rt;
		int			length; /* Total length of all frames */
		__be32			addr;
		struct flowi		fl;
	} cork;
	/*
	 * 看 http://blog.chinaunix.net/uid-23629988-id-186822.html
	 * cork在四个文件中被使用，分别是ip6_output.c，ip_output.c，raw.c，和udp.c
	 * 在ip_append_data()设置cork成员的值
	 * 在udp_sendmsg() 中设置cork->fl中成员的值
	 */	
};

#define IPCORK_OPT	1	/* ip-options has been held in ipcork.opt */
#define IPCORK_ALLFRAG	2	/* always fragment (for ipv6 for now) */

static inline struct inet_sock *inet_sk(const struct sock *sk)
{
	return (struct inet_sock *)sk;
}

static inline void __inet_sk_copy_descendant(struct sock *sk_to,
					     const struct sock *sk_from,
					     const int ancestor_size)
{
	memcpy(inet_sk(sk_to) + 1, inet_sk(sk_from) + 1,
	       sk_from->sk_prot->obj_size - ancestor_size);
}
#if !(defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE))
static inline void inet_sk_copy_descendant(struct sock *sk_to,
					   const struct sock *sk_from)
{
	__inet_sk_copy_descendant(sk_to, sk_from, sizeof(struct inet_sock));
}
#endif

extern int inet_sk_rebuild_header(struct sock *sk);

extern u32 inet_ehash_secret;
extern void build_ehash_secret(void);

static inline unsigned int inet_ehashfn(const __be32 laddr, const __u16 lport,
					const __be32 faddr, const __be16 fport)
{
	return jhash_2words((__force __u32) laddr ^ (__force __u32) faddr,
			    ((__u32) lport) << 16 | (__force __u32)fport,
			    inet_ehash_secret);
}

static inline int inet_sk_ehashfn(const struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);
	const __be32 laddr = inet->rcv_saddr;
	const __u16 lport = inet->num;
	const __be32 faddr = inet->daddr;
	const __be16 fport = inet->dport;

	return inet_ehashfn(laddr, lport, faddr, fport);
}


static inline int inet_iif(const struct sk_buff *skb)
{
	return ((struct rtable *)skb->dst)->rt_iif;
}

#endif	/* _INET_SOCK_H */
