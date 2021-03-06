/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The User Datagram Protocol (UDP).
 *
 * Version:	$Id: udp.c,v 1.102 2002/02/01 22:01:04 davem Exp $
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Alan Cox, <Alan.Cox@linux.org>
 *		Hirokazu Takahashi, <taka@valinux.co.jp>
 *
 * Fixes:
 *		Alan Cox	:	verify_area() calls
 *		Alan Cox	: 	stopped close while in use off icmp
 *					messages. Not a fix but a botch that
 *					for udp at least is 'valid'.
 *		Alan Cox	:	Fixed icmp handling properly
 *		Alan Cox	: 	Correct error for oversized datagrams
 *		Alan Cox	:	Tidied select() semantics.
 *		Alan Cox	:	udp_err() fixed properly, also now
 *					select and read wake correctly on errors
 *		Alan Cox	:	udp_send verify_area moved to avoid mem leak
 *		Alan Cox	:	UDP can count its memory
 *		Alan Cox	:	send to an unknown connection causes
 *					an ECONNREFUSED off the icmp, but
 *					does NOT close.
 *		Alan Cox	:	Switched to new sk_buff handlers. No more backlog!
 *		Alan Cox	:	Using generic datagram code. Even smaller and the PEEK
 *					bug no longer crashes it.
 *		Fred Van Kempen	: 	Net2e support for sk->broadcast.
 *		Alan Cox	:	Uses skb_free_datagram
 *		Alan Cox	:	Added get/set sockopt support.
 *		Alan Cox	:	Broadcasting without option set returns EACCES.
 *		Alan Cox	:	No wakeup calls. Instead we now use the callbacks.
 *		Alan Cox	:	Use ip_tos and ip_ttl
 *		Alan Cox	:	SNMP Mibs
 *		Alan Cox	:	MSG_DONTROUTE, and 0.0.0.0 support.
 *		Matt Dillon	:	UDP length checks.
 *		Alan Cox	:	Smarter af_inet used properly.
 *		Alan Cox	:	Use new kernel side addressing.
 *		Alan Cox	:	Incorrect return on truncated datagram receive.
 *	Arnt Gulbrandsen 	:	New udp_send and stuff
 *		Alan Cox	:	Cache last socket
 *		Alan Cox	:	Route cache
 *		Jon Peatfield	:	Minor efficiency fix to sendto().
 *		Mike Shaver	:	RFC1122 checks.
 *		Alan Cox	:	Nonblocking error fix.
 *	Willy Konynenberg	:	Transparent proxying support.
 *		Mike McLagan	:	Routing by source
 *		David S. Miller	:	New socket lookup architecture.
 *					Last socket cache retained as it
 *					does have a high hit rate.
 *		Olaf Kirch	:	Don't linearise iovec on sendmsg.
 *		Andi Kleen	:	Some cleanups, cache destination entry
 *					for connect.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year coma.
 *		Melvin Smith	:	Check msg_name not msg_namelen in sendto(),
 *					return ENOTCONN for unconnected sockets (POSIX)
 *		Janos Farkas	:	don't deliver multi/broadcasts to a different
 *					bound-to-device socket
 *	Hirokazu Takahashi	:	HW checksumming for outgoing UDP
 *					datagrams.
 *	Hirokazu Takahashi	:	sendfile() on UDP works now.
 *		Arnaldo C. Melo :	convert /proc/net/udp to seq_file
 *	YOSHIFUJI Hideaki @USAGI and:	Support IPV6_V6ONLY socket option, which
 *	Alexey Kuznetsov:		allow both IPv4 and IPv6 sockets to bind
 *					a single port at the same time.
 *	Derek Atkins <derek@ihtfp.com>: Add Encapulation Support
 *	James Chapman		:	Add L2TP encapsulation type.
 *
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/ioctls.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/igmp.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <net/tcp_states.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/net_namespace.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include "udp_impl.h"

/*
 *	Snmp MIB for the UDP layer
 */

DEFINE_SNMP_STAT(struct udp_mib, udp_statistics) __read_mostly;

struct hlist_head udp_hash[UDP_HTABLE_SIZE];
DEFINE_RWLOCK(udp_hash_lock);

static inline int __udp_lib_lport_inuse(__u16 num,
					const struct hlist_head udptable[])
{
	struct sock *sk;
	struct hlist_node *node;

	sk_for_each(sk, node, &udptable[num & (UDP_HTABLE_SIZE - 1)])
		if (sk->sk_hash == num)
			return 1;
	return 0;
}

/**
 *  __udp_lib_get_port  -  UDP/-Lite port lookup for IPv4 and IPv6
 *
 *  @sk:          socket struct in question
 *  @snum:        port number to look up
 *  @udptable:    hash list table, must be of UDP_HTABLE_SIZE
 *  @saddr_comp:  AF-dependent comparison of bound local IP addresses
 */
int __udp_lib_get_port(struct sock *sk, unsigned short snum,
		       struct hlist_head udptable[],
		       int (*saddr_comp)(const struct sock *sk1,
					 const struct sock *sk2 )    )
{
	struct hlist_node *node;
	struct hlist_head *head;
	struct sock *sk2;
	int    error = 1;

	write_lock_bh(&udp_hash_lock);

	if (!snum) {
		int i, low, high, remaining;
		unsigned rover, best, best_size_so_far;

		inet_get_local_port_range(&low, &high);
		remaining = (high - low) + 1;

		best_size_so_far = UINT_MAX;
		best = rover = net_random() % remaining + low;

		/* 1st pass: look for empty (or shortest) hash chain */
		for (i = 0; i < UDP_HTABLE_SIZE; i++) {
			int size = 0;

			head = &udptable[rover & (UDP_HTABLE_SIZE - 1)];
			if (hlist_empty(head))
				goto gotit;

			sk_for_each(sk2, node, head) {
				if (++size >= best_size_so_far)
					goto next;
			}
			best_size_so_far = size;
			best = rover;
		next:
			/* fold back if end of range */
			if (++rover > high)
				rover = low + ((rover - low)
					       & (UDP_HTABLE_SIZE - 1));


		}

		/* 2nd pass: find hole in shortest hash chain */
		rover = best;
		for (i = 0; i < (1 << 16) / UDP_HTABLE_SIZE; i++) {
			if (! __udp_lib_lport_inuse(rover, udptable))
				goto gotit;
			rover += UDP_HTABLE_SIZE;
			if (rover > high)
				rover = low + ((rover - low)
					       & (UDP_HTABLE_SIZE - 1));
		}


		/* All ports in use! */
		goto fail;

gotit:
		snum = rover;
	} else {
		head = &udptable[snum & (UDP_HTABLE_SIZE - 1)];

		sk_for_each(sk2, node, head)
			if (sk2->sk_hash == snum                             &&
			    sk2 != sk                                        &&
			    (!sk2->sk_reuse        || !sk->sk_reuse)         &&
			    (!sk2->sk_bound_dev_if || !sk->sk_bound_dev_if
			     || sk2->sk_bound_dev_if == sk->sk_bound_dev_if) &&
			    (*saddr_comp)(sk, sk2)                             )
				goto fail;
	}

	inet_sk(sk)->num = snum;
	sk->sk_hash = snum;
	if (sk_unhashed(sk)) {
		head = &udptable[snum & (UDP_HTABLE_SIZE - 1)];
		sk_add_node(sk, head);
		sock_prot_inc_use(sk->sk_prot);
	}
	error = 0;
fail:
	write_unlock_bh(&udp_hash_lock);
	return error;
}

int udp_get_port(struct sock *sk, unsigned short snum,
			int (*scmp)(const struct sock *, const struct sock *))
{
	return  __udp_lib_get_port(sk, snum, udp_hash, scmp);
}

int ipv4_rcv_saddr_equal(const struct sock *sk1, const struct sock *sk2)
{
	struct inet_sock *inet1 = inet_sk(sk1), *inet2 = inet_sk(sk2);

	return 	( !ipv6_only_sock(sk2)  &&
		  (!inet1->rcv_saddr || !inet2->rcv_saddr ||
		   inet1->rcv_saddr == inet2->rcv_saddr      ));
}

static inline int udp_v4_get_port(struct sock *sk, unsigned short snum)
{
	return udp_get_port(sk, snum, ipv4_rcv_saddr_equal);
}

/* UDP is nearly always wildcards out the wazoo, it makes no sense to try
 * harder than this. -DaveM
 *
 *  ip_rcv
 *   ip_rcv_finish
 *	  dst_input
 *	   ip_local_deliver
 *		ip_local_deliver_finish
 *       udp_rcv
 *        __udp4_lib_rcv    
 *         __udp4_lib_lookup()
 */
static struct sock *__udp4_lib_lookup(__be32 saddr, __be16 sport,
				      __be32 daddr, __be16 dport,
				      int dif, struct hlist_head udptable[])
{
	struct sock *sk, *result = NULL;
	struct hlist_node *node;
	unsigned short hnum = ntohs(dport);
	int badness = -1;

	read_lock(&udp_hash_lock);
	sk_for_each(sk, node, &udptable[hnum & (UDP_HTABLE_SIZE - 1)]) {
		
		struct inet_sock *inet = inet_sk(sk);

		if (sk->sk_hash == hnum && !ipv6_only_sock(sk)) {
			int score = (sk->sk_family == PF_INET ? 1 : 0);
			if (inet->rcv_saddr) {
				if (inet->rcv_saddr != daddr)
					continue;
				score+=2;
			}
			if (inet->daddr) {
				if (inet->daddr != saddr)
					continue;
				score+=2;
			}
			if (inet->dport) {
				if (inet->dport != sport)
					continue;
				score+=2;
			}
			if (sk->sk_bound_dev_if) {
				if (sk->sk_bound_dev_if != dif)
					continue;
				score+=2;
			}
			
			if (score == 9) { //找到
				result = sk;
				break;
			} else if (score > badness) {
				result = sk;
				badness = score;
			}
		}
	}
	if (result)
		sock_hold(result);
	read_unlock(&udp_hash_lock);
	return result;
}

static inline struct sock *udp_v4_mcast_next(struct sock *sk,
					     __be16 loc_port, __be32 loc_addr,
					     __be16 rmt_port, __be32 rmt_addr,
					     int dif)
{
	struct hlist_node *node;
	struct sock *s = sk;
	unsigned short hnum = ntohs(loc_port);

	sk_for_each_from(s, node) {
		struct inet_sock *inet = inet_sk(s);

		if (s->sk_hash != hnum					||
		    (inet->daddr && inet->daddr != rmt_addr)		||
		    (inet->dport != rmt_port && inet->dport)		||
		    (inet->rcv_saddr && inet->rcv_saddr != loc_addr)	||
		    ipv6_only_sock(s)					||
		    (s->sk_bound_dev_if && s->sk_bound_dev_if != dif))
			continue;
		if (!ip_mc_sf_allow(s, loc_addr, rmt_addr, dif))
			continue;
		goto found;
	}
	s = NULL;
found:
	return s;
}

/*
 * This routine is called by the ICMP module when it gets some
 * sort of error condition.  If err < 0 then the socket should
 * be closed and the error returned to the user.  If err > 0
 * it's just the icmp type << 8 | icmp code.
 * Header points to the ip header of the error packet. We move
 * on past this. Then (as it used to claim before adjustment)
 * header points to the first 8 bytes of the udp header.  We need
 * to find the appropriate port.
 */

void __udp4_lib_err(struct sk_buff *skb, u32 info, struct hlist_head udptable[])
{
	struct inet_sock *inet;
	struct iphdr *iph = (struct iphdr*)skb->data;
	struct udphdr *uh = (struct udphdr*)(skb->data+(iph->ihl<<2));
	const int type = icmp_hdr(skb)->type;
	const int code = icmp_hdr(skb)->code;
	struct sock *sk;
	int harderr;
	int err;

	sk = __udp4_lib_lookup(iph->daddr, uh->dest, iph->saddr, uh->source,
			       skb->dev->ifindex, udptable		    );
	if (sk == NULL) {
		ICMP_INC_STATS_BH(ICMP_MIB_INERRORS);
		return;	/* No socket for error */
	}

	err = 0;
	harderr = 0;
	inet = inet_sk(sk);

	switch (type) {
	default:
	case ICMP_TIME_EXCEEDED:
		err = EHOSTUNREACH;
		break;
	case ICMP_SOURCE_QUENCH:
		goto out;
	case ICMP_PARAMETERPROB:
		err = EPROTO;
		harderr = 1;
		break;
	case ICMP_DEST_UNREACH:
		if (code == ICMP_FRAG_NEEDED) { /* Path MTU discovery */
			if (inet->pmtudisc != IP_PMTUDISC_DONT) {
				err = EMSGSIZE;
				harderr = 1;
				break;
			}
			goto out;
		}
		err = EHOSTUNREACH;
		if (code <= NR_ICMP_UNREACH) {
			harderr = icmp_err_convert[code].fatal;
			err = icmp_err_convert[code].errno;
		}
		break;
	}

	/*
	 *      RFC1122: OK.  Passes ICMP errors back to application, as per
	 *	4.1.3.3.
	 */
	if (!inet->recverr) {
		if (!harderr || sk->sk_state != TCP_ESTABLISHED)
			goto out;
	} else {
		ip_icmp_error(sk, skb, err, uh->dest, info, (u8*)(uh+1));
	}
	sk->sk_err = err;
	sk->sk_error_report(sk);
out:
	sock_put(sk);
}

void udp_err(struct sk_buff *skb, u32 info)
{
	return __udp4_lib_err(skb, info, udp_hash);
}

/*
 * Throw away all pending data and cancel the corking. Socket is locked.
 */
static void udp_flush_pending_frames(struct sock *sk)
{
	struct udp_sock *up = udp_sk(sk);

	if (up->pending) {
		up->len = 0;
		up->pending = 0;
		ip_flush_pending_frames(sk);
	}
}

/**
 * 	udp4_hwcsum_outgoing  -  handle outgoing HW checksumming
 * 	@sk: 	socket we are sending on
 * 	@skb: 	sk_buff containing the filled-in UDP header
 * 	        (checksum field must be zeroed out)
 */
static void udp4_hwcsum_outgoing(struct sock *sk, struct sk_buff *skb,
				 __be32 src, __be32 dst, int len      )
{
	unsigned int offset;
	struct udphdr *uh = udp_hdr(skb);
	__wsum csum = 0;

	if (skb_queue_len(&sk->sk_write_queue) == 1) {
		/*
		 * Only one fragment on the socket.
		 */
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
		uh->check = ~csum_tcpudp_magic(src, dst, len, IPPROTO_UDP, 0);
	} else {
		/*
		 * HW-checksum won't work as there are two or more
		 * fragments on the socket so that all csums of sk_buffs
		 * should be together
		 */
		offset = skb_transport_offset(skb);
		skb->csum = skb_checksum(skb, offset, skb->len - offset, 0);

		skb->ip_summed = CHECKSUM_NONE;

		skb_queue_walk(&sk->sk_write_queue, skb) {
			csum = csum_add(csum, skb->csum);
		}

		uh->check = csum_tcpudp_magic(src, dst, len, IPPROTO_UDP, csum);
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;
	}
}

/*
 * Push out all pending data as one UDP datagram. Socket is locked.
 * 将待发送的数据打包成一个UDP数据报发送。
 *
 * udp_sendmsg()
 *  udp_push_pending_frames()
 *
 * udp_setsockopt()
 *  udp_lib_setsockopt( push_pending_frames==udp_push_pending_frames)
 *   udp_push_pending_frames()
 */
static int udp_push_pending_frames(struct sock *sk)
{
	struct udp_sock  *up = udp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct flowi *fl = &inet->cork.fl;
	struct sk_buff *skb;
	struct udphdr *uh;
	int err = 0;
	__wsum csum = 0;

	/* Grab the skbuff where UDP header space exists. */
	if ((skb = skb_peek(&sk->sk_write_queue)) == NULL)
		goto out;

	/*
	 * Create a UDP header
	 */
	uh = udp_hdr(skb);
	uh->source = fl->fl_ip_sport;
	uh->dest = fl->fl_ip_dport;
	uh->len = htons(up->len);
	uh->check = 0;

    // chekc sum 相关
	if (up->pcflag)  				 /*     UDP-Lite      */
		csum  = udplite_csum_outgoing(sk, skb);

	else if (sk->sk_no_check == UDP_CSUM_NOXMIT) {   /* UDP csum disabled */
    //不需要计算check sum值
		skb->ip_summed = CHECKSUM_NONE;
		goto send;

	} else if (skb->ip_summed == CHECKSUM_PARTIAL) { /* UDP hardware csum */

		udp4_hwcsum_outgoing(sk, skb, fl->fl4_src,fl->fl4_dst, up->len);
		goto send;

	} else						 /*   `normal' UDP    */
		csum = udp_csum_outgoing(sk, skb); //计算check sum值

	/* add protocol-dependent pseudo-header */
	uh->check = csum_tcpudp_magic(fl->fl4_src, fl->fl4_dst, up->len,
				      sk->sk_protocol, csum );
	if (uh->check == 0)
		uh->check = CSUM_MANGLED_0;

send:
    /*将组合后的skb发送出去，交由IP层处理*/
	err = ip_push_pending_frames(sk);
out:
	/*发送完成后清除pending标记，并向上层返回发送的字节数或者错误*/
	up->len = 0;
	up->pending = 0;
	if (!err)
		UDP_INC_STATS_USER(UDP_MIB_OUTDATAGRAMS, up->pcflag);
	return err;
}

/*
 * 用户态sendto/send(先调用connect建立连接)调用接口对应的UDP包发送的内核入口
 * @iocb: 异步控制块(尚未使用?)
 * @sk: sock描述符(传输控制块)
 * @msg: 描述发送数据的msghdr的指针
 * @len: 待发送数据的长度
 *
 *
 *
 * udp_sendpage()
 *  udp_sendmsg()
 * 
 *  sock_sendmsg()
 *   __sock_sendmsg()  ; socket->ops->sendmsg
 *    inet_sendmsg() 
 *     udp_sendmsg()
 *
 * sys_socketcall()
 *  sys_send()
 *   sys_sendto()
 *    sock_sendmsg()
 *     __sock_sendmsg() ; socket->ops->sendmsg
 *      inet_sendmsg()
 *       udp_sendmsg()
 */
int udp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t len)
{
    // 将sock结构转换为inet_sock结构
	struct inet_sock *inet = inet_sk(sk);
	// 将sock接口转换为udp_sock结构(UDP的传输控制块)
	struct udp_sock *up = udp_sk(sk);
	int ulen = len;
	struct ipcm_cookie ipc;
	struct rtable *rt = NULL;
	int free = 0;
	int connected = 0;
	__be32 daddr, faddr, saddr;
	__be16 dport;
	u8  tos;
	int err, is_udplite = up->pcflag;

	/*设置是否需要cork(阻塞)，通常由MSG_MORE标记控制,这个标志会传给ip_append_data */
	int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;
	/*用户从用户态拷贝实际数据的接口*/
	int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);

    /*数据长度不能超过64k*/
	if (len > 0xFFFF)
		return -EMSGSIZE;

	/*
	 *	Check the flags.
	 */

	if (msg->msg_flags&MSG_OOB)	/* Mirror BSD error message compatibility */
		return -EOPNOTSUPP;

	ipc.opt = NULL;

    /*
     * 当前的sock还有pending的帧(skb)没有发送到IP层，在设置了CORK标记的场景下才会设置这个标记
     */

	if (up->pending) {
		/* 
		 * There are pending frames.
		 * The socket lock must be held while it's corked.
		 */
		lock_sock(sk);
		
		if (likely(up->pending)) {
			/*pending既不是0，又不是AF_INET，那就是有问题了*/
			if (unlikely(up->pending != AF_INET)) {
				release_sock(sk);
				return -EINVAL;
			}
			/*利用当前sock发送队列中的原有的skb发送数据，将新数据附加到相应skb中的数据区即可*/
			goto do_append_data;
		}
		release_sock(sk);
	}
	/*UDP数据报长度累积，加上UDP头长度*/
	ulen += sizeof(struct udphdr);

	/*
	 *	Get and verify the address.
	 */
	/*判断msg中是否带了目的地址信息，如果有的话，则通常是由sendto调用进入*/
	if (msg->msg_name) {
		/*从msg中提取目的地址，并判断合法性*/
		struct sockaddr_in * usin = (struct sockaddr_in*)msg->msg_name;
		/*判断长度*/
		if (msg->msg_namelen < sizeof(*usin))
			return -EINVAL;
		
	    /*判断地址族，必须为AF_INET*/
		if (usin->sin_family != AF_INET) {
			if (usin->sin_family != AF_UNSPEC)
				return -EAFNOSUPPORT;
		}

        /*提取目的地址和端口信息*/
		daddr = usin->sin_addr.s_addr;
		dport = usin->sin_port;
		if (dport == 0)
			return -EINVAL;
	} else {
	    /*
         * 如果msg中不带目的地址信息，则通常是用send调用进入，在send之前调用了
         * connect建立连接，建立连接后相应状态为TCP_ESTABLISHED
         * 那么也会有地址信息，可以提取
         */
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;
		
		daddr = inet->daddr;
		dport = inet->dport;
		/* Open fast path for connected socket.
		   Route will not be used, if at least one option is set.
		 */
		 /*对于已连接的UDP套接口，设置connected标志，在后续查找路由时用，可以根据此做快速处理*/
		connected = 1;
	}
	ipc.addr = inet->saddr;

    //网卡号
	ipc.oif = sk->sk_bound_dev_if;
	
	/*处理待发送的控制信息，如果msg->msg_controllen不为0，则说明有控制信息需要处理*/
	if (msg->msg_controllen) {
		 /*处理控制信息，比如对IP选项的处理*/
		err = ip_cmsg_send(msg, &ipc);
		if (err)
			return err;
		/*如果ipc中存在IP选项，则设置free标记，表示需要在处理完成后释放。因为此时的ipc->opt肯定是在ip_cmsg_send中分配的*/
		if (ipc.opt)
			free = 1;
		connected = 0;
	}

	/*如果发送数据中的控制信息中没有IP选项信息，则从inet_sock结构中获取*/
	if (!ipc.opt)
		ipc.opt = inet->opt;

    /*由于控制信息需要保存目的地址，因此将源地址保存*/
	saddr = ipc.addr;
	ipc.addr = faddr = daddr;

    /*
     * 如果存在宽松或严格源站选路的IP选项，则不能根据目的地址选路，而需要将IP选项中
     * 下一站地址作为目的地址来选路，因此从IP选项中提取下一站地址，供后续选路时作为
     * 目的地址使用。另外，因为需要重新选路，所以清除connected标记
     */
	if (ipc.opt && ipc.opt->srr) {
		if (!daddr)
			return -EINVAL;
		faddr = ipc.opt->faddr;//下一站的ip地址
		connected = 0;
	}
	
	tos = RT_TOS(inet->tos);
    /*
     * 如果设置了SOCK_LOCALROUTE或者发送时设置了MSG_DONTROUTE标记，再或者IP选项中存在严格源站选路
     * 选项，则说明目的地址或下一跳必然位于本地子网中。此时需要设置tos中的RTO_ONLINK标记，表示
     * 后续查找路由时与目的地直连。
     */	
	if (sock_flag(sk, SOCK_LOCALROUTE) ||
	    (msg->msg_flags & MSG_DONTROUTE) ||
	    (ipc.opt && ipc.opt->is_strictroute)) {
		tos |= RTO_ONLINK;
		connected = 0;
	}

	/*广播相关处理*/
	if (MULTICAST(daddr)) {
		if (!ipc.oif)
			ipc.oif = inet->mc_index;
		
		if (!saddr)
			saddr = inet->mc_addr;
		connected = 0;
	}


	/*
	 * 如果已经建立了链接了，就可以直接从sk-sk_dst_cache中得到路由
	 * 选路相关处理，获取相应的路由缓存项
	 */
	if (connected)
		rt = (struct rtable*)sk_dst_check(sk, 0);

    //上一步没有得到路由项，需要从路由缓存或者路由表中查找路由
	if (rt == NULL) {
		struct flowi fl = { .oif = ipc.oif,
				    .nl_u = { .ip4_u =
					      { .daddr = faddr,
						.saddr = saddr,
						.tos = tos } },
				    .proto = sk->sk_protocol,
				    .uli_u = { .ports =
					       { .sport = inet->sport,
						 .dport = dport } } };
		security_sk_classify_flow(sk, &fl);
		//查找路由信息，存到rt中
		err = ip_route_output_flow(&rt, &fl, sk, 1);
		if (err) {
			if (err == -ENETUNREACH)
				IP_INC_STATS_BH(IPSTATS_MIB_OUTNOROUTES);
			goto out;
		}

		err = -EACCES;
		if ((rt->rt_flags & RTCF_BROADCAST) &&
		    !sock_flag(sk, SOCK_BROADCAST))
			goto out;

		//将dst信息缓存到sk->sk_dst_cache中去
		if (connected)
			sk_dst_set(sk, dst_clone(&rt->u.dst));
	}


    /*如果设置了MSG_CONFIRM标记，表明应用层确认网关有效并可达，则直接跳转到do_confirm对目的路由缓存项进行确认*/
	if (msg->msg_flags&MSG_CONFIRM)
		goto do_confirm;
back_from_confirm:


    /*
     * 从获取到的路由中获取源地址和目的地址。在发送UDP数据时其实可以不指定目的地址，而在通过在发送控制信
     * 息中加入严格或宽松源站选路选项，所以如此此时还没有获取目的地址，则需从路由缓存项中获取
     */
	saddr = rt->rt_src;
	if (!ipc.addr)
		daddr = ipc.addr = rt->rt_dst;

    /*要往skb中添加数据了并访问sock中的相关数据了，此时需要加锁了，因为同一个socket可能被多个进程在多个CPU上同时访问*/
	lock_sock(sk);
	if (unlikely(up->pending)) {
		/* The socket is already corked while preparing it. */
		/* ... which is an evident application bug. --ANK */

        /* 运行到这里说明，设置了cork，而在进入此函数的开始时已经检测过pending了，pending为空时才会走到这里，
         * 而这里再次检查时，pending又有了，此时说明有多个进程在同时使用socket，其它核上的流程进行了相关修改，此时认定为
         * 应用程序的bug。而实际上如果对访问pending时进行加锁保护，也不会有问题，但是这个pending不太好加锁，因为外面也在
         * 访问比如udp_sendpage中，此时很容易死锁。所以，无奈之下，这里进行了这样的判断，认定为是app bug。
         */		
		release_sock(sk);

		LIMIT_NETDEBUG(KERN_DEBUG "udp cork app bug 2\n");
		err = -EINVAL;
		goto out;
	}
	/*
	 *	Now cork the socket to pend data.
	 */
	/*缓存目的地址、目的端口、源地址和源端口信息，便于在发送处理时方便获取信息。*/ 
	inet->cork.fl.fl4_dst = daddr;
	inet->cork.fl.fl_ip_dport = dport;
	inet->cork.fl.fl4_src = saddr;
	inet->cork.fl.fl_ip_sport = inet->sport;
	up->pending = AF_INET;

	/*
	  * 运行到这里，有两种情况:1.最初进入函数时pending=AF_INET，即有udp数据包正在处理中；2.设置了cork，
	  * 则表明需要阻塞，使用原有的skb一起发送数据.
	  */
do_append_data:
	/*增加包长*/
	up->len += ulen;

  
    /*
     * 根据is_udplite标志来指定"从用户态复制数据到UDP分片"的函数，UDP和轻量级UDP的实现共用了一套函数，
     * 只是在计算校验和上有点区别。轻量级UDP可以在发送前(而不是在复制数据到分片中时)对数据前部
     * 指定数目的字节或全部数据执行校验和。而UDP如果是由软件执行校验和(当网卡硬件支持udp checksum offload
     * 并开启相关功能后，校验和由硬件执行)，则在复制数据到分片中时对数据包中的全部数据执行校验和。
     * 所以，轻量级UDP和UDP使用不同的"getfrag"函数。
     */	
	getfrag  =  is_udplite ?  udplite_getfrag : ip_generic_getfrag;

    /* 
     * 对UDP数据包进行分片处理，为ip层的分片处理做好准备
     *
     * 调用IP层接口函数ip_append_data，进入IP层处理，主要工作为:
     * 将数据拷贝到适合的skb(利用发送队列中现有的或新创建)中，可能有两种情况: 1. 放入skb的线性
     * 区(skb->data)中，或者放入skb_shared_info的分片(frag)中，同时还需要考虑MTU对skb数据进行分割。
     */	
	err = ip_append_data(sk, getfrag, msg->msg_iov, ulen,
			sizeof(struct udphdr), &ipc, rt,
			corkreq ? msg->msg_flags|MSG_MORE /* 如果有MSG_MORE，是不是意味这udp可以将多次发送合并成一次了？ */ : msg->msg_flags);

			
	if (err)
		/*出错则清空所有pending的数据帧，并清空pending标记*/
		udp_flush_pending_frames(sk);
	else if (!corkreq) 
		/*未设置cork(如果设置了cork，则需要等待组成64k大小的UDP数据报后再发送)，则直接发送数据到IP层*/
		err = udp_push_pending_frames(sk);
	else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
		/*如果发送队列为空，则说明没有数据正在处理了，则复位pending标记*/
		up->pending = 0;
	
	release_sock(sk);

out:
	/*发送完成，不再需要路由信息，因此递减对路由的引用计数*/
	ip_rt_put(rt);
	/*之前设置的free标记，用于是否释放IP选项*/
	if (free)
		kfree(ipc.opt);
	/*如果发送成功，则返回发送数据的字节数*/
	if (!err)
		return len;
	/*
	 * ENOBUFS = no kernel mem, SOCK_NOSPACE = no sndbuf space.  Reporting
	 * ENOBUFS might not be good (it's not tunable per se), but otherwise
	 * we don't have a good statistic (IpOutDiscards but it can be too many
	 * things).  We could add another new stat but at least for now that
	 * seems like overkill.
	 */
	 /*如果发送失败，则返回相应的错误码。*/
	if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		UDP_INC_STATS_USER(UDP_MIB_SNDBUFERRORS, is_udplite);
	}
	return err;

/*发送时设置了MSG_CONFIRM标记时，跳转到这里*/
do_confirm:
    /*应用层确认网关可达，因此直接对目的路由缓存项进行确认。*/
	dst_confirm(&rt->u.dst);
    /*
     * MSG_PROBE标志用于发现路径，并非真正发送数据。因此此处检查此标记，如果设置，
     * 这直接跳转到out，退出;如果未设置，且有需要发送的数据，则跳回到back_from_confirm
     * 处理相关数据。
     */	
	if (!(msg->msg_flags&MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto out;
}

int udp_sendpage(struct sock *sk, struct page *page, int offset,
		 size_t size, int flags)
{
	struct udp_sock *up = udp_sk(sk);
	int ret;

	if (!up->pending) {
		struct msghdr msg = {	.msg_flags = flags|MSG_MORE };

		/* Call udp_sendmsg to specify destination address which
		 * sendpage interface can't pass.
		 * This will succeed only when the socket is connected.
		 */
		ret = udp_sendmsg(NULL, sk, &msg, 0);
		if (ret < 0)
			return ret;
	}

	lock_sock(sk);

	if (unlikely(!up->pending)) {
		release_sock(sk);

		LIMIT_NETDEBUG(KERN_DEBUG "udp cork app bug 3\n");
		return -EINVAL;
	}

	ret = ip_append_page(sk, page, offset, size, flags);
	if (ret == -EOPNOTSUPP) {
		release_sock(sk);
		return sock_no_sendpage(sk->sk_socket, page, offset,
					size, flags);
	}
	if (ret < 0) {
		udp_flush_pending_frames(sk);
		goto out;
	}

	up->len += size;
	if (!(up->corkflag || (flags&MSG_MORE)))
		ret = udp_push_pending_frames(sk);
	if (!ret)
		ret = size;
out:
	release_sock(sk);
	return ret;
}

/*
 *	IOCTL requests applicable to the UDP protocol
 */

int udp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	switch (cmd) {
	case SIOCOUTQ:
	{
		int amount = atomic_read(&sk->sk_wmem_alloc);
		return put_user(amount, (int __user *)arg);
	}

	case SIOCINQ:
	{
		struct sk_buff *skb;
		unsigned long amount;

		amount = 0;
		spin_lock_bh(&sk->sk_receive_queue.lock);
		skb = skb_peek(&sk->sk_receive_queue);
		if (skb != NULL) {
			/*
			 * We will only return the amount
			 * of this packet since that is all
			 * that will be read.
			 */
			amount = skb->len - sizeof(struct udphdr);
		}
		spin_unlock_bh(&sk->sk_receive_queue.lock);
		return put_user(amount, (int __user *)arg);
	}

	default:
		return -ENOIOCTLCMD;
	}

	return 0;
}

/*
 * 	This should be easy, if there is something there we
 * 	return it, otherwise we block.
 *
 * sys_read()
 *	vfs_read()
 *	 do_sync_read()
 *	  sock_aio_read()
 *	   do_sock_read()
 *      __sock_recvmsg()
 *       sock_common_recvmsg()
 *        udp_recvmsg()
 */

int udp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t len, int noblock, int flags, int *addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sockaddr_in *sin = (struct sockaddr_in *)msg->msg_name;
	struct sk_buff *skb;
	unsigned int ulen, copied;
	int err;
	int is_udplite = IS_UDPLITE(sk);

	/*
	 *	Check any passed addresses
	 */
	if (addr_len)
		*addr_len=sizeof(*sin);

	if (flags & MSG_ERRQUEUE)
		return ip_recv_error(sk, msg, len);

try_again:
    //从套接字sk的接收队列中取出套接字缓冲区skb
	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb)
		goto out;

    //不需要udp头部
	ulen = skb->len - sizeof(struct udphdr);
	
	copied = len;
	if (copied > ulen)
		copied = ulen;
	else if (copied < ulen)
		msg->msg_flags |= MSG_TRUNC;

	/*
	 * If checksum is needed at all, try to do it while copying the
	 * data.  If the data is truncated, or if we only want a partial
	 * coverage checksum (UDP-Lite), do it before the copy.
	 */

	if (copied < ulen || UDP_SKB_CB(skb)->partial_cov) {
		if (udp_lib_checksum_complete(skb))
			goto csum_copy_err;
	}

    //复制数据到msg->msg_iov
	if (skb_csum_unnecessary(skb)) 
		err = skb_copy_datagram_iovec(skb, sizeof(struct udphdr),
					      msg->msg_iov, copied       );
	else { //复制数据到msg->msg_iov中，并且进行校验
		err = skb_copy_and_csum_datagram_iovec(skb, sizeof(struct udphdr), msg->msg_iov);

		if (err == -EINVAL)
			goto csum_copy_err;
	}

	if (err)
		goto out_free;

    //记录接收的时间
	sock_recv_timestamp(msg, sk, skb);

	/* Copy the address. 
	 * 复制地址信息
	 */
	if (sin)
	{
		sin->sin_family = AF_INET;
		sin->sin_port = udp_hdr(skb)->source;
		sin->sin_addr.s_addr = ip_hdr(skb)->saddr;
		memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
	}
	if (inet->cmsg_flags)
		ip_cmsg_recv(msg, skb);

	err = copied;
	if (flags & MSG_TRUNC)
		err = ulen;

out_free:
	skb_free_datagram(sk, skb);
out:
	return err;

csum_copy_err:
	UDP_INC_STATS_BH(UDP_MIB_INERRORS, is_udplite);

	skb_kill_datagram(sk, skb, flags);

	if (noblock)
		return -EAGAIN;
	goto try_again;
}


int udp_disconnect(struct sock *sk, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	/*
	 *	1003.1g - break association.
	 */

	sk->sk_state = TCP_CLOSE;
	inet->daddr = 0;
	inet->dport = 0;
	sk->sk_bound_dev_if = 0;
	if (!(sk->sk_userlocks & SOCK_BINDADDR_LOCK))
		inet_reset_saddr(sk);

	if (!(sk->sk_userlocks & SOCK_BINDPORT_LOCK)) {
		sk->sk_prot->unhash(sk);
		inet->sport = 0;
	}
	sk_dst_reset(sk);
	return 0;
}

/* returns:
 *  -1: error
 *   0: success
 *  >0: "udp encap" protocol resubmission
 *
 * Note that in the success and error cases, the skb is assumed to
 * have either been requeued or freed.
 *
 * 将skb插入到sk_receive_queue上,唤醒等待sk_sleep上的进程
 *
 * ip_rcv
 *  ip_rcv_finish
 *   dst_input
 *    ip_local_deliver
 *     ip_local_deliver_finish
 *      udp_rcv
 *       __udp4_lib_rcv   
 *        udp_queue_rcv_skb()
 */
int udp_queue_rcv_skb(struct sock * sk, struct sk_buff *skb)
{
	struct udp_sock *up = udp_sk(sk);
	int rc;

	/*
	 *	Charge it to the socket, dropping if the queue is full.
	 */
	if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
		goto drop;
	nf_reset(skb);

	if (up->encap_type) { 
		/*
		 * 判断和这个数据报关联的socket是不是 encapsulation socket。如果是，将packet 送到该层的处理函数
		 *
		 * This is an encapsulation socket so pass the skb to
		 * the socket's udp_encap_rcv() hook. Otherwise, just
		 * fall through and pass this up the UDP socket.
		 * up->encap_rcv() returns the following value:
		 * =0 if skb was successfully passed to the encap
		 *    handler or was discarded by it.
		 * >0 if skb should be passed on to UDP.
		 * <0 if skb should be resubmitted as proto -N
		 */

		/* if we're overly short, let UDP handle it */
		if (skb->len > sizeof(struct udphdr) &&
		    up->encap_rcv != NULL) {
			int ret;

			ret = (*up->encap_rcv)(sk, skb);
			if (ret <= 0) {
				UDP_INC_STATS_BH(UDP_MIB_INDATAGRAMS, up->pcflag);
				return -ret;
			}
		}

		/* FALLTHROUGH -- it's a UDP Packet */
	}

	/*
	 * 	UDP-Lite specific tests, ignored on UDP sockets
	 *  判断这个数据报是不是UDP-Lite数据报，做一些完整性检测
	 */
	if ((up->pcflag & UDPLITE_RECV_CC)  &&  UDP_SKB_CB(skb)->partial_cov) {

		/*
		 * MIB statistics other than incrementing the error count are
		 * disabled for the following two types of errors: these depend
		 * on the application settings, not on the functioning of the
		 * protocol stack as such.
		 *
		 * RFC 3828 here recommends (sec 3.3): "There should also be a
		 * way ... to ... at least let the receiving application block
		 * delivery of packets with coverage values less than a value
		 * provided by the application."
		 */
		if (up->pcrlen == 0) {          /* full coverage was set  */
			LIMIT_NETDEBUG(KERN_WARNING "UDPLITE: partial coverage "
				"%d while full coverage %d requested\n",
				UDP_SKB_CB(skb)->cscov, skb->len);
			goto drop;
		}
		/* The next case involves violating the min. coverage requested
		 * by the receiver. This is subtle: if receiver wants x and x is
		 * greater than the buffersize/MTU then receiver will complain
		 * that it wants x while sender emits packets of smaller size y.
		 * Therefore the above ...()->partial_cov statement is essential.
		 */
		if (UDP_SKB_CB(skb)->cscov  <  up->pcrlen) {
			LIMIT_NETDEBUG(KERN_WARNING
				"UDPLITE: coverage %d too small, need min %d\n",
				UDP_SKB_CB(skb)->cscov, up->pcrlen);
			goto drop;
		}
	}

	if (sk->sk_filter) {
		if (udp_lib_checksum_complete(skb))
			goto drop;
	}

	/* 插入skb到sk->sk_receive_queue上 */
	if ((rc = sock_queue_rcv_skb(sk,skb)) < 0) {
		/* Note that an ENOMEM error is charged twice */
		if (rc == -ENOMEM)
			UDP_INC_STATS_BH(UDP_MIB_RCVBUFERRORS, up->pcflag);
		goto drop;
	}

	UDP_INC_STATS_BH(UDP_MIB_INDATAGRAMS, up->pcflag);
	return 0;

drop:
	UDP_INC_STATS_BH(UDP_MIB_INERRORS, up->pcflag);
	kfree_skb(skb);
	return -1;
}

/*
 *	Multicasts and broadcasts go to each listener.
 *
 *	Note: called only from the BH handler context,
 *	so we don't need to lock the hashes.
 */
static int __udp4_lib_mcast_deliver(struct sk_buff *skb,
				    struct udphdr  *uh,
				    __be32 saddr, __be32 daddr,
				    struct hlist_head udptable[])
{
	struct sock *sk;
	int dif;

	read_lock(&udp_hash_lock);
	sk = sk_head(&udptable[ntohs(uh->dest) & (UDP_HTABLE_SIZE - 1)]);
	dif = skb->dev->ifindex;
	sk = udp_v4_mcast_next(sk, uh->dest, daddr, uh->source, saddr, dif);
	if (sk) {
		struct sock *sknext = NULL;

		do {
			struct sk_buff *skb1 = skb;

			sknext = udp_v4_mcast_next(sk_next(sk), uh->dest, daddr,
						   uh->source, saddr, dif);
			if (sknext)
				skb1 = skb_clone(skb, GFP_ATOMIC);

			if (skb1) {
				int ret = udp_queue_rcv_skb(sk, skb1);
				if (ret > 0)
					/* we should probably re-process instead
					 * of dropping packets here. */
					kfree_skb(skb1);
			}
			sk = sknext;
		} while (sknext);
	} else
		kfree_skb(skb);
	read_unlock(&udp_hash_lock);
	return 0;
}

/* Initialize UDP checksum. If exited with zero value (success),
 * CHECKSUM_UNNECESSARY means, that no more checks are required.
 * Otherwise, csum completion requires chacksumming packet body,
 * including udp header and folding it to skb->csum.
 */
static inline int udp4_csum_init(struct sk_buff *skb, struct udphdr *uh,
				 int proto)
{
	const struct iphdr *iph;
	int err;

	UDP_SKB_CB(skb)->partial_cov = 0;
	UDP_SKB_CB(skb)->cscov = skb->len;

	if (proto == IPPROTO_UDPLITE) {
		err = udplite_checksum_init(skb, uh);
		if (err)
			return err;
	}

	iph = ip_hdr(skb);
	if (uh->check == 0) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	} else if (skb->ip_summed == CHECKSUM_COMPLETE) {
	       if (!csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len,
				      proto, skb->csum))
			skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
	if (!skb_csum_unnecessary(skb))
		skb->csum = csum_tcpudp_nofold(iph->saddr, iph->daddr,
					       skb->len, proto, 0);
	/* Probably, we should checksum udp header (it should be in cache
	 * in any case) and data in tiny packets (< rx copybreak).
	 */

	return 0;
}

/*
 * All we need to do is get the socket, and then do a checksum.
 *
 * ip_rcv
 *  ip_rcv_finish
 *   dst_input
 *    ip_local_deliver
 *	   ip_local_deliver_finish
 *      udp_rcv
 *       __udp4_lib_rcv    
 */

int __udp4_lib_rcv(struct sk_buff *skb, struct hlist_head udptable[],
		   int proto)
{
	struct sock *sk;
	struct udphdr *uh = udp_hdr(skb);
	unsigned short ulen;
	struct rtable *rt = (struct rtable*)skb->dst;
	__be32 saddr = ip_hdr(skb)->saddr;
	__be32 daddr = ip_hdr(skb)->daddr;

	/*
	 *  Validate the packet.
	 * 判断skb是否中是否存在一个UDP头部长度的存储区
	 */
	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
		goto drop;		/* No space for header. */

	ulen = ntohs(uh->len);
	if (ulen > skb->len)
		goto short_packet;

	if (proto == IPPROTO_UDP) {
		/* UDP validates ulen. */
		if (ulen < sizeof(*uh) || pskb_trim_rcsum(skb, ulen))
			goto short_packet;
		uh = udp_hdr(skb);
	}

	if (udp4_csum_init(skb, uh, proto))
		goto csum_error;

    /*  到这里前面的代码都是检查各种合法性 */

	if (rt->rt_flags & (RTCF_BROADCAST|RTCF_MULTICAST))
		return __udp4_lib_mcast_deliver(skb, uh, saddr, daddr, udptable);

	/* 在udptable中查找监听的socket */
	sk = __udp4_lib_lookup(saddr, uh->source, daddr, uh->dest,
			       inet_iif(skb), udptable);

	if (sk != NULL) {
		/* 找到sock对象,将skb插入到sk_receive_queue上,唤醒等待sk_sleep上的进程 */
		int ret = udp_queue_rcv_skb(sk, skb);
		sock_put(sk);

		/* a return value > 0 means to resubmit the input, but
		 * it wants the return to be -protocol, or 0
		 */
		if (ret > 0)
			return -ret;
		return 0;
	}

	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
		goto drop;
	nf_reset(skb);

	/* No socket. Drop packet silently, if checksum is wrong */
	if (udp_lib_checksum_complete(skb))
		goto csum_error;

	UDP_INC_STATS_BH(UDP_MIB_NOPORTS, proto == IPPROTO_UDPLITE);

	/*
	 * 没有找到sock对象，就向反方向发送ICMP_DEST_UNREACH,ICMP_PORT_UNREACH的 icmp信息
	 */
	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

	/*
	 * Hmm.  We got an UDP packet to a port to which we
	 * don't wanna listen.  Ignore it.
	 */
	kfree_skb(skb);
	return 0;

short_packet:
	LIMIT_NETDEBUG(KERN_DEBUG "UDP%s: short packet: From %u.%u.%u.%u:%u %d/%d to %u.%u.%u.%u:%u\n",
		       proto == IPPROTO_UDPLITE ? "-Lite" : "",
		       NIPQUAD(saddr),
		       ntohs(uh->source),
		       ulen,
		       skb->len,
		       NIPQUAD(daddr),
		       ntohs(uh->dest));
	goto drop;

csum_error:
	/*
	 * RFC1122: OK.  Discards the bad packet silently (as far as
	 * the network is concerned, anyway) as per 4.1.3.4 (MUST).
	 */
	LIMIT_NETDEBUG(KERN_DEBUG "UDP%s: bad checksum. From %d.%d.%d.%d:%d to %d.%d.%d.%d:%d ulen %d\n",
		       proto == IPPROTO_UDPLITE ? "-Lite" : "",
		       NIPQUAD(saddr),
		       ntohs(uh->source),
		       NIPQUAD(daddr),
		       ntohs(uh->dest),
		       ulen);
drop:
	UDP_INC_STATS_BH(UDP_MIB_INERRORS, proto == IPPROTO_UDPLITE);
	kfree_skb(skb);
	return 0;
}

/*
 * ip_rcv
 *  ip_rcv_finish
 *   dst_input
 *    ip_local_deliver
 *	   ip_local_deliver_finish
 *      udp_rcv
 */

int udp_rcv(struct sk_buff *skb)
{
	return __udp4_lib_rcv(skb, udp_hash, IPPROTO_UDP);
}

int udp_destroy_sock(struct sock *sk)
{
	lock_sock(sk);
	udp_flush_pending_frames(sk);
	release_sock(sk);
	return 0;
}

/*
 *	Socket option code for UDP
 *
 * udp_setsockopt()
 *  udp_lib_setsockopt( push_pending_frames==udp_push_pending_frames)
 */
int udp_lib_setsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, int optlen,
		       int (*push_pending_frames)(struct sock *))
{
	struct udp_sock *up = udp_sk(sk);
	int val;
	int err = 0;

	if (optlen<sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	switch (optname) {
	case UDP_CORK:
		if (val != 0) {
			up->corkflag = 1;
		} else {
			up->corkflag = 0;
			lock_sock(sk);
			(*push_pending_frames)(sk);
			release_sock(sk);
		}
		break;

	case UDP_ENCAP:
		switch (val) {
		case 0:
		case UDP_ENCAP_ESPINUDP:
		case UDP_ENCAP_ESPINUDP_NON_IKE:
			up->encap_rcv = xfrm4_udp_encap_rcv;
			/* FALLTHROUGH */
		case UDP_ENCAP_L2TPINUDP:
			up->encap_type = val;
			break;
		default:
			err = -ENOPROTOOPT;
			break;
		}
		break;

	/*
	 * 	UDP-Lite's partial checksum coverage (RFC 3828).
	 */
	/* The sender sets actual checksum coverage length via this option.
	 * The case coverage > packet length is handled by send module. */
	case UDPLITE_SEND_CSCOV:
		if (!up->pcflag)         /* Disable the option on UDP sockets */
			return -ENOPROTOOPT;
		if (val != 0 && val < 8) /* Illegal coverage: use default (8) */
			val = 8;
		up->pcslen = val;
		up->pcflag |= UDPLITE_SEND_CC;
		break;

	/* The receiver specifies a minimum checksum coverage value. To make
	 * sense, this should be set to at least 8 (as done below). If zero is
	 * used, this again means full checksum coverage.                     */
	case UDPLITE_RECV_CSCOV:
		if (!up->pcflag)         /* Disable the option on UDP sockets */
			return -ENOPROTOOPT;
		if (val != 0 && val < 8) /* Avoid silly minimal values.       */
			val = 8;
		up->pcrlen = val;
		up->pcflag |= UDPLITE_RECV_CC;
		break;

	default:
		err = -ENOPROTOOPT;
		break;
	}

	return err;
}

int udp_setsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, int optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_setsockopt(sk, level, optname, optval, optlen,
					  udp_push_pending_frames);
	
	return ip_setsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_udp_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_setsockopt(sk, level, optname, optval, optlen,
					  udp_push_pending_frames);
	return compat_ip_setsockopt(sk, level, optname, optval, optlen);
}
#endif

int udp_lib_getsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, int __user *optlen)
{
	struct udp_sock *up = udp_sk(sk);
	int val, len;

	if (get_user(len,optlen))
		return -EFAULT;

	len = min_t(unsigned int, len, sizeof(int));

	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case UDP_CORK:
		val = up->corkflag;
		break;

	case UDP_ENCAP:
		val = up->encap_type;
		break;

	/* The following two cannot be changed on UDP sockets, the return is
	 * always 0 (which corresponds to the full checksum coverage of UDP). */
	case UDPLITE_SEND_CSCOV:
		val = up->pcslen;
		break;

	case UDPLITE_RECV_CSCOV:
		val = up->pcrlen;
		break;

	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val,len))
		return -EFAULT;
	return 0;
}

int udp_getsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, int __user *optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_getsockopt(sk, level, optname, optval, optlen);
	return ip_getsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_udp_getsockopt(struct sock *sk, int level, int optname,
				 char __user *optval, int __user *optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_getsockopt(sk, level, optname, optval, optlen);
	return compat_ip_getsockopt(sk, level, optname, optval, optlen);
}
#endif
/**
 * 	udp_poll - wait for a UDP event.
 *	@file - file struct
 *	@sock - socket
 *	@wait - poll table
 *
 *	This is same as datagram poll, except for the special case of
 *	blocking sockets. If application is using a blocking fd
 *	and a packet with checksum error is in the queue;
 *	then it could get return from select indicating data available
 *	but then block when reading it. Add special case code
 *	to work around these arguably broken applications.
 */
unsigned int udp_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	unsigned int mask = datagram_poll(file, sock, wait);
	struct sock *sk = sock->sk;
	int 	is_lite = IS_UDPLITE(sk);

	/* Check for false positives due to checksum errors */
	if ( (mask & POLLRDNORM) &&
	     !(file->f_flags & O_NONBLOCK) &&
	     !(sk->sk_shutdown & RCV_SHUTDOWN)){
		struct sk_buff_head *rcvq = &sk->sk_receive_queue;
		struct sk_buff *skb;

		spin_lock_bh(&rcvq->lock);
		while ((skb = skb_peek(rcvq)) != NULL &&
		       udp_lib_checksum_complete(skb)) {
			UDP_INC_STATS_BH(UDP_MIB_INERRORS, is_lite);
			__skb_unlink(skb, rcvq);
			kfree_skb(skb);
		}
		spin_unlock_bh(&rcvq->lock);

		/* nothing to see, move along */
		if (skb == NULL)
			mask &= ~(POLLIN | POLLRDNORM);
	}

	return mask;

}

DEFINE_PROTO_INUSE(udp)

struct proto udp_prot = {
	.name		   = "UDP",
	.owner		   = THIS_MODULE,
	.close		   = udp_lib_close,
	.connect	   = ip4_datagram_connect,
	.disconnect	   = udp_disconnect,
	.ioctl		   = udp_ioctl,
	.destroy	   = udp_destroy_sock,
	.setsockopt	   = udp_setsockopt,
	.getsockopt	   = udp_getsockopt,
	.sendmsg	   = udp_sendmsg,
	.recvmsg	   = udp_recvmsg,
	.sendpage	   = udp_sendpage,
	.backlog_rcv	   = udp_queue_rcv_skb,
	.hash		   = udp_lib_hash,
	.unhash		   = udp_lib_unhash,
	.get_port	   = udp_v4_get_port,
	.obj_size	   = sizeof(struct udp_sock),
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_udp_setsockopt,
	.compat_getsockopt = compat_udp_getsockopt,
#endif
	REF_PROTO_INUSE(udp)
};

/* ------------------------------------------------------------------------ */
#ifdef CONFIG_PROC_FS

static struct sock *udp_get_first(struct seq_file *seq)
{
	struct sock *sk;
	struct udp_iter_state *state = seq->private;

	for (state->bucket = 0; state->bucket < UDP_HTABLE_SIZE; ++state->bucket) {
		struct hlist_node *node;
		sk_for_each(sk, node, state->hashtable + state->bucket) {
			if (sk->sk_family == state->family)
				goto found;
		}
	}
	sk = NULL;
found:
	return sk;
}

static struct sock *udp_get_next(struct seq_file *seq, struct sock *sk)
{
	struct udp_iter_state *state = seq->private;

	do {
		sk = sk_next(sk);
try_again:
		;
	} while (sk && sk->sk_family != state->family);

	if (!sk && ++state->bucket < UDP_HTABLE_SIZE) {
		sk = sk_head(state->hashtable + state->bucket);
		goto try_again;
	}
	return sk;
}

static struct sock *udp_get_idx(struct seq_file *seq, loff_t pos)
{
	struct sock *sk = udp_get_first(seq);

	if (sk)
		while (pos && (sk = udp_get_next(seq, sk)) != NULL)
			--pos;
	return pos ? NULL : sk;
}

static void *udp_seq_start(struct seq_file *seq, loff_t *pos)
{
	read_lock(&udp_hash_lock);
	return *pos ? udp_get_idx(seq, *pos-1) : (void *)1;
}

static void *udp_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct sock *sk;

	if (v == (void *)1)
		sk = udp_get_idx(seq, 0);
	else
		sk = udp_get_next(seq, v);

	++*pos;
	return sk;
}

static void udp_seq_stop(struct seq_file *seq, void *v)
{
	read_unlock(&udp_hash_lock);
}

static int udp_seq_open(struct inode *inode, struct file *file)
{
	struct udp_seq_afinfo *afinfo = PDE(inode)->data;
	struct seq_file *seq;
	int rc = -ENOMEM;
	struct udp_iter_state *s = kzalloc(sizeof(*s), GFP_KERNEL);

	if (!s)
		goto out;
	s->family		= afinfo->family;
	s->hashtable		= afinfo->hashtable;
	s->seq_ops.start	= udp_seq_start;
	s->seq_ops.next		= udp_seq_next;
	s->seq_ops.show		= afinfo->seq_show;
	s->seq_ops.stop		= udp_seq_stop;

	rc = seq_open(file, &s->seq_ops);
	if (rc)
		goto out_kfree;

	seq	     = file->private_data;
	seq->private = s;
out:
	return rc;
out_kfree:
	kfree(s);
	goto out;
}

/* ------------------------------------------------------------------------ */
int udp_proc_register(struct udp_seq_afinfo *afinfo)
{
	struct proc_dir_entry *p;
	int rc = 0;

	if (!afinfo)
		return -EINVAL;
	afinfo->seq_fops->owner		= afinfo->owner;
	afinfo->seq_fops->open		= udp_seq_open;
	afinfo->seq_fops->read		= seq_read;
	afinfo->seq_fops->llseek	= seq_lseek;
	afinfo->seq_fops->release	= seq_release_private;

	p = proc_net_fops_create(&init_net, afinfo->name, S_IRUGO, afinfo->seq_fops);
	if (p)
		p->data = afinfo;
	else
		rc = -ENOMEM;
	return rc;
}

void udp_proc_unregister(struct udp_seq_afinfo *afinfo)
{
	if (!afinfo)
		return;
	proc_net_remove(&init_net, afinfo->name);
	memset(afinfo->seq_fops, 0, sizeof(*afinfo->seq_fops));
}

/* ------------------------------------------------------------------------ */
static void udp4_format_sock(struct sock *sp, char *tmpbuf, int bucket)
{
	struct inet_sock *inet = inet_sk(sp);
	__be32 dest = inet->daddr;
	__be32 src  = inet->rcv_saddr;
	__u16 destp	  = ntohs(inet->dport);
	__u16 srcp	  = ntohs(inet->sport);

	sprintf(tmpbuf, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %lu %d %p",
		bucket, src, srcp, dest, destp, sp->sk_state,
		atomic_read(&sp->sk_wmem_alloc),
		atomic_read(&sp->sk_rmem_alloc),
		0, 0L, 0, sock_i_uid(sp), 0, sock_i_ino(sp),
		atomic_read(&sp->sk_refcnt), sp);
}

int udp4_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_printf(seq, "%-127s\n",
			   "  sl  local_address rem_address   st tx_queue "
			   "rx_queue tr tm->when retrnsmt   uid  timeout "
			   "inode");
	else {
		char tmpbuf[129];
		struct udp_iter_state *state = seq->private;

		udp4_format_sock(v, tmpbuf, state->bucket);
		seq_printf(seq, "%-127s\n", tmpbuf);
	}
	return 0;
}

/* ------------------------------------------------------------------------ */
static struct file_operations udp4_seq_fops;
static struct udp_seq_afinfo udp4_seq_afinfo = {
	.owner		= THIS_MODULE,
	.name		= "udp",
	.family		= AF_INET,
	.hashtable	= udp_hash,
	.seq_show	= udp4_seq_show,
	.seq_fops	= &udp4_seq_fops,
};

int __init udp4_proc_init(void)
{
	return udp_proc_register(&udp4_seq_afinfo);
}

void udp4_proc_exit(void)
{
	udp_proc_unregister(&udp4_seq_afinfo);
}
#endif /* CONFIG_PROC_FS */

EXPORT_SYMBOL(udp_disconnect);
EXPORT_SYMBOL(udp_hash);
EXPORT_SYMBOL(udp_hash_lock);
EXPORT_SYMBOL(udp_ioctl);
EXPORT_SYMBOL(udp_get_port);
EXPORT_SYMBOL(udp_prot);
EXPORT_SYMBOL(udp_sendmsg);
EXPORT_SYMBOL(udp_lib_getsockopt);
EXPORT_SYMBOL(udp_lib_setsockopt);
EXPORT_SYMBOL(udp_poll);

#ifdef CONFIG_PROC_FS
EXPORT_SYMBOL(udp_proc_register);
EXPORT_SYMBOL(udp_proc_unregister);
#endif
