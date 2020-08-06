/*
 *	common UDP/RAW code
 *	Linux INET implementation
 *
 * Authors:
 * 	Hideaki YOSHIFUJI <yoshfuji@linux-ipv6.org>
 *
 * 	This program is free software; you can redistribute it and/or
 * 	modify it under the terms of the GNU General Public License
 * 	as published by the Free Software Foundation; either version
 * 	2 of the License, or (at your option) any later version.
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <net/ip.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/tcp_states.h>

/*
 * udp协议模块建立链接的目的是获取目的地址的路由信息，
 * 并且把它保存在路由缓存中.
 */ 
int ip4_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *) uaddr;
	struct rtable *rt;
	__be32 saddr;
	int oif;
	int err;


	if (addr_len < sizeof(*usin))
		return -EINVAL;

	if (usin->sin_family != AF_INET)
		return -EAFNOSUPPORT;

    //释放sk过去缓存的路由表项
	sk_dst_reset(sk);

	oif = sk->sk_bound_dev_if;
	saddr = inet->saddr;
	//是否为广播地址
	if (MULTICAST(usin->sin_addr.s_addr)) {
		if (!oif)
			oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
	}

	//查找路由表，返回路由表项信息，保存在rt变量中
	err = ip_route_connect(&rt, usin->sin_addr.s_addr, saddr,
			       RT_CONN_FLAGS(sk), oif,
			       sk->sk_protocol,
			       inet->sport, usin->sin_port, sk, 1);
	if (err) {
		if (err == -ENETUNREACH)
			IP_INC_STATS_BH(IPSTATS_MIB_OUTNOROUTES);
		return err;
	}

	if ((rt->rt_flags & RTCF_BROADCAST) && !sock_flag(sk, SOCK_BROADCAST)) {
		ip_rt_put(rt);
		return -EACCES;
	}
	//重新设置套接字中的地址信息
	if (!inet->saddr)
		inet->saddr = rt->rt_src;	/* Update source address */
	if (!inet->rcv_saddr)
		inet->rcv_saddr = rt->rt_src;
	inet->daddr = rt->rt_dst;
	inet->dport = usin->sin_port;

	//所以虽然是udp，但是也可以有TCP_ESTABLISHED状态啊
	sk->sk_state = TCP_ESTABLISHED;
	inet->id = jiffies;

    //为套接字设置路由缓存信息
	sk_dst_set(sk, &rt->u.dst);
	return(0);
}

EXPORT_SYMBOL(ip4_datagram_connect);

