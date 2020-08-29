/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Support for INET connection oriented protocols.
 *
 * Authors:	See the TCP sources
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or(at your option) any later version.
 */

#include <linux/module.h>
#include <linux/jhash.h>

#include <net/inet_connection_sock.h>
#include <net/inet_hashtables.h>
#include <net/inet_timewait_sock.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/tcp_states.h>
#include <net/xfrm.h>

#ifdef INET_CSK_DEBUG
const char inet_csk_timer_bug_msg[] = "inet_csk BUG: unknown timer value\n";
EXPORT_SYMBOL(inet_csk_timer_bug_msg);
#endif

/*
 * This array holds the first and last local port number.
 */
int sysctl_local_port_range[2] = { 32768, 61000 };
DEFINE_SEQLOCK(sysctl_port_range_lock);

void inet_get_local_port_range(int *low, int *high)
{
	unsigned seq;
	do {
		seq = read_seqbegin(&sysctl_port_range_lock);

		*low = sysctl_local_port_range[0];
		*high = sysctl_local_port_range[1];
	} while (read_seqretry(&sysctl_port_range_lock, seq));
}
EXPORT_SYMBOL(inet_get_local_port_range);

/*
 *  sys_socketcall()
 *   sys_bind()
 *    inet_bind()
 *     tcp_v4_get_port()
 *      inet_csk_get_port()  参数bind_conflict==inet_csk_bind_conflict
 *       inet_csk_bind_conflict()
 *
 */
int inet_csk_bind_conflict(const struct sock *sk,
			   const struct inet_bind_bucket *tb)
{
	const __be32 sk_rcv_saddr = inet_rcv_saddr(sk);
	struct sock *sk2;
	struct hlist_node *node;
	int reuse = sk->sk_reuse; /* SO_REUSEADDR，表示处于TIME_WAIT状态的端口允许重用 */

    /*
     * 遍历此端口上的sock。
	 */
	sk_for_each_bound(sk2, node, &tb->owners) {
	    /* 冲突的条件1：不是同一socket、绑定在相同的设备上 */
		if (sk != sk2 &&
		    !inet_v6_ipv6only(sk2) &&
		    (!sk->sk_bound_dev_if ||
		     !sk2->sk_bound_dev_if ||
		     sk->sk_bound_dev_if == sk2->sk_bound_dev_if)) {

            /* 冲突的条件2：绑定在相同的IP上
             * 冲突的条件3（符合一个即满足）：
             * 3.1 本socket不允许重用
             * 3.2 链表中的socket不允许重用
             * 3.3 链表中的socket处于监听状态
             */		     
			if (!reuse || !sk2->sk_reuse ||
			    sk2->sk_state == TCP_LISTEN) {
				const __be32 sk2_rcv_saddr = inet_rcv_saddr(sk2);
				
				if (!sk2_rcv_saddr || !sk_rcv_saddr ||
				    sk2_rcv_saddr == sk_rcv_saddr)
					break;
			}
		}
	}
	return node != NULL;
}

EXPORT_SYMBOL_GPL(inet_csk_bind_conflict);

/* Obtain a reference to a local port for the given sock,
 * if snum is zero it means select any available local port.
 *
 * 选定一个可用的端口
 *
 *  sys_socketcall()
 *   sys_bind()
 *    inet_bind()
 *     tcp_v4_get_port()
 *      inet_csk_get_port()  参数bind_conflict==inet_csk_bind_conflict
 */
int inet_csk_get_port(struct inet_hashinfo *hashinfo,
		      struct sock *sk, unsigned short snum,
		      int (*bind_conflict)(const struct sock *sk,
					   const struct inet_bind_bucket *tb))
{
	struct inet_bind_hashbucket *head;
	struct hlist_node *node;
	struct inet_bind_bucket *tb;
	int ret;

	local_bh_disable();
	if (!snum) { //snum==0,随机找一个空闲的端口号
		int remaining, rover, low, high;

        /* 获取端口号的取值范围 */
 		inet_get_local_port_range(&low, &high);
	    /* 取值范围内端口号的个数 */
		remaining = (high - low) + 1;
		rover = net_random() % remaining + low;

		do {
			/* 根据端口号，确定所在的哈希桶 */
			head = &hashinfo->bhash[inet_bhashfn(rover, hashinfo->bhash_size)];
			
			spin_lock(&head->lock);
		    /* 从头遍历哈希桶 */
			inet_bind_bucket_for_each(tb, node, &head->chain)
				if (tb->port == rover) /* 如果端口被使用了 */
					goto next;
				
			break;//找到,rover就是作为可以被使用的空闲端口号
		next:
			spin_unlock(&head->lock);
			if (++rover > high)
				rover = low; 
			
		} while (--remaining > 0);

		/* Exhausted local port range during search?  It is not
		 * possible for us to be holding one of the bind hash
		 * locks if this test triggers, because if 'remaining'
		 * drops to zero, we broke out of the do/while loop at
		 * the top level, not from the 'break;' statement.
		 */
		ret = 1;
		if (remaining <= 0)
			goto fail;

		/* OK, here is the one we will use.  HEAD is
		 * non-NULL and we hold it's mutex.
		 *
		 * 记录下来可以使用的空闲的端口号
		 */
		snum = rover;
	} else {
		/* 从头遍历哈希桶 */
		head = &hashinfo->bhash[inet_bhashfn(snum, hashinfo->bhash_size)];
		spin_lock(&head->lock);
		inet_bind_bucket_for_each(tb, node, &head->chain)
			if (tb->port == snum)
				goto tb_found; /* 发现端口在用 */
	}
	tb = NULL;
	goto tb_not_found;
tb_found:
	/* 端口上有绑定sock时 */
	if (!hlist_empty(&tb->owners)) {
		
		if (sk->sk_reuse > 1) 
			goto success;
		if (tb->fastreuse > 0 &&
		    sk->sk_reuse && sk->sk_state != TCP_LISTEN) {
			goto success;
		} else {
			ret = 1;
			if (bind_conflict(sk, tb))
				goto fail_unlock;
		}
	}
tb_not_found:
	ret = 1;
	if (!tb && (tb = inet_bind_bucket_create(hashinfo->bind_bucket_cachep, head, snum)) == NULL)
		goto fail_unlock;
	if (hlist_empty(&tb->owners)) {
		if (sk->sk_reuse && sk->sk_state != TCP_LISTEN)
			tb->fastreuse = 1;
		else
			tb->fastreuse = 0;
	} else if (tb->fastreuse &&
		   (!sk->sk_reuse || sk->sk_state == TCP_LISTEN))
		tb->fastreuse = 0;
success:
	if (!inet_csk(sk)->icsk_bind_hash)
		inet_bind_hash(sk, tb, snum);
	BUG_TRAP(inet_csk(sk)->icsk_bind_hash == tb);
	ret = 0;

fail_unlock:
	spin_unlock(&head->lock);
fail:
	local_bh_enable();
	return ret;
}

EXPORT_SYMBOL_GPL(inet_csk_get_port);

/*
 * Wait for an incoming connection, avoid race conditions. This must be called
 * with the socket locked.
 *
 * accept()超时时间为sk->sk_rcvtimeo，
 * 在sock_init_data()中初始化为MAX_SCHEDULE_TIMEOUT，表示无限等待。
 *
 * sys_socketcall()
 *  sys_accept()
 *   inet_accept()
 *    inet_csk_accept()
 *     inet_csk_wait_for_connect()
 */
static int inet_csk_wait_for_connect(struct sock *sk, long timeo)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	DEFINE_WAIT(wait); /* 初始化等待任务 */
	int err;

	/*
	 * True wake-one mechanism for incoming connections: only
	 * one process gets woken up, not the 'whole herd'.
	 * Since we do not 'race & poll' for established sockets
	 * anymore, the common case will execute the loop only once.
	 *
	 * Subtle issue: "add_wait_queue_exclusive()" will be added
	 * after any current non-exclusive waiters, and we know that
	 * it will always _stay_ after any new non-exclusive waiters
	 * because all non-exclusive waiters are added at the
	 * beginning of the wait-queue. As such, it's ok to "drop"
	 * our exclusiveness temporarily when we get woken up without
	 * having to remove and re-insert us on the wait queue.
	 */
	for (;;) {
		/* 把等待任务加入到socket的等待队列中，把进程状态设置为TASK_INTERRUPTIBLE */
		prepare_to_wait_exclusive(sk->sk_sleep, &wait,
					  TASK_INTERRUPTIBLE);
		 /* 等下可能要睡觉了，先释放 */
		release_sock(sk);
		 /* 如果全连接队列为空 */
		if (reqsk_queue_empty(&icsk->icsk_accept_queue))
			timeo = schedule_timeout(timeo); /* 进入睡眠，直到超时或收到信号 */
		/* 醒来后重新上锁 */
		lock_sock(sk);
		err = 0;
		/* 全连接队列不为空时，退出 */
		if (!reqsk_queue_empty(&icsk->icsk_accept_queue))
			break;
		err = -EINVAL;
		/* 如果sock不处于监听状态了，退出 */
		if (sk->sk_state != TCP_LISTEN)
			break;
		err = sock_intr_errno(timeo);
        /* 如果进程有待处理的信号，退出。
         * 因为timeo默认为MAX_SCHEDULE_TIMEOUT，所以err默认为-ERESTARTSYS。
         * 接下来会重新调用此函数，所以accept()依然阻塞。
         */		
		if (signal_pending(current))
			break;
		err = -EAGAIN;
		/* 如果等待超时，即超过用户设置的sk->sk_rcvtimeo，退出 */
		if (!timeo)
			break;
	}
	finish_wait(sk->sk_sleep, &wait);
	return err;
}

/*
 * This will accept the next outstanding connection.
 *
 * 从backlog队列（全连接队列）中取出一个ESTABLISHED状态的连接请求块，
 * 返回它所对应的连接sock。
 *
 *  sys_socketcall()
 *   sys_accept()
 *    inet_accept()
 *     inet_csk_accept()
 *
 *
   1. 非阻塞的，且当前没有已建立的连接，则直接退出，返回-EAGAIN。
   2. 阻塞的，且当前没有已建立的连接：
    2.1 用户没有设置超时时间，则无限期阻塞。
    2.2 用户设置了超时时间，超时后会退出。 
 */
struct sock *inet_csk_accept(struct sock *sk, int flags, int *err)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct sock *newsk;
	int error;

	lock_sock(sk);

	/* We need to make sure that this socket is listening,
	 * and that it has something pending.
	 */
	error = -EINVAL;
	if (sk->sk_state != TCP_LISTEN) /* socket必须处于监听状态 */
		goto out_err;

	/* Find already established connection 
	 * 发没有现ESTABLISHED状态的连接请求块。
	 */
	if (reqsk_queue_empty(&icsk->icsk_accept_queue)) {
		/* 等待超时时间，如果是非阻塞则为0 */
		long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

		/* If this is a non blocking socket don't sleep */
		error = -EAGAIN;
		if (!timeo) /* 如果是非阻塞的，则直接退出 */
			goto out_err;
        
		/* 阻塞等待，直到有全连接。如果用户有设置等待超时时间，超时后会退出 */
		error = inet_csk_wait_for_connect(sk, timeo);
		if (error)
			goto out_err;
	}

    /* 获取新连接的sock，释放连接控制块 */
	newsk = reqsk_queue_get_child(&icsk->icsk_accept_queue, sk);
	BUG_TRAP(newsk->sk_state != TCP_SYN_RECV);
out:
	release_sock(sk);
	return newsk;
out_err:
	newsk = NULL;
	*err = error;
	goto out;
}

EXPORT_SYMBOL(inet_csk_accept);

/*
 * Using different timers for retransmit, delayed acks and probes
 * We may wish use just one timer maintaining a list of expire jiffies
 * to optimize.
 *
 * tcp_init_xmit_timers()
 *  	inet_csk_init_xmit_timers(sk, &tcp_write_timer, &tcp_delack_timer, &tcp_keepalive_timer)
 */
void inet_csk_init_xmit_timers(struct sock *sk,
			       void (*retransmit_handler)(unsigned long),
			       void (*delack_handler)(unsigned long),
			       void (*keepalive_handler)(unsigned long))
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	init_timer(&icsk->icsk_retransmit_timer);
	init_timer(&icsk->icsk_delack_timer);
	init_timer(&sk->sk_timer);

	icsk->icsk_retransmit_timer.function = retransmit_handler;
	icsk->icsk_delack_timer.function     = delack_handler;
	sk->sk_timer.function		     = keepalive_handler;

	icsk->icsk_retransmit_timer.data =
		icsk->icsk_delack_timer.data =
			sk->sk_timer.data  = (unsigned long)sk;

	icsk->icsk_pending = icsk->icsk_ack.pending = 0;
}

EXPORT_SYMBOL(inet_csk_init_xmit_timers);

void inet_csk_clear_xmit_timers(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	icsk->icsk_pending = icsk->icsk_ack.pending = icsk->icsk_ack.blocked = 0;

	sk_stop_timer(sk, &icsk->icsk_retransmit_timer);
	sk_stop_timer(sk, &icsk->icsk_delack_timer);
	sk_stop_timer(sk, &sk->sk_timer);
}

EXPORT_SYMBOL(inet_csk_clear_xmit_timers);

void inet_csk_delete_keepalive_timer(struct sock *sk)
{
	sk_stop_timer(sk, &sk->sk_timer);
}

EXPORT_SYMBOL(inet_csk_delete_keepalive_timer);

void inet_csk_reset_keepalive_timer(struct sock *sk, unsigned long len)
{
	sk_reset_timer(sk, &sk->sk_timer, jiffies + len);
}

EXPORT_SYMBOL(inet_csk_reset_keepalive_timer);

struct dst_entry* inet_csk_route_req(struct sock *sk,
				     const struct request_sock *req)
{
	struct rtable *rt;
	const struct inet_request_sock *ireq = inet_rsk(req);
	struct ip_options *opt = inet_rsk(req)->opt;
	struct flowi fl = { .oif = sk->sk_bound_dev_if,
			    .nl_u = { .ip4_u =
				      { .daddr = ((opt && opt->srr) ?
						  opt->faddr :
						  ireq->rmt_addr),
					.saddr = ireq->loc_addr,
					.tos = RT_CONN_FLAGS(sk) } },
			    .proto = sk->sk_protocol,
			    .uli_u = { .ports =
				       { .sport = inet_sk(sk)->sport,
					 .dport = ireq->rmt_port } } };

	security_req_classify_flow(req, &fl);
	if (ip_route_output_flow(&rt, &fl, sk, 0)) {
		IP_INC_STATS_BH(IPSTATS_MIB_OUTNOROUTES);
		return NULL;
	}
	if (opt && opt->is_strictroute && rt->rt_dst != rt->rt_gateway) {
		ip_rt_put(rt);
		IP_INC_STATS_BH(IPSTATS_MIB_OUTNOROUTES);
		return NULL;
	}
	return &rt->u.dst;
}

EXPORT_SYMBOL_GPL(inet_csk_route_req);

static inline u32 inet_synq_hash(const __be32 raddr, const __be16 rport,
				 const u32 rnd, const u32 synq_hsize)
{
	return jhash_2words((__force u32)raddr, (__force u32)rport, rnd) & (synq_hsize - 1);
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#define AF_INET_FAMILY(fam) ((fam) == AF_INET)
#else
#define AF_INET_FAMILY(fam) 1
#endif

struct request_sock *inet_csk_search_req(const struct sock *sk,
					 struct request_sock ***prevp,
					 const __be16 rport, const __be32 raddr,
					 const __be32 laddr)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct listen_sock *lopt = icsk->icsk_accept_queue.listen_opt;
	struct request_sock *req, **prev;

	for (prev = &lopt->syn_table[inet_synq_hash(raddr, rport, lopt->hash_rnd,
						    lopt->nr_table_entries)];
	     (req = *prev) != NULL;
	     prev = &req->dl_next) {
		const struct inet_request_sock *ireq = inet_rsk(req);

		if (ireq->rmt_port == rport &&
		    ireq->rmt_addr == raddr &&
		    ireq->loc_addr == laddr &&
		    AF_INET_FAMILY(req->rsk_ops->family)) {
			BUG_TRAP(!req->sk);
			*prevp = prev;
			break;
		}
	}

	return req;
}

EXPORT_SYMBOL_GPL(inet_csk_search_req);

void inet_csk_reqsk_queue_hash_add(struct sock *sk, struct request_sock *req,
				   unsigned long timeout)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct listen_sock *lopt = icsk->icsk_accept_queue.listen_opt;
	const u32 h = inet_synq_hash(inet_rsk(req)->rmt_addr, inet_rsk(req)->rmt_port,
				     lopt->hash_rnd, lopt->nr_table_entries);

	reqsk_queue_hash_req(&icsk->icsk_accept_queue, h, req, timeout);
	inet_csk_reqsk_queue_added(sk, timeout);
}

/* Only thing we need from tcp.h */
extern int sysctl_tcp_synack_retries;

EXPORT_SYMBOL_GPL(inet_csk_reqsk_queue_hash_add);

void inet_csk_reqsk_queue_prune(struct sock *parent,
				const unsigned long interval,
				const unsigned long timeout,
				const unsigned long max_rto)
{
	struct inet_connection_sock *icsk = inet_csk(parent);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
	struct listen_sock *lopt = queue->listen_opt;
	int max_retries = icsk->icsk_syn_retries ? : sysctl_tcp_synack_retries;
	int thresh = max_retries;
	unsigned long now = jiffies;
	struct request_sock **reqp, *req;
	int i, budget;

	if (lopt == NULL || lopt->qlen == 0)
		return;

	/* Normally all the openreqs are young and become mature
	 * (i.e. converted to established socket) for first timeout.
	 * If synack was not acknowledged for 3 seconds, it means
	 * one of the following things: synack was lost, ack was lost,
	 * rtt is high or nobody planned to ack (i.e. synflood).
	 * When server is a bit loaded, queue is populated with old
	 * open requests, reducing effective size of queue.
	 * When server is well loaded, queue size reduces to zero
	 * after several minutes of work. It is not synflood,
	 * it is normal operation. The solution is pruning
	 * too old entries overriding normal timeout, when
	 * situation becomes dangerous.
	 *
	 * Essentially, we reserve half of room for young
	 * embrions; and abort old ones without pity, if old
	 * ones are about to clog our table.
	 */
	if (lopt->qlen>>(lopt->max_qlen_log-1)) {
		int young = (lopt->qlen_young<<1);

		while (thresh > 2) {
			if (lopt->qlen < young)
				break;
			thresh--;
			young <<= 1;
		}
	}

	if (queue->rskq_defer_accept)
		max_retries = queue->rskq_defer_accept;

	budget = 2 * (lopt->nr_table_entries / (timeout / interval));
	i = lopt->clock_hand;

	do {
		reqp=&lopt->syn_table[i];
		while ((req = *reqp) != NULL) {
			if (time_after_eq(now, req->expires)) {
				if ((req->retrans < thresh ||
				     (inet_rsk(req)->acked && req->retrans < max_retries))
				    && !req->rsk_ops->rtx_syn_ack(parent, req, NULL)) {
					unsigned long timeo;

					if (req->retrans++ == 0)
						lopt->qlen_young--;
					timeo = min((timeout << req->retrans), max_rto);
					req->expires = now + timeo;
					reqp = &req->dl_next;
					continue;
				}

				/* Drop this request */
				inet_csk_reqsk_queue_unlink(parent, req, reqp);
				reqsk_queue_removed(queue, req);
				reqsk_free(req);
				continue;
			}
			reqp = &req->dl_next;
		}

		i = (i + 1) & (lopt->nr_table_entries - 1);

	} while (--budget > 0);

	lopt->clock_hand = i;

	if (lopt->qlen)
		inet_csk_reset_keepalive_timer(parent, interval);
}

EXPORT_SYMBOL_GPL(inet_csk_reqsk_queue_prune);

struct sock *inet_csk_clone(struct sock *sk, const struct request_sock *req,
			    const gfp_t priority)
{
	struct sock *newsk = sk_clone(sk, priority);

	if (newsk != NULL) {
		struct inet_connection_sock *newicsk = inet_csk(newsk);

		newsk->sk_state = TCP_SYN_RECV;
		newicsk->icsk_bind_hash = NULL;

		inet_sk(newsk)->dport = inet_rsk(req)->rmt_port;
		newsk->sk_write_space = sk_stream_write_space;

		newicsk->icsk_retransmits = 0;
		newicsk->icsk_backoff	  = 0;
		newicsk->icsk_probes_out  = 0;

		/* Deinitialize accept_queue to trap illegal accesses. */
		memset(&newicsk->icsk_accept_queue, 0, sizeof(newicsk->icsk_accept_queue));

		security_inet_csk_clone(newsk, req);
	}
	return newsk;
}

EXPORT_SYMBOL_GPL(inet_csk_clone);

/*
 * At this point, there should be no process reference to this
 * socket, and thus no user references at all.  Therefore we
 * can assume the socket waitqueue is inactive and nobody will
 * try to jump onto it.
 */
void inet_csk_destroy_sock(struct sock *sk)
{
	BUG_TRAP(sk->sk_state == TCP_CLOSE);
	BUG_TRAP(sock_flag(sk, SOCK_DEAD));

	/* It cannot be in hash table! */
	BUG_TRAP(sk_unhashed(sk));

	/* If it has not 0 inet_sk(sk)->num, it must be bound */
	BUG_TRAP(!inet_sk(sk)->num || inet_csk(sk)->icsk_bind_hash);

	sk->sk_prot->destroy(sk);

	sk_stream_kill_queues(sk);

	xfrm_sk_free_policy(sk);

	sk_refcnt_debug_release(sk);

	atomic_dec(sk->sk_prot->orphan_count);
	sock_put(sk);
}

EXPORT_SYMBOL(inet_csk_destroy_sock);

/*
 * sys_socketcall()
 *  sys_listen()
 *   inet_listen()
 *    inet_csk_listen_start()
 *
 * 启动监听时，做的工作主要包括：
 * 1. 创建半连接队列的实例，初始化全连接队列。
 * 2. 初始化sock的一些变量，把它的状态设为TCP_LISTEN。
 * 3. 检查端口是否可用，防止bind()后其它进程修改了端口信息。
 * 4. 把sock链接进入监听哈希表listening_hash中。    
 *
 *
 */
int inet_csk_listen_start(struct sock *sk, const int nr_table_entries)
{
	struct inet_sock *inet = inet_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	/* 初始化全连接队列，创建半连接队列的实例 */
	int rc = reqsk_queue_alloc(&icsk->icsk_accept_queues nr_table_entries);

	if (rc != 0)
		return rc;

	sk->sk_max_ack_backlog = 0; /* 在返回inet_listen()时赋值 */
	sk->sk_ack_backlog = 0;
	/* icsk->icsk_ack结构清零 */
	inet_csk_delack_init(sk);

	/* There is race window here: we announce ourselves listening,
	 * but this transition is still not validated by get_port().
	 * It is OK, because this socket enters to hash table only
	 * after validation is complete.
	 */	 
	/* 把sock的状态置为LISTEN */
	sk->sk_state = TCP_LISTEN;
	 /* 检查端口是否仍然可用，防止bind()后其它进程修改了端口信息 */
	if (!sk->sk_prot->get_port(sk, inet->num)) {
		inet->sport = htons(inet->num);

		sk_dst_reset(sk);
		sk->sk_prot->hash(sk); /* 把sock链接入监听哈希表中 */

		return 0;
	}

	sk->sk_state = TCP_CLOSE;
	 /* 如果端口不可用，则释放半连接队列 */
	__reqsk_queue_destroy(&icsk->icsk_accept_queue);
	return -EADDRINUSE;
}

EXPORT_SYMBOL_GPL(inet_csk_listen_start);

/*
 *	This routine closes sockets which have been at least partially
 *	opened, but not yet accepted.
 */
void inet_csk_listen_stop(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct request_sock *acc_req;
	struct request_sock *req;

	inet_csk_delete_keepalive_timer(sk);

	/* make all the listen_opt local to us */
	acc_req = reqsk_queue_yank_acceptq(&icsk->icsk_accept_queue);

	/* Following specs, it would be better either to send FIN
	 * (and enter FIN-WAIT-1, it is normal close)
	 * or to send active reset (abort).
	 * Certainly, it is pretty dangerous while synflood, but it is
	 * bad justification for our negligence 8)
	 * To be honest, we are not able to make either
	 * of the variants now.			--ANK
	 */
	reqsk_queue_destroy(&icsk->icsk_accept_queue);

	while ((req = acc_req) != NULL) {
		struct sock *child = req->sk;

		acc_req = req->dl_next;

		local_bh_disable();
		bh_lock_sock(child);
		BUG_TRAP(!sock_owned_by_user(child));
		sock_hold(child);

		sk->sk_prot->disconnect(child, O_NONBLOCK);

		sock_orphan(child);

		atomic_inc(sk->sk_prot->orphan_count);

		inet_csk_destroy_sock(child);

		bh_unlock_sock(child);
		local_bh_enable();
		sock_put(child);

		sk_acceptq_removed(sk);
		__reqsk_free(req);
	}
	BUG_TRAP(!sk->sk_ack_backlog);
}

EXPORT_SYMBOL_GPL(inet_csk_listen_stop);

void inet_csk_addr2sockaddr(struct sock *sk, struct sockaddr *uaddr)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
	const struct inet_sock *inet = inet_sk(sk);

	sin->sin_family		= AF_INET;
	sin->sin_addr.s_addr	= inet->daddr;
	sin->sin_port		= inet->dport;
}

EXPORT_SYMBOL_GPL(inet_csk_addr2sockaddr);

int inet_csk_ctl_sock_create(struct socket **sock, unsigned short family,
			     unsigned short type, unsigned char protocol)
{
	int rc = sock_create_kern(family, type, protocol, sock);

	if (rc == 0) {
		(*sock)->sk->sk_allocation = GFP_ATOMIC;
		inet_sk((*sock)->sk)->uc_ttl = -1;
		/*
		 * Unhash it so that IP input processing does not even see it,
		 * we do not wish this socket to see incoming packets.
		 */
		(*sock)->sk->sk_prot->unhash((*sock)->sk);
	}
	return rc;
}

EXPORT_SYMBOL_GPL(inet_csk_ctl_sock_create);

#ifdef CONFIG_COMPAT
int inet_csk_compat_getsockopt(struct sock *sk, int level, int optname,
			       char __user *optval, int __user *optlen)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_af_ops->compat_getsockopt != NULL)
		return icsk->icsk_af_ops->compat_getsockopt(sk, level, optname,
							    optval, optlen);
	return icsk->icsk_af_ops->getsockopt(sk, level, optname,
					     optval, optlen);
}

EXPORT_SYMBOL_GPL(inet_csk_compat_getsockopt);

int inet_csk_compat_setsockopt(struct sock *sk, int level, int optname,
			       char __user *optval, int optlen)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_af_ops->compat_setsockopt != NULL)
		return icsk->icsk_af_ops->compat_setsockopt(sk, level, optname,
							    optval, optlen);
	return icsk->icsk_af_ops->setsockopt(sk, level, optname,
					     optval, optlen);
}

EXPORT_SYMBOL_GPL(inet_csk_compat_setsockopt);
#endif
