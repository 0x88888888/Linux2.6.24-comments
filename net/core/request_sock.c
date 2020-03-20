/*
 * NET		Generic infrastructure for Network protocols.
 *
 * Authors:	Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 *
 * 		From code originally in include/net/tcp.h
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include <net/request_sock.h>

/*
 * Maximum number of SYN_RECV sockets in queue per LISTEN socket.
 * One SYN_RECV socket costs about 80bytes on a 32bit machine.
 * It would be better to replace it with a global counter for all sockets
 * but then some measure against one socket starving all other sockets
 * would be needed.
 *
 * It was 128 by default. Experiments with real servers show, that
 * it is absolutely not enough even at 100conn/sec. 256 cures most
 * of problems. This value is adjusted to 128 for very small machines
 * (<=32Mb of memory) and to 1024 on normal or better ones (>=256Mb).
 * Note : Dont forget somaxconn that may limit backlog too.
 */
int sysctl_max_syn_backlog = 256;

/*
 * sys_socketcall()
 *  sys_listen()
 *   inet_listen()
 *    inet_csk_listen_start()
 *     reqsk_queue_alloc()
 *
 */
int reqsk_queue_alloc(struct request_sock_queue *queue,
		      unsigned int nr_table_entries)
{
	size_t lopt_size = sizeof(struct listen_sock);
	struct listen_sock *lopt;

	/*
	 * nr_table_entries必需在[8, sysctl_max_syn_backlog]之间，默认是[8, 256] 
	 * 但实际上在sys_listen()中要求backlog <= sysctl_somaxconn（默认为128）
	 * 所以此时默认区间为[8, 128]
	 */

	nr_table_entries = min_t(u32, nr_table_entries, sysctl_max_syn_backlog);
	nr_table_entries = max_t(u32, nr_table_entries, 8);
	/* 使nr_table_entries = 2^n，向上取整 */
	nr_table_entries = roundup_pow_of_two(nr_table_entries + 1);
	/* 增加一个指针数组的长度 */
	lopt_size += nr_table_entries * sizeof(struct request_sock *);
	if (lopt_size > PAGE_SIZE)
		/* 如果申请内存大于1页，则申请虚拟地址连续的空间 */
		lopt = __vmalloc(lopt_size,
			GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO,
			PAGE_KERNEL);
	else/* 申请内存在1页内，则申请物理地址连续的空间 */
		lopt = kzalloc(lopt_size, GFP_KERNEL);
	if (lopt == NULL)
		return -ENOMEM;

    /* 相当于把max_qlen_log设置为nr_table_entries以2为底的对数 */
	for (lopt->max_qlen_log = 3;
	     (1 << lopt->max_qlen_log) < nr_table_entries;
	     lopt->max_qlen_log++);
    /* 获取一个随机数 */ 
	get_random_bytes(&lopt->hash_rnd, sizeof(lopt->hash_rnd));
	rwlock_init(&queue->syn_wait_lock);
	queue->rskq_accept_head = NULL; /* 全连接队列置为空 */
	lopt->nr_table_entries = nr_table_entries; /* 半连接队列的最大长度 */

	write_lock_bh(&queue->syn_wait_lock);
	queue->listen_opt = lopt; /* 初始化半连接队列 */
	write_unlock_bh(&queue->syn_wait_lock);

	return 0;
}

EXPORT_SYMBOL(reqsk_queue_alloc);

// 销毁连接请求块中的listen_sock实例
void __reqsk_queue_destroy(struct request_sock_queue *queue)
{
	struct listen_sock *lopt;
	size_t lopt_size;

	/*
	 * this is an error recovery path only
	 * no locking needed and the lopt is not NULL
	 */

	lopt = queue->listen_opt;
	lopt_size = sizeof(struct listen_sock) +
		lopt->nr_table_entries * sizeof(struct request_sock *);

	if (lopt_size > PAGE_SIZE)
		vfree(lopt);
	else
		kfree(lopt);
}

EXPORT_SYMBOL(__reqsk_queue_destroy);

static inline struct listen_sock *reqsk_queue_yank_listen_sk(
		struct request_sock_queue *queue)
{
	struct listen_sock *lopt;

	write_lock_bh(&queue->syn_wait_lock);
	lopt = queue->listen_opt;
	queue->listen_opt = NULL;
	write_unlock_bh(&queue->syn_wait_lock);

	return lopt;
}

void reqsk_queue_destroy(struct request_sock_queue *queue)
{
	/* make all the listen_opt local to us */
	struct listen_sock *lopt = reqsk_queue_yank_listen_sk(queue);
	size_t lopt_size = sizeof(struct listen_sock) +
		lopt->nr_table_entries * sizeof(struct request_sock *);

	if (lopt->qlen != 0) {
		unsigned int i;

		for (i = 0; i < lopt->nr_table_entries; i++) {
			struct request_sock *req;

			while ((req = lopt->syn_table[i]) != NULL) {
				lopt->syn_table[i] = req->dl_next;
				lopt->qlen--;
				reqsk_free(req);
			}
		}
	}

	BUG_TRAP(lopt->qlen == 0);
	if (lopt_size > PAGE_SIZE)
		vfree(lopt);
	else
		kfree(lopt);
}

EXPORT_SYMBOL(reqsk_queue_destroy);
