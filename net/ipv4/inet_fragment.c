/*
 * inet fragments management
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * 		Authors:	Pavel Emelyanov <xemul@openvz.org>
 *				Started as consolidation of ipv4/ip_fragment.c,
 *				ipv6/reassembly. and ipv6 nf conntrack reassembly
 */

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>

#include <net/inet_frag.h>

/*
 * ip分片重组,
 */
static void inet_frag_secret_rebuild(unsigned long dummy)
{
	struct inet_frags *f = (struct inet_frags *)dummy;
	unsigned long now = jiffies;
	int i;

	write_lock(&f->lock);
	get_random_bytes(&f->rnd, sizeof(u32));
	for (i = 0; i < INETFRAGS_HASHSZ; i++) {
		struct inet_frag_queue *q;
		struct hlist_node *p, *n;

		hlist_for_each_entry_safe(q, p, n, &f->hash[i], list) {
			unsigned int hval = f->hashfn(q);

			if (hval != i) {
				hlist_del(&q->list);

				/* Relink to new hash chain. */
				hlist_add_head(&q->list, &f->hash[hval]);
			}
		}
	}
	write_unlock(&f->lock);

	mod_timer(&f->secret_timer, now + f->ctl->secret_interval);
}

/*
 * inet_init()
 *  ipfrag_init()
 *   inet_frags_init()
 */
void inet_frags_init(struct inet_frags *f)
{
	int i;

	for (i = 0; i < INETFRAGS_HASHSZ; i++)
		INIT_HLIST_HEAD(&f->hash[i]);

	INIT_LIST_HEAD(&f->lru_list);
	rwlock_init(&f->lock);

	f->rnd = (u32) ((num_physpages ^ (num_physpages>>7)) ^
				   (jiffies ^ (jiffies >> 6)));

	f->nqueues = 0;
	atomic_set(&f->mem, 0);

	init_timer(&f->secret_timer);
	/* 用于重建frag哈希表 */
	f->secret_timer.function = inet_frag_secret_rebuild;
	f->secret_timer.data = (unsigned long)f;
	f->secret_timer.expires = jiffies + f->ctl->secret_interval;
	add_timer(&f->secret_timer);
}
EXPORT_SYMBOL(inet_frags_init);

void inet_frags_fini(struct inet_frags *f)
{
	del_timer(&f->secret_timer);
}
EXPORT_SYMBOL(inet_frags_fini);

static inline void fq_unlink(struct inet_frag_queue *fq, struct inet_frags *f)
{
	write_lock(&f->lock);
	hlist_del(&fq->list);
	list_del(&fq->lru_list);
	f->nqueues--;
	write_unlock(&f->lock);
}

void inet_frag_kill(struct inet_frag_queue *fq, struct inet_frags *f)
{
	if (del_timer(&fq->timer))
		atomic_dec(&fq->refcnt);

	if (!(fq->last_in & COMPLETE)) {
		fq_unlink(fq, f);
		atomic_dec(&fq->refcnt);
		fq->last_in |= COMPLETE;
	}
}

EXPORT_SYMBOL(inet_frag_kill);

static inline void frag_kfree_skb(struct inet_frags *f, struct sk_buff *skb,
						int *work)
{
	if (work)
		*work -= skb->truesize;

	atomic_sub(skb->truesize, &f->mem);
	if (f->skb_free)
		f->skb_free(skb);
	kfree_skb(skb);
}

void inet_frag_destroy(struct inet_frag_queue *q, struct inet_frags *f,
					int *work)
{
	struct sk_buff *fp;

	BUG_TRAP(q->last_in & COMPLETE);
	BUG_TRAP(del_timer(&q->timer) == 0);

	/* Release all fragment data. */
	fp = q->fragments;
	while (fp) {
		struct sk_buff *xp = fp->next;

		frag_kfree_skb(f, fp, work);
		fp = xp;
	}

	if (work)
		*work -= f->qsize;
	atomic_sub(f->qsize, &f->mem);

	if (f->destructor)
		f->destructor(q);
	kfree(q);

}
EXPORT_SYMBOL(inet_frag_destroy);

int inet_frag_evictor(struct inet_frags *f)
{
	struct inet_frag_queue *q;
	int work, evicted = 0;

	work = atomic_read(&f->mem) - f->ctl->low_thresh;
	while (work > 0) {
		read_lock(&f->lock);
		if (list_empty(&f->lru_list)) {
			read_unlock(&f->lock);
			break;
		}

		q = list_first_entry(&f->lru_list,
				struct inet_frag_queue, lru_list);
		atomic_inc(&q->refcnt);
		read_unlock(&f->lock);

		spin_lock(&q->lock);
		if (!(q->last_in & COMPLETE))
			inet_frag_kill(q, f);
		spin_unlock(&q->lock);

		if (atomic_dec_and_test(&q->refcnt))
			inet_frag_destroy(q, f, &work);
		evicted++;
	}

	return evicted;
}
EXPORT_SYMBOL(inet_frag_evictor);
/*
 * ip_defrag()
 *  ip_find()
 *   inet_frag_find()
 *    inet_frag_create()
 *     inet_frag_intern()
 */
static struct inet_frag_queue *inet_frag_intern(struct inet_frag_queue *qp_in,
		struct inet_frags *f, unsigned int hash, void *arg)
{
	struct inet_frag_queue *qp;
#ifdef CONFIG_SMP
	struct hlist_node *n;
#endif

	write_lock(&f->lock);
#ifdef CONFIG_SMP
	/* With SMP race we have to recheck hash table, because
	 * such entry could be created on other cpu, while we
	 * promoted read lock to write lock.
	 */
	hlist_for_each_entry(qp, n, &f->hash[hash], list) {
		if (f->match(qp, arg)) {
		/* 
            其它CPU真的已经添加了该节点，那么我们只需要增加其计数器，并设置其标志位。
            目前还没有细致看，大概看的结果是设置标志位INET_FRAG_COMPLETE是避免该队列被删除。
            */
			atomic_inc(&qp->refcnt);
			write_unlock(&f->lock);
			qp_in->last_in |= COMPLETE;
			inet_frag_put(qp_in, f);
			return qp;
		}
	}
#endif
	qp = qp_in;
    /* 修改定时器 */
	if (!mod_timer(&qp->timer, jiffies + f->ctl->timeout))
		atomic_inc(&qp->refcnt);

    /* 加新的队列节点添加到hash表中 */
	atomic_inc(&qp->refcnt);
	hlist_add_head(&qp->list, &f->hash[hash]);
	list_add_tail(&qp->lru_list, &f->lru_list);
	f->nqueues++;
	write_unlock(&f->lock);
	return qp;
}

/*
 * ip_defrag()
 *	ip_find()
 *	 inet_frag_find()
 *	  inet_frag_create()
 *     inet_frag_alloc()
 *
 */
static struct inet_frag_queue *inet_frag_alloc(struct inet_frags *f, void *arg)
{
	struct inet_frag_queue *q;

	q = kzalloc(f->qsize, GFP_ATOMIC);
	if (q == NULL)
		return NULL;
	/* 
	因为需要同时支持IPv4和IPv6分片，所以这里使用一个回调函数。并且这种方式分隔了一些细节问题。
	对于IPv4来说，该回调为ip4_frag_init。
	*/
	f->constructor(q, arg);
	atomic_add(f->qsize, &f->mem);	
    /* 设置定时器，因为分片需要使用定时器清理过期的分片信息 */
	setup_timer(&q->timer, f->frag_expire, (unsigned long)q);
	spin_lock_init(&q->lock);
	atomic_set(&q->refcnt, 1);

	return q;
}

/*
 * ip_defrag()
 *  ip_find()
 *   inet_frag_find()
 *    inet_frag_create()
 *
 * 创建inet_frag_queue
 */
static struct inet_frag_queue *inet_frag_create(struct inet_frags *f,
		void *arg, unsigned int hash)
{
	struct inet_frag_queue *q;

	q = inet_frag_alloc(f, arg);
	if (q == NULL)
		return NULL;

	return inet_frag_intern(q, f, hash, arg);
}

/*
 * ip_defrag()
 *  ip_find()
 *   inet_frag_find()
 */
struct inet_frag_queue *inet_frag_find(struct inet_frags *f, void *key,
		unsigned int hash)
{
	struct inet_frag_queue *q;
	struct hlist_node *n;

	read_lock(&f->lock);
	hlist_for_each_entry(q, n, &f->hash[hash], list) {
		/* 匹配函数返回true，则表示为正确的分片队列  */
		if (f->match(q, key)) { //函数ip4_frag_match
			atomic_inc(&q->refcnt);
			read_unlock(&f->lock);
			return q;
		}
	}
	read_unlock(&f->lock);
	/* 
	没有找到正确的IP分片队列，需要重新创建一个新的IP分片队列。
	这个函数很简单，申请一个新的队列节点，计算其hash值，并将其添加到hash表中。
	*/
	return inet_frag_create(f, key, hash);
}
EXPORT_SYMBOL(inet_frag_find);
