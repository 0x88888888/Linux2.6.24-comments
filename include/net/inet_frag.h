#ifndef __NET_FRAG_H__
#define __NET_FRAG_H__

/*
 * 嵌入到ipq中去
 */
struct inet_frag_queue {
    /*
     * 用于链接ipq_hash散列表链接成双向链表
     */
	struct hlist_node	list;
	/*
	 * 用来将ipq链接到全局链表ipq_lru_list链表中，ipq_lru_list链表用于垃圾收集，
	 * 当IP组装模块消耗的内存大于规定的上限是，会遍历该链表的清楚符合条件的分片。
	 */
	struct list_head	lru_list;   /* lru list member */
	
	spinlock_t		lock;
	atomic_t		refcnt;
	/*
	 * 组装超时定时器，组装分片非常耗资源，因此不可能无休止地等待分片的到达。
	 */
	struct timer_list	timer;      /* when will this queue expire? */
	/*
	 * 用来链接已经接收到的分片。
	 */
	struct sk_buff		*fragments; /* list of received fragments */
	/* 记录最后一个分片的网络设备索引号 */
	ktime_t			stamp;
	/*
	 * 当前已收到分片中offset最大的那个分片的offset值加上其长度值，
	 * 即分片末尾在整个原始数据中的位置，因此当收到最后一个分片后该字段值将更新为原始数据报的长度
	 */
	int			len;        /* total length of orig datagram */
	
	//已接收到的所有分片总长度，因此可用len和meat来判断一个IP数据报的所有分片是否已到齐。
	int			meat;
	__u8			last_in;    /* first/last segment arrived? */

#define COMPLETE		4
#define FIRST_IN		2
#define LAST_IN			1
};

#define INETFRAGS_HASHSZ		64

struct inet_frags_ctl {
	int high_thresh;
	int low_thresh;
	int timeout;
	int secret_interval;
};

/*
 * 全局只有一个ip4_frags 对象
 */
struct inet_frags {
	struct list_head	lru_list;
	struct hlist_head	hash[INETFRAGS_HASHSZ];
	rwlock_t		lock;
	u32			rnd;
	int			nqueues;
	int			qsize;
	//系统中所有ip 分片使用掉的内存数量
	atomic_t		mem;
	/*
	 * 这个timer_list对象用于重建hash表
	 */
	struct timer_list	secret_timer;
	struct inet_frags_ctl	*ctl;

	unsigned int		(*hashfn)(struct inet_frag_queue *);
	void			(*constructor)(struct inet_frag_queue *q,
						void *arg);
	void			(*destructor)(struct inet_frag_queue *);
	void			(*skb_free)(struct sk_buff *);
	int			(*match)(struct inet_frag_queue *q,
						void *arg);
	void			(*frag_expire)(unsigned long data);
};

void inet_frags_init(struct inet_frags *);
void inet_frags_fini(struct inet_frags *);

void inet_frag_kill(struct inet_frag_queue *q, struct inet_frags *f);
void inet_frag_destroy(struct inet_frag_queue *q,
				struct inet_frags *f, int *work);
int inet_frag_evictor(struct inet_frags *f);
struct inet_frag_queue *inet_frag_find(struct inet_frags *f, void *key,
		unsigned int hash);

static inline void inet_frag_put(struct inet_frag_queue *q, struct inet_frags *f)
{
	if (atomic_dec_and_test(&q->refcnt))
		inet_frag_destroy(q, f, NULL);
}

#endif
