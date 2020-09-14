/*
 * connection tracking helpers.
 *
 * 16 Dec 2003: Yasuyuki Kozakai @USAGI <yasuyuki.kozakai@toshiba.co.jp>
 *	- generalize L3 protocol dependent part.
 *
 * Derived from include/linux/netfiter_ipv4/ip_conntrack_helper.h
 */

#ifndef _NF_CONNTRACK_HELPER_H
#define _NF_CONNTRACK_HELPER_H
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_extend.h>

struct module;

/*
 * 通过这个结构的help指针，能够实现期望连接的建立以及ALG的功能
 *
 * 所有的helper都存储在nf_ct_helper_hash[]中
 */
struct nf_conntrack_helper
{
    
	/*链表结构，实现将所有的nf_conntrack_helper变量链接在一起*/	
	struct hlist_node hnode;	/* Internal use. */
    
	/* helper变量的名称*/
	const char *name;		/* name of the module */
	struct module *me;		/* pointer to self */
	
	/*允许的最大期望连接*/
	unsigned int max_expected;	/* Maximum number of concurrent 
					 * expected connections */
    /*超时定时器*/				 	
	unsigned int timeout;		/* timeout for expecteds */

	/* Tuple of things we will help (compared against server response) */
    /* 该helper结构属于哪几条数据流，通过tuple，能够判断出一个连接跟踪项是否可以拥有该helper变量。*/	
	struct nf_conntrack_tuple tuple;

	/* Function to call when data passes; return verdict, or -1 to
           invalidate. */
    /* help函数指针，实现创建期望连接与ALG等功能的函数 */	           
	int (*help)(struct sk_buff *skb,
		    unsigned int protoff,
		    struct nf_conn *ct,
		    enum ip_conntrack_info conntrackinfo);

	void (*destroy)(struct nf_conn *ct);

	int (*to_nlattr)(struct sk_buff *skb, const struct nf_conn *ct);
};

extern struct nf_conntrack_helper *
__nf_ct_helper_find(const struct nf_conntrack_tuple *tuple);

extern struct nf_conntrack_helper *
nf_ct_helper_find_get( const struct nf_conntrack_tuple *tuple);

extern struct nf_conntrack_helper *
__nf_conntrack_helper_find_byname(const char *name);

extern void nf_ct_helper_put(struct nf_conntrack_helper *helper);
extern int nf_conntrack_helper_register(struct nf_conntrack_helper *);
extern void nf_conntrack_helper_unregister(struct nf_conntrack_helper *);

extern struct nf_conn_help *nf_ct_helper_ext_add(struct nf_conn *ct, gfp_t gfp);

static inline struct nf_conn_help *nfct_help(const struct nf_conn *ct)
{
	return nf_ct_ext_find(ct, NF_CT_EXT_HELPER);
}
#endif /*_NF_CONNTRACK_HELPER_H*/
