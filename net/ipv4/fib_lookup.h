#ifndef _FIB_LOOKUP_H
#define _FIB_LOOKUP_H

#include <linux/types.h>
#include <linux/list.h>
#include <net/ip_fib.h>

/*
 * 到达相同的网络的路由，因为其他一些参数二不同，比如TOS，
 * 不同的路由是通过fib_alias来区分的
 */
struct fib_alias {
    //链接与同一个fib_node结构相关联的所有fib_alias是咧
	struct list_head	fa_list; //fib_node->fn_alias
	struct rcu_head rcu;
	//fa_info存储着如何处理与该路由相匹配封包的信息
	struct fib_info		*fa_info;
	u8			fa_tos;
	u8			fa_type; //RTN_UNICAST,RTN_LOCAL之类的
	u8			fa_scope;
	u8			fa_state;
};

#define FA_S_ACCESSED	0x01

/* Exported by fib_semantics.c */
extern int fib_semantic_match(struct list_head *head,
			      const struct flowi *flp,
			      struct fib_result *res, __be32 zone, __be32 mask,
				int prefixlen);
extern void fib_release_info(struct fib_info *);
extern struct fib_info *fib_create_info(struct fib_config *cfg);
extern int fib_nh_match(struct fib_config *cfg, struct fib_info *fi);
extern int fib_dump_info(struct sk_buff *skb, u32 pid, u32 seq, int event,
			 u32 tb_id, u8 type, u8 scope, __be32 dst,
			 int dst_len, u8 tos, struct fib_info *fi,
			 unsigned int);
extern void rtmsg_fib(int event, __be32 key, struct fib_alias *fa,
		      int dst_len, u32 tb_id, struct nl_info *info,
		      unsigned int nlm_flags);
extern struct fib_alias *fib_find_alias(struct list_head *fah,
					u8 tos, u32 prio);
extern int fib_detect_death(struct fib_info *fi, int order,
			    struct fib_info **last_resort,
			    int *last_idx, int *dflt);

#endif /* _FIB_LOOKUP_H */
