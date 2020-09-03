#ifndef __NET_FIB_RULES_H
#define __NET_FIB_RULES_H

#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/fib_rules.h>
#include <net/flow.h>
#include <net/rtnetlink.h>

/*
 * 表示由策略路由在路由流量时选择的策略规则
 *
 * 在fib_default_rule_add() 中分配，初始化
 *
 * 添加到fib_rules_ops->rules_list上
 *
 * 实现策略路由的主要数据结构
 *
 * 作为fib4_rule成员出现
 */
struct fib_rule
{
	struct list_head	list;// 链接到fib_rules_ops->rule_lists
	atomic_t		refcnt;
	
	int			ifindex; //本策略路由的网络接口索引
	char		ifname[IFNAMSIZ];
	u32			mark; //mark 值  
	u32			mark_mask; //mark 掩 码 值 
    //策略规则优先级， 值越小优先级越大
	u32			pref; 
	u32			flags;
	u32			table; //路由表id  
	/*
	 * fib rule的action规则,包括FR_ACT_TO_TBL等
	 */
	u8			action; 

	u32			target;
	//action == FR_ACT_GOTO时，跳转到用这个ctarget
	struct fib_rule *	ctarget;
	struct rcu_head		rcu;
};

struct fib_lookup_arg
{
	void			*lookup_ptr;
	void			*result;
	struct fib_rule		*rule;
};

/*
 * 全局对象 fib4_rules_ops
 *
 * 所有的fib_rules_ops都链接到rules_ops链表中
 * 存放策略规则fib_rule和操作
 */
struct fib_rules_ops
{
	int			family; //AF_INET之类的
 	struct list_head	list; //在fib_rules_register()链接到rules_ops链表中
 	//一个策略路由规则所占用的内存大小
	int			rule_size;
	//协议相关的地址长度
	int			addr_size;
	
	int			unresolved_rules;
	int			nr_goto_rules;


    /*協議相關的action函數，即是策略規則匹配後，所調用的action函數，執行後續的操作，一般是獲取到相應的路由表，查找符合要求的路由項*/
	//fib4_rule_action
	int			(*action)(struct fib_rule *,
					  struct flowi *, int,
					  struct fib_lookup_arg *);
	/*協議相關的規則匹配函數，對於策略規則的匹配，首先是通用匹配，待通用匹配完成後，則會調用該函數，進行協議相關參數（源、目的地址等）的匹配*/
	//fib4_rule_match
	int			(*match)(struct fib_rule *,
					 struct flowi *, int);

	//fib4_rule_configure
	int			(*configure)(struct fib_rule *,
					     struct sk_buff *,
					     struct nlmsghdr *,
					     struct fib_rule_hdr *,
					     struct nlattr **);
	int			(*compare)(struct fib_rule *,
					   struct fib_rule_hdr *,
					   struct nlattr **);
	int			(*fill)(struct fib_rule *, struct sk_buff *,
					struct nlmsghdr *,
					struct fib_rule_hdr *);
	u32			(*default_pref)(void);
	size_t			(*nlmsg_payload)(struct fib_rule *);

	/* Called after modifications to the rules set, must flush
	 * the route cache if one exists. */
	void			(*flush_cache)(void);

	int			nlgroup;
	const struct nla_policy	*policy;
	
	struct list_head	rules_list; //fib_rule对象
	struct module		*owner;
};

#define FRA_GENERIC_POLICY \
	[FRA_IFNAME]	= { .type = NLA_STRING, .len = IFNAMSIZ - 1 }, \
	[FRA_PRIORITY]	= { .type = NLA_U32 }, \
	[FRA_FWMARK]	= { .type = NLA_U32 }, \
	[FRA_FWMASK]	= { .type = NLA_U32 }, \
	[FRA_TABLE]     = { .type = NLA_U32 }, \
	[FRA_GOTO]	= { .type = NLA_U32 }

static inline void fib_rule_get(struct fib_rule *rule)
{
	atomic_inc(&rule->refcnt);
}

static inline void fib_rule_put_rcu(struct rcu_head *head)
{
	struct fib_rule *rule = container_of(head, struct fib_rule, rcu);
	kfree(rule);
}

static inline void fib_rule_put(struct fib_rule *rule)
{
	if (atomic_dec_and_test(&rule->refcnt))
		call_rcu(&rule->rcu, fib_rule_put_rcu);
}

static inline u32 frh_get_table(struct fib_rule_hdr *frh, struct nlattr **nla)
{
	if (nla[FRA_TABLE])
		return nla_get_u32(nla[FRA_TABLE]);
	return frh->table;
}

extern int			fib_rules_register(struct fib_rules_ops *);
extern int			fib_rules_unregister(struct fib_rules_ops *);

extern int			fib_rules_lookup(struct fib_rules_ops *,
						 struct flowi *, int flags,
						 struct fib_lookup_arg *);
extern int			fib_default_rule_add(struct fib_rules_ops *,
						     u32 pref, u32 table,
						     u32 flags);
#endif
