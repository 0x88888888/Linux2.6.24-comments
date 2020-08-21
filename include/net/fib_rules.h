#ifndef __NET_FIB_RULES_H
#define __NET_FIB_RULES_H

#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/fib_rules.h>
#include <net/flow.h>
#include <net/rtnetlink.h>

/*
 * 表示由策略路由在路由流量时选择的规则
 */
struct fib_rule
{
	struct list_head	list;// 链接到fib_rules_ops->rule_lists
	atomic_t		refcnt;
	int			ifindex; //网络接口索引
	char		ifname[IFNAMSIZ];
	u32			mark; //mark 值  
	u32			mark_mask; //mark 掩 码 值 
	u32			pref; //路由规则优先级， 值越小优先级越大
	u32			flags;
	u32			table; //路由表id  
	/*
	 * 策略的动作,RTN_UNICAST, RTN_BLACKHOLE, RTN_UNREACHABLE, RTN_PROHIBIT, RTN_NAT
	 *
	 * 如果action取值RTN_UNICAST,则table表示供查询的路由表。
	 */
	u8			action; 
	
	u32			target;
	struct fib_rule *	ctarget;
	struct rcu_head		rcu;
};

struct fib_lookup_arg
{
	void			*lookup_ptr;
	void			*result;
	struct fib_rule		*rule;
};

struct fib_rules_ops
{
	int			family;
	struct list_head	list;
	int			rule_size;
	int			addr_size;
	int			unresolved_rules;
	int			nr_goto_rules;

	int			(*action)(struct fib_rule *,
					  struct flowi *, int,
					  struct fib_lookup_arg *);
	int			(*match)(struct fib_rule *,
					 struct flowi *, int);
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
	struct list_head	rules_list;
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
