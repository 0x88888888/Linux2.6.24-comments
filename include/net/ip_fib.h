/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Forwarding Information Base.
 *
 * Authors:	A.N.Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef _NET_IP_FIB_H
#define _NET_IP_FIB_H

#include <net/flow.h>
#include <linux/seq_file.h>
#include <net/fib_rules.h>

/*
 * fib_config主要用于将外部的route的配置/参数形式转为FIB的内部配置形式。
 * 如使用IP命令添加/删除route时，或者路由daemon向linux添加/删除时，
 * 都需要将其传入系统API的参数转为FIB的内部配置结构
 */
struct fib_config {
	//目的地址的掩码
	u8			fc_dst_len;
	u8			fc_tos;
    //路由协议，其实更像是指该条路由是从何而来，参见RTPROT_STATIC等宏
    //RTPROT_STATIC表示该route为管理员添加的静态路由，RTPROT_ZEBRA为由zebra添加的路由	
	u8			fc_protocol;
	//参见rt_scope_t的定义
	u8			fc_scope;
	//类型如RTN_UNICAST：直连路由，参见类似的定义
	u8			fc_type;
	/* 3 bytes unused */
	//指示哪个路由表，如RT6_TABLE_MAIN
	u32			fc_table;
	//目的地址
	__be32			fc_dst;
	//网关
	__be32			fc_gw;
	//出口的网卡
	int			fc_oif;
	//路由标志
	u32			fc_flags;
	//优先级
	u32			fc_priority;
	//prefer 源地址，暂不知道用途
	__be32			fc_prefsrc;
	struct nlattr		*fc_mx;
	struct rtnexthop	*fc_mp;
	int			fc_mx_len;
	int			fc_mp_len;
	u32			fc_flow;
	u32			fc_nlflags;
	struct nl_info		fc_nlinfo;
 };

struct fib_info;

/*
 * 管理与下一跳有关的信息
 */
struct fib_nh {

	struct net_device	*nh_dev;    // 设备
	struct hlist_node	nh_hash;    // 
	struct fib_info		*nh_parent;
	unsigned		nh_flags;       // 标志
	unsigned char		nh_scope;   // 范围
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	int			nh_weight;          // 路由权重字段
	int			nh_power;           // 路由的指数字段
#endif
#ifdef CONFIG_NET_CLS_ROUTE
	__u32			nh_tclassid;    // 分类标志
#endif
	int			nh_oif;             // 去往下一跳的出口
	__be32			nh_gw;          // 下一跳地址
};

/*
 * This structure contains data shared by many of routes.
 *
 * 路由表项信息
 *
 * fib_info用于存储路由条目的一些共用的参数
 */
struct fib_info {
	struct hlist_node	fib_hash;
	struct hlist_node	fib_lhash;
	
	int			fib_treeref;     // 路由表项树的引用
	atomic_t		fib_clntref; // 引用计数增量
	int			fib_dead;        // 无效条目标志
	unsigned		fib_flags;   // 标志字段
	
	int			fib_protocol;    // 协议
	__be32			fib_prefsrc; // 源地址信息
	u32			fib_priority;    // 优先级
	u32			fib_metrics[RTAX_MAX];  // 参数
#define fib_mtu fib_metrics[RTAX_MTU-1]
#define fib_window fib_metrics[RTAX_WINDOW-1]
#define fib_rtt fib_metrics[RTAX_RTT-1]
#define fib_advmss fib_metrics[RTAX_ADVMSS-1]
	int			fib_nhs;
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	int			fib_power;
#endif
	struct fib_nh		fib_nh[0];
#define fib_dev		fib_nh[0].nh_dev
};


#ifdef CONFIG_IP_MULTIPLE_TABLES
struct fib_rule;
#endif

struct fib_result {
	unsigned char	prefixlen;
	unsigned char	nh_sel;
	unsigned char	type;
	unsigned char	scope;
	struct fib_info *fi;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	struct fib_rule	*r;
#endif
};

struct fib_result_nl {
	__be32		fl_addr;   /* To be looked up*/
	u32		fl_mark;
	unsigned char	fl_tos;
	unsigned char   fl_scope;
	unsigned char   tb_id_in;

	unsigned char   tb_id;      /* Results */
	unsigned char	prefixlen;
	unsigned char	nh_sel;
	unsigned char	type;
	unsigned char	scope;
	int             err;      
};

#ifdef CONFIG_IP_ROUTE_MULTIPATH

#define FIB_RES_NH(res)		((res).fi->fib_nh[(res).nh_sel])
#define FIB_RES_RESET(res)	((res).nh_sel = 0)

#else /* CONFIG_IP_ROUTE_MULTIPATH */

#define FIB_RES_NH(res)		((res).fi->fib_nh[0])
#define FIB_RES_RESET(res)

#endif /* CONFIG_IP_ROUTE_MULTIPATH */

#define FIB_RES_PREFSRC(res)		((res).fi->fib_prefsrc ? : __fib_res_prefsrc(&res))
#define FIB_RES_GW(res)			(FIB_RES_NH(res).nh_gw)
#define FIB_RES_DEV(res)		(FIB_RES_NH(res).nh_dev)
#define FIB_RES_OIF(res)		(FIB_RES_NH(res).nh_oif)

struct fib_table {
    /* 负载成员，用于将所有的fib_table链接起来 */
	struct hlist_node tb_hlist;	
	/*tb_id字段是表的id，如果配置了多个表，它的值在1到255之间。如果没有配置多个表，则只会RT_TABLE_MAIN或RT_TABLE_LOCAL，tb_stamp目前没有使用。*/ 
	u32		tb_id;
	unsigned	tb_stamp;
	/*
	 * 指向查询路由表的函数，一般指向fib_lookup
	 */
	int		(*tb_lookup)(struct fib_table *tb, const struct flowi *flp, struct fib_result *res);
	/*
	 * 指向插入路由条目的函数,一般指向fn_hash_insert
	 */
	int		(*tb_insert)(struct fib_table *, struct fib_config *);

	/*
	 * 指向删除路由条目的函数,一般指向fn_hash_delete
	 */
	int		(*tb_delete)(struct fib_table *, struct fib_config *);
	/*
	 * 指向路由输出的函数，在RT netlink上输出条目，一般指向fn_hash_dump
	 */
	int		(*tb_dump)(struct fib_table *table, struct sk_buff *skb,
				     struct netlink_callback *cb);
	/*
	 * 指向删除多个路由条目的函数
	 */
	int		(*tb_flush)(struct fib_table *table);
	/*
	 * 指向选择默认路由条目的函数,一般指向fn_hash_select_default
	 */
	void		(*tb_select_default)(struct fib_table *table,
					     const struct flowi *flp, struct fib_result *res);
	/*
	 * 从表中获取所有的路由，这主要由rtnetlink使用inet_dump_fib调用它。
	 * int (*tb_dump)(...) 操作删除fib_table中所有的表项int (*tb_flash)(...) 
	 * 选择缺省的路由void (*tb_select_default) tb_data是指向hash表项的一个不透明指针，
	 * 此表中的其他函数操作此字段，它不能被直接访问。
	 *
	 * 被初始化函数fib_hash_init设置为指向struct fn_hash结构的指针
	 *
	 * 路由表数据：因为有hash和trie两种方式，所以使用零长数组
	 *
	 * 如果是用hash方式实现，就存储fn_hash对象
	 */
	unsigned char	tb_data[0];
};

#ifndef CONFIG_IP_MULTIPLE_TABLES

extern struct fib_table *ip_fib_local_table;
extern struct fib_table *ip_fib_main_table;

static inline struct fib_table *fib_get_table(u32 id)
{
	if (id != RT_TABLE_LOCAL)
		return ip_fib_main_table;
	return ip_fib_local_table;
}

static inline struct fib_table *fib_new_table(u32 id)
{
	return fib_get_table(id);
}

static inline int fib_lookup(const struct flowi *flp, struct fib_result *res)
{

     /* 
      * 先查询本地地址路由表, ip_fib_local_table->tb_lookup
      * 本地路由表保存本地地址，多播等，属于需要发送到本机的地址信息。
      *
      * 再查询main路由表,ip_fib_main_table->tb_lookup ，这个是咱们设置路由或路由daemon设置的路由表 
      *
      * tb_lookup == fn_hash_lookup或者fn_trie_lookup
      */
	if (ip_fib_local_table->tb_lookup(ip_fib_local_table, flp, res) &&
	    ip_fib_main_table->tb_lookup(ip_fib_main_table, flp, res))
		return -ENETUNREACH;
	return 0;
}

static inline void fib_select_default(const struct flowi *flp, struct fib_result *res)
{
	if (FIB_RES_GW(*res) && FIB_RES_NH(*res).nh_scope == RT_SCOPE_LINK)
		ip_fib_main_table->tb_select_default(ip_fib_main_table, flp, res);
}

#else /* CONFIG_IP_MULTIPLE_TABLES */
extern void __init fib4_rules_init(void);

#ifdef CONFIG_NET_CLS_ROUTE
extern u32 fib_rules_tclass(struct fib_result *res);
#endif

#define ip_fib_local_table fib_get_table(RT_TABLE_LOCAL)
#define ip_fib_main_table fib_get_table(RT_TABLE_MAIN)

extern int fib_lookup(struct flowi *flp, struct fib_result *res);

extern struct fib_table *fib_new_table(u32 id);
extern struct fib_table *fib_get_table(u32 id);
extern void fib_select_default(const struct flowi *flp, struct fib_result *res);

#endif /* CONFIG_IP_MULTIPLE_TABLES */

/* Exported by fib_frontend.c */
extern const struct nla_policy rtm_ipv4_policy[];
extern void		ip_fib_init(void);
extern int fib_validate_source(__be32 src, __be32 dst, u8 tos, int oif,
			       struct net_device *dev, __be32 *spec_dst, u32 *itag);
extern void fib_select_multipath(const struct flowi *flp, struct fib_result *res);

struct rtentry;

/* Exported by fib_semantics.c */
extern int ip_fib_check_default(__be32 gw, struct net_device *dev);
extern int fib_sync_down(__be32 local, struct net_device *dev, int force);
extern int fib_sync_up(struct net_device *dev);
extern __be32  __fib_res_prefsrc(struct fib_result *res);

/* Exported by fib_hash.c */
extern struct fib_table *fib_hash_init(u32 id);

static inline void fib_combine_itag(u32 *itag, struct fib_result *res)
{
#ifdef CONFIG_NET_CLS_ROUTE
#ifdef CONFIG_IP_MULTIPLE_TABLES
	u32 rtag;
#endif
	*itag = FIB_RES_NH(*res).nh_tclassid<<16;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	rtag = fib_rules_tclass(res);
	if (*itag == 0)
		*itag = (rtag<<16);
	*itag |= (rtag>>16);
#endif
#endif
}

extern void free_fib_info(struct fib_info *fi);

static inline void fib_info_put(struct fib_info *fi)
{
	if (atomic_dec_and_test(&fi->fib_clntref))
		free_fib_info(fi);
}

static inline void fib_res_put(struct fib_result *res)
{
	if (res->fi)
		fib_info_put(res->fi);
#ifdef CONFIG_IP_MULTIPLE_TABLES
	if (res->r)
		fib_rule_put(res->r);
#endif
}

#ifdef CONFIG_PROC_FS
extern int  fib_proc_init(void);
extern void fib_proc_exit(void);
#endif

#endif  /* _NET_FIB_H */
