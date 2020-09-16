#ifndef _X_TABLES_H
#define _X_TABLES_H

#define XT_FUNCTION_MAXNAMELEN 30
#define XT_TABLE_MAXNAMELEN 32

/*
 * 防火墙规则的匹配部分
 * ipt_entry_match
 *
 * 我们使用到ipt_entry_match时，就说明这是一个扩展match，
 * 对于一个标准match是通过调用函数ip_packet_match，
 * 对ipt_entry->ip进行判断来实现的，
 * 只有扩展match才会使用该结构体在ipt_entry中添加一个ipt_entry_match变量。
 *
 * ipt_entry：标准匹配结构，主要包含数据包的源、目的IP，出、入接口和掩码等；
 * ipt_entry_match：扩展匹配。一条rule规则可能有零个或多个ipt_entry_match结构；
 * ipt_entry_target：一条rule规则有且仅有一个targe
 * 动作。就是当所有的标准匹配和扩展匹配都符合之后才来执行该target。
 8
 * ipt_entry_match表示防火墙规则的匹配部分
 * ipt_entry_target{}表示防火墙规则的动作处理部分
 */
struct xt_entry_match
{
	union {
		struct {					
            /*该match所占用的内存大小(以字节为单位)*/
			u_int16_t match_size;

			/* Used by userspace */
            /*该match的名称*/
			char name[XT_FUNCTION_MAXNAMELEN-1];
			/*该match的版本,
			通过match的名称与版本信息可以唯一确定一个match。
			*/
			u_int8_t revision;
		} user;
		
		struct {
			/*该match所占用的内存大小(以字节为单位)*/
			u_int16_t match_size;

			/* Used inside the kernel */
			struct xt_match *match;
		} kernel;

		/* Total length */
		u_int16_t match_size;
	} u;

	/*可变长度数组，与下一个match或者target关联*/
	unsigned char data[0];
};

/*
 *
 * ipt_entry：标准匹配结构，主要包含数据包的源、目的IP，出、入接口和掩码等；
 * ipt_entry_match：扩展匹配。一条rule规则可能有零个或多个ipt_entry_match结构；
 * ipt_entry_target：一条rule规则有且仅有一个target动作。就是当所有的标准匹配和扩展匹配都符合之后才来执行该target。 
 *
 */
struct xt_entry_target
{
 union {
  struct {			
   //target 所占用的内存大小
   u_int16_t target_size;
   /* Used by userspace */
   char name[XT_FUNCTION_MAXNAMELEN-1]; //target 的名字		
	/*
	 * target的版本号，这个值也有很大的作用，这个值让target的向 上兼容成为了可能。
     * 存在以下情况:
     *  对于target名称为"ABC "，revision为0的target，我们想对这个 target的扩展target函数做新的架构修改，
     * 但是又不想改target的 名称，也不想直接改原target的扩展target函数，
     * 这时我们可以重 新添加一个target名称为"ABC"，revision为1，且扩展target函数
     * 为我们新编写的target。这样既保证了针对原来target "ABC"的 iptables规则能正确执行，
     * 又能满足我们新的需求。通过name与revision可以唯一确定一个target
	*/
	u_int8_t revision;
  } user;
		
  struct {
   /*target 所占用的内存大小*/
   u_int16_t target_size;
   /* Used inside the kernel */
   /* 扩展target使用，用于指向xt_target 
    *
    * 对于标准target来说,这个值为NULL。
    */
   struct xt_target *target;
  } kernel;

  /* Total length */
  u_int16_t target_size;
} u;
	
  /*可变长数组，与下一个ipt_entry关联*/
  unsigned char data[0];
};

#define XT_TARGET_INIT(__name, __size)					       \
{									       \
	.target.u.user = {						       \
		.target_size	= XT_ALIGN(__size),			       \
		.name		= __name,				       \
	},								       \
}

/*
 * ipt_standard_target 是xt_standard_target的别名
 *
 */
struct xt_standard_target
{
	struct xt_entry_target target;
	//根据verdict的值再划分为内建的动作或者跳转到自定义链中
	int verdict;
};

/* The argument to IPT_SO_GET_REVISION_*.  Returns highest revision
 * kernel supports, if >= revision. */
struct xt_get_revision
{
	char name[XT_FUNCTION_MAXNAMELEN-1];

	u_int8_t revision;
};

/* CONTINUE verdict for targets */
#define XT_CONTINUE 0xFFFFFFFF

/* For standard target */
#define XT_RETURN (-NF_REPEAT - 1)

/* this is a dummy structure to find out the alignment requirement for a struct
 * containing all the fundamental data types that are used in ipt_entry,
 * ip6t_entry and arpt_entry.  This sucks, and it is a hack.  It will be my
 * personal pleasure to remove it -HW
 */
struct _xt_align
{
	u_int8_t u8;
	u_int16_t u16;
	u_int32_t u32;
	u_int64_t u64;
};

#define XT_ALIGN(s) (((s) + (__alignof__(struct _xt_align)-1)) 	\
			& ~(__alignof__(struct _xt_align)-1))

/* Standard return verdict, or do jump. */
#define XT_STANDARD_TARGET ""
/* Error verdict. */
#define XT_ERROR_TARGET "ERROR"

#define SET_COUNTER(c,b,p) do { (c).bcnt = (b); (c).pcnt = (p); } while(0)
#define ADD_COUNTER(c,b,p) do { (c).bcnt += (b); (c).pcnt += (p); } while(0)

struct xt_counters
{
	u_int64_t pcnt, bcnt;			/* Packet and byte counters */
};

/* The argument to IPT_SO_ADD_COUNTERS. */
struct xt_counters_info
{
	/* Which table. */
	char name[XT_TABLE_MAXNAMELEN];

	unsigned int num_counters;

	/* The counters (actually `number' of these). */
	struct xt_counters counters[0];
};

#define XT_INV_PROTO		0x40	/* Invert the sense of PROTO. */

#ifdef __KERNEL__

#include <linux/netdevice.h>

/*
 * 就是 ipt_match
 * 内核用struct ipt_match表征一个Match数据结构：
 * 用户态用iptables_match来表示一个match数据结构
 * 
 * ah_match, ecn_match, iprange_match
 * owner_match, recent_match, tos_match
 * ttl_match,icmp_matchstruct, conntrack_match
 * realm_match, 
 *
 * xt_comment_match[], xt_connbytes_match[]
 * connlimit_reg[], xt_hashlimit[]
 * xt_helper_match[], xt_length_match[]
 * xt_limit_match[], xt_mac_match[]
 * xt_mark_match[], xt_multiport_match[]
 * xt_string_match[], xt_tcpmss_match[]
 * xt_tcpudp_match[], xt_time_reg[]
 * u32_reg[], xt_statistic_match[]
 * xt_state_match[], xt_sctp_match[]
 * xt_quota_match[], xt_policy_match[]
 * xt_pkttype_match[], xt_physdev_match[]
 * 
 *
 * 所有的xt_match都通过xt_register_match(), xt_register_matchs()来注册到xt[]数组中去
 */
struct xt_match
{
    //链表，使该match添加到match链表中
	struct list_head list;

    /* Match的名字，同时也要求包含该Match的模块文件名为ipt_'name'.o */
	const char name[XT_FUNCTION_MAXNAMELEN-1];

	/* Return true or false: return FALSE and set *hotdrop = 1 to
           force immediate packet drop. */
	/* Arguments changed since 2.6.9, as this must now handle
	   non-linear skb, using skb_header_pointer and
	   skb_ip_make_writable. */
	/* 返回非0表示匹配成功，如果返回0且hotdrop设为1， 则表示该报文应当立刻丢弃 */   
	bool (*match)(const struct sk_buff *skb,
		      const struct net_device *in,
		      const struct net_device *out,
		      const struct xt_match *match,
		      const void *matchinfo,
		      int offset,
		      unsigned int protoff,
		      bool *hotdrop);

	/* Called when user tries to insert an entry of this type. */
	/* Should return true or false. */
	/* 在使用本Match的规则注入表中之前调用，进行有效性检查，  如果返回0，规则就不会加入iptables中 */
	bool (*checkentry)(const char *tablename,
			   const void *ip,
			   const struct xt_match *match,
			   void *matchinfo,
			   unsigned int hook_mask);

	/* Called when entry of this type deleted. */
	/* 在包含本Match的规则从表中删除时调用， 与checkentry配合可用于动态内存分配和释放 */		   
	void (*destroy)(const struct xt_match *match, void *matchinfo);

	/* Called when userspace align differs from kernel space one */
	void (*compat_from_user)(void *dst, void *src);
	int (*compat_to_user)(void __user *dst, void *src);

	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	/* 表示当前Match是否为模块（NULL为否） */
	struct module *me;

	/* Free to use by each match */
	unsigned long data;

	char *table;
	unsigned int matchsize;
	unsigned int compatsize;
	unsigned int hooks;
	unsigned short proto;

	unsigned short family;
	u_int8_t revision;
};

/* Registration hooks for targets. 
 *
 * ipt_snat_reg, ipt_dnat_reg
 * clusterip_tgt, ipt_log_reg,
 * masquerade, target_module,
 * redirect_reg, ipt_reject_reg,
 * same_reg, ipt_ulog_reg,
 * ipt_standard_target, ipt_error_target,
 * xt_classify_target[], xt_connsecmark_target[]
 * xt_nflog_target[], xt_nfqueue_target[],
 * xt_notrack_target[], xt_secmark_target[]
 * xt_trace_target[], 
 */
struct xt_target
{
    //链表，使该match添加到target链表中
	struct list_head list;

    //target 名称
	const char name[XT_FUNCTION_MAXNAMELEN-1];

	/* Returns verdict. Argument order changed since 2.6.9, as this
	   must now handle non-linear skbs, using skb_copy_bits and
	   skb_ip_make_writable. */
    /*
     * target处理函数，对于SNAT、DNAT即在其target函数里，
     * 更新request或者reply方向 ip_conntrack_tuple值
     *
     * 如果ipt_target.target()函数是空的，那就是标准target，
     * 因为它不需要用户再去提供新的target函数了；
     * 反之，如果有target函数那就是扩展的target。
     */	   
	unsigned int (*target)(struct sk_buff *skb,
			       const struct net_device *in,
			       const struct net_device *out,
			       unsigned int hooknum,
			       const struct xt_target *target,
			       const void *targinfo);

	/* Called when user tries to insert an entry of this type:
           hook_mask is a bitmask of hooks from which it can be
           called. */
	/* Should return true or false. */
	bool (*checkentry)(const char *tablename,
			   const void *entry,
			   const struct xt_target *target,
			   void *targinfo,
			   unsigned int hook_mask);

	/* Called when entry of this type deleted. */
	void (*destroy)(const struct xt_target *target, void *targinfo);

	/* Called when userspace align differs from kernel space one */
	void (*compat_from_user)(void *dst, void *src);
	int (*compat_to_user)(void __user *dst, void *src);

	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	struct module *me;

	char *table;
	unsigned int targetsize;
	unsigned int compatsize;
	unsigned int hooks;
	unsigned short proto;

	unsigned short family;
	u_int8_t revision;
};

/* Furniture shopping...
 *
 * 
 * packet_filter, packet_mangler
 * packet_raw, nat_table 这几个对象代表 iptables操作的几个表
 *
 * ipt_table 是这个结构体的别名
 *
 * 该结构体对应于iptables中的表，目前内核注册的table有filter、mangle、nat、raw表，
 * 而这些table根据pf值添加到xt_af[pf].tables链表中。
 * 而一个xt_table中包含了该表所支持的hook点与该表里已添加的所有rule规则
 */
struct xt_table
{
    /* 表链 */
	struct list_head list;

	/* A unique name... */
	/* 表名，如"filter"、"nat"等，为了满足自动模块加载的设计， */
    /* 包含该表的模块应命名为iptable_'name'.o */
	char name[XT_TABLE_MAXNAMELEN];

	/* What hooks you will enter on */
	//该表所检测的HOOK点
	unsigned int valid_hooks;

	/* Lock for the curtain */
	rwlock_t lock;

	/* Man behind the curtain... */
	//struct ip6t_table_info *private;
	/* iptable的数据区，见下 */
	//描述表的具体属性，如表的size，表中的规则数等
	//通常情况下，private都指向一个xt_table_info{}类型的结构体变量 
	void *private;

	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	//如果要设计成模块，则为THIS_MODULE；否则为NULL
	struct module *me;

    //协议簇 ，如PF_INET(或PF_INET)
	int af;		/* address/protocol family */
};

#include <linux/netfilter_ipv4.h>

/* The table itself 
 * xt_table->private指针指向的数据
 *
 * 该结构描述了表中规则的一些基本信息，同时在该结构的末尾指示了该表中所有规则的入口点，
 * 即表中的第一条规则。记住：所有的规则是顺序依次存放的
 */
struct xt_table_info
{
	/* Size per table */
    //表的大小，即占用的内存空间
	unsigned int size;
	/* Number of entries: FIXME. --RR */
	//表中的规则数
	unsigned int number;
	/* Initial number of entries. Needed for module usage count */
	//初始的规则数，用于模块计数
	unsigned int initial_entries;

	/* Entry points and underflows */
	/* 记录所影响的HOOK的规则入口相对于下面的entries变量的偏移量*/
	unsigned int hook_entry[NF_IP_NUMHOOKS];
	/* 与hook_entry相对应的规则表上限偏移量，当无规则录入时，相应的hook_entry和underflow均为0 */
	unsigned int underflow[NF_IP_NUMHOOKS];

	/* ipt_entry tables: one per CPU */
	/*
	 * ipt_entry | ipt_entry_match | ipt_standard_target(xt_entry_target | verdict) | ipt_standard_target(xt_entry_target | verdict) |...
	 */
	char *entries[NR_CPUS];
};

extern int xt_register_target(struct xt_target *target);
extern void xt_unregister_target(struct xt_target *target);
extern int xt_register_targets(struct xt_target *target, unsigned int n);
extern void xt_unregister_targets(struct xt_target *target, unsigned int n);

extern int xt_register_match(struct xt_match *target);
extern void xt_unregister_match(struct xt_match *target);
extern int xt_register_matches(struct xt_match *match, unsigned int n);
extern void xt_unregister_matches(struct xt_match *match, unsigned int n);

extern int xt_check_match(const struct xt_match *match, unsigned short family,
			  unsigned int size, const char *table, unsigned int hook,
			  unsigned short proto, int inv_proto);
extern int xt_check_target(const struct xt_target *target, unsigned short family,
			   unsigned int size, const char *table, unsigned int hook,
			   unsigned short proto, int inv_proto);

extern int xt_register_table(struct xt_table *table,
			     struct xt_table_info *bootstrap,
			     struct xt_table_info *newinfo);
extern void *xt_unregister_table(struct xt_table *table);

extern struct xt_table_info *xt_replace_table(struct xt_table *table,
					      unsigned int num_counters,
					      struct xt_table_info *newinfo,
					      int *error);

extern struct xt_match *xt_find_match(int af, const char *name, u8 revision);
extern struct xt_target *xt_find_target(int af, const char *name, u8 revision);
extern struct xt_target *xt_request_find_target(int af, const char *name, 
						u8 revision);
extern int xt_find_revision(int af, const char *name, u8 revision, int target,
			    int *err);

extern struct xt_table *xt_find_table_lock(int af, const char *name);
extern void xt_table_unlock(struct xt_table *t);

extern int xt_proto_init(int af);
extern void xt_proto_fini(int af);

extern struct xt_table_info *xt_alloc_table_info(unsigned int size);
extern void xt_free_table_info(struct xt_table_info *info);

#ifdef CONFIG_COMPAT
#include <net/compat.h>

struct compat_xt_entry_match
{
	union {
		struct {
			u_int16_t match_size;
			char name[XT_FUNCTION_MAXNAMELEN - 1];
			u_int8_t revision;
		} user;
		struct {
			u_int16_t match_size;
			compat_uptr_t match;
		} kernel;
		u_int16_t match_size;
	} u;
	unsigned char data[0];
};

struct compat_xt_entry_target
{
	union {
		struct {
			u_int16_t target_size;
			char name[XT_FUNCTION_MAXNAMELEN - 1];
			u_int8_t revision;
		} user;
		struct {
			u_int16_t target_size;
			compat_uptr_t target;
		} kernel;
		u_int16_t target_size;
	} u;
	unsigned char data[0];
};

/* FIXME: this works only on 32 bit tasks
 * need to change whole approach in order to calculate align as function of
 * current task alignment */

struct compat_xt_counters
{
#if defined(CONFIG_X86_64) || defined(CONFIG_IA64)
	u_int32_t cnt[4];
#else
	u_int64_t cnt[2];
#endif
};

struct compat_xt_counters_info
{
	char name[XT_TABLE_MAXNAMELEN];
	compat_uint_t num_counters;
	struct compat_xt_counters counters[0];
};

#define COMPAT_XT_ALIGN(s) (((s) + (__alignof__(struct compat_xt_counters)-1)) \
		& ~(__alignof__(struct compat_xt_counters)-1))

extern void xt_compat_lock(int af);
extern void xt_compat_unlock(int af);

extern int xt_compat_match_offset(struct xt_match *match);
extern void xt_compat_match_from_user(struct xt_entry_match *m,
				      void **dstptr, int *size);
extern int xt_compat_match_to_user(struct xt_entry_match *m,
				   void __user **dstptr, int *size);

extern int xt_compat_target_offset(struct xt_target *target);
extern void xt_compat_target_from_user(struct xt_entry_target *t,
				       void **dstptr, int *size);
extern int xt_compat_target_to_user(struct xt_entry_target *t,
				    void __user **dstptr, int *size);

#endif /* CONFIG_COMPAT */
#endif /* __KERNEL__ */

#endif /* _X_TABLES_H */
