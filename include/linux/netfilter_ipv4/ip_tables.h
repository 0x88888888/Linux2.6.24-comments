/*
 * 25-Jul-1998 Major changes to allow for ip chain table
 *
 * 3-Jan-2000 Named tables to allow packet selection for different uses.
 */

/*
 * 	Format of an IP firewall descriptor
 *
 * 	src, dst, src_mask, dst_mask are always stored in network byte order.
 * 	flags are stored in host byte order (of course).
 * 	Port numbers are stored in HOST byte order.
 */

#ifndef _IPTABLES_H
#define _IPTABLES_H

#ifdef __KERNEL__
#include <linux/if.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#endif
#include <linux/compiler.h>
#include <linux/netfilter_ipv4.h>

#include <linux/netfilter/x_tables.h>

#define IPT_FUNCTION_MAXNAMELEN XT_FUNCTION_MAXNAMELEN
#define IPT_TABLE_MAXNAMELEN XT_TABLE_MAXNAMELEN
#define ipt_match xt_match
#define ipt_target xt_target
#define ipt_table xt_table
#define ipt_get_revision xt_get_revision

/* Yes, Virginia, you have to zero the padding. 
 *
 * ipt_entry中的成员
 *
 * 标准match匹配主要用于匹配由struct ipt_ip{}所定义的数据包的特征项。标准匹配的内核数据结构就是我们上面所看到的ipt_match{}定义在include/linux/netfilter/ip_tables.h。在所有的表中我们最后真正所用到的match结构为ipt_entry_match{}
 *
 */
struct ipt_ip {
	/* Source and destination IP addr */
	/* 源、目的ip地址 */
	struct in_addr src, dst;
	/* Mask for src and dest IP addr */
    /* 源、目的ip地址的掩码*/
	struct in_addr smsk, dmsk;
    /*数据包入口、出口的网络接口名称*/
	char iniface[IFNAMSIZ], outiface[IFNAMSIZ];
	/*入口、出口的网络接口掩码*/
	unsigned char iniface_mask[IFNAMSIZ], outiface_mask[IFNAMSIZ];

	/* Protocol, 0 = ANY */
    /*协议号*/
	u_int16_t proto;

	/* Flags word */
	u_int8_t flags;
	/* Inverse flags */
    /*是否是反转匹配*/
	u_int8_t invflags;
};

/*
 * 防火墙规则的匹配部分
 */
#define ipt_entry_match xt_entry_match
/*
 * 表示防火墙规则的动作处理部分
 */
#define ipt_entry_target xt_entry_target
#define ipt_standard_target xt_standard_target

#define ipt_counters xt_counters

/* Values for "flag" field in struct ipt_ip (general ip structure). */
#define IPT_F_FRAG		0x01	/* Set if rule is a fragment rule */
#define IPT_F_GOTO		0x02	/* Set if jump is a goto */
#define IPT_F_MASK		0x03	/* All possible flag bits mask. */

/* Values for "inv" field in struct ipt_ip. */
#define IPT_INV_VIA_IN		0x01	/* Invert the sense of IN IFACE. */
#define IPT_INV_VIA_OUT		0x02	/* Invert the sense of OUT IFACE */
#define IPT_INV_TOS		0x04	/* Invert the sense of TOS. */
#define IPT_INV_SRCIP		0x08	/* Invert the sense of SRC IP. */
#define IPT_INV_DSTIP		0x10	/* Invert the sense of DST OP. */
#define IPT_INV_FRAG		0x20	/* Invert the sense of FRAG. */
#define IPT_INV_PROTO		XT_INV_PROTO
#define IPT_INV_MASK		0x7F	/* All possible flag bits mask. */

/* This structure defines each of the firewall rules.  Consists of 3
   parts which are 1) general IP header stuff 2) match specific
   stuff 3) the target to perform if the rule matches 
 *
 * iptable中的一个entry
 *
 * ipt_entry：标准匹配结构，主要包含数据包的源、目的IP，出、入接口和掩码等；
 * ipt_entry_match：扩展匹配。一条rule规则可能有零个或多个ipt_entry_match结构；
 * ipt_entry_target：一条rule规则有且仅有一个target动作。就是当所有的标准匹配和扩展匹配都符合之后才来执行该target。 
 *
 * 
 * 规则按照所关注的HOOK点，被放置在struct ipt_table::private->entries之后的区域，比邻排列。
 */ 
 
struct ipt_entry
{
    /* 所要匹配的报文的IP头信息 */
	struct ipt_ip ip;

	/* Mark with fields that we care about. */
    /* 位向量，标示本规则关心报文的什么部分，暂未使用 */
	unsigned int nfcache;

	/* Size of ipt_entry + matches */
	/* target区的偏移，通常target区位于match区之后，而match区则在ipt_entry的末尾； 初始化为sizeof(struct ipt_entry)，即假定没有match */
	/*该规则中target结构相对于该ipt_entry首地址的偏移量*/
	u_int16_t target_offset;
	/* Size of ipt_entry + matches + target */
	/* 下一条规则相对于本规则的偏移，也即本规则所用空间的总和， 初始化为sizeof(struct ipt_entry)+sizeof(struct ipt_target)，即没有match */
	u_int16_t next_offset;

	/* Back pointer */
	
    /*
     * 这个变量的用途有两个：
     * 1.判断table表中的规则链是否存在环路
     * 2.遍历规则链链时，用于用户自定义链的规则执行完时返回到主链时使用
     */
	unsigned int comefrom;

	/* Packet and byte counters. */
	/* 记录该规则处理过的报文数和报文总字节数 */
	struct xt_counters counters;

	/* The matches (if any), then the target. */
	/*target或者是match的起始位置 */
	/*由于在设计时需要match结构与ipt_entry的内存是连续的，但是一个ipt_entry包含的match个数又是可变的，所以定义了一个可变长度数组elems，主要是为了实现动态的申请match内存空间*/
	unsigned char elems[0];
};

/*
 * New IP firewall options for [gs]etsockopt at the RAW IP level.
 * Unlike BSD Linux inherits IP options so you don't have to use a raw
 * socket for this. Instead we check rights in the calls.
 *
 * ATTENTION: check linux/in.h before adding new number here.
 */
#define IPT_BASE_CTL		64

#define IPT_SO_SET_REPLACE	(IPT_BASE_CTL)
#define IPT_SO_SET_ADD_COUNTERS	(IPT_BASE_CTL + 1)
#define IPT_SO_SET_MAX		IPT_SO_SET_ADD_COUNTERS

#define IPT_SO_GET_INFO			(IPT_BASE_CTL)
#define IPT_SO_GET_ENTRIES		(IPT_BASE_CTL + 1)
#define IPT_SO_GET_REVISION_MATCH	(IPT_BASE_CTL + 2)
#define IPT_SO_GET_REVISION_TARGET	(IPT_BASE_CTL + 3)
#define IPT_SO_GET_MAX			IPT_SO_GET_REVISION_TARGET

#define IPT_CONTINUE XT_CONTINUE
#define IPT_RETURN XT_RETURN

#include <linux/netfilter/xt_tcpudp.h>
#define ipt_udp xt_udp
#define ipt_tcp xt_tcp

#define IPT_TCP_INV_SRCPT	XT_TCP_INV_SRCPT
#define IPT_TCP_INV_DSTPT	XT_TCP_INV_DSTPT
#define IPT_TCP_INV_FLAGS	XT_TCP_INV_FLAGS
#define IPT_TCP_INV_OPTION	XT_TCP_INV_OPTION
#define IPT_TCP_INV_MASK	XT_TCP_INV_MASK

#define IPT_UDP_INV_SRCPT	XT_UDP_INV_SRCPT
#define IPT_UDP_INV_DSTPT	XT_UDP_INV_DSTPT
#define IPT_UDP_INV_MASK	XT_UDP_INV_MASK

/* ICMP matching stuff */
struct ipt_icmp
{
	u_int8_t type;				/* type to match */
	u_int8_t code[2];			/* range of code */
	u_int8_t invflags;			/* Inverse flags */
};

/* Values for "inv" field for struct ipt_icmp. */
#define IPT_ICMP_INV	0x01	/* Invert the sense of type/code test */

/* The argument to IPT_SO_GET_INFO */
struct ipt_getinfo
{
	/* Which table: caller fills this in. */
	char name[IPT_TABLE_MAXNAMELEN];

	/* Kernel fills these in. */
	/* Which hook entry points are valid: bitmask */
	unsigned int valid_hooks;

	/* Hook entry points: one per netfilter hook. */
	unsigned int hook_entry[NF_IP_NUMHOOKS];

	/* Underflow points. */
	unsigned int underflow[NF_IP_NUMHOOKS];

	/* Number of entries */
	unsigned int num_entries;

	/* Size of entries. */
	unsigned int size;
};

/* The argument to IPT_SO_SET_REPLACE. 
 * 在调用ipt_register_table时作为参数用
 *
 * 在我们创建一个xt_table,或者替换掉一个xt_table里的规则时，就会用到这个结构体
 */
struct ipt_replace
{
	/* Which table. */
	//表的名字
	char name[IPT_TABLE_MAXNAMELEN];

	/* Which hook entry points are valid: bitmask.  You can't
           change this. */
    //所影响的HOOK点       
	unsigned int valid_hooks;

	/* Number of entries */
	//表中的规则数目
	unsigned int num_entries;

	/* Total size of new entries */
	//新规则所占用存储空间的大小
	unsigned int size;

	/* Hook entry points. */
	//进入HOOK的入口点
	unsigned int hook_entry[NF_IP_NUMHOOKS];

	/* Underflow points. */
	unsigned int underflow[NF_IP_NUMHOOKS];

	/* Information about old entries: */
	/* Number of counters (must be equal to current number of entries). */
	/* 这个结构不同于ipt_table_info之处在于它还要保存旧的规则信息*/
	unsigned int num_counters;
	/* The old entries' counters. */
	struct xt_counters __user *counters;

	/* The entries (hang off end: not really an array). */
	/*
     * 表中的每一个规则的结构为ipt_entry+ipt_entry_match(大于等于0个)+ipt_standard_target
     * 而ipt_standard_target由xt_entry_target与verdict 组成可变长数组，
     * 下面内存里存放的就是需要替换到表中的新的规则。
     *
     * ipt_entry | ipt_entry_match | ipt_standard_target(xt_entry_target | verdict) | ipt_standard_target(xt_entry_target | verdict) |...
     */
	struct ipt_entry entries[0];
};

/* The argument to IPT_SO_ADD_COUNTERS. */
#define ipt_counters_info xt_counters_info

/* The argument to IPT_SO_GET_ENTRIES. */
struct ipt_get_entries
{
	/* Which table: user fills this in. */
	char name[IPT_TABLE_MAXNAMELEN];

	/* User fills this in: total entry size. */
	unsigned int size;

	/* The entries. */
	struct ipt_entry entrytable[0];
};

/* Standard return verdict, or do jump. */
#define IPT_STANDARD_TARGET XT_STANDARD_TARGET
/* Error verdict. */
#define IPT_ERROR_TARGET XT_ERROR_TARGET

/* Helper functions */
static __inline__ struct ipt_entry_target *
ipt_get_target(struct ipt_entry *e)
{
	return (void *)e + e->target_offset;
}

/* fn returns 0 to continue iteration */
#define IPT_MATCH_ITERATE(e, fn, args...)	\
({						\
	unsigned int __i;			\
	int __ret = 0;				\
	struct ipt_entry_match *__match;	\
						\
	for (__i = sizeof(struct ipt_entry);	\
	     __i < (e)->target_offset;		\
	     __i += __match->u.match_size) {	\
		__match = (void *)(e) + __i;	\
						\
		__ret = fn(__match , ## args);	\
		if (__ret != 0)			\
			break;			\
	}					\
	__ret;					\
})

/* fn returns 0 to continue iteration */
/*

功能如函数名称:

遍历所有的ipt_entry:

1、检查从entry0到entry0 + size之间每一个ipt_entry变量的大小是否符 合要求，以及每一个ipt_entry的起始地址的对齐

2、判断相邻的ipt_entry的offset值是否正确，在正确的情况下将offset 值设置到相应的newinfo->hook_entry[]、newinfo->underflow[]

*/		
#define IPT_ENTRY_ITERATE(entries, size, fn, args...)		\
({								\
	unsigned int __i;					\
	int __ret = 0;						\
	struct ipt_entry *__entry;				\
								\
	for (__i = 0; __i < (size); __i += __entry->next_offset) { \
		__entry = (void *)(entries) + __i;		\
								\
		__ret = fn(__entry , ## args);			\
		if (__ret != 0)					\
			break;					\
	}							\
	__ret;							\
})

/* fn returns 0 to continue iteration */
#define IPT_ENTRY_ITERATE_CONTINUE(entries, size, n, fn, args...) \
({								\
	unsigned int __i, __n;					\
	int __ret = 0;						\
	struct ipt_entry *__entry;				\
								\
	for (__i = 0, __n = 0; __i < (size);			\
	     __i += __entry->next_offset, __n++) { 		\
		__entry = (void *)(entries) + __i;		\
		if (__n < n)					\
			continue;				\
								\
		__ret = fn(__entry , ## args);			\
		if (__ret != 0)					\
			break;					\
	}							\
	__ret;							\
})

/*
 *	Main firewall chains definitions and global var's definitions.
 */
#ifdef __KERNEL__

#include <linux/init.h>
extern void ipt_init(void) __init;

extern int ipt_register_table(struct xt_table *table,
			      const struct ipt_replace *repl);
extern void ipt_unregister_table(struct xt_table *table);

/* Standard entry. */
struct ipt_standard
{
	struct ipt_entry entry;
	struct ipt_standard_target target;
};

struct ipt_error_target
{
	struct ipt_entry_target target;
	char errorname[IPT_FUNCTION_MAXNAMELEN];
};

struct ipt_error
{
	struct ipt_entry entry;
	struct ipt_error_target target;
};

#define IPT_ENTRY_INIT(__size)						       \
{									       \
	.target_offset	= sizeof(struct ipt_entry),			       \
	.next_offset	= (__size),					       \
}

#define IPT_STANDARD_INIT(__verdict)					       \
{									       \
	.entry		= IPT_ENTRY_INIT(sizeof(struct ipt_standard)),	       \
	.target		= XT_TARGET_INIT(IPT_STANDARD_TARGET,		       \
					 sizeof(struct xt_standard_target)),   \
	.target.verdict	= -(__verdict) - 1,				       \
}

#define IPT_ERROR_INIT							       \
{									       \
	.entry		= IPT_ENTRY_INIT(sizeof(struct ipt_error)),	       \
	.target		= XT_TARGET_INIT(IPT_ERROR_TARGET,		       \
					 sizeof(struct ipt_error_target)),     \
	.target.errorname = "ERROR",					       \
}

extern unsigned int ipt_do_table(struct sk_buff *skb,
				 unsigned int hook,
				 const struct net_device *in,
				 const struct net_device *out,
				 struct xt_table *table);

#define IPT_ALIGN(s) XT_ALIGN(s)

#ifdef CONFIG_COMPAT
#include <net/compat.h>

struct compat_ipt_entry
{
	struct ipt_ip ip;
	compat_uint_t nfcache;
	u_int16_t target_offset;
	u_int16_t next_offset;
	compat_uint_t comefrom;
	struct compat_xt_counters counters;
	unsigned char elems[0];
};

#define COMPAT_IPT_ALIGN(s) 	COMPAT_XT_ALIGN(s)

#endif /* CONFIG_COMPAT */
#endif /*__KERNEL__*/
#endif /* _IPTABLES_H */
