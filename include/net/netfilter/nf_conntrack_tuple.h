/*
 * Definitions and Declarations for tuple.
 *
 * 16 Dec 2003: Yasuyuki Kozakai @USAGI <yasuyuki.kozakai@toshiba.co.jp>
 *	- generalize L3 protocol dependent part.
 *
 * Derived from include/linux/netfiter_ipv4/ip_conntrack_tuple.h
 */

#ifndef _NF_CONNTRACK_TUPLE_H
#define _NF_CONNTRACK_TUPLE_H

#include <linux/netfilter/nf_conntrack_tuple_common.h>

/* A `tuple' is a structure containing the information to uniquely
  identify a connection.  ie. if two packets have the same tuple, they
  are in the same connection; if not, they are not.

  We divide the structure along "manipulatable" and
  "non-manipulatable" lines, for the benefit of the NAT code.
*/

#define NF_CT_TUPLE_L3SIZE	4

/* The l3 protocol-specific manipulable parts of the tuple: always in
   network order! */
union nf_conntrack_address {
	u_int32_t all[NF_CT_TUPLE_L3SIZE];
	__be32 ip;
	__be32 ip6[4];
};

/* The protocol-specific manipulable parts of the tuple: always in
   network order! */
union nf_conntrack_man_proto
{
	/* Add other protocols here. */
    /* 其他四层协议对应的识别信息，当不是tcp、udp、icmp、sctp时，
     * 使用该成员存储四层协议的识别信息
     */
	__be16 all;

	struct {
		__be16 port;
	} tcp;
	struct {
		__be16 port;
	} udp;
	struct {
		__be16 id;
	} icmp;
	struct {
		__be16 port;
	} sctp;
	struct {
		__be16 key;	/* GRE key is 32bit, PPtP only uses 16bit */
	} gre;
};

/* The manipulable part of the tuple. 
 * 该结构体主要用来存储一个三层ip地址、四层端口号、三层协议号等信息
 */
struct nf_conntrack_man
{
    
	/*三层协议相关的识别信息*/	
	union nf_conntrack_address u3;
	/*四层协议相关的识别信息*/
	union nf_conntrack_man_proto u;
	/* Layer 3 protocol */	
	/* 三层协议号 */	
	u_int16_t l3num;
};

/* This contains the information to distinguish a connection.  
 *
 * 该数据结构为将数据流抽象成连接跟踪项的归纳依据，
 * 根据该结构成员值，我们能唯一确定一个数据流。
 *
 * 该结构成员包括源ip地址、目的ip地址、源端口号/源序列、
 * 目的端口号/目的序列号、协议号等信息。以及最重要的，
 * 该tuple结构在所属的连接中是属于origin还是reply方向
 */
struct nf_conntrack_tuple
{
    
	/*源方向上的三层、四层协议相关的识别信息*/	
	struct nf_conntrack_man src;

	/* These are the parts of the tuple which are fixed. */
	
	/* 下面的信息时目的方向的三层、四层协议相关的识别信息*/	
	struct {
		union nf_conntrack_address u3;
		union {
			/* Add other protocols here. */		    
            /* 当四层协议不是tcp、udp、icmp、stcp时，
             * 则使用该成员存储四层协议识别信息
             */		
			__be16 all;

			struct {
				__be16 port;
			} tcp;
			struct {
				__be16 port;
			} udp;
			struct {
				u_int8_t type, code;
			} icmp;
			struct {
				__be16 port;
			} sctp;
			struct {
				__be16 key;
			} gre;
		} u;

		/* The protocol. */
		/* 四层协议号 */
		u_int8_t protonum;

		/* The direction (for tuplehash) */
		u_int8_t dir;
	} dst;
};

struct nf_conntrack_tuple_mask
{
	struct {
		union nf_conntrack_address u3;
		union nf_conntrack_man_proto u;
	} src;
};

/* This is optimized opposed to a memset of the whole structure.  Everything we
 * really care about is the  source/destination unions */
#define NF_CT_TUPLE_U_BLANK(tuple)                              	\
        do {                                                    	\
                (tuple)->src.u.all = 0;                         	\
                (tuple)->dst.u.all = 0;                         	\
		memset(&(tuple)->src.u3, 0, sizeof((tuple)->src.u3));	\
		memset(&(tuple)->dst.u3, 0, sizeof((tuple)->dst.u3));	\
        } while (0)

#ifdef __KERNEL__

#define NF_CT_DUMP_TUPLE(tp)						     \
pr_debug("tuple %p: %u %u " NIP6_FMT " %hu -> " NIP6_FMT " %hu\n",	     \
	 (tp), (tp)->src.l3num, (tp)->dst.protonum,			     \
	 NIP6(*(struct in6_addr *)(tp)->src.u3.all), ntohs((tp)->src.u.all), \
	 NIP6(*(struct in6_addr *)(tp)->dst.u3.all), ntohs((tp)->dst.u.all))

/* If we're the first tuple, it's the original dir. */
#define NF_CT_DIRECTION(h)						\
	((enum ip_conntrack_dir)(h)->tuple.dst.dir)

/* Connections have two entries in the hash table: one for each way
 * 存放nf_conntrack_tuple
 */
struct nf_conntrack_tuple_hash
{
	struct hlist_node hnode;
	struct nf_conntrack_tuple tuple;
};

#endif /* __KERNEL__ */

static inline int nf_ct_tuple_src_equal(const struct nf_conntrack_tuple *t1,
				        const struct nf_conntrack_tuple *t2)
{ 
	return (t1->src.u3.all[0] == t2->src.u3.all[0] &&
		t1->src.u3.all[1] == t2->src.u3.all[1] &&
		t1->src.u3.all[2] == t2->src.u3.all[2] &&
		t1->src.u3.all[3] == t2->src.u3.all[3] &&
		t1->src.u.all == t2->src.u.all &&
		t1->src.l3num == t2->src.l3num &&
		t1->dst.protonum == t2->dst.protonum);
}

static inline int nf_ct_tuple_dst_equal(const struct nf_conntrack_tuple *t1,
				        const struct nf_conntrack_tuple *t2)
{
	return (t1->dst.u3.all[0] == t2->dst.u3.all[0] &&
		t1->dst.u3.all[1] == t2->dst.u3.all[1] &&
		t1->dst.u3.all[2] == t2->dst.u3.all[2] &&
		t1->dst.u3.all[3] == t2->dst.u3.all[3] &&
		t1->dst.u.all == t2->dst.u.all &&
		t1->src.l3num == t2->src.l3num &&
		t1->dst.protonum == t2->dst.protonum);
}

/*
 * nf_conntrack_find_get()
 *	__nf_conntrack_find()
 *   nf_ct_tuple_equal()
 *
 */
static inline int nf_ct_tuple_equal(const struct nf_conntrack_tuple *t1,
				    const struct nf_conntrack_tuple *t2)
{
	return nf_ct_tuple_src_equal(t1, t2) && nf_ct_tuple_dst_equal(t1, t2);
}

static inline int nf_ct_tuple_mask_equal(const struct nf_conntrack_tuple_mask *m1,
					 const struct nf_conntrack_tuple_mask *m2)
{
	return (m1->src.u3.all[0] == m2->src.u3.all[0] &&
		m1->src.u3.all[1] == m2->src.u3.all[1] &&
		m1->src.u3.all[2] == m2->src.u3.all[2] &&
		m1->src.u3.all[3] == m2->src.u3.all[3] &&
		m1->src.u.all == m2->src.u.all);
}

static inline int nf_ct_tuple_src_mask_cmp(const struct nf_conntrack_tuple *t1,
					   const struct nf_conntrack_tuple *t2,
					   const struct nf_conntrack_tuple_mask *mask)
{
	int count;

	for (count = 0; count < NF_CT_TUPLE_L3SIZE; count++) {
		if ((t1->src.u3.all[count] ^ t2->src.u3.all[count]) &
		    mask->src.u3.all[count])
			return 0;
	}

	if ((t1->src.u.all ^ t2->src.u.all) & mask->src.u.all)
		return 0;

	if (t1->src.l3num != t2->src.l3num ||
	    t1->dst.protonum != t2->dst.protonum)
		return 0;

	return 1;
}

static inline int nf_ct_tuple_mask_cmp(const struct nf_conntrack_tuple *t,
				       const struct nf_conntrack_tuple *tuple,
				       const struct nf_conntrack_tuple_mask *mask)
{
	return nf_ct_tuple_src_mask_cmp(t, tuple, mask) &&
	       nf_ct_tuple_dst_equal(t, tuple);
}

#endif /* _NF_CONNTRACK_TUPLE_H */
