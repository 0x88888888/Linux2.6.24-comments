/* Header for use in defining a given protocol. */
#ifndef _NF_NAT_PROTOCOL_H
#define _NF_NAT_PROTOCOL_H
#include <net/netfilter/nf_nat.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

struct nf_nat_range;

/*
 * nf_nat_protocol , nf_nat_protos[]
 */
struct nf_nat_protocol
{
	/* Protocol name */
	const char *name;

	/* Protocol number. */
	unsigned int protonum;

	struct module *me;

	/* Translate a packet to the target according to manip type.
	   Return true if succeeded. */
	/*对数据包进行四层协议相关的关键字的NAT转换*/   	   
	int (*manip_pkt)(struct sk_buff *skb,
			 unsigned int iphdroff,
			 const struct nf_conntrack_tuple *tuple,
			 enum nf_nat_manip_type maniptype);

	/* Is the manipable part of the tuple between min and max incl? */
    /*
     * 判断一个连接跟踪的四层协议相关的关键字的值是否在合理的范围内
     */			 
	int (*in_range)(const struct nf_conntrack_tuple *tuple,
			enum nf_nat_manip_type maniptype,
			const union nf_conntrack_man_proto *min,
			const union nf_conntrack_man_proto *max);

	/* Alter the per-proto part of the tuple (depending on
	   maniptype), to give a unique tuple in the given range if
	   possible; return false if not.  Per-protocol part of tuple
	   is initialized to the incoming packet. */
    /*
     * 根据传递的tuple变量与range值，通过随机获取四层协议相关的关键字
     * 找到一个唯一的未被其他连接跟踪项使用的tuple变量。
     */ 	   
	int (*unique_tuple)(struct nf_conntrack_tuple *tuple,
			    const struct nf_nat_range *range,
			    enum nf_nat_manip_type maniptype,
			    const struct nf_conn *ct);

	/*netlink相关*/
	int (*range_to_nlattr)(struct sk_buff *skb,
			       const struct nf_nat_range *range);

	int (*nlattr_to_range)(struct nlattr *tb[],
			       struct nf_nat_range *range);
};

/* Protocol registration. */
extern int nf_nat_protocol_register(struct nf_nat_protocol *proto);
extern void nf_nat_protocol_unregister(struct nf_nat_protocol *proto);

extern struct nf_nat_protocol *nf_nat_proto_find_get(u_int8_t protocol);
extern void nf_nat_proto_put(struct nf_nat_protocol *proto);

/* Built-in protocols. */
extern struct nf_nat_protocol nf_nat_protocol_tcp;
extern struct nf_nat_protocol nf_nat_protocol_udp;
extern struct nf_nat_protocol nf_nat_protocol_icmp;
extern struct nf_nat_protocol nf_nat_unknown_protocol;

extern int init_protocols(void) __init;
extern void cleanup_protocols(void);
extern struct nf_nat_protocol *find_nat_proto(u_int16_t protonum);

extern int nf_nat_port_range_to_nlattr(struct sk_buff *skb,
				       const struct nf_nat_range *range);
extern int nf_nat_port_nlattr_to_range(struct nlattr *tb[],
				       struct nf_nat_range *range);

#endif /*_NF_NAT_PROTO_H*/
