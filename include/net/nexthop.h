#ifndef __NET_NEXTHOP_H
#define __NET_NEXTHOP_H

#include <linux/rtnetlink.h>
#include <net/netlink.h>

/*
 * inet_ioctl()
 *  ip_rt_ioctl()
 *   fn_hash_insert()
 *    fib_create_info()
 *     fib_count_nexthops()
 *      rtnh_ok()
 */
static inline int rtnh_ok(const struct rtnexthop *rtnh, int remaining)
{
	return remaining >= sizeof(*rtnh) &&
	       rtnh->rtnh_len >= sizeof(*rtnh) &&
	       rtnh->rtnh_len <= remaining;
}

/*
 * inet_ioctl()
 *  ip_rt_ioctl()
 *   fn_hash_insert()
 *    fib_create_info()
 *     fib_count_nexthops()
 *      rtnh_next()
 */
static inline struct rtnexthop *rtnh_next(const struct rtnexthop *rtnh,
                                         int *remaining)
{
	int totlen = NLA_ALIGN(rtnh->rtnh_len);

	*remaining -= totlen;
	//下一个rtnexthop对象
	return (struct rtnexthop *) ((char *) rtnh + totlen);
}

static inline struct nlattr *rtnh_attrs(const struct rtnexthop *rtnh)
{
	return (struct nlattr *) ((char *) rtnh + NLA_ALIGN(sizeof(*rtnh)));
}

static inline int rtnh_attrlen(const struct rtnexthop *rtnh)
{
	return rtnh->rtnh_len - NLA_ALIGN(sizeof(*rtnh));
}

#endif
