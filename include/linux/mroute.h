#ifndef __LINUX_MROUTE_H
#define __LINUX_MROUTE_H

#include <linux/sockios.h>
#include <linux/in.h>

/*
 *	Based on the MROUTING 3.5 defines primarily to keep
 *	source compatibility with BSD.
 *
 *	See the mrouted code for the original history.
 *
 *      Protocol Independent Multicast (PIM) data structures included
 *      Carlos Picoto (cap@di.fc.ul.pt)
 *
 */

#define MRT_BASE	200
#define MRT_INIT	(MRT_BASE)	/* Activate the kernel mroute code 	*/
#define MRT_DONE	(MRT_BASE+1)	/* Shutdown the kernel mroute		*/
#define MRT_ADD_VIF	(MRT_BASE+2)	/* Add a virtual interface		*/
#define MRT_DEL_VIF	(MRT_BASE+3)	/* Delete a virtual interface		*/
#define MRT_ADD_MFC	(MRT_BASE+4)	/* Add a multicast forwarding entry	*/
#define MRT_DEL_MFC	(MRT_BASE+5)	/* Delete a multicast forwarding entry	*/
#define MRT_VERSION	(MRT_BASE+6)	/* Get the kernel multicast version	*/
#define MRT_ASSERT	(MRT_BASE+7)	/* Activate PIM assert mode		*/
#define MRT_PIM		(MRT_BASE+8)	/* enable PIM code	*/

#define SIOCGETVIFCNT	SIOCPROTOPRIVATE	/* IP protocol privates */
#define SIOCGETSGCNT	(SIOCPROTOPRIVATE+1)
#define SIOCGETRPF	(SIOCPROTOPRIVATE+2)

#define MAXVIFS		32	
typedef unsigned long vifbitmap_t;	/* User mode code depends on this lot */
typedef unsigned short vifi_t;
#define ALL_VIFS	((vifi_t)(-1))

/*
 *	Same idea as select
 */
 
#define VIFM_SET(n,m)	((m)|=(1<<(n)))
#define VIFM_CLR(n,m)	((m)&=~(1<<(n)))
#define VIFM_ISSET(n,m)	((m)&(1<<(n)))
#define VIFM_CLRALL(m)	((m)=0)
#define VIFM_COPY(mfrom,mto)	((mto)=(mfrom))
#define VIFM_SAME(m1,m2)	((m1)==(m2))

/*
 *	Passed by mrouted for an MRT_ADD_VIF - again we use the
 *	mrouted 3.6 structures for compatibility
 *
 *  添加和删除虚拟接口时用到本结构
 */
 
struct vifctl {
    // 虚拟结构的索引号
	vifi_t	vifc_vifi;		/* Index of VIF */
	// 标识虚拟接口类型
	unsigned char vifc_flags;	/* VIFF_ flags */
	// 组播报文TTL的阈值
	unsigned char vifc_threshold;	/* ttl limit */
	// 用于流水限制
	unsigned int vifc_rate_limit;	/* Rate limiter values (NI) */
	/*
	 * 当采用物理网络设备方式时，vifc_lcl_addr为网络设备的IP地址，vifc_rmt_addr无效
	 * 当采用IP-IP隧道方式时，vifc_lcl_addr为隧道起点，vifc_rmt_addr为隧道终点.
	 *
	 */
	struct in_addr vifc_lcl_addr;	/* Our address */
	struct in_addr vifc_rmt_addr;	/* IPIP tunnel addr */
};

#define VIFF_TUNNEL	0x1	/* IPIP tunnel */
#define VIFF_SRCRT	0x2	/* NI */
#define VIFF_REGISTER	0x4	/* register vif	*/

/*
 *	Cache manipulation structures for mrouted and PIMd
 */
 
struct mfcctl
{
	struct in_addr mfcc_origin;		/* Origin of mcast	*/
	struct in_addr mfcc_mcastgrp;		/* Group in question	*/
	vifi_t	mfcc_parent;			/* Where it arrived	*/
	unsigned char mfcc_ttls[MAXVIFS];	/* Where it is going	*/
	unsigned int mfcc_pkt_cnt;		/* pkt count for src-grp */
	unsigned int mfcc_byte_cnt;
	unsigned int mfcc_wrong_if;
	int	     mfcc_expire;
};

/* 
 *	Group count retrieval for mrouted
 */
 
struct sioc_sg_req
{
	struct in_addr src;
	struct in_addr grp;
	unsigned long pktcnt;
	unsigned long bytecnt;
	unsigned long wrong_if;
};

/*
 *	To get vif packet counts
 */

struct sioc_vif_req
{
	vifi_t	vifi;		/* Which iface */
	unsigned long icount;	/* In packets */
	unsigned long ocount;	/* Out packets */
	unsigned long ibytes;	/* In bytes */
	unsigned long obytes;	/* Out bytes */
};

/*
 *	This is the format the mroute daemon expects to see IGMP control
 *	data. Magically happens to be like an IP packet as per the original
 */
 
struct igmpmsg
{
	__u32 unused1,unused2;
	unsigned char im_msgtype;		/* What is this */
	unsigned char im_mbz;			/* Must be zero */
	unsigned char im_vif;			/* Interface (this ought to be a vifi_t!) */
	unsigned char unused3;
	struct in_addr im_src,im_dst;
};

/*
 *	That's all usermode folks
 */

#ifdef __KERNEL__
#include <net/sock.h>

#ifdef CONFIG_IP_MROUTE
static inline int ip_mroute_opt(int opt)
{
	return (opt >= MRT_BASE) && (opt <= MRT_BASE + 10);
}
#else
static inline int ip_mroute_opt(int opt)
{
	return 0;
}
#endif

extern int ip_mroute_setsockopt(struct sock *, int, char __user *, int);
extern int ip_mroute_getsockopt(struct sock *, int, char __user *, int __user *);
extern int ipmr_ioctl(struct sock *sk, int cmd, void __user *arg);
extern void ip_mr_init(void);


/*
 * 组播报文接口通过两条途径来收发:一是通过VLAN网络设备收发，二是打包成二级单播IP数据报，然后通过隧道传输。
 * vif_table[]中的每个虚拟接口都代表着一个物理设备或者一条隧道。
 *
 * 系统中所有的虚拟静态设备都存储在vif_table[]中
 */
struct vif_device
{   
    /* 该虚拟接口对应的物理网路设备 */
	struct net_device 	*dev;			/* Device we are using */
	/* 通过该虚拟接口输入和输出的组播报文总字节数 */
	unsigned long	bytes_in,bytes_out;
	/* 通过该虚拟接口输入和输出的组播报文总报文数  */
	unsigned long	pkt_in,pkt_out;		/* Statistics 			*/
	
	unsigned long	rate_limit;		/* Traffic shaping (NI) 	*/
    /* TTL阈值 */
	unsigned char	threshold;		/* TTL threshold 		*/
	/* 标识虚拟接口的类型 */
	unsigned short	flags;			/* Control flags 		*/
	/*
	 * 当采用物理网路设备方式时，local为网络设备的IP地址，remote无效
	 * 当采用IP-IP隧道方式时,local为隧道起点地址,remote为隧道终点地址.
	 */
	__be32		local,remote;		/* Addresses(remote for tunnels)*/
	/* 对应物理网路设备的索引 */
	int		link;			/* Physical interface index	*/
};

#define VIFF_STATIC 0x8000

/*
 * 组播转发缓存
 */
struct mfc_cache 
{
    /* 指向下一个组播转发缓存，用于构成组播转发缓存散列表 */
	struct mfc_cache *next;			/* Next entry on cache line 	*/
    /*
     * mfc_mcastgrp是组播报文的组播地址，mfc_origin是组播报文发送方的IP地址，
     * 两者结合构成组播转发缓存散列表的健值。
     */
	__be32 mfc_mcastgrp;			/* Group the entry belongs to 	*/
	__be32 mfc_origin;			/* Source of packet 		*/
	/*
	 * 虚拟接口在vif_table数组中的索引，正式该虚拟接口接收了存储在本组播转发缓存的报文。
	 */
	vifi_t mfc_parent;			/* Source interface		*/
	/*
	 * 组播转发缓存标志
	 */
	int mfc_flags;				/* Flags on line		*/

	union {
		struct {
			unsigned long expires;
			struct sk_buff_head unresolved;	/* Unresolved buffers		*/
		} unres; /* 组播路由守护进程mrouted仍然没有结束路由选择时,会用unres代表组播转发缓存中的缓存项，组播报文一旦到达某个虚拟接口，在组播转发缓存中会为此创建一个mfc_cache结构的缓存项 */
		struct {
			/* 记录最近一次发送警告消息的时间，用来控制发送警告消息的评率 */
			unsigned long last_assert;
			/*
			 * 用来限定目前可使用的虚拟接口的范围
			 */
			int minvif;
			int maxvif;
			/*
			 * 满足此组播缓存转发的组播报文的字节数总和
			 */
			unsigned long bytes;
			/*
			 * 满足此组播转发缓存的组播报文的个数总和
			 */
			unsigned long pkt;
			/*
			 * 在组播转发过程中，出现能找到组播报文转发路由
			 */
			unsigned long wrong_if;
			/*
			 * 用来确定是否用vif_table[]数组中下标相同的那个虚拟接口来转发报文
			 * 只有当组播报文的TTL值大于等于ttls[]数组中的元素时，才能由对应的虚拟接口转发报文。
			 */
			unsigned char ttls[MAXVIFS];	/* TTL thresholds		*/
		} res;
		
	} mfc_un;
};

#define MFC_STATIC		1
#define MFC_NOTIFY		2

#define MFC_LINES		64

#ifdef __BIG_ENDIAN
#define MFC_HASH(a,b)	(((((__force u32)(__be32)a)>>24)^(((__force u32)(__be32)b)>>26))&(MFC_LINES-1))
#else
#define MFC_HASH(a,b)	((((__force u32)(__be32)a)^(((__force u32)(__be32)b)>>2))&(MFC_LINES-1))
#endif		

#endif


#define MFC_ASSERT_THRESH (3*HZ)		/* Maximal freq. of asserts */

/*
 *	Pseudo messages used by mrouted
 */

#define IGMPMSG_NOCACHE		1		/* Kern cache fill request to mrouted */
#define IGMPMSG_WRONGVIF	2		/* For PIM assert processing (unused) */
#define IGMPMSG_WHOLEPKT	3		/* For PIM Register processing */

#ifdef __KERNEL__

#define PIM_V1_VERSION		__constant_htonl(0x10000000)
#define PIM_V1_REGISTER		1

#define PIM_VERSION		2
#define PIM_REGISTER		1

#define PIM_NULL_REGISTER	__constant_htonl(0x40000000)

/* PIMv2 register message header layout (ietf-draft-idmr-pimvsm-v2-00.ps */

struct pimreghdr
{
	__u8	type;
	__u8	reserved;
	__be16	csum;
	__be32	flags;
};

extern int pim_rcv_v1(struct sk_buff *);

struct rtmsg;
extern int ipmr_get_route(struct sk_buff *skb, struct rtmsg *rtm, int nowait);
#endif

#endif
