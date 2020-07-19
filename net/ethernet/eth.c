/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Ethernet-type device handling.
 *
 * Version:	@(#)eth.c	1.0.7	05/25/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Florian  La Roche, <rzsfl@rz.uni-sb.de>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *
 * Fixes:
 *		Mr Linux	: Arp problems
 *		Alan Cox	: Generic queue tidyup (very tiny here)
 *		Alan Cox	: eth_header ntohs should be htons
 *		Alan Cox	: eth_rebuild_header missing an htons and
 *				  minor other things.
 *		Tegge		: Arp bug fixes.
 *		Florian		: Removed many unnecessary functions, code cleanup
 *				  and changes for new arp and skbuff.
 *		Alan Cox	: Redid header building to reflect new format.
 *		Alan Cox	: ARP only when compiled with CONFIG_INET
 *		Greg Page	: 802.2 and SNAP stuff.
 *		Alan Cox	: MAC layer pointers/new format.
 *		Paul Gortmaker	: eth_copy_and_sum shouldn't csum padding.
 *		Alan Cox	: Protect against forwarding explosions with
 *				  older network drivers and IFF_ALLMULTI.
 *	Christer Weinigel	: Better rebuild header message.
 *             Andrew Morton    : 26Feb01: kill ether_setup() - use netdev_boot_setup().
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/if_ether.h>
#include <net/dst.h>
#include <net/arp.h>
#include <net/sock.h>
#include <net/ipv6.h>
#include <net/ip.h>
#include <asm/uaccess.h>
#include <asm/system.h>

__setup("ether=", netdev_boot_setup);

/**
 * eth_header - create the Ethernet header
 * @skb:	buffer to alter
 * @dev:	source device
 * @type:	Ethernet type field
 * @daddr: destination address (NULL leave destination address)
 * @saddr: source address (NULL use device source address)
 * @len:   packet length (<= skb->len)
 *
 *
 * Set the protocol type. For a packet of type ETH_P_802_3 we put the length
 * in here instead. It is up to the 802.2 layer to carry protocol information.
 *
 * 构造以太网帧协议头
 */
int eth_header(struct sk_buff *skb, struct net_device *dev,
	       unsigned short type,
	       const void *daddr, const void *saddr, unsigned len)
{
	struct ethhdr *eth = (struct ethhdr *)skb_push(skb, ETH_HLEN);

	if (type != ETH_P_802_3)
		eth->h_proto = htons(type);
	else
		eth->h_proto = htons(len);

	/*
	 *      Set the source hardware address.
	 */

	if (!saddr)
		saddr = dev->dev_addr;
	memcpy(eth->h_source, saddr, ETH_ALEN);

	if (daddr) {
		memcpy(eth->h_dest, daddr, ETH_ALEN);
		return ETH_HLEN;
	}

	/*
	 *      Anyway, the loopback-device should never use this function...
	 */

	if (dev->flags & (IFF_LOOPBACK | IFF_NOARP)) {
		memset(eth->h_dest, 0, ETH_ALEN);
		return ETH_HLEN;
	}

	return -ETH_HLEN;
}
EXPORT_SYMBOL(eth_header);

/**
 * eth_rebuild_header- rebuild the Ethernet MAC header.
 * @skb: socket buffer to update
 *
 * This is called after an ARP or IPV6 ndisc it's resolution on this
 * sk_buff. We now let protocol (ARP) fill in the other fields.
 *
 * This routine CANNOT use cached dst->neigh!
 * Really, it is used only when dst->neigh is wrong.
 */
int eth_rebuild_header(struct sk_buff *skb)
{
	struct ethhdr *eth = (struct ethhdr *)skb->data;
	struct net_device *dev = skb->dev;

	switch (eth->h_proto) {
#ifdef CONFIG_INET
	case __constant_htons(ETH_P_IP):
		return arp_find(eth->h_dest, skb);
#endif
	default:
		printk(KERN_DEBUG
		       "%s: unable to resolve type %X addresses.\n",
		       dev->name, (int)eth->h_proto);

		memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
		break;
	}

	return 0;
}
EXPORT_SYMBOL(eth_rebuild_header);

/**
 * eth_type_trans - determine the packet's protocol ID.
 * @skb: received socket data
 * @dev: receiving network device
 *
 * The rule here is that we
 * assume 802.3 if the type field is short enough to be a length.
 * This is normal practice and works for any 'now in use' protocol.
 *
 * 对接受进来的数据帧设置skb->pkt_type 为PACKET_BROADCAST 或者PACKET_MULTICAST 或者PACKET_OTHERHOST
 *
 * net_interrupt()
 *  net_rx()
 *   eth_type_trans()
 */
__be16 eth_type_trans(struct sk_buff *skb, struct net_device *dev)
{
	struct ethhdr *eth;
	unsigned char *rawp;

	skb->dev = dev;
	skb_reset_mac_header(skb);
	/* 调用skb_pull后，data指针移动到ip包头部
	 * 这样可以访问IP层的字段了
	 */
	skb_pull(skb, ETH_HLEN);
	eth = eth_hdr(skb);

    /* 确定目的mac地址是单播，广播，还是多播 */
	if (is_multicast_ether_addr(eth->h_dest)) {
        /* 如果是多播地址，即bit0为1*/
	
		if (!compare_ether_addr(eth->h_dest, dev->broadcast))
			skb->pkt_type = PACKET_BROADCAST; //与设备的广播地址相同，则帧为广播帧
		else
			skb->pkt_type = PACKET_MULTICAST; //与设备的广播地址不同，则帧为多播帧
	}

	/*
	 *      This ALLMULTI check should be redundant by 1.4
	 *      so don't forget to remove it.
	 *
	 *      Seems, you forgot to remove it. All silly devices
	 *      seems to set IFF_PROMISC.
	 *
	 * 混杂模式下的处理
	 */
	else if (1 /*dev->flags&IFF_PROMISC */ ) {
		/* 如果数据帧的目的地址不是网卡的地址，那么数据帧的类型为PACKET_OTHERHOST */
		if (unlikely(compare_ether_addr(eth->h_dest, dev->dev_addr)))
			skb->pkt_type = PACKET_OTHERHOST; 

		/* 通常情况，skb->pkt_type为0，即PACKET_HOST，即数据帧是发给本主机的 */
	}

	
    /*
     当协议值大于1536时，那么这个数据帧一定为ethernet frame 
     因为802.2和802.3的对应域为帧长，均要小于或等于1500，而ethernet frame的协议类型都大于等于1536.
     */
	if (ntohs(eth->h_proto) >= 1536) /* 普通的Ethernet协议 */
		return eth->h_proto;

	rawp = skb->data;

	/* 下面的两种是Ethernet的变种
	 *
	 *      This is a magic hack to spot IPX packets. Older Novell breaks
	 *      the protocol design and runs IPX over 802.3 without an 802.2 LLC
	 *      layer. We look for FFFF which isn't a used 802.2 SSAP/DSAP. This
	 *      won't work for fault tolerant netware but does for the rest.
	 *
	 * 当IPX使用原始的802.3作为载体时，其头两个字节作为checksum，但是一般都设为0xffff。 
	 */
	if (*(unsigned short *)rawp == 0xFFFF)
		return htons(ETH_P_802_3); 

	/*
	 * Real 802.2 LLC
	 * LLC报头
	 */
	return htons(ETH_P_802_2);
}
EXPORT_SYMBOL(eth_type_trans);

/**
 * eth_header_parse - extract hardware address from packet
 * @skb: packet to extract header from
 * @haddr: destination buffer
 */
int eth_header_parse(const struct sk_buff *skb, unsigned char *haddr)
{
	const struct ethhdr *eth = eth_hdr(skb);
	memcpy(haddr, eth->h_source, ETH_ALEN);
	return ETH_ALEN;
}
EXPORT_SYMBOL(eth_header_parse);

/**
 * eth_header_cache - fill cache entry from neighbour
 * @neigh: source neighbour
 * @hh: destination cache entry
 * Create an Ethernet header template from the neighbour.
 */
int eth_header_cache(const struct neighbour *neigh, struct hh_cache *hh)
{
	__be16 type = hh->hh_type;
	struct ethhdr *eth;
	const struct net_device *dev = neigh->dev;

	eth = (struct ethhdr *)
	    (((u8 *) hh->hh_data) + (HH_DATA_OFF(sizeof(*eth))));

	if (type == htons(ETH_P_802_3))
		return -1;

	eth->h_proto = type;
	memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
	memcpy(eth->h_dest, neigh->ha, ETH_ALEN);
	hh->hh_len = ETH_HLEN;
	return 0;
}
EXPORT_SYMBOL(eth_header_cache);

/**
 * eth_header_cache_update - update cache entry
 * @hh: destination cache entry
 * @dev: network device
 * @haddr: new hardware address
 *
 * Called by Address Resolution module to notify changes in address.
 */
void eth_header_cache_update(struct hh_cache *hh,
			     const struct net_device *dev,
			     const unsigned char *haddr)
{
	memcpy(((u8 *) hh->hh_data) + HH_DATA_OFF(sizeof(struct ethhdr)),
	       haddr, ETH_ALEN);
}
EXPORT_SYMBOL(eth_header_cache_update);

/**
 * eth_mac_addr - set new Ethernet hardware address
 * @dev: network device
 * @p: socket address
 * Change hardware address of device.
 *
 * This doesn't change hardware matching, so needs to be overridden
 * for most real devices.
 */
static int eth_mac_addr(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	if (netif_running(dev))
		return -EBUSY;
	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;
	memcpy(dev->dev_addr, addr->sa_data, ETH_ALEN);
	return 0;
}

/**
 * eth_change_mtu - set new MTU size
 * @dev: network device
 * @new_mtu: new Maximum Transfer Unit
 *
 * Allow changing MTU size. Needs to be overridden for devices
 * supporting jumbo frames.
 */
static int eth_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < 68 || new_mtu > ETH_DATA_LEN)
		return -EINVAL;
	dev->mtu = new_mtu;
	return 0;
}

static int eth_validate_addr(struct net_device *dev)
{
	if (!is_valid_ether_addr(dev->dev_addr))
		return -EINVAL;

	return 0;
}

const struct header_ops eth_header_ops ____cacheline_aligned = {
	.create		= eth_header,
	.parse		= eth_header_parse,
	.rebuild	= eth_rebuild_header,
	.cache		= eth_header_cache,
	.cache_update	= eth_header_cache_update,
};

/**
 * ether_setup - setup Ethernet network device
 * @dev: network device
 * Fill in the fields of the device structure with Ethernet-generic values.
 *
 * e1000_probe()
 *  alloc_etherdev()
 *   alloc_etherdev_mq()
 *    alloc_netdev_mq(setup == ether_setup)
 *     ether_setup()
 *
 * 将dev初始化为ether设备哦
 */
void ether_setup(struct net_device *dev)
{
	dev->header_ops		= &eth_header_ops;

	dev->change_mtu		= eth_change_mtu;
	dev->set_mac_address 	= eth_mac_addr;
	dev->validate_addr	= eth_validate_addr;

	dev->type		= ARPHRD_ETHER;
	dev->hard_header_len 	= ETH_HLEN;
	dev->mtu		= ETH_DATA_LEN;
	dev->addr_len		= ETH_ALEN;
	dev->tx_queue_len	= 1000;	/* Ethernet wants good queues */
	dev->flags		= IFF_BROADCAST|IFF_MULTICAST;

	memset(dev->broadcast, 0xFF, ETH_ALEN);

}
EXPORT_SYMBOL(ether_setup);

/**
 * alloc_etherdev_mq - Allocates and sets up an Ethernet device
 * @sizeof_priv: Size of additional driver-private structure to be allocated
 *	for this Ethernet device
 * @queue_count: The number of queues this device has.
 *
 * Fill in the fields of the device structure with Ethernet-generic
 * values. Basically does everything except registering the device.
 *
 * Constructs a new net device, complete with a private data area of
 * size (sizeof_priv).  A 32-byte (not bit) alignment is enforced for
 * this private data area.
 *
 * e1000_probe()
 *  alloc_etherdev()
 *   alloc_etherdev_mq()
 */
struct net_device *alloc_etherdev_mq(int sizeof_priv, unsigned int queue_count)
{
	return alloc_netdev_mq(sizeof_priv, "eth%d", ether_setup, queue_count);
}
EXPORT_SYMBOL(alloc_etherdev_mq);

char *print_mac(char *buf, const u8 *addr)
{
	sprintf(buf, MAC_FMT,
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return buf;
}
EXPORT_SYMBOL(print_mac);
