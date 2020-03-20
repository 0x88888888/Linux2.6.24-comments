/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The options processing module for ip.c
 *
 * Version:	$Id: ip_options.c,v 1.21 2001/09/01 00:31:50 davem Exp $
 *
 * Authors:	A.N.Kuznetsov
 *
 */

#include <linux/capability.h>
#include <linux/module.h>
#include <linux/types.h>
#include <asm/uaccess.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/cipso_ipv4.h>

/*
 * Write options to IP header, record destination address to
 * source route option, address of outgoing interface
 * (we should already know it, so that this  function is allowed be
 * called only after routing decision) and timestamp,
 * if we originate this datagram.
 *
 * daddr is real destination address, next hop is recorded in IP header.
 * saddr is address of outgoing interface.
 *
 *
 * ip_build_and_send_pkt
 * ip_queue_xmit
 * ip_push_pending_frames
 *  ip_options_build()
 *
 */

void ip_options_build(struct sk_buff * skb, struct ip_options * opt,
			    __be32 daddr, struct rtable *rt, int is_frag)
{
    // 取得ip首部
	unsigned char *iph = skb_network_header(skb);

    /*
     * 将源ip选项信息块及其后面紧跟的选项数据复制到SKB对应的存储区中，
     * 并将opt指向SKB中的ip_options结构。
     * 注意:这里该结构的is_data字段是设置为0的，也就是说此结构后不跟选项内容，
     * SKB中选项信息和选项内容是分别存放的。
     */
    
	memcpy(&(IPCB(skb)->opt), opt, sizeof(struct ip_options));
	memcpy(iph+sizeof(struct iphdr), opt->__data, opt->optlen);
	opt = &(IPCB(skb)->opt);
	opt->is_data = 0;

    /* 
     * 有严格源路由选项,则将目的地址复制到源路由选项地址列表的末尾
     * iph[opt->srr+1]是取得该选项的长度。
     */
	if (opt->srr)
		memcpy(iph+opt->srr+iph[opt->srr+1]-4, &daddr, 4);

   /*
    * 如果该数据报不是IP分片，且存在记录路由/时间戳选项，则通过输出路由缓存
    * 获取源地址填写到记录路由选项/时间戳选项的地址部分中，获取当前的时间填写到时间戳选项中。
    */
	if (!is_frag) {
		if (opt->rr_needaddr)
			ip_rt_get_source(iph+opt->rr+iph[opt->rr+2]-5, rt);
		if (opt->ts_needaddr)
			ip_rt_get_source(iph+opt->ts+iph[opt->ts+2]-9, rt);
		if (opt->ts_needtime) {
			struct timeval tv;
			__be32 midtime;
			do_gettimeofday(&tv);
			midtime = htonl((tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000);
			memcpy(iph+opt->ts+iph[opt->ts+2]-5, &midtime, 4);
		}
		return;
	}
	//如果该数据报不是IP分片，但存在记录路由/时间戳选项，则将这些选项替换成无操作。
	if (opt->rr) {
		memset(iph+opt->rr, IPOPT_NOP, iph[opt->rr+1]);
		opt->rr = 0;
		opt->rr_needaddr = 0;
	}
	
	if (opt->ts) {
		memset(iph+opt->ts, IPOPT_NOP, iph[opt->ts+1]);
		opt->ts = 0;
		opt->ts_needaddr = opt->ts_needtime = 0;
	}
}

/*
 * Provided (sopt, skb) points to received options,
 * build in dopt compiled option set appropriate for answering.
 * i.e. invert SRR option, copy anothers,
 * and grab room in RR/TS options.
 *
 * NOTE: dopt cannot point to skb.
 */

int ip_options_echo(struct ip_options * dopt, struct sk_buff * skb)
{
	struct ip_options *sopt;
	unsigned char *sptr, *dptr;
	int soffset, doffset;
	int	optlen;
	__be32	daddr;

	memset(dopt, 0, sizeof(struct ip_options));

	dopt->is_data = 1;

	sopt = &(IPCB(skb)->opt);

    //数据报中没有IP选项数据
	if (sopt->optlen == 0) {
		dopt->optlen = 0;
		return 0;
	}

	sptr = skb_network_header(skb);
	dptr = dopt->__data;

    /* 获取该数据报中IP首部的起始地址，以及复制选项数据的目标起始地址。 */
	if (skb->dst)
		daddr = ((struct rtable*)skb->dst)->rt_spec_dst;
	else
		daddr = ip_hdr(skb)->daddr;

    /* 复制记录路由选项 */
	if (sopt->rr) {
		optlen  = sptr[sopt->rr+1];
		soffset = sptr[sopt->rr+2];
		dopt->rr = dopt->optlen + sizeof(struct iphdr);
        /* 将数据报中的记录路径选项内容复制到目标选项信息块dopt的__data字段开始的区域中 */
		memcpy(dptr, sptr+sopt->rr, optlen);
		
		if (sopt->rr_needaddr && soffset <= optlen) {
			if (soffset + 3 > optlen)
				return -EINVAL; //没有足够的空间放下一个地址值了。
			//更新选项中的值
			dptr[2] = soffset + 4;
			dopt->rr_needaddr = 1;
		}
		
		dptr += optlen;
		dopt->optlen += optlen;
	}
	if (sopt->ts) {
		optlen = sptr[sopt->ts+1];
		soffset = sptr[sopt->ts+2];
		dopt->ts = dopt->optlen + sizeof(struct iphdr);
		/* 将数据报ip首部中的时间戳选项内容复制到目标选项信息块dopt后数据区域中 */
		memcpy(dptr, sptr+sopt->ts, optlen);
		
		if (soffset <= optlen) {
			if (sopt->ts_needaddr) {
				
				if (soffset + 3 > optlen)
					return -EINVAL; //剩余的空间不够容纳一个ip地址了

				//有足够的空间容纳下一个ip地址了
				dopt->ts_needaddr = 1;
				soffset += 4;
			}

			
			if (sopt->ts_needtime) { //在需要记录时间戳的情况下，当选项标志位0或者1时，或当选项标志为3而指针指向的地址类型不是RTN_LOCAL时，即本地不是数据报的接收方，才设置ts_needtime=1
			  
				if (soffset + 3 > optlen)
					return -EINVAL;
				if ((dptr[3]&0xF) != IPOPT_TS_PRESPEC) {
					dopt->ts_needtime = 1;
					soffset += 4;
				} else {
					dopt->ts_needtime = 0;

					if (soffset + 8 <= optlen) {
						__be32 addr;

						memcpy(&addr, sptr+soffset-1, 4);
						if (inet_addr_type(addr) != RTN_LOCAL) {
							dopt->ts_needtime = 1;
							soffset += 8;
						}
					}
				}
			}
			//更新时间戳选项的指针值
			dptr[2] = soffset;
		}
		//将指针移动到下一个选项处，并处理更新选项长度
		dptr += optlen;
		dopt->optlen += optlen;
	}

	//复制路由选项
	if (sopt->srr) {
		//从IP首部中复制源路由选项到IP选项信息块的存储区域中。
		unsigned char * start = sptr+sopt->srr;
		__be32 faddr;

		optlen  = start[1];
		soffset = start[2];
		doffset = 0;
		if (soffset > optlen)
			soffset = optlen + 1;
		soffset -= 4;
		if (soffset > 3) {
			memcpy(&faddr, &start[soffset-1], 4);
			for (soffset-=4, doffset=4; soffset > 3; soffset-=4, doffset+=4)
				memcpy(&dptr[doffset-1], &start[soffset-1], 4);
			/*
			 * RFC1812 requires to fix illegal source routes.
			 */
			if (memcmp(&ip_hdr(skb)->saddr,
				   &start[soffset + 3], 4) == 0)
				doffset -= 4;
		}
		/*
		 * 如果成功复制源路由选项，则更新目标ip_options结构和目标选线区域中的一些字段
		 */
		if (doffset > 3) {
			memcpy(&start[doffset-1], &daddr, 4);
			dopt->faddr = faddr;
			dptr[0] = start[0];
			dptr[1] = doffset+3;
			dptr[2] = 4;
			dptr += doffset+3;
			dopt->srr = dopt->optlen + sizeof(struct iphdr);
			dopt->optlen += doffset+3;
			dopt->is_strictroute = sopt->is_strictroute;
		}
	}

	//复制商业IP安全选项
	//从IP首部中复制商业IP安全选项到IP选项信息块中
	if (sopt->cipso) {
		optlen  = sptr[sopt->cipso+1];
		dopt->cipso = dopt->optlen+sizeof(struct iphdr);
		memcpy(dptr, sptr+sopt->cipso, optlen);
		dptr += optlen;
		dopt->optlen += optlen;
	}
	
	while (dopt->optlen & 3) {
		*dptr++ = IPOPT_END;
		dopt->optlen++;
	}
	return 0;
}

/*
 *	Options "fragmenting", just fill options not
 *	allowed in fragments with NOOPs.
 *	Simple and stupid 8), but the most efficient way.
 *
 *  用来清理掉复制标志位0的选项，将他们填充为无操作，
 *  因为这些选项对一个完整的IP数据报只需处理一次，而无需对每个分片都处理。
 *  这样的选项其实也就包括了时间戳选项和记录路由选项，通过这种方法使协议首部的长度保持不变，只需重新计算校验和。
 *  
 *
 *  ip_fragment()
 *   ip_options_fragment()
 *
 */
void ip_options_fragment(struct sk_buff * skb)
{
	unsigned char *optptr = skb_network_header(skb) + sizeof(struct iphdr);
	struct ip_options * opt = &(IPCB(skb)->opt);
	int  l = opt->optlen;
	int  optlen;

    /*
     * 遍历所有的选项，直到遇到选项列表结束符返回.
     */
	while (l > 0) {
		switch (*optptr) {
		case IPOPT_END:
			return;
		case IPOPT_NOOP:
			l--;
			optptr++;
			continue;
		}
		optlen = optptr[1];
		if (optlen<2 || optlen>l)
		  return;
		if (!IPOPT_COPIED(*optptr))
			memset(optptr, IPOPT_NOOP, optlen);
		l -= optlen;
		optptr += optlen;
	}
	//修改SKB中对应的选项信息标志。
	opt->ts = 0;
	opt->rr = 0;
	opt->rr_needaddr = 0;
	opt->ts_needaddr = 0;
	opt->ts_needtime = 0;
	return;
}

/*
 * Verify options and fill pointers in struct options.
 * Caller should clear *opt, and set opt->data.
 * If opt == NULL, then skb->data should point to IP header.
 *
 * 发送时,待解析的IP选项存储在参数opt->__data字段的起始区域中,解析得到的信息会保存到opt中.
 * 接收时,IP选项存储在参数skb的skb->network_header指向的ip首部中，解析得到的信息则会保存在skb->cb[]中. 
 *
 * ip_options_get_finish(opt, NULL) 发送方向
 * ip_rcv_options(NULL, skb)  接受方向
 *  ip_options_compile()
 *
 * 
 *
 */
int ip_options_compile(struct ip_options * opt, struct sk_buff * skb)
{
	int l;
	unsigned char * iph;
	unsigned char * optptr;
	int optlen;
	unsigned char * pp_ptr = NULL;
	struct rtable *rt = skb ? (struct rtable*)skb->dst : NULL;

    /* 这个if else用于确定待解析的ip选项 */
	if (!opt) {
		opt = &(IPCB(skb)->opt);
		iph = skb_network_header(skb);
		opt->optlen = ((struct iphdr *)iph)->ihl*4 - sizeof(struct iphdr);
		optptr = iph + sizeof(struct iphdr);
		opt->is_data = 0;
	} else {
		optptr = opt->is_data ? opt->__data :
					(unsigned char *)&(ip_hdr(skb)[1]);
		iph = optptr - sizeof(struct iphdr);
	}

    /*
     * 循环各个选项的内容
	 */
	for (l = opt->optlen; l > 0; ) {
		switch (*optptr) {
		      case IPOPT_END://如果遇到列表结束符，则将后面所剩余的全部空间都设置为结束符
			for (optptr++, l--; l>0; optptr++, l--) {
				if (*optptr != IPOPT_END) {
					*optptr = IPOPT_END;
					opt->is_changed = 1;
				}
			}
			goto eol;
		      case IPOPT_NOOP://空操作符，直接下一个了
			l--;
			optptr++;
			continue;
		}

		/*
		 * 校验当前待处理选项长度值是否有效，若无效，则结束解析。
		 * 在此之所以判断optlen<2,是因为除了上面已经处理过的选项列表结束符和空操作符外，
		 * 其他选项长度都大于或等于2，即所谓的多字节选项.
		 */
		optlen = optptr[1];
		if (optlen<2 || optlen>l) {
			pp_ptr = optptr;
			goto error;
		}


		/*
		 * 多源路由
		 */
		switch (*optptr) {
		      case IPOPT_SSRR:
		      case IPOPT_LSRR:
			if (optlen < 3) { //校验待处理源路由选项长度值是否有效
				pp_ptr = optptr + 1;
				goto error;
			}
			//校验待处理源路由选项的指针值是否有效。
			if (optptr[2] < 4) {
				pp_ptr = optptr + 2;
				goto error;
			}
			
			/* NB: cf RFC-1812 5.2.4.1 */
			//IP选项信息块opt中源路由选项若已处理过，则无需再处理.
			if (opt->srr) {
				pp_ptr = optptr;
				goto error;
			}

			/*
			 * 显然这是针对发送的，先再次校验选项中的指针及长度的有效性，
			 * 对于选项指针值其最小值为4，对于选项长度值，除了选项类型、选项长度以及选项指针的三字节外，
			 * 至少应该可以容纳一个IP地址，且扣除了前面三字节应4字节对齐。
			 * 作为发送方，应取出第一个地址作为下一跳地址，将剩余的所有地址往前移动一个位置
			 */
			if (!skb) {
				if (optptr[2] != 4 || optlen < 7 || ((optlen-3) & 3)) {
					pp_ptr = optptr + 1;
					goto error;
				}
				memcpy(&opt->faddr, &optptr[3], 4);
				if (optlen > 7)
					memmove(&optptr[3], &optptr[7], optlen-7);
			}
			//根据选项类型标识是不是严格路由选项，并记录源路由选项在IP首部中的偏移量
			opt->is_strictroute = (optptr[0] == IPOPT_SSRR);
			opt->srr = optptr - iph;
			break;
			
		    case IPOPT_RR: //处理路由记录
			if (opt->rr) { //若IP选项信息块opt中记录由路由选项已经被处理过，则无需再次处理
				pp_ptr = optptr;
				goto error;
			}
			if (optlen < 3) { //校验待处理记录路由由选项的长度值是否有效
				pp_ptr = optptr + 1;
				goto error;
			}
			if (optptr[2] < 4) {//校验待处理记录路由选项的指针值是否有效。
				pp_ptr = optptr + 2;
				goto error;
			}
			/*
			 * 存储IP地址的数据区有效的情况下，如果是接收，则将本地源地址填入到记录路由选项中，
			 * 并设置需重新计算校验和标识，最后调整选项指针。
			 */
			if (optptr[2] <= optlen) {
				if (optptr[2]+3 > optlen) {
					pp_ptr = optptr + 2;
					goto error;
				}
				if (skb) {
					memcpy(&optptr[optptr[2]-1], &rt->rt_spec_dst, 4);
					opt->is_changed = 1;
				}
				optptr[2] += 4;
				opt->rr_needaddr = 1;
			}
			// 标记记录路由选项在IP首部中的偏移量
			opt->rr = optptr - iph;
			break;
		      case IPOPT_TIMESTAMP:
			if (opt->ts) { //opt中的时间戳选项已处理过，则无需再次处理。
				pp_ptr = optptr;
				goto error;
			}
			//长度是否有效
			if (optlen < 4) {
				pp_ptr = optptr + 1;
				goto error;
			}
			//校验待处理时间戳选项的指针值是否有效。
			if (optptr[2] < 5) {
				pp_ptr = optptr + 2;
				goto error;
			}
			
			if (optptr[2] <= optlen) { 
				__be32 *timeptr = NULL;
				
				if (optptr[2]+3 > optptr[1]) { //检查时间戳选项指针是否有效
					pp_ptr = optptr + 2;
					goto error;
				}
				
				switch (optptr[3]&0xF) { //针对时间戳选项中的标志FG的不同取值分别做处理.
				
				      case IPOPT_TS_TSONLY: //如果只记录时间戳
					opt->ts = optptr - iph;
					if (skb)
						timeptr = (__be32*)&optptr[optptr[2]-1];
					opt->ts_needtime = 1;
					optptr[2] += 4;
					break;
				      case IPOPT_TS_TSANDADDR://如果需要同时记录IP地址和时间戳
					if (optptr[2]+7 > optptr[1]) {
						pp_ptr = optptr + 2;
						goto error;
					}
					opt->ts = optptr - iph;
					if (skb) {
						memcpy(&optptr[optptr[2]-1], &rt->rt_spec_dst, 4);
						timeptr = (__be32*)&optptr[optptr[2]+3];
					}
					opt->ts_needaddr = 1;
					opt->ts_needtime = 1;
					optptr[2] += 8;
					break;
				      case IPOPT_TS_PRESPEC://根据发送方在列表中指定的IP地址记录时间戳
					if (optptr[2]+7 > optptr[1]) {
						pp_ptr = optptr + 2;
						goto error;
					}
					opt->ts = optptr - iph;
					{
						__be32 addr;
						memcpy(&addr, &optptr[optptr[2]-1], 4);
						if (inet_addr_type(addr) == RTN_UNICAST)
							break;
						if (skb)
							timeptr = (__be32*)&optptr[optptr[2]+3];
					}
					opt->ts_needtime = 1;
					optptr[2] += 8;
					break;
				      default:
					if (!skb && !capable(CAP_NET_RAW)) {
						pp_ptr = optptr + 3;
						goto error;
					}
					break;
				}
				//如果之前取得了时间戳的记录位置，则取得时间值并复制该值的记录位置，记得设置选项信息块opt->is_changed字段
				if (timeptr) {
					struct timeval tv;
					__be32  midtime;
					do_gettimeofday(&tv);
					midtime = htonl((tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000);
					memcpy(timeptr, &midtime, sizeof(__be32));
					opt->is_changed = 1;
				}
			} else {
			   // 若时间戳区域已满，此时如果OF标志溢出，则跳转到出错处理，否则若是接受，则重新计算OF标志。
				unsigned overflow = optptr[3]>>4;
				if (overflow == 15) {
					pp_ptr = optptr + 3;
					goto error;
				}
				opt->ts = optptr - iph;
				if (skb) {
					optptr[3] = (optptr[3]&0xF)|((overflow+1)<<4);
					opt->is_changed = 1;
				}
			}
			break;
		      case IPOPT_RA:
			if (optlen < 4) {
				pp_ptr = optptr + 1;
				goto error;
			}
			
			if (optptr[2] == 0 && optptr[3] == 0)
				//如果路由器警告选项值有效，则标记路由器警告选项在IP首部中的偏移量.如果是转发数据报
				opt->router_alert = optptr - iph;
			break;
		    case IPOPT_CIPSO: //如果是接收数据报，则操作该选项的进程必须具有操作RAW套接口和PACKET套接口的能力
			if ((!skb && !capable(CAP_NET_RAW)) || opt->cipso) {
				pp_ptr = optptr;
				goto error;
			}
			opt->cipso = optptr - iph;
			if (cipso_v4_validate(&optptr)) {
				pp_ptr = optptr;
				goto error;
			}
			break;
			/* 对于流标识选项与安全选项，无需做特别的处理，
			 * 但如果是接收数据报，
			 * 则操作选项的进程必须具有操作RAW套接口和PACKET套接口的能力
			 */
		    case IPOPT_SEC:
		    case IPOPT_SID:
		      default:
			if (!skb && !capable(CAP_NET_RAW)) {
				pp_ptr = optptr;
				goto error;
			}
			break;
		}
		//没处理完一个选项后，将指针往后移动到下一个选项，以便继续处理后面的选项。
		l -= optlen;
		optptr += optlen;
	}

eol:
	if (!pp_ptr)
		return 0;

error:
	if (skb) {
		/*
		 * 在处理选项过程中，无论何时遇到错误都会跳转到此处处理，
		 * 即如果是接收数据报，则需给IP数据报的发送方发送一个参数问题ICMP差错报文。
		 */
		icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl((pp_ptr-iph)<<24));
	}
	return -EINVAL;
}


/*
 * Undo all the changes done by ip_options_compile().
 *
 * 
 */

void ip_options_undo(struct ip_options * opt)
{

	if (opt->srr) {
		/*
		 * 如果存在源路由选项，则路径列表中的所有地址往后移动一个位置，然后将目的地址，
		 * 即下一条地址，重新复制到路径列表的第一个地址处。
		 */
		unsigned  char * optptr = opt->__data+opt->srr-sizeof(struct  iphdr);
		memmove(optptr+7, optptr+3, optptr[1]-7);
		memcpy(optptr+3, &opt->faddr, 4);
	}
	
	if (opt->rr_needaddr) {
		//如果存在记录路由选项，则将保存到路径列表中的本地地址删除
		unsigned  char * optptr = opt->__data+opt->rr-sizeof(struct  iphdr);
		optptr[2] -= 4;
		memset(&optptr[optptr[2]-1], 0, 4);
	}
	
	if (opt->ts) {
		/*
		 * 如果存在时间戳选项，
		 * 则根据记录时间戳和记录地址标志，将保存的时间戳或本地地址删除
	     */
		unsigned  char * optptr = opt->__data+opt->ts-sizeof(struct  iphdr);
		if (opt->ts_needtime) {
			optptr[2] -= 4;
			memset(&optptr[optptr[2]-1], 0, 4);
			if ((optptr[3]&0xF) == IPOPT_TS_PRESPEC)
				optptr[2] -= 4;
		}
		if (opt->ts_needaddr) {
			optptr[2] -= 4;
			memset(&optptr[optptr[2]-1], 0, 4);
		}
	}
}

static struct ip_options *ip_options_get_alloc(const int optlen)
{
	return kzalloc(sizeof(struct ip_options) + ((optlen + 3) & ~3),
		       GFP_KERNEL);
}

/*
 * ip_options_get()
 *  ip_options_get_finish()
 */
static int ip_options_get_finish(struct ip_options **optp,
				 struct ip_options *opt, int optlen)
{
	while (optlen & 3)
		opt->__data[optlen++] = IPOPT_END;
	opt->optlen = optlen;
	opt->is_data = 1;
	if (optlen && ip_options_compile(opt, NULL)) {
		kfree(opt);
		return -EINVAL;
	}
	kfree(*optp);
	*optp = opt;
	return 0;
}

int ip_options_get_from_user(struct ip_options **optp, unsigned char __user *data, int optlen)
{
	struct ip_options *opt = ip_options_get_alloc(optlen);

	if (!opt)
		return -ENOMEM;
	if (optlen && copy_from_user(opt->__data, data, optlen)) {
		kfree(opt);
		return -EFAULT;
	}
	return ip_options_get_finish(optp, opt, optlen);
}

/*
 * UDP套接口和RAW套接口的输出数据中如果带有控制信息，
 * 则需根据携带的控制信息生成相应的IP选项信息块，用于生成待输出IP数据报的IP选项。
 */
int ip_options_get(struct ip_options **optp, unsigned char *data, int optlen)
{
	struct ip_options *opt = ip_options_get_alloc(optlen);

	if (!opt)
		return -ENOMEM;
	if (optlen)
		memcpy(opt->__data, data, optlen);
	return ip_options_get_finish(optp, opt, optlen);
}

/*
 *  ip_rcv
 *	 ip_rcv_finish
 *	  dst_input
 *	   ip_forward
 *      ip_forward_finish
 *       ip_forward_options()
 *
 *  处理转发ip数据报中的IP选项,包括记录路由选项和时间戳选项
 */
void ip_forward_options(struct sk_buff *skb)
{
	struct   ip_options * opt	= &(IPCB(skb)->opt);
	unsigned char * optptr;
	struct rtable *rt = (struct rtable*)skb->dst;
	unsigned char *raw = skb_network_header(skb);

    /*
     * 如果需要记录IP地址，则获取本地地址并设置到IP记录路由选项中。
     */
	if (opt->rr_needaddr) {
		optptr = (unsigned char *)raw + opt->rr;
		ip_rt_get_source(&optptr[optptr[2]-5], rt);
		opt->is_changed = 1;
	}

	/*
	 * 如果目的地址是从源路由选项指定的，则还需要判断输出路由缓存的目的地址是否
	 * 存在于源路由选项中。如果存在，则根据输出路由缓存的目的地址重新设置IP首部中的目的地址。
	 */
	if (opt->srr_is_hit) {
		int srrptr, srrspace;

		optptr = raw + opt->srr;

		for ( srrptr=optptr[2], srrspace = optptr[1];
		     srrptr <= srrspace;
		     srrptr += 4
		     ) {
			if (srrptr + 3 > srrspace)
				break;
			if (memcmp(&rt->rt_dst, &optptr[srrptr-1], 4) == 0)
				break;
		}
		if (srrptr + 3 <= srrspace) {
			opt->is_changed = 1;
			ip_rt_get_source(&optptr[srrptr-1], rt);
			ip_hdr(skb)->daddr = rt->rt_dst;
			optptr[2] = srrptr+4;
		} else if (net_ratelimit())
			printk(KERN_CRIT "ip_forward(): Argh! Destination lost!\n");
		if (opt->ts_needaddr) {
			optptr = raw + opt->ts;
			ip_rt_get_source(&optptr[optptr[2]-9], rt);
			opt->is_changed = 1;
		}
	}
	//一旦IP首部做了修改，就需要重新计算IP数据报首部的校验和
	if (opt->is_changed) {
		opt->is_changed = 0;
		ip_send_check(ip_hdr(skb));
	}
}

/*
 * 输入数据中的宽松源路由以及严格源路由选项，并根据源路由选项更新IP数据报的下一跳地址。
 */
int ip_options_rcv_srr(struct sk_buff *skb)
{
	struct ip_options *opt = &(IPCB(skb)->opt);
	int srrspace, srrptr;
	__be32 nexthop;
	struct iphdr *iph = ip_hdr(skb);
	unsigned char *optptr = skb_network_header(skb) + opt->srr;
	struct rtable *rt = (struct rtable*)skb->dst;
	struct rtable *rt2;
	int err;

  
	if (!opt->srr)
		return 0;

	/*
	 * 待处理IP数据报其接收方必须是本地主机
	 */
	if (skb->pkt_type != PACKET_HOST)
		return -EINVAL;
	/*
	 * 在路由类型为RTN_UNICAST，即网关或直接连接的路由情况下执行严格源路
	 * 是会有问题的，此时会发送一个参数错误ICMP差错报文给发送方，并返回参数无效错误。
	 */
	if (rt->rt_type == RTN_UNICAST) {
		if (!opt->is_strictroute)
			return 0;
		icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl(16<<24));
		return -EINVAL;
	}
	// 待处理IP数据报其接收方必须是本地主机，否则返回参数无效错误。
	if (rt->rt_type != RTN_LOCAL)
		return -EINVAL;

    /*
     * 待处理IP数据报其接收方必须是本地主机，否则返回参数无效错误。
     */
	for (srrptr=optptr[2], srrspace = optptr[1]; srrptr <= srrspace; srrptr += 4) {
		if (srrptr + 3 > srrspace) {
			icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl((opt->srr+2)<<24));
			return -EINVAL;
		}
		memcpy(&nexthop, &optptr[srrptr-1], 4);

		rt = (struct rtable*)skb->dst;
		skb->dst = NULL;
		err = ip_route_input(skb, nexthop, iph->saddr, iph->tos, skb->dev);
		rt2 = (struct rtable*)skb->dst;

		if (err || (rt2->rt_type != RTN_UNICAST && rt2->rt_type != RTN_LOCAL)) {
			ip_rt_put(rt2);
			skb->dst = &rt->u.dst;
			return -EINVAL;
		}
		ip_rt_put(rt);

		if (rt2->rt_type != RTN_LOCAL)
			break;
		/* Superfast 8) loopback forward */
		memcpy(&iph->daddr, &optptr[srrptr-1], 4);
		opt->is_changed = 1;
	}
	/*
	 * 如果源路由选项的路径列表没有遍历完，则说明该IP数据报的目的地址是从源路由选项选出来的，
	 * 因此需设置srr_is_hit标志，待转发时需要进一步处理。同时还需要设置is_change标志，
	 * 标识需要重新计算IP数据报的首部校验和。
	 */
	if (srrptr <= srrspace) {
		opt->srr_is_hit = 1;
		opt->is_changed = 1;
	}
	return 0;
}
