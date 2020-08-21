/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol.
 *
 * Version:	@(#)tcp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_TCP_H
#define _LINUX_TCP_H

#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/socket.h>

struct tcphdr {
	__be16	source; //源端口
	__be16	dest; //目的端口
	__be32	seq; //序号
	__be32	ack_seq; //确认序号
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4, //保留
		doff:4, // 头部长度,4字节为单位,所以4*15=60，tcp头部最长为60字节，包括选项数据了
		fin:1, //F
		syn:1,
		rst:1,
		psh:1, // 是否需要 马上PUSH给上层application
		ack:1, //
		urg:1, // 紧急指针是否有效
		ece:1, // 拥塞控制
		cwr:1; // 拥塞控制
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__be16	window; // 接收窗口
	__sum16	check;  // 校验和
	__be16	urg_ptr; // 紧急指针
};

/*
 *	The union cast uses a gcc extension to avoid aliasing problems
 *  (union is compatible to any of its members)
 *  This means this part of the code is -fstrict-aliasing safe now.
 */
union tcp_word_hdr { 
	struct tcphdr hdr;
	__be32 		  words[5];
}; 

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3]) 

enum { 
	TCP_FLAG_CWR = __constant_htonl(0x00800000), 
	TCP_FLAG_ECE = __constant_htonl(0x00400000), 
	TCP_FLAG_URG = __constant_htonl(0x00200000), 
	TCP_FLAG_ACK = __constant_htonl(0x00100000), 
	TCP_FLAG_PSH = __constant_htonl(0x00080000), 
	TCP_FLAG_RST = __constant_htonl(0x00040000), 
	TCP_FLAG_SYN = __constant_htonl(0x00020000), 
	TCP_FLAG_FIN = __constant_htonl(0x00010000),
	TCP_RESERVED_BITS = __constant_htonl(0x0F000000),
	TCP_DATA_OFFSET = __constant_htonl(0xF0000000)
}; 

/* TCP socket options 
 *
 * TCP选项设置
 */
#define TCP_NODELAY		1	/* Turn off Nagle's algorithm. */
#define TCP_MAXSEG		2	/* Limit MSS */
#define TCP_CORK		3	/* Never send partially complete segments */
#define TCP_KEEPIDLE		4	/* Start keeplives after this period */
#define TCP_KEEPINTVL		5	/* Interval between keepalives */
#define TCP_KEEPCNT		6	/* Number of keepalives before death */
#define TCP_SYNCNT		7	/* Number of SYN retransmits */
#define TCP_LINGER2		8	/* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT	9	/* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP	10	/* Bound advertised window */
#define TCP_INFO		11	/* Information about this connection. */
#define TCP_QUICKACK		12	/* Block/reenable quick acks */
#define TCP_CONGESTION		13	/* Congestion control algorithm */
#define TCP_MD5SIG		14	/* TCP MD5 Signature (RFC2385) */

#define TCPI_OPT_TIMESTAMPS	1
#define TCPI_OPT_SACK		2
#define TCPI_OPT_WSCALE		4
#define TCPI_OPT_ECN		8

/*　拥塞状态
 *
 * 用于inet_connect_sock->icsk_ca_staet
 */
enum tcp_ca_state
{
    //这是正常状态，也是初始状态，套接字关闭后，也会被重置为该状态
	TCP_CA_Open = 0,
#define TCPF_CA_Open	(1<<TCP_CA_Open)
    //发送段检检测到重复的ack或者附带选择性应答的ACK报文时，进入这个状态
	TCP_CA_Disorder = 1,
#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)
	TCP_CA_CWR = 2,
#define TCPF_CA_CWR	(1<<TCP_CA_CWR)
	TCP_CA_Recovery = 3,
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)
	TCP_CA_Loss = 4
#define TCPF_CA_Loss	(1<<TCP_CA_Loss)
};

struct tcp_info
{
	__u8	tcpi_state;
	__u8	tcpi_ca_state;
	__u8	tcpi_retransmits;
	__u8	tcpi_probes;
	__u8	tcpi_backoff;
	__u8	tcpi_options;
	__u8	tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;

	__u32	tcpi_rto;
	__u32	tcpi_ato;
	__u32	tcpi_snd_mss;
	__u32	tcpi_rcv_mss;

	__u32	tcpi_unacked;
	__u32	tcpi_sacked;
	__u32	tcpi_lost;
	__u32	tcpi_retrans;
	__u32	tcpi_fackets;

	/* Times. */
	__u32	tcpi_last_data_sent;
	__u32	tcpi_last_ack_sent;     /* Not remembered, sorry. */
	__u32	tcpi_last_data_recv;
	__u32	tcpi_last_ack_recv;

	/* Metrics. */
	__u32	tcpi_pmtu;
	__u32	tcpi_rcv_ssthresh;
	__u32	tcpi_rtt;
	__u32	tcpi_rttvar;
	__u32	tcpi_snd_ssthresh;
	__u32	tcpi_snd_cwnd;
	__u32	tcpi_advmss;
	__u32	tcpi_reordering;

	__u32	tcpi_rcv_rtt;
	__u32	tcpi_rcv_space;

	__u32	tcpi_total_retrans;
};

/* for TCP_MD5SIG socket option */
#define TCP_MD5SIG_MAXKEYLEN	80

struct tcp_md5sig {
	struct __kernel_sockaddr_storage tcpm_addr;	/* address associated */
	__u16	__tcpm_pad1;				/* zero */
	__u16	tcpm_keylen;				/* key length */
	__u32	__tcpm_pad2;				/* zero */
	__u8	tcpm_key[TCP_MD5SIG_MAXKEYLEN];		/* key (binary) */
};

#ifdef __KERNEL__

#include <linux/skbuff.h>
#include <linux/dmaengine.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/inet_timewait_sock.h>

/* tcp头开始的地址 */
static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_transport_header(skb);
}

static inline unsigned int tcp_hdrlen(const struct sk_buff *skb)
{
	return tcp_hdr(skb)->doff * 4;
}

static inline unsigned int tcp_optlen(const struct sk_buff *skb)
{
	return (tcp_hdr(skb)->doff - 5) * 4;
}

/* This defines a selective acknowledgement block. */
struct tcp_sack_block_wire {
	__be32	start_seq;
	__be32	end_seq;
};

struct tcp_sack_block {
	u32	start_seq;
	u32	end_seq;
};

struct tcp_options_received {
/*	PAWS/RTTM data	*/
	long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
	u32	ts_recent;	/* Time stamp to echo next		*/
	u32	rcv_tsval;	/* Time stamp value             	*/
	u32	rcv_tsecr;	/* Time stamp echo reply        	*/
	u16 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/
		dsack : 1,	/* D-SACK is scheduled			*/
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/
		sack_ok : 4,	/* SACK seen on SYN packet		*/
		snd_wscale : 4,	/* Window scaling received from sender,对端接收窗口扩大因子 	*/
		rcv_wscale : 4;	/* Window scaling to send to receiver, 本端接收窗口扩大因子	*/
/*	SACKs data	*/
	u8	eff_sacks;	/* Size of SACK array to send with next packet */
	u8	num_sacks;	/* Number of SACK blocks		*/
	/* 用户通过TCP_MAXSEG选项设置的MSS上限，用于决定本端和对端的接收MSS上限 */
	u16	user_mss;  	/* mss requested by user in ioctl */
	u16	mss_clamp;	/* Maximal mss, negotiated at connection setup , 对端的最大mss*/
};

/*
 * 在链接建立过程中使用该结构来描述链接，从SYN直到链接被ACCEPT之前存在.
 */
struct tcp_request_sock {
	struct inet_request_sock 	req;
#ifdef CONFIG_TCP_MD5SIG
	/* Only used by TCP MD5 Signature so far. */
	struct tcp_request_sock_ops	*af_specific;
#endif
	u32			 	rcv_isn;
	u32			 	snt_isn;
};

static inline struct tcp_request_sock *tcp_rsk(const struct request_sock *req)
{
	return (struct tcp_request_sock *)req;
}

/*
 * 在链接建立之后到终止之前使用，这种传输控制块的生命期最长，发送和接受段都需要它进行控制。
 *
 * tcp_sock是TCP协议专用的一个socket表示，
 * 它是在struct inet_connection_sock基础进行扩展，主要是增加了滑动窗口协议，
 * 避免拥塞算法等一些TCP专有属性
 */
struct tcp_sock {
	/* inet_connection_sock has to be the first member of tcp_sock */
	struct inet_connection_sock	inet_conn;
	u16	tcp_header_len;	/* Bytes of tcp header to send		*/
	u16	xmit_size_goal;	/* Goal for segmenting output packets	*/

/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 */
	__be32	pred_flags;

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 */
 	u32	rcv_nxt;	/* What we want to receive next , 希望接收的下一个序列号，填写到tcp头部的ack_seq中	*/
	u32	copied_seq;	/* Head of yet unread data,应用程序下次从这里复制数据		*/
	/* 最早接收但未确认的段的序号，即当前接收窗口的左端*/
	u32	rcv_wup;	/* 接收窗口的起始位置,在tcp_select_window		中更新, rcv_nxt on last window update sent	*/
 	u32	snd_nxt;	/* Next sequence we send,下一次发送数据包时，用这个sequence 值		*/

    /* 发送窗口的左边沿 */
 	u32	snd_una;	/* First byte we want an ack for第一个没有被ack的序号	*/
 	u32	snd_sml;	/* Last byte of the most recently transmitted small packet */
	u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */
	u32	lsndtime;	/* timestamp of last sent data packet (for restart window) */

	/* Data for direct copy to user */
	struct {
		struct sk_buff_head	prequeue;
		struct task_struct	*task;
		struct iovec		*iov;
		int			memory;
		int			len;
#ifdef CONFIG_NET_DMA
		/* members for async copy */
		struct dma_chan		*dma_chan;
		int			wakeup;
		struct dma_pinned_list	*pinned_list;
		dma_cookie_t		dma_cookie;
#endif
	} ucopy;

	
	/*
	 * snd_wll 记录发送窗口更新时，造成窗口更新的那个数据报的第一个序号。
	 * 它主要用于在下一次判断是否需要更新发送窗口。
	 */
	u32	snd_wl1;	/* Sequence for window update		*/
	/* 发送窗口的大小，直接取值于来自对方的数据报的TCP首部 */
	u32	snd_wnd;	/* The window we expect to receive	*/
	/* 记录来自对方通告的窗口的最大值 */
	u32	max_window;	/* Maximal window ever seen from peer	*/
	
	/* 本端当前有效的发送MSS。显然不能超过对端接收的上限 
	 * tcp数据包最小长度
	 */
	u32	mss_cache;	/* Cached effective mss, not including SACKS */

	u32	window_clamp;	/* Maximal window to advertise,接收窗口的最大值，这个值也会动态调整		*/
	u32	rcv_ssthresh;	/* Current window clamp,当前接收窗口大小的阈值			*/

	u32	frto_highmark;	/* snd_nxt when RTO occurred */
	u8	reordering;	/* Packet reordering metric.		*/
	u8	frto_counter;	/* Number of new acks after RTO */
	/*
	 * Nagle算法只针对发送队列的最后一个数据包，对于发送队列中间的数据包无效，因为只有发送队列最后	 
	 * 一个数据包才有机会获得新的数据，形成更大的包。
	 * TCP_NAGLE_OFF，TCP_NAGLE_CORK ，TCP_NAGLE_PUSH 
	 */
	u8	nonagle;	/* Disable Nagle algorithm?             */
	u8	keepalive_probes; /* num of allowed keep alive probes	*/

/* RTT measurement */
	//经过平滑后的rtt
	u32	srtt;		/* smoothed round trip time << 3	*/
    //RTT的平均偏差，用来衡量RTT的抖动.
	u32	mdev;		/* medium deviation			*/
	// 为上一个RTT内的最大mdev
	u32	mdev_max;	/* maximal mdev for the last rtt period	*/
	// mdev_max的平滑值
	u32	rttvar;		/* smoothed mdev_max			*/
	u32	rtt_seq;	/* sequence number to update rttvar	*/

    /* 发送且未确认的数据包个数 */
	u32	packets_out;	/* Packets which are "in flight"	*/
	/* 重传的且未确认数据包个数 */
	u32	retrans_out;	/* Retransmitted packets out		*/
    /*
    *      Options received (usually on last packet, some only on SYN packets).
    * 收到的tcp数据包的tcp选项数据
    */
	struct tcp_options_received rx_opt;

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
    //启动slow start的阈值
 	u32	snd_ssthresh;	/* Slow start size threshold		*/
    //发送窗口的大小
 	u32	snd_cwnd;	/* Sending congestion window		*/
	/* 发送方拥塞窗口的增长因子*/
	u32	snd_cwnd_cnt;	/* Linear increase counter		*/
	//拥塞窗口
	u32	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this */
	u32	snd_cwnd_used;
	u32	snd_cwnd_stamp;

	struct sk_buff_head	out_of_order_queue; /* Out of order segments go here */

 	u32	rcv_wnd;	/* Current receiver window,当前接收窗口的大小 ,在tcp_select_window		中更新*/
	u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */

/*	SACKs data	*/
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/

	struct tcp_sack_block_wire recv_sack_cache[4];

	u32	highest_sack;	/* Start seq of globally highest revd SACK
				 * (validity guaranteed only if sacked_out > 0) */

	/* from STCP, retrans queue hinting */
	/* 在重传队列中，缓存下次要标志的段，为了加速对重传队列的标志操作 */			 
	/* 下一次要标志的段 */
	struct sk_buff* lost_skb_hint;

    /* 记录超时的数据包，序号最大*/
	struct sk_buff *scoreboard_skb_hint;
	struct sk_buff *retransmit_skb_hint;
	struct sk_buff *forward_skb_hint;
	struct sk_buff *fastpath_skb_hint;

	int     fastpath_cnt_hint;	/* Lags behind by current skb's pcount
					 * compared to respective fackets_out */
	/* 已经标志了多少个段 */				 	
	int     lost_cnt_hint;
	/* 表示将要重传的起始包*/				 
	int     retransmit_cnt_hint;

	u32	lost_retrans_low;	/* Sent seq after any rxmit (lowest) */

	u16	advmss;		/* Advertised MSS, 本端能接收的MSS上限，建立连接时用来通告对端			*/
	u16	prior_ssthresh; /* ssthresh saved at recovery start	*/
	u32	lost_out;	/* Lost packets			*/
	u32	sacked_out;	/* SACK'd packets,被SACKED数据段的个数			*/
	u32	fackets_out;	/* FACK'd packets			*/
	u32	high_seq;	/* snd_nxt at onset of congestion	*/

    /* 记录上次重传阶段，第一个段的发送时间，用于判断是否可以进行拥塞调整撤销*/
	u32	retrans_stamp;	/* Timestamp of the last retransmit,
				 * also used in SYN-SENT to remember stamp of
				 * the first SYN. */
	u32	undo_marker;	/* tracking retrans started here. */
	int	undo_retrans;	/* number of undoable retransmissions. */
	u32	urg_seq;	/* Seq of received urgent pointer */
	u16	urg_data;	/* Saved octet of OOB data and control flags */
	u8	urg_mode;	/* In urgent mode		*/
	u8	ecn_flags;	/* ECN status bits.			*/
	u32	snd_up;		/* Urgent pointer		*/

	u32	total_retrans;	/* Total retransmits for entire connection */
	u32	bytes_acked;	/* Appropriate Byte Counting - RFC3465 */

	unsigned int		keepalive_time;	  /* time before keep alive takes place */
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */
	int			linger2;

	unsigned long last_synq_overflow; 

    /* 上次TSO延迟的时间戳 */
	u32	tso_deferred;

/* Receiver side RTT estimation */
	struct {
		u32	rtt;
		u32	seq;
		u32	time;
	} rcv_rtt_est; /* 用于接收端的RTT测量*/

/* Receiver queue space */
	struct {
		int	space;
		u32	seq;
		u32	time;
	} rcvq_space; /* 用于调整接收缓冲区和接收窗口*/

/* TCP-specific MTU probe information. */
	struct {
		u32		  probe_seq_start;
		u32		  probe_seq_end;
	} mtu_probe;

#ifdef CONFIG_TCP_MD5SIG
/* TCP AF-Specific parts; only used by MD5 Signature support so far */
	struct tcp_sock_af_ops	*af_specific;

/* TCP MD5 Signagure Option information */
	struct tcp_md5sig_info	*md5sig_info;
#endif
};

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

/*
 * 只存在于主动关闭链接一方，终止链接过程中使用。
 */
struct tcp_timewait_sock {
	struct inet_timewait_sock tw_sk;
	u32			  tw_rcv_nxt;
	u32			  tw_snd_nxt;
	u32			  tw_rcv_wnd;
	u32			  tw_ts_recent;
	long			  tw_ts_recent_stamp;
#ifdef CONFIG_TCP_MD5SIG
	u16			  tw_md5_keylen;
	u8			  tw_md5_key[TCP_MD5SIG_MAXKEYLEN];
#endif
};

static inline struct tcp_timewait_sock *tcp_twsk(const struct sock *sk)
{
	return (struct tcp_timewait_sock *)sk;
}

#endif

#endif	/* _LINUX_TCP_H */
