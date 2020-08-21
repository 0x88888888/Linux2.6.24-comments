/*
 * Binary Increase Congestion control for TCP
 *
 * This is from the implementation of BICTCP in
 * Lison-Xu, Kahaled Harfoush, and Injong Rhee.
 *  "Binary Increase Congestion Control for Fast, Long Distance
 *  Networks" in InfoComm 2004
 * Available from:
 *  http://www.csc.ncsu.edu/faculty/rhee/export/bitcp.pdf
 *
 * Unless BIC is enabled and congestion window is large
 * this behaves the same as the original Reno.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <net/tcp.h>


#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define BICTCP_B		4	 /*
					  * In binary search,
					  * go to point (max+min)/N
					  */
/* BIC能快速的达到一个平衡值，开关*/
static int fast_convergence = 1;
/* 每次增加的MSS 不能超过这个值，防止增长太过剧烈*/
static int max_increment = 16;
//拥塞窗口的下限,提高算法的公平性
static int low_window = 14; 
// ==819 /1024 (BICTCP_BETA_SCAL)实际值是0.8*1024
static int beta = 819;		/* = 819/1024 (BICTCP_BETA_SCALE) */
static int initial_ssthresh; /* 初始的阈值,初始值被设置成2^31-1=2147483647 */
static int smooth_part = 20;

module_param(fast_convergence, int, 0644);
MODULE_PARM_DESC(fast_convergence, "turn on/off fast convergence");
module_param(max_increment, int, 0644);
MODULE_PARM_DESC(max_increment, "Limit on increment allowed during binary search");
module_param(low_window, int, 0644);
MODULE_PARM_DESC(low_window, "lower bound on congestion window (for TCP friendliness)");
module_param(beta, int, 0644);
MODULE_PARM_DESC(beta, "beta for multiplicative increase");
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");
module_param(smooth_part, int, 0644);
MODULE_PARM_DESC(smooth_part, "log(B/(B*Smin))/log(B/(B-1))+B, # of RTT from Wmax-B to Wmax");


/* BIC TCP Parameters */
struct bictcp {
	u32	cnt;		/* increase cwnd by 1 after ACKs */
	u32 	last_max_cwnd;	/* last maximum snd_cwnd */
	u32	loss_cwnd;	/* congestion window at last loss */
	u32	last_cwnd;	/* the last snd_cwnd */
	u32	last_time;	/* time when updated last_cwnd */
	u32	epoch_start;	/* beginning of an epoch */
#define ACK_RATIO_SHIFT	4
	u32	delayed_ack;	/* estimate the ratio of Packets/ACKs << 4 */
};

static inline void bictcp_reset(struct bictcp *ca)
{
	ca->cnt = 0;
	ca->last_max_cwnd = 0;
	ca->loss_cwnd = 0;
	ca->last_cwnd = 0;
	ca->last_time = 0;
	ca->epoch_start = 0;
	ca->delayed_ack = 2 << ACK_RATIO_SHIFT;
}

static void bictcp_init(struct sock *sk)
{
	bictcp_reset(inet_csk_ca(sk));
	if (initial_ssthresh)
		tcp_sk(sk)->snd_ssthresh = initial_ssthresh;
}

/*
 * Compute congestion window to use.
 *
 * tcp_rcv_state_process()
 *  tcp_ack()
 *   tcp_cong_avoid()
 *    bictcp_cong_avoid()
 *     bictcp_update()
 */
static inline void bictcp_update(struct bictcp *ca, u32 cwnd)
{
     /* 31.25ms以内不更新ca！！！*/
	if (ca->last_cwnd == cwnd &&
	    (s32)(tcp_time_stamp - ca->last_time) <= HZ / 32)
		return;

	ca->last_cwnd = cwnd;
	ca->last_time = tcp_time_stamp;

   
	if (ca->epoch_start == 0) /* record the beginning of an epoch */
		ca->epoch_start = tcp_time_stamp;

	/* start off normal */
	if (cwnd <= low_window) { /*为了保持友好性*/
		ca->cnt = cwnd; /*这样14个以内的ack，可使snd_cwnd++ */
		return;
	}

	/* binary increase */
	if (cwnd < ca->last_max_cwnd) { /*上次掉包前一个snd_cwnd */
		__u32 	dist = (ca->last_max_cwnd - cwnd)
			/ BICTCP_B; /* 四分之一,dist是实际数值差的1/4 */

		if (dist > max_increment)
			/* linear increase */
		    /*dist > 16，处于线性增长阶段，每收到16个ACK，会使snd_cwnd++ */
			ca->cnt = cwnd / max_increment;
		else if (dist <= 1U)
			/* binary search increase */
		    /* dist <=1 ， ca->cnt=5*cwnd，会造成snd_cwnd增长极其缓慢，即处于稳定阶段 */
			ca->cnt = (cwnd * smooth_part) / BICTCP_B;
		else
			/* binary search increase */
		    /* 1 < dist <= 16 ，每收到dist个ACK，会使snd_cwnd++，故增长很快 */
			ca->cnt = cwnd / dist;
 	} else { /* 进入max_probing阶段 */
		/* slow start AMD linear increase */
		if (cwnd < ca->last_max_cwnd + BICTCP_B)
			/* slow start */
			ca->cnt = (cwnd * smooth_part) / BICTCP_B;
		else if (cwnd < ca->last_max_cwnd + max_increment*(BICTCP_B-1))
			/* slow start */
		    /* 增长率从5/(3*cwnd)~47/(3*cwnd)，snd_cwnd的增长加快*/
			ca->cnt = (cwnd * (BICTCP_B-1))
				/ (cwnd - ca->last_max_cwnd);
		else
			/* linear increase */
		    /* 增长率为16/cwnd ，更快 */
			ca->cnt = cwnd / max_increment; 
	}

	/* if in slow start or link utilization is very low */
	if (ca->loss_cwnd == 0) { /* 没有发生过丢包，所以snd_cwnd增长应该快点*/
		if (ca->cnt > 20) /* increase cwnd 5% per RTT */
			ca->cnt = 20;
	}
    
	/* 相当于乘与delayed_ack的百分比，delayed得越严重，则snd_cwnd应该增加越快*/
	/* 这样有无delayed对snd_cwnd的影响不大*/
	ca->cnt = (ca->cnt << ACK_RATIO_SHIFT) / ca->delayed_ack;
	if (ca->cnt == 0)			/* cannot be zero */
		ca->cnt = 1;
}

//bictcp拥塞避免
/*
 * tcp_rcv_state_process()
 *  tcp_ack()
 *   tcp_cong_avoid()
 *    bictcp_cong_avoid()
 */
static void bictcp_cong_avoid(struct sock *sk, u32 ack,
			      u32 in_flight, int data_acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

    /* 判断拥塞窗口是否到达限制 */
	if (!tcp_is_cwnd_limited(sk, in_flight))
		return;

	if (tp->snd_cwnd <= tp->snd_ssthresh)
		tcp_slow_start(tp); //开始slow start
	else {
		bictcp_update(ca, tp->snd_cwnd);

		/* In dangerous area, increase slowly.
		 * In theory this is tp->snd_cwnd += 1 / tp->snd_cwnd
		 */
		if (tp->snd_cwnd_cnt >= ca->cnt) {
			if (tp->snd_cwnd < tp->snd_cwnd_clamp)
				tp->snd_cwnd++;
			tp->snd_cwnd_cnt = 0;
		} else
			tp->snd_cwnd_cnt++;
	}

}

/*
 *	behave like Reno until low_window is reached,
 *	then increase congestion window slowly
 *
 * sys_sendto()
 *  sock_sendmsg()
 *   __sock_sendmsg()
 *    tcp_sendmsg()
 *     __tcp_push_pending_frames()
 *      tcp_write_xmit()
 *       tcp_transmit_skb()
 *        tcp_enter_cwr()
 *         bictcp_recalc_ssthresh()
 *
 *  慢启动阈值重新计算
 *
 * 重赋值last_max_cwnd、返回新的慢启动阈值
 */
static u32 bictcp_recalc_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	ca->epoch_start = 0;	/* end of epoch , 平静的日子结束了*/

	/* Wmax and fast convergence 	
	 * fast? 好像是更安全点吧。丢包点比上次低，说明恶化，则主动降低。
	 * 丢包点比上次高，则说明更好，当然采用更大的。
	 */
	if (tp->snd_cwnd < ca->last_max_cwnd && fast_convergence)
		ca->last_max_cwnd = (tp->snd_cwnd * (BICTCP_BETA_SCALE + beta))
			/ (2 * BICTCP_BETA_SCALE);
	else
		ca->last_max_cwnd = tp->snd_cwnd;

	ca->loss_cwnd = tp->snd_cwnd;

    
	/* snd_cwnd<=14时，同reno，保持友好性 */
	if (tp->snd_cwnd <= low_window)
		return max(tp->snd_cwnd >> 1U, 2U);
	else
		/* 就是snd_ssthresh=0.8*snd_cwnd ，很大的一个数，能充分利用带宽 */
		return max((tp->snd_cwnd * beta) / BICTCP_BETA_SCALE, 2U);
}

static u32 bictcp_undo_cwnd(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct bictcp *ca = inet_csk_ca(sk);
	return max(tp->snd_cwnd, ca->last_max_cwnd);
}

static void bictcp_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Loss)
		bictcp_reset(inet_csk_ca(sk));
}

/* Track delayed acknowledgment ratio using sliding window
 * ratio = (15*ratio + sample) / 16
 *
 * sample是此时的cnt，而本来的ratio = delayed_ack / 16 
 * 按如下函数计算后，现在的ratio = (15*ratio) /16 + cnt /16
 * cnt = cnt - 原来的ratio
 */
static void bictcp_acked(struct sock *sk, u32 cnt, s32 rtt)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_ca_state == TCP_CA_Open) {
		struct bictcp *ca = inet_csk_ca(sk);
		/* 作者似乎很注重delayed包对snd_cwnd的影响，要尽量削弱 */
		cnt -= ca->delayed_ack >> ACK_RATIO_SHIFT;
		ca->delayed_ack += cnt;
	}
}


static struct tcp_congestion_ops bictcp = {
	.init		= bictcp_init,
	.ssthresh	= bictcp_recalc_ssthresh,
	.cong_avoid	= bictcp_cong_avoid,
	.set_state	= bictcp_state,
	.undo_cwnd	= bictcp_undo_cwnd,
	.pkts_acked     = bictcp_acked,
	.owner		= THIS_MODULE,
	.name		= "bic",
};

static int __init bictcp_register(void)
{
	BUILD_BUG_ON(sizeof(struct bictcp) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&bictcp);
}

static void __exit bictcp_unregister(void)
{
	tcp_unregister_congestion_control(&bictcp);
}

module_init(bictcp_register);
module_exit(bictcp_unregister);

MODULE_AUTHOR("Stephen Hemminger");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("BIC TCP");
