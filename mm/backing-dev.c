
#include <linux/wait.h>
#include <linux/backing-dev.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/module.h>

/* backing_device_info init */
int bdi_init(struct backing_dev_info *bdi)
{
	int i;
	int err;

	for (i = 0; i < NR_BDI_STAT_ITEMS; i++) {
		err = percpu_counter_init_irq(&bdi->bdi_stat[i], 0);
		if (err)
			goto err;
	}

	bdi->dirty_exceeded = 0;
	err = prop_local_init_percpu(&bdi->completions);

	if (err) {
err:
		while (i--)
			percpu_counter_destroy(&bdi->bdi_stat[i]);
	}

	return err;
}
EXPORT_SYMBOL(bdi_init);

void bdi_destroy(struct backing_dev_info *bdi)
{
	int i;

	for (i = 0; i < NR_BDI_STAT_ITEMS; i++)
		percpu_counter_destroy(&bdi->bdi_stat[i]);

	prop_local_destroy_percpu(&bdi->completions);
}
EXPORT_SYMBOL(bdi_destroy);

/*
 * 关于congestion_wgh，看request_queue中的congestion_on,congestion_off的值
 *
 * 关于设置和解除congestion是代码，看
 * blk_clear_queue_congested和blk_set_queue_congested函数的注释
 */
static wait_queue_head_t congestion_wqh[2] = {
		__WAIT_QUEUE_HEAD_INITIALIZER(congestion_wqh[0]),
		__WAIT_QUEUE_HEAD_INITIALIZER(congestion_wqh[1])
	};


void clear_bdi_congested(struct backing_dev_info *bdi, int rw)
{
	enum bdi_state bit;
	wait_queue_head_t *wqh = &congestion_wqh[rw];

	bit = (rw == WRITE) ? BDI_write_congested : BDI_read_congested;
	clear_bit(bit, &bdi->state);
	smp_mb__after_clear_bit();
	if (waitqueue_active(wqh))
		wake_up(wqh);
}
EXPORT_SYMBOL(clear_bdi_congested);

void set_bdi_congested(struct backing_dev_info *bdi, int rw)
{
	enum bdi_state bit;

	bit = (rw == WRITE) ? BDI_write_congested : BDI_read_congested;
	set_bit(bit, &bdi->state);
}
EXPORT_SYMBOL(set_bdi_congested);

/**
 * congestion_wait - wait for a backing_dev to become uncongested
 * @rw: READ or WRITE
 * @timeout: timeout in jiffies
 *
 * Waits for up to @timeout jiffies for a backing_dev (any backing_dev) to exit
 * write congestion.  If no backing_devs are congested then just wait for the
 * next write to be completed.
 *
 * pdflush_operation(wb_kupdate, 0)
 *  __pdflush()
 *   wb_kupdate()
 *    congestion_wait()
 *
 * 等待块设备结束占线 
 */
long congestion_wait(int rw, long timeout)
{
	long ret;
	DEFINE_WAIT(wait);
	/*
	 * 关于congestion_wgh，看request_queue中的congestion_on,congestion_off的值
	 */
	wait_queue_head_t *wqh = &congestion_wqh[rw];

    /* 当前进程挂到congestion_wqh[rw]上去 */
	prepare_to_wait(wqh, &wait, TASK_UNINTERRUPTIBLE);
	ret = io_schedule_timeout(timeout); /* 释放cpu */
	finish_wait(wqh, &wait);
	return ret;
}
EXPORT_SYMBOL(congestion_wait);

