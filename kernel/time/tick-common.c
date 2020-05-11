/*
 * linux/kernel/time/tick-common.c
 *
 * This file contains the base functions to manage periodic tick
 * related events.
 *
 * Copyright(C) 2005-2006, Thomas Gleixner <tglx@linutronix.de>
 * Copyright(C) 2005-2007, Red Hat, Inc., Ingo Molnar
 * Copyright(C) 2006-2007, Timesys Corp., Thomas Gleixner
 *
 * This code is licenced under the GPL version 2. For details see
 * kernel-base/COPYING.
 */
#include <linux/cpu.h>
#include <linux/err.h>
#include <linux/hrtimer.h>
#include <linux/irq.h>
#include <linux/percpu.h>
#include <linux/profile.h>
#include <linux/sched.h>
#include <linux/tick.h>

#include "tick-internal.h"

/*
 * Tick devices
 * 系统中所有的cpu局部时钟变量
 *
 */
DEFINE_PER_CPU(struct tick_device, tick_cpu_device);
/*
 * Tick next event: keeps track of the tick time
 * 指定下一个全局时钟事件的发生时间
 */
ktime_t tick_next_period;
/*
 * 存储时钟周期长度,单位为纳秒，它与HZ相对，后者存储了时钟的频率
 */
ktime_t tick_period;
/* 
 * global tick device,有些任务不适合在local tick device中处理，
 * 例如更新jiffies，更新系统的wall time，更新系统的平均负载（不是单一CPU core的负载），
 * 这些都是系统级别的任务，只需要在local tick device中选择一个作为global tick device就OK了。
 * tick_do_timer_cpu指明哪一个cpu上的local tick作为global tick
 */
int tick_do_timer_cpu __read_mostly = -1;
DEFINE_SPINLOCK(tick_device_lock);

/*
 * Debugging: see timer_list.c
 */
struct tick_device *tick_get_device(int cpu)
{
	return &per_cpu(tick_cpu_device, cpu);
}

/**
 * tick_is_oneshot_available - check for a oneshot capable event device
 */
int tick_is_oneshot_available(void)
{
	struct clock_event_device *dev = __get_cpu_var(tick_cpu_device).evtdev;

	return dev && (dev->features & CLOCK_EVT_FEAT_ONESHOT);
}

/*
 * Periodic tick
 *
 * 从timer_interrupt() 时钟中断处理函数
 *   do_timer_interrupt_hook() 调用过来
 *    tick_handle_periodic()
 *      tick_periodic()
 */
static void tick_periodic(int cpu)
{
	if (tick_do_timer_cpu == cpu) { /* 是否是全局时钟 */
		/* 在xtime_lock顺序锁上产生一个write_seqlock */
		write_seqlock(&xtime_lock);

		/* Keep track of the next tick event */
		tick_next_period = ktime_add(tick_next_period, tick_period);

        /* 在do_timer中更新jiffies和cur_timer */
		do_timer(1);
		write_sequnlock(&xtime_lock);
	}

    /* 
     * 更新和当前进程相关的内容 
     *
     * 在update_process_times中调用run_local_timers执行TIMER_SOFTIRQ软中断
     * 调用 scheduler_tick，执行当前cpu上的rq 的 load balance.
     */
	update_process_times(user_mode(get_irq_regs()));
	/* 和性能剖析相关 */
	profile_tick(CPU_PROFILING);
}

/*
 * Event handler for periodic ticks
 *
 * 在tick_set_periodic_handler() 和 tick_device_uses_broadcast中
 * 设置clock_event_device->event_handler ==  tick_handle_periodic
 *
 * 从 timer_interrupt() 时钟中断处理函数
 *     do_timer_interrupt_hook() 调用过来
 *      tick_handle_periodic()
 */
void tick_handle_periodic(struct clock_event_device *dev)
{
	int cpu = smp_processor_id();
	ktime_t next;

    /* 时钟中断的真正的处理在tick_periodic中的各种调用 */
	tick_periodic(cpu);

	/* peridoic的，不用设置下次的中断时间了 */
	if (dev->mode != CLOCK_EVT_MODE_ONESHOT)
		return;
	/*
	 * 计算下一个周期性tick触发的时间 
	 * Setup the next period for devices, which do not have
	 * periodic mode:
	 */
	next = ktime_add(dev->next_event, tick_period);
	for (;;) {
		/* 设定下一个clock event触发的时间  */
		if (!clockevents_program_event(dev, next, ktime_get()))
			return;
		
		tick_periodic(cpu);
		next = ktime_add(next, tick_period);
	}
}

/*
 * Setup the device for a periodic tick
 *
 * tick_notify()
 *  tick_check_new_device()
 *   tick_setup_device() 
 *    tick_setup_periodic()
 */
void tick_setup_periodic(struct clock_event_device *dev, int broadcast)
{
    /* 设定event handler为tick_handle_periodic或者tick_handle_periodic_broadcast */
	tick_set_periodic_handler(dev, broadcast);

	/* Broadcast setup ? */
	if (!tick_device_is_functional(dev))
		return;

	if (dev->features & CLOCK_EVT_FEAT_PERIODIC) {
		clockevents_set_mode(dev, CLOCK_EVT_MODE_PERIODIC);
	} else {
		unsigned long seq;
		ktime_t next;

		do {
			seq = read_seqbegin(&xtime_lock);
			next = tick_next_period; /* 获取下一个周期性tick触发的时间  */
		} while (read_seqretry(&xtime_lock, seq));

		clockevents_set_mode(dev, CLOCK_EVT_MODE_ONESHOT);

		for (;;) {
			if (!clockevents_program_event(dev, next, ktime_get()))
				return;
			next = ktime_add(next, tick_period); /* 计算下一个周期性tick触发的时间  */
		}
	}
}

/*
 * Setup the tick device
 * 这个函数将根据不同的情况设置clock_event_device->handler
 * 
 * tick_notify()
 *  tick_check_new_device()
 *   tick_setup_device()
 */
static void tick_setup_device(struct tick_device *td,
			      struct clock_event_device *newdev, int cpu,
			      cpumask_t cpumask)
{
	ktime_t next_event;
	void (*handler)(struct clock_event_device *) = NULL;

	/*
	 * First device setup ?
	 *
	 * 系统中的第一个时钟设备？
	 *
	 * 如果当前CPU还没有clock event device,就默认新设备为周期性的设备，
	 * 并计算该设备的中断周期，其中NSEC_PER_SEC表示一秒中的纳秒数，HZ是
	 * 编译时配置的每秒的中断次数，所以tick_period就是中断周期，单位为纳秒。
	 */
	if (!td->evtdev) {
		/*
		 * If no cpu took the do_timer update, assign it to
		 * this cpu:
		 * 下面几个都是全局变量
		 */
		if (tick_do_timer_cpu == -1) {
			tick_do_timer_cpu = cpu;
			tick_next_period = ktime_get();
			tick_period = ktime_set(0, NSEC_PER_SEC / HZ);
		}

		/*
		 * Startup in periodic mode first.
		 */
		td->mode = TICKDEV_MODE_PERIODIC;
	} else {
		/* 如果当前设备cpu已经有一个clock event device了 */
		handler = td->evtdev->event_handler;
		next_event = td->evtdev->next_event;
	}

    /* tick_device和clock_event_device关联起来 */
	td->evtdev = newdev;

	/*
	 * When the device is not per cpu, pin the interrupt to the
	 * current cpu:
	 *
	 * 如果不是local timer，那么还需要调用irq_set_affinity函数，
	 * 将该clockevent的中断，定向到本CPU
	 */
	if (!cpus_equal(newdev->cpumask, cpumask))
		irq_set_affinity(newdev->irq, cpumask);

	/*
	 * When global broadcasting is active, check if the current
	 * device is registered as a placeholder for broadcast mode.
	 * This allows us to handle this x86 misfeature in a generic
	 * way.
	 * 是否需要广播,如果是，就返回了
	 * 会设置newdev->event_handler == tick_handle_periodic
	 */
	if (tick_device_uses_broadcast(newdev, cpu))
		return;
	
    //到这里说明newdev不支持broadcast模式了
   
	/*  根据tick_device的工作模式设置clock_event_device的工作模式 */
	if (td->mode == TICKDEV_MODE_PERIODIC)
		/* 也会设置newdev->event_handler == tick_handle_periodic */
		tick_setup_periodic(newdev, 0);
	else
		/* 设置原设备的event_handler到newdev->event_handler */
		tick_setup_oneshot(newdev, handler, next_event);
}

/*
 * Check, if the new registered device should be used.
 *
 * tick_notify()
 *  tick_check_new_device()
 */
static int tick_check_new_device(struct clock_event_device *newdev)
{
	struct clock_event_device *curdev;
	struct tick_device *td;
	int cpu, ret = NOTIFY_OK;
	unsigned long flags;
	cpumask_t cpumask;

	spin_lock_irqsave(&tick_device_lock, flags);

	cpu = smp_processor_id();
	if (!cpu_isset(cpu, newdev->cpumask))
		goto out_bc;

    /* 当前cpu的   tick_device对象 */
	td = &per_cpu(tick_cpu_device, cpu);

	/* 当前cpu使用的 clock      event device*/
	curdev = td->evtdev;
	cpumask = cpumask_of_cpu(cpu);

	/* cpu local device ? */
	if (!cpus_equal(newdev->cpumask, cpumask)) {

		/*
		 * If the cpu affinity of the device interrupt can not
		 * be set, ignore it.
		 *
		 * 如果该设备不是CPU的本地设备，则先判断新注册的设备是否能够向该CPU发IRQ，
		 * 如果新注册的设备不能向该CPU发出中断请求，则维持不变。
		 */
		if (!irq_can_set_affinity(newdev->irq))
			goto out_bc;

		/*
		 * If we have a cpu local device already, do not replace it
		 * by a non cpu local device
		 *
		 * 如果新设备不是cpu的本地设备，且当前CPU使用的设备是本地设备，
		 * 则还是使用原设备。
		 */
		if (curdev && cpus_equal(curdev->cpumask, cpumask))
			goto out_bc;
	}

	/*
	 * If we have an active device, then check the rating and the oneshot
	 * feature.
	 */
	if (curdev) {
		/*
		 * Prefer one shot capable devices !
		 * 如果CPU当前设备使用的设备支持one shot工作模式，而新注册的设备不支持此模式，
		 * 依旧使用原设备
		 *
		 */
		if ((curdev->features & CLOCK_EVT_FEAT_ONESHOT) &&
		    !(newdev->features & CLOCK_EVT_FEAT_ONESHOT))
			goto out_bc;
		/*
		 * Check the rating
		 *
		 * 新设备的rating不够，依旧使用原设备
		 */
		if (curdev->rating >= newdev->rating)
			goto out_bc;
	}

	/*
	 * Replace the eventually existing device by the new
	 * device. If the current device is the broadcast device, do
	 * not give it back to the clockevents layer !
	 *
	 * 运行到此，则说明可以使用新的设备
	 */
	if (tick_is_broadcast_device(curdev)) {
		/* 关闭当前使用的设备 */
		clockevents_set_mode(curdev, CLOCK_EVT_MODE_SHUTDOWN);
		curdev = NULL;
	}

	/*  */
	clockevents_exchange_device(curdev, newdev);
	
	tick_setup_device(td, newdev, cpu, cpumask);

	if (newdev->features & CLOCK_EVT_FEAT_ONESHOT)
		tick_oneshot_notify();

	spin_unlock_irqrestore(&tick_device_lock, flags);
	return NOTIFY_STOP;

out_bc:
	/*
	 * Can the new device be used as a broadcast device ?
	 *  
	 * 如果新设备有broadcast功能的 clock event device，
	 * 并且没有被某个CPU用作自己的clock event device,
	 * 那么最后的tick_check_broadcast_device试图把它作为broadcast设备
	 * 并设置全局变量tick_broadcast_device
	 */
	if (tick_check_broadcast_device(newdev))
		ret = NOTIFY_STOP;

	spin_unlock_irqrestore(&tick_device_lock, flags);

	return ret;
}

/*
 * Shutdown an event device on a given cpu:
 *
 * This is called on a life CPU, when a CPU is dead. So we cannot
 * access the hardware device itself.
 * We just set the mode and remove it from the lists.
 */
static void tick_shutdown(unsigned int *cpup)
{
	struct tick_device *td = &per_cpu(tick_cpu_device, *cpup);
	struct clock_event_device *dev = td->evtdev;
	unsigned long flags;

	spin_lock_irqsave(&tick_device_lock, flags);
	td->mode = TICKDEV_MODE_PERIODIC;
	if (dev) {
		/*
		 * Prevent that the clock events layer tries to call
		 * the set mode function!
		 */
		dev->mode = CLOCK_EVT_MODE_UNUSED;
		clockevents_exchange_device(dev, NULL);
		td->evtdev = NULL;
	}
	/* Transfer the do_timer job away from this cpu */
	if (*cpup == tick_do_timer_cpu) {
		int cpu = first_cpu(cpu_online_map);

		tick_do_timer_cpu = (cpu != NR_CPUS) ? cpu : -1;
	}
	spin_unlock_irqrestore(&tick_device_lock, flags);
}

static void tick_suspend(void)
{
	struct tick_device *td = &__get_cpu_var(tick_cpu_device);
	unsigned long flags;

	spin_lock_irqsave(&tick_device_lock, flags);
	clockevents_set_mode(td->evtdev, CLOCK_EVT_MODE_SHUTDOWN);
	spin_unlock_irqrestore(&tick_device_lock, flags);
}

static void tick_resume(void)
{
	struct tick_device *td = &__get_cpu_var(tick_cpu_device);
	unsigned long flags;
	int broadcast = tick_resume_broadcast();

	spin_lock_irqsave(&tick_device_lock, flags);
	clockevents_set_mode(td->evtdev, CLOCK_EVT_MODE_RESUME);

	if (!broadcast) {
		if (td->mode == TICKDEV_MODE_PERIODIC)
			tick_setup_periodic(td->evtdev, 0);
		else
			tick_resume_oneshot();
	}
	spin_unlock_irqrestore(&tick_device_lock, flags);
}

/*
 * Notification about clock event devices
 *
 * tick_notifier->notifier_call ==  tick_notify
 *
 */
static int tick_notify(struct notifier_block *nb, unsigned long reason,
			       void *dev)
{
	switch (reason) {

	case CLOCK_EVT_NOTIFY_ADD: /* 检测到新的时钟设备，确定设备处理函数 */
		return tick_check_new_device(dev);

	case CLOCK_EVT_NOTIFY_BROADCAST_ON:
	case CLOCK_EVT_NOTIFY_BROADCAST_OFF:
	case CLOCK_EVT_NOTIFY_BROADCAST_FORCE:
		tick_broadcast_on_off(reason, dev);
		break;

	case CLOCK_EVT_NOTIFY_BROADCAST_ENTER:
	case CLOCK_EVT_NOTIFY_BROADCAST_EXIT:
		tick_broadcast_oneshot_control(reason);
		break;

	case CLOCK_EVT_NOTIFY_CPU_DEAD:
		tick_shutdown_broadcast_oneshot(dev);
		tick_shutdown_broadcast(dev);
		tick_shutdown(dev);
		break;

	case CLOCK_EVT_NOTIFY_SUSPEND:
		tick_suspend();
		tick_suspend_broadcast();
		break;

	case CLOCK_EVT_NOTIFY_RESUME:
		tick_resume();
		break;

	default:
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block tick_notifier = {
	.notifier_call = tick_notify,
};

/**
 * tick_init - initialize the tick control
 *
 * Register the notifier with the clockevents framework
 *
 * start_kernel()
 *  tick_init()
 */
void __init tick_init(void)
{
	clockevents_register_notifier(&tick_notifier);
}
