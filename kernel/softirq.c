/*
 *	linux/kernel/softirq.c
 *
 *	Copyright (C) 1992 Linus Torvalds
 *
 * Rewritten. Old one was good in 2.2, but in 2.3 it was immoral. --ANK (990903)
 */

#include <linux/module.h>
#include <linux/kernel_stat.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/notifier.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/rcupdate.h>
#include <linux/smp.h>
#include <linux/tick.h>

#include <asm/irq.h>
/*
   - No shared variables, all the data are CPU local.
   - If a softirq needs serialization, let it serialize itself
     by its own spinlocks.
   - Even if softirq is serialized, only local cpu is marked for
     execution. Hence, we get something sort of weak cpu binding.
     Though it is still not clear, will it result in better locality
     or will not.

   Examples:
   - NET RX softirq. It is multithreaded and does not require
     any global serialization.
   - NET TX softirq. It kicks software netdevice queues, hence
     it is logically serialized per device, but this serialization
     is invisible to common code.
   - Tasklets: serialized wrt itself.
 */

#ifndef __ARCH_IRQ_STAT
irq_cpustat_t irq_stat[NR_CPUS] ____cacheline_aligned;
EXPORT_SYMBOL(irq_stat);
#endif

static struct softirq_action softirq_vec[32] __cacheline_aligned_in_smp;

static DEFINE_PER_CPU(struct task_struct *, ksoftirqd);

/*
 * we cannot loop indefinitely here to avoid userspace starvation,
 * but we also don't want to introduce a worst case 1/HZ latency
 * to the pending events, so lets the scheduler to balance
 * the softirq load for us.
 */
static inline void wakeup_softirqd(void)
{
	/* Interrupts are disabled: no need to stop preemption */
	struct task_struct *tsk = __get_cpu_var(ksoftirqd);

	if (tsk && tsk->state != TASK_RUNNING)
		wake_up_process(tsk);
}

/*
 * This one is for softirq.c-internal use,
 * where hardirqs are disabled legitimately:
 */
#ifdef CONFIG_TRACE_IRQFLAGS
static void __local_bh_disable(unsigned long ip)
{
	unsigned long flags;

	WARN_ON_ONCE(in_irq());

	raw_local_irq_save(flags);
	add_preempt_count(SOFTIRQ_OFFSET);
	/*
	 * Were softirqs turned off above:
	 */
	if (softirq_count() == SOFTIRQ_OFFSET)
		trace_softirqs_off(ip);
	raw_local_irq_restore(flags);
}
#else /* !CONFIG_TRACE_IRQFLAGS */
static inline void __local_bh_disable(unsigned long ip)
{
	add_preempt_count(SOFTIRQ_OFFSET);
	barrier();
}
#endif /* CONFIG_TRACE_IRQFLAGS */

/*
 * 就是关闭软中断处理
 */
void local_bh_disable(void)
{
	__local_bh_disable((unsigned long)__builtin_return_address(0));
}

EXPORT_SYMBOL(local_bh_disable);

void __local_bh_enable(void)
{
	WARN_ON_ONCE(in_irq());

	/*
	 * softirqs should never be enabled by __local_bh_enable(),
	 * it always nests inside local_bh_enable() sections:
	 */
	WARN_ON_ONCE(softirq_count() == SOFTIRQ_OFFSET);

	sub_preempt_count(SOFTIRQ_OFFSET);
}
EXPORT_SYMBOL_GPL(__local_bh_enable);

/*
 * Special-case - softirqs can safely be enabled in
 * cond_resched_softirq(), or by __do_softirq(),
 * without processing still-pending softirqs:
 */
void _local_bh_enable(void)
{
	WARN_ON_ONCE(in_irq());
	WARN_ON_ONCE(!irqs_disabled());

	if (softirq_count() == SOFTIRQ_OFFSET)
		trace_softirqs_on((unsigned long)__builtin_return_address(0));
	sub_preempt_count(SOFTIRQ_OFFSET);
}

EXPORT_SYMBOL(_local_bh_enable);

void local_bh_enable(void)
{
#ifdef CONFIG_TRACE_IRQFLAGS
	unsigned long flags;

	WARN_ON_ONCE(in_irq());
#endif
	WARN_ON_ONCE(irqs_disabled());

#ifdef CONFIG_TRACE_IRQFLAGS
	local_irq_save(flags);
#endif
	/*
	 * Are softirqs going to be turned on now:
	 */
	if (softirq_count() == SOFTIRQ_OFFSET)
		trace_softirqs_on((unsigned long)__builtin_return_address(0));
	/*
	 * Keep preemption disabled until we are done with
	 * softirq processing:
 	 */
 	sub_preempt_count(SOFTIRQ_OFFSET - 1);

	if (unlikely(!in_interrupt() && local_softirq_pending()))
		do_softirq();

	dec_preempt_count();
#ifdef CONFIG_TRACE_IRQFLAGS
	local_irq_restore(flags);
#endif
	preempt_check_resched();
}
EXPORT_SYMBOL(local_bh_enable);

void local_bh_enable_ip(unsigned long ip)
{
#ifdef CONFIG_TRACE_IRQFLAGS
	unsigned long flags;

	WARN_ON_ONCE(in_irq());

	local_irq_save(flags);
#endif
	/*
	 * Are softirqs going to be turned on now:
	 */
	if (softirq_count() == SOFTIRQ_OFFSET)
		trace_softirqs_on(ip);
	/*
	 * Keep preemption disabled until we are done with
	 * softirq processing:
 	 */
 	sub_preempt_count(SOFTIRQ_OFFSET - 1);

	if (unlikely(!in_interrupt() && local_softirq_pending()))
		do_softirq();

	dec_preempt_count();
#ifdef CONFIG_TRACE_IRQFLAGS
	local_irq_restore(flags);
#endif
	preempt_check_resched();
}
EXPORT_SYMBOL(local_bh_enable_ip);

/*
 * We restart softirq processing MAX_SOFTIRQ_RESTART times,
 * and we fall back to softirqd after that.
 *
 * This number has been established via experimentation.
 * The two things to balance is latency against fairness -
 * we want to handle softirqs as soon as possible, but they
 * should not be able to lock up the box.
 */
#define MAX_SOFTIRQ_RESTART 10

/*
 * 执行软中断了,是在中断堆栈中执行这个函数的
 * 处理软中断的时候，允许处理硬件中断的。
 *
 * irq_exit()
 *  do_softirq()
 *   __do_softirq()
 */
asmlinkage void __do_softirq(void)
{
	struct softirq_action *h;
	__u32 pending;
	int max_restart = MAX_SOFTIRQ_RESTART;
	int cpu;

    /* 当前被设置的soft       irq */
	pending = local_softirq_pending();
	account_system_vtime(current);

	__local_bh_disable((unsigned long)__builtin_return_address(0));
	trace_softirq_enter();

	cpu = smp_processor_id();
restart:
	/* Reset the pending bitmask before enabling irqs */
	set_softirq_pending(0);

    /* 开启cpu中断,用sti指令设置IF标记 */
	local_irq_enable();

	h = softirq_vec; /* softirq_action数组 */

    /* 遍历softirq_vec，执行其中的函数 */
	do {
		if (pending & 1) {
			/* 调用软中断处理函数 */
			h->action(h);
			rcu_bh_qsctr_inc(cpu);
		}
		h++;
		pending >>= 1;
	} while (pending);

	local_irq_disable();

    /* 在上面的这个do while之间，又有软中断加进来了 */
	pending = local_softirq_pending();
	if (pending && --max_restart)  /* 没有到达max_restart次数，可以再次处理新来的软中断 */
		goto restart;

	/* 软中断太多了，还有软中断没有处理完，唤醒另外的ksoftirqd线程 */
	if (pending)
		wakeup_softirqd(); /* 唤醒ksoftirqd */

	trace_softirq_exit();

	account_system_vtime(current);
	_local_bh_enable();
}

#ifndef __ARCH_HAS_DO_SOFTIRQ

/*
 *
 * do_IRQ()
 *   irq_exit()
 *     do_softirq()
 *
 */
asmlinkage void do_softirq(void)
{
	__u32 pending;
	unsigned long flags;

	if (in_interrupt())
		return;

	local_irq_save(flags);

	pending = local_softirq_pending();

	if (pending)
		__do_softirq();

	local_irq_restore(flags);
}

#endif

/*
 * Enter an interrupt context.
 *
 * thread_info->preempt_count += 1;
 *
 * do_IRQ()
 *  irq_enter()
 */
void irq_enter(void)
{
	__irq_enter(); //增加preempt_count,暂时禁止内核态抢占
	 /* 更新系统时间 */
#ifdef CONFIG_NO_HZ
	if (idle_cpu(smp_processor_id()))
		tick_nohz_update_jiffies(); //更新计时，nohz模式由此来作为触发下一中断的时机参考。怎么理解呢？看看这个调用条件，只有在cpu处于idle状态时才更新时间，因为cpu处于idle时可能已经将周期时钟停掉了，为了不遗失时间信息，必须在中断中补上。
#endif
}

#ifdef __ARCH_IRQ_EXIT_IRQS_DISABLED
# define invoke_softirq()	__do_softirq()
#else
# define invoke_softirq()	do_softirq()
#endif

/*
 * Exit an interrupt context. Process softirqs if needed and possible:
 * 首先去掉中断上下文标记，然后处理软中断
 *
 * do_IRQ()
 *   irq_exit()
 */
void irq_exit(void)
{
	account_system_vtime(current);
	trace_hardirq_exit();
	/* 开启允许处理硬件中断 */
	sub_preempt_count(IRQ_EXIT_OFFSET);

	/* 不在处理硬件中断、软件中断，允许抢占，并且有软中断需要处理 */
	if (!in_interrupt() && local_softirq_pending())
		invoke_softirq(); /* kernel/softirq.c */

#ifdef CONFIG_NO_HZ
	/* 有配置tickless时
	 * Make sure that timer wheel updates are propagated 
     */
	if (!in_interrupt() && idle_cpu(smp_processor_id()) && !need_resched())
		tick_nohz_stop_sched_tick();
#endif
	preempt_enable_no_resched();
}

/*
 * This function must run with irqs disabled!
 * 唤醒ksoftirqd进程
 * 设置percpu(_cpu_data,cpuid)->__softirq_pending的第nr位
 */
inline fastcall void raise_softirq_irqoff(unsigned int nr)
{
	__raise_softirq_irqoff(nr);

	/*
	 * If we're in an interrupt or softirq, we're done
	 * (this also catches softirq-disabled code). We will
	 * actually run the softirq once we return from
	 * the irq or softirq.
	 *
	 * Otherwise we wake up ksoftirqd to make sure we
	 * schedule the softirq soon.
	 * 如果不是在中断上下文中调用本函数的，那就唤醒ksoftirqd进程
	 */
	if (!in_interrupt())
		wakeup_softirqd();
}

/*
 * 设置对应cpu上的irq_stat[cpuid].__softirq_pending的bit位
 */
void fastcall raise_softirq(unsigned int nr)
{
	unsigned long flags;

	local_irq_save(flags);
	raise_softirq_irqoff(nr);
	local_irq_restore(flags);
}

void open_softirq(int nr, void (*action)(struct softirq_action*), void *data)
{
	softirq_vec[nr].data = data;
	softirq_vec[nr].action = action;
}

/* Tasklets */
struct tasklet_head
{
	struct tasklet_struct *list;
};

/* Some compilers disobey section attribute on statics when not
 *  initialized -- RR 
 *
 * tasklet_hi_vec, tasklet_vec 都是PERCPU变量
 */
static DEFINE_PER_CPU(struct tasklet_head, tasklet_vec) = { NULL };
static DEFINE_PER_CPU(struct tasklet_head, tasklet_hi_vec) = { NULL };

/*
 * 将tasklet排队到tasklet_vec中
 */
void fastcall __tasklet_schedule(struct tasklet_struct *t)
{
	unsigned long flags;

	local_irq_save(flags);
	t->next = __get_cpu_var(tasklet_vec).list;
	__get_cpu_var(tasklet_vec).list = t;
	raise_softirq_irqoff(TASKLET_SOFTIRQ);
	local_irq_restore(flags);
}

EXPORT_SYMBOL(__tasklet_schedule);

/*
 * tasklet_hi_schedule()
 *    __tasklet_hi_schedule()
 *
 * 将tasklet排队到tasklet_hi_vec中
 *
 */
void fastcall __tasklet_hi_schedule(struct tasklet_struct *t)
{
	unsigned long flags;

	local_irq_save(flags);
	t->next = __get_cpu_var(tasklet_hi_vec).list;
	__get_cpu_var(tasklet_hi_vec).list = t; /* 添加到tasklet_hi_vec队列尾部 */
	raise_softirq_irqoff(HI_SOFTIRQ); /* 设置percpu(_cpu_data,cpuid)->__softirq_pending的第HI_SOFTIRQ */
	local_irq_restore(flags);
}

EXPORT_SYMBOL(__tasklet_hi_schedule);

/*
 * 运行tasklet_vec中的tasklet
 */
static void tasklet_action(struct softirq_action *a)
{
	struct tasklet_struct *list;

	local_irq_disable();
	list = __get_cpu_var(tasklet_vec).list;
	__get_cpu_var(tasklet_vec).list = NULL;
	local_irq_enable();

	while (list) {
		struct tasklet_struct *t = list;

		list = list->next;

		//设置RUN位
		if (tasklet_trylock(t)) {
			
			if (!atomic_read(&t->count)) {
				//清空SCHED位
				if (!test_and_clear_bit(TASKLET_STATE_SCHED, &t->state))
					BUG();
				
				t->func(t->data); /* 走起 */
				tasklet_unlock(t);
				continue; /* 跑下一个  tasklet */
			}
			tasklet_unlock(t);
		}

		local_irq_disable();
		t->next = __get_cpu_var(tasklet_vec).list;
		__get_cpu_var(tasklet_vec).list = t; /* 没有跑的放到头上 */
		__raise_softirq_irqoff(TASKLET_SOFTIRQ);
		local_irq_enable();
	}
}

/*
 * irq_exit()中调用
 *  __do_softirq()
 *   tasklet_hi_action()
 */
static void tasklet_hi_action(struct softirq_action *a)
{
	struct tasklet_struct *list;

	local_irq_disable();
	list = __get_cpu_var(tasklet_hi_vec).list;
	__get_cpu_var(tasklet_hi_vec).list = NULL;
	local_irq_enable();

	while (list) {
		struct tasklet_struct *t = list;

		list = list->next;

		if (tasklet_trylock(t)) {
			//t->count==0，说明tasklet没有被执行
			if (!atomic_read(&t->count)) {
				if (!test_and_clear_bit(TASKLET_STATE_SCHED, &t->state))
					BUG();
				//调用
				t->func(t->data);
				tasklet_unlock(t);
				continue;
			}
			tasklet_unlock(t);
		}

		local_irq_disable();
		
		t->next = __get_cpu_var(tasklet_hi_vec).list;
		__get_cpu_var(tasklet_hi_vec).list = t;
		__raise_softirq_irqoff(HI_SOFTIRQ);
		local_irq_enable();
	}
}


void tasklet_init(struct tasklet_struct *t,
		  void (*func)(unsigned long), unsigned long data)
{
	t->next = NULL;
	t->state = 0;
	atomic_set(&t->count, 0);
	t->func = func;
	t->data = data;
}

EXPORT_SYMBOL(tasklet_init);

void tasklet_kill(struct tasklet_struct *t)
{
	if (in_interrupt())
		printk("Attempt to kill tasklet from interrupt\n");

	while (test_and_set_bit(TASKLET_STATE_SCHED, &t->state)) {
		do
			yield();
		while (test_bit(TASKLET_STATE_SCHED, &t->state));
	}
	tasklet_unlock_wait(t);
	clear_bit(TASKLET_STATE_SCHED, &t->state);
}

EXPORT_SYMBOL(tasklet_kill);

/*
 * start_kernel()
 *  softirq_init()
 */
void __init softirq_init(void)
{

	open_softirq(TASKLET_SOFTIRQ, tasklet_action, NULL);
	open_softirq(HI_SOFTIRQ, tasklet_hi_action, NULL);
}


/*
 * 执行软中断的守护进程
 * 在__do_softirq中唤醒
 */
static int ksoftirqd(void * __bind_cpu)
{
	set_current_state(TASK_INTERRUPTIBLE);

	while (!kthread_should_stop()) {
		preempt_disable();
		
		if (!local_softirq_pending()) {
			/* 没有软中断可调 */
			preempt_enable_no_resched();
			schedule();/* 放弃cpu */
			preempt_disable(); /* 重新得到cpu时 */
		}

		__set_current_state(TASK_RUNNING);

		while (local_softirq_pending()) {
			/* Preempt disable stops cpu going offline.
			   If already offline, we'll be on wrong CPU:
			   don't process */
			if (cpu_is_offline((long)__bind_cpu))
				goto wait_to_die;
			do_softirq(); /* 执行软中断 */
			preempt_enable_no_resched();
			cond_resched(); /* 进程调度 */
			preempt_disable();
		}
		preempt_enable();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);
	return 0;

wait_to_die:
	preempt_enable();
	/* Wait for kthread_stop */
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);
	return 0;
}

#ifdef CONFIG_HOTPLUG_CPU
/*
 * tasklet_kill_immediate is called to remove a tasklet which can already be
 * scheduled for execution on @cpu.
 *
 * Unlike tasklet_kill, this function removes the tasklet
 * _immediately_, even if the tasklet is in TASKLET_STATE_SCHED state.
 *
 * When this function is called, @cpu must be in the CPU_DEAD state.
 */
void tasklet_kill_immediate(struct tasklet_struct *t, unsigned int cpu)
{
	struct tasklet_struct **i;

	BUG_ON(cpu_online(cpu));
	BUG_ON(test_bit(TASKLET_STATE_RUN, &t->state));

	if (!test_bit(TASKLET_STATE_SCHED, &t->state))
		return;

	/* CPU is dead, so no lock needed. */
	for (i = &per_cpu(tasklet_vec, cpu).list; *i; i = &(*i)->next) {
		if (*i == t) {
			*i = t->next;
			return;
		}
	}
	BUG();
}

static void takeover_tasklets(unsigned int cpu)
{
	struct tasklet_struct **i;

	/* CPU is dead, so no lock needed. */
	local_irq_disable();

	/* Find end, append list for that CPU. */
	for (i = &__get_cpu_var(tasklet_vec).list; *i; i = &(*i)->next);
	*i = per_cpu(tasklet_vec, cpu).list;
	per_cpu(tasklet_vec, cpu).list = NULL;
	raise_softirq_irqoff(TASKLET_SOFTIRQ);

	for (i = &__get_cpu_var(tasklet_hi_vec).list; *i; i = &(*i)->next);
	*i = per_cpu(tasklet_hi_vec, cpu).list;
	per_cpu(tasklet_hi_vec, cpu).list = NULL;
	raise_softirq_irqoff(HI_SOFTIRQ);

	local_irq_enable();
}
#endif /* CONFIG_HOTPLUG_CPU */

static int __cpuinit cpu_callback(struct notifier_block *nfb,
				  unsigned long action,
				  void *hcpu)
{
	int hotcpu = (unsigned long)hcpu;
	struct task_struct *p;

	switch (action) {
	case CPU_UP_PREPARE:
	case CPU_UP_PREPARE_FROZEN:
		p = kthread_create(ksoftirqd, hcpu, "ksoftirqd/%d", hotcpu);
		if (IS_ERR(p)) {
			printk("ksoftirqd for %i failed\n", hotcpu);
			return NOTIFY_BAD;
		}
		kthread_bind(p, hotcpu);
  		per_cpu(ksoftirqd, hotcpu) = p;
 		break;
	case CPU_ONLINE:
	case CPU_ONLINE_FROZEN:
		wake_up_process(per_cpu(ksoftirqd, hotcpu));
		break;
#ifdef CONFIG_HOTPLUG_CPU
	case CPU_UP_CANCELED:
	case CPU_UP_CANCELED_FROZEN:
		if (!per_cpu(ksoftirqd, hotcpu))
			break;
		/* Unbind so it can run.  Fall thru. */
		kthread_bind(per_cpu(ksoftirqd, hotcpu),
			     any_online_cpu(cpu_online_map));
	case CPU_DEAD:
	case CPU_DEAD_FROZEN: {
		struct sched_param param = { .sched_priority = MAX_RT_PRIO-1 };

		p = per_cpu(ksoftirqd, hotcpu);
		per_cpu(ksoftirqd, hotcpu) = NULL;
		sched_setscheduler(p, SCHED_FIFO, &param);
		kthread_stop(p);
		takeover_tasklets(hotcpu);
		break;
	}
#endif /* CONFIG_HOTPLUG_CPU */
 	}
	return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata cpu_nfb = {
	.notifier_call = cpu_callback
};

/*
 * start_kernel()
 *   rest_init() 中调用kernel_thread()创建kernel_init线程
 *    kernel_init()
 *     do_pre_smp_initcalls()
 *      spawn_ksoftirqd()
 * 创建或者启动watchdog_task线程(入口函数为ksoftirqd)
 */
__init int spawn_ksoftirqd(void)
{
	void *cpu = (void *)(long)smp_processor_id();
	int err = cpu_callback(&cpu_nfb, CPU_UP_PREPARE, cpu);

	BUG_ON(err == NOTIFY_BAD);
	cpu_callback(&cpu_nfb, CPU_ONLINE, cpu);
	register_cpu_notifier(&cpu_nfb);
	return 0;
}

#ifdef CONFIG_SMP
/*
 * Call a function on all processors
 */
int on_each_cpu(void (*func) (void *info), void *info, int retry, int wait)
{
	int ret = 0;

	preempt_disable();
	ret = smp_call_function(func, info, retry, wait);
	local_irq_disable();
	func(info);
	local_irq_enable();
	preempt_enable();
	return ret;
}
EXPORT_SYMBOL(on_each_cpu);
#endif
