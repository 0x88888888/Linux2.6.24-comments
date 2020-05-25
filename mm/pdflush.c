/*
 * mm/pdflush.c - worker threads for writing back filesystem data
 *
 * Copyright (C) 2002, Linus Torvalds.
 *
 * 09Apr2002	akpm@zip.com.au
 *		Initial version
 * 29Feb2004	kaos@sgi.com
 *		Move worker thread creation to kthread to avoid chewing
 *		up stack space with nested calls to kernel_thread.
 */

#include <linux/sched.h>
#include <linux/list.h>
#include <linux/signal.h>
#include <linux/spinlock.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>		// Needed by writeback.h
#include <linux/writeback.h>	// Prototypes pdflush_operation()
#include <linux/kthread.h>
#include <linux/cpuset.h>
#include <linux/freezer.h>


/*
 * Minimum and maximum number of pdflush instances
 */
#define MIN_PDFLUSH_THREADS	2
#define MAX_PDFLUSH_THREADS	8

static void start_one_pdflush_thread(void);


/*
 * The pdflush threads are worker threads for writing back dirty data.
 * Ideally, we'd like one thread per active disk spindle.  But the disk
 * topology is very hard to divine at this level.   Instead, we take
 * care in various places to prevent more than one pdflush thread from
 * performing writeback against a single filesystem.  pdflush threads
 * have the PF_FLUSHER flag set in current->flags to aid in this.
 */

/*
 * All the pdflush threads.  Protected by pdflush_lock
 */
static LIST_HEAD(pdflush_list);
static DEFINE_SPINLOCK(pdflush_lock);

/*
 * The count of currently-running pdflush threads.  Protected
 * by pdflush_lock.
 *
 * Readable by sysctl, but not writable.  Published to userspace at
 * /proc/sys/vm/nr_pdflush_threads.
 */
int nr_pdflush_threads = 0;

/*
 * The time at which the pdflush thread pool last went empty
 */
static unsigned long last_empty_jifs;

/*
 * The pdflush thread.
 *
 * Thread pool management algorithm:
 * 
 * - The minimum and maximum number of pdflush instances are bound
 *   by MIN_PDFLUSH_THREADS and MAX_PDFLUSH_THREADS.
 * 
 * - If there have been no idle pdflush instances for 1 second, create
 *   a new one.
 * 
 * - If the least-recently-went-to-sleep pdflush thread has been asleep
 *   for more than one second, terminate a thread.
 */

/*
 * A structure for passing work to a pdflush thread.  Also for passing
 * state information between pdflush threads.  Protected by pdflush_lock.
 *
 * 表示pdflush线程的工作，状态
 */
struct pdflush_work {
	struct task_struct *who;	/* The thread */
	void (*fn)(unsigned long);	/* A callback function */
	unsigned long arg0;		/* An argument to the callback */
	struct list_head list;		/* On pdflush_list, when idle */
	unsigned long when_i_went_to_sleep;
};

/*
 * pdflush()
 *  __pdflush()
 */
static int __pdflush(struct pdflush_work *my_work)
{
	current->flags |= PF_FLUSHER | PF_SWAPWRITE;
	set_freezable();
	my_work->fn = NULL;
	my_work->who = current;
	INIT_LIST_HEAD(&my_work->list);

	spin_lock_irq(&pdflush_lock);
	nr_pdflush_threads++;
	for ( ; ; ) {
		struct pdflush_work *pdf;

		set_current_state(TASK_INTERRUPTIBLE);
	   
		list_move(&my_work->list, &pdflush_list); /* 将my_work->list转移到pdflush_list链表 */
		my_work->when_i_went_to_sleep = jiffies;
		spin_unlock_irq(&pdflush_lock);
		schedule(); /* 放弃cpu */
		try_to_freeze();
		spin_lock_irq(&pdflush_lock);
		
		if (!list_empty(&my_work->list)) {
			/*
			 * Someone woke us up, but without removing our control
			 * structure from the global list.  swsusp will do this
			 * in try_to_freeze()->refrigerator().  Handle it.
			 */
			my_work->fn = NULL;
			continue;
		}
		
		if (my_work->fn == NULL) {
			printk("pdflush: bogus wakeup\n");
			continue;
		}
		spin_unlock_irq(&pdflush_lock);

        /*
         * 工作函数
		 */
		(*my_work->fn)(my_work->arg0);

		/*
		 * Thread creation: For how long have there been zero
		 * available threads?
		 */
		if (jiffies - last_empty_jifs > 1 * HZ) {
			/* unlocked list_empty() test is OK here */
			if (list_empty(&pdflush_list)) {
				/* unlocked test is OK here */
				if (nr_pdflush_threads < MAX_PDFLUSH_THREADS)
					start_one_pdflush_thread(); /* 启动一个新的pdflush线程 */
			}
		}

		spin_lock_irq(&pdflush_lock);
		my_work->fn = NULL;

		/*
		 * Thread destruction: For how long has the sleepiest
		 * thread slept?
		 */
		if (list_empty(&pdflush_list))
			continue;
		if (nr_pdflush_threads <= MIN_PDFLUSH_THREADS)
			continue;
		pdf = list_entry(pdflush_list.prev, struct pdflush_work, list);
		if (jiffies - pdf->when_i_went_to_sleep > 1 * HZ) {
			/* Limit exit rate */
			pdf->when_i_went_to_sleep = jiffies;
			break;					/* exeunt */
		}
	}
	nr_pdflush_threads--;
	spin_unlock_irq(&pdflush_lock);
	return 0;
}

/*
 * Of course, my_work wants to be just a local in __pdflush().  It is
 * separated out in this manner to hopefully prevent the compiler from
 * performing unfortunate optimisations against the auto variables.  Because
 * these are visible to other tasks and CPUs.  (No problem has actually
 * been observed.  This is just paranoia).
 *
 * pdflush内核线程,
 *
 */
static int pdflush(void *dummy)
{
	struct pdflush_work my_work;
	cpumask_t cpus_allowed;

	/*
	 * pdflush can spend a lot of time doing encryption via dm-crypt.  We
	 * don't want to do that at keventd's priority.
	 */
	set_user_nice(current, 0);

	/*
	 * Some configs put our parent kthread in a limited cpuset,
	 * which kthread() overrides, forcing cpus_allowed == CPU_MASK_ALL.
	 * Our needs are more modest - cut back to our cpusets cpus_allowed.
	 * This is needed as pdflush's are dynamically created and destroyed.
	 * The boottime pdflush's are easily placed w/o these 2 lines.
	 */
	cpus_allowed = cpuset_cpus_allowed(current);
	set_cpus_allowed(current, cpus_allowed);

	return __pdflush(&my_work);
}

/*
 * Attempt to wake up a pdflush thread, and get it to do some work for you.
 * Returns zero if it indeed managed to find a worker thread, and passed your
 * payload to it.
 *
 * balance_dirty_pages()
 *  pdflush_operation(background_writeout, 0)
 *
 * wakeup_pdflush()
 *  pdflush_operation(background_writeout, nr_pages)
 *
 * wb_timer_fn()
 *  pdflush_operation(wb_kupdate, 0)
 *
 * laptop_timer_fn()
 *  pdflush_operation(laptop_flush, 0)
 *
 * emergency_remount()
 *  pdflush_operation(do_emergency_remount, 0)
 *
 * emergency_sync()
 *  pdflush_operation(do_sync, 0)
 *
 *
 * 这个函数除了wakeup_pdflush调用,arg0都为0
 */
int pdflush_operation(void (*fn)(unsigned long), unsigned long arg0)
{
	unsigned long flags;
	int ret = 0;

	BUG_ON(fn == NULL);	/* Hard to diagnose if it's deferred */

	spin_lock_irqsave(&pdflush_lock, flags);
	if (list_empty(&pdflush_list)) { /* 没有空闲的pdflush线程 */
		
		spin_unlock_irqrestore(&pdflush_lock, flags);
		ret = -1;
	} else {
		struct pdflush_work *pdf;

		/* 遍历pdflush线程 */
		pdf = list_entry(pdflush_list.next, struct pdflush_work, list);
		
		list_del_init(&pdf->list); /* 脱离链表 */
		if (list_empty(&pdflush_list))
			last_empty_jifs = jiffies; /* 如果没有可用的pdflush了，设置last_empty_jifs,以备创建新的pdflush线程 */

		/* 回调函数设置 */
		pdf->fn = fn; //background_writeout
		pdf->arg0 = arg0;
		/* 唤醒 */
		wake_up_process(pdf->who);
		spin_unlock_irqrestore(&pdflush_lock, flags);
	}
	return ret;
}

/*
 * pdflush_init()
 *  start_one_pdflush_thread()
 */
static void start_one_pdflush_thread(void)
{
	kthread_run(pdflush, NULL, "pdflush");
}

static int __init pdflush_init(void)
{
	int i;

	for (i = 0; i < MIN_PDFLUSH_THREADS; i++)
		start_one_pdflush_thread();
	return 0;
}

module_init(pdflush_init);
