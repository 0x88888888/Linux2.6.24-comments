#ifndef __LINUX_SPINLOCK_TYPES_H
#define __LINUX_SPINLOCK_TYPES_H

/*
 * include/linux/spinlock_types.h - generic spinlock type definitions
 *                                  and initializers
 *
 * portions Copyright 2005, Red Hat, Inc., Ingo Molnar
 * Released under the General Public License (GPL).
 */

#if defined(CONFIG_SMP)
# include <asm/spinlock_types.h>
#else
# include <linux/spinlock_types_up.h>
#endif

#include <linux/lockdep.h>

typedef struct {
	raw_spinlock_t raw_lock;
#if defined(CONFIG_PREEMPT) && defined(CONFIG_SMP)
	unsigned int break_lock;
#endif
#ifdef CONFIG_DEBUG_SPINLOCK
	unsigned int magic, owner_cpu;
	void *owner;
#endif
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif
} spinlock_t;

#define SPINLOCK_MAGIC		0xdead4ead

typedef struct {
		/**
		 * 这个锁标志与自旋锁不一样，自旋锁的lock标志只能取0和1两种值。
		 * 读写自旋锁的lock分两部分：
		 *	   0-23位：表示并发读的数量。数据以补码的形式存放。
		 *	   24位：未锁标志。如果没有读或写时设置该，否则清0
		 * 注意：如果自旋锁为空（设置了未锁标志并且无读者），则lock字段为0x01000000
		 *	   如果写者获得了锁，则lock为0x00000000（未锁标志清0，表示已经锁，但是无读者）
		 *	   如果一个或者多个进程获得了读锁，那么lock的值为0x00ffffff,0x00fffffe等（未锁标志清0，后面跟读者数量的补码）
         */

	raw_rwlock_t raw_lock;
#if defined(CONFIG_PREEMPT) && defined(CONFIG_SMP)
	/**
	 * 表示进程正在忙等待自旋锁。
	 * 只有内核支持SMP和内核抢占时才使用本标志。
	 */
	unsigned int break_lock;
#endif
#ifdef CONFIG_DEBUG_SPINLOCK
	unsigned int magic, owner_cpu;
	void *owner;
#endif
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif
} rwlock_t;

#define RWLOCK_MAGIC		0xdeaf1eed

#define SPINLOCK_OWNER_INIT	((void *)-1L)

#ifdef CONFIG_DEBUG_LOCK_ALLOC
# define SPIN_DEP_MAP_INIT(lockname)	.dep_map = { .name = #lockname }
#else
# define SPIN_DEP_MAP_INIT(lockname)
#endif

#ifdef CONFIG_DEBUG_LOCK_ALLOC
# define RW_DEP_MAP_INIT(lockname)	.dep_map = { .name = #lockname }
#else
# define RW_DEP_MAP_INIT(lockname)
#endif

#ifdef CONFIG_DEBUG_SPINLOCK
# define __SPIN_LOCK_UNLOCKED(lockname)					\
	(spinlock_t)	{	.raw_lock = __RAW_SPIN_LOCK_UNLOCKED,	\
				.magic = SPINLOCK_MAGIC,		\
				.owner = SPINLOCK_OWNER_INIT,		\
				.owner_cpu = -1,			\
				SPIN_DEP_MAP_INIT(lockname) }
#define __RW_LOCK_UNLOCKED(lockname)					\
	(rwlock_t)	{	.raw_lock = __RAW_RW_LOCK_UNLOCKED,	\
				.magic = RWLOCK_MAGIC,			\
				.owner = SPINLOCK_OWNER_INIT,		\
				.owner_cpu = -1,			\
				RW_DEP_MAP_INIT(lockname) }
#else
# define __SPIN_LOCK_UNLOCKED(lockname) \
	(spinlock_t)	{	.raw_lock = __RAW_SPIN_LOCK_UNLOCKED,	\
				SPIN_DEP_MAP_INIT(lockname) }
#define __RW_LOCK_UNLOCKED(lockname) \
	(rwlock_t)	{	.raw_lock = __RAW_RW_LOCK_UNLOCKED,	\
				RW_DEP_MAP_INIT(lockname) }
#endif

/*
 * SPIN_LOCK_UNLOCKED and RW_LOCK_UNLOCKED defeat lockdep state tracking and
 * are hence deprecated.
 * Please use DEFINE_SPINLOCK()/DEFINE_RWLOCK() or
 * __SPIN_LOCK_UNLOCKED()/__RW_LOCK_UNLOCKED() as appropriate.
 */
#define SPIN_LOCK_UNLOCKED	__SPIN_LOCK_UNLOCKED(old_style_spin_init)
#define RW_LOCK_UNLOCKED	__RW_LOCK_UNLOCKED(old_style_rw_init)

#define DEFINE_SPINLOCK(x)	spinlock_t x = __SPIN_LOCK_UNLOCKED(x)
#define DEFINE_RWLOCK(x)	rwlock_t x = __RW_LOCK_UNLOCKED(x)

#endif /* __LINUX_SPINLOCK_TYPES_H */
