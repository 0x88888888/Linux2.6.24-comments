#ifndef __ASM_SPINLOCK_TYPES_H
#define __ASM_SPINLOCK_TYPES_H

#ifndef __LINUX_SPINLOCK_TYPES_H
# error "please don't include this file directly"
#endif

/*
 * 
 */
typedef struct {
    /*
     * 1:表示未加锁的状态
     * 其余任何负数和0都表示加锁状态
     */
	unsigned int slock;
} raw_spinlock_t;

#define __RAW_SPIN_LOCK_UNLOCKED	{ 1 }

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
	unsigned int lock;
} raw_rwlock_t;

#define __RAW_RW_LOCK_UNLOCKED		{ RW_LOCK_BIAS }

#endif
