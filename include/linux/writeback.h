/*
 * include/linux/writeback.h
 */
#ifndef WRITEBACK_H
#define WRITEBACK_H

#include <linux/sched.h>
#include <linux/fs.h>

struct backing_dev_info;

extern spinlock_t inode_lock;
extern struct list_head inode_in_use;
extern struct list_head inode_unused;

/*
 * Yes, writeback.h requires sched.h
 * No, sched.h is not included from here.
 */
static inline int task_is_pdflush(struct task_struct *task)
{
	return task->flags & PF_FLUSHER;
}

#define current_is_pdflush()	task_is_pdflush(current)

/*
 * fs/fs-writeback.c
 */
enum writeback_sync_modes {
	WB_SYNC_NONE,	/* Don't wait on anything */
	WB_SYNC_ALL,	/* Wait on every mapping */
	WB_SYNC_HOLD,	/* Hold the inode on sb_dirty for sys_sync() */
};

/*
 * A control structure which tells the writeback code what to do.  These are
 * always on the stack, and hence need no locking.  They are always initialised
 * in a manner such that unspecified fields are set to zero.
 *
 * 将数据写回磁盘时的控制参数.
 */
struct writeback_control {
	struct backing_dev_info *bdi;	/* If !NULL, only write back this
					   queue */
	/*
	 * 对WB_SYNC_ALL，表示等待所有回写数据已经写到磁盘上了
	 * 
	 */				   	
	enum writeback_sync_modes sync_mode;
	unsigned long *older_than_this;	/* If !NULL, only write back inodes
					   older than this */
	/* 可以回写到磁盘的最大page数量 */
	long nr_to_write;		/* Write this many pages, and decrement
					   this for each page written */
	/* 因为各种原因跳过回写的，用pages_skipped统计 */				   	
	long pages_skipped;		/* Pages which were not written */

	/*
	 * For a_ops->writepages(): is start or end are non-zero then this is
	 * a hint that the filesystem need only write out the pages inside that
	 *
	 *
	 * byterange.  The byte at `end' is included in the writeout request.
	 */
	loff_t range_start;
	loff_t range_end;

	/* 指定了回写队列在遇到拥塞时是否阻塞，如果要求被阻塞，则内核将一直等待，直到队列空闲位置,否则，内核将一直等待，直到队列空闲为止 */
	unsigned nonblocking:1;		/* Don't get stuck on request queues */
	/* 在数据回写期间是否发生了拥塞 */
	unsigned encountered_congestion:1; /* An output: a queue is full */
	/* 如果回写请求是周期性机制发出的，则for_kupdate设置为1,否则为0. */
	unsigned for_kupdate:1;		/* A kupdate writeback */
	unsigned for_reclaim:1;		/* Invoked from the page allocator */
	/* 如果回写是有do_writepages()发起的，则for_writepages设置为1 */
	unsigned for_writepages:1;	/* This is a writepages() call */
	/* 如果range_cyclic==0，则回写机制限于对range_start和range_end指定的范围进行操作
	 * 该限制是对回写操作的目标映射设置的。
	 * 如果range_cyclic==1,则内核可能多次遍历与映射相关的页
	 */
	unsigned range_cyclic:1;	/* range_start is cyclic */
};

/*
 * fs/fs-writeback.c
 */	
void writeback_inodes(struct writeback_control *wbc);
int inode_wait(void *);
void sync_inodes_sb(struct super_block *, int wait);
void sync_inodes(int wait);

/* writeback.h requires fs.h; it, too, is not included from here. */
static inline void wait_on_inode(struct inode *inode)
{
	might_sleep();
	wait_on_bit(&inode->i_state, __I_LOCK, inode_wait,
							TASK_UNINTERRUPTIBLE);
}
static inline void inode_sync_wait(struct inode *inode)
{
	might_sleep();
	wait_on_bit(&inode->i_state, __I_SYNC, inode_wait,
							TASK_UNINTERRUPTIBLE);
}


/*
 * mm/page-writeback.c
 */
int wakeup_pdflush(long nr_pages);
void laptop_io_completion(void);
void laptop_sync_completion(void);
void throttle_vm_writeout(gfp_t gfp_mask);

/* These are exported to sysctl. */
extern int dirty_background_ratio;
extern int vm_dirty_ratio;
extern int dirty_writeback_interval;
extern int dirty_expire_interval;
extern int block_dump;
extern int laptop_mode;

extern int dirty_ratio_handler(struct ctl_table *table, int write,
		struct file *filp, void __user *buffer, size_t *lenp,
		loff_t *ppos);

struct ctl_table;
struct file;
int dirty_writeback_centisecs_handler(struct ctl_table *, int, struct file *,
				      void __user *, size_t *, loff_t *);

void page_writeback_init(void);
void balance_dirty_pages_ratelimited_nr(struct address_space *mapping,
					unsigned long nr_pages_dirtied);

/*
 * generic_perform_write()
 *  balance_dirty_pages_ratelimited()
 *
 * set_page_dirty_balance()
 *  balance_dirty_pages_ratelimited()
 * 
 * generic_perform_write_2copy()
 *  balance_dirty_pages_ratelimited()
 *
 */
static inline void
balance_dirty_pages_ratelimited(struct address_space *mapping)
{
	balance_dirty_pages_ratelimited_nr(mapping, 1);
}

typedef int (*writepage_t)(struct page *page, struct writeback_control *wbc,
				void *data);

int pdflush_operation(void (*fn)(unsigned long), unsigned long arg0);
int generic_writepages(struct address_space *mapping,
		       struct writeback_control *wbc);
int write_cache_pages(struct address_space *mapping,
		      struct writeback_control *wbc, writepage_t writepage,
		      void *data);
int do_writepages(struct address_space *mapping, struct writeback_control *wbc);
int sync_page_range(struct inode *inode, struct address_space *mapping,
			loff_t pos, loff_t count);
int sync_page_range_nolock(struct inode *inode, struct address_space *mapping,
			   loff_t pos, loff_t count);
void set_page_dirty_balance(struct page *page, int page_mkwrite);
void writeback_set_ratelimit(void);

/* pdflush.c */
extern int nr_pdflush_threads;	/* Global so it can be exported to sysctl
				   read-only. */


#endif		/* WRITEBACK_H */
