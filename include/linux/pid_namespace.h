#ifndef _LINUX_PID_NS_H
#define _LINUX_PID_NS_H

#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/threads.h>
#include <linux/nsproxy.h>
#include <linux/kref.h>

struct pidmap {
       atomic_t nr_free;
       void *page;
};

#define PIDMAP_ENTRIES         ((PID_MAX_LIMIT + 8*PAGE_SIZE - 1)/PAGE_SIZE/8)

/*
 * 管理pid命名空间的两个数据结构 upid,pid
 */
struct pid_namespace {
	struct kref kref;
	/* 用于本pid_namespace分配唯一的pid 
	 * 跟踪用
	 */
	struct pidmap pidmap[PIDMAP_ENTRIES];
	int last_pid;
	
	struct task_struct *child_reaper; /* 局部命名空间中充当init进程(变体) */
	struct kmem_cache *pid_cachep;
	/* 表示当前命名空间在命名空间层次结构中的深度，0,1,2,3,以此递增,
	 * 低level值命名空间可以看见高level值中的id，
	 * 所以从给定的level值，可以推断进程会关联多少个id
	 *
	 * init_pid_ns->level == 0的.
	 */
	int level; 
	struct pid_namespace *parent; /* 上级命名空间 */
#ifdef CONFIG_PROC_FS
	struct vfsmount *proc_mnt;
#endif
};

extern struct pid_namespace init_pid_ns;

#ifdef CONFIG_PID_NS
static inline struct pid_namespace *get_pid_ns(struct pid_namespace *ns)
{
	if (ns != &init_pid_ns)
		kref_get(&ns->kref);
	return ns;
}

extern struct pid_namespace *copy_pid_ns(unsigned long flags, struct pid_namespace *ns);
extern void free_pid_ns(struct kref *kref);

static inline void put_pid_ns(struct pid_namespace *ns)
{
	if (ns != &init_pid_ns)
		kref_put(&ns->kref, free_pid_ns);
}

#else /* !CONFIG_PID_NS */
#include <linux/err.h>

static inline struct pid_namespace *get_pid_ns(struct pid_namespace *ns)
{
	return ns;
}

static inline struct pid_namespace *
copy_pid_ns(unsigned long flags, struct pid_namespace *ns)
{
	if (flags & CLONE_NEWPID)
		ns = ERR_PTR(-EINVAL);
	return ns;
}

static inline void put_pid_ns(struct pid_namespace *ns)
{
}

#endif /* CONFIG_PID_NS */

static inline struct pid_namespace *task_active_pid_ns(struct task_struct *tsk)
{
	return tsk->nsproxy->pid_ns;
}

static inline struct task_struct *task_child_reaper(struct task_struct *tsk)
{
	BUG_ON(tsk != current);
	return tsk->nsproxy->pid_ns->child_reaper;
}

#endif /* _LINUX_PID_NS_H */
