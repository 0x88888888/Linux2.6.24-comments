#ifndef _LINUX_KPROBES_H
#define _LINUX_KPROBES_H
/*
 *  Kernel Probes (KProbes)
 *  include/linux/kprobes.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2002, 2004
 *
 * 2002-Oct	Created by Vamsi Krishna S <vamsi_krishna@in.ibm.com> Kernel
 *		Probes initial implementation ( includes suggestions from
 *		Rusty Russell).
 * 2004-July	Suparna Bhattacharya <suparna@in.ibm.com> added jumper probes
 *		interface to access function arguments.
 * 2005-May	Hien Nguyen <hien@us.ibm.com> and Jim Keniston
 *		<jkenisto@us.ibm.com>  and Prasanna S Panchamukhi
 *		<prasanna@in.ibm.com> added function-return probes.
 */
#include <linux/list.h>
#include <linux/notifier.h>
#include <linux/smp.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>

#ifdef CONFIG_KPROBES
#include <asm/kprobes.h>

/* kprobe_status settings */
#define KPROBE_HIT_ACTIVE	0x00000001
#define KPROBE_HIT_SS		0x00000002
#define KPROBE_REENTER		0x00000004
#define KPROBE_HIT_SSDONE	0x00000008

/* Attach to insert probes on any functions which should be ignored*/
#define __kprobes	__attribute__((__section__(".kprobes.text")))

struct kprobe;
struct pt_regs;
struct kretprobe;
struct kretprobe_instance;
typedef int (*kprobe_pre_handler_t) (struct kprobe *, struct pt_regs *);
typedef int (*kprobe_break_handler_t) (struct kprobe *, struct pt_regs *);
typedef void (*kprobe_post_handler_t) (struct kprobe *, struct pt_regs *,
				       unsigned long flags);
typedef int (*kprobe_fault_handler_t) (struct kprobe *, struct pt_regs *,
				       int trapnr);
typedef int (*kretprobe_handler_t) (struct kretprobe_instance *,
				    struct pt_regs *);

/*
 涉及的API函数接口如下：
 int register_kprobe(struct kprobe *kp) 	 //向内核注册kprobe探测点
 void unregister_kprobe(struct kprobe *kp)	 //卸载kprobe探测点
 int register_kprobes(struct kprobe **kps, int num) 	//注册探测函数向量，包含多个探测点
 void unregister_kprobes(struct kprobe **kps, int num)	//卸载探测函数向量，包含多个探测点
 int disable_kprobe(struct kprobe *kp)		 //临时暂停指定探测点的探测
 int enable_kprobe(struct kprobe *kp)		 //恢复指定探测点的探测
 */
struct kprobe {
	/*
	 * 被用于kprobe全局hash，索引值为被探测点的地址
	 */
	struct hlist_node hlist;

	/* list of kprobes for multi-handler support 
	 * 用于链接同一被探测点的不同探测kprobe；
	 */
	struct list_head list;

	/* Indicates that the corresponding module has been ref counted */
	unsigned int mod_refcounted;

	/*count the number of times this probe was temporarily disarmed */
	unsigned long nmissed;

	/* location of the probe point
	 * 被探测点的地址
	 */
	kprobe_opcode_t *addr;

	/* Allow user to indicate symbol name of the probe point
	 * 被探测函数的名字
	 */
	const char *symbol_name;

	/* Offset into the symbol 
	 * 被探测点在函数内部的偏移，用于探测函数内部的指令，如果该值为0表示函数的入口
	 */
	unsigned int offset;

	/* Called before addr is executed.
	 * 在被探测点指令执行之前调用的回调函数
	 */
	kprobe_pre_handler_t pre_handler;

	/* Called after addr is executed, unless... 
	 * 在被探测指令执行之后调用的回调函数
	 */
	kprobe_post_handler_t post_handler;

	/* ... called if executing addr causes a fault (eg. page fault).
	 * Return 1 if it handled fault, otherwise kernel will see it.
	 * 在执行pre_handler、post_handler或单步执行被探测指令时出现内存异常则会调用该回调函数
	  */
	kprobe_fault_handler_t fault_handler;

	/* ... called if breakpoint trap occurs in probe handler.
	 * Return 1 if it handled break, otherwise kernel will see it.
	 * 在执行某一kprobe过程中触发了断点指令后会调用该函数，用于实现jprobe
	  */
	kprobe_break_handler_t break_handler;

	/* Saved opcode (which has been replaced with breakpoint) 
	 * 保存的被探测点原始指令
	 */
	kprobe_opcode_t opcode;

	/* copy of the original instruction
	 * 被复制的被探测点的原始指令，用于单步执行，架构强相关
	 */
	struct arch_specific_insn ainsn;
};

/*
 * Special probe type that uses setjmp-longjmp type tricks to resume
 * execution at a specified entry with a matching prototype corresponding
 * to the probed function - a trick to enable arguments to become
 * accessible seamlessly by probe handling logic.
 * Note:
 * Because of the way compilers allocate stack space for local variables
 * etc upfront, regardless of sub-scopes within a function, this mirroring
 * principle currently works only for probes placed on function entry points.
 */
struct jprobe {
	struct kprobe kp;
	void *entry;	/* probe handling code to jump to */
};

/* For backward compatibility with old code using JPROBE_ENTRY() */
#define JPROBE_ENTRY(handler)	(handler)

DECLARE_PER_CPU(struct kprobe *, current_kprobe);
DECLARE_PER_CPU(struct kprobe_ctlblk, kprobe_ctlblk);

#ifdef ARCH_SUPPORTS_KRETPROBES
extern void arch_prepare_kretprobe(struct kretprobe_instance *ri,
				   struct pt_regs *regs);
extern int arch_trampoline_kprobe(struct kprobe *p);
#else /* ARCH_SUPPORTS_KRETPROBES */
static inline void arch_prepare_kretprobe(struct kretprobe *rp,
					struct pt_regs *regs)
{
}
static inline int arch_trampoline_kprobe(struct kprobe *p)
{
	return 0;
}
#endif /* ARCH_SUPPORTS_KRETPROBES */
/*
 * Function-return probe -
 * Note:
 * User needs to provide a handler function, and initialize maxactive.
 * maxactive - The maximum number of instances of the probed function that
 * can be active concurrently.
 * nmissed - tracks the number of times the probed function's return was
 * ignored, due to maxactive being too low.
 *
 */
struct kretprobe {
	struct kprobe kp;
	kretprobe_handler_t handler;
	int maxactive;
	int nmissed;
	struct hlist_head free_instances;
	struct hlist_head used_instances;
};

struct kretprobe_instance {
	struct hlist_node uflist; /* either on free list or used list */
	struct hlist_node hlist;
	struct kretprobe *rp;
	kprobe_opcode_t *ret_addr;
	struct task_struct *task;
};

struct kretprobe_blackpoint {
	const char *name;
	void *addr;
};
extern struct kretprobe_blackpoint kretprobe_blacklist[];

static inline void kretprobe_assert(struct kretprobe_instance *ri,
	unsigned long orig_ret_address, unsigned long trampoline_address)
{
	if (!orig_ret_address || (orig_ret_address == trampoline_address)) {
		printk("kretprobe BUG!: Processing kretprobe %p @ %p\n",
				ri->rp, ri->rp->kp.addr);
		BUG();
	}
}

extern spinlock_t kretprobe_lock;
extern struct mutex kprobe_mutex;
extern int arch_prepare_kprobe(struct kprobe *p);
extern void arch_arm_kprobe(struct kprobe *p);
extern void arch_disarm_kprobe(struct kprobe *p);
extern int arch_init_kprobes(void);
extern void show_registers(struct pt_regs *regs);
extern kprobe_opcode_t *get_insn_slot(void);
extern void free_insn_slot(kprobe_opcode_t *slot, int dirty);
extern void kprobes_inc_nmissed_count(struct kprobe *p);

/* Get the kprobe at this addr (if any) - called with preemption disabled */
struct kprobe *get_kprobe(void *addr);
struct hlist_head * kretprobe_inst_table_head(struct task_struct *tsk);

/* kprobe_running() will just return the current_kprobe on this CPU */
static inline struct kprobe *kprobe_running(void)
{
	return (__get_cpu_var(current_kprobe));
}

static inline void reset_current_kprobe(void)
{
	__get_cpu_var(current_kprobe) = NULL;
}

static inline struct kprobe_ctlblk *get_kprobe_ctlblk(void)
{
	return (&__get_cpu_var(kprobe_ctlblk));
}

int register_kprobe(struct kprobe *p);
void unregister_kprobe(struct kprobe *p);
int setjmp_pre_handler(struct kprobe *, struct pt_regs *);
int longjmp_break_handler(struct kprobe *, struct pt_regs *);
int register_jprobe(struct jprobe *p);
void unregister_jprobe(struct jprobe *p);
void jprobe_return(void);
unsigned long arch_deref_entry_point(void *);

int register_kretprobe(struct kretprobe *rp);
void unregister_kretprobe(struct kretprobe *rp);

void kprobe_flush_task(struct task_struct *tk);
void recycle_rp_inst(struct kretprobe_instance *ri, struct hlist_head *head);
#else /* CONFIG_KPROBES */

#define __kprobes	/**/
struct jprobe;
struct kretprobe;

static inline struct kprobe *kprobe_running(void)
{
	return NULL;
}
static inline int register_kprobe(struct kprobe *p)
{
	return -ENOSYS;
}
static inline void unregister_kprobe(struct kprobe *p)
{
}
static inline int register_jprobe(struct jprobe *p)
{
	return -ENOSYS;
}
static inline void unregister_jprobe(struct jprobe *p)
{
}
static inline void jprobe_return(void)
{
}
static inline int register_kretprobe(struct kretprobe *rp)
{
	return -ENOSYS;
}
static inline void unregister_kretprobe(struct kretprobe *rp)
{
}
static inline void kprobe_flush_task(struct task_struct *tk)
{
}
#endif				/* CONFIG_KPROBES */
#endif				/* _LINUX_KPROBES_H */
