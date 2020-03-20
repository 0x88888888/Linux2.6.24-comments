#ifndef _LINUX_BINFMTS_H
#define _LINUX_BINFMTS_H

#include <linux/capability.h>

struct pt_regs;

/*
 * These are the maximum length and maximum number of strings passed to the
 * execve() system call.  MAX_ARG_STRLEN is essentially random but serves to
 * prevent the kernel from being unduly impacted by misaddressed pointers.
 * MAX_ARG_STRINGS is chosen to fit in a signed 32-bit integer.
 */
#define MAX_ARG_STRLEN (PAGE_SIZE * 32)
#define MAX_ARG_STRINGS 0x7FFFFFFF

/* sizeof(linux_binprm->buf) */
#define BINPRM_BUF_SIZE 128

#ifdef __KERNEL__

#define CORENAME_MAX_SIZE 128

/*
 * This structure is used to hold the arguments that are used when loading binaries.
 * 
 * 在装载可执行文件之前，需要准备好相关信息，传递给装载函数，
 * linux_binprm就是用来装载这些信息的
 */
struct linux_binprm{
    /* 要执行的文件头部 */
	char buf[BINPRM_BUF_SIZE];
#ifdef CONFIG_MMU
	struct vm_area_struct *vma;
#else
# define MAX_ARG_PAGES	32
	struct page *page[MAX_ARG_PAGES];
#endif
	struct mm_struct *mm;
	unsigned long p; /* current top of mem */
	int sh_bang;
	struct file * file;
	int e_uid, e_gid;
	kernel_cap_t cap_inheritable, cap_permitted;
	bool cap_effective;
	void *security;
	int argc, envc;
	char * filename;	/* 将被执行的文件名称，Name of binary as seen by procps */
	char * interp;		/* 解释器文件名称，Name of the binary really executed. Most
				   of the time same as filename, but could be
				   different for binfmt_{misc,script} */
	unsigned interp_flags;
	unsigned interp_data;
	unsigned long loader, exec;
	unsigned long argv_len;
};

#define BINPRM_FLAGS_ENFORCE_NONDUMP_BIT 0
#define BINPRM_FLAGS_ENFORCE_NONDUMP (1 << BINPRM_FLAGS_ENFORCE_NONDUMP_BIT)

/* fd of the binary should be passed to the interpreter */
#define BINPRM_FLAGS_EXECFD_BIT 1
#define BINPRM_FLAGS_EXECFD (1 << BINPRM_FLAGS_EXECFD_BIT)


/*
 * This structure defines the functions that are used to load the binary formats that
 * linux accepts.
 * 有各种各样的二进制可执行格式，用对应linux_binfmt不同的实例来加载
 */
struct linux_binfmt {
    /* 链接到全局变量formats链表 */
	struct list_head lh;
	/* 装载器可以是一个内核模块动态加载，module为模块指针 */
	struct module *module;
	/* 加载函数 */
	int (*load_binary)(struct linux_binprm *, struct  pt_regs * regs);
	/* 库加载函数 */
	int (*load_shlib)(struct file *);
	/*
	 * dump函数，当一个程序异常退出时，调用该函数生成一个core文件，
	 * 它把程序的内存进行dump(复制)到磁盘上，之后可以利用gdb等调试器等等
	 * 对这个文件进行分析.
	 */
	int (*core_dump)(long signr, struct pt_regs *regs, struct file *file, unsigned long limit);
	unsigned long min_coredump;	/* minimal dump size */
	int hasvdso;
};

extern int register_binfmt(struct linux_binfmt *);
extern void unregister_binfmt(struct linux_binfmt *);

extern int prepare_binprm(struct linux_binprm *);
extern int __must_check remove_arg_zero(struct linux_binprm *);
extern int search_binary_handler(struct linux_binprm *,struct pt_regs *);
extern int flush_old_exec(struct linux_binprm * bprm);

extern int suid_dumpable;
#define SUID_DUMP_DISABLE	0	/* No setuid dumping */
#define SUID_DUMP_USER		1	/* Dump as user of process */
#define SUID_DUMP_ROOT		2	/* Dump as root */

/* Stack area protections */
#define EXSTACK_DEFAULT   0	/* Whatever the arch defaults to */
#define EXSTACK_DISABLE_X 1	/* Disable executable stacks */
#define EXSTACK_ENABLE_X  2	/* Enable executable stacks */

extern int setup_arg_pages(struct linux_binprm * bprm,
			   unsigned long stack_top,
			   int executable_stack);
extern int bprm_mm_init(struct linux_binprm *bprm);
extern int copy_strings_kernel(int argc,char ** argv,struct linux_binprm *bprm);
extern void compute_creds(struct linux_binprm *binprm);
extern int do_coredump(long signr, int exit_code, struct pt_regs * regs);
extern int set_binfmt(struct linux_binfmt *new);

#endif /* __KERNEL__ */
#endif /* _LINUX_BINFMTS_H */
