/*
 * kobject.h - generic kernel object infrastructure.
 *
 * Copyright (c) 2002-2003 Patrick Mochel
 * Copyright (c) 2002-2003 Open Source Development Labs
 * Copyright (c) 2006-2007 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (c) 2006-2007 Novell Inc.
 *
 * This file is released under the GPLv2.
 *
 * 
 * Please read Documentation/kobject.txt before using the kobject
 * interface, ESPECIALLY the parts about reference counts and object
 * destructors. 
 */

#ifndef _KOBJECT_H_
#define _KOBJECT_H_

#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/list.h>
#include <linux/sysfs.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/kref.h>
#include <linux/kernel.h>
#include <linux/wait.h>
#include <asm/atomic.h>

#define KOBJ_NAME_LEN			20
#define UEVENT_HELPER_PATH_LEN		256
#define UEVENT_NUM_ENVP			32	/* number of env pointers */
#define UEVENT_BUFFER_SIZE		2048	/* buffer for the variables */

/* path to the userspace helper executed on an event */
extern char uevent_helper[];

/* counter to tag the uevent, read only except for the kobject core */
extern u64 uevent_seqnum;

/*
 * The actions here must match the index to the string array
 * in lib/kobject_uevent.c
 *
 * Do not add new actions here without checking with the driver-core
 * maintainers. Action strings are not meant to express subsystem
 * or device specific properties. In most cases you want to send a
 * kobject_uevent_env(kobj, KOBJ_CHANGE, env) with additional event
 * specific variables added to the event environment.
 */
enum kobject_action {
	/* Kobject（或上层数据结构）的添加/移除事件。 */
	KOBJ_ADD,  
	KOBJ_REMOVE, 
	
	KOBJ_CHANGE, /* Kobject（或上层数据结构）的状态或者内容发生改变。 */
	KOBJ_MOVE, /* Kobject（或上层数据结构）更改名称或者更改Parent（意味着在sysfs中更改了目录结构）。 */

	/* Kobject（或上层数据结构）的上线/下线事件，其实是是否使能。 */
	KOBJ_ONLINE,
	KOBJ_OFFLINE,
	
	KOBJ_MAX
};

/* 用于管理内核对象，方便多处引用，在没有引用的时候删除对象
 * 构建内核对象的层次结构体系
 *
 * 每个Kobject都会在"/sys/“文件系统中以目录的形式出现
 * 每个attribute都在/sys/中以文件的形式出现
 *
 * kobject可以有parent对象，也可以被包含到kset中
 *
 * 1,如果存在parent对象，就在其parent对象的目录下面建立一个对应的项
 * 2,如果parent不存在,那就将其放在kset所属kobject对应的目录中
 * 3,如果1,2都不是，那么就在系统层次的顶层目录下建一项
 */
struct kobject {
	/* 对象的文本名称，用于导出到sysfs中 */
	const char		* k_name;
	/* 只有一个atomic_t refcount成员 */
	struct kref		kref;
	/* 用于将Kobject加入到Kset中的list_head */
	struct list_head	entry;
    /* parent 用于 建立kobject之间的层次关系 */
	struct kobject		* parent;
	/* 该kobject属于的Kset。可以为NULL。如果存在，且没有指定parent，则会把Kset作为parent（别忘了Kset是一个特殊的Kobject） */
	struct kset		* kset;
	/* 用于释放该kobject时，调用析构函数 */
	struct kobj_type	* ktype;
	struct sysfs_dirent	* sd; /* 在/sys中的每一个节点都用sysfs_dirent表示 */
};

extern int kobject_set_name(struct kobject *, const char *, ...)
	__attribute__((format(printf,2,3)));

static inline const char * kobject_name(const struct kobject * kobj)
{
	return kobj->k_name;
}

extern void kobject_init(struct kobject *);
extern void kobject_cleanup(struct kobject *);

extern int __must_check kobject_add(struct kobject *);
extern void kobject_del(struct kobject *);

extern int __must_check kobject_rename(struct kobject *, const char *new_name);
extern int __must_check kobject_move(struct kobject *, struct kobject *);

extern int __must_check kobject_register(struct kobject *);
extern void kobject_unregister(struct kobject *);

extern struct kobject * kobject_get(struct kobject *);
extern void kobject_put(struct kobject *);

extern struct kobject *kobject_kset_add_dir(struct kset *kset,
					    struct kobject *, const char *);
extern struct kobject *kobject_add_dir(struct kobject *, const char *);

extern char * kobject_get_path(struct kobject *, gfp_t);

struct kobj_type {
	void (*release)(struct kobject *);
    /*该种类型的Kobject的sysfs文件系统接口*/
	struct sysfs_ops	* sysfs_ops;
	/*
	 * 该种类型的Kobject的atrribute列表（所谓attribute，就是sysfs文件系统中的一个文件）。
	 * 将会在Kobject添加到内核时，一并注册到sysfs中。
	 */
	struct attribute	** default_attrs;
};

/*
 * 在利用Kmod向用户空间上报event事件时，会直接执行用户空间的可执行文件。
 * 而在Linux系统，可执行文件的执行，依赖于环境变量，
 * 因此kobj_uevent_env用于组织此次事件上报时的环境变量。
 */
struct kobj_uevent_env {
    /* 指针数组，用于保存每个环境变量的地址，最多可支持的环境变量数量为UEVENT_NUM_ENVP。 */
	char *envp[UEVENT_NUM_ENVP]; 
	/* 用于访问环境变量指针数组的index。 */
	int envp_idx;
	/* 保存环境变量的buffer，最大为UEVENT_BUFFER_SIZE。 */
	char buf[UEVENT_BUFFER_SIZE];
	/* 访问buf的变量。 */
	int buflen;
};

/* kset_uevent_ops是为kset量身订做的一个数据结构，里面包含filter和uevent两个回调函数 */
struct kset_uevent_ops {
    /* 当任何Kobject需要上报uevent时，它所属的kset可以通过该接口过滤，阻止不希望上报的event，从而达到从整体上管理的目的 */
	int (*filter)(struct kset *kset, struct kobject *kobj);
	/* 该接口可以返回kset的名称。如果一个kset没有合法的名称，则其下的所有Kobject将不允许上报uvent */
	const char *(*name)(struct kset *kset, struct kobject *kobj);
	/* 当任何Kobject需要上报uevent时，它所属的kset可以通过该接口统一为这些event添加环境变量。
	 * 因为很多时候上报uevent时的环境变量都是相同的，
	 * 因此可以由kset统一处理，就不需要让每个Kobject独自添加了
	 */
	int (*uevent)(struct kset *kset, struct kobject *kobj,
		      struct kobj_uevent_env *env);
};

/**
 * struct kset - a set of kobjects of a specific type, belonging to a specific subsystem.
 *
 * A kset defines a group of kobjects.  They can be individually
 * different "types" but overall these kobjects all want to be grouped
 * together and operated on in the same manner.  ksets are used to
 * define the attribute callbacks and other common events that happen to
 * a kobject.
 *
 * @ktype: the struct kobj_type for this specific kset
 * @list: the list of all kobjects for this kset
 * @list_lock: a lock for iterating over the kobjects
 * @kobj: the embedded kobject for this kset (recursion, isn't it fun...)
 * @uevent_ops: the set of uevent operations for this kset.  These are
 * called whenever a kobject has something happen to it so that the kset
 * can add new environment variables, or filter out the uevents if so
 * desired.
 */
struct kset {
    /*
     * kset中的ktype对象用来表示kset.list中各个对象的公用kobj_type结构
     */
	struct kobj_type	*ktype;
	/* 用于保存该kset下所有的kobject的链表。 */
	struct list_head	list;
	spinlock_t		list_lock;
	/*
	 * kset中的kobj与ksetlist中包含的各个对象无关，
	 * 这个kobj只是用来管理kset对象本身的。
	 */
	struct kobject		kobj;
	/* 用于将集合的状态信息传递给用户层,该机制由驱动程序模型的核心使用，
	 * 例如格式化一个信息，通知添加了新设备。
	 *
	 * 该kset的uevent操作函数集。当任何Kobject需要上报uevent时，
	 * 都要调用它所从属的kset的uevent_ops，添加环境变量，
	 * 或者过滤event（kset可以决定哪些event可以上报）。
	 * 因此，如果一个kobject不属于任何kset时，是不允许发送uevent的
	 */
	struct kset_uevent_ops	*uevent_ops;
};


extern void kset_init(struct kset * k);
extern int __must_check kset_add(struct kset * k);
extern int __must_check kset_register(struct kset * k);
extern void kset_unregister(struct kset * k);

static inline struct kset * to_kset(struct kobject * kobj)
{
	return kobj ? container_of(kobj,struct kset,kobj) : NULL;
}

static inline struct kset * kset_get(struct kset * k)
{
	return k ? to_kset(kobject_get(&k->kobj)) : NULL;
}

static inline void kset_put(struct kset * k)
{
	kobject_put(&k->kobj);
}

static inline struct kobj_type * get_ktype(struct kobject * k)
{
	if (k->kset && k->kset->ktype)
		return k->kset->ktype;
	else 
		return k->ktype;
}

extern struct kobject * kset_find_obj(struct kset *, const char *);


/*
 * Use this when initializing an embedded kset with no other 
 * fields to initialize.
 */
#define set_kset_name(str)	.kset = { .kobj = { .k_name = str } }


#define decl_subsys(_name,_type,_uevent_ops) \
struct kset _name##_subsys = { \
	.kobj = { .k_name = __stringify(_name) }, \
	.ktype = _type, \
	.uevent_ops =_uevent_ops, \
}
#define decl_subsys_name(_varname,_name,_type,_uevent_ops) \
struct kset _varname##_subsys = { \
	.kobj = { .k_name = __stringify(_name) }, \
	.ktype = _type, \
	.uevent_ops =_uevent_ops, \
}

/* The global /sys/kernel/ subsystem for people to chain off of */
extern struct kset kernel_subsys;
/* The global /sys/hypervisor/ subsystem  */
extern struct kset hypervisor_subsys;

/*
 * Helpers for setting the kset of registered objects.
 * Often, a registered object belongs to a kset embedded in a 
 * subsystem. These do no magic, just make the resulting code
 * easier to follow. 
 */

/**
 *	kobj_set_kset_s(obj,subsys) - set kset for embedded kobject.
 *	@obj:		ptr to some object type.
 *	@subsys:	a subsystem object (not a ptr).
 *
 *	Can be used for any object type with an embedded ->kobj.
 */

#define kobj_set_kset_s(obj,subsys) \
	(obj)->kobj.kset = &(subsys)

extern int __must_check subsystem_register(struct kset *);
extern void subsystem_unregister(struct kset *);

struct subsys_attribute {
	struct attribute attr;
	ssize_t (*show)(struct kset *, char *);
	ssize_t (*store)(struct kset *, const char *, size_t);
};

extern int __must_check subsys_create_file(struct kset *,
					struct subsys_attribute *);

#if defined(CONFIG_HOTPLUG)
int kobject_uevent(struct kobject *kobj, enum kobject_action action);
int kobject_uevent_env(struct kobject *kobj, enum kobject_action action,
			char *envp[]);

int add_uevent_var(struct kobj_uevent_env *env, const char *format, ...)
	__attribute__((format (printf, 2, 3)));

int kobject_action_type(const char *buf, size_t count,
			enum kobject_action *type);
#else
static inline int kobject_uevent(struct kobject *kobj, enum kobject_action action)
{ return 0; }
static inline int kobject_uevent_env(struct kobject *kobj,
				      enum kobject_action action,
				      char *envp[])
{ return 0; }

static inline int add_uevent_var(struct kobj_uevent_env *env, const char *format, ...)
{ return 0; }

static inline int kobject_action_type(const char *buf, size_t count,
			enum kobject_action *type)
{ return -EINVAL; }
#endif

#endif /* __KERNEL__ */
#endif /* _KOBJECT_H_ */
