#ifndef _LINUX_NAMEI_H
#define _LINUX_NAMEI_H

#include <linux/dcache.h>
#include <linux/linkage.h>

struct vfsmount;

struct open_intent {
	int	flags;
	int	create_mode;
	struct file *file;
};

enum { MAX_NESTED_LINKS = 8 };

/*
 * 文件路径是由各级别的目录项组成的，因此路径的查找过程是对目录项的逐级查找。
 * nameidata结构是路径查找过程中的核心数据结构，在每一级目录项查找过程中，
 * 它向查找函数输入参数，并且保存本次查找的结果，因此它是不断变化的
 */
struct nameidata {
	/* 定位过程中，当前的目录对象 */
	struct dentry	*dentry;
	/* 定位过程中，当前目录所属的vfsmount对象 */
	struct vfsmount *mnt;

	// 该字段为qstr结构，表示当前dentry的名称
	struct qstr	last;
	unsigned int	flags;
	// 表示当前dentry的类型
	int		last_type;
	// 查找过程中，当前的符号链接嵌套级别，最大不能超过MAX_NESTED_LINKS；
	unsigned	depth;
	/*
     * 由于在定位过程中，会遇到符号链接，指针数组saved_names指向每一级别的符号链接
     * 最大为8，这是为了避免在定位符号链接过程中陷入死循环。
     * 注意，这是一个指针数组，每一项指向一个路径字符串路径。当定位一个普通路径时，
     * depth为0，每当进入一级符号链接时，depth会加1，最大为8.
     *
     * 该字符串数组表示符号链接每个嵌套级别的名称；
	 */
	char *saved_names[MAX_NESTED_LINKS + 1];

	/* Intent data */
	union {
		struct open_intent open;
	} intent;
};

// 该字段用于保存当前目录项。该字段是path结构，该结构将目录项和该目录项所关联的vfsmount结构进行封装。
struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

/*
 * Type of the last component on LOOKUP_PARENT
 */
enum {LAST_NORM, LAST_ROOT, LAST_DOT, LAST_DOTDOT, LAST_BIND};

/*
 * The bitmask for a lookup event:
 *  - follow links at the end
 *  - require a directory
 *  - ending slashes ok even for nonexistent files
 *  - internal "there are more path compnents" flag
 *  - locked when lookup done with dcache_lock held
 *  - dentry cache is untrusted; force a real lookup
 */
/*  如果最后一个分量是符号链接，则解释它 */ 
#define LOOKUP_FOLLOW		 1   
/*  最后一个分量必须是目录 */
#define LOOKUP_DIRECTORY	 2
/* 在路径名中还有文件名要检查 */
#define LOOKUP_CONTINUE		 4
/* 查找最后一个分量名所在的目录 */
#define LOOKUP_PARENT		16
/* 不考虑模拟根目录,在x86中没有用到这个 */
#define LOOKUP_NOALT		32
#define LOOKUP_REVAL		64
/*
 * Intent data
 */
/* 试图打开一个文件 */ 
#define LOOKUP_OPEN		(0x0100)
/* 试图创建一个文件 */
#define LOOKUP_CREATE		(0x0200)
/* 试图为一个检查用户的权限 */
#define LOOKUP_ACCESS		(0x0400)
#define LOOKUP_CHDIR		(0x0800)

extern int FASTCALL(__user_walk(const char __user *, unsigned, struct nameidata *));
extern int FASTCALL(__user_walk_fd(int dfd, const char __user *, unsigned, struct nameidata *));
#define user_path_walk(name,nd) \
	__user_walk_fd(AT_FDCWD, name, LOOKUP_FOLLOW, nd)
#define user_path_walk_link(name,nd) \
	__user_walk_fd(AT_FDCWD, name, 0, nd)
extern int FASTCALL(path_lookup(const char *, unsigned, struct nameidata *));
extern int vfs_path_lookup(struct dentry *, struct vfsmount *,
			   const char *, unsigned int, struct nameidata *);
extern void path_release(struct nameidata *);
extern void path_release_on_umount(struct nameidata *);

extern int __user_path_lookup_open(const char __user *, unsigned lookup_flags, struct nameidata *nd, int open_flags);
extern int path_lookup_open(int dfd, const char *name, unsigned lookup_flags, struct nameidata *, int open_flags);
extern struct file *lookup_instantiate_filp(struct nameidata *nd, struct dentry *dentry,
		int (*open)(struct inode *, struct file *));
extern struct file *nameidata_to_filp(struct nameidata *nd, int flags);
extern void release_open_intent(struct nameidata *);

extern struct dentry *lookup_one_len(const char *, struct dentry *, int);
extern struct dentry *lookup_one_noperm(const char *, struct dentry *);

extern int follow_down(struct vfsmount **, struct dentry **);
extern int follow_up(struct vfsmount **, struct dentry **);

extern struct dentry *lock_rename(struct dentry *, struct dentry *);
extern void unlock_rename(struct dentry *, struct dentry *);

static inline void nd_set_link(struct nameidata *nd, char *path)
{
	nd->saved_names[nd->depth] = path;
}

static inline char *nd_get_link(struct nameidata *nd)
{
	return nd->saved_names[nd->depth];
}

#endif /* _LINUX_NAMEI_H */
