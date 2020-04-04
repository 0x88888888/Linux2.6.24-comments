/*
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation, version 2 of the
 *  License.
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/nsproxy.h>
#include <linux/user_namespace.h>

struct user_namespace init_user_ns = {
	.kref = {
		.refcount	= ATOMIC_INIT(2),
	},
	.root_user = &root_user,
};

EXPORT_SYMBOL_GPL(init_user_ns);

#ifdef CONFIG_USER_NS

/*
 * 复制用户资源限制命名空间 
 * Clone a new ns copying an original user ns, setting refcount to 1
 * @old_ns: namespace to clone
 * Return NULL on error (failure to kmalloc), new ns otherwise
 *
 *
 * copy_process()
 *  copy_namespaces()
 *   create_new_namespaces()
 *    copy_user_ns()
 *     clone_user_ns()
 */
static struct user_namespace *clone_user_ns(struct user_namespace *old_ns)
{
	struct user_namespace *ns;
	struct user_struct *new_user;
	int n;

	ns = kmalloc(sizeof(struct user_namespace), GFP_KERNEL);
	if (!ns)
		return ERR_PTR(-ENOMEM);

	kref_init(&ns->kref);

	for (n = 0; n < UIDHASH_SZ; ++n)
		INIT_HLIST_HEAD(ns->uidhash_table + n);

	/* Insert new root user.新用户命名空间中的root用户  */
	ns->root_user = alloc_uid(ns, 0);
	if (!ns->root_user) {
		kfree(ns);
		return ERR_PTR(-ENOMEM);
	}

	/* Reset current->user with a new one,
       将current->user替换为一个新的user_struct
     *
     *
	 */
	new_user = alloc_uid(ns, current->uid);
	if (!new_user) {
		free_uid(ns->root_user);
		kfree(ns);
		return ERR_PTR(-ENOMEM);
	}

	//切换当前进程的user对象
	switch_uid(new_user);
	return ns;
}

/* 复制用户资源限制命名空间 
 *
 * copy_process()
 *  copy_namespaces()
 *   create_new_namespaces()
 *    copy_user_ns()
 */
struct user_namespace * copy_user_ns(int flags, struct user_namespace *old_ns)
{
	struct user_namespace *new_ns;

	BUG_ON(!old_ns);
	get_user_ns(old_ns);

	if (!(flags & CLONE_NEWUSER))
		return old_ns;

	/* 复制用户资源限制命名空间 */
	new_ns = clone_user_ns(old_ns);

	put_user_ns(old_ns);
	return new_ns;
}

void free_user_ns(struct kref *kref)
{
	struct user_namespace *ns;

	ns = container_of(kref, struct user_namespace, kref);
	release_uids(ns);
	kfree(ns);
}

#endif /* CONFIG_USER_NS */
