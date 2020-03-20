/*
 * kernel userspace event delivery
 *
 * Copyright (C) 2004 Red Hat, Inc.  All rights reserved.
 * Copyright (C) 2004 Novell, Inc.  All rights reserved.
 * Copyright (C) 2004 IBM, Inc. All rights reserved.
 *
 * Licensed under the GNU GPL v2.
 *
 * Authors:
 *	Robert Love		<rml@novell.com>
 *	Kay Sievers		<kay.sievers@vrfy.org>
 *	Arjan van de Ven	<arjanv@redhat.com>
 *	Greg Kroah-Hartman	<greg@kroah.com>
 */

#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/string.h>
#include <linux/kobject.h>
#include <net/sock.h>


u64 uevent_seqnum;
char uevent_helper[UEVENT_HELPER_PATH_LEN] = CONFIG_UEVENT_HELPER_PATH;
static DEFINE_SPINLOCK(sequence_lock);
#if defined(CONFIG_NET)
static struct sock *uevent_sock;
#endif

/* the strings here must match the enum in include/linux/kobject.h */
static const char *kobject_actions[] = {
	[KOBJ_ADD] =		"add",
	[KOBJ_REMOVE] =		"remove",
	[KOBJ_CHANGE] =		"change",
	[KOBJ_MOVE] =		"move",
	[KOBJ_ONLINE] =		"online",
	[KOBJ_OFFLINE] =	"offline",
};

/**
 * kobject_action_type - translate action string to numeric type
 *
 * 将事件的字符串名称，转化成kobject_action枚举类型
 * @buf: buffer containing the action string, newline is ignored
 * @len: length of buffer
 * @type: pointer to the location to store the action type
 *
 * Returns 0 if the action string was recognized.
 */
int kobject_action_type(const char *buf, size_t count,
			enum kobject_action *type)
{
	enum kobject_action action;
	int ret = -EINVAL;

	if (count && buf[count-1] == '\n')
		count--;

	if (!count)
		goto out;

	for (action = 0; action < ARRAY_SIZE(kobject_actions); action++) {
		if (strncmp(kobject_actions[action], buf, count) != 0)
			continue;
		if (kobject_actions[action][count] != '\0')
			continue;
		*type = action;
		ret = 0;
		break;
	}
out:
	return ret;
}

/**
 * kobject_uevent_env - send an uevent with environmental data
 *
 * 以envp为环境变量，上报一个指定action的uevent。环境变量的作用是为执行用户空间程序指定运行环境
 *
 * @action: action that is happening
 * @kobj: struct kobject that the action is happening to
 * @envp_ext: pointer to environmental data
 *
 * Returns 0 if kobject_uevent() is completed with success or the
 * corresponding error when it fails.
 */
int kobject_uevent_env(struct kobject *kobj, enum kobject_action action,
		       char *envp_ext[])
{
	struct kobj_uevent_env *env;
	const char *action_string = kobject_actions[action];
	const char *devpath = NULL;
	const char *subsystem;
	struct kobject *top_kobj;
	struct kset *kset;
	struct kset_uevent_ops *uevent_ops;
	u64 seq;
	int i = 0;
	int retval = 0;

	pr_debug("%s\n", __FUNCTION__);

	/* search the kset we belong to */
	/* 查找kobj本身或者其parent是否从属于某个kset */
	top_kobj = kobj;
	while (!top_kobj->kset && top_kobj->parent)
		top_kobj = top_kobj->parent;

    /* 如果一个kobject没有加入kset，是不允许上报uevent的 */
	if (!top_kobj->kset) {
		pr_debug("kobject attempted to send uevent without kset!\n");
		return -EINVAL;
	}

	kset = top_kobj->kset;
	uevent_ops = kset->uevent_ops;

	/* skip the event, if the filter returns zero. 
     * 如果所属的kset有uevent_ops->filter函数，则调用该函数，过滤此次上报
   	 */
	if (uevent_ops && uevent_ops->filter)
		/* 是否过滤掉本次上报 */
		if (!uevent_ops->filter(kset, kobj)) {
			pr_debug("kobject filter function caused the event to drop!\n");
			return 0;
		}

	/* originating subsystem 
	 * 判断所属的kset是否有合法的名称
     */
	if (uevent_ops && uevent_ops->name)
		subsystem = uevent_ops->name(kset, kobj);
	else
		subsystem = kobject_name(&kset->kobj);
	
	if (!subsystem) {
		pr_debug("unset subsystem caused the event to drop!\n");
		return 0;
	}

	/* environment buffer */
	env = kzalloc(sizeof(struct kobj_uevent_env), GFP_KERNEL);
	if (!env)
		return -ENOMEM;

	/* complete object path 
	 * 分配一个用于此次上报的、存储环境变量的buffer（结果保存在env指针中），并获得该Kobject在sysfs中路径信息（用户空间软件需要依据该路径信息在sysfs中访问它）
	 */
	devpath = kobject_get_path(kobj, GFP_KERNEL);
	if (!devpath) {
		retval = -ENOENT;
		goto exit;
	}

	/* default keys 
	 * 将Action、路径信息、subsystem等信息，添加到env指针中
	 */
	retval = add_uevent_var(env, "ACTION=%s", action_string);
	if (retval)
		goto exit;
	retval = add_uevent_var(env, "DEVPATH=%s", devpath);
	if (retval)
		goto exit;
	retval = add_uevent_var(env, "SUBSYSTEM=%s", subsystem);
	if (retval)
		goto exit;

	/* keys passed in from the caller 
	 * 如果传入的envp不空，则解析传入的环境变量中，同样调用add_uevent_var接口，添加到env指针中
	 */
	if (envp_ext) {
		for (i = 0; envp_ext[i]; i++) {
			retval = add_uevent_var(env, envp_ext[i]);
			if (retval)
				goto exit;
		}
	}

	/* let the kset specific function add its stuff 
	 * 如果所属的kset存在uevent_ops->uevent接口，调用该接口，添加kset统一的环境变量到env指针
	 */
	if (uevent_ops && uevent_ops->uevent) {
		retval = uevent_ops->uevent(kset, kobj, env);
		if (retval) {
			pr_debug ("%s - uevent() returned %d\n",
				  __FUNCTION__, retval);
			goto exit;
		}
	}

	/* we will send an event, so request a new sequence number */
	spin_lock(&sequence_lock);
	seq = ++uevent_seqnum;
	spin_unlock(&sequence_lock);
	// 添加格式为"SEQNUM=%llu”的序列号
	retval = add_uevent_var(env, "SEQNUM=%llu", (unsigned long long)seq);
	if (retval)
		goto exit;

/* 如果定义了"CONFIG_NET”，则使用netlink发送该uevent */
#if defined(CONFIG_NET)
	/* send netlink message */
	if (uevent_sock) {
		struct sk_buff *skb;
		size_t len;

		/* allocate message with the maximum possible size */
		len = strlen(action_string) + strlen(devpath) + 2;
		skb = alloc_skb(len + env->buflen, GFP_KERNEL);
		if (skb) {
			char *scratch;

			/* add header */
			scratch = skb_put(skb, len);
			sprintf(scratch, "%s@%s", action_string, devpath);

			/* copy keys to our continuous event payload buffer */
			for (i = 0; i < env->envp_idx; i++) {
				len = strlen(env->envp[i]) + 1;
				scratch = skb_put(skb, len);
				strcpy(scratch, env->envp[i]);
			}

			NETLINK_CB(skb).dst_group = 1;
			netlink_broadcast(uevent_sock, skb, 0, 1, GFP_KERNEL);
		}
	}
#endif

	/* call uevent_helper, usually only enabled during early boot 
	 * 以uevent_helper、subsystem以及添加了标准环境变量（HOME=/，PATH=/sbin:/bin:/usr/sbin:/usr/bin）的env指针为参数，
	   调用kmod模块提供的call_usermodehelper函数，上报uevent。 
       其中uevent_helper的内容是由内核配置项CONFIG_UEVENT_HELPER_PATH(位于./drivers/base/Kconfig)决定的(可参考lib/kobject_uevent.c, line 32)，
       该配置项指定了一个用户空间程序（或者脚本），用于解析上报的uevent，例如"/sbin/hotplug”。 
       call_usermodehelper的作用，就是fork一个进程，以uevent为参数，执行uevent_helper
     */
	if (uevent_helper[0]) {
		char *argv [3];

		argv [0] = uevent_helper;
		argv [1] = (char *)subsystem;
		argv [2] = NULL;
		retval = add_uevent_var(env, "HOME=/");
		if (retval)
			goto exit;
		retval = add_uevent_var(env, "PATH=/sbin:/bin:/usr/sbin:/usr/bin");
		if (retval)
			goto exit;

		call_usermodehelper (argv[0], argv, env->envp, UMH_WAIT_EXEC);
	}

exit:
	kfree(devpath);
	kfree(env);
	return retval;
}

EXPORT_SYMBOL_GPL(kobject_uevent_env);

/**
 * kobject_uevent - notify userspace by ending an uevent
 *
 * 和kobject_uevent_env功能一样，只是没有指定任何的环境变量
 * 
 * @action: action that is happening
 * @kobj: struct kobject that the action is happening to
 *
 * Returns 0 if kobject_uevent() is completed with success or the
 * corresponding error when it fails.
 */
int kobject_uevent(struct kobject *kobj, enum kobject_action action)
{
	return kobject_uevent_env(kobj, action, NULL);
}

EXPORT_SYMBOL_GPL(kobject_uevent);

/**
 * add_uevent_var - add key value string to the environment buffer
 * @env: environment buffer structure
 * @format: printf format for the key=value pair
 *
 * Returns 0 if environment variable was added successfully or -ENOMEM
 * if no space was available.
 */
int add_uevent_var(struct kobj_uevent_env *env, const char *format, ...)
{
	va_list args;
	int len;

	if (env->envp_idx >= ARRAY_SIZE(env->envp)) {
		printk(KERN_ERR "add_uevent_var: too many keys\n");
		WARN_ON(1);
		return -ENOMEM;
	}

	va_start(args, format);
	len = vsnprintf(&env->buf[env->buflen],
			sizeof(env->buf) - env->buflen,
			format, args);
	va_end(args);

	if (len >= (sizeof(env->buf) - env->buflen)) {
		printk(KERN_ERR "add_uevent_var: buffer size too small\n");
		WARN_ON(1);
		return -ENOMEM;
	}

	env->envp[env->envp_idx++] = &env->buf[env->buflen];
	env->buflen += len + 1;
	return 0;
}
EXPORT_SYMBOL_GPL(add_uevent_var);

#if defined(CONFIG_NET)
static int __init kobject_uevent_init(void)
{
	uevent_sock = netlink_kernel_create(&init_net, NETLINK_KOBJECT_UEVENT,
					    1, NULL, NULL, THIS_MODULE);
	if (!uevent_sock) {
		printk(KERN_ERR
		       "kobject_uevent: unable to create netlink socket!\n");
		return -ENODEV;
	}

	return 0;
}

postcore_initcall(kobject_uevent_init);
#endif
