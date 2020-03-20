#ifndef _LINUX_CDEV_H
#define _LINUX_CDEV_H
#ifdef __KERNEL__

#include <linux/kobject.h>
#include <linux/kdev_t.h>
#include <linux/list.h>

struct file_operations;
struct inode;
struct module;

/* 字符设备 */
struct cdev {
	struct kobject kobj; /* 用于该结构一般管理 */
	struct module *owner; /* 指向驱动程序的模块 */
	const struct file_operations *ops; /*  */
	struct list_head list; /* 包含所有表示该设备的设备特殊文件的inode */
	dev_t dev; /* 设备号 */
	unsigned int count; /* 表示与该设备关联的从设备号的数目 */
};

void cdev_init(struct cdev *, const struct file_operations *);

struct cdev *cdev_alloc(void);

void cdev_put(struct cdev *p);

int cdev_add(struct cdev *, dev_t, unsigned);

void cdev_del(struct cdev *);

void cd_forget(struct inode *);

extern struct backing_dev_info directly_mappable_cdev_bdi;

#endif
#endif
