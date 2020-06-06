/*
 *  linux/drivers/base/map.c
 *
 * (C) Copyright Al Viro 2002,2003
 *	Released under GPL v2.
 *
 * NOTE: data structure needs to be changed.  It works, but for large dev_t
 * it will be too slow.  It is isolated, though, so these changes will be
 * local to that file.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/kdev_t.h>
#include <linux/kobject.h>
#include <linux/kobj_map.h>

/* 通过要加入系统的设备的主设备号major（major=MAJOR(dev)）来获得probes数组的索引值i（i = major % 255）
 *
 * 两个全局对象cdev_map和bdev_map,分别用来存放字符设备对象和块设备对象
 */
struct kobj_map {
	struct probe {
		struct probe *next;/* 将所有的散列元素链接成链表 */
		dev_t dev;   /* 设备号,包含了主设备和从设备号 */
		unsigned long range; /* 从设备号的连续范围存储在range中 */
		struct module *owner; /*  设备驱动程序模块 */
		kobj_probe_t *get; /* 返回与设备关联的kobject实例 */
		int (*lock)(dev_t, void *);
		void *data;     /* 块设备指向genhd,字符设备指向cdev */
	} *probes[255];
	struct mutex *lock;
};

/*
 * cdev_add()
 *  kobj_map()
 *
 */
int kobj_map(struct kobj_map *domain, dev_t dev, unsigned long range,
	     struct module *module, kobj_probe_t *probe,
	     int (*lock)(dev_t, void *), void *data)
{
	unsigned n = MAJOR(dev + range - 1) - MAJOR(dev) + 1;
	//主设备号
	unsigned index = MAJOR(dev);
	unsigned i;
	struct probe *p;

	if (n > 255)
		n = 255;

    //分配n个probe结构
	p = kmalloc(sizeof(struct probe) * n, GFP_KERNEL);

	if (p == NULL)
		return -ENOMEM;

    //给n个probe结构，设置成员
	for (i = 0; i < n; i++, p++) {
		p->owner = module;
		p->get = probe;
		p->lock = lock;
		p->dev = dev;
		p->range = range;
		p->data = data;
	}
	
	mutex_lock(domain->lock);

	//n个probe对象,各个probe落在domain->probes[]不同的链表上
	for (i = 0, p -= n; i < n; i++, p++, index++) {
		//probes链表
		struct probe **s = &domain->probes[index % 255];
		//到链表的range伟指出
		while (*s && (*s)->range < range)
			s = &(*s)->next;
		//放进去
		p->next = *s;
		*s = p;
	}
	mutex_unlock(domain->lock);
	return 0;
}

void kobj_unmap(struct kobj_map *domain, dev_t dev, unsigned long range)
{
	unsigned n = MAJOR(dev + range - 1) - MAJOR(dev) + 1;
	unsigned index = MAJOR(dev);
	unsigned i;
	struct probe *found = NULL;

	if (n > 255)
		n = 255;

	mutex_lock(domain->lock);
	for (i = 0; i < n; i++, index++) {
		struct probe **s;
		for (s = &domain->probes[index % 255]; *s; s = &(*s)->next) {
			struct probe *p = *s;
			if (p->dev == dev && p->range == range) {
				*s = p->next;
				if (!found)
					found = p;
				break;
			}
		}
	}
	mutex_unlock(domain->lock);
	kfree(found);
}

/*
 * sys_open()
 *  do_sys_open()
 *   do_filp_open()
 *    nameidata_to_filp()
 *     __dentry_open()
 *      blkdev_open()
 *       do_open()
 *        get_gendisk()
 *         kobj_lookup()
 *
 * 在domain->probes[]中查找kobject
 */
struct kobject *kobj_lookup(struct kobj_map *domain, dev_t dev, int *index)
{
	struct kobject *kobj;
	struct probe *p;
	unsigned long best = ~0UL;

retry:
	mutex_lock(domain->lock);
	for (p = domain->probes[MAJOR(dev) % 255]; p; p = p->next) {
		struct kobject *(*probe)(dev_t, int *, void *);
		struct module *owner;
		void *data;

		if (p->dev > dev || p->dev + p->range - 1 < dev)
			continue;
		if (p->range - 1 >= best)
			break;
		if (!try_module_get(p->owner))
			continue;
		owner = p->owner;
		data = p->data;
		probe = p->get;
		best = p->range - 1;
		*index = dev - p->dev;
		if (p->lock && p->lock(dev, data) < 0) {
			module_put(owner);
			continue;
		}
		mutex_unlock(domain->lock);
		kobj = probe(dev, index, data);
		/* Currently ->owner protects _only_ ->probe() itself. */
		module_put(owner);
		if (kobj)
			return kobj;
		goto retry;
	}
	mutex_unlock(domain->lock);
	return NULL;
}

struct kobj_map *kobj_map_init(kobj_probe_t *base_probe, struct mutex *lock)
{
	struct kobj_map *p = kmalloc(sizeof(struct kobj_map), GFP_KERNEL);
	struct probe *base = kzalloc(sizeof(*base), GFP_KERNEL);
	int i;

	if ((p == NULL) || (base == NULL)) {
		kfree(p);
		kfree(base);
		return NULL;
	}

	base->dev = 1;
	base->range = ~0;
	base->get = base_probe;
	for (i = 0; i < 255; i++)
		p->probes[i] = base;
	p->lock = lock;
	return p;
}
