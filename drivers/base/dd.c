/*
 *	drivers/base/dd.c - The core device/driver interactions.
 *
 * 	This file contains the (sometimes tricky) code that controls the
 *	interactions between devices and drivers, which primarily includes
 *	driver binding and unbinding.
 *
 *	All of this code used to exist in drivers/base/bus.c, but was
 *	relocated to here in the name of compartmentalization (since it wasn't
 *	strictly code just for the 'struct bus_type'.
 *
 *	Copyright (c) 2002-5 Patrick Mochel
 *	Copyright (c) 2002-3 Open Source Development Labs
 *
 *	This file is released under the GPLv2
 */

#include <linux/device.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/wait.h>

#include "base.h"
#include "power/power.h"

#define to_drv(node) container_of(node, struct device_driver, kobj.entry)


/*
 * device_register()
 *  device_add()
 *   bus_attach_device()
 *    device_attach()
 *     device_bind_driver()
 *      driver_bound()
 *
 * 
 */
static void driver_bound(struct device *dev)
{
	if (klist_node_attached(&dev->knode_driver)) {
		printk(KERN_WARNING "%s: device %s already bound\n",
			__FUNCTION__, kobject_name(&dev->kobj));
		return;
	}

	pr_debug("bound device '%s' to driver '%s'\n",
		 dev->bus_id, dev->driver->name);

	if (dev->bus)
		blocking_notifier_call_chain(&dev->bus->bus_notifier,
					     BUS_NOTIFY_BOUND_DRIVER, dev);

	klist_add_tail(&dev->knode_driver, &dev->driver->klist_devices);
}

/*
 * device_register()
 *  device_add()
 *   bus_attach_device()
 *    device_attach()
 *     device_bind_driver()
 *      driver_sysfs_add()
 *
 * 建立device与驱动程序之间建立符号链接
 */
static int driver_sysfs_add(struct device *dev)
{
	int ret;

	ret = sysfs_create_link(&dev->driver->kobj, &dev->kobj,
			  kobject_name(&dev->kobj));
	
	if (ret == 0) {
		ret = sysfs_create_link(&dev->kobj, &dev->driver->kobj,
					"driver");
		if (ret)
			sysfs_remove_link(&dev->driver->kobj,
					kobject_name(&dev->kobj));
	}
	return ret;
}

static void driver_sysfs_remove(struct device *dev)
{
	struct device_driver *drv = dev->driver;

	if (drv) {
		sysfs_remove_link(&drv->kobj, kobject_name(&dev->kobj));
		sysfs_remove_link(&dev->kobj, "driver");
	}
}

/**
 *	device_bind_driver - bind a driver to one device.
 *	@dev:	device.
 *
 *	Allow manual attachment of a driver to a device.
 *	Caller must have already set @dev->driver.
 *
 *	Note that this does not modify the bus reference count
 *	nor take the bus's rwsem. Please verify those are accounted
 *	for before calling this. (It is ok to call with no other effort
 *	from a driver's probe() method.)
 *
 *	This function must be called with @dev->sem held.
 *
 * device_register()
 *  device_add()
 *   bus_attach_device()
 *    device_attach()
 *     device_bind_driver()
 *
 * 将device对象关联到相应的device_driver对象
 */
int device_bind_driver(struct device *dev)
{
	int ret;

    //这个函数是关键
	ret = driver_sysfs_add(dev);
	if (!ret)
		driver_bound(dev);
	return ret;
}

static atomic_t probe_count = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(probe_waitqueue);

/*
 * device_register()
 *  device_add()
 *   bus_attach_device()
 *    device_attach()
 *     bus_for_each_drv(fn == __device_attach)
 *      __device_attach()
 *       driver_probe_device()
 *        really_probe()
 *
 * start_kernel()
 *  rest_init() 中调用kernel_thread()创建kernel_init线程
 *   do_basic_setup()
 *    do_initcalls()
 *     acpi_pci_root_init()
 *      acpi_bus_register_driver( driver == acpi_pci_root_driver)
 *       driver_register(drv== acpi_pci_root_driver->drv)
 *        bus_add_driver(drv== acpi_pci_root_driver->drv)
 *         driver_attach(drv== acpi_pci_root_driver->drv)
 *          __driver_attach(data==acpi_pci_root_driver->drv)
 *           driver_probe_device(drv== acpi_pci_root_driver->drv)
 *            really_probe(, drv== acpi_pci_root_driver->drv)
 */
static int really_probe(struct device *dev, struct device_driver *drv)
{
	int ret = 0;

	atomic_inc(&probe_count);
	pr_debug("%s: Probing driver %s with device %s\n",
		 drv->bus->name, drv->name, dev->bus_id);
	WARN_ON(!list_empty(&dev->devres_head));

	dev->driver = drv;
	if (driver_sysfs_add(dev)) {
		printk(KERN_ERR "%s: driver_sysfs_add(%s) failed\n",
			__FUNCTION__, dev->bus_id);
		goto probe_failed;
	}

    //ide_bus_type.probe = generic_ide_probe
    //acpi_device_probe
	if (dev->bus->probe) {
		ret = dev->bus->probe(dev);
		if (ret)
			goto probe_failed;
	} else if (drv->probe) { 
	    // sr_template.gendrv.probe = sr_probe
		ret = drv->probe(dev);
		if (ret)
			goto probe_failed;
	}

	driver_bound(dev);
	ret = 1;
	pr_debug("%s: Bound Device %s to Driver %s\n",
		 drv->bus->name, dev->bus_id, drv->name);
	goto done;

probe_failed:
	devres_release_all(dev);
	driver_sysfs_remove(dev);
	dev->driver = NULL;

	if (ret != -ENODEV && ret != -ENXIO) {
		/* driver matched but the probe failed */
		printk(KERN_WARNING
		       "%s: probe of %s failed with error %d\n",
		       drv->name, dev->bus_id, ret);
	}
	/*
	 * Ignore errors returned by ->probe so that the next driver can try
	 * its luck.
	 */
	ret = 0;
done:
	atomic_dec(&probe_count);
	wake_up(&probe_waitqueue);
	return ret;
}

/**
 * driver_probe_done
 * Determine if the probe sequence is finished or not.
 *
 * Should somehow figure out how to use a semaphore, not an atomic variable...
 */
int driver_probe_done(void)
{
	pr_debug("%s: probe_count = %d\n", __FUNCTION__,
		 atomic_read(&probe_count));
	if (atomic_read(&probe_count))
		return -EBUSY;
	return 0;
}

/**
 * driver_probe_device - attempt to bind device & driver together
 * @drv: driver to bind a device to
 * @dev: device to try to bind to the driver
 *
 * First, we call the bus's match function, if one present, which should
 * compare the device IDs the driver supports with the device IDs of the
 * device. Note we don't do this ourselves because we don't know the
 * format of the ID structures, nor what is to be considered a match and
 * what is not.
 *
 * This function returns 1 if a match is found, -ENODEV if the device is
 * not registered, and 0 otherwise.
 *
 * This function must be called with @dev->sem held.  When called for a
 * USB interface, @dev->parent->sem must be held as well.
 *
 *
 * vortex_init()
 *  pci_register_driver(vertex_driver)
 *   __pci_register_driver(vertex_driver, THIS_MODULE, KBUILD_MODNAME)
 *    driver_register(vertex_driver->driver)
 *     bus_add_driver(vertex_driver->driver)
 *      driver_attach(vertex_driver->driver)
 *       bus_for_each_dev(fn == __driver_attach)
 *        __driver_attach()
 *         driver_probe_device()
 *
 * e1000_init_module()
 *  pci_register_driver(e1000_driver) 
 *   __pci_register_driver(e1000_driver, THIS_MODULE, KBUILD_MODNAME) 
 *    driver_register(e1000_driver->driver) 
 *     bus_add_driver(vertex_driver->driver)
 *      driver_attach(vertex_driver->driver) 
 *       bus_for_each_dev(fn == __driver_attach) 
 *        __driver_attach() 
 *         driver_probe_device()
 *
 * start_kernel()
 *  rest_init() 中调用kernel_thread()创建kernel_init线程
 *   do_basic_setup()
 *    do_initcalls()
 *     acpi_pci_root_init()
 *      acpi_bus_register_driver( driver == acpi_pci_root_driver)
 *       driver_register(drv== acpi_pci_root_driver->drv)
 *        bus_add_driver(drv== acpi_pci_root_driver->drv)
 *         driver_attach(drv== acpi_pci_root_driver->drv)
 *          __driver_attach(data==acpi_pci_root_driver->drv)
 *           driver_probe_device(drv== acpi_pci_root_driver->drv)
 */
int driver_probe_device(struct device_driver * drv, struct device * dev)
{
	int ret = 0;

	if (!device_is_registered(dev))
		return -ENODEV;
	/* 
	 * 从pci_register_driver()进来的调用的match都是pci_bus_type
	 * pci_bus_type.match == pci_bus_match
	 */
	if (drv->bus->match && !drv->bus->match(dev, drv))
		goto done;

	pr_debug("%s: Matched Device %s with Driver %s\n",
		 drv->bus->name, dev->bus_id, drv->name);

	ret = really_probe(dev, drv);

done:
	return ret;
}

/*
 * device_register()
 *  device_add()
 *   bus_attach_device()
 *    device_attach()
 *     bus_for_each_drv(fn == __device_attach)
 *      __device_attach()
 */
static int __device_attach(struct device_driver * drv, void * data)
{
	struct device * dev = data;
	return driver_probe_device(drv, dev);
}

/**
 *	device_attach - try to attach device to a driver.
 *	@dev:	device.
 *
 *	Walk the list of drivers that the bus has and call
 *	driver_probe_device() for each pair. If a compatible
 *	pair is found, break out and return.
 *
 *	Returns 1 if the device was bound to a driver;
 *	0 if no matching device was found;
 *	-ENODEV if the device is not registered.
 *
 *	When called for a USB interface, @dev->parent->sem must be held.
 *
 * device_register()
 *  device_add()
 *   bus_attach_device()
 *    device_attach()
 */
int device_attach(struct device * dev)
{
	int ret = 0;

	down(&dev->sem);
	if (dev->driver) {
		ret = device_bind_driver(dev);
		if (ret == 0)
			ret = 1;
		else {
			dev->driver = NULL;
			ret = 0;
		}
	} else {
		ret = bus_for_each_drv(dev->bus, NULL, dev, __device_attach);
	}
	up(&dev->sem);
	return ret;
}

/*
 *
 * vortex_init()
 *  pci_register_driver(vertex_driver)
 *   __pci_register_driver(vertex_driver, THIS_MODULE, KBUILD_MODNAME)
 *    driver_register(vertex_driver->driver)
 *     bus_add_driver(vertex_driver->driver)
 *      driver_attach(vertex_driver->driver)
 *       bus_for_each_dev(fn == __driver_attach)
 *        __driver_attach()
 *
 * e1000_init_module()
 *  pci_register_driver(e1000_driver) 
 *   __pci_register_driver(e1000_driver, THIS_MODULE, KBUILD_MODNAME) 
 *    driver_register(e1000_driver->driver) 
 *     bus_add_driver(vertex_driver->driver)
 *      driver_attach(vertex_driver->driver) 
 *       bus_for_each_dev(fn == __driver_attach) 
 *        __driver_attach()
 *
 * start_kernel()
 *  rest_init() 中调用kernel_thread()创建kernel_init线程
 *   do_basic_setup()
 *    do_initcalls()
 *     acpi_pci_root_init()
 *      acpi_bus_register_driver( driver == acpi_pci_root_driver)
 *       driver_register(drv== acpi_pci_root_driver->drv)
 *        bus_add_driver(drv== acpi_pci_root_driver->drv)
 *         driver_attach(drv== acpi_pci_root_driver->drv)
 *          __driver_attach(data==acpi_pci_root_driver->drv)
 */
static int __driver_attach(struct device * dev, void * data)
{
	struct device_driver * drv = data;

	/*
	 * Lock device and try to bind to it. We drop the error
	 * here and always return 0, because we need to keep trying
	 * to bind to devices and some drivers will return an error
	 * simply if it didn't support the device.
	 *
	 * driver_probe_device() will spit a warning if there
	 * is an error.
	 */

	if (dev->parent)	/* Needed for USB */
		down(&dev->parent->sem);
	down(&dev->sem);
	
	if (!dev->driver) //重要
		driver_probe_device(drv, dev);
	
	up(&dev->sem);
	if (dev->parent)
		up(&dev->parent->sem);

	return 0;
}

/**
 *	driver_attach - try to bind driver to devices.
 *	@drv:	driver.
 *
 *	Walk the list of devices that the bus has on it and try to
 *	match the driver with each one.  If driver_probe_device()
 *	returns 0 and the @dev->driver is set, we've found a
 *	compatible pair.
 *
 * vortex_init()
 *  pci_register_driver(vertex_driver)
 *   __pci_register_driver(vertex_driver, THIS_MODULE, KBUILD_MODNAME)
 *    driver_register(vertex_driver->driver)
 *     bus_add_driver(vertex_driver->driver)
 *      driver_attach(vertex_driver->driver)
 *
 * e1000_init_module()
 *  pci_register_driver(e1000_driver) 
 *   __pci_register_driver(e1000_driver, THIS_MODULE, KBUILD_MODNAME) 
 *    driver_register(e1000_driver->driver) 
 *     bus_add_driver(vertex_driver->driver)
 *      driver_attach(vertex_driver->driver)
 *
 * start_kernel()
 *  rest_init() 中调用kernel_thread()创建kernel_init线程
 *   do_basic_setup()
 *    do_initcalls()
 *     acpi_pci_root_init()
 *      acpi_bus_register_driver( driver == acpi_pci_root_driver)
 *       driver_register(drv== acpi_pci_root_driver->drv)
 *        bus_add_driver(drv== acpi_pci_root_driver->drv)
 &         driver_attach(drv== acpi_pci_root_driver->drv)
 */
int driver_attach(struct device_driver * drv)
{
	return bus_for_each_dev(drv->bus, NULL, drv, __driver_attach);
}

/*
 *	__device_release_driver() must be called with @dev->sem held.
 *	When called for a USB interface, @dev->parent->sem must be held as well.
 */
static void __device_release_driver(struct device * dev)
{
	struct device_driver * drv;

	drv = get_driver(dev->driver);
	if (drv) {
		driver_sysfs_remove(dev);
		sysfs_remove_link(&dev->kobj, "driver");
		klist_remove(&dev->knode_driver);

		if (dev->bus)
			blocking_notifier_call_chain(&dev->bus->bus_notifier,
						     BUS_NOTIFY_UNBIND_DRIVER,
						     dev);

		if (dev->bus && dev->bus->remove)
			dev->bus->remove(dev);
		else if (drv->remove)
			drv->remove(dev);
		devres_release_all(dev);
		dev->driver = NULL;
		put_driver(drv);
	}
}

/**
 *	device_release_driver - manually detach device from driver.
 *	@dev:	device.
 *
 *	Manually detach device from driver.
 *	When called for a USB interface, @dev->parent->sem must be held.
 */
void device_release_driver(struct device * dev)
{
	/*
	 * If anyone calls device_release_driver() recursively from
	 * within their ->remove callback for the same device, they
	 * will deadlock right here.
	 */
	down(&dev->sem);
	__device_release_driver(dev);
	up(&dev->sem);
}


/**
 * driver_detach - detach driver from all devices it controls.
 * @drv: driver.
 */
void driver_detach(struct device_driver * drv)
{
	struct device * dev;

	for (;;) {
		spin_lock(&drv->klist_devices.k_lock);
		if (list_empty(&drv->klist_devices.k_list)) {
			spin_unlock(&drv->klist_devices.k_lock);
			break;
		}
		dev = list_entry(drv->klist_devices.k_list.prev,
				struct device, knode_driver.n_node);
		get_device(dev);
		spin_unlock(&drv->klist_devices.k_lock);

		if (dev->parent)	/* Needed for USB */
			down(&dev->parent->sem);
		down(&dev->sem);
		if (dev->driver == drv)
			__device_release_driver(dev);
		up(&dev->sem);
		if (dev->parent)
			up(&dev->parent->sem);
		put_device(dev);
	}
}

EXPORT_SYMBOL_GPL(device_bind_driver);
EXPORT_SYMBOL_GPL(device_release_driver);
EXPORT_SYMBOL_GPL(device_attach);
EXPORT_SYMBOL_GPL(driver_attach);

