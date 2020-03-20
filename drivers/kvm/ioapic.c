/*
 *  Copyright (C) 2001  MandrakeSoft S.A.
 *
 *    MandrakeSoft S.A.
 *    43, rue d'Aboukir
 *    75002 Paris - France
 *    http://www.linux-mandrake.com/
 *    http://www.mandrakesoft.com/
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 *  Yunhong Jiang <yunhong.jiang@intel.com>
 *  Yaozu (Eddie) Dong <eddie.dong@intel.com>
 *  Based on Xen 3.1 code.
 */

#include "kvm.h"
#include <linux/kvm.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/smp.h>
#include <linux/hrtimer.h>
#include <linux/io.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/apicdef.h>
#include <asm/io_apic.h>
#include "irq.h"
/* #define ioapic_debug(fmt,arg...) printk(KERN_WARNING fmt,##arg) */
#define ioapic_debug(fmt, arg...)
static void ioapic_deliver(struct kvm_ioapic *vioapic, int irq);

static unsigned long ioapic_read_indirect(struct kvm_ioapic *ioapic,
					  unsigned long addr,
					  unsigned long length)
{
	unsigned long result = 0;

	switch (ioapic->ioregsel) {
	case IOAPIC_REG_VERSION:
		result = ((((IOAPIC_NUM_PINS - 1) & 0xff) << 16)
			  | (IOAPIC_VERSION_ID & 0xff));
		break;

	case IOAPIC_REG_APIC_ID:
	case IOAPIC_REG_ARB_ID:
		result = ((ioapic->id & 0xf) << 24);
		break;

	default:
		{
			u32 redir_index = (ioapic->ioregsel - 0x10) >> 1;
			u64 redir_content;

			ASSERT(redir_index < IOAPIC_NUM_PINS);

			redir_content = ioapic->redirtbl[redir_index].bits;
			result = (ioapic->ioregsel & 0x1) ?
			    (redir_content >> 32) & 0xffffffff :
			    redir_content & 0xffffffff;
			break;
		}
	}

	return result;
}

/*
 * kvm_ioapic_set_irq()
 *  ioapic_service()
 */
static void ioapic_service(struct kvm_ioapic *ioapic, unsigned int idx)
{
	union ioapic_redir_entry *pent;

    /*取得对应中断的重定向表*/
	pent = &ioapic->redirtbl[idx];

    /*检查中断是否被mask了，如果不允许中断则不触发*/
	if (!pent->fields.mask) {
		/*构造APIC消息，准备发送到LAPIC*/
		ioapic_deliver(ioapic, idx);
		/*如果投递成功并且是电瓶触发，设置目的中断请求寄存器*/
		if (pent->fields.trig_mode == IOAPIC_LEVEL_TRIG)
			pent->fields.remote_irr = 1;
	}
	if (!pent->fields.trig_mode)
		ioapic->irr &= ~(1 << idx);
}

static void ioapic_write_indirect(struct kvm_ioapic *ioapic, u32 val)
{
	unsigned index;

	switch (ioapic->ioregsel) {
	case IOAPIC_REG_VERSION:
		/* Writes are ignored. */
		break;

	case IOAPIC_REG_APIC_ID:
		ioapic->id = (val >> 24) & 0xf;
		break;

	case IOAPIC_REG_ARB_ID:
		break;

	default:
		index = (ioapic->ioregsel - 0x10) >> 1;

		ioapic_debug("change redir index %x val %x", index, val);
		if (index >= IOAPIC_NUM_PINS)
			return;
		if (ioapic->ioregsel & 1) {
			ioapic->redirtbl[index].bits &= 0xffffffff;
			ioapic->redirtbl[index].bits |= (u64) val << 32;
		} else {
			ioapic->redirtbl[index].bits &= ~0xffffffffULL;
			ioapic->redirtbl[index].bits |= (u32) val;
			ioapic->redirtbl[index].fields.remote_irr = 0;
		}
		if (ioapic->irr & (1 << index))
			ioapic_service(ioapic, index);
		break;
	}
}

static void ioapic_inj_irq(struct kvm_ioapic *ioapic,
			   struct kvm_lapic *target,
			   u8 vector, u8 trig_mode, u8 delivery_mode)
{
	ioapic_debug("irq %d trig %d deliv %d", vector, trig_mode,
		     delivery_mode);

	ASSERT((delivery_mode == dest_Fixed) ||
	       (delivery_mode == dest_LowestPrio));

	kvm_apic_set_irq(target, vector, trig_mode);
}

static u32 ioapic_get_delivery_bitmask(struct kvm_ioapic *ioapic, u8 dest,
				       u8 dest_mode)
{
	u32 mask = 0;
	int i;
	struct kvm *kvm = ioapic->kvm;
	struct kvm_vcpu *vcpu;

	ioapic_debug("dest %d dest_mode %d", dest, dest_mode);

	if (dest_mode == 0) {	/* Physical mode. */
		if (dest == 0xFF) {	/* Broadcast. */
			for (i = 0; i < KVM_MAX_VCPUS; ++i)
				if (kvm->vcpus[i] && kvm->vcpus[i]->apic)
					mask |= 1 << i;
			return mask;
		}
		for (i = 0; i < KVM_MAX_VCPUS; ++i) {
			vcpu = kvm->vcpus[i];
			if (!vcpu)
				continue;
			if (kvm_apic_match_physical_addr(vcpu->apic, dest)) {
				if (vcpu->apic)
					mask = 1 << i;
				break;
			}
		}
	} else if (dest != 0)	/* Logical mode, MDA non-zero. */
		for (i = 0; i < KVM_MAX_VCPUS; ++i) {
			vcpu = kvm->vcpus[i];
			if (!vcpu)
				continue;
			if (vcpu->apic &&
			    kvm_apic_match_logical_addr(vcpu->apic, dest))
				mask |= 1 << vcpu->vcpu_id;
		}
	ioapic_debug("mask %x", mask);
	return mask;
}

/*
 * kvm_ioapic_set_irq()
 *  ioapic_service()
 *   ioapic_deliver()
 */
static void ioapic_deliver(struct kvm_ioapic *ioapic, int irq)
{
	u8 dest = ioapic->redirtbl[irq].fields.dest_id;
	u8 dest_mode = ioapic->redirtbl[irq].fields.dest_mode;
	u8 delivery_mode = ioapic->redirtbl[irq].fields.delivery_mode;
	u8 vector = ioapic->redirtbl[irq].fields.vector;
	u8 trig_mode = ioapic->redirtbl[irq].fields.trig_mode;
	u32 deliver_bitmask;
	struct kvm_lapic *target;
	struct kvm_vcpu *vcpu;
	int vcpu_id;

	ioapic_debug("dest=%x dest_mode=%x delivery_mode=%x "
		     "vector=%x trig_mode=%x",
		     dest, dest_mode, delivery_mode, vector, trig_mode);

	deliver_bitmask = ioapic_get_delivery_bitmask(ioapic, dest, dest_mode);
	if (!deliver_bitmask) {
		ioapic_debug("no target on destination");
		return;
	}

	switch (delivery_mode) {
	case dest_LowestPrio:
		target =
		    kvm_apic_round_robin(ioapic->kvm, vector, deliver_bitmask);
		if (target != NULL)
			ioapic_inj_irq(ioapic, target, vector,
				       trig_mode, delivery_mode);
		else
			ioapic_debug("null round robin: "
				     "mask=%x vector=%x delivery_mode=%x",
				     deliver_bitmask, vector, dest_LowestPrio);
		break;
	case dest_Fixed:
		for (vcpu_id = 0; deliver_bitmask != 0; vcpu_id++) {
			if (!(deliver_bitmask & (1 << vcpu_id)))
				continue;
			deliver_bitmask &= ~(1 << vcpu_id);
			vcpu = ioapic->kvm->vcpus[vcpu_id];
			if (vcpu) {
				target = vcpu->apic;
				ioapic_inj_irq(ioapic, target, vector,
					       trig_mode, delivery_mode);
			}
		}
		break;

		/* TODO: NMI */
	default:
		printk(KERN_WARNING "Unsupported delivery mode %d\n",
		       delivery_mode);
		break;
	}
}

void kvm_ioapic_set_irq(struct kvm_ioapic *ioapic, int irq, int level)
{
	u32 old_irr = ioapic->irr;
	u32 mask = 1 << irq;
	union ioapic_redir_entry entry;

	if (irq >= 0 && irq < IOAPIC_NUM_PINS) {
		entry = ioapic->redirtbl[irq];
		level ^= entry.fields.polarity;
		if (!level)
			ioapic->irr &= ~mask;
		else {
			ioapic->irr |= mask;
			if ((!entry.fields.trig_mode && old_irr != ioapic->irr)
			    || !entry.fields.remote_irr)
				ioapic_service(ioapic, irq);
		}
	}
}

static int get_eoi_gsi(struct kvm_ioapic *ioapic, int vector)
{
	int i;

	for (i = 0; i < IOAPIC_NUM_PINS; i++)
		if (ioapic->redirtbl[i].fields.vector == vector)
			return i;
	return -1;
}

void kvm_ioapic_update_eoi(struct kvm *kvm, int vector)
{
	struct kvm_ioapic *ioapic = kvm->vioapic;
	union ioapic_redir_entry *ent;
	int gsi;

	gsi = get_eoi_gsi(ioapic, vector);
	if (gsi == -1) {
		printk(KERN_WARNING "Can't find redir item for %d EOI\n",
		       vector);
		return;
	}

	ent = &ioapic->redirtbl[gsi];
	ASSERT(ent->fields.trig_mode == IOAPIC_LEVEL_TRIG);

	ent->fields.remote_irr = 0;
	if (!ent->fields.mask && (ioapic->irr & (1 << gsi)))
		ioapic_deliver(ioapic, gsi);
}

static int ioapic_in_range(struct kvm_io_device *this, gpa_t addr)
{
	struct kvm_ioapic *ioapic = (struct kvm_ioapic *)this->private;

	return ((addr >= ioapic->base_address &&
		 (addr < ioapic->base_address + IOAPIC_MEM_LENGTH)));
}

static void ioapic_mmio_read(struct kvm_io_device *this, gpa_t addr, int len,
			     void *val)
{
	struct kvm_ioapic *ioapic = (struct kvm_ioapic *)this->private;
	u32 result;

	ioapic_debug("addr %lx", (unsigned long)addr);
	ASSERT(!(addr & 0xf));	/* check alignment */

	addr &= 0xff;
	switch (addr) {
	case IOAPIC_REG_SELECT:
		result = ioapic->ioregsel;
		break;

	case IOAPIC_REG_WINDOW:
		result = ioapic_read_indirect(ioapic, addr, len);
		break;

	default:
		result = 0;
		break;
	}
	switch (len) {
	case 8:
		*(u64 *) val = result;
		break;
	case 1:
	case 2:
	case 4:
		memcpy(val, (char *)&result, len);
		break;
	default:
		printk(KERN_WARNING "ioapic: wrong length %d\n", len);
	}
}

static void ioapic_mmio_write(struct kvm_io_device *this, gpa_t addr, int len,
			      const void *val)
{
	struct kvm_ioapic *ioapic = (struct kvm_ioapic *)this->private;
	u32 data;

	ioapic_debug("ioapic_mmio_write addr=%lx len=%d val=%p\n",
		     addr, len, val);
	ASSERT(!(addr & 0xf));	/* check alignment */
	if (len == 4 || len == 8)
		data = *(u32 *) val;
	else {
		printk(KERN_WARNING "ioapic: Unsupported size %d\n", len);
		return;
	}

	addr &= 0xff;
	switch (addr) {
	case IOAPIC_REG_SELECT:
		ioapic->ioregsel = data;
		break;

	case IOAPIC_REG_WINDOW:
		ioapic_write_indirect(ioapic, data);
		break;

	default:
		break;
	}
}

/*
 * compat_sys_ioctl()
 *  kvm_vm_ioctl()
 *   kvm_ioapic_init()
 */
int kvm_ioapic_init(struct kvm *kvm)
{
	struct kvm_ioapic *ioapic;
	int i;

	ioapic = kzalloc(sizeof(struct kvm_ioapic), GFP_KERNEL);
	if (!ioapic)
		return -ENOMEM;
	kvm->vioapic = ioapic;
	for (i = 0; i < IOAPIC_NUM_PINS; i++)
		ioapic->redirtbl[i].fields.mask = 1;
	ioapic->base_address = IOAPIC_DEFAULT_BASE_ADDRESS;
	ioapic->dev.read = ioapic_mmio_read;
	ioapic->dev.write = ioapic_mmio_write;
	ioapic->dev.in_range = ioapic_in_range;
	ioapic->dev.private = ioapic;
	ioapic->kvm = kvm;
	kvm_io_bus_register_dev(&kvm->mmio_bus, &ioapic->dev);
	return 0;
}
