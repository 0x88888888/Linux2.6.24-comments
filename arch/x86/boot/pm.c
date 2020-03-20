/* -*- linux-c -*- ------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *
 *   This file is part of the Linux kernel, and is made available under
 *   the terms of the GNU General Public License version 2.
 *
 * ----------------------------------------------------------------------- */

/*
 * arch/i386/boot/pm.c
 *
 * Prepare the machine for transition to protected mode.
 */

#include "boot.h"
#include <asm/segment.h>

/*
 * Invoke the realmode switch hook if present; otherwise
 * disable all interrupts.
 *
 * main()  [arch/x86/boot/main.c]
 *  go_to_protected_mode()
 *   realmode_switch_hook()
 */
static void realmode_switch_hook(void)
{
	if (boot_params.hdr.realmode_swtch) {
		asm volatile("lcallw *%0"
			     : : "m" (boot_params.hdr.realmode_swtch)
			     : "eax", "ebx", "ecx", "edx");
	} else {
		asm volatile("cli");
		outb(0x80, 0x70); /* Disable NMI */
		io_delay();
	}
}

/*
 * A zImage kernel is loaded at 0x10000 but wants to run at 0x1000.
 * A bzImage kernel is loaded and runs at 0x100000.
 *
 * main()  [arch/x86/boot/main.c]
 *  go_to_protected_mode() 
 *   move_kernel_around()
 */
static void move_kernel_around(void)
{
	/* Note: rely on the compile-time option here rather than
	   the LOADED_HIGH flag.  The Qemu kernel loader unconditionally
	   sets the loadflags to zero. */
#ifndef __BIG_KERNEL__
	u16 dst_seg, src_seg;
	u32 syssize;

	dst_seg =  0x1000 >> 4;
	src_seg = 0x10000 >> 4;
	syssize = boot_params.hdr.syssize; /* Size in 16-byte paragraphs */

	while (syssize) {
		int paras  = (syssize >= 0x1000) ? 0x1000 : syssize;
		int dwords = paras << 2;

		asm volatile("pushw %%es ; "
			     "pushw %%ds ; "
			     "movw %1,%%es ; "
			     "movw %2,%%ds ; "
			     "xorw %%di,%%di ; "
			     "xorw %%si,%%si ; "
			     "rep;movsl ; "
			     "popw %%ds ; "
			     "popw %%es"
			     : "+c" (dwords)
			     : "r" (dst_seg), "r" (src_seg)
			     : "esi", "edi");

		syssize -= paras;
		dst_seg += paras;
		src_seg += paras;
	}
#endif
}

/*
 * Disable all interrupts at the legacy PIC.
 */
static void mask_all_interrupts(void)
{
	outb(0xff, 0xa1);	/* Mask all interrupts on the secondary PIC */
	io_delay();
	outb(0xfb, 0x21);	/* Mask all but cascade on the primary PIC */
	io_delay();
}

/*
 * Reset IGNNE# if asserted in the FPU.
 */
static void reset_coprocessor(void)
{
	outb(0, 0xf0);
	io_delay();
	outb(0, 0xf1);
	io_delay();
}

/*
 * Set up the GDT
 */
#define GDT_ENTRY(flags,base,limit)		\
	(((u64)(base & 0xff000000) << 32) |	\
	 ((u64)flags << 40) |			\
	 ((u64)(limit & 0x00ff0000) << 32) |	\
	 ((u64)(base & 0x00ffff00) << 16) |	\
	 ((u64)(limit & 0x0000ffff)))

struct gdt_ptr {
	u16 len;
	u32 ptr;
} __attribute__((packed));

static void setup_gdt(void)
{
	/* There are machines which are known to not boot with the GDT
	   being 8-byte unaligned.  Intel recommends 16 byte alignment. */
	static const u64 boot_gdt[] __attribute__((aligned(16))) = {
		/* CS: code, read/execute, 4 GB, base 0 */
		[GDT_ENTRY_BOOT_CS] = GDT_ENTRY(0xc09b, 0, 0xfffff),
		/* DS: data, read/write, 4 GB, base 0 */
		[GDT_ENTRY_BOOT_DS] = GDT_ENTRY(0xc093, 0, 0xfffff),
	};
	/* Xen HVM incorrectly stores a pointer to the gdt_ptr, instead
	   of the gdt_ptr contents.  Thus, make it static so it will
	   stay in memory, at least long enough that we switch to the
	   proper kernel GDT. */
	static struct gdt_ptr gdt;

	gdt.len = sizeof(boot_gdt)-1;
	gdt.ptr = (u32)&boot_gdt + (ds() << 4);

	asm volatile("lgdtl %0" : : "m" (gdt));
}

/*
 * Set up the IDT
 */
static void setup_idt(void)
{
	static const struct gdt_ptr null_idt = {0, 0};
	asm volatile("lidtl %0" : : "m" (null_idt));
}

/*
 * Actual invocation sequence
 *
 * 进入保护模式,跳转到boot_params.hdr.code32_start
 *
 * main()  [arch/x86/boot/main.c]
 *  go_to_protected_mode()
 *
 */
void go_to_protected_mode(void)
{
	/* Hook before leaving real mode, also disables interrupts 
     * 调用 boot_params.hdr.realmode_swtch()
    */
	realmode_switch_hook();

	/* Move the kernel/setup to their final resting places */
	move_kernel_around();

	/* Enable the A20 gate */
	if (enable_a20()) {
		puts("A20 gate not responding, unable to boot...\n");
		die();
	}

	/* Reset coprocessor (IGNNE#) */
	reset_coprocessor();

	/* Mask all interrupts in the PIC 
	 * 一切的中断都屏蔽掉
	 */
	mask_all_interrupts();

	/* Actual transition to protected mode... 
	 * 将idt初始化为0。即当前不使用IDT
	 */
	setup_idt();
	setup_gdt();
	/* 在arch/x86/boot/pmjump.S中 
     * boot_params.hdr.code32_start 这个参数缺省由编译器产生，指向0x100000即1M的位置，
     * kernel的32位保护模式启动代码就在那里
     *
     * 在protected_mode_jump中切换到保护模式，然后跳转到 code32_start处，然后开启分页，设置GDT,IDT等等工作
     *
	 * 第二个参数是(u32)&boot_params + (ds() << 4)，
	 * 实际上是把boot_params在实模式下的地址转换到保护模式的地址。
	 * 因为CS和DS指的都是从0到4G的地址空间，所以这样的转换就足够了。
	 *
	 * 跳转到arch/i386/boot/compressed/head_32.S:startup_32()
	 * 或者 跳转到arch/i386/boot/head_32.S:startup_32()
	 */
	protected_mode_jump(boot_params.hdr.code32_start,
			    (u32)&boot_params + (ds() << 4));
}
