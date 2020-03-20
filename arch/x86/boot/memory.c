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
 * arch/i386/boot/memory.c
 *
 * Memory detection code
 */

#include "boot.h"

#define SMAP	0x534d4150	/* ASCII "SMAP" */


/* 收集物理内存信息
 * main()
 *  detect_memory()
 *   detect_memory_e820()
 */
static int detect_memory_e820(void)
{
	int count = 0;
	u32 next = 0;
	u32 size, id;
	u8 err;

	/*
	 * 
	 * 由于历史原因，一些i/o设备也会占据一部分内存物理地址空间，
	 * 因此系统可以使用的物理内存空间是不连续的，系统内存被分成了很多段，每个段的属性也是不一样的。
	 * int 0x15 查询物理内存时每次返回一个内存段的信息，因此要想返回系统中所有的物理内存，
	 * 我们必须以迭代的方式去查询。detect_memory_e820()函数把int 0x15放到一个do-while循环里，
     * 每次得到的一个内存段放到struct e820entry里，而struct e820entry的结构正是e820返回结果的结构！
     * 而像其它启动时获得的结果一样，最终都会被放到boot_params里，e820被放到了 boot_params.e820_map。
	 *
	 */
	struct e820entry *desc = boot_params.e820_map;

	do {
		size = sizeof(struct e820entry);

		/* Important: %edx is clobbered by some BIOSes,
		   so it must be either used for the error output
		   or explicitly marked clobbered. */
		asm("int $0x15; setc %0"
		    : "=d" (err), "+b" (next), "=a" (id), "+c" (size),
		      "=m" (*desc)
		    : "D" (desc), "d" (SMAP), "a" (0xe820));

		/* Some BIOSes stop returning SMAP in the middle of
		   the search loop.  We don't know exactly how the BIOS
		   screwed up the map at that point, we might have a
		   partial map, the full map, or complete garbage, so
		   just return failure. */
		if (id != SMAP) {
			count = 0;
			break;
		}

		if (err)
			break;

		count++;
		desc++;
	} while (next && count < E820MAX);

    // 设置boot_params中e820_entries的值为物理内存段的个数并返回物理内存段个数给函数调用者。
	return boot_params.e820_entries = count;
}

/*
 * main()
 *  detect_memory()
 *   detect_memory_e801()
 */
static int detect_memory_e801(void)
{
	u16 ax, bx, cx, dx;
	u8 err;

	bx = cx = dx = 0;
	ax = 0xe801;
	asm("stc; int $0x15; setc %0"
	    : "=m" (err), "+a" (ax), "+b" (bx), "+c" (cx), "+d" (dx));

	if (err)
		return -1;

	/* Do we really need to do this? */
	if (cx || dx) {
		ax = cx;
		bx = dx;
	}

	if (ax > 15*1024)
		return -1;	/* Bogus! */

	/* This ignores memory above 16MB if we have a memory hole
	   there.  If someone actually finds a machine with a memory
	   hole at 16MB and no support for 0E820h they should probably
	   generate a fake e820 map. */
	boot_params.alt_mem_k = (ax == 15*1024) ? (dx << 6)+ax : ax;

	return 0;
}

/*
 * main()
 *  detect_memory()
 *   detect_memory_88()
 */
static int detect_memory_88(void)
{
	u16 ax;
	u8 err;

	ax = 0x8800;
	asm("stc; int $0x15; setc %0" : "=bcdm" (err), "+a" (ax));

	boot_params.screen_info.ext_mem_k = ax;

	return -err;
}

/*
 * main()
 *  detect_memory()
 */
int detect_memory(void)
{
	int err = -1;

    /*
     * detect_memory_e820()、detcct_memory_e801()、detect_memory_88()
     * 获得系统物理内存布局，这3个函数内部其实都会以内联汇编的形式调用bios中断以取得内存信息，
     * 该中断调用形式为int 0x15，同时调用前分别把AX寄存器设置为0xe820h、0xe801h、0x88h
     */

    /*
     * 确定boot_params.e802_map中的值和
     *     boot_params.e820_entries
	 */
	if (detect_memory_e820() > 0)
		err = 0;

    /* 确定boot_params.alt_mem_k */
	if (!detect_memory_e801())
		err = 0;
    /* 确定boot_params.screen_info.ext_mem_t */
	if (!detect_memory_88())
		err = 0;

	return err;
}
