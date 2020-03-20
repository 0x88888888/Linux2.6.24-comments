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
 * arch/i386/boot/main.c
 *
 * Main module for the real-mode kernel code
 */

#include "boot.h"

struct boot_params boot_params __attribute__((aligned(16)));

char *HEAP = _end;
char *heap_end = _end;		/* Default end of heap = no heap */

/*
 * Copy the header into the boot parameter block.  Since this
 * screws up the old-style command line protocol, adjust by
 * filling in the new-style command line pointer instead.
 *
 *
 * 把header.S中的hdr结构(在第一个扇区)中的参数复制到boot_params中去
 * 这个函数目的就是将hdr从第一个扇区的497个字节的位置复制到boot_params.hdr里面，从而以后的C代码能够很方便地对于hdr进行操作。
 *
 * main()  [arch/x86/boot/main.c]
 *  copy_boot_params()
 */

static void copy_boot_params(void)
{
	struct old_cmdline {
		u16 cl_magic;
		u16 cl_offset;
	};
	
	const struct old_cmdline * const oldcmd =
		(const struct old_cmdline *)OLD_CL_ADDRESS;

	BUILD_BUG_ON(sizeof boot_params != 4096);
	/* 第二个参数在header.S中 */
	memcpy(&boot_params.hdr, &hdr, sizeof hdr);

	if (!boot_params.hdr.cmd_line_ptr &&
	    oldcmd->cl_magic == OLD_CL_MAGIC) {
		/* Old-style command line protocol. */
        /* 如果老的bootloader没有遵照新的hdr的协议传送启动参数给kernel，那么就要将hdr的命令行指针指向老的协议命令行。 */
		u16 cmdline_seg;

		/* Figure out if the command line falls in the region
		   of memory that an old kernel would have copied up
		   to 0x90000... */
		if (oldcmd->cl_offset < boot_params.hdr.setup_move_size)
			cmdline_seg = ds();
		else
			cmdline_seg = 0x9000;

		boot_params.hdr.cmd_line_ptr =
			(cmdline_seg << 4) + oldcmd->cl_offset;
	}

	printf("Mike debug: kernel command line: %s at 0x%x\n",
	       boot_params.hdr.cmd_line_ptr-(ds()<<4),
	       boot_params.hdr.cmd_line_ptr);
		
}

/*
 * Set the keyboard repeat rate to maximum.  Unclear why this
 * is done here; this might be possible to kill off as stale code.
 */
static void keyboard_set_repeat(void)
{
	u16 ax = 0x0305;
	u16 bx = 0;
	asm volatile("int $0x16"
		     : "+a" (ax), "+b" (bx)
		     : : "ecx", "edx", "esi", "edi");
}

/*
 * Get Intel SpeedStep (IST) information.
 */
static void query_ist(void)
{
	asm("int $0x15"
	    : "=a" (boot_params.ist_info.signature),
	      "=b" (boot_params.ist_info.command),
	      "=c" (boot_params.ist_info.event),
	      "=d" (boot_params.ist_info.perf_level)
	    : "a" (0x0000e980),	 /* IST Support */
	      "d" (0x47534943)); /* Request value */
}

/*
 * Tell the BIOS what CPU mode we intend to run in.
 */
static void set_bios_mode(void)
{
#ifdef CONFIG_X86_64
	u32 eax, ebx;

	eax = 0xec00;
	ebx = 2;
	asm volatile("int $0x15"
		     : "+a" (eax), "+b" (ebx)
		     : : "ecx", "edx", "esi", "edi");
#endif
}

/* header.S中调用这个函数
 * 这个函数 cpu处于实模式状态
*/
void main(void)
{
	/* First, copy the boot header into the "zeropage" 
     * 从第一个扇区中复制参数到boot_params中去
     */
	copy_boot_params();

	/* End of heap check 
     * 根据boot_params的值，设置heap
	 */
	if (boot_params.hdr.loadflags & CAN_USE_HEAP) {
		heap_end = (char *)(boot_params.hdr.heap_end_ptr
				    +0x200-STACK_SIZE);
	} else {
		/* Boot protocol 2.00 only, no heap available */
		puts("WARNING: Ancient bootloader, some functionality "
		     "may be limited!\n");
	}



	/* Make sure we have all the proper CPU support */
	if (validate_cpu()) {
		puts("Unable to boot - please use a kernel appropriate "
		     "for your CPU.\n");
		die();
	}

	/* Tell the BIOS what CPU mode we intend to run in. */
	set_bios_mode();

	/* Detect memory layout,收集物理内存信息
     * 将当前内存使用情况填充到boot_params.e820map， 
     * boot_params.alt_mem_k和
     * boot_params.screen_info.ext_mem_k
     *
     * 在　arch/x86/boot/main.c中
	 */
	detect_memory();

	/* Set keyboard repeat rate (why?)  */
	keyboard_set_repeat();

	/* Set the video mode */
	set_video();

	/* Query MCA information 
     * 查询system description table并将其存放在boot_params.sys_desc_table
	 */
	query_mca();

	/* Voyager */
#ifdef CONFIG_X86_VOYAGER
	query_voyager();
#endif

	/* Query Intel SpeedStep (IST) information 
     * 获得当前CPU的SpeedStep的信息
     */
	query_ist();

	/* Query APM information 
     * 使用query_apm_bios以检查APM的支持，
     * 并将APM的信息存放在boot_params.apm_bios_info
	 */
#if defined(CONFIG_APM) || defined(CONFIG_APM_MODULE)
	query_apm_bios();
#endif

	/* Query EDD information 
     * 使用query_edd以检查并设置boot_params.eddbuf_entries, 
     * boot_params.edd_mbr_sig_buf_entries, boot_params.edd_mbr_sig_buffer和boot_params.eddbuf.
     * 按照磁头，柱面，扇区的寻址方式，INT13只能支持不超过8G的硬盘。这是远远不够的，
     * 所以EDD （BIOS Enhanced Disk Drive Services）被加入INT13中来支持大硬盘。
     * query_edd会枚举所有当前硬盘的参数，并且进行记录为后面初始化硬盘驱动作准备
     */
#if defined(CONFIG_EDD) || defined(CONFIG_EDD_MODULE)
	query_edd();
#endif
	/* Do the last things and invoke protected mode 
     *  进入保护模式,并且跳转到boot_params.hdr.code32_start处
     *  跳转到arch/i386/boot/compressed/head_32.S:startup_32()
     *  或者 跳转到arch/i386/boot/head_32.S:startup_32()
     */
	go_to_protected_mode();
}
