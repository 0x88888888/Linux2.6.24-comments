#ifndef _ASM_GENERIC_MMAN_H
#define _ASM_GENERIC_MMAN_H

/*
 Author: Michael S. Tsirkin <mst@mellanox.co.il>, Mellanox Technologies Ltd.
 Based on: asm-xxx/mman.h
*/

#define PROT_READ	0x1		/* page can be read */
#define PROT_WRITE	0x2		/* page can be written */
#define PROT_EXEC	0x4		/* page can be executed */
#define PROT_SEM	0x8		/* page may be used for atomic ops */
#define PROT_NONE	0x0		/* page can not be accessed */
#define PROT_GROWSDOWN	0x01000000	/* mprotect flag: extend change to start of growsdown vma */
#define PROT_GROWSUP	0x02000000	/* mprotect flag: extend change to end of growsup vma */

#define MAP_SHARED	0x01		/* mmap2时如果一个对象(通常是文件)在几个进程之间共享时,则必须是用MAP_SHARED,Share changes */
#define MAP_PRIVATE	0x02		/* mmap2时如果创建一个与数据源分离的私有映射,对映射区域的写入操作不影响文件中的数据.
                                   Changes are private 
                                 */
#define MAP_TYPE	0x0f		/* Mask for type of mapping */
#define MAP_FIXED	0x10		/* mmap2时必须使用指定的虚拟地址，如果该虚拟地址不能用，就失败。Interpret addr exactly */
#define MAP_ANONYMOUS	0x20    /* 创建与任何数据源都不相关的匿名映射，此类映射可用于为应用程序分配类似malloc所用的内存。
                                    don't use a file 
                                 */

#define MS_ASYNC	1		/* sync memory asynchronously */
#define MS_INVALIDATE	2		/* invalidate the caches */
#define MS_SYNC		4		/* synchronous memory sync */

#define MADV_NORMAL	0		/* no further special treatment */
#define MADV_RANDOM	1		/* expect random page references */
#define MADV_SEQUENTIAL	2		/* expect sequential page references */
#define MADV_WILLNEED	3		/* will need these pages */
#define MADV_DONTNEED	4		/* don't need these pages */

/* common parameters: try to keep these consistent across architectures */
#define MADV_REMOVE	9		/* remove these pages & resources */
#define MADV_DONTFORK	10		/* don't inherit across fork */
#define MADV_DOFORK	11		/* do inherit across fork */

/* compatibility flags */
#define MAP_FILE	0

#endif
