/*
 * Discontiguous memory support, Kanoj Sarcar, SGI, Nov 1999
 */
#ifndef _LINUX_BOOTMEM_H
#define _LINUX_BOOTMEM_H

#include <linux/mmzone.h>
#include <asm/dma.h>

/*
 *  simple boot-time physical memory area allocator.
 */

extern unsigned long max_low_pfn;
extern unsigned long min_low_pfn;

/*
 * highest page
 */
extern unsigned long max_pfn;

#ifdef CONFIG_CRASH_DUMP
extern unsigned long saved_max_pfn;
#endif

/*
 * 注册新的自举分配器可使用init_bootmem_core，所有的注册分配器保存在一个链表中，表头为bdata_list(bootmem.c中)
 * node_bootmem_map is a map pointer - the bits represent all physical 
 * memory pages (including holes) on the node.
 */
typedef struct bootmem_data {
	unsigned long node_boot_start; /* 保存了系统中第一个页的编号，大多数体系结构下都是0 */
	unsigned long node_low_pfn; /* 直接管理的物理地址空间中最后一页的编号,即ZONE_NORMAL的结束页 */
	void *node_bootmem_map;   /* 存储分配位图的内存区的指针，在IA-32系统上，该地址保存在_end变量中,该变量在链接期间自动的插入到内核映像中去 */
	unsigned long last_offset; /* 上一次分配的页的编号 */
	unsigned long last_pos;
	unsigned long last_success;	/* 上一次成功分配的内存的位置，新的分配将由此开始. Previous allocation point.  To speed
					 * up searching */
	struct list_head list;  /* NUMA计算机和物理地址空间散布着空洞的计算机，需要为每个连续的内存区注册一个bootmem分配器 */
} bootmem_data_t;



extern unsigned long bootmem_bootmap_pages(unsigned long);
extern unsigned long init_bootmem(unsigned long addr, unsigned long memend);
extern void free_bootmem(unsigned long addr, unsigned long size);
extern void *__alloc_bootmem(unsigned long size,
			     unsigned long align,
			     unsigned long goal);
extern void *__alloc_bootmem_nopanic(unsigned long size,
				     unsigned long align,
				     unsigned long goal);
extern void *__alloc_bootmem_low(unsigned long size,
				 unsigned long align,
				 unsigned long goal);
extern void *__alloc_bootmem_low_node(pg_data_t *pgdat,
				      unsigned long size,
				      unsigned long align,
				      unsigned long goal);
extern void *__alloc_bootmem_core(struct bootmem_data *bdata,
				  unsigned long size,
				  unsigned long align,
				  unsigned long goal,
				  unsigned long limit);

#ifndef CONFIG_HAVE_ARCH_BOOTMEM_NODE
extern void reserve_bootmem(unsigned long addr, unsigned long size);
#define alloc_bootmem(x) \
	__alloc_bootmem(x, SMP_CACHE_BYTES, __pa(MAX_DMA_ADDRESS))
#define alloc_bootmem_low(x) \
	__alloc_bootmem_low(x, SMP_CACHE_BYTES, 0)
#define alloc_bootmem_pages(x) \
	__alloc_bootmem(x, PAGE_SIZE, __pa(MAX_DMA_ADDRESS))
#define alloc_bootmem_low_pages(x) \
	__alloc_bootmem_low(x, PAGE_SIZE, 0)
#endif /* !CONFIG_HAVE_ARCH_BOOTMEM_NODE */

extern unsigned long free_all_bootmem(void);
extern unsigned long free_all_bootmem_node(pg_data_t *pgdat);
extern void *__alloc_bootmem_node(pg_data_t *pgdat,
				  unsigned long size,
				  unsigned long align,
				  unsigned long goal);
extern unsigned long init_bootmem_node(pg_data_t *pgdat,
				       unsigned long freepfn,
				       unsigned long startpfn,
				       unsigned long endpfn);
extern void reserve_bootmem_node(pg_data_t *pgdat,
				 unsigned long physaddr,
				 unsigned long size);
extern void free_bootmem_node(pg_data_t *pgdat,
			      unsigned long addr,
			      unsigned long size);

#ifndef CONFIG_HAVE_ARCH_BOOTMEM_NODE
#define alloc_bootmem_node(pgdat, x) \
	__alloc_bootmem_node(pgdat, x, SMP_CACHE_BYTES, __pa(MAX_DMA_ADDRESS))
#define alloc_bootmem_pages_node(pgdat, x) \
	__alloc_bootmem_node(pgdat, x, PAGE_SIZE, __pa(MAX_DMA_ADDRESS))
#define alloc_bootmem_low_pages_node(pgdat, x) \
	__alloc_bootmem_low_node(pgdat, x, PAGE_SIZE, 0)
#endif /* !CONFIG_HAVE_ARCH_BOOTMEM_NODE */

#ifdef CONFIG_HAVE_ARCH_ALLOC_REMAP
extern void *alloc_remap(int nid, unsigned long size);
#else
static inline void *alloc_remap(int nid, unsigned long size)
{
	return NULL;
}
#endif /* CONFIG_HAVE_ARCH_ALLOC_REMAP */

extern unsigned long __meminitdata nr_kernel_pages;
extern unsigned long __meminitdata nr_all_pages;

extern void *alloc_large_system_hash(const char *tablename,
				     unsigned long bucketsize,
				     unsigned long numentries,
				     int scale,
				     int flags,
				     unsigned int *_hash_shift,
				     unsigned int *_hash_mask,
				     unsigned long limit);

#define HASH_EARLY	0x00000001	/* Allocating during early boot? */

/* Only NUMA needs hash distribution.
 * IA64 and x86_64 have sufficient vmalloc space.
 */
#if defined(CONFIG_NUMA) && (defined(CONFIG_IA64) || defined(CONFIG_X86_64))
#define HASHDIST_DEFAULT 1
#else
#define HASHDIST_DEFAULT 0
#endif
extern int hashdist;		/* Distribute hashes across NUMA nodes? */


#endif /* _LINUX_BOOTMEM_H */
