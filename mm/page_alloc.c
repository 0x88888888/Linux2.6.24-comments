/*
 *  linux/mm/page_alloc.c
 *
 *  Manages the free list, the system allocates free pages here.
 *  Note that kmalloc() lives in slab.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  Reshaped it to be a zoned allocator, Ingo Molnar, Red Hat, 1999
 *  Discontiguous memory support, Kanoj Sarcar, SGI, Nov 1999
 *  Zone balancing, Kanoj Sarcar, SGI, Jan 2000
 *  Per cpu hot/cold page lists, bulk allocation, Martin J. Bligh, Sept 2002
 *          (lots of bits borrowed from Ingo Molnar & Andrew Morton)
 */

#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/interrupt.h>
#include <linux/pagemap.h>
#include <linux/bootmem.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/suspend.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/oom.h>
#include <linux/notifier.h>
#include <linux/topology.h>
#include <linux/sysctl.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/memory_hotplug.h>
#include <linux/nodemask.h>
#include <linux/vmalloc.h>
#include <linux/mempolicy.h>
#include <linux/stop_machine.h>
#include <linux/sort.h>
#include <linux/pfn.h>
#include <linux/backing-dev.h>
#include <linux/fault-inject.h>
#include <linux/page-isolation.h>

#include <asm/tlbflush.h>
#include <asm/div64.h>
#include "internal.h"

/*
 * Array of node states.
 */
nodemask_t node_states[NR_NODE_STATES] __read_mostly = {
	[N_POSSIBLE] = NODE_MASK_ALL,
	[N_ONLINE] = { { [0] = 1UL } },
#ifndef CONFIG_NUMA
	[N_NORMAL_MEMORY] = { { [0] = 1UL } },
#ifdef CONFIG_HIGHMEM
	[N_HIGH_MEMORY] = { { [0] = 1UL } },
#endif
	[N_CPU] = { { [0] = 1UL } },
#endif	/* NUMA */
};
EXPORT_SYMBOL(node_states);

unsigned long totalram_pages __read_mostly;
unsigned long totalreserve_pages __read_mostly;
long nr_swap_pages;
int percpu_pagelist_fraction;

#ifdef CONFIG_HUGETLB_PAGE_SIZE_VARIABLE
int pageblock_order __read_mostly;
#endif

static void __free_pages_ok(struct page *page, unsigned int order);

/*
 * results with 256, 32 in the lowmem_reserve sysctl:
 *	1G machine -> (16M dma, 800M-16M normal, 1G-800M high)
 *	1G machine -> (16M dma, 784M normal, 224M high)
 *	NORMAL allocation will leave 784M/256 of ram reserved in the ZONE_DMA
 *	HIGHMEM allocation will leave 224M/32 of ram reserved in ZONE_NORMAL
 *	HIGHMEM allocation will (224M+784M)/256 of ram reserved in ZONE_DMA
 *
 * TBD: should special case ZONE_DMA32 machines here - in those we normally
 * don't need any ZONE_NORMAL reservation
 */
int sysctl_lowmem_reserve_ratio[MAX_NR_ZONES-1] = {
#ifdef CONFIG_ZONE_DMA
	 256,
#endif
#ifdef CONFIG_ZONE_DMA32
	 256,
#endif
#ifdef CONFIG_HIGHMEM
	 32,
#endif
	 32,
};

EXPORT_SYMBOL(totalram_pages);

static char * const zone_names[MAX_NR_ZONES] = {
#ifdef CONFIG_ZONE_DMA
	 "DMA",
#endif
#ifdef CONFIG_ZONE_DMA32
	 "DMA32",
#endif
	 "Normal",
#ifdef CONFIG_HIGHMEM
	 "HighMem",
#endif
	 "Movable",
};

int min_free_kbytes = 1024;

unsigned long __meminitdata nr_kernel_pages;
unsigned long __meminitdata nr_all_pages;
static unsigned long __meminitdata dma_reserve;

#ifdef CONFIG_ARCH_POPULATES_NODE_MAP
  /*
   * MAX_ACTIVE_REGIONS determines the maximum number of distinct
   * ranges of memory (RAM) that may be registered with add_active_range().
   * Ranges passed to add_active_range() will be merged if possible
   * so the number of times add_active_range() can be called is
   * related to the number of nodes and the number of holes
   */
  #ifdef CONFIG_MAX_ACTIVE_REGIONS
    /* Allow an architecture to set MAX_ACTIVE_REGIONS to save memory */
    #define MAX_ACTIVE_REGIONS CONFIG_MAX_ACTIVE_REGIONS
  #else
    #if MAX_NUMNODES >= 32
      /* If there can be many nodes, allow up to 50 holes per node */
      #define MAX_ACTIVE_REGIONS (MAX_NUMNODES*50)
    #else
      /* By default, allow up to 256 distinct regions */
      #define MAX_ACTIVE_REGIONS 256
    #endif
  #endif

  static struct node_active_region __meminitdata early_node_map[MAX_ACTIVE_REGIONS];
  static int __meminitdata nr_nodemap_entries;
  static unsigned long __meminitdata arch_zone_lowest_possible_pfn[MAX_NR_ZONES];
  static unsigned long __meminitdata arch_zone_highest_possible_pfn[MAX_NR_ZONES];
#ifdef CONFIG_MEMORY_HOTPLUG_RESERVE
  static unsigned long __meminitdata node_boundary_start_pfn[MAX_NUMNODES];
  static unsigned long __meminitdata node_boundary_end_pfn[MAX_NUMNODES];
#endif /* CONFIG_MEMORY_HOTPLUG_RESERVE */
  unsigned long __initdata required_kernelcore;
  static unsigned long __initdata required_movablecore;
  unsigned long __meminitdata zone_movable_pfn[MAX_NUMNODES];

  /* movable_zone is the "real" zone pages in ZONE_MOVABLE are taken from */
  int movable_zone;
  EXPORT_SYMBOL(movable_zone);
#endif /* CONFIG_ARCH_POPULATES_NODE_MAP */

#if MAX_NUMNODES > 1
int nr_node_ids __read_mostly = MAX_NUMNODES;
EXPORT_SYMBOL(nr_node_ids);
#endif

int page_group_by_mobility_disabled __read_mostly;

/*
 * 设置page为首的一个内存区的迁移类型
 * __rmqueue_fallback()
 *   set_pageblock_migratetype()
 */
static void set_pageblock_migratetype(struct page *page, int migratetype)
{
	set_pageblock_flags_group(page, (unsigned long)migratetype,
					PB_migrate, PB_migrate_end);
}

#ifdef CONFIG_DEBUG_VM
static int page_outside_zone_boundaries(struct zone *zone, struct page *page)
{
	int ret = 0;
	unsigned seq;
	unsigned long pfn = page_to_pfn(page);

	do {
		seq = zone_span_seqbegin(zone);
		if (pfn >= zone->zone_start_pfn + zone->spanned_pages)
			ret = 1;
		else if (pfn < zone->zone_start_pfn)
			ret = 1;
	} while (zone_span_seqretry(zone, seq));

	return ret;
}

static int page_is_consistent(struct zone *zone, struct page *page)
{
	if (!pfn_valid_within(page_to_pfn(page)))
		return 0;
	if (zone != page_zone(page))
		return 0;

	return 1;
}
/*
 * Temporary debugging check for pages not lying within a given zone.
 */
static int bad_range(struct zone *zone, struct page *page)
{
	if (page_outside_zone_boundaries(zone, page))
		return 1;
	if (!page_is_consistent(zone, page))
		return 1;

	return 0;
}
#else
static inline int bad_range(struct zone *zone, struct page *page)
{
	return 0;
}
#endif

static void bad_page(struct page *page)
{
	printk(KERN_EMERG "Bad page state in process '%s'\n"
		KERN_EMERG "page:%p flags:0x%0*lx mapping:%p mapcount:%d count:%d\n"
		KERN_EMERG "Trying to fix it up, but a reboot is needed\n"
		KERN_EMERG "Backtrace:\n",
		current->comm, page, (int)(2*sizeof(unsigned long)),
		(unsigned long)page->flags, page->mapping,
		page_mapcount(page), page_count(page));
	dump_stack();
	page->flags &= ~(1 << PG_lru	|
			1 << PG_private |
			1 << PG_locked	|
			1 << PG_active	|
			1 << PG_dirty	|
			1 << PG_reclaim |
			1 << PG_slab    |
			1 << PG_swapcache |
			1 << PG_writeback |
			1 << PG_buddy );
	set_page_count(page, 0);
	reset_page_mapcount(page);
	page->mapping = NULL;
	add_taint(TAINT_BAD_PAGE);
}

/*
 * Higher-order pages are called "compound pages".  They are structured thusly:
 *
 * The first PAGE_SIZE page is called the "head page".
 *
 * The remaining PAGE_SIZE pages are called "tail pages".
 *
 * All pages have PG_compound set.  All pages have their ->private pointing at
 * the head page (even the head page has this).
 *
 * The first tail page's ->lru.next holds the address of the compound page's
 * put_page() function.  Its ->lru.prev holds the order of allocation.
 * This usage means that zero-order pages may not be compound.
 */

static void free_compound_page(struct page *page)
{
	__free_pages_ok(page, compound_order(page));
}

/*
 * 复合页，设置复合页标记(PG_compound),
 * 设置页的析构函数(free_compound_page)，
 * 设置复合页的order
 *
 * alloc_pages_node()
 *  __alloc_pages()
 *   get_page_from_freelist()
 *    buffered_rmqueue()
 *     prep_new_page()
 *      prep_compound_page()
 */
static void prep_compound_page(struct page *page, unsigned long order)
{
	int i;
	int nr_pages = 1 << order;

	set_compound_page_dtor(page, free_compound_page);
	set_compound_order(page, order);
	__SetPageHead(page);
	for (i = 1; i < nr_pages; i++) {
		struct page *p = page + i;

		__SetPageTail(p);
		p->first_page = page;
	}
}

static void destroy_compound_page(struct page *page, unsigned long order)
{
	int i;
	int nr_pages = 1 << order;

	if (unlikely(compound_order(page) != order))
		bad_page(page);

	if (unlikely(!PageHead(page)))
			bad_page(page);
	__ClearPageHead(page);
	for (i = 1; i < nr_pages; i++) {
		struct page *p = page + i;

		if (unlikely(!PageTail(p) |
				(p->first_page != page)))
			bad_page(page);
		__ClearPageTail(p);
	}
}

static inline void prep_zero_page(struct page *page, int order, gfp_t gfp_flags)
{
	int i;

	/*
	 * clear_highpage() will use KM_USER0, so it's a bug to use __GFP_ZERO
	 * and __GFP_HIGHMEM from hard or soft interrupt context.
	 */
	VM_BUG_ON((gfp_flags & __GFP_HIGHMEM) && in_interrupt());
	for (i = 0; i < (1 << order); i++)
		clear_highpage(page + i);
}

static inline void set_page_order(struct page *page, int order)
{
	set_page_private(page, order);
	__SetPageBuddy(page);
}

static inline void rmv_page_order(struct page *page)
{
	__ClearPageBuddy(page);
	set_page_private(page, 0);
}

/*
 * Locate the struct page for both the matching buddy in our
 * pair (buddy1) and the combined O(n+1) page they form (page).
 *
 * 1) Any buddy B1 will have an order O twin B2 which satisfies
 * the following equation:
 *     B2 = B1 ^ (1 << O)
 * For example, if the starting buddy (buddy2) is #8 its order
 * 1 buddy is #10:
 *     B2 = 8 ^ (1 << 1) = 8 ^ 2 = 10
 *
 * 2) Any buddy B will have an order O+1 parent P which
 * satisfies the following equation:
 *     P = B & ~(1 << O)
 *
 *
 *   __free_pages()
 *    __free_pages_ok()
 *     free_one_page()
 *      __free_one_page()
 *       __page_find_buddy()
 *
 * Assumption: *_mem_map is contiguous at least up to MAX_ORDER
 * 查找page在order阶情况下对应的buddy
 */
static inline struct page *
__page_find_buddy(struct page *page, unsigned long page_idx, unsigned int order)
{
    /*
     *page_idx号对应buddy的page号
     * 
     * 使用(1<<order) 掩码的异或(XOR)装换page_idx第order位的值.
     * 因此如果这个位原先是0，buddy_idx就等于page_idx + order_size;
     * 相反，如果这个位原先是1，buddy_idx就等于page_idx - order_size
     *
     * 根据这个算法 page_idx = 2, order =0 时， buddy_idx = 2 ^ (1 << 0) = 3
     */
	unsigned long buddy_idx = page_idx ^ (1 << order);

    /*
     * buddy_idx - page_idx 为 伙伴和当前page号的距离值(可能为负值)
     * page + 这个距离值,得到的是伙伴部分的起始页号
     *
     * 由于buddy_idx-page_idx的值可能为正也可能为负，因此伙伴页框块可能在当前页框块之前，也可能在其之后
     */
	return page + (buddy_idx - page_idx);
}

/*
 *	__free_pages()
 *	 __free_pages_ok()
 *	  free_one_page()
 *	   __free_one_page()
 *      __find_combined_index()
 */
static inline unsigned long
__find_combined_index(unsigned long page_idx, unsigned int order)
{
    /* 与buddy合并之后,起始页的page号 */
	return (page_idx & ~(1 << order));
}

/*
 * This function checks whether a page is free && is the buddy
 * we can do coalesce a page and its buddy if
 * (a) the buddy is not in a hole &&
 * (b) the buddy is in the buddy system &&
 * (c) a page and its buddy have the same order &&
 * (d) a page and its buddy are in the same zone.
 *
 * For recording whether a page is in the buddy system, we use PG_buddy.
 * Setting, clearing, and testing PG_buddy is serialized by zone->lock.
 *
 * For recording page's order, we use page_private(page).
 */
static inline int page_is_buddy(struct page *page, struct page *buddy,
								int order)
{
	if (!pfn_valid_within(page_to_pfn(buddy)))
		return 0;

	/* 不在一个zone中的，不算buddy */
	if (page_zone_id(page) != page_zone_id(buddy))
		return 0;
    
	if (PageBuddy(buddy) && page_order(buddy) == order) {
	    /*  合并条件满足*/	
		BUG_ON(page_count(buddy) != 0);
		return 1;
	}
	return 0;
}

/*
 * Freeing function for a buddy system allocator.
 *
 * The concept of a buddy system is to maintain direct-mapped table
 * (containing bit values) for memory blocks of various "orders".
 * The bottom level table contains the map for the smallest allocatable
 * units of memory (here, pages), and each level above it describes
 * pairs of units from the levels below, hence, "buddies".
 * At a high level, all that happens here is marking the table entry
 * at the bottom level available, and propagating the changes upward
 * as necessary, plus some accounting needed to play nicely with other
 * parts of the VM system.
 * At each level, we keep a list of pages, which are heads of continuous
 * free pages of length of (1 << order) and marked with PG_buddy. Page's
 * order is recorded in page_private(page) field.
 * So when we are allocating or freeing one, we can derive the state of the
 * other.  That is, if we allocate a small block, and both were   
 * free, the remainder of the region must be split into blocks.   
 * If a block is freed, and its buddy is also free, then this
 * triggers coalescing into a block of larger size.            
 *
 * -- wli
 *
 *
 * start_kernel()
 *  mem_init()
 *   free_all_bootmem()
 *    free_all_bootmem_core()
 *     __free_pages_bootmem()
 *      __free_pages()
 *       __free_pages_ok()
 *        free_one_page()
 *         __free_one_page()
 *
 *
 * free_hot_cold_page()
 *  free_pages_bulk()
 *   __free_one_page()
 *
 * alloc_pages_node()
 *  __alloc_pages()
 *   drain_all_local_pages()
 *    __drain_pages()
 *     free_pages_bulk()
 *      __free_one_page()
 *
 * 在free的时候，没有修改migrate type啊
 * 即使buddy合并，也没有修改migrate type,只是从order A 对应的migrate type中移动到 order B对应的migrate type列表中
 */

static inline void __free_one_page(struct page *page,
		struct zone *zone, unsigned int order)
{

	unsigned long page_idx;   // 要释放页对应的页号
	int order_size = 1 << order;
	/*
     * 得到zone->free_area.free_list[]的索引
	 */
	int migratetype = get_pageblock_migratetype(page);

	/* 如果是复合页，需要析构 */
	if (unlikely(PageCompound(page)))
		destroy_compound_page(page, order);

    /* 得到要释放页对应的页号 */
	page_idx = page_to_pfn(page) & ((1 << MAX_ORDER) - 1);

	VM_BUG_ON(page_idx & (order_size - 1));
	VM_BUG_ON(bad_range(zone, page));

    /* 统计zone中的    freepages  信息 */
	__mod_zone_page_state(zone, NR_FREE_PAGES, order_size);
	
	while (order < MAX_ORDER-1) {
		unsigned long combined_idx;
		struct page *buddy;

		/* 查找page在order阶情况下对应的buddy */
		buddy = __page_find_buddy(page, page_idx, order);
		if (!page_is_buddy(page, buddy, order))
			break;		/* Move the buddy up one level. */

		list_del(&buddy->lru);
		zone->free_area[order].nr_free--;
		rmv_page_order(buddy);/* 消除buddy->flags 的PG_buddy标记 */
		/* 计算合并后的page的索引 */
		combined_idx = __find_combined_index(page_idx, order);
		
		/* 下个循环重新开始的page位置 */
		page = page + (combined_idx - page_idx);
		page_idx = combined_idx;
		
		order++;
	}

	/* 设置page->private= order,
	 *  page->flags = PG_buddy
	 */
	set_page_order(page, order);
	/* 放回到相应的zone的相应的free_area中相同的migratetype中去 */
	list_add(&page->lru,
		&zone->free_area[order].free_list[migratetype]);
	zone->free_area[order].nr_free++;
}

static inline int free_pages_check(struct page *page)
{
	if (unlikely(page_mapcount(page) |
		(page->mapping != NULL)  |
		(page_count(page) != 0)  |
		(page->flags & (
			1 << PG_lru	|
			1 << PG_private |
			1 << PG_locked	|
			1 << PG_active	|
			1 << PG_slab	|
			1 << PG_swapcache |
			1 << PG_writeback |
			1 << PG_reserved |
			1 << PG_buddy ))))
		bad_page(page);
	if (PageDirty(page))
		__ClearPageDirty(page);
	/*
	 * For now, we report if PG_reserved was found set, but do not
	 * clear it, and do not free the page.  But we shall soon need
	 * to do more, for when the ZERO_PAGE count wraps negative.
	 */
	return PageReserved(page);
}

/*
 * Frees a list of pages. 
 * Assumes all pages on list are in same zone, and of same order.
 * count is the number of pages to free.
 *
 * If the zone was previously in an "all pages pinned" state then look to
 * see if this freeing clears that state.
 *
 * And clear the zone's pages_scanned counter, to hold off the "all pages are
 * pinned" detection logic.
 *
 * free_hot_cold_page()
 *  free_pages_bulk()
 *
 * alloc_pages_node()
 *  __alloc_pages()
 *   drain_all_local_pages()
 *    __drain_pages()
 *     free_pages_bulk()
 */
static void free_pages_bulk(struct zone *zone, int count,
					struct list_head *list, int order)
{
	spin_lock(&zone->lock);
	zone_clear_flag(zone, ZONE_ALL_UNRECLAIMABLE);
	zone->pages_scanned = 0;
	while (count--) {
		struct page *page;

		VM_BUG_ON(list_empty(list));
		page = list_entry(list->prev, struct page, lru);
		/* have to delete it as __free_one_page list manipulates */
		list_del(&page->lru);
		__free_one_page(page, zone, order);
	}
	spin_unlock(&zone->lock);
}

/*
 * start_kernel()
 *  mem_init()
 *   free_all_bootmem()
 *    free_all_bootmem_core()
 *     __free_pages_bootmem()
 *      __free_pages()
 *       __free_pages_ok()
 *        free_one_page()
 *
 * start_kernel()
 *  mem_init()
 *	 free_all_bootmem()
 *    free_all_bootmem_core()
 *     __free_pages_bootmem()
 *      __free_pages()
 *       __free_pages_ok()
 *        free_one_page()
 */
static void free_one_page(struct zone *zone, struct page *page, int order)
{
	spin_lock(&zone->lock);
	zone_clear_flag(zone, ZONE_ALL_UNRECLAIMABLE);
	zone->pages_scanned = 0;
	/* 释放page */
	__free_one_page(page, zone, order);
	spin_unlock(&zone->lock);
}

/* 
 *
 * start_kernel()
 *  mem_init()
 *	 free_all_bootmem()
 *    free_all_bootmem_core()
 *     __free_pages_bootmem()
 *      __free_pages()
 *       __free_pages_ok()
 *
 * cpucache_init()
 *  start_cpu_timer()
 *   ......
 *    cache_reap()
 *     drain_freelist()
 *      slab_destroy()
 *       kmem_freepages()
 *        free_pages()
 *         __free_pages()
 *          __free_pages_ok()
 */
static void __free_pages_ok(struct page *page, unsigned int order)
{
	unsigned long flags;
	int i;
	int reserved = 0;

	for (i = 0 ; i < (1 << order) ; ++i)
		reserved += free_pages_check(page + i);
	
	if (reserved)
		return;

	if (!PageHighMem(page))
		debug_check_no_locks_freed(page_address(page),PAGE_SIZE<<order);
	
	arch_free_page(page, order);
	/* 修改对应的pte为0 */
	kernel_map_pages(page, 1 << order, 0);

	local_irq_save(flags);
	__count_vm_events(PGFREE, 1 << order);

	/* 释放单页，也释放复合页 */
	free_one_page(page_zone(page), page, order);
	local_irq_restore(flags);
}

/*
 * permit the bootmem allocator to evade page validation on high-order frees
 * 释放一个页面
 * start_kernel()
 *  mem_init()
 *	 free_all_bootmem()
 *    free_all_bootmem_core()
 *     __free_pages_bootmem()
 */
void fastcall __init __free_pages_bootmem(struct page *page, unsigned int order)
{
	if (order == 0) {
		__ClearPageReserved(page);
		set_page_count(page, 0);
		set_page_refcounted(page);
		__free_page(page);
	} else {
		int loop;

		prefetchw(page);
		for (loop = 0; loop < BITS_PER_LONG; loop++) {
			struct page *p = &page[loop];

			if (loop + 1 < BITS_PER_LONG)
				prefetchw(p + 1);
			__ClearPageReserved(p);
			set_page_count(p, 0);
		}

		set_page_refcounted(page);
		__free_pages(page, order);
	}
}


/*
 * The order of subdivision here is critical for the IO subsystem.
 * Please do not alter this order without good reasons and regression
 * testing. Specifically, as large blocks of memory are subdivided,
 * the order in which smaller blocks are delivered depends on the order
 * they're subdivided in this function. This is the primary factor
 * influencing the order in which pages are delivered to the IO
 * subsystem according to empirical testing, and this is also justified
 * by considering the behavior of a buddy system containing a single
 * large block of memory acted on by a series of small allocations.
 * This behavior is a critical factor in sglist merging's success.
 *
 * -- wli
 *
 *
 * buddy system 用
 * 如果要求分配的内存块长度小于所选择的内存块长度，
   那是因为没有更小的适当内存块可用，
   因而会从较高order的分配内存块，此时系统需要把选择的内存块分割成小块，
   只保留申请大小的内存块，而把后面的内存块返回给buddy系统。
   expand函数正是完成此功能的 
 *
 * alloc_pages_node()
 *  __alloc_pages()
 *   get_page_from_freelist()
 *    buffered_rmqueue()
 *     rmqueue_bulk()
 *      __rmqueue()
 *       __rmqueue_smallest()
 *        expand()
 */
static inline void expand(struct zone *zone, struct page *page,
	int low /*预期分配的阶*/ , int high /* 实际从哪个阶分配的 */ , 
	struct free_area *area,
	int migratetype)
{
	unsigned long size = 1 << high;

	while (high > low) {
		area--; //order下降之后对应的area
		high--; //order 下降
		size >>= 1;
		VM_BUG_ON(bad_range(zone, &page[size]));
		/* 插入到第阶的链表中去 */
		list_add(&page[size].lru, &area->free_list[migratetype]);
		area->nr_free++;
		set_page_order(&page[size], high);/* 设置page->private,page->flags */
	}
}

/*
 * This page is about to be returned from the page allocator
 *
 * alloc_pages_node()
 *  __alloc_pages()
 *   get_page_from_freelist()
 *    buffered_rmqueue()
 *     prep_new_page()
 */
static int prep_new_page(struct page *page, int order, gfp_t gfp_flags)
{
	if (unlikely(page_mapcount(page) |
		(page->mapping != NULL)  |
		(page_count(page) != 0)  |
		(page->flags & (
			1 << PG_lru	|
			1 << PG_private	|
			1 << PG_locked	|
			1 << PG_active	|
			1 << PG_dirty	|
			1 << PG_slab    |
			1 << PG_swapcache |
			1 << PG_writeback |
			1 << PG_reserved |
			1 << PG_buddy ))))
		bad_page(page);

	/*
	 * For now, we report if PG_reserved was found set, but do not
	 * clear it, and do not allocate the page: as a safety net.
	 */
	if (PageReserved(page))
		return 1;

	page->flags &= ~(1 << PG_uptodate | 1 << PG_error | 1 << PG_readahead |
			1 << PG_referenced | 1 << PG_arch_1 |
			1 << PG_owner_priv_1 | 1 << PG_mappedtodisk);
	set_page_private(page, 0);
	set_page_refcounted(page);

	arch_alloc_page(page, order);
	kernel_map_pages(page, 1 << order, 1);

    /* 清空页内遗留的数据 */
	if (gfp_flags & __GFP_ZERO)
		prep_zero_page(page, order, gfp_flags);

    /*复合页，设置复合页标记(PG_compound),设置页的析构函数(free_compound_page)，设置复合页的order*/
	if (order && (gfp_flags & __GFP_COMP))
		prep_compound_page(page, order);  

	return 0;
}

/*
 * 
 * Go through the free lists for the given migratetype and remove
 * the smallest available page from the freelists
 *  首先从满足条件的order开始，找到满足条件的空闲页，
 *  函数名字中的smallest表示：
 *      获得的空闲页表项应该是满足条件空闲表项中最小的
 *
 * alloc_pages_node()
 *  __alloc_pages()
 *   get_page_from_freelist()
 *    buffered_rmqueue()
 *     rmqueue_bulk()
 *      __rmqueue()
 *       __rmqueue_smallest()
 */
static struct page *__rmqueue_smallest(struct zone *zone, unsigned int order,
						int migratetype)
{
	unsigned int current_order;
	/* free_area有free_area[MIGRATE_UNMOVABLE],
	              free_area[MIGRATE_RECLAIMABLE],
                  free_area[MIGRATE_MOVABLE],
                  free_area[MIGRATE_RESERVE],
                  free_area[MIGRATE_ISOLATE] 数组元素,
                  migratetype对应这些类型*/
	struct free_area * area;
	struct page *page;

	/*
	 * Find a page of the appropriate size in the preferred list 
     * 在首选的列表中找到适当大小的页
	 */
	for (current_order = order; current_order < MAX_ORDER; ++current_order) {
		
		area = &(zone->free_area[current_order]);
		/* 首先这个项要满足迁移类型，buddy系统把不同迁移类型的内存块放在不同的链表中，迁移类型包括 MOVABLE UNMOVABLE和RECLAIMABLE */
		if (list_empty(&area->free_list[migratetype]))
			continue;

		/* 把内存块从free_list中删除，做一些善后处理 */
		page = list_entry(area->free_list[migratetype].next,
							struct page, lru);
		list_del(&page->lru);
		rmv_page_order(page);/* 删除PG_buddy标记,page->private=0 */
		area->nr_free--;

		/*
		 * 更新当前zone的统计量
		 */
		__mod_zone_page_state(zone, NR_FREE_PAGES, - (1UL << order));

		/*  如果要求分配的内存块长度小于所选择的内存块长度，
		    那是因为没有更小的适当内存块可用，
		    因而会从较高order的分配内存块，此时系统需要把选择的内存块分割成小块，
		    只保留申请大小的内存块，而把后面的内存块返回给buddy系统。
		    expand函数正是完成此功能的 
		 */
		expand(zone, page, order, current_order, area, migratetype);
		return page;
	}

	return NULL;
}


/*
 * This array describes the order lists are fallen back to when
 * the free lists for the desirable migrate type are depleted
 */
static int fallbacks[MIGRATE_TYPES][MIGRATE_TYPES-1] = {
	[MIGRATE_UNMOVABLE]   = { MIGRATE_RECLAIMABLE, MIGRATE_MOVABLE,   MIGRATE_RESERVE },
	[MIGRATE_RECLAIMABLE] = { MIGRATE_UNMOVABLE,   MIGRATE_MOVABLE,   MIGRATE_RESERVE },
	[MIGRATE_MOVABLE]     = { MIGRATE_RECLAIMABLE, MIGRATE_UNMOVABLE, MIGRATE_RESERVE },
	[MIGRATE_RESERVE]     = { MIGRATE_RESERVE,     MIGRATE_RESERVE,   MIGRATE_RESERVE }, /* Never used */
};

/*
 * Move the free pages in a range to the free lists of the requested type.
 * Note that start_page and end_pages are not aligned on a pageblock
 * boundary. If alignment is required, use move_freepages_block()
 *
 * alloc_pages_node()
 *  __alloc_pages()
 *   get_page_from_freelist()
 *    buffered_rmqueue()
 *     rmqueue_bulk()
 *      __rmqueue()
 *       __rmqueue_fallback()
 *        move_freepages_block()
 *         move_freepages()
 *
 * 返回值为migratetype被修改过的page数量
 */
int move_freepages(struct zone *zone,
			struct page *start_page, struct page *end_page,
			int migratetype)
{
	struct page *page;
	unsigned long order;
	int pages_moved = 0;

#ifndef CONFIG_HOLES_IN_ZONE
	/*
	 * page_zone is not safe to call in this context when
	 * CONFIG_HOLES_IN_ZONE is set. This bug check is probably redundant
	 * anyway as we check zone boundaries in move_freepages_block().
	 * Remove at a later date when no bug reports exist related to
	 * grouping pages by mobility
	 */
	BUG_ON(page_zone(start_page) != page_zone(end_page));
#endif

	for (page = start_page; page <= end_page;) {
		if (!pfn_valid_within(page_to_pfn(page))) {
			page++;
			continue;
		}

		if (!PageBuddy(page)) {
			page++;
			continue;
		}

		order = page_order(page);//返回page->private值
		list_del(&page->lru);
		/* 加入到相应的migrate type链表中中去 */
		list_add(&page->lru,
			&zone->free_area[order].free_list[migratetype]);
		/* 跳过2^order个page */
		page += 1 << order;
		/* migrate type修该过的page数量 */
		pages_moved += 1 << order;
	}

	return pages_moved;
}

/*
 * alloc_pages_node()
 *  __alloc_pages()
 *   get_page_from_freelist()
 *    buffered_rmqueue()
 *     rmqueue_bulk()
 *      __rmqueue()
 *       __rmqueue_fallback()
 *        move_freepages_block()
 *
 * 负责对一个给定page，按照pageblock size对齐，移动到新的迁移类型的free_list中，order不变
 * 以整个pageblock为单位迁移的
 */
int move_freepages_block(struct zone *zone, struct page *page, int migratetype)
{
	unsigned long start_pfn, end_pfn;
	struct page *start_page, *end_page;

    /* 起始，结束页框调整为pageblock_nr_pages对齐 */
	start_pfn = page_to_pfn(page);
	/* page所在pageblock起始的page    的pfn */
	start_pfn = start_pfn & ~(pageblock_nr_pages-1);
	start_page = pfn_to_page(start_pfn);
	/* page所在pageblock结束的page    的pfn */
	end_page = start_page + pageblock_nr_pages - 1;
	end_pfn = start_pfn + pageblock_nr_pages - 1;
    /* 下面的move_freepages以整个pageblock 开始migrate的 */
	/* Do not cross zone boundaries */
	/* 检查开始页框和结束页框是否都处于zone中，如果不属于，则用page作为开始页框 */
	if (start_pfn < zone->zone_start_pfn)
		start_page = page;
	if (end_pfn >= zone->zone_start_pfn + zone->spanned_pages)
		return 0;

    /* 将这个pageblock内的free page从旧迁移类型移动到新的类型链表free_list中，order不变，正在使用的页会被跳过 */
	return move_freepages(zone, start_page, end_page, migratetype);
}

/* 
 * Remove an element from the buddy allocator from the fallback list 
 *
 * alloc_pages_node()
 *  __alloc_pages()
 *   get_page_from_freelist()
 *    buffered_rmqueue()
 *     rmqueue_bulk()
 *      __rmqueue()
 *       __rmqueue_fallback()
 *
 *
 int fallbacks[MIGRATE_TYPES][MIGRATE_TYPES-1] = {
    [MIGRATE_UNMOVABLE] = { MIGRATE_RECLAIMABLE, MIGRATE_MOVABLE,   MIGRATE_RESERVE },
    [MIGRATE_RECLAIMABLE] = { MIGRATE_UNMOVABLE, MIGRATE_MOVABLE,   MIGRATE_RESERVE },
    [MIGRATE_MOVABLE] = { MIGRATE_RECLAIMABLE, MIGRATE_UNMOVABLE, MIGRATE_RESERVE },
    [MIGRATE_RESERVE] = { MIGRATE_RESERVE, MIGRATE_RESERVE,   MIGRATE_RESERVE },
  };
  当从其它链表迁移时，按照order从大到小的顺序选择被迁移的链表;
    如果一次性迁移的链表上的页数目太多（不小于一个页块的页数的一半)时，
    将会把迁移出的链表放在相应类型的其它order链表上，并且将页块属性修
    该成相应的MIGRATE类型;
    
    而后又将取出的链从相应的MIGRATE类型链表上取下，并按照buddy system要求，
    将链表上的页按照order大小依次放到小于所取下order的同类型的链表上.
  
    比如：在系统初始化过程中，所有order的MIGRATE_UNMOVABLE类型链表都为空，
         那么将从order = 10的MIGRATE_MOVABLE类型链表上取下一个buddy，
         并一次下放到order = [9..0]的MIGARTE_UNMOVABLE类型链表上，
         可以看出只下放了1023个页，因为传入的参数order = 0，正好请求1页，
         故，多出的1页将不会再在伙伴系统的链表中，而是交由slab来管理.
 */
static struct page *__rmqueue_fallback(struct zone *zone, int order,
						int start_migratetype)
{
	struct free_area * area;
	int current_order;
	struct page *page;
	int migratetype, i;

	/* Find the largest possible block of pages in the other list 
	 * 尽量一次性拨出尽可能多的内存页面给“该”start_migratetype的free_area链表
	 */
	for (current_order = MAX_ORDER-1; current_order >= order;
						--current_order) {
							/* 各个 migrate type */
		for (i = 0; i < MIGRATE_TYPES - 1; i++) {
			/* 后备migratetype */
			migratetype = fallbacks[start_migratetype][i];

			/* MIGRATE_RESERVE handled later if necessary 
               并不会尝试使用紧急分配的块，因为我们认为为紧急分配预留的块更重要，所以万不得以才分配
		     */
			if (migratetype == MIGRATE_RESERVE)
				continue;
      
			area = &(zone->free_area[current_order]);
			if (list_empty(&area->free_list[migratetype]))
				continue;  //对应的migrate type 没有空闲的page可供分配

            //到这里说明在相应的 migrate type中有足够的page可供分配了
			
            /* 对应的page头 */
			page = list_entry(area->free_list[migratetype].next,
					struct page, lru);
			area->nr_free--;

			/*
			 * If breaking a large block of pages, move all free
			 * pages to the preferred allocation list. If falling
			 * back for a reclaimable kernel allocation, be more
			 * agressive about taking ownership of free pages
			 * 如果分解一个大内存块，则将所有空闲页移动到优先选用的分配列表
			 * 如果内核在备用列表中分配可回收内存块，则会更为积极的取得空闲页的所有权
			 */
			if (unlikely(current_order >= (pageblock_order >> 1)) ||
					start_migratetype == MIGRATE_RECLAIMABLE) {

				unsigned long pages;
				/* 
				 * 修改page对应的migratetype,order不变
				 * 即将page加入到到对应的zone->free_area[order].free_list[migratetype]
				 */
				pages = move_freepages_block(zone, page,
								start_migratetype);

				/* Claim the whole block if over half of it is free
                 * 如果大内存块超过一半是空闲的，则修改page对应的pageblock的migratetype
				 */
				if (pages >= (1 << (pageblock_order-1)))
					set_pageblock_migratetype(page,
								start_migratetype);


			    /* 拆分过pageblock,要将剩余的page也移动到start_migratetype */
				migratetype = start_migratetype;
			}

			/* Remove the page from the freelists */
			list_del(&page->lru);
			rmv_page_order(page); //不在属于buddy systemm了，也清空migrate type信息
			__mod_zone_page_state(zone, NR_FREE_PAGES,
							-(1UL << order));
            /* huge page,修改migrate type */
			if (current_order == pageblock_order)
				set_pageblock_migratetype(page,
							start_migratetype);

			/*
			 * 将除去本次自己要用的page[order]之外的其它页面全部补充进该area的migratetype空闲链表
			 * 
			 */
			expand(zone, page, order, current_order, area, migratetype);
			return page;
		}
	}

	/* 
	 *  Use MIGRATE_RESERVE rather than fail an allocation 
     *  一切都失败后，从紧急分配的预留链表进行分配
	 */
	return __rmqueue_smallest(zone, order, MIGRATE_RESERVE);
}

/*
 * Do the hard work of removing an element from the buddy allocator.
 * Call me with the zone->lock already held.
 *
 * buddy allocator从zone中分配page
 *
 * alloc_pages_node()
 *  __alloc_pages()
 *   get_page_from_freelist()
 *    buffered_rmqueue()
 *     rmqueue_bulk()
 *      __rmqueue()
 */
static struct page *__rmqueue(struct zone *zone, unsigned int order,
						int migratetype)
{
	struct page *page;

	/*
	 * 从本migratetype对应的zone->free_area[i].free_list[migratetype]中得到page
	 */
	page = __rmqueue_smallest(zone, order, migratetype);

	if (unlikely(!page)) /* 如果__rmqueue_smallest失败，那么就调用__rmqueue_fallback尝试从其他migratetype的链表分配 */
		page = __rmqueue_fallback(zone, order, migratetype);

	return page;
}

/* 
 * Obtain a specified number of elements from the buddy allocator, all under
 * a single hold of the lock, for efficiency.  Add them to the supplied list.
 * Returns the number of new pages which were placed at *list.
 *
 * alloc_pages_node()
 *  __alloc_pages()
 *   get_page_from_freelist()
 *    buffered_rmqueue()
 *     rmqueue_bulk()
 */
static int rmqueue_bulk(struct zone *zone, unsigned int order, 
			unsigned long count, struct list_head *list,
			int migratetype)
{
	int i;
	
	spin_lock(&zone->lock);
	for (i = 0; i < count; ++i) {
		struct page *page = __rmqueue(zone, order, migratetype);
		if (unlikely(page == NULL))
			break;

		/*
		 * Split buddy pages returned by expand() are received here
		 * in physical page order. The page is added to the callers and
		 * list and the list head then moves forward. From the callers
		 * perspective, the linked list is ordered by page number in
		 * some conditions. This is useful for IO devices that can
		 * merge IO requests if the physical pages are ordered
		 * properly.
		 */
		list_add(&page->lru, list);
		set_page_private(page, migratetype);
		list = &page->lru;
	}
	spin_unlock(&zone->lock);
	return i;
}

#ifdef CONFIG_NUMA
/*
 * Called from the vmstat counter updater to drain pagesets of this
 * currently executing processor on remote nodes after they have
 * expired.
 *
 * Note that this function must be called with the thread pinned to
 * a single processor.
 */
void drain_zone_pages(struct zone *zone, struct per_cpu_pages *pcp)
{
	unsigned long flags;
	int to_drain;

	local_irq_save(flags);
	if (pcp->count >= pcp->batch)
		to_drain = pcp->batch;
	else
		to_drain = pcp->count;
	free_pages_bulk(zone, to_drain, &pcp->list, 0);
	pcp->count -= to_drain;
	local_irq_restore(flags);
}
#endif

/*
 * 释放zone->pcp[]中的page
 *
 * alloc_pages_node()
 *  __alloc_pages()
 *   drain_all_local_pages()
 *    __drain_pages()
 */
static void __drain_pages(unsigned int cpu)
{
	unsigned long flags;
	struct zone *zone;
	int i;

	for_each_zone(zone) {
		struct per_cpu_pageset *pset;

		if (!populated_zone(zone))
			continue;

		pset = zone_pcp(zone, cpu);
		for (i = 0; i < ARRAY_SIZE(pset->pcp); i++) {
			struct per_cpu_pages *pcp;

			pcp = &pset->pcp[i];
			local_irq_save(flags);
			// 释放zone->pcp[]中的page
			free_pages_bulk(zone, pcp->count, &pcp->list, 0);
			pcp->count = 0;
			local_irq_restore(flags);
		}
	}
}

#ifdef CONFIG_HIBERNATION

void mark_free_pages(struct zone *zone)
{
	unsigned long pfn, max_zone_pfn;
	unsigned long flags;
	int order, t;
	struct list_head *curr;

	if (!zone->spanned_pages)
		return;

	spin_lock_irqsave(&zone->lock, flags);

	max_zone_pfn = zone->zone_start_pfn + zone->spanned_pages;
	for (pfn = zone->zone_start_pfn; pfn < max_zone_pfn; pfn++)
		if (pfn_valid(pfn)) {
			struct page *page = pfn_to_page(pfn);

			if (!swsusp_page_is_forbidden(page))
				swsusp_unset_page_free(page);
		}

	for_each_migratetype_order(order, t) {
		list_for_each(curr, &zone->free_area[order].free_list[t]) {
			unsigned long i;

			pfn = page_to_pfn(list_entry(curr, struct page, lru));
			for (i = 0; i < (1UL << order); i++)
				swsusp_set_page_free(pfn_to_page(pfn + i));
		}
	}
	spin_unlock_irqrestore(&zone->lock, flags);
}
#endif /* CONFIG_PM */

/*
 * Spill all of this CPU's per-cpu pages back into the buddy allocator.
 *
 * alloc_pages_node()
 *  __alloc_pages()
 *   drain_all_local_pages()
 *    smp_drain_local_pages()
 *     drain_local_pages()
 */
void drain_local_pages(void)
{
	unsigned long flags;

	local_irq_save(flags);	
	__drain_pages(smp_processor_id());
	local_irq_restore(flags);	
}

/*
 * alloc_pages_node()
 *  __alloc_pages()
 *   drain_all_local_pages()
 *    smp_drain_local_pages()
 */
void smp_drain_local_pages(void *arg)
{
	drain_local_pages();
}

/*
 * Spill all the per-cpu pages from all CPUs back into the buddy allocator
 *
 * 释放zone->pcp[]中的page
 *
 * alloc_pages_node()
 *  __alloc_pages()
 *   drain_all_local_pages()
 */
void drain_all_local_pages(void)
{
	unsigned long flags;

	local_irq_save(flags);
	__drain_pages(smp_processor_id());
	local_irq_restore(flags);

	smp_call_function(smp_drain_local_pages, NULL, 0, 1);
}

/*
 * Free a 0-order page
 * 
 * free_hot_page()
 *  free_hot_cold_page()
 * 
 * free_cold_page()
 *  free_hot_cold_page()
 *
 */
static void fastcall free_hot_cold_page(struct page *page, int cold)
{
	struct zone *zone = page_zone(page);
	struct per_cpu_pages *pcp;
	unsigned long flags;

	if (PageAnon(page))
		page->mapping = NULL;
	if (free_pages_check(page))
		return;

	if (!PageHighMem(page))
		debug_check_no_locks_freed(page_address(page), PAGE_SIZE);
	arch_free_page(page, 0);
	kernel_map_pages(page, 1, 0);

	pcp = &zone_pcp(zone, get_cpu())->pcp[cold];
	local_irq_save(flags);
	__count_vm_event(PGFREE); 

	//将page加到zone->pcp[]中去
	list_add(&page->lru, &pcp->list);
	
	/* 设置迁移类型       migrate type  */
	set_page_private(page, get_pageblock_migratetype(page));
	pcp->count++;
	if (pcp->count >= pcp->high) {
		/* 超出限制了，归还一批给buddy system */
		free_pages_bulk(zone, pcp->batch, &pcp->list, 0);
		pcp->count -= pcp->batch;
	}
	local_irq_restore(flags);
	put_cpu();
}

void fastcall free_hot_page(struct page *page)
{
	free_hot_cold_page(page, 0);
}
	
void fastcall free_cold_page(struct page *page)
{
	free_hot_cold_page(page, 1);
}

/*
 * split_page takes a non-compound higher-order page, and splits it into
 * n (1<<order) sub-pages: page[0..n]
 * Each sub-page must be freed individually.
 *
 * Note: this is probably too low level an operation for use in drivers.
 * Please consult with lkml before using this in your driver.
 */
void split_page(struct page *page, unsigned int order)
{
	int i;

	VM_BUG_ON(PageCompound(page));
	VM_BUG_ON(!page_count(page));
	for (i = 1; i < (1 << order); i++)
		set_page_refcounted(page + i);
}

/*
 * 
 * Really, prep_compound_page() should be called from __rmqueue_bulk().  But
 * we cheat by calling it from here, in the order > 0 path.  Saves a branch
 * or two.
 *
 * alloc_pages_node()
 *  __alloc_pages()
 *   get_page_from_freelist()
 *    buffered_rmqueue()
 */
static struct page *buffered_rmqueue(struct zonelist *zonelist,
			struct zone *zone, int order, gfp_t gfp_flags)
{
	unsigned long flags;
	struct page *page;
	int cold = !!(gfp_flags & __GFP_COLD);
	int cpu;
	/*
     * 得到在zone->free_list.free_area[]中的索引
	 */
	int migratetype = allocflags_to_migratetype(gfp_flags);

again:
	cpu  = get_cpu();
	if (likely(order == 0)) {
		/* 如果只分配一个页，就从 zone->pageset[]中分配了  */
		struct per_cpu_pages *pcp;

		pcp = &zone_pcp(zone, cpu)->pcp[cold];
		local_irq_save(flags);
		if (!pcp->count) {
			
			/* 
			 * 如果zone->pageset[]中没有可以被分配的空闲页
             * 调用rmqueue_bulk填充之
			 */
			pcp->count = rmqueue_bulk(zone, 0,
					pcp->batch, &pcp->list, migratetype);
			if (unlikely(!pcp->count))
				goto failed;
		}

		/* Find a page of the appropriate migrate type */
		list_for_each_entry(page, &pcp->list, lru)
			if (page_private(page) == migratetype) /* 查找适当migrate type的页 */
				break;

		/* Allocate more to the pcp list if necessary */
		if (unlikely(&page->lru == &pcp->list)) {
			/* zone->pageset[]增加几个页，供以后分配用 */
			pcp->count += rmqueue_bulk(zone, 0,
					pcp->batch, &pcp->list, migratetype);
			page = list_entry(pcp->list.next, struct page, lru);
		}

		/* 分配到的页，脱离链表 */
		list_del(&page->lru);
		pcp->count--;
	} else {
		/* 如果需要分配更多的页 */
		spin_lock_irqsave(&zone->lock, flags);
		page = __rmqueue(zone, order, migratetype);
		spin_unlock(&zone->lock);
		if (!page)
			goto failed;
	}

	__count_zone_vm_events(PGALLOC, zone, 1 << order);
	zone_statistics(zonelist, zone);
	local_irq_restore(flags);
	put_cpu();

	VM_BUG_ON(bad_range(zone, page));

	/* 重新设置页的flags, private,count之类的准备工作 */
	if (prep_new_page(page, order, gfp_flags))
		goto again;
	return page;

failed:
	local_irq_restore(flags);
	put_cpu();
	return NULL;
}


/* __alloc_pages中使用下面的这些宏 */
#define ALLOC_NO_WATERMARKS	0x01 /* 完全不检查水印， don't check watermarks at all */
#define ALLOC_WMARK_MIN		0x02 /* 在zone包含个zone->pages_min时可以分配页, use pages_min watermark */
#define ALLOC_WMARK_LOW		0x04 /* 在zone包含个zone->pages_low时可以分配页, use pages_low watermark */
#define ALLOC_WMARK_HIGH	0x08 /* 只有在zone包含个zone->pages_high空闲页面时才分配页,use pages_high watermark */
#define ALLOC_HARDER		0x10 /* 通知buddy allocator放宽限制分配限制,   try to alloc harder */
#define ALLOC_HIGH		0x20 /* 进一步放宽限制 __GFP_HIGH set */
#define ALLOC_CPUSET		0x40 /* 只能从当前进程允许运行相关联的cpu的内存节点中分配, check for correct cpuset */

#ifdef CONFIG_FAIL_PAGE_ALLOC

static struct fail_page_alloc_attr {
	struct fault_attr attr;

	u32 ignore_gfp_highmem;
	u32 ignore_gfp_wait;
	u32 min_order;

#ifdef CONFIG_FAULT_INJECTION_DEBUG_FS

	struct dentry *ignore_gfp_highmem_file;
	struct dentry *ignore_gfp_wait_file;
	struct dentry *min_order_file;

#endif /* CONFIG_FAULT_INJECTION_DEBUG_FS */

} fail_page_alloc = {
	.attr = FAULT_ATTR_INITIALIZER,
	.ignore_gfp_wait = 1,
	.ignore_gfp_highmem = 1,
	.min_order = 1,
};

static int __init setup_fail_page_alloc(char *str)
{
	return setup_fault_attr(&fail_page_alloc.attr, str);
}
__setup("fail_page_alloc=", setup_fail_page_alloc);

static int should_fail_alloc_page(gfp_t gfp_mask, unsigned int order)
{
	if (order < fail_page_alloc.min_order)
		return 0;
	if (gfp_mask & __GFP_NOFAIL)
		return 0;
	if (fail_page_alloc.ignore_gfp_highmem && (gfp_mask & __GFP_HIGHMEM))
		return 0;
	
	if (fail_page_alloc.ignore_gfp_wait && (gfp_mask & __GFP_WAIT))
		return 0;

	return should_fail(&fail_page_alloc.attr, 1 << order);
}

#ifdef CONFIG_FAULT_INJECTION_DEBUG_FS

static int __init fail_page_alloc_debugfs(void)
{
	mode_t mode = S_IFREG | S_IRUSR | S_IWUSR;
	struct dentry *dir;
	int err;

	err = init_fault_attr_dentries(&fail_page_alloc.attr,
				       "fail_page_alloc");
	if (err)
		return err;
	dir = fail_page_alloc.attr.dentries.dir;

	fail_page_alloc.ignore_gfp_wait_file =
		debugfs_create_bool("ignore-gfp-wait", mode, dir,
				      &fail_page_alloc.ignore_gfp_wait);

	fail_page_alloc.ignore_gfp_highmem_file =
		debugfs_create_bool("ignore-gfp-highmem", mode, dir,
				      &fail_page_alloc.ignore_gfp_highmem);
	fail_page_alloc.min_order_file =
		debugfs_create_u32("min-order", mode, dir,
				   &fail_page_alloc.min_order);

	if (!fail_page_alloc.ignore_gfp_wait_file ||
            !fail_page_alloc.ignore_gfp_highmem_file ||
            !fail_page_alloc.min_order_file) {
		err = -ENOMEM;
		debugfs_remove(fail_page_alloc.ignore_gfp_wait_file);
		debugfs_remove(fail_page_alloc.ignore_gfp_highmem_file);
		debugfs_remove(fail_page_alloc.min_order_file);
		cleanup_fault_attr_dentries(&fail_page_alloc.attr);
	}

	return err;
}

late_initcall(fail_page_alloc_debugfs);

#endif /* CONFIG_FAULT_INJECTION_DEBUG_FS */

#else /* CONFIG_FAIL_PAGE_ALLOC */

static inline int should_fail_alloc_page(gfp_t gfp_mask, unsigned int order)
{
	return 0;
}

#endif /* CONFIG_FAIL_PAGE_ALLOC */

/*
 * 根据设置的标志判断能否从给定的内存域分配内存
 * 返回1 表示满足给定的水印，0表示不满足
 *
 * 确定是否可以从zone获得内存
 * Return 1 if free pages are above 'mark'. This takes into account the order
 * of the allocation.
 *
 * alloc_pages_node()
 *  __alloc_pages()
 *   get_page_from_freelist()
 *    zone_watermark_ok()
 */
int zone_watermark_ok(struct zone *z, int order, unsigned long mark,
		      int classzone_idx, int alloc_flags)
{
	/* free_pages my go negative - that's OK */
	long min = mark;
	/* zone中空闲页的数目 */
	long free_pages = zone_page_state(z, NR_FREE_PAGES) - (1 << order) + 1;
	int o;

    /*
     * 如果设置了ALLOC_HIGH 或 ALLOC_HARDER，min的值会进一步减少，
     * 这也就意味着把关条件放松，分配会更加aggressive
     *
     * 如果gfp_high标志被置位。通常atomic方式会置此标记。那么将水线降低一半，即内存分配可以穿越水线一半
	 */
	if (alloc_flags & ALLOC_HIGH)
		min -= min / 2;

	/*
	 * 如果can_try_harder标志被置位，水线再减少1/4，
	 * can_try_harder通常是当进程是一个实时进程并且在进程上下文中已经完成了内存分配。
	 */
	if (alloc_flags & ALLOC_HARDER)
		min -= min / 4;

    /* free_pages分配之后，不能满足reserve了，分配失败 */
	if (free_pages <= min + z->lowmem_reserve[classzone_idx])
		return 0;
	
	for (o = 0; o < order; o++) {
		/* At the next order, this order's pages become unavailable */
	    /* 扣除小于目标order的内存块，比如分配内存是指定的order为3，
	     * 即需要分配32k大小的内存，此时需要扣除掉小于32k大小的内存块，
         * 因为这些块的大小不足以分配32k的连续空间
         */
		free_pages -= z->free_area[o].nr_free << o;

		/* Require fewer higher order pages to be free */
	    /* 每扣除一个order的块，需要将水线除以2，
	     * 目的是将水线分担到各个order，当order为3时，
	     * 最终需要>=32k的内存块的容量>min/8,
         * 才能继续分配内存
         */
		min >>= 1;

		if (free_pages <= min)
			return 0;
	}
	return 1;
}

#ifdef CONFIG_NUMA
/*
 * zlc_setup - Setup for "zonelist cache".  Uses cached zone data to
 * skip over zones that are not allowed by the cpuset, or that have
 * been recently (in last second) found to be nearly full.  See further
 * comments in mmzone.h.  Reduces cache footprint of zonelist scans
 * that have to skip over a lot of full or unallowed zones.
 *
 * If the zonelist cache is present in the passed in zonelist, then
 * returns a pointer to the allowed node mask (either the current
 * tasks mems_allowed, or node_states[N_HIGH_MEMORY].)
 *
 * If the zonelist cache is not available for this zonelist, does
 * nothing and returns NULL.
 *
 * If the fullzones BITMAP in the zonelist cache is stale (more than
 * a second since last zap'd) then we zap it out (clear its bits.)
 *
 * We hold off even calling zlc_setup, until after we've checked the
 * first zone in the zonelist, on the theory that most allocations will
 * be satisfied from that first zone, so best to examine that zone as
 * quickly as we can.
 */
static nodemask_t *zlc_setup(struct zonelist *zonelist, int alloc_flags)
{
	struct zonelist_cache *zlc;	/* cached zonelist speedup info */
	nodemask_t *allowednodes;	/* zonelist_cache approximation */

	zlc = zonelist->zlcache_ptr;
	if (!zlc)
		return NULL;

	if (jiffies - zlc->last_full_zap > 1 * HZ) {
		bitmap_zero(zlc->fullzones, MAX_ZONES_PER_ZONELIST);
		zlc->last_full_zap = jiffies;
	}

	allowednodes = !in_interrupt() && (alloc_flags & ALLOC_CPUSET) ?
					&cpuset_current_mems_allowed :
					&node_states[N_HIGH_MEMORY];
	return allowednodes;
}

/*
 * Given 'z' scanning a zonelist, run a couple of quick checks to see
 * if it is worth looking at further for free memory:
 *  1) Check that the zone isn't thought to be full (doesn't have its
 *     bit set in the zonelist_cache fullzones BITMAP).
 *  2) Check that the zones node (obtained from the zonelist_cache
 *     z_to_n[] mapping) is allowed in the passed in allowednodes mask.
 * Return true (non-zero) if zone is worth looking at further, or
 * else return false (zero) if it is not.
 *
 * This check -ignores- the distinction between various watermarks,
 * such as GFP_HIGH, GFP_ATOMIC, PF_MEMALLOC, ...  If a zone is
 * found to be full for any variation of these watermarks, it will
 * be considered full for up to one second by all requests, unless
 * we are so low on memory on all allowed nodes that we are forced
 * into the second scan of the zonelist.
 *
 * In the second scan we ignore this zonelist cache and exactly
 * apply the watermarks to all zones, even it is slower to do so.
 * We are low on memory in the second scan, and should leave no stone
 * unturned looking for a free page.
 */
static int zlc_zone_worth_trying(struct zonelist *zonelist, struct zone **z,
						nodemask_t *allowednodes)
{
	struct zonelist_cache *zlc;	/* cached zonelist speedup info */
	int i;				/* index of *z in zonelist zones */
	int n;				/* node that zone *z is on */

	zlc = zonelist->zlcache_ptr;
	if (!zlc)
		return 1;

	i = z - zonelist->zones;
	n = zlc->z_to_n[i];

	/* This zone is worth trying if it is allowed but not full */
	return node_isset(n, *allowednodes) && !test_bit(i, zlc->fullzones);
}

/*
 * Given 'z' scanning a zonelist, set the corresponding bit in
 * zlc->fullzones, so that subsequent attempts to allocate a page
 * from that zone don't waste time re-examining it.
 */
static void zlc_mark_zone_full(struct zonelist *zonelist, struct zone **z)
{
	struct zonelist_cache *zlc;	/* cached zonelist speedup info */
	int i;				/* index of *z in zonelist zones */

	zlc = zonelist->zlcache_ptr;
	if (!zlc)
		return;

	i = z - zonelist->zones;

	set_bit(i, zlc->fullzones);
}

#else	/* CONFIG_NUMA */

static nodemask_t *zlc_setup(struct zonelist *zonelist, int alloc_flags)
{
	return NULL;
}

static int zlc_zone_worth_trying(struct zonelist *zonelist, struct zone **z,
				nodemask_t *allowednodes)
{
	return 1;
}

static void zlc_mark_zone_full(struct zonelist *zonelist, struct zone **z)
{
}
#endif	/* CONFIG_NUMA */

/*
 * 通过gfp_mask标记和order来判断是否能进行分配
 * get_page_from_freelist goes through the zonelist trying to allocate
 * a page.
 *
 * 从zone->free_area[oreder]中分配page
 * alloc_pages_node()
 *  __alloc_pages()
 *   get_page_from_freelist()
 */
static struct page *
get_page_from_freelist(gfp_t gfp_mask, unsigned int order,
		struct zonelist *zonelist, int alloc_flags)
{
	struct zone **z;
	struct page *page = NULL;
	int classzone_idx = zone_idx(zonelist->zones[0]);
	struct zone *zone;
	nodemask_t *allowednodes = NULL;/* zonelist_cache approximation */
	int zlc_active = 0;		/* set if using zonelist_cache */
	int did_zlc_setup = 0;		/* just call zlc_setup() one time */
	enum zone_type highest_zoneidx = -1; /* Gets set for policy zonelists */

zonelist_scan:
	/* 扫描zonelist，寻找具有足够空间的zone
	 * Scan zonelist, looking for a zone with enough free.
	 * See also cpuset_zone_allowed() comment in kernel/cpuset.c.
	 */
	z = zonelist->zones;

    //遍历各个zone，尝试分配
	do { 
		/*
		 * In NUMA, this could be a policy zonelist which contains
		 * zones that may not be allowed by the current gfp_mask.
		 * Check the zone is allowed by the current flags
		 */
		if (unlikely(alloc_should_filter_zonelist(zonelist))) {
			if (highest_zoneidx == -1)
				highest_zoneidx = gfp_zone(gfp_mask);
			if (zone_idx(*z) > highest_zoneidx)
				continue;
		}

		if (NUMA_BUILD && zlc_active &&
			!zlc_zone_worth_trying(zonelist, z, allowednodes))
				continue;
		
		zone = *z;

		//cpuset_zone_allowed_softwall用检测zone是否属于该进程允许允许的cpu
		if ((alloc_flags & ALLOC_CPUSET) &&
			!cpuset_zone_allowed_softwall(zone, gfp_mask))
				goto try_next_zone;

		/* 通过zone_watermark_ok检查是否有足够的空闲页可以分配 
         * 如果设置了ALLOC_NO_WATERMARKS标记，就跳过zone_watermark_ok检测
		 */
		if (!(alloc_flags & ALLOC_NO_WATERMARKS)) {
			unsigned long mark;
			
			/* 确定mark，用于检测zone中空闲page的底线 */
			if (alloc_flags & ALLOC_WMARK_MIN)
				mark = zone->pages_min;
			else if (alloc_flags & ALLOC_WMARK_LOW)
				mark = zone->pages_low;
			else
				mark = zone->pages_high;

			//zone中是否足够的空闲页可供分配
			if (!zone_watermark_ok(zone, order, mark,
				    classzone_idx, alloc_flags)) {
				/* mark在zone_watermark_ok中检测不通过，需要reclaim物理内存 */    
				if (!zone_reclaim_mode ||
				    !zone_reclaim(zone, gfp_mask, order))
					goto this_zone_full;
			}
		}

		/* 试图从zone中分配所需数目的页 */
		page = buffered_rmqueue(zonelist, zone, order, gfp_mask);
		if (page)
			break;
		
this_zone_full:
		if (NUMA_BUILD)
			zlc_mark_zone_full(zonelist, z);
try_next_zone:
		if (NUMA_BUILD && !did_zlc_setup) {
			/* we do zlc_setup after the first zone is tried */
			allowednodes = zlc_setup(zonelist, alloc_flags);
			zlc_active = 1;
			did_zlc_setup = 1;
		}
	} while (*(++z) != NULL);

	if (unlikely(NUMA_BUILD && page == NULL && zlc_active)) {
		/* Disable zlc cache for second zonelist scan */
		zlc_active = 0;
		goto zonelist_scan;
	}
	return page;
}

/*
 * This is the 'heart' of the zoned buddy allocator.
 * __alloc_pages 可称为伙伴系统的心脏
 *
 * alloc_pages_node()
 *  __alloc_pages()
 *
 *
 */
struct page * fastcall
__alloc_pages(gfp_t gfp_mask, unsigned int order,
		struct zonelist *zonelist)
{
    /* 是否可以阻塞 */
	const gfp_t wait = gfp_mask & __GFP_WAIT;
	
	struct zone **z;
	struct page *page;
	struct reclaim_state reclaim_state;
	struct task_struct *p = current;
	int do_retry;
	int alloc_flags;
	int did_some_progress;

	might_sleep_if(wait);

    //一些参数合法检测
 	if (should_fail_alloc_page(gfp_mask, order))
		return NULL;

restart:
	z = zonelist->zones;  /* the list of zones suitable for gfp_mask */

	if (unlikely(*z == NULL)) {
		/*
		 * Happens if we have an empty zonelist as a result of
		 * GFP_THISNODE being used on a memoryless node
		 */
		return NULL;
	}

    /* 
     * 第一次去分配page,以ALLOC_WMARK_LOW水位可以分配,这个算是比较高的要求,
     * 尽量保护各个zone预留的空闲内存
     *
     */
	page = get_page_from_freelist(gfp_mask|__GFP_HARDWALL, order,
				zonelist, ALLOC_WMARK_LOW|ALLOC_CPUSET);
	
	if (page)
		goto got_pg;

	/*
	 * GFP_THISNODE (meaning __GFP_THISNODE, __GFP_NORETRY and
	 * __GFP_NOWARN set) should not cause reclaim since the subsystem
	 * (f.e. slab) using GFP_THISNODE may choose to trigger reclaim
	 * using a larger set of nodes after it has established that the
	 * allowed per node queues are empty and that nodes are
	 * over allocated.
	 *
	 *
	 * 如果指定了GFP_THISNODE标志后，则不能继续进行慢速内存分配，
	 * 因为该标志指明了内存不能进行回收(reclaim)，因此直接跳到nopage处的代码。
	 */
	if (NUMA_BUILD && (gfp_mask & GFP_THISNODE) == GFP_THISNODE)
		goto nopage; //不允许尝试别的node了，那就直接失败

    /* 第一次分配失败，就唤醒kswapd进程 
     * 唤醒属于每个zone的kswapd进程
	 */
	for (z = zonelist->zones; *z; z++)
		wakeup_kswapd(*z, order);

	/*
	 * OK, we're below the kswapd watermark and have kicked background
	 * reclaim. Now things get more complex, so set up alloc_flags according
	 * to how we want to proceed.
	 *
	 * The caller may dip into page reserves a bit more if the caller
	 * cannot run direct reclaim, or if the caller has realtime scheduling
	 * policy or is asking for __GFP_HIGH memory.  GFP_ATOMIC requests will
	 * set both ALLOC_HARDER (!wait) and ALLOC_HIGH (__GFP_HIGH).
	 * 降低水位标准,再次尝试分配
	 */
	alloc_flags = ALLOC_WMARK_MIN;
  	/*
  	 * 是实时进程,且不是中断上下文,或者这次内存分配不能wait,那就激进一点了 
  	 *
  	 * 下面的ALLOC_HIGH和ALLOC_HARDER标记，会使得get_page_from_freelist 更加激进一些
	 */
	if ((unlikely(rt_task(p)) && !in_interrupt()) || !wait)
		alloc_flags |= ALLOC_HARDER;
	
	if (gfp_mask & __GFP_HIGH)
		alloc_flags |= ALLOC_HIGH;
	
	if (wait)
		alloc_flags |= ALLOC_CPUSET;

	/*
	 * Go through the zonelist again. Let __GFP_HIGH and allocations
	 * coming from realtime tasks go deeper into reserves.
	 *
	 * This is the last chance, in general, before the goto nopage.
	 * Ignore cpuset if GFP_ATOMIC (!wait) rather than fail alloc.
	 * See also cpuset_zone_allowed() comment in kernel/cpuset.c.
	 * 在降低水位标准之后，进行第二次page分配
	 */
	page = get_page_from_freelist(gfp_mask, order, zonelist, alloc_flags);
	if (page)
		goto got_pg;

	/* This allocation should allow future memory freeing. */

rebalance:

    /* 如果还是没能申请到内存，说明内存非常吃紧 */
    /* TIF_MEMDIE表示该进程已经被oom killer选择中 
     *
     *
     * 
	 * PF_MEMALLOC和TIF_MEMDIE到底表示啥东东呢？
	 * 简单地讲，它们的出现一般表示当前的上下文是在回收内存。
	 * 回收内存本身也是需要内存的，你先给我一点点空闲内存，
	 * 我将回报给你更多的空闲内存。给我一滴水，我将还你一片海。
	 * 所以它才有资格动用全部的预留内存。
	 */
	if (((p->flags & PF_MEMALLOC) || unlikely(test_thread_flag(TIF_MEMDIE)))
			&& !in_interrupt()) {

		/* 如果是__GFP_NOMEMALLOC的请求，表示禁止使用为紧急情况预留的内存，这种情况下Kernel再无它法，只能返回NULL */
		if (!(gfp_mask & __GFP_NOMEMALLOC)) {
nofail_alloc:
			/* go through the zonelist yet again, ignoring mins 
               在遍历一次空闲页，ALLOC_NO_WATERMARKS忽略水位检测
		     */
			page = get_page_from_freelist(gfp_mask, order,
				zonelist, ALLOC_NO_WATERMARKS);
			if (page)
				goto got_pg;
			
			if (gfp_mask & __GFP_NOFAIL) {
				
				congestion_wait(WRITE, HZ/50); /* 等待块设备结束占线 */
				/* 进入死循环了 */
				goto nofail_alloc;
			}
		}
		goto nopage;
	}

	/* Atomic allocations - we can't balance anything */
	if (!wait)
		goto nopage;

    /* 先释放cpu ,让给kswapd进程执行*/
	cond_resched();

	/* We now go into synchronous reclaim 
       进入同步回收的状态
	*/
	cpuset_memory_pressure_bump();

	//需要kill掉进程，释放一部分物理内存了
	p->flags |= PF_MEMALLOC;
	reclaim_state.reclaimed_slab = 0;
	p->reclaim_state = &reclaim_state;

    /* 释放掉一部分
     * did_some_progress表示的确释放了一些页面,这个函数可能会睡眠
     */
	did_some_progress = try_to_free_pages(zonelist->zones, order, gfp_mask);

	p->reclaim_state = NULL;
	p->flags &= ~PF_MEMALLOC;

	cond_resched();

	if (order != 0) // 释放zone->pcp[]中的page
		drain_all_local_pages();

	if (likely(did_some_progress)) {
		/* 再次尝试获取page */
		page = get_page_from_freelist(gfp_mask, order,
						zonelist, alloc_flags);
		if (page)
			goto got_pg;
	} else if ((gfp_mask & __GFP_FS) && !(gfp_mask & __GFP_NORETRY)) {
		if (!try_set_zone_oom(zonelist)) {
			schedule_timeout_uninterruptible(1);
			goto restart;
		}

		/*
		 * Go through the zonelist yet one more time, keep
		 * very high watermark here, this is only to catch
		 * a parallel oom killing, we must fail if we're still
		 * under heavy pressure.
		 */
		page = get_page_from_freelist(gfp_mask|__GFP_HARDWALL, order,
				zonelist, ALLOC_WMARK_HIGH|ALLOC_CPUSET);
		if (page) {
			clear_zonelist_oom(zonelist);
			goto got_pg;
		}

		/* The OOM killer will not help higher order allocs so fail */
		if (order > PAGE_ALLOC_COSTLY_ORDER) {
			clear_zonelist_oom(zonelist);
			goto nopage;
		}

		/* 杀掉一个进程，释放出其内存资源 */
		out_of_memory(zonelist, gfp_mask, order);
		clear_zonelist_oom(zonelist);
		goto restart;
	}

	/*
	 * Don't let big-order allocations loop unless the caller explicitly
	 * requests that.  Wait for some write requests to complete then retry.
	 *
	 * In this implementation, __GFP_REPEAT means __GFP_NOFAIL for order
	 * <= 3, but that may not be true in other implementations.
	 *
	 *
	 * 如果到此还没有分配到内存，根据各种条件，是否要retry.
	 */
	do_retry = 0;
	if (!(gfp_mask & __GFP_NORETRY)) {
		
		if ((order <= PAGE_ALLOC_COSTLY_ORDER) ||
						(gfp_mask & __GFP_REPEAT))
			do_retry = 1;
		
		if (gfp_mask & __GFP_NOFAIL)
			do_retry = 1;
	}
	
	if (do_retry) {
		congestion_wait(WRITE, HZ/50);
		goto rebalance;
	}

nopage:
	if (!(gfp_mask & __GFP_NOWARN) && printk_ratelimit()) {
		printk(KERN_WARNING "%s: page allocation failure."
			" order:%d, mode:0x%x\n",
			p->comm, order, gfp_mask);
		dump_stack();
		show_mem();
	}
got_pg:
	return page;
}

EXPORT_SYMBOL(__alloc_pages);

/*
 * Common helper functions.
 */
fastcall unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order)
{
	struct page * page;
	page = alloc_pages(gfp_mask, order);
	if (!page)
		return 0;
	return (unsigned long) page_address(page);
}

EXPORT_SYMBOL(__get_free_pages);

fastcall unsigned long get_zeroed_page(gfp_t gfp_mask)
{
	struct page * page;

	/*
	 * get_zeroed_page() returns a 32-bit address, which cannot represent
	 * a highmem page
	 */
	VM_BUG_ON((gfp_mask & __GFP_HIGHMEM) != 0);

	page = alloc_pages(gfp_mask | __GFP_ZERO, 0);
	if (page)
		return (unsigned long) page_address(page);
	return 0;
}

EXPORT_SYMBOL(get_zeroed_page);


/*
 * lru_cache_add()
 *  __pagevec_lru_add()
 *   release_pages()
 *    pagevec_free()
 *     __pagevec_free()
 *
 * 释放page的时候，先释放到zone->pcp[]中去的
 */
void __pagevec_free(struct pagevec *pvec)
{
	int i = pagevec_count(pvec);

	while (--i >= 0)
		free_hot_cold_page(pvec->pages[i], pvec->cold);
}


/* 释放物理页 
 *
 * start_kernel()
 *  mem_init()
 *	 free_all_bootmem()
 *    free_all_bootmem_core()
 *     __free_pages_bootmem()
 *      __free_pages()
 *
 * cpucache_init()
 *  start_cpu_timer()
 *   ......
 *    cache_reap()
 *     drain_freelist()
 *      slab_destroy()
 *       kmem_freepages()
 *        free_pages()
 *         __free_pages()
 */
fastcall void __free_pages(struct page *page, unsigned int order)
{
    //确定没有被引用了
	if (put_page_testzero(page)) {
		
		if (order == 0) /* 释放单页,到zone->pageset[]中去 */
			free_hot_page(page);
		else
			__free_pages_ok(page, order);
	}
}

EXPORT_SYMBOL(__free_pages);

/*
 * cpucache_init()
 *  start_cpu_timer()
 *   ......
 *    cache_reap()
 *     drain_freelist()
 *      slab_destroy()
 *       kmem_freepages()
 *        free_pages()
 */
fastcall void free_pages(unsigned long addr, unsigned int order)
{
	if (addr != 0) {
		VM_BUG_ON(!virt_addr_valid((void *)addr));
		__free_pages(virt_to_page((void *)addr), order);
	}
}

EXPORT_SYMBOL(free_pages);

static unsigned int nr_free_zone_pages(int offset)
{
	/* Just pick one node, since fallback list is circular */
	pg_data_t *pgdat = NODE_DATA(numa_node_id());
	unsigned int sum = 0;

	struct zonelist *zonelist = pgdat->node_zonelists + offset;
	struct zone **zonep = zonelist->zones;
	struct zone *zone;

	for (zone = *zonep++; zone; zone = *zonep++) {
		unsigned long size = zone->present_pages;
		unsigned long high = zone->pages_high;
		if (size > high)
			sum += size - high;
	}

	return sum;
}

/*
 * Amount of free RAM allocatable within ZONE_DMA and ZONE_NORMAL
 */
unsigned int nr_free_buffer_pages(void)
{
	return nr_free_zone_pages(gfp_zone(GFP_USER));
}
EXPORT_SYMBOL_GPL(nr_free_buffer_pages);

/*
 * Amount of free RAM allocatable within all zones
 */
unsigned int nr_free_pagecache_pages(void)
{
	return nr_free_zone_pages(gfp_zone(GFP_HIGHUSER_MOVABLE));
}

static inline void show_node(struct zone *zone)
{
	if (NUMA_BUILD)
		printk("Node %d ", zone_to_nid(zone));
}

void si_meminfo(struct sysinfo *val)
{
	val->totalram = totalram_pages;
	val->sharedram = 0;
	val->freeram = global_page_state(NR_FREE_PAGES);
	val->bufferram = nr_blockdev_pages();
	val->totalhigh = totalhigh_pages;
	val->freehigh = nr_free_highpages();
	val->mem_unit = PAGE_SIZE;
}

EXPORT_SYMBOL(si_meminfo);

#ifdef CONFIG_NUMA
void si_meminfo_node(struct sysinfo *val, int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);

	val->totalram = pgdat->node_present_pages;
	val->freeram = node_page_state(nid, NR_FREE_PAGES);
#ifdef CONFIG_HIGHMEM
	val->totalhigh = pgdat->node_zones[ZONE_HIGHMEM].present_pages;
	val->freehigh = zone_page_state(&pgdat->node_zones[ZONE_HIGHMEM],
			NR_FREE_PAGES);
#else
	val->totalhigh = 0;
	val->freehigh = 0;
#endif
	val->mem_unit = PAGE_SIZE;
}
#endif

#define K(x) ((x) << (PAGE_SHIFT-10))

/*
 * Show free area list (used inside shift_scroll-lock stuff)
 * We also calculate the percentage fragmentation. We do this by counting the
 * memory on each free list with the exception of the first item on the list.
 */
void show_free_areas(void)
{
	int cpu;
	struct zone *zone;

	for_each_zone(zone) {
		if (!populated_zone(zone))
			continue;

		show_node(zone);
		printk("%s per-cpu:\n", zone->name);

		for_each_online_cpu(cpu) {
			struct per_cpu_pageset *pageset;

			pageset = zone_pcp(zone, cpu);

			printk("CPU %4d: Hot: hi:%5d, btch:%4d usd:%4d   "
			       "Cold: hi:%5d, btch:%4d usd:%4d\n",
			       cpu, pageset->pcp[0].high,
			       pageset->pcp[0].batch, pageset->pcp[0].count,
			       pageset->pcp[1].high, pageset->pcp[1].batch,
			       pageset->pcp[1].count);
		}
	}

	printk("Active:%lu inactive:%lu dirty:%lu writeback:%lu unstable:%lu\n"
		" free:%lu slab:%lu mapped:%lu pagetables:%lu bounce:%lu\n",
		global_page_state(NR_ACTIVE),
		global_page_state(NR_INACTIVE),
		global_page_state(NR_FILE_DIRTY),
		global_page_state(NR_WRITEBACK),
		global_page_state(NR_UNSTABLE_NFS),
		global_page_state(NR_FREE_PAGES),
		global_page_state(NR_SLAB_RECLAIMABLE) +
			global_page_state(NR_SLAB_UNRECLAIMABLE),
		global_page_state(NR_FILE_MAPPED),
		global_page_state(NR_PAGETABLE),
		global_page_state(NR_BOUNCE));

	for_each_zone(zone) {
		int i;

		if (!populated_zone(zone))
			continue;

		show_node(zone);
		printk("%s"
			" free:%lukB"
			" min:%lukB"
			" low:%lukB"
			" high:%lukB"
			" active:%lukB"
			" inactive:%lukB"
			" present:%lukB"
			" pages_scanned:%lu"
			" all_unreclaimable? %s"
			"\n",
			zone->name,
			K(zone_page_state(zone, NR_FREE_PAGES)),
			K(zone->pages_min),
			K(zone->pages_low),
			K(zone->pages_high),
			K(zone_page_state(zone, NR_ACTIVE)),
			K(zone_page_state(zone, NR_INACTIVE)),
			K(zone->present_pages),
			zone->pages_scanned,
			(zone_is_all_unreclaimable(zone) ? "yes" : "no")
			);
		printk("lowmem_reserve[]:");
		for (i = 0; i < MAX_NR_ZONES; i++)
			printk(" %lu", zone->lowmem_reserve[i]);
		printk("\n");
	}

	for_each_zone(zone) {
 		unsigned long nr[MAX_ORDER], flags, order, total = 0;

		if (!populated_zone(zone))
			continue;

		show_node(zone);
		printk("%s: ", zone->name);

		spin_lock_irqsave(&zone->lock, flags);
		for (order = 0; order < MAX_ORDER; order++) {
			nr[order] = zone->free_area[order].nr_free;
			total += nr[order] << order;
		}
		spin_unlock_irqrestore(&zone->lock, flags);
		for (order = 0; order < MAX_ORDER; order++)
			printk("%lu*%lukB ", nr[order], K(1UL) << order);
		printk("= %lukB\n", K(total));
	}

	show_swap_cache_info();
}

/*
 * Builds allocation fallback zone lists.
 *
 * Add all populated zones of a node to the zonelist.
 *
 *
 * start_kernel()
 *	build_all_zonelists()
 *   __build_all_zonelists()
 *    build_zonelists() 
 *     build_zonelists_in_node_order()
 *      build_zonelists_node()
 *
 * 将pgdat->zones[zone_type]以下的zone都放入到zonelist->zones[]中去
 */
static int build_zonelists_node(pg_data_t *pgdat, struct zonelist *zonelist,
				int nr_zones /* 在zonelist->zones[]中可以插入的位置 */, 
				enum zone_type zone_type)
{
	struct zone *zone;

	BUG_ON(zone_type >= MAX_NR_ZONES);
	zone_type++;

	do {
		zone_type--;
		/* 得到pgdat中属于zone_type的zone */
		zone = pgdat->node_zones + zone_type;
		if (populated_zone(zone)) {
			/* zone中确实是有page frame的 */
			zonelist->zones[nr_zones++] = zone;
			check_highest_zone(zone_type); /* 设置policy_zone */
		}

	} while (zone_type);/* 还没低于DMA类型 */
	return nr_zones;
}


/*
 * pg_data 中zonelist中的zone的数据排序方式,
 * 可以以node来排序，也可以以zone_type来排序
 *  zonelist_order:
 *  0 = automatic detection of better ordering.
 *  1 = order by ([node] distance, -zonetype)
 *  2 = order by (-zonetype, [node] distance)
 *
 *  If not NUMA, ZONELIST_ORDER_ZONE and ZONELIST_ORDER_NODE will create
 *  the same zonelist. So only NUMA can configure this param.
 */
#define ZONELIST_ORDER_DEFAULT  0
#define ZONELIST_ORDER_NODE     1
#define ZONELIST_ORDER_ZONE     2

/* zonelist order in the kernel.
 * set_zonelist_order() will set this to NODE or ZONE.
 */
static int current_zonelist_order = ZONELIST_ORDER_DEFAULT;
static char zonelist_order_name[3][8] = {"Default", "Node", "Zone"};


#ifdef CONFIG_NUMA
/* The value user specified ....changed by config */
static int user_zonelist_order = ZONELIST_ORDER_DEFAULT;
/* string for sysctl */
#define NUMA_ZONELIST_ORDER_LEN	16
char numa_zonelist_order[16] = "default";

/*
 * interface for configure zonelist ordering.
 * command line option "numa_zonelist_order"
 *	= "[dD]efault	- default, automatic configuration.
 *	= "[nN]ode 	- order by node locality, then by zone within node
 *	= "[zZ]one      - order by zone, then by locality within zone
 */

static int __parse_numa_zonelist_order(char *s)
{
	if (*s == 'd' || *s == 'D') {
		user_zonelist_order = ZONELIST_ORDER_DEFAULT;
	} else if (*s == 'n' || *s == 'N') {
		user_zonelist_order = ZONELIST_ORDER_NODE;
	} else if (*s == 'z' || *s == 'Z') {
		user_zonelist_order = ZONELIST_ORDER_ZONE;
	} else {
		printk(KERN_WARNING
			"Ignoring invalid numa_zonelist_order value:  "
			"%s\n", s);
		return -EINVAL;
	}
	return 0;
}

static __init int setup_numa_zonelist_order(char *s)
{
	if (s)
		return __parse_numa_zonelist_order(s);
	return 0;
}
early_param("numa_zonelist_order", setup_numa_zonelist_order);

/*
 * sysctl handler for numa_zonelist_order
 */
int numa_zonelist_order_handler(ctl_table *table, int write,
		struct file *file, void __user *buffer, size_t *length,
		loff_t *ppos)
{
	char saved_string[NUMA_ZONELIST_ORDER_LEN];
	int ret;

	if (write)
		strncpy(saved_string, (char*)table->data,
			NUMA_ZONELIST_ORDER_LEN);
	ret = proc_dostring(table, write, file, buffer, length, ppos);
	if (ret)
		return ret;
	if (write) {
		int oldval = user_zonelist_order;
		if (__parse_numa_zonelist_order((char*)table->data)) {
			/*
			 * bogus value.  restore saved string
			 */
			strncpy((char*)table->data, saved_string,
				NUMA_ZONELIST_ORDER_LEN);
			user_zonelist_order = oldval;
		} else if (oldval != user_zonelist_order)
			build_all_zonelists();
	}
	return 0;
}


#define MAX_NODE_LOAD (num_online_nodes())
static int node_load[MAX_NUMNODES];

/**
 * find_next_best_node - find the next node that should appear in a given node's fallback list
 * @node: node whose fallback list we're appending
 * @used_node_mask: nodemask_t of already used nodes
 *
 * We use a number of factors to determine which is the next node that should
 * appear on a given node's fallback list.  The node should not have appeared
 * already in @node's fallback list, and it should be the next closest node
 * according to the distance array (which contains arbitrary distance values
 * from each node to each node in the system), and should also prefer nodes
 * with no CPUs, since presumably they'll have very little allocation pressure
 * on them otherwise.
 * It returns -1 if no node is found.
 */
static int find_next_best_node(int node, nodemask_t *used_node_mask)
{
	int n, val;
	int min_val = INT_MAX;
	int best_node = -1;

	/* Use the local node if we haven't already */
	if (!node_isset(node, *used_node_mask)) {
		node_set(node, *used_node_mask);
		return node;
	}

	for_each_node_state(n, N_HIGH_MEMORY) {
		cpumask_t tmp;

		/* Don't want a node to appear more than once */
		if (node_isset(n, *used_node_mask))
			continue;

		/* Use the distance array to find the distance */
		val = node_distance(node, n);

		/* Penalize nodes under us ("prefer the next node") */
		val += (n < node);

		/* Give preference to headless and unused nodes */
		tmp = node_to_cpumask(n);
		if (!cpus_empty(tmp))
			val += PENALTY_FOR_NODE_WITH_CPUS;

		/* Slight preference for less loaded node */
		val *= (MAX_NODE_LOAD*MAX_NUMNODES);
		val += node_load[n];

		if (val < min_val) {
			min_val = val;
			best_node = n;
		}
	}

	if (best_node >= 0)
		node_set(best_node, *used_node_mask);

	return best_node;
}


/*
 * Build zonelists ordered by node and zones within node.
 * This results in maximum locality--normal zone overflows into local
 * DMA zone, if any--but risks exhausting DMA zone.
 *
 *
 * start_kernel()
 *	 build_all_zonelists()
 *      __build_all_zonelists()
 *         build_zonelists() 
 *           build_zonelists_in_node_order()
 *
 * 将NODE_DATA(node)->zones[]放入到 pgdat->node_zonelists[]->zones[]中的元素
 */
static void build_zonelists_in_node_order(pg_data_t *pgdat, int node)
{
	enum zone_type i;
	int j;
	struct zonelist *zonelist;
     /*
     * 最后会形成如下局面
     *  node1放入到pgdata中
     *  pgdata->node_zonelist[DMA]->zones[DMA]=node1->zones[DMA]
     *  pgdata->node_zonelist[NORMAL]->zones[NORMAL]=node1->zones[DMA] + node1->zones[NORMAL]
     *  pgdata->node_zonelist[HIGH]->zones[HIGH]= node1->zones[DMA] + node1->zones[NORMAL] + node1->zones[HIGH]
     *
     *  继续 node2放入到pgdata中
     *
     *  pgdata->node_zonelist[DMA]->zones[DMA]=node1->zones[DMA] + node2->zones[DMA]
     *  pgdata->node_zonelist[NORMAL]->zones[NORMAL]=node1->zones[DMA] + node1->zones[NORMAL] + node2->zones[DMA] + node2->zones[NORMAL]
     *  pgdata->node_zonelist[HIGH]->zones[HIGH]= node1->zonesDMA + node1->zonesNORMAL + node1->zones[HIGH] + node2->zones[DMA] + node2->zones[NORMAL] + node2->zones[HIGH]
     *
     *
     */

	/*
	 * NODE_DATA(node)->zones[] 放入到pgdat->zonelist[]数组的各个元素
	 */
	for (i = 0; i < MAX_NR_ZONES; i++) {

		zonelist = pgdat->node_zonelists + i; /* 每一次都是不同的zonelist */

	
		for (j = 0; zonelist->zones[j] != NULL; j++)
			;

		/* 将NODE_DATA(node)->node_zones[i]以下的zone都放入到 zonelist->zones[zone_type]中去 */
 		j = build_zonelists_node(NODE_DATA(node), zonelist, j, i);
		zonelist->zones[j] = NULL;
	}
}

/*
 * Build gfp_thisnode zonelists
 */
static void build_thisnode_zonelists(pg_data_t *pgdat)
{
	enum zone_type i;
	int j;
	struct zonelist *zonelist;

	for (i = 0; i < MAX_NR_ZONES; i++) {
		zonelist = pgdat->node_zonelists + MAX_NR_ZONES + i;
		j = build_zonelists_node(pgdat, zonelist, 0, i);
		zonelist->zones[j] = NULL;
	}
}

/*
 * Build zonelists ordered by zone and nodes within zones.
 * This results in conserving DMA zone[s] until all Normal memory is
 * exhausted, but results in overflowing to remote node while memory
 * may still exist in local DMA zone.
 */
static int node_order[MAX_NUMNODES];

/*
 *
 * start_kernel()
 *	build_all_zonelists()
 *   __build_all_zonelists()
 *    build_zonelists() 
 *     build_zonelists_in_zone_order()
 *
 * 在pgdat->node_zonelists中插入node1->zones[]和node2->zones[]的值
 * 将形成如下的局面:
 * pgdat->node_zonelists[DMA]= node1->zones[DMA] + node2->zones[DMA]
 *
 * pgdata->node_zonelist[NORMAL] = node1->zones[DMA] + node2->zones[DMA] + node->zones[NORMAL] + node2->zones[NORMAL]
 *
 * pgdata->node_zonelist[HIGH] = node1->zones[DMA] + node2->zones[DMA] + node->zones[NORMAL] + node2->zones[NORMAL] + node1->zones[HIGH] + node2->zones[HIGH]
 *
 */
static void build_zonelists_in_zone_order(pg_data_t *pgdat, int nr_nodes)
{
	enum zone_type i;
	int pos, j, node;
	int zone_type;		/* needs to be signed */
	struct zone *z;
	struct zonelist *zonelist;

	for (i = 0; i < MAX_NR_ZONES; i++) {
		zonelist = pgdat->node_zonelists + i;
		pos = 0;
	    /* 按照类型排序 */
		for (zone_type = i; zone_type >= 0; zone_type--) {
			/* 遍历内存节点 */
			for (j = 0; j < nr_nodes; j++) {
				node = node_order[j];
				z = &NODE_DATA(node)->node_zones[zone_type];
				if (populated_zone(z)) {
					zonelist->zones[pos++] = z;
					check_highest_zone(zone_type);
				}
			}
		}
		zonelist->zones[pos] = NULL;
	}
}

/* 计算zonelist中zone的排序规则以zone type或者node id排序 */
static int default_zonelist_order(void)
{
	int nid, zone_type;
	unsigned long low_kmem_size,total_size;
	struct zone *z;
	int average_size;
	/*
         * ZONE_DMA and ZONE_DMA32 can be very small area in the sytem.
	 * If they are really small and used heavily, the system can fall
	 * into OOM very easily.
	 * This function detect ZONE_DMA/DMA32 size and confgigures zone order.
	 */
	/* Is there ZONE_NORMAL ? (ex. ppc has only DMA zone..) */
	low_kmem_size = 0;
	total_size = 0;
	for_each_online_node(nid) {
		for (zone_type = 0; zone_type < MAX_NR_ZONES; zone_type++) {
			z = &NODE_DATA(nid)->node_zones[zone_type];
			if (populated_zone(z)) {
				if (zone_type < ZONE_NORMAL)
					low_kmem_size += z->present_pages;
				total_size += z->present_pages;
			}
		}
	}
	if (!low_kmem_size ||  /* there are no DMA area. */
	    low_kmem_size > total_size/2) /* DMA/DMA32 is big. */
		return ZONELIST_ORDER_NODE;
	/*
	 * look into each node's config.
  	 * If there is a node whose DMA/DMA32 memory is very big area on
 	 * local memory, NODE_ORDER may be suitable.
         */
	average_size = total_size /
				(nodes_weight(node_states[N_HIGH_MEMORY]) + 1);
	for_each_online_node(nid) {
		low_kmem_size = 0;
		total_size = 0;
		for (zone_type = 0; zone_type < MAX_NR_ZONES; zone_type++) {
			z = &NODE_DATA(nid)->node_zones[zone_type];
			if (populated_zone(z)) {
				if (zone_type < ZONE_NORMAL)
					low_kmem_size += z->present_pages;
				total_size += z->present_pages;
			}
		}
		if (low_kmem_size &&
		    total_size > average_size && /* ignore small node */
		    low_kmem_size > total_size * 70/100)
			return ZONELIST_ORDER_NODE;
	}
	return ZONELIST_ORDER_ZONE;
}

/*
 * start_kernel()
 *    build_all_zonelists()
 *      set_zonelist_order()
 */
static void set_zonelist_order(void)
{
	if (user_zonelist_order == ZONELIST_ORDER_DEFAULT)
		current_zonelist_order = default_zonelist_order();
	else
		current_zonelist_order = user_zonelist_order;
}

/*
 * NUMA架构
 *
 * start_kernel()
 *	 build_all_zonelists()
 *      __build_all_zonelists()
 *         build_zonelists() 
 */
static void build_zonelists(pg_data_t *pgdat)
{
	int j, node, load;
	enum zone_type i;
	nodemask_t used_mask;
	int local_node, prev_node;
	struct zonelist *zonelist;
	int order = current_zonelist_order; // 0

	/* initialize zonelists ,通常 MAX_ZONELISTS=2 *2 
	 *
	 MAX_ZONELISTS的值在配置CONFIG_NUMA时为2，否则为1。
	 索引为0的链表表示后援 (Fallback)链表，
	 也即当该链表中的第一个不满足分配内存时，依次尝试链表的其他管理区。
	 索引为1,的链表则用来针对GFP_THISNODE的内存申请，
	 此时只能申请指定的该链表中的管理区
	 */
	for (i = 0; i < MAX_ZONELISTS; i++) {
		zonelist = pgdat->node_zonelists + i;
		zonelist->zones[0] = NULL; 
	}

	/* NUMA-aware ordering of nodes */
	local_node = pgdat->node_id; /* 当前节点id */
	load = num_online_nodes();   /* 所有可用的内存节点 */
	prev_node = local_node;
	nodes_clear(used_mask);

	memset(node_load, 0, sizeof(node_load));
	memset(node_order, 0, sizeof(node_order));
	j = 0;

	while ((node = find_next_best_node(local_node, &used_mask)) >= 0) {
		/* 与本节点距离最近的那个节点 */
		int distance = node_distance(local_node, node);

		/*
		 * If another node is sufficiently far away then it is better
		 * to reclaim pages in a zone before going off node.
		 */
		if (distance > RECLAIM_DISTANCE)
			zone_reclaim_mode = 1;

		/*
		 * We don't want to pressure a particular node.
		 * So adding penalty to the first node in same
		 * distance group to make it round-robin.
		 */
		if (distance != node_distance(local_node, prev_node))
			node_load[node] = load;

		prev_node = node;
		load--;
		/* 以node的方式排序 */
		if (order == ZONELIST_ORDER_NODE) /* node由近到远排序 */
			build_zonelists_in_node_order(pgdat, node);
		else
			node_order[j++] = node;	/* remember order */
	}

	/* 以zone的方式排序 */
	if (order == ZONELIST_ORDER_ZONE) {
		/* calculate node order -- i.e., DMA last! */
		build_zonelists_in_zone_order(pgdat, j); /* j为上面遍历的最后一个node的位置 */
	}

	/* 初始化用于GFP_THISNODE的zone */
	build_thisnode_zonelists(pgdat);
}

/* Construct the zonelist performance cache - see further mmzone.h */
static void build_zonelist_cache(pg_data_t *pgdat)
{
	int i;

	for (i = 0; i < MAX_NR_ZONES; i++) {
		struct zonelist *zonelist;
		struct zonelist_cache *zlc;
		struct zone **z;

		zonelist = pgdat->node_zonelists + i;
		zonelist->zlcache_ptr = zlc = &zonelist->zlcache;
		bitmap_zero(zlc->fullzones, MAX_ZONES_PER_ZONELIST);
		for (z = zonelist->zones; *z; z++)
			zlc->z_to_n[z - zonelist->zones] = zone_to_nid(*z);
	}
}


#else	/* CONFIG_NUMA */

/*
* start_kernel()
*  build_all_zonelists()
*/
static void set_zonelist_order(void)
{
	current_zonelist_order = ZONELIST_ORDER_ZONE;
}

/* UMA架构 */
static void build_zonelists(pg_data_t *pgdat)
{
	int node, local_node;
	enum zone_type i,j;

	local_node = pgdat->node_id;
	                /* zone_type最多为3
	                 * HIGHMEM, NORMAL, DMA
	                 */
	for (i = 0; i < MAX_NR_ZONES; i++) {
		struct zonelist *zonelist;

        /* 第i种zone列表 */
		zonelist = pgdat->node_zonelists + i;

        /* 将本pgdat的属于第i种的zone插入到zonelist中去,
           从zonelist->zones[0]开始插入，返回的值j为下次待插入的下标 
         */
 		j = build_zonelists_node(pgdat, zonelist, 0, i);
		
 		/*
 		 * 将其余节点的属于第i中的zone插入到zonelist中去
 		 * Now we build the zonelist so that it contains the zones
 		 * of all the other nodes.
 		 * We don't want to pressure a particular node, so when
 		 * building the zones for node N, we make sure that the
 		 * zones coming right after the local ones are those from
 		 * node N+1 (modulo N)
 		 */
		for (node = local_node + 1; node < MAX_NUMNODES; node++) {
			if (!node_online(node))
				continue;
			j = build_zonelists_node(NODE_DATA(node), zonelist, j, i);
		}
		for (node = 0; node < local_node; node++) {
			if (!node_online(node))
				continue;
			j = build_zonelists_node(NODE_DATA(node), zonelist, j, i);
		}

        /* 末尾为NULL */
		zonelist->zones[j] = NULL;
	}
}

/* non-NUMA variant of zonelist performance cache - just NULL zlcache_ptr */
static void build_zonelist_cache(pg_data_t *pgdat)
{
	int i;

	for (i = 0; i < MAX_NR_ZONES; i++)
		pgdat->node_zonelists[i].zlcache_ptr = NULL;
}

#endif	/* CONFIG_NUMA */

/* return values int ....just for stop_machine_run() 
对系统中的各个内存node调用build_zonelists
* start_kernel()
*  build_all_zonelists()
*   __build_all_zonelists()
*/
static int __build_all_zonelists(void *dummy)
{
	int nid;

    /* 对各个内存节点生成备用zone列表 */
	for_each_online_node(nid) {
		pg_data_t *pgdat = NODE_DATA(nid);

		build_zonelists(pgdat); /* 对不同的node生成相应的zone */
		build_zonelist_cache(pgdat);
	}
	return 0;
}

/*
 * start_kernel调用这个函数
 * start_kernel()
 *  build_all_zonelists()
 *
 * 设置pg_data_t->node_zonelists[]中的数据
 */
void build_all_zonelists(void)
{
    /* 计算zonelist中zone的排序规则以zone type或者node id排序
     如果配置了CONFIG_NUMA，没有DMA或者DMA,DMA32 的zone 区间比较大，
     就用ZONELIST_ORDER_NODE的方式排序
    
     在没有配置了CONFIG_NUMA的情况下，以ZONELIST_ORDER_ZONE方式排序
     current_zonelist_order = ZONELIST_ORDER_ZONE
    */
	set_zonelist_order();

	if (system_state == SYSTEM_BOOTING) {
		__build_all_zonelists(NULL);
		cpuset_init_current_mems_allowed();
	} else {
		/* we have to stop all cpus to guarantee there is no user
		   of zonelist */
		stop_machine_run(__build_all_zonelists, NULL, NR_CPUS);
		/* cpuset refresh routine should be here */
	}
	
	vm_total_pages = nr_free_pagecache_pages();
	/*
	 * Disable grouping by mobility if the number of pages in the
	 * system is too low to allow the mechanism to work. It would be
	 * more accurate, but expensive to check per-zone. This check is
	 * made on memory-hotadd so a system can start with mobility
	 * disabled and enable it later
	 * 确定是否开启free_area的分类功能
	 */
	if (vm_total_pages < (pageblock_nr_pages * MIGRATE_TYPES))
		page_group_by_mobility_disabled = 1;
	else
		page_group_by_mobility_disabled = 0;

	printk("Built %i zonelists in %s order, mobility grouping %s.  "
		"Total pages: %ld\n",
			num_online_nodes(),
			zonelist_order_name[current_zonelist_order],
			page_group_by_mobility_disabled ? "off" : "on",
			vm_total_pages);
#ifdef CONFIG_NUMA
	printk("Policy zone: %s\n", zone_names[policy_zone]);
#endif
}

/*
 * Helper functions to size the waitqueue hash table.
 * Essentially these want to choose hash table sizes sufficiently
 * large so that collisions trying to wait on pages are rare.
 * But in fact, the number of active page waitqueues on typical
 * systems is ridiculously low, less than 200. So this is even
 * conservative, even though it seems large.
 *
 * The constant PAGES_PER_WAITQUEUE specifies the ratio of pages to
 * waitqueues, i.e. the size of the waitq table given the number of pages.
 */
#define PAGES_PER_WAITQUEUE	256

#ifndef CONFIG_MEMORY_HOTPLUG
static inline unsigned long wait_table_hash_nr_entries(unsigned long pages)
{
	unsigned long size = 1;

	pages /= PAGES_PER_WAITQUEUE;

	while (size < pages)
		size <<= 1;

	/*
	 * Once we have dozens or even hundreds of threads sleeping
	 * on IO we've got bigger problems than wait queue collision.
	 * Limit the size of the wait table to a reasonable size.
	 */
	size = min(size, 4096UL);

	return max(size, 4UL);
}
#else
/*
 * A zone's size might be changed by hot-add, so it is not possible to determine
 * a suitable size for its wait_table.  So we use the maximum size now.
 *
 * The max wait table size = 4096 x sizeof(wait_queue_head_t).   ie:
 *
 *    i386 (preemption config)    : 4096 x 16 = 64Kbyte.
 *    ia64, x86-64 (no preemption): 4096 x 20 = 80Kbyte.
 *    ia64, x86-64 (preemption)   : 4096 x 24 = 96Kbyte.
 *
 * The maximum entries are prepared when a zone's memory is (512K + 256) pages
 * or more by the traditional way. (See above).  It equals:
 *
 *    i386, x86-64, powerpc(4K page size) : =  ( 2G + 1M)byte.
 *    ia64(16K page size)                 : =  ( 8G + 4M)byte.
 *    powerpc (64K page size)             : =  (32G +16M)byte.
 */
static inline unsigned long wait_table_hash_nr_entries(unsigned long pages)
{
	return 4096UL;
}
#endif

/*
 * This is an integer logarithm so that shifts can be used later
 * to extract the more random high bits from the multiplicative
 * hash function before the remainder is taken.
 */
static inline unsigned long wait_table_bits(unsigned long size)
{
	return ffz(~size);
}

#define LONG_ALIGN(x) (((x)+(sizeof(long))-1)&~((sizeof(long))-1))

/*
 * Mark a number of pageblocks as MIGRATE_RESERVE. The number
 * of blocks reserved is based on zone->pages_min. The memory within the
 * reserve will tend to store contiguous free pages. Setting min_free_kbytes
 * higher will lead to a bigger reserve which will get freed as contiguous
 * blocks as reclaim kicks in
 *
 * 确定zone中一些page的miggrate类型
 */
static void setup_zone_migrate_reserve(struct zone *zone)
{
	unsigned long start_pfn, pfn, end_pfn;
	struct page *page;
	unsigned long reserve, block_migratetype;

	/* Get the start pfn, end pfn and the number of blocks to reserve */
	start_pfn = zone->zone_start_pfn;
	end_pfn = start_pfn + zone->spanned_pages;
	reserve = roundup(zone->pages_min, pageblock_nr_pages) >>
							pageblock_order;

	for (pfn = start_pfn; pfn < end_pfn; pfn += pageblock_nr_pages) {
		if (!pfn_valid(pfn))
			continue;
		
		page = pfn_to_page(pfn);

		/* Blocks with reserved pages will never free, skip them. */
		if (PageReserved(page))
			continue;

		block_migratetype = get_pageblock_migratetype(page);

		/* If this block is reserved, account for it */
		if (reserve > 0 && block_migratetype == MIGRATE_RESERVE) {
			reserve--;
			continue;
		}

		/* Suitable for reserving if this block is movable */
		if (reserve > 0 && block_migratetype == MIGRATE_MOVABLE) {
			
			set_pageblock_migratetype(page, MIGRATE_RESERVE);
			move_freepages_block(zone, page, MIGRATE_RESERVE);
			reserve--;
			continue;
		}

		/*
		 * If the reserve is met and this is a previous reserved block,
		 * take it back
		 */
		if (block_migratetype == MIGRATE_RESERVE) {
			set_pageblock_migratetype(page, MIGRATE_MOVABLE);
			move_freepages_block(zone, page, MIGRATE_MOVABLE);
		}
	}
}

/*
 * Initially all pages are reserved - free ones are freed
 * up by free_all_bootmem() once the early boot process is
 * done. Non-atomic initialization, single-pass.
 *
 *设置所有的page为MIGRATE_MOVABLE
 
 * start_kernel()
 *  setup_arch()
 *   zone_sizes_init()
 *    free_area_init_nodes()
 *     free_area_init_node()
 *      free_area_init_core()
 *       memmap_init_zone()
 *      
 */
void __meminit memmap_init_zone(unsigned long size, int nid, unsigned long zone,
		unsigned long start_pfn, enum memmap_context context)
{
	struct page *page;
	unsigned long end_pfn = start_pfn + size;
	unsigned long pfn;

	for (pfn = start_pfn; pfn < end_pfn; pfn++) {
		/*
		 * There can be holes in boot-time mem_map[]s
		 * handed to this function.  They do not
		 * exist on hotplugged memory.
		 */
		if (context == MEMMAP_EARLY) {
			if (!early_pfn_valid(pfn))
				continue;
			if (!early_pfn_in_nid(pfn, nid))
				continue;
		}
		page = pfn_to_page(pfn);
		/* 设置page所属的zone和node id */
		set_page_links(page, zone, nid, pfn);
		init_page_count(page);
		reset_page_mapcount(page);
		SetPageReserved(page);  /* 把page设置为PG_reserved状态 */

		/*
		 * Mark the block movable so that blocks are reserved for
		 * movable at startup. This will force kernel allocations
		 * to reserve their blocks rather than leaking throughout
		 * the address space during boot when many long-lived
		 * kernel allocations are made. Later some blocks near
		 * the start are marked MIGRATE_RESERVE by
		 * setup_zone_migrate_reserve()
		 *
		 * 设置所有的page为MIGRATE_MOVABLE
		 *
		 */
		if ((pfn & (pageblock_nr_pages-1)))
			set_pageblock_migratetype(page, MIGRATE_MOVABLE);

		INIT_LIST_HEAD(&page->lru);
#ifdef WANT_PAGE_VIRTUAL
		/* The shift won't overflow because ZONE_NORMAL is below 4G. */
		if (!is_highmem_idx(zone))
			set_page_address(page, __va(pfn << PAGE_SHIFT));
#endif
	}
}


/*
 *
 * start_kernel()
 *	setup_arch()
 *	 zone_sizes_init()
 *	  free_area_init_nodes()
 *	   free_area_init_node()
 *		free_area_init_core()
 *		 init_currently_empty_zone()
 *        zone_init_free_lists()
 *
 */
static void __meminit zone_init_free_lists(struct pglist_data *pgdat,
				struct zone *zone, unsigned long size)
{
	int order, t;
	for_each_migratetype_order(order, t) {
		INIT_LIST_HEAD(&zone->free_area[order].free_list[t]);
		zone->free_area[order].nr_free = 0;
	}
}

#ifndef __HAVE_ARCH_MEMMAP_INIT
#define memmap_init(size, nid, zone, start_pfn) \
	memmap_init_zone((size), (nid), (zone), (start_pfn), MEMMAP_EARLY)
#endif

static int zone_batchsize(struct zone *zone)
{
	int batch;

	/*
	 * The per-cpu-pages pools are set to around 1000th of the
	 * size of the zone.  But no more than 1/2 of a meg.
	 *
	 * OK, so we don't know how big the cache is.  So guess.
	 */
	batch = zone->present_pages / 1024;
	if (batch * PAGE_SIZE > 512 * 1024)
		batch = (512 * 1024) / PAGE_SIZE;
	batch /= 4;		/* We effectively *= 4 below */
	if (batch < 1)
		batch = 1;

	/*
	 * Clamp the batch to a 2^n - 1 value. Having a power
	 * of 2 value was found to be more likely to have
	 * suboptimal cache aliasing properties in some cases.
	 *
	 * For example if 2 tasks are alternately allocating
	 * batches of pages, one task can end up with a lot
	 * of pages of one half of the possible page colors
	 * and the other with pages of the other colors.
	 */
	batch = (1 << (fls(batch + batch/2)-1)) - 1;

	return batch;
}


/*
 * 初始化 per_cpu_pageset->pcp[0],per_cpu_pageset->pcp[1]
 *
 * start_kernel()
 *  setup_arch()
 *   zone_sizes_init()
 *    free_area_init_nodes()
 *     free_area_init_node()
 *      free_area_init_core()
 *       zone_pcp_init() 
 *        setup_pageset()
 */
inline void setup_pageset(struct per_cpu_pageset *p, unsigned long batch)
{
	struct per_cpu_pages *pcp;

	memset(p, 0, sizeof(*p));

	pcp = &p->pcp[0];		/* hot */
	pcp->count = 0;
	pcp->high = 6 * batch;
	pcp->batch = max(1UL, 1 * batch);
	INIT_LIST_HEAD(&pcp->list);

	pcp = &p->pcp[1];		/* cold*/
	pcp->count = 0;
	pcp->high = 2 * batch;
	pcp->batch = max(1UL, batch/2);
	INIT_LIST_HEAD(&pcp->list);
}

/*
 * setup_pagelist_highmark() sets the high water mark for hot per_cpu_pagelist
 * to the value high for the pageset p.
 */

static void setup_pagelist_highmark(struct per_cpu_pageset *p,
				unsigned long high)
{
	struct per_cpu_pages *pcp;

	pcp = &p->pcp[0]; /* hot list */
	pcp->high = high;
	pcp->batch = max(1UL, high/4);
	if ((high/4) > (PAGE_SHIFT * 8))
		pcp->batch = PAGE_SHIFT * 8;
}


#ifdef CONFIG_NUMA
/*
 * Boot pageset table. One per cpu which is going to be used for all
 * zones and all nodes. The parameters will be set in such a way
 * that an item put on a list will immediately be handed over to
 * the buddy list. This is safe since pageset manipulation is done
 * with interrupts disabled.
 *
 * Some NUMA counter updates may also be caught by the boot pagesets.
 *
 * The boot_pagesets must be kept even after bootup is complete for
 * unused processors and/or zones. They do play a role for bootstrapping
 * hotplugged processors.
 *
 * zoneinfo_show() and maybe other functions do
 * not check if the processor is online before following the pageset pointer.
 * Other parts of the kernel may not check if the zone is available.
 */
static struct per_cpu_pageset boot_pageset[NR_CPUS];

/*
 * Dynamically allocate memory for the
 * per cpu pageset array in struct zone.
 *
 * start_kernel()
 *  setup_per_cpu_pageset()
 *   process_zones()
 *
 */
static int __cpuinit process_zones(int cpu)
{
	struct zone *zone, *dzone;
	int node = cpu_to_node(cpu);

	node_set_state(node, N_CPU);	/* this node has a cpu */

	for_each_zone(zone) {

		if (!populated_zone(zone))
			continue;

		zone_pcp(zone, cpu) = kmalloc_node(sizeof(struct per_cpu_pageset),
					 GFP_KERNEL, node);
		if (!zone_pcp(zone, cpu))
			goto bad;

		setup_pageset(zone_pcp(zone, cpu), zone_batchsize(zone));

		if (percpu_pagelist_fraction)
			setup_pagelist_highmark(zone_pcp(zone, cpu),
			 	(zone->present_pages / percpu_pagelist_fraction));
	}

	return 0;
bad:
	for_each_zone(dzone) {
		if (!populated_zone(dzone))
			continue;
		if (dzone == zone)
			break;
		kfree(zone_pcp(dzone, cpu));
		zone_pcp(dzone, cpu) = NULL;
	}
	return -ENOMEM;
}

static inline void free_zone_pagesets(int cpu)
{
	struct zone *zone;

	for_each_zone(zone) {
		struct per_cpu_pageset *pset = zone_pcp(zone, cpu);

		/* Free per_cpu_pageset if it is slab allocated */
		if (pset != &boot_pageset[cpu])
			kfree(pset);
		zone_pcp(zone, cpu) = NULL;
	}
}

static int __cpuinit pageset_cpuup_callback(struct notifier_block *nfb,
		unsigned long action,
		void *hcpu)
{
	int cpu = (long)hcpu;
	int ret = NOTIFY_OK;

	switch (action) {
	case CPU_UP_PREPARE:
	case CPU_UP_PREPARE_FROZEN:
		if (process_zones(cpu))
			ret = NOTIFY_BAD;
		break;
	case CPU_UP_CANCELED:
	case CPU_UP_CANCELED_FROZEN:
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		free_zone_pagesets(cpu);
		break;
	default:
		break;
	}
	return ret;
}

static struct notifier_block __cpuinitdata pageset_notifier =
	{ &pageset_cpuup_callback, NULL, 0 };

/*
 * start_kernel()
 *  setup_per_cpu_pageset()
 *   
 */
void __init setup_per_cpu_pageset(void)
{
	int err;

	/* Initialize per_cpu_pageset for cpu 0.
	 * A cpuup callback will do this for every cpu
	 * as it comes online
	 */
	err = process_zones(smp_processor_id());
	BUG_ON(err);
	register_cpu_notifier(&pageset_notifier);
}

#endif

static noinline __init_refok
int zone_wait_table_init(struct zone *zone, unsigned long zone_size_pages)
{
	int i;
	struct pglist_data *pgdat = zone->zone_pgdat;
	size_t alloc_size;

	/*
	 * The per-page waitqueue mechanism uses hashed waitqueues
	 * per zone.
	 */
	zone->wait_table_hash_nr_entries =
		 wait_table_hash_nr_entries(zone_size_pages);
	zone->wait_table_bits =
		wait_table_bits(zone->wait_table_hash_nr_entries);
	alloc_size = zone->wait_table_hash_nr_entries
					* sizeof(wait_queue_head_t);

 	if (system_state == SYSTEM_BOOTING) {
		zone->wait_table = (wait_queue_head_t *)
			alloc_bootmem_node(pgdat, alloc_size);
	} else {
		/*
		 * This case means that a zone whose size was 0 gets new memory
		 * via memory hot-add.
		 * But it may be the case that a new node was hot-added.  In
		 * this case vmalloc() will not be able to use this new node's
		 * memory - this wait_table must be initialized to use this new
		 * node itself as well.
		 * To use this new node's memory, further consideration will be
		 * necessary.
		 */
		zone->wait_table = vmalloc(alloc_size);
	}
	if (!zone->wait_table)
		return -ENOMEM;

	for(i = 0; i < zone->wait_table_hash_nr_entries; ++i)
		init_waitqueue_head(zone->wait_table + i);

	return 0;
}

/*
 * start_kernel()
 *  setup_arch()
 *   zone_sizes_init()
 *    free_area_init_nodes()
 *     free_area_init_node()
 *      free_area_init_core()
 *       zone_pcp_init()
 *
 * 初始化zone->pageset数组成员，只是建立空链表而已
 */
static __meminit void zone_pcp_init(struct zone *zone)
{
	int cpu;
	/* batch 约等于 1/1000 RAM */
	unsigned long batch = zone_batchsize(zone);

	for (cpu = 0; cpu < NR_CPUS; cpu++) {
#ifdef CONFIG_NUMA
		/* Early boot. Slab allocator not functional yet */
		zone_pcp(zone, cpu) = &boot_pageset[cpu];
		setup_pageset(&boot_pageset[cpu],0);
#else
		setup_pageset(zone_pcp(zone,cpu), batch);
#endif
	}
	if (zone->present_pages)
		printk(KERN_DEBUG "  %s zone: %lu pages, LIFO batch:%lu\n",
			zone->name, zone->present_pages, batch);
}

/*
 *
 * start_kernel()
 *  setup_arch()
 *   zone_sizes_init()
 *    free_area_init_nodes()
 *     free_area_init_node()
 *      free_area_init_core()
 *       init_currently_empty_zone()
 *
 */
__meminit int init_currently_empty_zone(struct zone *zone,
					unsigned long zone_start_pfn,
					unsigned long size,
					enum memmap_context context)
{
	struct pglist_data *pgdat = zone->zone_pgdat;
	int ret;
	ret = zone_wait_table_init(zone, size);
	if (ret)
		return ret;
	pgdat->nr_zones = zone_idx(zone) + 1;

	zone->zone_start_pfn = zone_start_pfn;

	memmap_init(size, pgdat->node_id, zone_idx(zone), zone_start_pfn);

	zone_init_free_lists(pgdat, zone, zone->spanned_pages);

	return 0;
}

#ifdef CONFIG_ARCH_POPULATES_NODE_MAP
/*
 * Basic iterator support. Return the first range of PFNs for a node
 * Note: nid == MAX_NUMNODES returns first region regardless of node
 */
static int __meminit first_active_region_index_in_nid(int nid)
{
	int i;

	for (i = 0; i < nr_nodemap_entries; i++)
		if (nid == MAX_NUMNODES || early_node_map[i].nid == nid)
			return i;

	return -1;
}

/*
 * Basic iterator support. Return the next active range of PFNs for a node
 * Note: nid == MAX_NUMNODES returns next region regardless of node
 */
static int __meminit next_active_region_index_in_nid(int index, int nid)
{
	for (index = index + 1; index < nr_nodemap_entries; index++)
		if (nid == MAX_NUMNODES || early_node_map[index].nid == nid)
			return index;

	return -1;
}

#ifndef CONFIG_HAVE_ARCH_EARLY_PFN_TO_NID
/*
 * Required by SPARSEMEM. Given a PFN, return what node the PFN is on.
 * Architectures may implement their own version but if add_active_range()
 * was used and there are no special requirements, this is a convenient
 * alternative
 */
int __meminit early_pfn_to_nid(unsigned long pfn)
{
	int i;

	for (i = 0; i < nr_nodemap_entries; i++) {
		unsigned long start_pfn = early_node_map[i].start_pfn;
		unsigned long end_pfn = early_node_map[i].end_pfn;

		if (start_pfn <= pfn && pfn < end_pfn)
			return early_node_map[i].nid;
	}

	return 0;
}
#endif /* CONFIG_HAVE_ARCH_EARLY_PFN_TO_NID */

/* Basic iterator support to walk early_node_map[] */
#define for_each_active_range_index_in_nid(i, nid) \
	for (i = first_active_region_index_in_nid(nid); i != -1; \
				i = next_active_region_index_in_nid(i, nid))

/**
 * free_bootmem_with_active_regions - Call free_bootmem_node for each active range
 * @nid: The node to free memory on. If MAX_NUMNODES, all nodes are freed.
 * @max_low_pfn: The highest PFN that will be passed to free_bootmem_node
 *
 * If an architecture guarantees that all ranges registered with
 * add_active_ranges() contain no holes and may be freed, this
 * this function may be used instead of calling free_bootmem() manually.
 */
void __init free_bootmem_with_active_regions(int nid,
						unsigned long max_low_pfn)
{
	int i;

	for_each_active_range_index_in_nid(i, nid) {
		unsigned long size_pages = 0;
		unsigned long end_pfn = early_node_map[i].end_pfn;

		if (early_node_map[i].start_pfn >= max_low_pfn)
			continue;

		if (end_pfn > max_low_pfn)
			end_pfn = max_low_pfn;

		size_pages = end_pfn - early_node_map[i].start_pfn;
		free_bootmem_node(NODE_DATA(early_node_map[i].nid),
				PFN_PHYS(early_node_map[i].start_pfn),
				size_pages << PAGE_SHIFT);
	}
}

/**
 * sparse_memory_present_with_active_regions - Call memory_present for each active range
 * @nid: The node to call memory_present for. If MAX_NUMNODES, all nodes will be used.
 *
 * If an architecture guarantees that all ranges registered with
 * add_active_ranges() contain no holes and may be freed, this
 * function may be used instead of calling memory_present() manually.
 */
void __init sparse_memory_present_with_active_regions(int nid)
{
	int i;

	for_each_active_range_index_in_nid(i, nid)
		memory_present(early_node_map[i].nid,
				early_node_map[i].start_pfn,
				early_node_map[i].end_pfn);
}

/**
 * push_node_boundaries - Push node boundaries to at least the requested boundary
 * @nid: The nid of the node to push the boundary for
 * @start_pfn: The start pfn of the node
 * @end_pfn: The end pfn of the node
 *
 * In reserve-based hot-add, mem_map is allocated that is unused until hotadd
 * time. Specifically, on x86_64, SRAT will report ranges that can potentially
 * be hotplugged even though no physical memory exists. This function allows
 * an arch to push out the node boundaries so mem_map is allocated that can
 * be used later.
 */
#ifdef CONFIG_MEMORY_HOTPLUG_RESERVE
void __init push_node_boundaries(unsigned int nid,
		unsigned long start_pfn, unsigned long end_pfn)
{
	printk(KERN_DEBUG "Entering push_node_boundaries(%u, %lu, %lu)\n",
			nid, start_pfn, end_pfn);

	/* Initialise the boundary for this node if necessary */
	if (node_boundary_end_pfn[nid] == 0)
		node_boundary_start_pfn[nid] = -1UL;

	/* Update the boundaries */
	if (node_boundary_start_pfn[nid] > start_pfn)
		node_boundary_start_pfn[nid] = start_pfn;
	if (node_boundary_end_pfn[nid] < end_pfn)
		node_boundary_end_pfn[nid] = end_pfn;
}

/* If necessary, push the node boundary out for reserve hotadd */
static void __meminit account_node_boundary(unsigned int nid,
		unsigned long *start_pfn, unsigned long *end_pfn)
{
	printk(KERN_DEBUG "Entering account_node_boundary(%u, %lu, %lu)\n",
			nid, *start_pfn, *end_pfn);

	/* Return if boundary information has not been provided */
	if (node_boundary_end_pfn[nid] == 0)
		return;

	/* Check the boundaries and update if necessary */
	if (node_boundary_start_pfn[nid] < *start_pfn)
		*start_pfn = node_boundary_start_pfn[nid];
	if (node_boundary_end_pfn[nid] > *end_pfn)
		*end_pfn = node_boundary_end_pfn[nid];
}
#else
void __init push_node_boundaries(unsigned int nid,
		unsigned long start_pfn, unsigned long end_pfn) {}

static void __meminit account_node_boundary(unsigned int nid,
		unsigned long *start_pfn, unsigned long *end_pfn) {}
#endif


/**
 * get_pfn_range_for_nid - Return the start and end page frames for a node
 * @nid: The nid to return the range for. If MAX_NUMNODES, the min and max PFN are returned.
 * @start_pfn: Passed by reference. On return, it will have the node start_pfn.
 * @end_pfn: Passed by reference. On return, it will have the node end_pfn.
 *
 * It returns the start and end page frame of a node based on information
 * provided by an arch calling add_active_range(). If called for a node
 * with no available memory, a warning is printed and the start and end
 * PFNs will be 0.
 */
void __meminit get_pfn_range_for_nid(unsigned int nid,
			unsigned long *start_pfn, unsigned long *end_pfn)
{
	int i;
	*start_pfn = -1UL;
	*end_pfn = 0;

	for_each_active_range_index_in_nid(i, nid) {
		*start_pfn = min(*start_pfn, early_node_map[i].start_pfn);
		*end_pfn = max(*end_pfn, early_node_map[i].end_pfn);
	}

	if (*start_pfn == -1UL)
		*start_pfn = 0;

	/* Push the node boundaries out if requested */
	account_node_boundary(nid, start_pfn, end_pfn);
}

/*
 * This finds a zone that can be used for ZONE_MOVABLE pages. The
 * assumption is made that zones within a node are ordered in monotonic
 * increasing memory addresses so that the "highest" populated zone is used
 */
void __init find_usable_zone_for_movable(void)
{
	int zone_index;
	for (zone_index = MAX_NR_ZONES - 1; zone_index >= 0; zone_index--) {
		if (zone_index == ZONE_MOVABLE)
			continue;

		if (arch_zone_highest_possible_pfn[zone_index] >
				arch_zone_lowest_possible_pfn[zone_index])
			break;
	}

	VM_BUG_ON(zone_index == -1);
	movable_zone = zone_index;
}

/*
 * The zone ranges provided by the architecture do not include ZONE_MOVABLE
 * because it is sized independant of architecture. Unlike the other zones,
 * the starting point for ZONE_MOVABLE is not fixed. It may be different
 * in each node depending on the size of each node and how evenly kernelcore
 * is distributed. This helper function adjusts the zone ranges
 * provided by the architecture for a given node by using the end of the
 * highest usable zone for ZONE_MOVABLE. This preserves the assumption that
 * zones within a node are in order of monotonic increases memory addresses
 */
void __meminit adjust_zone_range_for_zone_movable(int nid,
					unsigned long zone_type,
					unsigned long node_start_pfn,
					unsigned long node_end_pfn,
					unsigned long *zone_start_pfn,
					unsigned long *zone_end_pfn)
{
	/* Only adjust if ZONE_MOVABLE is on this node */
	if (zone_movable_pfn[nid]) {
		/* Size ZONE_MOVABLE */
		if (zone_type == ZONE_MOVABLE) {
			*zone_start_pfn = zone_movable_pfn[nid];
			*zone_end_pfn = min(node_end_pfn,
				arch_zone_highest_possible_pfn[movable_zone]);

		/* Adjust for ZONE_MOVABLE starting within this range */
		} else if (*zone_start_pfn < zone_movable_pfn[nid] &&
				*zone_end_pfn > zone_movable_pfn[nid]) {
			*zone_end_pfn = zone_movable_pfn[nid];

		/* Check if this whole range is within ZONE_MOVABLE */
		} else if (*zone_start_pfn >= zone_movable_pfn[nid])
			*zone_start_pfn = *zone_end_pfn;
	}
}

/*
 * Return the number of pages a zone spans in a node, including holes
 * present_pages = zone_spanned_pages_in_node() - zone_absent_pages_in_node()
 */
static unsigned long __meminit zone_spanned_pages_in_node(int nid,
					unsigned long zone_type,
					unsigned long *ignored)
{
	unsigned long node_start_pfn, node_end_pfn;
	unsigned long zone_start_pfn, zone_end_pfn;

	/* Get the start and end of the node and zone */
	get_pfn_range_for_nid(nid, &node_start_pfn, &node_end_pfn);
	zone_start_pfn = arch_zone_lowest_possible_pfn[zone_type];
	zone_end_pfn = arch_zone_highest_possible_pfn[zone_type];
	adjust_zone_range_for_zone_movable(nid, zone_type,
				node_start_pfn, node_end_pfn,
				&zone_start_pfn, &zone_end_pfn);

	/* Check that this node has pages within the zone's required range */
	if (zone_end_pfn < node_start_pfn || zone_start_pfn > node_end_pfn)
		return 0;

	/* Move the zone boundaries inside the node if necessary */
	zone_end_pfn = min(zone_end_pfn, node_end_pfn);
	zone_start_pfn = max(zone_start_pfn, node_start_pfn);

	/* Return the spanned pages */
	return zone_end_pfn - zone_start_pfn;
}

/*
 * Return the number of holes in a range on a node. If nid is MAX_NUMNODES,
 * then all holes in the requested range will be accounted for.
 */
unsigned long __meminit __absent_pages_in_range(int nid,
				unsigned long range_start_pfn,
				unsigned long range_end_pfn)
{
	int i = 0;
	unsigned long prev_end_pfn = 0, hole_pages = 0;
	unsigned long start_pfn;

	/* Find the end_pfn of the first active range of pfns in the node */
	i = first_active_region_index_in_nid(nid);
	if (i == -1)
		return 0;

	prev_end_pfn = min(early_node_map[i].start_pfn, range_end_pfn);

	/* Account for ranges before physical memory on this node */
	if (early_node_map[i].start_pfn > range_start_pfn)
		hole_pages = prev_end_pfn - range_start_pfn;

	/* Find all holes for the zone within the node */
	for (; i != -1; i = next_active_region_index_in_nid(i, nid)) {

		/* No need to continue if prev_end_pfn is outside the zone */
		if (prev_end_pfn >= range_end_pfn)
			break;

		/* Make sure the end of the zone is not within the hole */
		start_pfn = min(early_node_map[i].start_pfn, range_end_pfn);
		prev_end_pfn = max(prev_end_pfn, range_start_pfn);

		/* Update the hole size cound and move on */
		if (start_pfn > range_start_pfn) {
			BUG_ON(prev_end_pfn > start_pfn);
			hole_pages += start_pfn - prev_end_pfn;
		}
		prev_end_pfn = early_node_map[i].end_pfn;
	}

	/* Account for ranges past physical memory on this node */
	if (range_end_pfn > prev_end_pfn)
		hole_pages += range_end_pfn -
				max(range_start_pfn, prev_end_pfn);

	return hole_pages;
}

/**
 * absent_pages_in_range - Return number of page frames in holes within a range
 * @start_pfn: The start PFN to start searching for holes
 * @end_pfn: The end PFN to stop searching for holes
 *
 * It returns the number of pages frames in memory holes within a range.
 */
unsigned long __init absent_pages_in_range(unsigned long start_pfn,
							unsigned long end_pfn)
{
	return __absent_pages_in_range(MAX_NUMNODES, start_pfn, end_pfn);
}

/* Return the number of page frames in holes in a zone on a node */
static unsigned long __meminit zone_absent_pages_in_node(int nid,
					unsigned long zone_type,
					unsigned long *ignored)
{
	unsigned long node_start_pfn, node_end_pfn;
	unsigned long zone_start_pfn, zone_end_pfn;

	get_pfn_range_for_nid(nid, &node_start_pfn, &node_end_pfn);
	zone_start_pfn = max(arch_zone_lowest_possible_pfn[zone_type],
							node_start_pfn);
	zone_end_pfn = min(arch_zone_highest_possible_pfn[zone_type],
							node_end_pfn);

	adjust_zone_range_for_zone_movable(nid, zone_type,
			node_start_pfn, node_end_pfn,
			&zone_start_pfn, &zone_end_pfn);
	return __absent_pages_in_range(nid, zone_start_pfn, zone_end_pfn);
}

#else
static inline unsigned long __meminit zone_spanned_pages_in_node(int nid,
					unsigned long zone_type,
					unsigned long *zones_size)
{
	return zones_size[zone_type];
}

static inline unsigned long __meminit zone_absent_pages_in_node(int nid,
						unsigned long zone_type,
						unsigned long *zholes_size)
{
	if (!zholes_size)
		return 0;

	return zholes_size[zone_type];
}

#endif

static void __meminit calculate_node_totalpages(struct pglist_data *pgdat,
		unsigned long *zones_size, unsigned long *zholes_size)
{
	unsigned long realtotalpages, totalpages = 0;
	enum zone_type i;

	for (i = 0; i < MAX_NR_ZONES; i++)
		totalpages += zone_spanned_pages_in_node(pgdat->node_id, i,
								zones_size);
	pgdat->node_spanned_pages = totalpages;

	realtotalpages = totalpages;
	for (i = 0; i < MAX_NR_ZONES; i++)
		realtotalpages -=
			zone_absent_pages_in_node(pgdat->node_id, i,
								zholes_size);
	pgdat->node_present_pages = realtotalpages;
	printk(KERN_DEBUG "On node %d totalpages: %lu\n", pgdat->node_id,
							realtotalpages);
}

#ifndef CONFIG_SPARSEMEM
/*
 * Calculate the size of the zone->blockflags rounded to an unsigned long
 * Start by making sure zonesize is a multiple of pageblock_order by rounding
 * up. Then use 1 NR_PAGEBLOCK_BITS worth of bits per pageblock, finally
 * round what is now in bits to nearest long in bits, then return it in
 * bytes.
 */
static unsigned long __init usemap_size(unsigned long zonesize /* page数量 */ )
{
    /* 比如zonesize==225280进来 */
	unsigned long usemapsize;

    /* 1024对齐 */
	/* 比如zonesize==225280进来,usemapsize==225280 */
	usemapsize = roundup(zonesize, pageblock_nr_pages /*1024*/  );

	/* 右移,低10位，抹掉,相当于有多少个pageblock */
	/* 比如zonesize==225280进来,usemapsize=220=11011100(二进制) */
	usemapsize = usemapsize >> pageblock_order /*10*/ ;

	/* 比如zonesize==225280进来,usemapsize=220*4=880 */
	/*
	 * 每NR_PAGEBLOCK_BITS个bit负责一个pageblock的migrate type
	 * 需要 pageblock个数* NR_PAGEBLOCK_BITS 的bit位
	 */
	usemapsize *= NR_PAGEBLOCK_BITS; /*在pageblock_bits中定义 */
	/* 8*32对齐 */
	/* 比如zonesize==225280进来, usemapsize==8*32*/
	usemapsize = roundup(usemapsize, 8 * sizeof(unsigned long));

	return usemapsize / 8; /* 转成字节  */
}

/*
 * start_kernel()
 *  setup_arch()
 *   zone_sizes_init()
 *    free_area_init_nodes()
 *     free_area_init_node()
 *      free_area_init_core()
 *       setup_usemap()
 */
static void __init setup_usemap(struct pglist_data *pgdat,
				struct zone *zone, unsigned long zonesize /* zone中的page数量 */ )
{
    /*  zone->blockflags的大小 */
	unsigned long usemapsize = usemap_size(zonesize);
	
	zone->pageblock_flags = NULL;
	if (usemapsize) {
		zone->pageblock_flags = alloc_bootmem_node(pgdat, usemapsize);
		memset(zone->pageblock_flags, 0, usemapsize);
	}
}
#else
static void inline setup_usemap(struct pglist_data *pgdat,
				struct zone *zone, unsigned long zonesize) {}
#endif /* CONFIG_SPARSEMEM */

#ifdef CONFIG_HUGETLB_PAGE_SIZE_VARIABLE

/* Return a sensible default order for the pageblock size. */
static inline int pageblock_default_order(void)
{
	if (HPAGE_SHIFT > PAGE_SHIFT)
		return HUGETLB_PAGE_ORDER;

	return MAX_ORDER-1;
}

/* Initialise the number of pages represented by NR_PAGEBLOCK_BITS */
static inline void __init set_pageblock_order(unsigned int order)
{
	/* Check that pageblock_nr_pages has not already been setup */
	if (pageblock_order)
		return;

	/*
	 * Assume the largest contiguous order of interest is a huge page.
	 * This value may be variable depending on boot parameters on IA64
	 */
	pageblock_order = order;
}
#else /* CONFIG_HUGETLB_PAGE_SIZE_VARIABLE */

/*
 * When CONFIG_HUGETLB_PAGE_SIZE_VARIABLE is not set, set_pageblock_order()
 * and pageblock_default_order() are unused as pageblock_order is set
 * at compile-time. See include/linux/pageblock-flags.h for the values of
 * pageblock_order based on the kernel config
 */
static inline int pageblock_default_order(unsigned int order)
{
	return MAX_ORDER-1;
}
#define set_pageblock_order(x)	do {} while (0)

#endif /* CONFIG_HUGETLB_PAGE_SIZE_VARIABLE */

/*
 * Set up the zone data structures:
 *   - mark all pages reserved
 *   - mark all memory queues empty
 *   - clear the memory bitmaps
 *
 *
 *
 * start_kernel()
 *  setup_arch()
 *   zone_sizes_init()
 *    free_area_init_nodes()
 *     free_area_init_node()
 *      free_area_init_core()
 */
static void __meminit free_area_init_core(struct pglist_data *pgdat,
		unsigned long *zones_size, unsigned long *zholes_size)
{
	enum zone_type j;
	int nid = pgdat->node_id;
	unsigned long zone_start_pfn = pgdat->node_start_pfn;
	int ret;

	pgdat_resize_init(pgdat);
	pgdat->nr_zones = 0;

    /*
     * 当有进程在pgdat上申请内存时，内存又不够，在pgdat->kswapd_wait
     * 上等待.
	 */	
	init_waitqueue_head(&pgdat->kswapd_wait);
	pgdat->kswapd_max_order = 0;

	/* 初始化free_area */
	for (j = 0; j < MAX_NR_ZONES; j++) {
		/* 一个个的zone处理 */
		struct zone *zone = pgdat->node_zones + j;
		unsigned long size, realsize, memmap_pages;

        /* size为page的数量，包括hole  */
		size = zone_spanned_pages_in_node(nid, j, zones_size);
		/*   实际的page数量 */
		realsize = size - zone_absent_pages_in_node(nid, j,
								zholes_size);

		/*
		 * Adjust realsize so that it accounts for how much memory
		 * is used by this zone for memmap. This affects the watermark
		 * and per-cpu initialisations
		 * 
		 * 初始化空闲链表
		 */
		memmap_pages = (size * sizeof(struct page)) >> PAGE_SHIFT;
		
		if (realsize >= memmap_pages) {
			/* 够用，符合调剂 */
			realsize -= memmap_pages;
			printk(KERN_DEBUG
				"  %s zone: %lu pages used for memmap\n",
				zone_names[j], memmap_pages);
		} else
			printk(KERN_WARNING
				"  %s zone: %lu pages exceeds realsize %lu\n",
				zone_names[j], memmap_pages, realsize);

		/* Account for reserved pages */
		if (j == 0 && realsize > dma_reserve) {
			realsize -= dma_reserve;
			printk(KERN_DEBUG "  %s zone: %lu pages reserved\n",
					zone_names[0], dma_reserve);
		}

		if (!is_highmem_idx(j))
			nr_kernel_pages += realsize;
		
		nr_all_pages += realsize;

		zone->spanned_pages = size;
		zone->present_pages = realsize;
#ifdef CONFIG_NUMA
		zone->node = nid;
		zone->min_unmapped_pages = (realsize*sysctl_min_unmapped_ratio)
						/ 100;
		zone->min_slab_pages = (realsize * sysctl_min_slab_ratio) / 100;
#endif
		zone->name = zone_names[j];
		spin_lock_init(&zone->lock);
		spin_lock_init(&zone->lru_lock);
		zone_seqlock_init(zone);
		zone->zone_pgdat = pgdat;

		zone->prev_priority = DEF_PRIORITY;

		zone_pcp_init(zone);//初始化zone->pageset数组成员，只是建立空链表而已
		
		INIT_LIST_HEAD(&zone->active_list);
		INIT_LIST_HEAD(&zone->inactive_list);
		zone->nr_scan_active = 0;
		zone->nr_scan_inactive = 0;
		zap_zone_vm_stats(zone);
		zone->flags = 0;
		if (!size)
			continue;

		/*
		 * 如果没有配置 CONFIG_HUGETLB_PAGE_SIZE_VARIABLE= (MAX_ORDER-1) =10
		 * 即pageblock_order = 10
		 */
		set_pageblock_order(pageblock_default_order());
		// 申请位图内存,就是zone->pageblock_flags
		setup_usemap(pgdat, zone, size);

		/* 初始化zone->free_area[] */
		ret = init_currently_empty_zone(zone, zone_start_pfn,
						size, MEMMAP_EARLY);
		BUG_ON(ret);
		/* 下一个zone开始的page       pfn */
		zone_start_pfn += size;
	}
}

/*
 * start_kernel()
 *  setup_arch()
 *   zone_sizes_init()
 *    free_area_init_nodes()
 *     free_area_init_node()
 *      alloc_node_mem_map()
 */
static void __init_refok alloc_node_mem_map(struct pglist_data *pgdat)
{
	/* Skip empty nodes，内存节点中有hole */
	if (!pgdat->node_spanned_pages)
		return;

#ifdef CONFIG_FLAT_NODE_MEM_MAP
	/* ia64 gets its own node_mem_map, before this, without bootmem */
	if (!pgdat->node_mem_map) {
		unsigned long size, start, end;
		struct page *map;

		/*
		 * The zone's endpoints aren't required to be MAX_ORDER
		 * aligned but the node_mem_map endpoints must be in order
		 * for the buddy allocator to function correctly.
		 */
		start = pgdat->node_start_pfn & ~(MAX_ORDER_NR_PAGES - 1);
		end = pgdat->node_start_pfn + pgdat->node_spanned_pages;
		end = ALIGN(end, MAX_ORDER_NR_PAGES);
		size =  (end - start) * sizeof(struct page);
		map = alloc_remap(pgdat->node_id, size);
		if (!map)
			map = alloc_bootmem_node(pgdat, size);
		pgdat->node_mem_map = map + (pgdat->node_start_pfn - start);
	}
#ifndef CONFIG_NEED_MULTIPLE_NODES
	/*
	 * With no DISCONTIG, the global mem_map is just set as node 0's
	 */
	if (pgdat == NODE_DATA(0)) {
		mem_map = NODE_DATA(0)->node_mem_map;
#ifdef CONFIG_ARCH_POPULATES_NODE_MAP
		if (page_to_pfn(mem_map) != pgdat->node_start_pfn)
			mem_map -= (pgdat->node_start_pfn - ARCH_PFN_OFFSET);
#endif /* CONFIG_ARCH_POPULATES_NODE_MAP */
	}
#endif
#endif /* CONFIG_FLAT_NODE_MEM_MAP */
}

/*
 * 为指定的内存node初始化pglist_data结构 
 * start_kernel()
 *  setup_arch()
 *   zone_sizes_init()
 *    free_area_init_nodes()
 *     free_area_init_node()
 */
void __meminit free_area_init_node(int nid, struct pglist_data *pgdat,
		unsigned long *zones_size, unsigned long node_start_pfn,
		unsigned long *zholes_size)
{
	pgdat->node_id = nid;
	pgdat->node_start_pfn = node_start_pfn;

	/*
	 * 根据PFN计算该节点的总页面数，并保存到
	 * pgdat结构的node_present_pages,node_spanned_pages成员中
	 */
	calculate_node_totalpages(pgdat, zones_size, zholes_size);

    /*
     * 根据页面总数，向bootmem alloctor申请足够的page结构,
     * 并起始地址保存到pgdat的node_mem_map成员,以及全局变量mem_map数组中。
     * 数组中的第N项就对应第N个页面的page结构
	 */
	alloc_node_mem_map(pgdat);

    /* 初始化pgdat的各个zone */
	free_area_init_core(pgdat, zones_size, zholes_size);
}

#ifdef CONFIG_ARCH_POPULATES_NODE_MAP

#if MAX_NUMNODES > 1
/*
 * Figure out the number of possible node ids.
 *
 * start_kernel()
 *  setup_arch()
 *   zone_sizes_init()
 *    free_area_init_nodes()
 *     setup_nr_node_ids()
 */
static void __init setup_nr_node_ids(void)
{
	unsigned int node;
	unsigned int highest = 0;

	for_each_node_mask(node, node_possible_map)
		highest = node;
	nr_node_ids = highest + 1;
}
#else
static inline void setup_nr_node_ids(void)
{
}
#endif

/**
 * add_active_range - Register a range of PFNs backed by physical memory
 *
 *  活动内存区就是不包含空洞的内存区,在early_node_map中登记
 *  由zone_sizes_init调用
 *
 * @nid: The node ID the range resides on
 * @start_pfn: The start PFN of the available physical memory
 * @end_pfn: The end PFN of the available physical memory
 *
 * These ranges are stored in an early_node_map[] and later used by
 * free_area_init_nodes() to calculate zone sizes and holes. If the
 * range spans a memory hole, it is up to the architecture to ensure
 * the memory is not freed by the bootmem allocator. If possible
 * the range being registered will be merged with existing ranges.
 *
 * start_kernel()
 *  setup_arch()
 *   zone_sizes_init()
 *    add_active_range()
 *
 * 把PFN的有效范围添加到early_node_map[]中，如果可以合并就合并
 */
void __init add_active_range(unsigned int nid, unsigned long start_pfn,
						unsigned long end_pfn)
{
	int i;

	printk(KERN_DEBUG "Entering add_active_range(%d, %lu, %lu) "
			  "%d entries of %d used\n",
			  nid, start_pfn, end_pfn,
			  nr_nodemap_entries, MAX_ACTIVE_REGIONS);

	/* Merge with existing active regions if possible 
	 * 看是否有合并的可能，如果能合并，就合并掉了。
     */
	for (i = 0; i < nr_nodemap_entries; i++) {
		if (early_node_map[i].nid != nid)
			continue;

		/* Skip if an existing region covers this new one */
		if (start_pfn >= early_node_map[i].start_pfn &&
				end_pfn <= early_node_map[i].end_pfn)
			return;

		/* Merge forward if suitable */
		if (start_pfn <= early_node_map[i].end_pfn &&
				end_pfn > early_node_map[i].end_pfn) {
			early_node_map[i].end_pfn = end_pfn;
			return;
		}

		/* Merge backward if suitable */
		if (start_pfn < early_node_map[i].end_pfn &&
				end_pfn >= early_node_map[i].start_pfn) {
			early_node_map[i].start_pfn = start_pfn;
			return;
		}
	}

	/* Check that early_node_map is large enough */
	if (i >= MAX_ACTIVE_REGIONS) {
		printk(KERN_CRIT "More than %d memory regions, truncating\n",
							MAX_ACTIVE_REGIONS);
		return;
	}

    /* 登记新的active range     */
	early_node_map[i].nid = nid;
	early_node_map[i].start_pfn = start_pfn;
	early_node_map[i].end_pfn = end_pfn;
	nr_nodemap_entries = i + 1; /* active range 总数 */
}

/**
 * shrink_active_range - Shrink an existing registered range of PFNs
 * @nid: The node id the range is on that should be shrunk
 * @old_end_pfn: The old end PFN of the range
 * @new_end_pfn: The new PFN of the range
 *
 * i386 with NUMA use alloc_remap() to store a node_mem_map on a local node.
 * The map is kept at the end physical page range that has already been
 * registered with add_active_range(). This function allows an arch to shrink
 * an existing registered range.
 */
void __init shrink_active_range(unsigned int nid, unsigned long old_end_pfn,
						unsigned long new_end_pfn)
{
	int i;

	/* Find the old active region end and shrink */
	for_each_active_range_index_in_nid(i, nid)
		if (early_node_map[i].end_pfn == old_end_pfn) {
			early_node_map[i].end_pfn = new_end_pfn;
			break;
		}
}

/**
 * remove_all_active_ranges - Remove all currently registered regions
 *
 * During discovery, it may be found that a table like SRAT is invalid
 * and an alternative discovery method must be used. This function removes
 * all currently registered regions.
 */
void __init remove_all_active_ranges(void)
{
	memset(early_node_map, 0, sizeof(early_node_map));
	nr_nodemap_entries = 0;
#ifdef CONFIG_MEMORY_HOTPLUG_RESERVE
	memset(node_boundary_start_pfn, 0, sizeof(node_boundary_start_pfn));
	memset(node_boundary_end_pfn, 0, sizeof(node_boundary_end_pfn));
#endif /* CONFIG_MEMORY_HOTPLUG_RESERVE */
}

/* Compare two active node_active_regions */
static int __init cmp_node_active_region(const void *a, const void *b)
{
	struct node_active_region *arange = (struct node_active_region *)a;
	struct node_active_region *brange = (struct node_active_region *)b;

	/* Done this way to avoid overflows */
	if (arange->start_pfn > brange->start_pfn)
		return 1;
	if (arange->start_pfn < brange->start_pfn)
		return -1;

	return 0;
}

/* sort the node_map by start_pfn */
static void __init sort_node_map(void)
{
	sort(early_node_map, (size_t)nr_nodemap_entries,
			sizeof(struct node_active_region),
			cmp_node_active_region, NULL);
}

/* Find the lowest pfn for a node */
unsigned long __init find_min_pfn_for_node(unsigned long nid)
{
	int i;
	unsigned long min_pfn = ULONG_MAX;

	/* Assuming a sorted map, the first range found has the starting pfn */
	for_each_active_range_index_in_nid(i, nid)
		min_pfn = min(min_pfn, early_node_map[i].start_pfn);

	if (min_pfn == ULONG_MAX) {
		printk(KERN_WARNING
			"Could not find start_pfn for node %lu\n", nid);
		return 0;
	}

	return min_pfn;
}

/**
 * find_min_pfn_with_active_regions - Find the minimum PFN registered
 *
 * It returns the minimum PFN based on information provided via
 * add_active_range().
 */
unsigned long __init find_min_pfn_with_active_regions(void)
{
	return find_min_pfn_for_node(MAX_NUMNODES);
}

/**
 * find_max_pfn_with_active_regions - Find the maximum PFN registered
 *
 * It returns the maximum PFN based on information provided via
 * add_active_range().
 */
unsigned long __init find_max_pfn_with_active_regions(void)
{
	int i;
	unsigned long max_pfn = 0;

	for (i = 0; i < nr_nodemap_entries; i++)
		max_pfn = max(max_pfn, early_node_map[i].end_pfn);

	return max_pfn;
}

/*
 * early_calculate_totalpages()
 * Sum pages in active regions for movable zone.
 * Populate N_HIGH_MEMORY for calculating usable_nodes.
 */
static unsigned long __init early_calculate_totalpages(void)
{
	int i;
	unsigned long totalpages = 0;

	for (i = 0; i < nr_nodemap_entries; i++) {
		unsigned long pages = early_node_map[i].end_pfn -
						early_node_map[i].start_pfn;
		totalpages += pages;
		if (pages)
			node_set_state(early_node_map[i].nid, N_HIGH_MEMORY);
	}
  	return totalpages;
}

/*
 * Find the PFN the Movable zone begins in each node. Kernel memory
 * is spread evenly between nodes as long as the nodes have enough
 * memory. When they don't, some nodes will have more kernelcore than
 * others
 *
 * 计算ZONE_MOVABLE域的起始编号
 */
void __init find_zone_movable_pfns_for_nodes(unsigned long *movable_pfn)
{
	int i, nid;
	unsigned long usable_startpfn;
	unsigned long kernelcore_node, kernelcore_remaining;
	unsigned long totalpages = early_calculate_totalpages();
	int usable_nodes = nodes_weight(node_states[N_HIGH_MEMORY]);

	/*
	 * If movablecore was specified, calculate what size of
	 * kernelcore that corresponds so that memory usable for
	 * any allocation type is evenly spread. If both kernelcore
	 * and movablecore are specified, then the value of kernelcore
	 * will be used for required_kernelcore if it's greater than
	 * what movablecore would have allowed.
	 */
	if (required_movablecore) {
		unsigned long corepages;

		/*
		 * Round-up so that ZONE_MOVABLE is at least as large as what
		 * was requested by the user
		 */
		required_movablecore =
			roundup(required_movablecore, MAX_ORDER_NR_PAGES);
		corepages = totalpages - required_movablecore;

		required_kernelcore = max(required_kernelcore, corepages);
	}

	/* If kernelcore was not specified, there is no ZONE_MOVABLE */
	if (!required_kernelcore)
		return;

	/* usable_startpfn is the lowest possible pfn ZONE_MOVABLE can be at */
	find_usable_zone_for_movable();
	usable_startpfn = arch_zone_lowest_possible_pfn[movable_zone];

restart:
	/* Spread kernelcore memory as evenly as possible throughout nodes */
	kernelcore_node = required_kernelcore / usable_nodes;
	for_each_node_state(nid, N_HIGH_MEMORY) {
		/*
		 * Recalculate kernelcore_node if the division per node
		 * now exceeds what is necessary to satisfy the requested
		 * amount of memory for the kernel
		 */
		if (required_kernelcore < kernelcore_node)
			kernelcore_node = required_kernelcore / usable_nodes;

		/*
		 * As the map is walked, we track how much memory is usable
		 * by the kernel using kernelcore_remaining. When it is
		 * 0, the rest of the node is usable by ZONE_MOVABLE
		 */
		kernelcore_remaining = kernelcore_node;

		/* Go through each range of PFNs within this node */
		for_each_active_range_index_in_nid(i, nid) {
			unsigned long start_pfn, end_pfn;
			unsigned long size_pages;

			start_pfn = max(early_node_map[i].start_pfn,
						zone_movable_pfn[nid]);
			end_pfn = early_node_map[i].end_pfn;
			if (start_pfn >= end_pfn)
				continue;

			/* Account for what is only usable for kernelcore */
			if (start_pfn < usable_startpfn) {
				unsigned long kernel_pages;
				kernel_pages = min(end_pfn, usable_startpfn)
								- start_pfn;

				kernelcore_remaining -= min(kernel_pages,
							kernelcore_remaining);
				required_kernelcore -= min(kernel_pages,
							required_kernelcore);

				/* Continue if range is now fully accounted */
				if (end_pfn <= usable_startpfn) {

					/*
					 * Push zone_movable_pfn to the end so
					 * that if we have to rebalance
					 * kernelcore across nodes, we will
					 * not double account here
					 */
					zone_movable_pfn[nid] = end_pfn;
					continue;
				}
				start_pfn = usable_startpfn;
			}

			/*
			 * The usable PFN range for ZONE_MOVABLE is from
			 * start_pfn->end_pfn. Calculate size_pages as the
			 * number of pages used as kernelcore
			 */
			size_pages = end_pfn - start_pfn;
			if (size_pages > kernelcore_remaining)
				size_pages = kernelcore_remaining;
			zone_movable_pfn[nid] = start_pfn + size_pages;

			/*
			 * Some kernelcore has been met, update counts and
			 * break if the kernelcore for this node has been
			 * satisified
			 */
			required_kernelcore -= min(required_kernelcore,
								size_pages);
			kernelcore_remaining -= size_pages;
			if (!kernelcore_remaining)
				break;
		}
	}

	/*
	 * If there is still required_kernelcore, we do another pass with one
	 * less node in the count. This will push zone_movable_pfn[nid] further
	 * along on the nodes that still have memory until kernelcore is
	 * satisified
	 */
	usable_nodes--;
	if (usable_nodes && required_kernelcore > usable_nodes)
		goto restart;

	/* Align start of ZONE_MOVABLE on all nids to MAX_ORDER_NR_PAGES */
	for (nid = 0; nid < MAX_NUMNODES; nid++)
		zone_movable_pfn[nid] =
			roundup(zone_movable_pfn[nid], MAX_ORDER_NR_PAGES);
}

/* Any regular memory on that node ? 
   检查低于ZONE_HIGHMEM的内存域中是否有内存，并据此在节点位图中相应的设置N_NORMAL_MEMORY
*/
static void check_for_regular_memory(pg_data_t *pgdat)
{
#ifdef CONFIG_HIGHMEM
	enum zone_type zone_type;

	for (zone_type = 0; zone_type <= ZONE_NORMAL; zone_type++) {
		struct zone *zone = &pgdat->node_zones[zone_type];
		if (zone->present_pages)
			node_set_state(zone_to_nid(zone), N_NORMAL_MEMORY);
	}
#endif
}

/**
 * free_area_init_nodes - Initialise all pg_data_t and zone data
 * @max_zone_pfn: an array of max PFNs for each zone
 *
 * This will call free_area_init_node() for each active node in the system.
 * Using the page ranges provided by add_active_range(), the size of each
 * zone in each node and their holes is calculated. If the maximum PFN
 * between two adjacent zones match, it is assumed that the zone is empty.
 * For example, if arch_max_dma_pfn == arch_max_dma32_pfn, it is assumed
 * that arch_max_dma32_pfn has no pages. It is also assumed that a zone
 * starts where the previous one ended. For example, ZONE_DMA32 starts
 * at arch_max_dma_pfn.
 *
 * 由zone_sizes_init调用
 *
 * start_kernel()
 *  setup_arch()
 *   zone_sizes_init()
 *    free_area_init_nodes()
 *
 */
void __init free_area_init_nodes(unsigned long *max_zone_pfn /* 记录了各个内存域(DMA,NORMAL,HIGH_MEM)的最大页帧号 */ )
{
	unsigned long nid;
	enum zone_type i;

	/* Sort early_node_map as initialisation assumes it is sorted 
       对early_node_map进行排序，因为初始化代码假定它已经是排序了的
	*/
	sort_node_map();

	/* Record where the zone boundaries are 
	   各个ZONE的下限pfn
	 */
	memset(arch_zone_lowest_possible_pfn, 0,
				sizeof(arch_zone_lowest_possible_pfn));
	/* 各个zone的上限pfn */
	memset(arch_zone_highest_possible_pfn, 0,
				sizeof(arch_zone_highest_possible_pfn));

	/* arch_zone_lowest_possible_pfn ,arch_zone_highest_possible_pfn 
	 * 两个数组组成[low, high]这种形式的范围表示
	 * 从early_node_map[]中找到最小pfn
	 */
	arch_zone_lowest_possible_pfn[0] = find_min_pfn_with_active_regions();
	/* max_zone_pfn[]已经在前面初始化 */
	arch_zone_highest_possible_pfn[0] = max_zone_pfn[0];

	/* 分别计算出一个zone的最大和最小pfn */
	for (i = 1; i < MAX_NR_ZONES; i++) {
		if (i == ZONE_MOVABLE)
			continue;
		
		arch_zone_lowest_possible_pfn[i] =
			arch_zone_highest_possible_pfn[i-1];
		
		arch_zone_highest_possible_pfn[i] =
			max(max_zone_pfn[i], arch_zone_lowest_possible_pfn[i]);
	}
	
	arch_zone_lowest_possible_pfn[ZONE_MOVABLE] = 0;
	arch_zone_highest_possible_pfn[ZONE_MOVABLE] = 0;

	/* Find the PFNs that ZONE_MOVABLE begins at in each node */
	memset(zone_movable_pfn, 0, sizeof(zone_movable_pfn));

	/* 计算ZONE_MOVABLE域的起始编号 */
	find_zone_movable_pfns_for_nodes(zone_movable_pfn);

	/* Print out the zone ranges 
	 * 打印zone信息
	 */
	printk("Zone PFN ranges:\n");
	for (i = 0; i < MAX_NR_ZONES; i++) {
		if (i == ZONE_MOVABLE)
			continue;
		printk("  %-8s %8lu -> %8lu\n",
				zone_names[i],
				arch_zone_lowest_possible_pfn[i],
				arch_zone_highest_possible_pfn[i]);
	}

	/* Print out the PFNs ZONE_MOVABLE begins at in each node */
	printk("Movable zone start PFN for each node\n");
	for (i = 0; i < MAX_NUMNODES; i++) {
		if (zone_movable_pfn[i])
			printk("  Node %d: %lu\n", i, zone_movable_pfn[i]);
	}

	/* Print out the early_node_map[] */
	printk("early_node_map[%d] active PFN ranges\n", nr_nodemap_entries);
	for (i = 0; i < nr_nodemap_entries; i++)
		printk("  %3d: %8lu -> %8lu\n", early_node_map[i].nid,
						early_node_map[i].start_pfn,
						early_node_map[i].end_pfn);

	/* Initialise every node

      遍历各个内存节点，初始化相应的pg_data_t对象
	*/
	setup_nr_node_ids();
	for_each_online_node(nid) {
		                  //node_data[nid]
		pg_data_t *pgdat = NODE_DATA(nid);

		/* 初始化pg_data_t对象 */
		free_area_init_node(nid, pgdat, NULL,
				find_min_pfn_for_node(nid), NULL);

		/* Any memory on that node,节点上是否有内存 */
		if (pgdat->node_present_pages)
			node_set_state(nid, N_HIGH_MEMORY);
		
		check_for_regular_memory(pgdat);/* 检查低于ZONE_HIGHMEM的内存域中是否有内存，并据此在节点位图中相应的设置N_NORMAL_MEMORY */
	}
}

static int __init cmdline_parse_core(char *p, unsigned long *core)
{
	unsigned long long coremem;
	if (!p)
		return -EINVAL;

	coremem = memparse(p, &p);
	*core = coremem >> PAGE_SHIFT;

	/* Paranoid check that UL is enough for the coremem value */
	WARN_ON((coremem >> PAGE_SHIFT) > ULONG_MAX);

	return 0;
}

/*
 * kernelcore=size sets the amount of memory for use for allocations that
 * cannot be reclaimed or migrated.
 */
static int __init cmdline_parse_kernelcore(char *p)
{
	return cmdline_parse_core(p, &required_kernelcore);
}

/*
 * movablecore=size sets the amount of memory for use for allocations that
 * can be reclaimed or migrated.
 */
static int __init cmdline_parse_movablecore(char *p)
{
	return cmdline_parse_core(p, &required_movablecore);
}

early_param("kernelcore", cmdline_parse_kernelcore);
early_param("movablecore", cmdline_parse_movablecore);

#endif /* CONFIG_ARCH_POPULATES_NODE_MAP */

/**
 * set_dma_reserve - set the specified number of pages reserved in the first zone
 * @new_dma_reserve: The number of pages to mark reserved
 *
 * The per-cpu batchsize and zone watermarks are determined by present_pages.
 * In the DMA zone, a significant percentage may be consumed by kernel image
 * and other unfreeable allocations which can skew the watermarks badly. This
 * function may optionally be used to account for unfreeable pages in the
 * first zone (e.g., ZONE_DMA). The effect will be lower watermarks and
 * smaller per-cpu batchsize.
 */
void __init set_dma_reserve(unsigned long new_dma_reserve)
{
	dma_reserve = new_dma_reserve;
}

#ifndef CONFIG_NEED_MULTIPLE_NODES
static bootmem_data_t contig_bootmem_data;
struct pglist_data contig_page_data = { .bdata = &contig_bootmem_data };

EXPORT_SYMBOL(contig_page_data);
#endif

void __init free_area_init(unsigned long *zones_size)
{
	free_area_init_node(0, NODE_DATA(0), zones_size,
			__pa(PAGE_OFFSET) >> PAGE_SHIFT, NULL);
}

static int page_alloc_cpu_notify(struct notifier_block *self,
				 unsigned long action, void *hcpu)
{
	int cpu = (unsigned long)hcpu;

	if (action == CPU_DEAD || action == CPU_DEAD_FROZEN) {
		local_irq_disable();
		__drain_pages(cpu);
		vm_events_fold_cpu(cpu);
		local_irq_enable();
		refresh_cpu_vm_stats(cpu);
	}
	return NOTIFY_OK;
}

void __init page_alloc_init(void)
{
	hotcpu_notifier(page_alloc_cpu_notify, 0);
}

/*
 * calculate_totalreserve_pages - called when sysctl_lower_zone_reserve_ratio
 *	or min_free_kbytes changes.
 */
static void calculate_totalreserve_pages(void)
{
	struct pglist_data *pgdat;
	unsigned long reserve_pages = 0;
	enum zone_type i, j;

	for_each_online_pgdat(pgdat) {
		for (i = 0; i < MAX_NR_ZONES; i++) {
			struct zone *zone = pgdat->node_zones + i;
			unsigned long max = 0;

			/* Find valid and maximum lowmem_reserve in the zone */
			for (j = i; j < MAX_NR_ZONES; j++) {
				if (zone->lowmem_reserve[j] > max)
					max = zone->lowmem_reserve[j];
			}

			/* we treat pages_high as reserved pages. */
			max += zone->pages_high;

			if (max > zone->present_pages)
				max = zone->present_pages;
			reserve_pages += max;
		}
	}
	totalreserve_pages = reserve_pages;
}

/* 
 * 计算出各个zone的lowmem_reserve
 * setup_per_zone_lowmem_reserve - called whenever
 *	sysctl_lower_zone_reserve_ratio changes.  Ensures that each zone
 *	has a correct pages reserved value, so an adequate number of
 *	pages are left in the zone after a successful __alloc_pages().
 *
 * init_per_zone_pages_min()
 *  setup_per_zone_lowmem_reserve()
 */
static void setup_per_zone_lowmem_reserve(void)
{
	struct pglist_data *pgdat;
	enum zone_type j, idx;

	for_each_online_pgdat(pgdat) {
		for (j = 0; j < MAX_NR_ZONES; j++) {
			struct zone *zone = pgdat->node_zones + j;
			unsigned long present_pages = zone->present_pages;

			zone->lowmem_reserve[j] = 0;

			idx = j;
			while (idx) {
				struct zone *lower_zone;

				idx--;

				if (sysctl_lowmem_reserve_ratio[idx] < 1)
					sysctl_lowmem_reserve_ratio[idx] = 1;

				lower_zone = pgdat->node_zones + idx;
				lower_zone->lowmem_reserve[j] = present_pages /
					sysctl_lowmem_reserve_ratio[idx];
				present_pages += lower_zone->present_pages;
			}
		}
	}

	/* update totalreserve_pages */
	calculate_totalreserve_pages();
}

/**
 * setup_per_zone_pages_min - called when min_free_kbytes changes.
 *
 * Ensures that the pages_{min,low,high} values for each zone are set correctly
 * with respect to min_free_kbytes.
 *
 * 计算出zone->pages_min,zone->pages_low,zone->pages_high，在内存回收的时候会用到这些值
 *
 * init_per_zone_pages_min()
 *  setup_per_zone_pages_min()
 */
void setup_per_zone_pages_min(void)
{
	unsigned long pages_min = min_free_kbytes >> (PAGE_SHIFT - 10);
	unsigned long lowmem_pages = 0;
	struct zone *zone;
	unsigned long flags;

	/* Calculate total number of !ZONE_HIGHMEM pages */
	for_each_zone(zone) {
		if (!is_highmem(zone))
			lowmem_pages += zone->present_pages;
	}

	/* 遍历pgdata_t->node_zones上的zone */
	for_each_zone(zone) {
		u64 tmp;

		spin_lock_irqsave(&zone->lru_lock, flags);
		tmp = (u64)pages_min * zone->present_pages;
		do_div(tmp, lowmem_pages);
		//先计算出zone->pages_min
		if (is_highmem(zone)) {
			/*
			 * __GFP_HIGH and PF_MEMALLOC allocations usually don't
			 * need highmem pages, so cap pages_min to a small
			 * value here.
			 *
			 * The (pages_high-pages_low) and (pages_low-pages_min)
			 * deltas controls asynch page reclaim, and so should
			 * not be capped for highmem.
			 */
			int min_pages;

			min_pages = zone->present_pages / 1024;
			if (min_pages < SWAP_CLUSTER_MAX)  // SWAP_CLUSTER_MAX == 32
				min_pages = SWAP_CLUSTER_MAX;
			if (min_pages > 128)
				min_pages = 128;
			zone->pages_min = min_pages;
		} else {
			/*
			 * If it's a lowmem zone, reserve a number of pages
			 * proportionate to the zone's size.
			 */
			zone->pages_min = tmp;
		}

        //然后计算出zone->pages_low, zone_pages_high
		zone->pages_low   = zone->pages_min + (tmp >> 2);
		zone->pages_high  = zone->pages_min + (tmp >> 1);
		/* 确定zone的miggrate类型 */
		setup_zone_migrate_reserve(zone);
		spin_unlock_irqrestore(&zone->lru_lock, flags);
	}

	/* update totalreserve_pages */
	calculate_totalreserve_pages();
}

/*
 * Initialise min_free_kbytes.
 *
 * For small machines we want it small (128k min).  For large machines
 * we want it large (64MB max).  But it is not linear, because network
 * bandwidth does not increase linearly with machine size.  We use
 *
 * 	min_free_kbytes = 4 * sqrt(lowmem_kbytes), for better accuracy:
 *	min_free_kbytes = sqrt(lowmem_kbytes * 16)
 *
 * which yields
 *
 * 16MB:	512k
 * 32MB:	724k
 * 64MB:	1024k
 * 128MB:	1448k
 * 256MB:	2048k
 * 512MB:	2896k
 * 1024MB:	4096k
 * 2048MB:	5792k
 * 4096MB:	8192k
 * 8192MB:	11584k
 * 初始化各个zone的 pages_min, pages_high, pages_low
 * 16384MB:	16384k
 *
 *
 * 模块初始化就调用
 */
static int __init init_per_zone_pages_min(void)
{
	unsigned long lowmem_kbytes;

	lowmem_kbytes = nr_free_buffer_pages() * (PAGE_SIZE >> 10);

	min_free_kbytes = int_sqrt(lowmem_kbytes * 16);
	if (min_free_kbytes < 128)
		min_free_kbytes = 128;
	if (min_free_kbytes > 65536)
		min_free_kbytes = 65536;
	
	setup_per_zone_pages_min();/* 计算出zone->pages_min,zone->pages_low,zone->pages_high */
	setup_per_zone_lowmem_reserve();
	return 0;
}
module_init(init_per_zone_pages_min)

/*
 * min_free_kbytes_sysctl_handler - just a wrapper around proc_dointvec() so 
 *	that we can call two helper functions whenever min_free_kbytes
 *	changes.
 */
int min_free_kbytes_sysctl_handler(ctl_table *table, int write, 
	struct file *file, void __user *buffer, size_t *length, loff_t *ppos)
{
	proc_dointvec(table, write, file, buffer, length, ppos);
	if (write)
		setup_per_zone_pages_min();
	return 0;
}

#ifdef CONFIG_NUMA
int sysctl_min_unmapped_ratio_sysctl_handler(ctl_table *table, int write,
	struct file *file, void __user *buffer, size_t *length, loff_t *ppos)
{
	struct zone *zone;
	int rc;

	rc = proc_dointvec_minmax(table, write, file, buffer, length, ppos);
	if (rc)
		return rc;

	for_each_zone(zone)
		zone->min_unmapped_pages = (zone->present_pages *
				sysctl_min_unmapped_ratio) / 100;
	return 0;
}

int sysctl_min_slab_ratio_sysctl_handler(ctl_table *table, int write,
	struct file *file, void __user *buffer, size_t *length, loff_t *ppos)
{
	struct zone *zone;
	int rc;

	rc = proc_dointvec_minmax(table, write, file, buffer, length, ppos);
	if (rc)
		return rc;

	for_each_zone(zone)
		zone->min_slab_pages = (zone->present_pages *
				sysctl_min_slab_ratio) / 100;
	return 0;
}
#endif

/*
 * lowmem_reserve_ratio_sysctl_handler - just a wrapper around
 *	proc_dointvec() so that we can call setup_per_zone_lowmem_reserve()
 *	whenever sysctl_lowmem_reserve_ratio changes.
 *
 * The reserve ratio obviously has absolutely no relation with the
 * pages_min watermarks. The lowmem reserve ratio can only make sense
 * if in function of the boot time zone sizes.
 */
int lowmem_reserve_ratio_sysctl_handler(ctl_table *table, int write,
	struct file *file, void __user *buffer, size_t *length, loff_t *ppos)
{
	proc_dointvec_minmax(table, write, file, buffer, length, ppos);
	setup_per_zone_lowmem_reserve();
	return 0;
}

/*
 * percpu_pagelist_fraction - changes the pcp->high for each zone on each
 * cpu.  It is the fraction of total pages in each zone that a hot per cpu pagelist
 * can have before it gets flushed back to buddy allocator.
 */

int percpu_pagelist_fraction_sysctl_handler(ctl_table *table, int write,
	struct file *file, void __user *buffer, size_t *length, loff_t *ppos)
{
	struct zone *zone;
	unsigned int cpu;
	int ret;

	ret = proc_dointvec_minmax(table, write, file, buffer, length, ppos);
	if (!write || (ret == -EINVAL))
		return ret;
	for_each_zone(zone) {
		for_each_online_cpu(cpu) {
			unsigned long  high;
			high = zone->present_pages / percpu_pagelist_fraction;
			setup_pagelist_highmark(zone_pcp(zone, cpu), high);
		}
	}
	return 0;
}

int hashdist = HASHDIST_DEFAULT;

#ifdef CONFIG_NUMA
static int __init set_hashdist(char *str)
{
	if (!str)
		return 0;
	hashdist = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("hashdist=", set_hashdist);
#endif

/*
 * allocate a large system hash table from bootmem
 * - it is assumed that the hash table must contain an exact power-of-2
 *   quantity of entries
 * - limit is the number of hash buckets, not the total allocation size
 */
void *__init alloc_large_system_hash(const char *tablename,
				     unsigned long bucketsize,
				     unsigned long numentries,
				     int scale,
				     int flags,
				     unsigned int *_hash_shift,
				     unsigned int *_hash_mask,
				     unsigned long limit)
{
	unsigned long long max = limit;
	unsigned long log2qty, size;
	void *table = NULL;

	/* allow the kernel cmdline to have a say */
	if (!numentries) {
		/* round applicable memory size up to nearest megabyte */
		numentries = nr_kernel_pages;
		numentries += (1UL << (20 - PAGE_SHIFT)) - 1;
		numentries >>= 20 - PAGE_SHIFT;
		numentries <<= 20 - PAGE_SHIFT;

		/* limit to 1 bucket per 2^scale bytes of low memory */
		if (scale > PAGE_SHIFT)
			numentries >>= (scale - PAGE_SHIFT);
		else
			numentries <<= (PAGE_SHIFT - scale);

		/* Make sure we've got at least a 0-order allocation.. */
		if (unlikely((numentries * bucketsize) < PAGE_SIZE))
			numentries = PAGE_SIZE / bucketsize;
	}
	numentries = roundup_pow_of_two(numentries);

	/* limit allocation size to 1/16 total memory by default */
	if (max == 0) {
		max = ((unsigned long long)nr_all_pages << PAGE_SHIFT) >> 4;
		do_div(max, bucketsize);
	}

	if (numentries > max)
		numentries = max;

	log2qty = ilog2(numentries);

	do {
		size = bucketsize << log2qty;
		if (flags & HASH_EARLY)
			table = alloc_bootmem(size);
		else if (hashdist)
			table = __vmalloc(size, GFP_ATOMIC, PAGE_KERNEL);
		else {
			unsigned long order;
			for (order = 0; ((1UL << order) << PAGE_SHIFT) < size; order++)
				;
			table = (void*) __get_free_pages(GFP_ATOMIC, order);
			/*
			 * If bucketsize is not a power-of-two, we may free
			 * some pages at the end of hash table.
			 */
			if (table) {
				unsigned long alloc_end = (unsigned long)table +
						(PAGE_SIZE << order);
				unsigned long used = (unsigned long)table +
						PAGE_ALIGN(size);
				split_page(virt_to_page(table), order);
				while (used < alloc_end) {
					free_page(used);
					used += PAGE_SIZE;
				}
			}
		}
	} while (!table && size > PAGE_SIZE && --log2qty);

	if (!table)
		panic("Failed to allocate %s hash table\n", tablename);

	printk(KERN_INFO "%s hash table entries: %d (order: %d, %lu bytes)\n",
	       tablename,
	       (1U << log2qty),
	       ilog2(size) - PAGE_SHIFT,
	       size);

	if (_hash_shift)
		*_hash_shift = log2qty;
	if (_hash_mask)
		*_hash_mask = (1 << log2qty) - 1;

	return table;
}

#ifdef CONFIG_OUT_OF_LINE_PFN_TO_PAGE
struct page *pfn_to_page(unsigned long pfn)
{
	return __pfn_to_page(pfn);
}
unsigned long page_to_pfn(struct page *page)
{
	return __page_to_pfn(page);
}
EXPORT_SYMBOL(pfn_to_page);
EXPORT_SYMBOL(page_to_pfn);
#endif /* CONFIG_OUT_OF_LINE_PFN_TO_PAGE */

/* Return a pointer to the bitmap storing bits affecting a block of pages */
static inline unsigned long *get_pageblock_bitmap(struct zone *zone,
							unsigned long pfn)
{
#ifdef CONFIG_SPARSEMEM
	return __pfn_to_section(pfn)->pageblock_flags;
#else
	return zone->pageblock_flags;
#endif /* CONFIG_SPARSEMEM */
}

static inline int pfn_to_bitidx(struct zone *zone, unsigned long pfn)
{
#ifdef CONFIG_SPARSEMEM
	pfn &= (PAGES_PER_SECTION-1);
	return (pfn >> pageblock_order) * NR_PAGEBLOCK_BITS;
#else
    /* 在zone中的相对pfn */
	pfn = pfn - zone->zone_start_pfn;
    /* 
     * pageblock_order == 10, pfn >> pageblock_order 找到所属的pageblock,
     */
	return (pfn >> pageblock_order) * NR_PAGEBLOCK_BITS;
#endif /* CONFIG_SPARSEMEM */
}

/**
 * get_pageblock_flags_group - Return the requested group of flags for the pageblock_nr_pages block of pages
 * @page: The page within the block of interest
 * @start_bitidx: The first bit of interest to retrieve
 * @end_bitidx: The last bit of interest
 * returns pageblock_bits flags
 *
 *
 * __free_pages()
 *  __free_pages_ok()
 *   free_one_page()
 *    __free_one_page()
 *     get_pageblock_migratetype()
 *      get_pageblock_flags_group() 
 * 返回page所属的migrate_type,
 * migrate_type的计算过程在set_pageblock_flags_group中
 */
unsigned long get_pageblock_flags_group(struct page *page,
					int start_bitidx, int end_bitidx)
{
	struct zone *zone;
	unsigned long *bitmap;
	unsigned long pfn, bitidx;
	unsigned long flags = 0;
	unsigned long value = 1;

	zone = page_zone(page);
	pfn = page_to_pfn(page);
	/* 得到zone->pageblock_flags数组 */
	bitmap = get_pageblock_bitmap(zone, pfn);
	// 获得页面对应的第一页的索引保存在变量bitidx中
	bitidx = pfn_to_bitidx(zone, pfn);

	for (; start_bitidx <= end_bitidx; start_bitidx++, value <<= 1)
		if (test_bit(bitidx + start_bitidx, bitmap))
			flags |= value;//不断的累计

	return flags;
}

/**
 * set_pageblock_flags_group - Set the requested group of flags for a pageblock_nr_pages block of pages
 * @page: The page within the block of interest
 * @start_bitidx: The first bit of interest
 * @end_bitidx: The last bit of interest
 * @flags: The flags to set
 *
 * __rmqueue_fallback()
 *  set_pageblock_migratetype()
 *   set_pageblock_flags_group()
 * 设置zone->pageblack_flags相应的位
 */
void set_pageblock_flags_group(struct page *page, unsigned long flags,
					int start_bitidx, int end_bitidx)
{
	struct zone *zone;
	unsigned long *bitmap;
	unsigned long pfn, bitidx;
	unsigned long value = 1;

	zone = page_zone(page);
	pfn = page_to_pfn(page);
	
	/* 得到zone->pageblock_flags */
	bitmap = get_pageblock_bitmap(zone, pfn);
	/* 得到page在pageblock_flags中对应的位置 */
	bitidx = pfn_to_bitidx(zone, pfn);

    //设置到zone->pageblock_flags相应的bit中去
	for (; start_bitidx <= end_bitidx; start_bitidx++, value <<= 1)
		if (flags & value)
			__set_bit(bitidx + start_bitidx, bitmap);
		else
			__clear_bit(bitidx + start_bitidx, bitmap);
}

/*
 * This is designed as sub function...plz see page_isolation.c also.
 * set/clear page block's type to be ISOLATE.
 * page allocater never alloc memory from ISOLATE block.
 */

int set_migratetype_isolate(struct page *page)
{
	struct zone *zone;
	unsigned long flags;
	int ret = -EBUSY;

	zone = page_zone(page);
	spin_lock_irqsave(&zone->lock, flags);
	/*
	 * In future, more migrate types will be able to be isolation target.
	 */
	if (get_pageblock_migratetype(page) != MIGRATE_MOVABLE)
		goto out;
	set_pageblock_migratetype(page, MIGRATE_ISOLATE);
	move_freepages_block(zone, page, MIGRATE_ISOLATE);
	ret = 0;
out:
	spin_unlock_irqrestore(&zone->lock, flags);
	if (!ret)
		drain_all_local_pages();
	return ret;
}

void unset_migratetype_isolate(struct page *page)
{
	struct zone *zone;
	unsigned long flags;
	zone = page_zone(page);
	spin_lock_irqsave(&zone->lock, flags);
	if (get_pageblock_migratetype(page) != MIGRATE_ISOLATE)
		goto out;
	set_pageblock_migratetype(page, MIGRATE_MOVABLE);
	move_freepages_block(zone, page, MIGRATE_MOVABLE);
out:
	spin_unlock_irqrestore(&zone->lock, flags);
}

#ifdef CONFIG_MEMORY_HOTREMOVE
/*
 * All pages in the range must be isolated before calling this.
 */
void
__offline_isolated_pages(unsigned long start_pfn, unsigned long end_pfn)
{
	struct page *page;
	struct zone *zone;
	int order, i;
	unsigned long pfn;
	unsigned long flags;
	/* find the first valid pfn */
	for (pfn = start_pfn; pfn < end_pfn; pfn++)
		if (pfn_valid(pfn))
			break;
	if (pfn == end_pfn)
		return;
	zone = page_zone(pfn_to_page(pfn));
	spin_lock_irqsave(&zone->lock, flags);
	pfn = start_pfn;
	while (pfn < end_pfn) {
		if (!pfn_valid(pfn)) {
			pfn++;
			continue;
		}
		page = pfn_to_page(pfn);
		BUG_ON(page_count(page));
		BUG_ON(!PageBuddy(page));
		order = page_order(page);
#ifdef CONFIG_DEBUG_VM
		printk(KERN_INFO "remove from free list %lx %d %lx\n",
		       pfn, 1 << order, end_pfn);
#endif
		list_del(&page->lru);
		rmv_page_order(page);
		zone->free_area[order].nr_free--;
		__mod_zone_page_state(zone, NR_FREE_PAGES,
				      - (1UL << order));
		for (i = 0; i < (1 << order); i++)
			SetPageReserved((page+i));
		pfn += (1 << order);
	}
	spin_unlock_irqrestore(&zone->lock, flags);
}
#endif
