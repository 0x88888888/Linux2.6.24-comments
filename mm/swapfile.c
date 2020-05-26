/*
 *  linux/mm/swapfile.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 */

#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/namei.h>
#include <linux/shm.h>
#include <linux/blkdev.h>
#include <linux/writeback.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/rmap.h>
#include <linux/security.h>
#include <linux/backing-dev.h>
#include <linux/mutex.h>
#include <linux/capability.h>
#include <linux/syscalls.h>

#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/swapops.h>

DEFINE_SPINLOCK(swap_lock);

unsigned int nr_swapfiles;
long total_swap_pages;
static int swap_overflow;

static const char Bad_file[] = "Bad swap file entry ";
static const char Unused_file[] = "Unused swap file entry ";
static const char Bad_offset[] = "Bad swap offset entry ";
static const char Unused_offset[] = "Unused swap offset entry ";

/*
 * swap_list->next总是指向当前使用个的swap_info_struct 的type
 */
struct swap_list_t swap_list = {-1, -1};

/*
 * 只有设置了SWP_USED标志的交换区才被使用。活动的交换区描述符也被插入按交换区优先级排序的swap_list链表中。
 * 该链表是通过交换区描述符的next字段实现的，next字段存放的是swap_info数组中下一个描述符的索引。
 * swapon()和swapoff()系统调用用于激活和禁用交换区。
 */
static struct swap_info_struct swap_info[MAX_SWAPFILES];

static DEFINE_MUTEX(swapon_mutex);

/*
 * We need this because the bdev->unplug_fn can sleep and we cannot
 * hold swap_lock while calling the unplug_fn. And swap_lock
 * cannot be turned into a mutex.
 */
static DECLARE_RWSEM(swap_unplug_sem);

void swap_unplug_io_fn(struct backing_dev_info *unused_bdi, struct page *page)
{
	swp_entry_t entry;

	down_read(&swap_unplug_sem);
	entry.val = page_private(page);
	if (PageSwapCache(page)) {
		/* 交换区对应的块设备对象 */
		struct block_device *bdev = swap_info[swp_type(entry)].bdev;
		struct backing_dev_info *bdi;

		/*
		 * If the page is removed from swapcache from under us (with a
		 * racy try_to_unuse/swapoff) we need an additional reference
		 * count to avoid reading garbage from page_private(page) above.
		 * If the WARN_ON triggers during a swapoff it maybe the race
		 * condition and it's harmless. However if it triggers without
		 * swapoff it signals a problem.
		 */
		WARN_ON(page_count(page) <= 1);

		bdi = bdev->bd_inode->i_mapping->backing_dev_info;
		blk_run_backing_dev(bdi, page);
	}
	up_read(&swap_unplug_sem);
}

#define SWAPFILE_CLUSTER	256
#define LATENCY_LIMIT		256

/*
 * scan_swap_map函数负责在具体的交换分区中查找空闲的页槽，
 * 其搜索方法也值得分析交换系统有时候会集中在一个比较短的时间换出大量页面，
 * 这些页面也有可能是连续的，尽量把这些页面存储到一个连续的磁盘设备上，
 * 可以让页面从磁盘上换入时磁道寻址时间更加短一点。所以scan_swap_map使用了一种算法，
 * 首先在交换分区中寻找SWAPFILE_CLUSTER个空闲页槽的一块区域，然后从这个区域中一次分配空闲页槽，
 * 等这个区域分配完毕了，再次寻找一个SWAPFILE_CLUSTER空闲槽位的连续区域供给分配。
 *
 * 扫描swap_info_struct->swap_map[]
 * 返回swap_info_struct->swap_map[]数组空闲元素的下标.
 * shrink_page_list()
 *  add_to_swap()
 *   get_swap_page() 
 *
 * alloc_swapdev_block()
 *  get_swap_page_of_type()
 *   scan_swap_map()
 */
static inline unsigned long scan_swap_map(struct swap_info_struct *si)
{
	unsigned long offset, last_in_cluster;
	int latency_ration = LATENCY_LIMIT;

	/* 
	 * We try to cluster swap pages by allocating them sequentially
	 * in swap.  Once we've allocated SWAPFILE_CLUSTER pages this
	 * way, however, we resort to first-free allocation, starting
	 * a new cluster.  This prevents us from scattering swap pages
	 * all over the entire swap partition, so that we reduce
	 * overall disk seek times between swap pages.  -- sct
	 * But we do now try to find an empty cluster.  -Andrea
	 */

	si->flags += SWP_SCANNING; /*正在被scan状态*/
	if (unlikely(!si->cluster_nr)) { /* 从si->lowest_bit开始查找新的cluster区域 */
		
		si->cluster_nr = SWAPFILE_CLUSTER - 1;
		if (si->pages - si->inuse_pages < SWAPFILE_CLUSTER)
			goto lowest; /* 不够分配一个新的cluster了 */
		
		spin_unlock(&swap_lock);

        /* 扫描swap_info_struct->swap_map[]的起始索引 */
		offset = si->lowest_bit;
		last_in_cluster = offset + SWAPFILE_CLUSTER - 1;

		/* Locate the first empty (unaligned) cluster */
		for (; last_in_cluster <= si->highest_bit; offset++) {
			
			if (si->swap_map[offset])
				last_in_cluster = offset + SWAPFILE_CLUSTER;
			else if (offset == last_in_cluster) {
				spin_lock(&swap_lock);
				si->cluster_next = offset-SWAPFILE_CLUSTER+1;
				goto cluster;
			}
			
			if (unlikely(--latency_ration < 0)) {
				cond_resched();
				latency_ration = LATENCY_LIMIT;
			}
		}
		
		spin_lock(&swap_lock);
		goto lowest;
	}

    /* 到这里，说明老的cluster区域有空闲slot */
	si->cluster_nr--;
cluster:
	offset = si->cluster_next;
	if (offset > si->highest_bit)
lowest:		offset = si->lowest_bit;
	
checks:	if (!(si->flags & SWP_WRITEOK))
		goto no_page; /* 不能被write */
	
	if (!si->highest_bit)
		goto no_page;
	
	if (!si->swap_map[offset]) { /* si->swap_map[offset]处没有被使用 */
		if (offset == si->lowest_bit)
			si->lowest_bit++;
		
		if (offset == si->highest_bit)
			si->highest_bit--;
		
		si->inuse_pages++; /* 又一个磁盘上的page别使用了 */
		if (si->inuse_pages == si->pages) {/* 交换区的所有的page都被使用了 */
			
			si->lowest_bit = si->max;
			si->highest_bit = 0;
		}
		
		si->swap_map[offset] = 1; /* 被使用了 */
		si->cluster_next = offset + 1; /* next设置 */
		si->flags -= SWP_SCANNING; /* 结束正在被scan状态 */
		return offset; /* 找到 */
	}

	spin_unlock(&swap_lock);
	/* 从offset处的slot开始遍历，直到找到一个空闲的slot */
	while (++offset <= si->highest_bit) {
		if (!si->swap_map[offset]) { /* 未被使用 */
			spin_lock(&swap_lock);
			goto checks;
		}
		
		if (unlikely(--latency_ration < 0)) {
			cond_resched();
			latency_ration = LATENCY_LIMIT;
		}
	}
	spin_lock(&swap_lock);
	goto lowest;

no_page:
	/* 结束正在被scan状态 */
	si->flags -= SWP_SCANNING;
	return 0;
}

/*
 * get_swap_page函数会优先分配优先级高的交换分区中空闲的页槽，
 * 同优先级之间的交换分区会轮流分配空闲页槽。
 *
 * 通过搜索所有活动的交换区(swap_list链表)来查找一个空闲页槽
 *
 * 优先使用高优先级的交换分区是因为高优先级的交换分区一般磁盘读写速度都比较快，
 * 优先使用加快页面换出换入的速度，同优先级的交换分区轮流分配页槽的目的是，
 * 不同的交换分区可能位于不同的磁盘上，轮流使用可以加大并行IO的可能，也是加快换入换出的速度。
 *
 * shrink_zone()
 *  shrink_inactive_list()
 *   shrink_page_list()
 *    add_to_swap()
 *     get_swap_page()
 */
swp_entry_t get_swap_page(void)
{
	struct swap_info_struct *si;
	pgoff_t offset;
	int type, next;
	int wrapped = 0;

	spin_lock(&swap_lock);
	if (nr_swap_pages <= 0)
		goto noswap;
	
	nr_swap_pages--;

	/* 下一个swap_info[type] */
	for (type = swap_list.next; type >= 0 && wrapped < 2; type = next) {
		
		/* 根据type定位到数组中相应的swap_info_struct */
		si = swap_info + type;
		next = si->next; /* 下一个swap_info[]索引的下表  */
	
		if (next < 0 ||
		    (!wrapped && si->prio != swap_info[next].prio)) {
		    /* 优先级不同了,从头开始 */
			next = swap_list.head;
			wrapped++; //不会在第二次进入这个if判断了
		}

		if (!si->highest_bit)
			continue;
		
		if (!(si->flags & SWP_WRITEOK))
			continue;

		swap_list.next = next;

		/* 获得一个空闲页槽,swap_info_struct->swap_map[]的空闲元素的下标 */
		offset = scan_swap_map(si);
		
		if (offset) {
			spin_unlock(&swap_lock);
			/* 找到,合成swp_entry,返回 */
			return swp_entry(type, offset);
		}
		next = swap_list.next;
	}

	nr_swap_pages++;
noswap:
	spin_unlock(&swap_lock);
	return (swp_entry_t) {0};
}

/*
 * 在swap area中查找一个空闲的磁盘page
 *
 * alloc_swapdev_block()
 *  get_swap_page_of_type()
 */
swp_entry_t get_swap_page_of_type(int type)
{
	struct swap_info_struct *si;
	pgoff_t offset;

	spin_lock(&swap_lock);
	si = swap_info + type;
	if (si->flags & SWP_WRITEOK) {
		nr_swap_pages--;
		offset = scan_swap_map(si);
	
		if (offset) {/* 找到 */
			spin_unlock(&swap_lock);
			return swp_entry(type, offset);
		}
		//查找失败
		nr_swap_pages++;
	}
	spin_unlock(&swap_lock);
	return (swp_entry_t) {0};
}

/*
 * entry所在的swap_info_struct 
 * 返回swap_info[type]
 *
 * swap_free()
 *  swap_info_get()
 *
 * free_swap_and_cache()
 *  swap_info_get()
 * 
 * remove_exclusive_swap_page()
 *  swap_info_get()
 *
 */
static struct swap_info_struct * swap_info_get(swp_entry_t entry)
{
	struct swap_info_struct * p;
	unsigned long offset, type;

	if (!entry.val)
		goto out;
	type = swp_type(entry);
	if (type >= nr_swapfiles)
		goto bad_nofile;
	
	p = & swap_info[type];
	if (!(p->flags & SWP_USED))
		goto bad_device;

	/* swap_info_struct->swap_map[]中的索引 */
	offset = swp_offset(entry);
	if (offset >= p->max)
		goto bad_offset;
	
	if (!p->swap_map[offset])
		goto bad_free;
	spin_lock(&swap_lock);
	return p;

bad_free:
	printk(KERN_ERR "swap_free: %s%08lx\n", Unused_offset, entry.val);
	goto out;
bad_offset:
	printk(KERN_ERR "swap_free: %s%08lx\n", Bad_offset, entry.val);
	goto out;
bad_device:
	printk(KERN_ERR "swap_free: %s%08lx\n", Unused_file, entry.val);
	goto out;
bad_nofile:
	printk(KERN_ERR "swap_free: %s%08lx\n", Bad_file, entry.val);
out:
	return NULL;
}	

/*
 * swap_free()
 *  swap_entry_free()
 * 根据swap_info_struct->swap_map[offset]的计数来确定是否要释放对应的slot
 */
static int swap_entry_free(struct swap_info_struct *p, unsigned long offset)
{
	int count = p->swap_map[offset];

	if (count < SWAP_MAP_MAX) {
		count--; /* 被映射的数量减一 */
		p->swap_map[offset] = count;
	
		if (!count) { /* 已经没有进程引用该entry对应的page了 */
			if (offset < p->lowest_bit)
				p->lowest_bit = offset;
			
			if (offset > p->highest_bit)
				p->highest_bit = offset;
			
			if (p->prio > swap_info[swap_list.next].prio)
				swap_list.next = p - swap_info;
			
			nr_swap_pages++;
			/* 交换区中的page数量减少 */
			p->inuse_pages--;
		}
	}
	return count;
}

/*
 * Caller has made sure that the swapdevice corresponding to entry
 * is still around or has not been recycled.
 *
 * swap_free()函数执行swap_map计数器的减1操作，
 * 当计数器值为0时表示页槽变为空闲，此时应修改交换区描述符的相应字段
 *
 *
 * read_swap_cache_async()
 *  add_to_swap_cache()
 *   swap_free()
 *
 * sys_swapoff()
 *	try_to_unuse()
 *	 unuse_mm()
 *	  unuse_vma()
 *	   unuse_pud_range()
 *		unuse_pmd_range()
 *       unuse_pte_range()
 *        unuse_pte()
 *         swap_free()
 *
 * 根据swap_info_struct->swap_map[offset]的计数来确定是否要释放对应的slot
 */
void swap_free(swp_entry_t entry)
{
	struct swap_info_struct * p;

	p = swap_info_get(entry); /*  */
	if (p) {
		swap_entry_free(p, swp_offset(entry)); 
		spin_unlock(&swap_lock);
	}
}

/*
 * How many references to page are currently swapped out?
 *
 * 返回page的 swap引用计数 
 *
 * can_share_swap_page()
 *  page_swapcount()
 */
static inline int page_swapcount(struct page *page)
{
	int count = 0;
	struct swap_info_struct *p;
	swp_entry_t entry;

	entry.val = page_private(page);
	p = swap_info_get(entry);
	if (p) {
		/* Subtract the 1 for the swap cache itself */
		count = p->swap_map[swp_offset(entry)] - 1;
		spin_unlock(&swap_lock);
	}
	return count;
}

/*
 * We can use this swap cache entry directly
 * if there are no other references to it.
 *
 * swap的页面是否可以共享
 */
int can_share_swap_page(struct page *page)
{
	int count;

	BUG_ON(!PageLocked(page));
	count = page_mapcount(page);
	if (count <= 1 && PageSwapCache(page))
		count += page_swapcount(page);
	
	return count == 1;
}

/*
 * Work out if there are any other processes sharing this
 * swap cache page. Free it if you can. Return success.
 *
 * do_swap_page()
 *  remove_exclusive_swap_page()
 *
 * swap_writepage()
 *  remove_exclusive_swap_page()
 *
 * free_swap_cache()
 *  remove_exclusive_swap_page()
 *
 */
int remove_exclusive_swap_page(struct page *page)
{
	int retval;
	struct swap_info_struct * p;
	swp_entry_t entry;

	BUG_ON(PagePrivate(page));
	BUG_ON(!PageLocked(page));

	if (!PageSwapCache(page))
		return 0;
	
	if (PageWriteback(page)) /* 只有在writeback状态的page才是exclusive的? */
		return 0;
	
	if (page_count(page) != 2) /* 2: us + cache */
		return 0;

	entry.val = page_private(page);
	
	p = swap_info_get(entry);
	if (!p)
		return 0;

	/* Is the only swap cache user the cache itself? */
	retval = 0;
	if (p->swap_map[swp_offset(entry)] == 1) {
		/* Recheck the page count with the swapcache lock held.. */
		write_lock_irq(&swapper_space.tree_lock);
		if ((page_count(page) == 2) && !PageWriteback(page)) {
			__delete_from_swap_cache(page); //移除page
			SetPageDirty(page);
			retval = 1;
		}
		write_unlock_irq(&swapper_space.tree_lock);
	}
	spin_unlock(&swap_lock);

	if (retval) {
		swap_free(entry);
		page_cache_release(page);
	}

	return retval;
}

/*
 * Free the swap entry like above, but also try to
 * free the page cache entry if it is the last user.
 *
 * shmem_free_swp()
 *  free_swap_and_cache()
 *
 *
 * zap_pte_range()
 *  free_swap_and_cache()
 *
 *
 * sys_remap_file_pages()
 *  populate_range()
 *   install_file_pte()
 *    zap_pte() 
 *     free_swap_and_cache()
 * 
 * sys_munmap() 
 *	do_munmap()
 *	 unmap_region()
 *	  unmap_vmas()
 *	   unmap_page_range()
 *		zap_pud_range()
 *		 zap_pmd_range()
 *        zap_pte_range()
 *         free_swap_and_cache()
 */
void free_swap_and_cache(swp_entry_t entry)
{
	struct swap_info_struct * p;
	struct page *page = NULL;

	if (is_migration_entry(entry))
		return;

	p = swap_info_get(entry);
	if (p) {
		if (swap_entry_free(p, swp_offset(entry)) == 1) {
			/* 根据entry从swapper_space中得到page */
			page = find_get_page(&swapper_space, entry.val);
			if (page && unlikely(TestSetPageLocked(page))) {
				page_cache_release(page);
				page = NULL;
			}
		}
		spin_unlock(&swap_lock);
	}
	
	if (page) {
		int one_user;

		BUG_ON(PagePrivate(page));
		one_user = (page_count(page) == 2);
		/* Only cache user (+us), or swap space full? Free it! */
		/* Also recheck PageSwapCache after page is locked (above) */
		if (PageSwapCache(page) && !PageWriteback(page) &&
					(one_user || vm_swap_full())) {
			//将page从swapper_space中删除		
			delete_from_swap_cache(page);
			SetPageDirty(page);
		}
		unlock_page(page);
		page_cache_release(page);
	}
}

#ifdef CONFIG_HIBERNATION
/*
 * Find the swap type that corresponds to given device (if any).
 *
 * @offset - number of the PAGE_SIZE-sized block of the device, starting
 * from 0, in which the swap header is expected to be located.
 *
 * This is needed for the suspend to disk (aka swsusp).
 */
int swap_type_of(dev_t device, sector_t offset, struct block_device **bdev_p)
{
	struct block_device *bdev = NULL;
	int i;

	if (device)
		bdev = bdget(device);

	spin_lock(&swap_lock);
	for (i = 0; i < nr_swapfiles; i++) {
		struct swap_info_struct *sis = swap_info + i;

		if (!(sis->flags & SWP_WRITEOK))
			continue;

		if (!bdev) {
			if (bdev_p)
				*bdev_p = sis->bdev;

			spin_unlock(&swap_lock);
			return i;
		}
		if (bdev == sis->bdev) {
			struct swap_extent *se;

			se = list_entry(sis->extent_list.next,
					struct swap_extent, list);
		
			if (se->start_block == offset) {
				if (bdev_p)
					*bdev_p = sis->bdev;

				spin_unlock(&swap_lock);
				bdput(bdev);
				return i;
			}
		}
	}
	spin_unlock(&swap_lock);
	if (bdev)
		bdput(bdev);

	return -ENODEV;
}

/*
 * Return either the total number of swap pages of given type, or the number
 * of free pages of that type (depending on @free)
 *
 * This is needed for software suspend
 *
 * 返回swap_info[type]中空闲页的数量
 */
unsigned int count_swap_pages(int type, int free)
{
	unsigned int n = 0;

	if (type < nr_swapfiles) {
		spin_lock(&swap_lock);
		
		if (swap_info[type].flags & SWP_WRITEOK) {
			
			n = swap_info[type].pages;
			if (free)
				n -= swap_info[type].inuse_pages;
		}
		spin_unlock(&swap_lock);
	}
	return n;
}
#endif

/*
 * No need to decide whether this PTE shares the swap entry with others,
 * just let do_wp_page work it out if a write is requested later - to
 * force COW, vm_page_prot omits write permission from any private vma.
 *
 * sys_swapoff()
 *	try_to_unuse()
 *	 unuse_mm()
 *	  unuse_vma()
 *	   unuse_pud_range()
 *		unuse_pmd_range()
 *       unuse_pte_range()
 *        unuse_pte()
 */
static void unuse_pte(struct vm_area_struct *vma, pte_t *pte,
		unsigned long addr, swp_entry_t entry, struct page *page)
{
	inc_mm_counter(vma->vm_mm, anon_rss);
	get_page(page);
	set_pte_at(vma->vm_mm, addr, pte,
		   pte_mkold(mk_pte(page, vma->vm_page_prot)));

    /* 设置page->mapping = vma->anon_vma */
	page_add_anon_rmap(page, vma, addr);
	swap_free(entry);
	/*
	 * Move the page to the active list so it is not
	 * immediately swapped out again after swapon.
	 */
	activate_page(page);
}

/*
 * sys_swapoff()
 *	try_to_unuse()
 *	 unuse_mm()
 *	  unuse_vma()
 *	   unuse_pud_range()
 *		unuse_pmd_range()
 *       unuse_pte_range()
 */
static int unuse_pte_range(struct vm_area_struct *vma, pmd_t *pmd,
				unsigned long addr, unsigned long end,
				swp_entry_t entry, struct page *page)
{
	pte_t swp_pte = swp_entry_to_pte(entry);
	pte_t *pte;
	spinlock_t *ptl;
	int found = 0;

	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	do {
		/*
		 * swapoff spends a _lot_ of time in this loop!
		 * Test inline before going to call unuse_pte.
		 */
		if (unlikely(pte_same(*pte, swp_pte))) {
			unuse_pte(vma, pte++, addr, entry, page);
			found = 1;
			break;
		}
	} while (pte++, addr += PAGE_SIZE, addr != end);
		
	pte_unmap_unlock(pte - 1, ptl);
	return found;
}

/*
 * sys_swapoff()
 *	try_to_unuse()
 *	 unuse_mm()
 *	  unuse_vma()
 *	   unuse_pud_range()
 *      unuse_pmd_range()
 */
static inline int unuse_pmd_range(struct vm_area_struct *vma, pud_t *pud,
				unsigned long addr, unsigned long end,
				swp_entry_t entry, struct page *page)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(pmd))
			continue;
		
		if (unuse_pte_range(vma, pmd, addr, next, entry, page))
			return 1;
		
	} while (pmd++, addr = next, addr != end);
	return 0;
}

/*
 * sys_swapoff()
 *	try_to_unuse()
 *	 unuse_mm()
 *	  unuse_vma()
 *     unuse_pud_range()
 */
static inline int unuse_pud_range(struct vm_area_struct *vma, pgd_t *pgd,
				unsigned long addr, unsigned long end,
				swp_entry_t entry, struct page *page)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		if (unuse_pmd_range(vma, pud, addr, next, entry, page))
			return 1;
	} while (pud++, addr = next, addr != end);
	return 0;
}

/*
 * sys_swapoff()
 *	try_to_unuse()
 *	 unuse_mm()
 *    unuse_vma()
 */
static int unuse_vma(struct vm_area_struct *vma,
				swp_entry_t entry, struct page *page)
{
	pgd_t *pgd;
	unsigned long addr, end, next;

	if (page->mapping) {
		addr = page_address_in_vma(page, vma);
		if (addr == -EFAULT)
			return 0;
		else
			end = addr + PAGE_SIZE;
	} else {
		addr = vma->vm_start;
		end = vma->vm_end;
	}

	pgd = pgd_offset(vma->vm_mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		if (unuse_pud_range(vma, pgd, addr, next, entry, page))
			return 1;
	} while (pgd++, addr = next, addr != end);
	return 0;
}

/*
 * sys_swapoff()
 *  try_to_unuse()
 *   unuse_mm()
 */
static int unuse_mm(struct mm_struct *mm,
				swp_entry_t entry, struct page *page)
{
	struct vm_area_struct *vma;

	if (!down_read_trylock(&mm->mmap_sem)) {
		/*
		 * Activate page so shrink_cache is unlikely to unmap its
		 * ptes while lock is dropped, so swapoff can make progress.
		 */
		activate_page(page);
		unlock_page(page);
		down_read(&mm->mmap_sem);
		lock_page(page);
	}
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (vma->anon_vma && unuse_vma(vma, entry, page))
			break;
	}
	up_read(&mm->mmap_sem);
	/*
	 * Currently unuse_mm cannot fail, but leave error handling
	 * at call sites for now, since we change it from time to time.
	 */
	return 0;
}

/*
 * Scan swap_map from current position to next entry still in use.
 * Recycle to start on reaching the end, returning 0 when empty.
 *
 * sys_swapoff()
 *  try_to_unuse()
 *   find_next_to_unuse()
 *
 * 查找下一个要被unuse的slot的索引
 */
static unsigned int find_next_to_unuse(struct swap_info_struct *si,
					unsigned int prev)
{
	unsigned int max = si->max;
	unsigned int i = prev;
	int count;

	/*
	 * No need for swap_lock here: we're just looking
	 * for whether an entry is in use, not modifying it; false
	 * hits are okay, and sys_swapoff() has already prevented new
	 * allocations from this area (while holding swap_lock).
	 */
	for (;;) {
		if (++i >= max) {
			if (!prev) {
				i = 0;
				break;
			}
			/*
			 * No entries in use at top of swap_map,
			 * loop back to start and recheck there.
			 */
			max = prev + 1;
			prev = 0;
			i = 1;
		}
		count = si->swap_map[i];
		if (count && count != SWAP_MAP_BAD)
			break;
	}
	return i;
}

/*
 * We completely avoid races by reading each swap page in advance,
 * and then search for the process using it.  All the necessary
 * page table adjustments can then be made atomically.
 *
 * 将此区中所有的page换入RAM，这就需要从init_mm内存描述符开始，
 * 访问所有内核线程和进程的地址空间,找到使用这些page的pte，并且设置它们。
 *　这是一个相当耗时的操作，
 * 因此如果在try_to_unuse()执行期间，si_swapinfo()函数进行采集swap信息，
 * 那么次swap的状态必然为SWP_USED
 *
 * sys_swapoff()
 *  try_to_unuse()
 *
 */
static int try_to_unuse(unsigned int type)
{
	struct swap_info_struct * si = &swap_info[type];
	
	struct mm_struct *start_mm;
	unsigned short *swap_map;
	unsigned short swcount;
	struct page *page;
	swp_entry_t entry;
	unsigned int i = 0;
	int retval = 0;
	int reset_overflow = 0;
	int shmem;

	/*
	 * When searching mms for an entry, a good strategy is to
	 * start at the first mm we freed the previous entry from
	 * (though actually we don't notice whether we or coincidence
	 * freed the entry).  Initialize this start_mm with a hold.
	 *
	 * A simpler strategy would be to start at the last mm we
	 * freed the previous entry from; but that would take less
	 * advantage of mmlist ordering, which clusters forked mms
	 * together, child after parent.  If we race with dup_mmap(), we
	 * prefer to resolve parent before child, lest we miss entries
	 * duplicated after we scanned child: using last mm would invert
	 * that.  Though it's only a serious concern when an overflowed
	 * swap count is reset from SWAP_MAP_MAX, preventing a rescan.
	 */
	start_mm = &init_mm;
	atomic_inc(&init_mm.mm_users);

	/*
	 * Keep on scanning until all entries have gone.  Usually,
	 * one pass through swap_map is enough, but not necessarily:
	 * there are races when an instance of an entry might be missed.
	 *
	 * i为下一个slot索引
	 * 查找下一个要被unuse的slot的索引
	 */
	while ((i = find_next_to_unuse(si, i)) != 0) {
		
		if (signal_pending(current)) { /* 有信号未处理 */
			retval = -EINTR;
			break;
		}

		/* 
		 * Get a page for the entry, using the existing swap
		 * cache page if there is one.  Otherwise, get a clean
		 * page and read the swap into it. 
		 */
		swap_map = &si->swap_map[i]; 

		//这个entry为天下页表中的pte了
		entry = swp_entry(type, i);

		//从swap上读进来
		page = read_swap_cache_async(entry, NULL, 0);
		if (!page) {
			/*
			 * Either swap_duplicate() failed because entry
			 * has been freed independently, and will not be
			 * reused since sys_swapoff() already disabled
			 * allocation from here, or alloc_page() failed.
			 */
			if (!*swap_map)
				continue;
			retval = -ENOMEM;
			break;
		}

		/*
		 * Don't hold on to start_mm if it looks like exiting.
		 */
		if (atomic_read(&start_mm->mm_users) == 1) {
			mmput(start_mm);
			start_mm = &init_mm;
			atomic_inc(&init_mm.mm_users);
		}

		/*
		 * Wait for and lock page.  When do_swap_page races with
		 * try_to_unuse, do_swap_page can handle the fault much
		 * faster than try_to_unuse can locate the entry.  This
		 * apparently redundant "wait_on_page_locked" lets try_to_unuse
		 * defer to do_swap_page in such a case - in some tests,
		 * do_swap_page and try_to_unuse repeatedly compete.
		 *
		 * do_swap_page()也可能会将这个page读入进来，所以会有竞争出现
		 */
		wait_on_page_locked(page);
		wait_on_page_writeback(page);
		lock_page(page);
		wait_on_page_writeback(page);

		/*
		 * Remove all references to entry.
		 * Whenever we reach init_mm, there's no address space
		 * to search, but use it as a reminder to search shmem.
		 */
		shmem = 0;
		swcount = *swap_map;
		if (swcount > 1) {
			if (start_mm == &init_mm)
				shmem = shmem_unuse(entry, page);
			else //这个很重要
				retval = unuse_mm(start_mm, entry, page);
		}
		
		if (*swap_map > 1) { //有多个pte引用这个page
			int set_start_mm = (*swap_map >= swcount);
			struct list_head *p = &start_mm->mmlist;
			struct mm_struct *new_start_mm = start_mm;
			struct mm_struct *prev_mm = start_mm;
			struct mm_struct *mm;

			atomic_inc(&new_start_mm->mm_users);
			atomic_inc(&prev_mm->mm_users);
			spin_lock(&mmlist_lock);

			/*
			 * p为下一个mm_struct对象
			 *
			 * 逐个遍历mm_struct,重新设置上面使用这个page的pte
			 */
			while (*swap_map > 1 && !retval &&
					(p = p->next) != &start_mm->mmlist) {

				//从p中得到mm_struct对象
				mm = list_entry(p, struct mm_struct, mmlist);
				if (!atomic_inc_not_zero(&mm->mm_users))
					continue;
				
				spin_unlock(&mmlist_lock);
				mmput(prev_mm);
				prev_mm = mm;

				cond_resched();//调度

				swcount = *swap_map;
				if (swcount <= 1)
					;
				else if (mm == &init_mm) {
					set_start_mm = 1;
					shmem = shmem_unuse(entry, page);
				} else
					retval = unuse_mm(mm, entry, page);
				
				if (set_start_mm && *swap_map < swcount) {
					mmput(new_start_mm);
					atomic_inc(&mm->mm_users);
					new_start_mm = mm;//下一个mm_struct
					set_start_mm = 0;
				}
				spin_lock(&mmlist_lock);
			}
					
			spin_unlock(&mmlist_lock);
			mmput(prev_mm);
			mmput(start_mm);
			//设置当前要处理的mm_struct
			start_mm = new_start_mm;
		}
		if (retval) {
			unlock_page(page);
			page_cache_release(page);
			break;
		}

		/*
		 * How could swap count reach 0x7fff when the maximum
		 * pid is 0x7fff, and there's no way to repeat a swap
		 * page within an mm (except in shmem, where it's the
		 * shared object which takes the reference count)?
		 * We believe SWAP_MAP_MAX cannot occur in Linux 2.4.
		 *
		 * If that's wrong, then we should worry more about
		 * exit_mmap() and do_munmap() cases described above:
		 * we might be resetting SWAP_MAP_MAX too early here.
		 * We know "Undead"s can happen, they're okay, so don't
		 * report them; but do report if we reset SWAP_MAP_MAX.
		 */
		if (*swap_map == SWAP_MAP_MAX) {
			spin_lock(&swap_lock);
			*swap_map = 1;
			spin_unlock(&swap_lock);
			reset_overflow = 1;
		}

		/*
		 * If a reference remains (rare), we would like to leave
		 * the page in the swap cache; but try_to_unmap could
		 * then re-duplicate the entry once we drop page lock,
		 * so we might loop indefinitely; also, that page could
		 * not be swapped out to other storage meanwhile.  So:
		 * delete from cache even if there's another reference,
		 * after ensuring that the data has been saved to disk -
		 * since if the reference remains (rarer), it will be
		 * read from disk into another page.  Splitting into two
		 * pages would be incorrect if swap supported "shared
		 * private" pages, but they are handled by tmpfs files.
		 *
		 * Note shmem_unuse already deleted a swappage from
		 * the swap cache, unless the move to filepage failed:
		 * in which case it left swappage in cache, lowered its
		 * swap count to pass quickly through the loops above,
		 * and now we must reincrement count to try again later.
		 */
		if ((*swap_map > 1) && PageDirty(page) && PageSwapCache(page)) {
			
			struct writeback_control wbc = {
				.sync_mode = WB_SYNC_NONE,
			};

            //写到磁盘swap上去
			swap_writepage(page, &wbc);
			lock_page(page);
			//等待写入结束
			wait_on_page_writeback(page);
		}
		if (PageSwapCache(page)) {
			if (shmem)
				swap_duplicate(entry);
			else
				delete_from_swap_cache(page);
		}

		/*
		 * So we could skip searching mms once swap count went
		 * to 1, we did not mark any present ptes as dirty: must
		 * mark page dirty so shrink_page_list will preserve it.
		 */
		SetPageDirty(page);
		unlock_page(page);
		page_cache_release(page);

		/*
		 * Make sure that we aren't completely killing
		 * interactive performance.
		 */
		cond_resched();
	}

	mmput(start_mm);
	if (reset_overflow) {
		printk(KERN_WARNING "swapoff: cleared swap entry overflow\n");
		swap_overflow = 0;
	}
	return retval;
}

/*
 * After a successful try_to_unuse, if no swap is now in use, we know
 * we can empty the mmlist.  swap_lock must be held on entry and exit.
 * Note that mmlist_lock nests inside swap_lock, and an mm must be
 * added to the mmlist just after page_duplicate - before would be racy.
 *
 * sys_swapoff()
 *  drain_mmlist()
 *
 */
static void drain_mmlist(void)
{
	struct list_head *p, *next;
	unsigned int i;

	for (i = 0; i < nr_swapfiles; i++)
		if (swap_info[i].inuse_pages) /* 只要有page还在被使用中，那就直接返回了 */
			return;
		
	spin_lock(&mmlist_lock);
	list_for_each_safe(p, next, &init_mm.mmlist)
		list_del_init(p);
	
	spin_unlock(&mmlist_lock);
}

/*
 * Use this swapdev's extent info to locate the (PAGE_SIZE) block which
 * corresponds to page offset `offset'.
 *
 * 查找一个空闲slot
 *
 * swapdev_block()
 *  map_swap_page()
 * 
 * swap_writepage()
 *  get_swap_bio()
 *   map_swap_page()
 *
 * 返回 offset对应的block number
 */
sector_t map_swap_page(struct swap_info_struct *sis, pgoff_t offset)
{
	struct swap_extent *se = sis->curr_swap_extent;
	struct swap_extent *start_se = se;

	for ( ; ; ) {
		struct list_head *lh;

		if (se->start_page <= offset &&
				offset < (se->start_page + se->nr_pages)) {
			/* 得到block   number */
			return se->start_block + (offset - se->start_page);
		}
		lh = se->list.next;
		if (lh == &sis->extent_list) /* 跳过 */
			lh = lh->next;
		
		se = list_entry(lh, struct swap_extent, list);
		sis->curr_swap_extent = se; /* 下一个了 */
		BUG_ON(se == start_se);		/* It *must* be present */
	}
}

#ifdef CONFIG_HIBERNATION
/*
 * Get the (PAGE_SIZE) block corresponding to given offset on the swapdev
 * corresponding to given index in swap_info (swap type).
 *
 * alloc_swapdev_block()
 *  swapdev_block()
 *
 * 返回swap_info[swap_type]上offset对应的block number ?
 *
 */
sector_t swapdev_block(int swap_type, pgoff_t offset)
{
	struct swap_info_struct *sis;

	if (swap_type >= nr_swapfiles)
		return 0;

	sis = swap_info + swap_type;
	return (sis->flags & SWP_WRITEOK) ? map_swap_page(sis, offset) : 0;
}
#endif /* CONFIG_HIBERNATION */

/*
 * Free all of a swapdev's extent information
 *
 * sys_swapoff()
 *  destroy_swap_extents()
 *
 */
static void destroy_swap_extents(struct swap_info_struct *sis)
{
	while (!list_empty(&sis->extent_list)) {
		struct swap_extent *se;

        /* 删掉swap_extent   */
		se = list_entry(sis->extent_list.next,
				struct swap_extent, list);
		list_del(&se->list);
		
		kfree(se);
	}
}

/*
 * Add a block range (and the corresponding page range) into this swapdev's
 * extent list.  The extent list is kept sorted in page order.
 *
 * This function rather assumes that it is called in ascending page order.
 *
 * sys_swapon()
 *  setup_swap_extents()
 *   add_swap_extent()
 *
 * 添加给swap_extent对象到sis->extent_list上去
 */
static int
add_swap_extent(struct swap_info_struct *sis, unsigned long start_page,
		unsigned long nr_pages, sector_t start_block)
{
	struct swap_extent *se;
	struct swap_extent *new_se;
	struct list_head *lh;

	lh = sis->extent_list.prev;	/* The highest page extent */
	if (lh != &sis->extent_list) {
		se = list_entry(lh, struct swap_extent, list);
		BUG_ON(se->start_page + se->nr_pages != start_page);
		if (se->start_block + se->nr_pages == start_block) {
			/* Merge it */
			se->nr_pages += nr_pages;
			return 0;
		}
	}

	/*
	 * No merge.  Insert a new extent, preserving ordering.
	 */
	new_se = kmalloc(sizeof(*se), GFP_KERNEL);
	if (new_se == NULL)
		return -ENOMEM;
	new_se->start_page = start_page;
	new_se->nr_pages = nr_pages;
	new_se->start_block = start_block;

	list_add_tail(&new_se->list, &sis->extent_list);
	return 1;
}

/*
 * A `swap extent' is a simple thing which maps a contiguous range of pages
 * onto a contiguous range of disk blocks.  An ordered list of swap extents
 * is built at swapon time and is then used at swap_writepage/swap_readpage
 * time for locating where on disk a page belongs.
 *
 * If the swapfile is an S_ISBLK block device, a single extent is installed.
 * This is done so that the main operating code can treat S_ISBLK and S_ISREG
 * swap files identically.
 *
 * Whether the swapdev is an S_ISREG file or an S_ISBLK blockdev, the swap
 * extent list operates in PAGE_SIZE disk blocks.  Both S_ISREG and S_ISBLK
 * swapfiles are handled *identically* after swapon time.
 *
 * For S_ISREG swapfiles, setup_swap_extents() will walk all the file's blocks
 * and will parse them into an ordered extent list, in PAGE_SIZE chunks.  If
 * some stray blocks are found which do not fall within the PAGE_SIZE alignment
 * requirements, they are simply tossed out - we will never use those blocks
 * for swapping.
 *
 * For S_ISREG swapfiles we set S_SWAPFILE across the life of the swapon.  This
 * prevents root from shooting her foot off by ftruncating an in-use swapfile,
 * which will scribble on the fs.
 *
 * The amount of disk space which a single swap extent represents varies.
 * Typically it is in the 1-4 megabyte range.  So we can have hundreds of
 * extents in the list.  To avoid much list walking, we cache the previous
 * search location in `curr_swap_extent', and start new searches from there.
 * This is extremely effective.  The average number of iterations in
 * map_swap_page() has been measured at about 0.3 per page.  - akpm.
 *
 * sys_swapon()
 *  setup_swap_extents()
 *
 */
static int setup_swap_extents(struct swap_info_struct *sis, sector_t *span)
{
	struct inode *inode;
	unsigned blocks_per_page;
	unsigned long page_no;
	unsigned blkbits;
	sector_t probe_block;
	sector_t last_block;
	sector_t lowest_block = -1;
	sector_t highest_block = 0;
	int nr_extents = 0;
	int ret;

	inode = sis->swap_file->f_mapping->host;
	if (S_ISBLK(inode->i_mode)) { /* 是块设备文件 */
		/* 添加一个swap_extent到sis->extent_list */
		ret = add_swap_extent(sis, 0, sis->max, 0);
		*span = sis->pages;
		goto done;
	}

    /*
     * 执行到这里，说明swap_info_struct->swap_file只是一个普通文件了
     * 那就可能需要添加多个swap_extent结构了
     */
	
	blkbits = inode->i_blkbits;
	/* 一个磁盘page对应的磁盘块的数量 */
	blocks_per_page = PAGE_SIZE >> blkbits;

	/*
	 * Map all the blocks into the extent list.  This code doesn't try
	 * to be very smart.
	 */
	probe_block = 0; /* 已经读进来的block号码，相对 */
	page_no = 0;
	
	last_block = i_size_read(inode) >> blkbits;
	
	while ((probe_block + blocks_per_page) <= last_block &&
			page_no < sis->max) {
			
		unsigned block_in_page;
		sector_t first_block;

        /* 调用inode->i_mapping->a_ops->bmap   
         * 就是ext2_bmap函数
         *
         * 只映射第一个block
		 */
		first_block = bmap(inode, probe_block);
		if (first_block == 0)
			goto bad_bmap;

		/*
		 * It must be PAGE_SIZE aligned on-disk
		 */
		if (first_block & (blocks_per_page - 1)) {
			probe_block++;
			goto reprobe;
		}

		for (block_in_page = 1; block_in_page < blocks_per_page;
					block_in_page++) {
			sector_t block;

            /* 调用inode->i_mapping->a_ops->bmap   
             * 就是ext2_bmap函数
             * 返回block no,相对
			 */
			block = bmap(inode, probe_block + block_in_page);
			if (block == 0)
				goto bad_bmap;
			
			if (block != first_block + block_in_page) {
				/* Discontiguity,需要继续bmap */
				probe_block++;
				goto reprobe;
			}
		}

		first_block >>= (PAGE_SHIFT - blkbits);
		if (page_no) {	/* exclude the header page */
			if (first_block < lowest_block)
				lowest_block = first_block;
			
			if (first_block > highest_block)
				highest_block = first_block;
		}

		/*
		 * We found a PAGE_SIZE-length, PAGE_SIZE-aligned run of blocks
		 * 给swap_info_struct添加extent
		 */
		ret = add_swap_extent(sis, page_no, 1, first_block);
		if (ret < 0)
			goto out;
		nr_extents += ret;
		page_no++;
		probe_block += blocks_per_page;
reprobe:
		continue;
	}
			
	ret = nr_extents;
	*span = 1 + highest_block - lowest_block;
	if (page_no == 0)
		page_no = 1;	/* force Empty message */
	sis->max = page_no;
	sis->pages = page_no - 1;
	sis->highest_bit = page_no - 1;
done:
	sis->curr_swap_extent = list_entry(sis->extent_list.prev,
					struct swap_extent, list);
	goto out;
bad_bmap:
	printk(KERN_ERR "swapon: swapfile has holes\n");
	ret = -EINVAL;
out:
	return ret;
}

#if 0	/* We don't need this yet */
#include <linux/backing-dev.h>
int page_queue_congested(struct page *page)
{
	struct backing_dev_info *bdi;

	BUG_ON(!PageLocked(page));	/* It pins the swap_info_struct */

	if (PageSwapCache(page)) {
		swp_entry_t entry = { .val = page_private(page) };
		struct swap_info_struct *sis;

		sis = get_swap_info_struct(swp_type(entry));
		bdi = sis->bdev->bd_inode->i_mapping->backing_dev_info;
	} else
		bdi = page->mapping->backing_dev_info;
	return bdi_write_congested(bdi);
}
#endif

/*
 * swapoff系统调用 
 * 使specialfile所指定的交换区无效
 */
asmlinkage long sys_swapoff(const char __user * specialfile)
{
	struct swap_info_struct * p = NULL;
	unsigned short *swap_map;
	struct file *swap_file, *victim;
	struct address_space *mapping;
	struct inode *inode;
	char * pathname;
	int i, type, prev;
	int err;
	
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	pathname = getname(specialfile);
	err = PTR_ERR(pathname);
	if (IS_ERR(pathname))
		goto out;

	victim = filp_open(pathname, O_RDWR|O_LARGEFILE, 0);
	putname(pathname);
	err = PTR_ERR(victim);
	if (IS_ERR(victim))
		goto out;

	/* 得到文件对应的address_sapce */
 	mapping = victim->f_mapping;
	prev = -1;
	spin_lock(&swap_lock);
	/*
	 * 然后是扫描swap_list地址，看循环体中的条件，其中swap_list是交换区描述符链表。
	 * 而swap_info数组则包括MAX_SWAPFILES个交换区描述符。
	 * 其中的字段next存放的就是swap_info数组中下一个描述符的索引。
	 * 也就是说从描述符链表的基地址开始，然后p = swap_info + type得到的是基地址＋索引。
	 * 此时判断当前交换区的flags，如果此时是激活的，继续判断其中的对象，如果与传入的参数一样，
	 * 那么跳出循环。判断的意思是，如果不一致，那么传给函数的就是一个无效参数。
	 * 那么就要返回错误码。
	 *
	 * 找到specialfile对应的 swap_list_t对象.
	 */
	for (type = swap_list.head; type >= 0; type = swap_info[type].next) {
		p = swap_info + type;
		if ((p->flags & SWP_ACTIVE) == SWP_ACTIVE) {
			if (p->swap_file->f_mapping == mapping) //找到
				break;
		}
		prev = type;
	}
	
	/*
	 * 当type小于0的时候，那一定是完整执行循环的。也就是swap_info[type].next为负数了。
	 * 那么也是没有找到相应对象。此时就返回错误码。如果程序没有执行这个程序块的话，
	 * 那么就证明找到了参数传递的，可以进行下面的操作。
	 * 然后就是判断是否有足够的空闲页框把交换区上存放的所有页换入。
	 */
	if (type < 0) {
		err = -EINVAL;
		spin_unlock(&swap_lock);
		goto out_dput;
	}
	
	if (!security_vm_enough_memory(p->pages)) //是否有足够的内存存放p->pages个page
		vm_unacct_memory(p->pages);
	else {
		err = -ENOMEM;
		spin_unlock(&swap_lock);
		goto out_dput;
	}

	/*
	 * 如果又找到了对应对象，又有足够的内存空余，那么就可以进行操作了。
	 * 从上面的循环体中可以得知，如果prev是－1，那么一定是表头。那么就将它从链表上摘除，
	 * 也就是直接让head＝他的next.反之如果是中间的部分，那么也是如此，链表的简单操作。
	 */
	if (prev < 0) {
		swap_list.head = p->next;
	} else {
		swap_info[prev].next = p->next;
	}
	
	if (type == swap_list.next) {
		/* just pick something that's safe... */
		swap_list.next = swap_list.head;
	}

	
	nr_swap_pages -= p->pages; /* 也就是从所有活动交换区中可用的页槽总数减去当前交换区的可用页槽个数 */
	total_swap_pages -= p->pages; /* 从无缺陷页槽总数中减去当前交换区的页槽数。 */
	p->flags &= ~SWP_WRITEOK; /* 将交换区描述符中的SWP_WRITEOK标志清零。此标志清零的作用就是表明当前交换区只读。 */
	spin_unlock(&swap_lock);

	current->flags |= PF_SWAPOFF;
	/*
	 * 下面这个函数的作用就是强制将交换区中所有页都转移到ram中，
	 * 并相应地修改使用这些页的进程的页表。当执行该函数时，当前进程的PF_SWAPOFF标志置位，
	 * 该标志位置位的只有一个结果，页框严重不足，select_bad_process()函数就会被强制选择并删除该进程。
	 * 并且一直等到交换区所在的块设备驱动器被卸载。在交换区禁用之前，这个函数发出的读请求会被驱动器处理。
	 */
	err = try_to_unuse(type);
	current->flags &= ~PF_SWAPOFF;

	if (err) {
		/* try_to_unuse函数失败，那么就不能禁用这个交换区 */
		/* re-insert swap space back into swap_list */
		spin_lock(&swap_lock);
		for (prev = -1, i = swap_list.head; i >= 0; prev = i, i = swap_info[i].next)
			if (p->prio >= swap_info[i].prio)
				break;
			
		p->next = i;
		if (prev < 0)
			swap_list.head = swap_list.next = p - swap_info;
		else
			swap_info[prev].next = p - swap_info;
		
		nr_swap_pages += p->pages;
		total_swap_pages += p->pages;
		p->flags |= SWP_WRITEOK;
		spin_unlock(&swap_lock);
		goto out_dput;
	}

	/* wait for any unplug function to finish */
	down_write(&swap_unplug_sem);
	up_write(&swap_unplug_sem);

	destroy_swap_extents(p);
	mutex_lock(&swapon_mutex);
	spin_lock(&swap_lock);
	drain_mmlist();

	/* wait for anyone still in scan_swap_map */
	p->highest_bit = 0;		/* cuts scans short */
	while (p->flags >= SWP_SCANNING) {
		spin_unlock(&swap_lock);
		schedule_timeout_uninterruptible(1);
		spin_lock(&swap_lock);
	}

	swap_file = p->swap_file;
	p->swap_file = NULL; /* 清空对应的文件 */
	p->max = 0;
	swap_map = p->swap_map;
	p->swap_map = NULL;
	p->flags = 0;
	spin_unlock(&swap_lock);
	mutex_unlock(&swapon_mutex);
	vfree(swap_map);
	inode = mapping->host;
	if (S_ISBLK(inode->i_mode)) { /* 设备文件 */
		struct block_device *bdev = I_BDEV(inode);
		set_blocksize(bdev, p->old_block_size);
		bd_release(bdev);
	} else {
		mutex_lock(&inode->i_mutex);
		inode->i_flags &= ~S_SWAPFILE;
		mutex_unlock(&inode->i_mutex);
	}
	filp_close(swap_file, NULL);
	err = 0;

out_dput:
	filp_close(victim, NULL);
out:
	return err;
}

#ifdef CONFIG_PROC_FS
/* iterator */
static void *swap_start(struct seq_file *swap, loff_t *pos)
{
	struct swap_info_struct *ptr = swap_info;
	int i;
	loff_t l = *pos;

	mutex_lock(&swapon_mutex);

	if (!l)
		return SEQ_START_TOKEN;

	for (i = 0; i < nr_swapfiles; i++, ptr++) {
		
		if (!(ptr->flags & SWP_USED) || !ptr->swap_map)
			continue;
		
		if (!--l)
			return ptr;
	}

	return NULL;
}

static void *swap_next(struct seq_file *swap, void *v, loff_t *pos)
{
	struct swap_info_struct *ptr;
	struct swap_info_struct *endptr = swap_info + nr_swapfiles;

	if (v == SEQ_START_TOKEN)
		ptr = swap_info;
	else {
		ptr = v;
		ptr++;
	}

	for (; ptr < endptr; ptr++) {
		/* 未被使用 */
		if (!(ptr->flags & SWP_USED) || !ptr->swap_map)
			continue;
		
		++*pos;
		return ptr;
	}

	return NULL;
}

static void swap_stop(struct seq_file *swap, void *v)
{
	mutex_unlock(&swapon_mutex);
}

/*
 * 读取 /proc/swaps的时候，会调用到这个
 */
static int swap_show(struct seq_file *swap, void *v)
{
	struct swap_info_struct *ptr = v;
	struct file *file;
	int len;

	if (ptr == SEQ_START_TOKEN) {
		seq_puts(swap,"Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n");
		return 0;
	}

	file = ptr->swap_file;
	len = seq_path(swap, file->f_path.mnt, file->f_path.dentry, " \t\n\\");
	seq_printf(swap, "%*s%s\t%u\t%u\t%d\n",
		       len < 40 ? 40 - len : 1, " ",
		       S_ISBLK(file->f_path.dentry->d_inode->i_mode) ?
				"partition" : "file\t",
		       ptr->pages << (PAGE_SHIFT - 10),
		       ptr->inuse_pages << (PAGE_SHIFT - 10),
		       ptr->prio);
	return 0;
}

static const struct seq_operations swaps_op = {
	.start =	swap_start,
	.next =		swap_next,
	.stop =		swap_stop,
	.show =		swap_show
};

static int swaps_open(struct inode *inode, struct file *file)
{
    /* 迭代swap_info打开 */
	return seq_open(file, &swaps_op);
}

static const struct file_operations proc_swaps_operations = {
	.open		= swaps_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};


static int __init procswaps_init(void)
{
	struct proc_dir_entry *entry;

	entry = create_proc_entry("swaps", 0, NULL);
	if (entry)
		entry->proc_fops = &proc_swaps_operations;
	return 0;
}
__initcall(procswaps_init);
#endif /* CONFIG_PROC_FS */

/*
 * Written 01/25/92 by Simmule Turner, heavily changed by Linus.
 *
 * The swapon system call
 *
 * swapon系统调用
 */
asmlinkage long sys_swapon(const char __user * specialfile, int swap_flags)
{
	struct swap_info_struct * p;
	char *name = NULL;
	struct block_device *bdev = NULL;
	struct file *swap_file = NULL;
	struct address_space *mapping;
	unsigned int type;
	int i, prev;
	int error;
	static int least_priority;
	union swap_header *swap_header = NULL;
	int swap_header_version;
	unsigned int nr_good_pages = 0;
	int nr_extents = 0;
	sector_t span;
	unsigned long maxpages = 1;
	int swapfilesize;
	unsigned short *swap_map;
	struct page *page = NULL;
	struct inode *inode = NULL;
	int did_down = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	spin_lock(&swap_lock);
	p = swap_info;
	for (type = 0 ; type < nr_swapfiles ; type++,p++)
		if (!(p->flags & SWP_USED)) /* 找到第一个未被使用的一个swap_info_struct 在swap_info[]中的索引 */
			break;
		
	error = -EPERM;
	if (type >= MAX_SWAPFILES) { //过头了
		spin_unlock(&swap_lock);
		goto out;
	}
	
	if (type >= nr_swapfiles) /* 是最后一个swap_info_struct */
		nr_swapfiles = type+1;

	/* 初始化交换区描述符 */
	INIT_LIST_HEAD(&p->extent_list);
	//标识swap_info_struct信息
	p->flags = SWP_USED;
	p->swap_file = NULL;
	p->old_block_size = 0; /* 存放交换区的磁盘分区自然块大小 */
	p->swap_map = NULL; /* 指向计数器数组的指针，交换区的每个页槽对应一个数组元素 */
	p->lowest_bit = 0; /* 在搜索一个空闲页槽时要扫描的第一个页槽 */
	p->highest_bit = 0; /* 在搜索一个空闲页槽时要扫描的最后一个页槽 */
	p->cluster_nr = 0; /* 在搜索一个空闲页槽时要扫描的下一个页槽 */
	p->inuse_pages = 0; /* 交换区内已用页槽 */
	p->next = -1; /* 指向下一个交换区描述符的指针，这里是int类型，因为实际上是数组索引。 */

	/*
	 * 处理交换区的优先级问题。swap_flags是参数传递而来的，
	 * 只有SWAP_FLAG_PREFER置位的时候优先级别才有意义
	 */
	if (swap_flags & SWAP_FLAG_PREFER) {
		p->prio =
		  (swap_flags & SWAP_FLAG_PRIO_MASK)>>SWAP_FLAG_PRIO_SHIFT;
	} else {
		p->prio = --least_priority;
	}
	spin_unlock(&swap_lock);
	/*
	 * 用函数传递的参数获得字符串，
	 * 从用户态地址复制参数指向的设备文件、分区的路径名或者是指向实现交换区的普通文件的路径名。并打开指定文件
	 */
	name = getname(specialfile);
	error = PTR_ERR(name);
	if (IS_ERR(name)) {
		name = NULL;
		goto bad_swap_2;
	}
	/* swapfile 对应的文件名称 */
	swap_file = filp_open(name, O_RDWR|O_LARGEFILE, 0);
	error = PTR_ERR(swap_file);
	if (IS_ERR(swap_file)) {
		swap_file = NULL;
		goto bad_swap_2;
	}

	/* swap area对应的文件 */
	p->swap_file = swap_file;
	mapping = swap_file->f_mapping;
	inode = mapping->host;

	error = -EBUSY;
	/*
	 * 再次检查swap_info其他的活动区，确定此交换区未被激活，
	 * 第一个if的作用就是判断是否为空，如果不满足条件，
	 * 那么第二个if判断交换区描述符中存放的adress_space对象地址。
	 * 如果已经激活，那么返回错误提示。
	 */
	for (i = 0; i < nr_swapfiles; i++) {
		struct swap_info_struct *q = &swap_info[i];

		if (i == type || !q->swap_file) /*swap_info[type]对应的对象没有对应打开的文件  */
			continue;
		
		if (mapping == q->swap_file->f_mapping) //之前选中的swap_info_struct对象标识的交换区已经被激活，出现错误了。
			goto bad_swap;
	}

	error = -EINVAL;

	//inode为交换区的inode，为设备文件或者普通的ext2,ext3,ext4之类的文件
	if (S_ISBLK(inode->i_mode)) { /* swap area是否是块设备 */

	    /* 下面两句把交换子系统设置成块设备的占有者 */
		bdev = I_BDEV(inode);
		/* 变为持有者 */
		error = bd_claim(bdev, sys_swapon);
		if (error < 0) {
			bdev = NULL;
			error = -EINVAL;
			goto bad_swap;
		}
		//返回bdev->bd_block_size的值
		p->old_block_size = block_size(bdev);
		error = set_blocksize(bdev, PAGE_SIZE);
		if (error < 0)
			goto bad_swap;
		p->bdev = bdev;
		
	} else if (S_ISREG(inode->i_mode)) { /* swap area 是否是普通文件 */
		/*
		 * 如果是普通文件，搜索S_SWAPFILE字段：IS_SWAPFILE(inode)如果已经置位，
		 * 则该文件已经被用于交换区，返回错误
	     */
		p->bdev = inode->i_sb->s_bdev;
		mutex_lock(&inode->i_mutex);
		did_down = 1;
		if (IS_SWAPFILE(inode)) {
			error = -EBUSY;
			goto bad_swap;
		}
	} else {
		goto bad_swap;
	}

    /*  */
	swapfilesize = i_size_read(inode) >> PAGE_SHIFT;

	/*
	 * Read the swap header.
	 * 在已经打开的文件，读入第一页，包含坏块信息和交换区的长度之类的信息
	 */
	if (!mapping->a_ops->readpage) {
		error = -EINVAL;
		goto bad_swap;
	}

	/* 读入存放在交换区页槽0中的swap_header描述符 */
	page = read_mapping_page(mapping, 0, swap_file);
	if (IS_ERR(page)) {
		error = PTR_ERR(page);
		goto bad_swap;
	}
	kmap(page);

	/* 检查交换区中第一页的最后10个字符中的魔术字符串 */
	swap_header = page_address(page);
	if (!memcmp("SWAP-SPACE",swap_header->magic.magic,10))
		swap_header_version = 1;
	else if (!memcmp("SWAPSPACE2",swap_header->magic.magic,10))
		swap_header_version = 2;
	else {
		printk(KERN_ERR "Unable to find swap-space signature\n");
		error = -EINVAL;
		goto bad_swap;
	}
	
	switch (swap_header_version) {
	case 1:
		printk(KERN_ERR "version 0 swap is no longer supported. "
			"Use mkswap -v1 %s\n", name);
		error = -EINVAL;
		goto bad_swap;
	case 2:
		/* Check the swap header's sub-version and the size of
                   the swap file and bad block lists */
		if (swap_header->info.version != 1) {
			printk(KERN_WARNING
			       "Unable to handle swap header version %d\n",
			       swap_header->info.version);
			error = -EINVAL;
			goto bad_swap;
		}

        /*
         * p->lowest_bit表示的是开始搜索空闲页槽时的起始第一个页槽。
         * p->highest_bit表示的是搜索空闲页槽的时候要扫描的下一个页槽
         * 而swapheader联合体中的字段：info.last_page，可有效使用的最后一个页槽。
         * 那么p->highest_bit = maxpages - 1的作用就明朗了。
         * 减一是因为第一个页槽是留给联合体的。
		 */
		p->lowest_bit  = 1;
		p->cluster_next = 1;

		/*
		 * Find out how many pages are allowed for a single swap
		 * device. There are two limiting factors: 1) the number of
		 * bits for the swap offset in the swp_entry_t type and
		 * 2) the number of bits in the a swap pte as defined by
		 * the different architectures. In order to find the
		 * largest possible bit mask a swap entry with swap type 0
		 * and swap offset ~0UL is created, encoded to a swap pte,
		 * decoded to a swp_entry_t again and finally the swap
		 * offset is extracted. This will mask all the bits from
		 * the initial ~0UL mask that can't be encoded in either
		 * the swp_entry_t or the architecture definition of a
		 * swap pte.
		 *
		 * 一个swap area中对多的page数量
		 */
		maxpages = swp_offset(pte_to_swp_entry(swp_entry_to_pte(swp_entry(0,~0UL)))) - 1;
		if (maxpages > swap_header->info.last_page)
			maxpages = swap_header->info.last_page;
		
		p->highest_bit = maxpages - 1;

		error = -EINVAL;
		if (!maxpages)
			goto bad_swap;
		if (swapfilesize && maxpages > swapfilesize) {
			printk(KERN_WARNING
			       "Swap area shorter than signature indicates\n");
			goto bad_swap;
		}
		
		if (swap_header->info.nr_badpages && S_ISREG(inode->i_mode))
			goto bad_swap;
		
		if (swap_header->info.nr_badpages > MAX_SWAP_BADPAGES)
			goto bad_swap;

		/* OK, set up the swap map and apply the bad block list */
		/*
		 * 接下来的工作就是创建与新交换区相关的计数器数组
		 * 一个page对应map中的一个元素.
		 */
		if (!(p->swap_map = vmalloc(maxpages * sizeof(short)))) {
			error = -ENOMEM;
			goto bad_swap;
		}

		error = 0;

		/* 利用swap_header中的字段：info.badpages来判断初始化这个数组的swap_map的数值 */
		memset(p->swap_map, 0, maxpages * sizeof(short));
		/* 把所有的badpages，标记为SWAP_MAP_BAD */
		for (i = 0; i < swap_header->info.nr_badpages; i++) {
		    /* 该page在swap_info_struct->swap_map[]中的索引 */
			int page_nr = swap_header->info.badpages[i];
			if (page_nr <= 0 || page_nr >= swap_header->info.last_page)
				error = -EINVAL;
			else
				p->swap_map[page_nr] = SWAP_MAP_BAD;
		}
		/* 可有效使用的最后一个页槽减去坏的页槽数和第一个页槽。
		 * 然后就是将数值赋给交换区描述符 
		 */
		nr_good_pages = swap_header->info.last_page -
				swap_header->info.nr_badpages -
				1 /* header page */;
		if (error)
			goto bad_swap;
	}

	if (nr_good_pages) {
		/* 首个page不能用 */
		p->swap_map[0] = SWAP_MAP_BAD;
		p->max = maxpages;
		p->pages = nr_good_pages;
		/* span中返回block的数量 
		 * 初始化非连续的区间链表
		 *
		 * 设置swap_info_struct->extent_list
		 */
		nr_extents = setup_swap_extents(p, &span);
		if (nr_extents < 0) {
			error = nr_extents;
			goto bad_swap;
		}
		nr_good_pages = p->pages;
	}
	if (!nr_good_pages) {
		printk(KERN_WARNING "Empty swap-file\n");
		error = -EINVAL;
		goto bad_swap;
	}

	mutex_lock(&swapon_mutex);
	spin_lock(&swap_lock);
	/*
	 * nr_swap_pages包含的是所有活动交换区中的可用（空闲且无缺陷）的页槽数目，
	 * 此时就是加上了新激活的交换区可用页槽数目。flags字段是交换区当前状态，
	 * 是处于激活状态。而同样total_swap_pages包含的是无缺陷页槽总数。
	 *
	 * 该swap_info_struct被激活了.
	 */
	p->flags = SWP_ACTIVE;
	nr_swap_pages += nr_good_pages;
	total_swap_pages += nr_good_pages;

	printk(KERN_INFO "Adding %uk swap on %s.  "
			"Priority:%d extents:%d across:%lluk\n",
		nr_good_pages<<(PAGE_SHIFT-10), name, p->prio,
		nr_extents, (unsigned long long)span<<(PAGE_SHIFT-10));

	/* insert swap space into swap_list: */
	prev = -1;
	/*
	 * 接下来的工作就是将新交换区描述符插入到swap_list变量所指向的链表中。
	 * 其中swap_list的head字段是优先级最高元素链表在swap_info数组中的下标。
	 * 而next字段为换出页所选中的下一个交换区的描述符在swap_info数组中的下标。
	 * 该字段用于在具有空闲页槽的最大优先级的交换区之间实现轮询算法
	 */
	for (i = swap_list.head; i >= 0; i = swap_info[i].next) {
		if (p->prio >= swap_info[i].prio) { /* 优先级 */
			break;
		}
		prev = i;
	}

	/* 根据上面的for循环，swap_info_struct根据prio排序的 */
	p->next = i;
	if (prev < 0) { /*优先级最高的了 */
		swap_list.head = swap_list.next = p - swap_info;
	} else {
		swap_info[prev].next = p - swap_info;
	}
	spin_unlock(&swap_lock);
	mutex_unlock(&swapon_mutex);
	error = 0;
	goto out;
bad_swap:
	if (bdev) {
		set_blocksize(bdev, p->old_block_size);
		bd_release(bdev);
	}
	destroy_swap_extents(p);
bad_swap_2:
	spin_lock(&swap_lock);
	swap_map = p->swap_map;
	p->swap_file = NULL;
	p->swap_map = NULL;
	p->flags = 0;
	if (!(swap_flags & SWAP_FLAG_PREFER))
		++least_priority;
	spin_unlock(&swap_lock);
	vfree(swap_map);
	if (swap_file)
		filp_close(swap_file, NULL);
out:
	if (page && !IS_ERR(page)) {
		kunmap(page);
		page_cache_release(page);
	}
	if (name)
		putname(name);
	if (did_down) {
		if (!error)
			inode->i_flags |= S_SWAPFILE;
		mutex_unlock(&inode->i_mutex);
	}
	return error;
}

/* 统计类型的信息 */
void si_swapinfo(struct sysinfo *val)
{
	unsigned int i;
	unsigned long nr_to_be_unused = 0;

	spin_lock(&swap_lock);
	for (i = 0; i < nr_swapfiles; i++) {
		if (!(swap_info[i].flags & SWP_USED) ||
		     (swap_info[i].flags & SWP_WRITEOK))
			continue;
		
		nr_to_be_unused += swap_info[i].inuse_pages;
	}
	val->freeswap = nr_swap_pages + nr_to_be_unused;
	val->totalswap = total_swap_pages + nr_to_be_unused;
	spin_unlock(&swap_lock);
}

/*
 * Verify that a swap entry is valid and increment its swap map count.
 *
 * 将entry对应的swap_map[]加 1
 *
 * Note: if swap_map[] reaches SWAP_MAP_MAX the entries are treated as
 * "permanent", but will be reclaimed by the next swapoff.
 *
 * add_to_swap_cache()
 *  swap_duplicate()
 *
 *
 * dup_mm()
 *	copy_page_range()
 *	 copy_pud_range()
 *	  copy_pmd_range()
 *     copy_pte_range()
 *      copy_one_pte() 
 *       swap_duplicate()
 *
 * try_to_unmap()
 *  try_to_unmap_file()
 *   try_to_unmap_one()
 *    swap_duplicate()
 *
 * 主要是swap_info_struct->swap_map[offset]++，表明entry对应的page被换出多次了
 */
int swap_duplicate(swp_entry_t entry)
{
	struct swap_info_struct * p;
	unsigned long offset, type;
	int result = 0;

	if (is_migration_entry(entry))
		return 1;
    /* swap_info中索引 */
	type = swp_type(entry);
	if (type >= nr_swapfiles)
		goto bad_file;

	
	p = type + swap_info;
	offset = swp_offset(entry);

	spin_lock(&swap_lock);
	if (offset < p->max && p->swap_map[offset]) {
		if (p->swap_map[offset] < SWAP_MAP_MAX - 1) {
			/* 共享的多了一次 */
			p->swap_map[offset]++;
			result = 1;
		} else if (p->swap_map[offset] <= SWAP_MAP_MAX) {
			/* 共享的超出数量了 */
			if (swap_overflow++ < 5)
				printk(KERN_WARNING "swap_dup: swap entry overflow\n");
			p->swap_map[offset] = SWAP_MAP_MAX;
			result = 1;
		}
	}
	spin_unlock(&swap_lock);
out:
	return result;

bad_file:
	printk(KERN_ERR "swap_dup: %s%08lx\n", Bad_file, entry.val);
	goto out;
}

/* 根据索引，返回swap_info_struct对象 */
struct swap_info_struct *
get_swap_info_struct(unsigned type)
{
	return &swap_info[type];
}

/*
 * swap_lock prevents swap_map being freed. Don't grab an extra
 * reference on the swaphandle, it doesn't matter if it becomes unused.
 *
 * 
 */
int valid_swaphandles(swp_entry_t entry, unsigned long *offset)
{
	int our_page_cluster = page_cluster;
	int ret = 0, i = 1 << our_page_cluster;
	unsigned long toff;
	/* 对应的 */
	struct swap_info_struct *swapdev = swp_type(entry) + swap_info;

	if (!our_page_cluster)	/* no readahead */
		return 0;
	
	toff = (swp_offset(entry) >> our_page_cluster) << our_page_cluster;
	if (!toff)		/* first page is swap header */
		toff++, i--;
	*offset = toff;

	spin_lock(&swap_lock);
	do {
		/* Don't read-ahead past the end of the swap area */
		if (toff >= swapdev->max)
			break;
		/* Don't read in free or bad pages */
		if (!swapdev->swap_map[toff])
			break;
		if (swapdev->swap_map[toff] == SWAP_MAP_BAD)
			break;
		toff++;
		ret++;
	} while (--i);
	spin_unlock(&swap_lock);
	return ret;
}
