/*
 *  linux/mm/swap_state.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *
 *  Rewritten to use page cache, (C) 1998 Stephen Tweedie
 */
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/migrate.h>

#include <asm/pgtable.h>

/*
 * swapper_space is a fiction, retained to simplify the path through
 * vmscan's shrink_page_list, to make sync_page look nicer, and to allow
 * future use of radix_tree tags in the swap cache.
 */
static const struct address_space_operations swap_aops = {
	.writepage	= swap_writepage,
	.sync_page	= block_sync_page,
	.set_page_dirty	= __set_page_dirty_nobuffers,
	.migratepage	= migrate_page,
};

static struct backing_dev_info swap_backing_dev_info = {
	.capabilities	= BDI_CAP_NO_ACCT_DIRTY | BDI_CAP_NO_WRITEBACK,
	.unplug_io_fn	= swap_unplug_io_fn,
};

/*
 * swapper_space在选择交换换出页和实际执行页交换的机制之间，充当协调者
 */
struct address_space swapper_space = {
	.page_tree	= RADIX_TREE_INIT(GFP_ATOMIC|__GFP_NOWARN),
	.tree_lock	= __RW_LOCK_UNLOCKED(swapper_space.tree_lock),
	.a_ops		= &swap_aops,
	.i_mmap_nonlinear = LIST_HEAD_INIT(swapper_space.i_mmap_nonlinear),
	.backing_dev_info = &swap_backing_dev_info,
};

#define INC_CACHE_INFO(x)	do { swap_cache_info.x++; } while (0)

static struct {
	unsigned long add_total;
	unsigned long del_total;
	unsigned long find_success;
	unsigned long find_total;
	unsigned long noent_race;
	unsigned long exist_race;
} swap_cache_info;

void show_swap_cache_info(void)
{
	printk("Swap cache: add %lu, delete %lu, find %lu/%lu, race %lu+%lu\n",
		swap_cache_info.add_total, swap_cache_info.del_total,
		swap_cache_info.find_success, swap_cache_info.find_total,
		swap_cache_info.noent_race, swap_cache_info.exist_race);
	printk("Free swap  = %lukB\n", nr_swap_pages << (PAGE_SHIFT - 10));
	printk("Total swap = %lukB\n", total_swap_pages << (PAGE_SHIFT - 10));
}

/*
 * __add_to_swap_cache resembles add_to_page_cache on swapper_space,
 * but sets SwapCache flag and private instead of mapping and index.
 *
 * 添加page到swapper_space.page_tree中，
 * 并且在调用这个函数之前page已经被写入到swap磁盘分区中去了
 * 或者已经存在于swap磁盘分区中，但是读进来了
 *
 * read_swap_cache_async()
 *  add_to_swap_cache()
 *   __add_to_swap_cache()
 *
 * move_to_swap_cache()
 *  __add_to_swap_cache()
 *
 * 
 */
static int __add_to_swap_cache(struct page *page, swp_entry_t entry,
			       gfp_t gfp_mask)
{
	int error;

	BUG_ON(!PageLocked(page));
	BUG_ON(PageSwapCache(page));
	BUG_ON(PagePrivate(page));
	error = radix_tree_preload(gfp_mask);
	if (!error) {
		write_lock_irq(&swapper_space.tree_lock);
		//把page加入到swapper_space中去
		error = radix_tree_insert(&swapper_space.page_tree,
						entry.val, page);
		if (!error) {
			page_cache_get(page);
			SetPageSwapCache(page); /* 设置page->flags设置PG_swapcache */
			set_page_private(page, entry.val); /* 设置page->private = entry.val */
			total_swapcache_pages++;
			__inc_zone_page_state(page, NR_FILE_PAGES);
		}
		write_unlock_irq(&swapper_space.tree_lock);
		radix_tree_preload_end();
	}
	return error;
}

/*
 * 将一个page添加到swapper_space
 * 
 * read_swap_cache_async()
 *  add_to_swap_cache()
 *
 */
static int add_to_swap_cache(struct page *page, swp_entry_t entry)
{
	int error;

	BUG_ON(PageLocked(page));
	
	if (!swap_duplicate(entry)) { /* 主要是swap_info_struct->swap_map[offset]++，表明page被换出去的次数*/
		INC_CACHE_INFO(noent_race);
		return -ENOENT;
	}
	SetPageLocked(page);
	error = __add_to_swap_cache(page, entry, GFP_KERNEL);
	/*
	 * Anon pages are already on the LRU, we don't run lru_cache_add here.
	 */
	if (error) {
		ClearPageLocked(page);
		swap_free(entry);
		if (error == -EEXIST)
			INC_CACHE_INFO(exist_race);
		return error;
	}
	INC_CACHE_INFO(add_total);
	return 0;
}

/*
 * This must be called only on pages that have
 * been verified to be in the swap cache.
 *
 * 从swapper_space.page_tree中删除page,
 * 清空page->private,清空page->flags上的PG_swapcache标记
 *
 * remove_exclusive_swap_page()
 *  __delete_from_swap_cache()
 *
 * shmem_getpage()
 *  delete_from_swap_cache()
 *   __delete_from_swap_cache()
 *
 * free_swap_and_cache()
 *  delete_from_swap_cache()
 *   __delete_from_swap_cache()
 *
 * try_to_unuse()
 *  delete_from_swap_cache()
 *   __delete_from_swap_cache()
 *
 * move_from_swap_cache()
 *  delete_from_swap_cache() 
 *   __delete_from_swap_cache()
 *
 */
void __delete_from_swap_cache(struct page *page)
{
	BUG_ON(!PageLocked(page));
	BUG_ON(!PageSwapCache(page));
	BUG_ON(PageWriteback(page));
	BUG_ON(PagePrivate(page));

	radix_tree_delete(&swapper_space.page_tree, page_private(page));
	set_page_private(page, 0);
	ClearPageSwapCache(page);
	total_swapcache_pages--;
	__dec_zone_page_state(page, NR_FILE_PAGES);
	INC_CACHE_INFO(del_total);
}

/**
 * add_to_swap - allocate swap space for a page
 * @page: page we want to move to swap
 *
 * Allocate swap space for the page and add the page to the
 * swap cache.  Caller needs to hold the page lock. 
 *
 *
 * add_to_swap总共完成了两个动作，一个动作就是为一个page申请一个交换分区的页槽，
 * 一个动作是将页加入到页面交换缓冲区swapper_space 
 *
 * shrink_zone()
 *  shrink_inactive_list()
 *   shrink_page_list()
 *    add_to_swap()
 */
int add_to_swap(struct page * page, gfp_t gfp_mask)
{
	swp_entry_t entry;
	int err;

	BUG_ON(!PageLocked(page));

	for (;;) {
		/* 获得一个空闲的swap_entry */
		entry = get_swap_page();
		if (!entry.val)
			return 0;

		/*
		 * Radix-tree node allocations from PF_MEMALLOC contexts could
		 * completely exhaust the page allocator. __GFP_NOMEMALLOC
		 * stops emergency reserves from being allocated.
		 *
		 * TODO: this could cause a theoretical memory reclaim
		 * deadlock in the swap out path.
		 */
		/*
		 * Add it to the swap cache and mark it dirty
		 *
		 * 添加page到swapper_space.page_tree
		 */
		err = __add_to_swap_cache(page, entry,
				gfp_mask|__GFP_NOMEMALLOC|__GFP_NOWARN);

		switch (err) {
		case 0:				/* Success */
			SetPageUptodate(page); /* 设置page->flags的PG_uptodate标记 */
			SetPageDirty(page);   /* 设置page->flags的PG_dirty标记 */
			INC_CACHE_INFO(add_total);
			return 1;
		case -EEXIST:
			/* Raced with "speculative" read_swap_cache_async */
			INC_CACHE_INFO(exist_race);
			swap_free(entry);
			continue;
		default:
			/* -ENOMEM radix-tree allocation failure */
			swap_free(entry);
			return 0;
		}
	}
}

/*
 * This must be called only on pages that have
 * been verified to be in the swap cache and locked.
 * It will never put the page into the free list,
 * the caller has a reference on the page.
 *
 * 从swapper_space.page_tree中删除page
 *
 * shmem_getpage()
 *  delete_from_swap_cache()
 *
 * free_swap_and_cache()
 *  delete_from_swap_cache()
 *
 * try_to_unuse()
 *  delete_from_swap_cache()
 *
 * move_from_swap_cache()
 *  delete_from_swap_cache()
 *
 * sys_remap_file_pages()
 *  populate_range()
 *   install_file_pte()
 *    zap_pte() 
 *     free_swap_and_cache()
 *      delete_from_swap_cache()
 */
void delete_from_swap_cache(struct page *page)
{
	swp_entry_t entry;

	entry.val = page_private(page);

	write_lock_irq(&swapper_space.tree_lock);
	__delete_from_swap_cache(page);
	write_unlock_irq(&swapper_space.tree_lock);

	swap_free(entry);
	page_cache_release(page);
}

/*
 * Strange swizzling function only for use by shmem_writepage
 *
 * 将page插入到swapper_space.page_tree中去
 *
 * shmem_writepage()
 *  move_to_swap_cache()
 *
 */
int move_to_swap_cache(struct page *page, swp_entry_t entry)
{
	int err = __add_to_swap_cache(page, entry, GFP_ATOMIC);
	if (!err) {
		remove_from_page_cache(page);
		page_cache_release(page);	/* pagecache ref */
		if (!swap_duplicate(entry))
			BUG();
		SetPageDirty(page);
		INC_CACHE_INFO(add_total);
	} else if (err == -EEXIST)
		INC_CACHE_INFO(exist_race);
	return err;
}

/*
 * Strange swizzling function for shmem_getpage (and shmem_unuse)
 *
 * shmem_unuse_inode()
 *  move_from_swap_cache()
 *
 * shmem_getpage()
 *  move_from_swap_cache()
 *
 */
int move_from_swap_cache(struct page *page, unsigned long index,
		struct address_space *mapping)
{
    /* 将page放入到page->mapping->page_tree */
	int err = add_to_page_cache(page, mapping, index, GFP_ATOMIC);
	if (!err) {
		/* 从swapper_space->page_tree中删除page */
		delete_from_swap_cache(page);
		/* shift page from clean_pages to dirty_pages list */
		ClearPageDirty(page);
		set_page_dirty(page);
	}
	return err;
}

/* 
 * If we are the only user, then try to free up the swap cache. 
 * 
 * Its ok to check for PageSwapCache without the page lock
 * here because we are going to recheck again inside 
 * exclusive_swap_page() _with_ the lock. 
 * 					- Marcelo
 */
static inline void free_swap_cache(struct page *page)
{
	if (PageSwapCache(page) && !TestSetPageLocked(page)) {
		remove_exclusive_swap_page(page);
		unlock_page(page);
	}
}

/* 
 * Perform a free_page(), also freeing any swap cache associated with
 * this page if it is the last user of the page.
 */
void free_page_and_swap_cache(struct page *page)
{
	free_swap_cache(page);
	page_cache_release(page);
}

/*
 * Passed an array of pages, drop them all from swapcache and then release
 * them.  They are removed from the LRU and freed if this is their last use.
 */
void free_pages_and_swap_cache(struct page **pages, int nr)
{
	struct page **pagep = pages;

	lru_add_drain();
	while (nr) {
		int todo = min(nr, PAGEVEC_SIZE);
		int i;

		for (i = 0; i < todo; i++)
			free_swap_cache(pagep[i]); /* 清空page.private,page 上的PG_swapcache标记，从swapper_space->page_tree中删除 */
		
		release_pages(pagep, todo, 0);
		pagep += todo;
		nr -= todo;
	}
}

/*
 * Lookup a swap entry in the swap cache. A found page will be returned
 * unlocked and with its refcount incremented - we rely on the kernel
 * lock getting page table operations atomic even if we drop the page
 * lock before returning.
 *
 * 在swapper_space->page_tree中查找entry对应的page对象
 */
struct page * lookup_swap_cache(swp_entry_t entry)
{
	struct page *page;

	page = find_get_page(&swapper_space, entry.val);

	if (page)
		INC_CACHE_INFO(find_success);

	INC_CACHE_INFO(find_total);
	return page;
}

/* 
 * Locate a page of swap in physical memory, reserving swap cache space
 * and reading the disk if it is not already cached.
 * A failure return means that either the page allocation failed or that
 * the swap entry is no longer in use.
 *
 * sys_swapoff()
 *  try_to_unuse()
 *   read_swap_cache_async()
 *
 * do_page_fault()
 *  handle_pte_fault()
 *   do_swap_page()
 *    read_swap_cache_async()
 *
 * 将磁盘上的swap区读取到内存中来
 */
struct page *read_swap_cache_async(swp_entry_t entry,
			struct vm_area_struct *vma, unsigned long addr)
{
	struct page *found_page, *new_page = NULL;
	int err;

	do {
		/*
		 * First check the swap cache.  Since this is normally
		 * called after lookup_swap_cache() failed, re-calling
		 * that would confuse statistics.
		 *
		 * 从swapper_space->page_tree缓存中读取一个page单位的磁盘数据
		 */
		found_page = find_get_page(&swapper_space, entry.val);
		if (found_page)
			break;

		/*
		 * Get a new page to read into from swap.
		 * 需要从磁盘上读取了
		 */
		if (!new_page) {
			new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE,
								vma, addr);
			if (!new_page)
				break;		/* Out of memory */
		}

		/*
		 * Associate the page with swap entry in the swap cache.
		 * May fail (-ENOENT) if swap entry has been freed since
		 * our caller observed it.  May fail (-EEXIST) if there
		 * is already a page associated with this entry in the
		 * swap cache: added by a racing read_swap_cache_async,
		 * or by try_to_swap_out (or shmem_writepage) re-using
		 * the just freed swap entry for an existing page.
		 * May fail (-ENOMEM) if radix-tree node allocation failed.
		 *
		 * 添加到swapper_space.page_tree中去
		 * 设置page.private = entry,
		 * 设置page.flag |= PG_swapcache
		 * 设置page.flag |= PG_locked
		 */
		err = add_to_swap_cache(new_page, entry);
		if (!err) {
			/*
			 * Initiate read into locked page and return.
			 * 添加new_page到zone->active_list上去
			 */
			lru_cache_add_active(new_page);
			/* 从交换区读入数据 */
			swap_readpage(NULL, new_page);
			return new_page;
		}
	} while (err != -ENOENT && err != -ENOMEM);

	if (new_page)
		page_cache_release(new_page);
	return found_page;
}
