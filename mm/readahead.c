/*
 * mm/readahead.c - address_space-level file readahead.
 *
 * Copyright (C) 2002, Linus Torvalds
 *
 * 09Apr2002	akpm@zip.com.au
 *		Initial version.
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/pagevec.h>
#include <linux/pagemap.h>

void default_unplug_io_fn(struct backing_dev_info *bdi, struct page *page)
{
}
EXPORT_SYMBOL(default_unplug_io_fn);

struct backing_dev_info default_backing_dev_info = {
	.ra_pages	= VM_MAX_READAHEAD * 1024 / PAGE_CACHE_SIZE,
	.state		= 0,
	.capabilities	= BDI_CAP_MAP_COPY,
	.unplug_io_fn	= default_unplug_io_fn,
};
EXPORT_SYMBOL_GPL(default_backing_dev_info);

/*
 * Initialise a struct file's readahead state.  Assumes that the caller has
 * memset *ra to zero.
 *
 * sys_open()
 *  do_sys_open()
 *   do_filp_open()
 *    nameidata_to_filp()
 *     __dentry_open()
 *      file_ra_state_init()
 */
void
file_ra_state_init(struct file_ra_state *ra, struct address_space *mapping)
{
	ra->ra_pages = mapping->backing_dev_info->ra_pages;
	ra->prev_pos = -1;
}
EXPORT_SYMBOL_GPL(file_ra_state_init);

#define list_to_page(head) (list_entry((head)->prev, struct page, lru))

/**
 * read_cache_pages - populate an address space with some pages & start reads against them
 * @mapping: the address_space
 * @pages: The address of a list_head which contains the target pages.  These
 *   pages have their ->index populated and are otherwise uninitialised.
 * @filler: callback routine for filling a single page.
 * @data: private data for the callback routine.
 *
 * Hides the details of the LRU cache etc from the filesystems.
 */
int read_cache_pages(struct address_space *mapping, struct list_head *pages,
			int (*filler)(void *, struct page *), void *data)
{
	struct page *page;
	int ret = 0;

	while (!list_empty(pages)) {
		page = list_to_page(pages);
		list_del(&page->lru);
		if (add_to_page_cache_lru(page, mapping,
					page->index, GFP_KERNEL)) {
			page_cache_release(page);
			continue;
		}
		page_cache_release(page);

		ret = filler(data, page);
		if (unlikely(ret)) {
			put_pages_list(pages);
			break;
		}
		task_io_account_read(PAGE_CACHE_SIZE);
	}
	return ret;
}

EXPORT_SYMBOL(read_cache_pages);

/*
 * ext2文件系统调用路径
 * sys_read()
 *  vfs_read()
 *   do_sync_read()
 *    generic_file_aio_read()
 *     do_generic_file_read() 
 *      do_generic_mapping_read()
 *       page_cache_sync_readahead(, hit_readahead_marker == false)
 *        ondemand_readahead()
 *         __do_page_cache_readahead()
 *          read_pages()
 *
 * do_page_fault()
 *  handle_mm_fault()
 *   handle_pte_fault()
 *    do_linear_fault()
 *     __do_fault()
 *      filemap_fault()
 *       page_cache_sync_readahead()
 *        ondemand_readahead()
 *         ra_submit()
 *          __do_page_cache_readahead()
 *           read_pages()
 * 
 * nr_pages为链表pages的长度
 */
static int read_pages(struct address_space *mapping, struct file *filp,
		struct list_head *pages, unsigned nr_pages)
{
	unsigned page_idx;
	int ret;

	if (mapping->a_ops->readpages) {
		/* 从磁盘去读取,ext2_aops->readpages== ext2_readpages */
		ret = mapping->a_ops->readpages(filp, mapping, pages, nr_pages);
		/* Clean up the remaining pages */
		put_pages_list(pages);
		goto out;
	}

    /*
     * 不从磁盘预读的情况(即没有设置readpages)
     *
     * 设置page->mmaping, page->index,
     * 将page添加到mapping->page_tree对应的slot中
     * 将page添加到lru_add_pvecs[index] = page中
	 */
	for (page_idx = 0; page_idx < nr_pages; page_idx++) {
		
		struct page *page = list_to_page(pages); /* 类型转换 */
		
		list_del(&page->lru);/* 从别的链表(就是pages链表)上删掉去 */

		/*
		 * 添加到mapping->page_tree[slots]中，
		 * 添加到lru_add_pvecs链表了
		 */
		if (!add_to_page_cache_lru(page, mapping,
					page->index, GFP_KERNEL)) {

		    // ext2_aops->readpage = ext2_readpage
			mapping->a_ops->readpage(filp, page);
		}
		page_cache_release(page);
	}
	ret = 0;
out:
	return ret;
}

/*
 * do_page_cache_readahead actually reads a chunk of disk.  It allocates all
 * the pages first, then submits them all for I/O. This avoids the very bad
 * behaviour which would occur if page allocations are causing VM writeback.
 * We really don't want to intermingle reads and writes like that.
 *
 * Returns the number of pages requested, or the maximum amount of I/O allowed.
 *
 * do_page_cache_readahead() returns -1 if it encountered request queue
 * congestion.
 *
 * force_page_cache_readahead()
 *  __do_page_cache_readahead()
 *
 * do_page_cache_readahead()
 *  __do_page_cache_readahead()
 *
 * ra_submit()
 *  __do_page_cache_readahead()
 *
 * page_cache_sync_readhead()
 *  ondemand_readahead()
 *   __do_page_cache_readahead()
 *
 *
 *
 * ext2文件系统调用路径
 * sys_read()
 *  vfs_read()
 *   do_sync_read()
 *    generic_file_aio_read()
 *     do_generic_file_read() 
 *      do_generic_mapping_read()
 *       page_cache_sync_readahead(, hit_readahead_marker == false)
 *        ondemand_readahead()
 *         __do_page_cache_readahead()
 *
 * do_page_fault()
 *  handle_mm_fault()
 *   handle_pte_fault()
 *    do_linear_fault()
 *     __do_fault()
 *      filemap_fault()
 *       do_page_cache_readahead() 
 *        __do_page_cache_readahead()
 *
 * do_page_fault()
 *  handle_mm_fault()
 *   handle_pte_fault()
 *    do_linear_fault()
 *     __do_fault()
 *      filemap_fault()
 *       page_cache_sync_readahead()
 *        ondemand_readahead()
 *         ra_submit()
 *          __do_page_cache_readahead()
 */
static int
__do_page_cache_readahead(struct address_space *mapping, struct file *filp,
			pgoff_t offset, unsigned long nr_to_read,
			unsigned long lookahead_size)
{
	struct inode *inode = mapping->host;
	struct page *page;
	unsigned long end_index;	/* The last page we want to read */
	LIST_HEAD(page_pool);
	int page_idx;
	int ret = 0;
	loff_t isize = i_size_read(inode);

	if (isize == 0)
		goto out;

	end_index = ((isize - 1) >> PAGE_CACHE_SHIFT);

	/*
	 * Preallocate as many pages as we will need.
	 * 预先分配所需的page
	 */
	for (page_idx = 0; page_idx < nr_to_read; page_idx++) {
		pgoff_t page_offset = offset + page_idx;

		if (page_offset > end_index)
			break;

		rcu_read_lock();
		/* 从mapping->page_tree缓存中查找 */
		page = radix_tree_lookup(&mapping->page_tree, page_offset);
		rcu_read_unlock();
		if (page) /* 找到 */
			continue;

		/* 从mapping->page_tree缓存中查找失败   ,*/
		page = page_cache_alloc_cold(mapping);
		if (!page)
			break;
		
		page->index = page_offset;
		list_add(&page->lru, &page_pool);
		if (page_idx == nr_to_read - lookahead_size)
			SetPageReadahead(page);  /* 预读标记 */
		ret++;
	}

	/*
	 * Now start the IO.  We ignore I/O errors - if the page is not
	 * uptodate then the caller will launch readpage again, and
	 * will then handle the error.
	 */
	if (ret)
		read_pages(mapping, filp, &page_pool, ret); /* page_pool链表在read_pages中会被清空 */
	BUG_ON(!list_empty(&page_pool));
out:
	return ret;
}

/*
 * Chunk the readahead into 2 megabyte units, so that we don't pin too much
 * memory at once.
 */
int force_page_cache_readahead(struct address_space *mapping, struct file *filp,
		pgoff_t offset, unsigned long nr_to_read)
{
	int ret = 0;

	if (unlikely(!mapping->a_ops->readpage && !mapping->a_ops->readpages))
		return -EINVAL;

	while (nr_to_read) {
		int err;

		unsigned long this_chunk = (2 * 1024 * 1024) / PAGE_CACHE_SIZE;

		if (this_chunk > nr_to_read)
			this_chunk = nr_to_read;
		err = __do_page_cache_readahead(mapping, filp,
						offset, this_chunk, 0);
		if (err < 0) {
			ret = err;
			break;
		}
		ret += err;
		offset += this_chunk;
		nr_to_read -= this_chunk;
	}
	return ret;
}

/*
 * This version skips the IO if the queue is read-congested, and will tell the
 * block layer to abandon the readahead if request allocation would block.
 *
 * force_page_cache_readahead() will ignore queue congestion and will block on
 * request queues.
 *
 * do_page_fault()
 *  handle_mm_fault()
 *   handle_pte_fault()
 *    do_linear_fault()
 *     __do_fault()
 *      filemap_fault()
 *       do_page_cache_readahead()
 */
int do_page_cache_readahead(struct address_space *mapping, struct file *filp,
			pgoff_t offset, unsigned long nr_to_read)
{
	if (bdi_read_congested(mapping->backing_dev_info))
		return -1;

	return __do_page_cache_readahead(mapping, filp, offset, nr_to_read, 0);
}

/*
 * Given a desired number of PAGE_CACHE_SIZE readahead pages, return a
 * sensible upper limit.
 * 确定需要预读的page数量
 */
unsigned long max_sane_readahead(unsigned long nr)
{
	return min(nr, (node_page_state(numa_node_id(), NR_INACTIVE)
		+ node_page_state(numa_node_id(), NR_FREE_PAGES)) / 2);
}

static int __init readahead_init(void)
{
	return bdi_init(&default_backing_dev_info);
}
subsys_initcall(readahead_init);

/*
 * Submit IO for the read-ahead request in file_ra_state.
 *
 * sys_read()
 *  vfs_read()
 *   do_sync_read()
 *    generic_file_aio_read()
 *     do_generic_file_read() 
 *      do_generic_mapping_read()
 *       page_cache_sync_readahead()
 *        ondemand_readahead()
 *         ra_submit()
 *
 * do_page_fault()
 *  handle_mm_fault()
 *   handle_pte_fault()
 *    do_linear_fault()
 *     __do_fault()
 *      filemap_fault()
 *       page_cache_sync_readahead()
 *        ondemand_readahead()
 *         ra_submit()
 *
 * 根据file_ra_state对象，进行预读
 */
static unsigned long ra_submit(struct file_ra_state *ra,
		       struct address_space *mapping, struct file *filp)
{
	int actual;

	actual = __do_page_cache_readahead(mapping, filp,
					ra->start, ra->size, ra->async_size);

	return actual;
}

/*
 * Set the initial window size, round to next power of 2 and square
 * for small size, x 4 for medium, and x 2 for large
 * for 128k (32 page) max ra
 * 1-8 page = 32k initial, > 8 page = 128k initial
 *
 * page_cache_sync_readahead()
 *  ondemand_readahead()
 *   get_init_ra_size()
 *
 * 为一个文件确定最初的预读窗口长度。
 * 根据进程请求的page数目来确定窗口长度
 *
 */
static unsigned long get_init_ra_size(unsigned long size, unsigned long max)
{
	unsigned long newsize = roundup_pow_of_two(size);

	if (newsize <= max / 32)
		newsize = newsize * 4;
	else if (newsize <= max / 4)
		newsize = newsize * 2;
	else
		newsize = max;

	return newsize;
}

/*
 *  Get the previous window size, ramp it up, and
 *  return it as the new window size.
 *
 * page_cache_sync_readahead()
 *  ondemand_readahead()
 *   get_next_ra_size()
 *
 * 为后来的读取计算窗口长度，即此时已经有一个先前的预读窗口存在
 * 根据之前的窗口长度来确定以后的窗口长度。
 */
static unsigned long get_next_ra_size(struct file_ra_state *ra,
						unsigned long max)
{
	unsigned long cur = ra->size;
	unsigned long newsize;

	if (cur < max / 16)
		newsize = 4 * cur;
	else
		newsize = 2 * cur;

	return min(newsize, max);
}

/*
 * On-demand readahead design.
 *
 * The fields in struct file_ra_state represent the most-recently-executed
 * readahead attempt:
 *
 *                        |<----- async_size ---------|
 *     |------------------- size -------------------->|
 *     |==================#===========================|
 *     ^start             ^page marked with PG_readahead
 *
 * To overlap application thinking time and disk I/O time, we do
 * `readahead pipelining': Do not wait until the application consumed all
 * readahead pages and stalled on the missing page at readahead_index;
 * Instead, submit an asynchronous readahead I/O as soon as there are
 * only async_size pages left in the readahead window. Normally async_size
 * will be equal to size, for maximum pipelining.
 *
 * In interleaved sequential reads, concurrent streams on the same fd can
 * be invalidating each other's readahead state. So we flag the new readahead
 * page at (start+size-async_size) with PG_readahead, and use it as readahead
 * indicator. The flag won't be set on already cached pages, to avoid the
 * readahead-for-nothing fuss, saving pointless page cache lookups.
 *
 * prev_pos tracks the last visited byte in the _previous_ read request.
 * It should be maintained by the caller, and will be used for detecting
 * small random reads. Note that the readahead algorithm checks loosely
 * for sequential patterns. Hence interleaved reads might be served as
 * sequential ones.
 *
 * There is a special-case: if the first page which the application tries to
 * read happens to be the first page of the file, it is assumed that a linear
 * read is about to happen and the window is immediately set to the initial size
 * based on I/O request size and the max_readahead.
 *
 * The code ramps up the readahead size aggressively at first, but slow down as
 * it approaches max_readhead.
 */

/*
 * A minimal readahead algorithm for trivial sequential/random reads.
 *
 *  注意: 这里的offset 和req_size其实是页面数量  
 * page_cache_sync_readahead()
 *  ondemand_readahead()
 *
 * 实现预读策略
 *
 *
 * 预读要处理三种基本情况：
 * 1,当前偏移量在前一个预读窗口末尾，或在同步读取范围的末尾。在这两种情况下，内核
 *   假定进程在进行预读取，使用get_next_ra_size来计算新的预读窗口长度.
 * 2,如果遇到了预读标记，但与前一次预读的状态不符，那么很可能有两个或更多并发的控制流
 *   在交错的读取文件，使得对方的预读状态无效。内核将构建一个新的预读窗口，以适应所有的读取者。
 * 3,如果是在对文件进行第一次读取(特别是这种情况)或发生了缓存失败，则用get_init_ra_size建立一个新的预读窗口
 *
 *
 * ext2文件系统调用路径
 * sys_read()
 *  vfs_read()
 *   do_sync_read()
 *    generic_file_aio_read()
 *     do_generic_file_read() 
 *      do_generic_mapping_read()
 *       page_cache_sync_readahead(, hit_readahead_marker == false)
 *        ondemand_readahead()
 *
 * do_page_fault()
 *  handle_mm_fault()
 *   handle_pte_fault()
 *    do_linear_fault()
 *     __do_fault()
 *      filemap_fault()
 *       page_cache_sync_readahead()
 *        ondemand_readahead()
 */
static unsigned long
ondemand_readahead(struct address_space *mapping,
		   struct file_ra_state *ra, struct file *filp,
		   bool hit_readahead_marker, pgoff_t offset,
		   unsigned long req_size)
{
	int	max = ra->ra_pages;	/* max readahead pages */
	pgoff_t prev_offset;
	int	sequential;

	/*
	 * It's the expected callback offset, assume sequential access.
	 * Ramp up sizes, and push forward the readahead window.
	 */
    /* 如果: 
     * 1. 顺序读(本次读偏移为上次读偏移 (ra->start) + 读大小(ra->size,包含预读量) -  
     *    上次预读大小(ra->async_size)) 
     * 2. offset == (ra->start + ra->size)??? 
     */  	 
	if (offset && (offset == (ra->start + ra->size - ra->async_size) ||
			offset == (ra->start + ra->size))) {
			
		ra->start += ra->size;
		ra->size = get_next_ra_size(ra, max);
		ra->async_size = ra->size;
		goto readit;
	}

    /* 页为单位 */
	prev_offset = ra->prev_pos >> PAGE_CACHE_SHIFT;
	//顺序读
	sequential = offset - prev_offset <= 1UL || req_size > max;

	/*
	 * Standalone, small read.
	 * Read as is, and do not pollute the readahead state.
	 */
	if (!hit_readahead_marker && !sequential) {
		return __do_page_cache_readahead(mapping, filp,
						offset, req_size, 0);
	}

	/*
	 * Hit a marked page without valid readahead state.
	 * E.g. interleaved reads.
	 * Query the pagecache for async_size, which normally equals to
	 * readahead size. Ramp it up and use it as the new readahead size.
	 */
	if (hit_readahead_marker) {
		pgoff_t start;

		read_lock_irq(&mapping->tree_lock);
		start = radix_tree_next_hole(&mapping->page_tree, offset, max+1);
		read_unlock_irq(&mapping->tree_lock);

		if (!start || start - offset > max)
			return 0;

		ra->start = start;
		ra->size = start - offset;	/* old async_size */
		ra->size = get_next_ra_size(ra, max);
		ra->async_size = ra->size;
		goto readit;
	}

	/*
	 * It may be one of
	 * 	- first read on start of file
	 * 	- sequential cache miss
	 * 	- oversize random read
	 * Start readahead for it.
	 */
	ra->start = offset;
	ra->size = get_init_ra_size(req_size, max);
	/* 
	 * ra->size 一定是>= req_size的，这个由get_init_ra_size保证  
     * 如果req_size >= max,那么ra->async_size = ra_size  
     */
	ra->async_size = ra->size > req_size ? ra->size - req_size : ra->size;

readit:
	return ra_submit(ra, mapping, filp);
}

/**
 * page_cache_sync_readahead - generic file readahead
 * 从filep中预读操作
 *
 * @mapping: address_space which holds the pagecache and I/O vectors
 * @ra: file_ra_state which holds the readahead state
 * @filp: passed on to ->readpage() and ->readpages()
 * @offset: start offset into @mapping, in pagecache page-sized units
 * @req_size: hint: total size of the read which the caller is performing in
 *            pagecache pages
 *
 * page_cache_sync_readahead() should be called when a cache miss happened:
 * it will submit the read.  The readahead logic may decide to piggyback more
 * pages onto the read request if access patterns suggest it will improve
 * performance.
 *
 * do_generic_mapping_read()
 *  page_cache_sync_readahead()
 *
 * filemap_fault()
 *  page_cache_sync_readahead()
 *
 * __generic_file_splice_read()
 *  page_cache_sync_readahead()
 *
 * ext3_readdir()
 *  page_cache_sync_readahead()
 *
 *
 * ext2文件系统调用路径
 * sys_read()
 *  vfs_read()
 *   do_sync_read()
 *    generic_file_aio_read()
 *     do_generic_file_read() 
 *      do_generic_mapping_read()
 *       page_cache_sync_readahead()
 *
 * do_page_fault()
 *  handle_mm_fault()
 *   handle_pte_fault()
 *    do_linear_fault()
 *     __do_fault()
 *      filemap_fault()
 *       page_cache_sync_readahead()
 *
 */
void page_cache_sync_readahead(struct address_space *mapping,
			       struct file_ra_state *ra, struct file *filp,
			       pgoff_t offset, unsigned long req_size)
{
	/* no read-ahead */
	if (!ra->ra_pages)
		return;

	/* do read-ahead */
	ondemand_readahead(mapping, ra, filp, false, offset, req_size);
}
EXPORT_SYMBOL_GPL(page_cache_sync_readahead);

/**
 * page_cache_async_readahead - file readahead for marked pages
 * @mapping: address_space which holds the pagecache and I/O vectors
 * @ra: file_ra_state which holds the readahead state
 * @filp: passed on to ->readpage() and ->readpages()
 * @page: the page at @offset which has the PG_readahead flag set
 * @offset: start offset into @mapping, in pagecache page-sized units
 * @req_size: hint: total size of the read which the caller is performing in
 *            pagecache pages
 *
 * page_cache_async_ondemand() should be called when a page is used which
 * has the PG_readahead flag: this is a marker to suggest that the application
 * has used up enough of the readahead window that we should start pulling in
 * more pages. 
 *
 * sys_read()
 *  vfs_read()
 *   do_sync_read()
 *    generic_file_aio_read()
 *     do_generic_file_read() 
 *      do_generic_mapping_read()
 *       page_cache_async_readahead()
 */
void
page_cache_async_readahead(struct address_space *mapping,
			   struct file_ra_state *ra, struct file *filp,
			   struct page *page, pgoff_t offset,
			   unsigned long req_size)
{
	/* no read-ahead */
	if (!ra->ra_pages)
		return;

	/*
	 * Same bit is used for PG_readahead and PG_reclaim.
	 */
	if (PageWriteback(page))
		return;

	ClearPageReadahead(page);

	/*
	 * Defer asynchronous read-ahead on IO congestion.
	 */
	if (bdi_read_congested(mapping->backing_dev_info))
		return;

	/* do read-ahead */
	ondemand_readahead(mapping, ra, filp, true, offset, req_size);
}
EXPORT_SYMBOL_GPL(page_cache_async_readahead);
