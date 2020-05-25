/*
 * mm/rmap.c - physical to virtual reverse mappings
 *
 * Copyright 2001, Rik van Riel <riel@conectiva.com.br>
 * Released under the General Public License (GPL).
 *
 * Simple, low overhead reverse mapping scheme.
 * Please try to keep this thing as modular as possible.
 *
 * Provides methods for unmapping each kind of mapped page:
 * the anon methods track anonymous pages, and
 * the file methods track pages belonging to an inode.
 *
 * Original design by Rik van Riel <riel@conectiva.com.br> 2001
 * File methods by Dave McCracken <dmccr@us.ibm.com> 2003, 2004
 * Anonymous methods by Andrea Arcangeli <andrea@suse.de> 2004
 * Contributions by Hugh Dickins <hugh@veritas.com> 2003, 2004
 */

/*
 * Lock ordering in mm:
 *
 * inode->i_mutex	(while writing or truncating, not reading or faulting)
 *   inode->i_alloc_sem (vmtruncate_range)
 *   mm->mmap_sem
 *     page->flags PG_locked (lock_page)
 *       mapping->i_mmap_lock
 *         anon_vma->lock
 *           mm->page_table_lock or pte_lock
 *             zone->lru_lock (in mark_page_accessed, isolate_lru_page)
 *             swap_lock (in swap_duplicate, swap_info_get)
 *               mmlist_lock (in mmput, drain_mmlist and others)
 *               mapping->private_lock (in __set_page_dirty_buffers)
 *               inode_lock (in set_page_dirty's __mark_inode_dirty)
 *                 sb_lock (within inode_lock in fs/fs-writeback.c)
 *                 mapping->tree_lock (widely used, in set_page_dirty,
 *                           in arch-dependent flush_dcache_mmap_lock,
 *                           within inode_lock in __sync_single_inode)
 *                   zone->lock (within radix tree node alloc)
 */

#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/rmap.h>
#include <linux/rcupdate.h>
#include <linux/module.h>
#include <linux/kallsyms.h>

#include <asm/tlbflush.h>

struct kmem_cache *anon_vma_cachep;

/* This must be called under the mmap_sem. 
 * 如果vma->anon_vma 没有设置，则分配一个，否则什么都不做
 * 
 * handle_pte_fault()
 *  do_anonymous_page()
 *   anon_vma_prepare()
 *
 * do_wp_page()
 *  anon_vma_prepare()
 *
 * __do_fault()
 *  anon_vma_prepare()
 *
 * expand_stack()
 *  expand_upwards()
 *   anon_vma_prepare()
 *
 * expand_stack()
 *  expand_downwards()
 *   anon_vma_prepare()
 */
int anon_vma_prepare(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	might_sleep();
	if (unlikely(!anon_vma)) {
		struct mm_struct *mm = vma->vm_mm;
		struct anon_vma *allocated, *locked;
	
        /*根据vma的属性看vma->next和vma->prev是否可以共享anon_vma */
		anon_vma = find_mergeable_anon_vma(vma);
		
		if (anon_vma) {
			allocated = NULL;
			locked = anon_vma;
			spin_lock(&locked->lock);
		} else {

	        //给vma分配一个anon_vma对象
			anon_vma = anon_vma_alloc();
			if (unlikely(!anon_vma))
				return -ENOMEM;
			allocated = anon_vma;
			locked = NULL;
		}

		/* page_table_lock to protect against threads */
		spin_lock(&mm->page_table_lock);

		//还没有设置anon_vma
		if (likely(!vma->anon_vma)) { 
			/* 设置anon_vma */
			vma->anon_vma = anon_vma;
			/* anon_vma->head.prev= vma->anon_vma_node*/
			list_add_tail(&vma->anon_vma_node, &anon_vma->head);
			allocated = NULL;
		}
		spin_unlock(&mm->page_table_lock);

		if (locked)
			spin_unlock(&locked->lock);
		
		if (unlikely(allocated))
			anon_vma_free(allocated);
	}
	
	return 0;
}

void __anon_vma_merge(struct vm_area_struct *vma, struct vm_area_struct *next)
{
	BUG_ON(vma->anon_vma != next->anon_vma);
	list_del(&next->anon_vma_node);
}

void __anon_vma_link(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	if (anon_vma)
		list_add_tail(&vma->anon_vma_node, &anon_vma->head);
}

/*
 * copy_process()
 *  copy_mm()
 *   dup_mm()
 *    dup_mmap()
 *     anon_vma_link()
 * 将vma挂接到vma->anon_vma上
 */
void anon_vma_link(struct vm_area_struct *vma)
{

	struct anon_vma *anon_vma = vma->anon_vma;
	
	if (anon_vma) {
		spin_lock(&anon_vma->lock);
		list_add_tail(&vma->anon_vma_node, &anon_vma->head);
		spin_unlock(&anon_vma->lock);
	}
}

/*
 * free_pgtables()
 *  anon_vma_unlink()
 * 
 */
void anon_vma_unlink(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;
	int empty;

	if (!anon_vma)
		return;

	spin_lock(&anon_vma->lock);
	list_del(&vma->anon_vma_node);

	/* We must garbage collect the anon_vma if it's empty */
	empty = list_empty(&anon_vma->head);
	spin_unlock(&anon_vma->lock);

	if (empty)
		anon_vma_free(anon_vma);
}

static void anon_vma_ctor(struct kmem_cache *cachep, void *data)
{
	struct anon_vma *anon_vma = data;

	spin_lock_init(&anon_vma->lock);
	INIT_LIST_HEAD(&anon_vma->head);
}

void __init anon_vma_init(void)
{
	anon_vma_cachep = kmem_cache_create("anon_vma", sizeof(struct anon_vma),
			0, SLAB_DESTROY_BY_RCU|SLAB_PANIC, anon_vma_ctor);
}

/*
 * Getting a lock on a stable anon_vma from a page off the LRU is
 * tricky: page_lock_anon_vma rely on RCU to guard against the races.
 *
 * try_to_unmap()
 *  try_to_unmap_anon()
 *   page_lock_anon_vma()
 */
static struct anon_vma *page_lock_anon_vma(struct page *page)
{
	struct anon_vma *anon_vma;
	unsigned long anon_mapping;

	rcu_read_lock();
	anon_mapping = (unsigned long) page->mapping;
	if (!(anon_mapping & PAGE_MAPPING_ANON))
		goto out;
	if (!page_mapped(page))
		goto out;

	anon_vma = (struct anon_vma *) (anon_mapping - PAGE_MAPPING_ANON);
	spin_lock(&anon_vma->lock);
	return anon_vma;
out:
	rcu_read_unlock();
	return NULL;
}

static void page_unlock_anon_vma(struct anon_vma *anon_vma)
{
	spin_unlock(&anon_vma->lock);
	rcu_read_unlock();
}

/*
 * At what user virtual address is page expected in @vma?
 * Returns virtual address or -EFAULT if page's index/offset is not
 * within the range mapped the @vma.
 *
 * try_to_unmap()
 *  try_to_unmap_file()
 *   try_to_unmap_one() 
 *    vma_address()
 *
 * page对应在vma中的虚拟内存地址的值
 *
 *
 * 对于file mapped page，page->index表示的是映射到文件内的偏移（Byte为单位），而vma->vm_pgoff表示的是该VMA映射到文件内的偏移（page为单位），因此，通过vma->vm_pgoff和page->index可以得到该page frame在VMA中的地址偏移，再加上vma->vm_start就可以得到该page frame的虚拟地址。有了虚拟地址和地址空间（vma->vm_mm），我们就可以通过各级页表找到该page对应的pte entry。
 */
static inline unsigned long
vma_address(struct page *page, struct vm_area_struct *vma)
{
    //page在文件中的偏移量(字节量)
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	unsigned long address;

    //page在整个虚拟地址空间中的偏移量(字节)
	address = vma->vm_start + ((pgoff - vma->vm_pgoff) << PAGE_SHIFT);
	
	if (unlikely(address < vma->vm_start || address >= vma->vm_end)) {
		/* page should be within @vma mapping range
		 * page不在vma表示的线性地址范围内
		 */
		return -EFAULT;
	}
	return address;
}

/*
 * At what user virtual address is page expected in vma? checking that the
 * page matches the vma: currently only used on anon pages, by unuse_vma;
 */
unsigned long page_address_in_vma(struct page *page, struct vm_area_struct *vma)
{
	if (PageAnon(page)) {
		if ((void *)vma->anon_vma !=
		    (void *)page->mapping - PAGE_MAPPING_ANON)
			return -EFAULT;
	} else if (page->mapping && !(vma->vm_flags & VM_NONLINEAR)) {
		if (!vma->vm_file ||
		    vma->vm_file->f_mapping != page->mapping)
			return -EFAULT;
	} else
		return -EFAULT;
	return vma_address(page, vma);
}

/*
 * Check that @page is mapped at @address into @mm.
 *
 * On success returns with pte mapped and locked.
 */
pte_t *page_check_address(struct page *page, struct mm_struct *mm,
			  unsigned long address, spinlock_t **ptlp)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd))
		return NULL;

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		return NULL;

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		return NULL;

	pte = pte_offset_map(pmd, address);
	/* Make a quick check before getting the lock */
	if (!pte_present(*pte)) {
		pte_unmap(pte);
		return NULL;
	}

	ptl = pte_lockptr(mm, pmd);
	spin_lock(ptl);
	if (pte_present(*pte) && page_to_pfn(page) == pte_pfn(*pte)) {
		*ptlp = ptl;
		return pte;
	}
	pte_unmap_unlock(pte, ptl);
	return NULL;
}

/*
 * Subfunctions of page_referenced: page_referenced_one called
 * repeatedly from either page_referenced_anon or page_referenced_file.
 *
 * shrink_page_list()
 *  page_referenced()
 *   page_referenced_anon()
 *    page_referenced_one()
 *
 * shrink_active_list()
 *  page_referenced()
 *   page_referenced_file()
 *    page_referenced_one()
 */
static int page_referenced_one(struct page *page,
	struct vm_area_struct *vma, unsigned int *mapcount)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long address;
	pte_t *pte;
	spinlock_t *ptl;
	int referenced = 0;

    //返回page在vma中对应的虚拟地址。
	address = vma_address(page, vma); 
	if (address == -EFAULT) //不能在vma中找到page对应的虚拟地址
		goto out;

    /* 获取address对应的pte */
	pte = page_check_address(page, mm, address, &ptl);
	if (!pte)//page没有被映射到mm中
		goto out;

	/* 清空pte的PAGE_ACCESSED标记 */
	if (ptep_clear_flush_young(vma, address, pte))
		referenced++;//一次被reference

	/* Pretend the page is referenced if the task has the
	   swap token and is in the middle of a page fault.
	   如果mm对应进程有交换令牌而且正处于缺页异常处理过程中，则假装被引用
	 */
	if (mm != current->mm && has_swap_token(mm) &&
			rwsem_is_locked(&mm->mmap_sem))
		referenced++; //又被算一次reference了

	(*mapcount)--;
	pte_unmap_unlock(pte, ptl);
out:
	return referenced;
}

/*
 * 匿名映射page的数量
 *
 * 遍历anon_vma
 *
 * shrink_page_list()
 *  page_referenced()
 *   page_referenced_anon()
 *
 * shrink_active_list()
 *  page_referenced()
 *   page_referenced_anon()
 */
static int page_referenced_anon(struct page *page)
{
	unsigned int mapcount;
	struct anon_vma *anon_vma;
	struct vm_area_struct *vma;
	int referenced = 0;

    /* 得到page对应的anon_vma */
	anon_vma = page_lock_anon_vma(page);
	if (!anon_vma)
		return referenced;

    //得到page->_mapcount值
	mapcount = page_mapcount(page);
	/*
	 * 遍历得到这个page被referenced的值 
	 * 遍历vma->anon_vma_node,转成到vm_area_struct保存到vma
	 *
	 * 遍历page所在anon_vma上所有的node，这个链表可能会很长？
	 */
	list_for_each_entry(vma, &anon_vma->head, anon_vma_node) {
	    // 如果page在vma中, 基本上每调用一次，referenced都加 1
		referenced += page_referenced_one(page, vma, &mapcount); 
		if (!mapcount) //mapcount==0,说明所有的vma中对应的pte都找过了，没有必要在遍历了
			break;
	}

	page_unlock_anon_vma(anon_vma);
	return referenced;
}

/**
 * page_referenced_file - referenced check for object-based rmap
 * @page: the page we're checking references on.
 *
 * For an object-based mapped page, find all the places it is mapped and
 * check/clear the referenced flag.  This is done by following the page->mapping
 * pointer, then walking the chain of vmas it holds.  It returns the number
 * of references it found.
 *
 * This function is only called from page_referenced for object-based pages.
 *
 * 从address_space中查找page被引用的次数
 *
 * shrink_page_list()
 *  page_referenced()
 *   page_referenced_file()
 *
 * shrink_active_list()
 *  page_referenced()
 *   page_referenced_file()
 */
static int page_referenced_file(struct page *page)
{
	unsigned int mapcount;
	struct address_space *mapping = page->mapping;
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	struct vm_area_struct *vma;
	struct prio_tree_iter iter;
	int referenced = 0;

	/*
	 * The caller's checks on page->mapping and !PageAnon have made
	 * sure that this is a file page: the check for page->mapping
	 * excludes the case just before it gets set on an anon page.
	 */
	BUG_ON(PageAnon(page));

	/*
	 * The page lock not only makes sure that page->mapping cannot
	 * suddenly be NULLified by truncation, it makes sure that the
	 * structure at mapping cannot be freed and reused yet,
	 * so we can safely take mapping->i_mmap_lock.
	 */
	BUG_ON(!PageLocked(page));

	spin_lock(&mapping->i_mmap_lock);

	/*
	 * i_mmap_lock does not stabilize mapcount at all, but mapcount
	 * is more likely to be accurate if we note it after spinning.
	 */
	mapcount = page_mapcount(page);

    /*
     * 遍历address_space中所有的VMA
     */
	vma_prio_tree_foreach(vma, &iter, &mapping->i_mmap, pgoff, pgoff) {
		if ((vma->vm_flags & (VM_LOCKED|VM_MAYSHARE))
				  == (VM_LOCKED|VM_MAYSHARE)) {
			referenced++;
			break;
		}
		/* 如果page在vma中有映射，就返回1 */
		referenced += page_referenced_one(page, vma, &mapcount);
		if (!mapcount)
			break;
	}

	spin_unlock(&mapping->i_mmap_lock);
	return referenced;
}

/**
 * page_referenced - test if the page was referenced
 * @page: the page to test
 * @is_locked: caller holds lock on the page
 *
 * Quick test_and_clear_referenced for all mappings to a page,
 * returns the number of ptes which referenced the page.
 *
 * 返回引用page的pte数量
 *
 * shrink_page_list()
 *  page_referenced()
 *
 * shrink_active_list()
 *  page_referenced()
 *
 *  当操作系统进行页面回收时，每扫描到一个页面，就会调用该函数设置页面的 PG_referenced 位。如果一个页面的 PG_referenced 位被置位，但是在一定时间内该页面没有被再次访问，那么该页面的 PG_referenced 位会被清除。
 *
 *  通过比那里page->anon_vma->vma_node 或者遍历 page->address_sapce->prio_tree来计算
 */
int page_referenced(struct page *page, int is_locked)
{
	int referenced = 0;

    /* x86都返回0 */
	if (page_test_and_clear_young(page))
		referenced++;

    /* 如果已经设置了referenced标记了，那就清空这个标记，并且返回1 */
	if (TestClearPageReferenced(page))
		referenced++;

	if (page_mapped(page) && page->mapping) {
		if (PageAnon(page)) /* 匿名页 */
			referenced += page_referenced_anon(page);//遍历anon_vma
		else if (is_locked) /* 非匿名页 */
			referenced += page_referenced_file(page);//遍历vma_prio_tree
		else if (TestSetPageLocked(page))
			referenced++;
		else {
			if (page->mapping)
				referenced += page_referenced_file(page);
			unlock_page(page);
		}
	}
	return referenced;
}

static int page_mkclean_one(struct page *page, struct vm_area_struct *vma)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long address;
	pte_t *pte;
	spinlock_t *ptl;
	int ret = 0;

	address = vma_address(page, vma);
	if (address == -EFAULT)
		goto out;

	pte = page_check_address(page, mm, address, &ptl);
	if (!pte)
		goto out;

	if (pte_dirty(*pte) || pte_write(*pte)) {
		pte_t entry;

		flush_cache_page(vma, address, pte_pfn(*pte));
		entry = ptep_clear_flush(vma, address, pte);
		entry = pte_wrprotect(entry);
		entry = pte_mkclean(entry);
		set_pte_at(mm, address, pte, entry);
		ret = 1;
	}

	pte_unmap_unlock(pte, ptl);
out:
	return ret;
}

static int page_mkclean_file(struct address_space *mapping, struct page *page)
{
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	struct vm_area_struct *vma;
	struct prio_tree_iter iter;
	int ret = 0;

	BUG_ON(PageAnon(page));

	spin_lock(&mapping->i_mmap_lock);
	vma_prio_tree_foreach(vma, &iter, &mapping->i_mmap, pgoff, pgoff) {
		if (vma->vm_flags & VM_SHARED)
			ret += page_mkclean_one(page, vma);
	}
	spin_unlock(&mapping->i_mmap_lock);
	return ret;
}

int page_mkclean(struct page *page)
{
	int ret = 0;

	BUG_ON(!PageLocked(page));

	if (page_mapped(page)) {
		struct address_space *mapping = page_mapping(page);
		if (mapping) {
			ret = page_mkclean_file(mapping, page);
			if (page_test_dirty(page)) {
				page_clear_dirty(page);
				ret = 1;
			}
		}
	}

	return ret;
}
EXPORT_SYMBOL_GPL(page_mkclean);

/**
 * page_set_anon_rmap - setup new anonymous rmap
 * @page:	the page to add the mapping to
 * @vma:	the vm area in which the mapping is added
 * @address:	the user virtual address mapped
 *
 * handle_pte_fault()
 *  do_swap_page()
 *   page_add_anon_rmap() 已有的匿名页
 *    __page_set_anon_rmap()
 *
 * handle_pte_fault()
 *  do_anonymous_page()
 *   page_add_new_anon_rmap() 新匿名页加入 
 *    __page_set_anon_rmap()
 *
 * do_page_fault()
 *  handle_mm_fault()
 *   handle_pte_fault()
 *    do_wp_page()
 *     page_add_new_anon_rmap()
 *      __page_set_anon_rmap()
 *
 * 进行反向映射
 * 设置page->mapping最低位为1
 * page->mapping指向此vma->anon_vma
 * page->index存放此page在vma中的虚拟页框号，计算方法：page->index = ((address - vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;
 */
static void __page_set_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	BUG_ON(!anon_vma);
	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	page->mapping = (struct address_space *) anon_vma;

    /* 保存文件内或者share anonymous或者share anonymous的页面偏移 */
	page->index = linear_page_index(vma, address);

	/*
	 * nr_mapped state can be updated without turning off
	 * interrupts because it is not modified via interrupt.
	 *
	 * 统计更新page->zone->vm_stat[NR_ANON_PAGES] += 1
	 */
	__inc_zone_page_state(page, NR_ANON_PAGES);
}

/**
 * page_set_anon_rmap - sanity check anonymous rmap addition
 * @page:	the page to add the mapping to
 * @vma:	the vm area in which the mapping is added
 * @address:	the user virtual address mapped
 */
static void __page_check_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address)
{
#ifdef CONFIG_DEBUG_VM
	/*
	 * The page's anon-rmap details (mapping and index) are guaranteed to
	 * be set up correctly at this point.
	 *
	 * We have exclusion against page_add_anon_rmap because the caller
	 * always holds the page locked, except if called from page_dup_rmap,
	 * in which case the page is already known to be setup.
	 *
	 * We have exclusion against page_add_new_anon_rmap because those pages
	 * are initially only visible via the pagetables, and the pte is locked
	 * over the call to page_add_new_anon_rmap.
	 */
	struct anon_vma *anon_vma = vma->anon_vma;
	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	BUG_ON(page->mapping != (struct address_space *)anon_vma);
	BUG_ON(page->index != linear_page_index(vma, address));
#endif
}

/**
 * page_add_anon_rmap - add pte mapping to an anonymous page
 * @page:	the page to add the mapping to
 * @vma:	the vm area in which the mapping is added
 * @address:	the user virtual address mapped
 *
 * The caller needs to hold the pte lock and the page must be locked.
 *
 * do_page_fault()
 *  handle_pte_fault()
 *   do_swap_page()
 *   page_add_anon_rmap()
 *
 * migrate_pages()
 *  unmap_and_move()
 *   move_to_new_page()
 *    fallback_migrate_page()
 *     writeout()
 *      remove_migration_ptes()
 *       remove_file_migration_ptes()或者remove_anon_migration_ptes()
 *        remove_migration_pte()
 *         page_add_anon_rmap()
 */
void page_add_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address)
{
	VM_BUG_ON(!PageLocked(page));
	VM_BUG_ON(address < vma->vm_start || address >= vma->vm_end);
	
	if (atomic_inc_and_test(&page->_mapcount))
		__page_set_anon_rmap(page, vma, address);
	else
		__page_check_anon_rmap(page, vma, address);
}

/*
 * page_add_new_anon_rmap - add pte mapping to a new anonymous page
 * @page:	the page to add the mapping to
 * @vma:	the vm area in which the mapping is added
 * @address:	the user virtual address mapped
 *
 * Same as page_add_anon_rmap but must only be called on *new* pages.
 * This means the inc-and-test can be bypassed.
 * Page does not have to be locked.
 *
 * 集成到逆向映射
 * handle_pte_fault()
 *  do_anonymous_page()
 *   page_add_new_anon_rmap
 *
 * do_page_fault()
 *  handle_mm_fault()
 *   handle_pte_fault()
 *    do_wp_page()
 *     page_add_new_anon_rmap()
 */
void page_add_new_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address)
{
    /* 地址必须处于vma中 */
	BUG_ON(address < vma->vm_start || address >= vma->vm_end);
	/* 设置此页的_mapcount = 0，说明此页正在使用，但是是非共享的(>0是共享) */
	atomic_set(&page->_mapcount, 0); /* elevate count by 1 (starts at -1) */
	/* 进行反向映射
     * 设置page->mapping最低位为1
     * page->mapping指向此vma->anon_vma
     * page->index存放此page在vma中的虚拟页框号，计算方法：page->index = ((address - vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;
     */
	__page_set_anon_rmap(page, vma, address);
}

/**
 * page_add_file_rmap - add pte mapping to a file page
 * @page: the page to add the mapping to
 *
 * The caller needs to hold the pte lock.
 * 统计更新page->zone->vm_stat[NR_FILE_MAPPED]
 *
 * migrate_pages()
 *  unmap_and_move()
 *   move_to_new_page()
 *    fallback_migrate_page()
 *     writeout()
 *      remove_migration_ptes()
 *       remove_file_migration_ptes()或者remove_anon_migration_ptes()
 *        remove_migration_pte()
 *         page_add_file_rmap()
 */
void page_add_file_rmap(struct page *page)
{
	if (atomic_inc_and_test(&page->_mapcount))
		__inc_zone_page_state(page, NR_FILE_MAPPED);
}

#ifdef CONFIG_DEBUG_VM
/**
 * page_dup_rmap - duplicate pte mapping to a page
 * @page:	the page to add the mapping to
 *
 * For copy_page_range only: minimal extract from page_add_file_rmap /
 * page_add_anon_rmap, avoiding unnecessary tests (already checked) so it's
 * quicker.
 *
 * The caller needs to hold the pte lock.
 */
void page_dup_rmap(struct page *page, struct vm_area_struct *vma, unsigned long address)
{
	BUG_ON(page_mapcount(page) == 0);
	if (PageAnon(page))
		__page_check_anon_rmap(page, vma, address);
	atomic_inc(&page->_mapcount);
}
#endif

/**
 * page_remove_rmap - take down pte mapping from a page
 * @page: page to remove mapping from
 *
 * The caller needs to hold the pte lock.
 *
 * try_to_unmap()
 *  try_to_unmap_anon()
 *   try_to_unmap_one()
 *    page_remove_rmap()
 *
 * try_to_unmap()
 *  try_to_unmap_file()
 *   try_to_unmap_one()
 *    page_remove_rmap()
 *
 * sys_munmap() 
 *	do_munmap()
 *	 unmap_region()
 *	  unmap_vmas()
 *	   unmap_page_range()
 *		zap_pud_range()
 *		 zap_pmd_range()
 *        zap_pte_range()
 *         page_remove_rmap()
 *
 * do_page_fault()
 *  handle_mm_fault()
 *   handle_pte_fault()
 *    do_wp_page()
 *     page_remove_rmap()
 */
void page_remove_rmap(struct page *page, struct vm_area_struct *vma)
{
	if (atomic_add_negative(-1, &page->_mapcount)) {
		if (unlikely(page_mapcount(page) < 0)) {
			printk (KERN_EMERG "Eeek! page_mapcount(page) went negative! (%d)\n", page_mapcount(page));
			printk (KERN_EMERG "  page pfn = %lx\n", page_to_pfn(page));
			printk (KERN_EMERG "  page->flags = %lx\n", page->flags);
			printk (KERN_EMERG "  page->count = %x\n", page_count(page));
			printk (KERN_EMERG "  page->mapping = %p\n", page->mapping);
			print_symbol (KERN_EMERG "  vma->vm_ops = %s\n", (unsigned long)vma->vm_ops);
			if (vma->vm_ops) {
				print_symbol (KERN_EMERG "  vma->vm_ops->nopage = %s\n", (unsigned long)vma->vm_ops->nopage);
				print_symbol (KERN_EMERG "  vma->vm_ops->fault = %s\n", (unsigned long)vma->vm_ops->fault);
			}
			if (vma->vm_file && vma->vm_file->f_op)
				print_symbol (KERN_EMERG "  vma->vm_file->f_op->mmap = %s\n", (unsigned long)vma->vm_file->f_op->mmap);
			BUG();
		}

		/*
		 * It would be tidy to reset the PageAnon mapping here,
		 * but that might overwrite a racing page_add_anon_rmap
		 * which increments mapcount after us but sets mapping
		 * before us: so leave the reset to free_hot_cold_page,
		 * and remember that it's only reliable while mapped.
		 * Leaving it set also helps swapoff to reinstate ptes
		 * faster for those pages still in swapcache.
		 */
		if (page_test_dirty(page)) {
			page_clear_dirty(page);
			set_page_dirty(page);
		}
		__dec_zone_page_state(page,
				PageAnon(page) ? NR_ANON_PAGES : NR_FILE_MAPPED);
	}
}

/*
 * Subfunctions of try_to_unmap: try_to_unmap_one called
 * repeatedly from either try_to_unmap_anon or try_to_unmap_file.
 *
 * try_to_unmap()
 *  try_to_unmap_anon() 这里循环调用try_to_unmap_anon
 *   try_to_unmap_one()
 *
 * try_to_unmap()
 *  try_to_unmap_file()
 *   try_to_unmap_one()
 */
static int try_to_unmap_one(struct page *page, struct vm_area_struct *vma,
				int migration)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long address;
	pte_t *pte;
	pte_t pteval;
	spinlock_t *ptl;
	int ret = SWAP_AGAIN;

    /* page在vma中的虚拟地址 */
	address = vma_address(page, vma);
	if (address == -EFAULT) //page在vma中没有被map，所以直接返回了
		goto out;

	/* 确认address是否已经映射到mm空间中了 */
	pte = page_check_address(page, mm, address, &ptl);
	if (!pte)
		goto out;

	/*
	 * If the page is mlock()d, we cannot swap it out.
	 * If it's recently referenced (perhaps page_referenced
	 * skipped over this mm) then we should reactivate it.
	 *
	 * vma有VM_LOCKED标记，就不能被swap out了，
	 * 清空pte 的ACCESSED标记
	 */
	if (!migration && ((vma->vm_flags & VM_LOCKED) ||
			(ptep_clear_flush_young(vma, address, pte)))) {
		ret = SWAP_FAIL;
		goto out_unmap;
	}

	/* Nuke the page table entry. */
	flush_cache_page(vma, address, page_to_pfn(page));
	 /* 获取页表项内容，保存到pteval中，然后清空页表项 */		
	pteval = ptep_clear_flush(vma, address, pte);

	/* Move the dirty bit to the physical page now the pte is gone. */
	if (pte_dirty(pteval))
		set_page_dirty(page); /*  设置页描述符的PG_dirty标记 ,调用address_space->set_page_dirty()或者设置PG_dirty位 */

	/* Update high watermark before we lower rss
	 *
	 * 更新进程所拥有的最大页框数
	 */
	update_hiwater_rss(mm);

	if (PageAnon(page)) { /* 是匿名映射页(MAP_PRIVATE,MAP_SHARED映射) */

	
        /* 获取page->private中保存的内容，
         * 调用到try_to_unmap()前会把此页加入到swapcache，
         * 然后分配一个以swap页槽偏移量为内容的swp_entry_t 
         */
		swp_entry_t entry = { .val = page_private(page) };

		if (PageSwapCache(page)) { //是PG_swapcache页
			/*
			 * Store the swap location in the pte.
			 * See handle_pte_fault() ...
			 *
			 * 检查entry是否有效
             * 然后就是 swap_map[entry]++ 
			 */
			swap_duplicate(entry); 
			if (list_empty(&mm->mmlist)) { //此vma所属进程的mm没有加入到所有进程的mmlist中(init_mm.mmlist)
				
				spin_lock(&mmlist_lock);
				
				if (list_empty(&mm->mmlist))
					list_add(&mm->mmlist, &init_mm.mmlist);
				
				spin_unlock(&mmlist_lock);
			}
			
			dec_mm_counter(mm, anon_rss);//就是mm->_anon_rss--
#ifdef CONFIG_MIGRATION
		} else {
			/*
			 * Store the pfn of the page in a special migration
			 * pte. do_swap_page() will wait until the migration
			 * pte is removed and then restart fault handling.
			 */
			BUG_ON(!migration);
			
            /* 为此匿名页创建一个页迁移使用的swp_entry_t，此swp_entry_t指向此匿名页 */			
			entry = make_migration_entry(page, pte_write(pteval));
#endif
		}
		//设置pte的值为swap_entry
		set_pte_at(mm, address, pte, swp_entry_to_pte(entry));
		BUG_ON(pte_file(*pte));
	} else
#ifdef CONFIG_MIGRATION
	if (migration) {
		/* Establish migration entry for a file page */
		swp_entry_t entry;
		/* 建立一个迁移使用的swp_entry_t，用于文件页迁移 */
		entry = make_migration_entry(page, pte_write(pteval));
        /* 将此页表的pte页表项写入entry转为的页表项内容 */
		set_pte_at(mm, address, pte, swp_entry_to_pte(entry));
	} else
#endif
		dec_mm_counter(mm, file_rss);

	/* 
	 * 更新一些统计
	 */
	page_remove_rmap(page, vma);
    /* 每个进程对此页进行了unmap操作，此页的page->_count--，并判断是否为0，如果为0则释放此页，一般这里不会为0 */	
	page_cache_release(page);

out_unmap:
	pte_unmap_unlock(pte, ptl);
out:
	return ret;
}

/*
 * objrmap doesn't work for nonlinear VMAs because the assumption that
 * offset-into-file correlates with offset-into-virtual-addresses does not hold.
 * Consequently, given a particular page and its ->index, we cannot locate the
 * ptes which are mapping that page without an exhaustive linear search.
 *
 * So what this code does is a mini "virtual scan" of each nonlinear VMA which
 * maps the file to which the target page belongs.  The ->vm_private_data field
 * holds the current cursor into that scan.  Successive searches will circulate
 * around the vma's virtual address space.
 *
 * So as more replacement pressure is applied to the pages in a nonlinear VMA,
 * more scanning pressure is placed against them as well.   Eventually pages
 * will become fully unmapped and are eligible for eviction.
 *
 * For very sparsely populated VMAs this is a little inefficient - chances are
 * there there won't be many ptes located within the scan cluster.  In this case
 * maybe we could scan further - to the end of the pte page, perhaps.
 */
#define CLUSTER_SIZE	min(32*PAGE_SIZE, PMD_SIZE)
#define CLUSTER_MASK	(~(CLUSTER_SIZE - 1))

static void try_to_unmap_cluster(unsigned long cursor,
	unsigned int *mapcount, struct vm_area_struct *vma)
{
	struct mm_struct *mm = vma->vm_mm;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	pte_t pteval;
	spinlock_t *ptl;
	struct page *page;
	unsigned long address;
	unsigned long end;

	address = (vma->vm_start + cursor) & CLUSTER_MASK;
	end = address + CLUSTER_SIZE;
	if (address < vma->vm_start)
		address = vma->vm_start;
	if (end > vma->vm_end)
		end = vma->vm_end;

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd))
		return;

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		return;

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		return;

	pte = pte_offset_map_lock(mm, pmd, address, &ptl);

	/* Update high watermark before we lower rss */
	update_hiwater_rss(mm);

	for (; address < end; pte++, address += PAGE_SIZE) {
		if (!pte_present(*pte))
			continue;
		page = vm_normal_page(vma, address, *pte);
		BUG_ON(!page || PageAnon(page));

		if (ptep_clear_flush_young(vma, address, pte))
			continue;

		/* Nuke the page table entry. */
		flush_cache_page(vma, address, pte_pfn(*pte));
		pteval = ptep_clear_flush(vma, address, pte);

		/* If nonlinear, store the file page offset in the pte. */
		if (page->index != linear_page_index(vma, address))
			set_pte_at(mm, address, pte, pgoff_to_pte(page->index));

		/* Move the dirty bit to the physical page now the pte is gone. */
		if (pte_dirty(pteval))
			set_page_dirty(page);

		page_remove_rmap(page, vma);
		page_cache_release(page);
		dec_mm_counter(mm, file_rss);
		(*mapcount)--;
	}
	pte_unmap_unlock(pte - 1, ptl);
}

/*
 * try_to_unmap()
 *  try_to_unmap_anon()
 */
static int try_to_unmap_anon(struct page *page, int migration)
{
	struct anon_vma *anon_vma;
	struct vm_area_struct *vma;
	int ret = SWAP_AGAIN;

    //这里要lock anon_vma->lock，会引发性能bug了
	anon_vma = page_lock_anon_vma(page); /* page->mapping - 1表示anon_vma */
	
	if (!anon_vma)
		return ret;
    /* vma= (vma->anon_vma_node.next - 到vma结构开头的偏移);  ;vma = (vma->anon_vma_node.next - 到vma结构开头的偏移) 
     * 
     * anon_vma->head 连接到vm_area_struct->anon_vma_node
	 */
	list_for_each_entry(vma, &anon_vma->head, anon_vma_node) {
	    /* 同一个page，在不同的vma中被映射了，所以需要调用多次try_to_unmap_one */
		ret = try_to_unmap_one(page, vma, migration);
		if (ret == SWAP_FAIL || !page_mapped(page) /* page_mapped()返回0，说明page只被一个pte映射了，可以提前结束寻呼 */)
			break;
	}

	page_unlock_anon_vma(anon_vma);
	return ret;
}

/**
 * try_to_unmap_file - unmap file page using the object-based rmap method
 * @page: the page to unmap
 *
 * Find all the mappings of a page using the mapping pointer and the vma chains
 * contained in the address_space struct it points to.
 *
 * This function is only called from try_to_unmap for object-based pages.
 * 取消所有映射到本page的进程的相关的pte
 *
 * shrink_zone()
 *  shrink_inactive_list()
 *   shrink_page_list()  
 *    try_to_unmap()
 *     try_to_unmap_file()
 */
static int try_to_unmap_file(struct page *page, int migration)
{
	struct address_space *mapping = page->mapping;
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	struct vm_area_struct *vma;
	struct prio_tree_iter iter;
	int ret = SWAP_AGAIN;
	unsigned long cursor;
	unsigned long max_nl_cursor = 0;
	unsigned long max_nl_size = 0;
	unsigned int mapcount;

	spin_lock(&mapping->i_mmap_lock);
    
	/* 线性映射相关的vma,(   MAP_PRIVATE,MAP_SHARED映射出来的         )
	 * 
	 * 遍历address_space->prio_tree_root
	 */
	vma_prio_tree_foreach(vma, &iter, &mapping->i_mmap, pgoff, pgoff) {
		ret = try_to_unmap_one(page, vma, migration);
		if (ret == SWAP_FAIL || !page_mapped(page))
			goto out;
	}

	if (list_empty(&mapping->i_mmap_nonlinear))
		goto out;

    /* 非线性映射相关的  */
	list_for_each_entry(vma, &mapping->i_mmap_nonlinear,
						shared.vm_set.list) {
		if ((vma->vm_flags & VM_LOCKED) && !migration)
			continue;
		cursor = (unsigned long) vma->vm_private_data;
		if (cursor > max_nl_cursor)
			max_nl_cursor = cursor;
		cursor = vma->vm_end - vma->vm_start;
		if (cursor > max_nl_size)
			max_nl_size = cursor;
	}

	if (max_nl_size == 0) {	/* any nonlinears locked or reserved */
		ret = SWAP_FAIL;
		goto out;
	}

	/*
	 * We don't try to search for this page in the nonlinear vmas,
	 * and page_referenced wouldn't have found it anyway.  Instead
	 * just walk the nonlinear vmas trying to age and unmap some.
	 * The mapcount of the page we came in with is irrelevant,
	 * but even so use it as a guide to how hard we should try?
	 */
	mapcount = page_mapcount(page);
	if (!mapcount)
		goto out;
	cond_resched_lock(&mapping->i_mmap_lock);

	max_nl_size = (max_nl_size + CLUSTER_SIZE - 1) & CLUSTER_MASK;
	if (max_nl_cursor == 0)
		max_nl_cursor = CLUSTER_SIZE;

	do {
		//处理文件的非线性映射
		list_for_each_entry(vma, &mapping->i_mmap_nonlinear,
						shared.vm_set.list) {
			if ((vma->vm_flags & VM_LOCKED) && !migration)
				continue;
			cursor = (unsigned long) vma->vm_private_data;
			while ( cursor < max_nl_cursor &&
				cursor < vma->vm_end - vma->vm_start) {
				try_to_unmap_cluster(cursor, &mapcount, vma);
				cursor += CLUSTER_SIZE;
				vma->vm_private_data = (void *) cursor;
				if ((int)mapcount <= 0)
					goto out;
			}
			vma->vm_private_data = (void *) max_nl_cursor;
		}
		cond_resched_lock(&mapping->i_mmap_lock);
		max_nl_cursor += CLUSTER_SIZE;
	} while (max_nl_cursor <= max_nl_size);

	/*
	 * Don't loop forever (perhaps all the remaining pages are
	 * in locked vmas).  Reset cursor on all unreserved nonlinear
	 * vmas, now forgetting on which ones it had fallen behind.
	 */
	list_for_each_entry(vma, &mapping->i_mmap_nonlinear, shared.vm_set.list)
		vma->vm_private_data = NULL;
out:
	spin_unlock(&mapping->i_mmap_lock);
	return ret;
}

/**
 * try_to_unmap - try to remove all page table mappings to a page
 * @page: the page to get unmapped
 *
 * Tries to remove all the page table entries which are mapping this
 * page, used in the pageout path.  Caller must hold the page lock.
 * Return values are:
 *
 * SWAP_SUCCESS	- we succeeded in removing all mappings
 * SWAP_AGAIN	- we missed a mapping, try again later
 * SWAP_FAIL	- the page is unswappable
 * 取消对page所有有映射的进程的pte
 *
 * unmap_and_move()
 *  try_to_unmap()
 *
 * shrink_zone()
 *  shrink_inactive_list()
 *   shrink_page_list() 
 *    try_to_unmap()
 */
int try_to_unmap(struct page *page, int migration)
{
	int ret;

	BUG_ON(!PageLocked(page));

	if (PageAnon(page)) /* 匿名页，无后备文件 */
		ret = try_to_unmap_anon(page, migration);
	else /* 映射到文件,有后备文件 */
		ret = try_to_unmap_file(page, migration);

	if (!page_mapped(page))
		ret = SWAP_SUCCESS;
	return ret;
}

