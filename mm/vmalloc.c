/*
 *  linux/mm/vmalloc.c
 *
 *  Copyright (C) 1993  Linus Torvalds
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  SMP-safe vmalloc/vfree/ioremap, Tigran Aivazian <tigran@veritas.com>, May 2000
 *  Major rework to support vmap/vunmap, Christoph Hellwig, SGI, August 2002
 *  Numa awareness, Christoph Lameter, SGI, June 2005
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>

#include <linux/vmalloc.h>

#include <asm/uaccess.h>
#include <asm/tlbflush.h>


DEFINE_RWLOCK(vmlist_lock);
struct vm_struct *vmlist;

static void *__vmalloc_node(unsigned long size, gfp_t gfp_mask, pgprot_t prot,
			    int node);

static void vunmap_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end)
{
	pte_t *pte;

	pte = pte_offset_kernel(pmd, addr);
	do {
		pte_t ptent = ptep_get_and_clear(&init_mm, addr, pte);
		WARN_ON(!pte_none(ptent) && !pte_present(ptent));
	} while (pte++, addr += PAGE_SIZE, addr != end);
}

static inline void vunmap_pmd_range(pud_t *pud, unsigned long addr,
						unsigned long end)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(pmd))
			continue;
		vunmap_pte_range(pmd, addr, next);
	} while (pmd++, addr = next, addr != end);
}

static inline void vunmap_pud_range(pgd_t *pgd, unsigned long addr,
						unsigned long end)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		vunmap_pmd_range(pud, addr, next);
	} while (pud++, addr = next, addr != end);
}

/*
 * free_vm_area()
 *	remove_vm_area()
 *	 __remove_vm_area()
 *
 * iounmap()
 *	remove_vm_area()
 *	 __remove_vm_area()
 *
 * 只是情况init_mm.pgd对应的页表，应用进程对应的页表似乎没有被清空
 * 用户空间不会间接用到vmalloc
 */
void unmap_kernel_range(unsigned long addr, unsigned long size)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long start = addr;
	unsigned long end = addr + size;

	BUG_ON(addr >= end);
	//从init_mm.pgd中获取 pgd_offset的值，这是一个物理内存地址
	pgd = pgd_offset_k(addr);
	flush_cache_vunmap(addr, end);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		vunmap_pud_range(pgd, addr, next);
	} while (pgd++, addr = next, addr != end);
	flush_tlb_kernel_range(start, end);
}

static void unmap_vm_area(struct vm_struct *area)
{
	unmap_kernel_range((unsigned long)area->addr, area->size);
}

/* 一个pte映射到一个page，只操作init_mm->pgd */
static int vmap_pte_range(pmd_t *pmd, unsigned long addr,
			unsigned long end, pgprot_t prot, struct page ***pages)
{
	pte_t *pte;

	pte = pte_alloc_kernel(pmd, addr);
	if (!pte)
		return -ENOMEM;
	do {
		struct page *page = **pages;
		WARN_ON(!pte_none(*pte));
		if (!page)
			return -ENOMEM;
		set_pte_at(&init_mm, addr, pte, mk_pte(page, prot));
		(*pages)++;
	} while (pte++, addr += PAGE_SIZE, addr != end);
	return 0;
}

/* 调用vmap_pte_range来映射pte层 */
static inline int vmap_pmd_range(pud_t *pud, unsigned long addr,
			unsigned long end, pgprot_t prot, struct page ***pages)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_alloc(&init_mm, pud, addr);
	if (!pmd)
		return -ENOMEM;
	do {
		next = pmd_addr_end(addr, end);
		if (vmap_pte_range(pmd, addr, next, prot, pages))
			return -ENOMEM;
	} while (pmd++, addr = next, addr != end);
	return 0;
}

/* 调用vmap_pmd_range来映射pmd层 */
static inline int vmap_pud_range(pgd_t *pgd, unsigned long addr,
			unsigned long end, pgprot_t prot, struct page ***pages)
{
	pud_t *pud;
	unsigned long next;

	/*调用pud_alloc分配页上级目录*/	
	pud = pud_alloc(&init_mm, pgd, addr);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		if (vmap_pmd_range(pud, addr, next, prot, pages))
			return -ENOMEM;
	} while (pud++, addr = next, addr != end);
	return 0;
}
/*
 * vmalloc()
 *  __vmalloc()
 *   __vmalloc_node()
 *    __vmalloc_area_node()
 *     map_vm_area()
 */
int map_vm_area(struct vm_struct *area, pgprot_t prot, struct page ***pages)
{
	pgd_t *pgd;
	unsigned long next;
	/* 起始地址 */
	unsigned long addr = (unsigned long) area->addr;
	/* 结束地址 */
	unsigned long end = addr + area->size - PAGE_SIZE;
	int err;

	BUG_ON(addr >= end);

	/* 得到主内核页表中pgd中的相应项的线性地址 */  
	pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		err = vmap_pud_range(pgd, addr, next, prot, pages);
		if (err)
			break;
	} while (pgd++, addr = next, addr != end);
	flush_cache_vmap((unsigned long) area->addr, end);
	return err;
}
EXPORT_SYMBOL_GPL(map_vm_area);


/*
 * 内核分配内核不连续的虚拟内存，会调用到这个函数
 * 参数 start,end分别由调用者设置为VMALLOC_START,VMALLOC_END
 *
 * vmalloc()
 *  __vmalloc()
 *   __vmalloc_node()
 *    get_vm_area_node()
 *     __get_vm_area_node()
 */
static struct vm_struct *__get_vm_area_node(unsigned long size, unsigned long flags,
					    unsigned long start, unsigned long end,
					    int node, gfp_t gfp_mask)
{
	struct vm_struct **p, *tmp, *area;
	unsigned long align = 1;
	unsigned long addr;

	BUG_ON(in_interrupt());
	if (flags & VM_IOREMAP) {
		int bit = fls(size);

		if (bit > IOREMAP_MAX_ORDER)
			bit = IOREMAP_MAX_ORDER;
		else if (bit < PAGE_SHIFT)
			bit = PAGE_SHIFT;

		align = 1ul << bit;
	}
	addr = ALIGN(start, align);
	size = PAGE_ALIGN(size);
	if (unlikely(!size))
		return NULL;

	area = kmalloc_node(sizeof(*area), gfp_mask & GFP_RECLAIM_MASK, node);

	if (unlikely(!area))
		return NULL;

	/*
	 * We always allocate a guard page.
	 * 内核虚拟地址空间vmalloc区域中，每个vm_struct表达的空间之间都需要多出一个页面来防止越界访问。
	 * 所以在分配的时候就多分配一个页面了，用作这个警戒页
	 */
	size += PAGE_SIZE;

    /* 在操作vmlist之前,得到vmlist_lock */
	write_lock(&vmlist_lock);
	/* 遍历vmlist,找到一个有足够size字节空间的位置标记 */
	for (p = &vmlist; (tmp = *p) != NULL ;p = &tmp->next) {
		if ((unsigned long)tmp->addr < addr) {
			if((unsigned long)tmp->addr + tmp->size >= addr)
				addr = ALIGN(tmp->size + 
					     (unsigned long)tmp->addr, align);
			continue;
		}
		if ((size + addr) < addr)
			goto out;
		if (size + addr <= (unsigned long)tmp->addr)
			goto found; /* 找到 */
		addr = ALIGN(tmp->size + (unsigned long)tmp->addr, align);
		if (addr > end - size)
			goto out;
	}

found:  /* 空闲位置找到，填写新的vm_struct,然后加入到vm_list中去 */
	area->next = *p;
	*p = area;

	area->flags = flags;
	area->addr = (void *)addr;
	area->size = size;
	area->pages = NULL;
	area->nr_pages = 0;
	area->phys_addr = 0;
	write_unlock(&vmlist_lock);

	return area;

out:
	write_unlock(&vmlist_lock);
	kfree(area);
	if (printk_ratelimit())
		printk(KERN_WARNING "allocation failed: out of vmalloc space - use vmalloc=<size> to increase size.\n");
	return NULL;
}

struct vm_struct *__get_vm_area(unsigned long size, unsigned long flags,
				unsigned long start, unsigned long end)
{
	return __get_vm_area_node(size, flags, start, end, -1, GFP_KERNEL);
}
EXPORT_SYMBOL_GPL(__get_vm_area);

/**
 *	get_vm_area  -  reserve a contiguous kernel virtual area
 *	@size:		size of the area
 *	@flags:		%VM_IOREMAP for I/O mappings or VM_ALLOC
 *
 *	Search an area of @size in the kernel virtual mapping area,
 *	and reserved it for out purposes.  Returns the area descriptor
 *	on success or %NULL on failure.
 *  返回一个新的vm_struct对象
 *
 *  vmap()
 *   get_vm_area()
 *  vmalloc()
 *   get_vm_area()
 *
 * ioremap()
 *  __ioremap()
 *   get_vm_area()
 */
struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
{
	return __get_vm_area(size, flags, VMALLOC_START, VMALLOC_END);
}

/* 在VMALLOC_START和VMALLOC_END 找到一个线性区 (vm_struct)
 *
 * vmalloc()
 *  __vmalloc()
 *   __vmalloc_node()
 *    get_vm_area_node()
*/
struct vm_struct *get_vm_area_node(unsigned long size, unsigned long flags,
				   int node, gfp_t gfp_mask)
{
	return __get_vm_area_node(size, flags, VMALLOC_START, VMALLOC_END, node,
				  gfp_mask);
}

/* Caller must hold vmlist_lock */
static struct vm_struct *__find_vm_area(void *addr)
{
	struct vm_struct *tmp;

	for (tmp = vmlist; tmp != NULL; tmp = tmp->next) {
		 if (tmp->addr == addr)
			break;
	}

	return tmp;
}

/* Caller must hold vmlist_lock 
   从vmlist中删去addr对应的vm_struct实例
 *  free_vm_area()
 *   remove_vm_area()
 *    __remove_vm_area()
 *
 *  iounmap()
 *   remove_vm_area()
 *    __remove_vm_area()
 */
static struct vm_struct *__remove_vm_area(void *addr)
{
	struct vm_struct **p, *tmp;

	for (p = &vmlist ; (tmp = *p) != NULL ;p = &tmp->next) {
		 if (tmp->addr == addr)
			 goto found; /* 找到对应的位置 */
	}
	return NULL;

found:
	unmap_vm_area(tmp);
	*p = tmp->next;

	/*
	 * Remove the guard page.
	 */
	tmp->size -= PAGE_SIZE;
	return tmp;
}

/**
 *	remove_vm_area  -  find and remove a continuous kernel virtual area
 *	@addr:		base address
 *
 *	Search for the kernel VM area starting at @addr, and remove it.
 *	This function returns the found VM area, but using it is NOT safe
 *	on SMP machines, except for its size or flags.
 *
 *  从vmlist中删去addr对应的vm_struct实例
 *
 *  free_vm_area()
 *   remove_vm_area()
 *  iounmap()
 *   remove_vm_area()
 */
struct vm_struct *remove_vm_area(void *addr)
{
	struct vm_struct *v;
	write_lock(&vmlist_lock);
	v = __remove_vm_area(addr);
	write_unlock(&vmlist_lock);
	return v;
}

static void __vunmap(void *addr, int deallocate_pages)
{
	struct vm_struct *area;

	if (!addr)
		return;

	if ((PAGE_SIZE-1) & (unsigned long)addr) {
		printk(KERN_ERR "Trying to vfree() bad address (%p)\n", addr);
		WARN_ON(1);
		return;
	}

	area = remove_vm_area(addr);
	if (unlikely(!area)) {
		printk(KERN_ERR "Trying to vfree() nonexistent vm area (%p)\n",
				addr);
		WARN_ON(1);
		return;
	}

	debug_check_no_locks_freed(addr, area->size);

	if (deallocate_pages) {
		int i;

		for (i = 0; i < area->nr_pages; i++) {
			BUG_ON(!area->pages[i]);
			__free_page(area->pages[i]);
		}

		if (area->flags & VM_VPAGES)
			vfree(area->pages);
		else
			kfree(area->pages);
	}

	kfree(area);
	return;
}

/**
 *	vfree  -  release memory allocated by vmalloc()
 *	@addr:		memory base address
 *
 *	Free the virtually continuous memory area starting at @addr, as
 *	obtained from vmalloc(), vmalloc_32() or __vmalloc(). If @addr is
 *	NULL, no operation is performed.
 *
 *	Must not be called in interrupt context.
 */
void vfree(void *addr)
{
	BUG_ON(in_interrupt());
	__vunmap(addr, 1);
}
EXPORT_SYMBOL(vfree);

/**
 *	vunmap  -  release virtual mapping obtained by vmap()
 *	@addr:		memory base address
 *
 *	Free the virtually contiguous memory area starting at @addr,
 *	which was created from the page array passed to vmap().
 *
 *	Must not be called in interrupt context.
 */
void vunmap(void *addr)
{
	BUG_ON(in_interrupt());
	__vunmap(addr, 0);
}
EXPORT_SYMBOL(vunmap);

/**
 * 将物理内存空间pages数组中的页帧映射到VMALLOC区域中去
 *	vmap  -  map an array of pages into virtually contiguous space
 *	@pages:		array of page pointers
 *	@count:		number of pages to map
 *	@flags:		vm_area->flags
 *	@prot:		page protection for the mapping
 *
 *	Maps @count pages from @pages into contiguous kernel virtual
 *	space.
 */
void *vmap(struct page **pages, unsigned int count,
		unsigned long flags, pgprot_t prot)
{
	struct vm_struct *area;

	if (count > num_physpages)
		return NULL;
    /* 在VMALLOC空间中得到空闲空间 */
	area = get_vm_area((count << PAGE_SHIFT), flags);
	if (!area)
		return NULL;
	/* 将pages和area映射起来 */
	if (map_vm_area(area, prot, &pages)) {
		vunmap(area->addr);
		return NULL;
	}

	return area->addr;
}
EXPORT_SYMBOL(vmap);

/*
 * vmalloc()
 *  __vmalloc()
 *   __vmalloc_node()
 *    __vmalloc_area_node()
 */
void *__vmalloc_area_node(struct vm_struct *area, gfp_t gfp_mask,
				pgprot_t prot, int node)
{
	struct page **pages;
	unsigned int nr_pages, array_size, i;
	/*需要分配页的数量*/  
	nr_pages = (area->size - PAGE_SIZE) >> PAGE_SHIFT;
	 /*page指针数组的大小*/  
	array_size = (nr_pages * sizeof(struct page *));

	area->nr_pages = nr_pages;
	/* Please note that the recursion is strictly bounded. */
	/* 如果数组的大小大于页的大小就从非连续内存区分配，否则从kmalloc分配 */  
	if (array_size > PAGE_SIZE) { /* 会又递归到本函数 */
	
		pages = __vmalloc_node(array_size, gfp_mask | __GFP_ZERO,
					PAGE_KERNEL, node);
		area->flags |= VM_VPAGES;
	} else {
		pages = kmalloc_node(array_size,
				(gfp_mask & GFP_RECLAIM_MASK) | __GFP_ZERO,
				node);
	}
	area->pages = pages;
	/*如果这个数组没有分配到内存，就释放vm_struct描述符，返回*/ 
	if (!area->pages) {
		//从vmlist中删除area对象
		remove_vm_area(area->addr);
		kfree(area);
		return NULL;
	}

     /* 
      * 从高端物理内存非配每一个物理页，
      * 将描述符的pages字段的每一项指向得到的物理页的page结构
      * vmalloc设计的意图就是用连续的逻辑地址来使用不连续的物理地址
	  */ 
	for (i = 0; i < area->nr_pages; i++) {
		if (node < 0) /* 未指定内存节点 */
			// 分配实际的物理页
			area->pages[i] = alloc_page(gfp_mask);
		else
			
			area->pages[i] = alloc_pages_node(node, gfp_mask, 0);
		if (unlikely(!area->pages[i])) { //分配失败了
		
			/* Successfully allocated i pages, free them in __vunmap() */
			area->nr_pages = i;
			goto fail;
		}
	}
	/*
	 * 给每个pte映射到分散的page
	 * 建立页表与物理页之间的映射，一级一级的很复杂
	 */	
	if (map_vm_area(area, prot, &pages))
		goto fail;
	return area->addr;

fail:
	vfree(area->addr);
	return NULL;
}

void *__vmalloc_area(struct vm_struct *area, gfp_t gfp_mask, pgprot_t prot)
{
	return __vmalloc_area_node(area, gfp_mask, prot, -1);
}

/**
 *	__vmalloc_node  -  allocate virtually contiguous memory
 *	@size:		allocation size
 *	@gfp_mask:	flags for the page level allocator
 *	@prot:		protection mask for the allocated pages
 *	@node:		node to use for allocation or -1
 *
 *	Allocate enough pages to cover @size from the page level
 *	allocator with @gfp_mask flags.  Map them into contiguous
 *	kernel virtual space, using a pagetable protection of @prot.
 *
 * vmalloc()
 *  __vmalloc()
 *   __vmalloc_node()
 */
static void *__vmalloc_node(unsigned long size, gfp_t gfp_mask, pgprot_t prot,
			    int node)
{
   // 每次vmalloc的区域，用一个vm_struct表示
	struct vm_struct *area;

    // 分配内存区大小进行页对齐
	size = PAGE_ALIGN(size);
	/*
      需要分配的大小不能为0，也不能大于物理页的总数量
	*/
	if (!size || (size >> PAGE_SHIFT) > num_physpages)
		return NULL;
	
	/* 遍历vmlist,在VMALLOC_START和VMALLOC_END 找到一个线性区，
	  并获得vm_struct描述符，描述符的flags字段被初始化为VM_ALLOC标志，
	  该标志意味着通过使用vmalloc()函数*/  
	area = get_vm_area_node(size, VM_ALLOC, node, gfp_mask);
	if (!area)
		return NULL;

    /*
     * 分配物理内存，并通过修改内核页表建立物理地址和虚拟
     * 地址间的映射，返回值为vmalloc区的虚拟地址
     */
	return __vmalloc_area_node(area, gfp_mask, prot, node);
}

/* 
 *  由vmalloc调用，
 *  gfp_mask = GFP_KERNEL | __GFP_HIGHMEM
 *
 * vmalloc分配的区域用一个vm_struct 表示
 * 
 * 用户空间不会间接用到vmalloc
 *
 * vmalloc()
 *  __vmalloc()
 * 
 */
void *__vmalloc(unsigned long size, gfp_t gfp_mask, pgprot_t prot)
{
	return __vmalloc_node(size, gfp_mask, prot, -1);
}
EXPORT_SYMBOL(__vmalloc);

/**
 *	vmalloc  -  allocate virtually contiguous memory
 *	@size:		allocation size
 *	Allocate enough pages to cover @size from the page level
 *	allocator and map them into contiguous kernel virtual space.
 * 
 *	For tight control over page level allocator and protection flags
 *	use __vmalloc() instead.
 *  在调用vmalloc()时建立的映射是在物理内存和主内核页表(init_mm)之间的,
 *  并没有涉及到进程的页表
 *
 *
 * 以vmalloc为例(最常使用)，这部分区域对应的线性地址在内核使用vmalloc分配内存时，
 * 其实就已经分配了相应的物理内存，并做了相应的映射，建立了相应的页表项，
 * 但相关页表项仅写入了“内核页表”，并没有实时更新到“进程页表中”，
 * 内核在这里使用了“延迟更新”的策略，将“进程页表”真正更新推迟到第一次访问相关线性地址，
 * 发生page fault时，此时在page fault的处理流程中进行“进程页表”的更新：
 *
 *
 * 用户空间不会间接用到vmalloc
 * vmalloc_32 只从ZONE_NORMAL和ZONE_DMA中分配物理内存，vmalloc没有这个限制
 */
void *vmalloc(unsigned long size)
{
	return __vmalloc(size, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL);
}
EXPORT_SYMBOL(vmalloc);

/**
 * vmalloc_user - allocate zeroed virtually contiguous memory for userspace
 * @size: allocation size
 *
 * The resulting memory area is zeroed so it can be mapped to userspace
 * without leaking data.
 */
void *vmalloc_user(unsigned long size)
{
	struct vm_struct *area;
	void *ret;

	ret = __vmalloc(size, GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO, PAGE_KERNEL);
	if (ret) {
		write_lock(&vmlist_lock);
		area = __find_vm_area(ret);
		area->flags |= VM_USERMAP;
		write_unlock(&vmlist_lock);
	}
	return ret;
}
EXPORT_SYMBOL(vmalloc_user);

/**
 *	vmalloc_node  -  allocate memory on a specific node
 *	@size:		allocation size
 *	@node:		numa node
 *
 *	Allocate enough pages to cover @size from the page level
 *	allocator and map them into contiguous kernel virtual space.
 *
 *	For tight control over page level allocator and protection flags
 *	use __vmalloc() instead.
 */
void *vmalloc_node(unsigned long size, int node)
{
	return __vmalloc_node(size, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL, node);
}
EXPORT_SYMBOL(vmalloc_node);

#ifndef PAGE_KERNEL_EXEC
# define PAGE_KERNEL_EXEC PAGE_KERNEL
#endif

/**
 *	vmalloc_exec  -  allocate virtually contiguous, executable memory
 *	@size:		allocation size
 *
 *	Kernel-internal function to allocate enough pages to cover @size
 *	the page level allocator and map them into contiguous and
 *	executable kernel virtual space.
 *
 *	For tight control over page level allocator and protection flags
 *	use __vmalloc() instead.
 *
 * sys_init_module()
 *  load_module()
 *   module_alloc()
 *    vmalloc_exec()
 */

void *vmalloc_exec(unsigned long size)
{
	return __vmalloc(size, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL_EXEC);
}

#if defined(CONFIG_64BIT) && defined(CONFIG_ZONE_DMA32)
#define GFP_VMALLOC32 GFP_DMA32 | GFP_KERNEL
#elif defined(CONFIG_64BIT) && defined(CONFIG_ZONE_DMA)
#define GFP_VMALLOC32 GFP_DMA | GFP_KERNEL
#else
#define GFP_VMALLOC32 GFP_KERNEL
#endif

/**
 *	vmalloc_32  -  allocate virtually contiguous memory (32bit addressable)
 *	@size:		allocation size
 *
 *	Allocate enough 32bit PA addressable pages to cover @size from the
 *	page level allocator and map them into contiguous kernel virtual space.
 *
 *  vmalloc_32 只从ZONE_NORMAL和ZONE_DMA中分配物理内存，vmalloc没有这个限制
 *
 */
void *vmalloc_32(unsigned long size)
{
	return __vmalloc(size, GFP_VMALLOC32, PAGE_KERNEL);
}
EXPORT_SYMBOL(vmalloc_32);

/**
 * vmalloc_32_user - allocate zeroed virtually contiguous 32bit memory
 *	@size:		allocation size
 *
 * The resulting memory area is 32bit addressable and zeroed so it can be
 * mapped to userspace without leaking data.
 */
void *vmalloc_32_user(unsigned long size)
{
	struct vm_struct *area;
	void *ret;

	ret = __vmalloc(size, GFP_VMALLOC32 | __GFP_ZERO, PAGE_KERNEL);
	if (ret) {
		write_lock(&vmlist_lock);
		area = __find_vm_area(ret);
		area->flags |= VM_USERMAP;
		write_unlock(&vmlist_lock);
	}
	return ret;
}
EXPORT_SYMBOL(vmalloc_32_user);

long vread(char *buf, char *addr, unsigned long count)
{
	struct vm_struct *tmp;
	char *vaddr, *buf_start = buf;
	unsigned long n;

	/* Don't allow overflow */
	if ((unsigned long) addr + count < count)
		count = -(unsigned long) addr;

	read_lock(&vmlist_lock);
	for (tmp = vmlist; tmp; tmp = tmp->next) {
		vaddr = (char *) tmp->addr;
		if (addr >= vaddr + tmp->size - PAGE_SIZE)
			continue;
		while (addr < vaddr) {
			if (count == 0)
				goto finished;
			*buf = '\0';
			buf++;
			addr++;
			count--;
		}
		n = vaddr + tmp->size - PAGE_SIZE - addr;
		do {
			if (count == 0)
				goto finished;
			*buf = *addr;
			buf++;
			addr++;
			count--;
		} while (--n > 0);
	}
finished:
	read_unlock(&vmlist_lock);
	return buf - buf_start;
}

long vwrite(char *buf, char *addr, unsigned long count)
{
	struct vm_struct *tmp;
	char *vaddr, *buf_start = buf;
	unsigned long n;

	/* Don't allow overflow */
	if ((unsigned long) addr + count < count)
		count = -(unsigned long) addr;

	read_lock(&vmlist_lock);
	for (tmp = vmlist; tmp; tmp = tmp->next) {
		vaddr = (char *) tmp->addr;
		if (addr >= vaddr + tmp->size - PAGE_SIZE)
			continue;
		while (addr < vaddr) {
			if (count == 0)
				goto finished;
			buf++;
			addr++;
			count--;
		}
		n = vaddr + tmp->size - PAGE_SIZE - addr;
		do {
			if (count == 0)
				goto finished;
			*addr = *buf;
			buf++;
			addr++;
			count--;
		} while (--n > 0);
	}
finished:
	read_unlock(&vmlist_lock);
	return buf - buf_start;
}

/**
 *	remap_vmalloc_range  -  map vmalloc pages to userspace
 *	@vma:		vma to cover (map full range of vma)
 *	@addr:		vmalloc memory
 *	@pgoff:		number of pages into addr before first page to map
 *	@returns:	0 for success, -Exxx on failure
 *
 *	This function checks that addr is a valid vmalloc'ed area, and
 *	that it is big enough to cover the vma. Will return failure if
 *	that criteria isn't met.
 *
 *	Similar to remap_pfn_range() (see mm/memory.c)
 */
int remap_vmalloc_range(struct vm_area_struct *vma, void *addr,
						unsigned long pgoff)
{
	struct vm_struct *area;
	unsigned long uaddr = vma->vm_start;
	unsigned long usize = vma->vm_end - vma->vm_start;
	int ret;

	if ((PAGE_SIZE-1) & (unsigned long)addr)
		return -EINVAL;

	read_lock(&vmlist_lock);
	area = __find_vm_area(addr);
	if (!area)
		goto out_einval_locked;

	if (!(area->flags & VM_USERMAP))
		goto out_einval_locked;

	if (usize + (pgoff << PAGE_SHIFT) > area->size - PAGE_SIZE)
		goto out_einval_locked;
	read_unlock(&vmlist_lock);

	addr += pgoff << PAGE_SHIFT;
	do {
		struct page *page = vmalloc_to_page(addr);
		ret = vm_insert_page(vma, uaddr, page);
		if (ret)
			return ret;

		uaddr += PAGE_SIZE;
		addr += PAGE_SIZE;
		usize -= PAGE_SIZE;
	} while (usize > 0);

	/* Prevent "things" like memory migration? VM_flags need a cleanup... */
	vma->vm_flags |= VM_RESERVED;

	return ret;

out_einval_locked:
	read_unlock(&vmlist_lock);
	return -EINVAL;
}
EXPORT_SYMBOL(remap_vmalloc_range);

/*
 * Implement a stub for vmalloc_sync_all() if the architecture chose not to
 * have one.
 */
void  __attribute__((weak)) vmalloc_sync_all(void)
{
}


static int f(pte_t *pte, struct page *pmd_page, unsigned long addr, void *data)
{
	/* apply_to_page_range() does all the hard work. */
	return 0;
}

/**
 *	alloc_vm_area - allocate a range of kernel address space
 *	@size:		size of the area
 *	@returns:	NULL on failure, vm_struct on success
 *
 *	This function reserves a range of kernel address space, and
 *	allocates pagetables to map that range.  No actual mappings
 *	are created.  If the kernel address space is not shared
 *	between processes, it syncs the pagetable across all
 *	processes.
 */
struct vm_struct *alloc_vm_area(size_t size)
{
	struct vm_struct *area;

	area = get_vm_area(size, VM_IOREMAP);
	if (area == NULL)
		return NULL;

	/*
	 * This ensures that page tables are constructed for this region
	 * of kernel virtual address space and mapped into init_mm.
	 */
	if (apply_to_page_range(&init_mm, (unsigned long)area->addr,
				area->size, f, NULL)) {
		free_vm_area(area);
		return NULL;
	}

	/* Make sure the pagetables are constructed in process kernel
	   mappings */
	vmalloc_sync_all();

	return area;
}
EXPORT_SYMBOL_GPL(alloc_vm_area);

void free_vm_area(struct vm_struct *area)
{
	struct vm_struct *ret;
	ret = remove_vm_area(area->addr);
	BUG_ON(ret != area);
	kfree(area);
}
EXPORT_SYMBOL_GPL(free_vm_area);
