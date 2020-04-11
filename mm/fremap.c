/*
 *   linux/mm/fremap.c
 * 
 * Explicit pagetable population and nonlinear (random) mappings support.
 *
 * started by Ingo Molnar, Copyright (C) 2002, 2003
 */
#include <linux/backing-dev.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/file.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swapops.h>
#include <linux/rmap.h>
#include <linux/module.h>
#include <linux/syscalls.h>

#include <asm/mmu_context.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

static void zap_pte(struct mm_struct *mm, struct vm_area_struct *vma,
			unsigned long addr, pte_t *ptep)
{
	pte_t pte = *ptep;

	if (pte_present(pte)) {
		struct page *page;

        /* 要把page還回去，要先做flush的動作 */
		flush_cache_page(vma, addr, pte_pfn(pte));
	    /* 取出pte的值，清除pte，同時也要記得清除tlb相對應的欄位 */
		pte = ptep_clear_flush(vma, addr, ptep);
		/* 得到pte相對應pfn的page */
		page = vm_normal_page(vma, addr, pte); 
		if (page) {
			if (pte_dirty(pte))
				set_page_dirty(page);
			/* 移除在這個page上面相對應的map */
			page_remove_rmap(page, vma);
			page_cache_release(page);
			update_hiwater_rss(mm);
			dec_mm_counter(mm, file_rss);
		}
	} else {
		if (!pte_file(pte))
			free_swap_and_cache(pte_to_swp_entry(pte));
		
		pte_clear_not_present_full(mm, addr, ptep, 0);
	}
}

/*
 * Install a file pte to a given virtual memory address, release any
 * previously existing mapping.
 *
 * sys_remap_file_pages()
 *  populate_range()
 *   install_file_pte()
 */
static int install_file_pte(struct mm_struct *mm, struct vm_area_struct *vma,
		unsigned long addr, unsigned long pgoff, pgprot_t prot)
{
	int err = -ENOMEM;
	pte_t *pte;
	spinlock_t *ptl;

	pte = get_locked_pte(mm, addr, &ptl);
	if (!pte)
		goto out;

	if (!pte_none(*pte)) /* pte已经有值了 */
		zap_pte(mm, vma, addr, pte);/* 删除所涉及的现存页表项 */

	set_pte_at(mm, addr, pte, pgoff_to_pte(pgoff));
	/*
	 * We don't need to run update_mmu_cache() here because the "file pte"
	 * being installed by install_file_pte() is not a real pte - it's a
	 * non-present entry (like a swap entry), noting what file offset should
	 * be mapped there when there's a fault (in a non-linear vma where
	 * that's not obvious).
	 */
	pte_unmap_unlock(pte, ptl);
	err = 0;
out:
	return err;
}

/* 根据pgoff和addr,size不断的修改相应的pte 
 * sys_remap_file_pages()
 *  populate_range()
 */
static int populate_range(struct mm_struct *mm, struct vm_area_struct *vma,
			unsigned long addr, unsigned long size, pgoff_t pgoff)
{
	int err;

	do {
		err = install_file_pte(mm, vma, addr, pgoff, vma->vm_page_prot);
		if (err)
			return err;

		size -= PAGE_SIZE;
		addr += PAGE_SIZE;
		pgoff++;
	} while (size);

        return 0;

}

/**
 * sys_remap_file_pages - remap arbitrary pages of an existing VM_SHARED vma
 * @start: start of the remapped virtual memory range
 * @size: size of the remapped virtual memory range
 * @prot: new protection bits of the range (see NOTE)
 * @pgoff: to-be-mapped page of the backing store file
 * @flags: 0 or MAP_NONBLOCKED - the later will cause no IO.
 *
 * sys_remap_file_pages remaps arbitrary pages of an existing VM_SHARED vma
 * (shared backing store file).
 *
 * This syscall works purely via pagetables, so it's the most efficient
 * way to map the same (large) file into a given virtual window. Unlike
 * mmap()/mremap() it does not create any new vmas. The new mappings are
 * also safe across swapout.
 *
 * NOTE: the 'prot' parameter right now is ignored (but must be zero),
 * and the vma's default protection is used. Arbitrary protections
 * might be implemented in the future.
 *
 * 允许重排映射中的page，是的内存与文件中的次序不在等价，该实现无须移动内存中的数据
 *
 * 在一般情况下，非线性映射做的基本上就是在原来的线性映射中修改页表，
 * 已达到移动页的目的，这样会节省很多开支
 * 
 */
asmlinkage long sys_remap_file_pages(unsigned long start, unsigned long size,
	unsigned long prot, unsigned long pgoff/* start开始的页面序号，不是文件内的偏移 */ , unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct address_space *mapping;
	unsigned long end = start + size;
	struct vm_area_struct *vma;
	int err = -EINVAL;
	int has_write_lock = 0;

	if (prot) //prot必须为0，否则出错:Invalid argument。
		return err;
	/*
	 * Sanitize the syscall parameters:
	 * 将start和size按页大小对齐，因此传递这两个参数的时候最好是页大小的整数倍。
	 */
	start = start & PAGE_MASK;
	size = size & PAGE_MASK;

	/* Does the address range wrap, or is the span zero-sized? 
       一些检查，不涉及核心内容，省略。
	 */
	if (start + size <= start)
		return err;

	/* Can we represent this offset inside this architecture's pte's? */
#if PTE_FILE_MAX_BITS < BITS_PER_LONG
	if (pgoff + (size >> PAGE_SHIFT) >= (1UL << PTE_FILE_MAX_BITS))
		return err;
#endif

	/* We need down_write() to change vma->vm_flags. */
	down_read(&mm->mmap_sem);
 retry:
	vma = find_vma(mm, start);

	/*
	 * Make sure the vma is shared, that it supports prefaulting,
	 * and that the remapped range is valid and fully within
	 * the single existing vma.  vm_private_data is used as a
	 * swapout cursor in a VM_NONLINEAR vma.
	 * 
	 * 必须存在vma能够包含start地址，而且该vma的vm_flags中必须有VM_SHARED
	 */
	if (!vma || !(vma->vm_flags & VM_SHARED))
		goto out;

    /* 不能进行VM_NONLINEAR映射 */
	if (vma->vm_private_data && !(vma->vm_flags & VM_NONLINEAR))
		goto out;

    /* 不能进行VM_NONLINEAR映射 */
	if (!(vma->vm_flags & VM_CAN_NONLINEAR))
		goto out;

    /* 地址start必须在vma的映射范围内 */
	if (end <= start || start < vma->vm_start || end > vma->vm_end)
		goto out;

	/* Must set VM_NONLINEAR before any pages are populated. 
       如果vma此前没有进行过非线性映射,vm_flags上就不会设置VM_NONLINEAR
       就需要先从prio_tree(address_sapce->i_mmap)中移除，然后插入到address_sapce->i_mmap_nonlinear
	*/
	if (!(vma->vm_flags & VM_NONLINEAR)) {
		/* 如果vma目前不是非线性映射，则要走这个分支。 */
		/* Don't need a nonlinear mapping, exit success */
		if (pgoff == linear_page_index(vma, start)) {
			/* 如果地址start在原来的映射中就是pgoff所映射的位置，就不需要做什么了 */
			err = 0;
			goto out;
		}

		if (!has_write_lock) {
			up_read(&mm->mmap_sem);
			down_write(&mm->mmap_sem);
			has_write_lock = 1;
			goto retry;
		}
		mapping = vma->vm_file->f_mapping; /* 得到对应的address_space */
		/*
		 * page_mkclean doesn't work on nonlinear vmas, so if
		 * dirty pages need to be accounted, emulate with linear
		 * vmas.
		 */
		if (mapping_cap_account_dirty(mapping)) {
			unsigned long addr;

			flags &= MAP_NONBLOCK;
		    //这里会分配vma，并且插入到rb_tree
			addr = mmap_region(vma->vm_file, start, size,
					flags, vma->vm_flags, pgoff, 1);
			if (IS_ERR_VALUE(addr)) {
				err = addr;
			} else {
				BUG_ON(addr != start);
				err = 0;
				
			}
			goto out;
		}

		
		spin_lock(&mapping->i_mmap_lock);
		flush_dcache_mmap_lock(mapping);
		vma->vm_flags |= VM_NONLINEAR; //设置非线性映射的标志，下次如果再有同一个vma区域中的非线性映射，就不会再走这个分支了，将会直接跳到下面去修改页表。
		//nolinear map不能出现在address_space->i_mmap中,只能出现在address_space->i_mmap_nonlinear中
		vma_prio_tree_remove(vma, &mapping->i_mmap); //将该vma从该文件的线性映射相关的数据结构（address_space）上删除
		vma_nonlinear_insert(vma, &mapping->i_mmap_nonlinear); //将该vma->shared.vm_set.list插入到该文件的address_space->i_mmap_nonlinear链表中去
		flush_dcache_mmap_unlock(mapping);
		spin_unlock(&mapping->i_mmap_lock);
	}

    /* 修改页表,重新映射 */
	err = populate_range(mm, vma, start, size, pgoff);
	if (!err && !(flags & MAP_NONBLOCK)) {
		if (unlikely(has_write_lock)) {
			downgrade_write(&mm->mmap_sem);
			has_write_lock = 0;
		}
		/* 读入设置过的非线性页，通过触发缺页异常实现 */
		make_pages_present(start, start+size);
	}

	/*
	 * We can't clear VM_NONLINEAR because we'd have to do
	 * it after ->populate completes, and that would prevent
	 * downgrading the lock.  (Locks can't be upgraded).
	 */

out:
	if (likely(!has_write_lock))
		up_read(&mm->mmap_sem);
	else
		up_write(&mm->mmap_sem);

	return err;
}

