/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * MMU support
 *
 * Copyright (C) 2006 Qumranet, Inc.
 *
 * Authors:
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *   Avi Kivity   <avi@qumranet.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

/*
 * We need the mmu code to access both 32-bit and 64-bit guest ptes,
 * so the code in this file is compiled twice, once per pte size.
 */

#if PTTYPE == 64
	#define pt_element_t u64
	#define guest_walker guest_walker64
	#define FNAME(name) paging##64_##name
	#define PT_BASE_ADDR_MASK PT64_BASE_ADDR_MASK
	#define PT_DIR_BASE_ADDR_MASK PT64_DIR_BASE_ADDR_MASK
	#define PT_INDEX(addr, level) PT64_INDEX(addr, level)
	#define SHADOW_PT_INDEX(addr, level) PT64_INDEX(addr, level)
	#define PT_LEVEL_MASK(level) PT64_LEVEL_MASK(level)
	#ifdef CONFIG_X86_64
	#define PT_MAX_FULL_LEVELS 4
	#else
	#define PT_MAX_FULL_LEVELS 2
	#endif
#elif PTTYPE == 32
	#define pt_element_t u32
	#define guest_walker guest_walker32
	#define FNAME(name) paging##32_##name
	#define PT_BASE_ADDR_MASK PT32_BASE_ADDR_MASK
	#define PT_DIR_BASE_ADDR_MASK PT32_DIR_BASE_ADDR_MASK
	#define PT_INDEX(addr, level) PT32_INDEX(addr, level)
	#define SHADOW_PT_INDEX(addr, level) PT64_INDEX(addr, level)
	#define PT_LEVEL_MASK(level) PT32_LEVEL_MASK(level)
	#define PT_MAX_FULL_LEVELS 2
#else
	#error Invalid PTTYPE value
#endif

/*
 * The guest_walker structure emulates the behavior of the hardware page
 * table walker.
 */
struct guest_walker {
	int level;
	gfn_t table_gfn[PT_MAX_FULL_LEVELS];
	pt_element_t *table;
	pt_element_t pte;
	pt_element_t *ptep;
	struct page *page;
	int index;
	pt_element_t inherited_ar;
	gfn_t gfn;
	u32 error_code;
};

/*
 * Fetch a guest pte for a guest virtual address
 *
 * 该函数使用发生page_fault是的GVA和客户机页 目录的基地址GPA，
 * 一级一级的找到最后一级页表项，然后看该页表项中的 P位是否为1
 *
 * 取得guest os中的pte
 *
 * FNAME(page_fault)()
 *  FNAME(walk_addr)()
 */
static int FNAME(walk_addr)(struct guest_walker *walker,
			    struct kvm_vcpu *vcpu, gva_t addr,
			    int write_fault, int user_fault, int fetch_fault)
{
	hpa_t hpa;
	struct kvm_memory_slot *slot;
	pt_element_t *ptep;
	pt_element_t root;
	gfn_t table_gfn;

	

	pgprintk("%s: addr %lx\n", __FUNCTION__, addr);
	walker->level = vcpu->mmu.root_level;
	walker->table = NULL;
	walker->page = NULL;
	walker->ptep = NULL;
	root = vcpu->cr3;
	
#if PTTYPE == 64
	if (!is_long_mode(vcpu)) {
		walker->ptep = &vcpu->pdptrs[(addr >> 30) & 3];
		root = *walker->ptep;
		walker->pte = root;
		if (!(root & PT_PRESENT_MASK))
			goto not_present;
		--walker->level;
	}
#endif

	table_gfn = (root & PT64_BASE_ADDR_MASK) >> PAGE_SHIFT;
	walker->table_gfn[walker->level - 1] = table_gfn;
	pgprintk("%s: table_gfn[%d] %lx\n", __FUNCTION__,
		 walker->level - 1, table_gfn);
	
	slot = gfn_to_memslot(vcpu->kvm, table_gfn);
	
	hpa = safe_gpa_to_hpa(vcpu, root & PT64_BASE_ADDR_MASK);
	walker->page = pfn_to_page(hpa >> PAGE_SHIFT);
	walker->table = kmap_atomic(walker->page, KM_USER0);

	ASSERT((!is_long_mode(vcpu) && is_pae(vcpu)) ||
	       (vcpu->cr3 & CR3_NONPAE_RESERVED_BITS) == 0);

	walker->inherited_ar = PT_USER_MASK | PT_WRITABLE_MASK;

	for (;;) {
		int index = PT_INDEX(addr, walker->level);
		hpa_t paddr;

		ptep = &walker->table[index];
		walker->index = index;
		ASSERT(((unsigned long)walker->table & PAGE_MASK) ==
		       ((unsigned long)ptep & PAGE_MASK));

        /*
         * 看该页表项中的 P位是否为1
         */
		if (!is_present_pte(*ptep))
			goto not_present;

        /*
         * 写导致的异常，但是pte表明的page不可写
         */
		if (write_fault && !is_writeble_pte(*ptep))
			if (user_fault || is_write_protection(vcpu))
				goto access_error;

		if (user_fault && !(*ptep & PT_USER_MASK))
			goto access_error;

#if PTTYPE == 64
		if (fetch_fault && is_nx(vcpu) && (*ptep & PT64_NX_MASK))
			goto access_error;
#endif

		if (!(*ptep & PT_ACCESSED_MASK)) {
			mark_page_dirty(vcpu->kvm, table_gfn);
			*ptep |= PT_ACCESSED_MASK;
		}

		if (walker->level == PT_PAGE_TABLE_LEVEL) {
			walker->gfn = (*ptep & PT_BASE_ADDR_MASK)
				>> PAGE_SHIFT;
			break;
		}

		if (walker->level == PT_DIRECTORY_LEVEL
		    && (*ptep & PT_PAGE_SIZE_MASK)
		    && (PTTYPE == 64 || is_pse(vcpu))) {
			walker->gfn = (*ptep & PT_DIR_BASE_ADDR_MASK)
				>> PAGE_SHIFT;
			walker->gfn += PT_INDEX(addr, PT_PAGE_TABLE_LEVEL);
			break;
		}

		walker->inherited_ar &= walker->table[index];
		table_gfn = (*ptep & PT_BASE_ADDR_MASK) >> PAGE_SHIFT;
		kunmap_atomic(walker->table, KM_USER0);
		//得到host physical addr
		paddr = safe_gpa_to_hpa(vcpu, table_gfn << PAGE_SHIFT);
		walker->page = pfn_to_page(paddr >> PAGE_SHIFT);
		walker->table = kmap_atomic(walker->page, KM_USER0);
		--walker->level;
		walker->table_gfn[walker->level - 1 ] = table_gfn;
		pgprintk("%s: table_gfn[%d] %lx\n", __FUNCTION__,
			 walker->level - 1, table_gfn);
	}
	walker->pte = *ptep;
	if (walker->page)
		walker->ptep = NULL;
	if (walker->table)
		kunmap_atomic(walker->table, KM_USER0);
	pgprintk("%s: pte %llx\n", __FUNCTION__, (u64)*ptep);
	return 1;

not_present:
	walker->error_code = 0;
	goto err;

access_error:
	walker->error_code = PFERR_PRESENT_MASK;

err:
	//写造成缺页
	if (write_fault)
		walker->error_code |= PFERR_WRITE_MASK;
	
	if (user_fault)
		walker->error_code |= PFERR_USER_MASK;
	if (fetch_fault)
		walker->error_code |= PFERR_FETCH_MASK;
	if (walker->table)
		kunmap_atomic(walker->table, KM_USER0);
	return 0;
}

static void FNAME(mark_pagetable_dirty)(struct kvm *kvm,
					struct guest_walker *walker)
{
	mark_page_dirty(kvm, walker->table_gfn[walker->level - 1]);
}

/*
 * FNAME(set_pte)
 *  FNAME(set_pte_common)
 *
 */
static void FNAME(set_pte_common)(struct kvm_vcpu *vcpu,
				  u64 *shadow_pte,
				  gpa_t gaddr,
				  pt_element_t gpte,
				  u64 access_bits,
				  int user_fault,
				  int write_fault,
				  int *ptwrite,
				  struct guest_walker *walker,
				  gfn_t gfn)
{
	hpa_t paddr;
	int dirty = gpte & PT_DIRTY_MASK;
	u64 spte = *shadow_pte;
	int was_rmapped = is_rmap_pte(spte);

	pgprintk("%s: spte %llx gpte %llx access %llx write_fault %d"
		 " user_fault %d gfn %lx\n",
		 __FUNCTION__, spte, (u64)gpte, access_bits,
		 write_fault, user_fault, gfn);

	if (write_fault && !dirty) {
		pt_element_t *guest_ent, *tmp = NULL;

		if (walker->ptep)
			guest_ent = walker->ptep;
		else {
			tmp = kmap_atomic(walker->page, KM_USER0);
			guest_ent = &tmp[walker->index];
		}

		*guest_ent |= PT_DIRTY_MASK;
		if (!walker->ptep)
			kunmap_atomic(tmp, KM_USER0);
		dirty = 1;
		FNAME(mark_pagetable_dirty)(vcpu->kvm, walker);
	}

	spte |= PT_PRESENT_MASK | PT_ACCESSED_MASK | PT_DIRTY_MASK;
	spte |= gpte & PT64_NX_MASK;
	if (!dirty)
		access_bits &= ~PT_WRITABLE_MASK;

	paddr = gpa_to_hpa(vcpu, gaddr & PT64_BASE_ADDR_MASK);

	spte |= PT_PRESENT_MASK;
	if (access_bits & PT_USER_MASK)
		spte |= PT_USER_MASK;

	if (is_error_hpa(paddr)) {
		spte |= gaddr;
		spte |= PT_SHADOW_IO_MARK;
		spte &= ~PT_PRESENT_MASK;
		set_shadow_pte(shadow_pte, spte);
		return;
	}

	spte |= paddr;

	if ((access_bits & PT_WRITABLE_MASK)
	    || (write_fault && !is_write_protection(vcpu) && !user_fault)) {
		struct kvm_mmu_page *shadow;

		spte |= PT_WRITABLE_MASK;
		if (user_fault) {
			mmu_unshadow(vcpu, gfn);
			goto unshadowed;
		}

		shadow = kvm_mmu_lookup_page(vcpu, gfn);
		if (shadow) {
			pgprintk("%s: found shadow page for %lx, marking ro\n",
				 __FUNCTION__, gfn);
			access_bits &= ~PT_WRITABLE_MASK;
			if (is_writeble_pte(spte)) {
				spte &= ~PT_WRITABLE_MASK;
				kvm_x86_ops->tlb_flush(vcpu);
			}
			if (write_fault)
				*ptwrite = 1;
		}
	}

unshadowed:

	if (access_bits & PT_WRITABLE_MASK)
		mark_page_dirty(vcpu->kvm, gaddr >> PAGE_SHIFT);

	set_shadow_pte(shadow_pte, spte);
	page_header_update_slot(vcpu->kvm, shadow_pte, gaddr);
	if (!was_rmapped)
		rmap_add(vcpu, shadow_pte);
}

static void FNAME(set_pte)(struct kvm_vcpu *vcpu, pt_element_t gpte,
			   u64 *shadow_pte, u64 access_bits,
			   int user_fault, int write_fault, int *ptwrite,
			   struct guest_walker *walker, gfn_t gfn)
{
	access_bits &= gpte;
	FNAME(set_pte_common)(vcpu, shadow_pte, gpte & PT_BASE_ADDR_MASK,
			      gpte, access_bits, user_fault, write_fault,
			      ptwrite, walker, gfn);
}

static void FNAME(update_pte)(struct kvm_vcpu *vcpu, struct kvm_mmu_page *page,
			      u64 *spte, const void *pte, int bytes)
{
	pt_element_t gpte;

	if (bytes < sizeof(pt_element_t))
		return;
	gpte = *(const pt_element_t *)pte;
	if (~gpte & (PT_PRESENT_MASK | PT_ACCESSED_MASK))
		return;
	pgprintk("%s: gpte %llx spte %p\n", __FUNCTION__, (u64)gpte, spte);
	FNAME(set_pte)(vcpu, gpte, spte, PT_USER_MASK | PT_WRITABLE_MASK, 0,
		       0, NULL, NULL,
		       (gpte & PT_BASE_ADDR_MASK) >> PAGE_SHIFT);
}

static void FNAME(set_pde)(struct kvm_vcpu *vcpu, pt_element_t gpde,
			   u64 *shadow_pte, u64 access_bits,
			   int user_fault, int write_fault, int *ptwrite,
			   struct guest_walker *walker, gfn_t gfn)
{
	gpa_t gaddr;

	access_bits &= gpde;
	gaddr = (gpa_t)gfn << PAGE_SHIFT;
	if (PTTYPE == 32 && is_cpuid_PSE36())
		gaddr |= (gpde & PT32_DIR_PSE36_MASK) <<
			(32 - PT32_DIR_PSE36_SHIFT);
	FNAME(set_pte_common)(vcpu, shadow_pte, gaddr,
			      gpde, access_bits, user_fault, write_fault,
			      ptwrite, walker, gfn);
}

/*
 * Fetch a shadow pte for a specific level in the paging hierarchy.
 *
 * FNAME(page_fault)
 *  FNAME(fetch)
 *
 */
static u64 *FNAME(fetch)(struct kvm_vcpu *vcpu, gva_t addr,
			 struct guest_walker *walker,
			 int user_fault, int write_fault, int *ptwrite)
{
	hpa_t shadow_addr;
	int level;
	u64 *shadow_ent;
	u64 *prev_shadow_ent = NULL;

	if (!is_present_pte(walker->pte))
		return NULL;

	shadow_addr = vcpu->mmu.root_hpa;
	level = vcpu->mmu.shadow_root_level;
	if (level == PT32E_ROOT_LEVEL) {
		shadow_addr = vcpu->mmu.pae_root[(addr >> 30) & 3];
		shadow_addr &= PT64_BASE_ADDR_MASK;
		--level;
	}

    /*
     *  VMM遍历影子页表，当行走到最后一级页表项的时候，发现页表项为空，
     * 于是会将客户机物理页的gfn转化为pfn，将pfn填充到页表项中的addr部 分，
     * 并将P和A位置1。如果是一个写操作，而客户机的最后一级页表项中的 D位还没有置1，
     * 则还需要将页表项的R/W位清0，目的是将页面设置为只读，当发生写操作时捕捉 D位的修改
     * 
     */
	for (; ; level--) {
		u32 index = SHADOW_PT_INDEX(addr, level);
		struct kvm_mmu_page *shadow_page;
		u64 shadow_pte;
		int metaphysical;
		gfn_t table_gfn;
		unsigned hugepage_access = 0;

		shadow_ent = ((u64 *)__va(shadow_addr)) + index;
		if (is_present_pte(*shadow_ent) || is_io_pte(*shadow_ent)) {
			if (level == PT_PAGE_TABLE_LEVEL)
				break;
			shadow_addr = *shadow_ent & PT64_BASE_ADDR_MASK;
			prev_shadow_ent = shadow_ent;
			continue;
		}

		if (level == PT_PAGE_TABLE_LEVEL)
			break;

		if (level - 1 == PT_PAGE_TABLE_LEVEL
		    && walker->level == PT_DIRECTORY_LEVEL) {
			metaphysical = 1;
			hugepage_access = walker->pte;
			hugepage_access &= PT_USER_MASK | PT_WRITABLE_MASK;
			if (walker->pte & PT64_NX_MASK)
				hugepage_access |= (1 << 2);
			hugepage_access >>= PT_WRITABLE_SHIFT;
			table_gfn = (walker->pte & PT_BASE_ADDR_MASK)
				>> PAGE_SHIFT;
		} else {
			metaphysical = 0;
			table_gfn = walker->table_gfn[level - 2];
		}
		
		shadow_page = kvm_mmu_get_page(vcpu, table_gfn, addr, level-1,
					       metaphysical, hugepage_access,
					       shadow_ent);

		//host os 上的物理地址
		shadow_addr = __pa(shadow_page->spt);
		shadow_pte = shadow_addr | PT_PRESENT_MASK | PT_ACCESSED_MASK
			| PT_WRITABLE_MASK | PT_USER_MASK;
		//设置shadow page table 的 entry
		*shadow_ent = shadow_pte;
		prev_shadow_ent = shadow_ent;
	}

	if (walker->level == PT_DIRECTORY_LEVEL) {
		FNAME(set_pde)(vcpu, walker->pte, shadow_ent,
			       walker->inherited_ar, user_fault, write_fault,
			       ptwrite, walker, walker->gfn);
	} else {
		ASSERT(walker->level == PT_PAGE_TABLE_LEVEL);
		FNAME(set_pte)(vcpu, walker->pte, shadow_ent,
			       walker->inherited_ar, user_fault, write_fault,
			       ptwrite, walker, walker->gfn);
	}
	return shadow_ent;
}

/*
 * Page fault handler.  There are several causes for a page fault:
 *   - there is no shadow pte for the guest pte
 *   - write access through a shadow pte marked read only so that we can set
 *     the dirty bit
 *   - write access to a shadow pte marked read only so we can update the page
 *     dirty bitmap, when userspace requests it
 *   - mmio access; in this case we will never install a present shadow pte
 *   - normal guest page fault due to the guest pte marked not present, not
 *     writable, or not executable
 *
 *  Returns: 1 if we need to emulate the instruction, 0 otherwise, or
 *           a negative value on error.
 *
 *  函数名称 paging_32_page_fault,paging_64_page_fault
 */
static int FNAME(page_fault)(struct kvm_vcpu *vcpu, gva_t addr,
			       u32 error_code)
{
	int write_fault = error_code & PFERR_WRITE_MASK;
	int user_fault = error_code & PFERR_USER_MASK;
	int fetch_fault = error_code & PFERR_FETCH_MASK;
	struct guest_walker walker;
	u64 *shadow_pte;
	int write_pt = 0;
	int r;

	pgprintk("%s: addr %lx err %x\n", __FUNCTION__, addr, error_code);
	kvm_mmu_audit(vcpu, "pre page fault");

	r = mmu_topup_memory_caches(vcpu);
	if (r)
		return r;

	/*
	 * Look up the shadow pte for the faulting address.
	 *
	 * paging_32_walk_addr或者 paging_64_walk_addr
	 *
	 * 查找shadow page table中的pte
	 */
	r = FNAME(walk_addr)(&walker, vcpu, addr, write_fault, user_fault,
			     fetch_fault);

	/*
	 * The page is not mapped by the guest.  Let the guest handle it.
	 *
	 * guest os 没有mapped这个 gva，所以重新注入page fault异常到guest os中去
	 *
	 * 返回0，说明客户机页表有问题，这个问题是客户机的问题，
	 * 需要客户 机自行处理。把在FNAME(walk_addr)函数中得到的出错信息注入到客户机中
	 *
	 * 客户机调用客户机自己的page_fault处理函数，申请一个page，
	 * 将page的GPA填充到客户机页表项中，同时将 P位置1，A和D位都是0。
	 *
	 */
	if (!r) {
		pgprintk("%s: guest page fault\n", __FUNCTION__);
		inject_page_fault(vcpu, addr, walker.error_code);
		vcpu->last_pt_write_count = 0; /* reset fork detector */
		return 0;
	}

    //paging_32_fetch或者 paging_64_fetch
	shadow_pte = FNAME(fetch)(vcpu, addr, &walker, user_fault, write_fault,
				  &write_pt);
	pgprintk("%s: shadow pte %p %llx ptwrite %d\n", __FUNCTION__,
		 shadow_pte, *shadow_pte, write_pt);

	if (!write_pt)
		vcpu->last_pt_write_count = 0; /* reset fork detector */

	/*
	 * mmio: emulate if accessible, otherwise its a guest fault.
	 */
	if (is_io_pte(*shadow_pte))
		return 1;

	++vcpu->stat.pf_fixed;
	kvm_mmu_audit(vcpu, "post page fault (fixed)");

	return write_pt;
}

/*
 * 从guset vaddr 转到 host physical addr
 */
static gpa_t FNAME(gva_to_gpa)(struct kvm_vcpu *vcpu, gva_t vaddr)
{
	struct guest_walker walker;
	gpa_t gpa = UNMAPPED_GVA;
	int r;

	r = FNAME(walk_addr)(&walker, vcpu, vaddr, 0, 0, 0);

	if (r) {
		gpa = (gpa_t)walker.gfn << PAGE_SHIFT;
		gpa |= vaddr & ~PAGE_MASK;
	}

	return gpa;
}

#undef pt_element_t
#undef guest_walker
#undef FNAME
#undef PT_BASE_ADDR_MASK
#undef PT_INDEX
#undef SHADOW_PT_INDEX
#undef PT_LEVEL_MASK
#undef PT_DIR_BASE_ADDR_MASK
#undef PT_MAX_FULL_LEVELS
