#ifndef _LINUX_VMALLOC_H
#define _LINUX_VMALLOC_H

#include <linux/spinlock.h>
#include <asm/page.h>		/* pgprot_t */

struct vm_area_struct;

/* bits in vm_struct->flags */
// 表示当前虚拟内存块是给ioremap相关函数使用，映射的是I/O空间地址，也就是设备内存
#define VM_IOREMAP	0x00000001	/* ioremap() and friends */
// 表示当前虚拟内存块是给vmalloc函数使用，映射的是实际物理内存（RAM）
#define VM_ALLOC	0x00000002	/* vmalloc() */
#define VM_MAP		0x00000004	/* vmap()ed pages */
#define VM_USERMAP	0x00000008	/* suitable for remap_vmalloc_range */
#define VM_VPAGES	0x00000010	/* buffer for pages was vmalloc'ed */
/* bits [20..32] reserved for arch specific ioremap internals */

/*
 * Maximum alignment for ioremap() regions.
 * Can be overriden by arch-specific value.
 */
#ifndef IOREMAP_MAX_ORDER
#define IOREMAP_MAX_ORDER	(7 + PAGE_SHIFT)	/* 128 pages */
#endif

/* 每个通过vmalloc分配的子区域，都对应于这么一个结构实例
 * 非连续内存区(在high mem区域中)访问会使用一个vm_struct结构来描述每个非连续内存区 
 * 全局变量vmlist管理vm_struct实例
 *
 *
 * vmalloc区域中的子内存区，ioremap也使用了该区域
 * 所有的vm_struct组成一个链表，管理着vmalloc区域
 * 中已经建立的各个子区域，该链表头保存于
 * 全局变量vmlist中。
 */
struct vm_struct {
	/* keep next,addr,size together to speedup lookups */
	struct vm_struct	*next;
	void			*addr; /* 内存区内第一个内存单元的线性地址 */
	unsigned long		size; /* 内存区的大小加4096(内存区之间的安全区间的大小) */
	/*
	 * VM_ALLOC指定由vmalloc产生的子区域
     * VM_MAP表示将现存pages集合映射到连续的虚拟地址空间中。
     * VM_IOREMAP表示将IO内存映射到vmalloc区域中。
	 */
	unsigned long		flags; /* 非连续的内存区映射的内存类型    ,1 VM_ALLOC,2 VM_MAP, 3,VM_IOREMAP*/
	struct page		**pages; /* 二级数组，第一级是从slab中分配的,指向nr_pages数组的指针，该数组由指向页描述符的指针组成   */
	unsigned int		nr_pages; /* **pages 数组长度*/
    /*
     * ioremap时使用，用来保存该区域映射的物理
     * 内存地址，在通常的vmalloc流程中不使用该
     * 字段，因为vmalloc流程中会分配物理内存，并
     * 通过修改内核页表来实现虚拟地址到物理
     * 地址见的映射。
     */	
	unsigned long		phys_addr; /* 该字段为0，除非内存已被创建来映射一个硬件设备的I/O共享内存(VM_IOREMAP),即用ioremap()来映射    */
};

/*
 *	Highlevel APIs for driver use
 */
extern void *vmalloc(unsigned long size);
extern void *vmalloc_user(unsigned long size);
extern void *vmalloc_node(unsigned long size, int node);
extern void *vmalloc_exec(unsigned long size);
extern void *vmalloc_32(unsigned long size);
extern void *vmalloc_32_user(unsigned long size);
extern void *__vmalloc(unsigned long size, gfp_t gfp_mask, pgprot_t prot);
extern void *__vmalloc_area(struct vm_struct *area, gfp_t gfp_mask,
				pgprot_t prot);
extern void vfree(void *addr);

extern void *vmap(struct page **pages, unsigned int count,
			unsigned long flags, pgprot_t prot);
extern void vunmap(void *addr);

extern int remap_vmalloc_range(struct vm_area_struct *vma, void *addr,
							unsigned long pgoff);
void vmalloc_sync_all(void);
 
/*
 *	Lowlevel-APIs (not for driver use!)
 */

static inline size_t get_vm_area_size(const struct vm_struct *area)
{
	/* return actual size without guard page */
	return area->size - PAGE_SIZE;
}

extern struct vm_struct *get_vm_area(unsigned long size, unsigned long flags);
extern struct vm_struct *__get_vm_area(unsigned long size, unsigned long flags,
					unsigned long start, unsigned long end);
extern struct vm_struct *get_vm_area_node(unsigned long size,
					  unsigned long flags, int node,
					  gfp_t gfp_mask);
extern struct vm_struct *remove_vm_area(void *addr);

extern int map_vm_area(struct vm_struct *area, pgprot_t prot,
			struct page ***pages);
extern void unmap_kernel_range(unsigned long addr, unsigned long size);

/* Allocate/destroy a 'vmalloc' VM area. */
extern struct vm_struct *alloc_vm_area(size_t size);
extern void free_vm_area(struct vm_struct *area);

/*
 *	Internals.  Dont't use..
 */
extern rwlock_t vmlist_lock;
extern struct vm_struct *vmlist;

#endif /* _LINUX_VMALLOC_H */
