#ifndef _LINUX_MM_TYPES_H
#define _LINUX_MM_TYPES_H

#include <linux/auxvec.h>
#include <linux/types.h>
#include <linux/threads.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/prio_tree.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/completion.h>
#include <asm/page.h>
#include <asm/mmu.h>

#ifndef AT_VECTOR_SIZE_ARCH
#define AT_VECTOR_SIZE_ARCH 0
#endif
#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))

struct address_space;

#if NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS
typedef atomic_long_t mm_counter_t;
#else  /* NR_CPUS < CONFIG_SPLIT_PTLOCK_CPUS */
typedef unsigned long mm_counter_t;
#endif /* NR_CPUS < CONFIG_SPLIT_PTLOCK_CPUS */

/*
 * Each physical page in the system has a struct page associated with
 * it to keep track of whatever it is we are using the page for at the
 * moment. Note that we have no way to track which tasks are using
 * a page, though if it is a pagecache page, rmap structures can tell us
 * who is mapping it.
 *
 * page在刚刚建立到buddy system中时，没有设置PG_active标记
 */
struct page {
    /*
     * 标记: 
            PG_locked , 页是否被锁定
            PG_error, 该页在io期间，有错误出现
            PG_referenced和PG_active控制了系统使用该页的活跃程度,在页交换子系统选择换出页时，该信息很重要。
            PG_uptodate, 表示页的数据已经从块设备读取，期间没有出现错误
            PG_dirty, 和磁盘上的页相比，页的内容已经出现改变。
            PG_lru有助于实现页面回收和切换.内核使用lru链表来区别活动(zone->active)和不活动页(zone->inactive)，如果页在其中的一个链表中，就设置该标记，
            PG_active,如果页在活动链表中，就设置该标记
            PG_highmem,表示页在高端内存中，无法持久映射在内存中。
            PG_private,表示page结构的private成员非空,用于I/O页，可使用该字段将页细分为多个缓冲区,但内核的其他部分也有各种不同的用法。
            PG_writeback,如果页的内容处于向块设备回写的过程中，就设置这个标记
            PG_slab
            PG_swapcache,如果页用于交换缓存，就设置这个标记，在这种情况下， private就是swap_entry_t的项
            PG_reclaim,在决定回收这个页之后，设置这个标记
            PG_compound,表示该页属于一个更大的复合页，复合页由多个毗邻的普通页组成
            PG_buddy,如果空闲页包含在伙伴系统的列表中，就设置
            
            除去上面的这些标记外，也存储所属的nodeid,zone
     
     */
	unsigned long flags;		/* Atomic flags, some possibly
					               updated asynchronously */
	atomic_t _count;		/* 内核中引用改页的次数,在其值达0时,内核就知道page实例当前不使用，因此可以删除,Usage count, see below. */
	union {
		/*
		 * 如果一个page用与slub分配期，因为只会被内核映射，内核则不需要使用_mapcount来记录多少个pte映射了该page,而用该字段来记录本page内被多少个对象使用(slub时已经指定对象大小了),就用union中的inuse了
		 *
		 * 内核用page_mapped() 来确定是否被map
		 *
		 * page_mapcount 函数接收页描述符地址，返回值为 _mapcount + 1（这样，如果返回值为 1，表明是某个进程的用户态地址控件存放的一个非共享页）。
		 */
		atomic_t _mapcount;	/*  内存管理子系统中映射的页表项计数，
		                        用于表示页是否已经映射，还用于限制逆序映射搜索.

		                        表明共享该物理页面的页表项的数目,
		                        该计数器可用于快速检查该页面除所有者之外有多少个使用者在使用，初始值是 -1，每增加一个使用者，该计数器加 1
		                        
		                        取值-1时表示没有指向该页框的引用，             
		                        取值0时表示该页框不可共享                           
		                        取值大于0时表示该页框可共享表示有几个PTE引用
		              Count of ptes mapped in mms,
					 * to show when page is mapped
					 * & limit reverse map searches.
					 */
		/* slub: slab中已分配对象。如果等于slab中对象总数，即代表slab全满 */
		unsigned int inuse;	/* 用于slub分配器，表示slab中对象数目,SLUB: Nr of objects */
	};
	
	union {
	    struct {
		unsigned long private;		/*
                                     * 由映射私有:
                                     * 1.如果flags设置了PagePrivate,用于buffer_head，指向将page划分为更小单位的第一个buffer_head(一般是有4个buffer_head)
                                     *     buffer_head的关系看create_empty_buffers, link_dev_buffers.
                                     * 2.如果flags设置了PageSwapCache，则用于swp_entry_t
                                     * 3.如果flags设置了PG_buddy，则用于表示伙伴系统中的order(阶)
                                     * 4.PG_migratetype也存储在这里
		                             *
		                             *   Mapping-private opaque data:
					 	             * usually used for buffer_heads
						             * if PagePrivate set; used for
						             * swp_entry_t if PageSwapCache;
						             * indicates order in the buddy
						             * system if PG_buddy is set.
						             */
		struct address_space *mapping;	/* 
		                                   字段 mapping 用于区分匿名页面和基于文件映射的页面，
		                                   如果该字段的最低位被置位了，那么该字段包含的是指向anon_vma 结构（用于匿名页面）的指针；
		                                   否则，该字段包含指向inode->address_space 结构的指针（用于基于文件映射的页面）。
		                                 
		                                   mapping字段为空，则该页属于交换高速缓存,
		                                   如果最低位为0,则指向inode的address_space
		                                   如果页映射为匿名内存,最低位为1,而且该参数指向anon_vma对象,在__page_set_anon_rmap()中设置.
		                                   如果此页是匿名页，它的mapping变量会指向第一个访问此页的vma的anon_vma
		                 If low bit clear, points to
						 * inode address_space, or NULL.
						 * If page mapped as anonymous
						 * memory, low bit is set, and
						 * it points to anon_vma object:
						 * see PAGE_MAPPING_ANON below.
						 */
	    };
										   
#if NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS
	    spinlock_t ptl;
#endif
        /* slub:所属缓冲区 kmem_cache 结构的指针 */
	    struct kmem_cache *slab;	/* 用于SLUB分配器，指向slab指针. SLUB: Pointer to slab */
	    struct page *first_page;	/* 用于复合页的尾页,指向页首. Compound tail pages */
	};
	union {
		/*
		 * 对于file mapped page，page->index表示的是映射到文件内的偏移（Byte为单位），
		 * 而vma->vm_pgoff表示的是该VMA映射到文件内的偏移（page为单位），
		 * 因此，通过vma->vm_pgoff和page->index可以得到该page frame在VMA中的地址偏移，
		 * 再加上vma->vm_start就可以得到该page frame的虚拟地址。
		 * 有了虚拟地址和地址空间（vma->vm_mm），我们就可以通过各级页表找到该page对应的pte entry。
		 * 可以看vma_address()函数
		 */
		pgoff_t index;		/* 在__page_set_anon_rmap()中设置
		                     * 在映射文件内或者匿名映射到起始映射内存处的偏移(页面[4k]为单位), 
		                     *
		                     * 从函数find_get_pages_contig看,如果是一批连续的page，用在同一次分配时，所有的page的index是一样的。
		                     * 
		                     * 作为不同的含义被几种内核成分使用。例如，它在页磁盘映像或匿名区中标识存放在页框中的数据的位置，或者它存放一个换出页标识符
                             * 当此页作为映射页(文件映射)时，保存这块页的数据在整个文件数据中以页为大小的偏移量
                             * 当此页作为匿名页时，保存此页在线性区vma内的页索引或者是页的线性地址/PAGE_SIZE。
                             * 对于匿名页的page->index表示的是page在vma中的虚拟页框号(此页的开始线性地址 >> PAGE_SIZE)。共享匿名页的产生应该只有在fork，clone完成并写时复制之前。
                             *
		                     * Our offset within mapping. 
		                     */
	    /* slub:slab中第一个空闲对象的指针 */
		void *freelist;		/* SLUB: freelist req. slab lock */
	};
	struct list_head lru;		/* 1.链接到zone->active_list,zone->inactive_list
	                               2.链接到zone->pageset->pcp[].list
	                               
	                               用于在各种列表上维护该页,以便将页按不同类别分组，
	                               1.如换出页的列表,2.列如由zone->lru_lock保护active_list!. 

	                               3.在slab系统中,通过已分配的对象地址找到page对象,然后通过page对象分别找到 所属的kmem_cache和slab
	                                                     page->lru->next= kmem_cache.
	                                                    page->lru->prev = slab,在slab_map_pages中设置
	                                              
	                               4.compound page中page->lru->next= free_compound_page
	                                                page->lru->prev= order
	                             
	                               5.释放出来到buddy system的空闲页, 放到zone->free_area[order].free_list[migratetype]
	                                                
	                               Pageout list, eg. active_list
					             * protected by zone->lru_lock !
					             */
	/*
	 * On machines where all RAM is mapped into kernel address space,
	 * we can simply calculate the virtual address. On machines with
	 * highmem some memory is mapped into kernel virtual memory
	 * dynamically, so we need a place to store that address.
	 * Note that this field could be 16 bits on x86 ... ;)
	 *
	 * Architectures with slow multiplication can define
	 * WANT_PAGE_VIRTUAL in asm/page.h
	 */
#if defined(WANT_PAGE_VIRTUAL)
	void *virtual;			/* x86,arm中没有使用, 用于高端内存区域中的页,换言之，即无法直接映射到内核中的页。
	                           virtual用于存储改页的虚拟地址。
	                     Kernel virtual address (NULL if
					   not kmapped, ie. highmem) */
#endif /* WANT_PAGE_VIRTUAL */
};

/*
 * This struct defines a memory VMM memory area. There is one of these
 * per VM-area/task.  A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 *
 * 只有用户态的虚拟地址才会用这个结构？
 * 内核态的虚拟地址空间不用这个结构？
 */
struct vm_area_struct {
	struct mm_struct * vm_mm;	/* The address space we belong to. */
	unsigned long vm_start;		/* Our start address within vm_mm. */
	unsigned long vm_end;		/* The first byte after our end address
					   within vm_mm. */

	/* linked list of VM areas per task, sorted by address */
	struct vm_area_struct *vm_next;

	pgprot_t vm_page_prot;		/* Access permissions of this VMA. */
	/* 线性区标志
     * 读写可执行权限会复制到页表项中，由分页单元去检查这几个权限
     */
	unsigned long vm_flags;		/* Flags, listed below. */

    //链接到mm_struct->mm_rb
	struct rb_node vm_rb;

	/*
	 * For areas with an address space and backing store,
	 * linkage into the address_space->i_mmap prio tree, or
	 * linkage to the list of like vmas hanging off its node, or
	 * linkage of vma in the address_space->i_mmap_nonlinear list.
	 * 
	 * shared会链接到address_space->i_mmap优先树，或者链接到连接到悬挂在优先树之外、类似的
	 * 的一组虚拟内存区域的链表，
	 * 或链接到address_space->i_mmap_nonlinear链表中的vma
	 *
	 * 当一个文件的区间被好几个进程同时映射时,
	 *
	 * 链接到反向映射所使用的数据结构，用于文件映射的线性区，
	 * 主要用于文件页的反向映射
	 *
	 */
	union {

	    /*
	     * 这个结构的操作看__remove_shared_vm_struct()
	     */
		struct {
			/* vm_file不为空时(也就是有对应的磁盘文件时),  并且有vma有VM_NONLINEAR(非线性映射)属性时  ,这个成员链接到vma->vm_file->f_mapping->i_mapping_nonlinear链表
			 *
			 * 非线性map和线性map都会用到list
			 * 在vma_nonlinear_insert()操作
		     */
			struct list_head list; 
			/*
			 * 在vma_prio_tree_add中操作
			 */
			void *parent;	/* aligns with prio_tree_node parent */
			struct vm_area_struct *head; //当多个vma对应相同的page时，用这个head链接其各个不同的vma
		} vm_set; /* address_space->i_mmap */

        //看vma_prio_tree_insert()，vma_prio_tree_insert()， vma_prio_tree_add()
		struct raw_prio_tree_node prio_tree_node; /* 用于有file的非匿名映射， mmap线性映射时,链接到vma->vm_file->f_mapping->i_mmap */
	} shared;

	/*
	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
	 * list, after a COW of one of the file pages.	A MAP_SHARED vma
	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
	 * or brk vma (with NULL file) can only be in an anon_vma list.
	 *
	 *
	 * 指向匿名线性区链表头的指针，这个链表会将此mm_struct中的所有匿名线性区链接起来
     * 匿名的MAP_PRIVATE、堆和栈的vma都会存在于这个anon_vma_chain链表中
     * 如果mm_struct的anon_vma为空，那么其anon_vma_chain也一定为空
	 *
	 */
	struct list_head anon_vma_node;	/* anon_vma->head 连接到vm_area_struct->anon_vma_node->head,  Serialized by anon_vma->lock */
	/* 
	 * 在__page_set_anon_rmap()中关联到page->mapping上,
	 * 指向anon_vma数据结构的指针，对于匿名线性区，此为重要结构
	 *
	 * 在anon_vma_prepare中分配
	 */
	struct anon_vma *anon_vma;	/* 本vm_area_struct的anon_vma,用于没有file对象的匿名映射。      只在anon_vma_prepare()中分配和设置这个结构, Serialized by page_table_lock */

	/* Function pointers to deal with this struct.
	 * 在文件file mapping时会设置这个，如果是anonymous mapping,则不会设置这个。
	 *
	 *
	 * ext2:mmap=generic_file_mmap
	 * ext2: generic_file_mmap中设定 vm_area_struct->vm_ops=generic_file_vm_ops
	 * 另外有下面几个vm_operations_struct对象
	 * dma_region_vm_ops
     * shmem_vm_ops 在shmem_zero_setup中设置
     * kvm_vm_vm_ops
	 */
	struct vm_operations_struct * vm_ops;

	/* Information about our backing store: */
	/* 如果此vma用于映射文件，那么保存的是在映射文件中的偏移量。
	   如果是匿名线性区，它等于0或者vma开始地址对应的虚拟页框号(vm_start >> PAGE_SIZE)，这个虚拟页框号用于vma向下增长时反向映射的计算(栈) */
	unsigned long vm_pgoff;		/*   Offset (within vm_file) in PAGE_SIZE
					   units, *not* PAGE_CACHE_SIZE */
					   	
	/* 指向映射文件的文件对象，也可能指向建立shmem共享内存中返回的struct file，
	   如果是匿名线性区，此值为NULL或者一个匿名文件(这个匿名文件跟swap有关?待看) */
	struct file * vm_file;		/* 文件映射时对应的磁盘文件,File we map to (can be NULL). */
	void * vm_private_data;		/* was vm_pte (shared mem) */
	unsigned long vm_truncate_count;/* truncate_count or restart_addr */

#ifndef CONFIG_MMU
	atomic_t vm_usage;		/* refcount (VMAs shared if !MMU) */
#endif
#ifdef CONFIG_NUMA
	struct mempolicy *vm_policy;	/* NUMA policy for the VMA */
#endif
};

/* 内存描述符，每个进程都会有一个，除了内核线程(使用被调度出去的进程的mm_struct)和轻量级进程(使用父进程的mm_struct) */
/* 所有的内存描述符存放在一个双向链表中，链表中第一个元素是init_mm，它是初始化阶段进程0的内存描述符 */
struct mm_struct {
	/* 指向线性区对象的链表头，链表是经过排序的，按线性地址升序排列，里面包括了匿名映射线性区和文件映射线性区 */
	struct vm_area_struct * mmap;		/* list of VMAs */
	struct rb_root mm_rb;
	struct vm_area_struct * mmap_cache;	/* last find_vma result */
	unsigned long (*get_unmapped_area) (struct file *filp,
				unsigned long addr, unsigned long len,
				unsigned long pgoff, unsigned long flags); /* 这个函数通常是arch_get_unmapped_area_topdown */
	
	void (*unmap_area) (struct mm_struct *mm, unsigned long addr); /* 这个函数通常是arch_unmap_area或者arch_unmap_area_topdown */
	/* 标识第一个分配的匿名线性区或文件内存映射的线性地址 */
	unsigned long mmap_base;		/* 1/TASK_SIZE 。 base of mmap area */
	unsigned long task_size;		/* size of task vm space */
	unsigned long cached_hole_size; 	/* if non-zero, the largest hole below free_area_cache */
	unsigned long free_area_cache;		/* first hole of size cached_hole_size or larger */
	/* 指向页全局目录,这个值是物理地址 */
	pgd_t * pgd;
	/* 次使用计数器，存放了共享此mm_struct的轻量级进程的个数，但所有的mm_users在mm_count的计算中只算作1 */
	atomic_t mm_users;			/* How many users with user space? */
	/* 主使用计数器，当mm_count递减时，系统会检查是否为0，为0则解除这个mm_struct */
	atomic_t mm_count;			/* How many references to "struct mm_struct" (users count as 1) */
	/* 线性区的个数，默认最多是65535个，系统管理员可以通过写/proc/sys/vm/max_map_count文件修改这个值 */
	int map_count;				/* number of VMAs */
	struct rw_semaphore mmap_sem;
	spinlock_t page_table_lock;		/* Protects page tables and some counters */

    //链接到系统中所有的mm_struct对象
	struct list_head mmlist;		/* List of maybe swapped mm's.	These are globally strung
						 * together off init_mm.mmlist, and are protected
						 * by mmlist_lock
						 */

	/* Special counters, in some configurations protected by the
	 * page_table_lock, in other configurations by being atomic.
	 */
	mm_counter_t _file_rss;
	mm_counter_t _anon_rss;
	/* 进程所拥有的最大页框数 */
	unsigned long hiwater_rss;	/* High-watermark of RSS usage */
	/* 进程线性区中的最大页数 */
	unsigned long hiwater_vm;	/* High-water virtual memory usage */

	unsigned long total_vm, locked_vm, shared_vm, exec_vm;
	unsigned long stack_vm, reserved_vm, def_flags, nr_ptes;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long start_brk, brk, start_stack; /* 用户态堆栈、堆起始地址 */
	unsigned long arg_start, arg_end, env_start, env_end;

	unsigned long saved_auxv[AT_VECTOR_SIZE]; /* for /proc/PID/auxv */

	cpumask_t cpu_vm_mask;

	/* Architecture-specific MM context */
	mm_context_t context;

	/* Swap token stuff */
	/*
	 * Last value of global fault stamp as seen by this process.
	 * In other words, this value gives an indication of how long
	 * it has been since this task got the token.
	 * Look at mm/thrash.c
	 */
	unsigned int faultstamp;
	/*
	 * 上次获取swap_token(swap_token_mm)时的global_faults的值
	 * token_priority是一个与交换令牌相关的调度优先级，用于控制交换令牌的访问。
	 */
	unsigned int token_priority;
	/*
	 * 表示进程等待swap_token的时间间隔的长度
	 */
	unsigned int last_interval;

	unsigned long flags; /* Must use atomic bitops to access the bits */

	/* coredumping support 
	 * 正在把进程地址空间的内容卸载到转储文件中的轻量级进程的数量
	 */
	int core_waiters;
	struct completion *core_startup_done, core_done;

	/* aio bits */
	rwlock_t		ioctx_list_lock;
	//异步上下文链表
	struct kioctx		*ioctx_list;
};

#endif /* _LINUX_MM_TYPES_H */
