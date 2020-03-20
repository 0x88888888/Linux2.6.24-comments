/*
 * linux/mm/slab.c
 * Written by Mark Hemment, 1996/97.
 * (markhe@nextd.demon.co.uk)
 *
 * kmem_cache_destroy() + some cleanup - 1999 Andrea Arcangeli
 *
 * Major cleanup, different bufctl logic, per-cpu arrays
 *	(c) 2000 Manfred Spraul
 *
 * Cleanup, make the head arrays unconditional, preparation for NUMA
 * 	(c) 2002 Manfred Spraul
 *
 * An implementation of the Slab Allocator as described in outline in;
 *	UNIX Internals: The New Frontiers by Uresh Vahalia
 *	Pub: Prentice Hall	ISBN 0-13-101908-2
 * or with a little more detail in;
 *	The Slab Allocator: An Object-Caching Kernel Memory Allocator
 *	Jeff Bonwick (Sun Microsystems).
 *	Presented at: USENIX Summer 1994 Technical Conference
 *
 * The memory is organized in caches, one cache for each object type.
 * (e.g. inode_cache, dentry_cache, buffer_head, vm_area_struct)
 * Each cache consists out of many slabs (they are small (usually one
 * page long) and always contiguous), and each slab contains multiple
 * initialized objects.
 *
 * This means, that your constructor is used only for newly allocated
 * slabs and you must pass objects with the same initializations to
 * kmem_cache_free.
 *
 * Each cache can only support one memory type (GFP_DMA, GFP_HIGHMEM,
 * normal). If you need a special memory type, then must create a new
 * cache for that memory type.
 *
 * In order to reduce fragmentation, the slabs are sorted in 3 groups:
 *   full slabs with 0 free objects
 *   partial slabs
 *   empty slabs with no allocated objects
 *
 * If partial slabs exist, then new allocations come from these slabs,
 * otherwise from empty slabs or new slabs are allocated.
 *
 * kmem_cache_destroy() CAN CRASH if you try to allocate from the cache
 * during kmem_cache_destroy(). The caller must prevent concurrent allocs.
 *
 * Each cache has a short per-cpu head array, most allocs
 * and frees go into that array, and if that array overflows, then 1/2
 * of the entries in the array are given back into the global cache.
 * The head array is strictly LIFO and should improve the cache hit rates.
 * On SMP, it additionally reduces the spinlock operations.
 *
 * The c_cpuarray may not be read with enabled local interrupts -
 * it's changed with a smp_call_function().
 *
 * SMP synchronization:
 *  constructors and destructors are called without any locking.
 *  Several members in struct kmem_cache and struct slab never change, they
 *	are accessed without any locking.
 *  The per-cpu arrays are never accessed from the wrong cpu, no locking,
 *  	and local interrupts are disabled so slab code is preempt-safe.
 *  The non-constant members are protected with a per-cache irq spinlock.
 *
 * Many thanks to Mark Hemment, who wrote another per-cpu slab patch
 * in 2000 - many ideas in the current implementation are derived from
 * his patch.
 *
 * Further notes from the original documentation:
 *
 * 11 April '97.  Started multi-threading - markhe
 *	The global cache-chain is protected by the mutex 'cache_chain_mutex'.
 *	The sem is only needed when accessing/extending the cache-chain, which
 *	can never happen inside an interrupt (kmem_cache_create(),
 *	kmem_cache_shrink() and kmem_cache_reap()).
 *
 *	At present, each engine can be growing a cache.  This should be blocked.
 *
 * 15 March 2005. NUMA slab allocator.
 *	Shai Fultheim <shai@scalex86.org>.
 *	Shobhit Dayal <shobhit@calsoftinc.com>
 *	Alok N Kataria <alokk@calsoftinc.com>
 *	Christoph Lameter <christoph@lameter.com>
 *
 *	Modified the slab allocator to be node aware on NUMA systems.
 *	Each node has its own list of partial, free and full slabs.
 *	All object allocations for a node occur from node specific slab lists.
 */

#include	<linux/slab.h>
#include	<linux/mm.h>
#include	<linux/poison.h>
#include	<linux/swap.h>
#include	<linux/cache.h>
#include	<linux/interrupt.h>
#include	<linux/init.h>
#include	<linux/compiler.h>
#include	<linux/cpuset.h>
#include	<linux/seq_file.h>
#include	<linux/notifier.h>
#include	<linux/kallsyms.h>
#include	<linux/cpu.h>
#include	<linux/sysctl.h>
#include	<linux/module.h>
#include	<linux/rcupdate.h>
#include	<linux/string.h>
#include	<linux/uaccess.h>
#include	<linux/nodemask.h>
#include	<linux/mempolicy.h>
#include	<linux/mutex.h>
#include	<linux/fault-inject.h>
#include	<linux/rtmutex.h>
#include	<linux/reciprocal_div.h>

#include	<asm/cacheflush.h>
#include	<asm/tlbflush.h>
#include	<asm/page.h>

/*
 * DEBUG	- 1 for kmem_cache_create() to honour; SLAB_RED_ZONE & SLAB_POISON.
 *		  0 for faster, smaller code (especially in the critical paths).
 *
 * STATS	- 1 to collect stats for /proc/slabinfo.
 *		  0 for faster, smaller code (especially in the critical paths).
 *
 * FORCED_DEBUG	- 1 enables SLAB_RED_ZONE and SLAB_POISON (if possible)
 */

#ifdef CONFIG_DEBUG_SLAB
#define	DEBUG		1
#define	STATS		1
#define	FORCED_DEBUG	1
#else
#define	DEBUG		0
#define	STATS		0
#define	FORCED_DEBUG	0
#endif

/* Shouldn't this be in a header file somewhere? */
#define	BYTES_PER_WORD		sizeof(void *)
#define	REDZONE_ALIGN		max(BYTES_PER_WORD, __alignof__(unsigned long long))

#ifndef cache_line_size
#define cache_line_size()	L1_CACHE_BYTES  /* 32 */
#endif

#ifndef ARCH_KMALLOC_MINALIGN
/*
 * Enforce a minimum alignment for the kmalloc caches.
 * Usually, the kmalloc caches are cache_line_size() aligned, except when
 * DEBUG and FORCED_DEBUG are enabled, then they are BYTES_PER_WORD aligned.
 * Some archs want to perform DMA into kmalloc caches and need a guaranteed
 * alignment larger than the alignment of a 64-bit integer.
 * ARCH_KMALLOC_MINALIGN allows that.
 * Note that increasing this value may disable some debug features.
 */
#define ARCH_KMALLOC_MINALIGN __alignof__(unsigned long long)
#endif

#ifndef ARCH_SLAB_MINALIGN
/*
 * Enforce a minimum alignment for all caches.
 * Intended for archs that get misalignment faults even for BYTES_PER_WORD
 * aligned buffers. Includes ARCH_KMALLOC_MINALIGN.
 * If possible: Do not enable this flag for CONFIG_DEBUG_SLAB, it disables
 * some debug features.
 */
#define ARCH_SLAB_MINALIGN 0
#endif

#ifndef ARCH_KMALLOC_FLAGS
#define ARCH_KMALLOC_FLAGS SLAB_HWCACHE_ALIGN
#endif

/* Legal flag mask for kmem_cache_create(). */
#if DEBUG
# define CREATE_MASK	(SLAB_RED_ZONE | \
			 SLAB_POISON | SLAB_HWCACHE_ALIGN | \
			 SLAB_CACHE_DMA | \
			 SLAB_STORE_USER | \
			 SLAB_RECLAIM_ACCOUNT | SLAB_PANIC | \
			 SLAB_DESTROY_BY_RCU | SLAB_MEM_SPREAD)
#else
# define CREATE_MASK	(SLAB_HWCACHE_ALIGN | \
			 SLAB_CACHE_DMA | \
			 SLAB_RECLAIM_ACCOUNT | SLAB_PANIC | \
			 SLAB_DESTROY_BY_RCU | SLAB_MEM_SPREAD)
#endif

/*
 * kmem_bufctl_t:
 *
 * Bufctl's are used for linking objs within a slab
 * linked offsets.
 *
 * This implementation relies on "struct page" for locating the cache &
 * slab an object belongs to.
 *
 * This allows the bufctl structure to be small (one int), but limits
 * the number of objects a slab (not a cache) can contain when off-slab
 * bufctls are used. The limit is the size of the largest general cache
 * that does not use off-slab slabs.
 *
 * For 32bit archs with 4 kB pages, is this 56.
 * This is not serious, as it is only for large objects, when it is unwise
 * to have too many per slab.
 * Note: This limit can be raised by introducing a general cache whose size
 * is less than 512 (PAGE_SIZE<<3), but greater than 256.
 *
 */
  
/* 每个slab头(管理数据)之后都是一个数组，数组项的数目与slab中对象的数目相同。
   内核利用该数组来查找下一个空闲对象的位置。数组项的数据类型为kmem_bufctl_t 
 */
typedef unsigned int kmem_bufctl_t;
#define BUFCTL_END	(((kmem_bufctl_t)(~0U))-0)
#define BUFCTL_FREE	(((kmem_bufctl_t)(~0U))-1)
#define	BUFCTL_ACTIVE	(((kmem_bufctl_t)(~0U))-2)
#define	SLAB_LIMIT	(((kmem_bufctl_t)(~0U))-3)

/*
 * struct slab
 *
 * Manages the objs in a slab. Placed either at the beginning of mem allocated
 * for a slab, or allocated from an general cache.
 * Slabs are chained into three list: fully used, partial, fully free slabs.
 */
struct slab {
	struct list_head list;   // 用于将slab链入kmem_list3的链表
	unsigned long colouroff;  // Slab中第一个对象的偏移 
	void *s_mem;		/* 指向slab中的第一个对象 including colour offset */
	unsigned int inuse;	/* 已分配出去的对象, num of objs active in slab */
	kmem_bufctl_t free;  // 下一个空闲对象的下标
	unsigned short nodeid;  // 节点标识号
};

/*
 * struct slab_rcu
 *
 * slab_destroy on a SLAB_DESTROY_BY_RCU cache uses this structure to
 * arrange for kmem_freepages to be called via RCU.  This is useful if
 * we need to approach a kernel structure obliquely, from its address
 * obtained without the usual locking.  We can lock the structure to
 * stabilize it and check it's still at the given address, only if we
 * can be sure that the memory has not been meanwhile reused for some
 * other kind of object (which our subsystem's lock might corrupt).
 *
 * rcu_read_lock before reading the address, then rcu_read_unlock after
 * taking the spinlock within the structure expected at that address.
 *
 * We assume struct slab_rcu can overlay struct slab when destroying.
 */
struct slab_rcu {
	struct rcu_head head;
	struct kmem_cache *cachep;
	void *addr;
};

/*
 * struct array_cache
 *
 * Purpose:
 * - LIFO ordering, to hand out cache-warm objects from _alloc
 * - reduce the number of linked list operations
 * - reduce spinlock operations
 *
 * The limit is stored in the per-cpu structure to reduce the data cache
 * footprint.
 *
 struct kmem_cache中定义了一个struct array_cache指针数组，
 数组的元素个数对应了系统的CPU数，和伙伴系统中的每CPU页框高速缓存类似，
 该结构用来描述每个CPU的本地高速缓存，它可以减少SMP系统中对于自旋锁的竞争。
 在每个array_cache的末端都用一个指针数组记录了slab中的空闲对象，
 分配对象时，采用LIFO方式，也就是将该数组中的最后一个索引对应的对象分配出去，
 以保证该对象还驻留在高速缓存中的可能性。
 实际上，每次分配内存都是直接与本地CPU高速缓存进行交互，
 只有当其空闲内存不足时，才会从kmem_list中的slab中引入一部分对象到本地高速缓存中，
 而kmem_list中的空闲对象也不足了，那么就要从伙伴系统中引入新的页来建立新的slab了，
 这一点也和伙伴系统的每CPU页框高速缓存很类似

 看alloc_arraycache函数,
 进入kmem_cache->array->entry[]的都已经是被回收的对象了
 
 */
struct array_cache {
	unsigned int avail; /* 当前空闲对象的位置，取值时objp = ac->entry[--ac->avail]，可用的个数，也是一个索引，每次都是从后往前区 */
	unsigned int limit; /* 空闲对象上限 limit和batchcount与kmem_cache中的一样 */
	unsigned int batchcount; // 每次需要申请对象数量或释放的对象数量，和kmem_cache相同
	unsigned int touched; /* 从缓存移除一个对象时,touched-=1，这使得内核能够确认在缓存上一次被shrink之后是否被访问过 */
	spinlock_t lock;
	void *entry[];	/* 指向可用的slab对象指针数组,指针的值也是在各个的slab中
			 * Must have this definition in here for the proper
			 * alignment of array_cache. Also simplifies accessing
			 * the entries.
			 */
};

/*
 * bootstrap: The caches do not work without cpuarrays anymore, but the
 * cpuarrays are allocated from the generic caches...
 */
#define BOOT_CPUCACHE_ENTRIES	1
struct arraycache_init {
	struct array_cache cache;
	void *entries[BOOT_CPUCACHE_ENTRIES];
};

/*
 * The slab lists for all objects.
 *  用于管理slab链表表头,放在kmem_cache->nodelist[]数组中
 */
struct kmem_list3 {
	struct list_head slabs_partial;	/* 部分空闲链表 partial list first, better asm code */
	struct list_head slabs_full;    /* 全满 */
	struct list_head slabs_free;    /* 全空 */
	unsigned long free_objects;     /* slabs_partial和slabs_free中所有slab中空闲对象的数量 */
	unsigned int free_limit;        /* 指定了所有slab上容许未使用对象的最大数目 */
	unsigned int colour_next;	/* 下一个slab的颜色, Per-node cache coloring */
	spinlock_t list_lock;
	struct array_cache *shared;	/* 有各个节点内部共享或者源自其他节点，与NUMA系统相关。 shared per node */
	struct array_cache **alien;	/* on other nodes */
	unsigned long next_reap;	/* 内核在两次shrink缓存之间，必须经过的时间间隔。其想法是防止有频繁的
	                               shrink缓存和增长操作而降低系统性能，这种操作可能在某些系统负荷下发生。
	                               该技术只有在NUMA系统中使用。
	                               updated without locking */
	int free_touched;		/* 表示缓存是否活动的，在从缓存获取一个对象时，内核将该变量的值设置为1.
	                           在缓存收缩时，该值重置为0。但内核只有在free_touched预先设置为0时，才会shrink  缓存。
	                           因为1表示内核的另一部分刚从该缓存获取对象，此时shrink是不合适的。
	                           该变量将影响到整个缓存，与array_cache结构的touched成员不同
	                           updated without locking */
};

/*
 * Need this for bootstrapping a per node allocator.
 */
#define NUM_INIT_LISTS (2 * MAX_NUMNODES + 1)
/* */
struct kmem_list3 __initdata initkmem_list3[NUM_INIT_LISTS];
#define	CACHE_CACHE 0
#define	SIZE_AC 1
#define	SIZE_L3 (1 + MAX_NUMNODES)

static int drain_freelist(struct kmem_cache *cache,
			struct kmem_list3 *l3, int tofree);
static void free_block(struct kmem_cache *cachep, void **objpp, int len,
			int node);
static int enable_cpucache(struct kmem_cache *cachep);
static void cache_reap(struct work_struct *unused);

/*
 * This function must be completely optimized away if a constant is passed to
 * it.  Mostly the same as what is in linux/slab.h except it returns an index.
 */
static __always_inline int index_of(const size_t size)
{
	extern void __bad_size(void);

	if (__builtin_constant_p(size)) {
		int i = 0;

#define CACHE(x) \
	if (size <=x) \
		return i; \
	else \
		i++;
#include "linux/kmalloc_sizes.h"
#undef CACHE
		__bad_size();
	} else
		__bad_size();
	return 0;
}

static int slab_early_init = 1;

/* malloc_sizes[]中的索引 */
#define INDEX_AC index_of(sizeof(struct arraycache_init))  /* array_cache */
#define INDEX_L3 index_of(sizeof(struct kmem_list3))

static void kmem_list3_init(struct kmem_list3 *parent)
{
	INIT_LIST_HEAD(&parent->slabs_full);
	INIT_LIST_HEAD(&parent->slabs_partial);
	INIT_LIST_HEAD(&parent->slabs_free);
	parent->shared = NULL;
	parent->alien = NULL;
	parent->colour_next = 0;
	spin_lock_init(&parent->list_lock);
	parent->free_objects = 0;
	parent->free_touched = 0;
}

#define MAKE_LIST(cachep, listp, slab, nodeid)				\
	do {								\
		INIT_LIST_HEAD(listp);					\
		list_splice(&(cachep->nodelists[nodeid]->slab), listp);	\
	} while (0)

#define	MAKE_ALL_LISTS(cachep, ptr, nodeid)				\
	do {								\
	MAKE_LIST((cachep), (&(ptr)->slabs_full), slabs_full, nodeid);	\
	MAKE_LIST((cachep), (&(ptr)->slabs_partial), slabs_partial, nodeid); \
	MAKE_LIST((cachep), (&(ptr)->slabs_free), slabs_free, nodeid);	\
	} while (0)

/*
 * struct kmem_cache
 *
 * manages a cache.
 *
 * 在实际开始分配内存时，每个CPU都从kmem_cache结构体中的array中获取需要的内存，
 * 如果这里没有内存(用光或第一次用，第一次都是没有内存的需从buddy获取)，需要从buddy获取，
 * 从buddy获取的方式是通过slab三链的成员nodelists(slab三链这个名字是发现某个文章中这么叫的，
 * 所谓slab三链，是指全空、半空、全满三种slab链表)从buddy获取到物理页，
 * 然后把相关的物理页地址再传给array，
 * 可以看到在kmem_cache结构中array是每个CPU都有一个的(NR_CPUS代表CPU个数)，
 * 之所以有这种机制是因为如果都是通过slab三链获取物理页，
 * 那么在多CPU的情况下就会出现多个CPU抢占slab自旋锁的情况，这样会导致效率比较低，
 * 发没发现，这个array的机制和伙伴系统buddy的冷热页框机制很像
 */

struct kmem_cache {
/* 1) per-cpu data, touched during every alloc/free 
      per-cpu数据，在每次分配/释放的时候都会先访问这个数组s
 */
	struct array_cache *array[NR_CPUS];
/* 2) Cache tunables. Protected by cache_chain_mutex 
    可调整的缓存参数,有cache_chain_mutex保护
 */
    //本地高速缓存换入换出的批对象数量
	unsigned int batchcount; /* array中没有空闲对象时，每次为array分配的对象数目 */
	// 本地高速缓存中空闲对象的最大数量
	unsigned int limit;/* array中允许的最大对象数目，超出后会将batchcount个对象返回给slab。如果超出该值,内核会将batchcount个对象返回slab(如果接下来内核缩减缓存，则释放的内存从slab返回到伙伴系统) */
	unsigned int shared; /* 是否存在共享CPU高速缓存 */
 
	unsigned int buffer_size; /* 指定了缓存中管理对象的大小,对象长度+填充字节 */
	u32 reciprocal_buffer_size; // buff_size的倒数值
	
/* 3) touched by every alloc & free from the backend */

	unsigned int flags;		/* 如果管理结构存储在slab外部,就职位CFLGS_OFF_SLAB ,constant flags */
	unsigned int num;		/* 每个slab中对象的最大数量 # of objs per slab */

/* 4) cache_grow/shrink */
	/* order of pgs per slab (2^n) */
	unsigned int gfporder;   // 一个slab所包含的连续页框数的对数

	/* force GFP flags, e.g. GFP_DMA */
	gfp_t gfpflags;          // 与伙伴关系系统交互时提供的分配标识

	size_t colour;			/* 颜色个数 cache colouring range */
	unsigned int colour_off;	/*着色偏移量 colour offset */
	struct kmem_cache *slabp_cache; /* 如果slab头部的管理数据存储在slab外部，则slabp_cache指向分配所需内存的一般性缓存.
	                                  如果slab头部在slab上，则slabp_cache为NULL */
	unsigned int slab_size;     // slab管理区大小, 包含slab对象和kmem_buffctl_t数组
	unsigned int dflags;		/* 动态标识 dynamic flags */

	/* 每个对象创建时，调用该构造函数。constructor func */
	void (*ctor)(struct kmem_cache *, void *);

/* 5) cache creation/removal */
	const char *name;
/* 所有的kmem_cache变量都保存在全局变量cache_chain上 */
	struct list_head next;

/* 6) statistics 统计量 */
#if STATS
	unsigned long num_active;
	unsigned long num_allocations;
	unsigned long high_mark;
	unsigned long grown;
	unsigned long reaped;
	unsigned long errors;
	unsigned long max_freeable;
	unsigned long node_allocs;
	unsigned long node_frees;
	unsigned long node_overflow;
	atomic_t allochit;
	atomic_t allocmiss;
	atomic_t freehit;
	atomic_t freemiss;
#endif
#if DEBUG
	/*
	 * If debugging is enabled, then the allocator can add additional
	 * fields and/or padding to every object. buffer_size contains the total
	 * object size including these internal fields, the following two
	 * variables contain the offset to the user object and its size.
	 */
	int obj_offset;
	int obj_size; /* 缓存中对象的长度,包括用于对齐目的的所有填充的字节 */
#endif
	/*
	 * We put nodelists[] at the end of kmem_cache, because we want to size
	 * this array to nr_node_ids slots instead of MAX_NUMNODES
	 * (see kmem_cache_init())
	 * We still use [MAX_NUMNODES] and not [1] or [0] because cache_cache
	 * is statically defined, so we reserve the max number of nodes.
	 *
	 * 每个元素对应一个可能的物理内存节点,元素为kmem_list3实例
	 * 用于组织该高速缓存中的slab
	 */
	struct kmem_list3 *nodelists[MAX_NUMNODES];
	/*
	 * Do not add fields after nodelists[]
	 */
};

/* slab管理数据在slab外部  */
#define CFLGS_OFF_SLAB		(0x80000000UL)
#define	OFF_SLAB(x)	((x)->flags & CFLGS_OFF_SLAB)

#define BATCHREFILL_LIMIT	16
/*
 * Optimization question: fewer reaps means less probability for unnessary
 * cpucache drain/refill cycles.
 *
 * OTOH the cpuarrays can contain lots of objects,
 * which could lock up otherwise freeable slabs.
 */
#define REAPTIMEOUT_CPUC	(2*HZ)
#define REAPTIMEOUT_LIST3	(4*HZ)

#if STATS
#define	STATS_INC_ACTIVE(x)	((x)->num_active++)
#define	STATS_DEC_ACTIVE(x)	((x)->num_active--)
#define	STATS_INC_ALLOCED(x)	((x)->num_allocations++)
#define	STATS_INC_GROWN(x)	((x)->grown++)
#define	STATS_ADD_REAPED(x,y)	((x)->reaped += (y))
#define	STATS_SET_HIGH(x)						\
	do {								\
		if ((x)->num_active > (x)->high_mark)			\
			(x)->high_mark = (x)->num_active;		\
	} while (0)
#define	STATS_INC_ERR(x)	((x)->errors++)
#define	STATS_INC_NODEALLOCS(x)	((x)->node_allocs++)
#define	STATS_INC_NODEFREES(x)	((x)->node_frees++)
#define STATS_INC_ACOVERFLOW(x)   ((x)->node_overflow++)
#define	STATS_SET_FREEABLE(x, i)					\
	do {								\
		if ((x)->max_freeable < i)				\
			(x)->max_freeable = i;				\
	} while (0)
#define STATS_INC_ALLOCHIT(x)	atomic_inc(&(x)->allochit)
#define STATS_INC_ALLOCMISS(x)	atomic_inc(&(x)->allocmiss)
#define STATS_INC_FREEHIT(x)	atomic_inc(&(x)->freehit)
#define STATS_INC_FREEMISS(x)	atomic_inc(&(x)->freemiss)
#else
#define	STATS_INC_ACTIVE(x)	do { } while (0)
#define	STATS_DEC_ACTIVE(x)	do { } while (0)
#define	STATS_INC_ALLOCED(x)	do { } while (0)
#define	STATS_INC_GROWN(x)	do { } while (0)
#define	STATS_ADD_REAPED(x,y)	do { } while (0)
#define	STATS_SET_HIGH(x)	do { } while (0)
#define	STATS_INC_ERR(x)	do { } while (0)
#define	STATS_INC_NODEALLOCS(x)	do { } while (0)
#define	STATS_INC_NODEFREES(x)	do { } while (0)
#define STATS_INC_ACOVERFLOW(x)   do { } while (0)
#define	STATS_SET_FREEABLE(x, i) do { } while (0)
#define STATS_INC_ALLOCHIT(x)	do { } while (0)
#define STATS_INC_ALLOCMISS(x)	do { } while (0)
#define STATS_INC_FREEHIT(x)	do { } while (0)
#define STATS_INC_FREEMISS(x)	do { } while (0)
#endif

#if DEBUG

/*
 * memory layout of objects:
 * 0		: objp
 * 0 .. cachep->obj_offset - BYTES_PER_WORD - 1: padding. This ensures that
 * 		the end of an object is aligned with the end of the real
 * 		allocation. Catches writes behind the end of the allocation.
 * cachep->obj_offset - BYTES_PER_WORD .. cachep->obj_offset - 1:
 * 		redzone word.
 * cachep->obj_offset: The real object.
 * cachep->buffer_size - 2* BYTES_PER_WORD: redzone word [BYTES_PER_WORD long]
 * cachep->buffer_size - 1* BYTES_PER_WORD: last caller address
 *					[BYTES_PER_WORD long]
 */
static int obj_offset(struct kmem_cache *cachep)
{
	return cachep->obj_offset;
}

static int obj_size(struct kmem_cache *cachep)
{
	return cachep->obj_size;
}

static unsigned long long *dbg_redzone1(struct kmem_cache *cachep, void *objp)
{
	BUG_ON(!(cachep->flags & SLAB_RED_ZONE));
	return (unsigned long long*) (objp + obj_offset(cachep) -
				      sizeof(unsigned long long));
}

static unsigned long long *dbg_redzone2(struct kmem_cache *cachep, void *objp)
{
	BUG_ON(!(cachep->flags & SLAB_RED_ZONE));
	if (cachep->flags & SLAB_STORE_USER)
		return (unsigned long long *)(objp + cachep->buffer_size -
					      sizeof(unsigned long long) -
					      REDZONE_ALIGN);
	return (unsigned long long *) (objp + cachep->buffer_size -
				       sizeof(unsigned long long));
}

static void **dbg_userword(struct kmem_cache *cachep, void *objp)
{
	BUG_ON(!(cachep->flags & SLAB_STORE_USER));
	return (void **)(objp + cachep->buffer_size - BYTES_PER_WORD);
}

#else

#define obj_offset(x)			0
#define obj_size(cachep)		(cachep->buffer_size)
#define dbg_redzone1(cachep, objp)	({BUG(); (unsigned long long *)NULL;})
#define dbg_redzone2(cachep, objp)	({BUG(); (unsigned long long *)NULL;})
#define dbg_userword(cachep, objp)	({BUG(); (void **)NULL;})

#endif

/*
 * Do not go above this order unless 0 objects fit into the slab.
 */
#define	BREAK_GFP_ORDER_HI	1
#define	BREAK_GFP_ORDER_LO	0
static int slab_break_gfp_order = BREAK_GFP_ORDER_LO;

/*
 * Functions for storing/retrieving the cachep and or slab from the page
 * allocator.  These are used to find the slab an obj belongs to.  With kfree(),
 * these are used to find the cache which an obj belongs to.
 */
static inline void page_set_cache(struct page *page, struct kmem_cache *cache)
{
	page->lru.next = (struct list_head *)cache;
}

static inline struct kmem_cache *page_get_cache(struct page *page)
{
	page = compound_head(page);
	BUG_ON(!PageSlab(page));
	return (struct kmem_cache *)page->lru.next;
}

static inline void page_set_slab(struct page *page, struct slab *slab)
{
	page->lru.prev = (struct list_head *)slab;
}

static inline struct slab *page_get_slab(struct page *page)
{
	BUG_ON(!PageSlab(page));
	return (struct slab *)page->lru.prev;
}

static inline struct kmem_cache *virt_to_cache(const void *obj)
{
	struct page *page = virt_to_head_page(obj);
	return page_get_cache(page);
}

static inline struct slab *virt_to_slab(const void *obj)
{
	struct page *page = virt_to_head_page(obj);
	return page_get_slab(page);
}

static inline void *index_to_obj(struct kmem_cache *cache, struct slab *slab,
				 unsigned int idx)
{
	return slab->s_mem + cache->buffer_size * idx;
}

/*
 * We want to avoid an expensive divide : (offset / cache->buffer_size)
 *   Using the fact that buffer_size is a constant for a particular cache,
 *   we can replace (offset / cache->buffer_size) by
 *   reciprocal_divide(offset, cache->reciprocal_buffer_size)
 */
static inline unsigned int obj_to_index(const struct kmem_cache *cache,
					const struct slab *slab, void *obj)
{
	u32 offset = (obj - slab->s_mem);
	return reciprocal_divide(offset, cache->reciprocal_buffer_size);
}

/*
 * These are the default caches for kmalloc. Custom caches can have other sizes.
 *
 * malloc_sizes共21个成员,分别对应32,64,128,256,512,......4194304,0xffffffff的大小
 */
struct cache_sizes malloc_sizes[] = {
#define CACHE(x) { .cs_size = (x) },
/* CACHE宏定义cache_sizes兑现 */
#include <linux/kmalloc_sizes.h>
	CACHE(ULONG_MAX)
#undef CACHE
};
EXPORT_SYMBOL(malloc_sizes);

/* Must match cache_sizes above. Out of line to keep cache footprint low. */
struct cache_names {
	char *name;
	char *name_dma;
};

static struct cache_names __initdata cache_names[] = {
#define CACHE(x) { .name = "size-" #x, .name_dma = "size-" #x "(DMA)" },
#include <linux/kmalloc_sizes.h>
	{NULL,}
#undef CACHE
};

static struct arraycache_init initarray_cache __initdata =
    { {0, BOOT_CPUCACHE_ENTRIES, 1, 0} };
static struct arraycache_init initarray_generic =
    { {0, BOOT_CPUCACHE_ENTRIES, 1, 0} };

/* internal cache of cache description objs */
static struct kmem_cache cache_cache = {
	.batchcount = 1,
	.limit = BOOT_CPUCACHE_ENTRIES,
	.shared = 1,
	.buffer_size = sizeof(struct kmem_cache),
	.name = "kmem_cache",
};

#define BAD_ALIEN_MAGIC 0x01020304ul

#ifdef CONFIG_LOCKDEP

/*
 * Slab sometimes uses the kmalloc slabs to store the slab headers
 * for other slabs "off slab".
 * The locking for this is tricky in that it nests within the locks
 * of all other slabs in a few places; to deal with this special
 * locking we put on-slab caches into a separate lock-class.
 *
 * We set lock class for alien array caches which are up during init.
 * The lock annotation will be lost if all cpus of a node goes down and
 * then comes back up during hotplug
 */
static struct lock_class_key on_slab_l3_key;
static struct lock_class_key on_slab_alc_key;

static inline void init_lock_keys(void)

{
	int q;
	struct cache_sizes *s = malloc_sizes;

	while (s->cs_size != ULONG_MAX) {
		for_each_node(q) {
			struct array_cache **alc;
			int r;
			struct kmem_list3 *l3 = s->cs_cachep->nodelists[q];
			if (!l3 || OFF_SLAB(s->cs_cachep))
				continue;
			lockdep_set_class(&l3->list_lock, &on_slab_l3_key);
			alc = l3->alien;
			/*
			 * FIXME: This check for BAD_ALIEN_MAGIC
			 * should go away when common slab code is taught to
			 * work even without alien caches.
			 * Currently, non NUMA code returns BAD_ALIEN_MAGIC
			 * for alloc_alien_cache,
			 */
			if (!alc || (unsigned long)alc == BAD_ALIEN_MAGIC)
				continue;
			for_each_node(r) {
				if (alc[r])
					lockdep_set_class(&alc[r]->lock,
					     &on_slab_alc_key);
			}
		}
		s++;
	}
}
#else
static inline void init_lock_keys(void)
{
}
#endif

/*
 * 1. Guard access to the cache-chain.
 * 2. Protect sanity of cpu_online_map against cpu hotplug events
 */
static DEFINE_MUTEX(cache_chain_mutex);
/* 系统中所有的 struct kmem_cache变量,kmem_cache->list链接成一个链表 */
static struct list_head cache_chain;

/*
 * chicken and egg problem: delay the per-cpu array allocation
 * until the genral caches are up.
 *
 * g_cpucache_up记录general cache初始化的进度，
 * 比如PARTIAL_AC表示struct array_cache所在的cache已经创建，
 * PARTIAL_L3表示struct kmem_list3所在的cache已经创建,
 *
 * 注意创建这两个cache的先后顺序。在初始化阶段只需配置主cpu的local cache和slab三链
 * 若g_cpucache_up为NONE，说明sizeof(struct array)大小的cache还没有创建，      
 * 初始化阶段创建sizeof(struct array)大小的cache时进入这个流程，
 * 此时struct arraycache_init所在的general cache还未创建，
 * 只能使用静态分配的全局变量initarray_generic表示的local cache
 */
static enum {
	NONE,      /* 最初状态为NULL */
	PARTIAL_AC, /* struct array_cache所在的cache已经创建 */ /* 创建sizeof(struct arraycache_init)大小的cache之后 */
	PARTIAL_L3, /*  struct kmem_list3所在的cache已经创建 */ /* 创建sizeof(struct kmem_list3)大小的cache之后； */
	FULL
} g_cpucache_up;

/*
 * used by boot code to determine if it can use slab based allocator
 */
int slab_is_available(void)
{
	return g_cpucache_up == FULL;
}

static DEFINE_PER_CPU(struct delayed_work, reap_work);

static inline struct array_cache *cpu_cache_get(struct kmem_cache *cachep)
{
	return cachep->array[smp_processor_id()];
}

static inline struct kmem_cache *__find_general_cachep(size_t size,
							gfp_t gfpflags)
{
    /* 在malloc_sizes数组中查找size对应的cache_sizes对象 */
	struct cache_sizes *csizep = malloc_sizes;

#if DEBUG
	/* This happens if someone tries to call
	 * kmem_cache_create(), or __kmalloc(), before
	 * the generic caches are initialized.
	 */
	BUG_ON(malloc_sizes[INDEX_AC].cs_cachep == NULL);
#endif
	if (!size)
		return ZERO_SIZE_PTR;

   /* 寻找合适大小的cache_sizes */
	while (size > csizep->cs_size)
		csizep++;

	/*
	 * Really subtle: The last entry with cs->cs_size==ULONG_MAX
	 * has cs_{dma,}cachep==NULL. Thus no special case
	 * for large kmalloc calls required.
	 */
#ifdef CONFIG_ZONE_DMA
	if (unlikely(gfpflags & GFP_DMA))
		return csizep->cs_dmacachep;
#endif
	return csizep->cs_cachep;
}

static struct kmem_cache *kmem_find_general_cachep(size_t size, gfp_t gfpflags)
{
	return __find_general_cachep(size, gfpflags);
}

/* 得出slab管理对象对齐后总大小 */
static size_t slab_mgmt_size(size_t nr_objs, size_t align)
{
	return ALIGN(sizeof(struct slab)+nr_objs*sizeof(kmem_bufctl_t), align);
}

/*
 * Calculate the number of objects and left-over bytes for a given buffer size.
   gfporder: 取值0～11遍历直到计算出cache的对象数量跳出循环，slab由2^gfporder个页面组成
   buffer_size: 为当前cache中对象经过cache_line_size对齐后的大小
   align: 是cache_line_size，按照该大小对齐
   flags: 此处为0，用于标识内置slab还是外置slab
   left_over: 输出值，记录slab中浪费空间的大小
   num：输出值，用于记录当前cache中允许存在的对象数目
 */
static void cache_estimate(unsigned long gfporder, size_t buffer_size,
			   size_t align, int flags, size_t *left_over,
			   unsigned int *num)
{
	int nr_objs;
	size_t mgmt_size;
	/* PAGE_SIZE代表一个页面，slab_size记录需要多少个页面 */
	/*slab大小为2^gfporder个页面*/
	size_t slab_size = PAGE_SIZE << gfporder;

	/*
	 * The slab management structure can be either off the slab or
	 * on it. For the latter case, the memory allocated for a
	 * slab is used for:
	 *
	 * - The struct slab
	 * - One kmem_bufctl_t for each object
	 * - Padding to respect alignment of @align
	 * - @buffer_size bytes for each object
	 *
	 * If the slab management structure is off the slab, then the
	 * alignment will already be calculated into the size. Because
	 * the slabs are all pages aligned, the objects will be at the
	 * correct alignment when allocated.
	 * 外置slab
	 */
	if (flags & CFLGS_OFF_SLAB) {
		/*  slab中不含管理对象，全部用于存储slab对象，计算当前的对象数量 */
		mgmt_size = 0;
		nr_objs = slab_size / buffer_size;
        /* 如果超过阀值，则取上限 */
		if (nr_objs > SLAB_LIMIT)
			nr_objs = SLAB_LIMIT;
	} else {
		/*
		 * Ignore padding for the initial guess. The padding
		 * is at most @align-1 bytes, and @buffer_size is at
		 * least @align. In the worst case, this result will
		 * be one greater than the number of objects that fit
		 * into the memory allocation when taking the padding
		 * into account.
		    内置的slab管理对象，slab管理对象与slab对象在一起。
            此时slab页面中包含struct slab管理对象，
            kmem_bufctl_t数组和slab对象，其中kmem_bufctl_t数组个数与slab对象数量一致
		 */
		 /*内置式slab，slab管理对象与slab对象在一起，
           此时slab页面中包含：一个struct slab对象，
           一个kmem_bufctl_t数组(kmem_bufctl_t数组大小与slab对象数目相同)，
           slab对象。
           slab大小需要减去管理对象大小，所以对象个数为剩余大小除以每个对象大小加上kmem_bufctl_t结构大小
          */
		nr_objs = (slab_size - sizeof(struct slab)) /
			  (buffer_size + sizeof(kmem_bufctl_t));

		/*
		 * This calculated number will be either the right
		 * amount, or one greater than what we want.
		 */
		 /*如果对齐后大小超过slab总大小，需要减去一个对象*/
		if (slab_mgmt_size(nr_objs, align) + nr_objs*buffer_size
		       > slab_size)
			nr_objs--;

         /*对象个数不许超限*//
		if (nr_objs > SLAB_LIMIT)
			nr_objs = SLAB_LIMIT;

		/*得出slab管理对象对齐后总大小*/
		mgmt_size = slab_mgmt_size(nr_objs, align);
	}
	
	*num = nr_objs; //计算得到的slab对象的数目，通过num输出
	/*  计算当前slab中浪费的空间的大小 */
	*left_over = slab_size - nr_objs*buffer_size - mgmt_size;
}

#define slab_error(cachep, msg) __slab_error(__FUNCTION__, cachep, msg)

static void __slab_error(const char *function, struct kmem_cache *cachep,
			char *msg)
{
	printk(KERN_ERR "slab error in %s(): cache `%s': %s\n",
	       function, cachep->name, msg);
	dump_stack();
}

/*
 * By default on NUMA we use alien caches to stage the freeing of
 * objects allocated from other nodes. This causes massive memory
 * inefficiencies when using fake NUMA setup to split memory into a
 * large number of small nodes, so it can be disabled on the command
 * line
  */

static int use_alien_caches __read_mostly = 1;
static int numa_platform __read_mostly = 1;
static int __init noaliencache_setup(char *s)
{
	use_alien_caches = 0;
	return 1;
}
__setup("noaliencache", noaliencache_setup);

#ifdef CONFIG_NUMA
/*
 * Special reaping functions for NUMA systems called from cache_reap().
 * These take care of doing round robin flushing of alien caches (containing
 * objects freed on different nodes from which they were allocated) and the
 * flushing of remote pcps by calling drain_node_pages.
 */
static DEFINE_PER_CPU(unsigned long, reap_node);

static void init_reap_node(int cpu)
{
	int node;

	node = next_node(cpu_to_node(cpu), node_online_map);
	if (node == MAX_NUMNODES)
		node = first_node(node_online_map);

	per_cpu(reap_node, cpu) = node;
}

static void next_reap_node(void)
{
	int node = __get_cpu_var(reap_node);

	node = next_node(node, node_online_map);
	if (unlikely(node >= MAX_NUMNODES))
		node = first_node(node_online_map);
	__get_cpu_var(reap_node) = node;
}

#else
#define init_reap_node(cpu) do { } while (0)
#define next_reap_node(void) do { } while (0)
#endif

/*
 * Initiate the reap timer running on the target CPU.  We run at around 1 to 2Hz
 * via the workqueue/eventd.
 * Add the CPU number into the expiration time to minimize the possibility of
 * the CPUs getting into lockstep and contending for the global cache chain
 * lock.
 */
static void __cpuinit start_cpu_timer(int cpu)
{
	struct delayed_work *reap_work = &per_cpu(reap_work, cpu);

	/*
	 * When this gets called from do_initcalls via cpucache_init(),
	 * init_workqueues() has already run, so keventd will be setup
	 * at that time.
	 */
	if (keventd_up() && reap_work->work.func == NULL) {
		init_reap_node(cpu);
		INIT_DELAYED_WORK(reap_work, cache_reap);
		schedule_delayed_work_on(cpu, reap_work,
					__round_jiffies_relative(HZ, cpu));
	}
}

/*
  分配array_cache
  
kmem_cache_create
  setup_cpu_cache
    enable_cpucache
      do_tune_cpucache
        alloc_kmemlist  
*/
static struct array_cache *alloc_arraycache(int node, int entries,
					    int batchcount)
{
    /*array_cache 大小*/
	int memsize = sizeof(void *) * entries + sizeof(struct array_cache);
	struct array_cache *nc = NULL;

	nc = kmalloc_node(memsize, GFP_KERNEL, node);
	if (nc) {
		nc->avail = 0;//可用空间起始位置
		nc->limit = entries; //空间中可放对象的数量
		nc->batchcount = batchcount;
		nc->touched = 0;
		spin_lock_init(&nc->lock);
	}
	return nc;
}

/*
 * Transfer objects in one arraycache to another.
 * Locking must be handled by the caller.
 *
 * Return the number of entries transferred.
 *
 * 从from中移动对象到to中
 */
static int transfer_objects(struct array_cache *to,
		struct array_cache *from, unsigned int max)
{
	/* Figure out how many entries to transfer */
	int nr = min(min(from->avail, max), to->limit - to->avail);

	if (!nr)
		return 0;

    /* 拷贝并更新相关成员 */
	memcpy(to->entry + to->avail, from->entry + from->avail -nr,
			sizeof(void *) *nr);

	from->avail -= nr; 
	to->avail += nr;
	to->touched = 1;
	return nr;
}

#ifndef CONFIG_NUMA

#define drain_alien_cache(cachep, alien) do { } while (0)
#define reap_alien(cachep, l3) do { } while (0)

static inline struct array_cache **alloc_alien_cache(int node, int limit)
{
	return (struct array_cache **)BAD_ALIEN_MAGIC;
}

static inline void free_alien_cache(struct array_cache **ac_ptr)
{
}

static inline int cache_free_alien(struct kmem_cache *cachep, void *objp)
{
	return 0;
}

static inline void *alternate_node_alloc(struct kmem_cache *cachep,
		gfp_t flags)
{
	return NULL;
}

static inline void *____cache_alloc_node(struct kmem_cache *cachep,
		 gfp_t flags, int nodeid)
{
	return NULL;
}

#else	/* CONFIG_NUMA */

static void *____cache_alloc_node(struct kmem_cache *, gfp_t, int);
static void *alternate_node_alloc(struct kmem_cache *, gfp_t);

static struct array_cache **alloc_alien_cache(int node, int limit)
{
	struct array_cache **ac_ptr;
	int memsize = sizeof(void *) * nr_node_ids;
	int i;

	if (limit > 1)
		limit = 12;
	ac_ptr = kmalloc_node(memsize, GFP_KERNEL, node);
	if (ac_ptr) {
		for_each_node(i) {
			if (i == node || !node_online(i)) {
				ac_ptr[i] = NULL;
				continue;
			}
			ac_ptr[i] = alloc_arraycache(node, limit, 0xbaadf00d);
			if (!ac_ptr[i]) {
				for (i--; i >= 0; i--)
					kfree(ac_ptr[i]);
				kfree(ac_ptr);
				return NULL;
			}
		}
	}
	return ac_ptr;
}

static void free_alien_cache(struct array_cache **ac_ptr)
{
	int i;

	if (!ac_ptr)
		return;
	for_each_node(i)
	    kfree(ac_ptr[i]);
	kfree(ac_ptr);
}

static void __drain_alien_cache(struct kmem_cache *cachep,
				struct array_cache *ac, int node)
{
	struct kmem_list3 *rl3 = cachep->nodelists[node];

	if (ac->avail) {
		spin_lock(&rl3->list_lock);
		/*
		 * Stuff objects into the remote nodes shared array first.
		 * That way we could avoid the overhead of putting the objects
		 * into the free lists and getting them back later.
		 */
		if (rl3->shared)
			transfer_objects(rl3->shared, ac, ac->limit);

		free_block(cachep, ac->entry, ac->avail, node);
		ac->avail = 0;
		spin_unlock(&rl3->list_lock);
	}
}

/*
 * Called from cache_reap() to regularly drain alien caches round robin.
 */
static void reap_alien(struct kmem_cache *cachep, struct kmem_list3 *l3)
{
	int node = __get_cpu_var(reap_node);

	if (l3->alien) {
		struct array_cache *ac = l3->alien[node];

		if (ac && ac->avail && spin_trylock_irq(&ac->lock)) {
			__drain_alien_cache(cachep, ac, node);
			spin_unlock_irq(&ac->lock);
		}
	}
}

static void drain_alien_cache(struct kmem_cache *cachep,
				struct array_cache **alien)
{
	int i = 0;
	struct array_cache *ac;
	unsigned long flags;

	for_each_online_node(i) {
		ac = alien[i];
		if (ac) {
			spin_lock_irqsave(&ac->lock, flags);
			__drain_alien_cache(cachep, ac, i);
			spin_unlock_irqrestore(&ac->lock, flags);
		}
	}
}

static inline int cache_free_alien(struct kmem_cache *cachep, void *objp)
{
	struct slab *slabp = virt_to_slab(objp);
	int nodeid = slabp->nodeid;
	struct kmem_list3 *l3;
	struct array_cache *alien = NULL;
	int node;

	node = numa_node_id();

	/*
	 * Make sure we are not freeing a object from another node to the array
	 * cache on this cpu.
	 */
	if (likely(slabp->nodeid == node))
		return 0;

	l3 = cachep->nodelists[node];
	STATS_INC_NODEFREES(cachep);
	if (l3->alien && l3->alien[nodeid]) {
		alien = l3->alien[nodeid];
		spin_lock(&alien->lock);
		if (unlikely(alien->avail == alien->limit)) {
			STATS_INC_ACOVERFLOW(cachep);
			__drain_alien_cache(cachep, alien, nodeid);
		}
		alien->entry[alien->avail++] = objp;
		spin_unlock(&alien->lock);
	} else {
		spin_lock(&(cachep->nodelists[nodeid])->list_lock);
		free_block(cachep, &objp, 1, nodeid);
		spin_unlock(&(cachep->nodelists[nodeid])->list_lock);
	}
	return 1;
}
#endif

static void __cpuinit cpuup_canceled(long cpu)
{
	struct kmem_cache *cachep;
	struct kmem_list3 *l3 = NULL;
	int node = cpu_to_node(cpu);

	list_for_each_entry(cachep, &cache_chain, next) {
		struct array_cache *nc;
		struct array_cache *shared;
		struct array_cache **alien;
		cpumask_t mask;

		mask = node_to_cpumask(node);
		/* cpu is dead; no one can alloc from it. */
		nc = cachep->array[cpu];
		cachep->array[cpu] = NULL;
		l3 = cachep->nodelists[node];

		if (!l3)
			goto free_array_cache;

		spin_lock_irq(&l3->list_lock);

		/* Free limit for this kmem_list3 */
		l3->free_limit -= cachep->batchcount;
		if (nc)
			free_block(cachep, nc->entry, nc->avail, node);

		if (!cpus_empty(mask)) {
			spin_unlock_irq(&l3->list_lock);
			goto free_array_cache;
		}

		shared = l3->shared;
		if (shared) {
			free_block(cachep, shared->entry,
				   shared->avail, node);
			l3->shared = NULL;
		}

		alien = l3->alien;
		l3->alien = NULL;

		spin_unlock_irq(&l3->list_lock);

		kfree(shared);
		if (alien) {
			drain_alien_cache(cachep, alien);
			free_alien_cache(alien);
		}
free_array_cache:
		kfree(nc);
	}
	/*
	 * In the previous loop, all the objects were freed to
	 * the respective cache's slabs,  now we can go ahead and
	 * shrink each nodelist to its limit.
	 */
	list_for_each_entry(cachep, &cache_chain, next) {
		l3 = cachep->nodelists[node];
		if (!l3)
			continue;
		drain_freelist(cachep, l3, l3->free_objects);
	}
}

/*
 cpuup_callback
    cpuup_prepare
*/
static int __cpuinit cpuup_prepare(long cpu)
{
	struct kmem_cache *cachep;
	struct kmem_list3 *l3 = NULL;
	int node = cpu_to_node(cpu);
	const int memsize = sizeof(struct kmem_list3);

	/*
	 * We need to do this right in the beginning since
	 * alloc_arraycache's are going to use this list.
	 * kmalloc_node allows us to add the slab to the right
	 * kmem_list3 and not this cpu's kmem_list3
	 */

	list_for_each_entry(cachep, &cache_chain, next) {
		/*
		 * Set up the size64 kmemlist for cpu before we can
		 * begin anything. Make sure some other cpu on this
		 * node has not already allocated this
		 */
		if (!cachep->nodelists[node]) {
			l3 = kmalloc_node(memsize, GFP_KERNEL, node);
			if (!l3)
				goto bad;
			kmem_list3_init(l3);
			l3->next_reap = jiffies + REAPTIMEOUT_LIST3 +
			    ((unsigned long)cachep) % REAPTIMEOUT_LIST3;

			/*
			 * The l3s don't come and go as CPUs come and
			 * go.  cache_chain_mutex is sufficient
			 * protection here.
			 */
			cachep->nodelists[node] = l3;
		}

		spin_lock_irq(&cachep->nodelists[node]->list_lock);
		cachep->nodelists[node]->free_limit =
			(1 + nr_cpus_node(node)) *
			cachep->batchcount + cachep->num;
		spin_unlock_irq(&cachep->nodelists[node]->list_lock);
	}

	/*
	 * Now we can go ahead with allocating the shared arrays and
	 * array caches
	 */
	list_for_each_entry(cachep, &cache_chain, next) {
		struct array_cache *nc;
		struct array_cache *shared = NULL;
		struct array_cache **alien = NULL;

		nc = alloc_arraycache(node, cachep->limit,
					cachep->batchcount);
		if (!nc)
			goto bad;
		if (cachep->shared) {
			shared = alloc_arraycache(node,
				cachep->shared * cachep->batchcount,
				0xbaadf00d);
			if (!shared) {
				kfree(nc);
				goto bad;
			}
		}
		if (use_alien_caches) {
			alien = alloc_alien_cache(node, cachep->limit);
			if (!alien) {
				kfree(shared);
				kfree(nc);
				goto bad;
			}
		}
		cachep->array[cpu] = nc;
		l3 = cachep->nodelists[node];
		BUG_ON(!l3);

		spin_lock_irq(&l3->list_lock);
		if (!l3->shared) {
			/*
			 * We are serialised from CPU_DEAD or
			 * CPU_UP_CANCELLED by the cpucontrol lock
			 */
			l3->shared = shared;
			shared = NULL;
		}
#ifdef CONFIG_NUMA
		if (!l3->alien) {
			l3->alien = alien;
			alien = NULL;
		}
#endif
		spin_unlock_irq(&l3->list_lock);
		kfree(shared);
		free_alien_cache(alien);
	}
	return 0;
bad:
	cpuup_canceled(cpu);
	return -ENOMEM;
}

static int __cpuinit cpuup_callback(struct notifier_block *nfb,
				    unsigned long action, void *hcpu)
{
	long cpu = (long)hcpu;
	int err = 0;

	switch (action) {
	case CPU_LOCK_ACQUIRE:
		mutex_lock(&cache_chain_mutex);
		break;
	case CPU_UP_PREPARE:
	case CPU_UP_PREPARE_FROZEN:
		err = cpuup_prepare(cpu);
		break;
	case CPU_ONLINE:
	case CPU_ONLINE_FROZEN:
		start_cpu_timer(cpu);
		break;
#ifdef CONFIG_HOTPLUG_CPU
  	case CPU_DOWN_PREPARE:
  	case CPU_DOWN_PREPARE_FROZEN:
		/*
		 * Shutdown cache reaper. Note that the cache_chain_mutex is
		 * held so that if cache_reap() is invoked it cannot do
		 * anything expensive but will only modify reap_work
		 * and reschedule the timer.
		*/
		cancel_rearming_delayed_work(&per_cpu(reap_work, cpu));
		/* Now the cache_reaper is guaranteed to be not running. */
		per_cpu(reap_work, cpu).work.func = NULL;
  		break;
  	case CPU_DOWN_FAILED:
  	case CPU_DOWN_FAILED_FROZEN:
		start_cpu_timer(cpu);
  		break;
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		/*
		 * Even if all the cpus of a node are down, we don't free the
		 * kmem_list3 of any cache. This to avoid a race between
		 * cpu_down, and a kmalloc allocation from another cpu for
		 * memory from the node of the cpu going down.  The list3
		 * structure is usually allocated from kmem_cache_create() and
		 * gets destroyed at kmem_cache_destroy().
		 */
		/* fall through */
#endif
	case CPU_UP_CANCELED:
	case CPU_UP_CANCELED_FROZEN:
		cpuup_canceled(cpu);
		break;
	case CPU_LOCK_RELEASE:
		mutex_unlock(&cache_chain_mutex);
		break;
	}
	return err ? NOTIFY_BAD : NOTIFY_OK;
}

static struct notifier_block __cpuinitdata cpucache_notifier = {
	&cpuup_callback, NULL, 0
};

/*
 * swap the static kmem_list3 with kmalloced memory
 */
static void init_list(struct kmem_cache *cachep, struct kmem_list3 *list,
			int nodeid)
{
	struct kmem_list3 *ptr;

	ptr = kmalloc_node(sizeof(struct kmem_list3), GFP_KERNEL, nodeid);
	BUG_ON(!ptr);

	local_irq_disable();
	memcpy(ptr, list, sizeof(struct kmem_list3));
	/*
	 * Do not assume that spinlocks can be initialized via memcpy:
	 */
	spin_lock_init(&ptr->list_lock);

	MAKE_ALL_LISTS(cachep, ptr, nodeid);
	cachep->nodelists[nodeid] = ptr;
	local_irq_enable();
}

/*
 * Initialisation.  Called after the page allocator have been initialised and
 * before smp_init().
  调用过程
     start_kernel()->kmem_cache_init()
 */
void __init kmem_cache_init(void)
{
	size_t left_over;
	struct cache_sizes *sizes;
	struct cache_names *names;
	int i;
	int order;
	int node;

	/* 在slab初始化好之前，无法通过kmalloc分配初始化过程中必要的一些对象 ，只能使用静态的全局变量 
         ，待slab初始化后期，再使用kmalloc动态分配的对象替换全局变量 */  
  
       /* 如前所述，先借用全局变量initkmem_list3表示的slab三链 
        ，每个内存节点对应一组slab三链。initkmem_list3是个slab三链数组，对于每个内存节点，包含三组 
        ：struct kmem_cache的slab三链、struct arraycache_init的slab 三链、struct kmem_list3的slab三链 。
这里循环初始化所有内存节点的所有slab三链 */

    /*  在非NUMA平台上，将use_alien_cache设置为0，此时cache_free_alien将禁止调用 */
	if (num_possible_nodes() == 1) {
		/* 只有一个内存节点 */
		use_alien_caches = 0;
		numa_platform = 0;
	}
	
    /* initkmem_list3为全局变量，此时slab尚未完成初始化，kmalloc无法使用
        #define NODES_SHIFT     CONFIG_NODES_SHIFT
        #define MAX_NUMNODES    (1 << NODES_SHIFT)  2^CONFIG_NODES_SHIFT
        #define NUM_INIT_LISTS (3 * MAX_NUMNODES)   3*(2^CONFIG_NODES_SHIFT)

        CONFIG_NODES_SHIFT是当前系统配置的可支持的NUMA节点的最大个数，针对每个内存节点，包含： 
       struct kmem_cache/struct arraycache_init/struct kmem_list3的slab（full/free/partial）所以是3倍的NUMA节点
    */
	for (i = 0; i < NUM_INIT_LISTS; i++) {
		/* 初始化initkmem_list3三链. */
		kmem_list3_init(&initkmem_list3[i]);
		if (i < MAX_NUMNODES)
			/* cache_cache是全局变量，是内核中第一个cache(struct kmem_cache)，遍历当前所有节点，初始化为NULL */
			cache_cache.nodelists[i] = NULL;
	}

	/*
	 * Fragmentation resistance on low memory - only use bigger
	 * page orders on machines with more than 32MB of memory.
     *
	 */
	if (num_physpages > (32 << 20) >> PAGE_SHIFT)
		slab_break_gfp_order = BREAK_GFP_ORDER_HI  /* 1 */;

	/* Bootstrap is tricky, because several objects are allocated
	 * from caches that do not exist yet:
	 * 1) initialize the cache_cache cache: it contains the struct
	 *    kmem_cache structures of all caches, except cache_cache itself:
	 *    cache_cache is statically allocated.
	 *    Initially an __init data area is used for the head array and the
	 *    kmem_list3 structures, it's replaced with a kmalloc allocated
	 *    array at the end of the bootstrap.
	 * 2) Create the first kmalloc cache.
	 *    The struct kmem_cache for the new cache is allocated normally.
	 *    An __init data area is used for the head array.
	 * 3) Create the remaining kmalloc caches, with minimally sized
	 *    head arrays.
	 * 4) Replace the __init data head arrays for cache_cache and the first
	 *    kmalloc cache with kmalloc allocated arrays.
	 * 5) Replace the __init data for kmem_list3 for cache_cache and
	 *    the other cache's with kmalloc allocated memory.
	 * 6) Resize the head arrays of the kmalloc caches to their final sizes.
	 */

    /* 根据当前CPU，获取对应的NUMA节点的I */
	node = numa_node_id();

	/* 1) create the cache_cache 
          cache_chain 是内核slab cache链表的链表头
	*/
	/* 第一步，创建struct kmem_cache所在的cache，
	 * 由全局变量cache_cache指向，这里只是初始化数据结构，
	 * 并未真正创建这些对象，要待分配时才创建。
	 * 全局变量cache_chain是内核kmem_cache对象 slab链表的表头 
	 */
	INIT_LIST_HEAD(&cache_chain); //初始化保存所有slab cache的全局链表cache_chain
	
	list_add(&cache_cache.next, &cache_chain);//将cache_cache加入到slab cache链表
	
	cache_cache.colour_off = cache_line_size();//设置cache着色基本单位为cache line的大小：32字节
    //初始化cache_cache的local cache，同样这里也不能使用kmalloc，需要使用静态分配的全局变量initarray_cache
	cache_cache.array[smp_processor_id()] = &initarray_cache.cache;
	//初始化slab链表 ,用全局变量
	cache_cache.nodelists[node] = &initkmem_list3[CACHE_CACHE]; // CACHE_CAHCE =0

	/*
	 * struct kmem_cache size depends on nr_node_ids, which
	 * can be less than MAX_NUMNODES.

	   buffer_size保存slab中对象的大小，这里是计算struct kmem_cache的大小，
	   nodelists是最后一个成员，nr_node_ids保存内存节点个数，UMA为1，
	   所以nodelists偏移加上1个struct kmem_list3 的大小即为struct kmem_cache的大小
	 */
	cache_cache.buffer_size = offsetof(struct kmem_cache, nodelists) +
				 nr_node_ids * sizeof(struct kmem_list3 *);
#if DEBUG
	cache_cache.obj_size = cache_cache.buffer_size;
#endif

	//将对象大小与cache line大小对齐
	cache_cache.buffer_size = ALIGN(cache_cache.buffer_size,
					cache_line_size());

	cache_cache.reciprocal_buffer_size =
		reciprocal_value(cache_cache.buffer_size);

	for (order = 0; order < MAX_ORDER /* 11 */; order++) {
		//计算cache_cache中的对象数目
		cache_estimate(order, cache_cache.buffer_size,
			cache_line_size(), 0, &left_over, &cache_cache.num);
		if (cache_cache.num) //num不为0意味着创建struct kmem_cache对象成功，退出
			break;
	}
	
	BUG_ON(!cache_cache.num);
	/* slab包含的页面个数，2^gfporder个 */
	cache_cache.gfporder = order;

	//着色区的大小，以colour_off为单位
	cache_cache.colour = left_over / cache_cache.colour_off;
    //slab管理区对象的大小
	cache_cache.slab_size = ALIGN(cache_cache.num * sizeof(kmem_bufctl_t) +
				      sizeof(struct slab), cache_line_size());

	/* 2+3) create the kmalloc caches 
       
	*/
	sizes = malloc_sizes;
	names = cache_names;

    /*
     * 首先创建struct array_cache和struct kmem_list3所用的general cache，
	 * 它们是后续初始化动作的基础
     */
     
	/*
	 * Initialize the caches that provide memory for the array cache and the
	 * kmem_list3 structures first.  Without this, further allocations will
	 * bug.
	 */
	 
	/* 
	 * INDEX_AC是计算local cache所用的struct arraycache_init对象在malloc_sizes中的索引，
	 * 即属于哪一级别大小的general cache，创建此大小级别的cache为local cache所用
	 */
	sizes[INDEX_AC].cs_cachep = kmem_cache_create(names[INDEX_AC].name,
					sizes[INDEX_AC].cs_size,
					ARCH_KMALLOC_MINALIGN,
					ARCH_KMALLOC_FLAGS|SLAB_PANIC,
					NULL);

    /*
     * 如果struct kmem_list3和struct arraycache_init对应的malloc_sizes索引不同，
     * 即大小属于不同的级别，则创建struct kmem_list3所用的cache，否则共用一个cache
     */
	if (INDEX_AC != INDEX_L3) {
		sizes[INDEX_L3].cs_cachep =
			kmem_cache_create(names[INDEX_L3].name,
				sizes[INDEX_L3].cs_size,
				ARCH_KMALLOC_MINALIGN,
				ARCH_KMALLOC_FLAGS|SLAB_PANIC,
				NULL);
	}


	slab_early_init = 0;//创建完上述两个general cache后，slab early init阶段结束，在此之前，不允许创建外置式slab


	while (sizes->cs_size != ULONG_MAX) {
		//循环创建kmalloc {malloc_sizes}各级别的general cache
		/*
		 * For performance, all the general caches are L1 aligned.
		 * This should be particularly beneficial on SMP boxes, as it
		 * eliminates "false sharing".
		 * Note for systems short on memory removing the alignment will
		 * allow tighter packing of the smaller caches.
		 *
		 */
		if (!sizes->cs_cachep) {
			/* 
			 * 某级别的kmalloc cache还未创建，创建之，
			 * struct kmem_list3和struct arraycache_init对应的cache已经创建过了
			 */
			/* 新建kmem_cache对象 */
			sizes->cs_cachep = kmem_cache_create(names->name,
					sizes->cs_size,
					ARCH_KMALLOC_MINALIGN,
					ARCH_KMALLOC_FLAGS|SLAB_PANIC,
					NULL);
		}
#ifdef CONFIG_ZONE_DMA
		sizes->cs_dmacachep = kmem_cache_create(
					names->name_dma,
					sizes->cs_size,
					ARCH_KMALLOC_MINALIGN,
					ARCH_KMALLOC_FLAGS|SLAB_CACHE_DMA|
						SLAB_PANIC,
					NULL);
#endif
        /* next */
		sizes++;
		names++;
	}
	//至此，kmalloc general cache已经创建完毕，可以拿来使用了
	/* 4) Replace the bootstrap head arrays 
	*/
	{
	/* 第四步，用kmalloc对象替换静态分配的全局变量。到目前为止一共使用了两个全局local cache，
	   一个是cache_cache的local cache指向initarray_cache.cache，
	   另一个是malloc_sizes[INDEX_AC].cs_cachep的local cache指向
       initarray_generic.cache，参见setup_cpu_cache函数。这里替换它们。
     */
		struct array_cache *ptr;

        //申请cache_cache所用local cache的空间
		ptr = kmalloc(sizeof(struct arraycache_init), GFP_KERNEL); 

		local_irq_disable();
		BUG_ON(cpu_cache_get(&cache_cache) != &initarray_cache.cache);

		//复制原cache_cache的local cache，即initarray_cache，到新的位置
		memcpy(ptr, cpu_cache_get(&cache_cache),
		       sizeof(struct arraycache_init));
		/*
		 * Do not assume that spinlocks can be initialized via memcpy:
		 */
		spin_lock_init(&ptr->lock);

        //cache_cache的local cache指向新的位置
		cache_cache.array[smp_processor_id()] = ptr;
		local_irq_enable();

        //申请malloc_sizes[INDEX_AC].cs_cachep所用local cache的空间
		ptr = kmalloc(sizeof(struct arraycache_init), GFP_KERNEL);

		local_irq_disable();
		BUG_ON(cpu_cache_get(malloc_sizes[INDEX_AC].cs_cachep)
		       != &initarray_generic.cache);

			        /* kmem_cache->array[cpuid] */
		//复制原local cache到新分配的位置，注意此时local cache的大小是固定的
		memcpy(ptr, cpu_cache_get(malloc_sizes[INDEX_AC].cs_cachep),
		       sizeof(struct arraycache_init));
		/*
		 * Do not assume that spinlocks can be initialized via memcpy:
		 */
		spin_lock_init(&ptr->lock);

        
		malloc_sizes[INDEX_AC].cs_cachep->array[smp_processor_id()] =
		    ptr;
		local_irq_enable();
	}
	/* 5) Replace the bootstrap kmem_list3's 
       
	*/
	{//第五步，与第四步类似，用kmalloc的空间替换静态分配的slab三链
		int nid;

		/* Replace the static kmem_list3 structures for the boot cpu */
		//复制struct kmem_cache的slab三链
		init_list(&cache_cache, &initkmem_list3[CACHE_CACHE], node);

		for_each_online_node(nid) {
			//复制struct arraycache_init的slab三链
			init_list(malloc_sizes[INDEX_AC].cs_cachep,
				  &initkmem_list3[SIZE_AC + nid], nid);

			if (INDEX_AC != INDEX_L3) {
				//复制struct kmem_list3的slab三链
				init_list(malloc_sizes[INDEX_L3].cs_cachep,
					  &initkmem_list3[SIZE_L3 + nid], nid);
			}
		}
	}

	/* 6) resize the head arrays to their final sizes */
	{
	   //初始化阶段local cache的大小是固定的，要根据对象大小重新计算
		struct kmem_cache *cachep;
		mutex_lock(&cache_chain_mutex);
		list_for_each_entry(cachep, &cache_chain, next)
			
			if (enable_cpucache(cachep))
				BUG();
		mutex_unlock(&cache_chain_mutex);
	}

	/* Annotate slab for lockdep -- annotate the malloc caches */
	init_lock_keys();


	/* Done!  cache_cache初始化 结束 */
	g_cpucache_up = FULL;

	/*
	 * Register a cpu startup notifier callback that initializes
	 * cpu_cache_get for all new cpus
	 
	 注册cpu up回调函数，cpu up时配置local cache
	 */
	register_cpu_notifier(&cpucache_notifier); 

	/*
	 * The reap timers are started later, with a module init call: That part
	 * of the kernel is not yet operational.
	 */
}

static int __init cpucache_init(void)
{
	int cpu;

	/*
	 * Register the timers that return unneeded pages to the page allocator
	 */
	for_each_online_cpu(cpu)
		start_cpu_timer(cpu);
	return 0;
}
__initcall(cpucache_init);

/*
 * Interface to system's page allocator. No need to hold the cache-lock.
 *
 * If we requested dmaable memory, we will get it. Even if we
 * did not request dmaable memory, we might get it, but that
 * would be relatively rare and ignorable.
 * 分配page frame作为slab
 *
 kmem_cache_alloc
  __cache_alloc
   __do_cache_alloc
    ____cache_alloc
     cache_alloc_refill
      cache_grow
       kmem_getpages()
 */
static void *kmem_getpages(struct kmem_cache *cachep, gfp_t flags, int nodeid)
{
	struct page *page;
	int nr_pages;
	int i;

#ifndef CONFIG_MMU
	/*
	 * Nommu uses slab's for process anonymous memory allocations, and thus
	 * requires __GFP_COMP to properly refcount higher order allocations
	 */
	flags |= __GFP_COMP;
#endif

	flags |= cachep->gfpflags;
	if (cachep->flags & SLAB_RECLAIM_ACCOUNT)
		flags |= __GFP_RECLAIMABLE;

	/* 2^cachep->gfporder个对象 */
	page = alloc_pages_node(nodeid, flags, cachep->gfporder);
	if (!page)
		return NULL;

	/* 当前kmem_cache对象每个slab需要的page数量 */
	nr_pages = (1 << cachep->gfporder);
	if (cachep->flags & SLAB_RECLAIM_ACCOUNT)
		add_zone_page_state(page_zone(page),
			NR_SLAB_RECLAIMABLE, nr_pages);
	else
		add_zone_page_state(page_zone(page),
			NR_SLAB_UNRECLAIMABLE, nr_pages);
	
	for (i = 0; i < nr_pages; i++)
		__SetPageSlab(page + i);/* 设置page->flags 的PG_slab标记 */

	/* 内核态虚拟地址 */
	return page_address(page);
}

/*
 * Interface to system's page release.
 */
static void kmem_freepages(struct kmem_cache *cachep, void *addr)
{
	unsigned long i = (1 << cachep->gfporder);
	struct page *page = virt_to_page(addr);
	const unsigned long nr_freed = i;

	if (cachep->flags & SLAB_RECLAIM_ACCOUNT)
		sub_zone_page_state(page_zone(page),
				NR_SLAB_RECLAIMABLE, nr_freed);
	else
		sub_zone_page_state(page_zone(page),
				NR_SLAB_UNRECLAIMABLE, nr_freed);
	while (i--) {
		BUG_ON(!PageSlab(page));
		__ClearPageSlab(page);
		page++;
	}
	if (current->reclaim_state)
		current->reclaim_state->reclaimed_slab += nr_freed;
	free_pages((unsigned long)addr, cachep->gfporder);
}

static void kmem_rcu_free(struct rcu_head *head)
{
	struct slab_rcu *slab_rcu = (struct slab_rcu *)head;
	struct kmem_cache *cachep = slab_rcu->cachep;

	kmem_freepages(cachep, slab_rcu->addr);
	if (OFF_SLAB(cachep))
		kmem_cache_free(cachep->slabp_cache, slab_rcu);
}

#if DEBUG

#ifdef CONFIG_DEBUG_PAGEALLOC
static void store_stackinfo(struct kmem_cache *cachep, unsigned long *addr,
			    unsigned long caller)
{
	int size = obj_size(cachep);

	addr = (unsigned long *)&((char *)addr)[obj_offset(cachep)];

	if (size < 5 * sizeof(unsigned long))
		return;

	*addr++ = 0x12345678;
	*addr++ = caller;
	*addr++ = smp_processor_id();
	size -= 3 * sizeof(unsigned long);
	{
		unsigned long *sptr = &caller;
		unsigned long svalue;

		while (!kstack_end(sptr)) {
			svalue = *sptr++;
			if (kernel_text_address(svalue)) {
				*addr++ = svalue;
				size -= sizeof(unsigned long);
				if (size <= sizeof(unsigned long))
					break;
			}
		}

	}
	*addr++ = 0x87654321;
}
#endif

static void poison_obj(struct kmem_cache *cachep, void *addr, unsigned char val)
{
	int size = obj_size(cachep);
	addr = &((char *)addr)[obj_offset(cachep)];

	memset(addr, val, size);
	*(unsigned char *)(addr + size - 1) = POISON_END;
}

static void dump_line(char *data, int offset, int limit)
{
	int i;
	unsigned char error = 0;
	int bad_count = 0;

	printk(KERN_ERR "%03x:", offset);
	for (i = 0; i < limit; i++) {
		if (data[offset + i] != POISON_FREE) {
			error = data[offset + i];
			bad_count++;
		}
		printk(" %02x", (unsigned char)data[offset + i]);
	}
	printk("\n");

	if (bad_count == 1) {
		error ^= POISON_FREE;
		if (!(error & (error - 1))) {
			printk(KERN_ERR "Single bit error detected. Probably "
					"bad RAM.\n");
#ifdef CONFIG_X86
			printk(KERN_ERR "Run memtest86+ or a similar memory "
					"test tool.\n");
#else
			printk(KERN_ERR "Run a memory test tool.\n");
#endif
		}
	}
}
#endif

#if DEBUG

static void print_objinfo(struct kmem_cache *cachep, void *objp, int lines)
{
	int i, size;
	char *realobj;

	if (cachep->flags & SLAB_RED_ZONE) {
		printk(KERN_ERR "Redzone: 0x%llx/0x%llx.\n",
			*dbg_redzone1(cachep, objp),
			*dbg_redzone2(cachep, objp));
	}

	if (cachep->flags & SLAB_STORE_USER) {
		printk(KERN_ERR "Last user: [<%p>]",
			*dbg_userword(cachep, objp));
		print_symbol("(%s)",
				(unsigned long)*dbg_userword(cachep, objp));
		printk("\n");
	}
	realobj = (char *)objp + obj_offset(cachep);
	size = obj_size(cachep);
	for (i = 0; i < size && lines; i += 16, lines--) {
		int limit;
		limit = 16;
		if (i + limit > size)
			limit = size - i;
		dump_line(realobj, i, limit);
	}
}

static void check_poison_obj(struct kmem_cache *cachep, void *objp)
{
	char *realobj;
	int size, i;
	int lines = 0;

	realobj = (char *)objp + obj_offset(cachep);
	size = obj_size(cachep);

	for (i = 0; i < size; i++) {
		char exp = POISON_FREE;
		if (i == size - 1)
			exp = POISON_END;
		if (realobj[i] != exp) {
			int limit;
			/* Mismatch ! */
			/* Print header */
			if (lines == 0) {
				printk(KERN_ERR
					"Slab corruption: %s start=%p, len=%d\n",
					cachep->name, realobj, size);
				print_objinfo(cachep, objp, 0);
			}
			/* Hexdump the affected line */
			i = (i / 16) * 16;
			limit = 16;
			if (i + limit > size)
				limit = size - i;
			dump_line(realobj, i, limit);
			i += 16;
			lines++;
			/* Limit to 5 lines */
			if (lines > 5)
				break;
		}
	}
	if (lines != 0) {
		/* Print some data about the neighboring objects, if they
		 * exist:
		 */
		struct slab *slabp = virt_to_slab(objp);
		unsigned int objnr;

		objnr = obj_to_index(cachep, slabp, objp);
		if (objnr) {
			objp = index_to_obj(cachep, slabp, objnr - 1);
			realobj = (char *)objp + obj_offset(cachep);
			printk(KERN_ERR "Prev obj: start=%p, len=%d\n",
			       realobj, size);
			print_objinfo(cachep, objp, 2);
		}
		if (objnr + 1 < cachep->num) {
			objp = index_to_obj(cachep, slabp, objnr + 1);
			realobj = (char *)objp + obj_offset(cachep);
			printk(KERN_ERR "Next obj: start=%p, len=%d\n",
			       realobj, size);
			print_objinfo(cachep, objp, 2);
		}
	}
}
#endif

#if DEBUG
/**
 * slab_destroy_objs - destroy a slab and its objects
 * @cachep: cache pointer being destroyed
 * @slabp: slab pointer being destroyed
 *
 * Call the registered destructor for each object in a slab that is being
 * destroyed.
 */
static void slab_destroy_objs(struct kmem_cache *cachep, struct slab *slabp)
{
	int i;
	for (i = 0; i < cachep->num; i++) {
		void *objp = index_to_obj(cachep, slabp, i);

		if (cachep->flags & SLAB_POISON) {
#ifdef CONFIG_DEBUG_PAGEALLOC
			if (cachep->buffer_size % PAGE_SIZE == 0 &&
					OFF_SLAB(cachep))
				kernel_map_pages(virt_to_page(objp),
					cachep->buffer_size / PAGE_SIZE, 1);
			else
				check_poison_obj(cachep, objp);
#else
			check_poison_obj(cachep, objp);
#endif
		}
		if (cachep->flags & SLAB_RED_ZONE) {
			if (*dbg_redzone1(cachep, objp) != RED_INACTIVE)
				slab_error(cachep, "start of a freed object "
					   "was overwritten");
			if (*dbg_redzone2(cachep, objp) != RED_INACTIVE)
				slab_error(cachep, "end of a freed object "
					   "was overwritten");
		}
	}
}
#else
static void slab_destroy_objs(struct kmem_cache *cachep, struct slab *slabp)
{
}
#endif

/**
 * slab_destroy - destroy and release all objects in a slab
 * @cachep: cache pointer being destroyed
 * @slabp: slab pointer being destroyed
 *
 * Destroy all the objs in a slab, and release the mem back to the system.
 * Before calling the slab must have been unlinked from the cache.  The
 * cache-lock is not held/needed.
 */
static void slab_destroy(struct kmem_cache *cachep, struct slab *slabp)
{
    /* slabp->s_mem记录的是slab对象的起始地址，由于着色偏移，所以需要减去colouroff指向slab首页面的地址 */
	void *addr = slabp->s_mem - slabp->colouroff;
    
	slab_destroy_objs(cachep, slabp);
	/* 判断一下使用那种销毁方式，rcu是多核中的一种同步机制 */
	if (unlikely(cachep->flags & SLAB_DESTROY_BY_RCU)) {
		struct slab_rcu *slab_rcu;

		slab_rcu = (struct slab_rcu *)slabp;
		slab_rcu->cachep = cachep;
		slab_rcu->addr = addr;
		call_rcu(&slab_rcu->head, kmem_rcu_free);
	} else {
		/* 释放slab占用的页面，如果slab管理对象内置的话，随着页面一起释放了 */
		kmem_freepages(cachep, addr);
		/* 如果slab管理对象是外置的花，需要单独释放一下 */
		if (OFF_SLAB(cachep))
			kmem_cache_free(cachep->slabp_cache, slabp);
	}
}

/*
 * For setting up all the kmem_list3s for cache whose buffer_size is same as
 * size of kmem_list3.
 */
static void __init set_up_list3s(struct kmem_cache *cachep, int index)
{
	int node;

	for_each_online_node(node) {
		cachep->nodelists[node] = &initkmem_list3[index + node];
		cachep->nodelists[node]->next_reap = jiffies +
		    REAPTIMEOUT_LIST3 +
		    ((unsigned long)cachep) % REAPTIMEOUT_LIST3;
	}
}

static void __kmem_cache_destroy(struct kmem_cache *cachep)
{
	int i;
	struct kmem_list3 *l3;

	for_each_online_cpu(i)
	    kfree(cachep->array[i]);

	/* NUMA: free the list3 structures */
	for_each_online_node(i) {
		l3 = cachep->nodelists[i];
		if (l3) {
			kfree(l3->shared);
			free_alien_cache(l3->alien);
			kfree(l3);
		}
	}
	kmem_cache_free(&cache_cache, cachep);
}


/**
 * calculate_slab_order - calculate size (page order) of slabs
 * @cachep: pointer to the cache that is being created
 * @size: size of objects to be created in this cache.
 * @align: required alignment for the objects.
 * @flags: slab allocation flags
 *
 * Also calculates the number of objects per slab.
 *
 * This could be made much more intelligent.  For now, try to avoid using
 * high order pages for slabs.  When the gfp() functions are more friendly
 * towards high-order requests, this should be changed.
 * 计算slab由几个页面组成，以及每个slab中存在多少个对象
 *
  所创建的“规则”的内存长度size，最终创建的slab将应该有多少个物理页面、有多少个这样size的对象、有多少碎片(碎片就是说申请的内存长度除了对象以外剩下的不能用的内存的长度)：
 */
static size_t calculate_slab_order(struct kmem_cache *cachep,
			size_t size, size_t align, unsigned long flags)
{
	unsigned long offslab_limit;
	size_t left_over = 0;
	int gfporder;

	for (gfporder = 0; gfporder <= KMALLOC_MAX_ORDER; gfporder++) {
		unsigned int num;
		size_t remainder;

        /* 计算slab中存在的对象数量和slab浪费的空间大小

          参数: gfporder: slab大小为2^gfporder个页面
                buffer_size: 对象大小
                align: 对象的对齐方式
                flags: 是外置slab还是内置slab
                remainder: slab中浪费的空间(碎片)是多少
                num: slab中对象个数

          通过上面的这个for循环，找到理想的slab长度。
          基于给定兑现给定对象的长度(buffer_size),cache_estimate针对特定的页数，
          来计算数目、浪费的空间、着色所需的空间。
        */
		cache_estimate(gfporder, size, align, flags, &remainder, &num);
		/* 如果num为0，则代表当前order的页面数连一个对象都无放入，需要扩大页面数 */
		if (!num)
			continue;

		/*摘抄一段网友的注释：http://blog.csdn.net/bullbat/article/details/7192845
        /* 创建一个外置式slab时，要相应分配该slab的管理对象，包含struct slab对象和kmem_bufctl_t数组，分配管理对象的流程就是分配普通对象的流程，
           再来看一下分配对象的流程：          
           kmem_cache_alloc->__cache_alloc-> __do_cache_alloc-> ____cache_alloc->
                 cache_alloc_refill->cache_grow-> alloc_slabmgmt-> kmem_cache_alloc_node-> kmem_cache_alloc 
           可以看出这里可能存在一个循环，循环的关键在于alloc_slabmgmt函数，当slab管理对象是off-slab方式时，就形成了循环
           那么什么时候slab管理对象会采用外置式slab呢？显然当其管理的slab中对象很多，从而kmem_bufctl_t数组很大，致使整个管理对象也很大，
           此时才会形成循环。故需要对kmem_bufctl_t的数目做限制，下面的算法是很粗略的，既然对象大小为size时，是外置式slab，
           那么我们假设管理对象的大小也是size，计算出kmem_bufctl_t数组的大小，即此大小的kmem_bufctl_t数组一定会造成管理对象是外置式slab。
           之所以说粗略，是指数组大小小于这个限制时，也不能确保管理对象一定是内置式slab。但这也不会引发错误，因为还有一个slab_break_gfp_order
           阀门来控制每个slab所占页面数，通常其值为1，即每个slab最多两个页面，外置式slab存放的都是大于512的大对象，所以slab中不会有太多的大对象，
           kmem_bufctl_t数组也不会很大，粗略判断一下就足够了。 
        */
		if (flags & CFLGS_OFF_SLAB) {
			/*
			 * Max number of objs-per-slab for caches which
			 * use off-slab slabs. Needed to avoid a possible
			 * looping condition in cache_grow().
			 */
			offslab_limit = size - sizeof(struct slab);
			offslab_limit /= sizeof(kmem_bufctl_t);

            /* 当前计算得到的对象数量，大于计算得到的限制时，就可以跳出循环了 */
 			if (num > offslab_limit)
				break;
		}

		/* Found something acceptable - save it away 
           slab中的对象数量
		*/
		cachep->num = num;
		/* slab由几个页面组成，见cache_estimate的计算过程 */
		cachep->gfporder = gfporder;

		/* slab中存在的碎片的大小，同样在cache_estimate中计算出来 */
		left_over = remainder;

		/*
		 * A VFS-reclaimable slab tends to have most allocations
		 * as GFP_NOFS and we really don't want to have to be allocating
		 * higher-order pages when we are unable to shrink dcache.
		 */
		 /*SLAB_RECLAIM_ACCOUNT表示此slab所占页面为可回收的，
		   当内核检测是否有足够的页面满足用户态的需求时，此类页面将被计算在内，
		   通过调用kmem_freepages()函数可以释放分配给slab的页框。由于是可回收的，
		   所以不需要做后面的碎片检测了
		  */
		if (flags & SLAB_RECLAIM_ACCOUNT)
			break;

		/*
		 * Large number of objects is good, but very large slabs are
		 * currently bad for the gfp()s.
		 */
		 
		/*slab_break_gfp_order初始化后为1，即slab最多是2^1 = 2个页*/
		/* 一旦超过slab页框允许的上限，则不再继续循环，直接使用当前的gfporder */
		if (gfporder >= slab_break_gfp_order)
			break;

		/*
		 * Acceptable internal fragmentation?
		 */
		 /*slab所占页面的大小是碎片大小的8倍以上，页面利用率较高，可以接受这样的order */
		 /* 判断一下，当前页面的利用率，当利用率满足下方条件时，不再继续循环 */
		if (left_over * 8 <= (PAGE_SIZE << gfporder))
			break;
	}

	/* 当前slab引入的碎片的大小 */
	return left_over;
}

/* 为该cachep创建其本地缓存(local cache,即cachep->array)和slab三链 
kmem_cache_create
  setup_cpu_cache
*/
static int __init_refok setup_cpu_cache(struct kmem_cache *cachep)
{
	/*  FULL在kmem_cache_init中赋值，
		此时普通cache已经初始化完成了，直接配置每个cpu的local cache */

	if (g_cpucache_up == FULL) /* slab系统已经初始化结束 */
		return enable_cpucache(cachep);

	if (g_cpucache_up == NONE) {
		/*
		 * Note: the first kmem_cache_create must create the cache
		 * that's used by kmalloc(24), otherwise the creation of
		 * further caches will BUG().
		 *
		 * 初始化阶段创建struct array_cache时走进这里，此时general cache尚未创建，只能使用静态的cache
		 */
		cachep->array[smp_processor_id()] = &initarray_generic.cache;

		/*
		 * If the cache that's used by kmalloc(sizeof(kmem_list3)) is
		 * the first cache, then we need to set up all its list3s,
		 * otherwise the creation of further caches will BUG().
		 * 
		 * kmem_list3的cache也未创建，使用全局变量
		 *
		 * 创建struct kmem_list3所在的cache是在struct array_cache所在cache之后,
		 * 所以此时struct kmem_list3所在的cache也一定没有创建，
		 * 也需要使用全局变量initkmem_list3
		 */
		set_up_list3s(cachep, SIZE_AC);


		 /*
		   执行到这struct array_cache所在的cache创建完毕，
		   如果struct kmem_list3和struct array_cache位于同一个general cache中，
		   不会再重复创建了(不过显然不可能)，       g_cpucache_up表示的进度更进一步
		  */
		if (INDEX_AC == INDEX_L3)
			g_cpucache_up = PARTIAL_L3;
		else
			g_cpucache_up = PARTIAL_AC;
	} else {
	    /*g_cpucache_up至少为PARTIAL_AC时进入这个流程，
	      struct arraycache_init所在的general cache已经建立起来，
	      可以通过kmalloc分配了*/

   	    /* general cache已经创建，使用kmalloc申请 */
		cachep->array[smp_processor_id()] =
			kmalloc(sizeof(struct arraycache_init), GFP_KERNEL);

		if (g_cpucache_up == PARTIAL_AC) {
			
			/* kmem_list3所在cache尚未创建完成，仍使用静态全局的slab三链 */
			set_up_list3s(cachep, SIZE_L3);
			/* 只有创建kmem_list3 cache时才会走进该流程，set_up_list3创建了kmem_list3的cache，更新进度 */
			g_cpucache_up = PARTIAL_L3;
		} else {
			 /*struct kmem_list3所在的cache和struct array_cache所在cache都已经创建完毕，无需全局变量*/
			int node;
			for_each_node_state(node, N_NORMAL_MEMORY) {
				/*通过kmalloc分配struct kmem_list3对象*/
				cachep->nodelists[node] =
				    kmalloc_node(sizeof(struct kmem_list3),
						GFP_KERNEL, node);
				BUG_ON(!cachep->nodelists[node]);
				 /*初始化slab三链*/
				kmem_list3_init(cachep->nodelists[node]);
			}
		}
	}
	cachep->nodelists[numa_node_id()]->next_reap =
			jiffies + REAPTIMEOUT_LIST3 +
			((unsigned long)cachep) % REAPTIMEOUT_LIST3;

	cpu_cache_get(cachep)->avail = 0;
	cpu_cache_get(cachep)->limit = BOOT_CPUCACHE_ENTRIES;
	cpu_cache_get(cachep)->batchcount = 1;
	cpu_cache_get(cachep)->touched = 0;
	cachep->batchcount = 1;
	cachep->limit = BOOT_CPUCACHE_ENTRIES;
	return 0;
}

/**
 * kmem_cache_create - Create a cache.
 * @name: A string which is used in /proc/slabinfo to identify this cache.
 * @size: The size of objects to be created in this cache.
 * @align: The required alignment for the objects.
 * @flags: SLAB flags
 * @ctor: A constructor for the objects.
 *
 * Returns a ptr to the cache on success, NULL on failure.
 * Cannot be called within a int, but can be interrupted.
 * The @ctor is run when new pages are allocated by the cache.
 *
 * @name must be valid until the cache is destroyed. This implies that
 * the module calling this has to destroy the cache before getting unloaded.
 *
 * The flags are
 *
 * %SLAB_POISON - Poison the slab with a known test pattern (a5a5a5a5)
 * to catch references to uninitialised memory.
 *
 * %SLAB_RED_ZONE - Insert `Red' zones around the allocated memory to check
 * for buffer overruns.
 *
 * %SLAB_HWCACHE_ALIGN - Align the objects in this cache to a hardware
 * cacheline.  This can be beneficial if you're counting cycles as closely
 * as davem.
 *
 * 创建成功后，cache中没有任何slab及对象，当分配对象时才会创建新的slab
 */
struct kmem_cache *
kmem_cache_create (const char *name, size_t size, size_t align,
	unsigned long flags,
	void (*ctor)(struct kmem_cache *, void *))
{
	size_t left_over, slab_size, ralign;
	struct kmem_cache *cachep = NULL, *pc;

	/*
	 * Sanity checks... these are all serious usage bugs.
	 * cache未指定名字，在中断上下文，对象大小小于sizeof(void ×)，对象大小大于KMALLOC_MAX_SIZE，则报错
	 * 不许在中断中调用本函数(本函数可能睡眠)
	 * 获取长度不得小于4字节(CPU字长)、获取长度不得大于最大值(1<<22 = 4MB
	 */
	if (!name || in_interrupt() || (size < BYTES_PER_WORD) ||
	    size > KMALLOC_MAX_SIZE) {
		printk(KERN_ERR "%s: Early error in slab %s\n", __FUNCTION__,
				name);
		BUG();
	}

	/*
	 * We use cache_chain_mutex to ensure a consistent view of
	 * cpu_online_map as well.  Please see cpuup_callback
	 * cache_chain由cache_chain_mutex保护
	 */
	mutex_lock(&cache_chain_mutex);

    /* 所有创建的cache都连接在cache_chain链表上，遍历链表检查是否有重名的cache */
	list_for_each_entry(pc, &cache_chain, next) {
		char tmp;
		int res;

		/*
		 * This happens when the module gets unloaded and doesn't
		 * destroy its slab cache and no-one else reuses the vmalloc
		 * area of the module.  Print a warning.
		 * 检查cache是否都有名字，没有名字则告警，并跳过
		 */
		res = probe_kernel_address(pc->name, tmp);
		if (res) {
			printk(KERN_ERR
			       "SLAB: cache with size %d has lost its name\n",
			       pc->buffer_size);
			continue;
		}

        /* 检查是否存在名字冲突的cache */
		if (!strcmp(pc->name, name)) {
			printk(KERN_ERR
			       "kmem_cache_create: duplicate cache %s\n", name);
			dump_stack();
			goto oops;
		}
	}

#if DEBUG
	WARN_ON(strchr(name, ' '));	/* It confuses parsers */
#if FORCED_DEBUG
	/*
	 * Enable redzoning and last user accounting, except for caches with
	 * large objects, if the increased size would increase the object size
	 * above the next power of two: caches with object sizes just above a
	 * power of two have a significant amount of internal fragmentation.
	 */
	if (size < 4096 || fls(size - 1) == fls(size-1 + REDZONE_ALIGN +
						2 * sizeof(unsigned long long)))
		flags |= SLAB_RED_ZONE | SLAB_STORE_USER;
	if (!(flags & SLAB_DESTROY_BY_RCU))
		flags |= SLAB_POISON;
#endif
	if (flags & SLAB_DESTROY_BY_RCU)
		BUG_ON(flags & SLAB_POISON);
#endif
	/*
	 * Always checks flags, a caller might be expecting debug support which
	 * isn't available.
	 */
	BUG_ON(flags & ~CREATE_MASK);

	/*
	 * Check that size is in terms of words.  This is needed to avoid
	 * unaligned accesses for some archs when redzoning is used, and makes
	 * sure any on-slab bufctl's are also correctly aligned.
	 *
	 * 下面是一堆关于对齐的内容
	 *
	 * size 按照BYTES_PER_WORD对齐
	 */
	if (size & (BYTES_PER_WORD - 1)) {
		size += (BYTES_PER_WORD - 1);
		size &= ~(BYTES_PER_WORD - 1);
	}

	/* calculate the final buffer alignment: */

	/* 1) arch recommendation: can be overridden for debug 
	   与硬件高速缓存行的cache_line_size对齐，根据size的大小决定对齐的单位
	 */
	if (flags & SLAB_HWCACHE_ALIGN) {
		/*
		 * Default alignment: as specified by the arch code.  Except if
		 * an object is really small, then squeeze multiple objects into
		 * one cacheline.
		 */
		ralign = cache_line_size();
		while (size <= ralign / 2)
			ralign /= 2;
	} else {
		ralign = BYTES_PER_WORD;
	}

	/*
	 * Redzoning and user store require word alignment or possibly larger.
	 * Note this will be overridden by architecture or caller mandated
	 * alignment if either is greater than BYTES_PER_WORD.
	 */
	if (flags & SLAB_STORE_USER)
		ralign = BYTES_PER_WORD;

	if (flags & SLAB_RED_ZONE) {
		ralign = REDZONE_ALIGN;
		/* If redzoning, ensure that the second redzone is suitably
		 * aligned, by adjusting the object size accordingly. */
		size += REDZONE_ALIGN - 1;
		size &= ~(REDZONE_ALIGN - 1);
	}

	/* 2) arch mandated alignment */
	if (ralign < ARCH_SLAB_MINALIGN) {
		ralign = ARCH_SLAB_MINALIGN;
	}
	/* 3) caller mandated alignment */
	if (ralign < align) {
		ralign = align;
	}
	/* disable debug if necessary */
	if (ralign > __alignof__(unsigned long long))
		flags &= ~(SLAB_RED_ZONE | SLAB_STORE_USER);
	/*
	 * 4) Store it.
	 */
	align = ralign;

	/* Get cache's description obj. 
	   从cache_cache缓存中分配一个kmem_cache新实例,
       申请kmem_cache结构，并初始化，cache_cache的对象正是struct kmem_cache结构
	*/
	cachep = kmem_cache_zalloc(&cache_cache, GFP_KERNEL);
	if (!cachep)
		goto oops;

#if DEBUG
	cachep->obj_size = size;

	/*
	 * Both debugging options require word-alignment which is calculated
	 * into align above.
	 */
	if (flags & SLAB_RED_ZONE) {
		/* add space for red zone words */
		cachep->obj_offset += sizeof(unsigned long long);
		size += 2 * sizeof(unsigned long long);
	}
	if (flags & SLAB_STORE_USER) {
		/* user store requires one word storage behind the end of
		 * the real object. But if the second red zone needs to be
		 * aligned to 64 bits, we must allow that much space.
		 */
		if (flags & SLAB_RED_ZONE)
			size += REDZONE_ALIGN;
		else
			size += BYTES_PER_WORD;
	}
#if FORCED_DEBUG && defined(CONFIG_DEBUG_PAGEALLOC)
	if (size >= malloc_sizes[INDEX_L3 + 1].cs_size
	    && cachep->obj_size > cache_line_size() && size < PAGE_SIZE) {
		cachep->obj_offset += PAGE_SIZE - size;
		size = PAGE_SIZE;
	}
#endif
#endif

	/*
	 * Determine if the slab management is 'on' or 'off' slab.
	 * (bootstrapping cannot cope with offslab caches so don't do
	 * it too early on.)
	 * 确定slab管理对象时采用内置还是外置的方式，
	 * 当对象大小超过512时(1/8的page时)，采用外置方式；初始化阶段使用内置方式 (kmem_cache_init中创建两个普通高速缓存之后就把变量slab_early_init置0了)
	 */
	if ((size >= (PAGE_SIZE >> 3)) && !slab_early_init)
		/* 
		 * Size is large, assume best to place the slab management obj
		 * off-slab (should allow better packing of objs).
		 */
		flags |= CFLGS_OFF_SLAB;

    /* 按照之前计算的对齐单元，调整size的大小 */
	size = ALIGN(size, align);

    /*计算碎片大小，计算slab由几个页面组成，同时计算每个slab中有多少对象*/
	left_over = calculate_slab_order(cachep, size, align, flags);

    /*  num代表了当前cache允许每个slab中存在的对象数，正常不应该为0 */
	if (!cachep->num) {
		printk(KERN_ERR
		       "kmem_cache_create: couldn't create cache %s.\n", name);
		kmem_cache_free(&cache_cache, cachep);
		cachep = NULL;
		goto oops;
	}

	/* 计算slab管理对象的大小，包括slab和kmem_bufctl_t数组 */
	slab_size = ALIGN(cachep->num * sizeof(kmem_bufctl_t)
			  + sizeof(struct slab), align);

	/*
	 * If the slab has been placed off-slab, and we have enough space then
	 * move it on-slab. This is at the expene of any extra colouring.
	 *
	 * 如果碎片大小已经超过了管理对象的大小，并且是slab管理对象外置的话，可以直接移进slab中
	 */
	if (flags & CFLGS_OFF_SLAB && left_over >= slab_size) {
		/* 取消外置的标签，此时是内置的 */
		flags &= ~CFLGS_OFF_SLAB;
		/* 碎片的大小可以减去管理对象的大小了 */
		left_over -= slab_size;
	}
	
    /* 如果是外置的，则slab_size按照不对齐的方式重新计算一下大小  */
	if (flags & CFLGS_OFF_SLAB) {
		/* really off slab. No need for manual alignment */
		slab_size =
		    cachep->num * sizeof(kmem_bufctl_t) + sizeof(struct slab);
	}

    /*  记录着色块的大小，cache_line_size(),32字节 */
	cachep->colour_off = cache_line_size();
	/* Offset must be a multiple of the alignment. 
       着色块单位必须是对齐单位的整数倍
	*/
	if (cachep->colour_off < align)
		cachep->colour_off = align;
	
	/* 计算碎片区需要多少着色块 */
	cachep->colour = left_over / cachep->colour_off;
	/* 记录slab管理对象的大小 */
	cachep->slab_size = slab_size;
	cachep->flags = flags;
	cachep->gfpflags = 0;
	/* 如果当前kernel配置了DMA，并且函数指定了DMA参数，则在cache上打上DMA的标签 */
	if (CONFIG_ZONE_DMA_FLAG && (flags & SLAB_CACHE_DMA))
		cachep->gfpflags |= GFP_DMA;
	/* 记录每个slab对象的大小 */
	cachep->buffer_size = size;
	/* 
	   slab对象的大小的倒数，计算对象在slab中索引时用，参见obj_to_index函数
	   cachep->reciprocal_buffer_size = 1/ cachep->buffer_size ;
	*/
	cachep->reciprocal_buffer_size = reciprocal_value(size);

      /*外置slab，这里分配一个slab管理对象，保存在slabp_cache中，如果是内置式的slab，此指针为空*/
	if (flags & CFLGS_OFF_SLAB) {
		/* 分配一个slab管理区对象，保存在cachep->slabp_cache中
           函数传入的slab_size是管理区对象的大小，如果是slab管理区是外置的，则从slab_size大小的普通cache中申请对象 
           这里找到对应的kmem_cache并记录下来，如果是内置的，则slabp_cache为NULL
		*/
		cachep->slabp_cache = kmem_find_general_cachep(slab_size, 0u);
		/*
		 * This is a possibility for one of the malloc_sizes caches.
		 * But since we go off slab only for object size greater than
		 * PAGE_SIZE/8, and malloc_sizes gets created in ascending order,
		 * this should not happen at all.
		 * But leave a BUG_ON for some lucky dude.
		 */
		BUG_ON(ZERO_OR_NULL_PTR(cachep->slabp_cache));
	}
	/*  设置构造函数，名字 */
	cachep->ctor = ctor;
	cachep->name = name;

	
    /*设置每个cpu上的local cache，配置local cache和slab三链
      设置cachep->array[smp_processor_id()] = kmalloc...
	*/
	if (setup_cpu_cache(cachep)) {
		__kmem_cache_destroy(cachep);
		cachep = NULL;
		goto oops;
	}

	/* cache setup completed, link it into the list 
       cache创建完毕，将其加入全局的cache_chain上
	*/
	list_add(&cachep->next, &cache_chain);
oops:
	if (!cachep && (flags & SLAB_PANIC))
		panic("kmem_cache_create(): failed to create slab `%s'\n",
		      name);
	mutex_unlock(&cache_chain_mutex);
	return cachep;
}
EXPORT_SYMBOL(kmem_cache_create);

#if DEBUG
static void check_irq_off(void)
{
	BUG_ON(!irqs_disabled());
}

static void check_irq_on(void)
{
	BUG_ON(irqs_disabled());
}

static void check_spinlock_acquired(struct kmem_cache *cachep)
{
#ifdef CONFIG_SMP
	check_irq_off();
	assert_spin_locked(&cachep->nodelists[numa_node_id()]->list_lock);
#endif
}

static void check_spinlock_acquired_node(struct kmem_cache *cachep, int node)
{
#ifdef CONFIG_SMP
	check_irq_off();
	assert_spin_locked(&cachep->nodelists[node]->list_lock);
#endif
}

#else
#define check_irq_off()	do { } while(0)
#define check_irq_on()	do { } while(0)
#define check_spinlock_acquired(x) do { } while(0)
#define check_spinlock_acquired_node(x, y) do { } while(0)
#endif

static void drain_array(struct kmem_cache *cachep, struct kmem_list3 *l3,
			struct array_cache *ac,
			int force, int node);

static void do_drain(void *arg)
{
	struct kmem_cache *cachep = arg;
	struct array_cache *ac;
	int node = numa_node_id();

	check_irq_off();
	ac = cpu_cache_get(cachep);
	spin_lock(&cachep->nodelists[node]->list_lock);
	free_block(cachep, ac->entry, ac->avail, node);
	spin_unlock(&cachep->nodelists[node]->list_lock);
	ac->avail = 0;
}

static void drain_cpu_caches(struct kmem_cache *cachep)
{
	struct kmem_list3 *l3;
	int node;

	on_each_cpu(do_drain, cachep, 1, 1);
	check_irq_on();
	for_each_online_node(node) {
		l3 = cachep->nodelists[node];
		if (l3 && l3->alien)
			drain_alien_cache(cachep, l3->alien);
	}

	for_each_online_node(node) {
		l3 = cachep->nodelists[node];
		if (l3)
			drain_array(cachep, l3, l3->shared, 1, node);
	}
}

/*
 * Remove slabs from the list of free slabs.
 * Specify the number of slabs to drain in tofree.
 *
 * Returns the actual number of slabs released.
 */
static int drain_freelist(struct kmem_cache *cache,
			struct kmem_list3 *l3, int tofree)
{
	struct list_head *p;
	int nr_freed;
	struct slab *slabp;

	nr_freed = 0;
	while (nr_freed < tofree && !list_empty(&l3->slabs_free)) {

		spin_lock_irq(&l3->list_lock);
		p = l3->slabs_free.prev;
		if (p == &l3->slabs_free) {
			spin_unlock_irq(&l3->list_lock);
			goto out;
		}

		slabp = list_entry(p, struct slab, list);
#if DEBUG
		BUG_ON(slabp->inuse);
#endif
		list_del(&slabp->list);
		/*
		 * Safe to drop the lock. The slab is no longer linked
		 * to the cache.
		 */
		l3->free_objects -= cache->num;
		spin_unlock_irq(&l3->list_lock);
		slab_destroy(cache, slabp);
		nr_freed++;
	}
out:
	return nr_freed;
}

/* Called with cache_chain_mutex held to protect against cpu hotplug */
static int __cache_shrink(struct kmem_cache *cachep)
{
	int ret = 0, i = 0;
	struct kmem_list3 *l3;

	drain_cpu_caches(cachep);

	check_irq_on();
	for_each_online_node(i) {
		l3 = cachep->nodelists[i];
		if (!l3)
			continue;

		drain_freelist(cachep, l3, l3->free_objects);

		ret += !list_empty(&l3->slabs_full) ||
			!list_empty(&l3->slabs_partial);
	}
	return (ret ? 1 : 0);
}

/**
 * kmem_cache_shrink - Shrink a cache.
 * @cachep: The cache to shrink.
 *
 * Releases as many slabs as possible for a cache.
 * To help debugging, a zero exit status indicates all slabs were released.
 */
int kmem_cache_shrink(struct kmem_cache *cachep)
{
	int ret;
	BUG_ON(!cachep || in_interrupt());

	mutex_lock(&cache_chain_mutex);
	ret = __cache_shrink(cachep);
	mutex_unlock(&cache_chain_mutex);
	return ret;
}
EXPORT_SYMBOL(kmem_cache_shrink);

/**
 * kmem_cache_destroy - delete a cache
 * @cachep: the cache to destroy
 *
 * Remove a &struct kmem_cache object from the slab cache.
 *
 * It is expected this function will be called by a module when it is
 * unloaded.  This will remove the cache completely, and avoid a duplicate
 * cache being allocated each time a module is loaded and unloaded, if the
 * module doesn't have persistent in-kernel storage across loads and unloads.
 *
 * The cache must be empty before calling this function.
 *
 * The caller must guarantee that noone will allocate memory from the cache
 * during the kmem_cache_destroy().
 */
void kmem_cache_destroy(struct kmem_cache *cachep)
{
	BUG_ON(!cachep || in_interrupt());

	/* Find the cache in the chain of caches. */
	mutex_lock(&cache_chain_mutex);
	/*
	 * the chain is never empty, cache_cache is never destroyed
	 */
	list_del(&cachep->next);
	if (__cache_shrink(cachep)) {
		slab_error(cachep, "Can't free all objects");
		list_add(&cachep->next, &cache_chain);
		mutex_unlock(&cache_chain_mutex);
		return;
	}

	if (unlikely(cachep->flags & SLAB_DESTROY_BY_RCU))
		synchronize_rcu();

	__kmem_cache_destroy(cachep);
	mutex_unlock(&cache_chain_mutex);
}
EXPORT_SYMBOL(kmem_cache_destroy);

/*
 * Get the memory for a slab management obj.
 * For a slab cache when the slab descriptor is off-slab, slab descriptors
 * always come from malloc_sizes caches.  The slab descriptor cannot
 * come from the same cache which is getting created because,
 * when we are searching for an appropriate cache for these
 * descriptors in kmem_cache_create, we search through the malloc_sizes array.
 * If we are creating a malloc_sizes cache here it would not be visible to
 * kmem_find_general_cachep till the initialization is complete.
 * Hence we cannot have slabp_cache same as the original cache.
 *
 kmem_cache_alloc
 __cache_alloc
  __do_cache_alloc
   ____cache_alloc
    cache_alloc_refill
     cache_grow
      alloc_slabmgmt
 */
 /* 申请slab管理对象 */
static struct slab *alloc_slabmgmt(struct kmem_cache *cachep, void *objp,
				   int colour_off, gfp_t local_flags,
				   int nodeid)
{
	struct slab *slabp;

     /* 是否为外置slab */
	if (OFF_SLAB(cachep)) {
		/* Slab management obj is off-slab. */
	    /* 外置slab，从slabp_cache中申请一个对象，slabp_cache是在初始化阶段被设置上的 */
		slabp = kmem_cache_alloc_node(cachep->slabp_cache,
					      local_flags & ~GFP_THISNODE, nodeid);
		if (!slabp)
			return NULL;
	} else {
	    /* 内置slab */
        /* objp为slab的首页面的虚拟地址，根据着色偏移，计算slabp管理对象的地址 */
		slabp = objp + colour_off;
		/* slab_size是管理对象大小，包含了slab和kmem_bufctl，此处计算第一个slab对象的偏移量 */
		colour_off += cachep->slab_size;
	}
	/* 新申请的slab对象，已用对象数为0 */
	slabp->inuse = 0;
	/* 第1个对象的页面偏移 */
    /* 内置slab，则为着色区偏移+slab_size；外置slab，则为着色区偏移 */
	slabp->colouroff = colour_off;
	/* 第一个对象的虚拟地址 */
	slabp->s_mem = objp + colour_off;
	/* slab所属于的NUMA节点ID */
	slabp->nodeid = nodeid;
	return slabp;
}

/* 取得kmem_bufctl_t数组的首地址 */
static inline kmem_bufctl_t *slab_bufctl(struct slab *slabp)
{
                             /* slabp+1就是跳过sizeof(struct slab)大小的空闲，然后就是kmem_bufctl_t数组 */
	return (kmem_bufctl_t *) (slabp + 1);
}

/*
 kmem_cache_alloc
 __cache_alloc
  __do_cache_alloc
   ____cache_alloc
    cache_alloc_refill
     cache_grow
      cache_init_objs
 */
static void cache_init_objs(struct kmem_cache *cachep,
			    struct slab *slabp)
{
	int i;
    /* index_to_obj: slab->s_mem + cache->buffer_size * idx */
    /* s_mem为第一个对象的起始地址，buffer_size为对象的大小，idx为索引 */
	for (i = 0; i < cachep->num; i++) {
		 /* 遍历slab中的所有对象，先获取对象的地址 */
		void *objp = index_to_obj(cachep, slabp, i);
#if DEBUG
		/* need to poison the objs? */
		if (cachep->flags & SLAB_POISON)
			poison_obj(cachep, objp, POISON_FREE);
		if (cachep->flags & SLAB_STORE_USER)
			*dbg_userword(cachep, objp) = NULL;

		if (cachep->flags & SLAB_RED_ZONE) {
			*dbg_redzone1(cachep, objp) = RED_INACTIVE;
			*dbg_redzone2(cachep, objp) = RED_INACTIVE;
		}
		/*
		 * Constructors are not allowed to allocate memory from the same
		 * cache which they are a constructor for.  Otherwise, deadlock.
		 * They must also be threaded.
		 */
		if (cachep->ctor && !(cachep->flags & SLAB_POISON))
			cachep->ctor(cachep, objp + obj_offset(cachep));

		if (cachep->flags & SLAB_RED_ZONE) {
			if (*dbg_redzone2(cachep, objp) != RED_INACTIVE)
				slab_error(cachep, "constructor overwrote the"
					   " end of an object");
			if (*dbg_redzone1(cachep, objp) != RED_INACTIVE)
				slab_error(cachep, "constructor overwrote the"
					   " start of an object");
		}
		if ((cachep->buffer_size % PAGE_SIZE) == 0 &&
			    OFF_SLAB(cachep) && cachep->flags & SLAB_POISON)
			kernel_map_pages(virt_to_page(objp),
					 cachep->buffer_size / PAGE_SIZE, 0);
#else
        /* 如果cache指定了构造函数，则使用构造函数进行初始化 */
		if (cachep->ctor)
			cachep->ctor(cachep, objp);
#endif
		/* slab_bufctl:  (kmem_bufctl_t *) (slabp + 1) */
		/* kmem_bufctl数组紧接着struct slab存放，其中每个成员的值都代表了下一个可用对象的索引 */
		/* 建立静态数组的索引，其中slab->free指向了下一个可用的空闲对象，然后slab_bufctl(slabp)[slab->free]指向了下一个可用对象的索引 */
		slab_bufctl(slabp)[i] = i + 1;
	}
	
	/* 最后一个元素指向BUCTL_END，代表无法继续获取空闲对象 */
	slab_bufctl(slabp)[i - 1] = BUFCTL_END;
	slabp->free = 0;
}

static void kmem_flagcheck(struct kmem_cache *cachep, gfp_t flags)
{
	if (CONFIG_ZONE_DMA_FLAG) {
		if (flags & GFP_DMA)
			BUG_ON(!(cachep->gfpflags & GFP_DMA));
		else
			BUG_ON(cachep->gfpflags & GFP_DMA);
	}
}

/* 从slabp中得到一个可以被分配的空闲对象 */
static void *slab_get_obj(struct kmem_cache *cachep, struct slab *slabp,
				int nodeid)
{
    /* 获取空闲对象，free是slabp中第一个空闲对象索引 
     *  s_mem是指向Slab对象的内存起始地址，buffer_size是对象的大小包括colour offset.
     */
    /* index_to_obj:  slab->s_mem + cache->buffer_size * idx; s_mem是slab中第一个对象的起始地址，buffer_size是每个对象的大小*/
	void *objp = index_to_obj(cachep, slabp, slabp->free);
	kmem_bufctl_t next;

	/* 更新当前slab中活跃对象的数量 */
	slabp->inuse++;
	/* 获取下一个空闲对象的索引      */
	next = slab_bufctl(slabp)[slabp->free];
#if DEBUG
	slab_bufctl(slabp)[slabp->free] = BUFCTL_FREE;
	WARN_ON(slabp->nodeid != nodeid);
#endif
    /* 指向下一个空闲对象索引 */
	slabp->free = next;

	return objp;
}

static void slab_put_obj(struct kmem_cache *cachep, struct slab *slabp,
				void *objp, int nodeid)
{
    /* 首先求的Slab对象的索引值 */
	unsigned int objnr = obj_to_index(cachep, slabp, objp);

#if DEBUG
	/* Verify that the slab belongs to the intended node */
	WARN_ON(slabp->nodeid != nodeid);

	if (slab_bufctl(slabp)[objnr] + 1 <= SLAB_LIMIT + 1) {
		printk(KERN_ERR "slab: double free detected in cache "
				"'%s', objp %p\n", cachep->name, objp);
		BUG();
	}
#endif

	slab_bufctl(slabp)[objnr] = slabp->free;
	slabp->free = objnr;
	slabp->inuse--;
}

/*
 * Map pages beginning at addr to the given cache and slab. This is required
 * for the slab allocator to be able to lookup the cache and slab of a
 * virtual address for kfree, ksize, kmem_ptr_validate, and slab debugging.
 *
 * 建立slab/cache与page之间的映射，
 * 可以通过page的lru链表找到page所属的slab和cache
 *
 kmem_cache_alloc
 __cache_alloc
  __do_cache_alloc
   ____cache_alloc
    cache_alloc_refill
     cache_grow
      slab_map_pages
 */
 /* cache/slab地址，以及addr 虚拟页面的首地址 */
static void slab_map_pages(struct kmem_cache *cache, struct slab *slab,
			   void *addr)
{
	int nr_pages;
	struct page *page;

	page = virt_to_page(addr);

	nr_pages = 1;
	/* 如果不是大页面，则计算页面个数 */
	if (likely(!PageCompound(page)))
		nr_pages <<= cache->gfporder;

	do {
		/* 当page用于slab时，page的lru->next指向page所在cache, lru->prev指向page所在的slab */
        /* 当page空闲时，lru负责将page串联在一起 */
		page_set_cache(page, cache);
		page_set_slab(page, slab);
		page++;
	} while (--nr_pages);
}

/*
 * Grow (by 1) the number of slabs within a cache.  This is called by
 * kmem_cache_alloc() when there are no active objs left in a cache.
 *
 * cachep: 需要扩容的cache;  flags: 是否可以阻塞等； nodeid：对应的NUMA节点ID； 
   objp: 页面虚拟地址，为NULL代表尚未申请到页面；不为空代表已经申请，可以直接创建slab

kmem_cache_alloc
 __cache_alloc
  __do_cache_alloc
   ____cache_alloc
    cache_alloc_refill
     cache_grow
     分配一个slab对象和存储空间的页面,放入到cachep->slabs_free上去
 */
static int cache_grow(struct kmem_cache *cachep,
		gfp_t flags, int nodeid, void *objp)
{
	struct slab *slabp;
	size_t offset;
	gfp_t local_flags;
	struct kmem_list3 *l3;

	/*
	 * Be lazy and only check for valid flags here,  keeping it out of the
	 * critical path in kmem_cache_alloc().
	 */
	BUG_ON(flags & GFP_SLAB_BUG_MASK);
	local_flags = flags & (GFP_CONSTRAINT_MASK|GFP_RECLAIM_MASK);

	/* Take the l3 list lock to change the colour_next on this node */
	check_irq_off();
	
	/* 根据NUMA节点ID获取slab三链 */
	l3 = cachep->nodelists[nodeid];
	spin_lock(&l3->list_lock);

	/* Get colour for the slab, and cal the next value. */
	/* 获取slab的着色偏移 */
	offset = l3->colour_next;
	/* 更新着色偏移，使不同slab的着色偏移不同 */
	l3->colour_next++;
	/* 不能超过着色区的大小，否则重新循环 */
	if (l3->colour_next >= cachep->colour)
		l3->colour_next = 0;
	spin_unlock(&l3->list_lock);

    /* 根据着色区个数*着色偏移，计算着色区的大小 */
	offset *= cachep->colour_off;

	/* 是否允许阻塞，否则开启硬中断 */
	if (local_flags & __GFP_WAIT)
		local_irq_enable();

	/*
	 * The test for missing atomic flag is performed here, rather than
	 * the more obvious place, simply to reduce the critical path length
	 * in kmem_cache_alloc(). If a caller is seriously mis-behaving they
	 * will eventually be caught here (where it matters).
	 */
	kmem_flagcheck(cachep, flags);

	/*
	 * Get mem for the objs.  Attempt to allocate a physical page from
	 * 'nodeid'.
	 
	 是否已经申请页面，如尚未申请，则先申请 
     分配1<gfporder个页面，objp为slab首页面地址 
	 */
	if (!objp)  /* 分配2^cachep->gfporder个page */
		objp = kmem_getpages(cachep, local_flags, nodeid);
	if (!objp)
		goto failed;

	/* Get slab management. */
	/* 分配slab管理对象 */
	slabp = alloc_slabmgmt(cachep, objp, offset,
			local_flags & ~GFP_CONSTRAINT_MASK, nodeid);
	if (!slabp)
		goto opps1;

    
	slabp->nodeid = nodeid;
	/* 设置page到cache slab的映射
	 * 设置各个page->lru.next = cachep
	 *         page->lru.prev = slabp
	 */
	slab_map_pages(cachep, slabp, objp);

    /* 初始化slab中的对象 */
	cache_init_objs(cachep, slabp);

	if (local_flags & __GFP_WAIT)
		local_irq_disable();
	check_irq_off();
	spin_lock(&l3->list_lock);

	/* Make slab active. */
	/* 将申请到的slab挂入free链表上 */
	list_add_tail(&slabp->list, &(l3->slabs_free));
	/* 增加计数 */
	STATS_INC_GROWN(cachep);
	/* 更新空闲对象数量 */
	l3->free_objects += cachep->num;
	spin_unlock(&l3->list_lock);
	return 1;
opps1:
	kmem_freepages(cachep, objp);
failed:
	if (local_flags & __GFP_WAIT)
		local_irq_disable();
	return 0;
}

#if DEBUG

/*
 * Perform extra freeing checks:
 * - detect bad pointers.
 * - POISON/RED_ZONE checking
 */
static void kfree_debugcheck(const void *objp)
{
	if (!virt_addr_valid(objp)) {
		printk(KERN_ERR "kfree_debugcheck: out of range ptr %lxh.\n",
		       (unsigned long)objp);
		BUG();
	}
}

static inline void verify_redzone_free(struct kmem_cache *cache, void *obj)
{
	unsigned long long redzone1, redzone2;

	redzone1 = *dbg_redzone1(cache, obj);
	redzone2 = *dbg_redzone2(cache, obj);

	/*
	 * Redzone is ok.
	 */
	if (redzone1 == RED_ACTIVE && redzone2 == RED_ACTIVE)
		return;

	if (redzone1 == RED_INACTIVE && redzone2 == RED_INACTIVE)
		slab_error(cache, "double free detected");
	else
		slab_error(cache, "memory outside object was overwritten");

	printk(KERN_ERR "%p: redzone 1:0x%llx, redzone 2:0x%llx.\n",
			obj, redzone1, redzone2);
}

static void *cache_free_debugcheck(struct kmem_cache *cachep, void *objp,
				   void *caller)
{
	struct page *page;
	unsigned int objnr;
	struct slab *slabp;

	BUG_ON(virt_to_cache(objp) != cachep);

	objp -= obj_offset(cachep);
	kfree_debugcheck(objp);
	page = virt_to_head_page(objp);

	slabp = page_get_slab(page);

	if (cachep->flags & SLAB_RED_ZONE) {
		verify_redzone_free(cachep, objp);
		*dbg_redzone1(cachep, objp) = RED_INACTIVE;
		*dbg_redzone2(cachep, objp) = RED_INACTIVE;
	}
	if (cachep->flags & SLAB_STORE_USER)
		*dbg_userword(cachep, objp) = caller;

	objnr = obj_to_index(cachep, slabp, objp);

	BUG_ON(objnr >= cachep->num);
	BUG_ON(objp != index_to_obj(cachep, slabp, objnr));

#ifdef CONFIG_DEBUG_SLAB_LEAK
	slab_bufctl(slabp)[objnr] = BUFCTL_FREE;
#endif
	if (cachep->flags & SLAB_POISON) {
#ifdef CONFIG_DEBUG_PAGEALLOC
		if ((cachep->buffer_size % PAGE_SIZE)==0 && OFF_SLAB(cachep)) {
			store_stackinfo(cachep, objp, (unsigned long)caller);
			kernel_map_pages(virt_to_page(objp),
					 cachep->buffer_size / PAGE_SIZE, 0);
		} else {
			poison_obj(cachep, objp, POISON_FREE);
		}
#else
		poison_obj(cachep, objp, POISON_FREE);
#endif
	}
	return objp;
}

static void check_slabp(struct kmem_cache *cachep, struct slab *slabp)
{
	kmem_bufctl_t i;
	int entries = 0;

	/* Check slab's freelist to see if this obj is there. */
	for (i = slabp->free; i != BUFCTL_END; i = slab_bufctl(slabp)[i]) {
		entries++;
		if (entries > cachep->num || i >= cachep->num)
			goto bad;
	}
	if (entries != cachep->num - slabp->inuse) {
bad:
		printk(KERN_ERR "slab: Internal list corruption detected in "
				"cache '%s'(%d), slabp %p(%d). Hexdump:\n",
			cachep->name, cachep->num, slabp, slabp->inuse);
		for (i = 0;
		     i < sizeof(*slabp) + cachep->num * sizeof(kmem_bufctl_t);
		     i++) {
			if (i % 16 == 0)
				printk("\n%03x:", i);
			printk(" %02x", ((unsigned char *)slabp)[i]);
		}
		printk("\n");
		BUG();
	}
}
#else
#define kfree_debugcheck(x) do { } while(0)
#define cache_free_debugcheck(x,objp,z) (objp)
#define check_slabp(x,y) do { } while(0)
#endif

/* 
kmem_cache->array[cpuid]中没有空闲空间了，才调用这个函数

kmem_cache_alloc
  __cache_alloc
     __do_cache_alloc
        ____cache_alloc
           cache_alloc_refill

*/
static void *cache_alloc_refill(struct kmem_cache *cachep, gfp_t flags)
{
	int batchcount;
	struct kmem_list3 *l3;
	struct array_cache *ac;
	int node;

    /* 获取当前的NUMA节点 */
	node = numa_node_id();

	check_irq_off();
	/* 获取local cache(cachep->array[cpuid]) */
	ac = cpu_cache_get(cachep);
retry:
	batchcount = ac->batccount;
	/* 如果最近未使用过该local cache，则一次填充的上限为BATCHREFILL_LIMIT个 */
	if (!ac->touched && batchcount > BATCHREFILL_LIMIT) {
		/*
		 * If there was little recent activity on this cache, then
		 * perform only a partial refill.  Otherwise we could generate
		 * refill bouncing.
		 */
		batchcount = BATCHREFILL_LIMIT;
	}
	/* 获取本内存节点的kmem_list3的几个slab链表 */
	l3 = cachep->nodelists[node];

	BUG_ON(ac->avail > 0 || !l3);
	spin_lock(&l3->list_lock);

	/* See if we can refill from the shared array 
	
    /* shared local cache 用于多核中，所有cpu共享，首先从shared中批量获取slab对象到local 
       从l3->shared移动batchcount个已经被回收的对象到ac中去
	*/
	if (l3->shared && transfer_objects(ac, l3->shared, batchcount))
		goto alloc_done;

   /* 如果l3->shared==NULL，或者已无空闲对象空间，则从slab链表中分配 */
	while (batchcount > 0) {
		struct list_head *entry;
		struct slab *slabp;
		/* Get slab alloc is to come from. */
		/* 先从部分未满的slab链表中分配 */
		entry = l3->slabs_partial.next;
		/* 判断是否为空 */
		if (entry == &l3->slabs_partial) {
			/* 标示刚访问了空链表 */
			l3->free_touched = 1;
			entry = l3->slabs_free.next;
            /* 如果空链表为空，则必须新增slab */
			if (entry == &l3->slabs_free)
				goto must_grow;/* 去新增slab */
		}
		
        /* 从链表上获取到了一个slab */
		slabp = list_entry(entry, struct slab, list);
		check_slabp(cachep, slabp);
		check_spinlock_acquired(cachep);

		/*
		 * The slab was either on partial or free list so
		 * there must be at least one object available for
		 * allocation.
		 */
		BUG_ON(slabp->inuse < 0 || slabp->inuse >= cachep->num);
        /* 当前slab的对象活跃数必须小于每个slab的最大对象数 */
		while (slabp->inuse < cachep->num && batchcount--) {
			STATS_INC_ALLOCED(cachep);
			STATS_INC_ACTIVE(cachep);
			STATS_SET_HIGH(cachep);
			
            /* 从slab中提取空闲对象，将虚拟地址插入到local cache(array_cache)中 */
			ac->entry[ac->avail++] = slab_get_obj(cachep, slabp, node);
		}
		check_slabp(cachep, slabp);

		/* move slabp to correct slabp list: */
		/* 从原链表中删除slab,重新设置slab到full或者partial队列中去 */
		list_del(&slabp->list);
		if (slabp->free == BUFCTL_END)
			/* 此slab中已经没有空闲对象，移动到full链表中 */
			list_add(&slabp->list, &l3->slabs_full);
		else
			/* 此slab中还有空闲对象，移动到partial链表中 */
			list_add(&slabp->list, &l3->slabs_partial);
	}

must_grow:
    /* 从slab链表中添加了avail个空闲对象到local cache中，空闲的对象数量需要更新一下 */
	l3->free_objects -= ac->avail;
alloc_done:
	spin_unlock(&l3->list_lock);

    /* ac->avial==0说明上面用到slab链表中拉一批空闲对象到ac中去，
       说明slab链表也无空闲对象，要创建新的slab 
     */
	if (unlikely(!ac->avail)) {
		int x;
		/* 创建空slab到当前node的slab list上去 */
		x = cache_grow(cachep, flags | GFP_THISNODE, node, NULL);

		/* cache_grow can reenable interrupts, then ac could change. */
		/* 看注释，由于cache_grow开启了中断，local cache指针可能发生变化，ac需要重新获取 
         * cachep->array[cpuid]
		 */
		ac = cpu_cache_get(cachep);
		/* 新的slab创建失败 */
		if (!x && ac->avail == 0)	/* no objects in sight? abort */
			return NULL;
		
        /* 新增slab成功，重新填充local cache */
 		if (!ac->avail)		/* objects refilled by interrupt? */
			goto retry;
	}
	/* 设置近期访问的标志 */
	ac->touched = 1;
	/* 返回空闲对象的地址 */
	return ac->entry[--ac->avail];
}

static inline void cache_alloc_debugcheck_before(struct kmem_cache *cachep,
						gfp_t flags)
{
	might_sleep_if(flags & __GFP_WAIT);
#if DEBUG
	kmem_flagcheck(cachep, flags);
#endif
}

#if DEBUG
static void *cache_alloc_debugcheck_after(struct kmem_cache *cachep,
				gfp_t flags, void *objp, void *caller)
{
	if (!objp)
		return objp;
	if (cachep->flags & SLAB_POISON) {
#ifdef CONFIG_DEBUG_PAGEALLOC
		if ((cachep->buffer_size % PAGE_SIZE) == 0 && OFF_SLAB(cachep))
			kernel_map_pages(virt_to_page(objp),
					 cachep->buffer_size / PAGE_SIZE, 1);
		else
			check_poison_obj(cachep, objp);
#else
		check_poison_obj(cachep, objp);
#endif
		poison_obj(cachep, objp, POISON_INUSE);
	}
	if (cachep->flags & SLAB_STORE_USER)
		*dbg_userword(cachep, objp) = caller;

	if (cachep->flags & SLAB_RED_ZONE) {
		if (*dbg_redzone1(cachep, objp) != RED_INACTIVE ||
				*dbg_redzone2(cachep, objp) != RED_INACTIVE) {
			slab_error(cachep, "double free, or memory outside"
						" object was overwritten");
			printk(KERN_ERR
				"%p: redzone 1:0x%llx, redzone 2:0x%llx\n",
				objp, *dbg_redzone1(cachep, objp),
				*dbg_redzone2(cachep, objp));
		}
		*dbg_redzone1(cachep, objp) = RED_ACTIVE;
		*dbg_redzone2(cachep, objp) = RED_ACTIVE;
	}
#ifdef CONFIG_DEBUG_SLAB_LEAK
	{
		struct slab *slabp;
		unsigned objnr;

		slabp = page_get_slab(virt_to_head_page(objp));
		objnr = (unsigned)(objp - slabp->s_mem) / cachep->buffer_size;
		slab_bufctl(slabp)[objnr] = BUFCTL_ACTIVE;
	}
#endif
	objp += obj_offset(cachep);
	if (cachep->ctor && cachep->flags & SLAB_POISON)
		cachep->ctor(cachep, objp);
#if ARCH_SLAB_MINALIGN
	if ((u32)objp & (ARCH_SLAB_MINALIGN-1)) {
		printk(KERN_ERR "0x%p: not aligned to ARCH_SLAB_MINALIGN=%d\n",
		       objp, ARCH_SLAB_MINALIGN);
	}
#endif
	return objp;
}
#else
#define cache_alloc_debugcheck_after(a,b,objp,d) (objp)
#endif

#ifdef CONFIG_FAILSLAB

static struct failslab_attr {

	struct fault_attr attr;

	u32 ignore_gfp_wait;
#ifdef CONFIG_FAULT_INJECTION_DEBUG_FS
	struct dentry *ignore_gfp_wait_file;
#endif

} failslab = {
	.attr = FAULT_ATTR_INITIALIZER,
	.ignore_gfp_wait = 1,
};

static int __init setup_failslab(char *str)
{
	return setup_fault_attr(&failslab.attr, str);
}
__setup("failslab=", setup_failslab);

static int should_failslab(struct kmem_cache *cachep, gfp_t flags)
{
	if (cachep == &cache_cache)
		return 0;
	if (flags & __GFP_NOFAIL)
		return 0;
	if (failslab.ignore_gfp_wait && (flags & __GFP_WAIT))
		return 0;

	return should_fail(&failslab.attr, obj_size(cachep));
}

#ifdef CONFIG_FAULT_INJECTION_DEBUG_FS

static int __init failslab_debugfs(void)
{
	mode_t mode = S_IFREG | S_IRUSR | S_IWUSR;
	struct dentry *dir;
	int err;

	err = init_fault_attr_dentries(&failslab.attr, "failslab");
	if (err)
		return err;
	dir = failslab.attr.dentries.dir;

	failslab.ignore_gfp_wait_file =
		debugfs_create_bool("ignore-gfp-wait", mode, dir,
				      &failslab.ignore_gfp_wait);

	if (!failslab.ignore_gfp_wait_file) {
		err = -ENOMEM;
		debugfs_remove(failslab.ignore_gfp_wait_file);
		cleanup_fault_attr_dentries(&failslab.attr);
	}

	return err;
}

late_initcall(failslab_debugfs);

#endif /* CONFIG_FAULT_INJECTION_DEBUG_FS */

#else /* CONFIG_FAILSLAB */

static inline int should_failslab(struct kmem_cache *cachep, gfp_t flags)
{
	return 0;
}

#endif /* CONFIG_FAILSLAB */

/*
kmem_cache_alloc
  __cache_alloc
    __do_cache_alloc
      ____cache_alloc
*/
static inline void *____cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	void *objp;
	struct array_cache *ac;

	check_irq_off();

    /* cachep->array[smp_processor_id()]，获取当前cpu对应的array_cache */
	ac = cpu_cache_get(cachep);
	/* 检查是否存在可用对象，avail指向当前可用的节点 */
	if (likely(ac->avail)) {
		/* 首先从array_cache中分配,如果存在可用对象，更新local cache的命中次数 */
		STATS_INC_ALLOCHIT(cachep);
		/* 标示最近使用过local_cache */
		ac->touched = 1;
	    /* 获取空闲对象，从后向前，当avail变为0时表示已无可用对象 */
		objp = ac->entry[--ac->avail];
	} else {
		/* local cache(cachep->array)中已无空闲对象，更新未命中次数 */
		STATS_INC_ALLOCMISS(cachep);
		/* local cache中无空闲对象，则从slab的几个链表中提取空闲对象放入local cache中 */
		objp = cache_alloc_refill(cachep, flags);
	}
	return objp;
}

#ifdef CONFIG_NUMA
/*
 * Try allocating on another node if PF_SPREAD_SLAB|PF_MEMPOLICY.
 *
 * If we are in_interrupt, then process context, including cpusets and
 * mempolicy, may not apply and should not be used for allocation policy.
 */
static void *alternate_node_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	int nid_alloc, nid_here;

	if (in_interrupt() || (flags & __GFP_THISNODE))
		return NULL;
	nid_alloc = nid_here = numa_node_id();
	if (cpuset_do_slab_mem_spread() && (cachep->flags & SLAB_MEM_SPREAD))
		nid_alloc = cpuset_mem_spread_node();
	else if (current->mempolicy)
		nid_alloc = slab_node(current->mempolicy);
	if (nid_alloc != nid_here)
		return ____cache_alloc_node(cachep, flags, nid_alloc);
	return NULL;
}

/*
 * Fallback function if there was no memory available and no objects on a
 * certain node and fall back is permitted. First we scan all the
 * available nodelists for available objects. If that fails then we
 * perform an allocation without specifying a node. This allows the page
 * allocator to do its reclaim / fallback magic. We then insert the
 * slab into the proper nodelist and then allocate from it.
 */
static void *fallback_alloc(struct kmem_cache *cache, gfp_t flags)
{
	struct zonelist *zonelist;
	gfp_t local_flags;
	struct zone **z;
	void *obj = NULL;
	int nid;

	if (flags & __GFP_THISNODE)
		return NULL;

	zonelist = &NODE_DATA(slab_node(current->mempolicy))
			->node_zonelists[gfp_zone(flags)];
	local_flags = flags & (GFP_CONSTRAINT_MASK|GFP_RECLAIM_MASK);

retry:
	/*
	 * Look through allowed nodes for objects available
	 * from existing per node queues.
	 */
	for (z = zonelist->zones; *z && !obj; z++) {
		nid = zone_to_nid(*z);

		if (cpuset_zone_allowed_hardwall(*z, flags) &&
			cache->nodelists[nid] &&
			cache->nodelists[nid]->free_objects)
				obj = ____cache_alloc_node(cache,
					flags | GFP_THISNODE, nid);
	}

	if (!obj) {
		/*
		 * This allocation will be performed within the constraints
		 * of the current cpuset / memory policy requirements.
		 * We may trigger various forms of reclaim on the allowed
		 * set and go into memory reserves if necessary.
		 */
		if (local_flags & __GFP_WAIT)
			local_irq_enable();
		kmem_flagcheck(cache, flags);
		obj = kmem_getpages(cache, flags, -1);
		if (local_flags & __GFP_WAIT)
			local_irq_disable();
		if (obj) {
			/*
			 * Insert into the appropriate per node queues
			 */
			nid = page_to_nid(virt_to_page(obj));
			if (cache_grow(cache, flags, nid, obj)) {
				obj = ____cache_alloc_node(cache,
					flags | GFP_THISNODE, nid);
				if (!obj)
					/*
					 * Another processor may allocate the
					 * objects in the slab since we are
					 * not holding any locks.
					 */
					goto retry;
			} else {
				/* cache_grow already freed obj */
				obj = NULL;
			}
		}
	}
	return obj;
}

/*
 * A interface to enable slab creation on nodeid
 */
static void *____cache_alloc_node(struct kmem_cache *cachep, gfp_t flags,
				int nodeid)
{
	struct list_head *entry;
	struct slab *slabp;
	struct kmem_list3 *l3;
	void *obj;
	int x;

	l3 = cachep->nodelists[nodeid];
	BUG_ON(!l3);

retry:
	check_irq_off();
	spin_lock(&l3->list_lock);
	entry = l3->slabs_partial.next;
	if (entry == &l3->slabs_partial) {
		l3->free_touched = 1;
		entry = l3->slabs_free.next;
		if (entry == &l3->slabs_free)
			goto must_grow;
	}

	slabp = list_entry(entry, struct slab, list);
	check_spinlock_acquired_node(cachep, nodeid);
	check_slabp(cachep, slabp);

	STATS_INC_NODEALLOCS(cachep);
	STATS_INC_ACTIVE(cachep);
	STATS_SET_HIGH(cachep);

	BUG_ON(slabp->inuse == cachep->num);

	obj = slab_get_obj(cachep, slabp, nodeid);
	check_slabp(cachep, slabp);
	l3->free_objects--;
	/* move slabp to correct slabp list: */
	list_del(&slabp->list);

	if (slabp->free == BUFCTL_END)
		list_add(&slabp->list, &l3->slabs_full);
	else
		list_add(&slabp->list, &l3->slabs_partial);

	spin_unlock(&l3->list_lock);
	goto done;

must_grow:
	spin_unlock(&l3->list_lock);
	x = cache_grow(cachep, flags | GFP_THISNODE, nodeid, NULL);
	if (x)
		goto retry;

	return fallback_alloc(cachep, flags);

done:
	return obj;
}

/**
 * kmem_cache_alloc_node - Allocate an object on the specified node
 * @cachep: The cache to allocate from.
 * @flags: See kmalloc().
 * @nodeid: node number of the target node.
 * @caller: return address of caller, used for debug information
 *
 * Identical to kmem_cache_alloc but it will allocate memory on the given
 * node, which can improve the performance for cpu bound structures.
 *
 * Fallback to other node is possible if __GFP_THISNODE is not set.
 */
static __always_inline void *
__cache_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
		   void *caller)
{
	unsigned long save_flags;
	void *ptr;

	if (should_failslab(cachep, flags))
		return NULL;

	cache_alloc_debugcheck_before(cachep, flags);
	local_irq_save(save_flags);

	if (unlikely(nodeid == -1))
		nodeid = numa_node_id();

	if (unlikely(!cachep->nodelists[nodeid])) {
		/* Node not bootstrapped yet */
		ptr = fallback_alloc(cachep, flags);
		goto out;
	}

	if (nodeid == numa_node_id()) {
		/*
		 * Use the locally cached objects if possible.
		 * However ____cache_alloc does not allow fallback
		 * to other nodes. It may fail while we still have
		 * objects on other nodes available.
		 */
		ptr = ____cache_alloc(cachep, flags);
		if (ptr)
			goto out;
	}
	/* ___cache_alloc_node can fall back to other nodes */
	ptr = ____cache_alloc_node(cachep, flags, nodeid);
  out:
	local_irq_restore(save_flags);
	ptr = cache_alloc_debugcheck_after(cachep, flags, ptr, caller);

	if (unlikely((flags & __GFP_ZERO) && ptr))
		memset(ptr, 0, obj_size(cachep));

	return ptr;
}

/*
kmem_cache_alloc
__cache_alloc
   __do_cache_alloc

*/

static __always_inline void *
__do_cache_alloc(struct kmem_cache *cache, gfp_t flags)
{
	void *objp;

	if (unlikely(current->flags & (PF_SPREAD_SLAB | PF_MEMPOLICY))) {
		objp = alternate_node_alloc(cache, flags);
		if (objp)
			goto out;
	}
	objp = ____cache_alloc(cache, flags);

	/*
	 * We may just have run out of memory on the local node.
	 * ____cache_alloc_node() knows how to locate memory on other nodes
	 * 从别的内存节点分配内存
	 */
 	if (!objp)
 		objp = ____cache_alloc_node(cache, flags, numa_node_id());

  out:
	return objp;
}
#else

static __always_inline void *
__do_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	return ____cache_alloc(cachep, flags);
}

#endif /* CONFIG_NUMA */

/* kmalloc的具体分配工作函数, 从cachep中分配一个兑现出现，大小已经由kmem_cache->buffer_size决定 
 *
 * kmem_cache_alloc()
 *  __cache_alloc()
 */
static __always_inline void *
__cache_alloc(struct kmem_cache *cachep, gfp_t flags, void *caller)
{
	unsigned long save_flags;
	void *objp;

	if (should_failslab(cachep, flags))
		return NULL;

	cache_alloc_debugcheck_before(cachep, flags);
	local_irq_save(save_flags); /* 关中断 */
	/* 走起 */
	objp = __do_cache_alloc(cachep, flags);
	local_irq_restore(save_flags);
	objp = cache_alloc_debugcheck_after(cachep, flags, objp, caller);
	prefetchw(objp);

    /* 清0 */
	if (unlikely((flags & __GFP_ZERO) && objp))
		memset(objp, 0, obj_size(cachep));

	return objp;
}

/*
 * Caller needs to acquire correct kmem_list's list_lock
 */
 /* 没有shared cache，或者shared cache已经满载的情况下，会调用该函数进行回收
   cachep: 需要回收对象的cache
   objpp: local cache中记录slab对象的数组首地址 
   nr_objects: 需要释放的slab对象的数量
   node: 当前cpu所在的NUMA节点，也是当前slab对象所属的NUMA节点
  *
  *
  * alloc_kmemlist()
  *  free_block()
  *
  * do_drain()
  *  free_block()
  *
  * drain_array()
  *  free_block()
  *
  * do_tune_cpucache()
  *  free_block()
  *
  * __drain_alien_cache()
  *  free_block()
  */
static void free_block(struct kmem_cache *cachep, void **objpp, int nr_objects,
		       int node)
{
	int i;
	struct kmem_list3 *l3;

	for (i = 0; i < nr_objects; i++) {
		/* 根据索引，获取需要释放的对象 */
		void *objp = objpp[i];
		struct slab *slabp;
	
	/* 根据slan对象获取其所属的slab，首先根据对象地址获取其所在page，
	   根据page->lru.prev可以获取slab */

		slabp = virt_to_slab(objp);
        /* 根据NUMA节点获取slab三链 */
		l3 = cachep->nodelists[node];
		/* 将slab从原有链表上摘除，现在在那个链表上（free/paritcal/full三链之一） */
		list_del(&slabp->list);
		check_spinlock_acquired_node(cachep, node);
		check_slabp(cachep, slabp);
		/* 将对象释放到slab中 */
        /* 更新slab->inuse计数，更新slab->free指向当前释放的对象索引，更新slab->bufctl(slabp)[当前对象索引]指向上一节点索引 */
		slab_put_obj(cachep, slabp, objp, node);
		/* 减少当前cache中活跃对象的数量 */
		STATS_DEC_ACTIVE(cachep);
		/* 增加slab三链中可用空闲对象的计数 */
		l3->free_objects++;
		check_slabp(cachep, slabp);

		/* fixup slab chains */
		/* 判断当前slab是否已经没有正在使用的对象 */
		if (slabp->inuse == 0) {
			/* 当前slab三链中空闲对象数量已经超过了上限 */
			if (l3->free_objects > l3->free_limit) {
				/* 此时需要销毁一个slab，而每个slab中含有cache->num个对象，所以先把free_objects更新了，然后销毁slab */
				l3->free_objects -= cachep->num;
				/* No need to drop any previously held
				 * lock here, even if we have a off-slab slab
				 * descriptor it is guaranteed to come from
				 * a different cache, refer to comments before
				 * alloc_slabmgmt.
				 */
				 /* 销毁一个slab */
				slab_destroy(cachep, slabp);
			} else {
				/* 由于slab的所有对象已空闲，将slab挂在free链表上 */
				list_add(&slabp->list, &l3->slabs_free);
			}
		} else {
			/* Unconditionally move a slab to the end of the
			 * partial list on free - maximum time for the
			 * other objects to be freed, too.
			 */
			 /* 将slab挂在到partical链表上 */
			list_add_tail(&slabp->list, &l3->slabs_partial);
		}
	}
}

static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
{
	int batchcount;
	struct kmem_list3 *l3;
	/* 根据当前cpu获取所在的内存节点ID */
	int node = numa_node_id();

	/* 每次申请和释放，需要批量处理的对象个数 */
	batchcount = ac->batchcount;
#if DEBUG
	BUG_ON(!batchcount || batchcount > ac->avail);
#endif
	check_irq_off();
    /* 获取当前cache的slab 三链，kmem_list3结构  */
	l3 = cachep->nodelists[node];
	spin_lock(&l3->list_lock);
	/* 如果有shared 的local cache */
	if (l3->shared) {
		struct array_cache *shared_array = l3->shared;
		/* 计算当前shared local cache还能容纳多少slab对象，limit是上限，avail是当前拥有的空闲数量 */
		int max = shared_array->limit - shared_array->avail;
		if (max) {
			/* 不能超过shared local cache的容纳上限 */
			if (batchcount > max)
				batchcount = max;
			/* entry数组中记录的都是可用对象的地址，直接批量拷贝过去即可 */
			memcpy(&(shared_array->entry[shared_array->avail]),
			       ac->entry, sizeof(void *) * batchcount);
			/* 更新shared local cache当前的可用对象数量 */
			shared_array->avail += batchcount;
			goto free_done;
		}
	}
	/* 没有shared cache或者shared cache已经放满了，无法融入更多的对象，此时需要释放到slab三链中 */
	free_block(cachep, ac->entry, batchcount, node);
free_done:
#if STATS
	{
		int i = 0;
		struct list_head *p;

		p = l3->slabs_free.next;
		while (p != &(l3->slabs_free)) {
			struct slab *slabp;

			slabp = list_entry(p, struct slab, list);
			BUG_ON(slabp->inuse);

			i++;
			p = p->next;
		}
		STATS_SET_FREEABLE(cachep, i);
	}
#endif
	spin_unlock(&l3->list_lock);
    /* 至此，已批量释放batchcount个对象，调整avail的值 */
	ac->avail -= batchcount;
	/* 由于先释放的是旧的对象，即数组前面的对象，所以需要后面的对象整体前移 */
	memmove(ac->entry, &(ac->entry[batchcount]), sizeof(void *)*ac->avail);
}

/*
 * Release an obj back to its cache. If the obj has a constructed state, it must
 * be in this state _before_ it is released.  Called with disabled ints.
 */
static inline void __cache_free(struct kmem_cache *cachep, void *objp)
{
    /* 获取当前cache中的local cache，即cachep->array[smp_processor_id()] */
	struct array_cache *ac = cpu_cache_get(cachep);

	check_irq_off();
	objp = cache_free_debugcheck(cachep, objp, __builtin_return_address(0));

	/*
	 * Skip calling cache_free_alien() when the platform is not numa.
	 * This will avoid cache misses that happen while accessing slabp (which
	 * is per page memory  reference) to get nodeid. Instead use a global
	 * variable to skip the call, which is mostly likely to be present in
	 * the cache.
	 */
	 /* 判断当前是否为NUMA架构，对于NUMA架构需要判断释放的对象所在的内核节点与当前CPU所属的内存节点是否相同 */
    /* 如果相同，则执行后续的释放操作；如果不同在cache_free_alien函数中完成释放，并在下面return */
    /* 假设当前为UMA架构，先继续往下分析，cache_free_alien留在后面分析 */
	if (numa_platform && cache_free_alien(cachep, objp))
		return;

    /* 判断当前local cache中的可用对象数量是否超过了上限 */
	if (likely(ac->avail < ac->limit)) {
		/* 未超上限，释放到kmem_cache->array */
        /* 增加释放的命中计数 */
		STATS_INC_FREEHIT(cachep);
		/* 将释放对象直接保存在local cache中，申请时取[--ac->avail]释放时是[ac->avail++]，可以看出每次申请的都是最近释放的对象 */
		ac->entry[ac->avail++] = objp;
		return;
	} else {
		/* 已超出上限 */
        /* 增加释放未命中的计数 */
		STATS_INC_FREEMISS(cachep);
		/* 由于local cache中对象数量太多，需要释放batch_count个对象出去，后面我们会分析cache_flusharray函数 */
		cache_flusharray(cachep, ac);
		/* local cache中已经释放了一批，已有新空间记录最近释放的对象 */
		ac->entry[ac->avail++] = objp;
	}
}

/**
 * kmem_cache_alloc - Allocate an object
 * @cachep: The cache to allocate from.
 * @flags: See kmalloc().
 *
 * Allocate an object from this cache.  The flags are only relevant
 * if the cache has no available objects.
 */
void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	return __cache_alloc(cachep, flags, __builtin_return_address(0));
}
EXPORT_SYMBOL(kmem_cache_alloc);

/**
 * kmem_ptr_validate - check if an untrusted pointer might
 *	be a slab entry.
 * @cachep: the cache we're checking against
 * @ptr: pointer to validate
 *
 * This verifies that the untrusted pointer looks sane:
 * it is _not_ a guarantee that the pointer is actually
 * part of the slab cache in question, but it at least
 * validates that the pointer can be dereferenced and
 * looks half-way sane.
 *
 * Currently only used for dentry validation.
 */
int kmem_ptr_validate(struct kmem_cache *cachep, const void *ptr)
{
	unsigned long addr = (unsigned long)ptr;
	unsigned long min_addr = PAGE_OFFSET;
	unsigned long align_mask = BYTES_PER_WORD - 1;
	unsigned long size = cachep->buffer_size;
	struct page *page;

	if (unlikely(addr < min_addr))
		goto out;
	if (unlikely(addr > (unsigned long)high_memory - size))
		goto out;
	if (unlikely(addr & align_mask))
		goto out;
	if (unlikely(!kern_addr_valid(addr)))
		goto out;
	if (unlikely(!kern_addr_valid(addr + size - 1)))
		goto out;
	page = virt_to_page(ptr);
	if (unlikely(!PageSlab(page)))
		goto out;
	if (unlikely(page_get_cache(page) != cachep))
		goto out;
	return 1;
out:
	return 0;
}

#ifdef CONFIG_NUMA
void *kmem_cache_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid)
{
	return __cache_alloc_node(cachep, flags, nodeid,
			__builtin_return_address(0));
}
EXPORT_SYMBOL(kmem_cache_alloc_node);

static __always_inline void *
__do_kmalloc_node(size_t size, gfp_t flags, int node, void *caller)
{
	struct kmem_cache *cachep;

	cachep = kmem_find_general_cachep(size, flags);
	if (unlikely(ZERO_OR_NULL_PTR(cachep)))
		return cachep;
	return kmem_cache_alloc_node(cachep, flags, node);
}

#ifdef CONFIG_DEBUG_SLAB
void *__kmalloc_node(size_t size, gfp_t flags, int node)
{
	return __do_kmalloc_node(size, flags, node,
			__builtin_return_address(0));
}
EXPORT_SYMBOL(__kmalloc_node);

void *__kmalloc_node_track_caller(size_t size, gfp_t flags,
		int node, void *caller)
{
	return __do_kmalloc_node(size, flags, node, caller);
}
EXPORT_SYMBOL(__kmalloc_node_track_caller);
#else
void *__kmalloc_node(size_t size, gfp_t flags, int node)
{
	return __do_kmalloc_node(size, flags, node, NULL);
}
EXPORT_SYMBOL(__kmalloc_node);
#endif /* CONFIG_DEBUG_SLAB */
#endif /* CONFIG_NUMA */

/**
 * __do_kmalloc - allocate memory
 * @size: how many bytes of memory are required.
 * @flags: the type of memory to allocate (see kmalloc).
 * @caller: function caller for debug tracking of the caller
 *
 * 
 */
static __always_inline void *__do_kmalloc(size_t size, gfp_t flags,
					  void *caller)
{
	struct kmem_cache *cachep;

	/* If you want to save a few bytes .text space: replace
	 * __ with kmem_.
	 * Then kmalloc uses the uninlined functions instead of the inline
	 * functions.
	 */

	/* 根据size大小，查找对应的general cache(kmem_cache对象),
	   在malloc_sizes[]中查找 
	 */
	cachep = __find_general_cachep(size, flags);
	/* 对于0size的kmalloc请求，直接返回cache的地址 */
	if (unlikely(ZERO_OR_NULL_PTR(cachep)))
		return cachep;
	/* 具体分配在这里进行,在cachep中分配 */
	return __cache_alloc(cachep, flags, caller);
}


#ifdef CONFIG_DEBUG_SLAB
void *__kmalloc(size_t size, gfp_t flags)
{
	return __do_kmalloc(size, flags, __builtin_return_address(0));
}
EXPORT_SYMBOL(__kmalloc);

void *__kmalloc_track_caller(size_t size, gfp_t flags, void *caller)
{
	return __do_kmalloc(size, flags, caller);
}
EXPORT_SYMBOL(__kmalloc_track_caller);

#else
void *__kmalloc(size_t size, gfp_t flags)
{
	return __do_kmalloc(size, flags, NULL);
}
EXPORT_SYMBOL(__kmalloc);
#endif

/**
 * kmem_cache_free - Deallocate an object
 * @cachep: The cache the allocation was from.
 * @objp: The previously allocated object.
 *
 * Free an object which was previously allocated from this
 * cache.
 */
void kmem_cache_free(struct kmem_cache *cachep, void *objp)
{
	unsigned long flags;

	local_irq_save(flags);
	debug_check_no_locks_freed(objp, obj_size(cachep));
	__cache_free(cachep, objp);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(kmem_cache_free);

/**
 * kfree - free previously allocated memory
 * @objp: pointer returned by kmalloc.
 *
 * If @objp is NULL, no operation is performed.
 *
 * Don't free memory not originally allocated by kmalloc()
 * or you will run into trouble.
 *
 
 */
void kfree(const void *objp)
{
	struct kmem_cache *c;
	unsigned long flags;

    /* 检查需要释放的对象地址是否有效 */
	if (unlikely(ZERO_OR_NULL_PTR(objp)))
		return;
	
	local_irq_save(flags);
	/* 首先根据对象地址获取其所在的page，然后page的lru->prev指向了slab，page的lru->next指向了cache */
    /* slab的cache_grow函数中调用的slab_map_pages完成了Page和cache/slab的映射关系 */
	kfree_debugcheck(objp);
	c = virt_to_cache(objp);/* 得到所属的kmem_cache, 就是page->lru->next */
	debug_check_no_locks_freed(objp, obj_size(c));
	/* 找到了释放对象所属的cache，下面函数进行释放 */
	__cache_free(c, (void *)objp);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(kfree);

unsigned int kmem_cache_size(struct kmem_cache *cachep)
{
	return obj_size(cachep);
}
EXPORT_SYMBOL(kmem_cache_size);

const char *kmem_cache_name(struct kmem_cache *cachep)
{
	return cachep->name;
}
EXPORT_SYMBOL_GPL(kmem_cache_name);

/*
 * This initializes kmem_list3 or resizes various caches for all nodes.
   初始化shared local cache和slab的三个链表

 kmem_cache_create
  setup_cpu_cache
    enable_cpucache
      do_tune_cpucache  
 */
static int alloc_kmemlist(struct kmem_cache *cachep)
{
	int node;
	struct kmem_list3 *l3;
	struct array_cache *new_shared;
	struct array_cache **new_alien = NULL;

	for_each_online_node(node) {

                if (use_alien_caches) {
                        new_alien = alloc_alien_cache(node, cachep->limit);
                        if (!new_alien)
                                goto fail;
                }

		new_shared = NULL;
		/* 分配shared local cache */
		if (cachep->shared) {
			new_shared = alloc_arraycache(node,
				cachep->shared*cachep->batchcount,
					0xbaadf00d);
			if (!new_shared) {
				free_alien_cache(new_alien);
				goto fail;
			}
		}

		/* 获取旧的slab三个链表 */
		l3 = cachep->nodelists[node];
		if (l3) {
			struct array_cache *shared = l3->shared;

			spin_lock_irq(&l3->list_lock);

            /* 释放旧的shared local cache中的对象 */
			if (shared)
				free_block(cachep, shared->entry,
						shared->avail, node);

            /* 指向新的share local cache */
			l3->shared = new_shared;
			if (!l3->alien) {
				l3->alien = new_alien;
				new_alien = NULL;
			}
			/* 计算cache中空闲对象的上限 */
			l3->free_limit = (1 + nr_cpus_node(node)) *
					cachep->batchcount + cachep->num;
			spin_unlock_irq(&l3->list_lock);
			kfree(shared);
			free_alien_cache(new_alien);
			continue;
		}
		/* 分配新的slab 三链 */
		l3 = kmalloc_node(sizeof(struct kmem_list3), GFP_KERNEL, node);
		if (!l3) {
			free_alien_cache(new_alien);
			kfree(new_shared);
			goto fail;
		}

		/*进行初始化l3*/
		kmem_list3_init(l3);
		l3->next_reap = jiffies + REAPTIMEOUT_LIST3 +
				((unsigned long)cachep) % REAPTIMEOUT_LIST3;
		l3->shared = new_shared;
		l3->alien = new_alien;
		l3->free_limit = (1 + nr_cpus_node(node)) *
					cachep->batchcount + cachep->num;
		cachep->nodelists[node] = l3;
	}
	return 0;

fail:
	if (!cachep->next.next) {
		/* Cache is not active yet. Roll back what we did */
		node--;
		while (node >= 0) {
			if (cachep->nodelists[node]) {
				l3 = cachep->nodelists[node];

				kfree(l3->shared);
				free_alien_cache(l3->alien);
				kfree(l3);
				cachep->nodelists[node] = NULL;
			}
			node--;
		}
	}
	return -ENOMEM;
}

struct ccupdate_struct {
	struct kmem_cache *cachep;
	struct array_cache *new[NR_CPUS];
};

/* 更新每个cpu的struct array_cache对象
   info为ccupdate_struct对象

kmem_cache_create
  setup_cpu_cache
    enable_cpucache
      do_tune_cpucache

*/
static void do_ccupdate_local(void *info)
{
	struct ccupdate_struct *new = info;
	struct array_cache *old;

	check_irq_off();
	/* 保存老的array_cache对象 */
	old = cpu_cache_get(new->cachep);

	/* 指向新的struct array_cache对象 */
	new->cachep->array[smp_processor_id()] = new->new[smp_processor_id()];
	/* 保存旧的struct array_cache对象 */
	new->new[smp_processor_id()] = old;
}

/* Always called with the cache_chain_mutex held 
   设置local cache(cachep->array[cpuid]) , share local cache和slab的三个链表

kmem_cache_create
  setup_cpu_cache
    enable_cpucache
*/
static int do_tune_cpucache(struct kmem_cache *cachep, int limit,
				int batchcount, int shared)
{
	struct ccupdate_struct *new;
	int i;

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

    /* 给ccupdate_struct的new[]数组建立array_cache实例 */
	for_each_online_cpu(i) {
	    /* 为每个cpu分配新的struct array_cache对象 */
		new->new[i] = alloc_arraycache(cpu_to_node(i), limit,
						batchcount);
		
		if (!new->new[i]) { /* 一个分配失败，就都要归还 */
			for (i--; i >= 0; i--)
				kfree(new->new[i]);
			kfree(new);
			return -ENOMEM;
		}
	}

 	/* ccupdate_struct和kmem_cache 建立关联 */
	new->cachep = cachep;

    //设置cachep->array[cpuid]成员
    /* 将cachep->array[cpuid]用new->new[cpuid]的去替换,  老的保存在new->new[cpuid]中了 */
	on_each_cpu(do_ccupdate_local, (void *)new, 1, 1);

	check_irq_on();
	cachep->batchcount = batchcount;
	cachep->limit = limit;
	cachep->shared = shared;

	/* 释放旧的local cache   (就是do_ccupdate_local函数替换掉的，放在new->new[i]中) */
	for_each_online_cpu(i) {
		struct array_cache *ccold = new->new[i];
		if (!ccold)
			continue;
		spin_lock_irq(&cachep->nodelists[cpu_to_node(i)]->list_lock);
		/*  释放旧的local cache中的对象 */
		free_block(cachep, ccold->entry, ccold->avail, cpu_to_node(i));
		spin_unlock_irq(&cachep->nodelists[cpu_to_node(i)]->list_lock);
		/* 释放旧的struct array_cache对象 */
		kfree(ccold);
	}
	kfree(new);
	/* 初始化shared local cache和slab三个链表 */
	return alloc_kmemlist(cachep);
}

/* Called with cache_chain_mutex held always 
 *
 * kmem_cache_create
 *    setup_cpu_cache
 *       enable_cpucache
 *
 * 由kmem_cache_init或者setup_cpu_cache调用
   初始化local cache
*/
static int enable_cpucache(struct kmem_cache *cachep)
{
	int err;
	int limit, shared;

	/*
	 * The head array serves three purposes:
	 * - create a LIFO ordering, i.e. return objects that are cache-warm
	 * - reduce the number of spinlock operations.
	 * - reduce the number of linked list operations on the slab and
	 *   bufctl chains: array operations are cheaper.
	 * The numbers are guessed, we should auto-tune as described by
	 * Bonwick.
	 *
	 * 根据对象的大小计算local cache中对象的数量
	 */
	if (cachep->buffer_size > 131072)
		limit = 1;
	else if (cachep->buffer_size > PAGE_SIZE)
		limit = 8;
	else if (cachep->buffer_size > 1024)
		limit = 24;
	else if (cachep->buffer_size > 256)
		limit = 54;
	else
		limit = 120;

	/*
	 * CPU bound tasks (e.g. network routing) can exhibit cpu bound
	 * allocation behaviour: Most allocs on one cpu, most free operations
	 * on another cpu. For these cases, an efficient object passing between
	 * cpus is necessary. This is provided by a shared array. The array
	 * replaces Bonwick's magazine layer.
	 * On uniprocessor, it's functionally equivalent (but less efficient)
	 * to a larger limit. Thus disabled by default.
	 */
	shared = 0;
	/* 多核下设置share local cache中的对象数目 */
	if (cachep->buffer_size <= PAGE_SIZE && num_possible_cpus() > 1)
		shared = 8;

#if DEBUG
	/*
	 * With debugging enabled, large batchcount lead to excessively long
	 * periods with disabled local interrupts. Limit the batchcount
	 */
	if (limit > 32)
		limit = 32;
#endif

    /* 配置local cache  */
	err = do_tune_cpucache(cachep, limit, (limit + 1) / 2, shared);
	if (err)
		printk(KERN_ERR "enable_cpucache failed for %s, error %d.\n",
		       cachep->name, -err);
	return err;
}

/*
 * Drain an array if it contains any elements taking the l3 lock only if
 * necessary. Note that the l3 listlock also protects the array_cache
 * if drain_array() is used on the shared array.
 */
void drain_array(struct kmem_cache *cachep, struct kmem_list3 *l3,
			 struct array_cache *ac, int force, int node)
{
	int tofree;

	if (!ac || !ac->avail)
		return;
	if (ac->touched && !force) {
		ac->touched = 0;
	} else {
		spin_lock_irq(&l3->list_lock);
		if (ac->avail) {
			tofree = force ? ac->avail : (ac->limit + 4) / 5;
			if (tofree > ac->avail)
				tofree = (ac->avail + 1) / 2;
			
			free_block(cachep, ac->entry, tofree, node);
			ac->avail -= tofree;
			memmove(ac->entry, &(ac->entry[tofree]),
				sizeof(void *) * ac->avail);
		}
		spin_unlock_irq(&l3->list_lock);
	}
}

/**
 * cache_reap - Reclaim memory from caches.
 * @w: work descriptor
 *
 * Called from workqueue/eventd every few seconds.
 * Purpose:
 * - clear the per-cpu caches for this CPU.
 * - return freeable pages to the main free memory pool.
 *
 * If we cannot acquire the cache chain mutex then just give up - we'll try
 * again on the next iteration.
 */
static void cache_reap(struct work_struct *w)
{
	struct kmem_cache *searchp;
	struct kmem_list3 *l3;
	int node = numa_node_id();
	struct delayed_work *work =
		container_of(w, struct delayed_work, work);

	if (!mutex_trylock(&cache_chain_mutex))
		/* Give up. Setup the next iteration. */
		goto out;

	list_for_each_entry(searchp, &cache_chain, next) {
		check_irq_on();

		/*
		 * We only take the l3 lock if absolutely necessary and we
		 * have established with reasonable certainty that
		 * we can do some work if the lock was obtained.
		 */
		l3 = searchp->nodelists[node];

		reap_alien(searchp, l3);

		drain_array(searchp, l3, cpu_cache_get(searchp), 0, node);

		/*
		 * These are racy checks but it does not matter
		 * if we skip one check or scan twice.
		 */
		if (time_after(l3->next_reap, jiffies))
			goto next;

		l3->next_reap = jiffies + REAPTIMEOUT_LIST3;

		drain_array(searchp, l3, l3->shared, 0, node);

		if (l3->free_touched)
			l3->free_touched = 0;
		else {
			int freed;

			freed = drain_freelist(searchp, l3, (l3->free_limit +
				5 * searchp->num - 1) / (5 * searchp->num));
			STATS_ADD_REAPED(searchp, freed);
		}
next:
		cond_resched();
	}
	check_irq_on();
	mutex_unlock(&cache_chain_mutex);
	next_reap_node();
out:
	/* Set up the next iteration */
	schedule_delayed_work(work, round_jiffies_relative(REAPTIMEOUT_CPUC));
}

#ifdef CONFIG_SLABINFO

static void print_slabinfo_header(struct seq_file *m)
{
	/*
	 * Output format version, so at least we can change it
	 * without _too_ many complaints.
	 */
#if STATS
	seq_puts(m, "slabinfo - version: 2.1 (statistics)\n");
#else
	seq_puts(m, "slabinfo - version: 2.1\n");
#endif
	seq_puts(m, "# name            <active_objs> <num_objs> <objsize> "
		 "<objperslab> <pagesperslab>");
	seq_puts(m, " : tunables <limit> <batchcount> <sharedfactor>");
	seq_puts(m, " : slabdata <active_slabs> <num_slabs> <sharedavail>");
#if STATS
	seq_puts(m, " : globalstat <listallocs> <maxobjs> <grown> <reaped> "
		 "<error> <maxfreeable> <nodeallocs> <remotefrees> <alienoverflow>");
	seq_puts(m, " : cpustat <allochit> <allocmiss> <freehit> <freemiss>");
#endif
	seq_putc(m, '\n');
}

static void *s_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	mutex_lock(&cache_chain_mutex);
	if (!n)
		print_slabinfo_header(m);

	return seq_list_start(&cache_chain, *pos);
}

static void *s_next(struct seq_file *m, void *p, loff_t *pos)
{
	return seq_list_next(p, &cache_chain, pos);
}

static void s_stop(struct seq_file *m, void *p)
{
	mutex_unlock(&cache_chain_mutex);
}

static int s_show(struct seq_file *m, void *p)
{
	struct kmem_cache *cachep = list_entry(p, struct kmem_cache, next);
	struct slab *slabp;
	unsigned long active_objs;
	unsigned long num_objs;
	unsigned long active_slabs = 0;
	unsigned long num_slabs, free_objects = 0, shared_avail = 0;
	const char *name;
	char *error = NULL;
	int node;
	struct kmem_list3 *l3;

	active_objs = 0;
	num_slabs = 0;
	for_each_online_node(node) {
		l3 = cachep->nodelists[node];
		if (!l3)
			continue;

		check_irq_on();
		spin_lock_irq(&l3->list_lock);

		list_for_each_entry(slabp, &l3->slabs_full, list) {
			if (slabp->inuse != cachep->num && !error)
				error = "slabs_full accounting error";
			active_objs += cachep->num;
			active_slabs++;
		}
		list_for_each_entry(slabp, &l3->slabs_partial, list) {
			if (slabp->inuse == cachep->num && !error)
				error = "slabs_partial inuse accounting error";
			if (!slabp->inuse && !error)
				error = "slabs_partial/inuse accounting error";
			active_objs += slabp->inuse;
			active_slabs++;
		}
		list_for_each_entry(slabp, &l3->slabs_free, list) {
			if (slabp->inuse && !error)
				error = "slabs_free/inuse accounting error";
			num_slabs++;
		}
		free_objects += l3->free_objects;
		if (l3->shared)
			shared_avail += l3->shared->avail;

		spin_unlock_irq(&l3->list_lock);
	}
	num_slabs += active_slabs;
	num_objs = num_slabs * cachep->num;
	if (num_objs - active_objs != free_objects && !error)
		error = "free_objects accounting error";

	name = cachep->name;
	if (error)
		printk(KERN_ERR "slab: cache %s error: %s\n", name, error);

	seq_printf(m, "%-17s %6lu %6lu %6u %4u %4d",
		   name, active_objs, num_objs, cachep->buffer_size,
		   cachep->num, (1 << cachep->gfporder));
	seq_printf(m, " : tunables %4u %4u %4u",
		   cachep->limit, cachep->batchcount, cachep->shared);
	seq_printf(m, " : slabdata %6lu %6lu %6lu",
		   active_slabs, num_slabs, shared_avail);
#if STATS
	{			/* list3 stats */
		unsigned long high = cachep->high_mark;
		unsigned long allocs = cachep->num_allocations;
		unsigned long grown = cachep->grown;
		unsigned long reaped = cachep->reaped;
		unsigned long errors = cachep->errors;
		unsigned long max_freeable = cachep->max_freeable;
		unsigned long node_allocs = cachep->node_allocs;
		unsigned long node_frees = cachep->node_frees;
		unsigned long overflows = cachep->node_overflow;

		seq_printf(m, " : globalstat %7lu %6lu %5lu %4lu \
				%4lu %4lu %4lu %4lu %4lu", allocs, high, grown,
				reaped, errors, max_freeable, node_allocs,
				node_frees, overflows);
	}
	/* cpu stats */
	{
		unsigned long allochit = atomic_read(&cachep->allochit);
		unsigned long allocmiss = atomic_read(&cachep->allocmiss);
		unsigned long freehit = atomic_read(&cachep->freehit);
		unsigned long freemiss = atomic_read(&cachep->freemiss);

		seq_printf(m, " : cpustat %6lu %6lu %6lu %6lu",
			   allochit, allocmiss, freehit, freemiss);
	}
#endif
	seq_putc(m, '\n');
	return 0;
}

/*
 * slabinfo_op - iterator that generates /proc/slabinfo
 *
 * Output layout:
 * cache-name
 * num-active-objs
 * total-objs
 * object size
 * num-active-slabs
 * total-slabs
 * num-pages-per-slab
 * + further values on SMP and with statistics enabled
 */

const struct seq_operations slabinfo_op = {
	.start = s_start,
	.next = s_next,
	.stop = s_stop,
	.show = s_show,
};

#define MAX_SLABINFO_WRITE 128
/**
 * slabinfo_write - Tuning for the slab allocator
 * @file: unused
 * @buffer: user buffer
 * @count: data length
 * @ppos: unused
 */
ssize_t slabinfo_write(struct file *file, const char __user * buffer,
		       size_t count, loff_t *ppos)
{
	char kbuf[MAX_SLABINFO_WRITE + 1], *tmp;
	int limit, batchcount, shared, res;
	struct kmem_cache *cachep;

	if (count > MAX_SLABINFO_WRITE)
		return -EINVAL;
	if (copy_from_user(&kbuf, buffer, count))
		return -EFAULT;
	kbuf[MAX_SLABINFO_WRITE] = '\0';

	tmp = strchr(kbuf, ' ');
	if (!tmp)
		return -EINVAL;
	*tmp = '\0';
	tmp++;
	if (sscanf(tmp, " %d %d %d", &limit, &batchcount, &shared) != 3)
		return -EINVAL;

	/* Find the cache in the chain of caches. */
	mutex_lock(&cache_chain_mutex);
	res = -EINVAL;
	list_for_each_entry(cachep, &cache_chain, next) {
		if (!strcmp(cachep->name, kbuf)) {
			if (limit < 1 || batchcount < 1 ||
					batchcount > limit || shared < 0) {
				res = 0;
			} else {
				res = do_tune_cpucache(cachep, limit,
						       batchcount, shared);
			}
			break;
		}
	}
	mutex_unlock(&cache_chain_mutex);
	if (res >= 0)
		res = count;
	return res;
}

#ifdef CONFIG_DEBUG_SLAB_LEAK

static void *leaks_start(struct seq_file *m, loff_t *pos)
{
	mutex_lock(&cache_chain_mutex);
	return seq_list_start(&cache_chain, *pos);
}

static inline int add_caller(unsigned long *n, unsigned long v)
{
	unsigned long *p;
	int l;
	if (!v)
		return 1;
	l = n[1];
	p = n + 2;
	while (l) {
		int i = l/2;
		unsigned long *q = p + 2 * i;
		if (*q == v) {
			q[1]++;
			return 1;
		}
		if (*q > v) {
			l = i;
		} else {
			p = q + 2;
			l -= i + 1;
		}
	}
	if (++n[1] == n[0])
		return 0;
	memmove(p + 2, p, n[1] * 2 * sizeof(unsigned long) - ((void *)p - (void *)n));
	p[0] = v;
	p[1] = 1;
	return 1;
}

static void handle_slab(unsigned long *n, struct kmem_cache *c, struct slab *s)
{
	void *p;
	int i;
	if (n[0] == n[1])
		return;
	for (i = 0, p = s->s_mem; i < c->num; i++, p += c->buffer_size) {
		if (slab_bufctl(s)[i] != BUFCTL_ACTIVE)
			continue;
		if (!add_caller(n, (unsigned long)*dbg_userword(c, p)))
			return;
	}
}

static void show_symbol(struct seq_file *m, unsigned long address)
{
#ifdef CONFIG_KALLSYMS
	unsigned long offset, size;
	char modname[MODULE_NAME_LEN], name[KSYM_NAME_LEN];

	if (lookup_symbol_attrs(address, &size, &offset, modname, name) == 0) {
		seq_printf(m, "%s+%#lx/%#lx", name, offset, size);
		if (modname[0])
			seq_printf(m, " [%s]", modname);
		return;
	}
#endif
	seq_printf(m, "%p", (void *)address);
}

static int leaks_show(struct seq_file *m, void *p)
{
	struct kmem_cache *cachep = list_entry(p, struct kmem_cache, next);
	struct slab *slabp;
	struct kmem_list3 *l3;
	const char *name;
	unsigned long *n = m->private;
	int node;
	int i;

	if (!(cachep->flags & SLAB_STORE_USER))
		return 0;
	if (!(cachep->flags & SLAB_RED_ZONE))
		return 0;

	/* OK, we can do it */

	n[1] = 0;

	for_each_online_node(node) {
		l3 = cachep->nodelists[node];
		if (!l3)
			continue;

		check_irq_on();
		spin_lock_irq(&l3->list_lock);

		list_for_each_entry(slabp, &l3->slabs_full, list)
			handle_slab(n, cachep, slabp);
		list_for_each_entry(slabp, &l3->slabs_partial, list)
			handle_slab(n, cachep, slabp);
		spin_unlock_irq(&l3->list_lock);
	}
	name = cachep->name;
	if (n[0] == n[1]) {
		/* Increase the buffer size */
		mutex_unlock(&cache_chain_mutex);
		m->private = kzalloc(n[0] * 4 * sizeof(unsigned long), GFP_KERNEL);
		if (!m->private) {
			/* Too bad, we are really out */
			m->private = n;
			mutex_lock(&cache_chain_mutex);
			return -ENOMEM;
		}
		*(unsigned long *)m->private = n[0] * 2;
		kfree(n);
		mutex_lock(&cache_chain_mutex);
		/* Now make sure this entry will be retried */
		m->count = m->size;
		return 0;
	}
	for (i = 0; i < n[1]; i++) {
		seq_printf(m, "%s: %lu ", name, n[2*i+3]);
		show_symbol(m, n[2*i+2]);
		seq_putc(m, '\n');
	}

	return 0;
}

const struct seq_operations slabstats_op = {
	.start = leaks_start,
	.next = s_next,
	.stop = s_stop,
	.show = leaks_show,
};
#endif
#endif

/**
 * ksize - get the actual amount of memory allocated for a given object
 * @objp: Pointer to the object
 *
 * kmalloc may internally round up allocations and return more memory
 * than requested. ksize() can be used to determine the actual amount of
 * memory allocated. The caller may use this additional memory, even though
 * a smaller amount of memory was initially specified with the kmalloc call.
 * The caller must guarantee that objp points to a valid object previously
 * allocated with either kmalloc() or kmem_cache_alloc(). The object
 * must not be freed during the duration of the call.
 */
size_t ksize(const void *objp)
{
	BUG_ON(!objp);
	if (unlikely(objp == ZERO_SIZE_PTR))
		return 0;

	return obj_size(virt_to_cache(objp));
}
EXPORT_SYMBOL(ksize);
