/*
 * 2.5 block I/O model
 *
 * Copyright (C) 2001 Jens Axboe <axboe@suse.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of

 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public Licens
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-
 */
#ifndef __LINUX_BIO_H
#define __LINUX_BIO_H

#include <linux/highmem.h>
#include <linux/mempool.h>
#include <linux/ioprio.h>

#ifdef CONFIG_BLOCK

/* Platforms may set this to teach the BIO layer about IOMMU hardware. */
#include <asm/io.h>

#if defined(BIO_VMERGE_MAX_SIZE) && defined(BIO_VMERGE_BOUNDARY)
#define BIOVEC_VIRT_START_SIZE(x) (bvec_to_phys(x) & (BIO_VMERGE_BOUNDARY - 1))
#define BIOVEC_VIRT_OVERSIZE(x)	((x) > BIO_VMERGE_MAX_SIZE)
#else
#define BIOVEC_VIRT_START_SIZE(x)	0
#define BIOVEC_VIRT_OVERSIZE(x)		0
#endif

#ifndef BIO_VMERGE_BOUNDARY
#define BIO_VMERGE_BOUNDARY	0
#endif

#define BIO_DEBUG

#ifdef BIO_DEBUG
#define BIO_BUG_ON	BUG_ON
#else
#define BIO_BUG_ON
#endif

#define BIO_MAX_PAGES		256
#define BIO_MAX_SIZE		(BIO_MAX_PAGES << PAGE_CACHE_SHIFT)
#define BIO_MAX_SECTORS		(BIO_MAX_SIZE >> 9)

/*
 * was unsigned short, but we might as well be ready for > 64kB I/O pages
 *
 * bio中的每个段都是由bio_vec描述的
 */
struct bio_vec {
	struct page	*bv_page;
	unsigned int	bv_len;
	unsigned int	bv_offset; /* 页内偏移量 */
};

struct bio_set;
struct bio;
typedef void (bio_end_io_t) (struct bio *, int);
typedef void (bio_destructor_t) (struct bio *);

/*
 * main unit of I/O for the block layer and lower layers (ie drivers and
 * stacking drivers)
 * 一个request中可以有多个bio，一个bio中可以有多个page
 */
struct bio {
    //在初始阶段为相对于磁盘分区的起始扇区号, 在blk_partition_remap()转成相对于磁盘的起始扇区号
	sector_t		bi_sector;	/* 指定传输的扇区起始号, device address in 512 byte
						   sectors */
	struct bio		*bi_next;	/* request queue link */
	/*
	 * 如果bio->bi_bdev == bio->bi_bdev->bd_contains
	 * 说明已经将bi_sector从相对于分区的扇区号转成相对于磁盘的扇区号了。
	 *
	 */
	struct block_device	*bi_bdev; //指向请求所属设备的block_device
	unsigned long		bi_flags;	/* status, command, etc */
	unsigned long		bi_rw;		/* 区分是读还是写操作 bottom bits READ/WRITE,
						 * top bits priority
						 */
    // bi_io_vec 数组的长度,就是数组中段的数目.
	unsigned short		bi_vcnt;	/* how many bio_vec's */
	unsigned short		bi_idx;		/* bio操作中 bio_vec[]数组中段的当前索引值.current index into bvl_vec */

	/* Number of segments in this BIO after
	 * physical address coalescing is performed.
	 *
	 * 下面二者指定了传输中段的数目
	 *
	 */
	 //合并之后bio中硬件段的数目
	unsigned short		bi_phys_segments;

	/* Number of segments after physical and DMA remapping
	 * hardware coalescing is performed.
	 */
	 //合并之后硬件段的数目
	unsigned short		bi_hw_segments;

    //需要传送的直接数量
	unsigned int		bi_size;	/* residual I/O count */

	/*
	 * To keep track of the max hw size, we account for the
	 * sizes of the first and last virtually mergeable segments
	 * in this bio
	 */
 	unsigned int		bi_hw_front_size;   // 硬件段合并算法使用
	unsigned int		bi_hw_back_size;    // 硬件段合并算法使用

	unsigned int		bi_max_vecs;	/* bi_io_vec数组中允许的最大段数, max bvl_vecs we can hold */

    //bio中的每个段都是由bio_vec描述的
	struct bio_vec		*bi_io_vec;	/* bio_vec数组, bio涉及到的page, 这里的page可以是高端内存页,这些page无法直接映射到内核中，因而无法直接通过内核虚拟地址访问,可以利用这个特点将I/O数据直接复制给用户空间应用程序,而应用程序可以使用页表访问高端内存页
	                                    the actual vec list */

    /* 硬件传输完成时,设备驱动调用bi_end_io
     *
     * mpage_end_io_write(),
     * bounce_end_io_write(),
     * bounce_end_io_read()
     * bounce_end_io_write_isa()
     * bounce_end_io_read_isa()
     */
	bio_end_io_t		*bi_end_io;
	atomic_t		bi_cnt;		/* 引用计数 pin count */

	void			*bi_private; //通用块层和设备驱动程序的I/O完成方法使用的指针

	bio_destructor_t	*bi_destructor;	/* destructor */
};

/*
 * bio flags
 */
#define BIO_UPTODATE	0	/* ok after I/O completion */
#define BIO_RW_BLOCK	1	/* RW_AHEAD set, and read/write would block */
#define BIO_EOF		2	/* out-out-bounds error */
#define BIO_SEG_VALID	3	/* nr_hw_seg valid */
#define BIO_CLONED	4	/* doesn't own data */
#define BIO_BOUNCED	5	/* bio is a bounce bio */
#define BIO_USER_MAPPED 6	/* contains user pages */
#define BIO_EOPNOTSUPP	7	/* not supported */
#define bio_flagged(bio, flag)	((bio)->bi_flags & (1 << (flag)))

/*
 * top 4 bits of bio flags indicate the pool this bio came from
 */
#define BIO_POOL_BITS		(4)
#define BIO_POOL_OFFSET		(BITS_PER_LONG - BIO_POOL_BITS)
#define BIO_POOL_MASK		(1UL << BIO_POOL_OFFSET)
#define BIO_POOL_IDX(bio)	((bio)->bi_flags >> BIO_POOL_OFFSET)	

/*
 * bio bi_rw flags
 *
 * bit 0 -- read (not set) or write (set)
 * bit 1 -- rw-ahead when set
 * bit 2 -- barrier
 * bit 3 -- fail fast, don't want low level driver retries
 * bit 4 -- synchronous I/O hint: the block layer will unplug immediately
 */
#define BIO_RW		0
#define BIO_RW_AHEAD	1
#define BIO_RW_BARRIER	2
#define BIO_RW_FAILFAST	3
#define BIO_RW_SYNC	4
#define BIO_RW_META	5

/*
 * upper 16 bits of bi_rw define the io priority of this bio
 */
#define BIO_PRIO_SHIFT	(8 * sizeof(unsigned long) - IOPRIO_BITS)
#define bio_prio(bio)	((bio)->bi_rw >> BIO_PRIO_SHIFT)
#define bio_prio_valid(bio)	ioprio_valid(bio_prio(bio))

#define bio_set_prio(bio, prio)		do {			\
	WARN_ON(prio >= (1 << IOPRIO_BITS));			\
	(bio)->bi_rw &= ((1UL << BIO_PRIO_SHIFT) - 1);		\
	(bio)->bi_rw |= ((unsigned long) (prio) << BIO_PRIO_SHIFT);	\
} while (0)

/*
 * various member access, note that bio_data should of course not be used
 * on highmem page vectors
 */
#define bio_iovec_idx(bio, idx)	(&((bio)->bi_io_vec[(idx)]))
#define bio_iovec(bio)		bio_iovec_idx((bio), (bio)->bi_idx)
#define bio_page(bio)		bio_iovec((bio))->bv_page
#define bio_offset(bio)		bio_iovec((bio))->bv_offset
#define bio_segments(bio)	((bio)->bi_vcnt - (bio)->bi_idx)
#define bio_sectors(bio)	((bio)->bi_size >> 9)
#define bio_barrier(bio)	((bio)->bi_rw & (1 << BIO_RW_BARRIER))
#define bio_sync(bio)		((bio)->bi_rw & (1 << BIO_RW_SYNC))
#define bio_failfast(bio)	((bio)->bi_rw & (1 << BIO_RW_FAILFAST))
#define bio_rw_ahead(bio)	((bio)->bi_rw & (1 << BIO_RW_AHEAD))
#define bio_rw_meta(bio)	((bio)->bi_rw & (1 << BIO_RW_META))
#define bio_empty_barrier(bio)	(bio_barrier(bio) && !(bio)->bi_size)

static inline unsigned int bio_cur_sectors(struct bio *bio)
{
	if (bio->bi_vcnt)
		return bio_iovec(bio)->bv_len >> 9;

	return 0;
}

static inline void *bio_data(struct bio *bio)
{
	if (bio->bi_vcnt)
		return page_address(bio_page(bio)) + bio_offset(bio);

	return NULL;
}

/*
 * will die
 */
#define bio_to_phys(bio)	(page_to_phys(bio_page((bio))) + (unsigned long) bio_offset((bio)))
#define bvec_to_phys(bv)	(page_to_phys((bv)->bv_page) + (unsigned long) (bv)->bv_offset)

/*
 * queues that have highmem support enabled may still need to revert to
 * PIO transfers occasionally and thus map high pages temporarily. For
 * permanent PIO fall back, user is probably better off disabling highmem
 * I/O completely on that queue (see ide-dma for example)
 */
#define __bio_kmap_atomic(bio, idx, kmtype)				\
	(kmap_atomic(bio_iovec_idx((bio), (idx))->bv_page, kmtype) +	\
		bio_iovec_idx((bio), (idx))->bv_offset)

#define __bio_kunmap_atomic(addr, kmtype) kunmap_atomic(addr, kmtype)

/*
 * merge helpers etc
 */

#define __BVEC_END(bio)		bio_iovec_idx((bio), (bio)->bi_vcnt - 1)
#define __BVEC_START(bio)	bio_iovec_idx((bio), (bio)->bi_idx)

/*
 * allow arch override, for eg virtualized architectures (put in asm/io.h)
 */
#ifndef BIOVEC_PHYS_MERGEABLE
#define BIOVEC_PHYS_MERGEABLE(vec1, vec2)	\
	((bvec_to_phys((vec1)) + (vec1)->bv_len) == bvec_to_phys((vec2)))
#endif

#define BIOVEC_VIRT_MERGEABLE(vec1, vec2)	\
	((((bvec_to_phys((vec1)) + (vec1)->bv_len) | bvec_to_phys((vec2))) & (BIO_VMERGE_BOUNDARY - 1)) == 0)
#define __BIO_SEG_BOUNDARY(addr1, addr2, mask) \
	(((addr1) | (mask)) == (((addr2) - 1) | (mask)))
#define BIOVEC_SEG_BOUNDARY(q, b1, b2) \
	__BIO_SEG_BOUNDARY(bvec_to_phys((b1)), bvec_to_phys((b2)) + (b2)->bv_len, (q)->seg_boundary_mask)
#define BIO_SEG_BOUNDARY(q, b1, b2) \
	BIOVEC_SEG_BOUNDARY((q), __BVEC_END((b1)), __BVEC_START((b2)))

#define bio_io_error(bio) bio_endio((bio), -EIO)

/*
 * drivers should not use the __ version unless they _really_ want to
 * run through the entire bio and not just pending pieces
 */
#define __bio_for_each_segment(bvl, bio, i, start_idx)			\
	for (bvl = bio_iovec_idx((bio), (start_idx)), i = (start_idx);	\
	     i < (bio)->bi_vcnt;					\
	     bvl++, i++)

#define bio_for_each_segment(bvl, bio, i)				\
	__bio_for_each_segment(bvl, bio, i, (bio)->bi_idx)

/*
 * get a reference to a bio, so it won't disappear. the intended use is
 * something like:
 *
 * bio_get(bio);
 * submit_bio(rw, bio);
 * if (bio->bi_flags ...)
 *	do_something
 * bio_put(bio);
 *
 * without the bio_get(), it could potentially complete I/O before submit_bio
 * returns. and then bio would be freed memory when if (bio->bi_flags ...)
 * runs
 */
#define bio_get(bio)	atomic_inc(&(bio)->bi_cnt)


/*
 * A bio_pair is used when we need to split a bio.
 * This can only happen for a bio that refers to just one
 * page of data, and in the unusual situation when the
 * page crosses a chunk/device boundary
 *
 * The address of the master bio is stored in bio1.bi_private
 * The address of the pool the pair was allocated from is stored
 *   in bio2.bi_private
 */
struct bio_pair {
	struct bio	bio1, bio2;
	struct bio_vec	bv1, bv2;
	atomic_t	cnt;
	int		error;
};
extern struct bio_pair *bio_split(struct bio *bi, mempool_t *pool,
				  int first_sectors);
extern mempool_t *bio_split_pool;
extern void bio_pair_release(struct bio_pair *dbio);

extern struct bio_set *bioset_create(int, int);
extern void bioset_free(struct bio_set *);

extern struct bio *bio_alloc(gfp_t, int);
extern struct bio *bio_alloc_bioset(gfp_t, int, struct bio_set *);
extern void bio_put(struct bio *);
extern void bio_free(struct bio *, struct bio_set *);

extern void bio_endio(struct bio *, int);
struct request_queue;
extern int bio_phys_segments(struct request_queue *, struct bio *);
extern int bio_hw_segments(struct request_queue *, struct bio *);

extern void __bio_clone(struct bio *, struct bio *);
extern struct bio *bio_clone(struct bio *, gfp_t);

extern void bio_init(struct bio *);

extern int bio_add_page(struct bio *, struct page *, unsigned int,unsigned int);
extern int bio_add_pc_page(struct request_queue *, struct bio *, struct page *,
			   unsigned int, unsigned int);
extern int bio_get_nr_vecs(struct block_device *);
extern struct bio *bio_map_user(struct request_queue *, struct block_device *,
				unsigned long, unsigned int, int);
struct sg_iovec;
extern struct bio *bio_map_user_iov(struct request_queue *,
				    struct block_device *,
				    struct sg_iovec *, int, int);
extern void bio_unmap_user(struct bio *);
extern struct bio *bio_map_kern(struct request_queue *, void *, unsigned int,
				gfp_t);
extern void bio_set_pages_dirty(struct bio *bio);
extern void bio_check_pages_dirty(struct bio *bio);
extern void bio_release_pages(struct bio *bio);
extern struct bio *bio_copy_user(struct request_queue *, unsigned long, unsigned int, int);
extern int bio_uncopy_user(struct bio *);
void zero_fill_bio(struct bio *bio);

#ifdef CONFIG_HIGHMEM
/*
 * remember to add offset! and never ever reenable interrupts between a
 * bvec_kmap_irq and bvec_kunmap_irq!!
 *
 * This function MUST be inlined - it plays with the CPU interrupt flags.
 */
static inline char *bvec_kmap_irq(struct bio_vec *bvec, unsigned long *flags)
{
	unsigned long addr;

	/*
	 * might not be a highmem page, but the preempt/irq count
	 * balancing is a lot nicer this way
	 */
	local_irq_save(*flags);
	addr = (unsigned long) kmap_atomic(bvec->bv_page, KM_BIO_SRC_IRQ);

	BUG_ON(addr & ~PAGE_MASK);

	return (char *) addr + bvec->bv_offset;
}

static inline void bvec_kunmap_irq(char *buffer, unsigned long *flags)
{
	unsigned long ptr = (unsigned long) buffer & PAGE_MASK;

	kunmap_atomic((void *) ptr, KM_BIO_SRC_IRQ);
	local_irq_restore(*flags);
}

#else
#define bvec_kmap_irq(bvec, flags)	(page_address((bvec)->bv_page) + (bvec)->bv_offset)
#define bvec_kunmap_irq(buf, flags)	do { *(flags) = 0; } while (0)
#endif

static inline char *__bio_kmap_irq(struct bio *bio, unsigned short idx,
				   unsigned long *flags)
{
	return bvec_kmap_irq(bio_iovec_idx(bio, idx), flags);
}
#define __bio_kunmap_irq(buf, flags)	bvec_kunmap_irq(buf, flags)

#define bio_kmap_irq(bio, flags) \
	__bio_kmap_irq((bio), (bio)->bi_idx, (flags))
#define bio_kunmap_irq(buf,flags)	__bio_kunmap_irq(buf, flags)

#endif /* CONFIG_BLOCK */
#endif /* __LINUX_BIO_H */
