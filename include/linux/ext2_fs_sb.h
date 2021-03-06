/*
 *  linux/include/linux/ext2_fs_sb.h
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/include/linux/minix_fs_sb.h
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#ifndef _LINUX_EXT2_FS_SB
#define _LINUX_EXT2_FS_SB

#include <linux/blockgroup_lock.h>
#include <linux/percpu_counter.h>
#include <linux/rbtree.h>

/* XXX Here for now... not interested in restructing headers JUST now */

/* data type for block offset of block group */
typedef int ext2_grpblk_t;

/* data type for filesystem-wide blocks number */
typedef unsigned long ext2_fsblk_t;

#define E2FSBLK "%lu"

/* 这个结构用于表示一个块预留区间，[_rsv_start，_rsv_end] */
struct ext2_reserve_window {
	ext2_fsblk_t		_rsv_start;	/* First byte reserved */
	ext2_fsblk_t		_rsv_end;	/* Last byte reserved or 0 */
};

struct ext2_reserve_window_node {
	struct rb_node	 	rsv_node;
	__u32			rsv_goal_size;
	__u32			rsv_alloc_hit;
	struct ext2_reserve_window	rsv_window;
};


/* 
这个结构描述了一个inode的预留窗口，以及上一次分配的逻辑磁盘块号和物理磁盘块号。
*/
struct ext2_block_alloc_info {
	/* information about reservation window */
	struct ext2_reserve_window_node	rsv_window_node;
	/*
	 * was i_next_alloc_block in ext2_inode_info
	 * is the logical (file-relative) number of the
	 * most-recently-allocated block in this file.
	 * We use this for detecting linearly ascending allocation requests.
	 */
	__u32			last_alloc_logical_block;
	/*
	 * Was i_next_alloc_goal in ext2_inode_info
	 * is the *physical* companion to i_next_alloc_block.
	 * it the the physical block number of the block which was most-recentl
	 * allocated to this file.  This give us the goal (target) for the next
	 * allocation when we detect linearly ascending requests.
	 */
	ext2_fsblk_t		last_alloc_physical_block;
};

#define rsv_start rsv_window._rsv_start
#define rsv_end rsv_window._rsv_end

/*
 * second extended-fs super-block data in memory
 * 是ext2_super_block在内存中的表示,
 * ext2_sb_info的建立是在ext2_fill_super中完成的
 */
struct ext2_sb_info {
	unsigned long s_frag_size;	/* Size of a fragment in bytes */
	unsigned long s_frags_per_block;/* Number of fragments per block */
	unsigned long s_inodes_per_block;/* Number of inodes per block */
	unsigned long s_frags_per_group;/* Number of fragments in a group */
	unsigned long s_blocks_per_group;/* Number of blocks in a group */
	unsigned long s_inodes_per_group;/* Number of inodes in a group */
	unsigned long s_itb_per_group;	/* Number of inode table blocks per group */
	unsigned long s_gdb_count;	/* Number of group descriptor blocks */
	unsigned long s_desc_per_block;	/* Number of group descriptors per block */
	unsigned long s_groups_count;	/* Number of groups in the fs */
	unsigned long s_overhead_last;  /* Last calculated overhead */
	unsigned long s_blocks_last;    /* Last seen block count */
	struct buffer_head * s_sbh;	/*  exr2_super_block信息所在的缓冲区的buffer_head. Buffer containing the super block */
	struct ext2_super_block * s_es;	/* 指向包含磁盘超级块结构的内存首地址，Pointer to the super block in the buffer */
	struct buffer_head ** s_group_desc; /* ext2_group_desc信息所在的缓冲区的buffer head */
	unsigned long  s_mount_opt;  /* 装载选项,EXT2_MOUNT_CHECK, EXT2_MOUNT_XXX这类宏 */
	unsigned long s_sb_block; /* 如果不是从默认的块1读取，而是从其他的块读取，对应的块(相对值)保存在s_sb_block中 */
	uid_t s_resuid;  /*  */
	gid_t s_resgid;
	unsigned short s_mount_state;
	unsigned short s_pad;
	int s_addr_per_block_bits;
	int s_desc_per_block_bits;
	int s_inode_size;
	int s_first_ino;
	spinlock_t s_next_gen_lock;
	u32 s_next_generation;
	unsigned long s_dir_count;  /* 表示目录的总数 */
	/* 每当一个新目录加入,s_debts加1，每当其他类型的文件加入，s_debts减1 */
	u8 *s_debts;  /* 数组,每个数组项对应于一个块组,Orlov分配器使用该数组在一个块组中的文件和目录inode之间保存平衡 */
	struct percpu_counter s_freeblocks_counter;
	struct percpu_counter s_freeinodes_counter;
	struct percpu_counter s_dirs_counter;
	struct blockgroup_lock s_blockgroup_lock;
	/* root of the per fs reservation window tree 
       预分配时使用，预分配只是建议，不是决定.
	*/
	spinlock_t s_rsv_window_lock;
	struct rb_root s_rsv_window_root;
	struct ext2_reserve_window_node s_rsv_window_head;
};

#endif	/* _LINUX_EXT2_FS_SB */
