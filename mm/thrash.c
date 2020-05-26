/*
 * mm/thrash.c
 *
 * Copyright (C) 2004, Red Hat, Inc.
 * Copyright (C) 2004, Rik van Riel <riel@redhat.com>
 * Released under the GPL, see the file COPYING for details.
 *
 * Simple token based thrashing protection, using the algorithm
 * described in:  http://www.cs.wm.edu/~sjiang/token.pdf
 *
 * Sep 2006, Ashwin Chaugule <ashwin.chaugule@celunite.com>
 * Improved algorithm to pass token:
 * Each task has a priority which is incremented if it contended
 * for the token in an interval less than its previous attempt.
 * If the token is acquired, that task's priority is boosted to prevent
 * the token from bouncing around too often and to let the task make
 * some progress in its execution.
 */

#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/swap.h>

static DEFINE_SPINLOCK(swap_token_lock);

/* 拥有这个swap token的进程，不允许进程的内存被swap 出去 
 * 看grab_swap_token()
 */
struct mm_struct *swap_token_mm;

/* 统计do_swap_page的调用次数 */
static unsigned int global_faults;

/*
 * do_page_fault()
 *  handle_pte_fault()
 *   do_swap_page()
 *    grab_swap_token()
 */
void grab_swap_token(void)
{
	int current_interval;

	global_faults++;

	current_interval = global_faults - current->mm->faultstamp;

	if (!spin_trylock(&swap_token_lock))
		return;

	/* First come first served */
	/* swap_token_mm还没有被进程拥有 */
	if (swap_token_mm == NULL) {
		current->mm->token_priority = current->mm->token_priority + 2;
		swap_token_mm = current->mm;
		goto out;
	}

    /* 如果swap_token_mm已经被某个进程拥有 */
	if (current->mm != swap_token_mm) {
		
		if (current_interval < current->mm->last_interval)
			current->mm->token_priority++;
		else {
			if (likely(current->mm->token_priority > 0))
				current->mm->token_priority--;
		}
		
		/* Check if we deserve the token 
		 * 表示拥有swap_token的优先级超越swap_token_mm->token_priority
		 * 就去拥有swap_token
		 */
		if (current->mm->token_priority >
				swap_token_mm->token_priority) {
			current->mm->token_priority += 2;
			swap_token_mm = current->mm;
        }

	} else {
	    /* 当前进程已经拥有swap_token_mm了,那就意味着需要换入大量的page了 */
		/* Token holder came in again! */
		current->mm->token_priority += 2;
	}

out:
	current->mm->faultstamp = global_faults;
	current->mm->last_interval = current_interval;
	spin_unlock(&swap_token_lock);
return;
}

/* Called on process exit. */
void __put_swap_token(struct mm_struct *mm)
{
	spin_lock(&swap_token_lock);
	if (likely(mm == swap_token_mm))
		swap_token_mm = NULL;
	spin_unlock(&swap_token_lock);
}
