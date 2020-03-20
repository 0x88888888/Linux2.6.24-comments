/*
 * linux/arch/i386/mm/extable.c
 */

#include <linux/module.h>
#include <linux/spinlock.h>
#include <asm/uaccess.h>

/*fixup_exception()用于搜索异常表，并试图找到一个对应该异常的例程来进行修正， 
  这个例程在fixup_exception()返回后执行
  *
  * copy_from_user出现用户态内存没有准备好时，也从这个函数走
  */

int fixup_exception(struct pt_regs *regs)
{
	const struct exception_table_entry *fixup;

#ifdef CONFIG_PNPBIOS
	if (unlikely(SEGMENT_IS_PNP_CODE(regs->xcs)))
	{
		extern u32 pnp_bios_fault_eip, pnp_bios_fault_esp;
		extern u32 pnp_bios_is_utter_crap;
		pnp_bios_is_utter_crap = 1;
		printk(KERN_CRIT "PNPBIOS fault.. attempting recovery.\n");
		__asm__ volatile(
			"movl %0, %%esp\n\t"
			"jmp *%1\n\t"
			: : "g" (pnp_bios_fault_esp), "g" (pnp_bios_fault_eip));
		panic("do_trap: can't hit this");
	}
#endif

/* 从__start__ex_table和__stop_ex_table中查找 异常处理程序 */
	fixup = search_exception_tables(regs->eip);
	if (fixup) {
		regs->eip = fixup->fixup;
		return 1;
	}

	return 0;
}
