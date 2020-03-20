/* defines for inline arch setup functions */
#include <linux/clockchips.h>

#include <asm/i8259.h>
#include <asm/i8253.h>

/**
 * do_timer_interrupt_hook - hook into timer tick
 *
 * Call the pit clock event handler. see asm/i8253.h
 *
 * time_interrupt()
 *  do_timer_interrupt_hook()
 **/

static inline void do_timer_interrupt_hook(void)
{
    /*
     * 这个global_clock_event要么是hpet_clockevent，要么是pit_clockevent
     * 
     * event_handler可以是 tick_handle_periodic      periodic模式  ， 低精度模式 ,periodic tick
     *                     tick_nohz_handler      one shot模式， 低精度模式 , dynamic tick     
     *                     hrtimer_interrupt      高精度模式 periodic模式或者one shot模式 (lapic时钟中断)
     * 
     *
     *                     tick_handle_periodic_broadcast  hpet使用（在lapic停用的时候）
     *                     
     *                     tick_handle_oneshot_broadcast
     */


    /*
     * 调用不同时钟模式下注册的事件处理函数:
     * 周期时钟的处理函数为:tick_handle_periodic()
     * 高精度时钟的处理函数:hrtimer_interrupte()
     * nohz模式下的处理函数为:tick_nohz_hander()
     * 启动启动时默认采用周期时钟，在定时器软中断中检查是否满足模式切换条件，然后切换至相应的模式。
     * Fixme: 为何不在系统初始化时就将需要的时钟模式切换好?这样的话每次软中断定时器中都需要做这些冗余的检查，
     * 是否会影响效率?是否有改进的空间?
     */	
     
	global_clock_event->event_handler(global_clock_event);
}
