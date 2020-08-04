#include <linux/pci.h>
#include <linux/init.h>
#include "pci.h"

/* arch_initcall has too random ordering, so call the initializers
   in the right sequence from here. 
 *
 * start_kernel()
 *  rest_init() 中调用kernel_thread()创建kernel_init线程
 *   do_basic_setup()
 *    do_initcalls()
 *     pci_access_init()
 */
static __init int pci_access_init(void)
{
	int type __maybe_unused = 0;

#ifdef CONFIG_PCI_DIRECT
    // raw_pci_ops == pci_direct_conf2
	type = pci_direct_probe();
#endif

#ifdef CONFIG_PCI_MMCONFIG
    // raw_pci_ops == pci_mmcfg
	pci_mmcfg_init(type);
#endif

	if (raw_pci_ops)
		return 0;
#ifdef CONFIG_PCI_BIOS
    //raw_pci_ops== pci_bios_access
	pci_pcbios_init();
#endif
	/*
	 * don't check for raw_pci_ops here because we want pcbios as last
	 * fallback, yet it's needed to run first to set pcibios_last_bus
	 * in case legacy PCI probing is used. otherwise detecting peer busses
	 * fails.
	 */
#ifdef CONFIG_PCI_DIRECT
     //raw_pci_ops== pci_direct_conf1 或者 raw_pci_ops == pci_direct_conf2
	pci_direct_init(type);
#endif
	if (!raw_pci_ops)
		printk(KERN_ERR
		"PCI: Fatal: No config space access function found\n");

	return 0;
}
arch_initcall(pci_access_init);
