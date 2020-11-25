#ifndef __ASM_MPSPEC_DEF_H
#define __ASM_MPSPEC_DEF_H

/*
 * Structure definitions for SMP machines following the
 * Intel Multiprocessing Specification 1.1 and 1.4.
 */

/*
 * This tag identifies where the SMP configuration
 * information is. 
 */
 
#define SMP_MAGIC_IDENT	(('_'<<24)|('P'<<16)|('M'<<8)|'_')

#define MAX_MPC_ENTRY 1024
#define MAX_APICS      256

struct intel_mp_floating
{
	char mpf_signature[4];		/* "_MP_" 			*/
	unsigned long mpf_physptr;	/* Configuration table address	*/
	unsigned char mpf_length;	/* Our length (paragraphs)	*/
	unsigned char mpf_specification;/* Specification version	*/
	unsigned char mpf_checksum;	/* Checksum (makes sum 0)	*/
	unsigned char mpf_feature1;	/* Standard or configuration ? 	*/
	unsigned char mpf_feature2;	/* Bit7 set for IMCR|PIC	*/
	unsigned char mpf_feature3;	/* Unused (0)			*/
	unsigned char mpf_feature4;	/* Unused (0)			*/
	unsigned char mpf_feature5;	/* Unused (0)			*/
};

struct mp_config_table
{
	char mpc_signature[4];
#define MPC_SIGNATURE "PCMP"
	unsigned short mpc_length;	/* Size of table */
	char  mpc_spec;			/* 0x01 */
	char  mpc_checksum;
	char  mpc_oem[8];
	char  mpc_productid[12];
	unsigned long mpc_oemptr;	/* 0 if not present */
	unsigned short mpc_oemsize;	/* 0 if not present */
	unsigned short mpc_oemcount;
	unsigned long mpc_lapic;	/* APIC address */
	unsigned long reserved;
};

/* Followed by entries */

#define	MP_PROCESSOR	0
#define	MP_BUS		1
#define	MP_IOAPIC	2
#define	MP_INTSRC	3
#define	MP_LINTSRC	4
#define	MP_TRANSLATION  192  /* Used by IBM NUMA-Q to describe node locality */

struct mpc_config_processor
{
	unsigned char mpc_type;
	unsigned char mpc_apicid;	/* Local APIC number */
	unsigned char mpc_apicver;	/* Its versions */
	unsigned char mpc_cpuflag;
#define CPU_ENABLED		1	/* Processor is available */
#define CPU_BOOTPROCESSOR	2	/* Processor is the BP */
	unsigned long mpc_cpufeature;		
#define CPU_STEPPING_MASK 0x0F
#define CPU_MODEL_MASK	0xF0
#define CPU_FAMILY_MASK	0xF00
	unsigned long mpc_featureflag;	/* CPUID feature value */
	unsigned long mpc_reserved[2];
};

struct mpc_config_bus
{
	unsigned char mpc_type;
	unsigned char mpc_busid;
	unsigned char mpc_bustype[6];
};

/* List of Bus Type string values, Intel MP Spec. */
#define BUSTYPE_EISA	"EISA"
#define BUSTYPE_ISA	"ISA"
#define BUSTYPE_INTERN	"INTERN"	/* Internal BUS */
#define BUSTYPE_MCA	"MCA"
#define BUSTYPE_VL	"VL"		/* Local bus */
#define BUSTYPE_PCI	"PCI"
#define BUSTYPE_PCMCIA	"PCMCIA"
#define BUSTYPE_CBUS	"CBUS"
#define BUSTYPE_CBUSII	"CBUSII"
#define BUSTYPE_FUTURE	"FUTURE"
#define BUSTYPE_MBI	"MBI"
#define BUSTYPE_MBII	"MBII"
#define BUSTYPE_MPI	"MPI"
#define BUSTYPE_MPSA	"MPSA"
#define BUSTYPE_NUBUS	"NUBUS"
#define BUSTYPE_TC	"TC"
#define BUSTYPE_VME	"VME"
#define BUSTYPE_XPRESS	"XPRESS"

/*
 * 内核用 mp_ioapics 全局数组存放系统中所有 IOAPIC 对应的 struct mpc_config_ioapic，
 * nr_ioapics 为 IOAPIC 数量。目前 Linux 最多支持 64 个 IOAPIC，当数量超过时可以配置
 * MAX_IO_APICS 宏扩大限制
 *
 * 对应 MP spec 的 IOAPIC entry
 */
struct mpc_config_ioapic
{
	unsigned char mpc_type;
	unsigned char mpc_apicid;
	unsigned char mpc_apicver;
	/*
	 * 最低 bit 有效，其余 bit 预留
     * 0：IOAPIC disabled
     * 1：IOAPIC enabled
     */
	unsigned char mpc_flags;
#define MPC_APIC_USABLE		0x01
    //该 IOAPIC 基地址
	unsigned long mpc_apicaddr;
};

/*
 * 对应 MP spec 的 IO interrupt entry，
 * 代表各个中断源（一个 IOAPIC管脚连接一个中断源）
 */
struct mpc_config_intsrc
{
	unsigned char mpc_type;
	unsigned char mpc_irqtype;
	unsigned short mpc_irqflag;
	unsigned char mpc_srcbus;
	unsigned char mpc_srcbusirq;
	unsigned char mpc_dstapic;
	unsigned char mpc_dstirq;
};

enum mp_irq_source_types {
	mp_INT = 0,
	mp_NMI = 1,
	mp_SMI = 2,
	mp_ExtINT = 3
};

#define MP_IRQDIR_DEFAULT	0
#define MP_IRQDIR_HIGH		1
#define MP_IRQDIR_LOW		3


/*
 * 定义和 mpc_config_intsrc 一样。只是 mpc_dstapic 代表 LAPIC ，
 * 且 mpc_dstirq 只能取值 0 或 1。
 */
struct mpc_config_lintsrc
{
	unsigned char mpc_type;
	unsigned char mpc_irqtype;
	unsigned short mpc_irqflag;
	unsigned char mpc_srcbusid;
	unsigned char mpc_srcbusirq;
	unsigned char mpc_destapic;	
#define MP_APIC_ALL	0xFF
	unsigned char mpc_destapiclint;
};

struct mp_config_oemtable
{
	char oem_signature[4];
#define MPC_OEM_SIGNATURE "_OEM"
	unsigned short oem_length;	/* Size of table */
	char  oem_rev;			/* 0x01 */
	char  oem_checksum;
	char  mpc_oem[8];
};

struct mpc_config_translation
{
        unsigned char mpc_type;
        unsigned char trans_len;
        unsigned char trans_type;
        unsigned char trans_quad;
        unsigned char trans_global;
        unsigned char trans_local;
        unsigned short trans_reserved;
};

/*
 *	Default configurations
 *
 *	1	2 CPU ISA 82489DX
 *	2	2 CPU EISA 82489DX neither IRQ 0 timer nor IRQ 13 DMA chaining
 *	3	2 CPU EISA 82489DX
 *	4	2 CPU MCA 82489DX
 *	5	2 CPU ISA+PCI
 *	6	2 CPU EISA+PCI
 *	7	2 CPU MCA+PCI
 */

enum mp_bustype {
	MP_BUS_ISA = 1,
	MP_BUS_EISA,
	MP_BUS_PCI,
	MP_BUS_MCA,
};
#endif

