#ifndef _HOLLYWOOD_H
#define _HOLLYWOOD_H

enum arm_irq {
	IRQ_TIMER	= 0x00000001,
	IRQ_NAND	= 0x00000002,
	IRQ_AES		= 0x00000004,
	IRQ_SHA		= 0x00000008,

	IRQ_EHCI	= 0x00000010,
	IRQ_OHCI0	= 0x00000020,
	IRQ_OHCI1	= 0x00000040,
	IRQ_SDHC	= 0x00000080,

	IRQ_WIFI	= 0x00000100,
	IRQ_UNK9	= 0x00000200,
	IRQ_PPCGPIO	= 0x00000400,
	IRQ_ARMGPIO	= 0x00000800,

	IRQ_UNK12	= 0x00001000,
	IRQ_UNK13	= 0x00002000,
	IRQ_UNK14	= 0x00004000,
	IRQ_UNK15	= 0x00008000,

	IRQ_UNK16	= 0x00010000,
	IRQ_RESETBTN	= 0x00020000,
	IRQ_DI		= 0x00040000,
	IRQ_UNK19	= 0x00080000,

	IRQ_UNK20	= 0x00100000,
	IRQ_UNK21	= 0x00200000,
	IRQ_UNK22	= 0x00400000,
	IRQ_UNK23	= 0x00800000,

	IRQ_UNK24	= 0x01000000,
	IRQ_UNK25	= 0x02000000,
	IRQ_UNK26	= 0x04000000,
	IRQ_UNK27	= 0x08000000,

	IRQ_UNK28	= 0x10000000,
	IRQ_UNK29	= 0x20000000,
	IRQ_PPCIPC	= 0x40000000,
	IRQ_ARMIPC	= 0x80000000,
};

// ----------------------------------------------------------------------------

// NAND controller
#define NAND_CTRL		0x0d010000
#define NAND_CFG		0x0d010004
#define NAND_ADDR1		0x0d010008
#define NAND_ADDR2		0x0d01000c
#define NAND_DATABUF		0x0d010010
#define NAND_ECCBUF		0x0d010014
#define NAND_UNK1		0x0d010018
#define NAND_UNK2		0x0d010018

// AES engine
#define AES_CTRL		0x0d020000
#define AES_SRC			0x0d020004
#define AES_DST			0x0d020008
#define AES_KEY_FIFO		0x0d02000c
#define AES_IV_FIFO		0x0d020010

// SHA-1 engine
#define SHA_CTRL		0x0d030000
#define SHA_SRC			0x0d030004
#define SHA_H0			0x0d030008
#define SHA_H1			0x0d03000c
#define SHA_H2			0x0d030010
#define SHA_H3			0x0d030014
#define SHA_H4			0x0d030018

// Other I/Os
#define EHCI_CTRL		0x0d040000
#define OHCI0_CTRL		0x0d050000
#define OHCI1_CTRL		0x0d060000
#define SDHC_CTRL		0x0d070000
#define WLAN_CTRL		0x0d080000


// Hollywood register space
#define HW_IPC_PPCMSG		0x0d800000
#define HW_IPC_PPCCTR		0x0d800004
#define HW_IPC_ARMMSG		0x0d800008
#define HW_IPC_ARMCTRL		0x0d80000c

#define HW_TIMER     		0x0d800010
#define HW_ALARM     		0x0d800014

#define HW_PPCIRQFLAG		0x0d800030
#define HW_PPCIRQMASK		0x0d800034

// IRQ interrupt controller
#define HW_ARM_INTSTS		0x0d800038
#define HW_ARM_INTEN		0x0d80003c

#define HW_SRNPROT    		0x0d800060
#define HW_BUSPROT   		0x0d800064

#define HW_GPIO_ENABLE		0x0d8000dc
#define HW_GPIO_OUT  		0x0d8000e0
#define HW_GPIO_OUT_ENABLE 	0x0d8000e4
#define HW_GPIO_IN   		0x0d8000e8
#define HW_GPIO_INT_POLARITY	0x0d8000ec
#define HW_GPIO_INT_STATUS	0x0d8000f0
#define HW_GPIO_INT_ENABLE	0x0d8000f4
#define HW_GPIO_STRAPS		0x0d8000f8
#define HW_GPIO_OWNER		0x0d8000fc

#define HW_ARB_CFG_M0		0x0d800100
#define HW_ARB_CFG_M1		0x0d800104
#define HW_ARB_CFG_M2		0x0d800108
#define HW_ARB_CFG_M3		0x0d80010c
#define HW_ARB_CFG_M4		0x0d800110
#define HW_ARB_CFG_M5		0x0d800114
#define HW_ARB_CFG_M6		0x0d800118
#define HW_ARB_CFG_M7		0x0d80011c
#define HW_ARB_CFG_M8		0x0d800120
#define HW_ARB_CFG_M9		0x0d800124
#define HW_ARB_CFG_MA		0x0d800128
#define HW_ARB_CFG_MB		0x0d80012c
#define HW_ARB_CFG_MC		0x0d800130
#define HW_ARB_CFG_MD		0x0d800134
#define HW_ARB_CFG_ME		0x0d800138
#define HW_ARB_CFG_MF		0x0d80013c
#define HW_ARB_CFG_CPU		0x0d800140
#define HW_ARB_CFG_DMA		0x0d800144


#define HW_SPARE0		0x0d800188
#define HW_BOOT0		0x0d80018c

#define HW_PLLSYS		0x0d8001b0
#define HW_PLLSYSEXT		0x0d8001b4

#define EFUSE_ADDR    		0x0d8001ec
#define EFUSE_DATA   		0x0d8001f0
#define HW_VERSION   		0x0d800214

#define DDR_PROT_DDR     	0x0d8b420a
#define DDR_PROT_DDR_BASE	0x0d8b420c
#define DDR_PROT_DDR_END 	0x0d8b420e
#define DDR_AHMFLUSH		0x0d8b4228
#define DDR_AHMFLUSH_ACK 	0x0d8b422a

// ----------------------------------------------------------------------------

#define GPIO_POWER		0x00000001
#define GPIO_SHUTDOWN		0x00000002
#define GPIO_FAN		0x00000004
#define GPIO_DCDC		0x00000008

#define GPIO_DI_SPIN		0x00000010
#define GPIO_SLOT_LED		0x00000020
#define GPIO_EJECT_BUTTON	0x00000040
#define GPIO_SLOT_IN		0x00000080

#define GPIO_SENSOR_BAR		0x00000100
#define GPIO_DO_EJECT		0x00000200
#define GPIO_SEEPROM_CS		0x00000400
#define GPIO_SEEPROM_CLK	0x00000800

#define GPIO_SEEPROM_MOSI	0x00001000
#define GPIO_SEEPROM_MISO	0x00002000
#define GPIO_AVE_SCL		0x00004000
#define GPIO_AVE_SDA		0x00008000

#define GPIO_DEBUG0		0x00010000
#define GPIO_DEBUG1		0x00020000
#define GPIO_DEBUG2		0x00040000
#define GPIO_DEBUG3		0x00080000

#define GPIO_DEBUG4		0x00100000
#define GPIO_DEBUG5		0x00200000
#define GPIO_DEBUG6		0x00400000
#define GPIO_DEBUG7		0x00800000

#define GPIO_DEBUG_PINS		0x00ff0000

#endif // _HOLLYWOOD_H
