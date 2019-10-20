#ifndef _HOLLYWOOD_H
#define _HOLLYWOOD_H

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
#define AES_DEST		0x0d020008
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

#define HW_PPCIRQFLAG		0x0d800030
#define HW_PPCIRQMASK		0x0d800034
#define HW_ARMIRQFLAG		0x0d800038
#define HW_ARMIRQMASK		0x0d80003c

#define HW_SRNPROT    		0x0d800060
#define HW_BUSPROT   		0x0d800064

#define HW_GPIO_OUT  		0x0d8000e0

//#define HW_AHB_			0x0d800100
//#define HW_AHB_			0x0d800104
//#define HW_AHB_			0x0d800108
//#define HW_AHB_			0x0d80010c
//#define HW_AHB_			0x0d800110
//#define HW_AHB_			0x0d800114
//#define HW_AHB_			0x0d800118
//#define HW_AHB_			0x0d80011c
//#define HW_AHB_			0x0d800120
//#define HW_AHB_			0x0d800124
//#define HW_AHB_			0x0d800128
//#define HW_AHB_			0x0d80012c
//#define HW_AHB_			0x0d800130
//#define HW_AHB_			0x0d800134
//#define HW_AHB_			0x0d800138
//#define HW_AHB_			0x0d80013c
//#define HW_AHB_			0x0d800140

#define HW_SPARE0
#define HW_SPARE1_BOOT0     	0x0d80018c

#define EFUSE_ADDR    		0x0d8001ec
#define EFUSE_DATA   		0x0d8001f0
#define HW_VERSION   		0x0d800214

#define DDR_PROT_DDR     	0x0d8b420a
#define DDR_PROT_DDR_BASE	0x0d8b420c
#define DDR_PROT_DDR_END 	0x0d8b420e
#define DDR_AHMFLUSH		0x0d8b4228
#define DDR_AHMFLUSH_ACK 	0x0d8b422a

#endif // _HOLLYWOOD_H
