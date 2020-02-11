#ifndef _CORE_TYPES_H
#define _CORE_TYPES_H

#include <stddef.h>
#include <stdbool.h>
#include <unicorn/unicorn.h>
#include "generic_types.h"

// Log message types
#define MAX_ENTRY_LEN	0x100
enum log_types {
	DEBUG,
	SYSTEM,
	IOS,
	SVC,
	MMIO,
	GPIO,
	SEEPROM,
	NAND,
	SHA,
	AES,
	INTERRUPT,
};


/* Halt codes - these are meant to extend the space of Unicorn's uc_err enum.
 * Values < 0x10000 are fatal (causing us to break out of the main loop).
 *
 *	HALT_INTERRUPT			- Generic interrupt handling
 * 	HALT_INSN_INVALID		- Invalid insn/syscall handling
 * 	HALT_IRQ			- IRQ handling
 *
 * 	HALT_SYSCALL_FIXUP		- Post-syscall handling
 * 	HALT_IRQ_FIXUP			- Post-IRQ handling
 *
 * 	HALT_BROM_ON_TO_SRAM_ON		- SRAM mirror enable
 * 	HALT_SRAM_ON_TO_BROM_OFF	- BROM mapping disable
 *
 * 	HALT_BP				- Fatal; user-defined breakpoint
 * 	HALT_UNIMPL			- Fatal; unimplemented behaviour
 * 	HALT_USER			- Fatal; user-requested fatal halt
 */

enum halt_codes {

	HALT_INTERRUPT			= 0x80000000,
	HALT_INSN_INVALID		= 0x40000000,
	HALT_IRQ			= 0x20000000,

	HALT_SYSCALL_FIXUP		= 0x08000000,
	HALT_IRQ_FIXUP			= 0x04000000,

	HALT_BROM_ON_TO_SRAM_ON		= 0x00800000,
	HALT_SRAM_ON_TO_BROM_OFF	= 0x00400000,

	HALT_BP				= 0x00008000,
	HALT_UNIMPL			= 0x00004000,
	HALT_USER			= 0x00002000,
};


/* Flags for internal book-keeping.
 *
 *	STATE_BROM_MAP_ON	- The boot ROM is mapped
 *	STATE_SRAM_MIRROR_ON	- The SRAM mirror is enabled
 *
 *	STATE_BOOT0		- Execution in the boot ROM
 *	STATE_BOOT1		- Execution in the first-stage bootloader
 *	STATE_BOOT2		- Execution in the second-stage bootloader
 */

enum state {
	STATE_BROM_MAP_ON	= 0x4000000000000000,
	STATE_SRAM_MIRROR_ON	= 0x2000000000000000,

	STATE_BOOT0		= 0x0800000000000000,
	STATE_BOOT1		= 0x0400000000000000,
	STATE_BOOT2		= 0x0200000000000000,
};


/* These containers are used to hold the actual backing memory for Unicorn.
 * It's not clear yet if this is the best way to organize things.
 * Note that these correspond to *physical memory* attached to the machine.
 */

typedef struct sram
{
	u8     brom[0x00010000]; // 64K (this might actually be 128K...)
	u8   bank_a[0x00010000]; // 64K
	u8   bank_b[0x00010000]; // 64K
} sram;

typedef struct mram
{
	u8     mem1[0x01800000]; // 24M
	u8     mem2[0x04000000]; // 64M
} mram;

typedef struct iomem
{
	u8       nand[0x00000400]; // 1K, 0x0d010000
	u8        aes[0x00000400]; // 1K, 0x0d020000
	u8        sha[0x00000400]; // 1K, 0x0d030000

	u8       ehci[0x00000400]; // 1K, 0x0d040000
	u8      ohci0[0x00000400]; // 1K, 0x0d050000
	u8      ohci1[0x00000400]; // 1K, 0x0d060000

	u8	 hlwd[0x00000400]; // 1K, 0x0d800000
	u8	  exi[0x00000400]; // 1K, 0x0d806000
	u8    mem_unk[0x00000400]; // 1K, 0x0d8b0000
	u8	  ddr[0x00000400]; // 1K, 0x0d8b4000
} iomem;

typedef struct otpmem { u32 data[0x20]; } otpmem;


/* Containers for the state of various I/O devices. 
 * Some aspects of MMIO device state need to be managed outside of the actual
 * backing memory we have allocated for them.
 */

typedef struct nand_interface
{
	u8 *data;		// Underlying NAND flash data
	u64 data_len;		// Size of underlying flash data

} nand_interface;


typedef struct gpio
{
	u32 arm_out;
} gpio;

typedef struct seeprom
{
	u32 state;
	u32 clock;
	u32 count;
	u32 bits_out;
	u32 bits_in;
	u32 address;
	u32 opcode;
	u16 data[0x80];		// Backing memory
	u32 wren;
} seeprom;


/* Top-level container describing an instance of the Starlet emulator.
 * This could probably be organized a little bit better.
 */

typedef struct starlet
{
	uc_engine *uc;		// Pointer to an instance of Unicorn

	u32 timer;		// Hollywood timer
	u32 interrupt;		// Pending system interrupt number 
	u32 pending_irq;	// Pending IRQ bitmask (1=asserted)
	u32 stepped;		// Are we attached to a debugger?

	uc_hook halt_hook;	// Internal halt hook
	uc_hook fixup_hook;	// Syscall fixup hook

	u64 timeout;		// Emulation timeout, in seconds
	u64 halt_code;		// Reason for emulator halt
	u64 state;		// State bitfield
	u64 entrypoint;		// The initial entrypoint

	nand_interface nand;	// NAND controller interface
	iomem iomem;		// MMIO backing memory
	sram sram;		// SRAM backing memory
	mram mram;		// Main RAM backing memory
	otpmem otp;		// EFUSE/OTP backing memory
	seeprom seeprom;	// SEEPROM interface and backing memory
	gpio gpio;		// GPIO state

	void (*log_hook)(int type, char *entry);
} starlet;


extern const char *log_type_name[];
extern void __log(starlet *e, int type, const char *fmt, ...);
#define LOG(e, type, ...) do { __log(e, type, __VA_ARGS__); } while (0)


#endif // _CORE_TYPES_H
