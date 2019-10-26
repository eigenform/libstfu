#ifndef _CORE_TYPES_H
#define _CORE_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <unicorn/unicorn.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;


// Halt reason codes. The main loop uses either this enum, or Unicorn's codes
// in order to distinguish exactly what needs to happen when execution halts.
// 
// Halt codes < 0x10000 indicate that the emulator should actually halt.

enum halt_codes {

	HALT_INTERRUPT			= 0x80000000,
	HALT_INSN_INVALID		= 0x40000000,


	HALT_BROM_ON_TO_SRAM_ON		= 0x00800000,
	HALT_SRAM_ON_TO_BROM_OFF	= 0x00400000,
	//HALT_xxxx			= 0x00200000,
	//HALT_xxxx			= 0x00100000,

	HALT_BLOCK_HOOK_DONE		= 0x00080000,

	// Halt codes < 0x10000 break out of the main loop
	HALT_BP				= 0x00008000,
	HALT_EXCEPTION			= 0x00004000,
	HALT_NONE			= 0x00000000,
};

// Flags for book-keeping
enum state {
	STATE_INITED		= 0x8000000000000000,
	STATE_BROM_MAP_ON	= 0x4000000000000000,
	STATE_SRAM_MIRROR_ON	= 0x2000000000000000,

	STATE_BOOT0		= 0x0800000000000000,
	STATE_BOOT1		= 0x0400000000000000,
	STATE_BOOT2		= 0x0200000000000000,
};

// These containers are used to hold the actual backing memory for Unicorn.
// During execution these are all HOT; need to think of a good strategy
// for making sure accesses to these are as fast as possible.

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

typedef struct otpmem
{
	u32 data[0x20];
} otpmem;

// State for various I/O devices (NAND, AES, SHA, etc.)

typedef struct nand_interface
{
	u8 *data;		// Underlying NAND flash data
	u64 data_len;		// Size of underlying flash data

} nand_interface;


// Container describing an instance of the Starlet emulator.
// This will probably be used alot, so there are probably some optimizations
// we can do to make accesses on this super-fast.

typedef struct starlet
{
	// Emulator state

	uc_engine *uc;		// Pointer to an instance of Unicorn
	u32 timer;		// Hollywood timer
	u32 interrupt;


	uc_hook halt_hook;
	u64 timeout;		// Emulation timeout, in seconds
	u64 halt_code;		// Reason for emulator halt
	u64 state;		// State bitfield
	u64 entrypoint;		// The initial entrypoint

	nand_interface nand;	// NAND controller interface
	iomem iomem;		// MMIO backing memory

	sram sram;		// SRAM backing memory

	mram mram;		// Main RAM backing memory
	otpmem otp;		// EFUSE/OTP backing memory


} starlet;


#endif // _CORE_TYPES_H
