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
// Halt codes <= 0x10000 indicate that the emulator should actually halt.

enum halt_codes {
	HALT_NONE	= 0x00000000,
	HALT_EXCEPTION	= 0x00004000, // Do you still need this?
	HALT_BP		= 0x00008000, // Halt on a breakpoint

	// The Unicorn error codes are <= 0x20~ish
	// ...

	// For catching MMIO things (might not be necessary)
	HALT_MMIO_OTP	= 0x01000000,
	HALT_MMIO_SHA	= 0x02000000,
	HALT_MMIO_AES	= 0x04000000,
	HALT_MMIO_NAND	= 0x08000000,
};

// Flags for book-keeping
enum state {
	STATE_INITED		= 0x8000000000000000,
	STATE_BROM_UNMAPPED	= 0x4000000000000000,
	STATE_SRAM_MIRRORED	= 0x2000000000000000,

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
	u32 timer_pad;		
	u32 timer;		// Hollywood timer
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
