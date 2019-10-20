/* mmio.c - libstfu memory-mapped i/o 
 *
 * There is apparently no AFTER_WRITE hook in Unicorn [at least, not yet].
 * In order to compensate for this, simply perform I/O operations immediately
 * on relevant write accesses. Then, we can just immediately unset the busy 
 * bit for all I/O control registers on the next mainloop iteration.
 */

#include "mmio.h"
#include "ecc.h"
#include "hollywood.h"
#include "util.h"

#include <openssl/aes.h>
#include <unicorn/unicorn.h>


#define NAND_PAGE_LEN	0x840

#define NAND_FLAG_WAIT	0x08
#define NAND_FLAG_WRITE	0x04
#define NAND_FLAG_READ	0x02
#define NAND_FLAG_ECC	0x01

#define NAND_CMD_RESET	0xff
#define NAND_CMD_READ0b	0x30

#define LOGGING 1
#define DEBUG 1

// ----------------------------------------------------------------------------

// nand_dma_write()
// Do a NAND-to-ARM DMA write.
void nand_dma_write(starlet *starlet, u32 flags, u32 len)
{
	// Grab parameters from the MMIO
	u32 addr2 = htobe32(*(u32*)&starlet->iomem.nand[0x0c]);
	u32 data_addr = htobe32(*(u32*)&starlet->iomem.nand[0x10]);
	u32 ecc_addr = htobe32(*(u32*)&starlet->iomem.nand[0x14]);

	// Get the offset of source data in the NAND buffer
	u32 nand_off = addr2 * NAND_PAGE_LEN;
	u8 *src_buf = &starlet->nand.data[nand_off];

	if (len == 0x800)
	{
		dbg("NAND dma on %08x, len=%08x\n", data_addr, len);
		uc_mem_write(starlet->uc, data_addr, src_buf, len);
		return;
	}
	else if (len == 0x840)
	{
		dbg("NAND dma on %08x, len=%08x\n", data_addr, 0x800);
		dbg("NAND dma on %08x, len=%08x\n", ecc_addr, 0x40);
		uc_mem_write(starlet->uc, data_addr, src_buf, 0x800);
		uc_mem_write(starlet->uc, ecc_addr, src_buf + 0x40, 0x40);

		if (flags & NAND_FLAG_ECC)
		{
			u32 ecc_dst = 0;
			u32 ecc = 0;
			for (int i = 0; i < 4; i++)
			{
				src_buf += (0x200 * i);
				ecc_dst = (ecc_addr ^ 0x40) + (i * 4);
				ecc = calc_ecc(src_buf);
				uc_mem_write(starlet->uc, ecc_dst, &ecc, 4);
			}
		}
	}
	// Other cases are unimplemented
	// ...
}


// handle_nand_command()
// Perform a NAND interface command
void handle_nand_command(starlet *e, s64 ctrl)
{
	u32 cmd = (ctrl & 0x00ff0000) >> 16;
	u32 flags = (ctrl & 0x0000f000) >> 12;
	u32 dsize = (ctrl & 0x00000fff);
	switch(cmd) {
	case 0x00: break;
	case NAND_CMD_RESET: break;
	case NAND_CMD_READ0b:
		nand_dma_write(e, flags, dsize);
		break;
	default: break;
	}
}

// __mmio_nand()
// NAND MMIO handler
static bool __mmio_nand(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	if (type == UC_MEM_WRITE)
		log("NAND write %08x on %08x\n", value, address);
	if (type == UC_MEM_READ)
		log("NAND read %08x\n", address);

	if ((type == UC_MEM_WRITE) && (address == NAND_CTRL))
		if (value & 0x80000000) handle_nand_command(e, value);
}


// ----------------------------------------------------------------------------

// __mmio_aes()
// AES engine MMIO handler
static bool __mmio_aes(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	if (type == UC_MEM_WRITE)
		log("AES write %08x on %08x\n", value, address);
	if (type == UC_MEM_READ)
		log("AES read on %08x\n", address);

	return true;
}

// ----------------------------------------------------------------------------

// __mmio_sha()
// SHA1 engine MMIO handler
static bool __mmio_sha(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	if (type == UC_MEM_WRITE)
		log("SHA write %08x on %08x\n", value, address);
	if (type == UC_MEM_READ)
		log("SHA read on %08x\n", address);

	return true;
}


// ----------------------------------------------------------------------------

// __mmio_hlwd()
// Hollywood register MMIO handler
static bool __mmio_hlwd(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	if (type == UC_MEM_WRITE)
		log("Hollywood write %08x on %08x\n", value, address);
	if (type == UC_MEM_READ)
		log("Hollywood read on %08x\n", address);

	return true;
}


// ----------------------------------------------------------------------------

// __mmio_ddr()
// Memory controller MMIO handler
static bool __mmio_ddr(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	if (type == UC_MEM_WRITE)
		log("DDR write %08x on %08x\n", value, address);
	if (type == UC_MEM_READ)
		log("DDR read on %08x\n", address);

	return true;
}



// ---------------------------------------------------------------------------


// register_mmio_hooks()
// Register all of the MMIO hooks.
int register_mmio_hooks(starlet *e) 
{ 
	uc_hook x;
	uc_hook_add(e->uc, &x, UC_HOOK_MEM_WRITE|UC_HOOK_MEM_READ, __mmio_nand, 
			e, 0x0d010000, 0x0d010020);

	uc_hook_add(e->uc, &x, UC_HOOK_MEM_WRITE|UC_HOOK_MEM_READ, __mmio_aes,
			e, 0x0d020000, 0x0d020020);

	uc_hook_add(e->uc, &x, UC_HOOK_MEM_WRITE|UC_HOOK_MEM_READ, __mmio_sha,
			e, 0x0d030000, 0x0d030040);

	uc_hook_add(e->uc, &x, UC_HOOK_MEM_WRITE|UC_HOOK_MEM_READ, __mmio_hlwd,
			e, 0x0d800000, 0x0d800220);

	uc_hook_add(e->uc, &x, UC_HOOK_MEM_WRITE|UC_HOOK_MEM_READ, __mmio_ddr,
			e, 0x0d8b4200, 0x0d8b4300);

	return 0; 
}



