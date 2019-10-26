/* starlet.c - libstfu emulator core
 */

#include <unicorn/unicorn.h>
#include <string.h>
#include <endian.h>

#include "hollywood.h"
#include "core_types.h"
#include "starlet.h"
#include "util.h"

#ifndef LOGGING
#define LOGGING 1
#endif

#ifndef DEBUG
#define DEBUG 1
#endif


// __init_mmu()
// Initialize various memory mappings
// UC_PROT_ALL=7
static int __init_mmu(starlet *e)
{
	// Main memory
	uc_mem_map_ptr(e->uc, 0x00000000, 0x01800000, 7, e->mram.mem1);
	uc_mem_map_ptr(e->uc, 0x10000000, 0x04000000, 7, e->mram.mem2);

	// MMIOs
	uc_mem_map_ptr(e->uc, 0x0d010000, 0x00000400, 7, e->iomem.nand);
	uc_mem_map_ptr(e->uc, 0x0d020000, 0x00000400, 7, e->iomem.aes);
	uc_mem_map_ptr(e->uc, 0x0d030000, 0x00000400, 7, e->iomem.sha);

	uc_mem_map_ptr(e->uc, 0x0d040000, 0x00000400, 7, e->iomem.ehci);
	uc_mem_map_ptr(e->uc, 0x0d050000, 0x00000400, 7, e->iomem.ohci0);
	uc_mem_map_ptr(e->uc, 0x0d060000, 0x00000400, 7, e->iomem.ohci1);

	uc_mem_map_ptr(e->uc, 0x0d806000, 0x00000400, 7, e->iomem.exi);
	uc_mem_map_ptr(e->uc, 0x0d800000, 0x00000400, 7, e->iomem.hlwd);
	uc_mem_map_ptr(e->uc, 0x0d8b0000, 0x00000400, 7, e->iomem.mem_unk);
	uc_mem_map_ptr(e->uc, 0x0d8b4000, 0x00000400, 7, e->iomem.ddr);

	// [Initial] mappings for SRAM and BROM
	uc_mem_map_ptr(e->uc, 0xffff0000, 0x00010000, 7, e->sram.brom);
	uc_mem_map_ptr(e->uc, 0xfffe0000, 0x00010000, 7, e->sram.bank_a);
	uc_mem_map_ptr(e->uc, 0xfff00000, 0x00010000, 7, e->sram.bank_a);
	uc_mem_map_ptr(e->uc, 0xfff10000, 0x00010000, 7, e->sram.bank_b);
	uc_mem_map_ptr(e->uc, 0x0d400000, 0x00010000, 7, e->sram.bank_a);
	uc_mem_map_ptr(e->uc, 0x0d410000, 0x00010000, 7, e->sram.bank_b);
	return 0;
}

// __enable_sram_mirror()
// Enable the SRAM mirror.
static void __enable_sram_mirror(starlet *e)
{
	uc_mem_unmap(e->uc, 0xfff00000, 0x00020000);
	uc_mem_unmap(e->uc, 0x0d400000, 0x00020000);
	uc_mem_unmap(e->uc, 0xffff0000, 0x00010000);
	uc_mem_unmap(e->uc, 0xfffe0000, 0x00010000);

	uc_mem_map_ptr(e->uc, 0xfff00000, 0x00010000, 7, e->sram.bank_b);
	uc_mem_map_ptr(e->uc, 0x0d400000, 0x00010000, 7, e->sram.bank_b);
	uc_mem_map_ptr(e->uc, 0xfff10000, 0x00010000, 7, e->sram.bank_a);
	uc_mem_map_ptr(e->uc, 0x0d410000, 0x00010000, 7, e->sram.bank_a);
	uc_mem_map_ptr(e->uc, 0xfffe0000, 0x00010000, 7, e->sram.bank_b);
	uc_mem_map_ptr(e->uc, 0xffff0000, 0x00010000, 7, e->sram.bank_a);
}

// __disable_brom_mapping()
// Disable the boot ROM mapping.
static void __disable_brom_mapping(starlet *e)
{
	uc_mem_unmap(e->uc, 0xfff00000, 0x00020000);
	uc_mem_unmap(e->uc, 0x0d400000, 0x00020000);
	uc_mem_unmap(e->uc, 0xffff0000, 0x00010000);
	uc_mem_unmap(e->uc, 0xfffe0000, 0x00010000);

	uc_mem_map_ptr(e->uc, 0xfff00000, 0x00010000, 7, e->sram.bank_b);
	uc_mem_map_ptr(e->uc, 0x0d400000, 0x00010000, 7, e->sram.bank_b);
	uc_mem_map_ptr(e->uc, 0xfff10000, 0x00010000, 7, e->sram.bank_a);
	uc_mem_map_ptr(e->uc, 0x0d410000, 0x00010000, 7, e->sram.bank_a);
	uc_mem_map_ptr(e->uc, 0xfffe0000, 0x00010000, 7, e->sram.bank_b);
	uc_mem_map_ptr(e->uc, 0xffff0000, 0x00010000, 7, e->sram.bank_a);

}


// __destroy_mmu()
// Free any backing memory we allocated.
static int __destroy_mmu(starlet *emu) { return 0; }

// __hook_unmapped()
// Fired on UC_HOOK_MEM_UNMAPPED events.
static bool __hook_unmapped(uc_engine *uc, uc_mem_type type,
	u64 address, int size, s64 value, void *user_data)
{
	// FIXME: Returning 'true' here is a hack in order to step around the
	// fact the Unicorn cannot distinguish between invalid physical regions
	// and potentially valid virtual mappings setup in the 'real' ARM MMU.
	//
	// This probably implies that the Unicorn softmmu needs a little bit
	// of restructuring in order for hooks to account for accesses that
	// will later be translated by ARM MMU

	switch(type){
	case UC_MEM_WRITE_UNMAPPED:
		printf("Unmapped write on %08x\n", address);
		return true;
	case UC_MEM_READ_UNMAPPED:
		printf("Unmapped read on %08x\n", address);
		return true;
	case UC_MEM_FETCH_UNMAPPED:
		printf("Unmapped fetch on %08x\n", address);
		return true;
	}
	return false;
}


// __hook_simple_bp()
// Simple breakpoint hook
static void __hook_simple_bp(uc_engine *uc, u64 addr, u32 size, starlet *emu)
{
	emu->halt_code = HALT_BP;
	dbg("%s\n", "Hit breakpoint\n");
	uc_emu_stop(uc);
}

// __hook_halt()
// Internal hook to force halt emulation.
void __hook_halt(uc_engine *uc, u64 addr, u32 size, starlet *emu)
{
	u32 pc;
	uc_reg_read(uc, UC_ARM_REG_PC, &pc);
	dbg("Halted at PC=%08x\n", pc);
	uc_emu_stop(uc);
}


// __hook_intr()
// Interrupt-handling (UC_HOOK_INTR) hook
static void __hook_intr(uc_engine *uc, uint32_t intno, starlet *e)
{
	u32 pc;
	uc_reg_read(uc, UC_ARM_REG_PC, &pc);
	e->halt_code = HALT_INTERRUPT;
	e->interrupt = intno;
	uc_emu_stop(uc);
}


// __hook_insn_invalid()
// Hook triggered on UC_HOOK_INSN_INVALID (invalid instruction)
static bool __hook_insn_invalid(uc_engine *uc, starlet *e)
{
	e->halt_code = HALT_INSN_INVALID;
	uc_emu_stop(uc);
	return true;
}


// __hook_enter_boot1()
// Simple hook to keep track of boot1 state
static void __hook_enter_boot1(uc_engine *uc, u64 addr, u32 size, starlet *emu)
{
	u32 val;
	uc_reg_read(uc, UC_ARM_REG_PC, &val);
	if (emu->state & STATE_BOOT0)
	{
		emu->state &= ~STATE_BOOT0;
		emu->state |= STATE_BOOT1;
		dbg("ENTERED BOOT1 at PC=%08x\n", val);
	}
}

// __hook_enter_boot2()
// Simple hook to keep track of boot2 state
static void __hook_enter_boot2(uc_engine *uc, u64 addr, u32 size, starlet *emu)
{
	u32 val;
	uc_reg_read(uc, UC_ARM_REG_PC, &val);
	if (emu->state & STATE_BOOT1)
	{
		emu->state &= ~STATE_BOOT1;
		emu->state |= STATE_BOOT2;
		dbg("ENTERED BOOT2 at PC=%08x\n", val);
	}
}

// __register_hooks()
// Register all default hooks necessary for emulation.
// This includes: Unicorn exception handlers, MMIO emulation, etc.
static int __register_hooks(starlet *e)
{
	uc_hook x, y, z;
	uc_hook_add(e->uc, &x,UC_HOOK_MEM_UNMAPPED,__hook_unmapped, e, 1, 0);
	uc_hook_add(e->uc, &x,UC_HOOK_INTR, __hook_intr, e, 1, 0);
	uc_hook_add(e->uc, &x,UC_HOOK_INSN_INVALID, __hook_insn_invalid,e,1,0);
	uc_hook_add(e->uc, &x,UC_HOOK_CODE,__hook_enter_boot1, e,
			0xfff00000, 0xfff00000);
	uc_hook_add(e->uc, &x,UC_HOOK_CODE,__hook_enter_boot2, e,
			0xffff0000, 0xffff0000);
	register_mmio_hooks(e);
}


// ----------------------------------------------------------------------------
// These are the functions exposed to users linking against libstfu


// starlet_destroy()
// Destroy a Starlet instance.
void starlet_destroy(starlet *emu)
{
	dbg("%s\n", "destroying instance ...");
	uc_close(emu->uc);
	__destroy_mmu(emu);
	if (emu->nand.data)
		free(emu->nand.data);
}

// starlet_init()
// Initialize a new starlet instance.
//#define UC_MODE_ARM926 128
#define UC_STARLET_MODE	(UC_MODE_ARM|UC_MODE_BIG_ENDIAN|UC_MODE_ARM926)
int starlet_init(starlet *emu)
{
	uc_err err;
	err = uc_open(UC_ARCH_ARM, UC_STARLET_MODE, &emu->uc);
	if (err)
	{
		printf("Couldn't create Unicorn instance\n");
		return -1;
	}

	emu->state = (STATE_BROM_MAP_ON);
	__init_mmu(emu);
	__register_hooks(emu);
	dbg("%s\n", "initialized instance");
}

// starlet_halt()
// Halt a Starlet instance with the provided reason.
int starlet_halt(starlet *emu, u32 why)
{
	emu->halt_code = why;
	uc_emu_stop(emu->uc);
}

// __handle_halt_code()
// Deal with halt codes, which either (a) indicate a Unicorn exception, or (b)
// are used to implement some other feature that requires halting emulation.
static u8 stack_buf[0x100];

static char tmp_buf[0x10];
static char svc_buf[0x1000];
static u32 svc_buf_cur;
static bool __handle_halt_code(starlet *e)
{
	u32 r0, r1, r2, r3, r4, r5, pc, lr, sp, cpsr, tmp;
	size_t slen;

	// Halt codes < 0x10000 indicate that we need to exit the main loop
	if (e->halt_code < 0x10000)
	{
		uc_reg_read(e->uc, UC_ARM_REG_PC, &pc);
		uc_reg_read(e->uc, UC_ARM_REG_LR, &lr);
		dbg("Died with halt_code=%08x, pc=%08x, lr=%08x\n",
			e->halt_code, pc, lr);
		return true;
	}

	// Otherwise, we halted in order to do something more complicated
	switch (e->halt_code) {

	case HALT_INSN_INVALID:
		uc_reg_read(e->uc, UC_ARM_REG_PC, &pc);
		tmp = read32(e->uc, pc);
		dbg("Got bad instruction %08x at PC=%08x\n", tmp, pc);
		return true;
		break;

	// Interrupt handling
	case HALT_INTERRUPT:
		uc_reg_read(e->uc, UC_ARM_REG_PC, &pc);
		uc_reg_read(e->uc, UC_ARM_REG_PC, &sp);
		uc_reg_read(e->uc, UC_ARM_REG_CPSR, &cpsr);
		uc_reg_read(e->uc, UC_ARM_REG_R0, &r0);
		uc_reg_read(e->uc, UC_ARM_REG_R1, &r1);
		uc_reg_read(e->uc, UC_ARM_REG_R2, &r2);
		uc_reg_read(e->uc, UC_ARM_REG_R3, &r3);
		uc_reg_read(e->uc, UC_ARM_REG_R4, &r4);
		uc_reg_read(e->uc, UC_ARM_REG_R5, &r5);

		// Handle semi-hosting SVC calls (SWI - software interrupts)
		if (e->interrupt == 2)
		{
			uc_mem_read(e->uc, r1, &tmp_buf, 0x10);
			slen = strnlen(tmp_buf, 0x0f);
			strncpy(&svc_buf[svc_buf_cur], tmp_buf, slen);
			svc_buf_cur += slen;
			for (int i = 0; i < slen; i++)
			{
				if (tmp_buf[i] == '\n')
				{
					log("SVC: %s", svc_buf);
					memset(svc_buf, 0, sizeof(svc_buf));
					svc_buf_cur = 0;
					break;
				}
			}

			//hexdump("r1", tmp_buf, 0x10);
			return false;
		}
		else
		{
			dbg("Caught interrupt %08x at PC=%08x\n", e->interrupt, pc);
			dbg("lr=%08x, sp=%08x, cpsr=%08x\n,", lr, sp, cpsr);
			dbg("r0=%08x, r1=%08x, r2=%08x, r3=%08x, r4=%08x, r5=%08x\n",
				r0, r1, r2, r3, r4, r5);
			return false;
		}
		break;

	// We use the internal halt hook to halt in order to address these
	case HALT_BROM_ON_TO_SRAM_ON:
		dbg("%s\n", "Enabling the SRAM mirror ...");
		__enable_sram_mirror(e);
		uc_hook_del(e->uc, e->halt_hook);
		break;
	case HALT_SRAM_ON_TO_BROM_OFF:
		dbg("%s\n", "Disabling BROM mapping ...");
		__disable_brom_mapping(e);
		uc_hook_del(e->uc, e->halt_hook);
		break;
	}
	return false;
}

// starlet_run()
// Start running a Starlet instance. The main loop is implemented here.
#define LOOP_INSTRS 0x100
int starlet_run(starlet *emu)
{
	uc_err err;
	u32 pc, cpsr;
	u32 temp;
	u64 err_code;
	bool should_halt;

	// Set the initial entrypoint
	uc_reg_write(emu->uc, UC_ARM_REG_PC, &emu->entrypoint);
	if (emu->state & STATE_BOOT0) dbg("%s\n", "ENTERED BOOT0");

	// Do the main emulation loop; break out on errors
	while (true)
	{
		// The PC we read from Unicorn does not encode THUMB state.
		// If the processor is in THUMB mode, fix the program counter.
		// Then, start emulation.

		uc_reg_read(emu->uc, UC_ARM_REG_PC, &pc);
		uc_reg_read(emu->uc, UC_ARM_REG_CPSR, &cpsr);
		if (cpsr & 0x20) pc |= 1;
		uc_reg_write(emu->uc, UC_ARM_REG_PC, &pc);

		// Start emulating - pass Unicorn exception flags to halt_code
		err = uc_emu_start(emu->uc, pc, 0, 0, 0);
		switch (err) {
		case UC_ERR_OK:
			break;
		default:
			emu->halt_code = err;
			break;
		}

		// If the halt code is non-zero, deal with it here.
		// If __handle_halt_code returns true, stop the main loop.
		if (emu->halt_code != 0)
		{
			should_halt = __handle_halt_code(emu);
			emu->halt_code = 0;
			if (should_halt) break;
		}
	}
}


// starlet_load_code()
// Read a file with some code into memory, then write it into the emulator
// at the requested memory address.
// This sets the Starlet entrypoint to the provided address.
int starlet_load_code(starlet *emu, char *filename, u64 addr)
{
	FILE *fp;
	size_t bytes_read;
	uc_err err;

	// Die if we can't get the filesize
	size_t filesize = get_filesize(filename);
	if (filesize == -1)
	{
		printf("Couldn't open %s\n", filename);
		return -1;
	}

	// Temporarily load onto the heap
	u8 *data = malloc(filesize);
	fp = fopen(filename, "rb");
	bytes_read = fread(data, 1, filesize, fp);
	fclose(fp);

	// Die if we can't read the whole file
	if (bytes_read != filesize)
	{
		printf("Couldn't read all bytes in %s\n", filename);
		free(data);
		return -1;
	}

	// Write code to the destination address in memory
	uc_mem_write(emu->uc, addr, data, bytes_read);

	// Only set the entrypoint here if boot0 isn't loaded
	if (emu->entrypoint != 0xffff0000)
		emu->entrypoint = addr;

	free(data);
	return 0;
}

// starlet_load_boot0()
// Load the boot ROM from a file..
int starlet_load_boot0(starlet *emu, char *filename)
{
	FILE *fp;
	size_t bytes_read;
	uc_err err;

	// Die if we can't get the filesize
	size_t filesize = get_filesize(filename);
	if (filesize == -1)
	{
		printf("Couldn't open %s\n", filename);
		return -1;
	}
	if (filesize != 0x2000)
	{
		printf("boot0 must be 0x2000 bytes, got %08x\n", filesize);
		return -1;
	}

	// Temporarily load onto the heap
	u8 *data = malloc(filesize);
	fp = fopen(filename, "rb");
	bytes_read = fread(data, 1, filesize, fp);
	fclose(fp);

	// Die if we can't read the whole file
	if (bytes_read != filesize)
	{
		printf("Couldn't read all bytes in %s\n", filename);
		free(data);
		return -1;
	}

	uc_mem_write(emu->uc, 0xffff0000, data, bytes_read);
	emu->entrypoint = 0xffff0000;
	emu->state |= STATE_BOOT0;

	free(data);
	return 0;
}

// starlet_load_nand_buffer()
// Prepare the NAND flash interface with a buffer.
int starlet_load_nand_buffer(starlet *emu, void *buffer, u64 len)
{
	// Don't support NAND data larger than 512MB
	if (len > 0x21000400) return -1;

	u8 *buf = malloc(len);
	if (!buf)
	{
		log("Couldn't allocate buffer %08x for NAND\n", len);
		return -1;
	}
	emu->nand.data = buf;
	emu->nand.data_len = len;
	memcpy(buf, buffer, len);
	
	return 0;
}

// starlet_load_otp()
// Load EFUSE/one-time programmable memory from a file.
int starlet_load_otp(starlet *e, char *filename)
{
	FILE *fp;
	size_t bytes_read;
	uc_err err;

	size_t filesize = get_filesize(filename);
	if (filesize == -1)
	{
		printf("Couldn't open %s\n", filename);
		return -1;
	}

	fp = fopen(filename, "rb");
	bytes_read = fread(&e->otp, 1, 0x80, fp);
	fclose(fp);
	return 0;

}

// starlet_add_bp()
// Add a simple breakpoint
int starlet_add_bp(starlet *e, u32 addr)
{
	uc_hook x;
	uc_hook_add(e->uc, &x, UC_HOOK_CODE, __hook_simple_bp, e,addr,addr);
}
