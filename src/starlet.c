/* starlet.c - libstfu emulator core
 */

#include <unicorn/unicorn.h>
#include <string.h>
#include <endian.h>
#include <assert.h>

#include "core_types.h"
#include "starlet.h"
#include "util.h"

#include "hollywood.h"
#include "ios.h"

#define LOGGING 1
#define DEBUG 1


/* ----------------------------------------------------------------------------
 * These are internal functions for handling the main loop in starlet_run().
 *
 * Our strategy is currently: let uc_emu_start() run for as long as possible.
 * Occasionally, when Unicorn actually halts for some reason, we use the 
 * 'starlet->halt_code' field to discriminate between different cases.
 */


/* __handle_interrupt()
 * Deals with some pending interrupt.
 * Returns 'true' if we halt fatally.
 */
#define EXCEPTION_UNDEF		1
#define EXCEPTION_SWI		2

#define SVC_BUFLEN		0x10
static char line_buf[SVC_BUFLEN];
static char svc_buf[MAX_ENTRY_LEN];
static u32 svc_buf_cur;
static bool __handle_interrupt(starlet *e)
{
	u32 r0, r1, r2, r3, r4, r5, pc, lr, sp, cpsr, spsr, tmp;
	size_t slen;

	switch (e->interrupt) {

	// In practice, the semihosting SVC call for writing NUL-terminated
	// strings is the only one that occurs in IOSes that we care about.
	case EXCEPTION_SWI:
		// Read up to 16 bytes of string data
		uc_reg_read(e->uc, UC_ARM_REG_R1, &r1);
		uc_vmem_read(e->uc, r1, &line_buf, SVC_BUFLEN);

		// Append to buffer
		slen = strnlen(line_buf, SVC_BUFLEN-1);
		strncpy(&svc_buf[svc_buf_cur], line_buf, slen);
		svc_buf_cur += slen;

		// If this particular write has a newline, flush buffer
		for (int i = 0; i < slen; i++)
		{
			if (line_buf[i] == '\n')
			{
				char *pos;
				if ((pos = strchr(svc_buf, '\n')) != NULL)
					*pos = '\0';
				LOG(e, SVC, svc_buf);
				memset(svc_buf, 0, sizeof(svc_buf));
				svc_buf_cur = 0;
				break;
			}
		}
		return false;
		break;

	// All other interrupts are unimplemented, so we should fatally halt.
	default:
		uc_reg_read(e->uc, UC_ARM_REG_PC, &pc);
		uc_reg_read(e->uc, UC_ARM_REG_PC, &sp);
		uc_reg_read(e->uc, UC_ARM_REG_CPSR, &cpsr);
		uc_reg_read(e->uc, UC_ARM_REG_SPSR, &spsr);
		uc_reg_read(e->uc, UC_ARM_REG_R0, &r0);
		uc_reg_read(e->uc, UC_ARM_REG_R1, &r1);
		uc_reg_read(e->uc, UC_ARM_REG_R2, &r2);
		uc_reg_read(e->uc, UC_ARM_REG_R3, &r3);
		uc_reg_read(e->uc, UC_ARM_REG_R4, &r4);
		uc_reg_read(e->uc, UC_ARM_REG_R5, &r5);

		dbg("Interrupt %08x at PC=%08x\n", e->interrupt, pc);
		dbg("lr=%08x, sp=%08x, cpsr=%08x, spsr=%08x\n", 
				lr, sp, cpsr, spsr);
		dbg("r0=%08x,r1=%08x,r2=%08x,r3=%08x,r4=%08x,r5=%08x\n",
			r0, r1, r2, r3, r4, r5);
		return true;
	}
}


/* __handle_halt_code()
 * Deal with halt codes, which either (a) indicate a Unicorn exception, or (b)
 * are used to implement some other feature that requires halting emulation.
 *
 * Return 'true' if we should fatally halt in the main loop.
 */
static bool __handle_halt_code(starlet *e)
{
	u32 lr, pc, cpsr, sp, r0;
	bool die = true;

	// Fatal halt codes (stop our main emulation loop)
	if (e->halt_code < 0x10000)
	{
		if (e->halt_code == HALT_UNIMPL)
			LOG(e, DEBUG, "Unimplemented feature");
		return true;
	}

	// Handle halt cases that emulate some core functionality
	switch (e->halt_code) {
	case HALT_INTERRUPT:
		die = __handle_interrupt(e);
		break;
	case HALT_BROM_ON_TO_SRAM_ON:
		die = __enable_sram_mirror(e);
		break;
	case HALT_SRAM_ON_TO_BROM_OFF:
		die = __disable_brom_mapping(e);
		break;
	}

	// If we used e->halt_hook to halt, remove it
	if (e->halt_hook != -1)
	{
		uc_hook_del(e->uc, e->halt_hook);
		e->halt_hook = -1;
	}

	return die;
}

// __run_unstepped()
// "Non-stepped" (noninteractive) core emulator loop. 
// Just emulate until we are forced to halt.
static int __run_unstepped(starlet *emu)
{
	uc_err err;
	u32 pc, cpsr;
	bool should_halt;

	// Do the main emulation loop; break out on errors
	while (true)
	{
		// If the processor is in THUMB mode, fix the program counter.
		uc_reg_read(emu->uc, UC_ARM_REG_PC, &pc);
		uc_reg_read(emu->uc, UC_ARM_REG_CPSR, &cpsr);
		if (cpsr & 0x20) pc |= 1;
		uc_reg_write(emu->uc, UC_ARM_REG_PC, &pc);

		// Emulate until we halt for some reason
		err = uc_emu_start(emu->uc, pc, 0, 0, 0);

		// Temporary: break out if we reach PC=0
		uc_reg_read(emu->uc, UC_ARM_REG_PC, &pc);
		if (pc == 0) break;

		// Potentially handle some event depending on the halt code
		if (err != UC_ERR_OK) emu->halt_code = err;
		if (emu->halt_code != 0)
		{
			// Determine if we should break out the main loop
			should_halt = __handle_halt_code(emu);

			// Clear the current halt code after handling
			emu->halt_code = 0;

			// Break out of this loop if necessary
			if (should_halt) break;
		}
	}
}

bool __run_stepped(starlet *emu, u32 steps)
{
	uc_err err;
	u32 pc, cpsr;
	bool should_halt;

	// If the processor is in THUMB mode, fix the program counter.
	uc_reg_read(emu->uc, UC_ARM_REG_PC, &pc);
	uc_reg_read(emu->uc, UC_ARM_REG_CPSR, &cpsr);
	if (cpsr & 0x20) pc |= 1;
	uc_reg_write(emu->uc, UC_ARM_REG_PC, &pc);

	// Emulate until we halt for some reason
	err = uc_emu_start(emu->uc, pc, 0, 0, steps);
	if (err != UC_ERR_OK) emu->halt_code = err;
	if (emu->halt_code != 0)
	{
		// Determine if we should break out the main loop
		should_halt = __handle_halt_code(emu);

		// Clear the current halt code after handling
		emu->halt_code = 0;
	}
	return should_halt;
}

/* ----------------------------------------------------------------------------
 * These are functions exposed to users linking against us.
 */

// starlet_destroy()
// Destroy a Starlet instance.
void starlet_destroy(starlet *emu)
{
	LOG(emu, SYSTEM, "Instance destroyed");

	// Close handle to Unicorn
	uc_close(emu->uc);

	// Destroy everything we put on the heap
	if (emu->nand.data) 
		free(emu->nand.data);
}

// starlet_init()
// Initialize a new starlet instance.
#define UC_STARLET_MODE	(UC_MODE_ARM | UC_MODE_BIG_ENDIAN | UC_MODE_ARM926)
int starlet_init(starlet *emu)
{
	uc_err err;
	err = uc_open(UC_ARCH_ARM, UC_STARLET_MODE, &emu->uc);
	if (err)
	{
		LOG(emu, DEBUG, "Couldn't create Unicorn instance");
		return -1;
	}

	uc_excp_passthru(emu->uc, true);
	emu->state = (STATE_BROM_MAP_ON);
	emu->halt_hook = -1;
	init_mmu(emu);
	register_core_hooks(emu);
	register_mmio_hooks(emu);
	LOG(emu, SYSTEM, "Initialized instance");
}

// starlet_halt()
// Halt a Starlet instance with the provided reason.
int starlet_halt(starlet *emu, u32 why)
{
	emu->halt_code = why;
	uc_emu_stop(emu->uc);
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
		LOG(emu, DEBUG, "Couldn't open %s", filename);
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
		LOG(emu, DEBUG, "Couldn't read all bytes in %s", filename);
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
		LOG(emu, DEBUG, "Couldn't open %s", filename);
		return -1;
	}
	if (filesize != 0x2000)
	{
		LOG(emu, DEBUG, "boot0 must be 0x2000 bytes, got %08x", filesize);
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
		LOG(emu, DEBUG, "Couldn't read all bytes in %s", filename);
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
		LOG(emu, DEBUG, "Couldn't allocate buffer %08x for NAND", len);
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
		LOG(e, DEBUG, "Couldn't open %s", filename);
		return -1;
	}

	fp = fopen(filename, "rb");
	bytes_read = fread(&e->otp, 1, 0x80, fp);
	fclose(fp);
	return 0;

}

// starlet_load_seeprom()
// Load SEEPROM memory from a file.
int starlet_load_seeprom(starlet *e, char *filename)
{
	FILE *fp;
	size_t bytes_read;
	uc_err err;

	size_t filesize = get_filesize(filename);
	if (filesize == -1)
	{
		LOG(e, DEBUG, "Couldn't open %s", filename);
		return -1;
	}
	fp = fopen(filename, "rb");
	bytes_read = fread(&e->seeprom.data, 1, 0x100, fp);
	fclose(fp);
	return 0;
}

// starlet_add_bp()
// Add a simple breakpoint.
int starlet_add_bp(starlet *e, u32 addr) { register_bp_hook(e, addr); }

// starlet_add_log()
// Add a simple hook to log register state when PC == addr.
int starlet_add_log(starlet *e, u32 addr) { register_log_hook(e, addr); }


// starlet_run()
// Start running a Starlet instance in some mode (stepped, non-stepped).
int starlet_run(starlet *emu)
{
	int res; 

	// Set the initial entrypoint
	uc_reg_write(emu->uc, UC_ARM_REG_PC, &emu->entrypoint);
	if (emu->state & STATE_BOOT0)
		LOG(emu, SYSTEM, "Entered boot0");

	// Just run until we terminate
	res = __run_unstepped(emu);
	return res;
}

