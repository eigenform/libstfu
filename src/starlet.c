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


/* __handle_irqs()
 * Upstream Unicorn doesn't seem to have any way to fire an IRQ.
 * For now, we instead need to halt and manually move execution into the
 * exception vector for IRQs.
 * Returns 'true' if we should halt fatally.
 */
static u32 irq_fixup_cpsr;
static bool __handle_irqs(starlet *e)
{
	u32 en = read32(e->uc, HW_ARM_INTEN);
	u32 new_sts = e->pending_irq & en;
	write32(e->uc, HW_ARM_INTSTS, new_sts);

	// If there's no IRQ to deal with, why are we even here?
	assert(new_sts != 0);
	//if (new_sts == 0)
	//{	
	//	dbg("No interrupt to service! pending=%08x, en=%08x\n",
	//		e->pending_irq, en);
	//	return true;
	//}
	

	u32 regs[7];
	u32 entry_pc, entry_lr, entry_cpsr, entry_sp, entry_spsr;
	u32 irq_pc, irq_lr, irq_cpsr, irq_sp, irq_spsr;

	// Get the state before taking the exception
	uc_reg_read(e->uc, UC_ARM_REG_PC, &entry_pc);
	uc_reg_read(e->uc, UC_ARM_REG_SP, &entry_sp);
	uc_reg_read(e->uc, UC_ARM_REG_LR, &entry_lr);
	uc_reg_read(e->uc, UC_ARM_REG_CPSR, &entry_cpsr);
	uc_reg_read(e->uc, UC_ARM_REG_SPSR, &entry_spsr);
	
	//dbg("pre-irq: pc=%08x, lr=%08x, sp=%08x, cpsr=%08x, spsr=%08x\n",
	//		entry_pc, entry_lr, entry_sp, entry_cpsr, entry_spsr);

	// Try to log whatever thread of execution is on-CPU
	//log_context(entry_pc);


	// Switch into the IRQ system mode
	irq_cpsr = (entry_cpsr & 0xffffffe0) | 0x12;
	irq_cpsr &= ~0x20; 
	irq_cpsr |= 0x80;
	uc_reg_write(e->uc, UC_ARM_REG_CPSR, &irq_cpsr);

	// Save the old CPSR in SPSR_irq
	uc_reg_write(e->uc, UC_ARM_REG_SPSR, &entry_cpsr);
	irq_fixup_cpsr = entry_cpsr;

	// Put the old PC in r14_irq (does the handler code subtract 4?)
	irq_lr = entry_pc + 4;
	uc_reg_write(e->uc, UC_ARM_REG_LR, &irq_lr);
	//dbg("Set IRQ fixup to PC=%08x\n", entry_pc);
	register_irq_fixup_hook(e, entry_pc);

	// Set PC to the irq vector
	irq_pc = 0xffff0018;
	uc_reg_write(e->uc, UC_ARM_REG_PC, &irq_pc);

	// Get the state before taking the exception
	uc_reg_read(e->uc, UC_ARM_REG_PC, &irq_pc);
	uc_reg_read(e->uc, UC_ARM_REG_SP, &irq_sp);
	uc_reg_read(e->uc, UC_ARM_REG_LR, &irq_lr);
	uc_reg_read(e->uc, UC_ARM_REG_CPSR, &irq_cpsr);
	uc_reg_read(e->uc, UC_ARM_REG_SPSR, &irq_spsr);
	
	//dbg("pre-irq: pc=%08x, lr=%08x, sp=%08x, cpsr=%08x, spsr=%08x\n",
	//		irq_pc, irq_lr, irq_sp, irq_cpsr, irq_spsr);


	return false;
}


/* __handle_interrupt()
 * Deals with some pending interrupt.
 * Returns 'true' if we halt fatally.
 */
#define EXCEPTION_UNDEF		1
#define EXCEPTION_SWI		2
static char tmp_buf[0x10];
static char svc_buf[0x1000];
static u32 svc_buf_cur;
static bool __handle_interrupt(starlet *e)
{
	u32 r0, r1, r2, r3, r4, r5, pc, lr, sp, cpsr, spsr, tmp;
	size_t slen;

	switch (e->interrupt) {

	// In practice, the semihosting SVC call for writing NUL-terminated
	// strings is the only one that occurs in IOSes that we care about.
	case EXCEPTION_SWI:
		uc_reg_read(e->uc, UC_ARM_REG_R1, &r1);
		uc_virtual_mem_read(e->uc, r1, &tmp_buf, 0x10);
		slen = strnlen(tmp_buf, 0x0f);
		strncpy(&svc_buf[svc_buf_cur], tmp_buf, slen);
		svc_buf_cur += slen;
		for (int i = 0; i < slen; i++)
		{
			if (tmp_buf[i] == '\n')
			{
				printf("%s", svc_buf);
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



/* __handle_syscall()
 * Handle an IOS syscall.
 * Returns 'true' if we need to fatally halt in the main loop.
 */
static u32 undef_fixup_cpsr;
static bool __handle_syscall(starlet *e)
{
	u32 regs[7];
	u32 instr, sc_num;
	u32 entry_pc, entry_lr, entry_cpsr, entry_sp, entry_spsr;
	u32 undef_pc, undef_lr, undef_cpsr, undef_sp, undef_spsr;

	// Get the state before taking the exception
	uc_reg_read(e->uc, UC_ARM_REG_PC, &entry_pc);
	uc_reg_read(e->uc, UC_ARM_REG_SP, &entry_sp);
	uc_reg_read(e->uc, UC_ARM_REG_LR, &entry_lr);
	uc_reg_read(e->uc, UC_ARM_REG_CPSR, &entry_cpsr);
	uc_reg_read(e->uc, UC_ARM_REG_SPSR, &entry_spsr);

	// FIXME: Accuracy here is *always* entering the undef vector.
	// If this instruction isn't a syscall, just signal a fatal halt
	instr = vread32(e->uc, entry_pc);
	if ((instr & 0xe6000000) != 0xe6000000)
	{
		dbg("Got bad instruction %08x at PC=%08x\n", instr, entry_pc);
		return true;
	}

	// Try to log whatever thread of execution is on-CPU
	log_context(entry_pc);

	// Try to log the name of this syscall and arguments
	sc_num = (instr & 0x00ffffe0) >> 5;
	log_syscall(e, sc_num);

	// Write new CPSR, switching into the undef system mode
	undef_cpsr = (entry_cpsr & 0xffffffe0) | 0x1b;
	undef_cpsr &= ~0x20; 
	undef_cpsr |= 0x80;
	uc_reg_write(e->uc, UC_ARM_REG_CPSR, &undef_cpsr);

	// Save the old CPSR in SPSR_undef
	uc_reg_write(e->uc, UC_ARM_REG_SPSR, &entry_cpsr);
	undef_fixup_cpsr = entry_cpsr;

	// Treat undef instruction like a branch+link, put PC+4 in LR_undef
	undef_lr = entry_pc + 4;
	uc_reg_write(e->uc, UC_ARM_REG_LR, &undef_lr);

	// Register a post-syscall hook to fix up state.
	// FIXME: Need to figure out a better solution to this.
	register_syscall_fixup_hook(e, undef_lr);

	// Set PC to the undef vector, then resume execution!
	undef_pc = 0xffff0004;
	uc_reg_write(e->uc, UC_ARM_REG_PC, &undef_pc);
	return false;
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

	// These halt codes are *always fatal*
	if (e->halt_code < 0x10000)
	{
		uc_reg_read(e->uc, UC_ARM_REG_PC, &pc);
		uc_reg_read(e->uc, UC_ARM_REG_LR, &lr);
		dbg("halt_code=%08x, pc=%08x, lr=%08x\n", e->halt_code,pc,lr);
		return true;
	}

	// Handle halt cases that emulate core functionality
	switch (e->halt_code) {
	case HALT_INSN_INVALID:
		die = __handle_syscall(e);
		break;
	case HALT_SYSCALL_FIXUP:
		// FIXME: We just jump right to the LR; is this correct?
		// Restore the old cpsr (before we took the exception)
		uc_reg_write(e->uc, UC_ARM_REG_CPSR, &undef_fixup_cpsr);
		uc_reg_read(e->uc, UC_ARM_REG_LR, &lr);
		uc_reg_write(e->uc, UC_ARM_REG_PC, &lr);

		uc_reg_read(e->uc, UC_ARM_REG_PC, &pc);
		log_context(pc);
		die = false;
		break;
	case HALT_IRQ_FIXUP:
		// When returning from the IRQ handler, this PC is correct
		uc_reg_read(e->uc, UC_ARM_REG_PC, &pc);
		uc_reg_read(e->uc, UC_ARM_REG_LR, &lr);
		uc_reg_read(e->uc, UC_ARM_REG_SP, &sp);
		//dbg("pre-fixup: PC=%08x, LR=%08x, SP=%08x\n", pc,lr,sp);

		uc_reg_write(e->uc, UC_ARM_REG_CPSR, &irq_fixup_cpsr);
		//uc_reg_write(e->uc, UC_ARM_REG_PC, &pc);

		uc_reg_read(e->uc, UC_ARM_REG_PC, &pc);
		uc_reg_read(e->uc, UC_ARM_REG_LR, &lr);
		uc_reg_read(e->uc, UC_ARM_REG_SP, &sp);
		//dbg("post-fixup: PC=%08x, LR=%08x, SP=%08x\n", pc,lr,sp);
		destroy_irq_fixup_hook(e, pc);

		log_context(pc);
		die = false;
		break;
	case HALT_INTERRUPT:
		die = __handle_interrupt(e);
		break;
	case HALT_IRQ:
		die = __handle_irqs(e);
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



/* ----------------------------------------------------------------------------
 * These are functions exposed to users linking against us.
 */

// starlet_destroy()
// Destroy a Starlet instance.
void starlet_destroy(starlet *emu)
{
	dbg("%s\n", "destroying instance ...");
	FILE *fp;
	fp = fopen("/tmp/mem1.bin", "wb");
	fwrite(&emu->mram.mem1, 1, sizeof(emu->mram.mem1), fp);
	fclose(fp);
	fp = fopen("/tmp/mem2.bin", "wb");
	fwrite(&emu->mram.mem2, 1, sizeof(emu->mram.mem2), fp);
	fclose(fp);

	uc_close(emu->uc);
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
		printf("Couldn't create Unicorn instance\n");
		return -1;
	}

	emu->state = (STATE_BROM_MAP_ON);
	emu->halt_hook = -1;
	init_mmu(emu);
	register_core_hooks(emu);
	register_mmio_hooks(emu);
	dbg("%s\n", "initialized instance");
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
		printf("Couldn't open %s\n", filename);
		return -1;
	}
	fp = fopen(filename, "rb");
	bytes_read = fread(&e->seeprom, 1, 0x100, fp);
	fclose(fp);
	return 0;
}

// starlet_add_bp()
// Add a simple breakpoint.
int starlet_add_bp(starlet *e, u32 addr) { register_bp_hook(e, addr); }

int starlet_add_log(starlet *e, u32 addr) { register_log_hook(e, addr); }

// starlet_run()
// Start running a Starlet instance. The main loop is implemented here.
#define LOOP_INSTRS 0x100
int starlet_run(starlet *emu)
{
	uc_err err;
	u32 pc, cpsr;
	bool should_halt;

	// Set the initial entrypoint
	uc_reg_write(emu->uc, UC_ARM_REG_PC, &emu->entrypoint);
	if (emu->state & STATE_BOOT0) dbg("%s\n", "ENTERED BOOT0");

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
			should_halt = __handle_halt_code(emu);
			emu->halt_code = 0;
			if (should_halt) break;
		}
	}
}

