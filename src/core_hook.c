/* core_hook.c - Unicorn hooks implementing various features.
 *
 * When halting inside a hook, we set emu->halt_code to some value so the main 
 * loop can be responsible for determining whether or not anything needs to 
 * happen before execution resumes.
 */

#include "core_hook.h"

#include <unicorn/unicorn.h>
#include <assert.h>
#include "util.h"
#include "ios.h"

#define LOGGING 1
#define DEBUG 1


/* __hook_unmapped()
 * Fired on UC_HOOK_MEM_{WRITE,READ,FETCH}_UNMAPPED events.
 *
 * FIXME: Returning 'true' here is a hack in order to step around the fact
 * that Unicorn cannot properly distinguish between 'physical regions added
 * with 'uc_mem_map' and potentially valid virtual addresses that can actually
 * be translated by the ARM MMU.
 *
 * This probably implies that the Unicorn softmmu needs to be restructured in
 * a way such that we don't erroneously trigger these hooks when performing
 * some access on a virtual address.
 *
 * For now, we simply return 'true', and execution resumes as usual.
 */
bool __hook_unmapped(uc_engine *uc, uc_mem_type type,
	u64 address, int size, s64 value, void *user_data)
{
	switch(type){
	case UC_MEM_WRITE_UNMAPPED:
		if (address >0x30000000)
		{
			printf("Unmapped write on %08x\n", address);
			return false;
		}
		return true;
	case UC_MEM_READ_UNMAPPED:
		if (address >0x30000000)
		{
			printf("Unmapped write on %08x\n", address);
			return false;
		}
		return true;
	case UC_MEM_FETCH_UNMAPPED:
		if (address >0x30000000)
		{
			printf("Unmapped write on %08x\n", address);
			return false;
		}
		return true;
	}
	return false;
}

// __hook_simple_bp()
// Simple breakpoint hook
void __hook_simple_bp(uc_engine *uc, u64 addr, u32 size, starlet *emu)
{
	emu->halt_code = HALT_BP;
	dbg("%s\n", "Hit breakpoint\n");
	uc_emu_stop(uc);
}

// __hook_log_mem()
// Simple logging on memory accesses
static bool __hook_log_mem(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	if (type == UC_MEM_READ)
		log("READ on %08x\n", address);
	if (type == UC_MEM_WRITE)
		log("WRITE %08x on %08x\n", value, address);
}


// __hook_log_code
// For internal debugging - log every instruction
void __hook_log_code(uc_engine *uc, u64 addr, u32 size, starlet *emu)
{
	u32 pc, lr, sp, cpsr, instr;
	u32 r[13];
	bool thumb;

	uc_reg_read(uc, UC_ARM_REG_PC, &pc);
	uc_reg_read(uc, UC_ARM_REG_LR, &lr);
	uc_reg_read(uc, UC_ARM_REG_SP, &sp);
	uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr);
	uc_reg_read(uc, UC_ARM_REG_R0, &r[0]);
	uc_reg_read(uc, UC_ARM_REG_R1, &r[1]);
	uc_reg_read(uc, UC_ARM_REG_R2, &r[2]);
	uc_reg_read(uc, UC_ARM_REG_R3, &r[3]);
	uc_reg_read(uc, UC_ARM_REG_R4, &r[4]);
	uc_reg_read(uc, UC_ARM_REG_R5, &r[5]);
	uc_reg_read(uc, UC_ARM_REG_R6, &r[6]);
	uc_reg_read(uc, UC_ARM_REG_R7, &r[7]);
	uc_reg_read(uc, UC_ARM_REG_R8, &r[8]);
	uc_reg_read(uc, UC_ARM_REG_R9, &r[9]);
	uc_reg_read(uc, UC_ARM_REG_R10, &r[10]);
	uc_reg_read(uc, UC_ARM_REG_R11, &r[11]);
	uc_reg_read(uc, UC_ARM_REG_R12, &r[12]);

	instr = vread32(uc, pc);
	log("%08x: %08x\t [lr=%08x,sp=%08x,cpsr=%08x,r0=%08x]\n[r1=%08x,r2=%08x,r3=%08x,r4=%08x]\n[r5=%08x,r6=%08x,r7=%08x,r8=%08x]\n[r9=%08x,r10=%08x,r11=%08x,r12=%08x]\n\n",
			pc,instr,lr,sp,cpsr,r[0],r[1], r[2],r[3],r[4],r[5],r[6], r[7],r[8],r[9],r[10],r[11],r[12]);
}

// __hook_halt()
// Internal hook to force halt emulation.
void __hook_halt(uc_engine *uc, u64 addr, u32 size, starlet *emu)
{
	uc_emu_stop(uc);
}





// __hook_intr()
// Main exception hook [apart from the undefined instruction exception].
void __hook_intr(uc_engine *uc, uint32_t intno, starlet *e)
{
	u32 pc;
	uc_reg_read(e->uc, UC_ARM_REG_PC, &pc);
	e->interrupt = intno;
	LOG(e, DEBUG, "In interrupt %d hook, pc=%08x", intno, pc);

	e->halt_code = HALT_INTERRUPT;
	uc_emu_stop(uc);
}





// __hook_insn_invalid()
// Hook triggered on UC_HOOK_INSN_INVALID (invalid instruction).
bool __hook_insn_invalid(uc_engine *uc, starlet *e)
{
	u32 pc;
	uc_reg_read(e->uc, UC_ARM_REG_PC, &pc);
	u32 instr = vread32(e->uc, pc);
	u32 sc_num = (instr & 0x00ffffe0) >> 5;

	if ((instr & 0xe6000000) != 0xe6000000)
	{
		LOG(e, DEBUG, "Got bad instruction %08x at PC=%08x", 
			instr, pc);
		return false;
	}

	log_context(e, pc);
	log_syscall(e, sc_num);

	//LOG(e, DEBUG, "In invalid instruction hook, %08x @ pc=%08x", 
	//		instr, pc);
	return true;
}

// __hook_enter_boot1()
// Simple hook to keep track of boot1 state
void __hook_enter_boot1(uc_engine *uc, u64 addr, u32 size, starlet *emu)
{
	u32 val;
	if (emu->state & STATE_BOOT0)
	{
		emu->state &= ~STATE_BOOT0;
		emu->state |= STATE_BOOT1;
		LOG(emu, SYSTEM, "Entered boot1");
	}
}

// __hook_enter_boot2()
// Simple hook to keep track of boot2 state
void __hook_enter_boot2(uc_engine *uc, u64 addr, u32 size, starlet *emu)
{
	u32 val;
	if (emu->state & STATE_BOOT1)
	{
		emu->state &= ~STATE_BOOT1;
		emu->state |= STATE_BOOT2;
		LOG(emu, SYSTEM, "Entered boot2");
	}
}

// register_bp_hook()
// Register a breakpoint hook.
void register_bp_hook(starlet *e, u32 addr)
{
	uc_hook x;
	uc_hook_add(e->uc, &x, UC_HOOK_CODE, __hook_simple_bp, e,addr,addr);
}

// register_log_hook()
// Register a log hook. 
void register_log_hook(starlet *e, u32 addr)
{
	uc_hook x;
	uc_hook_add(e->uc, &x,UC_HOOK_CODE,__hook_log_code, e, addr, addr);
}

// register_core_hooks()
// Register all core hooks necessary for emulation.
int register_core_hooks(starlet *e)
{
	uc_hook x, y, z;
	uc_hook_add(e->uc, &x,UC_HOOK_MEM_UNMAPPED,__hook_unmapped, e, 1, 0);


	uc_hook_add(e->uc, &x,UC_HOOK_INTR, __hook_intr, e, 1, 0);
	uc_hook_add(e->uc, &x,UC_HOOK_INSN_INVALID, __hook_insn_invalid,e,1,0);


	uc_hook_add(e->uc, &x,UC_HOOK_CODE,__hook_enter_boot1, e,
			0xfff00000, 0xfff00000);
	uc_hook_add(e->uc, &x,UC_HOOK_CODE,__hook_enter_boot2, e,
			0xffff0000, 0xffff0000);

	// Syscall handler
	//uc_hook_add(e->uc, &x,UC_HOOK_CODE,__hook_log_code, e,
	//		0xffff1d64, 0xffff1e30);

	// IRQ handler
	//uc_hook_add(e->uc, &x,UC_HOOK_CODE,__hook_log_code, e,
	//		0xffff1f14, 0xffff2120);
	//uc_hook_add(e->uc, &x,UC_HOOK_CODE,__hook_log_code, e,
	//		0xffff2180, 0xffff21f0);

	// nand_command
	//uc_hook_add(e->uc, &x,UC_HOOK_CODE,__hook_log_code, e, 
	//		0x20000110, 0x20000188);
	//uc_hook_add(e->uc, &x,UC_HOOK_CODE,__hook_log_code, e, 
	//		0x20000318, 0x2000048a);

	//uc_hook_add(e->uc,&x,UC_HOOK_MEM_WRITE|UC_HOOK_MEM_READ,
	//		__hook_log_mem,e, 0x200091c0, 0x200091c0);

	// FS entry
	//uc_hook_add(e->uc, &x,UC_HOOK_CODE,__hook_log_code, e, 
	//		0x20005db0, 0x20005f50);

	//uc_hook_add(e->uc, &x,UC_HOOK_CODE,__hook_log_code, e, 
	//		0x20000e38, 0x2000120e);

}


// register_halt_hook()
// Registers a hook to halt emulation [on next instr] and sets the halt code.
// This is typically used inside *another* hook, for cases where we don't want
// to halt directly inside the hook (and would rather wait a small amount of 
// time before doing so).
//
// This *pre-emptively* sets the halt code and *assumes* that __hook_halt()
// will run very soon after registering, and *assumes* that the halt code we
// set here will actually be preserved until then.

int register_halt_hook(starlet *e, u32 req_halt_code)
{
	e->halt_code = req_halt_code;
	uc_hook_add(e->uc, &e->halt_hook, UC_HOOK_CODE,__hook_halt, e, 1, 0);
}

