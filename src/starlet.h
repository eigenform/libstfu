#ifndef _STARLET_H
#define _STARLET_H

#include "mmio.h"
#include "core_hook.h"
#include "mmu.h"

// These are libstfu functions exposed to the user.

void starlet_destroy(starlet *emu);
int starlet_init(starlet *emu);
int starlet_halt(starlet *emu, u32 why);
int starlet_run(starlet *emu);
int starlet_load_code(starlet *emu, char *filename, u64 addr);
int starlet_load_nand_buffer(starlet *emu, void *buffer, u64 len);
int starlet_load_boot0(starlet *emu, char *filename);
int starlet_load_otp(starlet *e, char *filename);
int starlet_load_seeprom(starlet *e, char *filename);
int starlet_add_bp(starlet *e, u32 addr);
int starlet_add_log(starlet *e, u32 addr);

#endif // _STARLET_H
