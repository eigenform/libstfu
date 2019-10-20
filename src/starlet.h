#ifndef _STARLET_H
#define _STARLET_H

#include "mmio.h"

// These are libstfu functions exposed to the user.

void starlet_destroy(starlet *emu);
int starlet_init(starlet *emu);
int starlet_halt(starlet *emu, u32 why);
int starlet_run(starlet *emu);
int starlet_load_code(starlet *emu, char *filename, u64 addr);
int starlet_load_nand_buffer(starlet *emu, void *buffer, u64 len);
int starlet_load_boot0(starlet *emu, char *filename);

#endif // _STARLET_H
