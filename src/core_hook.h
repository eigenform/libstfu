#include "core_types.h"

int register_core_hooks(starlet *e);
void register_bp_hook(starlet *e, u32 addr);
void register_log_hook(starlet *e, u32 addr);
int register_syscall_fixup_hook(starlet *e, u32 addr);

int register_irq_fixup_hook(starlet *e, u32 addr);
int destroy_irq_fixup_hook(starlet *e, u32 addr);

int register_halt_hook(starlet *e, u32 req_halt_code);
