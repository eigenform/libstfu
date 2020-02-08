
#include "core_types.h"
#include "util.h"

#define LOGGING 1
#define DEBUG 1


// Context passed to a syscall logger/formatter
struct r_ctx 
{
	const char *name;
	u32 lr;
	u32 r[6];
};

// Entry for logging information about a syscall.
struct syscall_info 
{ 
	const char *name; 
	void (*print)(starlet *e, struct r_ctx *ctx);
};

// Filled out before calling into a formatter
static char strbuf[0x100];
struct r_ctx fmt_ctx = {
	NULL,
	0,
	{ 0 },
};


// Indicies mapping to context names
enum ctx_name_idx {
	CTX_FS = 0,
	CTX_ES,
	CTX_DIP,
	CTX_STM,
	CTX_SDI,
	CTX_OH0,
	CTX_OH1,
	CTX_SO,
	CTX_KD,
	CTX_WD,
	CTX_WL,
	CTX_NCD,
	CTX_ETH,
	CTX_KBD,
	CTX_SSL,
	CTX_KERNEL,
	CTX_UNK,
};

// String table of context names
const char *ctx_name[] = {
	"FS",
	"ES",
	"DIP",
	"STM",
	"SDI",
	"OH0",
	"OH1",
	"SO",
	"KD",
	"WD",
	"WL",
	"NCD",
	"ETH",
	"KBD",
	"SSL",
	"KERNEL",
	"UNK",
};

/* The following are logging functions that are unique to particular syscalls
 * or groups of syscalls.
 */

void ios_log_default(starlet *e, struct r_ctx *ctx)
{
	log("%s() (lr=%08x)\n", ctx->name, ctx->lr);
}

void ios_log_mq_op(starlet *e, struct r_ctx *ctx)
{
	log("%s(%d, 0x%08x, 0x%08x) (lr=%08x)\n", ctx->name, ctx->r[0], 
		ctx->r[1], ctx->r[2], ctx->lr);
}

void ios_thread_create(starlet *e, struct r_ctx *ctx)
{
	log("%s(0x%08x, 0x%08x, 0x%08x, 0x%08x, %d, %d) (lr=%08x)\n", 
		ctx->name, ctx->r[0], ctx->r[1], ctx->r[2], ctx->r[3], 
		ctx->r[4], ctx->r[5], ctx->lr);
}
void ios_thread_cancel(starlet *e, struct r_ctx *ctx)
{
	log("%s(%d, 0x%08x) (lr=%08x)\n", ctx->name, 
		ctx->r[0], ctx->r[1], ctx->lr);
}
void ios_timer_create(starlet *e, struct r_ctx *ctx)
{
	log("%s(%d, %d, %d, 0x%08x) (lr=%08x)\n", ctx->name, 
		ctx->r[0], ctx->r[1], ctx->r[2], ctx->r[3], ctx->lr);
}
void ios_heap_alloc(starlet *e, struct r_ctx *ctx)
{
	log("%s(%d, 0x%08x) (lr=%08x)\n", ctx->name, 
		ctx->r[0], ctx->r[1], ctx->lr);
}
void ios_open(starlet *e, struct r_ctx *ctx)
{
	uc_virtual_mem_read(e->uc, ctx->r[0], strbuf, 0x100);
	log("%s(\"%s\", %d) (lr=%08x)\n", ctx->name, 
		strbuf, ctx->r[1], ctx->lr);
}





// Table of syscalls.
// Entries with a NULL function pointer are not logged.
const struct syscall_info syscall_table[0x80] = {
	{ "thread_create",		ios_thread_create },
	{ "thread_join",		ios_log_default },
	{ "thread_cancel",		ios_thread_cancel },
	{ "thread_get_id",		ios_log_default },
	{ "thread_get_pid",		ios_log_default },
	{ "thread_continue",		ios_log_default },
	{ "thread_suspend",		ios_log_default },
	{ "thread_yield",		ios_log_default },
	{ "thread_get_prio",		ios_log_default },
	{ "thread_set_prio",		ios_log_default },
	{ "mqueue_create",		ios_log_default },
	{ "mqueue_destroy",		ios_log_default },
	{ "mqueue_send",		ios_log_mq_op },
	{ "mqueue_jam",			ios_log_mq_op },
	{ "mqueue_recv",		ios_log_mq_op },
	{ "mqueue_register_handler",	ios_log_default },
	{ "mqueue_destroy_handler",	ios_log_default },
	{ "timer_create",		ios_timer_create },
	{ "timer_restart",		ios_log_default },
	{ "timer_stop",			ios_log_default },
	{ "timer_destroy",		ios_log_default },
	{ "timer_now",			ios_log_default },
	{ "heap_create",		ios_log_default },
	{ "heap_destroy",		ios_log_default },
	{ "heap_alloc",			ios_heap_alloc },
	{ "heap_alloc_aligned", 	ios_log_default },
	{ "heap_free",			ios_log_default },
	{ "register_device",		ios_log_default },
	{ "ios_open",			ios_open },
	{ "ios_close",			ios_log_default },
	{ "ios_read",			ios_log_default },
	{ "ios_write",			ios_log_default },
	{ "ios_seek",			ios_log_default },
	{ "ios_ioctl",			ios_log_default },
	{ "ios_ioctlv",			ios_log_default },
	{ "ios_open_async",		ios_log_default },
	{ "ios_close_async",		ios_log_default },
	{ "ios_read_async",		ios_log_default },
	{ "ios_write_async",		ios_log_default },
	{ "ios_seek_async",		ios_log_default },
	{ "ios_ioctl_async",		ios_log_default },
	{ "ios_ioctlv_async",		ios_log_default },
	{ "ios_resource_reply", 	ios_log_default },
	{ "set_uid",			ios_log_default },
	{ "get_uid",			ios_log_default },
	{ "set_gid",			ios_log_default },
	{ "get_gid",			ios_log_default },
	{ "ahb_memflush",		NULL },
	{ "cc_ahb_memflush",		NULL },
	{ "swirq31",			ios_log_default },
	{ "swirq18",			ios_log_default },
	{ "do_swirq7_8",		ios_log_default },
	{ "swirq",			ios_log_default },
	{ "iobuf_access_pool",		ios_log_default },
	{ "iobuf_alloc",		ios_log_default },
	{ "iobuf_free",			ios_log_default },
	{ "iobuf_log_hdrinfo",		ios_log_default },
	{ "iobuf_log_bufinfo",		ios_log_default },
	{ "iobuf_extend",		ios_log_default },
	{ "iobuf_push",			ios_log_default },
	{ "iobuf_pull",			ios_log_default },
	{ "iobuf_verify",		ios_log_default },
	{ "syscall_3e",			ios_log_default },
	{ "sync_before_read",		NULL },
	{ "sync_after_write",		NULL },
	{ "ppc_boot",			ios_log_default },
	{ "ios_boot",			ios_log_default },
	{ "boot_new_ios_kernel",	ios_log_default },
	{ "di_reset_assert",		ios_log_default },
	{ "di_reset_deassert",		ios_log_default },
	{ "di_reset_check",		ios_log_default },
	{ "syscall_47",			ios_log_default },
	{ "syscall_48",			ios_log_default },
	{ "get_boot_vector",		ios_log_default },
	{ "get_hlwd_rev",		ios_log_default },
	{ "kernel_printf",		ios_log_default },
	{ "kernel_setver",		ios_log_default },
	{ "kernel_getver",		ios_log_default },
	{ "set_di_spinup",		ios_log_default },
	{ "virt_to_phys",		NULL },
	{ "dvdvideo_set",		ios_log_default },
	{ "dvdvideo_get",		ios_log_default },
	{ "exictrl_toggle",		ios_log_default },
	{ "exictrl_get",		ios_log_default },
	{ "set_ahbprot",		ios_log_default },
	{ "get_busclk",			ios_log_default },
	{ "poke_gpio",			ios_log_default },
	{ "write_ddr_reg",		ios_log_default },
	{ "poke_debug_port",		ios_log_default },
	{ "load_ppc",			ios_log_default },
	{ "load_module",		ios_log_default },
	{ "iosc_object_create", 	ios_log_default },
	{ "iosc_object_delete", 	ios_log_default },
	{ "iosc_secretkey_import",	ios_log_default },
	{ "iosc_secretkey_export",	ios_log_default },
	{ "iosc_pubkey_import",		ios_log_default },
	{ "iosc_pubkey_export",		ios_log_default },
	{ "iosc_sharedkey_compute",	ios_log_default },
	{ "iosc_set_data",		ios_log_default },
	{ "iosc_get_data",		ios_log_default },
	{ "iosc_get_keysize",		ios_log_default },
	{ "iosc_get_sigsize",		ios_log_default },
	{ "iosc_genhash_async", 	ios_log_default },
	{ "iosc_genhash",		ios_log_default },
	{ "iosc_encrypt_async", 	ios_log_default },
	{ "iosc_encrypt",		ios_log_default },
	{ "iosc_decrypt_async", 	ios_log_default },
	{ "iosc_decrypt",		ios_log_default },
	{ "iosc_pubkey_verify_sign",	ios_log_default },
	{ "iosc_gen_blockmac",		ios_log_default },
	{ "iosc_get_blockmac_async",	ios_log_default },
	{ "iosc_import_cert",		ios_log_default },
	{ "iosc_get_device_cert",	ios_log_default },
	{ "iosc_set_ownership",		ios_log_default },
	{ "iosc_get_ownership", 	ios_log_default },
	{ "iosc_gen_rand",		ios_log_default },
	{ "iosc_gen_key",		ios_log_default },
	{ "iosc_gen_pubsign_key",	ios_log_default },
	{ "iosc_gen_cert",		ios_log_default },
	{ "iosc_check_dihash",		ios_log_default },
	{ "syscall_78",			ios_log_default },
	{ "syscall_79",			ios_log_default },
};


// get_ctx_name_idx()
// Given some PC, return the corresponding index of the context name.
static int get_ctx_name_idx(u32 pc)
{
	switch (pc >> 16) {
	case 0x2000: return CTX_FS;
	case 0x2010: return CTX_ES;
	case 0x2020: return CTX_DIP;
	case 0x2030: return CTX_STM;
	case 0x2040: return CTX_SDI;
	case 0xffff: return CTX_KERNEL;
	default: return CTX_UNK;
	}
}


// log_context()
// Given some PC, log some information about the current context.
static int last_ctx_idx = -1;
void log_context(u32 pc)
{
	int ctx_name_idx = get_ctx_name_idx(pc);
	if (last_ctx_idx != ctx_name_idx)
	{
		log("STFU ----------NOW RUNNING IN %s CONTEXT--------------\n",
				ctx_name[ctx_name_idx]);
		last_ctx_idx = ctx_name_idx;
	}
}

// log_syscall()
// Log some information about a syscall and the arguments.
void log_syscall(starlet *e, u32 sc_num)
{
	
	// FIXME: Deal with validation somewhere else, maybe
	if (sc_num > 0x80)
	{
		dbg("??? syscall %08x (unimpl)\n", sc_num);
		return;
	}

	if (syscall_table[sc_num].print != NULL)
	{
		uc_reg_read(e->uc, UC_ARM_REG_LR, &fmt_ctx.lr);
		uc_reg_read(e->uc, UC_ARM_REG_R0, &fmt_ctx.r[0]);
		uc_reg_read(e->uc, UC_ARM_REG_R1, &fmt_ctx.r[1]);
		uc_reg_read(e->uc, UC_ARM_REG_R2, &fmt_ctx.r[2]);
		uc_reg_read(e->uc, UC_ARM_REG_R3, &fmt_ctx.r[3]);
		uc_reg_read(e->uc, UC_ARM_REG_R4, &fmt_ctx.r[4]);
		uc_reg_read(e->uc, UC_ARM_REG_R5, &fmt_ctx.r[5]);
		fmt_ctx.name = syscall_table[sc_num].name;

		// Call the formatter for this particular syscall
		syscall_table[sc_num].print(
			e, 
			&fmt_ctx
		);
	}
}


