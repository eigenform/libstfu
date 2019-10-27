
#include "core_types.h"
#include "util.h"

#define LOGGING 1

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

const char *syscall_name[] = {
	"thread_create",
	"thread_join",
	"thread_cancel",
	"thread_get_id",
	"thread_get_pid",
	"thread_continue",
	"thread_suspend",
	"thread_yield",
	"thread_get_prio",
	"thread_set_prio",

	"mqueue_create",
	"mqueue_destroy",
	"mqueue_send",
	"mqueue_jam",
	"mqueue_recv",
	"mqueue_register_handler",
	"mqueue_destroy_handler",

	"timer_create",
	"timer_restart",
	"timer_stop",
	"timer_destroy",
	"timer_now",

	"heap_create",
	"heap_destroy",
	"heap_alloc",
	"heap_alloc_aligned",
	"heap_free",

	"register_device",

	"ios_open",
	"ios_close",
	"ios_read",
	"ios_write",
	"ios_seek",
	"ios_ioctl",
	"ios_ioctlv",

	"ios_open_async",
	"ios_close_async",
	"ios_read_async",
	"ios_write_async",
	"ios_seek_async",
	"ios_ioctl_async",
	"ios_ioctlv_async",
	"ios_resource_reply",

	"set_uid",
	"get_uid",
	"set_gid",
	"get_gid",

	"ahb_memflush",
	"cc_ahb_memflush",

	"swirq31",
	"swirq18",
	"do_swirq7_8",
	"swirq",

	"iobuf_access_pool",
	"iobuf_alloc",
	"iobuf_free",
	"iobuf_log_hdrinfo",
	"iobuf_log_bufinfo",
	"iobuf_extend",
	"iobuf_push",
	"iobuf_pull",
	"iobuf_verify",

	"syscall_3e",

	"sync_before_read",
	"sync_after_write",

	"ppc_boot",
	"ios_boot",
	"boot_new_ios_kernel",
	"di_reset_assert",
	"di_reset_deassert",
	"di_reset_check",

	"syscall_47",
	"syscall_48",

	"get_boot_vector",
	"get_hlwd_rev",
	"kernel_printf",
	"kernel_setver",
	"kernel_getver",
	"set_di_spinup",
	"virt_to_phys",
	"dvdvideo_set",
	"dvdvideo_get",
	"exictrl_toggle",
	"exictrl_get",
	"set_ahbprot",
	"get_busclk",
	"poke_gpio",
	"write_ddr_reg",
	"poke_debug_port",
	"load_ppc",
	"load_module",
	// ...
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
	u32 r[6];
	u32 lr;

	uc_reg_read(e->uc, UC_ARM_REG_R0, &r[0]);
	uc_reg_read(e->uc, UC_ARM_REG_R1, &r[1]);
	uc_reg_read(e->uc, UC_ARM_REG_R2, &r[2]);
	uc_reg_read(e->uc, UC_ARM_REG_R3, &r[3]);
	uc_reg_read(e->uc, UC_ARM_REG_R4, &r[4]);
	uc_reg_read(e->uc, UC_ARM_REG_R5, &r[5]);
	uc_reg_read(e->uc, UC_ARM_REG_LR, &lr);


	if (sc_num < sizeof(syscall_name))
		log("%s() (lr=%08x)\n", syscall_name[sc_num], lr);
	else
		log("syscall %08x (lr=%08x) (log unimpl)\n", sc_num,lr);
}


