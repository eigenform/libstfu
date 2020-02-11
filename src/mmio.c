/* mmio.c - libstfu memory-mapped i/o 
 */

#include <string.h>
#include <assert.h>
#include <openssl/aes.h>
#include <unicorn/unicorn.h>

#include "mmio.h"
#include "hollywood.h"
#include "ecc.h"
#include "util.h"
#include "sha1.h"
#include "core_hook.h"

#define LOGGING 1
#define DEBUG 1

// ----------------------------------------------------------------------------

#define NAND_PAGE_LEN		0x840

#define NAND_FLAG_WAIT		0x08
#define NAND_FLAG_WRITE		0x04
#define NAND_FLAG_READ		0x02
#define NAND_FLAG_ECC		0x01

#define NAND_CMD_READ0b		0x30
#define NAND_CMD_READ_ID	0x90
#define NAND_CMD_RESET		0xff


// nand_dma_write()
// Do a NAND-to-ARM DMA write.
// NOTE: It seems like NAND_{DATA,ECC}BUF expects physical addresses.
static u8 nand_id[5] = { 0xad, 0xdc, 0x80, 0x95, 0x00 }; // HY27UF084G2M
static u8 ecc[4];
static u8 nand_buf[0x10000];
void nand_dma_write(starlet *e, u32 flags, u32 len)
{
	u32 fix_addr = 0;
	u32 addr2 = read32(e->uc, NAND_ADDR2);
	u32 data_addr = read32(e->uc, NAND_DATABUF);
	u32 ecc_addr = read32(e->uc, NAND_ECCBUF);
	u32 pc;

	// Get the offset of source data in the NAND buffer.
	// FIXME: this extra copy into nand_buf is not necessary
	u32 nand_off = addr2 * NAND_PAGE_LEN;
	memcpy(nand_buf, &e->nand.data[nand_off], len);

	uc_reg_read(e->uc, UC_ARM_REG_PC, &pc);
	LOG(e, NAND, "DMA pg=%08x data=%08x ecc=%08x len=%08x",
			addr2, data_addr, ecc_addr, len);

	if (len == 0x800)
	{
		//dbg("NAND dma on %08x, len=%08x\n", data_addr, len);
		//uc_virtual_mem_write(e->uc, data_addr, nand_buf, len);
		uc_mem_write(e->uc, data_addr, nand_buf, len);
		memset(nand_buf, 0, 0x10000);
	}
	else if (len == 0x840)
	{
		//dbg("NAND dma on %08x, len=%08x\n", data_addr, 0x800);
		//dbg("NAND dma on %08x, len=%08x\n", ecc_addr, 0x40);
		//uc_virtual_mem_write(e->uc, data_addr, nand_buf, 0x800);
		//uc_virtual_mem_write(e->uc, ecc_addr, &nand_buf[0x800], 0x40);
		uc_mem_write(e->uc, data_addr, nand_buf, 0x800);
		uc_mem_write(e->uc, ecc_addr, &nand_buf[0x800], 0x40);

		if (flags & NAND_FLAG_ECC)
		{
			for (int i = 0; i < 4; i++)
			{
				fix_addr = (ecc_addr ^ 0x40) + (i * 4);
				calc_ecc(nand_buf + (0x200 * i), ecc);
				//uc_virtual_mem_write(e->uc,fix_addr,&ecc,4);
				uc_mem_write(e->uc,fix_addr,&ecc,4);
			}
		}
		memset(nand_buf, 0, 0x10000);
	}
}


// handle_nand_command()
// Perform a NAND interface command
void handle_nand_command(starlet *e, s64 ctrl)
{
	u32 cmd = (ctrl & 0x00ff0000) >> 16;
	u32 flags = (ctrl & 0x0000f000) >> 12;
	u32 dsize = (ctrl & 0x00000fff);

	u32 lr;
	u32 data_addr = read32(e->uc, NAND_DATABUF);
	u32 ecc_addr = read32(e->uc, NAND_ECCBUF);
	uc_reg_read(e->uc, UC_ARM_REG_LR, &lr);
	//log("NAND handling command %02x, flag=%08x databuf=%08x,eccbuf=%08x (lr=%08x)\n", 
	//		cmd, flags, data_addr, ecc_addr, lr);

	switch(cmd) {

	// Read page from NAND (used in bootloaders)
	case NAND_CMD_READ0b:
		assert(flags & NAND_FLAG_READ);
		nand_dma_write(e, flags, dsize);
		break;

	// No idea what this does, perhaps nothing?
	case 0x00:
		break;

	// Don't know what this does either; resets all the registers?
	case NAND_CMD_RESET:
		break;

	// Reads the NAND ID (I imagine hardware behaviour is different)
	case NAND_CMD_READ_ID:
		uc_mem_write(e->uc, data_addr, nand_id, 5);
		break;

	// Die on unimplemented commands
	default: 
		LOG(e, DEBUG, "NAND unimplemented command %02x", cmd);
		e->halt_code = HALT_UNIMPL;
		uc_emu_stop(e->uc);
		break;
	}

	// User requested an IRQ after NAND command completion
	if (ctrl & 0x40000000)
	{
		// Set the NAND IRQ bit, then schedule the handler to force
		// guest code into throwing an IRQ exception
		e->pending_irq |= IRQ_NAND;
		register_halt_hook(e, HALT_IRQ);
	}
}

// __mmio_nand()
// NAND MMIO handler
static bool __mmio_nand(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	u32 tmp;

	if (type == UC_MEM_READ)
	{
		switch (address) {
		// skyeye-starlet just hardwires this to zero?
		case NAND_CTRL:
			tmp = read32(uc, NAND_CTRL);


			// The IRQ handler writes this on NAND IRQ. 
			// Hardware behaviour probably does not involve this
			// write actually setting all these bits?
			if (tmp == 0x7fffffff)
			{
				write32(uc, NAND_CTRL, 0);
				break;
			}

			// If an IRQ was requested, don't do anything
			//if (tmp & 0x40000000) break;

			// On every read, just unset the busy bit
			write32(uc, NAND_CTRL, tmp & 0x7fffffff);
			break;
		default: 
			break;
		}
	}
	else if (type == UC_MEM_WRITE)
	{
		switch (address) {
		case NAND_CTRL:
			if (value & 0x80000000) handle_nand_command(e, value);
			break;
		case NAND_DATABUF:
			break;
		default: 
			break;
		}
	}
}


// ----------------------------------------------------------------------------

static u8 aes_key_fifo[0x10];
static u8 aes_iv_fifo[0x10];
static u8 tmp_iv[0x10];

static u8 aes_src_buf[0x10000];
static u8 aes_dst_buf[0x10000];

// handle_aes_command()
// Do an AES engine command
static void handle_aes_command(starlet *e, s64 value)
{
	u32 len = ((value & 0xfff) + 1) * 0x10;
	u32 src_addr = read32(e->uc, AES_SRC);
	u32 dst_addr = read32(e->uc, AES_DST);
	bool use_tmp_iv = (value & 0x1000) ? true : false;
	bool use_aes = (value & 0x10000000) ? true : false;
	bool decrypt = (value & 0x08000000) ? true : false;

	// Read into a temporary buffer
	memset(aes_src_buf, 0, 0x10000);
	//uc_virtual_mem_read(e->uc, src_addr, aes_src_buf, len);
	uc_mem_read(e->uc, src_addr, aes_src_buf, len);

	LOG(e, AES, "DMA dst=%08x len=%08x", dst_addr, len);

	if (use_aes)
	{
		AES_KEY key;
		if (decrypt)
		{
			memset(aes_dst_buf, 0, 0x10000);
			AES_set_decrypt_key(aes_key_fifo, 128, &key);
			AES_cbc_encrypt(aes_src_buf, aes_dst_buf, len, &key, 
				use_tmp_iv?tmp_iv:aes_iv_fifo, AES_DECRYPT);
			//hexdump("AES data", aes_dst_buf, 0x100);
		}
		else
		{
			memset(aes_dst_buf, 0, 0x10000);
			AES_set_encrypt_key(aes_key_fifo, 128, &key);
			AES_cbc_encrypt(aes_src_buf, aes_dst_buf, len, &key, 
				use_tmp_iv?tmp_iv:aes_iv_fifo, AES_ENCRYPT);
		}
	}
	else 
	{
		//uc_virtual_mem_write(e->uc, dst_addr, aes_src_buf, len);
		uc_mem_write(e->uc, dst_addr, aes_src_buf, len);
	}

	//uc_virtual_mem_write(e->uc, dst_addr, aes_dst_buf, len);
	uc_mem_write(e->uc, dst_addr, aes_dst_buf, len);
	memcpy(tmp_iv, aes_src_buf + (len - 0x10), 0x10);

	write32(e->uc, AES_SRC, src_addr + len);
	write32(e->uc, AES_DST, dst_addr + len);
}

// __mmio_aes()
// AES engine MMIO handler
static bool __mmio_aes(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	u32 tmp;

	if (type == UC_MEM_WRITE)
	{
		switch (address) {
		case AES_CTRL: 
			if (value & 0x80000000)
				handle_aes_command(e, value);
			break;
		case AES_KEY_FIFO:
			//dbg("AES KEY FIFO add %08x\n", value);
			memmove(aes_key_fifo, aes_key_fifo + 0x4, 0x0c);
			aes_key_fifo[0x0c] = value >> 24;
			aes_key_fifo[0x0d] = (value >> 16) & 0xff;
			aes_key_fifo[0x0e] = (value >> 8) & 0xff;
			aes_key_fifo[0x0f] = value & 0xff;
			//printf("KEY FIFO: ");
			//for (int i = 0; i < 0x10; i++)
			//	printf("%02x", aes_key_fifo[i]);
			//printf("\n");
			break;
		case AES_IV_FIFO:
			//dbg("AES IV FIFO add %08x\n", value);
			memmove(aes_iv_fifo, aes_iv_fifo + 0x4, 0x0c);
			aes_iv_fifo[0x0c] = value >> 24;
			aes_iv_fifo[0x0d] = (value >> 16) & 0xff;
			aes_iv_fifo[0x0e] = (value >> 8) & 0xff;
			aes_iv_fifo[0x0f] = value & 0xff;
			//printf("IV FIFO: ");
			//for (int i = 0; i < 0x10; i++)
			//	printf("%02x", aes_iv_fifo[i]);
			//printf("\n");
			break;
		default: break;
		}
	}
	else if (type == UC_MEM_READ)
	{
		switch (address) {
		case AES_CTRL:
			tmp = read32(uc, AES_CTRL);
			//dbg("AES_CTRL cleared with %08x\n", tmp & 0x7fffffff);
			write32(uc, AES_CTRL, tmp & 0x7fffffff);
			break;
		default: break;
		}

	}



	return true;
}

// ----------------------------------------------------------------------------

SHA1Context sha_ctx;
u8 sha_buf[0x10000];

// handle_sha_command()
// Handle a SHA-1 engine command.
static void handle_sha_command(starlet *e, s64 value)
{

	//dbg("pre sha_ctx  %08x%08x%08x%08x%08x\n", 
	//		read32(e->uc, SHA_H0),
	//		read32(e->uc, SHA_H1),
	//		read32(e->uc, SHA_H2),
	//		read32(e->uc, SHA_H3),
	//		read32(e->uc, SHA_H4));


	u32 len = ((value & 0xfff) + 1) * 0x40;
	u32 src_addr = read32(e->uc, SHA_SRC);
	//uc_virtual_mem_read(e->uc, src_addr, sha_buf, len);
	uc_mem_read(e->uc, src_addr, sha_buf, len);

	LOG(e, SHA, "DIGEST src=%08x len=%08x", src_addr, len);
	SHA1Input(&sha_ctx, sha_buf, len);

	write32(e->uc, SHA_SRC, src_addr + len);
	write32(e->uc, SHA_H0, sha_ctx.Message_Digest[0]);
	write32(e->uc, SHA_H1, sha_ctx.Message_Digest[1]);
	write32(e->uc, SHA_H2, sha_ctx.Message_Digest[2]);
	write32(e->uc, SHA_H3, sha_ctx.Message_Digest[3]);
	write32(e->uc, SHA_H4, sha_ctx.Message_Digest[4]);

	//dbg("post sha_ctx  %08x%08x%08x%08x%08x\n", 
	//		read32(e->uc, SHA_H0),
	//		read32(e->uc, SHA_H1),
	//		read32(e->uc, SHA_H2),
	//		read32(e->uc, SHA_H3),
	//		read32(e->uc, SHA_H4));

	memset(sha_buf, 0, 0x10000);
}

// __mmio_sha()
// SHA1 engine MMIO handler
static bool __mmio_sha(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	u32 tmp;
	if (type == UC_MEM_WRITE)
	{
		switch(address) {
		case SHA_CTRL:
			if (value & 0x80000000)
				handle_sha_command(e, value);
			break;
		case SHA_H0:
			sha_ctx.Message_Digest[0] = value;
			break;
		case SHA_H1:
			sha_ctx.Message_Digest[1] = value;
			break;
		case SHA_H2:
			sha_ctx.Message_Digest[2] = value;
			break;
		case SHA_H3:
			sha_ctx.Message_Digest[3] = value;
			break;
		case SHA_H4:
			sha_ctx.Message_Digest[4] = value;
			break;
		default: break;
		}
	}
	else if (type == UC_MEM_READ)
	{
		switch (address) {
		case SHA_CTRL:
			tmp = read32(uc, SHA_CTRL);
			//dbg("SHA_CTRL cleared with %08x\n", tmp & 0x7fffffff);
			write32(uc, SHA_CTRL, tmp & 0x7fffffff);
			break;
		default: break;
		}
	}

	return true;
}


// ----------------------------------------------------------------------------
// This is based entirely on marcan's state machine in skyeye-starlet. 
//
// All of the inlined functions are just for avoid unnecessary horizontal 
// space and making "how this works" a little bit more obvious:

// The current SEEPROM state
enum seeprom_state {
	ST_BUSY		= -1,
	ST_START	= 0,
	ST_OPCODE	= 1,
	ST_ADDRESS	= 2,
	ST_LAST		= 3,
};

// SEEPROM opcodes
enum seeprom_opcode {
	PROM_SPECIAL	= 0,
	PROM_WRITE	= 1,
	PROM_READ	= 2,
	PROM_ERASE	= 3,
};

// SEEPROM sub-opcodes
enum seeprom_subop {
	PROM_WRDIS	= 0,
	PROM_WRALL	= 1,
	PROM_ERALL	= 2,
	PROM_WREN	= 3,
};


// seeprom_state_clear()
// Clear SEEPROM state (nothing is happening).
static inline void seeprom_state_clear(starlet *e)
{
	e->seeprom.clock = 0;
	e->seeprom.state = 0;
	e->seeprom.bits_out = 0;
	e->seeprom.bits_in = 0;
	e->seeprom.count = 1;
	e->seeprom.address = 0;
}

// seeprom_state_busy()
// Wait for a cycle.
static inline void seeprom_state_busy(starlet *e) { e->seeprom.count = 1; }

// seeprom_set_busy()
// Transition to the BUSY state.
static inline void seeprom_set_busy(starlet *e)
{
	e->seeprom.count = 1;
	e->seeprom.state = ST_BUSY;
}

// seeprom_set_last()
// Transition to the LAST state.
static inline void seeprom_set_last(starlet *e)
{
	e->seeprom.count = 16;
	e->seeprom.state = ST_LAST;
}

// seeprom_delay_write()
// On catching a WRITE command, delay until the LAST state.
static inline void seeprom_delay_write(starlet *e)
{
	if (!e->seeprom.wren) seeprom_set_busy(e);
	else seeprom_set_last(e);
}

// seeprom_delay_wrall()
// On catching a WRALL command, delay until the LAST state.
static inline void seeprom_delay_wrall(starlet *e)
{
	if (!e->seeprom.wren) seeprom_set_busy(e);
	else seeprom_set_last(e);
}

// seeprom_state_start()
// Schedule transition to the OPCODE state.
static inline void seeprom_state_start(starlet *e)
{
	if (e->seeprom.bits_in != 1)
	{
		e->seeprom.bits_out = 1;
		seeprom_set_busy(e);
	}
	else
	{
		e->seeprom.count = 2;
		e->seeprom.state = ST_OPCODE;
	}
}

// seeprom_state_opcode()
// Read an opcode, schedule transition to the ADDRESS state.
static inline void seeprom_state_opcode(starlet *e)
{
	e->seeprom.opcode = e->seeprom.bits_in;
	e->seeprom.count = 8;
	e->seeprom.state = ST_ADDRESS;
}

// seeprom_wrall()
// Write all bytes in the SEEPROM.
static inline void seeprom_wrall(starlet *e)
{
	for (int i = 0; i < 0x80; i++)
		e->seeprom.data[i] = e->seeprom.bits_in;
}

// seeprom_set_wren()
// Set the write-enable bit.
static inline void seeprom_set_wren(starlet *e, u32 en)
{
	e->seeprom.wren = en;
	seeprom_set_busy(e);
}

// seeprom_erall()
// Erase all bytes in the SEEPROM.
static inline void seeprom_erall(starlet *e)
{
	if (e->seeprom.wren)
		memset(e->seeprom.data, 0, 0x100);
	seeprom_set_busy(e);
}

// seeprom_read()
// Read a 16-bit word from the SEEPROM.
static inline void seeprom_read(starlet *e)
{
	e->seeprom.bits_out = htobe16(e->seeprom.data[e->seeprom.address & 0x7f]);
	seeprom_set_last(e);
}

// seeprom_write()
// Write a 16-bit word to the SEEPROM.
static inline void seeprom_write(starlet *e)
{
	e->seeprom.data[e->seeprom.address & 0x7f] = htobe16(e->seeprom.bits_in);
	
}

// seeprom_erase()
// Erase a 16-bit word in the SEEPROM.
static inline void seeprom_erase(starlet *e)
{
	if (e->seeprom.wren)
		e->seeprom.data[e->seeprom.address & 0x7f] = 0x0000;
	seeprom_set_busy(e);
}

// seeprom_change_state()
// Main function for managing this state machine over time.
static void seeprom_change_state(starlet *e, u32 gpio_out)
{
	switch (e->seeprom.state) {
	case ST_BUSY: 
		//LOG(e, SEEPROM, "SEEPROM BUSY");
		seeprom_state_busy(e);
		break;
	case ST_START: 
		//LOG(e, SEEPROM, "SEEPROM START");
		seeprom_state_start(e);
		break;
	case ST_OPCODE: 
		//LOG(e, SEEPROM, "SEEPROM OPCODE");
		seeprom_state_opcode(e);
		break;
	case ST_ADDRESS:
		//LOG(e, SEEPROM, "SEEPROM ADDRESS");
		e->seeprom.address = e->seeprom.bits_in;
		switch (e->seeprom.opcode) {
		case PROM_READ: seeprom_read(e); break;
		case PROM_WRITE: seeprom_delay_write(e); break;
		case PROM_ERASE: seeprom_erase(e); break;
		case PROM_SPECIAL:
			switch (e->seeprom.address >> 6) {
			case PROM_WREN: seeprom_set_wren(e, 1); break;
			case PROM_WRDIS: seeprom_set_wren(e, 0); break;
			case PROM_WRALL: seeprom_delay_wrall(e); break;
			case PROM_ERALL: seeprom_erall(e); break;
			}
			break;
		}
		break;
	case ST_LAST:
		//LOG(e, SEEPROM, "SEEPROM LAST");
		switch (e->seeprom.opcode) {
		case PROM_SPECIAL: seeprom_wrall(e); break;
		case PROM_WRITE: seeprom_write(e); break;
		}
		seeprom_set_busy(e);
	}
}

// handle_seeprom()
//
static void handle_seeprom(starlet *e, u32 gpio_out)
{
	// When chip select is low
	if (!(gpio_out & 0x400))
		seeprom_state_clear(e);

	// When chip select is high AND we're on the rising edge of the clock
	else if ((gpio_out & 0x800) && !e->seeprom.clock)
	{
		e->seeprom.count--;
		e->seeprom.bits_in = (e->seeprom.bits_in << 1) | 
			((gpio_out & 0x00001000) ? 1:0);

		u32 tmp = read32(e->uc, HW_GPIO_IN);
		if (e->seeprom.bits_out & (1 << e->seeprom.count))
			write32(e->uc, HW_GPIO_IN, tmp | 0x00002000);
		else
			write32(e->uc, HW_GPIO_IN, tmp & ~0x00002000);

		if (e->seeprom.count == 0)
		{
			seeprom_change_state(e, gpio_out);
			e->seeprom.bits_in = 0;
		}
		e->seeprom.clock = gpio_out & 0x00000800;
	}
}

// __mmio_gpio()
// GPIO MMIO handler
static u32 g_gpio_out;
static bool __mmio_gpio(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	u32 tmp;
	u32 diff;
	if (type == UC_MEM_READ)
	{
		switch (address) {
		case HW_GPIO_IN:
		default: 
			break;
		}
	}
	else if (type == UC_MEM_WRITE)
	{
		switch (address) {
		case HW_GPIO_OUT:
			tmp = read32(uc, HW_GPIO_OUT);
			diff = tmp ^ value;

			// Just log debug GPIO writes
			if (diff & 0x00ff0000)
				LOG(e, GPIO, "DEBUG %02x", (value >> 16) & 0xff);

			// Deal with SEEPROM writes
			if (diff & 0x00001c00)
			{
				handle_seeprom(e, value);
			}
			break;

		case HW_GPIO_ENABLE:
		case HW_GPIO_DIR:
		case HW_GPIO_IN:
		case HW_GPIO_INTLVL:
		case HW_GPIO_INTSTS:
		case HW_GPIO_INTEN:
		case HW_GPIO_STRAPS:
		case HW_GPIO_OWNER:
		default:
			break;
		}
	}
}


// ----------------------------------------------------------------------------

// __mmio_hlwd()
// Hollywood register MMIO handler
static bool __mmio_hlwd(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	u32 tmp, tmp2;

	if (type == UC_MEM_READ)
	{
		switch (address) {

		// Update the timer before every read.
		// Not clear if this actually affects performance or accuracy.
		case HW_TIMER:
			tmp = read32(uc, HW_TIMER) + 100 ;
			write32(uc, HW_TIMER, tmp);
			//dbg("HW_TIMER=%08x\n", tmp);
			break;

		case HW_ALARM:
			//dbg("%s\n", "HW_ALARM read");
			break;

		// We use e->arm_int_sts to keep the actual value of this
		// register because guest writes will clear bits
		case HW_ARM_INTSTS:
			LOG(e, INTERRUPT, "ARM_INTSTS read");
			tmp = read32(uc, HW_ARM_INTEN);
			write32(uc, HW_ARM_INTSTS, e->pending_irq & tmp);
			break;

		case EFUSE_ADDR:
			// Clear the busy bit every time someone reads
			tmp = read32(uc, EFUSE_ADDR);
			write32(uc, EFUSE_ADDR, tmp & 0x7fffffff);
			break;

		// By default, just don't log accesses
		default:
			break;
		}
	}
	else if (type == UC_MEM_WRITE)
	{
		switch (address) {
		case HW_TIMER:
			//dbg("HW_TIMER write %08x\n", value);
			break;
		case HW_ALARM:
			//dbg("HW_ALARM write %08x\n", value);
			break;

		case HW_ARM_INTSTS:
			LOG(e, INTERRUPT, "Cleared %08x on ARM_INTSTS", value);
			e->pending_irq = (e->pending_irq & ~value);
			break;

		case HW_SRNPROT:
			// Enable the SRAM mirror
			if ((value & 0x20) && !(e->state & STATE_SRAM_MIRROR_ON))
			{
				LOG(e, SYSTEM, "SRAM mirror ON");
				e->state |= STATE_SRAM_MIRROR_ON;
				e->halt_code = HALT_BROM_ON_TO_SRAM_ON;
				register_halt_hook(e, HALT_BROM_ON_TO_SRAM_ON);
			}
			break;

		case HW_SPARE0:
			// Deal with this unknown AHB flush-related bit
			if ((value & 0x10000) == 0)
			{
				tmp = read32(uc, HW_BOOT0);
				write32(uc, HW_BOOT0, tmp | 9);
			}
			else
			{
				tmp = read32(uc, HW_BOOT0);
				write32(uc, HW_BOOT0, tmp & 0xfffffff6);
			}
			break;
		case HW_BOOT0:
			// Unmap the boot ROM
			if ((value & 0x1000) && (e->state & STATE_BROM_MAP_ON))
			{
				LOG(e, SYSTEM, "BROM unmapped");
				e->state &= ~STATE_BROM_MAP_ON;
				e->halt_code = HALT_SRAM_ON_TO_BROM_OFF;
				register_halt_hook(e, HALT_SRAM_ON_TO_BROM_OFF);
			}
			break;
		case EFUSE_ADDR:
			if (value & 0x80000000)
			{
				// OTP dumps are typically already in BE, so
				// we don't need to do any conversion here?
				tmp = value & 0x1f;
				//dbg("Set EFUSE_DATA to %08x\n", e->otp.data[tmp]);
				write32(uc, EFUSE_DATA, be32toh(e->otp.data[tmp]));
			}
			break;

		// By default, don't log any accesses
		default: 
			break;
		}
	}

	return true;
}


// ----------------------------------------------------------------------------

// __mmio_ddr()
// Memory controller MMIO handler
static bool __mmio_ddr(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	//if (type == UC_MEM_WRITE)
	//	log("DDR write %08x on %08x\n", value, address);
	//if (type == UC_MEM_READ)
	//	log("DDR read on %08x\n", address);

	if (type == UC_MEM_WRITE)
	{
		switch(address) {
		case DDR_AHMFLUSH:
			// Immediately acknowledge AHB flush requests
			write16(uc, DDR_AHMFLUSH_ACK, value);
			break;
		default: break;
		}
	}
	return true;
}


// ----------------------------------------------------------------------------

// register_mmio_hooks()
// Register all of the MMIO hooks.
#define MMIO_HOOK (UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ)
int register_mmio_hooks(starlet *e) 
{ 
	uc_hook x;
	uc_hook_add(e->uc,&x,MMIO_HOOK,__mmio_nand,e, 0x0d010000, 0x0d010020);
	uc_hook_add(e->uc,&x,MMIO_HOOK,__mmio_aes,e,  0x0d020000, 0x0d020020);
	uc_hook_add(e->uc,&x,MMIO_HOOK,__mmio_sha,e,  0x0d030000, 0x0d030040);

	//uc_hook_add(e->uc,&x,MMIO_HOOK,__mmio_hlwd,e, 0x0d800000, 0x0d800220);

	uc_hook_add(e->uc,&x,MMIO_HOOK,__mmio_hlwd,e, 0x0d800000, 0x0d8000bc);
	uc_hook_add(e->uc,&x,MMIO_HOOK,__mmio_gpio,e, 0x0d8000c0, 0x0d8000fc);
	uc_hook_add(e->uc,&x,MMIO_HOOK,__mmio_hlwd,e, 0x0d800100, 0x0d800220);

	uc_hook_add(e->uc,&x,MMIO_HOOK,__mmio_ddr,e,  0x0d8b4200, 0x0d8b4300);

	return 0; 
}



