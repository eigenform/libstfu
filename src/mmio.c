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


void irq_fire(starlet *e, u32 irqnum)
{
	// Set this IRQ bit in our internal representation
	e->pending_irq = (e->pending_irq & e->enabled_irq) | irqnum;
	write32(e->uc, HW_ARM_INTSTS, e->pending_irq);

	// Assert an IRQ, causing an exception
	uc_assert_irq(e->uc);
	LOG(e, IRQ, "Asserted IRQ %08x, pending=%08x", irqnum, e->pending_irq);
}

void irq_status_write(starlet *e, s64 value)
{
	u32 pc;
	u32 sts = read32(e->uc, HW_ARM_INTSTS);
	uc_reg_read(e->uc, UC_ARM_REG_PC, &pc);

	e->pending_irq &= value;
	write32(e->uc, HW_ARM_INTSTS, e->pending_irq);
}




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
	//LOG(e, NAND, "DMA pg=%08x data=%08x ecc=%08x len=%08x",
	//		addr2, data_addr, ecc_addr, len);

	if (len == 0x800)
	{
		uc_mem_write(e->uc, data_addr, nand_buf, len);
		//uc_vmem_write(e->uc, data_addr, nand_buf, len);
	}
	else if (len == 0x840)
	{
		uc_mem_write(e->uc, data_addr, nand_buf, 0x800);
		uc_mem_write(e->uc, ecc_addr, &nand_buf[0x800], 0x40);
		//uc_vmem_write(e->uc, data_addr, nand_buf, 0x800);
		//uc_vmem_write(e->uc, ecc_addr, &nand_buf[0x800], 0x40);

		if (flags & NAND_FLAG_ECC)
		{
			for (int i = 0; i < 4; i++)
			{
				fix_addr = (ecc_addr ^ 0x40) + (i * 4);
				calc_ecc(nand_buf + (0x200 * i), ecc);
				uc_vmem_write(e->uc,fix_addr,&ecc,4);
				//uc_mem_write(e->uc,fix_addr,&ecc,4);
			}
		}
	}
	memset(nand_buf, 0, 0x10000);
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

	switch(cmd) {
	// No idea what this does, perhaps nothing?
	case 0x00: 
		break;

	// Read page from NAND (used in bootloaders)
	case NAND_CMD_READ0b:
		assert(flags & NAND_FLAG_READ);
		nand_dma_write(e, flags, dsize);
		break;

	// Don't know what this does either; resets all the registers?
	case NAND_CMD_RESET:
		LOG(e, NAND, "RESET flag=%08x, dbuf=%08x, ebuf=%08x (lr=%08x)",
			flags, data_addr, ecc_addr, lr);
		break;

	// Reads the NAND ID (I imagine hardware behaviour is different)
	case NAND_CMD_READ_ID:
		LOG(e, NAND, "READ_ID flag=%08x, dbuf=%08x, ebuf=%08x (lr=%08x)",
			flags, data_addr, ecc_addr, lr);
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
	if (ctrl & 0x40000000) irq_fire(e, IRQ_NAND);
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
			LOG(e, AES, "AES_CTRL write %08x", value);
			if (value & 0x80000000)
				handle_aes_command(e, value);
			break;
		case AES_KEY_FIFO:
			LOG(e, AES, "AES_FIFO write %08x", value);
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
			LOG(e, AES, "AES_IV_FIFO write %08x", value);
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

static u32 __bits_in = 0;
static u32 __bits_recvd = 0;
static bool __clock = 0;
static u32 __count = 1;
static u32 __state = 0;
static u16 __bits_out = 0;

#define EEP_EXT		4
#define EEP_WRITE	5
#define EEP_READ	6
#define EEP_ERASE	7

#define EEP_EXT_EWEN	3
#define EEP_EXT_ERAL	2
#define EEP_EXT_WRAL	1
#define EEP_EXT_EWDS	0

// handle_seeprom()
// Deal with hosted code bit-banging the SEEPROM over the GPIOs
static void handle_seeprom(starlet *e, u32 value)
{
	u8 addr;
	u16 data;
	u32 regdata;

	u32 prev = read32(e->uc, HW_GPIO_OUT);
	u32 changed = prev ^ value;

	bool mosi = value & GPIO_SEEPROM_MOSI;
	bool clk = value & GPIO_SEEPROM_CLK;
	bool cs = value & GPIO_SEEPROM_CS;

	bool cs_rising_edge = (!(prev & GPIO_SEEPROM_CS) && 
			(value && GPIO_SEEPROM_CS));

	bool clk_rising_edge = (!(prev & GPIO_SEEPROM_CLK) && 
			(changed & GPIO_SEEPROM_CLK));

	// If chip select is deasserted, continuously reset our state
	if (!cs)
	{
		__bits_in = 0;
		__bits_out = 0;
		__bits_recvd = 0;
		__count = 1;
		__state = 0;
	}

	// If chip select is asserted and we're on the clock rising edge
	if (cs && clk_rising_edge)
	{
		// Shift some bit in and increment a counter
		__bits_in = (__bits_in << 1) | mosi;
		__bits_recvd++;

		//LOG(e, SEEPROM, "bits_in=%08x (got %d, total 0x%x bits)", 
		//	__bits_in, mosi, __bits_recvd);

		switch (__bits_recvd) {

		// The first 3 bits distinguish the opcode
		case 3: 
			switch(__bits_in) {
			case EEP_READ: 
				__state=EEP_READ;
				break;
			case EEP_EXT: 
				__state=EEP_EXT;
				break;
			case EEP_ERASE: 
				LOG(e, SEEPROM, "ERASE");
				__state=EEP_ERASE;
				break;
			case EEP_WRITE: 
				__state=EEP_WRITE;
				break;
			}
			break;

		// The first 5 bits distinguish "special" opcodes.
		case 5:
			if (__state == EEP_EXT)
			{
				switch (__bits_in & 0x3) {
				case EEP_EXT_EWDS: 
					LOG(e, SEEPROM, "SEEPROM EWDS");
					break;
				case EEP_EXT_WRAL: 
					LOG(e, SEEPROM, "SEEPROM WRAL");
					break;
				case EEP_EXT_ERAL:
					LOG(e, SEEPROM, "SEEPROM ERAL");
					break;
				case EEP_EXT_EWEN:
					LOG(e, SEEPROM, "SEEPROM EWEN");
					break;
				}
			}
			break;

		// We can resolve an address for a read after 11 bits
		case 0xb:
			if (__state == EEP_READ)
			{
				addr = (__bits_in & 0x7f);
				__bits_out = e->seeprom.data[addr];
				LOG(e, SEEPROM, "SEEPROM read %04x from addr %02x", 
						__bits_out, addr);
			}
			break;

		// We need 27 bits to resolve an address and data for a write
		case 0x1b:
			if (__state == EEP_WRITE)
			{
				addr = (__bits_in >> 16) & 0x7f;
				data = (__bits_in) & 0xffff;
				LOG(e, SEEPROM, "SEEPROM write %04x to %02x", 
						data, addr);
				e->seeprom.data[addr] = data;
			}
			break;
		}

		// Shift out 16 bits to service a read command.
		// Note that chip select is still asserted when this happens.
		if ((__state == EEP_READ) && (__bits_recvd > 0xb))
		{
			regdata = read32(e->uc, HW_GPIO_IN);
			if ((__bits_out & (0x8000 >> __bits_recvd - 0xc)))
				regdata |= GPIO_SEEPROM_MISO;
			else
				regdata &= ~GPIO_SEEPROM_MISO;
			//LOG(e, SEEPROM, "Writing HW_GPIO_IN=%08x", regdata);
			write32(e->uc, HW_GPIO_IN, regdata);
		}
	}
}

// gpio_arm_output()
// Handle writes on HW_GPIO_OUT
static void gpio_arm_output(starlet *e, s64 value)
{
	u32 diff = read32(e->uc, HW_GPIO_OUT) ^ value;

	// Deal with debug pin writes
	if (diff & GPIO_DEBUG_PINS)
		LOG(e, GPIO, "dbgport=%02x", (value >> 16) & 0xff);

	// Deal with SEEPROM writes
	if (diff & 0x00001c00)
		handle_seeprom(e, value);

}

// __mmio_gpio()
// GPIO MMIO handler
static bool __mmio_gpio(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	u32 tmp;
	u32 diff;
	if (type == UC_MEM_READ)
	{
		switch (address) {
		case HW_GPIO_IN:
			tmp = read32(e->uc, HW_GPIO_IN);
			//LOG(e, SEEPROM, "HW_GPIO_IN read %08x", tmp);
		default: 
			break;
		}
	}
	else if (type == UC_MEM_WRITE)
	{
		switch (address) {
		case HW_GPIO_OUT:
			gpio_arm_output(e, value);
			break;
		case HW_GPIO_IN:
			uc_reg_read(e->uc, UC_ARM_REG_PC, &tmp);
			LOG(e, DEBUG, "HW_GPIO_IN write? %08x, pc=%08x", value, tmp);
			break;
		case HW_GPIO_ENABLE:
		case HW_GPIO_OUT_ENABLE:
		case HW_GPIO_INT_POLARITY:
		case HW_GPIO_INT_STATUS:
		case HW_GPIO_INT_ENABLE:
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
		case HW_ARB_CFG_M0:
		case HW_ARB_CFG_M1:
		case HW_ARB_CFG_M2:
		case HW_ARB_CFG_M3:
		case HW_ARB_CFG_M4:
		case HW_ARB_CFG_M5:
		case HW_ARB_CFG_M6:
		case HW_ARB_CFG_M7:
		case HW_ARB_CFG_M8:
		case HW_ARB_CFG_M9:
		case HW_ARB_CFG_MA:
		case HW_ARB_CFG_MB:
		case HW_ARB_CFG_MC:
		case HW_ARB_CFG_MD:
		case HW_ARB_CFG_ME:	
		case HW_ARB_CFG_MF:	
		case HW_ARB_CFG_CPU:	
		case HW_ARB_CFG_DMA:	
		case HW_SPARE0:
		case HW_BOOT0:
		case HW_VERSION: 
		case EFUSE_DATA:
			break;

		// Update the timer before every read.
		// Not clear if this actually affects performance or accuracy.
		case HW_TIMER:
			tmp = read32(uc, HW_TIMER) + 4;
			write32(uc, HW_TIMER, tmp);
			break;
		case HW_ALARM:
			LOG(e, MMIO, "HW_ALARM read");
			break;

		case EFUSE_ADDR:
			// Clear the busy bit every time someone reads
			tmp = read32(uc, EFUSE_ADDR);
			write32(uc, EFUSE_ADDR, tmp & 0x7fffffff);
			break;

		// By default, just don't log accesses
		default:
			//LOG(e, MMIO, "unimpl HLWD %08x read", address);
			break;
		}
	}
	else if (type == UC_MEM_WRITE)
	{
		switch (address) {
		case HW_ARB_CFG_M0:
		case HW_ARB_CFG_M1:
		case HW_ARB_CFG_M2:
		case HW_ARB_CFG_M3:
		case HW_ARB_CFG_M4:
		case HW_ARB_CFG_M5:
		case HW_ARB_CFG_M6:
		case HW_ARB_CFG_M7:
		case HW_ARB_CFG_M8:
		case HW_ARB_CFG_M9:
		case HW_ARB_CFG_MA:
		case HW_ARB_CFG_MB:
		case HW_ARB_CFG_MC:
		case HW_ARB_CFG_MD:
		case HW_ARB_CFG_ME:	
		case HW_ARB_CFG_MF:	
		case HW_ARB_CFG_CPU:	
		case HW_ARB_CFG_DMA:	
			break;

		case HW_TIMER:
			//dbg("HW_TIMER write %08x\n", value);
			break;
		case HW_ALARM:
			LOG(e, MMIO, "HW_ALARM write %08x", value);
			break;
		case HW_ARM_INTSTS:
			irq_status_write(e, value);
			break;
		case HW_ARM_INTEN:
			e->enabled_irq = value;
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
			LOG(e, MMIO, "unimpl HLWD %08x write %08x", address, value);
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



