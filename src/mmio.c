/* mmio.c - libstfu memory-mapped i/o 
 *
 * There is apparently no AFTER_WRITE hook in Unicorn [at least, not yet].
 * In order to compensate for this, simply perform I/O operations immediately
 * on relevant write accesses. Then, we can just immediately unset the busy 
 * bit for all I/O control registers on the next mainloop iteration.
 */

#include <string.h>

#include "mmio.h"
#include "ecc.h"
#include "hollywood.h"
#include "util.h"
#include "sha1.h"

#include <openssl/aes.h>
#include <unicorn/unicorn.h>

#ifndef LOGGING
#define LOGGING 1
#endif

#ifndef DEBUG
#define DEBUG 1
#endif


// ----------------------------------------------------------------------------

#define NAND_PAGE_LEN	0x840

#define NAND_FLAG_WAIT	0x08
#define NAND_FLAG_WRITE	0x04
#define NAND_FLAG_READ	0x02
#define NAND_FLAG_ECC	0x01

#define NAND_CMD_RESET	0xff
#define NAND_CMD_READ0b	0x30


// nand_dma_write()
// Do a NAND-to-ARM DMA write.
u8 ecc[4];
u8 nand_buf[0x10000];
void nand_dma_write(starlet *starlet, u32 flags, u32 len)
{
	u32 eccfix_addr = 0;

	// Grab parameters from the MMIO

	u32 addr2 = read32(starlet->uc, NAND_ADDR2);
	u32 data_addr = read32(starlet->uc, NAND_DATABUF);
	u32 ecc_addr = read32(starlet->uc, NAND_ECCBUF);

	// Get the offset of source data in the NAND buffer.
	// FIXME: this extra copy into nand_buf is not necessary
	u32 nand_off = addr2 * NAND_PAGE_LEN;
	memcpy(nand_buf, &starlet->nand.data[nand_off], len);

	dbg("NAND addr2=%08x nand_off=%08x data_addr=%08x ecc_addr=%08x\n", 
		addr2, nand_off, data_addr, ecc_addr);

	if (len == 0x800)
	{
		dbg("NAND dma on %08x, len=%08x\n", data_addr, len);
		uc_mem_write(starlet->uc, data_addr, nand_buf, len);
		memset(nand_buf, 0, 0x10000);
	}
	else if (len == 0x840)
	{
		dbg("NAND dma on %08x, len=%08x\n", data_addr, 0x800);
		dbg("NAND dma on %08x, len=%08x\n", ecc_addr, 0x40);
		uc_mem_write(starlet->uc, data_addr, nand_buf, 0x800);
		uc_mem_write(starlet->uc, ecc_addr, &nand_buf[0x800], 0x40);

		if (flags & NAND_FLAG_ECC)
		{
			for (int i = 0; i < 4; i++)
			{
				eccfix_addr = (ecc_addr ^ 0x40) + (i * 4);
				calc_ecc(nand_buf + (0x200 * i), ecc);
				uc_mem_write(starlet->uc, eccfix_addr, &ecc,4);
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
	switch(cmd) {
	case NAND_CMD_READ0b:
		nand_dma_write(e, flags, dsize);
		break;
	case 0x00:
	case NAND_CMD_RESET:
	default: break;
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
		case NAND_CTRL:
			tmp = read32(uc, NAND_CTRL);
			//dbg("NAND_CTRL cleared with %08x\n", tmp & 0x7fffffff);
			write32(uc, NAND_CTRL, tmp & 0x7fffffff);
			break;
		default: break;
		}
	}
	else if (type == UC_MEM_WRITE)
	{
		switch (address) {
		case NAND_CTRL:
			if (value & 0x80000000) handle_nand_command(e, value);
			break;
		default: break;
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
	uc_mem_read(e->uc, src_addr, aes_src_buf, len);

	dbg("AES dma on %08x, len=%08x\n", dst_addr, len);

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
	else uc_mem_write(e->uc, dst_addr, aes_src_buf, len);

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
			dbg("AES KEY FIFO add %08x\n", value);
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
			dbg("AES IV FIFO add %08x\n", value);
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

	dbg("pre sha_ctx  %08x%08x%08x%08x%08x\n", 
			read32(e->uc, SHA_H0),
			read32(e->uc, SHA_H1),
			read32(e->uc, SHA_H2),
			read32(e->uc, SHA_H3),
			read32(e->uc, SHA_H4));


	u32 len = ((value & 0xfff) + 1) * 0x40;
	u32 src_addr = read32(e->uc, SHA_SRC);
	uc_mem_read(e->uc, src_addr, sha_buf, len);

	dbg("SHA digest, addr=%08x, len=%08x\n", src_addr, len);
	SHA1Input(&sha_ctx, sha_buf, len);

	write32(e->uc, SHA_SRC, src_addr + len);
	write32(e->uc, SHA_H0, sha_ctx.Message_Digest[0]);
	write32(e->uc, SHA_H1, sha_ctx.Message_Digest[1]);
	write32(e->uc, SHA_H2, sha_ctx.Message_Digest[2]);
	write32(e->uc, SHA_H3, sha_ctx.Message_Digest[3]);
	write32(e->uc, SHA_H4, sha_ctx.Message_Digest[4]);

	dbg("post sha_ctx  %08x%08x%08x%08x%08x\n", 
			read32(e->uc, SHA_H0),
			read32(e->uc, SHA_H1),
			read32(e->uc, SHA_H2),
			read32(e->uc, SHA_H3),
			read32(e->uc, SHA_H4));

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

// __mmio_hlwd()
// Hollywood register MMIO handler
static bool __mmio_hlwd(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	u32 tmp;

	if (type == UC_MEM_READ)
	{
		switch (address) {

		// Update the timer before every read.
		// Not clear if this actually affects performance or accuracy.
		case HW_TIMER:
			tmp = read32(uc, HW_TIMER);
			write32(uc, HW_TIMER, tmp + 100);
			//dbg("HW_TIMER=%08x\n", tmp+5);
			break;

		case HW_SRNPROT: break;

		// Clear the busy bit every time someone reads
		case EFUSE_ADDR:
			tmp = read32(uc, EFUSE_ADDR);
			//dbg("EFUSE_ADDR cleared with %08x\n", tmp & 0x7fffffff);
			write32(uc, EFUSE_ADDR, tmp & 0x7fffffff);
			break;

		// Suppress messages for these
		case 0x0d8000c0:
		case 0x0d8000c4:
		case 0x0d8000c8:
		case 0x0d8000cc:
		case 0x0d8000d0:
		case 0x0d8000d4:
		case 0x0d8000d8:

		case 0x0d8000dc:
		case 0x0d8000e4:
		case 0x0d8000e8:
		case 0x0d8000ec:
		case 0x0d8000f0:
		case 0x0d8000f4:
		case 0x0d8000f8:
		case 0x0d8000fc:
		case 0x0d800100:
		case 0x0d800104:
		case 0x0d800108:
		case 0x0d80010c:
		case 0x0d800110:
		case 0x0d800114:
		case 0x0d800118:
		case 0x0d80011c:
		case 0x0d800120:
		case 0x0d800124:
		case 0x0d800128:
		case 0x0d80012c:
		case 0x0d800130:
		case 0x0d800134:
		case 0x0d800138:
		case 0x0d80013c:
		case 0x0d800140:
		case 0x0d800180:
		case HW_SPARE0:
		case HW_BOOT0:
		case 0x0d800194:
		case 0x0d8001bc:
		case 0x0d8001c0:

		case HW_VERSION: 
			break;
		default:
			log("Hollywood read on %08x\n", address);
			break;
		}
	}
	else if (type == UC_MEM_WRITE)
	{
		switch (address) {
		case HW_SRNPROT:
			// Enable the SRAM mirror
			if (value & 0x20) 
			{
				dbg("%s\n", "SRAM mirror on");
				e->state |= STATE_SRAM_MIRRORED;
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
			if (value & 0x1000) 
			{
				dbg("%s\n", "BROM unmapped");
				e->state |= STATE_BROM_UNMAPPED;
			}
			break;
		case EFUSE_ADDR:
			if (value & 0x80000000)
			{
				// OTP dumps are typically already in BE, so
				// we don't need to do any conversion here?
				tmp = value & 0x1f;
				dbg("Set EFUSE_DATA to %08x\n", e->otp.data[tmp]);
				write32(uc, EFUSE_DATA, be32toh(e->otp.data[tmp]));
			}
			break;

		// Suppress messages for these
		case 0x0d8000c0:
		case 0x0d8000c4:
		case 0x0d8000c8:
		case 0x0d8000cc:
		case 0x0d8000d0:
		case 0x0d8000d4:
		case 0x0d8000d8:
		case 0x0d8000dc:

		case 0x0d8000e4:
		case 0x0d8000e8:
		case 0x0d8000ec:
		case 0x0d8000f0:
		case 0x0d8000f4:
		case 0x0d8000f8:
		case 0x0d8000fc:
		case 0x0d800100:
		case 0x0d800104:
		case 0x0d800108:
		case 0x0d80010c:
		case 0x0d800110:
		case 0x0d800114:
		case 0x0d800118:
		case 0x0d80011c:
		case 0x0d800120:
		case 0x0d800124:
		case 0x0d800128:
		case 0x0d80012c:
		case 0x0d800130:
		case 0x0d800134:
		case 0x0d800138:
		case 0x0d80013c:
		case 0x0d800140:
		case 0x0d800180:
		case 0x0d800194:
		case 0x0d8001bc:
		case 0x0d8001c0:

			break;
		default: 
			log("Hollywood write %08x on %08x\n", value, address);
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


// ---------------------------------------------------------------------------

#define MMIO_HOOK	(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ)

// register_mmio_hooks()
// Register all of the MMIO hooks.
int register_mmio_hooks(starlet *e) 
{ 
	uc_hook x;
	uc_hook_add(e->uc,&x,MMIO_HOOK,__mmio_nand,e, 0x0d010000, 0x0d010020);
	uc_hook_add(e->uc,&x,MMIO_HOOK,__mmio_aes,e,  0x0d020000, 0x0d020020);
	uc_hook_add(e->uc,&x,MMIO_HOOK,__mmio_sha,e,  0x0d030000, 0x0d030040);
	uc_hook_add(e->uc,&x,MMIO_HOOK,__mmio_hlwd,e, 0x0d800000, 0x0d800220);
	uc_hook_add(e->uc,&x,MMIO_HOOK,__mmio_ddr,e,  0x0d8b4200, 0x0d8b4300);

	return 0; 
}



