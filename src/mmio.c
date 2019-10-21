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
#define LOGGING 0
#endif

#ifndef DEBUG
#define DEBUG 0
#endif



#define NAND_PAGE_LEN	0x840

#define NAND_FLAG_WAIT	0x08
#define NAND_FLAG_WRITE	0x04
#define NAND_FLAG_READ	0x02
#define NAND_FLAG_ECC	0x01

#define NAND_CMD_RESET	0xff
#define NAND_CMD_READ0b	0x30

// ----------------------------------------------------------------------------

// nand_dma_write()
// Do a NAND-to-ARM DMA write.
u8 ecc[4];
u8 nand_buf[0x1000];
void nand_dma_write(starlet *starlet, u32 flags, u32 len)
{
	u32 eccfix_addr = 0;

	// Grab parameters from the MMIO
	u32 addr2 = htobe32(*(u32*)&starlet->iomem.nand[0x0c]);
	u32 data_addr = htobe32(*(u32*)&starlet->iomem.nand[0x10]);
	u32 ecc_addr = htobe32(*(u32*)&starlet->iomem.nand[0x14]);

	// Get the offset of source data in the NAND buffer.
	// FIXME: this extra copy into nand_buf is not necessary
	u32 nand_off = addr2 * NAND_PAGE_LEN;
	u8 *src_buf = &starlet->nand.data[nand_off];
	memcpy(nand_buf, src_buf, len);

	dbg("NAND addr2=%08x nand_off=%08x data_addr=%08x ecc_addr=%08x\n", 
		addr2, nand_off, data_addr, ecc_addr);

	if (len == 0x800)
	{
		dbg("NAND dma on %08x, len=%08x\n", data_addr, len);
		uc_mem_write(starlet->uc, data_addr, nand_buf, len);
		return;
	}
	else if (len == 0x840)
	{
		dbg("NAND dma on %08x, len=%08x\n", data_addr, 0x800);
		dbg("NAND dma on %08x, len=%08x\n", ecc_addr, 0x40);
		uc_mem_write(starlet->uc, data_addr, nand_buf, 0x800);
		uc_mem_write(starlet->uc, ecc_addr, nand_buf + 0x800, 0x40);

		if (flags & NAND_FLAG_ECC)
		{
			for (int i = 0; i < 4; i++)
			{
				eccfix_addr = (ecc_addr ^ 0x40) + (i * 4);
				calc_ecc(src_buf + (0x200 * i), ecc);
				uc_mem_write(starlet->uc, eccfix_addr, &ecc,4);
			}
		}
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
	case 0x00: break;
	case NAND_CMD_RESET: break;
	case NAND_CMD_READ0b:
		nand_dma_write(e, flags, dsize);
		break;
	default: break;
	}
}

// __mmio_nand()
// NAND MMIO handler
static bool __mmio_nand(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	if (type == UC_MEM_WRITE)
		log("NAND write %08x on %08x\n", value, address);
	if (type == UC_MEM_READ)
		log("NAND read %08x\n", address);

	if ((type == UC_MEM_WRITE) && (address == NAND_CTRL))
		if (value & 0x80000000) handle_nand_command(e, value);
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
	u32 src_addr = htobe32(*(u32*)&e->iomem.aes[0x04]);
	u32 dst_addr = htobe32(*(u32*)&e->iomem.aes[0x08]);
	bool use_tmp_iv = (value & 0x1000) ? true : false;
	bool use_aes = (value & 0x10000000) ? true : false;
	bool decrypt = (value & 0x08000000) ? true : false;

	// Read into a temporary buffer
	uc_mem_read(e->uc, src_addr, aes_src_buf, len);

	dbg("AES dma on %08x, len=%08x\n", dst_addr, len);

	if (use_aes)
	{
		AES_KEY key;
		if (decrypt)
		{
			AES_set_decrypt_key(aes_key_fifo, 128, &key);
			AES_cbc_encrypt(aes_src_buf, aes_dst_buf, len, &key, 
				use_tmp_iv?tmp_iv:aes_iv_fifo, AES_DECRYPT);
			//hexdump("AES data", aes_dst_buf, 0x100);
		}
		else
		{
			AES_set_encrypt_key(aes_key_fifo, 128, &key);
			AES_cbc_encrypt(aes_src_buf, aes_dst_buf, len, &key, 
				use_tmp_iv?tmp_iv:aes_iv_fifo, AES_ENCRYPT);
		}
	}
	else uc_mem_write(e->uc, dst_addr, aes_src_buf, len);

	uc_mem_write(e->uc, dst_addr, aes_dst_buf, len);
	memcpy(tmp_iv, aes_src_buf + (len - 0x10), 0x10);

	*(u32*)&e->iomem.aes[0x04] = htobe32(src_addr + len);
	*(u32*)&e->iomem.aes[0x08] = htobe32(dst_addr + len);
}

// __mmio_aes()
// AES engine MMIO handler
static bool __mmio_aes(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	if (type == UC_MEM_READ)
		log("AES read on %08x\n", address);
	if (type == UC_MEM_WRITE)
	{
		log("AES write %08x on %08x\n", value, address);
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



	return true;
}

// ----------------------------------------------------------------------------

SHA1Context sha_ctx;
u8 sha_buf[0x10000];
u8 sha_res[0x14];

// handle_sha_command()
// Handle a SHA-1 engine command.
static void handle_sha_command(starlet *e, s64 value)
{

	dbg("pre sha_ctx  %08x%08x%08x%08x%08x\n", 
			sha_ctx.Message_Digest[0],
			sha_ctx.Message_Digest[1],
			sha_ctx.Message_Digest[2],
			sha_ctx.Message_Digest[3],
			sha_ctx.Message_Digest[4]);


	u32 len = ((value & 0xfff) + 1) * 0x40;
	u32 src_addr = htobe32(*(u32*)&e->iomem.sha[0x04]);
	uc_mem_read(e->uc, src_addr, sha_buf, len);

	dbg("SHA digest, addr=%08x, len=%08x\n", src_addr, len);
	SHA1Input(&sha_ctx, sha_buf, len);

	*(u32*)&e->iomem.sha[0x04] = htobe32(src_addr + len);
	*(u32*)&e->iomem.sha[0x08] = sha_ctx.Message_Digest[0];
	*(u32*)&e->iomem.sha[0x0c] = sha_ctx.Message_Digest[1];
	*(u32*)&e->iomem.sha[0x10] = sha_ctx.Message_Digest[2];
	*(u32*)&e->iomem.sha[0x14] = sha_ctx.Message_Digest[3];
	*(u32*)&e->iomem.sha[0x18] = sha_ctx.Message_Digest[4];

	dbg("post sha_ctx  %08x%08x%08x%08x%08x\n", 
			sha_ctx.Message_Digest[0],
			sha_ctx.Message_Digest[1],
			sha_ctx.Message_Digest[2],
			sha_ctx.Message_Digest[3],
			sha_ctx.Message_Digest[4]);
}

// __mmio_sha()
// SHA1 engine MMIO handler
static bool __mmio_sha(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	if (type == UC_MEM_WRITE)
		log("SHA write %08x on %08x\n", value, address);
	if (type == UC_MEM_READ)
		log("SHA read on %08x\n", address);

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

	return true;
}


// ----------------------------------------------------------------------------

// __mmio_hlwd()
// Hollywood register MMIO handler
static bool __mmio_hlwd(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	if (type == UC_MEM_WRITE)
		log("Hollywood write %08x on %08x\n", value, address);
	if (type == UC_MEM_READ)
		log("Hollywood read on %08x\n", address);

	return true;
}


// ----------------------------------------------------------------------------

// __mmio_ddr()
// Memory controller MMIO handler
static bool __mmio_ddr(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	if (type == UC_MEM_WRITE)
		log("DDR write %08x on %08x\n", value, address);
	if (type == UC_MEM_READ)
		log("DDR read on %08x\n", address);

	return true;
}


// ----------------------------------------------------------------------------

// __mmio_otp()
// EFUSE/OTP MMIO handler
static bool __mmio_otp(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, starlet *e)
{
	if ((type == UC_MEM_WRITE) && (address == EFUSE_ADDR))
	{
		if (value & 0x80000000)
		{
			u32 addr = value & 0x1f;
			dbg("Set EFUSE_DATA to %08x\n", htobe32(e->otp.data[addr]));
			*(u32*)&e->iomem.hlwd[0x1f0] = htobe32(e->otp.data[addr]);
		}
	}

	return true;
}



// ---------------------------------------------------------------------------


// register_mmio_hooks()
// Register all of the MMIO hooks.
int register_mmio_hooks(starlet *e) 
{ 
	uc_hook x;
	uc_hook_add(e->uc, &x, UC_HOOK_MEM_WRITE|UC_HOOK_MEM_READ, __mmio_nand, 
			e, 0x0d010000, 0x0d010020);

	uc_hook_add(e->uc, &x, UC_HOOK_MEM_WRITE|UC_HOOK_MEM_READ, __mmio_aes,
			e, 0x0d020000, 0x0d020020);

	uc_hook_add(e->uc, &x, UC_HOOK_MEM_WRITE|UC_HOOK_MEM_READ, __mmio_sha,
			e, 0x0d030000, 0x0d030040);

	uc_hook_add(e->uc, &x, UC_HOOK_MEM_WRITE|UC_HOOK_MEM_READ, __mmio_hlwd,
			e, 0x0d800000, 0x0d800220);

	uc_hook_add(e->uc, &x, UC_HOOK_MEM_WRITE|UC_HOOK_MEM_READ, __mmio_ddr,
			e, 0x0d8b4200, 0x0d8b4300);

	uc_hook_add(e->uc, &x, UC_HOOK_MEM_WRITE|UC_HOOK_MEM_READ, __mmio_otp,
			e, 0x0d8001ec, 0x0d8001f0);


	return 0; 
}



