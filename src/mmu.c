/* mmu.c - MMU-related functions 
 */

#include "core_types.h"

// init_mmu()
// Initialize various memory mappings
// UC_PROT_ALL=7
int init_mmu(starlet *e)
{
	// Main memory
	uc_mem_map_ptr(e->uc, 0x00000000, 0x01800000, 7, e->mram.mem1);
	uc_mem_map_ptr(e->uc, 0x10000000, 0x04000000, 7, e->mram.mem2);

	// MMIOs
	uc_mem_map_ptr(e->uc, 0x0d010000, 0x00000400, 7, e->iomem.nand);
	uc_mem_map_ptr(e->uc, 0x0d020000, 0x00000400, 7, e->iomem.aes);
	uc_mem_map_ptr(e->uc, 0x0d030000, 0x00000400, 7, e->iomem.sha);

	uc_mem_map_ptr(e->uc, 0x0d040000, 0x00000400, 7, e->iomem.ehci);
	uc_mem_map_ptr(e->uc, 0x0d050000, 0x00000400, 7, e->iomem.ohci0);
	uc_mem_map_ptr(e->uc, 0x0d060000, 0x00000400, 7, e->iomem.ohci1);

	uc_mem_map_ptr(e->uc, 0x0d806000, 0x00000400, 7, e->iomem.exi);
	uc_mem_map_ptr(e->uc, 0x0d800000, 0x00000400, 7, e->iomem.hlwd);
	uc_mem_map_ptr(e->uc, 0x0d8b0000, 0x00000400, 7, e->iomem.mem_unk);
	uc_mem_map_ptr(e->uc, 0x0d8b4000, 0x00000400, 7, e->iomem.ddr);

	// [Initial] mappings for SRAM and BROM
	uc_mem_map_ptr(e->uc, 0xffff0000, 0x00010000, 7, e->sram.brom);
	uc_mem_map_ptr(e->uc, 0xfffe0000, 0x00010000, 7, e->sram.bank_a);
	uc_mem_map_ptr(e->uc, 0xfff00000, 0x00010000, 7, e->sram.bank_a);
	uc_mem_map_ptr(e->uc, 0xfff10000, 0x00010000, 7, e->sram.bank_b);
	uc_mem_map_ptr(e->uc, 0x0d400000, 0x00010000, 7, e->sram.bank_a);
	uc_mem_map_ptr(e->uc, 0x0d410000, 0x00010000, 7, e->sram.bank_b);
	return 0;
}

// __enable_sram_mirror()
// Enable the SRAM mirror.
bool __enable_sram_mirror(starlet *e)
{
	uc_mem_unmap(e->uc, 0xfff00000, 0x00020000);
	uc_mem_unmap(e->uc, 0x0d400000, 0x00020000);
	uc_mem_unmap(e->uc, 0xffff0000, 0x00010000);
	uc_mem_unmap(e->uc, 0xfffe0000, 0x00010000);

	uc_mem_map_ptr(e->uc, 0xfff00000, 0x00010000, 7, e->sram.bank_b);
	uc_mem_map_ptr(e->uc, 0x0d400000, 0x00010000, 7, e->sram.bank_b);
	uc_mem_map_ptr(e->uc, 0xfff10000, 0x00010000, 7, e->sram.bank_a);
	uc_mem_map_ptr(e->uc, 0x0d410000, 0x00010000, 7, e->sram.bank_a);
	uc_mem_map_ptr(e->uc, 0xfffe0000, 0x00010000, 7, e->sram.bank_b);
	uc_mem_map_ptr(e->uc, 0xffff0000, 0x00010000, 7, e->sram.bank_a);

	return false;
}

// __disable_brom_mapping()
// Disable the boot ROM mapping.
bool __disable_brom_mapping(starlet *e)
{
	uc_mem_unmap(e->uc, 0xfff00000, 0x00020000);
	uc_mem_unmap(e->uc, 0x0d400000, 0x00020000);
	uc_mem_unmap(e->uc, 0xffff0000, 0x00010000);
	uc_mem_unmap(e->uc, 0xfffe0000, 0x00010000);

	uc_mem_map_ptr(e->uc, 0xfff00000, 0x00010000, 7, e->sram.bank_b);
	uc_mem_map_ptr(e->uc, 0x0d400000, 0x00010000, 7, e->sram.bank_b);
	uc_mem_map_ptr(e->uc, 0xfff10000, 0x00010000, 7, e->sram.bank_a);
	uc_mem_map_ptr(e->uc, 0x0d410000, 0x00010000, 7, e->sram.bank_a);
	uc_mem_map_ptr(e->uc, 0xfffe0000, 0x00010000, 7, e->sram.bank_b);
	uc_mem_map_ptr(e->uc, 0xffff0000, 0x00010000, 7, e->sram.bank_a);

	return false;
}

