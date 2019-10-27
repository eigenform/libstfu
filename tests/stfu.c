#include <stdio.h>
#include "starlet.h"
#include "util.h"

static starlet emu;

int main(void)
{
	// Initialize the emulator
	starlet_init(&emu);


	// Read a NAND dump into memory
	size_t nand_size = get_filesize("nand.bin");
	if (nand_size == -1)
	{
		printf("Couldn't open ./nand.bin\n");
		return -1;
	}
	u8 *nand_data = malloc(nand_size);
	printf("Allocated %08x bytes for NAND\n", nand_size);
	FILE *fp = fopen("nand.bin", "rb");
	fread(nand_data, 1, nand_size, fp);
	fclose(fp);

	starlet_load_nand_buffer(&emu, nand_data, nand_size);
	free(nand_data);

	// Load boot ROM and OTP
	starlet_load_boot0(&emu, "boot0.bin");
	starlet_load_otp(&emu, "otp.bin");

	// Breakpoints on boot0/boot1 panic()
	//starlet_add_bp(&emu, 0xffff00bc);
	//starlet_add_bp(&emu, 0xfff00616);

	// Actually emulate something until we halt
	starlet_run(&emu);
	starlet_destroy(&emu);

	return 0;
}
