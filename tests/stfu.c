#include <stdio.h>
#include "starlet.h"

static starlet emu;

static u8 nand_data[0x840 * 0x200];
int main(void)
{
	FILE *fp = fopen("nand.bin", "rb");
	if (!fp)
	{
		printf("Couldn't open ./nand.bin\n");
		return -1;
	}
	fread(&nand_data, 0x840, 0x200, fp);
	fclose(fp);

	starlet_init(&emu);

	//starlet_load_code(&emu, "boot1c.bin", 0x0d400000);
	starlet_load_boot0(&emu, "boot0.bin");
	starlet_load_otp(&emu, "otp.bin");
	starlet_load_nand_buffer(&emu, &nand_data, 0x840*0x200);

	// Break on boot0 panic()
	starlet_add_bp(&emu, 0xffff00a4);

	starlet_run(&emu);
	starlet_destroy(&emu);
	return 0;
}
