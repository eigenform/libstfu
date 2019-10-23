#include "starlet.h"
#include <stdio.h>
#include <time.h>

static starlet emu;
static u8 nand_data[0x840 * 0x200];

struct timespec tdiff(struct timespec a, struct timespec b)
{
	struct timespec d;
	if ((b.tv_nsec - a.tv_nsec) < 0)
	{
		d.tv_sec = b.tv_sec - a.tv_sec - 1;
		d.tv_nsec = 1000000000 + b.tv_nsec - a.tv_nsec;
	}
	else
	{
		d.tv_sec = b.tv_sec - a.tv_sec;
		d.tv_nsec = b.tv_nsec - a.tv_nsec;
	}
	return d;
}

int main(void)
{
	struct timespec t0, t1, diff;

	FILE *fp = fopen("nand.bin", "rb");
	if (!fp)
	{
		printf("Couldn't open ./nand.bin\n");
		return -1;
	}
	fread(&nand_data, 0x840, 0x200, fp);
	fclose(fp);

	starlet_init(&emu);

	starlet_load_boot0(&emu, "boot0.bin");
	starlet_load_otp(&emu, "otp.bin");
	starlet_load_nand_buffer(&emu, &nand_data, 0x840*0x200);

	// Break on entry into boot2
	starlet_add_bp(&emu, 0xfff00058);

	clock_gettime(CLOCK_MONOTONIC, &t0);
	starlet_run(&emu);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	starlet_destroy(&emu);

	diff = tdiff(t0, t1);
	double ns = (diff.tv_sec * 1000000000) + diff.tv_nsec;
	double ms = ns /1000000;
	printf("Started boot1, took %.06lfms \n", ms);

	return 0;
}
