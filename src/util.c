/* util.c - helper functions
 */

#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <endian.h>

#include "core_types.h"

// get_filesize()
// Return the size of the given file; return -1 if the file doesn't exist.
size_t get_filesize(const char *filename)
{
	FILE *fp = fopen(filename, "rb");
	if (!fp) return -1;
	fseek(fp, 0, SEEK_SET);
	fseek(fp, 0, SEEK_END);
	size_t sz = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	fclose(fp);
	return sz;
}


// hexdump()
// https://stackoverflow.com/a/7776146 :^)
void hexdump(char *desc, void *addr, int len)
{
	unsigned char *pc = (unsigned char*)addr;
	unsigned char buff[17];
	int i;

	if (desc != NULL) printf ("%s:\n", desc);
	if (len == 0) 
	{
		printf("  ZERO LENGTH\n");
		return; 
	}
	if (len < 0)
	{
		printf("  NEGATIVE LENGTH: %i\n",len);
		return;
	}

	for (i = 0; i < len; i++)
	{
		if ((i % 16) == 0) 
		{
			if (i != 0) 
				printf("  %s\n", buff);
			printf("  %04x ", i); 
		}
		
		printf(" %02x", pc[i]);
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	while ((i % 16) != 0)
	{
		printf("   ");
		i++;
	}
	
	printf("  %s\n", buff);
}


u32 read32(uc_engine *uc, u32 addr)
{
	u32 val;
	uc_mem_read(uc, addr, &val, 4);
	return htobe32(val);
}
u32 read16(uc_engine *uc, u32 addr)
{
	u16 val;
	uc_mem_read(uc, addr, &val, 2);
	return htobe16(val);
}

void write32(uc_engine *uc, u32 addr, u32 val)
{
	u32 value = be32toh(val);
	uc_mem_write(uc, addr, &value, 4);
}


void write16(uc_engine *uc, u32 addr, u16 val)
{
	u16 value = be16toh(val);
	uc_mem_write(uc, addr, &value, 2);
}

u32 vread32(uc_engine *uc, u32 addr)
{
	u32 val;
	uc_vmem_read(uc, addr, &val, 4);
	return htobe32(val);
}
