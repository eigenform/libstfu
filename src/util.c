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




u32 be32(u32 x) { return htobe32(x); }
u32 le32(u32 x) { return be32toh(x); }
u32 be16(u32 x) { return htobe16(x); }
u32 le16(u32 x) { return be16toh(x); }
