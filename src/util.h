#ifndef _UTIL_H
#define _UTIL_H

#include "core_types.h"

// Logging macro
#define log(fmt, ...) \
	do { if (LOGGING) fprintf(stdout, "[*] " fmt, __VA_ARGS__); } while (0)

// Debug logging macro
#define dbg(fmt, ...) \
do { if (DEBUG) \
	fprintf(stdout, "%s:%d:%s(): " fmt, __FILE__, \
		__LINE__, __func__, __VA_ARGS__); \
} while (0)

// Utility functions
size_t get_filesize(const char *filename);
void hexdump(char *desc, void *addr, int len);

u32 be32(u32 x);
u32 le32(u32 x);
u32 be16(u32 x);
u32 le16(u32 x);
#endif //_UTIL_H
