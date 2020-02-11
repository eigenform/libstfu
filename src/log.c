#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "core_types.h"

// Strings for log message types
const char *log_type_name[] = {
	"DEBUG",
	"SYSTEM",
	"IOS",
	"SVC",
	"MMIO",
	"GPIO",
	"PROM",
	"NAND",
	"SHA",
	"AES",
	"INTRPT",
};

static char tmp_buf[MAX_ENTRY_LEN];
void __log_render(starlet *e, int type, const char *fmt, va_list args)
{

	vsnprintf(tmp_buf, 0x100, fmt, args);

	// Just print to stdout if there's no logging hook
	if (e->log_hook == NULL)
	{
		fprintf(stdout, "[%-6s] %s\n", log_type_name[type], tmp_buf);
		return;
	}
	e->log_hook(type, tmp_buf);
	return;
}

void __log(starlet *e, int type, const char *fmt, ...)
{
	if (e == NULL) return;

	va_list args;
	va_start(args, fmt);
	__log_render(e, type, fmt, args);
	va_end(args);
}
