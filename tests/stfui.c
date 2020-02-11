#include <stdio.h>
#include <signal.h>
#include <ncurses.h>
#include <string.h>
#include <stdbool.h>

#include "starlet.h"
#include "util.h"

extern bool __run_stepped(starlet *emu, u32 steps);

#define NUM_REGS	13
#define PANE_TITLE_LEN	32
#define BORDER_WIDTH	2
#define CON_HEIGHT	(6 + BORDER_WIDTH)
#define REG_WIDTH	(16 + BORDER_WIDTH)

struct pane 
{ 
	int h, l, y, x; 
	char title[PANE_TITLE_LEN]; 
	WINDOW *w; 
	WINDOW *b;
};

typedef struct starlet_ctx {
	u32 pc;
	u32 sp;
	u32 lr;
	u32 r[NUM_REGS];
} sctx;

static int parent_y, parent_x;
static struct pane reg, log, con;

static sctx ctx;
static starlet emu;
static char input_buf[0x100];
static char *token = NULL;

// ----------------------------------------------------------------------------

void refresh_pane(struct pane *p) { wrefresh(p->b); wrefresh(p->w); }
void init_pane(struct pane *p, char *title, int y, int x, int h, int l)
{
	strncpy(p->title, title, PANE_TITLE_LEN - 1);
	p->h = h;
	p->l = l;
	p->y = y;
	p->x = x;
	p->b = newwin(h, l, y, x);
	p->w = subwin(p->b, h - BORDER_WIDTH, l - BORDER_WIDTH, y + 1, x + 1);
}

void draw_border(struct pane *p)
{
	wattron(p->b, COLOR_PAIR(3));
	box(p->b, 0, 0);
	wattroff(p->b, COLOR_PAIR(3));
	wattron(p->b, COLOR_PAIR(1));
	mvwprintw(p->b, 0, 2, "[%s]", p->title);
	wattroff(p->b, COLOR_PAIR(1));
}

void init_tui()
{
	initscr();
	start_color();
	getmaxyx(stdscr, parent_y, parent_x);

	init_pair(1, COLOR_WHITE, COLOR_BLACK);
	init_pair(2, COLOR_BLACK, COLOR_GREEN);
	init_pair(3, COLOR_RED, COLOR_BLACK);
	init_pair(4, COLOR_BLUE, COLOR_BLACK);
	init_pair(5, COLOR_YELLOW, COLOR_BLUE);

	init_pane(&reg, "registers", 0, 0, parent_y - CON_HEIGHT, REG_WIDTH);
	init_pane(&con, "console", parent_y - CON_HEIGHT, 0, CON_HEIGHT, parent_x);
	init_pane(&log, "log", 0, REG_WIDTH, parent_y - CON_HEIGHT, 
			parent_x - REG_WIDTH);

	scrollok(log.w, true);
	idlok(log.w, true);
	scrollok(con.w, true);
	idlok(con.w, true);
}

void draw_registers()
{
	wattron(reg.w, COLOR_PAIR(1));
	mvwprintw(reg.w, 0, 0, "[pc ] %08x", ctx.pc);
	mvwprintw(reg.w, 1, 0, "[lr ] %08x", ctx.lr);
	mvwprintw(reg.w, 2, 0, "[sp ] %08x", ctx.sp);
	for (int i = 0; i < 13; i++)
		mvwprintw(reg.w, 4 + i, 0, "[r%-2d] %08x", i, ctx.r[i]);
	wattroff(reg.w, COLOR_PAIR(1));
}

void draw_log(int type, char *entry)
{
	wprintw(log.w, "%s\n", entry);
	refresh_pane(&log);
}

void draw_screen()
{
	// Draw the borders on all panes
	draw_border(&reg);
	draw_border(&log);
	draw_border(&con);

	// Draw contents in all the panes
	draw_registers();

	// Refresh all windows
	refresh_pane(&reg);
	refresh_pane(&log);
	refresh_pane(&con);
}

bool handle_console_input()
{
	int tmp;
	u32 word;
	wprintw(con.w, "$ ");
	wgetnstr(con.w, input_buf, 0x100);
	token = strtok(input_buf, " ");
	while (token != NULL)
	{
		if (!strcasecmp(token, "step"))
		{
			token = strtok(NULL, " ");
			if (token == NULL)
			{	
				__run_stepped(&emu, 1);
			}
			else 
			{
				tmp = atoi(token);
				if (tmp < 0) break;
				__run_stepped(&emu, tmp);
			}
		}
		else if (!strcasecmp(token, "x"))
		{
			// Parse an address
			token = strtok(NULL, " ");
			if (token == NULL)
			{
				wprintw(con.w, "usage: x <address> <length in 32-bit words>\n");
				break;
			}
			else
			{
				// Convert an address to an integer
				tmp = strtol(token, NULL, 0);
				word = vread32(emu.uc, tmp);
				wprintw(con.w, "%08x: %08x\n", tmp, word);
			}
		}
		else if (!strcasecmp(token, "quit")) 
			return true;
		token = strtok(NULL, " ");
	}
	return false;
}

// ----------------------------------------------------------------------------

void update_ctx(starlet *e, sctx *c)
{
	uc_reg_read(e->uc, UC_ARM_REG_PC, &c->pc);
	uc_reg_read(e->uc, UC_ARM_REG_SP, &c->sp);
	uc_reg_read(e->uc, UC_ARM_REG_LR, &c->lr);
	for (int i = 0; i < 13; i++)
		uc_reg_read(e->uc, UC_ARM_REG_R0 + i, &c->r[i]);
}

// Handler for SIGINT; fatally halt emulation
void sigint_handle(int signum)
{
	printf("Caught SIGINT\n");
	emu.halt_code = HALT_USER;
	uc_emu_stop(emu.uc);
	starlet_destroy(&emu);
	endwin();
	exit(0);
}

int load_nand(const char *filename)
{
	size_t nand_size = get_filesize(filename);
	if (nand_size == -1)
	{
		printf("Couldn't open %s\n", filename);
		return -1;
	}
	u8 *nand_data = malloc(nand_size);
	printf("Allocated %08x bytes for NAND\n", nand_size);
	FILE *fp = fopen(filename, "rb");
	fread(nand_data, 1, nand_size, fp);
	fclose(fp);

	starlet_load_nand_buffer(&emu, nand_data, nand_size);
	free(nand_data);
}


// ----------------------------------------------------------------------------

int main(void)
{
	init_tui();
	signal(SIGINT, sigint_handle);

	emu.log_hook = draw_log;
	starlet_init(&emu);
	load_nand("nand.bin");
	starlet_load_boot0(&emu, "boot0.bin");
	starlet_load_otp(&emu, "otp.bin");
	starlet_load_seeprom(&emu, "seeprom.bin");
	uc_reg_write(emu.uc, UC_ARM_REG_PC, &emu.entrypoint);

	while (true) 
	{ 
		update_ctx(&emu, &ctx);
		draw_screen();
		if (handle_console_input())
			break;
	}

	emu.halt_code = HALT_USER;
	uc_emu_stop(emu.uc);
	starlet_destroy(&emu);
	endwin();
	return 0;
}

