/* tui.h - minimal terminal UI layer (ANSI/VT, no external libraries).
 *
 * Drawing goes into an in-memory cell grid; tui_present() converts the
 * whole grid to one escape-sequence string and writes it in a single call,
 * so frames never flicker. Every piece of text is sanitised: control
 * characters can never reach the terminal (escape-injection safe).
 */
#ifndef PM_TUI_H
#define PM_TUI_H

#include <stddef.h>

/* colours (16-colour palette); -1 = terminal default */
enum {
    C_DEF = -1, C_BLACK = 0, C_RED, C_GREEN, C_YELLOW, C_BLUE, C_MAGENTA, C_CYAN, C_WHITE,
    C_GREY, C_BRED, C_BGREEN, C_BYELLOW, C_BBLUE, C_BMAGENTA, C_BCYAN, C_BWHITE
};
enum { A_NONE = 0, A_BOLD = 1, A_UNDER = 2, A_DIM = 4 };

/* special keys live above the Unicode range */
enum {
    K_NONE = 0, K_ENTER = 13, K_ESC = 27, K_TAB = 9, K_BACKSPACE = 8,
    K_UP = 0x110001, K_DOWN, K_LEFT, K_RIGHT, K_PGUP, K_PGDN, K_HOME, K_END, K_DEL,
    K_F1, K_F2, K_F3, K_F4, K_F5, K_F6, K_F7, K_F8, K_F9, K_F10
};

int  tui_init(void);
void tui_shutdown(void);
void tui_set_cleanup_hook(void (*fn)(void));

int  tui_w(void);
int  tui_h(void);

void tui_clear(void);                       /* re-reads terminal size, blanks the grid */
int  tui_text(int y, int x, int maxw, int fg, int bg, int attr, const char *utf8);
int  tui_textf(int y, int x, int maxw, int fg, int bg, int attr, const char *fmt, ...);
void tui_fill(int y, int x, int w, int fg, int bg, unsigned cp);
int  tui_link(int y, int x, int maxw, int fg, int bg, const char *text, const char *url);
void tui_box(int y, int x, int h, int w, int fg, int bg, const char *title);
void tui_meter(int y, int x, int w, const char *label, double frac, int fg, const char *value);
void tui_cursor(int show, int y, int x);
void tui_present(void);

int  tui_key(int timeout_ms);               /* K_NONE on timeout */

#include <stdio.h>
void tui_force_size(int w, int h);          /* render without a terminal */
void tui_dump(FILE *f);                     /* grid as plain text */
void tui_dump_json(FILE *f);                /* grid as JSON colour runs */

/* helpers */
int  utf8_width(const char *s);             /* display columns */
int  utf8_decode(const char **s);           /* next codepoint, advances; -1 at end */
size_t utf8_encode(unsigned cp, char out[4]);
int  tui_wrap(const char *text, int width, char lines[][512], int max_lines);

#endif
