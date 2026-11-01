/* tui.c - see tui.h */
#include "tui.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <conio.h>
#else
#  include <signal.h>
#  include <sys/ioctl.h>
#  include <sys/select.h>
#  include <termios.h>
#  include <unistd.h>
#endif

typedef struct {
    unsigned cp;
    signed char fg, bg;
    unsigned char attr, link;
} Cell;

#define MAX_LINKS 32
static Cell *g_grid;
static int g_w, g_h, g_cap;
static char g_links[MAX_LINKS][1024];
static int g_nlinks;
static int g_cur_show, g_cur_y, g_cur_x;
static int g_active;
static void (*g_cleanup_hook)(void);

/* ------------------------------------------------------------------ output buffer */
static char *g_out;
static size_t g_out_n, g_out_cap;

static void out_put(const char *s, size_t n) {
    if (g_out_n + n + 1 > g_out_cap) {
        size_t cap = g_out_cap ? g_out_cap : 65536;
        while (g_out_n + n + 1 > cap) cap *= 2;
        char *p = realloc(g_out, cap);
        if (!p) return;
        g_out = p;
        g_out_cap = cap;
    }
    memcpy(g_out + g_out_n, s, n);
    g_out_n += n;
}
static void out_str(const char *s) { out_put(s, strlen(s)); }
static void out_flush(void) {
    if (!g_out_n) return;
#ifdef _WIN32
    DWORD written;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), g_out, (DWORD)g_out_n, &written, NULL);
#else
    size_t off = 0;
    while (off < g_out_n) {
        ssize_t r = write(STDOUT_FILENO, g_out + off, g_out_n - off);
        if (r <= 0) break;
        off += (size_t)r;
    }
#endif
    g_out_n = 0;
}

/* ------------------------------------------------------------------ UTF-8 */
int utf8_decode(const char **ps) {
    const unsigned char *s = (const unsigned char *)*ps;
    if (!*s) return -1;
    unsigned cp;
    int n;
    if (s[0] < 0x80) { cp = s[0]; n = 1; }
    else if ((s[0] & 0xE0) == 0xC0) { cp = s[0] & 0x1F; n = 2; }
    else if ((s[0] & 0xF0) == 0xE0) { cp = s[0] & 0x0F; n = 3; }
    else if ((s[0] & 0xF8) == 0xF0) { cp = s[0] & 0x07; n = 4; }
    else { *ps += 1; return '?'; }
    for (int i = 1; i < n; i++) {
        if ((s[i] & 0xC0) != 0x80) { *ps += i; return '?'; }
        cp = (cp << 6) | (s[i] & 0x3F);
    }
    *ps += n;
    return (int)cp;
}

size_t utf8_encode(unsigned cp, char o[4]) {
    if (cp < 0x80) { o[0] = (char)cp; return 1; }
    if (cp < 0x800) { o[0] = (char)(0xC0 | (cp >> 6)); o[1] = (char)(0x80 | (cp & 0x3F)); return 2; }
    if (cp < 0x10000) {
        o[0] = (char)(0xE0 | (cp >> 12)); o[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        o[2] = (char)(0x80 | (cp & 0x3F)); return 3;
    }
    o[0] = (char)(0xF0 | (cp >> 18)); o[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    o[2] = (char)(0x80 | ((cp >> 6) & 0x3F)); o[3] = (char)(0x80 | (cp & 0x3F)); return 4;
}

/* Security: no control characters may reach the terminal, and wide glyphs
 * (which would break the grid alignment) are replaced. */
static unsigned sanitize_cp(int cp) {
    if (cp < 0x20 || (cp >= 0x7F && cp <= 0x9F)) return '?';
    if (cp >= 0x1100 && (cp <= 0x115F || (cp >= 0x2E80 && cp <= 0xA4CF) || (cp >= 0xAC00 && cp <= 0xD7A3)
                         || (cp >= 0xF900 && cp <= 0xFAFF) || (cp >= 0xFE30 && cp <= 0xFE4F)
                         || (cp >= 0xFF00 && cp <= 0xFF60) || (cp >= 0xFFE0 && cp <= 0xFFE6) || cp >= 0x1F000))
        return '?';
    if (cp >= 0xD800 && cp <= 0xDFFF) return '?';
    return (unsigned)cp;
}

int utf8_width(const char *s) {
    int w = 0;
    while (utf8_decode(&s) >= 0) w++;
    return w;
}

/* ------------------------------------------------------------------ terminal setup */
#ifdef _WIN32
static DWORD g_old_out_mode, g_old_in_mode;
static UINT g_old_cp, g_old_incp;
static BOOL WINAPI ctrl_handler(DWORD type) {
    (void)type;
    tui_shutdown();
    ExitProcess(130);
    return TRUE;
}
#else
static struct termios g_old_tio;
static void sig_handler(int sig) {
    tui_shutdown();
    signal(sig, SIG_DFL);
    raise(sig);
}
#endif

static int g_force_w, g_force_h;
void tui_force_size(int w, int h) { g_force_w = w; g_force_h = h; }

static void query_size(void) {
    int w = 80, h = 24;
    if (g_force_w) { w = g_force_w; h = g_force_h; goto have; }
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
        w = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        h = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
    }
#else
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) { w = ws.ws_col; h = ws.ws_row; }
#endif
have:
    if (w < 20) w = 20;
    if (h < 8) h = 8;
    if (w > 400) w = 400;
    if (h > 200) h = 200;
    if (w * h > g_cap) {
        Cell *g = realloc(g_grid, sizeof(Cell) * (size_t)(w * h));
        if (!g) return;
        g_grid = g;
        g_cap = w * h;
    }
    g_w = w;
    g_h = h;
}

void tui_set_cleanup_hook(void (*fn)(void)) { g_cleanup_hook = fn; }

int tui_init(void) {
#ifdef _WIN32
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE), in = GetStdHandle(STD_INPUT_HANDLE);
    if (!GetConsoleMode(out, &g_old_out_mode)) {
        fprintf(stderr, "pmtui needs an interactive console (Windows Terminal, cmd or PowerShell).\n");
        return -1;
    }
    GetConsoleMode(in, &g_old_in_mode);
    g_old_cp = GetConsoleOutputCP();
    g_old_incp = GetConsoleCP();
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    if (!SetConsoleMode(out, g_old_out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT)) {
        fprintf(stderr, "This console does not support ANSI escape codes. Use Windows 10+ / Windows Terminal.\n");
        return -1;
    }
    SetConsoleMode(in, (g_old_in_mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_QUICK_EDIT_MODE))
                       | ENABLE_EXTENDED_FLAGS | ENABLE_PROCESSED_INPUT);
    SetConsoleCtrlHandler(ctrl_handler, TRUE);
#else
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        fprintf(stderr, "pmtui needs an interactive terminal.\n");
        return -1;
    }
    tcgetattr(STDIN_FILENO, &g_old_tio);
    struct termios t = g_old_tio;
    t.c_lflag &= ~(tcflag_t)(ICANON | ECHO | IEXTEN);
    t.c_iflag &= ~(tcflag_t)(IXON | ICRNL);
    t.c_cc[VMIN] = 0;
    t.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &t);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGHUP, sig_handler);
#endif
    g_active = 1;
    out_str("\x1b[?1049h\x1b[?25l\x1b[H\x1b[2J");
    out_flush();
    query_size();
    return 0;
}

void tui_shutdown(void) {
    if (!g_active) return;
    g_active = 0;
    if (g_cleanup_hook) g_cleanup_hook();
    out_str("\x1b[0m\x1b]8;;\x1b\\\x1b[?25h\x1b[?1049l");
    out_flush();
#ifdef _WIN32
    SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), g_old_out_mode);
    SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), g_old_in_mode);
    SetConsoleOutputCP(g_old_cp);
    SetConsoleCP(g_old_incp);
#else
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_old_tio);
#endif
}

int tui_w(void) { return g_w; }
int tui_h(void) { return g_h; }

/* ------------------------------------------------------------------ drawing */
void tui_clear(void) {
    query_size();
    for (int i = 0; i < g_w * g_h; i++) g_grid[i] = (Cell){' ', C_DEF, C_DEF, 0, 0};
    g_nlinks = 0;
    g_cur_show = 0;
}

static void put_cell(int y, int x, unsigned cp, int fg, int bg, int attr, int link) {
    if (y < 0 || y >= g_h || x < 0 || x >= g_w) return;
    Cell *c = &g_grid[y * g_w + x];
    c->cp = cp;
    c->fg = (signed char)fg;
    c->bg = (signed char)bg;
    c->attr = (unsigned char)attr;
    c->link = (unsigned char)link;
}

static int draw(int y, int x, int maxw, int fg, int bg, int attr, const char *s, int link) {
    if (!s) s = "";
    if (maxw < 0 || x + maxw > g_w) maxw = g_w - x;
    int col = 0, cp;
    while (col < maxw && (cp = utf8_decode(&s)) >= 0) {
        put_cell(y, x + col, sanitize_cp(cp), fg, bg, attr, link);
        col++;
    }
    return col;
}

int tui_text(int y, int x, int maxw, int fg, int bg, int attr, const char *s) {
    return draw(y, x, maxw, fg, bg, attr, s, 0);
}

int tui_textf(int y, int x, int maxw, int fg, int bg, int attr, const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    return draw(y, x, maxw, fg, bg, attr, buf, 0);
}

void tui_fill(int y, int x, int w, int fg, int bg, unsigned cp) {
    for (int i = 0; i < w; i++) put_cell(y, x + i, cp, fg, bg, 0, 0);
}

int tui_link(int y, int x, int maxw, int fg, int bg, const char *text, const char *url) {
    int id = 0;
    if (url && *url && g_nlinks < MAX_LINKS - 1) {
        /* URLs are also sanitised: only printable ASCII is allowed inside the OSC sequence */
        char *dst = g_links[g_nlinks + 1];
        size_t n = 0;
        for (const char *p = url; *p && n < sizeof g_links[0] - 1; p++)
            if ((unsigned char)*p > 0x20 && (unsigned char)*p < 0x7F) dst[n++] = *p;
        dst[n] = 0;
        id = ++g_nlinks;
    }
    return draw(y, x, maxw, fg, bg, A_UNDER, text, id);
}

void tui_box(int y, int x, int h, int w, int fg, int bg, const char *title) {
    if (w < 2 || h < 2) return;
    put_cell(y, x, 0x250C, fg, bg, 0, 0);
    put_cell(y, x + w - 1, 0x2510, fg, bg, 0, 0);
    put_cell(y + h - 1, x, 0x2514, fg, bg, 0, 0);
    put_cell(y + h - 1, x + w - 1, 0x2518, fg, bg, 0, 0);
    for (int i = 1; i < w - 1; i++) {
        put_cell(y, x + i, 0x2500, fg, bg, 0, 0);
        put_cell(y + h - 1, x + i, 0x2500, fg, bg, 0, 0);
    }
    for (int j = 1; j < h - 1; j++) {
        put_cell(y + j, x, 0x2502, fg, bg, 0, 0);
        put_cell(y + j, x + w - 1, 0x2502, fg, bg, 0, 0);
        for (int i = 1; i < w - 1; i++) put_cell(y + j, x + i, ' ', fg, bg, 0, 0);
    }
    if (title && *title) {
        char t[256];
        snprintf(t, sizeof t, " %s ", title);
        draw(y, x + 2, w - 4, fg, bg, A_BOLD, t, 0);
    }
}

/* htop-style meter:  Label[|||||||||||        value] */
void tui_meter(int y, int x, int w, const char *label, double frac, int fg, const char *value) {
    int lw = tui_text(y, x, w, C_CYAN, C_DEF, A_BOLD, label);
    int inner = w - lw - 2;
    if (inner < 3) return;
    put_cell(y, x + lw, '[', C_WHITE, C_DEF, A_BOLD, 0);
    put_cell(y, x + lw + 1 + inner, ']', C_WHITE, C_DEF, A_BOLD, 0);
    if (frac < 0) frac = 0;
    if (frac > 1) frac = 1;
    int bars = (int)(frac * inner + 0.5);
    if (frac > 0 && bars == 0) bars = 1;
    int vw = value ? utf8_width(value) : 0;
    for (int i = 0; i < inner; i++)
        put_cell(y, x + lw + 1 + i, i < bars ? '|' : ' ', fg, C_DEF, A_BOLD, 0);
    if (value && vw + 1 < inner) {
        put_cell(y, x + lw + inner - vw, ' ', C_DEF, C_DEF, 0, 0);
        draw(y, x + lw + 1 + inner - vw, vw, C_GREY, C_DEF, A_BOLD, value, 0);
    }
}

void tui_cursor(int show, int y, int x) {
    g_cur_show = show;
    g_cur_y = y;
    g_cur_x = x;
}

static void sgr(int fg, int bg, int attr) {
    char b[64];
    int n = snprintf(b, sizeof b, "\x1b[0");
    if (attr & A_BOLD) n += snprintf(b + n, sizeof b - (size_t)n, ";1");
    if (attr & A_DIM) n += snprintf(b + n, sizeof b - (size_t)n, ";2");
    if (attr & A_UNDER) n += snprintf(b + n, sizeof b - (size_t)n, ";4");
    if (fg >= 0) n += snprintf(b + n, sizeof b - (size_t)n, ";%d", fg < 8 ? 30 + fg : 90 + fg - 8);
    if (bg >= 0) n += snprintf(b + n, sizeof b - (size_t)n, ";%d", bg < 8 ? 40 + bg : 100 + bg - 8);
    snprintf(b + n, sizeof b - (size_t)n, "m");
    out_str(b);
}

/* plain-text dump of the grid (used by --snapshot, e.g. for docs and checks) */
void tui_dump(FILE *f) {
    for (int y = 0; y < g_h; y++) {
        int last = g_w - 1;
        while (last >= 0 && g_grid[y * g_w + last].cp == ' ') last--;
        for (int x = 0; x <= last; x++) {
            char u[4];
            fwrite(u, 1, utf8_encode(g_grid[y * g_w + x].cp, u), f);
        }
        fputc('\n', f);
    }
}

void tui_present(void) {
    char tmp[64];
    if (!g_active) return;          /* snapshot / non-interactive mode */
    out_str("\x1b[?25l");
    for (int y = 0; y < g_h; y++) {
        snprintf(tmp, sizeof tmp, "\x1b[%d;1H", y + 1);
        out_str(tmp);
        int pfg = -2, pbg = -2, pat = -1, plink = 0;
        int lastx = (y == g_h - 1) ? g_w - 1 : g_w;   /* never write the bottom-right cell (scroll) */
        for (int x = 0; x < lastx; x++) {
            Cell *c = &g_grid[y * g_w + x];
            if (c->link != plink) {
                if (c->link) {
                    out_str("\x1b]8;;");
                    out_str(g_links[c->link]);
                    out_str("\x1b\\");
                } else {
                    out_str("\x1b]8;;\x1b\\");
                }
                plink = c->link;
            }
            if (c->fg != pfg || c->bg != pbg || c->attr != pat) {
                sgr(c->fg, c->bg, c->attr);
                pfg = c->fg; pbg = c->bg; pat = c->attr;
            }
            char u[4];
            out_put(u, utf8_encode(c->cp, u));
        }
        if (plink) out_str("\x1b]8;;\x1b\\");
    }
    out_str("\x1b[0m");
    if (g_cur_show) {
        snprintf(tmp, sizeof tmp, "\x1b[%d;%dH\x1b[?25h", g_cur_y + 1, g_cur_x + 1);
        out_str(tmp);
    }
    out_flush();
}

/* ------------------------------------------------------------------ input */
static int inactive_key(int timeout_ms) {
#ifdef _WIN32
    Sleep(timeout_ms > 0 ? (DWORD)timeout_ms : 0);
#else
    usleep(timeout_ms > 0 ? (useconds_t)timeout_ms * 1000 : 0);
#endif
    return K_NONE;
}

#ifdef _WIN32
int tui_key(int timeout_ms) {
    if (!g_active) return inactive_key(timeout_ms);
    DWORD start = GetTickCount();
    for (;;) {
        if (_kbhit()) {
            wint_t c = _getwch();
            if (c == 0 || c == 0xE0) {
                wint_t k = _getwch();
                switch (k) {
                    case 72: return K_UP;    case 80: return K_DOWN;
                    case 75: return K_LEFT;  case 77: return K_RIGHT;
                    case 73: return K_PGUP;  case 81: return K_PGDN;
                    case 71: return K_HOME;  case 79: return K_END;   case 83: return K_DEL;
                    default:
                        if (k >= 59 && k <= 68) return K_F1 + (int)(k - 59);
                        return K_NONE;
                }
            }
            if (c == '\r' || c == '\n') return K_ENTER;
            if (c == 8 || c == 127) return K_BACKSPACE;
            if (c >= 0xD800 && c <= 0xDBFF) {          /* surrogate pair */
                wint_t lo = _getwch();
                return 0x10000 + (((int)c - 0xD800) << 10) + ((int)lo - 0xDC00);
            }
            return (int)c;
        }
        if (timeout_ms >= 0 && (int)(GetTickCount() - start) >= timeout_ms) return K_NONE;
        Sleep(10);
    }
}
#else
static int read_byte(int timeout_ms) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    int r = select(STDIN_FILENO + 1, &fds, NULL, NULL, timeout_ms < 0 ? NULL : &tv);
    if (r <= 0) return -1;
    unsigned char ch;
    if (read(STDIN_FILENO, &ch, 1) != 1) return -1;
    return ch;
}

int tui_key(int timeout_ms) {
    if (!g_active) return inactive_key(timeout_ms);
    int c = read_byte(timeout_ms);
    if (c < 0) return K_NONE;
    if (c == 27) {
        int c1 = read_byte(30);
        if (c1 < 0) return K_ESC;
        if (c1 == 'O') {
            int c2 = read_byte(30);
            if (c2 >= 'P' && c2 <= 'S') return K_F1 + (c2 - 'P');
            if (c2 == 'H') return K_HOME;
            if (c2 == 'F') return K_END;
            return K_NONE;
        }
        if (c1 != '[') return K_ESC;
        char seq[16];
        int n = 0, ch;
        while (n < 15 && (ch = read_byte(30)) >= 0) {
            seq[n++] = (char)ch;
            if ((ch >= 'A' && ch <= 'Z') || ch == '~') break;
        }
        seq[n] = 0;
        if (n == 1) {
            switch (seq[0]) {
                case 'A': return K_UP; case 'B': return K_DOWN; case 'C': return K_RIGHT;
                case 'D': return K_LEFT; case 'H': return K_HOME; case 'F': return K_END;
            }
            return K_NONE;
        }
        int num = atoi(seq);
        switch (num) {
            case 1: case 7: return K_HOME; case 4: case 8: return K_END;
            case 3: return K_DEL; case 5: return K_PGUP; case 6: return K_PGDN;
            case 11: return K_F1; case 12: return K_F2; case 13: return K_F3; case 14: return K_F4;
            case 15: return K_F5; case 17: return K_F6; case 18: return K_F7; case 19: return K_F8;
            case 20: return K_F9; case 21: return K_F10;
        }
        return K_NONE;
    }
    if (c == '\r' || c == '\n') return K_ENTER;
    if (c == 127 || c == 8) return K_BACKSPACE;
    if (c >= 0x80) {                               /* UTF-8 multi-byte */
        char buf[5] = {(char)c, 0, 0, 0, 0};
        int need = (c & 0xE0) == 0xC0 ? 1 : (c & 0xF0) == 0xE0 ? 2 : (c & 0xF8) == 0xF0 ? 3 : 0;
        for (int i = 1; i <= need; i++) {
            int b = read_byte(30);
            if (b < 0) return '?';
            buf[i] = (char)b;
        }
        const char *p = buf;
        return utf8_decode(&p);
    }
    return c;
}
#endif

/* ------------------------------------------------------------------ word wrap */
int tui_wrap(const char *text, int width, char lines[][512], int max_lines) {
    int n = 0;
    if (width < 4) width = 4;
    if (width > 500) width = 500;
    const char *p = text ? text : "";
    while (*p && n < max_lines) {
        /* take up to `width` codepoints, break at last space */
        const char *start = p, *q = p, *last_space = NULL;
        int cols = 0;
        while (*q && cols < width) {
            if (*q == '\n') break;
            if (*q == ' ') last_space = q;
            utf8_decode(&q);
            cols++;
        }
        const char *end = q;
        if (*q && *q != '\n' && cols >= width && last_space && last_space > start) end = last_space;
        size_t len = (size_t)(end - start);
        if (len > 511) len = 511;
        memcpy(lines[n], start, len);
        lines[n][len] = 0;
        n++;
        p = end;
        while (*p == ' ' || *p == '\n') p++;
    }
    return n;
}
