/* screens.c - all interactive screens of pmtui. */
#include "app.h"
#include "tui.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIN_W 80
#define MIN_H 24

int g_snapshot_mode;   /* render one frame and return (pmtui --snapshot) */

/* ================================================================== art */
static const char *const BANNER_BIG[] = {
    "██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗███╗   ███╗███████╗██████╗ ██╗ ██████╗",
    "██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝████╗ ████║██╔════╝██╔══██╗██║██╔════╝",
    "██████╔╝███████║██║     █████╔╝ █████╗     ██║   ██╔████╔██║█████╗  ██║  ██║██║██║     ",
    "██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║   ██║╚██╔╝██║██╔══╝  ██║  ██║██║██║     ",
    "██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║   ██║ ╚═╝ ██║███████╗██████╔╝██║╚██████╗",
    "╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝     ╚═╝╚══════╝╚═════╝ ╚═╝ ╚═════╝",
};
static const char *const BANNER_SMALL[] = {
    " ___         _       _   __  __        _ _    ",
    "| _ \\__ _ __| |_____| |_|  \\/  |___ __| (_)__ ",
    "|  _/ _` / _| / / -_)  _| |\\/| / -_) _` | / _|",
    "|_| \\__,_\\__|_\\_\\___|\\__|_|  |_\\___\\__,_|_\\__|",
};
static const int BANNER_COLORS[] = {C_BCYAN, C_BCYAN, C_CYAN, C_BBLUE, C_BLUE, C_BLUE};
static const char *const SPIN[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
/* one heartbeat of an ECG trace - scrolls across the screen */
static const char *const ECG = "──────────────────╭╮────╱╲  ╱──────────────────────────────╭╮──╱╲ ╱────────";

/* ================================================================== chrome */
static void header(App *a, const char *context) {
    int w = tui_w();
    tui_fill(0, 0, w, C_BWHITE, C_BLUE, ' ');
    int x = tui_text(0, 1, -1, C_BRED, C_BLUE, A_BOLD, "♥");
    x += 2;
    x += tui_text(0, x, -1, C_BWHITE, C_BLUE, A_BOLD, "PacketMedic v" PM_VERSION);
    if (context && *context) {
        x += tui_text(0, x + 1, -1, C_BWHITE, C_BLUE, 0, "│") + 2;
        tui_text(0, x, w - x - 26, C_BWHITE, C_BLUE, 0, context);
    }
    const char *r = a->eng.ready ? "engine ready · offline" : "engine not ready";
    tui_text(0, w - utf8_width(r) - 2, -1, a->eng.ready ? C_BGREEN : C_BYELLOW, C_BLUE, A_BOLD, r);
}

/* htop-style function key bar: key in white-on-black, label black-on-cyan */
static void fkeys(const char *const *pairs, int n) {
    int y = tui_h() - 1, x = 0, w = tui_w();
    tui_fill(y, 0, w, C_BLACK, C_CYAN, ' ');
    for (int i = 0; i + 1 < n * 2 && x < w; i += 2) {
        x += tui_text(y, x, -1, C_BWHITE, C_BLACK, A_BOLD, pairs[i]);
        x += tui_text(y, x, -1, C_BLACK, C_CYAN, 0, pairs[i + 1]) + 2;
    }
}

static void ecg(int y, int x, int w, unsigned long tick, int fg) {
    int n = utf8_width(ECG);
    for (int i = 0; i < w; i++) {
        int idx = (int)((i + tick) % (unsigned long)n);
        const char *p = ECG;
        int cp = 0;
        for (int k = 0; k <= idx; k++) cp = utf8_decode(&p);
        char u[5] = {0};
        utf8_encode((unsigned)cp, u);
        tui_text(y, x + i, 1, fg, C_DEF, A_BOLD, u);
    }
}

static int too_small(App *a) {
    if (tui_w() >= MIN_W && tui_h() >= MIN_H) return 0;
    header(a, "");
    tui_text(2, 1, -1, C_BYELLOW, C_DEF, A_BOLD, "Please enlarge the terminal window");
    tui_textf(3, 1, -1, C_DEF, C_DEF, 0, "Need at least %dx%d, now %dx%d.", MIN_W, MIN_H, tui_w(), tui_h());
    tui_text(4, 1, -1, C_GREY, C_DEF, 0, "Press q to quit.");
    return 1;
}

static void set_status(App *a, int fg, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void set_status(App *a, int fg, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(a->status, sizeof a->status, fmt, ap);
    va_end(ap);
    a->status_fg = fg;
    a->status_until = now_ms() + 6000;
}

static void hrule(int y, int x, int w, int fg, const char *title) {
    tui_fill(y, x, w, fg, C_DEF, 0x2500);
    if (title && *title) {
        char t[300];
        snprintf(t, sizeof t, " %s ", title);
        tui_text(y, x + 2, w - 4, C_BWHITE, C_DEF, A_BOLD, t);
    }
}

void screen_message(App *a, const char *title, const char *text, int fg) {
    char lines[24][512];
    for (;;) {
        tui_clear();
        header(a, title);
        int w = tui_w(), h = tui_h();
        int bw = w > 90 ? 84 : w - 4;
        int n = tui_wrap(text, bw - 6, lines, 20);
        int bh = n + 5, by = (h - bh) / 2, bx = (w - bw) / 2;
        tui_box(by, bx, bh, bw, fg, C_DEF, title);
        for (int i = 0; i < n; i++) tui_text(by + 2 + i, bx + 3, bw - 6, C_DEF, C_DEF, 0, lines[i]);
        tui_text(by + bh - 2, bx + 3, -1, C_GREY, C_DEF, 0, "Press any key to continue");
        const char *k[] = {"Enter", "OK"};
        fkeys(k, 1);
        tui_present();
        if (g_snapshot_mode) return;
        int key = tui_key(250);
        if (key != K_NONE) return;
    }
}

#define TEAM_NAME "Docker Duo"

/* "━━  by Team Docker Duo  ━━" centred under the banner */
static void team_line(int y, int w) {
    const char *pre = "━━━  by Team ", *post = "  ━━━";
    int tw = utf8_width(pre) + utf8_width(TEAM_NAME) + utf8_width(post);
    int x = (w - tw) / 2;
    if (x < 1) x = 1;
    x += tui_text(y, x, -1, C_BLUE, C_DEF, A_BOLD, "━━━  ");
    x += tui_text(y, x, -1, C_GREY, C_DEF, 0, "by Team ");
    x += tui_text(y, x, -1, C_BMAGENTA, C_DEF, A_BOLD, TEAM_NAME);
    tui_text(y, x, -1, C_BLUE, C_DEF, A_BOLD, post);
}

/* ================================================================== splash */
int screen_splash(App *a) {
    tui_clear();
    header(a, "starting");
    int w = tui_w(), h = tui_h();
    int big = w >= 92;
    int rows = big ? 6 : 4;
    int bw = utf8_width(big ? BANNER_BIG[0] : BANNER_SMALL[0]);
    int y = h / 2 - rows;
    for (int i = 0; i < rows; i++)
        tui_text(y + i, (w - bw) / 2, -1, BANNER_COLORS[i], C_DEF, A_BOLD, big ? BANNER_BIG[i] : BANNER_SMALL[i]);
    team_line(y + rows + 1, w);
    tui_text(y + rows + 3, (w - 30) / 2, -1, C_GREY, C_DEF, 0, "Checking the analysis engine…");
    tui_present();
    return engine_check(&a->eng);
}

/* ================================================================== main menu */
static const char *const MENU_TITLES[3] = {
    "Analyse a bundled sample capture",
    "Analyse my own capture file",
    "Capture live traffic from this machine",
};
static const char *const MENU_DESC[3] = {
    "15 labelled scenarios, each with a description",
    "Type or paste the path to any .pcap / .pcapng",
    "Record 5-300 s passively, then diagnose it",
};

/* "C:\very\long\path" -> "…\long\path" so the end (the useful part) stays visible */
static const char *tail_fit(const char *s, int width) {
    int w = utf8_width(s);
    while (w > width) { utf8_decode(&s); w--; }
    return s;
}

int screen_menu(App *a) {
    static int sel = 0;
    for (;;) {
        a->tick++;
        tui_clear();
        if (too_small(a)) {
            tui_present();
            int k = tui_key(200);
            if (k == 'q' || k == K_F10) return NEXT_QUIT;
            continue;
        }
        header(a, "main menu");
        int w = tui_w(), h = tui_h();
        int big = w >= 92 && h >= 30;
        int rows = big ? 6 : 4;
        int bw = utf8_width(big ? BANNER_BIG[0] : BANNER_SMALL[0]);
        int content_h = rows + 17;
        int y = h - 2 > content_h ? 1 + (h - 2 - content_h) / 2 : 2;
        for (int i = 0; i < rows; i++)
            tui_text(y + i, (w - bw) / 2, -1, BANNER_COLORS[i], C_DEF, A_BOLD, big ? BANNER_BIG[i] : BANNER_SMALL[i]);
        y += rows;
        ecg(y, (w - bw) / 2, bw, a->tick, C_BGREEN);
        y += 1;
        team_line(y, w);
        y += 1;
        const char *tag = w >= 100
            ? "Finds the faults and attacks hidden in packet captures, and explains them in plain language."
            : "Faults vs attacks in packet captures, explained in plain language.";
        int tx = (w - utf8_width(tag)) / 2;
        tui_text(y + 1, tx > 1 ? tx : 1, w - 2, C_GREY, C_DEF, 0, tag);
        y += 3;

        /* left: options */
        int lw = w >= 110 ? 66 : w - 4 - 38;
        if (lw < 40) lw = w - 4;
        for (int i = 0; i < 3; i++) {
            int oy = y + i * 3;
            int on = i == sel;
            int bg = on ? C_CYAN : C_DEF;
            tui_fill(oy, 2, lw, C_DEF, bg, ' ');
            tui_fill(oy + 1, 2, lw, C_DEF, bg, ' ');
            tui_textf(oy, 3, lw - 2, on ? C_BLACK : C_BYELLOW, bg, A_BOLD, " [%d]  %s %s", i + 1, on ? "▶" : " ",
                      MENU_TITLES[i]);
            tui_text(oy + 1, 12, lw - 11, on ? C_BLACK : C_GREY, bg, 0, MENU_DESC[i]);
        }

        /* right: system panel */
        int px = 2 + lw + 2, pw = w - px - 2;
        if (pw >= 34) {
            tui_box(y - 1, px, 10, pw, C_BLUE, C_DEF, "System");
            int iy = y, ix = px + 2, iw = pw - 4;
            char v[160];
            snprintf(v, sizeof v, "python %s", a->eng.py_version);
            tui_meter(iy++, ix, iw, "Engine  ", a->eng.ready ? 1.0 : 0.1, a->eng.ready ? C_BGREEN : C_BRED,
                      a->eng.ready ? v : "NOT READY");
            int ns = (int)json_len(json_root(a->catalog));
            snprintf(v, sizeof v, "%d captures", ns);
            tui_meter(iy++, ix, iw, "Samples ", ns ? 1.0 : 0.0, C_BGREEN, v);
            int cap_ok = a->cap.backend != CAP_NONE && (!a->cap.needs_admin || a->cap.have_admin);
            snprintf(v, sizeof v, "%s%s", a->cap.backend == CAP_NONE ? "none" : a->cap.name,
                     cap_ok ? "" : a->cap.backend == CAP_NONE ? "" : " · admin needed");
            tui_meter(iy++, ix, iw, "Capture ", cap_ok ? 1.0 : 0.25, cap_ok ? C_BGREEN : C_BYELLOW, v);
            int web = a->web.proc.running;
            tui_meter(iy++, ix, iw, "Web UI  ", web ? 1.0 : 0.0, C_BGREEN, web ? a->web.url : "stopped");
            iy++;
            tui_text(iy++, ix, iw, C_GREY, C_DEF, 0, "Reports are saved to:");
            tui_text(iy++, ix, iw, C_DEF, C_DEF, 0, tail_fit(a->eng.reports, iw));
            tui_text(iy++, ix, iw, C_GREY, C_DEF, 0, "No data leaves this machine.");
        }

        int fy = y + 10;
        if (fy < h - 2) {
            int x = 3;
            x += tui_text(fy, x, -1, C_GREY, C_DEF, 0, "Verdicts:  ");
            x += tui_text(fy, x, -1, C_BRED, C_DEF, A_BOLD, "ATTACK");
            x += tui_text(fy, x, -1, C_GREY, C_DEF, 0, " malicious activity   ");
            x += tui_text(fy, x, -1, C_BYELLOW, C_DEF, A_BOLD, "SUSPICIOUS");
            x += tui_text(fy, x, -1, C_GREY, C_DEF, 0, " worth a look   ");
            x += tui_text(fy, x, -1, C_BBLUE, C_DEF, A_BOLD, "FAULT");
            tui_text(fy, x, w - x - 1, C_GREY, C_DEF, 0, " outage / misconfiguration");
        }
        const char *k[] = {"1-3", "Choose", "↑↓", "Move", "Enter", "Open", "F10", "Quit"};
        fkeys(k, 4);
        tui_present();
        if (g_snapshot_mode) return NEXT_QUIT;

        int key = tui_key(90);
        switch (key) {
            case K_UP: sel = (sel + 2) % 3; break;
            case K_DOWN: case K_TAB: sel = (sel + 1) % 3; break;
            case '1': sel = 0; return NEXT_SAMPLES;
            case '2': sel = 1; return NEXT_PATH;
            case '3': sel = 2; return NEXT_LIVE;
            case K_ENTER: return sel == 0 ? NEXT_SAMPLES : sel == 1 ? NEXT_PATH : NEXT_LIVE;
            case 'q': case 'Q': case K_F10: case K_ESC: return NEXT_QUIT;
            default: break;
        }
    }
}

/* ================================================================== samples */
static void human_size(long long n, char *out, size_t len) {
    if (n < 0) snprintf(out, len, "-");
    else if (n < 1024) snprintf(out, len, "%lldB", n);
    else if (n < 1024 * 1024) snprintf(out, len, "%.0fK", n / 1024.0);
    else snprintf(out, len, "%.1fM", n / 1048576.0);
}

static int expected_color(const char *e) {
    if (strstr(e, "ATTACK")) return C_BRED;
    if (strstr(e, "FAULT")) return C_BBLUE;
    if (strstr(e, "Reject")) return C_BMAGENTA;
    return C_BGREEN;
}

int screen_samples(App *a, char *out, size_t outlen) {
    static int sel = 0, top = 0;
    JVal *cat = json_root(a->catalog);
    int n = (int)json_len(cat);
    if (!n) {
        screen_message(a, "No samples", "samples/catalog.json is missing. Run: python samples/generate.py", C_YELLOW);
        return 0;
    }
    char lines[12][512];
    for (;;) {
        tui_clear();
        if (too_small(a)) { tui_present(); if (tui_key(200) == 'q') return 0; continue; }
        header(a, "bundled samples · synthetic, labelled captures");
        int w = tui_w(), h = tui_h();
        int list_h = h - 13;
        if (list_h > n) list_h = n;
        if (sel < top) top = sel;
        if (sel >= top + list_h) top = sel - list_h + 1;

        int y = 2;
        tui_fill(y, 0, w, C_BLACK, C_GREEN, ' ');
        tui_textf(y, 0, w, C_BLACK, C_GREEN, A_BOLD, "  %-3s %-38s %6s   %s", "#", "FILE", "SIZE", "EXPECTED RESULT");
        for (int i = 0; i < list_h; i++) {
            int idx = top + i;
            JVal *s = json_at(cat, (size_t)idx);
            const char *file = json_gets(s, "file", "?");
            const char *exp = json_gets(s, "expected", "");
            char path[PM_PATH], sz[16];
            path_join(path, sizeof path, a->eng.samples, file);
            human_size(file_size(path), sz, sizeof sz);
            int on = idx == sel, row = y + 1 + i;
            int bg = on ? C_CYAN : C_DEF;
            tui_fill(row, 0, w, C_DEF, bg, ' ');
            tui_textf(row, 0, 52, on ? C_BLACK : C_DEF, bg, on ? A_BOLD : 0, "  %-3d %-38.38s %6s", idx + 1, file, sz);
            tui_text(row, 53, w - 54, on ? C_BLACK : expected_color(exp), bg, A_BOLD, exp);
        }
        /* detail panel */
        JVal *s = json_at(cat, (size_t)sel);
        int py = y + list_h + 2, ph = h - py - 1;
        tui_box(py, 1, ph, w - 2, C_BLUE, C_DEF, json_gets(s, "title", ""));
        int nl = tui_wrap(json_gets(s, "description", ""), w - 8, lines, 8);
        for (int i = 0; i < nl && i < ph - 4; i++) tui_text(py + 1 + i, 4, w - 8, C_DEF, C_DEF, 0, lines[i]);
        tui_text(py + ph - 2, 4, -1, C_GREY, C_DEF, 0, "Expected: ");
        tui_text(py + ph - 2, 14, w - 18, expected_color(json_gets(s, "expected", "")), C_DEF, A_BOLD,
                 json_gets(s, "expected", ""));
        const char *k[] = {"↑↓", "Select", "Enter", "Analyse", "Esc", "Back", "F10", "Quit"};
        fkeys(k, 4);
        tui_present();
        if (g_snapshot_mode) return 0;

        int key = tui_key(250);
        switch (key) {
            case K_UP: if (sel > 0) sel--; break;
            case K_DOWN: if (sel < n - 1) sel++; break;
            case K_PGUP: sel = sel > list_h ? sel - list_h : 0; break;
            case K_PGDN: sel = sel + list_h < n ? sel + list_h : n - 1; break;
            case K_HOME: sel = 0; break;
            case K_END: sel = n - 1; break;
            case K_ENTER:
                path_join(out, outlen, a->eng.samples, json_gets(json_at(cat, (size_t)sel), "file", ""));
                return 1;
            case K_ESC: case K_F9: case 'b': return 0;
            case K_F10: case 'q': return -1;
            default: break;
        }
    }
}

/* ================================================================== path input */
int screen_path(App *a, char *out, size_t outlen) {
    char buf[PM_PATH] = "";
    char err[300] = "";
    size_t len = 0;
    for (;;) {
        tui_clear();
        if (too_small(a)) { tui_present(); if (tui_key(200) == K_ESC) return 0; continue; }
        header(a, "analyse my own capture");
        int w = tui_w(), h = tui_h();
        int bw = w - 8, bx = 4, by = h / 2 - 7;
        tui_box(by, bx, 13, bw, C_BLUE, C_DEF, "Path to a .pcap / .pcapng file");
        tui_text(by + 2, bx + 3, -1, C_DEF, C_DEF, 0, "Type or paste the full path, then press Enter:");
        int fw = bw - 6;
        tui_fill(by + 4, bx + 3, fw, C_BWHITE, C_BLACK, ' ');
        int bwid = utf8_width(buf);
        const char *show = buf;
        while (bwid > fw - 2) { utf8_decode(&show); bwid--; }   /* keep the end visible */
        tui_text(by + 4, bx + 4, fw - 2, C_BWHITE, C_BLACK, A_BOLD, show);
        tui_cursor(1, by + 4, bx + 4 + utf8_width(show));
        if (err[0]) tui_text(by + 6, bx + 3, bw - 6, C_BRED, C_DEF, A_BOLD, err);
        tui_text(by + 8, bx + 3, bw - 6, C_GREY, C_DEF, 0,
                 "Tip (Windows): Shift + right-click the file in Explorer → 'Copy as path', then paste here.");
        tui_text(by + 9, bx + 3, bw - 6, C_GREY, C_DEF, 0,
                 "The file is checked first (exists, ≤ 512 MB, real pcap/pcapng signature) and is analysed locally.");
        tui_text(by + 10, bx + 3, bw - 6, C_GREY, C_DEF, 0,
                 "Only analyse captures from networks you own or are authorised to monitor.");
        const char *k[] = {"Enter", "Analyse", "Esc", "Back", "Bksp", "Delete"};
        fkeys(k, 3);
        tui_present();

        int key = tui_key(-1);
        if (key == K_ESC) return 0;
        if (key == K_ENTER) {
            char clean[PM_PATH];
            clean_user_path(buf, clean, sizeof clean);
            if (validate_capture_file(clean, err, sizeof err) == 0) {
                snprintf(out, outlen, "%s", clean);
                return 1;
            }
            continue;
        }
        if (key == K_BACKSPACE) {
            while (len > 0) {               /* drop one whole UTF-8 codepoint */
                len--;
                if (((unsigned char)buf[len] & 0xC0) != 0x80) break;
            }
            buf[len] = 0;
            err[0] = 0;
            continue;
        }
        if (key >= 0x20 && key < 0x110000) {
            char u[4];
            size_t n = utf8_encode((unsigned)key, u);
            if (len + n < sizeof buf - 1) {
                memcpy(buf + len, u, n);
                len += n;
                buf[len] = 0;
            }
            err[0] = 0;
        }
    }
}

/* ================================================================== live capture */
int screen_live(App *a, char *out, size_t outlen) {
    static int secs = 30;                  /* remembered between captures */
    char dbuf[8];
    snprintf(dbuf, sizeof dbuf, "%d", secs);
    size_t dlen = strlen(dbuf);
    char derr[160] = "";
    capture_detect(&a->cap);
    int usable = a->cap.backend != CAP_NONE && (!a->cap.needs_admin || a->cap.have_admin);
    if (g_snapshot_mode) usable = 1;      /* render the duration UI for --snapshot live */
    char lines[10][512];
    /* phase 1: consent + duration */
    for (;;) {
        tui_clear();
        if (too_small(a)) { tui_present(); if (tui_key(200) == K_ESC) return 0; continue; }
        header(a, "live capture");
        int w = tui_w(), h = tui_h();
        int bw = w - 8, bx = 4, by = 3;
        tui_box(by, bx, 9, bw, C_YELLOW, C_DEF, "Before you capture");
        int n = tui_wrap("Only capture traffic on networks you own or are explicitly authorised to monitor. "
                         "PacketMedic captures passively: it records this machine's traffic and sends nothing. "
                         "The capture is saved locally in captures/ and never uploaded.", bw - 6, lines, 5);
        for (int i = 0; i < n; i++) tui_text(by + 2 + i, bx + 3, bw - 6, C_DEF, C_DEF, 0, lines[i]);

        int y = by + 10;
        tui_textf(y, bx, -1, C_CYAN, C_DEF, A_BOLD, "Capture backend: ");
        tui_text(y, bx + 17, -1, a->cap.backend == CAP_NONE ? C_BRED : C_BWHITE, C_DEF, A_BOLD,
                 a->cap.backend == CAP_NONE ? "none found" : a->cap.name);
        tui_textf(y + 1, bx, -1, C_CYAN, C_DEF, A_BOLD, "Privileges:      ");
        tui_text(y + 1, bx + 17, -1, a->cap.have_admin ? C_BGREEN : (a->cap.needs_admin ? C_BYELLOW : C_DEF), C_DEF,
                 A_BOLD, a->cap.have_admin ? "administrator" : "standard user");
        if (!usable) {
            n = tui_wrap(a->cap.hint, bw - 6, lines, 5);
            tui_box(y + 3, bx, n + 2, bw, C_RED, C_DEF, "Can't capture yet");
            for (int i = 0; i < n; i++) tui_text(y + 4 + i, bx + 3, bw - 6, C_BYELLOW, C_DEF, 0, lines[i]);
            const char *k[] = {"Esc", "Back"};
            fkeys(k, 1);
        } else {
            /* duration: typed by the user, clamped to [CAP_MIN_SECONDS, CAP_MAX_SECONDS] */
            tui_text(y + 3, bx, -1, C_CYAN, C_DEF, A_BOLD, "Listen for:");
            tui_fill(y + 3, bx + 12, 7, C_BWHITE, C_BLACK, ' ');
            tui_text(y + 3, bx + 13, 5, C_BWHITE, C_BLACK, A_BOLD, dbuf);
            tui_cursor(1, y + 3, bx + 13 + (int)dlen);
            tui_textf(y + 3, bx + 20, -1, C_DEF, C_DEF, 0, "seconds   (min %d s, max %d s = %d min)",
                      CAP_MIN_SECONDS, CAP_MAX_SECONDS, CAP_MAX_SECONDS / 60);
            int v = atoi(dbuf);
            double frac = (double)(v < CAP_MIN_SECONDS ? 0 : v > CAP_MAX_SECONDS ? CAP_MAX_SECONDS : v) / CAP_MAX_SECONDS;
            char vv[32];
            snprintf(vv, sizeof vv, "%d s", v);
            tui_meter(y + 4, bx, bw > 70 ? 70 : bw, "           ", frac,
                      (v >= CAP_MIN_SECONDS && v <= CAP_MAX_SECONDS) ? C_BGREEN : C_BRED, vv);
            if (derr[0]) tui_text(y + 5, bx, bw, C_BRED, C_DEF, A_BOLD, derr);
            tui_textf(y + 6, bx, bw, C_GREY, C_DEF, 0,
                      "Type the seconds, or adjust with ←/→ (±5 s) and ↑/↓ (±30 s). Auto-stops at %d MB.",
                      (int)(CAP_MAX_BYTES / (1024 * 1024)));
            tui_text(y + 8, bx, bw, C_BWHITE, C_DEF, A_BOLD, "Press Y to confirm you are authorised and start capturing.");
            const char *k[] = {"0-9", "Seconds", "←→↑↓", "Adjust", "Y", "Start", "Esc", "Back"};
            fkeys(k, 4);
        }
        (void)h;
        tui_present();
        if (g_snapshot_mode) return 0;
        int key = tui_key(-1);
        if (key == K_ESC || key == K_F9) return 0;
        if (!usable) continue;
        int cur = atoi(dbuf), delta = 0;
        if (key == K_LEFT) delta = -5;
        else if (key == K_RIGHT) delta = 5;
        else if (key == K_DOWN) delta = -30;
        else if (key == K_UP) delta = 30;
        if (delta) {
            cur += delta;
            if (cur < CAP_MIN_SECONDS) cur = CAP_MIN_SECONDS;
            if (cur > CAP_MAX_SECONDS) cur = CAP_MAX_SECONDS;
            snprintf(dbuf, sizeof dbuf, "%d", cur);
            dlen = strlen(dbuf);
            derr[0] = 0;
        } else if (key >= '0' && key <= '9') {
            if (dlen < 4) { dbuf[dlen++] = (char)key; dbuf[dlen] = 0; }
            derr[0] = 0;
        } else if (key == K_BACKSPACE) {
            if (dlen) dbuf[--dlen] = 0;
            derr[0] = 0;
        } else if (key == 'y' || key == 'Y' || key == K_ENTER) {
            int v = atoi(dbuf);
            if (!dlen || v < CAP_MIN_SECONDS || v > CAP_MAX_SECONDS) {
                snprintf(derr, sizeof derr, "Please choose between %d and %d seconds.", CAP_MIN_SECONDS, CAP_MAX_SECONDS);
                continue;
            }
            if (key == K_ENTER) {
                snprintf(derr, sizeof derr, "Press Y to confirm you are authorised to capture on this network.");
                continue;
            }
            secs = v;
            break;
        }
    }

    char err[600] = "";
    if (capture_start(&a->live, &a->cap, a->eng.captures, secs, err, sizeof err) != 0) {
        screen_message(a, "Capture failed", err, C_RED);
        return 0;
    }
    /* phase 2: progress */
    int stopped_early = 0, size_capped = 0;
    for (;;) {
        a->tick++;
        long el = now_ms() - a->live.started;
        double frac = el / (a->live.seconds * 1000.0);
        int done = frac >= 1.0;
        if (a->live.info.backend == CAP_DUMPCAP && !a->live.proc.running) done = 1;
        if (capture_bytes(&a->live) >= CAP_MAX_BYTES) { done = 1; size_capped = 1; }
        tui_clear();
        header(a, "live capture · recording");
        int w = tui_w(), h = tui_h();
        int y = h / 2 - 5;
        tui_text(y, 4, -1, C_BRED, C_DEF, A_BOLD, (a->tick / 5) % 2 ? "● REC" : "  REC");
        tui_textf(y, 12, -1, C_BWHITE, C_DEF, A_BOLD, "Capturing with %s", a->live.info.name);
        ecg(y + 2, 4, w - 8, a->tick, C_BGREEN);
        char v[64];
        snprintf(v, sizeof v, "%.0f / %d s", el / 1000.0, a->live.seconds);
        tui_meter(y + 4, 4, w - 8, "Time    ", frac, C_BGREEN, v);
        long long b = capture_bytes(&a->live);
        snprintf(v, sizeof v, "%.1f KB", b / 1024.0);
        tui_meter(y + 5, 4, w - 8, "Data    ", b > 0 ? 0.02 + (frac < 1 ? frac : 1) * 0.98 : 0, C_BCYAN, v);
        tui_text(y + 7, 4, w - 8, C_GREY, C_DEF, 0, a->live.out);
        tui_text(y + 9, 4, w - 8, C_GREY, C_DEF, 0,
                 "Tip: browse a few websites now so there is traffic to analyse.");
        const char *k[] = {"Enter", "Stop now & analyse", "Esc", "Cancel"};
        fkeys(k, 2);
        tui_present();
        (void)h;
        if (done) break;
        int key = tui_key(100);
        if (key == K_ESC) {
            capture_abort(&a->live);
            set_status(a, C_BYELLOW, "Capture cancelled.");
            return 0;
        }
        if (key == K_ENTER) { stopped_early = 1; break; }
    }
    (void)stopped_early;
    tui_clear();
    header(a, "live capture · finishing");
    tui_text(tui_h() / 2, 4, -1, C_BWHITE, C_DEF, A_BOLD, "Stopping capture and converting to pcapng…");
    tui_present();
    if (capture_finish(&a->live, err, sizeof err) != 0) {
        screen_message(a, "Capture failed", err, C_RED);
        return 0;
    }
    if (size_capped)
        set_status(a, C_BYELLOW, "Capture stopped early at the %d MB size limit.", (int)(CAP_MAX_BYTES / (1024 * 1024)));
    snprintf(out, outlen, "%s", a->live.out);
    return 1;
}

/* ================================================================== analysis */
int screen_analyse(App *a, const char *path) {
    Analysis an;
    char msg[1024] = "";
    if (analysis_start(&a->eng, &an, path) != 0) {
        screen_message(a, "Engine error", "Could not start the Python engine.", C_RED);
        return -1;
    }
    const char *b1 = strrchr(path, '/'), *b2 = strrchr(path, '\\');
    const char *base = b1 > b2 ? b1 + 1 : b2 ? b2 + 1 : path;
    int r;
    unsigned long t = 0;
    while ((r = analysis_poll(&an, msg, sizeof msg)) == 1) {
        t++;
        tui_clear();
        header(a, "analysing");
        int w = tui_w(), h = tui_h(), y = h / 2 - 4;
        tui_textf(y, 4, -1, C_BCYAN, C_DEF, A_BOLD, "%s  Analysing %s", SPIN[t % 10], base);
        tui_textf(y + 1, 7, -1, C_GREY, C_DEF, 0, "%.1f s elapsed", (now_ms() - an.started) / 1000.0);
        ecg(y + 3, 4, w - 8, t * 2, C_BGREEN);
        tui_text(y + 5, 7, w - 10, C_DEF, C_DEF, 0,
                 "safe ingest  →  protocol trackers  →  detectors  →  fault-vs-attack verdicts  →  explanations");
        tui_text(y + 7, 7, w - 10, C_GREY, C_DEF, 0, "Running locally with no network or AI calls.");
        const char *k[] = {"Esc", "Cancel"};
        fkeys(k, 1);
        tui_present();
        if (tui_key(80) == K_ESC) {
            analysis_cancel(&an);
            return -1;
        }
    }
    if (r == -1) {
        char text[1200];
        snprintf(text, sizeof text, "PacketMedic refused to analyse this file: %s", msg);
        screen_message(a, "File rejected", text, C_YELLOW);
        return -1;
    }
    if (r == -2) {
        char text[1200];
        snprintf(text, sizeof text, "The analysis engine failed. Last output: %.900s", msg);
        screen_message(a, "Engine error", text, C_RED);
        return -1;
    }
    char perr[256];
    JDoc *d = json_parse_file(an.json, perr, sizeof perr);
    if (!d) {
        screen_message(a, "Report error", perr, C_RED);
        return -1;
    }
    json_free(a->doc);
    a->doc = d;
    snprintf(a->capture, sizeof a->capture, "%s", an.capture);
    snprintf(a->html, sizeof a->html, "%s", an.html);
    snprintf(a->json, sizeof a->json, "%s", an.json);
    snprintf(a->analysed_name, sizeof a->analysed_name, "%s", base);
    return 0;
}

/* ================================================================== dashboard */
typedef struct { char text[512]; int fg, attr, indent; } DLine;
typedef struct { DLine *v; int n, cap; } DLines;

static void dl_add(DLines *d, const char *text, int fg, int attr, int indent, int width) {
    char wrapped[40][512];
    int n = tui_wrap(text, width - indent, wrapped, 40);
    if (n == 0) { n = 1; wrapped[0][0] = 0; }
    for (int i = 0; i < n; i++) {
        if (d->n == d->cap) {
            int cap = d->cap ? d->cap * 2 : 64;
            DLine *nv = realloc(d->v, sizeof(DLine) * (size_t)cap);
            if (!nv) return;
            d->v = nv;
            d->cap = cap;
        }
        DLine *l = &d->v[d->n++];
        snprintf(l->text, sizeof l->text, "%s", wrapped[i]);
        l->fg = fg;
        l->attr = attr;
        l->indent = indent + (i ? 2 : 0) * (indent > 0);
    }
}

static int verdict_color(const char *v) {
    if (!strcmp(v, "ATTACK")) return C_BRED;
    if (!strcmp(v, "SUSPICIOUS")) return C_BYELLOW;
    return C_BBLUE;
}

static void build_details(const JVal *inc, DLines *d, int width) {
    d->n = 0;
    char buf[2048];
    dl_add(d, json_gets(inc, "summary", ""), C_BWHITE, 0, 0, width);
    dl_add(d, "", C_DEF, 0, 0, width);
    snprintf(buf, sizeof buf, "Why it matters: %s", json_gets(inc, "why_it_matters", ""));
    dl_add(d, buf, C_DEF, 0, 0, width);
    snprintf(buf, sizeof buf, "Likely cause: %s", json_gets(inc, "likely_cause", ""));
    dl_add(d, buf, C_DEF, 0, 0, width);
    dl_add(d, "What to do next:", C_BCYAN, A_BOLD, 0, width);
    JVal *steps = json_get(inc, "next_steps");
    for (size_t i = 0; i < json_len(steps); i++) {
        snprintf(buf, sizeof buf, "• %s", json_str(json_at(steps, i), ""));
        dl_add(d, buf, C_DEF, 0, 2, width);
    }
    JVal *rs = json_get(inc, "reasoning");
    snprintf(buf, sizeof buf, "Fault or attack?  attack evidence %.1f  vs  fault evidence %.1f",
             json_getn(rs, "attack_score", 0), json_getn(rs, "fault_score", 0));
    dl_add(d, buf, C_BCYAN, A_BOLD, 0, width);
    JVal *pa = json_get(rs, "points_for_attack"), *pf = json_get(rs, "points_for_fault");
    for (size_t i = 0; i < json_len(pa); i++) {
        snprintf(buf, sizeof buf, "▲ %s", json_gets(json_at(pa, i), "text", ""));
        dl_add(d, buf, C_BRED, 0, 2, width);
    }
    for (size_t i = 0; i < json_len(pf); i++) {
        snprintf(buf, sizeof buf, "✓ %s", json_gets(json_at(pf, i), "text", ""));
        dl_add(d, buf, C_BGREEN, 0, 2, width);
    }
    JVal *sym = json_get(inc, "explains_symptoms");
    if (json_len(sym)) {
        size_t n = (size_t)snprintf(buf, sizeof buf, "Also explains: ");
        for (size_t i = 0; i < json_len(sym) && n < sizeof buf - 64; i++)
            n += (size_t)snprintf(buf + n, sizeof buf - n, "%s%s", i ? ", " : "", json_gets(json_at(sym, i), "kind", ""));
        dl_add(d, buf, C_BMAGENTA, 0, 0, width);
    }
    JVal *fr = json_get(inc, "evidence_frames");
    size_t n = (size_t)snprintf(buf, sizeof buf, "Evidence frames (%u): ", (unsigned)json_len(fr));
    for (size_t i = 0; i < json_len(fr) && i < 40 && n < sizeof buf - 16; i++)
        n += (size_t)snprintf(buf + n, sizeof buf - n, "%s%.0f", i ? ", " : "", json_num(json_at(fr, i), 0));
    if (json_len(fr) > 40) snprintf(buf + n, sizeof buf - n, " …");
    dl_add(d, buf, C_DEF, 0, 0, width);
    snprintf(buf, sizeof buf, "Wireshark filter: %s", json_gets(inc, "wireshark_filter", ""));
    dl_add(d, buf, C_BYELLOW, 0, 0, width);
}

static void open_html(App *a) {
    char url[PM_PATH * 3];
    file_url(a->html, url, sizeof url);
    if (proc_open_url(url) == 0) set_status(a, C_BGREEN, "Opened HTML report in your browser: %s", a->html);
    else set_status(a, C_BYELLOW, "Could not open a browser. Report file: %s", a->html);
}

static void launch_web(App *a, int (*redraw)(App *, int)) {
    if (a->web.proc.running && !strcmp(a->web.capture, a->capture) && web_ready(&a->web) == 1) {
        proc_open_url(a->web.url);
        set_status(a, C_BGREEN, "Web dashboard: %s (opened in browser)", a->web.url);
        return;
    }
    if (web_start(&a->eng, &a->web, a->capture) != 0) {
        set_status(a, C_BRED, "Could not start the web dashboard (no free port 8501-8520?).");
        return;
    }
    long start = now_ms();
    for (;;) {
        int r = web_ready(&a->web);
        if (r == 1) break;
        if (r == -1) {
            set_status(a, C_BRED, "Web dashboard exited. See %s", a->web.log);
            return;
        }
        if (now_ms() - start > 60000) {
            web_stop(&a->web);
            set_status(a, C_BRED, "Web dashboard did not start in time. See %s", a->web.log);
            return;
        }
        char s[128];
        snprintf(s, sizeof s, "%s Starting web dashboard on %s … %.0fs", SPIN[(now_ms() / 100) % 10],
                 a->web.url, (now_ms() - start) / 1000.0);
        set_status(a, C_BCYAN, "%s", s);
        redraw(a, 1);
        if (tui_key(150) == K_ESC) { web_stop(&a->web); set_status(a, C_BYELLOW, "Web dashboard cancelled."); return; }
    }
    proc_open_url(a->web.url);
    set_status(a, C_BGREEN, "Web dashboard running at %s (opened in browser)", a->web.url);
}

static void draw_help(App *a) {
    tui_clear();
    header(a, "help");
    int w = tui_w();
    tui_box(2, 2, 20, w - 4, C_BLUE, C_DEF, "Keys");
    const char *rows[][2] = {
        {"↑ / ↓", "select a finding"}, {"PgUp / PgDn", "scroll the details"},
        {"Enter", "expand / collapse the details view"}, {"F2  or  h", "open the HTML report in your browser"},
        {"F3  or  w", "start the Streamlit web dashboard and open it"},
        {"F5  or  e", "export each finding's evidence packets as .pcap files"},
        {"F9  or  Esc", "back to the main menu"}, {"F10 or  q", "quit (also stops the web dashboard)"},
    };
    for (int i = 0; i < 8; i++) {
        tui_text(4 + i, 5, -1, C_BYELLOW, C_DEF, A_BOLD, rows[i][0]);
        tui_text(4 + i, 20, w - 24, C_DEF, C_DEF, 0, rows[i][1]);
    }
    tui_text(13, 5, -1, C_BWHITE, C_DEF, A_BOLD, "Verdicts");
    tui_text(14, 5, -1, C_BRED, C_DEF, A_BOLD, "ATTACK    ");
    tui_text(14, 16, w - 20, C_DEF, C_DEF, 0, "strong evidence of malicious activity (scan, spoofing, hijack, rogue server)");
    tui_text(15, 5, -1, C_BYELLOW, C_DEF, A_BOLD, "SUSPICIOUS");
    tui_text(15, 16, w - 20, C_DEF, C_DEF, 0, "some attack indicators, but not conclusive - worth a look");
    tui_text(16, 5, -1, C_BBLUE, C_DEF, A_BOLD, "FAULT     ");
    tui_text(16, 16, w - 20, C_DEF, C_DEF, 0, "an outage or misconfiguration - no sign of an attacker");
    tui_text(18, 5, w - 10, C_GREY, C_DEF, 0,
             "Each finding lists the evidence for and against 'attack'. Frame numbers match Wireshark.");
    const char *k[] = {"any", "key to return"};
    fkeys(k, 1);
    tui_present();
    tui_key(-1);
}

/* dashboard state lives here so the web-launch spinner can redraw it */
static int g_sel, g_dscroll, g_full;
static DLines g_lines;

static int draw_dashboard(App *a, int present) {
    JVal *r = json_root(a->doc);
    JVal *incs = json_get(r, "incidents");
    int n = (int)json_len(incs);
    tui_clear();
    if (too_small(a)) { if (present) tui_present(); return n; }
    int w = tui_w(), h = tui_h();
    JVal *cap = json_get(r, "capture"), *health = json_get(r, "health"), *counts = json_get(r, "counts");
    char ctx[400];
    snprintf(ctx, sizeof ctx, "%s · analysed in %.2fs", a->analysed_name, json_getn(r, "analysis_seconds", 0));
    header(a, ctx);

    /* --- meters (htop CPU-bar style) --- */
    int score = (int)json_getn(health, "score", 0);
    const char *label = json_gets(health, "label", "");
    int hcol = !strcmp(label, "Under attack") ? C_BRED : score >= 90 ? C_BGREEN : score >= 60 ? C_BYELLOW : C_BRED;
    int mw = w / 2 - 2;
    char v[96];
    snprintf(v, sizeof v, "%d/100", score);
    tui_meter(1, 1, mw, "Health ", score / 100.0, hcol, v);
    int na = (int)json_getn(counts, "ATTACK", 0), ns = (int)json_getn(counts, "SUSPICIOUS", 0),
        nf = (int)json_getn(counts, "FAULT", 0);
    int tot = na + ns + nf ? na + ns + nf : 1;
    snprintf(v, sizeof v, "%d", na);
    tui_meter(2, 1, mw, "Attack ", (double)na / tot, C_BRED, v);
    snprintf(v, sizeof v, "%d", ns);
    tui_meter(3, 1, mw, "Suspic ", (double)ns / tot, C_BYELLOW, v);
    snprintf(v, sizeof v, "%d", nf);
    tui_meter(4, 1, mw, "Faults ", (double)nf / tot, C_BBLUE, v);

    int sx = w / 2 + 1;
    tui_text(1, sx, -1, C_DEF, C_DEF, 0, "Status: ");
    tui_text(1, sx + 8, w - sx - 9, hcol, C_DEF, A_BOLD, label);
    tui_textf(2, sx, w - sx - 1, C_DEF, C_DEF, 0, "Packets: %-9.0f  Duration: %.1f s", json_getn(cap, "packets", 0),
              json_getn(cap, "duration_s", 0));
    tui_textf(3, sx, w - sx - 1, C_DEF, C_DEF, 0, "Hosts:   %-9.0f  Format:   %s", json_getn(cap, "hosts_seen", 0),
              json_gets(json_get(r, "file"), "format", "?"));
    tui_textf(4, sx, w - sx - 1, C_DEF, C_DEF, 0, "Malformed skipped: %.0f", json_getn(cap, "malformed_skipped", 0));

    /* --- protocol meters --- */
    JVal *protos = json_get(cap, "protocols");
    double pk = json_getn(cap, "packets", 1);
    if (pk <= 0) pk = 1;
    int pcols = w >= 120 ? 4 : 3, pw = (w - 2) / pcols, np = (int)json_len(protos);
    for (int i = 0; i < np && i < pcols * 1; i++) {
        JVal *p = json_at(protos, (size_t)i);
        char lab[16], val[16];
        snprintf(lab, sizeof lab, "%-5.5s", p->key ? p->key : "?");
        snprintf(val, sizeof val, "%.0f%%", 100.0 * json_num(p, 0) / pk);
        tui_meter(5, 1 + i * pw, pw - 1, lab, json_num(p, 0) / pk, C_BGREEN, val);
    }
    int y = 6;
    JVal *warns = json_get(r, "warnings");
    if (json_len(warns)) {
        char wl[600];
        snprintf(wl, sizeof wl, "⚠ %s%s", json_str(json_at(warns, 0), ""),
                 json_len(warns) > 1 ? "  (+ more warnings)" : "");
        tui_text(y++, 1, w - 2, C_BYELLOW, C_DEF, 0, wl);
    }

    /* --- incident table --- */
    int list_h = 0;
    if (!g_full) {
        tui_fill(y, 0, w, C_BLACK, C_GREEN, ' ');
        int tlw = w >= 120 ? 30 : 18;
        tui_textf(y, 0, w, C_BLACK, C_GREEN, A_BOLD, " %-7s %-10s %-6s %-6s %-*s %s", "ID", "VERDICT", "SEV", "CONF",
                  tlw, "TIMELINE", "FINDING");
        y++;
        list_h = n < 7 ? n : 7;
        if (h - y < 12) list_h = h - y - 9 > 1 ? h - y - 9 : 1;
        if (list_h > n) list_h = n;
        int top = g_sel >= list_h ? g_sel - list_h + 1 : 0;
        double dur = json_getn(cap, "duration_s", 0);
        if (dur <= 0) dur = 1;
        for (int i = 0; i < list_h; i++) {
            int idx = top + i;
            JVal *inc = json_at(incs, (size_t)idx);
            const char *verdict = json_gets(inc, "verdict", "");
            int on = idx == g_sel, bg = on ? C_CYAN : C_DEF;
            tui_fill(y, 0, w, C_DEF, bg, ' ');
            tui_textf(y, 0, 9, on ? C_BLACK : C_BWHITE, bg, A_BOLD, " %-7s", json_gets(inc, "id", ""));
            tui_textf(y, 9, 10, on ? C_BLACK : verdict_color(verdict), bg, A_BOLD, "%-10s", verdict);
            tui_textf(y, 20, 14, on ? C_BLACK : C_DEF, bg, 0, "%-6s %-6s", json_gets(inc, "severity", ""),
                      json_gets(inc, "confidence", ""));
            double s0 = json_getn(inc, "start_offset_s", 0) / dur, s1 = json_getn(inc, "end_offset_s", 0) / dur;
            int b0 = (int)(s0 * tlw), b1 = (int)(s1 * tlw + 0.999);
            if (b1 <= b0) b1 = b0 + 1;
            for (int c = 0; c < tlw; c++) {
                int in = c >= b0 && c < b1;
                tui_text(y, 34 + c, 1, in ? verdict_color(verdict) : C_GREY, bg, A_BOLD, in ? "█" : "·");
            }
            tui_text(y, 35 + tlw, w - 36 - tlw, on ? C_BLACK : C_DEF, bg, on ? A_BOLD : 0, json_gets(inc, "title", ""));
            y++;
        }
        if (!n) {
            tui_text(y, 2, w - 4, C_BGREEN, C_DEF, A_BOLD, "✓ No faults or attacks found - this traffic looks healthy.");
            y++;
        }
    }

    /* --- detail pane --- */
    if (n) {
        JVal *inc = json_at(incs, (size_t)g_sel);
        char t[400];
        snprintf(t, sizeof t, "%s · %s · confidence %s · %s", json_gets(inc, "id", ""), json_gets(inc, "verdict", ""),
                 json_gets(inc, "confidence", ""), json_gets(inc, "title", ""));
        hrule(y, 0, w, verdict_color(json_gets(inc, "verdict", "")), t);
        y++;
        build_details(inc, &g_lines, w - 4);
        int avail = h - 3 - y;
        if (g_dscroll > g_lines.n - avail) g_dscroll = g_lines.n - avail;
        if (g_dscroll < 0) g_dscroll = 0;
        for (int i = 0; i < avail && g_dscroll + i < g_lines.n; i++) {
            DLine *l = &g_lines.v[g_dscroll + i];
            tui_text(y + i, 2 + l->indent, w - 4 - l->indent, l->fg, C_DEF, l->attr, l->text);
        }
        if (g_lines.n > avail)
            tui_textf(h - 3, w - 22, -1, C_GREY, C_DEF, 0, "lines %d-%d of %d", g_dscroll + 1,
                      g_dscroll + avail < g_lines.n ? g_dscroll + avail : g_lines.n, g_lines.n);
    }

    /* --- links / status line --- */
    int ly = h - 2;
    tui_fill(ly, 0, w, C_DEF, C_BLACK, ' ');
    if (a->status[0] && now_ms() < a->status_until) {
        tui_text(ly, 1, w - 2, a->status_fg, C_BLACK, A_BOLD, a->status);
    } else {
        char url[PM_PATH * 3];
        file_url(a->html, url, sizeof url);
        int x = tui_text(ly, 1, -1, C_BCYAN, C_BLACK, A_BOLD, "HTML ▸ ") + 1;
        const char *b1 = strrchr(a->html, '/'), *b2 = strrchr(a->html, '\\');
        const char *hb = b1 > b2 ? b1 + 1 : b2 ? b2 + 1 : a->html;
        char shown[300];
        snprintf(shown, sizeof shown, "reports/%s", hb);
        x += tui_link(ly, x, w / 2 - x, C_BWHITE, C_BLACK, shown, url) + 3;
        x += tui_text(ly, x, -1, C_BCYAN, C_BLACK, A_BOLD, "Web ▸ ");
        if (a->web.proc.running && !strcmp(a->web.capture, a->capture))
            tui_link(ly, x, w - x - 1, C_BGREEN, C_BLACK, a->web.url, a->web.url);
        else
            tui_text(ly, x, w - x - 1, C_GREY, C_BLACK, 0, "press F3 to launch the Streamlit dashboard");
    }
    const char *k[] = {"F1", "Help", "F2", "HTML", "F3", "Web", "F5", "Evidence", "Enter", g_full ? "Table" : "Expand",
                       "F9", "Menu", "F10", "Quit"};
    fkeys(k, 7);
    if (present) tui_present();
    return n;
}

static int redraw_cb(App *a, int present) { return draw_dashboard(a, present); }

int screen_dashboard(App *a) {
    g_sel = 0;
    g_dscroll = 0;
    g_full = 0;
    for (;;) {
        int n = draw_dashboard(a, 1);
        if (g_snapshot_mode) return NEXT_QUIT;
        int key = tui_key(250);
        int page = tui_h() / 3;
        switch (key) {
            case K_UP: if (g_sel > 0) { g_sel--; g_dscroll = 0; } break;
            case K_DOWN: if (g_sel < n - 1) { g_sel++; g_dscroll = 0; } break;
            case K_HOME: g_sel = 0; g_dscroll = 0; break;
            case K_END: g_sel = n ? n - 1 : 0; g_dscroll = 0; break;
            case K_PGDN: g_dscroll += page; break;
            case K_PGUP: g_dscroll -= page; break;
            case K_ENTER: g_full = !g_full; g_dscroll = 0; break;
            case K_F1: case '?': draw_help(a); break;
            case K_F2: case 'h': open_html(a); break;
            case K_F3: case 'w': launch_web(a, redraw_cb); break;
            case K_F5: case 'e': {
                if (!n) { set_status(a, C_BYELLOW, "Nothing to export - no findings."); break; }
                set_status(a, C_BCYAN, "Exporting evidence packets…");
                draw_dashboard(a, 1);
                char dir[PM_PATH], msg[512];
                if (evidence_export(&a->eng, a->capture, dir, sizeof dir, msg, sizeof msg) == 0)
                    set_status(a, C_BGREEN, "Evidence .pcap files (one per finding) saved in %s", dir);
                else
                    set_status(a, C_BRED, "Evidence export failed: %s", msg);
                break;
            }
            case K_F9: case K_ESC: case 'b': return NEXT_MENU;
            case K_F10: case 'q': case 'Q': return NEXT_QUIT;
            default: break;
        }
    }
}
