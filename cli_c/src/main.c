/* pmtui - PacketMedic terminal UI.
 *
 *   pmtui                 interactive menu
 *   pmtui <capture>       analyse a file and open the dashboard directly
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"
#include "tui.h"

static App g_app;

static void cleanup(void) {
    web_stop(&g_app.web);          /* never leave a web server running */
    capture_abort(&g_app.live);    /* never leave a capture running */
}

static void usage(void) {
    printf("PacketMedic TUI %s\n\n"
           "Usage:\n"
           "  pmtui              interactive menu (samples / your file / live capture)\n"
           "  pmtui <capture>    analyse a .pcap/.pcapng and open the dashboard\n"
           "  pmtui --help       this text\n\n"
           "Environment:\n"
           "  PACKETMEDIC_ROOT    path to the repository (if not run from inside it)\n"
           "  PACKETMEDIC_PYTHON  Python interpreter to use (default: .venv)\n",
           PM_VERSION);
}

/* pmtui --snapshot <menu|samples|dashboard> [capture] [WxH]
 * Renders one frame as plain text to stdout without touching the terminal. */
static int snapshot(App *a, int argc, char **argv) {
    const char *which = argc > 2 ? argv[2] : "menu";
    const char *cap = NULL;
    int w = 120, h = 40;
    for (int i = 3; i < argc; i++) {
        if (sscanf(argv[i], "%dx%d", &w, &h) == 2) continue;
        cap = argv[i];
    }
    g_snapshot_mode = 1;
    const char *env_sel = getenv("PMTUI_SNAPSHOT_SEL"), *env_fmt = getenv("PMTUI_SNAPSHOT_FORMAT");
    if (env_sel) g_snapshot_sel = atoi(env_sel);
    tui_force_size(w, h);
    if (engine_check(&a->eng) != 0) { fprintf(stderr, "%s\n", a->eng.error); return 2; }
    if (!strcmp(which, "dashboard")) {
        if (!cap) { fprintf(stderr, "dashboard snapshot needs a capture file\n"); return 2; }
        if (screen_analyse(a, cap) != 0) { tui_dump(stdout); return 1; }
        screen_dashboard(a);
    } else if (!strcmp(which, "samples")) {
        char p[PM_PATH];
        screen_samples(a, p, sizeof p);
    } else if (!strcmp(which, "live")) {
        char p[PM_PATH];
        screen_live(a, p, sizeof p);
    } else {
        screen_menu(a);
    }
    if (env_fmt && !strcmp(env_fmt, "json")) tui_dump_json(stdout);
    else tui_dump(stdout);
    return 0;
}

int main(int argc, char **argv) {
    const char *direct = NULL;
    int snap = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(); return 0; }
        if (!strcmp(argv[i], "--version")) { printf("pmtui %s\n", PM_VERSION); return 0; }
        if (!strcmp(argv[i], "--snapshot")) { snap = 1; break; }
        if (!strcmp(argv[i], "--webtest") && i + 1 < argc) {   /* self-test: launch + stop the web UI */
            App *t = &g_app;
            if (engine_locate(&t->eng) != 0) return 2;
            if (web_start(&t->eng, &t->web, argv[i + 1]) != 0) { puts("web_start failed"); return 1; }
            long t0 = now_ms();
            int r = 0;
            while ((r = web_ready(&t->web)) == 0 && now_ms() - t0 < 60000) sleep_ms(250);
            printf("web ready=%d url=%s after %.1fs\n", r, t->web.url, (now_ms() - t0) / 1000.0);
            int port = t->web.port;
            web_stop(&t->web);
            sleep_ms(500);
            printf("stopped; port %d still open=%d\n", port, tcp_port_open(port));
            return r == 1 ? 0 : 1;
        }
        direct = argv[i];
    }
    App *a = &g_app;
    if (engine_locate(&a->eng) != 0) {
        fprintf(stderr, "pmtui: %s\n", a->eng.error);
        return 2;
    }
    if (snap) {
        char cp[PM_PATH], s0[PM_PATH], e0[256];
        path_join(s0, sizeof s0, a->eng.root, "samples");
        path_join(cp, sizeof cp, s0, "catalog.json");
        a->catalog = json_parse_file(cp, e0, sizeof e0);
        capture_detect(&a->cap);
        return snapshot(a, argc, argv);
    }
    char direct_path[PM_PATH] = "";
    if (direct) {
        char err[300];
        clean_user_path(direct, direct_path, sizeof direct_path);
        if (validate_capture_file(direct_path, err, sizeof err) != 0) {
            fprintf(stderr, "pmtui: %s: %s\n", direct_path, err);
            return 2;
        }
        abs_path(direct_path, direct_path, sizeof direct_path);
    }
    char catpath[PM_PATH], s[PM_PATH], err[256];
    path_join(s, sizeof s, a->eng.root, "samples");
    path_join(catpath, sizeof catpath, s, "catalog.json");
    a->catalog = json_parse_file(catpath, err, sizeof err);
    capture_detect(&a->cap);

    if (tui_init() != 0) return 1;
    tui_set_cleanup_hook(cleanup);
    atexit(tui_shutdown);

    if (screen_splash(a) != 0) {
        screen_message(a, "Engine not ready", a->eng.error, C_RED);
        tui_shutdown();
        fprintf(stderr, "pmtui: %s\n", a->eng.error);
        return 2;
    }

    int next = NEXT_MENU;
    if (direct_path[0]) next = screen_analyse(a, direct_path) == 0 ? NEXT_DASH : NEXT_MENU;

    char path[PM_PATH];
    while (next != NEXT_QUIT) {
        switch (next) {
            case NEXT_MENU: next = screen_menu(a); break;
            case NEXT_SAMPLES: {
                int r = screen_samples(a, path, sizeof path);
                next = r < 0 ? NEXT_QUIT : r == 0 ? NEXT_MENU : (screen_analyse(a, path) == 0 ? NEXT_DASH : NEXT_SAMPLES);
                break;
            }
            case NEXT_PATH:
                next = screen_path(a, path, sizeof path) && screen_analyse(a, path) == 0 ? NEXT_DASH : NEXT_MENU;
                break;
            case NEXT_LIVE:
                next = screen_live(a, path, sizeof path) && screen_analyse(a, path) == 0 ? NEXT_DASH : NEXT_MENU;
                break;
            case NEXT_DASH: next = screen_dashboard(a); break;
            default: next = NEXT_QUIT;
        }
    }
    tui_shutdown();
    json_free(a->doc);
    json_free(a->catalog);
    printf("PacketMedic: goodbye. Reports are in %s\n", a->eng.reports);
    return 0;
}
