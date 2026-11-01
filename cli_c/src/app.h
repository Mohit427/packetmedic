/* app.h - shared application state and screen entry points. */
#ifndef PM_APP_H
#define PM_APP_H

#include "capture.h"
#include "engine.h"
#include "json.h"

#define PM_VERSION "1.0"

typedef struct {
    Engine eng;
    WebServer web;
    CapInfo cap;
    Capture live;
    JDoc *catalog;
    /* current report */
    JDoc *doc;
    char capture[PM_PATH];
    char html[PM_PATH];
    char json[PM_PATH];
    char analysed_name[256];
    /* transient status line */
    char status[512];
    int status_fg;
    long status_until;
    unsigned long tick;
} App;

enum { NEXT_MENU, NEXT_SAMPLES, NEXT_PATH, NEXT_LIVE, NEXT_DASH, NEXT_QUIT };

int screen_splash(App *a);
int screen_menu(App *a);
int screen_samples(App *a, char *out, size_t outlen);
int screen_path(App *a, char *out, size_t outlen);
int screen_live(App *a, char *out, size_t outlen);
int screen_analyse(App *a, const char *path);
int screen_dashboard(App *a);
void screen_message(App *a, const char *title, const char *text, int fg);

extern int g_snapshot_mode;
extern int g_snapshot_sel;    /* row selected in a snapshot */

#endif
