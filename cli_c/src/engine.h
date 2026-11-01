/* engine.h - drives the PacketMedic Python engine and the Streamlit dashboard. */
#ifndef PM_ENGINE_H
#define PM_ENGINE_H

#include "proc.h"

typedef struct {
    char root[PM_PATH];        /* project root (contains packetmedic/) */
    char python[PM_PATH];      /* interpreter used for the engine */
    char py_version[64];
    char reports[PM_PATH];     /* <root>/reports */
    char captures[PM_PATH];    /* <root>/captures */
    char samples[PM_PATH];     /* <root>/samples/pcaps */
    int  ready;
    char error[512];
} Engine;

typedef struct {
    Proc proc;
    char capture[PM_PATH];
    char json[PM_PATH];
    char html[PM_PATH];
    char log[PM_PATH];
    long started;
} Analysis;

typedef struct {
    Proc proc;
    int  port;
    char capture[PM_PATH];
    char url[64];
    char log[PM_PATH];
} WebServer;

int  engine_locate(Engine *e);                 /* find root + python (fast) */
int  engine_check(Engine *e);                  /* verify python can import the engine (slow, ~1-2 s) */

int  validate_capture_file(const char *path, char *err, size_t errlen);
void clean_user_path(const char *in, char *out, size_t outlen);

int  analysis_start(Engine *e, Analysis *a, const char *capture);
/* returns 1 running, 0 done ok, -1 rejected by engine (reason in msg), -2 engine error */
int  analysis_poll(Analysis *a, char *msg, size_t msglen);
void analysis_cancel(Analysis *a);

int  evidence_export(Engine *e, const char *capture, char *outdir, size_t outlen, char *msg, size_t msglen);

int  web_start(Engine *e, WebServer *w, const char *capture);
int  web_ready(WebServer *w);                  /* 1 when the port accepts connections */
void web_stop(WebServer *w);

#endif
