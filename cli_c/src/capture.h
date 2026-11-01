/* capture.h - passive live capture through an installed backend. */
#ifndef PM_CAPTURE_H
#define PM_CAPTURE_H

#include "proc.h"

typedef enum { CAP_NONE, CAP_DUMPCAP, CAP_TCPDUMP, CAP_PKTMON } CapBackend;

/* Listening caps: the user picks the duration, but only inside these bounds.
 * The byte cap keeps captures below the engine's 512 MB input limit. */
#define CAP_MIN_SECONDS 5
#define CAP_MAX_SECONDS 300
#define CAP_MAX_BYTES   (400LL * 1024 * 1024)

typedef struct {
    CapBackend backend;
    char tool[PM_PATH];
    char name[32];
    int  needs_admin;
    int  have_admin;
    char hint[512];            /* what to do if unusable */
} CapInfo;

typedef struct {
    CapInfo info;
    Proc proc;
    char out[PM_PATH];         /* final .pcap/.pcapng */
    char etl[PM_PATH];         /* pktmon intermediate */
    char log[PM_PATH];
    int  seconds;
    long started;
    int  active;
} Capture;

void capture_detect(CapInfo *ci);
int  capture_start(Capture *c, const CapInfo *ci, const char *captures_dir, int seconds, char *err, size_t errlen);
long long capture_bytes(const Capture *c);
/* stop + convert if needed; returns 0 and the final file in c->out */
int  capture_finish(Capture *c, char *err, size_t errlen);
void capture_abort(Capture *c);

#endif
