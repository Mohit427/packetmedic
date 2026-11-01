/* capture.c - see capture.h
 *
 * Capture is PASSIVE: these backends only record traffic, nothing is sent.
 */
#include "capture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void capture_detect(CapInfo *ci) {
    memset(ci, 0, sizeof *ci);
    ci->have_admin = is_admin();
    if (find_in_path("dumpcap", ci->tool, sizeof ci->tool) == 0
#ifdef _WIN32
        || file_exists(strcpy(ci->tool, "C:\\Program Files\\Wireshark\\dumpcap.exe"))
#endif
    ) {
        ci->backend = CAP_DUMPCAP;
        snprintf(ci->name, sizeof ci->name, "dumpcap");
        ci->needs_admin = 0;   /* Npcap / capture group permissions decide */
        return;
    }
#ifndef _WIN32
    if (find_in_path("tcpdump", ci->tool, sizeof ci->tool) == 0 || file_exists(strcpy(ci->tool, "/usr/sbin/tcpdump"))) {
        ci->backend = CAP_TCPDUMP;
        snprintf(ci->name, sizeof ci->name, "tcpdump");
        ci->needs_admin = 1;
        if (!ci->have_admin)
            snprintf(ci->hint, sizeof ci->hint, "tcpdump needs root. Re-run with: sudo ./cli_c/pmtui");
        return;
    }
    snprintf(ci->hint, sizeof ci->hint,
             "No capture tool found. Install tcpdump (sudo apt install tcpdump) or Wireshark (dumpcap).");
#else
    const char *sysroot = getenv("SystemRoot");
    char pk[PM_PATH];
    snprintf(pk, sizeof pk, "%s\\System32\\pktmon.exe", sysroot ? sysroot : "C:\\Windows");
    if (file_exists(pk)) {
        ci->backend = CAP_PKTMON;
        snprintf(ci->tool, sizeof ci->tool, "%s", pk);
        snprintf(ci->name, sizeof ci->name, "pktmon");
        ci->needs_admin = 1;
        if (!ci->have_admin)
            snprintf(ci->hint, sizeof ci->hint,
                     "Windows' built-in pktmon needs Administrator rights. Close this window, open Terminal "
                     "with 'Run as administrator', and start pmtui again (or install Wireshark).");
        return;
    }
    snprintf(ci->hint, sizeof ci->hint, "No capture tool found. Install Wireshark (includes dumpcap + Npcap).");
#endif
    ci->tool[0] = 0;
}

static void stamp(char *out, size_t n) {
    time_t t = time(NULL);
    struct tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    strftime(out, n, "%Y%m%d_%H%M%S", &tmv);
}

int capture_start(Capture *c, const CapInfo *ci, const char *dir, int seconds, char *err, size_t errlen) {
    memset(c, 0, sizeof *c);
    c->info = *ci;
    c->seconds = seconds;
    char ts[32], name[96];
    stamp(ts, sizeof ts);
    snprintf(name, sizeof name, "live_%s.log", ts);
    path_join(c->log, sizeof c->log, dir, name);
    /* defence in depth: the UI already validates, but the caps are enforced here too */
    if (seconds < CAP_MIN_SECONDS) seconds = CAP_MIN_SECONDS;
    if (seconds > CAP_MAX_SECONDS) seconds = CAP_MAX_SECONDS;
    c->seconds = seconds;
    char secs[32];
    snprintf(secs, sizeof secs, "duration:%d", seconds);

    if (ci->backend == CAP_DUMPCAP) {
        snprintf(name, sizeof name, "live_%s.pcapng", ts);
        path_join(c->out, sizeof c->out, dir, name);
        const char *argv[] = {ci->tool, "-q", "-a", secs, "-w", c->out, NULL};
        if (proc_spawn(&c->proc, argv, dir, c->log, NULL) != 0) { snprintf(err, errlen, "Could not start dumpcap."); return -1; }
    } else if (ci->backend == CAP_TCPDUMP) {
        snprintf(name, sizeof name, "live_%s.pcap", ts);
        path_join(c->out, sizeof c->out, dir, name);
#ifdef __APPLE__
        const char *argv[] = {ci->tool, "-U", "-w", c->out, NULL};
#else
        const char *argv[] = {ci->tool, "-i", "any", "-U", "-w", c->out, NULL};
#endif
        if (proc_spawn(&c->proc, argv, dir, c->log, NULL) != 0) { snprintf(err, errlen, "Could not start tcpdump."); return -1; }
    } else if (ci->backend == CAP_PKTMON) {
        snprintf(name, sizeof name, "live_%s.etl", ts);
        path_join(c->etl, sizeof c->etl, dir, name);
        snprintf(name, sizeof name, "live_%s.pcapng", ts);
        path_join(c->out, sizeof c->out, dir, name);
        /* --comp nics: record each packet once at the network card (not once per stack layer) */
        const char *argv[] = {ci->tool, "start", "--capture", "--comp", "nics", "--pkt-size", "0",
                              "--file-name", c->etl, NULL};
        int code = -1;
        if (proc_run(argv, dir, c->log, 20000, &code) != 0 || code != 0) {
            char tail[300];
            read_file_tail(c->log, tail, sizeof tail);
            for (char *p = tail; *p; p++) if (*p == '\r' || *p == '\n') *p = ' ';
            snprintf(err, errlen, "pktmon could not start (exit %d). %s", code, tail);
            return -1;
        }
    } else {
        snprintf(err, errlen, "%s", ci->hint[0] ? ci->hint : "No capture backend available.");
        return -1;
    }
    c->started = now_ms();
    c->active = 1;
    return 0;
}

long long capture_bytes(const Capture *c) {
    long long n = file_size(c->info.backend == CAP_PKTMON ? c->etl : c->out);
    return n < 0 ? 0 : n;
}

static int pktmon_stop(Capture *c) {
    const char *argv[] = {c->info.tool, "stop", NULL};
    int code = -1;
    char stoplog[PM_PATH];
    snprintf(stoplog, sizeof stoplog, "%s.stop", c->log);
    proc_run(argv, NULL, stoplog, 60000, &code);
    return code;
}

int capture_finish(Capture *c, char *err, size_t errlen) {
    if (!c->active) { snprintf(err, errlen, "No capture running."); return -1; }
    c->active = 0;
    if (c->info.backend == CAP_DUMPCAP) {
        int code = 0;
        if (proc_wait(&c->proc, 5000, &code) == 1) proc_kill(&c->proc, 1);
    } else if (c->info.backend == CAP_TCPDUMP) {
        proc_kill(&c->proc, 1);          /* SIGINT: tcpdump flushes and exits */
    } else if (c->info.backend == CAP_PKTMON) {
        pktmon_stop(c);
        char convlog[PM_PATH];
        snprintf(convlog, sizeof convlog, "%s.convert", c->log);
        const char *argv[] = {c->info.tool, "etl2pcap", c->etl, "--out", c->out, NULL};
        int code = -1;
        if (proc_run(argv, NULL, convlog, 120000, &code) != 0 || code != 0 || !file_exists(c->out)) {
            const char *argv2[] = {c->info.tool, "pcapng", c->etl, "-o", c->out, NULL};   /* newer Windows 11 name */
            proc_run(argv2, NULL, convlog, 120000, &code);
        }
        remove(c->etl);
    }
    if (!file_exists(c->out) || file_size(c->out) < 24) {
        char tail[300];
        read_file_tail(c->log, tail, sizeof tail);
        for (char *p = tail; *p; p++) if (*p == '\r' || *p == '\n') *p = ' ';
        snprintf(err, errlen, "The capture produced no file. %s", tail);
        return -1;
    }
    return 0;
}

void capture_abort(Capture *c) {
    if (!c->active) return;
    c->active = 0;
    if (c->info.backend == CAP_PKTMON) {
        pktmon_stop(c);
        remove(c->etl);
    } else {
        proc_kill(&c->proc, 1);
    }
}
