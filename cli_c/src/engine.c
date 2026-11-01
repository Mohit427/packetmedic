/* engine.c - see engine.h */
#include "engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CAPTURE_BYTES (512LL * 1024 * 1024)

static const char *const ENGINE_ENV[] = {"PYTHONIOENCODING=utf-8", "PYTHONUTF8=1", "NO_COLOR=1",
                                         "PYTHONDONTWRITEBYTECODE=1", NULL};

static int is_root(const char *dir) {
    char p[PM_PATH], q[PM_PATH];
    path_join(q, sizeof q, dir, "packetmedic");
    path_join(p, sizeof p, q, "__init__.py");
    return file_exists(p);
}

static int walk_up(char *dir) {
    for (int i = 0; i < 6; i++) {
        if (is_root(dir)) return 0;
        char *s1 = strrchr(dir, '/'), *s2 = strrchr(dir, '\\');
        char *s = s1 > s2 ? s1 : s2;
        if (!s || s == dir) return -1;
        *s = 0;
        if (strlen(dir) == 2 && dir[1] == ':') return is_root(dir) ? 0 : -1;  /* "C:" */
    }
    return -1;
}

int engine_locate(Engine *e) {
    memset(e, 0, sizeof *e);
    char dir[PM_PATH];
    int found = 0;
    const char *env_root = getenv("PACKETMEDIC_ROOT");
    if (env_root && is_root(env_root)) { snprintf(e->root, sizeof e->root, "%s", env_root); found = 1; }
    if (!found && get_cwd(dir, sizeof dir) == 0 && walk_up(dir) == 0) { snprintf(e->root, sizeof e->root, "%s", dir); found = 1; }
    if (!found && exe_dir(dir, sizeof dir) == 0 && walk_up(dir) == 0) { snprintf(e->root, sizeof e->root, "%s", dir); found = 1; }
    if (!found) {
        snprintf(e->error, sizeof e->error,
                 "Could not find the PacketMedic project (folder containing packetmedic/). "
                 "Run pmtui from inside the repository or set PACKETMEDIC_ROOT.");
        return -1;
    }
    path_join(e->reports, sizeof e->reports, e->root, "reports");
    path_join(e->captures, sizeof e->captures, e->root, "captures");
    char s[PM_PATH];
    path_join(s, sizeof s, e->root, "samples");
    path_join(e->samples, sizeof e->samples, s, "pcaps");
    make_dir(e->reports);
    make_dir(e->captures);

    const char *cands[] = {".venv/Scripts/python.exe", ".venv/bin/python", "venv/Scripts/python.exe",
                           "venv/bin/python", NULL};
    for (int i = 0; cands[i]; i++) {
        char c[PM_PATH];
        path_join(c, sizeof c, e->root, cands[i]);
        if (file_exists(c)) { snprintf(e->python, sizeof e->python, "%s", c); return 0; }
    }
    const char *envpy = getenv("PACKETMEDIC_PYTHON");
    if (envpy && *envpy) { snprintf(e->python, sizeof e->python, "%s", envpy); return 0; }
    if (find_in_path("python3", e->python, sizeof e->python) == 0) return 0;
    if (find_in_path("python", e->python, sizeof e->python) == 0) return 0;
    snprintf(e->error, sizeof e->error, "No Python interpreter found. Create the venv: python -m venv .venv");
    return -1;
}

int engine_check(Engine *e) {
    char log[PM_PATH];
    path_join(log, sizeof log, e->reports, "engine_check.log");
    const char *argv[] = {e->python, "-c",
                          "import sys, packetmedic.analyzer; print('PMOK', sys.version.split()[0])",
                          NULL};
    Proc p;
    int code = -1;
    if (proc_spawn(&p, argv, e->root, log, ENGINE_ENV) != 0) {
        snprintf(e->error, sizeof e->error, "Could not start %s", e->python);
        return -1;
    }
    if (proc_wait(&p, 60000, &code) == 1) { proc_kill(&p, 0); code = -1; }
    char out[2048];
    read_file_tail(log, out, sizeof out);
    char *ok = strstr(out, "PMOK ");
    if (code != 0 || !ok) {
        snprintf(e->error, sizeof e->error,
                 "The Python engine is not ready (missing dependencies?). Run: pip install -r requirements.txt");
        return -1;
    }
    sscanf(ok + 5, "%63s", e->py_version);
    e->ready = 1;
    return 0;
}

/* Remove wrapping quotes / whitespace that "Copy as path" or drag-and-drop add. */
void clean_user_path(const char *in, char *out, size_t outlen) {
    while (*in == ' ' || *in == '\t') in++;
    size_t n = strlen(in);
    while (n && (in[n - 1] == ' ' || in[n - 1] == '\t' || in[n - 1] == '\r' || in[n - 1] == '\n')) n--;
    if (n >= 2 && ((in[0] == '"' && in[n - 1] == '"') || (in[0] == '\'' && in[n - 1] == '\''))) { in++; n -= 2; }
    if (n >= outlen) n = outlen - 1;
    memcpy(out, in, n);
    out[n] = 0;
}

int validate_capture_file(const char *path, char *err, size_t errlen) {
    if (!*path) { snprintf(err, errlen, "Please enter a file path."); return -1; }
    for (const unsigned char *p = (const unsigned char *)path; *p; p++)
        if (*p < 0x20) { snprintf(err, errlen, "The path contains control characters."); return -1; }
    if (dir_exists(path)) { snprintf(err, errlen, "That is a folder, not a capture file."); return -1; }
    if (!file_exists(path)) { snprintf(err, errlen, "File not found."); return -1; }
    long long sz = file_size(path);
    if (sz <= 0) { snprintf(err, errlen, "File is empty."); return -1; }
    if (sz > MAX_CAPTURE_BYTES) { snprintf(err, errlen, "File is larger than 512 MB."); return -1; }
    FILE *f = fopen(path, "rb");
    if (!f) { snprintf(err, errlen, "Cannot open the file (permissions?)."); return -1; }
    unsigned char m[4] = {0};
    size_t rd = fread(m, 1, 4, f);
    fclose(f);
    static const unsigned char magics[5][4] = {{0xd4, 0xc3, 0xb2, 0xa1}, {0xa1, 0xb2, 0xc3, 0xd4},
                                               {0x4d, 0x3c, 0xb2, 0xa1}, {0xa1, 0xb2, 0x3c, 0x4d},
                                               {0x0a, 0x0d, 0x0d, 0x0a}};
    for (int i = 0; rd == 4 && i < 5; i++)
        if (!memcmp(m, magics[i], 4)) return 0;
    snprintf(err, errlen, "Not a pcap/pcapng file (unrecognised file signature).");
    return -1;
}

static void safe_stem(const char *path, char *out, size_t outlen) {
    const char *b1 = strrchr(path, '/'), *b2 = strrchr(path, '\\');
    const char *base = b1 > b2 ? b1 + 1 : b2 ? b2 + 1 : path;
    size_t n = 0;
    for (const char *p = base; *p && n + 1 < outlen && n < 80; p++) {
        char c = *p;
        out[n++] = ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_')
                       ? c : '_';
    }
    out[n] = 0;
    if (!n) snprintf(out, outlen, "capture");
}

int analysis_start(Engine *e, Analysis *a, const char *capture) {
    memset(a, 0, sizeof *a);
    if (abs_path(capture, a->capture, sizeof a->capture) != 0)
        snprintf(a->capture, sizeof a->capture, "%s", capture);
    char stem[128], name[200];
    safe_stem(a->capture, stem, sizeof stem);
    snprintf(name, sizeof name, "%s.json", stem);
    path_join(a->json, sizeof a->json, e->reports, name);
    snprintf(name, sizeof name, "%s.html", stem);
    path_join(a->html, sizeof a->html, e->reports, name);
    snprintf(name, sizeof name, "%s.log", stem);
    path_join(a->log, sizeof a->log, e->reports, name);
    remove(a->json);
    const char *argv[] = {e->python, "-m", "packetmedic", "analyze", a->capture,
                          "--json", a->json, "--html", a->html, "-q", NULL};
    a->started = now_ms();
    return proc_spawn(&a->proc, argv, e->root, a->log, ENGINE_ENV);
}

static void log_reason(const char *log, const char *marker, char *msg, size_t msglen) {
    char buf[4096];
    read_file_tail(log, buf, sizeof buf);
    char *r = marker ? strstr(buf, marker) : NULL;
    const char *src = r ? r + strlen(marker) : buf;
    while (*src == ' ') src++;
    size_t n = 0;
    for (const char *p = src; *p && n + 1 < msglen; p++) msg[n++] = (*p == '\n' || *p == '\r') ? ' ' : *p;
    msg[n] = 0;
}

int analysis_poll(Analysis *a, char *msg, size_t msglen) {
    int code = 0;
    if (proc_poll(&a->proc, &code) == 1) return 1;
    if (code == 0 && file_exists(a->json)) return 0;
    if (code == 2) { log_reason(a->log, "Rejected:", msg, msglen); return -1; }
    log_reason(a->log, NULL, msg, msglen);
    return -2;
}

void analysis_cancel(Analysis *a) { proc_kill(&a->proc, 0); }

int evidence_export(Engine *e, const char *capture, char *outdir, size_t outlen, char *msg, size_t msglen) {
    char stem[128], name[200], log[PM_PATH];
    safe_stem(capture, stem, sizeof stem);
    snprintf(name, sizeof name, "%s_evidence", stem);
    path_join(outdir, outlen, e->reports, name);
    snprintf(name, sizeof name, "%s_evidence.log", stem);
    path_join(log, sizeof log, e->reports, name);
    const char *argv[] = {e->python, "-m", "packetmedic", "analyze", capture, "--evidence-dir", outdir, "-q", NULL};
    Proc p;
    int code = -1;
    if (proc_spawn(&p, argv, e->root, log, ENGINE_ENV) != 0) { snprintf(msg, msglen, "could not start engine"); return -1; }
    if (proc_wait(&p, 300000, &code) == 1) { proc_kill(&p, 0); snprintf(msg, msglen, "timed out"); return -1; }
    if (code != 0) { log_reason(log, NULL, msg, msglen); return -1; }
    return 0;
}

int web_start(Engine *e, WebServer *w, const char *capture) {
    web_stop(w);
    memset(w, 0, sizeof *w);
    int port = 0;
    for (int p = 8501; p <= 8520; p++)
        if (!tcp_port_open(p)) { port = p; break; }
    if (!port) return -1;
    char portstr[16], envfile[PM_PATH + 32], app[PM_PATH];
    snprintf(portstr, sizeof portstr, "%d", port);
    if (abs_path(capture, w->capture, sizeof w->capture) != 0)
        snprintf(w->capture, sizeof w->capture, "%s", capture);
    snprintf(envfile, sizeof envfile, "PACKETMEDIC_FILE=%s", w->capture);
    path_join(app, sizeof app, e->root, "app.py");
    path_join(w->log, sizeof w->log, e->reports, "streamlit.log");
    const char *argv[] = {e->python, "-m", "streamlit", "run", app, "--server.port", portstr,
                          "--server.address", "127.0.0.1", "--server.headless", "true",
                          "--browser.gatherUsageStats", "false", NULL};
    const char *env[] = {envfile, "PYTHONIOENCODING=utf-8", "PYTHONUTF8=1", NULL};
    if (proc_spawn(&w->proc, argv, e->root, w->log, env) != 0) return -1;
    w->port = port;
    snprintf(w->url, sizeof w->url, "http://localhost:%d", port);
    return 0;
}

int web_ready(WebServer *w) {
    if (!w->proc.running) return 0;
    int code;
    if (proc_poll(&w->proc, &code) == 0) return -1;   /* server died */
    return tcp_port_open(w->port);
}

void web_stop(WebServer *w) {
    if (w->proc.running) proc_kill(&w->proc, 1);
    w->port = 0;
    w->url[0] = 0;
}
