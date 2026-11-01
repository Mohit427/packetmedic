/* proc.c - see proc.h */
#include "proc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <shellapi.h>
#  include <direct.h>
#else
#  include <arpa/inet.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <limits.h>
#  include <netinet/in.h>
#  include <signal.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <sys/wait.h>
#  include <time.h>
#  include <unistd.h>
#endif

/* ================================================================== Windows */
#ifdef _WIN32
static wchar_t *to_wide(const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    wchar_t *w = malloc(sizeof(wchar_t) * (size_t)n);
    if (w) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}
static void from_wide(const wchar_t *w, char *out, size_t outlen) {
    if (!WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)outlen, NULL, NULL) && outlen) out[0] = 0;
}

/* Quote one argument following the rules of CommandLineToArgvW / the MS C runtime. */
static void quote_arg(wchar_t *dst, size_t *pos, size_t cap, const wchar_t *arg) {
#define PUT(c) do { if (*pos + 1 < cap) dst[(*pos)++] = (c); } while (0)
    PUT(L'"');
    for (const wchar_t *p = arg;; p++) {
        size_t bs = 0;
        while (*p == L'\\') { p++; bs++; }
        if (*p == 0) { for (size_t i = 0; i < bs * 2; i++) PUT(L'\\'); break; }
        if (*p == L'"') { for (size_t i = 0; i < bs * 2 + 1; i++) PUT(L'\\'); PUT(L'"'); }
        else { for (size_t i = 0; i < bs; i++) PUT(L'\\'); PUT(*p); }
    }
    PUT(L'"');
#undef PUT
}

/* Every child gets its own job object. Killing the job kills the whole process
 * tree (the venv python.exe is only a launcher for the real interpreter), and
 * KILL_ON_JOB_CLOSE guarantees nothing survives if pmtui itself dies. */
static HANDLE new_job(void) {
    HANDLE j = CreateJobObjectW(NULL, NULL);
    if (j) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;
        memset(&info, 0, sizeof info);
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(j, JobObjectExtendedLimitInformation, &info, sizeof info);
    }
    return j;
}

int proc_spawn(Proc *p, const char *const argv[], const char *cwd, const char *log_path,
               const char *const env[]) {
    memset(p, 0, sizeof *p);
    size_t cap = 32768, pos = 0;
    wchar_t *cmd = malloc(sizeof(wchar_t) * cap);
    if (!cmd) return -1;
    for (int i = 0; argv[i]; i++) {
        wchar_t *w = to_wide(argv[i]);
        if (!w) { free(cmd); return -1; }
        if (i && pos + 1 < cap) cmd[pos++] = L' ';
        quote_arg(cmd, &pos, cap, w);
        free(w);
    }
    cmd[pos] = 0;

    SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
    HANDLE hout = INVALID_HANDLE_VALUE;
    if (log_path) {
        wchar_t *wl = to_wide(log_path);
        if (wl) {
            hout = CreateFileW(wl, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            free(wl);
        }
    }
    if (hout == INVALID_HANDLE_VALUE)
        hout = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    HANDLE hin = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ, &sa, OPEN_EXISTING, 0, NULL);

    /* extra environment: set in our process, inherited by the child, then removed */
    wchar_t names[8][128];
    int nenv = 0;
    for (int i = 0; env && env[i] && nenv < 8; i++) {
        const char *eq = strchr(env[i], '=');
        if (!eq || eq == env[i] || (size_t)(eq - env[i]) >= 127) continue;
        char name[128];
        memcpy(name, env[i], (size_t)(eq - env[i]));
        name[eq - env[i]] = 0;
        wchar_t *wn = to_wide(name), *wv = to_wide(eq + 1);
        if (wn && wv) {
            SetEnvironmentVariableW(wn, wv);
            wcsncpy(names[nenv], wn, 127);
            names[nenv][127] = 0;
            nenv++;
        }
        free(wn);
        free(wv);
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si);
    memset(&pi, 0, sizeof pi);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hin;
    si.hStdOutput = hout;
    si.hStdError = hout;
    wchar_t *wcwd = cwd ? to_wide(cwd) : NULL;
    BOOL ok = CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW | CREATE_SUSPENDED,
                             NULL, wcwd, &si, &pi);
    for (int i = 0; i < nenv; i++) SetEnvironmentVariableW(names[i], NULL);
    free(wcwd);
    free(cmd);
    if (hout != INVALID_HANDLE_VALUE) CloseHandle(hout);
    if (hin != INVALID_HANDLE_VALUE) CloseHandle(hin);
    if (!ok) return -1;
    p->job = new_job();
    if (p->job) AssignProcessToJobObject((HANDLE)p->job, pi.hProcess);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    p->handle = pi.hProcess;
    p->pid = (long)pi.dwProcessId;
    p->running = 1;
    return 0;
}

int proc_poll(Proc *p, int *exit_code) {
    if (!p->running) return 0;
    DWORD r = WaitForSingleObject((HANDLE)p->handle, 0);
    if (r == WAIT_TIMEOUT) return 1;
    DWORD code = 1;
    GetExitCodeProcess((HANDLE)p->handle, &code);
    CloseHandle((HANDLE)p->handle);
    p->handle = NULL;
    p->running = 0;
    if (p->job) { CloseHandle((HANDLE)p->job); p->job = NULL; }   /* also reaps grandchildren */
    if (exit_code) *exit_code = (int)code;
    return 0;
}

void proc_kill(Proc *p, int graceful) {
    (void)graceful;
    if (!p->running) return;
    if (p->job) TerminateJobObject((HANDLE)p->job, 1);
    TerminateProcess((HANDLE)p->handle, 1);
    WaitForSingleObject((HANDLE)p->handle, 2000);
    CloseHandle((HANDLE)p->handle);
    if (p->job) { CloseHandle((HANDLE)p->job); p->job = NULL; }
    p->handle = NULL;
    p->running = 0;
}

int proc_open_url(const char *url) {
    wchar_t *w = to_wide(url);
    if (!w) return -1;
    HINSTANCE r = ShellExecuteW(NULL, L"open", w, NULL, NULL, SW_SHOWNORMAL);
    free(w);
    return (INT_PTR)r > 32 ? 0 : -1;
}

void sleep_ms(int ms) { Sleep((DWORD)ms); }
long now_ms(void) { return (long)GetTickCount(); }

int file_exists(const char *path) {
    wchar_t *w = to_wide(path);
    if (!w) return 0;
    DWORD a = GetFileAttributesW(w);
    free(w);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}
int dir_exists(const char *path) {
    wchar_t *w = to_wide(path);
    if (!w) return 0;
    DWORD a = GetFileAttributesW(w);
    free(w);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}
long long file_size(const char *path) {
    wchar_t *w = to_wide(path);
    if (!w) return -1;
    WIN32_FILE_ATTRIBUTE_DATA d;
    BOOL ok = GetFileAttributesExW(w, GetFileExInfoStandard, &d);
    free(w);
    if (!ok) return -1;
    return ((long long)d.nFileSizeHigh << 32) | d.nFileSizeLow;
}
int make_dir(const char *path) {
    wchar_t *w = to_wide(path);
    if (!w) return -1;
    BOOL ok = CreateDirectoryW(w, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
    free(w);
    return ok ? 0 : -1;
}
int abs_path(const char *in, char *out, size_t outlen) {
    wchar_t *w = to_wide(in);
    wchar_t buf[PM_PATH];
    if (!w) return -1;
    DWORD n = GetFullPathNameW(w, PM_PATH, buf, NULL);
    free(w);
    if (!n || n >= PM_PATH) return -1;
    from_wide(buf, out, outlen);
    return 0;
}
int exe_dir(char *out, size_t outlen) {
    wchar_t buf[PM_PATH];
    DWORD n = GetModuleFileNameW(NULL, buf, PM_PATH);
    if (!n || n >= PM_PATH) return -1;
    wchar_t *slash = wcsrchr(buf, L'\\');
    if (slash) *slash = 0;
    from_wide(buf, out, outlen);
    return 0;
}
int get_cwd(char *out, size_t outlen) {
    wchar_t buf[PM_PATH];
    if (!GetCurrentDirectoryW(PM_PATH, buf)) return -1;
    from_wide(buf, out, outlen);
    return 0;
}
int is_admin(void) {
    BOOL member = FALSE;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID admins;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0, &admins)) {
        CheckTokenMembership(NULL, admins, &member);
        FreeSid(admins);
    }
    return member ? 1 : 0;
}
int tcp_port_open(int port) {
    static int wsa_ok;
    if (!wsa_ok) {
        WSADATA w;
        if (WSAStartup(MAKEWORD(2, 2), &w)) return 0;
        wsa_ok = 1;
    }
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int r = connect(s, (struct sockaddr *)&a, sizeof a);
    closesocket(s);
    return r == 0;
}
#define PATH_SEP '\\'
#define LIST_SEP ';'

/* ================================================================== POSIX */
#else
int proc_spawn(Proc *p, const char *const argv[], const char *cwd, const char *log_path,
               const char *const env[]) {
    memset(p, 0, sizeof *p);
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        setpgid(0, 0);
        int fd = log_path ? open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0600) : -1;
        if (fd < 0) fd = open("/dev/null", O_WRONLY);
        if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); close(fd); }
        int in = open("/dev/null", O_RDONLY);
        if (in >= 0) { dup2(in, 0); close(in); }
        for (int i = 0; env && env[i]; i++) putenv((char *)env[i]);
        if (cwd && chdir(cwd) != 0) _exit(126);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    p->pid = pid;
    p->running = 1;
    return 0;
}

int proc_poll(Proc *p, int *exit_code) {
    if (!p->running) return 0;
    int st;
    pid_t r = waitpid((pid_t)p->pid, &st, WNOHANG);
    if (r == 0) return 1;
    p->running = 0;
    if (exit_code) *exit_code = (r > 0 && WIFEXITED(st)) ? WEXITSTATUS(st) : 1;
    return 0;
}

void proc_kill(Proc *p, int graceful) {
    if (!p->running) return;
    kill((pid_t)p->pid, graceful ? SIGINT : SIGKILL);
    for (int i = 0; i < 40; i++) {
        if (proc_poll(p, NULL) == 0) return;
        sleep_ms(50);
    }
    kill((pid_t)p->pid, SIGKILL);
    waitpid((pid_t)p->pid, NULL, 0);
    p->running = 0;
}

int proc_open_url(const char *url) {
#ifdef __APPLE__
    const char *argv[] = {"open", url, NULL};
#else
    const char *argv[] = {"xdg-open", url, NULL};
#endif
    Proc p;
    return proc_spawn(&p, argv, NULL, NULL, NULL);
}

void sleep_ms(int ms) {
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}
long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long)(tv.tv_sec * 1000L + tv.tv_usec / 1000);
}
int file_exists(const char *path) { struct stat st; return stat(path, &st) == 0 && S_ISREG(st.st_mode); }
int dir_exists(const char *path) { struct stat st; return stat(path, &st) == 0 && S_ISDIR(st.st_mode); }
long long file_size(const char *path) { struct stat st; return stat(path, &st) == 0 ? (long long)st.st_size : -1; }
int make_dir(const char *path) { return (mkdir(path, 0700) == 0 || errno == EEXIST) ? 0 : -1; }
int abs_path(const char *in, char *out, size_t outlen) {
    char buf[PATH_MAX];
    if (!realpath(in, buf)) return -1;
    snprintf(out, outlen, "%s", buf);
    return 0;
}
int exe_dir(char *out, size_t outlen) {
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n <= 0) return -1;
    buf[n] = 0;
    char *slash = strrchr(buf, '/');
    if (slash) *slash = 0;
    snprintf(out, outlen, "%s", buf);
    return 0;
}
int get_cwd(char *out, size_t outlen) { return getcwd(out, outlen) ? 0 : -1; }
int is_admin(void) { return geteuid() == 0; }
int tcp_port_open(int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int r = connect(s, (struct sockaddr *)&a, sizeof a);
    close(s);
    return r == 0;
}
#define PATH_SEP '/'
#define LIST_SEP ':'
#endif

/* ================================================================== shared */
int proc_wait(Proc *p, int timeout_ms, int *exit_code) {
    long start = now_ms();
    while (proc_poll(p, exit_code) == 1) {
        if (timeout_ms >= 0 && now_ms() - start >= timeout_ms) return 1;
        sleep_ms(20);
    }
    return 0;
}

int proc_run(const char *const argv[], const char *cwd, const char *log_path, int timeout_ms,
             int *exit_code) {
    Proc p;
    if (proc_spawn(&p, argv, cwd, log_path, NULL) != 0) return -1;
    if (proc_wait(&p, timeout_ms, exit_code) == 1) {
        proc_kill(&p, 0);
        return -2;
    }
    return 0;
}

void path_join(char *out, size_t outlen, const char *a, const char *b) {
    size_t n = strlen(a);
    if (n && (a[n - 1] == '/' || a[n - 1] == '\\')) snprintf(out, outlen, "%s%s", a, b);
    else snprintf(out, outlen, "%s%c%s", a, PATH_SEP, b);
}

int find_in_path(const char *name, char *out, size_t outlen) {
    const char *path = getenv("PATH");
    if (!path) return -1;
    char dir[PM_PATH], cand[PM_PATH];
    const char *p = path;
    while (*p) {
        const char *e = strchr(p, LIST_SEP);
        size_t len = e ? (size_t)(e - p) : strlen(p);
        if (len && len < sizeof dir) {
            memcpy(dir, p, len);
            dir[len] = 0;
            path_join(cand, sizeof cand, dir, name);
            if (file_exists(cand)) { snprintf(out, outlen, "%s", cand); return 0; }
#ifdef _WIN32
            char withexe[PM_PATH];
            snprintf(withexe, sizeof withexe, "%s.exe", cand);
            if (file_exists(withexe)) { snprintf(out, outlen, "%s", withexe); return 0; }
#endif
        }
        if (!e) break;
        p = e + 1;
    }
    return -1;
}

int read_file_tail(const char *path, char *out, size_t outlen) {
    FILE *f = fopen(path, "rb");
    if (!f || outlen < 2) { if (f) fclose(f); if (outlen) out[0] = 0; return -1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    long start = sz > (long)outlen - 1 ? sz - (long)outlen + 1 : 0;
    fseek(f, start, SEEK_SET);
    size_t n = fread(out, 1, outlen - 1, f);
    out[n] = 0;
    fclose(f);
    return 0;
}

void file_url(const char *path, char *out, size_t outlen) {
    size_t n = 0;
    const char *prefix = path[0] == '/' ? "file://" : "file:///";
    n = (size_t)snprintf(out, outlen, "%s", prefix);
    for (const unsigned char *p = (const unsigned char *)path; *p && n + 4 < outlen; p++) {
        if (*p == '\\') out[n++] = '/';
        else if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9')
                 || strchr("/-_.~:", *p)) out[n++] = (char)*p;
        else n += (size_t)snprintf(out + n, outlen - n, "%%%02X", *p);
    }
    out[n < outlen ? n : outlen - 1] = 0;
}
