/* proc.h - cross-platform process control and small OS helpers.
 *
 * Processes are always started from an argv array. There is NO shell
 * involved anywhere (no system(), no popen()), so user-supplied paths can
 * never be interpreted as commands.
 */
#ifndef PM_PROC_H
#define PM_PROC_H

#include <stddef.h>

#define PM_PATH 1024

typedef struct {
    void *handle;     /* Windows HANDLE */
    void *job;        /* Windows job object (whole process tree) */
    long pid;         /* POSIX pid */
    int running;
} Proc;

/* env: NULL-terminated list of "NAME=value" added to the child's environment */
int  proc_spawn(Proc *p, const char *const argv[], const char *cwd, const char *log_path,
                const char *const env[]);
int  proc_poll(Proc *p, int *exit_code);              /* 1 running, 0 exited, -1 error */
int  proc_wait(Proc *p, int timeout_ms, int *exit_code); /* 0 exited, 1 timeout */
void proc_kill(Proc *p, int graceful);
int  proc_run(const char *const argv[], const char *cwd, const char *log_path, int timeout_ms,
              int *exit_code);                         /* 0 ok (exit code in *exit_code) */
int  proc_open_url(const char *url);

void sleep_ms(int ms);
long now_ms(void);
int  file_exists(const char *path);
int  dir_exists(const char *path);
long long file_size(const char *path);
int  make_dir(const char *path);
int  abs_path(const char *in, char *out, size_t outlen);
void path_join(char *out, size_t outlen, const char *a, const char *b);
int  find_in_path(const char *name, char *out, size_t outlen);
int  exe_dir(char *out, size_t outlen);
int  get_cwd(char *out, size_t outlen);
int  is_admin(void);
int  tcp_port_open(int port);
int  read_file_tail(const char *path, char *out, size_t outlen);
void file_url(const char *path, char *out, size_t outlen);

#endif
