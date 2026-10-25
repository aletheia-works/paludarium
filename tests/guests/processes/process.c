#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/vfs.h>
#include <sys/prctl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 1031
#define F_GETPIPE_SZ 1032
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif
#ifndef P_PIDFD
#define P_PIDFD 3
#endif
#ifndef PIDFD_NONBLOCK
#define PIDFD_NONBLOCK O_NONBLOCK
#endif

static void result(const char *name, long value) { printf("%s=%ld\n", name, value); }
static pid_t child(void) { return syscall(SYS_fork); }
static int thread_ready[2], thread_block[2];
static int discard_go[2], discard_done[2];
/* Reports whether SIGUSR2 is pending for this thread, before and after the
   main thread makes it ignored. */
static void *discard_reader(void *unused) {
    (void)unused;
    char byte;
    sigset_t pending;
    for (int round = 0; round < 2; round++) {
        if (read(discard_go[0], &byte, 1) != 1) return NULL;
        sigpending(&pending);
        result(round ? "thread-after" : "thread-before", sigismember(&pending, SIGUSR2));
        fflush(stdout);
        if (write(discard_done[1], "x", 1) != 1) return NULL;
    }
    return NULL;
}
static volatile sig_atomic_t received;
static void interrupted(int number) { (void)number; received++; }
static volatile sig_atomic_t usr2_blocked_in_handler = -1;
static void note_mask(int number) {
    (void)number;
    sigset_t now;
    sigprocmask(SIG_BLOCK, NULL, &now);
    usr2_blocked_in_handler = sigismember(&now, SIGUSR2);
    received++;
}
/* A child that sends `number` to its parent every 20 ms until killed. */
static pid_t pester(int number) {
    pid_t parent = getpid(), pid = child();
    if (pid == 0) {
        struct timespec nap = {0, 20000000};
        for (;;) {
            kill(parent, number);
            nanosleep(&nap, NULL);
        }
    }
    return pid;
}
static int vm_value;
static int vm_child(void *unused) { (void)unused; vm_value = 23; return 4; }
/* CLONE_SIGHAND children: one installs a SIGUSR1 handler, one execs. */
static int sighand_child(void *unused) {
    (void)unused;
    struct sigaction action = {0};
    action.sa_handler = interrupted;
    return sigaction(SIGUSR1, &action, NULL) ? 1 : 5;
}
static char *sighand_self;
static int sighand_exec(void *unused) {
    (void)unused;
    char *args[] = { "process", "sighand-exec-child", sighand_self, NULL };
    char *env[] = { NULL };
    execve(sighand_self, args, env);
    return 92;
}
static void *blocked_sibling(void *unused) {
    (void)unused;
    char byte;
    if (write(thread_ready[1], "x", 1) != 1) _exit(85);
    read(thread_block[0], &byte, 1);
    _exit(84);
}
static char thread_name[16];
static void *name_reader(void *unused) {
    (void)unused;
    prctl(PR_GET_NAME, thread_name);
    prctl(PR_SET_NAME, "worker");
    return NULL;
}
/* The kernel's struct sigevent, with the SIGEV_THREAD_ID target. */
struct thread_event { long value; int signo; int notify; int tid; int pad[11]; };
static int timer_report[2];
static void *timer_waiter(void *unused) {
    (void)unused;
    int tid = syscall(SYS_gettid);
    write(timer_report[1], &tid, sizeof tid);
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    siginfo_t info;
    int got[3] = {sigwaitinfo(&set, &info), info.si_code, info.si_value.sival_int};
    write(timer_report[1], got, sizeof got);
    return NULL;
}
static int tid_report[2], tid_release[2];
static void *parked(void *unused) {
    (void)unused;
    int tid = syscall(SYS_gettid);
    write(tid_report[1], &tid, sizeof tid);
    char byte;
    read(tid_release[0], &byte, 1);
    return NULL;
}
/* A child that exits with `code` once a byte arrives on `gate`. */
static pid_t gated(int gate[2], int code) {
    pipe(gate);
    pid_t pid = child();
    if (pid == 0) {
        char byte;
        close(gate[1]);
        read(gate[0], &byte, 1);
        _exit(code);
    }
    close(gate[0]);
    return pid;
}
struct clone3_args { unsigned long long flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls; };
static long clone3(void *args, unsigned long size) { return syscall(435, args, size); }
static long clone3_error(struct clone3_args args) {
    errno = 0;
    long r = clone3(&args, sizeof args);
    if (r == 0) _exit(99);
    return r < 0 ? -errno : 1000;
}
static int reaped(long pid) {
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
/* The value of `field` in /proc/self/status, read through a /proc/self
   descriptor as procfs readers do. */
static int status_field(const char *field, char *value, size_t size) {
    int dir = open("/proc/self", O_PATH | O_DIRECTORY | O_CLOEXEC);
    int fd = openat(dir, "status", O_RDONLY | O_CLOEXEC);
    close(dir);
    if (fd < 0) return -1;
    static char text[8192];
    ssize_t n = read(fd, text, sizeof text - 1);
    close(fd);
    if (n <= 0) return -1;
    text[n] = 0;
    size_t length = strlen(field);
    for (char *line = text; *line; line = strchr(line, '\n') + 1) {
        if (!strncmp(line, field, length) && line[length] == ':') {
            char *start = line + length + 1;
            while (*start == '\t') start++;
            size_t used = strcspn(start, "\n");
            if (used >= size) used = size - 1;
            memcpy(value, start, used);
            value[used] = 0;
            return 0;
        }
        if (!strchr(line, '\n')) break;
    }
    return -1;
}
static long raw_priority(int which, int who) { return syscall(SYS_getpriority, which, who); }
static int priority_ready[2], priority_go[2];
static volatile long priority_thread_start, priority_thread_after;
static volatile pid_t priority_tid;
static void *priority_thread(void *base) {
    long nice0 = 20 - (long)base;
    char byte;
    priority_tid = syscall(SYS_gettid);
    priority_thread_start = raw_priority(PRIO_PROCESS, 0);
    setpriority(PRIO_PROCESS, priority_tid, nice0 + 5);
    if (write(priority_ready[1], "x", 1) != 1 || read(priority_go[0], &byte, 1) != 1) return NULL;
    priority_thread_after = raw_priority(PRIO_PROCESS, 0);
    return NULL;
}
static void finish(pid_t pid) {
    int status = 0;
    result("wait", waitpid(pid, &status, 0) == pid);
    result("status", status);
}
int main(int argc, char **argv) {
    if (argc < 3) return 99;
    const char *mode = argv[1], *self = argv[2];
    if (!strcmp(mode, "clone-vm")) {
        char *stack = mmap(NULL, 65536, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (stack == MAP_FAILED) return 80;
        int parent_tid = 0, child_tid = 0;
        pid_t pid = clone(vm_child, stack + 65536, CLONE_VM|CLONE_PARENT_SETTID|CLONE_CHILD_SETTID|SIGCHLD, NULL, &parent_tid, NULL, &child_tid);
        if (pid < 0) return 79;
        finish(pid);
        result("vm", vm_value == 23);
        result("parent-tid", parent_tid == pid);
        result("child-tid", child_tid == pid);
        return 0;
    }
    if (!strcmp(mode, "clone-sighand")) {
        errno = 0;
        long r = syscall(SYS_clone, CLONE_SIGHAND|SIGCHLD, 0, 0, 0, 0);
        if (r == 0) _exit(99);
        result("needs-vm", r == -1 && errno == EINVAL);
        char *stack = mmap(NULL, 65536, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (stack == MAP_FAILED) return 80;
        signal(SIGUSR2, SIG_IGN);
        pid_t pid = clone(sighand_child, stack + 65536, CLONE_VM|CLONE_SIGHAND|SIGCHLD, NULL);
        if (pid < 0) return 79;
        result("child", reaped(pid));
        struct sigaction old;
        sigaction(SIGUSR1, NULL, &old);
        result("shared", old.sa_handler == interrupted);
        received = 0;
        raise(SIGUSR1);
        result("delivered", received);
        /* execve gives the child its own dispositions again. */
        sighand_self = (char *)self;
        fflush(stdout);
        pid = clone(sighand_exec, stack + 65536, CLONE_VM|CLONE_VFORK|CLONE_SIGHAND|SIGCHLD, NULL);
        if (pid < 0) return 78;
        result("exec-child", reaped(pid));
        sigaction(SIGUSR1, NULL, &old);
        result("kept", old.sa_handler == interrupted);
        sigaction(SIGUSR2, NULL, &old);
        result("unshared", old.sa_handler == SIG_IGN);
        return 0;
    }
    if (!strcmp(mode, "clone-high-bits")) {
        /* clone reads only the low 32 bits of its flags: bit 33 is no flag,
           and bit 32 (CLONE_CLEAR_SIGHAND) only exists for clone3. */
        signal(SIGUSR1, interrupted);
        const unsigned long long high[] = { 1ULL << 33, 1ULL << 32 };
        for (int i = 0; i < 2; i++) {
            errno = 0;
            long pid = syscall(SYS_clone, high[i] | SIGCHLD, 0, 0, 0, 0);
            if (pid == 0) {
                struct sigaction old;
                sigaction(SIGUSR1, NULL, &old);
                _exit(old.sa_handler == interrupted ? 7 : 8);
            }
            result(i ? "bit32" : "bit33", pid < 0 ? -errno : reaped(pid));
        }
        return 0;
    }
    if (!strcmp(mode, "sighand-exec-child")) {
        struct sigaction old;
        sigaction(SIGUSR1, NULL, &old);
        result("exec-default", old.sa_handler == SIG_DFL);
        sigaction(SIGUSR2, NULL, &old);
        result("exec-ignored", old.sa_handler == SIG_IGN);
        signal(SIGUSR2, SIG_DFL);
        return 6;
    }
    if (!strcmp(mode, "exec-thread-child")) {
        if (argc != 5) return 77;
        close(atoi(argv[4]));
        signal(SIGPIPE, SIG_IGN);
        errno = 0;
        result("sibling-gone", write(atoi(argv[3]), "x", 1) == -1 && errno == EPIPE);
        result("replacement", 1);
        return 0;
    }
    if (!strcmp(mode, "exec-thread")) {
        pthread_t sibling;
        if (pipe(thread_ready) || pipe(thread_block) || pthread_create(&sibling, NULL, blocked_sibling, NULL)) return 83;
        char byte;
        if (read(thread_ready[0], &byte, 1) != 1) return 82;
        char writer[16], reader[16];
        snprintf(writer, sizeof writer, "%d", thread_block[1]);
        snprintf(reader, sizeof reader, "%d", thread_block[0]);
        char *args[] = { "process", "exec-thread-child", (char *)self, writer, reader, NULL };
        char *env[] = { NULL };
        execve(self, args, env);
        return 81;
    }
    if (!strcmp(mode, "child")) {
        result("argv", argc == 4 && !strcmp(argv[3], "argument"));
        result("env", getenv("PROCESSES_VALUE") && !strcmp(getenv("PROCESSES_VALUE"), "value"));
        return 7;
    }
    if (!strcmp(mode, "exec-wait")) {
        /* After the exec: says so on argv[3], then waits on argv[4]. */
        char byte = 'x';
        if (argc != 5 || write(atoi(argv[3]), &byte, 1) != 1) return 1;
        return read(atoi(argv[4]), &byte, 1) == 1 ? 0 : 2;
    }
    if (!strcmp(mode, "fd-child")) {
        errno = 0;
        result("cloexec", fcntl(9, F_GETFD) == -1 && errno == EBADF);
        result("retained", fcntl(10, F_GETFD) >= 0);
        return 0;
    }
    if (!strcmp(mode, "enoent") || !strcmp(mode, "bad-elf") || !strcmp(mode, "exec-fault")) {
        const char *path = "/paludarium-not-present";
        if (!strcmp(mode, "bad-elf")) {
            path = "/tmp/paludarium-invalid-elf";
            int fd = open(path, O_CREAT|O_TRUNC|O_WRONLY, 0700);
            if (fd < 0 || write(fd, "invalid", 7) != 7 || close(fd)) return 98;
        }
        if (!strcmp(mode, "exec-fault")) path = (const char *)1;
        char *args[] = { "child", NULL };
        char *env[] = { NULL };
        errno = 0;
        result("exec", syscall(SYS_execve, path, args, env));
        result("errno", errno);
        result("old-state", 1);
        if (!strcmp(mode, "bad-elf")) unlink(path);
        return 0;
    }
    if (!strcmp(mode, "uname")) {
        struct utsname names;
        result("uname", uname(&names));
        result("sysname", !strcmp(names.sysname, "Linux"));
        result("machine", !strcmp(names.machine, "x86_64"));
        result("nodename", names.nodename[0] != 0);
        result("release", names.release[0] >= '0' && names.release[0] <= '9');
        errno = 0;
        result("fault", syscall(SYS_uname, (void *)1));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "affinity")) {
        unsigned long mask[16] = {0};
        long size = syscall(SYS_sched_getaffinity, 0, 8, mask);
        result("size", size);
        /* The same machine runs both sides, so the CPU counts agree. */
        result("cpus", __builtin_popcountl(mask[0]));
        result("online", sysconf(_SC_NPROCESSORS_ONLN) == __builtin_popcountl(mask[0]));
        result("pid", syscall(SYS_sched_getaffinity, getpid(), 8, mask));
        result("tid", syscall(SYS_sched_getaffinity, syscall(SYS_gettid), 8, mask));
        long lengths[] = {12, 0, 4};
        for (int i = 0; i < 3; i++) {
            errno = 0;
            result("length", syscall(SYS_sched_getaffinity, 0, lengths[i], mask));
            result("errno", errno);
        }
        errno = 0;
        result("missing", syscall(SYS_sched_getaffinity, 0x3fffffff, 8, mask));
        result("errno", errno);
        errno = 0;
        result("fault", syscall(SYS_sched_getaffinity, 0, 8, (void *)1));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "ids")) {
        /* Native IDs are the runner's and emulated ones root, so compare
           each with the owner of a newly created file. */
        const char *path = "/tmp/paludarium-processes-ids";
        unlink(path);
        int fd = open(path, O_CREAT|O_RDWR, 0600);
        struct stat st;
        result("stat", fstat(fd, &st));
        result("uid", getuid() == st.st_uid);
        result("euid", geteuid() == getuid());
        result("gid", getgid() == st.st_gid);
        result("egid", getegid() == getgid());
        close(fd);
        unlink(path);
        return 0;
    }
    if (!strcmp(mode, "access")) {
        /* The native side is an ordinary user and the emulated one root:
           only results both give are compared (no write without permission). */
        const char *path = "/tmp/paludarium-processes-access";
        unlink(path);
        int fd = open(path, O_CREAT|O_RDWR, 0644);
        result("exists", access(path, F_OK));
        result("read-write", access(path, R_OK|W_OK));
        errno = 0;
        result("execute", access(path, X_OK));
        result("errno", errno);
        chmod(path, 0755);
        result("executable", access(path, X_OK));
        result("directory", faccessat(AT_FDCWD, "/tmp", X_OK, 0));
        result("empty-path", syscall(439, fd, "", R_OK, AT_EMPTY_PATH));
        errno = 0;
        result("missing", access("/tmp/paludarium-processes-missing", F_OK));
        result("errno", errno);
        errno = 0;
        result("bad-mode", syscall(SYS_access, path, 8));
        result("errno", errno);
        errno = 0;
        result("bad-flags", syscall(439, AT_FDCWD, path, F_OK, 0x400));
        result("errno", errno);
        close(fd);
        unlink(path);
        return 0;
    }
    if (!strcmp(mode, "fsize-limit")) {
        /* RLIMIT_FSIZE cuts a regular file's writes at the limit, and a write
           or growing truncate past it raises SIGXFSZ and fails with EFBIG. */
        const char *path = "/tmp/paludarium-fsize";
        struct sigaction action = {0};
        action.sa_handler = interrupted;
        sigaction(SIGXFSZ, &action, NULL);
        struct rlimit limit;
        getrlimit(RLIMIT_FSIZE, &limit);
        limit.rlim_cur = 10;
        result("set", setrlimit(RLIMIT_FSIZE, &limit));
        int fd = open(path, O_CREAT|O_RDWR|O_TRUNC, 0600);
        char buf[32] = {0};
        received = 0;
        result("write", write(fd, buf, 4));
        result("cut", write(fd, buf, 10));
        result("empty", write(fd, buf, 0));
        result("signals-before", received);
        errno = 0;
        result("past", write(fd, buf, 1) < 0 ? -errno : 0);
        result("signals", received);
        lseek(fd, 7, SEEK_SET);
        struct iovec io[2] = {{buf, 2}, {buf, 2}};
        result("writev-cut", writev(fd, io, 2));
        errno = 0;
        result("writev-past", writev(fd, io, 2) < 0 ? -errno : 0);
        result("pwrite-cut", pwrite(fd, buf, 5, 8));
        errno = 0;
        result("pwrite-past", pwrite(fd, buf, 1, 10) < 0 ? -errno : 0);
        errno = 0;
        result("ftruncate-past", ftruncate(fd, 11) < 0 ? -errno : 0);
        result("ftruncate-shrink", ftruncate(fd, 3));
        result("ftruncate-to", ftruncate(fd, 10));
        errno = 0;
        result("truncate-past", truncate(path, 20) < 0 ? -errno : 0);
        result("signals-after", received);
        int appender = open(path, O_WRONLY|O_APPEND);
        errno = 0;
        result("append-past", write(appender, buf, 1) < 0 ? -errno : 0);
        /* An O_APPEND pwrite appends, so its offset does not count. */
        errno = 0;
        result("append-pwrite-past", pwrite(appender, buf, 1, 0) < 0 ? -errno : 0);
        close(appender);
        struct stat st;
        fstat(fd, &st);
        result("size", st.st_size);
        /* fork keeps the limit. */
        pid_t pid = child();
        if (pid == 0) {
            errno = 0;
            _exit(pwrite(fd, buf, 1, 10) < 0 && errno == EFBIG ? 0 : 1);
        }
        result("child", reaped(pid));
        close(fd);
        unlink(path);
        return 0;
    }
    if (!strcmp(mode, "nofile-limit")) {
        /* The soft RLIMIT_NOFILE bounds the descriptor numbers: room for two
           more past the lowest free one. */
        const char *a_path = "/tmp/paludarium-nofile-a", *b_path = "/tmp/paludarium-nofile-b";
        const char *c_path = "/tmp/paludarium-nofile-c";
        unlink(c_path);
        int base = dup(0);
        close(base);
        struct rlimit limit;
        getrlimit(RLIMIT_NOFILE, &limit);
        limit.rlim_cur = base + 2;
        result("set", setrlimit(RLIMIT_NOFILE, &limit));
        int a = open(a_path, O_CREAT|O_RDWR, 0600), b = open(b_path, O_CREAT|O_RDWR, 0600);
        result("opened", a == base && b == base + 1);
        int pair[2];
        struct stat st;
        errno = 0;
        result("open", open(c_path, O_CREAT|O_RDWR, 0600) < 0 ? -errno : 0);
        errno = 0;
        result("not-created", stat(c_path, &st) < 0 ? -errno : 0);
        errno = 0;
        result("dup", dup(a) < 0 ? -errno : 0);
        errno = 0;
        result("pipe", pipe(pair) < 0 ? -errno : 0);
        errno = 0;
        result("dup2", dup2(a, base + 2) < 0 ? -errno : 0);
        errno = 0;
        result("dupfd-past", fcntl(a, F_DUPFD, base + 2) < 0 ? -errno : 0);
        errno = 0;
        result("dupfd-full", fcntl(a, F_DUPFD, base) < 0 ? -errno : 0);
        fcntl(a, F_SETFD, FD_CLOEXEC);
        result("dup2-self", dup2(a, a) == a && fcntl(a, F_GETFD) == FD_CLOEXEC);
        /* With one descriptor free, pipe takes neither. */
        close(b);
        errno = 0;
        result("pipe-one", pipe(pair) < 0 ? -errno : 0);
        result("reused", dup(a) == base + 1);
        unlink(a_path);
        unlink(b_path);
        return 0;
    }
    if (!strcmp(mode, "rlimit")) {
        struct rlimit limit, old;
        getrlimit(RLIMIT_NOFILE, &limit);
        rlim_t hard = limit.rlim_max;
        limit.rlim_cur = 256;
        result("set", setrlimit(RLIMIT_NOFILE, &limit));
        getrlimit(RLIMIT_NOFILE, &old);
        result("soft", old.rlim_cur);
        result("hard-kept", old.rlim_max == hard);
        result("prlimit", syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, NULL, &old));
        result("prlimit-soft", old.rlim_cur);
        pid_t pid = child();
        if (pid == 0) {
            struct rlimit inherited;
            getrlimit(RLIMIT_NOFILE, &inherited);
            _exit(inherited.rlim_cur == 256 ? 0 : 1);
        }
        finish(pid);
        limit.rlim_cur = hard;
        limit.rlim_max = 1;
        errno = 0;
        result("soft-above-hard", setrlimit(RLIMIT_NOFILE, &limit));
        result("errno", errno);
        errno = 0;
        result("bad-resource", syscall(SYS_prlimit64, 0, 99, NULL, &old));
        result("errno", errno);
        errno = 0;
        result("missing", syscall(SYS_prlimit64, 0x3fffffff, RLIMIT_NOFILE, NULL, &old));
        result("errno", errno);
        errno = 0;
        result("bad-new", syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, (void *)1, &old));
        result("errno", errno);
        /* The new limit is set before the old one is written out. */
        limit.rlim_cur = 128;
        limit.rlim_max = hard;
        errno = 0;
        result("bad-old", syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, &limit, (void *)1));
        result("errno", errno);
        getrlimit(RLIMIT_NOFILE, &old);
        result("applied", old.rlim_cur);
        return 0;
    }
    if (!strcmp(mode, "pgid")) {
        result("same", getpgrp() == getpgid(0));
        result("own", setpgid(0, 0));
        result("leader", getpgrp() == getpid());
        int ready[2], go[2];
        if (pipe(ready) || pipe(go)) return 81;
        pid_t pid = child();
        if (pid == 0) {
            char byte;
            int inherited = getpgid(0) == getppid();
            if (write(ready[1], &byte, 1) != 1) _exit(85);
            if (read(go[0], &byte, 1) != 1) _exit(86);
            _exit(inherited && getpgid(0) == getpid() ? 0 : 1);
        }
        char byte;
        if (read(ready[0], &byte, 1) != 1) return 82;
        result("child-inherits", getpgid(pid) == getpid());
        result("child-own", setpgid(pid, pid));
        result("child-moved", getpgid(pid) == pid);
        errno = 0;
        result("no-group", setpgid(pid, 0x3ffffff0));
        result("errno", errno);
        if (write(go[1], &byte, 1) != 1) return 83;
        finish(pid);
        errno = 0;
        result("no-process", setpgid(0x3fffffff, 0));
        result("errno", errno);
        errno = 0;
        result("negative", setpgid(0, -1));
        result("errno", errno);
        errno = 0;
        result("getpgid-missing", getpgid(0x3fffffff));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "priority")) {
        /* Nice values are per thread. Each check only raises them, which
           needs no privilege, and compares them with the starting one. */
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) {
            long base = raw_priority(PRIO_PROCESS, 0), nice0 = 20 - base;
            char byte;
            int status;
            if (setpgid(0, 0) || pipe(priority_ready) || pipe(priority_go)) _exit(81);
            result("raise", setpriority(PRIO_PROCESS, 0, nice0 + 3));
            result("raised", raw_priority(PRIO_PROCESS, 0) - base);
            pthread_t worker;
            if (pthread_create(&worker, NULL, priority_thread, (void *)base)) _exit(82);
            if (read(priority_ready[0], &byte, 1) != 1) _exit(83);
            result("thread-inherits", priority_thread_start - base);
            result("thread-own", raw_priority(PRIO_PROCESS, priority_tid) - base);
            result("main-kept", raw_priority(PRIO_PROCESS, 0) - base);
            result("group-highest", raw_priority(PRIO_PGRP, 0) - base);
            result("group-set", setpriority(PRIO_PGRP, 0, nice0 + 6));
            result("group-thread", raw_priority(PRIO_PROCESS, priority_tid) - base);
            if (write(priority_go[1], "x", 1) != 1 || pthread_join(worker, NULL)) _exit(84);
            result("thread-after", priority_thread_after - base);
            pid_t inheritor = fork();
            if (inheritor == 0) _exit(raw_priority(PRIO_PROCESS, 0) - base == -6 ? 0 : 1);
            result("fork-inherits", waitpid(inheritor, &status, 0) == inheritor && status == 0);
            pid_t zombie = fork();
            if (zombie == 0) {
                setpriority(PRIO_PROCESS, 0, 19);
                _exit(0);
            }
            siginfo_t info;
            result("exited", waitid(P_PID, zombie, &info, WEXITED | WNOWAIT) == 0);
            result("zombie", raw_priority(PRIO_PROCESS, zombie));
            waitpid(zombie, &status, 0);
            errno = 0;
            result("reaped", raw_priority(PRIO_PROCESS, zombie));
            result("errno", errno);
            result("clamped", setpriority(PRIO_PROCESS, 0, 1000));
            result("lowest", raw_priority(PRIO_PROCESS, 0));
            errno = 0;
            result("bad-which", setpriority(3, 0, 0));
            result("errno", errno);
            errno = 0;
            result("bad-which-get", raw_priority(-1, 0));
            result("errno", errno);
            errno = 0;
            result("missing", raw_priority(PRIO_PROCESS, 0x3fffffff));
            result("errno", errno);
            errno = 0;
            result("negative", raw_priority(PRIO_PROCESS, -1));
            result("errno", errno);
            errno = 0;
            result("missing-group", raw_priority(PRIO_PGRP, 0x3fffffff));
            result("errno", errno);
            errno = 0;
            result("missing-set", setpriority(PRIO_PROCESS, 0x3fffffff, 19));
            result("errno", errno);
            fflush(stdout);
            _exit(0);
        }
        finish(pid);
        return 0;
    }
    if (!strcmp(mode, "pgid-exec")) {
        /* A child that has run execve keeps its group (EACCES). */
        int ready[2], go[2];
        if (pipe(ready) || pipe(go)) return 81;
        char byte, ready_fd[16], go_fd[16];
        snprintf(ready_fd, sizeof ready_fd, "%d", ready[1]);
        snprintf(go_fd, sizeof go_fd, "%d", go[0]);
        fflush(stdout);
        pid_t pid = child();
        if (pid == 0) {
            char *args[] = { "process", "exec-wait", (char *)self, ready_fd, go_fd, NULL };
            char *env[] = { NULL };
            execve(self, args, env);
            _exit(92);
        }
        if (read(ready[0], &byte, 1) != 1) return 82;
        errno = 0;
        result("executed-own", setpgid(pid, pid));
        result("errno", errno);
        errno = 0;
        result("executed-same", setpgid(pid, getpgrp()));
        result("errno", errno);
        if (write(go[1], "x", 1) != 1) return 83;
        finish(pid);
        /* An exited child not yet reaped still holds its group. */
        pid_t zombie = child();
        if (zombie == 0) _exit(0);
        result("zombie-own", setpgid(zombie, zombie));
        siginfo_t info;
        result("exited", waitid(P_PID, zombie, &info, WEXITED | WNOWAIT) == 0 && info.si_pid == zombie);
        int release[2];
        if (pipe(release)) return 84;
        pid_t member = child();
        if (member == 0) {
            if (read(release[0], &byte, 1) != 1) _exit(1);
            _exit(0);
        }
        result("zombie-group", setpgid(member, zombie));
        result("joined", getpgid(member) == zombie);
        result("back", setpgid(member, getpgrp()));
        finish(zombie);
        errno = 0;
        result("reaped-group", setpgid(member, zombie));
        result("errno", errno);
        if (write(release[1], "x", 1) != 1) return 85;
        finish(member);
        return 0;
    }
    if (!strcmp(mode, "session")) {
        /* setsid in a child, which is not a group leader; what each check
           gives is a bit, sent back through a pipe. */
        int bits_pipe[2], go[2];
        if (pipe(bits_pipe) || pipe(go)) return 81;
        fflush(stdout);
        pid_t pid = child();
        if (pid == 0) {
            int bits = 0, n = 0, status;
            char byte;
#define BIT(check) (bits |= (!!(check)) << n++)
            BIT(getsid(0) == getsid(getppid()));
            BIT(getpgrp() != getpid());
            pid_t parent_group = getpgid(getppid());
            BIT(setsid() == getpid());
            BIT(getsid(0) == getpid() && getpgrp() == getpid());
            errno = 0;
            BIT(setsid() == -1 && errno == EPERM);
            errno = 0;
            BIT(setpgid(0, 0) == -1 && errno == EPERM); /* a session leader */
            int release[2];
            if (pipe(release)) _exit(81);
            pid_t member = child();
            if (member == 0) {
                if (read(release[0], &byte, 1) != 1) _exit(1);
                _exit(0);
            }
            BIT(getsid(member) == getpid() && getpgid(member) == getpid());
            errno = 0;
            BIT(setpgid(member, parent_group) == -1 && errno == EPERM); /* another session's group */
            BIT(setpgid(member, member) == 0 && getpgid(member) == member);
            BIT(setpgid(member, getpid()) == 0 && getpgid(member) == getpid());
            if (write(release[1], "x", 1) != 1) _exit(82);
            BIT(waitpid(member, &status, 0) == member && status == 0);
            /* A process whose PID names a group cannot start a session. */
            pid_t leader = child();
            if (leader == 0) {
                if (setpgid(0, 0)) _exit(2);
                errno = 0;
                _exit(setsid() == -1 && errno == EPERM ? 0 : 1);
            }
            BIT(waitpid(leader, &status, 0) == leader && status == 0);
            /* A member of a session can start its own. */
            pid_t starter = child();
            if (starter == 0) _exit(setsid() == getpid() && getsid(getppid()) == getppid() ? 0 : 1);
            BIT(waitpid(starter, &status, 0) == starter && status == 0);
#undef BIT
            if (write(bits_pipe[1], &bits, sizeof bits) != sizeof bits) _exit(83);
            if (read(go[0], &byte, 1) != 1) _exit(84);
            _exit(0);
        }
        int bits = 0;
        if (read(bits_pipe[0], &bits, sizeof bits) != sizeof bits) return 82;
        result("child", bits);
        result("child-sid", getsid(pid) == pid);
        errno = 0;
        result("other-session", setpgid(pid, getpgrp()));
        result("errno", errno);
        if (write(go[1], "x", 1) != 1) return 83;
        finish(pid);
        errno = 0;
        result("getsid-missing", getsid(0x3fffffff));
        result("errno", errno);
        result("getsid-self", getsid(0) == getsid(getpid()));
        return 0;
    }
    if (!strcmp(mode, "sysinfo")) {
        struct sysinfo info;
        result("sysinfo", sysinfo(&info));
        result("unit", info.mem_unit >= 1);
        result("ram", info.totalram > 0 && info.freeram <= info.totalram);
        result("procs", info.procs >= 1);
        errno = 0;
        result("fault", syscall(SYS_sysinfo, (void *)1));
        result("errno", errno);
        result("yield", sched_yield());
        result("groups", getgroups(0, NULL) >= 0);
        errno = 0;
        result("negative-groups", syscall(SYS_getgroups, -1, NULL));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "seqpacket")) {
        int pair[2];
        result("socketpair", socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair));
        result("first", write(pair[0], "abc", 3));
        result("empty", write(pair[0], "", 0));
        result("second", write(pair[0], "defgh", 5));
        char buf[8] = {0};
        result("truncated", read(pair[1], buf, 2));
        result("start", buf[0] == 'a' && buf[1] == 'b');
        result("empty-read", read(pair[1], buf, 0));
        result("empty-message", read(pair[1], buf, sizeof buf));
        result("whole", read(pair[1], buf, sizeof buf));
        result("bytes", !memcmp(buf, "defgh", 5));
        fcntl(pair[1], F_SETFL, O_NONBLOCK);
        errno = 0;
        result("drained", read(pair[1], buf, sizeof buf));
        result("errno", errno);
        static char large[212961];
        errno = 0;
        result("too-large", write(pair[0], large, sizeof large));
        result("errno", errno);
        result("largest", write(pair[0], large, sizeof large - 1));
        result("read-largest", read(pair[1], large, sizeof large));
        close(pair[0]);
        result("eof", read(pair[1], buf, sizeof buf));
        close(pair[1]);
        return 0;
    }
    if (!strcmp(mode, "dgram")) {
        /* SIGPIPE comes only from SOCK_STREAM; count it instead of dying. */
        signal(SIGPIPE, interrupted);
        int pair[2];
        char buf[8] = {0};
        result("socketpair", socketpair(AF_UNIX, SOCK_DGRAM, 0, pair));
        result("first", write(pair[0], "abc", 3));
        result("empty", write(pair[0], "", 0));
        result("truncated", read(pair[1], buf, 2));
        result("start", buf[0] == 'a' && buf[1] == 'b');
        result("empty-message", read(pair[1], buf, sizeof buf));
        static char large[212961];
        errno = 0;
        result("too-large", write(pair[0], large, sizeof large));
        result("errno", errno);
        struct pollfd poll_fd = {pair[1], POLLIN | POLLOUT, 0};
        result("poll", poll(&poll_fd, 1, 0));
        result("revents", poll_fd.revents);
        /* A shutdown is this side's own: the peer still writes and gets no end of file. */
        result("shut-wr", shutdown(pair[0], SHUT_WR));
        errno = 0;
        result("after-shut-wr", write(pair[0], "x", 1));
        result("errno", errno);
        result("peer-writes", write(pair[1], "y", 1));
        result("read-own", read(pair[0], buf, sizeof buf));
        fcntl(pair[1], F_SETFL, O_NONBLOCK);
        errno = 0;
        result("no-eof", read(pair[1], buf, sizeof buf));
        result("errno", errno);
        result("shut-rd", shutdown(pair[1], SHUT_RD));
        poll_fd.revents = 0;
        result("poll-shut-rd", poll(&poll_fd, 1, 0));
        result("revents", poll_fd.revents);
        errno = 0;
        result("shut-rd-nonblocking", read(pair[1], buf, sizeof buf));
        result("errno", errno);
        fcntl(pair[1], F_SETFL, 0);
        result("shut-rd-blocking", read(pair[1], buf, sizeof buf));
        int closed[2];
        socketpair(AF_UNIX, SOCK_DGRAM, 0, closed);
        write(closed[1], "zz", 2);
        close(closed[1]);
        result("queued-after-close", read(closed[0], buf, sizeof buf));
        fcntl(closed[0], F_SETFL, O_NONBLOCK);
        errno = 0;
        result("no-eof-after-close", read(closed[0], buf, sizeof buf));
        result("errno", errno);
        struct pollfd closed_poll = {closed[0], POLLIN | POLLOUT, 0};
        result("poll-closed", poll(&closed_poll, 1, 0));
        result("revents", closed_poll.revents);
        errno = 0;
        result("refused", write(closed[0], "q", 1));
        result("errno", errno);
        errno = 0;
        result("not-connected", write(closed[0], "q", 1));
        result("errno", errno);
        int reader_shut[2];
        socketpair(AF_UNIX, SOCK_DGRAM, 0, reader_shut);
        shutdown(reader_shut[1], SHUT_RD);
        errno = 0;
        result("to-shut-rd", write(reader_shut[0], "a", 1));
        result("errno", errno);
        int packets[2];
        socketpair(AF_UNIX, SOCK_SEQPACKET, 0, packets);
        close(packets[1]);
        errno = 0;
        result("seqpacket-closed", write(packets[0], "a", 1));
        result("errno", errno);
        result("sigpipes", received);
        int stream[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, stream);
        close(stream[1]);
        errno = 0;
        result("stream-closed", write(stream[0], "a", 1));
        result("errno", errno);
        result("stream-sigpipes", received);
        return 0;
    }
    if (!strcmp(mode, "posix-timer")) {
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        sigprocmask(SIG_BLOCK, &set, NULL);
        struct sigevent event = {0};
        event.sigev_notify = SIGEV_SIGNAL;
        event.sigev_signo = SIGUSR1;
        event.sigev_value.sival_int = 42;
        timer_t timer;
        result("create", timer_create(CLOCK_MONOTONIC, &event, &timer));
        struct itimerspec once = {{0, 0}, {0, 20000000}}, now;
        result("arm", timer_settime(timer, 0, &once, NULL));
        struct timespec limit = {5, 0};
        siginfo_t info;
        result("signal", sigtimedwait(&set, &info, &limit));
        result("code", info.si_code == SI_TIMER);
        result("value", info.si_value.sival_int);
        result("timer-id", info.si_timerid == (int)(intptr_t)timer);
        result("disarmed", timer_gettime(timer, &now) == 0 && now.it_value.tv_sec == 0 && now.it_value.tv_nsec == 0);
        /* An interval timer whose signal stays blocked counts overruns. */
        struct itimerspec every = {{0, 10000000}, {0, 10000000}};
        result("interval", timer_settime(timer, 0, &every, NULL));
        struct timespec pause_for = {0, 80000000};
        nanosleep(&pause_for, NULL);
        result("repeated", sigtimedwait(&set, &info, &limit));
        result("overrun", info.si_overrun > 0);
        result("armed", timer_gettime(timer, &now) == 0 && now.it_interval.tv_nsec == 10000000);
        result("delete", timer_delete(timer));
        struct timespec zero = {0, 0};
        errno = 0;
        result("drained", sigtimedwait(&set, &info, &zero));
        result("errno", errno);
        errno = 0;
        result("bad-clock", syscall(SYS_timer_create, 99, NULL, &timer));
        result("errno", errno);
        event.sigev_signo = 99;
        errno = 0;
        int id;
        result("bad-signal", syscall(SYS_timer_create, CLOCK_MONOTONIC, &event, &id));
        result("errno", errno);
        errno = 0;
        result("bad-timer", syscall(SYS_timer_settime, 0x3ffff, 0, &once, NULL));
        result("errno", errno);
        errno = 0;
        result("bad-delete", syscall(SYS_timer_delete, (int)(intptr_t)timer));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "prctl")) {
        int value = -1;
        result("pdeathsig", prctl(PR_SET_PDEATHSIG, SIGUSR1));
        prctl(PR_GET_PDEATHSIG, &value);
        result("pdeathsig-value", value);
        result("dumpable", prctl(PR_GET_DUMPABLE));
        result("not-dumpable", prctl(PR_SET_DUMPABLE, 0));
        result("dumpable-now", prctl(PR_GET_DUMPABLE));
        errno = 0;
        result("bad-dumpable", prctl(PR_SET_DUMPABLE, 2));
        result("errno", errno);
        result("no-new-privs", prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
        result("no-new-privs-now", prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
        errno = 0;
        result("bad-signal", prctl(PR_SET_PDEATHSIG, 65));
        result("errno", errno);
        errno = 0;
        result("unknown", prctl(9999));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "thread-name")) {
        /* The first name comes from the executable's path, which differs. */
        char name[16];
        result("set", prctl(PR_SET_NAME, "paludarium-guest-name"));
        memset(name, 'x', sizeof name);
        result("get", prctl(PR_GET_NAME, name));
        result("truncated", !strcmp(name, "paludarium-gues"));
        result("short", prctl(PR_SET_NAME, "ab"));
        memset(name, 'x', sizeof name);
        prctl(PR_GET_NAME, name);
        result("cleared", !strcmp(name, "ab") && name[3] == 0 && name[15] == 0);
        errno = 0;
        result("set-fault", prctl(PR_SET_NAME, (char *)1));
        result("errno", errno);
        errno = 0;
        result("get-fault", prctl(PR_GET_NAME, (char *)1));
        result("errno", errno);
        pthread_t worker;
        pthread_create(&worker, NULL, name_reader, NULL);
        pthread_join(worker, NULL);
        result("thread-inherits", !strcmp(thread_name, "ab"));
        prctl(PR_GET_NAME, name);
        result("own-name-kept", !strcmp(name, "ab"));
        pid_t pid = child();
        if (pid == 0) {
            prctl(PR_GET_NAME, name);
            _exit(!strcmp(name, "ab") ? 5 : 6);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        result("fork-inherits", WEXITSTATUS(status));
        return 0;
    }
    if (!strcmp(mode, "timer-thread")) {
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        sigprocmask(SIG_BLOCK, &set, NULL);
        if (pipe(timer_report)) return 81;
        pthread_t waiter;
        pthread_create(&waiter, NULL, timer_waiter, NULL);
        int tid = 0;
        read(timer_report[0], &tid, sizeof tid);
        struct thread_event event = {7, SIGUSR1, 4, tid, {0}};
        int timer = -1;
        result("create", syscall(SYS_timer_create, CLOCK_MONOTONIC, &event, &timer));
        struct itimerspec once = {{0, 0}, {0, 20000000}};
        result("arm", syscall(SYS_timer_settime, timer, 0, &once, NULL));
        int got[3] = {0};
        read(timer_report[0], got, sizeof got);
        pthread_join(waiter, NULL);
        result("signal", got[0]);
        result("code", got[1] == SI_TIMER);
        result("value", got[2]);
        sigset_t pending;
        sigpending(&pending);
        result("not-for-main", sigismember(&pending, SIGUSR1));
        result("delete", syscall(SYS_timer_delete, timer));
        /* The thread must be in this thread group; a bad notify is EINVAL. */
        struct thread_event elsewhere = {0, SIGUSR1, 4, 999999, {0}};
        errno = 0;
        result("other-thread", syscall(SYS_timer_create, CLOCK_MONOTONIC, &elsewhere, &timer));
        result("errno", errno);
        struct thread_event bad_signal = {0, 0, 4, (int)syscall(SYS_gettid), {0}};
        errno = 0;
        result("bad-signal", syscall(SYS_timer_create, CLOCK_MONOTONIC, &bad_signal, &timer));
        result("errno", errno);
        struct thread_event mixed = {0, SIGUSR1, 6, (int)syscall(SYS_gettid), {0}};
        errno = 0;
        result("bad-notify", syscall(SYS_timer_create, CLOCK_MONOTONIC, &mixed, &timer));
        result("errno", errno);
        /* The kernel takes SIGEV_THREAD as a signal to the process. */
        struct thread_event as_signal = {0, SIGUSR1, 2, 0, {0}};
        result("sigev-thread", syscall(SYS_timer_create, CLOCK_MONOTONIC, &as_signal, &timer));
        result("delete-sigev-thread", syscall(SYS_timer_delete, timer));
        return 0;
    }
    if (!strcmp(mode, "ignore-discards")) {
        /* Making a signal ignored discards its pending instances, and only
           those: one sent while ignored and blocked stays pending. SIG_DFL
           discards a signal whose default is to ignore it. */
        sigset_t set, pending;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        sigaddset(&set, SIGUSR2);
        sigaddset(&set, SIGURG);
        sigprocmask(SIG_BLOCK, &set, NULL);
        raise(SIGUSR1);
        signal(SIGUSR1, SIG_IGN);
        sigpending(&pending);
        result("ignored", sigismember(&pending, SIGUSR1));
        raise(SIGUSR1);
        sigpending(&pending);
        result("sent-while-ignored", sigismember(&pending, SIGUSR1));
        signal(SIGUSR1, SIG_DFL);
        sigpending(&pending);
        result("default-terminate", sigismember(&pending, SIGUSR1));
        raise(SIGURG);
        signal(SIGURG, SIG_DFL);
        sigpending(&pending);
        result("default-ignore", sigismember(&pending, SIGURG));
        signal(SIGUSR1, SIG_IGN);
        /* A signal another thread already has pending goes too. */
        pthread_t reader;
        char byte;
        if (pipe(discard_go) || pipe(discard_done) || pthread_create(&reader, NULL, discard_reader, NULL)) return 84;
        pthread_kill(reader, SIGUSR2);
        if (write(discard_go[1], "x", 1) != 1 || read(discard_done[0], &byte, 1) != 1) return 85;
        signal(SIGUSR2, SIG_IGN);
        if (write(discard_go[1], "x", 1) != 1 || read(discard_done[0], &byte, 1) != 1) return 86;
        pthread_join(reader, NULL);
        return 0;
    }
    if (!strcmp(mode, "waitid")) {
        siginfo_t info;
        pid_t pid = child();
        if (pid == 0) _exit(5);
        memset(&info, 0x55, sizeof info);
        result("nowait", waitid(P_PID, pid, &info, WEXITED | WNOWAIT));
        result("signo", info.si_signo);
        result("code", info.si_code);
        result("pid", info.si_pid == pid);
        result("status", info.si_status);
        result("uid", info.si_uid == getuid());
        result("again", waitid(P_PID, pid, &info, WEXITED));
        result("status", info.si_status);
        pid = child();
        if (pid == 0) {
            pause();
            _exit(0);
        }
        kill(pid, SIGTERM);
        /* Without WEXITED an exited child cannot be waited for (ECHILD), and
           stays for a later wait (brush asks for WSTOPPED alone). */
        siginfo_t stopped;
        while (waitid(P_PID, pid, &stopped, WEXITED | WNOHANG | WNOWAIT) == 0 && stopped.si_pid == 0)
            sched_yield();
        errno = 0;
        result("stopped-only", waitid(P_PID, pid, &stopped, WSTOPPED | WNOHANG));
        result("errno", errno);
        result("killed", waitid(P_ALL, 0, &info, WEXITED));
        result("code", info.si_code);
        result("status", info.si_status);
        /* Nothing to report: the fields are zero, and so they are on an error. */
        int gate[2];
        pid = gated(gate, 6);
        memset(&info, 0x55, sizeof info);
        result("nohang", waitid(P_PID, pid, &info, WEXITED | WNOHANG));
        result("nohang-cleared", info.si_signo == 0 && info.si_pid == 0 && info.si_status == 0);
        memset(&info, 0x55, sizeof info);
        errno = 0;
        result("bad-pid", waitid(P_PID, 0, &info, WEXITED));
        result("errno", errno);
        result("error-cleared", info.si_signo == 0 && info.si_code == 0 && info.si_pid == 0);
        errno = 0;
        result("no-options", waitid(P_ALL, 0, &info, 0));
        result("errno", errno);
        errno = 0;
        result("bad-option", waitid(P_ALL, 0, &info, WEXITED | 0x10));
        result("errno", errno);
        errno = 0;
        result("bad-type", syscall(SYS_waitid, 9, 0, &info, WEXITED, NULL));
        result("errno", errno);
        errno = 0;
        result("bad-pidfd", syscall(SYS_waitid, 3, 0, &info, WEXITED, NULL));
        result("errno", errno);
        write(gate[1], "x", 1);
        result("gated", waitid(P_PID, pid, &info, WEXITED));
        result("status", info.si_status);
        errno = 0;
        result("no-children", waitid(P_ALL, 0, &info, WEXITED));
        result("errno", errno);
        /* Process groups, through waitid and wait4. */
        pid = gated(gate, 3);
        setpgid(pid, pid);
        write(gate[1], "x", 1);
        result("pgid", waitid(P_PGID, pid, &info, WEXITED));
        result("status", info.si_status);
        pid = gated(gate, 4);
        setpgid(pid, pid);
        write(gate[1], "x", 1);
        int status = 0;
        result("wait-pgid", waitpid(-pid, &status, 0) == pid);
        result("status", WEXITSTATUS(status));
        pid = gated(gate, 8);
        write(gate[1], "x", 1);
        result("wait-own-group", waitpid(0, &status, 0) == pid);
        result("status", WEXITSTATUS(status));
        /* pidfds: readable after the exit, waitable, and EAGAIN when nonblocking. */
        pid = gated(gate, 7);
        int pidfd = syscall(SYS_pidfd_open, pid, 0);
        result("pidfd", pidfd >= 0);
        result("cloexec", fcntl(pidfd, F_GETFD) & FD_CLOEXEC);
        struct pollfd ready = {pidfd, POLLIN, 0};
        result("running", poll(&ready, 1, 0));
        int nonblocking = syscall(SYS_pidfd_open, pid, PIDFD_NONBLOCK);
        errno = 0;
        result("nonblocking", syscall(SYS_waitid, P_PIDFD, nonblocking, &info, WEXITED, NULL));
        result("errno", errno);
        char byte;
        errno = 0;
        result("read", read(pidfd, &byte, 1));
        result("errno", errno);
        write(gate[1], "x", 1);
        /* epoll waits for the exit (Tokio's reaper does so); no timeout, as
           the emulated harness runs a virtual clock. */
        int epoll = epoll_create1(EPOLL_CLOEXEC);
        struct epoll_event watch = {.events = EPOLLIN, .data.u64 = 42}, seen = {0};
        epoll_ctl(epoll, EPOLL_CTL_ADD, pidfd, &watch);
        result("exited", epoll_wait(epoll, &seen, 1, -1));
        result("readable", (seen.events & EPOLLIN) && seen.data.u64 == 42);
        close(epoll);
        result("by-pidfd", syscall(SYS_waitid, P_PIDFD, pidfd, &info, WEXITED, NULL));
        result("status", info.si_status);
        errno = 0;
        result("signal-reaped", syscall(SYS_pidfd_send_signal, pidfd, SIGTERM, NULL, 0));
        result("errno", errno);
        close(nonblocking);
        close(pidfd);
        pid = gated(gate, 0);
        pidfd = syscall(SYS_pidfd_open, pid, 0);
        errno = 0;
        result("signal-flags", syscall(SYS_pidfd_send_signal, pidfd, SIGTERM, NULL, 8));
        result("errno", errno);
        result("signal", syscall(SYS_pidfd_send_signal, pidfd, SIGTERM, NULL, 0));
        result("signalled", waitid(P_PID, pid, &info, WEXITED));
        result("status", info.si_status);
        close(pidfd);
        close(gate[1]);
        errno = 0;
        result("open-zero", syscall(SYS_pidfd_open, 0, 0));
        result("errno", errno);
        errno = 0;
        result("open-flags", syscall(SYS_pidfd_open, getpid(), 1));
        result("errno", errno);
        errno = 0;
        result("open-missing", syscall(SYS_pidfd_open, 999999, 0));
        result("errno", errno);
        pipe(tid_report);
        pipe(tid_release);
        pthread_t thread;
        pthread_create(&thread, NULL, parked, NULL);
        int tid = 0;
        read(tid_report[0], &tid, sizeof tid);
        errno = 0;
        result("open-thread", syscall(SYS_pidfd_open, tid, 0));
        result("errno", errno);
        write(tid_release[1], "x", 1);
        pthread_join(thread, NULL);
        return 0;
    }
    if (!strcmp(mode, "pio")) {
        /* pread64, pwrite64, readv, preadv and pwritev: positioned calls leave
           the file position; errors come in Linux's order. */
        char buf[32] = {0};
        int fd = open("/tmp/pio", O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (fd < 0 || write(fd, "abcdefgh", 8) != 8) return 81;
        lseek(fd, 2, SEEK_SET);
        result("pread", pread(fd, buf, 3, 4));
        result("pread-bytes", !memcmp(buf, "efg", 3));
        result("position", lseek(fd, 0, SEEK_CUR));
        result("pwrite", pwrite(fd, "XY", 2, 6));
        result("position", lseek(fd, 0, SEEK_CUR));
        memset(buf, 0, sizeof buf);
        result("whole", pread(fd, buf, sizeof buf, 0));
        result("whole-bytes", !memcmp(buf, "abcdefXY", 8));
        result("gap", pwrite(fd, "Q", 1, 10));
        memset(buf, 1, sizeof buf);
        result("gap-read", pread(fd, buf, sizeof buf, 7));
        result("gap-bytes", buf[0] == 'Y' && buf[1] == 0 && buf[2] == 0 && buf[3] == 'Q');
        result("past-end", pread(fd, buf, 4, 100));
        result("empty", pread(fd, buf, 0, 0));
        struct iovec parts[2] = {{buf, 2}, {buf + 8, 3}};
        memset(buf, 0, sizeof buf);
        result("preadv", preadv(fd, parts, 2, 1));
        result("preadv-bytes", !memcmp(buf, "bc", 2) && !memcmp(buf + 8, "def", 3));
        struct iovec out[2] = {{"12", 2}, {"345", 3}};
        result("pwritev", pwritev(fd, out, 2, 0));
        result("position", lseek(fd, 0, SEEK_CUR));
        memset(buf, 0, sizeof buf);
        pread(fd, buf, 8, 0);
        result("pwritev-bytes", !memcmp(buf, "12345fXY", 8));
        errno = 0;
        result("negative", pread(fd, buf, 1, -1));
        result("errno", errno);
        errno = 0;
        result("negative-bad-fd", pread(99, buf, 1, -1));
        result("errno", errno);
        errno = 0;
        result("bad-fd", pread(99, buf, 1, 0));
        result("errno", errno);
        errno = 0;
        result("preadv-negative", preadv(fd, parts, 2, -5));
        result("errno", errno);
        errno = 0;
        result("too-many", preadv(fd, parts, 1025, 0));
        result("errno", errno);
        result("none", preadv(fd, parts, 0, 0));
        close(fd);
        /* A read-only and a write-only file, an append-mode file, a directory. */
        fd = open("/tmp/pio", O_RDONLY);
        errno = 0;
        result("pwrite-read-only", pwrite(fd, "x", 1, 0));
        result("errno", errno);
        close(fd);
        fd = open("/tmp/pio", O_WRONLY);
        errno = 0;
        result("pread-write-only", pread(fd, buf, 1, 0));
        result("errno", errno);
        /* The access mode is checked before the iovec array. */
        errno = 0;
        result("preadv-write-only-too-many", preadv(fd, parts, 1025, 0));
        result("errno", errno);
        close(fd);
        fd = open("/tmp/pio", O_RDWR | O_APPEND);
        result("append", pwrite(fd, "Z", 1, 0));
        result("append-position", lseek(fd, 0, SEEK_CUR));
        memset(buf, 0, sizeof buf);
        result("append-size", pread(fd, buf, sizeof buf, 0));
        result("append-last", buf[11]);
        close(fd);
        fd = open("/tmp", O_RDONLY | O_DIRECTORY);
        errno = 0;
        result("directory", pread(fd, buf, 1, 0));
        result("errno", errno);
        close(fd);
        /* Pipes have no position; readv gathers what one read gives. */
        int pipefd[2];
        if (pipe(pipefd)) return 82;
        errno = 0;
        result("pipe-pread", pread(pipefd[0], buf, 1, 0));
        result("errno", errno);
        errno = 0;
        result("pipe-pwrite", pwrite(pipefd[1], "x", 1, 0));
        result("errno", errno);
        if (write(pipefd[1], "hello world", 11) != 11) return 83;
        struct iovec two[2] = {{buf, 5}, {buf + 16, 6}};
        memset(buf, 0, sizeof buf);
        result("readv", readv(pipefd[0], two, 2));
        result("readv-bytes", !memcmp(buf, "hello", 5) && !memcmp(buf + 16, " world", 6));
        errno = 0;
        result("readv-too-many", readv(pipefd[0], two, 1025));
        result("errno", errno);
        errno = 0;
        result("readv-write-end", readv(pipefd[1], two, 2));
        result("errno", errno);
        errno = 0;
        result("readv-write-end-too-many", readv(pipefd[1], two, 1025));
        result("errno", errno);
        /* /dev/null reads nothing and takes everything at any offset. */
        fd = open("/dev/null", O_RDWR);
        result("null-pread", pread(fd, buf, 4, 3));
        result("null-pwrite", pwrite(fd, "abc", 3, 7));
        close(fd);
        unlink("/tmp/pio");
        return 0;
    }
    if (!strcmp(mode, "stop-restart")) {
        /* A child blocked in read, then in poll with no timeout, then in
           nanosleep, poll with a timeout, an absolute clock_nanosleep and a
           timed futex wait, is
           stopped and continued: each call runs again (the timed ones with
           the time they had left) instead of failing with EINTR, as no
           handler ran. The child says "ready" before each call; a stop
           that lands before the call is entered changes nothing. */
        int ready[2], data[2];
        if (pipe(ready) || pipe(data)) return 81;
        pid_t pid = child();
        if (pid == 0) {
            char byte;
            if (write(ready[1], "r", 1) != 1) _exit(82);
            ssize_t n = read(data[0], &byte, 1);
            if (n != 1) _exit(n < 0 && errno == EINTR ? 83 : 84);
            if (write(ready[1], "p", 1) != 1) _exit(85);
            struct pollfd pfd = {data[0], POLLIN, 0};
            int r = poll(&pfd, 1, -1);
            if (r != 1) _exit(r < 0 && errno == EINTR ? 86 : 87);
            /* Timed waits resume with the time they had left. */
            if (read(data[0], &byte, 1) != 1) _exit(88);
            if (write(ready[1], "s", 1) != 1) _exit(89);
            struct timespec sleep = {0, 300000000};
            if (nanosleep(&sleep, NULL)) _exit(90);
            if (write(ready[1], "t", 1) != 1) _exit(91);
            r = poll(&pfd, 1, 300);
            if (r != 0) _exit(r < 0 ? (errno == EINTR ? 95 : 96) : 92);
            if (write(ready[1], "a", 1) != 1) _exit(93);
            struct timespec until;
            clock_gettime(CLOCK_MONOTONIC, &until);
            until.tv_nsec += 300000000;
            if (until.tv_nsec >= 1000000000) { until.tv_sec++; until.tv_nsec -= 1000000000; }
            if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &until, NULL)) _exit(94);
            /* A timed futex wait nobody wakes ends with ETIMEDOUT, not EINTR. */
            if (write(ready[1], "f", 1) != 1) _exit(99);
            static int word;
            struct timespec wait = {0, 300000000};
            long f = syscall(SYS_futex, &word, 128 /* FUTEX_WAIT_PRIVATE */, 0, &wait, NULL, 0);
            if (f != -1 || errno != ETIMEDOUT) _exit(f == -1 && errno == EINTR ? 100 : 101);
            /* Wait for the parent, so that a sleep which ends before the stop
               (the emulated harness's clock is virtual) cannot exit early. */
            if (read(data[0], &byte, 1) != 1) _exit(97);
            _exit(0);
        }
        /* Only the child writes ready and reads data, so an early exit of
           the child ends the parent's read instead of hanging it. */
        close(ready[1]);
        close(data[0]);
        signal(SIGPIPE, SIG_IGN);
        int status;
        char byte;
        for (int round = 0; round < 6; round++) {
            if (read(ready[0], &byte, 1) != 1) break;
            struct timespec nap = {0, 20000000};
            nanosleep(&nap, NULL);
            kill(pid, SIGSTOP);
            result("stopped", waitpid(pid, &status, WUNTRACED) == pid && WIFSTOPPED(status));
            kill(pid, SIGCONT);
            result("continued", waitpid(pid, &status, WCONTINUED) == pid && WIFCONTINUED(status));
            /* A byte for the read, then one for the poll (read after it). */
            if (round < 2 && write(data[1], "x", 1) != 1) break;
        }
        if (write(data[1], "z", 1) != 1) return 98;
        result("exited", waitpid(pid, &status, 0) == pid);
        result("code", WEXITSTATUS(status));
        return 0;
    }
    if (!strcmp(mode, "sigsuspend")) {
        /* rt_sigsuspend swaps in its mask until a handler has run, then the
           old mask is back; pause waits with the mask as it is. Neither
           ends for an ignored signal. */
        struct sigaction act = {0};
        act.sa_handler = note_mask;
        sigaction(SIGUSR1, &act, NULL);
        signal(SIGHUP, SIG_IGN);
        sigset_t usr1, suspend, now;
        sigemptyset(&usr1);
        sigaddset(&usr1, SIGUSR1);
        sigprocmask(SIG_BLOCK, &usr1, NULL);
        pid_t pid = pester(SIGUSR1);
        sigemptyset(&suspend);
        sigaddset(&suspend, SIGUSR2);
        errno = 0;
        result("suspend", sigsuspend(&suspend));
        result("errno", errno);
        result("received", received >= 1);
        result("usr2-blocked-in-handler", usr2_blocked_in_handler);
        sigprocmask(SIG_BLOCK, NULL, &now);
        result("usr1-blocked-after", sigismember(&now, SIGUSR1));
        result("usr2-blocked-after", sigismember(&now, SIGUSR2));
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        /* pause: SIGHUP (ignored) arrives first and does not end it. */
        received = 0;
        sigprocmask(SIG_UNBLOCK, &usr1, NULL);
        kill(getpid(), SIGHUP);
        pid = pester(SIGUSR1);
        errno = 0;
        result("pause", pause());
        result("errno", errno);
        result("received", received >= 1);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        errno = 0;
        result("bad-size", syscall(SYS_rt_sigsuspend, &suspend, 7));
        result("errno", errno);
        errno = 0;
        result("bad-mask", syscall(SYS_rt_sigsuspend, (void *)16, 8));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "select")) {
        /* select, pselect6 and ppoll: ready sets, timeouts written back with
           the time left (none for a zero timeout), errors in Linux's order,
           and a temporary signal mask that a handler runs with. The calls
           with a timeout are raw syscalls: musl passes the kernel a copy of
           the timeout, so its wrappers never show the written-back time. */
        int p[2];
        if (pipe(p)) return 81;
        fd_set r, w, e;
        FD_ZERO(&r); FD_SET(p[0], &r);
        struct timeval zero = {0, 0};
        result("empty", syscall(SYS_select, p[0] + 1, &r, NULL, NULL, &zero));
        result("empty-cleared", !FD_ISSET(p[0], &r));
        result("zero-kept", zero.tv_sec == 0 && zero.tv_usec == 0);
        if (write(p[1], "x", 1) != 1) return 82;
        FD_ZERO(&r); FD_ZERO(&w); FD_ZERO(&e);
        FD_SET(p[0], &r); FD_SET(p[1], &w); FD_SET(p[0], &e);
        struct timeval five = {5, 0};
        result("ready", syscall(SYS_select, p[1] + 1, &r, &w, &e, &five));
        result("read", FD_ISSET(p[0], &r));
        result("write", FD_ISSET(p[1], &w));
        result("except", FD_ISSET(p[0], &e));
        long left = five.tv_sec * 1000000L + five.tv_usec;
        result("left", left > 4000000 && left <= 5000000);
        char byte;
        if (read(p[0], &byte, 1) != 1) return 83;
        FD_ZERO(&r); FD_SET(p[0], &r);
        struct timeval short_wait = {0, 20000};
        result("timeout", syscall(SYS_select, p[0] + 1, &r, NULL, NULL, &short_wait));
        result("timeout-left", short_wait.tv_sec == 0 && short_wait.tv_usec == 0);
        FD_ZERO(&r); FD_SET(60, &r);
        errno = 0;
        result("closed", select(61, &r, NULL, NULL, &zero));
        result("errno", errno);
        errno = 0;
        result("negative", select(-1, NULL, NULL, NULL, &zero));
        result("errno", errno);
        /* Whole seconds of microseconds carry into the seconds; a negative
           part is EINVAL. */
        struct timeval carry = {0, 1000000};
        result("carried-timeval", syscall(SYS_select, 1, NULL, NULL, NULL, &carry));
        struct timeval bad = {0, -1};
        errno = 0;
        result("bad-timeval", syscall(SYS_select, 1, NULL, NULL, NULL, &bad));
        result("errno", errno);
        /* ppoll */
        struct pollfd pfd = {p[0], POLLIN, 0};
        struct timespec ts = {0, 20000000};
        result("ppoll-timeout", syscall(SYS_ppoll, &pfd, 1, &ts, NULL, 8));
        result("ppoll-left", ts.tv_sec == 0 && ts.tv_nsec == 0);
        if (write(p[1], "y", 1) != 1) return 84;
        struct timespec ten = {10, 0};
        result("ppoll-ready", syscall(SYS_ppoll, &pfd, 1, &ten, NULL, 8));
        result("ppoll-revents", pfd.revents);
        long ns_left = ten.tv_sec * 1000000000L + ten.tv_nsec;
        result("ppoll-left-ready", ns_left > 9000000000L && ns_left <= 10000000000L);
        struct timespec bad_ts = {0, 1000000000};
        errno = 0;
        result("ppoll-bad-timespec", ppoll(&pfd, 1, &bad_ts, NULL));
        result("errno", errno);
        errno = 0;
        result("ppoll-bad-size", syscall(SYS_ppoll, &pfd, 1, NULL, &ten, 7));
        result("errno", errno);
        /* A blocked SIGUSR1 is let in by the temporary mask; the handler runs
           with it (SIGUSR2 blocked), and the old mask is back afterwards. */
        struct sigaction act = {0};
        act.sa_handler = note_mask;
        sigaction(SIGUSR1, &act, NULL);
        sigset_t usr1, temporary, now;
        sigemptyset(&usr1);
        sigaddset(&usr1, SIGUSR1);
        sigprocmask(SIG_BLOCK, &usr1, NULL);
        sigemptyset(&temporary);
        sigaddset(&temporary, SIGUSR2);
        if (read(p[0], &byte, 1) != 1) return 85;
        raise(SIGUSR1);
        received = 0;
        errno = 0;
        result("ppoll-signal", ppoll(&pfd, 1, NULL, &temporary));
        result("errno", errno);
        result("received", received);
        result("usr2-blocked-in-handler", usr2_blocked_in_handler);
        sigprocmask(SIG_BLOCK, NULL, &now);
        result("usr1-blocked-after", sigismember(&now, SIGUSR1));
        raise(SIGUSR1);
        received = 0;
        usr2_blocked_in_handler = -1;
        FD_ZERO(&r); FD_SET(p[0], &r);
        errno = 0;
        result("pselect-signal", pselect(p[0] + 1, &r, NULL, NULL, NULL, &temporary));
        result("errno", errno);
        result("received", received);
        result("usr2-blocked-in-handler", usr2_blocked_in_handler);
        sigprocmask(SIG_BLOCK, NULL, &now);
        result("usr1-blocked-after", sigismember(&now, SIGUSR1));
        struct timespec pzero = {0, 0};
        FD_ZERO(&r); FD_SET(p[0], &r);
        result("pselect-empty", syscall(SYS_pselect6, p[0] + 1, &r, NULL, NULL, &pzero, NULL));
        result("pselect-zero-kept", pzero.tv_sec == 0 && pzero.tv_nsec == 0);
        struct timespec pshort = {0, 20000000};
        FD_ZERO(&r); FD_SET(p[0], &r);
        result("pselect-timeout", syscall(SYS_pselect6, p[0] + 1, &r, NULL, NULL, &pshort, NULL));
        result("pselect-left", pshort.tv_sec == 0 && pshort.tv_nsec == 0);
        errno = 0;
        result("pselect-bad-timespec", pselect(1, NULL, NULL, NULL, &bad_ts, NULL));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "job-stop")) {
        /* A child stops itself, then is stopped and continued by kill; waits
           report each event once, and SIGCHLD follows unless SA_NOCLDSTOP.
           The child polls its gate, so no blocking call of its is interrupted
           by the stop. */
        sigset_t chld;
        sigemptyset(&chld);
        sigaddset(&chld, SIGCHLD);
        sigprocmask(SIG_BLOCK, &chld, NULL);
        int gate[2];
        if (pipe2(gate, O_NONBLOCK)) return 81;
        pid_t pid = child();
        if (pid == 0) {
            /* Not raise(): after a raw fork glibc's cached tid is the parent's. */
            kill(getpid(), SIGSTOP);
            char byte;
            while (read(gate[0], &byte, 1) != 1) sched_yield();
            _exit(7);
        }
        int status;
        result("untraced", waitpid(pid, &status, WUNTRACED) == pid);
        result("stopped", WIFSTOPPED(status));
        result("stop-signal", WSTOPSIG(status));
        sigset_t pending;
        sigpending(&pending);
        result("sigchld-stop", sigismember(&pending, SIGCHLD));
        siginfo_t info;
        result("sigchld", sigwaitinfo(&chld, &info));
        result("sigchld-code", info.si_code);
        result("sigchld-status", info.si_status);
        result("sigchld-pid", info.si_pid == pid);
        memset(&info, 0x55, sizeof info);
        result("consumed", waitid(P_PID, pid, &info, WSTOPPED | WNOHANG));
        result("consumed-pid", info.si_pid);
        result("not-untraced", waitpid(pid, &status, WNOHANG));
        kill(pid, SIGCONT);
        result("nowait", waitid(P_PID, pid, &info, WCONTINUED | WNOWAIT));
        result("code", info.si_code);
        result("status", info.si_status);
        result("pid", info.si_pid == pid);
        result("continued", waitpid(pid, &status, WCONTINUED) == pid);
        result("ifcontinued", WIFCONTINUED(status));
        result("raw", status);
        result("sigchld-cont", sigwaitinfo(&chld, &info));
        result("sigchld-cont-code", info.si_code);
        result("sigchld-cont-status", info.si_status);
        result("sigchld-cont-pid", info.si_pid == pid);
        result("again", waitpid(pid, &status, WCONTINUED | WNOHANG));
        /* A stop by kill, now with SA_NOCLDSTOP: no SIGCHLD for it. */
        struct sigaction quiet = { .sa_handler = SIG_DFL, .sa_flags = SA_NOCLDSTOP };
        sigaction(SIGCHLD, &quiet, NULL);
        kill(pid, SIGTSTP);
        result("waitid-stop", waitid(P_PID, pid, &info, WSTOPPED));
        result("code", info.si_code);
        result("status", info.si_status);
        kill(pid, SIGCONT);
        result("waitid-cont", waitid(P_ALL, 0, &info, WCONTINUED));
        result("code", info.si_code);
        sigpending(&pending);
        result("sigchld-quiet", sigismember(&pending, SIGCHLD));
        if (write(gate[1], "x", 1) != 1) return 82;
        result("exited", waitpid(pid, &status, 0) == pid);
        result("code", WEXITSTATUS(status));
        /* SA_NOCLDSTOP leaves the SIGCHLD of an exit, and of a kill. */
        result("sigchld-exit", sigwaitinfo(&chld, &info));
        result("sigchld-exit-code", info.si_code);
        result("sigchld-exit-status", info.si_status);
        result("sigchld-exit-pid", info.si_pid == pid);
        pid = child();
        if (pid == 0) {
            for (;;) pause();
        }
        kill(pid, SIGKILL);
        result("killed", waitpid(pid, &status, 0) == pid);
        result("sigchld-kill", sigwaitinfo(&chld, &info));
        result("sigchld-kill-code", info.si_code);
        result("sigchld-kill-status", info.si_status);
        result("sigchld-kill-pid", info.si_pid == pid);
        return 0;
    }
    if (!strcmp(mode, "timerfd")) {
        /* Values that depend on timing are printed only as conditions. */
        errno = 0;
        result("bad-clock", timerfd_create(99, 0));
        result("errno", errno);
        errno = 0;
        result("bad-flags", timerfd_create(CLOCK_MONOTONIC, 1));
        result("errno", errno);
        int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        result("fd", fd >= 0);
        result("getfl", fcntl(fd, F_GETFL));
        result("getfd", fcntl(fd, F_GETFD));
        struct itimerspec value, old;
        memset(&value, 0x55, sizeof value);
        result("gettime", timerfd_gettime(fd, &value));
        result("disarmed", value.it_value.tv_sec == 0 && value.it_value.tv_nsec == 0
                               && value.it_interval.tv_sec == 0 && value.it_interval.tv_nsec == 0);
        uint64_t ticks = 0;
        errno = 0;
        result("empty", read(fd, &ticks, 8));
        result("errno", errno);
        /* Errors, in Linux's order: the value, the flags and times, the fd. */
        struct itimerspec ten = {{0, 0}, {10, 0}};
        errno = 0;
        result("null", timerfd_settime(fd, 0, NULL, NULL));
        result("errno", errno);
        errno = 0;
        result("bad-settime-flags", timerfd_settime(fd, 4, &ten, NULL));
        result("errno", errno);
        struct itimerspec bad = {{0, 0}, {0, 1000000000}};
        errno = 0;
        result("bad-nsec", timerfd_settime(fd, 0, &bad, NULL));
        result("errno", errno);
        errno = 0;
        result("bad-fd", timerfd_settime(99, 0, &bad, NULL));
        result("errno", errno);
        errno = 0;
        result("bad-fd-valid", timerfd_settime(99, 0, &ten, NULL));
        result("errno", errno);
        errno = 0;
        result("not-timer", timerfd_settime(1, 0, &ten, NULL));
        result("errno", errno);
        errno = 0;
        result("not-timer-get", timerfd_gettime(1, &value));
        result("errno", errno);
        /* Ten seconds out: armed, not yet readable. */
        result("arm", timerfd_settime(fd, 0, &ten, NULL));
        timerfd_gettime(fd, &value);
        result("remaining", value.it_value.tv_sec <= 10 && (value.it_value.tv_sec > 0 || value.it_value.tv_nsec > 0));
        errno = 0;
        result("not-yet", read(fd, &ticks, 8));
        result("errno", errno);
        errno = 0;
        result("short", read(fd, &ticks, 7));
        result("errno", errno);
        errno = 0;
        result("write", write(fd, &ticks, 8));
        result("errno", errno);
        /* An absolute time already past fires at once; rearming clears it. */
        struct itimerspec past = {{0, 0}, {0, 1}};
        result("past", timerfd_settime(fd, TFD_TIMER_ABSTIME, &past, &old));
        result("old-interval", old.it_interval.tv_sec == 0 && old.it_interval.tv_nsec == 0);
        result("old-value", old.it_value.tv_sec <= 10);
        struct pollfd pfd = {fd, POLLIN, 0};
        result("poll", poll(&pfd, 1, -1));
        result("revents", pfd.revents);
        result("expired", timerfd_gettime(fd, &value) == 0 && value.it_value.tv_sec == 0 && value.it_value.tv_nsec == 0);
        timerfd_settime(fd, TFD_TIMER_ABSTIME, &past, NULL);
        timerfd_settime(fd, 0, &ten, NULL);
        errno = 0;
        result("cleared", read(fd, &ticks, 8));
        result("errno", errno);
        /* Linux's hrtimer fires a past time just after settime returns, so
           wait for it before a nonblocking read. */
        timerfd_settime(fd, TFD_TIMER_ABSTIME, &past, NULL);
        poll(&pfd, 1, -1);
        result("read", read(fd, &ticks, 8));
        result("ticks", ticks);
        errno = 0;
        result("drained", read(fd, &ticks, 8));
        result("errno", errno);
        close(fd);
        /* A blocking read waits for a 1 ms one-shot timer. */
        fd = timerfd_create(CLOCK_MONOTONIC, 0);
        struct itimerspec ms = {{0, 0}, {0, 1000000}};
        timerfd_settime(fd, 0, &ms, NULL);
        result("blocking", read(fd, &ticks, 8));
        result("ticks", ticks);
        /* A periodic timer counts every expiry; epoll sees it. */
        struct itimerspec every = {{0, 1000000}, {0, 1000000}};
        timerfd_settime(fd, 0, &every, NULL);
        int ep = epoll_create1(0);
        struct epoll_event ev = {EPOLLIN, {.u64 = 7}}, out;
        epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
        result("epoll", epoll_wait(ep, &out, 1, -1));
        result("epoll-events", out.events);
        result("epoll-data", out.data.u64);
        result("periodic", read(fd, &ticks, 8));
        result("at-least-one", ticks >= 1);
        struct itimerspec off = {{0, 0}, {0, 0}};
        result("disarm", timerfd_settime(fd, 0, &off, &old));
        result("old-period", old.it_interval.tv_sec == 0 && old.it_interval.tv_nsec == 1000000);
        timerfd_gettime(fd, &value);
        result("off", value.it_value.tv_sec == 0 && value.it_value.tv_nsec == 0 && value.it_interval.tv_nsec == 0);
        /* A zero value disarms, but the interval is kept and reported. */
        struct itimerspec idle = {{0, 5000000}, {0, 0}};
        timerfd_settime(fd, 0, &idle, NULL);
        timerfd_gettime(fd, &value);
        result("idle-interval", value.it_interval.tv_nsec);
        result("idle-value", value.it_value.tv_sec == 0 && value.it_value.tv_nsec == 0);
        timerfd_settime(fd, 0, &off, &old);
        result("idle-old", old.it_interval.tv_nsec);
        /* Any non-negative time is valid; Linux saturates a huge one. */
        struct itimerspec huge = {{LONG_MAX, 0}, {LONG_MAX, 0}};
        result("huge", timerfd_settime(fd, 0, &huge, NULL));
        timerfd_gettime(fd, &value);
        result("huge-interval", value.it_interval.tv_sec);
        result("huge-armed", value.it_value.tv_sec > 0);
        timerfd_settime(fd, 0, &off, NULL);
        close(ep);
        close(fd);
        /* CLOCK_REALTIME, with CANCEL_ON_SET accepted. */
        fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
        result("realtime", timerfd_settime(fd, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &past, NULL));
        pfd.fd = fd;
        result("realtime-poll", poll(&pfd, 1, -1));
        result("realtime-read", read(fd, &ticks, 8));
        result("ticks", ticks);
        close(fd);
        return 0;
    }
    if (!strcmp(mode, "clone3")) {
        signal(SIGUSR1, interrupted);
        signal(SIGUSR2, SIG_IGN);
        int parent_tid = 0;
        struct clone3_args args = {0x100000, 0, 0, (unsigned long)&parent_tid, SIGCHLD, 0, 0, 0};
        long pid = clone3(&args, sizeof args);
        if (pid == 0) _exit(7);
        result("exit", reaped(pid));
        result("parent-tid", parent_tid == pid);
        /* CLONE_CLEAR_SIGHAND: handlers go back to the default, ignored stays ignored. */
        struct clone3_args clear = {1ULL << 32, 0, 0, 0, SIGCHLD, 0, 0, 0};
        pid = clone3(&clear, sizeof clear);
        if (pid == 0) {
            struct sigaction one, two;
            sigaction(SIGUSR1, NULL, &one);
            sigaction(SIGUSR2, NULL, &two);
            _exit((one.sa_handler == SIG_DFL) | (two.sa_handler == SIG_IGN) << 1);
        }
        result("cleared", reaped(pid));
        struct sigaction kept;
        sigaction(SIGUSR1, NULL, &kept);
        result("parent-kept", kept.sa_handler == interrupted);
        /* A larger struct is fine while the part Linux does not know is zero. */
        unsigned long long larger[16] = {0};
        larger[4] = SIGCHLD;
        pid = clone3(larger, sizeof larger);
        if (pid == 0) _exit(9);
        result("larger", reaped(pid));
        larger[12] = 1;
        errno = 0;
        result("larger-nonzero", clone3(larger, sizeof larger));
        result("errno", errno);
        errno = 0;
        result("too-small", clone3(&args, 63));
        result("errno", errno);
        errno = 0;
        result("too-large", clone3(&args, 4097));
        result("errno", errno);
        errno = 0;
        result("fault", clone3((void *)1, 64));
        result("errno", errno);
        result("exit-signal-bits", clone3_error((struct clone3_args){0, 0, 0, 0, 0x100, 0, 0, 0}));
        result("detached", clone3_error((struct clone3_args){0x400000, 0, 0, 0, SIGCHLD, 0, 0, 0}));
        result("csignal-flag", clone3_error((struct clone3_args){SIGCHLD, 0, 0, 0, 0, 0, 0, 0}));
        result("sighand-clear", clone3_error((struct clone3_args){(1ULL << 32) | 0xd00, 0, 0, 0, 0, 0, 0, 0}));
        result("thread-signal", clone3_error((struct clone3_args){0x10900, 0, 0, 0, SIGCHLD, 0, 0, 0}));
        result("size-no-stack", clone3_error((struct clone3_args){0, 0, 0, 0, SIGCHLD, 0, 4096, 0}));
        result("stack-no-size", clone3_error((struct clone3_args){0, 0, 0, 0, SIGCHLD, 4096, 0, 0}));
        result("bad-signal", clone3_error((struct clone3_args){0, 0, 0, 0, 65, 0, 0, 0}));
        return 0;
    }
    if (!strcmp(mode, "proc-status")) {
        char value[128], link[32];
        umask(027);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        sigprocmask(SIG_BLOCK, &set, NULL);
        signal(SIGUSR2, SIG_IGN);
        signal(SIGHUP, interrupted);
        ssize_t n = readlink("/proc/self", link, sizeof link - 1);
        link[n > 0 ? n : 0] = 0;
        result("self-link", atoi(link) == getpid());
        struct stat st;
        result("self-dir", stat("/proc/self", &st) == 0 && S_ISDIR(st.st_mode));
        result("status-file", stat("/proc/self/status", &st) == 0 && S_ISREG(st.st_mode));
        /* Only fields that do not depend on the host user or limits. */
        const char *fields[] = {"Umask", "State", "Threads", "SigBlk", "SigIgn", "SigCgt", "TracerPid"};
        for (size_t i = 0; i < sizeof fields / sizeof *fields; i++) {
            if (status_field(fields[i], value, sizeof value)) strcpy(value, "missing");
            printf("%s=%s\n", fields[i], value);
        }
        status_field("Pid", value, sizeof value);
        result("pid", atoi(value) == getpid());
        status_field("PPid", value, sizeof value);
        result("ppid", atoi(value) == getppid());
        status_field("Tgid", value, sizeof value);
        result("tgid", atoi(value) == getpid());
        struct rusage usage;
        result("rusage-self", getrusage(RUSAGE_SELF, &usage));
        result("rusage-children", getrusage(RUSAGE_CHILDREN, &usage));
        result("rusage-thread", getrusage(1, &usage));
        errno = 0;
        result("rusage-who", getrusage(5, &usage));
        result("errno", errno);
        errno = 0;
        result("rusage-fault", syscall(SYS_getrusage, RUSAGE_SELF, (void *)1));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "poll")) {
        int pipefd[2];
        pipe(pipefd);
        struct pollfd fds[3] = {{pipefd[0], POLLIN, 0}, {-1, POLLIN, 7}, {99, POLLIN, 0}};
        /* An empty pipe: the timeout passes; the other two entries still count. */
        result("timeout", poll(fds, 1, 20));
        result("revents", fds[0].revents);
        result("ignored-and-invalid", poll(fds + 1, 2, 20));
        result("negative", fds[1].revents);
        result("invalid", fds[2].revents);
        struct pollfd writable = {pipefd[1], POLLOUT, 0};
        result("writable", poll(&writable, 1, -1));
        result("revents", writable.revents);
        /* A child's write wakes a wait without a timeout. */
        pid_t pid = child();
        if (pid == 0) {
            write(pipefd[1], "x", 1);
            _exit(0);
        }
        result("woken", poll(fds, 1, -1));
        result("revents", fds[0].revents);
        finish(pid);
        char byte;
        read(pipefd[0], &byte, 1);
        /* After the writer closes, the read end hangs up. */
        close(pipefd[1]);
        result("hangup", poll(fds, 1, -1));
        result("revents", fds[0].revents);
        /* fd 0 replaced by an empty pipe is not ready. */
        int other[2];
        pipe(other);
        dup2(other[0], 0);
        struct pollfd input = {0, POLLIN, 0};
        result("stdin-pipe", poll(&input, 1, 0));
        /* A signal ends a wait without a timeout. */
        signal(SIGUSR1, interrupted);
        int stop[2];
        pipe(stop);
        pid = child();
        if (pid == 0) {
            close(stop[1]);
            fcntl(stop[0], F_SETFL, O_NONBLOCK);
            char none;
            while (read(stop[0], &none, 1) < 0) {
                kill(getppid(), SIGUSR1);
                sched_yield();
            }
            _exit(0);
        }
        errno = 0;
        result("interrupted", poll(&input, 1, -1));
        result("errno", errno);
        write(stop[1], "x", 1);
        finish(pid);
        return 0;
    }
    if (!strcmp(mode, "pipe-size")) {
        /* brush sizes the pipe of a here-doc to its text. */
        int pipefd[2];
        pipe(pipefd);
        result("default", fcntl(pipefd[0], F_GETPIPE_SZ));
        result("one-page", fcntl(pipefd[1], F_SETPIPE_SZ, 5));
        result("other-end", fcntl(pipefd[0], F_GETPIPE_SZ));
        result("rounded", fcntl(pipefd[0], F_SETPIPE_SZ, 5000));
        fcntl(pipefd[1], F_SETFL, O_NONBLOCK);
        static char bytes[10000];
        result("partial", write(pipefd[1], bytes, sizeof bytes));
        errno = 0;
        result("full", write(pipefd[1], bytes, 1));
        result("errno", errno);
        errno = 0;
        result("busy", fcntl(pipefd[0], F_SETPIPE_SZ, 4096));
        result("errno", errno);
        result("drain", read(pipefd[0], bytes, sizeof bytes));
        result("shrink", fcntl(pipefd[0], F_SETPIPE_SZ, 4096));
        result("grow", fcntl(pipefd[0], F_SETPIPE_SZ, 1 << 20));
        errno = 0;
        result("too-large", fcntl(pipefd[0], F_SETPIPE_SZ, (1U << 31) + 1));
        result("errno", errno);
        int null = open("/dev/null", O_RDONLY);
        errno = 0;
        result("not-a-pipe", fcntl(null, F_GETPIPE_SZ));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "cpu-clocks")) {
        /* CPU time itself differs from host to host; its rules do not. */
        struct timespec a, b, res;
        result("thread", clock_gettime(CLOCK_THREAD_CPUTIME_ID, &a));
        result("process", clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &b));
        result("ordered", b.tv_sec > a.tv_sec || (b.tv_sec == a.tv_sec && b.tv_nsec >= a.tv_nsec));
        result("valid", a.tv_nsec >= 0 && a.tv_nsec < 1000000000 && b.tv_nsec < 1000000000);
        result("monotone", clock_gettime(CLOCK_THREAD_CPUTIME_ID, &b) == 0
            && (b.tv_sec > a.tv_sec || (b.tv_sec == a.tv_sec && b.tv_nsec >= a.tv_nsec)));
        for (int id = 2; id <= 3; id++) {
            result("res", clock_getres(id, &res));
            result("res-ns", res.tv_sec * 1000000000L + res.tv_nsec);
        }
        int clocks[] = {CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE, CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME};
        for (size_t i = 0; i < sizeof clocks / sizeof *clocks; i++)
            result("other-clock", clock_gettime(clocks[i], &a));
        errno = 0;
        result("unknown", clock_gettime(10, &a));
        result("errno", errno);
        errno = 0;
        /* 10 was CLOCK_SGI_CYCLE: no kernel has it; 16 on are auxiliary clocks now. */
        result("unknown-res", clock_getres(10, &res));
        result("errno", errno);
        result("res-null", clock_getres(CLOCK_PROCESS_CPUTIME_ID, NULL));
        struct rusage usage;
        result("rusage", getrusage(RUSAGE_SELF, &usage));
        result("rusage-valid", usage.ru_utime.tv_usec < 1000000 && usage.ru_stime.tv_usec < 1000000);
        /* A child's time joins the children's once it is waited for. */
        pid_t pid = child();
        if (pid == 0) _exit(0);
        int status;
        struct rusage reaped;
        result("wait4", wait4(pid, &status, 0, &reaped) == pid);
        result("wait4-valid", reaped.ru_utime.tv_usec < 1000000);
        result("children", getrusage(RUSAGE_CHILDREN, &usage));
        struct tms tms;
        result("times", times(&tms) != (clock_t)-1);
        result("times-null", times(NULL) != (clock_t)-1);
        errno = 0;
        result("times-fault", syscall(SYS_times, (void *)1));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "pdeathsig")) {
        /* A grandchild asks for SIGUSR1 when its parent exits, then waits. */
        int report[2];
        if (pipe(report)) return 81;
        pid_t middle = child();
        if (middle == 0) {
            int ready[2];
            if (pipe(ready)) _exit(82);
            pid_t grandchild = child();
            if (grandchild == 0) {
                sigset_t set;
                sigemptyset(&set);
                sigaddset(&set, SIGUSR1);
                sigprocmask(SIG_BLOCK, &set, NULL);
                prctl(PR_SET_PDEATHSIG, SIGUSR1);
                char byte = 'r';
                if (write(ready[1], &byte, 1) != 1) _exit(83);
                /* No timeout: the emulated harness runs a virtual clock, so a
                   bounded wait could end before the parent exits. The
                   harness's own watchdog bounds the run instead. */
                byte = sigwaitinfo(&set, NULL) == SIGUSR1 ? 'y' : 'n';
                if (write(report[1], &byte, 1) != 1) _exit(84);
                _exit(0);
            }
            char byte;
            if (read(ready[0], &byte, 1) != 1) _exit(85);
            _exit(0);
        }
        finish(middle);
        close(report[1]);
        char byte = 0;
        result("report", read(report[0], &byte, 1));
        result("signalled", byte == 'y');
        return 0;
    }
    if (!strcmp(mode, "statfs")) {
        /* Native /tmp is some real filesystem and the emulated one a tmpfs:
           only relations every filesystem keeps are compared. */
        struct statfs by_path, by_fd;
        result("statfs", statfs("/tmp", &by_path));
        result("block-size", by_path.f_bsize > 0);
        result("ordered", by_path.f_blocks >= by_path.f_bfree && by_path.f_bfree >= by_path.f_bavail);
        result("name-max", by_path.f_namelen);
        int fd = open("/tmp", O_RDONLY | O_DIRECTORY);
        result("fstatfs", fstatfs(fd, &by_fd));
        result("same-fs", by_fd.f_type == by_path.f_type && by_fd.f_bsize == by_path.f_bsize);
        close(fd);
        int pair[2];
        if (pipe(pair)) return 81;
        result("pipe", fstatfs(pair[0], &by_fd) == 0 && by_fd.f_type == 0x50495045);
        errno = 0;
        result("missing", statfs("/tmp/paludarium-processes-missing", &by_path));
        result("errno", errno);
        errno = 0;
        result("fault", syscall(SYS_statfs, "/tmp", (void *)1));
        result("errno", errno);
        errno = 0;
        result("bad-fd", fstatfs(99, &by_fd));
        result("errno", errno);
        /* The mount tables list the root, as regular files nobody may write. */
        const char *tables[] = {"/proc/self/mountinfo", "/proc/self/mounts", "/proc/mounts"};
        for (int t = 0; t < 3; t++) {
            FILE *table = fopen(tables[t], "r");
            char line[1024], first[256], second[256], third[256], fourth[256], fifth[256];
            int root = 0;
            while (table && fgets(line, sizeof line, table)) {
                if (t == 0 && sscanf(line, "%255s %255s %255s %255s %255s", first, second, third, fourth, fifth) == 5)
                    root |= !strcmp(fifth, "/");
                if (t > 0 && sscanf(line, "%255s %255s", first, second) == 2)
                    root |= !strcmp(second, "/");
            }
            if (table) fclose(table);
            result("root-listed", root);
            struct stat st;
            /* Opening one for writing is EACCES for a user and allowed for
               root, so it is not compared. */
            result("regular", stat(tables[t], &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 07777) == 0444);
        }
        return 0;
    }
    if (!strcmp(mode, "no-child")) {
        int status;
        errno = 0;
        result("wait", waitpid(-1, &status, 0));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "invalid-clone")) {
        errno = 0;
        result("clone", syscall(SYS_clone, 0x10000|SIGCHLD, 0, 0, 0, 0));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "invalid-wait")) {
        errno = 0;
        result("wait", syscall(SYS_wait4, -1, 0, 0x10, 0));
        result("errno", errno);
        return 0;
    }
    int sync[2];
    if (pipe(sync)) return 97;
    volatile int private_value = 11;
    int *shared = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED) return 96;
    *shared = 13;
    int fd = -1;
    if (!strcmp(mode, "offset") || !strcmp(mode, "cloexec")) {
        fd = open("/tmp/paludarium-offset", O_CREAT|O_TRUNC|O_RDWR, 0600);
        if (fd < 0 || write(fd, "abc", 3) != 3 || lseek(fd, 0, SEEK_SET)) return 95;
        unlink("/tmp/paludarium-offset");
        if (!strcmp(mode, "cloexec")) {
            if (dup2(fd, 9) != 9 || dup2(fd, 10) != 10 || fcntl(9, F_SETFD, FD_CLOEXEC)) return 94;
        }
    }
    fflush(NULL);
    pid_t parent = getpid();
    if (!strcmp(mode, "wait-interrupt") || !strcmp(mode, "wait-restart")) {
        struct sigaction action = {0};
        action.sa_handler = interrupted;
        action.sa_flags = !strcmp(mode, "wait-restart") ? SA_RESTART : 0;
        sigaction(SIGUSR1, &action, NULL);
        pid_t pid = child();
        if (pid < 0) return 78;
        if (!pid) { usleep(100000); kill(parent, SIGUSR1); usleep(100000); _exit(5); }
        int status = 0;
        errno = 0;
        pid_t waited = waitpid(pid, &status, 0);
        int error = errno;
        result("signal", received == 1);
        result("interrupted", waited == -1 && error == EINTR);
        if (waited == -1) waited = waitpid(pid, &status, 0);
        result("wait", waited == pid);
        result("status", status);
        return 0;
    }
    int vf = !strcmp(mode, "vfork-exec") || !strcmp(mode, "vfork-exit");
    pid_t pid = vf ? vfork() : child();
    if (pid < 0) return 93;
    if (!pid) {
        if (!strcmp(mode, "vfork-exit")) _exit(9);
        if (!strcmp(mode, "exec") || !strcmp(mode, "vfork-exec") || !strcmp(mode, "cloexec")) {
            char *args[] = { "process", !strcmp(mode, "cloexec") ? "fd-child" : "child", (char *)self, "argument", NULL };
            char *env[] = { "PROCESSES_VALUE=value", NULL };
            execve(self, args, env);
            _exit(92);
        }
        if (!strcmp(mode, "signal")) { kill(getpid(), SIGTERM); _exit(91); }
        if (!strcmp(mode, "fork")) {
            char ok = getpid() != parent && getppid() == parent;
            if (write(sync[1], &ok, 1) != 1) _exit(90);
        } else if (!strcmp(mode, "offset")) {
            char b;
            if (read(fd, &b, 1) != 1 || b != 'a') _exit(89);
        } else if (!strcmp(mode, "wnohang")) {
            char b;
            if (read(sync[0], &b, 1) != 1) _exit(88);
        }
        private_value = 17;
        *shared = 19;
        _exit(3);
    }
    if (!strcmp(mode, "fork")) {
        char ok = 0;
        if (read(sync[0], &ok, 1) != 1) return 87;
        result("relations", ok);
    }
    if (!strcmp(mode, "wnohang")) {
        int status = 0x1234;
        result("pending", waitpid(pid, &status, WNOHANG));
        result("unchanged", status == 0x1234);
        if (write(sync[1], "x", 1) != 1) return 86;
    }
    if (!strcmp(mode, "wait-fault")) {
        errno = 0;
        result("wait-fault", syscall(SYS_wait4, pid, (void *)1, 0, 0));
        result("errno", errno);
        errno = 0;
        result("after-fault", waitpid(pid, NULL, 0));
        result("after-errno", errno);
    } else if (!strcmp(mode, "usage")) {
        int status;
        struct rusage usage;
        memset(&usage, 0xff, sizeof usage);
        result("wait", wait4(pid, &status, 0, &usage) == pid);
        result("status", status);
        result("usage", usage.ru_utime.tv_sec >= 0 && usage.ru_utime.tv_usec >= 0 && usage.ru_utime.tv_usec < 1000000 && usage.ru_stime.tv_sec >= 0 && usage.ru_stime.tv_usec >= 0 && usage.ru_stime.tv_usec < 1000000);
    } else if (!strcmp(mode, "wait-any")) {
        int status;
        result("wait", waitpid(-1, &status, 0) == pid);
        result("status", status);
    } else finish(pid);
    if (!strcmp(mode, "private")) result("private", private_value == 11);
    if (!strcmp(mode, "shared")) result("shared", *shared == 19);
    if (!strcmp(mode, "offset")) {
        char b;
        result("offset", read(fd, &b, 1) == 1 && b == 'b');
    }
    if (!strcmp(mode, "double-reap")) {
        errno = 0;
        result("again", waitpid(pid, NULL, 0));
        result("errno", errno);
    }
    return 0;
}
