#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
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
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
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
static volatile sig_atomic_t received;
static void interrupted(int number) { (void)number; received++; }
static int vm_value;
static int vm_child(void *unused) { (void)unused; vm_value = 23; return 4; }
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
