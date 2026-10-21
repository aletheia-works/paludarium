#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

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
        char *args[] = { "u8-process", "exec-thread-child", (char *)self, writer, reader, NULL };
        char *env[] = { NULL };
        execve(self, args, env);
        return 81;
    }
    if (!strcmp(mode, "child")) {
        result("argv", argc == 4 && !strcmp(argv[3], "argument"));
        result("env", getenv("U8_VALUE") && !strcmp(getenv("U8_VALUE"), "value"));
        return 7;
    }
    if (!strcmp(mode, "fd-child")) {
        errno = 0;
        result("cloexec", fcntl(9, F_GETFD) == -1 && errno == EBADF);
        result("retained", fcntl(10, F_GETFD) >= 0);
        return 0;
    }
    if (!strcmp(mode, "enoent") || !strcmp(mode, "bad-elf") || !strcmp(mode, "exec-fault")) {
        const char *path = "/u8-not-present";
        if (!strcmp(mode, "bad-elf")) {
            path = "/tmp/u8-invalid-elf";
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
        fd = open("/tmp/u8-offset", O_CREAT|O_TRUNC|O_RDWR, 0600);
        if (fd < 0 || write(fd, "abc", 3) != 3 || lseek(fd, 0, SEEK_SET)) return 95;
        unlink("/tmp/u8-offset");
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
            char *args[] = { "u8-process", !strcmp(mode, "cloexec") ? "fd-child" : "child", (char *)self, "argument", NULL };
            char *env[] = { "U8_VALUE=value", NULL };
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
