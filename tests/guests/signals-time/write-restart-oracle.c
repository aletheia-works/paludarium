#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

/* Native-only oracle: fork/pipe are test infrastructure, not guest U4 APIs. */
extern char write_site[], write_after[];
static volatile long observed_rax, observed_site;
static void handler(int number, siginfo_t *info, void *raw) {
    (void)number; (void)info;
    ucontext_t *uc = raw;
    observed_rax = uc->uc_mcontext.gregs[REG_RAX];
    observed_site = uc->uc_mcontext.gregs[REG_RIP] == (long)write_site ? 0 :
        uc->uc_mcontext.gregs[REG_RIP] == (long)write_after ? 1 : 2;
}
static long blocked_write(int fd, const void *buf) {
    long result;
    __asm__ volatile("write_site: syscall\nwrite_after:"
        : "=a"(result) : "a"(1L), "D"((long)fd), "S"(buf), "d"(1L)
        : "rcx", "r11", "memory");
    return result;
}
int main(int argc, char **argv) {
    if (argc != 2) return 90;
    int restart = atoi(argv[1]), p[2], ready[2];
    if (pipe(p) || pipe(ready)) return 91;
    int flags = fcntl(p[1], F_GETFL);
    if (fcntl(p[1], F_SETFL, flags | O_NONBLOCK)) return 92;
    char bytes[4096] = {0};
    while (write(p[1], bytes, sizeof bytes) > 0) {}
    if (errno != EAGAIN || fcntl(p[1], F_SETFL, flags)) return 93;
    struct sigaction action = {.sa_sigaction = handler,
        .sa_flags = SA_SIGINFO | (restart ? SA_RESTART : 0)};
    if (sigaction(SIGUSR1, &action, NULL)) return 94;
    pid_t parent = getpid(), child = fork();
    if (child < 0) return 95;
    if (!child) {
        char token;
        if (read(ready[0], &token, 1) != 1) _exit(96);
        usleep(20000);
        if (kill(parent, SIGUSR1)) _exit(97);
        usleep(20000);
        if (read(p[0], bytes, sizeof bytes) <= 0) _exit(98);
        _exit(0);
    }
    if (write(ready[1], "x", 1) != 1) return 99;
    long result = blocked_write(p[1], "y");
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 100;
    printf("restart=%d frame_rax=%ld frame_site=%ld result=%ld\n",
        restart, observed_rax, observed_site, result);
    return 0;
}
