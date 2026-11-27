/* Signals a program starts with ignored.
 *
 * The test starts this program with SIGINT and SIGQUIT ignored, as a shell
 * starts a job it puts in the background with `&`. Linux's execve keeps an
 * ignored action (`flush_signal_handlers` resets only the handled ones), so
 * the program starts with them ignored, a forked child and a program it
 * execs keep them, a SIGINT it sends itself is discarded, and it may still
 * change them. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* The kernel's struct sigaction on x86-64. */
struct kact {
    unsigned long handler, flags, restorer, mask;
};

static const char *disposition(int sig) {
    struct kact old = {0x77, 0, 0, 0};
    if (syscall(SYS_rt_sigaction, sig, NULL, &old, 8) != 0) return "error";
    if (old.handler == (unsigned long)SIG_IGN) return "ignored";
    if (old.handler == (unsigned long)SIG_DFL) return "default";
    return "handled";
}

static void show(const char *who) {
    printf("%s: INT %s QUIT %s TERM %s USR1 %s\n", who, disposition(SIGINT),
           disposition(SIGQUIT), disposition(SIGTERM), disposition(SIGUSR1));
    fflush(stdout);
}

int main(int argc, char **argv) {
    /* The harness gives the program's own path after the case's name. */
    char *self = argc > 2 ? argv[2] : argv[0];
    if (argc > 1 && strcmp(argv[1], "after-exec") == 0) {
        show("after exec");
        return 0;
    }
    show("start");

    /* An ignored signal is discarded as it is sent. */
    kill(getpid(), SIGINT);
    sigset_t pending;
    sigemptyset(&pending);
    sigpending(&pending);
    printf("sent INT: alive, pending %d\n", sigismember(&pending, SIGINT));
    fflush(stdout);

    int pid = fork();
    if (pid == 0) {
        show("forked");
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);

    pid = fork();
    if (pid == 0) {
        char *args[] = {self, "after-exec", NULL};
        char *env[] = {NULL};
        execve(self, args, env);
        _exit(6);
    }
    waitpid(pid, &status, 0);
    printf("exec: exited %d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);

    /* It may still change them. */
    signal(SIGQUIT, SIG_DFL);
    show("reset QUIT");
    return 0;
}
