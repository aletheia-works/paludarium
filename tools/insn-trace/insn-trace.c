/*
 * insn-trace: run a program natively under ptrace single-stepping and print
 * the address of every executed instruction (one hex address per line).
 *
 * Used to derive the list of instructions a guest actually executes
 * (functional-spec W7). ASLR is disabled for the child so a
 * static-pie guest is placed at 0x555555554000 like the emulator does.
 *
 *   insn-trace <trace-output-file> <program> [args...]
 *
 * The program's own stdout/stderr are left untouched; the exit status of the
 * traced program is reported on stderr.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <trace-output> <program> [args...]\n", argv[0]);
        return 2;
    }
    FILE *out = fopen(argv[1], "w");
    if (out == NULL) {
        perror("fopen");
        return 2;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 2;
    }
    if (pid == 0) {
        if (personality(ADDR_NO_RANDOMIZE) == -1) {
            perror("personality");
            _exit(127);
        }
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace(TRACEME)");
            _exit(127);
        }
        execv(argv[2], argv + 2);
        perror("execv");
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        return 2;
    }
    unsigned long long steps = 0;
    while (WIFSTOPPED(status)) {
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
            perror("ptrace(GETREGS)");
            return 2;
        }
        fprintf(out, "%llx\n", (unsigned long long)regs.rip);
        steps++;
        int deliver = 0;
        int sig = WSTOPSIG(status);
        if (sig != SIGTRAP) {
            deliver = sig;
        }
        if (ptrace(PTRACE_SINGLESTEP, pid, NULL, (void *)(long)deliver) == -1) {
            perror("ptrace(SINGLESTEP)");
            return 2;
        }
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            return 2;
        }
    }
    fclose(out);
    if (WIFEXITED(status)) {
        fprintf(stderr, "insn-trace: exited %d after %llu steps\n", WEXITSTATUS(status), steps);
    } else if (WIFSIGNALED(status)) {
        fprintf(stderr, "insn-trace: signal %d after %llu steps\n", WTERMSIG(status), steps);
    }
    return 0;
}
