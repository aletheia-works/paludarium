/* BPF programs, compared with Linux: socket filters that the verifier
   loads or refuses, from instructions written out here (no libbpf, no
   BTF).
   bpf-prog-verify: programs of registers, jumps and the stack, without
   helpers or the context's fields. For each, the result of
   BPF_PROG_LOAD (a descriptor, or the error) and the line of the log
   that says why it was refused (the last before "processed ... insns");
   for a program loaded, its fdinfo's type, tag (a hash of the
   instructions) and memory, what the descriptor is, and its flags. Then
   the log's arguments: a buffer too small (ENOSPC), one that cannot be
   written (EFAULT), and the checks before the verifier, which log
   nothing.
   bpf-prog-maps: programs that use maps: the map and its value by
   descriptor in BPF_LD_IMM64, bpf_map_lookup_elem, bpf_map_update_elem
   and bpf_map_delete_elem with keys and values on the stack or in a
   value, the null check of a lookup's result, and the bounds and access
   (BPF_F_RDONLY_PROG, BPF_F_WRONLY_PROG) of a value.

   Each program refused is wrong in one way only, which both kernels the
   tests know (Linux 7.0, the CI machines', and master) find first, with
   the same error. The rest of the log, a trace of each instruction that
   each kernel words its own way, its size (log_true_size), the program's
   ID, whether a JIT compiled it (prog_jited) and how many instructions
   the verifier went through (verified_insns, which depends on how it
   prunes) are not printed. The case runs as root, as the guest does:
   loading needs CAP_BPF and CAP_PERFMON. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define PROG_LOAD 5
#define PROG_SOCKET_FILTER 1
#define F_SLEEPABLE (1 << 4)

/* union bpf_attr for BPF_PROG_LOAD, to keyring_id, the last field. */
struct prog_attr {
    uint32_t prog_type, insn_cnt;
    uint64_t insns, license;
    uint32_t log_level, log_size;
    uint64_t log_buf;
    uint32_t kern_version, prog_flags;
    char prog_name[16];
    uint32_t prog_ifindex, expected_attach_type, prog_btf_fd, func_info_rec_size;
    uint64_t func_info;
    uint32_t func_info_cnt, line_info_rec_size;
    uint64_t line_info;
    uint32_t line_info_cnt, attach_btf_id, attach_prog_fd, core_relo_cnt;
    uint64_t fd_array, core_relos;
    uint32_t core_relo_rec_size, log_true_size;
    int32_t prog_token_fd;
    uint32_t fd_array_cnt;
    uint64_t signature;
    uint32_t signature_size;
    int32_t keyring_id;
};
_Static_assert(sizeof(struct prog_attr) == 168, "union bpf_attr's size");

/* struct bpf_insn. */
struct insn {
    uint8_t code;
    uint8_t regs; /* dst_reg in the low 4 bits, src_reg in the high 4 */
    int16_t off;
    int32_t imm;
};
#define I(code, dst, src, off, imm) {(code), (uint8_t)((dst) | (src) << 4), (off), (imm)}
#define MOV(dst, imm) I(0xb7, dst, 0, 0, imm)           /* dst = imm */
#define MOV_REG(dst, src) I(0xbf, dst, src, 0, 0)       /* dst = src */
#define EXIT() I(0x95, 0, 0, 0, 0)
#define STX_DW(dst, src, off) I(0x7b, dst, src, off, 0) /* *(u64 *)(dst + off) = src */
#define STX_W(dst, src, off) I(0x63, dst, src, off, 0)
#define LDX_DW(dst, src, off) I(0x79, dst, src, off, 0) /* dst = *(u64 *)(src + off) */
#define LDX_W(dst, src, off) I(0x61, dst, src, off, 0)
#define LDX_B(dst, src, off) I(0x71, dst, src, off, 0)
#define ST_B(dst, off, imm) I(0x72, dst, 0, off, imm)   /* *(u8 *)(dst + off) = imm */
#define ADD(dst, imm) I(0x07, dst, 0, 0, imm)
#define COUNT(a) (sizeof(a) / sizeof((a)[0]))
/* r = the map of fd, or its value at off, in two instructions. */
#define LD_MAP(dst, fd) I(0x18, dst, 1, 0, fd), I(0, 0, 0, 0, 0)
#define LD_VALUE(dst, fd, off) I(0x18, dst, 2, 0, fd), I(0, 0, 0, 0, off)
#define CALL(id) I(0x85, 0, 0, 0, id)
#define ST_W(dst, off, imm) I(0x62, dst, 0, off, imm)
#define ST_DW(dst, off, imm) I(0x7a, dst, 0, off, imm)
#define JEQ(dst, imm, off) I(0x15, dst, 0, off, imm)
#define LOOKUP 1
#define UPDATE 2
#define DELETE 3

static char log_text[65536];

static void say(const char *format, ...) __attribute__((format(printf, 1, 2)));
static void say(const char *format, ...) {
    va_list list;
    va_start(list, format);
    vprintf(format, list);
    va_end(list);
    putchar('\n');
    fflush(stdout);
}

static long bpf(int cmd, void *attr, unsigned size) {
    long result = syscall(SYS_bpf, cmd, attr, size);
    return result < 0 ? -errno : result;
}

static struct prog_attr attr(const struct insn *insns, unsigned count) {
    struct prog_attr p;
    memset(&p, 0, sizeof p);
    p.prog_type = PROG_SOCKET_FILTER;
    p.insn_cnt = count;
    p.insns = (uintptr_t)insns;
    p.license = (uintptr_t)"GPL";
    p.log_level = 1;
    p.log_buf = (uintptr_t)log_text;
    p.log_size = sizeof log_text;
    return p;
}

/* The log's line that says why: the last before the "processed" line. */
static void reason(void) {
    const char *processed = strstr(log_text, "processed ");
    if (!processed || (processed != log_text && processed[-1] != '\n')) {
        say("  log -");
        return;
    }
    const char *end = processed == log_text ? log_text : processed - 1;
    const char *start = end;
    while (start > log_text && start[-1] != '\n') start--;
    say("  log %.*s", (int)(end - start), start);
}

static void fdinfo(int fd) {
    char path[64], text[1024];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", fd);
    int f = open(path, O_RDONLY);
    ssize_t n = f < 0 ? -1 : read(f, text, sizeof text - 1);
    if (f >= 0) close(f);
    if (n < 0) {
        say("  fdinfo unreadable");
        return;
    }
    text[n] = 0;
    for (char *line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
        if (!strncmp(line, "prog_type:", 10) || !strncmp(line, "prog_tag:", 9) ||
            !strncmp(line, "memlock:", 8))
            say("  %s", line);
    }
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    char link[64] = {0};
    if (readlink(path, link, sizeof link - 1) < 0) strcpy(link, "?");
    say("  link %s flags %#x fd flags %d", link, fcntl(fd, F_GETFL) & O_ACCMODE,
        fcntl(fd, F_GETFD));
}

static void run(const char *name, struct prog_attr p) {
    memset(log_text, 0, sizeof log_text);
    long fd = bpf(PROG_LOAD, &p, sizeof p);
    if (fd < 0) {
        say("%s: %ld", name, fd);
        reason();
        return;
    }
    say("%s: loaded", name);
    fdinfo((int)fd);
    close((int)fd);
}

#define LOAD(name, ...)                                         \
    do {                                                        \
        static const struct insn insns[] = {__VA_ARGS__};       \
        run(name, attr(insns, COUNT(insns)));                   \
    } while (0)

static int case_verify(void) {
    /* Programs it takes. */
    LOAD("return 0", MOV(0, 0), EXIT());
    LOAD("return the frame pointer", MOV_REG(0, 10), EXIT());
    LOAD("64-bit constant", I(0x18, 0, 0, 0, 2), I(0, 0, 0, 0, 1), EXIT());
    LOAD("pointer spilled and filled", STX_DW(10, 10, -8), LDX_DW(0, 10, -8), EXIT());
    LOAD("stack never written", LDX_DW(0, 10, -512), EXIT());
    LOAD("byte at an odd offset", ST_B(10, -3, 1), LDX_B(0, 10, -3), EXIT());
    LOAD("moved stack pointer", MOV_REG(1, 10), ADD(1, -16), MOV(2, 7), STX_DW(1, 2, 8),
         LDX_DW(0, 10, -8), EXIT());
    LOAD("known scalar plus frame pointer", MOV(1, -8), I(0x0f, 1, 10, 0, 0), MOV(0, 0),
         STX_DW(1, 0, 0), EXIT());
    LOAD("pointer less pointer", MOV_REG(0, 10), I(0x1f, 0, 1, 0, 0), EXIT());
    /* The jump is known not to be taken, so the read through R0 is never
       reached. */
    LOAD("known branch", MOV(0, 0), I(0x15, 0, 0, 1, 0), LDX_DW(1, 0, 0), EXIT());
    LOAD("unknown branch", LDX_DW(0, 10, -8), I(0x25, 0, 0, 1, 5), MOV(0, 1), EXIT());
    LOAD("arithmetic", MOV(1, 3), I(0x27, 1, 0, 0, 4), I(0x17, 1, 0, 0, 2), I(0x67, 1, 0, 0, 1),
         I(0xb4, 2, 0, 0, -1), I(0x74, 2, 0, 0, 28), I(0x3f, 1, 2, 0, 0), I(0x9f, 1, 2, 0, 0),
         I(0x87, 1, 0, 0, 0), I(0xdc, 1, 0, 0, 16), I(0xbc, 0, 1, 0, 0), EXIT());

    /* Programs it refuses. */
    LOAD("no return value", EXIT());
    LOAD("unknown opcode", I(0x8c, 0, 0, 0, 0), EXIT());
    LOAD("jump out of range", MOV(0, 0), I(0x05, 0, 0, 5, 0));
    LOAD("no exit at the end", MOV(0, 0));
    LOAD("unreachable", MOV(0, 0), EXIT(), EXIT());
    LOAD("bad second half", I(0x18, 0, 0, 0, 0), I(0, 1, 0, 0, 0), EXIT());
    LOAD("exit with a source", MOV(0, 0), I(0x95, 0, 1, 0, 0));
    LOAD("division by zero", MOV(0, 0), I(0x37, 0, 0, 0, 0), EXIT());
    LOAD("shift by 64", MOV(0, 0), I(0x67, 0, 0, 0, 64), EXIT());
    LOAD("32-bit shift by 32", MOV(0, 0), I(0x64, 0, 0, 0, 32), EXIT());
    LOAD("write the frame pointer", MOV(10, 0), MOV(0, 0), EXIT());
    LOAD("read an unwritten register", MOV_REG(0, 3), EXIT());
    LOAD("below the stack", MOV(0, 0), STX_DW(10, 0, -520), EXIT());
    LOAD("at the frame pointer", LDX_DW(0, 10, 0), EXIT());
    LOAD("misaligned", MOV(0, 0), STX_DW(10, 0, -4), EXIT());
    LOAD("misaligned through a moved pointer", MOV_REG(1, 10), ADD(1, -6), LDX_W(0, 1, 0), EXIT());
    LOAD("part of a spilled pointer", STX_DW(10, 10, -8), LDX_W(0, 10, -8), EXIT());
    LOAD("pointer spilled in part", STX_W(10, 10, -8), MOV(0, 0), EXIT());
    LOAD("subtract from the stack pointer", MOV_REG(1, 10), I(0x17, 1, 0, 0, 8), MOV(0, 0), EXIT());
    LOAD("multiply a pointer", MOV_REG(1, 10), I(0x27, 1, 0, 0, 2), MOV(0, 0), EXIT());
    LOAD("and a pointer", MOV_REG(1, 10), I(0x57, 1, 0, 0, 2), MOV(0, 0), EXIT());
    LOAD("32-bit pointer addition", MOV_REG(1, 10), I(0x04, 1, 0, 0, 2), MOV(0, 0), EXIT());
    LOAD("pointer plus pointer", MOV_REG(1, 10), I(0x0f, 1, 10, 0, 0), MOV(0, 0), EXIT());
    LOAD("scalar less pointer", MOV(1, 8), I(0x1f, 1, 10, 0, 0), MOV(0, 0), EXIT());
    LOAD("pointer far out", MOV_REG(1, 10), ADD(1, 1 << 29), MOV(0, 0), EXIT());
    LOAD("read through a scalar", MOV(1, 0), LDX_DW(0, 1, 0), EXIT());
    LOAD("unknown branch to a bad read", LDX_DW(0, 10, -8), I(0x15, 0, 0, 1, 0), LDX_DW(1, 0, 0),
         EXIT());

    static const struct insn ret0[] = {MOV(0, 0), EXIT()};
    struct prog_attr p = attr(ret0, 2);
    p.prog_flags = F_SLEEPABLE;
    run("sleepable", p);
    p = attr(ret0, 2);
    memcpy(p.prog_name, "filter.1", 9);
    p.license = (uintptr_t)"MIT";
    p.expected_attach_type = 5;
    run("named, not GPL, an attach type", p);

    /* The log's arguments. */
    static const struct insn bad[] = {EXIT()};
    p = attr(bad, 1);
    p.log_size = 8;
    run("log too small for a refusal", p);
    p = attr(ret0, 2);
    p.log_size = 8;
    run("log too small for a load", p);
    p = attr(ret0, 2);
    p.log_buf = 8;
    p.log_size = 64;
    run("log at no memory", p);
    p = attr(ret0, 2);
    p.log_level = 16;
    run("log level 16", p);
    p = attr(ret0, 2);
    p.log_level = 0;
    p.log_buf = 0;
    p.log_size = 0;
    run("no log", p);
    p = attr(ret0, 2);
    p.prog_ifindex = 1;
    run("bound to a device", p);
    return 0;
}

#define LOAD_MAPS(name, ...)                                    \
    do {                                                        \
        struct insn insns[] = {__VA_ARGS__};                    \
        run(name, attr(insns, COUNT(insns)));                   \
    } while (0)

/* A key of 0 at fp-4, the map in R1 and R2 pointing at the key. */
#define KEY4(fd) ST_W(10, -4, 0), LD_MAP(1, fd), MOV_REG(2, 10), ADD(2, -4)
/* The same for a hash's 8-byte key at fp-8. Linux knows that an array's
   element of a constant key is there, so its lookup needs no null check;
   a hash's does. */
#define KEY8(fd) ST_DW(10, -8, 0), LD_MAP(1, fd), MOV_REG(2, 10), ADD(2, -8)

static int map(uint32_t type, uint32_t key, uint32_t value, uint32_t entries, uint32_t flags) {
    uint32_t a[32] = {type, key, value, entries, flags};
    return (int)bpf(0, a, sizeof a);
}

static int case_maps(void) {
    int array = map(2, 4, 8, 1, 0);
    int pair = map(2, 4, 8, 2, 0);
    int hash = map(1, 8, 8, 4, 0);
    int lru = map(9, 4, 8, 4, 0);
    int trie = map(11, 8, 8, 4, 1);
    int rdonly = map(2, 4, 8, 1, 1 << 7);
    int wronly = map(2, 4, 8, 1, 1 << 8);
    int null = open("/dev/null", O_RDONLY);
    say("maps %d", array > 0 && pair > 0 && hash > 0 && lru > 0 && trie > 0 && rdonly > 0 &&
                       wronly > 0);

    /* Programs it takes. */
    LOAD_MAPS("lookup, check and read", KEY4(array), CALL(LOOKUP), JEQ(0, 0, 1), LDX_DW(0, 0, 0),
              EXIT());
    LOAD_MAPS("lookup and write", KEY4(array), CALL(LOOKUP), JEQ(0, 0, 2), ST_DW(0, 0, 7), MOV(0, 0),
              EXIT());
    LOAD_MAPS("update", STX_DW(10, 10, -16), KEY4(array), MOV_REG(3, 10), ADD(3, -16), MOV(4, 0),
              CALL(UPDATE), EXIT());
    LOAD_MAPS("delete from a hash", ST_DW(10, -8, 1), LD_MAP(1, hash), MOV_REG(2, 10), ADD(2, -8),
              CALL(DELETE), EXIT());
    LOAD_MAPS("lru update", ST_DW(10, -16, 2), KEY4(lru), MOV_REG(3, 10), ADD(3, -16), MOV(4, 1),
              CALL(UPDATE), EXIT());
    LOAD_MAPS("trie lookup", ST_DW(10, -8, 32), LD_MAP(1, trie), MOV_REG(2, 10), ADD(2, -8),
              CALL(LOOKUP), MOV(0, 0), EXIT());
    LOAD_MAPS("key in a value", KEY4(array), CALL(LOOKUP), JEQ(0, 0, 4), MOV_REG(2, 0), LD_MAP(1, array),
              CALL(LOOKUP), MOV(0, 0), EXIT());
    LOAD_MAPS("pointer into a value", KEY4(array), CALL(LOOKUP), JEQ(0, 0, 1), STX_DW(0, 10, 0),
              EXIT());
    LOAD_MAPS("direct value", LD_VALUE(1, array, 4), LDX_W(0, 1, 0), EXIT());
    LOAD_MAPS("map named twice", LD_MAP(1, array), LD_MAP(2, array), MOV(0, 0), EXIT());

    /* Programs it refuses. */
    LOAD_MAPS("no null check", KEY8(hash), CALL(LOOKUP), LDX_DW(0, 0, 0), EXIT());
    LOAD_MAPS("arithmetic before the check", KEY8(hash), CALL(LOOKUP), ADD(0, 1), EXIT());
    LOAD_MAPS("past the value", KEY4(array), CALL(LOOKUP), JEQ(0, 0, 1), LDX_DW(0, 0, 4), EXIT());
    LOAD_MAPS("write a read-only value", KEY4(rdonly), CALL(LOOKUP), JEQ(0, 0, 1), ST_DW(0, 0, 1),
              EXIT());
    LOAD_MAPS("read a write-only value", KEY4(wronly), CALL(LOOKUP), JEQ(0, 0, 1), LDX_DW(0, 0, 0),
              EXIT());
    LOAD_MAPS("update a read-only map", STX_DW(10, 10, -16), KEY4(rdonly), MOV_REG(3, 10), ADD(3, -16),
              MOV(4, 0), CALL(UPDATE), EXIT());
    LOAD_MAPS("key past the frame", LD_MAP(1, hash), MOV_REG(2, 10), ADD(2, -4), CALL(LOOKUP), MOV(0, 0),
              EXIT());
    LOAD_MAPS("no map in R1", MOV(1, 5), MOV_REG(2, 10), ADD(2, -8), CALL(LOOKUP), EXIT());
    LOAD_MAPS("argument after the call", KEY4(array), CALL(LOOKUP), MOV_REG(0, 1), EXIT());
    LOAD_MAPS("arithmetic on the map", LD_MAP(1, array), ADD(1, 8), MOV(0, 0), EXIT());
    LOAD_MAPS("descriptor of no file", LD_MAP(1, 1000), MOV(0, 0), EXIT());
    LOAD_MAPS("descriptor of no map", LD_MAP(1, null), MOV(0, 0), EXIT());
    LOAD_MAPS("value past its end", LD_VALUE(1, array, 8), MOV(0, 0), EXIT());
    LOAD_MAPS("value of two elements", LD_VALUE(1, pair, 0), MOV(0, 0), EXIT());
    LOAD_MAPS("value of a hash", LD_VALUE(1, hash, 0), MOV(0, 0), EXIT());
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    alarm(20);
    if (!strcmp(mode, "bpf-prog-verify")) return case_verify();
    if (!strcmp(mode, "bpf-prog-maps")) return case_maps();
    return 2;
}
