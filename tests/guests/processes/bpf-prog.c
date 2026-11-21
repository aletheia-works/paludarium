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
   bpf-prog-context: the context, struct __sk_buff, read and written
   (cb[]) at the offsets and sizes a socket filter may use, and the
   helpers of a socket filter: bpf_skb_load_bytes and its relative form,
   the socket's cookie and owner, the network namespace's cookie, and
   those of no arguments; then helpers a socket filter may not call, and
   an instruction reached through the context on one path and the stack
   on another.
   bpf-prog-attach: socket filters attached to AF_UNIX sockets with
   SO_ATTACH_BPF and run on what they receive: the options' errors
   (SO_ATTACH_BPF, SO_DETACH_FILTER, SO_LOCK_FILTER, SO_GET_FILTER,
   SO_BPF_EXTENSIONS); a filter that drops a message (the send still
   gives its length), keeps part of it, or reads it with
   bpf_skb_load_bytes and its relative form; one that counts messages in
   a map, which the case reads back; the results of division and
   remainder by 0 and by -1, which the bytes kept show; and where the
   filter runs among the send's checks: before the receiver's shutdown
   (EPIPE) of a datagram socket, after the sender's own shutdown of a
   SOCK_SEQPACKET pair, not at all for a stream socket, and before a
   datagram socket
   connected elsewhere refuses the sender (EPERM).

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
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
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
#define LDX_H(dst, src, off) I(0x69, dst, src, off, 0)
#define LOAD_BYTES 26
#define LOAD_BYTES_RELATIVE 68
#define SOCKET_COOKIE 46
#define SOCKET_UID 47
#define NETNS_COOKIE 122

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

static int case_context(void) {
    int array = map(2, 4, 8, 1, 0);
    int rdonly = map(2, 4, 8, 1, 1 << 7);
    say("maps %d", array > 0 && rdonly > 0);

    /* Programs it takes. R1 is the context as a program starts. */
    LOAD_MAPS("read len", LDX_W(0, 1, 0), EXIT());
    LOAD_MAPS("narrow reads", LDX_H(0, 1, 6), LDX_B(2, 1, 11), EXIT());
    LOAD_MAPS("write and read cb", ST_W(1, 48, 7), MOV(2, 1), STX_W(1, 2, 64), LDX_W(0, 1, 48), EXIT());
    LOAD_MAPS("cb as 8 bytes", MOV(2, 1), STX_DW(1, 2, 56), LDX_DW(0, 1, 56), EXIT());
    LOAD_MAPS("context spilled", STX_DW(10, 1, -8), LDX_DW(2, 10, -8), LDX_W(0, 2, 0), EXIT());
    LOAD_MAPS("context moved and back", ADD(1, 4), ADD(1, -4), LDX_W(0, 1, 0), EXIT());
    LOAD_MAPS("load bytes to the stack", MOV(2, 0), MOV_REG(3, 10), ADD(3, -16), MOV(4, 16),
              CALL(LOAD_BYTES), LDX_DW(0, 10, -16), EXIT());
    LOAD_MAPS("load bytes into a value", MOV_REG(6, 1), KEY4(array), CALL(LOOKUP), JEQ(0, 0, 5),
              MOV_REG(3, 0), MOV_REG(1, 6), MOV(2, 0), MOV(4, 8), CALL(LOAD_BYTES), MOV(0, 0), EXIT());
    LOAD_MAPS("load bytes relative", MOV(2, 0), MOV_REG(3, 10), ADD(3, -8), MOV(4, 8), MOV(5, 1),
              CALL(LOAD_BYTES_RELATIVE), EXIT());
    LOAD_MAPS("socket cookie and uid", MOV_REG(6, 1), CALL(SOCKET_COOKIE), MOV_REG(1, 6),
              CALL(SOCKET_UID), EXIT());
    LOAD_MAPS("netns cookie", CALL(NETNS_COOKIE), MOV(1, 0), CALL(NETNS_COOKIE), EXIT());
    LOAD_MAPS("helpers of no arguments", CALL(5), CALL(7), CALL(8), CALL(14), CALL(15), CALL(42),
              CALL(125), CALL(160), CALL(208), EXIT());

    /* Programs it refuses. */
    LOAD_MAPS("past the context", LDX_W(0, 1, 192), EXIT());
    LOAD_MAPS("read data", LDX_W(0, 1, 76), EXIT());
    LOAD_MAPS("8 bytes of len", LDX_DW(0, 1, 0), EXIT());
    LOAD_MAPS("misaligned field", LDX_W(0, 1, 2), EXIT());
    LOAD_MAPS("read tstamp_type", LDX_B(0, 1, 180), EXIT());
    LOAD_MAPS("read flow_keys", LDX_DW(0, 1, 144), EXIT());
    /* sk is a pointer, read whole only: Linux matches all its 8 bytes. */
    LOAD_MAPS("4 bytes of sk", LDX_W(0, 1, 168), EXIT());
    LOAD_MAPS("4 bytes inside sk", LDX_W(0, 1, 172), EXIT());
    LOAD_MAPS("write len", MOV(2, 1), STX_W(1, 2, 0), MOV(0, 0), EXIT());
    LOAD_MAPS("write past cb", MOV(2, 1), STX_DW(1, 2, 64), MOV(0, 0), EXIT());
    LOAD_MAPS("read through a moved context", ADD(1, 4), LDX_W(0, 1, 0), EXIT());
    LOAD_MAPS("helper of another type", CALL(9), EXIT());
    LOAD_MAPS("no such helper", CALL(212), EXIT());
    LOAD_MAPS("cookie of a scalar", MOV(1, 0), CALL(SOCKET_COOKIE), EXIT());
    LOAD_MAPS("cookie of a moved context", ADD(1, 8), CALL(SOCKET_COOKIE), EXIT());
    LOAD_MAPS("load no bytes", MOV(2, 0), MOV_REG(3, 10), ADD(3, -8), MOV(4, 0), CALL(LOAD_BYTES),
              EXIT());
    LOAD_MAPS("load bytes past the frame", MOV(2, 0), MOV_REG(3, 10), ADD(3, -8), MOV(4, 16),
              CALL(LOAD_BYTES), EXIT());
    LOAD_MAPS("load 2^29 bytes", MOV(2, 0), MOV_REG(3, 10), ADD(3, -8), MOV(4, 1 << 29),
              CALL(LOAD_BYTES), EXIT());
    LOAD_MAPS("load bytes to a scalar", MOV(2, 0), MOV(3, 0), MOV(4, 8), CALL(LOAD_BYTES), EXIT());
    LOAD_MAPS("size not a scalar", MOV(2, 0), MOV_REG(3, 10), ADD(3, -8), MOV_REG(4, 10),
              CALL(LOAD_BYTES), EXIT());
    LOAD_MAPS("load bytes into a read-only value", MOV_REG(6, 1), KEY4(rdonly), CALL(LOOKUP),
              JEQ(0, 0, 5), MOV_REG(3, 0), MOV_REG(1, 6), MOV(2, 0), MOV(4, 8), CALL(LOAD_BYTES),
              MOV(0, 0), EXIT());
    LOAD_MAPS("context and stack in one load", MOV_REG(2, 1), LDX_DW(0, 10, -8), JEQ(0, 0, 2),
              MOV_REG(2, 10), ADD(2, -16), LDX_W(0, 2, 0), EXIT());
    return 0;
}

#ifndef SO_ATTACH_BPF
#define SO_ATTACH_BPF 50
#endif
#ifndef SO_BPF_EXTENSIONS
#define SO_BPF_EXTENSIONS 48
#endif
#ifndef SO_LOCK_FILTER
#define SO_LOCK_FILTER 44
#endif
#define LD64(dst, v) I(0x18, dst, 0, 0, (int32_t)(uint32_t)(v)), I(0, 0, 0, 0, (int32_t)((uint64_t)(v) >> 32))

/* A program's descriptor, or the error. */
static int load(const struct insn *insns, unsigned count) {
    struct prog_attr p = attr(insns, count);
    return (int)bpf(PROG_LOAD, &p, sizeof p);
}
#define PROGRAM(...)                                            \
    ({                                                          \
        struct insn insns_[] = {__VA_ARGS__};                   \
        load(insns_, COUNT(insns_));                            \
    })

static int attach(int sock, int prog) {
    return setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog, sizeof prog) ? -errno : 0;
}
static int option(int sock, int name, int value) {
    return setsockopt(sock, SOL_SOCKET, name, &value, sizeof value) ? -errno : 0;
}
static void get(const char *name, int sock, int option) {
    int value = -1;
    socklen_t len = sizeof value;
    if (getsockopt(sock, SOL_SOCKET, option, &value, &len))
        say("%s %d", name, -errno);
    else
        say("%s value %d len %u", name, value, len);
}

/* Sends `len` bytes (0, 1, 2, ...) from a to b, and says what b receives:
   the bytes, or that nothing came. */
static void through(const char *name, int a, int b, size_t len) {
    unsigned char out[64], in[64];
    for (size_t i = 0; i < sizeof out; i++) out[i] = (unsigned char)i;
    long sent = send(a, out, len, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (sent < 0) sent = -errno;
    long got = recv(b, in, sizeof in, MSG_DONTWAIT);
    printf("%s sent %ld", name, sent);
    if (got < 0) {
        printf(" received %d\n", -errno);
    } else {
        printf(" received %ld:", got);
        for (long i = 0; i < got; i++) printf(" %u", in[i]);
        putchar('\n');
    }
    fflush(stdout);
}

/* The filter that keeps R0 bytes, R0 the result of `op` of a and b in 64
   or 32 bits. */
static int arithmetic(uint8_t op, int16_t off, int64_t a, int64_t b) {
    return PROGRAM(LD64(0, a), LD64(2, b), I(op, 0, 2, off, 0), EXIT());
}

static int case_attach(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair)) return 1;
    int drop = PROGRAM(MOV(0, 0), EXIT());
    int keep3 = PROGRAM(MOV(0, 3), EXIT());
    int all = PROGRAM(MOV(0, -1), EXIT());
    say("loaded %d", drop >= 0 && keep3 >= 0 && all >= 0);
    int m = map(2, 4, 8, 1, 0);
    int fds[2];
    if (pipe(fds)) return 1;

    say("attach len 8 %d", setsockopt(pair[1], SOL_SOCKET, SO_ATTACH_BPF, (uint64_t[]){(uint64_t)drop}, 8) ? -errno : 0);
    say("attach len 2 %d", setsockopt(pair[1], SOL_SOCKET, SO_ATTACH_BPF, &drop, 2) ? -errno : 0);
    say("attach no fd %d", attach(pair[1], 1000));
    say("attach -1 %d", attach(pair[1], -1));
    say("attach map %d", attach(pair[1], m));
    say("attach pipe %d", attach(pair[1], fds[0]));
    say("detach none %d", option(pair[1], SO_DETACH_FILTER, 0));
    get("get filter none", pair[1], SO_GET_FILTER);
    get("lock filter", pair[1], SO_LOCK_FILTER);
    get("bpf extensions", pair[1], SO_BPF_EXTENSIONS);

    through("no filter", pair[0], pair[1], 5);
    say("attach drop %d", attach(pair[1], drop));
    get("get filter bpf", pair[1], SO_GET_FILTER);
    through("drop", pair[0], pair[1], 5);
    through("drop empty", pair[0], pair[1], 0);
    through("other way", pair[1], pair[0], 5);
    say("attach keep 3 %d", attach(pair[1], keep3));
    through("keep 3", pair[0], pair[1], 5);
    through("keep 3 of 2", pair[0], pair[1], 2);
    say("attach all %d", attach(pair[1], all));
    through("keep all", pair[0], pair[1], 5);
    /* The descriptor may go: the socket keeps the program. */
    close(all);
    through("closed program", pair[0], pair[1], 4);

    say("lock %d", option(pair[1], SO_LOCK_FILTER, 1));
    get("lock filter locked", pair[1], SO_LOCK_FILTER);
    say("attach locked %d", attach(pair[1], drop));
    say("detach locked %d", option(pair[1], SO_DETACH_FILTER, 0));
    say("unlock locked %d", option(pair[1], SO_LOCK_FILTER, 0));
    say("lock again %d", option(pair[1], SO_LOCK_FILTER, 1));
    through("still all", pair[0], pair[1], 4);

    int b[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, b)) return 1;
    say("detach %d", (attach(b[1], keep3), option(b[1], SO_DETACH_FILTER, 0)));
    say("detach twice %d", option(b[1], SO_DETACH_FILTER, 0));
    through("detached", b[0], b[1], 5);

    /* R0 = the first byte of the message: its length kept. */
    int first = PROGRAM(MOV_REG(6, 1), MOV(2, 0), MOV_REG(3, 10), ADD(3, -8), MOV(4, 1), CALL(LOAD_BYTES),
                        JEQ(0, 0, 2), MOV(0, 1), EXIT(), LDX_B(0, 10, -8), EXIT());
    say("attach first byte %d", attach(b[1], first));
    {
        unsigned char msg[6] = {4, 9, 8, 7, 6, 5}, in[8];
        long sent = send(b[0], msg, sizeof msg, 0);
        long got = recv(b[1], in, sizeof in, MSG_DONTWAIT);
        say("first byte sent %ld received %ld", sent, got);
    }
    /* Past the end: EFAULT, and 1 byte kept. */
    int past = PROGRAM(MOV_REG(6, 1), MOV(2, 4), MOV_REG(3, 10), ADD(3, -8), MOV(4, 4), CALL(LOAD_BYTES),
                       JEQ(0, 0, 2), MOV(0, 1), EXIT(), MOV(0, 2), EXIT());
    say("attach past %d", attach(b[1], past));
    through("past the end", b[0], b[1], 6);
    through("not past the end", b[0], b[1], 8);
    /* The relative form: from the network header, the message's start; the
       MAC header is not set, EFAULT. R0 = the byte at 2, or 1. */
    int net = PROGRAM(MOV(2, 2), MOV_REG(3, 10), ADD(3, -8), MOV(4, 1), MOV(5, 1), CALL(LOAD_BYTES_RELATIVE),
                      JEQ(0, 0, 2), MOV(0, 1), EXIT(), LDX_B(0, 10, -8), EXIT());
    int mac = PROGRAM(MOV(2, 2), MOV_REG(3, 10), ADD(3, -8), MOV(4, 1), MOV(5, 0), CALL(LOAD_BYTES_RELATIVE),
                      JEQ(0, 0, 2), MOV(0, 1), EXIT(), LDX_B(0, 10, -8), EXIT());
    say("attach net %d", attach(b[1], net));
    through("network header", b[0], b[1], 6);
    say("attach mac %d", attach(b[1], mac));
    through("mac header", b[0], b[1], 6);
    /* The context: len, and cb[0] written then read. */
    int len = PROGRAM(LDX_W(0, 1, 0), ADD(0, -1), EXIT());
    say("attach len %d", attach(b[1], len));
    through("len less 1", b[0], b[1], 6);
    int cb = PROGRAM(ST_W(1, 48, 2), LDX_W(0, 1, 48), EXIT());
    say("attach cb %d", attach(b[1], cb));
    through("cb", b[0], b[1], 6);

    /* A map counts the messages: value[0] += 1 each time; keep all. */
    int counter = map(2, 4, 8, 1, 0);
    int count = PROGRAM(KEY4(counter), CALL(LOOKUP), JEQ(0, 0, 3), LDX_DW(1, 0, 0), ADD(1, 1), STX_DW(0, 1, 0),
                        MOV(0, -1), EXIT());
    say("attach count %d", attach(b[1], count));
    for (int i = 0; i < 3; i++) through("counted", b[0], b[1], 1);
    {
        uint32_t key = 0;
        uint64_t value = 0;
        struct {
            uint32_t map_fd, pad;
            uint64_t key, value, flags;
        } a = {(uint32_t)counter, 0, (uintptr_t)&key, (uintptr_t)&value, 0};
        long r = bpf(1, &a, sizeof a);
        say("count lookup %ld value %llu", r, (unsigned long long)value);
    }

    /* Division and remainder, as the bytes kept (of 64) show. */
    struct {
        const char *name;
        uint8_t op;
        int16_t off;
        int64_t a, b;
    } ops[] = {
        {"div 0", 0x3f, 0, 7, 0},          {"mod 0", 0x9f, 0, 7, 0},
        {"div32 0", 0x3c, 0, 7, 0},        {"mod32 0", 0x9c, 0, 0x100000007, 0},
        {"sdiv -1", 0x3f, 1, -7, -1},      {"smod -1", 0x9f, 1, 7, -1},
        {"sdiv 0", 0x3f, 1, 7, 0},         {"smod 0", 0x9f, 1, 7, 0},
        {"sdiv32 -7 2", 0x3c, 1, -7, 2},   {"smod32 -7 -2", 0x9c, 1, 7, -2},
        {"sdiv32 -1", 0x3c, 1, -9, -1},    {"smod32 0", 0x9c, 1, 0x100000009, 0},
        {"div large", 0x3f, 0, -1, 0x10000000000}, {"lsh 65", 0x6f, 0, 1, 65},
    };
    for (size_t i = 0; i < COUNT(ops); i++) {
        int c[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, c)) return 1;
        int prog = arithmetic(ops[i].op, ops[i].off, ops[i].a, ops[i].b);
        if (prog < 0) {
            say("%s load %d", ops[i].name, prog);
            continue;
        }
        attach(c[1], prog);
        unsigned char out[64] = {0}, in[64];
        send(c[0], out, sizeof out, 0);
        long got = recv(c[1], in, sizeof in, MSG_DONTWAIT);
        say("%s kept %ld", ops[i].name, got < 0 ? -errno : got);
        close(prog);
        close(c[0]);
        close(c[1]);
    }

    /* SOCK_DGRAM: the filter runs before the receiver's shutdown is seen,
       so a dropped datagram is sent where one kept is EPIPE. */
    int d[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, d)) return 1;
    shutdown(d[1], SHUT_RD);
    through("datagram shut", d[0], d[1], 5);
    say("attach datagram shut keep 3 %d", attach(d[1], keep3));
    through("datagram shut kept", d[0], d[1], 5);
    say("attach datagram shut drop %d", attach(d[1], drop));
    through("datagram shut dropped", d[0], d[1], 5);
    /* A blocking read of a datagram socket that has shut reading down ends
       (0), where one that does not wait finds nothing (EAGAIN). */
    {
        char in[8];
        long got = recv(d[1], in, sizeof in, 0);
        say("datagram shut blocking read %ld", got < 0 ? -errno : got);
    }

    /* SOCK_SEQPACKET: a filter trims and drops as for datagrams; the
       receiver's shutdown of reading shuts the sender's writing too, which
       the send finds before the filter runs (EPIPE). */
    int s[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, s)) return 1;
    through("seqpacket", s[0], s[1], 5);
    say("attach seqpacket keep 3 %d", attach(s[1], keep3));
    through("seqpacket keep 3", s[0], s[1], 5);
    shutdown(s[1], SHUT_RD);
    through("seqpacket shut kept", s[0], s[1], 5);
    say("attach seqpacket drop %d", attach(s[1], drop));
    through("seqpacket shut dropped", s[0], s[1], 5);
    shutdown(s[0], SHUT_WR);
    through("seqpacket own shutdown", s[0], s[1], 5);

    /* A stream socket takes a filter, which unix_stream_sendmsg never
       runs. */
    int t[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, t)) return 1;
    say("attach stream drop %d", attach(t[1], drop));
    through("stream", t[0], t[1], 5);

    /* A datagram socket connected to another refuses a third (EPERM), but
       its filter runs first. */
    int x = socket(AF_UNIX, SOCK_DGRAM, 0), y = socket(AF_UNIX, SOCK_DGRAM, 0), z = socket(AF_UNIX, SOCK_DGRAM, 0);
    struct sockaddr_un ax = {.sun_family = AF_UNIX, .sun_path = "\0bpf-prog-x"},
                       ay = {.sun_family = AF_UNIX, .sun_path = "\0bpf-prog-y"};
    socklen_t lx = sizeof(sa_family_t) + 11, ly = sizeof(sa_family_t) + 11;
    bind(x, (struct sockaddr *)&ax, lx);
    bind(y, (struct sockaddr *)&ay, ly);
    connect(x, (struct sockaddr *)&ay, ly);
    say("third %ld", sendto(z, "abc", 3, MSG_DONTWAIT, (struct sockaddr *)&ax, lx) < 0 ? -errno : 3L);
    say("attach x drop %d", attach(x, drop));
    say("third dropped %ld", sendto(z, "abc", 3, MSG_DONTWAIT, (struct sockaddr *)&ax, lx) < 0 ? -errno : 3L);
    char in[8];
    say("x received %ld", recv(x, in, sizeof in, MSG_DONTWAIT) < 0 ? -errno : 0L);
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    alarm(20);
    if (!strcmp(mode, "bpf-prog-verify")) return case_verify();
    if (!strcmp(mode, "bpf-prog-maps")) return case_maps();
    if (!strcmp(mode, "bpf-prog-context")) return case_context();
    if (!strcmp(mode, "bpf-prog-attach")) return case_attach();
    return 2;
}
