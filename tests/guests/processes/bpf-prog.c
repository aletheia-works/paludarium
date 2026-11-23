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
   bpf-prog-atomic: BPF_ATOMIC's read-modify-write operations (add, or,
   and, xor, each with and without BPF_FETCH, xchg and cmpxchg) in 32
   and 64 bits: programs it takes and refuses, with the order of the
   checks (the operation, its size, the registers, the context, the
   alignment on the stack and in a value, a read-only value, the register
   the old value goes to), and a filter that runs them on a map's value
   and the stack, whose results the case reads back from the map. Then,
   with BPF_F_STRICT_ALIGNMENT, plain loads through a hash lookup's result
   before its null check: misaligned, which is refused for that first, and
   aligned.
   bpf-prog-acqrel: BPF_ATOMIC's load-acquire and store-release in each
   size: programs it takes and refuses (the registers, the alignment on
   the stack and in a value, a read-only value, the context, before a
   load's access and after a store's, a spilled pointer's fill), and a
   filter that runs them on a map's value and the stack, whose results the
   case reads back from the map.
   bpf-prog-ldabs: BPF_LD_ABS and BPF_LD_IND in each size: programs it
   takes and refuses (R6 not the context, or moved, the source register,
   R1 to R5 after the load, the reserved fields, a 64-bit load), and
   filters that run them on AF_UNIX datagrams: the bytes they load,
   big-endian, at offsets from the start, the network header and a
   register, one that keeps as many bytes as it loads, and the loads past
   the message or before it, or from the MAC header, which drop it.
   bpf-prog-calls: bpf-to-bpf calls of static functions (no BTF): programs
   it takes and refuses (the call's destination, jumps that leave a
   function or fall into the next, BPF_LD_ABS and bpf_tail_call in a
   function, R0 to R5 after a call and R0 and R6 to R9 in the callee, a
   pointer to a stack returned or stored in a caller's frame, 9 frames,
   recursion, and the combined stack), each function's stack depth in the log's
   statistics, and a filter whose functions write a map's value through
   pointers to it and to their callers' stacks, which the case reads back.
   bpf-prog-rewrites: the program's memory in fdinfo (memlock), which
   grows with the instructions the verifier's rewrites make: for each
   rewrite, programs that come to 500 instructions after it, which fit a
   page with the program's header, and to 501, which take two. The
   rewrites: a division or remainder by a register, of each kind, and by
   -1, BPF_LD_ABS and BPF_LD_IND, the context's fields read whole, narrower
   and sign-extended, bpf_get_smp_processor_id and a lookup of an array, a
   hash and an LRU hash inlined and of either of two arrays not, dead code
   and jumps of 0 removed, a bpf_fastcall spill and fill that stay, a
   32-bit cmpxchg's zero-extension, and with
   BPF_F_TEST_RND_HI32 the 32-bit results' upper halves. Then what
   SO_ATTACH_BPF charges the socket for a program, after its rewrites, at
   the edge of net.core.optmem_max.
   bpf-prog-udp: in a network namespace of its own, with its loopback up,
   socket filters on UDP sockets of the loopback, IPv4 and
   IPv6, and an IPv4 datagram to a dual-stack IPv6 socket: the options'
   errors, SO_LOCK_FILTER and SO_BPF_EXTENSIONS, as on an AF_UNIX socket;
   what a filter keeps
   (always the UDP header, and of the rest what it says), and what is then
   queued (FIONREAD); the fields of struct __sk_buff that it reads, of an
   unconnected socket and of a connected one with SO_PRIORITY (the hash
   only as set or 0, as both kernels draw it at random); the bytes before
   the data with bpf_skb_load_bytes_relative, from the loopback's MAC
   header and from the network header, to the linear part's end, which
   for a datagram in pages is the UDP header's (the IPv4 ID and header
   checksum, the IPv6 flow label and the ports, random, are not printed);
   classic loads of the ancillary fields and of the headers, which reach
   the bytes in pages too; and that a
   datagram takes of the receive buffer what it took as it came, however
   little of it the filter kept.
   bpf-prog-corpus: 400 programs from a seeded generator, near the edges
   of what the verifier takes: registers read before they are written,
   the stack and a map's value read and written at their bounds, a
   lookup's result used before and after its null check, pointers moved by
   constants, the context's fields, helpers' arguments, 32-bit and signed
   arithmetic and jumps. For each, the load's result and the log's reason,
   and for one loaded whose run depends only on its input, what it keeps of
   a datagram and leaves in its maps. The generator tracks what both
   kernels know of each register on every path, so that the emulator's
   verifier, which knows less of a number than Linux's, decides as both
   kernels do: it compares a register only where both know its value or
   neither knows anything of it, and moves a pointer only by a number both
   know. It writes no instruction with reserved fields set: master refuses
   one before it walks any path (check_alu_fields), and 7.0 only when a
   path reaches it, so the two may give another error first. The rule this
   guards is that the emulator accepts no program Linux refuses.

   Each program refused is wrong in one way only, which both kernels the
   tests know (Linux 7.0, the CI machines', and master) find first, with
   the same error. The rest of the log, a trace of each instruction that
   each kernel words its own way, its size (log_true_size), the program's
   ID, whether a JIT compiled it (prog_jited) and how many instructions
   the verifier went through (verified_insns, which depends on how it
   prunes) are not printed. The case runs as root, as the guest does:
   loading needs CAP_BPF and CAP_PERFMON. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
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

/* bpf-prog-corpus: programs made by a seeded generator. */

/* What both kernels know of a register on every path to an instruction,
   as the generator tracks it. */
enum kind {
    UNINIT,   /* not written on some path */
    EXACT,    /* a value both know */
    FRESH,    /* a 64-bit value neither knows anything of, not yet compared */
    SCALAR,   /* a number Linux may know more of than the emulator */
    CTX,      /* the context, at off */
    FP,       /* the stack, at off from the frame pointer */
    VALUE,    /* a map's value, at off */
    NULLABLE, /* a lookup's result not yet checked; off is its ID */
    MAPPTR,   /* a map */
    ANY,      /* any of these */
};
struct reg {
    uint8_t kind;
    uint8_t has; /* whether off (or v) is known */
    int64_t v;   /* EXACT's value, or a pointer's offset */
};
struct gstate {
    int live;
    struct reg r[11];
    uint8_t init[512]; /* the stack's bytes written on every path, fp-512 first */
    struct reg slot[64]; /* what an 8-byte slot holds, filled as a whole */
};

#define MAXINSNS 96
#define MAXACTIONS 14
static struct gen {
    uint64_t seed;
    struct insn p[MAXINSNS];
    int n;
    int nondet; /* whether running it gives what only the kernel decides */
    int hash, array;
    int ids;
    struct gstate cur, pending[MAXACTIONS + 2];
    int start[MAXACTIONS + 2];
    struct { int at, to; } jumps[MAXACTIONS * 2];
    int njumps;
} g;

static uint32_t rnd(uint32_t n) {
    g.seed ^= g.seed << 13;
    g.seed ^= g.seed >> 7;
    g.seed ^= g.seed << 17;
    return n ? (uint32_t)(g.seed % n) : 0;
}
static int chance(int percent) { return (int)rnd(100) < percent; }

static int scalarish(const struct reg *r) { return r->kind == EXACT || r->kind == FRESH || r->kind == SCALAR; }
static int pointer(const struct reg *r) {
    return r->kind == CTX || r->kind == FP || r->kind == VALUE || r->kind == NULLABLE || r->kind == MAPPTR;
}

static struct reg mk(uint8_t kind, int has, int64_t v) { return (struct reg){kind, (uint8_t)has, v}; }

static struct reg merge_reg(struct reg a, struct reg b) {
    if (a.kind == b.kind && a.has == b.has && (!a.has || a.v == b.v)) return a;
    if (a.kind == UNINIT || b.kind == UNINIT) return mk(UNINIT, 0, 0);
    if (scalarish(&a) && scalarish(&b)) return mk(SCALAR, 0, 0);
    if (a.kind == b.kind && a.kind != NULLABLE) return mk(a.kind, 0, 0);
    return mk(ANY, 0, 0);
}

static void merge_into(struct gstate *into, const struct gstate *from) {
    if (!from->live) return;
    if (!into->live) {
        *into = *from;
        return;
    }
    for (int i = 0; i < 11; i++) into->r[i] = merge_reg(into->r[i], from->r[i]);
    for (int i = 0; i < 512; i++) into->init[i] &= from->init[i];
    for (int i = 0; i < 64; i++) into->slot[i] = merge_reg(into->slot[i], from->slot[i]);
}

#define EMIT(...) emit((struct insn)__VA_ARGS__)
static void emit(struct insn i) {
    if (g.n < MAXINSNS) g.p[g.n++] = i;
}
static void emit2(struct insn a, struct insn b) {
    EMIT(a);
    EMIT(b);
}

static int reg_pick(void) { return (int)rnd(10); }
/* A register to read: mostly one written on every path. */
static int read_pick(void) {
    int found[10], n = 0;
    for (int i = 0; i < 10; i++)
        if (g.cur.r[i].kind != UNINIT && g.cur.r[i].kind != ANY) found[n++] = i;
    return n && chance(92) ? found[rnd((uint32_t)n)] : reg_pick();
}

/* A number to compute with: mostly one in a register already, else one
   moved there first. */
static void emit(struct insn i);
static int scalar_pick(void) {
    int found[10], n = 0;
    for (int i = 0; i < 10; i++)
        if (scalarish(&g.cur.r[i])) found[n++] = i;
    if (!chance(88)) return read_pick();
    if (n && chance(80)) return found[rnd((uint32_t)n)];
    int r = (int)rnd(10);
    int32_t v = (int32_t)rnd(64) - 8;
    emit((struct insn)MOV(r, v));
    g.cur.r[r] = mk(EXACT, 1, v);
    return r;
}

/* A register of a kind, if one has it, else -1. */
static int find(uint8_t kind) {
    int found[11], n = 0;
    for (int i = 0; i < 10; i++)
        if (g.cur.r[i].kind == kind) found[n++] = i;
    return n ? found[rnd((uint32_t)n)] : -1;
}

static const int32_t edges[] = {0, 1, -1, 2, 3, 7, 8, 16, 31, 32, 63, 64, 255, 0x7fffffff,
                                INT32_MIN, -8, -512, 0x10000, 100};
static int32_t edge(void) {
    if (chance(15)) return (int32_t)(rnd(0xffffffff) - 0x80000000u);
    return edges[rnd(COUNT(edges))];
}

/* The stack's bytes [off, off + size) from the frame pointer, if all are
   in it. */
static int stack_range(int64_t off, int size, int *lo) {
    if (off < -512 || off + size > 0) return 0;
    *lo = (int)(off + 512);
    return 1;
}
static void stack_written(int64_t off, int size) {
    int lo;
    if (!stack_range(off, size, &lo)) return;
    for (int i = 0; i < size; i++) g.cur.init[lo + i] = 1;
    for (int s = lo / 8; s <= (lo + size - 1) / 8; s++) g.cur.slot[s] = mk(ANY, 0, 0);
}
static int stack_known(int64_t off, int size) {
    int lo;
    if (!stack_range(off, size, &lo)) return 1; /* refused anyway */
    for (int i = 0; i < size; i++)
        if (!g.cur.init[lo + i]) return 0;
    return 1;
}

/* The value of op on known values, as both kernels compute it, or 0 when
   the emulator does not know it (scalar_math). */
static int fold(uint8_t op, int wide, uint64_t a, uint64_t b, uint64_t *out) {
    unsigned bits = wide ? 64 : 32;
    if ((op == 0x60 || op == 0x70 || op == 0xc0) && b >= bits) return 0;
    if (!wide) {
        uint32_t x = (uint32_t)a, y = (uint32_t)b, r;
        switch (op) {
        case 0x00: r = x + y; break;
        case 0x10: r = x - y; break;
        case 0x20: r = x * y; break;
        case 0x40: r = x | y; break;
        case 0x50: r = x & y; break;
        case 0x60: r = x << y; break;
        case 0x70: r = x >> y; break;
        case 0xa0: r = x ^ y; break;
        case 0xc0: r = (uint32_t)((int32_t)x >> y); break;
        default: return 0;
        }
        *out = r;
        return 1;
    }
    switch (op) {
    case 0x00: *out = a + b; break;
    case 0x10: *out = a - b; break;
    case 0x20: *out = a * b; break;
    case 0x40: *out = a | b; break;
    case 0x50: *out = a & b; break;
    case 0x60: *out = a << b; break;
    case 0x70: *out = a >> b; break;
    case 0xa0: *out = a ^ b; break;
    case 0xc0: *out = (uint64_t)((int64_t)a >> b); break;
    default: return 0;
    }
    return 1;
}

static const uint8_t alu_ops[] = {0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
                                  0x90, 0xa0, 0xc0, 0x80, 0xd0};

/* An ALU instruction with an immediate. */
static void alu_imm(void) {
    int dst = scalar_pick();
    int wide = chance(70);
    uint8_t op = alu_ops[rnd(COUNT(alu_ops))];
    int32_t imm = edge();
    int16_t off = 0;
    if ((op == 0x30 || op == 0x90) && chance(30)) off = 1; /* sdiv, smod */
    if (op == 0x80) imm = 0; /* neg has none */
    if ((op == 0x60 || op == 0x70 || op == 0xc0) && chance(85)) imm = (int32_t)rnd(wide ? 64 : 32);
    if (op == 0xd0) {                                      /* bswap or to_le/to_be */
        static const int32_t widths[] = {16, 32, 64};
        imm = widths[rnd(3)];
        wide = chance(40);
    }
    uint8_t code = (uint8_t)((wide ? 0x07 : 0x04) | op);
    if (op == 0xd0 && !wide && chance(50)) code |= 0x08; /* to_be */
    EMIT(I(code, dst, 0, off, imm));
    struct reg *d = &g.cur.r[dst];
    uint64_t v;
    if (d->kind == EXACT && op != 0x80 && op != 0xd0 && fold(op, wide, (uint64_t)d->v, wide ? (uint64_t)(int64_t)imm : (uint32_t)imm, &v))
        *d = mk(EXACT, 1, (int64_t)v);
    else if (d->kind == EXACT && op == 0x80)
        *d = mk(EXACT, 1, wide ? -(int64_t)d->v : (int64_t)(uint32_t)-(uint32_t)d->v);
    else if (scalarish(d))
        *d = mk(SCALAR, 0, 0);
    else if ((d->kind == CTX || d->kind == FP || d->kind == VALUE) && wide && (op == 0x00 || op == 0x10))
        *d = mk(d->kind, d->has, d->v + (op == 0x00 ? imm : -(int64_t)imm));
    else {
        if (d->kind != UNINIT) g.nondet = 1;
        *d = mk(ANY, 0, 0);
    }
}

/* An ALU instruction of two registers, which never adds a number the
   kernels may know differently to a pointer. */
static void alu_reg(void) {
    int dst = scalar_pick(), src = chance(5) ? 10 : scalar_pick();
    int wide = chance(75);
    uint8_t op = alu_ops[rnd(COUNT(alu_ops) - 2)]; /* not neg or end */
    if (chance(20)) op = 0xb0;                      /* mov */
    struct reg *d = &g.cur.r[dst], s = g.cur.r[src];
    int16_t off = 0;
    if (op == 0xb0) {
        if (chance(15)) off = (int16_t)(8 << rnd(wide ? 3 : 2)); /* movsx 8, 16 (, 32) */
        EMIT(I((uint8_t)((wide ? 0x0f : 0x0c) | op), dst, src, off, 0));
        if (s.kind == UNINIT) {
            *d = mk(UNINIT, 0, 0);
            return;
        }
        if (wide && !off) {
            if (s.kind == FRESH) s = mk(SCALAR, 0, 0);
            if (src != 10 && g.cur.r[src].kind == FRESH) g.cur.r[src] = s;
            *d = s;
        } else if (s.kind == EXACT && !off) {
            *d = mk(EXACT, 1, (int64_t)(uint32_t)s.v);
        } else {
            if (!scalarish(&s)) g.nondet = 1;
            *d = mk(SCALAR, 0, 0);
        }
        return;
    }
    /* Two numbers, two pointers, or anything with a number both know:
       never a pointer, or what may be one, with another number. */
    int ok = (scalarish(d) && scalarish(&s)) || (pointer(d) && pointer(&s)) || d->kind == EXACT ||
             s.kind == EXACT || d->kind == UNINIT || s.kind == UNINIT;
    if (!ok) {
        alu_imm();
        return;
    }
    if ((op == 0x30 || op == 0x90) && chance(30)) off = 1;
    EMIT(I((uint8_t)((wide ? 0x0f : 0x0c) | op), dst, src, off, 0));
    uint64_t v;
    if (d->kind == UNINIT || s.kind == UNINIT) {
        *d = mk(ANY, 0, 0);
    } else if (d->kind == EXACT && s.kind == EXACT) {
        *d = fold(op, wide, (uint64_t)d->v, (uint64_t)s.v, &v) ? mk(EXACT, 1, (int64_t)v) : mk(SCALAR, 0, 0);
    } else if (scalarish(d) && scalarish(&s)) {
        *d = mk(SCALAR, 0, 0);
    } else if (wide && op == 0x00 && (s.kind == EXACT) && (d->kind == CTX || d->kind == FP || d->kind == VALUE)) {
        *d = mk(d->kind, d->has, d->v + s.v);
    } else if (wide && op == 0x00 && d->kind == EXACT && (s.kind == CTX || s.kind == FP || s.kind == VALUE)) {
        *d = mk(s.kind, s.has, s.v + d->v);
    } else if (wide && op == 0x10 && s.kind == EXACT && (d->kind == CTX || d->kind == FP || d->kind == VALUE)) {
        *d = mk(d->kind, d->has, d->v - s.v);
    } else {
        g.nondet = 1;
        *d = mk(ANY, 0, 0);
    }
}

/* The base of a load or store, and an offset near an edge of what it
   points to. */
static int base(int16_t *off, int size) {
    int b;
    switch (rnd(8)) {
    case 0: case 1: case 2:
        b = 10;
        break;
    case 3: case 4:
        b = find(VALUE);
        break;
    case 5:
        b = find(CTX);
        break;
    case 6:
        b = find(FP);
        break;
    default:
        b = read_pick();
        break;
    }
    if (b < 0) b = 10;
    struct reg r = g.cur.r[b];
    int64_t at = r.has ? r.v : 0;
    int64_t want;
    switch (r.kind) {
    case FP: {
        static const int16_t near[] = {-8, -16, -4, -1, -512, -513, -504, 0, -2, -24};
        want = chance(85) ? -8 * (int64_t)(1 + rnd(8)) + (int64_t)rnd(8 / size) * size
                          : near[rnd(COUNT(near))];
        break;
    }
    case VALUE: {
        static const int16_t near[] = {0, 8, 15, 16, -1, 4, 12, 9};
        want = chance(80) ? (int64_t)rnd(16 / size) * size : near[rnd(COUNT(near))];
        break;
    }
    case CTX: {
        static const int16_t near[] = {0, 0, 48, 52, 64, 68, 44, 2, 1, 76, 80, 4, 8, 72, 160, 192};
        want = chance(70) ? (chance(40) ? 0 : 48 + 4 * (int64_t)rnd(5)) : near[rnd(COUNT(near))];
        break;
    }
    default:
        want = (int64_t)rnd(16) - 8;
        break;
    }
    *off = (int16_t)(want - at);
    return b;
}

static const uint8_t sizes[] = {0x18, 0x00, 0x08, 0x10}; /* dw, w, h, b */
static int size_bytes(uint8_t s) { return s == 0x18 ? 8 : s == 0x00 ? 4 : s == 0x08 ? 2 : 1; }

static void store(void) {
    uint8_t sz = sizes[rnd(4)];
    int size = size_bytes(sz);
    int16_t off;
    int b = base(&off, size);
    struct reg r = g.cur.r[b];
    int imm = chance(30), src = size == 8 ? read_pick() : scalar_pick();
    if (imm)
        EMIT(I((uint8_t)(0x62 | sz), b, 0, off, edge()));
    else
        EMIT(I((uint8_t)(0x63 | sz), b, src, off, 0));
    struct reg s = imm ? mk(EXACT, 0, 0) : g.cur.r[src];
    if (r.kind == FP && r.has) {
        int64_t at = r.v + off;
        int lo;
        int spill = !imm && size == 8 && stack_range(at, 8, &lo) && lo % 8 == 0;
        stack_written(at, size);
        if (spill) g.cur.slot[lo / 8] = s.kind == FRESH ? mk(SCALAR, 0, 0) : s;
        else if (!imm && !scalarish(&s)) g.nondet = 1;
    } else {
        if (!imm && !scalarish(&s)) g.nondet = 1;
        /* It may have written any of the stack's slots. */
        if (r.kind == FP || r.kind == ANY)
            for (int i = 0; i < 64; i++) g.cur.slot[i] = mk(ANY, 0, 0);
    }
}

static void load_mem(void) {
    uint8_t sz = sizes[rnd(4)];
    int size = size_bytes(sz);
    int16_t off;
    int b = base(&off, size);
    int dst = reg_pick();
    int sx = sz != 0x18 && chance(10);
    struct reg r = g.cur.r[b];
    EMIT(I((uint8_t)((sx ? 0x81 : 0x61) | sz), dst, b, off, 0));
    struct reg got = mk(ANY, 0, 0);
    if (r.kind == FP && r.has) {
        int64_t at = r.v + off;
        int lo;
        if (!stack_known(at, size)) g.nondet = 1;
        if (size == 8 && stack_range(at, 8, &lo) && lo % 8 == 0 && g.cur.init[lo]) got = g.cur.slot[lo / 8];
        if (got.kind == EXACT) got = mk(SCALAR, 0, 0);
    } else if (r.kind == VALUE) {
        got = mk(size == 8 && !sx ? FRESH : SCALAR, 0, 0);
    } else if (r.kind == CTX && r.has) {
        int64_t at = r.v + off;
        if (!(at == 0 && size == 4) && !(at >= 48 && at + size <= 68)) g.nondet = 1;
        got = mk(SCALAR, 0, 0);
    } else {
        g.nondet = 1;
    }
    if (got.kind == ANY || !scalarish(&got)) {
        if (!pointer(&got)) got = mk(ANY, 0, 0);
    }
    g.cur.r[dst] = got;
}

static void clobber(void) {
    for (int i = 1; i <= 5; i++) g.cur.r[i] = mk(UNINIT, 0, 0);
}

/* R2 = the frame pointer at off, or an edge in its place. */
static void stack_arg(int reg, int64_t off) {
    EMIT(MOV_REG(reg, 10));
    EMIT(ADD(reg, (int32_t)off));
}

static void call(void) {
    switch (rnd(6)) {
    case 0: { /* no arguments */
        static const int32_t ids[] = {5, 7, 8, 14, 15};
        int32_t id = ids[rnd(COUNT(ids))];
        EMIT(CALL(id));
        clobber();
        g.cur.r[0] = mk(id == 5 || id == 7 ? FRESH : SCALAR, 0, 0);
        g.nondet = 1; /* the time, a random number, the processor, the task */
        break;
    }
    case 1: case 2: { /* lookup in the hash */
        int64_t key = chance(85) ? -4 : (chance(50) ? -2 : 0);
        if (chance(80)) {
            EMIT(ST_W(10, -4, (int32_t)rnd(3)));
            stack_written(-4, 4);
        }
        if (!stack_known(key, 4)) g.nondet = 1;
        emit2((struct insn)I(0x18, 1, 1, 0, chance(95) ? g.hash : 77), (struct insn)I(0, 0, 0, 0, 0));
        stack_arg(2, key);
        EMIT(CALL(LOOKUP));
        clobber();
        g.cur.r[0] = mk(NULLABLE, 1, ++g.ids);
        break;
    }
    case 3: { /* update or delete in the hash */
        int del = chance(30);
        EMIT(ST_W(10, -4, (int32_t)rnd(3)));
        stack_written(-4, 4);
        int64_t value = chance(80) ? -24 : (chance(50) ? -8 : -20);
        int v = find(VALUE);
        if (!del && v >= 0 && chance(30)) {
            EMIT(MOV_REG(3, v));
        } else if (!del) {
            if (!stack_known(value, 16)) g.nondet = 1;
            stack_arg(3, value);
        }
        emit2((struct insn)I(0x18, 1, 1, 0, g.hash), (struct insn)I(0, 0, 0, 0, 0));
        stack_arg(2, -4);
        if (!del) EMIT(MOV(4, (int32_t)rnd(4)));
        EMIT(CALL(del ? DELETE : UPDATE));
        clobber();
        g.cur.r[0] = mk(SCALAR, 0, 0);
        break;
    }
    case 4: { /* bpf_skb_load_bytes, from the context in R6 or R1 */
        static const int32_t offs[] = {0, 1, 60, 63, 64, -1, 0x7fffffff, 8};
        static const int32_t lens[] = {1, 4, 8, 16, 0, -1, 64, 3};
        static const int16_t to[] = {-8, -16, -64, -4, -12, 0, -520};
        int ctx = g.cur.r[6].kind == CTX && chance(90) ? 6 : 1;
        if (ctx != 1) EMIT(MOV_REG(1, ctx));
        if (g.cur.r[1].kind != CTX && ctx == 1) g.nondet = 1;
        int32_t len = lens[rnd(COUNT(lens))];
        int16_t at = to[rnd(COUNT(to))];
        EMIT(MOV(2, offs[rnd(COUNT(offs))]));
        stack_arg(3, at);
        EMIT(MOV(4, len));
        EMIT(CALL(LOAD_BYTES));
        clobber();
        if (len > 0) stack_written(at, len);
        g.cur.r[0] = mk(SCALAR, 0, 0);
        break;
    }
    default: { /* a value of the array by its address */
        int dst = 6 + (int)rnd(4);
        int32_t off = chance(85) ? 0 : (chance(50) ? 8 : 16);
        emit2((struct insn)I(0x18, dst, 2, 0, g.array), (struct insn)I(0, 0, 0, 0, off));
        g.cur.r[dst] = mk(VALUE, 1, off);
        break;
    }
    }
}

static const uint8_t jmp_ops[] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0xa0, 0xb0, 0xc0, 0xd0};

/* A jump to a later action, recorded to be aimed when it starts. */
static void jump(int action, int actions) {
    int to = action + 1 + (int)rnd((uint32_t)(actions - action));
    if (chance(3)) to = actions + 1; /* past the end */
    int wide = chance(75);
    uint8_t op = jmp_ops[rnd(COUNT(jmp_ops))];
    int a = read_pick(), b = -1;
    int32_t imm = 0;
    struct reg *ra = &g.cur.r[a];
    int nullcheck = 0;
    int n = find(NULLABLE);
    if (chance(3)) {
        op = 0x00; /* ja */
    } else if (n >= 0 && chance(60)) {
        a = n;
        ra = &g.cur.r[a];
        op = chance(50) ? 0x10 : 0x50; /* jeq, jne */
        wide = 1;
        imm = 0;
        nullcheck = 1;
    } else if (ra->kind == EXACT) {
        if (chance(50)) {
            imm = edge();
        } else {
            b = find(EXACT);
            if (b < 0) imm = edge();
        }
    } else if (ra->kind == FRESH) {
        static const int32_t safe[] = {1, 5, 100, -5};
        int f = find(FRESH);
        if (f >= 0 && f != a && chance(30)) b = f;
        else imm = safe[rnd(COUNT(safe))];
    } else if (ra->kind == UNINIT && chance(30)) {
        imm = 1; /* refused: not readable */
    } else {
        alu_imm(); /* no comparison both kernels decide alike */
        return;
    }
    int at = g.n;
    if (op == 0x00)
        EMIT(I(0x05, 0, 0, 0, 0));
    else
        EMIT(I((uint8_t)((wide ? 0x05 : 0x06) | op | (b >= 0 ? 0x08 : 0)), a, b >= 0 ? b : 0, 0, imm));
    if (g.njumps < (int)COUNT(g.jumps)) g.jumps[g.njumps++] = (typeof(g.jumps[0])){at, to};
    struct gstate other = g.cur;
    if (op != 0x00) {
        if (nullcheck) {
            int64_t id = ra->v;
            for (int i = 0; i < 10; i++) {
                if (g.cur.r[i].kind != NULLABLE || g.cur.r[i].v != id) continue;
                /* jeq: the target has it null; jne: the next instruction. */
                struct reg value = mk(VALUE, 1, 0), null = mk(SCALAR, 0, 0);
                other.r[i] = op == 0x10 ? null : value;
                g.cur.r[i] = op == 0x10 ? value : null;
            }
        } else {
            for (int i = 0; i < 2; i++) {
                int r = i ? b : a;
                if (r < 0 || g.cur.r[r].kind != FRESH) continue;
                g.cur.r[r] = mk(SCALAR, 0, 0);
                other.r[r] = mk(SCALAR, 0, 0);
            }
        }
    } else {
        g.cur.live = 0;
    }
    if (to <= actions) merge_into(&g.pending[to], &other);
}

/* One program, written to g.p. */
static void generate(void) {
    g.n = 0;
    g.nondet = 0;
    g.njumps = 0;
    g.ids = 0;
    memset(&g.cur, 0, sizeof g.cur);
    memset(g.pending, 0, sizeof g.pending);
    g.cur.live = 1;
    for (int i = 0; i < 11; i++) g.cur.r[i] = mk(UNINIT, 0, 0);
    for (int i = 0; i < 64; i++) g.cur.slot[i] = mk(ANY, 0, 0);
    g.cur.r[1] = mk(CTX, 1, 0);
    g.cur.r[10] = mk(FP, 1, 0);
    if (chance(85)) {
        EMIT(MOV_REG(6, 1));
        g.cur.r[6] = g.cur.r[1];
    }
    if (chance(60)) {
        emit2((struct insn)I(0x18, 7, 2, 0, g.array), (struct insn)I(0, 0, 0, 0, 0));
        g.cur.r[7] = mk(VALUE, 1, 0);
    }
    int actions = 1 + (int)rnd(8);
    for (int k = 0; k <= actions; k++) {
        g.start[k] = g.n;
        if (g.pending[k].live) merge_into(&g.cur, &g.pending[k]);
        if (!g.cur.live) { /* unreachable code, which both refuse */
            g.cur.live = 1;
        }
        if (k == actions) break;
        switch (rnd(12)) {
        case 0: case 1:
            alu_imm();
            break;
        case 2: case 3:
            alu_reg();
            break;
        case 4:
            EMIT(MOV(reg_pick(), edge()));
            {
                int d = g.p[g.n - 1].regs & 15;
                g.cur.r[d] = mk(EXACT, 1, g.p[g.n - 1].imm);
            }
            break;
        case 5: case 6:
            store();
            break;
        case 7: case 8:
            load_mem();
            break;
        case 9: case 10:
            call();
            break;
        default:
            jump(k, actions);
            break;
        }
    }
    /* The end: a result to keep in the array's value, R0, the exit. */
    g.start[actions + 1] = -1;
    if (g.cur.r[7].kind == VALUE && g.cur.r[7].has && g.cur.r[7].v == 0 && chance(70)) {
        int s = read_pick();
        if (!scalarish(&g.cur.r[s])) g.nondet = 1;
        EMIT(STX_DW(7, s, 8));
    }
    if (g.cur.r[0].kind == UNINIT ? chance(95) : chance(50)) {
        static const int32_t results[] = {0, 1, 3, 8, 64, -1, 17};
        EMIT(MOV(0, results[rnd(COUNT(results))]));
    } else if (!scalarish(&g.cur.r[0])) {
        g.nondet = 1;
    }
    if (chance(99)) EMIT(EXIT());
    for (int j = 0; j < g.njumps; j++) {
        int target = g.jumps[j].to <= actions ? g.start[g.jumps[j].to] : g.n;
        g.p[g.jumps[j].at].off = (int16_t)(target - g.jumps[j].at - 1);
    }
}

/* Runs a program on a datagram of 64 bytes and says what it kept and what
   it left in the maps. */
static void filter_run(int prog) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair)) return;
    int err = attach(pair[1], prog);
    if (err) {
        say("  attach %d", err);
    } else {
        unsigned char out[64], in[64];
        for (size_t i = 0; i < sizeof out; i++) out[i] = (unsigned char)(i * 7 + 3);
        long sent = send(pair[0], out, sizeof out, MSG_DONTWAIT);
        long got = recv(pair[1], in, sizeof in, MSG_DONTWAIT);
        printf("  sent %ld received %ld", sent < 0 ? -errno : sent, got < 0 ? -errno : got);
        for (int m = 0; m < 2; m++) {
            uint32_t key = 0;
            uint8_t value[16] = {0};
            uint64_t a[16] = {(uint32_t)(m ? g.hash : g.array), (uintptr_t)&key, (uintptr_t)value};
            long r = bpf(1, a, sizeof a);
            printf(" %s", m ? "hash" : "array");
            if (r < 0) printf(" %ld", r);
            else
                for (int i = 0; i < 16; i++) printf("%s%02x", i % 8 ? "" : " ", value[i]);
        }
        putchar('\n');
        fflush(stdout);
    }
    close(pair[0]);
    close(pair[1]);
}

static int case_corpus(void) {
    g.seed = 0x9e3779b97f4a7c15ull;
    for (int k = 0; k < 400; k++) {
        g.array = map(2, 4, 16, 1, 0);
        g.hash = map(1, 4, 16, 4, 0);
        uint32_t key = 0;
        uint8_t value[16];
        for (int i = 0; i < 16; i++) value[i] = (uint8_t)(0x10 + i);
        uint64_t u[16] = {(uint32_t)g.hash, (uintptr_t)&key, (uintptr_t)value, 0};
        if (g.array < 0 || g.hash < 0 || bpf(2, u, sizeof u)) return 1;
        generate();
        memset(log_text, 0, sizeof log_text);
        struct prog_attr p = attr(g.p, (unsigned)g.n);
        long fd = bpf(PROG_LOAD, &p, sizeof p);
        if (fd < 0) {
            say("corpus %d: %ld", k, fd);
            reason();
        } else if (g.nondet) {
            say("corpus %d: loaded, not run", k);
            close((int)fd);
        } else {
            say("corpus %d: loaded", k);
            filter_run((int)fd);
            close((int)fd);
        }
        close(g.array);
        close(g.hash);
    }
    return 0;
}

/* Classic filters: struct sock_filter and struct sock_fprog. */
struct sf {
    uint16_t code;
    uint8_t jt, jf;
    uint32_t k;
};
struct fprog {
    uint16_t len;
    const struct sf *filter;
};
#define S(code, k) ((struct sf){(code), 0, 0, (uint32_t)(k)})
#define SJ(code, jt, jf, k) ((struct sf){(code), (jt), (jf), (uint32_t)(k)})
#define C_RET_K 0x06
#define C_RET_A 0x16
#define C_LD_IMM 0x00
#define C_LDX_IMM 0x01
#define C_LD_W_ABS 0x20
#define C_LD_H_ABS 0x28
#define C_LD_B_ABS 0x30
#define C_LD_W_IND 0x40
#define C_LD_H_IND 0x48
#define C_LD_B_IND 0x50
#define C_LD_MEM 0x60
#define C_LDX_MEM 0x61
#define C_LD_LEN 0x80
#define C_LDX_LEN 0x81
#define C_LDX_MSH 0xb1
#define C_ST 0x02
#define C_STX 0x03
#define C_TAX 0x07
#define C_TXA 0x87
#define C_JA 0x05
#define C_JEQ_K 0x15
#define C_JEQ_X 0x1d
#define C_JGT_K 0x25
#define C_JGT_X 0x2d
#define C_JGE_K 0x35
#define C_JSET_K 0x45
#define C_JSET_X 0x4d
#define C_ALU_K(op) (0x04 | (op))
#define C_ALU_X(op) (0x0c | (op))
#define C_ADD 0x00
#define C_SUB 0x10
#define C_MUL 0x20
#define C_DIV 0x30
#define C_OR 0x40
#define C_AND 0x50
#define C_LSH 0x60
#define C_RSH 0x70
#define C_NEG 0x84
#define C_MOD 0x90
#define C_XOR 0xa0
#define AD(n) (-0x1000 + (n))
#define NET(n) (-0x100000 + (n))
#define LL(n) (-0x200000 + (n))

static int attach_classic_len(int sock, const struct sf *filter, unsigned count, socklen_t len) {
    struct fprog p = {(uint16_t)count, filter};
    return setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &p, len) ? -errno : 0;
}
static int attach_classic(int sock, const struct sf *filter, unsigned count) {
    return attach_classic_len(sock, filter, count, sizeof(struct fprog));
}
#define CLASSIC(sock, ...)                                      \
    ({                                                          \
        struct sf f_[] = {__VA_ARGS__};                         \
        attach_classic((sock), f_, COUNT(f_));                  \
    })

static unsigned char pattern[300], netlink[300];
static unsigned char *large;
#define LARGE 20000

/* What b receives of msg from a: its length, or -errno. */
static long kept(int a, int b, const unsigned char *msg, size_t len) {
    static unsigned char in[LARGE];
    if (send(a, msg, len, MSG_DONTWAIT) < 0) return -1000 - errno;
    long got = recv(b, in, sizeof in, MSG_DONTWAIT);
    return got < 0 ? -errno : got;
}

/* The value `code` leaves in A, byte by byte: each run keeps one byte
   more than the byte of A it shifts down, of a message longer than 256.
   A filter that returns 0 before the end drops the message. */
static void value(const char *name, const unsigned char *msg, size_t len, const struct sf *code, unsigned n) {
    int p[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, p)) return;
    int on = 1 << 20;
    setsockopt(p[1], SOL_SOCKET, SO_RCVBUF, &on, sizeof on);
    setsockopt(p[0], SOL_SOCKET, SO_SNDBUF, &on, sizeof on);
    uint32_t v = 0;
    for (int shift = 0; shift < 32; shift += 8) {
        struct sf f[64];
        memcpy(f, code, n * sizeof *f);
        f[n] = S(C_ALU_K(C_RSH), shift);
        f[n + 1] = S(C_ALU_K(C_AND), 0xff);
        f[n + 2] = S(C_ALU_K(C_ADD), 1);
        f[n + 3] = S(C_RET_A, 0);
        int r = attach_classic(p[1], f, n + 4);
        if (r) {
            say("%s attach %d", name, r);
            goto out;
        }
        long got = kept(p[0], p[1], msg, len);
        if (got <= 0) {
            say("%s dropped %ld", name, got);
            goto out;
        }
        v |= (uint32_t)(got - 1) << shift;
    }
    say("%s = %#x", name, v);
out:
    close(p[0]);
    close(p[1]);
}
#define VALUE(name, msg, ...)                                   \
    do {                                                        \
        struct sf c_[] = {__VA_ARGS__};                         \
        value((name), (msg), sizeof(msg), c_, COUNT(c_));       \
    } while (0)
#define LARGE_VALUE(name, ...)                                  \
    do {                                                        \
        struct sf c_[] = {__VA_ARGS__};                         \
        value((name), large, LARGE, c_, COUNT(c_));             \
    } while (0)

/* What a filter of `count` copies of `one` and a return is refused with,
   or 0. */
static int many(int sock, struct sf one, unsigned count, struct sf last) {
    static struct sf f[4097];
    for (unsigned i = 0; i < count; i++) f[i] = one;
    f[count] = last;
    return attach_classic(sock, f, count + 1);
}

/* SO_GET_FILTER with *len of `len` blocks: the error, or *len and the
   instructions given. */
static void get_classic(const char *name, int sock, socklen_t len) {
    struct sf out[16];
    socklen_t asked = len;
    memset(out, 0xee, sizeof out);
    if (getsockopt(sock, SOL_SOCKET, SO_GET_FILTER, out, &len)) {
        say("%s %d", name, -errno);
        return;
    }
    printf("%s len %u:", name, len);
    for (unsigned i = 0; asked && i < len && i < 16; i++)
        printf(" %#x/%u/%u/%#x", out[i].code, out[i].jt, out[i].jf, out[i].k);
    putchar('\n');
    fflush(stdout);
}

static int case_classic(void) {
    for (size_t i = 0; i < sizeof pattern; i++) pattern[i] = (unsigned char)(i * 7 + 3);
    large = malloc(LARGE);
    if (!large) return 1;
    for (size_t i = 0; i < LARGE; i++) large[i] = (unsigned char)(i * 13 + i / 256);
    /* Netlink attributes: type 1 of 4 bytes, a nested type 2 that holds
       type 5, type 3 of 2 bytes (padded to 4), type 4 with
       NLA_F_NET_BYTEORDER, then zeros, where the search stops. */
    static const unsigned char attrs[] = {8, 0, 1, 0, 0xa, 0xb, 0xc, 0xd,
                                          12, 0, 2, 0x80, 8, 0, 5, 0, 1, 2, 3, 4,
                                          6, 0, 3, 0, 9, 9, 0, 0,
                                          8, 0, 4, 0x40, 7, 7, 7, 7};
    memcpy(netlink, attrs, sizeof attrs);

    int p[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, p)) return 1;
    struct sf ret = S(C_RET_K, 0xffff);

    /* setsockopt's checks, in Linux's order. */
    say("short len %d", attach_classic_len(p[1], &ret, 1, 2));
    say("len 8 %d", attach_classic_len(p[1], &ret, 1, 8));
    say("len 24 %d", attach_classic_len(p[1], &ret, 1, 24));
    say("bad fprog %d", setsockopt(p[1], SOL_SOCKET, SO_ATTACH_FILTER, (void *)8, 16) ? -errno : 0);
    say("null filter %d", attach_classic(p[1], NULL, 1));
    say("no insns %d", attach_classic(p[1], &ret, 0));
    say("bad filter %d", attach_classic(p[1], (void *)8, 1));
    say("4097 insns %d", many(p[1], S(C_LD_IMM, 1), 4096, ret));
    say("4096 insns %d", many(p[1], S(C_LD_IMM, 1), 4095, ret));

    /* bpf_check_classic. */
    say("unknown code %d", CLASSIC(p[1], S(0x08, 0), ret));
    say("ret x %d", CLASSIC(p[1], S(0x0e, 0), ret));
    say("seccomp load %d", CLASSIC(p[1], S(0x21, 0), ret));
    say("div 0 %d", CLASSIC(p[1], S(C_ALU_K(C_DIV), 0), ret));
    say("mod 0 %d", CLASSIC(p[1], S(C_ALU_K(C_MOD), 0), ret));
    say("lsh 32 %d", CLASSIC(p[1], S(C_ALU_K(C_LSH), 32), ret));
    say("rsh 31 %d", CLASSIC(p[1], S(C_ALU_K(C_RSH), 31), ret));
    say("mem 16 %d", CLASSIC(p[1], S(C_ST, 16), ret));
    say("ja past %d", CLASSIC(p[1], S(C_JA, 1), ret));
    say("ja last %d", CLASSIC(p[1], S(C_JA, 0), ret));
    say("jeq past %d", CLASSIC(p[1], SJ(C_JEQ_K, 0, 1, 0), ret));
    say("ancillary 64 %d", CLASSIC(p[1], S(C_LD_W_ABS, AD(64)), ret));
    say("ancillary 2 %d", CLASSIC(p[1], S(C_LD_B_ABS, AD(2)), ret));
    say("below ancillary %d", CLASSIC(p[1], S(C_LD_B_ABS, AD(-1)), ret));
    say("ind ancillary %d", CLASSIC(p[1], S(C_LD_W_IND, AD(64)), ret));
    say("msh ancillary %d", CLASSIC(p[1], S(C_LDX_MSH, AD(64)), ret));
    say("no ret %d", CLASSIC(p[1], ret, S(C_LD_IMM, 0)));
    say("unwritten %d", CLASSIC(p[1], S(C_LD_MEM, 3), ret));
    say("one path %d", CLASSIC(p[1], SJ(C_JEQ_K, 1, 0, 0), S(C_ST, 3), S(C_LDX_MEM, 3), ret));
    say("both paths %d", CLASSIC(p[1], S(C_STX, 3), SJ(C_JEQ_K, 1, 0, 0), S(C_ST, 3), S(C_LDX_MEM, 3), ret));

    /* bpf_convert_filter: ld [40000] is 16 instructions, and a jump placed
       past 32,767 or going further is too far. */
    struct sf far = S(C_LD_W_ABS, 40000);
    {
        /* A program that converts is too large to charge (ENOMEM). */
        static struct sf f[2051];
        for (int i = 0; i < 2048; i++) f[i] = far;
        f[2048] = S(C_JA, 0);
        f[2049] = ret;
        say("jump at 32775 %d", attach_classic(p[1], f, 2050));
        say("jump at 32759 %d", attach_classic(p[1], f + 1, 2049));
        f[0] = S(C_JA, 2048);
        for (int i = 1; i <= 2048; i++) f[i] = far;
        f[2049] = ret;
        say("jump of 32768 %d", attach_classic(p[1], f, 2050));
        f[1] = S(C_JA, 2047);
        say("jump of 32752 %d", attach_classic(p[1], f + 1, 2049));
    }

    /* The charge, of the converted program: 168 + 128 n bytes for n of
       them, below net.core.optmem_max (131072) up to 1,022. */
    {
        int q[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, q)) return 1;
        say("1023 far loads %d", many(q[1], far, 1023, ret));
        say("1022 far loads %d", many(q[1], far, 1022, ret));
        say("and 1 more %d", CLASSIC(q[1], ret));
        say("detach %d", option(q[1], SO_DETACH_FILTER, 0));
        say("600 far loads %d", many(q[1], far, 600, ret));
        say("600 more %d", many(q[1], far, 600, ret));
        say("replaced %d", many(q[1], far, 100, ret));
        close(q[0]);
        close(q[1]);
    }

    /* SO_GET_FILTER, SO_DETACH_FILTER and the lock. */
    {
        int q[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, q)) return 1;
        get_classic("get none", q[1], 4);
        say("attach %d", CLASSIC(q[1], SJ(C_JEQ_K, 0, 1, 0), S(C_LD_IMM, 0x1234), S(C_RET_A, 0)));
        get_classic("get len 0", q[1], 0);
        get_classic("get len 2", q[1], 2);
        get_classic("get len 3", q[1], 3);
        get_classic("get len 9", q[1], 9);
        {
            socklen_t len = 3;
            say("get to nowhere %d", getsockopt(q[1], SOL_SOCKET, SO_GET_FILTER, (void *)8, &len) ? -errno : 0);
            len = 0;
            int r = getsockopt(q[1], SOL_SOCKET, SO_GET_FILTER, (void *)8, &len) ? -errno : 0;
            say("get len 0 to nowhere %d len %u", r, len);
        }
        through("classic", q[0], q[1], 5);
        int keep2 = PROGRAM(MOV(0, 2), EXIT());
        say("attach bpf %d", attach(q[1], keep2));
        get_classic("get bpf", q[1], 4);
        through("bpf", q[0], q[1], 5);
        say("back to classic %d", CLASSIC(q[1], S(C_RET_K, 1)));
        through("classic 1", q[0], q[1], 5);
        say("detach %d", option(q[1], SO_DETACH_FILTER, 0));
        get_classic("get detached", q[1], 4);
        say("lock %d", option(q[1], SO_LOCK_FILTER, 1));
        say("locked %d", CLASSIC(q[1], ret));
        say("locked len 8 %d", attach_classic_len(q[1], &ret, 1, 8));
        say("locked null %d", attach_classic(q[1], NULL, 1));
        say("locked bad fprog %d", setsockopt(q[1], SOL_SOCKET, SO_ATTACH_FILTER, (void *)8, 16) ? -errno : 0);
        close(keep2);
        close(q[0]);
        close(q[1]);
    }

    /* What the filters compute. */
    VALUE("len", pattern, S(C_LD_LEN, 0));
    VALUE("ldx len", pattern, S(C_LDX_LEN, 0), S(C_TXA, 0));
    VALUE("ld [0]", pattern, S(C_LD_W_ABS, 0));
    VALUE("ldh [1]", pattern, S(C_LD_H_ABS, 1));
    VALUE("ldb [2]", pattern, S(C_LD_B_ABS, 2));
    VALUE("ld [296]", pattern, S(C_LD_W_ABS, 296));
    VALUE("ld [297]", pattern, S(C_LD_W_ABS, 297));
    VALUE("ldb [299]", pattern, S(C_LD_B_ABS, 299));
    VALUE("ldb [300]", pattern, S(C_LD_B_ABS, 300));
    VALUE("ldb [0x7fffffff]", pattern, S(C_LD_B_ABS, 0x7fffffff));
    VALUE("ldb [0x80000000]", pattern, S(C_LD_B_ABS, 0x80000000u));
    VALUE("ldh net 4", pattern, S(C_LD_H_ABS, NET(4)));
    VALUE("ldb net 300", pattern, S(C_LD_B_ABS, NET(300)));
    VALUE("ldb ll 0", pattern, S(C_LD_B_ABS, LL(0)));
    VALUE("ldb below ll", pattern, S(C_LD_B_ABS, LL(-1)));
    VALUE("ld [x + 4]", pattern, S(C_LDX_IMM, 10), S(C_LD_W_IND, 4));
    VALUE("ldh [x - 1]", pattern, S(C_LDX_IMM, -1), S(C_LD_H_IND, 6));
    VALUE("ldb [x + net]", pattern, S(C_LDX_IMM, 3), S(C_LD_B_IND, NET(1)));
    VALUE("ldb [x + ancillary]", pattern, S(C_LDX_IMM, 0), S(C_LD_B_IND, AD(0)));
    VALUE("ldb [x] past", pattern, S(C_LDX_IMM, 300), S(C_LD_B_IND, 0));
    VALUE("msh", pattern, S(C_LD_IMM, 9), S(C_LDX_MSH, 3), S(C_TXA, 0));
    VALUE("msh keeps a", pattern, S(C_LD_IMM, 9), S(C_LDX_MSH, 3));
    VALUE("msh past", pattern, S(C_LDX_MSH, 300), S(C_TXA, 0));
    VALUE("msh net", pattern, S(C_LDX_MSH, NET(5)), S(C_TXA, 0));
    VALUE("imm", pattern, S(C_LD_IMM, 0xdeadbeef));
    VALUE("mem", pattern, S(C_LD_IMM, 0x11223344), S(C_ST, 15), S(C_LD_IMM, 0), S(C_LDX_IMM, 5),
          S(C_STX, 0), S(C_LD_MEM, 15), S(C_LDX_MEM, 0), S(C_ALU_X(C_ADD), 0));
    VALUE("tax", pattern, S(C_LD_IMM, 77), S(C_TAX, 0), S(C_LD_IMM, 0), S(C_TXA, 0));

    static const struct {
        const char *name;
        uint8_t op;
        uint32_t a, b;
    } alu[] = {
        {"add", C_ADD, 0xfffffff0, 0x20},       {"sub", C_SUB, 5, 9},
        {"mul", C_MUL, 0x10001, 0x10001},        {"div", C_DIV, 0xffffffff, 7},
        {"mod", C_MOD, 0xffffffff, 7},           {"and", C_AND, 0xf0f0f0f0, 0x3c3c3c3c},
        {"or", C_OR, 0xf0f0f0f0, 0x3c3c3c3c},    {"xor", C_XOR, 0xf0f0f0f0, 0x3c3c3c3c},
        {"lsh", C_LSH, 0x80000001, 31},          {"rsh", C_RSH, 0x80000001, 31},
        {"div 1", C_DIV, 0x80000000, 1},         {"mod big", C_MOD, 5, 0x80000000},
    };
    for (size_t i = 0; i < COUNT(alu); i++) {
        char name[32];
        snprintf(name, sizeof name, "%s k", alu[i].name);
        VALUE(name, pattern, S(C_LD_IMM, alu[i].a), S(C_ALU_K(alu[i].op), alu[i].b));
        snprintf(name, sizeof name, "%s x", alu[i].name);
        VALUE(name, pattern, S(C_LD_IMM, alu[i].a), S(C_LDX_IMM, alu[i].b), S(C_ALU_X(alu[i].op), 0));
    }
    VALUE("neg", pattern, S(C_LD_IMM, 5), S(C_NEG, 0));
    VALUE("div x 0", pattern, S(C_LD_IMM, 5), S(C_LDX_IMM, 0), S(C_ALU_X(C_DIV), 0));
    VALUE("mod x 0", pattern, S(C_LD_IMM, 5), S(C_LDX_IMM, 0), S(C_ALU_X(C_MOD), 0));
    VALUE("lsh x 33", pattern, S(C_LD_IMM, 3), S(C_LDX_IMM, 33), S(C_ALU_X(C_LSH), 0));
    VALUE("rsh x 32", pattern, S(C_LD_IMM, 3), S(C_LDX_IMM, 32), S(C_ALU_X(C_RSH), 0));

    /* Jumps: A = 1 when taken, else 2, for each way Linux converts one. */
    static const struct {
        const char *name;
        uint16_t code;
        uint32_t a, k;
    } jumps[] = {
        {"jeq", C_JEQ_K, 5, 5},          {"jeq not", C_JEQ_K, 5, 6},
        {"jgt", C_JGT_K, 6, 5},          {"jgt equal", C_JGT_K, 5, 5},
        {"jge equal", C_JGE_K, 5, 5},    {"jge less", C_JGE_K, 4, 5},
        {"jset", C_JSET_K, 6, 4},        {"jset not", C_JSET_K, 6, 8},
        {"jgt big", C_JGT_K, 0xffffffff, 0x80000000}, {"jgt big not", C_JGT_K, 0x7fffffff, 0x80000000},
        {"jeq big", C_JEQ_K, 0xfffffffe, 0xfffffffe}, {"jge big", C_JGE_K, 1, 0xffffffff},
    };
    for (size_t i = 0; i < COUNT(jumps); i++) {
        char name[48];
        for (int form = 0; form < 3; form++) {
            /* jt 0, jf 0, and neither 0. */
            struct sf c[7];
            int n = 0;
            c[n++] = S(C_LD_IMM, jumps[i].a);
            if (form == 0) {
                c[n++] = SJ(jumps[i].code, 0, 2, jumps[i].k);
                c[n++] = S(C_LD_IMM, 1), c[n++] = S(C_JA, 1), c[n++] = S(C_LD_IMM, 2);
            } else if (form == 1) {
                c[n++] = SJ(jumps[i].code, 2, 0, jumps[i].k);
                c[n++] = S(C_LD_IMM, 2), c[n++] = S(C_JA, 1), c[n++] = S(C_LD_IMM, 1);
            } else {
                c[n++] = SJ(jumps[i].code, 1, 3, jumps[i].k);
                c[n++] = S(C_LD_IMM, 99), c[n++] = S(C_LD_IMM, 1), c[n++] = S(C_JA, 1), c[n++] = S(C_LD_IMM, 2);
            }
            snprintf(name, sizeof name, "%s form %d", jumps[i].name, form);
            value(name, pattern, sizeof pattern, c, (unsigned)n);
            /* The same with X. */
            for (int j = 0; j < n; j++)
                if (c[j].code == jumps[i].code) {
                    struct sf x[8];
                    memcpy(x + 1, c, n * sizeof *c);
                    x[0] = S(C_LDX_IMM, jumps[i].k);
                    x[j + 1].code = (uint16_t)(jumps[i].code | 0x08);
                    x[j + 1].k = 0;
                    snprintf(name, sizeof name, "%s x form %d", jumps[i].name, form);
                    value(name, pattern, sizeof pattern, x, (unsigned)n + 1);
                }
        }
    }

    /* The ancillary loads of an AF_UNIX datagram. */
    static const struct {
        const char *name;
        int k;
    } ancillary[] = {{"protocol", 0}, {"pkttype", 4}, {"mark", 20}, {"queue", 24}, {"rxhash", 32},
                     {"vlan tag", 44}, {"vlan present", 48}, {"pay offset", 52}, {"vlan tpid", 60}};
    for (size_t i = 0; i < COUNT(ancillary); i++)
        VALUE(ancillary[i].name, pattern, S(C_LD_IMM, 0x55), S(C_LD_W_ABS, AD(ancillary[i].k)));
    /* No device: the program returns A as it is, 0x99, and keeps that
       many bytes, where it would go on to drop the message. */
    {
        int q[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, q)) return 1;
        say("ifindex %d", CLASSIC(q[1], S(C_LD_IMM, 0x99), S(C_LD_W_ABS, AD(8)), S(C_RET_K, 0)));
        say("ifindex keeps %ld", kept(q[0], q[1], pattern, sizeof pattern));
        say("hatype %d", CLASSIC(q[1], S(C_LD_IMM, 0x98), S(C_LD_H_ABS, AD(28)), S(C_RET_K, 0)));
        say("hatype keeps %ld", kept(q[0], q[1], pattern, sizeof pattern));
        close(q[0]);
        close(q[1]);
    }
    VALUE("xor x", pattern, S(C_LD_IMM, 0xff00), S(C_LDX_IMM, 0x0ff0), S(C_LD_B_ABS, AD(40)));
    /* The processor and a random number differ from run to run: only
       that the filter runs. */
    VALUE("cpu", pattern, S(C_LD_W_ABS, AD(36)), S(C_LD_IMM, 1));
    VALUE("random", pattern, S(C_LD_W_ABS, AD(56)), S(C_LD_IMM, 2));

    static const struct {
        const char *name;
        uint32_t a, x;
        int nested;
    } attr[] = {
        {"nlattr 1", 0, 1, 0},        {"nlattr 2", 0, 2, 0},       {"nlattr 3", 0, 3, 0},
        {"nlattr 4", 0, 4, 0},        {"nlattr 5", 0, 5, 0},       {"nlattr 4 from 8", 8, 4, 0},
        {"nlattr from 2", 2, 3, 0},   {"nlattr at 296", 296, 0, 0}, {"nlattr at 297", 297, 0, 0},
        {"nest 5", 8, 5, 1},          {"nest 2", 8, 2, 1},         {"nest of 1", 0, 1, 1},
        {"nest at 4", 4, 0, 1},       {"nest at 297", 297, 0, 1},  {"nlattr x big", 0, 0x10001, 0},
    };
    for (size_t i = 0; i < COUNT(attr); i++)
        VALUE(attr[i].name, netlink, S(C_LD_IMM, attr[i].a), S(C_LDX_IMM, attr[i].x),
              S(C_LD_W_ABS, AD(attr[i].nested ? 16 : 12)));

    /* A datagram in pages: loads past its linear part, which nlattr does
       not search. */
    LARGE_VALUE("large len", S(C_LD_LEN, 0));
    LARGE_VALUE("large ld [0]", S(C_LD_W_ABS, 0));
    /* 15,904 bytes in the linear part: the rest in a page. */
    LARGE_VALUE("large ld [15900]", S(C_LD_W_ABS, 15900));
    LARGE_VALUE("large ld [15902]", S(C_LD_W_ABS, 15902));
    LARGE_VALUE("large ld [19996]", S(C_LD_W_ABS, 19996));
    LARGE_VALUE("large ld [19997]", S(C_LD_W_ABS, 19997));
    LARGE_VALUE("large ldb [x + 18000]", S(C_LDX_IMM, 1000), S(C_LD_B_IND, 18000));
    LARGE_VALUE("large ldh net 17000", S(C_LD_H_ABS, NET(17000)));
    LARGE_VALUE("large msh 17001", S(C_LDX_MSH, 17001), S(C_TXA, 0));
    LARGE_VALUE("large nlattr", S(C_LD_IMM, 0), S(C_LDX_IMM, 0), S(C_LD_W_ABS, AD(12)));

    /* A SOCK_SEQPACKET pair runs the filter too. */
    {
        int q[2];
        if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, q)) return 1;
        say("seqpacket attach %d", CLASSIC(q[1], S(C_LD_B_ABS, 2), S(C_RET_A, 0)));
        through("seqpacket", q[0], q[1], 5);
        say("seqpacket drop %d", CLASSIC(q[1], S(C_RET_K, 0)));
        through("seqpacket drop", q[0], q[1], 5);
        close(q[0]);
        close(q[1]);
    }
    free(large);
    return 0;
}

#define ATOMIC_W(dst, src, off, op) I(0xc3, dst, src, off, op)
#define ATOMIC_DW(dst, src, off, op) I(0xdb, dst, src, off, op)
#define A_ADD 0x00
#define A_OR 0x40
#define A_AND 0x50
#define A_XOR 0xa0
#define A_FETCH 0x01
#define A_XCHG 0xe1
#define A_CMPXCHG 0xf1
#define SLOTS 24

/* The map's value, 8 bytes a slot. */
static void slots(const char *name, int m) {
    uint32_t key = 0;
    uint64_t value[SLOTS] = {0};
    uint64_t a[4] = {(uint32_t)m, (uintptr_t)&key, (uintptr_t)value, 0};
    long r = bpf(1, a, sizeof a);
    printf("%s lookup %ld:", name, r);
    for (int i = 0; i < SLOTS; i++) printf(" %llx", (unsigned long long)value[i]);
    putchar('\n');
    fflush(stdout);
}

static int case_atomic(void) {
    int value = map(2, 4, 8 * SLOTS, 1, 0);
    int rdonly = map(2, 4, 8, 1, 1 << 7);
    int hash = map(1, 8, 8, 4, 0);
    say("maps %d", value > 0 && rdonly > 0 && hash > 0);

    /* Programs it takes: fp-8 = 1 and r1 = 1, then the atomic. */
#define ON_STACK(name, ...) LOAD(name, MOV(1, 1), STX_DW(10, 1, -8), __VA_ARGS__, MOV(0, 0), EXIT())
    ON_STACK("add", ATOMIC_DW(10, 1, -8, A_ADD));
    ON_STACK("fetch add", ATOMIC_DW(10, 1, -8, A_ADD | A_FETCH));
    ON_STACK("or", ATOMIC_DW(10, 1, -8, A_OR));
    ON_STACK("fetch or", ATOMIC_DW(10, 1, -8, A_OR | A_FETCH));
    ON_STACK("and", ATOMIC_DW(10, 1, -8, A_AND));
    ON_STACK("fetch and", ATOMIC_DW(10, 1, -8, A_AND | A_FETCH));
    ON_STACK("xor", ATOMIC_DW(10, 1, -8, A_XOR));
    ON_STACK("fetch xor", ATOMIC_DW(10, 1, -8, A_XOR | A_FETCH));
    ON_STACK("xchg", ATOMIC_DW(10, 1, -8, A_XCHG));
    ON_STACK("cmpxchg", MOV(0, 1), ATOMIC_DW(10, 1, -8, A_CMPXCHG));
    ON_STACK("32-bit add", ATOMIC_W(10, 1, -4, A_ADD));
    ON_STACK("32-bit fetch xor", ATOMIC_W(10, 1, -8, A_XOR | A_FETCH));
    ON_STACK("32-bit xchg", ATOMIC_W(10, 1, -4, A_XCHG));
    ON_STACK("32-bit cmpxchg", MOV(0, 1), ATOMIC_W(10, 1, -8, A_CMPXCHG));
    ON_STACK("a pointer as the source", ATOMIC_DW(10, 10, -8, A_ADD));
    LOAD("fetch a spilled pointer", STX_DW(10, 10, -8), MOV(1, 0), ATOMIC_DW(10, 1, -8, A_ADD | A_FETCH),
         LDX_DW(0, 1, -16), EXIT());
    LOAD("never written stack", MOV(1, 1), ATOMIC_DW(10, 1, -16, A_ADD), MOV(0, 0), EXIT());
    LOAD_MAPS("into a value", LD_VALUE(6, value, 0), MOV(1, 1), ATOMIC_DW(6, 1, 8, A_ADD | A_FETCH),
              MOV(0, 0), ATOMIC_W(6, 1, 4, A_CMPXCHG), MOV(0, 0), EXIT());

    /* Programs it refuses. */
    ON_STACK("no such operation", ATOMIC_DW(10, 1, -8, 0x02));
    ON_STACK("operation -1", ATOMIC_DW(10, 1, -8, -1));
    ON_STACK("sub", ATOMIC_DW(10, 1, -8, 0x10));
    ON_STACK("8-bit fetch add", I(0xd3, 10, 1, -8, A_ADD | A_FETCH));
    ON_STACK("16-bit add", I(0xcb, 10, 1, -8, A_ADD));
    ON_STACK("16-bit, no such operation", I(0xcb, 10, 1, -8, 0x07));
    ON_STACK("unwritten source", ATOMIC_DW(10, 2, -8, A_ADD));
    ON_STACK("unwritten destination", ATOMIC_DW(3, 1, -8, A_ADD));
    LOAD("cmpxchg without R0", MOV(1, 1), STX_DW(10, 1, -8), ATOMIC_DW(10, 1, -8, A_CMPXCHG), EXIT());
    LOAD("into cb[]", MOV(2, 1), ATOMIC_W(1, 2, 48, A_ADD), MOV(0, 0), EXIT());
    ON_STACK("misaligned on the stack", ATOMIC_DW(10, 1, -12, A_ADD));
    ON_STACK("at the frame pointer", ATOMIC_DW(10, 1, 0, A_ADD));
    ON_STACK("below the stack", ATOMIC_DW(10, 1, -520, A_ADD));
    LOAD_MAPS("misaligned in a value", LD_VALUE(6, value, 0), MOV(1, 1), ATOMIC_W(6, 1, 2, A_ADD),
              MOV(0, 0), EXIT());
    LOAD_MAPS("past the value", LD_VALUE(6, value, 0), MOV(1, 1),
              ATOMIC_DW(6, 1, 8 * SLOTS, A_ADD), MOV(0, 0), EXIT());
    LOAD_MAPS("into a read-only value", LD_VALUE(6, rdonly, 0), MOV(1, 1), ATOMIC_DW(6, 1, 0, A_ADD),
              MOV(0, 0), EXIT());
    LOAD_MAPS("into a lookup's result unchecked", KEY8(hash), CALL(LOOKUP), MOV(1, 1),
              ATOMIC_W(0, 1, 2, A_ADD), MOV(0, 0), EXIT());
    ON_STACK("fetch into the frame pointer", ATOMIC_DW(10, 10, -8, A_ADD | A_FETCH));
    ON_STACK("fetch into its own pointer", MOV_REG(2, 10), ATOMIC_DW(2, 2, -8, A_ADD | A_FETCH));
    ON_STACK("cmpxchg through R0", MOV_REG(0, 10), ATOMIC_DW(0, 1, -8, A_CMPXCHG));
    LOAD("a pointer's slot after an atomic", STX_DW(10, 10, -8), MOV(1, 0),
         ATOMIC_DW(10, 1, -8, A_ADD | A_FETCH), LDX_DW(2, 10, -8), LDX_DW(0, 2, 0), EXIT());
    LOAD("32 bits of a spilled pointer", STX_DW(10, 10, -8), MOV(1, 0),
         ATOMIC_W(10, 1, -8, A_ADD | A_FETCH), MOV(0, 0), EXIT());
#undef ON_STACK

    /* BPF_F_STRICT_ALIGNMENT, for loads too: a lookup's result before its
       null check is checked for alignment before it is refused. */
    {
        struct insn misaligned[] = {KEY8(hash), CALL(LOOKUP), LDX_W(0, 0, 2), EXIT()};
        struct insn aligned[] = {KEY8(hash), CALL(LOOKUP), LDX_W(0, 0, 4), EXIT()};
        struct prog_attr p = attr(misaligned, COUNT(misaligned));
        p.prog_flags = 1;
        run("strict, misaligned in a lookup's result unchecked", p);
        p = attr(aligned, COUNT(aligned));
        p.prog_flags = 1;
        run("strict, aligned in a lookup's result unchecked", p);
        run("not strict, misaligned in a lookup's result unchecked",
            attr(misaligned, COUNT(misaligned)));
    }

    /* A filter that runs them on the map's value and the stack, and keeps
       what each gave in the value. */
    uint64_t start[SLOTS];
    for (int i = 0; i < SLOTS; i++) start[i] = 0x0123456789abcdefULL ^ (0x1010101010101010ULL * (uint64_t)i);
    uint32_t key = 0;
    uint64_t u[4] = {(uint32_t)value, (uintptr_t)&key, (uintptr_t)start, 0};
    say("update %ld", bpf(2, u, sizeof u));
    int filter = PROGRAM(
        LD_VALUE(6, value, 0),
        MOV(1, 1), ATOMIC_DW(6, 1, 0, A_ADD),
        MOV(1, 0xf00), ATOMIC_DW(6, 1, 8, A_OR),
        MOV(2, 0xff), ATOMIC_DW(6, 2, 16, A_AND | A_FETCH), STX_DW(6, 2, 96),
        MOV(3, -1), ATOMIC_DW(6, 3, 24, A_XOR | A_FETCH), STX_DW(6, 3, 104),
        MOV(4, 5), ATOMIC_DW(6, 4, 32, A_XCHG), STX_DW(6, 4, 112),
        /* Equal to what is there, then not. */
        LDX_DW(0, 6, 40), MOV(1, 7), ATOMIC_DW(6, 1, 40, A_CMPXCHG), STX_DW(6, 0, 120),
        MOV(0, 1), ATOMIC_DW(6, 1, 48, A_CMPXCHG), STX_DW(6, 0, 128),
        /* 32 bits: the source's lower half, the old value zero-extended,
           and R0's lower half compared. */
        LD64(5, 0x710000001ULL), ATOMIC_W(6, 5, 56, A_ADD | A_FETCH), STX_DW(6, 5, 136),
        LD64(5, 0x900000005ULL), ATOMIC_W(6, 5, 64, A_XCHG), STX_DW(6, 5, 144),
        LDX_W(0, 6, 72), LD64(1, 0x300000000ULL), I(0x4f, 0, 1, 0, 0), MOV(1, 9),
        ATOMIC_W(6, 1, 72, A_CMPXCHG), STX_DW(6, 0, 152),
        /* The upper half of a slot, by its own address. */
        LD64(1, 0xf000000f0ULL), ATOMIC_W(6, 1, 84, A_OR | A_FETCH), STX_DW(6, 1, 160),
        /* The stack. */
        LDX_DW(1, 6, 88), STX_DW(10, 1, -8), MOV(7, 2), ATOMIC_DW(10, 7, -8, A_ADD | A_FETCH),
        LDX_DW(1, 10, -8), STX_DW(6, 1, 168), STX_DW(6, 7, 176),
        MOV(0, 0), EXIT());
    say("filter loaded %d", filter >= 0);
    if (filter < 0) {
        LOAD_MAPS("why", LD_VALUE(6, value, 0), MOV(0, 0), EXIT());
        return 1;
    }
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair)) return 1;
    say("attach %d", attach(pair[1], filter));
    slots("before", value);
    through("first", pair[0], pair[1], 4);
    slots("after one", value);
    through("second", pair[0], pair[1], 4);
    slots("after two", value);
    return 0;
}

#define LOAD_ACQ(size, dst, src, off) I(0xc3 | (size), dst, src, off, 0x100)
#define STORE_REL(size, dst, src, off) I(0xc3 | (size), dst, src, off, 0x110)
#define S_B 0x10
#define S_H 0x08
#define S_W 0x00
#define S_DW 0x18

static int case_acqrel(void) {
    int value = map(2, 4, 8 * SLOTS, 1, 0);
    int rdonly = map(2, 4, 8, 1, 1 << 7);
    int hash = map(1, 8, 8, 4, 0);
    say("maps %d", value > 0 && rdonly > 0 && hash > 0);

    /* Programs it takes: r1 = 1, then the instructions. */
#define WITH_R1(name, ...) LOAD(name, MOV(1, 1), __VA_ARGS__, MOV(0, 0), EXIT())
#define MAPS_R1(name, ...) LOAD_MAPS(name, MOV(1, 1), __VA_ARGS__, MOV(0, 0), EXIT())
    WITH_R1("8-bit", STORE_REL(S_B, 10, 1, -1), LOAD_ACQ(S_B, 2, 10, -1));
    WITH_R1("16-bit", STORE_REL(S_H, 10, 1, -4), LOAD_ACQ(S_H, 2, 10, -4));
    WITH_R1("32-bit", STORE_REL(S_W, 10, 1, -8), LOAD_ACQ(S_W, 2, 10, -8));
    WITH_R1("64-bit", STORE_REL(S_DW, 10, 1, -8), LOAD_ACQ(S_DW, 2, 10, -8));
    WITH_R1("load of never written stack", LOAD_ACQ(S_DW, 2, 10, -16));
    LOAD_MAPS("in a value", LD_VALUE(6, value, 0), MOV(1, 1), STORE_REL(S_DW, 6, 1, 8),
              LOAD_ACQ(S_W, 2, 6, 12), MOV(0, 0), EXIT());
    LOAD_MAPS("load from a read-only value", LD_VALUE(6, rdonly, 0), LOAD_ACQ(S_DW, 2, 6, 0),
              MOV(0, 0), EXIT());
    LOAD("a pointer stored and loaded", STORE_REL(S_DW, 10, 10, -8), LOAD_ACQ(S_DW, 2, 10, -8),
         LDX_DW(0, 2, -16), EXIT());
    MAPS_R1("store of a pointer into a value", LD_VALUE(6, value, 0), STORE_REL(S_DW, 6, 10, 0));

    /* Programs it refuses. */
    WITH_R1("load from an unwritten register", LOAD_ACQ(S_DW, 2, 3, -8));
    WITH_R1("load into the frame pointer", LOAD_ACQ(S_DW, 10, 10, -8));
    WITH_R1("store of an unwritten register", STORE_REL(S_DW, 10, 3, -8));
    WITH_R1("store through an unwritten register", STORE_REL(S_DW, 3, 1, -8));
    WITH_R1("load misaligned on the stack", LOAD_ACQ(S_DW, 2, 10, -12));
    WITH_R1("store misaligned on the stack", STORE_REL(S_W, 10, 1, -6));
    MAPS_R1("load misaligned in a value", LD_VALUE(6, value, 0), LOAD_ACQ(S_W, 2, 6, 2));
    MAPS_R1("store misaligned in a value", LD_VALUE(6, value, 0), STORE_REL(S_H, 6, 1, 1));
    MAPS_R1("load past the value", LD_VALUE(6, value, 0), LOAD_ACQ(S_DW, 2, 6, 8 * SLOTS));
    WITH_R1("store below the stack", STORE_REL(S_DW, 10, 1, -520));
    MAPS_R1("store into a read-only value", LD_VALUE(6, rdonly, 0), STORE_REL(S_DW, 6, 1, 0));
    LOAD_MAPS("load from a lookup's result unchecked", KEY8(hash), CALL(LOOKUP),
              LOAD_ACQ(S_W, 2, 0, 2), MOV(0, 0), EXIT());
    LOAD("load from the context", LOAD_ACQ(S_W, 2, 1, 0), MOV(0, 0), EXIT());
    LOAD("load misaligned in the context", LOAD_ACQ(S_W, 2, 1, 2), MOV(0, 0), EXIT());
    LOAD("load from the context into its own register", LOAD_ACQ(S_W, 1, 1, 0), MOV(0, 0), EXIT());
    LOAD("store into cb[]", MOV(2, 1), STORE_REL(S_W, 1, 2, 48), MOV(0, 0), EXIT());
    LOAD("store into len", MOV(2, 1), STORE_REL(S_W, 1, 2, 0), MOV(0, 0), EXIT());
    LOAD("32 bits of a stored pointer", STORE_REL(S_DW, 10, 10, -8), LOAD_ACQ(S_W, 2, 10, -8),
         MOV(0, 0), EXIT());
#undef MAPS_R1
#undef WITH_R1

    /* A filter that runs them on the map's value and the stack, and keeps
       what each gave in the value. */
    uint64_t start[SLOTS];
    for (int i = 0; i < SLOTS; i++) start[i] = 0x0123456789abcdefULL ^ (0x1010101010101010ULL * (uint64_t)i);
    uint32_t key = 0;
    uint64_t u[4] = {(uint32_t)value, (uintptr_t)&key, (uintptr_t)start, 0};
    say("update %ld", bpf(2, u, sizeof u));
    int filter = PROGRAM(
        LD_VALUE(6, value, 0),
        /* Stores of each size change only their own bytes. */
        LD64(1, 0xfedcba9876543210ULL),
        STORE_REL(S_B, 6, 1, 0), STORE_REL(S_H, 6, 1, 10), STORE_REL(S_W, 6, 1, 20),
        STORE_REL(S_DW, 6, 1, 24),
        /* Loads of each size, zero-extended into all ones. */
        MOV(2, -1), LOAD_ACQ(S_B, 2, 6, 33), STX_DW(6, 2, 64),
        MOV(2, -1), LOAD_ACQ(S_H, 2, 6, 34), STX_DW(6, 2, 72),
        MOV(2, -1), LOAD_ACQ(S_W, 2, 6, 36), STX_DW(6, 2, 80),
        MOV(2, -1), LOAD_ACQ(S_DW, 2, 6, 40), STX_DW(6, 2, 88),
        /* A load into the register it loads from. */
        MOV_REG(3, 6), LOAD_ACQ(S_DW, 3, 3, 48), STX_DW(6, 3, 96),
        /* The stack: a store, then loads of its parts. */
        LDX_DW(1, 6, 56), STORE_REL(S_DW, 10, 1, -8), LOAD_ACQ(S_H, 2, 10, -6), STX_DW(6, 2, 104),
        MOV(1, 0x5a), STORE_REL(S_B, 10, 1, -7), LOAD_ACQ(S_DW, 2, 10, -8), STX_DW(6, 2, 112),
        /* Count the messages. */
        LOAD_ACQ(S_DW, 1, 6, 120), ADD(1, 1), STORE_REL(S_DW, 6, 1, 120),
        MOV(0, 0), EXIT());
    say("filter loaded %d", filter >= 0);
    if (filter < 0) {
        LOAD_MAPS("why", LD_VALUE(6, value, 0), MOV(0, 0), EXIT());
        return 1;
    }
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair)) return 1;
    say("attach %d", attach(pair[1], filter));
    slots("before", value);
    through("first", pair[0], pair[1], 4);
    slots("after one", value);
    through("second", pair[0], pair[1], 4);
    slots("after two", value);
    return 0;
}

#define ABS(size, imm) I(0x20 | (size), 0, 0, 0, imm)
#define IND(size, src, imm) I(0x40 | (size), 0, src, 0, imm)

/* Sends 64 bytes (0, 1, 2, ...) through a filter of `insns`, after R6 =
   the context. */
static void ldabs_through(const char *name, const struct insn *insns, unsigned count) {
    struct insn p[16] = {MOV_REG(6, 1)};
    memcpy(p + 1, insns, count * sizeof *insns);
    int prog = load(p, count + 1);
    int pair[2];
    if (prog < 0 || socketpair(AF_UNIX, SOCK_DGRAM, 0, pair)) {
        say("%s: %d", name, prog);
        return;
    }
    int r = attach(pair[1], prog);
    if (r) say("%s attach %d", name, r);
    through(name, pair[0], pair[1], 64);
    close(pair[0]);
    close(pair[1]);
    close(prog);
}
#define LDABS_THROUGH(name, ...)                                \
    do {                                                        \
        struct insn i_[] = {__VA_ARGS__};                       \
        ldabs_through((name), i_, COUNT(i_));                   \
    } while (0)

static int case_ldabs(void) {
    /* Programs it takes: R6 = the context, then the instructions. */
#define CTX(name, ...) LOAD(name, MOV_REG(6, 1), __VA_ARGS__, EXIT())
    CTX("abs 32-bit", ABS(S_W, 0));
    CTX("abs 16-bit", ABS(S_H, 1));
    CTX("abs 8-bit", ABS(S_B, 2));
    CTX("ind of each size", MOV(7, 1), IND(S_W, 7, 0), IND(S_H, 7, -1), IND(S_B, 7, 2));
    CTX("ind from the frame pointer", IND(S_B, 10, 0));
    CTX("ind from the context", IND(S_B, 6, 0));
    CTX("from the network and MAC headers", ABS(S_H, NET(0)), ABS(S_B, LL(0)));
    CTX("past the end and before the start", ABS(S_W, 0x7fffffff), ABS(S_B, -1));
    CTX("R6 to R9 kept", MOV(7, 7), MOV(8, 8), MOV(9, 9), ABS(S_B, 0), ADD(0, 1), MOV_REG(0, 9),
        MOV_REG(0, 8), MOV_REG(0, 7), LDX_W(0, 6, 0));
    CTX("R0 a number", ABS(S_B, 0), ADD(0, 1));

    /* Programs it refuses. */
    LOAD("R6 unwritten", ABS(S_B, 0), EXIT());
    LOAD("R6 a number", MOV(6, 0), ABS(S_B, 0), EXIT());
    LOAD("R6 the frame pointer", MOV_REG(6, 10), ABS(S_B, 0), EXIT());
    LOAD("R6 the context moved", MOV_REG(6, 1), ADD(6, 4), ABS(S_B, 0), EXIT());
    LOAD("R6 a number, the source unwritten", MOV(6, 0), IND(S_B, 7, 0), EXIT());
    CTX("the source unwritten", IND(S_B, 7, 0));
    LOAD("the context moved, the source unwritten", MOV_REG(6, 1), ADD(6, 4), IND(S_B, 7, 0), EXIT());
    CTX("R1 after the load", ABS(S_B, 0), MOV_REG(0, 1));
    CTX("R5 after the load", MOV(5, 5), ABS(S_B, 0), MOV_REG(0, 5));
    CTX("a destination", I(0x30, 1, 0, 0, 0));
    CTX("an offset", I(0x30, 0, 0, 1, 0));
    CTX("abs with a source", I(0x30, 0, 1, 0, 0));
    CTX("ind with an offset", I(0x50, 0, 1, 2, 0));
    CTX("abs 64-bit", I(0x38, 0, 0, 0, 0));
    CTX("ind 64-bit", I(0x58, 0, 1, 0, 0));
#undef CTX

    /* What they load, kept in a value of 8 slots. */
    int value = map(2, 4, 8 * SLOTS, 1, 0);
    say("map %d", value > 0);
    int filter = PROGRAM(
        MOV_REG(6, 1), LD_VALUE(8, value, 0), MOV(7, 5),
        ABS(S_W, 0), STX_DW(8, 0, 0),
        ABS(S_H, 1), STX_DW(8, 0, 8),
        ABS(S_B, 63), STX_DW(8, 0, 16),
        ABS(S_W, 60), STX_DW(8, 0, 24),
        IND(S_W, 7, 1), STX_DW(8, 0, 32),
        IND(S_H, 7, -5), STX_DW(8, 0, 40),
        ABS(S_H, NET(2)), STX_DW(8, 0, 48),
        IND(S_B, 7, NET(0)), STX_DW(8, 0, 56),
        /* The offset is an int: the upper half of R7 goes. */
        LD64(7, 0x100000003ULL), IND(S_W, 7, 1), STX_DW(8, 0, 64),
        LD64(7, -0x200000LL), IND(S_B, 7, 0x100009), STX_DW(8, 0, 72),
        MOV(0, 64), EXIT());
    say("filter loaded %d", filter >= 0);
    if (filter < 0) return 1;
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair)) return 1;
    say("attach %d", attach(pair[1], filter));
    through("loads", pair[0], pair[1], 64);
    slots("loaded", value);
    close(pair[0]);
    close(pair[1]);

    /* What they keep: R0 as loaded, or nothing where the load fails. */
    LDABS_THROUGH("keep byte 10", ABS(S_B, 10), EXIT());
    LDABS_THROUGH("keep 16 bits at 9", ABS(S_H, 9), EXIT());
    LDABS_THROUGH("keep from the network header", ABS(S_B, NET(20)), EXIT());
    LDABS_THROUGH("keep through R7", MOV(7, 30), IND(S_B, 7, 3), EXIT());
    LDABS_THROUGH("32 bits at 61", ABS(S_W, 61), MOV(0, 3), EXIT());
    LDABS_THROUGH("8 bits at 64", ABS(S_B, 64), MOV(0, 3), EXIT());
    LDABS_THROUGH("8 bits at -1", ABS(S_B, -1), MOV(0, 3), EXIT());
    LDABS_THROUGH("8 bits at INT_MAX", ABS(S_B, 0x7fffffff), MOV(0, 3), EXIT());
    LDABS_THROUGH("8 bits at INT_MIN", ABS(S_B, INT32_MIN), MOV(0, 3), EXIT());
    LDABS_THROUGH("8 bits from the network header at 64", ABS(S_B, NET(64)), MOV(0, 3), EXIT());
    LDABS_THROUGH("8 bits below the network header", ABS(S_B, NET(-1)), MOV(0, 3), EXIT());
    LDABS_THROUGH("8 bits from the MAC header", ABS(S_B, LL(0)), MOV(0, 3), EXIT());
    LDABS_THROUGH("8 bits below the MAC header", ABS(S_B, LL(-1)), MOV(0, 3), EXIT());
    LDABS_THROUGH("ind at -1", MOV(7, -1), IND(S_B, 7, 0), MOV(0, 3), EXIT());
    LDABS_THROUGH("ind past the end", MOV(7, 62), IND(S_H, 7, 1), MOV(0, 3), EXIT());
    LDABS_THROUGH("ind at the end", MOV(7, 62), IND(S_H, 7, 0), MOV(0, 3), EXIT());
    return 0;
}

#define CALLF(by) I(0x85, 0, 1, 0, by) /* call the function `by` instructions on */

/* The log's "stack depth" line, with BPF_LOG_STATS, of a program taken. */
static void depths(const char *name, const struct insn *insns, unsigned count) {
    struct prog_attr p = attr(insns, count);
    p.log_level = 4;
    memset(log_text, 0, sizeof log_text);
    long fd = bpf(PROG_LOAD, &p, sizeof p);
    const char *line = strstr(log_text, "stack depth ");
    const char *end = line ? strchr(line, '\n') : NULL;
    if (fd < 0 || !end) {
        say("%s: %ld", name, fd);
        return;
    }
    say("%s: %.*s", name, (int)(end - line), line);
    close((int)fd);
}
#define DEPTHS(name, ...)                                       \
    do {                                                        \
        static const struct insn insns[] = {__VA_ARGS__};       \
        depths(name, insns, COUNT(insns));                      \
    } while (0)

/* A chain of functions, each writing a byte `bytes` below its frame pointer
   and calling the next; the last returns 0. */
static void chain(const char *name, int functions, int16_t bytes) {
    struct insn p[64];
    unsigned n = 0;
    for (int f = 0; f < functions; f++) {
        p[n++] = (struct insn)ST_B(10, -bytes, 0);
        if (f + 1 < functions) p[n++] = (struct insn)CALLF(2);
        p[n++] = (struct insn)MOV(0, 0);
        p[n++] = (struct insn)EXIT();
    }
    run(name, attr(p, n));
}

static int case_calls(void) {
    /* Programs it takes. */
    LOAD("a call", MOV(1, 3), CALLF(1), EXIT(), MOV_REG(0, 1), EXIT());
    LOAD("R6 to R9 kept", MOV(6, 6), MOV(9, 9), CALLF(3), MOV_REG(0, 6), ADD(0, 9), EXIT(),
         MOV(6, 0), MOV(0, 0), EXIT());
    LOAD("R1 to R5 in", MOV(1, 1), MOV(2, 2), MOV(3, 3), MOV(4, 4), MOV(5, 5), CALLF(1), EXIT(),
         MOV_REG(0, 1), I(0x0f, 0, 2, 0, 0), I(0x0f, 0, 3, 0, 0), I(0x0f, 0, 4, 0, 0),
         I(0x0f, 0, 5, 0, 0), EXIT());
    LOAD("the caller's stack through R1", ST_DW(10, -8, 1), MOV_REG(1, 10), ADD(1, -8), CALLF(2),
         LDX_DW(0, 10, -8), EXIT(), ST_DW(1, 0, 7), MOV(0, 0), EXIT());
    LOAD("a pointer to the caller's own stack in its stack", MOV_REG(1, 10), ADD(1, -8), CALLF(3),
         LDX_DW(0, 10, -16), MOV(0, 0), EXIT(), STX_DW(10, 1, -8), MOV(0, 0), EXIT());
    LOAD("the context to the callee", CALLF(2), MOV(0, 0), EXIT(), LDX_W(0, 1, 0), EXIT());
    LOAD("a function called twice", CALLF(3), CALLF(2), MOV(0, 0), EXIT(), MOV(0, 1), EXIT());
    LOAD("two functions", CALLF(3), CALLF(4), MOV(0, 0), EXIT(), MOV(0, 1), EXIT(), MOV(0, 2),
         EXIT());
    LOAD("a function the walk never enters", MOV(0, 0), JEQ(0, 0, 1), CALLF(2), MOV(0, 0), EXIT(),
         ST_B(10, -512, 0), MOV(0, 0), EXIT());
    chain("8 frames", 8, 8);
    chain("8 frames of 64 bytes", 8, 64);
    chain("4 frames of 100 bytes", 4, 100);

    /* Programs it refuses. */
    LOAD("call past the end", CALLF(1), EXIT());
    LOAD("call before the start", CALLF(-2), EXIT());
    LOAD("jump into the function", CALLF(2), MOV(0, 0), I(0x05, 0, 0, 1, 0), EXIT(), EXIT());
    LOAD("fall into the function", CALLF(2), MOV(0, 0), MOV(1, 0), EXIT());
    LOAD("the function falls off the end", CALLF(1), EXIT(), MOV(0, 0));
    LOAD("BPF_LD_ABS in a function", CALLF(1), EXIT(), MOV_REG(6, 1), I(0x30, 0, 0, 0, 0), EXIT());
    LOAD("bpf_tail_call in a function", CALLF(1), EXIT(), CALL(12), EXIT());
    LOAD("R0 after a call to an exit", CALLF(1), EXIT(), EXIT());
    LOAD("R1 after the call", MOV(1, 1), CALLF(2), MOV_REG(0, 1), EXIT(), MOV(0, 0), EXIT());
    LOAD("R5 after the call", MOV(5, 1), CALLF(2), MOV_REG(0, 5), EXIT(), MOV(0, 0), EXIT());
    LOAD("R0 in the callee", MOV(0, 1), CALLF(1), EXIT(), ADD(0, 1), EXIT());
    LOAD("R6 in the callee", MOV(6, 1), CALLF(1), EXIT(), MOV_REG(0, 6), EXIT());
    LOAD("an argument not written", MOV(1, 1), CALLF(1), EXIT(), MOV_REG(0, 2), EXIT());
    LOAD("the callee's frame pointer back", CALLF(2), MOV(0, 0), EXIT(), MOV_REG(0, 10), EXIT());
    LOAD("the caller's stack pointer back", MOV_REG(1, 10), CALLF(2), MOV(0, 0), EXIT(),
         MOV_REG(0, 1), EXIT());
    LOAD("the callee's frame pointer into the caller's stack", MOV_REG(1, 10), ADD(1, -8), CALLF(2),
         MOV(0, 0), EXIT(), STX_DW(1, 10, 0), MOV(0, 0), EXIT());
    chain("9 frames", 9, 8);
    chain("5 frames of 100 bytes", 5, 100);
    LOAD("512 bytes and 1", ST_B(10, -504, 0), CALLF(2), MOV(0, 0), EXIT(), ST_B(10, -1, 0),
         MOV(0, 0), EXIT());
    LOAD("a function that calls itself", CALLF(1), EXIT(), CALLF(-1), EXIT());
    LOAD("two functions that call each other", CALLF(1), EXIT(), CALLF(1), EXIT(), CALLF(-3),
         EXIT());
    LOAD("a function that calls the main program", CALLF(1), EXIT(), MOV(0, 0), CALLF(-4),
         EXIT());

    /* Each function's stack depth. */
    DEPTHS("depths of one", ST_B(10, -3, 0), MOV(0, 0), EXIT());
    DEPTHS("depths of two", ST_DW(10, -8, 0), MOV_REG(1, 10), CALLF(2), MOV(0, 0), EXIT(),
           ST_B(1, -40, 0), ST_B(10, -3, 0), MOV(0, 0), EXIT());
    DEPTHS("depths of three", CALLF(3), CALLF(5), MOV(0, 0), EXIT(), ST_B(10, -100, 0), MOV(0, 0),
           EXIT(), MOV(0, 0), EXIT());

    /* A filter whose functions write the map's value. */
    int value = map(2, 4, 8 * SLOTS, 1, 0);
    say("map %d", value > 0);
    int filter = PROGRAM(
        LD_VALUE(6, value, 0),
        /* f(value, 5) writes 15 at value[0] and returns 6. */
        MOV_REG(1, 6), MOV(2, 5), CALLF(17), STX_DW(6, 0, 8),
        /* g(fp - 8) adds 1 to the caller's slot, and its own slot is its own. */
        ST_DW(10, -8, 41), ST_DW(10, -16, 1000), MOV_REG(1, 10), ADD(1, -8), CALLF(17),
        LDX_DW(1, 10, -8), STX_DW(6, 1, 16), LDX_DW(1, 10, -16), STX_DW(6, 1, 24), STX_DW(6, 0, 32),
        /* h(value) calls f(value + 40, 7) and keeps R6. */
        MOV(7, 77), MOV_REG(1, 6), CALLF(16), STX_DW(6, 7, 56),
        MOV(0, 64), EXIT(),
        /* f: *(R1) = R2 * 3; R0 = R2 + 1. */
        MOV_REG(3, 2), I(0x27, 3, 0, 0, 3), STX_DW(1, 3, 0), MOV_REG(0, 2), ADD(0, 1), EXIT(),
        /* g: *(R1) += 1; its own fp - 8 and fp - 16; R0 = its fp - 16. */
        ST_DW(10, -8, 5), ST_DW(10, -16, 9), LDX_DW(2, 1, 0), ADD(2, 1), STX_DW(1, 2, 0),
        LDX_DW(0, 10, -16), EXIT(),
        /* h: R6 = R1 + 40, f(R6, 7), then value[6] = R0, R7 its own. */
        MOV_REG(6, 1), ADD(1, 40), MOV(2, 7), MOV(7, 1), CALLF(-18), STX_DW(6, 0, 48), MOV(0, 0),
        EXIT());
    say("filter loaded %d", filter >= 0);
    if (filter < 0) {
        LOAD_MAPS("why", LD_VALUE(6, value, 0), MOV(0, 0), EXIT());
        return 1;
    }
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair)) return 1;
    say("attach %d", attach(pair[1], filter));
    through("calls", pair[0], pair[1], 64);
    slots("after", value);
    return 0;
}

/* A program of `count` instructions as loaded: the prologue, `n` copies of
   the block, moves of 0 and the exit. Its memory in fdinfo, in pages of
   the instructions after the verifier's rewrites, and the log's stack
   depth. */
static struct insn grown[600];
static void grow(const char *name, const struct insn *pro, unsigned npro,
                 const struct insn *block, unsigned nblock, unsigned n, unsigned count,
                 uint32_t flags) {
    unsigned at = 0;
    for (unsigned i = 0; i < npro; i++) grown[at++] = pro[i];
    for (unsigned k = 0; k < n; k++)
        for (unsigned i = 0; i < nblock; i++) grown[at++] = block[i];
    while (at < count - 1) grown[at++] = (struct insn)MOV(0, 0);
    grown[at++] = (struct insn)EXIT();
    struct prog_attr p = attr(grown, at);
    p.prog_flags = flags;
    p.log_level = 4;
    memset(log_text, 0, sizeof log_text);
    long fd = bpf(PROG_LOAD, &p, sizeof p);
    say("%s, %u: %s", name, at, fd < 0 ? "refused" : "loaded");
    if (fd < 0) {
        say("  %ld", fd);
        return;
    }
    fdinfo((int)fd);
    const char *line = strstr(log_text, "stack depth ");
    const char *end = line ? strchr(line, '\n') : NULL;
    if (end) say("  %.*s", (int)(end - line), line);
    close((int)fd);
}

/* The block's `d` more instructions after the rewrites, at 500 of them in
   all and at 501: 500 fit the first page with the program's header, 501
   take a second. */
#define REWRITE(name, d, n, flags, pro, ...)                                      \
    do {                                                                          \
        static const struct insn prologue[] = pro;                                \
        const struct insn block[] = {__VA_ARGS__};                                \
        unsigned at = 500 - (unsigned)((d) * (n));                                \
        grow(name, prologue, COUNT(prologue), block, COUNT(block), n, at, flags); \
        grow(name, prologue, COUNT(prologue), block, COUNT(block), n, at + 1, flags); \
    } while (0)
#define PRO(...) {__VA_ARGS__}
#define TEST_RND_HI32 (1 << 2)

static int case_rewrites(void) {
    int array = map(2, 4, 8, 1, 0);
    int other = map(2, 4, 8, 1, 0);
    int hash = map(1, 4, 8, 4, 0);
    int lru = map(9, 4, 8, 4, 0);
    say("maps %d", array > 0 && other > 0 && hash > 0 && lru > 0);
    /* R6 the context, R2 3, R0 1, R7 0 and fp-8 0. */
#define BASE PRO(MOV_REG(6, 1), MOV(2, 3), MOV(0, 1), MOV(7, 0), ST_DW(10, -8, 0))
    REWRITE("no rewrite", 0, 10, 0, BASE, MOV(3, 1));
    /* do_misc_fixups: a division or remainder by a register. */
    REWRITE("unsigned 64-bit division", 3, 10, 0, BASE, I(0x3f, 0, 2, 0, 0));
    REWRITE("signed 64-bit division", 7, 10, 0, BASE, I(0x3f, 0, 2, 1, 0));
    REWRITE("signed 32-bit division", 7, 10, 0, BASE, I(0x3c, 0, 2, 1, 0));
    REWRITE("unsigned 64-bit remainder", 1, 10, 0, BASE, I(0x9f, 0, 2, 0, 0));
    REWRITE("unsigned 32-bit remainder", 3, 10, 0, BASE, I(0x9c, 0, 2, 0, 0));
    REWRITE("signed 64-bit remainder", 6, 10, 0, BASE, I(0x9f, 0, 2, 1, 0));
    REWRITE("signed 32-bit remainder", 8, 10, 0, BASE, I(0x9c, 0, 2, 1, 0));
    REWRITE("signed division by -1", 0, 10, 0, BASE, I(0x37, 0, 0, 1, -1));
    REWRITE("division by a constant", 0, 10, 0, BASE, I(0x37, 0, 0, 0, 3));
    /* BPF_LD_ABS and BPF_LD_IND, with an offset and without. */
    REWRITE("BPF_LD_ABS", 5, 10, 0, BASE, I(0x30, 0, 0, 0, 1));
    REWRITE("BPF_LD_IND with an offset", 6, 10, 0, BASE, I(0x50, 0, 7, 0, 2));
    REWRITE("BPF_LD_IND", 5, 10, 0, BASE, I(0x48, 0, 7, 0, 0));
    /* convert_ctx_accesses: the fields of struct __sk_buff. */
    REWRITE("len", 0, 10, 0, BASE, LDX_W(0, 6, 0));
    REWRITE("len's second byte", 2, 10, 0, BASE, LDX_B(0, 6, 1));
    REWRITE("len's low half", 1, 10, 0, BASE, LDX_H(0, 6, 0));
    REWRITE("pkt_type", 1, 10, 0, BASE, LDX_W(0, 6, 4));
    REWRITE("queue_mapping", 0, 10, 0, BASE, LDX_W(0, 6, 12));
    REWRITE("protocol's second byte", 2, 10, 0, BASE, LDX_B(0, 6, 17));
    REWRITE("protocol's half", 0, 10, 0, BASE, LDX_H(0, 6, 16));
    REWRITE("vlan_present", 2, 10, 0, BASE, LDX_W(0, 6, 20));
    REWRITE("ifindex", 2, 10, 0, BASE, LDX_W(0, 6, 40));
    REWRITE("cb written and read", 0, 10, 0, BASE, STX_W(6, 0, 48), LDX_W(0, 6, 52));
    REWRITE("napi_id", 2, 10, 0, BASE, LDX_W(0, 6, 84));
    REWRITE("gso_segs", 3, 10, 0, BASE, LDX_W(0, 6, 164));
    REWRITE("gso_size", 3, 10, 0, BASE, LDX_W(0, 6, 176));
    REWRITE("len's byte sign-extended", 2, 10, 0, BASE, I(0x91, 0, 6, 0, 0));
    /* Helpers inlined: the processor, and a lookup of one map. */
    REWRITE("bpf_get_smp_processor_id", 2, 10, 0, BASE, CALL(8));
#define LOOKUP_OF(fd) LD_MAP(1, fd), MOV_REG(2, 10), ADD(2, -8), CALL(LOOKUP)
    REWRITE("array lookup", 6, 10, 0, BASE, LOOKUP_OF(array));
    REWRITE("hash lookup", 2, 10, 0, BASE, LOOKUP_OF(hash));
    REWRITE("LRU hash lookup", 5, 10, 0, BASE, LOOKUP_OF(lru));
    REWRITE("lookup of either of two arrays", 0, 4, 0,
            PRO(MOV_REG(6, 1), MOV(2, 3), MOV(0, 1), LDX_W(7, 6, 0), ST_DW(10, -8, 0)),
            LD_MAP(1, array), JEQ(7, 0, 2), LD_MAP(1, other), MOV_REG(2, 10), ADD(2, -8),
            CALL(LOOKUP));
    /* Dead code, and jumps of 0, which go first. */
    REWRITE("dead code before a division", 1, 10, 0, BASE, MOV(3, 0), JEQ(3, 0, 1), MOV(0, 2),
            I(0x3f, 0, 2, 0, 0));
    REWRITE("jump of 0 before a division", 2, 10, 0, BASE, I(0x05, 0, 0, 0, 0),
            I(0x3f, 0, 2, 0, 0));
    REWRITE("jump over a jump of 0", 2, 10, 0, BASE, I(0x05, 0, 0, 1, 0), I(0x05, 0, 0, 0, 0),
            I(0x3f, 0, 2, 0, 0));
    /* bpf_fastcall: a socket filter's bpf_get_smp_processor_id has none
       (bpf_get_raw_smp_processor_id_proto), so the spill and fill around
       it stay, and their stack, and only the call is inlined. */
    REWRITE("spill and fill around the processor", 2, 10, 0, PRO(MOV_REG(6, 1), MOV(0, 1)),
            STX_DW(10, 1, -8), CALL(8), LDX_DW(1, 10, -8));
    REWRITE("spill and fill around the processor, the stack read", 2, 10, 0,
            PRO(MOV_REG(6, 1), MOV(0, 1), LDX_DW(3, 10, -8)), STX_DW(10, 1, -8), CALL(8),
            LDX_DW(1, 10, -8));
    REWRITE("spill and fill around a hash lookup", 2, 10, 0, PRO(MOV_REG(6, 1), MOV(0, 1)),
            ST_W(10, -4, 0), LD_MAP(1, hash), MOV_REG(2, 10), ADD(2, -4), MOV(3, 5),
            STX_DW(10, 3, -16), CALL(LOOKUP), LDX_DW(3, 10, -16));
    /* opt_subreg_zext_lo32_rnd_hi32: a 32-bit compare-and-exchange's R0
       read as 64 bits, and with BPF_F_TEST_RND_HI32 32-bit results read
       as no more. */
    REWRITE("32-bit cmpxchg read as 64 bits", 1, 10, 0, BASE, I(0xc3, 10, 7, -8, 0xf1),
            MOV_REG(3, 0));
    REWRITE("32-bit cmpxchg read as 32", 0, 10, 0, BASE, I(0xc3, 10, 7, -8, 0xf1),
            I(0xbc, 3, 0, 0, 0));
    REWRITE("64-bit cmpxchg", 0, 10, 0, BASE, I(0xdb, 10, 7, -8, 0xf1), MOV_REG(3, 0));
    REWRITE("32-bit results never read", 3, 10, TEST_RND_HI32, BASE, I(0xb4, 3, 0, 0, 1));
    REWRITE("32-bit results read as 64 bits", 0, 10, TEST_RND_HI32, BASE, I(0xb4, 3, 0, 0, 1),
            MOV_REG(4, 3));
    REWRITE("32-bit loads never read", 3, 10, TEST_RND_HI32, BASE, LDX_W(3, 10, -8));
    REWRITE("32-bit context loads never read", 0, 10, TEST_RND_HI32, BASE, LDX_W(3, 6, 0));
#undef BASE

    /* The socket is charged the program after the rewrites (96 bytes and
       8 for each instruction), below net.core.optmem_max (131072): up to
       16,371 of them, here with 100 signed divisions of 8 each. */
    static struct insn big[16372 - 700];
    for (unsigned count = 16371 - 700; count <= 16372 - 700; count++) {
        unsigned at = 0;
        big[at++] = (struct insn)MOV(0, 1);
        big[at++] = (struct insn)MOV(2, 3);
        for (int k = 0; k < 100; k++) big[at++] = (struct insn)I(0x3f, 0, 2, 1, 0);
        while (at < count - 1) big[at++] = (struct insn)MOV(0, 1);
        big[at++] = (struct insn)EXIT();
        /* Without a log: Linux's at level 1 traces each instruction, more
           than log_text holds (ENOSPC). */
        struct prog_attr p = attr(big, at);
        p.log_level = 0;
        p.log_buf = 0;
        p.log_size = 0;
        long fd = bpf(PROG_LOAD, &p, sizeof p);
        int q[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, q)) return 1;
        say("%u instructions, %u after the rewrites: loaded %d, attached %d", at, at + 700,
            fd >= 0, fd < 0 ? 0 : attach(q[1], (int)fd));
        if (fd >= 0) close((int)fd);
        close(q[0]);
        close(q[1]);
    }
    return 0;
}

/* bpf-prog-udp: filters on UDP sockets of the loopback. */
#define UDP_PAYLOAD 40000
static unsigned char udp_out[UDP_PAYLOAD], udp_in[UDP_PAYLOAD];

/* A UDP socket of `family` bound to the loopback (or, `any`, to every
   address) at a port of its own, whose address goes to `to`. */
static int udp_bound(int family, int any, struct sockaddr_storage *to, socklen_t *len) {
    int s = socket(family, SOCK_DGRAM, 0);
    memset(to, 0, sizeof *to);
    if (family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)to;
        a->sin_family = AF_INET;
        a->sin_addr.s_addr = htonl(any ? INADDR_ANY : INADDR_LOOPBACK);
        *len = sizeof *a;
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)to;
        a->sin6_family = AF_INET6;
        a->sin6_addr = any ? in6addr_any : in6addr_loopback;
        *len = sizeof *a;
    }
    if (s < 0 || bind(s, (struct sockaddr *)to, *len) || getsockname(s, (struct sockaddr *)to, len)) return -1;
    return s;
}

/* Sends `len` bytes from s to `to` and receives them on r: the send's
   result, and the count received (or -errno) with its first bytes. */
static void udp_through(const char *name, int s, int r, const struct sockaddr_storage *to, socklen_t tolen,
                        size_t len) {
    long sent = sendto(s, udp_out, len, 0, (const struct sockaddr *)to, tolen);
    if (sent < 0) sent = -errno;
    long got = recv(r, udp_in, sizeof udp_in, MSG_DONTWAIT);
    printf("%s sent %ld received %ld", name, sent, got < 0 ? -errno : got);
    for (long i = 0; i < got && i < 4; i++) printf(" %u", udp_in[i]);
    putchar('\n');
    fflush(stdout);
}

/* The array map's value at key 0, `size` bytes of it, into `out`. */
static long value0(int fd, void *out) {
    uint32_t key = 0;
    struct {
        uint32_t map_fd, pad;
        uint64_t key, value, flags;
    } a = {(uint32_t)fd, 0, (uintptr_t)&key, (uintptr_t)out, 0};
    return bpf(1, &a, sizeof a);
}

/* A filter that copies struct __sk_buff's fields into the map's value,
   one u32 each, and keeps the datagram. */
#define FIELD(i, off) LDX_W(1, 6, off), STX_W(0, 1, 4 * (i))
static const int field_offsets[] = {0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 68, 84, 164, 176};
static const char *const field_names[] = {"len", "pkt_type", "mark", "queue_mapping", "protocol",
                                          "vlan_present", "vlan_tci", "vlan_proto", "priority",
                                          "ingress_ifindex", "ifindex", "tc_index", "hash", "napi_id",
                                          "gso_segs", "gso_size"};
static int fields_filter(int m) {
    return PROGRAM(MOV_REG(6, 1), KEY4(m), CALL(LOOKUP), JEQ(0, 0, 32), FIELD(0, 0), FIELD(1, 4), FIELD(2, 8),
                   FIELD(3, 12), FIELD(4, 16), FIELD(5, 20), FIELD(6, 24), FIELD(7, 28), FIELD(8, 32),
                   FIELD(9, 36), FIELD(10, 40), FIELD(11, 44), FIELD(12, 68), FIELD(13, 84), FIELD(14, 164),
                   FIELD(15, 176), MOV(0, -1), EXIT());
}
static void say_fields(const char *name, int m) {
    uint32_t v[16] = {0};
    long r = value0(m, v);
    printf("%s lookup %ld:", name, r);
    /* The hash is random, or 0. */
    for (int i = 0; i < 16; i++)
        if (i == 12)
            printf(" %s %s", field_names[i], v[i] ? "set" : "0");
        else
            printf(" %s %u", field_names[i], v[i]);
    putchar('\n');
    fflush(stdout);
}

/* A filter that copies `len` bytes from the MAC header (start 0) or the
   network header (1) into the map's value, the helper's result after
   them at 64, and keeps the datagram. */
static int headers_filter(int m, int start, int len) {
    return PROGRAM(MOV_REG(6, 1), KEY4(m), CALL(LOOKUP), JEQ(0, 0, 8), MOV_REG(7, 0), MOV_REG(1, 6), MOV(2, 0),
                   MOV_REG(3, 7), MOV(4, len), MOV(5, start), CALL(LOAD_BYTES_RELATIVE), STX_W(7, 0, 64), MOV(0, -1),
                   EXIT());
}
/* The bytes the filter copied, with those that are random in both
   kernels (the IPv4 ID and header checksum, the IPv6 flow label, and the
   ports) as "..". */
static void say_headers(const char *name, int m, int len, int mac, int v6) {
    unsigned char v[72] = {0};
    long r = value0(m, v);
    int32_t result;
    memcpy(&result, v + 64, 4);
    printf("%s lookup %ld result %d:", name, r, result);
    int ip = mac ? 14 : 0, udp = ip + (v6 ? 40 : 20);
    for (int i = 0; i < len; i++) {
        int masked = (!v6 && (i == ip + 4 || i == ip + 5 || i == ip + 10 || i == ip + 11)) ||
                     (v6 && i >= ip + 1 && i <= ip + 3) || (i >= udp && i < udp + 4);
        if (masked)
            printf(" ..");
        else
            printf(" %02x", v[i]);
    }
    putchar('\n');
    fflush(stdout);
}

/* A classic filter that keeps A + `add` bytes after loading A with
   `load`: the received count shows A + `add` - 8 (up to what was sent),
   and a load that fails drops the datagram. */
static void classic_load(const char *name, int s, int r, const struct sockaddr_storage *to, socklen_t tolen,
                         size_t len, struct sf load, int add) {
    struct sf f[] = {load, S(C_ALU_K(C_ADD), add), S(C_RET_A, 0)};
    int a = attach_classic(r, f, COUNT(f));
    long sent = sendto(s, udp_out, len, 0, (const struct sockaddr *)to, tolen);
    long got = recv(r, udp_in, sizeof udp_in, MSG_DONTWAIT);
    say("%s attach %d sent %ld A %ld", name, a, sent < 0 ? -errno : sent, got < 0 ? -errno : got);
}

static void udp_family(int family) {
    const char *f = family == AF_INET ? "v4" : "v6";
    int v6 = family == AF_INET6;
    char name[96];
    struct sockaddr_storage to;
    socklen_t tolen;
    int r = udp_bound(family, 0, &to, &tolen);
    int s = socket(family, SOCK_DGRAM, 0);
    say("%s sockets %d", f, r >= 0 && s >= 0);

    /* The options, as on any socket. */
    int drop = PROGRAM(MOV(0, 0), EXIT());
    say("%s attach len 2 %d", f, setsockopt(r, SOL_SOCKET, SO_ATTACH_BPF, &drop, 2) ? -errno : 0);
    say("%s attach no fd %d", f, attach(r, 1000));
    say("%s detach none %d", f, option(r, SO_DETACH_FILTER, 0));
    snprintf(name, sizeof name, "%s get filter none", f);
    get(name, r, SO_GET_FILTER);
    snprintf(name, sizeof name, "%s lock filter", f);
    get(name, r, SO_LOCK_FILTER);
    snprintf(name, sizeof name, "%s bpf extensions", f);
    get(name, r, SO_BPF_EXTENSIONS);

    /* What a filter keeps: the UDP header always, of what it says. */
    snprintf(name, sizeof name, "%s no filter", f);
    udp_through(name, s, r, &to, tolen, 20);
    say("%s attach drop %d", f, attach(r, drop));
    snprintf(name, sizeof name, "%s get filter bpf", f);
    get(name, r, SO_GET_FILTER);
    snprintf(name, sizeof name, "%s drop", f);
    udp_through(name, s, r, &to, tolen, 20);
    int keeps[] = {1, 8, 11, 28, -1};
    for (unsigned i = 0; i < COUNT(keeps); i++) {
        int keep = PROGRAM(MOV(0, keeps[i]), EXIT());
        say("%s attach keep %d %d", f, keeps[i], attach(r, keep));
        snprintf(name, sizeof name, "%s keep %d", f, keeps[i]);
        udp_through(name, s, r, &to, tolen, 20);
        close(keep);
    }
    /* What is queued is what was kept (FIONREAD). */
    int keep11 = PROGRAM(MOV(0, 11), EXIT());
    attach(r, keep11);
    sendto(s, udp_out, 20, 0, (struct sockaddr *)&to, tolen);
    int queued = -1;
    int asked = ioctl(r, FIONREAD, &queued) ? -errno : 0;
    say("%s queued after keep 11 %d %d", f, asked, queued);
    recv(r, udp_in, sizeof udp_in, MSG_DONTWAIT);

    /* The fields of struct __sk_buff: unconnected, and connected. */
    int fm = map(2, 4, 64, 1, 0);
    int fields = fields_filter(fm);
    say("%s attach fields %d", f, attach(r, fields));
    snprintf(name, sizeof name, "%s fields", f);
    udp_through(name, s, r, &to, tolen, 20);
    say_fields(name, fm);
    int c = socket(family, SOCK_DGRAM, 0);
    int priority = 3;
    setsockopt(c, SOL_SOCKET, SO_PRIORITY, &priority, sizeof priority);
    say("%s connect %d", f, connect(c, (struct sockaddr *)&to, tolen) ? -errno : 0);
    snprintf(name, sizeof name, "%s connected fields", f);
    udp_through(name, c, r, &to, tolen, 300);
    say_fields(name, fm);

    /* The headers, from the MAC header (the loopback's, of zeros) and
       the network header, to the linear part's end. */
    int hm = map(2, 4, 72, 1, 0);
    int all = v6 ? 62 : 42;
    int mac = headers_filter(hm, 0, all);
    say("%s attach mac %d", f, attach(r, mac));
    snprintf(name, sizeof name, "%s mac", f);
    udp_through(name, s, r, &to, tolen, 20);
    say_headers(name, hm, all, 1, v6);
    int net = headers_filter(hm, 1, all - 14);
    say("%s attach net %d", f, attach(r, net));
    snprintf(name, sizeof name, "%s net", f);
    udp_through(name, s, r, &to, tolen, 20);
    say_headers(name, hm, all - 14, 0, v6);
    int past = headers_filter(hm, 1, all - 14 + 20 + 1);
    say("%s attach past %d", f, attach(r, past));
    snprintf(name, sizeof name, "%s past the end", f);
    udp_through(name, s, r, &to, tolen, 20);
    say_headers(name, hm, 0, 0, v6);
    /* A datagram whose bytes go in pages: the headers alone are linear. */
    int linear = headers_filter(hm, 1, all - 14);
    attach(r, linear);
    snprintf(name, sizeof name, "%s paged", f);
    udp_through(name, s, r, &to, tolen, 20000);
    say_headers(name, hm, all - 14, 0, v6);
    int beyond = headers_filter(hm, 1, all - 14 + 1);
    attach(r, beyond);
    snprintf(name, sizeof name, "%s paged past the headers", f);
    udp_through(name, s, r, &to, tolen, 20000);
    say_headers(name, hm, 0, 0, v6);

    /* Classic loads: the ancillary fields, and the headers. */
    int ip = v6 ? 40 : 20;
    struct {
        const char *name;
        size_t len;
        struct sf load;
        int add;
    } loads[] = {
        {"protocol", UDP_PAYLOAD, S(C_LD_W_ABS, AD(0)), 8},
        {"pkttype", UDP_PAYLOAD, S(C_LD_W_ABS, AD(4)), 8},
        {"ifindex", UDP_PAYLOAD, S(C_LD_W_ABS, AD(8)), 8},
        {"mark", UDP_PAYLOAD, S(C_LD_W_ABS, AD(20)), 8},
        {"queue", UDP_PAYLOAD, S(C_LD_W_ABS, AD(24)), 8},
        {"hatype", UDP_PAYLOAD, S(C_LD_W_ABS, AD(28)), 8},
        {"vlan tag present", UDP_PAYLOAD, S(C_LD_W_ABS, AD(48)), 8},
        {"payload offset", UDP_PAYLOAD, S(C_LD_W_ABS, AD(52)), 8},
        /* 308, the UDP header and 300 bytes, less 290. */
        {"len", 300, S(C_LD_LEN, 0), -290},
        {"udp length", 300, S(C_LD_H_ABS, 4), -290},
        {"next header", 300, S(C_LD_B_ABS, NET(v6 ? 6 : 9)), 8},
        {"ethertype", UDP_PAYLOAD, S(C_LD_H_ABS, LL(12)), 8},
        {"destination mac", 300, S(C_LD_W_ABS, LL(0)), 8},
        {"before the mac header", 300, S(C_LD_B_ABS, LL(-1)), 8},
        {"payload byte", 300, S(C_LD_B_ABS, NET(ip + 8)), 8},
        {"paged byte", 20000, S(C_LD_B_ABS, 10000), 8},
        {"paged last header byte", 20000, S(C_LD_B_ABS, NET(ip + 7)), 8},
        {"paged payload by net", 20000, S(C_LD_B_ABS, NET(ip + 8)), 8},
    };
    for (unsigned i = 0; i < COUNT(loads); i++) {
        snprintf(name, sizeof name, "%s classic %s", f, loads[i].name);
        classic_load(name, s, r, &to, tolen, loads[i].len, loads[i].load, loads[i].add);
    }
    snprintf(name, sizeof name, "%s get filter classic", f);
    get_classic(name, r, 3);

    /* SO_LOCK_FILTER keeps the filter. */
    say("%s lock %d", f, option(r, SO_LOCK_FILTER, 1));
    say("%s attach locked %d", f, attach(r, drop));
    say("%s detach locked %d", f, option(r, SO_DETACH_FILTER, 0));
    say("%s unlock locked %d", f, option(r, SO_LOCK_FILTER, 0));

    /* A datagram takes of the receive buffer what it took as it came,
       however much the filter kept: the second of these does not fit. */
    struct sockaddr_storage small_to;
    socklen_t small_len;
    int small = udp_bound(family, 0, &small_to, &small_len);
    int one = 1;
    setsockopt(small, SOL_SOCKET, SO_RCVBUF, &one, sizeof one);
    int keep8 = PROGRAM(MOV(0, 8), EXIT());
    say("%s small attach %d", f, attach(small, keep8));
    for (int i = 0; i < 3; i++) sendto(s, udp_out, 3000, 0, (struct sockaddr *)&small_to, small_len);
    int n = 0;
    long got;
    while ((got = recv(small, udp_in, sizeof udp_in, MSG_DONTWAIT)) >= 0) n++;
    say("%s small received %d then %d", f, n, -errno);

    int fds[] = {r, s, c, small, drop, keep11, fields, fm, mac, net, past, linear, beyond, hm, keep8};
    for (unsigned i = 0; i < COUNT(fds); i++) close(fds[i]);
}

static int case_udp(void) {
    for (size_t i = 0; i < sizeof udp_out; i++) udp_out[i] = (unsigned char)(i * 7 + 3);
    /* A network namespace of its own, whose loopback it brings up: the
       emulator gives internet sockets to a guest without a network only
       there. */
    say("unshare %d", unshare(CLONE_NEWNET) ? -errno : 0);
    {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof ifr);
        strcpy(ifr.ifr_name, "lo");
        int u = socket(AF_INET, SOCK_DGRAM, 0);
        int r = ioctl(u, SIOCGIFFLAGS, &ifr) ? -errno : 0;
        ifr.ifr_flags |= IFF_UP;
        say("lo %d up %d", r, ioctl(u, SIOCSIFFLAGS, &ifr) ? -errno : 0);
        close(u);
    }
    udp_family(AF_INET);
    udp_family(AF_INET6);
    /* An IPv4 datagram to a dual-stack IPv6 socket is IPv4's. */
    struct sockaddr_storage any;
    socklen_t anylen;
    int r = udp_bound(AF_INET6, 1, &any, &anylen);
    int fm = map(2, 4, 64, 1, 0);
    say("dual attach %d", attach(r, fields_filter(fm)));
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = ((struct sockaddr_in6 *)&any)->sin6_port,
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    udp_through("dual", s, r, (struct sockaddr_storage *)&to, sizeof to, 20);
    say_fields("dual fields", fm);
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    alarm(20);
    if (!strcmp(mode, "bpf-prog-verify")) return case_verify();
    if (!strcmp(mode, "bpf-prog-maps")) return case_maps();
    if (!strcmp(mode, "bpf-prog-context")) return case_context();
    if (!strcmp(mode, "bpf-prog-attach")) return case_attach();
    if (!strcmp(mode, "bpf-prog-corpus")) return case_corpus();
    if (!strcmp(mode, "bpf-prog-classic")) return case_classic();
    if (!strcmp(mode, "bpf-prog-atomic")) return case_atomic();
    if (!strcmp(mode, "bpf-prog-acqrel")) return case_acqrel();
    if (!strcmp(mode, "bpf-prog-ldabs")) return case_ldabs();
    if (!strcmp(mode, "bpf-prog-calls")) return case_calls();
    if (!strcmp(mode, "bpf-prog-rewrites")) return case_rewrites();
    if (!strcmp(mode, "bpf-prog-udp")) return case_udp();
    return 2;
}
