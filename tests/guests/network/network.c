/* TCP client sockets against the differential test's local server, and
 * the guest's own servers on the loopback (the "listen" modes).
 *
 *   network <mode> <open-port> <closed-port> [<own-path>]
 *
 * The server (crates/paludarium-harness/tests/diff_network.rs) listens on
 * 127.0.0.1:<open-port> and reads one command byte per connection:
 *   'e' echoes everything until the end of input, then closes;
 *   'c' closes at once;
 *   'b' sends 1 MiB of a pattern, then closes;
 *   'w' reads until the end of input, sends "bye", then closes.
 * Nothing listens on <closed-port>; <own-path> is where the program is, for
 * the modes that run it again. Only what native Linux and the
 * emulator share is printed: never the client's own port, nor the ports
 * the guest's servers take. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SIOCOUTQ
#define SIOCOUTQ TIOCOUTQ
#endif

static int open_port, closed_port;

static struct sockaddr_in to(int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
}
static int tcp(int flags) { return socket(AF_INET, SOCK_STREAM | flags, 0); }
static int connected(char command) {
    int fd = tcp(0);
    if (fd < 0) {
        printf("socket failed errno=%d\n", errno);
        exit(71);
    }
    struct sockaddr_in a = to(open_port);
    if (connect(fd, (void *)&a, sizeof a)) {
        printf("connect failed errno=%d\n", errno);
        exit(70);
    }
    if (command) send(fd, &command, 1, 0);
    return fd;
}
/* The events among `events` poll reports for `fd`, waiting up to 5 s. */
static void polled(const char *name, int fd, short events) {
    struct pollfd p = {.fd = fd, .events = events};
    int n = poll(&p, 1, 5000);
    printf("  %s poll=%d revents=%#x\n", name, n, (unsigned)p.revents);
}
/* Waits for the end of input, which the peer's close or shutdown sends. */
static void await_end(int fd) {
    struct pollfd p = {.fd = fd, .events = POLLRDHUP};
    poll(&p, 1, 5000);
}
static void option(const char *name, int fd, int level, int opt) {
    int value = -7;
    socklen_t len = sizeof value;
    errno = 0;
    int r = getsockopt(fd, level, opt, &value, &len);
    printf("  %s=%d errno=%d value=%d len=%u\n", name, r, errno, value, (unsigned)len);
}
static void set_option(const char *name, int fd, int level, int opt, int value) {
    errno = 0;
    int r = setsockopt(fd, level, opt, &value, sizeof value);
    int e = errno;
    int got = -7;
    socklen_t len = sizeof got;
    getsockopt(fd, level, opt, &got, &len);
    printf("  set %s=%d errno=%d got=%d\n", name, r, e, got);
}
static void call(const char *name, int r) { printf("  %s=%d errno=%d\n", name, r, r < 0 ? errno : 0); }
static void print_bytes(const char *name, const char *buf, long n) {
    printf("  %s=%ld \"%.*s\"\n", name, n, n > 0 ? (int)n : 0, buf);
}
/* async: takes the signal-driven I/O signals of a step, and prints each
   different one as it comes (data may come in several pieces). */
static void signals(const char *step) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, 40);
    siginfo_t info;
    int last_code = 0;
    long last_band = 0;
    /* Linux wakes a poll before it sends the signal (tcp_fin calls
       sk_state_change, then sk_wake_async), so a signal may follow the
       poll that saw its event. Every step has one: the first is awaited
       for up to 5 s, the rest until none comes for 200 ms. */
    struct timespec first = {5, 0}, settle = {0, 200000000};
    printf("  %s:", step);
    for (const struct timespec *wait = &first; sigtimedwait(&set, &info, wait) == 40; wait = &settle) {
        if (info.si_code == last_code && info.si_band == last_band) continue;
        last_code = info.si_code;
        last_band = info.si_band;
        printf(" code=%d band=%#lx fd-ok=%d", info.si_code, info.si_band, info.si_fd >= 3);
    }
    putchar('\n');
}
static int async_socket(void) {
    int fd = tcp(SOCK_NONBLOCK);
    fcntl(fd, F_SETOWN, getpid());
    fcntl(fd, F_SETSIG, 40);
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_ASYNC);
    return fd;
}
/* The events among `events` poll reports for `fd` now. */
static void ready(const char *name, int fd, short events) {
    struct pollfd p = {.fd = fd, .events = events};
    int n = poll(&p, 1, 0);
    printf("  %s poll=%d revents=%#x\n", name, n, (unsigned)p.revents);
}
/* `fd`'s tcp_info (getsockopt TCP_INFO) as raw bytes, with room for
   `room`; the length it gave goes to `len`. */
static int tcp_info_raw(int fd, unsigned char *raw, int room, socklen_t *len) {
    memset(raw, 0xaa, 512);
    *len = room;
    errno = 0;
    return getsockopt(fd, IPPROTO_TCP, TCP_INFO, raw, len);
}
static unsigned info_word(const unsigned char *raw, int at) {
    unsigned v;
    memcpy(&v, raw + at, 4);
    return v;
}
static unsigned long long info_long(const unsigned char *raw, int at) {
    unsigned long long v;
    memcpy(&v, raw + at, 8);
    return v;
}
/* Prints the fields of `fd`'s tcp_info at the offsets in `at` (words, or
   with `+` the 8-byte ones), after its first eight bytes, or only those of
   them `bytes` marks. Linux's round trips, rates, windows and the times
   since data went or came vary from run to run, so they are not printed. */
static void tcp_info(const char *name, int fd, unsigned bytes, const int *at) {
    unsigned char raw[512];
    socklen_t len;
    int r = tcp_info_raw(fd, raw, 512, &len);
    printf("  %s=%d errno=%d len=%u b=", name, r, errno, (unsigned)len);
    for (int i = 0; i < 8; i++)
        if (bytes & 1u << i) printf("%u,", raw[i]);
    for (; *at; at++) {
        if (*at > 0) printf(" %d:%u", *at, info_word(raw, *at));
        else printf(" %d:%llu", -*at, info_long(raw, -*at));
    }
    putchar('\n');
}
/* tcp-segments: both sides' counts of segments sent, received, sent and
   received with data, delivered, unacknowledged and sent again, and the
   bytes not sent, once what may wait (TCP_DELACK_MIN's 40 ms) has gone. */
static void segment_counts(const char *step, int c, int s) {
    static const int at[] = {136, 140, 156, 152, 192, 24, 100, 144, -200, -208, 0};
    poll(NULL, 0, 120);
    printf(" %s\n", step);
    tcp_info("client", c, 0x1, at);
    tcp_info("server", s, 0x1, at);
}
/* A TCP socket listening with `backlog` on 127.0.0.1, at a port it takes,
   which `port` gets. */
static int listener(int backlog, int *port) {
    int fd = tcp(0);
    struct sockaddr_in a = to(0);
    if (bind(fd, (void *)&a, sizeof a) || listen(fd, backlog)) {
        printf("listen failed errno=%d\n", errno);
        exit(69);
    }
    socklen_t len = sizeof a;
    getsockname(fd, (void *)&a, &len);
    *port = ntohs(a.sin_port);
    return fd;
}
/* A TCP socket connecting to `port` on 127.0.0.1; its connect's result goes
   to `result`. */
static int client(int port, int flags, int *result) {
    int fd = tcp(flags);
    struct sockaddr_in a = to(port);
    errno = 0;
    *result = connect(fd, (void *)&a, sizeof a) ? errno : 0;
    return fd;
}
/* tcp-held: milliseconds of the monotonic and the real-time clock. */
static long long clock_ms(int clock) {
    struct timespec t;
    clock_gettime(clock, &t);
    return t.tv_sec * 1000LL + t.tv_nsec / 1000000;
}
/* The bytes that wait at `s` to be read and at `c` to be acknowledged, and
   whether `s` polls readable. */
static void held_queues(const char *step, int c, int s) {
    int in = -1, out = -1;
    struct pollfd p = {s, POLLIN, 0};
    ioctl(s, FIONREAD, &in);
    ioctl(c, SIOCOUTQ, &out);
    int ready = poll(&p, 1, 0);
    printf("  %s in=%d out=%d poll=%d\n", step, in, out, ready);
}
/* Reads what waits at `s` and says whether it came in the first `late`
   milliseconds before now, by its SO_TIMESTAMPNS and last_data_recv, and
   after the first `early` milliseconds since `start` (real time). */
static void held_read(const char *step, int s, long long start, int early, int late) {
    char bytes[200], control[64];
    struct iovec iov = {bytes, sizeof bytes};
    struct msghdr m = {0};
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = control;
    m.msg_controllen = sizeof control;
    static const int since = 52;
    unsigned char raw[512];
    socklen_t len;
    tcp_info_raw(s, raw, 512, &len);
    long long now = clock_ms(CLOCK_REALTIME), came = 0;
    int n = recvmsg(s, &m, MSG_DONTWAIT);
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    if (n > 0 && h) {
        struct timespec t;
        memcpy(&t, CMSG_DATA(h), sizeof t);
        came = t.tv_sec * 1000LL + t.tv_nsec / 1000000;
    }
    int ago = info_word(raw, since);
    printf("  %s=%d after=%d before=%d ago=%d\n", step, n, came - start >= early,
           now - came >= late, ago >= late && ago <= now - start - early + 1);
}
static void held_signal(int number) { (void)number; }
/* Holds data back once the first thread is about to sleep, and goes. */
static int held_pipe[2];
static long long held_at;
static void *held_thread(void *c) {
    char byte;
    if (read(held_pipe[0], &byte, 1) == 1) {
        held_at = clock_ms(CLOCK_MONOTONIC);
        send(*(int *)c, "held", 4, MSG_MORE);
    }
    return NULL;
}
/* What Nagle's algorithm, MSG_MORE and a delayed acknowledgement hold back
   reaches the peer once its time has come, whoever looks then. A step the
   machine took too long for is done again. */
static void held(int l, int port) {
    static char bytes[200];
    int result, on = 1;
    for (int step = 0; step < 9; step++) {
        for (int tries = 0; tries < 20; tries++) {
            int c = client(port, 0, &result), s = accept(l, NULL, NULL);
            setsockopt(s, SOL_SOCKET, SO_TIMESTAMPNS, &on, sizeof on);
            long long start = clock_ms(CLOCK_REALTIME), began = clock_ms(CLOCK_MONOTONIC);
            /* Sixteen acknowledged at once, one that waits 40 ms, and three
               held for it; or one held 200 ms. */
            int more = step == 1 || step == 5;
            for (int n = 0; n < (step == 8 ? 0 : more ? 1 : 20); n++)
                send(c, bytes, more ? 100 : 1, more ? MSG_MORE : 0);
            int in = 0;
            ioctl(s, FIONREAD, &in);
            if (clock_ms(CLOCK_MONOTONIC) - began > 15) {
                close(c);
                close(s);
                continue;
            }
            printf(" step %d\n", step);
            if (step == 0 || step == 1) held_queues("held", c, s);
            if (step == 0) {
                /* No call on the connection until its time has passed. */
                struct timespec t = {0, 150000000};
                nanosleep(&t, NULL);
                held_queues("later", c, s);
                held_read("read", s, start, 25, 40);
            } else if (step == 1) {
                struct timespec t = {0, 400000000};
                nanosleep(&t, NULL);
                held_read("read", s, start, 150, 40);
            } else if (step == 2) {
                /* A read acknowledges what it read. */
                call("recv", recv(s, bytes, 17, 0));
                held_queues("after", c, s);
            } else if (step == 3) {
                setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
                ioctl(s, FIONREAD, &in);
                printf("  nodelay in=%d\n", in);
            } else if (step == 4) {
                /* The end takes along what is held. */
                shutdown(c, SHUT_WR);
                call("recv", recv(s, bytes, sizeof bytes, 0));
                call("recv", recv(s, bytes, sizeof bytes, 0));
            } else if (step == 5) {
                /* A read waits for it. */
                call("recv", recv(s, bytes, sizeof bytes, 0));
                long long took = clock_ms(CLOCK_MONOTONIC) - began;
                printf("  waited=%d\n", took >= 150 && took < 2000);
            } else if (step == 6) {
                /* So does a poll past what has come. */
                recv(s, bytes, 17, 0);
                recv(s, bytes, 3, 0);
                for (int n = 0; n < 2; n++) send(c, bytes, 100, MSG_MORE);
                struct pollfd p = {s, POLLIN, 0};
                long long from = clock_ms(CLOCK_MONOTONIC);
                call("poll", poll(&p, 1, 5000));
                printf("  waited=%d\n", clock_ms(CLOCK_MONOTONIC) - from < 2000);
                call("recv", recv(s, bytes, sizeof bytes, 0));
            } else {
                /* SIGIO for it ends a sleep, also one that began before
                   another thread had it held. */
                struct sigaction a = {0};
                pthread_t other;
                sigset_t io;
                sigemptyset(&io);
                sigaddset(&io, SIGIO);
                a.sa_handler = held_signal;
                sigaction(SIGIO, &a, NULL);
                fcntl(s, F_SETOWN, getpid());
                fcntl(s, F_SETFL, O_ASYNC);
                struct timespec t = {10, 0}, rest = {0, 0};
                int slept = 0, late = 1, tries = 0;
                /* Again only where the other thread came after the whole
                   sleep, as the emulator's test clock may have it. */
                for (; tries < 20 && !slept && late; tries++) {
                    if (step == 8) {
                        if (pipe(held_pipe)) exit(70);
                        pthread_sigmask(SIG_BLOCK, &io, NULL);
                        if (pthread_create(&other, NULL, held_thread, &c)) exit(70);
                        pthread_sigmask(SIG_UNBLOCK, &io, NULL);
                        if (write(held_pipe[1], "g", 1) != 1) exit(70);
                    }
                    long long until = clock_ms(CLOCK_MONOTONIC) + 10000;
                    slept = nanosleep(&t, &rest);
                    int error = errno;
                    late = 0;
                    if (step == 8) {
                        pthread_join(other, NULL);
                        close(held_pipe[0]);
                        close(held_pipe[1]);
                        late = held_at >= until;
                        if (!slept && late) while (recv(s, bytes, sizeof bytes, 0) < 0) {}
                    }
                    errno = error;
                }
                if (!slept && late) puts("  the other thread came late each time");
                call("nanosleep", slept);
                printf("  rest=%d\n", rest.tv_sec >= 8);
                ioctl(s, FIONREAD, &in);
                printf("  in=%d\n", in);
            }
            close(c);
            close(s);
            break;
        }
    }
}
/* tcp-loss: filters on what comes to a connection's side, the data from
   the payload on (SO_ATTACH_FILTER; a packet starts at its TCP header). */
struct sock_filter {
    unsigned short code;
    unsigned char jt, jf;
    unsigned k;
};
struct sock_fprog {
    unsigned short len;
    struct sock_filter *filter;
};
enum { BPF_LD = 0, BPF_ALU = 4, BPF_JMP = 5, BPF_RET = 6, BPF_MISC = 7, BPF_TAX = 0, BPF_TXA = 0x80 };
enum { BPF_W = 0, BPF_B = 0x10, BPF_ABS = 0x20, BPF_IND = 0x40, BPF_LEN = 0x80, BPF_K = 0, BPF_X = 8, BPF_A = 0x10 };
enum { BPF_ADD = 0, BPF_SUB = 0x10, BPF_AND = 0x50, BPF_RSH = 0x70, BPF_JEQ = 0x10, BPF_JSET = 0x40 };
#define LOSS_HEAD                                                              \
    {BPF_LD | BPF_B | BPF_ABS, 0, 0, 12}, {BPF_ALU | BPF_RSH | BPF_K, 0, 0, 2}, \
        {BPF_ALU | BPF_AND | BPF_K, 0, 0, 0x3c}, {BPF_MISC | BPF_TAX, 0, 0, 0}, \
        {BPF_LD | BPF_W | BPF_LEN, 0, 0, 0}, {BPF_ALU | BPF_SUB | BPF_X, 0, 0, 0}
#define LOSS_KEEP {BPF_RET | BPF_K, 0, 0, 0xffffffff}
#define LOSS_DROP {BPF_RET | BPF_K, 0, 0, 0}
static struct sock_filter loss_data[] = {LOSS_HEAD, {BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0}, LOSS_KEEP, LOSS_DROP};
/* Data that starts with an A. */
static struct sock_filter loss_first[] = {LOSS_HEAD, {BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 0},
                                          {BPF_LD | BPF_B | BPF_IND, 0, 0, 0}, {BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 'A'},
                                          LOSS_KEEP, LOSS_DROP};
/* Keeps ten bytes of it. */
static struct sock_filter loss_cut[] = {LOSS_HEAD, {BPF_JMP | BPF_JEQ | BPF_K, 3, 0, 0},
                                        {BPF_MISC | BPF_TXA, 0, 0, 0}, {BPF_ALU | BPF_ADD | BPF_K, 0, 0, 10},
                                        {BPF_RET | BPF_A, 0, 0, 0}, LOSS_KEEP};
/* An acknowledgement alone; an end; a reset; anything. */
static struct sock_filter loss_acks[] = {LOSS_HEAD, {BPF_JMP | BPF_JEQ | BPF_K, 0, 2, 0},
                                         {BPF_LD | BPF_B | BPF_ABS, 0, 0, 13}, {BPF_JMP | BPF_JSET | BPF_K, 0, 1, 1},
                                         LOSS_KEEP, LOSS_DROP};
static struct sock_filter loss_end[] = {{BPF_LD | BPF_B | BPF_ABS, 0, 0, 13}, {BPF_JMP | BPF_JSET | BPF_K, 0, 1, 1},
                                        LOSS_DROP, LOSS_KEEP};
static struct sock_filter loss_reset[] = {{BPF_LD | BPF_B | BPF_ABS, 0, 0, 13}, {BPF_JMP | BPF_JSET | BPF_K, 0, 1, 4},
                                          LOSS_DROP, LOSS_KEEP};
static struct sock_filter loss_all[] = {LOSS_DROP};
#define LOSS(fd, f) loss_attach(fd, f, sizeof f / sizeof *f)
static char loss_out[8192];
/* Whether the step is to be done again, because a timer ran before what it
   looks for could be seen: told by the counts, not by the time. */
static int loss_len, loss_again;
static long long loss_start;
#define LOSS_WATCHDOG 10000
enum { UNACKED = 24, SACKED = 28, TOTAL = 100, ACKED = 120, RECEIVED = 128 };
static void loss_say(const char *format, ...) {
    va_list args;
    va_start(args, format);
    loss_len += vsnprintf(loss_out + loss_len, sizeof loss_out - loss_len, format, args);
    va_end(args);
}
static void loss_attach(int fd, struct sock_filter *f, int len) {
    struct sock_fprog p = {len, f};
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &p, sizeof p)) loss_say("  attach errno=%d\n", errno);
}
static void loss_lift(int fd) {
    if (setsockopt(fd, SOL_SOCKET, SO_DETACH_FILTER, &fd, sizeof fd)) loss_say("  detach errno=%d\n", errno);
}
static unsigned loss_word(int fd, int at) {
    unsigned char raw[512];
    socklen_t len;
    tcp_info_raw(fd, raw, 512, &len);
    return info_word(raw, at);
}
/* Waits until `fd`'s tcp_info has `value` at `at`; past it, which only a
   count can go, the step is done again. */
static void loss_wait(int fd, int at, unsigned value) {
    long long end = clock_ms(CLOCK_MONOTONIC) + LOSS_WATCHDOG;
    for (;;) {
        unsigned now = loss_word(fd, at);
        if (now == value) return;
        if (at != UNACKED && now > value) {
            loss_again = 1;
            return;
        }
        if (clock_ms(CLOCK_MONOTONIC) > end) {
            loss_say("  %d never %u\n", at, value);
            return;
        }
        struct timespec t = {0, 5000000};
        nanosleep(&t, NULL);
    }
}
static void loss_info(const char *name, int fd, const int *at) {
    unsigned char raw[512];
    socklen_t len;
    tcp_info_raw(fd, raw, 512, &len);
    loss_say("  %s state=%u ca=%u retransmits=%u backoff=%u", name, raw[0], raw[1], raw[2], raw[4]);
    for (; *at; at++)
        if (*at > 0) loss_say(" %d:%u", *at, info_word(raw, *at));
        else loss_say(" %d:%llu", -*at, info_long(raw, -*at));
    loss_say("\n");
}
/* Both sides, once the client has sent `total` segments again, and not yet
   one more. */
static void loss_both(unsigned total, int c, int s) {
    static const int sent[] = {24, 28, 32, 36, 80, 76, 100, 136, 140, 156, 192, 216, 220, 144, 240, -120, -200, -208, 0};
    static const int came[] = {136, 140, 152, 224, -128, 0};
    loss_wait(c, TOTAL, total);
    loss_say(" sent again %u\n", total);
    loss_info("server", s, came);
    loss_info("client", c, sent);
    loss_again |= loss_word(c, TOTAL) != total;
}
static void loss_send(int c, char byte, int len) {
    static char bytes[4000];
    memset(bytes, byte, len);
    int n = send(c, bytes, len, MSG_NOSIGNAL);
    if (n != len) loss_say("  send=%d errno=%d\n", n, errno);
}
/* Reads what waits: its length and first byte, and whether its time is at
   least `early` milliseconds after the step's start (no timer runs before
   its time) and `before` before now. */
static void loss_read(int s, int early, int before) {
    char bytes[4000], control[64];
    struct iovec iov = {bytes, sizeof bytes};
    struct msghdr m = {0};
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = control;
    m.msg_controllen = sizeof control;
    unsigned char raw[512];
    socklen_t len;
    tcp_info_raw(s, raw, 512, &len);
    long long now = clock_ms(CLOCK_REALTIME), mono = clock_ms(CLOCK_MONOTONIC);
    int n = recvmsg(s, &m, MSG_DONTWAIT);
    if (n < 0) {
        loss_say("  recv=-1 errno=%d\n", errno);
        loss_again |= before > 0;
        return;
    }
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    loss_say("  recv=%d %c", n, n > 0 ? bytes[0] : '-');
    if (n > 0 && h) {
        struct timespec t;
        memcpy(&t, CMSG_DATA(h), sizeof t);
        long long came = t.tv_sec * 1000LL + t.tv_nsec / 1000000, ago = info_word(raw, 52);
        loss_again |= now - came < before || ago < before;
        loss_say(" early=%d", came - (now - (mono - loss_start)) < early - 5 || mono - ago - loss_start < early - 5);
    }
    loss_say("\n");
}
static void loss_error(int fd) {
    int error = 0;
    socklen_t len = sizeof error;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
    loss_say("  error=%d\n", error);
}
static void loss_poll(int fd, int events) {
    struct pollfd p = {fd, events, 0};
    int r = poll(&p, 1, LOSS_WATCHDOG);
    loss_say("  poll=%d %x\n", r, r > 0 ? p.revents : 0);
}
/* An address of the loopback no connection has been to. Linux keeps, per
   network namespace, the round trip and the reordering that a connection's
   end leaves for its two addresses (`tcp_metrics`), and the next one starts
   with them, also another program's: its first timeout follows. */
static struct sockaddr_in fresh_to(int port) {
    static unsigned host;
    if (!host) {
        struct timespec t;
        clock_gettime(CLOCK_REALTIME, &t);
        host = 0x10000 + (t.tv_sec % 8000 * 1000000 + t.tv_nsec / 1000) % 0xe00000;
    }
    struct sockaddr_in a = to(port);
    a.sin_addr.s_addr = htonl(0x7f000000 | host++);
    return a;
}
/* A listener on every address, and a client of it on one of its own. */
static int fresh_listener(int *port) {
    int fd = tcp(0);
    struct sockaddr_in a = {.sin_family = AF_INET};
    socklen_t len = sizeof a;
    if (bind(fd, (void *)&a, sizeof a) || listen(fd, 8)) printf("listen failed errno=%d\n", errno);
    getsockname(fd, (void *)&a, &len);
    *port = ntohs(a.sin_port);
    return fd;
}
static int fresh_client(int port, int *result) {
    int fd = tcp(0);
    struct sockaddr_in a = fresh_to(port);
    errno = 0;
    *result = connect(fd, (void *)&a, sizeof a) ? errno : 0;
    return fd;
}
static void loss_step(int step, int c, int s) {
    struct timespec little = {0, 1000000};
    switch (step) {
    case 0:
        /* Dropped each time: a probe, then timeouts. */
        LOSS(s, loss_data);
        loss_send(c, 'A', 100);
        loss_both(1, c, s);
        loss_both(2, c, s);
        loss_lift(s);
        loss_wait(s, RECEIVED, 100);
        loss_wait(c, UNACKED, 0);
        loss_both(3, c, s);
        loss_read(s, 750, 0);
        loss_send(c, 'B', 10);
        loss_wait(s, RECEIVED, 110);
        loss_wait(c, UNACKED, 0);
        loss_both(3, c, s);
        break;
    case 1:
        /* Two, which go again as one while no one calls. */
        LOSS(s, loss_data);
        loss_send(c, 'A', 100);
        loss_send(c, 'B', 100);
        loss_both(1, c, s);
        loss_read(s, 0, 0);
        loss_lift(s);
        {
            struct timespec t = {1, 0};
            nanosleep(&t, NULL);
        }
        loss_read(s, 190, 100);
        loss_wait(c, UNACKED, 0);
        loss_both(2, c, s);
        break;
    case 2:
        /* A gap, told of by what comes after it. */
        LOSS(s, loss_first);
        loss_send(c, 'A', 100);
        nanosleep(&little, NULL);
        for (int n = 0; n < 4; n++) loss_send(c, 'B', 100);
        loss_wait(c, TOTAL, 1);
        loss_again |= loss_word(c, SACKED) != 1 || loss_word(c, UNACKED) != 2;
        loss_both(1, c, s);
        loss_read(s, 0, 0);
        loss_lift(s);
        loss_wait(s, RECEIVED, 500);
        loss_wait(c, UNACKED, 0);
        loss_both(2, c, s);
        loss_read(s, 190, 0);
        break;
    case 3:
        /* Ten bytes at a time. */
        LOSS(s, loss_cut);
        loss_send(c, 'A', 100);
        loss_wait(s, RECEIVED, 10);
        loss_wait(c, ACKED, 11);
        loss_both(0, c, s);
        loss_read(s, 0, 0);
        loss_wait(s, RECEIVED, 20);
        loss_wait(c, ACKED, 21);
        loss_both(1, c, s);
        loss_read(s, 190, 0);
        loss_lift(s);
        loss_wait(s, RECEIVED, 100);
        loss_wait(c, UNACKED, 0);
        loss_both(2, c, s);
        loss_read(s, 390, 0);
        break;
    case 4:
        /* Acknowledgements are lost, and the data goes again. */
        LOSS(c, loss_acks);
        loss_send(c, 'A', 100);
        loss_wait(s, RECEIVED, 100);
        loss_read(s, 0, 0);
        loss_wait(s, 136, 1);
        loss_both(0, c, s);
        loss_wait(s, 136, 2);
        loss_both(1, c, s);
        loss_lift(c);
        loss_wait(c, UNACKED, 0);
        loss_both(2, c, s);
        loss_read(s, 0, 0);
        break;
    case 5:
        LOSS(s, loss_end);
        shutdown(c, SHUT_WR);
        loss_both(1, c, s);
        loss_read(s, 0, 0);
        loss_lift(s);
        loss_poll(s, POLLIN | POLLRDHUP);
        loss_read(s, 0, 0);
        loss_wait(c, UNACKED, 0);
        loss_both(2, c, s);
        break;
    case 6: {
        /* The end comes with what is kept of its segment. */
        char bytes[30];
        memset(bytes, 'A', sizeof bytes);
        LOSS(s, loss_cut);
        send(c, bytes, sizeof bytes, MSG_MORE);
        shutdown(c, SHUT_WR);
        loss_poll(s, POLLIN | POLLRDHUP);
        loss_read(s, 0, 0);
        loss_read(s, 0, 0);
        loss_wait(c, ACKED, 12);
        loss_both(0, c, s);
        loss_wait(s, 140, 4);
        loss_both(1, c, s);
        break;
    }
    case 7:
        /* A reset dropped: sent again for each segment. */
        LOSS(c, loss_reset);
        loss_send(c, 'A', 5);
        loss_wait(s, RECEIVED, 5);
        loss_wait(c, UNACKED, 0);
        close(s);
        loss_send(c, 'B', 5);
        loss_wait(c, TOTAL, 1);
        loss_read(c, 0, 0);
        loss_error(c);
        loss_lift(c);
        loss_poll(c, 0);
        loss_error(c);
        loss_read(c, 0, 0);
        break;
    case 8: {
        int timeout = 300;
        setsockopt(c, IPPROTO_TCP, TCP_USER_TIMEOUT, &timeout, sizeof timeout);
        LOSS(s, loss_all);
        loss_send(c, 'A', 100);
        loss_poll(c, 0);
        loss_say("  early=%d\n", clock_ms(CLOCK_MONOTONIC) - loss_start < 295);
        loss_error(c);
        loss_read(c, 0, 0);
        int n = send(c, "B", 1, MSG_NOSIGNAL);
        loss_say("  send=%d errno=%d\n", n, n < 0 ? errno : 0);
        break;
    }
    case 9: {
        /* The accepted side has the listener's. */
        int port, result;
        int other = fresh_listener(&port);
        LOSS(other, loss_data);
        int c2 = fresh_client(port, &result), s2 = accept(other, NULL, NULL), on = 1;
        setsockopt(s2, SOL_SOCKET, SO_TIMESTAMPNS, &on, sizeof on);
        loss_say("  connect=%d accept=%d\n", result, s2 >= 0);
        loss_send(c2, 'A', 100);
        loss_wait(c2, TOTAL, 1);
        loss_read(s2, 0, 0);
        loss_lift(s2);
        loss_poll(s2, POLLIN);
        loss_read(s2, 190, 0);
        close(c2);
        close(s2);
        close(other);
        break;
    }
    case 10:
        /* Data after the other side's close: its reset is dropped too. */
        LOSS(c, loss_reset);
        close(s);
        loss_poll(c, POLLIN);
        loss_read(c, 0, 0);
        loss_send(c, 'A', 5);
        loss_error(c);
        loss_wait(c, TOTAL, 1);
        loss_error(c);
        loss_lift(c);
        {
            struct pollfd p = {c, 0, 0};
            poll(&p, 1, LOSS_WATCHDOG);
        }
        loss_error(c);
        loss_send(c, 'B', 5);
        break;
    }
}
/* Every line is decided by counts and conditions; what a timer could have
   changed before it was seen is told by a count past the one it waits for,
   and the step is then done again. */
/* A try that goes on past twice the watchdog is stuck in a call that does
   not return: it says where, with what it saw so far, and the run ends. */
static char loss_where[64];
static void loss_stuck(int signal) {
    (void)signal;
    fflush(stdout);
    if (write(1, loss_where, strlen(loss_where)) < 0 || write(1, loss_out, loss_len) < 0) _exit(2);
    _exit(1);
}
static void lost(int l, int port) {
    int result, on = 1;
    signal(SIGALRM, loss_stuck);
    for (int step = 0; step < 11; step++) {
        /* Tries again only while the watchdog allows: a step that misses
           each time gives up, with what it saw the last time. */
        long long end = clock_ms(CLOCK_MONOTONIC) + LOSS_WATCHDOG;
        for (int tries = 0; tries < 50; tries++) {
            loss_len = loss_again = 0;
            snprintf(loss_where, sizeof loss_where, " step %d stuck on try %d\n", step, tries);
            alarm(2 * LOSS_WATCHDOG / 1000);
            int c = fresh_client(port, &result);
            loss_say("  connect=%d\n", result);
            int s = accept(l, NULL, NULL);
            loss_say("  accepted\n");
            loss_len = 0;
            setsockopt(s, SOL_SOCKET, SO_TIMESTAMPNS, &on, sizeof on);
            setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
            loss_start = clock_ms(CLOCK_MONOTONIC);
            loss_step(step, c, s);
            close(c);
            if (step != 7 && step != 10) close(s);
            alarm(0);
            if (loss_again && tries < 49 && clock_ms(CLOCK_MONOTONIC) < end) continue;
            printf(" step %d%s\n%s", step, loss_again ? " given up" : "", loss_out);
            break;
        }
    }
}
/* tcp-handshake: filters on a handshake's last acknowledgement, which its
   listener's filter sees, and on its SYN-ACK, which the client's sees. */
static struct sock_filter loss_synack[] = {{BPF_LD | BPF_B | BPF_ABS, 0, 0, 13}, {BPF_JMP | BPF_JSET | BPF_K, 0, 1, 2},
                                           LOSS_DROP, LOSS_KEEP};
/* A bare acknowledgement; all but a SYN. */
static struct sock_filter loss_bare[] = {{BPF_LD | BPF_B | BPF_ABS, 0, 0, 13}, {BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0x10},
                                         LOSS_DROP, LOSS_KEEP};
static struct sock_filter loss_late[] = {{BPF_LD | BPF_B | BPF_ABS, 0, 0, 13}, {BPF_JMP | BPF_JSET | BPF_K, 1, 0, 2},
                                         LOSS_DROP, LOSS_KEEP};
static int loss_accept(int l) {
    int s = accept4(l, NULL, NULL, SOCK_NONBLOCK);
    loss_say("  accept=%d errno=%d\n", s >= 0 ? 0 : -1, s >= 0 ? 0 : errno);
    return s;
}
/* Both sides, once `in` segments have come to the client, and not yet one
   more, as a SYN-ACK that went again is. */
static void shake_both(int c, int s, unsigned in) {
    loss_wait(c, 140, in);
    static const int sent[] = {24, 80, 100, 136, 140, 156, 192, -120, -200, 0};
    static const int came[] = {100, 136, 140, 152, 192, -128, 0};
    loss_info("client", c, sent);
    if (s >= 0) loss_info("server", s, came);
    loss_again |= loss_word(c, 140) != in;
}
/* What `sock_diag` tells of the requests (`TCP_SYN_RECV`) of `port`. */
static void shake_requests(int port) {
    struct {
        unsigned len;
        unsigned short type, flags;
        unsigned seq, pid;
        unsigned char family, protocol, ext, pad;
        unsigned states, id[12];
    } ask = {sizeof ask, 20 /* SOCK_DIAG_BY_FAMILY */, 0x301 /* NLM_F_REQUEST | NLM_F_DUMP */, 1, 0, AF_INET,
             IPPROTO_TCP, 0, 0, 1 << 3, {0}};
    int fd = socket(16 /* AF_NETLINK */, SOCK_RAW, 4 /* NETLINK_SOCK_DIAG */), found = 0;
    if (send(fd, &ask, sizeof ask, 0) != sizeof ask) loss_say("  diag errno=%d\n", errno);
    for (int done = 0; !done;) {
        static unsigned char in[16384] __attribute__((aligned(8)));
        int got = recv(fd, in, sizeof in, 0);
        if (got <= 0) break;
        for (int at = 0; at + 16 <= got;) {
            unsigned *header = (unsigned *)(in + at), *tail = header + 4 + 13;
            unsigned char *body = in + at + 16;
            unsigned short type = header[1] & 0xffff;
            if (type != 20) {
                done = 1;
                break;
            }
            if ((body[4] << 8 | body[5]) == port) {
                found++;
                loss_say("  request state=%d timer=%d retrans=%d expires=%d queues=%u,%u uid=%u inode=%u\n", body[1], body[2],
                         body[3], (int)tail[0] > 0 && (int)tail[0] <= (1000 << body[3]) + 20, tail[1], tail[2], tail[3],
                         tail[4]);
            }
            at += (header[0] + 3) & ~3u;
        }
    }
    close(fd);
    loss_say("  requests=%d\n", found);
}
static void shake_step(int step, int l, int port) {
    int result, c, s;
    switch (step) {
    case 0:
        /* Connected for the client alone, until data comes. */
        LOSS(l, loss_bare);
        c = fresh_client(port, &result);
        loss_say("  connect=%d\n", result);
        loss_accept(l);
        shake_both(c, -1, 1);
        loss_send(c, 'A', 5);
        loss_wait(c, UNACKED, 0);
        s = loss_accept(l);
        shake_both(c, s, 2);
        loss_read(s, 0, 0);
        close(s);
        close(c);
        break;
    case 1:
        /* The SYN-ACK goes again, and its answer is dropped too; lifted,
           the next one's is not. */
        LOSS(l, loss_bare);
        c = fresh_client(port, &result);
        loss_wait(c, 140, 2);
        loss_accept(l);
        shake_both(c, -1, 2);
        loss_lift(l);
        loss_again |= loss_word(c, 140) != 2;
        loss_poll(l, POLLIN);
        s = loss_accept(l);
        loss_wait(s, 140, 2);
        shake_both(c, s, 3);
        loss_send(c, 'A', 5);
        loss_wait(s, RECEIVED, 5);
        loss_wait(c, UNACKED, 0);
        shake_both(c, s, 4);
        close(s);
        close(c);
        break;
    case 2:
        /* An end opens it too. */
        LOSS(l, loss_bare);
        c = fresh_client(port, &result);
        loss_accept(l);
        shutdown(c, SHUT_WR);
        loss_wait(c, UNACKED, 0);
        s = loss_accept(l);
        loss_read(s, 0, 0);
        shake_both(c, s, 2);
        close(s);
        close(c);
        break;
    case 3: {
        /* A reset drops the request: there is nothing to accept. */
        struct linger now = {1, 0};
        LOSS(l, loss_bare);
        c = fresh_client(port, &result);
        setsockopt(c, SOL_SOCKET, SO_LINGER, &now, sizeof now);
        close(c);
        loss_lift(l);
        /* A connection after it is the first. */
        c = fresh_client(port, &result);
        loss_poll(l, POLLIN);
        s = loss_accept(l);
        loss_accept(l);
        loss_send(c, 'B', 5);
        loss_wait(s, RECEIVED, 5);
        loss_read(s, 0, 0);
        close(s);
        close(c);
        break;
    }
    case 4: {
        /* Data the listener's filter drops opens nothing, and goes again. */
        LOSS(l, loss_late);
        c = fresh_client(port, &result);
        loss_say("  connect=%d\n", result);
        loss_send(c, 'A', 5);
        loss_wait(c, TOTAL, 1);
        loss_accept(l);
        loss_lift(l);
        loss_poll(l, POLLIN);
        s = loss_accept(l);
        /* What opened it, the data or the answer to a SYN-ACK that went
           again, depends on when. */
        loss_wait(s, RECEIVED, 5);
        loss_say("  data segments=%u\n", loss_word(s, 152));
        loss_read(s, 0, 0);
        close(s);
        close(c);
        break;
    }
    case 5: {
        /* The listener gone, what comes is answered with a reset. */
        int port2, other = fresh_listener(&port2);
        LOSS(other, loss_late);
        c = fresh_client(port2, &result);
        close(other);
        loss_send(c, 'A', 5);
        loss_poll(c, 0);
        loss_error(c);
        close(c);
        break;
    }
    case 6: {
        /* The SYN-ACK dropped: the client goes on trying. */
        struct sockaddr_in a = fresh_to(port);
        c = tcp(SOCK_NONBLOCK);
        LOSS(c, loss_synack);
        loss_say("  connect=%d", connect(c, (void *)&a, sizeof a));
        loss_say(" errno=%d\n", errno);
        loss_wait(c, TOTAL, 1);
        loss_accept(l);
        loss_lift(c);
        loss_poll(c, POLLOUT);
        loss_error(c);
        loss_poll(l, POLLIN);
        s = loss_accept(l);
        loss_send(c, 'A', 5);
        loss_wait(s, RECEIVED, 5);
        loss_read(s, 0, 0);
        close(s);
        close(c);
        break;
    }
    case 7:
        /* The request, before and after its SYN-ACK goes again. */
        LOSS(l, loss_bare);
        c = fresh_client(port, &result);
        shake_requests(port);
        loss_again |= loss_word(c, 140) != 1;
        loss_wait(c, 140, 2);
        shake_requests(port);
        loss_again |= loss_word(c, 140) != 2;
        loss_lift(l);
        loss_poll(l, POLLIN);
        shake_requests(port);
        s = loss_accept(l);
        close(s);
        close(c);
        break;
    case 8: {
        /* A thread in accept is all that waits for the SYN-ACK to go again,
           and then for a SYN that does. */
        struct timeval most = {10, 0};
        setsockopt(l, SOL_SOCKET, SO_RCVTIMEO, &most, sizeof most);
        fcntl(l, F_SETFL, 0);
        LOSS(l, loss_bare);
        c = fresh_client(port, &result);
        loss_lift(l);
        s = accept(l, NULL, NULL);
        loss_say("  connect=%d accept=%d\n", result, s >= 0);
        close(s);
        close(c);
        struct sockaddr_in a = fresh_to(port);
        c = tcp(SOCK_NONBLOCK);
        LOSS(c, loss_synack);
        loss_say("  connect=%d", connect(c, (void *)&a, sizeof a));
        loss_say(" errno=%d\n", errno);
        loss_lift(c);
        s = accept(l, NULL, NULL);
        loss_say("  accept=%d\n", s >= 0);
        close(s);
        close(c);
        break;
    }
    }
}
static void shaken(void) {
    for (int step = 0; step < 9; step++) {
        for (int tries = 0; tries < 50; tries++) {
            int port, l = fresh_listener(&port);
            fcntl(l, F_SETFL, O_NONBLOCK);
            loss_len = loss_again = 0;
            loss_start = clock_ms(CLOCK_MONOTONIC);
            shake_step(step, l, port);
            close(l);
            if (loss_again && tries < 49) continue;
            printf(" step %d%s\n%s", step, loss_again ? " given up" : "", loss_out);
            break;
        }
    }
}
/* TCP_CORK: parts of a segment wait until it is cleared, 200 ms pass, the
   end comes or TCP_NODELAY is set. A step the machine took too long for is
   done again. */
static void cork_in(const char *step, int s) {
    int in = -1;
    ioctl(s, FIONREAD, &in);
    printf("  %s in=%d\n", step, in);
}
static void cork_set(int c, int on) {
    int got = -1;
    socklen_t len = sizeof got;
    int set = setsockopt(c, IPPROTO_TCP, TCP_CORK, &on, sizeof on);
    getsockopt(c, IPPROTO_TCP, TCP_CORK, &got, &len);
    printf("  cork=%d set=%d got=%d len=%u\n", on, set, got, len);
}
static void corked(int l, int port) {
    static char bytes[70000];
    int result, on = 1, off = 0;
    call("short", setsockopt(l, IPPROTO_TCP, TCP_CORK, &on, 3));
    call("value", setsockopt(l, IPPROTO_TCP, TCP_CORK, NULL, sizeof on));
    for (int step = 0; step < 9; step++) {
        for (int tries = 0; tries < 20; tries++) {
            long long began = clock_ms(CLOCK_MONOTONIC);
            if (step == 8) setsockopt(l, IPPROTO_TCP, TCP_CORK, &on, sizeof on);
            int c = client(port, 0, &result), s = accept(l, NULL, NULL);
            setsockopt(l, IPPROTO_TCP, TCP_CORK, &off, sizeof off);
            int wait = step == 1;
            int nodelay = step == 3 || step == 4;
            if (step == 4) setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
            if (step == 6)
                for (int n = 0; n < 20; n++) send(c, bytes, 1, 0);
            if (step < 8) setsockopt(c, IPPROTO_TCP, TCP_CORK, &on, sizeof on);
            if (step != 6 && step < 8) {
                send(c, bytes, step == 5 ? 40000 : 100, 0);
                send(c, bytes, 100, 0);
            }
            if (step == 8) send(s, bytes, 10, 0);
            int in = 0;
            ioctl(step == 8 ? c : s, FIONREAD, &in);
            if (clock_ms(CLOCK_MONOTONIC) - began > 25) {
                close(c);
                close(s);
                continue;
            }
            printf(" step %d\n  in=%d\n", step, in);
            if (wait) {
                struct timespec t = {0, 400000000};
                nanosleep(&t, NULL);
                cork_in("later", s);
            } else if (step == 3) {
                setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
                cork_in("nodelay", s);
                send(c, bytes, 50, 0);
                cork_in("sent", s);
            } else if (step == 7) {
                shutdown(c, SHUT_WR);
                call("recv", recv(s, bytes, sizeof bytes, 0));
                call("recv", recv(s, bytes, sizeof bytes, 0));
            } else if (step == 8) {
                cork_set(s, 0);
                cork_in("inherited", c);
            }
            if (nodelay || step == 2) {
                send(c, bytes, 30, MSG_MORE);
                cork_in("more", s);
            }
            if (step < 7) {
                cork_set(c, 0);
                cork_in("uncorked", s);
            }
            if (step == 2 || step == 5) {
                recv(s, bytes, sizeof bytes, 0);
                cork_set(c, 1);
                send(c, bytes, 7, 0);
                cork_in("again", s);
                send(c, bytes, 70000, 0);
                recv(s, bytes, 7, 0);
                cork_set(c, 0);
            }
            close(c);
            close(s);
            break;
        }
    }
}
/* A client on a port of its own: bound to port 0 before it connects, it
   takes a port no other socket holds, where connect alone may share one
   with sockets still in TIME_WAIT towards other addresses (Linux's
   __inet_hash_connect), so that a bind there fails whatever this one left.
   No other connect takes the port while it is held. */
static int own_port_client(int port, int *result) {
    int fd = tcp(0);
    struct sockaddr_in any = to(0);
    if (bind(fd, (void *)&any, sizeof any)) {
        printf("bind failed errno=%d\n", errno);
        exit(72);
    }
    struct sockaddr_in a = to(port);
    errno = 0;
    *result = connect(fd, (void *)&a, sizeof a) ? errno : 0;
    return fd;
}
static void bind_to(const char *name, int fd, in_addr_t addr, int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    a.sin_addr.s_addr = addr;
    call(name, bind(fd, (void *)&a, sizeof a));
}
static int port_of(int fd) {
    struct sockaddr_in6 a;
    socklen_t len = sizeof a;
    getsockname(fd, (void *)&a, &len);
    return ntohs(a.sin6_port);
}
/* Whether /proc/net/udp or udp6 lists a socket bound to `port`. Native
   Linux lists every UDP socket in the runner's network, the other cases'
   included; the emulator has neither file, so nothing is listed there. */
static int udp_port_held(int port) {
    const char *paths[] = {"/proc/net/udp", "/proc/net/udp6"};
    for (int i = 0; i < 2; i++) {
        FILE *f = fopen(paths[i], "r");
        if (!f) continue;
        char line[512];
        unsigned local;
        int held = 0;
        while (!held && fgets(line, sizeof line, f))
            held = sscanf(line, " %*d: %*[0-9A-Fa-f]:%x", &local) == 1 && (int)local == port;
        fclose(f);
        if (held) return 1;
    }
    return 0;
}
/* Milliseconds on the monotonic clock. */
static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
/* Waits up to `limit` ms for `fd` to finish connecting, and prints how it
   ended and the nearest whole second after `start` (Linux's timers run a
   little late). */
static void finished(const char *name, int fd, long start, int limit) {
    struct pollfd p = {.fd = fd, .events = POLLOUT};
    int n = poll(&p, 1, limit);
    int error = 0;
    socklen_t len = sizeof error;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
    printf("  %s poll=%d revents=%#x error=%d second=%ld\n", name, n, (unsigned)p.revents, error,
           (now_ms() - start + 500) / 1000);
}
static volatile sig_atomic_t pipes;
static void on_pipe(int signal) { (void)signal; pipes++; }
static volatile sig_atomic_t urgs;
static void on_urg(int signal) { (void)signal; urgs++; }
/* A loopback connection to `port`, accepted from `l`: the server's side is
   nonblocking and owned by this process, for SIGURG. */
static void urgent_pair(int l, int port, int *c, int *s) {
    int result;
    *c = client(port, 0, &result);
    *s = accept(l, NULL, NULL);
    fcntl(*s, F_SETFL, O_NONBLOCK);
    fcntl(*s, F_SETOWN, getpid());
}
/* What an urgent byte shows: POLLIN and POLLPRI, SIOCATMARK, FIONREAD and
   the SIGURGs so far. */
static void urgent_state(const char *name, int fd) {
    struct pollfd p = {.fd = fd, .events = POLLIN | POLLPRI};
    poll(&p, 1, 0);
    int mark = -1, inq = -1;
    ioctl(fd, SIOCATMARK, &mark);
    ioctl(fd, FIONREAD, &inq);
    printf("  %s revents=%#x atmark=%d inq=%d urgs=%d\n", name, (unsigned)p.revents, mark, inq,
           (int)urgs);
}
static void urgent_read(const char *name, int fd, int len, int flags) {
    char b[64];
    errno = 0;
    long r = recv(fd, b, len, flags);
    printf("  %s r=%ld errno=%d data=%.*s\n", name, r, r < 0 ? errno : 0, r > 0 ? (int)r : 0, b);
}
/* Sends from `fd` until neither its buffer nor the peer's takes more, looking
   again after a pause, as the loopback's acknowledgments can trail the send
   that found no room. Returns how many bytes went. */
static long fill(int fd) {
    static char chunk[65536];
    long total = 0, n;
    for (;;) {
        long sent = 0;
        while ((n = send(fd, chunk, sizeof chunk, MSG_DONTWAIT)) > 0) sent += n;
        if (!sent && total) return total;
        total += sent;
        usleep(50000);
    }
}
/* Reads `fd` to its end, waiting up to 5 seconds for each part. Returns how
   many bytes came. */
static long drain(int fd) {
    static char chunk[65536];
    struct pollfd p = {.fd = fd, .events = POLLIN};
    long total = 0, n;
    while (poll(&p, 1, 5000) > 0 && (n = recv(fd, chunk, sizeof chunk, 0)) > 0) total += n;
    return total;
}
/* The whole seconds since `start`, to the nearest. */
static long seconds_since(long start) { return (now_ms() - start + 500) / 1000; }
/* The peer a thread drains after 300 ms, with the bytes it is to get. */
static int drained_fd;
static long drained_expected;
static void *drain_later(void *arg) {
    (void)arg;
    usleep(300000);
    return (void *)(long)(drain(drained_fd) == drained_expected);
}
static volatile sig_atomic_t alarms;
/* udp-timestamp: the option numbers, as x86-64 Linux has them. */
#define TS_OLD 29
#define TS_NS_OLD 35
#define TS_NEW 63
#define TS_NS_NEW 64
#define TSG_OLD 37
#define TSG_NEW 65
static long long real_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}
/* The six timestamp options as getsockopt reads them: an int each for
   SO_TIMESTAMP's four forms, the flags and PTP clock for SO_TIMESTAMPING's
   two. */
static void stamp_options(const char *name, int fd) {
    const int names[] = {TS_OLD, TS_NS_OLD, TS_NEW, TS_NS_NEW, TSG_OLD, TSG_NEW};
    printf("  %s:", name);
    for (int i = 0; i < 6; i++) {
        int got[2] = {-7, -7};
        socklen_t len = sizeof got;
        int r = getsockopt(fd, SOL_SOCKET, names[i], got, &len);
        if (i < 4)
            printf(" %d/%d", r ? -errno : got[0], (int)len);
        else
            printf(" %#x,%d/%d", r ? -errno : got[0], got[1], (int)len);
    }
    printf("\n");
}
static void stamp_option(const char *name, int fd, int opt, int value) {
    errno = 0;
    int r = setsockopt(fd, SOL_SOCKET, opt, &value, sizeof value);
    printf("  set %s %#x=%d errno=%d\n", name, value, r, r ? errno : 0);
}
/* tcp-timestamp: recvmsg of at most `len` bytes with `room` bytes of
   control and `flags`: what came, MSG_CTRUNC, msg_controllen, and each
   control message's type and length, and for a timestamp whether it is
   from `from` on and from before this call. */
static void tcp_stamped(const char *name, int fd, size_t len, size_t room, int flags, long long from) {
    char data[8] = {0};
    union { char bytes[256]; struct cmsghdr align; } control;
    memset(control.bytes, 0, sizeof control.bytes);
    struct iovec iov = {data, len};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
                             .msg_control = room ? control.bytes : NULL, .msg_controllen = room};
    long long asked = real_ns();
    errno = 0;
    long n = recvmsg(fd, &message, flags);
    printf("  %s=%ld errno=%d data=%.*s ctrunc=%d controllen=%zu", name, n, n < 0 ? errno : 0,
           n > 0 ? (int)n : 0, data, n >= 0 && (message.msg_flags & MSG_CTRUNC) != 0,
           n >= 0 ? (size_t)message.msg_controllen : 0);
    if (n >= 0 && room)
        for (struct cmsghdr *h = CMSG_FIRSTHDR(&message); h; h = CMSG_NXTHDR(&message, h)) {
            printf(" [%d len=%zu", h->cmsg_type, (size_t)h->cmsg_len);
            int ts = h->cmsg_type == TS_OLD || h->cmsg_type == TS_NEW;
            if (h->cmsg_len >= CMSG_LEN(16)) {
                long long v[2];
                memcpy(v, CMSG_DATA(h), sizeof v);
                long long unit = ts ? 1000 : 1, at = (v[0] * 1000000000LL + v[1] * unit) / unit;
                printf(" late=%d early=%d", at >= from / unit, at < asked / unit);
            }
            printf("]");
        }
    printf("\n");
}
/* recvmsg with `room` bytes of control (none at all for 0) and `flags`:
   what came, MSG_CTRUNC, msg_controllen, and each control message's type
   and length, and for a timestamp where it falls against the real times
   `sent` (taken after the send) and `asked` (before this call). */
static void receive_stamped(const char *name, int fd, size_t room, int flags, long long sent) {
    char data[8] = {0};
    union { char bytes[256]; struct cmsghdr align; } control;
    memset(control.bytes, 0, sizeof control.bytes);
    struct iovec iov = {data, sizeof data};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
                             .msg_control = room ? control.bytes : NULL, .msg_controllen = room};
    long long asked = real_ns();
    errno = 0;
    long n = recvmsg(fd, &message, flags);
    printf("  %s=%ld errno=%d ctrunc=%d controllen=%zu", name, n, n < 0 ? errno : 0,
           n >= 0 && (message.msg_flags & MSG_CTRUNC) != 0, n >= 0 ? (size_t)message.msg_controllen : 0);
    if (n >= 0 && room)
        for (struct cmsghdr *h = CMSG_FIRSTHDR(&message); h; h = CMSG_NXTHDR(&message, h)) {
            printf(" [%d len=%zu", h->cmsg_type, (size_t)h->cmsg_len);
            int ts = h->cmsg_type == TS_OLD || h->cmsg_type == TS_NEW;
            int any = ts || h->cmsg_type == TS_NS_OLD || h->cmsg_type == TS_NS_NEW ||
                      h->cmsg_type == TSG_OLD || h->cmsg_type == TSG_NEW;
            if (any && h->cmsg_len >= CMSG_LEN(16)) {
                long long v[6] = {0};
                memcpy(v, CMSG_DATA(h), h->cmsg_len >= CMSG_LEN(48) ? 48 : 16);
                /* A timeval holds microseconds: compare in them. */
                long long unit = ts ? 1000 : 1, at = v[0] * 1000000000LL + v[1] * unit;
                long long a = at / unit, s = sent / unit, q = asked / unit;
                printf(" %s fits=%d", a <= s ? "sent" : a >= q ? "read" : "between",
                       v[1] >= 0 && v[1] < 1000000000LL / unit);
                if (h->cmsg_len >= CMSG_LEN(48)) printf(" rest=%d", !(v[2] | v[3] | v[4] | v[5]));
            }
            printf("]");
        }
    printf("\n");
}
/* Landlock (ABI 4): a ruleset of TCP rights, a rule on a port, enforcing. */
static long ll_ruleset(unsigned long long net) {
    unsigned long long attr[2] = {0, net};
    return syscall(444, attr, sizeof attr, 0);
}
static long ll_port(long ruleset, unsigned long long port, unsigned long long allowed) {
    unsigned long long rule[2] = {allowed, port};
    return syscall(445, ruleset, 2, rule, 0);
}
/* bind of a new socket of `domain` and `type` to `address`. */
static void ll_bind(const char *name, int domain, int type, const void *address, socklen_t len) {
    int s = socket(domain, type | SOCK_CLOEXEC, 0);
    call(name, bind(s, address, len));
    close(s);
}
static void on_alarm(int signal) { (void)signal; alarms++; }
/* A ring of 8 entries (io_uring_setup) with its rings and entries mapped,
   for the io_uring mode. */
struct ring {
    int fd;
    unsigned char *rings, *sqes;
    unsigned array, sq_entries, cq_entries;
};
static unsigned *ring_u32(unsigned char *base, unsigned at) { return (unsigned *)(base + at); }
static int ring_open(struct ring *r) {
    unsigned char p[120];
    memset(p, 0, sizeof p);
    long fd = syscall(425, 8, p);
    if (fd < 0) return -1;
    r->fd = (int)fd;
    r->sq_entries = *ring_u32(p, 0);
    r->cq_entries = *ring_u32(p, 4);
    r->array = *ring_u32(p, 64);
    r->rings = mmap(NULL, r->array + 4 * r->sq_entries, PROT_READ | PROT_WRITE, MAP_SHARED, r->fd, 0);
    r->sqes = mmap(NULL, 64 * r->sq_entries, PROT_READ | PROT_WRITE, MAP_SHARED, r->fd, 0x10000000);
    return r->rings == MAP_FAILED || r->sqes == MAP_FAILED ? -1 : 0;
}
/* Waits for any of `events` on `fd`, at most 5 s. */
static void awaited(const char *name, int fd, short events) {
    struct pollfd p = {.fd = fd, .events = events};
    int n = poll(&p, 1, 5000);
    printf("  %s poll=%d\n", name, n);
}
/* An entry: `op` on `fd` with `off`, `addr`, `len` and `rw` flags. */
static void ring_push(struct ring *r, unsigned char op, unsigned long data, int fd, unsigned long off,
                      unsigned long addr, unsigned len, unsigned rw) {
    unsigned tail = *ring_u32(r->rings, 4);
    unsigned slot = tail & (r->sq_entries - 1);
    unsigned char *sqe = r->sqes + 64 * slot;
    memset(sqe, 0, 64);
    sqe[0] = op;
    memcpy(sqe + 4, &fd, 4);
    memcpy(sqe + 8, &off, 8);
    memcpy(sqe + 16, &addr, 8);
    memcpy(sqe + 24, &len, 4);
    memcpy(sqe + 28, &rw, 4);
    memcpy(sqe + 32, &data, 8);
    *ring_u32(r->rings, r->array + 4 * slot) = slot;
    __atomic_store_n(ring_u32(r->rings, 4), tail + 1, __ATOMIC_RELEASE);
}
/* The last result of each user_data. */
static int ring_result[64];
/* Submits `submit` entries, waits for `wait` completions, and prints
   those there, by user_data, with their flags; with `fds`, a descriptor
   as "fd". It gives the result of the last one printed. */
static int ring_run(struct ring *r, unsigned submit, unsigned wait, const char *label, int fds) {
    syscall(426, r->fd, submit, wait, 1, NULL, 0);
    unsigned head = *ring_u32(r->rings, 8);
    unsigned tail = __atomic_load_n(ring_u32(r->rings, 12), __ATOMIC_ACQUIRE);
    unsigned long datas[8];
    int results[8];
    unsigned flags[8], n = 0;
    for (; head != tail && n < 8; head++, n++) {
        unsigned char *cqe = r->rings + 64 + 16 * (head & (r->cq_entries - 1));
        memcpy(&datas[n], cqe, 8);
        memcpy(&results[n], cqe + 8, 4);
        memcpy(&flags[n], cqe + 12, 4);
    }
    __atomic_store_n(ring_u32(r->rings, 8), head, __ATOMIC_RELEASE);
    printf("  %s:", label);
    int last = 0;
    for (unsigned long data = 0; data < 64; data++) {
        for (unsigned i = 0; i < n; i++) {
            if (datas[i] != data) continue;
            if (fds && results[i] > 2)
                printf(" %lu=fd/%#x", data, flags[i]);
            else
                printf(" %lu=%d/%#x", data, results[i], flags[i]);
            last = ring_result[data] = results[i];
        }
    }
    printf("\n");
    return last;
}

/* A classic filter on a TCP socket needs CAP_NET_ADMIN over its network,
   which no one has over the first one from a user namespace of their own,
   whoever ran this; a UDP socket takes one. The filters are then on sockets
   of that namespace's own network, its loopback up. */
static void filter_network(void) {
    int first = tcp(0), datagram = socket(AF_INET, SOCK_DGRAM, 0);
    struct sock_fprog keep = {1, (struct sock_filter[]){LOSS_KEEP}};
    call("unshare-user", unshare(CLONE_NEWUSER));
    call("attach-first", setsockopt(first, SOL_SOCKET, SO_ATTACH_FILTER, &keep, sizeof keep));
    call("attach-udp", setsockopt(datagram, SOL_SOCKET, SO_ATTACH_FILTER, &keep, sizeof keep));
    close(first);
    close(datagram);
    call("unshare-net", unshare(CLONE_NEWNET));
    int control = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq up = {.ifr_name = "lo", .ifr_flags = IFF_UP};
    call("lo-up", ioctl(control, SIOCSIFFLAGS, &up));
    close(control);
    int own = tcp(0);
    call("attach-own", setsockopt(own, SOL_SOCKET, SO_ATTACH_FILTER, &keep, sizeof keep));
    close(own);
}

int main(int argc, char **argv) {
    if (argc < 4) return 99;
    const char *mode = argv[1];
    open_port = atoi(argv[2]);
    closed_port = atoi(argv[3]);
    setvbuf(stdout, NULL, _IONBF, 0);
    char buf[256];
    long n;

    if (!strcmp(mode, "unconnected")) {
        /* A TCP socket that never connected, and its options. */
        int fd = tcp(0);
        call("recv", recv(fd, buf, sizeof buf, MSG_DONTWAIT));
        call("send", send(fd, "x", 1, MSG_NOSIGNAL));
        polled("fresh", fd, POLLIN | POLLOUT | POLLRDHUP);
        struct sockaddr_in a;
        socklen_t len = sizeof a;
        call("getpeername", getpeername(fd, (void *)&a, &len));
        memset(&a, 0x55, sizeof a);
        len = sizeof a;
        call("getsockname", getsockname(fd, (void *)&a, &len));
        printf("  family=%d port=%d addr=%#x len=%u\n", a.sin_family, ntohs(a.sin_port),
               ntohl(a.sin_addr.s_addr), (unsigned)len);
        call("shutdown", shutdown(fd, SHUT_WR));
        call("shutdown-bad", shutdown(fd, 7));
        call("accept", accept(fd, NULL, NULL));
        struct sockaddr_in any = {.sin_family = AF_INET};
        call("bind-0", bind(fd, (void *)&any, sizeof any));
        option("type", fd, SOL_SOCKET, SO_TYPE);
        option("domain", fd, SOL_SOCKET, SO_DOMAIN);
        option("protocol", fd, SOL_SOCKET, SO_PROTOCOL);
        option("error", fd, SOL_SOCKET, SO_ERROR);
        option("acceptconn", fd, SOL_SOCKET, SO_ACCEPTCONN);
        option("nodelay", fd, IPPROTO_TCP, TCP_NODELAY);
        set_option("nodelay", fd, IPPROTO_TCP, TCP_NODELAY, 1);
        option("keepalive", fd, SOL_SOCKET, SO_KEEPALIVE);
        set_option("keepalive", fd, SOL_SOCKET, SO_KEEPALIVE, 5);
        set_option("reuseaddr", fd, SOL_SOCKET, SO_REUSEADDR, 1);
        option("keepidle", fd, IPPROTO_TCP, TCP_KEEPIDLE);
        option("keepintvl", fd, IPPROTO_TCP, TCP_KEEPINTVL);
        option("keepcnt", fd, IPPROTO_TCP, TCP_KEEPCNT);
        set_option("keepidle", fd, IPPROTO_TCP, TCP_KEEPIDLE, 60);
        set_option("keepidle-0", fd, IPPROTO_TCP, TCP_KEEPIDLE, 0);
        set_option("keepintvl", fd, IPPROTO_TCP, TCP_KEEPINTVL, 10);
        set_option("keepcnt", fd, IPPROTO_TCP, TCP_KEEPCNT, 3);
        set_option("keepcnt-200", fd, IPPROTO_TCP, TCP_KEEPCNT, 200);
        option("unknown", fd, SOL_SOCKET, 9999);
        option("tcp-unknown", fd, IPPROTO_TCP, 9999);
        char small = 0;
        errno = 0;
        n = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &small, 1);
        printf("  short-option=%ld errno=%d\n", n, errno);
        struct sockaddr_in6 six = {.sin6_family = AF_INET6};
        call("connect-family", connect(fd, (void *)&six, sizeof six));
        a = to(open_port);
        call("connect-short", connect(fd, (void *)&a, 8));
        close(fd);
        puts("kinds");
        call("udp-as-tcp", socket(AF_INET, SOCK_STREAM, IPPROTO_UDP));
        call("bad-flags", socket(AF_INET, SOCK_STREAM | 0x100000, 0));
        int u = socket(AF_INET, SOCK_DGRAM, 0);
        option("udp-type", u, SOL_SOCKET, SO_TYPE);
        option("udp-protocol", u, SOL_SOCKET, SO_PROTOCOL);
        option("udp-nodelay", u, IPPROTO_TCP, TCP_NODELAY);
        set_option("udp-nodelay", u, IPPROTO_TCP, TCP_NODELAY, 1);
        option("udp-unknown", u, IPPROTO_UDP, 9999);
        int six_fd = socket(AF_INET6, SOCK_STREAM, 0);
        option("v6-domain", six_fd, SOL_SOCKET, SO_DOMAIN);
        option("v6only", six_fd, IPPROTO_IPV6, IPV6_V6ONLY);
        set_option("v6-tos", six_fd, IPPROTO_IP, IP_TOS, 0x10);
        option("v4-v6only", u, IPPROTO_IPV6, IPV6_V6ONLY);
        close(six_fd);
        close(u);
        return 0;
    }
    if (!strcmp(mode, "stream")) {
        /* A blocking connection: addresses, echo, half-close, end. */
        int fd = connected('e');
        struct sockaddr_in a;
        socklen_t len = sizeof a;
        call("getpeername", getpeername(fd, (void *)&a, &len));
        printf("  family=%d port-ok=%d addr=%#x len=%u\n", a.sin_family,
               ntohs(a.sin_port) == open_port, ntohl(a.sin_addr.s_addr), (unsigned)len);
        len = sizeof a;
        call("getsockname", getsockname(fd, (void *)&a, &len));
        printf("  family=%d addr=%#x has-port=%d len=%u\n", a.sin_family, ntohl(a.sin_addr.s_addr),
               a.sin_port != 0, (unsigned)len);
        a = to(open_port);
        call("connect-again", connect(fd, (void *)&a, sizeof a));
        polled("writable", fd, POLLOUT);
        call("send", send(fd, "hello", 5, 0));
        call("write", write(fd, " world", 6));
        call("shutdown", shutdown(fd, SHUT_WR));
        await_end(fd);
        int queued = -1;
        call("fionread", ioctl(fd, FIONREAD, &queued));
        printf("  queued=%d\n", queued);
        n = recv(fd, buf, 2, MSG_PEEK);
        print_bytes("peek", buf, n);
        n = recv(fd, buf, 11, MSG_WAITALL);
        print_bytes("waitall", buf, n);
        call("end", recv(fd, buf, sizeof buf, 0));
        polled("ended", fd, POLLIN | POLLOUT | POLLRDHUP);
        signal(SIGPIPE, on_pipe);
        call("send-after-shutdown", send(fd, "x", 1, 0));
        printf("  sigpipes=%d\n", (int)pipes);
        call("send-nosignal", send(fd, "x", 1, MSG_NOSIGNAL));
        printf("  sigpipes=%d\n", (int)pipes);
        close(fd);
        return 0;
    }
    if (!strcmp(mode, "nonblocking")) {
        /* connect with O_NONBLOCK: EINPROGRESS, POLLOUT, SO_ERROR, then
           EALREADY's successor 0 and EISCONN. */
        int fd = tcp(SOCK_NONBLOCK);
        struct sockaddr_in a = to(open_port);
        call("connect", connect(fd, (void *)&a, sizeof a));
        polled("connecting", fd, POLLOUT);
        option("error", fd, SOL_SOCKET, SO_ERROR);
        call("connect-2", connect(fd, (void *)&a, sizeof a));
        call("connect-3", connect(fd, (void *)&a, sizeof a));
        call("recv-empty", recv(fd, buf, sizeof buf, 0));
        call("send-command", send(fd, "c", 1, 0));
        await_end(fd);
        polled("closed-by-peer", fd, POLLIN | POLLOUT | POLLRDHUP);
        call("recv-end", recv(fd, buf, sizeof buf, 0));
        close(fd);
        /* select and epoll see a connection become writable, then
           readable. */
        fd = tcp(SOCK_NONBLOCK);
        connect(fd, (void *)&a, sizeof a);
        fd_set writable;
        FD_ZERO(&writable);
        FD_SET(fd, &writable);
        struct timeval wait = {5, 0};
        n = select(fd + 1, NULL, &writable, NULL, &wait);
        printf("  select=%ld writable=%d\n", n, FD_ISSET(fd, &writable));
        int ep = epoll_create1(0);
        struct epoll_event e = {.events = EPOLLIN, .data.fd = fd}, got;
        epoll_ctl(ep, EPOLL_CTL_ADD, fd, &e);
        call("epoll-idle", epoll_wait(ep, &got, 1, 0));
        send(fd, "e", 1, 0);
        send(fd, "ping", 4, 0);
        n = epoll_wait(ep, &got, 1, 5000);
        printf("  epoll=%ld events=%#x\n", n, got.events);
        n = recv(fd, buf, sizeof buf, 0);
        print_bytes("recv", buf, n);
        call("recv-again", recv(fd, buf, sizeof buf, 0));
        close(ep);
        close(fd);
        return 0;
    }
    if (!strcmp(mode, "landlock")) {
        /* Landlock's TCP rights: bind and connect need a rule on the port,
           checked after the address's length and family. */
        enum { BIND = 1, CONNECT = 2 };
        int probe = tcp(0);
        struct sockaddr_in here = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        socklen_t len = sizeof here;
        bind(probe, (void *)&here, sizeof here);
        getsockname(probe, (void *)&here, &len);
        close(probe);
        int free_port = ntohs(here.sin_port);
        long r = ll_ruleset(BIND | CONNECT);
        call("port", ll_port(r, open_port, CONNECT));
        call("port-bind", ll_port(r, free_port, BIND));
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        call("enforce", syscall(446, r, 0));
        close(r);
        int fd = tcp(0);
        struct sockaddr_in a = to(open_port);
        call("connect-allowed", connect(fd, (void *)&a, sizeof a));
        close(fd);
        fd = tcp(0);
        a = to(closed_port);
        call("connect-denied", connect(fd, (void *)&a, sizeof a));
        struct sockaddr unspec = {.sa_family = AF_UNSPEC};
        call("connect-unspec", connect(fd, &unspec, sizeof unspec));
        call("connect-short", connect(fd, (void *)&a, 8));
        call("connect-tiny", connect(fd, (void *)&a, 1));
        close(fd);
        here.sin_port = htons(free_port);
        ll_bind("bind-allowed", AF_INET, SOCK_STREAM, &here, sizeof here);
        here.sin_port = 0;
        ll_bind("bind-any-port", AF_INET, SOCK_STREAM, &here, sizeof here);
        here.sin_port = htons(closed_port);
        ll_bind("bind-denied", AF_INET, SOCK_STREAM, &here, sizeof here);
        ll_bind("bind-udp", AF_INET, SOCK_DGRAM, &here, sizeof here);
        /* AF_UNSPEC binds as AF_INET only with the unspecified address. */
        struct sockaddr_in unspec_any = {.sin_family = AF_UNSPEC, .sin_port = htons(free_port)};
        ll_bind("bind-unspec-any", AF_INET, SOCK_STREAM, &unspec_any, sizeof unspec_any);
        unspec_any.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ll_bind("bind-unspec-loopback", AF_INET, SOCK_STREAM, &unspec_any, sizeof unspec_any);
        ll_bind("bind-unspec-short", AF_INET, SOCK_STREAM, &unspec_any, 8);
        /* IPv6: AF_UNSPEC never binds, and another family is EINVAL. */
        struct sockaddr_in6 six = {.sin6_family = AF_UNSPEC};
        ll_bind("bind6-unspec", AF_INET6, SOCK_STREAM, &six, sizeof six);
        ll_bind("bind6-unspec-short", AF_INET6, SOCK_STREAM, &six, 16);
        six.sin6_family = AF_INET6;
        six.sin6_port = htons(closed_port);
        ll_bind("bind6-denied", AF_INET6, SOCK_STREAM, &six, sizeof six);
        ll_bind("bind6-inet", AF_INET6, SOCK_STREAM, &here, sizeof here);
        /* A family Landlock does not know is the protocol's to refuse. */
        struct sockaddr unknown = {.sa_family = AF_UNIX};
        ll_bind("bind-unix-family", AF_INET, SOCK_STREAM, &unknown, sizeof here);
        return 0;
    }
    if (!strcmp(mode, "refused")) {
        /* Nothing listens: a blocking connect fails at once; a nonblocking
           one reports the error through poll and SO_ERROR, once. */
        int fd = tcp(0);
        struct sockaddr_in a = to(closed_port);
        call("connect", connect(fd, (void *)&a, sizeof a));
        option("error", fd, SOL_SOCKET, SO_ERROR);
        polled("after", fd, POLLIN | POLLOUT | POLLRDHUP);
        call("recv", recv(fd, buf, sizeof buf, MSG_DONTWAIT));
        close(fd);
        fd = tcp(SOCK_NONBLOCK);
        call("connect-nonblocking", connect(fd, (void *)&a, sizeof a));
        polled("failed", fd, POLLIN | POLLOUT | POLLRDHUP);
        option("error", fd, SOL_SOCKET, SO_ERROR);
        option("error-again", fd, SOL_SOCKET, SO_ERROR);
        polled("taken", fd, POLLIN | POLLOUT | POLLRDHUP);
        call("connect-again", connect(fd, (void *)&a, sizeof a));
        call("recv", recv(fd, buf, sizeof buf, 0));
        call("send", send(fd, "x", 1, MSG_NOSIGNAL));
        close(fd);
        return 0;
    }
    if (!strcmp(mode, "bulk")) {
        /* 1 MiB from the server, more than either side buffers, read in
           pieces of every size. */
        int fd = connected('b');
        unsigned long total = 0, sum = 0, wrong = 0;
        static char big[70000];
        size_t want = 1;
        while ((n = read(fd, big, want)) > 0) {
            for (long i = 0; i < n; i++, total++) {
                unsigned char expected = (unsigned char)(total * 7 + 3);
                if ((unsigned char)big[i] != expected) wrong++;
                sum += (unsigned char)big[i];
            }
            want = want * 3 % sizeof big + 1;
        }
        printf("  read=%ld total=%lu sum=%lu wrong=%lu\n", n, total, sum, wrong);
        close(fd);
        /* And 1 MiB to an echoing server, written while it echoes back. */
        fd = connected('e');
        int flags = fcntl(fd, F_GETFL);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        unsigned long sent = 0, back = 0;
        int shut = 0;
        while (back < 1 << 20) {
            struct pollfd p = {.fd = fd, .events = POLLIN | (sent < 1 << 20 ? POLLOUT : 0)};
            if (poll(&p, 1, 5000) <= 0) break;
            if (p.revents & POLLOUT) {
                size_t len = sizeof big;
                if (len > (1 << 20) - sent) len = (1 << 20) - sent;
                for (size_t i = 0; i < len; i++) big[i] = (char)(sent + i);
                n = send(fd, big, len, 0);
                if (n > 0) sent += n;
            }
            if (sent == 1 << 20 && !shut) shut = !shutdown(fd, SHUT_WR);
            if (p.revents & POLLIN) {
                char in[4096];
                n = recv(fd, in, sizeof in, 0);
                if (n <= 0) break;
                for (long i = 0; i < n; i++, back++)
                    if (in[i] != (char)back) wrong++;
            }
        }
        printf("  sent=%lu back=%lu wrong=%lu shut=%d\n", sent, back, wrong, shut);
        close(fd);
        return 0;
    }
    if (!strcmp(mode, "half")) {
        /* The server answers only once this side shuts its sending down. */
        int fd = connected('w');
        call("send", send(fd, "abc", 3, 0));
        call("shutdown", shutdown(fd, SHUT_WR));
        await_end(fd);
        n = read(fd, buf, sizeof buf);
        print_bytes("read", buf, n);
        call("end", read(fd, buf, sizeof buf));
        polled("both-shut", fd, POLLIN | POLLOUT | POLLRDHUP);
        call("shutdown-read", shutdown(fd, SHUT_RD));
        close(fd);
        /* SHUT_RD: what came stays readable, then reads end. */
        fd = connected('e');
        send(fd, "xy", 2, 0);
        polled("echoed", fd, POLLIN);
        call("shutdown-read", shutdown(fd, SHUT_RD));
        polled("read-shut", fd, POLLIN | POLLRDHUP);
        call("read-after", read(fd, buf, sizeof buf));
        close(fd);
        return 0;
    }
    if (!strcmp(mode, "mapped")) {
        /* An IPv6 socket reaches 127.0.0.1 as ::ffff:127.0.0.1. */
        int fd = socket(AF_INET6, SOCK_STREAM, 0);
        struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons(open_port)};
        inet_pton(AF_INET6, "::ffff:127.0.0.1", &a.sin6_addr);
        call("connect", connect(fd, (void *)&a, sizeof a));
        struct sockaddr_in6 peer;
        socklen_t len = sizeof peer;
        call("getpeername", getpeername(fd, (void *)&peer, &len));
        char text[64];
        inet_ntop(AF_INET6, &peer.sin6_addr, text, sizeof text);
        printf("  family=%d addr=%s port-ok=%d len=%u\n", peer.sin6_family, text,
               ntohs(peer.sin6_port) == open_port, (unsigned)len);
        len = sizeof peer;
        getsockname(fd, (void *)&peer, &len);
        inet_ntop(AF_INET6, &peer.sin6_addr, text, sizeof text);
        printf("  local family=%d addr=%s len=%u\n", peer.sin6_family, text, (unsigned)len);
        send(fd, "e", 1, 0);
        struct msghdr m = {0};
        struct iovec parts[2] = {{"ab", 2}, {"cd", 2}};
        m.msg_iov = parts;
        m.msg_iovlen = 2;
        call("sendmsg", sendmsg(fd, &m, 0));
        shutdown(fd, SHUT_WR);
        await_end(fd);
        char first[4] = {0}, second[8] = {0};
        struct iovec into[2] = {{first, 3}, {second, sizeof second - 1}};
        struct sockaddr_in6 from;
        memset(&from, 0x55, sizeof from);
        m.msg_iov = into;
        m.msg_name = &from;
        m.msg_namelen = sizeof from;
        call("recvmsg", recvmsg(fd, &m, 0));
        printf("  first=%s second=%s namelen=%u flags=%#x\n", first, second, (unsigned)m.msg_namelen,
               (unsigned)m.msg_flags);
        socklen_t fromlen = sizeof from;
        call("recvfrom-end", recvfrom(fd, buf, sizeof buf, 0, (void *)&from, &fromlen));
        printf("  fromlen=%u\n", (unsigned)fromlen);
        close(fd);
        return 0;
    }
    if (!strcmp(mode, "async")) {
        /* O_ASYNC with F_SETSIG: POLL_OUT once connected, POLL_IN for
           data, POLL_HUP for the peer's end after this side's, POLL_ERR
           for a refused connection. */
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, 40);
        sigprocmask(SIG_BLOCK, &set, NULL);
        int fd = async_socket();
        printf("  async=%d\n", !!(fcntl(fd, F_GETFL) & O_ASYNC));
        struct sockaddr_in a = to(open_port);
        call("connect", connect(fd, (void *)&a, sizeof a));
        polled("connected", fd, POLLOUT);
        signals("connected");
        send(fd, "eping", 5, 0);
        polled("echoed", fd, POLLIN);
        signals("echoed");
        n = recv(fd, buf, sizeof buf, 0);
        print_bytes("recv", buf, n);
        shutdown(fd, SHUT_WR);
        await_end(fd);
        signals("ended");
        close(fd);
        fd = async_socket();
        a = to(closed_port);
        call("connect-refused", connect(fd, (void *)&a, sizeof a));
        polled("refused", fd, POLLOUT);
        signals("refused");
        close(fd);
        return 0;
    }
    if (!strcmp(mode, "dns-tcp")) {
        /* DNS over TCP, as a resolver asks after a truncated answer: a
           query for localhost's A record, framed with its length, to port
           53. Run under the emulator only, as resolve is. */
        int fd = tcp(0);
        struct sockaddr_in a = to(53);
        call("connect", connect(fd, (void *)&a, sizeof a));
        unsigned char q[64] = {0, 0, 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 9};
        memcpy(q + 15, "localhost", 9);
        unsigned char tail[] = {0, 0, 1, 0, 1};
        memcpy(q + 24, tail, sizeof tail);
        int len = 24 + (int)sizeof tail;
        q[1] = (unsigned char)(len - 2);
        call("send", send(fd, q, len, 0));
        unsigned char reply[512];
        n = recv(fd, reply, 2, MSG_WAITALL);
        int size = n == 2 ? reply[0] << 8 | reply[1] : -1;
        n = size > 0 ? recv(fd, reply, size, MSG_WAITALL) : -1;
        printf("  answer=%d whole=%d id=%d rcode=%d answers=%d last=%d.%d.%d.%d\n", n > 0, n == size,
               n > 3 && reply[0] == 0x12 && reply[1] == 0x34, n > 3 ? reply[3] & 15 : -1, n > 7 ? reply[7] : -1,
               n > 3 ? reply[n - 4] : -1, n > 3 ? reply[n - 3] : -1, n > 3 ? reply[n - 2] : -1,
               n > 3 ? reply[n - 1] : -1);
        call("shutdown", shutdown(fd, SHUT_WR));
        call("end", recv(fd, reply, sizeof reply, 0));
        close(fd);
        return 0;
    }
    if (!strcmp(mode, "listen")) {
        /* A server on the loopback: bind, listen, a blocking connect the
           queue takes before accept, accept's address, bytes both ways and
           the ends, and what a listener answers. */
        int l = tcp(0);
        option("acceptconn", l, SOL_SOCKET, SO_ACCEPTCONN);
        struct sockaddr_in a = to(0);
        call("bind", bind(l, (void *)&a, sizeof a));
        socklen_t len = sizeof a;
        getsockname(l, (void *)&a, &len);
        int port = ntohs(a.sin_port);
        printf("  bound family=%d addr=%#x port-ok=%d\n", a.sin_family, ntohl(a.sin_addr.s_addr), port != 0);
        call("listen", listen(l, 4));
        option("acceptconn", l, SOL_SOCKET, SO_ACCEPTCONN);
        ready("idle", l, POLLIN | POLLOUT | POLLRDHUP);
        fcntl(l, F_SETOWN, getpid());
        fcntl(l, F_SETSIG, 40);
        fcntl(l, F_SETFL, fcntl(l, F_GETFL) | O_ASYNC);
        int ep = epoll_create1(0);
        struct epoll_event ev = {.events = EPOLLIN | EPOLLET};
        epoll_ctl(ep, EPOLL_CTL_ADD, l, &ev);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, 40);
        sigprocmask(SIG_BLOCK, &set, NULL);
        int result;
        int c = client(port, 0, &result);
        printf("  connect errno=%d\n", result);
        signals("arrival");
        printf("  epoll=%d\n", epoll_wait(ep, &ev, 1, 5000));
        printf("  epoll-again=%d\n", epoll_wait(ep, &ev, 1, 0));
        ready("queued", l, POLLIN | POLLOUT | POLLRDHUP);
        struct sockaddr_in peer, mine;
        len = sizeof peer;
        int s = accept4(l, (void *)&peer, &len, SOCK_CLOEXEC);
        printf("  accept-ok=%d len=%u cloexec=%d nonblock=%d\n", s >= 0, (unsigned)len,
               fcntl(s, F_GETFD) & FD_CLOEXEC, (fcntl(s, F_GETFL) & O_NONBLOCK) != 0);
        len = sizeof mine;
        getsockname(c, (void *)&mine, &len);
        printf("  peer-is-client=%d family=%d addr=%#x\n",
               peer.sin_port == mine.sin_port && peer.sin_addr.s_addr == mine.sin_addr.s_addr,
               peer.sin_family, ntohl(peer.sin_addr.s_addr));
        len = sizeof mine;
        getsockname(s, (void *)&mine, &len);
        printf("  server port-ok=%d addr=%#x\n", ntohs(mine.sin_port) == port, ntohl(mine.sin_addr.s_addr));
        len = sizeof peer;
        call("client-getpeername", getpeername(c, (void *)&peer, &len));
        printf("  client peer port-ok=%d addr=%#x\n", ntohs(peer.sin_port) == port, ntohl(peer.sin_addr.s_addr));
        option("server-acceptconn", s, SOL_SOCKET, SO_ACCEPTCONN);
        option("server-error", s, SOL_SOCKET, SO_ERROR);
        ready("drained", l, POLLIN);
        ready("server", s, POLLIN | POLLOUT | POLLRDHUP);
        call("send", send(c, "hello", 5, 0));
        polled("server-data", s, POLLIN | POLLOUT | POLLRDHUP);
        int queued = -1;
        ioctl(s, FIONREAD, &queued);
        printf("  fionread=%d\n", queued);
        n = recv(s, buf, sizeof buf, 0);
        print_bytes("recv", buf, n);
        call("send-back", send(s, "world!", 6, 0));
        polled("client-data", c, POLLIN);
        n = recv(c, buf, sizeof buf, 0);
        print_bytes("client-recv", buf, n);
        call("shutdown", shutdown(c, SHUT_WR));
        await_end(s);
        ready("server-end", s, POLLIN | POLLOUT | POLLRDHUP);
        call("server-eof", recv(s, buf, sizeof buf, 0));
        call("server-send-after", send(s, "late", 4, 0));
        polled("client-late", c, POLLIN);
        n = recv(c, buf, sizeof buf, 0);
        print_bytes("client-late", buf, n);
        close(s);
        await_end(c);
        call("client-eof", recv(c, buf, sizeof buf, 0));
        ready("client-closed", c, POLLIN | POLLOUT | POLLRDHUP);
        len = sizeof peer;
        call("client-getpeername-closed", getpeername(c, (void *)&peer, &len));
        close(c);
        call("listener-fionread", ioctl(l, FIONREAD, &queued));
        call("listener-recv", recv(l, buf, 1, MSG_DONTWAIT));
        call("listener-send", send(l, "x", 1, MSG_NOSIGNAL));
        call("listener-connect", connect(l, (void *)&a, sizeof a));
        len = sizeof peer;
        call("listener-getpeername", getpeername(l, (void *)&peer, &len));
        call("listen-again", listen(l, 8));
        call("shutdown-wr", shutdown(l, SHUT_WR));
        option("still-listening", l, SOL_SOCKET, SO_ACCEPTCONN);
        call("shutdown-rd", shutdown(l, SHUT_RD));
        option("after-shutdown", l, SOL_SOCKET, SO_ACCEPTCONN);
        call("accept-after", accept(l, NULL, NULL));
        c = client(port, 0, &result);
        printf("  connect-after errno=%d\n", result);
        close(c);
        call("listen-anew", listen(l, 1));
        printf("  anew port-ok=%d\n", port_of(l) != 0);
        close(l);
        close(ep);
        return 0;
    }
    if (!strcmp(mode, "tcp-info")) {
        /* getsockopt(TCP_INFO) of an unconnected socket, a listener, both
           sides of a loopback connection as bytes go and it ends, and a
           client whose receive buffer limits its window scale. */
        static const int every[] = {8, 12, 16, 20, 24, 28, 32, 36, 40, 48, 60, 64, 68, 72, 76, 80,
                                    84, 88, 92, 96, 100, -104, -112, -120, -128, 136, 140, 144, 148, 152,
                                    156, -160, -168, -176, -184, 192, 196, -200, -208, 216, 220, 224,
                                    228, 232, 236, 240, 244, 248, 252, 256, 260, 264, 268, 272, 276, 0};
        static const int connection[] = {24, 28, 32, 36, 60, 76, 80, 84, 88, 100, 144, -120, -128,
                                         152, 156, 192, -200, -208, 0};
        int u = tcp(0);
        tcp_info("unconnected", u, 0xff, every);
        int port;
        int l = listener(4, &port);
        tcp_info("listening", l, 0xff, every);
        int result;
        int c = client(port, 0, &result);
        printf("  connect errno=%d\n", result);
        poll(NULL, 0, 50);
        tcp_info("one-waiting", l, 0xff, every);
        int s = accept(l, NULL, NULL);
        tcp_info("client", c, 0x7f, connection);
        tcp_info("server", s, 0x7f, connection);
        call("send", send(c, buf, 100, 0));
        call("recv", recv(s, buf, sizeof buf, 0));
        /* Past the 40 ms an acknowledgement may wait (TCP_DELACK_MAX). */
        poll(NULL, 0, 100);
        tcp_info("client-sent", c, 0x7f, connection);
        tcp_info("server-read", s, 0x7f, connection);
        call("send-back", send(s, buf, 200, 0));
        poll(NULL, 0, 100);
        tcp_info("server-unread", s, 0x7f, connection);
        tcp_info("client-unread", c, 0x7f, connection);
        call("shutdown", shutdown(c, SHUT_WR));
        await_end(s);
        /* The FIN's acknowledgement may wait too: until it comes the client
           is in FIN_WAIT1. */
        unsigned char raw[512];
        socklen_t len;
        for (int i = 0; i < 50; i++) {
            tcp_info_raw(c, raw, 512, &len);
            if (raw[0] != 4) break;
            poll(NULL, 0, 20);
        }
        tcp_info("client-shut", c, 0x7f, connection);
        tcp_info("server-ended", s, 0x7f, connection);
        /* The window scale the handshake offered stays. */
        int tiny = 2304;
        setsockopt(c, SOL_SOCKET, SO_RCVBUF, &tiny, sizeof tiny);
        tcp_info("client-rcvbuf-after", c, 0x40, (const int[]){0});
        close(s);
        close(c);
        /* A shorter room takes that much, a negative one is EINVAL; UDP has
           no TCP options. */
        int r = tcp_info_raw(u, raw, 8, &len);
        printf("  short=%d len=%u state=%u\n", r, (unsigned)len, raw[0]);
        r = tcp_info_raw(u, raw, -1, &len);
        printf("  negative=%d errno=%d\n", r, errno);
        int udp = socket(AF_INET, SOCK_DGRAM, 0);
        r = tcp_info_raw(udp, raw, 512, &len);
        printf("  udp=%d errno=%d\n", r, errno);
        /* SO_RCVBUF before connect clamps the window scale it offers. */
        int small = tcp(0), size = 65536;
        setsockopt(small, SOL_SOCKET, SO_RCVBUF, &size, sizeof size);
        struct sockaddr_in a = to(port);
        call("small-connect", connect(small, (void *)&a, sizeof a));
        tcp_info("small", small, 0x60, (const int[]){0});
        close(small);
        close(l);
        close(u);
        return 0;
    }
    if (!strcmp(mode, "tcp-handshake")) {
        filter_network();
        shaken();
        return 0;
    }
    if (!strcmp(mode, "tcp-loss")) {
        filter_network();
        int port;
        int l = fresh_listener(&port);
        lost(l, port);
        close(l);
        return 0;
    }
    if (!strcmp(mode, "tcp-cork")) {
        int port;
        int l = listener(8, &port);
        corked(l, port);
        return 0;
    }
    if (!strcmp(mode, "tcp-held")) {
        int port;
        int l = listener(8, &port);
        held(l, port);
        close(l);
        return 0;
    }
    if (!strcmp(mode, "tcp-segments")) {
        /* The segments a loopback connection takes (tcp_write_xmit and
           __tcp_ack_snd_check), as tcp_info counts them. Writes of at most
           536 bytes leave the windows as they are. */
        static char bytes[40000];
        int port, result, on = 1, off = 0;
        int l = listener(8, &port);
        static const int writes[] = {1, 2, 15, 16, 17, 18, 30};
        for (size_t i = 0; i < sizeof writes / sizeof *writes; i++) {
            /* Sixteen are acknowledged at once; the next waits, and the
               ones after it are held for its acknowledgement (Nagle). */
            int c = client(port, 0, &result), s = accept(l, NULL, NULL);
            for (int n = 0; n < writes[i]; n++) send(c, bytes, 1, 0);
            printf(" writes %d\n", writes[i]);
            segment_counts("written", c, s);
            call("read", recv(s, bytes, sizeof bytes, 0));
            segment_counts("read", c, s);
            close(c);
            close(s);
        }
        static const int lengths[] = {100, 300, 536};
        for (size_t i = 0; i < sizeof lengths / sizeof *lengths; i++) {
            /* Each read before the next is written. */
            int c = client(port, 0, &result), s = accept(l, NULL, NULL);
            for (int n = 0; n < 25; n++) {
                send(c, bytes, lengths[i], 0);
                recv(s, bytes, sizeof bytes, 0);
            }
            printf(" length %d\n", lengths[i]);
            segment_counts("read each", c, s);
            close(c);
            close(s);
        }
        /* TCP_NODELAY: each write is a segment, and a loss probe sends the
           last again before their acknowledgement; set late, it sends what
           is held. */
        int c = client(port, 0, &result), s = accept(l, NULL, NULL);
        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
        for (int n = 0; n < 16; n++) send(c, bytes, 1, 0);
        segment_counts("nodelay", c, s);
        for (int n = 0; n < 4; n++) send(c, bytes, 1, 0);
        segment_counts("nodelay probe", c, s);
        close(c);
        close(s);
        c = client(port, 0, &result), s = accept(l, NULL, NULL);
        for (int n = 0; n < 20; n++) send(c, bytes, 1, 0);
        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
        segment_counts("nodelay late", c, s);
        close(c);
        close(s);
        /* MSG_MORE: held for a write without it, or for 200 ms. */
        c = client(port, 0, &result), s = accept(l, NULL, NULL);
        for (int n = 0; n < 3; n++) send(c, bytes, 100, MSG_MORE);
        segment_counts("more", c, s);
        send(c, bytes, 100, 0);
        segment_counts("more pushed", c, s);
        send(c, bytes, 100, MSG_MORE);
        poll(NULL, 0, 300);
        segment_counts("more late", c, s);
        close(c);
        close(s);
        /* Replies carry acknowledgements, and the side that replies delays
           its own. */
        c = client(port, 0, &result), s = accept(l, NULL, NULL);
        for (int n = 0; n < 5; n++) {
            send(c, bytes, 10, 0);
            recv(s, bytes, sizeof bytes, 0);
            send(s, bytes, 20, 0);
            recv(c, bytes, sizeof bytes, 0);
        }
        segment_counts("replies", c, s);
        for (int n = 0; n < 5; n++) send(c, bytes, 1, 0);
        segment_counts("after replies", c, s);
        close(c);
        close(s);
        c = client(port, 0, &result), s = accept(l, NULL, NULL);
        for (int n = 0; n < 5; n++) {
            send(c, bytes, 1, 0);
            send(s, bytes, 1, 0);
        }
        segment_counts("both ways", c, s);
        close(c);
        close(s);
        /* TCP_QUICKACK off and on. */
        c = client(port, 0, &result), s = accept(l, NULL, NULL);
        setsockopt(s, IPPROTO_TCP, TCP_QUICKACK, &off, sizeof off);
        for (int n = 0; n < 5; n++) send(c, bytes, 1, 0);
        segment_counts("quickack off", c, s);
        setsockopt(s, IPPROTO_TCP, TCP_QUICKACK, &on, sizeof on);
        for (int n = 0; n < 5; n++) send(c, bytes, 1, 0);
        segment_counts("quickack on", c, s);
        close(c);
        close(s);
        /* Urgent data, and a write past the MSS. */
        c = client(port, 0, &result), s = accept(l, NULL, NULL);
        send(c, bytes, 10, 0);
        send(c, bytes, 3, MSG_OOB);
        send(c, bytes, 10, 0);
        segment_counts("urgent", c, s);
        close(c);
        close(s);
        c = client(port, 0, &result), s = accept(l, NULL, NULL);
        call("send", send(c, bytes, 40000, 0));
        segment_counts("past the mss", c, s);
        close(c);
        close(s);
        /* The ends, alone and with data held. */
        c = client(port, 0, &result), s = accept(l, NULL, NULL);
        shutdown(c, SHUT_WR);
        segment_counts("end", c, s);
        send(s, bytes, 5, 0);
        segment_counts("answered", c, s);
        shutdown(s, SHUT_WR);
        segment_counts("both ended", c, s);
        close(c);
        close(s);
        c = client(port, 0, &result), s = accept(l, NULL, NULL);
        send(c, bytes, 10, MSG_MORE);
        shutdown(c, SHUT_WR);
        segment_counts("end with data", c, s);
        close(c);
        close(s);
        close(l);
        return 0;
    }
    if (!strcmp(mode, "listen-io-uring")) {
        /* io_uring's socket requests on the loopback: a socket, accepts of
           connections that wait (IORING_CQE_F_SOCK_NONEMPTY while more do)
           and one that waits for its connection, a connect in progress, a
           refused one, sends and receives (one that waits, one that waits
           for the whole length, what is left to read), and a shutdown. */
        struct ring r;
        if (ring_open(&r)) return 80;
        int l = ring_run(&r, (ring_push(&r, 45, 1, AF_INET, SOCK_STREAM, 0, 0, 0), 1), 1, "socket", 1);
        struct sockaddr_in a = to(0);
        call("bind", bind(l, (void *)&a, sizeof a));
        socklen_t len = sizeof a;
        getsockname(l, (void *)&a, &len);
        call("listen", listen(l, 4));
        int result;
        int c1 = client(ntohs(a.sin_port), 0, &result);
        int c2 = client(ntohs(a.sin_port), 0, &result);
        awaited("queued", l, POLLIN);
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof peer;
        ring_push(&r, 13, 2, l, (unsigned long)&peer_len, (unsigned long)&peer, 0, SOCK_CLOEXEC);
        int s1 = ring_run(&r, 1, 1, "accept-more", 1);
        printf("  peer len=%u family=%d addr=%#x cloexec=%d\n", (unsigned)peer_len, peer.sin_family,
               ntohl(peer.sin_addr.s_addr), fcntl(s1, F_GETFD) & FD_CLOEXEC);
        ring_push(&r, 13, 3, l, 0, 0, 0, SOCK_NONBLOCK);
        int s2 = ring_run(&r, 1, 1, "accept-last", 1);
        printf("  nonblock=%d\n", (fcntl(s2, F_GETFL) & O_NONBLOCK) != 0);
        close(s1);
        close(s2);
        close(c1);
        close(c2);
        ring_push(&r, 13, 4, l, 0, 0, 0, 0);
        ring_run(&r, 1, 0, "accept-waits", 0);
        int c = ring_run(&r, (ring_push(&r, 45, 5, AF_INET, SOCK_STREAM, 0, 0, 0), 1), 1, "socket", 1);
        ring_push(&r, 16, 6, c, sizeof a, (unsigned long)&a, 0, 0);
        ring_run(&r, 1, 2, "connect-accepted", 1);
        int s = ring_result[4];
        struct sockaddr_in closed = to(closed_port);
        int refused = ring_run(&r, (ring_push(&r, 45, 7, AF_INET, SOCK_STREAM, 0, 0, 0), 1), 1, "socket", 1);
        ring_push(&r, 16, 8, refused, sizeof closed, (unsigned long)&closed, 0, 0);
        ring_run(&r, 1, 1, "connect-refused", 0);
        ring_push(&r, 16, 9, c, sizeof a, (unsigned long)&a, 0, 0);
        ring_run(&r, 1, 1, "connect-again", 0);
        char got[16] = {0};
        ring_push(&r, 26, 10, s, 0, (unsigned long)"hello", 5, 0);
        ring_run(&r, 1, 1, "send", 0);
        awaited("sent", c, POLLIN);
        ring_push(&r, 27, 11, c, 0, (unsigned long)got, 3, 0);
        ring_run(&r, 1, 1, "recv-part", 0);
        ring_push(&r, 27, 12, c, 0, (unsigned long)got + 3, 8, 0);
        ring_run(&r, 1, 1, "recv-rest", 0);
        print_bytes("received", got, 5);
        ring_push(&r, 27, 13, c, 0, (unsigned long)got, 8, MSG_DONTWAIT);
        ring_run(&r, 1, 1, "recv-dontwait", 0);
        ring_push(&r, 27, 14, c, 0, (unsigned long)got, 8, 0);
        ring_run(&r, 1, 0, "recv-waits", 0);
        call("write", (int)write(s, "ab", 2));
        ring_run(&r, 0, 1, "recv-woken", 0);
        ring_push(&r, 27, 15, c, 0, (unsigned long)got, 4, MSG_WAITALL);
        ring_run(&r, 1, 0, "waitall-waits", 0);
        call("write", (int)write(s, "cd", 2));
        usleep(100000);
        call("write", (int)write(s, "ef", 2));
        ring_run(&r, 0, 1, "waitall-whole", 0);
        print_bytes("received", got, 4);
        ring_push(&r, 34, 16, s, 0, 0, SHUT_WR, 0);
        ring_run(&r, 1, 1, "shutdown", 0);
        awaited("shut", c, POLLRDHUP);
        ring_push(&r, 27, 17, c, 0, (unsigned long)got, 8, 0);
        ring_run(&r, 1, 1, "recv-end", 0);
        return 0;
    }
    if (!strcmp(mode, "listen-errors")) {
        /* What bind, listen and accept refuse, as Linux checks them. */
        int port;
        int l = listener(1, &port);
        int b = tcp(0);
        bind_to("bind-in-use", b, htonl(INADDR_LOOPBACK), port);
        bind_to("bind-any-in-use", b, htonl(INADDR_ANY), port);
        set_option("reuseaddr", b, SOL_SOCKET, SO_REUSEADDR, 1);
        bind_to("bind-reuse-beside-listener", b, htonl(INADDR_LOOPBACK), port);
        bind_to("bind-foreign", b, inet_addr("192.0.2.1"), 0);
        struct sockaddr_in a = to(0);
        call("bind-short", bind(b, (void *)&a, 8));
        struct sockaddr_in6 six = {.sin6_family = AF_INET6};
        call("bind-family", bind(b, (void *)&six, sizeof six));
        struct sockaddr_in unspec = {.sin_family = AF_UNSPEC};
        call("bind-unspec-any", bind(b, (void *)&unspec, sizeof unspec));
        printf("  unspec port-ok=%d\n", port_of(b) != 0);
        call("bind-twice", bind(b, (void *)&a, sizeof a));
        int other = tcp(0);
        unspec.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        call("bind-unspec-address", bind(other, (void *)&unspec, sizeof unspec));
        /* Two sockets with SO_REUSEADDR share a port until one listens. */
        int r1 = tcp(0), r2 = tcp(0), r3 = tcp(0);
        set_option("reuse-1", r1, SOL_SOCKET, SO_REUSEADDR, 1);
        set_option("reuse-2", r2, SOL_SOCKET, SO_REUSEADDR, 1);
        bind_to("reuse-bind-1", r1, htonl(INADDR_LOOPBACK), 0);
        int shared = port_of(r1);
        bind_to("reuse-bind-2", r2, htonl(INADDR_LOOPBACK), shared);
        bind_to("no-reuse-bind", r3, htonl(INADDR_LOOPBACK), shared);
        call("reuse-listen-1", listen(r1, 1));
        call("reuse-listen-2", listen(r2, 1));
        /* Another loopback address is another place for the same port. */
        bind_to("other-address", r3, inet_addr("127.0.0.2"), port);
        call("accept-not-listening", accept(r3, NULL, NULL));
        /* The system call itself: musl before 1.2.4 takes accept4's
           EINVAL for a kernel without accept4 and calls accept instead,
           which waits for a connection. */
        call("accept4-flags", (int)syscall(SYS_accept4, l, NULL, NULL, 1));
        /* The port of a socket bound but not listening refuses. */
        int result;
        int refused = client(port_of(b), 0, &result);
        printf("  connect-bound-only errno=%d\n", result);
        close(refused);
        refused = client(port_of(b), SOCK_NONBLOCK, &result);
        printf("  connect-bound-only-nonblocking errno=%d\n", result);
        polled("refused", refused, POLLIN | POLLOUT | POLLRDHUP);
        option("refused-error", refused, SOL_SOCKET, SO_ERROR);
        call("refused-connect-again", connect(refused, (void *)&a, sizeof a));
        close(refused);
        /* A connected socket does not listen; a listener's accept waits
           for SO_RCVTIMEO, and a nonblocking one does not wait. */
        int c = client(port, 0, &result);
        printf("  connect errno=%d\n", result);
        call("listen-connected", listen(c, 1));
        int s = accept(l, NULL, NULL);
        printf("  accept-ok=%d\n", s >= 0);
        struct timeval tv = {0, 100000};
        setsockopt(l, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        call("accept-timeout", accept(l, NULL, NULL));
        fcntl(l, F_SETFL, O_NONBLOCK);
        call("accept-nonblocking", accept(l, NULL, NULL));
        /* A full queue (backlog 1 holds two): the next connection is
           dropped and tried again, after accept makes room. (Backlog
           0 would leave Linux's first one to SYN cookies.) */
        int q;
        int full = listener(1, &q);
        int first = client(q, SOCK_NONBLOCK, &result);
        printf("  first errno=%d\n", result);
        polled("first", first, POLLOUT);
        int second = client(q, SOCK_NONBLOCK, &result);
        printf("  second errno=%d\n", result);
        polled("second", second, POLLOUT);
        int third = client(q, SOCK_NONBLOCK, &result);
        printf("  third errno=%d\n", result);
        ready("third-waiting", third, POLLIN | POLLOUT);
        call("third-again", connect(third, (void *)&a, sizeof a) ? -1 : 0);
        int got = accept(full, NULL, NULL);
        printf("  accept-first-ok=%d\n", got >= 0);
        polled("third-after-accept", third, POLLOUT);
        option("third-error", third, SOL_SOCKET, SO_ERROR);
        for (int i = 0; i < 2; i++) {
            got = accept(full, NULL, NULL);
            printf("  accept-next-ok=%d\n", got >= 0);
        }
        /* UDP neither listens nor accepts. */
        int u = socket(AF_INET, SOCK_DGRAM, 0);
        call("udp-listen", listen(u, 1));
        call("udp-accept", accept(u, NULL, NULL));
        return 0;
    }
    if (!strcmp(mode, "listen-full")) {
        /* A full queue (backlog 1 holds two) drops the handshake, and the
           client sends it again 1, 2, 3, 4, 5, 7… seconds later
           (tcp_syn_linear_timeouts): room made in between takes it only at
           the next try, a listener gone by then refuses it, and another
           listening there by then takes it. */
        int port, result;
        int l = listener(1, &port);
        client(port, SOCK_NONBLOCK, &result);
        client(port, SOCK_NONBLOCK, &result);
        long start = now_ms();
        int c = client(port, SOCK_NONBLOCK, &result);
        printf("  dropped errno=%d\n", result);
        ready("dropped", c, POLLOUT);
        poll(NULL, 0, 300);
        printf("  accept-ok=%d\n", accept(l, NULL, NULL) >= 0);
        ready("room-made", c, POLLOUT);
        finished("first-try", c, start, 3000);
        ready("listener", l, POLLIN);
        close(l);
        l = listener(1, &port);
        client(port, SOCK_NONBLOCK, &result);
        client(port, SOCK_NONBLOCK, &result);
        start = now_ms();
        c = client(port, SOCK_NONBLOCK, &result);
        poll(NULL, 0, 1500);
        accept(l, NULL, NULL);
        finished("second-try", c, start, 3000);
        close(l);
        l = listener(1, &port);
        client(port, SOCK_NONBLOCK, &result);
        client(port, SOCK_NONBLOCK, &result);
        start = now_ms();
        c = client(port, SOCK_NONBLOCK, &result);
        poll(NULL, 0, 200);
        close(l);
        ready("listener-gone", c, POLLOUT);
        finished("refused", c, start, 3000);
        l = listener(1, &port);
        client(port, SOCK_NONBLOCK, &result);
        client(port, SOCK_NONBLOCK, &result);
        start = now_ms();
        c = client(port, SOCK_NONBLOCK, &result);
        poll(NULL, 0, 200);
        close(l);
        int again = tcp(0), one = 1;
        setsockopt(again, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        bind_to("listen-again", again, htonl(INADDR_LOOPBACK), port);
        call("listen-again", listen(again, 4));
        finished("taken-by-another", c, start, 3000);
        /* A blocking connect waits only as long as SO_SNDTIMEO, then is in
           progress. */
        close(again);
        l = listener(1, &port);
        client(port, SOCK_NONBLOCK, &result);
        client(port, SOCK_NONBLOCK, &result);
        c = tcp(0);
        struct timeval tv = {0, 300000};
        setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        struct sockaddr_in a = to(port);
        call("blocking", connect(c, (void *)&a, sizeof a));
        call("blocking-again", connect(c, (void *)&a, sizeof a));
        return 0;
    }
    if (!strcmp(mode, "listen-time-wait")) {
        /* The side that closes a loopback connection first keeps its port in
           TIME_WAIT: a bind there is EADDRINUSE, with SO_REUSEADDR too
           unless the closed socket had it, while the side that closed
           second keeps nothing. A reset leaves nothing held. */
        int port, result, one = 1;
        int l = listener(8, &port);
        int c = own_port_client(port, &result);
        int s = accept(l, NULL, NULL);
        int client_port = port_of(c);
        close(c);
        await_end(s);
        close(s);
        int t = tcp(0);
        bind_to("client-first", t, htonl(INADDR_LOOPBACK), client_port);
        close(t);
        t = tcp(0);
        setsockopt(t, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        bind_to("client-first-reuse", t, htonl(INADDR_LOOPBACK), client_port);
        close(t);
        t = tcp(0);
        bind_to("client-first-any", t, htonl(INADDR_ANY), client_port);
        close(t);
        /* The client closes first while the server stays open: held too,
           until the server's send is answered with a reset. */
        c = own_port_client(port, &result);
        s = accept(l, NULL, NULL);
        int open_port = port_of(c);
        close(c);
        await_end(s);
        t = tcp(0);
        bind_to("peer-open", t, htonl(INADDR_LOOPBACK), open_port);
        call("send-to-closed", send(s, "x", 1, MSG_NOSIGNAL));
        polled("answered", s, POLLERR);
        bind_to("after-reset", t, htonl(INADDR_LOOPBACK), open_port);
        close(t);
        close(s);
        /* Closed with bytes the server has no room for yet: held while they
           go, then in TIME_WAIT once read to the end; or freed by the reset
           of a server that closes with them unread. */
        static char lots[4096];
        for (int drained = 1; drained >= 0; drained--) {
            c = own_port_client(port, &result);
            s = accept(l, NULL, NULL);
            int full_port = port_of(c);
            while (send(c, lots, sizeof lots, MSG_DONTWAIT) > 0) {}
            close(c);
            t = tcp(0);
            bind_to(drained ? "pending" : "pending-again", t, htonl(INADDR_LOOPBACK), full_port);
            if (drained)
                while (recv(s, lots, sizeof lots, 0) > 0) {}
            close(s);
            poll(NULL, 0, 100);
            if (drained) {
                bind_to("drained", t, htonl(INADDR_LOOPBACK), full_port);
            } else {
                /* Linux's loopback hands the reset to the client in its own
                   time, which a busy machine can put off past 100 ms: look
                   again for up to 5 seconds before the port counts as held. */
                struct sockaddr_in a = to(full_port);
                int r;
                for (int tries = 0; (r = bind(t, (void *)&a, sizeof a)) && tries < 50; tries++)
                    poll(NULL, 0, 100);
                call("unread-reset", r);
            }
            close(t);
        }
        /* Closed with input unread: a reset, and nothing held. */
        c = own_port_client(port, &result);
        s = accept(l, NULL, NULL);
        int unread_port = port_of(c);
        send(s, "x", 1, 0);
        polled("unread", c, POLLIN);
        close(c);
        polled("reset", s, POLLERR);
        close(s);
        t = tcp(0);
        bind_to("after-unread", t, htonl(INADDR_LOOPBACK), unread_port);
        close(t);
        close(l);
        /* The server closes first: the listener's port is held, and only a
           socket with SO_REUSEADDR shares it, as the closed one had it. */
        l = tcp(0);
        setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        struct sockaddr_in any = to(0);
        bind(l, (void *)&any, sizeof any);
        listen(l, 8);
        port = port_of(l);
        c = own_port_client(port, &result);
        s = accept(l, NULL, NULL);
        close(s);
        await_end(c);
        close(c);
        close(l);
        t = tcp(0);
        bind_to("server-first", t, htonl(INADDR_LOOPBACK), port);
        close(t);
        t = tcp(0);
        setsockopt(t, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        bind_to("server-first-reuse", t, htonl(INADDR_LOOPBACK), port);
        call("server-first-listen", listen(t, 1));
        close(t);
        return 0;
    }
    if (!strcmp(mode, "listen-reuseport")) {
        /* Sockets sharing a port with SO_REUSEPORT share its connections
           and datagrams by a hash of the addresses (reuseport_select_sock).
           Which one gets each hangs on Linux's secret, so only the counts
           are printed: each takes some of 64, and none once it leaves. */
        int one = 1, result, port = 0;
        int l[2], u[2];
        for (int i = 0; i < 2; i++) {
            l[i] = tcp(SOCK_NONBLOCK);
            setsockopt(l[i], SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
            bind_to("bind", l[i], htonl(INADDR_LOOPBACK), port);
            call("listen", listen(l[i], 128));
            port = port_of(l[i]);
        }
        int counts[2] = {0, 0};
        for (int i = 0; i < 64; i++) {
            close(client(port, 0, &result));
            if (result) printf("  connect errno=%d\n", result);
        }
        for (int i = 0; i < 2; i++) {
            int s;
            while ((s = accept(l[i], NULL, NULL)) >= 0) {
                counts[i]++;
                close(s);
            }
        }
        printf("  tcp total=%d shared=%d\n", counts[0] + counts[1], counts[0] > 0 && counts[1] > 0);
        close(l[0]);
        counts[1] = 0;
        for (int i = 0; i < 16; i++) close(client(port, 0, &result));
        for (int s; (s = accept(l[1], NULL, NULL)) >= 0; counts[1]++) close(s);
        printf("  tcp after-close=%d\n", counts[1]);
        close(l[1]);

        port = 0;
        for (int i = 0; i < 2; i++) {
            u[i] = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
            setsockopt(u[i], SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
            bind_to("bind-udp", u[i], htonl(INADDR_LOOPBACK), port);
            port = port_of(u[i]);
        }
        struct sockaddr_in at = to(port);
        int senders[64];
        for (int i = 0; i < 64; i++) {
            senders[i] = socket(AF_INET, SOCK_DGRAM, 0);
            sendto(senders[i], "x", 1, 0, (void *)&at, sizeof at);
        }
        counts[0] = counts[1] = 0;
        for (int i = 0; i < 2; i++)
            while (recv(u[i], buf, sizeof buf, 0) >= 0) counts[i]++;
        printf("  udp total=%d shared=%d\n", counts[0] + counts[1], counts[0] > 0 && counts[1] > 0);
        /* A connected one takes only its peer's: the rest go to the other. */
        struct sockaddr_in peer = to(port_of(senders[0]));
        call("connect-udp", connect(u[0], (void *)&peer, sizeof peer));
        for (int i = 1; i < 64; i++) sendto(senders[i], "x", 1, 0, (void *)&at, sizeof at);
        sendto(senders[0], "x", 1, 0, (void *)&at, sizeof at);
        counts[0] = counts[1] = 0;
        for (int i = 0; i < 2; i++)
            while (recv(u[i], buf, sizeof buf, 0) >= 0) counts[i]++;
        printf("  udp connected=%d other=%d\n", counts[0], counts[1]);
        return 0;
    }
    if (!strcmp(mode, "listen-fin-wait")) {
        /* The side that closes first waits for the peer's end up to 60
           seconds from its close (FIN_WAIT2, tcp_fin_timeout), then keeps
           its port in TIME_WAIT for 60 seconds from that end. The checks
           sit 10 seconds or more from each change, as Linux's timers run a
           few seconds late. A socket that stays open gives the port it took
           up with that TIME_WAIT (tcp_done), but keeps one it bound itself
           (SOCK_BINDPORT_LOCK) until it closes. */
        int port, result;
        int l = listener(8, &port);
        int c[5], s[5], at[5];
        for (int i = 0; i < 5; i++) {
            if (i == 4) {
                /* A port free now, which the client binds itself. */
                int t = tcp(0);
                bind_to("bind-free", t, htonl(INADDR_LOOPBACK), 0);
                int own = port_of(t);
                close(t);
                c[i] = tcp(0);
                bind_to("bind-own", c[i], htonl(INADDR_LOOPBACK), own);
                struct sockaddr_in a = to(port);
                call("connect-own", connect(c[i], (void *)&a, sizeof a));
            } else {
                c[i] = client(port, 0, &result);
            }
            s[i] = accept(l, NULL, NULL);
            at[i] = port_of(c[i]);
        }
        long start = now_ms();
        /* 0: the peer stays open. 1: the peer closes at 30 seconds. 2: shut
           down at once, closed at 30 seconds, the peer staying open. 3 and
           4: shut down at once, the peer closing at once, and kept open. */
        close(c[0]);
        close(c[1]);
        shutdown(c[2], SHUT_WR);
        for (int i = 3; i < 5; i++) {
            shutdown(c[i], SHUT_WR);
            close(s[i]);
        }
        static const struct {
            int second, which;
            const char *name;
        } checks[] = {{50, 0, "open-50"},  {50, 3, "kept-50"},   {50, 4, "own-50"},
                      {70, 0, "open-70"},  {70, 1, "late-70"},   {70, 3, "kept-70"},
                      {70, 4, "own-70"},   {80, 1, "late-80"},   {80, 2, "shut-80"},
                      {100, 1, "late-100"}, {100, 2, "shut-100"}};
        int closed = 0;
        for (unsigned i = 0; i < sizeof checks / sizeof *checks; i++) {
            if (!closed && checks[i].second > 30) {
                long wait = start + 30000 - now_ms();
                if (wait > 0) usleep(wait * 1000);
                close(s[1]);
                close(c[2]);
                closed = 1;
            }
            long wait = start + checks[i].second * 1000L - now_ms();
            if (wait > 0) usleep(wait * 1000);
            int t = tcp(0);
            bind_to(checks[i].name, t, htonl(INADDR_LOOPBACK), at[checks[i].which]);
            close(t);
        }
        close(c[4]);
        int t = tcp(0);
        bind_to("own-closed", t, htonl(INADDR_LOOPBACK), at[4]);
        return 0;
    }
    if (!strcmp(mode, "listen-urgent")) {
        /* MSG_OOB's urgent byte on the loopback (tcp_check_urg, tcp_urg,
           tcp_recvmsg, tcp_recv_urg): reads stop before its mark, one that
           starts there passes over it, losing it unless MSG_OOB took it,
           a later one makes it ordinary, and SO_OOBINLINE reads it as data.
           Each one sends the owner SIGURG. The waits after each send let
           Linux's loopback deliver it. */
        signal(SIGURG, on_urg);
        int port, c, s, one = 1;
        int l = listener(8, &port);
        puts("urgent");
        urgent_pair(l, port, &c, &s);
        urgent_state("before", s);
        call("send", send(c, "abc", 3, MSG_OOB));
        usleep(10000);
        urgent_state("sent", s);
        urgent_read("read", s, 16, 0);
        urgent_state("at-mark", s);
        urgent_read("peek-oob", s, 16, MSG_OOB | MSG_PEEK);
        urgent_read("oob", s, 16, MSG_OOB);
        urgent_state("taken", s);
        urgent_read("read-past", s, 16, 0);
        urgent_read("oob-again", s, 16, MSG_OOB);
        puts("passed");
        urgent_pair(l, port, &c, &s);
        send(c, "abc", 3, MSG_OOB);
        send(c, "de", 2, 0);
        usleep(10000);
        urgent_read("read", s, 16, 0);
        urgent_state("at-mark", s);
        urgent_read("peek", s, 16, MSG_PEEK);
        urgent_read("peek-oob", s, 16, MSG_OOB | MSG_PEEK);
        urgent_read("read", s, 16, 0);
        urgent_state("past", s);
        urgent_read("oob", s, 16, MSG_OOB);
        puts("two");
        urgent_pair(l, port, &c, &s);
        send(c, "ab", 2, MSG_OOB);
        send(c, "cd", 2, MSG_OOB);
        usleep(10000);
        urgent_state("two", s);
        urgent_read("read", s, 16, 0);
        urgent_read("read", s, 16, 0);
        urgent_read("oob", s, 16, MSG_OOB);
        puts("single");
        urgent_pair(l, port, &c, &s);
        send(c, "abc", 3, MSG_OOB);
        usleep(10000);
        urgent_read("read1", s, 1, 0);
        urgent_read("read1", s, 1, 0);
        urgent_read("read1", s, 1, 0);
        urgent_read("oob0", s, 0, MSG_OOB);
        puts("only");
        urgent_pair(l, port, &c, &s);
        send(c, "x", 1, MSG_OOB);
        usleep(10000);
        urgent_state("only", s);
        urgent_read("read", s, 16, 0);
        urgent_read("oob", s, 16, MSG_OOB);
        urgent_state("lost", s);
        puts("truncated");
        urgent_pair(l, port, &c, &s);
        send(c, "ab", 2, MSG_OOB);
        usleep(10000);
        {
            char b[1];
            struct iovec v = {.iov_base = b, .iov_len = 0};
            struct msghdr m = {.msg_iov = &v, .msg_iovlen = 1};
            long r = recvmsg(s, &m, MSG_OOB);
            printf("  recvmsg0 r=%ld flags=%#x\n", r, (unsigned)m.msg_flags);
            v.iov_len = 1;
            m.msg_flags = 0;
            r = recvmsg(s, &m, MSG_OOB);
            printf("  recvmsg1 r=%ld flags=%#x byte=%c\n", r, (unsigned)m.msg_flags, b[0]);
        }
        puts("waitall");
        urgent_pair(l, port, &c, &s);
        send(c, "ab", 2, MSG_OOB);
        close(c);
        usleep(10000);
        urgent_state("closed", s);
        urgent_read("read", s, 16, MSG_WAITALL);
        urgent_read("read", s, 16, 0);
        urgent_read("oob", s, 16, MSG_OOB);
        puts("inline");
        urgent_pair(l, port, &c, &s);
        setsockopt(s, SOL_SOCKET, SO_OOBINLINE, &one, sizeof one);
        send(c, "abc", 3, MSG_OOB);
        send(c, "de", 2, 0);
        usleep(10000);
        urgent_state("inline", s);
        urgent_read("oob", s, 16, MSG_OOB);
        urgent_read("read", s, 16, 0);
        urgent_state("at-mark", s);
        urgent_read("read", s, 16, 0);
        urgent_state("past", s);
        puts("inline-later");
        urgent_pair(l, port, &c, &s);
        send(c, "abc", 3, MSG_OOB);
        usleep(10000);
        setsockopt(s, SOL_SOCKET, SO_OOBINLINE, &one, sizeof one);
        urgent_read("read", s, 16, 0);
        urgent_read("read", s, 16, 0);
        urgent_read("oob", s, 16, MSG_OOB);
        puts("others");
        urgent_pair(l, port, &c, &s);
        call("send-empty", send(c, "", 0, MSG_OOB));
        usleep(10000);
        urgent_state("empty", s);
        urgent_read("oob-none", s, 16, MSG_OOB);
        urgent_read("oob-listener", l, 16, MSG_OOB);
        int fresh = tcp(0);
        urgent_read("oob-unconnected", fresh, 16, MSG_OOB);
        int u = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        urgent_read("udp-oob", u, 16, MSG_OOB);
        struct sockaddr_in to_u = to(9);
        call("udp-send-oob", sendto(u, "x", 1, MSG_OOB, (void *)&to_u, sizeof to_u));
        return 0;
    }
    if (!strcmp(mode, "listen-reset")) {
        /* What ends a loopback connection with a reset. */
        int port, result;
        int l = listener(8, &port);
        /* Closed with input unread: the peer reads what it had, then the
           reset, then the end. */
        int c = client(port, 0, &result);
        int s = accept(l, NULL, NULL);
        send(s, "abc", 3, 0);
        send(c, "xyz", 3, 0);
        polled("unread", s, POLLIN);
        polled("client-data", c, POLLIN);
        close(s);
        polled("reset", c, POLLIN | POLLOUT | POLLRDHUP);
        n = recv(c, buf, sizeof buf, 0);
        print_bytes("before-reset", buf, n);
        call("recv-reset", recv(c, buf, sizeof buf, 0));
        call("recv-after", recv(c, buf, sizeof buf, 0));
        call("send-after", send(c, "x", 1, MSG_NOSIGNAL));
        close(c);
        /* Closed cleanly, then written to: the write goes, the reset comes
           back, and the next write is EPIPE. */
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        close(s);
        await_end(c);
        call("eof", recv(c, buf, sizeof buf, 0));
        call("send-to-closed", send(c, "x", 1, MSG_NOSIGNAL));
        polled("answered", c, POLLERR);
        call("send-again", send(c, "x", 1, MSG_NOSIGNAL));
        option("error-after", c, SOL_SOCKET, SO_ERROR);
        call("recv-closed", recv(c, buf, sizeof buf, 0));
        close(c);
        /* A zero linger time resets. */
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        struct linger linger = {1, 0};
        setsockopt(s, SOL_SOCKET, SO_LINGER, &linger, sizeof linger);
        close(s);
        polled("lingered", c, POLLIN);
        call("recv-lingered", recv(c, buf, sizeof buf, 0));
        close(c);
        /* AF_UNSPEC disconnects with a reset, and the socket connects anew. */
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        struct sockaddr unspec = {.sa_family = AF_UNSPEC};
        call("disconnect", connect(c, &unspec, sizeof unspec));
        polled("disconnected", s, POLLIN);
        call("recv-disconnected", recv(s, buf, sizeof buf, 0));
        struct sockaddr_in a = to(port);
        call("reconnect", connect(c, (void *)&a, sizeof a));
        close(s);
        s = accept(l, NULL, NULL);
        printf("  accept-again-ok=%d\n", s >= 0);
        close(s);
        close(c);
        /* A listener that closes resets what it has not handed out. */
        int queued = client(port, 0, &result);
        printf("  queued errno=%d\n", result);
        close(l);
        polled("listener-gone", queued, POLLIN);
        call("recv-queued", recv(queued, buf, sizeof buf, 0));
        close(queued);
        return 0;
    }
    if (!strcmp(mode, "listen-buffers")) {
        /* SO_SNDBUF on the sender and SO_RCVBUF on the listener, set
           before the connection, bound what a sender that nobody reads
           fits in. Linux's exact counts hang on its window and per-segment
           accounting, so only their range shows, and that the two queues
           (SIOCOUTQ, FIONREAD) hold all that was sent. */
        static const struct {
            int bytes;
            long above, at_most;
        } sizes[] = {{4096, 0, 16384}, {16384, 16384, 65536}, {65536, 65536, 300000}, {0, 400000, 1L << 30}};
        for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
            int bytes = sizes[i].bytes, port, result;
            int l = tcp(0);
            if (bytes) setsockopt(l, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof bytes);
            struct sockaddr_in a = to(0);
            bind(l, (void *)&a, sizeof a);
            listen(l, 1);
            port = port_of(l);
            int c = tcp(0);
            if (bytes) setsockopt(c, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof bytes);
            a = to(port);
            result = connect(c, (void *)&a, sizeof a);
            int s = accept(l, NULL, NULL);
            long sent = fill(c);
            int outq = -1, inq = -1;
            ioctl(c, SIOCOUTQ, &outq);
            ioctl(s, FIONREAD, &inq);
            printf("  buffers=%d connect=%d in-range=%d queues-hold-all=%d\n", bytes, result,
                   sent > sizes[i].above && sent <= sizes[i].at_most, outq + inq == sent);
            /* A reader moves it all along: a blocking 1 MiB send through
               the smallest buffers ends once a thread has read it. */
            if (bytes == 4096) {
                static char big[1 << 20];
                drained_fd = s;
                drained_expected = sent + (long)sizeof big;
                pthread_t reader;
                if (pthread_create(&reader, NULL, drain_later, NULL)) return 70;
                long wrote = send(c, big, sizeof big, 0);
                shutdown(c, SHUT_WR);
                void *all;
                pthread_join(reader, &all);
                printf("  wrote-all=%d read-all=%d\n", wrote == (long)sizeof big, all != NULL);
            }
            close(s);
            close(c);
            close(l);
        }
        return 0;
    }
    if (!strcmp(mode, "listen-linger")) {
        /* A nonzero linger time holds the close of a socket's last
           descriptor while what it sent waits for room in the peer, up to
           that time (tcp_close's sk_stream_wait_close); the bytes still go
           after it. */
        int port, result, status;
        int l = listener(8, &port);
        struct linger one = {1, 1}, five = {1, 5};
        /* The peer never reads: the close waits out the second, nonblocking
           as it is, and the peer has every byte after it. */
        int c = client(port, 0, &result);
        int s = accept(l, NULL, NULL);
        fcntl(s, F_SETFL, O_NONBLOCK);
        long sent = fill(s);
        call("linger", setsockopt(s, SOL_SOCKET, SO_LINGER, &one, sizeof one));
        long start = now_ms();
        call("close-full", close(s));
        printf("  held=%ld\n", seconds_since(start));
        printf("  all-received=%d\n", drain(c) == sent);
        close(c);
        /* Another descriptor keeps the socket open: only the last close
           waits. */
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        sent = fill(s);
        setsockopt(s, SOL_SOCKET, SO_LINGER, &one, sizeof one);
        int d = dup(s);
        start = now_ms();
        close(s);
        printf("  held-dup=%ld\n", seconds_since(start));
        start = now_ms();
        close(d);
        printf("  held-last=%ld\n", seconds_since(start));
        printf("  all-received-last=%d\n", drain(c) == sent);
        close(c);
        /* The peer reads it all in another thread after 300 ms: the close
           ends then, well before its five seconds. How long it waited is not
           compared with the 300 ms: the emulated side runs on a virtual
           clock, which the reader's sleep moves for the closing thread too,
           maybe before the close looks at it (docs/design/quality.md). */
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        sent = fill(s);
        setsockopt(s, SOL_SOCKET, SO_LINGER, &five, sizeof five);
        drained_fd = c;
        drained_expected = sent;
        pthread_t reader;
        if (pthread_create(&reader, NULL, drain_later, NULL)) return 70;
        start = now_ms();
        call("close-read", close(s));
        long held = now_ms() - start;
        printf("  ended-before-time=%d\n", held < 2000);
        void *all;
        pthread_join(reader, &all);
        printf("  reader-received-all=%d\n", all != NULL);
        close(c);
        /* A signal ends the wait, and the close still succeeds. */
        struct sigaction sa = {.sa_handler = on_alarm};
        sigaction(SIGALRM, &sa, NULL);
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        sent = fill(s);
        setsockopt(s, SOL_SOCKET, SO_LINGER, &five, sizeof five);
        struct itimerval timer = {.it_value = {0, 300000}};
        setitimer(ITIMER_REAL, &timer, NULL);
        start = now_ms();
        call("close-signal", close(s));
        held = now_ms() - start;
        printf("  held-until-signal=%d alarms=%d\n", held >= 200 && held < 2000, (int)alarms);
        printf("  all-received-signal=%d\n", drain(c) == sent);
        close(c);
        /* Unread input resets the connection instead, with no wait. */
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        sent = fill(s);
        send(c, "x", 1, 0);
        polled("unread", s, POLLIN);
        setsockopt(s, SOL_SOCKET, SO_LINGER, &five, sizeof five);
        start = now_ms();
        call("close-unread", close(s));
        printf("  held-unread=%ld\n", seconds_since(start));
        close(c);
        /* Nothing left to send: no wait. */
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        send(s, "abc", 3, 0);
        polled("sent", c, POLLIN);
        setsockopt(s, SOL_SOCKET, SO_LINGER, &five, sizeof five);
        start = now_ms();
        call("close-sent", close(s));
        printf("  held-sent=%ld\n", seconds_since(start));
        close(c);
        /* dup2 over the last descriptor closes it with the same wait. */
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        sent = fill(s);
        setsockopt(s, SOL_SOCKET, SO_LINGER, &one, sizeof one);
        int other = tcp(0);
        start = now_ms();
        call("dup2", dup2(other, s) == s ? 0 : -1);
        printf("  held-dup2=%ld\n", seconds_since(start));
        printf("  all-received-dup2=%d\n", drain(c) == sent);
        close(other);
        close(s);
        close(c);
        /* A process that exits does not wait (PF_EXITING). */
        int sync[2];
        if (pipe(sync)) return 71;
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        sent = fill(s);
        setsockopt(s, SOL_SOCKET, SO_LINGER, &five, sizeof five);
        pid_t child = fork();
        if (!child) {
            if (read(sync[0], buf, 1) != 1) _exit(2);
            _exit(0);
        }
        close(s);
        start = now_ms();
        if (write(sync[1], "x", 1) != 1) return 72;
        waitpid(child, &status, 0);
        printf("  held-exit=%ld\n", seconds_since(start));
        printf("  all-received-exit=%d\n", drain(c) == sent);
        close(c);
        /* execve closes a close-on-exec socket as close does, waiting
           before the new program starts, which drains the peer. */
        if (argc < 5) return 98;
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        sent = fill(s);
        setsockopt(s, SOL_SOCKET, SO_LINGER, &one, sizeof one);
        fcntl(s, F_SETFD, FD_CLOEXEC);
        char peer[16], bytes[32], since[32];
        snprintf(peer, sizeof peer, "%d", c);
        snprintf(bytes, sizeof bytes, "%ld", sent);
        snprintf(since, sizeof since, "%ld", now_ms());
        char *again[] = {"network", "linger-exec", argv[2], argv[3], argv[4], peer, bytes, since, NULL};
        execv(argv[4], again);
        printf("  exec errno=%d\n", errno);
        return 1;
    }
    if (!strcmp(mode, "linger-exec")) {
        /* After listen-linger's execve: the peer, the bytes sent and when. */
        if (argc < 8) return 98;
        int c = atoi(argv[5]);
        long sent = atol(argv[6]);
        printf("  held-exec=%ld\n", seconds_since(atol(argv[7])));
        printf("  all-received-exec=%d\n", drain(c) == sent);
        return 0;
    }
    if (!strcmp(mode, "listen-fork")) {
        /* A child connects to its parent's listener, which a blocking
           accept waits on. */
        int port;
        int l = listener(1, &port);
        pid_t child = fork();
        if (child == 0) {
            usleep(100000);
            int result;
            int c = client(port, 0, &result);
            if (result) _exit(1);
            send(c, "from child", 10, 0);
            shutdown(c, SHUT_WR);
            n = recv(c, buf, 5, MSG_WAITALL);
            _exit(n == 5 && !memcmp(buf, "reply", 5) ? 0 : 2);
        }
        int s = accept(l, NULL, NULL);
        printf("  accept-ok=%d\n", s >= 0);
        n = recv(s, buf, sizeof buf, MSG_WAITALL);
        print_bytes("recv", buf, n);
        call("reply", send(s, "reply", 5, 0));
        int status;
        waitpid(child, &status, 0);
        printf("  child exited=%d status=%d\n", WIFEXITED(status), WEXITSTATUS(status));
        close(s);
        close(l);
        return 0;
    }
    if (!strcmp(mode, "listen-v6")) {
        /* IPv6 listeners: one on every address takes IPv4 connections too,
           with IPv4-mapped addresses; an IPv6-only one does not. */
        int l = socket(AF_INET6, SOCK_STREAM, 0);
        struct sockaddr_in6 any = {.sin6_family = AF_INET6};
        call("bind", bind(l, (void *)&any, sizeof any));
        call("listen", listen(l, 4));
        int port = port_of(l);
        int result;
        int c4 = client(port, 0, &result);
        printf("  v4 connect errno=%d\n", result);
        struct sockaddr_in6 peer;
        socklen_t len = sizeof peer;
        int s = accept(l, (void *)&peer, &len);
        printf("  accept family=%d len=%u mapped=%d\n", peer.sin6_family, (unsigned)len,
               IN6_IS_ADDR_V4MAPPED(&peer.sin6_addr));
        struct sockaddr_in6 mine;
        len = sizeof mine;
        getsockname(s, (void *)&mine, &len);
        printf("  server mapped=%d last=%#x port-ok=%d\n", IN6_IS_ADDR_V4MAPPED(&mine.sin6_addr),
               ntohl(mine.sin6_addr.s6_addr32[3]), ntohs(mine.sin6_port) == port);
        close(s);
        close(c4);
        int c6 = socket(AF_INET6, SOCK_STREAM, 0);
        struct sockaddr_in6 one = {.sin6_family = AF_INET6, .sin6_port = htons(port), .sin6_addr = in6addr_loopback};
        call("v6 connect", connect(c6, (void *)&one, sizeof one));
        len = sizeof peer;
        s = accept(l, (void *)&peer, &len);
        printf("  accept family=%d loopback=%d\n", peer.sin6_family, IN6_IS_ADDR_LOOPBACK(&peer.sin6_addr));
        len = sizeof mine;
        getsockname(c6, (void *)&mine, &len);
        printf("  client loopback=%d same-port=%d\n", IN6_IS_ADDR_LOOPBACK(&mine.sin6_addr),
               mine.sin6_port == peer.sin6_port);
        close(s);
        close(c6);
        /* The port on every address covers IPv4 binds too. */
        int b4 = tcp(0);
        bind_to("v4-beside-dual", b4, htonl(INADDR_LOOPBACK), port);
        close(b4);
        close(l);
        /* An IPv6-only bind does not conflict with IPv4 ones, so the port
           Linux hands it may be one where some other IPv4 socket on the
           host listens (the test's own server, say), and the IPv4 steps
           below would reach that one. Take a port no IPv4 socket holds:
           try again while an IPv4 bind to it on every address fails, or
           while it is the server's port or the closed one. The emulator's
           loopback is the guest's own, so the bind there does not see the
           server, but an IPv4 connect to its port reaches it on the host.
           The steps are printed once, for the socket that is kept. */
        int only, set_r, set_e, got, bind_r, bind_e;
        for (int tries = 0;; tries++) {
            only = socket(AF_INET6, SOCK_STREAM, 0);
            int on = 1;
            errno = 0;
            set_r = setsockopt(only, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on);
            set_e = errno;
            got = -7;
            socklen_t got_len = sizeof got;
            getsockopt(only, IPPROTO_IPV6, IPV6_V6ONLY, &got, &got_len);
            errno = 0;
            bind_r = bind(only, (void *)&any, sizeof any);
            bind_e = bind_r < 0 ? errno : 0;
            if (bind_r || tries == 99)
                break;
            int candidate = port_of(only);
            int probe = tcp(0);
            struct sockaddr_in every = {.sin_family = AF_INET, .sin_port = htons(candidate)};
            int free4 = !bind(probe, (void *)&every, sizeof every) && candidate != open_port &&
                        candidate != closed_port;
            close(probe);
            if (free4)
                break;
            close(only);
        }
        printf("  set v6only=%d errno=%d got=%d\n", set_r, set_e, got);
        printf("  only-bind=%d errno=%d\n", bind_r, bind_e);
        set_option("v6only-bound", only, IPPROTO_IPV6, IPV6_V6ONLY, 0);
        call("only-listen", listen(only, 4));
        int only_port = port_of(only);
        c4 = client(only_port, 0, &result);
        printf("  v4 to v6-only errno=%d\n", result);
        close(c4);
        b4 = tcp(0);
        bind_to("v4-beside-v6-only", b4, htonl(INADDR_LOOPBACK), only_port);
        close(b4);
        close(only);
        int m = socket(AF_INET6, SOCK_STREAM, 0);
        struct sockaddr_in6 mapped = {.sin6_family = AF_INET6};
        mapped.sin6_addr.s6_addr[10] = 0xff;
        mapped.sin6_addr.s6_addr[11] = 0xff;
        mapped.sin6_addr.s6_addr32[3] = htonl(INADDR_LOOPBACK);
        call("bind-mapped", bind(m, (void *)&mapped, sizeof mapped));
        close(m);
        m = socket(AF_INET6, SOCK_STREAM, 0);
        set_option("v6only", m, IPPROTO_IPV6, IPV6_V6ONLY, 1);
        call("bind-mapped-v6-only", bind(m, (void *)&mapped, sizeof mapped));
        struct sockaddr_in6 foreign = {.sin6_family = AF_INET6};
        inet_pton(AF_INET6, "2001:db8::1", &foreign.sin6_addr);
        call("bind-foreign", bind(m, (void *)&foreign, sizeof foreign));
        call("bind-short", bind(m, (void *)&any, 16));
        struct sockaddr_in four = to(0);
        call("bind-v4-family", bind(m, (void *)&four, sizeof mapped));
        close(m);
        return 0;
    }
    if (!strcmp(mode, "udp")) {
        /* UDP on the loopback: datagrams and their senders, truncation and
           peeking, a connected socket's filter and the loopback's ICMP
           answer to it, the size limit, SO_REUSEADDR and a dual-stack
           receiver. */
        int a = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in addr = to(0);
        call("bind", bind(a, (void *)&addr, sizeof addr));
        int port = port_of(a);
        printf("  port-ok=%d\n", port != 0);
        ready("idle", a, POLLIN | POLLOUT);
        int b = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in dst = to(port);
        call("sendto", sendto(b, "hello", 5, 0, (void *)&dst, sizeof dst));
        struct sockaddr_in bn;
        socklen_t len = sizeof bn;
        getsockname(b, (void *)&bn, &len);
        printf("  sender family=%d addr=%#x port-ok=%d\n", bn.sin_family, ntohl(bn.sin_addr.s_addr),
               ntohs(bn.sin_port) != 0);
        ready("arrived", a, POLLIN | POLLOUT);
        call("send-empty", sendto(b, "", 0, 0, (void *)&dst, sizeof dst));
        call("send-ten", sendto(b, "0123456789", 10, 0, (void *)&dst, sizeof dst));
        int queued = -1;
        ioctl(a, FIONREAD, &queued);
        printf("  fionread=%d\n", queued);
        struct sockaddr_in from;
        len = sizeof from;
        n = recvfrom(a, buf, sizeof buf, 0, (void *)&from, &len);
        print_bytes("recvfrom", buf, n);
        printf("  from-is-sender=%d len=%u addr=%#x\n", from.sin_port == bn.sin_port, (unsigned)len,
               ntohl(from.sin_addr.s_addr));
        call("recv-empty", recv(a, buf, sizeof buf, 0));
        call("recv-trunc", recv(a, buf, 4, MSG_TRUNC));
        call("recv-dontwait", recv(a, buf, 1, MSG_DONTWAIT));
        sendto(b, "abcdef", 6, 0, (void *)&dst, sizeof dst);
        struct iovec iov = {buf, 3};
        struct msghdr mh = {.msg_iov = &iov, .msg_iovlen = 1};
        n = recvmsg(a, &mh, 0);
        printf("  recvmsg=%ld trunc=%d\n", n, (mh.msg_flags & MSG_TRUNC) != 0);
        sendto(b, "peek", 4, 0, (void *)&dst, sizeof dst);
        n = recv(a, buf, sizeof buf, MSG_PEEK);
        print_bytes("peeked", buf, n);
        n = recv(a, buf, sizeof buf, 0);
        print_bytes("taken", buf, n);
        /* Connected, a socket takes datagrams only from its peer, and sends
           to it without an address. */
        struct sockaddr_in peer = to(ntohs(bn.sin_port));
        call("connect", connect(a, (void *)&peer, sizeof peer));
        len = sizeof peer;
        call("getpeername", getpeername(a, (void *)&peer, &len));
        printf("  peer-is-sender=%d addr=%#x\n", peer.sin_port == bn.sin_port, ntohl(peer.sin_addr.s_addr));
        int c = socket(AF_INET, SOCK_DGRAM, 0);
        call("stranger", sendto(c, "stranger", 8, 0, (void *)&dst, sizeof dst));
        call("friend", sendto(b, "friend", 6, 0, (void *)&dst, sizeof dst));
        n = recv(a, buf, sizeof buf, 0);
        print_bytes("connected-recv", buf, n);
        call("recv-none", recv(a, buf, sizeof buf, MSG_DONTWAIT));
        call("send-to-peer", send(a, "back", 4, 0));
        n = recv(b, buf, sizeof buf, 0);
        print_bytes("sender-recv", buf, n);
        call("send-unconnected", send(c, "x", 1, 0));
        /* A port nothing takes: the loopback answers a connected socket's
           datagram with ICMP, which its next call gives, once. */
        int gone = socket(AF_INET, SOCK_DGRAM, 0);
        bind(gone, (void *)&addr, sizeof addr);
        int gone_port = port_of(gone);
        close(gone);
        int d = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in closed = to(gone_port);
        call("connect-closed", connect(d, (void *)&closed, sizeof closed));
        len = sizeof bn;
        getsockname(d, (void *)&bn, &len);
        printf("  closed source=%#x port-ok=%d\n", ntohl(bn.sin_addr.s_addr), ntohs(bn.sin_port) != 0);
        call("send-closed", send(d, "x", 1, 0));
        ready("refused", d, POLLIN | POLLOUT);
        /* A send too big fails before it would take the error. */
        static char huge[65508];
        call("send-too-big-refused", send(d, huge, sizeof huge, 0));
        call("send-refused", send(d, "x", 1, 0));
        call("send-again", send(d, "x", 1, 0));
        call("recv-refused", recv(d, buf, sizeof buf, MSG_DONTWAIT));
        call("recv-after", recv(d, buf, sizeof buf, MSG_DONTWAIT));
        call("unconnected-closed", sendto(c, "x", 1, 0, (void *)&closed, sizeof closed));
        option("unconnected-error", c, SOL_SOCKET, SO_ERROR);
        /* The most a datagram holds over IPv4. */
        static char big[65508];
        call("send-most", sendto(b, big, 65507, 0, (void *)&dst, sizeof dst));
        call("send-too-big", sendto(b, big, 65508, 0, (void *)&dst, sizeof dst));
        call("recv-most", recv(a, big, sizeof big, 0));
        /* AF_UNSPEC disconnects: the address the guest named stays, but
           the port it let bind choose goes, so nothing reaches it there. */
        struct sockaddr unspec = {.sa_family = AF_UNSPEC};
        call("disconnect", connect(a, &unspec, sizeof unspec));
        len = sizeof peer;
        call("getpeername-after", getpeername(a, (void *)&peer, &len));
        len = sizeof bn;
        getsockname(a, (void *)&bn, &len);
        printf("  after-disconnect addr=%#x port=%d\n", ntohl(bn.sin_addr.s_addr), ntohs(bn.sin_port));
        call("stranger-again", sendto(c, "now", 3, 0, (void *)&dst, sizeof dst));
        call("recv-unbound", recv(a, buf, sizeof buf, MSG_DONTWAIT));
        /* Its next send binds a port on that address. */
        call("send-rebinds", sendto(a, "re", 2, 0, (void *)&dst, sizeof dst));
        len = sizeof bn;
        getsockname(a, (void *)&bn, &len);
        printf("  rebound addr=%#x port-ok=%d\n", ntohl(bn.sin_addr.s_addr), ntohs(bn.sin_port) != 0);
        /* SO_REUSEADDR shares a port; the last to bind takes the datagram. */
        int r1 = socket(AF_INET, SOCK_DGRAM, 0), r2 = socket(AF_INET, SOCK_DGRAM, 0),
            r3 = socket(AF_INET, SOCK_DGRAM, 0);
        set_option("reuse-1", r1, SOL_SOCKET, SO_REUSEADDR, 1);
        set_option("reuse-2", r2, SOL_SOCKET, SO_REUSEADDR, 1);
        bind_to("reuse-bind-1", r1, htonl(INADDR_LOOPBACK), 0);
        int shared = port_of(r1);
        bind_to("reuse-bind-2", r2, htonl(INADDR_LOOPBACK), shared);
        bind_to("no-reuse-bind", r3, htonl(INADDR_LOOPBACK), shared);
        struct sockaddr_in to_shared = to(shared);
        sendto(c, "who", 3, 0, (void *)&to_shared, sizeof to_shared);
        ready("first-bound", r1, POLLIN);
        ready("last-bound", r2, POLLIN);
        /* A TCP port is not a UDP one. Natively the guest shares the
           runner's network with the cases running beside it, so a UDP socket
           there may already hold the port the listener took. Only a failure
           while /proc/net/udp or udp6 lists such a socket takes another
           listener's port; any other result is printed as it came. */
        int t, l, r, err;
        for (int taken = 0;; taken++) {
            l = listener(1, &t);
            struct sockaddr_in on_tcp = to(t);
            r = bind(r3, (void *)&on_tcp, sizeof on_tcp);
            err = errno;
            if (!(r < 0 && err == EADDRINUSE && taken < 64 && udp_port_held(t))) break;
            close(l);
        }
        printf("  udp-on-tcp-port=%d errno=%d\n", r, r < 0 ? err : 0);
        close(l);
        /* An IPv6 socket on every address takes IPv4 datagrams, with the
           sender IPv4-mapped. */
        int s6 = socket(AF_INET6, SOCK_DGRAM, 0);
        struct sockaddr_in6 any6 = {.sin6_family = AF_INET6};
        call("bind-v6", bind(s6, (void *)&any6, sizeof any6));
        struct sockaddr_in to6 = to(port_of(s6));
        call("send-v6", sendto(c, "v4", 2, 0, (void *)&to6, sizeof to6));
        struct sockaddr_in6 f6;
        len = sizeof f6;
        n = recvfrom(s6, buf, sizeof buf, 0, (void *)&f6, &len);
        printf("  v6 recv=%ld family=%d len=%u mapped=%d\n", n, f6.sin6_family, (unsigned)len,
               IN6_IS_ADDR_V4MAPPED(&f6.sin6_addr));
        return 0;
    }
    if (!strcmp(mode, "udp-elsewhere")) {
        /* connect of a UDP socket to an address off the loopback binds a
           port first (inet_autobind), which then moves to the route's source
           address (ip_route_connect), takes no datagram from the loopback,
           and is held until AF_UNSPEC gives it back. The address itself is
           the machine's, so only how it compares is printed. */
        int u = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in far = {.sin_family = AF_INET, .sin_port = htons(9)};
        far.sin_addr.s_addr = htonl(0xc0000201);
        call("connect", connect(u, (void *)&far, sizeof far));
        int port = port_of(u);
        printf("  port-ok=%d\n", port != 0);
        struct sockaddr_in source, again;
        socklen_t source_len = sizeof source;
        getsockname(u, (void *)&source, &source_len);
        in_addr_t ip = ntohl(source.sin_addr.s_addr);
        printf("  source-specific=%d\n", ip != 0 && ip >> 24 != 127);
        int probe = socket(AF_INET, SOCK_DGRAM, 0);
        connect(probe, (void *)&far, sizeof far);
        source_len = sizeof again;
        getsockname(probe, (void *)&again, &source_len);
        printf("  same-source=%d\n", again.sin_addr.s_addr == source.sin_addr.s_addr);
        close(probe);
        /* The port is held on that address only. */
        int beside = socket(AF_INET, SOCK_DGRAM, 0);
        bind_to("bind-loopback", beside, htonl(INADDR_LOOPBACK), port);
        close(beside);
        struct sockaddr_in peer;
        socklen_t len = sizeof peer;
        call("getpeername", getpeername(u, (void *)&peer, &len));
        printf("  peer addr=%#x port=%d\n", ntohl(peer.sin_addr.s_addr), ntohs(peer.sin_port));
        int other = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in here = to(port);
        call("send-loopback", sendto(other, "x", 1, 0, (void *)&here, sizeof here));
        call("recv-none", recv(u, buf, sizeof buf, MSG_DONTWAIT));
        int taker = socket(AF_INET, SOCK_DGRAM, 0);
        bind_to("bind-held", taker, htonl(INADDR_ANY), port);
        struct sockaddr unspec = {.sa_family = AF_UNSPEC};
        call("disconnect", connect(u, &unspec, sizeof unspec));
        printf("  after-disconnect port=%d\n", port_of(u));
        bind_to("bind-freed", taker, htonl(INADDR_ANY), port);
        /* An IPv6-only socket has no route to an IPv4-mapped address, but
           took its port first. */
        int v6 = socket(AF_INET6, SOCK_DGRAM, 0);
        set_option("v6only", v6, IPPROTO_IPV6, IPV6_V6ONLY, 1);
        struct sockaddr_in6 mapped = {.sin6_family = AF_INET6, .sin6_port = htons(9)};
        mapped.sin6_addr.s6_addr[10] = mapped.sin6_addr.s6_addr[11] = 0xff;
        memcpy(&mapped.sin6_addr.s6_addr[12], "\xc0\x00\x02\x01", 4);
        call("connect-mapped", connect(v6, (void *)&mapped, sizeof mapped));
        printf("  mapped port-ok=%d\n", port_of(v6) != 0);
        return 0;
    }
    if (!strcmp(mode, "udp-rcvbuf")) {
        /* How many datagrams a UDP socket's receive buffer takes: each
           counts its sk_buff's truesize, and one that would take the buffer
           past SO_RCVBUF while another waits is dropped
           (__udp_enqueue_schedule_skb). SO_RCVBUF is doubled, and at least
           2304; past rmem_max, which a machine may raise, it is not tried. */
        static char data[65536];
        int asked[] = {0, 1024, 4096, 10000, 100000};
        for (unsigned i = 0; i < sizeof asked / sizeof *asked; i++) {
            int u = socket(AF_INET, SOCK_DGRAM, 0), got;
            socklen_t len = sizeof got;
            setsockopt(u, SOL_SOCKET, SO_RCVBUF, &asked[i], sizeof asked[i]);
            getsockopt(u, SOL_SOCKET, SO_RCVBUF, &got, &len);
            printf("  rcvbuf %d -> %d\n", asked[i], got);
            close(u);
        }
        /* 100000, doubled to 200000: three 65500-byte datagrams over IPv4,
           two over IPv6, which sends them as two fragments. */
        int buffers[] = {1024, 2048, 4096, 10000, 100000};
        int sizes[] = {0, 100, 261, 262, 645, 646, 1000, 3000, 9000, 16004, 16005, 30000, 65500};
        for (int v6 = 0; v6 < 2; v6++)
            for (unsigned b = 0; b < sizeof buffers / sizeof *buffers; b++)
                for (unsigned k = 0; k < sizeof sizes / sizeof *sizes; k++) {
                    int family = v6 ? AF_INET6 : AF_INET;
                    int r = socket(family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
                    int s = socket(family, SOCK_DGRAM, 0);
                    setsockopt(r, SOL_SOCKET, SO_RCVBUF, &buffers[b], sizeof buffers[b]);
                    struct sockaddr_storage at = {0};
                    socklen_t len;
                    if (v6) {
                        struct sockaddr_in6 *a = (void *)&at;
                        a->sin6_family = AF_INET6;
                        a->sin6_addr = in6addr_loopback;
                        len = sizeof *a;
                    } else {
                        struct sockaddr_in *a = (void *)&at;
                        a->sin_family = AF_INET;
                        a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                        len = sizeof *a;
                    }
                    bind(r, (void *)&at, len);
                    getsockname(r, (void *)&at, &len);
                    for (int n = 0; n < 64; n++) sendto(s, data, sizes[k], 0, (void *)&at, len);
                    usleep(2000);
                    int fit = 0;
                    while (recv(r, data, sizeof data, 0) >= 0) fit++;
                    printf("  v6=%d rcvbuf=%d size=%d fit=%d\n", v6, buffers[b], sizes[k], fit);
                    close(r);
                    close(s);
                }
        return 0;
    }
    if (!strcmp(mode, "tcp-timestamp")) {
        /* TCP's timestamps, as Linux's tcp_recvmsg gives them
           (tcp_recv_timestamp): a read, a peek or an empty one with bytes
           waiting gets the time the segment it read came, and a segment
           joined to the unread one before it (tcp_try_coalesce) gives that
           its own time; the end of input gets none. On the guest's own
           loopback, where a segment comes as it is sent, and through the
           host's (the echo server), where it comes between the send and
           the read. The keeper makes Linux stamp every segment, as in
           udp-timestamp. */
        int keeper = socket(AF_INET, SOCK_DGRAM, 0), one = 1;
        setsockopt(keeper, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof one);
        usleep(200000);
        int l = tcp(0);
        struct sockaddr_in la = to(0);
        socklen_t ll = sizeof la;
        bind(l, (void *)&la, ll);
        listen(l, 1);
        getsockname(l, (void *)&la, &ll);
        int c = tcp(0);
        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        connect(c, (void *)&la, ll);
        int a = accept(l, NULL, NULL);
        long long from;
        puts("loopback");
        from = real_ns();
        send(c, "ab", 2, 0);
        tcp_stamped("none", a, 8, 256, 0, from);
        stamp_option("ns-old", a, TS_NS_OLD, 1);
        from = real_ns();
        send(c, "ab", 2, 0);
        usleep(2000);
        tcp_stamped("ns-old", a, 8, 256, 0, from);
        /* Two sends, the second joined to the first while it is unread. */
        send(c, "cd", 2, 0);
        usleep(2000);
        from = real_ns();
        send(c, "ef", 2, 0);
        usleep(2000);
        tcp_stamped("peek", a, 1, 256, MSG_PEEK, from);
        tcp_stamped("empty", a, 0, 256, 0, from);
        tcp_stamped("first", a, 1, 256, 0, from);
        tcp_stamped("rest", a, 8, 256, 0, from);
        /* Taken after the bytes came: the time they came all the same. */
        stamp_option("off", a, TS_NS_OLD, 0);
        from = real_ns();
        send(c, "g", 1, 0);
        usleep(2000);
        stamp_option("old", a, TS_OLD, 1);
        tcp_stamped("old", a, 8, 256, 0, from);
        stamp_option("new", a, TS_NEW, 1);
        send(c, "h", 1, 0);
        usleep(2000);
        tcp_stamped("new", a, 8, 256, 0, from);
        /* SO_TIMESTAMPING with it, and alone. */
        stamp_option("tsg-old", a, TSG_OLD, 0x18);
        send(c, "i", 1, 0);
        usleep(2000);
        tcp_stamped("both", a, 8, 256, 0, from);
        stamp_option("ts-off", a, TS_NEW, 0);
        const int reports[] = {0x18, 0x10, 0x08, 0x10 | (1 << 17), 0};
        for (int i = 0; i < 5; i++) {
            stamp_option("report", a, TSG_OLD, reports[i]);
            send(c, "j", 1, 0);
            usleep(2000);
            tcp_stamped("report", a, 8, 256, 0, from);
        }
        /* A control buffer that holds less cuts it; none at all only says so. */
        stamp_option("ns-old", a, TS_NS_OLD, 1);
        const size_t rooms[] = {0, 8, 16, 32};
        for (int i = 0; i < 4; i++) {
            send(c, "k", 1, 0);
            usleep(2000);
            char label[16];
            snprintf(label, sizeof label, "room%zu", rooms[i]);
            tcp_stamped(label, a, 8, rooms[i], 0, from);
        }
        /* The end of input. */
        shutdown(c, SHUT_WR);
        usleep(2000);
        tcp_stamped("end", a, 8, 256, 0, from);
        close(a);
        close(c);
        close(l);
        puts("host");
        c = connected('e');
        stamp_option("ns-old", c, TS_NS_OLD, 1);
        from = real_ns();
        send(c, "hi", 2, 0);
        struct pollfd p = {c, POLLIN, 0};
        poll(&p, 1, 5000);
        usleep(2000);
        tcp_stamped("echo", c, 8, 256, 0, from);
        shutdown(c, SHUT_WR);
        poll(&p, 1, 5000);
        tcp_stamped("end", c, 8, 256, 0, from);
        close(c);
        close(keeper);
        return 0;
    }
    if (!strcmp(mode, "udp-timestamp")) {
        /* SO_TIMESTAMP, its kin and SO_TIMESTAMPING on inet sockets, as
           Linux's sock.c and udp_recvmsg (sock_recv_timestamp) have them: a
           UDP datagram carries the time it came, whatever the receiver took
           then, given as each option asks. Linux stamps a datagram as it
           comes only while some socket on the machine takes timestamps
           (netstamp_needed), which the keeper here makes sure of, waiting
           for the kernel to turn that on; the emulator always does. TCP's
           options are set and read back only. */
        int keeper = socket(AF_INET, SOCK_DGRAM, 0), one = 1;
        setsockopt(keeper, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof one);
        usleep(200000);
        int r = socket(AF_INET, SOCK_DGRAM, 0), s = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in at = to(0);
        socklen_t len = sizeof at;
        bind(r, (void *)&at, len);
        getsockname(r, (void *)&at, &len);
        connect(s, (void *)&at, len);
        long long sent;
#define STAMP_SEND() do { send(s, "u", 1, 0); sent = real_ns(); } while (0)
        puts("udp");
        stamp_options("none", r);
        STAMP_SEND();
        receive_stamped("none", r, 256, 0, sent);
        /* Taken after the datagram came: the time it came all the same. */
        STAMP_SEND();
        stamp_option("old", r, TS_OLD, 1);
        stamp_options("old", r);
        receive_stamped("old", r, 256, 0, sent);
        stamp_option("ns-old", r, TS_NS_OLD, 1);
        STAMP_SEND();
        receive_stamped("peek", r, 256, MSG_PEEK, sent);
        usleep(2000);
        receive_stamped("ns-old", r, 256, 0, sent);
        stamp_option("new", r, TS_NEW, 1);
        STAMP_SEND();
        receive_stamped("new", r, 256, 0, sent);
        stamp_option("ns-new", r, TS_NS_NEW, 1);
        stamp_options("ns-new", r);
        STAMP_SEND();
        receive_stamped("ns-new", r, 256, 0, sent);
        /* With SO_TIMESTAMPING too, its SCM_TIMESTAMPING follows. */
        stamp_option("tsg-old", r, TSG_OLD, 0x18);
        stamp_options("tsg-old", r);
        STAMP_SEND();
        receive_stamped("both", r, 256, 0, sent);
        stamp_option("tsg-new", r, TSG_NEW, 0x18);
        STAMP_SEND();
        receive_stamped("both-new", r, 256, 0, sent);
        /* SO_TIMESTAMPING alone, which UDP gives unlike AF_UNIX: the
           software stamp unless filtered out. */
        stamp_option("ts-off", r, TS_OLD, 0);
        stamp_options("ts-off", r);
        const int reports[] = {0x18, 0x10, 0x08, 0x10 | (1 << 17), 0x18 | (1 << 17), 0};
        for (int i = 0; i < 6; i++) {
            stamp_option("report", r, TSG_OLD, reports[i]);
            STAMP_SEND();
            receive_stamped("report", r, 256, 0, sent);
        }
        /* A control buffer that holds less cuts it; none at all only says so. */
        stamp_option("ts-old", r, TS_OLD, 1);
        stamp_option("tsg-old", r, TSG_OLD, 0x10);
        const size_t rooms[] = {0, 8, 32, 40, 64, 88};
        for (int i = 0; i < 6; i++) {
            STAMP_SEND();
            char label[16];
            snprintf(label, sizeof label, "room%zu", rooms[i]);
            receive_stamped(label, r, rooms[i], 0, sent);
        }
        /* A plain read takes the datagram all the same. */
        STAMP_SEND();
        printf("  read=%ld\n", (long)read(r, buf, 1));
        close(r);
        close(s);
        /* TCP: OPT_ID needs a connection, which a socket closed or
           listening lacks; the rest is taken anywhere. */
        puts("tcp");
        int t = tcp(0);
        stamp_options("none", t);
        stamp_option("id", t, TSG_OLD, 0x18 | (1 << 7));
        stamp_option("plain", t, TSG_NEW, 0x18);
        stamp_option("ts-ns", t, TS_NS_OLD, 1);
        stamp_options("set", t);
        stamp_option("unknown", t, TSG_OLD, 1 << 19);
        stamp_option("stats", t, TSG_OLD, 1 << 12);
        stamp_option("bind-phc", t, TSG_OLD, 1 << 15);
        int l = tcp(0);
        struct sockaddr_in la = to(0);
        socklen_t ll = sizeof la;
        bind(l, (void *)&la, ll);
        listen(l, 1);
        stamp_option("listening-id", l, TSG_OLD, 1 << 7);
        getsockname(l, (void *)&la, &ll);
        connect(t, (void *)&la, ll);
        stamp_option("connected-id", t, TSG_OLD, (1 << 7) | (1 << 16));
        stamp_options("connected", t);
        int a = accept(l, NULL, NULL);
        stamp_options("accepted", a);
        stamp_option("accepted-id", a, TSG_OLD, 1 << 7);
        close(a);
        close(l);
        close(t);
        close(keeper);
        return 0;
    }
    if (!strcmp(mode, "scm-options")) {
        /* SO_PASSCRED, SO_PASSSEC, SO_PASSPIDFD and SO_PASSRIGHTS on inet
           sockets, which Linux's sock.c takes only on AF_UNIX: EOPNOTSUPP
           both ways, after the int setsockopt needs (EINVAL). */
        const int names[] = {16, 34, 76, 83};
        const int kinds[][2] = {{AF_INET, SOCK_STREAM}, {AF_INET, SOCK_DGRAM},
                                {AF_INET6, SOCK_STREAM}, {AF_INET6, SOCK_DGRAM}};
        for (int k = 0; k < 4; k++) {
            int fd = socket(kinds[k][0], kinds[k][1], 0);
            if (fd < 0) {
                perror("socket");
                return 1;
            }
            for (int i = 0; i < 4; i++) {
                int one = 1, got = -7;
                socklen_t len = sizeof got;
                errno = 0;
                long set = setsockopt(fd, SOL_SOCKET, names[i], &one, sizeof one);
                int set_errno = set < 0 ? errno : 0;
                errno = 0;
                long shorter = setsockopt(fd, SOL_SOCKET, names[i], &one, 2);
                int shorter_errno = shorter < 0 ? errno : 0;
                errno = 0;
                long get = getsockopt(fd, SOL_SOCKET, names[i], &got, &len);
                printf("family=%d type=%d option=%d set=%ld/%d short=%ld/%d get=%ld/%d got=%d\n",
                       kinds[k][0], kinds[k][1], names[i], set, set_errno, shorter, shorter_errno,
                       get, get < 0 ? errno : 0, got);
            }
            close(fd);
        }
        return 0;
    }
    if (!strcmp(mode, "udp-shutdown")) {
        /* shutdown of a UDP socket: ENOTCONN unless it is connected, but
           shut all the same. A receive that would wait then ends with 0,
           datagrams still come, a send is EPIPE with no SIGPIPE, and poll
           shows the ends. Another process's shutdown ends a waiting
           receive. */
        signal(SIGPIPE, on_pipe);
        int a = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in addr = to(0);
        bind(a, (void *)&addr, sizeof addr);
        int port = port_of(a);
        call("shutdown-rd", shutdown(a, SHUT_RD));
        ready("read-shut", a, POLLIN | POLLOUT | POLLRDHUP);
        call("recv", recv(a, buf, sizeof buf, 0));
        call("recv-dontwait", recv(a, buf, sizeof buf, MSG_DONTWAIT));
        struct sockaddr_in from;
        memset(&from, 0x55, sizeof from);
        socklen_t len = sizeof from;
        call("recvfrom", recvfrom(a, buf, sizeof buf, 0, (void *)&from, &len));
        printf("  len=%u\n", (unsigned)len);
        int b = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in dst = to(port);
        call("sendto", sendto(b, "still", 5, 0, (void *)&dst, sizeof dst));
        n = recv(a, buf, sizeof buf, 0);
        print_bytes("arrived", buf, n);
        call("read", read(a, buf, sizeof buf));
        call("shutdown-wr", shutdown(a, SHUT_WR));
        ready("both-shut", a, POLLIN | POLLOUT | POLLRDHUP);
        struct sockaddr_in to_b = to(port_of(b));
        static char big[65508];
        call("send-shut", sendto(a, "x", 1, 0, (void *)&to_b, sizeof to_b));
        call("send-empty-shut", sendto(a, "", 0, 0, (void *)&to_b, sizeof to_b));
        call("send-too-big-shut", sendto(a, big, sizeof big, 0, (void *)&to_b, sizeof to_b));
        call("send-nosignal", sendto(a, "x", 1, MSG_NOSIGNAL, (void *)&to_b, sizeof to_b));
        call("write-unconnected", write(a, "x", 1));
        printf("  sigpipes=%d\n", (int)pipes);
        call("recv-b", recv(b, buf, sizeof buf, MSG_DONTWAIT));
        int c = socket(AF_INET, SOCK_DGRAM, 0);
        call("connect", connect(c, (void *)&to_b, sizeof to_b));
        call("connected-shutdown", shutdown(c, SHUT_WR));
        call("connected-send", send(c, "x", 1, 0));
        ready("connected", c, POLLIN | POLLOUT | POLLRDHUP);
        call("shutdown-bad", shutdown(c, 3));
        printf("  sigpipes=%d\n", (int)pipes);
        int w = socket(AF_INET, SOCK_DGRAM, 0);
        bind(w, (void *)&addr, sizeof addr);
        pid_t child = fork();
        if (child == 0) {
            usleep(200000);
            shutdown(w, SHUT_RD);
            _exit(0);
        }
        call("woken", recv(w, buf, sizeof buf, 0));
        int status;
        waitpid(child, &status, 0);
        return 0;
    }
    if (!strcmp(mode, "resolve")) {
        /* Name resolution through the guest's own resolver; run under the
           emulator only, with localhost allowed and nothing else. */
        struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM}, *found;
        int r = getaddrinfo("localhost", argv[2], &hints, &found);
        printf("  localhost=%d\n", r);
        if (r == 0) {
            struct sockaddr_in *a = (void *)found->ai_addr;
            printf("  addr=%#x port-ok=%d\n", ntohl(a->sin_addr.s_addr), ntohs(a->sin_port) == open_port);
            int fd = socket(found->ai_family, found->ai_socktype, 0);
            call("connect", connect(fd, found->ai_addr, found->ai_addrlen));
            send(fd, "eok", 3, 0);
            shutdown(fd, SHUT_WR);
            await_end(fd);
            n = read(fd, buf, sizeof buf);
            print_bytes("echo", buf, n);
            close(fd);
            freeaddrinfo(found);
        }
        printf("  blocked=%d\n", getaddrinfo("blocked.example", "80", &hints, &found) == EAI_NONAME);
        /* A loopback port the policy does not allow, where no guest socket
           listens, is refused. */
        int fd = tcp(0);
        struct sockaddr_in a = to(closed_port);
        call("connect-other-port", connect(fd, (void *)&a, sizeof a));
        close(fd);
        return 0;
    }
    return 98;
}
