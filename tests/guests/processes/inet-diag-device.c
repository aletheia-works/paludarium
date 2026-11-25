/* The devices sockets are bound to, as NETLINK_SOCK_DIAG tells of them
   (idiag_if), in a network namespace of its own (so as root), with lo (1)
   up and no other device: 1000 and 999 are indices of none, which
   SO_BINDTOIFINDEX takes. TCP sockets listening, closed with a port,
   connected, accepted and in TIME_WAIT, and UDP ones bound
   and connected, some bound to lo, to 1000 or to none, IPv4 and IPv6. Each is
   dumped, sorted by its line; then the dump's filter takes those bound to
   each device (INET_DIAG_BC_DEV_COND); then one socket is asked for at a
   time, as what comes in on the request's device finds it: not one bound to
   another device, and of two sharing a port with SO_REUSEPORT the one bound
   to the device before the one bound to none. A port the kernel picked is
   shown as "any". */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define NETLINK_SOCK_DIAG_ 4
#define SOCK_DIAG_BY_FAMILY 20
#define TCPDIAG_GETSOCK 18
#define NLM_F_REQUEST 1
#define NLM_F_DUMP 0x300
#define INET_DIAG_REQ_BYTECODE 1
#define BC_DEV_COND 9
#define SO_BINDTOIFINDEX_ 62
#define ALL 0x3fff

struct nl_address {
    unsigned short family;
    unsigned short pad;
    unsigned pid;
    unsigned groups;
};
struct nl_header {
    unsigned len;
    unsigned short type, flags;
    unsigned seq, pid;
};
struct sockid {
    unsigned short sport, dport;
    unsigned src[4], dst[4];
    unsigned device;
    unsigned cookie[2];
};
struct request {
    unsigned char family, protocol, ext, pad;
    unsigned states;
    struct sockid id;
};
struct old_request {
    unsigned char family, src_len, dst_len, ext;
    struct sockid id;
    unsigned states, dbs;
};
struct answer {
    unsigned char family, state, timer, retrans;
    struct sockid id;
    unsigned expires, rqueue, wqueue, uid, inode;
};

static int diag = -1;
static unsigned seq;

static long result(long r) { return r < 0 ? -errno : r; }

static void port(char *out, size_t len, unsigned short p) {
    if (ntohs(p) >= 32768)
        snprintf(out, len, "any");
    else
        snprintf(out, len, "%u", ntohs(p));
}
static void line(char *out, size_t len, const struct answer *a) {
    char src[64] = "-", dst[64] = "-", sport[16], dport[16];
    inet_ntop(a->family, a->id.src, src, sizeof src);
    inet_ntop(a->family, a->id.dst, dst, sizeof dst);
    port(sport, sizeof sport, a->id.sport);
    port(dport, sizeof dport, a->id.dport);
    snprintf(out, len, "family=%u state=%u %s %s -> %s %s if=%u", a->family, a->state, src, sport, dst, dport,
             a->id.device);
}
static int compare(const void *a, const void *b) { return strcmp(a, b); }

/* Sends the request `body` and prints its answers, sorted, or its error. */
static void ask(unsigned short type, unsigned short flags, const void *body, size_t len, const char *label) {
    static unsigned char buf[65536];
    static char lines[64][256];
    struct nl_header *h = (void *)buf;
    h->len = (unsigned)(sizeof *h + len);
    h->type = type;
    h->flags = NLM_F_REQUEST | flags;
    h->seq = ++seq;
    h->pid = 0;
    memcpy(buf + sizeof *h, body, len);
    struct nl_address kernel = {.family = AF_NETLINK};
    if (sendto(diag, buf, h->len, 0, (void *)&kernel, sizeof kernel) < 0) printf("%s: send=%d\n", label, -errno);
    size_t count = 0;
    int error = 0;
    for (int done = 0; !done;) {
        struct pollfd ready = {.fd = diag, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) {
            printf("%s: no answer\n", label);
            return;
        }
        long n = recv(diag, buf, sizeof buf, 0);
        if (n < 0) {
            printf("%s: recv=%d\n", label, -errno);
            return;
        }
        for (long at = 0; at + (long)sizeof *h <= n && !done;) {
            const struct nl_header *m = (const void *)(buf + at);
            if (m->len < sizeof *m || at + m->len > n) break;
            if (m->type == 2 || m->type == 3) {
                memcpy(&error, buf + at + sizeof *m, 4);
                done = 1;
            } else if (count < 64) {
                struct answer a;
                memcpy(&a, buf + at + sizeof *m, sizeof a);
                line(lines[count++], sizeof lines[0], &a);
                done = !(m->flags & 2);
            }
            at += (m->len + 3) & ~3u;
        }
    }
    qsort(lines, count, sizeof lines[0], compare);
    printf("%s: error=%d answers=%zu\n", label, error, count);
    for (size_t i = 0; i < count; i++) printf("  %s\n", lines[i]);
}
static void dump(int family, int protocol, unsigned states, const char *label) {
    struct request r = {.family = (unsigned char)family, .protocol = (unsigned char)protocol, .states = states};
    ask(SOCK_DIAG_BY_FAMILY, NLM_F_DUMP, &r, sizeof r, label);
}
static void filtered(int family, int protocol, unsigned device, const char *label) {
    struct {
        struct request r;
        unsigned short len, kind;
        struct {
            unsigned char code, yes;
            unsigned short no;
        } op;
        unsigned device;
    } m = {.r = {.family = (unsigned char)family, .protocol = (unsigned char)protocol, .states = ALL},
           .len = 12,
           .kind = INET_DIAG_REQ_BYTECODE,
           .op = {BC_DEV_COND, 8, 12},
           .device = device};
    ask(SOCK_DIAG_BY_FAMILY, NLM_F_DUMP, &m, sizeof m, label);
}
static struct sockid id(int family, const char *src, int sport, const char *dst, int dport, unsigned device) {
    struct sockid i = {.sport = htons((unsigned short)sport), .dport = htons((unsigned short)dport), .device = device,
                       .cookie = {~0u, ~0u}};
    inet_pton(family, src, i.src);
    inet_pton(family, dst, i.dst);
    return i;
}
static void one(int family, int protocol, const char *src, int sport, const char *dst, int dport, unsigned device) {
    struct request r = {.family = (unsigned char)family, .protocol = (unsigned char)protocol, .states = ALL,
                        .id = id(family, src, sport, dst, dport, device)};
    char label[160];
    snprintf(label, sizeof label, "%s %s %d -> %s %d if=%u", protocol == IPPROTO_TCP ? "tcp" : "udp", src, sport, dst,
             dport, device);
    ask(SOCK_DIAG_BY_FAMILY, 0, &r, sizeof r, label);
}

/* A socket of `family` and `type` bound to `device` (none for 0) and
   `ip` at `port_`. */
static int bound(int family, int type, unsigned device, const char *ip, int port_, int reuse) {
    int fd = socket(family, type, 0), yes = 1;
    long r = 0;
    if (reuse) setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof yes);
    if (device) r = result(setsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX_, &device, sizeof device));
    if (r) printf("bind to device %u=%ld\n", device, r);
    if (family == AF_INET) {
        struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port_)};
        inet_pton(AF_INET, ip, &a.sin_addr);
        r = result(bind(fd, (void *)&a, sizeof a));
    } else {
        struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)port_)};
        inet_pton(AF_INET6, ip, &a.sin6_addr);
        r = result(bind(fd, (void *)&a, sizeof a));
    }
    if (r) printf("bind %s %d device %u=%ld\n", ip, port_, device, r);
    return fd;
}
static int listener(int family, unsigned device, const char *ip, int port_, int reuse) {
    int fd = bound(family, SOCK_STREAM, device, ip, port_, reuse);
    long r = result(listen(fd, 8));
    if (r) printf("listen %s %d device %u=%ld\n", ip, port_, device, r);
    return fd;
}
static void to(int fd, int family, const char *ip, int port_) {
    long r;
    if (family == AF_INET) {
        struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port_)};
        inet_pton(AF_INET, ip, &a.sin_addr);
        r = result(connect(fd, (void *)&a, sizeof a));
    } else {
        struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)port_)};
        inet_pton(AF_INET6, ip, &a.sin6_addr);
        r = result(connect(fd, (void *)&a, sizeof a));
    }
    if (r) printf("connect %s %d=%ld\n", ip, port_, r);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "inet-diag-device")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int control = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr = {.ifr_name = "lo", .ifr_flags = IFF_UP};
    printf("up lo=%ld\n", result(ioctl(control, SIOCSIFFLAGS, &ifr)));
    close(control);
    diag = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG_);

    /* Listeners: two devices share a port; so do lo and none with
       SO_REUSEPORT. */
    int lo4 = listener(AF_INET, 1, "0.0.0.0", 7000, 0);
    listener(AF_INET, 1000, "0.0.0.0", 7000, 0);
    int any4 = listener(AF_INET, 0, "0.0.0.0", 7001, 0);
    listener(AF_INET, 0, "0.0.0.0", 7002, 1);
    listener(AF_INET, 1, "0.0.0.0", 7002, 1);
    int lo6 = listener(AF_INET6, 1, "::", 7003, 0);
    listener(AF_INET6, 1000, "::", 7004, 0);
    listener(AF_INET, 0, "127.0.0.1", 7005, 0);
    listener(AF_INET, 1000, "0.0.0.0", 7006, 0);
    /* Closed, with a port. */
    int closed = bound(AF_INET, SOCK_STREAM, 1000, "127.0.0.1", 7200, 0);
    bound(AF_INET6, SOCK_STREAM, 0, "::", 7201, 0);
    /* Connected. */
    int c1 = bound(AF_INET, SOCK_STREAM, 1, "127.0.0.1", 7100, 0);
    to(c1, AF_INET, "127.0.0.1", 7000);
    int s1 = accept(lo4, NULL, NULL);
    int c2 = bound(AF_INET, SOCK_STREAM, 0, "127.0.0.1", 7101, 0);
    to(c2, AF_INET, "127.0.0.1", 7001);
    int s2 = accept(any4, NULL, NULL);
    int c3 = bound(AF_INET6, SOCK_STREAM, 1, "::1", 7102, 0);
    to(c3, AF_INET6, "::1", 7003);
    int s3 = accept(lo6, NULL, NULL);
    /* Closed by its client first, so in TIME_WAIT. */
    int c5 = bound(AF_INET, SOCK_STREAM, 1, "127.0.0.1", 7104, 0);
    to(c5, AF_INET, "127.0.0.1", 7000);
    int s5 = accept(lo4, NULL, NULL);
    close(c5);
    close(s5);
    /* UDP. */
    bound(AF_INET, SOCK_DGRAM, 1, "0.0.0.0", 7000, 0);
    bound(AF_INET, SOCK_DGRAM, 1000, "0.0.0.0", 7000, 0);
    bound(AF_INET, SOCK_DGRAM, 0, "0.0.0.0", 7001, 0);
    bound(AF_INET, SOCK_DGRAM, 0, "0.0.0.0", 7002, 1);
    bound(AF_INET, SOCK_DGRAM, 1, "0.0.0.0", 7002, 1);
    bound(AF_INET6, SOCK_DGRAM, 1, "::", 7003, 0);
    int u = bound(AF_INET, SOCK_DGRAM, 1, "127.0.0.1", 7100, 0);
    to(u, AF_INET, "127.0.0.1", 7001);
    bound(AF_INET, SOCK_DGRAM, 1000, "127.0.0.1", 7006, 0);

    dump(AF_INET, IPPROTO_TCP, ALL, "tcp over IPv4");
    dump(AF_INET6, IPPROTO_TCP, ALL, "tcp over IPv6");
    dump(AF_INET, IPPROTO_UDP, ALL, "udp over IPv4");
    dump(AF_INET6, IPPROTO_UDP, ALL, "udp over IPv6");
    const unsigned devices[] = {0, 1, 1000, 999};
    for (size_t i = 0; i < 4; i++) {
        char label[64];
        snprintf(label, sizeof label, "tcp over IPv4 bound to %u", devices[i]);
        filtered(AF_INET, IPPROTO_TCP, devices[i], label);
        snprintf(label, sizeof label, "tcp over IPv6 bound to %u", devices[i]);
        filtered(AF_INET6, IPPROTO_TCP, devices[i], label);
        snprintf(label, sizeof label, "udp over IPv4 bound to %u", devices[i]);
        filtered(AF_INET, IPPROTO_UDP, devices[i], label);
        snprintf(label, sizeof label, "udp over IPv6 bound to %u", devices[i]);
        filtered(AF_INET6, IPPROTO_UDP, devices[i], label);
    }
    for (size_t i = 0; i < 4; i++) {
        unsigned d = devices[i];
        /* Listeners. */
        one(AF_INET, IPPROTO_TCP, "127.0.0.1", 7000, "127.0.0.1", 9999, d);
        one(AF_INET, IPPROTO_TCP, "127.0.0.1", 7001, "127.0.0.1", 9999, d);
        one(AF_INET, IPPROTO_TCP, "127.0.0.1", 7002, "127.0.0.1", 9999, d);
        one(AF_INET, IPPROTO_TCP, "127.0.0.1", 7003, "127.0.0.1", 9999, d);
        one(AF_INET6, IPPROTO_TCP, "::1", 7003, "::1", 9999, d);
        one(AF_INET6, IPPROTO_TCP, "::1", 7004, "::1", 9999, d);
        one(AF_INET, IPPROTO_TCP, "127.0.0.1", 7005, "127.0.0.1", 9999, d);
        one(AF_INET, IPPROTO_TCP, "127.0.0.1", 7006, "127.0.0.1", 9999, d);
        /* Connections. */
        one(AF_INET, IPPROTO_TCP, "127.0.0.1", 7100, "127.0.0.1", 7000, d);
        one(AF_INET, IPPROTO_TCP, "127.0.0.1", 7000, "127.0.0.1", 7100, d);
        one(AF_INET, IPPROTO_TCP, "127.0.0.1", 7101, "127.0.0.1", 7001, d);
        one(AF_INET6, IPPROTO_TCP, "::1", 7003, "::1", 7102, d);
        one(AF_INET, IPPROTO_TCP, "127.0.0.1", 7104, "127.0.0.1", 7000, d);
        /* UDP: from the source to the destination. */
        one(AF_INET, IPPROTO_UDP, "127.0.0.1", 9999, "127.0.0.1", 7000, d);
        one(AF_INET, IPPROTO_UDP, "127.0.0.1", 9999, "127.0.0.1", 7001, d);
        one(AF_INET, IPPROTO_UDP, "127.0.0.1", 9999, "127.0.0.1", 7002, d);
        one(AF_INET6, IPPROTO_UDP, "::1", 9999, "::1", 7003, d);
        one(AF_INET, IPPROTO_UDP, "127.0.0.1", 7001, "127.0.0.1", 7100, d);
        one(AF_INET, IPPROTO_UDP, "127.0.0.1", 9999, "127.0.0.1", 7006, d);
    }
    /* The old request, and a socket moved to another device. */
    struct old_request old = {.family = AF_INET, .states = ALL, .id = id(AF_INET, "127.0.0.1", 7000, "127.0.0.1", 9999, 1)};
    ask(TCPDIAG_GETSOCK, 0, &old, sizeof old, "the old request, if=1");
    old.id.device = 0;
    ask(TCPDIAG_GETSOCK, 0, &old, sizeof old, "the old request, if=0");
    unsigned device = 1;
    printf("to lo=%ld\n", result(setsockopt(closed, SOL_SOCKET, SO_BINDTOIFINDEX_, &device, sizeof device)));
    device = 0;
    printf("to none=%ld\n", result(setsockopt(c1, SOL_SOCKET, SO_BINDTOIFINDEX_, &device, sizeof device)));
    filtered(AF_INET, IPPROTO_TCP, 1, "tcp bound to 1");
    one(AF_INET, IPPROTO_TCP, "127.0.0.1", 7100, "127.0.0.1", 7000, 0);
    close(s1), close(s2), close(s3), close(c2), close(c3);
    return 0;
}
