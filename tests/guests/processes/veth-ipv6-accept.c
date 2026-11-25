/* The device of an accepted IPv6 connection (so as root): a child, B,
   makes a network namespace of its own and waits; the parent, A, makes
   another and a pair, its end "va" (1000, 02:00:00:00:00:0a, so
   fe80::ff:fe00:a) in A and "vb" (1001, fe80::ff:fe00:b) in B, with
   2001:db8::1/64 and 2001:db8::2/64, IFA_F_NODAD, and 10.0.0.1/24 and
   10.0.0.2/24. B listens on :: at 7000 and 7001, the second bound to vb,
   and on its link-local address at 7002; A connects. A connection from a
   link-local address is bound to the device it came in on, which its peer's
   and its own name and accept's address give as their scope ID; one from a
   global address to a link-local one is bound to none, so its own name has
   none; one to a listener bound to vb is bound to it. IPV6_MULTICAST_IF of
   each is the device it came in on, an IPv4-mapped one's too, and
   IPV6_UNICAST_IF the listener's. A accepts its own connections too, to
   its link-local address, its global one, ::1 and ::ffff:127.0.0.1. Bound to
   no device again, a connection's names lose their scope ID. The two
   processes take turns through pipes, so their lines come in one order; an
   address done is waited for on netlink. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define NETLINK_ROUTE_ 0
#define RTM_NEWLINK 16
#define RTM_NEWADDR 20
#define RTM_NEWROUTE 24
#define NLM_F_REQUEST 1
#define NLM_F_ACK 4
#define NLM_F_EXCL 0x200
#define NLM_F_CREATE 0x400
#define IFLA_ADDRESS 1
#define IFLA_IFNAME 3
#define IFLA_LINKINFO 18
#define IFLA_NET_NS_PID 19
#define IFLA_CARRIER 33
#define IFLA_INFO_KIND 1
#define IFLA_INFO_DATA 2
#define VETH_INFO_PEER 1
#define IFA_LOCAL 2
#define IFA_FLAGS 8
#define IFA_F_NODAD 0x02
#define A_INDEX 1000
#define B_INDEX 1001
#define SO_BINDTOIFINDEX_ 62
#define IPV6_UNICAST_IF_ 76

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
struct ifinfo {
    unsigned char family, pad;
    unsigned short type;
    int index;
    unsigned flags, change;
};
struct body {
    unsigned char bytes[1024];
    size_t len;
};

static const char *side = "A";
static unsigned seq;
/* RTNLGRP_LINK and RTNLGRP_IPV6_ROUTE, what is waited for. */
static int events = -1;

static long result(long r) { return r < 0 ? -errno : r; }

static void raw(struct body *b, const void *value, size_t len) {
    memcpy(b->bytes + b->len, value, len);
    b->len += (len + 3) & ~3u;
}
static void put(struct body *b, unsigned short type, const void *value, size_t len) {
    unsigned short attribute[2] = {(unsigned short)(4 + len), type};
    memcpy(b->bytes + b->len, attribute, 4);
    memcpy(b->bytes + b->len + 4, value, len);
    b->len += (4 + len + 3) & ~3u;
}
static void put32(struct body *b, unsigned short type, unsigned value) { put(b, type, &value, 4); }
static size_t begin(struct body *b, unsigned short type) {
    size_t at = b->len;
    put(b, type, NULL, 0);
    return at;
}
static void end(struct body *b, size_t at) {
    unsigned short len = (unsigned short)(b->len - at);
    memcpy(b->bytes + at, &len, 2);
}
static void info(struct body *b, int index, unsigned flags, unsigned change) {
    struct ifinfo i = {.index = index, .flags = flags, .change = change};
    raw(b, &i, sizeof i);
}
static int route_socket(unsigned groups) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE_);
    struct nl_address at = {.family = AF_NETLINK, .groups = groups};
    bind(fd, (void *)&at, sizeof at);
    return fd;
}
/* Sends a request and prints its acknowledgement's error, which it
   gives. */
static int request(int fd, unsigned short type, unsigned short flags, const struct body *b, const char *label) {
    unsigned char buf[4096] = {0};
    struct nl_header *h = (void *)buf;
    h->len = sizeof *h + b->len;
    h->type = type;
    h->flags = NLM_F_REQUEST | NLM_F_ACK | flags;
    h->seq = ++seq;
    memcpy(buf + sizeof *h, b->bytes, b->len);
    struct nl_address kernel = {.family = AF_NETLINK};
    if (sendto(fd, buf, h->len, 0, (void *)&kernel, sizeof kernel) < 0) printf("%s: send=%d\n", side, -errno);
    for (;;) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) {
            printf("%s: %s: no answer\n", side, label);
            return 1;
        }
        long n = recv(fd, buf, sizeof buf, 0);
        if (n < (long)sizeof *h + 4) return 1;
        if (h->type == 2) {
            int error;
            memcpy(&error, buf + sizeof *h, 4);
            printf("%s: %s: error=%d\n", side, label, error);
            return error;
        }
    }
}
static void set_link(int fd, int index, int up, const char *label) {
    struct body b = {0};
    info(&b, index, up ? IFF_UP : 0, IFF_UP);
    request(fd, RTM_NEWLINK, 0, &b, label);
}
static void sysctl(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    long r = result(fd < 0 ? fd : write(fd, value, strlen(value)));
    printf("%s: %s=%ld\n", side, path, r);
    if (fd >= 0) close(fd);
}
static void drain(int fd) {
    static unsigned char buf[65536];
    while (recv(fd, buf, sizeof buf, MSG_DONTWAIT) > 0) {
    }
}
static unsigned char wanted[16];
/* Whether `h` is what is waited for: the local route of `wanted` (an
   address done), or the RTM_NEWLINK of the device of `index` with its
   carrier. */
static int is(const struct nl_header *h, int index) {
    const unsigned char *body = (const unsigned char *)(h + 1);
    int len = (int)(h->len - sizeof *h);
    if (index) {
        int got;
        if (h->type != RTM_NEWLINK) return 0;
        memcpy(&got, body + 4, 4);
        if (got != index) return 0;
    } else if (h->type != RTM_NEWROUTE || body[0] != AF_INET6 || body[7] != 2)
        return 0;
    for (int a = index ? 16 : 12; a + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, body + a, 2);
        memcpy(&kind, body + a + 2, 2);
        if (alen < 4 || a + alen > len) break;
        if (!index && kind == 1 && alen == 20) return !memcmp(body + a + 4, wanted, 16);
        if (index && (kind & 0x3fff) == IFLA_CARRIER && alen >= 5) return body[a + 4] == 1;
        a += (alen + 3) & ~3;
    }
    return 0;
}
/* Waits, up to 5 s however much else comes, on `fd` for what `is` says. */
static void wait_for(int fd, const char *ip, int index, const char *label) {
    static unsigned char buf[65536];
    memset(wanted, 0, sizeof wanted);
    if (ip) inet_pton(AF_INET6, ip, wanted);
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long left = 5000 - ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000);
        if (left <= 0) break;
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, (int)(left < 1000 ? left : 1000)) <= 0) continue;
        long n;
        while ((n = recv(fd, buf, sizeof buf, MSG_DONTWAIT)) > 0)
            for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
                const struct nl_header *h = (const void *)(buf + at);
                if (h->len < sizeof *h || at + h->len > n) break;
                if (is(h, index)) return;
                at += (h->len + 3) & ~3u;
            }
    }
    printf("%s: %s: never came\n", side, label);
}
/* Adds the IPv6 address `ip`/`prefix` of the device of `index`,
   IFA_F_NODAD, and waits for its local route. */
static void address6(int fd, int index, const char *ip, int prefix, const char *label) {
    struct body b = {0};
    const unsigned char m[8] = {AF_INET6, (unsigned char)prefix, IFA_F_NODAD, 0, (unsigned char)index,
                                (unsigned char)(index >> 8), 0, 0};
    unsigned char in[16];
    inet_pton(AF_INET6, ip, in);
    raw(&b, m, sizeof m);
    put(&b, IFA_LOCAL, in, 16);
    put32(&b, IFA_FLAGS, IFA_F_NODAD);
    drain(events);
    if (request(fd, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &b, label) == 0)
        wait_for(events, ip, 0, label);
}
/* Adds the IPv4 address 10.0.0.`last`/24 of the device of `index`. */
static void address4(int fd, int index, unsigned char last, const char *label) {
    struct body b = {0};
    const unsigned char m[8] = {AF_INET, 24, 0, 0, (unsigned char)index, (unsigned char)(index >> 8), 0, 0};
    const unsigned char in[4] = {10, 0, 0, last};
    raw(&b, m, sizeof m);
    put(&b, IFA_LOCAL, in, 4);
    request(fd, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &b, label);
}
static void make_pair(int ctl, int ns) {
    struct body m = {0};
    const unsigned char mac_a[6] = {2, 0, 0, 0, 0, 0x0a}, mac_b[6] = {2, 0, 0, 0, 0, 0x0b};
    info(&m, A_INDEX, 0, 0);
    put(&m, IFLA_IFNAME, "va", 3);
    put(&m, IFLA_ADDRESS, mac_a, 6);
    size_t link = begin(&m, IFLA_LINKINFO);
    put(&m, IFLA_INFO_KIND, "veth", 5);
    size_t data = begin(&m, IFLA_INFO_DATA);
    size_t peer = begin(&m, VETH_INFO_PEER);
    info(&m, B_INDEX, 0, 0);
    put(&m, IFLA_IFNAME, "vb", 3);
    put(&m, IFLA_ADDRESS, mac_b, 6);
    put32(&m, IFLA_NET_NS_PID, (unsigned)ns);
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make a pair");
}

static struct sockaddr_in6 at(const char *ip, int port, unsigned scope) {
    struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)port), .sin6_scope_id = scope};
    inet_pton(AF_INET6, ip, &a.sin6_addr);
    return a;
}
/* Shows `a`, an ephemeral port as "any". */
static void show(const char *label, long r, const struct sockaddr_in6 *a) {
    char ip[64] = "-", port[16] = "any";
    if (a->sin6_family == AF_INET6) inet_ntop(AF_INET6, &a->sin6_addr, ip, sizeof ip);
    if (ntohs(a->sin6_port) < 32768) snprintf(port, sizeof port, "%u", ntohs(a->sin6_port));
    printf("%s:   %s=%ld %s port=%s scope=%u\n", side, label, r, ip, port, a->sin6_scope_id);
}
static void names(int fd) {
    struct sockaddr_in6 a = {0};
    socklen_t len = sizeof a;
    long r = result(getsockname(fd, (void *)&a, &len));
    show("its name", r, &a);
    memset(&a, 0, sizeof a);
    len = sizeof a;
    r = result(getpeername(fd, (void *)&a, &len));
    show("its peer's", r, &a);
}
static void option(int fd, int level, int name, const char *label) {
    unsigned value = 77;
    socklen_t len = sizeof value;
    long r = result(getsockopt(fd, level, name, &value, &len));
    printf("%s:   %s=%ld %u\n", side, label, r, level == IPPROTO_IPV6 && name == IPV6_UNICAST_IF_ ? ntohl(value) : value);
}
static void devices(int fd) {
    option(fd, SOL_SOCKET, SO_BINDTOIFINDEX_, "its device");
    option(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, "IPV6_MULTICAST_IF");
    option(fd, IPPROTO_IPV6, IPV6_UNICAST_IF_, "IPV6_UNICAST_IF");
}
static int listener(const char *ip, int port, unsigned scope, unsigned device, const char *label) {
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    long r = 0;
    if (device) r = result(setsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX_, &device, sizeof device));
    struct sockaddr_in6 a = at(ip, port, scope);
    if (r == 0) r = result(bind(fd, (void *)&a, sizeof a));
    if (r == 0) r = result(listen(fd, 8));
    printf("%s: %s: listen=%ld\n", side, label, r);
    return fd;
}
/* Accepts from `fd` and shows the connection's names and devices. */
static int take(int fd) {
    struct sockaddr_in6 a = {0};
    socklen_t len = sizeof a;
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    if (poll(&ready, 1, 2000) <= 0) {
        printf("%s:   nothing to accept\n", side);
        return -1;
    }
    int got = (int)result(accept(fd, (void *)&a, &len));
    show("accept", got < 0 ? got : 0, &a);
    if (got < 0) return got;
    names(got);
    devices(got);
    return got;
}
/* Connects from `from` (any for NULL), its scope ID `from_scope`, to `ip`
   at `port`, its scope ID `scope`. */
static int connect6(const char *from, unsigned from_scope, const char *ip, int port, unsigned scope,
                    const char *label) {
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    long r = 0;
    if (from) {
        struct sockaddr_in6 a = at(from, 0, from_scope);
        r = result(bind(fd, (void *)&a, sizeof a));
        if (r) printf("%s: %s: bind=%ld\n", side, label, r);
    }
    struct sockaddr_in6 to = at(ip, port, scope);
    r = result(connect(fd, (void *)&to, sizeof to));
    printf("%s: %s: connect=%ld\n", side, label, r);
    if (r == 0) {
        names(fd);
        devices(fd);
    }
    return fd;
}

/* B: makes its namespace, then does what A writes to `in`, one letter at
   a time, writing back to `out` when done. */
static void child(int in, int out) {
    side = "B";
    if (unshare(CLONE_NEWNET) < 0) printf("B: unshare=%d\n", -errno);
    int ctl = route_socket(0);
    events = route_socket(1 | 0x400);
    int any = -1, bound = -1, local = -1;
    fflush(stdout);
    if (write(out, "r", 1) != 1) _exit(2);
    for (char command; read(in, &command, 1) == 1;) {
        if (command == 'u') {
            sysctl("/proc/sys/net/ipv6/conf/vb/accept_dad", "0");
            set_link(ctl, 1, 1, "up lo");
            set_link(ctl, B_INDEX, 1, "up the end");
            address6(ctl, B_INDEX, "2001:db8::2", 64, "add its address");
            address4(ctl, B_INDEX, 2, "add its IPv4 address");
        } else if (command == 'l') {
            wait_for(events, "fe80::ff:fe00:b", 0, "the link-local address");
            any = listener("::", 7000, 0, 0, "on ::");
            unsigned vb = htonl(B_INDEX);
            printf("B: IPV6_UNICAST_IF vb=%ld\n",
                   result(setsockopt(any, IPPROTO_IPV6, IPV6_UNICAST_IF_, &vb, sizeof vb)));
            bound = listener("::", 7001, 0, B_INDEX, "on ::, through vb");
            local = listener("fe80::ff:fe00:b", 7002, B_INDEX, 0, "on its link-local address");
        } else if (command == 'x') {
            fflush(stdout);
            _exit(0);
        } else {
            int got = take(command == 'a' || command == 'n' ? any : command == 'b' ? bound : local);
            if (command == 'n') {
                int none = 0;
                printf("B:   to no device: setsockopt=%ld\n",
                       result(setsockopt(got, SOL_SOCKET, SO_BINDTOIFINDEX_, &none, sizeof none)));
                names(got);
                devices(got);
            }
            if (got >= 0) close(got);
        }
        fflush(stdout);
        if (write(out, "d", 1) != 1) _exit(2);
    }
    _exit(0);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-ipv6-accept")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    int to_b[2], to_a[2];
    if (pipe(to_b) < 0 || pipe(to_a) < 0) return 98;
    fflush(stdout);
    pid_t b = fork();
    if (b == 0) {
        close(to_b[1]), close(to_a[0]);
        child(to_b[0], to_a[1]);
    }
    close(to_b[0]), close(to_a[1]);
    char ready;
    if (read(to_a[0], &ready, 1) != 1) return 97;
#define B_DOES(command)                                                       \
    do {                                                                      \
        fflush(stdout);                                                       \
        if (write(to_b[1], command, 1) != 1 || read(to_a[0], &ready, 1) != 1) \
            printf("A: B gone\n");                                            \
    } while (0)
    printf("A: unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ctl = route_socket(0);
    events = route_socket(1 | 0x400);
    make_pair(ctl, b);
    sysctl("/proc/sys/net/ipv6/conf/va/accept_dad", "0");
    set_link(ctl, 1, 1, "up lo");
    B_DOES("u");
    drain(events);
    set_link(ctl, A_INDEX, 1, "up the end");
    wait_for(events, NULL, A_INDEX, "the carrier");
    wait_for(events, "fe80::ff:fe00:a", 0, "the link-local address");
    address6(ctl, A_INDEX, "2001:db8::1", 64, "add its address");
    address4(ctl, A_INDEX, 1, "add its IPv4 address");
    B_DOES("l");

    const char *a_ll = "fe80::ff:fe00:a", *b_ll = "fe80::ff:fe00:b";
    /* To B. */
    int s = connect6(NULL, 0, b_ll, 7000, A_INDEX, "link-local");
    B_DOES("a");
    close(s);
    s = connect6(NULL, 0, "2001:db8::2", 7000, 0, "global");
    B_DOES("a");
    close(s);
    s = connect6(a_ll, A_INDEX, "2001:db8::2", 7000, 0, "link-local to global");
    B_DOES("a");
    close(s);
    s = connect6("2001:db8::1", 0, b_ll, 7000, A_INDEX, "global to link-local");
    B_DOES("a");
    close(s);
    s = connect6(NULL, 0, "::ffff:10.0.0.2", 7000, 0, "IPv4-mapped");
    B_DOES("a");
    close(s);
    s = connect6(NULL, 0, b_ll, 7000, A_INDEX, "link-local, then to no device");
    B_DOES("n");
    close(s);
    s = connect6(NULL, 0, b_ll, 7001, A_INDEX, "link-local, through vb");
    B_DOES("b");
    close(s);
    s = connect6(NULL, 0, "2001:db8::2", 7001, 0, "global, through vb");
    B_DOES("b");
    close(s);
    s = connect6(NULL, 0, b_ll, 7002, A_INDEX, "link-local, its own address");
    B_DOES("c");
    close(s);
    s = connect6("2001:db8::1", 0, b_ll, 7002, A_INDEX, "global to its own address");
    B_DOES("c");
    close(s);
    /* To itself. */
    int own = listener("::", 7100, 0, 0, "on ::");
    const struct {
        const char *from;
        unsigned from_scope;
        const char *to;
        unsigned scope;
        const char *label;
    } selves[] = {
        {NULL, 0, a_ll, A_INDEX, "its own link-local"},
        {NULL, 0, "2001:db8::1", 0, "its own global"},
        {a_ll, A_INDEX, "2001:db8::1", 0, "its own link-local to its global"},
        {"2001:db8::1", 0, a_ll, A_INDEX, "its own global to its link-local"},
        {NULL, 0, "::1", 0, "::1"},
        {NULL, 0, "::ffff:127.0.0.1", 0, "::ffff:127.0.0.1"},
        {NULL, 0, "::ffff:10.0.0.1", 0, "its own IPv4-mapped"},
    };
    for (size_t i = 0; i < sizeof selves / sizeof *selves; i++) {
        s = connect6(selves[i].from, selves[i].from_scope, selves[i].to, 7100, selves[i].scope, selves[i].label);
        int got = take(own);
        close(s);
        if (got >= 0) close(got);
    }
    B_DOES("x");
    int status = 0;
    waitpid(b, &status, 0);
    printf("A: B exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}
