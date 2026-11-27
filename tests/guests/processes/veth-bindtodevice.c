/* SO_BINDTODEVICE and SO_BINDTOIFINDEX of inet sockets (so as root): a
   network namespace with two veth pairs, "va" (1000) with "vb" (1001) and
   "vc" (1002) with "vd" (1003), va having 10.0.0.1/24 and 2001:db8::1/64,
   vc 10.1.0.1/24 and 2001:db8:1::1/64. The options take a name (none or
   empty for no device, ENODEV for one there is not, at most 15 bytes
   read) or an index (EINVAL for a negative one, any other taken), and
   give the name back in room for a whole one (EINVAL for less, ENODEV for
   an index of no device) and the index. Without CAP_NET_RAW a socket bound
   to a device stays so (EPERM), one bound to none may bind. Sockets bound
   to other devices share a port, one bound to none takes it not. A packet
   to one's own address comes in on lo for IPv4, unless sent from a socket
   bound to a device, and on the address's device for IPv6, and only
   sockets bound to no device or to that one take it, one bound to it
   before others but a connected one; a TCP listener the same, and the connection it accepts
   is bound as it is. An IPv4 socket bound to a device goes by its routes
   only, else on link through it: from va to vc's address, out through va,
   in on vb. Through lo one to any address goes so too, from va's address
   (inet_select_addr's first of link scope), or 127.0.0.1, and comes back
   in on lo: a datagram to what takes it there, a connection's SYN with
   no answer, none from an address not the namespace's own, and one from
   10.0.0.1 in on va. A device down is ENETUNREACH, one gone ENODEV. */
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
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define NETLINK_ROUTE_ 0
#define RTM_NEWLINK 16
#define RTM_DELLINK 17
#define RTM_NEWADDR 20
#define NLM_F_REQUEST 1
#define NLM_F_ACK 4
#define NLM_F_EXCL 0x200
#define NLM_F_CREATE 0x400
#define IFLA_ADDRESS 1
#define IFLA_IFNAME 3
#define IFLA_LINKINFO 18
#define IFLA_CARRIER 33
#define IFLA_INFO_KIND 1
#define IFLA_INFO_DATA 2
#define VETH_INFO_PEER 1
#define IFA_LOCAL 2
#define IFA_ADDRESS_ 1
#define IFA_FLAGS 8
#define IFA_F_NODAD 0x02
#define RTA_DST 1
#define RTM_NEWROUTE 24
#define RTA_OIF 4
#define SO_BINDTODEVICE_ 25
#define SO_BINDTOIFINDEX_ 62
#define VA 1000
#define VB 1001
#define VC 1002
#define VD 1003

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

static unsigned seq;
/* RTNLGRP_LINK and RTNLGRP_IPV6_ROUTE, what is waited for; and
   RTNLGRP_IPV6_ROUTE, what is shown. */
static int events = -1, routes = -1;

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
    if (sendto(fd, buf, h->len, 0, (void *)&kernel, sizeof kernel) < 0) printf("send=%d\n", -errno);
    for (;;) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) {
            printf("%s: no answer\n", label);
            return 1;
        }
        long n = recv(fd, buf, sizeof buf, 0);
        if (n < (long)sizeof *h + 4) return 1;
        if (h->type == 2) {
            int error;
            memcpy(&error, buf + sizeof *h, 4);
            printf("%s: error=%d\n", label, error);
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
    printf("%s=%ld\n", path, r);
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
    int start;
    if (index) {
        int got;
        if (h->type != RTM_NEWLINK) return 0;
        memcpy(&got, body + 4, 4);
        if (got != index) return 0;
        start = 16;
    } else {
        if (h->type != RTM_NEWROUTE || body[0] != AF_INET6 || body[7] != 2) return 0;
        start = 12;
    }
    for (int a = start; a + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, body + a, 2);
        memcpy(&kind, body + a + 2, 2);
        if (alen < 4 || a + alen > len) break;
        if (!index && kind == RTA_DST && alen == 20) return !memcmp(body + a + 4, wanted, 16);
        if (index && (kind & 0x3fff) == IFLA_CARRIER && alen >= 5) return body[a + 4] == 1;
        a += (alen + 3) & ~3;
    }
    return 0;
}
/* Waits, up to 5 s however much else comes, for what `is` says. */
static void wait_for(const char *ip, int index, const char *label) {
    static unsigned char buf[65536];
    memset(wanted, 0, sizeof wanted);
    if (ip) inet_pton(AF_INET6, ip, wanted);
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long left = 5000 - ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000);
        if (left <= 0) break;
        struct pollfd ready = {.fd = events, .events = POLLIN};
        if (poll(&ready, 1, (int)(left < 1000 ? left : 1000)) <= 0) continue;
        long n;
        while ((n = recv(events, buf, sizeof buf, MSG_DONTWAIT)) > 0)
            for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
                const struct nl_header *h = (const void *)(buf + at);
                if (h->len < sizeof *h || at + h->len > n) break;
                if (is(h, index)) return;
                at += (h->len + 3) & ~3u;
            }
    }
    printf("%s: never came\n", label);
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
    if (request(fd, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &b, label) == 0) wait_for(ip, 0, label);
}
/* Brings the device of `index` up and waits for its carrier and its
   link-local address `ll`. */
static void up(int fd, int index, const char *ll, const char *label) {
    drain(events);
    set_link(fd, index, 1, label);
    wait_for(NULL, index, "its carrier");
    wait_for(ll, 0, "its link-local address");
}
static void make_pair(int ctl, int a, const char *name_a, int b, const char *name_b, unsigned char last) {
    struct body m = {0};
    const unsigned char mac_a[6] = {2, 0, 0, 0, 0, last}, mac_b[6] = {2, 0, 0, 0, 0, (unsigned char)(last + 1)};
    info(&m, a, 0, 0);
    put(&m, IFLA_IFNAME, name_a, 3);
    put(&m, IFLA_ADDRESS, mac_a, 6);
    size_t link = begin(&m, IFLA_LINKINFO);
    put(&m, IFLA_INFO_KIND, "veth", 5);
    size_t data = begin(&m, IFLA_INFO_DATA);
    size_t peer = begin(&m, VETH_INFO_PEER);
    info(&m, b, 0, 0);
    put(&m, IFLA_IFNAME, name_b, 3);
    put(&m, IFLA_ADDRESS, mac_b, 6);
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make a pair");
}

static void address4(int fd, int index, const char *ip, int prefix, const char *label) {
    struct body b = {0};
    const unsigned char m[8] = {AF_INET, (unsigned char)prefix, 0, 0, (unsigned char)index,
                                (unsigned char)(index >> 8), 0, 0};
    unsigned char in[4];
    inet_pton(AF_INET, ip, in);
    raw(&b, m, sizeof m);
    put(&b, IFA_LOCAL, in, 4);
    put(&b, IFA_ADDRESS_, in, 4);
    request(fd, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &b, label);
}

/* Sets SO_BINDTODEVICE to the `len` bytes of `name`. */
static void to_name(int fd, const char *name, int len, const char *label) {
    printf("%s: setsockopt=%ld\n", label, result(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE_, name, (socklen_t)len)));
}
static void to_index(int fd, int index, const char *label) {
    printf("%s: setsockopt=%ld\n", label, result(setsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX_, &index, sizeof index)));
}
/* Gets SO_BINDTODEVICE in `room` bytes, and SO_BINDTOIFINDEX. */
static void show(int fd, int room, const char *label) {
    char name[32];
    memset(name, 'x', sizeof name);
    socklen_t len = (socklen_t)room;
    long r = result(getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE_, name, &len));
    int index = -1;
    socklen_t ilen = sizeof index;
    long ir = result(getsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX_, &index, &ilen));
    printf("%s: name=%ld len=%u \"%.*s\" index=%ld %d\n", label, r, len, r == 0 ? (int)strnlen(name, len) : 0,
           name, ir, index);
}

static struct sockaddr_in at4(const char *ip, int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}
static struct sockaddr_in6 at6(const char *ip, int port) {
    struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)port)};
    inet_pton(AF_INET6, ip, &a.sin6_addr);
    return a;
}
/* A socket of `family` and `type`, bound to the device `dev` (none for
   NULL) and then to port `port` of the unspecified address. */
static int bound(int family, int type, const char *dev, int port, const char *label) {
    int fd = socket(family, type, 0);
    if (dev) setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE_, dev, (socklen_t)strlen(dev));
    long r;
    if (family == AF_INET6) {
        struct sockaddr_in6 a = at6("::", port);
        r = result(bind(fd, (void *)&a, sizeof a));
    } else {
        struct sockaddr_in a = at4("0.0.0.0", port);
        r = result(bind(fd, (void *)&a, sizeof a));
    }
    printf("%s: bind=%ld\n", label, r);
    return fd;
}
/* Says which of `fds` (named by `names`) has a datagram waiting, taking
   it, after a short wait. */
static void which(const int *fds, const char *const *names, int n, const char *label) {
    char got[128] = "";
    struct timespec pause = {0, 100 * 1000 * 1000};
    nanosleep(&pause, NULL);
    for (int i = 0; i < n; i++) {
        char buf[16];
        if (recv(fds[i], buf, sizeof buf, MSG_DONTWAIT) > 0) {
            strcat(got, " ");
            strcat(got, names[i]);
        }
    }
    printf("%s: taken by%s\n", label, got[0] ? got : " none");
}
static void send4(int fd, const char *ip, int port, const char *label) {
    struct sockaddr_in to = at4(ip, port);
    printf("%s: sendto=%ld\n", label, result(sendto(fd, "x", 1, 0, (void *)&to, sizeof to)));
}
static void send6(int fd, const char *ip, int port, const char *label) {
    struct sockaddr_in6 to = at6(ip, port);
    printf("%s: sendto=%ld\n", label, result(sendto(fd, "x", 1, 0, (void *)&to, sizeof to)));
}

/* Adds a route of link scope to `dst`/`len` through the device `oif`
   to the main table. */
static void route4(int fd, const char *dst, int len, int oif, const char *label) {
    struct body b = {0};
    const unsigned char m[12] = {AF_INET, (unsigned char)len, 0, 0, 254, 3, 253, 1, 0, 0, 0, 0};
    unsigned char in[4];
    inet_pton(AF_INET, dst, in);
    raw(&b, m, sizeof m);
    put(&b, RTA_DST, in, 4);
    put(&b, RTA_OIF, &oif, 4);
    request(fd, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &b, label);
}
/* Prints the IPv4 address `fd` is bound to. */
static void name4(int fd, const char *label) {
    struct sockaddr_in name = {0};
    socklen_t len = sizeof name;
    long r = result(getsockname(fd, (void *)&name, &len));
    char ip[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &name.sin_addr, ip, sizeof ip);
    printf("%s: getsockname=%ld %s\n", label, r, ip);
}
/* A nonblocking TCP connection from a socket bound to lo, and to `from`
   (none for NULL), to `ip`:`port`, and what it is a little later. */
static void connect_lo(const char *from, const char *ip, int port, const char *label) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE_, "lo", 2);
    if (from) {
        struct sockaddr_in a = at4(from, 0);
        printf("%s: bind=%ld\n", label, result(bind(fd, (void *)&a, sizeof a)));
    }
    fcntl(fd, F_SETFL, O_NONBLOCK);
    struct sockaddr_in to = at4(ip, port);
    printf("%s: connect=%ld\n", label, result(connect(fd, (void *)&to, sizeof to)));
    struct pollfd p = {.fd = fd, .events = POLLOUT};
    long ready = result(poll(&p, 1, 200));
    int error = -1;
    socklen_t len = sizeof error;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
    printf("%s: poll=%ld revents=%#x SO_ERROR=%d\n", label, ready, (unsigned)p.revents, error);
    name4(fd, label);
    close(fd);
}

/* Drops CAP_NET_RAW from the effective set. */
static void drop_net_raw(void) {
    struct {
        unsigned version;
        int pid;
    } head = {0x20080522, 0};
    struct {
        unsigned effective, permitted, inheritable;
    } data[2];
    printf("capget=%ld\n", result(syscall(SYS_capget, &head, data)));
    data[0].effective &= ~(1u << 13);
    printf("capset=%ld\n", result(syscall(SYS_capset, &head, data)));
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-bindtodevice")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ctl = route_socket(0);
    events = route_socket(1 | 0x400);
    make_pair(ctl, VA, "va", VB, "vb", 0x0a);
    make_pair(ctl, VC, "vc", VD, "vd", 0x0c);
    sysctl("/proc/sys/net/ipv6/conf/va/accept_dad", "0");
    sysctl("/proc/sys/net/ipv6/conf/vb/accept_dad", "0");
    sysctl("/proc/sys/net/ipv6/conf/vc/accept_dad", "0");
    sysctl("/proc/sys/net/ipv6/conf/vd/accept_dad", "0");
    set_link(ctl, 1, 1, "up lo");
    set_link(ctl, VB, 1, "up vb");
    set_link(ctl, VD, 1, "up vd");
    up(ctl, VA, "fe80::ff:fe00:a", "up va");
    up(ctl, VC, "fe80::ff:fe00:c", "up vc");
    address4(ctl, VA, "10.0.0.1", 24, "add va's IPv4 address");
    address4(ctl, VC, "10.1.0.1", 24, "add vc's IPv4 address");
    address6(ctl, VA, "2001:db8::1", 64, "add va's IPv6 address");
    address6(ctl, VC, "2001:db8:1::1", 64, "add vc's IPv6 address");

    /* The options. */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    show(s, 16, "unbound");
    to_name(s, "nope", 4, "to nope");
    to_name(s, "va", 2, "to va");
    show(s, 16, "on va");
    show(s, 15, "on va, in 15 bytes");
    to_name(s, "", 0, "to none, no bytes");
    show(s, 16, "on none");
    to_name(s, "vc\0junk", 7, "to vc, then junk");
    show(s, 32, "on vc");
    to_name(s, "", 1, "to an empty name");
    to_name(s, "vaaaaaaaaaaaaaaa", 16, "to a 16-byte name");
    to_index(s, VA, "to index 1000");
    show(s, 16, "on index 1000");
    to_index(s, -1, "to index -1");
    to_index(s, 9999, "to index 9999");
    show(s, 16, "on index 9999");
    to_index(s, 0, "to index 0");
    close(s);
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        drop_net_raw();
        int t = socket(AF_INET, SOCK_DGRAM, 0);
        to_name(t, "va", 2, "without CAP_NET_RAW, to va");
        to_name(t, "vc", 2, "then to vc");
        to_name(t, "", 0, "then to none");
        to_index(t, VA, "then to index 1000");
        show(t, 16, "still");
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    waitpid(child, &status, 0);
    printf("child exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);

    /* A port shared by devices. */
    int a = bound(AF_INET, SOCK_DGRAM, "va", 7000, "UDP on va, port 7000");
    int c = bound(AF_INET, SOCK_DGRAM, "vc", 7000, "UDP on vc, port 7000");
    int none = bound(AF_INET, SOCK_DGRAM, NULL, 7000, "UDP on none, port 7000");
    int again = bound(AF_INET, SOCK_DGRAM, "va", 7000, "UDP on va again");
    close(none), close(again);
    int lo = bound(AF_INET, SOCK_DGRAM, "lo", 7000, "UDP on lo, port 7000");
    int vb = bound(AF_INET, SOCK_DGRAM, "vb", 7000, "UDP on vb, port 7000");
    int six_a = bound(AF_INET6, SOCK_DGRAM, "va", 7100, "UDP6 on va, port 7100");
    int six_c = bound(AF_INET6, SOCK_DGRAM, "vc", 7100, "UDP6 on vc, port 7100");
    int six_any = bound(AF_INET6, SOCK_DGRAM, NULL, 7100, "UDP6 on none, port 7100");
    const int four[] = {a, c, lo, vb};
    const char *const four_names[] = {"va", "vc", "lo", "vb"};
    const int sixes[] = {six_a, six_c, six_any};
    const char *const six_names[] = {"va", "vc", "none"};

    /* Where a datagram comes in. */
    int out = socket(AF_INET, SOCK_DGRAM, 0);
    send4(out, "10.0.0.1", 7000, "from none to 10.0.0.1");
    which(four, four_names, 4, "to 10.0.0.1");
    int out_va = bound(AF_INET, SOCK_DGRAM, "va", 0, "a sender on va");
    send4(out_va, "10.0.0.1", 7000, "from va to 10.0.0.1");
    which(four, four_names, 4, "to 10.0.0.1 from va");
    send4(out_va, "10.1.0.1", 7000, "from va to 10.1.0.1");
    which(four, four_names, 4, "to 10.1.0.1 from va");
    send4(out_va, "224.0.0.5", 7000, "from va to 224.0.0.5");
    /* Of two bound to one address and port, a connected one before one
       bound to the device (compute_score). */
    int reuse = 1;
    struct sockaddr_in at7200 = at4("10.0.0.1", 7200);
    int on_dev = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(on_dev, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse);
    to_name(on_dev, "va", 2, "UDP to va, for 10.0.0.1:7200");
    printf("bind it=%ld\n", result(bind(on_dev, (void *)&at7200, sizeof at7200)));
    int joined = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(joined, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse);
    printf("UDP on none, 10.0.0.1:7200: bind=%ld\n", result(bind(joined, (void *)&at7200, sizeof at7200)));
    int from7300 = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in at7300 = at4("10.0.0.1", 7300);
    printf("a sender at 10.0.0.1:7300: bind=%ld\n", result(bind(from7300, (void *)&at7300, sizeof at7300)));
    printf("connect the one on none to it=%ld\n", result(connect(joined, (void *)&at7300, sizeof at7300)));
    send4(from7300, "10.0.0.1", 7200, "from 10.0.0.1:7300 to 10.0.0.1:7200");
    const int pair[] = {on_dev, joined};
    const char *const pair_names[] = {"va", "connected"};
    which(pair, pair_names, 2, "to 10.0.0.1:7200");
    int out6 = socket(AF_INET6, SOCK_DGRAM, 0);
    send6(out6, "2001:db8::1", 7100, "from none to 2001:db8::1");
    which(sixes, six_names, 3, "to 2001:db8::1");
    send6(out6, "2001:db8:1::1", 7100, "from none to 2001:db8:1::1");
    which(sixes, six_names, 3, "to 2001:db8:1::1");
    send6(out6, "::1", 7100, "from none to ::1");
    which(sixes, six_names, 3, "to ::1");

    /* A TCP listener bound to va. */
    int l = bound(AF_INET6, SOCK_STREAM, "va", 8000, "TCP6 on va, port 8000");
    printf("listen=%ld\n", result(listen(l, 4)));
    int t4 = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in to4 = at4("10.0.0.1", 8000);
    printf("connect to 10.0.0.1=%ld\n", result(connect(t4, (void *)&to4, sizeof to4)));
    int t6 = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 to6 = at6("2001:db8::1", 8000);
    printf("connect to 2001:db8::1=%ld\n", result(connect(t6, (void *)&to6, sizeof to6)));
    int got = (int)result(accept(l, NULL, NULL));
    printf("accept=%d\n", got >= 0 ? 0 : got);
    if (got >= 0) show(got, 16, "accepted");

    /* Through lo, by its routes or on link: whatever its address, it
       comes back in on lo, to whatever takes it there, and nothing
       answers from an address not the namespace's own. */
    route4(ctl, "10.8.0.0", 16, 1, "route 10.8.0.0/16 through lo");
    int on_lo = bound(AF_INET, SOCK_DGRAM, "lo", 0, "a sender on lo");
    const char *const through_lo[] = {"10.9.9.9", "10.8.0.1", "10.1.0.2", "10.0.0.1", "127.0.0.1"};
    for (int i = 0; i < 5; i++) {
        char label[64];
        snprintf(label, sizeof label, "from lo to %s", through_lo[i]);
        send4(on_lo, through_lo[i], 7000, label);
        which(four, four_names, 4, label);
    }
    struct sockaddr_in far = at4("10.9.9.9", 7999);
    printf("connect it to 10.9.9.9:7999=%ld\n", result(connect(on_lo, (void *)&far, sizeof far)));
    name4(on_lo, "connected through lo");
    printf("send=%ld\n", result(send(on_lo, "x", 1, 0)));
    struct timespec pause = {0, 100 * 1000 * 1000};
    nanosleep(&pause, NULL);
    printf("send again=%ld\n", result(send(on_lo, "x", 1, 0)));
    int lo_local = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(lo_local, SOL_SOCKET, SO_BINDTODEVICE_, "lo", 2);
    struct sockaddr_in local = at4("127.0.0.1", 0);
    printf("UDP on lo at 127.0.0.1: bind=%ld\n", result(bind(lo_local, (void *)&local, sizeof local)));
    send4(lo_local, "10.9.9.9", 7000, "from 127.0.0.1 on lo to 10.9.9.9");
    which(four, four_names, 4, "from 127.0.0.1 on lo to 10.9.9.9");
    int lo6 = bound(AF_INET6, SOCK_DGRAM, "lo", 0, "UDP6 on lo");
    send6(lo6, "::ffff:10.9.9.9", 7000, "from lo to ::ffff:10.9.9.9");
    which(four, four_names, 4, "from lo to ::ffff:10.9.9.9");
    int lo_l = bound(AF_INET, SOCK_STREAM, "lo", 8100, "TCP on lo, port 8100");
    printf("listen=%ld\n", result(listen(lo_l, 4)));
    fcntl(lo_l, F_SETFL, O_NONBLOCK);
    int any_l = bound(AF_INET, SOCK_STREAM, NULL, 8200, "TCP on none, port 8200");
    printf("listen=%ld\n", result(listen(any_l, 4)));
    fcntl(any_l, F_SETFL, O_NONBLOCK);
    connect_lo(NULL, "10.9.9.9", 8000, "TCP on lo to 10.9.9.9:8000");
    connect_lo(NULL, "10.8.0.1", 8000, "TCP on lo to 10.8.0.1:8000");
    connect_lo("127.0.0.1", "10.9.9.9", 8000, "TCP on lo at 127.0.0.1 to 10.9.9.9:8000");
    connect_lo(NULL, "10.9.9.9", 8100, "TCP on lo to 10.9.9.9:8100");
    printf("accept on lo=%ld\n", result(accept(lo_l, NULL, NULL)));
    connect_lo(NULL, "10.0.0.1", 8200, "TCP on lo to 10.0.0.1:8200");
    int took = (int)result(accept(any_l, NULL, NULL));
    printf("accept on none=%d\n", took >= 0 ? 0 : took);
    if (took >= 0) show(took, 16, "accepted"), name4(took, "accepted"), close(took);
    close(on_lo), close(lo_local), close(lo6), close(lo_l), close(any_l);

    /* Down, and gone. */
    int on_vc = bound(AF_INET, SOCK_DGRAM, "vc", 0, "a sender on vc");
    set_link(ctl, VC, 0, "down vc");
    send4(on_vc, "10.0.0.1", 7000, "from vc, down");
    struct body gone = {0};
    info(&gone, VC, 0, 0);
    request(ctl, RTM_DELLINK, 0, &gone, "delete vc");
    send4(on_vc, "10.0.0.1", 7000, "from vc, gone");
    show(on_vc, 16, "on vc, gone");
    return 0;
}
