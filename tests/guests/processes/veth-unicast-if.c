/* IP_UNICAST_IF (so as root): a network namespace with two veth pairs,
   "va" (1000) with "vb" (1001) and "vc" (1002) with "vd" (1003), va
   having 10.0.0.1/24 and vc 10.1.0.1/24. The option takes an int exactly
   (EINVAL for another length), the index of a device in network byte
   order (EADDRNOTAVAIL for one there is not, 0 for none), not on a socket
   bound to a device (EINVAL), on TCP and IPv6 sockets too, and gives it
   back so. A datagram to an address other than a group, from a socket
   bound to no device, goes out through it, as SO_BINDTODEVICE's would:
   from va to vc's address, out through va, in on vb, and from va's
   address; a connect takes its source so. A device the socket is bound
   to comes first. An IPv6 socket's IPv4-mapped datagrams go by it, not
   by IPV6_UNICAST_IF; a TCP connection by neither. */
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
#define SO_BINDTODEVICE_ 25
#define IP_UNICAST_IF_ 50
#define IPV6_UNICAST_IF_ 76
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

/* Says which of the sockets bound to the devices takes a datagram, and
   from where, after a short wait: one in on lo comes in on its
   address's device, and one out through va to an address of this
   namespace's, from another, is dropped on vb (a martian). */
static const char *const devs[] = {"va", "vc", "vb", "vd", "lo"};
#define DEVS 5
static int receivers[DEVS];
static void which(const char *label) {
    const char *const *names = devs;
    char got[160] = "";
    struct timespec pause = {0, 100 * 1000 * 1000};
    nanosleep(&pause, NULL);
    for (int i = 0; i < DEVS; i++) {
        char buf[16];
        struct sockaddr_in from;
        socklen_t len = sizeof from;
        if (recvfrom(receivers[i], buf, sizeof buf, MSG_DONTWAIT, (void *)&from, &len) > 0) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from.sin_addr, ip, sizeof ip);
            size_t n = strlen(got);
            snprintf(got + n, sizeof got - n, " %s (from %s)", names[i], ip);
        }
    }
    printf("%s: taken by%s\n", label, got[0] ? got : " none");
}
static void set_if(int fd, int level, int name, unsigned index, socklen_t len, const char *label) {
    unsigned char raw[8] = {0};
    unsigned value = htonl(index);
    memcpy(raw, &value, 4);
    printf("%s: setsockopt=%ld\n", label, result(setsockopt(fd, level, name, raw, len)));
}
static void get_if(int fd, int level, int name, socklen_t room, const char *label) {
    unsigned char raw[8];
    memset(raw, 0xee, sizeof raw);
    socklen_t len = room;
    long r = result(getsockopt(fd, level, name, raw, &len));
    printf("%s: getsockopt=%ld len=%u", label, r, len);
    for (socklen_t i = 0; r == 0 && i < len && i < sizeof raw; i++) printf(" %02x", raw[i]);
    printf("\n");
}
static void send4(int fd, const char *ip, int port, const char *label) {
    struct sockaddr_in to = at4(ip, port);
    printf("%s: sendto=%ld\n", label, result(sendto(fd, "x", 1, 0, (void *)&to, sizeof to)));
}
static void send_mapped(int fd, const char *ip, int port, const char *label) {
    char mapped[64];
    snprintf(mapped, sizeof mapped, "::ffff:%s", ip);
    struct sockaddr_in6 to = at6(mapped, port);
    printf("%s: sendto=%ld\n", label, result(sendto(fd, "x", 1, 0, (void *)&to, sizeof to)));
}
/* Connects `fd` to `ip`:`port` and prints the name it then has. */
static void connect_name(int fd, int family, const char *ip, int port, const char *label) {
    long r;
    if (family == AF_INET6) {
        char mapped[64];
        snprintf(mapped, sizeof mapped, "::ffff:%s", ip);
        struct sockaddr_in6 to = at6(mapped, port);
        r = result(connect(fd, (void *)&to, sizeof to));
    } else {
        struct sockaddr_in to = at4(ip, port);
        r = result(connect(fd, (void *)&to, sizeof to));
    }
    struct sockaddr_in6 name;
    socklen_t len = sizeof name;
    getsockname(fd, (void *)&name, &len);
    char text[INET6_ADDRSTRLEN] = "?";
    if (name.sin6_family == AF_INET6)
        inet_ntop(AF_INET6, &name.sin6_addr, text, sizeof text);
    else
        inet_ntop(AF_INET, &((struct sockaddr_in *)&name)->sin_addr, text, sizeof text);
    printf("%s: connect=%ld name %s\n", label, r, text);
}

/* The neighbours of IPv4 the sends made: their addresses and devices. */
static void arp(void) {
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) {
        printf("no /proc/net/arp\n");
        return;
    }
    char line[256];
    char lines[16][64];
    int n = 0;
    if (fgets(line, sizeof line, f))
        while (n < 16 && fgets(line, sizeof line, f)) {
            char ip[32], hw[32], flags[16], mac[32], mask[16], dev[32];
            if (sscanf(line, "%31s %31s %15s %31s %15s %31s", ip, hw, flags, mac, mask, dev) == 6)
                snprintf(lines[n++], sizeof lines[0], "%s %s", ip, dev);
        }
    fclose(f);
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (strcmp(lines[i], lines[j]) > 0) {
                char t[64];
                memcpy(t, lines[i], sizeof t);
                memcpy(lines[i], lines[j], sizeof t);
                memcpy(lines[j], t, sizeof t);
            }
    for (int i = 0; i < n; i++) printf("neighbour %s\n", lines[i]);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-unicast-if")) return 99;
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

    /* The option. */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    get_if(s, IPPROTO_IP, IP_UNICAST_IF_, 4, "at first");
    set_if(s, IPPROTO_IP, IP_UNICAST_IF_, VA, 4, "to va");
    get_if(s, IPPROTO_IP, IP_UNICAST_IF_, 4, "on va");
    get_if(s, IPPROTO_IP, IP_UNICAST_IF_, 8, "on va, in 8 bytes");
    get_if(s, IPPROTO_IP, IP_UNICAST_IF_, 2, "on va, in 2 bytes");
    set_if(s, IPPROTO_IP, IP_UNICAST_IF_, 9999, 4, "to 9999");
    set_if(s, IPPROTO_IP, IP_UNICAST_IF_, VC, 2, "to vc, in 2 bytes");
    set_if(s, IPPROTO_IP, IP_UNICAST_IF_, VC, 8, "to vc, in 8 bytes");
    set_if(s, IPPROTO_IP, IP_UNICAST_IF_, VC, 0, "to vc, in no bytes");
    get_if(s, IPPROTO_IP, IP_UNICAST_IF_, 4, "still on va");
    set_if(s, IPPROTO_IP, IP_UNICAST_IF_, 0, 4, "to none");
    get_if(s, IPPROTO_IP, IP_UNICAST_IF_, 4, "on none");
    printf("bind to va=%ld\n", result(setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE_, "va", 2)));
    set_if(s, IPPROTO_IP, IP_UNICAST_IF_, VA, 4, "bound, to va");
    set_if(s, IPPROTO_IP, IP_UNICAST_IF_, 0, 4, "bound, to none");
    close(s);
    int t = socket(AF_INET, SOCK_STREAM, 0);
    set_if(t, IPPROTO_IP, IP_UNICAST_IF_, VC, 4, "TCP to vc");
    get_if(t, IPPROTO_IP, IP_UNICAST_IF_, 4, "TCP on vc");
    close(t);
    int six = socket(AF_INET6, SOCK_DGRAM, 0);
    set_if(six, IPPROTO_IP, IP_UNICAST_IF_, VC, 4, "UDP6 to vc");
    get_if(six, IPPROTO_IP, IP_UNICAST_IF_, 4, "UDP6 on vc");
    get_if(six, IPPROTO_IPV6, IPV6_UNICAST_IF_, 4, "UDP6, IPV6_UNICAST_IF");
    close(six);

    /* Where a datagram goes. */
    for (int i = 0; i < DEVS; i++) {
        receivers[i] = socket(AF_INET, SOCK_DGRAM, 0);
        setsockopt(receivers[i], SOL_SOCKET, SO_BINDTODEVICE_, devs[i], (socklen_t)strlen(devs[i]));
        struct sockaddr_in any = at4("0.0.0.0", 7000);
        printf("UDP on %s, port 7000: bind=%ld\n", devs[i], result(bind(receivers[i], (void *)&any, sizeof any)));
    }
    int out = socket(AF_INET, SOCK_DGRAM, 0);
    send4(out, "10.1.0.1", 7000, "to 10.1.0.1");
    which("to 10.1.0.1");
    set_if(out, IPPROTO_IP, IP_UNICAST_IF_, VA, 4, "out through va");
    send4(out, "10.1.0.1", 7000, "through va to 10.1.0.1");
    which("through va to 10.1.0.1");
    send4(out, "10.0.0.1", 7000, "through va to 10.0.0.1");
    which("through va to 10.0.0.1");
    send4(out, "10.0.0.7", 7000, "through va to 10.0.0.7");
    which("through va to 10.0.0.7");
    send4(out, "10.9.0.1", 7000, "through va to 10.9.0.1");
    which("through va to 10.9.0.1");
    send4(out, "127.0.0.1", 7000, "through va to 127.0.0.1");
    which("through va to 127.0.0.1");
    int on = 1;
    setsockopt(out, SOL_SOCKET, SO_BROADCAST, &on, sizeof on);
    send4(out, "255.255.255.255", 7000, "through va to 255.255.255.255");
    which("through va to 255.255.255.255");
    send4(out, "10.0.0.255", 7000, "through va to 10.0.0.255");
    which("through va to 10.0.0.255");
    set_if(out, IPPROTO_IP, IP_UNICAST_IF_, VC, 4, "out through vc");
    send4(out, "10.1.0.1", 7000, "through vc to 10.1.0.1");
    which("through vc to 10.1.0.1");
    send4(out, "10.0.0.1", 7000, "through vc to 10.0.0.1");
    which("through vc to 10.0.0.1");
    printf("bind to va=%ld\n", result(setsockopt(out, SOL_SOCKET, SO_BINDTODEVICE_, "va", 2)));
    send4(out, "10.1.0.1", 7000, "bound to va, through vc, to 10.1.0.1");
    which("bound to va, through vc, to 10.1.0.1");
    close(out);

    /* A connect's source. */
    int c = socket(AF_INET, SOCK_DGRAM, 0);
    connect_name(c, AF_INET, "10.1.0.1", 7000, "to 10.1.0.1");
    close(c);
    c = socket(AF_INET, SOCK_DGRAM, 0);
    set_if(c, IPPROTO_IP, IP_UNICAST_IF_, VA, 4, "out through va");
    connect_name(c, AF_INET, "10.1.0.1", 7000, "through va to 10.1.0.1");
    printf("send=%ld\n", result(send(c, "x", 1, 0)));
    which("connected through va to 10.1.0.1");
    close(c);

    /* An IPv6 socket's IPv4-mapped datagrams. */
    int m = socket(AF_INET6, SOCK_DGRAM, 0);
    set_if(m, IPPROTO_IPV6, IPV6_UNICAST_IF_, VA, 4, "UDP6, IPV6_UNICAST_IF to va");
    send_mapped(m, "10.1.0.1", 7000, "UDP6 through va (IPv6) to 10.1.0.1");
    which("UDP6 through va (IPv6) to 10.1.0.1");
    set_if(m, IPPROTO_IPV6, IPV6_UNICAST_IF_, 0, 4, "UDP6, IPV6_UNICAST_IF to none");
    set_if(m, IPPROTO_IP, IP_UNICAST_IF_, VA, 4, "UDP6, IP_UNICAST_IF to va");
    send_mapped(m, "10.1.0.1", 7000, "UDP6 through va to 10.1.0.1");
    which("UDP6 through va to 10.1.0.1");
    close(m);
    m = socket(AF_INET6, SOCK_DGRAM, 0);
    set_if(m, IPPROTO_IP, IP_UNICAST_IF_, VA, 4, "UDP6, IP_UNICAST_IF to va");
    connect_name(m, AF_INET6, "10.1.0.1", 7000, "UDP6 through va to 10.1.0.1");
    close(m);

    /* TCP goes by its routes alone. */
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in at8000 = at4("0.0.0.0", 8000);
    long bound_l = result(bind(l, (void *)&at8000, sizeof at8000));
    printf("TCP listener: bind=%ld listen=%ld\n", bound_l, result(listen(l, 4)));
    int tc = socket(AF_INET, SOCK_STREAM, 0);
    set_if(tc, IPPROTO_IP, IP_UNICAST_IF_, VA, 4, "TCP out through va");
    connect_name(tc, AF_INET, "10.1.0.1", 8000, "TCP through va to 10.1.0.1");
    arp();
    return 0;
}
