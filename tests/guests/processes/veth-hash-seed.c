/* Exactly which next hop each flow of a multipath route takes, by the
   seed of the hash (so as root): a network namespace with two veth pairs,
   "va" (1000, 10.0.0.1/24, 2001:db8::1/64) and "vc" (1002, 10.1.0.1/24,
   2001:db8:1::1/64), and routes to 10.2.0.0/24 and 2001:db8:2::/64
   through both, of weights 1 and 3. With net.ipv4.fib_multipath_hash_seed
   set, the hash of a flow is known (fib_multipath_hash_from_keys), so each
   lookup's hop is shown, "a" for va's and "c" for vc's, for both families;
   with none set, the seed is the machine's, every namespace's, so only
   that another namespace's hops are the same is shown. Then what the file
   takes and who may write it. */
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
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define NETLINK_ROUTE_ 0
#define RTM_NEWLINK 16
#define RTM_NEWADDR 20
#define RTM_NEWROUTE 24
#define RTM_GETROUTE 26
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
#define RTA_SRC 2
#define RTA_OIF 4
#define RTA_GATEWAY 5
#define RTA_MULTIPATH 9
#define RTA_IP_PROTO 27
#define RTA_FLOWLABEL 31
#define VA 1000
#define VB 1001
#define VC 1002
#define VD 1003
#define COUNT 48
#define SEED "/proc/sys/net/ipv4/fib_multipath_hash_seed"

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
/* RTNLGRP_LINK and RTNLGRP_IPV6_ROUTE of this or the other namespace, what
   is waited for. */
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
/* Adds a route to `dst`, of `len` bits, through `one` on va and `two` on
   vc, of weights 1 and 3. */
static void route(int fd, const char *dst, int len, const char *one, const char *two, const char *label) {
    int family = strchr(dst, ':') ? AF_INET6 : AF_INET;
    size_t size = family == AF_INET6 ? 16 : 4;
    struct body b = {0};
    const unsigned char rtm[12] = {(unsigned char)family, (unsigned char)len, 0, 0, 254, 3, 0, 1};
    const char *via[] = {one, two};
    const int oif[] = {VA, VC};
    unsigned char in[16];
    inet_pton(family, dst, in);
    raw(&b, rtm, sizeof rtm);
    put(&b, RTA_DST, in, size);
    size_t mp = begin(&b, RTA_MULTIPATH);
    for (int i = 0; i < 2; i++) {
        size_t at = b.len;
        unsigned char rtnh[8] = {0, 0, 0, i ? 2 : 0};
        memcpy(rtnh + 4, &oif[i], 4);
        raw(&b, rtnh, sizeof rtnh);
        inet_pton(family, via[i], in);
        put(&b, RTA_GATEWAY, in, size);
        unsigned short rlen = (unsigned short)(b.len - at);
        memcpy(b.bytes + at, &rlen, 2);
    }
    end(&b, mp);
    request(fd, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &b, label);
}
/* The device of the lookup of `dst` from `src` (none for NULL), with the
   flow label `flowlabel` and the protocol `proto` (none for 0). */
static int lookup(int fd, const char *dst, const char *src, unsigned flowlabel, int proto) {
    int family = strchr(dst, ':') ? AF_INET6 : AF_INET, device = -1;
    size_t size = family == AF_INET6 ? 16 : 4;
    struct body b = {0};
    const unsigned char rtm[12] = {(unsigned char)family, (unsigned char)(size * 8),
                                   (unsigned char)(src ? size * 8 : 0)};
    unsigned char in[16], p = (unsigned char)proto;
    raw(&b, rtm, sizeof rtm);
    inet_pton(family, dst, in);
    put(&b, RTA_DST, in, size);
    if (src) {
        inet_pton(family, src, in);
        put(&b, RTA_SRC, in, size);
    }
    if (proto) put(&b, RTA_IP_PROTO, &p, 1);
    if (flowlabel) put32(&b, RTA_FLOWLABEL, htonl(flowlabel));
    unsigned char buf[4096] = {0};
    struct nl_header *h = (void *)buf;
    h->len = sizeof *h + b.len;
    h->type = RTM_GETROUTE;
    h->flags = NLM_F_REQUEST;
    h->seq = ++seq;
    memcpy(buf + sizeof *h, b.bytes, b.len);
    struct nl_address kernel = {.family = AF_NETLINK};
    sendto(fd, buf, h->len, 0, (void *)&kernel, sizeof kernel);
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    if (poll(&ready, 1, 2000) <= 0 || recv(fd, buf, sizeof buf, 0) < (long)sizeof *h + 4 || h->type != RTM_NEWROUTE)
        return -1;
    const unsigned char *at = (const unsigned char *)(h + 1);
    int len = (int)(h->len - sizeof *h);
    for (int a = 12; a + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, at + a, 2);
        memcpy(&kind, at + a + 2, 2);
        if (alen < 4 || a + alen > len) break;
        if (kind == RTA_OIF && alen == 8) memcpy(&device, at + a + 4, 4);
        a += (alen + 3) & ~3;
    }
    return device;
}
/* The hops of COUNT lookups into `net` from `src`, a character each. */
static void hops(int fd, const char *net, const char *src, unsigned flowlabel, int proto, char *out) {
    for (int i = 0; i < COUNT; i++) {
        char dst[64];
        snprintf(dst, sizeof dst, strchr(net, ':') ? "%s%x" : "%s%d", net, i + 1);
        int device = lookup(fd, dst, src, flowlabel, proto);
        out[i] = device == VA ? 'a' : device == VC ? 'c' : '?';
    }
    out[COUNT] = 0;
}
static void shown(int fd, const char *net, const char *src, unsigned flowlabel, int proto, const char *label) {
    char out[COUNT + 1];
    hops(fd, net, src, flowlabel, proto, out);
    printf("%s: %s\n", label, out);
}
/* What each family's lookups give, the hops of no protocol being
   RTM_GETROUTE's own. */
static void all(int fd, const char *label) {
    printf("-- %s\n", label);
    shown(fd, "10.2.0.", NULL, 0, 0, "IPv4");
    shown(fd, "10.2.0.", "10.5.0.1", 0, 0, "IPv4 from lo's");
    shown(fd, "10.2.0.", "10.200.0.1", 0, 0, "IPv4 from lo's greater");
    shown(fd, "10.2.0.", "10.0.0.1", 0, 0, "IPv4 from va's");
    shown(fd, "10.2.0.", "10.5.0.1", 0, 17, "IPv4 from lo's, UDP");
    shown(fd, "2001:db8:2::", NULL, 0, 0, "IPv6");
    shown(fd, "2001:db8:2::", "2001:db8:5::1", 0, 0, "IPv6 from lo's");
    shown(fd, "2001:db8:2::", "2001:db8:5::1", 0, 6, "IPv6 from lo's, TCP");
    shown(fd, "2001:db8:2::", "2001:db8:5::1", 0, 17, "IPv6 from lo's, UDP");
    shown(fd, "2001:db8:2::", "2001:db8:5::1", 0x12345, 17, "IPv6 from lo's, UDP, a flow label");
    /* The sources of unbound UDP sockets connected to each, which tell the
       hops. */
    char out[COUNT + 1];
    for (int i = 0; i < COUNT; i++) {
        struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(7000)}, at = {0};
        socklen_t len = sizeof at;
        to.sin_addr.s_addr = htonl(0x0a020000u + (unsigned)i + 1);
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        connect(s, (void *)&to, sizeof to);
        getsockname(s, (void *)&at, &len);
        close(s);
        out[i] = at.sin_addr.s_addr == inet_addr("10.0.0.1") ? 'a' : at.sin_addr.s_addr == inet_addr("10.1.0.1") ? 'c' : '?';
    }
    out[COUNT] = 0;
    printf("IPv4 connected: %s\n", out);
}
static void get(const char *label) {
    char text[32] = {0};
    int fd = open(SEED, O_RDONLY);
    long n = result(fd < 0 ? fd : read(fd, text, sizeof text - 1));
    if (fd >= 0) close(fd);
    for (char *c = text; *c; c++)
        if (*c == '\n') *c = '|';
    printf("%s: read=%ld %s\n", label, n, text);
}
static void set(const char *value, const char *label) {
    int fd = open(SEED, O_WRONLY);
    long n = result(fd < 0 ? fd : write(fd, value, strlen(value)));
    if (fd >= 0) close(fd);
    printf("%s: write=%ld\n", label, n);
    get(label);
}
/* Two pairs, their addresses and the routes. */
static int set_up(void) {
    int ctl = route_socket(0);
    events = route_socket(1 | 0x400);
    make_pair(ctl, VA, "va", VB, "vb", 0x0a);
    make_pair(ctl, VC, "vc", VD, "vd", 0x0c);
    sysctl("/proc/sys/net/ipv6/conf/va/accept_dad", "0");
    sysctl("/proc/sys/net/ipv6/conf/vc/accept_dad", "0");
    set_link(ctl, 1, 1, "up lo");
    set_link(ctl, VB, 1, "up vb");
    set_link(ctl, VD, 1, "up vd");
    up(ctl, VA, "fe80::ff:fe00:a", "up va");
    up(ctl, VC, "fe80::ff:fe00:c", "up vc");
    address4(ctl, VA, "10.0.0.1", 24, "add va's IPv4 address");
    address4(ctl, VC, "10.1.0.1", 24, "add vc's IPv4 address");
    address4(ctl, 1, "10.5.0.1", 32, "add 10.5.0.1/32");
    address4(ctl, 1, "10.200.0.1", 32, "add 10.200.0.1/32");
    address6(ctl, VA, "2001:db8::1", 64, "add va's address");
    address6(ctl, VC, "2001:db8:1::1", 64, "add vc's address");
    address6(ctl, 1, "2001:db8:5::1", 128, "add 2001:db8:5::1/128");
    route(ctl, "10.2.0.0", 24, "10.0.0.2", "10.1.0.2", "10.2.0.0/24");
    route(ctl, "2001:db8:2::", 64, "2001:db8::2", "2001:db8:1::2", "2001:db8:2::/64");
    return ctl;
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-hash-seed")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    struct stat st = {0};
    long r = result(stat(SEED, &st));
    printf("stat=%ld mode=%o uid=%d gid=%d\n", r, st.st_mode, st.st_uid, st.st_gid);
    get("built");
    int ctl = set_up();
    char first4[COUNT + 1], first6[COUNT + 1], second[COUNT + 1];
    hops(ctl, "10.2.0.", "10.5.0.1", 0, 0, first4);
    hops(ctl, "2001:db8:2::", "2001:db8:5::1", 0, 17, first6);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int other = set_up();
    hops(other, "10.2.0.", "10.5.0.1", 0, 0, second);
    printf("another namespace's IPv4: %s\n", strcmp(first4, second) ? "differ" : "same");
    hops(other, "2001:db8:2::", "2001:db8:5::1", 0, 17, second);
    printf("another namespace's IPv6: %s\n", strcmp(first6, second) ? "differ" : "same");

    set("1", "seed 1");
    all(other, "seed 1");
    set("3735928559", "seed 0xdeadbeef");
    all(other, "seed 0xdeadbeef");
    set("4294967295", "seed 0xffffffff");
    all(other, "seed 0xffffffff");
    /* Another namespace's is its own, the first one's still none. */
    hops(ctl, "10.2.0.", "10.5.0.1", 0, 0, second);
    printf("the first namespace's IPv4: %s\n", strcmp(first4, second) ? "differ" : "same");
    set("0", "seed 0");
    hops(other, "10.2.0.", "10.5.0.1", 0, 0, second);
    printf("IPv4 with none: %s\n", strcmp(first4, second) ? "differ" : "same");

    static const char *written[] = {"",      "x",          "-1",         "-0",   "4294967296", "4294967295", " 7 \n",
                                    "9 9",   "0x10",       "010",        "5x",   "8\n9",       "\n",         "99999999999999999999",
                                    "+3",    "000000012",  "6\t",        "11\r"};
    for (size_t i = 0; i < sizeof written / sizeof written[0]; i++) {
        char label[32];
        snprintf(label, sizeof label, "value %zu", i);
        set(written[i], label);
    }
    int fd = open(SEED, O_RDWR);
    /* Seeks first: a call's arguments may be evaluated in any order. */
    long seek = (long)lseek(fd, 1, SEEK_SET);
    printf("at 1: seek=%ld write=%ld\n", seek, result(write(fd, "3", 1)));
    get("at 1");
    lseek(fd, 0, SEEK_SET);
    printf("twice: write=%ld", result(write(fd, "21", 2)));
    printf(" %ld\n", result(write(fd, "22", 2)));
    get("twice");
    close(fd);
    /* Another user may not write it; one with CAP_NET_ADMIN over the user
       namespace that owns the network namespace may. */
    pid_t child = fork();
    if (child == 0) {
        printf("setuid=%ld\n", result(setresuid(1000, 1000, 1000)));
        fd = open(SEED, O_WRONLY);
        printf("another user's open: %ld\n", fd < 0 ? -(long)errno : 0);
        get("another user's");
        _exit(0);
    }
    waitpid(child, NULL, 0);
    child = fork();
    if (child == 0) {
        long made = result(unshare(CLONE_NEWUSER | CLONE_NEWNET));
        fd = open("/proc/self/uid_map", O_WRONLY);
        long mapped = result(write(fd, "0 0 1", 5));
        close(fd);
        printf("unshare=%ld map=%ld\n", made, mapped);
        r = result(stat(SEED, &st));
        printf("stat=%ld mode=%o uid=%d\n", r, st.st_mode, st.st_uid);
        set("17", "a user namespace's");
        _exit(0);
    }
    waitpid(child, NULL, 0);
    get("still");
    return 0;
}
