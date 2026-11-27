/* IPv6's anycast addresses (so as root): those sockets join
   (IPV6_JOIN_ANYCAST, IPV6_LEAVE_ANYCAST) and the subnet-router ones a
   device that forwards has of each of its addresses (addrconf_join_anycast),
   as /proc/net/anycast6, the RTM_GETANYCAST dump and the local table show
   them, and as RTNLGRP_IPV6_ACADDR and RTNLGRP_IPV6_ROUTE tell of them. The
   process makes a network namespace of its own, with lo, and a pair, va
   (1000, 02:00:00:00:00:0a) and vb (1001, ...:0b), without duplicate
   address detection. A host joins one only of a prefix of the device's;
   a device that forwards joins any. Each anycast address joins its
   solicited-node group. Linux makes a device's link-local address, and an
   address's subnet-router anycast one, from its work queue a little after
   what makes them, so the case polls /proc/net/anycast6 until what it
   waits for is there. No time is shown. */
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
#include <time.h>
#include <unistd.h>

#define NLM_F_REQUEST 1
#define NLM_F_ACK 4
#define NLM_F_DUMP 0x300
#define NLM_F_CREATE 0x400
#define NLMSG_ERROR 2
#define NLMSG_DONE 3
#define RTM_NEWLINK 16
#define RTM_DELLINK 17
#define RTM_NEWADDR 20
#define RTM_DELADDR 21
#define RTM_NEWROUTE 24
#define RTM_DELROUTE 25
#define RTM_GETROUTE 26
#define RTM_NEWANYCAST 60
#define RTM_DELANYCAST 61
#define RTM_GETANYCAST 62
#define IFA_ADDRESS 1
#define IFA_LOCAL 2
#define IFA_ANYCAST 5
#define IFA_CACHEINFO 6
#define RTA_DST 1
#define RTA_OIF 4
#define RTA_TABLE 15
#define SOL_NETLINK_ 270
#define NETLINK_ADD_MEMBERSHIP_ 1
#define NETLINK_GET_STRICT_CHK_ 12
#define RTNLGRP_IPV6_ROUTE 11
#define RTNLGRP_IPV6_ACADDR 39
#define IPV6_JOIN_ANYCAST_ 27
#define IPV6_LEAVE_ANYCAST_ 28
#define VA 1000
#define VB 1001

struct body {
    unsigned char bytes[512];
    size_t len;
};
static int ctl = -1, acmon = -1, rtmon = -1;
static unsigned seq;

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
/* Sends a request and prints its acknowledgement's error. */
static void request(unsigned short type, const struct body *b, const char *label) {
    unsigned char buf[4096] = {0};
    const unsigned head[4] = {(unsigned)(16 + b->len), type | (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE) << 16, ++seq, 0};
    memcpy(buf, head, 16);
    memcpy(buf + 16, b->bytes, b->len);
    send(ctl, buf, head[0], 0);
    struct pollfd ready = {.fd = ctl, .events = POLLIN};
    if (poll(&ready, 1, 2000) <= 0 || recv(ctl, buf, sizeof buf, 0) < 20) {
        printf("%s: no answer\n", label);
        return;
    }
    int error;
    memcpy(&error, buf + 16, 4);
    printf("%s: error=%d\n", label, error);
}
static void link_flags(int index, unsigned flags, const char *label) {
    struct body b = {0};
    const unsigned m[4] = {0, (unsigned)index, flags, IFF_UP};
    raw(&b, m, 16);
    request(RTM_NEWLINK, &b, label);
}
static void make_pair(void) {
    struct body m = {0};
    const unsigned char mac_a[6] = {2, 0, 0, 0, 0, 0x0a}, mac_b[6] = {2, 0, 0, 0, 0, 0x0b};
    const unsigned a[4] = {0, VA, 0, 0}, b[4] = {0, VB, 0, 0};
    raw(&m, a, 16);
    put(&m, 3, "va", 3);
    put(&m, 1, mac_a, 6);
    size_t link = begin(&m, 18);
    put(&m, 1, "veth", 5);
    size_t data = begin(&m, 2), peer = begin(&m, 1);
    raw(&m, b, 16);
    put(&m, 3, "vb", 3);
    put(&m, 1, mac_b, 6);
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(RTM_NEWLINK, &m, "make a pair");
}
/* Adds (or removes) an address of `prefix` bits without duplicate address
   detection (IFA_F_NODAD). */
static void address(unsigned short type, int index, const char *text, int prefix, const char *label) {
    struct body b = {0};
    const unsigned char m[8] = {AF_INET6, (unsigned char)prefix, 0x02, 0, (unsigned char)index, (unsigned char)(index >> 8), 0, 0};
    unsigned char in[16];
    inet_pton(AF_INET6, text, in);
    raw(&b, m, 8);
    put(&b, IFA_LOCAL, in, 16);
    put(&b, IFA_ADDRESS, in, 16);
    request(type, &b, label);
}
static void write_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY);
    long n = fd < 0 ? -errno : result(write(fd, text, strlen(text)));
    if (fd >= 0) close(fd);
    printf("%s <- %s: %ld\n", path, text, n);
}

static int ours(int index) { return index == 1 || index == VA || index == VB; }
/* An anycast address's message as a line: its kind, the ifaddrmsg, the
   address and the lifetimes of its cache information; 0 for one not
   ours. */
static int anycast_line(const unsigned char *m, char *out, size_t size) {
    unsigned short type;
    unsigned len;
    memcpy(&len, m, 4);
    memcpy(&type, m + 4, 2);
    int index;
    memcpy(&index, m + 20, 4);
    if (!ours(index)) return 0;
    char ip[64] = "-";
    unsigned prefered = 0, valid = 0;
    int cache = 0;
    for (unsigned at = 24; at + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, m + at, 2);
        memcpy(&kind, m + at + 2, 2);
        if (alen < 4) break;
        const unsigned char *v = m + at + 4;
        if (kind == IFA_ANYCAST && alen == 20) inet_ntop(AF_INET6, v, ip, sizeof ip);
        if (kind == IFA_CACHEINFO && alen == 20) {
            memcpy(&prefered, v, 4);
            memcpy(&valid, v + 4, 4);
            cache = 1;
        }
        at += (alen + 3) & ~3u;
    }
    snprintf(out, size, "%s family=%u len=%u flags=%#x scope=%u dev=%d %s cache=%d %#x %#x",
             type == RTM_NEWANYCAST ? "new" : type == RTM_DELANYCAST ? "del" : type == RTM_GETANYCAST ? "get" : "?", m[16], m[17], m[18], m[19], index,
             ip, cache, prefered, valid);
    return 1;
}
/* An IPv6 route's message as a line, for an anycast one (RTN_ANYCAST)
   alone: its kind, the rtmsg, its destination, table and device. */
static int route_line(const unsigned char *m, char *out, size_t size) {
    unsigned short type;
    unsigned len;
    memcpy(&len, m, 4);
    memcpy(&type, m + 4, 2);
    if (m[16] != AF_INET6 || m[23] != 4) return 0;
    char ip[64] = "-";
    unsigned table = 0;
    int oif = 0;
    for (unsigned at = 28; at + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, m + at, 2);
        memcpy(&kind, m + at + 2, 2);
        if (alen < 4) break;
        const unsigned char *v = m + at + 4;
        if (kind == RTA_DST && alen == 20) inet_ntop(AF_INET6, v, ip, sizeof ip);
        if (kind == RTA_TABLE && alen == 8) memcpy(&table, v, 4);
        if (kind == RTA_OIF && alen == 8) memcpy(&oif, v, 4);
        at += (alen + 3) & ~3u;
    }
    snprintf(out, size, "%s dst_len=%u table=%u/%u proto=%u scope=%u flags=%#x %s dev=%d",
             type == RTM_NEWROUTE ? "new" : type == RTM_DELROUTE ? "del" : "?", m[17], m[20], table, m[21], m[22],
             m[24] | m[25] << 8, ip, oif);
    return 1;
}

/* Dumps with a request of `type` and the header `head` of `size`
   bytes, printing each message `line_of` takes. */
static void dump(unsigned short type, const void *head, size_t size, int (*line_of)(const unsigned char *, char *, size_t),
                 const char *label) {
    unsigned char buf[16384] = {0};
    const unsigned h[4] = {(unsigned)(16 + size), type | (NLM_F_REQUEST | NLM_F_DUMP) << 16, ++seq, 0};
    memcpy(buf, h, 16);
    memcpy(buf + 16, head, size);
    send(ctl, buf, h[0], 0);
    printf("-- dump: %s\n", label);
    for (;;) {
        struct pollfd ready = {.fd = ctl, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) {
            printf("no end\n");
            return;
        }
        long n = recv(ctl, buf, sizeof buf, 0);
        for (long at = 0; at + 16 <= n;) {
            unsigned len;
            unsigned short kind;
            memcpy(&len, buf + at, 4);
            memcpy(&kind, buf + at + 4, 2);
            if (len < 16 || at + len > n) break;
            if (kind == NLMSG_ERROR) {
                int error;
                memcpy(&error, buf + at + 16, 4);
                printf("error=%d\n", error);
                return;
            }
            if (kind == NLMSG_DONE) return;
            char line[200];
            if (line_of(buf + at, line, sizeof line)) printf("%s\n", line);
            at += (len + 3) & ~3u;
        }
    }
}
static void anycast_dump(const char *label) {
    const unsigned char m[8] = {AF_INET6};
    dump(RTM_GETANYCAST, m, 8, anycast_line, label);
}
static void route_dump(const char *label) {
    const unsigned char m[12] = {AF_INET6};
    dump(RTM_GETROUTE, m, 12, route_line, label);
}
/* Prints what `fd` is told, as `line_of` takes it: `wait` lines, then
   those there are. */
static void heard(int fd, int wait, int (*line_of)(const unsigned char *, char *, size_t), const char *label) {
    int count = 0;
    printf("-- told: %s\n", label);
    for (;;) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (count >= wait && poll(&ready, 1, 0) <= 0) break;
        if (count < wait && poll(&ready, 1, 5000) <= 0) {
            printf("waited for %d, heard %d\n", wait, count);
            break;
        }
        unsigned char buf[8192];
        long n = recv(fd, buf, sizeof buf, 0);
        for (long at = 0; n > 0 && at + 16 <= n;) {
            unsigned len;
            memcpy(&len, buf + at, 4);
            if (len < 16 || at + len > n) break;
            char line[200];
            if (line_of(buf + at, line, sizeof line)) {
                printf("%s\n", line);
                count++;
            }
            at += (len + 3) & ~3u;
        }
    }
}

static char text[16384];
/* Reads `path` into `text`. */
static void slurp(const char *path) {
    int fd = open(path, O_RDONLY);
    long n, all = 0;
    while (fd >= 0 && (n = read(fd, text + all, sizeof text - 1 - (size_t)all)) > 0) all += n;
    if (fd >= 0) close(fd);
    text[all] = 0;
}
static double seconds(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
/* Polls the file `path` until it has (or, not `there`, has not) a line of
   `entry`, for 10 s at most; whether it waited in vain. */
static int await_file(const char *path, const char *entry, int there) {
    int found = !there;
    for (double until = seconds() + 10; seconds() < until;) {
        slurp(path);
        found = strstr(text, entry) != NULL;
        if (found == there) break;
        struct timespec pause = {0, 20 * 1000 * 1000};
        nanosleep(&pause, NULL);
    }
    return found != there;
}
/* Polls /proc/net/anycast6 until it has (or, not `there`, has not) a line
   of `entry`, for 10 s at most, then prints it. */
static void await_anycast(const char *entry, int there, const char *label) {
    int missed = await_file("/proc/net/anycast6", entry, there);
    printf("-- anycast6: %s\n", label);
    if (missed) printf("waited for %s\n", entry);
    printf("%s", text);
}
/* The anycast routes (RTF_ANYCAST) of /proc/net/ipv6_route: each one's
   destination, prefix, gateway, metric, flags and device, but not its
   reference and use counts. */
static void ipv6_route(const char *label) {
    slurp("/proc/net/ipv6_route");
    printf("-- ipv6_route: %s\n", label);
    for (char *line = text, *next; *line; line = next) {
        next = strchr(line, '\n');
        if (!next) break;
        *next++ = 0;
        char dst[40], len[4], src[40], slen[4], gw[40], metric[12], device[20];
        unsigned refs, use, flags;
        if (sscanf(line, "%39s %3s %39s %3s %39s %11s %x %x %x %19s", dst, len, src, slen, gw, metric, &refs, &use, &flags,
                   device) == 10 &&
            flags & 0x100000)
            printf("%s %s %s %s %s %s %08x %s\n", dst, len, src, slen, gw, metric, flags, device);
    }
}
/* The membership of `fd` in `ip` on the device `index`, joined or left,
   with the option of `len` bytes. */
static void anycast(int fd, int option, int index, const char *ip, socklen_t len, const char *label) {
    struct ipv6_mreq m = {.ipv6mr_interface = (unsigned)index};
    inet_pton(AF_INET6, ip, &m.ipv6mr_multiaddr);
    printf("%s: %ld\n", label, result(setsockopt(fd, IPPROTO_IPV6, option, &m, len)));
}
static void join(int fd, int index, const char *ip, const char *label) {
    anycast(fd, IPV6_JOIN_ANYCAST_, index, ip, sizeof(struct ipv6_mreq), label);
}
static void leave(int fd, int index, const char *ip, const char *label) {
    anycast(fd, IPV6_LEAVE_ANYCAST_, index, ip, sizeof(struct ipv6_mreq), label);
}
static int monitor_of(int group) {
    int fd = socket(AF_NETLINK, SOCK_RAW, 0);
    struct {
        unsigned short family, pad;
        unsigned pid, groups;
    } at = {.family = AF_NETLINK};
    bind(fd, (void *)&at, sizeof at);
    printf("monitor %d=%ld\n", group, result(setsockopt(fd, SOL_NETLINK_, NETLINK_ADD_MEMBERSHIP_, &group, sizeof group)));
    return fd;
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-ipv6-anycast")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    ctl = socket(AF_NETLINK, SOCK_RAW, 0);
    int one = 1;
    setsockopt(ctl, SOL_NETLINK_, NETLINK_GET_STRICT_CHK_, &one, sizeof one);
    acmon = monitor_of(RTNLGRP_IPV6_ACADDR);
    rtmon = monitor_of(RTNLGRP_IPV6_ROUTE);
    write_file("/proc/sys/net/ipv6/conf/default/accept_dad", "0");

    link_flags(1, IFF_UP, "lo up");
    make_pair();
    link_flags(VA, IFF_UP, "va up");
    link_flags(VB, IFF_UP, "vb up");
    /* Ready, each end has its link-local address. */
    printf("link-local addresses waited for: %d %d\n", await_file("/proc/net/if_inet6", "fe80000000000000000000fffe00000a", 1),
           await_file("/proc/net/if_inet6", "fe80000000000000000000fffe00000b", 1));
    address(RTM_NEWADDR, VB, "fe80::b1", 64, "vb's fe80::b1");

    /* A host joins only an address of a prefix of the device's. */
    int s = socket(AF_INET6, SOCK_DGRAM, 0), t = socket(AF_INET6, SOCK_STREAM, 0);
    anycast(s, IPV6_JOIN_ANYCAST_, VB, "fe80::1234", 19, "short");
    join(s, VB, "ff02::1", "a multicast address");
    join(s, 1, "::1", "a local address");
    join(s, VB, "fe80::b1", "vb's own address");
    join(s, 999, "fe80::1234", "no such device");
    join(s, VB, "2001:db8:9::1", "no prefix of vb's");
    join(s, 0, "2001:db8:9::1", "no route");
    join(s, VB, "fe80::1234", "fe80::1234 on vb");
    join(s, VB, "fe80::1234", "fe80::1234 on vb again");
    join(t, VB, "fe80::1234", "a TCP socket's fe80::1234 on vb");
    join(t, VA, "fe80::99", "a TCP socket's fe80::99 on va");
    leave(s, VB, "fe80::5678", "leave what it has not");
    leave(s, VA, "fe80::1234", "leave on another device");
    int value = 0;
    socklen_t size = sizeof value;
    printf("get: %ld\n", result(getsockopt(s, IPPROTO_IPV6, IPV6_JOIN_ANYCAST_, &value, &size)));
    await_anycast("fe800000000000000000000000001234", 1, "joined");
    anycast_dump("joined");
    route_dump("joined");
    ipv6_route("joined");
    heard(acmon, 2, anycast_line, "joined");
    heard(rtmon, 2, route_line, "joined");
    leave(s, 0, "fe80::1234", "leave on any device");
    close(t);
    await_anycast("fe800000000000000000000000000099", 0, "a socket closed");
    heard(acmon, 1, anycast_line, "a socket closed");
    heard(rtmon, 1, route_line, "a socket closed");

    /* va forwards: it joins the subnet-router anycast address of each of
       its addresses but those of 127 bits and more, and as a router any
       address. */
    write_file("/proc/sys/net/ipv6/conf/va/forwarding", "1");
    await_anycast("fe800000000000000000000000000000", 1, "va forwards");
    address(RTM_NEWADDR, VA, "2001:db8:1::5", 64, "va's 2001:db8:1::5/64");
    address(RTM_NEWADDR, VA, "2001:db8:2::5", 127, "va's 2001:db8:2::5/127");
    address(RTM_NEWADDR, VA, "2001:db8:1::6", 64, "va's 2001:db8:1::6/64");
    await_anycast("20010db8000100000000000000000000", 1, "va's addresses");
    join(s, VA, "2001:db8:9::1", "a router's 2001:db8:9::1");
    join(s, 0, "2001:db8:9::2", "a router's without a route, all hosts");
    join(s, VB, "2001:db8:1::77", "a host's of va's prefix on vb");
    join(s, 0, "2001:db8:1::77", "of va's prefix on the route's device");
    await_anycast("20010db8000100000000000000000077", 1, "joined as a router");
    anycast_dump("va forwards");
    route_dump("va forwards");
    ipv6_route("va forwards");
    heard(acmon, 4, anycast_line, "va forwards");
    heard(rtmon, 4, route_line, "va forwards");

    address(RTM_DELADDR, VA, "2001:db8:1::6", 64, "remove 2001:db8:1::6");
    address(RTM_DELADDR, VA, "2001:db8:1::5", 64, "remove 2001:db8:1::5");
    await_anycast("20010db8000100000000000000000000", 0, "va's 2001:db8:1:: addresses gone");
    heard(acmon, 1, anycast_line, "va's 2001:db8:1:: addresses gone");
    heard(rtmon, 1, route_line, "va's 2001:db8:1:: addresses gone");

    /* Down, va's routes go and so do its addresses, with their anycast
       ones; what sockets joined stays. Up, its link-local address brings
       its own again. */
    link_flags(VA, 0, "va down");
    await_anycast("fe800000000000000000000000000000", 0, "va down");
    route_dump("va down");
    heard(acmon, 1, anycast_line, "va down");
    heard(rtmon, 3, route_line, "va down");
    link_flags(VA, IFF_UP, "va up again");
    await_anycast("fe800000000000000000000000000000", 1, "va up again");
    route_dump("va up again");
    heard(acmon, 1, anycast_line, "va up again");
    heard(rtmon, 1, route_line, "va up again");

    write_file("/proc/sys/net/ipv6/conf/va/forwarding", "0");
    await_anycast("fe800000000000000000000000000000", 0, "va forwards no more");
    heard(acmon, 1, anycast_line, "va forwards no more");
    heard(rtmon, 1, route_line, "va forwards no more");
    write_file("/proc/sys/net/ipv6/conf/all/forwarding", "1");
    await_anycast("fe800000000000000000000000000000", 1, "all forward");
    heard(acmon, 2, anycast_line, "all forward");
    heard(rtmon, 2, route_line, "all forward");
    write_file("/proc/sys/net/ipv6/conf/all/forwarding", "0");
    await_anycast("fe800000000000000000000000000000", 0, "none forwards");
    heard(acmon, 2, anycast_line, "none forwards");
    heard(rtmon, 2, route_line, "none forwards");

    /* The pair goes, and what is left of its anycast addresses. */
    struct body b = {0};
    const unsigned m[4] = {0, VA, 0, 0};
    raw(&b, m, 16);
    request(RTM_DELLINK, &b, "the pair goes");
    await_anycast("fe800000000000000000000000001234", 0, "the pair gone");
    heard(acmon, 0, anycast_line, "the pair gone");
    heard(rtmon, 0, route_line, "the pair gone");
    leave(s, VB, "fe80::1234", "leave on a device gone");
    close(s);
    return 0;
}
