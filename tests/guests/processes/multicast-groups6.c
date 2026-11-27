/* The IPv6 groups of each device (so as root): those a device joins by
   itself, the all-nodes groups as it comes to IPv6, the solicited-node group
   of each address, the all-routers groups as it forwards (while it has no
   address, so no subnet-router anycast one), and those sockets
   join, as RTM_GETMULTICAST dumps them, /proc/net/igmp6 shows them and
   RTNLGRP_IPV6_MCADDR is told of them. The process makes a network namespace
   of its own, with lo, and a pair, va (1000, 02:00:00:00:00:0a) and vb
   (1001, ...:0b), and follows them up, given an address, forwarding, down,
   up again and deleted. Linux joins an address's solicited-node group by its
   work after the address comes, so the case waits to be told of each before
   it goes on, and prints what is told sorted where two may come in either
   order. IFA_MC_USERS (Linux master only) and the cache information are not
   shown, nor any device but lo, va and vb. */
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
#define RTM_NEWMULTICAST 56
#define RTM_DELMULTICAST 57
#define RTM_GETMULTICAST 58
#define IFA_ADDRESS 1
#define IFA_LOCAL 2
#define IFA_MULTICAST 7
#define IFA_F_NODAD 2
#define SOL_NETLINK_ 270
#define NETLINK_ADD_MEMBERSHIP_ 1
#define NETLINK_GET_STRICT_CHK_ 12
#define RTNLGRP_IPV6_MCADDR 38
#define VA 1000
#define VB 1001

struct body {
    unsigned char bytes[512];
    size_t len;
};
static int ctl = -1, monitor = -1;
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
static void link_flags(unsigned short type, int index, unsigned flags, const char *label) {
    struct body b = {0};
    const unsigned m[4] = {0, (unsigned)index, flags, IFF_UP};
    raw(&b, m, 16);
    request(type, &b, label);
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
static void address(int index, const char *text, const char *label) {
    struct body b = {0};
    const unsigned char m[8] = {AF_INET6, 64, IFA_F_NODAD, 0, (unsigned char)index, (unsigned char)(index >> 8), 0, 0};
    unsigned char in[16];
    inet_pton(AF_INET6, text, in);
    raw(&b, m, 8);
    put(&b, IFA_LOCAL, in, 16);
    put(&b, IFA_ADDRESS, in, 16);
    request(RTM_NEWADDR, &b, label);
}

static int ours(int index) { return index == 1 || index == VA || index == VB; }
/* One group's message, as a line: its kind, header and group. */
static int line_of(const unsigned char *m, char *out, size_t size) {
    unsigned short type;
    unsigned len;
    memcpy(&len, m, 4);
    memcpy(&type, m + 4, 2);
    int index;
    memcpy(&index, m + 20, 4);
    if (!ours(index)) return 0;
    char group[64] = "?";
    for (unsigned at = 24; at + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, m + at, 2);
        memcpy(&kind, m + at + 2, 2);
        if (alen < 4) break;
        if (kind == IFA_MULTICAST && alen == 20) inet_ntop(AF_INET6, m + at + 4, group, sizeof group);
        at += (alen + 3) & ~3u;
    }
    snprintf(out, size, "%s family=%u prefix=%u flags=%u scope=%u index=%d %s",
             type == RTM_NEWMULTICAST ? "new" : type == RTM_DELMULTICAST ? "del" : "get", m[16], m[17], m[18], m[19],
             index, group);
    return 1;
}
static int compare(const void *a, const void *b) { return strcmp((const char *)a, (const char *)b); }
/* Reads what the monitor is told: `wait` messages of ours, or, for 0, those
   there are now; printed sorted where `sorted`. */
static void heard(int wait, int sorted, const char *label) {
    static char lines[64][128];
    int count = 0;
    printf("-- told: %s\n", label);
    for (;;) {
        struct pollfd ready = {.fd = monitor, .events = POLLIN};
        if (count >= wait && poll(&ready, 1, 0) <= 0) break;
        if (count < wait && poll(&ready, 1, 5000) <= 0) {
            printf("waited for %d, heard %d\n", wait, count);
            break;
        }
        unsigned char buf[8192];
        long n = recv(monitor, buf, sizeof buf, 0);
        for (long at = 0; n > 0 && at + 16 <= n;) {
            unsigned len;
            memcpy(&len, buf + at, 4);
            if (len < 16 || at + len > n) break;
            if (count < 64 && line_of(buf + at, lines[count], sizeof lines[count])) count++;
            at += (len + 3) & ~3u;
        }
    }
    if (sorted) qsort(lines, (size_t)count, sizeof lines[0], compare);
    for (int i = 0; i < count; i++) printf("%s\n", lines[i]);
}
/* A dump of the IPv6 groups, of the device `index` or of all for 0, with
   `prefix` in the request's header; strictly. */
static void dump(int index, int prefix, const char *label) {
    unsigned char buf[16384] = {0};
    const unsigned head[4] = {24, RTM_GETMULTICAST | (NLM_F_REQUEST | NLM_F_DUMP) << 16, ++seq, 0};
    memcpy(buf, head, 16);
    buf[16] = AF_INET6;
    buf[17] = (unsigned char)prefix;
    memcpy(buf + 20, &index, 4);
    send(ctl, buf, 24, 0);
    printf("-- dump: %s\n", label);
    for (int done = 0; !done;) {
        struct pollfd ready = {.fd = ctl, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) {
            printf("no answer\n");
            return;
        }
        long n = recv(ctl, buf, sizeof buf, 0);
        for (long at = 0; at + 16 <= n;) {
            unsigned len;
            unsigned short type, flags;
            memcpy(&len, buf + at, 4);
            memcpy(&type, buf + at + 4, 2);
            memcpy(&flags, buf + at + 6, 2);
            if (len < 16 || at + len > n) break;
            if (type == NLMSG_DONE || type == NLMSG_ERROR) {
                int error;
                memcpy(&error, buf + at + 16, 4);
                printf("%s %d flags=%#x\n", type == NLMSG_DONE ? "done" : "error", error, flags);
                done = 1;
            } else {
                char line[128];
                if (line_of(buf + at, line, sizeof line)) printf("%s multi=%d\n", line, !!(flags & 2));
            }
            at += (len + 3) & ~3u;
        }
    }
}
static void igmp6(const char *label) {
    static char text[16384];
    int fd = open("/proc/net/igmp6", O_RDONLY);
    long n, all = 0;
    while (fd >= 0 && (n = read(fd, text + all, sizeof text - 1 - (size_t)all)) > 0) all += n;
    if (fd >= 0) close(fd);
    text[all] = 0;
    printf("-- igmp6: %s\n", label);
    for (char *line = text, *next; *line; line = next) {
        next = strchr(line, '\n');
        if (!next) break;
        *next++ = 0;
        if (ours(atoi(line))) printf("|%s|\n", line);
    }
}
static void forwarding(const char *value, const char *label) {
    int fd = open("/proc/sys/net/ipv6/conf/va/forwarding", O_WRONLY);
    printf("%s: %ld\n", label, result(write(fd, value, 1)));
    close(fd);
}
static int join(int fd, int index, const char *group, int how, const char *label) {
    struct ipv6_mreq m = {.ipv6mr_interface = (unsigned)index};
    inet_pton(AF_INET6, group, &m.ipv6mr_multiaddr);
    if (fd < 0) fd = socket(AF_INET6, SOCK_DGRAM, 0);
    printf("%s: %ld\n", label, result(setsockopt(fd, IPPROTO_IPV6, how, &m, sizeof m)));
    return fd;
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "multicast-groups6")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    ctl = socket(AF_NETLINK, SOCK_RAW, 0);
    int one = 1;
    setsockopt(ctl, SOL_NETLINK_, NETLINK_GET_STRICT_CHK_, &one, sizeof one);
    monitor = socket(AF_NETLINK, SOCK_RAW, 0);
    struct {
        unsigned short family, pad;
        unsigned pid, groups;
    } at = {.family = AF_NETLINK};
    bind(monitor, (void *)&at, sizeof at);
    int group = RTNLGRP_IPV6_MCADDR;
    printf("monitor=%ld\n", result(setsockopt(monitor, SOL_NETLINK_, NETLINK_ADD_MEMBERSHIP_, &group, sizeof group)));
    dump(0, 0, "lo down");
    igmp6("lo down");
    link_flags(RTM_NEWLINK, 1, IFF_UP, "lo up");
    heard(0, 0, "lo up");
    igmp6("lo up");

    make_pair();
    heard(4, 0, "the pair made");
    link_flags(RTM_NEWLINK, VA, IFF_UP, "va up");
    link_flags(RTM_NEWLINK, VB, IFF_UP, "vb up");
    /* Each end's link-local address, as it has its carrier. */
    heard(2, 1, "the pair up");
    address(VA, "2001:db8::1", "va's address");
    heard(1, 0, "va's address");
    dump(0, 0, "the pair up");
    dump(VA, 0, "of va");
    dump(4242, 0, "of no device");
    dump(0, 64, "of a prefix");
    igmp6("the pair up");

    int a = join(-1, VA, "ff15::1", IPV6_ADD_MEMBERSHIP, "va joins ff15::1");
    int b = join(-1, VA, "ff02::1", IPV6_ADD_MEMBERSHIP, "va joins ff02::1");
    heard(1, 0, "the sockets joined");
    igmp6("the sockets joined");
    join(b, VA, "ff02::1", IPV6_DROP_MEMBERSHIP, "va leaves ff02::1");
    heard(0, 0, "ff02::1 left");

    link_flags(RTM_NEWLINK, VA, 0, "va down");
    heard(2, 0, "va down");
    igmp6("va down");
    /* Down, va has no address, whose subnet-router anycast address a
       device that forwards would join the solicited-node group of. */
    forwarding("1", "va forwards");
    heard(3, 0, "va forwards");
    dump(VA, 0, "va forwards");
    forwarding("0", "va forwards no more");
    heard(3, 0, "va forwards no more");
    link_flags(RTM_NEWLINK, VA, IFF_UP, "va up again");
    heard(1, 0, "va up again");
    igmp6("va up again");
    close(a);
    heard(1, 0, "the socket closed");
    close(b);
    link_flags(RTM_DELLINK, VA, 0, "delete va");
    heard(0, 0, "va deleted");
    igmp6("va deleted");
    return 0;
}
