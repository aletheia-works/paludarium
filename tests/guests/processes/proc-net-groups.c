/* /proc/net/igmp, mcfilter and mcfilter6: the multicast groups each device of
   a network namespace has joined, and the sources their memberships name (so
   as root). The process makes a network namespace of its own and prints the
   files as lo comes up, as a pair, va (1000) and vb (1001), is made and comes
   up, and as sockets join groups on lo and va, with and without sources, of
   both families, and leave them: by closing, as lo goes down (its sockets'
   groups stay), and as va is deleted. mcfilter begins at the first device
   whose newest group names a source, so lo's sources do not show while its
   newest group names none. Devices a kernel has of its own (tunnels) are
   down and have joined nothing; of IPv6 only lo's sources are joined, as a
   veth end's newest group may be one it joins as its address comes. */
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
#define NLM_F_CREATE 0x400
#define RTM_NEWLINK 16
#define RTM_DELLINK 17
#define VA 1000
#define VB 1001

struct body {
    unsigned char bytes[512];
    size_t len;
};
static int ctl = -1;
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
    const unsigned a[4] = {0, VA, 0, 0}, b[4] = {0, VB, 0, 0};
    raw(&m, a, 16);
    put(&m, 3, "va", 3);
    size_t link = begin(&m, 18);
    put(&m, 1, "veth", 5);
    size_t data = begin(&m, 2), peer = begin(&m, 1);
    raw(&m, b, 16);
    put(&m, 3, "vb", 3);
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(RTM_NEWLINK, &m, "make a pair");
}

static char text[16384];
/* Prints `path`, each line between bars, of the devices lo, va and vb alone
   (a device's line of igmp, and those under it, name it once). */
static void show(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("%s: open=%d\n", path, -errno);
        return;
    }
    long n, all = 0;
    while ((n = read(fd, text + all, sizeof text - 1 - (size_t)all)) > 0) all += n;
    close(fd);
    text[all < 0 ? 0 : all] = 0;
    printf("%s:\n", path);
    int ours = 1;
    for (char *line = text, *next; *line; line = next) {
        next = strchr(line, '\n');
        if (!next) break;
        *next++ = 0;
        if (line != text) {
            char name[32] = {0};
            if (line[0] != '\t') {
                /* "index\tname" in igmp, "index name" in the others. */
                sscanf(line, "%*d %31s", name);
                char *colon = strchr(name, ':');
                if (colon) *colon = 0;
                ours = !strcmp(name, "lo") || !strcmp(name, "va") || !strcmp(name, "vb");
            }
        }
        if (ours) printf("|%s|\n", line);
    }
}
static void all(const char *label) {
    printf("-- %s\n", label);
    show("/proc/net/igmp");
    show("/proc/net/mcfilter");
    show("/proc/net/mcfilter6");
}

static void group4(struct sockaddr_storage *s, const char *text) {
    struct sockaddr_in *in = (struct sockaddr_in *)s;
    memset(s, 0, sizeof *s);
    in->sin_family = AF_INET;
    inet_pton(AF_INET, text, &in->sin_addr);
}
static void group6(struct sockaddr_storage *s, const char *text) {
    struct sockaddr_in6 *in = (struct sockaddr_in6 *)s;
    memset(s, 0, sizeof *s);
    in->sin6_family = AF_INET6;
    inet_pton(AF_INET6, text, &in->sin6_addr);
}
/* A socket of `family` joins `group` on the device `index`: with no source, or
   of `source` alone (MCAST_JOIN_SOURCE_GROUP). */
static int join(int family, int fd, int index, const char *group, const char *source, const char *label) {
    int level = family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
    void (*address)(struct sockaddr_storage *, const char *) = family == AF_INET ? group4 : group6;
    long r;
    if (fd < 0) fd = socket(family, SOCK_DGRAM, 0);
    if (source) {
        struct group_source_req req = {.gsr_interface = (unsigned)index};
        address(&req.gsr_group, group);
        address(&req.gsr_source, source);
        r = result(setsockopt(fd, level, MCAST_JOIN_SOURCE_GROUP, &req, sizeof req));
    } else {
        struct group_req req = {.gr_interface = (unsigned)index};
        address(&req.gr_group, group);
        r = result(setsockopt(fd, level, MCAST_JOIN_GROUP, &req, sizeof req));
    }
    printf("%s: %ld\n", label, r);
    return fd;
}
/* The membership of `fd` in `group` on `index` keeps out `source`
   (MCAST_BLOCK_SOURCE). */
static void block(int family, int fd, int index, const char *group, const char *source, const char *label) {
    void (*address)(struct sockaddr_storage *, const char *) = family == AF_INET ? group4 : group6;
    struct group_source_req req = {.gsr_interface = (unsigned)index};
    address(&req.gsr_group, group);
    address(&req.gsr_source, source);
    int level = family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
    printf("%s: %ld\n", label, result(setsockopt(fd, level, MCAST_BLOCK_SOURCE, &req, sizeof req)));
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "proc-net-groups")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    ctl = socket(AF_NETLINK, SOCK_RAW, 0);
    all("lo down");
    link_flags(RTM_NEWLINK, 1, IFF_UP, "lo up");
    all("lo up");
    make_pair();
    link_flags(RTM_NEWLINK, VA, IFF_UP, "va up");
    link_flags(RTM_NEWLINK, VB, IFF_UP, "vb up");
    all("the pair up");

    /* lo: a group of a source first, then two sockets in one of none. */
    int lo_source = join(AF_INET, -1, 1, "239.3.3.3", "10.0.0.9", "lo joins 239.3.3.3 of 10.0.0.9");
    all("lo's newest group names a source");
    int lo_a = join(AF_INET, -1, 1, "239.1.1.1", NULL, "lo joins 239.1.1.1");
    int lo_b = join(AF_INET, -1, 1, "239.1.1.1", NULL, "lo joins 239.1.1.1 again");
    all("lo's newest group names none");
    /* va: one that excludes two sources, one of which another includes. */
    int va_a = join(AF_INET, -1, VA, "239.2.2.2", NULL, "va joins 239.2.2.2");
    block(AF_INET, va_a, VA, "239.2.2.2", "10.0.0.1", "va's keeps out 10.0.0.1");
    block(AF_INET, va_a, VA, "239.2.2.2", "10.0.0.2", "va's keeps out 10.0.0.2");
    int va_b = join(AF_INET, -1, VA, "239.2.2.2", "10.0.0.2", "va joins 239.2.2.2 of 10.0.0.2");
    all("va's groups name sources");

    /* IPv6, on lo. */
    int six_a = join(AF_INET6, -1, 1, "ff15::1", NULL, "lo joins ff15::1");
    block(AF_INET6, six_a, 1, "ff15::1", "2001:db8::1", "lo's keeps out 2001:db8::1");
    int six_b = join(AF_INET6, -1, 1, "ff15::2", "2001:db8::2", "lo joins ff15::2 of 2001:db8::2");
    join(AF_INET6, six_b, 1, "ff15::2", "2001:db8::3", "and of 2001:db8::3");
    all("lo's IPv6 groups name sources");

    close(va_b);
    close(lo_b);
    close(six_b);
    all("a socket of each closed");
    link_flags(RTM_NEWLINK, 1, 0, "lo down");
    all("lo down again");
    close(lo_a);
    close(lo_source);
    close(six_a);
    all("lo's sockets closed");
    link_flags(RTM_DELLINK, VA, 0, "delete va");
    all("va deleted");
    close(va_a);
    all("va's socket closed");
    return 0;
}
