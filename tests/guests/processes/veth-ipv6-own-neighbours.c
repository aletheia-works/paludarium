/* The neighbours of what IPv6 sends of itself (so as root): its MLD
   reports to ff02::16, duplicate address detection's probes to each
   address's solicited-node group, and the router solicitation to ff02::2,
   each a NUD_NOARP neighbour of the group, made without a word. The process
   makes a network namespace of its own, with lo, and a pair, va (1000,
   02:00:00:00:00:0a) and vb (1001, ...:0b). A socket joining a group on
   lo has lo report it. Each end up with its carrier reports its
   link-local address's group, probes for it and, done, solicits routers;
   va, up again without its carrier, loads its groups again as an address
   comes (ipv6_find_idev's ipv6_mc_up, which /proc/net/igmp6's flags show)
   and reports that address's group, which it probes for once it has its
   carrier; the group is shown once its report's neighbour is there. A report's neighbour deleted comes back with the next report,
   of a group a socket joins. An end going down, or losing its carrier,
   takes its neighbours, each told of; vb, ready still as it has its
   carrier again, reports again, and only that. Linux makes these from its
   work queue a little after what makes them, so the case polls the
   neighbours until those it waits for are there, and prints them, and what
   is told of them, sorted, as Linux dumps them in the order of a randomly
   keyed hash. No time is shown. */
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
#define RTM_NEWADDR 20
#define RTM_NEWNEIGH 28
#define RTM_DELNEIGH 29
#define RTM_GETNEIGH 30
#define IFA_ADDRESS 1
#define IFA_LOCAL 2
#define NDA_DST 1
#define NDA_LLADDR 2
#define NDA_PROBES 4
#define SOL_NETLINK_ 270
#define NETLINK_ADD_MEMBERSHIP_ 1
#define NETLINK_GET_STRICT_CHK_ 12
#define RTNLGRP_NEIGH 3
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
/* Adds an address, checked for duplicates. */
static void address(int index, const char *text, const char *label) {
    struct body b = {0};
    const unsigned char m[8] = {AF_INET6, 64, 0, 0, (unsigned char)index, (unsigned char)(index >> 8), 0, 0};
    unsigned char in[16];
    inet_pton(AF_INET6, text, in);
    raw(&b, m, 8);
    put(&b, IFA_LOCAL, in, 16);
    put(&b, IFA_ADDRESS, in, 16);
    request(RTM_NEWADDR, &b, label);
}
static void forget(int index, const char *key, const char *label) {
    struct body b = {0};
    const unsigned char m[12] = {AF_INET6, 0, 0, 0, (unsigned char)index, (unsigned char)(index >> 8), 0, 0};
    unsigned char in[16];
    inet_pton(AF_INET6, key, in);
    raw(&b, m, 12);
    put(&b, NDA_DST, in, 16);
    request(RTM_DELNEIGH, &b, label);
}

static int ours(int index) { return index == 1 || index == VA || index == VB; }
/* A neighbour's message as a line: its kind, device, key, state, flags,
   type, link-layer address (or -) and probes; 0 for one not ours or not
   IPv6's. */
static int line_of(const unsigned char *m, char *out, size_t size) {
    unsigned short type;
    unsigned len;
    memcpy(&len, m, 4);
    memcpy(&type, m + 4, 2);
    int index;
    memcpy(&index, m + 20, 4);
    if (m[16] != AF_INET6 || !ours(index)) return 0;
    unsigned short state;
    memcpy(&state, m + 24, 2);
    char key[64] = "?", ll[32] = "-";
    unsigned probes = 0;
    for (unsigned at = 28; at + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, m + at, 2);
        memcpy(&kind, m + at + 2, 2);
        if (alen < 4) break;
        const unsigned char *v = m + at + 4;
        if (kind == NDA_DST && alen == 20) inet_ntop(AF_INET6, v, key, sizeof key);
        if (kind == NDA_LLADDR && alen == 10)
            snprintf(ll, sizeof ll, "%02x:%02x:%02x:%02x:%02x:%02x", v[0], v[1], v[2], v[3], v[4], v[5]);
        if (kind == NDA_PROBES && alen == 8) memcpy(&probes, v, 4);
        at += (alen + 3) & ~3u;
    }
    snprintf(out, size, "%s dev=%d %s state=%#x flags=%#x type=%u lladdr=%s probes=%u",
             type == RTM_NEWNEIGH ? "new" : type == RTM_DELNEIGH ? "del" : "?", index, key, state, m[26], m[27], ll,
             probes);
    return 1;
}
static int compare(const void *a, const void *b) { return strcmp((const char *)a, (const char *)b); }

static char lines[64][160];
/* The IPv6 neighbours of the device `index`, sorted, into `lines`: how
   many. */
static int neighbours(int index) {
    unsigned char buf[16384] = {0};
    const unsigned head[4] = {28 + 8, RTM_GETNEIGH | (NLM_F_REQUEST | NLM_F_DUMP) << 16, ++seq, 0};
    memcpy(buf, head, 16);
    buf[16] = AF_INET6;
    const unsigned short attribute[2] = {8, 8 /* NDA_IFINDEX */};
    memcpy(buf + 28, attribute, 4);
    memcpy(buf + 32, &index, 4);
    send(ctl, buf, head[0], 0);
    int count = 0;
    for (;;) {
        struct pollfd ready = {.fd = ctl, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) return -1;
        long n = recv(ctl, buf, sizeof buf, 0);
        for (long at = 0; at + 16 <= n;) {
            unsigned len;
            unsigned short type;
            memcpy(&len, buf + at, 4);
            memcpy(&type, buf + at + 4, 2);
            if (len < 16 || at + len > n) break;
            if (type == NLMSG_DONE || type == NLMSG_ERROR) {
                qsort(lines, (size_t)count, sizeof lines[0], compare);
                return count;
            }
            if (count < 64 && line_of(buf + at, lines[count], sizeof lines[count])) count++;
            at += (len + 3) & ~3u;
        }
    }
}
/* Whether `lines` has a neighbour keyed by `key`. */
static int has(int count, const char *key) {
    char spaced[80];
    snprintf(spaced, sizeof spaced, " %s ", key);
    for (int i = 0; i < count; i++)
        if (strstr(lines[i], spaced)) return 1;
    return 0;
}
static double seconds(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
/* Polls the neighbours of `index` until it has each of the `keys`, for
   10 s at most, then prints them. */
static void await_neighbours(int index, const char *const *keys, int wanted, const char *label) {
    int count = 0, missing = wanted;
    for (double until = seconds() + 10; seconds() < until;) {
        count = neighbours(index);
        missing = 0;
        for (int i = 0; i < wanted; i++) missing += !has(count, keys[i]);
        if (!missing) break;
        struct timespec pause = {0, 20 * 1000 * 1000};
        nanosleep(&pause, NULL);
    }
    printf("-- neighbours of %d: %s\n", index, label);
    if (missing) printf("waited for %d more\n", missing);
    for (int i = 0; i < count; i++) printf("%s\n", lines[i]);
}
/* Reads what the monitor is told: `wait` messages of ours, then those
   there are, sorted. */
static void heard(int wait, const char *label) {
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
    qsort(lines, (size_t)count, sizeof lines[0], compare);
    for (int i = 0; i < count; i++) printf("%s\n", lines[i]);
}
/* The lines of /proc/net/igmp6 of va. */
static void igmp6(const char *label) {
    static char text[16384];
    int fd = open("/proc/net/igmp6", O_RDONLY);
    long n, all = 0;
    while (fd >= 0 && (n = read(fd, text + all, sizeof text - 1 - (size_t)all)) > 0) all += n;
    if (fd >= 0) close(fd);
    text[all] = 0;
    printf("-- igmp6 of va: %s\n", label);
    for (char *line = text, *next; *line; line = next) {
        next = strchr(line, '\n');
        if (!next) break;
        *next++ = 0;
        if (atoi(line) == VA) printf("|%s|\n", line);
    }
}
static int join(int index, const char *group, const char *label) {
    struct ipv6_mreq m = {.ipv6mr_interface = (unsigned)index};
    inet_pton(AF_INET6, group, &m.ipv6mr_multiaddr);
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    printf("%s: %ld\n", label, result(setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &m, sizeof m)));
    return fd;
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-ipv6-own-neighbours")) return 99;
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
    int group = RTNLGRP_NEIGH;
    printf("monitor=%ld\n", result(setsockopt(monitor, SOL_NETLINK_, NETLINK_ADD_MEMBERSHIP_, &group, sizeof group)));

    link_flags(1, IFF_UP, "lo up");
    int lo = join(1, "ff02::1234", "lo joins ff02::1234");
    const char *reports[] = {"ff02::16"};
    await_neighbours(1, reports, 1, "lo reports");

    make_pair();
    link_flags(VA, IFF_UP, "va up");
    printf("va alone: %d\n", neighbours(VA));
    link_flags(VB, IFF_UP, "vb up");
    const char *a_ready[] = {"ff02::16", "ff02::1:ff00:a", "ff02::2"};
    const char *b_ready[] = {"ff02::16", "ff02::1:ff00:b", "ff02::2"};
    await_neighbours(VA, a_ready, 3, "va ready");
    await_neighbours(VB, b_ready, 3, "vb ready");
    heard(0, "the pair ready");

    /* va loses its carrier and keeps its groups; down, it unloads them,
       and up again without its carrier, loads them as an address comes. */
    link_flags(VB, 0, "vb down");
    heard(6, "vb down");
    link_flags(VA, 0, "va down");
    link_flags(VA, IFF_UP, "va up alone");
    igmp6("up alone");
    address(VA, "2001:db8::1", "va's address");
    /* Its group is joined, and reported, by Linux's work. */
    await_neighbours(VA, reports, 1, "va's address");
    igmp6("its address");

    link_flags(VB, IFF_UP, "vb up again");
    const char *a_both[] = {"ff02::16", "ff02::1:ff00:1", "ff02::1:ff00:a", "ff02::2"};
    await_neighbours(VA, a_both, 4, "va ready again");
    await_neighbours(VB, b_ready, 3, "vb ready again");
    heard(0, "the pair ready again");

    forget(VA, "ff02::16", "forget va's ff02::16");
    heard(1, "forgotten");
    int a = join(VA, "ff15::1", "va joins ff15::1");
    await_neighbours(VA, a_both, 4, "va reports ff15::1");

    link_flags(VA, 0, "va down again");
    heard(7, "va down again");
    link_flags(VA, IFF_UP, "va up again");
    const char *a_again[] = {"ff02::16", "ff02::1:ff00:a", "ff02::2"};
    await_neighbours(VA, a_again, 3, "va up again");
    await_neighbours(VB, reports, 1, "vb has its carrier again");
    heard(0, "the pair up again");

    close(a);
    close(lo);
    link_flags(1, 0, "lo down");
    heard(1, "lo down");
    return 0;
}
