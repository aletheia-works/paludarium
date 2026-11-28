/* What a device that forwards learns from a router solicitation (so as
   root): ndisc_recv_rs makes the neighbour of its sender's address, or
   changes it, stale at the link-layer address it carries, and no router
   (NTF_ROUTER goes). The process makes a network namespace of its own and
   two pairs: va (1000, 02:00:00:00:00:e8), which forwards, and vb (1001,
   ...:e9), which solicits routers as the detection of its link-local
   address ends; and vc (1002) and vd (1003), neither forwarding, where vc
   learns nothing of vd's. Before, va has vb's link-local address as a
   router's, stale at the same address. Linux sends these from its work
   queue a little after what makes them, so the case polls the neighbours
   until those it waits for are there, and prints them sorted, as Linux
   dumps them in the order of a randomly keyed hash. */
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
#define VC 1002
#define VD 1003

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
static void link_flags(int index, unsigned flags, const char *label) {
    struct body b = {0};
    const unsigned m[4] = {0, (unsigned)index, flags, IFF_UP};
    raw(&b, m, 16);
    request(RTM_NEWLINK, &b, label);
}
/* A pair, `a` (index `ia`, 02:00:00:00:00:`ia` % 256) and `b`
   (index `ia` + 1, one more). */
static void make_pair(int ia, const char *a, const char *b, const char *label) {
    struct body m = {0};
    const unsigned char mac_a[6] = {2, 0, 0, 0, 0, (unsigned char)ia}, mac_b[6] = {2, 0, 0, 0, 0, (unsigned char)(ia + 1)};
    const unsigned ma[4] = {0, (unsigned)ia, 0, 0}, mb[4] = {0, (unsigned)(ia + 1), 0, 0};
    raw(&m, ma, 16);
    put(&m, 3, a, strlen(a) + 1);
    put(&m, 1, mac_a, 6);
    size_t link = begin(&m, 18);
    put(&m, 1, "veth", 5);
    size_t data = begin(&m, 2), peer = begin(&m, 1);
    raw(&m, mb, 16);
    put(&m, 3, b, strlen(b) + 1);
    put(&m, 1, mac_b, 6);
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(RTM_NEWLINK, &m, label);
}
/* Adds the neighbour `key` of `index` at `lladdr`, stale and a router
   (NTF_ROUTER). */
static void router(int index, const char *key, const unsigned char lladdr[6], const char *label) {
    struct body b = {0};
    const unsigned char m[12] = {AF_INET6, 0, 0, 0, (unsigned char)index, (unsigned char)(index >> 8), 0, 0, 0x04, 0, 0x80, 0};
    unsigned char in[16];
    inet_pton(AF_INET6, key, in);
    raw(&b, m, 12);
    put(&b, NDA_DST, in, 16);
    put(&b, NDA_LLADDR, lladdr, 6);
    request(RTM_NEWNEIGH, &b, label);
}
static int ours(int index) { return index >= VA && index <= VD; }
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
/* Polls the neighbours of `index` until one's line has `text`, for 10 s at
   most, then prints them. */
static void await_line(int index, const char *text, const char *label) {
    int count = 0, found = 0;
    for (double until = seconds() + 10; seconds() < until;) {
        count = neighbours(index);
        for (int i = 0; i < count && !found; i++) found = strstr(lines[i], text) != NULL;
        if (found) break;
        struct timespec pause = {0, 20 * 1000 * 1000};
        nanosleep(&pause, NULL);
    }
    printf("-- neighbours of %d: %s\n", index, label);
    if (!found) printf("waited for %s\n", text);
    for (int i = 0; i < count; i++) printf("%s\n", lines[i]);
}
static void write_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY);
    long n = fd < 0 ? -errno : result(write(fd, text, strlen(text)));
    if (fd >= 0) close(fd);
    printf("%s <- %s: %ld\n", path, text, n);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-ipv6-solicited-routers")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    ctl = socket(AF_NETLINK, SOCK_RAW, 0);
    int one = 1;
    setsockopt(ctl, SOL_NETLINK_, NETLINK_GET_STRICT_CHK_, &one, sizeof one);
    link_flags(1, IFF_UP, "lo up");
    make_pair(VA, "va", "vb", "make va and vb");
    make_pair(VC, "vc", "vd", "make vc and vd");
    write_file("/proc/sys/net/ipv6/conf/va/forwarding", "1");
    const unsigned char mac_b[6] = {2, 0, 0, 0, 0, (unsigned char)VB};
    router(VA, "fe80::ff:fe00:e9", mac_b, "vb's link-local address on va, a router's");
    printf("va: %d\n", neighbours(VA));
    link_flags(VA, IFF_UP, "va up");
    link_flags(VB, IFF_UP, "vb up");
    link_flags(VC, IFF_UP, "vc up");
    link_flags(VD, IFF_UP, "vd up");
    /* vb and vd solicit routers once their detection ends. */
    const char *b_done[] = {"ff02::2"}, *d_done[] = {"ff02::2"};
    await_neighbours(VB, b_done, 1, "vb has solicited routers");
    await_neighbours(VD, d_done, 1, "vd has solicited routers");
    /* Stale still, and no router. */
    await_line(VA, "fe80::ff:fe00:e9 state=0x4 flags=0 ", "va, which forwards");
    int count = neighbours(VC);
    printf("vc learns nothing of vd: %d\n", count >= 0 && !has(count, "fe80::ff:fe00:eb"));
    return 0;
}
