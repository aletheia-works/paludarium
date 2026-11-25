/* Which next hop of an IPv4 multipath route of veth ends a flow takes
   (so as root): a network namespace with "va" (1000, 10.0.0.1/24) and
   "vc" (1002, 10.1.0.1/24), whose peers "vb" and "vd", in another, have
   10.0.0.2 and 10.0.0.3, and 10.1.0.2, with the destinations on its lo.
   The hash of the source and the destination chooses (fib_select_multipath,
   of fib_multipath_hash_policy 0), by a key of its own, so that what is
   shown holds for any: each hop takes some, the one of more weight more,
   and a destination the same one again. Before the hash comes the hop
   whose device's source is the packet's, and a device named chooses
   itself. A socket not bound takes the source of the hop the destination
   hashes to, and a connected one then looks its route up from that
   (ip_route_connect), as where a route has a preferred source, which is
   one hop's. Every packet comes in on the peer of its hop's device, where
   a socket bound to that takes it, and the answer goes back by a route of
   its own, through the device its listener is bound to or whichever hop
   its own hash takes. A dead hop takes none. */
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
#define IFLA_NET_NS_PID 19
#define IFLA_CARRIER 33
#define IFLA_INFO_KIND 1
#define IFLA_INFO_DATA 2
#define VETH_INFO_PEER 1
#define IFA_LOCAL 2
#define IFA_ADDRESS_ 1
#define RTA_DST 1
#define RTA_SRC 2
#define RTA_OIF 4
#define RTA_GATEWAY 5
#define RTA_PREFSRC 7
#define RTA_MULTIPATH 9
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
/* RTNLGRP_LINK of the first namespace, where carriers are waited for. */
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
/* Whether `h` is the RTM_NEWLINK of the device of `index` with its
   carrier `carrier`. */
static int is(const struct nl_header *h, int index, int carrier) {
    const unsigned char *body = (const unsigned char *)(h + 1);
    int len = (int)(h->len - sizeof *h), got;
    if (h->type != RTM_NEWLINK) return 0;
    memcpy(&got, body + 4, 4);
    if (got != index) return 0;
    for (int a = 16; a + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, body + a, 2);
        memcpy(&kind, body + a + 2, 2);
        if (alen < 4 || a + alen > len) break;
        if ((kind & 0x3fff) == IFLA_CARRIER && alen >= 5) return body[a + 4] == carrier;
        a += (alen + 3) & ~3;
    }
    return 0;
}
/* Waits, up to 5 s however much else comes, for the device of `index`
   to have its carrier `carrier`. */
static void wait_carrier(int index, int carrier, const char *label) {
    static unsigned char buf[65536];
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
                if (is(h, index, carrier)) return;
                at += (h->len + 3) & ~3u;
            }
    }
    printf("%s: never came\n", label);
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
/* Makes the pair of `a` and, in this process's namespace, `b`. */
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
    put32(&m, IFLA_NET_NS_PID, (unsigned)getpid());
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make a pair");
}

/* A next hop of an RTA_MULTIPATH request. */
struct hop {
    const char *via;
    int oif;
    int weight;
};
/* Adds a route to `dst`/24 of the two next hops `hops`, of the preferred
   source `prefsrc` (none for NULL). */
static void route4(int fd, const char *dst, const char *prefsrc, const struct hop *hops, const char *label) {
    struct body b = {0};
    const unsigned char rtm[12] = {AF_INET, 24, 0, 0, 254, 3, 0, 1};
    unsigned char in[4];
    inet_pton(AF_INET, dst, in);
    raw(&b, rtm, sizeof rtm);
    put(&b, RTA_DST, in, 4);
    if (prefsrc) {
        inet_pton(AF_INET, prefsrc, in);
        put(&b, RTA_PREFSRC, in, 4);
    }
    size_t mp = begin(&b, RTA_MULTIPATH);
    for (int i = 0; i < 2; i++) {
        size_t at = b.len;
        unsigned char rtnh[8] = {0, 0, 0, (unsigned char)(hops[i].weight - 1)};
        memcpy(rtnh + 4, &hops[i].oif, 4);
        raw(&b, rtnh, sizeof rtnh);
        inet_pton(AF_INET, hops[i].via, in);
        put(&b, RTA_GATEWAY, in, 4);
        unsigned short len = (unsigned short)(b.len - at);
        memcpy(b.bytes + at, &len, 2);
    }
    end(&b, mp);
    request(fd, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &b, label);
}

/* The last byte of 10.x.0.y's x and y, as sockets and lookups name them. */
struct picked {
    int dev;
    unsigned char via, src;
};
/* The address `net`.`host`, of `net` as "10.2.0". */
static unsigned addr(const char *net, int host) {
    char text[32];
    snprintf(text, sizeof text, "%s.%d", net, host);
    return inet_addr(text);
}
/* The lookup of `dst` from `src` (0 for none) through `oif` (0 for any):
   its device, the last byte of its gateway, and the second of its
   source. */
static struct picked lookup(int fd, unsigned dst, unsigned src, int oif) {
    struct picked p = {-1, 0, 0};
    struct body b = {0};
    const unsigned char rtm[12] = {AF_INET, 32, src ? 32 : 0};
    raw(&b, rtm, sizeof rtm);
    put(&b, RTA_DST, &dst, 4);
    if (src) put(&b, RTA_SRC, &src, 4);
    if (oif) put32(&b, RTA_OIF, (unsigned)oif);
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
        return p;
    const unsigned char *body = (const unsigned char *)(h + 1);
    int len = (int)(h->len - sizeof *h);
    for (int a = 12; a + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, body + a, 2);
        memcpy(&kind, body + a + 2, 2);
        if (alen < 4 || a + alen > len) break;
        if (kind == RTA_OIF && alen == 8) memcpy(&p.dev, body + a + 4, 4);
        if (kind == RTA_GATEWAY && alen == 8) p.via = body[a + 7];
        if (kind == RTA_PREFSRC && alen == 8) p.src = body[a + 5];
        a += (alen + 3) & ~3;
    }
    return p;
}
/* How the lookups of the 254 destinations of `net` from `src` through
   `oif` are shared: those through va, vc and 10.0.0.3, whether each again
   is the same, and whether each, from no source, names its device's, or
   `prefsrc`'s (the second byte, none for -1). Shown only as whether all,
   some or none, and whether vc has more, which no key changes but with
   these chances, of 254 hashes as good as independent: of weights 1 and
   3, va none is 0.75^254, under 1e-31, and vc not more is under 1e-15
   (Chernoff: e^(-254 D(1/2||1/4)) = e^-36); of even weights, a hop none
   is 2^-254. */
static const char *share(int count) { return count == 0 ? "none" : count == 254 ? "all" : "some"; }
static void lookups(int fd, const char *net, unsigned src, int oif, int prefsrc, const char *label) {
    int va = 0, vc = 0, third = 0, same = 0, named = 0;
    for (int i = 1; i <= 254; i++) {
        struct picked p = lookup(fd, addr(net, i), src, oif), q = lookup(fd, addr(net, i), src, oif);
        va += p.dev == VA;
        vc += p.dev == VC;
        third += p.dev == VA && p.via == 3;
        same += p.dev == q.dev && p.via == q.via;
        named += p.src == (prefsrc >= 0 ? prefsrc : p.dev == VC);
    }
    printf("%s: va %s, vc %s, 10.0.0.3 %s, vc more %s, again %s, source %s\n", label, share(va), share(vc),
           share(third), vc > va ? "yes" : "no", share(same), src ? "-" : share(named));
}
/* The other namespace's sockets bound to vb and vd: UDP's and TCP's. */
static int udp[2], tcp[2];
static void bound(int i, const char *device) {
    struct sockaddr_in any = {.sin_family = AF_INET};
    udp[i] = socket(AF_INET, SOCK_DGRAM, 0);
    tcp[i] = socket(AF_INET, SOCK_STREAM, 0);
    any.sin_port = htons(7000);
    long device_set = result(setsockopt(udp[i], SOL_SOCKET, SO_BINDTODEVICE, device, 3));
    printf("udp on %s: %ld %ld\n", device, device_set, result(bind(udp[i], (void *)&any, sizeof any)));
    any.sin_port = htons(7001);
    device_set = result(setsockopt(tcp[i], SOL_SOCKET, SO_BINDTODEVICE, device, 3));
    long at = result(bind(tcp[i], (void *)&any, sizeof any));
    printf("tcp on %s: %ld %ld %ld\n", device, device_set, at, result(listen(tcp[i], 64)));
}
/* Which of the sockets `fds` is ready within 2 s: 0 or 1, or -1. */
static int arrived(const int *fds) {
    struct pollfd ready[2] = {{.fd = fds[0], .events = POLLIN}, {.fd = fds[1], .events = POLLIN}};
    if (poll(ready, 2, 2000) <= 0) return -1;
    return ready[0].revents ? 0 : 1;
}
enum { SENDTO, CONNECT, STREAM };
/* A packet to each of the 254 destinations of `net`, as many as lookups()
   counts on, from a socket bound to `src` (0 for none): how many come, by the device of
   the lookup from their source, and, `first`, how many from the source a
   lookup from none gives. */
static void send_all(int fd, int how, const char *net, unsigned src, const char *label) {
    int count = 254;
    int came = 0, vb = 0, vd = 0, right = 0, first = 0;
    for (int i = 1; i <= count; i++) {
        unsigned dst = addr(net, i);
        struct sockaddr_in to = {.sin_family = AF_INET, .sin_addr.s_addr = dst};
        to.sin_port = htons(how == STREAM ? 7001 : 7000);
        int s = socket(AF_INET, how == STREAM ? SOCK_STREAM : SOCK_DGRAM, 0);
        if (src) {
            struct sockaddr_in at = {.sin_family = AF_INET, .sin_addr.s_addr = src};
            bind(s, (void *)&at, sizeof at);
        }
        long r;
        if (how == SENDTO) r = sendto(s, "x", 1, 0, (void *)&to, sizeof to);
        else if ((r = connect(s, (void *)&to, sizeof to)) == 0 && how == CONNECT) r = send(s, "x", 1, 0);
        if (r < 0) {
            printf("%s: %d: %d\n", label, i, -errno);
            close(s);
            continue;
        }
        int at = arrived(how == STREAM ? tcp : udp);
        struct sockaddr_in from = {0};
        socklen_t len = sizeof from;
        if (at >= 0 && how == STREAM) {
            int a = accept(tcp[at], (void *)&from, &len);
            close(a);
        } else if (at >= 0) {
            char byte[4];
            recvfrom(udp[at], byte, sizeof byte, 0, (void *)&from, &len);
        }
        close(s);
        if (at < 0) continue;
        came++;
        vb += at == 0;
        vd += at == 1;
        unsigned source = from.sin_addr.s_addr;
        /* Sent from no source, the lookup is from none too. */
        struct picked p = lookup(fd, dst, how == SENDTO ? src : source, 0), q = lookup(fd, dst, 0, 0);
        right += p.dev == (at == 0 ? VA : VC);
        first += ((const unsigned char *)&source)[1] == q.src;
    }
    printf("%s: came %d of %d, vb %s, vd %s, by the lookup %d, from its source %d\n", label, came, count,
           vb ? vd ? "some" : "all" : "none", vd ? vb ? "some" : "all" : "none", right, src ? -1 : first);
}

/* A connection to each of the 254 destinations of `net` from `src`, by a
   socket bound to no device, at a listener bound to none and at a closed
   port, and a datagram to one: how many answers, which come back through
   whichever hop their own hash takes, come. */
static int anywhere;
static void answers(const char *net, unsigned src) {
    int accepted = 0, refused = 0, unreachable = 0;
    for (int i = 1; i <= 254; i++)
        for (int how = 0; how < 3; how++) {
            struct sockaddr_in to = {.sin_family = AF_INET, .sin_addr.s_addr = addr(net, i)};
            struct sockaddr_in at = {.sin_family = AF_INET, .sin_addr.s_addr = src};
            to.sin_port = htons((unsigned short)(7002 + how));
            int s = socket(AF_INET, how == 2 ? SOCK_DGRAM : SOCK_STREAM, 0);
            bind(s, (void *)&at, sizeof at);
            long r = result(connect(s, (void *)&to, sizeof to));
            if (how == 0 && r == 0) {
                int a = accept(anywhere, NULL, NULL);
                accepted += a >= 0;
                close(a);
            } else if (how == 1) {
                refused += r == -ECONNREFUSED;
            } else if (how == 2 && i == 1) {
                send(s, "x", 1, 0);
                struct pollfd ready = {.fd = s, .events = POLLIN};
                poll(&ready, 1, 2000);
                unreachable = result(send(s, "x", 1, 0)) == -ECONNREFUSED;
            }
            close(s);
        }
    printf("answers: accepted %d of 254, refused %d of 254, unreachable %d\n", accepted, refused, unreachable);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-ipv4-hash")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ctl = route_socket(0);
    events = route_socket(1);
    int ns = open("/proc/self/ns/net", O_RDONLY);
    sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
    sysctl("/proc/sys/net/ipv4/conf/default/rp_filter", "0");
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int far = route_socket(0);
    sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
    sysctl("/proc/sys/net/ipv4/conf/default/rp_filter", "0");
    make_pair(ctl, VA, "va", VB, "vb", 0x0a);
    make_pair(ctl, VC, "vc", VD, "vd", 0x0c);
    set_link(ctl, 1, 1, "up lo");
    set_link(far, 1, 1, "up the other lo");
    set_link(far, VB, 1, "up vb");
    set_link(far, VD, 1, "up vd");
    drain(events);
    set_link(ctl, VA, 1, "up va");
    wait_carrier(VA, 1, "va's carrier");
    drain(events);
    set_link(ctl, VC, 1, "up vc");
    wait_carrier(VC, 1, "vc's carrier");
    address4(ctl, VA, "10.0.0.1", 24, "add va's address");
    address4(ctl, VC, "10.1.0.1", 24, "add vc's address");
    address4(far, VB, "10.0.0.2", 24, "add vb's address");
    address4(far, VB, "10.0.0.3", 24, "add vb's other");
    address4(far, VD, "10.1.0.2", 24, "add vd's address");
    address4(far, 1, "10.2.0.1", 24, "add 10.2.0.1/24");
    address4(far, 1, "10.3.0.1", 24, "add 10.3.0.1/24");
    address4(far, 1, "10.4.0.1", 24, "add 10.4.0.1/24");
    address4(ctl, 1, "10.5.0.1", 32, "add 10.5.0.1/32");
    bound(0, "vb");
    bound(1, "vd");
    struct sockaddr_in any = {.sin_family = AF_INET, .sin_port = htons(7002)};
    anywhere = socket(AF_INET, SOCK_STREAM, 0);
    printf("tcp on any: %ld", result(bind(anywhere, (void *)&any, sizeof any)));
    printf(" %ld\n", result(listen(anywhere, 64)));
    printf("setns=%ld\n", result(setns(ns, CLONE_NEWNET)));

    /* The way back to 10.5.0.1, through either, as the hash has it, and not
       by the way there. */
    const struct hop back[] = {{"10.0.0.1", VB, 1}, {"10.1.0.1", VD, 1}};
    route4(far, "10.5.0.0", NULL, back, "10.5.0.0/24 through vb and vd");
    const struct hop apart[] = {{"10.0.0.2", VA, 1}, {"10.1.0.2", VC, 3}};
    const struct hop together[] = {{"10.0.0.2", VA, 1}, {"10.0.0.3", VA, 1}};
    const struct hop named[] = {{"10.0.0.2", VA, 1}, {"10.1.0.2", VC, 3}};
    route4(ctl, "10.2.0.0", NULL, apart, "10.2.0.0/24 through va and vc");
    route4(ctl, "10.3.0.0", NULL, together, "10.3.0.0/24 through va twice");
    route4(ctl, "10.4.0.0", "10.0.0.1", named, "10.4.0.0/24 from 10.0.0.1");
    unsigned a = inet_addr("10.0.0.1"), c = inet_addr("10.1.0.1");

    lookups(ctl, "10.2.0", 0, 0, -1, "lookups");
    lookups(ctl, "10.2.0", a, 0, -1, "lookups from va's");
    lookups(ctl, "10.2.0", c, 0, -1, "lookups from vc's");
    lookups(ctl, "10.2.0", inet_addr("127.0.0.1"), 0, -1, "lookups from lo's");
    lookups(ctl, "10.2.0", 0, VA, -1, "lookups through va");
    lookups(ctl, "10.2.0", a, VC, -1, "lookups from va's through vc");
    lookups(ctl, "10.3.0", 0, 0, -1, "one device's lookups");
    lookups(ctl, "10.3.0", a, 0, -1, "one device's lookups from its own");
    lookups(ctl, "10.3.0", c, 0, -1, "one device's lookups from another's");
    lookups(ctl, "10.4.0", 0, 0, 0, "preferred source's lookups");
    lookups(ctl, "10.4.0", a, 0, 0, "lookups from the preferred source");

    send_all(ctl, SENDTO, "10.2.0", 0, "sendto");
    send_all(ctl, CONNECT, "10.2.0", 0, "connect");
    send_all(ctl, STREAM, "10.2.0", 0, "stream");
    send_all(ctl, SENDTO, "10.2.0", c, "sendto from vc's");
    send_all(ctl, CONNECT, "10.2.0", a, "connect from va's");
    send_all(ctl, STREAM, "10.2.0", c, "stream from vc's");
    send_all(ctl, SENDTO, "10.3.0", 0, "one device's sendto");
    send_all(ctl, CONNECT, "10.3.0", 0, "one device's connect");
    send_all(ctl, STREAM, "10.3.0", c, "one device's stream from another's");
    send_all(ctl, SENDTO, "10.4.0", 0, "preferred source's sendto");
    send_all(ctl, CONNECT, "10.4.0", 0, "preferred source's connect");
    send_all(ctl, STREAM, "10.4.0", 0, "preferred source's stream");

    answers("10.2.0", inet_addr("10.5.0.1"));

    set_link(ctl, VC, 0, "down vc");
    lookups(ctl, "10.2.0", 0, 0, -1, "lookups with vc down");
    send_all(ctl, CONNECT, "10.2.0", 0, "connect with vc down");
    drain(events);
    set_link(ctl, VC, 1, "up vc");
    wait_carrier(VC, 1, "vc's carrier");
    lookups(ctl, "10.2.0", 0, 0, -1, "lookups with vc up");
    return 0;
}
