/* ARP neighbours of veth ends (so as root): a child, B, makes a network
   namespace of its own and waits; the parent, A, makes another and a pair,
   its end "va" (1000, 10.77.0.1/24, 02:00:00:00:00:0a) in A and "vb"
   (1001, 10.77.0.2/24, 02:00:00:00:00:0b) in B, and brings both ends and
   both loopbacks up. A adds, shows and removes neighbours of va as
   requests ask, of each type an address has there. Then traffic makes
   them: a datagram to B leaves A's a reachable neighbour of B's address
   and B one of A's that is stale, which B's answer makes delay and, 5
   seconds on, a unicast probe makes reachable; one to an address nobody
   has leaves an incomplete one, failed once ARP gives up 3 seconds
   later. A permanent neighbour of B's address with another link-layer
   address takes A's datagrams where B takes none, until it is replaced.
   An end that goes down takes its neighbours with it, and its peer, whose
   carrier goes, all but its permanent ones. Up again, a TCP connection
   makes them as a datagram does; a broadcast or a group makes one that
   needs no ARP, and NTF_USE asks ARP as a packet does. ARP's table has
   each device's parameters. Each change is told of to RTNLGRP_NEIGH, in its order
   with the links' and addresses' as the peer's carrier goes and as the
   pair goes. Only IPv4's are shown, as the
   ends make IPv6's of their own as they come up. The two processes take
   turns through pipes, so their lines come in one order; the peer's
   carrier going, which Linux's link watch may tell of a second later, is
   waited for on RTNLGRP_LINK, and the ARP answer NTF_USE asks for on
   RTNLGRP_NEIGH. */
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
#define RTM_DELLINK 17
#define RTM_DELADDR 21
#define RTM_NEWNEIGH 28
#define RTM_GETNEIGHTBL 66
#define NDTA_PARMS 6
#define NDTPA_IFINDEX 1
#define NDTPA_REFCNT 2
#define NTF_USE 0x01
#define RTM_DELNEIGH 29
#define RTM_GETNEIGH 30
#define NLM_F_DUMP 0x300
#define NLM_F_REPLACE 0x100
#define NDA_DST 1
#define NDA_LLADDR 2
#define NDA_PROBES 4
#define NDA_IFINDEX 8
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
#define IFA_ADDRESS 1
#define IFA_LOCAL 2
#define A_INDEX 1000
#define B_INDEX 1001

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
struct ifaddrmsg_ {
    unsigned char family, prefix, flags, scope;
    int index;
};
struct body {
    unsigned char bytes[1024];
    size_t len;
};

static const char *side = "A";
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
/* Sends a request and prints its acknowledgement's error. */
static void request(int fd, unsigned short type, unsigned short flags, const struct body *b, const char *label) {
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
            return;
        }
        long n = recv(fd, buf, sizeof buf, 0);
        if (n < (long)sizeof *h + 4) return;
        if (h->type == 2) {
            int error;
            memcpy(&error, buf + sizeof *h, 4);
            printf("%s: %s: error=%d\n", side, label, error);
            return;
        }
    }
}
static void set_up(int fd, int index, const char *label) {
    struct body b = {0};
    info(&b, index, IFF_UP, IFF_UP);
    request(fd, RTM_NEWLINK, 0, &b, label);
}
static void address(int fd, int index, const char *ip, const char *label) {
    struct body b = {0};
    struct ifaddrmsg_ a = {.family = AF_INET, .prefix = 24, .index = index};
    struct in_addr in;
    inet_pton(AF_INET, ip, &in);
    raw(&b, &a, sizeof a);
    put(&b, IFA_LOCAL, &in, 4);
    put(&b, IFA_ADDRESS, &in, 4);
    request(fd, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &b, label);
}
/* Waits, up to 5 s however much else comes, until the member links hears
   that the device of `index` has its carrier, or with `gone` has lost it,
   as Linux's link watch may tell of it a second later. */
static void carrier_is(int links, int index, int gone) {
    static unsigned char buf[65536];
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long left = 5000 - ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000);
        if (left <= 0) break;
        struct pollfd ready = {.fd = links, .events = POLLIN};
        if (poll(&ready, 1, (int)left) <= 0) continue;
        long n = recv(links, buf, sizeof buf, MSG_DONTWAIT);
        if (n <= 0) continue;
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            const struct nl_header *h = (const void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            const unsigned char *body = (const unsigned char *)(h + 1);
            int body_len = (int)(h->len - sizeof *h);
            struct ifinfo i;
            if (h->type == RTM_NEWLINK && body_len >= (int)sizeof i) {
                memcpy(&i, body, sizeof i);
                for (int a = 16; i.index == index && a + 4 <= body_len;) {
                    unsigned short alen, kind;
                    memcpy(&alen, body + a, 2);
                    memcpy(&kind, body + a + 2, 2);
                    if (alen < 4 || a + alen > body_len) break;
                    if ((kind & 0x3fff) == IFLA_CARRIER && alen >= 5 && body[a + 4] == !gone) return;
                    a += (alen + 3) & ~3;
                }
            }
            at += (h->len + 3) & ~3u;
        }
    }
    printf("%s: %s %d: never came\n", side, gone ? "carrier gone from" : "carrier on", index);
}

static void carrier(int links, int index) { carrier_is(links, index, 0); }

static struct sockaddr_in at(const char *ip, int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}
static void receive(int fd, const char *label) {
    char buf[64] = {0};
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    if (poll(&ready, 1, 2000) <= 0) {
        printf("%s: %s: nothing\n", side, label);
        return;
    }
    struct sockaddr_in from = {0};
    socklen_t len = sizeof from;
    long n = result(recvfrom(fd, buf, sizeof buf - 1, 0, (void *)&from, &len));
    char ip[32] = "-";
    if (len == sizeof from && from.sin_family == AF_INET) inet_ntop(AF_INET, &from.sin_addr, ip, sizeof ip);
    printf("%s: %s=%ld \"%s\" from %s\n", side, label, n, n > 0 ? buf : "", ip);
}


struct ndmsg_ {
    unsigned char family, pad1;
    unsigned short pad2;
    int index;
    unsigned short state;
    unsigned char flags, type;
};

/* Describes a neighbour message: device, key, state, flags, type,
   link-layer address (or -) and probes. */
static void describe(const unsigned char *body, int len, char *line, size_t size) {
    struct ndmsg_ n;
    memcpy(&n, body, sizeof n);
    char ip[32] = "?", ll[32] = "-";
    unsigned probes = 0;
    for (int a = (int)sizeof n; a + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, body + a, 2);
        memcpy(&kind, body + a + 2, 2);
        if (alen < 4 || a + alen > len) break;
        const unsigned char *v = body + a + 4;
        if (kind == NDA_DST && alen == 8) inet_ntop(AF_INET, v, ip, sizeof ip);
        if (kind == NDA_LLADDR && alen == 10)
            snprintf(ll, sizeof ll, "%02x:%02x:%02x:%02x:%02x:%02x", v[0], v[1], v[2], v[3], v[4], v[5]);
        if (kind == NDA_PROBES && alen == 8) memcpy(&probes, v, 4);
        a += (alen + 3) & ~3;
    }
    snprintf(line, size, "dev=%d %s state=0x%x flags=0x%x type=%u lladdr=%s probes=%u", n.index, ip, n.state, n.flags,
             n.type, ll, probes);
}
static void show_neighbour(const unsigned char *body, int len, const char *label) {
    char line[160];
    describe(body, len, line, sizeof line);
    printf("%s: %s: %s\n", side, label, line);
}
/* Dumps IPv4's neighbours of the device of `index`. */
static void dump(int fd, int index, const char *label) {
    static unsigned char buf[65536];
    struct {
        struct nl_header h;
        struct ndmsg_ n;
        unsigned short alen, kind;
        unsigned value;
    } ask = {{sizeof ask, RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP, ++seq, 0}, {.family = AF_INET}, 8, NDA_IFINDEX,
             (unsigned)index};
    struct nl_address kernel = {.family = AF_NETLINK};
    sendto(fd, &ask, sizeof ask, 0, (void *)&kernel, sizeof kernel);
    /* Linux dumps them in the order of a randomly keyed hash: sorted
       here. */
    static char lines[64][160];
    int count = 0;
    for (;;) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) break;
        long n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0) break;
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            const struct nl_header *h = (const void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            if (h->type == 3) {
                qsort(lines, (size_t)count, sizeof lines[0], (int (*)(const void *, const void *))strcmp);
                for (int i = 0; i < count; i++) printf("%s: %s: %s\n", side, label, lines[i]);
                printf("%s: %s: %d\n", side, label, count);
                return;
            }
            if (h->type == 2) {
                int error;
                memcpy(&error, h + 1, 4);
                printf("%s: %s: error=%d\n", side, label, error);
                return;
            }
            if (h->type == RTM_NEWNEIGH && count < 64)
                describe((const unsigned char *)(h + 1), (int)(h->len - sizeof *h), lines[count++], sizeof lines[0]);
            at += (h->len + 3) & ~3u;
        }
    }
    printf("%s: %s: no end\n", side, label);
}
/* Prints what the member `watch` heard since, in its order: a device's
   neighbours go the newest first, as each was put at the head of its
   list. */
static void heard(int watch, const char *label) {
    static unsigned char buf[65536];
    for (;;) {
        long n = recv(watch, buf, sizeof buf, MSG_DONTWAIT);
        if (n <= 0) return;
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            const struct nl_header *h = (const void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            const unsigned char *body = (const unsigned char *)(h + 1);
            /* IPv6's, which the ends make of their own, are not shown. */
            if ((h->type == RTM_NEWNEIGH || h->type == RTM_DELNEIGH) && body[0] == AF_INET) {
                char line[160];
                describe(body, (int)(h->len - sizeof *h), line, sizeof line);
                printf("%s: %s: %s %s\n", side, label, h->type == RTM_NEWNEIGH ? "new" : "del", line);
            }
            at += (h->len + 3) & ~3u;
        }
    }
}
/* Prints, or with `quiet` only takes, what the member `order` heard of
   links, IPv4's addresses and IPv4's neighbours since, in its order. */
static void sequence(int order, const char *label, int quiet) {
    static unsigned char buf[65536];
    for (;;) {
        long n = recv(order, buf, sizeof buf, MSG_DONTWAIT);
        if (n <= 0) return;
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            const struct nl_header *h = (const void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            const unsigned char *body = (const unsigned char *)(h + 1);
            int index;
            memcpy(&index, body + 4, 4);
            if (quiet) {
            } else if (h->type == RTM_NEWLINK || h->type == RTM_DELLINK) {
                printf("%s: %s: %s %d\n", side, label, h->type == RTM_NEWLINK ? "link" : "link gone", index);
            } else if ((h->type == RTM_NEWADDR || h->type == RTM_DELADDR) && body[0] == AF_INET) {
                printf("%s: %s: %s %d\n", side, label, h->type == RTM_NEWADDR ? "address" : "address gone", index);
            } else if ((h->type == RTM_NEWNEIGH || h->type == RTM_DELNEIGH) && body[0] == AF_INET) {
                char line[160];
                describe(body, (int)(h->len - sizeof *h), line, sizeof line);
                printf("%s: %s: %s %s\n", side, label, h->type == RTM_NEWNEIGH ? "neighbour" : "neighbour gone", line);
            }
            at += (h->len + 3) & ~3u;
        }
    }
}
/* Asks for the neighbour `ip` of the device of `index`. */
static void get(int fd, int index, const char *ip, const char *label) {
    unsigned char buf[4096] = {0};
    struct nl_header *h = (void *)buf;
    struct body b = {0};
    struct ndmsg_ n = {.family = AF_INET, .index = index};
    struct in_addr in;
    inet_pton(AF_INET, ip, &in);
    raw(&b, &n, sizeof n);
    put(&b, NDA_DST, &in, 4);
    h->len = sizeof *h + b.len;
    h->type = RTM_GETNEIGH;
    h->flags = NLM_F_REQUEST;
    h->seq = ++seq;
    memcpy(buf + sizeof *h, b.bytes, b.len);
    struct nl_address kernel = {.family = AF_NETLINK};
    sendto(fd, buf, h->len, 0, (void *)&kernel, sizeof kernel);
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    if (poll(&ready, 1, 2000) <= 0) {
        printf("%s: %s: no answer\n", side, label);
        return;
    }
    long got = recv(fd, buf, sizeof buf, 0);
    if (got < (long)sizeof *h + 4) return;
    if (h->type == 2) {
        int error;
        memcpy(&error, buf + sizeof *h, 4);
        printf("%s: %s: error=%d\n", side, label, error);
    } else {
        show_neighbour(buf + sizeof *h, (int)(h->len - sizeof *h), label);
    }
}
/* Adds (or replaces) or removes the neighbour `ip` of the device of
   `index`, with `state` and the link-layer address 02:00:00:00:00:`last`
   (none for 0). */
static void neighbour(int fd, unsigned short type, unsigned short flags, int index, const char *ip, unsigned short state,
                      int last, const char *label) {
    struct body b = {0};
    struct ndmsg_ n = {.family = AF_INET, .index = index, .state = state};
    struct in_addr in;
    inet_pton(AF_INET, ip, &in);
    raw(&b, &n, sizeof n);
    put(&b, NDA_DST, &in, 4);
    if (last) {
        const unsigned char ll[6] = {2, 0, 0, 0, 0, (unsigned char)last};
        put(&b, NDA_LLADDR, ll, 6);
    }
    request(fd, type, flags, &b, label);
}
/* Asks ARP for the neighbour `ip` of the device of `index` with NTF_USE. */
static void use(int fd, int index, const char *ip, const char *label) {
    struct body b = {0};
    struct ndmsg_ n = {.family = AF_INET, .index = index, .flags = NTF_USE};
    struct in_addr in;
    inet_pton(AF_INET, ip, &in);
    raw(&b, &n, sizeof n);
    put(&b, NDA_DST, &in, 4);
    request(fd, RTM_NEWNEIGH, NLM_F_CREATE, &b, label);
}
/* Dumps ARP's table: each set of parameters, of a device or the table's,
   with its references. */
static void tables(int fd, const char *label) {
    static unsigned char buf[65536];
    struct {
        struct nl_header h;
        unsigned char family, pad[3];
    } ask = {{sizeof ask, RTM_GETNEIGHTBL, NLM_F_REQUEST | NLM_F_DUMP, ++seq, 0}, AF_INET, {0}};
    struct nl_address kernel = {.family = AF_NETLINK};
    sendto(fd, &ask, sizeof ask, 0, (void *)&kernel, sizeof kernel);
    for (;;) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) break;
        long n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0) break;
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            const struct nl_header *h = (const void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            if (h->type == 3 || h->type == 2) return;
            const unsigned char *body = (const unsigned char *)(h + 1);
            int len = (int)(h->len - sizeof *h);
            for (int a = 4; a + 4 <= len;) {
                unsigned short alen, kind;
                memcpy(&alen, body + a, 2);
                memcpy(&kind, body + a + 2, 2);
                if (alen < 4 || a + alen > len) break;
                if ((kind & 0x3fff) == NDTA_PARMS) {
                    int index = 0;
                    unsigned refs = 0;
                    for (int p = a + 4; p + 4 <= a + alen;) {
                        unsigned short plen, pkind;
                        memcpy(&plen, body + p, 2);
                        memcpy(&pkind, body + p + 2, 2);
                        if (plen < 4 || p + plen > a + alen) break;
                        if (pkind == NDTPA_IFINDEX) memcpy(&index, body + p + 4, 4);
                        if (pkind == NDTPA_REFCNT) memcpy(&refs, body + p + 4, 4);
                        p += (plen + 3) & ~3;
                    }
                    printf("%s: %s: dev=%d refs=%u\n", side, label, index, refs);
                }
                a += (alen + 3) & ~3;
            }
            at += (h->len + 3) & ~3u;
        }
    }
    printf("%s: %s: no end\n", side, label);
}
#define NUD_INCOMPLETE 0x01
#define NUD_REACHABLE 0x02
#define NUD_STALE 0x04
#define NUD_NOARP 0x40
#define NUD_PERMANENT 0x80

/* Waits, up to 5 s however much else comes, on `resolved` (a member of
   RTNLGRP_NEIGH) for the neighbour `ip` of the device of `index` to be
   reachable: Linux's ARP answer comes back through the peer's namespace
   in its own time. */
static void reachable(int resolved, int index, const char *ip) {
    static unsigned char buf[65536];
    unsigned char wanted[4];
    inet_pton(AF_INET, ip, wanted);
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long left = 5000 - ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000);
        if (left <= 0) break;
        struct pollfd ready = {.fd = resolved, .events = POLLIN};
        if (poll(&ready, 1, (int)left) <= 0) continue;
        long n = recv(resolved, buf, sizeof buf, MSG_DONTWAIT);
        if (n <= 0) continue;
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            const struct nl_header *h = (const void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            const unsigned char *body = (const unsigned char *)(h + 1);
            int body_len = (int)(h->len - sizeof *h);
            struct ndmsg_ m;
            if (h->type == RTM_NEWNEIGH && body_len >= (int)sizeof m) {
                memcpy(&m, body, sizeof m);
                for (int a = (int)sizeof m; m.family == AF_INET && m.index == index && m.state == NUD_REACHABLE &&
                                            a + 4 <= body_len;) {
                    unsigned short alen, kind;
                    memcpy(&alen, body + a, 2);
                    memcpy(&kind, body + a + 2, 2);
                    if (alen < 4 || a + alen > body_len) break;
                    if (kind == NDA_DST && alen == 8 && !memcmp(body + a + 4, wanted, 4)) return;
                    a += (alen + 3) & ~3;
                }
            }
            at += (h->len + 3) & ~3u;
        }
    }
    printf("%s: %s reachable: never came\n", side, ip);
}

/* B: makes its namespace, then does what A writes to `in`, one letter at
   a time, writing back to `out` when done. */
static void child(int in, int out) {
    side = "B";
    if (unshare(CLONE_NEWNET) < 0) printf("B: unshare=%d\n", -errno);
    int ctl = route_socket(0), links = route_socket(1), watch = route_socket(4), order = route_socket(1 | 4 | 0x10);
    int udp = -1, listener = -1;
    fflush(stdout);
    if (write(out, "r", 1) != 1) _exit(2);
    for (char command; read(in, &command, 1) == 1;) {
        if (command == 'u') {
            set_up(ctl, 1, "up lo");
            address(ctl, B_INDEX, "10.77.0.2", "add 10.77.0.2/24");
            set_up(ctl, B_INDEX, "up vb");
            carrier(links, B_INDEX);
            udp = socket(AF_INET, SOCK_DGRAM, 0);
            struct sockaddr_in any = at("0.0.0.0", 6000);
            printf("B: bind udp=%ld\n", result(bind(udp, (void *)&any, sizeof any)));
        } else if (command == 's') {
            dump(ctl, B_INDEX, "vb's");
            heard(watch, "heard");
        } else if (command == 'z') {
            sequence(order, "order", 1);
        } else if (command == 'q') {
            sequence(order, "order", 0);
        } else if (command == 'c') {
            carrier(links, B_INDEX);
        } else if (command == 'k') {
            /* vb has lost its carrier, and so its neighbours. */
            carrier_is(links, B_INDEX, 1);
        } else if (command == 'l') {
            listener = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in any = at("0.0.0.0", 5000);
            printf("B: bind=%ld\n", result(bind(listener, (void *)&any, sizeof any)));
            printf("B: listen=%ld\n", result(listen(listener, 4)));
        } else if (command == 'a') {
            int conn = (int)result(accept(listener, NULL, NULL));
            printf("B: accept=%d\n", conn >= 0 ? 0 : conn);
            char buf[16] = {0};
            printf("B: read=%ld \"%s\"\n", result(read(conn, buf, sizeof buf - 1)), buf);
            printf("B: write=%ld\n", result(write(conn, "pong", 4)));
            close(conn);
        } else if (command == 'd') {
            receive(udp, "udp recvfrom");
        } else if (command == 'b') {
            struct sockaddr_in back = at("10.77.0.1", 6100);
            printf("B: udp reply=%ld\n", result(sendto(udp, "back", 4, 0, (void *)&back, sizeof back)));
        } else if (command == 'w') {
            sleep(6);
            printf("B: waited 6 s\n");
        } else if (command == 'n') {
            int none = (int)result(recv(udp, (char[8]){0}, 8, MSG_DONTWAIT));
            printf("B: udp nothing more=%d\n", none);
        } else if (command == 'p') {
            neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL, B_INDEX, "10.77.0.70", NUD_PERMANENT, 0x70,
                      "add permanent 10.77.0.70");
            neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL, B_INDEX, "10.77.0.71", NUD_STALE, 0x71,
                      "add stale 10.77.0.71");
        } else if (command == 'o') {
            carrier_is(links, B_INDEX, 1);
            dump(ctl, B_INDEX, "vb's, va down");
            heard(watch, "heard");
        }
        fflush(stdout);
        if (write(out, "d", 1) != 1) _exit(2);
    }
    _exit(0);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-neigh")) return 99;
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
    int ctl = route_socket(0), links = route_socket(1), watch = route_socket(4), order = route_socket(1 | 4 | 0x10);
    int resolved = route_socket(4);
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
    put32(&m, IFLA_NET_NS_PID, (unsigned)b);
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make");

    /* Requests, while va is down and has no address, then up with one. */
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL, A_INDEX, "10.77.0.50", NUD_PERMANENT, 0x50,
              "add while down");
    dump(ctl, A_INDEX, "va's, down first");
    set_up(ctl, 1, "up lo");
    address(ctl, A_INDEX, "10.77.0.1", "add 10.77.0.1/24");
    set_up(ctl, A_INDEX, "up va");
    B_DOES("u");
    carrier(links, A_INDEX);
    dump(ctl, A_INDEX, "va's, up");
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL, A_INDEX, "10.77.0.50", NUD_PERMANENT, 0x50,
              "add permanent 10.77.0.50");
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL, A_INDEX, "10.77.0.50", NUD_PERMANENT, 0x50,
              "add it again");
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL, A_INDEX, "10.77.0.51", NUD_STALE, 0x51,
              "add stale 10.77.0.51");
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL, A_INDEX, "10.77.0.52", NUD_REACHABLE, 0,
              "add reachable without lladdr");
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL, A_INDEX, "10.77.0.53", NUD_NOARP, 0,
              "add noarp without lladdr");
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL, A_INDEX, "10.77.0.255", NUD_PERMANENT, 0x55,
              "add broadcast");
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL, A_INDEX, "224.1.2.3", NUD_PERMANENT, 0x56,
              "add multicast");
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL, A_INDEX, "10.77.0.1", NUD_PERMANENT, 0x57,
              "add va's own");
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL, A_INDEX, "127.0.0.9", NUD_PERMANENT, 0x58,
              "add loopback");
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL, B_INDEX, "10.77.0.59", NUD_PERMANENT, 0x59,
              "add on vb's index");
    dump(ctl, A_INDEX, "va's");
    dump(ctl, 1, "lo's");
    get(ctl, A_INDEX, "10.77.0.50", "get 10.77.0.50");
    get(ctl, A_INDEX, "10.77.0.60", "get one va has not");
    get(ctl, 1, "10.77.0.50", "get it on lo");
    get(ctl, B_INDEX, "10.77.0.50", "get it on vb's index");
    neighbour(ctl, RTM_DELNEIGH, 0, A_INDEX, "10.77.0.51", 0, 0, "delete 10.77.0.51");
    neighbour(ctl, RTM_DELNEIGH, 0, A_INDEX, "10.77.0.51", 0, 0, "delete it again");
    neighbour(ctl, RTM_DELNEIGH, 0, 1, "10.77.0.50", 0, 0, "delete 10.77.0.50 on lo");
    for (const char **ip = (const char *[]){"10.77.0.53", "10.77.0.255", "224.1.2.3", "10.77.0.1", NULL}; *ip; ip++)
        neighbour(ctl, RTM_DELNEIGH, 0, A_INDEX, *ip, 0, 0, "delete");
    dump(ctl, A_INDEX, "va's, after");
    heard(watch, "heard");
    tables(ctl, "arp table");

    /* Traffic: A to B and back. */
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in mine = at("0.0.0.0", 6100);
    printf("A: bind udp=%ld\n", result(bind(u, (void *)&mine, sizeof mine)));
    struct sockaddr_in to = at("10.77.0.2", 6000);
    printf("A: udp sendto=%ld\n", result(sendto(u, "hello", 5, 0, (void *)&to, sizeof to)));
    B_DOES("d");
    dump(ctl, A_INDEX, "va's, sent");
    B_DOES("s");
    B_DOES("b");
    receive(u, "udp recvfrom");
    B_DOES("s");
    B_DOES("w");
    B_DOES("s");
    dump(ctl, A_INDEX, "va's, later");
    heard(watch, "heard");

    /* To an address nobody has. */
    to = at("10.77.0.9", 6000);
    printf("A: udp sendto nobody=%ld\n", result(sendto(u, "who", 3, 0, (void *)&to, sizeof to)));
    get(ctl, A_INDEX, "10.77.0.9", "resolving");
    sleep(4);
    get(ctl, A_INDEX, "10.77.0.9", "4 s on");
    heard(watch, "heard");
    printf("A: udp sendto nobody again=%ld\n", result(sendto(u, "who", 3, 0, (void *)&to, sizeof to)));
    get(ctl, A_INDEX, "10.77.0.9", "again");
    heard(watch, "heard");

    /* A permanent neighbour of B's address with another link-layer one. */
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_REPLACE, A_INDEX, "10.77.0.2", NUD_PERMANENT, 0x99,
              "replace B's with another");
    to = at("10.77.0.2", 6000);
    printf("A: udp sendto B=%ld\n", result(sendto(u, "lost", 4, 0, (void *)&to, sizeof to)));
    B_DOES("n");
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_REPLACE, A_INDEX, "10.77.0.2", NUD_PERMANENT, 0x0b,
              "replace B's with vb's");
    printf("A: udp sendto B=%ld\n", result(sendto(u, "found", 5, 0, (void *)&to, sizeof to)));
    B_DOES("d");
    get(ctl, A_INDEX, "10.77.0.2", "B's");
    heard(watch, "heard");

    /* Down: va's go, and vb's but its permanent ones. */
    B_DOES("p");
    B_DOES("s");
    B_DOES("z");
    sequence(order, "order", 1);
    struct body d = {0};
    info(&d, A_INDEX, 0, IFF_UP);
    request(ctl, RTM_NEWLINK, 0, &d, "down va");
    dump(ctl, A_INDEX, "va's, down");
    heard(watch, "heard");
    sequence(order, "order", 0);
    B_DOES("o");
    B_DOES("q");

    /* Up again: a TCP connection, then broadcasts and a group. */
    set_up(ctl, A_INDEX, "up va");
    carrier(links, A_INDEX);
    B_DOES("c");
    dump(ctl, A_INDEX, "va's, up again");
    heard(watch, "heard");
    B_DOES("s");
    /* NTF_USE asks ARP, as a packet does; B's answer is waited for. */
    static char unread[65536];
    while (recv(resolved, unread, sizeof unread, MSG_DONTWAIT) > 0) {
    }
    use(ctl, A_INDEX, "10.77.0.2", "use B's");
    reachable(resolved, A_INDEX, "10.77.0.2");
    use(ctl, A_INDEX, "10.77.0.8", "use nobody's");
    get(ctl, A_INDEX, "10.77.0.2", "used B's");
    get(ctl, A_INDEX, "10.77.0.8", "used nobody's");
    heard(watch, "heard");
    B_DOES("s");
    B_DOES("l");
    int c = socket(AF_INET, SOCK_STREAM, 0);
    to = at("10.77.0.2", 5000);
    printf("A: connect=%ld\n", result(connect(c, (void *)&to, sizeof to)));
    printf("A: write=%ld\n", result(write(c, "ping", 4)));
    B_DOES("a");
    char got[8] = {0};
    printf("A: read=%ld \"%s\"\n", result(read(c, got, sizeof got - 1)), got);
    close(c);
    dump(ctl, A_INDEX, "va's, connected");
    heard(watch, "heard");
    B_DOES("s");
    B_DOES("w");
    B_DOES("s");
    get(ctl, A_INDEX, "10.77.0.8", "used nobody's later");
    dump(ctl, A_INDEX, "va's, connected later");
    heard(watch, "heard");
    int on = 1;
    setsockopt(u, SOL_SOCKET, SO_BROADCAST, &on, sizeof on);
    to = at("10.77.0.255", 6002);
    printf("A: udp sendto broadcast=%ld\n", result(sendto(u, "all", 3, 0, (void *)&to, sizeof to)));
    to = at("255.255.255.255", 6002);
    int bound = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in va = at("10.77.0.1", 6101);
    printf("A: bind udp to va's=%ld\n", result(bind(bound, (void *)&va, sizeof va)));
    setsockopt(bound, SOL_SOCKET, SO_BROADCAST, &on, sizeof on);
    printf("A: udp sendto limited broadcast=%ld\n", result(sendto(bound, "all", 3, 0, (void *)&to, sizeof to)));
    to = at("224.1.2.3", 6002);
    printf("A: udp sendto a group=%ld\n", result(sendto(bound, "some", 4, 0, (void *)&to, sizeof to)));
    close(bound);
    dump(ctl, A_INDEX, "va's, broadcast");
    heard(watch, "heard");
    B_DOES("s");
    close(u);

    /* The pair goes: va, down with a neighbour added since, takes its
       addresses first; vb, up, is closed and takes its neighbours first. */
    struct body down = {0};
    info(&down, A_INDEX, 0, IFF_UP);
    request(ctl, RTM_NEWLINK, 0, &down, "down va again");
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL, A_INDEX, "10.77.0.50", NUD_PERMANENT, 0x50,
              "add while down again");
    B_DOES("k");
    B_DOES("z");
    sequence(order, "order", 1);
    struct body gone = {0};
    info(&gone, A_INDEX, 0, 0);
    request(ctl, RTM_DELLINK, 0, &gone, "delete va");
    sequence(order, "order", 0);
    B_DOES("q");

    fflush(stdout);
    close(to_b[1]);
    int status = 0;
    waitpid(b, &status, 0);
    printf("A: B exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}
