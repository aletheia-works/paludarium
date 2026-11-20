/* Route lookups for packets coming in on a veth end (RTA_IIF, as
   `ip route get ... iif va` sends them), as ip_route_input_slow takes
   them: the process makes a network namespace with a pair whose two ends
   are both in it, "va" (1000, 10.77.0.1/24) and "vb" (1001, 10.88.0.1/24),
   all up, with IPv4 forwarding and reverse path filtering off first, as
   a host may have changed the first namespace's, which a new one takes.
   Then it looks up local, broadcast, multicast and forwarded
   destinations, martians, sources checked strictly and loosely, and the
   same once va is down. */
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
#define RTM_GETROUTE 26
#define RTA_DST 1
#define RTA_SRC 2
#define RTA_IIF 3
#define RTA_OIF 4
#define RTA_GATEWAY 5
#define RTA_PREFSRC 7
#define RTA_TABLE 15
#define RTM_F_LOOKUP_TABLE 0x1000
#define RTM_F_FIB_MATCH 0x2000

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
/* Waits, up to 5 s, until the member links hears that the device of
   `index` has its carrier. */
static void carrier(int links, int index) {
    static unsigned char buf[65536];
    for (;;) {
        struct pollfd ready = {.fd = links, .events = POLLIN};
        if (poll(&ready, 1, 5000) <= 0) {
            printf("%s: no carrier on %d\n", side, index);
            return;
        }
        long n = recv(links, buf, sizeof buf, MSG_DONTWAIT);
        if (n <= 0) return;
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
                    if ((kind & 0x3fff) == IFLA_CARRIER && alen >= 5 && body[a + 4] == 1) return;
                    a += (alen + 3) & ~3;
                }
            }
            at += (h->len + 3) & ~3u;
        }
    }
}


/* Writes `value` to /proc/sys/net/ipv4/conf/<device>/<name>. */
static void setting(const char *device, const char *name, const char *value) {
    char path[96];
    snprintf(path, sizeof path, "/proc/sys/net/ipv4/conf/%s/%s", device, name);
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        printf("%s: open=%d\n", path, -errno);
        return;
    }
    if (write(fd, value, strlen(value)) < 0) printf("%s: write=%d\n", path, -errno);
    close(fd);
}
static void ip_of(const unsigned char *value, char *out, size_t len) { inet_ntop(AF_INET, value, out, (socklen_t)len); }
/* Looks a route up for a packet in on `iif` from `src` to `dst`, with the
   rtmsg's `flags`, and prints the answer or the error. */
static void get(int fd, int iif, const char *src, const char *dst, unsigned flags, const char *label) {
    unsigned char buf[4096] = {0};
    struct nl_header *h = (void *)buf;
    struct body b = {0};
    unsigned char rtm[12] = {AF_INET, 32, 0, 0};
    memcpy(rtm + 8, &flags, 4);
    raw(&b, rtm, sizeof rtm);
    struct in_addr in;
    inet_pton(AF_INET, dst, &in);
    put(&b, RTA_DST, &in, 4);
    if (src) {
        inet_pton(AF_INET, src, &in);
        put(&b, RTA_SRC, &in, 4);
        b.bytes[1] = 32;
    }
    put32(&b, RTA_IIF, (unsigned)iif);
    h->len = sizeof *h + b.len;
    h->type = RTM_GETROUTE;
    h->flags = NLM_F_REQUEST;
    h->seq = ++seq;
    memcpy(buf + sizeof *h, b.bytes, b.len);
    struct nl_address kernel = {.family = AF_NETLINK};
    if (sendto(fd, buf, h->len, 0, (void *)&kernel, sizeof kernel) < 0) printf("%s: send=%d\n", label, -errno);
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    if (poll(&ready, 1, 2000) <= 0) {
        printf("%s: no answer\n", label);
        return;
    }
    long n = recv(fd, buf, sizeof buf, 0);
    if (n < (long)sizeof *h + 4) {
        printf("%s: short=%ld\n", label, n);
        return;
    }
    if (h->type == 2) {
        int error;
        memcpy(&error, buf + sizeof *h, 4);
        printf("%s: error=%d\n", label, error);
        return;
    }
    const unsigned char *r = buf + sizeof *h;
    unsigned rflags;
    memcpy(&rflags, r + 8, 4);
    printf("%s: type=%u dst_len=%u src_len=%u tos=%u table=%u scope=%u flags=%#x", label, r[7], r[1], r[2],
           r[3], r[4], r[6], rflags);
    long body_len = (long)h->len - (long)sizeof *h;
    for (long a = 12; a + 4 <= body_len;) {
        unsigned short alen, kind;
        memcpy(&alen, r + a, 2);
        memcpy(&kind, r + a + 2, 2);
        if (alen < 4 || a + alen > body_len) break;
        const unsigned char *v = r + a + 4;
        char ip[32];
        unsigned u = 0;
        if (alen >= 8) memcpy(&u, v, 4);
        switch (kind) {
        case RTA_DST: ip_of(v, ip, sizeof ip), printf(" dst=%s", ip); break;
        case RTA_SRC: ip_of(v, ip, sizeof ip), printf(" src=%s", ip); break;
        case RTA_PREFSRC: ip_of(v, ip, sizeof ip), printf(" prefsrc=%s", ip); break;
        case RTA_GATEWAY: ip_of(v, ip, sizeof ip), printf(" gateway=%s", ip); break;
        case RTA_IIF: printf(" iif=%u", u); break;
        case RTA_OIF: printf(" oif=%u", u); break;
        case RTA_TABLE: printf(" rta_table=%u", u); break;
        default: break;
        }
        a += (alen + 3) & ~3;
    }
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-iif")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    side = "iif";
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    /* all's forwarding sets every device's; default's settings are what a
       new device takes. */
    setting("all", "forwarding", "0");
    setting("all", "rp_filter", "0");
    setting("default", "rp_filter", "0");
    setting("lo", "rp_filter", "0");
    int ctl = route_socket(0), links = route_socket(1);
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
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make");
    set_up(ctl, 1, "up lo");
    address(ctl, A_INDEX, "10.77.0.1", "add 10.77.0.1/24");
    address(ctl, B_INDEX, "10.88.0.1", "add 10.88.0.1/24");
    set_up(ctl, A_INDEX, "up va");
    set_up(ctl, B_INDEX, "up vb");
    carrier(links, A_INDEX);
    carrier(links, B_INDEX);

    /* Local, broadcast and multicast destinations. */
    get(ctl, A_INDEX, "10.77.0.2", "10.77.0.1", 0, "va's own");
    get(ctl, A_INDEX, "10.77.0.2", "10.88.0.1", 0, "vb's address");
    get(ctl, B_INDEX, "10.88.0.2", "10.77.0.1", 0, "in on vb");
    get(ctl, A_INDEX, "10.77.0.2", "10.77.0.1", RTM_F_LOOKUP_TABLE, "lookup table");
    get(ctl, A_INDEX, "10.77.0.2", "10.77.0.1", RTM_F_FIB_MATCH, "fib match");
    get(ctl, A_INDEX, "10.77.0.2", "10.77.0.255", 0, "subnet broadcast");
    get(ctl, A_INDEX, "10.77.0.2", "255.255.255.255", 0, "limited broadcast");
    get(ctl, A_INDEX, NULL, "255.255.255.255", 0, "limited broadcast from none");
    get(ctl, A_INDEX, "10.77.0.2", "224.0.0.1", 0, "all hosts");
    get(ctl, A_INDEX, NULL, "224.0.0.1", 0, "all hosts from none");
    get(ctl, A_INDEX, "10.77.0.2", "224.0.0.5", 0, "a group not joined");
    /* Martians. */
    get(ctl, A_INDEX, "10.77.0.1", "10.77.0.1", 0, "from va's own");
    get(ctl, A_INDEX, "10.88.0.1", "10.77.0.1", 0, "from vb's address");
    get(ctl, A_INDEX, "127.0.0.1", "10.77.0.1", 0, "from loopback");
    get(ctl, A_INDEX, "10.77.0.2", "127.0.0.1", 0, "to loopback");
    get(ctl, A_INDEX, NULL, "10.77.0.1", 0, "from none");
    get(ctl, A_INDEX, "224.0.0.9", "10.77.0.1", 0, "from multicast");
    get(ctl, A_INDEX, "10.77.0.2", "0.0.0.0", 0, "to none");
    get(ctl, 1234, "10.77.0.2", "10.77.0.1", 0, "no such device");
    /* To be forwarded, with forwarding off. */
    get(ctl, A_INDEX, "10.77.0.2", "10.88.0.7", 0, "through vb, off");
    get(ctl, A_INDEX, "10.77.0.2", "10.99.0.1", 0, "no route, off");
    get(ctl, A_INDEX, "10.77.0.2", "10.88.0.7", RTM_F_FIB_MATCH, "fib match, off");
    /* va's forwarding on: vb's stays off. */
    setting("va", "forwarding", "1");
    get(ctl, A_INDEX, "10.77.0.2", "10.88.0.7", 0, "through vb");
    get(ctl, A_INDEX, "10.77.0.2", "10.77.0.9", 0, "back out of va");
    get(ctl, A_INDEX, "10.77.0.2", "10.77.0.9", RTM_F_FIB_MATCH | RTM_F_LOOKUP_TABLE, "back out, fib match");
    get(ctl, A_INDEX, "10.88.0.2", "10.77.0.9", 0, "back out, from vb's net");
    get(ctl, A_INDEX, "10.77.0.2", "10.99.0.1", 0, "no route");
    get(ctl, A_INDEX, "10.77.0.2", "10.99.0.1", RTM_F_FIB_MATCH, "no route, fib match");
    get(ctl, B_INDEX, "10.88.0.2", "10.77.0.9", 0, "in on vb, off");
    /* Reverse path filtering on va: strictly, a source routed out through
       vb is dropped, as is one no route takes; loosely, only the latter. */
    get(ctl, A_INDEX, "10.88.0.5", "10.77.0.1", 0, "rp_filter 0, through vb");
    get(ctl, A_INDEX, "10.99.0.5", "10.77.0.1", 0, "rp_filter 0, no route");
    setting("va", "rp_filter", "1");
    get(ctl, A_INDEX, "10.77.0.2", "10.77.0.1", 0, "rp_filter 1, on link");
    get(ctl, A_INDEX, "10.88.0.5", "10.77.0.1", 0, "rp_filter 1, through vb");
    get(ctl, A_INDEX, "10.99.0.5", "10.77.0.1", 0, "rp_filter 1, no route");
    get(ctl, A_INDEX, "10.88.0.5", "10.88.0.7", 0, "rp_filter 1, forwarded");
    get(ctl, A_INDEX, "10.88.0.5", "224.0.0.1", 0, "rp_filter 1, all hosts");
    setting("va", "rp_filter", "2");
    get(ctl, A_INDEX, "10.88.0.5", "10.77.0.1", 0, "rp_filter 2, through vb");
    get(ctl, A_INDEX, "10.99.0.5", "10.77.0.1", 0, "rp_filter 2, no route");
    get(ctl, A_INDEX, "10.77.0.2", "10.77.0.9", 0, "rp_filter 2, back out");
    setting("va", "rp_filter", "0");
    setting("all", "rp_filter", "1");
    get(ctl, A_INDEX, "10.88.0.5", "10.77.0.1", 0, "all's rp_filter 1, through vb");
    setting("all", "rp_filter", "0");
    /* va down: its addresses' routes go, and it leaves 224.0.0.1. */
    {
        struct body b = {0};
        info(&b, A_INDEX, 0, IFF_UP);
        request(ctl, RTM_NEWLINK, 0, &b, "down va");
    }
    get(ctl, A_INDEX, "10.77.0.2", "10.77.0.1", 0, "down, va's own");
    get(ctl, A_INDEX, "10.77.0.2", "10.88.0.1", 0, "down, vb's address");
    get(ctl, A_INDEX, "10.77.0.2", "224.0.0.1", 0, "down, all hosts");
    get(ctl, A_INDEX, "10.77.0.2", "10.88.0.7", 0, "down, through vb");
    return 0;
}
