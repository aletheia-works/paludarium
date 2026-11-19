/* veth pairs between two network namespaces (so as root): a child, B,
   makes a network namespace of its own and waits; the parent, A, makes
   another and asks for a pair (RTM_NEWLINK of kind "veth"), its end "va"
   in A and the peer "vb" in B, by B's process ID. Each side shows what a
   member of RTNLGRP_LINK hears (A's also RTNLGRP_NSID, as B's ID goes
   before B's end), its link dump and the interface ioctls, as the pair
   is made, brought up, deleted, made again and taken away with B's
   namespace, and what RTNLGRP_IPV4_NETCONF and RTNLGRP_IPV6_NETCONF hear
   of each end's settings as it comes and goes, and as A writes
   forwarding and rp_filter in /proc/sys/net. Names, indices and addresses are given, as Linux
   picks a random address and the next free index otherwise; some kernels
   put fallback tunnels in every namespace, which take the low indices, so
   the pairs' are 1000 to 1003, and only lo and those are shown. The two
   processes take turns through pipes, so their lines come in one order. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define NETLINK_ROUTE_ 0
#define RTM_NEWLINK 16
#define RTM_DELLINK 17
#define RTM_GETLINK 18
#define RTM_NEWNSID 88
#define RTM_DELNSID 89
#define SOL_NETLINK_ 270
#define NETLINK_ADD_MEMBERSHIP_ 1
#define RTNLGRP_NSID_ 28
#define RTNLGRP_IPV4_NETCONF_ 24
#define RTNLGRP_IPV6_NETCONF_ 25
#define RTM_NEWNETCONF 80
#define RTM_DELNETCONF 81
#define NLM_F_REQUEST 1
#define NLM_F_ACK 4
#define NLM_F_DUMP 0x300
#define NLM_F_EXCL 0x200
#define NLM_F_CREATE 0x400
#define IFLA_ADDRESS 1
#define IFLA_IFNAME 3
#define IFLA_MTU 4
#define IFLA_LINKINFO 18
#define IFLA_NET_NS_PID 19
#define IFLA_INFO_KIND 1
#define IFLA_INFO_DATA 2
#define VETH_INFO_PEER 1
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
/* A request's payload, its attributes nested by begin and end. */
struct body {
    unsigned char bytes[1024];
    size_t len;
};

static const char *side = "A";
static unsigned seq;

static long result(long r) { return r < 0 ? -errno : r; }

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
    memcpy(b->bytes + b->len, &i, sizeof i);
    b->len += sizeof i;
}

/* Has mon join the netconf groups, saying how it went. */
static void join_netconf(int mon) {
    int groups[2] = {RTNLGRP_IPV4_NETCONF_, RTNLGRP_IPV6_NETCONF_};
    for (int i = 0; i < 2; i++)
        printf("%s: join netconf %d=%ld\n", side, groups[i],
               result(setsockopt(mon, SOL_NETLINK_, NETLINK_ADD_MEMBERSHIP_, &groups[i], sizeof groups[i])));
}
/* Writes value to /proc/sys/net/<path>, saying whether it was taken (a
   count, which Linux 7.0's IPv6 forwarding gives as 1, shows as 0). */
static void sysctl_write(const char *path, const char *value) {
    char name[128];
    snprintf(name, sizeof name, "/proc/sys/net/%s", path);
    int fd = open(name, O_WRONLY);
    long got = fd < 0 ? -errno : result(write(fd, value, strlen(value)));
    if (fd >= 0) close(fd);
    printf("%s: write %s=%s: %ld\n", side, path, value, got < 0 ? got : 0);
}
/* A new namespace takes the first one's IPv4 all and default settings,
   which the host may have changed (Docker turns forwarding on, Ubuntu
   rp_filter to 2): sets them, and lo's, to 0 as Linux is built, before
   anything hears of them. */
static void settings_as_built(void) {
    static const char *const paths[] = {
        "ipv4/conf/all/forwarding", "ipv4/conf/default/forwarding", "ipv4/conf/lo/forwarding",
        "ipv4/conf/all/rp_filter",  "ipv4/conf/default/rp_filter",  "ipv4/conf/lo/rp_filter",
    };
    for (unsigned i = 0; i < sizeof paths / sizeof *paths; i++) sysctl_write(paths[i], "0");
}
static int route_socket(unsigned groups) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE_);
    struct nl_address at = {.family = AF_NETLINK, .groups = groups};
    bind(fd, (void *)&at, sizeof at);
    return fd;
}
static void send_request(int fd, unsigned short type, unsigned short flags, const struct body *b) {
    unsigned char buf[2048] = {0};
    struct nl_header *h = (void *)buf;
    h->len = sizeof *h + b->len;
    h->type = type;
    h->flags = flags;
    h->seq = ++seq;
    memcpy(buf + sizeof *h, b->bytes, b->len);
    struct nl_address kernel = {.family = AF_NETLINK};
    if (sendto(fd, buf, h->len, 0, (void *)&kernel, sizeof kernel) < 0) printf("%s: send=%d\n", side, -errno);
}

/* A link message's attributes that are the same from run to run. */
static void show_attribute(unsigned short type, const unsigned char *v, int len) {
    unsigned value = 0;
    if (len >= 4) memcpy(&value, v, 4);
    switch (type) {
    case 1:
    case 2:
        printf(" %s=", type == 1 ? "address" : "broadcast");
        for (int i = 0; i < len; i++) printf("%s%02x", i ? ":" : "", v[i]);
        break;
    case 3: printf(" name=%.*s", len > 0 ? len - 1 : 0, v); break;
    case 4: printf(" mtu=%u", value); break;
    case 5: printf(" link=%u", value); break;
    case 6: printf(" qdisc=%.*s", len > 0 ? len - 1 : 0, v); break;
    case 13: printf(" txqlen=%u", value); break;
    case 16: printf(" operstate=%u", v[0]); break;
    case 17: printf(" linkmode=%u", v[0]); break;
    case 27: printf(" group=%u", value); break;
    case 33: printf(" carrier=%u", v[0]); break;
    case 35: printf(" carrier-changes=%u", value); break;
    case 37: printf(" link-netnsid=%d", (int)value); break;
    case 45: printf(" new-netnsid=%d", (int)value); break;
    case 49: printf(" new-ifindex=%d", (int)value); break;
    case 18:
        for (int at = 0; at + 4 <= len;) {
            unsigned short alen, kind;
            memcpy(&alen, v + at, 2);
            memcpy(&kind, v + at + 2, 2);
            if (alen < 4 || at + alen > len) break;
            if ((kind & 0x3fff) == 1) printf(" kind=%.*s", alen - 5, v + at + 4);
            at += (alen + 3) & ~3;
        }
        break;
    }
}
/* Prints the link messages of the n bytes at buf for lo and the pair,
   and the errors and ends; returns whether one ended a request. */
static int show(const unsigned char *buf, long n, const char *label) {
    int ended = 0;
    for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
        const struct nl_header *h = (const void *)(buf + at);
        if (h->len < sizeof *h || at + h->len > n) break;
        const unsigned char *body = (const unsigned char *)(h + 1);
        int body_len = (int)(h->len - sizeof *h);
        if (h->type == 2 && body_len >= 4) {
            int error;
            memcpy(&error, body, 4);
            printf("%s: %s: error=%d\n", side, label, error);
            ended = 1;
        } else if (h->type == 3) {
            printf("%s: %s: done\n", side, label);
            ended = 1;
        } else if ((h->type == RTM_NEWNSID || h->type == RTM_DELNSID) && body_len >= 4) {
            printf("%s: %s: type=%u", side, label, h->type);
            for (int a = 4; a + 4 <= body_len;) {
                unsigned short alen, kind;
                memcpy(&alen, body + a, 2);
                memcpy(&kind, body + a + 2, 2);
                if (alen < 4 || a + alen > body_len) break;
                int value = 0;
                if (alen >= 8) memcpy(&value, body + a + 4, 4);
                if ((kind & 0x3fff) == 1) printf(" nsid=%d", value);
                a += (alen + 3) & ~3;
            }
            printf("\n");
        } else if ((h->type == RTM_NEWNETCONF || h->type == RTM_DELNETCONF) && body_len >= 4) {
            /* Of all, default, lo and the pairs; others are tunnels. */
            int index = 0;
            if (body_len >= 12) memcpy(&index, body + 8, 4);
            if (index == -1 || index == -2 || index == 1 || (index >= A_INDEX && index <= A_INDEX + 3)) {
                printf("%s: %s: type=%u family=%u", side, label, h->type, body[0]);
                for (int a = 4; a + 4 <= body_len;) {
                    unsigned short alen, kind;
                    memcpy(&alen, body + a, 2);
                    memcpy(&kind, body + a + 2, 2);
                    if (alen < 4 || a + alen > body_len) break;
                    int value = 0;
                    if (alen >= 8) memcpy(&value, body + a + 4, 4);
                    printf(" %u=%d", kind & 0x3fff, value);
                    a += (alen + 3) & ~3;
                }
                printf("\n");
            }
        } else if ((h->type == RTM_NEWLINK || h->type == RTM_DELLINK) && body_len >= 16) {
            struct ifinfo i;
            memcpy(&i, body, sizeof i);
            if (i.index == 1 || (i.index >= A_INDEX && i.index <= A_INDEX + 3)) {
                printf("%s: %s: type=%u multi=%d family=%u arphrd=%u index=%d flags=%#x change=%#x", side, label,
                       h->type, !!(h->flags & 2), i.family, i.type, i.index, i.flags, i.change);
                for (int a = 16; a + 4 <= body_len;) {
                    unsigned short alen, kind;
                    memcpy(&alen, body + a, 2);
                    memcpy(&kind, body + a + 2, 2);
                    if (alen < 4 || a + alen > body_len) break;
                    show_attribute(kind & 0x3fff, body + a + 4, alen - 4);
                    a += (alen + 3) & ~3;
                }
                printf("\n");
            }
        }
        at += (h->len + 3) & ~3u;
    }
    return ended;
}
/* Receives the answer to the last request on fd, until its error or end. */
static void answer(int fd, const char *label) {
    static unsigned char buf[65536];
    for (;;) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) {
            printf("%s: %s: no answer\n", side, label);
            return;
        }
        long n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0) return;
        if (show(buf, n, label)) return;
    }
}
/* What the member mon hears: the first datagram within `first` ms, then
   each until none has come for `quiet` ms. */
static void heard(int mon, const char *label, int first, int quiet) {
    static unsigned char buf[65536];
    for (int wait = first;; wait = quiet) {
        struct pollfd ready = {.fd = mon, .events = POLLIN};
        if (poll(&ready, 1, wait) <= 0) return;
        long n = recv(mon, buf, sizeof buf, MSG_DONTWAIT);
        if (n < 0) printf("%s: %s: recv=%d\n", side, label, -errno);
        if (n <= 0) return;
        show(buf, n, label);
    }
}
static void dump(int fd, const char *label) {
    struct body b = {0};
    info(&b, 0, 0, 0);
    send_request(fd, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, &b);
    answer(fd, label);
}
static void request(int fd, unsigned short type, unsigned short flags, const struct body *b, const char *label) {
    send_request(fd, type, NLM_F_REQUEST | NLM_F_ACK | flags, b);
    answer(fd, label);
}
static void set_up(int fd, int index, int up, const char *label) {
    struct body b = {0};
    info(&b, index, up ? IFF_UP : 0, IFF_UP);
    request(fd, RTM_NEWLINK, 0, &b, label);
}
/* SIOCGIFINDEX and SIOCGIFFLAGS of name, and SIOCGIFNAME of index. */
static void ioctls(int fd, const char *name, int index) {
    struct ifreq r = {0};
    strncpy(r.ifr_name, name, IFNAMSIZ - 1);
    long got = result(ioctl(fd, SIOCGIFINDEX, &r));
    printf("%s: SIOCGIFINDEX %s=%ld index=%d\n", side, name, got, got == 0 ? r.ifr_ifindex : 0);
    memset(&r, 0, sizeof r);
    strncpy(r.ifr_name, name, IFNAMSIZ - 1);
    got = result(ioctl(fd, SIOCGIFFLAGS, &r));
    printf("%s: SIOCGIFFLAGS %s=%ld flags=%#x\n", side, name, got, got == 0 ? (unsigned)(unsigned short)r.ifr_flags : 0);
    memset(&r, 0, sizeof r);
    r.ifr_ifindex = index;
    got = result(ioctl(fd, SIOCGIFNAME, &r));
    printf("%s: SIOCGIFNAME %d=%ld name=%s\n", side, index, got, got == 0 ? r.ifr_name : "-");
}
/* RTM_NEWLINK of kind veth: `name` of `index` here (any for 0), of the
   address `mac` (02:00:00:00:00:0a for none), with its peer `peer_name`
   of `peer_index`, of 02:00:00:00:00:0b, in the namespace of process
   `peer` (this one for 0). */
static void veth(struct body *b, const char *name, int index, const char *peer_name, int peer_index, pid_t peer,
                 const unsigned char *mac, int mac_len) {
    const unsigned char a[6] = {2, 0, 0, 0, 0, 0x0a}, bm[6] = {2, 0, 0, 0, 0, 0x0b};
    info(b, index, 0, 0);
    put(b, IFLA_IFNAME, name, strlen(name) + 1);
    put(b, IFLA_ADDRESS, mac ? mac : a, mac ? mac_len : 6);
    size_t link = begin(b, IFLA_LINKINFO);
    put(b, IFLA_INFO_KIND, "veth", 5);
    size_t data = begin(b, IFLA_INFO_DATA);
    size_t pe = begin(b, VETH_INFO_PEER);
    info(b, peer_index, 0, 0);
    put(b, IFLA_IFNAME, peer_name, strlen(peer_name) + 1);
    put(b, IFLA_ADDRESS, bm, 6);
    if (peer) put32(b, IFLA_NET_NS_PID, (unsigned)peer);
    end(b, pe);
    end(b, data);
    end(b, link);
}

/* B: makes its namespace, then does what A writes to `in`, one letter at
   a time, writing back to `out` when done. */
static void child(int in, int out) {
    side = "B";
    if (unshare(CLONE_NEWNET) < 0) printf("B: unshare=%d\n", -errno);
    settings_as_built();
    int ctl = route_socket(0), mon = route_socket(1);
    join_netconf(mon);
    fflush(stdout);
    if (write(out, "r", 1) != 1) _exit(2);
    for (char command; read(in, &command, 1) == 1;) {
        if (command == 'p') {
            heard(mon, "heard", 300, 300);
            dump(ctl, "dump");
            ioctls(ctl, "vb", B_INDEX);
        } else if (command == 'c') {
            /* Waits for the carrier, which linkwatch may tell later. */
            heard(mon, "heard", 3000, 1500);
            dump(ctl, "dump");
        } else if (command == 'u') {
            set_up(ctl, B_INDEX, 1, "up vb");
        } else if (command == 'x') {
            fflush(stdout);
            _exit(0);
        }
        fflush(stdout);
        if (write(out, "d", 1) != 1) _exit(2);
    }
    _exit(0);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-links")) return 99;
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
    /* Has B do `command` and waits until it has. */
#define B_DOES(command)                                                       \
    do {                                                                      \
        fflush(stdout);                                                       \
        if (write(to_b[1], command, 1) != 1 || read(to_a[0], &ready, 1) != 1) \
            printf("A: B gone\n");                                            \
    } while (0)
    printf("A: unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    settings_as_built();
    int ctl = route_socket(0), mon = route_socket(1);
    /* RTNLGRP_NSID too, to hear B's ID go before its end of the pair. */
    int nsid_group = RTNLGRP_NSID_;
    printf("A: join nsid=%ld\n",
           result(setsockopt(mon, SOL_NETLINK_, NETLINK_ADD_MEMBERSHIP_, &nsid_group, sizeof nsid_group)));
    join_netconf(mon);
    struct body m = {0};
    veth(&m, "va", A_INDEX, "vb", B_INDEX, b, NULL, 0);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make");
    heard(mon, "heard", 300, 300);
    dump(ctl, "dump");
    ioctls(ctl, "va", A_INDEX);
    B_DOES("p");
    /* The settings' writes: all's IPv4 forwarding tells all's, default's
       and each device's; a device's or default's its own; rp_filter of
       default its own alone; IPv6's only as it turns on or off. A value
       the setting has tells nothing. */
    sysctl_write("ipv4/conf/all/forwarding", "1");
    heard(mon, "heard", 300, 300);
    sysctl_write("ipv4/conf/va/forwarding", "0");
    sysctl_write("ipv4/conf/va/forwarding", "0");
    sysctl_write("ipv4/conf/default/forwarding", "0");
    sysctl_write("ipv4/conf/default/rp_filter", "2");
    sysctl_write("ipv4/conf/va/rp_filter", "2");
    heard(mon, "heard", 300, 300);
    sysctl_write("ipv6/conf/all/forwarding", "1");
    heard(mon, "heard", 300, 300);
    sysctl_write("ipv6/conf/all/forwarding", "2");
    sysctl_write("ipv6/conf/va/forwarding", "0");
    sysctl_write("ipv6/conf/default/forwarding", "1");
    sysctl_write("ipv6/conf/all/disable_ipv6", "0");
    heard(mon, "heard", 300, 300);
    sysctl_write("ipv4/conf/all/forwarding", "0");
    sysctl_write("ipv6/conf/all/forwarding", "0");
    sysctl_write("ipv4/conf/default/rp_filter", "0");
    heard(mon, "heard", 300, 300);
    /* What is refused: the name again, an address of 5 bytes, a multicast
       address, an MTU below 68, a kind there is not, deleting lo. */
    m = (struct body){0};
    veth(&m, "va", 0, "vc", 0, 0, NULL, 0);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make va again");
    const unsigned char short_mac[5] = {2, 0, 0, 0, 0}, group[6] = {1, 0, 0x5e, 0, 0, 1};
    m = (struct body){0};
    veth(&m, "vd", 0, "ve", 0, 0, short_mac, 5);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make short address");
    m = (struct body){0};
    veth(&m, "vd", 0, "ve", 0, 0, group, 6);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make multicast address");
    m = (struct body){0};
    veth(&m, "vd", 0, "ve", 0, 0, NULL, 0);
    put32(&m, IFLA_MTU, 67);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make mtu 67");
    m = (struct body){0};
    info(&m, 0, 0, 0);
    put(&m, IFLA_IFNAME, "vd", 3);
    size_t link = begin(&m, IFLA_LINKINFO);
    put(&m, IFLA_INFO_KIND, "nosuchkind", 11);
    end(&m, link);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make unknown kind");
    m = (struct body){0};
    info(&m, 1, 0, 0);
    request(ctl, RTM_DELLINK, 0, &m, "delete lo");
    heard(mon, "heard", 300, 300);
    /* Up: va alone has no carrier; with vb up too, both have it. */
    set_up(ctl, A_INDEX, 1, "up va");
    heard(mon, "heard", 300, 300);
    ioctls(ctl, "va", A_INDEX);
    B_DOES("u");
    heard(mon, "carrier", 3000, 1500);
    B_DOES("c");
    dump(ctl, "dump up");
    ioctls(ctl, "va", A_INDEX);
    /* Down again: the peer loses its carrier. */
    set_up(ctl, A_INDEX, 0, "down va");
    heard(mon, "heard", 3000, 1500);
    B_DOES("c");
    /* Deleting one end takes both. */
    m = (struct body){0};
    info(&m, A_INDEX, 0, 0);
    request(ctl, RTM_DELLINK, 0, &m, "delete va");
    heard(mon, "heard", 300, 300);
    dump(ctl, "dump deleted");
    ioctls(ctl, "va", A_INDEX);
    B_DOES("p");
    /* A pair within A (its peer of no namespace is the requester's), then
       its end vd, up, moved to B (IFLA_NET_NS_PID of a link there is):
       closed first, and gone from A with its new ID and index. vc stays
       down, so neither has a carrier to lose. Then deleted from A. vc's
       MTU is too small for IPv6, so it has only IPv4's settings; each end
       takes default's (forwarding on), and vd takes B's as it moves. */
    sysctl_write("ipv4/conf/default/forwarding", "1");
    heard(mon, "heard", 300, 300);
    m = (struct body){0};
    veth(&m, "vc", A_INDEX + 2, "vd", A_INDEX + 3, 0, NULL, 0);
    put32(&m, IFLA_MTU, 1279);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make within");
    heard(mon, "heard", 300, 300);
    dump(ctl, "dump within");
    set_up(ctl, A_INDEX + 3, 1, "up vd");
    heard(mon, "heard", 300, 300);
    m = (struct body){0};
    info(&m, A_INDEX + 3, 0, 0);
    put32(&m, IFLA_NET_NS_PID, (unsigned)b);
    request(ctl, RTM_NEWLINK, 0, &m, "move vd");
    heard(mon, "heard", 300, 300);
    dump(ctl, "dump moved");
    B_DOES("p");
    m = (struct body){0};
    info(&m, A_INDEX + 2, 0, 0);
    request(ctl, RTM_DELLINK, 0, &m, "delete vc");
    heard(mon, "heard", 300, 300);
    B_DOES("p");
    /* A pair within A with vd up, deleted by vc: every end up is closed
       before either is told gone. */
    m = (struct body){0};
    veth(&m, "vc", A_INDEX + 2, "vd", A_INDEX + 3, 0, NULL, 0);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make within again");
    /* Linux's link watch finds each end's operational state (vd's lower
       layer down once up, as vc is down) as it runs after the make. */
    heard(mon, "heard", 300, 300);
    set_up(ctl, A_INDEX + 3, 1, "up vd again");
    heard(mon, "heard", 300, 300);
    m = (struct body){0};
    info(&m, A_INDEX + 2, 0, 0);
    request(ctl, RTM_DELLINK, 0, &m, "delete vc within");
    heard(mon, "heard", 300, 300);
    /* Made again, and taken when B's namespace goes. */
    m = (struct body){0};
    veth(&m, "va", A_INDEX, "vb", B_INDEX, b, NULL, 0);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make again");
    heard(mon, "heard", 300, 300);
    fflush(stdout);
    if (write(to_b[1], "x", 1) != 1) printf("A: B gone\n");
    int status = 0;
    waitpid(b, &status, 0);
    printf("A: B exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    heard(mon, "namespace gone", 5000, 1500);
    dump(ctl, "dump at the end");
    return 0;
}
