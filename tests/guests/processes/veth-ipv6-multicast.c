/* IPv6 multicast groups across two veth pairs (so as root): a child, B,
   makes a network namespace of its own and waits; the parent, A, makes
   another and the pairs, va (1000, 02:00:00:00:00:0a, 2001:db8:1::1/64) to
   vb (1001, ...:0b, 2001:db8:1::2) and vc (1002, ...:0c, 2001:db8:3::1) to vd
   (1003, ...:0d, 2001:db8:3::2), with va and vc in A, and no duplicate
   address detection. First the options and their errors
   (IPV6_MULTICAST_HOPS, IPV6_MULTICAST_LOOP, IPV6_MULTICAST_ALL,
   IPV6_ADD_MEMBERSHIP, IPV6_DROP_MEMBERSHIP), over UDP, TCP and IPv4
   sockets. Then datagrams to groups, by the route, IPV6_MULTICAST_IF, a
   scope ID, the socket's device: B's sockets get each that came in on a
   device in the group, whichever socket joined it, unless
   IPV6_MULTICAST_ALL is off and they are members of it nowhere, or they
   are bound to another group, address or device; A's own sockets get a copy
   too where its device is in the group, not with IPV6_MULTICAST_LOOP off.
   With a hop limit of 0 that copy is all there is, but with none it goes
   on to B. A group of the interface's scope stays, one of scope 0 comes
   nowhere. Each device is in the all-nodes groups, its addresses'
   solicited-node groups and, forwarding, the all-routers ones; a socket
   that is no member cannot leave one. Leaving, closing and a device going
   away end memberships. Last, both ends of a pair in one namespace, ve (1004) and vf
   (1005), told apart by a socket filter that keeps as many bytes as the
   packet type (PACKET_LOOPBACK is 5, PACKET_MULTICAST 2). For each send
   every socket that got it is shown, and "nobody" where none did. A
   datagram to a group has been delivered as sendto returns, so each side
   looks after A has sent; addresses are waited for on netlink. */
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
#define RTM_NEWROUTE 24
#define RTM_DELLINK 17
#define RTA_DST 1
#define NLM_F_REQUEST 1
#define NLM_F_ACK 4
#define NLM_F_EXCL 0x200
#define NLM_F_CREATE 0x400
#define IFLA_ADDRESS 1
#define IFLA_IFNAME 3
#define IFLA_LINKINFO 18
#define IFLA_NET_NS_PID 19
#define IPV6_MULTICAST_ALL_ 29
#define IFLA_INFO_KIND 1
#define IFLA_INFO_DATA 2
#define VETH_INFO_PEER 1
#define IFA_LOCAL 2
#define IFA_FLAGS 8
#define IFA_F_NODAD 0x02
#define VA 1000
#define VB 1001
#define VC 1002
#define VD 1003
#define VE 1004
#define VF 1005
#define SO_BINDTOIFINDEX_ 62

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

static void set_link(int fd, int index, int up, const char *label) {
    struct body b = {0};
    info(&b, index, up ? IFF_UP : 0, IFF_UP);
    request(fd, RTM_NEWLINK, 0, &b, label);
}
/* The local IPv6 routes heard of, each of an address there. */
static unsigned char locals[64][16];
static int known;
/* Hears what comes to the member `links`, waiting up to 5 s: whether any
   did. */
static int hear(int links) {
    static unsigned char buf[65536];
    struct pollfd ready = {.fd = links, .events = POLLIN};
    if (poll(&ready, 1, 5000) <= 0) return 0;
    long n = recv(links, buf, sizeof buf, MSG_DONTWAIT);
    for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
        const struct nl_header *h = (const void *)(buf + at);
        if (h->len < sizeof *h || at + h->len > n) break;
        const unsigned char *body = (const unsigned char *)(h + 1);
        int body_len = (int)(h->len - sizeof *h);
        int local = h->type == RTM_NEWROUTE && body_len >= 12 && body[0] == AF_INET6 && body[7] == 2;
        for (int a = 12; local && a + 4 <= body_len;) {
            unsigned short alen, kind;
            memcpy(&alen, body + a, 2);
            memcpy(&kind, body + a + 2, 2);
            if (alen < 4 || a + alen > body_len) break;
            if (kind == RTA_DST && alen == 20 && known < 64) memcpy(locals[known++], body + a + 4, 16);
            a += (alen + 3) & ~3;
        }
        at += (h->len + 3) & ~3u;
    }
    return n > 0;
}
/* Waits for the address `ip` to be there. */
static void address_up(int links, const char *ip) {
    unsigned char want[16];
    inet_pton(AF_INET6, ip, want);
    for (int seen = 0;;) {
        for (; seen < known; seen++)
            if (!memcmp(locals[seen], want, 16)) return;
        if (!hear(links)) {
            printf("%s: %s never came\n", side, ip);
            return;
        }
    }
}
static void sysctl(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    long r = result(fd < 0 ? fd : write(fd, value, strlen(value)));
    printf("%s: %s=%ld\n", side, path, r);
    if (fd >= 0) close(fd);
}
/* Adds the IPv6 address `ip`/64 of the device of `index`, IFA_F_NODAD. */
static void address(int fd, int links, int index, const char *ip, const char *label) {
    struct body b = {0};
    const unsigned char m[8] = {AF_INET6, 64, IFA_F_NODAD, 0, (unsigned char)index, (unsigned char)(index >> 8), 0, 0};
    unsigned char in[16];
    inet_pton(AF_INET6, ip, in);
    raw(&b, m, sizeof m);
    put(&b, IFA_LOCAL, in, 16);
    put32(&b, IFA_FLAGS, IFA_F_NODAD);
    request(fd, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &b, label);
    address_up(links, ip);
}
static void make_pair(int ctl, int ns, int own, const char *own_name, int theirs, const char *their_name) {
    struct body m = {0};
    unsigned char mac[6] = {2, 0, 0, 0, 0, (unsigned char)(own - 1000 + 10)};
    info(&m, own, 0, 0);
    put(&m, IFLA_IFNAME, own_name, strlen(own_name) + 1);
    put(&m, IFLA_ADDRESS, mac, 6);
    size_t link = begin(&m, IFLA_LINKINFO);
    put(&m, IFLA_INFO_KIND, "veth", 5);
    size_t data = begin(&m, IFLA_INFO_DATA);
    size_t peer = begin(&m, VETH_INFO_PEER);
    info(&m, theirs, 0, 0);
    put(&m, IFLA_IFNAME, their_name, strlen(their_name) + 1);
    mac[5]++;
    put(&m, IFLA_ADDRESS, mac, 6);
    put32(&m, IFLA_NET_NS_PID, (unsigned)ns);
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make a pair");
}

static struct sockaddr_in6 at(const char *ip, int port, unsigned scope) {
    struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)port), .sin6_scope_id = scope};
    inet_pton(AF_INET6, ip, &a.sin6_addr);
    return a;
}
static long set(int fd, int name, const void *value, socklen_t len) {
    return result(setsockopt(fd, IPPROTO_IPV6, name, value, len));
}
static long set_int(int fd, int name, int value) { return set(fd, name, &value, sizeof value); }
static void show(const char *label, long r) { printf("%s: %s=%ld\n", side, label, r); }
static struct ipv6_mreq mreq(const char *group, int index) {
    struct ipv6_mreq m = {.ipv6mr_interface = (unsigned)index};
    inet_pton(AF_INET6, group, &m.ipv6mr_multiaddr);
    return m;
}
static long join(int fd, const char *group, int index) {
    struct ipv6_mreq m = mreq(group, index);
    return set(fd, IPV6_JOIN_GROUP, &m, sizeof m);
}
static long leave(int fd, const char *group, int index) {
    struct ipv6_mreq m = mreq(group, index);
    return set(fd, IPV6_LEAVE_GROUP, &m, sizeof m);
}
static void get(int fd, int name, const char *label) {
    int v = 77;
    socklen_t len = sizeof v;
    long r = result(getsockopt(fd, IPPROTO_IPV6, name, &v, &len));
    printf("%s: %s: getsockopt=%ld len=%u %d\n", side, label, r, len, v);
}
static void accepted(const char *ip, const char *label) {
    int l = socket(AF_INET6, SOCK_STREAM, 0), t = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 a = at(ip, 7100, 0);
    bind(l, (void *)&a, sizeof a);
    listen(l, 1);
    show(label, result(connect(t, (void *)&a, sizeof a)));
    int got = accept(l, NULL, NULL);
    get(t, IPV6_MULTICAST_HOPS, "hops of the connected");
    get(got, IPV6_MULTICAST_HOPS, "hops of the accepted");
    close(got), close(t), close(l);
}
static void options(void) {
    int u = socket(AF_INET6, SOCK_DGRAM, 0), t = socket(AF_INET6, SOCK_STREAM, 0), four = socket(AF_INET, SOCK_DGRAM, 0);
    void *const nowhere = (void *)8;
    struct ipv6_mreq m = mreq("ff05::1:3", VA);
    get(u, IPV6_MULTICAST_HOPS, "hops unset");
    show("hops 5", set_int(u, IPV6_MULTICAST_HOPS, 5));
    get(u, IPV6_MULTICAST_HOPS, "hops");
    show("hops 256", set_int(u, IPV6_MULTICAST_HOPS, 256));
    show("hops -2", set_int(u, IPV6_MULTICAST_HOPS, -2));
    show("hops -1", set_int(u, IPV6_MULTICAST_HOPS, -1));
    get(u, IPV6_MULTICAST_HOPS, "hops");
    show("hops in 3 bytes", set(u, IPV6_MULTICAST_HOPS, &m, 3));
    show("hops from nowhere", set(u, IPV6_MULTICAST_HOPS, nowhere, 4));
    show("hops from NULL", set(u, IPV6_MULTICAST_HOPS, NULL, 4));
    get(u, IPV6_MULTICAST_HOPS, "hops");
    show("hops of TCP", set_int(t, IPV6_MULTICAST_HOPS, 5));
    show("hops of TCP in 3 bytes", set(t, IPV6_MULTICAST_HOPS, &m, 3));
    get(t, IPV6_MULTICAST_HOPS, "hops of TCP");
    show("hops of IPv4", set_int(four, IPV6_MULTICAST_HOPS, 5));
    get(u, IPV6_MULTICAST_LOOP, "loop unset");
    show("loop 2", set_int(u, IPV6_MULTICAST_LOOP, 2));
    show("loop 0", set_int(u, IPV6_MULTICAST_LOOP, 0));
    get(u, IPV6_MULTICAST_LOOP, "loop");
    show("loop in 3 bytes", set(u, IPV6_MULTICAST_LOOP, &m, 3));
    show("loop 1 of TCP", set_int(t, IPV6_MULTICAST_LOOP, 1));
    get(u, IPV6_MULTICAST_ALL_, "all unset");
    show("all 0", set_int(u, IPV6_MULTICAST_ALL_, 0));
    get(u, IPV6_MULTICAST_ALL_, "all");
    show("all 2", set_int(u, IPV6_MULTICAST_ALL_, 2));
    get(u, IPV6_MULTICAST_ALL_, "all");
    show("all in 3 bytes", set(u, IPV6_MULTICAST_ALL_, &m, 3));
    /* Memberships. */
    show("join on va", join(u, "ff05::1:3", VA));
    show("join on va again", join(u, "ff05::1:3", VA));
    show("join anywhere", join(u, "ff05::1:3", 0));
    show("join on vc", join(u, "ff05::1:3", VC));
    show("join on lo", join(u, "ff05::1:3", 1));
    show("join on no device", join(u, "ff05::1:3", 999));
    show("join on -1", join(u, "ff05::1:3", -1));
    show("join no group", join(u, "2001:db8:1::2", VA));
    show("join another by the route", join(u, "ff05::1:4", 0));
    show("join another by the route again", join(u, "ff05::1:4", VA));
    show("join in 19 bytes", set(u, IPV6_JOIN_GROUP, &m, 19));
    show("join in 24 bytes", set(u, IPV6_JOIN_GROUP, &(struct {
                                    struct ipv6_mreq m;
                                    int more;
                                }){mreq("ff05::1:5", VA), 0},
                                24));
    show("join from nowhere", set(u, IPV6_JOIN_GROUP, nowhere, 20));
    show("join from NULL", set(u, IPV6_JOIN_GROUP, NULL, 20));
    show("join of TCP", join(t, "ff05::1:3", VA));
    show("join of TCP in 19 bytes", set(t, IPV6_JOIN_GROUP, &m, 19));
    show("join of TCP from NULL", set(t, IPV6_JOIN_GROUP, NULL, 20));
    show("join of IPv4", join(four, "ff05::1:3", VA));
    show("leave another group", leave(u, "ff05::9:9", VA));
    show("leave on no device", leave(u, "ff05::1:3", 999));
    show("leave no group", leave(u, "2001:db8:1::2", VA));
    show("leave on vc", leave(u, "ff05::1:3", VC));
    show("leave on vc again", leave(u, "ff05::1:3", VC));
    show("leave anywhere", leave(u, "ff05::1:3", 0));
    show("leave anywhere again", leave(u, "ff05::1:3", 0));
    show("leave anywhere once more", leave(u, "ff05::1:3", 0));
    show("leave in 19 bytes", set(u, IPV6_LEAVE_GROUP, &m, 19));
    show("leave of TCP", leave(t, "ff05::1:3", VA));
    /* What the devices are in by themselves. */
    show("leave all nodes", leave(u, "ff02::1", VA));
    show("leave all nodes anywhere", leave(u, "ff02::1", 0));
    show("leave a solicited-node group", leave(u, "ff02::1:ff00:a", VA));
    show("join all nodes", join(u, "ff02::1", VA));
    show("join a solicited-node group", join(u, "ff02::1:ff00:a", VA));
    show("leave all nodes", leave(u, "ff02::1", VA));
    show("leave all nodes again", leave(u, "ff02::1", VA));
    show("leave a solicited-node group", leave(u, "ff02::1:ff00:a", VA));
    int many = socket(AF_INET6, SOCK_DGRAM, 0);
    for (int i = 1; i <= 25; i++) {
        char group[32];
        snprintf(group, sizeof group, "ff05::2:%d", i);
        long r = join(many, group, VA);
        if (r || i == 25) show(group, r);
    }
    close(many), close(u), close(t), close(four);
    accepted("::1", "connect");
    accepted("::ffff:127.0.0.1", "connect mapped");
}

/* An IPv6 UDP socket with SO_REUSEADDR on `ip` at `port`. */
static int udp(const char *ip, int port, unsigned scope) {
    int fd = socket(AF_INET6, SOCK_DGRAM, 0), on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in6 a = at(ip, port, scope);
    long r = result(bind(fd, (void *)&a, sizeof a));
    if (r) printf("%s: bind %s=%ld\n", side, ip, r);
    return fd;
}
#define MOST 16
static struct {
    int fd;
    const char *label;
} sockets[MOST];
static int count;
static int watch(int fd, const char *label) {
    sockets[count].fd = fd;
    sockets[count++].label = label;
    return fd;
}
/* Shows every datagram the sockets watched have, or "nobody". */
static void look(void) {
    int any = 0;
    for (int i = 0; i < count; i++) {
        char buf[64] = {0};
        struct sockaddr_in6 from = {0};
        socklen_t len = sizeof from;
        long n;
        while (sockets[i].fd >= 0 &&
               (n = recvfrom(sockets[i].fd, buf, sizeof buf - 1, MSG_DONTWAIT, (void *)&from, &len)) >= 0) {
            char ip[64] = "-";
            inet_ntop(AF_INET6, &from.sin6_addr, ip, sizeof ip);
            printf("%s:   %s: \"%.*s\" from %s port %u scope %u\n", side, sockets[i].label, (int)n, buf, ip,
                   ntohs(from.sin6_port), from.sin6_scope_id);
            any = 1;
            len = sizeof from;
        }
    }
    if (!any) printf("%s:   nobody\n", side);
}
static int to_b, from_b;
/* Has B do `command`. */
static void b_does(char command) {
    char ready;
    fflush(stdout);
    if (write(to_b, &command, 1) != 1 || read(from_b, &ready, 1) != 1) printf("A: B gone\n");
}
/* Sends `what` to `group` at port 7000, through the scope ID `scope`, from
   `fd`, and shows who got it. */
static void send_to(int fd, const char *group, unsigned scope, const char *what) {
    struct sockaddr_in6 to = at(group, 7000, scope);
    printf("A: \"%s\" to %s: sendto=%ld\n", what, group,
           result(sendto(fd, what, strlen(what), 0, (void *)&to, sizeof to)));
    look();
    b_does('r');
}

/* B: makes its namespace, then does what A writes to `in`, one letter at
   a time, writing back to `out` when done. */
static void child(int in, int out) {
    side = "B";
    if (unshare(CLONE_NEWNET) < 0) printf("B: unshare=%d\n", -errno);
    int ctl = route_socket(0), links = route_socket(0x400);
    int member = -1, on_vd = -1, device = VD;
    fflush(stdout);
    if (write(out, "r", 1) != 1) _exit(2);
    for (char command; read(in, &command, 1) == 1;) {
        if (command == 'u') {
            sysctl("/proc/sys/net/ipv6/conf/vb/accept_dad", "0");
            sysctl("/proc/sys/net/ipv6/conf/vd/accept_dad", "0");
            set_link(ctl, 1, 1, "up lo");
            set_link(ctl, VB, 1, "up vb");
            set_link(ctl, VD, 1, "up vd");
        } else if (command == 's') {
            address_up(links, "fe80::ff:fe00:b");
            address_up(links, "fe80::ff:fe00:d");
            address(ctl, links, VB, "2001:db8:1::2", "add 2001:db8:1::2/64");
            address(ctl, links, VD, "2001:db8:3::2", "add 2001:db8:3::2/64");
            member = watch(udp("::", 7000, 0), "member on vb");
            show("join on vb", join(member, "ff05::1:3", VB));
            show("join a link's on vb", join(member, "ff02::1:3", VB));
            show("join an interface's on vb", join(member, "ff01::1:3", VB));
            show("join one of scope 0 on vb", join(member, "ff00::1:3", VB));
            watch(udp("::", 7000, 0), "no member");
            int fd = watch(udp("::", 7000, 0), "no member, all off");
            set_int(fd, IPV6_MULTICAST_ALL_, 0);
            watch(udp("ff05::1:3", 7000, 0), "bound to ff05::1:3");
            watch(udp("ff05::1:4", 7000, 0), "bound to ff05::1:4");
            watch(udp("ff02::1:3", 7000, VD), "bound to ff02::1:3 on vd");
            on_vd = watch(udp("::", 7000, 0), "member on vd, all off");
            set_int(on_vd, IPV6_MULTICAST_ALL_, 0);
            show("join on vd", join(on_vd, "ff05::1:3", VD));
            fd = watch(udp("::", 7000, 0), "bound to vd");
            setsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX_, &device, sizeof device);
            watch(udp("2001:db8:1::2", 7000, 0), "unicast");
            fd = watch(udp("ff05::1:3", 7000, 0), "connected to 2001:db8:1::1 7001");
            struct sockaddr_in6 to = at("2001:db8:1::1", 7001, 0);
            show("connect", result(connect(fd, (void *)&to, sizeof to)));
            /* A disconnect keeps the IPv6 peer's address, which a group's
               datagram from another one does not pass. */
            const char *const peers[] = {"2001:db8:1::1", "2001:db8:1::9"};
            const char *const disconnected[] = {"disconnected from 2001:db8:1::1", "disconnected from 2001:db8:1::9"};
            for (int i = 0; i < 2; i++) {
                fd = watch(udp("ff05::1:3", 7000, 0), disconnected[i]);
                to = at(peers[i], 7001, 0);
                show("connect", result(connect(fd, (void *)&to, sizeof to)));
                struct sockaddr none = {.sa_family = AF_UNSPEC};
                show("disconnect", result(connect(fd, &none, sizeof none)));
            }
            fd = socket(AF_INET, SOCK_DGRAM, 0);
            struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(7000)};
            bind(fd, (void *)&a, sizeof a);
            watch(fd, "IPv4");
        } else if (command == 'r') {
            look();
        } else if (command == 'l') {
            show("leave on vb", leave(member, "ff05::1:3", VB));
        } else if (command == 'c') {
            close(on_vd);
            for (int i = 0; i < count; i++)
                if (sockets[i].fd == on_vd) sockets[i].fd = -1;
        } else if (command == 'b') {
            /* Back to A. */
            int fd = udp("::", 7002, 0);
            struct sockaddr_in6 to = at("ff02::1:3", 7000, VB);
            show("\"back\" to ff02::1:3: sendto", result(sendto(fd, "back", 4, 0, (void *)&to, sizeof to)));
            close(fd);
            look();
        } else if (command == 'f') {
            sysctl("/proc/sys/net/ipv6/conf/vb/forwarding", "1");
        } else if (command == 'x') {
            fflush(stdout);
            _exit(0);
        }
        fflush(stdout);
        if (write(out, "d", 1) != 1) _exit(2);
    }
    _exit(0);
}

/* Both ends of a pair in one namespace. */
static void one_namespace(void) {
    printf("A: unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ctl = route_socket(0), links = route_socket(0x400);
    known = 0;
    make_pair(ctl, getpid(), VE, "ve", VF, "vf");
    sysctl("/proc/sys/net/ipv6/conf/ve/accept_dad", "0");
    sysctl("/proc/sys/net/ipv6/conf/vf/accept_dad", "0");
    set_link(ctl, VE, 1, "up ve");
    set_link(ctl, VF, 1, "up vf");
    address_up(links, "fe80::ff:fe00:e");
    address_up(links, "fe80::ff:fe00:f");
    /* ldb [SKF_AD_OFF + SKF_AD_PKTTYPE]; add #8, the UDP header; ret a */
    const struct {
        unsigned short code;
        unsigned char jt, jf;
        unsigned k;
    } code[] = {{0x30, 0, 0, 0xfffff004u}, {0x04, 0, 0, 8}, {0x16, 0, 0, 0}};
    const struct {
        unsigned short len;
        const void *filter;
    } program = {3, code};
    const int devices[] = {VE, VF};
    const char *const labels[] = {"member on ve", "member on vf"};
    for (int i = 0; i < 2; i++) {
        int fd = watch(udp("::", 7000, 0), labels[i]);
        show("filter", result(setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof program)));
        show("to its device", result(setsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX_, &devices[i], sizeof devices[i])));
        show("join", join(fd, "ff02::1:3", devices[i]));
    }
    int s = udp("::", 7001, 0);
    struct sockaddr_in6 to = at("ff02::1:3", 7000, VE);
    show("\"1234567\" to ff02::1:3: sendto", result(sendto(s, "1234567", 7, 0, (void *)&to, sizeof to)));
    look();
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-ipv6-multicast")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    int down[2], up[2];
    if (pipe(down) < 0 || pipe(up) < 0) return 98;
    fflush(stdout);
    pid_t b = fork();
    if (b == 0) {
        close(down[1]), close(up[0]);
        child(down[0], up[1]);
    }
    close(down[0]), close(up[1]);
    to_b = down[1], from_b = up[0];
    char ready;
    if (read(from_b, &ready, 1) != 1) return 97;
    printf("A: unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ctl = route_socket(0), links = route_socket(0x400);
    make_pair(ctl, b, VA, "va", VB, "vb");
    make_pair(ctl, b, VC, "vc", VD, "vd");
    sysctl("/proc/sys/net/ipv6/conf/va/accept_dad", "0");
    sysctl("/proc/sys/net/ipv6/conf/vc/accept_dad", "0");
    set_link(ctl, 1, 1, "up lo");
    int early = udp("::", 7001, 0);
    show("join with no route", join(early, "ff05::1:3", 0));
    show("join on va, down", join(early, "ff05::1:3", VA));
    close(early);
    b_does('u');
    set_link(ctl, VA, 1, "up va");
    address_up(links, "fe80::ff:fe00:a");
    set_link(ctl, VC, 1, "up vc");
    address_up(links, "fe80::ff:fe00:c");
    address(ctl, links, VA, "2001:db8:1::1", "add 2001:db8:1::1/64");
    address(ctl, links, VC, "2001:db8:3::1", "add 2001:db8:3::1/64");
    options();

    b_does('s');
    int member = watch(udp("::", 7000, 0), "member on va");
    show("join on va", join(member, "ff05::1:3", VA));
    show("join a link's on va", join(member, "ff02::1:3", VA));
    show("join an interface's on va", join(member, "ff01::1:3", VA));
    show("join one of scope 0 on va", join(member, "ff00::1:3", VA));
    watch(udp("::", 7000, 0), "no member");
    int off = watch(udp("::", 7000, 0), "no member, all off");
    set_int(off, IPV6_MULTICAST_ALL_, 0);

    int s = udp("::", 7001, 0);
    send_to(s, "ff05::1:3", 0, "by the route");
    show("if va", set_int(s, IPV6_MULTICAST_IF, VA));
    send_to(s, "ff05::1:3", 0, "through va");
    send_to(s, "ff05::1:9", 0, "another group");
    send_to(s, "ff02::1:3", 0, "a link's group");
    send_to(s, "ff02::1:3", VC, "a link's group through vc");
    send_to(s, "ff01::1:3", 0, "an interface's group");
    send_to(s, "ff00::1:3", 0, "a group of scope 0");
    send_to(s, "ff02::1", 0, "all nodes");
    send_to(s, "ff01::1", 0, "all nodes of va");
    send_to(s, "ff05::1", 0, "no all nodes");
    send_to(s, "ff02::1:ff00:b", 0, "vb's solicited-node");
    send_to(s, "ff02::1:ff00:a", 0, "va's solicited-node");
    send_to(s, "ff02::1:ff00:2", 0, "vb's other");
    send_to(s, "ff02::1:ff00:77", 0, "nobody's");
    send_to(s, "ff02::2", 0, "no router");
    b_does('f');
    send_to(s, "ff02::2", 0, "a router");
    send_to(s, "ff05::2", 0, "a site's router");
    show("if vc", set_int(s, IPV6_MULTICAST_IF, VC));
    send_to(s, "ff05::1:3", 0, "through vc");
    send_to(s, "ff02::2", 0, "no router on vd");
    show("if va", set_int(s, IPV6_MULTICAST_IF, VA));
    show("loop 0", set_int(s, IPV6_MULTICAST_LOOP, 0));
    send_to(s, "ff05::1:3", 0, "no loop");
    show("hops 0", set_int(s, IPV6_MULTICAST_HOPS, 0));
    send_to(s, "ff05::1:3", 0, "no loop, no hops");
    show("loop 1", set_int(s, IPV6_MULTICAST_LOOP, 1));
    send_to(s, "ff05::1:3", 0, "no hops");
    show("hops 1", set_int(s, IPV6_MULTICAST_HOPS, 1));
    b_does('b');
    look();
    close(s);
    /* By the socket's address, and by its device. */
    s = udp("2001:db8:3::1", 7001, 0);
    show("if va", set_int(s, IPV6_MULTICAST_IF, VA));
    send_to(s, "ff05::1:3", 0, "from vc's address through va");
    close(s);
    int device = VC;
    s = udp("::", 7001, 0);
    show("to vc", result(setsockopt(s, SOL_SOCKET, SO_BINDTOIFINDEX_, &device, sizeof device)));
    send_to(s, "ff05::1:3", 0, "on vc");
    send_to(s, "ff02::1:3", 0, "a link's group on vc");
    close(s);
    /* Connected. */
    s = udp("::", 7001, 0);
    show("if vc", set_int(s, IPV6_MULTICAST_IF, VC));
    struct sockaddr_in6 group = at("ff05::1:3", 7000, 0);
    show("connect", result(connect(s, (void *)&group, sizeof group)));
    show("\"connected\": send", result(send(s, "connected", 9, 0)));
    look();
    b_does('r');
    close(s);
    /* Leaving and closing. */
    s = udp("::", 7001, 0);
    show("if va", set_int(s, IPV6_MULTICAST_IF, VA));
    b_does('l');
    send_to(s, "ff05::1:3", 0, "B has left");
    show("if vc", set_int(s, IPV6_MULTICAST_IF, VC));
    send_to(s, "ff05::1:3", 0, "before a close");
    b_does('c');
    send_to(s, "ff05::1:3", 0, "after a close");
    show("if va", set_int(s, IPV6_MULTICAST_IF, VA));
    show("leave on va", leave(member, "ff05::1:3", VA));
    send_to(s, "ff05::1:3", 0, "A has left");
    /* vc goes, and B's vd with it. */
    show("join on vc", join(member, "ff05::1:3", VC));
    struct body gone = {0};
    info(&gone, VC, 0, 0);
    request(ctl, RTM_DELLINK, 0, &gone, "delete vc");
    show("join on vc, gone", join(member, "ff05::1:3", VC));
    show("join another on vc, gone", join(member, "ff05::1:4", VC));
    show("leave on vc, gone", leave(member, "ff05::1:3", VC));
    show("leave on vc again", leave(member, "ff05::1:3", VC));
    b_does('x');
    int status = 0;
    waitpid(b, &status, 0);
    printf("A: B exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    for (int i = 0; i < count; i++) close(sockets[i].fd);
    close(s), close(ctl), close(links);
    count = 0;
    one_namespace();
    return 0;
}
