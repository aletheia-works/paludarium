/* /proc/net/dev_mcast (so as root): the link-layer multicast addresses each
   device takes packets to, as its IPv4 and IPv6 groups map to them
   (ip_mc_filter_add, igmp6_group_added), each with how many groups map
   there. The process makes a network namespace of its own, with lo, which
   maps none, and a pair, va (1000, 02:00:00:00:00:0a) and vb (1001,
   ...:0b), without duplicate address detection. A group maps as it is
   joined, down or up; down, a device's groups come out of its filter and
   leave it no address; up, the all-hosts group comes first, then the
   others, the newest first. An interface-local IPv6 group maps to none.
   Linux makes a device's link-local address from its work queue a little
   after it is up, so the case polls /proc/net/dev_mcast until its
   solicited-node group's address is there or gone. */
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
#define NLM_F_CREATE 0x400
#define RTM_NEWLINK 16
#define RTM_DELLINK 17
#define SOL_NETLINK_ 270
#define NETLINK_GET_STRICT_CHK_ 12
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
static void write_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY);
    long n = fd < 0 ? -errno : result(write(fd, text, strlen(text)));
    if (fd >= 0) close(fd);
    printf("%s <- %s: %ld\n", path, text, n);
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
/* Polls /proc/net/dev_mcast until it has (or, not `there`, has not)
   `entry`, for 10 s at most, then prints it under `label`, unless that is
   NULL; an `entry` of NULL waits for nothing. */
static void await_mcast(const char *entry, int there, const char *label) {
    int found = !there;
    for (double until = seconds() + 10; seconds() < until;) {
        slurp("/proc/net/dev_mcast");
        found = !entry || strstr(text, entry) != NULL;
        if (!entry || found == there) break;
        struct timespec pause = {0, 20 * 1000 * 1000};
        nanosleep(&pause, NULL);
    }
    if (entry && found != there) printf("waited for %s\n", entry);
    if (!label) return;
    printf("-- dev_mcast: %s\n", label);
    /* Only this namespace's own devices: a kernel may make others in each
       (gretap0, erspan0). */
    for (char *line = text, *next; *line; line = next) {
        next = strchr(line, '\n');
        if (!next) break;
        *next++ = 0;
        int index = atoi(line);
        if (index == 1 || index == VA || index == VB) printf("%s\n", line);
    }
}
static void show(const char *label) { await_mcast(NULL, 1, label); }

/* `fd` joins (or leaves) the IPv4 group `ip` on the device `index`. */
static void group4(int fd, int option, int index, const char *ip, const char *label) {
    struct ip_mreqn m = {.imr_ifindex = index};
    inet_pton(AF_INET, ip, &m.imr_multiaddr);
    printf("%s: %ld\n", label, result(setsockopt(fd, IPPROTO_IP, option, &m, sizeof m)));
}
/* And the IPv6 group. */
static void group6(int fd, int option, int index, const char *ip, const char *label) {
    struct ipv6_mreq m = {.ipv6mr_interface = (unsigned)index};
    inet_pton(AF_INET6, ip, &m.ipv6mr_multiaddr);
    printf("%s: %ld\n", label, result(setsockopt(fd, IPPROTO_IPV6, option, &m, sizeof m)));
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-dev-mcast")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    ctl = socket(AF_NETLINK, SOCK_RAW, 0);
    int one = 1;
    setsockopt(ctl, SOL_NETLINK_, NETLINK_GET_STRICT_CHK_, &one, sizeof one);
    write_file("/proc/sys/net/ipv6/conf/default/accept_dad", "0");
    show("lo down, mapping none");
    link_flags(1, IFF_UP, "lo up");
    show("lo up, mapping none still");

    /* Down, a new pair maps the link-local all-nodes group of IPv6. */
    make_pair();
    show("a pair, down");

    /* Groups joined down map as they are; three IPv4 groups share an
       address, and the interface-local IPv6 one maps to none. */
    int s4 = socket(AF_INET, SOCK_DGRAM, 0), s6 = socket(AF_INET6, SOCK_DGRAM, 0);
    group4(s4, IP_ADD_MEMBERSHIP, VA, "224.1.1.1", "224.1.1.1 on va");
    group4(s4, IP_ADD_MEMBERSHIP, VA, "225.1.1.1", "225.1.1.1 on va");
    group4(s4, IP_ADD_MEMBERSHIP, VA, "239.129.1.1", "239.129.1.1 on va");
    group6(s6, IPV6_ADD_MEMBERSHIP, VA, "ff02::1:2", "ff02::1:2 on va");
    group6(s6, IPV6_ADD_MEMBERSHIP, VA, "ff01::5", "ff01::5 on va");
    group6(s6, IPV6_ADD_MEMBERSHIP, VA, "ff05::1", "ff05::1 on va");
    group4(s4, IP_ADD_MEMBERSHIP, 1, "224.3.3.3", "224.3.3.3 on lo");
    group6(s6, IPV6_ADD_MEMBERSHIP, 1, "ff02::3", "ff02::3 on lo");
    show("joined down");

    /* Up, the all-hosts group, then each link-local address's
       solicited-node group. */
    link_flags(VA, IFF_UP, "va up");
    link_flags(VB, IFF_UP, "vb up");
    await_mcast("3333ff00000a", 1, NULL);
    await_mcast("3333ff00000b", 1, "both ends' link-local addresses");

    /* Down, every group comes out of va's filter; joined down, one comes
       in all the same. */
    link_flags(VA, 0, "va down");
    await_mcast("3333ff00000a", 0, "va down");
    group4(s4, IP_ADD_MEMBERSHIP, VA, "224.2.2.2", "224.2.2.2 on va, down");
    group6(s6, IPV6_ADD_MEMBERSHIP, VA, "ff02::3", "ff02::3 on va, down");
    show("joined on va down");
    link_flags(VA, IFF_UP, "va up again");
    await_mcast("3333ff00000a", 1, "va up again");

    /* Left, a group's address goes with the last that maps to it. */
    group4(s4, IP_DROP_MEMBERSHIP, VA, "224.1.1.1", "leave 224.1.1.1");
    group6(s6, IPV6_DROP_MEMBERSHIP, VA, "ff05::1", "leave ff05::1");
    group6(s6, IPV6_DROP_MEMBERSHIP, VA, "ff02::1:2", "leave ff02::1:2");
    show("left some");

    /* IPv6 off on va takes its groups out; on again, they come back. */
    write_file("/proc/sys/net/ipv6/conf/va/disable_ipv6", "1");
    await_mcast("3333ff00000a", 0, "va's IPv6 off");
    write_file("/proc/sys/net/ipv6/conf/va/disable_ipv6", "0");
    await_mcast("3333ff00000a", 1, "va's IPv6 on again");

    /* A socket closed leaves its groups. */
    close(s4);
    show("the IPv4 socket closed");
    close(s6);
    show("the IPv6 socket closed");

    struct body b = {0};
    const unsigned m[4] = {0, VA, 0, 0};
    raw(&b, m, 16);
    request(RTM_DELLINK, &b, "the pair goes");
    show("the pair gone");
    return 0;
}
