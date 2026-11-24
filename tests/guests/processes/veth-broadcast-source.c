/* The source of what a socket bound to a broadcast or multicast address
   sends, across a veth pair (so as root): a child, B, makes a network
   namespace of its own and waits; the parent, A, makes another and a
   pair, its end "va" (1000, 10.77.0.1/24) in A and "vb" (1001,
   10.77.0.2/24) in B. IPv4's bind keeps such an address as the socket's
   name but not as its source (inet_bind: inet_saddr 0, "use device"), so
   what B's sockets bound to 10.77.0.255, 255.255.255.255 or 224.0.0.251
   send to A leaves from the route's source, 10.77.0.2: a UDP sendto, a
   UDP connect and send, whose name stays the bound address
   (__ip4_datagram_connect sets only an unset inet_rcv_saddr), a
   broadcast, and a TCP connect, whose name becomes the route's source
   (tcp_v4_connect: inet_bhash2_update_saddr). A takes them on a UDP
   socket bound to the unspecified address and a TCP listener. The two
   processes take turns through pipes, so their lines come in one order;
   a datagram is waited for with poll, the carrier on RTNLGRP_LINK. */
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
#define RTM_DELROUTE 25
#define RTA_DST 1
#define RTA_OIF 4
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

static void set_link(int fd, int index, int up, const char *label) {
    struct body b = {0};
    info(&b, index, up ? IFF_UP : 0, IFF_UP);
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
   `index` has its carrier, or has lost it. */
static void carrier(int links, int index, int want) {
    static unsigned char buf[65536];
    for (;;) {
        struct pollfd ready = {.fd = links, .events = POLLIN};
        if (poll(&ready, 1, 5000) <= 0) {
            printf("%s: no carrier change on %d\n", side, index);
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
                    if ((kind & 0x3fff) == IFLA_CARRIER && alen >= 5 && body[a + 4] == want) return;
                    a += (alen + 3) & ~3;
                }
            }
            at += (h->len + 3) & ~3u;
        }
    }
}


static struct sockaddr_in at(const char *ip, int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}
static void name(int fd, const char *label) {
    struct sockaddr_in a = {0};
    socklen_t len = sizeof a;
    long r = result(getsockname(fd, (void *)&a, &len));
    char ip[32] = "-";
    inet_ntop(AF_INET, &a.sin_addr, ip, sizeof ip);
    printf("%s: %s: getsockname=%ld %s:%u\n", side, label, r, ip, ntohs(a.sin_port));
}
/* A socket of `type` bound to `ip` port `port`, its name printed. */
static int bound(int type, const char *ip, int port, const char *label) {
    int fd = socket(AF_INET, type, 0);
    struct sockaddr_in a = at(ip, port);
    printf("%s: %s: bind=%ld\n", side, label, result(bind(fd, (void *)&a, sizeof a)));
    name(fd, label);
    return fd;
}
static void send_to(int fd, const char *ip, const char *text, const char *label) {
    struct sockaddr_in to = at(ip, 7000);
    printf("%s: %s: sendto=%ld\n", side, label,
           result(sendto(fd, text, strlen(text), 0, (void *)&to, sizeof to)));
}
/* What `fd` takes, waiting up to 2 s. */
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
    inet_ntop(AF_INET, &from.sin_addr, ip, sizeof ip);
    printf("%s: %s=%ld \"%s\" from %s:%u\n", side, label, n, n > 0 ? buf : "", ip, ntohs(from.sin_port));
}

/* B: makes its namespace, then does what A writes to `in`, one letter at
   a time, writing back to `out` when done. */
static void child(int in, int out) {
    side = "B";
    if (unshare(CLONE_NEWNET) < 0) printf("B: unshare=%d\n", -errno);
    int ctl = route_socket(0), links = route_socket(1);
    fflush(stdout);
    if (write(out, "r", 1) != 1) _exit(2);
    for (char command; read(in, &command, 1) == 1;) {
        if (command == 'u') {
            set_link(ctl, 1, 1, "up lo");
            address(ctl, B_INDEX, "10.77.0.2", "add 10.77.0.2/24");
            set_link(ctl, B_INDEX, 1, "up vb");
            carrier(links, B_INDEX, 1);
        } else if (command == 's') {
            int on = 1;
            int fd = bound(SOCK_DGRAM, "10.77.0.255", 7100, "subnet");
            send_to(fd, "10.77.0.1", "subnet", "subnet");
            name(fd, "subnet after");
            fd = bound(SOCK_DGRAM, "10.77.0.255", 7101, "connected");
            struct sockaddr_in to = at("10.77.0.1", 7000);
            printf("B: connected: connect=%ld\n", result(connect(fd, (void *)&to, sizeof to)));
            name(fd, "connected after");
            printf("B: connected: send=%ld\n", result(send(fd, "connected", 9, 0)));
            fd = bound(SOCK_DGRAM, "255.255.255.255", 7102, "limited");
            send_to(fd, "10.77.0.1", "limited", "limited");
            fd = bound(SOCK_DGRAM, "224.0.0.251", 7103, "group");
            send_to(fd, "10.77.0.1", "group", "group");
            fd = bound(SOCK_DGRAM, "10.77.0.255", 7104, "broadcast");
            setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof on);
            send_to(fd, "10.77.0.255", "broadcast", "broadcast");
            fd = bound(SOCK_STREAM, "10.77.0.255", 7105, "tcp");
            to = at("10.77.0.1", 7000);
            printf("B: tcp: connect=%ld\n", result(connect(fd, (void *)&to, sizeof to)));
            name(fd, "tcp after");
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
    if (argc < 2 || strcmp(argv[1], "veth-broadcast-source")) return 99;
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
    put32(&m, IFLA_NET_NS_PID, (unsigned)b);
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make");
    set_link(ctl, 1, 1, "up lo");
    address(ctl, A_INDEX, "10.77.0.1", "add 10.77.0.1/24");
    set_link(ctl, A_INDEX, 1, "up va");
    B_DOES("u");
    carrier(links, A_INDEX, 1);

    int any = bound(SOCK_DGRAM, "0.0.0.0", 7000, "any");
    int listener = bound(SOCK_STREAM, "10.77.0.1", 7000, "listener");
    printf("A: listen=%ld\n", result(listen(listener, 4)));
    B_DOES("s");
    for (int i = 0; i < 5; i++) receive(any, "any");
    struct pollfd ready_tcp = {.fd = listener, .events = POLLIN};
    if (poll(&ready_tcp, 1, 2000) > 0) {
        struct sockaddr_in from = {0};
        socklen_t len = sizeof from;
        long fd = result(accept(listener, (void *)&from, &len));
        char ip[32] = "-";
        inet_ntop(AF_INET, &from.sin_addr, ip, sizeof ip);
        printf("A: accept=%s from %s:%u\n", fd < 0 ? "error" : "ok", ip, ntohs(from.sin_port));
    } else {
        printf("A: accept: nothing\n");
    }

    fflush(stdout);
    if (write(to_b[1], "x", 1) != 1) printf("A: B gone\n");
    int status = 0;
    waitpid(b, &status, 0);
    printf("A: B exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}
