/* What a UDP socket's disconnect leaves (so as root): in a network namespace
   of its own, lo has 2001:db8::1/128 (IFA_F_NODAD) too. IPv4's and IPv6's lose
   their peer's port, the device they are bound to, and what the guest did not
   bind; but an IPv6 one keeps its peer's address (sk_v6_daddr, which
   __udp_disconnect leaves), which sock_diag tells with port 0: it takes an
   IPv6 datagram from that address alone, of any port, and any IPv4 one; after
   an IPv4-mapped peer it takes no IPv6 one. The next bind has it too, and the
   next connect another. That address ranks a socket as a device does, and
   among equals the one that got its address last, by bind or by a connect or
   disconnect that changed it, comes first (udp_lib_rehash). Which datagrams
   come is what is read without waiting, as the loopback delivers before
   sendto returns. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define SO_BINDTOIFINDEX_ 62

static long result(long r) { return r < 0 ? -errno : r; }
static struct sockaddr_in6 six(const char *ip, int port) {
    struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)port)};
    inet_pton(AF_INET6, ip, &a.sin6_addr);
    return a;
}
static struct sockaddr_in four(const char *ip, int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}
static int made6(const char *ip, int port, int device) {
    const int one = 1;
    int s = socket(AF_INET6, SOCK_DGRAM, 0);
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (device) setsockopt(s, SOL_SOCKET, SO_BINDTOIFINDEX_, &device, sizeof device);
    struct sockaddr_in6 a = six(ip, port);
    if (port && bind(s, (void *)&a, sizeof a)) printf("bind: %d\n", -errno);
    return s;
}
static long join6(int s, const char *ip, int port) {
    struct sockaddr_in6 a = six(ip, port);
    return result(connect(s, (void *)&a, sizeof a));
}
static long leave(int s, socklen_t size) {
    struct sockaddr_storage none;
    memset(&none, 0, sizeof none);
    return result(connect(s, (void *)&none, size));
}
/* The senders: of two IPv6 addresses, the first twice, and of IPv4. */
static int senders[4];
static int asked = 4;
/* Which of `names`' sockets a datagram of each sender to `port` reaches, of
   the first `asked`. */
static void reach(const char *label, int port, const int *sockets, const char *const *names, int count) {
    const char *const from[4] = {"::1", "::1 again", "2001:db8::1", "127.0.0.1"};
    printf("%s:", label);
    for (int i = 0; i < asked; i++) {
        struct sockaddr_in6 to = six("::1", port);
        struct sockaddr_in to4 = four("127.0.0.1", port);
        long r = i < 3 ? sendto(senders[i], "x", 1, 0, (void *)&to, sizeof to)
                       : sendto(senders[i], "x", 1, 0, (void *)&to4, sizeof to4);
        printf(" %s%s", from[i], r == 1 ? "->" : "!");
        char byte[8];
        int any = 0;
        for (int k = 0; k < count; k++)
            if (recv(sockets[k], byte, sizeof byte, MSG_DONTWAIT) == 1) printf("%s", names[k]), any = 1;
        if (!any) printf("none");
        printf(";");
        /* What nobody took leaves an error. */
        int error;
        socklen_t len = sizeof error;
        getsockopt(senders[i], SOL_SOCKET, SO_ERROR, &error, &len);
    }
    printf("\n");
}
static void names(int s, const char *label) {
    struct sockaddr_in6 a;
    char text[64] = "-";
    socklen_t len = sizeof a;
    memset(&a, 0, sizeof a);
    long own = result(getsockname(s, (void *)&a, &len));
    if (a.sin6_family == AF_INET6) inet_ntop(AF_INET6, &a.sin6_addr, text, sizeof text);
    int port = ntohs(a.sin6_port);
    len = sizeof a;
    long peer = result(getpeername(s, (void *)&a, &len));
    int device = -1;
    len = sizeof device;
    getsockopt(s, SOL_SOCKET, SO_BINDTOIFINDEX_, &device, &len);
    printf("%s: name=%ld %s %s peer=%ld device=%d\n", label, own, text, port == 0 ? "0" : port < 9000 ? "its port" : "a port",
           peer, device);
}
/* What sock_diag tells of the UDP sockets of `family` bound to `port`. */
static void diag(int family, int port, const char *label) {
    int fd = socket(AF_NETLINK, SOCK_RAW, 4);
    struct {
        unsigned len;
        unsigned short type, flags;
        unsigned seq, pid;
        unsigned char family, protocol, ext, pad;
        unsigned states;
        unsigned short sport, dport;
        unsigned src[4], dst[4], device, cookie[2];
    } q = {72, 20, 0x301, 1, 0, (unsigned char)family, IPPROTO_UDP, 0, 0, ~0u, htons((unsigned short)port), 0, {0}, {0}, 0, {0}};
    static unsigned char buf[16384];
    send(fd, &q, sizeof q, 0);
    for (int done = 0; !done;) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) break;
        long n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0) break;
        for (long at = 0; at + 16 <= n;) {
            unsigned len;
            unsigned short type, dport;
            memcpy(&len, buf + at, 4);
            memcpy(&type, buf + at + 4, 2);
            if (len < 16 || type == 3 || type == 2) {
                done = 1;
                break;
            }
            const unsigned char *m = buf + at + 16;
            char src[64], dst[64];
            unsigned device;
            memcpy(&dport, m + 6, 2);
            memcpy(&device, m + 40, 4);
            inet_ntop(m[0], m + 8, src, sizeof src);
            inet_ntop(m[0], m + 24, dst, sizeof dst);
            printf("%s: state=%u %s -> %s %s if=%u\n", label, m[1], src, dst, dport ? "a port" : "0", device);
            at += (len + 3) & ~3u;
        }
    }
    close(fd);
}
/* The one socket a datagram from `from` and `port` to ::1 and 1003 finds. */
static void exact(const char *from, int port, const char *label) {
    int fd = socket(AF_NETLINK, SOCK_RAW, 4);
    struct {
        unsigned len;
        unsigned short type, flags;
        unsigned seq, pid;
        unsigned char family, protocol, ext, pad;
        unsigned states;
        unsigned short sport, dport;
        unsigned char src[16], dst[16];
        unsigned device, cookie[2];
    } q = {72, 20, 1, 1, 0, AF_INET6, IPPROTO_UDP, 0, 0, ~0u, htons((unsigned short)port), htons(1003), {0}, {0}, 0, {~0u, ~0u}};
    inet_pton(AF_INET6, from, q.src);
    inet_pton(AF_INET6, "::1", q.dst);
    static unsigned char buf[4096];
    send(fd, &q, sizeof q, 0);
    long n = recv(fd, buf, sizeof buf, 0);
    int error = 0;
    unsigned short type = 0;
    if (n >= 20) memcpy(&type, buf + 4, 2), memcpy(&error, buf + 16, 4);
    printf("%s: %s\n", label, type == 20 ? "found" : strerror(-error));
    close(fd);
}
static void add_address(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW, 0);
    struct {
        unsigned len;
        unsigned short type, flags;
        unsigned seq, pid;
        unsigned char family, prefix, ifaflags, scope;
        unsigned index;
        unsigned short alen, akind;
        unsigned char ip[16];
    } q = {44, 20, 0x605, 1, 0, AF_INET6, 128, 2, 0, 1, 20, 2, {0}};
    inet_pton(AF_INET6, "2001:db8::1", q.ip);
    unsigned char buf[4096];
    int error = 1;
    send(fd, &q, sizeof q, 0);
    if (recv(fd, buf, sizeof buf, 0) >= 20) memcpy(&error, buf + 16, 4);
    printf("add 2001:db8::1: %d\n", error);
    close(fd);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "udp-disconnect")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int lo = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq up = {.ifr_name = "lo", .ifr_flags = IFF_UP};
    printf("up lo=%ld\n", result(ioctl(lo, SIOCSIFFLAGS, &up)));
    add_address();
    senders[0] = made6("::1", 2000, 0);
    senders[1] = made6("::1", 2001, 0);
    senders[2] = made6("2001:db8::1", 2002, 0);
    senders[3] = lo;
    struct sockaddr_in at4 = four("127.0.0.1", 2003);
    bind(lo, (void *)&at4, sizeof at4);

    const char *const one[] = {"it"};
    int s = made6("::", 1003, 0);
    reach("bound", 1003, &s, one, 1);
    printf("connect=%ld\n", join6(s, "::1", 2000));
    reach("connected", 1003, &s, one, 1);
    diag(AF_INET6, 1003, "connected");
    printf("disconnect=%ld\n", leave(s, sizeof(struct sockaddr_in6)));
    names(s, "disconnected");
    reach("disconnected", 1003, &s, one, 1);
    diag(AF_INET6, 1003, "disconnected");
    exact("::1", 5, "exact from ::1");
    exact("2001:db8::1", 5, "exact from 2001:db8::1");
    printf("disconnect again=%ld\n", leave(s, sizeof(struct sockaddr_in6)));
    reach("disconnected twice", 1003, &s, one, 1);
    printf("send=%ld\n", result(send(s, "x", 1, 0)));
    printf("connect to none=%ld\n", join6(s, "2001:db8:9::1", 5));
    reach("a failed connect", 1003, &s, one, 1);
    printf("connect=%ld\n", join6(s, "2001:db8::1", 2002));
    printf("disconnect=%ld\n", leave(s, sizeof(struct sockaddr_in6)));
    reach("disconnected from the other", 1003, &s, one, 1);
    printf("connect=%ld\n", join6(s, "::ffff:127.0.0.1", 2003));
    reach("connected to IPv4", 1003, &s, one, 1);
    printf("disconnect=%ld\n", leave(s, sizeof(struct sockaddr_in6)));
    names(s, "disconnected from IPv4");
    reach("disconnected from IPv4", 1003, &s, one, 1);
    diag(AF_INET6, 1003, "disconnected from IPv4");
    close(s);

    /* Bound by connect alone: it is unbound then, and keeps the address. */
    s = made6("::", 0, 0);
    printf("connect=%ld\n", join6(s, "::1", 2000));
    printf("disconnect=%ld\n", leave(s, sizeof(struct sockaddr_in6)));
    names(s, "not bound");
    struct sockaddr_in6 a = six("::", 1003);
    printf("bind=%ld\n", result(bind(s, (void *)&a, sizeof a)));
    reach("bound again", 1003, &s, one, 1);
    close(s);

    /* A device, which goes, and an address, which stays. */
    s = made6("::1", 1003, 1);
    names(s, "bound to lo");
    printf("connect=%ld\n", join6(s, "::1", 2000));
    printf("disconnect=%ld\n", leave(s, sizeof(struct sockaddr_in6)));
    names(s, "disconnected from lo");
    diag(AF_INET6, 1003, "disconnected from lo");
    close(s);
    s = socket(AF_INET, SOCK_DGRAM, 0);
    const int device = 1;
    struct sockaddr_in any = four("0.0.0.0", 1003), peer = four("127.0.0.1", 2003);
    printf("device=%ld", result(setsockopt(s, SOL_SOCKET, SO_BINDTOIFINDEX_, &device, sizeof device)));
    printf(" bind=%ld", result(bind(s, (void *)&any, sizeof any)));
    printf(" connect=%ld\n", result(connect(s, (void *)&peer, sizeof peer)));
    printf("disconnect=%ld\n", leave(s, sizeof(struct sockaddr_in)));
    int left = -1;
    socklen_t len = sizeof left;
    getsockopt(s, SOL_SOCKET, SO_BINDTOIFINDEX_, &left, &len);
    printf("device=%d\n", left);
    diag(AF_INET, 1003, "IPv4 disconnected");
    close(s);

    /* Ranks: the one that keeps ::1 before another, and as one bound to lo,
       where the last bound comes first. For IPv4 that would hang on the
       CPU, as only the one that keeps an address notes the CPU of what it
       takes (sk_incoming_cpu_update), and ranks higher on it. */
    asked = 3;
    const char *const two[] = {"first", "second"};
    for (int other = 0; other < 2; other++)
        for (int order = 0; order < 2; order++) {
            int p[2];
            for (int i = 0; i < 2; i++) {
                int keeps = i == order;
                p[i] = made6("::", 1003, keeps ? 0 : other);
                if (keeps) join6(p[i], "::1", 2000), leave(p[i], sizeof(struct sockaddr_in6));
            }
            char label[64];
            snprintf(label, sizeof label, "%s, %s", other ? "with one bound to lo" : "with another",
                     order ? "keeping second" : "keeping first");
            reach(label, 1003, p, two, 2);
            close(p[0]), close(p[1]);
        }
    /* IPv4's, by the order alone: the one disconnected last is the last. */
    asked = 4;
    for (int order = 0; order < 2; order++) {
        int p[2];
        const int yes = 1;
        for (int i = 0; i < 2; i++) {
            p[i] = socket(AF_INET, SOCK_DGRAM, 0);
            setsockopt(p[i], SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
            bind(p[i], (void *)&any, sizeof any);
        }
        connect(p[order], (void *)&peer, sizeof peer);
        leave(p[order], sizeof(struct sockaddr_in));
        reach(order ? "IPv4, the second disconnected" : "IPv4, the first disconnected", 1003, p, two, 2);
        close(p[0]), close(p[1]);
    }
    return 0;
}
