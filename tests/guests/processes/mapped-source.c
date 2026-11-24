/* What an IPv6 socket bound to an IPv4-mapped broadcast or multicast
   address does to IPv4 (so as root, in a network namespace of its own
   with only its loopback up): __inet6_bind keeps the address as the
   socket's IPv4 source (inet_saddr), where IPv4's inet_bind drops it, so
   the route to 127.0.0.1 from it fails (ip_route_output_key_hash_rcu): a
   group's and the limited broadcast address's with EINVAL, the loopback's
   subnet broadcast address's, which no device has, with ENETUNREACH. UDP's
   sendto and connect fail so, and the socket stays unconnected; TCP's
   connect fails so (tcp_v4_connect). The bind succeeds and the name stays. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static long result(long r) { return r < 0 ? -errno : r; }

static struct sockaddr_in6 at(const char *ip, int port) {
    struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)port)};
    inet_pton(AF_INET6, ip, &a.sin6_addr);
    return a;
}
static void name(int fd, const char *label) {
    struct sockaddr_in6 a = {0};
    socklen_t len = sizeof a;
    long r = result(getsockname(fd, (void *)&a, &len));
    char ip[64] = "-";
    inet_ntop(AF_INET6, &a.sin6_addr, ip, sizeof ip);
    printf("%s: getsockname=%ld [%s]:%u\n", label, r, ip, ntohs(a.sin6_port));
}
/* A socket of `type` bound to `ip` port `port`, which sends to and
   connects to 127.0.0.1 port 9. */
static void from(int type, const char *ip, int port, const char *label) {
    int fd = socket(AF_INET6, type, 0);
    struct sockaddr_in6 bound = at(ip, port), to = at("::ffff:127.0.0.1", 9);
    printf("%s: bind=%ld\n", label, result(bind(fd, (void *)&bound, sizeof bound)));
    name(fd, label);
    if (type == SOCK_DGRAM)
        printf("%s: sendto=%ld\n", label, result(sendto(fd, "x", 1, 0, (void *)&to, sizeof to)));
    printf("%s: connect=%ld\n", label, result(connect(fd, (void *)&to, sizeof to)));
    name(fd, label);
    if (type == SOCK_DGRAM) printf("%s: send=%ld\n", label, result(send(fd, "x", 1, 0)));
    close(fd);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "mapped-source")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq lo = {0};
    strcpy(lo.ifr_name, "lo");
    ioctl(s, SIOCGIFFLAGS, &lo);
    lo.ifr_flags |= IFF_UP;
    printf("up lo=%ld\n", result(ioctl(s, SIOCSIFFLAGS, &lo)));
    from(SOCK_DGRAM, "::ffff:224.0.0.251", 7200, "udp mapped group");
    from(SOCK_DGRAM, "::ffff:127.255.255.255", 7201, "udp mapped broadcast");
    from(SOCK_DGRAM, "::ffff:255.255.255.255", 7202, "udp mapped limited");
    from(SOCK_STREAM, "::ffff:224.0.0.251", 7203, "tcp mapped group");
    from(SOCK_STREAM, "::ffff:127.255.255.255", 7204, "tcp mapped broadcast");
    from(SOCK_STREAM, "::ffff:255.255.255.255", 7205, "tcp mapped limited");
    return 0;
}
