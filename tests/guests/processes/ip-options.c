/* The `int` options of the level IPPROTO_IP, set and read in other sizes than
   an int's (do_ip_setsockopt, do_ip_getsockopt): of fewer than 4 bytes the
   first is the value, and of none it is 0, without a look at the pointer;
   read in room for fewer, a value one byte holds is one byte. IP_TOS of a
   datagram socket keeps its two bits of ECN, of a stream socket its own
   (__ip_sock_set_tos), and a new one sets SO_PRIORITY. Of IPv4's and IPv6's
   sockets, in a network namespace of its own (so as root). */
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static long result(long r) { return r < 0 ? -errno : r; }
static void sized(int fd, int option, const unsigned char *bytes, socklen_t len) {
    long r = result(setsockopt(fd, IPPROTO_IP, option, bytes, len));
    int value = -1, priority = -1;
    socklen_t size = sizeof value;
    long g = result(getsockopt(fd, IPPROTO_IP, option, &value, &size));
    socklen_t other = sizeof priority;
    getsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, &other);
    printf("  %d bytes: set=%ld get=%ld value=%#x size=%u priority=%d\n", (int)len, r, g, (unsigned)value, size, priority);
}
static void room(int fd, int option, socklen_t len) {
    unsigned char bytes[8];
    memset(bytes, 0xee, sizeof bytes);
    long r = result(getsockopt(fd, IPPROTO_IP, option, bytes, &len));
    printf("  room: get=%ld size=%u", r, len);
    for (int i = 0; i < 5; i++) printf(" %02x", bytes[i]);
    printf("\n");
}
static void options(int family, int type, const char *label) {
    int fd = socket(family, type, 0);
    static const unsigned char full[8] = {0x13, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}, big[8] = {0x10, 1, 0, 0}, one[8] = {0x08, 0xff, 0xff, 0xff},
                               minus[8] = {0xff, 0xff, 0xff, 0xff};
    printf("%s\n", label);
    sized(fd, IP_TOS, full, 4);
    sized(fd, IP_TOS, full, 8);
    for (socklen_t n = 0; n < 5; n++) sized(fd, IP_TOS, one, n);
    sized(fd, IP_TOS, big, 4);
    sized(fd, IP_TOS, big, 4);
    sized(fd, IP_TOS, minus, 4);
    sized(fd, IP_TOS, minus, 1);
    sized(fd, IP_TOS, full, (socklen_t)-1);
    printf("  no pointer: %ld", result(setsockopt(fd, IPPROTO_IP, IP_TOS, NULL, 0)));
    printf(" %ld", result(setsockopt(fd, IPPROTO_IP, IP_TOS, NULL, 1)));
    printf(" %ld\n", result(setsockopt(fd, IPPROTO_IP, IP_TOS, NULL, 4)));
    sized(fd, IP_TOS, full, 1);
    for (socklen_t n = 0; n < 6; n++) room(fd, IP_TOS, n);
    /* A priority of its own lasts until another type of service. */
    const int five = 5;
    setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &five, sizeof five);
    sized(fd, IP_TOS, full, 1);
    sized(fd, IP_TOS, one, 1);
    close(fd);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "ip-options")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    options(AF_INET, SOCK_DGRAM, "IPv4 datagram");
    options(AF_INET, SOCK_STREAM, "IPv4 stream");
    options(AF_INET6, SOCK_DGRAM, "IPv6 datagram");
    options(AF_INET6, SOCK_STREAM, "IPv6 stream");
    return 0;
}
