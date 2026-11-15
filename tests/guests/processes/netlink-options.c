/* The SOL_NETLINK socket options of NETLINK_ROUTE sockets, each case in a
   network namespace of its own (so as root): what setsockopt and
   getsockopt take and give for each flag, the NETLINK_PKTINFO control
   message of a receive, and NETLINK_NO_ENOBUFS on a socket whose receive
   buffer overflows. Only errno values, flags and the bytes of messages are
   printed, never ports or counts that depend on the kernel's buffer
   accounting. */
#define _GNU_SOURCE
#include <errno.h>
#include <net/if.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define SOL_NETLINK_ 270
#define NETLINK_ROUTE_ 0
#define PKTINFO 3
#define BROADCAST_ERROR 4
#define NO_ENOBUFS 5
#define CAP_ACK 10
#define EXT_ACK 11
#define STRICT_CHK 12
#define ADD_MEMBERSHIP 1

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

static long result(long r) { return r < 0 ? -errno : r; }

static int route_socket(void) { return socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE_); }

/* Asks for RTM_NEWADDR of 10.9.<i / 250>.<i % 250 + 1>/32 on lo, with no
   acknowledgement. */
static void add_address(int fd, int i) {
    struct {
        struct nl_header h;
        unsigned char family, prefix, flags, scope;
        unsigned index;
        unsigned short len, type;
        unsigned char address[4];
    } request = {
        .h = {.len = sizeof request, .type = 20, .flags = 0x601, .seq = (unsigned)i + 1},
        .family = AF_INET,
        .prefix = 32,
        .index = 1,
        .len = 8,
        .type = 2, /* IFA_LOCAL */
        .address = {10, 9, (unsigned char)(i / 250), (unsigned char)(i % 250 + 1)},
    };
    struct nl_address kernel = {.family = AF_NETLINK};
    sendto(fd, &request, sizeof request, 0, (void *)&kernel, sizeof kernel);
}

static void lo_up(void) {
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr = {0};
    strcpy(ifr.ifr_name, "lo");
    ifr.ifr_flags = IFF_UP;
    printf("lo up=%ld\n", result(ioctl(udp, SIOCSIFFLAGS, &ifr)));
    close(udp);
}

static void flags_case(void) {
    int fd = route_socket();
    static const int names[] = {PKTINFO, BROADCAST_ERROR, NO_ENOBUFS, CAP_ACK, EXT_ACK, STRICT_CHK};
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        int name = names[i], value = -1, one = 1, seven = 7, zero = 0;
        socklen_t len = sizeof value;
        long got = result(getsockopt(fd, SOL_NETLINK_, name, &value, &len));
        printf("option %d: default=%ld value=%d len=%u", name, got, value, len);
        printf(" set1=%ld", result(setsockopt(fd, SOL_NETLINK_, name, &one, sizeof one)));
        value = -1, len = sizeof value;
        getsockopt(fd, SOL_NETLINK_, name, &value, &len);
        printf(" ->%d", value);
        printf(" set0=%ld", result(setsockopt(fd, SOL_NETLINK_, name, &zero, sizeof zero)));
        value = -1, len = sizeof value;
        getsockopt(fd, SOL_NETLINK_, name, &value, &len);
        printf(" ->%d", value);
        printf(" set7=%ld", result(setsockopt(fd, SOL_NETLINK_, name, &seven, sizeof seven)));
        value = -1, len = sizeof value;
        getsockopt(fd, SOL_NETLINK_, name, &value, &len);
        printf(" ->%d", value);
        /* Shorter than an int is 0, read or not. */
        printf(" short=%ld", result(setsockopt(fd, SOL_NETLINK_, name, &one, 2)));
        value = -1, len = sizeof value;
        getsockopt(fd, SOL_NETLINK_, name, &value, &len);
        printf(" ->%d", value);
        setsockopt(fd, SOL_NETLINK_, name, &one, sizeof one);
        printf(" empty-bad=%ld", result(setsockopt(fd, SOL_NETLINK_, name, (void *)8, 0)));
        value = -1, len = sizeof value;
        getsockopt(fd, SOL_NETLINK_, name, &value, &len);
        printf(" ->%d", value);
        printf(" bad=%ld", result(setsockopt(fd, SOL_NETLINK_, name, (void *)8, 4)));
        printf(" long=%ld", result(setsockopt(fd, SOL_NETLINK_, name, (long[]){1}, sizeof(long))));
        long wide = -1;
        len = sizeof wide;
        got = result(getsockopt(fd, SOL_NETLINK_, name, &wide, &len));
        printf(" get-long=%ld len=%u low=%d", got, len, (int)wide);
        short tiny = -1;
        len = sizeof tiny;
        got = result(getsockopt(fd, SOL_NETLINK_, name, &tiny, &len));
        printf(" get-short=%ld len=%u", got, len);
        len = (socklen_t)-1;
        got = result(getsockopt(fd, SOL_NETLINK_, name, &value, &len));
        printf(" get-negative=%ld", got);
        len = sizeof value;
        printf(" get-bad=%ld\n", result(getsockopt(fd, SOL_NETLINK_, name, (void *)8, &len)));
    }
    /* Options netlink has not, and other levels. */
    static const int others[] = {0, 6, 7, 13, 14, 100};
    for (size_t i = 0; i < sizeof others / sizeof others[0]; i++) {
        int value = 1;
        socklen_t len = sizeof value;
        printf("other %d: set=%ld get=%ld\n", others[i],
               result(setsockopt(fd, SOL_NETLINK_, others[i], &value, sizeof value)),
               result(getsockopt(fd, SOL_NETLINK_, others[i], &value, &len)));
    }
    int value = 1;
    socklen_t len = sizeof value;
    printf("SOL_IP: set=%ld get=%ld\n", result(setsockopt(fd, 0, PKTINFO, &value, sizeof value)),
           result(getsockopt(fd, 0, PKTINFO, &value, &len)));
    len = (socklen_t)-1;
    printf("unknown negative get=%ld\n", result(getsockopt(fd, SOL_NETLINK_, 100, &value, &len)));
    printf("membership short=%ld\n", result(setsockopt(fd, SOL_NETLINK_, ADD_MEMBERSHIP, &value, 2)));
}

/* Receives one datagram with a control buffer of `room` bytes (none for 0,
   or a NULL one of `room` bytes when `null`), and prints its flags, the
   control length and the control message. */
static void receive(int fd, size_t room, int null, int flags, const char *label) {
    unsigned char data[4096];
    unsigned char control[64];
    memset(control, 0xee, sizeof control);
    struct nl_address from = {0};
    struct iovec iov = {data, sizeof data};
    struct msghdr msg = {
        .msg_name = &from,
        .msg_namelen = sizeof from,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = null ? NULL : control,
        .msg_controllen = room,
    };
    long n = result(recvmsg(fd, &msg, MSG_DONTWAIT | flags));
    printf("%s: n=%s", label, n > 0 ? "some" : n == 0 ? "0" : "");
    if (n < 0) {
        printf("%ld\n", n);
        return;
    }
    struct nl_header *h = (void *)data;
    printf(" type=%u from-kernel=%d groups=%#x flags=%#x controllen=%zu", h->type, from.pid == 0, from.groups,
           msg.msg_flags, (size_t)msg.msg_controllen);
    if (!null && room >= sizeof(struct cmsghdr)) {
        struct cmsghdr *cm = (void *)control;
        printf(" cmsg len=%zu level=%d type=%d", (size_t)cm->cmsg_len, cm->cmsg_level, cm->cmsg_type);
        if (cm->cmsg_len >= CMSG_LEN(4)) {
            unsigned group;
            memcpy(&group, CMSG_DATA(cm), 4);
            printf(" group=%u", group);
        }
        printf(" after=%#x", control[room < sizeof control ? room : sizeof control - 1]);
    }
    printf("\n");
}

static void drain(int fd) {
    char buf[8192];
    while (recv(fd, buf, sizeof buf, MSG_DONTWAIT) >= 0) {
    }
}

static void pktinfo_case(void) {
    /* Before the socket joins: lo's 127.0.0.1 is a notification too. */
    lo_up();
    int mon = route_socket(), ctl = route_socket();
    struct nl_address members = {.family = AF_NETLINK, .groups = 1u << 4}; /* RTNLGRP_IPV4_IFADDR */
    bind(mon, (void *)&members, sizeof members);
    int one = 1, zero = 0;
    /* Without the option, no control message. */
    add_address(ctl, 0);
    receive(mon, 64, 0, 0, "off");
    printf("pktinfo=%ld\n", result(setsockopt(mon, SOL_NETLINK_, PKTINFO, &one, sizeof one)));
    static const struct {
        size_t room;
        int null, flags;
        const char *label;
    } tries[] = {
        {64, 0, 0, "room 64"},
        {64, 0, MSG_PEEK, "peek"},
        {64, 0, MSG_CMSG_CLOEXEC, "cloexec"},
        {24, 0, 0, "room 24"},
        {20, 0, 0, "room 20"},
        {19, 0, 0, "room 19"},
        {16, 0, 0, "room 16"},
        {15, 0, 0, "room 15"},
        {0, 0, 0, "room 0"},
        {64, 1, 0, "null 64"},
    };
    for (size_t i = 0; i < sizeof tries / sizeof tries[0]; i++) {
        /* After the peek, one is left over, so each try reads the one
           before its own. */
        add_address(ctl, (int)i + 1);
        receive(mon, tries[i].room, tries[i].null, tries[i].flags, tries[i].label);
    }
    drain(mon);
    /* A reply of the kernel to the socket itself went to no group. */
    struct {
        struct nl_header h;
        unsigned char family, pad[3];
    } dump = {.h = {.len = sizeof dump, .type = 22, .flags = 0x301, .seq = 99}, .family = AF_INET};
    struct nl_address kernel = {.family = AF_NETLINK};
    sendto(mon, &dump, sizeof dump, 0, (void *)&kernel, sizeof kernel);
    receive(mon, 64, 0, 0, "dump");
    drain(mon);
    /* A datagram another socket sends to its port, naming group 3. */
    struct nl_address name = {0};
    socklen_t name_len = sizeof name;
    getsockname(mon, (void *)&name, &name_len);
    struct nl_address to = {.family = AF_NETLINK, .pid = name.pid, .groups = 1u << 2};
    struct nl_header hello = {.len = sizeof hello, .type = 0x20, .seq = 7};
    printf("send=%ld\n", result(sendto(ctl, &hello, sizeof hello, 0, (void *)&to, sizeof to)));
    receive(mon, 64, 0, 0, "unicast");
    /* Off again. */
    setsockopt(mon, SOL_NETLINK_, PKTINFO, &zero, sizeof zero);
    add_address(ctl, 40);
    receive(mon, 64, 0, 0, "off again");
}

/* Fills a socket with notifications it has too little room for, then
   reads it till it is empty: whether the first receive gave ENOBUFS, and
   whether any message came. */
static void overflow(int no_enobufs, const char *label, int base) {
    int mon = route_socket(), ctl = route_socket();
    int small = 1;
    setsockopt(mon, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
    if (no_enobufs) setsockopt(mon, SOL_NETLINK_, NO_ENOBUFS, &no_enobufs, sizeof no_enobufs);
    struct nl_address members = {.family = AF_NETLINK, .groups = 1u << 4};
    bind(mon, (void *)&members, sizeof members);
    for (int i = 0; i < 200; i++) add_address(ctl, base + i);
    char buf[8192];
    long first = result(recv(mon, buf, sizeof buf, MSG_DONTWAIT));
    int messages = first > 0, errors = first == -ENOBUFS;
    long last;
    while ((last = result(recv(mon, buf, sizeof buf, MSG_DONTWAIT))) > 0 || last == -ENOBUFS) {
        if (last > 0) messages++;
        else errors++;
    }
    int error = -1;
    socklen_t len = sizeof error;
    getsockopt(mon, SOL_SOCKET, SO_ERROR, &error, &len);
    printf("%s: first=%s messages=%d later-enobufs=%d last=%ld so_error=%d\n", label,
           first > 0 ? "message" : first == -ENOBUFS ? "ENOBUFS" : "other", messages > 0,
           errors - (first == -ENOBUFS), last, error);
    /* Once emptied, the next notification comes. */
    add_address(ctl, base + 200);
    long next = result(recv(mon, buf, sizeof buf, MSG_DONTWAIT));
    printf("%s: next=%s\n", label, next > 0 ? "message" : next == -ENOBUFS ? "ENOBUFS" : "other");
    close(mon);
    close(ctl);
}

static void no_enobufs_case(void) {
    lo_up();
    overflow(0, "default", 0);
    overflow(1, "no-enobufs", 250);
    /* Congested, then NETLINK_NO_ENOBUFS: the pending error stays, and the
       socket takes notifications again. */
    int mon = route_socket(), ctl = route_socket();
    int small = 1, one = 1;
    setsockopt(mon, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
    struct nl_address members = {.family = AF_NETLINK, .groups = 1u << 4};
    bind(mon, (void *)&members, sizeof members);
    for (int i = 0; i < 200; i++) add_address(ctl, 500 + i);
    printf("set=%ld\n", result(setsockopt(mon, SOL_NETLINK_, NO_ENOBUFS, &one, sizeof one)));
    char buf[8192];
    printf("after set: first=%ld\n", result(recv(mon, buf, sizeof buf, MSG_DONTWAIT)));
    drain(mon);
    add_address(ctl, 750);
    long next = result(recv(mon, buf, sizeof buf, MSG_DONTWAIT));
    printf("after set: next=%s\n", next > 0 ? "message" : "other");
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    const char *mode = argv[1];
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        printf("unshare=%ld\n", result(syscall(SYS_unshare, CLONE_NEWNET)));
        if (!strcmp(mode, "netlink-option-flags")) flags_case();
        else if (!strcmp(mode, "netlink-pktinfo")) pktinfo_case();
        else if (!strcmp(mode, "netlink-no-enobufs")) no_enobufs_case();
        else return 2;
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    printf("child status=%#x\n", status);
    return 0;
}
