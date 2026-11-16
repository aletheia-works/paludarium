/* The SOL_NETLINK socket options of NETLINK_ROUTE sockets, each case in a
   network namespace of its own (so as root): what setsockopt and
   getsockopt take and give for each flag, the NETLINK_PKTINFO control
   message of a receive, and NETLINK_NO_ENOBUFS on a socket whose receive
   buffer overflows. Only errno values, flags and the bytes of messages are
   printed, never ports or counts that depend on the kernel's buffer
   accounting. */
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
#include <sys/uio.h>
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
#define LISTEN_ALL_NSID 8

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
/* One bound to a port of its own: an unbound one, port 0, hears no
   notification (do_one_broadcast passes over the sender's port, 0). */
static int bound_socket(void) {
    int fd = route_socket();
    struct nl_address any = {.family = AF_NETLINK};
    bind(fd, (void *)&any, sizeof any);
    return fd;
}

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
    static const int names[] = {PKTINFO, BROADCAST_ERROR, NO_ENOBUFS, LISTEN_ALL_NSID, CAP_ACK, EXT_ACK, STRICT_CHK};
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


/* Peer namespace IDs. */
#define RTM_NEWNSID 88
#define RTM_DELNSID 89
#define RTM_GETNSID 90
#define NETNSA_NSID 1
#define NETNSA_PID 2
#define NETNSA_FD 3
#define NETNSA_TARGET_NSID 4
#define NETNSA_CURRENT_NSID 5
#define RTNLGRP_NSID 28

struct request {
    struct nl_header h;
    unsigned char body[256];
};
/* Starts a request of `type` with a 4-byte rtgenmsg. */
static void begin(struct request *r, unsigned short type, unsigned short flags, unsigned seq) {
    memset(r, 0, sizeof *r);
    r->h.len = sizeof r->h + 4;
    r->h.type = type;
    r->h.flags = flags;
    r->h.seq = seq;
}
static void put(struct request *r, unsigned short type, const void *value, unsigned short len) {
    unsigned char *at = (unsigned char *)r + r->h.len;
    unsigned short total = 4 + len;
    memcpy(at, &total, 2);
    memcpy(at + 2, &type, 2);
    memcpy(at + 4, value, len);
    r->h.len += (total + 3) & ~3u;
}
static void put32(struct request *r, unsigned short type, int value) { put(r, type, &value, 4); }
static void send_request(int fd, struct request *r) {
    struct nl_address kernel = {.family = AF_NETLINK};
    sendto(fd, r, r->h.len, 0, (void *)&kernel, sizeof kernel);
}

/* Prints each datagram waiting on `fd`, each message of it, and the
   control messages that came with it. */
static void show(int fd, const char *label) {
    unsigned own = 0;
    struct nl_address name = {0};
    socklen_t name_len = sizeof name;
    getsockname(fd, (void *)&name, &name_len);
    own = name.pid;
    for (;;) {
        unsigned char data[8192];
        unsigned char control[128];
        memset(control, 0, sizeof control);
        struct iovec iov = {data, sizeof data};
        struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof control};
        long n = recvmsg(fd, &msg, MSG_DONTWAIT);
        if (n < 0) {
            if (errno != EAGAIN) printf("%s: recv=%d\n", label, -errno);
            break;
        }
        printf("%s: datagram flags=%#x", label, msg.msg_flags);
        for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
            int value = 0;
            if (cm->cmsg_len >= CMSG_LEN(4)) memcpy(&value, CMSG_DATA(cm), 4);
            printf(" cmsg(%d,%d)=%d", cm->cmsg_level, cm->cmsg_type, value);
        }
        printf("\n");
        for (long at = 0; at + 16 <= n;) {
            struct nl_header *h = (void *)(data + at);
            if (h->len < 16 || at + h->len > n) break;
            printf("  type=%u flags=%#x seq=%u own=%d", h->type, h->flags, h->seq, h->pid == own);
            unsigned char *body = data + at + 16;
            long body_len = h->len - 16;
            long attrs = -1;
            if (h->type == 2) {
                int error;
                memcpy(&error, body, 4);
                printf(" error=%d", error);
                /* With NETLINK_CAP_ACK, the request's header alone. */
                if (h->flags & 0x200) attrs = 4 + 16;
            } else if (h->type == 3) {
                int error;
                memcpy(&error, body, 4);
                printf(" done=%d", error);
                if (h->flags & 0x200) attrs = 4;
            } else if (h->type == RTM_NEWNSID || h->type == RTM_DELNSID) {
                attrs = 4;
            } else if (h->type == 20 || h->type == 21) {
                printf(" family=%u prefix=%u index=%u", body[0], body[1], *(unsigned *)(body + 4));
                attrs = 8;
            } else if (h->type == 16) {
                printf(" index=%d up=%u", *(int *)(body + 4), *(unsigned *)(body + 8) & 1);
                attrs = 16;
            }
            while (attrs >= 0 && attrs + 4 <= body_len) {
                unsigned short alen, atype;
                memcpy(&alen, body + attrs, 2);
                memcpy(&atype, body + attrs + 2, 2);
                if (alen < 4 || attrs + alen > body_len) break;
                unsigned char *value = body + attrs + 4;
                if (h->type == 2 || h->type == 3) {
                    if (atype == 1) printf(" msg=\"%.*s\"", alen - 5, value);
                    if (atype == 2) printf(" offset=%u", *(unsigned *)value);
                } else if (h->type == RTM_NEWNSID || h->type == RTM_DELNSID) {
                    printf(" nsa%u=%d", atype, *(int *)value);
                } else if (h->type == 16) {
                    if (atype == 3) printf(" name=%s", value);
                    if (atype == 46) printf(" netnsid=%d", *(int *)value);
                } else if (atype == 2 /* IFA_LOCAL */ && alen == 8) {
                    printf(" local=%u.%u.%u.%u", value[0], value[1], value[2], value[3]);
                } else if (atype == 10 /* IFA_TARGET_NETNSID */) {
                    printf(" netnsid=%d", *(int *)value);
                }
                attrs += (alen + 3) & ~3;
            }
            printf("\n");
            at += (h->len + 3) & ~3u;
        }
    }
}

static int acked_socket(void) {
    int fd = route_socket(), one = 1;
    setsockopt(fd, SOL_NETLINK_, EXT_ACK, &one, sizeof one);
    setsockopt(fd, SOL_NETLINK_, CAP_ACK, &one, sizeof one);
    return fd;
}

/* A child in a network namespace of its own, which acts on commands
   from a pipe: 'u' brings lo up, a digit adds 10.7.0.<digit>/32. It
   writes a byte back when done. */
struct peer {
    pid_t pid;
    int command, done;
};
static struct peer peer_start(void) {
    int to[2], from[2];
    if (pipe(to) || pipe(from)) exit(91);
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        close(to[1]);
        close(from[0]);
        char c = syscall(SYS_unshare, CLONE_NEWNET) == 0 ? 'r' : 'x';
        int fd = route_socket();
        write(from[1], &c, 1);
        while (read(to[0], &c, 1) == 1) {
            if (c == 'u') {
                int udp = socket(AF_INET, SOCK_DGRAM, 0);
                struct ifreq ifr = {0};
                strcpy(ifr.ifr_name, "lo");
                ifr.ifr_flags = IFF_UP;
                ioctl(udp, SIOCSIFFLAGS, &ifr);
                close(udp);
            } else if (c == 'q') {
                break;
            } else {
                add_address(fd, 7 * 250 + (c - '0') - 1);
            }
            write(from[1], &c, 1);
        }
        _exit(0);
    }
    close(to[0]);
    close(from[1]);
    char c = 0;
    read(from[0], &c, 1);
    printf("peer ready=%d\n", c == 'r');
    return (struct peer){pid, to[1], from[0]};
}
static void peer_do(struct peer *p, char c) {
    write(p->command, &c, 1);
    read(p->done, &c, 1);
}
static void peer_stop(struct peer *p) {
    peer_do(p, 'q');
    int status = 0;
    waitpid(p->pid, &status, 0);
}

static void nsid_case(void) {
    struct peer p = peer_start();
    int ctl = acked_socket(), mon = bound_socket();
    int group = RTNLGRP_NSID, one = 1;
    printf("join=%ld\n", result(setsockopt(mon, SOL_NETLINK_, ADD_MEMBERSHIP, &group, sizeof group)));
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/ns/net", p.pid);
    int peer_fd = open(path, O_RDONLY), self_fd = open("/proc/self/ns/net", O_RDONLY),
        uts_fd = open("/proc/self/ns/uts", O_RDONLY), pipe_fd[2];
    pipe(pipe_fd);
    printf("opened=%d %d %d\n", peer_fd >= 0, self_fd >= 0, uts_fd >= 0);
    struct request r;
    unsigned seq = 1;
#define REQUEST(type, flags, ...)                                                                                 \
    do {                                                                                                          \
        begin(&r, type, flags, seq++);                                                                            \
        __VA_ARGS__;                                                                                              \
        send_request(ctl, &r);                                                                                    \
    } while (0)
    printf("-- before\n");
    REQUEST(RTM_GETNSID, 0x1, put32(&r, NETNSA_PID, p.pid));
    REQUEST(RTM_GETNSID, 0x301);
    show(ctl, "ctl");
    printf("-- new: errors\n");
    REQUEST(RTM_NEWNSID, 0x5);
    REQUEST(RTM_NEWNSID, 0x5, put32(&r, NETNSA_NSID, 5));
    REQUEST(RTM_NEWNSID, 0x5, put32(&r, NETNSA_NSID, 5), put32(&r, NETNSA_PID, 999999));
    REQUEST(RTM_NEWNSID, 0x5, put32(&r, NETNSA_NSID, 5), put32(&r, NETNSA_PID, 0));
    REQUEST(RTM_NEWNSID, 0x5, put32(&r, NETNSA_NSID, 5), put32(&r, NETNSA_FD, 9999));
    REQUEST(RTM_NEWNSID, 0x5, put32(&r, NETNSA_NSID, 5), put32(&r, NETNSA_FD, -1));
    REQUEST(RTM_NEWNSID, 0x5, put32(&r, NETNSA_NSID, 5), put32(&r, NETNSA_FD, pipe_fd[0]));
    REQUEST(RTM_NEWNSID, 0x5, put32(&r, NETNSA_NSID, 5), put32(&r, NETNSA_FD, uts_fd));
    show(ctl, "ctl");
    show(mon, "mon");
    printf("-- new\n");
    /* The process wins over the descriptor. */
    REQUEST(RTM_NEWNSID, 0x5, put32(&r, NETNSA_NSID, 5), put32(&r, NETNSA_FD, uts_fd), put32(&r, NETNSA_PID, p.pid));
    show(ctl, "ctl");
    show(mon, "mon");
    REQUEST(RTM_NEWNSID, 0x5, put32(&r, NETNSA_NSID, 6), put32(&r, NETNSA_FD, peer_fd));
    REQUEST(RTM_NEWNSID, 0x5, put32(&r, NETNSA_NSID, 5), put32(&r, NETNSA_FD, self_fd));
    show(ctl, "ctl");
    /* The lowest free, with NLM_F_ECHO: the requester alone has the copy. */
    REQUEST(RTM_NEWNSID, 0xd, put32(&r, NETNSA_NSID, -1), put32(&r, NETNSA_FD, self_fd));
    show(ctl, "ctl");
    show(mon, "mon");
    printf("-- get\n");
    REQUEST(RTM_GETNSID, 0x1, put32(&r, NETNSA_PID, p.pid));
    REQUEST(RTM_GETNSID, 0x1, put32(&r, NETNSA_FD, peer_fd));
    REQUEST(RTM_GETNSID, 0x1, put32(&r, NETNSA_NSID, 5));
    REQUEST(RTM_GETNSID, 0x1, put32(&r, NETNSA_NSID, 0));
    REQUEST(RTM_GETNSID, 0x1, put32(&r, NETNSA_FD, self_fd));
    REQUEST(RTM_GETNSID, 0x1, put32(&r, NETNSA_PID, getpid()));
    REQUEST(RTM_GETNSID, 0x1, put32(&r, NETNSA_NSID, 7));
    REQUEST(RTM_GETNSID, 0x1, put32(&r, NETNSA_NSID, -3));
    REQUEST(RTM_GETNSID, 0x1, put32(&r, NETNSA_PID, 999999));
    REQUEST(RTM_GETNSID, 0x1, put32(&r, NETNSA_FD, uts_fd));
    REQUEST(RTM_GETNSID, 0x1);
    REQUEST(RTM_GETNSID, 0x1, put32(&r, NETNSA_PID, p.pid), put32(&r, NETNSA_CURRENT_NSID, 1));
    REQUEST(RTM_GETNSID, 0x1, put32(&r, NETNSA_FD, self_fd), put32(&r, NETNSA_TARGET_NSID, 5));
    REQUEST(RTM_GETNSID, 0x1, put32(&r, NETNSA_PID, p.pid), put32(&r, NETNSA_TARGET_NSID, 0));
    REQUEST(RTM_GETNSID, 0x1, put32(&r, NETNSA_PID, p.pid), put32(&r, NETNSA_TARGET_NSID, 7));
    REQUEST(RTM_GETNSID, 0x1, put(&r, NETNSA_PID, "ab", 2));
    show(ctl, "ctl");
    /* Each dump is read before the next, as one still running makes
       another EBUSY. */
    printf("-- dump\n");
    REQUEST(RTM_GETNSID, 0x301);
    show(ctl, "ctl");
    REQUEST(RTM_GETNSID, 0x301, put32(&r, NETNSA_NSID, 1));
    show(ctl, "ctl");
    printf("strict=%ld\n", result(setsockopt(ctl, SOL_NETLINK_, STRICT_CHK, &one, sizeof one)));
    REQUEST(RTM_GETNSID, 0x301);
    show(ctl, "ctl");
    REQUEST(RTM_GETNSID, 0x301, put32(&r, NETNSA_TARGET_NSID, 5));
    show(ctl, "ctl");
    REQUEST(RTM_GETNSID, 0x301, put32(&r, NETNSA_TARGET_NSID, 0));
    show(ctl, "ctl");
    REQUEST(RTM_GETNSID, 0x301, put32(&r, NETNSA_TARGET_NSID, 9));
    show(ctl, "ctl");
    REQUEST(RTM_GETNSID, 0x301, put32(&r, NETNSA_TARGET_NSID, 5), put32(&r, NETNSA_NSID, 1));
    show(ctl, "ctl");
    REQUEST(RTM_GETNSID, 0x301, put32(&r, 9, 1));
    show(ctl, "ctl");
    REQUEST(RTM_GETNSID, 0x1, put32(&r, NETNSA_PID, p.pid), put32(&r, NETNSA_CURRENT_NSID, 1));
    REQUEST(RTM_GETNSID, 0x1, put32(&r, NETNSA_PID, p.pid));
    show(ctl, "ctl");
    printf("-- others\n");
    REQUEST(RTM_DELNSID, 0x5, put32(&r, NETNSA_NSID, 5));
    show(ctl, "ctl");
    fflush(stdout);
    pid_t user = fork();
    if (user == 0) {
        if (setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) _exit(90);
        ctl = acked_socket();
        REQUEST(RTM_NEWNSID, 0x5, put32(&r, NETNSA_NSID, 8), put32(&r, NETNSA_PID, p.pid));
        REQUEST(RTM_GETNSID, 0x1, put32(&r, NETNSA_PID, p.pid));
        show(ctl, "user");
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    waitpid(user, &status, 0);
    printf("user status=%#x\n", status);
    show(mon, "mon");
    peer_stop(&p);
#undef REQUEST
}

static void listen_case(void) {
    struct peer p = peer_start();
    int ctl = acked_socket(), one = 1, zero = 0, group = 5 /* RTNLGRP_IPV4_IFADDR */;
    int all = bound_socket(), plain = bound_socket();
    /* Opened without capabilities, set by root. */
    if (setresuid(0, 65534, 0)) exit(92);
    int weak = bound_socket();
    if (setresuid(0, 0, 0)) exit(93);
    int fds[] = {all, plain, weak};
    for (int i = 0; i < 3; i++) setsockopt(fds[i], SOL_NETLINK_, ADD_MEMBERSHIP, &group, sizeof group);
    setsockopt(all, SOL_NETLINK_, PKTINFO, &one, sizeof one);
    printf("listen all=%ld weak=%ld\n", result(setsockopt(all, SOL_NETLINK_, LISTEN_ALL_NSID, &one, sizeof one)),
           result(setsockopt(weak, SOL_NETLINK_, LISTEN_ALL_NSID, &one, sizeof one)));
    int value = -1;
    socklen_t len = sizeof value;
    getsockopt(all, SOL_NETLINK_, LISTEN_ALL_NSID, &value, &len);
    printf("get=%d\n", value);
    fflush(stdout);
    pid_t user = fork();
    if (user == 0) {
        if (setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) _exit(90);
        int own = route_socket();
        printf("user: set=%ld clear=%ld\n", result(setsockopt(own, SOL_NETLINK_, LISTEN_ALL_NSID, &one, sizeof one)),
               result(setsockopt(own, SOL_NETLINK_, LISTEN_ALL_NSID, &zero, sizeof zero)));
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    waitpid(user, &status, 0);
    printf("-- peer up, without an ID\n");
    peer_do(&p, 'u');
    peer_do(&p, '1');
    show(all, "all");
    show(plain, "plain");
    show(weak, "weak");
    printf("-- with an ID\n");
    struct request r;
    begin(&r, RTM_NEWNSID, 0x5, 1);
    put32(&r, NETNSA_NSID, 3);
    put32(&r, NETNSA_PID, p.pid);
    send_request(ctl, &r);
    show(ctl, "ctl");
    peer_do(&p, '2');
    show(all, "all");
    show(plain, "plain");
    show(weak, "weak");
    printf("-- own\n");
    lo_up();
    show(all, "all");
    show(plain, "plain");
    show(weak, "weak");
    printf("-- off\n");
    setsockopt(all, SOL_NETLINK_, LISTEN_ALL_NSID, &zero, sizeof zero);
    peer_do(&p, '3');
    show(all, "all");
    printf("-- short control buffers\n");
    setsockopt(all, SOL_NETLINK_, LISTEN_ALL_NSID, &one, sizeof one);
    static const size_t rooms[] = {24, 40, 39, 0};
    for (size_t i = 0; i < sizeof rooms / sizeof rooms[0]; i++) {
        peer_do(&p, (char)('4' + i));
        unsigned char data[4096], control[64];
        memset(control, 0, sizeof control);
        struct iovec iov = {data, sizeof data};
        struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = rooms[i] ? control : NULL,
                             .msg_controllen = rooms[i] ? rooms[i] : 64};
        long n = result(recvmsg(all, &msg, MSG_DONTWAIT));
        printf("room %zu: n=%d flags=%#x controllen=%zu", rooms[i], n > 0, msg.msg_flags, (size_t)msg.msg_controllen);
        if (rooms[i]) {
            for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm))
                printf(" cmsg len=%zu (%d,%d)", (size_t)cm->cmsg_len, cm->cmsg_level, cm->cmsg_type);
        }
        printf("\n");
    }
    printf("-- without pktinfo\n");
    setsockopt(all, SOL_NETLINK_, PKTINFO, &zero, sizeof zero);
    peer_do(&p, '8');
    show(all, "all");
    peer_stop(&p);
}

/* Waits up to 10 s for `fd` to have something, as Linux tells of a
   namespace that went from a work queue, a little later. */
static void await(int fd, const char *label) {
    struct pollfd pfd = {fd, POLLIN, 0};
    printf("%s: ready=%d\n", label, poll(&pfd, 1, 10000));
}

static void gone_case(void) {
    int ctl = acked_socket(), mon = bound_socket();
    int group = RTNLGRP_NSID;
    printf("join=%ld\n", result(setsockopt(mon, SOL_NETLINK_, ADD_MEMBERSHIP, &group, sizeof group)));
    int self_fd = open("/proc/self/ns/net", O_RDONLY);
    struct request r;
    begin(&r, RTM_NEWNSID, 0x5, 1);
    put32(&r, NETNSA_NSID, 2);
    put32(&r, NETNSA_FD, self_fd);
    send_request(ctl, &r);
    struct peer p = peer_start(), q = peer_start();
    begin(&r, RTM_NEWNSID, 0x5, 2);
    put32(&r, NETNSA_NSID, 4);
    put32(&r, NETNSA_PID, p.pid);
    send_request(ctl, &r);
    begin(&r, RTM_NEWNSID, 0x5, 3);
    put32(&r, NETNSA_NSID, 7);
    put32(&r, NETNSA_PID, q.pid);
    send_request(ctl, &r);
    show(ctl, "ctl");
    show(mon, "mon");
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/ns/net", q.pid);
    int q_fd = open(path, O_RDONLY);
    printf("-- the first peer goes\n");
    peer_stop(&p);
    await(mon, "mon");
    show(mon, "mon");
    begin(&r, RTM_GETNSID, 0x301, 4);
    send_request(ctl, &r);
    show(ctl, "ctl");
    printf("-- the second goes, but a descriptor holds it\n");
    peer_stop(&q);
    struct pollfd pfd = {mon, POLLIN, 0};
    printf("held: ready=%d\n", poll(&pfd, 1, 500));
    close(q_fd);
    await(mon, "mon");
    show(mon, "mon");
    printf("-- the IDs are free again\n");
    struct peer n = peer_start();
    begin(&r, RTM_NEWNSID, 0x5, 5);
    put32(&r, NETNSA_NSID, 4);
    put32(&r, NETNSA_PID, n.pid);
    send_request(ctl, &r);
    begin(&r, RTM_GETNSID, 0x1, 6);
    put32(&r, NETNSA_PID, n.pid);
    send_request(ctl, &r);
    show(ctl, "ctl");
    show(mon, "mon");
    begin(&r, RTM_GETNSID, 0x301, 7);
    send_request(ctl, &r);
    show(ctl, "ctl");
    peer_stop(&n);
    await(mon, "mon");
    show(mon, "mon");
}

static void write_case(void) {
    struct peer p = peer_start();
    int ctl = acked_socket(), mon = bound_socket();
    int group = RTNLGRP_NSID;
    setsockopt(mon, SOL_NETLINK_, ADD_MEMBERSHIP, &group, sizeof group);
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/ns/net", p.pid);
    int peer_fd = open(path, O_RDONLY);
    struct request r;
    printf("-- write\n");
    begin(&r, RTM_NEWNSID, 0x5, 1);
    put32(&r, NETNSA_NSID, 3);
    put32(&r, NETNSA_PID, p.pid);
    printf("write=%d\n", write(ctl, &r, r.h.len) == r.h.len);
    begin(&r, RTM_GETNSID, 0x1, 2);
    put32(&r, NETNSA_FD, peer_fd);
    printf("write=%d\n", write(ctl, &r, r.h.len) == r.h.len);
    begin(&r, RTM_GETNSID, 0x1, 3);
    put32(&r, NETNSA_PID, 999999);
    printf("write=%d\n", write(ctl, &r, r.h.len) == r.h.len);
    begin(&r, RTM_GETNSID, 0x1, 4);
    put32(&r, NETNSA_FD, 9999);
    printf("write=%d\n", write(ctl, &r, r.h.len) == r.h.len);
    show(ctl, "ctl");
    show(mon, "mon");
    printf("-- writev\n");
    begin(&r, RTM_GETNSID, 0x1, 5);
    put32(&r, NETNSA_PID, p.pid);
    struct iovec parts[2] = {{&r, 16}, {(char *)&r + 16, r.h.len - 16}};
    printf("writev=%d\n", writev(ctl, parts, 2) == r.h.len);
    show(ctl, "ctl");
    printf("-- a writer without CAP_NET_ADMIN, on root's socket\n");
    fflush(stdout);
    pid_t user = fork();
    if (user == 0) {
        if (setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) _exit(90);
        begin(&r, RTM_GETNSID, 0x1, 6);
        put32(&r, NETNSA_PID, p.pid);
        put32(&r, NETNSA_TARGET_NSID, 3);
        write(ctl, &r, r.h.len);
        begin(&r, RTM_GETNSID, 0x1, 7);
        put32(&r, NETNSA_PID, p.pid);
        write(ctl, &r, r.h.len);
        show(ctl, "user");
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    waitpid(user, &status, 0);
    printf("user status=%#x\n", status);
    begin(&r, RTM_GETNSID, 0x1, 8);
    put32(&r, NETNSA_PID, p.pid);
    put32(&r, NETNSA_TARGET_NSID, 3);
    write(ctl, &r, r.h.len);
    show(ctl, "ctl");
    close(peer_fd);
    peer_stop(&p);
}

/* Starts a request of `type` whose body is `body` zero bytes, with
   `family` first and `index` at byte 4. */
static void begin_body(struct request *r, unsigned short type, unsigned short flags, unsigned seq, int body,
                       unsigned char family, int index) {
    begin(r, type, flags, seq);
    r->h.len = sizeof r->h + body;
    r->body[0] = family;
    memcpy(r->body + 4, &index, 4);
}

#define IFLA_IFNAME 3
#define IFLA_NET_NS_PID 19
#define IFLA_TARGET_NETNSID 46
#define IFA_ADDRESS 1
#define IFA_TARGET_NETNSID 10

static void target_case(void) {
    struct peer p = peer_start();
    peer_do(&p, 'u');
    peer_do(&p, '1');
    int ctl = acked_socket(), one = 1;
    /* Opened without capabilities, used by root. */
    if (setresuid(0, 65534, 0)) exit(92);
    int weak = acked_socket();
    if (setresuid(0, 0, 0)) exit(93);
    struct request r;
    unsigned seq = 1;
    int self_fd = open("/proc/self/ns/net", O_RDONLY);
    begin(&r, RTM_NEWNSID, 0x5, seq++);
    put32(&r, NETNSA_NSID, 3);
    put32(&r, NETNSA_PID, p.pid);
    send_request(ctl, &r);
    begin(&r, RTM_NEWNSID, 0x5, seq++);
    put32(&r, NETNSA_NSID, 2);
    put32(&r, NETNSA_FD, self_fd);
    send_request(ctl, &r);
    show(ctl, "ctl");
    static const unsigned char loopback6[16] = {[15] = 1};
    for (int strict = 0; strict < 2; strict++) {
        printf("-- strict=%d\n", strict);
        setsockopt(ctl, SOL_NETLINK_, STRICT_CHK, &strict, sizeof strict);
        printf("link dumps\n");
        static const int ids[] = {3, 2, 9, -1};
        for (size_t i = 0; i < sizeof ids / sizeof ids[0]; i++) {
            begin_body(&r, 18, 0x301, seq++, 16, 0, 0);
            put32(&r, IFLA_TARGET_NETNSID, ids[i]);
            send_request(ctl, &r);
            show(ctl, "ctl");
        }
        printf("link gets\n");
        begin_body(&r, 18, 0x1, seq++, 16, 0, 1);
        put32(&r, IFLA_TARGET_NETNSID, 3);
        send_request(ctl, &r);
        begin_body(&r, 18, 0x1, seq++, 16, 0, 0);
        put(&r, IFLA_IFNAME, "lo", 3);
        put32(&r, IFLA_TARGET_NETNSID, 3);
        send_request(ctl, &r);
        begin_body(&r, 18, 0x1, seq++, 16, 0, 5);
        put32(&r, IFLA_TARGET_NETNSID, 3);
        send_request(ctl, &r);
        begin_body(&r, 18, 0x1, seq++, 16, 0, 0);
        put32(&r, IFLA_TARGET_NETNSID, 3);
        send_request(ctl, &r);
        begin_body(&r, 18, 0x1, seq++, 16, 0, 1);
        put32(&r, IFLA_TARGET_NETNSID, 9);
        send_request(ctl, &r);
        begin_body(&r, 18, 0x1, seq++, 16, 0, 1);
        put32(&r, IFLA_TARGET_NETNSID, 3);
        put32(&r, IFLA_NET_NS_PID, p.pid);
        send_request(ctl, &r);
        show(ctl, "ctl");
        printf("address dumps\n");
        static const unsigned char families[] = {AF_UNSPEC, AF_INET, AF_INET6};
        for (size_t i = 0; i < sizeof families; i++) {
            begin_body(&r, 22, 0x301, seq++, 8, families[i], 0);
            put32(&r, IFA_TARGET_NETNSID, 3);
            send_request(ctl, &r);
            show(ctl, "ctl");
        }
        begin_body(&r, 22, 0x301, seq++, 8, AF_INET, 1);
        put32(&r, IFA_TARGET_NETNSID, 3);
        send_request(ctl, &r);
        show(ctl, "ctl");
        begin_body(&r, 22, 0x301, seq++, 8, AF_INET6, 0);
        put32(&r, IFA_TARGET_NETNSID, 9);
        send_request(ctl, &r);
        show(ctl, "ctl");
        begin_body(&r, 22, 0x301, seq++, 8, AF_INET, 0);
        put(&r, IFA_ADDRESS, "\x7f\0\0\1", 4);
        put32(&r, IFA_TARGET_NETNSID, 3);
        send_request(ctl, &r);
        show(ctl, "ctl");
        printf("address gets\n");
        /* Answered to this port in the other namespace, which none has. */
        begin_body(&r, 22, 0x5, seq++, 8, AF_INET6, 0);
        put(&r, IFA_ADDRESS, loopback6, 16);
        put32(&r, IFA_TARGET_NETNSID, 3);
        send_request(ctl, &r);
        begin_body(&r, 22, 0x5, seq++, 8, AF_INET6, 0);
        put(&r, IFA_ADDRESS, loopback6, 16);
        put32(&r, IFA_TARGET_NETNSID, 9);
        send_request(ctl, &r);
        show(ctl, "ctl");
    }
    printf("-- own namespace by its ID\n");
    lo_up();
    begin_body(&r, 22, 0x5, seq++, 8, AF_INET6, 0);
    put(&r, IFA_ADDRESS, loopback6, 16);
    put32(&r, IFA_TARGET_NETNSID, 2);
    send_request(ctl, &r);
    show(ctl, "ctl");
    printf("-- without CAP_NET_ADMIN\n");
    setsockopt(weak, SOL_NETLINK_, STRICT_CHK, &one, sizeof one);
    begin_body(&r, 18, 0x301, seq++, 16, 0, 0);
    put32(&r, IFLA_TARGET_NETNSID, 3);
    send_request(weak, &r);
    show(weak, "weak");
    begin_body(&r, 18, 0x1, seq++, 16, 0, 1);
    put32(&r, IFLA_TARGET_NETNSID, 3);
    send_request(weak, &r);
    show(weak, "weak");
    fflush(stdout);
    pid_t user = fork();
    if (user == 0) {
        if (setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) _exit(90);
        begin_body(&r, 22, 0x301, seq++, 8, AF_INET, 0);
        put32(&r, IFA_TARGET_NETNSID, 3);
        send_request(ctl, &r);
        show(ctl, "user");
        begin_body(&r, 18, 0x1, seq++, 16, 0, 1);
        put32(&r, IFLA_TARGET_NETNSID, 3);
        send_request(ctl, &r);
        begin_body(&r, 18, 0x1, seq++, 16, 0, 1);
        send_request(ctl, &r);
        show(ctl, "user");
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    waitpid(user, &status, 0);
    printf("user status=%#x\n", status);
    peer_stop(&p);
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
        else if (!strcmp(mode, "netlink-nsid")) nsid_case();
        else if (!strcmp(mode, "netlink-listen-all-nsid")) listen_case();
        else if (!strcmp(mode, "netlink-nsid-gone")) gone_case();
        else if (!strcmp(mode, "netlink-nsid-write")) write_case();
        else if (!strcmp(mode, "netlink-target-netnsid")) target_case();
        else return 2;
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    printf("child status=%#x\n", status);
    return 0;
}
