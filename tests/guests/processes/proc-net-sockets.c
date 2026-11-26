/* /proc/net's files of sockets: tcp, tcp6, udp, udp6, unix and netlink, and
   those of kinds of which there is none. As root: each runs in a network
   namespace of the process's own, so what is printed is this process's
   sockets alone, each by its name in place of its inode. The kernel's
   addresses, the references, `sl`, a timer's time and how TCP sends (the RTO
   and what follows it) are not printed, the lines are sorted, as their order
   is a hash's, and a file is read again until nothing waits to be
   acknowledged. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <net/if.h>

static long result(long r) { return r < 0 ? -errno : r; }

/* The sockets and their names. */
static struct {
    unsigned long inode;
    const char *name;
} known[64];
static int knowns;
static int named(int fd, const char *name) {
    struct stat s;
    if (fd < 0 || fstat(fd, &s) < 0) {
        printf("%s: %d\n", name, -errno);
        return fd;
    }
    known[knowns].inode = (unsigned long)s.st_ino;
    known[knowns++].name = name;
    return fd;
}
static const char *name_of(const char *inode) {
    unsigned long n = strtoul(inode, NULL, 10);
    if (!n) return "0";
    for (int i = knowns; i-- > 0;)
        if (known[i].inode == n) return known[i].name;
    return "?";
}

static char text[65536];
static long slurp(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -errno;
    long n, all = 0;
    while ((n = read(fd, text + all, sizeof text - 1 - (size_t)all)) > 0) all += n;
    close(fd);
    text[all] = 0;
    return all;
}
static int compare(const void *a, const void *b) { return strcmp(a, b); }
/* Splits a line at its spaces. */
static int split(char *line, char **fields, int most) {
    int n = 0;
    for (char *f = strtok(line, " "); f && n < most; f = strtok(NULL, " ")) fields[n++] = f;
    return n;
}
/* Whether a connection of the file has sent what is not acknowledged yet. */
static int sending(const char *file) {
    for (const char *line = strchr(file, '\n'); line && line[1]; line = strchr(line + 1, '\n')) {
        unsigned state, queue;
        if (sscanf(line + 1, "%*s %*s %*s %x %x", &state, &queue) == 2 && queue) return 1;
    }
    return 0;
}
/* Prints the header of `path` and, of each line, what is compared. */
static void show(const char *file) {
    char path[64];
    static char lines[64][512];
    int count = 0, tcp = !strncmp(file, "tcp", 3), unx = !strcmp(file, "unix");
    snprintf(path, sizeof path, "/proc/net/%s", file);
    long n = 0;
    for (int tries = 0; tries < 200; tries++) {
        n = slurp(path);
        if (!tcp || !sending(text)) break;
        poll(NULL, 0, 10);
    }
    if (n < 0) {
        printf("%s: %ld\n", file, n);
        return;
    }
    char *line = text, *next = strchr(line, '\n');
    int listeners_over = 0, order = 1;
    if (!next) return;
    *next++ = 0;
    if (!strcmp(file, "netlink") || !strcmp(file, "packet")) /* newer ones have no room for an address */
        printf("%s: |sk%s|\n", file, line + 2 + strspn(line + 2, " "));
    else
        printf("%s: |%s|\n", file, line);
    for (line = next; *line; line = next) {
        next = strchr(line, '\n');
        if (!next || count == 64) break;
        *next++ = 0;
        char *f[32], *out = lines[count];
        size_t width = strlen(line);
        int padded = !strcmp(file, "tcp") || !strcmp(file, "udp");
        int k = 0;
        const char *after = line;
        for (; unx && k < 7; k++) after += strspn(after, " "), after += strcspn(after, " ");
        char tail[256];
        snprintf(tail, sizeof tail, "%s", unx ? after : "");
        k = split(line, f, 32);
        if (unx) {
            if (k < 7) continue;
            snprintf(out, 512, "protocol=%s flags=%s type=%s st=%s %s|%s|", f[2], f[3], f[4], f[5], name_of(f[6]), tail);
        } else if (!strcmp(file, "netlink")) {
            if (k < 10 || !strcmp(f[2], "0")) continue; /* the kernel's */
            snprintf(out, 512, "eth=%s pid=%s groups=%s rmem=%d wmem=%s dump=%s drops=%s %s", f[1],
                     strtoul(f[2], NULL, 10) == (unsigned long)getpid() ? "own" : f[2], f[3], strcmp(f[4], "0") != 0, f[5],
                     f[6], f[8], name_of(f[9]));
        } else {
            if (k < 12) continue;
            char *when = strchr(f[5], ':');
            if (when) *when = 0;
            if (tcp) {
                if (strcmp(f[3], "0A"))
                    listeners_over = 1;
                else if (listeners_over)
                    order = 0;
                if (atoi(f[0]) != count) order = 0;
            }
            snprintf(out, 512, "%s %s st=%s queues=%s tr=%s %s uid=%s timeout=%s %s, %d fields, %zu wide", f[1], f[2],
                     f[3], f[4], f[5], f[6], f[7], f[8], name_of(f[9]), k, padded ? width : 0);
            if (!tcp) sprintf(out + strlen(out), " drops=%s", f[12]);
        }
        count++;
    }
    if (tcp) printf("in order=%d\n", order);
    qsort(lines, (size_t)count, sizeof *lines, compare);
    for (int i = 0; i < count; i++) printf("%s\n", lines[i]);
}

static socklen_t at(struct sockaddr_storage *a, const char *ip, int port) {
    memset(a, 0, sizeof *a);
    if (strchr(ip, ':')) {
        struct sockaddr_in6 *in = (struct sockaddr_in6 *)a;
        in->sin6_family = AF_INET6;
        in->sin6_port = htons((unsigned short)port);
        inet_pton(AF_INET6, ip, &in->sin6_addr);
        return sizeof *in;
    }
    struct sockaddr_in *in = (struct sockaddr_in *)a;
    in->sin_family = AF_INET;
    in->sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, ip, &in->sin_addr);
    return sizeof *in;
}
static int made(int type, const char *ip, int port, const char *name) {
    struct sockaddr_storage a;
    socklen_t len = at(&a, ip, port);
    int fd = named(socket(a.ss_family, type, 0), name);
    const int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (port >= 0) {
        long r = result(bind(fd, (struct sockaddr *)&a, len));
        if (r) printf("%s: bind=%ld\n", name, r);
    }
    return fd;
}
static int joined(int fd, const char *ip, int port, const char *name) {
    struct sockaddr_storage a;
    socklen_t len = at(&a, ip, port);
    long r = result(connect(fd, (struct sockaddr *)&a, len));
    if (r) printf("%s: connect=%ld\n", name, r);
    return fd;
}
static void say(int fd, const char *what, const char *label) {
    long r = result(send(fd, what, strlen(what), 0));
    if (r != (long)strlen(what)) printf("%s: send=%ld\n", label, r);
}
static void both(const char *label, const char *a, const char *b) {
    printf("-- %s\n", label);
    show(a);
    if (b) show(b);
}

static void streams(void) {
    int bound = made(SOCK_STREAM, "127.0.0.1", 1000, "bound");
    int listener = made(SOCK_STREAM, "127.0.0.1", 1001, "listener");
    listen(listener, 3);
    int any = made(SOCK_STREAM, "0.0.0.0", 1002, "any");
    listen(any, 3);
    int six = made(SOCK_STREAM, "::1", 1003, "six");
    listen(six, 3);
    int dual = made(SOCK_STREAM, "::", 1004, "dual");
    listen(dual, 3);
    int lonely = made(SOCK_STREAM, "0.0.0.0", -1, "unbound");
    both("listening", "tcp", "tcp6");
    int one = joined(made(SOCK_STREAM, "127.0.0.1", 1100, "one"), "127.0.0.1", 1001, "one");
    int two = joined(made(SOCK_STREAM, "::1", 1101, "two"), "::1", 1003, "two");
    int three = joined(made(SOCK_STREAM, "127.0.0.2", 1102, "three"), "127.0.0.1", 1004, "three");
    int four = joined(made(SOCK_STREAM, "::ffff:127.0.0.1", 1103, "four"), "::ffff:127.0.0.1", 1001, "four");
    both("connected, not accepted", "tcp", "tcp6");
    int one_ = named(accept(listener, NULL, NULL), "one's");
    int four_ = named(accept(listener, NULL, NULL), "four's");
    int two_ = named(accept(six, NULL, NULL), "two's");
    int three_ = named(accept(dual, NULL, NULL), "three's");
    say(one, "hello", "one");
    say(two_, "hi", "two's");
    say(three, "a", "three");
    both("accepted, with data", "tcp", "tcp6");
    printf("fchown=%ld\n", result(fchown(one, 1234, 5678)));
    shutdown(one, SHUT_WR);
    shutdown(three_, SHUT_WR);
    both("one way shut", "tcp", "tcp6");
    char buf[16];
    printf("recv=%ld\n", result(recv(one_, buf, sizeof buf, 0)));
    printf("recv=%ld\n", result(recv(one_, buf, sizeof buf, 0)));
    both("read to the end", "tcp", NULL);
    close(one_);
    close(four);
    close(four_);
    both("closed", "tcp", "tcp6");
    close(one), close(bound), close(lonely), close(listener), close(any);
    both("listeners closed", "tcp", "tcp6");
    close(two), close(two_), close(three), close(three_), close(six), close(dual);
}

static void datagrams(void) {
    int bound = made(SOCK_DGRAM, "127.0.0.1", 1001, "bound");
    int any = made(SOCK_DGRAM, "0.0.0.0", 1002, "any");
    int unbound = made(SOCK_DGRAM, "0.0.0.0", -1, "unbound");
    int six = made(SOCK_DGRAM, "::1", 1003, "six");
    int dual = made(SOCK_DGRAM, "::", 1004, "dual");
    int joins = joined(made(SOCK_DGRAM, "127.0.0.1", 1005, "joins"), "127.0.0.1", 1001, "joins");
    int joins6 = joined(made(SOCK_DGRAM, "::1", 1006, "joins6"), "::1", 1003, "joins6");
    int mapped = joined(made(SOCK_DGRAM, "::ffff:127.0.0.1", 1007, "mapped"), "::ffff:127.0.0.1", 1002, "mapped");
    both("bound and connected", "udp", "udp6");
    printf("fchown=%ld\n", result(fchown(six, 4321, -1)));
    const int small = 1;
    setsockopt(any, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
    say(joins, "hello", "joins");
    say(joins6, "hello", "joins6");
    for (int i = 0; i < 12; i++) say(mapped, "hello", "mapped");
    both("with data, and some dropped", "udp", "udp6");
    char buf[16];
    printf("recv=%ld\n", result(recv(bound, buf, sizeof buf, 0)));
    struct sockaddr_storage none;
    memset(&none, 0, sizeof none);
    printf("disconnect=%ld\n", result(connect(joins, (struct sockaddr *)&none, sizeof(struct sockaddr_in))));
    /* An IPv6 socket keeps its peer's address (sk_v6_daddr), with port 0. */
    printf("disconnect6=%ld\n", result(connect(joins6, (struct sockaddr *)&none, sizeof(struct sockaddr_in6))));
    printf("disconnect mapped=%ld\n", result(connect(mapped, (struct sockaddr *)&none, sizeof(struct sockaddr_in6))));
    close(any);
    both("read, disconnected and closed", "udp", "udp6");
    close(bound), close(unbound), close(six), close(dual), close(joins), close(joins6), close(mapped);
}

static socklen_t path_of(struct sockaddr_un *a, const char *path, size_t len) {
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    memcpy(a->sun_path, path, len);
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + len);
}
static int local(int type, const char *path, size_t len, const char *name) {
    struct sockaddr_un a;
    int fd = named(socket(AF_UNIX, type, 0), name);
    if (path) {
        socklen_t size = path_of(&a, path, len);
        long r = result(bind(fd, (struct sockaddr *)&a, size));
        if (r) printf("%s: bind=%ld\n", name, r);
    }
    return fd;
}
static void to_local(int fd, const char *path, size_t len, const char *name) {
    struct sockaddr_un a;
    socklen_t size = path_of(&a, path, len);
    long r = result(connect(fd, (struct sockaddr *)&a, size));
    if (r) printf("%s: connect=%ld\n", name, r);
}
static void locals(void) {
    char directory[] = "/tmp/proc-net-XXXXXX";
    if (!mkdtemp(directory) || chdir(directory) < 0) printf("no directory\n");
    both("none", "unix", NULL);
    int listener = local(SOCK_STREAM, "listener", 8, "listener");
    listen(listener, 5);
    int ended = local(SOCK_STREAM, "a path", 7, "with its NUL");
    int abstract = local(SOCK_SEQPACKET, "\0an\0abstract\0", 13, "abstract");
    listen(abstract, 5);
    int empty = local(SOCK_DGRAM, "\0", 1, "empty");
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    int plain = local(SOCK_STREAM, NULL, 0, "plain");
    int datagram = local(SOCK_DGRAM, "datagram", 8, "datagram");
    int pair[2], pair2[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) || socketpair(AF_UNIX, SOCK_DGRAM, 0, pair2)) printf("no pair\n");
    named(pair[0], "left"), named(pair[1], "right"), named(pair2[0], "datagram left"), named(pair2[1], "datagram right");
    both("made", "unix", NULL);
    int one = local(SOCK_STREAM, NULL, 0, "one"), two = local(SOCK_SEQPACKET, "two", 3, "two"),
        three = local(SOCK_DGRAM, NULL, 0, "three");
    to_local(one, "listener", 8, "one");
    to_local(two, "\0an\0abstract\0", 13, "two");
    to_local(three, "datagram", 8, "three");
    both("connected", "unix", NULL);
    int one_ = named(accept(listener, NULL, NULL), "one's");
    unlink("listener");
    shutdown(pair[0], SHUT_RDWR);
    close(pair2[0]);
    both("accepted, unlinked, shut and half a pair", "unix", NULL);
    close(listener);
    close(one);
    both("closed", "unix", NULL);
    close(ended), close(abstract), close(empty), close(plain), close(datagram), close(pair[0]), close(pair[1]);
    close(pair2[1]), close(two), close(three), close(one_);
    both("all closed", "unix", NULL);
    const char *paths[] = {"a path", "datagram", "two"};
    for (int i = 0; i < 3; i++) unlink(paths[i]);
    if (chdir("/") < 0 || rmdir(directory) < 0) printf("the directory stays\n");
}

static void links(void) {
    unsigned address[3] = {AF_NETLINK, 0, 0};
    int route = named(socket(AF_NETLINK, SOCK_RAW, 0), "route"), diag = named(socket(AF_NETLINK, SOCK_RAW, 4), "diag"),
        generic = named(socket(AF_NETLINK, SOCK_RAW, 16), "generic"), groups = named(socket(AF_NETLINK, SOCK_RAW, 0), "groups");
    both("netlink sockets, not bound", "netlink", NULL);
    bind(route, (struct sockaddr *)address, 12);
    address[1] = 77;
    bind(diag, (struct sockaddr *)address, 12);
    address[1] = 78;
    bind(generic, (struct sockaddr *)address, 12);
    address[1] = 79;
    address[2] = 0x111;
    bind(groups, (struct sockaddr *)address, 12);
    const int far = 40;
    printf("a group past the first 32=%ld\n", result(setsockopt(groups, 270, 1, &far, sizeof far)));
    both("bound", "netlink", NULL);
    const unsigned dump[5] = {17 + 3, 18 | 0x301 << 16, 1, 0, AF_UNSPEC};
    if (send(route, dump, 20, 0) != 20) printf("no request\n");
    both("with an answer to read", "netlink", NULL);
    close(route), close(diag), close(generic), close(groups);
    both("closed", "netlink", NULL);
}

/* Whose sockets a file tells, as its opener's user namespace sees them, and
   which namespace's. */
static void write_map(pid_t pid, const char *name) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/%s", pid, name);
    int fd = open(path, O_WRONLY);
    if (write(fd, "5 1000 10", 9) != 9) printf("%s=%d\n", name, -errno);
    close(fd);
}
static void users(void) {
    int udp = made(SOCK_DGRAM, "127.0.0.1", 1001, "ours"), other = made(SOCK_DGRAM, "127.0.0.1", 1002, "another's");
    int down[2], up[2];
    char c;
    if (fchown(udp, 1003, -1) || pipe(down) || pipe(up)) printf("no pipe\n");
    printf("-- in a user namespace\n");
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        if (unshare(CLONE_NEWUSER)) _exit(1);
        if (write(up[1], "u", 1) != 1 || read(down[0], &c, 1) != 1) _exit(2);
        show("udp");
        if (unshare(CLONE_NEWNET)) _exit(3);
        both("in a network namespace of its own", "udp", "unix");
        int s = local(SOCK_DGRAM, "\0there", 6, "there");
        show("unix");
        close(s);
        fflush(stdout);
        _exit(0);
    }
    if (read(up[0], &c, 1) != 1) printf("no child\n");
    write_map(child, "uid_map");
    if (write(down[1], "m", 1) != 1) printf("no child\n");
    int status = 0;
    waitpid(child, &status, 0);
    printf("exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    close(udp), close(other);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "proc-net-sockets")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct ifreq up = {.ifr_name = "lo", .ifr_flags = IFF_UP};
    printf("up lo=%ld\n", result(ioctl(s, SIOCSIFFLAGS, &up)));
    close(s);
    const char *files[] = {"raw", "raw6", "icmp", "icmp6", "packet", "tcp", "tcp6", "udp", "udp6", "unix", "netlink"};
    for (int i = 0; i < 11; i++) {
        struct stat st = {0};
        char path[64];
        snprintf(path, sizeof path, "/proc/net/%s", files[i]);
        long r = result(stat(path, &st));
        printf("%s: stat=%ld mode=%o uid=%u size=%ld\n", path, r, st.st_mode, st.st_uid, (long)st.st_size);
        show(files[i]);
    }
    streams();
    datagrams();
    locals();
    links();
    users();
    return 0;
}
