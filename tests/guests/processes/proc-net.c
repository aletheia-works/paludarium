/* /proc/net and /proc/<pid>/net: what the files of a network namespace's
   devices, addresses, routes and neighbours hold, and whose namespace's they
   are (so as root). The process makes a network namespace of its own with lo
   and a pair, va (1000, 02:00:00:00:00:0a) and vb (1001, ...:0b), and gives va
   addresses, routes and a neighbour. It prints `route` and `ipv6_route` as
   they are, but the reference counts and uses of the latter; the lines of
   `if_inet6` and `arp`, sorted, as their order is a hash's; and of `dev` the
   names of its own devices and how many counters. Then a child in a namespace of its own: the
   names are looked up in the namespace its process has then, a file open
   stays with the one it was opened in, and a zombie has none; and whose the
   files are, the root of the user namespace as it mapped it when the network
   namespace was made. The names a
   kernel has there differ, so none but those is looked at. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define NLM_F_REQUEST 1
#define NLM_F_ACK 4
#define NLM_F_CREATE 0x400
#define RTM_NEWLINK 16
#define RTM_NEWADDR 20
#define RTM_NEWROUTE 24
#define RTM_NEWNEIGH 28
#define VA 1000
#define VB 1001

struct body {
    unsigned char bytes[1024];
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
static void ip(struct body *b, int family, unsigned short type, const char *text) {
    unsigned char in[16];
    inet_pton(family, text, in);
    put(b, type, in, family == AF_INET ? 4 : 16);
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
static void up(int index, const char *label) {
    struct body b = {0};
    const unsigned m[4] = {0, (unsigned)index, IFF_UP, IFF_UP};
    raw(&b, m, 16);
    request(RTM_NEWLINK, &b, label);
}
static void address(int family, int index, const char *text, int prefix, unsigned flags, const char *label) {
    struct body b = {0};
    const unsigned char m[8] = {(unsigned char)family, (unsigned char)prefix, (unsigned char)flags, 0,
                                (unsigned char)index, (unsigned char)(index >> 8), 0, 0};
    raw(&b, m, 8);
    ip(&b, family, 2, text);
    request(RTM_NEWADDR, &b, label);
}
/* A route of `family` and `type` to `dst`/`len`, by `gateway` and through
   `oif`, where they are given, of `metric`, with metrics where `advmss`. */
static void route(int family, int type, const char *dst, int len, const char *gateway, int oif, unsigned metric,
                  int advmss, const char *label) {
    struct body b = {0};
    const unsigned char m[12] = {(unsigned char)family, (unsigned char)len, 0, 0, 254, 4,
                                 (unsigned char)(family == AF_INET && !gateway && type == 1 ? 253 : 0),
                                 (unsigned char)type, 0, 0, 0, 0};
    raw(&b, m, 12);
    if (len) ip(&b, family, 1, dst);
    if (gateway) ip(&b, family, 5, gateway);
    if (oif) put32(&b, 4, (unsigned)oif);
    if (metric) put32(&b, 6, metric);
    if (advmss) {
        size_t at = begin(&b, 8);
        put32(&b, 8, (unsigned)advmss);
        put32(&b, 3, 1000);
        put32(&b, 4, 80);
        end(&b, at);
    }
    request(RTM_NEWROUTE, &b, label);
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

static char text[65536];
/* Reads all of `path` into `text`: its length, or the error. */
static long slurp(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -errno;
    long n, all = 0;
    while ((n = read(fd, text + all, sizeof text - 1 - (size_t)all)) > 0) all += n;
    if (n < 0) all = -errno;
    close(fd);
    text[all < 0 ? 0 : all] = 0;
    return all;
}
static int compare(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }
/* Prints the lines of `path` as they are, or sorted; of `ipv6_route` its
   counts masked, and of `dev` the names alone. */
enum how { AS_IT_IS, SORTED, ROUTES6, DEVICES };
static void show(const char *path, enum how how) {
    long n = slurp(path);
    printf("%s: %ld\n", path, how == DEVICES && n > 0 ? 1 : n);
    char *lines[256];
    size_t count = 0;
    for (char *line = text, *next; *line && count < 256; line = next) {
        next = strchr(line, '\n');
        if (!next) break;
        *next++ = 0;
        lines[count++] = line;
    }
    if (how == SORTED) qsort(lines, count, sizeof *lines, compare);
    for (size_t i = 0; i < count; i++) {
        if (how == ROUTES6 && strlen(lines[i]) > 130) memset(lines[i] + 114, 'x', 17);
        if (how == DEVICES && i >= 2) {
            int fields = 0;
            char *colon = strchr(lines[i], ':');
            for (char *c = colon ? colon + 1 : lines[i]; *c; c++) fields += *c != ' ' && (c[1] == ' ' || !c[1]);
            if (colon) *colon = 0;
            /* A kernel's own tunnels are in every namespace. */
            const char *name = lines[i] + strspn(lines[i], " ");
            if (!strcmp(name, "lo") || !strcmp(name, "va") || !strcmp(name, "vb"))
                printf("|%s| %d counters\n", lines[i], fields);
        } else
            printf("|%s|\n", lines[i]);
    }
}
static void all(const char *label) {
    printf("-- %s\n", label);
    show("/proc/net/dev", DEVICES);
    show("/proc/net/if_inet6", SORTED);
    show("/proc/net/route", AS_IT_IS);
    show("/proc/net/ipv6_route", ROUTES6);
    show("/proc/net/arp", SORTED);
}
static void mode(const char *path, int link) {
    struct stat s;
    long r = result(link ? lstat(path, &s) : stat(path, &s));
    if (r)
        printf("%s: stat=%ld\n", path, r);
    else
        printf("%s: mode=%o uid=%u gid=%u size=%ld\n", path, s.st_mode, s.st_uid, s.st_gid, (long)s.st_size);
}
static void opened(const char *path, int flags, const char *label) {
    int fd = open(path, flags);
    printf("%s: open=%d\n", label, fd < 0 ? -errno : 0);
    if (fd < 0) return;
    if ((flags & 3) == O_RDWR) printf("%s: write=%ld\n", label, result(write(fd, "x", 1)));
    close(fd);
}
/* Whether the `dev` of `path` has va. */
static void has_va(const char *path, const char *label) {
    long n = slurp(path);
    printf("%s: %s\n", label, n < 0 ? "no file" : strstr(text, " va:") ? "va" : "no va");
}

static void owner(const char *path, const char *label) {
    struct stat s = {0};
    long r = result(stat(path, &s));
    printf("%s: stat=%ld uid=%u gid=%u\n", label, r, s.st_uid, s.st_gid);
}
static void write_map(pid_t pid, const char *name) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/%s", pid, name);
    int fd = open(path, O_WRONLY);
    long r = result(write(fd, "0 1000 10", 9));
    if (r != 9) printf("%s=%ld\n", name, r);
    close(fd);
}
/* Whose the files are of a child's that makes the namespaces `first`, has its
   IDs mapped to 1000 and on, and makes `then`: as it sees them and as this
   process does. */
static void users(int first, int then, const char *label) {
    int down[2], up_[2];
    char c, path[64];
    if (pipe(down) < 0 || pipe(up_) < 0) return;
    printf("-- %s\n", label);
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        if (unshare(first) < 0) _exit(1);
        if (write(up_[1], "u", 1) != 1 || read(down[0], &c, 1) != 1) _exit(2);
        if (then && unshare(then) < 0) _exit(3);
        owner("/proc/net/dev", "its own file");
        owner("/proc/net", "its own directory");
        fflush(stdout);
        if (write(up_[1], "d", 1) != 1 || read(down[0], &c, 1) != 1) _exit(4);
        _exit(0);
    }
    if (read(up_[0], &c, 1) != 1) printf("no child\n");
    write_map(child, "uid_map");
    write_map(child, "gid_map");
    if (write(down[1], "m", 1) != 1 || read(up_[0], &c, 1) != 1) printf("no child\n");
    snprintf(path, sizeof path, "/proc/%d/net/dev", child);
    owner(path, "its file");
    snprintf(path, sizeof path, "/proc/%d/net/ipv6_route", child);
    owner(path, "its other file");
    if (write(down[1], "x", 1) != 1) printf("no child\n");
    int status = 0;
    waitpid(child, &status, 0);
    printf("exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    close(down[0]), close(down[1]), close(up_[0]), close(up_[1]);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "proc-net")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    ctl = socket(AF_NETLINK, SOCK_RAW, 0);
    char link[64] = {0};
    printf("readlink=%ld %s\n", result(readlink("/proc/net", link, sizeof link - 1)), link);
    mode("/proc/net", 1);
    mode("/proc/net", 0);
    mode("/proc/net/", 1);
    mode("/proc/self/net", 1);
    mode("/proc/thread-self/net", 1);
    const char *files[] = {"arp", "dev", "route", "if_inet6", "ipv6_route"};
    char path[128];
    for (int i = 0; i < 5; i++) {
        snprintf(path, sizeof path, "/proc/net/%s", files[i]);
        mode(path, 0);
    }
    mode("/proc/net/none-such", 0);
    mode("/proc/net/dev/x", 0);
    opened("/proc/net", O_RDONLY | O_DIRECTORY, "the directory");
    opened("/proc/net", O_RDONLY | O_NOFOLLOW, "the link");
    opened("/proc/net", O_RDWR, "the directory to write");
    opened("/proc/net/dev", O_RDWR, "a file to write");
    opened("/proc/net/dev", O_PATH | O_RDWR, "a file's path to write");
    opened("/proc/net/dev", O_RDONLY | O_DIRECTORY, "a file as a directory");
    opened("/proc/net/none-such", O_RDONLY | O_CREAT, "a file to make");
    int dir = open("/proc/net", O_RDONLY | O_DIRECTORY);
    int in_it = openat(dir, "dev", O_RDONLY);
    printf("openat=%d\n", in_it < 0 ? -errno : 0);
    char piece[8] = {0};
    long some = result(pread(in_it, piece, 5, 6));
    printf("pread=%ld \"%s\"\n", some, piece);
    long to = result(lseek(in_it, 1, SEEK_SET)), got = result(read(in_it, piece, 5));
    printf("lseek=%ld read=%ld \"%s\"\n", to, got, piece);
    close(in_it);

    all("a new namespace");
    up(1, "up lo");
    all("lo up");
    make_pair();
    address(AF_INET, VA, "10.77.0.1", 24, 0, "10.77.0.1/24");
    all("a pair, down");
    up(VA, "up va");
    /* No carrier yet, so no link-local address comes. */
    route(AF_INET, 1, "10.80.0.0", 16, NULL, VA, 5, 0, "10.80.0.0/16");
    route(AF_INET, 1, "10.81.0.0", 16, "10.77.0.2", 0, 0, 1400, "10.81.0.0/16 by a gateway");
    route(AF_INET, 1, "0.0.0.0", 0, "10.77.0.2", 0, 100, 0, "a default route");
    route(AF_INET, 1, "10.82.0.1", 32, NULL, VA, 0, 0, "10.82.0.1");
    route(AF_INET, 7, "10.83.0.0", 16, NULL, 0, 0, 0, "unreachable");
    route(AF_INET, 8, "10.84.0.0", 16, NULL, 0, 0, 0, "prohibit");
    route(AF_INET, 6, "10.85.0.0", 16, NULL, 0, 0, 0, "blackhole");
    route(AF_INET6, 7, "2001:db8:7::", 48, NULL, 0, 0, 0, "unreachable");
    route(AF_INET6, 6, "2001:db8:8::", 48, NULL, 0, 5, 0, "blackhole");
    struct body n = {0};
    const unsigned char nd[12] = {AF_INET, 0, 0, 0, (unsigned char)VA, (unsigned char)(VA >> 8), 0, 0, 0x80, 0, 0, 0};
    const unsigned char mac[6] = {2, 0, 0, 0, 0, 0x0b};
    raw(&n, nd, 12);
    ip(&n, AF_INET, 1, "10.77.0.2");
    put(&n, 2, mac, 6);
    request(RTM_NEWNEIGH, &n, "a permanent neighbour");
    all("routes");

    /* Whose namespace. */
    int own = open("/proc/net/dev", O_RDONLY);
    int down[2], from[2];
    if (pipe(down) < 0 || pipe(from) < 0) return 98;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        char c;
        if (read(down[0], &c, 1) != 1) _exit(1);
        if (unshare(CLONE_NEWNET) < 0) _exit(2);
        if (write(from[1], "u", 1) != 1 || read(down[0], &c, 1) != 1) _exit(3);
        _exit(0);
    }
    snprintf(path, sizeof path, "/proc/%d/net/dev", child);
    has_va(path, "a child's");
    int before = open(path, O_RDONLY);
    char c = 0;
    if (write(down[1], "g", 1) != 1 || read(from[0], &c, 1) != 1) printf("no child\n");
    has_va(path, "its own namespace's");
    got = result(pread(before, text, sizeof text - 1, 0));
    text[got < 0 ? 0 : got] = 0;
    printf("opened before: %s\n", strstr(text, " va:") ? "va" : "no va");
    char directory[64];
    snprintf(directory, sizeof directory, "/proc/%d/net", child);
    int held = open(directory, O_RDONLY | O_DIRECTORY);
    snprintf(path, sizeof path, "/proc/%d/task/%d/net/dev", child, child);
    has_va(path, "its thread's");
    if (write(down[1], "x", 1) != 1) printf("no child\n");
    siginfo_t info;
    waitid(P_PID, (id_t)child, &info, WEXITED | WNOWAIT);
    snprintf(path, sizeof path, "/proc/%d/net/dev", child);
    opened(path, O_RDONLY, "a zombie's file");
    struct stat s;
    got = result(stat(directory, &s));
    printf("its directory: stat=%ld mode=%o\n", got, s.st_mode);
    char entries[1024];
    printf("a zombie's names: %ld\n", result(syscall(SYS_getdents64, held, entries, sizeof entries)));
    int again = open(directory, O_RDONLY | O_DIRECTORY);
    printf("a zombie's directory: open=%d\n", again < 0 ? -errno : 0);
    printf("openat a zombie's: %d\n", openat(held, "dev", O_RDONLY) < 0 ? -errno : 0);
    waitpid(child, NULL, 0);
    opened(directory, O_RDONLY, "a reaped one's");
    users(CLONE_NEWUSER | CLONE_NEWNET, 0, "user and network namespaces at once");
    users(CLONE_NEWUSER, CLONE_NEWNET, "a user namespace, mapped, then a network one");
    unshare(CLONE_NEWNET);
    has_va("/proc/net/dev", "after unshare");
    got = result(pread(own, text, sizeof text - 1, 0));
    text[got < 0 ? 0 : got] = 0;
    printf("opened before it: %s\n", strstr(text, " va:") ? "va" : "no va");
    in_it = openat(dir, "dev", O_RDONLY);
    got = result(pread(in_it, text, sizeof text - 1, 0));
    text[got < 0 ? 0 : got] = 0;
    printf("in the directory opened before: %s\n", strstr(text, " va:") ? "va" : "no va");
    return 0;
}
