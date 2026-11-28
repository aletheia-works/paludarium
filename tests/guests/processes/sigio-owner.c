/* Who may be sent a file's SIGIO and SIGURG.
 *
 * F_SETOWN (and F_SETOWN_EX, and the owner dnotify gives a directory)
 * keeps the real and effective user IDs of whoever set the owner. A signal reaches a process only when the effective ID kept is
 * root's, or either kept ID is the process's real or saved one. Who makes
 * the file signal does not count, nor does a later F_SETSIG.
 *
 * A Landlock domain that scopes signals, when it set the owner, keeps the
 * signal from any process outside the domain, but not from the setter's own
 * process. A domain the setter enters later, or the domain of whoever makes
 * the file signal, does not count, and a scoped owner is still reached.
 *
 * Each case runs the setter and the owners as processes of their own, made
 * by a root parent: the setter takes its IDs, sets the owner and exits; an
 * owner takes its IDs, blocks the signals and reports which are pending
 * once the file has signalled. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define RT (SIGRTMIN + 1)

/* Landlock's ABI, which musl's headers do not have. */
struct ll_scoped_attr {
    unsigned long long fs, net, scoped;
};
#define LL_SCOPE_SIGNAL (1ULL << 1)

/* Enters a domain that scopes signals. */
static int scope_signals(void) {
    struct ll_scoped_attr attr = {0, 0, LL_SCOPE_SIGNAL};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return -1;
    long ruleset = syscall(444, &attr, sizeof attr, 0);
    if (ruleset < 0)
        return -1;
    long r = syscall(446, ruleset, 0);
    close(ruleset);
    return r < 0 ? -1 : 0;
}

/* A thread's real, effective and saved user IDs, as setresuid takes them. */
struct ids {
    unsigned uid, euid, suid;
};
static const struct ids ROOT = {0, 0, 0};

static int take_ids(struct ids ids) {
    return syscall(SYS_setresuid, ids.uid, ids.euid, ids.suid) < 0 ? -1 : 0;
}

/* An owner: a process of `ids`, with SIGIO, SIGURG and RT blocked, in the
   process group `group` (0 for its own, -1 for its parent's), maybe in a
   domain that scopes signals. It reports `ready` and then, when asked,
   which of the signals are pending. */
struct owner {
    pid_t pid;
    int ask, answer;
};
static struct owner start_owner(struct ids ids, pid_t group, int scoped) {
    int ask[2], answer[2];
    struct owner o = {-1, -1, -1};
    if (pipe(ask) || pipe(answer))
        return o;
    pid_t pid = fork();
    if (pid == 0) {
        close(ask[1]);
        close(answer[0]);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGIO);
        sigaddset(&set, SIGURG);
        sigaddset(&set, RT);
        sigprocmask(SIG_BLOCK, &set, NULL);
        if (group >= 0 && setpgid(0, group))
            _exit(80);
        if (scoped && scope_signals())
            _exit(81);
        if (take_ids(ids))
            _exit(82);
        char byte = 'r';
        if (write(answer[1], &byte, 1) != 1 || read(ask[0], &byte, 1) != 1)
            _exit(83);
        sigset_t pending;
        sigpending(&pending);
        int found = (sigismember(&pending, SIGIO) ? 1 : 0) | (sigismember(&pending, SIGURG) ? 2 : 0) |
                    (sigismember(&pending, RT) ? 4 : 0);
        if (write(answer[1], &found, sizeof found) != sizeof found)
            _exit(84);
        _exit(0);
    }
    close(ask[0]);
    close(answer[1]);
    char byte;
    if (pid < 0 || read(answer[0], &byte, 1) != 1)
        return o;
    o.pid = pid;
    o.ask = ask[1];
    o.answer = answer[0];
    return o;
}

/* What owner `o` has pending: "io", "urg", "rt" or "none". */
static const char *finish_owner(struct owner o) {
    static char text[4][16];
    static int next;
    char *out = text[next++ % 4];
    int found = -1;
    if (o.pid < 0 || write(o.ask, "a", 1) != 1 || read(o.answer, &found, sizeof found) != sizeof found)
        found = -1;
    waitpid(o.pid, NULL, 0);
    close(o.ask);
    close(o.answer);
    if (found < 0)
        return "lost";
    out[0] = 0;
    if (found & 1)
        strcat(out, "io,");
    if (found & 2)
        strcat(out, "urg,");
    if (found & 4)
        strcat(out, "rt,");
    if (!*out)
        return "none";
    out[strlen(out) - 1] = 0;
    return out;
}

/* How a setter names the owner. */
enum how { SETOWN, SETOWN_GROUP, SETOWN_EX, SETSIG_ONLY };

/* A setter: in a process of `ids`, maybe after entering a domain that
   scopes signals (`scoped` 1) or before entering one (`scoped` 2), names
   `pid` as the owner of `fd` the `how` way, or only sets F_SETSIG. Gives
   0 or the errno, or 98 with no owner to name: an owner that did not
   start has no PID, and -1 would name a process group. */
static int run_setter(struct ids ids, int scoped, int fd, enum how how, pid_t pid, int sig) {
    if (pid <= 0)
        return 98;
    pid_t child = fork();
    if (child == 0) {
        if (scoped == 1 && scope_signals())
            _exit(90);
        if (take_ids(ids))
            _exit(91);
        long r = 0;
        switch (how) {
        case SETOWN:
            r = fcntl(fd, F_SETOWN, pid);
            break;
        case SETOWN_GROUP:
            r = fcntl(fd, F_SETOWN, -pid);
            break;
        case SETOWN_EX: {
            struct f_owner_ex ex = {F_OWNER_PID, pid};
            r = fcntl(fd, F_SETOWN_EX, &ex);
            break;
        }
        case SETSIG_ONLY:
            break;
        }
        if (r == 0 && sig)
            r = fcntl(fd, F_SETSIG, sig);
        if (r == 0 && scoped == 2 && scope_signals())
            _exit(92);
        _exit(r < 0 ? errno : 0);
    }
    int status;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 99;
}

/* Makes the reading end of an O_ASYNC socket pair signal, by writing to
   the other end in a process that maybe scopes signals itself. */
static void make_readable(int writer, int scoped) {
    pid_t child = fork();
    if (child == 0) {
        if (scoped && scope_signals())
            _exit(1);
        _exit(write(writer, "x", 1) == 1 ? 0 : 1);
    }
    waitpid(child, NULL, 0);
}

struct io_case {
    const char *name;
    struct ids setter;
    int setter_scoped;
    enum how how;
    int sig;
    /* A second setter after the first, when `then_how` is not SETOWN or
       `then` differs from root's (all zero means none). */
    int then_used;
    struct ids then;
    enum how then_how;
    int then_sig;
    struct ids owner;
    int owner_scoped;
    int trigger_scoped;
};

static void io_case(const struct io_case *c) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) {
        printf("%s: socketpair %d\n", c->name, errno);
        return;
    }
    fcntl(pair[0], F_SETFL, fcntl(pair[0], F_GETFL) | O_ASYNC);
    struct owner o = start_owner(c->owner, -1, c->owner_scoped);
    int set = run_setter(c->setter, c->setter_scoped, pair[0], c->how, o.pid, c->sig);
    int then = c->then_used ? run_setter(c->then, 0, pair[0], c->then_how, o.pid, c->then_sig) : 0;
    make_readable(pair[1], c->trigger_scoped);
    printf("%s: set=%d then=%d owner=%s\n", c->name, set, then, finish_owner(o));
    close(pair[0]);
    close(pair[1]);
}

/* A process group of two owners, of `first` and `second`, named by a setter
   of `setter`, maybe scoped. */
static void group_case(const char *name, struct ids setter, struct ids first, struct ids second) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) {
        printf("%s: socketpair %d\n", name, errno);
        return;
    }
    fcntl(pair[0], F_SETFL, fcntl(pair[0], F_GETFL) | O_ASYNC);
    struct owner a = start_owner(first, 0, 0);
    struct owner b = start_owner(second, a.pid, 0);
    int set = run_setter(setter, 0, pair[0], SETOWN_GROUP, a.pid, 0);
    make_readable(pair[1], 0);
    const char *got_a = finish_owner(a);
    printf("%s: set=%d first=%s second=%s\n", name, set, got_a, finish_owner(b));
    close(pair[0]);
    close(pair[1]);
}

/* A setter that scopes signals and owns the file itself, then makes it
   signal: its own process is always reached. With `child`, it names a
   child it forks after entering the domain instead, which shares it. */
static void own_process_case(const char *name, int child) {
    int report[2];
    if (pipe(report))
        return;
    pid_t pid = fork();
    if (pid == 0) {
        close(report[0]);
        int pair[2];
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGIO);
        sigprocmask(SIG_BLOCK, &set, NULL);
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) || scope_signals())
            _exit(1);
        fcntl(pair[0], F_SETFL, fcntl(pair[0], F_GETFL) | O_ASYNC);
        int found = -1;
        if (child) {
            struct owner o = start_owner(ROOT, -1, 0);
            long r = fcntl(pair[0], F_SETOWN, o.pid);
            if (write(pair[1], "x", 1) != 1)
                _exit(2);
            const char *got = finish_owner(o);
            found = r < 0 ? -errno : strcmp(got, "io") == 0;
        } else {
            long r = fcntl(pair[0], F_SETOWN, getpid());
            if (write(pair[1], "x", 1) != 1)
                _exit(2);
            sigset_t pending;
            sigpending(&pending);
            found = r < 0 ? -errno : sigismember(&pending, SIGIO);
        }
        if (write(report[1], &found, sizeof found) != sizeof found)
            _exit(3);
        _exit(0);
    }
    close(report[1]);
    int found = -9;
    if (read(report[0], &found, sizeof found) != sizeof found)
        found = -9;
    waitpid(pid, NULL, 0);
    close(report[0]);
    printf("%s: io=%d\n", name, found);
}

/* A network namespace of its own, with its loopback up: the emulator
   gives internet sockets to a guest without a network only there. */
static void own_network(void) {
    if (unshare(CLONE_NEWNET)) {
        printf("unshare %d\n", errno);
        return;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strcpy(ifr.ifr_name, "lo");
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    if (u < 0 || ioctl(u, SIOCGIFFLAGS, &ifr))
        printf("lo %d\n", errno);
    ifr.ifr_flags |= IFF_UP;
    if (u >= 0 && ioctl(u, SIOCSIFFLAGS, &ifr))
        printf("lo up %d\n", errno);
    if (u >= 0)
        close(u);
}

/* SIGURG of a TCP connection's urgent byte, to the owner a setter of
   `setter` named, maybe scoped. */
static void urgent_case(const char *name, struct ids setter, int scoped, struct ids owner) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in at = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof at;
    if (listener < 0 || bind(listener, (struct sockaddr *)&at, sizeof at) || listen(listener, 1) ||
        getsockname(listener, (struct sockaddr *)&at, &len)) {
        printf("%s: listen %d\n", name, errno);
        return;
    }
    int client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0 || connect(client, (struct sockaddr *)&at, sizeof at)) {
        printf("%s: connect %d\n", name, errno);
        return;
    }
    int server = accept(listener, NULL, NULL);
    struct owner o = start_owner(owner, -1, 0);
    int set = run_setter(setter, scoped, server, SETOWN, o.pid, 0);
    long sent = send(client, "!", 1, MSG_OOB);
    /* The urgent mark shows once the byte, and its SIGURG, have come. */
    struct pollfd p = {server, POLLPRI, 0};
    int ready = poll(&p, 1, 5000);
    printf("%s: set=%d sent=%ld pri=%d owner=%s\n", name, set, sent, ready == 1 && (p.revents & POLLPRI),
           finish_owner(o));
    close(server);
    close(client);
    close(listener);
}

/* dnotify names the caller the owner, with the caller's IDs then. A caller
   that becomes another user afterwards is reached only while one of the
   IDs kept is its real or saved one. */
static void dnotify_case(const char *name, struct ids before, struct ids after) {
    const char *dir = "/tmp/paludarium-sigio-owner";
    mkdir(dir, 0777);
    chmod(dir, 0777);
    int report[2];
    if (pipe(report))
        return;
    pid_t pid = fork();
    if (pid == 0) {
        close(report[0]);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGIO);
        sigprocmask(SIG_BLOCK, &set, NULL);
        int fd = open(dir, O_RDONLY | O_DIRECTORY);
        if (fd < 0 || take_ids(before))
            _exit(1);
        long r = fcntl(fd, F_NOTIFY, DN_CREATE | DN_MULTISHOT);
        if (take_ids(after))
            _exit(2);
        char path[64];
        snprintf(path, sizeof path, "%s/made", dir);
        int made = open(path, O_CREAT | O_WRONLY, 0666);
        close(made);
        unlink(path);
        sigset_t pending;
        sigpending(&pending);
        int found = r < 0 ? -errno : sigismember(&pending, SIGIO);
        if (write(report[1], &found, sizeof found) != sizeof found)
            _exit(3);
        _exit(0);
    }
    close(report[1]);
    int found = -9;
    if (read(report[0], &found, sizeof found) != sizeof found)
        found = -9;
    int status;
    waitpid(pid, &status, 0);
    close(report[0]);
    rmdir(dir);
    printf("%s: io=%d exit=%d\n", name, found, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    const struct ids u1000 = {1000, 1000, 1000}, u2000 = {2000, 2000, 2000};
    const struct io_case cases[] = {
        /* The kept IDs against the owner's real and saved ones. */
        {.name = "same user", .setter = u1000, .owner = u1000},
        {.name = "other user", .setter = u1000, .owner = u2000},
        {.name = "root setter", .setter = ROOT, .owner = u2000},
        {.name = "effective root", .setter = {1000, 0, 0}, .owner = u2000},
        {.name = "effective is saved", .setter = {1000, 3000, 0}, .owner = {2000, 2000, 3000}},
        {.name = "real is saved", .setter = {3000, 1000, 0}, .owner = {2000, 2000, 3000}},
        {.name = "real is real", .setter = {2000, 1000, 0}, .owner = u2000},
        {.name = "owner effective only", .setter = u1000, .owner = {2000, 1000, 2000}},
        /* Every way of naming the owner keeps the IDs; F_SETSIG's signal
           meets the same check. */
        {.name = "setown_ex other", .setter = u1000, .how = SETOWN_EX, .owner = u2000},
        {.name = "setsig other", .setter = u1000, .sig = 1, .owner = u2000},
        {.name = "setsig same", .setter = u2000, .sig = 1, .owner = u2000},
        /* A later F_SETSIG keeps the IDs; a later F_SETOWN takes new ones. */
        {.name = "later setsig",
         .setter = ROOT,
         .then_used = 1,
         .then = u1000,
         .then_how = SETSIG_ONLY,
         .then_sig = 1,
         .owner = u2000},
        {.name = "later setown", .setter = ROOT, .then_used = 1, .then = u1000, .owner = u2000},
        /* Landlock: the setter's domain when it set the owner. */
        {.name = "scoped setter", .setter = ROOT, .setter_scoped = 1, .owner = ROOT},
        {.name = "scoped after setting", .setter = ROOT, .setter_scoped = 2, .owner = ROOT},
        {.name = "scoped owner", .setter = ROOT, .owner = ROOT, .owner_scoped = 1},
        {.name = "scoped trigger", .setter = ROOT, .owner = ROOT, .trigger_scoped = 1},
        {.name = "scoped then root",
         .setter = ROOT,
         .setter_scoped = 1,
         .then_used = 1,
         .then = ROOT,
         .owner = ROOT},
    };
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        /* F_SETSIG's signal stands for RT. */
        struct io_case c = cases[i];
        if (c.sig)
            c.sig = RT;
        if (c.then_sig)
            c.then_sig = RT;
        io_case(&c);
    }
    group_case("group", u1000, u1000, u2000);
    own_process_case("scoped own process", 0);
    own_process_case("scoped own child", 1);
    own_network();
    urgent_case("urgent same", u2000, 0, u2000);
    urgent_case("urgent other", u1000, 0, u2000);
    urgent_case("urgent scoped", ROOT, 1, ROOT);
    dnotify_case("dnotify kept", (struct ids){1000, 1000, 2000}, u2000);
    dnotify_case("dnotify root kept", (struct ids){0, 0, 0}, u2000);
    return 0;
}
