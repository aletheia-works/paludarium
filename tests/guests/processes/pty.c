/* Pseudo-terminals, compared with Linux: /dev/ptmx and /dev/pts, the line
   discipline's editing, echoes and signals, termios and window sizes, the
   controlling terminal and job control, and the hang-ups of either side.

   Linux hands what one side writes to the other's line discipline from a
   work queue, so a case reads what a side has been given by polling until it
   stays quiet for a while (`drain`), never by one read. Outputs are booleans
   and errno values, never pseudo-terminal numbers or process IDs. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#ifndef TIOCGPTPEER
#define TIOCGPTPEER 0x5441
#endif
#ifndef TIOCGPTLCK
#define TIOCGPTLCK 0x80045439
#endif
#ifndef TIOCGEXCL
#define TIOCGEXCL 0x80045440
#endif
#ifndef TIOCSIG
#define TIOCSIG 0x40045436
#endif
#ifndef TIOCGDEV
#define TIOCGDEV 0x80045432
#endif
#define K_TCGETS2 0x802c542a
#define K_TCSETS2 0x402c542b
#define K_BOTHER 010000

/* The kernel's struct termios2. */
struct ktermios {
    unsigned iflag, oflag, cflag, lflag;
    unsigned char line, cc[19];
    unsigned ispeed, ospeed;
};

static void say(const char *format, ...) {
    va_list list;
    va_start(list, format);
    vprintf(format, list);
    va_end(list);
    putchar('\n');
    fflush(stdout);
}

/* `label`, and the bytes, escaped. */
static void show(const char *label, const char *bytes, int count) {
    printf("%s %d \"", label, count);
    for (int i = 0; i < count; i++) {
        unsigned char c = bytes[i];
        if (c >= 0x20 && c < 0x7f && c != '\\' && c != '"') putchar(c);
        else printf("\\x%02x", c);
    }
    say("\"");
}

/* Reads what `fd` gives until it stays quiet for 100 ms, at its end or an
   error; each read's bytes are kept, with `|` between reads when `reads`.
   Returns the count, or -errno of a read that failed first. */
static int drain(int fd, char *buffer, int size, int reads) {
    int count = 0;
    for (;;) {
        struct pollfd p = {fd, POLLIN, 0};
        if (poll(&p, 1, 100) <= 0 || !(p.revents & (POLLIN | POLLHUP))) break;
        int n = read(fd, buffer + count, size - count - 1);
        if (n < 0) return count ? count : -errno;
        if (n == 0) {
            if (reads && count < size - 4) {
                memcpy(buffer + count, "<0>", 3);
                count += 3;
            }
            if (!reads) break;
            /* A canonical end of file reads 0; at a hang-up every read
               does. */
            struct pollfd q = {fd, POLLIN, 0};
            if (poll(&q, 1, 100) <= 0 || (q.revents & POLLHUP)) break;
            continue;
        }
        count += n;
        if (reads && count < size - 1) buffer[count++] = '|';
    }
    return count;
}

static void show_drained(const char *label, int fd, int reads) {
    char buffer[4096];
    int count = drain(fd, buffer, sizeof buffer, reads);
    if (count < 0) say("%s error %d", label, -count);
    else show(label, buffer, count);
}

/* Reads from the master until its end (EIO), as a program waiting for its
   child does. */
static void show_to_end(const char *label, int fd) {
    char buffer[8192];
    int count = 0, n;
    while ((n = read(fd, buffer + count, sizeof buffer - count)) > 0) count += n;
    show(label, buffer, count);
    say("%s end %d %d", label, n, n < 0 ? errno : 0);
}

/* Prints `label`, what `expression` returned and, when that is negative,
   errno. */
#define TRY(label, expression)                                       \
    do {                                                             \
        errno = 0;                                                   \
        long result_ = (long)(expression);                           \
        say("%s %ld %d", label, result_, result_ < 0 ? errno : 0); \
    } while (0)

static int kernel_get(int fd, struct ktermios *t) { return ioctl(fd, K_TCGETS2, t); }
static int kernel_set(int fd, struct ktermios *t) { return ioctl(fd, K_TCSETS2, t); }

static void set_flags(int fd, unsigned iflag, unsigned oflag, unsigned lflag) {
    struct termios t;
    tcgetattr(fd, &t);
    t.c_iflag = iflag;
    t.c_oflag = oflag;
    t.c_lflag = lflag;
    tcsetattr(fd, TCSANOW, &t);
}

static short polled(int fd, short events) {
    struct pollfd p = {fd, events, 0};
    poll(&p, 1, 100);
    return p.revents;
}

static long elapsed_ms(struct timeval *since) {
    struct timeval now;
    gettimeofday(&now, NULL);
    return (now.tv_sec - since->tv_sec) * 1000 + (now.tv_usec - since->tv_usec) / 1000;
}

static int wait_status(pid_t pid) {
    int status = 0;
    while (waitpid(pid, &status, WUNTRACED) < 0 && errno == EINTR) {}
    return status;
}

/* The pair, its numbering and locking, the slave's files and names, and
   what each side sees as the other closes. */
static int case_open(void) {
    char buffer[256];
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    say("posix_openpt %d", m >= 0);
    unsigned number = 0;
    say("TIOCGPTN %d", ioctl(m, TIOCGPTN, &number));
    char name[64];
    strcpy(name, ptsname(m));
    say("ptsname %d", !strncmp(name, "/dev/pts/", 9) && (unsigned)atoi(name + 9) == number);
    int locked = -1;
    TRY("TIOCGPTLCK", ioctl(m, TIOCGPTLCK, &locked));
    say("locked %d", locked);
    TRY("open locked", open(name, O_RDWR | O_NOCTTY));
    TRY("TIOCGPTPEER locked", ioctl(m, TIOCGPTPEER, O_RDWR | O_NOCTTY));
    /* The slave's line discipline takes it, echoing it at some time Linux's
       work queue decides: only the slave's read below shows it. */
    TRY("write without a slave", write(m, "x", 1));
    say("grantpt %d unlockpt %d", grantpt(m), unlockpt(m));
    TRY("TIOCGPTLCK", ioctl(m, TIOCGPTLCK, &locked));
    say("locked %d", locked);
    struct stat path, opened;
    say("stat slave %d", stat(name, &path));
    /* Its mode and group are devpts's mount options. */
    say("slave %d %d %d %d", S_ISCHR(path.st_mode), major(path.st_rdev) == 136,
        minor(path.st_rdev) == number, path.st_uid == getuid());
    int s = open(name, O_RDWR | O_NOCTTY);
    say("open slave %d", s >= 0);
    fstat(s, &opened);
    say("same inode %d %d %d", opened.st_ino == path.st_ino, opened.st_dev == path.st_dev,
        opened.st_rdev == path.st_rdev);
    say("isatty %d %d", isatty(m), isatty(s));
    say("ttyname %d", ttyname(s) && !strcmp(ttyname(s), name));
    struct statfs fs;
    TRY("fstatfs", fstatfs(s, &fs));
    say("f_type %#lx", (unsigned long)fs.f_type);
    struct stat master;
    fstat(m, &master);
    say("master %d %d %d", S_ISCHR(master.st_mode), major(master.st_rdev) == 5,
        minor(master.st_rdev) == 2);
    unsigned device = 0;
    TRY("TIOCGDEV", ioctl(m, TIOCGDEV, &device));
    say("device %d", device == ((136u << 8) | number));
    TRY("TIOCGPTN of the slave", ioctl(s, TIOCGPTN, &number));
    TRY("TIOCGPTPEER of the slave", ioctl(s, TIOCGPTPEER, O_RDWR));
    int peer = ioctl(m, TIOCGPTPEER, O_RDWR | O_NOCTTY | O_CLOEXEC);
    struct stat peer_stat;
    fstat(peer, &peer_stat);
    say("TIOCGPTPEER %d %d %d", peer >= 0, peer_stat.st_ino == path.st_ino,
        fcntl(peer, F_GETFD) == FD_CLOEXEC);
    char link[64], target[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", peer);
    ssize_t length = readlink(link, target, sizeof target - 1);
    target[length > 0 ? length : 0] = 0;
    say("peer link %d", !strcmp(target, name));
    int listed = 0, ptmx = 0;
    DIR *directory = opendir("/dev/pts");
    for (struct dirent *e; directory && (e = readdir(directory));) {
        listed |= !strcmp(e->d_name, name + 9);
        ptmx |= !strcmp(e->d_name, "ptmx");
    }
    if (directory) closedir(directory);
    say("listed %d %d", listed, ptmx);
    struct stat other;
    TRY("stat ptmx", stat("/dev/pts/ptmx", &other));
    say("ptmx %d", other.st_rdev == makedev(5, 2));
    TRY("stat a missing slave", stat("/dev/pts/4294967", &other));
    TRY("open a bad name", open("/dev/pts/x1", O_RDWR));
    say("poll the slave %#x", polled(s, POLLIN | POLLOUT));
    /* Through, and back with the echo. */
    say("write %zd", write(m, "in\n", 3));
    say("read %zd", read(s, buffer, sizeof buffer));
    say("write %zd", write(s, "out\n", 4));
    show_drained("master reads", m, 0);
    /* Every slave description closed: the master reads what is left, then
       EIO, and is hung up; a write is EIO. */
    write(s, "left", 4);
    close(s);
    close(peer);
    show_drained("after the slave", m, 0);
    TRY("read", read(m, buffer, 1));
    say("poll %#x", polled(m, POLLIN | POLLOUT));
    TRY("write", write(m, "x", 1));
    say("still named %d", stat(name, &other));
    s = open(name, O_RDWR | O_NOCTTY);
    say("open again %d poll %#x", s >= 0, polled(m, POLLIN | POLLOUT));
    /* The master closed: the slave is hung up. */
    close(m);
    TRY("unnamed", stat(name, &other));
    say("read %zd", read(s, buffer, 1));
    TRY("write", write(s, "x", 1));
    struct termios t;
    TRY("tcgetattr", tcgetattr(s, &t));
    pid_t group = getpgrp();
    TRY("TIOCSPGRP", ioctl(s, TIOCSPGRP, &group));
    say("poll %#x", polled(s, POLLIN | POLLOUT));
    say("F_GETFL %#o", fcntl(s, F_GETFL) & 03);
    close(s);
    return 0;
}

/* The slave's termios, through either side, its speeds and fixed control
   flags, the window size, and what the queues hold. */
static int case_termios(void) {
    int m, s;
    if (openpty(&m, &s, NULL, NULL, NULL)) return 1;
    struct ktermios t;
    say("TCGETS2 %d", kernel_get(s, &t));
    say("flags %#o %#o %#o %#o line %d speeds %u %u", t.iflag, t.oflag, t.cflag, t.lflag, t.line,
        t.ispeed, t.ospeed);
    printf("cc");
    for (int i = 0; i < 19; i++) printf(" %d", t.cc[i]);
    say("");
    struct ktermios from_master;
    kernel_get(m, &from_master);
    say("the master's are the slave's %d", !memcmp(&t, &from_master, sizeof t));
    /* B9600 with parity and 7 bits, through the master: a pseudo-terminal
       keeps 8 bits and no parity. */
    t.cflag = (t.cflag & ~(CBAUD | CSIZE)) | B9600 | PARENB | CS7;
    t.line = 3;
    say("TCSETS2 %d", kernel_set(m, &t));
    kernel_get(s, &t);
    say("cflag %#o line %d speeds %u %u", t.cflag, t.line, t.ispeed, t.ospeed);
    t.cflag |= B1200 << 16;
    kernel_set(s, &t);
    kernel_get(s, &t);
    say("input speed %u %u", t.ispeed, t.ospeed);
    t.cflag = (t.cflag & ~(CBAUD | (CBAUD << 16))) | K_BOTHER;
    t.ospeed = 12345;
    t.ispeed = 777;
    kernel_set(s, &t);
    kernel_get(s, &t);
    say("other speed %#o %u %u", t.cflag & CBAUD, t.ispeed, t.ospeed);
    struct termios libc;
    tcgetattr(s, &libc);
    say("cfgetospeed %d", cfgetospeed(&libc) == K_BOTHER);
    t.cflag = (t.cflag & ~CBAUD) | B38400;
    t.line = 0;
    kernel_set(s, &t);
    struct winsize w = {0};
    TRY("TIOCGWINSZ", ioctl(s, TIOCGWINSZ, &w));
    say("window %d %d %d %d", w.ws_row, w.ws_col, w.ws_xpixel, w.ws_ypixel);
    struct winsize set = {24, 80, 640, 480};
    say("TIOCSWINSZ %d", ioctl(m, TIOCSWINSZ, &set));
    ioctl(s, TIOCGWINSZ, &w);
    say("from the slave %d %d %d %d", w.ws_row, w.ws_col, w.ws_xpixel, w.ws_ypixel);
    TRY("TIOCGWINSZ bad address", ioctl(m, TIOCGWINSZ, (void *)8));
    /* A canonical slave counts whole lines; a raw one every byte. */
    write(m, "ab\ncd", 5);
    polled(s, POLLIN);
    int count = -1;
    TRY("FIONREAD", ioctl(s, FIONREAD, &count));
    say("unread %d", count);
    TRY("TIOCOUTQ", ioctl(s, TIOCOUTQ, &count));
    say("unwritten %d", count);
    show_drained("echo", m, 0);
    set_flags(s, ICRNL, OPOST | ONLCR, ISIG | ECHO);
    ioctl(s, FIONREAD, &count);
    say("raw FIONREAD %d", count);
    set_flags(s, ICRNL | IXON, OPOST | ONLCR, ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL |
              ECHOKE | IEXTEN);
    /* TCSETSF discards the input. */
    tcgetattr(s, &libc);
    say("TCSETSF %d", tcsetattr(s, TCSAFLUSH, &libc));
    ioctl(s, FIONREAD, &count);
    say("flushed %d", count);
    write(s, "out", 3);
    polled(m, POLLIN);
    ioctl(m, FIONREAD, &count);
    say("master FIONREAD %d", count);
    say("TCFLSH %d", tcflush(m, TCIFLUSH));
    ioctl(m, FIONREAD, &count);
    say("master flushed %d poll %#x", count, polled(m, POLLIN));
    TRY("TCFLSH 3", ioctl(s, TCFLSH, 3));
    /* TCOOFF stops the slave's output; TCOON starts it. */
    say("TCOOFF %d", tcflow(s, TCOOFF));
    fcntl(s, F_SETFL, O_NONBLOCK);
    TRY("write stopped", write(s, "x", 1));
    say("poll stopped %#x", polled(s, POLLOUT));
    say("TCOON %d", tcflow(s, TCOON));
    say("write %zd", write(s, "y", 1));
    fcntl(s, F_SETFL, 0);
    show_drained("started", m, 0);
    say("TCIOFF %d", tcflow(s, TCIOFF));
    show_drained("stop character", m, 0);
    say("tcdrain %d tcsendbreak %d", tcdrain(s), tcsendbreak(s, 0));
    int discipline = -1;
    TRY("TIOCGETD", ioctl(s, TIOCGETD, &discipline));
    say("discipline %d", discipline);
    discipline = 0;
    say("TIOCSETD %d", ioctl(s, TIOCSETD, &discipline));
    discipline = 31;
    TRY("TIOCSETD 31", ioctl(s, TIOCSETD, &discipline));
    int exclusive = -1;
    ioctl(s, TIOCEXCL);
    TRY("TIOCGEXCL", ioctl(s, TIOCGEXCL, &exclusive));
    say("exclusive %d", exclusive);
    ioctl(s, TIOCNXCL);
    ioctl(s, TIOCGEXCL, &exclusive);
    say("TIOCNXCL %d", exclusive);
    TRY("unknown request", ioctl(s, 0x54ff, 0));
    TRY("TIOCMGET", ioctl(s, TIOCMGET, &count));
    return 0;
}

/* Types `input` at the master and shows each read of the slave, then the
   echo. */
static void type(int m, int s, const char *label, const char *input, int length) {
    write(m, input, length);
    char name[64];
    snprintf(name, sizeof name, "%s reads", label);
    show_drained(name, s, 1);
    snprintf(name, sizeof name, "%s echo", label);
    show_drained(name, m, 0);
}

/* Canonical mode: editing, the echoes each flag asks for, line ends, and the
   input and output conversions. */
static int case_canonical(void) {
    int m, s;
    if (openpty(&m, &s, NULL, NULL, NULL)) return 1;
    const unsigned iflag = ICRNL | IXON, oflag = OPOST | ONLCR;
    const unsigned lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN;
#define TYPE(label, text) type(m, s, label, text, sizeof text - 1)
    TYPE("lines", "hello\rwor\177ld\n");
    TYPE("kill", "abc\025x\004");
    TYPE("word", "one two\027three\n");
    TYPE("literal", "\026\003\026\177\n");
    TYPE("end of file", "\004");
    TYPE("reprint", "abc\022\n");
    TYPE("tab", "a\tb\177\177\n");
    TYPE("control", "\001\177x\n");
    TYPE("kill control", "a\002\025\n");
    char small[4];
    write(m, "abcdef\n", 7);
    polled(s, POLLIN);
    ssize_t first = read(s, small, sizeof small);
    show("small read", small, first);
    first = read(s, small, sizeof small);
    show("small read", small, first);
    show_drained("small echo", m, 0);
    set_flags(s, iflag, oflag, lflag | ECHOPRT);
    TYPE("echoprt", "abc\177\177d\n");
    set_flags(s, iflag, oflag, lflag & ~ECHOKE);
    TYPE("echok", "ab\025c\n");
    set_flags(s, iflag, oflag, lflag & ~(ECHOE | ECHOKE));
    TYPE("no echoe", "ab\177c\n");
    set_flags(s, iflag, oflag, (lflag & ~ECHO) | ECHONL);
    TYPE("echonl", "secret\n");
    set_flags(s, iflag, oflag, lflag & ~ECHOCTL);
    TYPE("no echoctl", "a\001\177\n");
    struct termios t;
    set_flags(s, iflag, oflag, lflag);
    tcgetattr(s, &t);
    t.c_cc[VEOL] = ';';
    t.c_cc[VEOL2] = '#';
    tcsetattr(s, TCSANOW, &t);
    TYPE("eol", "a;b#c\n");
    t.c_cc[VEOL] = 0;
    t.c_cc[VEOL2] = 0;
    t.c_cc[VERASE] = 0;
    tcsetattr(s, TCSANOW, &t);
    TYPE("disabled", "a\000\177\n");
    t.c_cc[VERASE] = 0177;
    tcsetattr(s, TCSANOW, &t);
    set_flags(s, iflag | IGNCR, oflag, lflag);
    TYPE("igncr", "a\rb\n");
    set_flags(s, INLCR, oflag, lflag);
    TYPE("inlcr", "a\n\004");
    set_flags(s, iflag | IUCLC, oflag, lflag);
    TYPE("iuclc", "AbC\n");
    set_flags(s, iflag | ISTRIP, oflag, lflag);
    TYPE("istrip", "\341\n");
    set_flags(s, iflag, oflag, lflag & ~ICANON);
    TYPE("raw echo", "a\rb\n\001");
    set_flags(s, iflag, oflag, lflag);
    /* What the slave writes, as c_oflag says. */
    const struct {
        const char *label;
        unsigned oflag;
        const char *text;
    } outputs[] = {
        {"onlcr", OPOST | ONLCR, "a\nb\r\n"},
        {"olcuc xtabs", OPOST | ONLCR | OLCUC | XTABS, "ab\tc\td\n"},
        {"onocr", OPOST | ONOCR, "\rx\r\r"},
        {"ocrnl", OPOST | OCRNL, "a\rb\n"},
        {"onlret", OPOST | ONLRET | OCRNL, "ab\rc"},
        {"no opost", ONLCR | OLCUC, "a\nb"},
    };
    for (unsigned i = 0; i < sizeof outputs / sizeof *outputs; i++) {
        set_flags(s, iflag, outputs[i].oflag, lflag);
        write(s, outputs[i].text, strlen(outputs[i].text));
        show_drained(outputs[i].label, m, 0);
    }
    set_flags(s, iflag, oflag, lflag);
    /* ^S stops the output, ^Q starts it, and with IXANY any character
       does. */
    write(m, "\023", 1);
    polled(m, POLLIN);
    fcntl(s, F_SETFL, O_NONBLOCK);
    usleep(50000);
    TRY("stopped write", write(s, "x", 1));
    write(m, "q\021", 2);
    usleep(50000);
    say("started write %zd", write(s, "y", 1));
    show_drained("flow", m, 0);
    show_drained("flow reads", s, 1);
    set_flags(s, iflag | IXANY, oflag, lflag);
    write(m, "\023", 1);
    usleep(50000);
    TRY("stopped write", write(s, "x", 1));
    write(m, "z", 1);
    usleep(50000);
    say("any character %zd", write(s, "w", 1));
    show_drained("ixany", m, 0);
    fcntl(s, F_SETFL, 0);
    return 0;
}

/* Non-canonical mode: VMIN and VTIME, and switching modes with input
   waiting. */
static int case_raw(void) {
    int m, s;
    if (openpty(&m, &s, NULL, NULL, NULL)) return 1;
    struct termios t;
    tcgetattr(s, &t);
    struct termios canonical = t;
    t.c_iflag = 0;
    t.c_oflag = 0;
    t.c_lflag = 0;
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
    tcsetattr(s, TCSANOW, &t);
    write(m, "a\rb\003\004\n", 6);
    show_drained("raw reads", s, 0);
    show_drained("raw echo", m, 0);
    write(s, "x\ny", 3);
    show_drained("raw output", m, 0);
    char buffer[16];
    struct timeval since;
    t.c_cc[VMIN] = 0;
    tcsetattr(s, TCSANOW, &t);
    say("min 0 time 0 %zd", read(s, buffer, sizeof buffer));
    t.c_cc[VTIME] = 2;
    tcsetattr(s, TCSANOW, &t);
    gettimeofday(&since, NULL);
    ssize_t n = read(s, buffer, sizeof buffer);
    say("min 0 time 2 %zd waited %d", n, elapsed_ms(&since) >= 150);
    write(m, "q", 1);
    polled(s, POLLIN);
    say("min 0 time 2 with input %zd", read(s, buffer, sizeof buffer));
    t.c_cc[VMIN] = 3;
    t.c_cc[VTIME] = 0;
    tcsetattr(s, TCSANOW, &t);
    write(m, "12", 2);
    usleep(50000);
    say("min 3 poll %#x", polled(s, POLLIN));
    fcntl(s, F_SETFL, O_NONBLOCK);
    n = read(s, buffer, sizeof buffer);
    say("min 3 nonblocking %zd", n);
    TRY("again", read(s, buffer, sizeof buffer));
    fcntl(s, F_SETFL, 0);
    write(m, "345", 3);
    usleep(50000);
    say("min 3 poll %#x", polled(s, POLLIN));
    say("min 3 read %zd", read(s, buffer, sizeof buffer));
    write(m, "67", 2);
    usleep(50000);
    say("min 3 short buffer %zd", read(s, buffer, 1));
    write(m, "89", 2);
    usleep(50000);
    say("min 3 rest %zd", read(s, buffer, sizeof buffer));
    t.c_cc[VMIN] = 2;
    t.c_cc[VTIME] = 1;
    tcsetattr(s, TCSANOW, &t);
    write(m, "x", 1);
    gettimeofday(&since, NULL);
    n = read(s, buffer, sizeof buffer);
    say("min 2 time 1 %zd", n);
    /* Raw input becomes one line in canonical mode; a canonical end of
       file reads as a 0 byte in raw mode. */
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
    tcsetattr(s, TCSANOW, &t);
    write(m, "x\ny", 3);
    usleep(50000);
    polled(s, POLLIN);
    tcsetattr(s, TCSANOW, &canonical);
    show_drained("to canonical", s, 1);
    show_drained("to canonical echo", m, 0);
    write(m, "ab\004", 3);
    polled(s, POLLIN);
    tcsetattr(s, TCSANOW, &t);
    show_drained("to raw", s, 1);
    return 0;
}

/* The controlling terminal: taking it, /dev/tty, the foreground group, job
   control and letting it go. */
static int case_session(void) {
    int m, s;
    if (openpty(&m, &s, NULL, NULL, NULL)) return 1;
    char name[64];
    strcpy(name, ttyname(s));
    pid_t child = fork();
    if (child == 0) {
        close(m);
        TRY("TIOCSCTTY before setsid", ioctl(s, TIOCSCTTY, 0));
        say("setsid %d", setsid() == getpid());
        TRY("tcgetsid", tcgetsid(s));
        TRY("tcgetpgrp", tcgetpgrp(s));
        TRY("open /dev/tty", open("/dev/tty", O_RDWR));
        say("TIOCSCTTY %d", ioctl(s, TIOCSCTTY, 0));
        say("tcgetsid %d tcgetpgrp %d", tcgetsid(s) == getpid(), tcgetpgrp(s) == getpgrp());
        say("TIOCSCTTY again %d", ioctl(s, TIOCSCTTY, 0));
        int other_m, other_s;
        openpty(&other_m, &other_s, NULL, NULL, NULL);
        TRY("TIOCSCTTY of another", ioctl(other_s, TIOCSCTTY, 0));
        close(other_s);
        close(other_m);
        int tty = open("/dev/tty", O_RDWR);
        struct stat st;
        fstat(tty, &st);
        say("/dev/tty %d %d %d", tty >= 0, major(st.st_rdev) == 5, minor(st.st_rdev) == 0);
        write(tty, "through /dev/tty\n", 17);
        close(tty);
        pid_t bad = 0x3ffffff0;
        TRY("tcsetpgrp missing", tcsetpgrp(s, bad));
        TRY("tcsetpgrp other session", tcsetpgrp(s, getppid()));
        TRY("tcsetpgrp negative", ioctl(s, TIOCSPGRP, &(pid_t){-1}));
        /* A job in the foreground. */
        int ready[2];
        pipe(ready);
        pid_t job = fork();
        if (job == 0) {
            setpgid(0, 0);
            char byte;
            read(ready[0], &byte, 1);
            _exit(0);
        }
        setpgid(job, job);
        TRY("tcsetpgrp", tcsetpgrp(s, job));
        say("foreground %d", tcgetpgrp(s) == job);
        /* The leader is in the background now, its group orphaned. */
        char buffer[8];
        TRY("background read", read(s, buffer, 1));
        say("background write %zd", write(s, "bg\n", 3));
        struct termios t;
        tcgetattr(s, &t);
        TRY("background tcsetattr", tcsetattr(s, TCSANOW, &t));
        signal(SIGTTOU, SIG_IGN);
        t.c_lflag |= TOSTOP;
        say("tcsetattr ignoring SIGTTOU %d", tcsetattr(s, TCSANOW, &t));
        say("TOSTOP write ignoring SIGTTOU %zd", write(s, "ok\n", 3));
        signal(SIGTTOU, SIG_DFL);
        TRY("TOSTOP write", write(s, "no\n", 3));
        /* A background group that is not orphaned stops. */
        for (int which = 0; which < 4; which++) {
            pid_t reader = fork();
            if (reader == 0) {
                setpgid(0, 0);
                if (which == 1) signal(SIGTTIN, SIG_IGN);
                if (which == 2) {
                    sigset_t set;
                    sigemptyset(&set);
                    sigaddset(&set, SIGTTIN);
                    sigprocmask(SIG_BLOCK, &set, NULL);
                }
                errno = 0;
                ssize_t n = which == 3 ? write(s, "w", 1) : read(s, buffer, 1);
                _exit(n < 0 ? errno : 100);
            }
            setpgid(reader, reader);
            int status = wait_status(reader);
            if (WIFSTOPPED(status)) {
                say("job %d stopped by %d", which, WSTOPSIG(status));
                kill(reader, SIGKILL);
                wait_status(reader);
            } else {
                say("job %d exited %d", which, WEXITSTATUS(status));
            }
        }
        signal(SIGTTOU, SIG_IGN);
        TRY("tcsetpgrp back", tcsetpgrp(s, getpgrp()));
        say("foreground %d", tcgetpgrp(s) == getpgrp());
        signal(SIGTTOU, SIG_DFL);
        write(ready[1], "x", 1);
        wait_status(job);
        /* A process other than the leader lets the terminal go alone. */
        pid_t member = fork();
        if (member == 0) {
            say("member TIOCNOTTY %d", ioctl(s, TIOCNOTTY));
            TRY("member /dev/tty", open("/dev/tty", O_RDWR));
            _exit(0);
        }
        wait_status(member);
        say("leader still has it %d", tcgetsid(s) == getpid());
        /* The leader's TIOCNOTTY hangs up its foreground group. */
        signal(SIGHUP, SIG_IGN);
        say("TIOCNOTTY %d", ioctl(s, TIOCNOTTY));
        TRY("after TIOCNOTTY", tcgetsid(s));
        TRY("TIOCNOTTY again", ioctl(s, TIOCNOTTY));
        /* Opening it without O_NOCTTY takes it again, not for writing
           only. */
        int again = open(name, O_WRONLY);
        TRY("write-only open", tcgetsid(again));
        close(again);
        again = open(name, O_RDWR);
        say("open takes it %d", tcgetsid(again) == getpid());
        _exit(7);
    }
    close(s);
    int status = wait_status(child);
    show_to_end("master", m);
    say("child %d", WEXITSTATUS(status));
    return 0;
}

static int signals_pipe[2];
static void record(int number) {
    char byte = number;
    write(signals_pipe[1], &byte, 1);
}

/* Signals from the terminal to its foreground group. */
static int case_signals(void) {
    int m, s;
    if (openpty(&m, &s, NULL, NULL, NULL)) return 1;
    pipe(signals_pipe);
    pid_t child = fork();
    if (child == 0) {
        close(m);
        setsid();
        ioctl(s, TIOCSCTTY, 0);
        int handled[] = {SIGINT, SIGQUIT, SIGTSTP, SIGWINCH, SIGUSR1};
        for (unsigned i = 0; i < sizeof handled / sizeof *handled; i++) {
            struct sigaction action = {.sa_handler = record, .sa_flags = SA_RESTART};
            sigaction(handled[i], &action, NULL);
        }
        raise(SIGUSR1);
        for (;;) pause();
    }
    char byte;
    read(signals_pipe[0], &byte, 1);
    say("ready %d", byte);
    say("tcgetpgrp of the master %d tcgetsid %d", tcgetpgrp(m) == child, tcgetsid(m) == child);
    int count = -1;
    const struct {
        const char *label, *text;
    } typed[] = {{"intr", "ab\003"}, {"quit", "cd\034"}, {"susp", "ef\032"}};
    for (unsigned i = 0; i < 3; i++) {
        write(m, typed[i].text, 3);
        read(signals_pipe[0], &byte, 1);
        ioctl(s, FIONREAD, &count);
        say("%s %d unread %d", typed[i].label, byte, count);
    }
    show_drained("echo", m, 0);
    struct termios t;
    tcgetattr(m, &t);
    t.c_lflag |= NOFLSH;
    tcsetattr(m, TCSANOW, &t);
    write(m, "gh\003", 3);
    read(signals_pipe[0], &byte, 1);
    write(m, "\n", 1);
    char line[16];
    ssize_t n = read(s, line, sizeof line);
    say("noflsh %d", byte);
    show("kept", line, n);
    show_drained("noflsh echo", m, 0);
    say("TIOCSIG %d", ioctl(m, TIOCSIG, SIGQUIT));
    read(signals_pipe[0], &byte, 1);
    say("signal %d", byte);
    TRY("TIOCSIG 9", ioctl(m, TIOCSIG, SIGKILL));
    TRY("TIOCSIG of the slave", ioctl(s, TIOCSIG, SIGINT));
    struct winsize w = {10, 20, 0, 0};
    say("TIOCSWINSZ %d", ioctl(m, TIOCSWINSZ, &w));
    read(signals_pipe[0], &byte, 1);
    say("signal %d", byte);
    /* The same size again sends nothing. */
    ioctl(s, TIOCSWINSZ, &w);
    ioctl(m, TIOCSIG, SIGINT);
    read(signals_pipe[0], &byte, 1);
    say("next signal %d", byte);
    t.c_lflag &= ~ISIG;
    tcsetattr(m, TCSANOW, &t);
    write(m, "\003\n", 2);
    n = read(s, line, sizeof line);
    show("no isig", line, n);
    kill(child, SIGTERM);
    int status = wait_status(child);
    say("child %d %d", WIFSIGNALED(status), WTERMSIG(status));
    show_drained("echo", m, 0);
    return 0;
}

static volatile sig_atomic_t hangups, continues;
static void on_hangup(int number) {
    if (number == SIGHUP) hangups++;
    else continues++;
    char byte = number;
    write(signals_pipe[1], &byte, 1);
}

/* The master's close hangs up the slave and tells the session's leader; the
   leader's exit tells its foreground group. */
static int case_hangup(void) {
    prctl(PR_SET_CHILD_SUBREAPER, 1);
    int m, s;
    if (openpty(&m, &s, NULL, NULL, NULL)) return 1;
    char name[64];
    strcpy(name, ttyname(s));
    pipe(signals_pipe);
    pid_t child = fork();
    if (child == 0) {
        close(m);
        close(s);
        setsid();
        int tty = open(name, O_RDWR);
        say("taken on open %d", tcgetsid(tty) == getpid());
        struct sigaction action = {.sa_handler = on_hangup};
        sigaction(SIGHUP, &action, NULL);
        sigaction(SIGCONT, &action, NULL);
        sigset_t all, none;
        sigfillset(&all);
        sigemptyset(&none);
        sigprocmask(SIG_BLOCK, &all, NULL);
        write(signals_pipe[1], "r", 1);
        while (!hangups || !continues) sigsuspend(&none);
        say("hangup %d %d", hangups, continues);
        char buffer[4];
        say("read %zd", read(tty, buffer, sizeof buffer));
        TRY("write", write(tty, "x", 1));
        TRY("tcgetsid", tcgetsid(tty));
        TRY("/dev/tty", open("/dev/tty", O_RDWR));
        say("poll %#x", polled(tty, POLLIN | POLLOUT));
        _exit(0);
    }
    close(s);
    char byte;
    read(signals_pipe[0], &byte, 1);
    char order[2];
    close(m);
    for (int got = 0; got < 2;) {
        ssize_t n = read(signals_pipe[0], order + got, 2 - got);
        if (n <= 0) break;
        got += n;
    }
    int status = wait_status(child);
    /* Linux runs the second handler first, nested in the first. */
    say("signals %d %d", order[0] < order[1] ? order[0] : order[1],
        order[0] < order[1] ? order[1] : order[0]);
    say("child %d", WEXITSTATUS(status));
    /* A leader's exit hangs up its foreground job. */
    if (openpty(&m, &s, NULL, NULL, NULL)) return 1;
    close(signals_pipe[0]);
    close(signals_pipe[1]);
    pipe(signals_pipe);
    hangups = 0;
    child = fork();
    if (child == 0) {
        close(m);
        setsid();
        ioctl(s, TIOCSCTTY, 0);
        pid_t job = fork();
        if (job == 0) {
            setpgid(0, 0);
            struct sigaction action = {.sa_handler = on_hangup};
            sigaction(SIGHUP, &action, NULL);
            write(signals_pipe[1], "j", 1);
            while (!hangups) pause();
            _exit(tcgetsid(s) < 0 ? errno : 0);
        }
        setpgid(job, job);
        tcsetpgrp(s, job);
        char ready;
        read(signals_pipe[0], &ready, 1);
        _exit(4);
    }
    close(s);
    status = wait_status(child);
    say("leader %d", WEXITSTATUS(status));
    read(signals_pipe[0], &byte, 1);
    say("job got %d", byte);
    pid_t job = wait(&status);
    say("job %d sees %d", job > 0, WEXITSTATUS(status));
    show_to_end("master", m);
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    /* A case that waits for good ends with what it printed so far. */
    alarm(20);
    if (!strcmp(mode, "pty-open")) return case_open();
    if (!strcmp(mode, "pty-termios")) return case_termios();
    if (!strcmp(mode, "pty-canonical")) return case_canonical();
    if (!strcmp(mode, "pty-raw")) return case_raw();
    if (!strcmp(mode, "pty-session")) return case_session();
    if (!strcmp(mode, "pty-signals")) return case_signals();
    if (!strcmp(mode, "pty-hangup")) return case_hangup();
    return 2;
}
