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
#include <sys/syscall.h>
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
#ifndef TIOCVHANGUP
#define TIOCVHANGUP 0x5437
#endif
#ifndef TIOCGPKT
#define TIOCGPKT 0x80045438
#endif
#define K_TCGETA 0x5405
#define K_TCSETA 0x5406
#define K_TCSETAF 0x5408
#define K_TIOCGLCKTRMIOS 0x5456
#define K_TIOCSLCKTRMIOS 0x5457
#define K_EXTPROC 0200000
#define K_TCGETS2 0x802c542a
#define K_TCSETS2 0x402c542b
#define K_BOTHER 010000

/* The kernel's struct termio. */
struct ktermio {
    unsigned short iflag, oflag, cflag, lflag;
    unsigned char line, cc[8];
};

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
    /* Whether the slave's line discipline has echoed the "x" yet is Linux's
       work queue's timing, so only POLLOUT is looked at. */
    say("open again %d poll %#x", s >= 0, polled(m, POLLOUT));
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
/* A master in packet mode reads the slave's flushes, stops, starts and
   flow-control changes as a status byte alone, and data after a 0 byte. */
static int case_packet(void) {
    int m, s;
    if (openpty(&m, &s, NULL, NULL, NULL)) return 1;
    int on = 1, off = 0, mode = -1;
    TRY("TIOCPKT slave", ioctl(s, TIOCPKT, &on));
    TRY("TIOCGPKT slave", ioctl(s, TIOCGPKT, &mode));
    TRY("TIOCGPKT", ioctl(m, TIOCGPKT, &mode));
    say("mode %d", mode);
    TRY("TIOCPKT fault", ioctl(m, TIOCPKT, NULL));
    /* Events before packet mode are not kept. */
    tcflush(s, TCIFLUSH);
    TRY("TIOCPKT", ioctl(m, TIOCPKT, &on));
    TRY("TIOCGPKT", ioctl(m, TIOCGPKT, &mode));
    say("mode %d", mode);
    say("poll empty %#x", polled(m, POLLIN | POLLPRI));
    write(s, "hi", 2);
    show_drained("data", m, 1);
    tcflush(s, TCIFLUSH);
    say("poll flush %#x", polled(m, POLLIN | POLLPRI));
    show_drained("flush input", m, 1);
    tcflush(s, TCOFLUSH);
    show_drained("flush output", m, 1);
    tcflush(s, TCIOFLUSH);
    show_drained("flush both", m, 1);
    /* The master's own flushes are not events. */
    tcflush(m, TCIOFLUSH);
    show_drained("master flush", m, 1);
    tcflow(s, TCOOFF);
    show_drained("tcoff", m, 1);
    tcflow(s, TCOOFF);
    show_drained("tcoff again", m, 1);
    tcflow(s, TCOON);
    show_drained("tcon", m, 1);
    /* Two events before a read: a start forgets the stop. */
    tcflow(s, TCOOFF);
    tcflow(s, TCOON);
    show_drained("stop then start", m, 1);
    struct termios t;
    tcgetattr(s, &t);
    t.c_iflag &= ~IXON;
    tcsetattr(s, TCSANOW, &t);
    show_drained("no ixon", m, 1);
    t.c_iflag |= IXON;
    tcsetattr(m, TCSANOW, &t);
    show_drained("ixon from master", m, 1);
    t.c_cc[VSTOP] = 1;
    tcsetattr(s, TCSANOW, &t);
    show_drained("other stop char", m, 1);
    t.c_cc[VSTOP] = 023;
    tcsetattr(s, TCSAFLUSH, &t);
    show_drained("tcsaflush", m, 1);
    t.c_lflag |= K_EXTPROC;
    tcsetattr(s, TCSANOW, &t);
    show_drained("extproc", m, 1);
    t.c_lflag &= ~K_EXTPROC;
    tcsetattr(s, TCSANOW, &t);
    show_drained("extproc off", m, 1);
    /* ^S and ^Q typed, and ^C, which flushes both ways and echoes. */
    write(m, "\023", 1);
    show_drained("typed stop", m, 1);
    write(m, "\021", 1);
    show_drained("typed start", m, 1);
    write(m, "ab\003", 3);
    show_drained("interrupt", m, 1);
    /* A one-byte read of data gives the 0 byte alone. */
    write(s, "xy", 2);
    char buffer[8];
    usleep(100000);
    TRY("short read", read(m, buffer, 1));
    say("short byte %d", buffer[0]);
    show_drained("rest", m, 1);
    TRY("TIOCPKT off", ioctl(m, TIOCPKT, &off));
    tcflush(s, TCIFLUSH);
    write(s, "z", 1);
    show_drained("off", m, 1);
    close(s);
    close(m);
    return 0;
}

static void show_termio(const char *label, struct ktermio *t) {
    printf("%s %04x %04x %04x %04x %d", label, t->iflag, t->oflag, t->cflag, t->lflag, t->line);
    for (int i = 0; i < 8; i++) printf(" %d", t->cc[i]);
    say("");
}

/* The old struct termio, and the slave's locked termios. */
static int case_termio(void) {
    int m, s;
    if (openpty(&m, &s, NULL, NULL, NULL)) return 1;
    struct ktermio t;
    memset(&t, 0xff, sizeof t);
    TRY("TCGETA", ioctl(s, K_TCGETA, &t));
    show_termio("slave", &t);
    TRY("TCGETA master", ioctl(m, K_TCGETA, &t));
    show_termio("master", &t);
    TRY("TCGETA fault", ioctl(s, K_TCGETA, NULL));
    TRY("TCSETA fault", ioctl(s, K_TCSETA, NULL));
    /* The high bits of the flags and the other characters stay. */
    struct termios full;
    tcgetattr(s, &full);
    full.c_lflag |= K_EXTPROC;
    full.c_cc[VEOL2] = 7;
    tcsetattr(s, TCSANOW, &full);
    t.lflag &= ~ECHO;
    t.cc[VINTR] = 1;
    t.cflag = (t.cflag & ~CBAUD) | B9600 | PARENB;
    TRY("TCSETA", ioctl(m, K_TCSETA, &t));
    tcgetattr(s, &full);
    say("after %o %o %o %d %d speed %d %d", full.c_lflag, full.c_cflag, full.c_iflag,
        full.c_cc[VINTR], full.c_cc[VEOL2], (int)cfgetospeed(&full), (int)cfgetispeed(&full));
    /* TCSETAF drops the input. */
    cfmakeraw(&full);
    tcsetattr(s, TCSANOW, &full);
    write(m, "abc", 3);
    polled(s, POLLIN);
    int count = -1;
    ioctl(s, FIONREAD, &count);
    say("queued %d", count);
    ioctl(s, K_TCGETA, &t);
    TRY("TCSETAF", ioctl(s, K_TCSETAF, &t));
    ioctl(s, FIONREAD, &count);
    say("queued after %d", count);
    struct termios locked;
    memset(&locked, 0xff, sizeof locked);
    TRY("TIOCGLCKTRMIOS", ioctl(s, K_TIOCGLCKTRMIOS, &locked));
    unsigned char *bytes = (unsigned char *)&locked;
    int nonzero = 0;
    for (int i = 0; i < 36; i++) nonzero += bytes[i] != 0;
    say("locked nonzero %d", nonzero);
    TRY("TIOCGLCKTRMIOS master", ioctl(m, K_TIOCGLCKTRMIOS, &locked));
    TRY("TIOCGLCKTRMIOS fault", ioctl(s, K_TIOCGLCKTRMIOS, NULL));
    /* Only CAP_SYS_ADMIN locks, which is checked first. */
    if (geteuid() != 0) TRY("TIOCSLCKTRMIOS", ioctl(s, K_TIOCSLCKTRMIOS, NULL));
    else say("TIOCSLCKTRMIOS -1 1");
    close(s);
    close(m);
    return 0;
}

/* Fields 7 and 8 of /proc/<pid>/stat: the controlling terminal and its
   foreground group. */
static void stat_terminal(pid_t pid, long *tty, long *tpgid) {
    char path[64], line[1024];
    snprintf(path, sizeof path, "/proc/%d/stat", (int)pid);
    FILE *f = fopen(path, "r");
    *tty = *tpgid = -2;
    if (!f) return;
    if (fgets(line, sizeof line, f)) {
        char *rest = strrchr(line, ')');
        if (rest) sscanf(rest + 2, "%*c %*d %*d %*d %ld %ld", tty, tpgid);
    }
    fclose(f);
}

static int case_proc_stat(void) {
    int m, s;
    if (openpty(&m, &s, NULL, NULL, NULL)) return 1;
    struct stat st;
    fstat(s, &st);
    int ready[2], done[2];
    pipe(ready);
    pipe(done);
    pid_t child = fork();
    if (child == 0) {
        long tty, tpgid;
        setsid();
        stat_terminal(getpid(), &tty, &tpgid);
        say("no terminal %ld %ld", tty, tpgid);
        ioctl(s, TIOCSCTTY, 0);
        stat_terminal(getpid(), &tty, &tpgid);
        say("terminal %d tpgid %d", tty == (long)st.st_rdev, tpgid == getpgrp());
        pid_t job = fork();
        if (job == 0) {
            setpgid(0, 0);
            pause();
            _exit(0);
        }
        setpgid(job, job);
        tcsetpgrp(s, job);
        stat_terminal(getpid(), &tty, &tpgid);
        say("job %d tpgid %d", tty == (long)st.st_rdev, tpgid == job);
        stat_terminal(job, &tty, &tpgid);
        say("job's own %d tpgid %d", tty == (long)st.st_rdev, tpgid == job);
        write(ready[1], "r", 1);
        char byte;
        read(done[0], &byte, 1);
        kill(job, SIGKILL);
        waitpid(job, NULL, 0);
        stat_terminal(getpid(), &tty, &tpgid);
        say("job gone %d tpgid %d", tty == (long)st.st_rdev, tpgid == job);
        ioctl(s, TIOCNOTTY);
        stat_terminal(getpid(), &tty, &tpgid);
        say("released %ld %ld", tty, tpgid);
        _exit(0);
    }
    char byte;
    read(ready[0], &byte, 1);
    long tty, tpgid;
    stat_terminal(child, &tty, &tpgid);
    say("child from parent %d tpgid %d", tty == (long)st.st_rdev, tpgid > 0 && tpgid != child);
    write(done[1], "d", 1);
    waitpid(child, NULL, 0);
    return 0;
}

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

/* The queued signals of `number` that came, each as its code, band and
   whether its descriptor is `fd`, the same in a row once. Waits for Linux's
   work queue first. */
static void collect(const char *label, int number, int fd) {
    usleep(100000);
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, number);
    struct timespec none = {0, 0};
    siginfo_t info;
    int count = 0, last_code = 0;
    long last_band = 0;
    printf("%s", label);
    while (sigtimedwait(&set, &info, &none) == number) {
        if (count++ && info.si_code == last_code && info.si_band == last_band) continue;
        last_code = info.si_code;
        last_band = info.si_band;
        printf(" %d/%#lx/%d", info.si_code, info.si_band, info.si_fd == fd);
    }
    say("%s", count ? "" : " none");
}

static void show_owner(const char *label, int fd) {
    struct f_owner_ex owner = {-1, -1};
    fcntl(fd, F_GETOWN_EX, &owner);
    int own = fcntl(fd, F_GETOWN);
    say("%s type %d self %d group %d", label, owner.type, own == getpid(),
        own < 0 && -own == getpgrp());
}

/* O_ASYNC on either side: who owns a file it is turned on for, which input
   signals (a whole line in canonical mode, any byte otherwise), the room
   after a short write, and the hang-up that turns it off. */
static int case_async(void) {
    int m, s;
    if (openpty(&m, &s, NULL, NULL, NULL)) return 1;
    int in = SIGRTMIN + 1, out = SIGRTMIN + 2;
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, in);
    sigaddset(&block, out);
    sigaddset(&block, SIGIO);
    sigprocmask(SIG_BLOCK, &block, NULL);
    show_owner("before", s);
    TRY("F_SETFL", fcntl(s, F_SETFL, O_ASYNC));
    say("O_ASYNC %d", (fcntl(s, F_GETFL) & O_ASYNC) != 0);
    show_owner("slave", s);
    fcntl(s, F_SETSIG, in);
    /* Canonical input signals at the end of a line. */
    write(m, "ab", 2);
    collect("partial line", in, s);
    write(m, "c\n", 2);
    collect("line", in, s);
    char buffer[8192];
    read(s, buffer, sizeof buffer);
    write(m, "\004", 1);
    collect("end of file", in, s);
    read(s, buffer, sizeof buffer);
    struct termios t;
    tcgetattr(s, &t);
    cfmakeraw(&t);
    tcsetattr(s, TCSANOW, &t);
    collect("raw", in, s);
    write(m, "x", 1);
    collect("raw byte", in, s);
    read(s, buffer, sizeof buffer);
    /* The master: an owner set before stays. */
    TRY("F_SETOWN master", fcntl(m, F_SETOWN, getpid()));
    int one = 1;
    TRY("FIOASYNC master", ioctl(m, FIOASYNC, &one));
    say("master O_ASYNC %d", (fcntl(m, F_GETFL) & O_ASYNC) != 0);
    show_owner("master", m);
    fcntl(m, F_SETSIG, out);
    write(s, "out", 3);
    collect("slave output", out, m);
    read(m, buffer, sizeof buffer);
    collect("master read", out, m);
    /* Packet events wake the master but do not signal. */
    int on = 1;
    ioctl(m, TIOCPKT, &on);
    tcflow(s, TCOOFF);
    say("packet poll %#x", polled(m, POLLPRI));
    collect("packet stop", out, m);
    tcflow(s, TCOON);
    read(m, buffer, sizeof buffer);
    collect("packet start", out, m);
    ioctl(m, TIOCPKT, &(int){0});
    /* A master that fills the slave's input gets POLL_OUT for room once the
       slave reads; a write that went whole does not. */
    fcntl(m, F_SETFL, O_ASYNC | O_NONBLOCK);
    fcntl(s, F_SETFL, O_ASYNC | O_NONBLOCK);
    long written = 0;
    for (;;) {
        ssize_t n = write(m, buffer, sizeof buffer);
        if (n <= 0) break;
        written += n;
    }
    say("filled %d %d", written > 4096, errno);
    collect("full", out, m);
    collect("slave input", in, s);
    long taken = 0;
    for (int quiet = 0; quiet < 3;) {
        ssize_t n = read(s, buffer, sizeof buffer);
        if (n > 0) {
            taken += n;
            quiet = 0;
        } else {
            quiet++;
            usleep(20000);
        }
    }
    say("drained %d", taken == written);
    sigset_t pending;
    sigpending(&pending);
    say("room %d", sigismember(&pending, out));
    collect("room", out, m);
    /* The slave's descriptions lose O_ASYNC with the master's close, and
       cannot take it again. */
    close(m);
    say("hung up O_ASYNC %d", (fcntl(s, F_GETFL) & O_ASYNC) != 0);
    TRY("F_SETFL hung up", fcntl(s, F_SETFL, O_ASYNC));
    TRY("FIOASYNC hung up", ioctl(s, FIOASYNC, &one));
    TRY("F_SETFL hung up other", fcntl(s, F_SETFL, O_NONBLOCK));
    close(s);
    /* The slave's foreground group owns a file that had no owner. */
    if (openpty(&m, &s, NULL, NULL, NULL)) return 1;
    pid_t child = fork();
    if (child == 0) {
        close(m);
        setsid();
        ioctl(s, TIOCSCTTY, 0);
        TRY("F_SETFL controlling", fcntl(s, F_SETFL, O_ASYNC));
        show_owner("controlling", s);
        int again = open(ttyname(s), O_RDWR);
        TRY("F_SETOWN 0", fcntl(again, F_SETOWN, 0));
        fcntl(again, F_SETFL, O_ASYNC);
        show_owner("no owner", again);
        _exit(0);
    }
    waitpid(child, NULL, 0);
    close(s);
    close(m);
    return 0;
}

/* What a hung-up file of either side answers. */
static void show_hung_up(const char *label, int fd) {
    char buffer[8];
    TRY(label, read(fd, buffer, sizeof buffer));
    TRY("  write", write(fd, "x", 1));
    TRY("  TIOCGPGRP", ioctl(fd, TIOCGPGRP, &(int){0}));
    TRY("  TIOCSPGRP", ioctl(fd, TIOCSPGRP, &(int){0}));
    say("  poll %#x", polled(fd, POLLIN | POLLOUT));
}

/* As root: TIOCVHANGUP of the slave and of the master, vhangup, and
   TIOCCONS, and what a process without the capabilities gets. */
static int case_vhangup(void) {
    int m, s;
    if (openpty(&m, &s, NULL, NULL, NULL)) return 1;
    char name[64];
    strcpy(name, ttyname(s));
    pid_t child = fork();
    if (child == 0) {
        setuid(65534);
        TRY("TIOCVHANGUP user", ioctl(s, TIOCVHANGUP));
        TRY("TIOCVHANGUP user master", ioctl(m, TIOCVHANGUP));
        TRY("TIOCCONS user", ioctl(s, TIOCCONS));
        TRY("TIOCCONS user master", ioctl(m, TIOCCONS));
        TRY("vhangup user", syscall(SYS_vhangup));
        _exit(0);
    }
    waitpid(child, NULL, 0);
    /* Only without a controlling terminal, which it would hang up. */
    int own = open("/dev/tty", O_RDONLY);
    if (own < 0) TRY("vhangup without a terminal", syscall(SYS_vhangup));
    else {
        say("vhangup without a terminal 0 0");
        close(own);
    }
    /* The slave hangs up with the master open; the session it controls
       loses it, its leader told. */
    struct termios t;
    tcgetattr(s, &t);
    t.c_lflag &= ~ECHO;
    tcsetattr(s, TCSANOW, &t);
    signal(SIGIO, SIG_IGN);
    fcntl(s, F_SETFL, O_ASYNC);
    write(m, "ab\n", 3);
    polled(s, POLLIN);
    pipe(signals_pipe);
    child = fork();
    if (child == 0) {
        close(m);
        close(s);
        setsid();
        int tty = open(name, O_RDWR);
        struct sigaction action = {.sa_handler = on_hangup};
        sigaction(SIGHUP, &action, NULL);
        sigaction(SIGCONT, &action, NULL);
        sigset_t all, none;
        sigfillset(&all);
        sigemptyset(&none);
        sigprocmask(SIG_BLOCK, &all, NULL);
        write(signals_pipe[1], "r", 1);
        while (!hangups || !continues) sigsuspend(&none);
        say("leader told %d %d", hangups, continues);
        TRY("leader tcgetsid", tcgetsid(tty));
        TRY("leader /dev/tty", open("/dev/tty", O_RDWR));
        _exit(0);
    }
    char byte;
    read(signals_pipe[0], &byte, 1);
    int hung = ioctl(s, TIOCVHANGUP), error = errno;
    waitpid(child, NULL, 0);
    say("TIOCVHANGUP %d %d", hung, hung < 0 ? error : 0);
    show_hung_up("slave read", s);
    say("O_ASYNC %d", (fcntl(s, F_GETFL) & O_ASYNC) != 0);
    TRY("F_SETFL", fcntl(s, F_SETFL, O_ASYNC));
    /* The line discipline is gone: the master's input waits, unechoed,
       until an open brings it back and the master writes again. */
    show_drained("echo before", m, 1);
    write(m, "cd", 2);
    show_drained("echo gone", m, 1);
    int again = open(name, O_RDWR | O_NOCTTY);
    say("reopened %d", again >= 0);
    tcgetattr(again, &t);
    say("termios reset %d", (t.c_lflag & ECHO) != 0);
    show_drained("echo on open", m, 1);
    show_drained("input on open", again, 1);
    write(m, "e\n", 2);
    show_drained("echo after", m, 1);
    show_drained("input after", again, 1);
    close(s);
    /* The master hangs up alone: its file reads nothing, while the slave
       still writes. */
    TRY("TIOCVHANGUP master", ioctl(m, TIOCVHANGUP));
    show_hung_up("master read", m);
    TRY("  TIOCGPTN", ioctl(m, TIOCGPTN, &(int){0}));
    TRY("slave write", write(again, "y", 1));
    TRY("slave TIOCGPGRP", ioctl(again, TIOCGPGRP, &(int){0}));
    say("slave poll %#x", polled(again, POLLIN | POLLOUT));
    close(m);
    say("slave poll closed %#x", polled(again, POLLIN | POLLOUT));
    close(again);
    /* vhangup hangs up the caller's controlling terminal. */
    if (openpty(&m, &s, NULL, NULL, NULL)) return 1;
    hangups = continues = 0;
    child = fork();
    if (child == 0) {
        close(m);
        setsid();
        ioctl(s, TIOCSCTTY, 0);
        struct sigaction action = {.sa_handler = on_hangup};
        sigaction(SIGHUP, &action, NULL);
        sigaction(SIGCONT, &action, NULL);
        TRY("vhangup", syscall(SYS_vhangup));
        say("vhangup told %d %d", hangups, continues);
        TRY("vhangup tcgetsid", tcgetsid(s));
        TRY("vhangup TIOCSCTTY", ioctl(s, TIOCSCTTY, 0));
        _exit(0);
    }
    waitpid(child, NULL, 0);
    close(s);
    close(m);
    /* One terminal takes the console's output at a time, until it hangs
       up. */
    int m2, s2;
    if (openpty(&m, &s, NULL, NULL, NULL) || openpty(&m2, &s2, NULL, NULL, NULL)) return 1;
    int reader = open(ttyname(s), O_RDONLY | O_NOCTTY);
    TRY("TIOCCONS master", ioctl(m, TIOCCONS));
    TRY("TIOCCONS read only", ioctl(reader, TIOCCONS));
    TRY("TIOCCONS", ioctl(s, TIOCCONS));
    TRY("TIOCCONS again", ioctl(s, TIOCCONS));
    TRY("TIOCCONS other", ioctl(s2, TIOCCONS));
    ioctl(s, TIOCVHANGUP);
    TRY("TIOCCONS after hang-up", ioctl(s2, TIOCCONS));
    ioctl(s2, TIOCVHANGUP);
    TRY("TIOCCONS free", ioctl(s, TIOCCONS));
    close(reader);
    close(s);
    close(s2);
    close(m2);
    close(m);
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
    if (!strcmp(mode, "pty-packet")) return case_packet();
    if (!strcmp(mode, "pty-termio")) return case_termio();
    if (!strcmp(mode, "pty-proc-stat")) return case_proc_stat();
    if (!strcmp(mode, "pty-async")) return case_async();
    if (!strcmp(mode, "pty-vhangup")) return case_vhangup();
    return 2;
}
