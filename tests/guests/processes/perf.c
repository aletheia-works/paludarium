/* perf_event_open, compared with Linux: the order of its checks and their
   errors, and the software events the emulator counts (task-clock,
   cpu-clock and the dummy event) with read, the read formats, groups, the
   ENABLE, DISABLE, RESET and ID ioctls, enable_on_exec, prctl's
   PR_TASK_PERF_EVENTS_DISABLE and ENABLE of the events a thread opened,
   inherit, which counts the children a task makes, and the page faults,
   context switches and CPU migrations a thread makes, with and without
   exclude_user and exclude_kernel; and mmap of an event's ring buffer:
   its user page, the sizes and mappings it takes, its AUX area, a fork's
   child, which has none of it, and the pages a user may lock; and
   output to another event's buffer, with PERF_EVENT_IOC_SET_OUTPUT and
   PERF_FLAG_FD_OUTPUT.

   Counts and times are given as whether they are 0, grew or stayed,
   never as values, and IDs as whether they match. Hardware events are not
   opened: a CI machine may or may not have a PMU. The size Linux writes
   back for a structure too large is not printed either, as it grows with
   each kernel. The cases run as root, as the guest does. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

/* struct perf_event_attr as of PERF_ATTR_SIZE_VER8 (136 bytes), which
   every kernel the tests run on knows. */
struct attr {
    uint32_t type, size;
    uint64_t config, sample_period, sample_type, read_format, flags;
    uint32_t wakeup_events, bp_type;
    uint64_t config1, config2, branch_sample_type, sample_regs_user;
    uint32_t sample_stack_user;
    int32_t clockid;
    uint64_t sample_regs_intr;
    uint32_t aux_watermark;
    uint16_t sample_max_stack, reserved_2;
    uint32_t aux_sample_size, aux_action;
    uint64_t sig_data, config3;
};

#define DISABLED (1ULL << 0)
#define INHERIT (1ULL << 1)
#define EXCLUDE_USER (1ULL << 4)
#define EXCLUDE_KERNEL (1ULL << 5)
#define EXCLUDE_HV (1ULL << 6)
#define FREQ (1ULL << 10)
#define ENABLE_ON_EXEC (1ULL << 12)
#define USE_CLOCKID (1ULL << 25)
#define WRITE_BACKWARD (1ULL << 27)
#define AUX_OUTPUT (1ULL << 31)
#define INHERIT_THREAD (1ULL << 35)
#define REMOVE_ON_EXEC (1ULL << 36)
#define ATTR_SIGTRAP (1ULL << 37)

#define SAMPLE_TID (1ULL << 1)
#define SAMPLE_READ (1ULL << 4)
#define SAMPLE_BRANCH_STACK (1ULL << 11)
#define SAMPLE_REGS_USER (1ULL << 12)
#define SAMPLE_STACK_USER (1ULL << 13)
#define SAMPLE_WEIGHT (1ULL << 14)
#define SAMPLE_WEIGHT_STRUCT (1ULL << 24)

#define FORMAT_ENABLED 1
#define FORMAT_RUNNING 2
#define FORMAT_ID 4
#define FORMAT_GROUP 8

#define IOC_ENABLE _IO('$', 0)
#define IOC_DISABLE _IO('$', 1)
#define IOC_REFRESH _IO('$', 2)
#define IOC_RESET _IO('$', 3)
#define IOC_PERIOD _IOW('$', 4, uint64_t)
#define IOC_SET_OUTPUT _IO('$', 5)
#define IOC_ID _IOR('$', 7, uint64_t *)
#define IOC_FLAG_GROUP 1

#define FLAG_FD_NO_GROUP 1
#define FLAG_FD_OUTPUT 2
#define FLAG_PID_CGROUP 4
#define FLAG_FD_CLOEXEC 8

static void say(const char *format, ...) {
    va_list list;
    va_start(list, format);
    vprintf(format, list);
    va_end(list);
    putchar('\n');
    fflush(stdout);
}

#define TRY(call) ({ long try_result = (call); try_result < 0 ? -errno : try_result; })

static long open_event(void *attr, int pid, int cpu, int group, unsigned long flags) {
    long fd = syscall(SYS_perf_event_open, attr, pid, cpu, group, flags);
    return fd < 0 ? -errno : fd;
}

/* A software event of this thread, counting user time only. */
static struct attr software(uint64_t config) {
    struct attr a;
    memset(&a, 0, sizeof a);
    a.type = 1;
    a.size = sizeof a;
    a.config = config;
    a.flags = EXCLUDE_KERNEL | EXCLUDE_HV;
    return a;
}

/* What an error case gives: an fd is closed and shown as "fd". */
static void attempt(const char *name, struct attr a, int pid, int cpu, int group, unsigned long flags) {
    long fd = open_event(&a, pid, cpu, group, flags);
    if (fd >= 0) {
        close((int)fd);
        say("%s fd", name);
    } else {
        say("%s %ld", name, fd);
    }
}

static volatile uint64_t sink;
static void spin(void) {
    for (int i = 0; i < 200000; i++) sink += (uint64_t)i;
}

static uint64_t count(int fd) {
    uint64_t value = 0;
    if (read(fd, &value, sizeof value) != sizeof value) return (uint64_t)-1;
    return value;
}

static int case_calls(void) {
    struct attr a = software(1);
    attempt("flags", a, 0, -1, -1, 0x10);
    say("fault %ld", open_event(NULL, 0, -1, -1, 0));
    /* Sizes: 0 is the first one's, 64 bytes. */
    a.size = 0;
    attempt("size 0", a, 0, -1, -1, 0);
    a.size = 1;
    long result = open_event(&a, 0, -1, -1, 0);
    say("size 1 %ld written %d", result, a.size != 1);
    a = software(1);
    a.size = 0x2000;
    result = open_event(&a, 0, -1, -1, 0);
    say("size 0x2000 %ld written %d", result, a.size != 0x2000);
    unsigned char big[512];
    memset(big, 0, sizeof big);
    a = software(1);
    a.size = 300;
    memcpy(big, &a, sizeof a);
    {
        long fd = open_event(big, 0, -1, -1, 0);
        say("size 300 zero tail %s", fd >= 0 ? "fd" : "error");
        if (fd >= 0) close((int)fd);
        big[299] = 1;
        fd = open_event(big, 0, -1, -1, 0);
        uint32_t written;
        memcpy(&written, big + 4, 4);
        say("size 300 tail %ld written %d", fd, written != 300);
    }

    /* The fields perf_copy_attr checks. */
    a = software(1);
    a.flags |= 1ULL << 63;
    attempt("reserved flag", a, 0, -1, -1, 0);
    a = software(1);
    a.reserved_2 = 1;
    attempt("reserved 2", a, 0, -1, -1, 0);
    a = software(1);
    a.aux_action = 1 << 5;
    attempt("reserved 3", a, 0, -1, -1, 0);
    a = software(1);
    a.sample_type = 1ULL << 40;
    attempt("sample type", a, 0, -1, -1, 0);
    a = software(1);
    a.read_format = 1 << 9;
    attempt("read format", a, 0, -1, -1, 0);
    a = software(1);
    a.sample_type = SAMPLE_BRANCH_STACK;
    a.branch_sample_type = 1;
    attempt("branch only plm", a, 0, -1, -1, 0);
    a.branch_sample_type = 1ULL << 40;
    attempt("branch unknown", a, 0, -1, -1, 0);
    a.branch_sample_type = 1 << 3;
    attempt("branch software", a, 0, -1, -1, 0);
    a = software(1);
    a.sample_type = SAMPLE_REGS_USER;
    attempt("regs none", a, 0, -1, -1, 0);
    a.sample_regs_user = 1 << 12;
    attempt("regs ds", a, 0, -1, -1, 0);
    a.sample_regs_user = 1 << 26;
    attempt("regs reserved", a, 0, -1, -1, 0);
    a.sample_regs_user = 1ULL << 32;
    attempt("regs xmm", a, 0, -1, -1, 0);
    a.sample_regs_user = 0xff;
    attempt("regs", a, 0, -1, -1, 0);
    a = software(1);
    a.sample_type = SAMPLE_STACK_USER;
    a.sample_stack_user = 65535;
    attempt("stack too big", a, 0, -1, -1, 0);
    a.sample_stack_user = 12;
    attempt("stack unaligned", a, 0, -1, -1, 0);
    a = software(1);
    a.sample_type = SAMPLE_WEIGHT | SAMPLE_WEIGHT_STRUCT;
    attempt("weights", a, 0, -1, -1, 0);
    a = software(1);
    a.flags |= INHERIT_THREAD;
    attempt("inherit thread", a, 0, -1, -1, 0);
    a = software(1);
    a.flags |= REMOVE_ON_EXEC | ENABLE_ON_EXEC;
    attempt("remove and enable on exec", a, 0, -1, -1, 0);
    a = software(1);
    a.flags |= ATTR_SIGTRAP;
    attempt("sigtrap", a, 0, -1, -1, 0);
    a.flags |= REMOVE_ON_EXEC;
    attempt("sigtrap of no task", a, -1, 0, -1, 0);

    /* Then sys_perf_event_open's own. */
    a = software(1);
    a.sample_period = 1ULL << 63;
    attempt("period", a, 0, -1, -1, 0);
    a = software(1);
    a.flags |= FREQ;
    a.sample_period = 1000000000;
    attempt("frequency", a, 0, -1, -1, 0);
    a = software(1);
    attempt("cgroup of no cpu", a, 0, -1, -1, FLAG_PID_CGROUP);
    int null = open("/dev/null", O_RDONLY);
    attempt("group of a file", a, 0, -1, null, 0);
    close(null);
    attempt("group of no file", a, 0, -1, 999, 0);
    attempt("no task", a, 0x7fffffff, -1, -1, 0);
    attempt("no task and no cpu", a, -1, -1, -1, 0);
    attempt("no such cpu", a, 0, 100000, -1, 0);
    attempt("cpu -2", a, 0, -2, -1, 0);
    a = software(1);
    a.flags |= INHERIT;
    a.sample_type = SAMPLE_READ;
    attempt("inherit sample read", a, 0, -1, -1, 0);
    a = software(1);
    a.flags |= AUX_OUTPUT;
    attempt("aux output", a, 0, -1, -1, 0);
    a = software(1);
    a.flags |= USE_CLOCKID;
    a.clockid = 3;
    attempt("thread clock", a, 0, -1, -1, 0);
    a.clockid = 1;
    attempt("monotonic clock", a, 0, -1, -1, 0);

    /* The events. */
    a = software(99);
    attempt("software 99", a, 0, -1, -1, 0);
    a = software(12);
    attempt("software max", a, 0, -1, -1, 0);
    for (int config = 0; config <= 1; config++) {
        a = software((uint64_t)config);
        attempt(config ? "task-clock" : "cpu-clock", a, 0, -1, -1, 0);
        attempt(config ? "task-clock of cpu 0" : "cpu-clock of cpu 0", a, -1, 0, -1, 0);
    }
    a = software(9);
    attempt("dummy", a, 0, -1, -1, 0);
    a = software(1);
    a.type = 1000;
    attempt("other type", a, 0, -1, -1, 0);
    return 0;
}

static int case_counts(void) {
    struct attr a = software(1);
    a.read_format = FORMAT_ENABLED | FORMAT_RUNNING | FORMAT_ID;
    int fd = (int)open_event(&a, 0, -1, -1, FLAG_FD_CLOEXEC);
    say("open %d cloexec %d access %d", fd >= 0, (fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0,
        fcntl(fd, F_GETFL) & O_ACCMODE);
    char path[64], link[64];
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    ssize_t length = readlink(path, link, sizeof link - 1);
    link[length < 0 ? 0 : length] = 0;
    say("link %s", link);
    uint64_t values[4];
    say("short read %ld", TRY(read(fd, values, 31)));
    spin();
    ssize_t n = read(fd, values, sizeof values);
    uint64_t id = 0;
    long got = TRY(ioctl(fd, IOC_ID, &id));
    say("read %zd counted %d enabled %d running %d id %ld same %d", n, values[0] > 0, values[1] > 0,
        values[2] > 0 && values[2] <= values[1], got, id == values[3]);
    say("write %ld", TRY(write(fd, values, 8)));
    say("unknown ioctl %ld", TRY(ioctl(fd, _IO('$', 99), 0)));
    say("refresh %ld", TRY(ioctl(fd, IOC_REFRESH, 1)));
    uint64_t period = 1000;
    say("period %ld", TRY(ioctl(fd, IOC_PERIOD, &period)));
    close(fd);

    /* Disabled, enabled, disabled again and reset. */
    a = software(1);
    a.flags |= DISABLED;
    fd = (int)open_event(&a, 0, -1, -1, 0);
    spin();
    say("disabled %d", count(fd) == 0);
    say("enable %ld", TRY(ioctl(fd, IOC_ENABLE, 0)));
    spin();
    uint64_t first = count(fd);
    say("counted %d", first > 0 && first != (uint64_t)-1);
    say("disable %ld", TRY(ioctl(fd, IOC_DISABLE, 0)));
    first = count(fd);
    spin();
    say("stays %d", count(fd) == first);
    say("reset %ld", TRY(ioctl(fd, IOC_RESET, 0)));
    say("after reset %d", count(fd) == 0);
    close(fd);

    /* cpu-clock counts too; the dummy event never does. */
    a = software(0);
    fd = (int)open_event(&a, 0, -1, -1, 0);
    spin();
    say("cpu-clock counted %d", count(fd) > 0);
    close(fd);
    a = software(9);
    fd = (int)open_event(&a, 0, -1, -1, 0);
    spin();
    say("dummy %d", count(fd) == 0);
    close(fd);

    /* A group: the leader reads them all. */
    a = software(1);
    a.flags |= DISABLED;
    a.read_format = FORMAT_GROUP | FORMAT_ID;
    int leader = (int)open_event(&a, 0, -1, -1, 0);
    /* A member of the leader's own PMU. One of another software PMU keeps
       its own PMU context in Linux and runs for a part of its leader's time
       that changes from run to run (fork run 43896857630 on x86-64
       Ubuntu 7.0), where the emulator counts it with its leader (see the
       limitations page). */
    struct attr b = software(1);
    b.flags |= DISABLED;
    int member = (int)open_event(&b, 0, -1, leader, 0);
    say("member %d", member >= 0);
    attempt("member of a member", b, 0, -1, member, 0);
    attempt("other cpu", b, 0, 0, leader, 0);
    attempt("other task", b, -1, 0, leader, 0);
    struct attr c = b;
    c.flags |= 1ULL << 2;
    attempt("pinned member", c, 0, -1, leader, 0);
    c = b;
    c.flags |= INHERIT;
    attempt("inherit differs", c, 0, -1, leader, 0);
    attempt("no group", b, 0, 0, leader, FLAG_FD_NO_GROUP);
    say("enable group %ld", TRY(ioctl(leader, IOC_ENABLE, IOC_FLAG_GROUP)));
    spin();
    uint64_t group[5];
    uint64_t ids[2] = {0, 0};
    say("short group read %ld", TRY(read(leader, group, 32)));
    n = read(leader, group, sizeof group);
    ioctl(leader, IOC_ID, &ids[0]);
    ioctl(member, IOC_ID, &ids[1]);
    say("group read %zd nr %llu counted %d %d ids %d %d", n, (unsigned long long)group[0], group[1] > 0,
        group[3] > 0, group[2] == ids[0], group[4] == ids[1]);
    say("member read %ld", TRY(read(member, group, 8)));
    say("disable leader %ld", TRY(ioctl(leader, IOC_DISABLE, 0)));
    uint64_t before[5], after[5];
    read(leader, before, sizeof before);
    spin();
    read(leader, after, sizeof after);
    say("leader stays %d member stays %d", after[1] == before[1], after[3] == before[3]);
    close(member);
    close(leader);
    return 0;
}

static int case_exec(const char *self) {
    int pipes[2];
    pipe(pipes);
    pid_t child = fork();
    if (child == 0) {
        char go;
        close(pipes[1]);
        read(pipes[0], &go, 1);
        execl(self, self, "perf-spin", (char *)NULL);
        _exit(127);
    }
    close(pipes[0]);
    struct attr a = software(1);
    a.flags |= DISABLED | ENABLE_ON_EXEC;
    int fd = (int)open_event(&a, child, -1, -1, 0);
    say("open %d", fd >= 0);
    say("before exec %d", count(fd) == 0);
    write(pipes[1], "g", 1);
    close(pipes[1]);
    int status;
    waitpid(child, &status, 0);
    say("child status %d", status);
    say("after exec counted %d", count(fd) > 0);
    close(fd);
    return 0;
}

#define TASK_PERF_EVENTS_DISABLE 31
#define TASK_PERF_EVENTS_ENABLE 32

/* PR_TASK_PERF_EVENTS_DISABLE and ENABLE: every event this thread opened,
   one opened disabled too, whatever its other arguments; a child's own
   prctl leaves its parent's events alone. */
static int case_prctl(void) {
    struct attr a = software(1);
    int on = (int)open_event(&a, 0, -1, -1, 0);
    a.flags |= DISABLED;
    int off = (int)open_event(&a, 0, -1, -1, 0);
    spin();
    say("disable %ld", TRY(prctl(TASK_PERF_EVENTS_DISABLE, 0, 0, 0, 0)));
    uint64_t was_on = count(on), was_off = count(off);
    spin();
    say("disabled: on stayed %d off stayed %d at 0 %d", count(on) == was_on, count(off) == was_off, was_off == 0);
    say("enable with other arguments %ld", TRY(prctl(TASK_PERF_EVENTS_ENABLE, 1, 2, 3, 4)));
    spin();
    say("enabled: on grew %d off grew %d", count(on) > was_on, count(off) > was_off);

    pid_t child = fork();
    if (child == 0) {
        prctl(TASK_PERF_EVENTS_DISABLE, 0, 0, 0, 0);
        _exit(0);
    }
    int status;
    waitpid(child, &status, 0);
    was_on = count(on);
    spin();
    say("after a child's disable: on grew %d status %d", count(on) > was_on, status);
    close(on);
    close(off);
    return 0;
}

/* inherit: a child's time is added to an event its parent opened with
   inherit, by itself and in a group, and not to one without it or with
   inherit_thread, which a fork does not inherit. The child reports what an
   event of its own counted, which the inherited one, there from the fork,
   counts at least. */
static int case_inherit(void) {
    struct attr a = software(1);
    a.flags |= INHERIT;
    int inherited = (int)open_event(&a, 0, -1, -1, 0);
    a.flags |= INHERIT_THREAD;
    int threads_only = (int)open_event(&a, 0, -1, -1, 0);
    struct attr b = software(1);
    int plain = (int)open_event(&b, 0, -1, -1, 0);
    a = software(1);
    a.flags |= INHERIT;
    a.read_format = FORMAT_GROUP;
    int leader = (int)open_event(&a, 0, -1, -1, 0);
    a.read_format = 0;
    int member = (int)open_event(&a, 0, -1, leader, 0);
    say("open %d %d %d %d %d", inherited >= 0, threads_only >= 0, plain >= 0, leader >= 0, member >= 0);
    uint64_t before[3] = {count(inherited), count(threads_only), count(plain)};
    uint64_t group_before[3], group_after[3];
    long n = TRY(read(leader, group_before, sizeof group_before));
    int pipes[2];
    pipe(pipes);
    pid_t child = fork();
    if (child == 0) {
        struct attr own = software(1);
        int mine = (int)open_event(&own, 0, -1, -1, 0);
        spin();
        spin();
        spin();
        uint64_t counted = count(mine);
        write(pipes[1], &counted, sizeof counted);
        _exit(0);
    }
    uint64_t counted = 0;
    read(pipes[0], &counted, sizeof counted);
    int status;
    waitpid(child, &status, 0);
    long m = TRY(read(leader, group_after, sizeof group_after));
    say("child status %d counted %d", status, counted > 0);
    say("inherited has the child %d", count(inherited) - before[0] >= counted);
    say("inherit_thread has it %d plain has it %d", count(threads_only) - before[1] >= counted,
        count(plain) - before[2] >= counted);
    say("group read %ld %ld nr %llu leader has the child %d member has the child %d", n, m,
        (unsigned long long)group_after[0], group_after[1] - group_before[1] >= counted,
        group_after[2] - group_before[2] >= counted);
    close(member);
    close(leader);
    close(plain);
    close(threads_only);
    close(inherited);
    return 0;
}

/* A software event of this thread with the exclusions given. */
static int open_software(uint64_t config, uint64_t exclude) {
    struct attr a = software(config);
    a.flags = exclude;
    return (int)open_event(&a, 0, -1, -1, 0);
}

/* Writes a byte to each of the pages of an anonymous mapping, its first
   write: one minor fault each. */
static void touch(int pages) {
    char *p = mmap(NULL, (size_t)pages * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    for (int i = 0; i < pages; i++) p[(size_t)i * 4096] = 1;
}

static int case_software(void) {
    int faults = open_software(2, 0), minor = open_software(5, 0), major = open_software(6, 0);
    int user_faults = open_software(2, EXCLUDE_KERNEL), kernel_faults = open_software(2, EXCLUDE_USER);
    int switches = open_software(3, 0), user_switches = open_software(3, EXCLUDE_KERNEL);
    int migrations = open_software(4, 0), user_migrations = open_software(4, EXCLUDE_KERNEL);
    say("open %d %d %d %d %d %d %d %d %d", faults >= 0, minor >= 0, major >= 0, user_faults >= 0,
        kernel_faults >= 0, switches >= 0, user_switches >= 0, migrations >= 0, user_migrations >= 0);

    /* Sixteen first writes of the program's own, once its code has run. */
    touch(16);
    uint64_t f = count(faults), m = count(minor), j = count(major), u = count(user_faults);
    touch(16);
    uint64_t df = count(faults) - f, dm = count(minor) - m, dj = count(major) - j, du = count(user_faults) - u;
    say("own writes: faults %d minor %d major %d user %d", df >= 16 && df <= 20, dm >= 16 && dm <= 20,
        dj == 0, du >= 16 && du <= 20);

    /* A system call writes a page first: a fault of the kernel's. */
    int pipes[2];
    pipe(pipes);
    char *fresh = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    write(pipes[1], "x", 1);
    uint64_t k = count(kernel_faults);
    read(pipes[0], fresh, 1);
    say("a read's copy: kernel faults %d", count(kernel_faults) - k >= 1);

    /* Three sleeps each switch at least once, all in the kernel. */
    uint64_t s = count(switches), us = count(user_switches);
    for (int i = 0; i < 3; i++) usleep(1000);
    say("sleeps: switches %d user %d", count(switches) - s >= 3, count(user_switches) - us == 0);

    /* Moved to another CPU, then kept on it. */
    cpu_set_t set;
    CPU_ZERO(&set);
    if (sched_getaffinity(0, sizeof set, &set) == 0 && CPU_COUNT(&set) >= 2 && CPU_ISSET(0, &set) &&
        CPU_ISSET(1, &set)) {
        cpu_set_t one;
        CPU_ZERO(&one);
        CPU_SET(0, &one);
        sched_setaffinity(0, sizeof one, &one);
        uint64_t g = count(migrations), ug = count(user_migrations);
        CPU_ZERO(&one);
        CPU_SET(1, &one);
        long moved = TRY(sched_setaffinity(0, sizeof one, &one));
        uint64_t h = count(migrations);
        say("moved %ld: migrations %d user %d", moved, h - g >= 1, count(user_migrations) - ug == 0);
        for (int i = 0; i < 3; i++) usleep(1000);
        say("kept: migrations %d", count(migrations) - h == 0);
    } else {
        say("fewer than two cpus");
    }
    return 0;
}

/* The user page's fields (struct perf_event_mmap_page). */
#define PAGE_U32(page, at) (*(volatile uint32_t *)((char *)(page) + (at)))
#define PAGE_U64(page, at) (*(volatile uint64_t *)((char *)(page) + (at)))

static long map_event(int fd, size_t pages, int prot, int flags, off_t offset, void **at) {
    void *p = mmap(NULL, pages * 4096, prot, flags, fd, offset);
    if (p == MAP_FAILED) return -errno;
    if (at) *at = p;
    else munmap(p, pages * 4096);
    return 0;
}

/* Run in a child as another user, whose caps go with root's IDs: what it
   locks of buffers is its own, and gone when it ends. */
static void as_user(uid_t uid, void (*run)(int), int fd) {
    pid_t pid = fork();
    if (pid == 0) {
        if (setresgid(uid, uid, uid) || setresuid(uid, uid, uid)) _exit(90);
        run(fd);
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status)) say("child %d", status);
}

/* Each mapping of a buffer of 1 + 8 pages through its event shares it. */
static void map_twice(int fd) {
    void *a = NULL, *b = NULL;
    long first = map_event(fd, 9, PROT_READ | PROT_WRITE, MAP_SHARED, 0, &a);
    long second = map_event(fd, 9, PROT_READ | PROT_WRITE, MAP_SHARED, 0, &b);
    long other = map_event(fd, 5, PROT_READ | PROT_WRITE, MAP_SHARED, 0, NULL);
    if (first || second) {
        say("map twice %ld %ld", first, second);
        return;
    }
    PAGE_U64(a, 1032) = 64;
    say("map twice: other size %ld shared %d", other, PAGE_U64(b, 1032) == 64);
}

/* Without RLIMIT_MEMLOCK or CAP_IPC_LOCK, what passes the user's share
   (perf_event_mlock_kb a CPU, 516 KiB unless the host tunes it, read as
   it is) is refused. */
static void map_past_limit(int fd) {
    struct rlimit none = {0, 0};
    setrlimit(RLIMIT_MEMLOCK, &none);
    char text[32] = {0};
    int sysctl = open("/proc/sys/kernel/perf_event_mlock_kb", O_RDONLY);
    if (sysctl < 0 || read(sysctl, text, sizeof text - 1) <= 0) {
        say("past limit: no perf_event_mlock_kb");
        return;
    }
    close(sysctl);
    long kb = strtol(text, NULL, 10);
    if (kb < 8) {
        say("past limit: share below two pages");
        return;
    }
    size_t share = (size_t)(kb >> 2) * (size_t)get_nprocs();
    /* The largest buffer within the share, and the smallest past it. */
    size_t within = 1, over = 1;
    while (2 * within + 1 <= share) within <<= 1;
    while (over + 1 <= share) over <<= 1;
    say("past limit: within %ld over %ld", map_event(fd, within + 1, PROT_READ, MAP_SHARED, 0, NULL),
        map_event(fd, over + 1, PROT_READ, MAP_SHARED, 0, NULL));
}

static int case_mmap(void) {
    int fd = open_software(2, EXCLUDE_KERNEL | EXCLUDE_HV);
    say("open %d", fd >= 0);

    /* Mappings refused before the buffer is made. */
    say("private %ld", map_event(fd, 9, PROT_READ, MAP_PRIVATE, 0, NULL));
    say("three data pages %ld", map_event(fd, 4, PROT_READ, MAP_SHARED, 0, NULL));
    say("aux without buffer %ld", map_event(fd, 1, PROT_READ, MAP_SHARED, 4096 * 16, NULL));
    struct attr inherited = software(2);
    inherited.flags |= INHERIT;
    int inherit = (int)open_event(&inherited, 0, -1, -1, 0);
    say("inherit %ld", map_event(inherit, 9, PROT_READ, MAP_SHARED, 0, NULL));
    close(inherit);

    /* The user page of a buffer of eight data pages. */
    void *page = NULL;
    touch(4);
    long mapped = map_event(fd, 9, PROT_READ | PROT_WRITE, MAP_SHARED, 0, &page);
    say("mapped %ld", mapped);
    if (mapped) return 0;
    uint64_t caps = PAGE_U64(page, 40);
    say("version %u compat %u lock even %d index %u", PAGE_U32(page, 0), PAGE_U32(page, 4),
        PAGE_U32(page, 8) % 2 == 0, PAGE_U32(page, 12));
    say("caps bit0 %d deprecated %d rdpmc %d", (int)(caps & 1), (int)(caps >> 1 & 1), (int)(caps >> 2 & 1));
    say("size %u data offset %llu size %llu head %llu tail %llu", PAGE_U32(page, 72),
        (unsigned long long)PAGE_U64(page, 1040), (unsigned long long)PAGE_U64(page, 1048),
        (unsigned long long)PAGE_U64(page, 1024), (unsigned long long)PAGE_U64(page, 1032));
    say("count %d times %d", PAGE_U64(page, 16) <= count(fd),
        PAGE_U64(page, 24) >= PAGE_U64(page, 32));
    /* The data pages read as zeros. */
    int zeros = 1;
    for (size_t i = 4096; i < 9 * 4096; i += 512) zeros &= ((volatile char *)page)[i] == 0;
    say("data zeros %d", zeros);

    /* Another size while mapped, and the AUX area, which a software event
       has none of once Linux's checks pass. */
    say("other size %ld", map_event(fd, 17, PROT_READ, MAP_SHARED, 0, NULL));
    say("aux unset %ld", map_event(fd, 4, PROT_READ, MAP_SHARED, 4096 * 16, NULL));
    PAGE_U64(page, 1072) = 4096 * 16;
    PAGE_U64(page, 1080) = 4096 * 4;
    say("aux elsewhere %ld", map_event(fd, 4, PROT_READ, MAP_SHARED, 4096 * 32, NULL));
    say("aux other size %ld", map_event(fd, 2, PROT_READ, MAP_SHARED, 4096 * 16, NULL));
    say("aux %ld", map_event(fd, 4, PROT_READ, MAP_SHARED, 4096 * 16, NULL));
    PAGE_U64(page, 1080) = 4096 * 3;
    say("aux three pages %ld", map_event(fd, 3, PROT_READ, MAP_SHARED, 4096 * 16, NULL));
    PAGE_U64(page, 1072) = 4096 * 4;
    PAGE_U64(page, 1080) = 4096 * 4;
    say("aux within %ld", map_event(fd, 4, PROT_READ, MAP_SHARED, 4096 * 4, NULL));

    /* A fork's child has none of it. */
    pid_t pid = fork();
    if (pid == 0) _exit(msync(page, 4096, MS_ASYNC) == 0 ? 0 : errno == ENOMEM ? 1 : 2);
    int status = 0;
    waitpid(pid, &status, 0);
    say("child mapping %d", WIFEXITED(status) ? WEXITSTATUS(status) : -1);

    /* Unmapped, the buffer goes, and another size maps. Closed, the
       event lives on in its mapping. */
    munmap(page, 9 * 4096);
    say("unmapped: other size %ld", map_event(fd, 17, PROT_READ, MAP_SHARED, 0, NULL));
    mapped = map_event(fd, 5, PROT_READ, MAP_SHARED, 0, &page);
    close(fd);
    say("closed %ld: mapped %d data size %llu", mapped, msync(page, 5 * 4096, MS_ASYNC) == 0,
        (unsigned long long)PAGE_U64(page, 1048));
    munmap(page, 5 * 4096);
    int again = open_software(2, EXCLUDE_KERNEL | EXCLUDE_HV);
    say("one page %ld", map_event(again, 1, PROT_READ, MAP_SHARED, 0, NULL));
    say("fixed %ld", ({
            void *hint = mmap(NULL, 9 * 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            void *got = mmap(hint, 9 * 4096, PROT_READ, MAP_SHARED | MAP_FIXED, again, 0);
            long fixed = got == MAP_FAILED ? -errno : got == hint;
            if (got != MAP_FAILED) munmap(got, 9 * 4096);
            fixed;
        }));

    as_user(4242, map_twice, again);
    as_user(4243, map_past_limit, again);
    close(again);
    return 0;
}

static long set_output(int fd, long output) {
    return TRY(ioctl(fd, IOC_SET_OUTPUT, output));
}

/* An event of this thread like open_software's, with more flags. */
static int open_like(uint64_t flags, int pid, int cpu, int group, unsigned long open_flags) {
    struct attr a = software(2);
    a.flags |= flags;
    return (int)open_event(&a, pid, cpu, group, open_flags);
}

/* Each call in its own statement: the arguments of one call run in no
   set order. */
static int case_output(void) {
    int owner = open_like(0, 0, -1, -1, 0), other = open_like(0, 0, -1, -1, 0);
    void *page = NULL;
    long a = map_event(owner, 3, PROT_READ, MAP_SHARED, 0, &page), b, c;
    say("open %d mapped %ld", owner >= 0 && other >= 0, a);

    /* What may not write to the buffer. */
    say("self %ld", set_output(owner, owner));
    say("no buffer %ld", set_output(other, open_like(0, 0, -1, -1, 0)));
    a = set_output(other, 0);
    b = set_output(other, 1000);
    c = set_output(other, 0xffffffffL);
    say("not an event %ld closed %ld high %ld", a, b, c);
    say("other cpu %ld", set_output(open_like(0, 0, 0, -1, 0), owner));
    struct attr clocked = software(2);
    clocked.flags |= USE_CLOCKID;
    clocked.clockid = CLOCK_MONOTONIC;
    say("other clock %ld", set_output((int)open_event(&clocked, 0, -1, -1, 0), owner));
    say("backward %ld", set_output(open_like(WRITE_BACKWARD, 0, -1, -1, 0), owner));
    pid_t child = fork();
    if (child == 0) {
        pause();
        _exit(0);
    }
    int theirs = open_like(0, child, -1, -1, 0);
    say("other task %d %ld", theirs >= 0, set_output(theirs, owner));
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);

    /* Another event writes to it, and maps none of it. */
    a = set_output(other, owner);
    b = set_output(other, owner);
    say("set %ld again %ld", a, b);
    a = map_event(other, 3, PROT_READ, MAP_SHARED, 0, NULL);
    b = map_event(other, 5, PROT_READ, MAP_SHARED, 0, NULL);
    say("other mapped %ld other size %ld", a, b);
    a = set_output(owner, other);
    b = set_output(owner, -1);
    say("owner elsewhere %ld owner none %ld", a, b);
    int third = open_like(0, 0, -1, -1, 0);
    a = set_output(third, other);
    b = map_event(third, 3, PROT_READ, MAP_SHARED, 0, NULL);
    say("through %ld mapped %ld", a, b);
    a = set_output(third, -1);
    void *own = NULL;
    b = map_event(third, 3, PROT_READ, MAP_SHARED, 0, &own);
    say("none %ld mapped %ld", a, b);
    if (!b) {
        say("own mapping elsewhere %ld", set_output(third, owner));
        munmap(own, 3 * 4096);
    }

    /* At open, through the group's event, in its group or not. */
    long grouped = open_like(0, 0, -1, owner, FLAG_FD_OUTPUT);
    long alone = open_like(0, 0, -1, owner, FLAG_FD_OUTPUT | FLAG_FD_NO_GROUP);
    say("open grouped %d alone %d", grouped >= 0, alone >= 0);
    if (alone >= 0) say("alone mapped %ld", map_event((int)alone, 3, PROT_READ, MAP_SHARED, 0, NULL));
    say("open without buffer %ld", (long)open_like(0, 0, -1, third, FLAG_FD_OUTPUT | FLAG_FD_NO_GROUP));
    say("open backward %ld", (long)open_like(WRITE_BACKWARD, 0, -1, owner, FLAG_FD_OUTPUT | FLAG_FD_NO_GROUP));
    say("open other cpu %ld", (long)open_like(0, 0, 0, owner, FLAG_FD_OUTPUT | FLAG_FD_NO_GROUP));

    /* Unmapped, the buffer goes, and those that wrote to it are free. */
    munmap(page, 3 * 4096);
    a = set_output(third, other);
    b = map_event(other, 5, PROT_READ, MAP_SHARED, 0, NULL);
    say("unmapped: set %ld other maps %ld", a, b);
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    alarm(20);
    if (!strcmp(mode, "perf-calls")) return case_calls();
    if (!strcmp(mode, "perf-counts")) return case_counts();
    if (!strcmp(mode, "perf-prctl")) return case_prctl();
    if (!strcmp(mode, "perf-inherit")) return case_inherit();
    if (!strcmp(mode, "perf-software")) return case_software();
    if (!strcmp(mode, "perf-mmap")) return case_mmap();
    if (!strcmp(mode, "perf-output")) return case_output();
    if (!strcmp(mode, "perf-exec")) return case_exec(argc > 2 ? argv[2] : argv[0]);
    if (!strcmp(mode, "perf-spin")) {
        spin();
        spin();
        return 0;
    }
    return 2;
}
