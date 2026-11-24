/* perf_event_open, compared with Linux: the order of its checks and their
   errors, and the software events the emulator counts (task-clock,
   cpu-clock and the dummy event) with read, the read formats, groups, the
   ENABLE, DISABLE, RESET and ID ioctls, enable_on_exec, prctl's
   PR_TASK_PERF_EVENTS_DISABLE and ENABLE of the events a thread opened,
   inherit, which counts the children a task makes, and the page faults,
   context switches and CPU migrations a thread makes, with and without
   exclude_user and exclude_kernel; and mmap of an event's ring buffer:
   its user page, the sizes and mappings it takes, its AUX area, a fork's
   child, which has none of it, the pages a user may lock, and the rules
   of its VM_PFNMAP mapping (pfn_rules); and
   output to another event's buffer, with PERF_EVENT_IOC_SET_OUTPUT and
   PERF_FLAG_FD_OUTPUT; and the side-band records an event asks for:
   MMAP and MMAP2 of mmap, mprotect, brk and shmat, COMM of
   PR_SET_NAME and of an execve, and FORK and EXIT of a child.

   Counts and times are given as whether they are 0, grew or stayed,
   never as values, and IDs as whether they match. Hardware events are not
   opened: a CI machine may or may not have a PMU. The size Linux writes
   back for a structure too large is not printed either, as it grows with
   each kernel. The cases run as root, as the guest does. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <poll.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <setjmp.h>
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

/* Events of this thread on CPU 0 and on CPU 1 (task-clock, page-faults
   and cpu-migrations), while it runs on CPU 1 and then is moved to CPU 0:
   each counts only while it runs on its CPU (event_filter_match), but is
   enabled all the while, and the migration counts on the CPU it comes
   to. */
static void per_cpu(void) {
    static const uint64_t configs[3] = {1, 2, 4};
    static const char *const names[3] = {"task-clock", "page-faults", "cpu-migrations"};
    int fds[3][2];
    for (int i = 0; i < 3; i++)
        for (int cpu = 0; cpu < 2; cpu++) {
            struct attr a = software(configs[i]);
            a.read_format = FORMAT_ENABLED | FORMAT_RUNNING;
            fds[i][cpu] = (int)open_event(&a, 0, cpu, -1, 0);
        }
    spin();
    touch(8);
    cpu_set_t one;
    CPU_ZERO(&one);
    CPU_SET(0, &one);
    sched_setaffinity(0, sizeof one, &one);
    spin();
    touch(8);
    uint64_t values[3][2][3];
    for (int i = 0; i < 3; i++)
        for (int cpu = 0; cpu < 2; cpu++) ioctl(fds[i][cpu], IOC_DISABLE, 0);
    for (int i = 0; i < 3; i++)
        for (int cpu = 0; cpu < 2; cpu++)
            if (read(fds[i][cpu], values[i][cpu], sizeof values[i][cpu]) != sizeof values[i][cpu])
                memset(values[i][cpu], 0xff, sizeof values[i][cpu]);
    for (int i = 0; i < 2; i++)
        say("%s on cpu 0: counted %d running less %d; on cpu 1: counted %d running less %d", names[i],
            values[i][0][0] > 0 && values[i][0][0] != (uint64_t)-1, values[i][0][2] < values[i][0][1],
            values[i][1][0] > 0 && values[i][1][0] != (uint64_t)-1, values[i][1][2] < values[i][1][1]);
    say("cpu-migrations on cpu 0 %llu on cpu 1 %llu", (unsigned long long)values[2][0][0],
        (unsigned long long)values[2][1][0]);
    for (int i = 0; i < 3; i++)
        for (int cpu = 0; cpu < 2; cpu++) close(fds[i][cpu]);
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
        per_cpu();
    } else {
        say("fewer than two cpus");
    }
    return 0;
}

/* The perf-gup case: a fault through get_user_pages (handle_mm_fault with
   no registers) counts to the task's min_flt and is no perf event. Each
   step brings 32 fresh pages in: MADV_POPULATE_READ, MADV_POPULATE_WRITE,
   MAP_POPULATE, mlock, process_vm_readv and process_vm_writev. */
static long thread_minflt(void) {
    struct rusage usage;
    getrusage(RUSAGE_THREAD, &usage);
    return usage.ru_minflt;
}

static char *fresh_pages(int pages) {
    return mmap(NULL, (size_t)pages * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static void gup_step(const char *name, int faults, int step, char *pages, char *local) {
    uint64_t before = count(faults);
    long minflt = thread_minflt();
    long result = 0;
    struct iovec mine = {local, 32 * 4096}, theirs = {pages, 32 * 4096};
    switch (step) {
    case 0: result = TRY(madvise(pages, 32 * 4096, 22 /* MADV_POPULATE_READ */)); break;
    case 1: result = TRY(madvise(pages, 32 * 4096, 23 /* MADV_POPULATE_WRITE */)); break;
    case 2:
        pages = mmap(NULL, 32 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
        result = pages == MAP_FAILED ? -errno : 0;
        break;
    case 3: result = TRY(mlock(pages, 32 * 4096)); break;
    case 4: result = TRY(syscall(SYS_process_vm_readv, getpid(), &mine, 1, &theirs, 1, 0)); break;
    case 5: result = TRY(syscall(SYS_process_vm_writev, getpid(), &mine, 1, &theirs, 1, 0)); break;
    }
    uint64_t events = count(faults) - before;
    long counted = thread_minflt() - minflt;
    say("%s %ld: min_flt %d perf %d", name, result, counted >= 32, events <= 4);
}

static int case_gup(void) {
    int faults = open_software(2, 0);
    say("open %d", faults >= 0);
    /* The local side of process_vm's copies has its frames already. */
    char *local = fresh_pages(32);
    memset(local, 1, 32 * 4096);
    gup_step("populate read", faults, 0, fresh_pages(32), local);
    gup_step("populate write", faults, 1, fresh_pages(32), local);
    gup_step("map populate", faults, 2, NULL, local);
    gup_step("mlock", faults, 3, fresh_pages(32), local);
    gup_step("process_vm_readv", faults, 4, fresh_pages(32), local);
    gup_step("process_vm_writev", faults, 5, fresh_pages(32), local);
    return 0;
}

/* The perf-ring-gup case: a ring is VM_IO | VM_PFNMAP, which
   get_user_pages refuses (check_vma_flags): process_vm_readv and
   process_vm_writev pin nothing of it (EFAULT), and MADV_POPULATE_READ is
   EINVAL (FOLL_MADV_POPULATE), while the task's own reads see it. */
static int case_ring_gup(void) {
    int fd = open_software(9, 0);
    char *ring = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    say("open %d mapped %d", fd >= 0, ring != MAP_FAILED);
    if (ring == MAP_FAILED) return 0;
    /* The task's own read of the user page: its compat_version, 0. */
    say("own read: compat %u", ((volatile uint32_t *)ring)[1]);
    static char local[16];
    struct iovec mine = {local, sizeof local}, theirs = {ring, sizeof local};
    say("process_vm_readv %ld", TRY(syscall(SYS_process_vm_readv, getpid(), &mine, 1, &theirs, 1, 0)));
    say("process_vm_writev %ld", TRY(syscall(SYS_process_vm_writev, getpid(), &mine, 1, &theirs, 1, 0)));
    say("populate read %ld", TRY(madvise(ring, 4096, 22 /* MADV_POPULATE_READ */)));
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

static sigjmp_buf fault_jump;
static void on_fault(int number) {
    siglongjmp(fault_jump, number);
}

/* The signal a write of the byte at `at` (as it is) raises: 0 for none. */
static int write_signal(volatile char *at) {
    struct sigaction a, bus, segv;
    memset(&a, 0, sizeof a);
    a.sa_handler = on_fault;
    a.sa_flags = SA_NODEFER;
    sigaction(SIGBUS, &a, &bus);
    sigaction(SIGSEGV, &a, &segv);
    int number = sigsetjmp(fault_jump, 1);
    if (number == 0) *at = *at;
    sigaction(SIGBUS, &bus, NULL);
    sigaction(SIGSEGV, &segv, NULL);
    return number;
}

/* VmLck of /proc/self/status, in kB: -1 if not there. */
static long locked_kb(void) {
    FILE *status = fopen("/proc/self/status", "r");
    if (!status) return -1;
    char line[256];
    long kb = -1;
    while (fgets(line, sizeof line, status))
        if (sscanf(line, "VmLck: %ld", &kb) == 1) break;
    fclose(status);
    return kb;
}

/* What mremap gives: 0 or -errno. */
static long remapped(void *at) {
    return at == MAP_FAILED ? -errno : 0;
}

/* Linux's rules for a ring buffer's mapping of 9 pages at `page`, a
   VM_PFNMAP and VM_IO one (perf_mmap_vmops): its data pages are mapped
   read-only (perf_mmap_pfn_mkwrite's SIGBUS), and no part of it is
   unmapped, mapped over, moved, given another protection or other flags,
   or sealed on its own (perf_mmap_may_split's EINVAL); but a part that
   would not change takes the call. As memory core mm does not back, it
   takes no MADV_DOFORK or MADV_DODUMP, gives no pages to MADV_DONTNEED,
   and mlock leaves it unlocked. */
static void pfn_rules(char *page) {
    say("write user page %d data page %d", write_signal(page + 8), write_signal(page + 4096));
    say("munmap first %ld", TRY(munmap(page, 4096)));
    say("munmap last %ld", TRY(munmap(page + 8 * 4096, 4096)));
    say("map over %ld", remapped(mmap(page + 4096, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0)));
    say("mprotect part %ld", TRY(mprotect(page, 4096, PROT_READ)));
    say("mprotect part same %ld", TRY(mprotect(page, 4096, PROT_READ | PROT_WRITE)));
    say("mremap shrink %ld", remapped(mremap(page, 9 * 4096, 4096, 0)));
    char *target = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    say("mremap part %ld",
        remapped(mremap(page + 4096, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, target)));
    munmap(target, 4096);
    say("madvise random part %ld", TRY(madvise(page, 4096, MADV_RANDOM)));
    say("madvise dontdump part %ld", TRY(madvise(page, 4096, MADV_DONTDUMP)));
    say("madvise dofork %ld", TRY(madvise(page, 9 * 4096, MADV_DOFORK)));
    say("madvise dodump %ld", TRY(madvise(page, 9 * 4096, MADV_DODUMP)));
    say("madvise dontneed %ld", TRY(madvise(page, 9 * 4096, MADV_DONTNEED)));
    say("madvise dontneed locked %ld", TRY(madvise(page, 9 * 4096, 24 /* MADV_DONTNEED_LOCKED */)));
    say("mseal part %ld", TRY(syscall(462 /* mseal */, page, 4096, 0)));
    long before = locked_kb();
    say("mlock %ld", TRY(mlock(page, 9 * 4096)));
    say("locked %d", locked_kb() == before);
    munlock(page, 9 * 4096);
    /* All of it takes the calls. */
    say("mprotect whole %ld", TRY(mprotect(page, 9 * 4096, PROT_READ | PROT_WRITE)));
    say("madvise random whole %ld", TRY(madvise(page, 9 * 4096, MADV_RANDOM)));
    madvise(page, 9 * 4096, MADV_NORMAL);
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
    pfn_rules(page);

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

#define SAMPLE_CALLCHAIN (1ULL << 5)
#define SAMPLE_ID (1ULL << 6)
#define SAMPLE_PERIOD (1ULL << 8)
#define SAMPLE_STREAM_ID (1ULL << 9)
#define SAMPLE_IDENTIFIER (1ULL << 16)
#define SAMPLE_ID_ALL (1ULL << 18)
#define EXCLUDE_CALLCHAIN_KERNEL (1ULL << 21)
#define FORMAT_LOST 16
#define IOC_PAUSE_OUTPUT _IOW('$', 9, uint32_t)
#define RECORD_LOST 2
#define RECORD_SAMPLE 9
#define CONTEXT_USER ((uint64_t)-512)

/* A disabled page-fault event of this thread that samples each fault. */
static int open_sampling(uint64_t sample_type, uint64_t flags) {
    struct attr a = software(2);
    a.sample_period = 1;
    a.sample_type = sample_type;
    a.read_format = FORMAT_LOST;
    a.flags |= DISABLED | flags;
    return (int)open_event(&a, 0, -1, -1, 0);
}

/* The samples it lost, from a read with PERF_FORMAT_LOST. */
static uint64_t lost_samples(int fd) {
    uint64_t values[2] = {0, (uint64_t)-1};
    if (read(fd, values, sizeof values) != sizeof values) return (uint64_t)-1;
    return values[1];
}

/* Copies the record at `at` of a buffer of `size` data bytes out, round
   the end of the data pages. */
static void copy_record(void *page, uint64_t size, uint64_t at, uint64_t *out, size_t words) {
    unsigned char *data = (unsigned char *)page + 4096, *to = (unsigned char *)out;
    for (size_t i = 0; i < words * 8; i++) to[i] = data[(at + i) & (size - 1)];
}

static void faults_while_enabled(int fd, int pages) {
    ioctl(fd, IOC_ENABLE, 0);
    touch(pages);
    ioctl(fd, IOC_DISABLE, 0);
}

static int case_sample(void) {
    /* Each fault is a sample of the fields asked for, in Linux's order. */
    int fd = open_sampling(SAMPLE_IDENTIFIER | SAMPLE_TID | SAMPLE_PERIOD | SAMPLE_ID | SAMPLE_STREAM_ID, 0);
    void *page = NULL;
    long mapped = map_event(fd, 3, PROT_READ | PROT_WRITE, MAP_SHARED, 0, &page);
    uint64_t id = 0;
    ioctl(fd, IOC_ID, &id);
    say("open %d mapped %ld", fd >= 0, mapped);
    if (mapped) return 1;
    faults_while_enabled(fd, 5);
    uint64_t head = PAGE_U64(page, 1024);
    int samples = 0, alike = 1;
    for (uint64_t at = 0; at < head; at += 48) {
        uint64_t r[6];
        copy_record(page, 8192, at, r, 6);
        uint32_t type = (uint32_t)r[0];
        uint16_t misc = (uint16_t)(r[0] >> 32), size = (uint16_t)(r[0] >> 48);
        alike &= type == RECORD_SAMPLE && misc == 2 && size == 48 && r[1] == id;
        alike &= (uint32_t)r[2] == (uint32_t)getpid() && (uint32_t)(r[2] >> 32) == (uint32_t)gettid();
        /* PERF_SAMPLE_PERIOD comes after the IDs. */
        alike &= r[3] == id && r[4] == id && r[5] == 1;
        samples++;
    }
    say("samples>=5 %d alike %d whole %d", samples >= 5, alike, head % 48 == 0);
    say("lost %llu", (unsigned long long)lost_samples(fd));
    munmap(page, 3 * 4096);
    close(fd);

    /* A full buffer loses samples, and the next record after room is made
       tells how many, with its sample_id. */
    fd = open_sampling(SAMPLE_TID | SAMPLE_PERIOD, SAMPLE_ID_ALL);
    ioctl(fd, IOC_ID, &id);
    mapped = map_event(fd, 2, PROT_READ | PROT_WRITE, MAP_SHARED, 0, &page);
    faults_while_enabled(fd, 400);
    head = PAGE_U64(page, 1024);
    uint64_t lost = lost_samples(fd);
    say("full: mapped %ld fits %d lost>0 %d", mapped, head == 4080, lost > 0 && lost != (uint64_t)-1);
    PAGE_U64(page, 1032) = head;
    faults_while_enabled(fd, 1);
    uint64_t r[4];
    copy_record(page, 4096, head, r, 4);
    say("lost record %d size %d id %d count %d", (uint32_t)r[0] == RECORD_LOST, (int)(r[0] >> 48),
        r[1] == id, r[2] == lost);
    say("pid %d", (uint32_t)r[3] == (uint32_t)getpid());
    copy_record(page, 4096, head + 32, r, 1);
    say("then sample %d", (uint32_t)r[0] == RECORD_SAMPLE);

    /* Paused, it takes nothing and counts it lost. */
    PAGE_U64(page, 1032) = PAGE_U64(page, 1024);
    head = PAGE_U64(page, 1024);
    long paused = TRY(ioctl(fd, IOC_PAUSE_OUTPUT, 1));
    faults_while_enabled(fd, 3);
    say("paused %ld kept %d lost more %d", paused, PAGE_U64(page, 1024) == head, lost_samples(fd) >= lost + 3);
    long resumed = TRY(ioctl(fd, IOC_PAUSE_OUTPUT, 0));
    faults_while_enabled(fd, 1);
    copy_record(page, 4096, head, r, 1);
    say("resumed %ld lost record %d", resumed, (uint32_t)r[0] == RECORD_LOST);
    munmap(page, 2 * 4096);
    say("pause unmapped %ld", TRY(ioctl(fd, IOC_PAUSE_OUTPUT, 1)));
    close(fd);

    /* Read-only, the buffer overwrites what it holds and loses nothing. */
    fd = open_sampling(SAMPLE_TID | SAMPLE_PERIOD, 0);
    map_event(fd, 2, PROT_READ, MAP_SHARED, 0, &page);
    faults_while_enabled(fd, 400);
    head = PAGE_U64(page, 1024);
    say("overwrite past %d whole %d lost %llu", head > 4096, head % 24 == 0,
        (unsigned long long)lost_samples(fd));
    munmap(page, 2 * 4096);
    close(fd);

    /* Backward, the head goes down from 0. */
    fd = open_sampling(SAMPLE_TID | SAMPLE_PERIOD, WRITE_BACKWARD);
    map_event(fd, 2, PROT_READ, MAP_SHARED, 0, &page);
    faults_while_enabled(fd, 3);
    head = PAGE_U64(page, 1024);
    copy_record(page, 4096, head, r, 1);
    say("backward below %d whole %d sample %d", (int64_t)head < 0, (0 - head) % 24 == 0,
        (uint32_t)r[0] == RECORD_SAMPLE);
    munmap(page, 2 * 4096);
    close(fd);

    /* The callchain of user mode starts with its context. */
    fd = open_sampling(SAMPLE_CALLCHAIN, EXCLUDE_CALLCHAIN_KERNEL);
    map_event(fd, 2, PROT_READ | PROT_WRITE, MAP_SHARED, 0, &page);
    faults_while_enabled(fd, 1);
    copy_record(page, 4096, 0, r, 3);
    say("callchain sample %d context %d frames %d", (uint32_t)r[0] == RECORD_SAMPLE, r[2] == CONTEXT_USER,
        r[1] >= 2 && r[1] <= 128);
    munmap(page, 2 * 4096);
    close(fd);

    struct attr a = software(2);
    a.sample_period = 1;
    a.sample_type = SAMPLE_CALLCHAIN;
    a.flags |= EXCLUDE_CALLCHAIN_KERNEL;
    a.sample_max_stack = 128;
    attempt("max stack 128", a, 0, -1, -1, 0);
    a.sample_max_stack = 127;
    attempt("max stack 127", a, 0, -1, -1, 0);
    a = software(2);
    a.aux_action = 7;
    attempt("aux start paused pause resume", a, 0, -1, -1, 0);
    a.aux_action = 1;
    attempt("aux start paused", a, 0, -1, -1, 0);
    return 0;
}

#define WATERMARK (1ULL << 14)

static short polled(int fd) {
    struct pollfd p = {.fd = fd, .events = POLLIN};
    return poll(&p, 1, 0) < 0 ? -1 : p.revents;
}

static volatile int io_count, io_in, io_hup, io_alike, trap_count, trap_alike;
static int io_fd;
static void on_io(int number, siginfo_t *info, void *context) {
    (void)number;
    (void)context;
    io_count++;
    if (info->si_code == POLL_IN) io_in++;
    if (info->si_code == POLL_HUP) io_hup++;
    io_alike &= info->si_fd == io_fd && (info->si_code == POLL_HUP || info->si_band == (POLLIN | POLLRDNORM));
}
static void on_trap(int number, siginfo_t *info, void *context) {
    (void)number;
    (void)context;
    trap_count++;
    const unsigned char *raw = (const unsigned char *)info;
    trap_alike &= info->si_code == 6 && *(const uint64_t *)(raw + 24) == 0x1234 && *(const uint32_t *)(raw + 32) == 1 &&
                  *(const uint32_t *)(raw + 36) == 0;
}

/* Signal-driven I/O to this process with SIGRTMIN, which is queued. */
static void own_signals(int fd) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_io;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGRTMIN, &sa, NULL);
    fcntl(fd, F_SETOWN, getpid());
    fcntl(fd, F_SETSIG, SIGRTMIN);
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_ASYNC);
    io_fd = fd;
    io_count = io_in = io_hup = 0;
    io_alike = 1;
}

static int case_wakeup(void) {
    /* Without a buffer, poll finds the event hung up. */
    int fd = open_sampling(SAMPLE_TID | SAMPLE_PERIOD, 0);
    say("no buffer %d", polled(fd));
    void *page = NULL;
    map_event(fd, 2, PROT_READ | PROT_WRITE, MAP_SHARED, 0, &page);
    say("empty %d", polled(fd));
    munmap(page, 2 * 4096);
    close(fd);

    /* Each wakeup_events-th sample makes it readable once. */
    struct attr a = software(2);
    a.sample_period = 1;
    a.sample_type = SAMPLE_TID | SAMPLE_PERIOD;
    a.flags |= DISABLED;
    a.wakeup_events = 1;
    fd = (int)open_event(&a, 0, -1, -1, 0);
    map_event(fd, 2, PROT_READ | PROT_WRITE, MAP_SHARED, 0, &page);
    faults_while_enabled(fd, 1);
    short first = polled(fd), second = polled(fd);
    say("wakeup events: readable %d then %d", first, second);
    munmap(page, 2 * 4096);
    close(fd);

    /* With watermark, once wakeup_watermark bytes are written. */
    a.flags |= WATERMARK;
    a.wakeup_events = 4 * 24;
    fd = (int)open_event(&a, 0, -1, -1, 0);
    map_event(fd, 2, PROT_READ | PROT_WRITE, MAP_SHARED, 0, &page);
    faults_while_enabled(fd, 6);
    first = polled(fd);
    say("watermark: readable %d head>96 %d", first, PAGE_U64(page, 1024) > 96);
    munmap(page, 2 * 4096);
    close(fd);

    /* O_ASYNC signals each overflow, with or without a buffer. */
    fd = open_sampling(SAMPLE_TID | SAMPLE_PERIOD, 0);
    own_signals(fd);
    faults_while_enabled(fd, 3);
    say("signals>=3 %d in %d alike %d hup %d", io_count >= 3, io_in == io_count, io_alike, io_hup);
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_ASYNC);
    io_count = 0;
    faults_while_enabled(fd, 2);
    say("off %d", io_count);
    close(fd);

    /* REFRESH allows that many overflows, the last hanging up. */
    fd = open_sampling(SAMPLE_TID | SAMPLE_PERIOD, 0);
    map_event(fd, 2, PROT_READ | PROT_WRITE, MAP_SHARED, 0, &page);
    own_signals(fd);
    long refreshed = TRY(ioctl(fd, IOC_REFRESH, 2));
    touch(5);
    ioctl(fd, IOC_ID, &(uint64_t){0});
    say("refresh %ld: signals %d in %d hup %d records %d", refreshed, io_count, io_in, io_hup,
        (int)(PAGE_U64(page, 1024) / 24));
    touch(2);
    ioctl(fd, IOC_ID, &(uint64_t){0});
    say("after: signals %d", io_count);
    struct attr counting = software(2);
    say("refresh counting %ld", TRY(ioctl((int)open_event(&counting, 0, -1, -1, 0), IOC_REFRESH, 1)));
    struct attr inherited = software(2);
    inherited.sample_period = 1;
    inherited.flags |= INHERIT;
    say("refresh inherit %ld", TRY(ioctl((int)open_event(&inherited, 0, -1, -1, 0), IOC_REFRESH, 1)));
    munmap(page, 2 * 4096);
    close(fd);

    /* sigtrap: SIGTRAP of TRAP_PERF with sig_data and the type. */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_trap;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGTRAP, &sa, NULL);
    a = software(2);
    a.sample_period = 1;
    a.flags |= DISABLED | ATTR_SIGTRAP | REMOVE_ON_EXEC;
    a.sig_data = 0x1234;
    fd = (int)open_event(&a, 0, -1, -1, 0);
    trap_alike = 1;
    faults_while_enabled(fd, 2);
    say("sigtrap>=1 %d alike %d", trap_count >= 1, trap_alike);
    /* Blocked, it waits, flagged as late. */
    sigset_t trap, old;
    sigemptyset(&trap);
    sigaddset(&trap, SIGTRAP);
    sigprocmask(SIG_BLOCK, &trap, &old);
    faults_while_enabled(fd, 1);
    siginfo_t info;
    struct timespec none = {0, 0};
    int got = sigtimedwait(&trap, &info, &none);
    const unsigned char *raw = (const unsigned char *)&info;
    say("blocked %d code %d async %u", got, info.si_code, *(const uint32_t *)(raw + 36));
    sigprocmask(SIG_SETMASK, &old, NULL);
    close(fd);

    /* A child's event hangs up when the child ends. */
    pid_t child = fork();
    if (child == 0) {
        pause();
        _exit(0);
    }
    struct attr theirs = software(2);
    theirs.sample_period = 1;
    fd = (int)open_event(&theirs, child, -1, -1, 0);
    map_event(fd, 2, PROT_READ | PROT_WRITE, MAP_SHARED, 0, &page);
    say("child running %d", polled(fd));
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    say("child gone %d", polled(fd));
    return 0;
}

#define ATTR_MMAP (1ULL << 8)
#define ATTR_COMM (1ULL << 9)
#define ATTR_TASK (1ULL << 13)
#define ATTR_MMAP_DATA (1ULL << 17)
#define ATTR_MMAP2 (1ULL << 23)
#define RECORD_MMAP 1
#define RECORD_COMM 3
#define RECORD_EXIT 4
#define RECORD_FORK 7
#define RECORD_MMAP2 10
#define MISC_DATA (1 << 13)

/* A dummy event of `pid` on `cpu` that takes the side-band records of
   `flags`, with the thread's IDs after each (sample_id_all), and its
   buffer of 8 data pages. */
static int open_side_band(int pid, int cpu, uint64_t flags, void **page) {
    struct attr a = software(9);
    a.sample_type = SAMPLE_TID;
    a.flags |= DISABLED | SAMPLE_ID_ALL | flags;
    int fd = (int)open_event(&a, pid, cpu, -1, 0);
    if (fd < 0 || map_event(fd, 9, PROT_READ | PROT_WRITE, MAP_SHARED, 0, page) < 0) return -1;
    return fd;
}

/* The records in a buffer of 8 data pages, from where the reader left off
   (`tail`), each passed to `seen` and then consumed. */
static void each_record(void *page, uint64_t *tail, void (*seen)(const uint64_t *record, void *with), void *with) {
    uint64_t head = PAGE_U64(page, 1024);
    __sync_synchronize();
    while (*tail < head) {
        uint64_t first;
        copy_record(page, 8 * 4096, *tail, &first, 1);
        uint64_t size = first >> 48;
        if (size < 8 || size > 4096) break;
        uint64_t record[512];
        copy_record(page, 8 * 4096, *tail, record, size / 8);
        seen(record, with);
        *tail += size;
    }
    PAGE_U64(page, 1032) = *tail;
}

#define RECORD_THROTTLE 5
#define RECORD_UNTHROTTLE 6

static const char RATE[] = "/proc/sys/kernel/perf_event_max_sample_rate";
static const char PERCENT[] = "/proc/sys/kernel/perf_cpu_time_max_percent";

/* What writing `text` to the sysctl at `path` gives: 0 or -errno. */
static int write_sysctl(const char *path, const char *text) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -errno;
    int result = write(fd, text, strlen(text)) < 0 ? -errno : 0;
    close(fd);
    return result;
}

/* The records of a throttled clock, which should come as THROTTLE, the
   sample it was throttled at, and UNTHROTTLE at the next tick. */
struct throttled {
    uint64_t id;
    pid_t pid, tid;
    int records, in_order, ids;
    char first[16];
};

static void see_throttled(const uint64_t *record, void *with) {
    struct throttled *t = with;
    static const uint32_t cycle[3] = {RECORD_THROTTLE, RECORD_SAMPLE, RECORD_UNTHROTTLE};
    uint32_t type = (uint32_t)record[0];
    uint64_t size = record[0] >> 48;
    if (type != cycle[t->records % 3]) t->in_order = 0;
    if (t->records < (int)sizeof t->first - 1)
        t->first[t->records] = type == RECORD_THROTTLE ? 'T' : type == RECORD_UNTHROTTLE ? 'U' : type == RECORD_SAMPLE ? 'S' : '?';
    if (type == RECORD_THROTTLE || type == RECORD_UNTHROTTLE) {
        /* time, id, stream_id, then the writer's IDs (sample_id_all). */
        const uint32_t *writer = (const uint32_t *)((const char *)record + size - 8);
        if (size != 40 || record[2] != t->id || record[3] != t->id || writer[0] != (uint32_t)t->pid ||
            writer[1] != (uint32_t)t->tid)
            t->ids = 0;
    }
    t->records++;
}

/* Throttling, with kernel.perf_event_max_sample_rate at 1: one interrupt
   of an event a tick throttles it. Only the harness runs this case on
   Linux, and only where it is allowed to change the sysctl (CI); the case
   puts the value back, and the harness does if the case cannot. */
static int case_throttle(void) {
    char saved[32] = {0};
    int fd = open(RATE, O_RDONLY);
    if (fd < 0 || read(fd, saved, sizeof saved - 1) <= 0) {
        say("rate unread %d", errno);
        return 1;
    }
    close(fd);
    /* Values Linux refuses leave the sysctls as they are. */
    say("rate 0 %d", write_sysctl(RATE, "0"));
    say("percent 101 %d", write_sysctl(PERCENT, "101"));
    int set = write_sysctl(RATE, "1");
    say("rate 1 %d", set);
    if (set) return 1;
    cpu_set_t first;
    CPU_ZERO(&first);
    CPU_SET(0, &first);
    sched_setaffinity(0, sizeof first, &first);
    /* A frequency above the rate is refused, at open and as a period, of
       page faults: a clock's frequency is a period once it is open. */
    struct attr f = software(2);
    f.flags |= FREQ;
    f.sample_period = 2;
    attempt("freq 2", f, 0, -1, -1, 0);
    f.sample_period = 1;
    fd = (int)open_event(&f, 0, -1, -1, 0);
    uint64_t two = 2;
    say("freq 1 %d period 2 %ld", fd >= 0, fd >= 0 ? TRY(ioctl(fd, IOC_PERIOD, &two)) : 0L);
    if (fd >= 0) close(fd);
    /* cpu-clock every 100 us, for 20 ms of the thread's time. */
    struct attr a = software(0);
    a.sample_period = 100000;
    a.sample_type = SAMPLE_TID;
    a.flags |= DISABLED | SAMPLE_ID_ALL;
    void *page;
    fd = (int)open_event(&a, 0, -1, -1, 0);
    struct throttled t = {.pid = getpid(), .tid = (pid_t)syscall(SYS_gettid), .in_order = 1, .ids = 1};
    int mapped = fd >= 0 && map_event(fd, 9, PROT_READ | PROT_WRITE, MAP_SHARED, 0, &page) == 0;
    if (mapped) {
        ioctl(fd, IOC_ID, &t.id);
        ioctl(fd, IOC_ENABLE, 0);
        struct timespec from, now;
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &from);
        do {
            spin();
            clock_gettime(CLOCK_THREAD_CPUTIME_ID, &now);
        } while ((now.tv_sec - from.tv_sec) * 1000000000L + now.tv_nsec - from.tv_nsec < 20000000L);
        ioctl(fd, IOC_DISABLE, 0);
    }
    say("restored %d", write_sysctl(RATE, saved));
    say("mapped %d", mapped);
    if (!mapped) return 1;
    uint64_t tail = 0;
    each_record(page, &tail, see_throttled, &t);
    say("first %.6s in order %d ids %d cycles %d", t.first, t.in_order, t.ids, t.records >= 9);
    return 0;
}

/* What the cases compare the records with. */
struct expected {
    pid_t pid, tid, child, parent;
    char *anon, *exec_at, *shm, *heap, *shared, *ring;
    size_t anon_len;
    const char *path, *self;
    struct stat file;
    /* The device and inode /proc/self/maps gives the shared mapping. */
    unsigned shared_major, shared_minor;
    unsigned long shared_inode;
    /* The same of another event's ring buffer. */
    unsigned ring_major, ring_minor;
    unsigned long ring_inode;
    int mmap_records;
};

/* The device and inode of the mapping at `at` in /proc/self/maps: 1 if
   its line was found. */
static int maps_identity(const char *at, unsigned *major_, unsigned *minor_, unsigned long *inode) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;
    char line[512];
    int found = 0;
    while (!found && fgets(line, sizeof line, maps)) {
        unsigned long start;
        found = sscanf(line, "%lx-%*x %*s %*x %x:%x %lu", &start, major_, minor_, inode) == 4 &&
                start == (unsigned long)at;
    }
    fclose(maps);
    return found;
}

/* Whether the line of the mapping at `at` in /proc/self/maps names it
   `name`. */
static int maps_names(const char *at, const char *name) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;
    char line[512];
    int named = 0;
    while (fgets(line, sizeof line, maps)) {
        unsigned long start;
        int path = 0;
        if (sscanf(line, "%lx-%*x %*s %*x %*x:%*x %*u %n", &start, &path) < 1 || start != (unsigned long)at || !path)
            continue;
        line[strcspn(line, "\n")] = 0;
        named = !strcmp(line + path, name);
        break;
    }
    fclose(maps);
    return named;
}

/* An MMAP or MMAP2 record's name, at `words` 64-bit words in. */
static const char *mapping_name(const uint64_t *record, int mmap2) {
    return (const char *)(record + (mmap2 ? 9 : 5));
}

static void say_record(const uint64_t *record, void *with) {
    struct expected *e = with;
    uint32_t type = (uint32_t)record[0];
    unsigned misc = (unsigned)(record[0] >> 32) & 0xffff;
    const uint32_t *ids = (const uint32_t *)(record + 1);
    if (type == RECORD_MMAP || type == RECORD_MMAP2) {
        int mmap2 = type == RECORD_MMAP2;
        uint64_t start = record[2], len = record[3], pgoff = record[4];
        const char *name = mapping_name(record, mmap2);
        /* The emulator has no vDSO (see the limitations): Linux's records
           of its mappings at exec are not compared. */
        if (!strcmp(name, "[vdso]") || !strncmp(name, "[vvar", 5)) return;
        const uint32_t *words = (const uint32_t *)(record + 5);
        char *at = (char *)start;
        const char *what = "other";
        if (e->path && !strcmp(name, e->path)) what = "file";
        else if (!strcmp(name, "//anon")) what = "anon";
        else if (!strcmp(name, "/dev/zero (deleted)")) what = name;
        else if (!strncmp(name, "/SYSV", 5)) what = name;
        else if (!strcmp(name, "anon_inode:[perf_event]")) what = name;
        else if (name[0] == '[') what = name;
        say("%s %s data %d ids %d", mmap2 ? "mmap2" : "mmap", what, !!(misc & MISC_DATA),
            ids[0] == (uint32_t)e->pid && ids[1] == (uint32_t)e->tid);
        if (at <= e->anon && at + len > e->anon)
            say("  anon covers %d offset is address %d len %d", at + len >= e->anon + e->anon_len,
                pgoff == start, len == 4096 || len >= e->anon_len);
        if (at == e->exec_at)
            say("  exec offset %llu len %llu", (unsigned long long)pgoff, (unsigned long long)len);
        if (e->heap && at <= e->heap && at + len > e->heap)
            say("  heap covers the new break");
        if (mmap2) {
            say("  prot %u flags %u", words[6], words[7]);
            if (at == e->exec_at)
                say("  device %d inode %d", words[0] == major(e->file.st_dev) && words[1] == minor(e->file.st_dev),
                    *(const uint64_t *)(words + 2) == (uint64_t)e->file.st_ino);
            /* Shared anonymous memory's file: the device and inode its
               line in /proc/self/maps gives. */
            if (e->shared && at == e->shared)
                say("  shared device %d inode %d", words[0] == e->shared_major && words[1] == e->shared_minor,
                    *(const uint64_t *)(words + 2) == (uint64_t)e->shared_inode);
            /* A ring buffer's file: the event's anonymous inode. */
            if (e->ring && at == e->ring)
                say("  ring offset %llu len %llu device %d inode %d", (unsigned long long)pgoff,
                    (unsigned long long)len, words[0] == e->ring_major && words[1] == e->ring_minor,
                    *(const uint64_t *)(words + 2) == (uint64_t)e->ring_inode);
        }
        e->mmap_records++;
    } else if (type == RECORD_COMM) {
        const char *name = (const char *)(record + 2);
        say("comm exec %d ids %d name %s", !!(misc & MISC_DATA), ids[0] == (uint32_t)e->pid && ids[1] == (uint32_t)e->tid,
            e->self && !strncmp(name, e->self, 15) ? "self" : name);
    } else if (type == RECORD_FORK || type == RECORD_EXIT) {
        const uint32_t *parent = (const uint32_t *)(record + 2);
        const uint32_t *trailer = (const uint32_t *)(record + 4);
        /* pid, ppid, tid, ptid */
        say("%s child %d parent %d by %s", type == RECORD_FORK ? "fork" : "exit",
            ids[0] == (uint32_t)e->child && parent[0] == (uint32_t)e->child,
            type == RECORD_FORK ? ids[1] == (uint32_t)e->pid && parent[1] == (uint32_t)e->tid
                                : ids[1] == (uint32_t)e->parent && parent[1] == (uint32_t)e->parent,
            trailer[1] == (uint32_t)e->child ? "child" : trailer[1] == (uint32_t)e->tid ? "parent" : "other");
    } else {
        say("record %u", type);
    }
}

static int case_side_band(void) {
    struct expected e;
    memset(&e, 0, sizeof e);
    e.pid = e.parent = getpid();
    e.tid = (pid_t)syscall(SYS_gettid);
    char path[] = "/tmp/perf-side-band-XXXXXX";
    int file = mkstemp(path);
    static char zeros[2 * 4096];
    write(file, zeros, sizeof zeros);
    fstat(file, &e.file);
    e.path = path;
    /* Linux maps no buffer of an inherited event of every CPU: this one
       is of CPU 0, where the process and its child run, so that the
       child's exit is written too. */
    cpu_set_t first;
    CPU_ZERO(&first);
    CPU_SET(0, &first);
    sched_setaffinity(0, sizeof first, &first);
    void *all, *exec_only;
    int fd = open_side_band(0, 0, ATTR_MMAP2 | ATTR_MMAP_DATA | ATTR_COMM | ATTR_TASK | INHERIT, &all);
    int exec_fd = open_side_band(0, -1, ATTR_MMAP, &exec_only);
    say("open %d %d", fd >= 0, exec_fd >= 0);
    if (fd < 0 || exec_fd < 0) return 1;
    int id = shmget(IPC_PRIVATE, 8192, IPC_CREAT | 0600);
    char *old_break = (char *)syscall(SYS_brk, 0);
    ioctl(fd, IOC_ENABLE, 0);
    ioctl(exec_fd, IOC_ENABLE, 0);
    e.anon_len = 3 * 4096;
    e.anon = mmap(NULL, e.anon_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    e.exec_at = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, file, 4096);
    e.shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (e.shared == MAP_FAILED) e.shared = NULL;
    say("shared in maps %d",
        e.shared && maps_identity(e.shared, &e.shared_major, &e.shared_minor, &e.shared_inode));
    mprotect(e.anon, 4096, PROT_READ);
    mprotect(e.anon, 4096, PROT_READ);
    char *new_break = old_break + 3 * 4096;
    e.heap = (char *)syscall(SYS_brk, new_break) == new_break ? new_break - 1 : NULL;
    e.shm = shmat(id, NULL, 0);
    prctl(PR_SET_NAME, "side-band", 0, 0, 0);
    pid_t child = fork();
    if (child == 0) _exit(0);
    int status;
    waitpid(child, &status, 0);
    e.child = child;
    /* Another event's ring buffer, a shared mapping of its file. */
    struct attr ring_attr = software(9);
    ring_attr.flags |= DISABLED;
    int ring = (int)open_event(&ring_attr, 0, -1, -1, 0);
    void *ring_at = NULL;
    if (ring >= 0 && map_event(ring, 2, PROT_READ | PROT_WRITE, MAP_SHARED, 0, &ring_at) >= 0) e.ring = ring_at;
    ioctl(fd, IOC_DISABLE, 0);
    ioctl(exec_fd, IOC_DISABLE, 0);
    /* Its line in /proc/self/maps: the anonymous inode `fstat` gives. */
    struct stat ring_stat;
    int ring_found = e.ring && maps_identity(e.ring, &e.ring_major, &e.ring_minor, &e.ring_inode) &&
                     !fstat(ring, &ring_stat);
    say("ring in maps %d as fstat %d named %d", ring_found,
        ring_found && e.ring_major == major(ring_stat.st_dev) && e.ring_minor == minor(ring_stat.st_dev) &&
            e.ring_inode == (unsigned long)ring_stat.st_ino,
        ring_found && maps_names(e.ring, "anon_inode:[perf_event]"));
    shmdt(e.shm);
    shmctl(id, IPC_RMID, NULL);
    unlink(path);
    uint64_t tail = 0;
    say("all:");
    each_record(all, &tail, say_record, &e);
    say("exec only:");
    tail = 0;
    e.mmap_records = 0;
    each_record(exec_only, &tail, say_record, &e);
    say("exec only records %d", e.mmap_records);
    return 0;
}

/* The thread that writes the leader's `comm` in case_side_band_comm. */
static void *rename_leader(void *with) {
    const pid_t *ids = with;
    char at[64];
    snprintf(at, sizeof at, "/proc/%d/task/%d/comm", ids[0], ids[1]);
    int to = open(at, O_WRONLY);
    say("thread write %zd", write(to, "by-thread", 9));
    close(to);
    return NULL;
}

/* A COMM record of each write to `comm`: what was renamed in the record,
   who wrote it after (sample_id_all), and which events it reached. */
static void say_comm(const uint64_t *record, void *with) {
    const pid_t *ids = with;
    if ((uint32_t)record[0] != RECORD_COMM) {
        say("record %u", (uint32_t)record[0]);
        return;
    }
    unsigned misc = (unsigned)(record[0] >> 32) & 0xffff;
    uint64_t size = record[0] >> 48;
    const uint32_t *renamed = (const uint32_t *)(record + 1);
    const uint32_t *writer = (const uint32_t *)((const char *)record + size - 8);
    say("comm exec %d leader %d name %s by %s", !!(misc & MISC_DATA),
        renamed[0] == (uint32_t)ids[0] && renamed[1] == (uint32_t)ids[1], (const char *)(record + 2),
        writer[0] != (uint32_t)ids[0] ? "other" : writer[1] == (uint32_t)ids[1] ? "leader" : "thread");
}

static int case_side_band_comm(void) {
    pid_t ids[2] = {getpid(), (pid_t)syscall(SYS_gettid)};
    /* Pinned to CPU 0, as the inherited event is of that CPU only. */
    cpu_set_t first;
    CPU_ZERO(&first);
    CPU_SET(0, &first);
    sched_setaffinity(0, sizeof first, &first);
    void *all, *leader;
    int fd = open_side_band(0, 0, ATTR_COMM | INHERIT, &all);
    int leader_fd = open_side_band(0, -1, ATTR_COMM, &leader);
    say("open %d %d", fd >= 0, leader_fd >= 0);
    if (fd < 0 || leader_fd < 0) return 1;
    ioctl(fd, IOC_ENABLE, 0);
    ioctl(leader_fd, IOC_ENABLE, 0);
    int own = open("/proc/self/comm", O_WRONLY);
    say("leader write %zd", write(own, "by-proc", 7));
    close(own);
    pthread_t thread;
    pthread_create(&thread, NULL, rename_leader, ids);
    pthread_join(thread, NULL);
    /* Another process may not rename this one's threads: no record. */
    pid_t child = fork();
    if (child == 0) {
        char at[64];
        snprintf(at, sizeof at, "/proc/%d/comm", ids[0]);
        int to = open(at, O_WRONLY);
        ssize_t wrote = write(to, "by-child", 8);
        _exit(wrote < 0 && errno == EINVAL ? 0 : 1);
    }
    int status;
    waitpid(child, &status, 0);
    say("child status %d", status);
    ioctl(fd, IOC_DISABLE, 0);
    ioctl(leader_fd, IOC_DISABLE, 0);
    char name[16] = {0};
    prctl(PR_GET_NAME, name, 0, 0, 0);
    say("name %s", name);
    uint64_t tail = 0;
    say("all:");
    each_record(all, &tail, say_comm, ids);
    say("leader only:");
    tail = 0;
    each_record(leader, &tail, say_comm, ids);
    return 0;
}

static int case_side_band_exec(const char *self) {
    struct expected e;
    memset(&e, 0, sizeof e);
    /* The program the child runs, by the path the kernel names it: the
       emulator starts this one under another name than it gives the
       child to run. */
    char exe[PATH_MAX];
    if (!realpath(self, exe)) snprintf(exe, sizeof exe, "%s", self);
    const char *base = strrchr(self, '/');
    e.self = base ? base + 1 : self;
    e.path = exe;
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
    e.pid = e.tid = e.child = child;
    e.parent = getpid();
    void *page;
    int fd = open_side_band(child, -1, ATTR_MMAP2 | ATTR_MMAP_DATA | ATTR_COMM | ENABLE_ON_EXEC, &page);
    say("open %d", fd >= 0);
    if (fd < 0) return 1;
    write(pipes[1], "g", 1);
    close(pipes[1]);
    int status;
    waitpid(child, &status, 0);
    say("child status %d", status);
    uint64_t tail = 0;
    each_record(page, &tail, say_record, &e);
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
    if (!strcmp(mode, "perf-ring-gup")) return case_ring_gup();
    if (!strcmp(mode, "perf-gup")) return case_gup();
    if (!strcmp(mode, "perf-mmap")) return case_mmap();
    if (!strcmp(mode, "perf-output")) return case_output();
    if (!strcmp(mode, "perf-sample")) return case_sample();
    if (!strcmp(mode, "perf-wakeup")) return case_wakeup();
    if (!strcmp(mode, "perf-side-band")) return case_side_band();
    if (!strcmp(mode, "perf-side-band-comm")) return case_side_band_comm();
    if (!strcmp(mode, "perf-throttle")) return case_throttle();
    if (!strcmp(mode, "perf-side-band-exec")) return case_side_band_exec(argc > 2 ? argv[2] : argv[0]);
    if (!strcmp(mode, "perf-exec")) return case_exec(argc > 2 ? argv[2] : argv[0]);
    if (!strcmp(mode, "perf-spin")) {
        spin();
        spin();
        return 0;
    }
    return 2;
}
