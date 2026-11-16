/* perf_event_open, compared with Linux: the order of its checks and their
   errors, and the software events the emulator counts (task-clock,
   cpu-clock and the dummy event) with read, the read formats, groups, the
   ENABLE, DISABLE, RESET and ID ioctls, enable_on_exec, and prctl's
   PR_TASK_PERF_EVENTS_DISABLE and ENABLE of the events a thread opened.

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
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
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
#define EXCLUDE_KERNEL (1ULL << 5)
#define EXCLUDE_HV (1ULL << 6)
#define FREQ (1ULL << 10)
#define ENABLE_ON_EXEC (1ULL << 12)
#define USE_CLOCKID (1ULL << 25)
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
#define IOC_ID _IOR('$', 7, uint64_t *)
#define IOC_FLAG_GROUP 1

#define FLAG_FD_NO_GROUP 1
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

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    alarm(20);
    if (!strcmp(mode, "perf-calls")) return case_calls();
    if (!strcmp(mode, "perf-counts")) return case_counts();
    if (!strcmp(mode, "perf-prctl")) return case_prctl();
    if (!strcmp(mode, "perf-exec")) return case_exec(argc > 2 ? argv[2] : argv[0]);
    if (!strcmp(mode, "perf-spin")) {
        spin();
        spin();
        return 0;
    }
    return 2;
}
