#!/usr/bin/env python3
"""Check that the system-call tables of the features pages list exactly the implemented calls."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "crates/paludarium-kernel/src"
PAGES = (ROOT / "docs/guide/features.md", ROOT / "docs/ja/guide/features.md")

# Linux x86-64 names of the implemented numbers. A number the kernel handles
# but this map lacks is an error, so a new system call gets its name here.
# Only the names of `nr::` constants are checked against the kernel; the
# others must match the Linux x86-64 table by hand.
# The dispatch sites are read with regular expressions that assume rustfmt's
# layout (implemented() below); a call dispatched in another form is missed.
LAYOUT = "the kernel's dispatch is written in a form scripts/syscall-docs.py does not read"

NAMES = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    4: "stat",
    5: "fstat",
    6: "lstat",
    7: "poll",
    8: "lseek",
    9: "mmap",
    10: "mprotect",
    11: "munmap",
    12: "brk",
    13: "rt_sigaction",
    14: "rt_sigprocmask",
    15: "rt_sigreturn",
    16: "ioctl",
    17: "pread64",
    18: "pwrite64",
    19: "readv",
    20: "writev",
    21: "access",
    22: "pipe",
    23: "select",
    24: "sched_yield",
    25: "mremap",
    26: "msync",
    27: "mincore",
    28: "madvise",
    29: "shmget",
    30: "shmat",
    31: "shmctl",
    32: "dup",
    33: "dup2",
    34: "pause",
    35: "nanosleep",
    36: "getitimer",
    37: "alarm",
    38: "setitimer",
    39: "getpid",
    40: "sendfile",
    41: "socket",
    42: "connect",
    43: "accept",
    44: "sendto",
    45: "recvfrom",
    46: "sendmsg",
    47: "recvmsg",
    48: "shutdown",
    49: "bind",
    50: "listen",
    51: "getsockname",
    52: "getpeername",
    53: "socketpair",
    54: "setsockopt",
    55: "getsockopt",
    56: "clone",
    57: "fork",
    58: "vfork",
    59: "execve",
    60: "exit",
    61: "wait4",
    62: "kill",
    63: "uname",
    64: "semget",
    65: "semop",
    66: "semctl",
    67: "shmdt",
    68: "msgget",
    69: "msgsnd",
    70: "msgrcv",
    71: "msgctl",
    72: "fcntl",
    73: "flock",
    74: "fsync",
    75: "fdatasync",
    76: "truncate",
    77: "ftruncate",
    78: "getdents",
    79: "getcwd",
    80: "chdir",
    81: "fchdir",
    82: "rename",
    83: "mkdir",
    84: "rmdir",
    85: "creat",
    86: "link",
    87: "unlink",
    88: "symlink",
    89: "readlink",
    90: "chmod",
    91: "fchmod",
    92: "chown",
    93: "fchown",
    94: "lchown",
    95: "umask",
    96: "gettimeofday",
    97: "getrlimit",
    98: "getrusage",
    99: "sysinfo",
    100: "times",
    102: "getuid",
    104: "getgid",
    105: "setuid",
    106: "setgid",
    107: "geteuid",
    108: "getegid",
    109: "setpgid",
    110: "getppid",
    111: "getpgrp",
    112: "setsid",
    113: "setreuid",
    114: "setregid",
    115: "getgroups",
    116: "setgroups",
    117: "setresuid",
    118: "getresuid",
    119: "setresgid",
    120: "getresgid",
    121: "getpgid",
    122: "setfsuid",
    123: "setfsgid",
    124: "getsid",
    125: "capget",
    126: "capset",
    127: "rt_sigpending",
    128: "rt_sigtimedwait",
    129: "rt_sigqueueinfo",
    130: "rt_sigsuspend",
    131: "sigaltstack",
    132: "utime",
    133: "mknod",
    135: "personality",
    136: "ustat",
    137: "statfs",
    138: "fstatfs",
    140: "getpriority",
    141: "setpriority",
    142: "sched_setparam",
    143: "sched_getparam",
    144: "sched_setscheduler",
    145: "sched_getscheduler",
    146: "sched_get_priority_max",
    147: "sched_get_priority_min",
    148: "sched_rr_get_interval",
    149: "mlock",
    150: "munlock",
    151: "mlockall",
    152: "munlockall",
    153: "vhangup",
    157: "prctl",
    158: "arch_prctl",
    159: "adjtimex",
    160: "setrlimit",
    162: "sync",
    163: "acct",
    164: "settimeofday",
    170: "sethostname",
    171: "setdomainname",
    172: "iopl",
    173: "ioperm",
    186: "gettid",
    187: "readahead",
    188: "setxattr",
    189: "lsetxattr",
    190: "fsetxattr",
    191: "getxattr",
    192: "lgetxattr",
    193: "fgetxattr",
    194: "listxattr",
    195: "llistxattr",
    196: "flistxattr",
    197: "removexattr",
    198: "lremovexattr",
    199: "fremovexattr",
    200: "tkill",
    201: "time",
    202: "futex",
    203: "sched_setaffinity",
    204: "sched_getaffinity",
    206: "io_setup",
    207: "io_destroy",
    208: "io_getevents",
    209: "io_submit",
    210: "io_cancel",
    213: "epoll_create",
    216: "remap_file_pages",
    217: "getdents64",
    218: "set_tid_address",
    219: "restart_syscall",
    220: "semtimedop",
    221: "fadvise64",
    222: "timer_create",
    223: "timer_settime",
    224: "timer_gettime",
    225: "timer_getoverrun",
    226: "timer_delete",
    227: "clock_settime",
    228: "clock_gettime",
    229: "clock_getres",
    230: "clock_nanosleep",
    231: "exit_group",
    232: "epoll_wait",
    233: "epoll_ctl",
    234: "tgkill",
    235: "utimes",
    237: "mbind",
    238: "set_mempolicy",
    239: "get_mempolicy",
    240: "mq_open",
    241: "mq_unlink",
    242: "mq_timedsend",
    243: "mq_timedreceive",
    244: "mq_notify",
    245: "mq_getsetattr",
    247: "waitid",
    251: "ioprio_set",
    252: "ioprio_get",
    253: "inotify_init",
    254: "inotify_add_watch",
    255: "inotify_rm_watch",
    256: "migrate_pages",
    257: "openat",
    258: "mkdirat",
    259: "mknodat",
    260: "fchownat",
    261: "futimesat",
    262: "newfstatat",
    263: "unlinkat",
    264: "renameat",
    265: "linkat",
    266: "symlinkat",
    267: "readlinkat",
    268: "fchmodat",
    269: "faccessat",
    270: "pselect6",
    271: "ppoll",
    272: "unshare",
    273: "set_robust_list",
    274: "get_robust_list",
    275: "splice",
    276: "tee",
    277: "sync_file_range",
    278: "vmsplice",
    279: "move_pages",
    280: "utimensat",
    281: "epoll_pwait",
    282: "signalfd",
    283: "timerfd_create",
    284: "eventfd",
    285: "fallocate",
    286: "timerfd_settime",
    287: "timerfd_gettime",
    288: "accept4",
    289: "signalfd4",
    290: "eventfd2",
    291: "epoll_create1",
    292: "dup3",
    293: "pipe2",
    294: "inotify_init1",
    295: "preadv",
    296: "pwritev",
    297: "rt_tgsigqueueinfo",
    299: "recvmmsg",
    302: "prlimit64",
    303: "name_to_handle_at",
    304: "open_by_handle_at",
    305: "clock_adjtime",
    306: "syncfs",
    307: "sendmmsg",
    308: "setns",
    309: "getcpu",
    310: "process_vm_readv",
    311: "process_vm_writev",
    312: "kcmp",
    314: "sched_setattr",
    315: "sched_getattr",
    316: "renameat2",
    317: "seccomp",
    318: "getrandom",
    319: "memfd_create",
    322: "execveat",
    324: "membarrier",
    325: "mlock2",
    326: "copy_file_range",
    327: "preadv2",
    328: "pwritev2",
    329: "pkey_mprotect",
    330: "pkey_alloc",
    331: "pkey_free",
    332: "statx",
    333: "io_pgetevents",
    334: "rseq",
    424: "pidfd_send_signal",
    425: "io_uring_setup",
    426: "io_uring_enter",
    427: "io_uring_register",
    434: "pidfd_open",
    435: "clone3",
    436: "close_range",
    437: "openat2",
    438: "pidfd_getfd",
    439: "faccessat2",
    440: "process_madvise",
    441: "epoll_pwait2",
    444: "landlock_create_ruleset",
    445: "landlock_add_rule",
    446: "landlock_restrict_self",
    447: "memfd_secret",
    448: "process_mrelease",
    449: "futex_waitv",
    450: "set_mempolicy_home_node",
    451: "cachestat",
    452: "fchmodat2",
    453: "map_shadow_stack",
    454: "futex_wake",
    455: "futex_wait",
    456: "futex_requeue",
    462: "mseal",
    463: "setxattrat",
    464: "getxattrat",
    465: "listxattrat",
    466: "removexattrat",
    468: "file_getattr",
    469: "file_setattr",
}


def between(text, start, end):
    """The text after the first `start` up to the next `end`."""
    begin = text.find(start)
    stop = text.find(end, begin + len(start)) if begin >= 0 else -1
    if stop < 0:
        raise ValueError(f"{start!r} ... {end!r} not found; {LAYOUT}")
    return text[begin + len(start) : stop]


def some(where, numbers):
    """The numbers read from one dispatch site, which must not be empty."""
    if not numbers:
        raise ValueError(f"{where}: no system-call numbers found; {LAYOUT}")
    return numbers


def implemented():
    """The numbers the kernel dispatches; anything else returns ENOSYS."""
    syscalls = (KERNEL / "syscalls.rs").read_text(encoding="utf-8")
    consts = {
        name: int(value)
        for name, value in re.findall(
            r"pub const (\w+): u64 = (\d+);", between(syscalls, "pub mod nr", "\n}\n")
        )
    }
    for name, value in consts.items():
        if NAMES.get(value, name.lower()) != name.lower():
            raise ValueError(f"nr::{name} is {value}, which NAMES calls {NAMES[value]}")
    table = between(syscalls, "pub fn u1()", "SyscallTable { handlers }")
    numbers = some("u1() entries", {consts[name] for name in re.findall(r"\(\s*nr::(\w+),", table)})
    numbers |= some(
        "u1() inserts", {int(n) for n in re.findall(r"handlers\.insert\((\d+),", table)}
    )
    groups = re.findall(r"for number in \[([\d,\s]+)\]", table)
    numbers |= some("u1() loops", {int(n) for group in groups for n in re.findall(r"\d+", group)})
    files = (KERNEL / "files.rs").read_text(encoding="utf-8")
    numbers |= some(
        "files::NUMBERS",
        {
            int(n)
            for n in re.findall(r"\d+", between(files, "pub const NUMBERS: &[u64] = &[", "];"))
        },
    )
    # The calls the kernel handles before the table, by match arm.
    for path, function in (
        ("processes.rs", "fn process_syscall("),
        ("threads.rs", "fn thread_syscall("),
    ):
        body = between((KERNEL / path).read_text(encoding="utf-8"), function, "\n    }\n")
        arms = between(body, "let result = match n {", "\n        };")
        found = re.findall(r"^ {12}(\d+(?: \| \d+)*)(?: if [^\n]*)? =>", arms, re.MULTILINE)
        numbers |= some(function, {int(n) for arm in found for n in arm.split("|")})
    lib = (KERNEL / "lib.rs").read_text(encoding="utf-8")
    numbers |= some(
        "Kernel::syscall",
        {
            int(n)
            for n in re.findall(
                r"if number == (\d+) \{", between(lib, "fn syscall(", "let Some(handler)")
            )
        },
    )
    return numbers


def listed(page):
    """The lower-case names in backquotes in the system-call table of a page."""
    tables = re.findall(r"(?:^\|[^\n]*\n)+", page.read_text(encoding="utf-8"), re.MULTILINE)
    table = [block for block in tables if "`getrandom`" in block]
    if len(table) != 1:
        raise ValueError(f"{page.relative_to(ROOT)}: no single system-call table")
    return set(re.findall(r"`([a-z_][a-z0-9_]*)`", table[0]))


def main():
    try:
        numbers = implemented()
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    errors = [
        f"number {n} is implemented but has no name in NAMES"
        for n in sorted(numbers - NAMES.keys())
    ]
    errors += [
        f"NAMES has {n} ({NAMES[n]}), which is not implemented"
        for n in sorted(NAMES.keys() - numbers)
    ]
    names = {NAMES[n] for n in numbers if n in NAMES}
    for page in PAGES:
        found = listed(page)
        where = page.relative_to(ROOT)
        errors += [
            f"{where}: `{name}` is implemented but not listed" for name in sorted(names - found)
        ]
        errors += [
            f"{where}: `{name}` is listed but not implemented" for name in sorted(found - names)
        ]
    for error in errors:
        print(error, file=sys.stderr)
    if any(error.endswith("not implemented") for error in errors):
        print(f"If the kernel does handle it, {LAYOUT}: extend implemented().", file=sys.stderr)
    if errors:
        return 1
    print(f"{len(names)} system calls listed on {len(PAGES)} pages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
