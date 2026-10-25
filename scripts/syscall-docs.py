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
    28: "madvise",
    32: "dup",
    33: "dup2",
    34: "pause",
    35: "nanosleep",
    38: "setitimer",
    39: "getpid",
    40: "sendfile",
    41: "socket",
    44: "sendto",
    45: "recvfrom",
    48: "shutdown",
    53: "socketpair",
    56: "clone",
    57: "fork",
    58: "vfork",
    59: "execve",
    60: "exit",
    61: "wait4",
    62: "kill",
    63: "uname",
    72: "fcntl",
    73: "flock",
    74: "fsync",
    75: "fdatasync",
    76: "truncate",
    77: "ftruncate",
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
    95: "umask",
    97: "getrlimit",
    98: "getrusage",
    99: "sysinfo",
    100: "times",
    102: "getuid",
    104: "getgid",
    107: "geteuid",
    108: "getegid",
    109: "setpgid",
    110: "getppid",
    111: "getpgrp",
    112: "setsid",
    115: "getgroups",
    121: "getpgid",
    124: "getsid",
    127: "rt_sigpending",
    128: "rt_sigtimedwait",
    129: "rt_sigqueueinfo",
    130: "rt_sigsuspend",
    131: "sigaltstack",
    137: "statfs",
    138: "fstatfs",
    140: "getpriority",
    141: "setpriority",
    157: "prctl",
    158: "arch_prctl",
    160: "setrlimit",
    162: "sync",
    186: "gettid",
    200: "tkill",
    202: "futex",
    204: "sched_getaffinity",
    213: "epoll_create",
    217: "getdents64",
    218: "set_tid_address",
    219: "restart_syscall",
    221: "fadvise64",
    222: "timer_create",
    223: "timer_settime",
    224: "timer_gettime",
    225: "timer_getoverrun",
    226: "timer_delete",
    228: "clock_gettime",
    229: "clock_getres",
    230: "clock_nanosleep",
    231: "exit_group",
    232: "epoll_wait",
    233: "epoll_ctl",
    234: "tgkill",
    247: "waitid",
    257: "openat",
    258: "mkdirat",
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
    280: "utimensat",
    281: "epoll_pwait",
    283: "timerfd_create",
    285: "fallocate",
    286: "timerfd_settime",
    287: "timerfd_gettime",
    290: "eventfd2",
    291: "epoll_create1",
    292: "dup3",
    293: "pipe2",
    295: "preadv",
    296: "pwritev",
    297: "rt_tgsigqueueinfo",
    302: "prlimit64",
    318: "getrandom",
    319: "memfd_create",
    326: "copy_file_range",
    332: "statx",
    424: "pidfd_send_signal",
    434: "pidfd_open",
    435: "clone3",
    436: "close_range",
    439: "faccessat2",
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
    numbers = some("u1() entries", {consts[name] for name in re.findall(r"\(nr::(\w+),", table)})
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
