//! The width of each system call's arguments, from the C types Linux's
//! `SYSCALL_DEFINE`s declare them with on x86-64.
//!
//! Linux casts each register to its parameter's type before the call runs, so
//! an `int` or `unsigned int` argument is read from the low 32 bits and a
//! `umode_t` from the low 16: a caller may leave the rest of the register
//! dirty (fish's `fcntl` does). [`narrow`] does the same once, before any
//! handler reads the arguments. The registers themselves are left as they are,
//! as a restarted call finds them on Linux.

/// One letter per argument, from the first: `i` for a signed 32-bit type
/// (`int`, `pid_t`, `clockid_t`, `timer_t`, `key_t`, `mqd_t`, `rwf_t`), which
/// is sign-extended; `u` for an unsigned one (`unsigned int`, `u32`, `uid_t`,
/// `gid_t`, `dev_t`'s `unsigned`), which is zero-extended; `h` for `umode_t`;
/// and `l` for a full register (pointers, `long`, `size_t`, `loff_t`).
/// Arguments past the end are full registers. An `unsigned long` that Linux
/// itself passes on as an `unsigned` (an iovec count) is `u`: `import_iovec`
/// takes an `unsigned` on the kernel CI runs. Linux master widened it to
/// `unsigned long` in 965e5e451146 (2026-11-05), so a count past 32 bits is
/// `EINVAL` there; these become `l` once the CI kernel has that change (and
/// `aio`'s vectored `aio_nbytes` is read whole).
fn widths(number: u64) -> &'static [u8] {
    match number {
        // read, write, close, fstat, pread64, pwrite64, dup, fsync,
        // fdatasync, ftruncate, fchdir, fstatfs, alarm, personality, ustat,
        // eventfd, iopl, memfd_secret
        0 | 1 | 3 | 5 | 17 | 18 | 32 | 74 | 75 | 77 | 81 | 138 | 37 | 135 | 136 | 284 | 172
        | 447 => b"u",
        // open: flags, mode
        2 => b"lih",
        // poll: nfds, timeout
        7 => b"lui",
        // lseek: whence
        8 => b"ulu",
        // rt_sigaction, rt_sigprocmask, select, getitimer, setitimer, exit,
        // umask, getrusage, getgroups, setgroups, getpgid, getsid,
        // sched_setparam, sched_getparam, sched_getscheduler,
        // sched_get_priority_max/min, sched_rr_get_interval, mlockall, prctl,
        // arch_prctl, sysfs, modify_ldt, readahead, fgetxattr, flistxattr,
        // fremovexattr, epoll_create, timer_gettime, timer_getoverrun,
        // timer_delete, clock_settime, clock_gettime, clock_getres,
        // exit_group, set_mempolicy, mq_timedreceive, mq_notify,
        // mq_getsetattr, migrate_pages, futimesat, pselect6, get_robust_list,
        // signalfd, timerfd_gettime, epoll_create1, inotify_init1,
        // clock_adjtime, syncfs, userfaultfd,
        // pkey_free, openat2
        13 | 14 | 23 | 36 | 38 | 60 | 95 | 98 | 115 | 116 | 121 | 124 | 142 | 143 | 145 | 146
        | 147 | 148 | 151 | 157 | 158 | 139 | 154 | 187 | 193 | 196 | 199 | 213 | 224 | 225
        | 226 | 227 | 228 | 229 | 231 | 238 | 243 | 244 | 245 | 256 | 261 | 270 | 274 | 282
        | 287 | 291 | 294 | 305 | 306 | 323 | 331 | 437 => b"i",
        // ioctl, fcntl, flock: fd, cmd; dup2; setreuid, setregid;
        // fanotify_init; seccomp
        16 | 72 | 73 | 33 | 113 | 114 | 300 | 317 => b"uu",
        // access: mode
        21 => b"li",
        // msync, madvise, mlock2, ioperm: the last
        26 | 28 | 325 | 173 => b"lli",
        // shmget: key, size, flags; shmat; syslog
        29 | 30 | 103 => b"ili",
        // shmctl, sendfile, shutdown, listen, kill, msgget, msgctl,
        // getpriority, setpgid, sched_setscheduler, tkill, timer_settime,
        // clock_nanosleep, ioprio_get, inotify_rm_watch, timerfd_create,
        // fallocate, timerfd_settime, setns
        31 | 40 | 48 | 50 | 62 | 68 | 71 | 140 | 109 | 144 | 200 | 223 | 230 | 252 | 255 | 283
        | 285 | 286 | 308 => b"ii",
        // socket, socketpair, getsockopt, semget, semctl, setpriority,
        // epoll_ctl, tgkill, ioprio_set, rt_tgsigqueueinfo, kcmp
        41 | 53 | 55 | 64 | 66 | 141 | 233 | 234 | 251 | 297 | 312 => b"iii",
        // connect, bind: fd, addrlen; finit_module, open_by_handle_at: fd, flags
        42 | 49 | 313 | 304 => b"ili",
        // accept, getsockname, getpeername: fd
        43 | 51 | 52 => b"i",
        // sendto: fd, flags, addrlen
        44 => b"illuli",
        // recvfrom: fd, flags
        45 => b"illu",
        // sendmsg, recvmsg: fd, flags; semop, semtimedop: nsops
        46 | 47 | 65 | 220 => b"ilu",
        // setsockopt: fd, level, optname, optlen
        54 => b"iiili",
        // wait4: pid, options
        61 => b"ili",
        // msgsnd: msqid, msgflg
        69 => b"illi",
        // msgrcv: msqid, msgflg
        70 => b"illli",
        // getdents, getdents64: fd, count
        78 | 217 => b"ulu",
        // mkdir, creat, chmod: mode
        83 | 85 | 90 => b"lh",
        // readlink: bufsiz; umount2, swapon, sethostname, setdomainname, pipe2
        89 => b"lli",
        166 | 167 | 170 | 171 | 293 => b"li",
        // fchmod: fd, mode
        91 => b"uh",
        // chown, lchown: uid, gid
        92 | 94 => b"luu",
        // fchown: fd, uid, gid; setresuid, setresgid; close_range
        93 | 117 | 119 | 436 => b"uuu",
        // getrlimit, setrlimit, setuid, setgid, setfsuid, setfsgid,
        // io_setup, io_uring_setup
        97 | 160 | 105 | 106 | 122 | 123 | 206 | 425 => b"u",
        // rt_sigqueueinfo: pid, sig
        129 => b"ii",
        // mknod: mode, dev
        133 => b"lhu",
        // reboot
        169 => b"iiu",
        // setxattr, lsetxattr: flags
        188 | 189 => b"lllli",
        // fsetxattr: fd, flags
        190 => b"illli",
        // futex: op, val, (timeout, uaddr2), val3
        202 => b"liullu",
        // sched_setaffinity, sched_getaffinity: pid, len; prlimit64: pid,
        // resource; pidfd_open: pid, flags
        203 | 204 | 302 | 434 => b"iu",
        // fadvise64: fd, advice
        221 => b"illi",
        // timer_create: clock
        222 => b"i",
        // epoll_wait, epoll_pwait: epfd, maxevents, timeout
        232 | 281 => b"ilii",
        // mbind: flags
        237 => b"lllllu",
        // mq_open: oflag, mode
        240 => b"lih",
        // mq_timedsend: mqdes, prio
        242 => b"illu",
        // waitid: which, pid, options
        247 => b"iili",
        // inotify_add_watch: fd, mask
        254 => b"ilu",
        // openat: dfd, flags, mode
        257 => b"ilih",
        // mkdirat, fchmodat: dfd, mode
        258 | 268 => b"ilh",
        // mknodat: dfd, mode, dev
        259 => b"ilhu",
        // fchownat: dfd, uid, gid, flag
        260 => b"iluui",
        // newfstatat, utimensat, readlinkat: dfd, the last
        262 | 280 | 267 => b"illi",
        // unlinkat, faccessat: dfd, the third
        263 | 269 => b"ili",
        // renameat: olddfd, newdfd
        264 => b"ili",
        // linkat: olddfd, newdfd, flags
        265 => b"ilili",
        // symlinkat: newdfd
        266 => b"li",
        // ppoll: nfds
        271 => b"lu",
        // splice, copy_file_range: fd_in, fd_out, flags
        275 | 326 => b"ilillu",
        // tee: fdin, fdout, flags
        276 => b"iilu",
        // sync_file_range: fd, flags
        277 => b"illu",
        // vmsplice: fd, nr_segs, flags
        278 => b"iluu",
        // readv, writev, preadv, pwritev: vlen. Linux declares it unsigned
        // long but hands it to import_iovec, whose nr_segs is unsigned
        // before 965e5e451146 (see widths).
        19 | 20 | 295 | 296 => b"llu",
        // process_vm_readv, process_vm_writev: pid, liovcnt (import_iovec's
        // too; riovcnt is read whole)
        310 | 311 => b"ilu",
        // move_pages: pid, flags
        279 => b"illlli",
        // accept4, signalfd4: fd, flags
        288 | 289 => b"illi",
        // eventfd2: count, flags
        290 => b"ui",
        // dup3: oldfd, newfd, flags
        292 => b"uui",
        // perf_event_open: pid, cpu, group_fd
        298 => b"liii",
        // recvmmsg, sendmmsg: fd, vlen, flags
        299 | 307 => b"iluu",
        // fanotify_mark: fd, flags, (mask), dfd
        301 => b"iuli",
        // name_to_handle_at: dfd, flag
        303 => b"illli",
        // sched_setattr: pid, flags
        314 => b"ilu",
        // sched_getattr: pid, size, flags
        315 => b"iluu",
        // renameat2: olddfd, newdfd, flags
        316 => b"ililu",
        // getrandom: flags
        318 => b"llu",
        // memfd_create: flags
        319 => b"lu",
        // kexec_file_load: kernel_fd, initrd_fd
        320 => b"ii",
        // bpf: cmd, size
        321 => b"ilu",
        // execveat: fd, flags
        322 => b"illli",
        // membarrier: cmd, flags, cpu_id
        324 => b"iui",
        // preadv2, pwritev2: vlen (import_iovec's), flags
        327 | 328 => b"llulli",
        // pkey_mprotect: pkey
        329 => b"llli",
        // statx: dfd, flags, mask
        332 => b"iluu",
        // rseq: len, flags, sig
        334 => b"luiu",
        // pidfd_send_signal: pidfd, sig, flags
        424 => b"iilu",
        // io_uring_enter: fd, to_submit, min_complete, flags
        426 => b"uuuu",
        // io_uring_register: fd, op, nr_args
        427 => b"uulu",
        // open_tree, fspick: dfd, flags
        428 | 433 => b"ilu",
        // move_mount: from_dfd, to_dfd, flags
        429 => b"ililu",
        // fsopen: flags
        430 => b"lu",
        // fsconfig: fd, cmd, aux
        431 => b"iulli",
        // fsmount: fs_fd, flags, attr_flags
        432 => b"iuu",
        // pidfd_getfd: pidfd, fd, flags
        438 => b"iiu",
        // faccessat2: dfd, mode, flags
        439 => b"ilii",
        // process_madvise: pidfd, behavior, flags
        440 => b"illiu",
        // epoll_pwait2: epfd, maxevents
        441 => b"ili",
        // mount_setattr: dfd, flags
        442 => b"ilu",
        // quotactl_fd: fd, cmd, id
        443 => b"uuu",
        // landlock_create_ruleset: flags
        444 => b"llu",
        // landlock_add_rule: ruleset_fd, rule_type, flags
        445 => b"iilu",
        // landlock_restrict_self, process_mrelease: fd, flags
        446 | 448 => b"iu",
        // futex_waitv: nr_futexes, flags, clockid
        449 => b"luuli",
        // cachestat: fd, flags
        451 => b"ullu",
        // fchmodat2: dfd, mode, flags
        452 => b"ilhu",
        // map_shadow_stack: flags
        453 => b"llu",
        // futex_wake: nr, flags
        454 => b"lliu",
        // futex_wait: flags, clockid
        455 => b"llluli",
        // futex_requeue: flags, nr_wake, nr_requeue
        456 => b"luii",
        // statmount, listmount: flags
        457 | 458 => b"lllu",
        // lsm_get_self_attr: attr, flags
        459 => b"ullu",
        // lsm_set_self_attr: attr, size, flags
        460 => b"uluu",
        // lsm_list_modules: flags
        461 => b"llu",
        // setxattrat, getxattrat, listxattrat, removexattrat,
        // open_tree_attr: dfd, at_flags
        463..=467 => b"ilu",
        // file_getattr, file_setattr: dfd, at_flags
        468 | 469 => b"illlu",
        // delete_module: flags
        176 => b"lu",
        // quotactl: cmd, id
        179 => b"ulu",
        // add_key: ringid
        248 => b"lllli",
        // request_key: destringid
        249 => b"llli",
        // keyctl: option
        250 => b"i",
        // Every argument a full register (kexec_load and mseal among those
        // with only unsigned long flags), or a number Linux does not have.
        _ => b"",
    }
}

/// Narrows `args` of system call `number` (itself already cut to 32 bits by
/// `Kernel::syscall`) to their C types, as Linux's syscall wrappers do.
pub(crate) fn narrow(number: u64, args: &mut [u64; 6]) {
    for (arg, width) in args.iter_mut().zip(widths(number)) {
        *arg = match width {
            b'i' => i64::from(*arg as i32) as u64,
            b'u' => u64::from(*arg as u32),
            b'h' => u64::from(*arg as u16),
            _ => *arg,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrows_each_type() {
        let dirty = 0x1234_5678_0000_0000;
        // openat(AT_FDCWD, path, O_RDONLY, 0o10644 | bits past umode_t)
        let mut args = [
            dirty | 0xffff_ff9c,
            dirty | 0x1000,
            dirty,
            dirty | 0x1_01a4,
            0,
            0,
        ];
        narrow(257, &mut args);
        assert_eq!(args, [(-100i64) as u64, dirty | 0x1000, 0, 0x1a4, 0, 0]);
        // setresuid(-1, ...): uid_t stays unsigned.
        let mut args = [u64::MAX, dirty | 5, 0, 0, 0, 0];
        narrow(117, &mut args);
        assert_eq!(args[..2], [0xffff_ffff, 5]);
        // An unknown number keeps its registers.
        let mut args = [dirty; 6];
        narrow(100_000, &mut args);
        assert_eq!(args, [dirty; 6]);
    }

    /// Calls whose arguments are all full registers, so that one missing from
    /// the table above is a choice, not an oversight: a handler for any other
    /// number must give its narrower arguments a line there.
    #[test]
    fn full_width_calls_are_listed() {
        // stat, lstat, mmap, mprotect, munmap, brk, rt_sigreturn, pipe,
        // sched_yield, mremap, mincore, shmdt, pause, nanosleep, getpid,
        // clone, fork, vfork, execve, uname, truncate, getcwd, chdir, rename,
        // rmdir, link, unlink, symlink, gettimeofday, sysinfo, times, ptrace,
        // the get*id calls, getppid, getpgrp, setsid, getresuid, getresgid,
        // capget, capset, rt_sigpending, rt_sigtimedwait, rt_sigsuspend,
        // sigaltstack, utime, uselib, statfs, mlock, munlock, munlockall,
        // vhangup, pivot_root, _sysctl, adjtimex, chroot, sync, acct,
        // settimeofday, mount, swapoff, init_module, gettid, the xattr calls
        // by path, time, set_thread_area, io_destroy..io_cancel,
        // get_thread_area, remap_file_pages, set_tid_address,
        // restart_syscall, utimes, get_mempolicy, mq_unlink, kexec_load,
        // inotify_init, unshare, set_robust_list, getcpu, pkey_alloc,
        // io_pgetevents, clone3, set_mempolicy_home_node, mseal
        let full = [
            4, 6, 9, 10, 11, 12, 15, 22, 24, 25, 27, 67, 34, 35, 39, 56, 57, 58, 59, 63, 76, 79,
            80, 82, 84, 86, 87, 88, 96, 99, 100, 101, 102, 104, 107, 108, 110, 111, 112, 118, 120,
            125, 126, 127, 128, 130, 131, 132, 134, 137, 149, 150, 152, 153, 155, 156, 159, 161,
            162, 163, 164, 165, 168, 175, 186, 191, 192, 194, 195, 197, 198, 201, 205, 207, 208,
            209, 210, 211, 216, 218, 219, 235, 239, 241, 246, 253, 272, 273, 309, 330, 333, 435,
            450, 462,
        ];
        for number in full {
            assert!(widths(number).is_empty(), "{number}");
        }
    }

    #[test]
    fn every_letter_is_known() {
        for number in 0..1024 {
            let spec = widths(number);
            assert!(spec.len() <= 6, "{number}");
            assert!(spec.iter().all(|c| b"iulh".contains(c)), "{number}");
        }
    }
}
