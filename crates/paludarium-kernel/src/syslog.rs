//! `syslog(type, buf, len)`, as Linux's `do_syslog` (`kernel/printk/printk.c`)
//! on a kernel whose log is empty: nothing in the emulator writes to it.
//!
//! `kernel.dmesg_restrict` is 1, as `CONFIG_SECURITY_DMESG_RESTRICT` sets it on
//! Ubuntu's kernels, so every action needs `CAP_SYSLOG` in the first user
//! namespace (`EPERM`). The log buffer is `CONFIG_LOG_BUF_SHIFT` 18's 256 KiB.
use paludarium_types::Errno;

use crate::syscalls::{Context, Outcome};

/// `CAP_SYSLOG`.
const CAP_SYSLOG: u64 = 1 << 34;
/// `log_buf_len`, which `SYSLOG_ACTION_SIZE_BUFFER` gives.
const LOG_BUF_LEN: u64 = 1 << 18;

const READ: i32 = 2;
const READ_ALL: i32 = 3;
const READ_CLEAR: i32 = 4;
const CONSOLE_LEVEL: i32 = 8;
const SIZE_UNREAD: i32 = 9;
const SIZE_BUFFER: i32 = 10;

/// Whether `syslog` of `type` waits (`SYSLOG_ACTION_READ`), which a signal
/// interrupts with `ERESTARTSYS`.
pub(crate) fn waits(kind: u64) -> bool {
    kind as i32 == READ
}

pub(crate) fn sys_syslog(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    Outcome::Return(syslog(c, a).unwrap_or_else(Errno::to_syscall_return))
}

fn syslog(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let (kind, buf, len) = (a[0] as i32, a[1], a[2] as i32);
    // `check_syslog_permissions`: with dmesg_restrict every action is
    // restricted, the reads and the buffer size too.
    if !c.process.credentials.capable(CAP_SYSLOG) {
        return Err(Errno::EPERM);
    }
    match kind {
        // CLOSE, OPEN, CLEAR, CONSOLE_OFF and CONSOLE_ON change nothing a
        // program can read back here.
        0 | 1 | 5 | 6 | 7 => Ok(0),
        READ | READ_ALL | READ_CLEAR => {
            if buf == 0 || len < 0 {
                return Err(Errno::EINVAL);
            }
            if len == 0 {
                return Ok(0);
            }
            crate::sockets::access_ok(buf, len as usize)?;
            if kind == READ {
                // `syslog_print` waits for a record, which never comes.
                return crate::syscalls::wait_for_signal(c);
            }
            // `syslog_print_all` of an empty log copies nothing.
            Ok(0)
        }
        CONSOLE_LEVEL if !(1..=8).contains(&len) => Err(Errno::EINVAL),
        CONSOLE_LEVEL => Ok(0),
        // No record is unread.
        SIZE_UNREAD => Ok(0),
        SIZE_BUFFER => Ok(LOG_BUF_LEN),
        _ => Err(Errno::EINVAL),
    }
}
