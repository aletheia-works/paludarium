//! The file system types the kernel has, which `sysfs` (Linux's
//! `fs/filesystems.c` with `CONFIG_SYSFS_SYSCALL`) numbers.
use paludarium_types::{Errno, GuestAddr};

use crate::syscalls::{Context, Outcome};

/// The types of the files the emulator gives, as their `statfs` names them:
/// tmpfs, `/proc`, sockets, pipes, pseudo-terminals, POSIX message queues
/// and the host's files (ext4's), in the order Linux registers them (its
/// boot's initcalls). Linux has many more.
pub(crate) const TYPES: [&[u8]; 7] = [
    b"tmpfs", b"proc", b"sockfs", b"pipefs", b"devpts", b"ext4", b"mqueue",
];

/// `PATH_MAX`, the longest name `sysfs` reads, its NUL included.
const PATH_MAX: usize = 4096;

/// `sysfs(option, arg1, arg2)`: 1 gives the index of the type named at
/// `arg1`, 2 copies the name of type `arg1` to `arg2`, and 3 gives how many
/// types there are. An unknown option, name or index is `EINVAL`.
pub(crate) fn sys_sysfs(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    Outcome::Return(sysfs(c, a).unwrap_or_else(Errno::to_syscall_return))
}

fn sysfs(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    match a[0] as i32 {
        1 => {
            // `strndup_user(name, PATH_MAX)`: a name without its NUL in
            // PATH_MAX bytes is EINVAL.
            let mut name = Vec::new();
            loop {
                let mut byte = [0];
                c.mem
                    .read(
                        GuestAddr(a[1].checked_add(name.len() as u64).ok_or(Errno::EFAULT)?),
                        &mut byte,
                    )
                    .map_err(|_| Errno::EFAULT)?;
                if byte[0] == 0 {
                    break;
                }
                name.push(byte[0]);
                if name.len() == PATH_MAX {
                    return Err(Errno::EINVAL);
                }
            }
            TYPES
                .iter()
                .position(|kind| *kind == name.as_slice())
                .map(|index| index as u64)
                .ok_or(Errno::EINVAL)
        }
        2 => {
            let kind = TYPES.get(a[1] as u32 as usize).ok_or(Errno::EINVAL)?;
            let mut name = kind.to_vec();
            name.push(0);
            c.mem
                .write(GuestAddr(a[2]), &name)
                .map_err(|_| Errno::EFAULT)?;
            Ok(0)
        }
        3 => Ok(TYPES.len() as u64),
        _ => Err(Errno::EINVAL),
    }
}
