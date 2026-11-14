//! The system calls that administer the machine: `reboot`, `swapon` and
//! `swapoff`, the module calls, the kexec calls and the quota calls, each in
//! Linux master's order of checks.
//!
//! The kernel here is locked down for integrity, as Ubuntu's is under Secure
//! Boot (and as `iopl` and `ioperm` already refuse port access): nothing can
//! load code into it. A module without a valid signature and a kexec image are
//! refused (`EPERM`), and there is no key a signature could be checked
//! against. No file system has swap or quotas, as tmpfs has neither.
use std::sync::Arc;

use paludarium_host::FileHandle;
use paludarium_mmu::AddressSpace;
use paludarium_types::{Errno, GuestAddr};

use crate::credentials::Credentials;
use crate::namespaces::Namespace;
use crate::syscalls::{Context, Outcome};

const CAP_SYS_MODULE: u64 = 1 << 16;
const CAP_SYS_ADMIN: u64 = 1 << 21;
const CAP_SYS_BOOT: u64 = 1 << 22;
const ENOEXEC: Errno = Errno(8);
const ENOTBLK: Errno = Errno(15);
const EFBIG: Errno = Errno(27);
const EBADMSG: Errno = Errno(74);
const ENOPKG: Errno = Errno(65);

fn outcome(result: Result<u64, Errno>) -> Outcome {
    Outcome::Return(result.unwrap_or_else(Errno::to_syscall_return))
}

/// What `reboot` asks of the caller's PID namespace once it passes its
/// checks: to go on (`false`), or that the calling thread ends now with
/// status 0 (Linux's `do_exit(0)`), its namespace's init killed.
///
/// As Linux's `sys_reboot`: `CAP_SYS_BOOT` in the user namespace that owns
/// the PID namespace (`EPERM`), the magic numbers (`EINVAL`), and then, in
/// a nested PID namespace, `reboot_pid_ns`: a restart ends its init with
/// `SIGHUP` and a halt or power-off with `SIGINT`; any other command is
/// `EINVAL`. In the first namespace the same commands end the machine the
/// same way, its first process being the init, after a restart command's
/// string is read (`EFAULT`). `LINUX_REBOOT_CMD_CAD_ON` and `CAD_OFF`
/// succeed; `KEXEC` finds no kernel loaded (`EINVAL`), and `SW_SUSPEND`
/// cannot hibernate a locked-down kernel (`EPERM`).
pub(crate) fn reboot(
    processes: &crate::processes::Processes,
    space: &Arc<Namespace>,
    credentials: &Credentials,
    mem: &AddressSpace,
    a: [u64; 6],
) -> Result<bool, Errno> {
    const RESTART: u32 = 0x0123_4567;
    const HALT: u32 = 0xCDEF_0123;
    const CAD_ON: u32 = 0x89AB_CDEF;
    const CAD_OFF: u32 = 0;
    const POWER_OFF: u32 = 0x4321_FEDC;
    const RESTART2: u32 = 0xA1B2_C3D4;
    const SW_SUSPEND: u32 = 0xD000_FCE2;
    const KEXEC: u32 = 0x4558_4543;
    if !credentials.capable_in(CAP_SYS_BOOT, space.owner()) {
        return Err(Errno::EPERM);
    }
    let (magic1, magic2, cmd) = (a[0] as u32, a[1] as u32, a[2] as u32);
    if magic1 != 0xfee1_dead
        || !matches!(magic2, 672_274_793 | 85_072_278 | 369_367_448 | 537_993_216)
    {
        return Err(Errno::EINVAL);
    }
    let signal = match cmd {
        RESTART | RESTART2 => 1, // SIGHUP
        HALT | POWER_OFF => 2,   // SIGINT
        _ if !space.is_first() => return Err(Errno::EINVAL),
        CAD_ON | CAD_OFF => return Ok(false),
        KEXEC => return Err(Errno::EINVAL),
        SW_SUSPEND => return Err(Errno::EPERM),
        _ => return Err(Errno::EINVAL),
    };
    if space.is_first() && cmd == RESTART2 {
        // `strncpy_from_user` of at most 255 bytes, which stops at a NUL.
        for offset in 0..255 {
            let mut byte = [0];
            mem.read(GuestAddr(a[3].wrapping_add(offset)), &mut byte)
                .map_err(|_| Errno::EFAULT)?;
            if byte[0] == 0 {
                break;
            }
        }
    }
    processes.reboot(space, signal);
    Ok(true)
}

/// What the module and kexec checks read of an image: its length, its
/// first bytes (a bzImage's header) and its last (a module's signature),
/// which are all they look at; the rest is not copied.
struct Image {
    len: u64,
    head: Vec<u8>,
    tail: Vec<u8>,
}
/// The bytes of [`Image::head`] and [`Image::tail`].
const HEAD: u64 = 0x238;
const TAIL: u64 = 40;
impl Image {
    /// The ends of an image of `total` bytes, which `read(at, buf)` fills
    /// from byte `at`.
    fn read(
        total: u64,
        mut read: impl FnMut(u64, &mut [u8]) -> Result<(), Errno>,
    ) -> Result<Self, Errno> {
        let mut head = vec![0; total.min(HEAD) as usize];
        read(0, &mut head)?;
        let tail_len = total.min(TAIL);
        let mut tail = vec![0; tail_len as usize];
        read(total - tail_len, &mut tail)?;
        Ok(Self {
            len: total,
            head,
            tail,
        })
    }
}

/// The regular file a descriptor `fd` holds open for reading, as
/// `kernel_read_file_from_fd` reads it, up to `limit` bytes: a descriptor not
/// open for reading is `EBADF`, a file that is not regular or is empty
/// `EINVAL`, and one past `limit` `EFBIG`.
fn read_file(c: &Context<'_>, fd: u64, limit: u64) -> Result<Image, Errno> {
    const O_PATH: u32 = 0o10_000_000;
    let descriptor = c.files.descriptor(u64::from(fd as u32))?;
    let file: Arc<dyn FileHandle> = descriptor.file;
    if file.flags() & O_PATH != 0 || file.flags() & 3 == 1 {
        return Err(Errno::EBADF);
    }
    let stat = file.stat()?;
    if stat.mode & 0o170_000 != 0o100_000 || stat.size == 0 {
        return Err(Errno::EINVAL);
    }
    if stat.size > limit {
        return Err(EFBIG);
    }
    Image::read(stat.size, |at, buf| {
        let mut done = 0;
        while done < buf.len() {
            match file.read_at(at + done as u64, &mut buf[done..])? {
                0 => break,
                n => done += n,
            }
        }
        Ok(())
    })
}

/// `module_sig_check` of a module's bytes on a kernel locked down for
/// integrity, where no key is trusted: a module that ends in a signature
/// whose `struct module_signature` Linux's `mod_check_sig` refuses gives
/// that error, and any other module, signed or not, `EPERM`, as a signature
/// no key verifies leaves it unsigned (`-ENOKEY`) and lockdown refuses that.
/// `mangled`, a module whose version information is to be ignored, is taken
/// as unsigned.
fn check_signature(module: &Image, mangled: bool) -> Errno {
    const MARKER: &[u8] = b"~Module signature appended~\n";
    const SIGNATURE: usize = 12;
    let len = module.len as usize;
    if mangled || len <= MARKER.len() || !module.tail.ends_with(MARKER) {
        return Errno::EPERM;
    }
    let signed = len - MARKER.len();
    if signed <= SIGNATURE {
        return EBADMSG;
    }
    let end = module.tail.len() - MARKER.len();
    let info = &module.tail[end - SIGNATURE..end];
    let length = u32::from_be_bytes([info[8], info[9], info[10], info[11]]) as usize;
    if length >= signed - SIGNATURE {
        return EBADMSG;
    }
    if info[2] != 2 {
        return ENOPKG;
    }
    if info[..2] != [0, 0] || info[3..8] != [0; 5] {
        return EBADMSG;
    }
    Errno::EPERM
}

/// `init_module(image, len, params)`: `CAP_SYS_MODULE` (`EPERM`), an image
/// shorter than an ELF header (`ENOEXEC`), the image copied in (`EFAULT`),
/// and then its signature ([`check_signature`]).
pub(crate) fn sys_init_module(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        if !c.process.credentials.capable(CAP_SYS_MODULE) {
            return Err(Errno::EPERM);
        }
        if a[1] < 64 {
            return Err(ENOEXEC);
        }
        // More than the machine's memory cannot be allocated (`vmalloc`).
        if a[1] > 1 << 32 {
            return Err(Errno::ENOMEM);
        }
        // All of it must be readable (`EFAULT`), though only its ends are
        // looked at.
        let len = usize::try_from(a[1]).map_err(|_| Errno::ENOMEM)?;
        c.mem
            .check_read(GuestAddr(a[0]), len)
            .map_err(|_| Errno::EFAULT)?;
        let module = Image::read(a[1], |at, buf| {
            c.mem
                .read(GuestAddr(a[0].wrapping_add(at)), buf)
                .map_err(|_| Errno::EFAULT)
        })?;
        Err(check_signature(&module, false))
    })())
}

/// `finit_module(fd, params, flags)`: `CAP_SYS_MODULE` (`EPERM`), flags
/// beyond `MODULE_INIT_IGNORE_MODVERSIONS`, `MODULE_INIT_IGNORE_VERMAGIC`
/// and `MODULE_INIT_COMPRESSED_FILE` (`EINVAL`), the file ([`read_file`]),
/// and then its signature ([`check_signature`]). A compressed file is not
/// decompressed: one that does not start as zstd's frames do is `EINVAL`,
/// as Linux's decompressor finds, and any other is taken as unsigned.
pub(crate) fn sys_finit_module(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        if !c.process.credentials.capable(CAP_SYS_MODULE) {
            return Err(Errno::EPERM);
        }
        let flags = a[2] as u32;
        if flags & !7 != 0 {
            return Err(Errno::EINVAL);
        }
        let module = read_file(c, a[0], i32::MAX as u64)?;
        if flags & 4 != 0 {
            if !module.head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
                return Err(Errno::EINVAL);
            }
            return Err(Errno::EPERM);
        }
        Err(check_signature(&module, flags & 3 != 0))
    })())
}

/// `delete_module(name, flags)`: `CAP_SYS_MODULE` (`EPERM`), the name read
/// (`EFAULT`; an empty one, or one of 56 bytes or more, `ENOENT`), and then
/// no module has it, as none is loaded (`ENOENT`).
pub(crate) fn sys_delete_module(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    const MODULE_NAME_LEN: u64 = 56;
    outcome((|| {
        if !c.process.credentials.capable(CAP_SYS_MODULE) {
            return Err(Errno::EPERM);
        }
        for offset in 0..MODULE_NAME_LEN {
            let mut byte = [0];
            c.mem
                .read(GuestAddr(a[0].wrapping_add(offset)), &mut byte)
                .map_err(|_| Errno::EFAULT)?;
            if byte[0] == 0 {
                break;
            }
        }
        Err(Errno::ENOENT)
    })())
}

/// `kexec_load(entry, nr_segments, segments, flags)`: `CAP_SYS_BOOT`
/// (`EPERM`), and then lockdown refuses it (`LOCKDOWN_KEXEC`, `EPERM`)
/// before any other check.
pub(crate) fn sys_kexec_load(_: &mut Context<'_>, _: [u64; 6]) -> Outcome {
    Outcome::Return(Errno::EPERM.to_syscall_return())
}

/// `kexec_file_load(kernel_fd, initrd_fd, cmdline_len, cmdline, flags)`:
/// `CAP_SYS_BOOT` (`EPERM`), unknown flags (`EINVAL`), and with
/// `KEXEC_FILE_UNLOAD` success, as no kernel is loaded. Otherwise the
/// kernel's file ([`read_file`]) must be a 64-bit bzImage that can load
/// above 4 GiB (`ENOEXEC`, as Linux's `bzImage64_probe`), whose signature no
/// key verifies, so lockdown refuses it (`EPERM`).
pub(crate) fn sys_kexec_file_load(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    const FLAGS: u64 = 0x3f;
    outcome((|| {
        if !c.process.credentials.capable(CAP_SYS_BOOT) {
            return Err(Errno::EPERM);
        }
        let flags = a[4];
        if flags & !FLAGS != 0 {
            return Err(Errno::EINVAL);
        }
        if flags & 1 != 0 {
            return Ok(0);
        }
        // Linux's `KEXEC_FILE_SIZE_MAX`, `min(4 GiB, SSIZE_MAX)`: not
        // `finit_module`'s `INT_MAX`.
        let kernel = read_file(c, a[0], 4 << 30)?;
        let head = &kernel.head;
        let u16_at = |at: usize| u16::from_le_bytes([head[at], head[at + 1]]);
        let bzimage = kernel.len >= 1024
            && &head[0x202..0x206] == b"HdrS"
            && u16_at(0x1fe) == 0xAA55
            && u16_at(0x206) >= 0x020C
            && head[0x211] & 1 != 0
            && u16_at(0x236) & 3 == 3;
        if !bzimage {
            return Err(ENOEXEC);
        }
        Err(Errno::EPERM)
    })())
}

/// `swapon(path, flags)`: unknown flags (`EINVAL`), `CAP_SYS_ADMIN`
/// (`EPERM`), the open of the path for reading and writing, and then, as no
/// file here has the page reads swap needs (tmpfs's `read_folio`), `EINVAL`.
pub(crate) fn sys_swapon(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    const SWAP_FLAGS_VALID: u32 = 0x7_ffff;
    outcome((|| {
        if a[1] as u32 & !SWAP_FLAGS_VALID != 0 {
            return Err(Errno::EINVAL);
        }
        if !c.process.credentials.capable(CAP_SYS_ADMIN) {
            return Err(Errno::EPERM);
        }
        crate::files::open_name(c, a[0], 0o100_000 | 0o200 | 2)?;
        Err(Errno::EINVAL)
    })())
}

/// `swapoff(path)`: `CAP_SYS_ADMIN` (`EPERM`), the open of the path for
/// reading and writing, and then no swap is on, so none is that file
/// (`EINVAL`).
pub(crate) fn sys_swapoff(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        if !c.process.credentials.capable(CAP_SYS_ADMIN) {
            return Err(Errno::EPERM);
        }
        crate::files::open_name(c, a[0], 0o100_000 | 2)?;
        Err(Errno::EINVAL)
    })())
}

const Q_SYNC: u32 = 0x80_0001;
/// `MAXQUOTAS`: user, group and project quotas.
const MAXQUOTAS: u32 = 3;

/// `quotactl(cmd, special, id, addr)`: a quota type past the project's
/// (`EINVAL`); with no device `Q_SYNC` syncs nothing and succeeds and the
/// rest are `ENODEV`; and then the device is looked up as `lookup_bdev`
/// does, and as nothing here is a block device, a path that names a file
/// is `ENOTBLK`.
pub(crate) fn sys_quotactl(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        let cmd = a[0] as u32;
        if cmd & 0xff >= MAXQUOTAS {
            return Err(Errno::EINVAL);
        }
        if a[1] == 0 {
            return if cmd >> 8 == Q_SYNC {
                Ok(0)
            } else {
                Err(Errno::ENODEV)
            };
        }
        crate::files::named_at(c, a[1])?;
        Err(ENOTBLK)
    })())
}

/// `quotactl_fd(fd, cmd, id, addr)`: a descriptor, `O_PATH` ones too
/// (`EBADF`), a quota type past the project's (`EINVAL`), and then, as no
/// file system here supports quotas (tmpfs mounted without them), `ENOSYS`
/// from Linux's `do_quotactl`.
pub(crate) fn sys_quotactl_fd(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        c.files.descriptor(u64::from(a[0] as u32))?;
        if a[1] as u32 & 0xff >= MAXQUOTAS {
            return Err(Errno::EINVAL);
        }
        Err(Errno::ENOSYS)
    })())
}
