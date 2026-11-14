//! The Linux Security Module system calls (`security/lsm_syscalls.c` and
//! `security_getselfattr`/`security_setselfattr` in `security/security.c`).
//!
//! The modules here are the ones the emulator has: Lockdown (whose port
//! access it refuses, see `iopl`), the capability module, Landlock and Yama,
//! in the order Linux starts them with Ubuntu's configuration: Lockdown is an
//! early module there (`CONFIG_SECURITY_LOCKDOWN_LSM_EARLY`), the capability
//! module comes first of the rest, and then `CONFIG_LSM`'s order. None of them keeps
//! attributes of its own for a task, so `lsm_get_self_attr` and
//! `lsm_set_self_attr` find no module to ask and give `EOPNOTSUPP` once
//! their arguments pass Linux's checks.
use paludarium_types::{Errno, GuestAddr};

use crate::syscalls::{Context, Outcome};

/// `LSM_ID_LOCKDOWN`, `LSM_ID_CAPABILITY`, `LSM_ID_LANDLOCK` and
/// `LSM_ID_YAMA`.
const MODULES: [u64; 4] = [108, 100, 110, 105];
/// `LSM_ATTR_UNDEF`.
const ATTR_UNDEF: u32 = 0;
/// `LSM_ID_UNDEF`.
const ID_UNDEF: u64 = 0;
/// `LSM_FLAG_SINGLE`.
const FLAG_SINGLE: u32 = 1;
/// `struct lsm_ctx` without its context: `id`, `flags`, `len`, `ctx_len`.
const CTX_HEADER: u64 = 32;
const E2BIG: Errno = Errno(7);

fn outcome(result: Result<u64, Errno>) -> Outcome {
    Outcome::Return(result.unwrap_or_else(Errno::to_syscall_return))
}

fn read_u32(c: &Context<'_>, at: u64) -> Result<u32, Errno> {
    let mut bytes = [0; 4];
    c.mem
        .read(GuestAddr(at), &mut bytes)
        .map_err(|_| Errno::EFAULT)?;
    Ok(u32::from_le_bytes(bytes))
}

fn write_u32(c: &Context<'_>, at: u64, value: u32) -> Result<(), Errno> {
    c.mem
        .write(GuestAddr(at), &value.to_le_bytes())
        .map_err(|_| Errno::EFAULT)
}

/// `lsm_list_modules(ids, size, flags)`: the modules' IDs, and in `size`
/// the bytes they take, which a smaller `size` gives with `E2BIG`.
pub(crate) fn sys_lsm_list_modules(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        if a[2] as u32 != 0 {
            return Err(Errno::EINVAL);
        }
        let total = (MODULES.len() * 8) as u32;
        let room = read_u32(c, a[1])?;
        write_u32(c, a[1], total)?;
        if room < total {
            return Err(E2BIG);
        }
        for (index, id) in MODULES.iter().enumerate() {
            c.mem
                .write_u64(GuestAddr(a[0].wrapping_add(index as u64 * 8)), *id)
                .map_err(|_| Errno::EFAULT)?;
        }
        Ok(MODULES.len() as u64)
    })())
}

/// `lsm_get_self_attr(attr, ctx, size, flags)`, as `security_getselfattr`
/// with no module that has the hook: after its checks the size is 0 and the
/// call `EOPNOTSUPP`.
pub(crate) fn sys_lsm_get_self_attr(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        let (attr, ctx, size, flags) = (a[0] as u32, a[1], a[2], a[3] as u32);
        if attr == ATTR_UNDEF || size == 0 {
            return Err(Errno::EINVAL);
        }
        read_u32(c, size)?;
        if flags != 0 {
            if flags != FLAG_SINGLE || ctx == 0 {
                return Err(Errno::EINVAL);
            }
            let mut header = [0; CTX_HEADER as usize];
            c.mem
                .read(GuestAddr(ctx), &mut header)
                .map_err(|_| Errno::EFAULT)?;
            if u64::from_le_bytes(header[..8].try_into().unwrap_or_default()) == ID_UNDEF {
                return Err(Errno::EINVAL);
            }
        }
        write_u32(c, size, 0)?;
        Err(Errno::EOPNOTSUPP)
    })())
}

/// `lsm_set_self_attr(attr, ctx, size, flags)`, as `security_setselfattr`:
/// a context that passes its checks names no module with the hook
/// (`EOPNOTSUPP`).
pub(crate) fn sys_lsm_set_self_attr(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        let (ctx, size, flags) = (a[1], u64::from(a[2] as u32), a[3] as u32);
        if flags != 0 || size < CTX_HEADER {
            return Err(Errno::EINVAL);
        }
        if size > 4096 {
            return Err(E2BIG);
        }
        // `memdup_user` copies all of it.
        let mut copy = vec![0; size as usize];
        c.mem
            .read(GuestAddr(ctx), &mut copy)
            .map_err(|_| Errno::EFAULT)?;
        let word = |at: usize| u64::from_le_bytes(copy[at..at + 8].try_into().unwrap_or_default());
        let (len, ctx_len) = (word(16), word(24));
        match CTX_HEADER.checked_add(ctx_len) {
            Some(required) if size >= len && len >= required => Err(Errno::EOPNOTSUPP),
            _ => Err(Errno::EINVAL),
        }
    })())
}
