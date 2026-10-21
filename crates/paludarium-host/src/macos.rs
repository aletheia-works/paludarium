//! Darwin terminal observations translated into the Linux guest ABI.
use crate::{TerminalAttributes, TerminalInfo};
use paludarium_types::Errno;

fn flags(value: libc::tcflag_t, mapping: &[(u64, u32)]) -> Result<u32, Errno> {
    let mut known = 0;
    let mut output = 0;
    for &(host, guest) in mapping {
        known |= host;
        if value & host != 0 {
            output |= guest;
        }
    }
    if value & !known != 0 {
        return Err(Errno::EINVAL);
    }
    Ok(output)
}

fn speed(value: libc::speed_t) -> Result<u32, Errno> {
    const RATES: &[u64] = &[
        0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 38400,
    ];
    if let Some(index) = RATES.iter().position(|&rate| rate == value) {
        return Ok(index as u32);
    }
    match value {
        57600 => Ok(0x1001),
        115200 => Ok(0x1002),
        230400 => Ok(0x1003),
        _ => Err(Errno::EINVAL),
    }
}

fn attributes(value: &libc::termios) -> Result<TerminalAttributes, Errno> {
    let input = flags(
        value.c_iflag,
        &[
            (1, 1),
            (2, 2),
            (4, 4),
            (8, 8),
            (16, 16),
            (32, 32),
            (64, 64),
            (128, 128),
            (256, 256),
            (512, 1024),
            (1024, 4096),
            (2048, 2048),
            (8192, 8192),
            (16384, 16384),
        ],
    )?;
    let output = flags(
        value.c_oflag,
        &[
            (1, 1),
            (2, 4),
            (16, 8),
            (32, 16),
            (64, 32),
            (128, 64),
            (131072, 128),
        ],
    )?;
    let mut control = flags(
        value.c_cflag & !0x30300,
        &[
            (0x400, 0x40),
            (0x800, 0x80),
            (0x1000, 0x100),
            (0x2000, 0x200),
            (0x4000, 0x400),
            (0x8000, 0x800),
        ],
    )?;
    control |= ((value.c_cflag & 0x300) >> 4) as u32;
    match value.c_cflag & 0x30000 {
        0 => (),
        0x30000 => control |= 0x80000000,
        _ => return Err(Errno::EINVAL),
    }
    control |= speed(value.c_ospeed)?;
    // Linux represents a differing input baud rate in CIBAUD.
    if value.c_ispeed != value.c_ospeed {
        control |= speed(value.c_ispeed)? << 16;
    }
    let local = flags(
        value.c_lflag,
        &[
            (1, 0x800),
            (2, 0x10),
            (4, 0x20),
            (8, 8),
            (16, 0x40),
            (32, 0x400),
            (64, 0x200),
            (128, 1),
            (256, 2),
            (1024, 0x8000),
            (0x400000, 0x100),
            (0x800000, 0x1000),
            (0x20000000, 0x4000),
            (0x80000000, 0x80),
        ],
    )?;
    let mut chars = [0; 19];
    for (guest, host) in [
        (0, 8),
        (1, 9),
        (2, 3),
        (3, 5),
        (4, 0),
        (5, 17),
        (6, 16),
        (8, 12),
        (9, 13),
        (10, 10),
        (11, 1),
        (12, 6),
        (13, 15),
        (14, 4),
        (15, 14),
        (16, 2),
    ] {
        // VMIN and VTIME are byte-valued counts, not disable-able controls.
        chars[guest] = if value.c_cc[host] == 255 && guest != 5 && guest != 6 {
            0
        } else {
            value.c_cc[host]
        };
    }
    Ok(TerminalAttributes::new(
        input, output, control, local, 0, chars,
    ))
}

fn error() -> Errno {
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EBADF) => Errno::EBADF,
        Some(libc::EINVAL) => Errno::EINVAL,
        Some(libc::ENOTTY) => Errno::ENOTTY,
        _ => Errno::EIO,
    }
}

pub(super) fn terminal_info(fd: i32) -> Result<Option<TerminalInfo>, Errno> {
    let mut terminal = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: libc writes its own Darwin layout into a host-owned buffer;
    // no guest pointer or ioctl request is forwarded.
    if unsafe { libc::tcgetattr(fd, terminal.as_mut_ptr()) } != 0 {
        // Darwin /dev/null reports ENODEV (observed on macOS 27), while
        // other non-terminals report ENOTTY. Both mean no terminal data.
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODEV) {
            return Ok(None);
        }
        let errno = error();
        return if errno == Errno::ENOTTY {
            Ok(None)
        } else {
            Err(errno)
        };
    }
    // SAFETY: successful tcgetattr initialized the complete structure.
    let terminal = unsafe { terminal.assume_init() };
    let mut size = std::mem::MaybeUninit::<libc::winsize>::uninit();
    // SAFETY: Darwin TIOCGWINSZ writes libc::winsize into this live buffer.
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, size.as_mut_ptr()) } != 0 {
        return Err(error());
    }
    // SAFETY: successful ioctl initialized the complete structure.
    let size = unsafe { size.assume_init() };
    Ok(Some(TerminalInfo::new(
        attributes(&terminal)?,
        size.ws_col,
        size.ws_row,
        size.ws_xpixel,
        size.ws_ypixel,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    fn blank() -> libc::termios {
        // SAFETY: termios contains only integer fields and an integer array.
        unsafe { std::mem::zeroed() }
    }

    fn pty() -> (OwnedFd, OwnedFd) {
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: writable descriptor outputs are host-owned; optional name,
        // attributes and dimensions are null to request the Darwin defaults.
        assert_eq!(
            // SAFETY: openpty writes only the two host-owned descriptor outputs.
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        // SAFETY: successful openpty returned two fresh owned descriptors.
        unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) }
    }

    #[test]
    fn input_flag_translation() {
        let mut value = blank();
        value.c_iflag = libc::IXON | libc::IXOFF | libc::ICRNL;
        assert_eq!(attributes(&value).unwrap().input_flags, 0x1500);
    }
    #[test]
    fn output_flag_translation() {
        let mut value = blank();
        value.c_oflag = libc::OPOST | libc::ONLCR;
        assert_eq!(attributes(&value).unwrap().output_flags, 5);
    }
    #[test]
    fn control_width_baud_translation() {
        let mut value = blank();
        value.c_cflag = libc::CS8 | libc::CREAD | libc::HUPCL;
        value.c_ospeed = libc::B9600;
        value.c_ispeed = libc::B9600;
        assert_eq!(attributes(&value).unwrap().control_flags, 0x4bd);
        for (host, guest) in [
            (libc::CS5, 0),
            (libc::CS6, 0x10),
            (libc::CS7, 0x20),
            (libc::CS8, 0x30),
        ] {
            value.c_cflag = host | libc::CRTSCTS;
            assert_eq!(
                attributes(&value).unwrap().control_flags,
                0x8000000d | guest
            );
        }
    }
    #[test]
    fn local_flag_translation() {
        let mut value = blank();
        value.c_lflag = libc::ISIG | libc::ICANON | libc::ECHO | libc::IEXTEN;
        assert_eq!(attributes(&value).unwrap().local_flags, 0x800b);
    }
    #[test]
    fn control_character_order_and_disabled() {
        let mut value = blank();
        value.c_cc.fill(255);
        value.c_cc[libc::VINTR] = 3;
        value.c_cc[libc::VEOF] = 4;
        value.c_cc[libc::VMIN] = 1;
        let chars = attributes(&value).unwrap().control_chars;
        assert_eq!(
            (chars[0], chars[4], chars[6], chars[7], chars[18]),
            (3, 4, 1, 0, 0)
        );
        value.c_cc[libc::VMIN] = 255;
        value.c_cc[libc::VTIME] = 255;
        let chars = attributes(&value).unwrap().control_chars;
        assert_eq!((chars[5], chars[6]), (255, 255));
    }
    #[test]
    fn input_speed_and_extended_baud() {
        let mut value = blank();
        value.c_ospeed = libc::B115200;
        value.c_ispeed = libc::B9600;
        assert_eq!(attributes(&value).unwrap().control_flags, 0xd1002);
    }
    #[test]
    fn unrepresentable_attributes_rejected() {
        let mut value = blank();
        value.c_ospeed = libc::B7200;
        assert_eq!(attributes(&value), Err(Errno::EINVAL));
        value.c_ospeed = 0;
        value.c_lflag = 0x200;
        assert_eq!(attributes(&value), Err(Errno::EINVAL));
        value.c_lflag = 0;
        value.c_cflag = 0x10000;
        assert_eq!(attributes(&value), Err(Errno::EINVAL));
    }

    #[test]
    fn real_pty_attributes() {
        let (_master, slave) = pty();
        let terminal = terminal_info(slave.as_raw_fd()).unwrap().unwrap();
        assert_ne!(terminal.attributes.local_flags & 2, 0);
        assert_eq!(terminal.attributes.control_chars[0], 3);
    }
    #[test]
    fn real_pty_positive_dimensions() {
        let (_master, slave) = pty();
        let size = libc::winsize {
            ws_row: 37,
            ws_col: 109,
            ws_xpixel: 800,
            ws_ypixel: 600,
        };
        // SAFETY: TIOCSWINSZ reads the host-owned winsize for a live PTY.
        assert_eq!(
            // SAFETY: size is a live host-owned winsize and slave is a live PTY.
            unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSWINSZ, &size) },
            0
        );
        let value = terminal_info(slave.as_raw_fd()).unwrap().unwrap();
        assert_eq!(
            (value.rows, value.columns, value.x_pixels, value.y_pixels),
            (37, 109, 800, 600)
        );
    }
    #[test]
    fn real_pty_zero_dimensions() {
        let (_master, slave) = pty();
        let size = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: the host-owned structure is live for this ioctl call.
        assert_eq!(
            // SAFETY: size is a live host-owned winsize and slave is a live PTY.
            unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSWINSZ, &size) },
            0
        );
        let value = terminal_info(slave.as_raw_fd()).unwrap().unwrap();
        assert_eq!(
            (value.rows, value.columns, value.x_pixels, value.y_pixels),
            (0, 0, 0, 0)
        );
    }
    #[test]
    fn dev_null_is_not_terminal() {
        let file = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(terminal_info(file.as_raw_fd()), Ok(None));
    }
    #[test]
    fn invalid_descriptor_errno_is_linux() {
        assert_eq!(terminal_info(-1), Err(Errno::EBADF));
    }
    #[test]
    fn pty_drop_closes_descriptor() {
        let (_master, slave) = pty();
        let fd = slave.as_raw_fd();
        drop(slave);
        assert_eq!(terminal_info(fd), Err(Errno::EBADF));
    }
    #[test]
    fn stderr_terminal_in_child() {
        const CHILD: &str = "PALUDARIUM_U12_STDERR_PTY";
        if std::env::var_os(CHILD).is_some() {
            use crate::{Host, NativeHost, StreamId};
            assert!(
                NativeHost
                    .terminal_info(StreamId::Stderr)
                    .unwrap()
                    .is_some()
            );
            return;
        }
        let (_master, slave) = pty();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "macos::tests::stderr_terminal_in_child",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .stderr(std::process::Stdio::from(slave))
            .status()
            .unwrap();
        assert!(status.success());
    }
}
