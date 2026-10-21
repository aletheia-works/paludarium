//! Read-only observations of Windows console handles in the Linux guest ABI.
use crate::{StreamId, TerminalAttributes, TerminalInfo};
use paludarium_types::Errno;
use std::ffi::c_void;

type Handle = *mut c_void;
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Coord {
    x: i16,
    y: i16,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Rect {
    left: i16,
    top: i16,
    right: i16,
    bottom: i16,
}
#[repr(C)]
#[derive(Default)]
struct Screen {
    size: Coord,
    cursor: Coord,
    attributes: u16,
    window: Rect,
    maximum: Coord,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetStdHandle(kind: u32) -> Handle;
    fn GetFileType(handle: Handle) -> u32;
    fn GetConsoleMode(handle: Handle, mode: *mut u32) -> i32;
    fn GetConsoleScreenBufferInfo(handle: Handle, screen: *mut Screen) -> i32;
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: Handle,
        creation: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
}
fn invalid(handle: Handle) -> bool {
    handle.is_null() || handle as isize == -1
}
fn error() -> Errno {
    match std::io::Error::last_os_error().raw_os_error() {
        Some(6) => Errno::EBADF,
        Some(87) => Errno::EINVAL,
        _ => Errno::EIO,
    }
}
struct Owned(Handle);
impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: this handle was acquired by CreateFileW and is owned once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}
fn console(name: &str) -> Result<Owned, Errno> {
    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    // SAFETY: the terminated UTF-16 buffer lives through the call; no guest data.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            0x8000_0000,
            3,
            std::ptr::null_mut(),
            3,
            0,
            std::ptr::null_mut(),
        )
    };
    if invalid(handle) {
        Err(error())
    } else {
        Ok(Owned(handle))
    }
}
fn mode(handle: Handle) -> Result<u32, Errno> {
    let mut result = 0;
    // SAFETY: writes one DWORD into a live host-owned buffer.
    if unsafe { GetConsoleMode(handle, &mut result) } == 0 {
        Err(error())
    } else {
        Ok(result)
    }
}
fn convert(input: u32, output: u32, window: Rect) -> Result<TerminalInfo, Errno> {
    // Console input/output flags have no baud rate, parity or flow-control ABI.
    // Only observable line, signal, echo and processed-output behavior is mapped.
    if input & !0x3ff != 0 || output & !0x1f != 0 || (input & 4 != 0 && input & 2 == 0) {
        return Err(Errno::EINVAL);
    }
    let columns = i32::from(window.right) - i32::from(window.left) + 1;
    let rows = i32::from(window.bottom) - i32::from(window.top) + 1;
    if window.left < 0 || window.top < 0 || columns <= 0 || rows <= 0 {
        return Err(Errno::EINVAL);
    }
    let mut local = 0;
    if input & 1 != 0 {
        local |= 1;
    }
    if input & 2 != 0 {
        local |= 2;
    }
    if input & 4 != 0 {
        local |= 8;
    }
    let mut chars = [0; 19];
    if input & 1 != 0 {
        chars[0] = 3;
    }
    chars[6] = 1;
    Ok(TerminalInfo::new(
        TerminalAttributes::new(0, if output & 1 != 0 { 1 } else { 0 }, 0, local, 0, chars),
        u16::try_from(columns).map_err(|_| Errno::EINVAL)?,
        u16::try_from(rows).map_err(|_| Errno::EINVAL)?,
        0,
        0,
    ))
}
pub(super) fn terminal_info(stream: StreamId) -> Result<Option<TerminalInfo>, Errno> {
    // SAFETY: fixed Windows standard-handle identifiers; handle is borrowed.
    let handle = unsafe {
        GetStdHandle([(-10_i32) as u32, (-11_i32) as u32, (-12_i32) as u32][stream.index()])
    };
    if invalid(handle) {
        return Err(Errno::EBADF);
    }
    // SAFETY: GetFileType inspects a borrowed host handle without modifying it.
    match unsafe { GetFileType(handle) } {
        1 | 3 => return Ok(None),
        2 => (),
        0 => return Err(error()),
        _ => return Err(Errno::EINVAL),
    }
    // Character devices such as NUL are valid streams but not console handles.
    match mode(handle) {
        Err(Errno::EBADF) => return Ok(None),
        Err(errno) => return Err(errno),
        Ok(_) => (),
    }
    let input = console("CONIN$")?;
    let output = console("CONOUT$")?;
    let screen_handle = if stream == StreamId::Stdin {
        output.0
    } else {
        handle
    };
    let mut screen = Screen::default();
    // SAFETY: Windows writes its own fixed ABI layout into this live buffer.
    if unsafe { GetConsoleScreenBufferInfo(screen_handle, &mut screen) } == 0 {
        return Err(error());
    }
    Ok(Some(convert(
        mode(input.0)?,
        mode(screen_handle)?,
        screen.window,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn viewport() -> Rect {
        Rect {
            left: 2,
            top: 3,
            right: 81,
            bottom: 26,
        }
    }
    #[test]
    fn console_processed_flags() {
        let info = convert(7, 1, viewport()).unwrap();
        assert_eq!(info.attributes.local_flags, 11);
        assert_eq!(info.attributes.output_flags, 1);
        assert_eq!(info.attributes.control_chars[0], 3);
    }
    #[test]
    fn console_raw_flags() {
        let info = convert(0, 0, viewport()).unwrap();
        assert_eq!(info.attributes.local_flags, 0);
        assert_eq!(info.attributes.output_flags, 0);
        assert_eq!(info.attributes.control_flags, 0);
    }
    #[test]
    fn console_viewport_not_buffer() {
        let info = convert(3, 3, viewport()).unwrap();
        assert_eq!(
            (info.columns, info.rows, info.x_pixels, info.y_pixels),
            (80, 24, 0, 0)
        );
    }
    #[test]
    fn console_unknown_input_rejected() {
        assert_eq!(convert(0x400, 0, viewport()), Err(Errno::EINVAL));
    }
    #[test]
    fn console_unknown_output_rejected() {
        assert_eq!(convert(0, 0x20, viewport()), Err(Errno::EINVAL));
    }
    #[test]
    fn console_echo_without_line_rejected() {
        assert_eq!(convert(4, 0, viewport()), Err(Errno::EINVAL));
    }
    #[test]
    fn console_inverted_rectangle_rejected() {
        assert_eq!(
            convert(
                0,
                0,
                Rect {
                    left: 2,
                    right: 1,
                    ..viewport()
                }
            ),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            convert(
                0,
                0,
                Rect {
                    top: 4,
                    bottom: 3,
                    ..viewport()
                }
            ),
            Err(Errno::EINVAL)
        );
    }
    #[test]
    fn console_negative_origin_rejected() {
        assert_eq!(
            convert(
                0,
                0,
                Rect {
                    left: -1,
                    ..viewport()
                }
            ),
            Err(Errno::EINVAL)
        );
    }
    #[test]
    fn console_one_cell() {
        let info = convert(
            0x3ff,
            0x1f,
            Rect {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            },
        )
        .unwrap();
        assert_eq!((info.columns, info.rows), (1, 1));
    }
}

#[cfg(test)]
mod real_console {
    use super::*;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn AllocConsole() -> i32;
        fn FreeConsole() -> i32;
        fn SetStdHandle(kind: u32, handle: Handle) -> i32;
        fn CreatePipe(read: *mut Handle, write: *mut Handle, security: Handle, size: u32) -> i32;
    }
    fn subprocess(case: &str) {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows::real_console::real_console_child",
                "--nocapture",
            ])
            .env("PALUDARIUM_U13_CONSOLE_CASE", case)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "real console case {case}: {status}");
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("real console deadline: {case}");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    #[test]
    fn real_console_stdin() {
        subprocess("0");
    }
    #[test]
    fn real_console_stdout() {
        subprocess("1");
    }
    #[test]
    fn real_console_stderr() {
        subprocess("2");
    }
    #[test]
    fn real_console_redirected_stdin() {
        subprocess("3");
    }
    #[test]
    fn real_console_redirected_stdout() {
        subprocess("4");
    }
    #[test]
    fn real_console_redirected_stderr() {
        subprocess("5");
    }
    #[test]
    fn real_console_invalid_handle() {
        subprocess("6");
    }
    #[test]
    fn real_console_child() {
        let Ok(case) = std::env::var("PALUDARIUM_U13_CONSOLE_CASE") else {
            subprocess("0");
            return;
        };
        let case: usize = case.parse().unwrap();
        // SAFETY: this test runs in its own process; console ownership is local.
        unsafe {
            FreeConsole();
            assert_ne!(AllocConsole(), 0);
        }
        let input = console("CONIN$").unwrap();
        let output = console("CONOUT$").unwrap();
        let kinds = [(-10_i32) as u32, (-11_i32) as u32, (-12_i32) as u32];
        for (index, kind) in kinds.iter().enumerate() {
            assert_ne!(
                // SAFETY: all fixture handles remain live throughout the test.
                unsafe { SetStdHandle(*kind, if index == 0 { input.0 } else { output.0 }) },
                0
            );
        }
        let before = (mode(input.0).unwrap(), mode(output.0).unwrap());
        let index = case % 3;
        let stream = [StreamId::Stdin, StreamId::Stdout, StreamId::Stderr][index];
        let mut read = std::ptr::null_mut();
        let mut write = std::ptr::null_mut();
        if (3..6).contains(&case) {
            assert_ne!(
                // SAFETY: pipe outputs are live host-owned pointer buffers.
                unsafe { CreatePipe(&mut read, &mut write, std::ptr::null_mut(), 0) },
                0
            );
            assert_ne!(
                // SAFETY: the selected pipe is owned and live through the query.
                unsafe { SetStdHandle(kinds[index], if index == 0 { read } else { write }) },
                0
            );
            assert_eq!(terminal_info(stream), Ok(None));
        } else if case == 6 {
            // SAFETY: only this isolated test process receives a null stdin.
            assert_ne!(unsafe { SetStdHandle(kinds[0], std::ptr::null_mut()) }, 0);
            assert_eq!(terminal_info(StreamId::Stdin), Err(Errno::EBADF));
        } else {
            let info = terminal_info(stream).unwrap().unwrap();
            assert!(info.columns > 0 && info.rows > 0);
        }
        assert_eq!((mode(input.0).unwrap(), mode(output.0).unwrap()), before);
        for (index, kind) in kinds.iter().enumerate() {
            assert_ne!(
                // SAFETY: reset borrowed standard handles to the live fixture.
                unsafe { SetStdHandle(*kind, if index == 0 { input.0 } else { output.0 }) },
                0
            );
        }
        if !read.is_null() {
            // SAFETY: both handles are owned once by this pipe fixture.
            unsafe {
                CloseHandle(read);
                CloseHandle(write);
            }
        }
    }
}
