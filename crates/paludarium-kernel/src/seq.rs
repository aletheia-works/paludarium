//! A file generated record by record as it is read, as Linux's `seq_file`
//! serves one (`seq_read_iter`, `traverse`, `seq_lseek`): each `read` asks
//! its [`Records`] for the records of that moment from where the reader
//! had got to, so a reader sees what is there when it reads, not what was
//! there when it opened the file. `/proc/sysvipc`'s files are these
//! ([`crate::ipc::proc_record`]).
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::Errno;
use std::sync::{Mutex, PoisonError};

/// How much a `read` gathers: Linux's `seq_file` buffer, one page until a
/// single record needs more.
const BUFFER: usize = 4096;

/// The records of a file, as Linux's `seq_operations` walk them.
pub(crate) trait Records: Send + Sync {
    /// The record at `index` or, with none there, the first after it, and
    /// the index of the one after that (`start` or `next`, then `show`);
    /// `None` past the last.
    fn record(&self, index: u64) -> Option<(Vec<u8>, u64)>;
}

/// Where a reader has got to, as Linux's `struct seq_file` keeps it.
struct State {
    /// The bytes gathered but not yet read (`buf`, `count`).
    pending: Vec<u8>,
    /// How far into `pending` the reader is (`from`).
    from: usize,
    /// The index of the next record to gather (`index`).
    next: u64,
    /// The file position (`read_pos`).
    position: u64,
    /// The size of the buffer, which a long record doubles (`size`).
    buffer: usize,
}

/// A file served from its [`Records`] as it is read; system-wide, as a
/// `proc_create` file is: of size 0, and a write is `EIO`, as
/// `proc_reg_write` gives without a `proc_write`.
pub(crate) struct SeqFile {
    records: Box<dyn Records>,
    writable: bool,
    state: Mutex<State>,
}
impl SeqFile {
    pub(crate) fn open(records: Box<dyn Records>, flags: u32) -> Self {
        Self {
            records,
            writable: flags & 3 != 0,
            state: Mutex::new(State {
                pending: Vec::new(),
                from: 0,
                next: 0,
                position: 0,
                buffer: BUFFER,
            }),
        }
    }
    /// Gathers whole records until `wanted` bytes are there or one more
    /// would fill the buffer, as `seq_read_iter` does; the first always
    /// goes in, the buffer doubling until it fits.
    fn gather(&self, state: &mut State, wanted: usize) {
        state.pending.clear();
        state.from = 0;
        while let Some((record, after)) = self.records.record(state.next) {
            if state.pending.is_empty() {
                while record.len() >= state.buffer {
                    state.buffer *= 2;
                }
            } else if state.pending.len() + record.len() >= state.buffer {
                break;
            }
            state.pending.extend_from_slice(&record);
            state.next = after;
            if state.pending.len() >= wanted {
                break;
            }
        }
    }
    /// Starts over and walks to `offset`, as Linux's `traverse`: past the
    /// end it only reads nothing.
    fn walk_to(&self, state: &mut State, offset: u64) {
        state.pending.clear();
        state.from = 0;
        state.next = 0;
        if offset == 0 {
            return;
        }
        let mut reached = 0;
        while let Some((record, after)) = self.records.record(state.next) {
            state.next = after;
            let length = record.len() as u64;
            if reached + length > offset {
                state.from = (offset - reached) as usize;
                state.pending = record;
                return;
            }
            reached += length;
            if reached == offset {
                return;
            }
        }
    }
}
/// Whether `file` is one of these, whose reads its size of 0 does not
/// bound.
pub(crate) fn is_file(file: &dyn std::any::Any) -> bool {
    file.is::<SeqFile>()
}
impl FileHandle for SeqFile {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let state = &mut *state;
        // A read from the start starts the records over.
        if state.position == 0 {
            state.pending.clear();
            state.from = 0;
            state.next = 0;
        }
        let mut copied = 0;
        let waiting = &state.pending[state.from..];
        if !waiting.is_empty() {
            copied = buf.len().min(waiting.len());
            buf[..copied].copy_from_slice(&waiting[..copied]);
            state.from += copied;
            if state.from < state.pending.len() {
                state.position += copied as u64;
                return Ok(copied);
            }
        }
        // With what was left all read, the next record is gathered now,
        // even when the reader has no room left for it.
        self.gather(state, buf.len() - copied);
        let count = (buf.len() - copied).min(state.pending.len());
        buf[copied..copied + count].copy_from_slice(&state.pending[..count]);
        state.from = count;
        copied += count;
        state.position += copied as u64;
        Ok(copied)
    }
    /// It has no write operation: `EIO`, or `EBADF` on a descriptor opened
    /// read-only.
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(if self.writable {
            Errno::EIO
        } else {
            Errno::EBADF
        })
    }
    /// As Linux's `seq_lseek`: from the start or the current position,
    /// never the end, which it does not know.
    fn seek(&self, offset: i64, whence: u32) -> Result<u64, Errno> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let base = match whence {
            0 => 0,
            1 => state.position,
            _ => return Err(Errno::EINVAL),
        };
        let target = base.checked_add_signed(offset).ok_or(Errno::EINVAL)?;
        if i64::try_from(target).is_err() {
            return Err(Errno::EINVAL);
        }
        if target != state.position {
            self.walk_to(&mut state, target);
            state.position = target;
        }
        Ok(target)
    }
    /// Size 0, as Linux's `/proc`: a reader goes by what `read` gives.
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(crate::proc::entry_stat())
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
    fn flags(&self) -> u32 {
        0
    }
    fn set_flags(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Records `"<n>\n"` for each number in the shared list, by their
    /// place in it.
    struct Numbers(Arc<Mutex<Vec<u32>>>);
    impl Records for Numbers {
        fn record(&self, index: u64) -> Option<(Vec<u8>, u64)> {
            let numbers = self.0.lock().unwrap();
            let number = numbers.get(usize::try_from(index).ok()?)?;
            Some((format!("{number}\n").into_bytes(), index + 1))
        }
    }
    fn file(numbers: &[u32]) -> (SeqFile, Arc<Mutex<Vec<u32>>>) {
        let shared = Arc::new(Mutex::new(numbers.to_vec()));
        let file = SeqFile::open(Box::new(Numbers(shared.clone())), 0);
        (file, shared)
    }
    fn read(file: &SeqFile, count: usize) -> Vec<u8> {
        let mut buf = vec![0; count];
        let n = file.read(&mut buf).unwrap();
        buf.truncate(n);
        buf
    }

    #[test]
    fn a_read_sees_the_records_of_that_moment_from_where_it_had_got_to() {
        let (file, numbers) = file(&[1, 2, 3]);
        // The first record and part of the second: the rest of that one
        // stays as it was gathered.
        assert_eq!(read(&file, 3), b"1\n2");
        numbers.lock().unwrap()[1] = 9;
        numbers.lock().unwrap().push(4);
        assert_eq!(read(&file, 100), b"\n3\n4\n");
        assert_eq!(read(&file, 100), b"");
        // From the start again, everything as it is now.
        assert_eq!(file.seek(0, 0), Ok(0));
        assert_eq!(read(&file, 100), b"1\n9\n3\n4\n");
    }

    #[test]
    fn a_read_gathers_the_next_record_even_with_no_room_left() {
        let (file, numbers) = file(&[1, 2]);
        assert_eq!(read(&file, 1), b"1");
        // What was left fills the read exactly; the next record is
        // gathered then, so a later change does not show.
        assert_eq!(read(&file, 1), b"\n");
        numbers.lock().unwrap()[1] = 7;
        assert_eq!(read(&file, 100), b"2\n");
    }

    #[test]
    fn a_read_stops_at_a_page_of_whole_records() {
        let (file, _) = file(&(0..2000).collect::<Vec<_>>());
        let first = read(&file, 1 << 20);
        assert!(first.len() < BUFFER && first.ends_with(b"\n"));
        assert!(BUFFER - first.len() <= "1999\n".len());
        assert_eq!(read(&file, 0), b"");
    }

    #[test]
    fn a_seek_walks_from_the_start_and_never_from_the_end() {
        let (file, numbers) = file(&[10, 20, 30]);
        assert_eq!(file.seek(4, 0), Ok(4));
        numbers.lock().unwrap()[2] = 40;
        assert_eq!(read(&file, 100), b"0\n40\n");
        assert_eq!(file.seek(-4, 1), Ok(5));
        assert_eq!(read(&file, 100), b"\n40\n");
        assert_eq!(file.seek(0, 2), Err(Errno::EINVAL));
        assert_eq!(file.seek(-100, 1), Err(Errno::EINVAL));
        assert_eq!(file.seek(100, 0), Ok(100));
        assert_eq!(read(&file, 100), b"");
    }

    #[test]
    fn it_is_a_system_wide_file_of_size_0_that_cannot_be_written() {
        let (file, _) = file(&[1]);
        assert_eq!(file.stat().unwrap().size, 0);
        assert_eq!(file.write(b"x"), Err(Errno::EBADF));
        let numbers = Arc::new(Mutex::new(Vec::new()));
        let writable = SeqFile::open(Box::new(Numbers(numbers)), 1);
        assert_eq!(writable.write(b"x"), Err(Errno::EIO));
    }
}
