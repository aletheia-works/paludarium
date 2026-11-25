//! A file generated record by record as it is read, as Linux's `seq_file`
//! serves one (`seq_read_iter`, `traverse`, `seq_lseek`): each `read` asks
//! its [`Records`] for the records of that moment from where the reader
//! had got to, so a reader sees what is there when it reads, not what was
//! there when it opened the file. `/proc/sysvipc`'s files are these
//! ([`crate::ipc::proc_record`]), and so are a process's `maps`, `smaps`,
//! `smaps_rollup` and `io` ([`crate::proc::maps_file`],
//! [`crate::proc::single_file`]).
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
    /// `None` past the last; an error is what `show` failed with.
    fn record(&self, index: u64) -> Result<Option<(Vec<u8>, u64)>, Errno>;
    /// The records as they are now, for those whose `start` locks them until
    /// `stop`; otherwise each is as it is when it is reached.
    fn held(&self) -> Option<Box<dyn Records>> {
        None
    }
}

/// The records of a [`Records::held`]: each index's, or nothing for one that
/// `show` skips.
pub(crate) struct Held(pub Vec<Vec<u8>>);
impl Records for Held {
    fn record(&self, index: u64) -> Result<Option<(Vec<u8>, u64)>, Errno> {
        let shown = (0..)
            .zip(&self.0)
            .skip(usize::try_from(index).unwrap_or(usize::MAX))
            .find(|(_, record)| !record.is_empty());
        Ok(shown.map(|(at, record)| (record.clone(), at + 1)))
    }
}

/// Records that are the lines of a text made again for each record, as
/// a file whose `show` writes one line for each thing there is then:
/// the mounts of a mount namespace, the extents of an ID map.
pub(crate) struct Lines<F>(pub F);
impl<F: Fn() -> Vec<u8> + Send + Sync> Records for Lines<F> {
    fn record(&self, index: u64) -> Result<Option<(Vec<u8>, u64)>, Errno> {
        let text = (self.0)();
        let line = usize::try_from(index)
            .ok()
            .and_then(|index| text.split_inclusive(|&b| b == b'\n').nth(index));
        Ok(line.map(|line| (line.to_vec(), index + 1)))
    }
}

/// The write operation of a file of a process's `/proc` directory that has
/// one, as a `proc_write` handler: given the bytes and the file position,
/// the count it took and the position it leaves (Linux's `*ppos`).
pub(crate) type Writer = Box<dyn Fn(&[u8], u64) -> Result<(usize, u64), Errno> + Send + Sync>;

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
    /// A write moved the position away from where reading had got to, so
    /// the next read walks there first (`read_pos` apart from `ki_pos`).
    moved: bool,
}

/// A file served from its [`Records`] as it is read, of size 0. A
/// system-wide one, as a `proc_create` file is, gives `EIO` for a write, as
/// `proc_reg_write` does without a `proc_write`; one of a process's `/proc`
/// directory ([`Self::of_task`]) has no write operation at all (`EINVAL`).
pub(crate) struct SeqFile {
    records: Box<dyn Records>,
    /// The access mode it was opened with (`O_RDONLY`, `O_WRONLY` or
    /// `O_RDWR`), which `F_GETFL` shows and a read or write checks.
    access: u32,
    writable: bool,
    /// Its write operation, if it has one ([`Self::writing`]).
    writer: Option<Writer>,
    /// What a write on a descriptor open for writing gives.
    unwritable: Errno,
    /// Whether Linux makes it with `seq_open`, which clears `FMODE_PWRITE`
    /// so that a `pwrite` is `ESPIPE`; `cmdline` and `environ` have read
    /// operations of their own instead ([`Self::not_seq_opened`]).
    seq_opened: bool,
    /// What `fstat` shows but the owner.
    stat: FileStat,
    /// Its inode's owner, for a file of a process's `/proc` directory
    /// ([`crate::proc::Owners`]).
    owner: Option<crate::proc::Owner>,
    state: Mutex<State>,
    /// What `F_SETFL` set on it ([`crate::files::StatusFlags`]).
    status: crate::files::StatusFlags,
}
impl SeqFile {
    pub(crate) fn open(records: Box<dyn Records>, flags: u32) -> Self {
        Self {
            status: crate::files::StatusFlags::opened(flags),
            records,
            access: flags & 3,
            writable: flags & 3 != 0,
            writer: None,
            unwritable: Errno::EIO,
            seq_opened: true,
            stat: crate::proc::entry_stat(),
            owner: None,
            state: Mutex::new(State {
                pending: Vec::new(),
                from: 0,
                next: 0,
                position: 0,
                buffer: BUFFER,
                moved: false,
            }),
        }
    }
    /// A file of a process's `/proc` directory, whose `fstat` shows `stat`
    /// with `owner`'s user and group, and which has no write operation.
    pub(crate) fn of_task(
        records: Box<dyn Records>,
        flags: u32,
        stat: FileStat,
        owner: crate::proc::Owner,
    ) -> Self {
        Self {
            unwritable: Errno::EINVAL,
            stat,
            owner: Some(owner),
            ..Self::open(records, flags)
        }
    }
    /// The same, with `writer` as its write operation, as `comm`,
    /// `uid_map`, `gid_map` and `setgroups` have one.
    pub(crate) fn writing(self, writer: Writer) -> Self {
        Self {
            writer: Some(writer),
            ..self
        }
    }
    /// The same, for a file Linux does not open with `seq_open`, whose
    /// `pwrite` checks its access mode and write operation as a `write`
    /// does.
    pub(crate) fn not_seq_opened(self) -> Self {
        Self {
            seq_opened: false,
            ..self
        }
    }
    /// Gathers whole records until `wanted` bytes are there or one more
    /// would fill the buffer, as `seq_read_iter` does; the first always
    /// goes in, the buffer doubling until it fits. A record that fails
    /// ends the gathering, and fails the read when it is the first.
    fn gather(&self, state: &mut State, wanted: usize) -> Result<(), Errno> {
        state.pending.clear();
        state.from = 0;
        let held = self.records.held();
        let records = held.as_deref().unwrap_or(&*self.records);
        loop {
            let (record, after) = match records.record(state.next) {
                Ok(Some(record)) => record,
                Ok(None) => return Ok(()),
                Err(e) if state.pending.is_empty() => return Err(e),
                Err(_) => return Ok(()),
            };
            if state.pending.is_empty() {
                while record.len() >= state.buffer {
                    state.buffer *= 2;
                }
            } else if state.pending.len() + record.len() >= state.buffer {
                return Ok(());
            }
            state.pending.extend_from_slice(&record);
            state.next = after;
            if state.pending.len() >= wanted {
                return Ok(());
            }
        }
    }
    /// Starts over and walks to `offset`, as Linux's `traverse`: past the
    /// end it only reads nothing, and a record that fails fails it.
    fn walk_to(&self, state: &mut State, offset: u64) -> Result<(), Errno> {
        state.pending.clear();
        state.from = 0;
        state.next = 0;
        if offset == 0 {
            return Ok(());
        }
        let held = self.records.held();
        let records = held.as_deref().unwrap_or(&*self.records);
        let mut reached = 0;
        while let Some((record, after)) = records.record(state.next)? {
            state.next = after;
            let length = record.len() as u64;
            if reached + length > offset {
                state.from = (offset - reached) as usize;
                state.pending = record;
                return Ok(());
            }
            reached += length;
            if reached == offset {
                return Ok(());
            }
        }
        Ok(())
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
        // Where a write left the position, the records are walked to it
        // first, as `seq_read_iter` does `traverse` when `ki_pos` is not
        // `read_pos`; a walk that fails starts over and fails the read.
        if std::mem::take(&mut state.moved)
            && let Err(e) = self.walk_to(state, state.position)
        {
            self.walk_to(state, 0)?;
            state.position = 0;
            return Err(e);
        }
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
        if let Err(e) = self.gather(state, buf.len() - copied)
            && copied == 0
        {
            return Err(e);
        }
        let count = (buf.len() - copied).min(state.pending.len());
        buf[copied..copied + count].copy_from_slice(&state.pending[..count]);
        state.from = count;
        copied += count;
        state.position += copied as u64;
        Ok(copied)
    }
    /// Its write operation, from the file position; otherwise it has no
    /// `proc_write` (`EIO`) or no write operation (`EINVAL`), or `EBADF` on
    /// a descriptor opened read-only.
    fn write(&self, b: &[u8]) -> Result<usize, Errno> {
        if !self.writable {
            return Err(Errno::EBADF);
        }
        let Some(writer) = &self.writer else {
            return Err(self.unwritable);
        };
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let (count, position) = writer(b, state.position)?;
        if position != state.position {
            state.position = position;
            state.moved = true;
        }
        Ok(count)
    }
    /// `ESPIPE`, whatever the access mode, as `seq_open` clears the file's
    /// `FMODE_PWRITE`, which `pwrite64` checks before anything else; one not
    /// so opened writes through its position (`ENODEV`).
    fn write_at(&self, _: u64, _: &[u8]) -> Result<usize, Errno> {
        Err(if self.seq_opened {
            Errno::ESPIPE
        } else {
            Errno::ENODEV
        })
    }
    /// As Linux's `seq_lseek`: from the start or the current position,
    /// never the end, which it does not know. A walk that a record fails
    /// leaves it at the start.
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
            if let Err(e) = self.walk_to(&mut state, target) {
                self.walk_to(&mut state, 0)?;
                state.position = 0;
                return Err(e);
            }
            state.position = target;
        }
        Ok(target)
    }
    /// Size 0, as Linux's `/proc`: a reader goes by what `read` gives.
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(match &self.owner {
            Some(owner) => crate::proc::owned(self.stat, owner),
            None => self.stat,
        })
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
    fn flags(&self) -> u32 {
        self.status.of(self.access)
    }
    /// `F_SETFL`, as Linux's `setfl`.
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.status.set(flags);
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
    /// A list that starts with this fails every record.
    const FAILS: u32 = u32::MAX;
    impl Records for Numbers {
        fn record(&self, index: u64) -> Result<Option<(Vec<u8>, u64)>, Errno> {
            let numbers = self.0.lock().unwrap();
            if numbers.first() == Some(&FAILS) {
                return Err(Errno::EACCES);
            }
            let number = usize::try_from(index).ok().and_then(|i| numbers.get(i));
            Ok(number.map(|number| (format!("{number}\n").into_bytes(), index + 1)))
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

    #[test]
    fn a_failing_record_fails_the_read_or_seek_that_reaches_it_first() {
        let (file, numbers) = file(&[FAILS, 1]);
        assert_eq!(read(&file, 0), b"");
        assert_eq!(file.read(&mut [0; 10]), Err(Errno::EACCES));
        // A walk that fails leaves the file at the start.
        assert_eq!(file.seek(1, 0), Err(Errno::EACCES));
        assert_eq!(file.seek(0, 1), Ok(0));
        numbers.lock().unwrap()[0] = 5;
        assert_eq!(read(&file, 2), b"5\n");
        // From the start again, the first record fails again.
        numbers.lock().unwrap()[0] = FAILS;
        assert_eq!(file.seek(0, 0), Ok(0));
        assert_eq!(file.read(&mut [0; 10]), Err(Errno::EACCES));
    }

    #[test]
    fn a_file_of_a_process_has_its_owner_and_no_write_operation() {
        let owner = crate::proc::Owner::default();
        *owner.lock().unwrap() = (7, 8);
        let numbers = Arc::new(Mutex::new(vec![1]));
        let stat = crate::proc::private_stat(0);
        let file = SeqFile::of_task(Box::new(Numbers(numbers)), 2, stat, owner);
        let shown = file.stat().unwrap();
        assert_eq!((shown.uid, shown.gid, shown.mode), (7, 8, stat.mode));
        assert_eq!(file.write(b"x"), Err(Errno::EINVAL));
        assert_eq!(read(&file, 10), b"1\n");
        assert_eq!(file.flags(), 2);
    }

    #[test]
    fn a_write_operation_moves_the_position_the_next_read_walks_to() {
        let numbers = Arc::new(Mutex::new(vec![10, 20]));
        let shared = numbers.clone();
        let stat = crate::proc::private_stat(0);
        let file = SeqFile::of_task(Box::new(Numbers(numbers)), 2, stat, Default::default())
            .writing(Box::new(move |b, at| {
                if at != 0 {
                    return Err(Errno::EINVAL);
                }
                shared.lock().unwrap().push(b.len() as u32);
                Ok((b.len(), b.len() as u64))
            }));
        assert_eq!(file.write(b"abc"), Ok(3));
        // Three bytes in, among the records as they are now.
        assert_eq!(read(&file, 100), b"20\n3\n");
        assert_eq!(file.write(b"x"), Err(Errno::EINVAL));
        assert_eq!(file.write_at(0, b"x"), Err(Errno::ESPIPE));
        assert_eq!(file.seek(0, 0), Ok(0));
        assert_eq!(read(&file, 100), b"10\n20\n3\n");
        // `cmdline` and `environ` write through the position instead.
        let other = SeqFile::of_task(
            Box::new(Numbers(Default::default())),
            2,
            stat,
            Default::default(),
        );
        assert_eq!(other.not_seq_opened().write_at(0, b"x"), Err(Errno::ENODEV));
    }
    /// Records held for each gather: reaching one by itself takes the first
    /// away.
    struct Changing(Arc<Mutex<Vec<Vec<u8>>>>);
    impl Records for Changing {
        fn record(&self, index: u64) -> Result<Option<(Vec<u8>, u64)>, Errno> {
            let mut now = self.0.lock().unwrap();
            now.remove(0);
            Held(now.clone()).record(index)
        }
        fn held(&self) -> Option<Box<dyn Records>> {
            Some(Box::new(Held(self.0.lock().unwrap().clone())))
        }
    }
    #[test]
    fn held_records_stay_for_a_whole_gather() {
        let list = [&b"a\n"[..], b"", b"b\n", b"c\n"].map(<[u8]>::to_vec);
        let list = Arc::new(Mutex::new(list.to_vec()));
        let file = SeqFile::open(Box::new(Changing(Arc::clone(&list))), 0);
        let mut buf = [0; 16];
        let n = file.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"a\nb\nc\n");
        // The next read starts where the last gather ended.
        list.lock().unwrap().push(b"d\n".to_vec());
        let n = file.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"d\n");
        assert_eq!(file.read(&mut buf), Ok(0));
    }
}
