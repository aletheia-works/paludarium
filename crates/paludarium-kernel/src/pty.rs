//! Pseudo-terminals, as Linux's devpts and `drivers/tty/pty.c` make them,
//! with the N_TTY line discipline of `drivers/tty/n_tty.c` on the slave.
//!
//! Each open of `/dev/ptmx` makes a [`Terminal`]: its master ([`Master`])
//! and the slave `/dev/pts/<n>` ([`Slave`]). What the master writes is the
//! slave's input, which the line discipline edits, echoes and turns into
//! signals for the foreground process group as the `termios` says; what the
//! slave writes is its output, processed as `c_oflag` says, which the
//! master reads as it is. The master's own line discipline is raw, as
//! Linux's `ptm_driver` sets it, so only the slave's `termios` is kept:
//! `TCGETS` and `TCSETS` on the master reach it, as Linux's
//! `tty_pair_get_tty` makes them. The terminal keeps its session and
//! foreground group; [`crate::processes::Processes`] keeps which terminal
//! controls each process (Linux's `signal->tty`).
use crate::events::{IN, NONBLOCK, OUT, PRI, ReadinessHub};
use crate::fasync::{FileOwner, Notice, O_ASYNC, OwnerKind, Reason, Registration};
use crate::processes::Processes;
use crate::syscalls::Context;
use paludarium_host::{DirectoryEntry, FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

const EINTR: Errno = Errno(4);
const EIO: Errno = Errno(5);
const EBUSY: Errno = Errno(16);
const ENOSPC: Errno = Errno(28);
const ESRCH: Errno = Errno(3);

const SIGINT: i32 = 2;
const SIGQUIT: i32 = 3;
const SIGTSTP: i32 = 20;
const SIGTTIN: i32 = 21;
const SIGTTOU: i32 = 22;
const SIGWINCH: i32 = 28;

/// `TIOCPKT_*`: the events a master in packet mode reads.
const TIOCPKT_FLUSHREAD: u8 = 1;
const TIOCPKT_FLUSHWRITE: u8 = 2;
const TIOCPKT_STOP: u8 = 4;
const TIOCPKT_START: u8 = 8;
const TIOCPKT_NOSTOP: u8 = 0x10;
const TIOCPKT_DOSTOP: u8 = 0x20;
const TIOCPKT_IOCTL: u8 = 0x40;

/// `kernel.pty.max`: how many pairs may be open at once.
const PTY_MAX: usize = 4096;
/// The line discipline's buffer, `N_TTY_BUF_SIZE`.
const BUFFER: usize = 4096;
/// What a side's flip buffer holds before a write to it waits
/// (`TTYB_DEFAULT_MEM_LIMIT`).
const FLIP: usize = 640 * 1024;
/// The master reads from its line discipline's buffer and the flip buffer
/// behind it.
const OUTPUT_LIMIT: usize = BUFFER + FLIP;
/// The devpts group a slave belongs to and its mode, as distributions mount
/// devpts (`gid=5,mode=620`).
const TTY_GROUP: u32 = 5;
const SLAVE_MODE: u32 = 0o620;
/// The majors of the pseudo-terminal slaves and of `/dev/tty`, `/dev/ptmx`.
const SLAVE_MAJOR: u64 = 136;
const TTYAUX_MAJOR: u64 = 5;

const O_NOCTTY: u32 = 0o400;

// c_iflag
const ISTRIP: u32 = 0o40;
const INLCR: u32 = 0o100;
const IGNCR: u32 = 0o200;
const ICRNL: u32 = 0o400;
const IUCLC: u32 = 0o1000;
const IXON: u32 = 0o2000;
const IXANY: u32 = 0o4000;
const PARMRK: u32 = 0o10;
const IUTF8: u32 = 0o40000;
// c_oflag
const OPOST: u32 = 0o1;
const OLCUC: u32 = 0o2;
const ONLCR: u32 = 0o4;
const OCRNL: u32 = 0o10;
const ONOCR: u32 = 0o20;
const ONLRET: u32 = 0o40;
const TABDLY: u32 = 0o14000;
const XTABS: u32 = 0o14000;
// c_cflag
const CBAUD: u32 = 0o10017;
const CBAUDEX: u32 = 0o10000;
const BOTHER: u32 = 0o10000;
const B38400: u32 = 0o17;
const CSIZE: u32 = 0o60;
const CS8: u32 = 0o60;
const CREAD: u32 = 0o200;
const PARENB: u32 = 0o400;
const IBSHIFT: u32 = 16;
// c_lflag
const ISIG: u32 = 0o1;
const ICANON: u32 = 0o2;
const ECHO: u32 = 0o10;
const ECHOE: u32 = 0o20;
const ECHOK: u32 = 0o40;
const ECHONL: u32 = 0o100;
const NOFLSH: u32 = 0o200;
const TOSTOP: u32 = 0o400;
const ECHOCTL: u32 = 0o1000;
const ECHOPRT: u32 = 0o2000;
const ECHOKE: u32 = 0o4000;
const IEXTEN: u32 = 0o100000;
const EXTPROC: u32 = 0o200000;
// c_cc
const VINTR: usize = 0;
const VQUIT: usize = 1;
const VERASE: usize = 2;
const VKILL: usize = 3;
const VEOF: usize = 4;
const VTIME: usize = 5;
const VMIN: usize = 6;
const VSTART: usize = 8;
const VSTOP: usize = 9;
const VSUSP: usize = 10;
const VEOL: usize = 11;
const VREPRINT: usize = 12;
const VWERASE: usize = 14;
const VLNEXT: usize = 15;
const VEOL2: usize = 16;

/// Linux's `baud_table`: the speed of each `CBAUD` code, `CBAUDEX` ones
/// from 15 on.
const BAUD: [u32; 31] = [
    0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 38400, 57600,
    115_200, 230_400, 460_800, 500_000, 576_000, 921_600, 1_000_000, 1_152_000, 1_500_000,
    2_000_000, 2_500_000, 3_000_000, 3_500_000, 4_000_000,
];

/// The kernel's `struct termios2`: `struct termios` (36 bytes) and the two
/// speeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Termios {
    pub iflag: u32,
    pub oflag: u32,
    pub cflag: u32,
    pub lflag: u32,
    pub line: u8,
    pub cc: [u8; 19],
    pub ispeed: u32,
    pub ospeed: u32,
}
impl Termios {
    /// A new slave's: `tty_std_termios`, which the pts driver gives
    /// `B38400 | CS8 | CREAD`, and `INIT_C_CC`.
    pub(crate) const SLAVE: Self = Self {
        iflag: ICRNL | IXON,
        oflag: OPOST | ONLCR,
        cflag: B38400 | CS8 | CREAD,
        lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
        line: 0,
        cc: [
            3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0, 0, 0,
        ],
        ispeed: 38400,
        ospeed: 38400,
    };
    /// Nothing locked: a new slave's `termios_locked`.
    const ZERO: Self = Self {
        iflag: 0,
        oflag: 0,
        cflag: 0,
        lflag: 0,
        line: 0,
        cc: [0; 19],
        ispeed: 0,
        ospeed: 0,
    };
    /// The master's control characters, `INIT_C_CC`, which `TCXONC` sends.
    const MASTER_CC: [u8; 19] = Self::SLAVE.cc;
    /// `struct termios`, or with `long` `struct termios2`.
    fn encode(&self, long: bool) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(44);
        for flag in [self.iflag, self.oflag, self.cflag, self.lflag] {
            bytes.extend_from_slice(&flag.to_le_bytes());
        }
        bytes.push(self.line);
        bytes.extend_from_slice(&self.cc);
        if long {
            bytes.extend_from_slice(&self.ispeed.to_le_bytes());
            bytes.extend_from_slice(&self.ospeed.to_le_bytes());
        }
        bytes
    }
    /// `struct termio` (`TCGETA`): the low 16 bits of each flag, the line
    /// discipline and the first 8 control characters, as Linux's
    /// `kernel_termios_to_user_termio`.
    fn termio(&self) -> [u8; 18] {
        let mut bytes = [0; 18];
        for (i, flag) in [self.iflag, self.oflag, self.cflag, self.lflag]
            .into_iter()
            .enumerate()
        {
            bytes[i * 2..i * 2 + 2].copy_from_slice(&(flag as u16).to_le_bytes());
        }
        bytes[8] = self.line;
        bytes[9..17].copy_from_slice(&self.cc[..8]);
        bytes
    }
    /// The `struct termios` that `TCSETA`'s `struct termio` makes of
    /// `self`, as Linux's `user_termio_to_kernel_termios`: the high bits of
    /// the flags and the other control characters stay.
    fn with_termio(&self, bytes: &[u8]) -> Vec<u8> {
        let mut new = *self;
        let half = |i: usize| u32::from(u16::from_le_bytes([bytes[i], bytes[i + 1]]));
        new.iflag = self.iflag & 0xffff_0000 | half(0);
        new.oflag = self.oflag & 0xffff_0000 | half(2);
        new.cflag = self.cflag & 0xffff_0000 | half(4);
        new.lflag = self.lflag & 0xffff_0000 | half(6);
        new.line = bytes[8];
        new.cc[..8].copy_from_slice(&bytes[9..17]);
        new.encode(false)
    }
    /// What `TCSETS` (36 bytes) or `TCSETS2` (44) sets over `self`, as
    /// Linux's `set_termios`: the speeds follow the `CBAUD` codes, what
    /// `locked` holds stays as it was (`unset_locked_termios`), and a
    /// pseudo-terminal keeps `CS8 | CREAD` without parity
    /// (`pty_set_termios`).
    fn decoded(&self, bytes: &[u8], locked: &Self) -> Self {
        let word =
            |i: usize| u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        let mut new = *self;
        new.iflag = word(0);
        new.oflag = word(4);
        new.cflag = word(8);
        new.lflag = word(12);
        new.line = bytes[16];
        new.cc.copy_from_slice(&bytes[17..36]);
        if bytes.len() >= 44 {
            new.ispeed = word(36);
            new.ospeed = word(40);
        }
        new.ispeed = new.input_speed();
        new.ospeed = new.output_speed();
        // As on Linux, the speeds come from the request before the lock
        // applies: `set_termios` sets them, then `tty_set_termios` calls
        // `unset_locked_termios`, which leaves them ("FIXME: What should we
        // do for i/ospeed"), so a locked `CBAUD` keeps the old code while
        // the speeds follow the request.
        let keep = |new: u32, old: u32, locked: u32| new & !locked | old & locked;
        new.iflag = keep(new.iflag, self.iflag, locked.iflag);
        new.oflag = keep(new.oflag, self.oflag, locked.oflag);
        new.cflag = keep(new.cflag, self.cflag, locked.cflag);
        new.lflag = keep(new.lflag, self.lflag, locked.lflag);
        if locked.line != 0 {
            new.line = self.line;
        }
        for (i, &lock) in locked.cc.iter().enumerate() {
            if lock != 0 {
                new.cc[i] = self.cc[i];
            }
        }
        new.cflag = (new.cflag & !(CSIZE | PARENB)) | CS8 | CREAD;
        new
    }
    /// `tty_termios_baud_rate`.
    fn output_speed(&self) -> u32 {
        Self::speed(self.cflag & CBAUD, self.ospeed)
    }
    /// `tty_termios_input_baud_rate`: the output speed when `CIBAUD` is 0.
    fn input_speed(&self) -> u32 {
        match (self.cflag >> IBSHIFT) & CBAUD {
            0 => self.output_speed(),
            code => Self::speed(code, self.ispeed),
        }
    }
    fn speed(code: u32, other: u32) -> u32 {
        if code == BOTHER {
            return other;
        }
        let index = if code & CBAUDEX != 0 {
            (code & !CBAUDEX) + 15
        } else {
            code
        };
        BAUD.get(index as usize).copied().unwrap_or(0)
    }
}

/// A byte of the line discipline's buffer and whether a line ends at it
/// (`read_flags`); an end at a 0 byte is an end of file.
#[derive(Clone, Copy, Debug)]
struct Cell {
    byte: u8,
    end: bool,
}

/// `stopped` and `tco_stopped` of a side's `tty->flow`.
#[derive(Clone, Copy, Debug, Default)]
struct Flow {
    stopped: bool,
    tco: bool,
}

/// Signals for process groups, sent once the state is unlocked.
type Signals = Vec<(u32, i32)>;

struct State {
    termios: Termios,
    window: [u16; 4],
    /// `TIOCSPTLCK`: the slave cannot be opened.
    locked: bool,
    /// The master is open.
    master: bool,
    /// Open descriptions of the slave.
    slaves: usize,
    /// The master's `TTY_OTHER_CLOSED`: the slave was open and all its
    /// descriptions have closed since.
    other_closed: bool,
    /// Hang-ups so far; a slave description opened before the last one is
    /// hung up.
    hangups: u64,
    /// The slave's flip buffer: what the master wrote that the line
    /// discipline has not taken yet.
    pending: VecDeque<u8>,
    /// The line discipline's buffer, from `read_tail` to `read_head`.
    read: VecDeque<Cell>,
    /// `read_tail`, `read_head` and `canon_head` as counts since the buffer
    /// was last emptied.
    tail: u64,
    head: u64,
    canon_head: u64,
    /// `push`: the line in the buffer ends without a delimiter.
    pushed: bool,
    lnext: bool,
    erasing: bool,
    column: usize,
    canon_column: usize,
    /// The slave's output and the master's.
    flow: Flow,
    master_flow: Flow,
    /// Echoes not output yet: those of the input the line discipline is
    /// taking now, which a signal character discards, or made while the
    /// output is stopped (Linux's echo buffer).
    echoes: Vec<u8>,
    /// The bytes being put are echoes.
    echoing: bool,
    /// The master's input: the slave's output and the echoes.
    output: VecDeque<u8>,
    session: Option<u32>,
    pgrp: Option<u32>,
    exclusive: bool,
    /// `TIOCSLCKTRMIOS`: the slave's bits and characters that stay.
    locked_termios: Termios,
    /// `TIOCPKT`: the master reads in packet mode.
    packet: bool,
    /// The slave's `ctrl.pktstatus`: the `TIOCPKT_*` events the master has
    /// not read yet.
    pktstatus: u8,
    /// The slave's inode: owner, group and mode.
    uid: u32,
    gid: u32,
    mode: u32,
    /// Rising edges of the slave's and the master's input and output.
    edges: [u64; 4],
    /// The slave's line discipline is gone, from a hang-up until the slave
    /// is opened again (`tty_ldisc_kill`, `tty_reopen`): what the master
    /// writes waits in the flip buffer.
    ldisc_down: bool,
    /// `TIOCVHANGUP` hung up the master: its file reads nothing, and its
    /// line discipline is gone.
    master_hung_up: bool,
    /// The `fasync` lists of the slave ([`SLAVE`]) and the master
    /// ([`MASTER`]): the descriptions open with `O_ASYNC`, the latest first
    /// as `fasync_insert_entry` puts them, and the descriptor each was set
    /// through.
    fasync: [Vec<(Weak<dyn FileHandle>, Registration)>; 2],
    /// Each side's `TTY_DO_WRITE_WAKEUP`: a write left bytes unwritten while
    /// the side had `O_ASYNC` descriptions, so room signals `POLL_OUT`.
    write_wakeup: [bool; 2],
    /// The `kill_fasync` calls made under the lock, sent once it is let go.
    io: Vec<(usize, Reason)>,
}
/// The sides of [`State::fasync`].
const SLAVE: usize = 0;
const MASTER: usize = 1;
/// `TTY_THRESHOLD_UNTHROTTLE`: a read that leaves at most this many bytes
/// wakes the other side's writers (`n_tty_check_unthrottle`).
const UNTHROTTLE: u64 = 128;
const SLAVE_IN: usize = 0;
const SLAVE_OUT: usize = 1;
const MASTER_IN: usize = 2;
const MASTER_OUT: usize = 3;

fn is_control(c: u8) -> bool {
    c < 0x20 || (0x7f..=0x9f).contains(&c)
}
/// Linux's `isalnum` of its Latin-1 `_ctype`.
fn is_alphanumeric(c: u8) -> bool {
    c.is_ascii_alphanumeric() || (c >= 0xc0 && c != 0xd7 && c != 0xf7)
}
fn lower(c: u8) -> u8 {
    if c.is_ascii_uppercase() || ((0xc0..=0xde).contains(&c) && c != 0xd7) {
        c + 32
    } else {
        c
    }
}
fn upper(c: u8) -> u8 {
    if c.is_ascii_lowercase() || ((0xe0..=0xfe).contains(&c) && c != 0xf7) {
        c - 32
    } else {
        c
    }
}

impl State {
    fn new(uid: u32) -> Self {
        Self {
            termios: Termios::SLAVE,
            window: [0; 4],
            locked: true,
            master: true,
            slaves: 0,
            other_closed: false,
            hangups: 0,
            pending: VecDeque::new(),
            read: VecDeque::new(),
            tail: 0,
            head: 0,
            canon_head: 0,
            pushed: false,
            lnext: false,
            erasing: false,
            column: 0,
            canon_column: 0,
            flow: Flow::default(),
            master_flow: Flow::default(),
            echoes: Vec::new(),
            echoing: false,
            output: VecDeque::new(),
            session: None,
            pgrp: None,
            exclusive: false,
            locked_termios: Termios::ZERO,
            packet: false,
            pktstatus: 0,
            uid,
            gid: TTY_GROUP,
            mode: SLAVE_MODE,
            edges: [0; 4],
            ldisc_down: false,
            master_hung_up: false,
            fasync: [Vec::new(), Vec::new()],
            write_wakeup: [false; 2],
            io: Vec::new(),
        }
    }
    /// `kill_fasync` of `side`'s list with `reason`, sent with the next
    /// [`Terminal::changed`].
    fn kill_fasync(&mut self, side: usize, reason: Reason) {
        if !self.fasync[side].is_empty() && !self.io.contains(&(side, reason)) {
            self.io.push((side, reason));
        }
    }
    /// `tty_wakeup` of `side`: room for a write that was left short.
    fn wakeup(&mut self, side: usize) {
        if std::mem::take(&mut self.write_wakeup[side]) {
            self.kill_fasync(side, Reason::Out);
        }
    }
    /// The end of `__receive_buf`: outside canonical mode, input in the
    /// buffer signals the slave's readers.
    fn received(&mut self) {
        if !self.canonical() && !self.read.is_empty() {
            self.kill_fasync(SLAVE, Reason::In);
        }
    }
    /// `chars_in_buffer` of the slave: the bytes a read could take.
    fn chars_in_buffer(&self) -> u64 {
        if self.canonical() {
            self.canon_head - self.tail
        } else {
            self.head - self.tail
        }
    }
    fn input(&self, flag: u32) -> bool {
        self.termios.iflag & flag != 0
    }
    fn output_flag(&self, flag: u32) -> bool {
        self.termios.oflag & flag != 0
    }
    fn local(&self, flag: u32) -> bool {
        self.termios.lflag & flag != 0
    }
    fn cc(&self, index: usize) -> u8 {
        self.termios.cc[index]
    }
    fn canonical(&self) -> bool {
        self.local(ICANON) && !self.local(EXTPROC)
    }
    fn continuation(&self, c: u8) -> bool {
        self.input(IUTF8) && c & 0xc0 == 0x80
    }
    fn edge(&mut self, which: usize) {
        self.edges[which] = self.edges[which].wrapping_add(1);
    }

    // The slave's output, as `do_output_char` and the echoes put it.

    fn put(&mut self, bytes: &[u8]) {
        if self.echoing {
            self.echoes.extend_from_slice(bytes);
        } else {
            self.output.extend(bytes);
            self.edge(MASTER_IN);
            self.kill_fasync(MASTER, Reason::In);
        }
    }
    /// `flush_echoes`: the echoes go out, unless the output is stopped.
    fn flush_echoes(&mut self) {
        if !self.flow.stopped && !self.echoes.is_empty() {
            let echoes = std::mem::take(&mut self.echoes);
            self.output.extend(echoes);
            self.edge(MASTER_IN);
            self.kill_fasync(MASTER, Reason::In);
        }
    }
    /// Linux's `do_output_char` with `room` bytes free: false when it does
    /// not fit.
    fn output_char(&mut self, mut c: u8, room: usize) -> bool {
        if room == 0 {
            return false;
        }
        match c {
            b'\n' => {
                if self.output_flag(ONLRET) {
                    self.column = 0;
                }
                if self.output_flag(ONLCR) {
                    if room < 2 {
                        return false;
                    }
                    self.column = 0;
                    self.canon_column = 0;
                    self.put(b"\r\n");
                    return true;
                }
                self.canon_column = self.column;
            }
            b'\r' => {
                if self.output_flag(ONOCR) && self.column == 0 {
                    return true;
                }
                if self.output_flag(OCRNL) {
                    c = b'\n';
                    if self.output_flag(ONLRET) {
                        self.column = 0;
                        self.canon_column = 0;
                    }
                } else {
                    self.column = 0;
                    self.canon_column = 0;
                }
            }
            b'\t' => {
                let spaces = 8 - (self.column & 7);
                if self.termios.oflag & TABDLY == XTABS {
                    if room < spaces {
                        return false;
                    }
                    self.column += spaces;
                    self.put(&b"        "[..spaces]);
                    return true;
                }
                self.column += spaces;
            }
            8 => self.column = self.column.saturating_sub(1),
            _ if !is_control(c) => {
                if self.output_flag(OLCUC) {
                    c = upper(c);
                }
                if !self.continuation(c) {
                    self.column += 1;
                }
            }
            _ => {}
        }
        self.put(&[c]);
        true
    }
    /// What the slave writes, as far as it fits: the bytes taken.
    fn write_output(&mut self, bytes: &[u8]) -> usize {
        if self.flow.stopped {
            return 0;
        }
        self.flush_echoes();
        if !self.output_flag(OPOST) {
            let count = bytes
                .len()
                .min(OUTPUT_LIMIT.saturating_sub(self.output.len()));
            self.put(&bytes[..count]);
            return count;
        }
        let mut done = 0;
        for &c in bytes {
            let room = OUTPUT_LIMIT.saturating_sub(self.output.len());
            if !self.output_char(c, room) {
                break;
            }
            done += 1;
        }
        done
    }
    /// An echo of a byte as it is (`echo_char_raw`).
    fn echo_raw(&mut self, c: u8) {
        self.echoing = true;
        if self.output_flag(OPOST) {
            self.output_char(c, usize::MAX);
        } else {
            self.put(&[c]);
        }
        self.echoing = false;
    }
    /// `echo_char`: with `ECHOCTL`, a control character other than a tab
    /// as `^X`.
    fn echo_char(&mut self, c: u8) {
        if self.local(ECHOCTL) && is_control(c) && c != b'\t' {
            self.echoing = true;
            self.put(&[b'^', c ^ 0o100]);
            self.echoing = false;
            self.column += 2;
        } else {
            self.echo_raw(c);
        }
    }
    fn finish_erasing(&mut self) {
        if self.erasing {
            self.echo_raw(b'/');
            self.erasing = false;
        }
    }
    /// `echo_set_canon_col` for the first character of a line.
    fn line_column(&mut self) {
        if self.canon_head == self.head {
            self.canon_column = self.column;
        }
    }
    /// `ECHO_OP_ERASE_TAB`: back over the columns a tab took.
    fn erase_tab(&mut self, columns: usize, after_tab: bool) {
        let columns = if after_tab {
            columns
        } else {
            columns + self.canon_column
        };
        self.echoing = true;
        for _ in 0..8 - (columns & 7) {
            self.put(b"\x08");
            self.column = self.column.saturating_sub(1);
        }
        self.echoing = false;
    }

    // The line discipline's input.

    fn queue(&mut self, byte: u8, end: bool) {
        self.read.push_back(Cell { byte, end });
        self.head += 1;
        if !self.canonical() {
            self.edge(SLAVE_IN);
        }
    }
    /// `reset_buffer_flags`: the buffer emptied.
    fn reset(&mut self) {
        self.read.clear();
        self.tail = 0;
        self.head = 0;
        self.canon_head = 0;
        self.pushed = false;
        self.erasing = false;
        self.lnext = false;
    }
    /// Takes the pending input while the buffer has room, as Linux's
    /// `n_tty_receive_buf_common`: a canonical line that fills it keeps
    /// only its last byte changing, so that a newline still ends it.
    fn receive(&mut self, signals: &mut Signals) {
        if self.ldisc_down {
            return;
        }
        let before = self.pending.len();
        while let Some(&c) = self.pending.front() {
            if self.read.len() >= BUFFER - 1 {
                if !(self.canonical() && self.canon_head == self.tail) {
                    break;
                }
                if self.read.len() >= BUFFER {
                    self.read.pop_back();
                    self.head -= 1;
                }
            }
            self.pending.pop_front();
            self.receive_char(c, signals);
        }
        if self.pending.len() != before {
            self.edge(MASTER_OUT);
            self.received();
        }
        self.flush_echoes();
    }
    /// Whether the line discipline looks at characters at all, rather than
    /// taking them as they come (`ldata->raw`).
    fn cooked(&self) -> bool {
        self.input(ISTRIP | IUCLC | IGNCR | ICRNL | INLCR | IXON | PARMRK)
            || self.local(ICANON | ISIG | ECHO)
    }
    /// Whether `c` is in `char_map`: one the line discipline acts on.
    fn special(&self, c: u8) -> bool {
        if c == 0 {
            return false;
        }
        let is = |index: usize| self.cc(index) == c;
        (c == b'\r' && self.input(IGNCR | ICRNL))
            || (c == b'\n' && self.input(INLCR))
            || (self.local(ICANON)
                && (is(VERASE) || is(VKILL) || is(VEOF) || c == b'\n' || is(VEOL)))
            || (self.local(ICANON)
                && self.local(IEXTEN)
                && (is(VWERASE) || is(VLNEXT) || is(VEOL2) || (self.local(ECHO) && is(VREPRINT))))
            || (self.input(IXON) && (is(VSTART) || is(VSTOP)))
            || (self.local(ISIG) && (is(VINTR) || is(VQUIT) || is(VSUSP)))
    }
    fn receive_char(&mut self, mut c: u8, signals: &mut Signals) {
        if !self.cooked() {
            self.queue(c, false);
            return;
        }
        if self.input(ISTRIP) {
            c &= 0x7f;
        }
        if self.input(IUCLC) && self.local(IEXTEN) {
            c = lower(c);
        }
        if self.lnext {
            self.lnext = false;
            self.receive_plain(c);
        } else if self.special(c) {
            self.receive_special(c, signals);
        } else {
            self.receive_plain(c);
        }
    }
    /// `n_tty_receive_char`.
    fn receive_plain(&mut self, c: u8) {
        if self.flow.stopped && !self.flow.tco && self.input(IXON) && self.input(IXANY) {
            self.start();
        }
        if self.local(ECHO) {
            self.finish_erasing();
            self.line_column();
            self.echo_char(c);
        }
        if c == 0xff && self.input(PARMRK) {
            self.queue(c, false);
        }
        self.queue(c, false);
    }
    /// `n_tty_receive_char_special`.
    fn receive_special(&mut self, mut c: u8, signals: &mut Signals) {
        let is = |state: &Self, index: usize| state.cc(index) == c;
        if self.input(IXON) && (is(self, VSTART) || is(self, VSTOP)) {
            if is(self, VSTART) {
                self.start();
            } else {
                self.stop();
            }
            return;
        }
        if self.local(ISIG) {
            for (index, signal) in [(VINTR, SIGINT), (VQUIT, SIGQUIT), (VSUSP, SIGTSTP)] {
                if is(self, index) {
                    self.signal_char(signal, c, signals);
                    return;
                }
            }
        }
        if self.flow.stopped && !self.flow.tco && self.input(IXON) && self.input(IXANY) {
            self.start();
        }
        if c == b'\r' {
            if self.input(IGNCR) {
                return;
            }
            if self.input(ICRNL) {
                c = b'\n';
            }
        } else if c == b'\n' && self.input(INLCR) {
            c = b'\r';
        }
        if self.canonical() {
            let is = |state: &Self, index: usize| state.cc(index) == c;
            if is(self, VERASE) || is(self, VKILL) || (is(self, VWERASE) && self.local(IEXTEN)) {
                self.eraser(c);
                return;
            }
            if is(self, VLNEXT) && self.local(IEXTEN) {
                self.lnext = true;
                if self.local(ECHO) {
                    self.finish_erasing();
                    if self.local(ECHOCTL) {
                        self.echo_raw(b'^');
                        self.echo_raw(8);
                    }
                }
                return;
            }
            if is(self, VREPRINT) && self.local(ECHO) && self.local(IEXTEN) {
                self.finish_erasing();
                self.echo_char(c);
                self.echo_raw(b'\n');
                let line: Vec<u8> = self
                    .read
                    .iter()
                    .skip((self.canon_head - self.tail) as usize)
                    .map(|cell| cell.byte)
                    .collect();
                for byte in line {
                    self.echo_char(byte);
                }
                return;
            }
            if c == b'\n' {
                if self.local(ECHO) || self.local(ECHONL) {
                    self.echo_raw(b'\n');
                }
                self.end_line(c);
                return;
            }
            if is(self, VEOF) {
                self.end_line(0);
                return;
            }
            if is(self, VEOL) || (is(self, VEOL2) && self.local(IEXTEN)) {
                if self.local(ECHO) {
                    self.line_column();
                    self.echo_char(c);
                }
                if c == 0xff && self.input(PARMRK) {
                    self.queue(c, false);
                }
                self.end_line(c);
                return;
            }
        }
        if self.local(ECHO) {
            self.finish_erasing();
            if c == b'\n' {
                self.echo_raw(b'\n');
            } else {
                self.line_column();
                self.echo_char(c);
            }
        }
        if c == 0xff && self.input(PARMRK) {
            self.queue(c, false);
        }
        self.queue(c, false);
    }
    /// `handle_newline`: the line ends, and can be read.
    fn end_line(&mut self, c: u8) {
        self.queue(c, true);
        self.canon_head = self.head;
        self.edge(SLAVE_IN);
        self.kill_fasync(SLAVE, Reason::In);
    }
    /// `n_tty_receive_signal_char`: the foreground group gets `signal`,
    /// and unless `NOFLSH` the input and the echoes not yet made go.
    fn signal_char(&mut self, signal: i32, c: u8, signals: &mut Signals) {
        if let Some(pgrp) = self.pgrp {
            signals.push((pgrp, signal));
        }
        if !self.local(NOFLSH) {
            self.echoes.clear();
            self.reset();
            self.packet_event(TIOCPKT_FLUSHWRITE | TIOCPKT_FLUSHREAD, 0);
        }
        if self.input(IXON) {
            self.start();
        }
        if self.local(ECHO) {
            self.echo_char(c);
        }
    }
    /// Notes `set` (clearing `clear`) for a master in packet mode, which
    /// wakes it, as `pty_stop`, `pty_start`, `pty_flush_buffer`,
    /// `n_tty_packet_mode_flush` and `pty_set_termios` do.
    fn packet_event(&mut self, set: u8, clear: u8) {
        if self.packet {
            self.pktstatus = self.pktstatus & !clear | set;
            self.edge(MASTER_IN);
        }
    }
    /// `stop_tty`.
    fn stop(&mut self) {
        if !self.flow.stopped {
            self.flow.stopped = true;
            self.packet_event(TIOCPKT_STOP, TIOCPKT_START);
        }
    }
    /// `start_tty`: the held echoes go out.
    fn start(&mut self) {
        if !self.flow.stopped || self.flow.tco {
            return;
        }
        self.flow.stopped = false;
        self.packet_event(TIOCPKT_START, TIOCPKT_STOP);
        self.flush_echoes();
        self.edge(SLAVE_OUT);
        self.wakeup(SLAVE);
    }
    /// The cells from `at` (a count, as `head`) to the head, which go.
    fn cut(&mut self, at: u64) -> Vec<u8> {
        let keep = (at - self.tail) as usize;
        let cut = self.read.split_off(keep);
        self.head = at;
        cut.into_iter().map(|cell| cell.byte).collect()
    }
    fn byte_at(&self, at: u64) -> u8 {
        self.read[(at - self.tail) as usize].byte
    }
    /// Linux's `eraser`: `VERASE` takes a character back, `VWERASE` a
    /// word and `VKILL` the line, echoed as `ECHOE`, `ECHOK`, `ECHOKE`,
    /// `ECHOPRT` and `ECHOCTL` say.
    fn eraser(&mut self, c: u8) {
        #[derive(PartialEq)]
        enum Kind {
            Erase,
            Word,
            Kill,
        }
        if self.head == self.canon_head {
            return;
        }
        let kind = if c == self.cc(VERASE) {
            Kind::Erase
        } else if c == self.cc(VWERASE) {
            Kind::Word
        } else {
            if !self.local(ECHO) {
                self.cut(self.canon_head);
                return;
            }
            if !self.local(ECHOK) || !self.local(ECHOKE) || !self.local(ECHOE) {
                self.cut(self.canon_head);
                self.finish_erasing();
                self.echo_char(self.cc(VKILL));
                if self.local(ECHOK) {
                    self.echo_raw(b'\n');
                }
                return;
            }
            Kind::Kill
        };
        let mut alphanumerics = 0;
        while self.head != self.canon_head {
            let mut at = self.head;
            let mut ch;
            loop {
                at -= 1;
                ch = self.byte_at(at);
                if !(self.continuation(ch) && at != self.canon_head) {
                    break;
                }
            }
            if self.continuation(ch) {
                break;
            }
            if kind == Kind::Word {
                if is_alphanumeric(ch) || ch == b'_' {
                    alphanumerics += 1;
                } else if alphanumerics > 0 {
                    break;
                }
            }
            let erased = self.cut(at);
            if self.local(ECHO) {
                if self.local(ECHOPRT) {
                    if !self.erasing {
                        self.echo_raw(b'\\');
                        self.erasing = true;
                    }
                    self.echo_char(ch);
                    for &byte in &erased[1..] {
                        self.echo_raw(byte);
                        self.column = self.column.saturating_sub(1);
                    }
                } else if kind == Kind::Erase && !self.local(ECHOE) {
                    self.echo_char(self.cc(VERASE));
                } else if ch == b'\t' {
                    let (mut columns, mut after_tab) = (0, false);
                    let mut back = self.head;
                    while back != self.canon_head {
                        back -= 1;
                        let c = self.byte_at(back);
                        if c == b'\t' {
                            after_tab = true;
                            break;
                        } else if is_control(c) {
                            if self.local(ECHOCTL) {
                                columns += 2;
                            }
                        } else if !self.continuation(c) {
                            columns += 1;
                        }
                    }
                    self.erase_tab(columns, after_tab);
                } else {
                    // Linux's two tests: a control character takes two
                    // columns with ECHOCTL, and none without.
                    let times = match (is_control(ch), self.local(ECHOCTL)) {
                        (true, true) => 2,
                        (true, false) => 0,
                        (false, _) => 1,
                    };
                    for _ in 0..times {
                        for byte in *b"\x08 \x08" {
                            self.echo_raw(byte);
                        }
                    }
                }
            }
            if kind == Kind::Erase {
                break;
            }
        }
        if self.head == self.canon_head && self.local(ECHO) {
            self.finish_erasing();
        }
    }

    // Reading the slave and the master.

    /// `input_available_p`: in canonical mode a whole line, otherwise
    /// a byte, or for `poll` `VMIN` of them when `VTIME` is 0.
    fn input_available(&self, poll: bool) -> bool {
        if self.canonical() {
            return self.canon_head > self.tail;
        }
        let (min, time) = (self.cc(VMIN), self.cc(VTIME));
        let amount = if poll && time == 0 && min != 0 {
            u64::from(min)
        } else {
            1
        };
        self.head - self.tail >= amount
    }
    /// `canon_copy_from_read_buf`: up to the end of the first line, whose
    /// end of file is not read.
    fn read_line(&mut self, out: &mut [u8]) -> usize {
        let available = (self.canon_head - self.tail) as usize;
        let n = out.len().min(available);
        let end = self.read.iter().take(n).position(|cell| cell.end);
        let (copied, taken) = match end {
            Some(end) if self.read[end].byte == 0 => (end, end + 1),
            Some(end) => (end + 1, end + 1),
            None => (n, n),
        };
        for (slot, cell) in out.iter_mut().zip(self.read.drain(..taken)).take(copied) {
            *slot = cell.byte;
        }
        self.tail += taken as u64;
        if end.is_some() {
            self.pushed = false;
        }
        copied
    }
    /// `copy_from_read_buf`: what there is, up to `out`'s length.
    fn read_raw(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.read.len());
        for (slot, cell) in out.iter_mut().zip(self.read.drain(..n)) {
            *slot = cell.byte;
        }
        self.tail += n as u64;
        n
    }
    /// After a read: the room it made takes more of the pending input.
    /// A read that leaves little in the buffer wakes the master's writers,
    /// as `n_tty_check_unthrottle` does before the flip buffer refills it.
    fn after_read(&mut self, signals: &mut Signals) {
        let low = self.chars_in_buffer() <= UNTHROTTLE;
        self.receive(signals);
        self.edge(MASTER_OUT);
        if low {
            self.wakeup(MASTER);
        }
    }
    /// `TIOCINQ` of the slave: the bytes of whole lines without their ends
    /// of file in canonical mode, else all.
    fn unread(&self) -> usize {
        if !self.canonical() {
            return self.read.len();
        }
        self.read
            .iter()
            .take(self.canon_head.saturating_sub(self.tail) as usize)
            .filter(|cell| !(cell.end && cell.byte == 0))
            .count()
    }
    /// `n_tty_set_termios`: changing `ICANON` makes what the buffer holds
    /// one line, or no lines.
    fn set_termios(&mut self, termios: Termios) {
        let old = self.termios;
        self.termios = termios;
        // `pty_set_termios`: whether ^S and ^Q now stop and start output.
        let flow = |t: &Termios| t.iflag & IXON != 0 && t.cc[VSTOP] == 0o23 && t.cc[VSTART] == 0o21;
        let extproc = (old.lflag | termios.lflag) & EXTPROC != 0;
        if flow(&old) != flow(&termios) || extproc {
            let mut set = 0;
            let mut clear = 0;
            if flow(&old) != flow(&termios) {
                clear = TIOCPKT_DOSTOP | TIOCPKT_NOSTOP;
                set = if flow(&termios) {
                    TIOCPKT_DOSTOP
                } else {
                    TIOCPKT_NOSTOP
                };
            }
            if extproc {
                set |= TIOCPKT_IOCTL;
            }
            self.packet_event(set, clear);
        }
        if (old.lflag ^ termios.lflag) & (ICANON | EXTPROC) != 0 {
            for cell in &mut self.read {
                cell.end = false;
            }
            if !self.canonical() || self.read.is_empty() {
                self.canon_head = self.tail;
                self.pushed = false;
            } else {
                if let Some(last) = self.read.back_mut() {
                    last.end = true;
                }
                self.canon_head = self.head;
                self.pushed = true;
            }
            self.erasing = false;
            self.lnext = false;
            self.edge(SLAVE_IN);
        }
        if !self.input(IXON) && old.iflag & IXON != 0 && !self.flow.tco {
            self.start();
        }
    }
}

/// One devpts instance: the pairs by number.
#[derive(Default)]
pub(crate) struct Devpts {
    terminals: Mutex<BTreeMap<u32, Weak<Terminal>>>,
    /// Linux's `redirect`: the terminal file `TIOCCONS` gave the console's
    /// output, which it holds open until its terminal hangs up.
    redirect: Mutex<Option<Arc<dyn FileHandle>>>,
}
impl Devpts {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<u32, Weak<Terminal>>> {
        self.terminals
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
    /// A new pair with the lowest free number (`ENOSPC` past
    /// `kernel.pty.max`), its slave owned by `uid` and locked.
    fn create(
        self: &Arc<Self>,
        hub: &Arc<ReadinessHub>,
        processes: &Arc<Processes>,
        uid: u32,
    ) -> Result<Arc<Terminal>, Errno> {
        let mut terminals = self.lock();
        terminals.retain(|_, terminal| terminal.strong_count() != 0);
        if terminals.len() >= PTY_MAX {
            return Err(ENOSPC);
        }
        let index = (0..).find(|n| !terminals.contains_key(n)).unwrap_or(0);
        let terminal = Arc::new(Terminal {
            index,
            hub: Arc::clone(hub),
            processes: Arc::downgrade(processes),
            devpts: Arc::downgrade(self),
            state: Mutex::new(State::new(uid)),
        });
        terminals.insert(index, Arc::downgrade(&terminal));
        Ok(terminal)
    }
    /// The pair `/dev/pts/<index>` names: one whose master is open.
    pub(crate) fn named(&self, index: u32) -> Option<Arc<Terminal>> {
        let terminal = self.lock().get(&index)?.upgrade()?;
        let named = terminal.lock().master;
        named.then_some(terminal)
    }
    /// `/dev/pts`'s entries: `.`, `..` (`/dev`, inode `parent`), the
    /// slaves by number, and `ptmx`.
    pub(crate) fn entries(&self, parent: u64) -> Vec<DirectoryEntry> {
        const DT_CHR: u8 = 2;
        const DT_DIR: u8 = 4;
        let indexes: Vec<u32> = self.lock().keys().copied().collect();
        let mut entries = vec![
            DirectoryEntry {
                name: b".".to_vec(),
                inode: 1,
                kind: DT_DIR,
            },
            DirectoryEntry {
                name: b"..".to_vec(),
                inode: parent,
                kind: DT_DIR,
            },
        ];
        for index in indexes {
            if self.named(index).is_some() {
                entries.push(DirectoryEntry {
                    name: index.to_string().into_bytes(),
                    inode: u64::from(index) + 3,
                    kind: DT_CHR,
                });
            }
        }
        entries.push(DirectoryEntry {
            name: b"ptmx".to_vec(),
            inode: 2,
            kind: DT_CHR,
        });
        entries
    }
}

/// A pseudo-terminal pair.
pub(crate) struct Terminal {
    index: u32,
    hub: Arc<ReadinessHub>,
    processes: Weak<Processes>,
    devpts: Weak<Devpts>,
    state: Mutex<State>,
}
impl Terminal {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// Wakes the terminal's waiters, and sends the signals its `O_ASYNC`
    /// descriptions are owed, each to the owner of its description.
    fn changed(&self) {
        self.hub.changed();
        let notices: Vec<_> = {
            let mut state = self.lock();
            let io = std::mem::take(&mut state.io);
            io.into_iter()
                .flat_map(|(side, reason)| {
                    state.fasync[side]
                        .iter()
                        .map(move |(file, to)| (file.clone(), to.clone(), reason))
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        if notices.is_empty() {
            return;
        }
        let Some(processes) = self.processes.upgrade() else {
            return;
        };
        for (file, to, reason) in notices {
            if let Some(file) = file.upgrade() {
                let owner = processes.file_owner(&file);
                Notice { to, owner, reason }.send();
            }
        }
    }
    /// Takes `side`'s `fasync` list away, its descriptions' `O_ASYNC` with
    /// it, as `__tty_hangup` calls `__tty_fasync(-1, filp, 0)` for each.
    /// Returns the descriptions, for the caller to let go of once the state
    /// is unlocked, as the last of one closes it, which locks the state.
    fn drop_fasync(state: &mut State, which: usize) -> Vec<Arc<dyn FileHandle>> {
        state.write_wakeup[which] = false;
        let files: Vec<_> = std::mem::take(&mut state.fasync[which])
            .into_iter()
            .filter_map(|(file, _)| file.upgrade())
            .collect();
        for file in &files {
            let flags = match side(file) {
                Some(Side::Master(master)) => &master.flags,
                Some(Side::Slave(slave)) => &slave.flags,
                None => continue,
            };
            flags.fetch_and(!O_ASYNC, Ordering::SeqCst);
        }
        files
    }
    /// `tty_vhangup` of the slave, as the master's close and `TIOCVHANGUP`
    /// make it: every description of the slave open now is hung up and
    /// loses `O_ASYNC`, the line discipline flushes and goes until the next
    /// open, the `termios` is the driver's again (`TTY_DRIVER_RESET_TERMIOS`),
    /// the packet events go, and the session the terminal controls loses it,
    /// its leader told with SIGHUP and SIGCONT. A `TIOCCONS` redirect to the
    /// slave ends.
    fn hang_up(self: &Arc<Self>) {
        let released = {
            let mut state = self.lock();
            state.hangups += 1;
            let released = Self::drop_fasync(&mut state, SLAVE);
            state.reset();
            state.echoes.clear();
            state.ldisc_down = true;
            state.termios = Termios::SLAVE;
            state.pktstatus = 0;
            for edge in [SLAVE_IN, SLAVE_OUT, MASTER_OUT] {
                state.edge(edge);
            }
            released
        };
        drop(released);
        // The redirect goes after the lock, as dropping it may close a slave.
        let redirect = self.devpts.upgrade().and_then(|devpts| {
            let mut redirect = devpts
                .redirect
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let ours = redirect
                .as_ref()
                .and_then(side)
                .is_some_and(|side| Arc::ptr_eq(side.terminal(), self));
            if ours { redirect.take() } else { None }
        });
        drop(redirect);
        self.changed();
        if let Some(processes) = self.processes.upgrade() {
            processes.hang_up_terminal(self);
        }
    }
    /// `tty_vhangup` of the master: its file is hung up and loses
    /// `O_ASYNC`, and the master's line discipline flushes what it holds of
    /// the slave's output, and the slave's input not taken yet
    /// (`pty_flush_buffer`), and goes.
    fn hang_up_master(&self) {
        let released = {
            let mut state = self.lock();
            state.master_hung_up = true;
            state.output.clear();
            state.pending.clear();
            for edge in [MASTER_IN, MASTER_OUT, SLAVE_OUT] {
                state.edge(edge);
            }
            Self::drop_fasync(&mut state, MASTER)
        };
        drop(released);
        self.changed();
    }
    /// The session this terminal controls (`tty->ctrl.session`).
    pub(crate) fn session(&self) -> Option<u32> {
        self.lock().session
    }
    /// The foreground process group (`tty->ctrl.pgrp`).
    pub(crate) fn foreground(&self) -> Option<u32> {
        self.lock().pgrp
    }
    /// `__proc_set_tty`: the terminal controls `session`, with `pgrp` in
    /// the foreground.
    pub(crate) fn control(&self, session: u32, pgrp: u32) {
        let mut state = self.lock();
        state.session = Some(session);
        state.pgrp = Some(pgrp);
    }
    /// The terminal controls no session any more.
    pub(crate) fn release(&self) {
        let mut state = self.lock();
        state.session = None;
        state.pgrp = None;
    }
    /// Sends the line discipline's signals, from the kernel.
    fn deliver(&self, signals: Signals) {
        if signals.is_empty() {
            return;
        }
        if let Some(processes) = self.processes.upgrade() {
            for (pgrp, signal) in signals {
                processes.signal_group(pgrp, signal, None);
            }
        }
    }
    /// The slave's `stat`.
    fn slave_stat(&self) -> FileStat {
        let state = self.lock();
        FileStat {
            inode: u64::from(self.index) + 3,
            mode: 0o020_000 | state.mode,
            uid: state.uid,
            gid: state.gid,
            links: 1,
            rdev: encode_device(SLAVE_MAJOR, u64::from(self.index)),
            ..FileStat::default()
        }
    }
}

/// Linux's `huge_encode_dev`, as `stat` gives `st_rdev`.
fn encode_device(major: u64, minor: u64) -> u64 {
    (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
}

/// `/dev/pts`'s `stat`.
pub(crate) fn directory_stat() -> FileStat {
    FileStat {
        inode: 1,
        mode: 0o040_755,
        links: 2,
        ..FileStat::default()
    }
}
/// `/dev/ptmx`'s `stat`, or with `devpts` that of `/dev/pts/ptmx`, whose
/// mode is devpts's default `ptmxmode` of 0.
pub(crate) fn ptmx_stat(devpts: bool) -> FileStat {
    FileStat {
        inode: 2,
        mode: if devpts { 0o020_000 } else { 0o020_666 },
        links: 1,
        rdev: encode_device(TTYAUX_MAJOR, 2),
        ..FileStat::default()
    }
}
/// The `stat` of `/dev/pts/<index>`, or `ENOENT` when no open master has
/// that number.
pub(crate) fn slave_stat(c: &Context<'_>, index: u32) -> Result<FileStat, Errno> {
    Ok(c.files
        .devpts
        .named(index)
        .ok_or(Errno::ENOENT)?
        .slave_stat())
}

/// An open file description of a master.
pub(crate) struct Master {
    terminal: Arc<Terminal>,
    flags: AtomicU32,
}
impl Drop for Master {
    /// `pty_close` of the master: the slave hangs up, its name goes, and
    /// the session it controls loses it, its leader told with SIGHUP.
    fn drop(&mut self) {
        self.terminal.lock().master = false;
        self.terminal.hang_up();
    }
}
/// An open file description of a slave, or of `/dev/tty` (`alias`).
pub(crate) struct Slave {
    terminal: Arc<Terminal>,
    flags: AtomicU32,
    /// The hang-ups before its open: one since hangs it up.
    generation: u64,
    alias: bool,
}
impl Drop for Slave {
    fn drop(&mut self) {
        {
            let mut state = self.terminal.lock();
            state.slaves -= 1;
            if state.slaves == 0 {
                state.other_closed = true;
                state.edge(MASTER_IN);
            }
        }
        self.terminal.changed();
    }
}
impl Slave {
    fn hung_up(&self, state: &State) -> bool {
        self.generation < state.hangups
    }
}

/// Opens `/dev/ptmx`: a new pair, whose locked slave's number `TIOCGPTN`
/// gives.
pub(crate) fn open_master(c: &mut Context<'_>, flags: u32) -> Result<Arc<dyn FileHandle>, Errno> {
    let terminal =
        c.files
            .devpts
            .create(&c.files.readiness, c.processes, c.process.credentials.fsuid)?;
    Ok(Arc::new(Master {
        terminal,
        flags: AtomicU32::new(flags & (3 | NONBLOCK)),
    }))
}

/// Opens the slave of `terminal`, as Linux's `tty_open` and `pty_open`: not
/// while it is locked or its master closed (`EIO`), nor, for a user without
/// `CAP_SYS_ADMIN`, while `TIOCEXCL` holds it (`EBUSY`). A session leader
/// without a controlling terminal that opens it for reading without
/// `O_NOCTTY` gets it as its own; `alias` opens it as `/dev/tty`, which
/// never does that.
fn open_slave(
    c: &mut Context<'_>,
    terminal: &Arc<Terminal>,
    flags: u32,
    alias: bool,
) -> Result<Arc<Slave>, Errno> {
    let (generation, signals) = {
        let mut state = terminal.lock();
        if state.exclusive && !c.process.credentials.may_administer() {
            return Err(EBUSY);
        }
        if state.locked || !state.master {
            return Err(EIO);
        }
        state.slaves += 1;
        state.other_closed = false;
        // Input waiting for room, if any, goes on. After a hang-up the line
        // discipline comes back, and what waits goes with the master's next
        // write, as Linux's `tty_reopen` does not push the flip buffer.
        let mut signals = Vec::new();
        if state.ldisc_down {
            state.ldisc_down = false;
        } else {
            state.receive(&mut signals);
        }
        (state.hangups, signals)
    };
    terminal.deliver(signals);
    let slave = Arc::new(Slave {
        terminal: Arc::clone(terminal),
        flags: AtomicU32::new(flags & (3 | NONBLOCK)),
        generation,
        alias,
    });
    terminal.changed();
    if flags & O_NOCTTY == 0 && !alias && flags & 3 != 1 {
        c.processes.open_terminal(c.process.pid, terminal);
    }
    Ok(slave)
}

/// Opens `/dev/pts/<index>` (`ENOENT` when no open master has the number).
pub(crate) fn open_named(
    c: &mut Context<'_>,
    index: u32,
    flags: u32,
) -> Result<Arc<dyn FileHandle>, Errno> {
    let terminal = c.files.devpts.named(index).ok_or(Errno::ENOENT)?;
    Ok(open_slave(c, &terminal, flags, false)?)
}

/// Opens `/dev/tty`: the controlling terminal, when it is a pseudo-terminal
/// here. `None` for a process of the session outside the emulator that has
/// none, whose `/dev/tty` is the host's; `ENXIO` for one in a session of its
/// own without one.
pub(crate) fn open_controlling(
    c: &mut Context<'_>,
    flags: u32,
) -> Option<Result<Arc<dyn FileHandle>, Errno>> {
    match c.processes.terminal(c.process.pid) {
        Some(terminal) => {
            Some(open_slave(c, &terminal, flags, true).map(|slave| slave as Arc<dyn FileHandle>))
        }
        None => match c.processes.group_and_session(c.process.pid) {
            Ok((_, 0)) => None,
            _ => Some(Err(Errno(6))),
        },
    }
}

/// What `file` is, if it is a pseudo-terminal's.
#[derive(Clone, Copy)]
enum Side<'a> {
    Master(&'a Master),
    Slave(&'a Slave),
}
fn side(file: &Arc<dyn FileHandle>) -> Option<Side<'_>> {
    let any = file.as_any()?;
    if let Some(master) = any.downcast_ref::<Master>() {
        Some(Side::Master(master))
    } else {
        any.downcast_ref::<Slave>().map(Side::Slave)
    }
}
impl Side<'_> {
    fn terminal(&self) -> &Arc<Terminal> {
        match self {
            Side::Master(master) => &master.terminal,
            Side::Slave(slave) => &slave.terminal,
        }
    }
    fn flags(&self) -> u32 {
        match self {
            Side::Master(master) => master.flags.load(Ordering::SeqCst),
            Side::Slave(slave) => slave.flags.load(Ordering::SeqCst),
        }
    }
}

/// Whether `file` is a pseudo-terminal's, which has `fasync`.
pub(crate) fn is_terminal(file: &Arc<dyn FileHandle>) -> bool {
    side(file).is_some()
}

/// Whether `file` is a pseudo-terminal's that is hung up, whose
/// `hung_up_tty_fasync` refuses `O_ASYNC` with `ENOTTY`.
pub(crate) fn hung_up(file: &Arc<dyn FileHandle>) -> bool {
    match side(file) {
        Some(Side::Slave(slave)) => slave.hung_up(&slave.terminal.lock()),
        Some(Side::Master(master)) => master.terminal.lock().master_hung_up,
        None => false,
    }
}

/// `__tty_fasync`: `F_SETFL` turning `O_ASYNC` of a terminal's `file` on,
/// with its registration, or off. Turning it on gives a file without an
/// owner one: the foreground process group of the slave, or else the
/// calling process, as `__f_setown` without `force`.
pub(crate) fn set_async(
    c: &Context<'_>,
    file: &Arc<dyn FileHandle>,
    registration: Option<Registration>,
) {
    let Some(side) = side(file) else { return };
    let terminal = side.terminal();
    let which = if matches!(side, Side::Master(_)) {
        MASTER
    } else {
        SLAVE
    };
    let foreground = {
        let mut state = terminal.lock();
        let list = &mut state.fasync[which];
        list.retain(|(entry, _)| {
            entry.strong_count() != 0 && !std::ptr::addr_eq(entry.as_ptr(), Arc::as_ptr(file))
        });
        let Some(registration) = registration else {
            return;
        };
        list.insert(0, (Arc::downgrade(file), registration));
        if which == SLAVE { state.pgrp } else { None }
    };
    let owner = c.processes.file_owner(file);
    if owner.id == 0 {
        let (kind, id) = match foreground {
            Some(pgrp) => (OwnerKind::Group, pgrp),
            None => (OwnerKind::Process, c.process.pid),
        };
        c.processes
            .set_file_owner(file, FileOwner { kind, id, ..owner });
    }
}

/// Whether `file` is a slave, whose file system is devpts.
pub(crate) fn is_slave(file: &Arc<dyn FileHandle>) -> bool {
    matches!(side(file), Some(Side::Slave(slave)) if !slave.alias)
}

/// The monotonic time, in nanoseconds.
fn now(c: &Context<'_>) -> Result<u64, Errno> {
    c.host.clock(paludarium_host::ClockId::Monotonic)
}

/// Linux's `__tty_check_change` for the calling process and `terminal`: a
/// process of a background group of the session the terminal controls
/// gets `EIO` for a `signal` it ignores or blocks (unless it is SIGTTOU,
/// which then lets it go on) or when its group is orphaned; otherwise its
/// group gets `signal` and the call ends with `EINTR`, which restarts it.
fn check_change(c: &mut Context<'_>, terminal: &Arc<Terminal>, signal: i32) -> Result<(), Errno> {
    let pid = c.process.pid;
    if !c
        .processes
        .terminal(pid)
        .is_some_and(|own| Arc::ptr_eq(&own, terminal))
    {
        return Ok(());
    }
    let Some(foreground) = terminal.foreground() else {
        return Ok(());
    };
    let (pgid, _) = c.processes.group_and_session(pid)?;
    if foreground == pgid {
        return Ok(());
    }
    let blocked = c.process.signal_mask & (1 << (signal - 1)) != 0;
    let ignored = c
        .group
        .shared_actions()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&signal)
        .is_some_and(|action| action.handler == 1);
    if blocked || ignored {
        return if signal == SIGTTIN { Err(EIO) } else { Ok(()) };
    }
    if c.processes.group_orphaned(pgid) {
        return Err(EIO);
    }
    c.processes.signal_group(pgid, signal, None);
    Err(EINTR)
}

/// Waits for the terminal to change, until `deadline`.
fn wait(c: &mut Context<'_>, ticket: u32, deadline: Option<u64>) -> Result<(), Errno> {
    crate::events::wait(c, ticket, deadline)
}

/// `read` of a pseudo-terminal's file; `None` for any other file.
pub(crate) fn read(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    out: &mut [u8],
) -> Option<Result<usize, Errno>> {
    Some(match side(file)? {
        Side::Master(master) => read_master(c, master, out),
        Side::Slave(slave) => read_slave(c, slave, out),
    })
}

/// The master reads what there is, waiting for a byte; once every slave
/// description has closed and nothing is left, `EIO`.
fn read_master(c: &mut Context<'_>, master: &Master, out: &mut [u8]) -> Result<usize, Errno> {
    if out.is_empty() {
        return Ok(0);
    }
    let terminal = &master.terminal;
    loop {
        let ticket = terminal.hub.token.value();
        match master.read_once(out) {
            Err(e) if e == Errno::EAGAIN && master.flags.load(Ordering::SeqCst) & NONBLOCK == 0 => {
                wait(c, ticket, None)?;
            }
            result => return result,
        }
    }
}
impl Master {
    fn read_once(&self, out: &mut [u8]) -> Result<usize, Errno> {
        let terminal = &self.terminal;
        let mut state = terminal.lock();
        // `hung_up_tty_read`.
        if state.master_hung_up {
            return Ok(0);
        }
        // In packet mode the events come first, a byte alone; data comes
        // after a 0 byte (`TIOCPKT_DATA`), as Linux's `n_tty_read`.
        if state.packet && state.pktstatus != 0 {
            out[0] = std::mem::take(&mut state.pktstatus);
            return Ok(1);
        }
        if !state.output.is_empty() {
            let (head, rest) = if state.packet {
                let (head, rest) = out.split_at_mut(1);
                head[0] = 0;
                (1, rest)
            } else {
                (0, out)
            };
            let n = rest.len().min(state.output.len());
            // What the master's line discipline held, a buffer's worth of it.
            let held = state.output.len().min(BUFFER);
            for (slot, byte) in rest.iter_mut().zip(state.output.drain(..n)) {
                *slot = byte;
            }
            state.edge(SLAVE_OUT);
            // `n_tty_check_unthrottle` of the master: a read that leaves
            // little of that wakes the slave's writers.
            if held.saturating_sub(n) as u64 <= UNTHROTTLE {
                state.wakeup(SLAVE);
            }
            drop(state);
            terminal.changed();
            return Ok(head + n);
        }
        if state.other_closed {
            return Err(EIO);
        }
        Err(Errno::EAGAIN)
    }
    fn write_once(&self, bytes: &[u8]) -> Result<usize, Errno> {
        let terminal = &self.terminal;
        let mut signals = Vec::new();
        let count = {
            let mut state = terminal.lock();
            if state.master_hung_up {
                return Err(EIO);
            }
            let count = if state.master_flow.stopped {
                0
            } else {
                bytes.len().min(FLIP.saturating_sub(state.pending.len()))
            };
            state.pending.extend(&bytes[..count]);
            state.receive(&mut signals);
            count
        };
        if count > 0 {
            terminal.changed();
        }
        terminal.deliver(signals);
        if count == 0 && !bytes.is_empty() {
            return Err(Errno::EAGAIN);
        }
        Ok(count)
    }
}

/// The slave reads as its line discipline says: in canonical mode a line,
/// otherwise as `VMIN` and `VTIME` say. A process of a background group
/// gets SIGTTIN, and a hung-up slave reads nothing.
fn read_slave(c: &mut Context<'_>, slave: &Slave, out: &mut [u8]) -> Result<usize, Errno> {
    let terminal = &slave.terminal;
    if slave.hung_up(&terminal.lock()) {
        return Ok(0);
    }
    check_change(c, terminal, SIGTTIN)?;
    if out.is_empty() {
        return Ok(0);
    }
    let started = now(c)?;
    let mut got = 0;
    let mut deadline = None;
    loop {
        let ticket = terminal.hub.token.value();
        let mut signals = Vec::new();
        // Whether this pass took input, which wakes the master's writers.
        let mut took = false;
        let (done, min, time) = {
            let mut state = terminal.lock();
            let (min, time) = (state.cc(VMIN), state.cc(VTIME));
            let done = if slave.hung_up(&state) {
                Some(got)
            } else if state.canonical() {
                state.input_available(false).then(|| {
                    let n = state.read_line(&mut out[got..]);
                    state.after_read(&mut signals);
                    took = true;
                    got + n
                })
            } else {
                if !state.read.is_empty() {
                    got += state.read_raw(&mut out[got..]);
                    state.after_read(&mut signals);
                    took = true;
                    if min > 0 && time > 0 {
                        deadline = None;
                    }
                }
                let minimum = usize::from(min.max(1)).min(out.len());
                (got >= minimum || (min == 0 && time == 0)).then_some(got)
            };
            (done, min, time)
        };
        if took {
            terminal.changed();
        }
        terminal.deliver(signals);
        if let Some(count) = done {
            return Ok(count);
        }
        if slave.flags.load(Ordering::SeqCst) & NONBLOCK != 0 {
            return if got > 0 { Ok(got) } else { Err(Errno::EAGAIN) };
        }
        let tenths = u64::from(time) * 100_000_000;
        if time > 0 && deadline.is_none() && (min == 0 || got > 0) {
            deadline = Some(if min == 0 { started } else { now(c)? } + tenths);
        }
        if deadline.is_some_and(|deadline| now(c).is_ok_and(|now| now >= deadline)) {
            return Ok(got);
        }
        if let Err(e) = wait(c, ticket, deadline) {
            return if got > 0 { Ok(got) } else { Err(e) };
        }
    }
}
impl Slave {
    /// One read that does not wait: `EAGAIN` for nothing yet.
    fn read_once(&self, out: &mut [u8]) -> Result<usize, Errno> {
        let terminal = &self.terminal;
        let mut signals = Vec::new();
        let result = {
            let mut state = terminal.lock();
            if self.hung_up(&state) || out.is_empty() {
                Ok(0)
            } else if state.canonical() {
                if state.input_available(false) {
                    let n = state.read_line(out);
                    state.after_read(&mut signals);
                    Ok(n)
                } else {
                    Err(Errno::EAGAIN)
                }
            } else if !state.read.is_empty() {
                let n = state.read_raw(out);
                state.after_read(&mut signals);
                Ok(n)
            } else if state.cc(VMIN) == 0 && state.cc(VTIME) == 0 {
                Ok(0)
            } else {
                Err(Errno::EAGAIN)
            }
        };
        if result.as_ref().is_ok_and(|&n| n > 0) {
            terminal.changed();
        }
        terminal.deliver(signals);
        result
    }
    fn write_once(&self, bytes: &[u8]) -> Result<usize, Errno> {
        let count = {
            let mut state = self.terminal.lock();
            if self.hung_up(&state) {
                return Err(EIO);
            }
            state.write_output(bytes)
        };
        if count > 0 {
            self.terminal.changed();
        }
        if count == 0 && !bytes.is_empty() {
            return Err(Errno::EAGAIN);
        }
        Ok(count)
    }
}

/// `write` to a pseudo-terminal's file, which goes on until all is written
/// unless the file does not block; `None` for any other file.
pub(crate) fn write(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    bytes: &[u8],
) -> Option<Result<u64, Errno>> {
    let side = side(file)?;
    let terminal = Arc::clone(side.terminal());
    if matches!(side, Side::Master(_)) && terminal.lock().master_hung_up {
        return Some(Err(EIO));
    }
    if let Side::Slave(slave) = side {
        let (hung_up, tostop) = {
            let state = terminal.lock();
            (slave.hung_up(&state), state.local(TOSTOP))
        };
        if hung_up {
            return Some(Err(EIO));
        }
        if tostop && let Err(e) = check_change(c, &terminal, SIGTTOU) {
            return Some(Err(e));
        }
    }
    let mut done = 0;
    let result = loop {
        let ticket = terminal.hub.token.value();
        let result = match side {
            Side::Master(master) => master.write_once(&bytes[done..]),
            Side::Slave(slave) => slave.write_once(&bytes[done..]),
        };
        match result {
            Ok(count) => {
                done += count;
                if done == bytes.len() {
                    break Ok(done as u64);
                }
            }
            Err(e) if e == Errno::EAGAIN => {}
            Err(e) => break if done > 0 { Ok(done as u64) } else { Err(e) },
        }
        if side.flags() & NONBLOCK != 0 {
            break if done > 0 {
                Ok(done as u64)
            } else {
                Err(Errno::EAGAIN)
            };
        }
        if let Err(e) = wait(c, ticket, None) {
            break if done > 0 { Ok(done as u64) } else { Err(e) };
        }
    };
    // `n_tty_write`: a write left short, with `O_ASYNC` descriptions,
    // signals `POLL_OUT` when room comes (`TTY_DO_WRITE_WAKEUP`).
    if done < bytes.len() {
        let which = if matches!(side, Side::Master(_)) {
            MASTER
        } else {
            SLAVE
        };
        let mut state = terminal.lock();
        if !state.fasync[which].is_empty() {
            state.write_wakeup[which] = true;
        }
    }
    Some(result)
}

fn read_int(c: &Context<'_>, address: u64) -> Result<i32, Errno> {
    let mut bytes = [0; 4];
    c.mem
        .read(GuestAddr(address), &mut bytes)
        .map_err(|_| Errno::EFAULT)?;
    Ok(i32::from_le_bytes(bytes))
}
fn write_bytes(c: &Context<'_>, address: u64, bytes: &[u8]) -> Result<u64, Errno> {
    c.mem
        .write(GuestAddr(address), bytes)
        .map_err(|_| Errno::EFAULT)?;
    Ok(0)
}

/// `ioctl` of a pseudo-terminal's file; `None` for any other file.
pub(crate) fn ioctl(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    request: u64,
    arg: u64,
) -> Option<Result<u64, Errno>> {
    let side = side(file)?;
    let result = terminal_ioctl(c, file, &side, request as u32, arg);
    // A call job control stopped runs again, as Linux's ERESTARTSYS.
    if result == Err(EINTR) {
        c.process.restart = Some(16);
    }
    Some(result)
}

fn terminal_ioctl(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    side: &Side<'_>,
    request: u32,
    arg: u64,
) -> Result<u64, Errno> {
    const TCGETS: u32 = 0x5401;
    const TCSETS: u32 = 0x5402;
    const TCSETSW: u32 = 0x5403;
    const TCSETSF: u32 = 0x5404;
    const TCSBRK: u32 = 0x5409;
    const TCXONC: u32 = 0x540a;
    const TCFLSH: u32 = 0x540b;
    const TIOCEXCL: u32 = 0x540c;
    const TIOCNXCL: u32 = 0x540d;
    const TIOCSCTTY: u32 = 0x540e;
    const TIOCGPGRP: u32 = 0x540f;
    const TIOCSPGRP: u32 = 0x5410;
    const TIOCOUTQ: u32 = 0x5411;
    const TIOCSTI: u32 = 0x5412;
    const TIOCGWINSZ: u32 = 0x5413;
    const TIOCSWINSZ: u32 = 0x5414;
    const FIONREAD: u32 = 0x541b;
    const TIOCNOTTY: u32 = 0x5422;
    const TIOCSETD: u32 = 0x5423;
    const TIOCGETD: u32 = 0x5424;
    const TCSBRKP: u32 = 0x5425;
    const TIOCSBRK: u32 = 0x5427;
    const TIOCCBRK: u32 = 0x5428;
    const TIOCGSID: u32 = 0x5429;
    const TCGETS2: u32 = 0x802c_542a;
    const TCSETS2: u32 = 0x402c_542b;
    const TCSETSW2: u32 = 0x402c_542c;
    const TCSETSF2: u32 = 0x402c_542d;
    const TIOCGPTN: u32 = 0x8004_5430;
    const TIOCSPTLCK: u32 = 0x4004_5431;
    const TIOCGDEV: u32 = 0x8004_5432;
    const TIOCSIG: u32 = 0x4004_5436;
    const TIOCGPTLCK: u32 = 0x8004_5439;
    const TIOCGEXCL: u32 = 0x8004_5440;
    const TIOCGPTPEER: u32 = 0x5441;
    const TCGETA: u32 = 0x5405;
    const TCSETA: u32 = 0x5406;
    const TCSETAW: u32 = 0x5407;
    const TCSETAF: u32 = 0x5408;
    const TIOCPKT: u32 = 0x5420;
    const TIOCGPKT: u32 = 0x8004_5438;
    const TIOCGLCKTRMIOS: u32 = 0x5456;
    const TIOCSLCKTRMIOS: u32 = 0x5457;
    const TIOCCONS: u32 = 0x541d;
    const TIOCVHANGUP: u32 = 0x5437;
    let terminal = Arc::clone(side.terminal());
    let master = matches!(side, Side::Master(_));
    // A hung-up file answers only these (`hung_up_tty_ioctl`).
    let hung_up = match side {
        Side::Slave(slave) => slave.hung_up(&terminal.lock()),
        Side::Master(_) => terminal.lock().master_hung_up,
    };
    if hung_up {
        return Err(if request == TIOCSPGRP {
            Errno::ENOTTY
        } else {
            EIO
        });
    }
    // Whether the calling process is controlled by this terminal.
    let controlled = |c: &Context<'_>| {
        c.processes
            .terminal(c.process.pid)
            .is_some_and(|own| Arc::ptr_eq(&own, &terminal))
    };
    let admin = c.process.credentials.may_administer();
    match request {
        // `tty_vhangup` of this side.
        TIOCVHANGUP => {
            if !admin {
                return Err(Errno::EPERM);
            }
            if master {
                terminal.hang_up_master();
            } else {
                terminal.hang_up();
            }
            Ok(0)
        }
        // `tioccons`: the console's output goes to this slave, which must
        // be open for writing, while no other terminal has it.
        TIOCCONS => {
            if master {
                return Err(Errno::EINVAL);
            }
            if !admin {
                return Err(Errno::EPERM);
            }
            if side.flags() & 3 == 0 {
                return Err(Errno::EBADF);
            }
            let devpts = &c.files.devpts;
            let mut redirect = devpts
                .redirect
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if redirect.is_some() {
                return Err(EBUSY);
            }
            *redirect = Some(Arc::clone(file));
            Ok(0)
        }
        TCGETS | TCGETS2 => {
            let bytes = terminal.lock().termios.encode(request == TCGETS2);
            write_bytes(c, arg, &bytes)
        }
        TCGETA => write_bytes(c, arg, &terminal.lock().termios.termio()),
        TCSETS | TCSETSW | TCSETSF | TCSETS2 | TCSETSW2 | TCSETSF2 | TCSETA | TCSETAW | TCSETAF => {
            check_change(c, &terminal, SIGTTOU)?;
            let termio = matches!(request, TCSETA | TCSETAW | TCSETAF);
            let long = request >= TCSETS2;
            let mut bytes = vec![
                0;
                if termio {
                    18
                } else if long {
                    44
                } else {
                    36
                }
            ];
            c.mem
                .read(GuestAddr(arg), &mut bytes)
                .map_err(|_| Errno::EFAULT)?;
            let mut signals = Vec::new();
            {
                let mut state = terminal.lock();
                if matches!(request, TCSETSF | TCSETSF2 | TCSETAF) {
                    state.reset();
                    state.packet_event(TIOCPKT_FLUSHREAD, 0);
                    state.receive(&mut signals);
                }
                if termio {
                    bytes = state.termios.with_termio(&bytes);
                }
                let termios = state.termios.decoded(&bytes, &state.locked_termios);
                state.set_termios(termios);
            }
            terminal.changed();
            terminal.deliver(signals);
            Ok(0)
        }
        TIOCGWINSZ => {
            let window = terminal.lock().window;
            let bytes: Vec<u8> = window.iter().flat_map(|v| v.to_le_bytes()).collect();
            write_bytes(c, arg, &bytes)
        }
        TIOCSWINSZ => {
            let mut bytes = [0; 8];
            c.mem
                .read(GuestAddr(arg), &mut bytes)
                .map_err(|_| Errno::EFAULT)?;
            let window = [0, 2, 4, 6].map(|i| u16::from_le_bytes([bytes[i], bytes[i + 1]]));
            let foreground = {
                let mut state = terminal.lock();
                if state.window == window {
                    return Ok(0);
                }
                state.window = window;
                state.pgrp
            };
            if let Some(pgrp) = foreground {
                terminal.deliver(vec![(pgrp, SIGWINCH)]);
            }
            Ok(0)
        }
        TIOCGPGRP => {
            if !master && !controlled(c) {
                return Err(Errno::ENOTTY);
            }
            let pgrp = terminal.foreground().unwrap_or(0);
            write_bytes(c, arg, &pgrp.to_le_bytes())
        }
        TIOCSPGRP => {
            match check_change(c, &terminal, SIGTTOU) {
                Err(e) if e == EIO => return Err(Errno::ENOTTY),
                result => result?,
            }
            let pgrp = read_int(c, arg)?;
            let (_, session) = c.processes.group_and_session(c.process.pid)?;
            if !controlled(c) || terminal.session() != Some(session) {
                return Err(Errno::ENOTTY);
            }
            if pgrp < 0 {
                return Err(Errno::EINVAL);
            }
            // No process has ID 0 (Linux's find_vpid(0)), though a group
            // outside the emulator is shown as 0.
            if pgrp == 0 {
                return Err(ESRCH);
            }
            let pgrp = pgrp.cast_unsigned();
            match c.processes.session_of_group(pgrp) {
                None => Err(ESRCH),
                Some(other) if other != session => Err(Errno::EPERM),
                Some(_) => {
                    terminal.lock().pgrp = Some(pgrp);
                    Ok(0)
                }
            }
        }
        TIOCGSID => {
            if !master && !controlled(c) {
                return Err(Errno::ENOTTY);
            }
            let session = terminal.session().ok_or(Errno::ENOTTY)?;
            write_bytes(c, arg, &session.to_le_bytes())
        }
        TIOCSCTTY => {
            let readable = side.flags() & 3 != 1;
            c.processes
                .set_terminal(c.process.pid, &terminal, arg == 1, readable, admin)
                .map(|()| 0)
        }
        TIOCNOTTY => {
            if master || !controlled(c) {
                return Err(Errno::ENOTTY);
            }
            c.processes
                .leave_terminal(c.process.pid, &terminal)
                .map(|()| 0)
        }
        // The slave's, whichever side asks (`tty_mode_ioctl`'s `real_tty`).
        TIOCGLCKTRMIOS => {
            let bytes = terminal.lock().locked_termios.encode(false);
            write_bytes(c, arg, &bytes)
        }
        TIOCSLCKTRMIOS => {
            if !admin {
                return Err(Errno::EPERM);
            }
            let mut bytes = [0; 36];
            c.mem
                .read(GuestAddr(arg), &mut bytes)
                .map_err(|_| Errno::EFAULT)?;
            let mut state = terminal.lock();
            let locked = state.locked_termios;
            let mut new = locked;
            let word =
                |i: usize| u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
            (new.iflag, new.oflag, new.cflag, new.lflag) = (word(0), word(4), word(8), word(12));
            new.line = bytes[16];
            new.cc.copy_from_slice(&bytes[17..36]);
            state.locked_termios = new;
            Ok(0)
        }
        // `pty_set_pktmode`: turning it on forgets the events so far.
        TIOCPKT if master => {
            let on = read_int(c, arg)? != 0;
            let mut state = terminal.lock();
            if on && !state.packet {
                state.pktstatus = 0;
            }
            state.packet = on;
            Ok(0)
        }
        TIOCGPKT if master => {
            let on = i32::from(terminal.lock().packet);
            write_bytes(c, arg, &on.to_le_bytes())
        }
        TIOCGPTN if master => write_bytes(c, arg, &terminal.index.to_le_bytes()),
        TIOCSPTLCK if master => {
            let locked = read_int(c, arg)? != 0;
            terminal.lock().locked = locked;
            Ok(0)
        }
        TIOCGPTLCK if master => {
            let locked = i32::from(terminal.lock().locked);
            write_bytes(c, arg, &locked.to_le_bytes())
        }
        TIOCSIG if master => {
            let signal = arg as i32;
            if ![SIGINT, SIGQUIT, SIGTSTP].contains(&signal) {
                return Err(Errno::EINVAL);
            }
            if let Some(pgrp) = terminal.foreground() {
                terminal.deliver(vec![(pgrp, signal)]);
            }
            Ok(0)
        }
        TIOCGPTPEER => {
            if !master {
                return Err(EIO);
            }
            let flags = arg as u32;
            let fd = c.files.reserve(c.group.nofile())?;
            match open_slave(c, &terminal, flags, false) {
                Ok(slave) => {
                    let path = format!("/dev/pts/{}", terminal.index).into_bytes();
                    c.files.fill_opened(fd, slave, path, flags & 0x80000 != 0);
                    Ok(u64::from(fd))
                }
                Err(e) => {
                    c.files.unreserve(fd);
                    Err(e)
                }
            }
        }
        TIOCGDEV => {
            let device = terminal.device();
            write_bytes(c, arg, &device.to_le_bytes())
        }
        TIOCEXCL | TIOCNXCL => {
            terminal.lock().exclusive = request == TIOCEXCL;
            Ok(0)
        }
        TIOCGEXCL => {
            let exclusive = i32::from(terminal.lock().exclusive);
            write_bytes(c, arg, &exclusive.to_le_bytes())
        }
        TIOCGETD => write_bytes(c, arg, &0i32.to_le_bytes()),
        TIOCSETD => {
            check_change(c, &terminal, SIGTTOU)?;
            match read_int(c, arg)? {
                0 => Ok(0),
                _ => Err(Errno::EINVAL),
            }
        }
        // A pseudo-terminal sends no break and has nothing to drain.
        TCSBRK | TCSBRKP | TIOCSBRK | TIOCCBRK => {
            check_change(c, &terminal, SIGTTOU)?;
            Ok(0)
        }
        TCXONC => {
            check_change(c, &terminal, SIGTTOU)?;
            let mut signals = Vec::new();
            {
                let mut state = terminal.lock();
                let tco = if master {
                    state.master_flow.tco
                } else {
                    state.flow.tco
                };
                match arg {
                    // TCOOFF, TCOON: only what TCOOFF stopped starts again.
                    0 if !tco => {
                        if master {
                            state.master_flow = Flow {
                                stopped: true,
                                tco: true,
                            };
                        } else {
                            state.flow.tco = true;
                            state.stop();
                        }
                    }
                    1 if tco => {
                        if master {
                            state.master_flow = Flow::default();
                            state.wakeup(MASTER);
                        } else {
                            state.flow.tco = false;
                            state.start();
                        }
                    }
                    0 | 1 => {}
                    // TCIOFF, TCION: the STOP or START character goes to
                    // the other side.
                    2 | 3 => {
                        let index = if arg == 2 { VSTOP } else { VSTART };
                        let ch = if master {
                            Termios::MASTER_CC[index]
                        } else {
                            state.cc(index)
                        };
                        if ch != 0 {
                            if master {
                                state.pending.push_back(ch);
                                state.receive(&mut signals);
                            } else {
                                state.output.push_back(ch);
                                state.edge(MASTER_IN);
                                state.kill_fasync(MASTER, Reason::In);
                            }
                        }
                    }
                    _ => return Err(Errno::EINVAL),
                }
                state.edge(SLAVE_OUT);
                state.edge(MASTER_OUT);
            }
            terminal.changed();
            terminal.deliver(signals);
            Ok(0)
        }
        TCFLSH => {
            check_change(c, &terminal, SIGTTOU)?;
            if arg > 2 {
                return Err(Errno::EINVAL);
            }
            {
                let mut state = terminal.lock();
                let (input, output) = (arg != 1, arg != 0);
                // The input of the master is the slave's output; the output
                // of the master is the slave's pending input.
                if master {
                    if input {
                        state.output.clear();
                    }
                    if output {
                        state.pending.clear();
                    }
                } else {
                    if input {
                        state.pending.clear();
                        state.reset();
                        state.packet_event(TIOCPKT_FLUSHREAD, 0);
                    }
                    if output {
                        state.packet_event(TIOCPKT_FLUSHWRITE, 0);
                    }
                }
                for edge in [SLAVE_OUT, MASTER_OUT] {
                    state.edge(edge);
                }
            }
            terminal.changed();
            Ok(0)
        }
        FIONREAD => {
            let count = {
                let state = terminal.lock();
                if master {
                    state.output.len()
                } else {
                    state.unread()
                }
            };
            write_bytes(c, arg, &(count as i32).to_le_bytes())
        }
        TIOCOUTQ => write_bytes(c, arg, &0i32.to_le_bytes()),
        // As with `dev.tty.legacy_tiocsti` off: only CAP_SYS_ADMIN pushes
        // input.
        TIOCSTI => {
            if !admin {
                return Err(EIO);
            }
            let mut byte = [0];
            c.mem
                .read(GuestAddr(arg), &mut byte)
                .map_err(|_| Errno::EFAULT)?;
            let mut signals = Vec::new();
            {
                let mut state = terminal.lock();
                if master {
                    state.output.push_back(byte[0]);
                    state.edge(MASTER_IN);
                    state.kill_fasync(MASTER, Reason::In);
                } else {
                    state.receive_char(byte[0], &mut signals);
                    state.received();
                    state.flush_echoes();
                }
            }
            terminal.changed();
            terminal.deliver(signals);
            Ok(0)
        }
        _ => Err(Errno::ENOTTY),
    }
}

/// `vhangup`: with CAP_SYS_TTY_CONFIG (else `EPERM`), the calling process's
/// controlling terminal hangs up, as `TIOCVHANGUP` of its slave
/// (`tty_vhangup_self`); without one it does nothing.
pub(crate) fn sys_vhangup(c: &mut Context<'_>, _: [u64; 6]) -> crate::syscalls::Outcome {
    if !c.process.credentials.may_configure_terminals() {
        return crate::syscalls::err(Errno::EPERM);
    }
    if let Some(terminal) = c.processes.terminal(c.process.pid) {
        terminal.hang_up();
    }
    crate::syscalls::ok(0)
}

/// `tty_nr` and `tpgid` of `/proc/<pid>/stat` for a process controlled by
/// `terminal`: the slave's device and its foreground group (0 for none);
/// 0 and -1 for no terminal.
pub(crate) fn stat_fields(terminal: Option<&Terminal>) -> (u32, i32) {
    terminal.map_or((0, -1), |t| {
        (t.device(), t.foreground().map_or(0, u32::cast_signed))
    })
}
impl Terminal {
    /// The slave's device number, `new_encode_dev` as `TIOCGDEV` gives it.
    fn device(&self) -> u32 {
        encode_new(SLAVE_MAJOR as u32, self.index)
    }
}
/// Linux's `new_encode_dev`, as `TIOCGDEV` gives it.
fn encode_new(major: u32, minor: u32) -> u32 {
    (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
}

impl FileHandle for Master {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, out: &mut [u8]) -> Result<usize, Errno> {
        if out.is_empty() {
            return Ok(0);
        }
        self.read_once(out)
    }
    fn write(&self, bytes: &[u8]) -> Result<usize, Errno> {
        self.write_once(bytes)
    }
    /// `n_tty_poll` of the master: readable with the slave's output,
    /// writable while its flip buffer has room, and hung up once every
    /// slave description has closed.
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        let state = self.terminal.lock();
        if state.master_hung_up {
            let edges = (state.edges[MASTER_IN], state.edges[MASTER_OUT]);
            return Ok((IN | OUT | 0x8 | 0x10 | 0x40 | 0x100, edges.0, edges.1));
        }
        let mut mask = 0;
        if !state.output.is_empty() {
            mask |= IN | 0x40;
        }
        if state.packet && state.pktstatus != 0 {
            mask |= IN | PRI | 0x40;
        }
        if state.other_closed {
            mask |= 0x10;
        }
        if !state.master_flow.stopped && state.pending.len() < FLIP {
            mask |= OUT | 0x100;
        }
        Ok((mask, state.edges[MASTER_IN], state.edges[MASTER_OUT]))
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Err(Errno(29))
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(ptmx_stat(false))
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
    fn flags(&self) -> u32 {
        self.flags.load(Ordering::SeqCst)
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        let access = self.flags() & 3;
        self.flags
            .store(access | (flags & !3 & !0x80000), Ordering::SeqCst);
        Ok(())
    }
}

impl FileHandle for Slave {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, out: &mut [u8]) -> Result<usize, Errno> {
        self.read_once(out)
    }
    fn write(&self, bytes: &[u8]) -> Result<usize, Errno> {
        self.write_once(bytes)
    }
    /// `n_tty_poll` of the slave, or `hung_up_tty_poll` once it is hung up.
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        let state = self.terminal.lock();
        let edges = (state.edges[SLAVE_IN], state.edges[SLAVE_OUT]);
        if self.hung_up(&state) {
            return Ok((IN | OUT | 0x8 | 0x10 | 0x40 | 0x100, edges.0, edges.1));
        }
        let mut mask = 0;
        if state.input_available(true) {
            mask |= IN | 0x40;
        }
        if !state.flow.stopped && state.output.len() < OUTPUT_LIMIT {
            mask |= OUT | 0x100;
        }
        Ok((mask, edges.0, edges.1))
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Err(Errno(29))
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        if self.alias {
            return Ok(FileStat {
                inode: 4,
                mode: 0o020_666,
                links: 1,
                rdev: encode_device(TTYAUX_MAJOR, 0),
                ..FileStat::default()
            });
        }
        Ok(self.terminal.slave_stat())
    }
    fn set_mode(&self, mode: u32) -> Result<(), Errno> {
        self.terminal.lock().mode = mode & 0o7777;
        Ok(())
    }
    fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) -> Result<(), Errno> {
        let mut state = self.terminal.lock();
        state.uid = uid.unwrap_or(state.uid);
        state.gid = gid.unwrap_or(state.gid);
        Ok(())
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
    fn flags(&self) -> u32 {
        self.flags.load(Ordering::SeqCst)
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        let access = self.flags() & 3;
        self.flags
            .store(access | (flags & !3 & !0x80000), Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> State {
        let mut state = State::new(0);
        state.slaves = 1;
        state
    }
    fn type_in(state: &mut State, bytes: &[u8]) -> Signals {
        let mut signals = Vec::new();
        state.pending.extend(bytes);
        state.receive(&mut signals);
        signals
    }
    fn echoed(state: &mut State) -> Vec<u8> {
        state.output.drain(..).collect()
    }
    fn line(state: &mut State) -> Vec<u8> {
        let mut out = [0; 64];
        let n = state.read_line(&mut out);
        out[..n].to_vec()
    }

    #[test]
    fn a_canonical_line_is_echoed_and_read_whole() {
        let mut state = state();
        type_in(&mut state, b"ab\rcd");
        assert_eq!(echoed(&mut state), b"ab\r\ncd");
        assert!(!state.input_available(false) || state.canon_head > state.tail);
        assert_eq!(line(&mut state), b"ab\n");
        assert!(!state.input_available(false));
        type_in(&mut state, b"\x04");
        assert_eq!(line(&mut state), b"cd");
        type_in(&mut state, b"\x04");
        assert!(state.input_available(false));
        assert_eq!(line(&mut state), b"");
    }

    #[test]
    fn erase_kill_and_word_erase() {
        let mut state = state();
        type_in(&mut state, b"abc\x7f");
        assert_eq!(echoed(&mut state), b"abc\x08 \x08");
        type_in(&mut state, b"\x15");
        assert_eq!(echoed(&mut state), b"\x08 \x08\x08 \x08");
        type_in(&mut state, b"one two\x17x\n");
        assert_eq!(line(&mut state), b"one x\n");
        echoed(&mut state);
        type_in(&mut state, b"\x01\x7f\n");
        assert_eq!(echoed(&mut state)[..2], *b"^A");
        assert_eq!(line(&mut state), b"\n");
    }

    #[test]
    fn interrupt_signals_and_flushes() {
        let mut state = state();
        state.pgrp = Some(7);
        let signals = type_in(&mut state, b"abc\x03d\n");
        assert_eq!(signals, [(7, SIGINT)]);
        assert_eq!(line(&mut state), b"d\n");
        // The echoes of the same input before the signal character go.
        assert_eq!(echoed(&mut state), b"^Cd\r\n");
    }

    #[test]
    fn raw_mode_takes_bytes_as_they_come() {
        let mut state = state();
        let mut raw = state.termios;
        raw.lflag = 0;
        raw.iflag = 0;
        state.set_termios(raw);
        type_in(&mut state, b"a\r\x03");
        assert!(echoed(&mut state).is_empty());
        let mut out = [0; 8];
        assert_eq!(state.read_raw(&mut out), 3);
        assert_eq!(&out[..3], b"a\r\x03");
    }

    #[test]
    fn switching_to_canonical_makes_one_line() {
        let mut state = state();
        let canonical = state.termios;
        let mut raw = canonical;
        raw.lflag &= !ICANON;
        state.set_termios(raw);
        type_in(&mut state, b"x\ny");
        state.set_termios(canonical);
        assert_eq!(line(&mut state), b"x\ny");
    }

    #[test]
    fn stop_holds_output_until_start() {
        let mut state = state();
        type_in(&mut state, b"\x13a");
        assert_eq!(state.write_output(b"out"), 0);
        assert!(echoed(&mut state).is_empty());
        type_in(&mut state, b"\x11");
        assert_eq!(echoed(&mut state), b"a");
        assert_eq!(state.write_output(b"o\n"), 2);
        assert_eq!(echoed(&mut state), b"o\r\n");
    }

    #[test]
    fn output_processing() {
        let mut state = state();
        state.termios.oflag |= XTABS | OLCUC;
        assert_eq!(state.write_output(b"ab\tc\n"), 5);
        assert_eq!(echoed(&mut state), b"AB      C\r\n");
    }

    #[test]
    fn termio_and_locked_termios() {
        let termios = Termios::SLAVE;
        let termio = termios.termio();
        assert_eq!(termio[0..2], (ICRNL as u16 | IXON as u16).to_le_bytes());
        assert_eq!(termio[9..17], termios.cc[..8]);
        let mut changed = termio;
        changed[6..8].copy_from_slice(&0u16.to_le_bytes());
        changed[9] = 1;
        let mut high = termios;
        high.lflag |= EXTPROC;
        high.cc[VEOL2] = 7;
        let set = high.decoded(&high.with_termio(&changed), &Termios::ZERO);
        assert_eq!((set.lflag, set.cc[VINTR], set.cc[VEOL2]), (EXTPROC, 1, 7));
        // What is locked stays: ECHO, the line and VINTR.
        let mut locked = Termios::ZERO;
        locked.lflag = ECHO;
        locked.line = 1;
        locked.cc[VINTR] = 1;
        let mut bytes = termios.encode(false);
        bytes[12..16].copy_from_slice(&0u32.to_le_bytes());
        bytes[16] = 5;
        bytes[17] = 9;
        bytes[17 + VQUIT] = 9;
        let set = termios.decoded(&bytes, &locked);
        assert_eq!((set.lflag, set.line), (ECHO, 0));
        assert_eq!((set.cc[VINTR], set.cc[VQUIT]), (3, 9));
        // A locked CBAUD keeps B38400 in cflag; the speeds follow B9600.
        let mut speed = Termios::ZERO;
        speed.cflag = CBAUD;
        let mut bytes = termios.encode(false);
        bytes[8..12].copy_from_slice(&(0o15 | CS8 | CREAD).to_le_bytes());
        let set = termios.decoded(&bytes, &speed);
        assert_eq!(
            (set.cflag & CBAUD, set.ospeed, set.ispeed),
            (B38400, 9600, 9600)
        );
    }

    #[test]
    fn packet_events() {
        let mut state = State::new(0);
        state.stop();
        assert_eq!(state.pktstatus, 0);
        state.start();
        state.packet = true;
        state.stop();
        state.stop();
        assert_eq!(state.pktstatus, TIOCPKT_STOP);
        state.start();
        assert_eq!(state.pktstatus, TIOCPKT_START);
        let mut termios = state.termios;
        termios.iflag &= !IXON;
        state.set_termios(termios);
        assert_eq!(state.pktstatus, TIOCPKT_START | TIOCPKT_NOSTOP);
        termios.lflag |= EXTPROC;
        state.pktstatus = 0;
        state.set_termios(termios);
        assert_eq!(state.pktstatus, TIOCPKT_IOCTL);
    }

    /// A description in `side`'s `fasync` list, which the test keeps alive.
    fn listen(state: &mut State, side: usize) -> Arc<dyn FileHandle> {
        let [file, _] = crate::sockets::PipeEnd::pair(0, Arc::default()).unwrap();
        let file: Arc<dyn FileHandle> = file;
        let registration = Registration {
            processes: Weak::new(),
            fd: 3,
        };
        state.fasync[side].push((Arc::downgrade(&file), registration));
        file
    }

    #[test]
    fn async_input_signals_lines_or_bytes() {
        let mut state = state();
        // Nothing listens: nothing is owed.
        type_in(&mut state, b"a\n");
        assert!(state.io.is_empty());
        state.reset();
        let _slave = listen(&mut state, SLAVE);
        let _master = listen(&mut state, MASTER);
        // Canonical: only the end of a line; its echo reaches the master.
        type_in(&mut state, b"ab");
        assert_eq!(state.io, [(MASTER, Reason::In)]);
        state.io.clear();
        type_in(&mut state, b"\n\x04");
        assert_eq!(state.io, [(SLAVE, Reason::In), (MASTER, Reason::In)]);
        state.io.clear();
        // Raw: any byte, and no echo.
        let mut termios = state.termios;
        termios.lflag = 0;
        state.set_termios(termios);
        type_in(&mut state, b"xy");
        assert_eq!(state.io, [(SLAVE, Reason::In)]);
        state.io.clear();
        // The line discipline gone, input waits.
        state.ldisc_down = true;
        type_in(&mut state, b"z");
        assert!(state.io.is_empty());
        assert_eq!(state.pending.len(), 1);
    }

    #[test]
    fn room_signals_only_a_short_writer() {
        let mut state = state();
        let _master = listen(&mut state, MASTER);
        let _slave = listen(&mut state, SLAVE);
        let mut termios = state.termios;
        termios.lflag = 0;
        state.set_termios(termios);
        type_in(&mut state, &[b'q'; 400]);
        state.io.clear();
        let mut signals = Vec::new();
        state.after_read(&mut signals);
        assert!(state.io.is_empty());
        // A short write, then a read that leaves little: one POLL_OUT.
        state.write_wakeup[MASTER] = true;
        let mut out = [0; 200];
        state.read_raw(&mut out);
        state.after_read(&mut signals);
        assert!(state.io.is_empty(), "200 bytes left are over the threshold");
        state.read_raw(&mut out);
        state.after_read(&mut signals);
        assert_eq!(state.io, [(MASTER, Reason::Out)]);
        assert!(!state.write_wakeup[MASTER]);
        state.io.clear();
        // The slave's start is room for its writers.
        state.write_wakeup[SLAVE] = true;
        state.stop();
        state.start();
        assert_eq!(state.io, [(SLAVE, Reason::Out)]);
    }

    #[test]
    fn termios_speeds_and_fixed_control_flags() {
        let termios = Termios::SLAVE;
        let mut bytes = termios.encode(false);
        // B9600 with parity and 7 bits.
        bytes[8..12].copy_from_slice(&(0o15u32 | 0o400 | 0o40).to_le_bytes());
        let set = termios.decoded(&bytes, &Termios::ZERO);
        assert_eq!((set.ispeed, set.ospeed), (9600, 9600));
        assert_eq!(set.cflag, 0o15 | CS8 | CREAD);
        assert_eq!(termios.encode(true).len(), 44);
    }
}
