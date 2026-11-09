# Design decisions

The main decisions made while building paludarium, and why.

## Using existing components

External crates and tools are welcome, after checking that their licence is
compatible with Apache-2.0. Anything with copyright or licence concerns, or
with bugs or a poor fit, is written in-house for that part. Dependencies come
from crates.io only, and `cargo deny` checks them.

No code is copied from other emulators. blink and others are references for
behaviour and design only. The blink derivatives whose history contained
malware (`lanmower/blink` and its line) are never referenced or depended on.

## Wrapping an existing decoder

The first plan was to write the decoder too. When the policy on external
components was revised, [iced-x86](https://github.com/icedland/iced) (MIT) was
chosen instead. `paludarium-decoder` wraps it and shows only its own
instruction types to other crates, so the decoder can be replaced, or partly
rewritten, without touching anything else.

## A software MMU

WebAssembly (wasm32) memory stops at 4 GB, so a guest's 64-bit address space
cannot be placed in it directly. paludarium therefore uses a software MMU with
two-level page tables of 4 KiB pages on every host. Every access is checked; a
missing page or a permission violation becomes a guest exception. A cache
of the private pages used last (a software TLB of 1024 entries) lets the
next access to one of them skip the page table, still checking its
protection; it is emptied whenever a mapping or a page entry may change.

An entry holds the bytes of its page's frame, but not the frame's charge to
the session's memory meter (`memory.current`), which the page tables and
shared memory hold. A thread empties its TLB only at its next access, so a
thread that is waiting may hold the bytes of pages that are gone; they no
longer count, and new frames find the room at once. Only a frame that had no
bytes when the TLB took it is held whole, as another space sharing it may
give it bytes without this space's lock.

Each guest thread has a TLB of its own. Its loads, stores and instruction
fetches, and its locked instructions within one 8-byte word, take no lock
when the TLB holds the page, so threads do not wait for each other. The TLB
is valid while the address space keeps the epoch it was filled at. The epoch
moves on whenever a mapping or a page entry may change, and every access
compares it. A store says which epoch it is under while it is under way, and
moving the epoch on waits until no store is under the old one. Then, as with
Linux's TLB shootdown, no other thread writes through the old page after
`mprotect` or `fork` returns. The wait is usually for one store per thread,
but a store that spans words first waits its turn behind the others to the
same page (below), so it can last as long as that queue.

The pages of a private file mapping go in the TLB too: the file's page-cache
pages, which the mapping shows until it writes them, and the copies it has
made. Their file can shrink without the address space's lock, by `ftruncate`
from any process, so an access through the TLB to one of them also checks
that the page is not wholly past the end of the file, which raises SIGBUS,
and, for a copy, that the file has not shrunk since the TLB took it, after
which Linux may have dropped the copy. Otherwise it takes the locks, which do
both. Each access checks both itself, so the order in which a truncation
changes them does not matter: an access that saw neither change comes before
the truncation, as one under way while it ran, and a copy that the truncation
leaves past the end is replaced at the next access under the locks, so a
store that landed in it is never seen. No access that starts after the
truncation returns uses the page. Under the locks, an access checks the end
of the file again after it has brought the page entry up to date, as a
truncation may come between the two. The page cache gives the new size, and
zeros past it, before it counts the shrink, and a copy of a page-cache page
records the count read before it copies. So an entry that records the new
count was made after the new size could be seen, and a copy that took bytes
from before the shrink records an older count, and goes if the page is past
the end.

The pages of a shared mapping (`MAP_SHARED` memory or file, System V shared
memory) go in the TLB too, with the memory they show. A store through the
TLB does what one under the locks does: it moves the memory's generation on
before and after its bytes, and marks the page dirty in between, so that a
write-back, which marks a page clean before it reads it, either hands over
the store or leaves the page dirty for the next one. Other processes that
share the memory already stored to it without this space's lock, so taking
none here changes nothing they can see. A store to a shared mapping that
another space may run code from moves that space's code generation on, as
before.

A TLB entry holds neither the file nor the memory's owner, only the file's
size and count of shrinks, which the file keeps apart for this, and the
memory's generation. Holding the file would keep it open after `munmap`
until the thread's next access, and System V shared memory counts its
attachments (`shm_nattch`) by who holds them.

A locked instruction within one word is one compare-and-swap of the word, so
it stays atomic against the stores that take no lock, and it is a full fence.
A split lock across two words, or `CMPXCHG16B`, takes the locks and first
moves the epoch on, which waits for the stores under way and sends the next
ones to the locks. Until it ends, only loads run without a lock, and a load
that spans the words may see one of them written before the other, except an
aligned 16-byte load (below).

A guest's threads see each other's memory in the order x86 gives (TSO): a
thread's loads and stores stay in order, except that a load may pass an earlier
store. The page contents are read with acquire and written with release
ordering, which keeps that order on an Arm host too, without the lock. A write
to an executable page that an instruction was fetched from moves the code
generation on after its bytes, so whoever sees the new generation sees the new
code. The first fetch from a page marks it under the locks after moving the
epoch on, so a store through the TLB only loads the mark: either it sees the
mark, or the fetch sees its bytes.

An aligned load of 16 bytes (`MOVDQA`, for one) is one access on an x86-64
CPU, so it sees a `CMPXCHG16B` or a 16-byte store of another thread whole.
The emulator keeps page contents as 8-byte words, and a load takes no lock, so
each page counts the writes of more than one word it has started and finished.
Such a load reads its two words again while one of them may have come between
them; other loads and writes pay nothing for it. The counts also make such
writes to a page take turns, as stores take no lock: two 16-byte stores never
leave the low word of one with the high word of the other.

## Owning the waiting primitives

`futex`, `epoll`, `eventfd` and `timerfd` are implemented in paludarium's
kernel instead of with the host's equivalents. macOS and Windows have no Linux
`futex`, and in WebAssembly the only way to wait is `Atomics.wait` and
`notify`. The host provides only the smallest tools: wait, wake, and sleep with
a deadline. The price is care with races in the wait queues.

## Separating the CPU and the kernel

The CPU stops at a system call or an exception and returns the reason; it does
not know the kernel. The kernel owns the thread state. Each can then be tested
alone, and the JIT and the interpreter are easy to swap.

## Separating the kernel and the filesystem

The filesystem is separate from the kernel so that the guarantee "a guest
cannot leave the given directory" can be checked in `paludarium-vfs` alone, and
fuzzed with a narrow target. Host directories are reached only relative to a
directory capability opened when the Session is created (with cap-std on
native hosts).

## Threads in WebAssembly

This was one of the biggest uncertainties, so it was tried at small scale in
the first stage: two Workers sharing memory used `memory.atomic.wait32` and
`notify` successfully on Node.js, Chromium, Firefox and the real Safari before
the real work started.

- The JavaScript launcher creates the Workers: WebAssembly cannot create
  Workers itself, the main thread cannot wait, and the launcher can stop them
  all at once.
- In WebKit, the launcher grows the shared memory to its maximum of 1 GiB
  before any guest runs. There, growing a shared memory while other threads run
  in it sometimes makes them fail with "Out of bounds memory access" or crashes
  the page: 13 of 2,700 runs of a test program that grows its memory while
  threads start and end, against none of 2,700 with the memory grown
  beforehand. The allocator gets more memory only by growing it, so the
  launcher allocates the heap and frees it at once. It does not write to these
  blocks, so on macOS their pages take no physical memory until used. Other
  browsers grow the memory as needed, since on Windows, and in Firefox on
  Linux, a grown memory counts against the system's commit limit at once.
  WebKit browsers are told apart by their user agent: `AppleWebKit/` without
  `Chrome/`, which includes every browser on iOS. The crash is reported as
  [WebKit bug 330591](https://bugs.webkit.org/show_bug.cgi?id=330591), with a
  reproduction that needs no paludarium; once it is fixed, WebKit may not need
  this.
- A finished Worker waits for the next thread, and only ends with the launcher.
  In WebKit, a Worker with an instance of a shared memory ending while another
  thread grows that memory crashes the page.
- To share the whole emulator (the Rust heap and std) between Workers, std is
  rebuilt with atomics and every Worker gets its own stack and TLS.

## The JIT as a separate component

The JIT is a component of its own, next to the interpreter. A setting turns it
on or off, and the same tests compare both. Instruction semantics then live in
two places, the CPU and the JIT, so differential tests keep them equal.

Rust translates blocks into WebAssembly bytes; the JavaScript in the guest's
Worker compiles and runs them. Generated code keeps the MMU's permission and
range checks, and translations of rewritten pages are discarded.

## One way to create a filesystem

A snapshot is passed back to `createFileSystem` as its `entries` rather than to
a separate restore call, so it combines with `files`, and `run()` accepts it the
same way. Modification times are kept, because programs such as aube decide
whether their state is fresh by them. Inode numbers are not kept, only which
paths share one. A hard link may name a symlink, as on Linux, so every state a
guest can create can be rebuilt; a hard link to a directory is rejected.

## Three entry points

A library, a command and a WebAssembly package give each kind of user a fitting
entry point, and the command serves the differential tests. The price is more
interfaces to keep compatible.

## Explicit CPU differences

When a `REP` instruction faults midway, Intel and AMD leave different flags.
paludarium does not inspect the host CPU to choose; it models the behaviour
explicitly, following Intel's design by default. `CPUID` names AMD for glibc's
sake ([Features](../guide/features)), and that name does not change this.

## A relay for the browser's network

A browser cannot open TCP connections or resolve names, so its guests reach
the network through a WebSocket relay. Each connection and each lookup is a
WebSocket of its own: nothing is multiplexed, so neither side keeps state
between them and each connection's flow control is its own. The relay
resolves the names, and signs each address it gives with a ticket, because
the guest then connects to the address and the relay, perhaps another
instance, must know which allowed name it came from. The kernel's allow list
still decides first; the relay keeps its own, since anything in a page is
public.

## The guest's own loopback

A guest may run its own TCP and UDP servers, but only for its own sockets:
a connection from a guest socket to a loopback address where a guest socket
listens is joined in the kernel, two in-memory streams like the host's, and
a datagram goes straight to the socket that takes it; neither reaches the
host. Serving the host or other machines would let a
guest open ports on the user's machine, which the allow list does not
govern, so it is left out. The allow list does not govern the guest's own
loopback either, as nothing leaves the guest; a loopback port where no guest
socket listens is refused, as Linux's loopback is, unless the list allows
the host's.

## Trusted Publishing only

Releases go to crates.io and npm by Trusted Publishing (OIDC) only, with no
long-lived token stored anywhere, and npm packages carry provenance. Published
versions cannot be deleted, so a problem is handled with a crates.io yank or an
npm deprecation and a fixed release.
