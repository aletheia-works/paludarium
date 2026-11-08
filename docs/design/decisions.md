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
missing page or a permission violation becomes a guest exception. A small
cache of the private pages used last (a software TLB of 64 entries) lets the
next access to one of them skip the page table, still checking its
protection; it is emptied whenever a mapping or a page entry may change.

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
to an executable page moves the code generation on after its bytes, so whoever
sees the new generation sees the new code.

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
