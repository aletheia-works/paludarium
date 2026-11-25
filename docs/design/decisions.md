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
  rebuilt with atomics, and every run and guest thread gets a stack and TLS of
  its own, freed when it ends; an idle Worker takes the next thread's.

## The JIT as a separate component

The JIT is a component of its own, next to the interpreter. A setting turns it
on or off, and the same tests compare both. Instruction semantics then live in
two places, the CPU and the JIT, so differential tests keep them equal.

Rust translates blocks into WebAssembly bytes; the JavaScript in the guest's
Worker compiles and runs them. Generated code keeps the MMU's permission and
range checks, and translations of rewritten pages are discarded.

## A native JIT with Cranelift

Native builds get a JIT of their own rather than the WebAssembly one, which
needs a JavaScript engine to compile its output. It compiles with Cranelift,
a code generator written in Rust that compiles a small function in tens to
hundreds of microseconds, rather than with LLVM, which is far slower to
compile with and is not a Rust library. It compiles the forms the
interpreter already works out when it decodes, not instructions of its own,
so each instruction it compiles has one meaning, the interpreter's, which
unit tests from random states, a fuzz target and the differential tests
([most with every block compiled](./quality#the-native-jit)) check.

It is a crate of its own because it needs `unsafe`, to map code and call it, and
every other crate but the host's forbids it. Compiling happens on a thread of
its own while the interpreter goes on, because compiling on the thread that runs
the block made short programs, which run many blocks only a few hundred times,
up to twice as slow. It compiles with Cranelift's `none` level, at a block's
300th entry. `speed` made faster code but cost more to compile. With a threshold
of 100 that made programs of 0.1–0.25 s up to 12% slower than without the JIT,
because they compiled dozens of blocks they then ran too few times. In one run
of the speed check below (fork run 44116579985), `none` at 300 cut the cases the
JIT made slower from 14 to 3. It kept most of the long programs' gain, though
less of it for some: Perl's hash benchmark was 46% faster instead of 53%, `perl
-c` 3% instead of 10%. The registers live in memory, not in Cranelift variables:
each early exit then needs no copy of every register, which made compiling about
three times faster and the code faster too.

It now compiles more of each block than when it was added, and it is much
faster for long programs. The numbers, and what is still slower, are in the
criteria below. Every Debian program still gives native Linux's results with
it. It is off by default until those criteria hold.

### When the native JIT is turned on by default

On Linux x86-64 hosts the native JIT is to be on by default, with `--no-jit`
to turn it off, once all of the following hold. Other hosts and the
WebAssembly package keep the behaviour they have. Each criterion is read off
CI's own records, so anyone can check it:

1. **Correctness on main, 14 days in a row.** Every run of the
   `differential-jit` job on main passed (`ci.yml`, which runs on each push to
   main that changes Rust), and so did every night's Debian comparison with
   the JIT (the `jit` run of `distro-programs.yml`), with every case giving
   native Linux's result. One failure starts the count again. The two
   complement each other: the first compiles every block the first time it
   runs, over [most of the differential tests](./quality#the-native-jit); the
   second uses the default threshold, over Debian's real programs.
2. **Fuzzing.** The nightly `jit_native` fuzz target, which compares compiled
   code with the interpreter for arbitrary instruction bytes, found nothing in
   each of those 14 nights. The target exists already, so no new one is needed.
3. **No open correctness bug.** No open issue labelled `type: bug` is about
   the native JIT (`gh issue list --state open --label "type: bug" --search
   jit`).
4. **Speed.** The `Native JIT speed` workflow (`jit-speed.yml`), run by hand
   on the JIT's default settings, passes on one kind of Intel runner and one
   kind of AMD runner. A kind of runner is its CPU model, which the summary
   names first; the workflow cannot choose it. On one runner it times the
   probe, ripgrep and aube cases, Perl's benchmarks and 12 Debian programs,
   five rounds each, with and without the JIT. It fails when the JIT makes a
   case slower than every round without it. Short programs count as much as
   long ones, since turning the JIT on by default would add its cost to every
   command.

The last criterion holds. With three rounds, the case that tripped changed
from runner to runner (aube's `list` by 3% on an Intel Xeon 6973P-C; probe's
`fs-basic`, probe's `tokio-timer` and ripgrep's `parallel` case by 1–4% on an
AMD EPYC 7763), which looked like noise around the line rather than one cost.
So each case now runs five rounds. Five rounds widen both ranges, which makes
the check easier to pass: a slowdown smaller than the rounds' spread can pass
on one run and fail on the next. The check finds what is slower beyond that
spread, not every slowdown.

The evidence is two fork runs of main at `c615ddf8` (the default of a
threshold of 300 and compiling in the background) with the five-round
workflow: an Intel Xeon Platinum 8573C (run 44193580662) and an AMD EPYC 9V74
(run 44193575557). In both no case was slower; Java was 43–50% faster, Perl's
hash benchmark 34–41% and OCaml 36–42%. These runs count for the switch while
the JIT compiles and runs code as it did at `c615ddf8`, with the same defaults.
A change to the compiled code, to how blocks are compiled or entered, or to the
threshold or compiling in the background, is measured again, on the commit
that brings it, before the switch.

**A known limitation of the default.** Short programs pay for their first
compiles. A third run of the same commit, on an AMD EPYC 7763 (run
44193570604), failed on one case: ripgrep's `no-match` was 2% slower, about
3 ms (225–230 ms against 219–223 ms). On all three runners the ripgrep cases'
medians are up to 2% slower with the JIT. Compiling more instructions of each
block does not help: it lengthens those compiles, and made ripgrep's
`no-match` 2.4% slower again than main's JIT on the 7763 (#758, closed; run
44219431384). The Intel Xeon 6973P-C has not been run with five rounds. An
older version of this comparison started only the JIT through a shell wrapper,
which made programs of about 20 ms look slower than they are.

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

## Single-stepping outside the JIT

The trap flag makes every instruction trap, which a JIT block or a long
interpreted run would step over. The runtime looks at the flag once per
run, where it chooses how to run the guest: with the flag set, the
interpreter runs one instruction and reports the trap, so a run without it
pays one test and nothing per instruction. `popf`, the only instruction
that sets the flag, ends its run when it does, so the next one is stepped;
the kernel sets it only between runs (`rt_sigreturn`, a tracer). Neither
JIT needs to know of the flag. Hardware breakpoints go the same way: while
a tracer has one enabled, the interpreter runs the guest one instruction at
a time and matches it against them, and a guest without any pays nothing
for them.

## A machine with 4-level paging

paludarium is always a machine with 4-level page tables: user space ends
below 2^47 bytes, and `TASK_SIZE_MAX` is 2^47 - 4096, on every host. A guest
then behaves the same on a Linux host with 5-level paging, on macOS and in
WebAssembly, and its results do not depend on the paging depth of the
machine it runs on. Little is lost: Linux maps above 2^47 only for a
process that asks for it with an `mmap` hint there. What differs from a
Linux on a CPU with 5-level paging is listed in the
[limitations](../guide/limitations); the differential tests use no value
whose result there would depend on the paging depth.

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

Releases go to crates.io and npm by Trusted Publishing (OIDC) only, and to
JSR by the OIDC token of the repository linked to the package, with no
long-lived token stored anywhere; npm and JSR packages carry provenance. Published
versions cannot be deleted, so a problem is handled with a crates.io yank or an
npm deprecation and a fixed release.
