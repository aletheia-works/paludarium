# 対応している機能

paludarium が目指すのは、実際のプログラムを本物の Linux と同じ結果で動かすことです。
ここに挙げたものは、差分テストで本物の x86-64 Linux と比べて確かめています。

## 命令

- **整数命令とフラグ**：算術・論理・シフト・ビット操作、`lock` 付きの原子的な命令、
  `REP` の文字列命令（途中で止まったときの再開を含む）、`CMPXCHG8B`／`CMPXCHG16B`、
  BMI 系（`ADCX`／`ADOX`、`ANDN`、`BZHI`、`MULX`、`PEXT`、`RORX`、`SHLX`／`SHRX`）、
  `MOVBE`、`ENTER`／`LEAVE` など。
- **ヒントの命令**：`PAUSE` と、プリフェッチの `PREFETCHNTA`／`PREFETCHT0`／`T1`／`T2`。
  状態を何も変えず、フォールトも起こしません。
- **トラップ**：トラップフラグでシングルステップします。`TF` が立っている間（`popf`、
  `rt_sigreturn`、トレーサーが立てられます）、各命令の後に `TRAP_TRACE` の `SIGTRAP` が
  来て、アドレスは命令の次です（トラップ 1）。`syscall` だけは、カーネルの中でフラグが
  消され、Linux が `iret` で戻るので来ません。`rep` 付きの文字列命令は 1 回ごとにトラップし、
  最後の回までは `rip` がその命令のままです。シグナルハンドラーはフラグを消して始まります。
  `int3` は、カーネルからの（`SI_KERNEL`、トラップ 3）`SIGTRAP` で、`rip` はその次です。
- **SSE 系**：MMX レジスタを使うものを除く SSE と SSE2 のすべての命令（エンコーディング
  ごとにテストで動かしています。フェンスの `MFENCE`／`LFENCE`／`SFENCE` を含みます）。
  それより後の命令セットは、実際のプログラム（probe、aube、pitchfork、ripgrep、coreutils）が使う命令と、
  AES・PCLMUL・SHA などの暗号の命令です。浮動小数点はソフトウェアで計算します。
- 命令のデコードには [iced-x86](https://github.com/icedland/iced) を使っています。
- `CPUID` はホストの値を見せません。glibc は知っているベンダーの機能しか読まないので、
  ベンダーには AMD を名乗ります。glibc が必須とするので、すべての x86-64 の CPU にある機能も
  示します。HotSpot が必須とするので、`CLFLUSH` とその 64 バイトの行も示します。
  そのうち FPU と MMX は実装していませんが、それ以外に実装していない機能は広告
  しません。名乗りが変えるのはここだけです。`REP` のフォルト後のフラグなど、ベンダーで
  CPU の動きが違うところは、仮想 CPU 自身の動きのままです。
- `RDTSC` と `RDTSCP` は仮想 CPU のカウンタを読みます。カウンタは時間ではなく読むたびに
  進みます。ホストのプロセス内のすべてのゲストがこのカウンタを共有するので、値は他のゲストが
  読んだ回数によって変わります。シャドウスタックがないので、`RDSSP` は何もせず、`map_shadow_stack` は `EOPNOTSUPP` を返します。`FXSAVE` と `FXRSTOR` は
  x87 の状態、MXCSR、XMM レジスタを保ちます。
- x87 の命令は、すべての丸めモードで、値の移動、変換、比較と、制御ワード、状態ワード、
  環境、スタックの操作を行います。すべての丸めモードと精度で、加減乗除と平方根を計算し、
  `FPREM`、`FPREM1`、`FSCALE`、`FRNDINT`、`FXTRACT`、`FCOM` の仲間、`FLD` の定数、
  `FCMOV` と、glibc と musl の `long double` の数学関数が使う超越関数の命令
  （`FSIN`、`FCOS`、`FSINCOS`、`FPTAN`、`FPATAN`、`F2XM1`、`FYL2X`、`FYL2XP1`）も
  正しく丸めて実行します。これは実際の CPU の最後のビットと同じとは限りません
  （[制限](./limitations)）。10 進数を読み書きし（`FBLD`、`FBSTP`）、`FNSAVE`、
  `FRSTOR`、`FNSTENV`、`FLDENV` で、16 ビット形式（`0x66` プレフィックス付き）も
  含めて、ユニットを保存して戻します。シグナルハンドラは、Linux と同じく x87 と
  SSE の状態をリセット直後にして始まります。
- AVX、AVX-512、MMX は対象外です。glibc が必須とするので `CPUID` は MMX を示しますが、
  その命令は `SIGILL` で止まります。

ゲストが実行できない命令に当たったときは、本物の Linux と同じようにゲストに
`SIGILL` を送ります。ページフォールトは `SIGSEGV`、整数の 0 除算は `SIGFPE` になります。
マスクされていない浮動小数点の例外も `SIGFPE` になります。MXCSR でマスクを外した SSE の
例外は、その命令のところで起きます。書き込み先は元のままで、MXCSR には命令の例外の
フラグが残り、シグナルハンドラからはそれが見えます。x87 の例外は CPU と同じく、次の
待つ x87 の命令のところで起き、元の命令の結果も CPU と同じになります。無効な演算、
0 除算、演算の非正規化数のオペランドはレジスタを変えず、オーバーフローとアンダーフローは
レジスタの結果の指数を 2²⁴⁵⁷⁶ ずらし、メモリには何も書きません。

## システムコール {#system-calls}

実装したシステムコールだけを、明示した表で扱います。それ以外はすべて `ENOSYS` を返し、
ホストに渡すことはありません。次の表には実装したシステムコールをすべて載せていて、
`lint:all` がカーネルと照らし合わせます。

| 分類 | システムコール |
|---|---|
| プロセスとスレッド | `clone`、`clone3`、`fork`、`vfork`、`execve`、`execveat`、`wait4`、`waitid`、`pidfd_open`、`pidfd_send_signal`、`pidfd_getfd`、`kcmp`、`process_vm_readv`／`process_vm_writev`、`ptrace`（スレッドとプロセスを参照）、`exit`、`exit_group`、`getpid`、`getppid`、`gettid`、`set_tid_address`、`futex`、`futex_waitv`、`futex_wake`／`futex_wait`／`futex_requeue`、`set_robust_list`、`get_robust_list`、`sched_setaffinity`／`sched_getaffinity`、`getcpu`、`sched_yield`、`sched_setscheduler`／`sched_getscheduler`、`sched_setparam`／`sched_getparam`、`sched_setattr`／`sched_getattr`、`sched_get_priority_max`／`sched_get_priority_min`、`sched_rr_get_interval`、`ioprio_set`／`ioprio_get`、`personality`、`unshare`、`setns`、`membarrier`、`rseq`、`setpgid`／`getpgid`／`getpgrp`、`setsid`／`getsid`、`getpriority`／`setpriority`、`prlimit64`／`getrlimit`／`setrlimit`、`prctl` |
| メモリ | `mmap`（anonymous と、プライベートまたは共有のファイル）、`munmap`、`mremap`、`mprotect`、`pkey_mprotect`／`pkey_alloc`／`pkey_free`、`mseal`、`madvise`、`process_madvise`、`process_mrelease`、`mincore`、`cachestat`、`mlock`／`mlock2`／`munlock`／`mlockall`／`munlockall`、`mbind`、`set_mempolicy`／`get_mempolicy`、`set_mempolicy_home_node`、`migrate_pages`、`move_pages`、`map_shadow_stack`、`msync`、`remap_file_pages`、`brk`、`arch_prctl`、`modify_ldt`、`userfaultfd`（下を参照） |
| System V IPC | `shmget`、`shmat`、`shmdt`、`shmctl`（共有メモリ）、`semget`、`semop`、`semtimedop`、`semctl`（セマフォー）、`msgget`、`msgsnd`、`msgrcv`、`msgctl`（メッセージキュー） |
| POSIX メッセージキュー | `mq_open`、`mq_unlink`、`mq_timedsend`、`mq_timedreceive`、`mq_notify`、`mq_getsetattr` |
| 鍵 | `add_key`、`request_key`、`keyctl` |
| システムの情報 | `uname`、`sethostname`、`setdomainname`、`sysinfo`、`getrusage`、`times`、`acct`、`iopl`、`ioperm`、`syslog`、`sysfs`、`perf_event_open`（下を参照） |
| 資格情報 | `getuid`、`geteuid`、`getgid`、`getegid`、`getresuid`／`getresgid`、`setuid`／`setgid`、`setreuid`／`setregid`、`setresuid`／`setresgid`、`setfsuid`／`setfsgid`、`getgroups`／`setgroups`、`capget`／`capset` |
| シグナル | `rt_sigaction`、`rt_sigprocmask`、`rt_sigreturn`、`sigaltstack`、`kill`、`tkill`、`tgkill`、`getitimer`／`setitimer`、`alarm`、`rt_sigtimedwait`、`rt_sigqueueinfo`、`rt_tgsigqueueinfo`、`rt_sigpending`、`rt_sigsuspend`、`pause`、`restart_syscall` |
| 時刻 | `clock_gettime`、`clock_getres`、`gettimeofday`、`time`、`nanosleep`、`clock_nanosleep`、`timer_create`／`timer_settime`／`timer_gettime`／`timer_getoverrun`／`timer_delete`、`adjtimex`、`clock_adjtime`、`settimeofday`、`clock_settime` |
| ファイル | `open`／`openat`／`openat2`／`creat`、`read`、`write`、`readv`／`writev`、`pread64`／`pwrite64`、`preadv`／`pwritev`、`preadv2`／`pwritev2`、`copy_file_range`、`sendfile`、`splice`、`tee`、`vmsplice`、`setxattr`／`lsetxattr`／`fsetxattr`、`getxattr`／`lgetxattr`／`fgetxattr`、`listxattr`／`llistxattr`／`flistxattr`、`removexattr`／`lremovexattr`／`fremovexattr`、`setxattrat`、`getxattrat`、`listxattrat`、`removexattrat`、`file_getattr`、`file_setattr`、`close`、`close_range`、`lseek`、`stat`／`fstat`／`lstat`／`newfstatat`、`statx`、`name_to_handle_at`、`open_by_handle_at`、`getdents`／`getdents64`、`mkdir`／`mkdirat`、`mknod`／`mknodat`、`rmdir`、`unlink`／`unlinkat`、`rename`／`renameat`／`renameat2`、`link`／`linkat`、`symlink`／`symlinkat`、`readlink`／`readlinkat`、`truncate`／`ftruncate`、`fallocate`、`memfd_create`、`memfd_secret`、`flock`、`fcntl`、`dup`／`dup2`／`dup3`、`pipe`／`pipe2`、`chdir`／`fchdir`、`getcwd`、`chroot`、`mount`、`umount2`、`pivot_root`、`open_tree`、`move_mount`、`fsopen`、`fsconfig`、`fsmount`、`fspick`、`mount_setattr`、`open_tree_attr`、`statmount`、`listmount`、`umask`、`chmod`／`fchmod`／`fchmodat`／`fchmodat2`、`chown`／`fchown`／`lchown`／`fchownat`、`utimensat`、`utime`／`utimes`／`futimesat`、`fsync`／`fdatasync`、`sync_file_range`、`sync`、`syncfs`、`fadvise64`、`readahead`、`access`／`faccessat`／`faccessat2`、`statfs`／`fstatfs`、`ustat` |
| Landlock | `landlock_create_ruleset`、`landlock_add_rule`、`landlock_restrict_self` |
| セキュリティモジュール | `lsm_list_modules`、`lsm_get_self_attr`、`lsm_set_self_attr` |
| プローブ | `uprobe`、`uretprobe` |
| 管理 | `reboot`、`swapon`／`swapoff`、`init_module`／`finit_module`／`delete_module`、`kexec_load`／`kexec_file_load`、`quotactl`／`quotactl_fd` |
| seccomp | `seccomp`（下に書きます） |
| BPF | `bpf`、マップと、検証器つきのソケットフィルターの `BPF_PROG_LOAD`。インタープリタで動き、AF_UNIX のソケットにアタッチします（下を参照） |
| 入出力 | `poll`、`ppoll`、`select`、`pselect6`、`vhangup`、`ioctl`（`TCGETS`、`TIOCGWINSZ`、`FIOCLEX`、`FIONCLEX`、`FIONBIO`、`FIOASYNC`、`FIOQSIZE`、`FIGETBSZ`、`SIOCATMARK`、`FIONREAD`/`SIOCINQ`、`SIOCOUTQ`、ループバックと veth の端の `SIOCGIFFLAGS`・`SIOCSIFFLAGS`・`SIOCGIFINDEX`・`SIOCGIFNAME`、`INOTIFY_IOC_SETNEXTWD`、seccomp のリスナーの `SECCOMP_IOCTL_NOTIF_*`（後述の seccomp を見てください）、`FS_IOC_GETFLAGS`、`FS_IOC_SETFLAGS`、`FS_IOC_FSGETXATTR`、`FS_IOC_FSSETXATTR`、後述の疑似端末のリクエスト） |
| イベント | `eventfd`／`eventfd2`、`timerfd_create`／`timerfd_settime`／`timerfd_gettime`、`signalfd`／`signalfd4`、`inotify_init`／`inotify_init1`、`inotify_add_watch`、`inotify_rm_watch`、`fanotify_init`、`fanotify_mark`、`epoll_create`／`epoll_create1`、`epoll_ctl`、`epoll_wait`、`epoll_pwait`、`epoll_pwait2`、`io_uring_setup`、`io_uring_enter`、`io_uring_register`（下を参照） |
| 非同期 I/O | `io_setup`、`io_destroy`、`io_submit`、`io_cancel`、`io_getevents`、`io_pgetevents`（下を参照） |
| ソケット | `socket`（AF_UNIX のストリーム、パケット、データグラムのソケット。[ネットワーク](#network)があるか新しいネットワーク名前空間の中なら `AF_INET`、`AF_INET6`、`AF_NETLINK`（`NETLINK_ROUTE`、`NETLINK_SOCK_DIAG`、`NETLINK_GENERIC`）、`AF_MCTP` のデータグラム、なければ `EAFNOSUPPORT`）、`connect`、`getsockname`、`getpeername`、`bind`、`listen`、`accept`、`accept4`（AF_UNIX のストリームとパケットのソケット、ゲスト自身の[ループバック](#loopback-servers)の上の TCP）、`socketpair`（AF_UNIX、`SOCK_STREAM`、`SOCK_SEQPACKET`、`SOCK_DGRAM`）、`sendto`、`recvfrom`、`sendmsg` と `recvmsg`（`SCM_RIGHTS` でのディスクリプタ、`SCM_CREDENTIALS` での資格情報、`SCM_PIDFD` での送り手の pidfd の受け渡し）、`sendmmsg` と `recvmmsg`、`setsockopt` と `getsockopt`（`SOL_SOCKET`）、`shutdown` |
| 乱数 | `getrandom` |

- `readv`・`writev` とその位置指定版、`vmsplice`、`sendmsg`、`recvmsg` の `struct iovec` の配列は、
  Linux の `import_iovec` と同じ順で確かめます。要素がなければ何も動かさず、1024 を超えれば
  `EINVAL`、配列がユーザー空間をはみ出せば `EFAULT` です。次に、どのバッファーを見るよりも先に
  全要素を読み、負の長さは `EINVAL` です。その後で各バッファーがユーザー空間に収まるかを確かめ
  （`EFAULT`）、要素が複数なら長さ全体で、1 つなら `MAX_RW_COUNT` までで確かめます。長さは、
  合計が `MAX_RW_COUNT` を超えないように切り詰めます。

- `pread64`・`pwrite64`・`preadv`・`pwritev` はファイルの位置を動かさず、パイプとソケットでは
  `ESPIPE` を返します。`O_APPEND` のファイルでは、Linux と同じく位置を指定した書き込みも
  末尾に足します。

- `preadv2` と `pwritev2` は、指定した位置で読み書きし、位置が -1 なら `readv` と `writev` と
  同じくファイルの位置で読み書きします。フラグは、ベクターと範囲を確かめた後、動かすバイトが
  あるときだけ、Linux の `kiocb_set_rw_flags` と同じく確かめます。知らないフラグは
  `EOPNOTSUPP`、`RWF_APPEND` と `RWF_NOAPPEND` の両方は `EINVAL`、`RWF_ATOMIC` は不可分に
  書けるファイルがないので `EOPNOTSUPP` です。`RWF_NOWAIT` は待たずに読み書きできるファイル
  （パイプ、ソケット、eventfd、signalfd、timerfd、`/dev/null`、`/dev/zero`、`/dev/random`、
  `/dev/urandom`、それを持つファイルシステムの通常のファイル。ほかは `EOPNOTSUPP`）で使え、
  待つところで `EAGAIN` を返します。`RWF_DONTCACHE` は `FOP_DONTCACHE` を持つファイル
  システムの通常のファイルが必要で、何も変えません（何もキャッシュしません）。通常のファイルの
  ファイルシステムは、そのファイルがあるもの（`fstatfs` の名前）で、Linux master と同じく
  どちらも決めます。ext4 は NOWAIT を受け付けますが書き込みでは断り、DONTCACHE も受け付け
  ます。xfs はどちらも、書き込みの NOWAIT も受け付けます。btrfs と f2fs は NOWAIT を
  書き込みでも受け付け、DONTCACHE は断ります。tmpfs（メモリ上のファイルシステムと memfd）、
  overlayfs、`/proc`、そのほかのファイルシステムはどちらも断ります。Linux が番号を持たない
  ファイルシステムの macOS と Windows のホストでは、ホストのファイルを ext4 のものとして
  扱います。`RWF_NOSIGNAL` は、Linux 6.18 からと同じく、読む側のない
  パイプやソケットへの書き込みで `SIGPIPE` を送りません（`EPIPE` は返します）。
  `RWF_NOAPPEND` は、その呼び出しのあいだ `O_APPEND` の追記を止めます。書き込みは指定した
  位置へ行き（末尾より先ならファイルを伸ばします）、-1 ならファイルの位置へ行って位置が進みます。
  追記専用のファイル（`FS_APPEND_FL`）は、読み込みでも `EPERM` です。
  `RWF_APPEND` は通常のファイルの末尾に書き、`RWF_DSYNC` と
  `RWF_SYNC` は `fdatasync` と同じく書き出し、`RWF_HIPRI` は何も変えません。

- `copy_file_range` は、同じマウントにある 2 つの通常のファイルの間でコピーし（マウントを
  またぐと `EXDEV`）、入力の末尾で止まります。確かめる順番は Linux と同じです（`EISDIR`、
  `EINVAL`、`EBADF`、`EOVERFLOW`、同じファイルの中で範囲が重なると `EINVAL`）。
  `sendfile` は、通常のファイルを書き込める任意のファイルに送り、パイプには 1 回でその容量
  までを送ります。どちらも、渡されたオフセットかファイルの位置を進めます。`sendfile` は、
  失敗したときもオフセットを書き戻します。

- `splice` は、パイプ（または FIFO）と、通常のファイル、デバイス、ソケット、別のパイプの
  間でバイトを動かします。`tee` は、あるパイプにあるものを取り出さずに別のパイプへ
  コピーし、`vmsplice` は、ゲストのバッファーを書き込み用に開いたパイプへ入れるか、
  パイプのバイトをバッファーへ取り出します。確かめる順番は Linux の `fs/splice.c` と
  同じです。`splice` はバイト数が 0 なら何よりも先に 0 を返し、`tee` は先にフラグを
  確かめます。そのあと、フラグ（`EINVAL`）、ディスクリプタ（`EBADF`、`O_PATH` も）、
  パイプへのオフセット（`ESPIPE`）、オフセットの読み込み（`EFAULT`）、アクセスモード
  （`EBADF`）、ソケットのように位置のないファイルへのオフセットか `O_APPEND` の出力
  （`EINVAL`）、範囲（`EINVAL`）、splice できない種類のファイル（ディレクトリ、eventfd。
  `EINVAL`）の順です。同じパイプの 2 つの記述は `EINVAL`、パイプでないファイルへの
  `vmsplice` は `EBADF` です。読み手のいないパイプは `SIGPIPE` を伴う `EPIPE` で、入力より
  先に、入力が終わりにあっても確かめます。`SPLICE_F_NONBLOCK` かパイプの `O_NONBLOCK`
  （`vmsplice` はフラグだけ）が待たないと言わない限り、データか空きを待ち
  （`EAGAIN`）、書き手のいなくなったパイプは 0 を返し、いくらか動かした呼び出しは、
  また待たずにその数を返します。1 回で動かすのは、パイプにあるか空いている分までです。
  unix のストリームソケットからの読み込みも `SPLICE_F_NONBLOCK` で待ちません。
  ソケットへの送信は、`splice_to_socket` と同じく、ほかのファイルと同様にそれ自身の
  `O_NONBLOCK` のとおりに読み書きします。
  バイトはコピーするので、`SPLICE_F_MOVE`、`SPLICE_F_GIFT`、`SPLICE_F_MORE` は何も
  変えません。ここでのパイプは Linux のページのバッファーではなくバイトを持ち、大きさの
  分だけバイトを受け取ります。Linux は 1 バイトのバッファーも容量の 1 ページと数えるので、
  一部が埋まったパイプや、ページ単位でない `vmsplice` のバッファーでは、ここのほうが
  多く受け取ることがあります。また、Linux のパイプのロックと違い、あるスレッドの呼び出しは、
  別のスレッドによる同じパイプの読み込みに対して不可分ではありません。
  パイプの代わりであるホストの標準のストリームは、`splice` のどちらの端にもなれます
  （オフセットを渡すと `ESPIPE`）。`tee` と `vmsplice` はゲスト自身のパイプだけを受け付け、
  標準のストリームは受け付けません。

- `getdents64` は返したエントリーの続きから読むので、それらを `unlink` しても
  読み飛ばしません。ディレクトリが変わらない間は、`d_off` への `lseek` で同じ
  エントリーに戻ります。`dup` と `fork` は読んでいる位置を共有します。`getdents`
  も同じで、古い `linux_dirent` を書きます（型は各エントリーの最後のバイトです）。
  どちらも Linux と同じく大きさを `int` で持つので、2 GiB 以上ではどのエントリーも
  入りません（`EINVAL`）。

- 拡張属性はメモリ上のファイルとともに保持し、ハードリンクや名前の変更のあとも、
  最後の名前がなくなったあとも残ります。Linux と同じく、`user.*` は通常のファイルと
  ディレクトリ用で（ほかでは読むと `ENODATA`、書くと `EPERM`）、スティッキー
  ディレクトリでは、その持ち主か `CAP_FOWNER` のある呼び出し元だけが変えられます
  （`EPERM`）。`trusted.*` は `CAP_SYS_ADMIN` があるときだけ見えます。`security.*` と
  `system.*` にはファイルのアクセス権を求めず、`security.*` の変更には
  `CAP_SYS_ADMIN` が必要です。名前は 1〜255 バイト（`ERANGE`）、値は 64 KiB まで
  （`E2BIG`）で、ほかの名前空間は `EOPNOTSUPP` です。Linux 6.13 以降と同じく、名前は
  ファイルを探す前に読みます。

- ファイルケーパビリティ（`security.capability`）は、Linux のケーパビリティモジュールと
  同じように確かめて変換します。書く値はリビジョン 2（20 バイト）か 3（24 バイト）の
  `vfs_cap_data` でなければならず（`EINVAL`）、呼び出し元には、ファイルの持ち主とグループを
  マップするユーザー名前空間での `CAP_SETFCAP` が必要です（`EPERM`）。取り除くときも
  同じです。最初のユーザー名前空間で `CAP_SETFCAP` のある呼び出し元はリビジョン 2 の値を
  そのまま保ちます。それ以外の値は、呼び出し元の名前空間で値が示す root のカーネル ID を
  持つリビジョン 3 として保存し、その名前空間はその root をマップしていなければなりません
  （`EINVAL`）。読むときは、読み手の名前空間がその root を 0 以外の ID にマップしていれば
  リビジョン 3、その名前空間かその上で root ならリビジョン 2 の値を返し、どちらでも
  なければ `EOVERFLOW` です。ファイルへの書き込みと切り詰め、ディレクトリ以外の
  `chown` は、誰がしてもファイルケーパビリティを取り除きます。`execve` は、実行する
  プログラムにそれを与えます（下の資格情報を見てください）。

- `setxattrat`、`getxattrat`、`listxattrat`、`removexattrat`（Linux 6.13）は、
  ディレクトリのディスクリプタからファイルを探し、受け付けるフラグは
  `AT_SYMLINK_NOFOLLOW` と `AT_EMPTY_PATH` だけです（`EINVAL`）。`AT_EMPTY_PATH` では、
  NULL または空のパスはディスクリプタのファイルを指します（ディスクリプタがないか
  `O_PATH` のものなら `EBADF`）。このとき `setxattrat` と `getxattrat` は `AT_FDCWD` を
  作業ディレクトリとして扱い、残りの 2 つは `EBADF` です。値とその大きさ、フラグは
  `struct xattr_args` で渡し、`copy_struct_from_user` と同じように確かめます。16 バイト
  未満は `EINVAL`、1 ページを超えるか 16 バイトより後ろに 0 でないバイトがあれば
  `E2BIG` で、`getxattrat` はフラグを受け付けません（`EINVAL`）。

- メモリ上の通常のファイルとディレクトリは、tmpfs と同じ inode フラグを保持します。
  `FS_IMMUTABLE_FL`、`FS_APPEND_FL`、`FS_NODUMP_FL`、`FS_NOATIME_FL` の 4 つです。
  `file_getattr` と `file_setattr`（Linux 6.17）、`FS_IOC_GETFLAGS`・
  `FS_IOC_SETFLAGS`・`FS_IOC_FSGETXATTR`・`FS_IOC_FSSETXATTR` の ioctl は、Linux の
  `vfs_fileattr_set` と tmpfs の `shmem_fileattr_set` と同じようにこれを読み書きします。
  - 変えられるのは所有者か `CAP_FOWNER` を持つスレッドだけで（`EPERM`）、最初の 2 つには
    `CAP_LINUX_IMMUTABLE` も必要です（`EPERM`）。
  - プロジェクト ID の -1 と、種類の合わないファイルへのエクステントサイズのフラグは
    `EINVAL` です。tmpfs は保持しないので、それ以外のフラグ、プロジェクト ID、
    エクステントサイズは `EOPNOTSUPP` です。
  - `file_getattr` と `file_setattr` は `setxattrat` と同じようにファイルを探し、24 バイト
    以上の `struct file_attr` を `copy_struct_from_user` と同じように確かめます。Linux の
    知らないフラグは、ここでは `EINVAL`、`FS_IOC_FSSETXATTR` では `EOPNOTSUPP` です。
  - 新しいファイルやディレクトリは、親ディレクトリの `FS_NODUMP_FL` と
    `FS_NOATIME_FL` を受け継ぎます。`statx` は `STATX_ATTR_IMMUTABLE`、
    `STATX_ATTR_APPEND`、`STATX_ATTR_NODUMP` を返します。
  - マウントしたホストのディレクトリのファイル、`/proc` の下、シンボリックリンク、
    特殊ファイルは保持しません。システムコールは `EOPNOTSUPP`、ioctl は `ENOTTY` です。
  - 設定すると `IN_ATTRIB` が生じます。

- フラグは、Linux が `IS_IMMUTABLE` と `IS_APPEND` を確かめるところで、root にも
  適用します。
  - 変更不可のファイルへの書き込みは、ほかのどの権限確認よりも先に `EPERM` です
    （`inode_permission`）。書き込みや切り詰めのための open、`truncate`、`W_OK` の
    `access`、変更不可のディレクトリでの名前の作成と削除がこれにあたります。
  - 変更不可か追記のみのファイルは、削除も、名前の変更の元や上書き先になることも、
    ハードリンクもできず、モード、所有者、拡張属性、指定した時刻も変わりません
    （`EPERM`）。変更不可のファイルは、現在時刻にすることもできません。
  - 追記のみのディレクトリからは何も削除できません。
  - 追記のみのファイルは、書き込むなら `O_APPEND` 付きでしか開けず、`O_TRUNC` では
    開けません。`O_APPEND` は外せません（`F_SETFL`、`RWF_NOAPPEND`：`EPERM`）。
    `ftruncate` はできず、`fallocate` は事前割り当てだけです（`EPERM`）。書き込み用に
    開いたものは共有でマップできません（`EACCES`）。
  - `copy_file_range` は変更不可のファイルに書き込みません（`EPERM`）。
  - tmpfs と同じく、フラグを設定する前に開いたものからは書き込めます。
    アクセス時刻は保持しないので、`FS_NOATIME_FL` と `FS_NODUMP_FL` はほかに何も変えません。

- `statx` は、`stat` にある項目（`STATX_BASIC_STATS`）と、デバイス番号としてマウントの
  `st_dev` を返します。flags と mask は Linux と同じように確かめます（`EINVAL`）。
  mask が何を求めても、Linux と同じくマウントの ID も返します。`/proc/self/mountinfo`
  が示す ID（`STATX_MNT_ID`）か、`STATX_MNT_ID_UNIQUE` を求めたときはその代わりに、
  マシンが終わるまで一意な 64 ビットの ID（`statmount` と `listmount` が使うもの）です。内部のファイルシステムのファイル（パイプ・ソケット・memfd
  など。後の `statfs` を参照）は、mountinfo に出ない小さな ID のマウントにあります。
  mountinfo の ID は 21 から始まり、Linux の内部のマウントも mountinfo に出ません。
  `AT_EMPTY_PATH` はディスクリプタを、`AT_FDCWD` なら作業ディレクトリを指し、Linux 6.11
  からと同じく、それとともに渡した空ポインタのパスも同じ扱いです。

- `name_to_handle_at` はファイルのハンドルを返し、Linux（6.13 以降）と同じ順に確かめます。
  まずフラグ（`EINVAL`。`AT_HANDLE_CONNECTABLE` と `AT_HANDLE_FID` か `AT_EMPTY_PATH` を
  合わせたときも）、次にパス（`AT_SYMLINK_FOLLOW` がなければ最後のリンクそのもの。空の
  パスと `AT_EMPTY_PATH` ではディスクリプタか作業ディレクトリ）、ファイルシステム、渡した
  大きさ（128 バイトを超えると `EINVAL`、ハンドルより小さいと `EOVERFLOW` で、要る大きさと
  `FILEID_INVALID` を書き戻します）、最後に `statx` と同じマウントの ID
  （`AT_HANDLE_MNT_ID_UNIQUE` では 64 ビットの ID）です。tmpfs のファイル（と memfd）は
  tmpfs と同じ 12 バイトで型 `FILEID_INO32_GEN` のハンドルを持ちます。世代、inode の下位と
  上位の半分の順です。pidfd は pidfs と同じ 8 バイトで型 `FILEID_KERNFS` のハンドル
  （その inode）を持ちます。ほかのファイルシステム（eventfd の匿名 inode、パイプ、
  `/proc` など）は NFS のエクスポートがないものとしてハンドルを断り（`EOPNOTSUPP`）、
  `AT_HANDLE_FID` には型 `FILEID_INO64_GEN` の識別子を返します。inode、世代の順です。
  接続できるハンドルは、tmpfs も pidfs も作れないので `EOPNOTSUPP` です。

- `open_by_handle_at` はハンドルが指すファイルを開き、Linux と同じ順に確かめます。
  まずハンドルの見出し（`EFAULT`）、その大きさ（0 か 128 バイトを超えると `EINVAL`）と
  型のフラグ（接続できるハンドルとディレクトリのハンドルのもの以外は `EINVAL`）、
  ハンドルを読み解くマウント（`EBADF`。ディスクリプタのファイルシステム、`AT_FDCWD` では
  作業ディレクトリのもの、または `FD_PIDFS_ROOT` と `FD_NSFS_ROOT`）、そこでハンドルを
  読み解いてよいか、ハンドルのバイト列（`EFAULT`）、最後にファイルです。見つからない
  ときや、ハンドルを断るとき（ファイルにディレクトリのハンドルの印があるとき、接続できる
  ハンドルのファイルがマウントのディレクトリの外にあるとき）は `ESTALE` です。pidfs の
  ハンドルは、pidfd か `FD_PIDFS_ROOT` から、誰でも開けます。フラグは pidfd が開くときの
  ものだけを受け付けます（ほかは `EINVAL`）。プロセスが回収されておらず、呼んだ側の PID
  名前空間がそのプロセスに番号を付けている間は、そのプロセスの pidfd になります。いつも
  読み書きできるように開き、`O_NONBLOCK` と `O_CLOEXEC` は指定のとおりで、`F_GETFL` にも
  表れます。Linux 7.0 と同じく `PIDFD_THREAD` は付きません。ほかの場所で読み解くには `CAP_DAC_READ_SEARCH` が要ります
  （`EPERM`）。メモリー上のルートの tmpfs のハンドルは、そのファイルそのものを開くのと
  同じようにファイルを開きます。`O_CREAT` はそのファイルを見つけ（`O_EXCL` では
  `EEXIST`、ディレクトリでは `EISDIR`）、シンボリックリンクはたどりません。

- `fallocate` は、Linux の `vfs_fallocate` と同じ順に引数を確かめます（`EINVAL`、
  `EOPNOTSUPP`、`EBADF`、通常のファイルでなければ `ESPIPE`・`EISDIR`・`ENODEV`、
  そして `EFBIG`）。そのあとは tmpfs と同じふるまいです。通常の確保は範囲の
  ページを確保し、`FALLOC_FL_KEEP_SIZE` がなければファイルを大きくします。
  `FALLOC_FL_PUNCH_HOLE` は範囲が覆うページを解放し、残りを 0 にします
  （`O_APPEND` のファイルでも）。ほかのモードは `EOPNOTSUPP` です。
  `RLIMIT_FSIZE` を超えて大きくすると `SIGXFSZ` を起こして `EFBIG` で失敗し、
  メモリ上のファイルシステムの 4 GiB を超える `fallocate` は、何も確保せずに
  `ENOSPC` で失敗します（書き込みにはこの上限はありません。
  [制限](./limitations) を見てください）。

- メモリ上のファイルシステムのファイルは、tmpfs と同じく中身を 4 KiB のページで
  持ちます。書き込みは触れたページを確保し、それ以外は 0 として読める穴で、
  メモリを使いません。そのため `ftruncate` で大きくしたファイルは、書くまで何も
  使いません。`st_blocks` は確保したページを数え、ファイルを小さくすると末尾より
  後ろのページを解放します。`SEEK_DATA` と `SEEK_HOLE` の `lseek` は、書いたページと
  穴を見つけます。`fallocate` で確保したページは書くまで穴で、ファイルの末尾も
  穴です。末尾以降や負のオフセットは `ENXIO` です。

- マウントしたホストのディレクトリのファイルでは、Linux と macOS のホストなら
  `SEEK_DATA`、`SEEK_HOLE`、`st_blocks` をホストから得ます（`st_blocks` は Unix の
  ホストすべてで）。ホストのファイルシステムが穴の場所を答えられないときと、ほかの
  ホストでは、Linux の `generic_file_llseek` が穴のないファイルシステムで扱うのと
  同じく、ファイル全体をデータとします。

- `memfd_create` は、リンクのないメモリ上のファイル（モード 0777、
  `MFD_NOEXEC_SEAL` なら 0666）を作り、flags と名前を Linux と同じく確かめます
  （`EINVAL`、`EFAULT`）。`MFD_HUGETLB` は、hugetlbfs のないカーネルと同じく
  `ENOSYS` です。`fcntl` の `F_ADD_SEALS`・`F_GET_SEALS` で扱うシールは、
  `MFD_ALLOW_SEALING` がなければ `F_SEAL_SEAL` から始まり（`MFD_NOEXEC_SEAL` なら
  `F_SEAL_EXEC`）、tmpfs と同じくファイルを制限します。`F_SEAL_WRITE` と
  `F_SEAL_FUTURE_WRITE` は書き込み・穴あけ・書き込める共有マッピングを、
  `F_SEAL_SHRINK` と `F_SEAL_GROW` は大きさを（書き込みはファイルの中で終わる最後の
  ページで止まります）、`F_SEAL_EXEC` は実行ビットを、どれも `EPERM` で拒みます。
  memfd どうしは、Linux の内部の tmpfs マウントと同じく専用のファイルシステムを
  共有するので、memfd とマウント上のファイルの間の `copy_file_range` は `EXDEV` です。
  ほかのファイルにシールはありません（`EINVAL`）。本物の tmpfs のファイルなら
  `F_SEAL_SEAL` を返すところですが、メモリ上の `/tmp` のファイルも同じです。
  Linux と同じく、書き込める共有マッピングが memfd を見せている間の `F_SEAL_WRITE` は
  `EBUSY` になり、書き込みを封じた memfd の共有マッピングは書き込めるようにできません
  （`EACCES`）。実行できる memfd への `F_SEAL_EXEC` も書き込みを封じるので、そのときは
  Linux 7.1 以降と同じく `EBUSY` になります（それより前のカーネルはシールを加えます）。

- `memfd_secret` は、Linux の secretmem と同じファイルを作ります。中身のない通常の
  ファイルで、モードは 0600、リンクは 1 つ、読み書き用に開いていて、`/proc/self/fd` と
  `/proc/self/maps` では `/secretmem (deleted)` と見え、専用のファイルシステム
  （`SECRETMEM_MAGIC`）にあります。フラグは `O_CLOEXEC` だけです（`EINVAL`）。サイズは
  `ftruncate` で一度だけ決められ（その後は `EINVAL`）、見せられるのは共有マッピング
  だけで（`EINVAL`）、終わりより先は `SIGBUS` です。`read`、`write` とその位置指定や
  ベクタの形はなく（`EINVAL`）、`lseek`（`ESPIPE`）、`fsync`（`EINVAL`）、`fallocate`
  （`EOPNOTSUPP`）、シール（`EINVAL`）もありません。`/proc/self/fd` から開き直すと
  `ENXIO` です。Linux の `get_user_pages` と同じく、カーネルはそのマッピングのページに
  触れられません。`MADV_POPULATE_READ` と `MADV_POPULATE_WRITE` は `EINVAL`、`mlock` は
  `ENOMEM` です。`mlock_fixup` がその VMA に `VM_LOCKONFAULT` を付けないので、
  `MLOCK_ONFAULT` でも同じです。ファイルに `fsync` がないので、`MS_SYNC` の `msync` も、
  範囲に穴があってもそのマッピングに着けば `EINVAL` です。ページフォールトでページを
  割り当てるのは、そのユーザーが作ったファイルのページが、フォールトしたプロセスの
  `RLIMIT_MEMLOCK` に収まる間だけです（超えると `CAP_IPC_LOCK` の有無によらず `SIGBUS`）。
  Linux master の secretmem が作ったユーザーの `locked_vm` に数えるのと同じく、ページは
  マップしているかによらず、ファイルがなくなるまで数えます。ページはエミュレータのものなので、
  ゲストのほかのメモリと同じだけしか秘密になりません。

- `openat2` は `openat` と同じように開き（FIFO も）、`struct open_how` を Linux と同じく
  より厳しく調べます。24 バイトに満たない大きさは `EINVAL`、1 ページを超えるものや、
  最初の版より後ろに 0 でない未知のバイトがあるものは `E2BIG` です。未知のフラグや
  `RESOLVE_*` フラグ、`O_CREAT` も `O_TMPFILE` もないのに付けたモードや許可ビットを
  超えるモード、`O_CREAT | O_DIRECTORY`、`O_DIRECTORY`・`O_NOFOLLOW`・`O_CLOEXEC`
  以外のフラグを伴う `O_PATH` は `EINVAL` です。`RESOLVE_NO_SYMLINKS` はシンボリック
  リンクを、`RESOLVE_NO_MAGICLINKS` は `/proc/self/fd` のリンクや `exe`・`cwd`・`root` を
  たどりません（`ELOOP`）。`RESOLVE_NO_XDEV` は `/proc` や `/dev` も含めてマウントを
  越えません（`EXDEV`）。`RESOLVE_BENEATH` では絶対パスや絶対パスへのリンク、
  ディレクトリの外に出る `..`、マジックリンクが `EXDEV` になり、`RESOLVE_IN_ROOT` は
  ディレクトリをルートとして扱うので、それらはその中にとどまります（マジックリンクは
  `EXDEV`）。両方のスコープのフラグを付けると `EINVAL` です。`RESOLVE_CACHED` は
  `O_CREAT`、`O_TRUNC`、`O_TMPFILE` と一緒なら `EAGAIN` で、それ以外はすべての名前が
  キャッシュにあるものとして常にファイルを見つけます。

- `close_range` は `first` から `last` までの開いているディスクリプタを閉じ、
  `CLOSE_RANGE_CLOEXEC` なら閉じずに close-on-exec を付けます。`CLOSE_RANGE_UNSHARE`
  は先に、`CLONE_FILES` のスレッドと共有している表をそのスレッド専用の写しにします。
  共有していたスレッドのディスクリプタはそのまま残ります。未知のフラグや `last` より
  大きい `first` は `EINVAL` です。

- どのシステムコールも、引数を Linux が宣言している C の型の幅で読みます。Linux の
  システムコールの入口が、呼び出しの前にレジスタをその型にキャストするのと同じです。
  `int`・`pid_t`・`clockid_t` は下位 32 ビットを符号拡張して、`unsigned int`・`uid_t`・
  `u32` は下位 32 ビットを、`umode_t` は下位 16 ビットを読みます。レジスタの残りを
  0 にせずに呼ぶもの（fish の `fcntl`）でも、Linux と同じ結果になります。ポインタと
  `long`・`unsigned long`・`size_t`・`loff_t` の引数はそのまま全体を読むので、`prot` の
  32 ビットより上が立っている `mprotect` は `EINVAL` のままです。ただし `readv`・`writev`
  などの iovec の数（`process_vm_readv`・`process_vm_writev` の手元側、`vmsplice`、
  ベクタを使う `io_submit` の要求の `aio_nbytes` も）は例外で、下位 32 ビットだけを読みます。
  CI のランナーのカーネルはこの数を `unsigned` として `import_iovec` に渡すので、
  `0x100000001` は要素 1 つになります。Linux master は 965e5e451146（2026-11-05）から
  全体を読み、そうした数を `EINVAL` にします。paludarium は CI のカーネルがそうなってから
  合わせます。システムコールの番号も、
  Linux の `do_syscall_64` が `int` で受け取るのと同じく `rax` の下位 32 ビットから読み、
  負の番号は `ENOSYS` です。

- `futex` は `WAIT`・`WAKE`・`WAIT_BITSET`・`WAKE_BITSET`・`REQUEUE`・`CMP_REQUEUE`・
  `WAKE_OP` を扱います。ワードは Linux の
  `get_futex_key` と同じように見分けます。共有マッピング（共有の無名メモリかファイルのもの）では、
  shared の操作はそのメモリとその中のオフセットを指すので、wake はそのメモリをマップしている
  どのプロセスの待ち手にも、どこにマップしていても届きます。それ以外のワードと private の操作は、
  このプロセスのアドレス空間とアドレスを指すので、private の wake はほかのプロセスに届きません。
  プロセス間で共有する mutex とセマフォ（Python の `multiprocessing`）も、持ち主が終わった
  robust futex の wake も、こうして動きます。wake は、0 以下の数を頼まれても待ち手を 1 つ起こします
  （Linux は比べる前に数えるからです）。private の wake はワードのページを見ません。Linux の
  ナノ秒に収まらない長さのタイムアウトは `KTIME_MAX` まで待ちます。requeue は、`val` 個の待ち手を
  起こし、さらに最大 `val2` 個（Linux と同じくタイムアウトの引数から読みます）を `uaddr2` の
  キューに移して、扱った数を返します。負の数は `EINVAL` です。`CMP_REQUEUE` は、両方のワードを
  確かめた後で、1 つめのワードが `val3` でなければ `EAGAIN` を返します。待ち手はビットセットに
  かかわらず、来た順に扱います。同じワードへの requeue は、Linux が 1 つのハッシュバケットの中で
  そうするのと同じく、待ち手を動かさず、それぞれ 1 回だけ数えます。`WAKE_OP` は、`val3` が
  表す演算（代入・加算・論理和・否定との論理積・排他的論理和。引数は 1 のシフトにもできます）で
  `uaddr2` を不可分に変え、`uaddr` の待ち手を最大 `val` 個起こします。続けて、`uaddr2` の元の
  値を符号付きの `int` として比べた結果が真なら、`uaddr2` の待ち手を最大 `val2` 個起こし、
  起こした数を返します。x86 の Linux と同じく、知らない演算はワードに触れる前に `ENOSYS`、
  知らない比較はワードを変えた後で `ENOSYS`、書けないワードは `EFAULT` です。

- futex2 の呼び出しは、32 ビットのワードと `FUTEX2_PRIVATE`・`FUTEX2_NUMA`・`FUTEX2_MPOL` を
  Linux と同じ順に確かめて受け付けます。ほかの大きさやフラグは `EINVAL` です。`futex_wake` と
  `futex_wait` は、`FUTEX_WAKE_BITSET` と `FUTEX_WAIT_BITSET` に、`CLOCK_REALTIME` か
  `CLOCK_MONOTONIC` の絶対時刻のタイムアウトを付けたものです。数 0 の `futex_wake` は何も
  起こしません。`futex_waitv` は最大 128 個のワードを一度に待ち、起こされたワードの添字を返します。
  値を比べる前にすべてのワードのアドレスを確かめ、その後で最初に違ったワードで `EAGAIN` を
  返します。`futex_requeue` は、`struct futex_waitv` の 2 つのワードに対する `CMP_REQUEUE` で、
  6.12 より後のカーネルと同じく、2 つのフラグは同じでなければなりません。比べるのは 1 つめの
  値です。`FUTEX2_NUMA` のワードの後ろにはノードが続き、ただ 1 つのノード 0 か、`-1` で
  なければなりません。`-1` は、Linux がスレッドのノードを書くのと同じく 0 になります。待ちを
  シグナルで中断すると `ERESTARTSYS` になるので、停止の後と `SA_RESTART` のハンドラの後にやり直します。

- `set_robust_list` と `get_robust_list` は、スレッドごとの robust futex のリストを
  持ちます。glibc と musl の robust mutex に必要です。スレッドが終わるときと `execve`
  のときに、Linux の `exit_robust_list` と同じようにリストをたどります。スレッドが
  持っていたワードに `FUTEX_OWNER_DIED` を付け、`FUTEX_WAITERS` があれば shared の
  wake をします。使えないものに当たるか 2048 個たどると止まり、コアダンプはその前に
  書きます。新しいスレッドとプロセスのリストは空です。`get_robust_list` は、ほかの
  プロセスのスレッドの先頭も、Linux の `ptrace_may_access` が
  `PTRACE_MODE_READ_REALCREDS` で読めるとする呼び出し元には返します（`EPERM` は
  アドレスに書く前です）。ゾンビなら 0 です。この検査と、`kcmp`、`pidfd_getfd`、
  `migrate_pages`、`move_pages` の検査では、Linux 7.1 以降と同じく、ゾンビもダンプ
  できるかどうかをそのまま持ちます（それより前は、メモリのなくなったプロセスでは
  この判定を飛ばしていました）。

- `futex`・`epoll`・`eventfd` は paludarium の中で実装していて、ホストの同じ機能には
  頼りません。そのため、macOS・Windows・WebAssembly でも同じように動きます。

- [ネットワーク](#network)がなければ、新しいネットワーク名前空間の外では、`socket()` は `AF_INET`、`AF_INET6`、`AF_NETLINK`、`AF_MCTP` に
  `EAFNOSUPPORT` を返します。

- `epoll_wait`・`epoll_pwait`・`epoll_pwait2` は、Linux 6.12 より後のカーネルと同じ順番で引数を
  確かめます（6.12 は記述子より先に `maxevents` を確かめていました）。
  `epoll_pwait2` はまずタイムアウト（`struct timespec`。なければいつまでも待ちます）を読み
  （`EFAULT`）、Linux が受け付けない値なら `EINVAL` を返し、大きすぎる値は上限で止めます。次に
  シグナルマスクを設定し（大きさが 8 でなければ `EINVAL`）、記述子（`EBADF`）、`maxevents`
  （`EINVAL`）、epoll であること（`EINVAL`）の順に確かめます。

- `poll` は `epoll_wait` と同じように、どれかの記述子が準備できるか、ミリ秒の
  タイムアウトが過ぎるか（負の値なら過ぎません）、シグナルが届くまで（`EINTR`）待ちます。
  ホストの標準入力は、Linux の端末やパイプと同じく、読むバイトがあるときか、入力が
  終わったとき（WebAssembly では `Guest.stdin` を閉じたとき、Unix のホストでは記述子が
  終わったとき）だけ読めるとします。終わったときは切断（`POLLHUP`）も示し、`read` は
  0 を返します。読むものがない `read` はカーネルの中で待つので、Linux と同じく、
  シグナルが来ると `EINTR` で終わり、`SA_RESTART` なら始め直します。
  `poll`・`ppoll`・`select`・`pselect6` と、標準入力を監視できる `epoll`
  は、どれもそう見ます。それを見分けられないホスト（Windows）では、いつも読めると
  します。出力はいつも書けます。パイプの読み出し側は、読まれていないデータがあるときだけ読めるとし、書き手が
  いなくなると切断だけを示します。Linux の `pipe_poll` と同じです。

- `ppoll`・`select`・`pselect6` も同じように待ちます。Linux と同じく、残りの時間を
  タイムアウトの引数に書き戻し（0 のタイムアウトには書き戻しません）、`ppoll` と
  `pselect6` は一時的なシグナルのマスクを受け取り、ハンドラはそのマスクで動きます。
  `select` は、集合の中の閉じた記述子に `EBADF` を返し、見る記述子は 1024 個
  （`FD_SETSIZE`）までです。Linux は `nfds` を記述子の表の大きさで切ります。

- `fcntl` の `F_GETFL` は、Linux が持つのと同じ状態フラグを返します。開いたときの
  フラグから `O_CLOEXEC`、`O_CREAT`、`O_EXCL`、`O_NOCTTY`、`O_TRUNC` を除き、パスで
  開いたファイルと memfd には `O_LARGEFILE` を加えます。`O_PATH` のファイルは
  `O_DIRECTORY`、`O_NOFOLLOW`、`O_PATH` だけを持ちます。パイプ、ソケット、カーネル
  自身のファイルには、パスで開いたとき（`/proc/self/fd` のリンク、`/dev/stdout`）を
  除いて `O_LARGEFILE` がありません。

- `O_PATH` のディスクリプタはパスだけを持ち、Linux の `fdget` と同じく受け付けません。
  読み書き、`lseek`、`flock`、`getdents`、`getdents64`、`sendfile`、`copy_file_range`、`splice`、`tee`、`vmsplice`、`fsync`、
  `fdatasync`、`syncfs`、`sync_file_range`、`fadvise64`、`readahead`、`ftruncate`、`fallocate`、`mmap`、`ioctl`、`f*xattr` の
  呼び出し、`epoll_ctl`（epoll のディスクリプタとしても対象としても）、`epoll_wait`、`fcntl`（`F_DUPFD`、`F_DUPFD_CLOEXEC`、`F_DUPFD_QUERY`、
  `F_GETFD`、`F_SETFD`、`F_GETFL` を除く）は `EBADF`、`poll` は `POLLNVAL` で、
  `select` は準備ができたものとみなします。`fstat`、`fstatfs`、`fchdir`、`dup`、
  `close` は受け付け、`*at` の呼び出しではディレクトリになります。

- `fcntl` のバイト範囲のロックを、Linux の `fs/locks.c` と同じく扱います。記述子の表
  （Linux の `files_struct` と同じく、プロセスのもので、そのスレッドと `CLONE_FILES` で
  clone した子が共有します）が持つレコードロック（`F_SETLK`、`F_SETLKW`、`F_GETLK`）と、開いたファイルの記述が持つ OFD ロック
  （`F_OFD_SETLK`、`F_OFD_SETLKW`、`F_OFD_GETLK`）で、互いにぶつかります。ある範囲のロックは、
  `posix_lock_inode` と同じく、そこにある持ち主自身のロックを置き換え、分け、まとめます。
  `F_GETLK` は、最初にぶつかるロックを掛けたプロセスの PID（記述のロックは -1）とともに返し、なければ
  `F_UNLCK` を返します。引数は `fcntl_getlk` と `fcntl_setlk` の順に確かめます（whence、
  `EINVAL` か `EOVERFLOW` になる範囲、種類、記述子のアクセスで許されない種類の `EBADF`、
  OFD ロックの `l_pid`）。表のレコードロックは、その表を使うタスクがそのファイルの記述子を
  どれか閉じるか、表を使う最後のタスクが終わると外れ、`fork` や `execve` では外れません。
  ほかのタスクと共有する表で exec、`unshare(CLONE_FILES)`、`CLOSE_RANGE_UNSHARE` をすると、
  呼んだ側はそのロックを持たない写しを得ます。記述のロックは、最後の記述子が
  閉じると外れます。`F_SETLKW` は範囲が空くまで待ち、互いを待つ表のレコードロックが
  （10 個までで）輪になるなら `EDEADLK` を返します。待ちがこの判定に数えられるのは、待っている
  ロックがそのままの間だけです。そのロックを外す、変える、閉じると、`locks_wake_up_blocks` と
  同じく、待つ側がまだ動き出す前でもその待ちはすぐ数えられなくなります。ロックはゲストだけのもので、ホストの
  プログラムからは見えず、ゲストからもホストのロックは見えません。

- パイプは Linux と同じく 64 KiB を持ちます。`fcntl` の `F_SETPIPE_SZ` と
  `F_GETPIPE_SZ` は、`pipe_set_size` と同じように大きさを変えて返します。大きさは
  1 ページ以上の 2 のべき乗で、読まれていないデータより小さくすると `EBUSY`、
  2³¹ を超えると `EINVAL` です。

- `SOCK_DGRAM` の組は、`SOCK_SEQPACKET` と同じくメッセージの区切りを保ちますが、
  ファイルの終わりがありません。相手が閉じると、読み込みは待ち続け、次の送信は
  `ECONNREFUSED`、その後は `ENOTCONN` になります。その送信は、下と同じく、その端が
  読んでいないものを捨てます。`EPIPE` で `SIGPIPE` を送るのは、
  Linux と同じく `SOCK_STREAM` だけです。

- `socket(AF_UNIX)` は、Linux の `af_unix.c` と同じく、`SOCK_STREAM` か
  `SOCK_SEQPACKET` のソケットを作ります。抽象名前空間の名前（0 で始まる `sun_path`）に
  `bind` し、ファミリーだけなら空いている 5 桁の 16 進の名前に `bind` し、待ち受けて
  受け付け、または同じ種類の待ち受けへ接続します。使われている名前は `EADDRINUSE`、
  待ち受けがなければ `ECONNREFUSED`、いっぱいの列へのノンブロッキングの接続は
  `EAGAIN`（ブロッキングなら `SO_SNDTIMEO` まで待ちます）、名前のない、または接続済みのソケットの `listen` と、
  待ち受けていない `accept` は `EINVAL`、もう一度の接続は `EISCONN` です。接続する前は、
  `poll` には書けて切れているように見え、何も送りません（`ENOTCONN`）。待ち受けは、
  接続が待っている間は読めて、`SO_ACCEPTCONN` を示します。`getsockname` と
  `getpeername` は名前を返し、受け付けたソケットは待ち受けの名前を持ちます。まだ受け
  付けていない接続も、もうデータを運びます。待ち受けを閉じるとその接続はリセットされ、
  クライアントの次の読み込みは `ECONNRESET` です。接続したあとは、ほかのすべてで
  ソケットのペアの端と同じです。Linux が種類と一緒にハッシュするのと同じく、名前は
  ソケットの種類ごとに持つので、ストリームとデータグラムのソケットは同じ名前に
  `bind` できます。

- AF_UNIX のソケットは、Linux の `unix_bind_bsd` と同じく、パスにも `bind` します。
  `bind` はそこにソケットファイル（`S_IFSOCK`、モードは 0777 から umask を引いたもの）を
  作ります。Linux のホストからマウントしたディレクトリにも作ります（[制限](./limitations)）。
  そのため、すでにあるパスは、宛先のないシンボリックリンクでも `EADDRINUSE` です。
  `getsockname` は、0 で終えたパスを返します。パスへの接続と送信は、`unix_find_bsd` と
  同じく、ファイルの inode でソケットを見つけます。シンボリックリンクを通しても、
  `rename` のあとでも見つかりますが、ファイルを `unlink` したあとは見つかりません。
  ソケットのファイルでないもの、ソケットが閉じたファイル（ファイルは残ります）は
  `ECONNREFUSED`、種類の違うソケットは `EPROTOTYPE` です。ソケットファイルを開くと
  `ENXIO` で、`readdir` はそれを `DT_SOCK` と示します。

- `socket(AF_UNIX, SOCK_DGRAM)`（と、Linux が同じものを作る `SOCK_RAW`）は、
  Linux の `unix_dgram_*` と同じく、上と同じように `bind` し、名前のソケットへ
  `sendto` で、または接続したソケットへ送るデータグラムのソケットを作ります。その名前の
  ソケットがなければ `ECONNREFUSED`、接続していないのにアドレスがなければ `ENOTCONN`、
  ほかのソケットに接続している（なくなったソケットでも）ソケットへは `EPERM`、自分の書き
  込みか受け手の読み込みを止めたあとは `EPIPE` です。受け手のキューは、送り手自身のもの
  か送り手に接続しているものでなければ、`net.unix.max_dgram_qlen` の 10 個を超えると
  いっぱいです。そのときノンブロッキングの送信は `EAGAIN`、ブロッキングの送信は
  `SO_SNDTIMEO` まで待ち、接続している送り手は `poll` に書けないように見えます。
  待っているデータグラムは、読まれるか捨てられるか受け手がなくなるまで、x86-64 の
  Linux 7.0 がその `sk_buff` の `truesize` として数える分（`sk_wmem_alloc`）を送り手の
  送信バッファから取り、`SIOCOUTQ` はその合計を返します。それが `SO_SNDBUF` 全体に
  達している間は、送信は `EAGAIN` になるか待ちます。送り手が `poll` に書けるように
  見え、待っている送信が起きるのは、その 4 分の 1 が空いてから（`unix_writable`）か、
  待ちの `SO_SNDTIMEO` が過ぎたときで、そのとき送信はもう 1 度確かめます。`SO_SNDBUF` から
  32 バイト引いた長さを超えるデータグラムは `EMSGSIZE` です。受け手が読んでいない
  バイト数では抑えません。パケットのソケット（`SOCK_SEQPACKET`）のメッセージも、
  Linux の `unix_seqpacket_sendmsg` が `unix_dgram_sendmsg` で送るのと同じく、同じ分を
  取り、同じく待ちます。長さは送信の停止（`EPIPE`）より先に確かめます。
  `AF_UNSPEC` のアドレスへの `connect` は接続を切り、何度でも接続し直せます。接続している
  ソケットがなくなると、次の送信は `ECONNREFUSED`、その後は `ENOTCONN` です。ほかの
  ソケットか `AF_UNSPEC` への接続や、その拒まれた送信で接続が切れると、Linux の
  `unix_dgram_disconnected` と同じく、そのソケットが読んでいないデータグラムを捨て、
  それが渡すディスクリプタを閉じます。捨てたものがあり、前の相手が接続し返していれば、
  前の相手は `ECONNRESET` を受けます。それは次の読み込み（キューにあるものより先）か
  送信か `SO_ERROR` が 1 度だけ返し、それまでは `poll` に `POLLERR` として見えます。資格情報を
  受け渡すソケットは、接続するときか送るときに自動で `bind` されます。`listen` と
  `accept` は `EOPNOTSUPP` で、`unix_dgram_connect` は何も記録しないので、接続していても
  いなくても `SO_PEERCRED` はどのプロセスも示さず（プロセス 0、ID は -1）、`SO_PEERPIDFD`
  は `ENODATA` です。データグラムのソケットのペアの端は、ほかのペアと同じく組を作った
  プロセスを示します。ソケットのペアのデータグラムの端も名前へ送れます。

- `socketpair(AF_UNIX)` は、Linux の `unix_socketpair` と同じく、名前がなく互いに
  接続した 2 つのソケットを作ります。そのほかは、それぞれその種類のソケットと同じです。
  どちらも上と同じく `bind` でき、そのあとは相手の `getpeername` と、そのソケットが
  送ったものがその名前を返します。ペアのストリームとパケットのソケットは、もう接続
  しません（その名前で待ち受けがあれば `EISCONN`）。データグラムのソケットは、ほかの
  データグラムのソケットと同じく、別のソケットや `AF_UNSPEC` へ接続し直し、上と同じく
  もう一方の端との接続を切ります。

- `recvmsg` と `recvfrom` は、Linux の AF_UNIX のソケットと同じくフラグを扱います。
  `MSG_PEEK` はデータを残し、受け渡すディスクリプタの写しを渡します。`MSG_WAITALL` は、
  ストリームの終わりやディスクリプタが来るまで、またはデータを受け取ったあとにシグナルが
  来るまで、ストリームのバッファを満たします。ただし `MSG_PEEK` と一緒なら、見つけた分を
  返し、続きを待ちません。`MSG_TRUNC` はメッセージの全体の長さを
  返します。`sendmsg` と `sendto` は `MSG_NOSIGNAL` と `MSG_DONTWAIT` を扱います。
  データグラムとパケットのソケットへの `MSG_OOB` は `EOPNOTSUPP` です。ほかのフラグは、
  Linux と同じく何もしません。これらが返すアドレスは、Linux の `unix_copy_addr` と
  同じく、読んだときに送ったソケットが持っている名前で、そのソケットがなくなったあとも
  同じです。渡された場所に収まる分だけ書き、長さは全体の長さです。名前のないソケットの
  アドレスの長さは 0 です。

- `sendmmsg` と `recvmmsg` は、Linux の `__sys_sendmmsg` と `do_recvmmsg` と同じく、ベクターの
  メッセージを 1 つずつ `sendmsg` と `recvmsg` と同じように送受信し（どのソケットでも）、
  それぞれのバイト数を `msg_len` に書きます。`MSG_CMSG_COMPAT` は `EINVAL` です。`sendmmsg` は
  最大 1024 個を送り、一部しか送れなかったメッセージのあとで止まります。どちらもエラーで
  止まり、1 つも送受信できなかったときだけエラーを返し、それ以外は数を返します。
  `MSG_WAITFORONE` は最初のメッセージだけを待ち、`recvmmsg` は帯域外データのあとで止まります。
  タイムアウトは記述子より先に読み（`EFAULT`）確かめます（`EINVAL`）が、Linux と同じく各
  メッセージのあとにしか見ないので、最初のメッセージはそれなしに待ちます。メッセージが
  届いたら、残りの時間を書き戻します。`recvmmsg` は、`MSG_ERRQUEUE` でエラーキューを
  求めないかぎり、まずソケットに残っているエラーを返します。いくつかのメッセージのあとの
  `EAGAIN` 以外のエラーは、そのソケットのエラーとして残り、次の呼び出しか `SO_ERROR` が
  返します（シグナルでやり直す待ちなら、Linux と同じく `ERESTARTSYS` の 512 が残ります）。
  データグラムやパケットのソケットの受信もキューより先にそれを返し、AF_UNIX のストリームは、
  Linux の `unix_stream_read_generic` と同じく、キューが空になってから返します。

- 読まれていないメッセージだけが持っているソケットは、Linux のガベージコレクタ
  （`unix_gc`）がソケットのなくなるときに閉じるのと同じく閉じられます。自分のキューで
  ディスクリプタが待っているソケットや、そうして互いを持ち合うソケットは、ディスクリプタが
  どれも持たなくなれば、キューの中のディスクリプタと一緒に閉じられます。開いている
  ソケットのキューが持っているものは残ります。Linux の `unix_edge_successor` と同じく、
  待ち受けのまだ受け付けていない接続が持っているものは、待ち受けが持っているものとして
  数えます。そうした接続だけが持っている待ち受けはゴミとして、接続が持っているものと
  一緒に閉じられ、その接続のクライアントはリセットされます。

- ストリームへの書き込みは、Linux の `unix_stream_sendmsg` と同じく、いくつかの部分に
  分けて送ります。1 つの部分は最大 36544 バイト（1 ページの先頭部分と 32 KiB のページ）、
  または送信バッファの半分から 64 バイトを引いた大きさです。送信バッファは `SO_SNDBUF` が
  2 倍にして設定し、読み出す値なので、`SO_SNDBUF` を 10000 にすると 1 つの部分は 9936 バイトです。
  ディスクリプタは最初の部分と一緒に渡るので、それを受け取る読み込みはそこで止まります。
  部分ごとに `O_ASYNC` の持ち主へシグナルを送ります。データグラムとパケットのメッセージは
  分けません。部分と帯域外のバイトは、すべて読まれるまで、データグラムと同じく x86-64 の
  Linux 7.0 がその `truesize` として数える分（3776 バイトまでの先頭部分と、残りの
  ページ単位の分）を送り手の送信バッファから取ります。部分はバッファに空きがある間だけ
  送るので、ノンブロッキングの送信は一部だけを送ることがあります。満杯の送り手の待ち方、
  `poll` での書ける条件、`SIOCOUTQ` もデータグラムのソケットと同じです。相手が読んで
  いないバイト数では抑えません。

- ストリームは、Linux 7.0 の AF_UNIX と同じく帯域外のデータを持ちます。`MSG_OOB` を
  付けた送信では、ほかのデータのあとに、最後の 1 バイトが帯域外のバイトになります
  （空の送信は `EOPNOTSUPP`）。まだ読まれていない前のバイトは、ふつうのデータになります。
  読み込みは印の手前で止まり、印は `SIOCATMARK` でわかります。`poll`、`select` の例外の
  集合、`epoll` には `POLLPRI` が出ます。`MSG_OOB` を付けた `recv` がそのバイトを取り
  （ないときは `EINVAL`）、`MSG_PEEK` なら残します。何も読まないうちに印に着いた読み込みは、
  そのバイトを捨てて先を読みます。`SO_OOBINLINE` なら、そのバイトをふつうのデータとして
  読みます（そのとき `MSG_OOB` を付けた `recv` は `EINVAL`）。1 バイトの帯域外の送信が
  受け渡すディスクリプタは、渡されずに閉じられます。帯域外のバイトは、受け取る側の
  持ち主に `SIGURG` を送ります（下のシグナル駆動の入出力を見てください）。

- Linux と同じくシグナル駆動の入出力を扱います。`fcntl` の `F_SETOWN` で、どのファイルにも
  持ち主を決められます。
  - プロセス、または負の値でプロセスグループ
  - `F_SETOWN_EX` では、1 つのスレッドも

  Linux と同じく ID で探すので、どの種類の持ち主でも、その ID のスレッド、プロセス、
  グループ、セッションがなければ `ESRCH` です。`F_GETOWN` と `F_GETOWN_EX` で
  読み出し、その役割のもの（たとえばプロセスのいないグループ）がない間は 0 です。
  `F_SETSIG` で送るシグナルを選びます。`O_ASYNC` を持てるのはパイプ、ソケット、
  疑似端末、inotify のインスタンス、それにパイプ、ソケット、端末のどれかであるときの
  ホストの標準のストリームだけで、ほかのファイルでは
  `F_SETFL` が落とし、`FIOASYNC` で付けようとすると `ENOTTY` です。`O_ASYNC` を付けた
  パイプ、ソケット、疑似端末（疑似端末は後述のとおり）は、持ち主にカーネルから
  `SIGIO` を送ります。inotify のインスタンスは、`fsnotify_insert_event` の
  `kill_fasync` と同じく、溜めたイベント 1 つごとに `POLL_IN` を送ります（直前の
  イベントにまとめたものでは送りません）。`F_SETSIG` があれば代わりにそのシグナルを送り、`si_code`
  （`POLL_IN`、`POLL_OUT`、`POLL_ERR`、`POLL_PRI`、`POLL_HUP`）、`si_band`、`si_fd`（`O_ASYNC` を
  付けたディスクリプタ）を付けます。
  - **パイプ**：書き込みは、終わるときに読む側へ送ります（いっぱいで書けなかったときも
    送ります）。待つときは、待つたびに、その前にも送ります。読み込みは、データがあってもなくても、
    終わるときに書く側へ送ります。どちらかの端を閉じると、もう一方へ送ります。
  - **ソケット**：送信すると相手へ送ります。ストリームとパケットのソケットでは、書き込みの
    `shutdown` でも、閉じたときも送り、閉じたときは切断（ハングアップ）になります。データグラムの
    ソケットでは、どちらでも送りません。バッファが
    いっぱいで送れなかった側には、読み込みでバッファの 4 分の 3 が空いたときに 1 回送ります。
    データグラムとパケットのソケットでは、いっぱいのときに `poll`、`select`、`epoll_ctl` で
    書き込めるかを尋ねた側にも同じように送ります。`epoll_wait` で尋ねた側にも送りますが、
    Linux と同じく、尋ねるのは準備ができた一覧にあるものだけです。一覧に載るのは、追加した
    ときに準備ができていたもの、起こされたもの、レベルトリガーで報告したあとのものです
    （エッジトリガーで報告したものは載り直しません）。どちらも、`O_ASYNC` が付いている間に
    起きたものだけが対象です。
    帯域外のバイトは `POLL_PRI` のシグナルも送ります。
  - **ホストの標準のストリーム**：エミュレーターの外で変わるので、`O_ASYNC` が付いている
    間はスレッドが 10 ms ごとに見て、準備ができていなかったものが準備できるたびに送ります。読み書きが
    `EAGAIN` を返したあとなら、どんなに早くても送ります。それ以外で、それより短い間だけ満杯や空
    だったストリームは見逃され、シグナルが出ないことがあります。
    標準入力は入力や終わりを見つけたときに `POLL_IN`、標準出力と標準エラーは、いっぱい
    だったところに空きができたときに `POLL_OUT` です。`F_SETFL` は標準のストリームそれぞれの状態フラグ
    （`O_NONBLOCK`、`O_APPEND` など）を持ち、ホストのディスクリプタには届けません。
    `O_NONBLOCK` を付けると、何もない標準入力の読み込みは `EAGAIN` で、ホストに空きの
    ない標準出力や標準エラーへの書き込みも `EAGAIN` です。
  - **TCP と UDP のソケット**（[ネットワーク](#network)）：Linux の TCP と同じように
    送ります。接続が開くと `POLL_OUT`、失敗すると `POLL_ERR`、データが届くと
    `POLL_IN` です。相手の終わりが届くと `POLL_IN`（こちらも閉じていれば `POLL_HUP`）を
    送り、続けて `POLL_IN` を送ります。送信や `poll` がバッファをいっぱいと見たあとは、
    空きができたときに `POLL_OUT` を 1 回送ります。DNS の代わりの答えは、用意できた
    ときに `POLL_IN` を送り、ゲストのソケットからのデータグラムも、届いたときに
    `POLL_IN` を送ります。接続した UDP のソケットへのループバックの ICMP の答えは
    `POLL_ERR` を送ります。ループバックの緊急のバイトは、`SIGURG` のあとに `POLL_PRI` を
    送ります。
  - **待っている読み手**：ストリームで読み込みが待っているときは、その待ちを終わらせるデータ、
    終わり、切断のシグナルを送りません。Linux もそのときは送りません
    （`SOCKWQ_ASYNC_WAITDATA`）。分けて送る送信では、送らないのは最初の分だけです。
    ただし Linux が送らないのは読み手がまだ動いていないときだけです（読み手を起こしてから
    確かめるため）。そのため送信でも、相手が `shutdown` したときや閉じたときでも、Linux では
    送ることがありますが、エミュレータは送りません。データグラムとパケットの
    ソケットの読み手には送ります。

- `setsockopt` と `getsockopt` は、Linux の `sk_setsockopt` と `sk_getsockopt` と同じく、
  既定の値やチェックも含めて `SOL_SOCKET` のオプションを扱います。4 バイトに満たない
  `int` の値は `EINVAL`、読み出す値は渡された長さで切り、ほかのレベルは `EOPNOTSUPP`、
  知らないオプションは `ENOPROTOOPT` です。`SO_TYPE`、`SO_DOMAIN`、`SO_PROTOCOL`、
  `SO_ERROR`、`SO_ACCEPTCONN`、`SO_PEERCRED` と `SO_PEERPIDFD`（相手のプロセス。下を参照）は
  読むだけです。
  `SO_SNDBUF` と `SO_RCVBUF` は 2 倍にして、Linux の下限と上限に収め、`SO_LINGER` は
  `struct linger` を受け取ります。

- `SO_PASSCRED` を設定すると、Linux の AF_UNIX と同じく、メッセージが資格情報を運びます。
  どちらかの端に設定があるときに送ったメッセージは、送り手のプロセス ID、実ユーザー、
  実グループを運びます。`SCM_CREDENTIALS` を渡したときは、その値を運びます。設定のある
  受け手は、それを `SCM_CREDENTIALS` のメッセージで、ディスクリプタより先に受け取ります。
  資格情報なしで送ったメッセージは、プロセス 0、ユーザーとグループ 65534 として読めます。
  そのような受け手のストリームの読み込みは、`read` と `MSG_WAITALL` も含めて、資格情報の
  違う書き込みをまとめて読みません。`SCM_CREDENTIALS` は `struct ucred` をちょうど 1 つ
  持つ必要があり（違えば `EINVAL`）、どちらの ID も -1 にはできません（`EINVAL`）。
  呼び出し側のプロセス以外を示すには `CAP_SYS_ADMIN`、自分の実、実効、保存ユーザー ID
  以外を示すには `CAP_SETUID`、自分のグループ ID 以外を示すには `CAP_SETGID` が要ります
  （なければ `EPERM`）。そのあとでプロセスを探し、なければ `ESRCH` です。

- `SO_PASSPIDFD` を設定すると、`SO_PASSCRED` と同じようにメッセージが資格情報を運び、
  設定のある受け手は、送り手のプロセスの pidfd（close-on-exec）を `SCM_PIDFD` の
  メッセージで受け取ります。Linux 7.0 と同じく、ディスクリプタのあとに来ます。pidfd を
  作るのは、そのメッセージ全体が制御のバッファに入るときだけです。入らないときは
  メッセージを失い（`MSG_CTRUNC`）、ディスクリプタも作りません。どちらの端も資格情報を
  渡していないときに送ったメッセージは、何も運びません。`SO_PEERCRED` と
  `SO_PEERPIDFD` は、Linux が記録するのと同じく相手のプロセスを示し、`SO_PEERCRED` は
  そのときの実効 ID も示します。ペアでは、
  両方の端で組を作ったプロセスです。`socket()` で作ったソケットでは、待ち受けるか接続する
  までは何も示しません（プロセス 0、ID は -1、`SO_PEERPIDFD` は `ENODATA`）。待ち受けでは
  `listen` を呼んだプロセス（`init_peercred`）、受け付けたソケットでは接続したプロセス、
  クライアントでは待ち受けのプロセス（`copy_peercred`）です。`SO_PEERPIDFD` は、その
  プロセスの新しい pidfd を読み出します。渡した長さに番号の一部しか入らなくても、
  pidfd は作ります。読み出すだけのオプションで、`setsockopt` は `ENOPROTOOPT` です。

- `SO_PASSSEC` は Linux と同じく設定でき、読み出せます。設定のある受け手が制御の
  バッファなしで受け取ると `MSG_CTRUNC` になります。`SCM_SECURITY` のメッセージは
  来ません。AF_UNIX に送り手のコンテキストを渡すセキュリティモジュールのない Linux
  （モジュールなし、または AppArmor）と同じです。

- `SO_PASSRIGHTS` は、Linux 6.16 以降と同じく、新しい AF_UNIX のソケットでは
  有効です。0 にするとソケットはディスクリプタを受け取らず、それを渡す送信は
  `EPERM` になります。シャットダウンの `EPIPE` よりあと、キューが満杯の `EAGAIN`
  より先です。ストリームで 0 バイトを送るときは何も渡さないので、0 を返します。
  すでに待っているディスクリプタは読めます。

- 待ち受けが受け付けたソケットは、クライアントが接続したときの待ち受けの
  `SO_PASSCRED`、`SO_PASSPIDFD`、`SO_PASSSEC`、`SO_PASSRIGHTS` を引き継ぎます。
  inet のソケットでは、Linux が AF_UNIX でしか受け付けないので、この 4 つは
  設定も読み出しも `EOPNOTSUPP` です。

- `SO_RCVTIMEO` と `SO_SNDTIMEO`（と `_NEW` の形）は、Linux と同じく、そのソケットでの
  `recv`、`read`、`send`、`write` が待つ時間を限ります。限りを過ぎると `EAGAIN`、または
  そこまでに動かした分を返し、`MSG_WAITALL` もそこで止まります。0 の `timeval` は
  いつまでも待ち、負の値は待ちません。1 秒を超えるマイクロ秒は `EDOM` です。値は
  1000 Hz の時計の刻みで持つので、読み出すとミリ秒に切り上がっています。そのような待ちを
  シグナルが終わらせると `EINTR` になり、Linux の `sock_intr_errno` と同じく
  `SA_RESTART` でもやり直しません。

- `SO_RCVLOWAT` を設定すると、Linux の `sock_rcvlowat` と同じく、ブロックするストリームの
  `recv` や `read` は、その量のバイトが揃うか、バッファが一杯になるまで待ちます。ストリームの
  終わり、時間切れ、ディスクリプタの到着では、それより少なくても返します。`MSG_PEEK`、
  ブロックしない読み込み、`poll`、データグラムとパケットのソケットは待たせません。0 は 1、
  負の値は `INT_MAX` として扱います。

- `SO_PEEK_OFF` は、Linux の `sk_peek_off` と同じく、`MSG_PEEK` が読み始める位置を決めます。
  覗くたびに読んだ分だけ進み、読み込むたびに取った分だけ戻ります（0 より下には戻りません）。
  データグラムとパケットのソケットでは、メッセージ単位で先へ進み、一度覗いた空のメッセージも
  飛ばします。`MSG_TRUNC` は、そこから先のメッセージの長さを返します。どんな値も受け付け、
  負の値（既定は -1）では位置を使いません。

- `SO_TIMESTAMP` と `SO_TIMESTAMPNS`、それに `_NEW` の形は、Linux の AF_UNIX と同じく、
  メッセージにタイムスタンプを付けます。設定したデータグラムやパケットのソケットは、
  メッセージごとに実時間を制御メッセージで受け取ります。資格情報やディスクリプタより先に並び、
  `SO_TIMESTAMP` では `timeval`、`SO_TIMESTAMPNS` では `timespec` です。ほかの制御メッセージと
  同じく、制御バッファに収まる分に切ります。時刻は、受け手がそのときタイムスタンプを
  取っていれば送った時刻、そうでなければ最初に読むか覗いた時刻です。ストリームには付きません。
  `getsockopt` は、それぞれ自分の形で設定したときだけ 1 を返します。どれかを切っても、次に
  どれかを設定するまで `_NEW` の選択は残ります。

- `SO_TIMESTAMPING` とその `_NEW` の形は、Linux の知るフラグを受け付け、Linux の
  `sock_set_timestamping` と同じものを断ります。知らないフラグ、`OPT_ID` のない
  `SOF_TIMESTAMPING_OPT_ID_TCP`、`OPT_TSONLY` のない `OPT_STATS` は `EINVAL` です。
  PTP クロックは、デバイスに結び付けたソケットにしか結び付かないので `EOPNOTSUPP` です。
  `getsockopt` はフラグをクロックなしで返し、`_NEW` の形はそれで設定したときだけ返します。
  どちらを設定しても、`SO_TIMESTAMP` の `_NEW` の選択も決まります。Linux の AF_UNIX と同じく、
  `SO_TIMESTAMP` などが付けるタイムスタンプに足すもので、単独では何も付けません。
  その制御メッセージのあとに `SCM_TIMESTAMPING` が並び、フラグがソフトウェアの
  タイムスタンプを報告し、受信したものを除いていなければ、最初の `timespec` が同じ時刻です。
  ローカルのソケットどうしのメッセージには、ハードウェアのタイムスタンプは付きません。

- `mmap` と `shmat` は、マッピングを作り、ファイル、共有メモリ、セグメントを付ける
  までを、アドレス空間のロックを一度取る間に行います。Linux が `mmap_lock` の下で
  するのと同じです。`MAP_FIXED` や `SHM_REMAP` では、範囲にあったマッピングを外すのも
  同じ間に行います。そのため、ほかのスレッドがその間に範囲を取ることも、中身を付ける前の
  新しいマッピングを見ることもありません。ページキャッシュは、その前にロックの外で
  読みます。`MAP_FIXED_NOREPLACE` は、何かがマップされていれば、ファイルに尋ねる前に
  `EEXIST` になります。中身を付けられなかったときは、新しいマッピングを外し、置き換えた
  マッピングは戻りません。

- ファイルの `MAP_SHARED` のマッピングは、Linux と同じくファイルのページキャッシュを
  見せます。どのプロセスのものでも、そのファイルの共有マッピングはみな同じページを
  持ちます。そこへの書き込みは `read` にも、そのファイルのプライベートなマッピングにも
  見え、`write`、`ftruncate`、穴あけはマッピングに見える中身を変えます。ファイルの
  終わりより先への書き込みは、ファイルに入りません。このマッピングが書き込めるのも、
  `mprotect` で書き込めるようにできるのも、Linux と同じく、ファイルを読み書きの両方で
  開いたときだけです（ほかは `EACCES`）。

- ファイルの `MAP_PRIVATE` のマッピングは、まだ書いていないページでは同じページ
  キャッシュを見せます。そのため、そこではファイルの後の変更も見えます。ページに初めて
  書き込むと、Linux と同じく、そのページをそのプロセスだけのために写し取ります。`fork`
  した子とは、どちらもまだ書いていないページを共有します。ファイルを縮めて、写しが
  ファイルの終わりより完全に先になると、その写しは捨てられます。そのため、ファイルが
  また伸びればファイルを読み直します。Linux も同じく写しを捨てます。

- ファイルのマッピングで、ファイルの終わりより完全に先にあるページに触れると、
  プライベートでも共有でも、Linux と同じく `SIGBUS`（`BUS_ADRERR` とそのアドレス）に
  なります。そのようなメモリを渡したシステムコールは `EFAULT` で失敗します。終わりは
  ファイルに合わせて動きます。ファイルが伸びれば先のページも読めるようになり、縮めば
  前に読んだページでも `SIGBUS` になります。ファイルが一部だけを覆うページは、
  ファイルの終わりより先が 0 として読めます。

- `mincore` は、どのページがメモリにあるかを返します。プライベートなページと共有の
  無名メモリは読むか書いたあとから、ファイルのページはファイルの範囲内ならメモリに
  あるとします。Linux と同じく、マップされていない最初のページの手前まで書いて
  `ENOMEM` を返します。

- `cachestat`（Linux 6.5）は、バイト範囲（長さ 0 ならファイルの終わりまで）のうち、
  ファイルのページキャッシュにあるページを数えます。メモリ上のファイルは、tmpfs と同じく
  割り当て済みのページを持ち、tmpfs は印を付けないので dirty や書き戻し中のページはなく、
  スワップアウトしないので追い出されたページもありません。パイプ、ディレクトリ、`/proc`、
  マウントしたホストのディレクトリのファイルは、ここでは何も持ちません。Linux と同じく、
  ディスクリプタは `O_PATH` でなく（`EBADF`）、2 つの構造体は読み書きでき（`EFAULT`）、
  読み込み専用で開いたものは、呼び出し元がファイルの所有者か書き込めることが必要で
  （`EPERM`）、そのあとで未知のフラグが `EINVAL` です。

- `mlock`、`mlock2`、`munlock` は、Linux と同じように範囲を確かめます。長さはページ単位に
  切り上げ、アドレスの終わりを越える範囲は `EINVAL`、マップされていないページを含む範囲は、
  その前の VMA に新しい状態を付けてから `ENOMEM` です。ロック（`VM_LOCKED`、
  `MLOCK_ONFAULT` なら `VM_LOCKONFAULT` も）した部分は、`/proc/<pid>/maps` に見えるとおり
  別の VMA になります。ロックには 0 より大きい `RLIMIT_MEMLOCK`（`EPERM`）と、まだ
  ロックしていないページの分の空き（`ENOMEM`）が要ります。`CAP_IPC_LOCK` があれば
  要りません。`mlock` と、`MLOCK_ONFAULT` なしの `mlock2` は、そのあとページを
  割り当て、割り当てられないページ（`PROT_NONE`、ガードページ、ファイルの終わりより
  先）があれば `ENOMEM` を返します。書き込めるプライベートなマッピングのページは、
  Linux の `populate_vma_page_range` と同じく書き込んで取り込みます（`FOLL_WRITE`）。
  そこにあるファイルのページは自分だけのコピーになり、そのあとのファイルへの書き込みは
  見えなくなります。`MAP_POPULATE`、`MAP_LOCKED`、`MCL_CURRENT` の `mlockall`、
  ロックしたプライベートなマッピングを書き込めるようにする `mprotect` も同じです。
  `MLOCK_ONFAULT` や `MCL_ONFAULT` のロックは何も取り込みません。`mlockall` は `MCL_CURRENT` ですべてのマッピングを
  （マップしているもの全部が収まらなければ `ENOMEM`）、`MCL_FUTURE` で新しいマッピングを
  ロックします。そのあとの `mmap`、`brk`、広がる `mremap` には、`MAP_LOCKED` と同じく
  空きが要ります（`EAGAIN`。`brk` は区切りを変えません）。`munlockall` はどちらも
  外します。ロックした VMA は、`MADV_DONTNEED`、`MADV_FREE`、`MADV_COLD`、
  `MADV_PAGEOUT`、`MADV_REMOVE`、`MADV_GUARD_INSTALL` を断り（`EINVAL`。前の VMA は
  指定を受けたあとです）、`MS_INVALIDATE` の `msync` も断ります（`EBUSY`）。
  `MADV_DONTNEED_LOCKED` は受け付けます。`fork` の子と、`MREMAP_DONTUNMAP` が残す元の
  範囲はロックされず、AIO と `io_uring` のリングもロックされません。`mlock2` と
  `mlockall` の未知のフラグは `EINVAL` です。スワップアウトは起きないので、ほかに
  何もしなくてもメモリはそのまま残ります。

- `madvise`：`MADV_DONTNEED` を受けたプライベートなページは空になり、エントリーも
  なくなります。無名のページはそのあと 0 として読め、ファイルのマッピングのページは、
  Linux がファイルから読み込み直すのと同じく、次のアクセスでそのときのファイルの中身を
  読みます。`mremap` で動かしたあとも、`fork` した子でも同じです。プログラム自身の
  セグメントは Linux と同じ形で置きます。ファイルのデータを持つページはファイルの
  マッピングで、実行ファイルを読み直します。`mprotect` で書き込めるようにして
  書き換えた読み込み専用のセグメント（コード）も同じです。残り（`.bss`）は無名の
  メモリで、0 として読めます。共有メモリは自分の中身を保ち、Linux の zap と同じく
  エントリーを外します。shmem、System V 共有メモリ、ファイルの共有マッピングの
  ページは、次のアクセスでまたマップされます。`MADV_FREE` では
  中身を残します。メモリが足りているときの Linux と同じです。
  `MADV_WILLNEED` を受け付けます。`MADV_COLD` と `MADV_PAGEOUT`（回収するものが
  ないので、これもヒントです）も受け付け、どれも範囲がマップされていれば足ります
  （`ENOMEM`）。
  `MADV_DONTNEED_LOCKED` は `MADV_DONTNEED` と同じく捨てます。`MADV_POPULATE_READ` と
  `MADV_POPULATE_WRITE` は、読み込みや書き込みと同じようにページを割り当てます
  （ゼロページ、自分のページ）。どのマッピングにもないページ（`ENOMEM`）、マッピングが
  読めないか書けないページ（`EINVAL`）、ファイルの終わりより先のページ（`EFAULT`）で
  止まります。`MADV_DONTFORK` と `MADV_DOFORK`、`MADV_WIPEONFORK` と `MADV_KEEPONFORK`、
  `MADV_DONTDUMP` と `MADV_DODUMP`、アクセスの仕方のヒント（`MADV_NORMAL`、
  `MADV_SEQUENTIAL`、`MADV_RANDOM`）、`MADV_HUGEPAGE` と `MADV_NOHUGEPAGE`、KSM の
  `MADV_MERGEABLE`（共有メモリはそのままにします）と `MADV_UNMERGEABLE` は、範囲の
  VMA のフラグを付けたり外したりします（あとのものでページは変わりません）。
  VMA は、Linux と同じように前後の VMA から分かれたり、つながったりします
  （`/proc/<pid>/maps`）。VMA を順に処理し、受け付けない VMA があればそこで `EINVAL`
  で止まります（`MADV_WIPEONFORK` はプライベートの匿名メモリだけです）。範囲に穴が
  あれば、残りを処理してから `ENOMEM` を返します。`fork` の子は、`MADV_DONTFORK` の
  マッピングを受け継がず、`MADV_WIPEONFORK` のマッピングはページなしの、0 で埋まった
  新しいメモリとして受け継ぎます。そのフラグと `MADV_DONTDUMP` は子にも残ります。
  `MADV_DONTDUMP` のマッピングは、コアダンプに何も書きません。`MADV_REMOVE` は、
  共有メモリを、そのファイルに穴を開けて（`FALLOC_FL_PUNCH_HOLE` の `fallocate`）
  解放します。範囲は、そのメモリのどのマッピングでも 0 として読めるようになります。
  対象は、共有の匿名メモリ、System V の共有メモリ、書き込めるように開いたファイルの
  共有マッピング（読み込みだけのマッピングでも構いません。`VM_MAYWRITE`）です。
  ファイルのないメモリには `EINVAL`、プライベートか読み込みだけのファイルの
  マッピングには `EACCES` を返し、ファイルの確認で失敗すればそのエラーを返します。
  ほかの指定と同じく、VMA を順に処理します。`MADV_GUARD_INSTALL` は、Linux の
  ガード PTE マーカーと同じように、範囲のページをガードページにします。ページの
  内容はなくなり（ファイルのマッピングはファイルを読み直します）、ガードページに
  触れると、マッピングのない場所と同じく `SEGV_MAPERR` の `SIGSEGV` になります。
  システムコールのコピーは `EFAULT` になり、`MADV_POPULATE_READ` と
  `MADV_POPULATE_WRITE` も `EFAULT` を返します。ページを割り当てられない `mlock` は
  `ENOMEM` を返します。ガードは VMA を分けず、`MADV_DONTNEED` や重ねての指定の後も
  残ります。`fork` の子に受け継がれ（`MADV_WIPEONFORK` のマッピングを除きます）、
  `mremap` でページと一緒に移り、`munmap` でなくなります。`MADV_GUARD_REMOVE` は
  ガードを外し、内容のないページを残します。ページを捨てられない封印したメモリには
  ガードを置けません（`EPERM`）。Linux が `VM_DONTEXPAND` でマップする AIO と
  `io_uring` のリングは、どちらの指定も受け付けません（`EINVAL`）。ほかの指定には
  `EINVAL` を返します。

- `process_madvise` は、iovec の範囲を順に指定どおりにします。呼んだプロセス自身の
  メモリ（`PIDFD_SELF_THREAD`、`PIDFD_SELF_THREAD_GROUP`、自身かメモリを共有する
  プロセスの pidfd）には `madvise` と同じようにします。結果は、最初に失敗した範囲より
  前の範囲のバイト数で、それがなければその失敗のエラーです。ほかのプロセスのメモリに
  使えるのは `MADV_COLD`、`MADV_PAGEOUT`、`MADV_WILLNEED`、`MADV_COLLAPSE` だけで
  （`EINVAL`）、`CAP_SYS_NICE` が要ります（`EPERM`）。その範囲は、マップされていれば
  足ります（`ENOMEM`）。確かめる順は Linux と同じで、`flags`、iovec、pidfd（`EBADF`、
  `ESRCH`）、プロセスを読む権利（`EACCES`）、指定の順です。

- `process_mrelease` は、`process_madvise` と同じようにプロセスを探します（`flags` は
  0 で、そのあと `EBADF`、`ESRCH`）。終わったプロセス（ゾンビ）には、もうメモリが
  ありません（`ESRCH`）。そのメモリが解放されるところなら成功します。つまり、プロセスが
  終わりかけていて（命取りのシグナルを送られたか、終わり始めていて、コアダンプを書いていない）、
  そのメモリで動くほかのプロセスもみな同じときです。
  それ以外は、呼んだプロセス自身も含めて `EINVAL` です。Linux の `complete_signal` が
  送ったときにグループの終了を始めるのと同じく、次のシグナルは送ったときに命取りに
  なります。SIGKILL か、既定の動作がコアを書かずにプロセスを終わらせるシグナル
  （受け取った側がコアを書く SIGQUIT、SIGILL、SIGTRAP、SIGABRT、SIGBUS、SIGFPE、
  SIGSEGV、SIGXCPU、SIGXFSZ、SIGSYS を除きます）で、送り先のスレッド（またはプロセスの
  どれかのスレッド）がブロックしておらず、プロセスが止まっていないときです。メモリは
  プロセスの最後のスレッドが終わるときに解放されるので、それより早く解放するものは
  ありません。

- `mremap` は、後ろが空いていればその場で広げ、空いていなければ `MREMAP_MAYMOVE` で
  中身ごと動かします。`MREMAP_FIXED` と `MREMAP_DONTUNMAP` も使えます。共有のメモリは、
  動かしても `fork` した相手と共有したままです。ファイルのマッピングは、ファイルの
  続きの上へ広げられ、そのページは初めて触れたときに読み込みます。また、複数の
  マッピングにまたがる範囲を
  `MREMAP_FIXED` で動かすと、`EFAULT` になります（最近の Linux は動かせます）。
  AIO と `io_uring` のリングは固定のマッピング（`VM_DONTEXPAND`）で、広げられず
  （`EFAULT`）、動かして元を残すこともできません（`MREMAP_DONTUNMAP`、`EINVAL`）。
  AIO のリングは、Linux master の `aio_ring_mremap` と同じく丸ごとでなければ動かせず
  （行き先を空け、縮めて落とす分を外したあとで `EINVAL`）、コンテキストも一緒に移ります。

- `msync` は、引数と範囲を確かめ、`MS_SYNC` か `MS_ASYNC` なら共有のファイルの
  マッピングへの書き込みをファイルに書き戻します。

- `userfaultfd` は、登録したメモリでほかのスレッドが起こすフォールトをスレッドが
  さばくためのファイルを、Linux の `fs/userfaultfd.c` と同じに作ります。カーネル自身の
  フォールトも届くもの（`UFFD_USER_MODE_ONLY` なし）には `CAP_SYS_PTRACE` が要り
  （`vm.unprivileged_userfaultfd` が 0 なので `EPERM`）、これはフラグ（`EINVAL`）より
  先に確かめます。ファイルは読み出し用の `anon_inode:[userfaultfd]` で、誰が持っていても
  作られたアドレス空間のものです。`UFFDIO_API` はバージョンと機能を一度だけ受け取り
  （2 度目は `EINVAL`）、提供する機能と ioctl を書き戻します。失敗したときは 0 を
  書きます。提供する機能は `UFFD_FEATURE_PAGEFAULT_FLAG_WP`、`UFFD_FEATURE_SIGBUS`、
  `UFFD_FEATURE_THREAD_ID`、`UFFD_FEATURE_MINOR_SHMEM`、
  `UFFD_FEATURE_MINOR_HUGETLBFS`、
  `UFFD_FEATURE_EXACT_ADDRESS`、`UFFD_FEATURE_MISSING_SHMEM`、
  `UFFD_FEATURE_MISSING_HUGETLBFS`、`UFFD_FEATURE_WP_HUGETLBFS_SHMEM`、
  `UFFD_FEATURE_WP_UNPOPULATED`、`UFFD_FEATURE_POISON`、`UFFD_FEATURE_WP_ASYNC`、
  `UFFD_FEATURE_MOVE`、それにイベントの `UFFD_FEATURE_EVENT_FORK`、
  `UFFD_FEATURE_EVENT_REMAP`、`UFFD_FEATURE_EVENT_REMOVE`、
  `UFFD_FEATURE_EVENT_UNMAP` で（`HUGETLBFS` の
  ものは Linux と同じく示しますが、`MFD_HUGETLB` と `SHM_HUGETLB` は `ENOSYS` なので、
  登録する hugetlbfs のメモリはありません）、`UFFD_FEATURE_EVENT_FORK` には
  `CAP_SYS_PTRACE` が要ります（`EPERM`）。`UFFDIO_REGISTER` はプライベートな anonymous
  メモリ、共有の anonymous メモリ、shmem の memfd（Linux が VMA を shmem のものと
  数えない System V の共有メモリは除きます）の共有または
  プライベートなマッピングを、ないページについて登録し
  （`UFFDIO_REGISTER_MODE_MISSING`）、shmem（共有の anonymous メモリと memfd の
  マッピング）をマイナーフォールトについて登録し（`UFFDIO_REGISTER_MODE_MINOR`。示す
  ioctl に `UFFDIO_CONTINUE` が、`smaps` に `ui` が加わります）、プライベートな anonymous メモリと shmem を書き込み保護に
  ついて登録します（`UFFDIO_REGISTER_MODE_WP`。示す ioctl に `UFFDIO_WRITEPROTECT`
  が加わります）。`UFFD_FEATURE_WP_ASYNC` では、書き込み保護だけなら、
  `vma_can_userfault` と同じくどのメモリも登録します（ファイルのプライベートまたは
  共有のマッピングや System V の共有メモリも）。確かめることと順は Linux と同じで（範囲、次に各 VMA。登録できない
  ものは `EINVAL`、ファイルに書き込めない共有のものは `EPERM`、ほかの `userfaultfd` の
  ものは `EBUSY`）、モードは、VMA がすでに
  持っていなければその VMA のモードに置き換わります。登録した部分は
  `/proc/<pid>/maps` に見えるとおり VMA に分かれ、`smaps` に `um` と `uw` が
  つきます。`fork` した子と、`mremap` が動かしたマッピングには引き継がれず、
  `UFFDIO_UNREGISTER` とファイルを閉じることで外れます。ないページについて登録した
  ページでまだないもの（shmem では、そのページキャッシュにないもの。どのマッピングも
  持ち込んでおらず、ファイルも書き込みや割り当てで持っていないページで、ファイルの
  終わりより先のページは先に SIGBUS です）に命令が触れるか、
  書き込み保護について登録した範囲の保護されたページに書き込むと待ち、ファイルは
  そのフォールトを古い順に `uffd_msg` として読みます。書き込みかどうか、保護された
  ページなら `UFFD_PAGEFAULT_FLAG_WP`、ページのアドレス
  （`UFFD_FEATURE_EXACT_ADDRESS` ではアドレスそのもの）、`UFFD_FEATURE_THREAD_ID`
  ではスレッドの ID が入ります。待ちは、`UFFDIO_COPY` か `UFFDIO_ZEROPAGE` がページを
  埋めたときか `UFFDIO_WRITEPROTECT` が保護を解いたとき（`DONTWAKE` でなければ）、
  `UFFDIO_WAKE` がその範囲を取ったとき、`UFFDIO_UNREGISTER` がないページについて
  登録した範囲からそれを取ったとき、ファイルが閉じられたとき、シグナルが来たときに
  終わり、命令は、Linux がフォールトをやり直すのと同じくもう一度動きます。
  `UFFD_FEATURE_SIGBUS` では待たずに SIGBUS（`BUS_ADRERR`）にします。
  `UFFDIO_WRITEPROTECT` は、`mwriteprotect_range` と同じく VMA ごとに、範囲のページを
  保護するか保護を解きます。どの VMA も書き込み保護について登録したものでなければ
  ならず（`ENOENT`。それより前の VMA は変わったあとです）、保護するときは
  `DONTWAKE` を受け付けません（`EINVAL`）。プライベートな anonymous メモリの
  エントリーのないページは、Linux に present の PTE がないので、
  `UFFD_FEATURE_WP_UNPOPULATED` のときだけ保護します。読んだだけのページは Linux の
  ゼロページで、保護します。shmem のエントリーのないページはいつも保護します。
  そうしたページには Linux の uffd-wp マーカーがつき、`/proc/<pid>/pagemap` は
  ビット 57 のついたスワップエントリーとして示します。アクセスがそのページに作る
  エントリーは書き込み保護されるので、書き込みはページが入ってからフォールトします。
  `MADV_DONTNEED` は、ほかの共有マッピングと同じく、ページキャッシュにページを残したまま
  shmem のエントリーを外し、
  `zap_install_uffd_wp_if_needed` と同じく、保護されていたものにはマーカーを残します。
  プライベートな anonymous メモリの `MADV_DONTNEED` はマーカーを消します。埋める操作と
  `UFFDIO_CONTINUE` はマーカーに置き換わり、保護は自分のモードによるものだけです。
  プライベートな anonymous メモリの `UFFDIO_ZEROPAGE` と `UFFDIO_POISON` はそこでは
  `EEXIST` です。`mprotect` は保護を残し、許さない書き込みはこれまでどおり SIGSEGV です。
  （そのイベントの機能がないときの）`fork` した子と `mremap` による移動、
  `UFFDIO_UNREGISTER`、ファイルを閉じること、書き込み保護のモードを置き換える登録で
  保護は外れます。
  `UFFD_FEATURE_WP_ASYNC`（`/proc/<pid>/fdinfo` が示すとおり
  `UFFD_FEATURE_WP_UNPOPULATED` を伴います）では、書き込み保護されたページへの
  書き込みは、命令のものもシステムコールのものもフォールトせず、`do_wp_page` と
  同じくページの保護を外して進みます。そのため `/proc/<pid>/pagemap` のビット 57 で、
  `UFFDIO_WRITEPROTECT` から書き込まれたページがわかり、`PAGEMAP_SCAN`（後述）で
  それらを探して保護し直せます。ファイルのプライベートなマッピングや共有
  マッピング、System V 共有メモリの `MADV_DONTNEED` は、shmem と同じく、まだ保護されているページに
  マーカーを残します。そこを埋める操作は、anonymous メモリでも shmem でもないので
  `EINVAL` です。`UFFDIO_COPY` と
  `UFFDIO_ZEROPAGE` は `mfill_atomic` と同じく 1 ページずつ埋めます。1 つの登録した
  VMA に収まらない範囲は `ENOENT`、ページのあるところは `EEXIST`、読めないコピー元は
  `EFAULT`、shmem のファイルの終わりより先のページも `EFAULT` で、途中で止まると、埋めた分を構造体の最後のフィールドに入れて `EAGAIN`
  です。`UFFDIO_COPY_MODE_WP` は書き込み保護したページを埋め、範囲は書き込み保護に
  ついて登録したものでなければなりません（`EINVAL`）。shmem のファイルの共有の
  マッピングを埋めるときは、ファイルのページキャッシュにページがあれば `EEXIST` で、
  ページはファイルに入り、`read` からも見えます。プライベートなマッピングを埋めると、
  マッピングが自分のページを持ち、ファイルは変わりません。`UFFDIO_POISON`
  （`UFFD_FEATURE_POISON`）は、登録した範囲のページを同じやり方で poison にします。
  モードは `DONTWAKE` だけで、このマッピングにページかガードがあるところは `EEXIST`
  です。poison にしたページへのアクセスは、Linux の poison マーカーが
  `VM_FAULT_HWPOISON` を返すのと同じく、保護の確認の後、範囲がまだ登録されているか
  どうかにかかわらず、`BUS_MCEERR_AR` と `si_addr_lsb` 12 の SIGBUS を起こします。
  そこへのシステムコールのコピーは `EFAULT`、`MADV_POPULATE_READ` は `EHWPOISON` で、
  `/proc/<pid>/pagemap` はスワップエントリーとして示します。
  `UFFDIO_COPY` は、Linux の `mfill_atomic_install_pte` がマーカーを受け付けるのと同じく、
  poison にしたページを代わりに埋め、shmem の `UFFDIO_ZEROPAGE` も同じです。
  プライベートな anonymous メモリの `UFFDIO_ZEROPAGE` はそこでは `EEXIST` です。
  poison は `mprotect` と `UFFDIO_UNREGISTER` では残り、`mremap` では一緒に動き、
  `fork` した子には、プライベートなメモリでは引き継がれ、共有メモリでは引き継がれず、
  `MADV_DONTNEED`、`MADV_FREE`、`MADV_GUARD_INSTALL`（ガードに置き換わります）、
  `munmap` で消えます。マイナーフォールトは、Linux の `shmem_get_folio_gfp` が
  フォリオを見つけて `handle_userfault` が `VM_UFFD_MINOR` を取るのと同じく、ページ
  キャッシュにあるのにマッピングにエントリーのない shmem のページへのアクセスです。
  メッセージには `UFFD_PAGEFAULT_FLAG_MINOR` が入り、範囲がないページについても
  登録されていなければ、穴はそのまま取り込みます。`UFFDIO_CONTINUE` は
  `mfill_atomic_pte_continue` と同じく、ページキャッシュのページを 1 ページずつ範囲に
  対応付けます。shmem でないメモリ、`DONTWAKE` と `WP`（書き込み保護のモードが要ります）
  以外のモード、ファイルの終わりより先のページは `EINVAL`、ページキャッシュにない
  ページは `EFAULT`、マッピングにあるページは `EEXIST` です。プライベートな
  マッピングは、`mfill_atomic_install_pte` が読み出し専用で対応付けるので、書き込む
  までそのページを見せ、`UFFDIO_CONTINUE_MODE_WP` は書き込み保護して対応付けます。
  `MADV_DONTNEED` は shmem のマッピングのエントリーを外すので、そのページはまた
  マイナーフォールトになります。`UFFDIO_MOVE` は、Linux の `move_pages` と同じく、
  コンテキスト自身のアドレス空間（ほかの空間からは `EINVAL`）のプライベートな
  anonymous のページを、登録した範囲へ動かします。`UFFD_FEATURE_MOVE` を求めたか
  どうかは問いません。それぞれの先頭が VMA にあること（`ENOENT`）、どちらの VMA も
  共有でなく、それぞれの範囲を丸ごと持ち、保護が同じで書き込めること、どちらも
  ロックしているかどちらもしていないこと、動かし先がこの `userfaultfd` に登録した
  もので、どちらも anonymous のメモリであること（`EINVAL`）を確かめます。そのあと
  1 ページずつ、動かし先にページかマーカーがあれば `EEXIST`、動かし元にページが
  なければ `ENOENT`（`UFFDIO_MOVE_MODE_ALLOW_SRC_HOLES` では動かしたものとして
  数えます）、動かし元の poison、ガード、uffd-wp マーカーは `EFAULT`、`fork` が共有していて、書き込みで
  自分のものになっていないページは `EBUSY`（`PageAnonExclusive`）です。ゼロページは
  ゼロページのまま動き、ほかのページは動かし先の保護で書き込めるようになり、書き込み
  保護は外れ、動かし元にはページがなくなります。動かした分かエラーは構造体の最後の
  フィールドに入り、`DONTWAKE` でなければ動かしたページの待ちが終わり、途中で止まると
  `EAGAIN` です。read はメッセージを丸ごと取り（1 つも入らないバッファーと `UFFDIO_API` の前は
  `EINVAL`）、ノンブロッキングでなければ待ちます。`poll` は、Linux と同じく
  `UFFDIO_API` の前とブロックするファイルでは `POLLERR`、それ以外ではまだ読まれていない
  フォールトかイベントがあれば `POLLIN` です。`/proc/self/fdinfo` は `userfaultfd_show_fdinfo` と
  同じく、読まれていないフォールトの数、待っているもの全部の数、API を示します。
  イベントは、Linux の non-cooperative モードと同じく、アドレス空間の変化を
  `userfaultfd` に知らせます。`UFFD_FEATURE_EVENT_FORK` では、`fork` した子が登録と、
  そのページとマーカーの書き込み保護を、子自身の新しい `userfaultfd` で引き継ぎます。
  `UFFD_EVENT_FORK` はそれを、read が入れるファイル（古いものの `O_CLOEXEC` と
  `O_NONBLOCK` つき）として渡し、メッセージにはその番号が入ります。
  `UFFD_FEATURE_EVENT_REMAP` では `mremap` が動かしたマッピングも登録を引き継ぎ、
  `UFFD_EVENT_REMAP` が元の場所、移った先、長さを示します。
  `UFFD_FEATURE_EVENT_REMOVE` は、`MADV_DONTNEED`、`MADV_DONTNEED_LOCKED`、
  `MADV_FREE`、`MADV_REMOVE`（と呼んだ側自身のメモリへの `process_madvise`）が
  落とそうとする範囲を、マッピングごとに知らせます（`UFFD_EVENT_REMOVE`）。
  `UFFD_FEATURE_EVENT_UNMAP` は、`munmap`、`brk`、`MAP_FIXED` の `mmap`、`mremap` が
  外した範囲全体を、その一部を登録した `userfaultfd` ごとに一度知らせます
  （`UFFD_EVENT_UNMAP`）。`mremap` は Linux の `notify_uffd` と同じく、`MREMAP_FIXED` が
  置き換えた範囲、移動、残した範囲と縮めた分の順に知らせます。変化を起こしたスレッドは、
  イベントが読まれるか、ファイルが閉じられるか、致命的なシグナルが来るまで待ちます
  （`TASK_KILLABLE`）。`fork` は子が動く前に待ち、イベントが読まれなかった子の
  `userfaultfd` は子のマッピングから外れます。read はイベントより先にフォールトを取り、
  イベントが読まれるまで `UFFDIO_COPY`、`UFFDIO_ZEROPAGE`、`UFFDIO_POISON`、
  `UFFDIO_CONTINUE`、`UFFDIO_MOVE` は（先に最後のフィールドへ書いてから）
  `EAGAIN`、`UFFDIO_WRITEPROTECT` も `EAGAIN` です（`mmap_changing`）。

- `remap_file_pages` は、共有のマッピングの範囲を、そのファイルや共有メモリの別の
  ページに張り直します。Linux がマッピング自身のファイルを `mmap` し直すのと同じで、
  保護はそのままです。Linux と同じく、`prot` は 0 でなければならず、範囲は、ファイルを
  書き込み用に開いた（`VM_SHARED`。memfd の封印は外しません）同じメモリの共有の
  マッピングの中に隙間なく収まっていなければなりません（`EINVAL`）。
  ファイルが届かないページは `EOVERFLOW` です。

- System V の共有メモリ（`shmget`、`shmat`、`shmdt`、`shmctl`）は、スレッドの IPC
  名前空間のものです。確かめる内容とその順序は Linux と同じで、上限はその名前空間の
  `/proc/sys/kernel` のファイル（後述）です。大きさは 1 から `shmmax` まで（`EINVAL`）、
  ページの数が桁あふれする大きさは `ENOSPC`、全セグメントのページは `shmall` まで、
  セグメントの数は `shmmni` まで（どちらも `ENOSPC`）です。新しい IPC 名前空間には
  セグメントがなく、上限は Linux の既定値です。
  セグメントの ID は添字とシーケンス番号からなり、Linux と同じ順に割り当てます。
  `/proc/<pid>/maps` は、つないだ領域をデバイス 00:01 の `/SYSV<key> (deleted)` と示し、
  inode は ID です。つないでいる数（`shm_nattch`）は、Linux と同じく、どのプロセスでも
  セグメントを映す VMA ごとに数えます。`fork` はそれを写します。`munmap` と、一部を
  変える `mprotect`、`mlock`、`madvise`、`mseal`、`userfaultfd` の登録はそれを分け、
  分かれたものは 1 つに戻りません。VMA ができるたびに（分割、`fork` の写し、`mremap` での
  移動）セグメントの `shm_atime` と `shm_lpid` が、VMA が閉じるたびに（アンマップ、`shmdt`、
  終了、`exec`）`shm_dtime` と `shm_lpid` が変わります。Linux の `shm_open` と
  `shm_close` と同じです。`shm_lpid` は、Linux の `current` と同じく、実際にしたプロセスの
  ものです。スレッドではないのに親のメモリを共有する子（`CLONE_VM`、`vfork`）がマップや
  アンマップをすると、その子のものとして記録します。終了や `exec` で VMA が閉じるのは、
  ほかにそのアドレス空間を使うプロセスがないときだけで、最後のプロセスのものとして記録します。
  `shmdt` は、`munmap` などが残したその領域のかけらをすべて
  外します。つながったまま `IPC_RMID`
  したセグメントは、ID はそのままで、どのキーでも見つからなくなり、最後に外れたとき
  消えます。`SHM_LOCK` は Linux と同じく所有者と `RLIMIT_MEMLOCK` を確かめます。
  `SHM_HUGETLB` は、hugetlbfs なしでビルドしたカーネルと同じく `ENOSYS` です。

- System V のセマフォー（`semget`、`semop`、`semtimedop`、`semctl`）も、スレッドの IPC
  名前空間のものです。確かめる内容とその順序は Linux の `ipc/sem.c` と同じで、上限は
  その名前空間の `/proc/sys/kernel/sem`（Linux の既定値は `SEMMSL` 32000、`SEMMNS`
  1024000000、`SEMOPM` 500、`SEMMNI` 32000。`SEMVMX` 32767 は固定）です。`semget`、
  全セットのセマフォーの数、`semop` がこれに従います（`semopm` は符号なしで比べるので、
  負の値は何も制限しません）。セットの ID はセグメントと同じように割り当てます。`semctl` には
  `IPC_STAT`、`IPC_SET`、`IPC_RMID`、`IPC_INFO`、`SEM_INFO`、`SEM_STAT`、`SEM_STAT_ANY`、
  `GETVAL`、`SETVAL`、`GETALL`、`SETALL`、`GETPID`（呼び出し元の PID 名前空間の番号。セマフォーがその `struct pid` を持ち続けるので、
  そのプロセスが回収された後も返します。終了時の取り消しで変わったものも同じです）、
  `GETNCNT` と `GETZCNT`（待ちがどの操作で待っているかで数えます）があります。1 回の
  呼び出しの操作は、すべてまとめて行うか、どれも行いません。すぐに通らない操作は、待つ
  ことになる操作に `IPC_NOWAIT` があれば `EAGAIN` で、なければ変更で通れるようになるか、
  セットが消える（`EIDRM`）か、シグナルが来る（`EINTR`。Linux と同じく再開しません）か、
  `semtimedop` の時間切れ（`EAGAIN`）まで待ちます。待ちは Linux と同じ待ち行列に入ります。
  1 つのセマフォーだけへの操作はそのセマフォーの待ち行列に、複数のセマフォーへの操作はセットの
  待ち行列に入り、後者が待っている間は、1 つのセマフォーを変える待ちもセットの待ち行列に
  加わります。変更のたびに、Linux の `do_smart_update` と同じく、まず 0 にしたセマフォーで
  0 を待つものを、次に値を変える待ちを、どの待ち行列も待ち始めた順に試します。
  `SEM_UNDO` の調整値はプロセスの undo リストに持ちます。このリストは `CLONE_SYSVSEM` で
  共有し（`pthread_create` はこれを渡します）、`fork` では共有しません。`SETVAL` と
  `SETALL` は調整値を消します。リストを共有する最後のスレッドが、終わるとき、または
  `unshare`（`CLONE_SYSVSEM` か `CLONE_NEWIPC`）やほかの IPC 名前空間への `setns` で
  リストを離れるときに、Linux と同じく 0 と `SEMVMX` の間に収めて値に足します。

- System V のメッセージキュー（`msgget`、`msgsnd`、`msgrcv`、`msgctl`）も、スレッドの
  IPC 名前空間のものです。確かめる内容とその順序は Linux の `ipc/msg.c` と同じで、上限は
  その名前空間の `/proc/sys/kernel` のファイル（Linux の既定値は `MSGMAX` 8192、`MSGMNB`
  16384、`MSGMNI` 32000）です。メッセージの大きさ、新しいキューが持つバイト数（
  `CAP_SYS_RESOURCE` なしの `IPC_SET` が与えられる上限でもあります）、キューの数が
  これに従います。キューは
  `msg_qbytes` のバイト数まで、同じ数のメッセージまで持ちます。いっぱいのキューへの送信は、
  `IPC_NOWAIT` があれば `EAGAIN` で、なければキューの送信者の列で、受信か `IPC_SET` で
  そのメッセージが入る空きができるか、キューが消える（`EIDRM`）か、シグナルが来るまで
  待ちます。Linux の `ss_wakeup` と同じく、キューが変わると、メッセージが入るように
  なった送信者だけを起こし（起きた送信者は権限を確かめ直します）、ほかの送信者は順序を
  保ったままその後ろに回します。`msgrcv` は、最初のメッセージ、ある型の
  最初のもの、ほかの型の最初のもの（`MSG_EXCEPT`）、ある値までのいちばん小さい型のもの
  （負の `msgtyp`）を取ります。バッファーより長いものは `E2BIG` で、`MSG_NOERROR` が
  あれば切り詰めます。`IPC_NOWAIT` を付けた `MSG_COPY` は、その位置のメッセージを写して
  残します。何もなければ、`IPC_NOWAIT` があれば `ENOMSG` で、なければキューの受信者の
  列で待ちます。送られたメッセージは、Linux の `pipelined_send` と同じく、それを取る最初の
  受信者に渡り、バッファーが小さすぎる受信者は `E2BIG` を受けます。どちらの待ちも
  シグナルで `EINTR` になり、ハンドラーを走らせないシグナルなら再開します
  （`ERESTARTNOHAND`）。`msgctl` には、`IPC_STAT`、`MSG_STAT`、`MSG_STAT_ANY`（プロセスは
  呼び出し元の PID 名前空間の番号）、`IPC_SET`（`MSGMNB` を超えるには
  `CAP_SYS_RESOURCE`）、`IPC_RMID`、`IPC_INFO`、`MSG_INFO` があります。

- POSIX メッセージキュー（`mq_open`、`mq_unlink`、`mq_timedsend`、`mq_timedreceive`、
  `mq_notify`、`mq_getsetattr`）は、スレッドの IPC 名前空間が持つ `mqueue` ファイル
  システムのファイルです。確かめる内容とその順序は Linux の `ipc/mqueue.c` と同じです。
  ルートはスティッキーで誰でも書き込めます。名前はそこで引き（`.`、`..`、`/` を含む名前は
  `EACCES`、255 バイトを超えれば `ENAMETOOLONG`）、既存のキューを開くときはその
  パーミッションを確かめ、キューを消せるのは、持ち主、ルートの持ち主（IPC 名前空間を
  作った者。そのときのファイルシステム ID です）、`CAP_FOWNER` を持つ者だけです（`EPERM`）。名前空間の
  上限はその `/proc/sys/fs/mqueue` のファイルで、新しい名前空間は Linux の既定値で始まります。
  キューは 256 個まで（`queues_max`、`ENOSPC`）、メッセージは 10 個まで（`msg_max`）、
  1 つ 8192 バイトまで（`msgsize_max`）で、既定値（`msg_default`、`msgsize_default`）も
  同じです。属性なしで作るキューは、それぞれ既定値と上限の小さいほうを取ります。
  `CAP_SYS_RESOURCE` があれば上限を超えられ、16 MiB のメッセージを 65536 個まで持てます。キューは、消されて閉じられるまで、その
  バイト数と Linux がメッセージごとに使う管理領域（x86-64 で 48 + 48 バイト）を、Linux の
  `inc_rlimit_ucounts` と同じく課します（どれかの上限を超えれば `EMFILE`）。作った者の
  ユーザー名前空間でのその実ユーザー ID に、作った者の `RLIMIT_MSGQUEUE` に対して課し、
  作った者がいるユーザー名前空間のそれぞれについて、親の名前空間でのその名前空間の持ち主に、
  持ち主が名前空間を作ったときの `RLIMIT_MSGQUEUE` に対して課します。`mq_open` は close-on-exec の
  記述子を返し、`fork` はそれを `O_NONBLOCK`（`mq_getsetattr` でも `fcntl` でも設定
  できます）ごと共有します。`poll`、`select`、`epoll` では、アクセスモードによらず、
  メッセージがあれば読め、空きがあれば書けます。メッセージが入るたびに、エッジトリガーの
  `epoll` はまた起きます。`read` はファイル位置から Linux と同じ状態の行（`QSIZE`、
  `NOTIFY`、`SIGNO`、`NOTIFY_PID`）を返し、`fstat` は 80 バイトの通常ファイルを示し、
  その更新時刻は最後の送信か受信（なければ作成）のときです（失敗したもの、`mq_notify`、
  `mq_getsetattr`、`read` では変わりません）。`mqueue` ファイルシステムは `s_time_gran` を
  設定しないので、時刻は秒単位です。`fchmod`、`fchown`、`futimens` はそれを変えます（時刻は
  秒単位にします）。`ftruncate` は、Linux の `simple_setattr` と同じく、示すサイズと更新時刻を
  変えます（`mq_open` は `O_LARGEFILE` を付けないので 2^31 − 1 バイトを超えると `EINVAL`、
  書き込みのアクセスがなくても `EINVAL`）。`lseek` の終わりはそのサイズです。`fstatfs` は
  `mqueue` ファイルシステム（`MQUEUE_MAGIC`、ブロックは 1 ページ、名前は 255 バイトまで）を
  示します。`/proc/self/fd` のリンクを開くと同じキューになり、アクセスモードと `O_TRUNC` の
  権限を確かめます（`EACCES`。`O_DIRECTORY` では `ENOTDIR`）。`/proc/self/fd` のリンクは `/<名前>` で、消された
  あとは空白と `(deleted)` が後ろに付きます。メッセージは優先度の高い順（32768 未満。それ以外は
  `EINVAL`）に、同じ優先度なら送った順に出てきます。`mq_msgsize` より小さいバッファーへの
  受信は `EMSGSIZE` で、それより長い送信も同じです。空のキューからの受信といっぱいの
  キューへの送信は、`O_NONBLOCK` があれば `EAGAIN` で、なければ `CLOCK_REALTIME` の
  絶対時刻の時間切れ（`ETIMEDOUT`。時刻は最初に読んで確かめます：`EFAULT`、`EINVAL`）か
  シグナル（`EINTR`。`ERESTARTSYS` と同じく、`SA_RESTART` とハンドラーを走らせない
  シグナルなら再開します）まで待ちます。待っている受信者は、待ち始めた順に、Linux の
  `pipelined_send` と同じく送信者から直接メッセージを受け取ります。待っている送信者の
  メッセージは、受信でできた空きに入ります（`pipelined_receive`）。`mq_notify` は呼び出した
  プロセスを登録し（ほかのプロセスが登録している間は `EBUSY`。通知なしで呼ぶと、自分の
  登録だけを外します）、受信者が待っていないときに空のキューへメッセージが来たことを 1 回
  知らせます。`SIGEV_SIGNAL` は、`si_code` が `SI_MESGQ` で、送ったプロセスとその実
  ユーザー ID、`sigev_value` を持つシグナルを送ります（シグナル 0 なら何も送りません。
  登録したあとに `execve` したプロセスにも送りません）。`SIGEV_NONE` は登録を終える
  だけです。`SIGEV_THREAD` は `sigev_value` から 32 バイトを写し、`sigev_signo` が示す
  netlink ソケット（`EBADF`、`ENOTSOCK`、ほかのソケットなら `EINVAL`）へ、最後の
  バイトが 1（`NOTIFY_WOKENUP`）のデータグラムとして送ります。メッセージなしで登録が
  終わるときは 2（`NOTIFY_REMOVED`）です。C ライブラリーの補助スレッドはこれを読んで
  `sigev_notify_function` を始めます。クッキーは、Linux の `netlink_attachskb` と同じく、
  登録のときから受け取られるまで、そのソケットの受信バッファーの空きを取ります。ソケットに
  何かがあり、クッキーの空きがないか、ソケットが混んでいる（`NETLINK_S_CONGESTED`。下の netlink ソケットを参照）とされていれば、
  `mq_notify` はキューを引く前に、受信で空きができるか空になるまで待ちます（シグナルで待ちは終わり `EINTR`。`SA_RESTART` なら再開します）。そのあと失敗すれば
  空きを返します。キューのどの記述子を閉じても、またはプロセスが
  終わっても、Linux の `mqueue_flush_file` と同じくそのプロセスの登録は外れます。

- `/dev/mqueue` は、Linux の起動時に systemd がマウントするのと同じく、呼び出し元がどの IPC
  名前空間にいても、最初の IPC 名前空間の `mqueue` ファイルシステムです。誰でも書ける
  スティッキーなディレクトリ（01777。作った者のもの）で、`/dev` に並び、中にはキューが通常
  ファイルとして並びます。ファイルの `stat` は `mq_open` が作るとおりです。開くと `mq_*` の
  呼び出しが受け付ける記述子になり、確かめる内容は同じです（`EACCES`）。`O_CREAT | O_EXCL`
  では `EEXIST`、`O_CREAT` がなければ `ENOENT`、`O_DIRECTORY` では `ENOTDIR` です。
  `O_CREAT` は名前空間の既定の属性でキューを作ります（`mqueue_create`）。`O_TRUNC` は、
  アクセスモードによらず書き込みの権限が要り、すでにあったキューのサイズを 0 にして更新時刻を
  変えます（`handle_truncate`）。`/proc/self/fd` の
  リンクは `/dev/mqueue/<名前>` です。`unlink` は `mq_unlink` と同じくキューを消します
  （キューへの `rmdir` は `ENOTDIR`）。キューのパスへの `chmod`、`chown`、`utimensat`、
  `utimes`、`truncate` は、記述子への呼び出しと同じくそのファイルを変え、確かめる権限も
  同じです（`EPERM`、`EACCES`）。ただし、パスへの truncate は更新時刻を変えず、2^31 − 1
  バイトまで伸ばせます（それを超えると、スーパーブロックの `s_maxbytes` のとおり `EFBIG`）。
  `statfs` は `mqueue` ファイルシステムを示します。ルートのサイズはエントリー（`.`、`..`、
  それぞれのキュー）ごとに 20 バイト（`DIRENT_SIZE`）で、更新時刻は名前空間を作ったとき、
  またはそこで最後にキューを作ったか消したときです。`/dev/mqueue` への `chmod`、`chown`、
  `utimensat` と、それを開いたものへの `fchmod`、`fchown`、`futimens` はルートを変えます
  （`truncate` は `EISDIR`）。そのモードが、ほかの者にできることを決めます。そこで名前を
  引くには検索の権限が要り（`EACCES`）、開くには読む権限が要ります。キューを作るとき
  （`mq_open` も）と消すときは書き込みと検索の権限が要ります（`may_create`、`may_delete`）。
  スティッキービットがあれば、消せるのはキューの所有者、ルートの所有者、`CAP_FOWNER` を
  持つ者だけです。すでにあるキューの `mq_open` は検索しません（`lookup_noperm`）。その中での
  `link` と `rename` は、ルートが断る前に Landlock が確かめます（`EACCES`）。ルートにある操作は、名前を引くこと、キューを作ること、消すことだけ
  です。そこで空いている名前（使われていれば `EEXIST`。`/dev/mqueue` 自身も同じ）への `mkdir`、
  `symlink`、通常ファイル以外の `mknod` は、Landlock の確認のあとで `EPERM` です。通常ファイル
  （型 0 も）の `mknod` は、`vfs_create` と同じく既定の属性のキューを作ります。`link` と
  `rename` は `do_linkat` と `do_renameat2` と同じく名前を引き（`ENOENT`、`EEXIST`。
  `RENAME_NOREPLACE` と `RENAME_EXCHANGE` もそのとおり）、ほかのマウントとの間では、両方の
  パスをたどったあと（途中の各ディレクトリを検索でき、なければ `EACCES`）で `EXDEV`
  （`rename` は名前を引く前）、その中では `EPERM` です。ただし、名前をそれ自身へ `rename`
  すると何もせずに成功します。

- 鍵の保管サービス（`add_key`、`request_key`、`keyctl`）は Linux の `security/keys`
  と同じです。`keyring`、`user`、`logon` の鍵があり、それぞれに通し番号、所有者、グループ、
  許可（所持者、ユーザー、グループ、その他）、期限があります。スレッドはスレッド、
  プロセス、セッションのキーリングを持ちます（`fork` と `exec` はセッションのものを残し、
  新しいスレッドは、作ったスレッドが持っていれば自分のスレッドのキーリングを持ちます。
  スレッドのキーリングはファイルシステムの ID に従います）。ユーザーはユーザー名前空間に
  `_uid.<uid>`、`_uid_ses.<uid>`、`_persistent.<uid>` のキーリングを持ちます。検索は
  `search_nested_keyrings` と同じく入れ子のキーリングを 6 段までたどり、エラーの順
  （`EKEYREVOKED`、`EKEYEXPIRED`、`EACCES`、否定の鍵のエラー）もそのとおりです。スレッドの
  キーリングから見つかった鍵は所持しているものとします。ユーザーごとに Linux と同じ割り当て
  （鍵 200 個と 20000 バイト。ルートは 100 万個と 25 MB）があり、キーリングのリンクも
  そこに数えます。`keyctl` は、big key、Diffie-Hellman、非対称鍵、通知のないカーネルの
  すべてのオプションを受け付けます。`GET_KEYRING_ID`、`JOIN_SESSION_KEYRING`（名前付きの
  セッションも）、`UPDATE`、`REVOKE`、`CHOWN`、`SETPERM`、`DESCRIBE`、`CLEAR`、`LINK`、
  `UNLINK`、`SEARCH`、`READ`、`SET_REQKEY_KEYRING`、`SET_TIMEOUT`、`GET_SECURITY`、
  `SESSION_TO_PARENT`、`INVALIDATE`、`GET_PERSISTENT`、`RESTRICT_KEYRING`（これ以上リンクを
  取らないものだけ。ここの型には制限がなく `ENOENT`）、`MOVE`、`CAPABILITIES` です。ほかは `EOPNOTSUPP` です。呼び出し情報つきの
  `request_key` は、`/sbin/request-key` が失敗したときと同じく鍵を 60 秒の否定の鍵にして
  `ENOENT` を返します。そのため `INSTANTIATE`、`NEGATE`、`REJECT`、`INSTANTIATE_IOV` は
  権限を見つけられず（`EPERM`）、鍵の `ASSUME_AUTHORITY` は `ENOKEY` です。

- `sched_getaffinity` では、ゲストのどのスレッドもホストのすべての CPU で動けるとします。
  そのため、ゲストにはホストと同じ数の CPU が見えます（WebAssembly では 1 つ）。
  `sched_setaffinity` は、プロセスのスレッドのマスクを Linux と同じように読んで持ちます。
  CPU マスクの大きさまで読み（短ければ残りは空とみなします）、ホストの CPU だけを残し、
  何も残らなければ `EINVAL` です。その後の `sched_getaffinity` はそのマスクを返し、新しい
  スレッドとプロセスはそれを継ぎます。ただし、ホストはそのスレッドをどの CPU でも動かします。
  どちらも、root と同じくほかのプロセスのスレッドも見つけ、その ID の生きているスレッドが
  なければ `ESRCH` です。`getcpu` は NUMA ノード 0 と、`rseq` を登録したスレッドなら
  その仮想 CPU を返します。ほかのスレッドには、マスクが許すいちばん小さい番号の CPU を返します。

- Linux と同じく、スレッドごとにスケジューリングの属性があります。ポリシー
  （`SCHED_OTHER`、`SCHED_BATCH`、`SCHED_IDLE`、`SCHED_EXT`、`SCHED_FIFO`、`SCHED_RR`、
  `SCHED_DEADLINE`）、リアルタイムの優先度、`SCHED_RESET_ON_FORK`、デッドライン
  タスクのランタイム・デッドライン・周期、通常のポリシーのスライス、使用率のクランプ
  です。`sched_setscheduler`、`sched_setparam`、`sched_setattr` は、Linux と同じ確認を
  同じ順に行って設定します。引数、ポリシーと優先度、デッドラインの値、それから権限です。
  `CAP_SYS_NICE` がなければ、リアルタイムのポリシーには `RLIMIT_RTPRIO` が、nice 値を
  下げるには `RLIMIT_NICE` が要り、ユーザーは `SCHED_DEADLINE` を取れず、`SCHED_IDLE`
  からも戻れず、リセットのフラグも外せません。`sched_setattr` は Linux と同じように
  `struct sched_attr` を読み（大きさを書き戻して `E2BIG`）、`SCHED_FLAG_KEEP_POLICY` と
  `SCHED_FLAG_KEEP_PARAMS` ではポリシーや値を保ち、デッドラインのタスクを Linux 6.12 と
  同じく受け入れます。マスクがすべての CPU を含むこと（でなければ `EPERM`）、各 CPU の
  95% から fair server の 5% を引いた範囲に収まること（でなければ `EBUSY`）です。
  `sched_getscheduler`、`sched_getparam`、`sched_getattr` は、どのプロセスのスレッドでも
  それを返します。`sched_getattr` は、通常のポリシーなら nice 値と、スライスを
  `sched_runtime` として返します。構造体より大きいバッファーの残りは、Linux 6.13
  以降と同じく 0 で埋めます。新しいスレッドとプロセスは Linux の `sched_fork` と
  同じくそれを継ぎます。リセットのフラグがあれば、リアルタイムやデッドラインのタスクの
  子は通常のタスクになり、nice 値は 0、フラグはなくなります。デッドラインのタスクは
  fork できません（`EAGAIN`）。`sched_setaffinity` は、デッドラインのスレッドには
  すべての CPU を残させます（`EBUSY`）。ホストはどのゲストのスレッドも通常のスレッドと
  して動かします。`sched_get_priority_max` と `sched_get_priority_min` は、Linux と同じく
  `SCHED_FIFO` と `SCHED_RR` で 99 と 1、ほかのポリシーで 0 です。
  `sched_rr_get_interval` は、`SCHED_RR` なら 100 ms、`SCHED_FIFO` と `SCHED_DEADLINE` なら
  0、それ以外ならスレッドのスライスをティック単位に切り捨てて返します。スライスは、
  `sched_setattr` で求めたもの（0.1 ms から 100 ms）か、Linux のホストではホストの
  スケジューラーがそのスレッドに与えるものです。ゲストのスレッドはホストのスレッドで
  動くからです。ほかのホストでは Linux 6.12 の 1000 Hz での既定値、つまり 0.75 ms に
  1 + log2(CPU の数、最大 8) を掛けた値です。

- `ioprio_set` と `ioprio_get` は、`getpriority` と同じようにスレッドを見つけます
  （`IOPRIO_WHO_PROCESS`、`IOPRIO_WHO_PGRP`、`IOPRIO_WHO_USER`）。`ioprio_set` は、まず
  Linux の `ioprio_check_cap` と同じく優先度を確かめ（知られたクラスであること、
  リアルタイムは `CAP_SYS_NICE` か `CAP_SYS_ADMIN` があること）、実ユーザー ID が呼んだ
  側の実または実効ユーザー ID であるスレッドにそれを与えます（`CAP_SYS_NICE` が
  なければ、ほかは `EPERM`）。`ioprio_get` は、スレッドに与えた優先度を返し、一度も
  持たなかったスレッドやクラスなしを与えたスレッドには、nice 値にかかわらず 0 を返します。複数の
  スレッドなら、Linux の `ioprio_best` と同じように比べていちばんよいものです（クラスの
  ないものはベストエフォートのレベル 4 とみなします）。クラスのある優先度は、新しい
  スレッドとプロセスに渡ります。

- `kcmp` は、呼んだ側の PID 名前空間の番号でそれぞれのスレッドを見つけ（`ESRCH`）、実 ID で
  判断する読み取りモードの `ptrace_may_access` と同じく、両方を読めることを求めます（`EPERM`）。
  そのうえで Linux の `kernel/kcmp.c` と同じく、ディスクリプタで指したそれぞれの開いたファイル
  （`EBADF`）、メモリ、ディスクリプタ表、作業ディレクトリと umask（`CLONE_FS`）、シグナルの
  処理、`ioprio_set` が与える I/O コンテキスト、System V セマフォの undo リスト、または
  2 つめのスレッドの epoll インスタンスが見張るファイルとの比較（`KCMP_EPOLL_TFD`：`EFAULT`、
  `EBADF`、epoll でないファイルは `EINVAL`、`ENOENT`）を比べます。同じものなら 0、違うものなら、
  Linux がアドレスを隠すのと同じく、ランダムなクッキーで決まる順の 1 か 2 を返します。それを
  持たないスレッド（終わったプロセス、I/O コンテキストや undo リストのないスレッド）どうしは
  等しいとみなします。

- `process_vm_readv` と `process_vm_writev` は Linux の `mm/process_vm_access.c` と同じ順に
  確かめます。`flags` は 0 でなければならず（`EINVAL`）、次に手元の iovec 配列を `readv` と
  同じく読み、次に相手側の配列を読みます（1024 を超える要素や負の長さは `EINVAL`、読めない
  配列は `EFAULT`。バッファはまだ見ません）。どちらかの側に写すバイトがなければ、スレッドを
  探す前に 0 を返します。`pid` は呼んだ側の PID 名前空間の番号でスレッドを指し（`ESRCH`。
  ゾンビも同じ）、自分のメモリでない限り、実 ID で判断するアタッチモードの
  `ptrace_may_access` と同じく、そのメモリにアタッチできることを求めます（`EPERM`）。
  手元のバッファに空きがある間、相手側のバッファを順に写します。マップされていない相手側の
  ページ、`PROT_READ` なしのページ（読む場合。Linux の `VM_READ` と同じく `PROT_WRITE` や
  `PROT_EXEC` だけでは足りません）、`PROT_WRITE` なしのページ（書く場合）、または書けない・
  読めない手元のバイトで写すのをやめ、それまでに写したバイト数を返します。1 バイトも
  写せなければ `EFAULT` です。

- `pidfd_getfd` はフラグを取らず（`EINVAL`）、pidfd を取り（`EBADF`）、そのプロセスに上と
  同じくアタッチできることを求めます（`EPERM`）。終わったプロセスは回収の前でも後でも
  `ESRCH`、そのプロセスにないディスクリプタは `EBADF` です。写しは開いたファイル記述を
  共有し、空いている最小の番号を close-on-exec で得ます（`RLIMIT_NOFILE` に達すれば
  `EMFILE`）。

- ほかのプロセスのスレッドを読めるか、アタッチできるかは、Linux の `__ptrace_may_access` が
  ケーパビリティモジュールと Yama を合わせて決めるのと同じく決めます。読む場合（`kcmp`、`get_robust_list`、
  `/proc/<pid>/environ` など、`move_pages`、`migrate_pages`、pidfd を渡した `setns`）は、
  相手のユーザー名前空間での `CAP_SYS_PTRACE` か、次のすべてを求めます。相手がダンプでき、
  相手のユーザー ID とグループ ID がすべて呼び出し元のもの（呼び出しに応じて実 ID か
  ファイルシステム ID）と同じで、同じユーザー名前空間にいて、呼び出し元の許可された
  ケーパビリティ（ファイルシステム ID の場合は実効ケーパビリティ）が相手の許可された
  ケーパビリティを含むことです。そのうえで Landlock が、ドメインの中の呼び出し元を外の
  タスクから遠ざけます。アタッチする場合（`process_vm_readv`、`process_vm_writev`、
  `pidfd_getfd`）は、Debian や Ubuntu、CI のランナーと同じく Yama の `ptrace_scope` を 1 と
  します。相手が呼び出し元の子孫であるか、`PR_SET_PTRACER` で呼び出し元を入れているか、
  呼び出し元が相手のユーザー名前空間で `CAP_SYS_PTRACE` を持つことも求めます。

- `personality` は、Linux と同じくどんな値でもスレッドに持ち、前の値を返します
  （`0xffffffff` は問い合わせだけです）。新しいスレッドとプロセスはそれを継ぎ、
  `execve` は `READ_IMPLIES_EXEC` を、set-ID のプログラムなら `PER_CLEAR_ON_SETID` も
  落として保ちます。Linux と同じく、3 つの設定はゲストに見えるものを変えます。
  `PER_LINUX32` なら `uname` は `i686` と、`UNAME26` なら 2.6 のリリース（`2.6.72`）と
  答え、`READ_IMPLIES_EXEC` なら `mmap` と `mprotect` は読めるマッピングを実行もできる
  ようにします。Linux の `load_elf_binary` と同じく、さらに 2 つは次の `execve` で
  効きます。`ADDR_COMPAT_LAYOUT` なら、アドレスを決めないマッピング（インタープリターも）
  を、上から下ではなく `TASK_UNMAPPED_BASE`（アドレス空間の 3 分の 1）から上に置きます。
  `MMAP_PAGE_ZERO` なら、新しい資格情報に `CAP_SYS_RAWIO` があればページ 0 を読み取りと
  実行のできるようにマップします。`ADDR_NO_RANDOMIZE` は持つだけです。もともと何も
  ランダムにしないからです。x86-64 の Linux でも何もしないフラグ（`ADDR_LIMIT_32BIT`、
  `SHORT_INODE`、`WHOLE_SECONDS`、`STICKY_TIMEOUTS` など）も持つだけです。

- `mprotect` は引数を Linux と同じ順で確かめます。`PROT_GROWSDOWN` と `PROT_GROWSUP` の
  両方、そろっていない先頭、空の範囲（ビットが何でも成功します）、あふれる終わり（`ENOMEM`）、
  そのあと未知のビットの順です。`PROT_GROWSDOWN` は範囲を、その中の最初の VMA の先頭まで
  下に広げます。その VMA は下に伸びるもの（メインのスタックか、`MAP_GROWSDOWN` の
  マッピング）でなければならず、そうでなければ
  `EINVAL` です。`PROT_GROWSUP` は、x86-64 には上に伸びる VMA がないので、先頭がマップ済みなら
  `EINVAL` です。範囲に VMA がなければ、どちらも `ENOMEM` です。

- 下に伸びるマッピング（メインのスタックか、`mmap` が `MAP_GROWSDOWN` で作った
  プライベートな匿名メモリで、`VmFlags` は `gd` を示します）は、Linux の
  `expand_downwards` と同じように伸びます。その下のマップされていないページへの
  アクセスや、そこへのシグナルフレームの書き込みで、そのページまで下に伸び、アクセスは
  やり直されます。`mmap_min_addr`（64 KiB）より下、下に伸びずアクセスできるマッピングの
  上の 256 ページの guard gap（`stack_guard_gap`）の中、VMA 全体で `RLIMIT_STACK` を
  超えるところ、ロックされていれば `CAP_IPC_LOCK` なしで `RLIMIT_MEMLOCK` を超える
  ところへは伸びず、そのアクセスは `SIGSEGV` になります。その下の gap には、ヒントでも、
  `mmap` が空きを探すときでも、マッピングを置きません。ファイルのマッピング
  （`/dev/zero` も含みます）と共有メモリは下に伸ばせません（`EINVAL`）。メインの
  スタックの VMA は 8 MiB から始まるので、それより大きい `RLIMIT_STACK` ではそれを
  超えて伸びます。

- 保護キーは、保護キーのない CPU での Linux と同じ答えを返します。仮想 CPU はそういう CPU
  です（`CPUID` は PKU を報告しません）。キーは、既定のキー 0 も含めて一つも割り当てられて
  いません。`pkey_alloc` は `ENOSPC` で、フラグや `PKEY_DISABLE_ACCESS` と
  `PKEY_DISABLE_WRITE` 以外の権利には `EINVAL` です。`pkey_free` は `EINVAL` です。
  `pkey_mprotect` はキーが `-1` なら `mprotect` と同じで、それ以外のキーは、Linux が先に
  行う確認のあとで `EINVAL` です（空の範囲は成功し、あふれる範囲は `ENOMEM` です）。

- `mseal` は、Linux の `mm/mseal.c` と同じようにマッピングを封印します。フラグは受け付けず、
  先頭はページ境界でなければならず、一周する長さや上端を超える長さは `EINVAL` です。
  マップされていないページを含む範囲は `ENOMEM` で、何も封印しません。封印された
  マッピングへの操作は、どれも `EPERM` で拒否されます。
  - `munmap` は、封印されたマッピングを含む範囲を何も解除しません。`MAP_FIXED` の
    `mmap`、`mremap`（それ自身の、または `MREMAP_FIXED` でそこへの）、
    `remap_file_pages`、縮める `brk` も置き換えません（`brk` はブレークを変えません）。
  - `mprotect` と `pkey_mprotect` は、Linux の VMA ごとのループと同じく、範囲で最初の
    封印されたマッピングより前を変えてからそこで止まります。同じ保護でも止まります。
  - `MADV_DONTNEED` と `MADV_FREE` は、書き込めない封印されたプライベートの匿名
    マッピングを捨てません。書き込めるものやファイルのマッピングは捨てられます。
  - 封印された共有メモリの `shmdt` は、Linux が失敗した解除を無視するのと同じく、
    成功してマップされたまま残します。
  - `fork` の子は封印を受け継ぎ、`exec` のあとは何も封印されていません。

- io_uring は、操作が `IORING_OP_NOP` と `IORING_OP_EPOLL_CTL`（libuv が `epoll_ctl` を
  まとめるのに使います）の 2 つだけの Linux 6.12 のものです。ほかの操作は、それらなしで
  ビルドした Linux と同じく `EOPNOTSUPP` で完了し、`IORING_REGISTER_PROBE` もその 2 つだけを
  報告します。リングの大きさ、オフセット、機能は Linux が返すものと同じで、記述子の `mmap` で
  見えます。要求は `io_uring_enter` が取り出すときに実行されるので、呼び出しが戻るときには
  完了がキューにあります。リンク、成功時に完了を省くもの、キューがいっぱいのあいだ保たれる
  完了（`IORING_FEAT_NODROP`）は Linux と同じです。

- Linux のネイティブな非同期 I/O（libaio が包む呼び出し）は `fs/aio.c` のものです。
  `io_setup` はイベント数を CPU ごとに少なくとも 4 にして 2 倍にし（`0x8000000 / 32` を
  超えると `EINVAL`、単独でもマシンのほかのコンテキストと合わせても
  `/proc/sys/fs/aio-max-nr` を超えると `EAGAIN`）、`mmap` が置く場所にリングをマップします。
  リングはヘッダー（コンテキストの番号、保てるイベント数、head、tail、マジック
  `0xa10a10a1`、機能、ヘッダーの大きさ 32）とその後のイベントで、libaio と同じく
  プログラムが自分で読んで取り出せます。`/proc/self/maps` での名前は `/[aio] (deleted)` です。
  コンテキストの ID はリングのアドレスで、どの呼び出しもそのヘッダーの番号でコンテキストを
  探します（ないと `EINVAL`）。`io_submit` はリングが保てる数までの要求を取り、それぞれを
  Linux の `io_submit_one` と同じ順で確かめ（`aio_reserved2`、長さ、リングの空き、ファイル、
  `IOCB_FLAG_RESFD` の eventfd、`aio_key` の消去、そして操作です。操作は `IOCB_CMD_PREAD`、
  `PWRITE`、`PREADV`、`PWRITEV`、`FSYNC`、`FDSYNC`、`POLL` で、ほかは `IOCB_CMD_NOOP` も
  `EINVAL`）、最初に失敗したものの前までに取った数を返します。読み書きと同期は取られたときに
  `aio_offset` で実行され（パイプ、ソケット、端末はストリームとして）、`IOCB_FLAG_IOPRIO` の
  優先度と `aio_rw_flags` は `preadv2` と同じく確かめ、そのイベントは呼び出しが戻る前に
  リングにあります。空のパイプの読み込みはそこで待ち、シグナルで結果が `EINTR` になります。
  poll はファイルが準備できていれば、そのイベントのうち準備できたものですぐに完了し、
  そうでなければ準備できるまで待ちます。待ったあとは、Linux の `aio_poll_wake` と同じく
  起床のキーをそのまま返します（パイプなら `POLLIN` だけを求めても `POLLIN | POLLRDNORM`、
  キーのないハングアップなら準備できたもの）。
  `io_cancel` が取り消せるのは待っている poll だけで（`EINPROGRESS` で、イベントのない
  イベントがリングに入ります）、ほかの要求には `EINVAL` です。`io_getevents` と
  `io_pgetevents` は head からイベントを取り、Linux の `read_events` と同じく `min_nr` 個まで
  待ちます（負のタイムアウトは、Linux と同じくタイムアウトなしと同じに待ちます）。
  待ちが終わるのは、タイムアウト、シグナル（`io_getevents` は再開しない `EINTR`、
  `io_pgetevents` は `ERESTARTNOHAND` で、待つあいだはそのシグナルマスクです）、ほかの
  スレッドの `io_destroy`（`EINVAL`）です。eventfd を指定した要求の完了は、それぞれ eventfd が
  数えます。コンテキストはアドレス空間のものです。スレッドと `CLONE_VM` の子は共有し、fork の
  子はコンテキストもリングも持たず（2026 年からの `VM_DONTCOPY` と同じ）、`execve` か最後の
  終了でコンテキストは終わり、待っている poll は取り消されます。

- `modify_ldt` は、Linux の `arch/x86/kernel/ldt.c` と同じく、アドレス空間のローカル
  ディスクリプタテーブルを持ちます。書き込み（1 は古いモード、0x11 は新しいモード）は
  16 バイトの `struct user_desc` を 1 つ受けます。エントリ番号が 8,192 以上なら `EINVAL` を
  返し、コンフォーミングのコードセグメントも、新しいモードで存在しないものでなければ `EINVAL`
  を返します。Linux と同じ
  ディスクリプタを書き、空のもの（古いモードでは、ベースもリミットもないもの）ならエントリを
  消します。テーブルは書いたうちで最も大きいエントリまで伸びます。読み込み（0）は、何かを
  書くまでは 0 を返し、そのあとはエントリを、数まで 0 で埋めて返します（最大 64 KiB）。2 は
  最大 128 バイトの 0 を読み、ほかの関数は `ENOSYS` です。fork はコピーを保ち、exec のあとは
  テーブルがありません。結果は Linux の `int` を `unsigned int` にしたものなので、エラーは
  `-EINVAL` ではなく、たとえば `0xffffffea` として返ります。

- `membarrier` は、`CONFIG_RSEQ` があって `nohz_full` の CPU がない x86-64 の Linux の
  コマンドを持ちます（`MEMBARRIER_CMD_QUERY` は `0x3ff`）。プライベートのコマンドは、
  アドレス空間がそれに登録するまで `EPERM` です。fork は登録を保ち、exec のあとは登録がなく、
  `MEMBARRIER_CMD_GET_REGISTRATIONS` は Linux と同じビットで登録を答えます（`SYNC_CORE`
  に登録すると、空間はプライベートとしても印が付きます）。バリアは、Linux の割り込みと
  同じく、アドレス空間のすべてのスレッドにかかります。ほとんどのアクセスはロックを取らない
  ので、空間のロックを取り、スレッドの TLB のエポックを進めます。これで途中の書き込みを
  待ち、各スレッドの次のアクセスをロックへ回します。
  `MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ` は、さらに空間のほかのスレッドの `rseq` の
  クリティカルセクションを中止させます（`MEMBARRIER_CMD_FLAG_CPU` ならその CPU のスレッドだけ、
  マシンにない CPU ならどれも）。ゲストのコードを実行していたスレッドがそれぞれ止まってから
  戻ります。

- `rseq` は、Linux と同じ検査とエラー（`EINVAL`、`EPERM`、`EBUSY`、`EFAULT`）でスレッドの
  領域を登録し、今の Linux と同じく登録のときに領域の `rseq_cs` を消します。補助ベクターは
  今の Linux と同じく `AT_RSEQ_FEATURE_SIZE` に 28、`AT_RSEQ_ALIGN` に 64 を与えるので、
  32 バイトより長い領域は 64 にそろえます。`rseq` を登録したスレッドは、
  マシンが報告する CPU の数だけある仮想 CPU の一つで、CPU マスクの範囲で動きます。そこでは同時に
  ほかのそうしたスレッドは動きません。領域には、その CPU、NUMA ノード 0、並行 ID（`mm_cid`）を
  示します。並行 ID は CPU の数より小さく、アドレス空間のほかの動いているスレッドが持たない
  ものです。スレッドはゲストのコードを実行する前に CPU を取り、システムコール、フォールト、
  バジェットの終わりのたびに手放します。別の CPU に戻ったとき、ほかのスレッドが使ったあとの
  自分の CPU に戻ったとき、`membarrier` のあと、シグナルを届けるときには、中にいる
  クリティカルセクションは中止ハンドラーから続きます。Linux のプリエンプト、移動、シグナルの
  あとと同じです。今の Linux と同じく、スレッドがセクションの外にいる間は、カーネルは
  セクションの場所だけを読んで領域の `rseq_cs` を消します。ディスクリプターのバージョンと
  フラグは読みません。セクションの中のスレッドが使えない中止ハンドラー（セクションの中にある
  もの、前にシグネチャーのないもの）、ユーザー空間の外にあるセクション、カーネルが書けない領域
  では、スレッドは `SIGSEGV` で終わります。CPU を待つスレッドがあると、自分の CPU を 4 ms 使った
  スレッドは先に譲ります。fork は登録を保ち、新しいスレッド、`CLONE_VM` の子、exec は登録なしで
  始まります。

- `chroot` は、Linux の `set_fs_root` と同じく、呼び出し元と作業ディレクトリを共有する
  タスク（`CLONE_FS`）に自分のルートを与えます。その前に Linux と同じ順に確かめます。
  パスのたどり（`ENOENT`、`ENOTDIR`、`ELOOP`、`EACCES`）、ディレクトリの検索の許可
  （`EACCES`）、呼び出し元のユーザー名前空間での `CAP_SYS_CHROOT`（`EPERM`）です。
  そのあと、絶対パスと絶対のシンボリックリンクはルートから始まり、`..` はそこで止まります。
  exec とそのインタープリターも同じです。作業ディレクトリは元の場所のままで、ルートの外の
  作業ディレクトリからは、Linux と同じくパスはどこへでも行けます。`getcwd` は、作業
  ディレクトリをルートからのパスで返し、ルートの下にないときは、マシンのルートからのパスの前に
  `(unreachable)` を付けて返します。`fork` の子はルートを保ち、名前の変更はディレクトリと
  一緒にルートも動かし、マウント名前空間への `setns` はマシンのルートに戻します。生成される
  `/proc` と `/dev` がほかのルートの下にあるのは、それをバインドマウントした場所だけです。
  そこには `proc` ファイルシステムがマウントされていないからです。

- `mount` は、呼び出し元のマウント名前空間のディレクトリに新しい tmpfs をマウントします。
  その前に Linux と同じ順に確かめます。型・ソース・オプションを写し（`EFAULT`。4096 バイト
  の中で終わらない文字列は `EINVAL`）、リンクをたどってターゲットを探し（`ENOENT`、
  `ENOTDIR`、`ELOOP`、`EACCES`）、`MS_NOUSER` は `EINVAL`、ファイルへのアクセスを扱う
  Landlock のドメインは `EPERM` で、マウント名前空間に対する `CAP_SYS_ADMIN` が要ります
  （`EPERM`）。新しいマウントには、型（`EINVAL`）が `tmpfs` であること（ほかは `ENODEV`）、
  tmpfs が受け取るオプション（ほかのもの、種類の違う値は `EINVAL`。`size`、`nr_blocks`、
  `nr_inodes`、`mode`、`uid`、`gid`、`huge`、`mpol`、`inode32`、`inode64`、`noswap`、
  クォータのもの、共通の `sync`、`dirsync`、`lazytime`、`mand` とその反対）、呼び出し元の
  ユーザー名前空間での `CAP_SYS_ADMIN`（`EPERM`）、マウントが呼び出し元の名前空間にある
  （`EINVAL`）ディレクトリ（`ENOTDIR`）が要ります。マウントはその下にあるものを隠し、
  Linux と同じく空いているいちばん小さいデバイスと ID を持ちます。ルートは、`mode`、`uid`、
  `gid` で変えなければ、呼び出し元のファイルシステム ID が持つモード 01777 のディレクトリ
  です。`statfs` は `TMPFS_MAGIC` と、マウントしたときの大きさと inode の数（既定は
  `sysinfo` が返すメモリーの半分、0 は上限なし）と、ファイルが使っている分を返します。
  ファイルは tmpfs と同じくその大きさと inode の数に収めます。書き込みは大きさを
  超える最初のページで止まり（短い書き込み。何も入らなければ `ENOSPC`）、`fallocate` は
  範囲をすべて割り当てるか何も割り当てません（`ENOSPC`）。長いシンボリックリンク
  （127 バイトを超えるもの）は 1 ページを使い、新しい inode とファイルの 2 つめ以降の
  名前（`link`）はそれぞれ inode を 1 つ使います（残っていなければ `ENOSPC`）。消した
  けれどまだ開いているファイルは、最後に閉じるまでその分を持ちます。マウントし直すと
  上限が変わります。数え方は `shmem` の `shmem_inode_acct_blocks` と
  `shmem_reserve_inode` と同じです。`/proc/self/mountinfo` と
  `/proc/self/mounts` は、ソース、`nosuid`・`nodev`・`noexec`・`noatime`・`nodiratime`・
  `relatime`、Linux の `shmem_show_options` が出す tmpfs のオプションとともにそれを並べ
  ます。パスは通るディレクトリごとにいちばん上のマウントに入り、マウントのルートでの
  `..` はマウントした場所に出ます。マウントをまたぐ `rename` と `link` は `EXDEV`、
  マウントポイントの `rmdir`、`unlink`、`rename` は `EBUSY` で、名前の変更は動かす
  ディレクトリの下のマウントも動かします。`MS_RDONLY` は新しいマウントとその
  スーパーブロックを読み出し専用にし、`ro` オプションはスーパーブロックだけをそうします。
  mountinfo の 2 つの `ro` の欄がそれを示します。共有マウントの上のマウントも、自分の
  ピアグループで共有になります。

- `MS_BIND` 付きの `mount` は、`CAP_SYS_ADMIN` までの同じ確認のあと、Linux の
  `do_loopback` と同じくバインドマウントを作ります。ソースが要り（ないものや空のものは
  `EINVAL`）、リンクをたどって探し（`ENOENT`、`ENOTDIR`、`ELOOP`、`EACCES`）、ターゲットの
  マウントが呼び出し元の名前空間にあること（`EINVAL`）、ディレクトリの上にはディレクトリ、
  ファイルの上にはファイルであること（`ENOTDIR`）が要ります。新しいマウントは、ソースの
  マウントのファイルシステムをソースから下で見せます。デバイス、型、ソース、フラグは
  そのマウントのものです（呼び出しの型、データ、ほかのフラグは何も変えないので、
  `MS_RDONLY` を付けても読み出し専用になりません）。ID は自分のものを持ち、mountinfo の
  4 つ目の欄にはソースをルートとして出します。ロックはされません。`MS_REC` がなければ、
  ソースの下にロックされたマウントがあると `EINVAL`（`has_locked_children`）で、
  ロックされていないマウントは付いてこないので、新しいマウントにはそれが覆っている
  ディレクトリが見えます（`--mount` のディレクトリでも同じです）。`MS_REC` があれば、
  下のマウントも写しとして付いてきます。元がロックされていた写しはロックされます。
  tmpfs は、最初のマウントを外したあとも、そのバインドマウントがある間は残ります。
  バインドマウントは、ソースの名前を変えたあともそれを見せ続けます。`statx` と
  `/proc/self/fdinfo` はファイルのマウント ID をパスから求めるので、バインドマウントの
  ファイルはバインドマウントの ID を持ちます。ソースのマウントがバインドできない
  （unbindable）ものなら `EINVAL` で、`MS_REC` はその下のバインドできないマウントと
  その上のものを除きます（ロックされたものは `EPERM`）。新しいマウントはソースの
  マウントのピアで、そのマスターのスレーブです。共有マウントの上では共有になり、ソースの
  マウントがどのピアグループにもなければ新しいグループに入ります。

- バインドマウントのソースには、カーネルが `/dev` や `/proc` に生成するファイルも使えます
  （`mount --bind /dev/null file` や、プロセスのディレクトリのファイル。`/proc/self` は
  呼び出し元のものとして扱います）。新しいマウントはそのファイルをデバイスごと見せ、
  devtmpfs、procfs、devpts、mqueue のマウントとして、Linux がそれぞれに付けるフラグを
  持ちます（権限の低い所有者の名前空間ではロックされます）。mountinfo のルートは、その
  ファイルシステムの中でのファイルのパスです。マウントの場所へのパスや、そこへたどるリンクは
  そのファイルに届き、`stat`、`open`、読み書きはそのファイルを見ます。`/proc/self/fd` の
  リンクは、Linux の `d_path` と同じくマウントの場所を指します。名前そのものはマウントの
  もので、`unlink` と `rename` は使用中（`EBUSY`）、そこへの `mkdir` は `EEXIST`、その
  `link` は `EXDEV` です。そのマウントのバインドマウントは同じファイルのもう 1 つの
  マウントで、`umount2` で外せます。そこのディレクトリ（`/proc`、`/dev` やその下のもの）は
  ディレクトリの上にバインドできます。マウントの場所より下のパスはそのディレクトリより下の
  カーネルのパスなので、カーネルがそこに生成するものを見せます。マウントのルートでの `..`
  はマウントを出ます。そこを作業ディレクトリにすると、作業ディレクトリはマウントの場所で、
  `getcwd` はそれを返します（ない名前は `chdir` でも `ENOENT`）。生成されるディレクトリより
  下のマウントは表にないので、ロックされたもの（`has_locked_children`）はなく、`MS_REC`
  で付いてくるものもありません。

- `MS_REMOUNT` と `MS_BIND` 付きの `mount` は、Linux の `do_reconfigure_mnt` と同じく
  マウントのフラグだけを変えます。ターゲットは呼び出し元の名前空間のマウントのルートで
  （`EINVAL`）、より権限の少ない名前空間への写しでロックされたフラグはそのままで
  （`EPERM`。`MNT_LOCK_READONLY`、`MNT_LOCK_NODEV`、`MNT_LOCK_NOSUID`、
  `MNT_LOCK_NOEXEC`、`MNT_LOCK_ATIME`）、読み出し専用にするにはその上で書き込みのために
  開いたファイルがないことが要ります（`EBUSY`）。フラグは呼び出しのもので、atime の
  フラグはどれかを指定しなければそのままです。`MS_REMOUNT` だけのもの（`do_remount`）は
  同じ確認のあと、マウントのファイルシステムのオプションを解釈し（`EINVAL`）、
  スーパーブロックのユーザー名前空間に対する `CAP_SYS_ADMIN` が要り（`EPERM`）、
  `reconfigure_super` と同じくスーパーブロックを設定し直します。マウントし直しで変えない
  フラグのオプション（`dirsync`）は `EINVAL` で（フラグの `MS_DIRSYNC` は無視します）、
  読み出し専用にするにはそのどのマウントにも書き込みのために開いたファイルがないことが
  要り（`EBUSY`）、tmpfs のオプションは `shmem_reconfigure` と同じく確かめて変えます
  （上限なしでマウントしたものへの上限、ファイルが使っている量より小さい上限、スワップ
  するものへの `noswap`、クォータのないものへのクォータ、クォータの上限の変更は
  `EINVAL`。`size`、`nr_blocks`、`nr_inodes`、`huge`、`inode32`、`inode64`、`mpol` は
  変わり、`mode`、`uid`、`gid` は変わりません）。そのあとマウントは呼び出しのフラグを
  持ちます。

- `noexec` のマウントは、Linux の `path_noexec` と同じく何も実行しません。そこにある
  プログラム、スクリプトのインタープリター、ELF のインタープリターの `execve` は、許可の
  前に `EACCES` で、通常のファイルへの `X_OK` 付きの `access` も同じです。そこのファイルを
  `PROT_EXEC` で `mmap` すると `EPERM`、`READ_IMPLIES_EXEC` はそれに `PROT_EXEC` を足さず、
  `mprotect` もそのマッピングを実行できるようにはしません（`EACCES`。VMA に `VM_MAYEXEC`
  がありません）。カーネルが作るファイルは、Linux の `/proc` と `/dev`（`/dev` は
  systemd のもとで）と同じく `noexec` のマウントにあります。`/dev/zero` を `PROT_EXEC`
  で `mmap` すると `EPERM` ですが、そこのリンク（`/dev/fd`、`/proc/self/fd`）から
  たどったファイルはそれ自身のマウントにあります。`nodev` のマウントは、そこのデバイスを開きません（`EACCES`。
  `may_open_dev`。root でも同じです）。`nosuid` のマウントや、呼び出し元がいない
  ユーザー名前空間のスーパーブロックにあるプログラムは、set-user-ID と set-group-ID の
  ビットもファイルケーパビリティもなしに実行します（`mnt_may_suid`）。スクリプトでは、
  実際に動くファイルであるそのインタープリターについてです。

- 読み出し専用のマウントや、読み出し専用のスーパーブロックのマウントは、Linux の
  `mnt_want_write` と同じところで、その前に来るエラーのあとに、書き込むものを `EROFS` で
  断ります。名前を作るもの（`O_CREAT` と `O_TMPFILE` 付きの `open`、`mkdir`、`mknod`、
  `symlink`、`link`、`AF_UNIX` ソケットの `bind`）は名前がないとわかったあと（`EEXIST` が
  先）、ディレクトリに書く許可の前（と `link` の `EXDEV`、デバイスの `mknod` の `EPERM`
  の前）です。`unlink`、`rmdir`、`rename` はディレクトリが見つかったあと、名前を探す前
  です（なので、ない名前も `EROFS` です）。通常のファイルの `O_TRUNC` 付きの `open` と、
  書き込みのために開くこと（許可と `ETXTBSY` のあと。FIFO、ソケット、デバイスは
  開けます）、`EISDIR` と `EINVAL` のあとの `truncate`、許可の確認の前の `chmod`、
  `chown`、`utimensat`、`utimes` とそのディスクリプタの形、`setxattr`、`removexattr` と
  そのディスクリプタの形、`file_setattr`、`FS_IOC_SETFLAGS`、許可の確認のあとの `W_OK`
  付きの `access` もそうです。読み出し専用のスーパーブロックは、通常のファイル、
  ディレクトリ、シンボリックリンクに書くことも許可を確かめる前に断ります
  （`sb_permission`）。`statfs` の `f_flags` は、`flags_by_mnt` と同じくマウントの
  フラグ（`ST_RDONLY`、`ST_NOSUID`、`ST_NODEV`、`ST_NOEXEC`、`ST_NOATIME`、
  `ST_NODIRATIME`、`ST_RELATIME`）を返します。`/proc` と `/dev` では Linux がそれを
  マウントするときのフラグです。`/proc` と `/dev/mqueue` は `nosuid`・`nodev`・
  `noexec`・`relatime`、`/dev/pts` は `nosuid`・`noexec`・`relatime`、ほかの `/dev`
  （devtmpfs）は systemd がマウントするのと同じく `nosuid`・`noexec`・`relatime` です。
  `/dev/shm` は、systemd がマウントするのと同じく、起動したときから `/dev` の上にある
  tmpfs です（`mode=01777`、`nosuid`、`nodev`）。C ライブラリの POSIX 共有メモリと
  セマフォはここにファイルを作ります。アンマウントも、上へのマウントもできます。`/proc/self/fd` のリンクはそのファイルの
  ものを返し、カーネルの内部のマウント（パイプ、ソケット、匿名 inode、pidfs、memfd、
  secretmem、`mq_open` で開いたキュー）は `ST_VALID` だけです。

- `MS_SHARED`、`MS_PRIVATE`、`MS_SLAVE`、`MS_UNBINDABLE` 付きの `mount`（`MS_REC` が
  あればターゲットの上のマウントも）は、`do_change_type` の確認のあと、マウントの伝播の
  種類を変えます。マウントのルートであること（`EINVAL`）、種類が 1 つでほかのフラグが
  ないこと（`EINVAL`）、マウントの名前空間に対する `CAP_SYS_ADMIN`（`EPERM`）が要ります。
  共有マウントはピアグループに入り（どれにもなければ空いているいちばん小さい番号の新しい
  もの）、バインドできないものではなくなります。ほかの種類にするとグループから出ます。
  そのスレーブはピアに、ピアが残っていなければそのマウントのマスターにつきます。
  `MS_SLAVE` は、ピアがあれば元のグループの、なければマスターのスレーブにし、
  `MS_PRIVATE` と `MS_UNBINDABLE` はマスターをなくします。`/proc/self/mountinfo` は
  Linux の `show_mountinfo` と同じく、それを `shared:N`、`master:N`、`propagate_from:N`、
  `unbindable` で示します。新しいマウント名前空間への写しは写したマウントのピアで、
  ユーザー名前空間がほかのものならそのスレーブです。外したマウントや、名前空間が
  終わったマウントも、同じようにピアグループから出ます。

- 共有マウントの上へのマウント、バインドマウント、移動は、Linux の `propagate_mnt` と
  同じく伝播します。そのピアグループが届くほかのマウント（ピア、スレーブ、そのスレーブ。
  どのマウント名前空間のものも）のうち、ルートがその場所を含むものそれぞれに、新しい
  マウントの写しがそこにできます。ピアの写しは新しいマウントのピアで、スレーブの写しは
  そのスレーブです。スレーブが共有なら、写しは新しいピアグループで共有になります。ほかの
  ユーザー名前空間の名前空間への写しはロックされ、その場所にすでにあるマウントは写しの
  ルートの上に移ります。共有マウントの下でのマウントの解除は、`propagate_umount` と同じく、
  それらの同じ場所にあるマウントも外します。ただし、ほかのマウントが上にあるものは残します
  （ルートの上のマウントは、その場所に移ります）。外した場所のものはロックが外れ
  （`propagate_mount_unlock`）、その下のロックされたものは親と一緒にだけ外れます
  （`handle_locked`）。`MNT_DETACH` がなければ、そのどれかで
  開いているファイルがあると、解除は `EBUSY` です（`propagate_mount_busy`）。スレーブ自身の
  マウントは、そのスレーブには届き、マスターには届きません。

- `MS_MOVE` 付きの `mount` は、Linux master の `do_move_mount` と同じ確認のあと、
  マウントを動かします。ソースがあること（ないか空なら `EINVAL`）、最後のリンクを
  たどって探したソースがマウントのルートであること（`EINVAL`）、ディレクトリーは
  ディレクトリーの上に、ファイルはファイルの上に置くこと（`EINVAL`）を確かめ、
  そのあと名前空間のルート、ロックされたマウント、共有マウントの上のマウントは
  `EINVAL`、バインドできないマウントを含む木を共有マウントの上に置くのも `EINVAL`、
  そのマウント自身かその上のマウントの上に置くのは `ELOOP` です。マウントは、上の
  マウントとともにターゲットにあるものの上に行き、元の場所には下のディレクトリーが
  また見えます。共有マウントの上では、それぞれが共有になります（どのピアグループにも
  なければ新しいものに入ります）。その中のルートと作業ディレクトリーも一緒に動きます。

- `pivot_root`（Linux master の `path_pivot_root`）は、2 つのパスを、リンクをたどって
  ディレクトリーとして新しいルートから探します。そのあと、マウント名前空間に対する
  `CAP_SYS_ADMIN` と、ファイルへのアクセスを扱う Landlock のドメインがないこと
  （`EPERM`）が要ります。`put_old`・新しいルートの下・呼び出し元のルートの下に共有
  マウントがあるか、新しいルートがロックされていれば `EINVAL`、新しいルートや `put_old`
  がルートのマウントにあれば `EBUSY` です。ルートと新しいルートはマウントのルートで、
  `put_old` は新しいルートかその下に、新しいルートはルートの下にあることが要ります
  （`EINVAL`）。新しいルートのマウントは上のマウントとともにルートの場所に入り、古い
  ルートはその木の残りとともに `put_old` に行きます。古いルートのロックは新しいルートが
  引き継ぐので、新しいユーザー名前空間のマウント名前空間でも古いルートを外せます。
  名前空間の中で、ルートか作業ディレクトリーが古いルートだったプロセスはどれも新しい
  ルートに移り（`chroot_fs_refs`）、ほかのプロセスのものはそのマウントとともに動きます。
  `pivot_root(".", ".")` は古いルートを新しいルートの上に重ね、それを
  `umount2(".", MNT_DETACH)` で外せます。

- `open_tree`（Linux master の `vfs_open_tree`）は、まずフラグを確かめ（知らない
  もの、写しなしの `AT_RECURSIVE`、再帰的な写しなしの `OPEN_TREE_DROP_MNTNS_MOUNTS`
  は `EINVAL`）、`OPEN_TREE_CLONE` にはマウント名前空間に対する `CAP_SYS_ADMIN` を
  求め（`EPERM`）、そのあとパスを探します。最後のリンクは `AT_SYMLINK_NOFOLLOW`
  がなければたどり、`AT_EMPTY_PATH` があれば空のパスは `dfd` 自身です。ファイルの
  `O_PATH` のディスクリプタを返し、`OPEN_TREE_CLONE` ではそのマウントの写し
  （`AT_RECURSIVE` があれば、バインドマウントと同じく下のマウントも）を、自分だけの
  木として返します。この木にはどのパスからも mountinfo からも届かず、`move_mount`
  でつながなければディスクリプタを最後に閉じたときになくなります。ディスクリプタからの
  パスは写しの中に入り、`..` はその根にとどまります。`OPEN_TREE_NAMESPACE` には
  呼び出し元のユーザー名前空間での `CAP_SYS_ADMIN` が要り（パスを探す前に
  `EPERM`）、そのユーザー名前空間が持つ新しいマウント名前空間のディスクリプタを
  返します（Linux master の `create_new_namespace`）。`/proc/<pid>/ns/mnt` を開いた
  ものと同じく `mnt:[...]` で、`setns` で入れます。そのルートは、名指したディレクトリを
  根とするマウントの写しで（ファイルなら `ENOTDIR`）、`AT_RECURSIVE` があれば下の
  マウントも写します。写しは、どの mountinfo にも出ない下のマウント（Linux の nullfs
  の写し）の上に載ります。呼び出し元の名前空間のルートがロックされていれば、ルートも
  ロックされます。別のユーザー名前空間が持つマウント名前空間からでは、写しはピアでなく
  スレーブになり、下のバインドできないマウントも写し、どの写しもフラグごとロックされ
  （`lock_mnt_tree`）、ディレクトリの下にマウントがあるマウントの `AT_RECURSIVE` なしの
  写しは `EINVAL` です。

- `move_mount`（Linux master のもの）は、マウント名前空間に対する
  `CAP_SYS_ADMIN`（`EPERM`）と、知っているフラグ（`EINVAL`。`MOVE_MOUNT_BENEATH` と
  `MOVE_MOUNT_SET_GROUP` の両方も）を求め、ターゲット、ソースの順に探します。それぞれ
  `MOVE_MOUNT_*_SYMLINKS` があるときだけ最後のリンクをたどり、`MOVE_MOUNT_*_EMPTY_PATH`
  があれば空のパスはディスクリプタ自身です。Landlock のドメインでは `EPERM` です。
  マウントを `MS_MOVE` と同じく動かすか、`open_tree` の木をつなぎます。つなげるのは
  その根だけで（`EINVAL`）、自分の木の上にはつなげず（`EINVAL`）、名前空間のマウントは
  切り離された木の上には行きません（`EINVAL`）。`MOVE_MOUNT_BENEATH` では、ソースは
  ターゲットのいちばん上のマウントの下、そのマウントの親の上に入り、いちばん上のマウントは
  ソースのルートの上に載ったまま残ります（`MNT_TREE_BENEATH` 付きの `do_move_mount`）。
  ターゲットはマウントのルートで、名前空間のルートではないこと（`EINVAL`）が要り、
  そのあと移動の確認をその親について行います。ソースがいちばん上のマウントの木の中に
  あるときは `EINVAL` で、共有の親がソースの写しを、いちばん上のマウントかソースの
  ルートの上に伝えてしまうとき（`propagation_would_overmount`）も `EINVAL` です。いちばん上のマウントがロックされて
  いれば、そのロックはソースに移るので、いちばん上のマウントはそのあと外せます。
  `MOVE_MOUNT_SET_GROUP` は、ターゲットを
  ソースのピアグループに入れます（`do_set_group`）。どちらもマウントのルートで、同じ
  スーパーブロックのもの、ターゲットのルートはソースのルートかその下、ターゲットは
  プライベート、ソースは共有かスレーブであることが要ります（`EINVAL`）。

- `fsopen`、`fsconfig`、`fsmount`、`fspick`（Linux master の `fs/fsopen.c`）は、
  ファイルシステムのコンテキストを通して tmpfs を作ります。コンテキストは
  ディスクリプタ（`anon_inode:[fscontext]`）で、`fsconfig` が中身を入れて操作します。
  `fsopen` はマウント名前空間に対する `CAP_SYS_ADMIN`（`EPERM`）と知っているフラグ
  （`EINVAL`）を求め、tmpfs 以外の型は `ENODEV` です。`fsconfig` はコマンドごとの
  引数（`EINVAL`。知らないコマンドは `EOPNOTSUPP`）、次にディスクリプタ（`EBADF`。
  ほかのファイルなら `EINVAL`）を確かめます。`mount` が受け取るパラメーターを 1 つずつ
  同じ確認で受け取り、断ったものごとに Linux が記録するメッセージを、ディスクリプタの
  `read` が古い順に返し（`e tmpfs: Bad value for 'size'`、`e tmpfs: Unknown parameter
  'x'` など）、なくなると `ENODATA` です。`FSCONFIG_CMD_CREATE` はスーパーブロックを
  作り（ユーザー名前空間に対する `CAP_SYS_ADMIN`、`EPERM`）、そのあとコンテキストは
  パラメーターを受け取りません（`EBUSY`）。`fsmount` はフラグとマウントの属性を確かめ
  （`EINVAL`）、`open_tree` と同じ切り離された木にそれをマウントします（スーパー
  ブロックを作る前は `EINVAL`、マウントしたあとは `EBUSY`）。`move_mount` でそれを
  つなげ、コンテキストはそのあとそれをマウントし直すものになります。`fspick` は
  マウントのスーパーブロックのコンテキストを返し（マウントのルートでなければ
  `EINVAL`）、その `FSCONFIG_CMD_RECONFIGURE` は、名前を挙げたフラグと tmpfs の
  オプションを `MS_REMOUNT` と同じく変えます（スーパーブロックのユーザー名前空間に
  対する `CAP_SYS_ADMIN` がなければ `EPERM` で、コンテキストは失敗した状態になり、
  それからは `EBUSY` です）。

- `mount_setattr`（Linux master のもの）は、フラグ（`EINVAL`）、次に
  `struct mount_attr`（1 ページを超えるか、その後ろに 0 でないバイトがあれば `E2BIG`、
  32 バイト未満なら `EINVAL`）、マウント名前空間に対する `CAP_SYS_ADMIN`（`EPERM`）、
  伝播の種類が 1 つまでで知っている属性であること（`EINVAL`）、アクセス時刻の設定は
  `MOUNT_ATTR__ATIME` をすべて消すときだけであること（`EINVAL`）を確かめます。何も
  変えないものは、探す前に 0 です。マウントのルート（`EINVAL`）で、名前空間のものか
  切り離された木の根であれば、そのマウントのフラグを付けたり消したりし、
  `AT_RECURSIVE` があれば下のマウントのものも、すべてかどれも変えないかです。ロック
  されたフラグが変わるなら `EPERM`、書き込みのために開いたファイルがあって読み出し専用に
  するなら `EBUSY` です。そのあとマウントは伝播の種類を受け取ります。`open_tree_attr` は、
  同じ変更をディスクリプタのマウントに加える `open_tree` で、変更に失敗すれば
  ディスクリプタはまたなくなります。

- マウントはそれぞれ、マシンが終わるまで一意な ID（`mnt_id_unique`。`1 << 31` の次
  から、作った順で、名前空間の写しは `copy_tree` がたどる順）を持ち、マウント
  名前空間もそれぞれ ID（最初のものは 8）を持ちます。`listmount`（Linux master の
  もの）はフラグ・数・配列（`EINVAL`、`EOVERFLOW`、`EFAULT`）と `struct mnt_id_req`
  （`E2BIG`、`EINVAL`）を確かめ、呼び出し元のルート（`LSMT_ROOT`）かマウント（ない
  なら `ENOENT`）から届くマウントの ID を、最後に渡された ID のあとから順に
  （`LISTMOUNT_REVERSE` なら逆順に）返します。名前空間は呼び出し元のものか、名前空間の
  ファイルか ID で示すものです（`ENOENT`、`EBADF`、`EINVAL`。ほかのものは、それに
  対する `CAP_SYS_ADMIN` があるときだけです）。`statmount` はその 1 つ、または
  `STATMOUNT_BY_FD` ならディスクリプタのファイルのマウントについて、スーパーブロックの
  デバイス・型・フラグ、マウントの ID・属性・伝播、そのルートと呼び出し元のルートから
  見たマウントポイント、型の名前、オプションそのものとその配列、ソース、名前空間の ID を、
  求められたとおりに返します（`mask`、`supported_mask`）。文字列に足りないバッファは
  `EOVERFLOW`、呼び出し元のルートから届かないマウントは `CAP_SYS_ADMIN` がなければ
  `EPERM` です。

- `umount2` は、ターゲットを探す前にフラグを確かめます（`EINVAL`）。最後のリンクは
  `UMOUNT_NOFOLLOW` がなければたどり、パスの始まりの上のマウントにも入ります
  （`LOOKUP_MOUNTPOINT`）。そのあと Linux の `can_umount` と `do_umount`
  と同じく、マウント名前空間に対する `CAP_SYS_ADMIN`（`EPERM`）、その名前空間のマウントの
  ルートで、ロックされていないこと（`EINVAL`）、`MNT_FORCE` にはスーパーブロックのユーザー
  名前空間での `CAP_SYS_ADMIN`（`EPERM`）、ファイルへのアクセスを扱う Landlock のドメインが
  ないこと（`EPERM`）が要ります。開いたファイル（`O_PATH` のものとマッピングも）・作業
  ディレクトリ・ルートが使っているマウントや、上にほかのマウントがあるマウントは `EBUSY`
  です。ただし `MNT_DETACH` は、それと上のマウントをすぐに外し、開いたファイルは読み書き
  できるままです。`MNT_EXPIRE`（`MNT_FORCE` や `MNT_DETACH` 付き、呼び出し元のルートでは
  `EINVAL`）は、だれも使っていないマウントに印を付け（`EAGAIN`）、次の呼び出しで外します。
  Linux の `mntput` と同じく、マウントで終わる探索やその上のファイルを閉じることで印は
  消えます。`MNT_DETACH` なしの呼び出し元のルートには、そのスーパーブロックのユーザー
  名前空間に対する `CAP_SYS_ADMIN` が要り（`EPERM`）、マウントされたまま、
  スーパーブロックを読み出し専用にマウントし直します（`do_umount_root`。その上で書き込みの
  ために開いたファイルがあれば `EBUSY`）。

- `unshare` は、Linux と同じく `CLONE_FILES` ならスレッドに自分のディスクリプター表を、
  `CLONE_FS` なら自分の作業ディレクトリーと umask を与えます。`CLONE_THREAD`、
  `CLONE_SIGHAND`、`CLONE_VM` は、分けるものがなければ成功し、Linux と同じ場合に
  `EINVAL` です。プロセスにほかのスレッドがあるとき、ほかのプロセスとシグナルの扱いを
  共有しているとき（`CLONE_SIGHAND`）、ほかのプロセスとメモリーを共有しているとき
  （`CLONE_THREAD` なしの `CLONE_VM`）です。`CLONE_SYSVSEM`（と `CLONE_NEWIPC`）は、
  終了と同じくセマフォーの undo リストを離れます。名前空間のフラグは、次のとおりスレッドに
  新しい名前空間を与えます。

- スレッドは、Linux の `nsproxy` と同じく自分の名前空間を持ちます。UTS・IPC・マウント・
  cgroup・time・PID・ネットワーク・ユーザーの名前空間は自分のものです（ユーザーの名前空間は
  資格情報が持ちます）。`CLONE_NEWUTS`、`CLONE_NEWIPC`、`CLONE_NEWNS`、`CLONE_NEWCGROUP`、
  `CLONE_NEWTIME`、`CLONE_NEWPID`、`CLONE_NEWNET`、`CLONE_NEWUSER` を付けた `unshare` は
  スレッドに新しい名前空間を与え、`clone` も子に（`CLONE_NEWPID` と `CLONE_NEWUSER` を
  除いてスレッドにも）与えます（`CLONE_NEWTIME` は `clone3` で付けます）。新しいユーザーの
  名前空間には特権が要りません。ほかの名前空間には、そのときスレッドが持つユーザーの名前空間での
  `CAP_SYS_ADMIN` が要り（なければ `EPERM`）、いっしょに作る新しいユーザーの名前空間が
  それを与えます。新しい UTS 名前空間はホスト名と
  ドメイン名の写しで始まり、その後の `sethostname` と `setdomainname` はその名前空間だけを
  変えます。新しいマウント名前空間は、マウントごとに新しい ID の写しを同じファイルシステムに
  持って始まり、新しい名前空間のユーザー名前空間がほかのものならそれをロックします
  （`lock_mnt_tree`）。その中の `mount` と `umount2` は、その名前空間のマウントだけを変え
  ます。スレッドのルートと作業ディレクトリは同じパスのまま写しの上に移ります。新しい time 名前空間は、スレッドの子が入るものです。メモリーを共有しない子は
  それに入り、スレッドもプログラムを実行するとそれに入ります。`clone` は、Linux と同じく
  `CLONE_FS` 付きの `CLONE_NEWNS` と `CLONE_SYSVSEM` 付きの `CLONE_NEWIPC` を `EINVAL`
  で断ります。`/proc/<pid>/ns`（と `/proc/thread-self/ns`、`/proc/<pid>/task/<tid>/ns`）
  には Linux と同じ 10 個のリンクがあり、`uts:[4026531838]` のように読めます。最初の
  名前空間は Linux の固定の番号を持ち、新しい名前空間は作った順に番号が付きます。リンクを
  開くと名前空間のファイルになります。これはハンドルで、読み書きは `EINVAL`、シークは
  `ESPIPE` で、inode はその番号です。`setns` は、そのファイルの名前空間（`nstype` は
  その種類か 0）か、pidfd のプロセスの名前空間のうち `nstype` で指定したものに入ります。
  確かめる中身と順番は Linux と同じです。ユーザーの名前空間は、スレッド自身のものでも、
  メモリーか作業ディレクトリーをほかと共有するスレッドでもいけず（`EINVAL`）、その中での
  `CAP_SYS_ADMIN` が要り、入るとそこでのすべてのケーパビリティを持ちます。time 名前空間は
  スレッドがメモリーの中でひとりであること（`EUSERS`）、マウント名前空間にそれだけで入る
  ときはほかのスレッドと共有しない作業ディレクトリー（`EINVAL`）と `CAP_SYS_CHROOT`、
  どの名前空間も、それを持つユーザーの名前空間とスレッド自身のものでの `CAP_SYS_ADMIN`
  （`EPERM`）が要り、PID 名前空間はスレッド自身のものか、その中のものでなければなりません
  （`EINVAL`）。マウント
  名前空間に入ると、作業ディレクトリーはその root に移り、PID 名前空間に入ると、それが
  スレッドの子に番号を付ける名前空間になり、ネットワーク名前空間に入ると、それが
  スレッドが新しく作るソケットの名前空間になります。新しく作れない名前空間は
  [制限](./limitations.md)を見てください。

- 新しいユーザーの名前空間は、Linux の `create_user_ns` と同じく、スレッドのものの中に
  入れ子になり、その実効ユーザーが持ち主です（そのユーザーかグループに中での ID がなければ
  `EPERM`、32 段を超えると `ENOSPC`）。スレッドはその中と、いっしょに作った名前空間で
  すべてのケーパビリティを持ちます。カーネルは ID を最初のユーザーの名前空間のものとして
  持ち、システムコールは呼び出し元の名前空間の対応表で ID を受け渡しします。対応のない ID は
  65534（`overflowuid`）に見え、渡すと `EINVAL` です。これは `get*id` と `set*id`、
  `setgroups`、`getgroups`、`stat` と `statx`、`chown` の仲間、シグナルと `waitid` の
  `si_uid`、`SCM_CREDENTIALS` と `SO_PEERCRED`、`shmctl` と `semctl`、
  `/proc/<pid>/status`、コアで同じです。`set*id`・`access`・exec のケーパビリティの規則でのルートは、名前空間が 0 に
  対応させる ID で、持ち主かグループに対応のない set-user-ID のプログラムは呼び出し元の
  ままで動きます。ケーパビリティは、Linux の `cap_capable` と同じく、スレッド自身の
  ユーザーの名前空間と、その実効ユーザーが作った入れ子の名前空間で効きます。ファイルには
  名前空間がその持ち主とグループに対応を持つときだけ、名前空間（ホスト名の設定、`setns`、
  `SIOCSIFFLAGS`、System V の共有メモリとセマフォー）にはそれを持つユーザーの名前空間でのもの、ほかの
  プロセス（`kill`、`ptrace` のアクセス、優先度、リソース制限）にはそのユーザーの名前空間での
  もの、マシン全体（`RENAME_WHITEOUT`、リアルタイムのスケジューリング、`vhangup`、`trusted.*` の属性
  など）には最初のユーザーの名前空間でのものだけが効きます。`/proc/<pid>/uid_map` と
  `gid_map` は、タスクのユーザーの名前空間の範囲を、下の ID を読み手の名前空間のもの
  （自分の名前空間なら親のもの）で読みます。書き込みは、3 つの数の行を 340 行までの 1 回だけで、
  確かめる中身と順番は Linux の `proc_uid_map_write`・`map_write`・`new_idmap_permitted` と
  同じです。その名前空間かその親の、中で `CAP_SYS_ADMIN` を持つスレッドから書き、持ち主は
  自分の実効 ID だけを対応させられます（グループは `setgroups` を `deny` にしてから）。
  ほかの対応には親での `CAP_SETUID` か `CAP_SETGID` が、親のルートの対応には
  `CAP_SETFCAP` が要ります。`/proc/<pid>/setgroups` は `allow` か `deny` を読み、gid の
  対応表より前に書けます。`setgroups` には、それが `allow` で gid の対応表があることが要ります。
  これらのファイルは、開いたときにタスクがいたユーザーの名前空間を（`proc_id_map_open`）、
  先頭から読むたびにそのときの中身で、範囲ごとに 1 行ずつ読みます。書き込みは先頭からでなければ
  ならず、ファイル位置を書いた分の後ろに進めるので、そのあとの読み込みはそこから続きます。

- 新しい PID 名前空間は、Linux と同じく、スレッドの子に番号を付ける名前空間です。
  スレッド自身は元の名前空間に残り、`pid_for_children` のリンクは、最初の子
  （名前空間の init で、番号は 1）ができるまで `ENOENT` です。子が新しい名前空間に
  入る状態での 2 度目の `CLONE_NEWPID` は `EINVAL` で、そのときのスレッドの作成も、
  プロセスと別に番号が付くことになるので `EINVAL` です。Linux の 32 段（最初の名前空間を
  0 段目とします）より深い名前空間は `ENOSPC` です。プロセスやスレッドは、自分の
  名前空間と、それを含む名前空間のそれぞれで番号を持ち、ほかのプロセスを自分の名前空間の
  番号で見ます。名前空間の外のプロセスは 0 で、名前空間が配っていない番号は何も指しません。
  これは `getpid`、`gettid`、`getppid`、`getpgid`、`getpgrp`、`getsid`、`setsid`、
  `setpgid`、`kill`、`tkill`、`tgkill`、`rt_sigqueueinfo`、`rt_tgsigqueueinfo`、`wait4`、
  `waitid`、`pidfd_open`、`getpriority`、`setpriority`、`ioprio_get`、`ioprio_set`、
  `sched_*` の呼び出し、`prlimit64`、`capget`、`capset`、`get_robust_list` でも、`clone`
  が返して書き込む ID、`set_tid_address` が返す ID、シグナルの `si_pid`（外からなら 0）でも、
  `F_SETOWN`、`F_GETOWN`、`F_GETLK` の `l_pid`、`TIOCGPGRP`、`TIOCSPGRP`、`TIOCGSID`
  でも、`SCM_CREDENTIALS` と `SO_PEERCRED` でも、`shmctl` のプロセス ID と `semctl` の
  `GETPID`、コアの中でも同じです。`kill(-1)` は、呼び出したプロセスの名前空間の、init を除くプロセスに送ります。
  `/proc` は、Linux で最初の名前空間でマウントした `/proc` と同じく、最初の名前空間の ID を
  見せます。`/proc/<pid>/status` の `NStgid`、`NSpid`、`NSpgid`、`NSsid` の行は、
  タスクの ID を、そこと、その下から自分の名前空間までのそれぞれの名前空間で示します
  （名前空間の外のグループやセッションは 0）。`clone3` の `set_tid` は、子が取る番号を
  自分の名前空間から外へ 1 つずつ与え、Linux の `alloc_pid` と同じく確かめます。名前空間より
  多い番号、1 より小さいか 4194304（Linux の `pid_max` の最大）以上の番号、init がまだない
  名前空間での 1 以外の番号は `EINVAL`、その名前空間を持つユーザー名前空間で
  `CAP_SYS_ADMIN` も `CAP_CHECKPOINT_RESTORE` もなければ `EPERM`、使われている番号は
  `EEXIST` です。最初の名前空間の番号は paludarium がタスクを呼ぶ ID なので、そこでの
  `set_tid` は、まだどのタスクも持ったことのない ID を取ります。init は、ハンドラーのあるシグナルと、名前空間の外かカーネルからの SIGKILL と
  SIGSTOP だけを受け取ります（Linux の `SIGNAL_UNKILLABLE`）。フォールトでは終わります。
  名前空間の孤児は init か、名前空間の中の子のサブリーパーに引き取られます。init が
  終わると、名前空間のほかのプロセスはすべて SIGKILL を受け、名前空間にはもう入れません
  （`ENOMEM`）。init の親は、Linux の `zap_pid_ns_processes` と同じく、残りがいなくなって
  から（init の子は init が刈り取ります）init の終了を知ります。

- 新しいネットワーク名前空間には、Linux の `loopback_net_init` と同じく、ループバックの
  `lo`（インデックス 1）だけがあり、それは落ちています。そこでの TCP や UDP のソケットは、
  IPv4 に経路ができるまではどの IPv4 のアドレスにも bind できますが、`::1` には
  できず（`EADDRNOTAVAIL`）、接続もデータグラムもどこにも届きません（`ENETUNREACH`）。
  `IFF_UP` を付けた `SIOCSIFFLAGS`（CAP_NET_ADMIN が要り、なければ `EPERM`）で上げると、
  上がっている間だけ `::1` が付き、ほかのどの名前空間とも別のポート・待ち受け・データグラムを持つ
  自分の[ループバック](#loopback-servers)になります。ループバックの外は、DNS スタブが
  ないので 53 番ポートも含めて、`ENETUNREACH` のままです。ネットワークのないセッションでも
  そこにはループバックがあります。ソケットは作られた名前空間に残ります。抽象名前空間の
  unix ソケットの名前（0 で始まるもの）は、Linux の `unix_find_abstract` と同じく
  ソケットの名前空間の名前の中で bind され、探されます。パスのソケットファイルには
  どの名前空間からも届きます。どのファミリーのソケットへの `SIOCGIFFLAGS` と
  `SIOCGIFINDEX` も（glibc と musl の `if_nametoindex` が使う AF_UNIX のものも）、
  Linux の `dev_ioctl` が `sock_net` を取るのと同じく、ソケットが作られた名前空間の
  デバイスを読みます。ループバック（上がっている間は最初の名前空間でも
  `IFF_UP | IFF_LOOPBACK | IFF_RUNNING`）と veth の端（下の veth の組）です。accept した AF_UNIX のソケットは、
  クライアントの名前空間のものです。`SIOCSIFFLAGS` には、呼び出し元がどこにいても、
  その名前空間を持つユーザーの名前空間での CAP_NET_ADMIN が要ります。ネットワークの
  ない最初の名前空間の AF_UNIX のソケットには、ネットワークがありません（`ENOTTY`）。
  ほかのインターフェースの名前は `ENODEV` です。`SIOCGIFNAME`
  （`if_indextoname`）は、そのインデックスのデバイスの名前を答えます（なければ
  `ENODEV`）。

- netlink のソケット（`AF_NETLINK`、`SOCK_RAW` か `SOCK_DGRAM`、プロトコル
  `NETLINK_ROUTE`）は、作られたネットワーク名前空間のデバイス（ループバックと、下の veth の組の
  端）を見せ、変えます。
  そのため glibc と musl の `getifaddrs`、`ip link`、`ip addr`（`ip addr add` と `del` も）、
  `ip route`（`ip route add`、`del`、`replace`、`append` も）、`ip route get`、
  `ip link set lo up`、`ip monitor` が動きます。
  - **ソケット:** Linux の `af_netlink` と同じく、`bind` はポート ID（ほかのソケットが
    持つものは `EADDRINUSE`）を、0 ならプロセスの ID を、それが使われていれば負の ID を
    取ります。bind していないソケットは、`connect` か最初の送信で同じように bind されます。
    `getsockname` と `getpeername` はポートとグループを返し、ほかのソケットのポートへの
    データグラムはそのソケットに届きます（なければ `ECONNREFUSED`）。`recvmsg` は送り手の
    `sockaddr_nl` を返し、`MSG_PEEK` と `MSG_TRUNC` が使えます。`SO_RCVBUF`、
    `SO_SNDBUF`、`SO_RCVTIMEO`、`NETLINK_PKTINFO`、`NETLINK_BROADCAST_ERROR`、
    `NETLINK_NO_ENOBUFS`、`NETLINK_LISTEN_ALL_NSID`（ソケットの名前空間への
    `CAP_NET_BROADCAST` が要ります）、`NETLINK_CAP_ACK`、`NETLINK_EXT_ACK`、
    `NETLINK_GET_STRICT_CHK` を設定できます。Linux の `netlink_setsockopt` と同じく、
    `int` より短い値は 0 です。`NETLINK_PKTINFO` を付けると、`recvmsg` はデータグラムの
    グループ（ソケット自身のポートに来たものは 0）を `SOL_NETLINK` の `NETLINK_PKTINFO`
    制御メッセージで返し、入らなければ `MSG_CTRUNC` を立てます。`NETLINK_BROADCAST_ERROR`
    は覚えるだけです。ここでは届かなかった通知を誰かに伝えることがないからです。
    受信バッファーがいっぱいのときにカーネルから来た
    メッセージは捨て、次の受信で `ENOBUFS` を返します。そのあとソケットは、Linux の
    `NETLINK_S_CONGESTED` と同じく混んでいるとされ、受信でキューが空になるまで、カーネルから
    来るほかのメッセージも捨てます（`ENOBUFS` は繰り返しません）。`NETLINK_NO_ENOBUFS`
    を付けたソケットは、どちらもなしに捨てます。これを付けると混んだ状態も終わります。
    ダンプの続きはこれを見ません。ほかのソケットから来るデータグラムは、空きがないかソケットが混んでいれば、
    空きができるまで待ちます（`MSG_DONTWAIT` か `O_NONBLOCK` なら `EAGAIN`）。こちらは
    あふれたことにはなりません。
  - **リクエスト:** カーネル（ポート 0）は、`rtnetlink` と同じくデータグラムのメッセージを
    1 つずつ受け取ります。ダンプ（`NLM_F_DUMP`）は、Linux の `netlink_dump` と同じ大きさに
    分けて答えます（1 ページ分、あるいはそれまでで一番長い受信の分で 32 KiB まで。次の部分は
    受信が空きを作ったときに送ります）。最後は別の部分の `NLMSG_DONE` です。`AF_INET6` の
    アドレスとリンクのダンプでは、`inet6_dump_ifaddr` と `inet6_dump_ifinfo` と同じく、
    空きがあれば最後のメッセージと同じ部分に入れます。
    エラーと、`NLM_F_ACK` を付けた成功には `NLMSG_ERROR` を返し、エラーのものは
    `NETLINK_CAP_ACK` がなければリクエスト全体を載せます。`NETLINK_EXT_ACK` を付けると、
    エラーと、ダンプをすぐに終える `NLMSG_DONE` に、Linux の `netlink_ext_ack` が持つものを
    載せます（`NLM_F_ACK_TLVS`）。Linux のメッセージ（`NLMSGERR_ATTR_MSG`）、問題の属性の
    オフセット（`NLMSGERR_ATTR_OFFS`）、その属性を拒んだポリシー（`NLMSGERR_ATTR_POLICY`）
    です。確認応答には、属性のあとに残ったバイトのような警告を載せます。`rtnetlink` の知る最後
    （`RTM_MAX`、123）より後の型のメッセージも送れて、`rtnetlink_rcv_msg` と同じく
    `EOPNOTSUPP` を返します。`GET` のほかには、ネットワーク
    名前空間を持つユーザーの名前空間での `CAP_NET_ADMIN` が、送るスレッドとソケットを
    開いたものの両方に要ります（なければ `EPERM`）。アドレスを指して送るとき
    （`sendto`、名前を付けた `sendmsg`）は、`netlink_sendmsg` がそれに `NETLINK_SKB_DST` の
    印を付け、`__netlink_ns_capable` が開いた側を見ないので、送るスレッドのものだけが要ります。
    `write`（と `writev`、`sendfile`、`splice`、AIO の書き込み）は、`netlink_sendmsg` が
    書くスレッドで動くので、アドレスのない `send` と同じく、書くスレッドとして送ります。
    自動のバインドはそのプロセス ID をポートにし、経路の検索はそのユーザー ID を `RTA_UID`
    にし、変更にはその `CAP_NET_ADMIN` と開いた側のものが要ります。`bind` と
    `NETLINK_ADD_MEMBERSHIP` のマルチキャストの経路のグループ、ほかのポートやグループへの
    `connect` は、呼び出したスレッドのものだけを見ます（`rtnetlink_bind`、`netlink_allowed`）。
  - **厳密な検査:** iproute2 と同じく `NETLINK_GET_STRICT_CHK` を設定すると、Linux と
    同じくリクエストを調べます。ダンプには、絞り込みに使うもの以外は空のヘッダーが
    そろっていて、属性は絞り込みに使うものだけで、型が知られたもので、余るバイトが
    ないことが要ります。そうでなければ `NLMSG_DONE` の `EINVAL` で終わります。
    アドレスのダンプのインデックスは `lo` のアドレスだけを見せ（ほかは `ENODEV`）、
    経路のダンプの表・プロトコル・種類・`RTA_OIF` は指した経路だけを見せます。どちらも
    `NLM_F_DUMP_FILTERED` が付きます。作られていない表は、そのファミリーだけのダンプでは
    `ENOENT` です。`lo` への `RTM_GETLINK` はフラグを取らず、名前、`IFLA_EXT_MASK`、
    `IFLA_TARGET_NETNSID` だけを取ります。経路の検索は、`rtnl_valid_getlink_req`、
    `inet_rtm_valid_getroute_req`、`inet6_rtm_valid_getroute_req` と同じく、アドレス
    全体の接頭辞長と経路を選ぶ属性だけを取ります。検査の有無にかかわらず、`lo` には
    マスターがないのでリンクのダンプの `IFLA_MASTER` はどのデバイスも見せません。`lo` には
    プレフィックス経路がないので、`RTM_F_PREFIX` はどの経路もダンプしません。
  - **ID で指したほかの名前空間:** `IFLA_TARGET_NETNSID` を付けたリンクのダンプと取得
    （検査の有無にかかわらず）と、`IFA_TARGET_NETNSID` を付けた厳密な検査のアドレスの
    ダンプは、その ID が指す名前空間（後述の名前空間の ID を参照）のリンクやアドレスを
    見せます。答えにはその ID を載せます。リンクでは、Linux 7.0 の `rtnl_fill_ifinfo` と
    同じく名前より前の先頭の `IFLA_TARGET_NETNSID`（`IFLA_IF_NETNSID`）です（Linux の
    master ブランチは名前の後に置きます）。アドレスでは、`inet_fill_ifaddr`、
    `inet6_fill_ifaddr` と同じくそれぞれの先頭の `IFA_TARGET_NETNSID` です。
    `AF_UNSPEC` のダンプの MCTP のアドレスは、ソケット自身の名前空間のままです。だれも
    持たない ID は `EINVAL`、ソケットを開いた側か送り手がその名前空間の持ち主で
    `CAP_NET_ADMIN` を持たなければ `EACCES` で（`rtnl_get_net_ns_capable`）、ダンプでは
    Linux の拡張 ACK のメッセージを付けます。IPv6 のアドレス 1 つ（`IFA_TARGET_NETNSID`
    を付けた `RTM_GETADDR`）は、その名前空間で探します。その答えは、`inet6_rtm_getaddr` が
    `rtnl_unicast` で送るのと同じく、その名前空間でリクエストした側のポートを持つ
    ソケットに届きます。そのようなソケットがなければ、リクエストは `ECONNREFUSED` です。
  - **属性のポリシー:** 各リクエストの属性は、まず Linux がそのリクエストに持つ
    ポリシー（`ifla_policy`、`ifa_ipv4_policy`、`ifa_ipv6_policy`、`rtm_ipv4_policy`、
    `rtm_ipv6_policy`、新しいリンクの `IFLA_LINKINFO` の中では `ifla_info_policy`）で、
    並びの順に調べます。その前に調べるのは、Linux がその前に調べるヘッダーだけです。
    型より短い整数、ポリシーより長い文字列やバイナリ、空の文字列、範囲外の整数は
    `ERANGE` です。断る属性（`IFLA_PERM_ADDRESS` など）は `EINVAL` です。ポリシーの
    `strict_start_type` 以降の型（`RTA_NH_ID`、`IFLA_DPLL_PIN`）の属性で、長さが違うもの、
    入れ子の印が合わないもの、ポリシーにないものも `EINVAL` です。厳密な検査では、
    型 0 や最後より後の型、余ったバイトは `EINVAL` です。検査しなければ読み飛ばし、
    属性がポリシーに反するリンクのダンプは、属性をどれも使いません。リンクの変更は
    `IFLA_NET_NS_PID`、`IFLA_NET_NS_FD`、`IFLA_TARGET_NETNSID` のうち一つまでを
    取ります（`EINVAL`）。リンクの取得は、はじめの二つのどちらも取りません（`EOPNOTSUPP`）。
  - **リンクの変更とほかの名前空間:** `RTM_SETLINK` と `RTM_NEWLINK` は、
    `rtnl_link_get_net_capable` と同じく、`lo` を探す前に、それらが指す名前空間を探します。
    どれも指さないプロセス、記述子、ID は `ESRCH`、`EBADF`、`EINVAL` で、その名前空間への
    `CAP_NET_ADMIN` が、開いた側と送り手のどちらかになければ `EPERM` です（アドレスを指して
    送るときは、前述のとおり送り手のものだけを見ます）。`lo` が見つかると
    （`NLM_F_CREATE` と `NLM_F_EXCL` の `RTM_NEWLINK` はその名前空間で探し、そこにも
    あるので `EEXIST`）、ほかの名前空間への移動は、ほかのどの属性よりも先に、`lo` の名前空間は
    変えられないので `EINVAL` です（`__dev_change_net_namespace`）。プロセス、記述子、ID で
    自分の名前空間を指すのは移動ではありません。`RTM_DELLINK` は、`rtnl_dellink` と同じく
    ID だけを取り（はじめの二つは `EOPNOTSUPP`）、`rtnl_get_net_ns_capable` と同じく
    その名前空間を探して（`EINVAL`、`EACCES`）、そこでインデックスか名前で `lo` を探します。
    `lo` は消せません（`rtnl_link_ops` がないので `EOPNOTSUPP`）。veth の端は消せます（下）。
    ほかのリンクは `ENODEV` で、
    どちらもなければ、`IFLA_GROUP` がグループ 0 なら `EPERM`、ほかなら `ENODEV`、
    何もなければ `EINVAL` です。
  - **veth の組:** 種類が `veth` の `RTM_NEWLINK`（`IFLA_LINKINFO`）は、`rtnl_newlink` と
    `veth_newlink` と同じく組を作ります。まず `VETH_INFO_PEER` の名前、アドレス、MTU、
    名前空間（`IFLA_NET_NS_PID` か `IFLA_NET_NS_FD`。なければ要求した名前空間）で相手を、
    次に要求のもので最初の端を作ります。名前がなければ `veth%d`、アドレスがなければ乱数の
    アドレスで、要求が指すインデックスを取ります（相手のインデックスは、最初の端のものを
    指したときだけです）。`VETH_INFO_PEER` がなければ、相手は要求の MTU と名前空間を取り、
    名前とアドレスは自分のものになります。
    調べる順は Linux と同じです。6 バイトでないアドレスか 68 から 65535 の外の MTU
    （`EINVAL`）、マルチキャストのアドレス（`EADDRNOTAVAIL`）、使われている名前か
    インデックス（`EEXIST`、`EBUSY`）、要求が指すリンクがすでにあるとき（`NLM_F_EXCL`
    なら `EEXIST`）です。どちらの端も Ethernet のデバイスで、それぞれの名前空間に
    `RTM_NEWLINK` で伝えます。両端が上がっている間はキャリアを持ち（`IFF_LOWER_UP`、
    それから `IFF_RUNNING` と動作状態の up）、それぞれがそれを伝えます（上がっていて
    キャリアのない端は、`default_operstate` と同じく、自分の名前空間で相手のインデックスの
    デバイスが up でなければ lower layer down です）。リンクの
    メッセージには種類、相手（`IFLA_LINK`）と、相手が別の名前空間にあればその名前空間の
    ID（`IFLA_LINK_NETNSID`。伝える名前空間がまず `RTM_NEWNSID` でその ID を与えます）が
    入ります。`RTM_SETLINK` か `RTM_NEWLINK` は、`SIOCSIFFLAGS` と同じく端を上げ下げし
    （`SIOCGIFFLAGS`、`SIOCGIFINDEX`、`SIOCGIFNAME` もあります）、
    `__dev_change_net_namespace` と同じく別の名前空間へ移します。上がっていればまず閉じ
    （`IFF_UP` と `IFF_RUNNING` が変わったと伝えます）、移る前の名前空間に `RTM_DELLINK`
    で伝えます。その名前空間は移る先に ID を与え、その ID と移った先のインデックス
    （`IFLA_NEW_NETNSID`、`IFLA_NEW_IFINDEX`）を付けます。それから移った先に
    `RTM_NEWLINK` で伝えます。インデックスは、移る先で使われていなければそのままです。
    どちらかの端の `RTM_DELLINK` は両端を消し、どちらかの名前空間がなくなるときも
    （その `RTM_DELNSID` の後で）両端が消えます。`unregister_netdevice_many_notify` と
    同じく、上がっている端をすべて閉じてから、それぞれが消えたことを伝えます。
    端は `lo` と同じく IPv4 のアドレスを持てます（`inet_rtm_newaddr`）。アドレスは端ごとに
    扱うので、別のデバイスのアドレスがあるサブネットのアドレスもセカンダリにはなりません。
    ラベルは端の名前です。アドレスはすぐにローカル経路を持ち、端が上がっている間は
    ブロードキャストの経路と、main テーブルのリンクスコープのユニキャストのプレフィックス
    経路も持ちます（`fib_add_ifaddr`）。どれも端を通ります（`RTA_OIF`）。端が上がると、
    リンクのメッセージの後でアドレスごとにそれらの経路ができます。下がると、ローカル経路の
    ほかは何も伝えずに消えます。上がっていてキャリアがない間は `RTNH_F_LINKDOWN` です
    （`fib_check_nh_nongw`、`NETDEV_CHANGE`）。ゲスト自身が足す、ゲートウェイのない端を
    通る経路も取ります（端が下がっていれば `ENETDOWN`、ないデバイスは `ENODEV`）。端を
    通る出力の経路の検索は、端の最初のプライマリアドレスから、なければほかのデバイスの
    作られた順で最初のものから出て（`inet_select_addr`）、その端を `RTA_OIF` に、
    `RTCF_LOCAL` なしで答えます。`lo` から端へ転送する検索もその端を答え、送り元を
    `__fib_validate_source` と同じく調べます（厳しい逆経路フィルタは、経路が別のデバイスを
    通る送り元を捨てます）。端が消えるか別の名前空間へ移るときは、`inetdev_destroy` と
    同じく、`RTM_DELLINK` の前に、アドレスとそのローカル経路が消えたことを一つずつ
    伝えます。アドレスと経路のダンプは端のインデックス（`ifaddrmsg` のもの、`RTA_OIF`）を
    取ります。
  - **組を通る TCP と UDP:** 経路が端を通る接続とデータグラムは、その経路が出るアドレスから
    出て、端がキャリアを持ち、宛先が相手の名前空間のアドレスで（そのローカル経路が
    持つもの。`arp_process` はどれにも答えます）、相手の端が送り元を受け入れるとき
    （`fib_validate_source`。逆経路フィルタも使います）に、相手の名前空間に着きます。
    そこではループバックと同じく、そのアドレスとポートで待ち受けるソケットへの接続、または
    そのソケットへのデータグラムです。待ち受けのないポートはリセットで答え
    （`ECONNREFUSED`）、ソケットのない UDP のポートは ICMP の port unreachable で答え、
    接続したソケットはそれを知ります。答えが戻るのは、相手の名前空間が送り元への経路を
    その端から出し、こちらの端がそれを受け入れるときだけです。ARP に誰も答えない宛先への
    接続は、ARP があきらめる 3 秒後（1 秒おきの 3 回の問い合わせ、`mcast_probes`）に、
    ループバックを通る ICMP の host unreachable が伝える `EHOSTUNREACH` で失敗し
    （ループバックが下がっていると、また答えがどこにも戻らないと、ハンドシェイクの再送が
    尽きた後の `ETIMEDOUT`）、データグラムは捨てられます。`arp_process` が問い合わせを
    受けないループバックのアドレスへのものも同じです。ループバックのアドレスから端を
    通る接続とデータグラムは `EINVAL` です（`__mkroute_output`）。範囲の合うアドレスが
    ないとき（`inet_select_addr`）は 0.0.0.0 から出ます。ARP もそこから問い合わせて相手は
    答えますが、相手は届いたものを martian として捨てるので、接続は時間切れ
    （`ETIMEDOUT`）になり、データグラムは失われます。TCP はブロードキャストとマルチ
    キャストの経路を取らず（`ENETUNREACH`）、UDP は、`SO_BROADCAST` がなければ、
    ブロードキャストの経路が持つアドレスや限定ブロードキャストのアドレスへの経路を
    取りません（`EACCES`）。端のアドレスにバインドしたソケット
    からのグループや限定ブロードキャストのアドレスへのものは、経路がなくてもその端から
    出ます（`ip_route_output_key_hash_rcu`）。
  - **veth の端の netconf:** それぞれの端の設定は、その名前空間に伝えます（`RTNLGRP_IPV4_NETCONF`、
    `RTNLGRP_IPV6_NETCONF`。`inetdev_init`、`ipv6_add_dev` とその後始末が伝えるのと
    同じです）。増えるときは IPv4 の、それから IPv6 の設定のすべての `RTM_NEWNETCONF` を
    その `RTM_NEWLINK` の前に、消えるときはそれぞれの `RTM_DELNETCONF` をその
    `RTM_DELLINK` の前に伝えます。MTU が 1280 より小さい端には IPv6 がないので、
    IPv4 のものだけです。移すときは、離れる名前空間の `RTM_NEWNSID` と `RTM_DELLINK` の
    前に設定が消えたことを伝え、端は移った先の名前空間の `default` の設定を取り、それを
    そこでの `RTM_NEWLINK` の前に伝えます。
  - **名前空間の ID:** Linux の `net_namespace.c` と同じく、`RTM_NEWNSID` は、
    プロセス（`NETNSA_PID`、なければ `ESRCH`）か `/proc/<pid>/ns/net` の記述子
    （`NETNSA_FD`、`EBADF`、ほかのファイルなら `EINVAL`）のネットワーク名前空間に
    ID `NETNSA_NSID` を、負の値なら空いている一番小さい ID を与えます。どちらもなければ
    `EINVAL`、すでに ID がある名前空間や使われている ID は `EEXIST` で、それぞれ Linux の
    拡張 ACK のメッセージを付けます。相手が別の名前空間にある veth の端を伝えるときも、
    `peernet2id_alloc` と同じく、その名前空間に空いている一番小さい ID を与えます。そこへ
    veth の端を移すときも同じです（上の veth の組）。`RTNLGRP_NSID` のメンバーは新しい ID を知らされます
    （`NLM_F_ECHO` なら、そのうちリクエストした側だけが受け取ります）。名前空間が
    なくなって ID が消えるときも、`unhash_nsid` と同じく `RTM_DELNSID` で知らされます。
    なくなるのは、それを持つプロセス、記述子、ソケットがなくなったときで、その ID は
    また空きます。リクエストが指すプロセスや記述子は、`send` でも `write` でも送り手から
    見たもので、`CAP_NET_ADMIN` は開いた側だけでなく書いた側にも要ります。`RTM_GETNSID` は、
    プロセス、記述子、ID で指した名前空間の ID（なければ -1、だれも持たない ID は
    `ENOENT`）を返し、`NETNSA_TARGET_NSID` を付けるとその名前空間が与えた ID を、
    こちらの ID を `NETNSA_CURRENT_NSID` に添えて返します（その名前空間がなければ
    `EINVAL`、それへの `CAP_NET_ADMIN` がなければ `EACCES`）。そのダンプは ID を順に
    並べ、厳密な検査では `rtnl_net_dumpid` と同じく `NETNSA_TARGET_NSID` でほかの
    名前空間を指せ、それ以外は取りません。`NETLINK_LISTEN_ALL_NSID` を付けたソケットは、
    自分の名前空間が ID を与えた名前空間の通知も、開いた側がその名前空間への
    `CAP_NET_BROADCAST` を持てば受け取ります。`recvmsg` はその ID を、
    `do_one_broadcast` と `netlink_cmsg_listen_all_nsid` と同じく `NETLINK_PKTINFO`
    の後の `SOL_NETLINK` の `NETLINK_LISTEN_ALL_NSID` 制御メッセージで返します。
  - **リンク:** `RTM_GETLINK` には、ダンプでも、インデックスか `IFLA_IFNAME` で指しても、
    `lo`（インデックス 1）を返します（ほかは `ENODEV`）。属性は Linux 7.0 と同じものを
    同じ順に載せます。フラグ、名前、キュー、状態、MTU、キューの数、セグメントの大きさ、キャリア、
    キューイング規律、0 の統計（`IFLA_EXT_MASK` に `RTEXT_FILTER_SKIP_STATS` があれば
    載せません）、XDP、マップ、MCTP と IPv4 と IPv6 の設定（MCTP を組み込んだカーネルと同じ `IFLA_AF_SPEC`）です。そのため
    `ip -d link` は Linux と同じ詳細を出します。`AF_INET6` のダンプには、`inet6_dump_ifinfo`
    と同じく、`AF_INET6` の `ifinfomsg` に名前、ハードウェアアドレス、MTU、状態と、
    `IFLA_PROTINFO` に入れた IPv6 の設定（統計付き）を載せた `lo` を返します。
    `RTNL_FAMILY_IPMR` のダンプには、`ipmr_rtm_dumplink` と同じく、IPv4 のマルチキャストの
    経路表（名前空間にある唯一の表 `RT_TABLE_DEFAULT`）を `IFLA_AF_SPEC` に入れて返します。
    レジスター VIF、assert、PIM、パケット全体の設定はなく、解決を待つものも VIF もありません。
    検査するときは、`ipmr_valid_dumplink` と同じく、空の `ifinfomsg` だけを取ります。
    `RTNL_FAMILY_IP6MR` のダンプには専用の処理がないので、ふつうのリンクのダンプになります。
    `RTM_NEWLINK` と `RTM_SETLINK` は `IFF_UP` で上げ下げします。正でないインデックスはリンクを
    指さないので、`rtnl_getlink` と `rtnl_setlink` と同じく名前で探します（名前もなければ
    `EINVAL`）。`RTM_NEWLINK` は負のインデックスを取りません（`EINVAL`）。
  - **アドレス:** `RTM_GETADDR` は `lo` のアドレスを Linux の順でダンプします。IPv4 の
    プライマリは、同じかより広いスコープのプライマリの後に並び、セカンダリ（プライマリの
    サブネットの中のアドレス。`IFA_F_SECONDARY` が付きます）は最後です。IPv6 はグローバルな
    ものが先で、新しいものが先です。`lo` が上がるたびに `127.0.0.1/8`（消されていれば）と
    `::1/128` が付き、落とすと IPv6 のアドレスはすべて消えます（`keep_addr_on_down` は 0）。
    `RTM_NEWADDR` は、`inet_rtm_newaddr` と `inet6_rtm_newaddr` と同じくアドレスを足します。
    `lo` がすでに持つものは、`NLM_F_EXCL` なしの `NLM_F_REPLACE` でなければ `EEXIST` です。
    `IFA_LOCAL` のない IPv4 のもの、32 を超える接頭辞、`IFA_LOCAL` も `IFA_ADDRESS` も
    ない IPv6 のもの、有効な寿命がないか、それより長い推奨の寿命、`ifaddrmsg` より短い
    メッセージは `EINVAL`、ほかのインターフェースは `ENODEV` です。そのあと、新しい IPv6 の
    ものでは、128 を超える接頭辞と、64 でない接頭辞の `IFA_F_MANAGETEMPADDR` が
    `EINVAL`、`::` と、`IFA_F_MCAUTOJOIN` のないマルチキャストアドレスが `EADDRNOTAVAIL`
    です。スコープの違うアドレスのサブネットに入る IPv4 のものは `EINVAL` です。
    `0.0.0.0` の `IFA_LOCAL` は受け取るだけで何もしません。`IFA_LABEL`、
    `IFA_BROADCAST`、`IFA_FLAGS`（`IFA_F_NOPREFIXROUTE` と、IPv6 ではアドレスを 1 度だけ
    伝える `IFA_F_NODAD` も。IPv6 は要求が付けられるフラグだけを保ちます）、`IFA_PROTO`、
    アドレスの接頭辞の経路のメトリックになる `IFA_RT_PRIORITY`、`IFA_CACHEINFO` の寿命を
    保ちます。有効な寿命のあるアドレスは `IFA_F_PERMANENT` でなく、推奨の寿命が 0 のものは
    `IFA_F_DEPRECATED` で、`IFA_CACHEINFO` はそれぞれの残りと、アドレスが作られた時刻と
    寿命を決めた時刻を伝えます。Linux の確認（`check_lifetime`、`addrconf_verify_rtnl`）と
    同じく、推奨の寿命が尽きたアドレスは非推奨になり、有効な寿命が尽きると経路とともに
    消えます。要求がなくても時間どおりです。bind や送信をするソケットは消えたことに気づき、
    アドレスと経路のグループのメンバーが `poll`、`epoll`、読み込みで待っていれば、そのとき
    に伝わります。IPv6 の接頭辞の経路は、Linux と同じく
    ひとりでには尽きません。Linux ではループバックを通る経路は作るときに `RTF_EXPIRES` を
    失います（`fib6_is_reject`）。変更が永続のアドレスに寿命を与えたとき
    （`modify_prefix_route`）か、接頭辞のアドレスの 1 つが消えて残りに寿命があるときに、
    経路も寿命（`rta_expires`）を持ち、それが尽きると消えます。`NLM_F_REPLACE` は `lo` が
    持つアドレスを変えて、
    それを伝えます。IPv4 のものは要求の優先度（なければ 0）、プロトコル、寿命を取り、IPv6 の
    ものは `inet6_addr_modify` と同じく、フラグ、プロトコル、寿命と、要求が指していれば
    優先度を取ります。接頭辞の経路もそれに従います。`RTM_DELADDR` は、指した
    `IFA_LOCAL`、`IFA_LABEL`、`IFA_ADDRESS` と接頭辞を持つ最初のものを消し（なければ
    `EADDRNOTAVAIL`）、プライマリならそのセカンダリも消します。`127.0.0.1` と `::1` も
    消せます。ダンプでない `RTM_GETADDR` は、`inet6_rtm_getaddr` と同じく IPv6 のアドレスを
    1 つ返します。`IFA_LOCAL` が指すもの、なければ `IFA_ADDRESS` が指すもので、インデックスは
    問いません。どちらもなければ `EINVAL`、`lo` が持たないものなら `EADDRNOTAVAIL` です。
    厳密に確かめるソケットでは、ほかに何も指せません（`EINVAL`）。IPv4 と MCTP には 1 つだけ
    返す処理がないので、Linux と同じく `EOPNOTSUPP` です。
  - **MCTP のアドレス:** `CONFIG_MCTP` を組み込んだカーネルのループバックと同じく、`lo` は
    MCTP のエンドポイント ID を持てます。`AF_MCTP` の `RTM_NEWADDR` と `RTM_DELADDR` は、
    `mctp_rtm_newaddr` と `mctp_rtm_deladdr` と同じく ID を足し、消します。リクエストは
    ソケットにかかわらず厳しく解釈します。`ifaddrmsg` 全体と、1 バイトの `IFA_LOCAL`
    （なければ `IFA_ADDRESS`）が要り、ほかの属性は取りません（`EINVAL`）。インデックスは
    `lo` のものです（ほかは `ENODEV`）。足せる ID は 8 から 254 で（ほかは `EINVAL`）、
    同じものは一度だけです（`EEXIST`）。`lo` にないものを消そうとすると `ENOENT` です。
    変更は、`mctp_addr_notify` と同じく、リクエストのシーケンス番号とポートを付けて
    `RTNLGRP_MCTP_IFADDR`（34）に伝えます。`AF_MCTP` のアドレスのダンプは、
    `mctp_dump_addrinfo` と同じく MCTP 自身が扱い、ID を足した順に、それぞれ `IFA_LOCAL` と
    `IFA_ADDRESS` で返します。検査するときに要るのは `ifaddrmsg` 全体だけで（足りなければ
    `EINVAL`）、インデックスは `NLM_F_DUMP_FILTERED` を付けずに絞り込みます。ID ごとに
    ローカルの経路が付き（`mctp_route_add_local`）、ID を消すと消えます。ただし、
    ネットワーク 1 にその ID だけの経路がすでにあれば付きません。すべてのファミリーの
    アドレスと経路のダンプ（`rtnl_dump_all`）は、最後に MCTP のものを返します。
  - **MCTP の経路:** `AF_MCTP` の `RTM_NEWROUTE` は、`mctp_newroute` と同じく
    ゲートウェイを通る経路を足します。範囲は `RTA_DST` とその後の `rtm_dst_len` 個の ID で、
    `RTA_GATEWAY` の `mctp_fq_addr` を通ります（ネットワーク 0 は既定の 1 です）。
    `RTA_METRICS` に MTU があれば持ちます。リクエストは `rta_mctp_policy` で厳しく
    解釈します（`EINVAL`、8 バイトでないゲートウェイと 1 から 3 バイトのメトリクスは
    `ERANGE`）。`RTA_DST`、ユニキャストの
    ゲートウェイ ID、`RTN_UNICAST` の型が要ります（`EINVAL`）。`lo` を通る経路
    （`EINVAL`、"no routes to loopback"）、ほかのインターフェースを通る経路（`ENODEV`）、
    8 より小さい ID か 254 を超える範囲（`EINVAL`）、そのネットワークにすでにある範囲
    （`EEXIST`）は取りません。`RTM_DELROUTE` は、`mctp_delroute` と同じく、ネットワークと
    範囲の合う `RTN_UNICAST` の経路を消します（なければ `ENOENT`）。ネットワークは
    ゲートウェイのもの、または `lo` のインデックスのものです。どちらも、Linux と同じく
    通知を送りません。`AF_MCTP` の経路のダンプは、`mctp_dump_rtinfo` と同じく絞り込みを
    取らずに、ローカルの経路とゲートウェイの経路を新しいものから返します。
  - **経路:** ファミリーごとに、Linux の `fib_trie` と `ip6_fib` と同じく経路の表を
    持ちます。IPv4 のローカルの表とメインの表は、ポリシーのルールがない間の Linux と同じく
    1 つのトライを分け合います。アドレスの経路は、`fib_add_ifaddr` と `addrconf` が付ける
    カーネルのものです。IPv4 のアドレスには、初めからローカルの表に `local` の経路があり、
    `lo` が上がると、接頭辞の経路（ループバックでは `local` で、落ちても残り、優先度は
    アドレスのものです）、サブネットの `broadcast` の経路、`IFA_BROADCAST` のものが付きます。
    IPv6 のアドレスには、ローカルの表に `local` の経路が、そのアドレスを持って `lo` が初めて
    上がってからは（落ちている間に足したものは永続のときだけ）、メインの表に、アドレスの
    優先度か、なければメトリック 256 のユニキャストの接頭辞の経路があります（`::1` には
    ありません）。`RTM_NEWROUTE` は、`inet_rtm_newroute` と `inet6_rtm_newroute` と同じく、
    `lo`（IPv4 のゲートウェイのない経路なら veth の端も）を通る経路か、デバイスのない種類（`blackhole`、`unreachable`、`prohibit`、
    `throw`）の経路を、どの表にも足します。メトリック、プロトコル、スコープ、TOS、
    優先する送り元、IPv4 のゲートウェイ（オンリンクも）を持てます。`NLM_F_EXCL`、
    `NLM_F_REPLACE`、`NLM_F_APPEND`、`NLM_F_CREATE` に従って Linux と同じ場所に置くか、
    Linux と同じエラーで断ります（`EEXIST`、`ENOENT`。接頭辞、スコープ、種類、
    ゲートウェイ、優先する送り元がおかしいときと、`RTA_FLOWLABEL`、`RTA_VIA`、
    `RTM_F_CLONED` を持つ IPv6 の経路は `EINVAL`、ほかのデバイス（IPv4 ではないデバイス）は
    `ENODEV`、そのデバイスが落ちている間はホストのスコープの IPv4 の経路のほかは `ENETDOWN`）。
    `RTM_DELROUTE` は、指したものに合う最初の経路を消します（なければ `ESRCH`）。
    カーネルの経路も消せ、アドレスの変化や `lo` が上がったときに戻ります。`lo` を落とすと、
    ホストのスコープのほかの、`lo` を通る IPv4 の経路と、IPv6 の経路がすべて消えます。
    IPv4 のアドレスを消すと、そこを送り元とするメインの表の経路が消え、デバイスの最後の
    アドレスを消すとそのデバイスを通る経路がすべて消えます。IPv6 のアドレスを消すと、`cleanup_prefix_route`
    と同じく、その接頭辞へのメインの表の最初の経路が、誰のものでも消えます。
    `NLM_F_DUMP` を付けた `RTM_GETROUTE` には、Linux の表のハッシュの順に表ごとに、IPv4 の
    ものはトライの順で、IPv6 のものは木をたどる順で経路を返します。`AF_INET` か `AF_INET6`
    だけを指せばそのファミリーのものを、マルチキャストの経路のファミリーには何も返しません。
    ダンプでなければ、`inet_rtm_getroute` と `inet6_rtm_getroute` と同じく、`RTA_DST` の
    指す宛先への経路を引きます。IPv4 はローカルとメインの表の最も長い接頭辞で引き、
    そこに経路がないか `throw` の経路に当たれば既定の表で引きます。IPv6 は、`lo` が
    上がっている間、ローカルの表、メインの表の順に引きます。拒む経路に当たれば、その
    エラー（`EINVAL`、`EHOSTUNREACH`、`EACCES`）を返します。IPv4 の答えは、メインの表
    （`RTM_F_LOOKUP_TABLE` を付ければ、経路のあった表）、`fib_select_path` の選ぶ送り元、
    オンリンクで届くゲートウェイ、リクエストが指した `RTA_MARK`（0 なら付けません）、呼び出し元の `RTA_UID`（リクエストが指せばそのまま。
    -1 なら付けず、4 バイトより短ければ `ERANGE`）を持ちます。`0.0.0.0` は 127.0.0.1 から
    ループバックへ向かいます。IPv6 の答えは、`ipv6_dev_get_saddr` の選ぶ送り元を
    持ちます。経路がなければ `ENETUNREACH`、`AF_UNSPEC` は `EOPNOTSUPP` です。
    ファミリーのアドレスより短い宛先は、IPv4 なら `ERANGE`、IPv6 なら `EINVAL` です。
    `RTM_F_FIB_MATCH` を付ければ、合った表の項目を返します（`0.0.0.0` に合う項目はないので
    `EHOSTUNREACH` です）。
  - **経路の引き当ての条件:** `ip route get ... from ... oif ... tos ... ipproto ...` が送るように
    リクエストが宛先のほかに指すものも、`ip_route_output_key_hash_rcu` と `ip6_route_output`
    と同じく使います。IPv4 の送り元（`RTA_SRC`）はループバックのものでなければならず
    （`ENETUNREACH`。マルチキャストとブロードキャストのものは `EINVAL`）、答えは選ぶはずの
    `RTA_PREFSRC` の代わりに、それを `RTA_SRC` として返します。出力デバイス（`RTA_OIF`）は
    `lo` のほかは `ENODEV`、`lo` が落ちている間は `ENETUNREACH` です。表が経路を与えないか
    エラーを返せば、IPv4 の宛先はそのデバイスのリンク上にあるとみなします（どの表のもので
    もないので、`RTM_F_FIB_MATCH` では `EHOSTUNREACH` です）。`0.0.0.0` は、選んだホストの
    スコープのアドレスから向かいます。IPv4 の表は、経路の TOS をリクエストの従来の TOS の
    ビットと比べ、答えは合った経路の TOS を返します。マルチキャストアドレスと制限
    ブロードキャストアドレスの IPv4 の答えは、`__mkroute_output` が作るのと同じく、
    マルチキャストかブロードキャストの種類です（`RTCF_MULTICAST` か `RTCF_BROADCAST` で、
    ブロードキャストアドレスと、`lo` が入っているグループ（上がっている間の 224.0.0.1）には
    `RTCF_LOCAL` も付きます）。`RTM_F_FIB_MATCH` で返す表の項目も、その種類になります。
    出力デバイスなしでループバックの送り元を指したとき、および `lo` を通してローカルの
    グループ（224.0.0.0/24）かブロードキャストアドレスへ向かうときは、表を引かずに作ります
    （TOS は 0、表はなく、`RTM_F_FIB_MATCH` では `EHOSTUNREACH` です）。送り元を指さなければ、
    リンクのスコープのアドレスから向かいます。IPv6 の答えはリクエストの送り元を `RTA_SRC`
    として返します。`lo` のほかの出力デバイスを指すと、送り元がないか、宛先が
    ループバック、リンクローカル、マルチキャストのアドレスなら、経路は見つかりません
    （`ENETUNREACH`）。`RTA_IP_PROTO` は
    TCP、UDP、そのファミリーの ICMP のほかは `EOPNOTSUPP`、`RTA_IIF` はないデバイスなら
    `ENODEV` です。`RTA_IIF` が `lo` なら、また IPv4 では veth の端でも、そのデバイスに
    入ってきたパケットと同じく経路を引き（`ip_route_input_slow`、
    `ip6_route_input_lookup`）、答えには `RTA_IIF` にそのデバイスを入れます。IPv4 は martian を捨てます（`EINVAL`）。マルチキャスト、限定ブロード
    キャスト、ループバック、0.0.0.0 の送り元、ループバックか 0.0.0.0 の宛先、デバイスが
    入っていないグループ（224.0.0.1 には上がっている間入っています）、名前空間自身のアドレスの送り元です。要求がローカルの経路を
    足したあとは、引き当てでユニキャストでない経路が見つかる送り元も捨てます
    （`fib_validate_source`）。ローカル、ブロードキャスト、マルチキャストの宛先には、
    その型のローカルの経路（`RTCF_LOCAL`、`RTCF_BROADCAST`、`RTCF_MULTICAST`）を、
    一致した経路の TOS で、優先する送り元なしで返し、`lo` から出ます（`RTA_OIF`）。ほかは
    転送されるはずのものです。デバイスの `forwarding`（`/proc/sys/net`）が切れていれば `EHOSTUNREACH` です。入っていれば、
    経路のない宛先は引き当てのエラー、ユニキャストでない種類の経路は `EINVAL` で、
    ユニキャストのものは、`__mkroute_input` と同じく、転送する経路を返します。ユニキャストで、
    経路のデバイスから出て（`RTA_OIF`）、経路のゲートウェイとメトリクスを持ちます。入って
    きたデバイスから出るとき、送り元自身の経路がそのデバイスを通るゲートウェイなしの
    ユニキャストなら、入ってきたところから出るパケットとしてリダイレクトを求める
    `RTCF_DOREDIRECT` が付きます。逆経路のフィルター（`rp_filter`、`all` とデバイスの
    大きいほう）は、どの送り元も、それを引き当てて確かめます
    （`__fib_validate_source`）。入っていれば、経路のない送り元も捨てます。厳密（1）な
    フィルターは、入ってきたデバイスにアドレスがあれば、経路がほかのデバイスを通る送り元も
    捨てます。緩い（2）フィルターでは、そのデバイスを通る引き当てで決めます。IPv6 は、送り元と
    `forwarding` によらず、表が返す経路を返します。マーク、ユーザー ID、プロトコル、ポートはポリシーのルールとマルチパスの
    経路を選ぶためのもので、どちらもないので何も変えません。
  - **経路のメトリクス:** IPv4 と IPv6 の経路は、`RTA_METRICS` が持つメトリクス
    （`ip route add ... mtu 1400` が送るもの）を、`ip_metrics_convert` と同じく読んで
    保ちます。種類を順に読み、0 の種類は飛ばします。`RTAX_MTU` は 65520 に、`RTAX_ADVMSS`
    は 65495 に、`RTAX_HOPLIMIT` は 255 に抑えます。`RTAX_MAX` を超える種類、4 バイトでない
    値、`cubic` と `reno` のほかの輻輳制御（`RTAX_CC_ALGO`）、`RTAX_FEATURE_MASK` を超える
    機能、ロックした 0 の輻輳ウィンドウは `EINVAL` です。`fib_find_info` と同じく、
    メトリクスだけが違う IPv4 の経路は別の経路になります。ダンプ、通知、引き当ての答えは、
    `rtnetlink_put_metrics` と同じく、0 のもののほかの経路のメトリクスを持ちます
    （制限ブロードキャストアドレスと、4 より短い接頭辞の経路を通るマルチキャストアドレスの
    引き当ては、経路のゲートウェイとともにメトリクスを落とすので持ちません）。
    メトリクスを指した IPv4 の削除は、`fib_metrics_match` と同じく、それを持つ経路だけを
    消します。抑える前の値で比べるので、MTU の 70000 は保った 65520 と合いません。IPv6 の
    削除はメトリクスを見ません。
  - **ソケット:** ローカルな経路が持つアドレスはゲスト自身のものです。TCP や UDP の
    ソケットはそこへ bind でき、その経路の優先する送り元からループバックの上で届きます。
    ループバックでは、IPv4 のアドレスはそのサブネット全体を、IPv4 のローカルな経路
    （`ip route add local` が足すもの）はその接頭辞のアドレスすべてをローカルにします。
    IPv6 は自分のアドレスにだけ bind できます。IPv4 にまだローカルの表がなければ、Linux の
    `inet_addr_type` がそのときどのアドレスもブロードキャストと見るのと同じく、ソケットは
    どの IPv4 のアドレスにも bind できます。
  - **近隣:** `RTM_GETNEIGH` のダンプは、`neigh_dump_info` と同じくループバックと veth の
    端の近隣（下の通知の項と veth の端の近隣の項のとおり通信が作るものと、リクエストが
    足したもの）を返します。それぞれは、消えるときに伝える
    `RTM_DELNEIGH` と同じ形の `RTM_NEWNEIGH` です。`AF_UNSPEC` では ARP（IPv4）の
    ものに続けて近隣探索（IPv6）のものを、`AF_INET` と `AF_INET6` ではそのファミリーの
    ものを返し、ほかのファミリーでは何も返しません。フラグが `NTF_PROXY` の `ndmsg` は
    代わりに代理のエントリを求め、ハッシュ（`pneigh_hash`）のバケットの順に、それぞれの
    中では新しいものから返します。`NDA_IFINDEX` と `NDA_MASTER` は
    ダンプを絞り、どのメッセージにも `NLM_F_DUMP_FILTERED` を付けます。デバイスの番号は
    そのデバイスの近隣だけを、マスターの -1（マスターなし）はすべてを残し（代理のエントリは、
    番号で絞ると `lo` の番号で `lo` のものだけを残します）、ほかのマスターでは何も返しません。
    厳しく調べるときは、`neigh_valid_dump_req` と同じく、短い `ndmsg`、詰め物・番号・
    状態・型・`NTF_PROXY` 以外のフラグを持つ `ndmsg`、ほかの属性は `EINVAL` です。
    調べないときは、属性が `nda_policy` に合わないダンプは絞りません。`AF_MCTP` の
    ダンプは近隣を返しません（`mctp_rtm_getneigh` と同じく、短い `ndmsg` は `EINVAL`）。
    ダンプでないリクエストは、`neigh_get` と同じく、ファミリーとキー（`NDA_DST`）と
    デバイスの番号で 1 つの近隣を指し、答えは引き当てが持つ参照も数えます。キーがない
    （`NLMSGERR_ATTR_MISS_TYPE` で伝えます）、ほかの属性がある、キーの長さが違う、
    デバイスがない、詰め物・状態・型・`NTF_PROXY` 以外のフラグがあるものは `EINVAL`、
    IPv4 と IPv6 以外のファミリーは `EAFNOSUPPORT`、名前空間にないデバイスは `ENODEV`、
    veth の端の IPv6 の近隣と代理のエントリは `EOPNOTSUPP`、デバイスにない近隣と、
    指したデバイスのものもデバイスのないものもない代理のエントリは `ENOENT` です。
  - **近隣の変更:** `RTM_NEWNEIGH` は `lo` か veth の端（下）の近隣を足すか変え、
    `RTM_DELNEIGH` は消します。`neigh_add` と `neigh_delete` と同じで、`CAP_NET_ADMIN` が要ります。調べる
    のは Linux の順です。追加では厳しくない `nda_policy`、それと短い `ndmsg`、
    `NDA_DST` がないもの（`EINVAL`）、名前空間にないデバイス（`ENODEV`）、追加では
    デバイスの 6 バイトより短いリンク層のアドレス（`EINVAL`）、IPv4 と IPv6 以外の
    ファミリー（`EAFNOSUPPORT`）、ファミリーのものより短いキー（`EINVAL`）、veth の端
    では IPv6 の近隣と代理のエントリ（`EOPNOTSUPP`）です。ループバックの
    IPv4 の近隣は、`arp_constructor` と同じく、何を求めても `0.0.0.0` をキーにします。
    ほかのキーのリクエストは、`NLM_F_CREATE` があればそれを作るか変え（なければ
    `ENOENT`）、そのキーで消すと `ENOENT` です。あるものに `NLM_F_EXCL` を付けると
    `EEXIST` で、`NLM_F_REPLACE` がなければリンク層のアドレスと `NTF_ROUTER` は変わり
    ません。近隣は `lo` のアドレスを持つ `NUD_NOARP` として作り、`__neigh_update` と同じく
    変えます。`NTF_EXT_LEARNED`、`NTF_EXT_MANAGED`、`NTF_EXT_VALIDATED` はリクエストの
    とおりになり、有効でない状態はそのまま受け取ってアドレスを落とし、有効な状態は
    渡したアドレスを取るか、持っているものが要ります（`EINVAL`）。変わるたびに、
    求めたソケットのポートを付けて `RTNLGRP_NEIGH` に伝えます。`NTF_USE` と
    `NTF_MANAGED` は `NUD_PERMANENT` だけを外し、それから近隣を使います
    （`neigh_event_send`）。到達可能な近隣のタイマーは `neigh_timer_handler` と同じく
    動きます。確認から到達可能時間（30 秒）が過ぎると、その前の 5 秒のうちに使われて
    いれば遅延中になり、そうでなければ古くなって、ポートを付けずに `RTNLGRP_NEIGH` に
    伝えます。`NTF_EXT_MANAGED` の永続の近隣と、有効でない状態の
    `NTF_EXT_VALIDATED` は `EINVAL` です。削除は近隣をまず失敗させ（`NUD_FAILED`。
    有効だったなら伝えます）、それから `RTM_DELNEIGH` で消えたと伝えます。`NTF_PROXY`
    のリクエストは、代わりに `lo` かデバイスのない代理のエントリを足し、変え、消します
    （IPv6 のものには `lo` が要り、なければ `ENOBUFS`）。渡したフラグとプロトコルを持ち、
    何も伝えません。それに `NTF_EXT_MANAGED` か `NTF_EXT_VALIDATED` を付けると
    `EINVAL` です。変えるときは `lo` のものかデバイスのないものを探し、消すときは自分の
    デバイスのものだけを探します（`ENOENT`）。`NTF_PROXY` のないリクエストは、デバイスが
    なければ `EINVAL` です。`lo` を落とすと、`neigh_ifdown` と同じくその近隣と代理の
    エントリが消えますが、デバイスのないものは残ります。
  - **veth の端の近隣:** veth の端は IPv4 の近隣を持ち、`arp_constructor`、
    `neigh_event_send`、`arp_process`、`neigh_timer_handler` と同じく ARP で解決します。
    それぞれは求めたアドレスをキーにし、作るときに `inet_addr_type` がそのアドレスに
    与える型を持ちます（名前空間にローカルの表がないうちは `RTN_BROADCAST`）。グループの
    ものはグループの Ethernet のアドレス（`ip_eth_mc_map`）を、ブロードキャストの
    アドレスのものはブロードキャストのアドレスを持つ `NUD_NOARP`、ほかは `NUD_NONE` で、
    失敗したリクエストもそのまま残します。端を通るパケット（TCP のハンドシェイク、UDP、
    返る ICMP の port unreachable）は、次のホップの近隣を使います。有効なものはその
    アドレスへ送り、相手は自分のアドレスへのものだけを受け取ります。古いものは遅延中に
    なります。ほかのものは ARP で問い合わせ、ユニキャストの問い合わせの数（3）と最初の
    問い合わせを数えます。相手が答えればすぐに相手のアドレスで到達可能になり、相手は
    送り手を、そのアドレスの古いものとして覚えます（`neigh_event_ns`）。答えがなければ
    未完了になり、6 回の問い合わせを送った 3 秒後に失敗します。遅延中のものは 5 秒後に
    問い合わせ（`NUD_PROBE`）、相手が答えれば到達可能になり、3 回の問い合わせの後に
    失敗します。未完了と遅延中になるとき以外の変化はそれぞれ `RTNLGRP_NEIGH` に伝え、
    タイマーによるものは名前空間の netlink ソケットが次に読み、poll し、書くときに
    伝えます。`NTF_USE` や `NTF_MANAGED` のリクエストは、パケットと同じく、端で
    `inet_select_addr` が選ぶアドレスから ARP で問い合わせます（`arp_solicit`）。
    端を下げると、その `RTM_NEWLINK` の後に、端の近隣がそれぞれ
    `RTM_DELNEIGH` を伝えて消えます。相手がキャリアを失うと永続のもの以外が
    （`neigh_carrier_down`）、端がなくなるか別の名前空間に移るとすべてが消えます。
  - **近隣の表:** `RTM_GETNEIGHTBL` のダンプは、`neightbl_dump_info` と同じく、
    ファミリーが指す表（`AF_UNSPEC` では ARP と近隣探索の表、ほかのファミリーでは
    なし）を、名前、ガベージコレクションの間隔としきい値、構成、統計、既定の
    パラメーターとともに返し、続けてデバイスごとのパラメーターを新しいものから返します。
    ARP では veth の端と `lo` のもの（`inetdev_init`）、近隣探索では `lo` のものです。
    それぞれ、その近隣が持つ参照を数えます。厳しく調べるときは、短い `ndtmsg`、詰め物のある
    もの、後ろに属性のあるものは `EINVAL` です（`neightbl_valid_dump_info`）。
  - **通知:** ソケットは、`bind` が指すグループ（最初の 32 を置き換えます）と
    `NETLINK_ADD_MEMBERSHIP` が足すグループのメンバーになります。グループは `RTNLGRP_*` の
    1 から 39 で（0 とそれを超えるものは `EINVAL`、マルチキャストの経路の 30 と 31 には
    呼び出し元の `CAP_NET_ADMIN` が要り、なければ `EPERM`）、`NETLINK_DROP_MEMBERSHIP` で抜け、
    `NETLINK_LIST_MEMBERSHIPS` は 2 ワードで全部を返します。`lo` の変化は、名前空間の中の
    そのグループのメンバーに、1 つずつ別のデータグラムで、Linux の順に伝えます。上げ下げには
    `ifi_change` に `IFF_UP` を持つ `RTM_NEWLINK`（`RTNLGRP_LINK`）を、それから
    `inetdev_event`、`fib_add_ifaddr`、`fib_del_ifaddr`、`addrconf`、`rt6_disable_ip`、
    `rtmsg_fib`、`inet6_rt_notify` と同じく、増えたり消えたりしたアドレス
    （`RTNLGRP_IPV4_IFADDR`、`RTNLGRP_IPV6_IFADDR`）と経路（`RTNLGRP_IPV4_ROUTE`、
    `RTNLGRP_IPV6_ROUTE`。新しいものは Linux と同じ `NLM_F_CREATE`、`NLM_F_EXCL`、
    `NLM_F_APPEND`、`NLM_F_REPLACE` を持ちます）を伝えます。上げたときは最後に、
    `inet6_ifinfo_notify` と同じく、`AF_INET6` のリンクのダンプと同じ IPv6 自身の
    `RTM_NEWLINK`（`RTNLGRP_IPV6_IFINFO`）を伝えます。IPv4 のアドレスのものと経路の
    リクエストのものはリクエストのシーケンス番号とポートを持ち、IPv6 のアドレスは足したときに
    仮のものと仮でないものの 2 度伝えます。bind していないソケットには何も届きません。
    IPv4 のアドレスか経路の変化を求めたソケットには確認応答の前に届き、`NLM_F_ECHO` を
    付ければ自分の写しとして届きます。`RTNLGRP_NEIGH` には、ループバックの近隣を
    リクエストが変えたとき（上のとおり）と、消えるときに伝えます。`lo` を通る UDP のデータグラム（待つものがないポートからは ICMP の port
    unreachable が戻ります）と、TCP のハンドシェイクの最初のセグメント（とその答え）は、
    `___neigh_create` と同じく、次のホップの近隣を黙って作ります。IPv4 は `0.0.0.0` を
    キーにする 1 つ（`RTN_BROADCAST`）、IPv6 は 1 つずつ（`RTN_LOCAL`）で、どれも
    `NUD_NOARP` です。`lo` を落とすと、新しいものから順に `RTM_DELNEIGH` で伝えます
    （`fib_disable_ip` と `rt6_disable_ip` が消すのと同じく、IPv4 のものは `RTM_NEWLINK`
    のあと、IPv6 のものはその経路のあとでアドレスの前）。IPv4 のものは、最後の IPv4 の
    アドレスがなくなったときにも伝えます。`lo` の変化では netconf の通知
    （`RTNLGRP_IPV4_NETCONF`、`RTNLGRP_IPV6_NETCONF`）は来ません。Linux も、デバイスが
    増えるか消えるとき（上の veth ペア）か、`/proc/sys/net` の設定が変わったとき（下）に
    しか送りません。どれも、ファミリーと `NETCONFA_IFINDEX`（`all` は -1、`default` は
    -2）と伝える設定を持つ `netconfmsg` で、ポートとシーケンス番号は 0 です。増える
    デバイスでは、`inet_netconf_fill_devconf` と（`CONFIG_IPV6_MROUTE` のある
    カーネルの）`inet6_netconf_fill_devconf` と同じく、IPv4 の転送、逆経路のフィルター、
    マルチキャストとブロードキャストの転送、プロキシ ARP、リンクの落ちた経路を無視する
    設定と、IPv6 の転送、マルチキャストの転送、プロキシ NDP、最後のものを伝えます。

- 汎用 netlink のソケット（プロトコル `NETLINK_GENERIC`）は自分のポートを持つので、
  `NETLINK_ROUTE` のソケットもプロセスの ID に bind していても、同じくプロセスの ID に
  bind します。ファミリーは、ほかを入れずに作ったカーネルと同じく、コントローラの `nlctrl`
  （ファミリー ID 16）だけです。そのため、ファミリーを引くプログラム（libnl の
  `genl_ctrl_resolve` や `genl ctrl list` など）は、そのファミリーがないことを知ります。
  - **リクエスト:** `genl_rcv_msg` と同じく、ファミリーでない型は `ENOENT`、
    `genlmsghdr` が欠けたメッセージは `EINVAL`、`nlctrl` にないコマンドは
    `EOPNOTSUPP` です。コマンド 11 からは、予約のフィールドや、`NLM_F_REQUEST`、
    `NLM_F_ACK`、`NLM_F_ECHO`、`NLM_F_DUMP` のほかのフラグも `EINVAL` です。属性は
    Linux のポリシーのとおりに確かめます。ダンプでない `CTRL_CMD_GETFAMILY` では緩く
    （知らない属性は飛ばし、短い整数は `ERANGE`）、ダンプでは厳しく（知らない属性、
    長さの違う整数、余ったバイトは `EINVAL`）確かめます。
  - **ファミリー:** `CTRL_CMD_GETFAMILY` は、`CTRL_ATTR_FAMILY_NAME` の `nlctrl` か
    `CTRL_ATTR_FAMILY_ID` の 16 に（両方あれば名前が勝ちます。ほかは `ENOENT`、どちらも
    なければ `EINVAL`）、`ctrl_fill_info` と同じく、名前、ID、バージョン 2、ヘッダーの
    大きさ、コマンドとそのフラグ、グループを持つ `nlctrl` の `CTRL_CMD_NEWFAMILY` で
    答えます。ダンプはそれを挙げ、`NLMSG_DONE` を同じデータグラムに入れます。
    `CTRL_CMD_GETPOLICY` のダンプは、`ctrl_dumppolicy` と同じく、`nlctrl` のコマンドの、
    あるいは `CTRL_ATTR_OP` が指す 1 つ（ほかは `ENOENT`）のポリシーを返します。各コマンドの
    リクエストとダンプがどのポリシーを使うか、それから各属性の型と範囲を、1 つずつ別の
    メッセージで返します。ダンプの途中でのもう 1 つのダンプは `EBUSY` です。
  - **グループ:** ソケットのグループは 64 で（0 とそれを超えるものは `EINVAL`）、誰でも
    入れます。`nlctrl` の `notify` はグループ 16 で、ファミリーが増えも減りもしないので
    何も届きません。

- ソケット診断の netlink ソケット（プロトコル `NETLINK_SOCK_DIAG`）は、Linux の
  `sock_diag`、`unix_diag`、`inet_diag`、`tcp_diag`、`udp_diag` と同じく、作られた
  ネットワーク名前空間の AF_UNIX、TCP、UDP のソケットを伝えます。そのため `ss -x`、
  `ss -t`、`ss -u` はそれらを挙げます。
  - **リクエスト:** AF_UNIX への `SOCK_DIAG_BY_FAMILY` は、状態（`TCP_ESTABLISHED`、
    `TCP_CLOSE`、`TCP_LISTEN`）が `udiag_states` にあるソケットを、Linux の `netlink_dump` と
    同じ大きさに分けてダンプします（1 ページ分、あるいはそれまでで一番長い受信の分で
    32 KiB まで。次の部分は受信が空きを作ったときに送ります）。`NLMSG_DONE` はそのあとです。ダンプでなければ、inode が `udiag_ino` で（0 は `EINVAL`、ない
    ものは `ENOENT`）、cookie が合う（違えば `ESTALE`、すべて 1 ならどれにも合います）
    ソケットに答えます。リスナーがまだ accept していない接続は inode をまだ持たないので
    挙げません。AF_UNIX、AF_INET、AF_INET6 のほかのファミリーにはハンドラーがなく
    （`ENOENT`）、`AF_MAX` を超えるファミリーや短すぎるリクエストは `EINVAL`、
    `SOCK_DESTROY` は `EOPNOTSUPP`、`SOCK_DIAG_BY_FAMILY`、`SOCK_DESTROY`、
    `TCPDIAG_GETSOCK` のほかの型は `EINVAL` です。
    ダンプの途中のもう 1 つのダンプは `EBUSY` です。
  - **伝えること:** ソケットごとに、型、状態、inode、cookie を、それから `udiag_show` が
    求めるものを `sk_diag_fill` の順に伝えます。名前、ソケットファイルの inode とデバイス、
    peer の inode（peer が閉じたあとと、accept を待つあいだは 0）、リスナーを待つ
    クライアント、キュー（読まれるのを待つものと送って待っているもの、リスナーなら待つ
    接続とバックログ）、メモリ（`SO_RCVBUF`、`SO_SNDBUF`、送って待っているもの）です。
    そのあとに shutdown を必ず伝えます（ストリームとパケットのソケットでは peer が逆向きに
    閉じたものも含み、peer が閉じたあとは両方）。最後に、所有者を、netlink ソケットを
    作った側のユーザー名前空間での値で伝えます。ほかのソケットが connect した
    データグラムのソケットは、Linux と同じく `TCP_ESTABLISHED` です。
  - **TCP と UDP のリクエスト:** AF_INET か AF_INET6 への `SOCK_DIAG_BY_FAMILY` は
    プロトコルを指します（`sdiag_protocol`、または `INET_DIAG_REQ_PROTOCOL` の属性）。
    TCP か UDP で、ほかのものにはハンドラーがありません（`ENOENT` で、ダンプなら
    `NLMSG_DONE` がそれを運びます）。ダンプは、状態が `idiag_states` にあるその
    ファミリーのソケットを、Linux の表が持つとおりに挙げます。TCP では、まずリスナー
    （宛先のポートを求められていなければ）、次にポートを持つ閉じたソケット
    （`TCP_BOUND_INACTIVE`）、最後に接続で、ソケットがなくなったあとも残る `TIME_WAIT`
    （または `FIN_WAIT2`）の保持もここに入ります。求められた送り元と宛先のポートのもの、
    フィルター（`INET_DIAG_REQ_BYTECODE`。`ss` が `sport = :80` などから作るもの）が通す
    ものだけを挙げます。フィルターは Linux の `inet_diag_bc_audit` と同じように確かめます
    （`EINVAL`。`CAP_NET_ADMIN` のないマークの条件は `EPERM`）。ダンプでなければ、
    アドレスとポートが指す 1 つのソケットに、Linux と同じ引き方で答えます。TCP では接続、
    なければリスナーで、ないものと cookie が合わないものは `ENOENT` です。UDP では送り元
    から宛先へのデータグラムが届くソケットで、cookie が合わなければ `ESTALE` です。古い
    `TCPDIAG_GETSOCK` は、両方のファミリーの TCP に同じことをします。`SOCK_DESTROY` は、
    `CONFIG_INET_DIAG_DESTROY` なしで作ったカーネルと同じく `EOPNOTSUPP` です。短すぎる
    リクエストは `EINVAL` です。
  - **TCP と UDP について伝えること:** ソケットごとに、状態（ハンドシェイクがリスナーの
    空きを待つあいだは `TCP_SYN_SENT`、そのあとは接続の端の状態、または `TCP_LISTEN`）、
    アドレスとポート（IPv6 のソケットでは IPv4 のものを対応させた形）、cookie、タイマー
    （ハンドシェイクの再送、キープアライブ、`TIME_WAIT` のもの）、キュー（リスナーなら
    待つ接続とバックログ）、netlink ソケットを作った側のユーザー名前空間での所有者、
    inode（まだ accept されていない接続は 0）を伝えます。そのあと `inet_sk_diag_fill` の
    順に、shutdown を伝え、`idiag_ext` が求めれば `IP_TOS`、IPv6 のソケットのトラフィック
    クラス、待ち受け中か閉じていれば `IPV6_V6ONLY` を伝えます。続けて、`CAP_NET_ADMIN`
    にはマーク、クラスとして優先度、cgroup、オプション（`inet_diag_sockopt`）、メモリ
    （UDP のソケットのデータグラムは `udp_rmem_schedule` と同じくページ単位で数えたもの、
    バッファー、リスナーのキューがいっぱいで落としたハンドシェイクの数）、TCP のソケットの
    `tcp_info`（`ss -i` が見せる `INET_DIAG_INFO`）と輻輳制御（`cubic`）を伝えます。`TIME_WAIT` の保持
    については、アドレス、状態、タイマーだけを伝えます。
  - **グループ:** Linux は `sock_diag` の 4 つのグループを 32 にするので、ソケットの
    グループは 32 です。誰でも入れますが、何も届きません。

- MCTP のソケット（`AF_MCTP`、`SOCK_DGRAM`、プロトコル 0。ほかのプロトコルは
  `EPROTONOSUPPORT`、その次にほかの型は `ESOCKTNOSUPPORT`）は、`CONFIG_MCTP` を組み込んだ
  カーネルの Linux 7.0 の `af_mctp` と同じく、ネットワーク名前空間のループバックの MCTP
  エンドポイント ID の間でメッセージを送受信します。
  - **バインド:** `bind` は `sockaddr_mctp` を取ります（短いものや詰め物のあるものは
    `EINVAL`、ほかのファミリーは `EAFNOSUPPORT`、`CAP_NET_BIND_SERVICE` がなければ
    `EACCES`）。中身は、整合性検査のビットを除いたメッセージの型、ローカルのエンドポイント
    ID か `MCTP_ADDR_ANY`、ネットワークです。ID があって `MCTP_NET_ANY` なら、既定の
    ネットワーク（1）になります。同じようにバインドするソケットは 2 つ持てず、1 つの
    ソケットは 1 度しかバインドできません（`EADDRINUSE`）。その前の `connect` は、
    バインドが受け取る相手と型を決めます（長さが 12 でないもの、タグや整合性検査の
    ビットのあるもの、それと違う型やネットワークのバインドは `EINVAL`。バインドや
    `connect` の後は `EADDRINUSE`）。
  - **送信:** `sendto` と `sendmsg` には、欠けも詰め物もなく、タグのビットがタグ・
    `MCTP_TAG_OWNER`・`MCTP_TAG_PREALLOC` だけで、最後のものには持ち主のビットもある
    アドレス（違えば `EINVAL`。なければ `EDESTADDRREQ` で、`write` も同じです）と
    `CAP_NET_RAW`（`EACCES`）が要ります。メッセージは型を先頭に、`mctp_route_lookup` と
    同じくゲートウェイをたどってローカルの経路に至る経路で（なければ `EHOSTUNREACH`）、
    ループバックの最初の MCTP アドレスから、途中のいちばん小さい MTU のパケットに
    分けて送ります。パケットはすぐに受け取られ（`mctp_dst_input`）、そこでのエラーが
    送信のエラーになります。受け取る鍵もバインドもなければ `ENOENT`、受信バッファが
    いっぱいなら `ENOMEM`（Linux と同じく各パケットの `truesize` で数えます）、
    どの鍵も組み立て直さない 64 KiB を超えるメッセージは `EINVAL` です。バッファに
    収まらない長さ（`kmalloc` の 4 MiB）は `ENOBUFS` です。
  - **受信:** メッセージは、タグとアドレスが一致する鍵のソケットに届きます。送り手が
    タグを持つメッセージの始まりなら、その型のバインドに Linux の順番で届きます。
    宛先と送り手の両方、送り手、宛先、そのネットワークの任意のアドレス、任意の
    ネットワークの順です。`recvfrom` と `recvmsg` は、その中身と、ネットワーク・送り手・
    型・タグの `sockaddr_mctp` を返します。フラグは `MSG_PEEK`、`MSG_TRUNC`、
    `MSG_DONTWAIT` だけを取ります（ほかは `EOPNOTSUPP`）。
  - **タグ:** `MCTP_TAG_OWNER` の送信は、相手への鍵がまだ持っていないいちばん小さい
    タグを取ります（8 つとも取られていれば `EBUSY`）。その鍵は 6 秒の間か、そのタグの
    答えが来るまで残ります。`SIOCMCTPALLOCTAG` と `SIOCMCTPALLOCTAG2` は手でタグを作り
    （タグ・フラグ・ローカルの ID のある要求は `EINVAL`）、`MCTP_TAG_PREALLOC` の送信が
    それを使います（作っていないものは `ENOENT`）。そのタグは `SIOCMCTPDROPTAG` か
    `SIOCMCTPDROPTAG2` が捨てるまで残ります（なければ `EINVAL`）。ソケット自身の
    ほかの `ioctl` は、`FIONREAD` も含めてすべて `EINVAL` です。
  - **ハードウェアアドレス:** `MCTP_OPT_ADDR_EXT`（`SOL_MCTP`。ちょうど `int` の大きさで、
    違えば `EINVAL`）を付けると、`sockaddr_mctp_ext` はインターフェースの番号と
    ハードウェアアドレスでループバックの外に送ります（ほかの番号は `ENOENT`、6 バイトで
    ないアドレスや詰め物は `EINVAL`）。Linux と同じく、送信は成功してもメッセージは
    失われます。ループバックが下りている間は `noop` のキューイング規則が捨てます。
    上がっている間は戻ってきますが、`eth_type_trans` が `ETH_P_MCTP`（0xfa）を
    `ETH_P_802_3_MIN` より小さい 802.3 の長さとみなすので、フレームは 802.2 に渡り、
    MCTP には届きません。このオプションを付けたソケットが受け取るメッセージは、
    入ってきたインターフェースを示しますが、それは 0（なし）です。
  - **そのほか:** `getsockname`、`getpeername`、`listen`、`accept`、`shutdown`、`socketpair` は
    `EOPNOTSUPP` です。`SOL_SOCKET` と `SOL_MCTP` 以外のレベルの `setsockopt` と
    `getsockopt` は `EINVAL` です。

- マシンの NUMA ノードは、ノード 0 の 1 つだけです。`set_mempolicy` と `mbind` は、
  Linux 6.9 のすべてのモードとそのフラグを受け付け、ノードのマスクを Linux と同じように
  確かめます。ノード 0 より後ろのノードは落とし、それが 1 つもないマスクは `EINVAL`、
  Linux の 1024 ノードを超えるビットも `EINVAL` です。`get_mempolicy` は、スレッドの
  ポリシー、範囲のポリシー（`MPOL_F_ADDR`）、使えるノード（`MPOL_F_MEMS_ALLOWED`）、
  ページや次にインターリーブするノードとしてのノード 0（`MPOL_F_NODE`）を返します。
  新しいスレッドやプロセスは作ったスレッドのポリシーを継ぎ、`execve` の後も残ります。
  プロセスの範囲のポリシーは `fork` と `mremap` の後も残り、ページの割り当てを外すか
  新しく割り当てるまで続きます。メモリはすべてノード 0 にあるので、どのポリシーでも
  ページは動きません。
  `set_mempolicy_home_node` は、範囲、フラグ、ノード（ノード 0 だけ）を確かめ、
  範囲に自分のポリシーを持つ VMA が要ります。なければ `ENOENT`、`MPOL_BIND` と
  `MPOL_PREFERRED_MANY` 以外のポリシーなら `EOPNOTSUPP` です。`migrate_pages` と
  `move_pages` は、Linux と同じようにタスクを探し（`ESRCH`、読む権利がなければ
  `EPERM`、ゾンビなら `EINVAL`）、タスクが使えないノードや `MPOL_MF_MOVE_ALL` には
  `CAP_SYS_NICE` が要ります。`migrate_pages` は何も動かさず、何も残しません。
  `move_pages` も何も動かさず、状態にはページのものを返します。自分のページは 0
  （ノード 0）、まだ何も触れていないページは `-ENOENT`、プライベートの匿名メモリを
  読んだだけで割り当てられるゼロページと、何もマップされていない所は `-EFAULT` です。
  0 以外のノードは `ENODEV` です。`fork` の子は、Linux の `vma_needs_copy` がコピーする
  VMA のページテーブルだけを受け継ぎます。`anon_vma` を持つ VMA（何かが書き込んだ
  プライベートのメモリ）と、ガード領域を置いたことのある VMA です。ほかの VMA の
  ページは子が改めて割り当てるので、子が触れるまでは `-ENOENT` です。

- `uname` は x86_64 の Linux で、スレッドの UTS 名前空間のホスト名 `paludarium` と
  ドメイン名 `(none)` を答えます。これは `sethostname` と `setdomainname` で変えられます
  （`CAP_SYS_ADMIN` がなければ `EPERM`、64 バイトを超えると `EINVAL`）。`CPUID` と同じく、
  ホストのことは見せません。ゲストは root（ユーザーとグループが 0 で、すべての
  ケーパビリティを持つ）として、Linux の最初のプロセスと同じく補助グループなしで
  始まります。ネイティブのプログラムは、起動したものの補助グループを持ちます。
  Linux と同じく、資格情報はスレッドごとにあります。実・実効・保存・ファイル
  システム用のユーザー ID とグループ ID、補助グループ、許可、実効、継承、
  バウンディング、アンビエントのケーパビリティ、securebits です。`capget` は、
  どのスレッドのケーパビリティでも、ヘッダーの 3 つの版のどれでも読み、`capset` は、
  呼んだスレッドのケーパビリティを、持っている範囲で Linux の規則どおりに変えます
  （継承のものはバウンディングセットの範囲でもあります）。アンビエントセットには、
  新しい許可と継承のセットの両方にあるものだけを残します。`set*id` 系と
  `setgroups` は、Linux の規則どおりにそれらを変えます。ID は、そのスレッド自身の
  ID のどれかにするか、`CAP_SETUID` や `CAP_SETGID` があれば何にでもできます。
  `SECBIT_NO_SETUID_FIXUP` がなければ、ユーザー ID がすべて root でなくなると
  ケーパビリティ（`PR_SET_KEEPCAPS` があれば、許可されたものは残ります）と
  アンビエントのものを失います。実効 ID が root でなくなると実効
  ケーパビリティを失い、root に戻ると取り戻します。ファイルシステム用の ID も、
  ファイルシステムのケーパビリティについて同じです。実効 ID かファイルシステム用の
  ID が変わると、プロセスはダンプできなくなり（`fs.suid_dumpable` は 0）、親の
  終了で受けるシグナルも消えます。`execve` は、set-user-ID のプログラムならその
  持ち主を実効ユーザー ID にし、set-group-ID のプログラムなら、グループが実行できる
  ときにそのグループを実効グループ ID にします。`PR_SET_NO_NEW_PRIVS` があれば
  これらのビットを無視します。それでも実効 ID が変わる（ファイルシステム用の
  グループでも補助グループでもないグループが実効グループになる）か、ケーパビリティが
  増える exec では、実 ID を実効 ID にして、ケーパビリティも元より増やしません。
  そのうえで `execve` は、保存 ID とファイルシステム用の ID を実効 ID にそろえ、
  Linux の `cap_bprm_creds_from_file` と同じくケーパビリティを与えます。
  - **ファイルケーパビリティ**：プログラムの `security.capability` は、その許可の
    ものをバウンディングセットの範囲で、継承のものをスレッドの継承セットの範囲で
    与え、実効フラグがあれば実効にもします。リビジョン 3 の値は、その root が
    スレッドのユーザー名前空間かその上で root のときだけ効きます。どのリビジョン
    でもない値と、実効フラグがあって許可のものをバウンディングセットがすべては
    認めない値では、プログラムとそのインタープリタを読んだあとで exec を断ります
    （`EINVAL`、`EPERM`）。
  - **root**：`SECBIT_NOROOT` がなければ、（実 ID か実効 ID が）root ならバウンディング
    セットと継承セットを与え、実効 ID が root なら実効にもします。ただし、
    ファイルケーパビリティのある set-user-ID の root のプログラムを別のユーザーが
    実行するときは別です。
  - **アンビエント**：ファイルケーパビリティか実効 ID の変化があればアンビエント
    セットを消し、残ったものは許可にも実効にもなります。
  - `PR_SET_KEEPCAPS` を消し、ほかの securebits、バウンディングセット、継承セットは
    残します。

  exec で実効 ID が変わるとき、exec の前の実 ID と違うとき、root でないユーザーが
  実効フラグかアンビエントを超える許可のケーパビリティを得るときは `AT_SECURE` を
  立てます。この安全な exec は、
  親の終了で受けるシグナルを消し、`RLIMIT_STACK` のソフトの上限を 8 MiB まで
  下げます。`execve` の後、プロセスはまたダンプできるようになります。ただし、
  exec の前に実効 ID が実 ID と違っていたとき、プログラムを読めないとき、exec で
  実効 ID かファイルシステム用の ID が変わったときは別です。最後の場合は、親の
  終了で受けるシグナルも消えます。補助ベクトルと `/proc/self/status` は、
  これらの ID とケーパビリティを示します。
  初めに渡したファイルは root のもので、スレッドが作ったファイル、ディレクトリ、
  シンボリックリンク、memfd は、そのスレッドのファイルシステム用のユーザー ID と
  グループ ID のものです。`chown` で別の持ち主やグループにでき、メモリ上の
  ファイルシステムはその持ち主を覚えています。マウントしたホストのディレクトリでは、
  初めはどのファイルも root のもので、持ち主とグループはその回の間だけ覚えます。

- ファイルは Linux と同じように確かめます（`generic_permission`）。持ち主には
  持ち主のビット、ファイルのグループに属する者（ファイルシステム用のグループ ID か
  補助グループで）にはグループのビット、それ以外にはその他のビットが当てはまります。
  `CAP_DAC_READ_SEARCH` があればどのファイルも読め、どのディレクトリも検索できます。
  `CAP_DAC_OVERRIDE` があれば、誰も実行できないファイルの実行のほかは何でもできます。
  パスは、名前を探す各ディレクトリの検索の許可が要ります。たどり始める場所（ルート、
  作業ディレクトリ、`dirfd`。その上のディレクトリは確かめません）から、たどる
  シンボリックリンクの先までです。`open` は、アクセスモードと `O_TRUNC` に応じて
  読み書きの許可が要り、新しいファイルにはそのディレクトリの書き込みと検索の許可が
  要ります。`mkdir`、`symlink`、`link` と `rename` の新しい名前も同じです。名前を
  消す（`unlink`、`rmdir`、`rename`）にも同じ許可が要り、スティッキーな
  ディレクトリでは、ファイルかディレクトリの持ち主であるか `CAP_FOWNER` が要ります
  （`EPERM`）。別のディレクトリへ移すディレクトリは、それ自身の書き込みの許可が
  要ります。`chmod` と時刻の設定は、持ち主か `CAP_FOWNER` が要ります（`EPERM`）。
  ファイルのグループに属さず `CAP_FSETID` もないスレッドの `chmod` は、set-group-ID の
  ビットを外します。両方の時刻を今にするだけなら、ファイルを書けるスレッドにも
  許します（`EACCES`）。`chown` で別の持ち主にするには `CAP_CHOWN` が要り、持ち主は
  自分の属するグループにできます。`truncate` は書き込み、`chdir` は検索の許可が
  要ります。`access` は実 ID で確かめ（root なら許可されたケーパビリティで）、
  `AT_EACCESS` ならファイルシステム用の ID で確かめます。`execve` には、スレッドが
  実行できる通常のファイルが要ります（ディレクトリや、実行のビットがないときの root
  でも `EACCES`）。読めないプログラムはダンプできないまま動きます。
  `PT_INTERP` のあるプログラムは、Linux の `load_elf_binary` と同じくそのインタプリタ
  から始まり、`AT_BASE` と `AT_ENTRY` でプログラムを見つけます。インタプリタにも同じ権限が
  要り、読めなければダンプできません。set-ID ビットは効かず、x86-64 のプログラムでない
  ファイルは `ELIBBAD` です。
  `#!` で始まるファイルは、Linux の `load_script` と同じくインタプリタを動かします。
  最初の行（255 バイトまで）がインタプリタの名前と、任意の引数 1 つを示します。引数は、
  その名前、その引数、そして `argv[0]` の代わりにスクリプトのパスです。set-ID ビットは
  スクリプトではなくインタプリタのものが効きます。インタプリタもスクリプトでよく、
  最初のスクリプトの 5 段下までです（それより深いと `ELOOP`）。最初のプログラムも
  スクリプトでよく、同じように動きます。Linux と同じく、
  `chown` はディレクトリ以外のファイルから set-user-ID のビットを外します。
  set-group-ID のビットも、グループが実行できるとき、または呼んだ側がそのグループに
  属さず `CAP_FSETID` もないときに外します。持ち主とグループが変わらなくても外します。
  `CAP_FSETID` のないスレッドが通常ファイルに書くか切り詰めたときも同じものを外しますが、
  グループの実行権限のない set-group-ID ビットは、そのグループの一員なら残ります。
  `AF_UNIX` のソケットファイルは新しいファイルと同じ権限が要り、呼び出し側の
  ファイルシステム ID のものになります。`connect` と `sendto` には、パスが示すファイルへの
  書き込み権限が要り、ファイルの種類より先に確かめます。
  set-group-ID のディレクトリの中に作ったものはディレクトリのグループを継ぎ、
  新しいディレクトリはそのビットも継ぎます。`fchmod` と `fchown` は、`pipe` や
  `pipe2` で作ったパイプとソケットについても、`fstat` が返すモードと持ち主を
  変えます。パイプでは両端がそれらを共有し、ソケットペアでは端ごとに持ちます。最初の
  持ち主は、それを作ったスレッド、または接続を受け付けたスレッドのファイルシステム ID です。
  ホストが用意する標準入力、標準出力、標準エラー出力では `EPERM` を返します。

- `execveat(dir, path, argv, envp, flags)` は `execve` と同じくプログラムを動かし、
  相対パスは `dir` から探します。`AT_EMPTY_PATH` は、パスが空のときディスクリプタ
  （`O_PATH` のものも）が持つファイルを動かし、`AT_SYMLINK_NOFOLLOW` はシンボリック
  リンクを断ります（`ELOOP`）。ほかのフラグは `EINVAL`、`AT_EMPTY_PATH` のない空の
  パスは `ENOENT` です。プログラムは、Linux の `alloc_bprm` と同じく `/dev/fd/<dir>`
  か `/dev/fd/<dir>/<path>` を `AT_EXECFN` として、スクリプトならそのパスとして
  受け取ります。exec で閉じるディスクリプタのスクリプトは `ENOENT` です
  （`BINPRM_FLAGS_PATH_INACCESSIBLE`）。どのパスも指さない memfd や削除したファイルは、
  `execveat` でも `/proc/self/fd` のリンクでも、ディスクリプタから動きます
  （`fexecve`）。そのとき `/proc/self/exe` は memfd のリンクか、` (deleted)` の付いた
  パスを読みます。そのファイルは丸ごと読むので、メモリの上限より大きいものは、
  セグメントが小さくても `ENOMEM` です。ELF のプログラムでもスクリプトでもないものは、
  先頭のバイトで `ENOEXEC` になります。Landlock は、削除したファイルの `EXECUTE` を、
  Linux がその dentry から確かめるのと同じく、もとの場所から確かめます。memfd はどの
  階層にも属しません。`AT_EXECVE_CHECK`（Linux 6.14）は `EINVAL` です。

- プログラムのファイルとそのファイルへの書き込みは、Linux の `i_writecount` と
  同じく互いを断ります（`ETXTBSY`）。exec は、書き込みのために開いた記述があるファイルを
  断ります。プログラム、スクリプトとそのインタープリタ、ELF のプログラムの
  インタープリタのどれでもです。プロセスがプログラムを動かしている間は、その fork が
  動かしている間も含めて、そのファイルは書き込みのために開けず、`O_TRUNC` や
  `truncate` でも空にできません。最後のプロセスが終わるか別のプログラムを exec すると、
  また書き込めます。スクリプトと ELF のインタープリタは、読み込む間だけ押さえます。
  `memfd_create` が返す memfd 自身のディスクリプタは書き込む側に数えないので、Linux と
  同じく、動かすこともそれで書き込むこともできます。`/proc/self/fd` から書き込みのために
  開き直したものは数えます。数えるのはエミュレータのプロセスだけで、マウントした
  ディレクトリのファイルにホストのプログラムが書き込んでいても分かりません。

- `chmod` と `utimensat` は、メモリ上のファイルシステムでも、マウントしたホストの
  ディレクトリでも使えます。Windows のホストでは、`chmod` が変えるのは読み取り専用の
  属性だけです。`fchmodat2`（Linux 6.6）は `AT_SYMLINK_NOFOLLOW` と `AT_EMPTY_PATH` を
  受け取ります。シンボリックリンクのモードは変えられないので、`AT_SYMLINK_NOFOLLOW` で
  シンボリックリンクを指すと `EOPNOTSUPP` です。glibc の `lchmod` は最初にこれを呼びます。`stat` が返すのは更新時刻だけで、アクセスと変更の時刻は
  0 です。マウントしたディレクトリのファイルでは、渡した両方の時刻がホストに残ります。
  umask は、Linux で `CLONE_FS` が共有するのと同じく、スレッドの間で共有します。
  `fsync` と `fdatasync` はファイルとディレクトリでは成功し、パイプ・ソケット・端末では
  `EINVAL` を返します。`fadvise64` はヒントとして受け付けます。
  `utime`・`utimes`・`futimesat` は、Linux の `do_futimesat` と同じく、`utimensat` の古い形です。
  秒単位、または 2 つの `struct timeval` を受け取ります。マイクロ秒は 100 万未満でなければならず
  （`EINVAL`。パスより先に確かめます）、時刻を渡さなければ今の時刻にし、`futimesat` にパスを
  渡さなければその記述子の時刻を設定します。`syncfs` は、`sync` と同じく、どの記述子でも
  成功します。`readahead` は、読むために開いた（`EBADF`）通常のファイルかブロックデバイスの
  記述子（`EINVAL`）と、`loff_t` として負でない数（`EINVAL`）を受け取ります。満たすキャッシュは
  ありません。
  `sync_file_range` は、Linux と同じくフラグと範囲（`EINVAL`）、次にファイル（通常の
  ファイル、ディレクトリー、ブロックデバイス以外は `ESPIPE`）を確かめ、共有のマッピングへの
  書き込みをファイルに書き戻します。

- `mknod` と `mknodat` は、FIFO、ソケットのノード、空の通常のファイル（種類が 0 のときも）を、
  モードの許可のビットから umask を除いて作ります。Linux の `do_mknodat` と同じく、ディレクトリの
  種類は `EPERM`、知らない種類は `EINVAL` です。キャラクターデバイスとブロックデバイスは、
  表すデバイスがないので、`CAP_MKNOD` のないプロセスと同じく `EPERM` です。FIFO は、Linux の
  `fifo_open` と同じように開きます。どのプロセスがそのノードを開いても、記述が一つでも開いて
  いる間は同じパイプにつながり、一つも開いていなければ新しいパイプになります。ブロックする
  読み手は書き手を、ブロックする書き手は読み手を待ちます（シグナルが来ると `EINTR` で終わるか、
  `SA_RESTART` のハンドラや停止の後にやり直します）。ブロックしない読み手はすぐに開き、書き手が
  いない間はファイルの終わりを読みます。読み手のいないブロックしない書き手は `ENXIO` です。
  `O_RDWR` は両方の端を開き、どちらも待ちません。開いた FIFO の `fstat` はノードの inode、
  モード、持ち主を返し、`/proc/self/fd` はそのパスを示します。マウントしたホストのディレクトリ
  では、FIFO を作れるのは Linux のホストだけです（ほかでは `EPERM`）。そのパイプはエミュレーター
  のもので、同じノードを開いたホストのプログラムにはつながりません。

- `statfs` は、メモリ上のファイルシステムを 4 GiB の tmpfs として返します。使用量と
  inode の数は、実際に持っているものです。マウントしたホストのディレクトリでは、
  ホストのファイルシステムの値を返します。`/proc/self/mountinfo`、`/proc/self/mounts`、
  `/proc/mounts` は呼び出し元のマウント名前空間のマウントの一覧です（ルートは `tmpfs`、
  `--mount` ごとに `hostfs`。ホストのパスは見せません。起動したときからの `/dev` は
  `devtmpfs`、`/dev/shm` は tmpfs です。`mount` が作った tmpfs とバインドの
  マウントは、ソースと、`mountinfo` ではルートとして見せるディレクトリ、マウントと
  スーパーブロックが読み出し専用かどうか、伝播の種類とともに出します）。`chroot` のあとは、Linux の `seq_path_root` と同じく、
  マウントポイントをプロセスのルートから見せ、ルートの下にないものは出しません。
  `/proc/<pid>/mountinfo` と `mounts`（`/proc/thread-self` と `/proc/<pid>/task/<tid>` のものも）は、
  Linux の `mounts_open_common` と同じくそのタスクのもので、そのマウント名前空間のマウントを
  そのルートから見せます。読むのは誰でもかまいません。開いたときの名前空間とルートを、
  読むたびにそのときの中身で見せます。終わったプロセスは、回収されるまで
  これらのファイルを持ちますが、開くと `EINVAL` です。ほかのスレッドより先に終わった
  リーダーのプロセスのもの（`/proc/<pid>/mountinfo`）も、開くと `EINVAL` です。残った
  スレッドの `task/<tid>` のものは開けます。
  ファイルシステムごとに `mountinfo` のマウントの行と同じ `st_dev` を持つので、
  `df` はどのファイルシステムも表示します。バインドマウントは、Linux と同じく、ソースと同じ
  `st_dev` を持つので、`df` はそのデバイスを一度表示したあとは出しません。パスから開いたのではないパイプ・ソケット・pidfd・
  memfd・`memfd_secret` のファイル・名前空間のファイル・匿名 inode（eventfd や epoll
  など）は、Linux と同じく、それぞれのファイルシステム（pipefs・sockfs・pidfs・内部の
  tmpfs・secretmem・nsfs・anon_inodefs）が持つデバイスにあり、どれもマウントのもの
  ではありません。`ustat` は、マウントの `st_dev` なら空きブロックと空き inode の数を
  返し、それらのデバイスなら何も空いていない（0）と返します。Linux の `simple_statfs`
  と、制限のない内部の tmpfs も 0 を返すからです。ほかのデバイスなら `EINVAL` です。

- ファイルのブロックの大きさ（`st_blksize`、`stx_blksize`、`FIGETBSZ`）は、Linux と
  同じくそのファイルシステムのものです。`/proc`（procfs）と、疑似端末のスレーブ、
  標準入力・出力・エラーの端末（devpts）は 1024 で、ほかは、パイプ、ソケット、`memfd`、`/dev` も含めて 4096
  です。そこでの `statfs` は、Linux の `simple_statfs` と同じく、procfs や devpts、
  （ほかの `/dev` は devtmpfs なので）tmpfs の種類と 4096 の `f_bsize` を返します。
  `/proc/self/fd` のリンクは procfs のものですが、Linux のマジックリンクと同じく、
  それをたどる呼び出しはディスクリプタのファイルそのものに届きます。アクセスモードは
  問いません（`O_PATH` のディスクリプタも）。`stat`、`statfs`、`open`、`access`、
  `chmod` と `fchmodat`、`chown` と `fchownat`、`utimensat`、`truncate`、`chdir`、
  拡張属性の呼び出し、`execve` がそうです（`O_PATH` のディスクリプタへの `fchmod`、
  `fchown`、`futimens`、`ftruncate` は `EBADF` です）。削除したファイル、memfd、パイプには
  ディスクリプタ自身を通して届きます（memfd と削除したファイルの `execve` はそれを
  動かし、パイプのものは `EACCES` です）。
  `O_PATH | O_NOFOLLOW` のディスクリプタが持つシンボリックリンクはもうたどりません。
  そのモードは変えられず（`EOPNOTSUPP`）、`chdir` はディレクトリでないもの（`ENOTDIR`）、
  `truncate` は通常のファイルでないもの（`EINVAL`）とし、`execve` は `ELOOP` になります。

- パスの途中にある `/proc/self/fd`（や `/dev/fd`）のリンク、`/proc/self/cwd`、
  `/proc/self/exe` は、Linux の `nd_jump_link` と同じく飛び越えます。
  `/proc/self/fd/3/name` は、ディスクリプタ 3 が持つディレクトリの中の `name` で、
  そのディレクトリは名前を変えた後も今の名前で見つかり、`..` はそこから続きます。
  削除したディレクトリと開いていないディスクリプタは `ENOENT`、ディレクトリでない
  ファイルは `ENOTDIR` です。ほかのプロセスの `fd` のリンク（`/proc/<pid>/fd/3/name`）も、
  Linux の `proc_fd_link` と同じく、そのディスクリプタを見てよい読み手なら同じように
  たどり（見てはいけなければ `EACCES`）、プロセスが終わった後は `ENOENT` です。絶対パスを取るファイルの呼び出しはこう扱います（`RESOLVE_*` フラグ付きの
  `openat2` は自身の解決の中で扱います）。`/proc` のディスクリプタや `/proc` の中の
  作業ディレクトリからの相対パス、`..` やシンボリックリンクで `/proc` に入るパス、
  `execve`、Unix ソケットのアドレスは扱いません。

- `/proc` にあるのは、ほかには `/proc/loadavg`、`/proc/meminfo`、`/proc/stat`、`/proc/uptime`、`/proc/sysvipc`（後述）、
  `fs`、`kernel`、`net` だけを持つ `/proc/sys`（後述）、
  プロセスごとのディレクトリと、自分のプロセスのものです。`/proc/<pid>` は、その中のものを相対的に開けて、それらを並べる
  ディレクトリです。`/proc/self` はそこへの
  シンボリックリンク（0777、サイズ 0）で、`readlink` で PID になります。`lstat` と、
  `AT_SYMLINK_NOFOLLOW` の `fstatat` や `statx` はリンクを返し、`stat` と末尾の `/` は
  リンクをたどり、`O_NOFOLLOW` はたどらず `ELOOP` です。`O_PATH | O_NOFOLLOW` は
  リンクそのものを開き、読んだプロセスの PID を読み、自分を `/proc/self` と
  名乗ります。ほかに `/proc/self/status`、`stat`、`statm`、`cmdline`、`environ`、`auxv`、
  `limits`、`personality`、`comm`、`syscall`、`exe`、`cwd`、`root`、`maps`、`mounts`、`mountinfo`、`clear_refs`、`smaps`、
  `pagemap`、`wchan`、`io`、`fd`、`fdinfo`、`ns`、`task` があります。これらの持ち主は、Linux の `task_dump_owner` と同じく
  プロセスの実効ユーザーとグループで、ダンプできなくなると（ID を変えてから
  `PR_SET_DUMPABLE` まで）root です。ディレクトリ、`task`、`fdinfo`（0555）はどちらでも
  プロセスのもので、`/proc/self` そのものは root のものです。`stat` は
  その持ち主とモード（`environ`、`auxv`、`pagemap`、`io`、`personality`、`syscall` は 0400、`comm` は 0644、`clear_refs`
  は 0200、ほかのファイルは 0444）を示します。
  開いたファイルの `fstat` は、そのパスを最後に探したとき（どのプロセスの open や `stat` でも）の
  持ち主を示します。Linux の inode と同じで、開いたファイルが押さえるパスを探すたびに新しく
  なります（`pid_revalidate`）。開いたディレクトリとその `ns` の `fstat` は、Linux の
  `pid_getattr` と同じくその時点の持ち主を示します。開くときは Linux の `generic_permission` と同じくその
  持ち主に対してモードを確かめるので、`CAP_DAC_OVERRIDE` なしに書き込み用に開くと
  `EACCES` で、ダンプできないプロセスが `environ`、`auxv`、`pagemap` を読むために開いても
  `EACCES` です。書き込み用に開いたもの（root のもの）への書き込みは `EINVAL` です。ただし `comm` への書き込みは、
  Linux の `comm_write` と同じくスレッドの名前を変えます。書き手がそのスレッドのプロセスのものなら、
  最初の 15 バイト（NUL まで）を名前にして、書いた数をすべて返します（スレッドは次のシステムコールで
  その名前になり、`/proc` にはすぐ出ます）。ほかのプロセスからは `EINVAL`、スレッドがもういなければ
  `ESRCH` です。musl の `pthread_setname_np` は、ほかのスレッドの名前をここに書きます。`root` はルートへのリンクで、`chroot` が動かさなければ `/` です。`exe`、`cwd`、`root`、`fd` の
  リンクは、Linux の `d_path` と同じく、ファイルが読み手のルートの下にあればそのルートからの
  パスとして、そうでなければ印を付けずにマシンのルートからのパスとして読めます。`maps` と
  `smaps` も、マップしたファイルを同じように名付けます。`status` は、Linux と同じ項目を
  同じ順番で持ちます
  （umask、ID、スレッドの数、シグナルのマスク、ケーパビリティなど）。メモリの項目は
  ロックしたメモリ（`VmLck`）、常駐するメモリの最大値（`VmHWM`）、常駐するメモリ
  （`VmRSS`）で、ゾンビは示しません。何も測っていないほかのメモリの項目と CPU の
  項目はありません。最大値は Linux の `hiwater_rss` です。`update_hiwater_rss` と同じく
  `munmap`、`MADV_DONTNEED` などページを捨てる呼び出しの前に記録するので、`VmHWM` が
  `VmRSS` を下回ることはありません。`fork` の子の最大値は、`dup_mm` と同じく持っている
  ページから始まり、`clear_refs` に 5 を書くと戻ります。`statm` は、Linux の `task_statm` が数えるものをページ単位で示します。
  マップの大きさ、常駐しているページ、そのうちファイルか共有メモリのもの、`stat` が示す
  コードの範囲のページ、0、書き込めるプライベートなマップとスタック、0 です。`limits` は、
  `prlimit` が返すソフトとハードのリソース制限を Linux と同じ列で並べます。`auxv`（0400）は、
  プログラムの `execve` がスタックに書いた補助ベクトルです。Linux の `saved_auxv` と同じく、
  プログラムがそのあとスタックに何をしても、`fork` しても残ります。自分のディレクトリと `/proc` の下の
  それ以外のパスは、ふつうのパスと同じようにファイルシステムで探します。
  そのため `--mount /:/` では、ホストの `/proc` に届きます。

- `/proc` は、ファイルシステムがそこに持つプロセス以外のもの（`--mount /:/` では、
  ホストのプロセスを除いたホストの項目）、上のファイル、そしてゲストのプロセスごとの
  ディレクトリ（ゾンビも含む）を、Linux と同じくこの順に並べます。`ps`、`pgrep`、`pidof`
  が読むのはこれです。ほかのプロセスの `/proc/<pid>`（0555 で、持ち主はその実効 ID）には、
  `status`、`stat`、`statm`、`cmdline`、`environ`（0400）、`auxv`（0400）、`limits`、`personality`（0400）、`comm`、
  `syscall`（0400）、`maps`、`clear_refs`（0200）、`smaps`、`pagemap`（0400）、`wchan`、`io`（0400）、`exe`、`cwd`、`root`、`mounts`、`mountinfo`、`fd`、`fdinfo`、
  `ns`（0511）、`task` があり、
  Linux の `fs/proc/base.c` と `array.c` が root に見せるとおりに作ります。そこのほかの名前は
  `ENOENT` です。いなかったプロセスや回収されたプロセスのディレクトリも、マウントした
  ホストの `/proc` に何があっても `ENOENT` です。`task` はプロセスのスレッドを並べ、
  `/proc/<pid>/task/<tid>`（読むプロセス自身のスレッドも）には `task` 以外の同じファイルが
  あり、そのスレッドのもの（名前、シグナルのマスク、`Pid` にスレッドの ID、`Tgid` に
  プロセスの ID）を示します。`/proc/thread-self` は読んでいるスレッドのディレクトリへの
  リンク（0777）で、`<pid>/task/<tid>` と読めます。スレッド自身の ID も、Linux と同じく、
  そのスレッドから見たプロセスのディレクトリを指し、`/proc` には並びません。Linux の
  `ptrace_may_access` と同じく、同じプロセスでなく `CAP_SYS_PTRACE` もない読み手には、
  `environ` は実 ID が、`auxv`、`maps`、`smaps`、`pagemap`、`exe`、`cwd`、`root`、`fdinfo`、`ns` と `fd` のリンクはファイルシステムの ID が、ダンプできるプロセスの
  ユーザーとグループのすべての ID と同じで、そのプロセスが同じユーザー名前空間にいて、
  その許可されたケーパビリティを読み手のもの（ファイルシステムの ID の場合は実効
  ケーパビリティ）が含むのでなければ `EACCES` です。上に書いた、ほかのプロセスを読む場合と
  同じです。ファイルの持ち主はこのプロセス自身のもの（前述）と
  同じで（ダンプできないプロセスのディレクトリ（0555）もそのプロセスのものです）、開くときは Linux の `generic_permission` と同じく、ほかの何よりも先に通常の
  ファイルのモードをその持ち主に対して確かめます（`EACCES`）。書き込むには、`comm`、
  `uid_map`、`gid_map`、`setgroups`（0644）を除いて `CAP_DAC_OVERRIDE` が要り、`environ`、
  `auxv`、`pagemap` を読むには持ち主か `CAP_DAC_OVERRIDE` が要ります。開いたものの `fstat` は、
  このプロセス自身のもの（前述）と同じく持ち主を示します。`statm` と `limits` は、Linux と同じく誰でも読めます。
  `fd` そのものを読むことと中を探すことは、Linux の
  `proc_fd_permission` と同じくそのモード（0500）が許す読み手だけができます。`fd` と
  `fdinfo` は、このプロセス自身のもの（後述）と同じものを、ほかのプロセスのディスクリプタに
  ついて示します。`fd` のリンクを開くと、そのディスクリプタのファイルを開き直します。
  Linux の `d_path` と同じく、リンクは読み手のルートからのパスとして読めますが、ファイルは
  そのプロセスが開いた場所、つまりそのプロセスのルートとマウント名前空間で探します。
  そこでの `/proc/self` は、そのプロセスのディレクトリです。`fdinfo` は、そのプロセスの
  ファイルのマウントと、そのプロセスが持つレコードロックを示します。ほかのプロセスについて見えるのは、そのプロセスのスレッドが
  最後のシステムコールかシグナルの確認で公開したもの（名前（`PR_SET_NAME`、`execve`）、
  ブロックしているシグナルと保留中のシグナル、資格情報）と、その時点のプロセスの
  シグナルの扱い、メモリ（`cmdline`、`environ`、`auxv`、`maps`、`smaps`、`pagemap`、`statm`、`stat` の大きさ）、リソース制限、カレントディレクトリ、
  umask、ディスクリプタです。状態は、読んでいるプロセスなら `R`、ジョブ制御で止まって
  いる間は `T (stopped)`、終わってから回収されるまでは `Z (zombie)`、Linux が動いていない
  タスクをそう見せるのと同じく、スレッドが待ちで眠っている間（パイプ、futex、タイマーなど
  何を待っていても）は `S (sleeping)`、それ以外は `R` です。待たないシステムコールの中に
  いる間も `R` です。
  ゾンビは名前と ID を残し、スレッドは 1 つと数え、メモリも umask もディスクリプタも
  持ちません。Linux と同じく、`cmdline`、`maps`、`smaps` は空、`statm` はすべて 0、`fd` と `fdinfo` には何もなく、`exe`、`cwd`、`root` は `ENOENT` で、`limits` は残ります。
  Linux の `proc_mem_open` はメモリのあるプロセスについてだけ読み手を確かめるので、
  ゾンビの `maps` と `smaps` は、モードが許すどの読み手も開けます。Linux の `__mem_open` と
  `pagemap_open` は、読み手を確かめる前にメモリのないプロセスを断るので、ゾンビの
  `environ`、`auxv`、`pagemap` は、モードが許すどの読み手にも開けません（`ESRCH`）。

- プロセスやスレッドの `personality` は 0400 で大きさは 0 で、Linux の
  `proc_pid_personality` と同じく、読んだときにスレッドの実行ドメインとフラグを 16 進数 8 桁と
  改行で書きます。そのとき、Linux の `lock_trace` がアタッチのモードの `ptrace_may_access` と
  読み手のファイルシステムの ID で決めるとおり、そして Yama の `ptrace_scope` 1（祖先、
  `PR_SET_PTRACER` で名指しされたもの、または `CAP_SYS_PTRACE`）のとおりに、ほかのプロセスの
  読み手が読めるかを確かめます（`EPERM`）。回収されたタスクは `ESRCH` です。`wchan`
  （0444）は、Linux の `proc_pid_wchan` が動いているタスクと、タスクを読めない読み手に
  返すのと同じく、改行のない `0` を読みます。`stat` の `wchan` の項目は別のもので、
  下のとおり、待っているタスクは 1 です。

- プロセスやスレッドの `syscall` は 0400 で大きさは 0 で、Linux の `proc_pid_syscall` と同じく
  読んだときに書きます。読み手が読めるかは `personality` と同じくアタッチできるかで決め
  （`EPERM`）、読むスレッド自身のものは、読んでいるその呼び出しです。ほかのスレッドは、
  動いている（システムコールの中かどうかにかかわらず、待ちで眠っても止まってもいない）なら
  `running`、呼び出しの中で
  眠っているか止まっているなら、Linux の `pt_regs` と同じく、最後にカーネルに入ったときの
  レジスタです。呼び出しの番号と 6 つの引数、スタックポインターと命令ポインター（`syscall`
  命令の次）を 16 進数で並べ、呼び出しでない入り方（ユーザーのコードからの停止）なら `-1` と
  2 つのポインターです（Linux の `handle_userfault` と同じく、`userfaultfd` を待つ
  フォールトの間も眠っていて、こう見えます）。終わったスレッドにはカーネルのスタックが残っていないので
  `-1 0x0 0x0` です。スレッドは、カーネルに入るたびにいくつかのストアでレジスタを記録し、
  ほかのスレッドはそれを欠けずに読みます。新しいスレッドや子は、Linux の `copy_thread` と
  同じく、それを作った呼び出しでの親のレジスタから始まります。

- プロセスやスレッドの `io`（`/proc/<pid>/task/<tid>/io`）は 0400 で大きさは 0 で、
  Linux の `task_io_accounting` が数えるものを示します。`rchar` と `wchar` は読み書きの
  呼び出し（`read`、`pread64`、`readv`、`preadv`、`preadv2`、それらの書き込み版、
  `sendfile` と `copy_file_range` は両方、ホストの stdout と stderr への書き込みも）が
  動かしたバイト数、`syscr` と `syscw` はその呼び出しの数です。Linux の `vfs_read`、
  `do_readv`、`do_preadv` がそれぞれ決めるとおり、ファイル自身の読み書きで失敗した
  呼び出しは数え、その前に断られたものは数えません（`readv` は不正なディスクリプタも
  数え、`pread64` は位置のないファイルを数えません）。`splice`、`tee`、`vmsplice`、
  `recv` と `send` の仲間、`io_uring` は、Linux と同じく何も数えません。`read_bytes`、
  `write_bytes`、`cancelled_write_bytes` は、ファイルがすべてメモリにある Linux と同じく
  0 です。ブロックデバイスがないからです。スレッドのファイルはそのスレッドの数を示し、
  プロセスのファイルは、Linux の `do_io_accounting` と `wait_task_zombie` と同じく、
  スレッド、終わったスレッド、`wait` で回収した子（とその子たちのもの）の数を足します。
  `fork` した子は 0 から始まり、ゾンビは数を残します。中身は、Linux の `seq_file` と
  同じく、読んだときと、`lseek` でほかの位置へ移ったときに作ります。そのとき Linux の
  `ptrace_may_access` が読み手のファイルシステムの ID で決めるとおり、そのプロセスの
  ものでない読み手が読めるかを確かめます（`EACCES`）。そのため、ダンプできる間に開いた
  ディスクリプタでも、ダンプできなくなった後は読めません。その後に回収された
  スレッドやプロセスは `ESRCH` です。こうして失敗した `lseek` は、Linux の
  `seq_lseek` と同じく、ファイルを先頭に戻します。

- `/proc/self/stat` は、括弧に入った名前の後に Linux と同じ 52 の項目を持ちます。状態は
  `R`（読んでいるプロセスは動いているので。ほかのプロセスは上のとおり）、親、プロセスグループ、セッション、制御端末のデバイスとフォアグラウンドのグループ（なければ 0 と -1）、
  プロセスと wait した子の CPU 時間（`USER_HZ` の 100 分の 1 秒単位）、優先度と nice 値、
  スレッドの数、マッピングの大きさ、`RLIMIT_RSS` の上限、プログラムのコードの始まりと終わり
  （Linux の `start_code` と `end_code`。`load_elf_binary` と同じく、実行できる `PT_LOAD`
  セグメントの最も低いアドレスと、ファイルにある部分の最も高い終わりです。ゾンビは 0）、
  スタックとヒープの始まり、
  10 進数のシグナルの集合、`wchan`（Linux が root に見せるのと同じく、待っているタスクは
  1。ただし複数のスレッドを持つプロセス全体のものは 0）、`exit_signal`、
  プログラムのデータの始まりと終わり（Linux の `start_data` と `end_data`。
  `load_elf_binary` と同じく、すべての `PT_LOAD` セグメントの最も高いアドレスと、
  ファイルにある部分の最も高い終わりです）、引数と環境変数の文字列の位置です。何も
  測っていないもの（ページフォールト、常駐メモリ、開始時刻、スケジューラーの
  数値）は 0 です。Linux の `ptrace_may_access` がファイルシステムの ID で決めるとおり、
  タスクのメモリを見てはいけない読み手には、Linux の `do_task_stat` と同じく、
  `start_code` と `end_code` を 1、スタックの始まり、`wchan`、`start_data` から後の
  項目をすべて 0 として隠します。その最後の `exit_code` は、終わったプロセスでは wait の
  ステータス（終了コードの 256 倍か、シグナル。コアダンプしたものは 0x80 を足します）で、
  止まったプロセスでは、wait がその停止を報告するまで、プロセス自身の `stat` に止めた
  シグナルが出ます（Linux の `group_exit_code`）。`task` の下のスレッドの `stat` には
  停止のものは出ません。`stat` は Linux と同じく先頭から読むたびに作るので、
  同じディスクリプターでもそのときのタスクと読み手で決まります。権限を手放した読み手には
  アドレスが隠れ、回収されたタスクは `ESRCH` です。`status`、`statm`、`limits`、
  `cmdline`、`comm` も、Linux の `proc_single_show`・`proc_pid_cmdline_read`・`comm_show` と
  同じく読むたびに作ります。`status` の ID は開いたプロセスのユーザー名前空間から見たものです。
  `environ` は、Linux の `environ_read` が開いたときの `mm` を読むのと同じく、開いたときの
  アドレス空間を読むので、そのプロセスが `execve` するか終わったあとは何も読めません。
  `auxv` は、そのアドレス空間の `execve` が残したものを読みます（`auxv_read`）。
  このプロセス自身のものも、ほかのプロセスのものと同じく、スレッドが最後のシステムコールで
  公開したものから読むたびに作ります。`cmdline` と `environ` のほかへの
  `pwrite` は、Linux が `seq_open` で作るファイルと同じく `ESPIPE` です。`cmdline` と `environ` は、今メモリにある引数と環境変数の文字列で、
  それぞれ NUL で終わります。`comm` は名前と改行です。

- `/proc/self/exe` と `/proc/self/cwd` はシンボリックリンク（0777、サイズ 0）で、それぞれ
  プロセスが動かしているプログラム（`execve` が読み込んだもので、シンボリックリンクは
  たどった後のパス。最初のプログラムは CLI が与えるパスで、`--mount` の中ならそのパス、ほかは
  `/<ファイル名>`）と、カレント
  ディレクトリを指します。`stat` と `open` はたどり、`O_NOFOLLOW` はたどらず `ELOOP` です。

- `/proc/sys/fs/mqueue` には、Linux の `ipc/mq_sysctl.c` と同じく、読むプロセスの IPC
  名前空間の POSIX メッセージキューの上限があります。`queues_max`、`msg_max` と
  `msg_default`（1〜65536）、`msgsize_max` と `msgsize_default`（128〜16 MiB）です。
  モード 0644 の通常ファイルで、IPC 名前空間を持つユーザー名前空間の root のもので、
  書くために開けるのもその root だけです（`EACCES`）。`/proc/sys` のファイルは、Linux の
  `proc_sys_make_inode` と同じく、それぞれ自分の inode を持ち、サイズは 0 です。そのため、
  別の sysctl からの `copy_file_range` は何も写さず、ほかのファイルシステムからは `EXDEV`
  です。読むと、先頭から値と改行を返し、
  その先では何も返しません。先頭への書き込みは、Linux の `proc_dointvec_minmax` と同じく
  `int` を 1 つ読んで値にします。空白、あってもよい `-`、10 進の数字（`0x` の後は 16 進、
  `0` の後は 8 進）、その後に空白・タブ・改行か終わりです。読んだ分（値の後の空白も含みます）を
  返し、値がない、余計な文字がある、長すぎる、範囲外なら `EINVAL` です（`queues_max` は
  どの `int` も取り、符号なしで比べます）。先頭より後への書き込みは、`sysctl_writes_strict`
  と同じく受け取るだけで何も変えません。

- `/proc/sys/fs/aio-nr`（モード 0444）はマシンの aio コンテキストが用意したイベントの数で、
  `/proc/sys/fs/aio-max-nr`（0644、最初は 65536）はその上限です。書くために開けるのは
  root（どのユーザー名前空間の外でもユーザー ID 0）だけです。どちらも Linux の
  `proc_doulongvec_minmax` と同じく unsigned long として読み書きし、書き込みは `-` を取らず
  （`EINVAL`）、それ以外は `/proc/sys/fs/mqueue` のファイルと同じに読みます。
  `/proc/sys/fs` にあるのはこれらと `fanotify`、`inotify`、`mqueue` だけです。

- `/proc/sys/fs/inotify` はマシンの inotify の上限で、root の持つモード 0644 の
  通常のファイルです。書くために開けるのは root（どのユーザー名前空間の外でも
  ユーザー ID 0）だけで、上のファイルと同じに読み書きします。`max_user_instances`
  （最初は 128）と `max_user_watches`（最初は 31956、下のインスタンスの説明のとおり）は
  0 から `INT_MAX` までの unsigned long で、それ以後に各ユーザーが持てる数です。
  `max_queued_events`（最初は 16384）は 0 以上の `int` で、それ以後に作るインスタンスが
  `IN_Q_OVERFLOW` までに溜めるイベントの数です。

- `/proc/sys/fs/fanotify` も同じく、マシンの fanotify の上限です。`max_user_groups`
  （最初は 128）と `max_user_marks`（最初は 33979。`sysinfo` が示すメモリーの 1% を inode
  2 つ分の大きさで割った数）は 0 から `INT_MAX` までの unsigned long、`max_queued_events`
  （最初は 16384）と `watchdog_timeout`（0）は 0 以上の `int` です。

- `/proc/sys/kernel` には、Linux の `ipc/ipc_sysctl.c` と同じく、開くプロセスの IPC
  名前空間の System V IPC の上限があります。新しい名前空間では Linux の既定値で、持ち主と
  書くために開ける者は `/proc/sys/fs/mqueue` のファイルと同じです。`shmmax` と `shmall`
  は（`aio-max-nr` と同じ）unsigned long、`shmmni` と `msgmni` は 0 から 32768 までの
  `int`、`msgmax` と `msgmnb` は 0 以上の `int`、`sem` は `semmsl`、`semmns`、`semopm`、
  `semmni` の 4 つの `int` で、タブで区切って読めます。`sem` への書き込みは、Linux の
  `proc_dointvec` がベクトルを読むのと同じく、与えた数だけを設定します。不正な値は
  `EINVAL` で、その前の値は設定されたままです。`semmni` は、最後に 0 から 32768 の間に
  なければ元に戻ります（`ERANGE`、`proc_ipc_sem_dointvec`）。ほかに、マシンの
  `perf_cpu_time_max_percent`、`perf_event_max_sample_rate`、`perf_event_mlock_kb`、
  `perf_event_paranoid`、`unprivileged_bpf_disabled` があります。
  エミュレートするマシン全体に 1 つずつで、最初は Linux の既定値（25、100000、516、2、2）です。
  root の持つモード 0644 のファイルで、書くために開けるのは root（どのユーザー名前空間の
  外でもユーザー ID 0）だけです（`EACCES`）。`perf_event_mlock_kb` と
  `perf_event_paranoid` は任意の `int` を取ります（`proc_dointvec`）。
  `perf_cpu_time_max_percent` は 0 から 100 まで、`perf_event_max_sample_rate` は 1 以上を
  取ります（`EINVAL`）。後者は、Linux の `perf_event_max_sample_rate_handler` と同じく、
  前者が 0 か 100 のあいだは拒まれます（`EINVAL`）。`unprivileged_bpf_disabled` は、Linux の `bpf_unpriv_handler`
  と同じく、`CAP_SYS_ADMIN` のある書き手から（`EPERM`）0 から 2 まで（`EINVAL`）を
  取り、いったん 1 になるとほかの値を取りません（`EPERM`）。`perf_event_open` と `bpf` は
  そのときの値を確かめます。`shm_rmid_forced`（0 か 1。持ち主と書ける者は上限と同じ）を
  設定すると、Linux の `shm_close` と `exit_shm` と同じく、セグメントは最後に外れたときに
  消え、作ったスレッドが一度もつながなかったものは、そのスレッドが終わるか名前空間を
  離れたときに消えます。設定したときには、どのマッピングにもない孤児のセグメントを
  消します（`shm_destroy_orphaned`）。`auto_msgmni` は 0 を読め、0 か 1 を書いても何も
  起きません。`shm_next_id`、`sem_next_id`、`msg_next_id`（モード 0444。名前空間の
  ユーザー名前空間で `CAP_CHECKPOINT_RESTORE` か `CAP_SYS_ADMIN` を持つ者は書けます）は、
  その種類の次のオブジェクトが一度だけ取る ID で、なければ -1 です。書けるのは 0 から
  `INT_MAX` までで、オブジェクトはそのシーケンス番号と、その添字から 32768 未満で最初の
  空いている添字を取ります。なければ `ENOSPC` で、Linux master の `idr_alloc` が
  `ipc_mni` で止まるのと同じです（7.0 はその先を探しました）。その場合も次の ID は
  使われてなくなります。これらの
  ファイルへの書き込みは、Linux の `proc_sys_call_handler` と同じく、書き込みのときに
  もう一度確かめます。開いたときには書けても、今は書けない書き手は `EPERM` で、
  `unprivileged_bpf_disabled` は開いた者ではなく書き手に `CAP_SYS_ADMIN` を求めます。
  孤児を消すのは `shm_rmid_forced` を設定する書き込みだけで、Linux master の
  ハンドラーと同じです（7.0 は設定したものを読んでも消しました）。
  `/proc/sys/kernel` にあるのはこれらだけで、`/proc/sys` のどの
  ディレクトリも、Linux の木と同じく、名前の順に並べます。

- `/proc/sys/net` には、Linux の `net/ipv4/devinet.c` と `net/ipv6/addrconf.c` が `all`、
  `default`、デバイスごと（`lo` と veth の端）に持つのと同じく、開いたプロセスのネットワーク名前空間の
  設定があります。`ipv4/ip_forward`、`ipv4/conf/<デバイス>/forwarding` と `rp_filter`、
  `ipv6/conf/<デバイス>/disable_ipv6` と `forwarding` です。ファイルとディレクトリは、
  ネットワーク名前空間を持つユーザー名前空間の root のもので、ファイルは 0644 です。
  書き込みで開けるのは、root と、その名前空間への `CAP_NET_ADMIN` を持つものです
  （`net_ctl_permissions`。開けなければ `EACCES`、書き込みのときに書けなければ
  `EPERM`）。どれも `proc_dointvec` と同じく `int` を 1 つ取ります。最初の名前空間は、
  Linux の組み込みの値と同じく、どれも 0 で始まります。新しい名前空間は、最初の名前空間の
  IPv4 の `all` と `default` を写し、IPv6 のものは組み込みの値で始めます
  （`devconf_inherit_init_net` が 0 のとき）。その `lo` は `default` を写します。
  ハンドラーと同じく:
  - IPv4 の `forwarding`（`ip_forward` は `all` のもの）には、書き手の `CAP_NET_ADMIN` が
    要ります（`EPERM`、`devinet_sysctl_forward`）。`all` のものが変わると、`default` と
    すべてのデバイスのものも変わります。`default` のものはどのデバイスにも及びません。
    変えた書き込みは、`RTNLGRP_IPV4_NETCONF` のメンバーにその転送の `RTM_NEWNETCONF` で
    伝えます。`all` のものなら `all`、`default`、すべてのデバイスの順に、`default` か
    デバイスのものならそれだけです。
  - デバイスに設定した `rp_filter` はそのデバイスのものになります。`default` に設定すると、
    まだ設定していないすべてのデバイスに及びます。失敗した書き込みでも、設定したことに
    なります（`devinet_conf_proc`）。値を変えた書き込みは、書いた先のものだけを伝え、
    `default` のものを取ったデバイスのものは伝えません。
  - IPv6 の 2 つは、Linux master の `addrconf_sysctl_forward` と `addrconf_sysctl_disable`、
    そして CI のカーネルと同じく、正しくない値を `EINVAL` で知らせます（7.0 は知らせず、
    `all` かデバイスの `forwarding` は 1 を返しました）。`all` のものは `default` とすべてのデバイスのものを変えます。
    `forwarding` は、`addrconf_fixup_forwarding` と同じく、入るか切れるときだけ
    `RTNLGRP_IPV6_NETCONF` のメンバーに伝えます（1 から 2 では伝えません）。`all` の
    ものでは、`default`、切り替わったデバイスのもの、`all` 自身の順です。
    `disable_ipv6` はこうして伝えることはありません。
    デバイスの `disable_ipv6` を入れると、そのデバイスは IPv6 のアドレスと経路を失い、
    落ちたときと同じく知らせます（`addrconf_ifdown`）。上がっている間に切ると、
    `NETDEV_UP` と同じく `::1` が戻り、IPv6 自身の `RTM_NEWLINK`（`RTNLGRP_IPV6_IFINFO`）を
    知らせます。入っている間は、`lo` が上がっても IPv6 は何もせず、新しい IPv6 の
    アドレスは `EACCES` です（`addrconf_add_dev`）。
  - リンクの `IFLA_AF_SPEC` の IPv4 と IPv6 の設定にこれらが出ます。IPv6 は
    `disable_ipv6` が切れているときだけ準備ができています。

- `/proc/self/fdinfo`（0555）は、開いているディスクリプタごとに、Linux の `seq_show`
  と同じ内容のファイル（0444、大きさ 0）を持ちます。`pos` はファイル記述の位置
  （パイプやソケットでは 0）、`flags` は 8 進のフラグ（`F_GETFL` のものに、
  ディスクリプタの `O_CLOEXEC` を加えたもの）、`mnt_id` は `statx` が返す ID、
  `ino` は `fstat` が返す inode です。inotify のインスタンスでは、`inotify_fdinfo` と
  同じく、新しいウォッチから順に 1 行ずつ加わります。`inotify wd:` にウォッチの
  ディスクリプタ、`ino:` と `sdev:` にファイルの inode とカーネルの番号の付け方
  （`MKDEV`）でのファイルシステムのデバイス、`mask:` に与えたマスクを 16 進で書き、
  `ignored_mask:0` と、`show_mark_fhandle` と同じファイルのハンドルが続きます。
  `fhandle-bytes:` と `fhandle-type:` は 16 進で、`f_handle:` はそのバイトで、
  `AT_HANDLE_FID` の `name_to_handle_at` が返す識別子です。pidfd では、`pidfd_show_fdinfo` と
  同じく `Pid:` と `NSpid:` が加わります。そのプロセス（またはスレッド）の、`/proc` の PID
  名前空間である最初の名前空間での番号（ゾンビでも同じで、回収されると -1）と、その下の
  名前空間それぞれでの自分の名前空間までの番号です。ほかの種類のファイルも Linux と同じ行を加えます。
  最初の 4 行の後には `lock:` の行が続きます（`show_fd_locks`）。まずファイル記述の
  `flock` のロック、次にそのファイル記述を通して掛けたレコードロックのうちプロセスの表か
  ファイル記述が持つものが始まりの順に並び、両方を通して 1 から番号が付きます。各行には
  `FLOCK`、`POSIX` か `OFDLCK`、`READ` か `WRITE`、掛けたプロセスの ID（ファイル記述の
  レコードロックでは -1）、デバイスと inode、範囲（`flock` の
  ロックでは `0 EOF`）が並びます。ファイル記述が持つのと同じ種類の `flock` を頼み直しても
  ロックはそのままです。種類を変えると、`flock_lock_inode` と同じく、新しいロックがぶつかる
  ときでも古いロックを先に外します。ほかのロックにまとめたロックは、
  `posix_lock_inode` と同じく、広げた側のロックのファイル記述に残ります。続いて eventfd では
  `eventfd-count`（16 進）、`eventfd-id`（`ida_alloc` と同じく、ほかの eventfd が持たない
  いちばん小さい番号）、`eventfd-semaphore`、signalfd では `sigmask`、timerfd では
  `clockid`、`ticks`、`settime flags`、`it_value`、`it_interval` です（満了したタイマーは、
  読み込みか `timerfd_gettime` が先へ進めるまで満了した時点にとどまり、`it_value` は 0、
  `ticks` は最初の満了のものです）。epoll では見張るファイルごとに `tfd:` の行が加わります。
  追加したときのディスクリプタ、イベント（`epoll_ctl` が加える `EPOLLERR` と `EPOLLHUP` を
  含み、発火した one-shot ではフラグだけ）、データ、ファイルの位置、inode、デバイス
  （プロセスが持つそのファイルのディスクリプタのもの。なければ 0）です。

- `/proc/loadavg`、`/proc/meminfo`、`/proc/uptime` は、Linux と同じ形式で `sysinfo` と
  合った値を返します。ロードアベレージは 0 で、動いているタスクと生きているタスクの数、
  最後に割り当てた ID が続きます。メモリは合計、空き、使えるものがどれも 4 GiB で、ほかの
  使用はなく、スワップも huge page もありません。起動からの時間は単調時計の値で、アイドルの
  時間は数えません。

- `/proc/stat` は Linux の `show_stat` と同じ形式です。`cpu` の行と、`sched_getaffinity` が
  返す CPU ごとの行があり、`/proc/uptime` がアイドルの時間を数えないのと同じく、時間はどれも
  0 です。続いて `intr 0`、`ctxt 0`、`btime`（実時間の時計から単調時計を引いた秒数で、`ps` は
  これで起動時刻を得ます）、`processes`（割り当てた ID の数）、`procs_running 1`、
  `procs_blocked 0`、0 が並ぶ `softirq` の行です。

- `/proc/sysvipc` には `msg`、`sem`、`shm` がこの順に並びます。どれも 64 ビットのカーネルでの
  Linux の `sysvipc_*_proc_show` と同じ形式です。
  - 見出しの行に続けて、開いたプロセスの IPC 名前空間のキュー、セット、セグメントを、
    インデックスの順に 1 行ずつ並べます。
  - Linux の `seq_file` と同じく、`read` のたびに、読み手が進んだインデックスから、そのときの
    オブジェクトで行を作ります。読み込みの合間に作ったオブジェクトや消したオブジェクトが見えるか
    どうかは、読み手がどこまで進んだかで決まります。IPC 名前空間を `unshare` する前に開いた
    ファイルは、開いたときの名前空間を読み続けます。`lseek` は先頭か今の位置からで、`SEEK_END` は
    `EINVAL` です。
  - 行にはキー、ID、モードがあります。セグメントのモードには `SHM_DEST` と `SHM_LOCKED` も
    入ります。
  - 数、開いたプロセスの PID 名前空間での PID（見えないものは 0）、開いたプロセスのユーザー
    名前空間での所有者と作成者、時刻も入ります。
  - セグメントの行には、メモリにあるページのバイト数と、スワップした 0 も入ります。
  - セグメントやキューの PID は、`IPC_STAT` が返すものも、そのプロセスがなくなっても見えます。
    オブジェクトがその `struct pid` を持ち続けるためです。

- これらのシステムのファイル（`loadavg`、`meminfo`、`stat`、`uptime`、`sysvipc` の中のもの）の
  サイズは、Linux の `proc_create` が作るものと同じく 0 です。読み込みは中身の終わりまで進みます。
  プロセスやスレッドのディレクトリのファイルも、Linux の `proc_pid_make_inode` が残すとおり、
  読み込みが何を返しても（`stat` でも `fstat` でも）サイズは 0 です。

- root はこれらのシステムのファイルを書き込み用に開けますが、書き込みは `EIO` です。書き込みの
  操作がないファイルに Linux の `pde_write` が返すのと同じです。プロセス自身のファイルへの書き込みは
  `EINVAL` です。

- `/proc/self/maps` は VMA を Linux の形式で並べます。隣り合うマッピングの併合と
  分割も Linux と同じです。項目は、範囲、保護、`s` か `p`、ファイル内のオフセット、
  `stat` と同じファイルのデバイス（glibc の `major` と `minor` と同じく分けます）と inode、
  Linux と同じ桁に置く名前です。名前は
  ファイルのパス（中の改行は `\012` で、どこからも指されなくなれば空白と `(deleted)` が
  付きます）、`/memfd:<名前> (deleted)`、共有の無名メモリの `/dev/zero (deleted)`、
  `[heap]`、`[stack]` です。Linux の `seq_file` と同じく、読むときに内容を作ります。
  `read` は 1 ページまでの行全体を集め、次に見つけた VMA から続け、その時点の
  マッピングを示します。`lseek` は先頭か現在位置からだけで（末尾からは `EINVAL`）、
  大きさは 0 です。ディスクリプタが示すのは開いたときのアドレス空間で、fork した
  子が読んでもそのアドレス空間を示します。`execve` の後のように、そのアドレス空間を
  使うスレッドがなくなると何も示しません。マップはできません（`ENODEV`）。

- `/proc/self/smaps` は、`maps` の各行のあとに Linux の `show_smap` と同じ項目を
  続け、`maps` と同じように読めます。大きさ、ページの中身（`Rss`、`Pss`、`Pss_Dirty`、
  共有とプライベートそれぞれの clean と dirty のページ、`Anonymous`、`Locked`。
  ヒュージページ、スワップ、KSM は 0）、`THPeligible`、`VmFlags` です。ページは
  エントリーを持てば数えます。読んだだけの匿名のプライベートメモリはゼロページを示すので
  数えず、書いたプライベートメモリは匿名で dirty です。このプロセスでもほかのプロセスでも
  2 つ以上のページテーブルのエントリーがマップするページ（`fork` が書き込みまで共有する
  ページや、2 つのマッピングが見せるファイルのページ）は共有として数え、Linux の
  `smaps_account` が正確なマップ数を使うのと同じく、`Pss` にはその大きさをその数で割って足します。
  ファイルのマッピングで読み込みのフォールトが起きると、Linux の `do_fault_around` と
  同じく周りのページにもエントリーを作ります。`get_user_pages` を通してフォールトする
  読み込み（コアダンプ、トレーサーの `PTRACE_PEEKDATA`）も
  同じです。フォールトしたページを含む 16 ページの
  そろった区切りから（VMA の始まりがそれより後ならそこから）最大 16 ページ（既定の
  `fault_around_bytes`、64 KiB）で、VMA、そのページテーブル、ファイルの中に限り、ページ
  キャッシュにあるページだけです。memfd では書いたページ、共有メモリではどれかの
  プロセスが触れたページ、ほかのファイルでは大きさの中のすべてのページです。読み込んだ
  プログラムのセグメントは読み込みのときからすべてのページがありますが、`MADV_DONTNEED`
  がページを落としたあとは同じく周りもマップします。エントリーや
  マーカーのあるページはそのままです。System V の共有メモリと秘密のメモリは、Linux で
  `map_pages` がないので周りをマップしません。`userfaultfd` が書き込みかマイナー
  フォールトを見ている VMA もマップしません。`pagemap` の present の
  ビットも同じページを示します。`VmFlags` は VMA の Linux の
  フラグを Linux と同じ順番で並べます。保護とそのなれる先（`mr`、`mw`、`me`、`ms`。
  読むためだけに開いたファイルと書き込みを封じたファイルには `mw` がなく、AIO と
  `io_uring` のリングと秘密のメモリには、何も実行しない疑似ファイルシステムなので
  `me` がありません）、`sh`、最初のスタックの `gd`、`userfaultfd` が登録した範囲の `um` と `uw`、ロック（`lo`、`lf`）、ガード
  （`gu`）、アドバイス（`sr`、`rr`、`dc`、`wf`、`dd`、`hg`、`nh`、`mg`）、リングと秘密の
  メモリの `de`、`mm`、`dd`、課金（`ac`。書き込めたプライベートメモリが持ち、
  `MAP_NORESERVE` なら代わりに `nr` を持ちます。一度も書いていない匿名メモリは書き込め
  なくなるときに返します）、`MAP_STACK` のマッピングの `nh`、封印（`sl`）、最初の
  スタック以外の、作られてから `clear_refs` に消されていない VMA の `sd`（`VM_SOFTDIRTY`）
  です。新しい VMA とつながった VMA は、Linux の引き継がれるフラグと同じく、また `sd` を持ちます。

- `/proc/self/pagemap`（モード 0400、大きさ 0）は、Linux の `pagemap_read` と同じく、
  ユーザー空間のページごとに 8 バイトのエントリーを持ちます。あるアドレスのページの
  エントリーは、そのアドレスをページの大きさで割って 8 を掛けた位置にあります。どの
  マッピングにもないページのエントリーは 0 です。マッピングの中のページは、VMA が `sd`
  を持つあいだ soft-dirty（ビット 55）で、エントリーのあるページは `clear_refs`（後述）の
  あとに書き込まれたときもそうです。Linux の書き込みのフォールトが `_PAGE_SOFT_DIRTY` を
  付けるのと同じです。ガード領域のページ
  （`MADV_GUARD_INSTALL`）はさらにスワップのエントリー（ビット 62）でガードのビット（58）を
  持ち、何かのアクセスでエントリーを得たページは存在します（ビット 63）。プライベートな
  匿名メモリを読んだだけで見えるゼロページは、それだけです。ほかの存在するページは、
  `smaps` の数え方で匿名でなければファイルか共有メモリのもの（ビット 61）です。このプロセスでも
  ほかのプロセスでも、そのページをマップするページテーブルのエントリーがちょうど 1 つのあいだは、
  Linux が正確なマップ数 1 を見るのと同じく、ここだけにマップされています（ビット 56）。`fork` が
  共有したページは、どちらかが自分の写しに書き込むか手放すまで 2 回マップされ、2 つのマッピングが
  見せるファイルのページも 2 回マップされています。
  `userfaultfd` が書き込みから守るページはビット 57 を持ちます。フレーム番号（ビット 0 から
  54）は、Linux が `CAP_SYS_ADMIN` のない読み手に返すとおり 0 です。`read` と `pread` は
  エントリーの区切りから始め、エントリー単位で読む必要があり（`EINVAL`）、ユーザー空間の
  終わりから先や、開いたときのアドレス空間をどのスレッドも使わなくなったあとは何も
  返しません。`lseek` は Linux の `mem_lseek` と同じく、始めか今の位置からどの位置にも
  動かせ、負の位置にもなります。そこからの `read` は `EINVAL` です。終わりからは
  `EINVAL` です。書き込めません（`EINVAL`。読むためだけに開いたディスクリプタでは `EBADF`）。
  その ioctl の `PAGEMAP_SCAN` は、Linux master の `do_pagemap_scan` と同じく、範囲の
  ページを種類で探します。
  - 種類は `PAGE_IS_WPALLOWED`、`WRITTEN`、`FILE`、`PRESENT`、`SWAPPED`（ガード、
    ポイズン、uffd-wp のマーカー）、`PFNZERO`、`SOFT_DIRTY`、`GUARD` で、エントリーと
    同じ状態から決まります。
    - `PAGE_IS_WPALLOWED`：VMA が `UFFD_FEATURE_WP_ASYNC` を持つ `userfaultfd` に
      書き込み保護で登録されていて、プライベートな匿名メモリでないか、
      `UFFD_FEATURE_WP_UNPOPULATED` を持ちます。
    - `PAGE_IS_WRITTEN`：書き込み保護に登録された VMA の中で、書き込み保護されて
      いないページです。空のページも含みます。
  - ページは `category_mask`、`category_anyof_mask`、`category_inverted` で選ばれ、
    `return_mask` の種類で知らされます。同じ種類で接するページは 1 つの領域に
    まとまります。
  - スキャンは `vec_len` 個の領域か `max_pages` 個のページで早めに止まります。
    止まった場所は `walk_end` でわかり、結果は領域の数です。
  - `PM_SCAN_WP_MATCHING` では、選ばれた書き込まれたページを `UFFDIO_WRITEPROTECT`
    と同じく保護し直し、保護できない VMA は飛ばします。バッファーがなければ、Linux
    ならページテーブルがあるところのページをすべて保護します。
  - `PM_SCAN_CHECK_WPASYNC` では、そうした VMA でスキャンが止まります（`EPERM`）。
  - 要求は `pagemap_scan_get_args` と同じく確かめます。大きさ、フラグ、種類
    （`EINVAL`）、ページの区切りから始まること（`EINVAL`）、範囲とバッファーが
    ユーザー空間にあること（`EFAULT`）、長さがあればバッファーがあること（`EINVAL`）です。
  - ほかの ioctl は `ENOTTY` で、アドレス空間がなくなったあとのスキャンは `ESRCH` です。

- `/proc/<pid>/clear_refs`（モード 0200、大きさ 0。スレッドのものも）は、Linux の
  `clear_refs_write` と同じく、書き込みの先頭の多くて 12 バイト（書き込みはこれを返します）を、
  `kstrtoint` が 10 進で読むとおりに数として読みます（前後の空白を除き、符号と改行 1 つまで。
  ほかは `EINVAL`、`int` を超えれば `ERANGE`）。数は 1 から 5 で（`EINVAL`）、そのあと
  プロセスがまだある必要があります（`ESRCH`）。4 は、プロセスがそのとき持つアドレス空間の
  すべての VMA とページの soft-dirty のビットを消します。ページは次の書き込みで、また
  `mremap` が動かしたページ、`UFFDIO_COPY`、`UFFDIO_CONTINUE`、`UFFDIO_MOVE` がマップした
  ページもビットを得ます。`fork` の子は各ページのビットを引き継ぎます。5
  （`CLEAR_REFS_MM_HIWATER_RSS`）は、`reset_mm_hiwater_rss` と同じく、常駐するメモリの
  最大値（`status` の `VmHWM`）をいま常駐するメモリにします。1 から 3 は受け付けますが、
  見えるものは変わりません（制限事項を参照）。読み出しの操作はなく
  （`EINVAL`。書くためだけに開いたディスクリプタでは `EBADF`）、`lseek` は 0 のままです。

- `/proc/self/fd`（モード 0500。大きさは Linux の `proc_fd_getattr` と同じく開いている
  ディスクリプタの数）は、`.`、`..` と、開いているディスクリプタごとのリンクを並べます。名前は番号で、Linux と同じく先頭に 0 のない形で読みます。各リンクの
  `lstat` は、ユーザーのビットでディスクリプタのアクセスを示し、大きさは 64 です。`stat`
  はリンクをたどってファイルを示します。`readlink` は Linux と同じ名前を返します。
  `.`、`..` とシンボリックリンクを解決したファイルのパス（このプロセスのものは
  `/proc/<pid>/…`、procfs のルートは `/proc`）で、どこからも指されなくなれば空白と `(deleted)` が付きます。ほかに
  `pipe:[<inode>]`、`socket:[<inode>]`、`anon_inode:[eventfd]`・`[eventpoll]`・
  `[timerfd]`・`[signalfd]`・`[perf_event]`・`[pidfd]`（無名 inode の名前で、Linux 6.9 からの pidfs も同じ
  名前を返します）、`anon_inode:inotify`（Linux と同じく角括弧なし）、`anon_inode:bpf-map`、`/memfd:<名前> (deleted)` です。
  そのためにパイプとソケットは自分の inode 番号を持ちます。リンクを開くと、ファイルを
  パスで開き直します。どのパスもそのファイルを指さなくなったとき（消された、または
  名前が変わった）は、同じファイルをそのハンドルから開き直し、オフセットは別に持ちます。
  memfd なら同じファイルとシールへの新しいハンドルを返します。パイプは、Linux の
  `fifo_open` と同じく、どちらの端のリンクからでもどちらの端も開けます。`O_RDONLY` なら
  読み手、`O_WRONLY` なら書き手、`O_RDWR` なら両方を、自分の状態フラグ（`O_NONBLOCK`）を
  持つ新しいオープンファイル記述として開きます。`O_RDWR` の記述は自分の書いたものを
  読め、自分が両方の端なので、パイプの終わりも `EPIPE` も見ません。記述がすべて閉じた
  端も開き直せるので、書き手がいなくなったパイプにもまた書き手ができます。
  FIFO と違い、反対の端を待つことも、読み手のいない書き手を断ることもありません。
  端は最後の記述を閉じたときに閉じます。
  シグナルの持ち主と `O_ASYNC` は、Linux と同じく記述ごとに持ちます。データ
  （`POLL_IN`）は `O_ASYNC` のある読み手の記述すべてに、空き（`POLL_OUT`）は書き手の
  記述すべてに知らせ、`O_RDWR` の記述はその両方です。Linux の `kill_fasync` と同じく、
  最後に `O_ASYNC` を付けた記述から順に知らせます。標準のストリームは、持っている
  アクセスなら、新しい記述として開きます。
  `O_CREAT | O_EXCL` はリンクがあるので `EEXIST`、`O_NOFOLLOW` はリンクをたどらず
  `ELOOP` です。`O_PATH` も付けると、ほかのシンボリックリンク（`/dev` のものや
  ファイルシステムのもの）と同じく、リンクそのものを開きます。その `fstat`
  （`AT_EMPTY_PATH` の `fstatat` も）と `fstatfs` はリンクのもので、
  `readlinkat(fd, "")` はリンク先を読み（ほかのものの `O_PATH` のディスクリプタでは
  `ENOENT`。プロセスの `/proc` ディレクトリのリンク、つまり `fd/<n>`、`exe`、`cwd`、
  `root` では、Linux の `proc_pid_readlink` と同じく、開いたプロセスのリンクが
  そのとき指す先を、読み手のルートから見たパスで読みます）、自分のリンクはそのリンクを指し、そこから読むことはできません（`EBADF`）。
  自分のリンクをたどって開くと、そのリンクに着くので `ELOOP` です。ソケットは Linux と
  同じく `ENXIO` です。eventfd、epoll、timerfd、signalfd、inotify のインスタンスも、Linux がその無名 inode を
  `no_open` で開くので `ENXIO` です。pidfd は、root が開いたときと同じく、そのプロセスの
  別の記述として開きます（pidfs は自分の `open` を持ちません）。アクセスは開いたときの
  もので、`O_NONBLOCK` も自分で持ち、プロセスが回収された後でも開けます。Linux は先に
  inode のモード（root の 0600、pidfd は 0700）を確かめるので、ほかのユーザーは
  `EACCES` になりますが、paludarium は root と同じように開きます。Linux 以外のホストからマウントした
  ディレクトリの消されたファイルは、Linux なら開けますが、ここでは `ENXIO` です。

- `/dev`（モード 0755）は、メモリのデバイスと、Linux のシステムがそこに置くリンクと、
  疑似端末の `ptmx` と `pts`（後述）を持ち、それだけを並べます。ゲストが `/dev` の下に作ったファイルは、開いたり `stat`
  したりできますが、一覧には出ません。各エントリは 1 つの inode 番号を持ち、`stat` と
  `getdents` は同じ番号を返します。`/dev` は読み込み用にしか開けず（`EISDIR`）、
  デバイスは `O_DIRECTORY` では開けません（`ENOTDIR`）。`null`、`zero`、`full`、`random`、`urandom` は
  キャラクタデバイス（モード 0666）で、`st_rdev` に Linux と同じ番号（1:3、1:5、1:7、
  1:8、1:9）を持ちます。`null` は何も読めず、`zero` と `full` は 0 を、`random` と
  `urandom` はホストの乱数を読みます。`full` は書き込みを `ENOSPC` で拒み、ほかは
  受け取ります。`zero` のマッピングは無名のメモリで、`MAP_SHARED` なら共有です。
  `fd`、`stdin`、`stdout`、`stderr` は `/proc/self/fd` とその最初の 3 つへのリンク
  （0777）で、`open` や `stat`、それを通るパス（`/dev/fd/3`）はリンクをたどります。
  リンクに `O_NOFOLLOW` を付けると `ELOOP` で、`O_PATH` も付けると `/proc/self/fd` と
  同じくリンクそのものを開きます。ホストのマウントのファイルはデバイス番号を
  持ちません。

- **疑似端末**は、Linux の devpts、`pty.c`、N_TTY の行規則と同じに動きます。
  `/dev/ptmx`（5:2、モード 0666。devpts 自身の `/dev/pts/ptmx` も）を開くたびに
  組が 1 つでき、そのスレーブは空いている最も小さい番号の `/dev/pts/<n>` です。
  スレーブはキャラクタデバイス（136:n、モード 0620、グループ 5、持ち主は開いた
  ユーザー）で、マスターが開いている間 `/dev/pts` に並びます。スレーブは
  `TIOCSPTLCK` で解くまでロックされています。これと `TIOCGPTN`、`TIOCGPTLCK` で
  `posix_openpt`、`grantpt`、`unlockpt`、`ptsname`、`openpty` が動き、
  `TIOCGPTPEER` はマスターからスレーブを開きます。ロックされたスレーブや、マスターが
  閉じたスレーブを開くと `EIO` です。
  - マスターが書いたものはスレーブの入力になり、スレーブが書いたものをマスターが
    読みます。スレーブの行規則は、カノニカルモードの行を編集し（`VERASE`、`VWERASE`、
    `VKILL`、`VLNEXT`、`VREPRINT`、`VEOF`、`VEOL`、`VEOL2`）、`ECHO`、`ECHOE`、
    `ECHOK`、`ECHOKE`、`ECHONL`、`ECHOCTL`、`ECHOPRT` のとおりにエコーします。
    非カノニカルモードでは `VMIN` と `VTIME` のとおりに読みます。入力（`ICRNL`、
    `INLCR`、`IGNCR`、`ISTRIP`、`IUCLC`）と出力（`OPOST`、`ONLCR`、`OCRNL`、
    `ONOCR`、`ONLRET`、`OLCUC`、`XTABS`）を変換し、出力を止めて再開し（`IXON`、
    `IXANY`）、`ISIG` があれば `SIGINT`、`SIGQUIT`、`SIGTSTP` をフォアグラウンドの
    プロセスグループに送って、`NOFLSH` がなければ入力を捨てます。マスター側は
    バイトをそのまま渡します。
  - `TCGETS`、`TCSETS`、`TCSETSW`、`TCSETSF`、その `termios2` 版（`TCGETS2`
    など）と古い `struct termio` 版（`TCGETA`、`TCSETA`、`TCSETAW`、`TCSETAF`。
    各フラグの下位 16 ビットと最初の 8 文字を設定します）は、どちらの側からでも
    スレーブの `termios` に届きます。`termios` はパリティなしの `CS8 | CREAD` を
    保ち、速さは `CBAUD` か `BOTHER` から決め、`TIOCSLCKTRMIOS` でロックした部分は
    変えません（ロックには `CAP_SYS_ADMIN` が要り、`TIOCGLCKTRMIOS` で読めます）。
    `TIOCPKT` でマスターはパケットモードで読みます。スレーブのフラッシュ、出力の
    停止と再開、`^S` と `^Q` で出力を止めるかどうか（と `EXTPROC`）の変化は、
    状態のバイト 1 つだけで届き、`poll` には `POLLPRI` として見えます。データは
    0 のバイトの後に続きます。`TIOCGPKT` はモードを返します。
    `TIOCGWINSZ` と `TIOCSWINSZ`（変わるとフォアグラウンドのグループに `SIGWINCH`
    を送ります）、`FIONREAD`、`TIOCOUTQ`、`TCFLSH`、`TCXONC`、`TCSBRK`、`TIOCEXCL`、
    `TIOCGEXCL`、`TIOCGETD` と `TIOCSETD`（N_TTY だけ）、`TIOCGDEV`、`TIOCSIG` は
    Linux と同じに動きます。`TIOCSTI` も `dev.tty.legacy_tiocsti` が無効のときと同じで、
    入力を押し込めるのは `CAP_SYS_ADMIN` だけで、ほかは `EIO` です。
  - `O_ASYNC`（後述のシグナル駆動の入出力）を付けると、スレーブはカノニカル
    モードでは 1 行が読めるようになったとき、それ以外では 1 バイトが入ったときに
    `POLL_IN` を送り、マスターはスレーブの出力（やエコー）が届いたときに送ります。
    書き切れなかった書き込みは、相手の側がバッファを 128 バイトまで読み減らすか、
    出力が再開すると `POLL_OUT` を送ります。パケットのイベントでは送りません。
    `O_ASYNC` を付けると、持ち主のないファイルには持ち主が決まります。スレーブの
    フォアグラウンドのプロセスグループ、なければ呼んだプロセスです。
  - 制御端末のないセッションリーダーは、`TIOCSCTTY` か、スレーブを `O_NOCTTY`
    なしに読み込み用に開くと、それを制御端末にします。子はそれを継ぎ、`setsid` で
    なくなります。`/dev/tty` は制御端末を開きます（なければ `ENXIO`。エミュレーターの
    外のセッションのプロセスは、ホストの `/dev/tty` のままです）。`TIOCSPGRP`、
    `TIOCGPGRP`、`TIOCGSID` はフォアグラウンドのグループとセッションを決めて返します。
    バックグラウンドのグループが読むと `SIGTTIN`、`TOSTOP` のもとで書くか
    `termios` を変えると `SIGTTOU` を受け、グループが再開すると呼び出しをやり直します。
    シグナルを無視しているか、ブロックしている（ただし `SIGTTOU` ならそのまま進みます）
    か、グループが孤立しているときは `EIO` です。`TIOCNOTTY` は制御端末を手放し、
    リーダーならセッション全体が手放して、フォアグラウンドのグループに `SIGHUP` と
    `SIGCONT` を送ります。
  - スレーブの記述がすべて閉じると、マスターは残りを読んだ後 `EIO` になり、`poll` では
    切断された状態です。マスターが閉じるとスレーブは切断され（何も読めず、書き込みと
    リクエストは `EIO`）、名前も消えます。それが制御していたセッションは制御端末を
    失い、セッションリーダーに `SIGHUP` と `SIGCONT` が届きます。セッションリーダーが
    終わると、その端末のフォアグラウンドのグループに `SIGHUP` が届きます。
  - `TIOCVHANGUP`（`CAP_SYS_ADMIN` が要り、なければ `EPERM`）は、マスターが開いたまま
    スレーブを、マスターが閉じたときと同じに切断します。`vhangup`
    （`CAP_SYS_TTY_CONFIG`）は呼んだプロセスの制御端末を切断します。そのとき開いている
    スレーブの記述は切断されて `O_ASYNC` を失い、もう付けられません（`ENOTTY`）。
    入力は捨てられ、`termios` は新しいスレーブのものに戻り、行規則はスレーブがまた
    開かれるまでなくなります。その間にマスターが書いたものはエコーされずに待ち、
    開いた後のマスターの次の書き込みで一緒に届きます。マスターへの `TIOCVHANGUP` は
    マスターのファイルだけを切断し、そのファイルは何も読めなくなりますが、スレーブは
    書き続けられます。`TIOCCONS`（`CAP_SYS_ADMIN` が要ります。マスターなら `EINVAL`、
    書き込み用に開いていないスレーブなら `EBADF`）は、コンソールの出力をスレーブが
    受け取るようにし、そのスレーブが切断されるまで開いたまま持ちます。ほかの端末が
    持っている間は `EBUSY` です。

- CPU 時間は、ホストが測れるところ（Linux・macOS・Windows）では、ゲストのスレッドの
  最初のシステムコールからの、ホストのスレッドの CPU 時間（ユーザーとシステムの合計）
  です。WebAssembly などそれ以外では、代わりに経過時間を数えます。
  `CLOCK_THREAD_CPUTIME_ID` はそのスレッドの時間、`CLOCK_PROCESS_CPUTIME_ID` は
  プロセスのスレッドの合計（それぞれ最後のシステムコールの時点）を返します。子は 0 から
  始まり、待たれたときに親の「子の時間」に足されます。`getrusage`、`times`、`wait4` と
  `waitid` の rusage は、すべてをユーザーの時間として返します。システムコールのための
  エミュレータの処理も、ホストのユーザー空間で動くためです。`ru_maxrss` は、`VmHWM` と
  同じ常駐の大きさの最大値（KiB）です。プロセス（`RUSAGE_SELF`。`RUSAGE_THREAD` も同じ）
  では、アドレス空間のものと、`execve` で離れたアドレス空間や終了したときのアドレス空間の
  もののうち最大です。`RUSAGE_CHILDREN` では、待たれた子とその子たちのもののうち最大です。
  wait の rusage は、Linux の `RUSAGE_BOTH` と同じく、CPU 時間も `ru_maxrss` も、子のものと
  その子たちのものを合わせて返します。トレーサーがトレース先を待つときも同じです。fork した
  子は 0 から始まり、`execve` はどちらも保ちます。`ru_minflt` は、Linux の
  `mm_account_fault` がタスクに足すのと同じくマイナーフォールトを数えます。スレッドが
  ページを初めて読み書きしたとき、`fork` が共有したページやファイルのプライベートな
  マッピングのページに書いたとき（自身のコードでも、システムコールのコピーでも）と、
  `get_user_pages` がそのスレッドのために読み書きしてフォールトしたときです。後者は
  `perf` は数えません。`mlock` が取り込むとき、トレーサーの `PTRACE_PEEKDATA` と
  `PTRACE_POKEDATA`（トレーサーに数えます）、コアダンプ（一度も触れていない無名メモリは
  穴として残し、フォールトしません）です。`RUSAGE_SELF` はプロセスのスレッドの合計、
  `RUSAGE_THREAD` はそのスレッドのもの、`RUSAGE_CHILDREN` と wait は CPU 時間と同じく
  子のものです。fork した子は 0 から始まり、`execve` は保ちます。ほかの値
  （メジャーフォールト、コンテキストスイッチ、ブロック）は 0 です。

- 負の時計 ID は、Linux の `pid_for_clock` が分けるのと同じく、タスクの CPU 時計を指します。
  呼び出し元の PID 名前空間でのタスクの番号（`~id >> 3`。0 は呼び出し元）、スレッドの時計か
  （ビット 2）プロセスの時計か、下位 2 ビットの時間の種類（`CPUCLOCK_PROF`、
  `CPUCLOCK_VIRT`、`CPUCLOCK_SCHED`。ここではどれも同じ時間）です。`clock_gettime` は、
  どのプロセスの時計も（ゾンビのものも）、プロセスの時計として渡した呼び出し元自身の
  スレッドの番号も、呼び出し元のプロセスのスレッドの時計も読めます。`clock_getres` は、
  はじめの 2 種類にはティック（1 ms）、3 つめには 1 ns を返します。ほかのタスクのスレッド、
  プロセスの時計として渡したスレッドの番号（読むときの呼び出し元自身のものを除く）、
  ないタスク、4 つめの種類は `EINVAL` です。PTP デバイスのファイルが要る動的な時計
  （下位 3 ビットが `3`）も `EINVAL` です。時計 ID は、Linux のシステムコールと同じく
  `int` として受け取るので、上位 32 ビットは見ません。

- `clock_gettime` は、`CLOCK_MONOTONIC_RAW`、粗い時計、`CLOCK_BOOTTIME`（ホストは
  サスペンドしないものとします）、アラームの時計、`CLOCK_TAI`（TAI のずれは 0）も
  読めます。粗い時計は、Linux と同じく直近のティックの時刻を返し、`time` は
  `CLOCK_REALTIME_COARSE` の秒を返します。そのため、どちらも `CLOCK_REALTIME` や
  `gettimeofday` より最大 1 ティック遅れます。ティックはホストのもので、ホストの
  `CLOCK_MONOTONIC_COARSE` の分解能です（ホストが教えない macOS、Windows、WebAssembly では
  1 ms）。スケジューラの呼び出しも同じティックを使います。ここでは、ティックは
  単調時計でその倍数ちょうどに来て、Linux の時刻管理がティックごとに両方を更新するのと
  同じく、2 つの粗い時計は同じ瞬間に進みます。`clock_getres` は 1 ns、粗い時計では
  ティックの長さを返します。

- `clock_nanosleep` と `timer_create` は、`CLOCK_REALTIME`、`CLOCK_MONOTONIC`、
  `CLOCK_BOOTTIME`、`CLOCK_TAI`、プロセスの CPU 時計で動きます。`timer_create` は、
  スレッドの CPU 時計でも動きます。Linux と同じく、`CLOCK_MONOTONIC_RAW` と
  粗い時計は読むことしかできないので `EOPNOTSUPP` になり、スレッドの CPU 時計で眠る
  ときも `EOPNOTSUPP` です。`clock_nanosleep` は、`flags` のうち `TIMER_ABSTIME`
  しか見ません。アラームの時計でも動き、`CLOCK_REALTIME_ALARM` は実時間の時計、
  `CLOCK_BOOTTIME_ALARM` は単調時計で動きます。CI のランナーのようにマシンを起こせる
  RTC がある Linux の `alarmtimer.c` と同じく、`CAP_WAKE_ALARM` が要ります。眠る場合は、
  要求を読み、次に `TIMER_ABSTIME` 以外の `flags` を断り（`EINVAL`）、そのあとで
  ケーパビリティのない呼び出し元を断ります（`EPERM`）。`timer_create` は、断る前に
  タイマーの ID を書き出します。書き出せない場合（`EFAULT`）と同じく、その ID は
  使われたことになります。`timer_create` は、呼び出し元のプロセスとスレッドの CPU 時計を
  番号で指しても、ほかのプロセスの CPU 時計を番号で指しても動きます。ほかのプロセスの CPU
  時間でのタイマーは、Linux でそのプロセスのティックが満了させるのと同じく、設定されている
  間はそのプロセスのチェックポイントが満了させ、シグナルは作ったプロセスに届きます。その
  プロセスが回収されたあとは、設定すると `ESRCH` で、読んでも何も見えません。Linux の `posix_cpu_timer_create` と同じく ID を書き出したあとで
  タスクを探すので、ないタスクは `EINVAL` で、その ID は使われたことになります。動的な時計は
  タイマーを持てず、眠れもしません（`EOPNOTSUPP`）。番号で指した CPU 時計で眠る場合は、
  要求を読み、呼び出し元自身のスレッドの時計を断り（`EINVAL`）、次にないタスクを断ります
  （`EINVAL`）。そのあとは下に書くとおりに眠り、呼び出し元のプロセス、ほかのプロセス
  （ゾンビの時計は進みません）、呼び出し元のプロセスのほかのスレッドのどれかがその時間を
  使うまで待ちます。待つ間は、そのタスクのスレッドが CPU 時間を数えます。待つ間にタスクが
  いなくなると、眠りはシグナルを待ちます。そのシグナルでほかの眠りと同じく終わりますが、
  残りの時間には頼んだ時間をそのまま書き出します。Linux の `posix_cpu_timer_set` がタスクを
  見つけられないとき、`do_cpu_nanosleep` が頼まれた時間を書き出すのと同じです。停止の
  あとの再開では、タスクが見つからず `EINVAL` になります。

- プロセスの CPU 時計での眠りは、Linux の `do_cpu_nanosleep` と同じく、プロセスの
  スレッドが合わせてその時間を使うと終わります。過ぎた時刻や 0 の時間ならすぐに戻ります。
  眠っているスレッド自身は CPU 時間を使わないので、ほかに動くスレッドのないプロセスは
  シグナルが来るまで眠ります（CPU 時間を測れない WebAssembly では、眠っているスレッドの
  経過時間も数えます）。ハンドラのあるシグナルは `EINTR` で眠りを終わらせ、相対時間
  なら残りの時間を書き出します。ただし、そのときもう時間を使い終えていれば 0 を返します。
  停止からは、ほかの眠りと同じように再開します。

- プロセスの実時間のインターバルタイマー（`ITIMER_REAL`）は、Linux と同じく、満了すると
  `SIGALRM` を送り、間隔の分だけ次に進みます。`setitimer` はタイマーより先に新しい値を読んで
  確かめ、古い値はタイマーを設定してから書き出すので、古い値を書けないときはタイマーを設定した
  うえで `EFAULT` を返します。値が 0 なら止めて間隔も捨て、Linux の `KTIME_MAX` を超える値は
  そこで止めます。`getitimer` は Linux の `itimer_get_remtime` と同じく、残りの時間を
  マイクロ秒に切り捨てて返します。設定中で時間が来たタイマーは 1 µs、残りが 1 µs に満たない
  タイマーは 0 と見せます。`alarm` は Linux の `alarm_setitimer` と同じく、間隔なしの秒単位で
  設定し、残っていた秒数を四捨五入して返します（設定中だったなら少なくとも 1）。

- プロセスの CPU 時間のインターバルタイマー（`ITIMER_VIRTUAL` と `ITIMER_PROF`）は、Linux の
  `check_cpu_itimer` と同じく、プロセスのスレッドが合わせてその時間を使うと、カーネルから
  （`SI_KERNEL`）`SIGVTALRM` と `SIGPROF` を送ります。満了するたびに間隔ひとつ分だけ進み、
  新しい値は 1 ティック遅れて始まり、時間が来たタイマーは残り 1 ティックと見せます。値が 0
  なら止めますが間隔は残し、`KTIME_MAX` を超えて設定した値は、Linux の `ns_to_timespec64`
  と同じく負の秒数に見えます。`fork` の子はどちらも持たずに始まり、`execve` は引き継ぎます。
  CPU 時間は CPU の時計と同じく数えるので、それを測れない WebAssembly では経過時間を数えます。

- `CLOCK_REALTIME` での `adjtimex` と `clock_adjtime` は、時計の NTP の状態を読みます。
  ネイティブの Linux では実時間の時計はホストのものなので、状態もホストのものです。結果、
  ステータス、誤差、補正、ティック、TAI のオフセットを、ホスト自身の `adjtimex` が読むとおりに
  返します。それ以外（WebAssembly、macOS、Windows、またはその読み取りもサンドボックスが拒む
  ホスト）では、Linux が起動したときの状態です。
  同期しておらず（`STA_UNSYNC` なので結果は `TIME_ERROR`）、誤差は 16 秒、オフセットと
  周波数の補正はなく、時定数は 2、ティックは 10,000 µs、PPS と TAI のオフセットはありません。
  時刻は実時間の時計のもので、ステータスに `STA_NANO` があればナノ秒です。Linux と同じく
  モードを確かめたうえで、読むこと（モードなし、または adjtime の `ADJ_OFFSET_SS_READ`）
  だけを受けます。`adjtimex` は結果にかかわらず構造体を書き戻し、`clock_adjtime` は時計を
  見る前に構造体を読みます（ほかの時計は `EOPNOTSUPP`、知らない時計は `EINVAL`）。
  `settimeofday` と `clock_settime`（`CLOCK_REALTIME` だけで、ほかは `EINVAL`）は、Linux と
  同じく時刻を確かめ（`KTIME_MAX` の 30 年前より先は `EINVAL`）、そのうえで `EPERM` を
  返します。

- `sysinfo` は、空きが 4 GiB でスワップのない固定のメモリを返し、ホストのメモリは
  見せません。起動からの時間は単調時計の値で、Linux と同じく秒単位に切り上げます。

- `iopl` と `ioperm` は Linux と同じく引数を確かめ（3 を超えるレベルや、空の範囲、
  ポート 65,535 を越える範囲は `EINVAL`）、スレッドのレベル 0 を保つことと、持っていない
  ポートを手放すことは受け、それ以上はポートへのアクセスをロックダウンしたカーネルと同じく
  `EPERM` を返します。`acct` は `CAP_SYS_PACCT` を求め（`EPERM`）、そのうえで、いつも
  切れているアカウンティングを切ることは受け、ファイルには `EPERM` を返します。

- `syslog` が読むカーネルのログは空です。ログに書くものがないためです。Ubuntu の
  `kernel.dmesg_restrict` が 1 であるのと同じく、どの操作にも `CAP_SYSLOG` が要ります
  （`EPERM`）。そのあとは Linux の `do_syslog` と同じく、知らない操作と 1 から 8 の外の
  コンソールのレベルは `EINVAL` です。読む操作には、バッファと負でない長さ（`EINVAL`）、
  ユーザー空間の中のバッファ（`EFAULT`）が要ります。`SYSLOG_ACTION_READ` は来ることの
  ないメッセージを、シグナルが来るまで待ちます（`ERESTARTSYS`）。ほかの読む操作は何も
  写さず 0 を返します。バッファの大きさは 256 KiB（`CONFIG_LOG_BUF_SHIFT` が 18）で、
  未読のものはありません。

- `sysfs` はファイルシステムの種類に番号を付けます。種類は `tmpfs`、`proc`、`sockfs`、
  `pipefs`、`devpts`、`ext4`、`mqueue` で、paludarium が渡すファイルの種類（ホストの
  ファイルは `ext4`）を、Linux が登録する順に並べています。オプション 1 は名前の番号を、
  2 は番号の名前を、3 は種類の数を返します。知らないオプション、名前、番号は `EINVAL`
  で、`PATH_MAX` バイトのうちに終わらない名前も `EINVAL` です。

- セキュリティモジュールは paludarium にあるもので、Ubuntu の設定で Linux が始める順に、
  Lockdown（Ubuntu では early のモジュールで、paludarium はこれによってポートへの
  アクセスを断ります）、capability モジュール、Landlock、Yama です。`lsm_list_modules` はこれを並べます
  （バッファが小さければ、要る大きさを書いて `E2BIG`）。どれもタスクの属性を持たない
  ので、`lsm_get_self_attr` と `lsm_set_self_attr` は、引数が Linux の確認をその順に
  通ったあと `EOPNOTSUPP` を返します（大きさは 0 にします）。

- uprobe が置かれることはないので、プローブのトランポリンもありません。そのため、
  Linux でトランポリンの外から呼んだときと同じく、`uretprobe` は `SIGILL`（`SI_KERNEL`）
  を送って -1 を返し、`uprobe` は `EPROTO` を返します。

- 管理の syscall は、Linux master の確認をその順に行います。カーネルは、Ubuntu が
  Secure Boot のときと同じく integrity でロックダウンしています（`iopl` と `ioperm` が
  ポートへのアクセスを断るのもこのためです）。なので、カーネルにコードを読み込むことは
  できません。tmpfs と同じく、どのファイルシステムにもスワップとクォータはありません。
  - `reboot` には、呼び出し元の PID 名前空間を持つユーザー名前空間での `CAP_SYS_BOOT`
    （`EPERM`）と、Linux のマジックナンバー（`EINVAL`）が要ります。再起動
    （`LINUX_REBOOT_CMD_RESTART` か `RESTART2`）は名前空間の init を止め、init は
    `SIGHUP` で終わります。停止と電源断も同じで、init は `SIGINT` で終わります。これは
    Linux の `reboot_pid_ns` と同じで、呼んだスレッドは状態 0 で終わります。入れ子の
    PID 名前空間では、ほかのコマンドは `EINVAL` です。最初の名前空間では init は最初の
    プロセスなので、実行が終わります。`RESTART2` の文字列はその前に読みます（`EFAULT`）。
    最初の名前空間では、`CAD_ON` と `CAD_OFF` は成功し、`KEXEC` は読み込まれた
    カーネルがないので `EINVAL`、`SW_SUSPEND` はロックダウンしたカーネルを休止
    できないので `EPERM` です。
  - `swapon` はフラグ（`EINVAL`）と `CAP_SYS_ADMIN`（`EPERM`）を確かめ、パスを読み書き
    用に開き（その open のエラーを返します）、そのあと `EINVAL` を返します。tmpfs には
    スワップに要るページの読み込みがないためです。`swapoff` は `CAP_SYS_ADMIN` を確かめて
    パスを開き、スワップが使われていないので `EINVAL` を返します。
  - `init_module`、`finit_module`、`delete_module` には `CAP_SYS_MODULE` が要ります
    （`EPERM`）。`init_module` は ELF ヘッダーより短いイメージを断り（`ENOEXEC`）、
    イメージを読みます（`EFAULT`）。`finit_module` はフラグを確かめ（`EINVAL`）、
    Linux の `kernel_read_file` と同じくファイルを読みます（読むために開いていない
    ディスクリプタは `EBADF`、通常のファイルでないものと空のものは `EINVAL`）。その
    あと、`mod_check_sig` が断る署名はそのエラー（`EBADMSG`、`ENOPKG`）で、ほかの
    モジュールは `EPERM` です。署名を確かめられる鍵がなく、署名のないモジュールは
    ロックダウンが断るためです。`delete_module` は名前を読み（`EFAULT`）、モジュールが
    ないので `ENOENT` を返します。
  - `kexec_load` には `CAP_SYS_BOOT` が要り、そのあとロックダウンが断ります（どちらでも
    `EPERM`）。`kexec_file_load` には `CAP_SYS_BOOT`（`EPERM`）と知っているフラグ
    （`EINVAL`）が要ります。何も読み込まれていないので、`KEXEC_FILE_UNLOAD` は成功
    します。それ以外は、カーネルのファイルを `finit_module` と同じく読みます。4 GiB より
    上に置ける 64 ビットの bzImage でないものは `ENOEXEC`、そうであるものは確かめる鍵が
    ないので `EPERM` です。
  - `quotactl` はクォータの種類を確かめます（`EINVAL`）。デバイスを指定しないときは
    `Q_SYNC` が成功し、ほかは `ENODEV` です。デバイスのパスはそのエラーとともに探し、
    ブロックデバイスはないので `ENOTBLK` を返します。`quotactl_fd` はどのディスクリプタも
    受け付け（`EBADF`）、種類を確かめ（`EINVAL`）、クォータのないファイルシステムに
    対する Linux の `do_quotactl` と同じく `ENOSYS` を返します。

- `perf_event_open` は、Linux の `kernel/events/core.c` の順に引数を確かめます。知らない
  フラグ、次に構造体です（`perf_copy_attr`。サイズ 0 は最初の版の 64 バイトで、それより
  小さいか 1 ページより大きいと `E2BIG` になり、Linux master の知るサイズ 176 を書き戻します。
  それより大きくても、その先のバイトが 0 でなければ同じです。続いて予約フィールド、知らない
  サンプルと読み込みの形式、分岐のない分岐サンプリング、DS・ES・FS・GS や予約ビットを含む
  レジスタのマスク、大きすぎるか 8 バイト境界でないユーザースタック、両方の weight、
  `inherit` なしの `inherit_thread`、`enable_on_exec` と一緒の `remove_on_exec`、
  `remove_on_exec` なしの `sigtrap` がどれも `EINVAL` です）。次はマシンの
  `perf_event_paranoid`（root が `/proc/sys/kernel/perf_event_paranoid` に書くまでは
  Linux の既定の 2）です。1 より大きければカーネルのイベント（`exclude_kernel` なし、
  `text_poke`、カーネルのコールチェーン、物理アドレス、カーネルかハイパーバイザーの
  分岐）に、0 より大きければ CPU のイベントに、`CAP_PERFMON` か `CAP_SYS_ADMIN` が要ります
  （`EACCES`）。`namespaces` にはいつも要ります。そのあと、
  ビット 63 の立った周期や `perf_event_max_sample_rate`（最初は 100000）を超える周波数は `EINVAL`、
  CPU とタスクのない `PERF_FLAG_PID_CGROUP` は `EINVAL`、イベントでないグループの
  ディスクリプタは `EBADF`、ないタスクは `ESRCH`、タスクも CPU もないときや最後より先の
  CPU は `EINVAL`、知らない `clockid` は `EINVAL` です。数えるイベントは、ソフトウェアの
  `cpu-clock` と `task-clock`（スレッドの CPU 時間をナノ秒で。CPU のイベントは経った時間）、
  スレッドの `page-faults` と `minor-faults`（ページへの最初の読み書きと、`fork` で共有した
  ページやファイルのプライベートなマッピングへの書き込み。スレッドのコードのフォルトは
  `exclude_user` で、システムコールのコピーのフォルトは `exclude_kernel` で除きます）、
  `context-switches`（眠るたび）と `cpu-migrations`（`getcpu` の返す CPU が変わるたび）。
  後の二つはカーネルが起こすので、Linux と同じく `exclude_kernel` で除きます。すべての
  ページがメモリにあるので何も数えない `major-faults` と、x86-64 と同じく何も数えない
  `alignment-faults`、`emulation-faults`、`dummy`、`bpf-output` もあります。それらの
  分岐サンプリングや XMM レジスタは `EOPNOTSUPP` です。ハードウェア、
  キャッシュ、raw のイベントは、PMU のないマシンと同じく `ENOENT` です。ほかのプロセスの
  イベントには `CAP_PERFMON` か、それを読めること（`ptrace_may_access`、`EACCES`）が
  要ります。`read` は、読み込みの形式に従って、数に有効な時間と動いた時間、ID、失った
  サンプルを付けて返し、`PERF_FORMAT_GROUP` ではグループ全体を返します。バッファが
  小さすぎると `ENOSPC` です。グループのメンバーはリーダーと同じタスク、CPU、クロックで、
  pinned でも exclusive でもないこと（`EINVAL`）が要り、リーダーが有効な間だけ数えます。
  ioctl は `PERF_EVENT_IOC_ENABLE`、`DISABLE`、`RESET`（イベントか、`PERF_IOC_FLAG_GROUP`
  ならそのグループ）と `PERF_EVENT_IOC_ID` があり、サンプリングしないイベントでは `PERIOD`
  は `EINVAL` で、サンプリングするイベントには新しい周期（`freq` なら新しい頻度）を
  与え、周期は初めからになります。`REFRESH` は、サンプリングしないか、新しい
  タスクが引き継ぐイベントでは `EINVAL` で、そうでなければその数だけオーバーフローを
  許してイベントを有効にします（`event_limit`）。その最後でイベントは無効になり、
  `POLL_HUP` を知らせます。`enable_on_exec` は、`perf stat` が使うように、無効な
  イベントをそのタスクの `execve` で有効にし、`remove_on_exec` は、Linux master と同じく、そのとき
  イベントを以後ずっと取り除きます。イベントは数えなくなり、最後の数と時間は読めるまま残り、
  持ち主がなくなり、グループを離れます。それがグループを率いていたなら、メンバーはそれぞれで
  数えます。そうしたイベントは新しいグループを率いられません（`ENODEV`）。`execve` なしで
  終わったスレッドは、開いたイベントの持ち主でなくなります（`perf_event_exit_task`）。それを
  数えるイベントは Linux の `EXIT` の状態になり、数えなくなり、最後の数と時間は読めるまま残り、
  グループに残り、新しいグループを率いられません（`ENODEV`）。`inherit` があると、
  `perf_event_init_task` と同じく、新しいスレッドかプロセスは、それを作ったスレッドを数える
  グループを引き継ぎます。その一つ一つのイベントが、新しいタスクを数える自分のものを得て、
  元のものと同じく有効か無効になります。`inherit_thread` は新しいプロセスには、`sigtrap` は
  `CLONE_CLEAR_SIGHAND` では引き継がせません。開いたイベントの読み込みは、引き継いだ
  イベントと、終わったタスクのものが返したものを、数と時間に加えます。グループではメンバー
  ごとです（タスクが引き継いだあとでメンバーが変わったグループは `ECHILD`）。その `ENABLE`、
  `DISABLE`、`RESET`（終わったタスクが返したものは残します）と下の `prctl` は、引き継いだ
  イベントにも及びます。
  `prctl` の `PR_TASK_PERF_EVENTS_DISABLE` と `ENABLE` は、
  呼んだスレッドが開いたすべてのイベントを、どのタスクを数えるものでも（無効で開いたものも）
  無効または有効にし、ほかの引数は読みません。`execve` を実行したスレッドは、開いたイベントを
  そのまま持ちます。`sample_simd_regs_enabled` があると、Linux master の構造体の SIMD
  レジスタのフィールドを、x86 の `perf_simd_reg_validate` と同じく確かめます（`EINVAL`）。
  XMM か YMM（2 か 4 クワッドワード）は 16 個すべて、ZMM（8）は 32 個すべて、opmask（1）は
  8 個すべてか、どれもないかです。正しく使っても、ソフトウェアのイベントは取らないので
  `EOPNOTSUPP` です。イベントの `mmap` は、Linux の `perf_mmap` と同じく
  リングバッファをマップします。共有のマッピング（`EINVAL`）で、ユーザーページと 2 の
  べき乗の数のデータページ、またはデータページなし（`EINVAL`）です。新しいタスクが
  引き継ぐ、すべての CPU のイベントはマップできません（`EINVAL`）。最初のマッピングが
  バッファを作り、後のマッピングは同じ大きさでなければならず（`EINVAL`）、それを
  共有します。バッファより先のオフセットは AUX 領域を求めます。AUX 領域はユーザー
  ページの `aux_offset` と `aux_size` の示す、データページより先の場所にあり、2 の
  べき乗のページ数でなければなりません（`EINVAL`）。ソフトウェアのイベントには
  ありません（`EOPNOTSUPP`）。ページは、CPU ごとに `perf_event_mlock_kb` まで
  マッピングのユーザーに課され、残りはアドレス空間の固定したページに課されます。
  後者は、`perf_event_paranoid` が -1 か、呼び出し元が `CAP_IPC_LOCK` を持つので
  なければ、`RLIMIT_MEMLOCK` を超えられません（`EPERM`）。後のマッピングも、Linux
  master と同じくユーザーに課され、返されません。マッピングは `fork` した子に写されず、
  コアダンプにも含まれず（`VM_DONTCOPY`、`VM_DONTDUMP`）、ディスクリプタが閉じられても
  イベントを数え続けさせます。最後にアンマップされると、バッファと課したものは
  なくなります。ユーザーページは `struct perf_event_mmap_page` で、バージョン 0、
  `size` 96、データのオフセットと大きさ、`cap_bit0_is_deprecated` があり
  `cap_user_rdpmc` はなく、インデックス 0、そしてシーケンスロックの 2 回の増加の間に
  数と有効な時間と動いた時間があります。`PERF_EVENT_IOC_SET_OUTPUT` と、開くときに
  グループのディスクリプタで指す `PERF_FLAG_FD_OUTPUT` は、Linux の
  `perf_event_set_output` と同じく、イベントの出力をほかのイベントのバッファへ向けます。
  相手はイベントで（`EBADF`）、同じイベントではなく、同じ CPU の、すべての CPU の
  イベントなら同じタスクのもので、時計と `write_backward` が同じで、自分のものか
  書き込み先のバッファを持たなければなりません。イベント自身のバッファをマップして
  いるときも断ります（`EINVAL`）。-1（`SET_OUTPUT` だけ）は出力先をなくします。こうした
  イベントはユーザーページを共有しますが、マップすると `EBUSY`（大きさが違えば
  `EINVAL`）で、バッファの最後のマッピングがなくなると、書き込んでいたイベントは
  どれも自由になります。サンプリングするイベントは、Linux の `perf_swevent_event` と
  `perf_swevent_hrtimer` と同じく、オーバーフローのたびに `PERF_RECORD_SAMPLE` を
  バッファへ書きます。`sample_period` 回ごと、`PERF_SAMPLE_PERIOD` ならそれぞれ（周期 1）、
  `cpu-clock` と `task-clock` は数えたナノ秒の周期ごとで、少なくとも 10 µs ごとです。
  `freq` では、クロックの周期は 1 秒を頻度で割ったもので、ほかのイベントの周期は 1 から
  始まり、数える速さへ 8 分の 1 ずつ近づきます（`perf_adjust_period`）。サンプルは
  `sample_type` の求めるフィールドを `perf_output_sample` の順に持ちます。識別子、
  アドレス、開いたタスクの PID 名前空間でのプロセスとスレッド、イベントの時計での時刻、
  ID とストリーム ID、CPU、周期、`PERF_SAMPLE_READ` の読む値（`PERF_FORMAT_GROUP`
  ならグループのもの）、コールチェーン（`PERF_CONTEXT_USER`、アドレス、`rbp` の
  連なりがたどる戻りアドレスで、`sample_max_stack` まで。0 なら `perf_event_max_stack`
  （127）で、それより多いと `EOVERFLOW`）、空の raw データ、マスクのユーザーレジスタ、
  ページがメモリにある限りのユーザースタックの写し、そして残りはソフトウェアイベントの
  とおりです（重みなし、データソースは `PERF_MEM_NA`、ルートの cgroup）。記録は読み手が
  空けたところ（`data_tail`）まで、前へ、`write_backward` なら 0 から後ろへ書かれます。
  入らない記録は失われて数えられ、次に入る記録の前に、それらの数の `PERF_RECORD_LOST`
  が、`sample_id_all` の足す `sample_id` を付けて書かれます。読み取り専用でマップした
  バッファは中身を上書きし、何も失いません。`PERF_EVENT_IOC_PAUSE_OUTPUT` はバッファを
  止め、また動かし（バッファがないか、データページがなければ `EINVAL`）、止まっている
  バッファは受け取らない記録を失ったものと数えます。引き継いだイベントは、元のイベントの
  バッファへ書きます。`wakeup_events` 回のサンプルごと、`watermark` なら
  `wakeup_watermark` バイトごと（ないときはデータの半分）に、バッファは `poll` や
  `epoll` で待つものを起こします。そのとき一度だけ読める（`POLLIN`）ようになり、
  `perf_poll` が起こされた状態を取るので、次まではまた読めません。バッファのない
  イベントと、タスクが終わり引き継いだイベントも残っていないイベントは、切れています
  （`POLLHUP`）。`O_ASYNC` では、オーバーフローのたびに、バッファがあってもなくても、
  ファイルの持ち主（`F_SETOWN`）へ `POLL_IN` を知らせ、`F_SETSIG` のシグナルは
  `si_code`、`si_band`、`si_fd` を持ちます。`sigtrap` では、オーバーフローはスレッドに
  `TRAP_PERF` の SIGTRAP を送り、`si_perf_data` と `si_perf_type` に `sig_data` と
  イベントの型を、スレッドがそれをブロックしていれば `TRAP_PERF_FLAG_ASYNC` を
  持たせます。それを求めるタスクのイベントは、`perf_iterate_sb` が記録を作るスレッドを
  数える有効なイベントへ渡すように、サイドバンドの記録を、そのスレッドの `sample_id` を
  付けて受け取ります。実行できるマッピングの `PERF_RECORD_MMAP`（`mmap`）か
  `MMAP2`（`mmap2`）と、`mmap_data` ではほかのマッピングのもの
  （`PERF_RECORD_MISC_MMAP_DATA`）を、`mmap`、`brk` が伸ばしたとき、`shmat`、
  `remap_file_pages`、`mprotect`（保護を変えた VMA ごと）が残した、隣と合わさった
  VMA について書きます。アドレス、長さ、オフセット（ファイルのもの、プライベートな
  無名メモリーではアドレス）を、`MMAP2` ではさらにファイルのデバイスと inode、保護と
  共有、`d_path` が与える名前（`[heap]`、`[stack]`、`//anon`、共有の無名メモリーでは
  `/dev/zero (deleted)`）を持ちます。`PERF_RECORD_COMM`（`comm`）は `PR_SET_NAME`、
  `/proc/<pid>/comm` への書き込み（書き込んだスレッドを数えるイベントへ、名前を変えた
  スレッドのものを）、`execve`（`PERF_RECORD_MISC_COMM_EXEC`）で書き、`execve` はそのあと新しい
  プログラムのスタックとマッピングを書きます。`PERF_RECORD_FORK` と `EXIT`
  （`task`、またはほかのどれか）は、スレッドが作られたときと終わったときに書きます。
  `cpu-clock` と `task-clock` のイベントは、ティックの割り込みが
  `perf_event_max_sample_rate` を `HZ` で割った数に届くと次のティックまで抑えられ、
  そのあいだは数えません。グループのリーダーの `PERF_RECORD_THROTTLE` と `UNTHROTTLE`
  （時刻、ID、`stream_id`）を書きます。
  ディスクリプタのリンクは
  `anon_inode:[perf_event]` で、読み書きで開かれ、書き込みは `EINVAL` です。ないものは
  [制限](./limitations) を参照してください。

- `bpf` は、Linux の `kernel/bpf/syscall.c`、`arraymap.c`、`hashtab.c`、`bpf_lru_list.c`、
  `lpm_trie.c`、`queue_stack_maps.c`、`bloom_filter.c` と同じくマップを持ちます。どのコマンドも、まず union のサイズ（1 ページより大きいか、Linux master の 168
  バイトより先に 0 でないバイトがあれば `E2BIG`）と、コマンド自身のフィールドより先
  （`CHECK_ATTR`、`EINVAL`）を確かめます。`BPF_MAP_CREATE` は `BPF_MAP_TYPE_ARRAY`
  （4 バイトのキーで、どの要素も初めからあって 0）か `BPF_MAP_TYPE_HASH` を、Linux の検査の
  順に作ります。BTF の型 ID、`map_extra`、NUMA ノード（一つです）、型、型ごとのサイズと
  フラグ（`EINVAL`。大きすぎるハッシュの要素は `E2BIG`、`CAP_SYS_ADMIN` なしの
  `BPF_F_ZERO_SEED` は `EPERM`）、マシンの `kernel.unprivileged_bpf_disabled`
  （root が書くまでは Linux の既定の 2。0 でなければマップには `CAP_BPF` か
  `CAP_SYS_ADMIN` が要ります、`EPERM`）、名前（英数字、`_`、`.`）、
  BTF（どのファイルも BTF ではありません、`EINVAL`）、`BPF_F_RDONLY` と `BPF_F_WRONLY` の
  両方（`EINVAL`）の順です。ディスクリプタは close-on-exec で、`BPF_F_RDONLY` と
  `BPF_F_WRONLY` に従って読み込み、書き込み、その両方で開かれ、リンクは
  `anon_inode:bpf-map`、読み書きは `EINVAL` です。`BPF_MAP_LOOKUP_ELEM`、`UPDATE_ELEM`
  （`BPF_ANY`、`BPF_NOEXIST`、`BPF_EXIST`。いっぱいのハッシュと配列の終わりより先の
  添字は `E2BIG`）、`DELETE_ELEM`（配列では `EINVAL`）、`GET_NEXT_KEY`、
  `LOOKUP_AND_DELETE_ELEM`（配列ではカーネルの `ENOTSUPP`、524）、`BPF_MAP_FREEZE`
  （どのディスクリプタからの書き込みも止めるので、2 回目も `EPERM`）は、ディスクリプタのアクセスを
  要ります（`EPERM`）。バッチのコマンドは、数を指定して検索、更新、削除、検索して削除を行い、
  `count` を書き戻します（配列は削除できません、`ENOTSUPP`）。`BPF_OBJ_GET_INFO_BY_FD` は
  マップの `struct bpf_map_info` を求められた長さまで返します（ディスクリプタがなければ
  `EBADFD`、マップでなければ `EINVAL`）。どのマップにもマシンの ID があり、Linux の
  `idr_alloc_cyclic` と同じく 1 から順に渡され、マップの最後の参照がなくなると空きます。
  `BPF_MAP_GET_NEXT_ID` は `start_id` より後の最初の ID を返し（最後より後は `ENOENT`、
  `INT_MAX` からは `EINVAL`）、`BPF_MAP_GET_FD_BY_ID` はマップの新しい close-on-exec の
  ディスクリプタを `open_flags`（`BPF_F_RDONLY` か `BPF_F_WRONLY`）に従って開きます
  （どのマップの ID でもなければ `ENOENT`）。どちらも、フィールドを確かめた（`EINVAL`）あとで
  `CAP_SYS_ADMIN` が要ります（`EPERM`）。マップが取るメモリは、x86-64 のテストのマシンの
  カーネル（Ubuntu の Linux 7.0）が x86-64 で与えるものです。配列は 312 バイトの
  ヘッダーと、8 バイトに切り上げたすべての値です（マップできるものはそれぞれをページに揃えます）。ハッシュは
  896 バイトのヘッダー、バケット一つに 16 バイト（`max_entries` を 2 のべき乗に切り上げた数。
  2^31 を超えるエントリや 4 GiB を超えるバケットは `E2BIG`）と要素で、要素は 48 バイトと、
  それぞれ 8 バイトに切り上げたキーと値です。事前に確保するものはすべての要素と CPU ごとに
  予備を一つ、それを指す CPU ごとの 8 バイトを、`BPF_F_NO_PREALLOC` では持っている要素と
  一つにつき 8 バイトを数えます。そのメモリがマシンのメモリ（`sysinfo` の 4 GiB）を、
  `vmalloc` と同じ確かめ方で超えるマップは `ENOMEM` です。fdinfo には `map_type`、
  `key_size`、`value_size`、`max_entries`、`map_flags`、`map_extra`、`memlock`
  （そのメモリ）、`map_id`、`frozen` があります。`BPF_MAP_TYPE_LRU_HASH` は、いっぱいに
  なると `E2BIG` にせず、新しいキーのために一つのキーを手放すハッシュで、手放すキーは Linux の
  `bpf_lru_list.c` と同じ選び方です。要素は空き、active、inactive のリストと、CPU の
  ローカルな空きと保留のリストのあいだを動くので、手放すキーは、更新が拒まれたときや
  キーを置き換えたとき（どちらも先に要素を取ります）も Linux と同じです。どのユーザーでも
  マップを作れる設定でも `CAP_BPF` が要り（`EPERM`）、いつも事前に確保され
  （`BPF_F_NO_PREALLOC` は `ENOTSUPP`）、`BPF_F_NO_COMMON_LRU` では CPU ごとにリストを持ちます
  （`max_entries` を CPU の数の倍数に切り上げ、どの CPU も同じ数です。`BPF_F_NUMA_NODE` と
  一緒なら `EINVAL`）。メモリは予備のない要素だけを数えます。`BPF_MAP_TYPE_QUEUE` と
  `BPF_MAP_TYPE_STACK` は、Linux の `queue_stack_maps.c` と同じく、キーのない値を持ちます
  （`key_size` は 0 で、null でないキーのポインタは `EINVAL`）。`UPDATE_ELEM` は積み
  （いっぱいなら `E2BIG`。`BPF_EXIST` ならいちばん古い値を手放して場所を空けます。
  `BPF_NOEXIST` は `EINVAL`）、`LOOKUP_ELEM` は見るだけ、`LOOKUP_AND_DELETE_ELEM` は
  取り出します。キューはいちばん古い値を、スタックはいちばん新しい値を返します（なければ
  `ENOENT`）。`DELETE_ELEM` と `GET_NEXT_KEY` は `EINVAL`、バッチのコマンドは
  `ENOTSUPP` です。`CAP_BPF` が要り、フラグは `BPF_F_NUMA_NODE` とアクセスのものだけで、
  4 MiB を超える値と、`max_entries` と値の大きさの積が 32 ビットを超えるものは、Linux
  master と同じく `E2BIG` です。312 バイトのヘッダーと `max_entries + 1` 個の値の場所を
  取ります。`BPF_MAP_TYPE_BLOOM_FILTER` も、Linux の `bloom_filter.c` と同じく、キーのない
  値を取ります。`UPDATE_ELEM`（`BPF_ANY` だけ）はハッシュごとにビットを立て（ハッシュの数は
  `map_extra` の下位 4 ビットで、0 なら 5。それより上のビットは `EINVAL`）、`LOOKUP_ELEM`
  は値を読んで、どのビットも立っているかを答えます（そうでなければ `ENOENT`。何も書き
  戻しません）。ハッシュは、値がワードの並びなら Linux の `jhash2`、そうでなければ
  `jhash` で、シードはランダムか、`BPF_F_ZERO_SEED` なら 0 です。そのため、0 のシードの
  フィルタは Linux と同じ偽陽性を返します。ビットの数は `max_entries` とハッシュの数の積の
  7 / 5 倍を、64 以上の 2 のべき乗にしたものです（2^31 を超えれば 2^32）。`DELETE_ELEM` と
  `GET_NEXT_KEY` は `EOPNOTSUPP`、`LOOKUP_AND_DELETE_ELEM` とバッチのコマンドは
  `ENOTSUPP` です。`CAP_BPF` が要り、312 バイトのヘッダーと、8 バイトのワードにした
  ビットを取ります。`map_extra` は fdinfo と `bpf_map_info` に出ます。
  `BPF_MAP_TYPE_LPM_TRIE` は、Linux の `lpm_trie.c` と同じくプレフィックスを持ちます。キーは
  プレフィックスの長さ（`u32`）と、上位のバイトから並べた 1 から 256 バイトのデータで、
  `LOOKUP_ELEM` はキーを含むいちばん長いプレフィックスの値を返します（なければ `ENOENT`。
  データのビット数を超えるプレフィックスの長さも `ENOENT`）。ノードは Linux と同じで、二つの
  プレフィックスが分かれるところに中間のノードがあります。そのため `GET_NEXT_KEY` は、
  Linux と同じ後行順で、より細かいプレフィックスを先にキーを返します（キーがないとき、
  データのビット数を超えるプレフィックスの長さのとき、どの要素のキーでもないときは最初から
  返します）。どのキーも、プレフィックスより後ろのバイトは最後の更新で与えられたものです。
  `UPDATE_ELEM` は `BPF_ANY`、`BPF_NOEXIST`、`BPF_EXIST` を取り（ほかのフラグとデータの
  ビット数を超えるプレフィックスの長さは `EINVAL`、いっぱいなら `ENOSPC`）、`DELETE_ELEM` は
  同じプレフィックスを消し（なければ `ENOENT`）、`LOOKUP_AND_DELETE_ELEM` とそのバッチは
  `ENOTSUPP` で、ほかのバッチのコマンドは次のキーをたどります。`CAP_BPF` と
  `BPF_F_NO_PREALLOC` が要り、フラグはそれと `BPF_F_NUMA_NODE` とアクセスのものだけで、
  値は 1 バイトから 4 MiB より 280 バイト小さい大きさまでです（`EINVAL`）。メモリは要素ごとに
  24 バイトとデータと値で、ヘッダーと中間のノードは数えません。
  `BPF_MAP_TYPE_ARRAY_OF_MAPS` と `BPF_MAP_TYPE_HASH_OF_MAPS` は、Linux の `map_in_map.c` と
  同じくほかのマップを持ちます。値は 4 バイトのディスクリプタで（ほかの大きさは `EINVAL`）、
  `inner_map_fd` のマップが、持つマップの手本になります（ディスクリプタがなければ `EBADF`、
  マップでなければ `EINVAL`、マップのマップは一段だけなので `EINVAL`）。型、キーと値の大きさ、
  フラグが手本と同じマップが合い、配列は、手本に `BPF_F_INNER_MAP` がなければ要素の数も
  同じでなければなりません（合わなければ `EINVAL`）。`UPDATE_ELEM` はそのようなマップの
  ディスクリプタを取り、`LOOKUP_ELEM` は要素が持つマップの ID を返します。外側のマップは、
  ディスクリプタが閉じたあとも、消されるか置き換えられるまでマップを持ち続けます。
  マップの配列は `BPF_ANY` だけを取り（ディスクリプタを見る前に `EINVAL`）、インデックスは
  `max_entries` より小さくなければなりません（`E2BIG`）。マップを持たないインデックスは
  `ENOENT` で、次のキーは配列と同じです。バッチの検索はマップを持たないインデックスを飛ばし、
  バッチの削除はありません（`ENOTSUPP`）。`BPF_F_RDONLY_PROG`、`BPF_F_WRONLY_PROG`、
  `BPF_F_MMAPABLE`、`BPF_F_INNER_MAP` は取りません（`EINVAL`）。マップのハッシュは、
  フラグより先にディスクリプタを見ます。フラグはハッシュと同じです。ハッシュのバッチの
  コマンドを持ちますが `LOOKUP_AND_DELETE_ELEM` はなく（`ENOTSUPP`）、事前に確保するときも
  予備の要素は数えません。どちらも `CAP_BPF` は要りません。`excl_prog_hash` を付けて作った
  マップは、Linux master と同じく、どのマップの内側のマップにもなりません（`ENOTSUPP`）。
  テストのマシンの Linux 7.0 は受け入れます。`BPF_F_RDONLY` と `BPF_F_WRONLY` はマップではなく
  ディスクリプタのものなので、Linux の `bpf_map_flags_retain_permanent` と同じく、
  `map_flags`（fdinfo、`bpf_map_info`、手本）には入りません。ないものは
  [制限](./limitations) を参照してください。

- `BPF_PROG_LOAD` はソケットフィルター（`BPF_PROG_TYPE_SOCKET_FILTER`）を読み込み、
  Linux と同じく検証器で確かめます。アタッチした AF_UNIX のソケットで、インタープリタが
  動かします（下を参照）。引数は Linux の
  `bpf_prog_load` と同じく、master の順に同じエラーで確かめます。最初はログの引数です
  （サイズのないバッファとバッファのないサイズ、レベルのないバッファ、知らないレベルは
  `EINVAL`。テストのマシンのカーネル、Ubuntu の Linux 7.0 は検証器を始めるときに確かめます）。
  続いて、コマンドより先のフィールド（`EINVAL`）、プログラムのフラグ（`EINVAL`）、トークンの
  ディスクリプタ（ないものは `EBADF`、ほかのファイルは `EINVAL`。ここにトークンはありません）、
  `CAP_BPF` のないときの `kernel.unprivileged_bpf_disabled`（`EPERM`）、命令の数（0 か、
  `CAP_BPF` なしで 4096、ありで 1,000,000 を超えると `E2BIG`）、ソケットフィルターと cgroup
  skb 以外の型の `CAP_BPF`、それを求める型の `CAP_NET_ADMIN` と `CAP_PERFMON`（`EPERM`。
  どれも `CAP_SYS_ADMIN` で代えられます）、アタッチ先のプログラムか BTF ID、または master の
  複数の関数にアタッチする型（ここではどの型も `EINVAL`）、命令とライセンスの読み込み
  （`EFAULT`）、結び付けるデバイス（`EINVAL`）、そして型です。ソケットフィルター以外の型は、
  それを組み込まずにビルドしたカーネルと同じく `EINVAL` です。名前は、マップと同じく最後に
  確かめます（`EINVAL`）。

- 検証器（`kernel/bpf/verifier.c`）は、テストが知る二つのカーネル、master と 7.0 の
  どちらも受け入れるプログラムだけを受け入れ、どちらかが断るものは断ります。最初に構造を
  master の順に確かめます。どれも `EINVAL` です。最後の命令が `BPF_LD_IMM64` の半分でないこと、
  ジャンプがプログラムの中に収まり（"jump out of range from insn %d to %d"）、最後の命令が
  exit かジャンプであること、命令ごとのレジスタ、オペコード（"unknown opcode %02x"）、
  予約フィールド（クラスごとの "... uses reserved fields"）、`BPF_LD_IMM64` の後半、そして
  命令のあいだの辺です。どの命令にも届き（"unreachable insn %d"）、`BPF_LD_IMM64` の
  途中へのジャンプがないことを確かめます。そのあと、最初の命令からのすべての道を、各レジスタの
  中身（R1 はコンテキスト、R10 はフレームポインタ、ほかはまだ何もない）と 512 バイトの
  スタックとともにたどります。書く前に読んだレジスタ（"R%d !read_ok"、`EACCES`）、
  フレームポインタへの書き込み、即値 0 での割り算と幅を超えるシフト（`EINVAL`）、
  Linux が許すポインタの演算（スタックかコンテキストのポインタへのオフセットの足し算、
  ポインタからポインタの引き算、32 ビットの引き算。スタックのポインタからの引き算、ほかの
  演算子、32 ビットの足し算は `EACCES`。2^29 を超えるオフセットは `EINVAL`）、スタックへの
  読み書き（大きさに揃っていて 512 バイトに収まること、`EACCES`）、スタックにまるごと書いて
  まるごと読むポインタ、スカラーを通した読み込み（"R%d invalid mem access 'scalar'"、
  `EACCES`）、exit のときの R0（値は何でもかまいません）です。オペランドを知っている
  条件ジャンプは一方へだけ進み、ほかは両方をたどります。Linux と同じく、1,000,000 命令か、
  たどるのを待つジャンプが 8,192 個を超えるとあきらめます（`E2BIG`）。

- プログラムは、Linux の検証器が許すとおりにマップを使えます。マップのディスクリプタの
  `BPF_LD_IMM64`（`BPF_PSEUDO_MAP_FD`）はマップを、その値の `BPF_LD_IMM64`
  （`BPF_PSEUDO_MAP_VALUE`）は要素が一つの配列の値へのポインタを与えます。マップでない
  ディスクリプタは `EBADF` か `EINVAL`（"fd %d is not pointing to valid bpf_map"）、ほかの型の
  値は `EINVAL`、要素が二つ以上の配列の値は `ENOTSUPP`、値の先は `EINVAL` です。同じマップを
  二度名指しても一つで、一つのプログラムが使えるのは 64 個までです（`E2BIG`）。呼べるのは
  `bpf_map_lookup_elem`、`bpf_map_update_elem`、`bpf_map_delete_elem` で、R1 にマップ
  （"R1 type=%s expected=map_ptr"、`EACCES`）、キーと値はスタックかマップの値に、その大きさに
  収まるように置きます。呼び出しのあと R1 から R5 はなくなり、R0 が結果です。
  `BPF_F_RDONLY_PROG` を付けて作ったマップの更新と削除は "write into map forbidden"
  （`EACCES`）です。検索の結果は null かもしれません。64 ビットの `BPF_JEQ` か `BPF_JNE` で
  0 と比べるまで、それを通した読み書きもオフセットの足し算もできません。比べると、その結果と、レジスタや
  スタックにあるそのすべての写しが、一方では値へのポインタ、もう一方では 0 になります
  （"R%d invalid mem access 'map_value_or_null'"、`EACCES`）。値の読み書きはその大きさに
  収まり（"invalid access to map value"、`EACCES`）、マップが `BPF_F_RDONLY_PROG` なら書けず、
  `BPF_F_WRONLY_PROG` なら読めません（`EACCES`）。プログラムは使うマップを持ち続けます。

- コンテキストは、プログラムが始まるときの R1 で、パケットの `struct __sk_buff` です。
  Linux がソケットフィルターに許すとおりに読み書きできます。4 バイトのフィールドは、
  まるごとか、その大きさの倍数のオフセットでより狭く読めます。`cb[0]` から `cb[4]` は、
  その中に収まればどの大きさでも読み書きでき、ほかは書けません。`data`、`data_end`、
  `data_meta`、`tc_classid`、ソケットのアドレスとポート、`tstamp`、`wire_len`、`hwtstamp`、
  `flow_keys` はソケットフィルターのものではありません（"invalid bpf_context access off=%d
  size=%d"、`EACCES`）。読み書きやヘルパーへの受け渡しに使えるのは、受け取ったままの
  コンテキストだけです（"dereference of modified ctx ptr R%d off=%d disallowed"、`EACCES`）。
  ある経路でコンテキストを通して読み書きする命令は、別の経路でほかのポインタを通しては
  使えません（"same insn cannot be used with different pointers"、`EINVAL`）。マップの
  ヘルパーのほかに呼べるのは次のものです。`bpf_skb_load_bytes` と
  `bpf_skb_load_bytes_relative` には、コンテキスト、オフセット、スタックか書き込めるマップの
  値にあるバッファ、そしてその大きさを渡します。大きさは 1 から 2^29 - 1 の定数で、バッファに
  収まらなければなりません（どれも Linux の行で `EACCES`、フレームの先に出るバッファは
  `EINVAL`）。`bpf_get_socket_cookie` と `bpf_get_socket_uid` にはコンテキストを、
  `bpf_get_netns_cookie` にはコンテキストか 0 を渡します（"R1 type=%s expected=ctx"、
  `EACCES`）。引数のないヘルパーは、`bpf_ktime_get_ns`、`bpf_ktime_get_boot_ns`、
  `bpf_ktime_get_coarse_ns`、`bpf_ktime_get_tai_ns`、`bpf_get_prandom_u32`、
  `bpf_get_smp_processor_id`、`bpf_get_numa_node_id`、`bpf_get_current_pid_tgid`、
  `bpf_get_current_uid_gid` です。ソケットフィルターが呼べないヘルパーは "program of this
  type cannot use helper %s#%d"、ヘルパーでない番号は "invalid func %s#%d" です（`EINVAL`）。

- ソケットフィルターは `SO_ATTACH_BPF` で AF_UNIX の `SOCK_DGRAM` か `SOCK_SEQPACKET` の
  ソケットにアタッチし、送られてくるメッセージごとに、Linux の `sk_filter` と
  `unix_dgram_sendmsg` と同じく動きます。送り手自身のシャットダウンと送信バッファの確認の
  後、受け手の確認の前に、メッセージをどうするか決めます。0 なら捨て、それでも送信は長さを
  返します。それ以外の値なら、その数のバイトを残します。インタープリタは、Linux の
  `___bpf_prog_run` が検証器の書き換えの後に動かすのと同じくプログラムを動かします。0 の
  レジスタによる除算は 0 で、剰余は被除数のままです。-1 による符号付き除算は符号を反転し、
  符号付き剰余は 0 です。コンテキストはメッセージの `__sk_buff` です。`len`、0 から始まる
  `cb[]` があり、AF_UNIX のメッセージが設定しないフィールドは 0 です。
  `bpf_skb_load_bytes` はメッセージを読み、相対形はネットワークヘッダ（メッセージの先頭）
  から読みます。MAC ヘッダはありません（`EFAULT`）。プログラムが更新するマップは、
  ユーザー空間が読むものと同じです。
  - `SO_ATTACH_BPF` は 4 バイトの記述子を取ります（ほかの大きさは `EINVAL`）。記述子が
    なければ `EBADF`、ソケットフィルターでなければ `EINVAL` です。新しいフィルターは古い
    ものに置き換わります。
  - `SO_DETACH_FILTER`（`SO_DETACH_BPF`）はフィルターを外します。ないときは `ENOENT` です。
  - `SO_LOCK_FILTER` は、ソケットがなくなるまでフィルターを今のままにします（`EPERM`）。
    ロックは外せません。
  - `SO_GET_FILTER` は、フィルターがなければ 0 ブロック、`SO_ATTACH_BPF` でアタッチした
    ものには `EACCES` を返します。
  - `SO_BPF_EXTENSIONS` は 64（`SKF_AD_MAX`）を返します。

- ログ（`log_level`、`log_buf`、`log_size`）には、プログラムを断った理由の行（二つの
  カーネルで言い方が違うときは 7.0 の言い方）と "processed %d insns" の行を、固定
  （`BPF_LOG_FIXED`）か回転するバッファに書きます。小さすぎるログは `ENOSPC`、書けないログは
  `EFAULT` で、読み込みの結果に代わります。`log_true_size` はログの長さです。読み込んだ
  プログラムは `anon_inode:bpf-prog` の close-on-exec のディスクリプタです。その fdinfo は、
  型、タグ（Linux の `bpf_prog_calc_tag` と同じく、マップのディスクリプタを除いた命令の
  SHA-256 の先頭 8 バイト）、メモリ（96 バイトのヘッダーと命令をページで）、ID（マップとは
  別のプログラムの ID）、検証器が通った命令の数を示します。`prog_jited` と実行の統計は 0 です。
  Linux が受け入れるのに検証器が断るものは [制限](./limitations) を参照してください。

- timerfd は `CLOCK_REALTIME` か `CLOCK_MONOTONIC` で動き（`CLOCK_BOOTTIME` は
  `CLOCK_MONOTONIC` として扱います）、絶対時刻と周期の指定ができます。読むと前回からの
  満了の回数を返し、満了すると `poll` と `epoll` から読めるように見えます。
  `TFD_TIMER_CANCEL_ON_SET` は受け付けますが、ゲストは時計を設定できないので取り消しは
  起きません。アラームの時計は `CLOCK_REALTIME` と `CLOCK_MONOTONIC` として動き、
  `CAP_WAKE_ALARM` が要ります（`EPERM`。知らないフラグの `EINVAL` が先です）。

- signalfd（`signalfd`、`signalfd4`）は、読むスレッドに保留されているシグナルのうち
  マスクにあるものを、ブロックされていてもいなくても、Linux の `dequeue_signal` と
  同じ順で読みます。スレッド自身のものが先で、次にプロセスのもの、それぞれ番号の
  小さいものからです。1 回の読み込みで、入るだけの 128 バイトの
  `struct signalfd_siginfo` を返し（1 つも入らなければ `EINVAL`）、それぞれに
  Linux がシグナルの種類ごとに写す欄を入れます。`kill` と `sigqueue` なら送り手の
  プロセスとユーザー（と値）、`SIGCHLD` なら子のプロセス・状態・CPU 時間、タイマー
  なら ID・オーバーラン・値、フォールトならアドレスです。非ブロッキングでなければ
  最初の 1 つを待ち、配送できるシグナルが来るとその待ちは終わります（`EINTR` で、
  `SA_RESTART` なら再開します）。`poll`・`select`・`epoll` は、呼んだスレッドに
  マスクのシグナルが保留されている間、Linux と同じく読めると見ます。そのため
  スレッド自身へのシグナルはそのスレッドにだけ見え、fork した子が受け継いだ
  ファイルは子のシグナルを読みます。エッジトリガーの `epoll` は、ファイルのシグナルが
  待つスレッドに保留されている間、プロセスかそのどれかのスレッドにシグナルが積まれる
  たびにエッジを受けます。
  Linux の `signalfd_notify` が、そのたびにファイルを起こすのと同じです。同じ番号が
  待っているリアルタイムシグナルも数え、すでに保留されている標準のシグナルや、
  ブロックされずに無視されるシグナルは数えません。マスクが変わるのもエッジです。
  signalfd のディスクリプタに `signalfd` を呼ぶと
  マスクが変わります（ほかのファイルなら `EINVAL`）。`SIGKILL` と `SIGSTOP` は
  マスクに入りません。書き込みは `EINVAL`、`pread` と `pwrite` は `ESPIPE`、`lseek` は
  Linux の `noop_llseek` と同じく 0 を返します。

- inotify のインスタンス（`inotify_init`、`inotify_init1`。`IN_NONBLOCK` と
  `IN_CLOEXEC` が使えます）は、ファイルをデバイスと inode で見張ります。
  `inotify_add_watch` は Linux の `inotify_find_inode` と同じくファイルを探します。
  `IN_DONT_FOLLOW` でなければ最後のシンボリックリンクをたどり、`IN_ONLYDIR` なら
  ディレクトリでなければならず（`ENOTDIR`）、呼び手が読めるものでなければなりません
  （`EACCES`）。エラーは Linux と同じ順で、マスク（知らないビットか、ビットがなければ
  `EINVAL`）、ディスクリプタ（`EBADF`。`O_PATH` のものも）、`IN_MASK_ADD` と
  `IN_MASK_CREATE` の両方（`EINVAL`）、別の種類のファイル（`EINVAL`）、そしてパスです。
  すでに見張っているファイルは同じウォッチディスクリプタのままで、マスクが新しいもの
  になります。`IN_MASK_ADD` なら前のものと合わせ、`IN_MASK_CREATE` なら `EEXIST`
  です。ウォッチディスクリプタは Linux の `idr_alloc_cyclic` と同じく 1 から番号が付き、
  一回りするまで使い回されません。`INOTIFY_IOC_SETNEXTWD` で次の番号を決められます。
  ウォッチのないディスクリプタの `inotify_rm_watch` は `EINVAL` です。1 人のユーザーが
  持てるのは、インスタンスが 128（`EMFILE`）、ウォッチが 31956（`ENOSPC`）で、
  `sysinfo` が示す 4 GiB から Linux が出す数です。インスタンスが溜めるイベントは
  16384 です。どれも `/proc/sys/fs/inotify` で変えられます。
  ゲスト自身のシステムコールによる変更がイベントになり、Linux の `fsnotify` のフックと
  同じ順で届きます。新しいファイル、ディレクトリ、シンボリックリンク、FIFO、ソケット、
  リンクは `IN_CREATE` です（リンクではリンクされたファイルの `IN_ATTRIB` の後）。
  消したものは `IN_DELETE` で、その前にファイルの `IN_ATTRIB`、最後のリンクか
  ディレクトリならそのファイルの `IN_DELETE_SELF` と `IN_IGNORED` が来ます。これは、
  そのファイルの開いている記述があれば、Linux の dentry と同じく最後に閉じるまで
  待ちます（マッピングは解除されるまで記述を持ちます）。それをプログラムとして
  実行しているプロセスがなくなるまでも待ちます。プログラムが使う ELF インタープリタは、
  それをマッピングしているプロセスがなくなるまで待ちます（マッピングは解除、exec、
  終了で終わり、fork でコピーされます）。
  ディレクトリは、それを作業ディレクトリにしているプロセスがなくなるまでも待ちます。名前の
  変更は同じクッキーの `IN_MOVED_FROM` と `IN_MOVED_TO` で、続いて置き換えられた
  ファイルの `IN_ATTRIB`、動いたファイルの `IN_MOVE_SELF`、置き換えられたファイルの
  `IN_DELETE_SELF` で、同じように待ちます（`RENAME_EXCHANGE` では 2 回。同じファイルの別のリンクへの
  変更では何もありません）。モード、所有者（どちらも指定しない `chown` では何も
  ありません）、両方の時刻、拡張属性を変えると `IN_ATTRIB`、アクセス時刻だけなら
  `IN_ACCESS`、更新時刻だけなら `IN_MODIFY`、切り詰めは `IN_MODIFY` です（通常の
  ファイルを空にする `O_TRUNC` も、その `IN_OPEN` の後に）。開く（`O_PATH` 以外。
  `/proc/self/fd` のリンクからも）と `IN_OPEN`、開いたファイル記述の最後の参照が
  なくなると `IN_CLOSE_WRITE` か `IN_CLOSE_NOWRITE` です（マッピングは解除される
  まで参照を持ちます）。バイトを動かした `read`、`write`、`pread64`、`pwrite64`、
  `readv`、`writev`、`preadv`、`pwritev`、`preadv2`、`pwritev2`、`sendfile` と
  `copy_file_range`（入力の後に出力）、`fallocate`、毎回の `getdents` と `getdents64` は
  `IN_ACCESS` か `IN_MODIFY` です。バイトを動かした `splice` は出力の `IN_MODIFY` の後に
  入力の `IN_ACCESS`、`tee` は入力の後に出力、`vmsplice` は書き込み側なら `IN_MODIFY`、
  読み込み側なら `IN_ACCESS` です。パイプにはウォッチがありませんが、パスで開いた FIFO は
  ほかと同じ開いたファイルです。開き終えると `IN_OPEN`（書き手の `ENXIO` のように失敗した
  ものは何もなし）、ファイル記述の最後のクローズで `IN_CLOSE_WRITE` か `IN_CLOSE_NOWRITE`
  です。読み書きは FIFO 自身のウォッチだけに届き、Linux と同じくディレクトリのウォッチには
  届きません（`d_is_special`）。イベントはファイルと同じく名前の変更が名前を移した先に届きます。
  `/proc/self/fd` から開くと、どの名前も指さなくなった後でも、同じ名前のところでパイプを
  もう一度開きます（`IN_OPEN` があり、パスで開くときと同じく相手側を待ちます）。削除した
  FIFO の `IN_DELETE_SELF` は、その最後のクローズを待ちます。どの名前も指さない memfd は、
  何も持たなくなる（ファイル記述も、マップも、それを実行するプロセスもなくなる）と
  `IN_DELETE_SELF` を受けます。`memfd_create` 自身のファイル記述には `IN_OPEN` も
  クローズもありません。exec が実行するファイルも
  開いたファイルです。`execve` か `execveat` がプログラム（ディスクリプタだけが持つ memfd や
  削除したファイルも）、各スクリプト、ELF インタプリタを開くと `IN_OPEN`、先頭の
  バイトを読むと `IN_ACCESS`（空のファイルではなし）、使うものがなくなると
  `IN_CLOSE_NOWRITE` です。プログラムは実行するプロセスがなくなったときに、インタプリタは
  マップするプロセスがなくなったときに閉じます。スクリプトは呼び出しの終わりに、exec が
  置き換えたプログラムとそのインタプリタの後に閉じます。Linux が遅らせる `fput` は新しい
  ものから走るからです。失敗した exec は、諦めるときに開いたファイルを最後に開いたものから
  閉じます。プログラムは、見つけたインタプリタより先です。`IN_EXCL_UNLINK` のウォッチは、開いた後に
  （`unlink`、`rmdir`、上書きする rename で）消えた名前を通してファイルを開く・閉じる・
  読み書きすることを受けません。別のリンクがファイルを残していても同じです。
  `truncate` と `mknod` は何も開きません。ファイルの変更は、そのディレクトリのウォッチに
  名前付きで先に届き、次にファイル自身のウォッチに届きます（開いたファイルでは、開いたときの
  名前を、ファイル自身や上のディレクトリの名前の変更に合わせて動かしたもの、または消える前の
  最後の名前です）。ディレクトリのものには
  `IN_ISDIR` が付きます（`IN_DELETE_SELF` と `IN_MOVE_SELF` には Linux と同じく
  付きません）。`IN_ONESHOT` のウォッチは最初のイベントの後に `IN_IGNORED` とともに
  消えます。tmpfs のスーパーブロックが最後のマウントとともに消えると（バインドマウントが
  残っていれば消えず、切り離したものはそこで開いている最後のファイルが閉じられたときに
  消えます）、そのファイルのウォッチはどれも、何を求めていても `IN_UNMOUNT`
  （ディレクトリなら `IN_ISDIR` 付き）を受け取り、`IN_IGNORED` とともに消えます。
  Linux の `fsnotify_sb_delete` と同じです。インスタンスのウォッチは新しいものから
  消えます。インスタンスはイベントを溜め、直前のイベントと同じもの（ディスクリプタ、
  マスク、名前）は、それが `IN_IGNORED` か名前の変更でなければまとめます。16384 個
  溜まると、読まれるまで `IN_Q_OVERFLOW`（ディスクリプタは -1）を 1 つだけ溜めます。
  読み込みは入るだけの `struct inotify_event` を返し、名前は 16 バイトの倍数まで NUL で
  埋めます。最初の 1 つが入らなければ `EINVAL` です。非ブロッキングでなければ最初の
  1 つを待ち、シグナルでその待ちは終わります（`EINTR` で、`SA_RESTART` なら再開
  します）。Linux の `inotify_read` と同じく、1 つ取り出すたびにそれを書き出します。
  プロセスが書けないページに届いたものも取り出され、そのページの手前までのバイトを
  書き、それまでに読んだものにかかわらず読み込みは `EFAULT` です（ユーザーの半分の
  外のアドレスは、何も取り出さずに `EFAULT` です）。インスタンスには `read_iter` が
  ないので、`readv` と `preadv2` はバッファを 1 つずつこの読み込みで読み、埋まらない
  ものか失敗したもので止まります（`EFAULT` になるのはそれが最初のときだけです）。
  0 バイトなら 0 を返し、`RWF_HIPRI` 以外のフラグは受けません（`EOPNOTSUPP`）。`FIONREAD` は溜まっているバイト数を返し、`poll`・`select`・`epoll` は
  イベントが溜まっている間読めると見ます。エッジトリガーの `epoll` は、イベントが
  1 つ溜まるたびにエッジを受けます。インスタンスの最後のディスクリプタを閉じると
  ウォッチも消えます。書き込みは `EBADF`、`pread` は `ESPIPE`、`lseek` は 0 です。

- fanotify のグループ（`fanotify_init`）は Linux の `fs/notify/fanotify` と同じです。
  フラグはその順に確かめ（CAP_SYS_ADMIN がなければ `EPERM`。ただしファイルハンドルか
  マウントを報告するグループは作れ、ディスクリプタもほかのプロセスの ID も報告しません）、
  ユーザーのグループを数え（`EMFILE`）、ファイルは読み書きできる `anon_inode:[fanotify]`
  で、`O_NONBLOCK` と `O_CLOEXEC` は求められたとおりです。`fanotify_mark` はファイル、
  マウント、ファイルシステムへのマーク（マウント名前空間へのものも受け付けます）を足し、外し、
  まとめて消します。マウントへのマークはマウントの ID で持ち、同じファイルシステムの
  バインドマウントではなくそのマウントの中のパスのイベントだけを受け、fdinfo はその ID を
  示します。マウントが解放されるとそのマークもなくなるので（`fsnotify_vfsmount_delete`）、
  次にその ID を得たマウントにはマークがありません。exec がプログラムとそのインタープリターを
  開くことは、`do_open_execat` が `__FMODE_EXEC` で開くのと同じく `FAN_OPEN_EXEC` 付きの
  `FAN_OPEN` として伝わり、inotify には `IN_OPEN` として伝わります。その前に、そうした
  オープンはそれぞれ `FAN_OPEN_EXEC_PERM`、`FAN_OPEN_PERM` を、exec によるそのファイルの
  読み出し（`kernel_read`）は 1 回ごとに `FAN_ACCESS_PERM` を、exec が確定する前に
  この順に尋ねます（バイトを読んだ読み出しは続いて `IN_ACCESS` です）。スクリプトは
  先頭のバイトを 1 回、ELF のプログラムはそれに加えてプログラムヘッダーと `PT_INTERP`
  の名前を、続いてインタプリタの ELF ヘッダーとプログラムヘッダーを読みます（x86-64 は
  `PT_GNU_PROPERTY` を読みません）。拒まれると `execve` は `EPERM` で失敗し、そのあとの
  ものは尋ねません。そのあとで失敗する exec（インタプリタがない、
  引数が読めない）も同じように尋ね終えています。拒まれたときの `EPERM` が先に返り、
  通されたオープンはそのオープンとクローズを伝えます。確認もその順です。フラグとマスク（`EINVAL`）、ディスクリプタ
  （`EBADF`、`EINVAL`）、グループのクラスとモード、パス（`ENOENT`、`ENOTDIR`）、
  ファイルシステムが受け付けるイベント（/proc への許可イベントと、カーネル自身のファイル
  システムへのマウントとファイルシステムのマークは `EINVAL`。新しいフラグでのファイルへの
  ディレクトリのイベントは `ENOTDIR`）、読む許可（`EACCES`）、FID モードでのファイル
  システムの ID とハンドル（`ENODEV`、`EOPNOTSUPP`、`EXDEV`）、無視マスクの規則
  （`EISDIR`、`EEXIST`。書くために開かれているファイルには何もしません）、ユーザーの
  マーク（`ENOSPC`）です。マークは Linux と同じく `FAN_EVENT_ON_CHILD` と `FAN_ONDIR` を
  持ち（ディレクトリのマーク以外では前者を外し、`FAN_REPORT_DIR_FID` ではディレクトリと
  名前がわかるように足します）、無視マスクは `FAN_MARK_IGNORED_SURV_MODIFY` がなければ
  変更で消えます。
  グループは inotify と同じフックで、Linux の `fsnotify` と同じくイベントを受けます。
  ファイル、そのマウント、そのファイルシステムのマーク、子を見ているときのディレクトリの
  マーク、`FAN_RENAME` では新しいディレクトリのマークです。イベントは
  `fanotify_handle_event` と同じに作って溜めます。FID モードでなければ、通常のファイルか
  ディレクトリを開く、読む、変える、閉じることだけで、グループのフラグで開き直した
  ディスクリプタがつきます。`dentry_open` と同じく、`F_GETFL` には `O_CLOEXEC` が残り、
  ディレクトリも書くために開きます（どのウォッチにも何も知らせないもの。開けなければ
  `FAN_REPORT_FD_ERROR` ではそのエラー、それ以外は read のエラーです）。FID モードでは
  ファイルのハンドル（`name_to_handle_at` の識別子）、ディレクトリのハンドルと名前、
  名前の変更での古いと新しいディレクトリと名前、ディレクトリ自身のイベントでの `.` の
  レコードがつきます。まだ溜まっている同じ対象、同じプロセス、同じ種類のイベントには
  まとめ、`max_queued_events` を超えると `FAN_Q_OVERFLOW` を 1 つ溜め、
  `FAN_REPORT_PIDFD` ではプロセスの pidfd を足します（`FAN_REPORT_TID` と一緒には、CI の
  ランナーの Linux 7.0 と同じく `EINVAL` です。master は両方を受け付け、スレッドのものを
  示します）。read はイベントを丸ごと取り（最初のイベントが入らないバッファーは
  `EINVAL`）、ノンブロッキングでなければ待ちます。`FIONREAD` は溜まったバイト数を返し、
  `/proc/self/fdinfo` は `fanotify_show_fdinfo` と同じくフラグと各マークを新しい順に
  示します。write は許可イベントへの応答で、Linux と同じに確かめ、そのディスクリプタが指す読まれた
  イベントに答えます（待つものがなければ `ENOENT`）。`open`、`openat`、`openat2`、`creat`、
  `open_by_handle_at` で（`/proc/self/fd` のリンクからも）開くファイルについて、コンテンツかプレコンテンツのグループのマークが `FAN_OPEN_PERM` を
  求めると、`fanotify_get_response` と同じく、プレコンテンツのものから順にそれぞれのグループの
  答えを待ちます。`FAN_DENY` は `EPERM` で失敗させ、`FAN_ALLOW` とグループの最後のクローズは
  通します。待つのを止めるのは致命的なシグナルだけです。`FAN_OPEN` は通ってから届き、拒まれた
  ものは開かれないのでクローズも伝えません。許可イベントはまとめません。キューがいっぱいなら
  溢れのイベントのあとに通し、ディスクリプタを渡せない読み出しはそれを拒みます。
  `do_dentry_open` が `security_file_open` を先に呼ぶのと同じく、このオープンの
  `FAN_OPEN_PERM` は Landlock の確認を通ってから尋ねます。グループのマークが
  `FAN_ACCESS_PERM` を求めていたときに開いたファイル記述の読み出し（`read`、`pread64`、
  `readv`、`preadv`、`preadv2`、`sendfile`・`splice`・`copy_file_range` の入力）も、
  `rw_verify_area` と同じくディスクリプタ、バッファ、大きさ、位置の確認のあとに同じように
  答えを待ちます。`vfs_readv` と同じく、0 バイトの `readv` と `preadv` は何も尋ねず、
  0 バイトの `read` と `pread64` は尋ねます。AIO の読み出し（`IOCB_CMD_PREAD`、
  `IOCB_CMD_PREADV`）は、`aio_read` が `rw_verify_area` を呼ぶのと同じく `io_submit` の
  ときに、0 バイトでも尋ねます。拒まれたものは、`io_submit` がほかの失敗と同じく
  その要求で失敗させます（最初のものなら `EPERM`）。
  `statfs` の `f_fsid` はイベントが示すファイルシステムの ID と同じです。カーネル自身の
  ファイルシステム、/proc、devpts、mqueue では `simple_statfs` と同じくデバイス番号、
  ほかのファイルシステムでは、tmpfs が UUID を引くように、ファイルシステムごとに引いた
  数です。

- POSIX タイマーは上の時計で動き、プロセスへの
  シグナル（`SIGEV_SIGNAL`。`SI_TIMER` の siginfo とオーバーランつき）か、プロセスの
  中の 1 つのスレッドへのシグナル（`SIGEV_THREAD_ID`）で知らせるか、何も知らせません
  （`SIGEV_NONE`）。`SIGEV_THREAD` は、Linux と同じく `SIGEV_SIGNAL` として扱います
  （スレッドは C ライブラリが `SIGEV_THREAD_ID` を使って作ります）。スレッドへの
  タイマーのシグナルは、そのスレッドがまだ受け取っていない間だけオーバーランに足され、
  スレッドが終わっていれば失われます。`CLOCK_PROCESS_CPUTIME_ID` のタイマーはプロセスの
  CPU 時間を、`CLOCK_THREAD_CPUTIME_ID` のタイマーはそれを作ったスレッドの CPU 時間を、
  Linux の `posix_cpu_timer_*` と同じように数えます。値はその時間で表し
  （`TIMER_ABSTIME` なら絶対時刻）、`KTIME_MAX` で頭打ちにします。止めると間隔も含めて
  何も示さず、`SIGEV_NONE` のタイマーは読んだときに間隔の分だけ進めます。時計の
  スレッドが終わったあとは、`timer_settime` は `ESRCH` を返し、`timer_gettime` は何も
  示しません。ほかの時計では、Linux の `common_timer_set` と同じく、`timer_settime` は
  `flags` のうち `TIMER_ABSTIME` しか見ず、値と間隔は `KTIME_MAX` で頭打ちにし、相対時間で
  `KTIME_MAX` を超える満了もそこで止めます。相対時間の `CLOCK_REALTIME` のタイマーは
  単調時計で数えます。タイマーは
  `fork` では受け継がれず、`execve` で消えます。`rt_sigtimedwait` は、プロセス全体に
  届いてブロックされているシグナルも受け取ります。

- `clone3` は、`struct clone_args` を Linux と同じように確かめ（後ろに足された部分が
  0 でない長い構造体には `E2BIG`）、それが表す `clone` として動きます。
  `CLONE_CLEAR_SIGHAND` は、ハンドラを設定したシグナルを既定に戻します。`set_tid` は上の PID
  名前空間で書いたとおりで、`CLONE_INTO_CGROUP` は `EINVAL` を返します。`clone` そのものは、Linux と同じく flags の
  下位 32 ビットだけを読むので、`CLONE_CLEAR_SIGHAND` は `clone3` でしか使えません。

- `prctl` は `PR_SET_NAME`／`PR_GET_NAME`（スレッドごとの 15 バイトまでの名前。
  `execve` でプログラムのファイル名になり、新しいスレッドとプロセスに受け継がれます）、
  `PR_SET_PDEATHSIG`（親が終わったときにシグナルを送ります）、`PR_SET_DUMPABLE`
  （`execve` は、上に書いた場合のほかは、またダンプできるようにします）、
  `PR_SET_KEEPCAPS`（スレッドごとで、`execve` で消えます）、ケーパビリティモジュールの
  `PR_CAPBSET_READ`、`PR_CAPBSET_DROP`（`CAP_SETPCAP` が要ります）、`PR_GET_SECUREBITS`、
  `PR_SET_SECUREBITS`（ロックされたビットは変えません。`CAP_SETPCAP` がなければ、
  ユーザー空間で exec を確かめるための 2 つのビットだけを、変えるときだけ変えられます）、
  `PR_CAP_AMBIENT`（上げるケーパビリティは許可と継承の両方になければならず、
  `SECBIT_NO_CAP_AMBIENT_RAISE` があれば断ります）（どれもスレッドごと）、
  `PR_SET_CHILD_SUBREAPER`（`fork` では受け継がれず、`execve` では残ります）、
  `PR_SET_NO_NEW_PRIVS`、`PR_SET_SECCOMP`（下の seccomp を見てください）と、
  それぞれの `PR_GET_*`、そして Yama の `PR_SET_PTRACER` に対応します。`PR_SET_PTRACER` は
  ほかの引数を読みません。0 で消え、`PR_SET_PTRACER_ANY`（`int` として -1 も同じ）でどの
  プロセスもアタッチできるようになります。ほかの値は `int` として、呼び出し元の PID 名前空間の
  タスクを指します（なければ `EINVAL`）。そのタスクがある間、そのプロセスとその子孫が
  アタッチできます。どのスレッドが設定してもプロセスのもので、子には受け継がれません。
  ほかの指定には `EINVAL` を返します。

- プロセスが終わると、その子は、`PR_SET_CHILD_SUBREAPER` を設定していてまだ終わって
  いない一番近い祖先に、いなければ PID 名前空間の init にあたる最初のプロセスに
  引き取られます。Linux の `forget_original_parent` と同じです。その後 `getppid` は
  新しい親を返し、新しい親はその子を待てて、子の終了シグナルは `SIGCHLD` になります。
  すでに終わっていた子は、すぐに新しい親に知らせます（その親が `SIGCHLD` を
  無視していれば、すぐに回収します）。

- 最初のプロセスが終わると、PID 名前空間の init が終わったとき（Linux の
  `zap_pid_ns_processes`）と同じように、ほかのすべてのプロセスがカーネルから
  `SIGKILL` を受け取り、実行もそこで終わります。

- 終わったプロセスのせいでプロセスグループが孤児になり（同じセッションの別のグループに
  親を持つメンバーがいなくなり）、そのグループに止まっているメンバーがいれば、Linux の
  `kill_orphaned_pgrp` と同じように、すべてのメンバーにカーネルから（`SI_KERNEL` で）
  `SIGHUP`、続けて `SIGCONT` を送ります。最初のプロセスの親はエミュレータの外にあり、
  最初のプロセスが動いている間は、そのような親として数えます。最初のプロセス自身も、
  ほかの親と同じように、自分の子のグループをつなぐ親として数えます。Linux が数えない
  のはシステム全体の init の子だけで、最初のプロセスは、コンテナと同じく PID
  名前空間の init として振る舞うからです。

- `kill` は、Linux の `kill_something_info` と同じように、PID かそのスレッドの ID
  でそのプロセスに、0 で呼び出し元のプロセスグループに、`-pgid` でほかのグループに、
  -1 で最初のプロセスと呼び出し元以外のすべてのプロセスに届きます。終わったプロセスも、
  回収されるまでは数えます。送る相手のプロセスがなければ、無効なシグナルでも `ESRCH`
  を返し、相手がいれば無効なシグナルは `EINVAL` を返します。Linux の
  `check_kill_permission` と同じく、スレッドがほかのプロセスに送れるのは、実ユーザー ID か
  実効ユーザー ID が相手の実 ID か保存 ID と同じか、`CAP_KILL` があるときで、`SIGCONT` は
  同じセッションの中でも送れます。そうでなければ `kill`、`rt_sigqueueinfo`、
  `rt_tgsigqueueinfo`、`pidfd_send_signal` は、シグナル 0 やゾンビでも `EPERM` を返します。
  確かめる資格情報は ID が指すスレッドのものです。グループはどれかのメンバーに届けば
  成功とし、-1 は送れない相手を報告しません。`kill` や `pidfd_send_signal` で送った
  シグナルの `si_pid` と `si_uid` は送り主の PID と実ユーザー ID に（`tkill` と `tgkill`
  も同じです）、`PR_SET_PDEATHSIG` のシグナルでは終わった親の PID と実ユーザー ID に
  なります。このシグナルにも同じ許可が要ります。

- `rt_sigqueueinfo`（`sigqueue` の中身）は、呼び出し元の siginfo をそのままプロセスに
  送り、`rt_tgsigqueueinfo` は 1 つのスレッドに送ります。そのためシグナルは値を運び、
  リアルタイムシグナルは送った数だけ届きます。Linux と同じく、カーネルや `kill`、
  `tkill` が付ける `si_code` を付けられるのは、自分自身に送るスレッドだけです（相手を
  探す前に `EPERM`）。Linux が形を知らない `si_code` では、siginfo の残りを 0 にして
  おく必要があります（`E2BIG`）。

- 資源の上限は Linux の既定値（`RLIMIT_NOFILE` は 1024／4096、`RLIMIT_STACK` は
  8 MiB／無制限など）から始まり、`fork` で受け継がれ、読み書きできます。ハードの
  `RLIMIT_NOFILE` は 1048576（Linux の `fs.nr_open`）まで、埋め込む側がそれより低い
  天井を決めたときはその値まで上げられます。ハードの上限を上げるには
  `CAP_SYS_RESOURCE` が必要です（`EPERM`）。ほかのスレッドへの `prlimit64` は、読むにも
  書くにも、`CAP_SYS_RESOURCE` があるか、呼んだ側の実ユーザー ID と実グループ ID が相手の
  実、実効、保存の ID すべてと同じであることが必要です（`EPERM`。知らない資源より先に
  確かめます）。スレッドの ID はそのプロセスを指します。Linux と同じく
  守らせるのは次の 4 つです。
  - `RLIMIT_NOFILE`：ソフトの上限を超える新しいディスクリプタは `EMFILE`（`open` は
    何も作りません）、上限を超える番号への `dup2`／`dup3` は `EBADF`、上限を超える
    番号からの `F_DUPFD` は `EINVAL` になります。
  - `RLIMIT_FSIZE`：通常のファイルへの書き込み（`O_APPEND` なら末尾から書く `write`、
    `writev`、`pwrite`、`pwritev` と、`copy_file_range`、`sendfile`、`splice`）はソフトの上限で
    止まります。上限かその先から始まる
    書き込みと、ファイルを上限より大きくする `truncate`／`ftruncate` と `fallocate` は、`SIGXFSZ` を
    起こして `EFBIG` で失敗します。
  - `RLIMIT_CPU`：Linux の `check_process_timers` と同じく、プロセスの CPU 時間がハードの
    上限に届くと `SIGKILL` を送ります。ソフトの上限に届くと `SIGXCPU` を送ってソフトの
    上限を 1 秒上げるので、その後も 1 秒ごとに送ります。秒からナノ秒へは、Linux と同じく
    桁あふれする 64 ビットの掛け算で直すので、2^55 秒以上のソフトの上限ですぐに届くことが
    あります。`fork` の子は上限を引き継ぎ、子自身の CPU 時間をそれと比べます。
  - `RLIMIT_CORE`：コアダンプするシグナル（`SIGSEGV`、`SIGABRT` など）で終わる
    プロセスは、ソフトの上限が 1 ページ以上で、`PR_SET_DUMPABLE` でダンプを止めて
    いなければ、Linux の `do_coredump` が既定の `core_pattern` でするのと同じように、
    作業ディレクトリに `core` という名前の ELF のコアを書きます（モードは 0600 から
    umask を除いたもので、前のコアは置き換えます）。シグナルで終わったスレッドが、自分の
    権限とファイルシステム ID でファイルを作るので、書けない場所や置き換えられないファイル
    があるときは何も書きません。コアには、各スレッドのレジスタ（`NT_PRSTATUS`）、
    プロセスとそのリーダーの実ユーザー、実グループ（`NT_PRPSINFO`）、致命的なシグナル（`NT_SIGINFO`）、
    exec が保存した補助ベクトル（Linux の `saved_auxv`。プログラムがスタックに何をしても
    変わりません）、マップしたファイル（`NT_FILE`）、メモリが入ります。`NT_FILE` は
    ファイルをマップした VMA ごとにそのパスを示し、unlink されたファイルには
    パスの後に `(deleted)` を付けます。共有の無名メモリは、Linux と同じく
    `/dev/zero (deleted)` と示します。`NT_X86_XSTATE` ノートはありません。Linux は
    XSAVE のない CPU では書かず、仮想 CPU には XSAVE がないからです。メモリは、
    Linux の `vma_dump_size` が既定の `coredump_filter` で選ぶのと同じように
    選びます。private なマッピングは、その VMA の
    ページが一度でも書かれていれば（Linux の `anon_vma`。分割、`MADV_DONTNEED`、`fork`
    の後も残り、VMA に併合されたマッピングも共有し、書き込めるマッピングのページを
    取り込むと付きます。`MAP_POPULATE`、`MAP_LOCKED`、フォールト時でないロックです）丸ごと入り、そうでなければ入りません。
    ただし、ELF のファイルの先頭からのファイルのマッピングは最初のページが入ります。
    共有のマッピングは、そのファイルをどの名前もリンクしていなければ（無名のもの、
    memfd、後から unlink したファイル）丸ごと入り、そうでなければ入りません。
    マッピングが読めるかどうかは ELF のヘッダーのページにしか関わらず、Linux はほかを
    保護に関係なく読みます。セグメントは VMA ごとに 1 つで、併合された隣の
    マッピングも同じセグメントに入ります。
    そのとき `wait` は `CLD_DUMPED` とコアのフラグを
    返します。上限より大きいコアはそこで切りますが、Linux が書き始めたコアを
    ダンプしたと報告するのと同じように、ダンプしたと返します。

  プロセスグループとセッションも同じように持ち、`wait4` と `waitid` でプロセス
  グループを選んで待てます。最初のプロセスは PID 名前空間の最初のプロセスと同じで、
  そのグループとセッションはエミュレータの外で始まったものなので、`getpgrp` と
  `getsid` は、Linux が PID 名前空間の外の ID を示すのと同じく 0 を返し、自分の
  セッションを始めることもできます。`setsid` は、PID がグループを指すプロセス
  では `EPERM` で失敗し、それ以外のプロセスを新しいセッションとグループの先頭に
  します。`setpgid` は Linux と
  同じくセッションを確かめ、セッションの先頭、別のセッションの子、別のセッションの
  グループには `EPERM` を、`execve` を済ませた子には `EACCES` を返します。グループは、
  まだ回収されていない終わった子も含め、メンバーが残っている間は存在します。

- nice 値は Linux と同じくスレッドごとに持ちます。新しいスレッドやプロセスは作った
  スレッドの値を受け継ぎ、`execve` は呼んだスレッドの値を保ちます。`getpriority` は
  見つけたスレッドのうち最も高い優先度を `20 - nice` で返し、`setpriority` はそれらを
  すべて -20〜19 に収めた値にします。`PRIO_PROCESS` は 1 つのスレッド（0 は呼んだ
  スレッド）、`PRIO_PGRP` はプロセスグループのすべてのスレッド、`PRIO_USER` は実ユーザー
  ID が同じすべてのスレッド（0 は呼んだスレッドの ID）です。まだ回収されていない
  終わったプロセスも見つかります。スレッドがなければ `ESRCH`、知らない `which` は
  `EINVAL` です。値は報告するだけで、スケジューリングは変えません。

- `setpriority` は、Linux の `set_one_prio` と同じくスレッドごとに確かめます。呼んだ側の
  実効ユーザー ID が相手の実または実効ユーザー ID と同じか、`CAP_SYS_NICE` があることが
  必要で、なければ `EPERM` です。nice 値を下げるには、`CAP_SYS_NICE` があるか、
  `20 - nice` が相手の `RLIMIT_NICE` のソフトリミット以内であることが必要で、なければ
  `EACCES` です。変えられるスレッドは変わり、そのうえで最後に断られた理由を返します。

- `waitid` は、Linux と同じ確かめ方と書き出し方をします。報告する子がないときは、
  エラーのときも含めて siginfo の項目を 0 にします。終わった子は、`WEXITED` か
  `WCONTINUED` がないと待てません（`ECHILD`）。停止と再開は、`WUNTRACED`
  （`WSTOPPED`）か `WCONTINUED` を付けた待ちにそれぞれ一度だけ報告し（`WNOWAIT` なら
  残します）、親が `SA_NOCLDSTOP` を付けていなければ `SIGCHLD` で知らせます。
  `SIGCHLD` の siginfo には、子の PID、`CLD_*` のコード（`CLD_EXITED`、`CLD_KILLED`、
  `CLD_STOPPED`、`CLD_CONTINUED`）、状態、`si_utime` としての CPU 時間が入ります。
  `si_uid` と `waitid` の `si_uid` は子の実ユーザー ID で、`SIGCHLD` が保留中に届いた次の
  `SIGCHLD` は、Linux と同じく捨てます。
  `SIGCHLD` を無視するか `SA_NOCLDWAIT` を設定したプロセスの子は、終了シグナルが
  `SIGCHLD` なら、Linux の `do_notify_parent` と同じく終わったその場で回収します。
  待ちはそうした子が終わるまで待ってから `ECHILD` で失敗し、その CPU 時間は親の
  子の分に足しません。`SIGCHLD` を無視しているときは、ブロック中でも `SIGCHLD` を
  保留しません。それより前にできたゾンビは、待ちのために残ります。
  `pidfd_open` の pidfd の `fstat` は、pidfs と同じくモード 0700 で、ファイルの種類を
  示しません。inode は、pidfs がプロセスごとに一度だけ番号を付けるのと同じく、その
  プロセスのもの（ここでは ID を二度配らないので、プロセスの ID）です。`fstatfs` は
  pidfs（`PID_FS_MAGIC`）を返します。pidfd は、そのプロセスが終わると読めるようになり（回収されると
  切断も示します。自動で回収された子では両方を同時に示します）、`epoll` で待てます。ノンブロッキングの pidfd での
  `waitid(P_PIDFD)` は `EAGAIN` を返します。`pidfd_send_signal` は siginfo と
  範囲の指定を受け付けず、`PIDFD_THREAD` を付けてもプロセス全体を指します。ただし
  `F_GETFL` には Linux と同じく `O_EXCL` として表れます。pidfd の
  代わりに Linux の特別な値も受け付けます。`PIDFD_SELF_THREAD`（-10000）は呼んだ
  スレッドに `tkill` と同じく（`SI_TKILL`）、`PIDFD_SELF_THREAD_GROUP`（-10001）は
  そのプロセスに `kill` と同じく送ります。

- 不正なポインタを渡されたときは `EFAULT` を返します。

## ネットワーク {#network}

組み込む側が行き先を許可しない限り、ゲストはネットワークを使えません
（`Config::with_network`、コマンドの `--allow-net`、JavaScript の `network` の指定。
ブラウザでは [中継](./relay) を通します）。許可の一覧には、ホスト名
（`github.com`）、そのすべてのサブドメイン（`*.github.com`）、IPv4 アドレス、IPv6
アドレス（`[::1]`）を書きます。どれもポートを付けるか（`github.com:443`）、付けずに
すべてのポートを許します。

- **TCP のクライアントのソケット**：`socket(AF_INET` または `AF_INET6, SOCK_STREAM)`
  （`SOCK_NONBLOCK`、`SOCK_CLOEXEC` も付けられます）は、ホストを通して接続するか、
  ループバックの上の[ゲスト自身のサーバー](#loopback-servers)に接続します。
  - **`connect`**：ブロッキングなら接続を待ちます。ノンブロッキングなら
    `EINPROGRESS` を返し、そのあとソケットが書き込めるようになり、`SO_ERROR` が結果を
    1 回だけ返します。2 回目の呼び出しは `EALREADY`、接続したあとは 0、その次からは
    `EISCONN` です。失敗した接続はその誤りを返し、`SO_ERROR` が取ったあとは
    `ECONNABORTED` です。IPv6 のソケットは、IPv4 のアドレスに `::ffff:a.b.c.d` として
    届きます。
  - **方針が許さない行き先**は `ENETUNREACH` です。ただし 53 番ポートは DNS の代わりに
    届き（下を参照）、ゲストのソケットが待ち受けていないループバックのアドレスは
    拒まれます（`ECONNREFUSED`。ノンブロッキングのソケットなら `EINPROGRESS` のあと
    `SO_ERROR` で）。
  - **データ**：`read`、`write`、`send`／`recv`、`sendto`／`recvfrom`、
    `sendmsg`／`recvmsg` を、`MSG_PEEK`、`MSG_WAITALL`、`MSG_DONTWAIT`、
    `MSG_NOSIGNAL` とともに使えます。書き込みはすべて送るまで続きます。相手が
    リセットした接続は、その誤りを 1 回返し、そのあとは入力の終わりです。接続したことの
    ないソケットや、`shutdown(SHUT_WR)` のあとの送信は `EPIPE` で、`SIGPIPE` も
    送ります。接続したことのないソケットの受信は `ENOTCONN` です。
  - **準備状態**：`poll`、`select`、`epoll` は Linux の `tcp_poll` と同じものを
    見ます。接続する前は切断と書き込み可能、接続している間は何もなし、データか入力の
    終わりがあれば `POLLIN`（終わりなら `POLLRDHUP` も）、送信のバッファに空きが
    あれば `POLLOUT`、両方向を閉じたら `POLLHUP`、誤りが残っていれば `POLLERR`
    です。
  - **`shutdown`**、`getsockname`（接続したあとはホストのアドレスとポート）、
    `getpeername`、`bind`、`FIONREAD`／`SIOCINQ`、`SIOCOUTQ`。
  - **オプション**：`SO_TYPE`、`SO_DOMAIN`、`SO_PROTOCOL`、`SO_ERROR`、
    `SO_ACCEPTCONN`、`SO_KEEPALIVE`、`SO_REUSEADDR`、`SO_REUSEPORT`、`SO_SNDBUF`、
    `SO_RCVBUF`、`SO_RCVTIMEO`、`SO_SNDTIMEO`、`SO_LINGER`、`SO_PRIORITY`、
    `SO_BROADCAST`、`SO_OOBINLINE`、`TCP_NODELAY`（ホストにも伝えます）、
    `TCP_KEEPIDLE`、`TCP_KEEPINTVL`、`TCP_KEEPCNT`、`TCP_QUICKACK`、
    `TCP_USER_TIMEOUT`、`TCP_INFO`（読み出しのみ）、`IP_TOS`、`IPV6_V6ONLY`。
    既定値と範囲の確かめ方は Linux と
    同じで、`SO_SNDBUF` と `SO_RCVBUF` は既定の `wmem_max` と `rmem_max`（212992）までを
    2 倍にします。新しい `IP_TOS` は、その TOS ビットから `SO_PRIORITY` も決めます
    （`rt_tos2priority`）。`SO_TIMESTAMP` とその仲間、`SO_TIMESTAMPING` は AF_UNIX のソケットと同じく
    設定して読み出せ、`SOF_TIMESTAMPING_OPT_ID` には TCP のソケットの接続が要ります
    （閉じているか待ち受けている間は `EINVAL`）。
  - **`TCP_INFO`** は、Linux の 280 バイトの `struct tcp_info` を、渡された大きさの分だけ
    返します（`tcp_get_info`）。リスナーは状態、待っている接続とバックログ、まだ接続して
    いないソケットは Linux の既定値、ハンドシェイク中は再送の回数（タイムアウトは
    `tcp_syn_linear_timeouts` を超えてから倍になります）を返します。接続は、状態、
    オプション（タイムスタンプ、SACK、ウィンドウスケーリング）、ウィンドウスケール（10、
    ゲストが受信バッファーを設定していればそれ以下）、送ったバイト、確認応答を受けた
    バイト、受け取ったバイト（ハンドシェイクと終わりを含む）、まだ送っていないバイト、
    データのセグメント、データを最後に送ってから・受け取ってからの時間を返します。UDP の
    ソケットには TCP のオプションがありません（`EOPNOTSUPP`）。
  - **タイムスタンプ**：`recvmsg` は、Linux の `udp_recvmsg`（`sock_recv_timestamp`）と同じく、
    UDP のデータグラムに届いた時刻を付けます。受け手がいつオプションを設定したかによりません。
    `SO_TIMESTAMP` などの制御メッセージを付け、`SO_TIMESTAMPING` のフラグがソフトウェアの
    タイムスタンプを報告し、受信したものを除いていなければ `SCM_TIMESTAMPING` も続けます。
    UDP では `SCM_TIMESTAMPING` だけでも付きます。どちらも AF_UNIX と同じく、制御バッファに
    収まる分に切ります。DNS の代わりの答えには、読んだ時刻を付けます。TCP のバイトにも、
    ループバックでもホストを通しても、届いた時刻を付けます。読み込みと覗き見、それにバイトが
    待っているときの長さ 0 の読み込みは、Linux の `tcp_recvmsg`（`tcp_recv_timestamp`）が
    セグメントの時刻を返すのと同じく、読んだバイトの時刻を受け取ります。入力の終わりには
    付きません。読まれずに待っているバイトがあるときに届いたバイトは、Linux の
    `tcp_try_coalesce` が前のセグメントにつなげるときと同じく、待っているバイトにも
    自分の時刻を与えます。
- **名前解決**：組み込みの DNS の代わりが、ゲストのリゾルバが 53 番ポートへ送る UDP の
  問い合わせに、宛先のアドレスによらず答えます。宛先は `/etc/resolv.conf` のサーバー、
  またはその既定です。許可した名前の `A` と `AAAA` の問い合わせには、ホストが引いた
  アドレスを（60 秒の有効期間で）返し、ほかの名前には `NXDOMAIN` を返します。許可した
  名前について返したアドレスへの接続は、最後に返してから 10 分の間、その名前と同じ
  ように許可します。データグラムの答えは 512 バイトまでです。すべてのアドレスが
  入らない答えには切り詰めの印（`TC`）を付け、TCP で問い合わせ直せるようにします。
  53 番ポートへの TCP の接続も、宛先のアドレスによらず DNS の代わりに届きます。
  2 バイトの長さを前に付けた問い合わせを受け取り、1 つずつ、すべてのアドレスを入れて
  答えます。
- **名前で届くのはグローバルなアドレスだけ**：ループバック、プライベート（RFC 1918 と
  ユニークローカル）、リンクローカル、共有（RFC 6598）、マルチキャスト、予約済みの
  アドレス（NAT64 や 6to4 のアドレスに含まれる IPv4 のアドレスとしても）は、DNS の代わりが答えから除き、名前の規則でも届きません。DNS がそこを指す
  名前（DNS リバインディング）で、ホスト自身やその内側のネットワークに届かないように
  するためです。アドレスが 1 つも残らない名前は `NXDOMAIN` です。`localhost` と
  そのサブドメインは、ループバックにも届きます。ほかのそういうアドレスに届くには、
  アドレスそのものを許可します（`127.0.0.1:8080`）。

### ループバックのサーバー {#loopback-servers}

TCP のソケットは、ゲスト自身のループバックの上で Linux と同じく `bind`、`listen`、
`accept` できます。UDP のソケットも、そこで `bind` してデータグラムをやり取りできます。ゲストのソケットが、待ち受けているループバックのアドレスに接続すると、
方針によらずカーネルの中で届き、ゲストの外には出ません。ホストもほかのマシンも、
ゲストの待ち受けには届きません。待ち受けていなければ、許可したアドレスはこれまで
どおりホストに届き、ほかは拒まれます。何も許可しないネットワーク（JavaScript の
`allow: []`、Rust の `NetworkPolicy::new()`）にもループバックはあります。コマンドで
ネットワークを作るには `--allow-net` が要ります。

- **`bind`** はループバックのアドレス（`127.0.0.0/8`、`::1`、IPv6 のソケットでは
  IPv4 を IPv4-mapped にしたもの）か未指定のアドレスに、ポートを付けて、ポート 0 なら
  32768〜60999 の一時的なポートを取ります。確かめ方とその順序は Linux と同じです。
  ほかのアドレスは `EADDRNOTAVAIL`、`bind` 済みなら `EINVAL`、両方が覆うアドレスで
  ほかのソケット（待ち受け、それが受け付けた接続、クライアント）がポートを持って
  いれば `EADDRINUSE` です。ただし、両方が `SO_REUSEADDR` を付けていて相手が待ち
  受けていないとき、両方が `SO_REUSEPORT` を付けているときは共有できます。`::` の
  IPv6 のソケットは、`IPV6_V6ONLY` でなければ IPv4 のポートも持ちます。`::` でも
  IPv4 のものでもない IPv6 のアドレスに `bind` すると、`__inet6_bind` と同じく
  `IPV6_V6ONLY` が付きます。
- **`listen`** は `backlog` + 1 本までの接続を待たせます（多くて 4096、
  `net.core.somaxconn`）。`bind` していないソケットは、すべてのアドレスで一時的な
  ポートを取ります。待ち受けているソケットは、接続が待っている間は読めます
  （`poll`、`select`、`epoll`、`O_ASYNC` の `POLL_IN`）。`SO_ACCEPTCONN` を示し、
  `FIONREAD` は `EINVAL`、`connect` は `EISCONN` で、`shutdown(SHUT_RD)` か
  `AF_UNSPEC` の `connect` で待ち受けをやめます。
- **`connect`** は、待ち受けの列が接続を受け取った時点で、`accept` の前に戻ります。
  ノンブロッキングなら Linux と同じく `EINPROGRESS` です。列がいっぱいなら接続は
  捨てられ、クライアントは、Linux が既定の `tcp_syn_linear_timeouts`（4）で
  するのと同じく、始めてから 1、2、3、4、5、7、11、19、35、67 秒後に試し直します。
  試し直しは、そのときそこで待ち受けているものに届き、列がまだいっぱいならまた
  捨てられ、待ち受けがなければ拒まれ（`ECONNREFUSED`）、131 秒でクライアントは
  `ETIMEDOUT` であきらめます。ブロッキングの `connect` が待つのは `SO_SNDTIMEO`
  までで、そのあとは `EINPROGRESS`、すでに進んでいたなら `EALREADY` です。
- **`accept`** と **`accept4`**（`SOCK_NONBLOCK`、`SOCK_CLOEXEC`）は、最初に
  待っている接続と相手のアドレスを返します。待ち受けているソケットがノンブロッキング
  でなければ、`SO_RCVTIMEO` まで待ちます（`EAGAIN`）。受け付けたソケットは、待ち
  受けているソケットのオプションを引き継ぎます。
- **`SO_REUSEPORT`**：これでポートを共有する、同じファミリーで同じアドレスの待ち受けは、
  Linux の `reuseport_select_sock` と同じく接続を分け合います。両端のアドレスとポートの
  ハッシュで、各接続が届く待ち受けを選びます。ただしハッシュは Linux のもの（その秘密の
  値は起動のたびに変わります）とは違います。待ち受けをやめたり閉じたりしたものには、
  それ以上届きません。ポートを共有する UDP のソケットも、同じようにデータグラムを分け
  合います。
- **`TIME_WAIT`**：接続を先に閉じた側（クライアントでも、`accept` した接続でも）は、
  Linux と同じくポートを持ちます。送ったバイトがまだ届いていない間（`FIN_WAIT1`）、
  そのあと相手の終わりが来るまで、`close` から、またはバイトが届いたのがそれより
  あとならそこから、最大 60 秒（`FIN_WAIT2`、`tcp_fin_timeout`）、そして相手の終わりから
  60 秒（`TCP_TIMEWAIT_LEN`）です。そこへの `bind` は `EADDRINUSE` で、
  `SO_REUSEADDR` を付けても、閉じたソケットにも付いていなければ同じです（`accept`
  した接続は待ち受けのものを引き継ぎます）。あとから閉じた側は何も持たず、リセット
  （次の項目）は、閉じた側への送信に答えるものも含めて、この保持を終わらせます。
  `shutdown` で先に終えて開いたままのソケットは、自分で取ったポートを、Linux の
  `tcp_done` と同じく相手の終わりから 60 秒で返し、ゲストが `bind` したポート
  （`SOCK_BINDPORT_LOCK`。`accept` した接続は待ち受けのものを引き継ぎます）は
  閉じるまで持ちます。
- **リセット**は Linux と同じです。読んでいない入力のあるソケットや `SO_LINGER` の
  時間が 0 のソケットを閉じたとき、`AF_UNSPEC` で切断したとき、まだ渡していない
  接続のある待ち受けを閉じたときは、相手をリセットします（相手は持っている分を
  読んだあと `ECONNRESET`）。閉じた相手に送ったバイトにはリセットが返り、次の送信は
  `EPIPE` です。
- **`SO_LINGER` の待ち**は Linux の `tcp_close` と同じです。`SO_LINGER` の時間が 0 で
  ないソケットの最後のディスクリプタを閉じると（`close`、`close_range`、その上への
  `dup2`、`FD_CLOEXEC` を付けたときの `execve`。`execve` では新しいプログラムが始まる前）、送ったバイトが相手の空きを待っている間、すべて届くか、時間が来るか、
  シグナルが来るまで待ちます。ノンブロッキングでも同じです。それでも閉じるのは成功し、
  バイトはそのあとも届きます。読んでいない入力のあるソケットは待たずにリセットし、
  終了するプロセスは待ちません。
- **バッファ**：送り手が設定した `SO_SNDBUF` と、受け手が設定した `SO_RCVBUF`
  （`accept` した接続は待ち受けのものを引き継ぎます）は、Linux と同じく、おおまかに接続を
  制限します。送るのを待つ分は 2 倍にした `SO_SNDBUF` まで、届いた分は 2 倍にした
  `SO_RCVBUF` の半分までで、小さくすると送り手は早く待つか `EAGAIN` になります。
  設定しない側は 256 KiB です。`SIOCOUTQ` と `FIONREAD` はこの 2 つを数えます。
- **緊急データ**は Linux の TCP と同じです。`MSG_OOB` を付けた送信の最後のバイトが
  緊急のバイトで、その前のバイトといっしょに相手に届きます。読み込みはその印の手前で
  止まり、印は `SIOCATMARK` でわかります。`FIONREAD` は印までを数え、`MSG_WAITALL`
  もそこで止まります。バイトが待っている間は、`poll`、`select` の例外の集合、`epoll` に
  `POLLPRI` が出ます。印にいる読み手が読めるのは、印の先にもバイトがあるときだけです。
  `MSG_OOB` を付けた `recv` は、そのバイトを 1 回だけ取ります（待っているものがなければ
  `EINVAL`、受け取る場所がなければ `MSG_TRUNC`、待ち受けでは `ENOTCONN`）。印から
  始まる読み込みはそのバイトを飛ばし、`MSG_OOB` がまだ取っていなければバイトはなくなり
  ます。あとの緊急のバイトは、前のものをふつうのデータにします。`SO_OOBINLINE` なら
  バイトはデータとして読まれ、読み込みはやはりその手前で止まり、`MSG_OOB` は `EINVAL`
  です。緊急のバイトはそれぞれ、受け取るソケットの持ち主に `SIGURG` を送ります。UDP は
  受信の `MSG_OOB` を無視し、それを付けた送信は `EOPNOTSUPP` です。
- **UDP** の `bind` は TCP と同じですが、ポートは UDP 自身のもので、両方が
  `SO_REUSEADDR` を付けていればポートを共有できます。ループバックのアドレスへの
  データグラムは、そこに `bind` したゲストのソケットに、Linux の `compute_score` と
  同じ選び方で届きます。接続したソケットは相手からだけ受け取り、そのアドレスに
  `bind` したもの、接続したもの、IPv4 のものが先で、同じなら最後に `bind` したものです。
  `SO_REUSEPORT` でポートを共有するものの間では、接続したものを飛ばして、同じハッシュで
  選んだものに届きます。別のアドレスから接続したものは、その共有から抜けます。
  `bind` せずに送るソケットは、すべてのアドレスで一時的なポートを取ります。接続する
  ソケットは、接続がそのあと失敗するとき（`IPV6_V6ONLY` のソケットから IPv4 の相手へは
  `ENETUNREACH`、ホストに経路がなければホストのエラー）でも先にポートを取ります。
  ポートは相手への経路の送り元のアドレスに移ります。相手がループバックならループバックの
  アドレス、ほかなら、ポリシーが許す相手ではホストの経路が選ぶホストのアドレスで（何も
  送らずに調べます。許さない相手ではすべてのアドレスのままです）、
  相手からだけ受け取ります。
  `AF_UNSPEC` で切断すると、ゲストが自分で `bind` したポートとアドレスだけが残ります。
  データグラムは IPv4 で 65507 バイト、IPv6 で 65527 バイトまでで（超えると
  `EMSGSIZE`）、空でもよく、読み手のバッファに切り詰められます（`MSG_TRUNC`）。
  `FIONREAD` は最初のものの長さです。それぞれは、x86-64 の Linux 7.0 が `sk_buff` の
  `truesize` として数える分を受信バッファから取り、ほかのものが待っている間に
  `SO_RCVBUF` を超えさせるものは、`__udp_enqueue_schedule_skb` と同じく捨てられます。
  空のバッファは、どの大きさのものでも 1 つ取ります。受け取るソケットがないときは、そこに接続した
  ソケットにループバックの ICMP の答えが届き、次の送信か受信が 1 回だけ
  `ECONNREFUSED` になります（`SO_ERROR` と `POLLERR` にも出ます）。53 番ポートへの
  データグラムで、受け取るゲストのソケットがないものは、これまでどおり DNS の代わりに
  届きます。
- **UDP の `shutdown`** は、接続していてもいなくてもソケットに印を付けます（接続して
  いなければ、Linux の `inet_shutdown` と同じく、それでも `ENOTCONN` を返します）。
  読む側を閉じると、待つはずの受信はすぐに 0 で終わります。ただしデータグラムは
  それまでどおり届き、先に読めます。ノンブロッキングの受信は `EAGAIN` です。送る側を
  閉じると、送信は `EPIPE` で、`SIGPIPE` は来ません。`poll` はそのあと `POLLIN` と
  `POLLRDHUP` を、両方を閉じると `POLLHUP` も示します。

## スレッドとプロセス

- `clone` で作ったゲストのスレッドは、ネイティブではホストのスレッドに、WebAssembly では
  Worker に割り当てます。
- `fork`／`vfork` 相当の `clone` と `execve` で、仮想ファイルシステムの中の別の
  プログラムを起動し、`wait4` で終了を受け取れます。Rust の `std::process::Command` も
  動きます。`posix_spawn` を使わずに fork するとき（たとえば `pre_exec` を使うとき）も
  同じです。
- `CLONE_THREAD` なしで `CLONE_VM | CLONE_SIGHAND` を付けた `clone` で作ったプロセスは、
  シグナルの処理の設定を親と共有します。片方の `sigaction` が、もう片方にも見えます。
  `execve` すると、Linux と同じく、そのプロセスは自分だけの設定に戻ります。
- プロセスのスレッドは、Linux の `sighand_struct` と同じく、シグナルの処理の設定を共有します。
  ほかのスレッドが `sigaction` を呼んだときにすでに待っていた（`epoll_wait`、`poll`、`futex` の
  待ちなど）スレッドも、プロセスあてのシグナルを新しいハンドラで受け取ります。そのため、補助の
  スレッドが待ち始めた後に設定した SIGCHLD のハンドラも動きます。Node.js の子プロセスにはこれが
  必要です。
- `ptrace` は Linux の `kernel/ptrace.c` と同じく、ほかのタスクをトレースします。
  `PTRACE_TRACEME` では、呼び出したタスクを fork したスレッドがトレーサーになります。
  `PTRACE_ATTACH` はカーネルからそのタスクに `SIGSTOP` を送り、`PTRACE_SEIZE` は
  `PTRACE_INTERRUPT` のときだけ止めます。`PTRACE_ATTACH` と `PTRACE_SEIZE` はどちらも、呼び出したプロセス自身のタスク、すでに
  トレースされているか終了したタスク、アタッチしてはいけないタスク（実 ID での
  `ptrace_may_access` と、Yama の `ptrace_scope` 1）を `EPERM` で断ります。要求を出せるのは
  トレーサーのスレッドだけで、相手が ptrace 停止にあるときだけです（`PTRACE_KILL` と
  `PTRACE_INTERRUPT` を除き、`ESRCH`）。アタッチまたは SEIZE の時点ですでにグループ停止にある
  タスクには、その停止を新しいトレーサーへ報告させ、報告し終えてから呼び出しが返ります。
- トレースされたスレッドは、`SIGKILL` 以外の受け取るシグナルごと（無視するものも含む）と、
  グループ停止でトレーサーのために止まります。グループ停止は、SEIZE したタスクなら siginfo
  付きの `PTRACE_EVENT_STOP`、それ以外なら停止シグナルだけとして報告します。`PTRACE_CONT` は、
  止まったシグナル、シグナルなし、別のシグナル（トレーサーからの `SI_USER` になります）、または
  `PTRACE_SETSIGINFO` が残した siginfo で再開させます。ブロックしているシグナルは待ちます。
  グループ停止から再開したトレース対象は、グループが止まったままでも動きます。
  `PTRACE_DETACH` はシグナルを渡して手放し、`PTRACE_KILL` はそのプロセスに `SIGKILL` を
  送ります。トレース中のプロセスは、`SIGKILL` 以外の致命的なシグナルを送られた時点では受けず、
  まずトレーサーがそれを見ます。
- `wait4` と `waitid` は、オプションが何を求めていても、トレース対象の ptrace 停止を
  トレーサーに報告します（`CLD_TRAPPED`、状態ではシグナルの上にイベント）。トレースされた
  スレッドは `__WALL` なしでも報告し、`__WNOTHREAD` では呼び出したスレッドがトレースする
  ものだけです。子をトレースする親は、子のグループ停止の代わりに ptrace 停止を見ます。終了した
  トレース対象のスレッドはトレーサーの wait を待ち、親以外にトレースされたプロセスの終了は、
  まずトレーサーに、次に親に伝わります。
- トレース対象が止まっている間、トレーサーは `PTRACE_PEEKTEXT`／`PTRACE_PEEKDATA` と
  `PTRACE_POKETEXT`／`PTRACE_POKEDATA` で、`FOLL_FORCE` と同じくそのメモリを読み書きします。
  マップされたページはどれも読め、書き込めない private のページには自分の写しができ、書き込めない
  共有のページは断ります（`EIO`）。レジスタは `PTRACE_PEEKUSER`／`PTRACE_POKEUSER`
  （`struct user`）、`PTRACE_GETREGS`／`PTRACE_SETREGS`、`PTRACE_GETFPREGS`／
  `PTRACE_SETFPREGS`、`NT_PRSTATUS` と `NT_PRFPREG` の `PTRACE_GETREGSET`／
  `PTRACE_SETREGSET` で読み書きし、Linux の `putreg` と同じ値を受け付けます（トレーサーが
  変えてよいフラグだけ、セグメントのベースは `TASK_SIZE_MAX` 未満、セグメントセレクタは null か
  ユーザーのもので、`cs` と `ss` は null 以外、それ以外は `EIO`。セレクタは書いたとおりに残り、
  `fs` と `gs` の新しいセレクタは FSGSBASE と同じくベースを変えません。exec で初めの値に
  戻ります）。停止の
  siginfo は `PTRACE_GETSIGINFO`／`PTRACE_SETSIGINFO` で扱います（siginfo のない停止では
  `EINVAL`）。`orig_rax` は止まる直前のシステムコール、それ以外の後では -1 です。停止が
  割り込んだシステムコールは `rax` に再実行のコード（`-ERESTARTSYS`、`-ERESTARTNOINTR`、
  `-ERESTARTNOHAND`、`-ERESTART_RESTARTBLOCK`）を見せます。Linux と同じく、トレーサーが
  そこに残したコードで再実行が決まり（別の再実行のコードならそのとおりに、
  `-ERESTART_RESTARTBLOCK` は `restart_syscall` として）、ほかの値や、`orig_rax` を -1 に
  したときは再実行せず、コードがそのまま戻り値になります。`orig_rax` を変えると、そのシステム
  コールが実行されます。停止中にトレース対象へ送られたシグナルは、Linux の `get_signal` が停止の後も
  続けるのと同じく、停止が終わるときに再実行より先に受け取り、トレース対象は `rax` に再実行の
  コードを残したままそのシグナルで止まります。グループが停止中に解放されたトレース対象は停止したままで、
  グループが再開してからシグナルを受け取ります。`PTRACE_O_SUSPEND_SECCOMP` は、トレース対象のシステムコールを
  seccomp のフィルターと strict モードに通さず、checkpoint／restore のある Linux と同じく、
  設定には `CAP_SYS_ADMIN` と、seccomp のないトレーサーが要ります（`EPERM`）。
- `PTRACE_SYSCALL` で再開したトレース対象は、システムコールの入口と出口ごとに止まります
  （`SIGTRAP`、`PTRACE_O_TRACESYSGOOD` があれば `SIGTRAP | 0x80`）。`PTRACE_SYSEMU` では入口だけで
  止まり、システムコールは実行されません。入口では `rax` が `-ENOSYS`、`orig_rax` がシステム
  コールで、トレーサーはシステムコールと引数を変えられ、`orig_rax` を -1 にすると、`rax` を
  残したい値にしたまま実行を飛ばします。出口では `rax` が戻り値で、トレーサーはそれを変え
  られます。システムコール停止をシグナル付きで再開すると、そのシグナルはカーネルから
  （`SI_KERNEL`）プロセスに送られます。`PTRACE_GET_SYSCALL_INFO` は Linux の `struct ptrace_syscall_info` と
  同じく停止を示します。入口ではシステムコールと引数、出口では戻り値とエラーかどうか、
  ほかの停止や `PTRACE_O_TRACESYSGOOD` なしでは命令ポインタとスタックポインタだけです。
  `PTRACE_SET_SYSCALL_INFO` はシステムコール、引数、戻り値を変えます。種類の違う停止、
  フラグ、足りないバッファは `EINVAL`、`int` に収まらない番号は `ERANGE` です。
- `PTRACE_O_TRACEFORK`、`PTRACE_O_TRACEVFORK`、`PTRACE_O_TRACECLONE`、`PTRACE_O_TRACEEXEC`、
  `PTRACE_O_TRACEVFORKDONE`、`PTRACE_O_TRACEEXIT` のイベントでは、トレース対象はステータスの
  `SIGTRAP` の上にイベントを載せて止まり、`rax` は `-ENOSYS` です。`PTRACE_GETEVENTMSG` は
  新しいタスク、`execve` 前のスレッド ID、終了ステータスを返します。トレーサーがイベントを
  求めている間に `clone`、`fork`、`vfork` が作ったタスク、または `CLONE_PTRACE` 付きで作った
  タスク（`CLONE_UNTRACED` 付きは除く）は、同じトレーサーに同じオプションでトレースされ、
  SEIZE なら `PTRACE_EVENT_STOP` で、それ以外は保留中の `SIGSTOP` を持って始まります。
  システムコール停止は持たずに始まります。`vfork` の親は、子が終了するか別のプログラムを
  実行した後に `PTRACE_EVENT_VFORK_DONE` を報告します。プロセスを終わらせたスレッドは
  `PTRACE_EVENT_EXIT` を報告し（致命的なシグナルがコアをダンプするときは、ステータスに
  0x80 が付きます）、それとともに終わるスレッドは報告しません。
- トレーサーは `PTRACE_POKEUSER` でデバッグレジスタにハードウェアブレークポイントを設定でき、
  Linux の `ptrace_set_debugreg` と同じ値を受け付けます。DR0〜DR3 はアドレスで、ユーザー空間に
  あってブレークポイントの長さにそろっていなければなりません（`EINVAL`）。DR7 はそれらを有効にし、
  種類（命令（1 バイト）、書き込み、読み書き）と長さ（1、2、4、8）を与えます。I/O の
  ブレークポイントや長い命令のブレークポイントは `EINVAL` で、DR7 は元のままです。DR4 と DR5 は
  ありません（`EIO`）。命令のブレークポイントはその命令の前でトレース対象を止め、再開したときに
  一度は実行されるよう RF を立てます。データのブレークポイントは範囲にアクセスした命令の後で
  止めます。`rep` 付きの文字列命令ではその回の後で、繰り返しの途中なら `rip` はその命令のままです。どちらも `TRAP_HWBKPT` の `SIGTRAP` で、アドレスは `rip` です。DR6 には
  ブレークポイントのビットが、シングルステップの後は `DR_STEP` が立ちます。新しいタスクは
  ブレークポイントを持たず、exec で消えます。ひとつもなければゲストはこれまでと同じ速さで、
  あれば 1 命令ずつ動きます。
- `PTRACE_SINGLESTEP` はトラップフラグを立ててトレース対象を再開します。トレース対象が
  自分で立てたのでなければ、トレーサーにはレジスタで見えず（`TIF_FORCED_TF`）、ほかの再開で
  消えます。トレース対象は 1 命令の後に `SIGTRAP` で止まり、`syscall` の後はその出口で
  `TRAP_BRKPT` で止まります。シングルステップ中のトレース対象は、シグナルハンドラーに入る前に
  `SIGTRAP` で止まり、そこでステップは終わります。ハンドラーのフレームには、トレーサーが
  立てたトラップフラグは残りません。`PTRACE_SYSEMU_SINGLESTEP` も同じくステップし、さらに
  `PTRACE_SYSEMU` と同じく、各システムコールの入口で止まって実行しません。
- `PTRACE_PEEKSIGINFO` は、止まっているトレース対象に、`PTRACE_PEEKSIGINFO_SHARED` 付きでは
  そのプロセスに保留中のシグナルの siginfo を、来た順に読みます。`PTRACE_GETSIGMASK` は
  ブロックしているシグナル（`sigsuspend` や `ppoll` の待ちの間は、戻すマスク）を示し、
  `PTRACE_SETSIGMASK` は再開後のそれを設定します（SIGKILL と SIGSTOP は含めません）。
  `PTRACE_LISTEN` は、グループ停止中の SEIZE されたトレース対象を、wait やほかの要求から
  停止に見えないまま待たせます。グループ停止が終わるか始まり直すか、`PTRACE_INTERRUPT` が
  来ると、もう一度 `PTRACE_EVENT_STOP` を報告します。`PTRACE_ARCH_PRCTL` は `arch_prctl` と
  同じく `fs` と `gs` のベースを読み書きし、`PTRACE_GET_RSEQ_CONFIGURATION` はトレース対象の
  `rseq` の登録を示します。
- `PTRACE_SEIZE` でも `PTRACE_O_TRACEEXEC` でもなくトレースされたタスクは、`execve` の後に
  自分から `SIGTRAP` を受けます。リーダー以外のスレッドが `execve` すると、その後はリーダーの
  番号でトレースされます。トレーサーのスレッドが終了するとトレース対象は手放され、`PTRACE_O_EXITKILL` を設定したものは
  殺されます。`/proc/<pid>/status` は `TracerPid` を示し、ptrace 停止中のトレース対象は
  `t (tracing stop)` です。

## シグナル

- 登録、マスク、配送（Linux の x86-64 のシグナルフレームと `rt_sigreturn`）、
  `sigaltstack`、リアルタイムシグナルのキュー、`SIGSTOP` による停止と再開を扱います。
  停止で中断されたブロッキングの呼び出しは、ハンドラが動かないときの Linux と同じく、
  再開の後にやり直します。対象は `read`、`write`、`readv`、`writev`、`pread64`、`pwrite64`、`preadv`、`pwritev`、`preadv2`、`pwritev2`、`wait4`、`waitid`、`pause`、`rt_sigsuspend`、`flock`、
  `fcntl` の `F_SETLKW` と `F_OFD_SETLKW`、FIFO を開く `open`・`openat`・`openat2`、`accept`、`accept4`、`sendto`、`recvfrom`、`sendmsg`、`recvmsg`、`sendmmsg`、`recvmmsg`、`msgsnd`、`msgrcv`、`mq_timedsend`、`mq_timedreceive`、`sendfile`、`splice`、`tee`、`vmsplice`、`ppoll`、`select`、`pselect6`、時間制限なしの `poll`、時間制限なしの `futex` の待ち、時間制限の有無にかかわらず `futex_waitv` と futex2 の `futex_wait` です。
  `nanosleep`、相対時間の `clock_nanosleep`、時間制限つきの `poll`、時間制限つきの `futex` の待ちは、
  `restart_syscall` で元の締め切りのまま待ちを続け（`futex` は先に値をもう一度確かめ、変わっていれば
  `EAGAIN` を返します）、絶対時刻の `clock_nanosleep` はもう一度実行します。ハンドラが
  動いたときはやり直さず、`EINTR` を返します。
  `SA_RESTART` を付けたハンドラが動いたときは、Linux と同じく、ハンドラから戻った後に、停止の後にやり直す呼び出し（`read` から時間制限なしの `futex` の待ちまで）をやり直します。
  ただし `pause`、`rt_sigsuspend`、`msgsnd`、`msgrcv`、`poll`、`ppoll`、`select`、`pselect6` と、`SO_RCVTIMEO` や `SO_SNDTIMEO`
  で待ちに時間制限のあるソケットの呼び出しと、そうしたソケットへの `sendfile` は、`EINTR` を返します。
  停止が終わるときに保留中の、ハンドラのあるシグナル（`SIGCONT` の前に送られたものなど）は、
  Linux の `get_signal` が停止の後も続けるのと同じく、そのときに受け取ります。呼び出しはそのハンドラに
  従って終わり、`pause` は `EINTR` を返します。`SIGCONT` のすぐ後に送られたものは、Linux と同じく、
  シグナルが見つからなかった後に届くことがあります。そのときは呼び出しがもう巻き戻されていて、
  ハンドラはそこへ戻ります。
  `epoll_wait`、`epoll_pwait`、`epoll_pwait2`、`rt_sigtimedwait` は、Linux と同じく `EINTR` を返します。
  `rt_sigsuspend` は、シグナルのマスクを渡されたマスクに置き換えてハンドラが動くまで待ちます。
  ハンドラはそのマスクで動き、終わると元のマスクに戻ります。Linux と同じく、そのマスクは停止の間も
  残るので、停止中に送られた、そのマスクだけが通すシグナルは、停止が終わるときに受け取ります。
- シグナルを無視にする `sigaction`（`SIG_IGN` か、既定で無視される `SIGCHLD`、`SIGCONT`、
  `SIGURG`、`SIGWINCH` への `SIG_DFL`）は、Linux の `do_sigaction` と同じく、プロセスと
  すべてのスレッドで保留中のそのシグナルを捨てます。その後に送られたブロック中の
  シグナルは、保留のまま残ります。ブロックされていない無視されるシグナル（終わった子の
  `SIGCHLD` など）は、どのスレッドの待ちも終わらせません。Linux が送る時点で捨てる
  （`sig_ignored`）のと同じく、ブロック中の `read` はそのまま待ち続け、`nanosleep` は
  眠り続けます。

## ファイルシステム

- 既定では、実行ごとに、ほかと切り離されたメモリ上のファイルシステムを作ります。
  `/tmp` もあります。
- 作成、読み書き、ハードリンク、シンボリックリンク、`flock`、`rename`、ディレクトリの
  一覧、`stat` 系に対応しています。開いているファイルは `unlink` の後も使えます。
- `renameat2` は、名前を置き換えずに断る `RENAME_NOREPLACE`（`EEXIST`）と、
  二つの名前を入れ替える `RENAME_EXCHANGE`（片方がなければ `ENOENT`）に対応して
  います。メモリ上でも、Linux か macOS でマウントしたホストのディレクトリでも使えます。
  `RENAME_WHITEOUT` には `CAP_MKNOD` が要り（なければ `EPERM`）、あっても
  ホワイトアウトのない Linux のファイルシステムと同じく `EINVAL` を返します。
- `/dev` と `/proc` の外にあって、その中を指すシンボリックリンク
  （`ln -s /dev/null f` が作るものや、途中にある `/dev` へのリンク）は、カーネルが
  そこに作るファイルにつながります。`stat`、`statx`、`access`、`open` と、パスを
  たどるほかの呼び出しは、リンク先のパスと同じようにそこで続きます（`readlink` は
  `/dev/fd` のようなそこのリンクを読み、`xattr` の呼び出し、`statfs`、`link`、
  `name_to_handle_at` は、その `*at` の形も、生成されるファイルを扱います）。それを
  通して開いたディスクリプタは、`/proc/self/fd` でそのファイルを指します。
- カーネルが `/dev` と `/proc` に生成するファイルは、そのパスでもそうしたリンクを
  通しても、ファイルを変えるパスの呼び出しを、Linux の `notify_change` と同じように
  受けます。`chmod`、`chown`、`utimensat` とほかの時刻の呼び出しは、ほかのファイルと
  同じく所有者とモードを確かめます。procfs は、プロセスのファイルの新しいモード
  （`proc_setattr`）と、sysctl のファイルの新しいモードや所有者（`proc_sys_setattr`）を
  `EPERM` で断ります。`/dev/pts` の疑似端末のスレーブは、所有者から新しいモードと
  所有者を受けます。そこの通常のファイルへの `truncate` は、書き込めるなら成功して
  何も変えず、ディレクトリなら `EISDIR`、デバイスなら `EINVAL` です。`chdir` と
  `fchdir` はそこのディレクトリを作業ディレクトリにし、`getcwd` はそれを返し、相対
  パスはそこから始まります。
- `linkat` は `AT_SYMLINK_FOLLOW` と `AT_EMPTY_PATH` に対応しています。
  `AT_SYMLINK_FOLLOW` は古いパスの最後のシンボリックリンク（リンク先がなければ
  `ENOENT`）と、`/proc/self/fd` のリンクをディスクリプタのファイルまでたどります。
  `AT_EMPTY_PATH` は古いパスが空のとき、ディスクリプタ（`O_PATH` のものも）が持つ
  ファイルをリンクします（ディレクトリは `EPERM`）。削除したファイルはもうリンク
  できず（`ENOENT`）、memfd、パイプ、ソケット、`/proc` のファイルは別のファイル
  システムにあります（`EXDEV`）。Linux 6.10 以降は、呼び出し元と違う資格情報で
  開いたファイルへの `AT_EMPTY_PATH` を、`CAP_DAC_READ_SEARCH` がなければ断ります
  （`ENOENT`）が、paludarium はこれを確かめません。
- Landlock は、スレッドがアクセスできるファイルの階層と TCP のポート、ドメインの外で
  届くものを、ABI バージョン 8 と errata 1〜4 の範囲で制限します。
  `landlock_create_ruleset`（バージョンと errata の問い合わせを含む）、
  `LANDLOCK_RULE_PATH_BENEATH` と `LANDLOCK_RULE_NET_PORT` の `landlock_add_rule`、
  `landlock_restrict_self`（`no_new_privs` か `CAP_SYS_ADMIN` が要ります）に対応し、
  層は 16 までです。各層は、扱う権利を、ルールが指すファイルやディレクトリの下でだけ
  許します。ルールはデバイスと
  inode で指すので、名前を変えたディレクトリにもついていきます。ファイルを開くと
  `LANDLOCK_ACCESS_FS_READ_FILE`、`WRITE_FILE`、`READ_DIR` を、`execve` とその
  インタープリタでは `EXECUTE` を確かめます。名前を作るときはディレクトリについて
  種類ごとの `MAKE_*` を、消すときは `REMOVE_FILE` か `REMOVE_DIR` を、切り詰めるときは
  `TRUNCATE` を確かめます。`TRUNCATE` は、開いたときの結果を開いたファイルの記述が
  持ち続けます。キャラクタデバイスとブロックデバイスへの `ioctl` には `IOCTL_DEV` が要り、
  これも開いたときの結果を持ち続けます。ただし、どのファイルでも答えるコマンド
  （`FIOCLEX`、`FIONBIO`、`FIGETBSZ` など）は除きます。別のディレクトリへのリンクや
  名前の変更には `REFER` が要り、ファイルの権利が増えてはいけません（`EXDEV`）。
  TCP のソケットの `bind` にはそのポートの `LANDLOCK_ACCESS_NET_BIND_TCP` が、`connect`
  には `CONNECT_TCP` が要ります。その前に、Linux と同じくアドレスを確かめます。
  UDP と、`AF_UNSPEC` への `connect` は確かめません。ホワイトアウト（`mknod` が
  キャラクタデバイス 0 として作り、`RENAME_WHITEOUT` が残すもの）には `MAKE_REG` が
  要ります。ルールセットのスコープは、ドメインの外のスレッドが作ったものや、そのスレッド
  そのものからスレッドを遠ざけます。`LANDLOCK_SCOPE_SIGNAL` はそのスレッドへのシグナルを、
  `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` はそのスレッドが作った抽象名前空間の unix
  ソケットへの接続と送信を断ります（`EPERM`）。同じプロセスのスレッドどうしは、いつでも
  シグナルを送れます。`ptrace` と同じく、ドメインの中のスレッドは、外のタスクの
  `/proc/<pid>/environ` などを読めません。`landlock_restrict_self` は記録のフラグと
  `LANDLOCK_RESTRICT_SELF_TSYNC` を受け付け、TSYNC はプロセスのすべてのスレッドに、
  それまでのドメインの代わりに新しいドメインを与えます。記述子が -1 のときは
  `LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF` だけか、それと TSYNC を受け付け、TSYNC は
  ほかのスレッドに呼び出し元のドメインを与えます。-1 にほかのフラグを付けると `EBADF` です。
  スレッド、プロセス、`execve` はドメインを引き継ぎます。`O_PATH`、`stat`、制限の前に
  開いた記述子は確かめません。
- seccomp は、Linux の `kernel/seccomp.c` と同じように、スレッドが使えるシステム
  コールを制限します。strict モード（`SECCOMP_SET_MODE_STRICT`、または
  `PR_SET_SECCOMP` の 1）で許されるのは `read`、`write`、`exit`、`rt_sigreturn`
  だけです。ほかの呼び出しは、`exit_group` も含めて、スレッドを `SIGKILL` で
  終わらせます。フィルターモード（`SECCOMP_SET_MODE_FILTER`。`no_new_privs` か
  `CAP_SYS_ADMIN` が要ります）は、クラシック BPF のプログラムを足します。
  プログラムは Linux と同じように確かめます。命令は 4096 個までで、seccomp が
  受け付けるもの（`struct seccomp_data` からの 32 ビットの読み込み。`mod` は
  使えません）だけです。ジャンプは前向きでプログラムの中に収まり、スクラッチの語は
  どの道筋でも読む前に書かれ、最後の命令は戻る命令でなければなりません。そうでなければ
  `EINVAL` です。スレッドのフィルターは合わせて 32768 命令まで（それぞれ 4 命令多く
  数えます）で、超えると `ENOMEM` です。呼び出しの前に、すべてのフィルターが、
  呼び出しの番号、`AUDIT_ARCH_X86_64`、`syscall` 命令の次のアドレス、6 つの引数の
  レジスタ全体を見て、いちばん低いアクションが決めます。
  `SECCOMP_RET_KILL_PROCESS` はプロセスを `SIGSYS` で終わらせます。
  `SECCOMP_RET_KILL_THREAD` はスレッドを、最後のスレッドならプロセスを終わらせます
  （X が 0 の割り算は 0 を返すので、このアクションになります）。
  `SECCOMP_RET_TRAP` は `SIGSYS` を強制し、`SYS_SECCOMP`、`si_errno` のデータ、
  呼び出しのアドレス、番号、アーキテクチャを渡し、`rax` には呼び出しの番号を戻します。
  `SECCOMP_RET_ERRNO` はデータ（4095 まで）をエラーとして返します。
  `SECCOMP_RET_TRACE` は、トレーサーが `PTRACE_O_TRACESECCOMP` で求めていれば、データを
  イベントのメッセージにして `PTRACE_EVENT_SECCOMP` でスレッドを止めます。トレーサーは呼び出しを
  変えるか、`orig_rax` を 0 未満にして飛ばせ、呼び出しはもう一度フィルターを通ります。そういう
  トレーサーがなければ `ENOSYS` です。
  `SECCOMP_RET_USER_NOTIF` はフィルターのリスナー（下に書きます）の答えを待ち、
  フィルターにリスナーがなければ `ENOSYS` です。`SECCOMP_RET_LOG` と
  `SECCOMP_RET_ALLOW` は呼び出しをそのまま行います。`SECCOMP_FILTER_FLAG_TSYNC` は新しいフィルターを
  すべてのスレッドに与えます。ただし、strict モードのスレッドや、呼び出し側の
  フィルターの元にならないフィルターを持つスレッドがあれば、そのスレッドの ID を
  返します（`SECCOMP_FILTER_FLAG_TSYNC_ESRCH` があれば `ESRCH`）。
  `SECCOMP_GET_ACTION_AVAIL` と `SECCOMP_GET_NOTIF_SIZES` は Linux と同じに
  答えます。新しいスレッドとプロセスはモードとフィルターを受け継ぎ、`execve` でも
  残ります。`/proc/<pid>/status` の `Seccomp` と `Seccomp_filters` に表れます。
  `SECCOMP_FILTER_FLAG_NEW_LISTENER` は、新しいフィルターのリスナーを close-on-exec
  で返します（`anon_inode:seccomp notify`。スレッドのフィルターにリスナーは 1 つ
  だけで、2 つ目は `EBUSY` です）。フィルターがそこへ送った呼び出しは、
  `SECCOMP_IOCTL_NOTIF_RECV` が受け取り（まだ受け取られていない中でいちばん古い
  もので、乱数から始まる ID、スレッドの ID、`seccomp_data` が渡ります）、
  `SECCOMP_IOCTL_NOTIF_SEND` が値、エラー、または呼び出しをそのまま行わせる
  `SECCOMP_USER_NOTIF_FLAG_CONTINUE` で答えるまで待ちます。その間に
  `SECCOMP_IOCTL_NOTIF_ADDFD` は、リスナー側のファイルを、待っているスレッドの
  空いているいちばん小さいディスクリプターか指定のディスクリプターに入れさせます。
  `SECCOMP_ADDFD_FLAG_SEND` なら、呼び出しはそのディスクリプターを返します。
  `SECCOMP_IOCTL_NOTIF_ID_VALID` と `SECCOMP_IOCTL_NOTIF_SET_FLAGS` は Linux と
  同じに答えます。リスナーは、受け取られるのを待つ呼び出しがあれば読み込み可能、
  受け取られて答えを待つ呼び出しがあれば書き込み可能、フィルターを使うスレッドが
  いなくなればハングアップとして poll に表れます。待っている呼び出しはシグナルで
  `EINTR` として戻ります。`SA_RESTART` のハンドラーか停止の後は、新しい呼び出しと
  してもう一度行われます（Linux master の
  `SECCOMP_FILTER_FLAG_RESTART_BEFORE_RECV` では、まだ受け取られていない呼び出し
  なら、どのハンドラーの後でも行われます）。そのとき、その呼び出しの分の受け取りは、
  Linux と同じく何も見つけません（`ENOENT`）。
  `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` では、受け取られた呼び出しは、致命的な
  シグナル以外では戻らずに待ち続けます。リスナーを閉じると、待っている呼び出しには
  すべて `ENOSYS` が返り、その後の呼び出しも `ENOSYS` です。
- 起動の前にファイルを置けます。
- 指定したときだけ、ホストのディレクトリをマウントできます（コマンドの `--mount`、
  Rust の `Config::mounts`）。操作はすべてそのディレクトリの中に閉じ込められ、
  `..` やシンボリックリンクで外には出られません。その中でも `getdents64` は `.` と `..` を
  返し、inode は `stat` の値と同じです。残りはホストの一覧と同じ順序で返します。

## 確かめたプログラム {#programs-verified}

- C と Rust の hello world と、命令ごとの小さなテストのプログラム。
- **probe**：スレッドとファイルシステムの機能を 8 項目で確かめる Rust のプログラム
  （tokio のタイマー、UNIX のソケットの組、rayon の並列処理、Mutex と Condvar、
  ファイル操作、ハードリンク、シンボリックリンク、`flock`）。
- **aube**：Rust で書かれた Node.js のパッケージマネージャ（v2.10.0）。`--version`、
  `install`、`install --frozen-lockfile`、`list` の 4 つの操作が、本物の Linux と
  同じ出力と終了コードになります。
- **ripgrep**：Rust で書かれたテキストの検索のツール（15.2.0）。検索を複数のスレッドで
  動かします。正規表現での置き換え、並列の検索、ファイルをメモリへマップした検索、2 つの
  エラーを含む 9 つの検索が、本物の Linux と同じ出力と終了コードになります。
  `--version` は比べていません。`CPUID` が見せる SIMD の機能を表示するためで、
  paludarium はそれをわざと絞っています。
- **coreutils**：uutils の coreutils（0.13.0）。GNU のユーティリティを Rust で書き直した
  もので、1 つのマルチコールのバイナリとしてビルドします。47 のユーティリティの 68 のケースが、
  本物の Linux と同じ出力と終了コードになり、ファイルを変える 15 のケースでは、
  できたファイルも同じになります。テキストを読む・並べる・切り出す・数える、ハッシュと
  エンコード、ファイルの一覧と `stat`、2 つのタイムゾーンでの日時の表示、ファイルの
  コピー・移動・リンク・分割・削除を、ファイルがない、ディレクトリが空でないといった
  エラーも含めて比べます。`id`、`uname`、`pwd`、`env` は比べていません。ホストの
  ユーザー、パス、環境を表示するためです。

これらはすべて、Linux・macOS・Windows と、Node.js・Chromium・Firefox・Safari
のすべてで、本物の x86-64 Linux と同じ結果になることを確かめています。
