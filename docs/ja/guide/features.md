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
- **SSE 系**：実際のプログラム（probe、aube、pitchfork）が使う SSE 系の 145 の命令
  （フェンスの `MFENCE`／`LFENCE`／`SFENCE` を含む）と、AES・PCLMUL・SHA などの暗号の命令。浮動小数点はソフトウェアで計算します。
- 命令のデコードには [iced-x86](https://github.com/icedland/iced) を使っています。
- `CPUID` はホストの値を見せません。実装していない機能は広告しません。
- AVX、AVX-512、x87、MMX は対象外です。

ゲストが実行できない命令に当たったときは、本物の Linux と同じようにゲストに
`SIGILL` を送ります。ページフォールトは `SIGSEGV`、整数の 0 除算は `SIGFPE` になります。

## システムコール

実装したシステムコールだけを、明示した表で扱います。それ以外はすべて `ENOSYS` を返し、
ホストに渡すことはありません。次の表には実装したシステムコールをすべて載せていて、
`lint:all` がカーネルと照らし合わせます。

| 分類 | システムコール |
|---|---|
| プロセスとスレッド | `clone`、`clone3`、`fork`、`vfork`、`execve`、`wait4`、`waitid`、`pidfd_open`、`pidfd_send_signal`、`exit`、`exit_group`、`getpid`、`getppid`、`gettid`、`set_tid_address`、`futex`、`sched_getaffinity`、`sched_yield`、`setpgid`／`getpgid`／`getpgrp`、`setsid`／`getsid`、`getpriority`／`setpriority`、`prlimit64`／`getrlimit`／`setrlimit`、`prctl` |
| メモリ | `mmap`（anonymous と、プライベートまたは共有のファイル）、`munmap`、`mremap`、`mprotect`、`madvise`、`msync`、`brk`、`arch_prctl` |
| システムの情報 | `uname`、`sysinfo`、`getuid`、`geteuid`、`getgid`、`getegid`、`getgroups`、`getrusage`、`times` |
| シグナル | `rt_sigaction`、`rt_sigprocmask`、`rt_sigreturn`、`sigaltstack`、`kill`、`tkill`、`tgkill`、`setitimer`、`rt_sigtimedwait`、`rt_sigqueueinfo`、`rt_tgsigqueueinfo`、`rt_sigpending`、`rt_sigsuspend`、`pause`、`restart_syscall` |
| 時刻 | `clock_gettime`、`clock_getres`、`nanosleep`、`clock_nanosleep`、`timer_create`／`timer_settime`／`timer_gettime`／`timer_getoverrun`／`timer_delete` |
| ファイル | `open`／`openat`／`creat`、`read`、`write`、`readv`／`writev`、`pread64`／`pwrite64`、`preadv`／`pwritev`、`copy_file_range`、`sendfile`、`close`、`close_range`、`lseek`、`stat`／`fstat`／`lstat`／`newfstatat`、`statx`、`getdents64`、`mkdir`／`mkdirat`、`rmdir`、`unlink`／`unlinkat`、`rename`／`renameat`、`link`／`linkat`、`symlink`／`symlinkat`、`readlink`／`readlinkat`、`truncate`／`ftruncate`、`fallocate`、`memfd_create`、`flock`、`fcntl`、`dup`／`dup2`／`dup3`、`pipe`／`pipe2`、`chdir`／`fchdir`、`getcwd`、`umask`、`chmod`／`fchmod`／`fchmodat`、`chown`／`fchown`／`lchown`／`fchownat`、`utimensat`、`fsync`／`fdatasync`、`sync`、`fadvise64`、`access`／`faccessat`／`faccessat2`、`statfs`／`fstatfs` |
| 入出力 | `poll`、`ppoll`、`select`、`pselect6`、`ioctl`（`TCGETS`、`TIOCGWINSZ`、`FIOCLEX`、`FIONCLEX`、`FIONBIO`、`FIOASYNC`、`FIOQSIZE`、`FIGETBSZ`、`SIOCATMARK`、`FIONREAD`/`SIOCINQ`、`SIOCOUTQ`） |
| イベント | `eventfd2`、`timerfd_create`／`timerfd_settime`／`timerfd_gettime`、`epoll_create`／`epoll_create1`、`epoll_ctl`、`epoll_wait`、`epoll_pwait` |
| ソケット | `socket`（AF_UNIX のストリーム、パケット、データグラムのソケット。[ネットワーク](#network)があれば `AF_INET` と `AF_INET6`、なければ `EAFNOSUPPORT`）、`connect`、`getsockname`、`getpeername`、`bind`、`listen`、`accept`、`accept4`（AF_UNIX のストリームとパケットのソケット、ゲスト自身の[ループバック](#loopback-servers)の上の TCP）、`socketpair`（AF_UNIX、`SOCK_STREAM`、`SOCK_SEQPACKET`、`SOCK_DGRAM`）、`sendto`、`recvfrom`、`sendmsg` と `recvmsg`（`SCM_RIGHTS` でのディスクリプタ、`SCM_CREDENTIALS` での資格情報、`SCM_PIDFD` での送り手の pidfd の受け渡し）、`setsockopt` と `getsockopt`（`SOL_SOCKET`）、`shutdown` |
| 乱数 | `getrandom` |

- `pread64`・`pwrite64`・`preadv`・`pwritev` はファイルの位置を動かさず、パイプとソケットでは
  `ESPIPE` を返します。`O_APPEND` のファイルでは、Linux と同じく位置を指定した書き込みも
  末尾に足します。
- `copy_file_range` は、同じマウントにある 2 つの通常のファイルの間でコピーし（マウントを
  またぐと `EXDEV`）、入力の末尾で止まります。確かめる順番は Linux と同じです（`EISDIR`、
  `EINVAL`、`EBADF`、`EOVERFLOW`、同じファイルの中で範囲が重なると `EINVAL`）。
  `sendfile` は、通常のファイルを書き込める任意のファイルに送り、パイプには 1 回でその容量
  までを送ります。どちらも、渡されたオフセットかファイルの位置を進めます。`sendfile` は、
  失敗したときもオフセットを書き戻します。
- `statx` は、`stat` にある項目（`STATX_BASIC_STATS`）と、デバイス番号としてマウントの
  `st_dev` を返します。flags と mask は Linux と同じように確かめます（`EINVAL`）。
  `AT_EMPTY_PATH` はディスクリプタを、`AT_FDCWD` なら作業ディレクトリを指し、Linux 6.11
  からと同じく、それとともに渡した空ポインタのパスも同じ扱いです。
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
- `close_range` は `first` から `last` までの開いているディスクリプタを閉じ、
  `CLOSE_RANGE_CLOEXEC` なら閉じずに close-on-exec を付けます。`CLOSE_RANGE_UNSHARE`
  は先に、`CLONE_FILES` のスレッドと共有している表をそのスレッド専用の写しにします。
  共有していたスレッドのディスクリプタはそのまま残ります。未知のフラグや `last` より
  大きい `first` は `EINVAL` です。
- `futex` は `WAIT`・`WAKE`・`WAIT_BITSET`・`WAKE_BITSET` を扱います。
- `futex`・`epoll`・`eventfd` は paludarium の中で実装していて、ホストの同じ機能には
  頼りません。そのため、macOS・Windows・WebAssembly でも同じように動きます。
- [ネットワーク](#network)がなければ、`socket()` は `AF_INET` と `AF_INET6` に
  `EAFNOSUPPORT` を返します。
- `poll` は `epoll_wait` と同じように、どれかの記述子が準備できるか、ミリ秒の
  タイムアウトが過ぎるか（負の値なら過ぎません）、シグナルが届くまで（`EINTR`）待ちます。
  ホストの標準入力は、Linux の端末やパイプと同じく、読むバイトがあるときか、入力が
  終わったとき（WebAssembly では `Guest.stdin` を閉じたとき、Unix のホストでは記述子が
  終わったとき）だけ読めるとします。終わったときは切断（`POLLHUP`）も示し、`read` は
  0 を返します。`poll`・`ppoll`・`select`・`pselect6` と、標準入力を監視できる `epoll`
  は、どれもそう見ます。それを見分けられないホスト（Windows）では、いつも読めると
  します。出力はいつも書けます。パイプの読み出し側は、読まれていないデータがあるときだけ読めるとし、書き手が
  いなくなると切断だけを示します。Linux の `pipe_poll` と同じです。
- `ppoll`・`select`・`pselect6` も同じように待ちます。Linux と同じく、残りの時間を
  タイムアウトの引数に書き戻し（0 のタイムアウトには書き戻しません）、`ppoll` と
  `pselect6` は一時的なシグナルのマスクを受け取り、ハンドラはそのマスクで動きます。
  `select` は、集合の中の閉じた記述子に `EBADF` を返し、見る記述子は 1024 個
  （`FD_SETSIZE`）までです。Linux は `nfds` を記述子の表の大きさで切ります。
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
  `EAGAIN`（ブロッキングなら `SO_SNDTIMEO` まで待ちます）、名前のない `listen` と、
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
  作るので、すでにあるパスは、宛先のないシンボリックリンクでも `EADDRINUSE` です。
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

  持ち主がいなければ `ESRCH` です。`F_GETOWN` と `F_GETOWN_EX` で読み出し、`F_SETSIG` で
  送るシグナルを選びます。`O_ASYNC` を持てるのはパイプとソケットだけで、ほかのファイルでは
  `F_SETFL` が落とし、`FIOASYNC` で付けようとすると `ENOTTY` です。`O_ASYNC` を付けたパイプやソケットは、持ち主にカーネルから
  `SIGIO` を送ります。`F_SETSIG` があれば代わりにそのシグナルを送り、`si_code`
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
    終わり、切断のシグナルを送りません。Linux もそのときは送りません。分けて送る送信では、
    送らないのは最初の分だけです。ただし相手が `shutdown` したときや閉じたときは、
    Linux が送らないのは読み手がまだ動いていないときだけです（読み手を起こしてから
    確かめるため）。そのため Linux では送ることもあります。データグラムとパケットの
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
  どちらかの端に設定があるときに送ったメッセージは、送り手のプロセス ID、ユーザー、
  グループを運びます。`SCM_CREDENTIALS` を渡したときは、その値を運びます。設定のある
  受け手は、それを `SCM_CREDENTIALS` のメッセージで、ディスクリプタより先に受け取ります。
  資格情報なしで送ったメッセージは、プロセス 0、ユーザーとグループ 65534 として読めます。
  そのような受け手のストリームの読み込みは、`read` と `MSG_WAITALL` も含めて、資格情報の
  違う書き込みをまとめて読みません。`SCM_CREDENTIALS` は `struct ucred` をちょうど 1 つ
  持つ必要があり（違えば `EINVAL`）、どちらの ID も -1 にはできません（`EINVAL`）。
  そのあとでプロセスを探し、なければ `ESRCH` です。
- `SO_PASSPIDFD` を設定すると、`SO_PASSCRED` と同じようにメッセージが資格情報を運び、
  設定のある受け手は、送り手のプロセスの pidfd（close-on-exec）を `SCM_PIDFD` の
  メッセージで受け取ります。Linux 7.0 と同じく、ディスクリプタのあとに来ます。pidfd を
  作るのは、そのメッセージ全体が制御のバッファに入るときだけです。入らないときは
  メッセージを失い（`MSG_CTRUNC`）、ディスクリプタも作りません。どちらの端も資格情報を
  渡していないときに送ったメッセージは、何も運びません。`SO_PEERCRED` と
  `SO_PEERPIDFD` は、Linux が記録するのと同じく相手のプロセスを示します。ペアでは、
  両方の端で組を作ったプロセスです。`socket()` で作ったソケットでは、待ち受けるか接続する
  までは何も示しません（プロセス 0、ID は -1、`SO_PEERPIDFD` は `ENODATA`）。待ち受けでは
  `listen` を呼んだプロセス（`init_peercred`）、受け付けたソケットでは接続したプロセス、
  クライアントでは待ち受けのプロセス（`copy_peercred`）です。`SO_PEERPIDFD` は、その
  プロセスの新しい pidfd を読み出します。渡した長さに番号の一部しか入らなくても、
  pidfd は作ります。読み出すだけのオプションで、`setsockopt` は `ENOPROTOOPT` です。
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
- `madvise`：`MADV_DONTNEED` を受けたプライベートなページは空になります。無名の
  ページはそのあと 0 として読め、ファイルのマッピングのページは、Linux がファイルから
  読み込み直すのと同じく、そのときのファイルの中身を読みます。`mremap` で動かしたあとも、`fork` した子でも同じです。プログラム自身の
  セグメントは Linux と同じ形で置きます。ファイルのデータを持つページはファイルの
  マッピングで、実行ファイルを読み直します。`mprotect` で書き込めるようにして
  書き換えた読み込み専用のセグメント（コード）も同じです。残り（`.bss`）は無名の
  メモリで、0 として読めます。共有メモリは自分の中身を保ちます。`MADV_FREE` では
  中身を残します。メモリが足りているときの Linux と同じです。
  アクセスの仕方のヒントは受け付け、ほかの指定には `EINVAL` を返します。
- `mremap` は、後ろが空いていればその場で広げ、空いていなければ `MREMAP_MAYMOVE` で
  中身ごと動かします。`MREMAP_FIXED` と `MREMAP_DONTUNMAP` も使えます。共有のメモリは、
  動かしても `fork` した相手と共有したままです。ファイルのマッピングは、ファイルの
  続きの上へ広げられ、そのページは初めて触れたときに読み込みます。また、複数の
  マッピングにまたがる範囲を
  `MREMAP_FIXED` で動かすと、`EFAULT` になります（最近の Linux は動かせます）。
- `msync` は、引数と範囲を確かめ、`MS_SYNC` か `MS_ASYNC` なら共有のファイルの
  マッピングへの書き込みをファイルに書き戻します。
- `sched_getaffinity` では、ゲストのどのスレッドもホストのすべての CPU で動けるとします。
  そのため、ゲストにはホストと同じ数の CPU が見えます（WebAssembly では 1 つ）。
- `uname` は x86_64 の Linux で、ホスト名は `paludarium` と答えます。`CPUID` と同じく、
  ホストのことは見せません。ゲストは root（ユーザーとグループが 0）として動きます。
  ファイルはどれも、`chown` で別の持ち主やグループにするまでは root のもので、
  メモリ上のファイルシステムはその持ち主を覚えています。Linux と同じく、`chown` は
  ディレクトリ以外のファイルから set-user-ID のビットを外し、グループが実行できる
  ときは set-group-ID のビットも外します。持ち主とグループが変わらなくても外します。
  set-group-ID のディレクトリの中に作ったものはディレクトリのグループを継ぎ、
  新しいディレクトリはそのビットも継ぎます。`fchmod` と `fchown` は、`pipe` や
  `pipe2` で作ったパイプとソケットペアについても、`fstat` が返すモードと持ち主を
  変えます。パイプでは両端がそれらを共有し、ソケットペアでは端ごとに持ちます。
  ホストが用意する標準入力、標準出力、標準エラー出力では `EPERM` を返します。
- `chmod` と `utimensat` は、メモリ上のファイルシステムでも、マウントしたホストの
  ディレクトリでも使えます。Windows のホストでは、`chmod` が変えるのは読み取り専用の
  属性だけです。`stat` が返すのは更新時刻だけで、アクセスと変更の時刻は
  0 です。マウントしたディレクトリのファイルでは、渡した両方の時刻がホストに残ります。
  umask は、Linux で `CLONE_FS` が共有するのと同じく、スレッドの間で共有します。
  `fsync` と `fdatasync` はファイルとディレクトリでは成功し、パイプ・ソケット・端末では
  `EINVAL` を返します。`fadvise64` はヒントとして受け付けます。
- `statfs` は、メモリ上のファイルシステムを 4 GiB の tmpfs として返します。使用量と
  inode の数は、実際に持っているものです。マウントしたホストのディレクトリでは、
  ホストのファイルシステムの値を返します。`/proc/self/mountinfo`、`/proc/self/mounts`、
  `/proc/mounts` はマウントの一覧です（ルートは `tmpfs`、`--mount` ごとに `hostfs`。
  ホストのパスは見せません）。マウントごとに `mountinfo` の行と同じ `st_dev` を持つので、
  `df` はどのマウントも表示します。
- `/proc` にあるのは、ほかには自分のプロセスのものだけです。`/proc/self`
  （`/proc/<pid>` としても）は、`readlink` で PID になり、その中のものを相対的に
  開けるディレクトリです。ほかに `/proc/self/status` と `/proc/self/fd` があります。
  `/proc/self/status` は、Linux と同じ項目を同じ順番で持ちます
  （umask、ID、スレッドの数、シグナルのマスク、ケーパビリティなど）。ただし、何も
  測っていないメモリと CPU の項目はありません。
- `/proc/self/fd`（モード 0500）は、`.`、`..` と、開いているディスクリプタごとの
  リンクを並べます。名前は番号で、Linux と同じく先頭に 0 のない形で読みます。各リンクの
  `lstat` は、ユーザーのビットでディスクリプタのアクセスを示し、大きさは 64 です。`stat`
  はリンクをたどってファイルを示します。`readlink` は Linux と同じ名前を返します。
  `.`、`..` とシンボリックリンクを解決したファイルのパス（このプロセスのものは
  `/proc/<pid>/…`）で、どこからも指されなくなれば空白と `(deleted)` が付きます。ほかに
  `pipe:[<inode>]`、`socket:[<inode>]`、`anon_inode:[eventfd]`・`[eventpoll]`・
  `[timerfd]`・`[pidfd]`（Linux 6.9 以降は pidfs の名前です）、
  `/memfd:<名前> (deleted)` です。
  そのためにパイプとソケットは自分の inode 番号を持ちます。リンクを開くと、ファイルを
  パスで開き直し、memfd なら同じファイルとシールへの新しいハンドルを返します。パイプと
  標準の入出力は、持っているアクセスなら同じハンドルを返します。ソケットは Linux と同じく
  `ENXIO` です。消されたファイル、パイプの反対の端、種類のないファイルも、Linux なら
  開き直せますが、ここでは `ENXIO` です。
- `/dev`（モード 0755）は、メモリのデバイスと、Linux のシステムがそこに置くリンクを
  持ち、それだけを並べます。ゲストが `/dev` の下に作ったファイルは、開いたり `stat`
  したりできますが、一覧には出ません。各エントリは 1 つの inode 番号を持ち、`stat` と
  `getdents` は同じ番号を返します。`/dev` は読み込み用にしか開けず（`EISDIR`）、
  デバイスは `O_DIRECTORY` では開けません（`ENOTDIR`）。`null`、`zero`、`full`、`random`、`urandom` は
  キャラクタデバイス（モード 0666）で、`st_rdev` に Linux と同じ番号（1:3、1:5、1:7、
  1:8、1:9）を持ちます。`null` は何も読めず、`zero` と `full` は 0 を、`random` と
  `urandom` はホストの乱数を読みます。`full` は書き込みを `ENOSPC` で拒み、ほかは
  受け取ります。`zero` のマッピングは無名のメモリで、`MAP_SHARED` なら共有です。
  `fd`、`stdin`、`stdout`、`stderr` は `/proc/self/fd` とその最初の 3 つへのリンク
  （0777）で、`open` や `stat`、それを通るパス（`/dev/fd/3`）はリンクをたどります。
  リンクに `O_NOFOLLOW` を付けると `ELOOP` です。`O_PATH` も付けると Linux はリンク
  そのものを開きますが、ここでは対応しておらず、やはり `ELOOP` です。ホストの
  マウントのファイルはデバイス番号を持ちません。
- CPU 時間は、ホストが測れるところ（Linux・macOS・Windows）では、ゲストのスレッドの
  最初のシステムコールからの、ホストのスレッドの CPU 時間（ユーザーとシステムの合計）
  です。WebAssembly などそれ以外では、代わりに経過時間を数えます。
  `CLOCK_THREAD_CPUTIME_ID` はそのスレッドの時間、`CLOCK_PROCESS_CPUTIME_ID` は
  プロセスのスレッドの合計（それぞれ最後のシステムコールの時点）を返します。子は 0 から
  始まり、待たれたときに親の「子の時間」に足されます。`getrusage`、`times`、`wait4` と
  `waitid` の rusage は、すべてをユーザーの時間として返します。システムコールのための
  エミュレータの処理も、ホストのユーザー空間で動くためです。メモリの使用量は測りません。
- `clock_gettime` は、`CLOCK_MONOTONIC_RAW`、粗い時計、`CLOCK_BOOTTIME`（ホストは
  サスペンドしないものとします）、アラームの時計、`CLOCK_TAI`（TAI のずれは 0）も
  読めます。`clock_getres` は 1 ns、粗い時計では 4 ms を返します。
- `access` は root として、読み書きはいつも許し、実行は実行のビットがあるか
  ディレクトリのときに許します。`getgroups` はグループを返しません。
- `sysinfo` は、空きが 4 GiB でスワップのない固定のメモリを返し、ホストのメモリは
  見せません。起動からの時間は単調時計の値です。
- timerfd は `CLOCK_REALTIME` か `CLOCK_MONOTONIC` で動き（`CLOCK_BOOTTIME` は
  `CLOCK_MONOTONIC` として扱います）、絶対時刻と周期の指定ができます。読むと前回からの
  満了の回数を返し、満了すると `poll` と `epoll` から読めるように見えます。
  `TFD_TIMER_CANCEL_ON_SET` は受け付けますが、ゲストは時計を設定できないので取り消しは
  起きません。アラームの時計は `EPERM` を返します。
- POSIX タイマーは `CLOCK_REALTIME` か `CLOCK_MONOTONIC` で動き、プロセスへの
  シグナル（`SIGEV_SIGNAL`。`SI_TIMER` の siginfo とオーバーランつき）か、プロセスの
  中の 1 つのスレッドへのシグナル（`SIGEV_THREAD_ID`）で知らせるか、何も知らせません
  （`SIGEV_NONE`）。`SIGEV_THREAD` は、Linux と同じく `SIGEV_SIGNAL` として扱います
  （スレッドは C ライブラリが `SIGEV_THREAD_ID` を使って作ります）。スレッドへの
  タイマーのシグナルは、そのスレッドがまだ受け取っていない間だけオーバーランに足され、
  スレッドが終わっていれば失われます。CPU 時間の時計のタイマーは `EINVAL` を返します。タイマーは
  `fork` では受け継がれず、`execve` で消えます。`rt_sigtimedwait` は、プロセス全体に
  届いてブロックされているシグナルも受け取ります。
- `clone3` は、`struct clone_args` を Linux と同じように確かめ（後ろに足された部分が
  0 でない長い構造体には `E2BIG`）、それが表す `clone` として動きます。
  `CLONE_CLEAR_SIGHAND` は、ハンドラを設定したシグナルを既定に戻します。`set_tid` と
  `CLONE_INTO_CGROUP` は `EINVAL` を返します。`clone` そのものは、Linux と同じく flags の
  下位 32 ビットだけを読むので、`CLONE_CLEAR_SIGHAND` は `clone3` でしか使えません。
- `prctl` は `PR_SET_NAME`／`PR_GET_NAME`（スレッドごとの 15 バイトまでの名前。
  `execve` でプログラムのファイル名になり、新しいスレッドとプロセスに受け継がれます）、
  `PR_SET_PDEATHSIG`（親が終わったときにシグナルを送ります）、`PR_SET_DUMPABLE`、
  `PR_SET_CHILD_SUBREAPER`（`fork` では受け継がれず、`execve` では残ります）、
  `PR_SET_NO_NEW_PRIVS` と、それぞれの `PR_GET_*` に対応します。ほかの指定には
  `EINVAL` を返します。
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
  を返し、相手がいれば無効なシグナルは `EINVAL` を返します。`kill` や
  `pidfd_send_signal` で送ったシグナルの `si_pid` は送り主の PID に、
  `PR_SET_PDEATHSIG` のシグナルの `si_pid` は終わった親の PID になります。
- `rt_sigqueueinfo`（`sigqueue` の中身）は、呼び出し元の siginfo をそのままプロセスに
  送り、`rt_tgsigqueueinfo` は 1 つのスレッドに送ります。そのためシグナルは値を運び、
  リアルタイムシグナルは送った数だけ届きます。Linux と同じく、カーネルや `kill`、
  `tkill` が付ける `si_code` を付けられるのは、自分自身に送るスレッドだけです（相手を
  探す前に `EPERM`）。Linux が形を知らない `si_code` では、siginfo の残りを 0 にして
  おく必要があります（`E2BIG`）。
- 資源の上限は Linux の既定値（`RLIMIT_NOFILE` は 1024／4096、`RLIMIT_STACK` は
  8 MiB／無制限など）から始まり、`fork` で受け継がれ、読み書きできます。ハードの
  `RLIMIT_NOFILE` は 1048576（Linux の `fs.nr_open`）まで、埋め込む側がそれより低い
  天井を決めたときはその値まで上げられます。Linux と同じく
  守らせるのは次の 3 つです。
  - `RLIMIT_NOFILE`：ソフトの上限を超える新しいディスクリプタは `EMFILE`（`open` は
    何も作りません）、上限を超える番号への `dup2`／`dup3` は `EBADF`、上限を超える
    番号からの `F_DUPFD` は `EINVAL` になります。
  - `RLIMIT_FSIZE`：通常のファイルへの書き込み（`O_APPEND` なら末尾から書く `write`、
    `writev`、`pwrite`、`pwritev` と、`copy_file_range`、`sendfile`）はソフトの上限で
    止まります。上限かその先から始まる
    書き込みと、ファイルを上限より大きくする `truncate`／`ftruncate` と `fallocate` は、`SIGXFSZ` を
    起こして `EFBIG` で失敗します。
  - `RLIMIT_CORE`：コアダンプするシグナル（`SIGSEGV`、`SIGABRT` など）で終わる
    プロセスは、ソフトの上限が 1 ページ以上で、`PR_SET_DUMPABLE` でダンプを止めて
    いなければ、Linux の `do_coredump` が既定の `core_pattern` でするのと同じように、
    作業ディレクトリに `core` という名前の ELF のコアを書きます（モードは 0600 から
    umask を除いたもので、前のコアは置き換えます）。コアには、各スレッドのレジスタ
    （`NT_PRSTATUS`）、プロセス（`NT_PRPSINFO`）、致命的なシグナル（`NT_SIGINFO`）、
    補助ベクトル、メモリが入ります。そのとき `wait` は `CLD_DUMPED` とコアのフラグを
    返します。上限より大きいコアはそこで切りますが、Linux が書き始めたコアを
    ダンプしたと報告するのと同じように、ダンプしたと返します。

  プロセスグループとセッションも同じように持ち、`wait4` と `waitid` でプロセス
  グループを選んで待てます。最初のプロセスのセッションはエミュレータの外で始まった
  ものなので、`getsid` は、Linux が PID 名前空間の外の ID を示すのと同じく 0 を
  返します。`setsid` は、PID がグループを指すプロセスでは `EPERM` で失敗し、それ
  以外のプロセスを新しいセッションとグループの先頭にします。`setpgid` は Linux と
  同じくセッションを確かめ、セッションの先頭、別のセッションの子、別のセッションの
  グループには `EPERM` を、`execve` を済ませた子には `EACCES` を返します。グループは、
  まだ回収されていない終わった子も含め、メンバーが残っている間は存在します。
- nice 値は Linux と同じくスレッドごとに持ちます。新しいスレッドやプロセスは作った
  スレッドの値を受け継ぎ、`execve` は呼んだスレッドの値を保ちます。`getpriority` は
  見つけたスレッドのうち最も高い優先度を `20 - nice` で返し、`setpriority` はそれらを
  すべて -20〜19 に収めた値にします。ゲストは root なので下げることもできます。
  `PRIO_PROCESS` は 1 つのスレッド（0 は呼んだスレッド）、`PRIO_PGRP` はプロセス
  グループのすべてのスレッド、`PRIO_USER` はユーザー 0 のすべてのスレッドです。まだ
  回収されていない終わったプロセスも見つかります。スレッドがなければ `ESRCH`、
  知らない `which` は `EINVAL` です。値は報告するだけで、スケジューリングは変えません。
- `waitid` は、Linux と同じ確かめ方と書き出し方をします。報告する子がないときは、
  エラーのときも含めて siginfo の項目を 0 にします。終わった子は、`WEXITED` か
  `WCONTINUED` がないと待てません（`ECHILD`）。停止と再開は、`WUNTRACED`
  （`WSTOPPED`）か `WCONTINUED` を付けた待ちにそれぞれ一度だけ報告し（`WNOWAIT` なら
  残します）、親が `SA_NOCLDSTOP` を付けていなければ `SIGCHLD` で知らせます。
  `SIGCHLD` の siginfo には、子の PID、`CLD_*` のコード（`CLD_EXITED`、`CLD_KILLED`、
  `CLD_STOPPED`、`CLD_CONTINUED`）、状態、`si_utime` としての CPU 時間が入ります。
  `si_uid` は 0 で、`SIGCHLD` が保留中に届いた次の `SIGCHLD` は、Linux と同じく捨てます。
  `SIGCHLD` を無視するか `SA_NOCLDWAIT` を設定したプロセスの子は、終了シグナルが
  `SIGCHLD` なら、Linux の `do_notify_parent` と同じく終わったその場で回収します。
  待ちはそうした子が終わるまで待ってから `ECHILD` で失敗し、その CPU 時間は親の
  子の分に足しません。`SIGCHLD` を無視しているときは、ブロック中でも `SIGCHLD` を
  保留しません。それより前にできたゾンビは、待ちのために残ります。
  `pidfd_open` の pidfd は、そのプロセスが終わると読めるようになり（回収されると
  切断も示します。自動で回収された子では両方を同時に示します）、`epoll` で待てます。ノンブロッキングの pidfd での
  `waitid(P_PIDFD)` は `EAGAIN` を返します。`pidfd_send_signal` は siginfo と
  範囲の指定を受け付けず、`PIDFD_THREAD` を付けてもプロセス全体を指します。
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
    `TCP_USER_TIMEOUT`、`IP_TOS`、`IPV6_V6ONLY`。既定値と範囲の確かめ方は Linux と
    同じで、`SO_SNDBUF` と `SO_RCVBUF` は既定の `wmem_max` と `rmem_max`（212992）までを
    2 倍にします。
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
  IPv6 のソケットは、`IPV6_V6ONLY` でなければ IPv4 のポートも持ちます。
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
  `dup2`）、送ったバイトが相手の空きを待っている間、すべて届くか、時間が来るか、
  シグナルが来るまで待ちます。ノンブロッキングでも同じです。それでも閉じるのは成功し、
  バイトはそのあとも届きます。読んでいない入力のあるソケットは待たずにリセットし、
  終了するプロセスは待ちません。
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
  `ENETUNREACH`）でも先にポートを取ります。相手がループバックならループバックの送り元の
  アドレスで、ほかならすべてのアドレスで取り、相手からだけ受け取ります。
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

## シグナル

- 登録、マスク、配送（Linux の x86-64 のシグナルフレームと `rt_sigreturn`）、
  `sigaltstack`、リアルタイムシグナルのキュー、`SIGSTOP` による停止と再開を扱います。
  停止で中断されたブロッキングの呼び出しは、ハンドラが動かないときの Linux と同じく、
  再開の後にやり直します。対象は `read`、`write`、`readv`、`writev`、`pread64`、`pwrite64`、`preadv`、`pwritev`、`wait4`、`waitid`、`pause`、`rt_sigsuspend`、`flock`、
  `sendto`、`recvfrom`、`sendmsg`、`recvmsg`、`ppoll`、`select`、`pselect6`、時間制限なしの `poll`、時間制限なしの `futex` の待ちです。
  `nanosleep`、相対時間の `clock_nanosleep`、時間制限つきの `poll`、時間制限つきの `futex` の待ちは、
  `restart_syscall` で元の締め切りのまま待ちを続け（`futex` は先に値をもう一度確かめ、変わっていれば
  `EAGAIN` を返します）、絶対時刻の `clock_nanosleep` はもう一度実行します。ハンドラが
  動いたときはやり直さず、`EINTR` を返します。
  `SA_RESTART` を付けたハンドラが動いたときは、Linux と同じく、ハンドラから戻った後に、停止の後にやり直す呼び出し（`read` から時間制限なしの `futex` の待ちまで）をやり直します。
  ただし `pause`、`rt_sigsuspend`、`poll`、`ppoll`、`select`、`pselect6` と、`SO_RCVTIMEO` や `SO_SNDTIMEO`
  で待ちに時間制限のあるソケットの呼び出しは、`EINTR` を返します。
  `epoll_wait` と `rt_sigtimedwait` は、Linux と同じく `EINTR` を返します。
  `rt_sigsuspend` は、シグナルのマスクを渡されたマスクに置き換えてハンドラが動くまで待ちます。
  ハンドラはそのマスクで動き、終わると元のマスクに戻ります。
- シグナルを無視にする `sigaction`（`SIG_IGN` か、既定で無視される `SIGCHLD`、`SIGCONT`、
  `SIGURG`、`SIGWINCH` への `SIG_DFL`）は、Linux の `do_sigaction` と同じく、プロセスと
  すべてのスレッドで保留中のそのシグナルを捨てます。その後に送られたブロック中の
  シグナルは、保留のまま残ります。

## ファイルシステム

- 既定では、実行ごとに、ほかと切り離されたメモリ上のファイルシステムを作ります。
  `/tmp` もあります。
- 作成、読み書き、ハードリンク、シンボリックリンク、`flock`、`rename`、ディレクトリの
  一覧、`stat` 系に対応しています。開いているファイルは `unlink` の後も使えます。
- 起動の前にファイルを置けます。
- 指定したときだけ、ホストのディレクトリをマウントできます（コマンドの `--mount`、
  Rust の `Config::mounts`）。操作はすべてそのディレクトリの中に閉じ込められ、
  `..` やシンボリックリンクで外には出られません。

## 確かめたプログラム {#programs-verified}

- C と Rust の hello world と、命令ごとの小さなテストのプログラム。
- **probe**：スレッドとファイルシステムの機能を 8 項目で確かめる Rust のプログラム
  （tokio のタイマー、UNIX のソケットの組、rayon の並列処理、Mutex と Condvar、
  ファイル操作、ハードリンク、シンボリックリンク、`flock`）。
- **aube**：Rust で書かれた Node.js のパッケージマネージャ（v2.8.3）。`--version`、
  `install`、`install --frozen-lockfile`、`list` の 4 つの操作が、本物の Linux と
  同じ出力と終了コードになります。
- **ripgrep**：Rust で書かれたテキストの検索のツール（15.2.0）。検索を複数のスレッドで
  動かします。正規表現での置き換え、並列の検索、ファイルをメモリへマップした検索、2 つの
  エラーを含む 9 つの検索が、本物の Linux と同じ出力と終了コードになります。
  `--version` は比べていません。`CPUID` が見せる SIMD の機能を表示するためで、
  paludarium はそれをわざと絞っています。

これらは、Linux・macOS・Windows と、Node.js・Chromium・Firefox・Safari のすべてで、
本物の x86-64 Linux と同じ結果になることを確かめています。
