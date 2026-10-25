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
| メモリ | `mmap`（anonymous と、写し取ったファイル）、`munmap`、`mremap`、`mprotect`、`madvise`、`msync`、`brk`、`arch_prctl` |
| システムの情報 | `uname`、`sysinfo`、`getuid`、`geteuid`、`getgid`、`getegid`、`getgroups`、`getrusage`、`times` |
| シグナル | `rt_sigaction`、`rt_sigprocmask`、`rt_sigreturn`、`sigaltstack`、`kill`、`tkill`、`tgkill`、`setitimer`、`rt_sigtimedwait`、`rt_sigpending`、`rt_sigsuspend`、`pause`、`restart_syscall` |
| 時刻 | `clock_gettime`、`clock_getres`、`nanosleep`、`clock_nanosleep`、`timer_create`／`timer_settime`／`timer_gettime`／`timer_getoverrun`／`timer_delete` |
| ファイル | `open`／`openat`／`creat`、`read`、`write`、`readv`／`writev`、`pread64`／`pwrite64`、`preadv`／`pwritev`、`copy_file_range`、`sendfile`、`close`、`close_range`、`lseek`、`stat`／`fstat`／`lstat`／`newfstatat`、`statx`、`getdents64`、`mkdir`／`mkdirat`、`rmdir`、`unlink`／`unlinkat`、`rename`／`renameat`、`link`／`linkat`、`symlink`／`symlinkat`、`readlink`／`readlinkat`、`truncate`／`ftruncate`、`fallocate`、`memfd_create`、`flock`、`fcntl`、`dup`／`dup2`／`dup3`、`pipe`／`pipe2`、`chdir`／`fchdir`、`getcwd`、`umask`、`chmod`／`fchmod`／`fchmodat`、`utimensat`、`fsync`／`fdatasync`、`sync`、`fadvise64`、`access`／`faccessat`／`faccessat2`、`statfs`／`fstatfs` |
| 入出力 | `poll`、`ppoll`、`select`、`pselect6`、`ioctl`（`TCGETS`、`TIOCGWINSZ`） |
| イベント | `eventfd2`、`timerfd_create`／`timerfd_settime`／`timerfd_gettime`、`epoll_create`／`epoll_create1`、`epoll_ctl`、`epoll_wait`、`epoll_pwait` |
| ソケット | `socket`（常に `EAFNOSUPPORT`）、`socketpair`（AF_UNIX、`SOCK_STREAM`、`SOCK_SEQPACKET`、`SOCK_DGRAM`）、`sendto`、`recvfrom`、`shutdown` |
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
  そして `EFBIG`）。そのあとは tmpfs と同じふるまいです。通常の確保は
  `FALLOC_FL_KEEP_SIZE` がなければファイルを大きくし、`FALLOC_FL_PUNCH_HOLE` は
  範囲を 0 にし（`O_APPEND` のファイルでも）、ほかのモードは `EOPNOTSUPP` です。
  `RLIMIT_FSIZE` を超えて大きくすると `SIGXFSZ` を起こして `EFBIG` で失敗します。
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
  シールのない memfd も、ほかのファイルと同じく書き込める共有マッピングには
  できません（`ENODEV`）。
- `close_range` は `first` から `last` までの開いているディスクリプタを閉じ、
  `CLOSE_RANGE_CLOEXEC` なら閉じずに close-on-exec を付けます。`CLOSE_RANGE_UNSHARE`
  は先に、`CLONE_FILES` のスレッドと共有している表をそのスレッド専用の写しにします。
  共有していたスレッドのディスクリプタはそのまま残ります。未知のフラグや `last` より
  大きい `first` は `EINVAL` です。
- `futex` は `WAIT`・`WAKE`・`WAIT_BITSET`・`WAKE_BITSET` を扱います。
- `futex`・`epoll`・`eventfd` は paludarium の中で実装していて、ホストの同じ機能には
  頼りません。そのため、macOS・Windows・WebAssembly でも同じように動きます。
- `socket()` はいつも `EAFNOSUPPORT` を返します。ネットワークは使えません。
- `poll` は `epoll_wait` と同じように、どれかの記述子が準備できるか、ミリ秒の
  タイムアウトが過ぎるか（負の値なら過ぎません）、シグナルが届くまで（`EINTR`）待ちます。
  ホストの標準入出力は、別の記述子に置き換えられるまで、いつも準備ができています。
  パイプの読み出し側は、読まれていないデータがあるときだけ読めるとし、書き手が
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
  `ECONNREFUSED`、その後は `ENOTCONN` になります。`EPIPE` で `SIGPIPE` を送るのは、
  Linux と同じく `SOCK_STREAM` だけです。
- `madvise`：`MADV_DONTNEED` を受けたプライベートなページは空になります。無名の
  ページはそのあと 0 として読め、ファイルのマッピングのページは、Linux がファイルから
  読み込み直すのと同じく、そのときのファイルの中身を読みます（ファイルの終わりより先は
  0）。`mremap` で動かしたあとも、`fork` した子でも同じです。プログラム自身の
  セグメントは Linux と同じ形で置きます。ファイルのデータを持つページはファイルの
  マッピングで、書き込めるもの（`.data`）は実行ファイルを読み直します。残り（`.bss`）は
  無名のメモリで、0 として読めます。共有メモリは自分の中身を保ちます。`MADV_FREE` では
  中身を残します。メモリが足りているときの Linux と同じです。
  アクセスの仕方のヒントは受け付け、ほかの指定には `EINVAL` を返します。
- `mremap` は、後ろが空いていればその場で広げ、空いていなければ `MREMAP_MAYMOVE` で
  中身ごと動かします。`MREMAP_FIXED` と `MREMAP_DONTUNMAP` も使えます。共有のメモリは、
  動かしても `fork` した相手と共有したままです。ファイルを写し取ったマッピングは、ファイルの
  続きを読めないので広げられません（`ENOMEM`）。また、複数のマッピングにまたがる範囲を
  `MREMAP_FIXED` で動かすと、`EFAULT` になります（最近の Linux は動かせます）。
- `msync` は、引数と範囲を確かめて成功を返します。共有のファイルのマッピングは読むだけの
  写しなので、書き戻すものがありません。
- `sched_getaffinity` では、ゲストのどのスレッドもホストのすべての CPU で動けるとします。
  そのため、ゲストにはホストと同じ数の CPU が見えます（WebAssembly では 1 つ）。
- `uname` は x86_64 の Linux で、ホスト名は `paludarium` と答えます。`CPUID` と同じく、
  ホストのことは見せません。ゲストは root（ユーザーとグループが 0）として動きます。
  `stat` がどのファイルについても返す持ち主と同じです。
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
  `PR_SET_NO_NEW_PRIVS` と、それぞれの `PR_GET_*` に対応します。ほかの指定には
  `EINVAL` を返します。
- 資源の上限は Linux の既定値（`RLIMIT_NOFILE` は 1024／4096、`RLIMIT_STACK` は
  8 MiB／無制限など）から始まり、`fork` で受け継がれ、読み書きできます。ハードの
  `RLIMIT_NOFILE` は 1048576（Linux の `fs.nr_open`）まで、埋め込む側がそれより低い
  天井を決めたときはその値まで上げられます。Linux と同じく
  守らせるのは次の 2 つです。
  - `RLIMIT_NOFILE`：ソフトの上限を超える新しいディスクリプタは `EMFILE`（`open` は
    何も作りません）、上限を超える番号への `dup2`／`dup3` は `EBADF`、上限を超える
    番号からの `F_DUPFD` は `EINVAL` になります。
  - `RLIMIT_FSIZE`：通常のファイルへの書き込み（`O_APPEND` なら末尾から書く `write`、
    `writev`、`pwrite`、`pwritev` と、`copy_file_range`、`sendfile`）はソフトの上限で
    止まります。上限かその先から始まる
    書き込みと、ファイルを上限より大きくする `truncate`／`ftruncate` と `fallocate` は、`SIGXFSZ` を
    起こして `EFBIG` で失敗します。

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
  `pidfd_open` の pidfd は、そのプロセスが終わると読めるようになり（回収されると
  切断も示します）、`epoll` で待てます。ノンブロッキングの pidfd での
  `waitid(P_PIDFD)` は `EAGAIN` を返します。`pidfd_send_signal` は siginfo と
  範囲の指定を受け付けず、`PIDFD_THREAD` を付けてもプロセス全体を指します。
- 不正なポインタを渡されたときは `EFAULT` を返します。

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
  `sendto`、`recvfrom`、`ppoll`、`select`、`pselect6`、時間制限なしの `poll`、時間制限なしの `futex` の待ちです。
  `nanosleep`、相対時間の `clock_nanosleep`、時間制限つきの `poll`、時間制限つきの `futex` の待ちは、
  `restart_syscall` で元の締め切りのまま待ちを続け（`futex` は先に値をもう一度確かめ、変わっていれば
  `EAGAIN` を返します）、絶対時刻の `clock_nanosleep` はもう一度実行します。ハンドラが
  動いたときはやり直さず、`EINTR` を返します。
  `epoll_wait` と `rt_sigtimedwait` は、Linux と同じく `EINTR` を返します。
  `rt_sigsuspend` は、シグナルのマスクを渡されたマスクに置き換えてハンドラが動くまで待ちます。
  ハンドラはそのマスクで動き、終わると元のマスクに戻ります。

## ファイルシステム

- 既定では、実行ごとに、ほかと切り離されたメモリ上のファイルシステムを作ります。
  `/tmp` もあります。
- 作成、読み書き、ハードリンク、シンボリックリンク、`flock`、`rename`、ディレクトリの
  一覧、`stat` 系に対応しています。開いているファイルは `unlink` の後も使えます。
- 起動の前にファイルを置けます。
- 指定したときだけ、ホストのディレクトリをマウントできます（コマンドの `--mount`、
  Rust の `Config::mounts`）。操作はすべてそのディレクトリの中に閉じ込められ、
  `..` やシンボリックリンクで外には出られません。

## 確かめたプログラム

- C と Rust の hello world と、命令ごとの小さなテストのプログラム。
- **probe**：スレッドとファイルシステムの機能を 8 項目で確かめる Rust のプログラム
  （tokio のタイマー、UNIX のソケットの組、rayon の並列処理、Mutex と Condvar、
  ファイル操作、ハードリンク、シンボリックリンク、`flock`）。
- **aube**：Rust で書かれた Node.js のパッケージマネージャ（v2.8.2）。`--version`、
  `install`、`install --frozen-lockfile`、`list` の 4 つの操作が、本物の Linux と
  同じ出力と終了コードになります。
- **ripgrep**：Rust で書かれたテキストの検索のツール（15.2.0）。検索を複数のスレッドで
  動かします。正規表現での置き換え、並列の検索、ファイルをメモリへマップした検索、2 つの
  エラーを含む 9 つの検索が、本物の Linux と同じ出力と終了コードになります。
  `--version` は比べていません。`CPUID` が見せる SIMD の機能を表示するためで、
  paludarium はそれをわざと絞っています。

これらは、Linux・macOS・Windows と、Node.js・Chromium・Firefox・Safari のすべてで、
本物の x86-64 Linux と同じ結果になることを確かめています。
