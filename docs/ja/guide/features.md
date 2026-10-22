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
- **SSE 系**：実際のプログラム（probe と aube）が使う SSE 系の 129 の命令と、
  AES・PCLMUL・SHA などの暗号の命令。浮動小数点はソフトウェアで計算します。
- 命令のデコードには [iced-x86](https://github.com/icedland/iced) を使っています。
- `CPUID` はホストの値を見せません。実装していない機能は広告しません。
- AVX、AVX-512、x87、MMX は対象外です。

ゲストが実行できない命令に当たったときは、本物の Linux と同じようにゲストに
`SIGILL` を送ります。ページフォールトは `SIGSEGV`、整数の 0 除算は `SIGFPE` になります。

## システムコール

実装したシステムコールだけを、明示した表で扱います。それ以外はすべて `ENOSYS` を返し、
ホストに渡すことはありません。

| 分類 | 主なシステムコール |
|---|---|
| プロセスとスレッド | `clone`、`fork`、`vfork`、`execve`、`wait4`、`exit`、`exit_group`、`getpid`、`gettid`、`set_tid_address`、`futex`、`sched_getaffinity`、`sched_yield`、`setpgid`／`getpgid`／`getpgrp`、`prlimit64`／`getrlimit`／`setrlimit` |
| メモリ | `mmap`（anonymous）、`munmap`、`mprotect`、`madvise`、`brk`、`arch_prctl` |
| システムの情報 | `uname`、`sysinfo`、`getuid`、`geteuid`、`getgid`、`getegid`、`getgroups` |
| シグナル | `rt_sigaction`、`rt_sigprocmask`、`rt_sigreturn`、`sigaltstack`、`kill`、`tkill`、`tgkill`、`setitimer` |
| 時刻 | `clock_gettime`、`nanosleep`、`clock_nanosleep` |
| ファイル | `open`／`openat`、`read`、`write`、`writev`、`close`、`lseek`、`stat` 系、`getdents64`、`mkdir`、`rmdir`、`unlink`、`rename`、`link`、`symlink`、`readlink`、`truncate`、`flock`、`fcntl`、`dup` 系、`pipe`／`pipe2`、`chdir`、`getcwd`、`umask`、`chmod`／`fchmod`／`fchmodat`、`utimensat`、`fsync`／`fdatasync`、`sync`、`fadvise64`、`access`／`faccessat`／`faccessat2` |
| 入出力 | `poll`、`ioctl`（`TCGETS`、`TIOCGWINSZ`） |
| イベント | `eventfd2`、`epoll_create1`、`epoll_ctl`、`epoll_wait`、`epoll_pwait` |
| ソケット | `socketpair`（AF_UNIX、`SOCK_STREAM` と `SOCK_SEQPACKET`）、`sendto`、`recvfrom`、`shutdown` |
| 乱数 | `getrandom` |

- `futex` は `WAIT`・`WAKE`・`WAIT_BITSET`・`WAKE_BITSET` を扱います。
- `futex`・`epoll`・`eventfd` は paludarium の中で実装していて、ホストの同じ機能には
  頼りません。そのため、macOS・Windows・WebAssembly でも同じように動きます。
- `socket()` はいつも `EAFNOSUPPORT` を返します。ネットワークは使えません。
- `madvise`：`MADV_DONTNEED` を受けたプライベートなページは空になり、0 として読めます。
  `MADV_FREE` では中身を残します。メモリが足りているときの Linux と同じです。
  アクセスの仕方のヒントは受け付け、ほかの指定には `EINVAL` を返します。
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
- `access` は root として、読み書きはいつも許し、実行は実行のビットがあるか
  ディレクトリのときに許します。`getgroups` はグループを返しません。
- `sysinfo` は、空きが 4 GiB でスワップのない固定のメモリを返し、ホストのメモリは
  見せません。起動からの時間は単調時計の値です。
- 資源の上限は Linux の既定値（`RLIMIT_NOFILE` は 1024／4096、`RLIMIT_STACK` は
  8 MiB／無制限など）から始まり、`fork` で受け継がれ、読み書きできます。ただし
  paludarium はその上限を守らせません。プロセスグループも同じように持ちますが、
  プロセスグループを選ぶ `wait` はまだありません。
- 不正なポインタを渡されたときは `EFAULT` を返します。

## スレッドとプロセス

- `clone` で作ったゲストのスレッドは、ネイティブではホストのスレッドに、WebAssembly では
  Worker に割り当てます。
- `fork`／`vfork` 相当の `clone` と `execve` で、仮想ファイルシステムの中の別の
  プログラムを起動し、`wait4` で終了を受け取れます。Rust の `std::process::Command` も
  動きます。`posix_spawn` を使わずに fork するとき（たとえば `pre_exec` を使うとき）も
  同じです。

## シグナル

- 登録、マスク、配送（Linux の x86-64 のシグナルフレームと `rt_sigreturn`）、
  `sigaltstack`、リアルタイムシグナルのキュー、`SIGSTOP` による停止と再開を扱います。

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
- **aube**：Rust で書かれた Node.js のパッケージマネージャ（v2.8.1）。`--version`、
  `install`、`install --frozen-lockfile`、`list` の 4 つの操作が、本物の Linux と
  同じ出力と終了コードになります。

これらは、Linux・macOS・Windows と、Node.js・Chromium・Firefox・Safari のすべてで、
本物の x86-64 Linux と同じ結果になることを確かめています。

- **ripgrep**：Rust で書かれたテキストの検索のツール（15.2.0）。検索を複数のスレッドで
  動かします。正規表現での置き換え、並列の検索、2 つのエラーを含む 8 つの検索が、本物の
  Linux と同じ出力と終了コードになります。今のところ確かめているのは x86-64 Linux だけです。
  `--version` は比べていません。`CPUID` が見せる SIMD の機能を表示するためで、
  paludarium はそれをわざと絞っています。
