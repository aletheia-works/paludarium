# 対応している機能

paludarium が目指すのは、実際のプログラムを本物の Linux と同じ結果で動かすことです。
ここに挙げたものは、差分テストで本物の x86-64 Linux と比べて確かめています。

## 命令

- **整数命令とフラグ**：算術・論理・シフト・ビット操作、`lock` 付きの原子的な命令、
  `REP` の文字列命令（途中で止まったときの再開を含む）、`CMPXCHG8B`／`CMPXCHG16B`、
  BMI 系（`ADCX`／`ADOX`、`ANDN`、`BZHI`、`MULX`、`PEXT`、`RORX`、`SHLX`／`SHRX`）、
  `MOVBE`、`ENTER`／`LEAVE` など。
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
| プロセスとスレッド | `clone`、`fork`、`vfork`、`execve`、`wait4`、`exit`、`exit_group`、`getpid`、`gettid`、`set_tid_address`、`futex` |
| メモリ | `mmap`（anonymous）、`munmap`、`mprotect`、`brk`、`arch_prctl` |
| シグナル | `rt_sigaction`、`rt_sigprocmask`、`rt_sigreturn`、`sigaltstack`、`kill`、`tkill`、`tgkill`、`setitimer` |
| 時刻 | `clock_gettime`、`nanosleep`、`clock_nanosleep` |
| ファイル | `open`／`openat`、`read`、`write`、`writev`、`close`、`lseek`、`stat` 系、`getdents64`、`mkdir`、`rmdir`、`unlink`、`rename`、`link`、`symlink`、`readlink`、`truncate`、`flock`、`fcntl`、`dup` 系、`pipe`／`pipe2`、`chdir`、`getcwd` |
| 入出力 | `poll`、`ioctl`（`TCGETS`、`TIOCGWINSZ`） |
| イベント | `eventfd2`、`epoll_create1`、`epoll_ctl`、`epoll_wait`、`epoll_pwait` |
| ソケット | `socketpair`（AF_UNIX）、`sendto`、`recvfrom`、`shutdown` |
| 乱数 | `getrandom` |

- `futex` は `WAIT`・`WAKE`・`WAIT_BITSET`・`WAKE_BITSET` を扱います。
- `futex`・`epoll`・`eventfd` は paludarium の中で実装していて、ホストの同じ機能には
  頼りません。そのため、macOS・Windows・WebAssembly でも同じように動きます。
- `socket()` はいつも `EAFNOSUPPORT` を返します。ネットワークは使えません。
- 不正なポインタを渡されたときは `EFAULT` を返します。

## スレッドとプロセス

- `clone` で作ったゲストのスレッドは、ネイティブではホストのスレッドに、WebAssembly では
  Worker に割り当てます。
- `fork`／`vfork` 相当の `clone` と `execve` で、仮想ファイルシステムの中の別の
  プログラムを起動し、`wait4` で終了を受け取れます。Rust の `std::process::Command` も
  動きます。

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
