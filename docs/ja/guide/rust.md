# Rust のライブラリ

[`paludarium`](https://crates.io/crates/paludarium) crate を使うと、Rust からゲストの
プログラムを動かせます。使う型は、内部の crate からこの crate に再公開してあります。

```sh
cargo add paludarium
```

## プログラムを動かす

```rust
use std::sync::Arc;
use paludarium::{Config, ExitStatus, NativeHost, Session};

fn main() -> Result<(), paludarium::Error> {
    let program = std::fs::read("hello").expect("read the guest program");
    let config = Config::new("/hello", vec![b"hello".to_vec()])
        .with_env("LANG", "C.UTF-8")
        .with_file("/hello", program);
    let session = Session::new(config, Arc::new(NativeHost::new()))?;
    match session.run()? {
        ExitStatus::Exited(code) => println!("exited with {code}"),
        ExitStatus::Signaled(signal) => println!("ended by signal {signal}"),
        other => println!("{other:?}"), // ExitStatus is #[non_exhaustive]
    }
    Ok(())
}
```

- `Config::new(program, args)` には、プログラムのゲストの中での絶対パスと、
  `argv[0]` を含む `argv` を渡します。Linux と同じく、パス、引数、環境変数は
  バイト列です。
- `with_file(path, bytes)` は、起動の前にゲストの仮想ファイルシステムへファイルを
  置きます（権限は `0755`）。ほかの権限にするときは `with_file_mode` を使います。
  `with_env(key, value)` は環境変数を足します。
- `Config` には、公開のフィールドもあります。`program`、`args`、`env`（`new` と
  `with_env` が設定するもの）、`files` と `file_modes`（`with_file` と `with_file_mode`
  が足すもの。パスと中身、またはパスと権限の組です）、`cwd`（最初の作業ディレクトリを
  `Some(path)` で指定します。既定の `None` は `/` です）、`mounts`（ホストのディレクトリ。
  下を参照）、`tty`（`Some(TerminalInfo::new(columns, rows))` にすると、ゲストの標準の
  ストリームがその大きさの端末になります。既定の `None` では、端末は `Host` に任せます）、
  `jit`（使うのは WebAssembly 版だけです。ネイティブ版には JIT がありません）、
  `limits`、`network` です。
- `limits` は `Limits` で、既定では上限がありません。`Limits::default().with_tasks(n)`
  は、ゲストが持てるタスクを `n` 個までにします（タスクはスレッドと、回収されるまでの
  プロセスで、cgroup の `pids.max` と同じ数え方です。超える `clone` や `fork` は
  `EAGAIN` で失敗します）。`with_open_files(n)` は、Linux の `fs.nr_open` と同じように
  `RLIMIT_NOFILE` の天井を `n` にするので、それ以上ファイルを開くと `EMFILE` になります。
  `with_memory(n)` は、cgroup の `memory.max` と同じように、ゲストが使えるメモリを
  `n` バイトまでにします。超える書き込みをしたプロセスは、OOM killer と同じように
  `SIGKILL` で終わり、収まらない `execve` は `ENOMEM` で失敗します（何を
  数えるかはフィールドのドキュメントにあります）。これらはフィールドの `tasks`、
  `open_files`、`memory` を設定し、`None` は上限なしです。
- `network` の既定は `None` で、ゲストはネットワークを使えません。
  `with_network(policy)` は、これを `NetworkPolicy` にします。`NetworkPolicy` は
  `NetworkPolicy::new()` から作り、行き先ごとに `allow(entry)` を呼びます
  （`github.com:443`、`*.example.org`、`127.0.0.1`、`[::1]:8080`）。読めない項目には、
  `allow` が `InvalidRule` を返します。ゲストは、方針が許す行き先へ `Host` を通して TCP で
  接続し、許した名前を引けます（[ネットワーク](./features#network)）。
- `Session::new` は、何かを動かす前に設定を確かめます。`run()` はゲストを最後まで
  動かします。`NativeHost` は `Host` トレイトのネイティブ版の実装で、ゲストの
  標準入出力をホストのプロセスにつなぎます。
- `ExitStatus::command_exit_code()` は、コマンドが返す終了コードです。終了コードか、
  128 + シグナルの番号になります。

## ホストのディレクトリを見せる

```rust
use paludarium::Mount;

let mut config = Config::new("/work/app", vec![b"app".to_vec()]);
config.mounts.push(Mount { host: "/srv/data".into(), guest: b"/work".to_vec() });
```

ゲストに見えるのは、マウントしたディレクトリだけです。パスはマウントしたディレクトリの
中で解決され、`..` でもシンボリックリンクでも、その外には出られません。

## ゲストを止める、シグナルを送る

`Session` は、別のスレッドと共有できます。

- `kill()` はゲストに止まるよう求めます。インタプリタが次に確かめたとき
  （`DEFAULT_BUDGET` ＝ 100,000 命令ごと）に、`SIGKILL` で終わります。
- `signal(number)` は、ゲストのプロセスに Linux のシグナルを送ります。ゲストの外から
  送るので、PID 名前空間の外の送り主と同じく、`si_code` は `SI_USER`、`si_pid` は 0
  になります。
- `is_stopped()` は、ゲストが `SIGSTOP` などのジョブ制御で止まっているかどうかを
  返します。
- 動かした後、`unimplemented_syscalls()` は、ゲストが呼んで `ENOSYS` が返った
  システムコールを小さい順に返します（コマンドの `--report-enosys` が表示するもの）。
  `termination_detail()` は、CPU の例外でゲストが終わったとき、その止まり方
  （`ExitReason`）を返します。

## エラー

`run()` は、ゲストが終わったときやシグナルで止まったときは `Ok(ExitStatus)` を返し、
エミュレータの問題のときだけ `Err(Error)` を返します。`Error::kind` は次のどれかです。

| `ErrorKind` | 意味 |
|---|---|
| `Unimplemented` | paludarium がまだ対応していないものを、ゲストが使った |
| `Internal` | エミュレータの中の食い違い |
| `InvalidProgram` | プログラムを読み込めない |
| `Host` | ホストの失敗（I/O のエラー、乱数が得られないなど） |

エラーは `message` を持ち、わかっていれば、命令のアドレス（`rip`。`GuestAddr` です）、
命令のバイト列（`bytes`）、syscall の番号（`syscall`）も持っています。paludarium が実装していない syscall はエラーにはなりません。古いカーネルと
同じように、ゲストに `ENOSYS` が返ります。
