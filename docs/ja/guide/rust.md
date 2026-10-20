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
- `Config` には、公開のフィールドもあります。`cwd`（最初の作業ディレクトリ。既定は `/`）、
  `mounts`（ホストのディレクトリ。下を参照）、`tty`（端末の大きさを表す `TerminalInfo`）です。
- `Session::new` は、何かを動かす前に設定を確かめます。`run()` はゲストを最後まで
  動かします。`NativeHost` は、ゲストの標準入出力をホストのプロセスにつなぎます。

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
- `signal(number)` は、ゲストのプロセスに Linux のシグナルを送ります。

## エラー

`run()` は、ゲストが終わったときやシグナルで止まったときは `Ok(ExitStatus)` を返し、
エミュレータの問題のときだけ `Err(Error)` を返します。`Error::kind` は次のどれかです。

| `ErrorKind` | 意味 |
|---|---|
| `Unimplemented` | paludarium がまだ対応していないものを、ゲストが使った |
| `Internal` | エミュレータの中の食い違い |
| `InvalidProgram` | プログラムを読み込めない |
| `Host` | ホストの失敗（I/O のエラー、乱数が得られないなど） |

エラーは、わかっていれば、命令のアドレス（`rip`）、命令のバイト列、syscall の番号を
持っています。paludarium が実装していない syscall はエラーにはなりません。古いカーネルと
同じように、ゲストに `ENOSYS` が返ります。
