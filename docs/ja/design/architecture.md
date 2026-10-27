# アーキテクチャ

paludarium は、役割ごとに分けた crate でできています。依存は上から下への一方向だけで、
循環はありません。

| 層 | 使う層 |
|---|---|
| 入口（`paludarium` コマンド、Rust の API、WebAssembly の launcher） | runtime |
| runtime | cpu、jit、kernel、loader、host |
| cpu、jit | decoder、mmu |
| kernel | mmu、vfs、loader、host |
| loader | mmu、vfs |
| vfs | host |

すべての crate が、`paludarium-types` の共通の型を使います。

## crate

| crate | 役割 |
|---|---|
| `paludarium-types` | 共通の型（`GuestAddr`、`Errno`、`ExitReason`、`ExitStatus`、`Error`） |
| `paludarium-decoder` | iced-x86 を包んだデコーダ。外には自前の命令の型だけを出す |
| `paludarium-mmu` | ソフトウェア MMU。4 KiB のページの 2 段のページテーブル |
| `paludarium-host` | ホストとの境界（`Host` trait）と、Linux・macOS・Windows・WebAssembly の実装 |
| `paludarium-vfs` | メモリ上の安全なファイルシステムと、ホストのディレクトリのマウント |
| `paludarium-loader` | 静的な ELF の読み込みと、最初のスタック（argv・envp・補助ベクタ） |
| `paludarium-cpu` | x86-64 のインタプリタ |
| `paludarium-jit` | コードキャッシュの口と、WebAssembly 向けの JIT |
| `paludarium-kernel` | Linux のシステムコール。プロセスとスレッドの状態を持つ |
| `paludarium-runtime` | `Session` と、スレッドごとの実行ループ |
| `paludarium` | 公開の API と `paludarium` コマンド |

公開していない crate が 2 つあります。`paludarium-harness` は差分テストの道具、
`paludarium-wasm` は npm パッケージの `paludarium.wasm` になる WebAssembly の入口です。

## 実行の流れ

1. Loader が ELF を読み込み、メモリに置いて、最初のスタックを作ります。
2. 実行ループが CPU に命令を実行させます。JIT が有効なら、先にコードキャッシュに
   変換済みのブロックがあるかを聞き、なければインタプリタで実行します。
3. CPU は、システムコールやゲストの例外に当たると、止まった理由を返して止まります。
   CPU は Kernel を知りません。
4. 実行ループが Kernel を呼んでシステムコールを処理するか、ゲストにシグナルを送ります。
5. 実行ループは、10 万命令ごとに、外から止めるよう求められていないかを確かめます。

スレッドのレジスタの状態は Kernel が持ち、CPU は渡された状態を実行するだけです。

## ホストとの境界

ネイティブと WebAssembly の違いは、`paludarium-host` の中だけに閉じ込めています。
ほかの crate は、`std::thread`・`std::fs`・`std::time` を直接は呼びません。
`Host` trait が出すのは、スレッドの起動、待機と起床、時計、期限つきの待機、端末の情報、
標準入出力、安全な乱数、ホストのディレクトリのマウントです。

ゲストのシステムコールの番号、ゲストのポインタ、ゲストの `ioctl` の番号は、
この境界を越えません。

## エラーの 3 つの種類

型で分けています。

| 種類 | 型 | 行き先 |
|---|---|---|
| システムコールの失敗 | `Errno` | ゲストに errno として返す |
| ゲストの例外 | `ExitReason` | ゲストへのシグナル（`SIGSEGV`、`SIGBUS`、`SIGILL`、`SIGFPE` など） |
| エミュレータ自身の問題 | `Error` | 命令のアドレス・バイト列・システムコールの番号を添えて止まる |

ゲストの終了（`ExitStatus`）とエミュレータのエラーは混ぜません。

## 安全のための決まり

- `unsafe` を使ってよいのは、ホストとの接続部と JIT だけです。それ以外の crate は
  `#![forbid(unsafe_code)]` です（今は JIT も `unsafe` を使っていません）。
- 製品のコードでは、`unwrap`・`expect`・`panic` を clippy で禁止しています。
- ゲストのアドレス（`GuestAddr(u64)`）とホストのアドレスを型で分けています。
  WebAssembly では `usize` が 32 bit なので、境界の変換はすべて検査します。
