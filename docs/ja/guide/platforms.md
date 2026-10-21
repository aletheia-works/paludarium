# 対応環境

## ゲスト

- x86-64 の Linux のプログラムだけを動かします。32-bit の x86 は対象外です。
- 静的にリンクした実行ファイル（`ET_EXEC` と、interpreter のない static-pie）を
  読み込みます。動的リンクのプログラム（glibc の共有ライブラリを使うもの）は、
  まだ対象にしていません。

## ホスト

| ホスト | 状態 |
|---|---|
| Linux | 対応。差分テストの基準もここで取ります |
| macOS | 対応。Linux 用の同じ ELF をソフトウェアで実行します |
| Windows | 対応。Linux 用の同じ ELF をソフトウェアで実行します |
| Node.js（`worker_threads`） | 対応（npm パッケージ） |
| Chromium 系のブラウザ | 対応（npm パッケージ） |
| Firefox | 対応（npm パッケージ） |
| Safari | 対応（npm パッケージ）。CI で本物の Safari を動かして確かめています |

macOS と Windows でも、Linux のバイナリを直接 exec するのではなく、paludarium が
命令とシステムコールを処理して動かします。そのため、同じ ELF がどのホストでも
同じように動きます。

端末の情報（tty かどうか、画面の大きさ）は、ホストごとのやり方で取ります。Linux は
`TCGETS` と `TIOCGWINSZ`、macOS は libc の termios、Windows はコンソールの API
（読み取りだけ）から、Linux の形に変換してゲストに見せます。

## 確かめた版

公開の前に、同じコードで、次の環境のすべてで同じ結果になることを確かめています
（[テストと検証](../design/quality)）。

- Linux・macOS・Windows（GitHub Actions のランナー）
- Node.js（確かめた時点の最新版）
- Chromium、Firefox、本物の Safari（macOS のランナー）

## ブラウザで必要なもの

- `SharedArrayBuffer` と module Worker。
- ページを cross-origin isolated にすること（`Cross-Origin-Opener-Policy: same-origin`
  と `Cross-Origin-Embedder-Policy: require-corp`）。これがないと
  `SharedArrayBuffer` が使えません。
- ブラウザの主スレッドでは `Atomics.wait` が使えないので、エミュレータはすべて
  Worker の中で動きます。

## Rust のツールチェーン

- 日付を固定した nightly（今は `nightly-2026-10-11`）で作って確かめています。
- crate の MSRV は 1.101 なので、今の stable の Rust ではビルドできません。
- WebAssembly 版は、さらに nightly の `build-std` と atomics の機能を使います。
