# インストール

paludarium は、crates.io の crate と、npm のパッケージとして公開しています。

| 使いたいもの | 入れるもの |
|---|---|
| コマンド | `cargo install paludarium` |
| Rust のライブラリ | `cargo add paludarium` |
| ブラウザ・Node.js | `npm install @aletheia-works/paludarium-wasm` |

## Rust

paludarium は、日付を固定した nightly の Rust（`nightly-2026-10-11`）で作って
確かめています。crate は MSRV（使える最も古い Rust）として 1.101 を宣言しているので、
今の stable の Rust ではビルドできません。nightly の Rust を使ってください。

```sh
rustup toolchain install nightly
cargo +nightly install paludarium
```

動かせるのは、静的にリンクした x86-64 Linux の実行ファイル（`ET_EXEC` と static-pie）です。
musl で静的にリンクすると作れます。

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
paludarium target/x86_64-unknown-linux-musl/release/hello
```

## JavaScript

```sh
npm install @aletheia-works/paludarium-wasm
```

パッケージには、`paludarium.wasm`、起動用の JavaScript と、その Worker、
TypeScript の型が入っています。ブラウザで使うときは、cross-origin isolated な
ページにする必要があります。[JavaScript とブラウザ](./javascript) を見てください。

## ソースから作る

```sh
git clone https://github.com/aletheia-works/paludarium.git
cd paludarium
cargo build --release --locked       # paludarium コマンド
mise run wasm:build                  # npm パッケージの paludarium.wasm
```

`rust-toolchain.toml` に固定した nightly を、rustup が自動で入れます。
`mise run` には [mise](https://mise.jdx.dev/) が必要です。`mise tasks` ですべてのタスクを確認できます。
