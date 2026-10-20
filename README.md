# paludarium

**Documentation: <https://aletheia-works.github.io/paludarium/>**
([日本語](https://aletheia-works.github.io/paludarium/ja/)) — what paludarium is,
how to install and use it, supported features, design, and a live demo.

A Rust re-implementation of [jart/blink](https://github.com/jart/blink), the
x86-64 Linux user-mode emulator written in C (ISC licensed). It is meant to
eventually replace the emulator core of the sibling project
[formicarium](../formicarium), which provides the browser side (Worker, page,
filesystem) and the integration, and currently runs its PoC on jart/blink
itself.

Background research is in
`formicarium/aidlc/spaces/default/knowledge/documents/research/cheerpx-oss.md`.

## 状態（U1：細い一本）

段階 1 の最初の作業単位 U1 は実装と検証を進めています。検証済み：`scripts/linux-dev.sh cargo test --locked -p paludarium-harness --test diff_u1` は 2026-10-04 に 16 passed / 0 failed（C/Rust hello world と 13 の命令系テスト）で終了しました。検証済み：Linux の `cargo llvm-cov ... --fail-under-lines 80` は行カバレッジ 87.11%（3259 行、未実行 420 行）を記録しています。検証済み：`cargo test --locked -p paludarium-harness --lib coverage::tests -- --nocapture` は命令別のゲスト・ソース根拠の対応 66/66 を記録しています。全命令形式・全フラグの意味論の網羅を保証する測定ではありません。

- ELF の読み込み（ET_EXEC と static-pie）→ 命令のデコード（iced-x86 を包む）→ インタプリタ → ソフトウェア MMU → syscall → Host の trait を通した標準出力、の道筋がつながっています。
- C と Rust の hello world、と命令ごとのゲスト 13 本の出力・終了状態が、ネイティブの x86-64 Linux と一致することを差分テストで確かめています。
- 実装した syscall は、hello world がネイティブで呼ぶもの（write・exit・exit_group・brk・arch_prctl・set_tid_address・mmap・munmap・mprotect・rt_sigaction・rt_sigprocmask・sigaltstack・poll・ioctl）だけです。それ以外は `-ENOSYS` を返し、番号のままホストに渡すことはありません。
- シグナルは登録を記録するだけで、配送しません（U4 で実装）。スレッド、ファイル、端末、wasm 版はまだありません。

## 状態（U2：整数命令）

検証済み：整数命令・REP restart・typed atomics と全MMUアクセス共通同期を追加しました。最新Linux `RUST_TEST_THREADS=1 cargo llvm-cov --locked --workspace --fail-under-lines 80` は197件通過（U1差分16/U2差分38/並行10を含む）、行coverage94.00%でexit0です。各差分/並行ケースの30秒watchdogを維持しています。[命令と取得根拠](docs/u2/inventory.md)、[nativeケース対応](docs/u2/differential-coverage.md)、[flags比較](docs/u2/flag-masks.md)を参照してください。

未検証：bounded native traceは全probe/aube経路の対応を保証しません。全ゲスト統合、syscall/thread、SSE拡充、wasm、JITは後続unitです。nightly CPU/MMU fuzz各600秒を追加し、既存依存/pinと80%gateを維持しています。
## 状態（U8：別のプログラムの起動）

VFS 内の static-musl ELF を fork／vfork 相当の clone と execve で起動し、親が wait4 で終了を回収する経路を追加しています。私有メモリは fork 時に複製し、MAP_SHARED と開いた fd の実体は親子で共有します。Rust `Command::spawn`／`status`／`output` のために匿名 pipe、CLOEXEC、writev、FIONBIO、Kernel 所有の `/dev/null` を接続しています。

差分検証は x86-64 Linux で `cargo test --locked -p paludarium-harness --test diff_u8 u8_ -- --nocapture` を実行します。各実行で新しい native 結果を取得し、stdout・stderr・終了状態を比較します。PID と rusage の変動値は真偽条件に正規化し、各ケースには時間上限を付けています。全体の Linux 行カバレッジ下限は 80% です。

未対応：clone3、独立したプロセス間の CLONE_SIGHAND、停止／再開の wait 通知、プロセスグループの wait 選択。native trace で必要性を確認した場合に対象ケースを先に追加します。

## U10：probe と固定 aube の差分検証

Linux x86-64 の専用 CI で、独自 probe の標準 8 項目と aube v2.6.1 の 4 操作を、同じ ELF の新しい native 実行結果と比較します。各操作の制限時間は 30 秒です。検証済み：実装コミットの CI run 38009664758 は全11ジョブが成功し、native14 / emulator16 の全操作が一致しました。範囲、実行方法、既知の制限は [U10 検証資料](docs/u10/README.md) を参照してください。

## 必要なもの

- Rust：`rust-toolchain.toml` の nightly（rustup が自動で入れます）
- 差分テスト・カバレッジ・ファジング：x86-64 Linux（CI の ubuntu のランナー、または下の開発用コンテナ）と musl-tools
- wasm のスレッドの確認：Node.js（LTS）

## ビルドと実行

```bash
cargo build --release --locked
./target/release/paludarium [--env KEY=VALUE]... [--no-jit] <program> [args...]
```

- `<program>` はホストのファイルで、ゲストの中では `/<ファイル名>` に置かれます。argv[0] は指定した文字列のままです。
- 終了コード：ゲストの終了コード、シグナルで終わったら 128 + シグナル番号、引数の誤りは 2、エミュレータ自身のエラーは 70。
- `--mount` は U7 で実装する予定で、今は引数の誤り（2）になります。`--no-jit` は受け付けますが、ネイティブ版には JIT がないので何もしません。

ライブラリとして使う場合は、`paludarium::{Config, Session, NativeHost}` を使います（`crates/paludarium/src/lib.rs` の例）。

## テスト

単体テスト（Linux・macOS・Windows）：

```bash
cargo test --locked -p paludarium-types -p paludarium-decoder -p paludarium-mmu -p paludarium-cpu -p paludarium-loader -p paludarium-vfs -p paludarium-kernel -p paludarium-host -p paludarium-jit -p paludarium-runtime -p paludarium
```

差分テスト（x86-64 Linux だけ）：

```bash
cargo test --locked -p paludarium-harness --test diff_u1 -- --nocapture
```

- 初回に `tests/guests/build.sh` がゲストをソースからビルドします（musl-gcc と `x86_64-unknown-linux-musl` が必要）。ビルドした ELF はリポジトリに入れません。
- 各ゲストをネイティブとエミュレータで動かし、標準出力・標準エラー・終了状態をバイト単位で比べます。期待結果はその場でネイティブから作り、保存しません。1 件あたり 30 秒の時間切れがあります。
- 命令ごとのゲスト（`tests/guests/insn/`）は、レジスタ・フラグ・メモリの値を出力します。x86 で未定義のフラグは比べません（`tests/guests/insn/UNDEFINED.md`）。
- `--nocapture` を付けると、ゲストごとの実行時間を出します。

カバレッジ（x86-64 Linux、行カバレッジ 80% 未満で失敗）：

```bash
cargo llvm-cov --locked -p paludarium-types -p paludarium-decoder -p paludarium-mmu -p paludarium-cpu -p paludarium-loader -p paludarium-vfs -p paludarium-kernel -p paludarium-host -p paludarium-jit -p paludarium-runtime -p paludarium --fail-under-lines 80
```

ファジング（nightly、x86-64 Linux）：

```bash
cd fuzz
LSAN_OPTIONS=suppressions=$PWD/lsan.supp cargo fuzz run -O decode -- -max_total_time=600
# 対象：decode、load_elf、mmu_ops、syscall_args
```

依存の検査：`cargo deny --locked check`

### Windows や macOS から Linux のテストを動かす

`ci/linux-dev/Dockerfile` が、差分テスト・strace・objdump・カバレッジ・ファジングに必要なものをそろえた x86-64 Linux の環境です。

```bash
scripts/linux-dev.sh cargo test --locked -p paludarium-harness --test diff_u1 -- --nocapture
```

作業ツリーを名前付きボリュームに写してから実行するので、Docker Desktop がリポジトリのパスを共有していなくても動きます（`PALUDARIUM_DEV_MOUNT=bind` で直接のマウントに切り替えます）。

### 命令の一覧の作り方

U1 で実装する命令は、hello world がネイティブで実際に実行する命令から決めました（BR4.4）。`tools/insn-trace/insn-census.sh <program> <出力の接頭辞>` が、ptrace で 1 命令ずつ実行して一覧を作ります。結果は `docs/u1/census/` にあります。

## wasm のスレッドの確認

`spikes/wasm-threads/` が、共有メモリを使う 2 つの Worker で「待つ・起こす」が動くかを確かめる小さなプログラムです。結果と、Worker を作る場所についての提案は `docs/reports/wasm-threads.md` にあります。

```bash
bash spikes/wasm-threads/build.sh
node spikes/wasm-threads/node-check.mjs
(cd spikes/wasm-threads && npm ci) && node spikes/wasm-threads/browser-check.mjs chromium firefox
```

## CI

- `.github/workflows/ci.yml`（PR ごと）：3 つの OS の単体テスト、rustfmt、clippy（`-D warnings`）、wasm32 でのビルド、cargo-deny、差分テスト、カバレッジ 80%。
- `.github/workflows/nightly.yml`（夜間）：ファジング（対象ごとに 10 分）、wasm のスレッドの確認（Node.js・Chromium・Firefox・macOS の本物の Safari）。失敗したら Issue を作ります。

action はコミットの SHA で固定し、既定の権限は読み取りだけです。

## リポジトリの構成

| 場所 | 中身 |
|------|------|
| `crates/paludarium-types` | 共通の型（GuestAddr・Errno・ExitReason・ExitStatus・Error） |
| `crates/paludarium-decoder` | iced-x86 を包んだデコーダ（外には自前の型だけを出す） |
| `crates/paludarium-mmu` | 4 KiB ページの 2 段のページテーブル |
| `crates/paludarium-cpu` | インタプリタ |
| `crates/paludarium-loader` | ELF の読み込みと最初のスタック |
| `crates/paludarium-vfs` | 仮想ファイルシステム（U1 は最小限） |
| `crates/paludarium-kernel` | syscall |
| `crates/paludarium-host` | Host の trait とネイティブの実装（`unsafe` を許す唯一のクレート） |
| `crates/paludarium-jit` | JIT の口（U1 は何もしない実装） |
| `crates/paludarium-runtime` | Session と実行ループ |
| `crates/paludarium` | 公開 API とコマンド |
| `crates/paludarium-harness` | 差分テスト（公開しない） |
| `tests/guests/` | 差分テストのゲストのソース |
| `fuzz/` | cargo-fuzz の対象 |
| `spikes/wasm-threads/` | wasm のスレッドの確認 |

## License

Apache License 2.0

## 配布と公開（U15）

公開用検査と手順は [docs/release.md](docs/release.md) にあります。
最初の公開版は0.1.0に決めました（11 crateとnpm配布物の版を0.1.0にそろえています）。
registryへの公開はまだ行っていません。
11 crateとnpm配布物を隔離環境で検査し、公開には別の明示承認と実際の
registry設定・保護environment・同headの受理証拠が必要です。
Rust利用者は固定nightlyを使用してください。stable対応は主張していません。






U2取得記録：固定source/lock・immutable builderでprobe/aubeを隔離再構築しました。[取得receiptと新form分類](docs/u2/inventory/rebuild/build-receipt.json)にbuild args/hash/原artifactとの照合を記録しています。追加memory/prefixはnative aggregate各1件とdecoder幅1件が通過しました。この取得時の追加prefix検証はtest-onlyでした。その後FS/GS atomic addressを修正し、上記coverageは修正後sourceの値へ更新しています。全任意経路・U10全program統合の未検証とは区別します。


