# ロードマップ

paludarium は、土台から順に、次の段階で作りました。

| 段階 | 目標 | 状態 |
|---|---|---|
| 1 | ネイティブの Linux で、static-musl の hello world が動く | 完了 |
| 2 | ネイティブの Linux で、probe と aube が動く | 完了 |
| 3 | Node.js と 3 種類のブラウザ（Chromium 系・Firefox・Safari）で、probe と aube が動く | 完了 |
| 4 | macOS と Windows のホストで、probe と aube が動く | 完了 |
| 5 | WebAssembly 向けの JIT の最小版。Node.js で JIT なしより速い | 完了 |
| 公開 | crates.io と npm に公開する | 0.1.0 から公開中（[リリース](https://github.com/aletheia-works/paludarium/releases)） |

それぞれの段階では、「その段階のプログラムが、本物の x86-64 Linux と同じ結果になる」ことを、
差分テストで確かめてから次へ進みました。その後、probe と aube に加えて、ripgrep も
確かめたプログラムになりました（[対応している機能](../guide/features#programs-verified)）。

## これから

決まった予定ではありませんが、次のようなことを考えています。

- 確かめるプログラムに、uutils の coreutils と brush シェルを加える。今のリリースは、
  依存先の取り下げられたクレートやセキュリティのアドバイザリのためにゲストの監査を
  通らないので、次のリリースを待っています。
- 対応するシステムコールと命令を増やす。いちばん大きいのは、書き込める共有の
  ファイルのマッピングです（[制限](../guide/limitations) に挙げています）。
- 動的リンクのプログラムへの対応を検討する。
- ネイティブ向けの JIT を検討する。
- stable の Rust でビルドできるようにするかを見直す。
- 公開の前の確かめを、もっと軽くできるかを見直す。
