# ロードマップ

paludarium は、土台から順に、次の段階で作りました。

| 段階 | 目標 | 状態 |
|---|---|---|
| 1 | ネイティブの Linux で、static-musl の hello world が動く | 完了 |
| 2 | ネイティブの Linux で、probe と aube が動く | 完了 |
| 3 | Node.js と 3 種類のブラウザ（Chromium 系・Firefox・Safari）で、probe と aube が動く | 完了 |
| 4 | macOS と Windows のホストで、probe と aube が動く | 完了 |
| 5 | WebAssembly 向けの JIT の最小版。Node.js で JIT なしより速い | 完了 |
| 公開 | crates.io、npm、JSR に公開する | crates.io と npm は 0.1.0 から、JSR は 0.15.0 の次のリリースから（[リリース](https://github.com/aletheia-works/paludarium/releases)） |

それぞれの段階では、「その段階のプログラムが、本物の x86-64 Linux と同じ結果になる」ことを、
差分テストで確かめてから次へ進みました。その後、probe と aube に加えて、ripgrep と
uutils の coreutils も確かめたプログラムになりました（[対応している機能](../guide/features#programs-verified)）。

## これから

決まった予定ではありませんが、次のようなことを考えています。

- 確かめるプログラムに、brush シェルを加える。今のリリースは、依存先の取り下げられた
  クレートやセキュリティのアドバイザリのためにゲストの監査を通らないので、次のリリースを待っています。
- coreutils を、ripgrep がすでに動いているほかのホスト（macOS、Windows、WebAssembly の
  環境）でも比べる。
- 対応するシステムコールと命令を増やす（[制限](../guide/limitations) を参照）。
- ネイティブの JIT（`--jit`、x86-64 の Linux で試験的）：[決定事項](decisions#when-the-native-jit-is-turned-on-by-default)の条件がそろったら既定で有効にすること、ほかの
  ホスト（Arm64、macOS、Windows）、ブロックのより多くをコンパイルすること（命令を増やす、
  ブロックどうしをつなぐ、フラグを読むときにだけ求める）。
- stable の Rust でビルドできるようにするかを見直す。
- 公開の前の確かめを、もっと軽くできるかを見直す。
