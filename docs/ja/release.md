# リリースの流れ

paludarium の新しい版は、決まった流れで自動的に公開されます。人が判断するのは、
release PR をマージするかどうかだけです。詳しい手順と、すべての確かめの一覧は、
英語の [Release process](/release) にあります。

## 流れ

1. **release PR**：[Release Please](https://github.com/googleapis/release-please) が、
   main に入ったコミットの種類（Conventional Commits）から次の版を決めて、版を更新する
   release PR を開いたままにします。リリースノートは release PR の本文に書かれ、
   `CHANGELOG.md` は作りません。
2. **マージ**：人が release PR をマージします。毎週月曜には、自動でマージする仕組みもあります。
3. **同じコードでの確かめ**：マージしたコードで、[テストと検証](./design/quality) のすべて
   （3 つの OS、4 つの WebAssembly の環境、JIT ありとなし、速さの測定）を動かし、
   受け入れの条件がそろったことを確かめます。
4. **公開**：12 の crate を crates.io に、`@aletheia-works/paludarium-wasm` を npm に、
   Trusted Publishing（OIDC）で公開します。続けて、npm と同じファイルを JSR に、
   パッケージにリンクした GitHub リポジトリの OIDC で公開します（0.15.0 の次のリリースから）。
   npm と JSR には provenance を付けます。人の承認は待ちません。
   JSR への公開には Deno 2.8.1 を使い、dry run とアップロードの前にその版であることを確かめます
   （CI は setup-deno で、`mise.toml` は mise で固定します）。Deno 2.8.2 以降は、公開するときに
   Wasm の import のモジュール名を書き換えるためです（denoland/deno#34549）。`env` が `./env` に
   なり、JSR の 0.15.0 の `paludarium.wasm` は import オブジェクトで読み込めなくなったので、
   その版は削除しました（denoland/deno#37171）。JSR はそのときの成功した公開タスクを残すので、
   0.15.0 をもう一度アップロードしても断られます（`duplicateVersionPublish`。`deno publish` は
   アップロードせずに終了コード 0 で終わります）。そのため 0.15.0 は JSR なしでリリースしました。
   また、jsr.io の前の CDN は版のメタデータ
   （`<version>_meta.json`）を 1 年キャッシュし、削除した 0.15.0 も 200 を返し続けたので、
   JSR の版のメタデータは毎回新しい `?uncached=` のクエリを付けて問い合わせます。
5. **タグ**：すべての公開が成功した後で、最後にタグと GitHub Release を作ります。
   GitHub Release の本文には、マージした release PR の本文のリリースノートを使います。
   前の Publish の run が止まっている間に main が進むと、公開するのは release PR の
   マージコミットより後の main の head になります。そのときは、間に入ったコミットのうち
   `feat`、`fix`、`perf`、`revert` を、Release Please と同じ形でそれぞれの節に書き足します。
   互換を壊す変更（`!` か `BREAKING CHANGE:` の footer）は、その説明を
   `⚠ BREAKING CHANGES` の節にも書きます。
   次の release PR はタグより後のコミットしか数えないため、ここで書き足さないと、
   どのリリースノートにも載りません。

確かめの job がエミュレーターと関係のない理由（ブラウザーがページを読み込めなかった、
runner がなかったなど）で失敗したら、同じ run の中でその job を再実行します。そのあと、
release-acceptance がもう動いていればその失敗した job を、最後に Publish の run の失敗した
job を再実行します。再実行した job の artifact は、いちばん新しい attempt のものを使います。
ただし、速さを測る `wasm-programs / differential (ubuntu-latest, node)` の job は
再実行できません。同じバイナリーで測り直すことになるためです。

公開に失敗したら、同じ run の中で止まった job を再実行します。公開済みの版は digest を
確かめるだけで飛ばし、残りだけを公開します。公開されていない版にタグが付くことはありません。
原因が公開のスクリプト自体にあるときは、再実行しても同じスクリプトが動いてまた止まります。
その場合は修正を main にマージします。その後の head の Publish の run は、その head の確かめを
改めて行い、同じように公開済みの版を確かめてから残りだけを公開します。そのため、その head の
crate は公開済みの digest と同じでなければなりません（違えば、何もアップロードせずに
止まるので、それまではパッケージの中身を変える変更をマージしません）。npm の tarball は
同じになりません。package check は `target/release-evidence/package-<time_ns>/` でビルドし、
`paludarium.wasm` にはその下の依存のパスが残るためです。そこで、integrity の違う公開済みの
npm の版は、レジストリから取った tarball（レジストリの integrity と一致するもの）が、
`paludarium.wasm` の中のそのディレクトリ名を除いて同じファイルと同じバイトのときに限り認め、
JSR にはその公開済みのファイルを出します。JSR と npm は同じバイトになります。それ以外の違いが
あれば、何もアップロードせずに止まります。リリースノートには、
ほかの後の head と同じく release PR より後のコミットを書き足すので、どのリリースにも載らない
コミットは出ません。0.15.0 は、この形で JSR への最初の問い合わせで止まりました。

## 公開する crate

依存の順に、`paludarium-types`、`paludarium-host`、`paludarium-mmu`、`paludarium-vfs`、
`paludarium-loader`、`paludarium-decoder`、`paludarium-cpu`、`paludarium-jit`、
`paludarium-jit-native`、`paludarium-kernel`、`paludarium-runtime`、`paludarium` の 12 個です。0.x の間は、
minor を上げることで互換を壊す変更をすることがあり、その場合はリリースノートに書きます。

確かめるツールチェーンは、`rust-toolchain.toml` に固定した nightly です。どの crate も `rust-version` は
最新の stable の Rust で（`scripts/bump-pins.py` がリリースごとに上げます）、パッケージの検査は crate の外の
利用者をその stable の Rust でもビルドします。WebAssembly 版（Rust の Wasm アダプタと、wasm32 の
`paludarium-host`）は、nightly の build-std と atomics の wait を使います。
