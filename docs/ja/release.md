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
4. **公開**：11 の crate を crates.io に、`@aletheia-works/paludarium-wasm` を npm に、
   Trusted Publishing（OIDC）で公開します。npm には provenance を付けます。人の承認は
   待ちません。
5. **タグ**：すべての公開が成功した後で、最後にタグと GitHub Release を作ります。
   GitHub Release の本文には、マージした release PR の本文のリリースノートを使います。

公開に失敗したら、同じ run の中で止まった job を再実行します。公開済みの版は digest を
確かめるだけで飛ばし、残りだけを公開します。公開されていない版にタグが付くことはありません。

## 公開する crate

依存の順に、`paludarium-types`、`paludarium-host`、`paludarium-mmu`、`paludarium-vfs`、
`paludarium-loader`、`paludarium-decoder`、`paludarium-cpu`、`paludarium-jit`、
`paludarium-kernel`、`paludarium-runtime`、`paludarium` の 11 個です。0.x の間は、
minor を上げることで互換を壊す変更をすることがあり、その場合はリリースノートに書きます。
