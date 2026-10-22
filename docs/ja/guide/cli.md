# コマンドライン

`paludarium` crate には、静的な x86-64 Linux のプログラムを 1 つ、ホストの上で動かす
`paludarium` コマンドも入っています。

```sh
cargo install paludarium
paludarium [--env KEY=VALUE]... [--mount HOST:GUEST]... [--no-jit] [--report-enosys] <program> [args...]
```

- `<program>` はホストのファイルです。ゲストの中では `/<ファイル名>` に置かれ、
  `argv[0]` は指定した文字列のままになります。
- `--env KEY=VALUE` は環境変数を足します。何度でも指定できます。
- `--mount HOST:GUEST` は、ホストのディレクトリを 1 つ、ゲストの絶対パス `GUEST` に
  見せます。何度でも指定できます。ゲストは `..` やシンボリックリンクを使っても、
  そのディレクトリの外には出られません。
- `--no-jit` は互換のために受け付けますが、ネイティブ版には JIT がないので何もしません。
- `--report-enosys` を付けると、ゲストが呼んだのに paludarium が実装していない
  システムコール（`ENOSYS` を返したもの）の番号を、終わった後に表示します。
- `--` でオプションを終わりにできます。`-` で始まる名前のプログラムを動かすときに使います。

## 終了コード

| 終了コード | 意味 |
|---|---|
| ゲストの終了コード | ゲストが `exit` か `exit_group` を呼んだ |
| 128 + シグナルの番号 | ゲストがシグナルで終わった |
| 2 | コマンドラインの指定の誤り |
| 70 | エミュレータ自身のエラー（`EX_SOFTWARE`） |

## 足りないものを探す

CPU のフォールトでゲストが終わったときは、どのシグナルでどこで止まったかを、
シェルがクラッシュを知らせるのと同じように標準エラーに 1 行表示します。
ゲスト自身から見える結果は、Linux とまったく同じです。

```text
paludarium: SIGILL: cannot run the instruction at 0x5555556e1189 (bytes 41 0f 18 0b 48 83 c0 04 41 0f 18 4b 40 8b 7a)
paludarium: SIGSEGV: read of an unmapped address 0x0 at 0x401000
```

バイト列の先頭が、paludarium が実行できなかった命令です。その後ろは、メモリで
それに続くバイトです。実装していないシステムコールを呼んだプログラムは `ENOSYS` を
受け取り、そのまま動き続けることが多いので、`--report-enosys` を付けたときだけ
表示します。

```text
paludarium: unimplemented system calls (they returned ENOSYS): 28, 63, 204
```

番号は x86-64 の Linux のシステムコールの表のものです。エミュレータ自身のエラーは
`paludarium: <種類>: <メッセージ>` と表示します。
