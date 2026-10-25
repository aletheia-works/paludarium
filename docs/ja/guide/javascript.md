# JavaScript とブラウザ

[`@aletheia-works/paludarium-wasm`](https://www.npmjs.com/package/@aletheia-works/paludarium-wasm)
は、x86-64 Linux のプログラムを、共有された WebAssembly のメモリの上で動かします。
ゲストのスレッド 1 つにつき Worker を 1 つ使います。同じモジュールが、ブラウザでも
Node.js（`worker_threads`）でも動きます。[デモ](../demo) もこのパッケージを使っています。

```sh
npm install @aletheia-works/paludarium-wasm
```

## プログラムを動かす

```js
import { createPaludarium } from "@aletheia-works/paludarium-wasm";

const launcher = await createPaludarium({ wasmUrl: "/paludarium.wasm" });
try {
  const guest = launcher.run({
    program: "/guest",
    files: { "/guest": elfBytes }, // Uint8Array。既定の権限は 0755
    args: ["/guest"],
  });
  const output = new Response(guest.stdout).text();
  const errors = new Response(guest.stderr).text();
  await guest.stdin.getWriter().close();
  console.log(await guest.exited, await output, await errors);
} finally {
  await launcher.dispose();
}
```

- `createPaludarium({ wasmUrl })` は、パッケージに入っている `paludarium.wasm` を
  読み込み、まとめ役の Worker を起動します。
- `run(options)` はゲストを 1 つ起動して、すぐに戻ります。`stdin` は
  `WritableStream`、`stdout` と `stderr` は `Uint8Array` の `ReadableStream` で、
  `exited` は `{ kind: "exited", code }` か `{ kind: "signaled", signal }` になります。
- `exited` を待つ前に、2 つの出力を読み切り、`stdin` を閉じてください。
- `kill()` は、協調的な `SIGKILL` でゲストに止まるよう求めます。ゲストには自動の
  時間切れがないので、必要なら自分で期限を決め、止まらないときは launcher を
  `dispose()` してください。

### run の options

| 項目 | 意味 |
|---|---|
| `program` | 動かすプログラムの、ゲストの中での絶対パス |
| `args` | `argv`（`argv[0]` を含む） |
| `env` | 環境変数（オブジェクト） |
| `cwd` | 最初の作業ディレクトリ（既定は `/`。存在している必要があります） |
| `files` | 起動の前に作るファイル。パス → `Uint8Array` |
| `fileModes` | `files` の一部の権限（既定は `0755`） |
| `entries` | `files` の後に作る木。snapshot など（下を参照）。`filesystem` と一緒には使えません |
| `tty` | 端末の大きさ `{ columns, rows }`（0〜65535） |
| `filesystem` | 使い回す、`createFileSystem()` で作ったファイルシステム（下を参照） |
| `jit` | `true` にすると、よく通る x86-64 のコードを WebAssembly に変換する（既定は `false`） |
| `limits` | ゲストに上限を設ける `{ tasks, openFiles }`（既定は上限なし。下を参照） |

このパッケージは、ホストのディレクトリもネットワークも、ゲストに見せません。

`limits.tasks`（1〜4294967295）は、ゲストが同時に持てるタスクの数です。タスクは
スレッドと、回収されるまでのプロセスで、cgroup の `pids.max` と同じ数え方です。
それを超える `clone` や `fork` は `EAGAIN` で失敗します。`limits.openFiles`
（0〜1048576）は `RLIMIT_NOFILE` の天井で、Linux の `fs.nr_open` と同じです。
ゲストは両方の上限がこの値以下の状態で始まり、それより上には上げられません
（`EPERM`）。そのため、それ以上ファイルを開くと `EMFILE` になります。メモリには、
まだ上限がありません。

## 実行の間でファイルを残す

`run()` のたびに、ほかとは切り離された、メモリ上のファイルシステムが作られます。
ゲストの間で状態を残したいときは、ファイルシステムを作って `run()` に渡します。

```js
const filesystem = await launcher.createFileSystem({
  files: { "/app/program": elfBytes, "/app/input": inputBytes },
  fileModes: { "/app/input": 0o644 },
});
const guest = launcher.run({ program: "/app/program", cwd: "/app", filesystem });
// 上と同じように、exited を待つ前に出力を読み切り、stdin を閉じます。
await guest.exited;
const entries = await filesystem.snapshot();
await filesystem.remove("/app/node_modules", { recursive: true });
await filesystem.dispose();
```

動いているゲストは、そのファイルシステムを独占します。その間は、`snapshot()`、
`remove()`、`dispose()` と、同じファイルシステムを使う 2 つ目の `run()` は断られます。
snapshot は、すべてのパスについて、権限、inode、リンクの数、ナノ秒の更新時刻と、
通常ファイルの中身かシンボリックリンクの行き先のバイト列を返します。
シンボリックリンクはたどりません。スナップショットは 272 MiB までで、それを超えると `snapshot()` は失敗します。
エラーなく作れたファイルシステムでも、超えることがあります。スナップショットはハードリンクごとに中身を書き
（作るときはまとまりを 1 回だけ数えます）、項目ごとに約 44 バイトとパスを書くので、大きなファイルへの
多くのハードリンクや、上限の 1,048,576 個に近い項目があると超えます。

### snapshot からファイルシステムを作り直す

`createFileSystem({ entries })` は、`snapshot()` が返すのと同じ形の一覧からファイル
システムを作ります。snapshot はそのまま渡せます。実行のたびに launcher を作り直す
ホストは、こうしてファイルシステムを引き継げます。

```js
const entries = await filesystem.snapshot();
await filesystem.dispose();
const next = await launcher.createFileSystem({ entries });
```

各項目は `path` と、種類のビットで通常ファイル・ディレクトリ・シンボリックリンクの
どれかを表す `mode` を持ち、`content`（ファイルの中身かリンクの行き先）、`mtimeNs`
（既定は 0）、`inode` を持てます。同じ `inode` の値を持つ項目は、1 つのファイルか
シンボリックリンクへのハードリンクになります。値そのものは引き継がず、`links` は
数え直すので、snapshot から項目を除いてから渡してもかまいません。新しいファイル
システムには必ず `/` と `/tmp` があります。それらや、`files` のために作られた
ディレクトリの項目は、そのディレクトリの権限と時刻を設定します。

作り直したものは、snapshot のパス、種類、権限、ファイルの中身、リンクの行き先、
更新時刻、リンクの数と、どのパスが同じ inode かを保ちます。UTF-8 でない名前は
snapshot の時点で置き換わっていて、アクセス時刻と変更時刻は引き継ぎません。

一覧は何かを作る前に確かめ、問題があれば kind が `"invalid-program"` の
`PaludariumError` が、最初の問題とそのパスを示します。

- `path` は絶対パスで正規化されていること（`.`、`..`、空、末尾の `/` を含まない）。
  4096 バイト未満で、各部分は 255 バイト以下。`files` も含めて 1 回だけ現れること。
- 親は、ディレクトリの項目、`/`、`/tmp`、`files` のために作られたディレクトリの
  どれかであること。シンボリックリンクは親になれません。
- `mode` は種類のビットと権限 0o7777 だけを持つこと。シンボリックリンクの権限は
  0o777 で、行き先は NUL を含まない 1〜4095 バイト。ディレクトリは中身を持たないこと。
- 同じ `inode` を持つ項目は、同じ種類のファイルかシンボリックリンクで、権限・時刻・
  中身が同じであること。
- 項目は 1,048,576 個まで、1 つあたり 128 MiB まで、中身は合わせて 256 MiB まで
  （ハードリンクのまとまりは 1 回だけ数えます）。

## エラー

ゲストが終わったときやシグナルで止まったときは、`exited` が resolve します。
エミュレータ自身のエラーのときは、`PaludariumError` で reject します。`kind` は
`"unimplemented"`・`"internal"`・`"invalid-program"`・`"host"` のどれかで、
わかっていれば、命令のアドレス（`rip`）、命令の `bytes`、`syscall` の番号も持っています。
Worker が trap したときは、共有のランタイム全体を捨てます。捨てた Worker が
ロックを持っていたかもしれないためです。

## ブラウザで必要なもの

- `SharedArrayBuffer` と module Worker。
- ページ、`paludarium.wasm`、パッケージの `.mjs` を同じ origin から配り、
  `Cross-Origin-Opener-Policy: same-origin` と
  `Cross-Origin-Embedder-Policy: require-corp` を付けてください。ヘッダーを付けられない
  ホストでは、このサイトのように
  [coi-serviceworker](https://github.com/gzuidhof/coi-serviceworker) のような
  service worker で足せます。
- パッケージのファイルは、そのまま配ってください。launcher は `index.mjs` からの相対パスで
  Worker を起動するので、バンドラーで中に取り込んだり名前を変えたりしてはいけません。

## JIT

`jit: true` にすると、paludarium は、レジスタだけを使う x86-64 の命令のまとまりを、
ゲストの Worker の中で WebAssembly のモジュールに変換して、取っておきます。それ以外は
これまでどおりインタプリタで動き、結果は同じです。測った Node.js の実行では、probe の
プログラム全体が、JIT ありで約 21 % 速くなりました。
[テストと検証](../design/quality#jit-とインタプリタ) を見てください。
