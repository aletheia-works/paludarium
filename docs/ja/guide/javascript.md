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
| `tty` | 端末の大きさ `{ columns, rows }`（0〜65535） |
| `filesystem` | 使い回す、`createFileSystem()` で作ったファイルシステム（下を参照） |
| `jit` | `true` にすると、よく通る x86-64 のコードを WebAssembly に変換する（既定は `false`） |

このパッケージは、ホストのディレクトリもネットワークも、ゲストに見せません。

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
シンボリックリンクはたどりません。

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
