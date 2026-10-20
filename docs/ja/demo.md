# デモ

このページでは、paludarium をブラウザの中で動かします。**実行する** を押すと、
入力したメッセージを `write` システムコールで表示して `exit_group` で終わる、
小さな静的 x86-64 Linux プログラムをページが組み立て、paludarium が
WebAssembly の上でそれを動かします。

<ClientOnly>
  <HelloDemo />
</ClientOnly>

## 何が起きているか

1. ページが JavaScript で、200 バイトほどの ELF 実行ファイルを組み立てます。
   読み込むセグメントは 1 つで、8 つの命令と入力したメッセージだけを含みます
   （[`hello-elf.ts`](https://github.com/aletheia-works/paludarium/blob/main/docs/.vitepress/theme/hello-elf.ts)）。
2. [`@aletheia-works/paludarium-wasm`](https://www.npmjs.com/package/@aletheia-works/paludarium-wasm)
   を読み込み、そのプログラムを、そのたびに作られるメモリ上のファイルシステムに置いて
   `run()` を呼びます。
3. paludarium が x86-64 の命令をデコードして実行し、2 つのシステムコールを処理し、
   標準出力を Web Streams で、終了状態を Promise で返します。

同じパッケージで、静的にリンクした C や Rust のプログラムのような本物のプログラムも
動かせます。[JavaScript とブラウザ](./guide/javascript) を見てください。

::: info cross-origin isolation
paludarium は `SharedArrayBuffer` を使います。ブラウザは、cross-origin isolated な
ページでしかこれを使わせません。GitHub Pages は必要なヘッダーを付けられないので、
このサイトは [coi-serviceworker](https://github.com/gzuidhof/coi-serviceworker) を
登録してヘッダーを足しています。初めて開いたときに、ページが 1 回だけ再読み込みされます。
:::
