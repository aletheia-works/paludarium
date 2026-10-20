---
layout: home
hero:
  name: paludarium
  text: x86-64 Linux のプログラムを、どこでも
  tagline: Rust で書いた、ユーザーモードの x86-64 Linux エミュレータです。静的な Linux のバイナリを、Linux・macOS・Windows と WebAssembly の上で動かします。
  actions:
    - theme: brand
      text: はじめる
      link: /ja/guide/introduction
    - theme: alt
      text: デモ
      link: /ja/demo
    - theme: alt
      text: GitHub
      link: https://github.com/aletheia-works/paludarium
features:
  - title: Linux のバイナリをそのまま
    details: C や Rust のプログラムを static-musl でビルドしたものなど、静的にリンクした x86-64 Linux のプログラムを、変更せずに動かします。
    link: /ja/guide/introduction
  - title: Linux・macOS・Windows とブラウザ
    details: 同じ ELF が、3 つのネイティブのホストと、WebAssembly を通して Node.js、Chromium、Firefox、Safari で動きます。
    link: /ja/guide/platforms
  - title: ゲストを外に出さない
    details: システムコールは明示した表で扱い、知らないものには ENOSYS を返します。見せたホストのディレクトリの外には出られません。
    link: /ja/design/architecture
  - title: 本物の Linux と同じ結果
    details: 公開の前に、すべての環境で、すべての結果を本物の x86-64 Linux と比べる差分テストをしています。
    link: /ja/design/quality
  - title: WebAssembly 向けの JIT
    details: よく通る x86-64 のコードを WebAssembly に変換します。測った Node.js の実行では、インタプリタより約 21% 速くなりました。
    link: /ja/guide/javascript#jit
  - title: 今すぐ試す
    details: ページの中で小さな x86-64 Linux のプログラムを組み立てて、ブラウザで動かします。
    link: /ja/demo

---
