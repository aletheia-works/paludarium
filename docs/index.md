---
layout: home
hero:
  name: paludarium
  text: x86-64 Linux programs, anywhere
  tagline: A user-mode x86-64 Linux emulator in Rust. Run static Linux binaries on Linux, macOS, Windows and in WebAssembly.
  actions:
    - theme: brand
      text: Get started
      link: /guide/introduction
    - theme: alt
      text: Live demo
      link: /demo
    - theme: alt
      text: GitHub
      link: https://github.com/aletheia-works/paludarium
features:
  - title: Unchanged Linux binaries
    details: Runs statically linked x86-64 Linux programs, such as static-musl builds of C and Rust programs, without changing them.
    link: /guide/introduction
  - title: Linux, macOS, Windows and the browser
    details: The same ELF runs on three native hosts, in Node.js, and in Chromium, Firefox and Safari through WebAssembly.
    link: /guide/platforms
  - title: The guest stays inside
    details: System calls go through an explicit table, unknown ones return ENOSYS, and a shown host directory cannot be left.
    link: /design/architecture
  - title: Same results as real Linux
    details: Differential tests compare every result with a real x86-64 Linux on every platform before each release.
    link: /design/quality
  - title: A JIT for WebAssembly
    details: Translates hot x86-64 code into WebAssembly; about 21 % faster than the interpreter in the measured Node.js run.
    link: /guide/javascript#the-jit
  - title: Try it now
    details: Build a tiny x86-64 Linux program in the page and run it in your browser.
    link: /demo

---
