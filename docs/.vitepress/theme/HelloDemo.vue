<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useData, withBase } from 'vitepress'
import { helloElf, MAX_MESSAGE_BYTES } from './hello-elf'

const { lang } = useData()
const ja = computed(() => lang.value === 'ja')
const t = computed(() => ja.value
  ? {
      message: 'プログラムが表示するメッセージ',
      run: '実行する',
      running: '実行中…',
      loading: 'paludarium を読み込んでいます…',
      output: '標準出力',
      exited: (code: number) => `終了コード ${code} で終了しました。`,
      signaled: (signal: number) => `シグナル ${signal} で終了しました。`,
      notIsolated: 'このページはまだ cross-origin isolated ではありません。ページを再読み込みしてください（初回はサービスワーカーが登録されます）。',
      unsupported: 'このブラウザは SharedArrayBuffer か module Worker に対応していません。',
      bytes: (n: number) => `ELF は ${n} バイトです。`,
    }
  : {
      message: 'Message the program prints',
      run: 'Run',
      running: 'Running…',
      loading: 'Loading paludarium…',
      output: 'Standard output',
      exited: (code: number) => `Exited with status ${code}.`,
      signaled: (signal: number) => `Ended by signal ${signal}.`,
      notIsolated: 'This page is not cross-origin isolated yet. Reload the page (the first visit registers a service worker).',
      unsupported: 'This browser does not support SharedArrayBuffer or module Workers.',
      bytes: (n: number) => `The ELF is ${n} bytes.`,
    })

const message = ref('Hello from x86-64 Linux, running in your browser!')
const output = ref('')
const status = ref('')
const error = ref('')
const busy = ref(false)
const ready = ref(false)
let launcher: { run: Function; dispose: () => Promise<void> } | undefined
const importModule = new Function('url', 'return import(url)') as (url: string) => Promise<any>

onMounted(() => {
  if (typeof SharedArrayBuffer === 'undefined' || typeof Worker === 'undefined') error.value = t.value.unsupported
  else if (!globalThis.crossOriginIsolated) error.value = t.value.notIsolated
  else ready.value = true
})
onBeforeUnmount(() => { void launcher?.dispose() })

async function run() {
  busy.value = true
  output.value = ''
  status.value = ''
  error.value = ''
  try {
    const program = helloElf(message.value.endsWith('\n') ? message.value : `${message.value}\n`)
    if (!launcher) {
      status.value = t.value.loading
      // The package starts its Workers relative to its own modules, so it is
      // served as is from public/paludarium/ instead of being bundled. The
      // import goes through a function so that Vite does not rewrite it.
      const url = new URL(withBase('/paludarium/index.mjs'), location.href).href
      const { createPaludarium } = await importModule(url)
      launcher = await createPaludarium({ wasmUrl: withBase('/paludarium/paludarium.wasm') })
    }
    status.value = t.value.running
    const guest = launcher!.run({ program: '/hello', files: { '/hello': program }, args: ['/hello'] })
    const stdout = new Response(guest.stdout).text()
    const stderr = new Response(guest.stderr).text()
    await guest.stdin.getWriter().close()
    const exit = await guest.exited
    output.value = (await stdout) + (await stderr)
    status.value = `${exit.kind === 'exited' ? t.value.exited(exit.code) : t.value.signaled(exit.signal)} ${t.value.bytes(program.length)}`
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
    status.value = ''
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="hello-demo">
    <label class="field">
      <span>{{ t.message }}</span>
      <input v-model="message" type="text" :maxlength="MAX_MESSAGE_BYTES" spellcheck="false" />
    </label>
    <button type="button" :disabled="!ready || busy" @click="run">{{ busy ? t.running : t.run }}</button>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
    <div class="result" aria-live="polite">
      <div class="label">{{ t.output }}</div>
      <pre><code>{{ output }}</code></pre>
      <p v-if="status" class="status">{{ status }}</p>
    </div>
  </div>
</template>

<style scoped>
.hello-demo { margin: 24px 0; padding: 20px; border: 1px solid var(--vp-c-divider); border-radius: 12px; background: var(--vp-c-bg-soft); }
.field { display: flex; flex-direction: column; gap: 6px; font-weight: 600; }
.field input { font: inherit; font-weight: 400; padding: 8px 12px; border: 1px solid var(--vp-c-divider); border-radius: 8px; background: var(--vp-c-bg); color: var(--vp-c-text-1); width: 100%; }
button { margin-top: 12px; padding: 8px 20px; border-radius: 20px; background: var(--vp-c-brand-3); color: var(--vp-c-white); font-weight: 600; }
button:disabled { opacity: 0.5; cursor: not-allowed; }
.error { color: var(--vp-c-danger-1); }
.result { margin-top: 16px; }
.label { font-size: 13px; color: var(--vp-c-text-2); }
.result pre { margin: 6px 0 0; padding: 12px 16px; min-height: 3em; border-radius: 8px; background: var(--vp-code-block-bg); overflow-x: auto; }
.status { margin: 8px 0 0; font-size: 14px; color: var(--vp-c-text-2); }
</style>
