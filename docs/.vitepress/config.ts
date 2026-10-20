import { defineConfig, type DefaultTheme } from 'vitepress'

const base = '/paludarium/'
const repository = 'https://github.com/aletheia-works/paludarium'

function nav(prefix: string, labels: { guide: string; design: string; demo: string }): DefaultTheme.NavItem[] {
  return [
    { text: labels.guide, link: `${prefix}/guide/introduction`, activeMatch: `${prefix}/guide/` },
    { text: labels.design, link: `${prefix}/design/architecture`, activeMatch: `${prefix}/design/` },
    { text: labels.demo, link: `${prefix}/demo` },
  ]
}

type Labels = Record<
  | 'start' | 'introduction' | 'gettingStarted' | 'use' | 'cli' | 'rust' | 'javascript'
  | 'reference' | 'platforms' | 'features' | 'limitations'
  | 'design' | 'architecture' | 'quality' | 'decisions' | 'roadmap' | 'release',
  string
>

function sidebar(prefix: string, t: Labels): DefaultTheme.Sidebar {
  const guide = [
    { text: t.start, items: [
      { text: t.introduction, link: `${prefix}/guide/introduction` },
      { text: t.gettingStarted, link: `${prefix}/guide/getting-started` },
    ] },
    { text: t.use, items: [
      { text: t.cli, link: `${prefix}/guide/cli` },
      { text: t.rust, link: `${prefix}/guide/rust` },
      { text: t.javascript, link: `${prefix}/guide/javascript` },
    ] },
    { text: t.reference, items: [
      { text: t.platforms, link: `${prefix}/guide/platforms` },
      { text: t.features, link: `${prefix}/guide/features` },
      { text: t.limitations, link: `${prefix}/guide/limitations` },
    ] },
  ]
  const design = [
    { text: t.design, items: [
      { text: t.architecture, link: `${prefix}/design/architecture` },
      { text: t.quality, link: `${prefix}/design/quality` },
      { text: t.decisions, link: `${prefix}/design/decisions` },
      { text: t.roadmap, link: `${prefix}/design/roadmap` },
      { text: t.release, link: `${prefix}/release` },
    ] },
  ]
  return { [`${prefix}/guide/`]: guide, [`${prefix}/design/`]: design, [`${prefix}/release`]: design }
}

export default defineConfig({
  base,
  title: 'paludarium',
  cleanUrls: true,
  lastUpdated: true,
  // The AI-DLC working records under docs/ are not part of the site.
  srcExclude: ['reports/**', 'u*/**', 'aidlc-checkpoint-repair.md', 'node_modules/**', 'scripts/**'],
  head: [
    // SharedArrayBuffer needs cross-origin isolation; GitHub Pages cannot send
    // COOP/COEP headers, so this service worker adds them (it reloads once).
    ['script', { src: `${base}coi-serviceworker.js` }],
    ['link', { rel: 'icon', href: `${base}favicon.svg`, type: 'image/svg+xml' }],
  ],
  themeConfig: {
    logo: '/favicon.svg',
    socialLinks: [{ icon: 'github', link: repository }],
    search: {
      provider: 'local',
      options: {
        locales: {
          ja: {
            translations: {
              button: { buttonText: '検索', buttonAriaLabel: '検索' },
              modal: {
                displayDetails: '詳しい一覧を表示',
                resetButtonTitle: '検索をリセット',
                backButtonTitle: '検索を閉じる',
                noResultsText: '見つかりませんでした',
                footer: { selectText: '選ぶ', navigateText: '移動', closeText: '閉じる' },
              },
            },
          },
        },
      },
    },
  },
  locales: {
    root: {
      label: 'English',
      lang: 'en',
      description: 'Run static x86-64 Linux programs on Linux, macOS, Windows and in the browser.',
      themeConfig: {
        nav: nav('', { guide: 'Guide', design: 'Design', demo: 'Live demo' }),
        sidebar: sidebar('', {
          start: 'Getting started', introduction: 'What is paludarium?', gettingStarted: 'Install',
          use: 'Usage', cli: 'Command line', rust: 'Rust library', javascript: 'JavaScript and the browser',
          reference: 'Reference', platforms: 'Supported platforms', features: 'Supported features', limitations: 'Limitations',
          design: 'Design', architecture: 'Architecture', quality: 'Testing and verification', decisions: 'Design decisions',
          roadmap: 'Roadmap', release: 'Release process',
        }),
        editLink: { pattern: `${repository}/edit/main/docs/:path`, text: 'Edit this page on GitHub' },
        footer: { message: 'Released under the Apache-2.0 License.', copyright: 'aletheia-works' },
      },
    },
    ja: {
      label: '日本語',
      lang: 'ja',
      link: '/ja/',
      description: '静的な x86-64 Linux のプログラムを、Linux・macOS・Windows とブラウザで動かします。',
      themeConfig: {
        nav: nav('/ja', { guide: 'ガイド', design: '設計', demo: 'デモ' }),
        sidebar: sidebar('/ja', {
          start: 'はじめに', introduction: 'paludarium とは', gettingStarted: 'インストール',
          use: '使い方', cli: 'コマンドライン', rust: 'Rust のライブラリ', javascript: 'JavaScript とブラウザ',
          reference: 'リファレンス', platforms: '対応環境', features: '対応している機能', limitations: '制限',
          design: '設計', architecture: 'アーキテクチャ', quality: 'テストと検証', decisions: '設計の判断',
          roadmap: 'ロードマップ', release: 'リリースの流れ',
        }),
        editLink: { pattern: `${repository}/edit/main/docs/:path`, text: 'GitHub でこのページを編集' },
        footer: { message: 'Apache-2.0 ライセンスで公開しています。', copyright: 'aletheia-works' },
        outline: { label: 'このページの内容' },
        docFooter: { prev: '前のページ', next: '次のページ' },
        lastUpdated: { text: '最終更新' },
        returnToTopLabel: 'ページの先頭へ',
        sidebarMenuLabel: 'メニュー',
        darkModeSwitchLabel: '表示',
        langMenuLabel: '言語',
      },
    },
  },
})
