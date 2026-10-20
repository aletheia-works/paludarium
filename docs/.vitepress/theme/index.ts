import DefaultTheme from 'vitepress/theme'
import type { Theme } from 'vitepress'
import HelloDemo from './HelloDemo.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('HelloDemo', HelloDemo)
  },
} satisfies Theme
