import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// The SPA is deployed as an IIS application under the Laravel site, at
// domain/app/, so assets must resolve under that base. The backend (Laravel)
// is the site root, so API calls go to the root (/api, /nafath) — same origin.
// https://vite.dev/config/
export default defineConfig({
  plugins: [vue()],
  base: '/app/',
  server: {
    port: 5173,
    proxy: {
      // Forward backend calls to Laravel during local dev.
      '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true },
      '/nafath': { target: 'http://127.0.0.1:8000', changeOrigin: true },
      '/_IAM': { target: 'http://127.0.0.1:8000', changeOrigin: true },
    },
  },
})
