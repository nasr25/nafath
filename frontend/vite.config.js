import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import fs from 'node:fs'

// The IAM callback (redirect_uri) is registered as
// https://mydomain.com/_IAM/login, so IAM hands the token to the browser at
// THAT host over HTTPS. To capture it on this machine we:
//   1) map mydomain.com -> 127.0.0.1 in the hosts file, and
//   2) serve this dev app for that host over HTTPS on port 443.
// Drop a cert/key at frontend/certs/mydomain.com.pem(+ -key.pem) (e.g. via
// mkcert) and this config switches to the HTTPS-on-443 callback setup.
// Without the certs it falls back to the plain http://localhost:5173 dev mode.
const cert = './certs/mydomain.com.pem'
const key = './certs/mydomain.com-key.pem'
const haveCerts = fs.existsSync(cert) && fs.existsSync(key)

// https://vite.dev/config/
export default defineConfig({
  plugins: [vue()],
  server: {
    host: haveCerts ? 'mydomain.com' : true,
    port: haveCerts ? 443 : 5173,
    // Allow IAM's redirect to land on this dev server under the real host name.
    allowedHosts: ['mydomain.com'],
    https: haveCerts
      ? { cert: fs.readFileSync(cert), key: fs.readFileSync(key) }
      : undefined,
    proxy: {
      // Forward API calls to the Laravel backend during development.
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
})
