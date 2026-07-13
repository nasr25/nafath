<script setup>
import { ref, onMounted, computed } from 'vue'

const loading = ref(false)
const error = ref('')
const result = ref(null) // { authorize_url, request, payload }

// Callback state (populated when IAM redirects back to /callback)
const callback = ref(null)

const jwtHeader = computed(() => {
  if (!result.value?.request) return null
  try {
    const [h] = result.value.request.split('.')
    return JSON.parse(atob(h.replace(/-/g, '+').replace(/_/g, '/')))
  } catch {
    return null
  }
})

async function buildRequest() {
  loading.value = true
  error.value = ''
  result.value = null
  try {
    const res = await fetch('/api/nafath/authorize')
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    result.value = await res.json()
  } catch (e) {
    error.value = `Failed to reach backend: ${e.message}. Is Laravel running on :8000?`
  } finally {
    loading.value = false
  }
}

function redirectToNafath() {
  if (result.value?.authorize_url) {
    window.location.href = result.value.authorize_url
  }
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    /* ignore */
  }
}

// Send the token IAM returned to the backend for FULL verification
// (signature against the IAM cert + issuer/audience + one-time state/nonce).
// The browser only ever sees the fragment, so we forward it here.
async function verifyCallback(idToken, state) {
  callback.value = { loading: true }
  try {
    const res = await fetch('/api/nafath/callback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ Id_token: idToken, State: state }),
    })
    const data = await res.json()
    callback.value = {
      ok: res.ok && data.status === true,
      idToken,
      message: data.message,
      claims: data.data ?? null,
    }
  } catch (e) {
    callback.value = {
      ok: false,
      idToken,
      message: `Failed to reach backend: ${e.message}. Is Laravel running on :8000?`,
      claims: null,
    }
  }
}

onMounted(() => {
  // Detect a Nafath callback. IAM may return id_token in the URL fragment
  // (#id_token=...) or the query string (?id_token=...).
  if (window.location.pathname.includes('/callback')) {
    const hash = new URLSearchParams(window.location.hash.slice(1))
    const query = new URLSearchParams(window.location.search)
    const idToken = hash.get('id_token') || query.get('id_token')
    const errParam = hash.get('error') || query.get('error')
    const state = hash.get('state') || query.get('state')

    if (errParam) {
      callback.value = { ok: false, error: errParam }
    } else if (idToken) {
      // Verify server-side rather than decoding unverified in the browser.
      verifyCallback(idToken, state)
    } else {
      callback.value = { ok: false, message: 'No id_token in the callback URL.' }
    }
  }
})
</script>

<template>
  <div class="page">
    <header class="head">
      <h1>Nafath OIDC — Test Console</h1>
      <p class="sub">Build &amp; inspect the signed OIDC request sent to IAM (نفاذ)</p>
    </header>

    <!-- Callback view -->
    <section v-if="callback" class="card">
      <h2>Callback received</h2>

      <p v-if="callback.loading" class="muted">Verifying with backend…</p>

      <template v-else>
        <p v-if="callback.error" class="err">IAM returned an error: {{ callback.error }}</p>
        <p v-else-if="callback.ok" class="ok">✓ {{ callback.message || 'Verified' }}</p>
        <p v-else class="err">✗ Verification failed: {{ callback.message }}</p>

        <template v-if="callback.claims">
          <label>Verified claims (from backend)</label>
          <pre class="mono">{{ JSON.stringify(callback.claims, null, 2) }}</pre>
        </template>

        <template v-if="callback.idToken">
          <label>id_token</label>
          <pre class="mono wrap short">{{ callback.idToken }}</pre>
        </template>
      </template>

      <a class="btn ghost" href="/">← Back</a>
    </section>

    <!-- Main view -->
    <section v-else class="card">
      <button class="btn primary" :disabled="loading" @click="buildRequest">
        {{ loading ? 'Building…' : 'Build Nafath request' }}
      </button>

      <p v-if="error" class="err">{{ error }}</p>

      <template v-if="result">
        <div class="row">
          <label>Authorize URL</label>
          <button class="link" @click="copy(result.authorize_url)">copy</button>
        </div>
        <pre class="mono wrap">{{ result.authorize_url }}</pre>

        <div class="row">
          <label>JWT header</label>
        </div>
        <pre class="mono">{{ JSON.stringify(jwtHeader, null, 2) }}</pre>

        <div class="row">
          <label>JWT payload (request object)</label>
        </div>
        <pre class="mono">{{ JSON.stringify(result.payload, null, 2) }}</pre>

        <div class="row">
          <label>Signed request (JWT)</label>
          <button class="link" @click="copy(result.request)">copy</button>
        </div>
        <pre class="mono wrap short">{{ result.request }}</pre>

        <button class="btn accent" @click="redirectToNafath">
          Redirect to Nafath →
        </button>
        <p class="muted">
          Note: the live redirect only works once your SP + certificate are
          registered with the IAM integration team.
        </p>
      </template>
    </section>

    <footer class="foot">Laravel 10 API · Vue 3 · RS256 signed request</footer>
  </div>
</template>

<style>
:root {
  --bg: #0f172a;
  --card: #1e293b;
  --line: #334155;
  --text: #e2e8f0;
  --muted: #94a3b8;
  --primary: #2563eb;
  --accent: #16a34a;
  --err: #f87171;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font-family: ui-sans-serif, system-ui, Segoe UI, Roboto, sans-serif; }
.page { max-width: 760px; margin: 0 auto; padding: 32px 20px 64px; }
.head h1 { margin: 0; font-size: 26px; }
.sub { color: var(--muted); margin: 6px 0 24px; }
.card { background: var(--card); border: 1px solid var(--line);
  border-radius: 12px; padding: 22px; }
h2 { margin-top: 0; }
label { font-size: 13px; color: var(--muted); text-transform: uppercase;
  letter-spacing: .04em; }
.row { display: flex; align-items: center; justify-content: space-between;
  margin-top: 18px; }
.mono { background: #0b1220; border: 1px solid var(--line); border-radius: 8px;
  padding: 12px; font-family: Consolas, Menlo, monospace; font-size: 13px;
  overflow-x: auto; margin: 6px 0 0; }
.wrap { white-space: pre-wrap; word-break: break-all; }
.short { max-height: 140px; overflow-y: auto; }
.btn { border: none; border-radius: 8px; padding: 11px 18px; font-size: 15px;
  font-weight: 600; cursor: pointer; color: #fff; margin-top: 8px; }
.btn.primary { background: var(--primary); }
.btn.accent { background: var(--accent); margin-top: 20px; }
.btn.ghost { background: transparent; border: 1px solid var(--line);
  color: var(--text); text-decoration: none; display: inline-block; }
.btn:disabled { opacity: .6; cursor: default; }
.link { background: none; border: none; color: #60a5fa; cursor: pointer;
  font-size: 13px; }
.err { color: var(--err); margin-top: 14px; }
.ok { color: var(--accent); margin-top: 14px; font-weight: 600; }
.muted { color: var(--muted); font-size: 13px; }
.foot { text-align: center; color: var(--muted); font-size: 12px;
  margin-top: 28px; }
</style>
