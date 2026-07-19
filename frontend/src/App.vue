<script setup>
import { ref, onMounted, computed } from 'vue'

const loading = ref(false)
const error = ref('')
const result = ref(null) // { authorize_url, request, payload }

// Callback state (populated when IAM redirects back to the callback path)
const callback = ref(null)

// --- Environment config (see .env.example) ---
// Base URL of the Laravel backend. Empty = same origin (the web server on the
// whitelisted host must serve /api, e.g. reverse-proxy it to Laravel). In local
// dev the Vite proxy handles /api, so this stays empty.
const API_BASE = import.meta.env.VITE_API_BASE_URL || ''
// The path IAM redirects back to — must match the registered redirect_uri path.
const CALLBACK_PATH = import.meta.env.VITE_CALLBACK_PATH || '/_IAM/login'

// UTF-8-safe base64url decode (id_token claims include Arabic names).
function b64urlDecode(segment) {
  const b64 = segment.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(b64)
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0))
  return new TextDecoder('utf-8').decode(bytes)
}

const jwtHeader = computed(() => {
  if (!result.value?.request) return null
  try {
    const [h] = result.value.request.split('.')
    return JSON.parse(b64urlDecode(h))
  } catch {
    return null
  }
})

// --- Paste & decode box (home page) ---
// Decode any id_token/JWT locally, WITHOUT verifying the signature. Purely for
// inspecting the claims — never trust these values for auth.
const pasteInput = ref('')
const pasteError = ref('')
const pasted = ref(null) // { header, payload }

function decodePasted() {
  pasteError.value = ''
  pasted.value = null
  const raw = pasteInput.value.trim()
  if (!raw) {
    pasteError.value = 'Paste an id_token first.'
    return
  }
  const parts = raw.split('.')
  if (parts.length < 2) {
    pasteError.value = 'That does not look like a JWT (expected header.payload.signature).'
    return
  }
  try {
    pasted.value = {
      header: JSON.parse(b64urlDecode(parts[0])),
      payload: JSON.parse(b64urlDecode(parts[1])),
    }
  } catch (e) {
    pasteError.value = `Could not decode: ${e.message}`
  }
}

function clearPasted() {
  pasteInput.value = ''
  pasteError.value = ''
  pasted.value = null
}

async function buildRequest() {
  loading.value = true
  error.value = ''
  result.value = null
  try {
    const res = await fetch(`${API_BASE}/api/nafath/authorize`)
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

// IAM Single Logout: full-page navigation (not AJAX) so IAM can fan the logout
// out to the other SPs through the browser. Backend kills the local session,
// then redirects to IAM (?slo=true).
function logout() {
  window.location.href = `${API_BASE}/_IAM/logout`
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
    const res = await fetch(`${API_BASE}/api/nafath/callback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ Id_token: idToken, State: state }),
    })
    const data = await res.json()
    const payload = data.data ?? {}
    callback.value = {
      ok: res.ok && data.status === true,
      idToken,
      message: data.message,
      matched: payload.matched ?? false,
      nationalId: payload.national_id ?? null,
      comparison: payload.comparison ?? [],
      claims: payload.claims ?? null,
    }
  } catch (e) {
    callback.value = {
      ok: false,
      idToken,
      message: `Failed to reach backend: ${e.message}. Is Laravel running on :8000?`,
      comparison: [],
      claims: null,
    }
  }
}

onMounted(() => {
  // Detect a Nafath callback. IAM may return id_token in the URL fragment
  // (#id_token=...) or the query string (?id_token=...).
  if (window.location.pathname.includes(CALLBACK_PATH)) {
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
      <button class="btn ghost logout" @click="logout">Logout (IAM SLO)</button>
    </header>

    <!-- Callback view -->
    <section v-if="callback" class="card">
      <h2>Callback received</h2>

      <p v-if="callback.loading" class="muted">Verifying with backend…</p>

      <template v-else>
        <p v-if="callback.error" class="err">IAM returned an error: {{ callback.error }}</p>
        <p v-else-if="callback.ok" class="ok">✓ {{ callback.message || 'Verified' }}</p>
        <p v-else class="err">✗ Verification failed: {{ callback.message }}</p>

        <!-- DB (old) vs NAFATH (corrected) comparison -->
        <template v-if="callback.ok && callback.matched">
          <div class="row">
            <label>Database vs NAFATH</label>
            <span class="muted">National Id: {{ callback.nationalId }}</span>
          </div>
          <table class="cmp">
            <thead>
              <tr>
                <th>Field</th>
                <th>Database (old)</th>
                <th>NAFATH (corrected)</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in callback.comparison" :key="row.field">
                <td class="fld">{{ row.label }}</td>
                <td :class="row.match ? 'match' : 'mismatch'">{{ row.database ?? '—' }}</td>
                <td :class="row.match ? 'match' : 'mismatch'">{{ row.nafath ?? '—' }}</td>
              </tr>
            </tbody>
          </table>
          <p class="muted">Green = value matches NAFATH · Red = differs (needs correcting).</p>
        </template>

        <p v-else-if="callback.ok && !callback.matched" class="muted">
          No local user found with National Id {{ callback.nationalId }}.
        </p>

        <template v-if="callback.claims">
          <details>
            <summary class="muted">Raw verified claims</summary>
            <pre class="mono">{{ JSON.stringify(callback.claims, null, 2) }}</pre>
          </details>
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

    <!-- Paste & decode an id_token (no verification) -->
    <section v-if="!callback" class="card" style="margin-top: 20px">
      <h2>Decode an id_token</h2>
      <p class="muted">
        Paste the <code>id_token</code> from the IAM callback URL to inspect its
        claims. Decoded locally in your browser — the signature is
        <strong>not</strong> verified, so don't trust these values for auth.
      </p>

      <textarea
        v-model="pasteInput"
        class="mono paste"
        rows="5"
        placeholder="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ..."
        spellcheck="false"
      ></textarea>

      <div class="row" style="justify-content: flex-start; gap: 10px">
        <button class="btn primary" @click="decodePasted">Decode</button>
        <button class="btn ghost" @click="clearPasted">Clear</button>
      </div>

      <p v-if="pasteError" class="err">{{ pasteError }}</p>

      <template v-if="pasted">
        <div class="row"><label>Header</label></div>
        <pre class="mono">{{ JSON.stringify(pasted.header, null, 2) }}</pre>

        <div class="row"><label>Payload (claims)</label></div>
        <pre class="mono">{{ JSON.stringify(pasted.payload, null, 2) }}</pre>
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
.head { position: relative; }
.logout { position: absolute; top: 0; right: 0; margin: 0; padding: 8px 14px;
  font-size: 13px; }
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
.paste { width: 100%; resize: vertical; margin: 12px 0; color: var(--text);
  white-space: pre-wrap; word-break: break-all; }
code { background: #0b1220; border: 1px solid var(--line); border-radius: 4px;
  padding: 1px 5px; font-family: Consolas, Menlo, monospace; font-size: 12px; }
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
.cmp { width: 100%; border-collapse: collapse; margin: 8px 0 4px;
  font-size: 14px; }
.cmp th, .cmp td { text-align: left; padding: 9px 12px;
  border-bottom: 1px solid var(--line); }
.cmp th { color: var(--muted); font-size: 12px; text-transform: uppercase;
  letter-spacing: .04em; font-weight: 600; }
.cmp .fld { color: var(--muted); }
.cmp .match { color: #4ade80; }
.cmp .mismatch { color: var(--err); }
details { margin-top: 16px; }
summary { cursor: pointer; }
.muted { color: var(--muted); font-size: 13px; }
.foot { text-align: center; color: var(--muted); font-size: 12px;
  margin-top: 28px; }
</style>
