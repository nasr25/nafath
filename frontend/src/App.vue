<script setup>
import { ref, onMounted } from 'vue'

// Base URL of the Laravel backend. Empty = same origin (Laravel is the site
// root; this SPA is the /app application under it). In dev the Vite proxy
// forwards /api, /nafath, /_IAM to the backend.
const API_BASE = import.meta.env.VITE_API_BASE_URL || ''

// UTF-8-safe base64url decode (id_token claims include Arabic names).
function b64urlDecode(segment) {
  const b64 = segment.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(b64)
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0))
  return new TextDecoder('utf-8').decode(bytes)
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    /* ignore */
  }
}

// --- Callback result (fetched by one-time rid after the backend callback) ---
const callback = ref(null)

async function loadResult(rid) {
  callback.value = { loading: true }
  try {
    const res = await fetch(`${API_BASE}/nafath/result?rid=${encodeURIComponent(rid)}`)
    const data = await res.json()
    if (!res.ok || !data.ok) {
      callback.value = { ok: false, message: data.message || `HTTP ${res.status}` }
      return
    }
    const r = data.result
    callback.value = {
      ok: !!r.verified,
      error: r.errorParam ?? null,
      message: r.verified
        ? 'NAFATH verification successful'
        : r.verifyError || 'Not verified — decoded for inspection only',
      matched: !!r.matched,
      nationalId: r.nationalId ?? null,
      comparison: r.comparison ?? [],
      claims: r.decoded?.payload ?? null,
      header: r.decoded?.header ?? null,
      idToken: r.idToken ?? null,
    }
  } catch (e) {
    callback.value = { ok: false, message: `Failed to reach backend: ${e.message}` }
  }
}

// --- Paste & decode box (decode any id_token locally, no verification) ---
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

// --- Optional diagnostic dump (append ?debug to the URL) ---
const debug = ref(null)

function collectDebug() {
  const loc = window.location
  const toObj = (params) => {
    const o = {}
    for (const [k, v] of params) o[k] = v
    return o
  }
  const query = new URLSearchParams(loc.search)
  return {
    time: new Date().toISOString(),
    href: loc.href,
    pathname: loc.pathname,
    search: loc.search || '(none)',
    query: toObj(query),
    referrer: document.referrer || '(none)',
    userAgent: navigator.userAgent,
  }
}

onMounted(() => {
  const query = new URLSearchParams(window.location.search)
  const rid = query.get('rid')

  if (query.has('debug')) {
    debug.value = collectDebug()
  }
  // The backend callback redirects here with a one-time ?rid= to display.
  if (rid) {
    loadResult(rid)
  }
})
</script>

<template>
  <div class="page">
    <header class="head">
      <h1>Nafath OIDC — Result</h1>
      <p class="sub">Displays the decoded &amp; verified NAFATH callback</p>
      <a class="btn ghost home" href="/">← Home (build request)</a>
    </header>

    <!-- Optional debug dump (?debug) -->
    <section v-if="debug" class="card debug">
      <div class="row" style="margin-top:0">
        <h2 style="margin:0">🐞 Debug</h2>
        <button class="link" @click="copy(JSON.stringify(debug, null, 2))">copy all</button>
      </div>
      <pre class="mono">{{ JSON.stringify(debug, null, 2) }}</pre>
    </section>

    <!-- Callback result -->
    <section v-if="callback" class="card">
      <h2>Callback result</h2>

      <p v-if="callback.loading" class="muted">Loading result…</p>

      <template v-else>
        <p v-if="callback.error" class="err">IAM returned an error: {{ callback.error }}</p>
        <p v-else-if="callback.ok" class="ok">✓ {{ callback.message }}</p>
        <p v-else class="err">✗ {{ callback.message }}</p>

        <!-- DB (old) vs NAFATH (corrected) comparison -->
        <template v-if="callback.comparison && callback.comparison.length && callback.matched">
          <div class="row">
            <label>Database vs NAFATH</label>
            <span class="muted">National Id: {{ callback.nationalId }}</span>
          </div>
          <table class="cmp">
            <thead>
              <tr><th>Field</th><th>Database (old)</th><th>NAFATH (corrected)</th></tr>
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
          Verified, but no local user matched National Id {{ callback.nationalId }}.
        </p>

        <template v-if="callback.claims">
          <label>Claims</label>
          <pre class="mono">{{ JSON.stringify(callback.claims, null, 2) }}</pre>
        </template>

        <template v-if="callback.idToken">
          <div class="row">
            <label>Raw id_token</label>
            <button class="link" @click="copy(callback.idToken)">copy</button>
          </div>
          <pre class="mono brk">{{ callback.idToken }}</pre>
        </template>
      </template>
    </section>

    <!-- Paste & decode any id_token (no verification) -->
    <section class="card">
      <h2>Decode an id_token</h2>
      <p class="muted">
        Paste an <code>id_token</code> to inspect its claims. Decoded locally —
        the signature is <strong>not</strong> verified.
      </p>

      <textarea
        v-model="pasteInput"
        class="mono paste"
        rows="5"
        placeholder="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ..."
        spellcheck="false"
      ></textarea>

      <div class="row" style="justify-content:flex-start; gap:10px">
        <button class="btn primary" @click="decodePasted">Decode</button>
        <button class="btn ghost" @click="clearPasted">Clear</button>
      </div>

      <p v-if="pasteError" class="err">{{ pasteError }}</p>

      <template v-if="pasted">
        <label>Header</label>
        <pre class="mono">{{ JSON.stringify(pasted.header, null, 2) }}</pre>
        <label>Payload (claims)</label>
        <pre class="mono">{{ JSON.stringify(pasted.payload, null, 2) }}</pre>
      </template>
    </section>

    <footer class="foot">Laravel API (site) · Vue result app · RS256 signed request</footer>
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
.head { position: relative; }
.head h1 { margin: 0; font-size: 26px; }
.sub { color: var(--muted); margin: 6px 0 24px; }
.home { position: absolute; top: 0; right: 0; margin: 0; padding: 8px 14px; font-size: 13px; }
.card { background: var(--card); border: 1px solid var(--line);
  border-radius: 12px; padding: 22px; margin-bottom: 20px; }
.card.debug { border-color: #a16207; }
h2 { margin-top: 0; }
label { font-size: 13px; color: var(--muted); text-transform: uppercase;
  letter-spacing: .04em; display: block; margin: 16px 0 6px; }
.row { display: flex; align-items: center; justify-content: space-between; margin-top: 8px; }
.mono { background: #0b1220; border: 1px solid var(--line); border-radius: 8px;
  padding: 12px; font-family: Consolas, Menlo, monospace; font-size: 13px;
  overflow-x: auto; margin: 0; white-space: pre-wrap; word-break: break-all; }
.brk { word-break: break-all; }
.paste { width: 100%; resize: vertical; margin: 12px 0; color: var(--text); }
.btn { border: none; border-radius: 8px; padding: 11px 18px; font-size: 15px;
  font-weight: 600; cursor: pointer; color: #fff; margin-top: 8px;
  text-decoration: none; display: inline-block; }
.btn.primary { background: var(--primary); }
.btn.ghost { background: transparent; border: 1px solid var(--line); color: var(--text); }
.btn:disabled { opacity: .6; cursor: default; }
.link { background: none; border: none; color: #60a5fa; cursor: pointer; font-size: 13px; }
.err { color: var(--err); margin-top: 14px; }
.ok { color: var(--accent); margin-top: 14px; font-weight: 600; }
.cmp { width: 100%; border-collapse: collapse; margin: 8px 0 4px; font-size: 14px; }
.cmp th, .cmp td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--line); }
.cmp th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
.cmp .fld { color: var(--muted); white-space: nowrap; }
.cmp .match { color: #4ade80; }
.cmp .mismatch { color: var(--err); }
code { background: #0b1220; border: 1px solid var(--line); border-radius: 4px;
  padding: 1px 5px; font-family: Consolas, Menlo, monospace; font-size: 12px; }
.muted { color: var(--muted); font-size: 13px; }
.foot { text-align: center; color: var(--muted); font-size: 12px; margin-top: 28px; }
</style>
