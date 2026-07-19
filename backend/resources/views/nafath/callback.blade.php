<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Nafath callback</title>
  <style>
    :root { --bg:#0f172a; --card:#1e293b; --line:#334155; --text:#e2e8f0;
      --muted:#94a3b8; --ok:#16a34a; --err:#f87171; }
    * { box-sizing: border-box; }
    body { margin:0; background:var(--bg); color:var(--text);
      font-family: ui-sans-serif, system-ui, Segoe UI, Roboto, sans-serif; }
    .page { max-width:760px; margin:0 auto; padding:32px 20px 64px; }
    h1 { font-size:24px; margin:0 0 4px; }
    .sub { color:var(--muted); margin:0 0 24px; }
    .card { background:var(--card); border:1px solid var(--line);
      border-radius:12px; padding:22px; margin-bottom:20px; }
    h2 { margin-top:0; font-size:18px; }
    .ok { color:#4ade80; font-weight:600; }
    .err { color:var(--err); font-weight:600; }
    .muted { color:var(--muted); font-size:13px; }
    label { font-size:13px; color:var(--muted); text-transform:uppercase;
      letter-spacing:.04em; display:block; margin:16px 0 6px; }
    pre.mono { background:#0b1220; border:1px solid var(--line); border-radius:8px;
      padding:12px; font-family:Consolas, Menlo, monospace; font-size:13px;
      overflow-x:auto; margin:0; white-space:pre-wrap; word-break:break-all; }
    table.cmp { width:100%; border-collapse:collapse; margin:8px 0 4px; font-size:14px; }
    .cmp th, .cmp td { text-align:left; padding:9px 12px; border-bottom:1px solid var(--line); }
    .cmp th { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
    .cmp .fld { color:var(--muted); }
    .match { color:#4ade80; } .mismatch { color:var(--err); }
    a.btn { display:inline-block; margin-top:8px; padding:10px 16px; border-radius:8px;
      border:1px solid var(--line); color:var(--text); text-decoration:none; }
    details { margin-top:12px; } summary { cursor:pointer; color:var(--muted); }
  </style>
</head>
<body>
  <div class="page">
    <h1>Nafath callback</h1>
    <p class="sub">Result IAM (نفاذ) returned to <code>/_IAM/login</code></p>

    @if ($errorParam)
      <div class="card"><p class="err">✗ IAM returned an error: {{ $errorParam }}</p></div>
    @endif

    {{-- Server-side result (form_post / query). Hidden when nothing arrived on
         the server, so the JS fragment fallback below can take over. --}}
    <div id="server" class="card" @if(!$idToken) style="display:none" @endif>
      <h2>Verification</h2>
      @if ($verified)
        <p class="ok">✓ Signature, issuer, audience, and one-time state/nonce all valid.</p>
      @elseif ($idToken)
        <p class="err">✗ Not fully verified: {{ $verifyError ?? 'unknown reason' }}</p>
        <p class="muted">The decoded claims below are still shown for inspection
          (they are NOT verified — do not trust them for auth).</p>
      @endif

      @if ($verified)
        <p class="muted">National Id: {{ $nationalId ?? '—' }} ·
          {{ $matched ? 'matched a local user' : 'no matching local user' }}</p>
      @endif

      @if ($comparison)
        <label>Database (old) vs NAFATH (corrected)</label>
        <table class="cmp">
          <thead><tr><th>Field</th><th>Database</th><th>NAFATH</th></tr></thead>
          <tbody>
            @foreach ($comparison as $row)
              <tr>
                <td class="fld">{{ $row['label'] }}</td>
                <td class="{{ $row['match'] ? 'match' : 'mismatch' }}">{{ $row['database'] ?? '—' }}</td>
                <td class="{{ $row['match'] ? 'match' : 'mismatch' }}">{{ $row['nafath'] ?? '—' }}</td>
              </tr>
            @endforeach
          </tbody>
        </table>
      @endif

      @if ($decoded)
        <label>Header</label>
        <pre class="mono">{{ json_encode($decoded['header'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) }}</pre>
        <label>Payload (claims)</label>
        <pre class="mono">{{ json_encode($decoded['payload'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) }}</pre>
      @endif

      @if ($idToken)
        <label>Raw id_token</label>
        <pre class="mono">{{ $idToken }}</pre>
      @endif
    </div>

    {{-- Fragment fallback: if IAM returned via #id_token=... (GET), the token
         never reaches the server. Decode it here in the browser instead. --}}
    <div id="fragment" class="card" style="display:none">
      <h2>Decoded from URL fragment</h2>
      <p class="muted">Token returned in the URL fragment — decoded in your
        browser (signature NOT verified).</p>
      <label>Header</label><pre class="mono" id="fHeader"></pre>
      <label>Payload (claims)</label><pre class="mono" id="fPayload"></pre>
      <label>Raw id_token</label><pre class="mono" id="fRaw"></pre>
    </div>

    <a class="btn" href="/">← Back</a>
  </div>

  <script>
    (function () {
      var hasServer = @json((bool) $idToken);
      if (hasServer) return; // server already rendered the result

      function b64urlDecode(seg) {
        var b64 = seg.replace(/-/g, '+').replace(/_/g, '/');
        var bin = atob(b64);
        var bytes = Uint8Array.from(bin, function (c) { return c.charCodeAt(0); });
        return new TextDecoder('utf-8').decode(bytes);
      }
      var hash = new URLSearchParams(location.hash.slice(1));
      var query = new URLSearchParams(location.search);
      var token = hash.get('id_token') || query.get('id_token');
      if (!token) return;

      try {
        var parts = token.split('.');
        document.getElementById('fHeader').textContent =
          JSON.stringify(JSON.parse(b64urlDecode(parts[0])), null, 2);
        document.getElementById('fPayload').textContent =
          JSON.stringify(JSON.parse(b64urlDecode(parts[1])), null, 2);
        document.getElementById('fRaw').textContent = token;
        document.getElementById('fragment').style.display = '';
      } catch (e) {
        document.getElementById('fPayload').textContent = 'Could not decode: ' + e.message;
        document.getElementById('fragment').style.display = '';
      }
    })();
  </script>
</body>
</html>
