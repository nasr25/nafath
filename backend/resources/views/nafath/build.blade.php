<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Nafath OIDC — Build request</title>
  <style>
    :root { --bg:#0f172a; --card:#1e293b; --line:#334155; --text:#e2e8f0;
      --muted:#94a3b8; --primary:#2563eb; --accent:#16a34a; --err:#f87171; }
    * { box-sizing: border-box; }
    body { margin:0; background:var(--bg); color:var(--text);
      font-family: ui-sans-serif, system-ui, Segoe UI, Roboto, sans-serif; }
    .page { max-width:760px; margin:0 auto; padding:32px 20px 64px; }
    .head { position:relative; }
    h1 { font-size:24px; margin:0 0 4px; }
    .sub { color:var(--muted); margin:0 0 24px; }
    .card { background:var(--card); border:1px solid var(--line);
      border-radius:12px; padding:22px; margin-bottom:20px; }
    h2 { margin-top:0; font-size:18px; }
    label { font-size:13px; color:var(--muted); text-transform:uppercase;
      letter-spacing:.04em; display:block; margin:16px 0 6px; }
    .row { display:flex; align-items:center; justify-content:space-between; }
    pre.mono { background:#0b1220; border:1px solid var(--line); border-radius:8px;
      padding:12px; font-family:Consolas, Menlo, monospace; font-size:13px;
      overflow-x:auto; margin:0; white-space:pre-wrap; word-break:break-all; }
    .btn { border:none; border-radius:8px; padding:11px 18px; font-size:15px;
      font-weight:600; cursor:pointer; color:#fff; margin-top:8px;
      text-decoration:none; display:inline-block; }
    .btn.primary { background:var(--primary); }
    .btn.accent { background:var(--accent); margin-top:20px; }
    .btn.ghost { background:transparent; border:1px solid var(--line); color:var(--text); }
    /* Sits top-right of the header. Given its own colours rather than .ghost:
       a transparent border on the dark background made it read as plain text. */
    .logout { position:absolute; top:0; right:0; margin:0; padding:9px 16px;
      font-size:13px; font-weight:600; background:rgba(248,113,113,.14);
      border:1px solid var(--err); color:var(--err); }
    .logout:hover { background:var(--err); color:var(--bg); }
    .notice { background:rgba(22,163,74,.12); border:1px solid var(--accent);
      color:#4ade80; border-radius:8px; padding:13px 16px; margin:0 0 20px;
      font-size:14px; font-weight:600; }
    .err { color:var(--err); margin-top:14px; }
    .muted { color:var(--muted); font-size:13px; }
    .link { color:#60a5fa; }
  </style>
</head>
<body>
  <div class="page">
    <header class="head">
      <h1>Nafath OIDC — Test Console</h1>
      <p class="sub">Build &amp; inspect the signed OIDC request sent to IAM (نفاذ)</p>
      <a class="btn logout" href="/_IAM/logout">Logout (IAM SLO)</a>
    </header>

    {{-- Raised by NafathController::logout() once IAM has dispatched Single
         Logout back to us — i.e. the NAFATH session is gone, not just ours. --}}
    @if (request()->query('logged_out'))
      <p class="notice">✓ You have been signed out of NAFATH successfully.</p>
    @endif

    <section class="card">
      @if ($error)
        <p class="err">✗ Could not build the request: {{ $error }}</p>
        <p class="muted">Check the signing key at
          <code>storage/app/{{ config('nafath.private_key_path') }}</code>.</p>
        <a class="btn primary" href="/">Try again</a>
      @elseif ($auth)
        <div class="row">
          <label style="margin-top:0">Authorize URL</label>
          <a class="link" href="/">rebuild</a>
        </div>
        <pre class="mono">{{ $auth['url'] }}</pre>

        <label>JWT header</label>
        <pre class="mono">{{ json_encode($header, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) }}</pre>

        <label>JWT payload (request object)</label>
        <pre class="mono">{{ json_encode($auth['payload'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) }}</pre>

        <label>Signed request (JWT)</label>
        <pre class="mono">{{ $auth['request'] }}</pre>

        <a class="btn accent" href="{{ $auth['url'] }}">Redirect to Nafath →</a>
        <p class="muted">
          After you authenticate, IAM returns to
          <code>{{ config('nafath.redirect_uri') }}</code>; this backend decodes
          the token and hands the result to the frontend
          (<code>{{ config('nafath.frontend_url') }}</code>) to display.
        </p>
      @endif
    </section>

    <footer class="muted" style="text-align:center">Laravel API (site) · Vue result app · RS256 signed request</footer>
  </div>
</body>
</html>
