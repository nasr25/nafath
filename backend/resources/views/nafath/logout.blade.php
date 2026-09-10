{{--
  Shown when NAFATH_LOGOUT_RETURN=direct.

  The local session is already destroyed by the time this renders. What is left
  is ending the IAM session, and only the browser can do that — IAM identifies
  the session by its own cookie, so a server-side call from Laravel would carry
  nothing and terminate nothing.

  Two independent channels request the IAM logout URL, because either one can be
  blocked on its own:
    - <img>    survives X-Frame-Options, but cannot run IAM's page scripts.
    - <iframe> can run them, but IAM may refuse to be framed.
  Whichever gets through, we then redirect ourselves rather than waiting for IAM
  to dispatch ?slo=false back to us.
--}}
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Signing out…</title>
  <style>
    :root { --bg:#0f172a; --line:#334155; --text:#e2e8f0; --muted:#94a3b8; --accent:#16a34a; }
    body { margin:0; background:var(--bg); color:var(--text); display:flex;
      align-items:center; justify-content:center; min-height:100vh;
      font-family: ui-sans-serif, system-ui, Segoe UI, Roboto, sans-serif; }
    .box { text-align:center; padding:0 20px; }
    h1 { font-size:19px; font-weight:600; margin:0 0 10px; }
    p { color:var(--muted); font-size:14px; margin:0; }
    a { color:#60a5fa; }
    .spin { width:34px; height:34px; margin:0 auto 22px; border-radius:50%;
      border:3px solid var(--line); border-top-color:var(--accent);
      animation:spin .8s linear infinite; }
    @keyframes spin { to { transform:rotate(360deg); } }
    @media (prefers-reduced-motion: reduce) { .spin { animation:none; } }
    .hidden { position:absolute; width:0; height:0; border:0; visibility:hidden; }
  </style>
</head>
<body>
  <div class="box">
    <div class="spin"></div>
    <h1>Signing you out of NAFATH…</h1>
    <p>One moment — you will be returned automatically.</p>
    <noscript>
      <p style="margin-top:14px"><a href="{{ $target }}">Continue</a></p>
    </noscript>
  </div>

  <img class="hidden" src="{{ $iamUrl }}" alt="" aria-hidden="true">
  <iframe class="hidden" src="{{ $iamUrl }}" title="NAFATH logout" aria-hidden="true" tabindex="-1"></iframe>

  <script>
    (function () {
      var target = @json($target);
      var settled = false;

      function go() {
        if (settled) return;
        settled = true;
        window.location.replace(target);
      }

      // Give the logout request a moment to reach IAM, then leave regardless —
      // a blocked frame or a slow IAM must never strand the user on this page.
      var img = document.querySelector('img.hidden');
      img.addEventListener('load', function () { setTimeout(go, 400); });
      img.addEventListener('error', function () { setTimeout(go, 400); });
      setTimeout(go, 2500);
    })();
  </script>
</body>
</html>
