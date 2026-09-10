{{--
  Interstitial for NAFATH_LOGOUT_RETURN=direct.

  The local session is already gone by the time this renders. All that is left is
  to end the IAM session, which only the browser can do — IAM identifies it from
  its own cookie, so a server-side call would terminate nothing. The frame below
  performs that request, then we send the user to the public page ourselves
  rather than waiting for IAM to dispatch ?slo=false back to us.
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
    iframe { position:absolute; width:0; height:0; border:0; visibility:hidden; }
  </style>
</head>
<body>
  <div class="box">
    <div class="spin"></div>
    <h1>Signing you out of NAFATH…</h1>
    <p>One moment — you will be redirected automatically.</p>
    <noscript>
      <p style="margin-top:14px">
        JavaScript is disabled.
        <a href="{{ $iamUrl }}">Continue to NAFATH to finish signing out</a>.
      </p>
    </noscript>
  </div>

  {{-- Ends the IAM session. Carries the user's IAM cookie; a backend HTTP call would not. --}}
  <iframe src="{{ $iamUrl }}" title="NAFATH logout" aria-hidden="true" tabindex="-1"></iframe>

  <script>
    (function () {
      var target = @json($target);
      var done = false;

      function finish() {
        if (done) return;
        done = true;
        window.location.replace(target);
      }

      // Whichever comes first: the frame reporting back, or a hard cap so a
      // blocked frame (X-Frame-Options) can never strand the user here.
      document.querySelector('iframe').addEventListener('load', function () {
        setTimeout(finish, 600);
      });
      setTimeout(finish, 4000);
    })();
  </script>
</body>
</html>
