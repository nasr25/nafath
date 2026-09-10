<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Nafath (IAM) OIDC configuration
    |--------------------------------------------------------------------------
    | These values map directly to the OIDC request the SP must build and sign
    | before redirecting the user to the IAM authorize endpoint.
    */

    // IAM authorize endpoint. In production this is provided by the IAM team.
    'authorize_url' => env('NAFATH_AUTHORIZE_URL', 'https://www.iam.sa/authservice/authorize'),

    // Service provider identifier (recommended to be a URL). Used for both
    // the query-string client_id and the "client_id"/"iss" JWT claims.
    'client_id' => env('NAFATH_CLIENT_ID', 'https://www.sp.com'),

    // Where IAM returns the user claims (must be registered with IAM).
    'redirect_uri' => env('NAFATH_REDIRECT_URI', 'http://localhost:5173/callback'),

    // IAM Single Logout (SLO) endpoint. Direct/simplified logout (applicable to
    // OIDC): redirect the browser here with ?slo=true to end the IAM session.
    'logout_url' => env('NAFATH_LOGOUT_URL', 'https://www.iam.gov.sa/samlsso'),

    // How the user gets back to us after logging out of IAM.
    //
    //   "dispatch" — the guide's flow (§2.2.1): redirect the browser to IAM and
    //   wait for IAM to call our logout URL back with ?slo=false. This only
    //   happens once the Service Provider Logout URL is registered with IAM
    //   (§3.3.3); until then IAM ends the session and leaves the user on its own
    //   page, and our post-logout redirect never runs.
    //
    //   "direct" — do the redirect ourselves. The IAM logout URL is requested by
    //   the browser in the background and we send the user straight to
    //   post_logout_redirect, so they never leave our system.
    'logout_return' => env('NAFATH_LOGOUT_RETURN', 'dispatch'),

    // Where to land the user once logout finishes (a public page on the SP).
    'post_logout_redirect' => env('NAFATH_POST_LOGOUT_REDIRECT', '/'),

    // Frontend (Vue) application path, mounted under this Laravel site. After a
    // callback the backend caches the decoded result and redirects here with a
    // one-time ?rid= so the SPA can fetch and display it.
    'frontend_url' => env('NAFATH_FRONTEND_URL', '/app'),

    // Language shown to the user by IAM: "ar" or "en".
    'ui_locales' => env('NAFATH_UI_LOCALES', 'ar'),

    // response_type must be "id_token" so the response contains claims.
    'response_type' => 'id_token',

    'scope' => 'openid',

    // RS256 signing key provided by the IAM integration team.
    // For local testing a self-generated keypair is used (storage/keys).

    // Optional key id to place in the JWT header.
    'key_id' => env('NAFATH_KEY_ID'),

    // iDart UserInfo service — called with the Nafath access token (from the
    // id_token's `accessToken` claim) to obtain the user's profile.
    //   Test: https://api.id.sa/identityServices/userInfo
    //   Prod: https://api.id.gov.sa/identityServices/userInfo
    'userinfo_url' => env('NAFATH_USERINFO_URL', 'https://api.id.sa/identityServices/userInfo'),

    // TLS trust for outbound calls (UserInfo / JWKS). Point NAFATH_CA_BUNDLE at
    // a PEM containing the missing root CA (e.g. the Saudi gov root or your TLS-
    // inspection firewall root) — this is the correct fix. NAFATH_VERIFY_SSL=false
    // disables verification entirely (INSECURE — local testing only).
    'ca_bundle'  => env('NAFATH_CA_BUNDLE'),
    'verify_ssl' => (bool) env('NAFATH_VERIFY_SSL', true),

    'issuer'        => env('NAFATH_ISSUER'),
    'alg'           => env('NAFATH_ALG', 'RS256'),
    'ui_locale'     => env('NAFATH_UI_LOCALE', 'ar'),

    // Keys live on the "local" disk (storage/app). Move to a secret store in prod.
    'private_key_path' => env('NAFATH_PRIVATE_KEY_PATH', 'nafath/sp_private_key.pem'),
    'iam_cert_path'    => env('NAFATH_IAM_CERT_PATH', 'nafath/iam_public.cer'),

    // Preferred over the static cert: IAM's JWKS endpoint. When set, the token
    // is verified against the key whose `kid` matches the token header, which
    // handles key rotation and multiple signing keys. Leave empty to use the
    // static cert above.
    'jwks_url' => env('NAFATH_JWKS_URL'),
    'jwks_ttl' => (int) env('NAFATH_JWKS_TTL', 3600), // seconds to cache the JWKS

    // Whether to verify the id_token signature. The real authorization is the
    // access token (validated by iDart UserInfo), so this can be disabled while
    // the IAM signing cert/JWKS is being finalised. Keep true when you can.
    'verify_idtoken' => (bool) env('NAFATH_VERIFY_IDTOKEN', true),

    // Clock-skew tolerance (seconds) when validating the Id_token timestamps.
    'leeway' => 60,

    // How long (minutes) an issued state/nonce stays valid for the callback.
    'state_ttl' => (int) env('NAFATH_STATE_TTL', 10),
];
