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

    // Language shown to the user by IAM: "ar" or "en".
    'ui_locales' => env('NAFATH_UI_LOCALES', 'ar'),

    // response_type must be "id_token" so the response contains claims.
    'response_type' => 'id_token',

    'scope' => 'openid',

    // RS256 signing key provided by the IAM integration team.
    // For local testing a self-generated keypair is used (storage/keys).

    // Optional key id to place in the JWT header.
    'key_id' => env('NAFATH_KEY_ID'),

    'issuer'        => env('NAFATH_ISSUER'),
    'alg'           => env('NAFATH_ALG', 'RS256'),
    'ui_locale'     => env('NAFATH_UI_LOCALE', 'ar'),

    // Keys live on the "local" disk (storage/app). Move to a secret store in prod.
    'private_key_path' => env('NAFATH_PRIVATE_KEY_PATH', 'nafath/sp_private_key.pem'),
    'iam_cert_path'    => env('NAFATH_IAM_CERT_PATH', 'nafath/iam_public.cer'),

    // Clock-skew tolerance (seconds) when validating the Id_token timestamps.
    'leeway' => 60,
];
