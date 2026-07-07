<?php

namespace App\Services;

use Firebase\JWT\JWT;
use Illuminate\Support\Str;

class NafathService
{
    /**
     * Build a signed OIDC "request object" (JWT) plus the full authorize URL
     * the frontend should redirect the user to.
     *
     * @return array{authorize_url:string, request:string, payload:array}
     */
    public function buildAuthorizeRequest(): array
    {
        $clientId = config('nafath.client_id');

        // "state" is used to link the request and the response; per the IAM
        // spec it carries the same value as "nonce".
        $nonce = Str::random(24);

        $payload = [
            'client_id'     => $clientId,
            'iss'           => $clientId,            // iss == client_id
            'response_type' => config('nafath.response_type'),
            'redirect_uri'  => config('nafath.redirect_uri'),
            'scope'         => config('nafath.scope'),
            'nonce'         => $nonce,
            'ui_locales'    => config('nafath.ui_locales'),
            'max_age'       => (string) now()->timestamp,   // time of issuance
            'state'         => $nonce,                        // state == nonce
        ];

        $privateKey = $this->privateKey();

        $headers = [];
        if ($kid = config('nafath.key_id')) {
            $headers['kid'] = $kid;
        }

        // Sign the request object with RS256, as mandated by IAM.
        $jwt = JWT::encode($payload, $privateKey, 'RS256', null, $headers);

        $authorizeUrl = config('nafath.authorize_url') . '?' . http_build_query([
            'client_id' => $clientId,
            'request'   => $jwt,
        ]);

        return [
            'authorize_url' => $authorizeUrl,
            'request'       => $jwt,
            'payload'       => $payload,
        ];
    }

    /**
     * Read the RS256 private key used to sign the request object.
     */
    protected function privateKey(): string
    {
        $path = config('nafath.private_key_path');

        if (! is_file($path)) {
            abort(500, "Nafath private key not found at: {$path}. " .
                'Generate a test key or set NAFATH_PRIVATE_KEY_PATH.');
        }

        return (string) file_get_contents($path);
    }
}
