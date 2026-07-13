<?php

namespace App\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use RuntimeException;

class NafathService
{
    /**
     * Build the authorize URL + the request-state to remember.
     *
     * @return array{url:string, state:string, nonce:string}
     */
    public function buildAuthorizationUrl(): array
    {
        $cfg   = config('nafath');
        $nonce = Str::random(32);
        $state = $nonce; // guide: "state": same as nonce — links request & response.

        $payload = [
            'client_id'     => $cfg['client_id'],
            'iss'           => $cfg['client_id'],   // guide: iss == client_id
            'response_type' => 'id_token',          // so the response carries the claims
            'redirect_uri'  => $cfg['redirect_uri'],
            'scope'         => 'openid',
            'nonce'         => $nonce,
            'ui_locales'    => $cfg['ui_locale'],
            'max_age'       => time(),
            'state'         => $state,
        ];

        Log::info($payload);
        // Sign the request JWT (RS256) with OUR private key — this is the step
        // that jwt.io got wrong: it must be the IAM-registered certificate's key.
        $request = JWT::encode($payload, $this->privateKey(), $cfg['alg']);

        Log::info($request);
        $url = $cfg['authorize_url'] . '?' . http_build_query([
            'client_id' => $cfg['client_id'],
            'request'   => $request,
        ]);
        Log::info($url);

        return ['url' => $url, 'state' => $state, 'nonce' => $nonce];
    }

    /**
     * Verify the Id_token returned by IAM and return its claims.
     *
     * @throws RuntimeException on any validation failure.
     * @return array<string,mixed>
     */
    public function verifyIdToken(string $idToken, ?string $expectedState): array
    {
        $cfg = config('nafath');
        JWT::$leeway = (int) $cfg['leeway'];

        // 1) Signature — verified against the IAM PUBLIC certificate.
        try {
            $claims = (array) JWT::decode($idToken, new Key($this->iamCert(), $cfg['alg']));
        } catch (\Throwable $e) {
            throw new RuntimeException('Id_token signature/decoding failed: ' . $e->getMessage());
        }

        // 2) Issuer must be IAM.
        if (!empty($cfg['issuer']) && ($claims['iss'] ?? null) !== $cfg['issuer']) {
            throw new RuntimeException('Invalid issuer.');
        }

        // 3) Audience must be our client_id (when present).
        if (isset($claims['aud']) && !in_array($cfg['client_id'], (array) $claims['aud'], true)) {
            throw new RuntimeException('Invalid audience.');
        }

        // 4) Single-use: the state/nonce we sent must match what came back.
        if ($expectedState !== null) {
            $returned = $claims['state'] ?? $claims['nonce'] ?? null;
            if (!hash_equals($expectedState, (string) $returned)) {
                throw new RuntimeException('State/nonce mismatch (possible replay).');
            }
        }

        // exp/iat/nbf are enforced by JWT::decode above (with leeway).
        return $claims;
    }

    private function privateKey(): string
    {
        return $this->readKey($this->config('private_key_path'));
    }

    private function iamCert(): string
    {
        return $this->readKey($this->config('iam_cert_path'));
    }

    private function config(string $key): string
    {
        return (string) config("nafath.$key");
    }

    private function readKey(string $relativePath): string
    {
        if (!Storage::disk('local')->exists($relativePath)) {
            throw new RuntimeException("NAFATH key not found: storage/app/{$relativePath}");
        }
        return Storage::disk('local')->get($relativePath);
    }
}
