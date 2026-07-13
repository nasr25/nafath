<?php

namespace App\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use RuntimeException;

class NafathService
{
    /**
     * Build the authorize URL + the request-state to remember.
     *
     * @return array{url:string, request:string, payload:array<string,mixed>, state:string, nonce:string}
     */
    public function buildAuthorizationUrl(): array
    {
        $cfg   = config('nafath');
        $nonce = Str::random(32);
        $state = $nonce; // guide: "state": same as nonce — links request & response.

        Log::channel('nafath')->info('login: building authorize request', [
            'client_id'    => $cfg['client_id'],
            'redirect_uri' => $cfg['redirect_uri'],
            'alg'          => $cfg['alg'],
            'state'        => $this->mask($state),
        ]);

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

        // Sign the request JWT (RS256) with OUR private key — must be the
        // IAM-registered certificate's key.
        try {
            $request = JWT::encode($payload, $this->privateKey(), $cfg['alg']);
        } catch (\Throwable $e) {
            Log::channel('nafath')->error('login: signing the request JWT failed', [
                'error' => $e->getMessage(),
            ]);
            throw $e;
        }
        Log::channel('nafath')->info('login: request JWT signed');

        // Remember the state → nonce binding so the callback can validate the
        // response (anti-replay). Keyed by `state`, which IAM echoes back, so it
        // survives the cross-site POST without needing a session cookie.
        Cache::put(
            $this->stateCacheKey($state),
            $nonce,
            now()->addMinutes((int) $cfg['state_ttl'])
        );
        Log::channel('nafath')->info('login: state cached', [
            'state'       => $this->mask($state),
            'ttl_minutes' => (int) $cfg['state_ttl'],
        ]);

        $url = $cfg['authorize_url'] . '?' . http_build_query([
            'client_id' => $cfg['client_id'],
            'request'   => $request,
        ]);
        Log::channel('nafath')->info('login: authorize URL built');

        return [
            'url'     => $url,
            'request' => $request,
            'payload' => $payload,
            'state'   => $state,
            'nonce'   => $nonce,
        ];
    }

    /**
     * Verify the Id_token returned by IAM and return its claims.
     *
     * @param  string       $idToken        the Id_token from the callback
     * @param  string|null  $returnedState  the `State` field IAM POSTs back
     * @throws RuntimeException on any validation failure.
     * @return array<string,mixed>
     */
    public function verifyIdToken(string $idToken, ?string $returnedState): array
    {
        $cfg = config('nafath');
        JWT::$leeway = (int) $cfg['leeway'];
        Log::channel('nafath')->info('callback: verifying Id_token', [
            'returned_state' => $this->mask($returnedState),
        ]);

        // 1) Signature — verified against the IAM PUBLIC certificate.
        try {
            $claims = (array) JWT::decode($idToken, new Key($this->iamCert(), $cfg['alg']));
        } catch (\Throwable $e) {
            return $this->fail('signature/decoding failed: ' . $e->getMessage());
        }
        Log::channel('nafath')->info('callback: step 1/4 signature OK', [
            'iss' => $claims['iss'] ?? null,
        ]);

        // 2) Issuer must be IAM.
        if (!empty($cfg['issuer']) && ($claims['iss'] ?? null) !== $cfg['issuer']) {
            return $this->fail('invalid issuer', [
                'expected' => $cfg['issuer'],
                'got'      => $claims['iss'] ?? null,
            ]);
        }
        Log::channel('nafath')->info('callback: step 2/4 issuer OK');

        // 3) Audience must be our client_id (when present).
        if (isset($claims['aud']) && !in_array($cfg['client_id'], (array) $claims['aud'], true)) {
            return $this->fail('invalid audience', [
                'expected' => $cfg['client_id'],
                'got'      => $claims['aud'],
            ]);
        }
        Log::channel('nafath')->info('callback: step 3/4 audience OK');

        // 4) Anti-replay: the state must be one we issued and haven't consumed.
        // Prefer the POSTed State; fall back to a state claim inside the token.
        $state = $returnedState ?? ($claims['state'] ?? null);
        if (!$state) {
            return $this->fail('missing state');
        }

        // pull() is atomic get-and-forget → single use.
        $expectedNonce = Cache::pull($this->stateCacheKey($state));
        if ($expectedNonce === null) {
            return $this->fail('unknown, expired, or already-used state (possible replay)', [
                'state' => $this->mask($state),
            ]);
        }

        // The nonce bound to that state must match the one inside the token.
        if (!hash_equals($expectedNonce, (string) ($claims['nonce'] ?? ''))) {
            return $this->fail('nonce mismatch (possible replay)');
        }

        // exp/iat/nbf are enforced by JWT::decode above (with leeway).
        Log::channel('nafath')->info('callback: step 4/4 state & nonce OK — verification succeeded');
        return $claims;
    }

    /**
     * Log a verification failure and throw. Return type is a hint only — this
     * never returns.
     *
     * @return never
     */
    private function fail(string $reason, array $context = []): array
    {
        Log::channel('nafath')->warning('callback: verification failed — ' . $reason, $context);
        throw new RuntimeException('Id_token ' . $reason);
    }

    /** Mask a one-time secret (state/nonce) so logs can correlate without leaking it. */
    private function mask(?string $value): ?string
    {
        if ($value === null || $value === '') {
            return $value;
        }
        return substr($value, 0, 6) . '…(' . strlen($value) . ')';
    }

    private function stateCacheKey(string $state): string
    {
        return 'nafath_state:' . $state;
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
