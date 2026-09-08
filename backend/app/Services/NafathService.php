<?php

namespace App\Services;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
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

        // Optional. `prompt=login` makes IAM re-authenticate the user even when
        // it still holds an SSO session, so a login right after a logout proves
        // whether the IAM session was really ended.
        if (!empty($cfg['prompt'])) {
            $payload['prompt'] = $cfg['prompt'];
        }

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
     * Build the URL that ends the IAM (Nafath) session.
     *
     * IAM can only terminate a session it can identify. In OIDC mode that means
     * echoing the id_token we were issued back as `id_token_hint` — redirecting
     * to the logout endpoint with nothing but `?slo=true` ends OUR session while
     * IAM keeps its SSO session, which is why the next login then sails straight
     * through without re-authenticating.
     *
     * @param  string|null  $idToken  the raw id_token from the login callback
     */
    public function buildLogoutUrl(?string $idToken = null): string
    {
        $cfg  = config('nafath');
        $mode = $cfg['logout_mode'] ?? 'oidc';

        if ($mode === 'slo') {
            $params = ['slo' => 'true'];
        } else {
            if ($idToken === null || $idToken === '') {
                Log::channel('nafath')->warning(
                    'logout: no id_token_hint available — IAM will most likely keep its SSO session',
                );
            }
            $params = array_filter([
                'id_token_hint'            => $idToken,
                'post_logout_redirect_uri' => $this->postLogoutRedirectUri(),
            ]);
        }

        // The configured URL may already carry query parameters (IAM sometimes
        // registers the SP identifier on it), so pick the separator rather than
        // blindly appending "?".
        $base = rtrim((string) $cfg['logout_url'], '?&');
        $sep  = str_contains($base, '?') ? '&' : '?';

        Log::channel('nafath')->info('logout: building IAM logout URL', [
            'mode'          => $mode,
            'endpoint'      => $base,
            'has_id_token'  => (bool) $idToken,
        ]);

        return $base . $sep . http_build_query($params);
    }

    /**
     * `post_logout_redirect_uri` has to be an absolute URL registered with IAM;
     * the config allows a site-relative path for convenience.
     */
    private function postLogoutRedirectUri(): string
    {
        $target = (string) config('nafath.post_logout_redirect');

        return Str::startsWith($target, ['http://', 'https://']) ? $target : url($target);
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

        // 1) Signature — verified against IAM's JWKS (by `kid`) when configured,
        //    otherwise the static IAM public certificate.
        $header = $this->tokenHeader($idToken);
        Log::channel('nafath')->info('callback: verifying signature', [
            'alg'        => $header['alg'] ?? null,
            'kid'        => $header['kid'] ?? null,
            'key_source' => !empty($cfg['jwks_url']) ? 'jwks' : 'cert',
        ]);
        try {
            $claims = (array) JWT::decode($idToken, $this->signingKeys($cfg));
        } catch (\Throwable $e) {
            return $this->fail('signature/decoding failed: ' . $e->getMessage(), [
                'token_kid'  => $header['kid'] ?? null,
                'token_alg'  => $header['alg'] ?? null,
                'key_source' => !empty($cfg['jwks_url']) ? 'jwks' : 'cert',
            ]);
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
     * Decode a JWT's header + payload WITHOUT verifying the signature.
     * For inspection only — never trust these claims for authentication.
     *
     * @return array{header:array<string,mixed>, payload:array<string,mixed>}
     */
    public function decodeWithoutVerification(string $idToken): array
    {
        $parts = explode('.', $idToken);
        if (count($parts) < 2) {
            throw new RuntimeException('Not a JWT (expected header.payload.signature).');
        }
        return [
            'header'  => $this->b64urlJson($parts[0]),
            'payload' => $this->b64urlJson($parts[1]),
        ];
    }

    /** Base64url-decode a JWT segment into an associative array. */
    private function b64urlJson(string $segment): array
    {
        $json = base64_decode(strtr($segment, '-_', '+/'), true);
        if ($json === false) {
            throw new RuntimeException('Invalid base64url in token segment.');
        }
        $data = json_decode($json, true);
        if (!is_array($data)) {
            throw new RuntimeException('Token segment is not valid JSON.');
        }
        return $data;
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

    /**
     * Call the iDart UserInfo service with the Nafath access token (from the
     * id_token's `accessToken` claim) and return the decoded `user_info` profile.
     * The response is itself a signed JWT (application/jwt); we decode its
     * payload for the profile. (Verifying that JWT's signature is a later step.)
     *
     * @return array<string,mixed>
     * @throws RuntimeException on HTTP or decoding failure.
     */
    public function fetchUserInfo(string $accessToken): array
    {
        $url = $this->config('userinfo_url');
        Log::channel('nafath')->info('userinfo: requesting', ['url' => $url]);

        $res = Http::withToken($accessToken) // Authorization: Bearer <token>
            ->withHeaders(['Accept' => 'application/jwt'])
            ->withOptions(['verify' => $this->httpVerify()])
            ->timeout(15)
            ->get($url);

        if (!$res->successful()) {
            $reason = $res->header('WWW-Authenticate') ?: $res->body();
            Log::channel('nafath')->warning('userinfo: request failed', [
                'status'   => $res->status(),
                'trace_id' => $res->header('X-TraceId'),
                'reason'   => $reason,
            ]);
            throw new RuntimeException('UserInfo request failed: HTTP ' . $res->status() . ' ' . $reason);
        }

        $jwt = trim($res->body());
        $payload = $this->decodeWithoutVerification($jwt)['payload'];
        Log::channel('nafath')->info('userinfo: received', [
            'trace_id' => $res->header('X-TraceId'),
            'has_user_info' => isset($payload['user_info']),
        ]);

        return $payload['user_info'] ?? $payload;
    }

    /**
     * Guzzle `verify` value for outbound calls: a CA-bundle path when configured
     * (the correct fix for an untrusted root), otherwise the verify_ssl bool
     * (set false only for local testing — insecure).
     */
    private function httpVerify(): bool|string
    {
        $bundle = (string) config('nafath.ca_bundle');
        return $bundle !== '' ? $bundle : (bool) config('nafath.verify_ssl');
    }

    /**
     * The key(s) used to verify the id_token signature. When a JWKS URL is
     * configured, returns the parsed key set (JWT::decode selects by `kid`);
     * otherwise the single static IAM certificate.
     *
     * @param  array<string,mixed>  $cfg
     * @return Key|array<string,Key>
     */
    private function signingKeys(array $cfg): Key|array
    {
        if (!empty($cfg['jwks_url'])) {
            return JWK::parseKeySet($this->fetchJwks($cfg['jwks_url'], (int) $cfg['jwks_ttl']), $cfg['alg']);
        }
        return new Key($this->iamCert(), $cfg['alg']);
    }

    /**
     * Fetch and cache IAM's JWKS document.
     *
     * @return array<string,mixed>
     */
    private function fetchJwks(string $url, int $ttl): array
    {
        return Cache::remember('nafath_jwks', $ttl, function () use ($url) {
            Log::channel('nafath')->info('callback: fetching JWKS', ['url' => $url]);
            $res = Http::withOptions(['verify' => $this->httpVerify()])->timeout(10)->get($url);
            if (!$res->ok()) {
                throw new RuntimeException('Failed to fetch JWKS: HTTP ' . $res->status());
            }
            $jwks = $res->json();
            if (!is_array($jwks) || empty($jwks['keys'])) {
                throw new RuntimeException('JWKS response has no "keys".');
            }
            return $jwks;
        });
    }

    /**
     * Decode a JWT header (no verification) for diagnostics — exposes `alg`/`kid`.
     *
     * @return array<string,mixed>
     */
    private function tokenHeader(string $idToken): array
    {
        try {
            return $this->decodeWithoutVerification($idToken)['header'];
        } catch (\Throwable) {
            return [];
        }
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
