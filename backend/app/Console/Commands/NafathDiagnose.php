<?php

namespace App\Console\Commands;

use App\Services\NafathService;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Storage;

/**
 * Diagnose why an id_token fails signature verification against the static IAM
 * certificate: prints the cert identity + fingerprints, the token header
 * (alg/kid/x5t), whether the token's signing-cert thumbprint matches your cert,
 * and the actual verification result.
 *
 *   php artisan nafath:diagnose "<id_token>"
 */
class NafathDiagnose extends Command
{
    protected $signature = 'nafath:diagnose {token : the raw id_token to inspect}';

    protected $description = 'Diagnose id_token signature verification against the configured IAM cert';

    public function handle(NafathService $nafath): int
    {
        $cfg = config('nafath');
        $this->line('alg      : ' . $cfg['alg']);
        $this->line('jwks_url : ' . ($cfg['jwks_url'] ?: '(none — using static cert)'));

        // ---- The configured static cert ----
        $certPath = $cfg['iam_cert_path'];
        $sha1 = null;
        $pem = null;

        if (!Storage::disk('local')->exists($certPath)) {
            $this->error("Cert NOT found: storage/app/{$certPath}");
        } else {
            $pem = Storage::disk('local')->get($certPath);
            $this->line('cert file: storage/app/' . $certPath);

            $parsed = @openssl_x509_parse($pem);
            if (!$parsed) {
                $this->error('  -> did NOT parse as an X.509 certificate.');
                $this->warn('     It may be DER (binary), a bare public key, or corrupted.');
                $this->warn('     Expected PEM text starting with -----BEGIN CERTIFICATE-----');
            } else {
                $sha1 = openssl_x509_fingerprint($pem, 'sha1');
                $this->line('  subject: ' . ($parsed['name'] ?? '(?)'));
                $this->line('  issuer : ' . ($parsed['issuer']['CN'] ?? json_encode($parsed['issuer'] ?? [])));
                $this->line('  valid  : ' . date('Y-m-d', $parsed['validFrom_time_t'] ?? 0)
                    . ' .. ' . date('Y-m-d', $parsed['validTo_time_t'] ?? 0));
                $this->line('  SHA1   : ' . $sha1);
                $this->line('  SHA256 : ' . openssl_x509_fingerprint($pem, 'sha256'));
            }
        }

        // ---- The token header ----
        $token = (string) $this->argument('token');
        $header = [];
        try {
            $header = $this->decodeHeader($token);
        } catch (\Throwable $e) {
            $this->error('Could not decode token header: ' . $e->getMessage());
            return self::FAILURE;
        }

        $this->newLine();
        $this->line('token alg: ' . ($header['alg'] ?? '(none)'));
        $this->line('token kid: ' . ($header['kid'] ?? '(none)'));
        $this->line('token x5t: ' . ($header['x5t'] ?? '(none)'));

        // ---- Does the token's signing cert match our cert? ----
        if (!empty($header['x5t']) && $sha1) {
            $x5tHex = bin2hex($this->b64url($header['x5t']));
            $certHex = strtolower(str_replace(':', '', $sha1));
            if (hash_equals($certHex, strtolower($x5tHex))) {
                $this->info('x5t vs cert SHA1: MATCH — this IS the signing cert.');
            } else {
                $this->error('x5t vs cert SHA1: MISMATCH — your .cer is NOT the cert that signed this token.');
                $this->warn('   token x5t (sha1): ' . $x5tHex);
                $this->warn('   your  cert sha1 : ' . $certHex);
            }
        } else {
            $this->warn('No x5t in header (or no cert) — cannot thumbprint-compare; relying on verify below.');
        }

        // ---- Actual verification ----
        $this->newLine();
        if ($pem) {
            try {
                JWT::$leeway = (int) $cfg['leeway'];
                JWT::decode($token, new Key($pem, $cfg['alg']));
                $this->info('Signature: VALID against the configured cert. ✅');
            } catch (\Throwable $e) {
                $this->error('Signature: ' . $e->getMessage());
                $this->warn('Fix: replace storage/app/' . $certPath
                    . ' with IAM\'s real signing certificate for THIS environment,');
                $this->warn('or set NAFATH_JWKS_URL to IAM\'s JWKS endpoint.');
            }
        }

        return self::SUCCESS;
    }

    /** @return array<string,mixed> */
    private function decodeHeader(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) < 2) {
            throw new \RuntimeException('not a JWT');
        }
        return json_decode($this->b64url($parts[0]), true) ?? [];
    }

    private function b64url(string $s): string
    {
        return (string) base64_decode(strtr($s, '-_', '+/'));
    }
}
