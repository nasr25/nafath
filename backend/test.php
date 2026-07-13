<?php
/**
 * =====================================================================
 *  NAFATH / IAM (OIDC) integration — Laravel scaffold (codegen scratch)
 * =====================================================================
 *  Split each block into its own file at the path shown in its banner.
 *
 *  Flow (per "NAFATH Authentication Service Integration Guide v3.3"):
 *    1) Build the OIDC request as a JWT signed RS256 with YOUR private
 *       key (the cert registered with / issued by the IAM team).
 *    2) Redirect the user to:
 *         {authorize_url}?client_id={client_id}&request={signed_jwt}
 *    3) IAM authenticates the user and POSTs back to redirect_uri:
 *         State=<same state you sent>
 *         Id_token=<RS256 JWT signed by IAM, containing the claims>
 *    4) Verify Id_token with the IAM PUBLIC certificate and validate
 *       issuer / audience / expiry / single-use (state), then map claims.
 *
 *  Prereqs:
 *    composer require firebase/php-jwt
 *    - Your PRIVATE key (PEM)                → storage/app/nafath/sp_private_key.pem
 *    - IAM's PUBLIC certificate (PEM)        → storage/app/nafath/iam_public.cer
 *    - Callback MUST be HTTPS and CSRF-exempt (external POST from IAM).
 *    - Confirm exact alg (guide text says RS256; sample header shows
 *      RS512), issuer URL, and endpoints with the integration team.
 * =====================================================================
 */


/* =====================================================================
 * ENV  →  add to .env
 * ===================================================================== */
/*
NAFATH_CLIENT_ID=https://www.sp.com
NAFATH_REDIRECT_URI=https://www.sp.com/nafath/callback
# Staging: https://www.iam.sa/authservice/authorize
# Production: https://www.iam.gov.sa/authservice/authorize
NAFATH_AUTHORIZE_URL=https://www.iam.sa/authservice/authorize
# Issuer claim expected in the returned Id_token (confirm with IAM team)
NAFATH_ISSUER=https://staging.iam.gov.sa/userauth
NAFATH_ALG=RS256
NAFATH_UI_LOCALE=ar
NAFATH_PRIVATE_KEY_PATH=nafath/sp_private_key.pem
NAFATH_IAM_CERT_PATH=nafath/iam_public.cer
*/


/* =====================================================================
 * CONFIG  →  config/nafath.php
 * ===================================================================== */

return [
    'client_id'     => env('NAFATH_CLIENT_ID'),
    'redirect_uri'  => env('NAFATH_REDIRECT_URI'),
    'authorize_url' => env('NAFATH_AUTHORIZE_URL', 'https://www.iam.sa/authservice/authorize'),
    'issuer'        => env('NAFATH_ISSUER'),
    'alg'           => env('NAFATH_ALG', 'RS256'),
    'ui_locale'     => env('NAFATH_UI_LOCALE', 'ar'),

    // Keys live on the "local" disk (storage/app). Move to a secret store in prod.
    'private_key_path' => env('NAFATH_PRIVATE_KEY_PATH', 'nafath/sp_private_key.pem'),
    'iam_cert_path'    => env('NAFATH_IAM_CERT_PATH', 'nafath/iam_public.cer'),

    // Clock-skew tolerance (seconds) when validating the Id_token timestamps.
    'leeway' => 60,
];


/* =====================================================================
 * SERVICE  →  app/Services/NafathService.php
 * ===================================================================== */

namespace App\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
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
            'max_age'       => (string) time(),
            'state'         => $state,
        ];

        // Sign the request JWT (RS256) with OUR private key — this is the step
        // that jwt.io got wrong: it must be the IAM-registered certificate's key.
        $request = JWT::encode($payload, $this->privateKey(), $cfg['alg']);

        $url = $cfg['authorize_url'] . '?' . http_build_query([
            'client_id' => $cfg['client_id'],
            'request'   => $request,
        ]);

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


/* =====================================================================
 * CONTROLLER  →  app/Http/Controllers/Api/NafathController.php
 *   (or App\Http\Controllers — it renders web redirects/JSON)
 * ===================================================================== */

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\NafathService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

class NafathController extends Controller
{
    public function __construct(private NafathService $nafath) {}

    /** Step 1-2: build the signed request and redirect the user to IAM. */
    public function login(Request $request): RedirectResponse
    {
        $auth = $this->nafath->buildAuthorizationUrl();

        // Remember the state to validate the response (single-use / anti-replay).
        $request->session()->put('nafath_state', $auth['state']);

        return redirect()->away($auth['url']);
    }

    /**
     * Step 3-4: IAM POSTs { State, Id_token } here. Verify and consume.
     * NOTE: exclude this route from CSRF (external POST) — see VerifyCsrfToken.
     */
    public function callback(Request $request)
    {
        $idToken = $request->input('Id_token', $request->input('id_token'));
        if (!$idToken) {
            return response()->json(['status' => false, 'message' => 'Missing Id_token'], 400);
        }

        $expectedState = $request->session()->pull('nafath_state'); // pull = one-time use

        try {
            $claims = $this->nafath->verifyIdToken($idToken, $expectedState);
        } catch (\Throwable $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 401);
        }

        // ── Map the NAFATH claims to your user model here ────────────────
        // $nationalId  = $claims['sub'] ?? null;   // National / Iqama Id
        // $englishName = $claims['englishName'] ?? null;
        // $arabicName  = $claims['arabicName']  ?? null;
        // $gender      = $claims['gender']      ?? null;
        // $user = User::updateOrCreate(['national_id' => $nationalId], [...]);
        // Auth::login($user);  // or issue a Sanctum token for the SPA.

        return response()->json([
            'status'  => true,
            'code'    => 200,
            'message' => 'NAFATH authentication successful',
            'data'    => $claims,
        ]);
    }
}


/* =====================================================================
 * ROUTES  →  routes/web.php  (browser-facing: redirect + external POST)
 * ===================================================================== */

use App\Http\Controllers\Api\NafathController;
use Illuminate\Support\Facades\Route;

Route::get('/nafath/login',      [NafathController::class, 'login'])->name('nafath.login');
Route::post('/nafath/callback',  [NafathController::class, 'callback'])->name('nafath.callback');


/* =====================================================================
 * CSRF EXEMPTION
 * ---------------------------------------------------------------------
 *  The callback is an external POST from IAM, so it has no CSRF token.
 *
 *  Laravel 10 →  app/Http/Middleware/VerifyCsrfToken.php
 *      protected $except = ['nafath/callback'];
 *
 *  Laravel 11+ →  bootstrap/app.php
 *      ->withMiddleware(function (Middleware $middleware) {
 *          $middleware->validateCsrfTokens(except: ['nafath/callback']);
 *      })
 * ===================================================================== */


/* =====================================================================
 * KEY CONVERSION (if IAM gave you a .pfx/.p12)  — run in a shell
 * ---------------------------------------------------------------------
 *  # your signing private key (PEM)
 *  openssl pkcs12 -in iam.pfx -nocerts -nodes -out sp_private_key.pem
 *  # IAM public certificate (PEM) used to verify the Id_token
 *  openssl pkcs12 -in iam.pfx -clcerts -nokeys -out iam_public.cer
 *  → place both under storage/app/nafath/
 * ===================================================================== */
