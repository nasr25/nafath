<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Services\NafathService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

class NafathController extends Controller
{
    public function __construct(private NafathService $nafath) {}

    /**
     * Home page (site root): build the signed OIDC request and render the Blade
     * console showing the authorize URL + decoded request, with a button to
     * redirect the browser to IAM. Builds fresh on each load.
     */
    public function build()
    {
        $auth = null;
        $header = null;
        $error = null;

        try {
            $auth = $this->nafath->buildAuthorizationUrl();
            $header = $this->nafath->decodeWithoutVerification($auth['request'])['header'];
        } catch (\Throwable $e) {
            Log::channel('nafath')->error('build page: ' . $e->getMessage());
            $error = $e->getMessage();
        }

        return response()->view('nafath.build', compact('auth', 'header', 'error'));
    }

    /**
     * One-time fetch of a decoded callback result by its `rid`. The frontend SPA
     * calls this after the callback redirects it here with ?rid=. Cache::pull
     * makes it single-use.
     */
    public function result(Request $request): JsonResponse
    {
        $rid = (string) $request->query('rid', '');
        $data = $rid !== '' ? Cache::pull('nafath_result:' . $rid) : null;

        if (!$data) {
            return response()->json([
                'ok'      => false,
                'message' => 'No result found — the rid is missing, already used, or expired.',
            ], 404);
        }

        return response()->json(['ok' => true, 'result' => $data]);
    }

    /**
     * Step 1-2: build the signed request object. Returns the authorize URL and
     * the decoded request (for the console to inspect); the browser then
     * navigates to `authorize_url` to reach IAM. Building here also caches the
     * `state` server-side for anti-replay, so the redirect must use this URL.
     */
    public function start(Request $request): JsonResponse
    {
        Log::channel('nafath')->info('login: request received', ['ip' => $request->ip()]);

        // The state → nonce binding is stashed in the cache by the service
        // (keyed by `state`), so no session is needed on these API routes.
        $auth = $this->nafath->buildAuthorizationUrl();

        return response()->json([
            'authorize_url' => $auth['url'],
            'request'       => $auth['request'],
            'payload'       => $auth['payload'],
        ]);
    }

    /**
     * IAM redirect_uri (/_IAM/login). IAM returns the user here, usually as a
     * form_post (POST { State, Id_token }). Decodes + verifies the token, caches
     * the result under a one-time `rid`, then redirects the browser to the
     * frontend SPA (?rid=) which fetches and displays it via result().
     */
    public function iamCallback(Request $request)
    {
        Log::channel('nafath')->info('iam callback (_IAM/login): received', [
            'ip'        => $request->ip(),
            'method'    => $request->method(),
            'has_token' => $request->filled('Id_token') || $request->filled('id_token'),
            'keys'      => array_keys($request->all()),
        ]);

        $idToken    = $request->input('Id_token', $request->input('id_token'));
        $state      = $request->input('State', $request->input('state'));
        $errorParam = $request->input('error');

        // Print the raw id_token to the log for debugging (contains PII — remove
        // or mask before production).
        Log::channel('nafath')->info('iam callback: id_token', ['id_token' => $idToken]);

        $view = [
            'idToken'     => $idToken,
            'state'       => $state,
            'errorParam'  => $errorParam,
            'decoded'     => null,
            'verified'    => false,
            'verifyError' => null,
            'nationalId'  => null,
            'matched'     => false,
            'comparison'  => null,
        ];

        if ($idToken) {
            // Always decode (no signature check) so the claims are visible even
            // before the IAM public cert is in place.
            try {
                $view['decoded'] = $this->nafath->decodeWithoutVerification($idToken);
            } catch (\Throwable $e) {
                $view['verifyError'] = 'Decode failed: ' . $e->getMessage();
            }

            // Attempt full verification (needs the IAM cert + a live state/nonce).
            try {
                $claims = $this->nafath->verifyIdToken($idToken, $state);
                $view['verified'] = true;

                $nationalId = $claims['sub'] ?? $claims['userid'] ?? $claims['nationalId'] ?? null;
                $user = $nationalId ? User::where('id_number', $nationalId)->first() : null;
                $view['nationalId'] = $nationalId;
                $view['matched']    = (bool) $user;
                $view['comparison'] = $this->nafath->buildComparison($user, $claims);

                // Mark a local session so logout has real state to terminate.
                $request->session()->put('nafath_sub', $nationalId);
            } catch (\Throwable $e) {
                // Service already logged the precise failing step.
                $view['verifyError'] = $e->getMessage();
            }
        }

        // Cache the decoded result under a one-time id and hand off to the
        // frontend SPA, which fetches it via result() and renders it.
        $rid = Str::random(40);
        Cache::put('nafath_result:' . $rid, $view, now()->addMinutes(5));

        $frontend = rtrim((string) config('nafath.frontend_url'), '/');
        Log::channel('nafath')->info('iam callback: redirecting to frontend', [
            'frontend' => $frontend,
            'verified' => $view['verified'],
        ]);

        return redirect($frontend . '/?rid=' . $rid);
    }

    /**
     * IAM Single Logout (SLO) — the "simplified/direct logout URI" flow, which
     * the guide marks as applicable to OIDC. One endpoint, two directions:
     *
     *  - IAM dispatch (?slo=false): IAM is logging the user out of us as part of
     *    a Single Logout it is orchestrating. Kill our session and land on the
     *    public page. (This URL, with ?slo=false, is what IAM has registered.)
     *  - User-initiated (no slo): kill our session, then redirect the browser to
     *    IAM's logout URL with ?slo=true so IAM ends its session and dispatches
     *    logout to the other SPs.
     */
    public function logout(Request $request)
    {
        $cfg = config('nafath');
        $slo = $request->input('slo', $request->query('slo'));

        Log::channel('nafath')->info('logout: received', [
            'ip'     => $request->ip(),
            'method' => $request->method(),
            'slo'    => $slo,
        ]);

        // Terminate our local session either way.
        if (Auth::check()) {
            Auth::logout();
        }
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        // IAM is dispatching Single Logout to us — nothing more to do.
        if ($slo === 'false') {
            Log::channel('nafath')->info('logout: IAM SLO dispatch handled (slo=false)');
            return redirect($cfg['post_logout_redirect']);
        }

        // User-initiated — hand off to IAM to end the IAM session + fan out SLO.
        $url = rtrim($cfg['logout_url'], '?&') . '?slo=true';
        Log::channel('nafath')->info('logout: redirecting to IAM', ['url' => $url]);
        return redirect()->away($url);
    }

    /**
     * Step 3-4: IAM POSTs { State, Id_token } here. Verify and consume.
     */
    public function callback(Request $request)
    {
        Log::channel('nafath')->info('callback: received', [
            'ip'        => $request->ip(),
            'method'    => $request->method(),
            'has_token' => $request->filled('Id_token') || $request->filled('id_token'),
            'keys'      => array_keys($request->all()),
        ]);

        $idToken = $request->input('Id_token', $request->input('id_token'));
        if (!$idToken) {
            Log::channel('nafath')->warning('callback: missing Id_token', [
                'keys' => array_keys($request->all()),
            ]);
            return response()->json(['status' => false, 'message' => 'Missing Id_token'], 400);
        }

        $returnedState = $request->input('State', $request->input('state'));

        try {
            $claims = $this->nafath->verifyIdToken($idToken, $returnedState);
        } catch (\Throwable $e) {
            // The service already logged the precise failing step at warning level.
            return response()->json(['status' => false, 'message' => $e->getMessage()], 401);
        }

        Log::channel('nafath')->info('callback: authentication successful', [
            'sub' => $claims['sub'] ?? null,
        ]);

        // Find the local user by their National Id (NAFATH `sub`) and compare
        // the stored ("old") data against the verified NAFATH ("corrected") data.
        $nationalId = $claims['sub'] ?? $claims['userid'] ?? $claims['nationalId'] ?? null;
        $user = $nationalId
            ? User::where('id_number', $nationalId)->first()
            : null;

        Log::channel('nafath')->info('callback: user lookup', [
            'has_national_id' => (bool) $nationalId,
            'matched'         => (bool) $user,
        ]);

        return response()->json([
            'status'  => true,
            'code'    => 200,
            'message' => $user
                ? 'NAFATH authentication successful'
                : 'NAFATH verified, but no matching user was found for this National Id',
            'data'    => [
                'national_id' => $nationalId,
                'matched'     => (bool) $user,
                'user_id'     => $user?->id,
                'comparison'  => $this->nafath->buildComparison($user, $claims),
                'claims'      => $claims,
            ],
        ]);
    }
}
