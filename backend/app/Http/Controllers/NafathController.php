<?php

namespace App\Http\Controllers;

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
            'idToken'       => $idToken,
            'state'         => $state,
            'errorParam'    => $errorParam,
            'decoded'       => null,
            'verified'      => false,
            'verifyError'   => null,
            'nationalId'    => null,
            'userInfo'      => null,
            'userInfoError' => null,
        ];

        if ($idToken) {
            // Decode (no signature check) so the claims are always visible.
            try {
                $view['decoded'] = $this->nafath->decodeWithoutVerification($idToken);
            } catch (\Throwable $e) {
                $view['verifyError'] = 'Decode failed: ' . $e->getMessage();
            }
            $payload = $view['decoded']['payload'] ?? [];
            $view['nationalId'] = $payload['sub'] ?? $payload['userid'] ?? null;

            // Verify the id_token signature (optional; the real authorization is
            // the access token, validated by iDart UserInfo). Disable with
            // NAFATH_VERIFY_IDTOKEN=false. verified: true=ok, false=failed,
            // null=skipped.
            if (config('nafath.verify_idtoken')) {
                try {
                    $this->nafath->verifyIdToken($idToken, $state);
                    $view['verified'] = true;
                } catch (\Throwable $e) {
                    $view['verifyError'] = $e->getMessage(); // service logged the step
                }
            } else {
                $view['verified'] = null;
            }

            // The profile lives behind the access token: get it from the
            // id_token, call UserInfo with it, and decode the returned token.
            $accessToken = $payload['accessToken'] ?? $payload['access_token'] ?? null;
            if ($accessToken) {
                try {
                    $view['userInfo'] = $this->nafath->fetchUserInfo($accessToken);
                } catch (\Throwable $e) {
                    $view['userInfoError'] = $e->getMessage();
                }
            } else {
                $view['userInfoError'] = 'No access token found in the id_token.';
            }
        }

        // Keep the raw id_token for logout. OIDC RP-initiated logout has to hand
        // it back as `id_token_hint` so IAM knows which session to end; without
        // it IAM keeps its SSO session and the next login skips authentication.
        if ($idToken) {
            $request->session()->put('nafath.id_token', $idToken);
            $request->session()->put('nafath.national_id', $view['nationalId']);
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
     * Logout. One endpoint, two directions:
     *
     *  - IAM dispatch (?slo=false): IAM is logging the user out of us as part of
     *    a Single Logout it is orchestrating. Kill our session and land on the
     *    public page. (This URL, with ?slo=false, is what IAM has registered.)
     *  - User-initiated (no `slo`, or slo=true): kill our session, then send the
     *    browser to IAM's logout endpoint so IAM ends the Nafath SSO session too.
     *    The id_token stashed at login travels along as `id_token_hint` — that is
     *    what lets IAM identify the session to terminate. See
     *    NafathService::buildLogoutUrl().
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

        // Read the id_token before the session is thrown away — it is the
        // `id_token_hint` IAM needs to end the right session.
        $idToken = $request->session()->get('nafath.id_token');

        // Terminate our local session either way.
        if (Auth::check()) {
            Auth::logout();
        }
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        // IAM is dispatching Single Logout to us — nothing more to do. Anything
        // that is not an explicit "true" counts as a dispatch: bouncing back to
        // IAM here would make it dispatch again, and round we go.
        if ($slo !== null && strtolower((string) $slo) !== 'true') {
            Log::channel('nafath')->info('logout: IAM SLO dispatch handled', ['slo' => $slo]);
            return redirect($cfg['post_logout_redirect']);
        }

        // User-initiated — hand off to IAM to end the IAM session + fan out SLO.
        $url = $this->nafath->buildLogoutUrl($idToken);
        Log::channel('nafath')->info('logout: redirecting to IAM', ['url' => $url]);
        return redirect()->away($url);
    }

}
