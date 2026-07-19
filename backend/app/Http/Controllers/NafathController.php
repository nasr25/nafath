<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Services\NafathService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class NafathController extends Controller
{
    public function __construct(private NafathService $nafath) {}

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
     * form_post (POST { State, Id_token }). Renders an HTML page showing the
     * decoded claims + (when possible) the full verification and DB comparison.
     * Unlike callback() below, this returns a browser page, not JSON.
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
            } catch (\Throwable $e) {
                // Service already logged the precise failing step.
                $view['verifyError'] = $e->getMessage();
            }
        }

        return response()->view('nafath.callback', $view);
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
