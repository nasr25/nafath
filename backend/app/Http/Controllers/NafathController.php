<?php

namespace App\Http\Controllers;

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
