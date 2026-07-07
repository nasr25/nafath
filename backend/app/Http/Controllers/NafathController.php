<?php

namespace App\Http\Controllers;

use App\Services\NafathService;
use Firebase\JWT\JWT;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class NafathController extends Controller
{
    public function __construct(private NafathService $nafath)
    {
    }

    /**
     * Return the signed OIDC request object and the full authorize URL so the
     * frontend can inspect it and then redirect the user to IAM.
     */
    public function start(): JsonResponse
    {
        return response()->json($this->nafath->buildAuthorizeRequest());
    }

    /**
     * Callback receiver. IAM returns the id_token here (fragment or query).
     * For a simple test we just decode the claims WITHOUT verification and
     * echo them back. In production, verify the signature against the IAM
     * public key and validate nonce/state before trusting anything.
     */
    public function callback(Request $request): JsonResponse
    {
        $idToken = $request->input('id_token');

        if (! $idToken) {
            return response()->json([
                'ok'      => false,
                'message' => 'No id_token received.',
                'query'   => $request->query(),
            ], 400);
        }

        // NOTE: unverified decode for local testing / inspection only.
        $parts = explode('.', $idToken);
        $claims = count($parts) === 3
            ? json_decode(JWT::urlsafeB64Decode($parts[1]), true)
            : null;

        return response()->json([
            'ok'       => true,
            'id_token' => $idToken,
            'claims'   => $claims,
        ]);
    }
}
