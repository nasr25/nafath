<?php

use App\Http\Controllers\NafathController;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "web" middleware group. Make something great!
|
*/

// Home = the Blade "build request" console (Laravel is the site root now).
Route::get('/', [NafathController::class, 'build']);

// Diagnostic: proves a request reached the Laravel backend app. No token, no
// POST, no CSRF — just a plain 200 so you can isolate IIS routing from app
// errors. Test:  domain/backend/_IAM/ping  (direct) and  domain/_IAM/ping
// (through the frontend rewrite). Remove before production.
Route::get('/_IAM/ping', function () {
    Log::channel('nafath')->info('iam ping: reached Laravel backend');
    return response()->json([
        'ok'      => true,
        'message' => 'IAM ping OK — request reached the Laravel backend',
        'path'    => request()->path(),
        'method'  => request()->method(),
        'time'    => now()->toIso8601String(),
    ]);
});

// IAM (Nafath) redirect_uri. IAM returns the user here — as a form_post (POST)
// or with the token in the URL fragment (GET). Served by Laravel so the POST
// has a real handler (a static host answers POST with 405).
Route::match(['get', 'post'], '/_IAM/login', [NafathController::class, 'iamCallback']);

// IAM Single Logout. One endpoint, two directions:
//  - user-initiated (no slo)  -> kill local session, redirect to IAM ?slo=true
//  - IAM dispatch (?slo=false) -> kill local session, land on the public page
// The SLO dispatch URL (?slo=false) must be the logout URL registered with IAM.
Route::match(['get', 'post'], '/_IAM/logout', [NafathController::class, 'logout']);

// One-time decoded-result fetch for the frontend SPA. The callback caches the
// result under a random rid and redirects to the SPA with ?rid=; the SPA calls
// this once to render it (Cache::pull => single use).
Route::get('/nafath/result', [NafathController::class, 'result']);
