<?php

use App\Http\Controllers\NafathController;
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

Route::get('/', function () {
    return view('welcome');
});

// IAM (Nafath) redirect_uri. IAM returns the user here — as a form_post (POST)
// or with the token in the URL fragment (GET). Served by Laravel so the POST
// has a real handler (a static host answers POST with 405).
Route::match(['get', 'post'], '/_IAM/login', [NafathController::class, 'iamCallback']);
