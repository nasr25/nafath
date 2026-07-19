<?php

namespace App\Http\Middleware;

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken as Middleware;

class VerifyCsrfToken extends Middleware
{
    /**
     * The URIs that should be excluded from CSRF verification.
     *
     * @var array<int, string>
     */
    protected $except = [
        // IAM posts the id_token here cross-site (form_post) with no CSRF token.
        '_IAM/login',
        // IAM dispatches Single Logout here (slo=false) cross-site, no CSRF token.
        '_IAM/logout',
    ];
}
