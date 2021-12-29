<?php

namespace Darkink\OpenIdServer;

use Darkink\OpenIdServer\Http\Controllers\DiscoveryController;
use Illuminate\Support\Facades\Route;

class OpenIdServer
{

    public static $resourceScopes = [];
    public static $issuer = '';

    public static function resourceScopes(array $resourceScopes)
    {
        static::$resourceScopes = $resourceScopes;
    }

    public static function issuer(string $issuer)
    {
        static::$issuer = $issuer;
    }

    public static function routes()
    {
        Route::prefix('.well-known')->group(function () {
            Route::prefix('/openid-configuration')->group(function () {
                Route::get('', [DiscoveryController::class, 'index'])->name('openid.discovery.index');
                Route::get('/jwks', [DiscoveryController::class, 'jwks'])->name('openid.discovery.jwks');
            });
        });
    }
}
