<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Passport;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        Passport::enablePasswordGrant();
        Passport::tokensExpireIn(now()->addMinutes(10));        // access token 10 minut
        Passport::refreshTokensExpireIn(now()->addDay());       // refresh token 1 kun
        Passport::personalAccessTokensExpireIn(now()->addMonths(6));
    }
}
