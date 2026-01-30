<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Laravel\Passport\Http\Controllers\AccessTokenController;
use Psr\Http\Message\ServerRequestInterface;

class AuthController extends Controller
{
    public function register(Request $r)
    {
        $r->validate(['name' => 'required', 'email' => 'required|email', 'password' => 'required|min:1']);
        $user = User::create([
            'name' => $r->name,
            'email' => $r->email,
            'password' => Hash::make($r->password)
        ]);
        return response()->json($user, 201);
    }


    public function login(Request $request)
    {
        $request->validate([
            'email'    => 'required|email',
            'password' => 'required',
        ]);

        // Laravel request → PSR-7 request
        $psrRequest = app(ServerRequestInterface::class)->withParsedBody([
            'grant_type'    => 'password',
            'client_id'     => config('passport.password_client_id'),
            'client_secret' => config('passport.password_client_secret'),
            'username'      => $request->email,
            'password'      => $request->password,
            'scope'         => '',
        ]);

        return app(AccessTokenController::class)->issueToken($psrRequest);
    }


    public function refresh(Request $r)
    {
        $r->validate(['refresh_token' => 'required']);
        $resp = Http::asForm()->post(config('services.passport.token_url'), [
            'grant_type' => 'refresh_token',
            'refresh_token' => $r->refresh_token,
            'client_id' => env('PASSPORT_CLIENT_ID'),
            'client_secret' => env('PASSPORT_CLIENT_SECRET'),
        ]);
        return response()->json($resp->json(), $resp->status());
    }
}
