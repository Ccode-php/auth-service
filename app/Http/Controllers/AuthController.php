<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;

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


    public function login(Request $r)
    {
        $r->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        $resp = Http::asForm()->post(
            config('services.passport.token_url'),
            [
                'grant_type' => 'password',
                'client_id' => env('PASSPORT_CLIENT_ID'),
                'client_secret' => env('PASSPORT_CLIENT_SECRET'),
                'username' => $r->email,
                'password' => $r->password,
                'scope' => '',
            ]
        );

        // 🔴 MUHIM: agar Passport error qaytarsa
        if (! $resp->successful()) {
            logger()->error('PASSPORT ERROR', [
                'status' => $resp->status(),
                'body' => $resp->body(),
            ]);

            return response()->json([
                'message' => 'Login failed',
                'passport' => $resp->json(),
            ], 401);
        }

        // 🔴 MUHIM: json ni majburan array qilamiz
        $data = json_decode($resp->body(), true);

        return response()->json([
            'access_token' => $data['access_token'],
            'refresh_token' => $data['refresh_token'],
            'expires_in' => $data['expires_in'],
            'token_type' => $data['token_type'],
        ]);
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
