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
                'client_id' => config('passport.client_id'),
                'client_secret' => config('passport.client_secret'),
                'username' => $r->email,
                'password' => $r->password,
                'scope' => '',
            ]
        );

        return response()->json([
            'access_token' => $resp['access_token'],
            'refresh_token' => $resp['refresh_token'],
            'expires_in' => $resp['expires_in'],
            'token_type' => $resp['token_type'],
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
