<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Laravel\Passport\Http\Controllers\AccessTokenController;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\Diactoros\Response;


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
            'email' => 'required|email',
            'password' => 'required',
        ]);

        $psrRequest = ServerRequestFactory::fromGlobals()->withParsedBody([
            'grant_type' => 'password',
            'client_id' => config('passport.client_id'),
            'client_secret' => config('passport.client_secret'),
            'username' => $request->email,
            'password' => $request->password,
            'scope' => '',
        ]);

        $response = new Response();

        return app(AccessTokenController::class)
            ->issueToken($psrRequest, $response);
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

    public function logout(Request $r)
    {
        $user = $r->user();
        $user->tokens()->delete(); // barcha tokenlarni o'chiradi
        return response()->json(['message' => 'Logged out'], 200);
    }
}
