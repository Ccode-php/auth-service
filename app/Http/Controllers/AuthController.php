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
        $r->validate([
            'name' => 'required',
            'email' => 'required|email',
            'password' => 'required|min:1',
        ]);

        $user = User::create([
            'name' => $r->name,
            'email' => $r->email,
            'password' => Hash::make($r->password),
            'phone' => null,
            'address' => null,
            'card_number' => null,
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
            'client_id' => env('PASSPORT_CLIENT_ID'),
            'client_secret' => env('PASSPORT_CLIENT_SECRET'),
            'username' => $request->email,
            'password' => $request->password,
            'scope' => '',
        ]);

        $response = new Response();
        $res = app(AccessTokenController::class)->issueToken($psrRequest, $response);
        $data = json_decode($res->getContent(), true);

        // refresh tokenni cookie ga qo'yamiz
        if (isset($data['refresh_token'])) {
            cookie()->queue(cookie(
                'refresh_token',
                $data['refresh_token'],
                60*24, // 1 kun
                '/',
                null,
                false,   // secure
                true,   // httpOnly
                false,
                'Strict' // SameSite
            ));
            unset($data['refresh_token']); // frontendga yubormaymiz
        }

        return response()->json($data);
    }

    public function refresh(Request $request)
    {
        $refresh_token = $request->cookie('refresh_token');
        if (!$refresh_token) {
            return response()->json(['message' => 'No refresh token'], 401);
        }

        $resp = Http::asForm()->post(config('services.passport.token_url'), [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refresh_token,
            'client_id' => env('PASSPORT_CLIENT_ID'),
            'client_secret' => env('PASSPORT_CLIENT_SECRET'),
        ]);

        $data = $resp->json();

        if (isset($data['refresh_token'])) {
            // refresh tokenni yangilaymiz
            cookie()->queue(cookie(
                'refresh_token',
                $data['refresh_token'],
                60*24,
                '/',
                null,
                false,
                true,
                false,
                'Strict'
            ));
            unset($data['refresh_token']);
        }

        return response()->json($data, $resp->status());
    }

    public function logout(Request $request)
    {
        $user = $request->user();
        $user->tokens()->delete();

        // refresh token cookie ni o'chiramiz
        cookie()->queue(cookie()->forget('refresh_token'));

        return response()->json(['message' => 'Logged out']);
    }

    public function user(Request $request)
    {
        return response()->json([
            'id' => $request->user()->id,
            'name' => $request->user()->name,
            'email' => $request->user()->email,
        ]);
    }
}
