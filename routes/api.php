<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

Route::post('/auth/register', [AuthController::class,'register']);
Route::post('/auth/login', [AuthController::class,'login']);
Route::post('/auth/refresh', [AuthController::class,'refresh']);

// token check used by gateway
use Illuminate\Http\Request;
Route::get('/check-token', function(Request $request){
    return auth()->check() ? response()->json(['valid'=>true, 'user'=>auth()->user()]) : response()->json(['valid'=>false],401);
});
