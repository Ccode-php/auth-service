<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

Route::post('/auth/register', [AuthController::class,'register']);
Route::post('/auth/login', [AuthController::class,'login']);
Route::post('/auth/refresh', [AuthController::class,'refresh']);

Route::middleware('auth:api')->group(function () {
    Route::post('/auth/logout', [AuthController::class,'refresh']);
    Route::post('/auth/user', [AuthController::class,'user']);
});
