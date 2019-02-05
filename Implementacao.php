<?php

namespace App\Http\Controllers;

use App\User;
use Carbon\Carbon;
use Tymon\JWTAuth\Facades\JWTFactory;

class TesteController extends Controller
{
    public function index(User $user)
    {
        $user = $user->find(1);
        //Auth::login($user);
        //$authUser = Auth::user()->id;

        // Create token header as a JSON string
        $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
        // Create token payload as a JSON string
        $customClaims = [
            'sub' => $user->id,
            'exp' => Carbon::now()->addMonth(12)->timestamp
        ];
        $factory = JWTFactory::customClaims($customClaims);
        $payload = $factory->make();

        // Encode Header to Base64Url String
        $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
        // Encode Payload to Base64Url String
        $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
        // Create Signature Hash
        $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, env('JWT_SECRET'), true);
        // Encode Signature to Base64Url String
        $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
        // Create JWT
        $jwt = $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;

        dd($jwt);
    }
}
