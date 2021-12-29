<?php

namespace Darkink\OpenIdServer\Http\Controllers;

use Error;
use Illuminate\Http\Request;
use Laravel\Passport\Passport;

class DiscoveryController
{
    private $_publicKeyType = [
        0 => 'rsa',
        1 => 'dsa',
        3 => 'dh',
        4 => 'ec'
    ];

    public function index(Request $request)
    {
        $host = $request->getSchemeAndHttpHost();
        $scopes = Passport::scopes()->map(function ($p) {
            return $p->id;
        })->values();

        return [
            'issuer' => $host, //TODO(demarco): Could be an issue field
            'jwks_uri' => route('openid.discovery.jwks'),
            'authorization_endpoint' => route('passport.authorizations.authorize'),
            'token_endpoint' => route('passport.token'),
            'userinfo_endpoint' => route('api.userinfo'),
            'end_session_endpoint' => '???',
            'check_session_iframe' => '???',
            'revocation_endpoint' => '???',
            'introspection_endpoint' => '???',
            'device_authorization_endpoint' => '???',
            'frontchannel_logout_supported' => true,
            'frontchannel_logout_session_supported' => true,
            'backchannel_logout_supported' => true,
            'backchannel_logout_session_supported' => true,
            'scopes_supported' => $scopes,

            //TODO(demarco): Should be parameterized AND used in the application
            // {
            'claims_supported' => [
                'sub'
            ],
            'grant_types_supported' => [
                'authorization_code',
                'client_credentials',
                'refresh_token',
                'implicit',
                'urn:ietf:params:oauth:grant-type:device_code'
            ],
            'response_types_supported' => [
                'code',
                // 'token',
                // 'id_token',
                // 'id_token token',
                // 'code id_token',
                // 'code token',
                // 'code id_token token'
            ],
            'response_modes_supported' => [
                'form_post',
                'query',
                'fragment'
            ],
            'token_endpoint_auth_methods_supported' => [
                'client_secret_basic',
                'client_secret_post'
            ],
            'id_token_signing_alg_values_supported'  => [
                'RS256'
            ],
            'subject_types_supported' => [
                'public'
            ],
            'code_challenge_methods_supported' => [
                'plain',
                'S256'
            ],
            'request_parameter_supported'    => true
            // }
        ];
    }

    public function jwks(Request $request)
    {
        $publicKeyPath = Passport::keyPath('oauth-public.key');
        $publicKeyContent = file_get_contents($publicKeyPath);
        $publicKey = openssl_pkey_get_public($publicKeyContent);
        if (!$publicKey) {
            throw new Error('Cannot read public key');
        }
        $publicKeyInfo = openssl_pkey_get_details($publicKey);
        if (!$publicKeyInfo) {
            throw new Error('Cannot read public key');
        }

        $type = $this->_publicKeyType[$publicKeyInfo['type']];
        // $base64 = base64_encode($publicKeyInfo['key']);
        $hash = strtoupper($this->_base64EncodeUrl(hash('MD5', $publicKeyInfo['key'])));

        return [
            'keys' => [
                0 => [
                    'kty' => strtoupper($type),
                    'use' => 'sig',
                    'kid' => $hash,
                    'e' => $this->_base64EncodeUrl($publicKeyInfo[$type]['e']),
                    'n' => $this->_base64EncodeUrl($publicKeyInfo[$type]['n']),
                    'alg' => 'RS256',
                ]
            ]
        ];
    }

    private function _base64EncodeUrl($data){
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

}
