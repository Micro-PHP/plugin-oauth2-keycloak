<?php

declare(strict_types=1);

namespace Micro\Plugin\OAuth2\Client\Keycloak\Tests;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Micro\Plugin\OAuth2\Client\Facade\Oauth2ClientFacadeInterface;
use Micro\Plugin\OAuth2\Client\Keycloak\Provider\OAuth2Provider;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

final class OAuth2KeycloakProviderTest extends TestCase
{
    private const REALM_URL = 'https://identity.example/realms/partners/protocol/openid-connect';

    public function testAuthorizationCodeAndJsonUserInfoUseTheConfiguredRealm(): void
    {
        $profile = ['sub' => 'user-42', 'email' => 'user@example.org'];
        $transport = new MockHandler([
            $this->jsonResponse(['access_token' => 'test-token', 'token_type' => 'Bearer']),
            $this->jsonResponse($profile),
        ]);
        $provider = $this->provider($transport);

        [$url, $query] = explode('?', $provider->getAuthorizationUrl(), 2);
        parse_str($query, $options);
        self::assertSame(self::REALM_URL . '/auth', $url);
        self::assertSame('portal-app', $options['client_id']);
        self::assertSame('https://portal.example/callback', $options['redirect_uri']);

        $token = $provider->getAccessToken('authorization_code', ['code' => 'test-code']);
        $request = $transport->getLastRequest();
        self::assertSame('POST', $request->getMethod());
        self::assertSame(self::REALM_URL . '/token', (string) $request->getUri());
        parse_str((string) $request->getBody(), $form);
        self::assertSame('authorization_code', $form['grant_type']);
        self::assertSame('test-code', $form['code']);
        self::assertSame('test-token', $token->getToken());

        $owner = $provider->getResourceOwner($token);
        $request = $transport->getLastRequest();
        self::assertSame('GET', $request->getMethod());
        self::assertSame(self::REALM_URL . '/userinfo', (string) $request->getUri());
        self::assertSame('Bearer test-token', $request->getHeaderLine('Authorization'));
        self::assertSame('user-42', $owner->getId());
        self::assertSame($profile, $owner->toArray());
    }

    public static function symmetricKeySettings(): array
    {
        return [
            ['SECURITY_TOKEN_PROVIDER_DEFAULT_SECRET'],
            ['SECURITY_TOKEN_PROVIDER_DEFAULT_PUBLIC'],
        ];
    }

    #[DataProvider('symmetricKeySettings')]
    public function testReadsSignedClaimsWithTheConfiguredSecret(string $setting): void
    {
        $key = '/' . base64_encode(random_bytes(32));
        $claims = ['sub' => 'signed-user', 'name' => 'Example'];
        $jwt = JWT::encode($claims, $key, 'HS256');
        $provider = $this->provider(new MockHandler([
            $this->jsonResponse(['jwt' => $jwt, 'sub' => 'outer-profile']),
        ]), [$setting => $key]);

        $owner = $provider->getResourceOwner($this->accessToken());
        self::assertSame('signed-user', $owner->getId());
        self::assertSame($claims, $owner->toArray());
    }

    #[TestWith([''])]
    #[TestWith(['file://'])]
    public function testVerifiesRealmSignaturesWithAPublicKeyFile(string $prefix): void
    {
        $privateKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        $publicKeyFile = tempnam(sys_get_temp_dir(), 'keycloak-public-');
        try {
            file_put_contents($publicKeyFile, openssl_pkey_get_details($privateKey)['key']);
            $jwt = JWT::encode(['sub' => 'realm-user'], $privateKey, 'RS256');
            $provider = $this->provider(new MockHandler([$this->jsonResponse(['jwt' => $jwt])]), [
                'SECURITY_TOKEN_PROVIDER_DEFAULT_ALGORITHM' => 'RS256',
                'SECURITY_TOKEN_PROVIDER_DEFAULT_PUBLIC' => $prefix . $publicKeyFile,
            ]);
            self::assertSame('realm-user', $provider->getResourceOwner($this->accessToken())->getId());
        } finally {
            unlink($publicKeyFile);
        }
    }

    public function testRejectsASignatureFromADifferentKey(): void
    {
        $jwt = JWT::encode(['sub' => 'user'], bin2hex(random_bytes(32)), 'HS256');
        $provider = $this->provider(new MockHandler([$this->jsonResponse(['jwt' => $jwt])]), [
            'SECURITY_TOKEN_PROVIDER_DEFAULT_SECRET' => bin2hex(random_bytes(32)),
        ]);
        $this->expectException(SignatureInvalidException::class);
        $provider->getResourceOwner($this->accessToken());
    }

    public function testPemKeyRequiresAnAsymmetricAlgorithm(): void
    {
        $privateKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        $jwt = JWT::encode(['sub' => 'realm-user'], $privateKey, 'RS256');
        $provider = $this->provider(new MockHandler([$this->jsonResponse(['jwt' => $jwt])]), [
            'SECURITY_TOKEN_PROVIDER_DEFAULT_PUBLIC' => "Realm signing key\n" . openssl_pkey_get_details($privateKey)['key'],
        ]);
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('asymmetric signing algorithm');
        $provider->getResourceOwner($this->accessToken());
    }

    #[TestWith(['file://'])]
    #[TestWith(['FiLe://'])]
    public function testAnExplicitKeyFileMustExist(string $scheme): void
    {
        $jwt = JWT::encode(['sub' => 'user'], bin2hex(random_bytes(32)), 'HS256');
        $provider = $this->provider(new MockHandler([$this->jsonResponse(['jwt' => $jwt])]), [
            'SECURITY_TOKEN_PROVIDER_DEFAULT_SECRET' => $scheme . sys_get_temp_dir() . '/' . bin2hex(random_bytes(16)),
        ]);
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('verification key file');
        $provider->getResourceOwner($this->accessToken());
    }

    public function testRejectsAnExpiredSignedProfile(): void
    {
        $key = bin2hex(random_bytes(32));
        $jwt = JWT::encode(['sub' => 'user', 'exp' => time() - 60], $key, 'HS256');
        $provider = $this->provider(new MockHandler([$this->jsonResponse(['jwt' => $jwt])]), [
            'SECURITY_TOKEN_PROVIDER_DEFAULT_SECRET' => $key,
        ]);
        $this->expectException(ExpiredException::class);
        $provider->getResourceOwner($this->accessToken());
    }

    public function testSignedProfilesRequireAnExplicitVerificationKey(): void
    {
        $jwt = JWT::encode(['sub' => 'user'], bin2hex(random_bytes(32)), 'HS256');
        $provider = $this->provider(new MockHandler([$this->jsonResponse(['jwt' => $jwt])]));
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('verification key');
        $provider->getResourceOwner($this->accessToken());
    }

    public function testRejectsAnInvalidJwtField(): void
    {
        $provider = $this->provider(new MockHandler([$this->jsonResponse(['jwt' => []])]));
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('signed JWT string');
        $provider->getResourceOwner($this->accessToken());
    }

    public function testPropagatesTheTokenEndpointError(): void
    {
        $provider = $this->provider(new MockHandler([
            $this->jsonResponse(['error' => 'invalid_grant', 'error_description' => 'Code expired'], 400),
        ]));
        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('invalid_grant: Code expired');
        $provider->getAccessToken('authorization_code', ['code' => 'expired-code']);
    }

    private function provider(MockHandler $transport, array $settings = []): OAuth2Provider
    {
        $boot = require __DIR__ . '/Fixture/application.php';
        $facade = $boot($settings)->container()->get(Oauth2ClientFacadeInterface::class);
        $provider = $facade->getProvider('portal');
        $provider->setHttpClient(new Client(['handler' => HandlerStack::create($transport)]));

        return $provider;
    }

    private function accessToken(): AccessToken
    {
        return new AccessToken(['access_token' => 'test-token']);
    }

    private function jsonResponse(array $body, int $status = 200): Response
    {
        return new Response($status, ['Content-Type' => 'application/json'], json_encode($body, JSON_THROW_ON_ERROR));
    }
}
