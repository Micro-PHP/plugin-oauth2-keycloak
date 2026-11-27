<?php

declare(strict_types=1);

namespace Micro\Plugin\OAuth2\Client\Keycloak\Provider;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Micro\Framework\Kernel\Configuration\ApplicationConfigurationInterface;

final class UserInfoJwtDecoder
{
    public function __construct(private readonly ApplicationConfigurationInterface $configuration)
    {
    }

    public function decode(string $jwt): array
    {
        $algorithm = $this->configuration->get('SECURITY_TOKEN_PROVIDER_DEFAULT_ALGORITHM', 'HS256');
        $key = $this->configuration->get('SECURITY_TOKEN_PROVIDER_DEFAULT_PUBLIC');
        if (($key === null || $key === '') && $algorithm === 'HS256') {
            $key = $this->configuration->get('SECURITY_TOKEN_PROVIDER_DEFAULT_SECRET');
        }
        if (!is_string($key) || $key === '') {
            throw new \UnexpectedValueException('A verification key is required for signed userinfo.');
        }
        $key = $this->readKey($key);
        if (str_starts_with($algorithm, 'HS') && preg_match('/-----BEGIN [A-Z0-9 ]+-----/', $key) === 1) {
            throw new \UnexpectedValueException('A PEM verification key requires an asymmetric signing algorithm.');
        }

        return (array) JWT::decode($jwt, new Key($key, $algorithm));
    }

    private function readKey(string $value): string
    {
        if (is_file($value)) {
            $contents = file_get_contents($value);
            if ($contents !== false && $contents !== '') {
                return $contents;
            }
        } elseif (strncasecmp($value, 'file://', 7) !== 0) {
            return $value;
        }

        throw new \UnexpectedValueException('Unable to read the userinfo verification key file.');
    }
}
