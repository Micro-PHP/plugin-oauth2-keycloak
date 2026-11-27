<?php

declare(strict_types=1);

use Micro\Component\DependencyInjection\Container;
use Micro\Framework\Kernel\Boot\ConfigurationProviderBootLoader;
use Micro\Framework\Kernel\Boot\DependencyProviderBootLoader;
use Micro\Framework\Kernel\Kernel;
use Micro\Framework\Kernel\KernelInterface;
use Micro\Plugin\OAuth2\Client\Keycloak\OAuth2KeycloakProviderPlugin;
use Micro\Plugin\OAuth2\Client\OAuth2ClientPlugin;

return static function (array $settings = []): Kernel {
    $container = new Container();
    $kernel = new Kernel([OAuth2ClientPlugin::class, OAuth2KeycloakProviderPlugin::class], [
        new ConfigurationProviderBootLoader($settings + [
            'MICRO_OAUTH2_PORTAL_TYPE' => 'Keycloak',
            'MICRO_OAUTH2_PORTAL_CLIENT_ID' => 'portal-app',
            'MICRO_OAUTH2_PORTAL_CLIENT_SECRET' => 'client-secret',
            'MICRO_OAUTH2_PORTAL_CLIENT_URL_AUTHORIZATION' => 'https://identity.example/',
            'MICRO_OAUTH2_PORTAL_CLIENT_URL_REDIRECT' => 'https://portal.example/callback',
            'MICRO_OAUTH2_PORTAL_REALM' => 'partners',
        ]),
        new DependencyProviderBootLoader($container),
    ], $container);
    $container->register(KernelInterface::class, static fn () => $kernel);
    $kernel->run();

    return $kernel;
};
