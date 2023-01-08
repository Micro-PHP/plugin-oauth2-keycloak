<?php

declare(strict_types=1);

/**
 * This file is part of the Micro framework package.
 *
 * (c) Stanislau Komar <head.trackingsoft@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Micro\Plugin\OAuth2\Client\Keycloak;

use League\OAuth2\Client\Provider\AbstractProvider;
use Micro\Component\DependencyInjection\Container;
use Micro\Framework\Kernel\Plugin\ConfigurableInterface;
use Micro\Framework\Kernel\Plugin\DependencyProviderInterface;
use Micro\Framework\Kernel\Plugin\PluginDependedInterface;
use Micro\Framework\Kernel\Plugin\PluginConfigurationTrait;
use Micro\Plugin\OAuth2\Client\Configuration\OAuth2ClientPluginConfigurationInterface;
use Micro\Plugin\OAuth2\Client\Keycloak\Provider\OAuth2Provider;
use Micro\Plugin\OAuth2\Client\Provider\OAuth2ClientProviderPluginInterface;
use Micro\Plugin\Security\Facade\SecurityFacadeInterface;

/**
 * @author Stanislau Komar <head.trackingsoft@gmail.com>
 *
 * @method OAuth2ClientPluginConfigurationInterface configuration()
 */
class OAuth2KeycloakProviderPlugin implements OAuth2ClientProviderPluginInterface, DependencyProviderInterface, ConfigurableInterface
{

    use PluginConfigurationTrait;

    const PROVIDER_TYPE = 'keycloak';

    /**
     * @var Container
     */
    private readonly Container $container;

    /**
     * {@inheritDoc}
     */
    public function createProvider(string $providerName): AbstractProvider
    {
        return new OAuth2Provider(
            $this->configuration()->getProviderConfiguration($providerName),
            $this->container->get(SecurityFacadeInterface::class),
        );
    }

    /**
     * {@inheritDoc}
     */
    public function getType(): string
    {
        return self::PROVIDER_TYPE;
    }

    /**
     * {@inheritDoc}
     */
    public function provideDependencies(Container $container): void
    {
        $this->container = $container;
    }
}