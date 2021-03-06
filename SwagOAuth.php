<?php declare(strict_types=1);

namespace SwagOAuth;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Plugin;
use Shopware\Core\Framework\Plugin\Context\UninstallContext;
use SwagOAuth\OAuth\Data\OAuthAccessTokenDefinition;
use SwagOAuth\OAuth\Data\OAuthAuthorizationCodeDefinition;
use SwagOAuth\OAuth\Data\OAuthRefreshTokenDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\XmlFileLoader;

class SwagOAuth extends Plugin
{
    public function build(ContainerBuilder $container): void
    {
        parent::build($container);
        $loader = new XmlFileLoader($container, new FileLocator(__DIR__ . '/DependencyInjection/'));
        $loader->load('services.xml');
    }

    public function uninstall(UninstallContext $context): void
    {
        if ($context->keepUserData()) {
            parent::uninstall($context);

            return;
        }

        $this->removeTables();
        parent::uninstall($context);
    }

    private function removeTables()
    {
        /** @var Connection $dbal */
        $dbal = $this->container->get('Doctrine\DBAL\Connection');
        $dbal->exec('DROP TABLE IF EXISTS `' . OAuthAccessTokenDefinition::getEntityName() . '`;');
        $dbal->exec('DROP TABLE IF EXISTS `' . OAuthAuthorizationCodeDefinition::getEntityName() . '`;');
        $dbal->exec('DROP TABLE IF EXISTS `' . OAuthRefreshTokenDefinition::getEntityName() . '`;');
    }
}
