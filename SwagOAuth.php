<?php declare(strict_types=1);

namespace SwagOAuth;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Plugin\Context\InstallContext;
use Shopware\Core\Framework\Plugin\Context\UninstallContext;
use Shopware\Core\Framework\Plugin;
use SwagOAuth\OAuth\Data\OAuthAccessTokenDefinition;
use SwagOAuth\OAuth\Data\OAuthAuthorizationCodeDefinition;
use SwagOAuth\OAuth\Data\OAuthClientDefinition;
use SwagOAuth\OAuth\Data\OAuthRefreshTokenDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\XmlFileLoader;

class SwagOAuth extends Plugin
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);
        $loader = new XmlFileLoader($container, new FileLocator(__DIR__ . '/DependencyInjection/'));
        $loader->load('services.xml');
    }

    public function install(InstallContext $context)
    {
        parent::install($context);

        $this->removeTables();

        /** @var Connection $dbal */
        $dbal = $this->container->get('Doctrine\DBAL\Connection');
        $dbal->exec(OAuthClientDefinition::getSQLDefinition());
        $dbal->exec(OAuthRefreshTokenDefinition::getSQLDefinition());
        $dbal->exec(OAuthAuthorizationCodeDefinition::getSQLDefinition());
        $dbal->exec(OAuthAccessTokenDefinition::getSQLDefinition());
    }

    public function uninstall(UninstallContext $context)
    {
        parent::uninstall($context);
        $this->removeTables();
    }

    private function removeTables()
    {
        /** @var Connection $dbal */
        $dbal = $this->container->get('Doctrine\DBAL\Connection');
        $dbal->exec('DROP TABLE IF EXISTS `' . OAuthAccessTokenDefinition::getEntityName() .'`;');
        $dbal->exec('DROP TABLE IF EXISTS `' . OAuthAuthorizationCodeDefinition::getEntityName() .'`;');
        $dbal->exec('DROP TABLE IF EXISTS `' . OAuthRefreshTokenDefinition::getEntityName() .'`;');
        $dbal->exec('DROP TABLE IF EXISTS `' . OAuthClientDefinition::getEntityName() .'`;');
    }
}