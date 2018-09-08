<?php declare(strict_types=1);

namespace SwagOAuth;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DBALException;
use Shopware\Core\Framework\Plugin\Context\InstallContext;
use Shopware\Core\Framework\Plugin\Context\UninstallContext;
use Shopware\Core\Framework\Plugin;
use SwagOAuth\OAuth\Data\OAuthAccessTokenDefinition;
use SwagOAuth\OAuth\Data\OAuthAuthorizationCodeDefinition;
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
        /** @var Connection $connection */
        $connection = $this->container->get(Connection::class);
        $sql = file_get_contents($this->getPath() . '/schema.sql');

        $connection->beginTransaction();
        try {
            $connection->executeUpdate($sql);
        } catch (DBALException $e) {
            $connection->rollBack();
            throw $e;
        }
    }

    public function uninstall(UninstallContext $context)
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
        $dbal->exec('DROP TABLE IF EXISTS `' . OAuthAccessTokenDefinition::getEntityName() .'`;');
        $dbal->exec('DROP TABLE IF EXISTS `' . OAuthAuthorizationCodeDefinition::getEntityName() .'`;');
        $dbal->exec('DROP TABLE IF EXISTS `' . OAuthRefreshTokenDefinition::getEntityName() .'`;');
    }
}