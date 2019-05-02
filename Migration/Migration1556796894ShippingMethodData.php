<?php declare(strict_types=1);

namespace SwagOAuth\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

class Migration1556796894ShippingMethodData extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1556796894;
    }

    public function update(Connection $connection): void
    {
        $connection->exec('ALTER TABLE swag_oauth_access_token ADD COLUMN created_at DATETIME(3), ADD COLUMN updated_at DATETIME(3)');
        $connection->exec('ALTER TABLE swag_oauth_refresh_token ADD COLUMN created_at DATETIME(3), ADD COLUMN updated_at DATETIME(3)');
        $connection->exec('ALTER TABLE swag_oauth_authorization_code ADD COLUMN created_at DATETIME(3), ADD COLUMN updated_at DATETIME(3)');
    }

    public function updateDestructive(Connection $connection): void
    {
        // nth
    }
}
