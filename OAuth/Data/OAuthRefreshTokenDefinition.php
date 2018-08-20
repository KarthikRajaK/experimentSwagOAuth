<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Data;

use Shopware\Core\Checkout\Customer\CustomerDefinition;
use Shopware\Core\Framework\ORM\EntityDefinition;
use Shopware\Core\Framework\ORM\Field\DateField;
use Shopware\Core\Framework\ORM\Field\FkField;
use Shopware\Core\Framework\ORM\Field\IdField;
use Shopware\Core\Framework\ORM\Field\ReferenceVersionField;
use Shopware\Core\Framework\ORM\Field\StringField;
use Shopware\Core\Framework\ORM\Field\TenantIdField;
use Shopware\Core\Framework\ORM\Field\VersionField;
use Shopware\Core\Framework\ORM\FieldCollection;
use Shopware\Core\Framework\ORM\Write\Flag\PrimaryKey;
use Shopware\Core\Framework\ORM\Write\Flag\Required;

class OAuthRefreshTokenDefinition extends EntityDefinition
{
    public static function getSQLDefinition(): string
    {
        return <<<SQL
            CREATE TABLE `swag_oauth_refresh_token` (
              `id` BINARY(16) NOT NULL,
              `tenant_id` BINARY(16) NOT NULL,
              `version_id` BINARY(16) NOT NULL,
              `refresh_token` VARCHAR(250) NOT NULL,
              `swag_oauth_client_id` BINARY(16) NOT NULL,
              `swag_oauth_client_version_id` BINARY(16) NOT NULL,
              `swag_oauth_client_tenant_id` BINARY(16) NOT NULL,
              `customer_id` BINARY(16) NOT NULL,
              `customer_tenant_id` BINARY(16) NOT NULL,
              `customer_version_id` BINARY(16) NOT NULL,
              `expires` DATETIME(3),
              PRIMARY KEY (`id`, `version_id`, `tenant_id`),
              FOREIGN KEY (`swag_oauth_client_id`, `swag_oauth_client_version_id`, `swag_oauth_client_tenant_id`) REFERENCES swag_oauth_client (`id`, `version_id`, `tenant_id`)
                ON UPDATE CASCADE,
              FOREIGN KEY (`customer_id`, `customer_version_id`, `customer_tenant_id`) REFERENCES customer (`id`, `version_id`, `tenant_id`)
                ON UPDATE CASCADE
            );
SQL;
    }

    public static function getEntityName(): string
    {
        return 'swag_oauth_refresh_token';
    }

    protected static function defineFields(): FieldCollection
    {
        return new FieldCollection(
            [
                new TenantIdField(),
                (new IdField('id', 'id'))->setFlags(new PrimaryKey(), new Required()),
                new VersionField(),

                (new StringField('refresh_token', 'refreshToken'))->setFlags(new Required()),

                (new FkField('swag_oauth_client_id', 'clientId', OAuthClientDefinition::class))->setFlags(
                    new Required()
                ),
                (new ReferenceVersionField(OAuthClientDefinition::class))->setFlags(new Required()),

                (new FkField('customer_id', 'customerId', CustomerDefinition::class))->setFlags(new Required()),
                (new ReferenceVersionField(CustomerDefinition::class))->setFlags(new Required()),

                new DateField('expires', 'expires'),
            ]
        );
    }

    public static function getStructClass(): string
    {
        return OAuthRefreshTokenStruct::class;
    }
}