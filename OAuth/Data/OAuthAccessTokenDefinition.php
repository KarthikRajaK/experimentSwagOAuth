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

class OAuthAccessTokenDefinition extends EntityDefinition
{
    public static function getEntityName(): string
    {
        return 'swag_oauth_access_token';
    }

    public static function getSQLDefinition(): string
    {
        return <<<SQL
            CREATE TABLE `swag_oauth_access_token` (
              `id`                  BINARY(16)   NOT NULL,
              `tenant_id`           BINARY(16)   NOT NULL,
              `version_id`          BINARY(16)   NOT NULL,
              `customer_id`         BINARY(16)   NOT NULL,
              `customer_tenant_id`  BINARY(16)   NOT NULL,
              `customer_version_id` BINARY(16)   NOT NULL,
              `access_token`        VARCHAR(255) NOT NULL,
              `expires`             DATETIME(3)  NOT NULL,
              PRIMARY KEY (`id`, `version_id`, `tenant_id`),
              FOREIGN KEY (`customer_id`, `customer_version_id`, `customer_tenant_id`) REFERENCES customer (`id`, `version_id`, `tenant_id`)
                ON UPDATE CASCADE
            );
SQL;
    }

    public static function getStructClass(): string
    {
        return OAuthAccessTokenStruct::class;
    }

    protected static function defineFields(): FieldCollection
    {
        return new FieldCollection(
            [
                new TenantIdField(),
                (new IdField('id', 'id'))->setFlags(new PrimaryKey(), new Required()),
                new VersionField(),

                (new FkField('customer_id', 'customerId', CustomerDefinition::class))->setFlags(new Required()),
                (new ReferenceVersionField(CustomerDefinition::class))->setFlags(new Required()),

                (new StringField('access_token', 'accessToken'))->setFlags(new Required()),
                (new DateField('expires', 'expires'))->setFlags(new Required()),
            ]
        );
    }

}