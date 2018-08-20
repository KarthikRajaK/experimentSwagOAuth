<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Data;

use Shopware\Core\Checkout\Customer\CustomerDefinition;
use Shopware\Core\Framework\ORM\EntityDefinition;
use Shopware\Core\Framework\ORM\Field\FkField;
use Shopware\Core\Framework\ORM\Field\IdField;
use Shopware\Core\Framework\ORM\Field\ReferenceVersionField;
use Shopware\Core\Framework\ORM\Field\StringField;
use Shopware\Core\Framework\ORM\Field\TenantIdField;
use Shopware\Core\Framework\ORM\Field\VersionField;
use Shopware\Core\Framework\ORM\FieldCollection;
use Shopware\Core\Framework\ORM\Write\Flag\PrimaryKey;
use Shopware\Core\Framework\ORM\Write\Flag\Required;

class OAuthClientDefinition extends EntityDefinition
{
    public static function getSQLDefinition(): string
    {
        return <<<SQL
            CREATE TABLE `swag_oauth_client` (
              `id` BINARY(16) NOT NULL,
              `tenant_id` BINARY(16) NOT NULL,
              `version_id` BINARY(16) NOT NULL,
              `client_id` VARCHAR(250) NOT NULL,
              `client_secret` VARCHAR(250) NOT NULL,
              `redirect_uri` VARCHAR(2000),
              `grant_types` VARCHAR(80),
              `customer_id` BINARY(16) NOT NULL,
              `customer_tenant_id` BINARY(16) NOT NULL,
              `customer_version_id` BINARY(16) NOT NULL,
              PRIMARY KEY (`id`, `version_id`, `tenant_id`),
              FOREIGN KEY (`customer_id`, `customer_version_id`, `customer_tenant_id`) REFERENCES customer (`id`, `version_id`, `tenant_id`)
                ON UPDATE CASCADE
            );
SQL;
    }

    public static function getEntityName(): string
    {
        return 'swag_oauth_client';
    }

    protected static function defineFields(): FieldCollection
    {
        return new FieldCollection(
            [
                new TenantIdField(),
                (new IdField('id', 'id'))->setFlags(new Required(), new PrimaryKey()),
                new VersionField(),

                (new StringField('client_id', 'clientId'))->setFlags(new Required()),
                (new StringField('client_secret', 'clientSecret'))->setFlags(new Required()),
                new StringField('redirect_uri', 'redirectUri'),
                new StringField('grant_types', 'grantTypes'),

                (new FkField('customer_id', 'customerId', CustomerDefinition::class))->setFlags(new Required()),
                (new ReferenceVersionField(CustomerDefinition::class))->setFlags(new Required()),
            ]
        );
    }

    public static function getStructClass(): string
    {
        return OAuthClientStruct::class;
    }
}