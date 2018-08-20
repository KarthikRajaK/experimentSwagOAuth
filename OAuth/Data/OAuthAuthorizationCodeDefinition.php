<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Data;

use Shopware\Core\Framework\ORM\EntityDefinition;
use Shopware\Core\Framework\ORM\Field\DateField;
use Shopware\Core\Framework\ORM\Field\FkField;
use Shopware\Core\Framework\ORM\Field\IdField;
use Shopware\Core\Framework\ORM\Field\LongTextField;
use Shopware\Core\Framework\ORM\Field\ManyToOneAssociationField;
use Shopware\Core\Framework\ORM\Field\ReferenceVersionField;
use Shopware\Core\Framework\ORM\Field\StringField;
use Shopware\Core\Framework\ORM\Field\TenantIdField;
use Shopware\Core\Framework\ORM\Field\VersionField;
use Shopware\Core\Framework\ORM\FieldCollection;
use Shopware\Core\Framework\ORM\Write\Flag\PrimaryKey;
use Shopware\Core\Framework\ORM\Write\Flag\Required;

class OAuthAuthorizationCodeDefinition extends EntityDefinition
{
    public static function getSQLDefinition(): string
    {
        return <<<SQL
            CREATE TABLE `swag_oauth_authorization_code` (
              `id` BINARY(16) NOT NULL,
              `tenant_id` BINARY(16) NOT NULL,
              `version_id` BINARY(16) NOT NULL,
              `authorization_code` VARCHAR(250) NOT NULL,
              `swag_oauth_client_id` BINARY(16) NOT NULL,
              `swag_oauth_client_version_id` BINARY(16) NOT NULL,
              `swag_oauth_client_tenant_id` BINARY(16) NOT NULL,
              `redirect_uri` VARCHAR(2000),
              `expires` DATETIME(3) NOT NULL,
              `swag_oauth_refresh_token_id` BINARY(16),
              `swag_oauth_refresh_token_version_id` BINARY(16),
              `swag_oauth_refresh_token_tenant_id` BINARY(16),
              `sw_x_context_token` VARCHAR(2000) NOT NULL,
              PRIMARY KEY (`id`, `version_id`, `tenant_id`),
              FOREIGN KEY (`swag_oauth_client_id`, `swag_oauth_client_version_id`,  `swag_oauth_client_tenant_id`) REFERENCES swag_oauth_client(`id`, `version_id`, `tenant_id`)
                ON UPDATE CASCADE,
              FOREIGN KEY (`swag_oauth_refresh_token_id`, `swag_oauth_refresh_token_version_id`, `swag_oauth_refresh_token_tenant_id`) REFERENCES swag_oauth_refresh_token(`id`, `version_id`, `tenant_id`)
                ON UPDATE CASCADE
            );
SQL;
    }

    public static function getEntityName(): string
    {
        return 'swag_oauth_authorization_code';
    }

    public static function getStructClass(): string
    {
        return OAuthAuthorizationCodeStruct::class;
    }

    protected static function defineFields(): FieldCollection
    {
        return new FieldCollection(
            [
                new TenantIdField(),
                (new IdField('id', 'id'))->setFlags(new PrimaryKey(), new Required()),
                new VersionField(),

                (new StringField('authorization_code', 'authorizationCode'))->setFlags(new Required()),

                (new FkField('swag_oauth_client_id', 'clientId', OAuthClientDefinition::class))->setFlags(
                    new Required()
                ),
                (new ReferenceVersionField(OAuthClientDefinition::class))->setFlags(new Required()),

                new LongTextField('redirect_uri', 'redirectUri'),
                (new DateField('expires', 'expires'))->setFlags(new Required()),

                new FkField('swag_oauth_refresh_token_id', 'tokenId', OAuthRefreshTokenDefinition::class),
                new ReferenceVersionField(OAuthRefreshTokenDefinition::class),

                (new LongTextField('sw_x_context_token', 'swXContextToken'))->setFlags(new Required()),

                new ManyToOneAssociationField('client', 'swag_oauth_client_id', OAuthClientDefinition::class, true),
                new ManyToOneAssociationField('token', 'swag_oauth_token_id', OAuthRefreshTokenDefinition::class, false),
            ]
        );
    }
}