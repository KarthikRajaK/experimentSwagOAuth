<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Data;

use Shopware\Core\Framework\ORM\EntityDefinition;
use Shopware\Core\Framework\ORM\Field\DateField;
use Shopware\Core\Framework\ORM\Field\FkField;
use Shopware\Core\Framework\ORM\Field\IdField;
use Shopware\Core\Framework\ORM\Field\LongTextField;
use Shopware\Core\Framework\ORM\Field\ManyToOneAssociationField;
use Shopware\Core\Framework\ORM\Field\StringField;
use Shopware\Core\Framework\ORM\Field\TenantIdField;
use Shopware\Core\Framework\ORM\FieldCollection;
use Shopware\Core\Framework\ORM\Write\Flag\PrimaryKey;
use Shopware\Core\Framework\ORM\Write\Flag\Required;
use Shopware\Core\System\Integration\IntegrationDefinition;

class OAuthAuthorizationCodeDefinition extends EntityDefinition
{
    const ENTITY_NAME = 'swag_oauth_authorization_code';

    public static function getEntityName(): string
    {
        return self::ENTITY_NAME;
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

                (new StringField('authorization_code', 'authorizationCode'))->setFlags(new Required()),

                (new FkField('integration_id', 'integrationId', IntegrationDefinition::class))->setFlags(
                    new Required()
                ),

                new LongTextField('redirect_uri', 'redirectUri'),
                (new DateField('expires', 'expires'))->setFlags(new Required()),

                new FkField('swag_oauth_refresh_token_id', 'tokenId', OAuthRefreshTokenDefinition::class),

                (new StringField('context_token', 'contextToken'))->setFlags(new Required()),

                new ManyToOneAssociationField('integration', 'integration_id', IntegrationDefinition::class, true),
                new ManyToOneAssociationField('token', 'swag_oauth_token_id', OAuthRefreshTokenDefinition::class, false),
            ]
        );
    }
}