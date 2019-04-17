<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Data;

use Shopware\Core\Framework\DataAbstractionLayer\EntityDefinition;
use Shopware\Core\Framework\DataAbstractionLayer\Field\DateField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\FkField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\PrimaryKey;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\Required;
use Shopware\Core\Framework\DataAbstractionLayer\Field\IdField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\LongTextField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\ManyToOneAssociationField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\StringField;
use Shopware\Core\Framework\DataAbstractionLayer\FieldCollection;
use Shopware\Core\System\Integration\IntegrationDefinition;

class OAuthAuthorizationCodeDefinition extends EntityDefinition
{
    const ENTITY_NAME = 'swag_oauth_authorization_code';

    public static function getEntityName(): string
    {
        return self::ENTITY_NAME;
    }

    public static function getEntityClass(): string
    {
        return OAuthAuthorizationCodeEntity::class;
    }

    protected static function defineFields(): FieldCollection
    {
        return new FieldCollection(
            [

                (new IdField('id', 'id'))->setFlags(new PrimaryKey(), new Required()),

                (new StringField('authorization_code', 'authorizationCode'))->setFlags(new Required()),

                (new FkField('integration_id', 'integrationId', IntegrationDefinition::class))->setFlags(new Required()),

                new LongTextField('redirect_uri', 'redirectUri'),
                (new DateField('expires', 'expires'))->setFlags(new Required()),

                new FkField('swag_oauth_refresh_token_id', 'tokenId', OAuthRefreshTokenDefinition::class),

                (new StringField('context_token', 'contextToken'))->setFlags(new Required()),

                new ManyToOneAssociationField('integration', 'integration_id', IntegrationDefinition::class),
                new ManyToOneAssociationField('token', 'swag_oauth_token_id', OAuthRefreshTokenDefinition::class, 'id', false),
            ]
        );
    }
}