<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Data;

use Shopware\Core\Framework\DataAbstractionLayer\EntityDefinition;
use Shopware\Core\Framework\DataAbstractionLayer\Field\FkField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\PrimaryKey;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\Required;
use Shopware\Core\Framework\DataAbstractionLayer\Field\IdField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\StringField;

use Shopware\Core\Framework\DataAbstractionLayer\FieldCollection;
use Shopware\Core\System\Integration\IntegrationDefinition;

class OAuthRefreshTokenDefinition extends EntityDefinition
{
    const ENTITY_NAME = 'swag_oauth_refresh_token';

    public static function getEntityName(): string
    {
        return self::ENTITY_NAME;
    }

    public static function getEntityClass(): string
    {
        return OAuthRefreshTokenEntity::class;
    }

    protected static function defineFields(): FieldCollection
    {
        return new FieldCollection(
            [

                (new IdField('id', 'id'))->setFlags(new PrimaryKey(), new Required()),

                (new StringField('refresh_token', 'refreshToken'))->setFlags(new Required()),

                (new FkField('integration_id', 'integrationId', IntegrationDefinition::class))->setFlags(
                    new Required()
                ),

                (new StringField('context_token', 'contextToken'))->setFlags(new Required()),
            ]
        );
    }
}