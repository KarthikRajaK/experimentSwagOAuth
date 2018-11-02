<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Data;

use Shopware\Core\Framework\DataAbstractionLayer\EntityDefinition;
use Shopware\Core\Framework\DataAbstractionLayer\Field\DateField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\FkField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\IdField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\LongTextField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\StringField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\TenantIdField;
use Shopware\Core\Framework\DataAbstractionLayer\FieldCollection;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Flag\PrimaryKey;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Flag\Required;
use Shopware\Core\System\SalesChannel\SalesChannelDefinition;

class OAuthAccessTokenDefinition extends EntityDefinition
{
    const ENTITY_NAME = 'swag_oauth_access_token';

    public static function getEntityName(): string
    {
        return self::ENTITY_NAME;
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

                (new StringField('context_token', 'contextToken'))->setFlags(new Required()),
                (new FkField('sales_channel_id', 'salesChannelId', SalesChannelDefinition::class))->setFlags(new Required()),
                (new LongTextField('access_token', 'accessToken'))->setFlags(new Required()),
                (new DateField('expires', 'expires'))->setFlags(new Required()),
            ]
        );
    }

}