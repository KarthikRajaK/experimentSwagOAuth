<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Data;

use Shopware\Core\Framework\ORM\EntityDefinition;
use Shopware\Core\Framework\ORM\Field\DateField;
use Shopware\Core\Framework\ORM\Field\IdField;
use Shopware\Core\Framework\ORM\Field\LongTextField;
use Shopware\Core\Framework\ORM\Field\StringField;
use Shopware\Core\Framework\ORM\Field\TenantIdField;
use Shopware\Core\Framework\ORM\FieldCollection;
use Shopware\Core\Framework\ORM\Write\Flag\PrimaryKey;
use Shopware\Core\Framework\ORM\Write\Flag\Required;

class OAuthAccessTokenDefinition extends EntityDefinition
{
    public static function getEntityName(): string
    {
        return 'swag_oauth_access_token';
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
                (new StringField('x_sw_access_key', 'xSwAccessKey'))->setFlags(new Required()),
                (new LongTextField('access_token', 'accessToken'))->setFlags(new Required()),
                (new DateField('expires', 'expires'))->setFlags(new Required()),
            ]
        );
    }

}