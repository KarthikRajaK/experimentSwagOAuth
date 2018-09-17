<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Exception;

use Shopware\Core\Framework\ShopwareHttpException;

abstract class OAuthException extends ShopwareHttpException
{
    protected $code = 'ERROR-OAUTH-TOKEN';

    public function getErrorData(): array
    {
        return [
            'error' => $this->code,
            'error_description' => $this->message
        ];
    }
}