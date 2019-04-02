<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Exception;

class OAuthUnsupportedGrantTypeException extends OAuthException
{
    protected $code = 'unsupported_grant_type';

    public function getErrorCode(): string
    {
        return $this->code;
    }
}