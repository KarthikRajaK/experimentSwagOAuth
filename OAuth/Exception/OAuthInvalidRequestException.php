<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Exception;

class OAuthInvalidRequestException extends OAuthException
{
    protected $code = 'invalid_request';
    protected $message = 'The request is missing a parameter so the server can’t proceed with the request. '
            .'This may also be returned if the request includes an unsupported parameter or repeats a parameter.';
}