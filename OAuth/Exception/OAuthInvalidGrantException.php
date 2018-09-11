<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Exception;

class OAuthInvalidGrantException extends OAuthException
{
    protected $code = 'invalid_grant';
    protected $message = 'The authorization code (or user’s password for the password grant type) is invalid or expired';
}