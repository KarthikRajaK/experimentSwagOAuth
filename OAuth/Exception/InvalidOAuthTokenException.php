<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Exception;

use Symfony\Component\HttpFoundation\Response;

class InvalidOAuthTokenException extends OAuthException
{
    protected $code = 'INVALID-OAUTH-TOKEN';

    public function __construct(string $token)
    {
        $message = sprintf('The provided token %s is invalid and the authorization could not be processed.', $token);

        parent::__construct($message);
    }

    public function getStatusCode(): int
    {
        return Response::HTTP_BAD_REQUEST;
    }

    public function getErrorCode(): string
    {
        return $this->code;
    }
}