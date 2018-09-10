<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Request;

use Shopware\Core\Framework\Struct\Struct;

class TokenRequest extends Struct
{
    /** @var string */
    protected $client_id;

    /** @var string */
    protected $grant_type;

    /** @var string */
    protected $client_secret;

    /** @var string */
    protected $code;

    /** @var string */
    protected $refresh_token;

    public function getClientId(): string
    {
        return $this->client_id;
    }

    public function setClientId(string $client_id): void
    {
        $this->client_id = $client_id;
    }

    public function getGrantType(): string
    {
        return $this->grant_type;
    }

    public function setGrantType(string $grant_type): void
    {
        $this->grant_type = $grant_type;
    }

    public function getClientSecret(): string
    {
        return $this->client_secret;
    }

    public function setClientSecret(string $client_secret): void
    {
        $this->client_secret = $client_secret;
    }

    public function getCode(): string
    {
        return $this->code;
    }

    public function setCode(string $code): void
    {
        $this->code = $code;
    }

    public function getRefreshToken(): string
    {
        return $this->refresh_token;
    }

    public function setRefreshToken(string $refreshToken): void
    {
        $this->refresh_token = $refreshToken;
    }
}