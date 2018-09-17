<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Data;

use Shopware\Core\Framework\ORM\Entity;
use Shopware\Core\System\Integration\IntegrationStruct;

class OAuthAuthorizationCodeStruct extends Entity
{
    /** @var string */
    protected $authorizationCode;

    /** @var string */
    protected $integrationId;

    /** @var string|null */
    protected $redirectUri;

    /** @var \DateTime */
    protected $expires;

    /** @var string|null */
    protected $tokenId;

    /** @var OAuthRefreshTokenStruct|null */
    protected $token;

    /** @var IntegrationStruct|null */
    protected $integration;

    /** @var string */
    protected $contextToken;

    public function getAuthorizationCode(): string
    {
        return $this->authorizationCode;
    }

    public function setAuthorizationCode(string $authorizationCode): void
    {
        $this->authorizationCode = $authorizationCode;
    }

    public function getIntegrationId(): string
    {
        return $this->integrationId;
    }

    public function setIntegrationId(string $integrationId): void
    {
        $this->integrationId = $integrationId;
    }

    public function getExpires(): \DateTime
    {
        return $this->expires;
    }

    public function setExpires(\DateTime $expires): void
    {
        $this->expires = $expires;
    }

    public function getTokenId(): ?string
    {
        return $this->tokenId;
    }

    public function setTokenId(?string $tokenId): void
    {
        $this->tokenId = $tokenId;
    }

    public function getRedirectUri(): ?string
    {
        return $this->redirectUri;
    }

    public function setRedirectUri(?string $redirectUri): void
    {
        $this->redirectUri = $redirectUri;
    }

    public function getToken(): ?OAuthRefreshTokenStruct
    {
        return $this->token;
    }

    public function setToken(?OAuthRefreshTokenStruct $token): void
    {
        $this->token = $token;
    }

    public function getIntegration(): ?IntegrationStruct
    {
        return $this->integration;
    }

    public function setIntegration(?IntegrationStruct $client): void
    {
        $this->integration = $client;
    }

    public function getContextToken(): string
    {
        return $this->contextToken;
    }

    public function setContextToken(string $contextToken): void
    {
        $this->contextToken = $contextToken;
    }
}