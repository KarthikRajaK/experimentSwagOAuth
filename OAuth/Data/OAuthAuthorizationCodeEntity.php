<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Data;

use Shopware\Core\Framework\DataAbstractionLayer\Entity;
use Shopware\Core\System\Integration\IntegrationEntity;

class OAuthAuthorizationCodeEntity extends Entity
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

    /** @var OAuthRefreshTokenEntity|null */
    protected $token;

    /** @var IntegrationEntity|null */
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

    public function getToken(): ?OAuthRefreshTokenEntity
    {
        return $this->token;
    }

    public function setToken(?OAuthRefreshTokenEntity $token): void
    {
        $this->token = $token;
    }

    public function getIntegration(): ?IntegrationEntity
    {
        return $this->integration;
    }

    public function setIntegration(?IntegrationEntity $client): void
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