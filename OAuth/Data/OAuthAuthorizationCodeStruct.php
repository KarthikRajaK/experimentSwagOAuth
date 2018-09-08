<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Data;

use Shopware\Core\Framework\ORM\Entity;
use Shopware\Core\System\Integration\IntegrationStruct;

class OAuthAuthorizationCodeStruct extends Entity
{
    /**
     * @var string
     */
    protected $authorizationCode;

    /**
     * @var string
     */
    protected $integrationId;

    /**
     * @var string|null
     */
    protected $redirectUri;

    /**
     * @var \DateTime
     */
    protected $expires;

    /**
     * @var string|null
     */
    protected $tokenId;

    /**
     * @var OAuthRefreshTokenStruct|null
     */
    protected $token;

    /**
     * @var IntegrationStruct|null
     */
    protected $integration;

    /**
     * @var string
     */
    protected $contextToken;

    /**
     * @return string
     */
    public function getAuthorizationCode(): string
    {
        return $this->authorizationCode;
    }

    /**
     * @param string $authorizationCode
     */
    public function setAuthorizationCode(string $authorizationCode): void
    {
        $this->authorizationCode = $authorizationCode;
    }

    /**
     * @return string
     */
    public function getIntegrationId(): string
    {
        return $this->integrationId;
    }

    /**
     * @param string $integrationId
     */
    public function setIntegrationId(string $integrationId): void
    {
        $this->integrationId = $integrationId;
    }

    /**
     * @return \DateTime
     */
    public function getExpires(): \DateTime
    {
        return $this->expires;
    }

    /**
     * @param \DateTime $expires
     */
    public function setExpires(\DateTime $expires): void
    {
        $this->expires = $expires;
    }

    /**
     * @return null|string
     */
    public function getTokenId(): ?string
    {
        return $this->tokenId;
    }

    /**
     * @param null|string $tokenId
     */
    public function setTokenId(?string $tokenId): void
    {
        $this->tokenId = $tokenId;
    }

    /**
     * @return null|string
     */
    public function getRedirectUri(): ?string
    {
        return $this->redirectUri;
    }

    /**
     * @param null|string $redirectUri
     */
    public function setRedirectUri(?string $redirectUri): void
    {
        $this->redirectUri = $redirectUri;
    }

    /**
     * @return null|OAuthRefreshTokenStruct
     */
    public function getToken(): ?OAuthRefreshTokenStruct
    {
        return $this->token;
    }

    /**
     * @param null|OAuthRefreshTokenStruct $token
     */
    public function setToken(?OAuthRefreshTokenStruct $token): void
    {
        $this->token = $token;
    }

    /**
     * @return null|IntegrationStruct
     */
    public function getIntegration(): ?IntegrationStruct
    {
        return $this->integration;
    }

    /**
     * @param null|IntegrationStruct $client
     */
    public function setIntegration(?IntegrationStruct $client): void
    {
        $this->integration = $client;
    }

    /**
     * @return string
     */
    public function getContextToken(): string
    {
        return $this->contextToken;
    }

    /**
     * @param string $contextToken
     */
    public function setContextToken(string $contextToken): void
    {
        $this->contextToken = $contextToken;
    }
}