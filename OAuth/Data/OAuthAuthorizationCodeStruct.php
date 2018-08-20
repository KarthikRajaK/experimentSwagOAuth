<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Data;

use Shopware\Core\Framework\ORM\Entity;

class OAuthAuthorizationCodeStruct extends Entity
{
    /**
     * @var string
     */
    protected $authorizationCode;

    /**
     * @var string
     */
    protected $clientId;

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
     * @var OAuthClientStruct|null
     */
    protected $client;

    /**
     * @var string
     */
    protected $swXContextToken;

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
    public function getClientId(): string
    {
        return $this->clientId;
    }

    /**
     * @param string $clientId
     */
    public function setClientId(string $clientId): void
    {
        $this->clientId = $clientId;
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
     * @return null|OAuthClientStruct
     */
    public function getClient(): ?OAuthClientStruct
    {
        return $this->client;
    }

    /**
     * @param null|OAuthClientStruct $client
     */
    public function setClient(?OAuthClientStruct $client): void
    {
        $this->client = $client;
    }

    /**
     * @return string
     */
    public function getSwXContextToken(): string
    {
        return $this->swXContextToken;
    }

    /**
     * @param string $swXContextToken
     */
    public function setSwXContextToken(string $swXContextToken): void
    {
        $this->swXContextToken = $swXContextToken;
    }
}