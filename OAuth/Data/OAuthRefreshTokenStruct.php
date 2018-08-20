<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Data;

use Shopware\Core\Framework\ORM\Entity;

class OAuthRefreshTokenStruct extends Entity
{
    /**
     * @var string
     */
    protected $refreshToken;

    /**
     * @var string
     */
    protected $clientId;

    /**
     * @var string
     */
    protected $customerId;

    /**
     * @var null|\DateTime
     */
    protected $expires;

    /**
     * @return string
     */
    public function getRefreshToken(): string
    {
        return $this->refreshToken;
    }

    /**
     * @param string $refreshToken
     */
    public function setRefreshToken(string $refreshToken): void
    {
        $this->refreshToken = $refreshToken;
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
     * @return string
     */
    public function getCustomerId(): string
    {
        return $this->customerId;
    }

    /**
     * @param string $customerId
     */
    public function setCustomerId(string $customerId): void
    {
        $this->customerId = $customerId;
    }

    /**
     * @return \DateTime|null
     */
    public function getExpires(): ?\DateTime
    {
        return $this->expires;
    }

    /**
     * @param \DateTime|null $expires
     */
    public function setExpires(?\DateTime $expires): void
    {
        $this->expires = $expires;
    }
}