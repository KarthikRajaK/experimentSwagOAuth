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
    protected $integrationId;

    /**
     * @var string
     */
    protected $contextToken;

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
     * @return string
     */
    public function getContextToken(): string
    {
        return $this->contextToken;
    }

    /**
     * @param string $customerId
     */
    public function setContextToken(string $contextToken): void
    {
        $this->contextToken = $contextToken;
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