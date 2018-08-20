<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Data;

use Shopware\Core\Framework\ORM\Entity;

class OAuthAccessTokenStruct extends Entity
{
    /**
     * @var string
     */
    protected $customerId;

    /**
     * @var string
     */
    protected $accessToken;

    /**
     * @var \DateTime
     */
    protected $expires;

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
     * @return string
     */
    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    /**
     * @param string $accessToken
     */
    public function setAccessToken(string $accessToken): void
    {
        $this->accessToken = $accessToken;
    }

    /**
     * @param \DateTime $expires
     */
    public function setExpires(\DateTime $expires): void
    {
        $this->expires = $expires;
    }

    /**
     * @return \DateTime
     */
    public function getExpires(): \DateTime
    {
        return $this->expires;
    }
}