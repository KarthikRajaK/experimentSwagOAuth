<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Data;

use Shopware\Core\Framework\ORM\Entity;

class OAuthAccessTokenStruct extends Entity
{
    /**
     * @var string
     */
    protected $contextToken;

    /**
     * @var string
     */
    protected $accessToken;

    /**
     * @var \DateTime
     */
    protected $expires;

    /**
     * @var string
     */
    protected $xSwAccessKey;

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

    /**
     * @return string
     */
    public function getXSwAccessKey(): string
    {
        return $this->xSwAccessKey;
    }

    /**
     * @param string $xSwAccessKey
     */
    public function setXSwAccessKey(string $xSwAccessKey): void
    {
        $this->xSwAccessKey = $xSwAccessKey;
    }
}