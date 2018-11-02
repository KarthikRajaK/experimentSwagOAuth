<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Data;

use Shopware\Core\Framework\DataAbstractionLayer\Entity;
use Shopware\Core\System\SalesChannel\SalesChannelStruct;

class OAuthAccessTokenStruct extends Entity
{
    /** @var string */
    protected $contextToken;

    /** @var string */
    protected $accessToken;

    /** @var string */
    protected $salesChannelId;

    /** @var SalesChannelStruct */
    protected $salesChannel;

    /** @var \DateTime */
    protected $expires;

    public function getContextToken(): string
    {
        return $this->contextToken;
    }

    public function setContextToken(string $contextToken): void
    {
        $this->contextToken = $contextToken;
    }

    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    public function setAccessToken(string $accessToken): void
    {
        $this->accessToken = $accessToken;
    }

    public function getSalesChannelId(): string
    {
        return $this->salesChannelId;
    }

    public function setSalesChannelId(string $salesChannelId): void
    {
        $this->salesChannelId = $salesChannelId;
    }

    public function getSalesChannel(): ?SalesChannelStruct
    {
        return $this->salesChannel;
    }

    public function setSalesChannel(?SalesChannelStruct $salesChannel): void
    {
        $this->salesChannel = $salesChannel;
    }

    public function getExpires(): \DateTime
    {
        return $this->expires;
    }

    public function setExpires(\DateTime $expires): void
    {
        $this->expires = $expires;
    }
}