<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Data;

use Shopware\Core\Framework\ORM\Entity;

class OAuthRefreshTokenStruct extends Entity
{
    /** @var string */
    protected $refreshToken;

    /** @var string */
    protected $integrationId;

    /** @var string */
    protected $contextToken;

    public function getRefreshToken(): string
    {
        return $this->refreshToken;
    }

    public function setRefreshToken(string $refreshToken): void
    {
        $this->refreshToken = $refreshToken;
    }

    public function getIntegrationId(): string
    {
        return $this->integrationId;
    }

    public function setIntegrationId(string $integrationId): void
    {
        $this->integrationId = $integrationId;
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