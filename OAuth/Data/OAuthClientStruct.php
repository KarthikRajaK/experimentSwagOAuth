<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Data;

use Shopware\Core\Framework\ORM\Entity;

class OAuthClientStruct extends Entity
{
    /**
     * @var string
     */
    protected $clientId;

    /**
     * @var null|string
     */
    protected $redirectUri;

    /**
     * @var null|string
     */
    protected $grantTypes;

    /**
     * @var string
     */
    protected $customerId;

    /**
     * @var string
     */
    protected $clientSecret;

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
     * @return null|string
     */
    public function getGrantTypes(): ?string
    {
        return $this->grantTypes;
    }

    /**
     * @param null|string $grantTypes
     */
    public function setGrantTypes(?string $grantTypes): void
    {
        $this->grantTypes = $grantTypes;
    }

    /**
     * @return string
     */
    public function getClientSecret(): string
    {
        return $this->clientSecret;
    }

    /**
     * @param string $clientSecret
     */
    public function setClientSecret(string $clientSecret): void
    {
        $this->clientSecret = $clientSecret;
    }
}