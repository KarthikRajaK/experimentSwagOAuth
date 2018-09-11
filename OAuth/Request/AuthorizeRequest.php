<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Request;

use Shopware\Storefront\Page\Account\LoginRequest;

class AuthorizeRequest extends LoginRequest
{
    /** @var ?string */
    protected $integrationId;

    /** @var ?string */
    protected $state;

    /** @var ?string */
    protected $redirect_uri;

    /** @var ?string */
    protected $loginError;

    /** @var ?string */
    protected $client_id;

    /** @var ?string */
    protected $clientSecret;

    public function getIntegrationId(): ?string
    {
        return $this->integrationId;
    }

    public function setIntegrationId(?string $integrationId): void
    {
        $this->integrationId = $integrationId;
    }

    public function getState(): ?string
    {
        return $this->state;
    }

    public function setState(?string $state): void
    {
        $this->state = $state;
    }

    public function getRedirectUri(): ?string
    {
        return $this->redirect_uri;
    }

    public function setRedirectUri(?string $redirectUri): void
    {
        $this->redirect_uri = $redirectUri;
    }

    public function getLoginError(): ?string
    {
        return $this->loginError;
    }

    public function setLoginError(?string $loginError): void
    {
        $this->loginError = $loginError;
    }

    public function getClientId(): ?string
    {
        return $this->client_id;
    }

    public function setClientId(?string $clientId): void
    {
        $this->client_id = $clientId;
    }

    public function getClientSecret(): ?string
    {
        return $this->clientSecret;
    }

    public function setClientSecret(?string $clientSecret): void
    {
        $this->clientSecret = $clientSecret;
    }
}