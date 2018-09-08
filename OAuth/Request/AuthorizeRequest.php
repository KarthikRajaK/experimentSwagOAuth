<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Request;

use Shopware\Storefront\Page\Account\LoginRequest;

class AuthorizeRequest extends LoginRequest
{
    /** @var string */
    protected $integrationId;

    /** @var string */
    protected $state;

    /** @var string */
    protected $redirectUri;

    /** @var string */
    protected $loginError;

    public function getIntegrationId(): string
    {
        return $this->integrationId;
    }

    public function setIntegrationId(string $integrationId): void
    {
        $this->integrationId = $integrationId;
    }

    public function getState(): string
    {
        return $this->state;
    }

    public function setState(string $state): void
    {
        $this->state = $state;
    }

    public function getRedirectUri(): string
    {
        return $this->redirectUri;
    }

    public function setRedirectUri(string $redirectUri): void
    {
        $this->redirectUri = $redirectUri;
    }

    public function getLoginError(): string
    {
        return $this->loginError;
    }

    public function setLoginError(string $loginError): void
    {
        $this->loginError = $loginError;
    }
}