<?php declare(strict_types=1);

namespace SwagOAuth\OAuth;

use Shopware\Core\Checkout\CheckoutContext;
use Shopware\Core\Framework\DataAbstractionLayer\RepositoryInterface;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\Struct\Uuid;
use Shopware\Core\System\Integration\IntegrationCollection;
use Shopware\Core\System\Integration\IntegrationDefinition;
use Shopware\Core\System\Integration\IntegrationEntity;
use SwagOAuth\OAuth\Data\OAuthAccessTokenEntity;
use SwagOAuth\OAuth\Data\OAuthAuthorizationCodeDefinition;
use SwagOAuth\OAuth\Data\OAuthAuthorizationCodeEntity;
use SwagOAuth\OAuth\Data\OAuthRefreshTokenDefinition;
use SwagOAuth\OAuth\Data\OAuthRefreshTokenEntity;
use SwagOAuth\OAuth\Exception\OAuthException;
use SwagOAuth\OAuth\Exception\OAuthInvalidClientException;
use SwagOAuth\OAuth\Exception\OAuthInvalidRequestException;
use SwagOAuth\OAuth\Exception\OAuthUnsupportedGrantTypeException;
use SwagOAuth\OAuth\Request\AuthorizeRequest;
use SwagOAuth\OAuth\Request\TokenRequest;

class CustomerOAuthService
{
    const EXPIRE_IN_SECONDS = 3600;

    /** @var RepositoryInterface */
    private $integrationRepository;

    /** @var RepositoryInterface */
    private $oauthAuthCodeRepository;

    /** @var RepositoryInterface */
    private $oauthRefreshTokenRepository;

    /** @var RepositoryInterface */
    private $oauthAccessTokenRepository;

    /** @var JWTFactory */
    private $JWTFactory;

    public function __construct(
        RepositoryInterface $integrationRepository,
        RepositoryInterface $oauthAuthCodeRepository,
        RepositoryInterface $oauthRefreshTokenRepository,
        RepositoryInterface $oauthAccessTokenRepository,
        JWTFactory $JWTFactory
    ) {
        $this->integrationRepository = $integrationRepository;
        $this->oauthAuthCodeRepository = $oauthAuthCodeRepository;
        $this->oauthRefreshTokenRepository = $oauthRefreshTokenRepository;
        $this->oauthAccessTokenRepository = $oauthAccessTokenRepository;
        $this->JWTFactory = $JWTFactory;
    }

    public function generateRedirectUri(
        OAuthAuthorizationCodeEntity $authCode,
        AuthorizeRequest $authorizeRequest
    ): string {
        $responseData = [
            'code' => $authCode->getAuthorizationCode(),
            'state' => $authorizeRequest->getState(),
        ];

        $callbackUrl = sprintf('%s?%s', $authorizeRequest->getRedirectUri(), http_build_query($responseData));

        return $callbackUrl;
    }

    /**
     * @throws OAuthInvalidRequestException
     */
    public function createAuthCode(
        CheckoutContext $checkoutContext,
        AuthorizeRequest $authorizeRequest,
        string $contextToken
    ): OAuthAuthorizationCodeEntity {
        if (!$authorizeRequest->getIntegrationId()){
            throw new OAuthInvalidRequestException();
        }

        $code = Uuid::uuid4()->getHex();

        $expires = new \DateTime();
        $expires->modify('+30 second');
        $data = [
            'id' => Uuid::uuid4()->getHex(),
            'authorizationCode' => $code,
            'integrationId' => $authorizeRequest->getIntegrationId(),
            'expires' => $expires,
            'contextToken' => $contextToken,
        ];

        $this->oauthAuthCodeRepository->create([$data], $checkoutContext->getContext());

        return (new OAuthAuthorizationCodeEntity())->assign($data);
    }

    /**
     * @throws OAuthInvalidClientException
     */
    public function checkClientValid(TokenRequest $tokenRequest, CheckoutContext $context): void
    {
        if (!$tokenRequest->getClientId() || !$tokenRequest->getClientSecret()) {
            throw new OAuthInvalidClientException();
        }

        $integration = $this->getIntegrationByAccessKey($context, $tokenRequest->getClientId());
        if (!password_verify($tokenRequest->getClientSecret(), $integration->getSecretAccessKey())) {
           throw new OAuthInvalidClientException();
        }
    }

    /**
     * @throws OAuthInvalidClientException
     */
    public function getIntegrationByAccessKey(CheckoutContext $checkoutContext, string $accessKey): IntegrationEntity
    {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter(IntegrationDefinition::getEntityName() . '.accessKey', $accessKey));

        /** @var IntegrationCollection $integrations */
        $integrations = $this->integrationRepository->search($criteria, $checkoutContext->getContext());

        /** @var null|IntegrationEntity $integration */
        $integration = $integrations->first();

        if (!$integration) {
            throw new OAuthInvalidClientException();
        }

        return $integration;
    }

    /**
     * @throws OAuthInvalidRequestException
     */
    public function generateTokenAuthCode(
        CheckoutContext $checkoutContext,
        TokenRequest $tokenRequest
    ): array {
        if (!$tokenRequest->getCode()) {
            throw new OAuthInvalidRequestException();
        }

        $authCode = $this->getAuthCode($checkoutContext, $tokenRequest);
        $refreshToken = $this->createRefreshToken($checkoutContext, $authCode);
        $this->linkRefreshTokenAuthCode($checkoutContext, $authCode, $refreshToken);

        $accessToken = $this->createAccessToken($checkoutContext, $authCode->getContextToken());

        return [
            'token_type' => 'Bearer',
            'expires_in' => self::EXPIRE_IN_SECONDS,
            'expires_on' => $accessToken->getExpires()->getTimestamp(),
            'access_token' => $accessToken->getAccessToken(),
            'refresh_token' => $refreshToken->getRefreshToken(),
        ];
    }

    public function getAuthCode(
        CheckoutContext $checkoutContext,
        TokenRequest $tokenRequest
    ): OAuthAuthorizationCodeEntity {
        $criteria = new Criteria();
        $criteria->addFilter(
            new EqualsFilter(
                OAuthAuthorizationCodeDefinition::ENTITY_NAME . '.' . IntegrationDefinition::getEntityName(
                ) . '.accessKey', $tokenRequest->getClientId()
            )
        );
        $criteria->addFilter(
            new EqualsFilter(
                OAuthAuthorizationCodeDefinition::ENTITY_NAME . '.authorizationCode', $tokenRequest->getCode()
            )
        );

        $authCodes = $this->oauthAuthCodeRepository->search($criteria, $checkoutContext->getContext())->getElements();
        /** @var OAuthAuthorizationCodeEntity $authCode */
        $authCode = array_pop($authCodes);

        return $authCode;
    }

    public function createRefreshToken(
        CheckoutContext $checkoutContext,
        OAuthAuthorizationCodeEntity $authCode
    ): OAuthRefreshTokenEntity {
        $refreshToken = new OAuthRefreshTokenEntity();
        $refreshToken->setId(Uuid::uuid4()->getHex());
        $refreshToken->setRefreshToken(Uuid::uuid4()->getHex());
        $refreshToken->setIntegrationId($authCode->getIntegrationId());
        $refreshToken->setContextToken($authCode->getContextToken());

        $this->oauthRefreshTokenRepository->create([$refreshToken->jsonSerialize()], $checkoutContext->getContext());

        return $refreshToken;
    }

    public function linkRefreshTokenAuthCode(
        CheckoutContext $checkoutContext,
        OAuthAuthorizationCodeEntity $authCode,
        OAuthRefreshTokenEntity $refreshToken
    ): void {
        $data = [
            'id' => $authCode->getId(),
            'tokenId' => $refreshToken->getId(),
        ];

        $this->oauthAuthCodeRepository->update([$data], $checkoutContext->getContext());
    }

    public function createAccessToken(
        CheckoutContext $checkoutContext,
        string $contextToken
    ): OAuthAccessTokenEntity {
        $expires = new \DateTime();
        $expires->modify('+' . self::EXPIRE_IN_SECONDS . ' second');

        $accessToken = new OAuthAccessTokenEntity();
        $accessToken->setId(Uuid::uuid4()->getHex());
        $accessToken->setContextToken($contextToken);
        $accessToken->setSalesChannel($checkoutContext->getSalesChannel());
        $accessToken->setSalesChannelId($checkoutContext->getSalesChannel()->getId());
        $accessToken->setExpires($expires);

        $accessTokenString = $this->JWTFactory->generateToken(
            $accessToken,
            $checkoutContext->getContext(),
            self::EXPIRE_IN_SECONDS
        );

        $accessToken->setAccessToken($accessTokenString);

        $this->oauthAccessTokenRepository->create([$accessToken->jsonSerialize()], $checkoutContext->getContext());

        return $accessToken;
    }

    public function generateTokenRefreshToken(
        CheckoutContext $checkoutContext,
        TokenRequest $tokenRequest
    ): array {
        $criteria = new Criteria();
        $criteria->addFilter(
            new EqualsFilter(
                OAuthRefreshTokenDefinition::ENTITY_NAME . '.refreshToken', $tokenRequest->getRefreshToken()
            )
        );

        /** @var OAuthRefreshTokenEntity $refreshToken */
        $refreshToken = $this->oauthRefreshTokenRepository->search($criteria, $checkoutContext->getContext())->first();

        $accessToken = $this->createAccessToken($checkoutContext, $refreshToken->getContextToken());

        return [
            'token_type' => 'Bearer',
            'expires_in' => self::EXPIRE_IN_SECONDS,
            'expires_on' => $accessToken->getExpires()->getTimestamp(),
            'access_token' => $accessToken->getAccessToken(),
        ];
    }

    /**
     * @throws OAuthException
     */
    public function createTokenData(CheckoutContext $checkoutContext, TokenRequest $tokenRequest): array {
        if (!$tokenRequest->getGrantType()) {
            throw new OAuthUnsupportedGrantTypeException();
        }

        switch (true) {
            case $tokenRequest->getGrantType() === 'authorization_code':
                return $this->generateTokenAuthCode($checkoutContext, $tokenRequest);
            case $tokenRequest->getGrantType() === 'refresh_token':
                return $this->generateTokenRefreshToken($checkoutContext, $tokenRequest);
            default:
                throw new OAuthUnsupportedGrantTypeException();
        }
    }
}