<?php declare(strict_types=1);

namespace SwagOAuth\OAuth;

use Shopware\Core\Framework\DataAbstractionLayer\EntityRepositoryInterface;
use Shopware\Core\Framework\DataAbstractionLayer\Exception\InconsistentCriteriaIdsException;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Framework\Validation\DataBag\DataBag;
use Shopware\Core\System\Integration\IntegrationCollection;
use Shopware\Core\System\Integration\IntegrationDefinition;
use Shopware\Core\System\Integration\IntegrationEntity;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use SwagOAuth\OAuth\Data\OAuthAccessTokenEntity;
use SwagOAuth\OAuth\Data\OAuthAuthorizationCodeDefinition;
use SwagOAuth\OAuth\Data\OAuthAuthorizationCodeEntity;
use SwagOAuth\OAuth\Data\OAuthRefreshTokenEntity;
use SwagOAuth\OAuth\Exception\OAuthException;
use SwagOAuth\OAuth\Exception\OAuthInvalidClientException;
use SwagOAuth\OAuth\Exception\OAuthInvalidRequestException;
use SwagOAuth\OAuth\Exception\OAuthUnsupportedGrantTypeException;
use SwagOAuth\OAuth\Request\TokenRequest;

class CustomerOAuthService
{
    const EXPIRE_IN_SECONDS = 3600;

    /** @var EntityRepositoryInterface */
    private $integrationRepository;

    /** @var EntityRepositoryInterface */
    private $oauthAuthCodeRepository;

    /** @var EntityRepositoryInterface */
    private $oauthRefreshTokenRepository;

    /** @var EntityRepositoryInterface */
    private $oauthAccessTokenRepository;

    /** @var JWTFactory */
    private $JWTFactory;

    /**
     * @var IntegrationDefinition
     */
    private $integrationDefinition;

    public function __construct(
        EntityRepositoryInterface $integrationRepository,
        EntityRepositoryInterface $oauthAuthCodeRepository,
        EntityRepositoryInterface $oauthRefreshTokenRepository,
        EntityRepositoryInterface $oauthAccessTokenRepository,
        JWTFactory $JWTFactory,
        IntegrationDefinition $integrationDefinition
    ) {
        $this->integrationRepository = $integrationRepository;
        $this->oauthAuthCodeRepository = $oauthAuthCodeRepository;
        $this->oauthRefreshTokenRepository = $oauthRefreshTokenRepository;
        $this->oauthAccessTokenRepository = $oauthAccessTokenRepository;
        $this->JWTFactory = $JWTFactory;
        $this->integrationDefinition = $integrationDefinition;
    }

    public function generateRedirectUri(
        OAuthAuthorizationCodeEntity $authCode,
        DataBag $authorizeRequest
    ): string {
        $responseData = [
            'code' => $authCode->getAuthorizationCode(),
            'state' => $authorizeRequest->get('state'),
        ];

        $callbackUrl = sprintf('%s?%s', $authorizeRequest->get('redirect_uri'), http_build_query($responseData));

        return $callbackUrl;
    }

    /**
     * @throws OAuthInvalidRequestException
     */
    public function createAuthCode(
        SalesChannelContext $salesChannelContext,
        DataBag $authorizeRequest,
        string $contextToken
    ): OAuthAuthorizationCodeEntity {
        if (!$authorizeRequest->get('integrationId')){
            throw new OAuthInvalidRequestException();
        }

        $code = Uuid::randomHex();

        $expires = new \DateTime();
        $expires->modify('+30 second');
        $data = [
            'id' => Uuid::randomHex(),
            'authorizationCode' => $code,
            'integrationId' => $authorizeRequest->get('integrationId'),
            'expires' => $expires,
            'contextToken' => $contextToken,
        ];

        $this->oauthAuthCodeRepository->create([$data], $salesChannelContext->getContext());

        return (new OAuthAuthorizationCodeEntity())->assign($data);
    }

    /**
     * @throws OAuthInvalidClientException
     * @throws InconsistentCriteriaIdsException
     */
    public function checkClientValid(TokenRequest $tokenRequest, SalesChannelContext $context): void
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
     * @throws InconsistentCriteriaIdsException
     */
    public function getIntegrationByAccessKey(SalesChannelContext $salesChannelContext, string $accessKey): IntegrationEntity
    {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter($this->integrationDefinition->getEntityName() . '.accessKey', $accessKey));

        /** @var IntegrationCollection $integrations */
        $integrations = $this->integrationRepository->search($criteria, $salesChannelContext->getContext());

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
        SalesChannelContext $salesChannelContext,
        TokenRequest $tokenRequest
    ): array {
        if (!$tokenRequest->getCode()) {
            throw new OAuthInvalidRequestException();
        }

        $authCode = $this->getAuthCode($salesChannelContext, $tokenRequest);
        $refreshToken = $this->createRefreshToken($salesChannelContext, $authCode);
        $this->linkRefreshTokenAuthCode($salesChannelContext, $authCode, $refreshToken);

        $accessToken = $this->createAccessToken($salesChannelContext, $authCode->getContextToken());

        return [
            'token_type' => 'Bearer',
            'expires_in' => self::EXPIRE_IN_SECONDS,
            'expires_on' => $accessToken->getExpires()->getTimestamp(),
            'access_token' => $accessToken->getAccessToken(),
            'refresh_token' => $refreshToken->getRefreshToken(),
        ];
    }

    public function getAuthCode(
        SalesChannelContext $salesChannelContext,
        TokenRequest $tokenRequest
    ): OAuthAuthorizationCodeEntity {
        $criteria = new Criteria();
        $criteria->addFilter(
            new EqualsFilter(
                OAuthAuthorizationCodeDefinition::ENTITY_NAME . '.' . $this->integrationDefinition->getEntityName()
                . '.accessKey', $tokenRequest->getClientId()
            )
        );
        $criteria->addFilter(
            new EqualsFilter(
                'authorizationCode', $tokenRequest->getCode()
            )
        );

        $authCodes = $this->oauthAuthCodeRepository->search($criteria, $salesChannelContext->getContext())->getElements();
        /** @var OAuthAuthorizationCodeEntity $authCode */
        $authCode = array_pop($authCodes);

        return $authCode;
    }

    public function createRefreshToken(
        SalesChannelContext $salesChannelContext,
        OAuthAuthorizationCodeEntity $authCode
    ): OAuthRefreshTokenEntity {
        $refreshToken = new OAuthRefreshTokenEntity();
        $refreshToken->setUniqueIdentifier(Uuid::randomHex());
        $refreshToken->setRefreshToken(Uuid::randomHex());
        $refreshToken->setIntegrationId($authCode->getIntegrationId());
        $refreshToken->setContextToken($authCode->getContextToken());

        $this->oauthRefreshTokenRepository->create(
            [
                [
                    'id' => $refreshToken->getUniqueIdentifier(),
                    'refreshToken' => $refreshToken->getRefreshToken(),
                    'integrationId' => $refreshToken->getIntegrationId(),
                    'contextToken' => $refreshToken->getContextToken(),
                ],
            ], $salesChannelContext->getContext()
        );

        return $refreshToken;
    }

    public function linkRefreshTokenAuthCode(
        SalesChannelContext $salesChannelContext,
        OAuthAuthorizationCodeEntity $authCode,
        OAuthRefreshTokenEntity $refreshToken
    ): void {
        $data = [
            'id' => $authCode->getUniqueIdentifier(),
            'tokenId' => $refreshToken->getUniqueIdentifier(),
        ];

        $this->oauthAuthCodeRepository->update([$data], $salesChannelContext->getContext());
    }

    public function createAccessToken(
        SalesChannelContext $salesChannelContext,
        string $contextToken
    ): OAuthAccessTokenEntity {
        $expires = new \DateTime();
        $expires->modify('+' . self::EXPIRE_IN_SECONDS . ' second');

        $accessToken = new OAuthAccessTokenEntity();
        $accessToken->setUniqueIdentifier(Uuid::randomHex());
        $accessToken->setContextToken($contextToken);
        $accessToken->setSalesChannel($salesChannelContext->getSalesChannel());
        $accessToken->setSalesChannelId($salesChannelContext->getSalesChannel()->getId());
        $accessToken->setExpires($expires);

        $accessTokenString = $this->JWTFactory->generateToken(
            $accessToken,
            $salesChannelContext->getContext(),
            self::EXPIRE_IN_SECONDS
        );

        $accessToken->setAccessToken($accessTokenString);

        $this->oauthAccessTokenRepository->create(
            [
                [
                    'id' => $accessToken->getUniqueIdentifier(),
                    'contextToken' => $accessToken->getContextToken(),
                    'salesChannelId' => $accessToken->getSalesChannelId(),
                    'expires' => $accessToken->getExpires(),
                    'accessToken' => $accessToken->getAccessToken(),
                ],
            ], $salesChannelContext->getContext()
        );

        return $accessToken;
    }

    public function generateTokenRefreshToken(
        SalesChannelContext $salesChannelContext,
        TokenRequest $tokenRequest
    ): array {
        $criteria = new Criteria();
        $criteria->addFilter(
            new EqualsFilter(
                'refreshToken', $tokenRequest->getRefreshToken()
            )
        );

        /** @var OAuthRefreshTokenEntity $refreshToken */
        $refreshToken = $this->oauthRefreshTokenRepository->search($criteria, $salesChannelContext->getContext())->first();

        $accessToken = $this->createAccessToken($salesChannelContext, $refreshToken->getContextToken());

        return [
            'token_type' => 'Bearer',
            'expires_in' => self::EXPIRE_IN_SECONDS,
            'expires_on' => $accessToken->getExpires()->getTimestamp(),
            'access_token' => $accessToken->getAccessToken(),
            'refresh_token' => $tokenRequest->getRefreshToken(),
        ];
    }

    /**
     * @throws OAuthException
     */
    public function createTokenData(SalesChannelContext $salesChannelContext, TokenRequest $tokenRequest): array {
        if (!$tokenRequest->getGrantType()) {
            throw new OAuthUnsupportedGrantTypeException('invalid grant type');
        }

        switch (true) {
            case $tokenRequest->getGrantType() === 'authorization_code':
                return $this->generateTokenAuthCode($salesChannelContext, $tokenRequest);
            case $tokenRequest->getGrantType() === 'refresh_token':
                return $this->generateTokenRefreshToken($salesChannelContext, $tokenRequest);
            default:
                throw new OAuthUnsupportedGrantTypeException('invalid grant type');
        }
    }
}