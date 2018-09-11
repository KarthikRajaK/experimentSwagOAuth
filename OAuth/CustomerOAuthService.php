<?php declare(strict_types=1);

namespace SwagOAuth\OAuth;

use Shopware\Core\Checkout\CheckoutContext;
use Shopware\Core\Framework\ORM\RepositoryInterface;
use Shopware\Core\Framework\ORM\Search\Criteria;
use Shopware\Core\Framework\ORM\Search\Query\MatchQuery;
use Shopware\Core\Framework\Struct\Uuid;
use Shopware\Core\System\Integration\IntegrationCollection;
use Shopware\Core\System\Integration\IntegrationDefinition;
use Shopware\Core\System\Integration\IntegrationStruct;
use SwagOAuth\OAuth\Data\OAuthAccessTokenStruct;
use SwagOAuth\OAuth\Data\OAuthAuthorizationCodeDefinition;
use SwagOAuth\OAuth\Data\OAuthAuthorizationCodeStruct;
use SwagOAuth\OAuth\Data\OAuthRefreshTokenDefinition;
use SwagOAuth\OAuth\Data\OAuthRefreshTokenStruct;
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
        OAuthAuthorizationCodeStruct $authCode,
        AuthorizeRequest $authorizeRequest
    ): string {
        $responseData = [
            'code' => $authCode->getAuthorizationCode(),
            'state' => $authorizeRequest->getState(),
        ];

        $callbackUrl = sprintf('%s?%s', $authorizeRequest->getRedirectUri(), http_build_query($responseData));

        return $callbackUrl;
    }

    public function createAuthCode(
        CheckoutContext $checkoutContext,
        AuthorizeRequest $authorizeRequest,
        string $contextToken
    ): OAuthAuthorizationCodeStruct {
        $code = UUid::uuid4()->getHex();

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

        return (new OAuthAuthorizationCodeStruct())->assign($data);
    }

    /**
     * @throws OAuthInvalidClientException
     */
    public function checkClientValid(TokenRequest $tokenRequest, CheckoutContext $context): void
    {
        $integration = $this->getIntegrationByAccessKey($context, $tokenRequest->getClientId());

        if (!($integration
            && password_verify($tokenRequest->getClientSecret(), $integration->getSecretAccessKey()))) {
           throw new OAuthInvalidClientException();
        }
    }

    /**
     * @throws OAuthInvalidClientException
     */
    public function getIntegrationByAccessKey(CheckoutContext $checkoutContext, string $accessKey): IntegrationStruct
    {
        $criteria = new Criteria();
        $criteria->addFilter(new MatchQuery(IntegrationDefinition::getEntityName() . '.accessKey', $accessKey));

        /** @var IntegrationCollection $integrations */
        $integrations = $this->integrationRepository->search($criteria, $checkoutContext->getContext());

        /** @var ?IntegrationStruct $integration */
        $integration = $integrations->first();

        if (!$integration) {
            throw new OAuthInvalidClientException();
        }

        return $integration;
    }

    public function generateTokenAuthCode(
        CheckoutContext $checkoutContext,
        TokenRequest $tokenRequest
    ): array {
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
    ): OAuthAuthorizationCodeStruct {
        $criteria = new Criteria();
        $criteria->addFilter(
            new MatchQuery(
                OAuthAuthorizationCodeDefinition::ENTITY_NAME . '.' . IntegrationDefinition::getEntityName(
                ) . '.accessKey', $tokenRequest->getClientId()
            )
        );
        $criteria->addFilter(
            new MatchQuery(
                OAuthAuthorizationCodeDefinition::ENTITY_NAME . '.authorizationCode', $tokenRequest->getCode()
            )
        );

        $authCodes = $this->oauthAuthCodeRepository->search($criteria, $checkoutContext->getContext())->getElements();
        /** @var OAuthAuthorizationCodeStruct $authCode */
        $authCode = array_pop($authCodes);

        return $authCode;
    }

    public function createRefreshToken(
        CheckoutContext $checkoutContext,
        OAuthAuthorizationCodeStruct $authCode
    ): OAuthRefreshTokenStruct {
        $refreshToken = new OAuthRefreshTokenStruct();
        $refreshToken->setId(Uuid::uuid4()->getHex());
        $refreshToken->setRefreshToken(Uuid::uuid4()->getHex());
        $refreshToken->setIntegrationId($authCode->getIntegrationId());
        $refreshToken->setContextToken($authCode->getContextToken());

        $this->oauthRefreshTokenRepository->create([$refreshToken->jsonSerialize()], $checkoutContext->getContext());

        return $refreshToken;
    }

    public function linkRefreshTokenAuthCode(
        CheckoutContext $checkoutContext,
        OAuthAuthorizationCodeStruct $authCode,
        OAuthRefreshTokenStruct $refreshToken
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
    ): OAuthAccessTokenStruct {
        $expires = new \DateTime();
        $expires->modify('+' . self::EXPIRE_IN_SECONDS . ' second');

        $accessToken = new OAuthAccessTokenStruct();
        $accessToken->setId(Uuid::uuid4()->getHex());
        $accessToken->setContextToken($contextToken);
        $accessToken->setSalesChannel($checkoutContext->getSalesChannel());

        $accessTokenString = $this->JWTFactory->generateToken(
            $accessToken,
            $checkoutContext->getContext(),
            self::EXPIRE_IN_SECONDS
        )
        ;
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
            new MatchQuery(
                OAuthRefreshTokenDefinition::ENTITY_NAME . '.refreshToken', $tokenRequest->getRefreshToken()
            )
        );

        /** @var OAuthRefreshTokenStruct $refreshToken */
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
     * @throws OAuthUnsupportedGrantTypeException
     */
    public function createTokenData(CheckoutContext $checkoutContext, TokenRequest $tokenRequest): array {
        switch (true) {
            case $tokenRequest->getGrantType() === 'authorization_code':
                return $this->generateTokenAuthCode($checkoutContext, $tokenRequest);
                break;
            case $tokenRequest->getGrantType() === 'refresh_token':
                return $this->generateTokenRefreshToken($checkoutContext, $tokenRequest);
                break;
            default:
                throw new OAuthUnsupportedGrantTypeException();
        }
    }
}