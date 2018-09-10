<?php declare(strict_types=1);

namespace SwagOAuth\OAuth;

use Shopware\Core\Checkout\CheckoutContext;
use Shopware\Core\Framework\ORM\RepositoryInterface;
use Shopware\Core\Framework\ORM\Search\Criteria;
use Shopware\Core\Framework\ORM\Search\Query\MatchQuery;
use Shopware\Core\Framework\Struct\Uuid;
use Shopware\Core\System\Integration\IntegrationCollection;
use Shopware\Core\System\Integration\IntegrationStruct;
use SwagOAuth\OAuth\Data\OAuthAccessTokenStruct;
use SwagOAuth\OAuth\Data\OAuthAuthorizationCodeStruct;
use SwagOAuth\OAuth\Data\OAuthRefreshTokenStruct;
use SwagOAuth\OAuth\Request\AuthorizeRequest;
use SwagOAuth\OAuth\Request\TokenRequest;

class CustomerOAuthService
{
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

    public function generateRedirectUri(string $code, AuthorizeRequest $authorizeRequest): string
    {
        $responseData = [
            'code' => $code,
            'state' => $authorizeRequest->getState(),
        ];

        $callbackUrl = sprintf('%s?%s', $authorizeRequest->getRedirectUri(), http_build_query($responseData));

        return $callbackUrl;
    }

    public function createAuthCode(
        CheckoutContext $checkoutContext,
        string $code,
        AuthorizeRequest $authorizeRequest,
        string $contextToken
    ): void {
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
    }

    public function isClientValid(TokenRequest $tokenRequest, CheckoutContext $context): bool
    {
        $integration = $this->getIntegrationByAccessKey($context, $tokenRequest->getClientId());

        return $integration
            && password_verify($tokenRequest->getClientSecret(), $integration->getSecretAccessKey());
    }

    public function getIntegrationByAccessKey(CheckoutContext $checkoutContext, string $accessKey): ?IntegrationStruct
    {
        $criteria = new Criteria();
        $criteria->addFilter(new MatchQuery('integration.accessKey', $accessKey));

        /** @var IntegrationCollection $integrations */
        $integrations = $this->integrationRepository->search($criteria, $checkoutContext->getContext());

        /** @var ?IntegrationStruct $integration */
        $integration = $integrations->first();

        return $integration;
    }

    /**
     * @return [OAuthAccessTokenStruct, OAuthRefreshTokenStruct]
     */
    public function generateTokenAuthCode(
        CheckoutContext $checkoutContext,
        TokenRequest $tokenRequest
    ): array {
        $authCode = $this->getAuthCode($checkoutContext, $tokenRequest);
        $refreshToken = $this->createRefreshToken($checkoutContext, $authCode);
        $this->linkRefreshTokenAuthCode($checkoutContext, $authCode, $refreshToken);

        return [
            $this->createAccessToken(
                $checkoutContext,
                $authCode->getContextToken()
            ),
            $refreshToken,
        ];
    }

    public function getAuthCode(
        CheckoutContext $checkoutContext,
        TokenRequest $tokenRequest
    ): OAuthAuthorizationCodeStruct {
        $criteria = new Criteria();
        $criteria->addFilter(
            new MatchQuery('swag_oauth_authorization_code.integration.accessKey', $tokenRequest->getClientId())
        );
        $criteria->addFilter(
            new MatchQuery('swag_oauth_authorization_code.authorizationCode', $tokenRequest->getCode())
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
        $refreshToken->setExpires(new \DateTime());
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
        $expires->modify('+360 second');

        $accessToken = new OAuthAccessTokenStruct();
        $accessToken->setId(Uuid::uuid4()->getHex());
        $accessToken->setExpires($expires);
        $accessToken->setContextToken($contextToken);
        $accessToken->setXSwAccessKey($checkoutContext->getSalesChannel()->getAccessKey());

        $accessTokenString =
            $this->JWTFactory->generateToken($accessToken, $checkoutContext->getContext(), 360);
        $accessToken->setAccessToken($accessTokenString);

        $this->oauthAccessTokenRepository->create([$accessToken->jsonSerialize()], $checkoutContext->getContext());

        return $accessToken;
    }

    public function generateTokenRefreshToken(
        CheckoutContext $checkoutContext,
        TokenRequest $tokenRequest
    ): OAuthAccessTokenStruct {
        $criteria = new Criteria();
        $criteria->addFilter(new MatchQuery('swag_oauth_refresh_token.refreshToken', $tokenRequest->getRefreshToken()));

        /** @var OAuthRefreshTokenStruct $refreshToken */
        $refreshToken = $this->oauthRefreshTokenRepository->search($criteria, $checkoutContext->getContext())->first();

        return $this->createAccessToken($checkoutContext, $refreshToken->getContextToken());
    }
}