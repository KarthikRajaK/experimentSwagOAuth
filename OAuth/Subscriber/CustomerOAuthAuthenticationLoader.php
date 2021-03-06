<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Subscriber;

use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepositoryInterface;
use Shopware\Core\Framework\DataAbstractionLayer\Exception\InconsistentCriteriaIdsException;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\PlatformRequest;
use SwagOAuth\OAuth\Data\OAuthAccessTokenEntity;
use SwagOAuth\OAuth\Exception\InvalidOAuthTokenException;
use SwagOAuth\OAuth\Exception\OAuthException;
use SwagOAuth\OAuth\Exception\OAuthInvalidRequestException;
use SwagOAuth\OAuth\JWTFactory;
use SwagOAuth\OAuth\Data\TokenStruct;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class CustomerOAuthAuthenticationLoader implements EventSubscriberInterface
{
    const HEADER_AUTHORIZATION = 'Authorization';
    const ROUTE_PREFIX = '/storefront-api/';

    /** @var EntityRepositoryInterface */
    private $oauthAccessTokenRepository;

    /** @var JWTFactory */
    private $JWTFactory;

    public function __construct(
        EntityRepositoryInterface $oauthAccessTokenRepository,
        JWTFactory $JWTFactory
    ) {
        $this->oauthAccessTokenRepository = $oauthAccessTokenRepository;
        $this->JWTFactory = $JWTFactory;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['validateRequest', 256],
        ];
    }

    public function validateRequest(GetResponseEvent $event): void
    {
        $request = $event->getRequest();

        try {
            $this->checkCustomerOAuthRequest($request);
            $token = $this->extractToken($request);
            $this->checkValidAccessToken($token);
        } catch (OAuthException | InconsistentCriteriaIdsException $oAuthException) {
            return;
        }

        $request->headers->set(PlatformRequest::HEADER_ACCESS_KEY, $token->getXSwAccessKey());
        $request->headers->set(PlatformRequest::HEADER_CONTEXT_TOKEN, $token->getContextToken());
    }

    /**
     * @throws OAuthInvalidRequestException
     */
    protected function checkCustomerOAuthRequest(Request $request): void
    {
        if ($request->headers->has(PlatformRequest::HEADER_ACCESS_KEY)
            || $request->headers->has(PlatformRequest::HEADER_CONTEXT_TOKEN)
            || !$request->headers->has(self::HEADER_AUTHORIZATION)
            || stripos($request->getPathInfo(), self::ROUTE_PREFIX) !== 0) {
            throw new OAuthInvalidRequestException();
        }
    }

    /**
     * @throws InvalidOAuthTokenException
     */
    protected function extractToken(Request $request): TokenStruct
    {
        $authorization = $request->headers->get(self::HEADER_AUTHORIZATION);
        $authorization = substr($authorization, 7);

        return $this->JWTFactory->parseToken($authorization);
    }

    /**
     * @throws OAuthInvalidRequestException
     * @throws InconsistentCriteriaIdsException
     */
    protected function checkValidAccessToken(TokenStruct $token): void
    {
        if ($token->isExpired()) {
            throw new OAuthInvalidRequestException();
        }

        $context = Context::createDefaultContext();
        $readCriteria = new Criteria([$token->getAccessTokenId()]);

        /** @var OAuthAccessTokenEntity|null $accessToken */
        $accessToken = $this->oauthAccessTokenRepository
            ->search($readCriteria, $context)
            ->get($token->getAccessTokenId());

        if (!$accessToken) {
            throw new OAuthInvalidRequestException();
        }
    }
}