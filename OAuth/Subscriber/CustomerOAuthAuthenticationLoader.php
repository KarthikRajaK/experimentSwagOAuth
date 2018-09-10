<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Subscriber;

use Monolog\Logger;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\ORM\Read\ReadCriteria;
use Shopware\Core\Framework\ORM\RepositoryInterface;
use Shopware\Core\PlatformRequest;
use SwagOAuth\OAuth\Data\OAuthAccessTokenStruct;
use SwagOAuth\OAuth\InvalidOAuthTokenException;
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

    /**
     * @var RepositoryInterface
     */
    private $oauthAccessTokenRepository;

    /**
     * @var JWTFactory
     */
    private $JWTFactory;

    public function __construct(
        RepositoryInterface $oauthAccessTokenRepository,
        JWTFactory $JWTFactory
    ) {
        $this->oauthAccessTokenRepository = $oauthAccessTokenRepository;
        $this->JWTFactory = $JWTFactory;
    }

    public static function getSubscribedEvents()
    {
        return [
            KernelEvents::REQUEST => ['validateRequest', 256],
        ];
    }

    public function validateRequest(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        if (!$this->isCustomerOAuthRequest($request)) {
            return;
        }

        $token = $this->extractToken($request);

        if (!$token || $token->isExpired()) {
            return;
        }

        if (!$this->isValidAccessToken($token)) {
            return;
        }

        $request->headers->set(PlatformRequest::HEADER_ACCESS_KEY, $token->getXSwAccessKey());
        $request->headers->set(PlatformRequest::HEADER_CONTEXT_TOKEN, $token->getContextToken());
    }

    protected function isCustomerOAuthRequest(Request $request): bool
    {
        return !$request->headers->has(PlatformRequest::HEADER_ACCESS_KEY)
            && !$request->headers->has(PlatformRequest::HEADER_CONTEXT_TOKEN)
            && $request->headers->has(self::HEADER_AUTHORIZATION)
            && stripos($request->getPathInfo(), self::ROUTE_PREFIX) === 0;
    }

    protected function extractToken(Request $request): ?TokenStruct
    {
        $authorization = $request->headers->get(self::HEADER_AUTHORIZATION);
        $authorization = substr($authorization, 7);
        try {
            return $this->JWTFactory->parseToken($authorization);
        } catch (InvalidOAuthTokenException $authTokenException) {
            return null;
        }
    }

    protected function isValidAccessToken(TokenStruct $token): bool
    {
        $context = Context::createDefaultContext($token->getTenantId());
        $readCriteria = new ReadCriteria([$token->getAccessTokenId()]);

        /** @var OAuthAccessTokenStruct $accessToken */
        $accessToken = $this->oauthAccessTokenRepository
            ->read($readCriteria, $context)
            ->get($token->getAccessTokenId());

        return $accessToken !== null;
    }
}