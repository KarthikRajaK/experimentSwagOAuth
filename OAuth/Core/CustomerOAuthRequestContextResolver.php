<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Core;

use Shopware\Core\PlatformRequest;
use Symfony\Bridge\Monolog\Logger;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class CustomerOAuthRequestContextResolver implements EventSubscriberInterface
{
    const HEADER_AUTHORIZATION = 'Authorization';
    const ROUTE_PREFIX = '/storefront-api/';

    /**
     * @var Logger
     */
    private $logger;

    public function __construct(
        Logger $logger
    ) {
        $this->logger = $logger;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['validateCustomerOAuth', 1000],
        ];
    }

    public function validateCustomerOAuth(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        if (!$this->isCustomerOAuthRequest($request)) {
            return;
        }

        $this->logger->addInfo('Headers', $request->headers->all());
        $request->headers->set(PlatformRequest::HEADER_ACCESS_KEY, 'SWSCCULRETHVZXI3DJZ3CJGWBA');
        $request->headers->set(PlatformRequest::HEADER_CONTEXT_TOKEN, 'a108cc61e6af460b8ae220312daf8dd9');
    }

    protected function isCustomerOAuthRequest(Request $request): bool
    {
        return !$request->headers->has(PlatformRequest::HEADER_ACCESS_KEY)
            && !$request->headers->has(PlatformRequest::HEADER_CONTEXT_TOKEN)
            && $request->headers->has(self::HEADER_AUTHORIZATION)
            && stripos($request->getPathInfo(), self::ROUTE_PREFIX) === 0;
    }


}