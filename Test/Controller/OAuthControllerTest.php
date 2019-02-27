<?php declare(strict_types=1);

namespace SwagOAuth\Test\Controller;

use PHPUnit\Framework\TestCase;
use Shopware\Core\Checkout\CheckoutContext;
use Shopware\Core\Checkout\Customer\Storefront\AccountService;
use Shopware\Core\Checkout\Exception\BadCredentialsException;
use Shopware\Core\Checkout\Test\Cart\Common\Generator;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\NotFilter;
use Shopware\Core\Framework\Routing\InternalRequest;
use Shopware\Core\Framework\Struct\Uuid;
use Shopware\Core\Framework\Test\TestCaseBase\AdminApiTestBehaviour;
use Shopware\Core\Framework\Test\TestCaseBase\StorefrontFunctionalTestBehaviour;
use Shopware\Core\System\Integration\IntegrationEntity;
use Shopware\Core\System\SalesChannel\SalesChannelEntity;
use SwagOAuth\Controller\OAuthController;
use SwagOAuth\OAuth\CustomerOAuthService;
use SwagOAuth\OAuth\Data\OAuthAuthorizationCodeEntity;
use SwagOAuth\OAuth\Data\OAuthRefreshTokenEntity;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * @coversDefaultClass \SwagOAuth\Controller\OAuthController
 */
class OAuthControllerTest extends TestCase
{
    use AdminApiTestBehaviour,
        StorefrontFunctionalTestBehaviour;

    protected $controller;

    protected $accountService;

    protected function setUp(): void
    {
        $this->accountService = $this->createMock(AccountService::class);

        $this->controller = $this->getMockBuilder(OAuthController::class)->setConstructorArgs(
            [
                $this->accountService,
                $this->getContainer()->get(CustomerOAuthService::class),
            ]
        )
            ->setMethods(['renderStorefront'])
            ->getMock();

        $this->controller->method('renderStorefront')->will(
            $this->returnCallback(
                function ($template, $parameters) {
                    return new JsonResponse(
                        array_merge(
                            ['template' => $template],
                            $parameters
                        )
                    );
                }
            )
        );
    }

    public function testAuthorizeShowsLogin(): void
    {
        $integration = $this->createIntegration();
        $data = [
            'redirect_uri' => 'https://shopware.local/redirect_uri',
            'client_id' => $integration->getAccessKey(),
            'state' => 'TheStateForCSRF',
        ];
        $request = new InternalRequest($data);

        /** @var JsonResponse $response */
        $response = $this->controller->authorize($request, $this->getCheckoutContext());
        $responseData = $this->getData($response);

        static::assertNull($responseData['username']);
        static::assertSame($data['state'], $responseData['state']);
        static::assertSame($data['redirect_uri'], $responseData['redirect_uri']);
        static::assertSame($integration->getId(), $responseData['integrationId']);
        static::assertSame('@SwagOAuth/frontend/oauth/login.html.twig', $responseData['template']);
    }

    public function testAuthorizeWithoutClientId(): void
    {
        $data = [
            'redirect_uri' => 'https://shopware.local/redirect_uri',
            'state' => 'TheStateForCSRF',
        ];
        $request = new InternalRequest($data);

        $response = $this->controller->authorize($request, $this->getCheckoutContext());

        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertInstanceOf(RedirectResponse::class, $response);
    }

    public function testAuthorizeWithNotExistingClientId(): void
    {
        $data = [
            'redirect_uri' => 'https://shopware.local/redirect_uri',
            'client_id' => 'NotExistingClientId',
            'state' => 'TheStateForCSRF',
        ];
        $request = new InternalRequest($data);

        /** @var RedirectResponse $response */
        $response = $this->controller->authorize($request, $this->getCheckoutContext());

        $query = $this->parseUrl($response);

        static::assertInstanceOf(RedirectResponse::class, $response);
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame($query['error'], 'invalid_client');
        static::assertSame(
            $query['error_description'],
            'Client authentication failed, such as if the request contains an invalid client ID or secret.'
        );
        static::assertSame($query['path'], '/redirect_uri');
        static::assertSame($query['host'], 'shopware.local');
        static::assertSame($query['scheme'], 'https');
    }

    public function testAuthorizeWithoutState(): void
    {
        $integration = $this->createIntegration();
        $data = [
            'redirect_uri' => 'https://shopware.local/redirect_uri',
            'client_id' => $integration->getAccessKey(),
        ];
        $request = new InternalRequest($data);

        /** @var JsonResponse $response */
        $response = $this->controller->authorize($request, $this->getCheckoutContext());
        static::assertInstanceOf(JsonResponse::class, $response);
        $responseData = $this->getData($response);

        static::assertSame($data['redirect_uri'], $responseData['redirect_uri']);
        static::assertSame($integration->getId(), $responseData['integrationId']);
        static::assertNull($responseData['state']);
        static::assertSame('@SwagOAuth/frontend/oauth/login.html.twig', $responseData['template']);
    }

    public function testCheckAuthorize(): void
    {
        $contextToken = Uuid::uuid4()->getHex();

        $this->accountService->expects($this->once())->method('login')->willReturn($contextToken);
        $integration = $this->createIntegration();
        $data = [
            'username' => 'test@example.com',
            'password' => 'shopware',
            'integrationId' => $integration->getId(),
            'redirect_uri' => 'https://shopware.local/redirect_uri',
            'state' => 'TheStateForCSRF',
        ];
        $request = new InternalRequest([], $data);
        /** @var RedirectResponse $response */
        $response = $this->controller->checkAuthorize($request, $this->getCheckoutContext());
        static::assertInstanceOf(RedirectResponse::class, $response);

        $urlParts = $this->parseUrl($response);

        static::assertSame($data['state'], $urlParts['state']);
        static::assertSame('/redirect_uri', $urlParts['path']);
        static::assertSame( 'shopware.local', $urlParts['host']);
        static::assertSame('https', $urlParts['scheme']);

        $authCode = $this->getAuthCodeByContextToken($contextToken);

        static::assertNotNull($authCode);
        static::assertInstanceOf(OAuthAuthorizationCodeEntity::class, $authCode);
        static::assertSame($urlParts['code'], $authCode->getAuthorizationCode());
        static::assertLessThanOrEqual((new \DateTime)->modify('+30 second'), $authCode->getExpires());
    }

    public function testCheckAuthorizeBadCredentials(): void
    {
        $this->accountService->expects($this->once())->method('login')->willThrowException(new BadCredentialsException());

        $integration = $this->createIntegration();
        $data = [
            'username' => 'unknown',
            'password' => 'invalid',
            'integrationId' => $integration->getId(),
            'redirect_uri' => 'https://shopware.local/redirect_uri',
            'state' => 'TheStateForCSRF',
        ];

        /** @var JsonResponse $response */
        $response = $this->controller->checkAuthorize(new InternalRequest([], $data), $this->getCheckoutContext());

        static::assertInstanceOf(JsonResponse::class, $response);
        $responseData = $this->getData($response);

        static::assertSame($data['username'], $responseData['username']);
        static::assertSame($data['redirect_uri'], $responseData['redirect_uri']);
        static::assertSame($data['state'], $responseData['state']);
        static::assertSame('@SwagOAuth/frontend/oauth/login.html.twig', $responseData['template']);
        static::assertSame($integration->getId(), $responseData['integrationId']);
        static::assertArrayHasKey('loginError', $responseData);
        static::assertSame('Invalid username and/or password.', $responseData['loginError']);
        static::assertSame('@SwagOAuth/frontend/oauth/login.html.twig', $responseData['template']);
    }

    public function testCheckAuthorizeWithoutIntegrationId(): void
    {
        $contextToken = Uuid::uuid4()->getHex();

        $this->accountService->expects($this->once())->method('login')->willReturn($contextToken);

        $data = [
            'username' => 'unknown',
            'password' => 'invalid',
            'redirect_uri' => 'https://shopware.local/redirect_uri',
            'state' => 'TheStateForCSRF',
        ];

        /** @var JsonResponse $response */
        $response = $this->controller->checkAuthorize(new InternalRequest([], $data), $this->getCheckoutContext());

        static::assertInstanceOf(JsonResponse::class, $response);

        $responseData = $this->getData($response);

        static::assertSame($data['username'], $responseData['username']);
        static::assertSame($data['redirect_uri'], $responseData['redirect_uri']);
        static::assertSame($data['state'], $responseData['state']);
        static::assertSame('@SwagOAuth/frontend/oauth/login.html.twig', $responseData['template']);
        static::assertNull($responseData['integrationId']);
        static::assertArrayHasKey('loginError', $responseData);
        static::assertStringStartsWith('The request is missing a parameter so the server can’t proceed with the request.', $responseData['loginError']);
        static::assertSame('@SwagOAuth/frontend/oauth/login.html.twig', $responseData['template']);
    }

    public function testGenerateTokenAuthCode(): void
    {
        $integration = $this->createIntegration();
        $authCode = $this->createAuthCode($integration);
        $context = $this->getCheckoutContext($this->getSalesChannel());
        $data = [
            'grant_type' => 'authorization_code',
            'code' => $authCode->getAuthorizationCode(),
        ];
        $request = new Request([], $data);
        $request->headers->add(
            [
                'php-auth-user' => $integration->getAccessKey(),
                'php-auth-pw' => $integration->getSecretAccessKey(),
            ]
        );
        /** @var JsonResponse $response */
        $response = $this->controller->generateToken($request, $context);

        static::assertInstanceOf(JsonResponse::class, $response);
        $responseData = $this->getData($response);

        static::assertNotNull($responseData['token_type']);
        static::assertNotNull($responseData['expires_in']);
        static::assertNotNull($responseData['refresh_token']);
        static::assertNotNull($responseData['access_token']);
    }

    public function testGenerateTokenWithoutCode(): void
    {
        $integration = $this->createIntegration();
        $context = $this->getCheckoutContext($this->getSalesChannel());
        $data = [
            'grant_type' => 'authorization_code',
        ];
        $request = new Request([], $data);
        $request->headers->add(
            [
                'php-auth-user' => $integration->getAccessKey(),
                'php-auth-pw' => $integration->getSecretAccessKey(),
            ]
        );
        /** @var JsonResponse $response */
        $response = $this->controller->generateToken($request, $context);

        static::assertInstanceOf(JsonResponse::class, $response);
        $responseData = $this->getData($response);

        static::assertSame('invalid_request', $responseData['error']);
        static::assertSame(Response::HTTP_INTERNAL_SERVER_ERROR, $response->getStatusCode());
    }

    public function testGenerateTokenInvalidAuth(): void
    {
        $request = new Request();
        $request->headers->add(
            [
                'php-auth-user' => 'Invalid',
                'php-auth-pw' => 'Invalid',
            ]
        );

        /** @var JsonResponse $response */
        $response = $this->controller->generateToken($request, $this->getCheckoutContext());

        $responseData = $this->getData($response);

        static::assertSame('invalid_client', $responseData['error']);
        static::assertSame(Response::HTTP_INTERNAL_SERVER_ERROR, $response->getStatusCode());
    }

    public function testGenerateTokenInvalidSecret()
    {
        $integration = $this->createIntegration();

        $request = new Request();
        $request->headers->add(
            [
                'php-auth-user' => $integration->getAccessKey(),
                'php-auth-pw' => 'Invalid',
            ]
        );

        /** @var JsonResponse $response */
        $response = $this->controller->generateToken($request, $this->getCheckoutContext());

        $responseData = $this->getData($response);

        static::assertSame('invalid_client', $responseData['error']);
        static::assertSame(Response::HTTP_INTERNAL_SERVER_ERROR, $response->getStatusCode());
    }

    public function testGenerateTokenWithoutAuth(): void
    {
        /** @var JsonResponse $response */
        $response = $this->controller->generateToken(new Request(), $this->getCheckoutContext());

        $responseData = $this->getData($response);

        static::assertSame('invalid_client', $responseData['error']);
        static::assertSame(Response::HTTP_INTERNAL_SERVER_ERROR, $response->getStatusCode());
    }

    public function testGenerateTokenWithoutGrantType(): void
    {
        $integration = $this->createIntegration();
        $context = $this->getCheckoutContext($this->getSalesChannel());
        $data = [
        ];
        $request = new Request([], $data);
        $request->headers->add(
            [
                'php-auth-user' => $integration->getAccessKey(),
                'php-auth-pw' => $integration->getSecretAccessKey(),
            ]
        );
        /** @var JsonResponse $response */
        $response = $this->controller->generateToken($request, $context);

        static::assertInstanceOf(JsonResponse::class, $response);
        $responseData = $this->getData($response);

        static::assertSame('unsupported_grant_type', $responseData['error']);
        static::assertSame(Response::HTTP_INTERNAL_SERVER_ERROR, $response->getStatusCode());
    }

    public function testGenerateTokenWitInvalidGrantType(): void
    {
        $integration = $this->createIntegration();
        $context = $this->getCheckoutContext($this->getSalesChannel());
        $data = [
            'grant_type' => 'invalid'
        ];
        $request = new Request([], $data);
        $request->headers->add(
            [
                'php-auth-user' => $integration->getAccessKey(),
                'php-auth-pw' => $integration->getSecretAccessKey(),
            ]
        );
        /** @var JsonResponse $response */
        $response = $this->controller->generateToken($request, $context);

        static::assertInstanceOf(JsonResponse::class, $response);
        $responseData = $this->getData($response);

        static::assertSame('unsupported_grant_type', $responseData['error']);
        static::assertSame(Response::HTTP_INTERNAL_SERVER_ERROR, $response->getStatusCode());
    }

    public function testGenerateTokenRefreshToken(): void
    {
        $integration = $this->createIntegration();
        $refreshToken = $this->createRefreshToken($integration);
        $context = $this->getCheckoutContext($this->getSalesChannel());
        $data = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken->getRefreshToken(),
        ];
        $request = new Request([], $data);
        $request->headers->add(
            [
                'php-auth-user' => $integration->getAccessKey(),
                'php-auth-pw' => $integration->getSecretAccessKey(),
            ]
        );
        /** @var JsonResponse $response */
        $response = $this->controller->generateToken($request, $context);

        static::assertInstanceOf(JsonResponse::class, $response);
        $responseData = $this->getData($response);

        static::assertNotNull($responseData['token_type']);
        static::assertNotNull($responseData['expires_in']);
        static::assertNotNull($responseData['access_token']);
    }

    protected function getAuthCodeByContextToken(string $contextToken): ?OAuthAuthorizationCodeEntity
    {
        $repo = $this->getContainer()->get('swag_oauth_authorization_code.repository');

        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('swag_oauth_authorization_code.contextToken', $contextToken));

        return $repo->search($criteria, $this->getCheckoutContext()->getContext())->first();
    }

    protected function getSalesChannel(): SalesChannelEntity
    {
        $criteria = new Criteria();
        $criteria->addFilter(new NotFilter(NotFilter::CONNECTION_AND, [new EqualsFilter('sales_channel.accessKey', null)]));
        return $this->getContainer()->get('sales_channel.repository')->search($criteria, $this->getCheckoutContext()->getContext())->first();
    }

    protected function createRefreshToken(IntegrationEntity $integrationEntity): OAuthRefreshTokenEntity
    {
        $refreshToken = new OAuthRefreshTokenEntity();
        $refreshToken->setUniqueIdentifier(Uuid::uuid4()->getHex());
        $refreshToken->setContextToken(Uuid::uuid4()->getHex());
        $refreshToken->setRefreshToken(Uuid::uuid4()->getHex());
        $refreshToken->setIntegrationId($integrationEntity->getId());

        $this->getContainer()->get('swag_oauth_refresh_token.repository')
            ->create([$refreshToken->jsonSerialize()], $this->getCheckoutContext()->getContext());

        return $refreshToken;
    }

    protected function createIntegration(): IntegrationEntity
    {
        $integration = new IntegrationEntity();
        $integration->setId(Uuid::uuid4()->getHex());
        $integration->setAccessKey('ThisIsAClientID');
        $integration->setSecretAccessKey('Thi$I$A$uper$ecretAcce$$Key');
        $integration->setLabel('OAuthTest');
        $integration->setCreatedAt(new \DateTime());
        $integration->setUpdatedAt(new \DateTime());
        $integration->setLastUsageAt(new \DateTime());
        $integration->setWriteAccess(false);

        $this->getContainer()->get('integration.repository')
            ->create([$integration->jsonSerialize()], $this->getCheckoutContext()->getContext());

        return $integration;
    }

    protected function createAuthCode(IntegrationEntity $integrationEntity): OAuthAuthorizationCodeEntity
    {
        $code = new OAuthAuthorizationCodeEntity();
        $expires = (new \DateTime())->modify('+ ' .CustomerOAuthService::EXPIRE_IN_SECONDS . ' second');
        $data = [
            'id' => Uuid::uuid4()->getHex(),
            'authorizationCode' => Uuid::uuid4()->getHex(),
            'integrationId' => $integrationEntity->getId(),
            'expires' => $expires,
            'contextToken' => Uuid::uuid4()->getHex(),
        ];

        $code->assign($data);

        $this->getContainer()->get('swag_oauth_authorization_code.repository')
            ->create([$data], $this->getCheckoutContext()->getContext());

        return $code;
    }

    protected function getCheckoutContext(?SalesChannelEntity $salesChannelEntity = null): CheckoutContext
    {
        return Generator::createCheckoutContext(null, null, null, $salesChannelEntity);
    }

    public function parseUrl(RedirectResponse $response): array
    {
        $urlParts = parse_url($response->getTargetUrl());
        parse_str($urlParts['query'], $query);

        return array_merge($urlParts, $query);
    }

    protected function getData(JsonResponse $jsonResponse): array
    {
        return json_decode($jsonResponse->getContent(), true);
    }
}
