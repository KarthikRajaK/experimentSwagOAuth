<?php declare(strict_types=1);

namespace SwagOAuth\OAuth\Controller;

use Monolog\Handler\StreamHandler;
use Shopware\Core\Checkout\CheckoutContext;
use Shopware\Core\Checkout\Context\CheckoutContextPersister;
use Shopware\Core\Framework\Api\Response\Type\JsonType;
use Shopware\Core\Framework\ORM\Read\ReadCriteria;
use Shopware\Core\Framework\ORM\RepositoryInterface;
use Shopware\Core\Framework\ORM\Search\Criteria;
use Shopware\Core\Framework\ORM\Search\Query\MatchQuery;
use Shopware\Core\Framework\ORM\Search\Query\TermQuery;
use Shopware\Core\Framework\Struct\Uuid;
use Shopware\Core\PlatformRequest;
use Shopware\Storefront\Controller\StorefrontController;
use Shopware\Storefront\Page\Account\AccountService;
use Shopware\Storefront\Page\Account\LoginRequest;
use SwagOAuth\OAuth\Data\OAuthAccessTokenStruct;
use SwagOAuth\OAuth\Data\OAuthAuthorizationCodeStruct;
use SwagOAuth\OAuth\Data\OAuthClientStruct;
use SwagOAuth\OAuth\Data\OAuthRefreshTokenStruct;
use Symfony\Bridge\Monolog\Logger;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Serializer\Serializer;

class OAuthController extends StorefrontController
{
    /**
     * @var Serializer
     */
    private $serializer;

    /**
     * @var RepositoryInterface
     */
    private $oauthClientRepository;

    /**
     * @var RepositoryInterface
     */
    private $oauthAuthCodeRepository;

    /**
     * @var RepositoryInterface
     */
    private $oauthRefreshTokenRepository;

    /**
     * @var RepositoryInterface
     */
    private $oauthAccessTokenRepository;

    /**
     * @var CheckoutContextPersister
     */
    private $contextPersister;

    /**
     * @var AccountService
     */
    private $accountService;

    /**
     * @var Logger
     */
    private $logger;

    public function __construct(
        Serializer $serializer,
        RepositoryInterface $oauthClientRepository,
        RepositoryInterface $oauthAuthCodeRepository,
        RepositoryInterface $oauthRefreshTokenRepository,
        RepositoryInterface $oauthAccessTokenRepository,
        CheckoutContextPersister $contextPersister,
        AccountService $accountService,
        Logger $logger
    ) {
        $this->serializer = $serializer;
        $this->oauthClientRepository = $oauthClientRepository;
        $this->oauthAuthCodeRepository = $oauthAuthCodeRepository;
        $this->oauthRefreshTokenRepository = $oauthRefreshTokenRepository;
        $this->oauthAccessTokenRepository = $oauthAccessTokenRepository;
        $this->contextPersister = $contextPersister;
        $this->accountService = $accountService;
        $this->logger = $logger;
    }

    /**
     * @Route(path="/customer/oauth/authorize", name="customer.oauth.authorize", methods={"GET"})
     */
    public function authorize(Request $request, CheckoutContext $checkoutContext): Response
    {
        $clientId = $request->get('client_id');
        $redirectUri = $request->get('redirect_uri');
        $state = $request->get('state');

        $criteria = new Criteria();
        $criteria->addFilter(new MatchQuery('swag_oauth_client.clientId', $clientId));

        /** @var OAuthClientStruct[] $clients */
        $clients = $this->oauthClientRepository->search($criteria, $checkoutContext->getContext())->getElements();

        $client = array_pop($clients);

        if (!$client) {
            $data = [
                'error' => 'unauthorized_client',
                'error_description' => 'the user canceled the authentication',
            ];

            $callbackUrl = sprintf('%s?%s', $redirectUri, http_build_query($data));

            return $this->redirect($callbackUrl);
        }

        $data = [
            'clientId' => $client->getId(),
            'redirectUri' => $redirectUri,
            'state' => $state,
        ];

        return $this->renderStorefront('@SwagOAuth/frontend/oauth/login.html.twig', $data);
    }

    /**
     * @Route(path="/customer/oauth/authorize", name="customer.oauth.authorize.check", methods={"POST"})
     */
    public function checkAuthorize(Request $request, CheckoutContext $checkoutContext): Response
    {
        $clientId = $request->get('client_id');
        $redirectUri = $request->get('redirect_uri');
        $state = $request->get('state');
        $username = $request->get('username');
        $password = $request->get('password');

        $loginRequest = new LoginRequest();
        $loginRequest->setUsername($username);
        $loginRequest->setPassword($password);

        $data = [
            'clientId' => $clientId,
            'redirectUri' => $redirectUri,
            'state' => $state,
            'username' => $username,
            'password' => $password,
        ];

        try {
            $token = $this->accountService->login($loginRequest, $checkoutContext);
        } catch (BadCredentialsException | UnauthorizedHttpException $exception) {
            $data['login_error'] = $exception->getMessage();

            return $this->renderStorefront('@SwagOAuth/frontend/oauth/login.html.twig', $data);
        }

        $code = Uuid::uuid4()->getHex();

        $expires = new \DateTime();
        $expires->modify('+30 second');

        $responseData = [
            'code' => $code,
            'state' => $state,
        ];

        $callbackUrl = sprintf('%s?%s', $redirectUri, http_build_query($responseData));

        $data = [
            'id' => Uuid::uuid4()->getHex(),
            'authorizationCode' => $code,
            'clientId' => $clientId,
            'expires' => $expires,
            'redirectUri' => $callbackUrl,
            'swXContextToken' => $token,
        ];

        $this->oauthAuthCodeRepository->create([$data], $checkoutContext->getContext());

        return $this->redirect($callbackUrl);
    }

    /**
     * @Route(path="/customer/oauth/token", name="customer.oauth.generate_token", methods={"POST"})
     */
    public function generateToken(Request $request, CheckoutContext $checkoutContext): Response
    {
        $clientId = $request->get('client_id');
        $grantType = $request->get('grant_type');
        $secret = $request->get('client_secret');
        $code = $request->get('code');

        $criteria = new Criteria();
        $criteria->addFilter(new MatchQuery('swag_oauth_authorization_code.client.clientId', $clientId));
        $criteria->addFilter(new MatchQuery('swag_oauth_authorization_code.authorizationCode', $code));

        if ($secret) {
            $criteria->addFilter(new MatchQuery('swag_oauth_authorization_code.client.clientSecret', $secret));
        }

        $authCodes = $this->oauthAuthCodeRepository->search($criteria, $checkoutContext->getContext())->getElements();
        /** @var OAuthAuthorizationCodeStruct $authCode */
        $authCode = array_pop($authCodes);

        $refreshToken = new OAuthRefreshTokenStruct();
        $refreshToken->setId(Uuid::uuid4()->getHex());
        $refreshToken->setCustomerId($authCode->getClient()->getCustomerId());
        $refreshToken->setRefreshToken(Uuid::uuid4()->getHex());
        $refreshToken->setExpires(new \DateTime());
        $refreshToken->setClientId($authCode->getClientId());

        $this->oauthRefreshTokenRepository->create([$refreshToken->jsonSerialize()], $checkoutContext->getContext());

        $data = [
            'id' => $authCode->getId(),
            'tokenId' => $refreshToken->getId(),
        ];

        $this->oauthAuthCodeRepository->update([$data], $checkoutContext->getContext());

        $expires = new \DateTime();
        $expires->modify('+3600 second');

        $accessTokenString = Uuid::uuid4()->getHex();

        $accessToken = new OAuthAccessTokenStruct();
        $accessToken->setId(Uuid::uuid4()->getHex());
        $accessToken->setExpires($expires);
        $accessToken->setCustomerId($authCode->getClient()->getCustomerId());
        $accessToken->setAccessToken($accessTokenString);

        $this->oauthAccessTokenRepository->create([$accessToken->jsonSerialize()], $checkoutContext->getContext());

        $data = [
            'token_type' => 'Bearer',
            'expires_in' => '3600',
            'expires_on' => $expires->getTimestamp(),
            'access_token' => $accessToken->getAccessToken(),
            'refresh_token' => $refreshToken->getRefreshToken(),
            'sw_x_context_id' => $authCode->getSwXContextToken(),
        ];

        $response = new JsonResponse($data);
        $response->headers->set('Authorization', `Bearer ${accessTokenString}`);
        $response->headers->set(PlatformRequest::HEADER_CONTEXT_TOKEN, $authCode->getSwXContextToken());

        return $response;
    }

    /**
     * @Route(path="/storefront-api/customer/oauth/client", name="api.customer.oauth.client.overview", methods={"GET"})
     */
    public function clientOverview(Request $request, CheckoutContext $checkoutContext): Response
    {
        $this->denyAccessUnlessLoggedIn();
        $content = $this->decodedContent($request);

        $limit = 10;
        $page = 1;

        if (array_key_exists('limit', $content)) {
            $limit = (int) $content['limit'];
        }
        if (array_key_exists('page', $content)) {
            $limit = (int) $content['page'];
        }

        $tokens = $this->serialize($this->loadClients($page, $limit, $checkoutContext));

        return new JsonResponse($tokens);
    }

    private function decodedContent(Request $request): array
    {
        if (!empty($request->request->all())) {
            return $request->request->all();
        }

        if (empty($request->getContent())) {
            return [];
        }

        return $this->serializer->decode($request->getContent(), 'json');
    }

    private function serialize($data): array
    {
        $decoded = $this->serializer->normalize($data);

        return [
            'data' => JsonType::format($decoded),
        ];
    }

    /**
     * @return OAuthClientStruct[]
     */
    private function loadClients(int $page, int $limit, CheckoutContext $checkoutContext): array
    {
        $page = $page - 1;

        $criteria = new Criteria();
        $criteria->addFilter(new TermQuery('swag_oauth_client.customerId', $checkoutContext->getCustomer()->getId()));
        $criteria->setLimit($limit);
        $criteria->setOffset($page * $limit);
        $criteria->setFetchCount(Criteria::FETCH_COUNT_NEXT_PAGES);

        return $this->oauthClientRepository->search($criteria, $checkoutContext->getContext())->getElements();
    }

    /**
     * @Route(path="/storefront-api/customer/oauth/client/{id}", name="api.customer.oauth.client.details",
     *     methods={"GET"})
     */
    public function clientDetails(string $id, CheckoutContext $checkoutContext)
    {
        $this->denyAccessUnlessLoggedIn();

        $criteria = new ReadCriteria([$id]);
        $criteria->addFilter(new TermQuery('swag_oauth_client.customerId', $checkoutContext->getCustomer()->getId()));

        $tokens = $this->serialize($this->oauthClientRepository->read($criteria, $checkoutContext->getContext()));

        return new JsonResponse($tokens);
    }

    /**
     * @Route(path="/storefront-api/customer/oauth/client", name="api.customer.oauth.client.create", methods={"POST"})
     */
    public function createClient(Request $request, CheckoutContext $checkoutContext): Response
    {
        $this->denyAccessUnlessLoggedIn();

        $redirectUri = $request->get('redirect');

        $client = new OAuthClientStruct();
        $client->setId(Uuid::uuid4()->getHex());
        $client->setCustomerId($checkoutContext->getCustomer()->getId());
        $client->setClientId(Uuid::uuid4()->getHex());
        $client->setClientSecret(Uuid::uuid4()->getHex());

        if ($redirectUri) {
            $client->setRedirectUri($redirectUri);
        }

        $this->oauthClientRepository->create([$client->jsonSerialize()], $checkoutContext->getContext());

        return new JsonResponse($client->jsonSerialize());
    }

    /**
     * @Route(path="/storefront-api/customer/oauth/{id}", name="storefront.api.customer.oauth.update", methods={"PUT",
     *     "PATCH"})
     */
    public function updateToken(string $id, Request $request, CheckoutContext $checkoutContext): Response
    {
        $this->denyAccessUnlessLoggedIn();

        $content = $this->decodedContent($request);
        $data = [
            'id' => $id,
            'name' => $content['name'],
        ];

        $data = $this->serialize($this->oauthAccessTokenRepository->update([$data], $checkoutContext->getContext()));

        return new JsonResponse($data);
    }

    /**
     * @Route(path="/storefront-api/customer/oauth/{id}", name="storefront.api.customer.oauth.new.token",
     *     methods={"POST"})
     */
    public function generateNewToken(string $id, CheckoutContext $checkoutContext): Response
    {
        $this->denyAccessUnlessLoggedIn();

        $data = [
            'id' => $id,
            'accessToken' => 'Neuer Token',
        ];

        $writtenEvents = $this->oauthAccessTokenRepository->update([$data], $checkoutContext->getContext());

        return new JsonResponse($writtenEvents->getEvents()->getElements());
    }

    /**
     * @Route(path="/storefront-api/customer/oauth/{id}", name="storefront.api.customer.oauth.delete",
     *     methods={"DELETE"})
     */
    public function deleteToken(string $id, CheckoutContext $checkoutContext): Response
    {
        $this->denyAccessUnlessLoggedIn();

        $data = [
            'id' => $id,
        ];

        $data = $this->serialize($this->oauthAccessTokenRepository->delete([$data], $checkoutContext->getContext()));

        return new JsonResponse($data);
    }

    private function validateToken(OAuthAccessTokenStruct $token)
    {
        if (!$token->getId()) {
            throw new \InvalidArgumentException();
        }

        if (!$token->getAccessToken()) {
            throw new \InvalidArgumentException();
        }

        if (!$token->getCustomerId()) {
            throw new \InvalidArgumentException();
        }

        if (!$token->getSwContextToken()) {
            throw new \InvalidArgumentException();
        }
    }
}