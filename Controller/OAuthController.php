<?php declare(strict_types=1);

namespace SwagOAuth\Controller;

use Shopware\Core\Checkout\CheckoutContext;
use Shopware\Core\Framework\Struct\Uuid;
use Shopware\Storefront\Controller\StorefrontController;
use Shopware\Storefront\Page\Account\AccountService;
use SwagOAuth\OAuth\CustomerOAuthService;
use SwagOAuth\OAuth\Data\OAuthAccessTokenStruct;
use SwagOAuth\OAuth\Data\OAuthRefreshTokenStruct;
use SwagOAuth\OAuth\Request\AuthorizeRequest;
use SwagOAuth\OAuth\Request\TokenRequest;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

class OAuthController extends StorefrontController
{
    /**
     * @var AccountService
     */
    private $accountService;

    /**
     * @var CustomerOAuthService
     */
    private $customerOAuthService;

    public function __construct(
        AccountService $accountService,
        CustomerOAuthService $customerOAuthService
    ) {
        $this->accountService = $accountService;
        $this->customerOAuthService = $customerOAuthService;
    }

    /**
     * @Route(path="/customer/oauth/authorize", name="customer.oauth.authorize", methods={"GET"})
     */
    public function authorize(Request $request, CheckoutContext $checkoutContext): Response
    {
        $clientId = $request->get('client_id');
        $redirectUri = $request->get('redirect_uri');
        $state = $request->get('state');

        $integration = $this->customerOAuthService->getIntegrationByAccessKey($checkoutContext, $clientId);

        if (!$integration) {
            $callbackUrl = $this->buildErrorUrl($redirectUri, 'unauthorized_client', 'the client id is unknown');

            return $this->redirect($callbackUrl);
        }

        return $this->renderStorefront(
            '@SwagOAuth/frontend/oauth/login.html.twig',
            [
                'integrationId' => $integration->getId(),
                'redirectUri' => $redirectUri,
                'state' => $state,
            ]
        );
    }

    /**
     * @Route(path="/customer/oauth/authorize", name="customer.oauth.authorize.check", methods={"POST"})
     */
    public function checkAuthorize(Request $request, CheckoutContext $checkoutContext): Response
    {
        $authorizeRequest = (new AuthorizeRequest())->assign($request->request->all());

        try {
            $contextToken = $this->accountService->login($authorizeRequest, $checkoutContext);
        } catch (BadCredentialsException | UnauthorizedHttpException $exception) {
            $authorizeRequest->setLoginError($exception->getMessage());

            return $this->renderStorefront(
                '@SwagOAuth/frontend/oauth/login.html.twig',
                $authorizeRequest->jsonSerialize()
            );
        }

        $code = Uuid::uuid4()->getHex();

        $redirectUri = $this->customerOAuthService->generateRedirectUri($code, $authorizeRequest);

        $this->customerOAuthService->createAuthCode($checkoutContext, $code, $authorizeRequest, $contextToken);

        return $this->redirect($redirectUri);
    }

    /**
     * @Route(path="/customer/oauth/token", name="customer.oauth.generate_token", methods={"POST"})
     */
    public function generateToken(Request $request, CheckoutContext $checkoutContext): Response
    {
        $tokenRequest = (new TokenRequest())->assign($request->request->all());
        $tokenRequest->setClientId($request->headers->get('php-auth-user'));
        $tokenRequest->setClientSecret($request->headers->get('php-auth-pw'));

        if (!$this->customerOAuthService->isClientValid($tokenRequest, $checkoutContext))
        {
            return new JsonResponse(
                [
                    'error' => 'unauthorized_client',
                    'error_description' =>  'the client id is unknown',
                ]
            );
        }

        switch (true) {
            case $tokenRequest->getGrantType() === 'authorization_code':
                /** @var OAuthAccessTokenStruct $accessToken */
                list($accessToken, $refreshToken) = $this->customerOAuthService->generateTokenAuthCode($checkoutContext, $tokenRequest);
                break;
            case $tokenRequest->getGrantType() === 'refresh_token':
                $accessToken = $this->customerOAuthService->generateTokenRefreshToken($checkoutContext, $tokenRequest);
                break;
            default:
                return new JsonResponse(
                    [
                        'error' => 'invalid_request',
                        'error_description' =>  'the grant type is unknown',
                    ]
                );
        }

        $data = [
            'token_type' => 'Bearer',
            'expires_in' => '360',
            'expires_on' => $accessToken->getExpires()->getTimestamp(),
            'access_token' => $accessToken->getAccessToken(),
        ];

        if (isset($refreshToken)) {
            /** @var OAuthRefreshTokenStruct $refreshToken */
            $data['refresh_token'] = $refreshToken->getRefreshToken();
        }

        return new JsonResponse($data);
    }

    private function buildErrorUrl(string $redirectUrl, string $error, string $errorDescription): string
    {
        $data = [
            'error' => $error,
            'error_description' => $errorDescription,
        ];
        return sprintf('%s?%s', $redirectUrl, http_build_query($data));
    }
}