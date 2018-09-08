<?php declare(strict_types=1);

namespace SwagOAuth\Controller;

use Shopware\Core\Checkout\CheckoutContext;
use Shopware\Core\Framework\Struct\Uuid;
use Shopware\Storefront\Controller\StorefrontController;
use Shopware\Storefront\Page\Account\AccountService;
use SwagOAuth\OAuth\CustomerOAuthService;
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
            $data = [
                'error' => 'unauthorized_client',
                'error_description' => 'the client id is unknown',
            ];

            $callbackUrl = sprintf('%s?%s', $redirectUri, http_build_query($data));

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

        $authCode = $this->customerOAuthService->getAuthCode($checkoutContext, $tokenRequest);
        $refreshToken = $this->customerOAuthService->createRefreshToken($checkoutContext, $authCode);
        $this->customerOAuthService->linkRefreshTokenAuthCode($checkoutContext, $authCode, $refreshToken);

        $expires = new \DateTime();
        $expires->modify('+3600 second');

        $accessToken = $this->customerOAuthService->createAccessToken(
            $checkoutContext, $expires, $authCode->getContextToken()
        );

        $data = [
            'token_type' => 'Bearer',
            'expires_in' => '3600',
            'expires_on' => $expires->getTimestamp(),
            'access_token' => $accessToken->getAccessToken(),
            'refresh_token' => $refreshToken->getRefreshToken(),
        ];

        $response = new JsonResponse($data);

        return $response;
    }
}