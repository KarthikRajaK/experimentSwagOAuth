<?php declare(strict_types=1);

namespace SwagOAuth\Controller;

use Shopware\Core\Checkout\CheckoutContext;
use Shopware\Storefront\Account\Page\AccountService;
use Shopware\Storefront\Framework\Controller\StorefrontController;
use Shopware\Storefront\Framework\Exception\BadCredentialsException;
use SwagOAuth\OAuth\CustomerOAuthService;
use SwagOAuth\OAuth\Exception\OAuthException;
use SwagOAuth\OAuth\Exception\OAuthInvalidClientException;
use SwagOAuth\OAuth\Request\AuthorizeRequest;
use SwagOAuth\OAuth\Request\TokenRequest;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\Routing\Annotation\Route;

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
        $authorizeRequest = (new AuthorizeRequest())->assign($request->query->all());

        try {
            $integration = $this->customerOAuthService
                ->getIntegrationByAccessKey($checkoutContext, $authorizeRequest->getClientId());

            $authorizeRequest->setIntegrationId($integration->getId());
        } catch (OAuthInvalidClientException $invalidClientException) {
            $callbackUrl = $this->buildErrorUrl($authorizeRequest->getRedirectUri(), $invalidClientException);

            return $this->redirect($callbackUrl);
        } catch (\TypeError $error) {
            return new Response('', Response::HTTP_PRECONDITION_FAILED);
        }

        return $this->renderStorefront(
            '@SwagOAuth/frontend/oauth/login.html.twig',
            $authorizeRequest->jsonSerialize()
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

            $authCode = $this->customerOAuthService->createAuthCode($checkoutContext, $authorizeRequest, $contextToken);
        } catch (BadCredentialsException | UnauthorizedHttpException | OAuthException $exception) {
            $authorizeRequest->setLoginError($exception->getMessage());

            return $this->renderStorefront(
                '@SwagOAuth/frontend/oauth/login.html.twig',
                $authorizeRequest->jsonSerialize()
            );
        }

        $redirectUri = $this->customerOAuthService
            ->generateRedirectUri($authCode, $authorizeRequest);

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

        try {
            $this->customerOAuthService->checkClientValid($tokenRequest, $checkoutContext);
            $data = $this->customerOAuthService->createTokenData($checkoutContext, $tokenRequest);
        } catch (OAuthException $authException) {
            return new JsonResponse($authException->getErrorData(), $authException->getStatusCode());
        }

        return new JsonResponse($data);
    }

    private function buildErrorUrl(string $redirectUrl, OAuthException $authException): string
    {
        return sprintf('%s?%s', $redirectUrl, http_build_query($authException->getErrorData()));
    }
}