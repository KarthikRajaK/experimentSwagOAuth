<?php declare(strict_types=1);

namespace SwagOAuth\Controller;

use Shopware\Core\Checkout\CheckoutContext;
use Shopware\Core\Checkout\Customer\Storefront\AccountService;
use Shopware\Core\Checkout\Customer\Exception\BadCredentialsException;
use Shopware\Core\Framework\DataAbstractionLayer\Exception\InconsistentCriteriaIdsException;
use Shopware\Core\Framework\Routing\Exception\MissingRequestParameterException;
use Shopware\Core\Framework\Routing\InternalRequest;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use Shopware\Storefront\Framework\Controller\StorefrontController;
use SwagOAuth\OAuth\CustomerOAuthService;
use SwagOAuth\OAuth\Exception\OAuthException;
use SwagOAuth\OAuth\Exception\OAuthInvalidClientException;
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
    public function authorize(InternalRequest $request, CheckoutContext $checkoutContext): Response
    {
        try {
            $integration = $this->customerOAuthService
                ->getIntegrationByAccessKey($checkoutContext, $request->requireGet('client_id'));

            $request->addParam('integrationId', $integration->getId());
        } catch (OAuthInvalidClientException
        | InconsistentCriteriaIdsException
        | MissingRequestParameterException $invalidClientException) {
            $callbackUrl = $this->buildErrorUrl(
                (string) $request->optionalGet('redirect_uri', ''), [
                    'error' => $invalidClientException->getCode(),
                    'error_description' => $invalidClientException->getMessage(),
                ]
            );

            return $this->redirect($callbackUrl);
        } catch (\TypeError $error) {
            return new Response('', Response::HTTP_PRECONDITION_FAILED);
        }

        return $this->renderStorefront(
            '@SwagOAuth/frontend/oauth/login.html.twig',
            [
                'redirect_uri' => $request->optionalGet('redirect_uri', ''),
                'integrationId' => $request->getParam('integrationId'),
                'state' => $request->optionalGet('state'),
                'username' => $request->optionalGet('username'),
            ]
        );
    }

    /**
     * @Route(path="/customer/oauth/authorize", name="customer.oauth.authorize.check", methods={"POST"})
     */
    public function checkAuthorize(RequestDataBag $request, CheckoutContext $checkoutContext): Response
    {
        try {
            $contextToken = $this->accountService->loginWithPassword($request, $checkoutContext);

            $authCode = $this->customerOAuthService->createAuthCode($checkoutContext, $request, $contextToken);
        } catch (BadCredentialsException | UnauthorizedHttpException | OAuthException $exception) {
            $request->add(['loginError' => $exception->getMessage()]);
            return $this->renderStorefront(
                '@SwagOAuth/frontend/oauth/login.html.twig',
                [
                    'redirect_uri' => $request->get('redirect_uri', ''),
                    'integrationId' => $request->get('integrationId'),
                    'state' => $request->get('state'),
                    'username' => $request->get('username'),
                    'loginError' => $request->get('loginError')
                ]
            );
        }

        $redirectUri = $this->customerOAuthService
            ->generateRedirectUri($authCode, $request);

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

    private function buildErrorUrl(string $redirectUrl, array $errorData): string
    {
        return sprintf('%s?%s', $redirectUrl, http_build_query($errorData));
    }
}