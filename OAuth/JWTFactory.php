<?php declare(strict_types=1);

namespace SwagOAuth\OAuth;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key;
use League\OAuth2\Server\CryptKey;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Struct\Uuid;
use SwagOAuth\OAuth\Data\OAuthAccessTokenStruct;
use SwagOAuth\OAuth\Data\TokenStruct;

class JWTFactory
{
    /**
     * @var Key|CryptKey|string
     */
    protected $privateKey;

    /**
     * @param Key|CryptKey|string $privateKey
     */
    public function __construct($privateKey)
    {
        if ($privateKey instanceof CryptKey === false) {
            $privateKey = new CryptKey($privateKey);
        }

        $this->privateKey = $privateKey;
    }

    public function generateToken(OAuthAccessTokenStruct $accessToken, Context $context, int $expiresInSeconds = 3600): string
    {
        $jwtToken = (new Builder())
            ->setIssuer($accessToken->getXSwAccessKey())
            ->setAudience($context->getTenantId())
            ->setId(Uuid::uuid4()->getHex(), true)
            ->setIssuedAt(time())
            ->setNotBefore(time())
            ->setExpiration(time() + $expiresInSeconds)
            ->setSubject($accessToken->getId())
            ->set('pmi', $accessToken->getContextToken())
            ->sign(new Sha256(), new Key($this->privateKey->getKeyPath(), $this->privateKey->getPassPhrase()))
            ->getToken();

        return (string) $jwtToken;
    }

    /**
     * @throws InvalidOAuthTokenException
     */
    public function parseToken(string $token): TokenStruct
    {
        try {
            $jwtToken = (new Parser())->parse($token);
        } catch (\InvalidArgumentException $e) {
            throw new InvalidOAuthTokenException($token, 0, $e);
        }

        if ($jwtToken->verify(new Sha256(), $this->privateKey->getKeyPath()) === false) {
            throw new InvalidOAuthTokenException($token);
        }

        $tokenStruct = new TokenStruct(
            $jwtToken->getClaim('jti'),
            $token,
            $jwtToken->getClaim('pmi'),
            $jwtToken->getClaim('sub'),
            $jwtToken->getClaim('aud'),
            $jwtToken->getClaim('iss'),
            $jwtToken->getClaim('exp')
        );

        return $tokenStruct;
    }
}