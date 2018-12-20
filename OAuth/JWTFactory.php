<?php declare(strict_types=1);

namespace SwagOAuth\OAuth;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key;
use League\OAuth2\Server\CryptKey;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Struct\Uuid;
use SwagOAuth\OAuth\Data\OAuthAccessTokenEntity;
use SwagOAuth\OAuth\Data\TokenStruct;
use SwagOAuth\OAuth\Exception\InvalidOAuthTokenException;

class JWTFactory
{
    const ID = 'jti';
    const CONTEXT_TOKEN = 'pmi';
    const SUBJECT = 'sub';
    const AUDIENCE = 'aud';
    const ISSUER = 'iss';
    const EXPIRATION = 'exp';

    /**
     * @var CryptKey
     */
    protected $privateKey;

    /**
     * @param CryptKey|string $privateKey
     */
    public function __construct($privateKey)
    {
        if (!($privateKey instanceof CryptKey)) {
            $privateKey = new CryptKey($privateKey);
        }

        $this->privateKey = $privateKey;
    }

    public function generateToken(OAuthAccessTokenEntity $accessToken, Context $context, int $expiresInSeconds): string
    {
        $jwtToken = (new Builder())
            ->setIssuer($accessToken->getSalesChannel()->getAccessKey())
            ->setId(Uuid::uuid4()->getHex(), true)
            ->setIssuedAt(time())
            ->setNotBefore(time())
            ->setExpiration(time() + $expiresInSeconds)
            ->setSubject($accessToken->getUniqueIdentifier())
            ->set(self::CONTEXT_TOKEN, $accessToken->getContextToken())
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

        if (!$jwtToken->verify(new Sha256(), $this->privateKey->getKeyPath())) {
            throw new InvalidOAuthTokenException($token);
        }

        $tokenStruct = new TokenStruct(
            $jwtToken->getClaim(self::ID),
            $token,
            $jwtToken->getClaim(self::CONTEXT_TOKEN),
            $jwtToken->getClaim(self::SUBJECT),
            $jwtToken->getClaim(self::AUDIENCE),
            $jwtToken->getClaim(self::EXPIRATION)
        );

        return $tokenStruct;
    }
}