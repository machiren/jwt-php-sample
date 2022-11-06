<?php

require __DIR__.'/vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
// 必要に応じて以下を使用
use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;

class JwtManager
{
  private $algorithm = 'HS256';
  private $seacret_key = "SEACRET_KEY";

  /**
   * @see 必要に応じて使用
   */
  function __construct()
  {
    // 今の設計だと現状必要なし
  }

  /**
   * @see 発行日、トークン有効期限をとユーザーを特定するためのIDを発行します
   * @return string
   * @todo トークンに必要な情報があればさらに追加する
   */
  public function build_jwt_token(string $user_id): string 
  {
    $payload_by_user = [
      // Tokenを払い出したユーザの識別ID (仮でUser ID)
      "sub" => $user_id,
      // Tokenの発行元
      "iss" => "localhost",
      // Tokenの発行時間(現在時刻のUNIX TIMESTANP)
      "iat" => time(),
      // Tokenの有効期限(現在時刻から仮で1週間後のUNIX TIMESTANP)
      "exp" => (new DateTime())->add(new DateInterval('P1W'))->format('U'),
    ];

    $jwt = JWT::encode($payload_by_user, $this->seacret_key, $this->algorithm);
    
    return $jwt;
  }

  /**
   * @see クライアントから渡されたJWT Tokenの検証を行う
   * @return string
   */
  public function verify_jwt_token(string $jwt_token): array
  {
    try {
      $decoded = JWT::decode($jwt_token, new Key($this->seacret_key, $this->algorithm));
    } catch (InvalidArgumentException $e) {
        // provided key/key-array is empty or malformed.
    } catch (DomainException $e) {
        // provided algorithm is unsupported OR
        // provided key is invalid OR
        // unknown error thrown in openSSL or libsodium OR
        // libsodium is required but not available.
    } catch (SignatureInvalidException $e) {
        // provided JWT signature verification failed.
    } catch (BeforeValidException $e) {
        // provided JWT is trying to be used before "nbf" claim OR
        // provided JWT is trying to be used before "iat" claim.
    } catch (ExpiredException $e) {
        // provided JWT is trying to be used after "exp" claim.
    } catch (UnexpectedValueException $e) {
        // provided JWT is malformed OR
        // provided JWT is missing an algorithm / using an unsupported algorithm OR
        // provided JWT algorithm does not match provided key OR
        // provided key ID in key/key-array is empty or invalid.
    }

    return (array)$decoded;
  }
}

$jwt_manager = new JwtManager();

$jwt_token = $jwt_manager->build_jwt_token('999');

// jwt tokenの生成を確認
echo $jwt_token;

// jwt tokenの検証
echo $jwt_manager->verify_jwt_token($jwt_token);

?>