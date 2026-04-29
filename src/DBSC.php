<?php
/*
 * Copyright 2026 Tecsi Aron
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

namespace EdituraEDU\DBSC;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use LogicException;
use Throwable;

class DBSC
{
    private static DBSC|null $Instance = null;
    private readonly DBSCConfig $Config;
    private readonly IDBSCInvalidationHandler|null $InvalidationHandler;
    private readonly IDBSCLogger $Logger;

    public static function Initialize(string $configFilePath, IDBSCInvalidationHandler|null $invalidationHandler = null, IDBSCLogger|null $logger = null): void
    {
        $activeLogger = $logger ?? new DBSCLogger();
        if (self::$Instance === null)
            self::$Instance = new DBSC( $configFilePath,$invalidationHandler, $activeLogger);
        else
            throw new LogicException("DBSC already initialized, call DBSC::GetInstance() instead");
    }

    public static function GetInstance(): DBSC
    {
        if (self::$Instance === null)
            throw new LogicException("DBSC instance not initialized, call DBSC::Initialize first");
        return self::$Instance;
    }

    private function __construct(string $configFilePath, IDBSCInvalidationHandler|null $invalidationHandler, IDBSCLogger|null $logger)
    {
        $this->Config = DBSCConfig::LoadFromFile($configFilePath, $logger);
        $this->InvalidationHandler = $invalidationHandler;
        $this->Logger = $logger ?? new DBSCLogger();
        if ($this->Config->AutoEnforce)
        {
            $this->Enforce();
        }
    }

    public function HasDBSCCookie(): bool
    {
        return isset($_COOKIE[$this->Config->CookieName]);
    }

    public function SendStartHeader(string|null $dbscStartEndpoint = null): void
    {
        $dbscStartEndpoint = $dbscStartEndpoint ?? $this->Config->StartEndpoint;
        $existingChallenge = $this->SessionRead($this->Config->SessionLastChallengeKey);
        if ($existingChallenge == null)
        {
            $challenge = rtrim(strtr(base64_encode(random_bytes(32)), "+/", "-_"), "=");
        }
        else
        {
            $challenge = $existingChallenge;
        }
        $this->SessionWrite($this->Config->SessionLastChallengeKey, $challenge);
        header("Secure-Session-Registration: (ES256 RS256);challenge=\"$challenge\"; path=\"$dbscStartEndpoint\"");
    }

    public function Enforce(): bool
    {
        if(defined("DBSC_START_REFRESH_FLOW") && constant("DBSC_START_REFRESH_FLOW") === true )
            return true;
        $sessionDBSCGuard =$this->SessionRead($this->Config->CookieName);
        if(empty($sessionDBSCGuard))
        {
            return true;
        }
        $cookieDBSCGuard = $_COOKIE[$this->Config->CookieName] ?? null;
        if(empty($cookieDBSCGuard))
        {
            $this->Invalidate();
            return false;
        }
        if(!hash_equals($sessionDBSCGuard, $cookieDBSCGuard))
        {
            $this->Invalidate();
            return false;
        }
        return true;
    }

    public function StartDBSCSession(): DBSCStartResponse
    {
        $userJWT = $this->NormalizeDBSCHeaderValue($_SERVER["HTTP_SECURE_SESSION_RESPONSE"] ?? null);
        if (empty($userJWT))
        {
            http_response_code(500);
            $this->Logger->Error("DBSC session start endpoint hit with empty body!");
            exit();
        }
        $challenge = $this->SessionRead($this->Config->SessionLastChallengeKey);
        if (!$this->VerifyChallenge($challenge, $userJWT, $userJWT))
        {
            $this->Logger->Error("DBSC session start endpoint hit with invalid JWT!");
            http_response_code(400);
            exit();
        }
        if ($this->HasDBSCCookie())
        {
            $currentSecret = $this->SessionRead($this->Config->CookieName);
        }
        else
        {
            $currentSecret = null;
        }
        if (!empty($currentSecret))
        {
            $sessionSecret = $currentSecret;
        }
        else
        {
            $sessionSecret = base64_encode(random_bytes(32));
        }
        $this->SessionWrite($this->Config->SessionUserJwtKey, $userJWT);
        $this->SessionWrite($this->Config->CookieName, $sessionSecret);
        $this->WriteCookie($sessionSecret);
        header("Content-Type: application/json");
        header("Cache-Control: no-store");
        return new DBSCStartResponse($this->Config, $sessionSecret);
    }

    public function Refresh(): void
    {
        $currentSecret = $this->SessionRead($this->Config->CookieName);
        $headerSessionID = $this->NormalizeDBSCHeaderValue($_SERVER["HTTP_SEC_SECURE_SESSION_ID"] ?? null);
        if (empty($headerSessionID) || empty($currentSecret) || !hash_equals($currentSecret, $headerSessionID))
        {
            $this->Logger->Error("DBSC session refresh hit with invalid or missing session id header!");
            http_response_code(400);
            exit();
        }
        if (!isset($_SERVER["HTTP_SECURE_SESSION_RESPONSE"]))
        {
            $challenge = rtrim(strtr(base64_encode(random_bytes(32)), "+/", "-_"), "=");
            $this->SessionWrite($this->Config->SessionLastChallengeKey, $challenge);
            header("Secure-Session-Challenge: \"$challenge\";id=\"$currentSecret\"");
            http_response_code(403);
            return;
        }

        $userJWT = $this->NormalizeDBSCHeaderValue($_SERVER["HTTP_SECURE_SESSION_RESPONSE"] ?? null);
        if (empty($userJWT))
        {
            $this->Logger->Error("DBSC session refresh hit with empty Secure-Session-Response header!");
            http_response_code(400);
            exit();
        }
        $sessionPublicKey = $this->SessionRead($this->Config->SessionUserJwtKey);
        if (empty($sessionPublicKey))
        {
            $this->Logger->Error("DBSC session refresh hit with invalid or missing server side JWT, this should not happen!");
            http_response_code(401);
            $this->Invalidate();
            exit();
        }
        $challenge = $this->SessionRead($this->Config->SessionLastChallengeKey);
        if ($this->VerifyChallenge($challenge, $userJWT, $sessionPublicKey))
        {
            $this->WriteCookie($currentSecret);
            header("Content-Type: application/json");
            header("Cache-Control: no-store");
            return;
        }
        $this->Logger->Error("DBSC Failed to verify JWT on refresh");
        http_response_code(401);
        $this->Invalidate();
        exit();
    }

    private function Invalidate(): void
    {
        if ($this->Config->DestroySessionOnInvalidate)
        {
            $this->DestroyCurrentSessionIfPresent();
        }
        if ($this->InvalidationHandler !== null)
        {
            $this->InvalidationHandler->InvalidateSensitiveInfo();
        }
    }

    private function DestroyCurrentSessionIfPresent(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE)
        {
            if (session_name() == "" || !isset($_COOKIE[session_name()]))
            {
                return;
            }

            session_start();
        }

        $_SESSION = [];

        $sessionCookieName = session_name();
        $sessionCookieParams = session_get_cookie_params();

        setcookie(
            $sessionCookieName,
            "",
            time() - 42000,
            $sessionCookieParams["path"],
            $sessionCookieParams["domain"],
            $sessionCookieParams["secure"],
            $sessionCookieParams["httponly"]
        );

        if (!session_destroy())
        {
            $this->Logger->Error("[CRITICAL] Failed to destroy session on invalidate");
        }
    }

    private function VerifyChallenge(string $originalChallenge, string $jwt, string $userKey): bool
    {
        if (empty($originalChallenge) || empty($jwt))
            return false;
        $verificationKey = $this->ResolveVerificationKey($userKey);
        if ($verificationKey === null)
            return false;
        $headers = new \stdClass();
        try
        {
            $decoded = JWT::decode($jwt, $verificationKey, $headers);
        }
        catch (Throwable)
        {
            return false;
        }
        $typ = $headers->typ ?? null;
        if (!is_string($typ) || strtolower($typ) !== "dbsc+jwt")
            return false;
        if (!is_object($decoded))
            return false;
        $jti = $decoded->jti ?? null;
        if (!is_string($jti) || $jti === "")
            return false;
        return hash_equals($originalChallenge, $jti);
    }

    private function ResolveVerificationKey(string $jwt): Key|null
    {
        $trimmedUserKey = trim($jwt);
        if (empty($trimmedUserKey))
            return null;
        $parts = explode(".", $trimmedUserKey);
        if(empty($parts) || !is_array($parts) || count($parts) !== 3)
            return null;
        $decoded = json_decode(JWT::urlsafeB64Decode($parts[0]), true);
        if (!is_array($decoded))
            return null;
        if(!isset($decoded["jwk"]) || !is_array($decoded["jwk"]) || !isset($decoded["alg"]))
            return null;
        return JWK::parseKey($decoded["jwk"], $decoded["alg"]);
    }

    private function SessionRead(string $valueName): mixed
    {
        $openedSession = false;
        if (session_status() !== PHP_SESSION_ACTIVE)
        {
            session_start(["read_and_close" => false]);
            $openedSession = true;
        }
        try
        {
            if (isset($_SESSION[$valueName]))
                return $_SESSION[$valueName];
            return null;
        }
        finally
        {
            if ($openedSession && session_status() === PHP_SESSION_ACTIVE)
                session_write_close();
        }
    }

    private function SessionWrite(string $key, mixed $value): void
    {
        $openedSession = false;
        if (session_status() !== PHP_SESSION_ACTIVE)
        {
            session_start(["read_and_close" => false]);
            $openedSession = true;
        }
        $_SESSION[$key] = $value;
        if ($openedSession && session_status() === PHP_SESSION_ACTIVE)
            session_write_close();
    }

    private function WriteCookie(string $sessionSecret): void
    {
        setcookie($this->Config->CookieName, $sessionSecret, [
            "expires" => time() + $this->Config->CookieRefreshLifetimeSeconds,
            "path" => $this->Config->CookiePath,
            "domain" => $this->Config->CookieDomain,
            "secure" => $this->Config->CookieSecure,
            "httponly" => $this->Config->CookieHttpOnly,
            "samesite" => $this->Config->CookieSameSite,
        ]);
    }

    private function NormalizeDBSCHeaderValue(string|null $value): string|null
    {
        if ($value === null)
            return null;

        $trimmed = trim($value);
        if ($trimmed === "")
            return null;

        $length = strlen($trimmed);
        if ($length >= 2 && $trimmed[0] === "\"" && $trimmed[$length - 1] === "\"")
        {
            $inner = substr($trimmed, 1, -1);
            return str_replace(["\\\"", "\\\\"], ["\"", "\\"], $inner);
        }

        return $trimmed;
    }

}
