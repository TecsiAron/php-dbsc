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

namespace EdituraEDU\DBSC\Tests;

use EdituraEDU\DBSC\DBSC;
use EdituraEDU\DBSC\IDBSCInvalidationHandler;
use LogicException;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

class DBSCTest extends TestCase
{
    private string $ConfigPath;
    private string $CookieName = "dbsc_guard_test";
    private const string VALID_INITTIAL_JWT="eyJhbGciOiJFUzI1NiIsImp3ayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImJRczV3SXNDejc2NjZUTDl2bkJJMFRrTktmWkFvWkhQbnZBWXowWFdlUkkiLCJ5IjoiT0pnLVpMWTB5NHc5eW85NjRXLUhxT01LZDFLajZNSUFpSkxJa1E1ZTY0RSJ9LCJ0eXAiOiJkYnNjK2p3dCJ9.eyJqdGkiOiJ2NHJ6YTFtTlRyVk1xbFFLZzBaQnN4QmlHRkFoQmJTSWJYcENvSmlXTWZVIn0.Qaqw0VE8Z4QbW5mQgK1Y7XGQm9hRYmqROaAIOo5Fysqxz6GHpUqDa8MW-9jjBp8n-4aKgZDAphUvR5irRVI-YA";

    protected function setUp(): void
    {
        parent::setUp();
        $this->resetDBSCSingleton();
        $this->resetHeaders();
        $this->resetState();
        $this->ConfigPath = $this->createConfigFile();
    }

    protected function tearDown(): void
    {
        $this->resetState();
        $this->resetHeaders();
        $this->resetDBSCSingleton();
        if (is_file($this->ConfigPath))
        {
            unlink($this->ConfigPath);
        }
        parent::tearDown();
    }

    public function testInitializeAndGetInstanceLifecycle(): void
    {
        $this->initializeDBSC();
        $instance = DBSC::GetInstance();
        self::assertInstanceOf(DBSC::class, $instance);
        self::assertSame($instance, DBSC::GetInstance());

        $this->expectException(LogicException::class);
        $this->initializeDBSC();
    }

    public function testIsDBSCEnabledDependsOnCookiePresence(): void
    {
        $this->initializeDBSC();
        $dbsc = DBSC::GetInstance();
        self::assertFalse($dbsc->HasDBSCCookie());

        $_COOKIE[$this->CookieName] = "cookie-secret";
        self::assertTrue($dbsc->HasDBSCCookie());
    }

    public function testEnforceReturnsTrueWithoutSessionGuard(): void
    {
        $this->initializeDBSC();
        $dbsc = DBSC::GetInstance();
        self::assertTrue($dbsc->Enforce());
    }

    public function testEnforceInvalidatesWhenCookieMissing(): void
    {
        $handler = new DBSCInvalidationHandlerTestDouble();
        $this->initializeDBSC($handler);
        $this->writeSessionValue($this->CookieName, "expected-secret");

        $result = DBSC::GetInstance()->Enforce();
        self::assertFalse($result);
        self::assertSame(1, $handler->Calls);
    }

    public function testEnforceInvalidatesWhenCookieDoesNotMatchSession(): void
    {
        $handler = new DBSCInvalidationHandlerTestDouble();
        $this->initializeDBSC($handler);

        $this->writeSessionValue($this->CookieName, "expected-secret");
        $_COOKIE[$this->CookieName] = "wrong-secret";

        $result = DBSC::GetInstance()->Enforce();
        self::assertFalse($result);
        self::assertSame(1, $handler->Calls);
    }

    public function testEnforceReturnsTrueWhenSessionAndCookieMatch(): void
    {
        $this->initializeDBSC();
        $this->writeSessionValue($this->CookieName, "same-secret");
        $_COOKIE[$this->CookieName] = "same-secret";

        self::assertTrue(DBSC::GetInstance()->Enforce());
    }

    public function testSendStartHeaderWritesAndReusesChallenge(): void
    {
        $this->initializeDBSC();
        $dbsc = DBSC::GetInstance();

        $dbsc->SendStartHeader("/custom-start");
        $firstChallenge = $this->readSessionValue("dbsc_last_challenge_test");
        self::assertIsString($firstChallenge);
        self::assertNotSame("", $firstChallenge);

        $this->resetHeaders();
        $dbsc->SendStartHeader("/custom-start");
        $secondChallenge = $this->readSessionValue("dbsc_last_challenge_test");
        self::assertSame($firstChallenge, $secondChallenge);
    }

    public function testVerifyChallengeAcceptsKnownGoodInitialJwt(): void
    {
        $this->initializeDBSC();
        $dbsc = DBSC::GetInstance();
        $expectedChallenge = "v4rza1mNTrVMqlQKg0ZBsxBiGFAhBbSIbXpCoJiWMfU";

        $result = $this->invokeVerifyChallenge($dbsc, $expectedChallenge, self::VALID_INITTIAL_JWT, self::VALID_INITTIAL_JWT);

        self::assertTrue($result, "Known good initial JWT should pass VerifyChallenge for matching jti");
    }

    public function testStartDBSCSessionSetsExpectedHeaders(): void
    {
        $this->initializeDBSC();
        $this->writeSessionValue("dbsc_last_challenge_test", "v4rza1mNTrVMqlQKg0ZBsxBiGFAhBbSIbXpCoJiWMfU");
        $_SERVER["HTTP_SECURE_SESSION_RESPONSE"] = self::VALID_INITTIAL_JWT;

        DBSC::GetInstance()->StartDBSCSession();

        $this->assertHeaderContains("Content-Type", "application/json");
        $this->assertHeaderContains("Cache-Control", "no-store");
    }

    public function testRefreshWithoutChallengeResponseSetsChallengeHeaderAnd403(): void
    {
        $this->initializeDBSC();
        $sessionSecret = "refresh-secret";
        $this->writeSessionValue($this->CookieName, $sessionSecret);
        $_SERVER["HTTP_SEC_SECURE_SESSION_ID"] = $sessionSecret;
        unset($_SERVER["HTTP_SECURE_SESSION_RESPONSE"]);

        DBSC::GetInstance()->Refresh();

        self::assertSame(403, http_response_code());
        $this->assertHeaderContains("Secure-Session-Challenge", ";id=\"$sessionSecret\"");
    }

    public function testRefreshWithChallengeResponseSetsExpectedHeaders(): void
    {
        $this->initializeDBSC();
        $sessionSecret = "refresh-secret";
        $challenge = "v4rza1mNTrVMqlQKg0ZBsxBiGFAhBbSIbXpCoJiWMfU";
        $this->writeSessionValue($this->CookieName, $sessionSecret);
        $this->writeSessionValue("dbsc_user_jwt_test", self::VALID_INITTIAL_JWT);
        $this->writeSessionValue("dbsc_last_challenge_test", $challenge);
        $_SERVER["HTTP_SEC_SECURE_SESSION_ID"] = $sessionSecret;
        $_SERVER["HTTP_SECURE_SESSION_RESPONSE"] = self::VALID_INITTIAL_JWT;

        DBSC::GetInstance()->Refresh();

        $this->assertHeaderContains("Content-Type", "application/json");
        $this->assertHeaderContains("Cache-Control", "no-store");
    }

    private function createConfigFile(): string
    {
        $configPath = __DIR__ . "/DBSCConfig.test.json";
        $config = [
            "CookieName" => $this->CookieName,
            "SessionUserJwtKey" => "dbsc_user_jwt_test",
            "SessionLastChallengeKey" => "dbsc_last_challenge_test",
            "StartEndpoint" => "/app/Common/DBSC/start.php",
            "StartResponseCookieDomain" => ".example.test",
            "StartResponseOriginDomain" => "https://example.test",
            "RefreshEndpoint" => "/app/Common/DBSC/refresh.php",
            "CookieRefreshLifetimeSeconds" => 600,
            "CookiePath" => "/",
            "CookieDomain" => ".example.test",
            "CookieSecure" => true,
            "CookieHttpOnly" => true,
            "CookieSameSite" => "Lax",
            "AutoEnforce" => true,
            "DestroySessionOnInvalidate" => true,
        ];

        file_put_contents($configPath, json_encode($config, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
        return $configPath;
    }

    private function writeSessionValue(string $key, string $value): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE)
        {
            session_start(["read_and_close" => false]);
        }

        $_SESSION[$key] = $value;
        session_write_close();
    }

    private function readSessionValue(string $key): mixed
    {
        if (session_status() !== PHP_SESSION_ACTIVE)
        {
            session_start(["read_and_close" => false]);
        }
        $value = $_SESSION[$key] ?? null;
        session_write_close();
        return $value;
    }

    private function resetState(): void
    {
        unset($_COOKIE[$this->CookieName]);
        if (session_status() !== PHP_SESSION_ACTIVE)
        {
            session_start(["read_and_close" => false]);
        }
        unset($_SESSION[$this->CookieName], $_SESSION["dbsc_last_challenge_test"], $_SESSION["dbsc_user_jwt_test"]);
        session_write_close();
    }

    private function resetHeaders(): void
    {
        if (function_exists("header_remove"))
        {
            header_remove();
        }
        http_response_code(200);
    }

    private function resetDBSCSingleton(): void
    {
        $reflection = new ReflectionClass(DBSC::class);
        $property = $reflection->getProperty("Instance");
        /** @noinspection PhpExpressionResultUnusedInspection */
        $property->setAccessible(true);
        $property->setValue(null, null);
    }

    private function initializeDBSC(?IDBSCInvalidationHandler $invalidationHandler = null): void
    {
        DBSC::Initialize($this->ConfigPath, $invalidationHandler);
    }

    private function invokeVerifyChallenge(DBSC $dbsc, string $challenge, string $jwt, string $userKey): bool
    {
        $reflection = new ReflectionClass(DBSC::class);
        $method = $reflection->getMethod("VerifyChallenge");
        /** @noinspection PhpExpressionResultUnusedInspection */
        $method->setAccessible(true);
        return $method->invoke($dbsc, $challenge, $jwt, $userKey);
    }

    private function assertHeaderContains(string $headerName, string $expectedFragment): void
    {
        $headers = $this->getInspectableHeaders();
        if ($headers === null)
        {
            $this->markTestSkipped("Header inspection is not available in this PHP runtime.");
        }

        foreach ($headers as $headerLine)
        {
            if (stripos($headerLine, $headerName . ":") === 0 && stripos($headerLine, $expectedFragment) !== false)
            {
                self::assertTrue(true);
                return;
            }
        }

        self::fail("Expected header '$headerName' to contain '$expectedFragment'. Headers: " . json_encode($headers));
    }

    private function getInspectableHeaders(): ?array
    {
        if (function_exists("xdebug_get_headers"))
        {
            $xdebugHeaders = xdebug_get_headers();
            if (is_array($xdebugHeaders))
            {
                return $xdebugHeaders;
            }
        }

        $nativeHeaders = headers_list();
        if (!empty($nativeHeaders))
        {
            return $nativeHeaders;
        }

        return null;
    }
}

class DBSCInvalidationHandlerTestDouble implements IDBSCInvalidationHandler
{
    public int $Calls = 0;

    public function InvalidateSensitiveInfo(): void
    {
        $this->Calls++;
    }
}
