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

use EdituraEDU\DBSC\DBSCConfig;
use EdituraEDU\DBSC\IDBSCLogger;
use PHPUnit\Framework\TestCase;

class DBSCConfigTest extends TestCase
{
    private array $baseConfig = [
        "CookieName" => "dbsc_guard_test",
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
        "AutoEnforce" => false,
        "DestroySessionOnInvalidate" => true,
    ];

    public function testLoadFromFilePreservesBooleanFalse(): void
    {
        $path = $this->writeConfig($this->baseConfig);

        try
        {
            $config = DBSCConfig::LoadFromFile($path, new DBSCConfigTestLogger());
            self::assertFalse($config->AutoEnforce);
            self::assertTrue($config->DestroySessionOnInvalidate);
        }
        finally
        {
            unlink($path);
        }
    }

    public function testLoadFromFileCastsStringBoolAndIntValues(): void
    {
        $configData = $this->baseConfig;
        $configData["CookieSecure"] = "true";
        $configData["CookieHttpOnly"] = "false";
        $configData["AutoEnforce"] = "false";
        $configData["DestroySessionOnInvalidate"] = "true";
        $configData["CookieRefreshLifetimeSeconds"] = "600";

        $path = $this->writeConfig($configData);

        try
        {
            $config = DBSCConfig::LoadFromFile($path, new DBSCConfigTestLogger());
            self::assertTrue($config->CookieSecure);
            self::assertFalse($config->CookieHttpOnly);
            self::assertFalse($config->AutoEnforce);
            self::assertTrue($config->DestroySessionOnInvalidate);
            self::assertSame(600, $config->CookieRefreshLifetimeSeconds);
        }
        finally
        {
            unlink($path);
        }
    }

    public function testLoadFromFileThrowsWhenRequiredFieldMissing(): void
    {
        $configData = $this->baseConfig;
        unset($configData["CookieName"]);

        $path = $this->writeConfig($configData);

        try
        {
            $this->expectException(\RuntimeException::class);
            $this->expectExceptionMessage("Missing required field: CookieName");
            DBSCConfig::LoadFromFile($path, new DBSCConfigTestLogger());
        }
        finally
        {
            unlink($path);
        }
    }

    public function testLoadFromFileWarnsAndTreatsInvalidBooleanAsFalse(): void
    {
        $configData = $this->baseConfig;
        $configData["CookieHttpOnly"] = "definitely-not-a-bool";
        $logger = new DBSCConfigTestLogger();
        $path = $this->writeConfig($configData);

        try
        {
            $config = DBSCConfig::LoadFromFile($path, $logger);
            self::assertFalse($config->CookieHttpOnly);
            self::assertCount(1, $logger->Warnings);
            self::assertStringContainsString("Invalid boolean value for CookieHttpOnly", $logger->Warnings[0]);
        }
        finally
        {
            unlink($path);
        }
    }

    private function writeConfig(array $config): string
    {
        $path = __DIR__ . "/DBSCConfig.unit.test.json";
        file_put_contents($path, json_encode($config, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
        return $path;
    }
}

class DBSCConfigTestLogger implements IDBSCLogger
{
    public array $Errors = [];
    public array $Warnings = [];
    public array $Info = [];

    public function Error(string $message): void
    {
        $this->Errors[] = $message;
    }

    public function Warning(string $message): void
    {
        $this->Warnings[] = $message;
    }

    public function Info(string $message): void
    {
        $this->Info[] = $message;
    }
}
