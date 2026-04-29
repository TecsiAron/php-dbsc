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

class DBSCConfig
{
    public readonly string $CookieName;
    public readonly string $SessionUserJwtKey;
    public readonly string $SessionLastChallengeKey;
    public readonly string $StartEndpoint;
    public readonly string $StartResponseCookieDomain;
    public readonly string $StartResponseOriginDomain;
    public readonly string $RefreshEndpoint;
    public readonly int $CookieRefreshLifetimeSeconds;
    public readonly string $CookiePath;
    public readonly string $CookieDomain;
    public readonly bool $CookieSecure;
    public readonly bool $CookieHttpOnly;
    public readonly string $CookieSameSite;
    public readonly bool $AutoEnforce;
    public readonly bool $DestroySessionOnInvalidate;

    private function __construct(string $filePath, IDBSCLogger $logger)
    {
        $config = json_decode(file_get_contents($filePath), true);
        if(json_last_error() !== JSON_ERROR_NONE)        {
            throw new \RuntimeException("Failed to parse DBSC config file: " . json_last_error_msg());
        }
        $requiredFields=[
            "CookieName",
            "SessionUserJwtKey",
            "SessionLastChallengeKey",
            "StartEndpoint",
            "StartResponseCookieDomain",
            "StartResponseOriginDomain",
            "RefreshEndpoint",
            "CookieRefreshLifetimeSeconds",
            "CookiePath",
            "CookieDomain",
            "CookieSecure",
            "CookieHttpOnly",
            "CookieSameSite",
            "AutoEnforce",
            "DestroySessionOnInvalidate"
        ];
        $boolFields=[
            "CookieSecure",
            "CookieHttpOnly",
            "AutoEnforce",
            "DestroySessionOnInvalidate"
        ];
        foreach($requiredFields as $field)
        {
            if(!isset($config[$field]))
            {
                throw new \RuntimeException("Missing required field: $field");
            }
            if(in_array($field, $boolFields, true))
            {
                // lets be safe and allow both boolean and string representations of booleans
                if (is_bool($config[$field]))
                {
                    $this->$field = $config[$field];
                }
                else
                {
                    $normalized = strtolower($config[$field]);
                    if($normalized!=="true" && $normalized!=="false")
                    {
                        $logger->Warning("Invalid boolean value for $field: " . $config[$field] . " will be treated as false");
                    }
                    $this->$field = $normalized === "true";
                }
            }
            else if($field==="CookieRefreshLifetimeSeconds")
            {
                $this->$field = intval($config[$field]);
            }
            else
            {
                $this->$field = $config[$field];
            }
        }


    }

    public static function LoadFromFile(string $filePath, IDBSCLogger $logger): DBSCConfig
    {
        return new DBSCConfig($filePath, $logger);
    }
}
