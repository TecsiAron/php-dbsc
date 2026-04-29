# php-dbsc

Experimental PHP implementation of Device Bound Session Credentials (DBSC).

## Status

This package is **completely experimental**.

Do not treat it as production-ready security infrastructure yet. APIs, behavior, and defaults may change quickly.

## Requirements

- PHP **8.4+**
- `firebase/php-jwt` (installed automatically via Composer)

## Installation

```bash
composer require edituraedu/php-dbsc
```

## What It Provides

- `EdituraEDU\\DBSC\\DBSC` singleton for DBSC flow handling
- Start header emission (`Secure-Session-Registration`)
- Start endpoint verification (`Secure-Session-Response`)
- Refresh challenge/verification handling (`Secure-Session-Challenge`, `Sec-Secure-Session-Id`)
- Cookie + session guard enforcement
- Optional dependency injection for:
- `IDBSCLogger`
- `IDBSCInvalidationHandler`

## Quick Start

```php
<?php

use EdituraEDU\\DBSC\\DBSC;

DBSC::Initialize(__DIR__ . '/DBSCConfig.json');

// Emit registration header when client has no DBSC cookie yet:
if (!DBSC::GetInstance()->HasDBSCCookie()) {
    DBSC::GetInstance()->SendStartHeader();
}
```

### Start Endpoint

```php
<?php

use EdituraEDU\\DBSC\\DBSC;

const DBSC_START_REFRESH_FLOW = true;
DBSC::Initialize(__DIR__ . '/DBSCConfig.json');
echo json_encode(DBSC::GetInstance()->StartDBSCSession());
```

### Refresh Endpoint

```php
<?php

use EdituraEDU\\DBSC\\DBSC;

const DBSC_START_REFRESH_FLOW = true;
DBSC::Initialize(__DIR__ . '/DBSCConfig.json');
DBSC::GetInstance()->Refresh();
```

## Config

The package reads JSON config via `DBSCConfig::LoadFromFile(...)`.

Start from [`src/DBSCConfig.json`](./src/DBSCConfig.json) and adjust domains, paths, cookie flags, and endpoint paths for your environment.

## Optional Logger / Invalidation Handler

`DBSC::Initialize(...)` accepts optional custom implementations:

- `IDBSCLogger` for structured logging
- `IDBSCInvalidationHandler` for custom cleanup when DBSC invalidates a session

If no logger is passed, `DBSCLogger` is used by default.

## Notes

- Header normalization currently tolerates both raw and quoted DBSC header values for compatibility.
- This project is under active iteration, feedback and contributions are welcome!

## License

MIT
