🛡️ @neabyte/express-shield

[![npm version](https://img.shields.io/npm/v/@neabyte/express-shield.svg)](https://www.npmjs.com/package/@neabyte/express-shield)
[![CI](https://img.shields.io/github/actions/workflow/status/NeaByteLab/Express-Shield/ci.yml?branch=main)](https://github.com/NeaByteLab/Express-Shield/actions)
[![coverage](https://img.shields.io/codecov/c/github/NeaByteLab/express-shield)](https://codecov.io/gh/NeaByteLab/express-shield)

A lightweight and robust Express middleware designed to enhance your application's security through efficient rate limiting, unique client fingerprinting, and automatic application of essential security headers.

---

## ✨ Features

- 🚦 **Rate Limiting**: Configurable time window and maximum requests per IP address to prevent abuse.

- 🔒 **Fingerprinting**: Generates a unique, consistent client fingerprint for better request tracking.

- 🛡️ **Security Headers**: Automatically applies crucial HTTP security headers, including `X-Content-Type-Options`, `Strict-Transport-Security`, `X-Frame-Options`, and `X-Powered-By`.

- 🎨 **Custom Error Responses**: Allows overriding the default 429 (Too Many Requests) handler with custom logic and response formats.

- 📦 **Modular Design**: Optional Redis support; rate limiting is automatically skipped when no Redis client is provided, offering flexibility.

- ⚙️ **TypeScript Support**: Includes built-in `.d.ts` declarations for a seamless development experience with full autocomplete.

- 🔄 **Minimal & Lightweight**: Zero external dependencies beyond Express and the optional `ioredis`.


## 🚀 Installation

```bash
npm install @neabyte/express-shield
```

> Requires Node.js >=18.20.8 📌

---

## 🛠️ Quick Start

### With Redis (Enables Rate Limiting)
```js
const express = require('express')
const Redis = require('ioredis')
const { createExpressShield } = require('@neabyte/express-shield')

const app = express()
const redisClient = new Redis() // Initialize your Redis client

// Apply the middleware with Redis for rate limiting
app.use(
  createExpressShield(
    redisClient, // Pass the Redis client
    {
      app, // Pass the Express app instance
      windowSec: 60, // Rate limit window of 60 seconds
      maxRequests: 10, // Allow 10 requests per IP within the window
      showHeader: true, // Include X-Fingerprint-Id header
      showLog: false, // Disable internal console logging
      applySecurity: true, // Apply security headers
      customErrorResponse: (req, res, ttl) => {
        // Custom 429 error response
        res.status(429).json({
          error: 'Too many requests',
          ip: req.fingerprint.ip,
          retryAfterSec: ttl // Time until the client can retry
        })
      }
    }
  )
)

app.get('/', (req, res) => {
  res.send('Hello, world! 🎉 This route is protected with rate limiting and security headers.')
})

app.listen(3000, () => console.log('Server running on port 3000 🚀'))
```

### Without Redis (Skips Rate Limiting)
```js
const express = require('express')
const { createExpressShield } = require('@neabyte/express-shield')

const app = express()

// Apply the middleware without Redis (rate limiting will be skipped)
app.use(
  createExpressShield(
    null, // Pass null or undefined as the Redis client
    {
      app, // Pass the Express app instance
      applySecurity: true // Still applies security headers
    }
  )
)

app.get('/', (req, res) => {
  res.send('Hello, world! 🎉 This route is protected with security headers.')
})

app.listen(3000, () => console.log('Server running on port 3000 🚀'))
```

---

## 🧩 Parameters & Defaults
The `createExpressShield` function accepts a `redisClient` and an `options` object.

| Parameter | Type | Default | Description |
| :----- | :----- | :----- | :----- |
| `redisClient` | `object?` | `null` | Optional `ioredis` client instance. If falsy, rate limiting is bypassed. |
| `options.app` | `Express` | `null` | **Required** Express application instance for applying security headers. |
| `options.windowSec` | `number` | `60` | The duration, in seconds, for the rate-limit window. |
| `options.maxRequests` | `number` | `10` | The maximum allowed requests per unique IP within the `windowSec` period. |
| `options.showHeader` | `boolean` | `true` | If `true`, includes the `X-Fingerprint-Id` header in responses. |
| `options.showLog` | `boolean` | `false` | If `true`, enables console logging for internal events and actions. |
| `options.applySecurity` | `boolean` | `true` | If `true`, applies a set of standard HTTP security headers to responses. |
| `options.customErrorResponse` | `function` | Default 429 JSON response | A custom function to handle responses when a client hits the rate limit. Signature: `(req, res, ttl) => void`. |
| `options.ipResolver` | `function` | `getClientIpAddress(req)` | An optional custom function to determine the client's IP address from the request object. Signature: `(req) => string`. |

---

## 📖 API Reference

* **`createExpressShield(redisClient, options)`**
  * The main factory function that returns the Express middleware.
  * `@param {object | null} redisClient` - An `ioredis` client instance or `null`.
  * `@param {object} options` - Configuration options (see "Parameters & Defaults" table).
  * `@returns {function}` - An Express middleware function.

* **`getClientIpAddress(req)`**
  * A utility function used internally to detect the client's IP address. It checks `X-Forwarded-For` and `req.ip`.
  * `@param {object} req` - The Express request object.
  * `@returns {string}` - The detected IP address.

* **`generateFingerprintHash(req)`**
  * A utility function that generates a SHA256 fingerprint based on the client's IP address, User-Agent, and Accept headers.
  * `@param {object} req` - The Express request object.
  * `@returns {string}` - The generated SHA256 fingerprint hash.

---

## ✅ Running Tests Locally

To run the unit tests for this project, clone the repository and execute the following commands:

```bash
npm install
npm test
```

---

## ❤️ Contributing

1. Fork the repo 🔱
2. Create your feature branch (`git checkout -b feature/your-feature-name`)
3. Commit your changes (`git commit -am 'Add some your-feature-name'`)
4. Push to the branch (`git push origin feature/your-feature-name`)
5. Open a Pull Request 📬

---

## 📜 License

MIT License © 2025 NeaByteLab