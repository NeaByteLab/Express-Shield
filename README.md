# 🛡️ @neabyte/express-shield

[![release](https://img.shields.io/github/v/tag/NeaByteLab/Express-Shield)](https://github.com/NeaByteLab/Express-Shield/releases)
[![npm version](https://img.shields.io/npm/v/@neabyte/express-shield.svg)](https://www.npmjs.com/package/@neabyte/express-shield)
[![CI](https://img.shields.io/github/actions/workflow/status/NeaByteLab/Express-Shield/ci.yml?branch=main)](https://github.com/NeaByteLab/Express-Shield/actions)
[![coverage](https://img.shields.io/codecov/c/github/NeaByteLab/express-shield)](https://codecov.io/gh/NeaByteLab/express-shield)

Lightweight Express middleware for **rate limiting**, **unique client fingerprinting**, Cloudflare-aware IP trust, and **essential security headers** 🛡️  
Now with **auto-updated Cloudflare IP lists**, **hot-reload without restart**, and **zero dependency design** for production-grade security and flexibility.

---

## ✨ Features

* 🔁 **Auto-updated Cloudflare IPs**: Automatically keeps the IP whitelist in sync with Cloudflare’s official ranges (IPv4/IPv6) and hot-reloads without restart.
* 🚦 **Rate Limiting**: Configurable time window and maximum requests per IP address (with Cloudflare trusted IP logic).
* 🔒 **Fingerprinting**: Generates a unique, consistent client fingerprint for better request tracking.
* 🛡️ **Security Headers**: Automatically applies crucial HTTP security headers (`X-Content-Type-Options`, `Strict-Transport-Security`, `X-Frame-Options`, `Referrer-Policy`, and more).
* 🎨 **Custom Error Responses**: Override default 429 (Too Many Requests) handler with custom logic/format.
* 📦 **Modular Design**: Redis is optional; rate limiting is skipped if no Redis is supplied.
* ⚙️ **TypeScript Support**: Built-in `.d.ts` types, fully typed exports.
* 🔄 **Zero External Dependency**: No deps except Express and (optionally) ioredis for rate-limit.

---

## 🚀 Installation

```sh
npm install @neabyte/express-shield
```

> Requires Node.js >=18.20.8
* After install, Cloudflare IPs are fetched to `data/` folder.
* To update manually: `node ./script/update-cloudflare-ip.js`

---

## 🛠️ Quick Start

### With Redis (Enables Rate Limiting)

```js
const express = require('express')
const Redis = require('ioredis')
const { createExpressShield } = require('@neabyte/express-shield')

const app = express()
const redisClient = new Redis()

app.use(
  createExpressShield(
    redisClient,
    {
      app,
      windowSec: 60,
      maxRequests: 10,
      showHeader: true,
      showLog: false,
      applySecurity: true,
      customErrorResponse: (req, res, ttl) => {
        res.status(429).json({
          error: 'Too many requests',
          ip: req.fingerprint.ip,
          retryAfterSec: ttl
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

app.use(
  createExpressShield(
    null,
    {
      app,
      applySecurity: true
    }
  )
)

app.get('/', (req, res) => {
  res.send('Hello, world! 🎉 This route is protected with security headers.')
})

app.listen(3000, () => console.log('Server running on port 3000 🚀'))
```

---

## ⚡ Cloudflare IP Support

* The IP whitelist used for trusting `cf-connecting-ip` is **auto-updated** using [Cloudflare’s published range](https://www.cloudflare.com/ips/).
* After install, files `data/cloudflare_ipv4.json` and `data/cloudflare_ipv6.json` are created/updated.
* IPs are **hot-reloaded** at runtime (no restart needed).
* To force reload in app code:

  ```js
  const { reloadCloudflareIpList } = require('@neabyte/express-shield')
  reloadCloudflareIpList()
  ```

---

## 🧩 Parameters & Defaults

| Parameter                     | Type      | Default              | Description                                                    |
| ----------------------------- | --------- | -------------------- | -------------------------------------------------------------- |
| `redisClient`                 | object?   | `null`               | Optional `ioredis` instance. If falsy, disables rate limiting. |
| `options.app`                 | Express   | `null`               | Express app instance for header patching.                      |
| `options.windowSec`           | number    | `60`                 | Duration of the rate limit window (seconds).                   |
| `options.maxRequests`         | number    | `10`                 | Max allowed requests per IP within the window.                 |
| `options.showHeader`          | boolean   | `true`               | Show `X-Fingerprint-Id` header.                                |
| `options.showLog`             | boolean   | `false`              | Enable debug console logging.                                  |
| `options.applySecurity`       | boolean   | `true`               | Apply HTTP security headers.                                   |
| `options.customErrorResponse` | function  | default 429 JSON     | Custom 429 handler. `(req, res, ttl) => void`                  |
| `options.whitelist`           | string\[] | `[]`                 | Skip rate-limit for these IPs.                                 |
| `options.ipResolver`          | function  | `getClientIpAddress` | Custom IP resolver (rarely needed).                            |

---

## 📖 API Reference

* **`createExpressShield(redisClient, options)`**  
  Creates the Express middleware. Handles security headers, fingerprinting, rate limit (if Redis provided).

* **`getClientIpAddress(req)`**  
  Returns the trusted client IP. Automatically checks `cf-connecting-ip` if request comes from Cloudflare IP range.

* **`generateFingerprintHash(req)`**  
  Returns a SHA256 hash of client IP + headers (used for fingerprinting).

* **`reloadCloudflareIpList()`**  
  Forces reload of Cloudflare IPv4 + IPv6 lists from `data/` folder. Useful for manual reload or custom schedulers.

* **`watchCloudflareIpList()`**  
  Starts file watcher. Automatically reloads Cloudflare IPs when `data/cloudflare_ipv4.json` or `data/cloudflare_ipv6.json` change.

* **`CLOUDFLARE_IPV4` / `CLOUDFLARE_IPV6`**  
  Exposes current trusted Cloudflare IP lists (arrays of CIDR).

* **`checkIpInCidrList(ip, cidrList)`**  
  Utility to check if an IP (IPv4/IPv6) is within any CIDR in the list.

* **`checkIpv4InCidr(ip, cidr)` / `checkIpv6InCidr(ip, cidr)`**  
  Low-level CIDR match utilities for IPv4 / IPv6.

* **`convertIpv4ToNumber(ip)` / `convertIpv6ToBigint(ip)`**  
  Internal helpers to convert IP addresses for CIDR math (exposed for testability).

> Note: All utility functions are exposed primarily for testing and advanced use cases.  
> Typical users only need `createExpressShield` and optionally `reloadCloudflareIpList`.

---

## ✅ Running Tests Locally

```sh
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

## 📬 Questions / Support

For questions, issues or feature requests, please open an [issue](https://github.com/NeaByteLab/Express-Shield/issues) or start a [discussion](https://github.com/NeaByteLab/Express-Shield/discussions).

---

## 🗒️ Changelog

See [CHANGELOG.md](./CHANGELOG.md) for all updates.

---

## 📜 License

MIT License © 2025 NeaByteLab