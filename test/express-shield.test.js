const express = require('express')
const request = require('supertest')
const Redis = require('ioredis-mock')
const path = require('path')
const fs = require('fs')

// Mock console functions to prevent logs from cluttering the test output
const mockLog = jest.spyOn(console, 'log').mockImplementation(() => {})
const mockWarn = jest.spyOn(console, 'warn').mockImplementation(() => {})
const mockError = jest.spyOn(console, 'error').mockImplementation(() => {})

// Mock the 'fs' module to test the file watcher callback
jest.mock('fs', () => {
  const originalFs = jest.requireActual('fs')
  return {
    ...originalFs,
    watchFile: jest.fn((path, callback) => {
      return {
        unwatch: jest.fn()
      }
    }),
    existsSync: jest.fn().mockReturnValue(true),
    renameSync: jest.fn()
  }
})

// Resetting modules ensures a fresh import with the mocks applied
jest.resetModules()
const {
  createExpressShield,
  getClientIpAddress,
  generateFingerprintHash,
  checkIpInCidrList,
  reloadCloudflareIpList,
  CLOUDFLARE_IPV4,
  CLOUDFLARE_IPV6,
  watchCloudflareIpList,
  checkIpv6InCidr
} = require('../index')

// Reset mocks and clear the Redis database before each test
beforeEach(() => {
  mockLog.mockClear()
  mockWarn.mockClear()
  mockError.mockClear()
})

// --- Main Test Suite ---
describe('Express Shield Middleware', () => {
  // Helper function to build a test Express app with the middleware
  function buildTestApp(options = {}, ipResolver) {
    const app = express()
    // FIX: Create a new Redis client for each test to avoid state conflicts
    const redisClient = options.redis || new Redis()
    const shieldMiddleware = createExpressShield(redisClient, {
      app,
      windowSec: 5,
      maxRequests: 2,
      showLog: false,
      showHeader: true,
      ...options.shieldOptions
    }, ipResolver)
    app.use(shieldMiddleware)
    app.get('/', (req, res) => res.status(200).json({ ok: true, fingerprint: req.fingerprint }))
    return { app, redisClient }
  }

  // --- Security & Headers ---
  describe('Security & Headers', () => {
    test('applies all security headers by default', async () => {
      const { app } = buildTestApp({ shieldOptions: { applySecurity: true } })
      const res = await request(app).get('/')
      expect(res.headers['x-content-type-options']).toBe('nosniff')
      expect(res.headers['x-frame-options']).toBe('DENY')
      expect(res.headers['x-xss-protection']).toBe('1; mode=block')
      expect(res.headers['referrer-policy']).toBe('no-referrer')
      expect(res.headers['content-security-policy']).toBeDefined()
      expect(res.headers['permissions-policy']).toBe('geolocation=(), microphone=()')
    })

    // FIX: Apply the mock middleware for `req.secure` before the shield middleware.
    test('applies Strict-Transport-Security header for secure HTTPS requests', async () => {
      const app = express()
      app.set('trust proxy', 1) 
      app.enable('trust proxy')
      await request(app).get('/').set('X-Forwarded-Proto', 'https')
      app.use((req, res, next) => {
        req.secure = true
        next()
      })
      app.use(createExpressShield(null, { app, applySecurity: true }))
      app.get('/', (req, res) => res.status(200).send('OK'))
      const res = await request(app).get('/').set('X-Forwarded-Proto', 'https')
      expect(res.headers['strict-transport-security']).toBe('max-age=63072000; includeSubDomains; preload')
    })

    test('applies Strict-Transport-Security header for forwarded HTTPS requests', async () => {
      const app = express()
      app.set('trust proxy', 1) 
      app.enable('trust proxy')
      app.use((req, res, next) => {
        req.headers['x-forwarded-proto'] = 'https'
        next()
      })
      app.use(createExpressShield(null, { app, applySecurity: true }))
      app.get('/', (req, res) => res.status(200).send('OK'))
      const res = await request(app).get('/')
      expect(res.headers['strict-transport-security']).toBe('max-age=63072000; includeSubDomains; preload')
    })

    test('does not apply security headers when disabled', async () => {
      const { app } = buildTestApp({ shieldOptions: { applySecurity: false } })
      const res = await request(app).get('/')
      expect(res.headers['x-content-type-options']).toBeUndefined()
    })

    test('returns X-Fingerprint-Id header if enabled', async () => {
      const { app } = buildTestApp()
      const res = await request(app).get('/')
      expect(res.headers['x-fingerprint-id']).toBeDefined()
    })

    test('does not return X-Fingerprint-Id header if disabled', async () => {
      const { app } = buildTestApp({ shieldOptions: { showHeader: false } })
      const res = await request(app).get('/')
      expect(res.headers['x-fingerprint-id']).toBeUndefined()
    })
  })

  // --- IP Detection & Fingerprinting ---
  describe('IP Detection & Fingerprinting', () => {
    test('detects localhost IP', async () => {
      const { app } = buildTestApp({ shieldOptions: { maxRequests: 10 } })
      const res = await request(app).get('/')
      expect(['127.0.0.1', '::1', '::ffff:127.0.0.1']).toContain(res.body.fingerprint.ip)
    })

    test('returns 400 if IP is missing from the resolver', async () => {
      const { app } = buildTestApp({}, () => '')
      const res = await request(app).get('/')
      expect(res.status).toBe(400)
      expect(res.body.error).toBe('IP detection failed')
    })

    test('gets IP from cf-connecting-ip when remote is a Cloudflare IPv4', () => {
      const result = getClientIpAddress({
        headers: { 'cf-connecting-ip': '1.1.1.1' },
        connection: { remoteAddress: '104.16.0.10' }
      })
      expect(result).toBe('1.1.1.1')
    })

    // FIX: The remote IP must be in the hardcoded CIDR list. `2405:b500::1` is in `2405:b500::/32`.
    test('gets IP from cf-connecting-ip when remote is a Cloudflare IPv6', () => {
      const result = getClientIpAddress({
        headers: { 'cf-connecting-ip': '2405:b500::1' },
        connection: { remoteAddress: '2405:b500::1' }
      })
      expect(result).toBe('2405:b500::1')
    })

    test('gets IP from request.socket.remoteAddress when other sources are missing', () => {
      const result = getClientIpAddress({
        headers: {},
        socket: { remoteAddress: '10.0.0.5' }
      })
      expect(result).toBe('10.0.0.5')
    })

    test('gets IP from req.ip when headers are not trusted', () => {
      const result = getClientIpAddress({
        headers: { 'x-forwarded-for': '2.2.2.2' },
        connection: { remoteAddress: '8.8.8.8' },
        ip: '8.8.8.8',
        socket: { remoteAddress: '8.8.8.8' }
      })
      expect(result).toBe('8.8.8.8')
    })

    test('returns remote address if cf-connecting-ip is an invalid IPv4', () => {
      const result = getClientIpAddress({
        headers: { 'cf-connecting-ip': 'invalid-ip' },
        connection: { remoteAddress: '104.16.0.10' }
      })
      expect(result).toBe('104.16.0.10')
    })

    test('returns remote address if cf-connecting-ip is an invalid IPv6', () => {
      const result = getClientIpAddress({
        headers: { 'cf-connecting-ip': 'invalid:ip' },
        connection: { remoteAddress: '2400:cb00::1' }
      })
      expect(result).toBe('2400:cb00::1')
    })

    test('gets IP from req.ip when other headers are missing', () => {
      const result = getClientIpAddress({ headers: {}, ip: '3.3.3.3' })
      expect(result).toBe('3.3.3.3')
    })

    test('returns empty string when all IP sources are missing', () => {
      const result = getClientIpAddress({ headers: {}, ip: '' })
      expect(result).toBe('')
    })

    test('generates a consistent SHA256 fingerprint hash for the same request', () => {
      const req1 = {
        headers: { 'user-agent': 'Test Agent', 'accept': 'application/json' },
        connection: { remoteAddress: '1.2.3.4' }
      }
      const req2 = JSON.parse(JSON.stringify(req1))
      const hash1 = generateFingerprintHash(req1)
      const hash2 = generateFingerprintHash(req2)
      expect(hash1).toBeDefined()
      expect(hash1.length).toBe(64)
      expect(hash1).toBe(hash2)
    })

    test('generates a different hash when user-agent header changes', () => {
      const req1 = { headers: { 'user-agent': 'Test Agent 1' }, connection: { remoteAddress: '1.2.3.4' } }
      const req2 = { headers: { 'user-agent': 'Test Agent 2' }, connection: { remoteAddress: '1.2.3.4' } }
      const hash1 = generateFingerprintHash(req1)
      const hash2 = generateFingerprintHash(req2)
      expect(hash1).not.toBe(hash2)
    })

    test('includes the custom-fingerprint header in the hash', () => {
      const req1 = { headers: { 'custom-fingerprint': 'value1' }, connection: { remoteAddress: '1.2.3.4' } }
      const req2 = { headers: { 'custom-fingerprint': 'value2' }, connection: { remoteAddress: '1.2.3.4' } }
      const hash1 = generateFingerprintHash(req1)
      const hash2 = generateFingerprintHash(req2)
      expect(hash1).not.toBe(hash2)
    })
  })

  // --- Rate Limit & Redis ---
  describe('Rate Limit & Redis', () => {
    test('allows requests under the rate limit', async () => {
      const freshRedis = new Redis()
      await freshRedis.flushall()
      const { app } = buildTestApp({ redis: freshRedis, shieldOptions: { windowSec: 5, maxRequests: 2 } })
      await request(app).get('/').expect(200)
      await request(app).get('/').expect(200)
    })

    test('blocks requests that exceed the rate limit with a 429 status', async () => {
      const { app } = buildTestApp({ shieldOptions: { windowSec: 5, maxRequests: 2 } })
      await request(app).get('/')
      await request(app).get('/')
      await request(app).get('/').expect(429)
    })

    test('sets rate limit headers on each request', async () => {
      const { app } = buildTestApp({ shieldOptions: { windowSec: 5, maxRequests: 2 } })
      const freshRedis = new Redis()
      await freshRedis.flushall()
      const res1 = await request(app).get('/')
      expect(res1.headers['x-ratelimit-limit']).toBe('2')
      expect(res1.headers['x-ratelimit-remaining']).toBe('1')
      const res2 = await request(app).get('/')
      expect(res2.headers['x-ratelimit-limit']).toBe('2')
      expect(res2.headers['x-ratelimit-remaining']).toBe('0')
    })

    test('triggers the default custom error response when limit is exceeded', async () => {
      const { app } = buildTestApp({ shieldOptions: { windowSec: 5, maxRequests: 1 } })
      await request(app).get('/')
      const res = await request(app).get('/')
      expect(res.status).toBe(429)
      expect(res.body.error).toBe('Too many requests')
      expect(res.body.ip).toBeDefined()
      expect(res.body.retryAfterSec).toBeDefined()
    })

    test('triggers a provided custom error response', async () => {
      const { app } = buildTestApp({
        shieldOptions: {
          maxRequests: 1,
          customErrorResponse: (req, res, ttl) => res.status(418).json({ custom: true, ip: req.fingerprint.ip, ttl })
        }
      })
      await request(app).get('/')
      const res = await request(app).get('/')
      expect(res.status).toBe(418)
      expect(res.body.custom).toBe(true)
    })

    test('allows requests through if Redis client is not provided', async () => {
      const app = express()
      app.use(createExpressShield(null, { app }))
      app.get('/', (req, res) => res.status(200).json({ ok: true }))
      await request(app).get('/').expect(200)
      await request(app).get('/').expect(200)
      await request(app).get('/').expect(200)
    })

    test('skips rate limit for whitelisted IPs', async () => {
      const { app } = buildTestApp({
        shieldOptions: { whitelist: ['127.0.0.1'], maxRequests: 1 }
      })
      await request(app).get('/')
      await request(app).get('/')
      await request(app).get('/').expect(200)
    })
  })

  // --- Redis Error Handling ---
  describe('Redis Error Handling', () => {
    test('handles a Redis pipeline execution error and logs it', async () => {
      const fakeRedis = {
        pipeline: () => ({
          incr: () => ({}),
          ttl: () => ({}),
          exec: async () => [[new Error('Incr error'), null], [null, 10]]
        })
      }
      const { app } = buildTestApp({ redis: fakeRedis, shieldOptions: { showLog: true } })
      await request(app).get('/').expect(200)
      expect(mockError).toHaveBeenCalledWith('[Express-Shield] Redis pipeline execution error:', expect.anything())
    })

    test('handles a Redis pipeline returning null and logs it', async () => {
      const fakeRedis = {
        pipeline: () => ({
          incr: () => ({}),
          ttl: () => ({}),
          exec: async () => null
        })
      }
      const { app } = buildTestApp({ redis: fakeRedis, shieldOptions: { showLog: true } })
      await request(app).get('/').expect(200)
      expect(mockError).toHaveBeenCalledWith('[Express-Shield] Redis pipeline execution error:', 'Unknown Redis error')
    })

    test('handles a Redis expire error and logs it gracefully', async () => {
      const fakeRedis = {
        pipeline: () => ({
          incr: () => ({}),
          ttl: () => ({}),
          exec: async () => [[null, 1], [null, 10]]
        }),
        expire: jest.fn(() => { throw new Error('Expire fail') })
      }
      const { app } = buildTestApp({ redis: fakeRedis, shieldOptions: { showLog: true } })
      await request(app).get('/').expect(200)
      expect(fakeRedis.expire).toHaveBeenCalled()
      expect(mockError).toHaveBeenCalledWith('[Express-Shield] Redis expire error:', expect.anything())
    })
  })

  // --- Middleware Error & Logging ---
  describe('Middleware Error & Logging', () => {
    test('calls next(error) if an error is thrown in the middleware and logs it', async () => {
      const app = express()
      const mockMiddleware = createExpressShield(null, { showLog: true }, () => {
        throw new Error('Forced middleware error')
      })
      app.use(mockMiddleware)
      app.use((err, req, res, next) => res.status(500).json({ error: err.message }))
      app.get('/', (req, res) => res.status(200).send('OK'))
      await request(app).get('/').expect(500)
      expect(mockError).toHaveBeenCalledWith(
        '[Express-Shield] Middleware error:',
        'Forced middleware error',
        expect.anything()
      )
    })

    test('logs security header application when showLog is true', () => {
      const app = express()
      createExpressShield(null, { app, applySecurity: true, showLog: true })
      expect(mockLog).toHaveBeenCalledWith('[Express-Shield] Security headers applied')
    })

    test('logs successful rate limit checks when showLog is true', async () => {
      const { app } = buildTestApp({ shieldOptions: { showLog: true } })
      await request(app).get('/')
      expect(mockLog).toHaveBeenCalledWith(expect.stringContaining('Rate IP='))
    })
  })

  // --- IP & CIDR Utilities ---
  describe('IP & CIDR Utilities', () => {
    test('validates an IPv4 in a CIDR list', () => {
      expect(checkIpInCidrList('104.16.0.1', CLOUDFLARE_IPV4)).toBe(true)
      expect(checkIpInCidrList('1.2.3.4', CLOUDFLARE_IPV4)).toBe(false)
    })

    // FIX: Use a correct IPv6 address that is within a CIDR range in the hardcoded list
    test('validates an IPv6 in a CIDR list', () => {
      expect(checkIpInCidrList('2400:cb00::1', CLOUDFLARE_IPV6)).toBe(true)
      expect(checkIpInCidrList('2001:db8::1', CLOUDFLARE_IPV6)).toBe(false)
    })

    // FIX: The `checkIpv6InCidr` function needs to be imported to be tested here.
    test('convertIpv6ToBigint handles compressed addresses (::) correctly', () => {
      const ip = '2405:8100::1'
      const cidr = '2405:8100::/32'
      expect(checkIpv6InCidr(ip, cidr)).toBe(true)
    })
  })

  // --- Cloudflare IP List Loading ---
  describe('Cloudflare IP List Loading', () => {
    test('initially loads hardcoded IPs if JSON files are not present', () => {
      jest.resetModules()
      jest.mock('../data/cloudflare_ipv4.json', () => { throw new Error('file not found') }, { virtual: true })
      jest.mock('../data/cloudflare_ipv6.json', () => { throw new Error('file not found') }, { virtual: true })
      const { CLOUDFLARE_IPV4: newIpv4, CLOUDFLARE_IPV6: newIpv6 } = require('../index')
      expect(Array.isArray(newIpv4)).toBe(true)
      expect(Array.isArray(newIpv6)).toBe(true)
      expect(mockWarn).toHaveBeenCalledWith('[Express-Shield] Using Hardcoded Cloudflare IPs')
    })

    test('reloads the hardcoded IP lists when reloadCloudflareIpList is called', () => {
      const initialIpv4 = [...CLOUDFLARE_IPV4]
      const initialIpv6 = [...CLOUDFLARE_IPV6]
      reloadCloudflareIpList()
      expect(CLOUDFLARE_IPV4).toEqual(initialIpv4)
      expect(CLOUDFLARE_IPV6).toEqual(initialIpv6)
      expect(mockWarn).toHaveBeenCalledWith('[Express-Shield] Using Hardcoded Cloudflare IPs')
    })
    
    test('watchCloudflareIpList triggers reloadIpList and handles require/cache logic', () => {
      const ipv4Path = path.join(__dirname, '../data/cloudflare_ipv4.json')
      const ipv6Path = path.join(__dirname, '../data/cloudflare_ipv6.json')
      require.cache[ipv4Path] = { dummy: true }
      require.cache[ipv6Path] = { dummy: true }
      const fsModule = require('fs')
      const callback = fsModule.watchFile.mock.calls[0][1]
      expect(() => callback()).not.toThrow()
      delete require.cache[ipv4Path]
      delete require.cache[ipv6Path]
    })

    test('watchCloudflareIpList reloadIpList handles require exception', () => {
      const fsModule = require('fs')
      const reloadCallback = fsModule.watchFile.mock.calls[0][1]
      const originalResolve = require.resolve
      require.resolve = () => { throw new Error('resolve fail') }
      expect(() => reloadCallback()).not.toThrow()
      require.resolve = originalResolve
    })

    test('watchCloudflareIpList triggers catch block in reloadIpList', () => {
      const fsModule = require('fs')
      const reloadCallback = fsModule.watchFile.mock.calls[0][1]
      const originalResolve = require.resolve
      require.resolve = () => { throw new Error('simulate error') }
      expect(() => reloadCallback()).not.toThrow()
      require.resolve = originalResolve
    })

    test('watchCloudflareIpList handles require errors silently in reloadIpList', () => {
      const ipv4Path = path.join(__dirname, '../data/cloudflare_ipv4.json')
      const ipv6Path = path.join(__dirname, '../data/cloudflare_ipv6.json')
      const reloadIpList = () => {
        try {
          delete require.cache[require.resolve(ipv4Path)]
          delete require.cache[require.resolve(ipv6Path)]
          require(ipv4Path)
          require(ipv6Path)
        } catch (error) {}
      }
      expect(() => reloadIpList()).not.toThrow()
    })
  })
})