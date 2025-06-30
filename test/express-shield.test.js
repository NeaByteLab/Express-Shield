const express = require('express')
const request = require('supertest')
const Redis = require('ioredis-mock')
const { createExpressShield, getClientIpAddress, generateFingerprintHash } = require('../index')

/**
 * Express Shield Middleware Test Suite
 */
describe('Express Shield Middleware', () => {
  /**
   * Create Test Application
   * Params: OptionsObject, IpResolverFunction
   */
  function createTestApp (optionsObject = {}, ipResolverFunction) {
    const mainApp = express()
    const redisClientInstance = optionsObject.redis || new Redis()
    mainApp.use(createExpressShield(redisClientInstance, {
      app: mainApp,
      windowSec: 5,
      maxRequests: 2,
      showLog: false,
      showHeader: true,
      ...optionsObject.shieldOptions
    }, ipResolverFunction))
    mainApp.get('/', (requestObject, responseObject) => {
      responseObject.status(200).json({
        ok: true,
        fingerprint: requestObject.fingerprint
      })
    })
    return { app: mainApp, redisClient: redisClientInstance }
  }

  /**
   * Test Security Headers Application
   */
  test('Should Apply Security Headers', async () => {
    const { app: testApp } = createTestApp({ shieldOptions: { applySecurity: true } })
    const responseResult = await request(testApp).get('/')
    expect(responseResult.headers['x-content-type-options']).toBe('nosniff')
    expect(responseResult.headers['x-frame-options']).toBe('DENY')
    expect(responseResult.headers['x-xss-protection']).toBe('1; mode=block')
  })

  /**
   * Test X-Fingerprint-Id Header Return
   */
  test('Should Return X-Fingerprint-Id Header', async () => {
    const { app: testApp } = createTestApp()
    const responseResult = await request(testApp).get('/')
    expect(responseResult.headers['x-fingerprint-id']).toBeDefined()
  })

  /**
   * Test Fingerprint Header Not Set When ShowHeader Disabled
   */
  test('Should Not Set Fingerprint Header When ShowHeader Disabled', async () => {
    const { app: testApp } = createTestApp({ shieldOptions: { showHeader: false } })
    const responseResult = await request(testApp).get('/')
    expect(responseResult.headers['x-fingerprint-id']).toBeUndefined()
  })

  /**
   * Test Localhost IP Detection
   */
  test('Should Detect Localhost IP', async () => {
    const { app: testApp } = createTestApp({ shieldOptions: { maxRequests: 10 } })
    const responseResult = await request(testApp).get('/')
    expect(responseResult.body.fingerprint.ip).toMatch(/^(127\.0\.0\.1|::1)$/)
  })

  /**
   * Test 400 Response If IP Missing
   */
  test('Should Respond 400 If IP Missing', async () => {
    const { app: testApp } = createTestApp({}, () => '')
    await request(testApp).get('/').expect(400)
    const responseResult = await request(testApp).get('/')
    expect(responseResult.body.error).toBe('IP address detection failed')
  })

  /**
   * Test Fallback To Empty IP
   */
  test('Should Fallback To Empty IP', async () => {
    const newApp = express()
    const shieldMiddleware = createExpressShield(null, { app: newApp, maxRequests: 100 }, () => '')
    newApp.use(shieldMiddleware)
    newApp.get('/', (requestObject, responseObject) => responseObject.status(200).json({ ok: true }))
    await request(newApp).get('/').expect(400)
    const responseResult = await request(newApp).get('/')
    expect(responseResult.body.error).toBe('IP address detection failed')
  })

  /**
   * Test Fallback To Request IP When Headers Missing
   */
  test('Should Fallback To Request IP When Headers Missing', async () => {
    const newApp = express()
    newApp.use((requestObject, responseObject, nextFunction) => {
      delete requestObject.headers['x-forwarded-for']
      delete requestObject.headers['cf-connecting-ip']
      createExpressShield(null, { app: newApp, maxRequests: 100 })(requestObject, responseObject, nextFunction)
    })
    newApp.get('/', (requestObject, responseObject) => responseObject.status(200).json({ ok: true }))
    await request(newApp).get('/').expect(200)
  })

  /**
   * Test Rate Limit Skip If No Redis
   */
  test('Should Skip Rate Limit If No Redis', async () => {
    const newApp = express()
    newApp.use(createExpressShield(null, { app: newApp }))
    newApp.get('/', (requestObject, responseObject) => responseObject.status(200).json({ ok: true }))
    await request(newApp).get('/').expect(200)
  })

  /**
   * Test Graceful Handling Of Redis Failure
   */
  test('Should Handle Redis Fail Gracefully', async () => {
    const redisClientInstance = new Redis()
    redisClientInstance.incr = () => { throw new Error('Redis error') }
    const { app: testApp } = createTestApp({ redis: redisClientInstance })
    await request(testApp).get('/').expect(200)
  })

  /**
   * Test Graceful Handling Of Redis TTL Failure
   */
  test('Should Handle Redis TTL Fail Gracefully', async () => {
    const redisClientInstance = new Redis()
    redisClientInstance.ttl = () => { throw new Error('TTL fail') }
    const { app: testApp } = createTestApp({ redis: redisClientInstance })
    await request(testApp).get('/').expect(200)
  })

  /**
   * Test Graceful Handling Of Redis Expire Failure
   */
  test('Should Handle Redis Expire Fail Gracefully', async () => {
    const redisClientInstance = new Redis()
    redisClientInstance.expire = () => { throw new Error('Expire fail') }
    const { app: testApp } = createTestApp({ redis: redisClientInstance, shieldOptions: { maxRequests: 100 } })
    await request(testApp).get('/').expect(200)
  })

  /**
   * Test Graceful Handling Of Middleware Error With ShowLog False
   */
  test('Should Handle Middleware Error Gracefully With ShowLog False', async () => {
    const newApp = express()
    const shieldMiddleware = createExpressShield(null, { app: newApp, showLog: false }, () => { throw new Error('force') })
    newApp.use(shieldMiddleware)
    newApp.get('/', (requestObject, responseObject) => responseObject.status(200).json({ ok: true }))
    await request(newApp).get('/').expect(200)
  })

  /**
   * Test Graceful Handling Of Middleware Error With ShowLog True
   */
  test('Should Handle Middleware Error Gracefully With ShowLog True', async () => {
    const newApp = express()
    const shieldMiddleware = createExpressShield(null, { app: newApp, showLog: true }, () => { throw new Error('force') })
    newApp.use(shieldMiddleware)
    newApp.get('/', (requestObject, responseObject) => responseObject.status(200).json({ ok: true }))
    await request(newApp).get('/').expect(200)
  })

  /**
   * Test Running With ApplySecurity False And App Null
   */
  test('Should Run With ApplySecurity False And App Null', async () => {
    const shieldMiddleware = createExpressShield(null, { app: null, applySecurity: false })
    const newApp = express()
    newApp.use(shieldMiddleware)
    newApp.get('/', (requestObject, responseObject) => responseObject.status(200).json({ ok: true }))
    await request(newApp).get('/').expect(200)
  })

  /**
   * Test Running With ApplySecurity True And App Null
   */
  test('Should Run With ApplySecurity True And App Null', async () => {
    const shieldMiddleware = createExpressShield(null, { app: null, applySecurity: true })
    const newApp = express()
    newApp.use(shieldMiddleware)
    newApp.get('/', (requestObject, responseObject) => responseObject.status(200).json({ ok: true }))
    await request(newApp).get('/').expect(200)
  })

  /**
   * Test Running With ApplySecurity True And App Undefined
   */
  test('Should Run With ApplySecurity True And App Undefined', async () => {
    const shieldMiddleware = createExpressShield(null, { app: undefined, applySecurity: true })
    const newApp = express()
    newApp.use(shieldMiddleware)
    newApp.get('/', (requestObject, responseObject) => responseObject.status(200).json({ ok: true }))
    await request(newApp).get('/').expect(200)
  })

  /**
   * Test Running With ApplySecurity False And App Undefined
   */
  test('Should Run With ApplySecurity False And App Undefined', async () => {
    const shieldMiddleware = createExpressShield(null, { app: undefined, applySecurity: false })
    const newApp = express()
    newApp.use(shieldMiddleware)
    newApp.get('/', (requestObject, responseObject) => responseObject.status(200).json({ ok: true }))
    await request(newApp).get('/').expect(200)
  })

  /**
   * Test Running With ApplySecurity False And App Provided
   */
  test('Should Run With ApplySecurity False And App Provided', async () => {
    const { app: testApp } = createTestApp({
      shieldOptions: { applySecurity: false, maxRequests: 100 }
    })
    await request(testApp).get('/').expect(200)
  })

  /**
   * Test Logging When ShowLog Enabled
   */
  test('Should Log When ShowLog Enabled', async () => {
    const { app: testApp } = createTestApp({ shieldOptions: { showLog: true, maxRequests: 100 } })
    await request(testApp).get('/').expect(200)
  })

  /**
   * Test Running With ShowLog Disabled
   */
  test('Should Run With ShowLog Disabled', async () => {
    const { app: testApp } = createTestApp({ shieldOptions: { showLog: false, maxRequests: 100 } })
    await request(testApp).get('/').expect(200)
  })

  /**
   * Test Getting IP From CF Connecting IP Header
   */
  test('Should Get IP From CF Connecting IP', () => {
    const clientIp = getClientIpAddress({ headers: { 'cf-connecting-ip': '1.1.1.1' } })
    expect(clientIp).toBe('1.1.1.1')
  })

  /**
   * Test Getting IP From X-Forwarded-For When CF Missing
   */
  test('Should Get IP From X-Forwarded-For When CF Missing', () => {
    const clientIp = getClientIpAddress({ headers: { 'x-forwarded-for': '2.2.2.2' } })
    expect(clientIp).toBe('2.2.2.2')
  })

  /**
   * Test Getting IP From req.ip When Headers Missing
   */
  test('Should Get IP From req.ip When Headers Missing', () => {
    const clientIp = getClientIpAddress({ headers: {}, ip: '3.3.3.3' })
    expect(clientIp).toBe('3.3.3.3')
  })

  /**
   * Test Getting Empty IP When All Sources Missing
   */
  test('Should Get Empty IP When All Sources Missing', () => {
    const clientIp = getClientIpAddress({ headers: {}, ip: '' })
    expect(clientIp).toBe('')
  })

  /**
   * Test Generate Fingerprint Hash
   */
  test('Should Generate Consistent Fingerprint Hash', () => {
    const mockRequestOne = {
      headers: {
        'cf-connecting-ip': '192.168.1.1',
        'user-agent': 'Test Agent',
        'accept': 'application/json',
        'accept-language': 'en-US',
        'sec-ch-ua': 'Brave'
      }
    }
    const mockRequestTwo = {
      headers: {
        'cf-connecting-ip': '192.168.1.1',
        'user-agent': 'Test Agent',
        'accept': 'application/json',
        'accept-language': 'en-US',
        'sec-ch-ua': 'Brave'
      }
    }
    const hashOne = generateFingerprintHash(mockRequestOne)
    const hashTwo = generateFingerprintHash(mockRequestTwo)
    expect(hashOne).toBeDefined()
    expect(hashOne.length).toBe(64)
    expect(hashOne).toBe(hashTwo)
  })

  /**
   * Test Allowing Requests Under Rate Limit
   */
  test('Should Allow Requests Under Limit', async () => {
    const freshRedisInstance = new Redis()
    await freshRedisInstance.flushall()
    const newApp = express()
    newApp.use(createExpressShield(freshRedisInstance, {
      app: newApp,
      windowSec: 5,
      maxRequests: 2
    }))
    newApp.get('/', (requestObject, responseObject) => responseObject.status(200).json({ ok: true }))
    await request(newApp).get('/').expect(200)
    await request(newApp).get('/').expect(200)
  })

  /**
   * Test Blocking Requests Over Rate Limit
   */
  test('Should Block Requests Over Limit', async () => {
    const { app: testApp } = createTestApp()
    await request(testApp).get('/')
    await request(testApp).get('/')
    await request(testApp).get('/').expect(429)
  })

  /**
   * Test Setting Rate Limit Headers
   */
  test('Should Set Rate Limit Headers', async () => {
    const { app: testApp } = createTestApp()
    const responseResult = await request(testApp).get('/')
    expect(responseResult.headers['x-ratelimit-limit']).toBe('2')
    expect(['1', '0']).toContain(responseResult.headers['x-ratelimit-remaining'])
    expect(responseResult.headers['x-ratelimit-reset']).toBeDefined()
  })

  /**
   * Test Triggering Default Custom Error Response
   */
  test('Should Trigger Default Custom Error Response', async () => {
    const { app: testApp } = createTestApp({ shieldOptions: { maxRequests: 1 } })
    await request(testApp).get('/')
    const responseResult = await request(testApp).get('/')
    expect(responseResult.status).toBe(429)
    expect(responseResult.body.error).toBe('Too many requests')
    expect(responseResult.body.ip).toBeDefined()
    expect(responseResult.body.retryAfterSec).toBeDefined()
  })

  /**
   * Test Calling Custom Error Response
   */
  test('Should Call Custom Error Response', async () => {
    const { app: testApp } = createTestApp({
      shieldOptions: {
        maxRequests: 1,
        customErrorResponse: (requestObject, responseObject, timeToLive) => {
          responseObject.status(429).json({ custom: true, ip: requestObject.fingerprint.ip, ttl: timeToLive })
        }
      }
    })
    await request(testApp).get('/')
    const responseResult = await request(testApp).get('/')
    expect(responseResult.status).toBe(429)
    expect(responseResult.body.custom).toBe(true)
    expect(responseResult.body.ip).toBeDefined()
    expect(responseResult.body.ttl).toBeDefined()
  })
})