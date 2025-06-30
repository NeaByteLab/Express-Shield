const crypto = require('crypto')

/**
 * Get Client IP Address
 * Params: Request
 */
function getClientIpAddress(request) {
  let rawIpAddress = ''
  if (request.headers['cf-connecting-ip']) {
    rawIpAddress = request.headers['cf-connecting-ip']
  } else if (request.headers['x-forwarded-for']) {
    rawIpAddress = request.headers['x-forwarded-for'].split(',').shift().trim()
  } else if (request.ip) {
    rawIpAddress = request.ip
  }
  const cleanIpAddress = rawIpAddress.replace(/^::ffff:/, '')
  return cleanIpAddress
}

/**
 * Generate Fingerprint Hash
 * Params: Request
 */
function generateFingerprintHash(request) {
  const clientIpAddress = getClientIpAddress(request)
  const clientUserAgent = request.headers['user-agent'] || ''
  const clientAcceptType = request.headers['accept'] || ''
  const clientLanguage = request.headers['accept-language'] || ''
  const clientSecUa = request.headers['sec-ch-ua'] || ''
  const combinedRawData = [
    clientIpAddress,
    clientUserAgent,
    clientAcceptType,
    clientLanguage,
    clientSecUa
  ].join('|')
  return crypto.createHash('sha256').update(combinedRawData).digest('hex')
}

/**
 * Create Express Shield Middleware
 * Params: RedisClient, Options, IpResolver
 */
function createExpressShield(redisClient, {
  app = null,
  windowSec = 60,
  maxRequests = 10,
  showHeader = true,
  showLog = false,
  applySecurity = true,
  customErrorResponse = (req, res, ttl) => {
    res.status(429).json({
      error: 'Too many requests',
      ip: req.fingerprint?.ip,
      retryAfterSec: ttl
    })
  }
} = {}, ipResolver = getClientIpAddress) {
  if (applySecurity && app) {
    app.disable('x-powered-by')
    app.use((req, res, next) => {
      res.setHeader('X-Content-Type-Options', 'nosniff')
      res.setHeader('X-Frame-Options', 'DENY')
      res.setHeader('X-XSS-Protection', '1; mode=block')
      next()
    })
    if (showLog) {
      console.log('[Express-Shield] Security headers applied')
    }
  }
  return async function expressShieldMiddleware(req, res, next) {
    try {
      const clientIpAddress = ipResolver(req)
      if (!(clientIpAddress)) {
        res.status(400).json({ error: 'IP address detection failed' })
        return
      }
      const fingerprintHash = generateFingerprintHash(req)
      req.fingerprint = {
        ip: clientIpAddress,
        userAgent: req.headers['user-agent'] || '',
        accept: req.headers['accept'] || '',
        lang: req.headers['accept-language'] || '',
        secUa: req.headers['sec-ch-ua'] || '',
        hash: fingerprintHash
      }
      if (showHeader) {
        res.setHeader('X-Fingerprint-Id', fingerprintHash)
      }
      if (showLog) {
        console.log(`[Express-Shield] IP=${clientIpAddress} HASH=${fingerprintHash}`)
      }
      if (redisClient) {
        const rateLimitKey = `rate:ip:${clientIpAddress}`
        const currentCount = await redisClient.incr(rateLimitKey)
        if (currentCount === 1) {
          await redisClient.expire(rateLimitKey, windowSec)
        }
        const timeToLive = await redisClient.ttl(rateLimitKey)
        res.setHeader('X-RateLimit-Limit', maxRequests)
        res.setHeader('X-RateLimit-Remaining', Math.max(0, maxRequests - currentCount))
        res.setHeader('X-RateLimit-Reset', Date.now() + (timeToLive * 1000))
        if (showLog) {
          console.log(`[Express-Shield] Rate IP=${clientIpAddress} Count=${currentCount}/${maxRequests} TTL=${timeToLive}s`)
        }
        if (!(currentCount <= maxRequests)) {
          customErrorResponse(req, res, timeToLive)
          return
        }
      }
      next()
    } catch (err) {
      if (showLog) {
        console.error('[Express-Shield] Middleware error:', err.message)
      }
      next()
    }
  }
}

module.exports = {
  createExpressShield,
  getClientIpAddress,
  generateFingerprintHash
}