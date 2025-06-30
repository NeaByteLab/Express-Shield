const crypto = require('crypto')
const path = require('path')
const fs = require('fs')

/**
 * Cloudflare Ip List Loader
 */
function loadCloudflareIpList() {
  let ipv4List = []
  let ipv6List = []
  try {
    ipv4List = require(path.join(__dirname, './data/cloudflare_ipv4.json'))
    ipv6List = require(path.join(__dirname, './data/cloudflare_ipv6.json'))
  } catch (error) {
    console.warn('[Express-Shield] Using Hardcoded Cloudflare IPs')
    ipv4List = [
      '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '104.16.0.0/13', '104.24.0.0/14',
      '108.162.192.0/18', '131.0.72.0/22', '141.101.64.0/18', '162.158.0.0/15', '172.64.0.0/13',
      '173.245.48.0/20', '188.114.96.0/20', '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17'
    ]
    ipv6List = [
      '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
      '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32'
    ]
  }
  return { ipv4List, ipv6List }
}
let { ipv4List: CLOUDFLARE_IPV4, ipv6List: CLOUDFLARE_IPV6 } = loadCloudflareIpList()

/**
 * Watch Cloudflare Ip Data Change
 */
function watchCloudflareIpList() {
  const ipv4FilePath = path.join(__dirname, './data/cloudflare_ipv4.json')
  const ipv6FilePath = path.join(__dirname, './data/cloudflare_ipv6.json')
  function reloadIpList() {
    try {
      delete require.cache[require.resolve(ipv4FilePath)]
      delete require.cache[require.resolve(ipv6FilePath)]
      CLOUDFLARE_IPV4 = require(ipv4FilePath)
      CLOUDFLARE_IPV6 = require(ipv6FilePath)
    } catch (error) {
      console.error('[Express-Shield] Reload error:', error.message, error.stack)
      return true
    }
  }
  fs.watchFile(ipv4FilePath, reloadIpList)
  fs.watchFile(ipv6FilePath, reloadIpList)
}
watchCloudflareIpList()

/**
 * Force Reload Cloudflare Ip List
 */
function reloadCloudflareIpList() {
  const result = loadCloudflareIpList()
  CLOUDFLARE_IPV4 = result.ipv4List
  CLOUDFLARE_IPV6 = result.ipv6List
  return result
}

/**
 * Check Is Ipv6 Address
 * Params: IpAddress
 */
function checkIsIpv6Address(ipAddress) {
  return ipAddress.includes(':')
}

/**
 * Convert Ipv4 To Number
 * Params: IpAddress
 */
function convertIpv4ToNumber(ipAddress) {
  return ipAddress.split('.').reduce((acc, octet) => ((acc << 8) + parseInt(octet, 10)), 0) >>> 0
}

/**
 * Convert Ipv6 To Bigint
 * Params: IpAddress
 */
function convertIpv6ToBigint(ipAddress) {
  const parts = ipAddress.split('::')
  const head = parts[0] ? parts[0].split(':') : []
  const tail = parts[1] ? parts[1].split(':') : []
  const zeros = Array(8 - head.length - tail.length).fill('0')
  const full = [...head, ...zeros, ...tail]
  return BigInt('0x' + full.map(x => x.padStart(4, '0')).join(''))
}

/**
 * Check Ipv4 In Cidr
 * Params: IpAddress, RangeCidr
 */
function checkIpv4InCidr(ipAddress, rangeCidr) {
  const [range, bits = 32] = rangeCidr.split('/')
  const ipLong = convertIpv4ToNumber(ipAddress)
  const rangeLong = convertIpv4ToNumber(range)
  const mask = ~(2 ** (32 - bits) - 1) >>> 0
  return (ipLong & mask) === (rangeLong & mask)
}

/**
 * Check Ipv6 In Cidr
 * Params: IpAddress, RangeCidr
 */
function checkIpv6InCidr(ipAddress, rangeCidr) {
  const [range, bits = 128] = rangeCidr.split('/')
  const ipBig = convertIpv6ToBigint(ipAddress)
  const rangeBig = convertIpv6ToBigint(range)
  const mask = (BigInt(1) << BigInt(128 - bits)) - BigInt(1)
  const networkMask = ~mask & ((BigInt(1) << BigInt(128)) - BigInt(1))
  return (ipBig & networkMask) === (rangeBig & networkMask)
}

/**
 * Check Ip In Cidr List
 * Params: IpAddress, CidrList
 */
function checkIpInCidrList(ipAddress, cidrList) {
  if (checkIsIpv6Address(ipAddress)) {
    return cidrList.some(cidr => checkIpv6InCidr(ipAddress, cidr))
  }
  return cidrList.some(cidr => checkIpv4InCidr(ipAddress, cidr))
}

/**
 * Check Is Valid Ipv4 Address
 * Params: IpAddress
 */
function checkIsValidIpv4Address(ipAddress) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(ipAddress)
}

/**
 * Check Is Valid Ipv6 Address
 * Params: IpAddress
 */
function checkIsValidIpv6Address(ipAddress) {
  return /^[a-fA-F0-9:]+$/.test(ipAddress)
}

/**
 * Get Trusted Client Ip Address Cloudflare Safe
 * Params: Request
 */
function getClientIpAddress(request) {
  let remoteIpAddress = (request.connection?.remoteAddress || request.socket?.remoteAddress || request.ip || '').replace(/^::ffff:/, '')
  if (request.headers['cf-connecting-ip']) {
    const cfIp = request.headers['cf-connecting-ip']
    if (checkIsIpv6Address(remoteIpAddress)) {
      if (checkIpInCidrList(remoteIpAddress, CLOUDFLARE_IPV6) && checkIsValidIpv6Address(cfIp)) {
        return cfIp
      }
    } else {
      if (checkIpInCidrList(remoteIpAddress, CLOUDFLARE_IPV4) && checkIsValidIpv4Address(cfIp)) {
        return cfIp
      }
    }
  }
  return remoteIpAddress
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
    clientSecUa,
    ...(request.headers['custom-fingerprint'] ? [request.headers['custom-fingerprint']] : [])
  ].join('|')
  return crypto.createHash('sha256').update(combinedRawData).digest('hex')
}

/**
 * Create Express Shield Middleware With Ip Only Rate Limit
 * Params: RedisClient, Options, IpResolver
 */
function createExpressShield(redisClient, {
  app = null,
  windowSec = 60,
  maxRequests = 10,
  showHeader = true,
  showLog = false,
  applySecurity = true,
  whitelist = [],
  customErrorResponse = (request, response, ttl) => {
    response.status(429).json({
      error: 'Too many requests',
      ip: request.fingerprint?.ip,
      retryAfterSec: ttl
    })
  }
} = {}, ipResolver = getClientIpAddress) {
  if (applySecurity && app) {
    app.disable('x-powered-by')
    app.use((request, response, next) => {
      response.setHeader('X-Content-Type-Options', 'nosniff')
      response.setHeader('X-Frame-Options', 'DENY')
      response.setHeader('X-XSS-Protection', '1; mode=block')
      response.setHeader('Referrer-Policy', 'no-referrer')
      if ((request.secure || request.headers['x-forwarded-proto'] === 'https')) {
        response.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload')
      }
      response.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';"
      )
      response.setHeader('Permissions-Policy', 'geolocation=(), microphone=()')
      next()
    })
    if (showLog) {
      console.log('[Express-Shield] Security headers applied')
    }
  }
  
  return async function expressShieldMiddleware(request, response, next) {
    try {
      const clientIpAddress = ipResolver(request)
      if (Array.isArray(whitelist) && whitelist.includes(clientIpAddress)) {
        next()
        return
      }
      if (!(clientIpAddress)) {
        response.status(400).json({ error: 'IP detection failed' })
        return
      }
      const fingerprintHash = generateFingerprintHash(request)
      request.fingerprint = {
        ip: clientIpAddress,
        userAgent: request.headers['user-agent'] || '',
        accept: request.headers['accept'] || '',
        lang: request.headers['accept-language'] || '',
        secUa: request.headers['sec-ch-ua'] || '',
        hash: fingerprintHash
      }
      if (showHeader) {
        response.setHeader('X-Fingerprint-Id', fingerprintHash)
      }
      if (showLog) {
        console.log(`[Express-Shield] IP=${clientIpAddress} Hash=${fingerprintHash}`)
      }
      if (redisClient) {
        const rateLimitKey = `rate:ip:${clientIpAddress}`
        const pipeline = redisClient.pipeline()
        pipeline.incr(rateLimitKey)
        pipeline.ttl(rateLimitKey)
        const result = await pipeline.exec()
        if (!(result) || result[0][0] || result[1][0]) {
          if (showLog) {
            console.error('[Express-Shield] Redis pipeline execution error:', result ? (result[0][0] || result[1][0]) : 'Unknown Redis error')
          }
          next()
          return
        }
        const currentCount = result[0][1]
        let timeToLive = result[1][1]
        if (currentCount === 1) {
          try {
            await redisClient.expire(rateLimitKey, windowSec)
          } catch (expireError) {
            if (showLog) {
              console.error('[Express-Shield] Redis expire error:', expireError)
            }
          }
          timeToLive = windowSec
        }
        response.setHeader('X-RateLimit-Limit', maxRequests)
        response.setHeader('X-RateLimit-Remaining', Math.max(0, maxRequests - currentCount))
        response.setHeader('X-RateLimit-Reset', Math.floor(Date.now() / 1000) + timeToLive)
        if (showLog) {
          console.log(`[Express-Shield] Rate IP=${clientIpAddress} Count=${currentCount}/${maxRequests} TTL=${timeToLive}s`)
        }
        if (currentCount > maxRequests) {
          customErrorResponse(request, response, timeToLive)
          return
        }
      }
      next()
    } catch (error) {
      if (showLog) {
        console.error('[Express-Shield] Middleware error:', error.message, error.stack)
      }
      next(error)
    }
  }
}

module.exports = {
  createExpressShield,
  getClientIpAddress,
  generateFingerprintHash,
  checkIpInCidrList,
  checkIpv4InCidr,
  checkIpv6InCidr,
  checkIsIpv6Address,
  checkIsValidIpv4Address,
  checkIsValidIpv6Address,
  convertIpv4ToNumber,
  convertIpv6ToBigint,
  watchCloudflareIpList,
  reloadCloudflareIpList,
  CLOUDFLARE_IPV4,
  CLOUDFLARE_IPV6
}