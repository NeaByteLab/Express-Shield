/**
 * Create Express Shield Middleware
 * Params: RedisClient, Options, IpResolver
 */
export function createExpressShield(redisClient: any, { app, windowSec, maxRequests, showHeader, showLog, applySecurity, customErrorResponse }?: {
    app?: null | undefined;
    windowSec?: number | undefined;
    maxRequests?: number | undefined;
    showHeader?: boolean | undefined;
    showLog?: boolean | undefined;
    applySecurity?: boolean | undefined;
    customErrorResponse?: ((req: any, res: any, ttl: any) => void) | undefined;
}, ipResolver?: typeof getClientIpAddress): (req: any, res: any, next: any) => Promise<void>;
/**
 * Get Client IP Address
 * Params: Request
 */
export function getClientIpAddress(request: any): string;
/**
 * Generate Fingerprint Hash
 * Params: Request
 */
export function generateFingerprintHash(request: any): string;
