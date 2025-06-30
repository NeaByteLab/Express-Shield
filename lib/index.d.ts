/**
 * Create Express Shield Middleware With Ip Only Rate Limit
 * Params: RedisClient, Options, IpResolver
 */
export function createExpressShield(redisClient: any, { app, windowSec, maxRequests, showHeader, showLog, applySecurity, whitelist, customErrorResponse }?: {
    app?: null | undefined;
    windowSec?: number | undefined;
    maxRequests?: number | undefined;
    showHeader?: boolean | undefined;
    showLog?: boolean | undefined;
    applySecurity?: boolean | undefined;
    whitelist?: never[] | undefined;
    customErrorResponse?: ((request: any, response: any, ttl: any) => void) | undefined;
}, ipResolver?: typeof getClientIpAddress): (request: any, response: any, next: any) => Promise<void>;
/**
 * Get Trusted Client Ip Address Cloudflare Safe
 * Params: Request
 */
export function getClientIpAddress(request: any): any;
/**
 * Generate Fingerprint Hash
 * Params: Request
 */
export function generateFingerprintHash(request: any): string;
/**
 * Check Ip In Cidr List
 * Params: IpAddress, CidrList
 */
export function checkIpInCidrList(ipAddress: any, cidrList: any): any;
/**
 * Check Ipv4 In Cidr
 * Params: IpAddress, RangeCidr
 */
export function checkIpv4InCidr(ipAddress: any, rangeCidr: any): boolean;
/**
 * Check Ipv6 In Cidr
 * Params: IpAddress, RangeCidr
 */
export function checkIpv6InCidr(ipAddress: any, rangeCidr: any): boolean;
/**
 * Check Is Ipv6 Address
 * Params: IpAddress
 */
export function checkIsIpv6Address(ipAddress: any): any;
/**
 * Check Is Valid Ipv4 Address
 * Params: IpAddress
 */
export function checkIsValidIpv4Address(ipAddress: any): boolean;
/**
 * Check Is Valid Ipv6 Address
 * Params: IpAddress
 */
export function checkIsValidIpv6Address(ipAddress: any): boolean;
/**
 * Convert Ipv4 To Number
 * Params: IpAddress
 */
export function convertIpv4ToNumber(ipAddress: any): number;
/**
 * Convert Ipv6 To Bigint
 * Params: IpAddress
 */
export function convertIpv6ToBigint(ipAddress: any): bigint;
/**
 * Watch Cloudflare Ip Data Change
 */
export function watchCloudflareIpList(): void;
/**
 * Force Reload Cloudflare Ip List
 */
export function reloadCloudflareIpList(): {
    ipv4List: any;
    ipv6List: any;
};
export let CLOUDFLARE_IPV4: any;
export let CLOUDFLARE_IPV6: any;
