# Changelog

## [1.0.1] - 2025-06-30

### Added
- Auto-update Cloudflare IP (IPv4 & IPv6) via `script/update-cloudflare-ip.js` on install and on-demand.
- Folder `data/` to store and load up-to-date Cloudflare IP lists for runtime validation.
- Hot-reload mechanism for IP list: module now reloads Cloudflare IPs from data files when changed, without app restart.
- Function `reloadCloudflareIpList()` for manual/forced reload of the IP list from disk.
- All utility functions (CIDR, validator, reload, etc.) are now exported for testability.
- Typescript definition for all core exported functions (if running `build:types`).

### Changed
- Middleware and IP validator now **always use IP list from `./data/` folder** (fallback ke hardcoded hanya jika file tidak ditemukan).
- All function names and variables updated to be readable, consistent, and compliant with two-word camelCase standard.
- Logging standardized for IP loading/fallback (warn when fallback used).
- Improved security: Always validates CF-Connecting-IP only if request comes from official Cloudflare IPs (IPv4 or IPv6).

### Fixed
- Parsing and validation logic for both IPv4 and IPv6 ranges.
- Fixed race condition/consistency issues if IP list file is updated while app is running.
- Removed all unnecessary console output except for critical warnings/errors.

### Removed
- No breaking changes, all public APIs are backward compatible.

---

## [1.0.0] - 2025-06-01

### Added
- Initial stable release: Express middleware with rate limiting, fingerprinting, security headers, and Cloudflare-aware IP trust.

---

**Migration:**  
- Run `npm install` or `npm run postinstall` to fetch the latest Cloudflare IPs to the `data/` folder.
- No code migration needed for existing usage.