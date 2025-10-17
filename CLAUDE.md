# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an RPKI (Resource Public Key Infrastructure) Firefox browser extension that checks if websites are protected by RPKI. The extension provides real-time RPKI protection status and network ownership information for any website. The extension is cross-browser compatible and also works with Chrome/Chromium browsers.

## Architecture

The extension consists of:

- `manifest.json` - Firefox extension manifest v2 with required permissions and strict CSP (cross-browser compatible)
- `popup.html` - Extension popup UI with status display (no inline styles)
- `popup.css` - External stylesheet for popup UI
- `popup.js` - Frontend logic and UI updates with cross-browser API support
- `background.js` - Background script handling API calls and data processing with cross-browser API support
- `README.md` - Installation and usage documentation

## Key Features

- **RPKI Protection Check**: Verifies if website IPs are in Cloudflare's RPKI records
- **IPv6 Support**: Displays both IPv4 and IPv6 addresses when available
- **Network Information**: Shows AS number, organization, and location for all sites
- **DNS Resolution**: Uses Google DNS-over-HTTPS for both A and AAAA record lookup
- **Advanced Caching**: 12-hour default cache with configurable timeout (1-96 hours) and manual flush option
- **TLS Analysis**: Displays TLS version, cipher suites, and security level information
- **Post-Quantum Cryptography Detection**: Highlights PQC algorithms in TLS connections
- **Security Reporting**: Email reporting for sites missing RPKI and/or DNSSEC protection
- **Color-coded Status**: Green "PROTECTED", Red "NOT PROTECTED", Purple "ERROR"

## APIs Used

- `https://rpki.cloudflare.com/rpki.json` - RPKI ROA data
- `https://dns.google/resolve` - DNS-over-HTTPS resolution
- `https://ipinfo.io/{ip}/json` - AS and geolocation information

## Development

### Testing the Extension

**Firefox:**
1. Navigate to `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on..." and select `manifest.json`
3. Click extension icon on any website to test functionality
4. Check browser console for background script logs
5. Use Developer Tools on popup for frontend debugging

**Chrome (legacy support):**
1. Load unpacked extension in `chrome://extensions/` (enable Developer mode)
2. Click extension icon on any website to test functionality
3. Check browser console for background script logs
4. Use Developer Tools on popup for frontend debugging

### Key Functions

#### Background Script (background.js)
- `fetchRPKIData()` - Downloads and caches RPKI data with rate limiting
- `checkRPKIProtection()` - Performs CIDR prefix matching with ROA validation
- `validateROA()` - Validates ROA structure (prefix, ASN, maxLength)
- `resolveHostname()` - Resolves both IPv4 and IPv6 addresses
- `resolveIPv4()` - Queries A records for IPv4 addresses with rate limiting
- `resolveIPv6()` - Queries AAAA records for IPv6 addresses with rate limiting
- `validateIPv4()` - Validates IPv4 address format
- `validateIPv6()` - Validates IPv6 address format (ReDoS-safe regex)
- `validateHostname()` - Validates and sanitizes hostnames with IDN/punycode support
- `checkDNSSECStatus()` - Checks DNSSEC with record data validation
- `getASInfo()` - Gets network ownership data for IPv4/IPv6 with rate limiting
- `isIpInPrefix()` - CIDR matching with integer overflow protection
- `handleFlushCache()` - Clears RPKI data cache
- `handleSetCacheTimeout()` - Sets custom cache timeout
- `handleGetCacheSettings()` - Retrieves cache status and settings
- `RateLimiter` class - Rate limits API calls to prevent abuse

#### Popup UI (popup.js)
- `updateIPAddresses()` - Updates both IPv4 and IPv6 display
- `showNetworkInfo()` - Displays AS and location information
- `showDNSSECInfo()` - Displays DNSSEC validation status
- `initializeSettings()` - Sets up cache management UI
- `showReportSection()` - Shows reporting UI for missing protections
- `generateSecurityReport()` - Creates security report with site details

### Permissions Required

- `activeTab` - Access current tab URL
- `storage` - Cache RPKI data
- Host permissions for API endpoints:
  - `https://rpki.cloudflare.com/*` - RPKI data
  - `https://dns.google/*` - DNS-over-HTTPS
  - `https://ipinfo.io/*` - AS information

## RPKI Implementation Details

- Downloads ROA (Route Origin Authorization) list from Cloudflare
- Validates ROA structure before processing (prefix format, ASN format, maxLength range)
- Performs CIDR subnet matching using bitwise operations with overflow protection
- Handles both IPv4 prefixes and variable prefix lengths (0-32)
- Caches RPKI data with configurable timeout (1-96 hours, default 12 hours)
- Timestamp validation prevents cache poisoning attacks
- Provides cache management with manual flush and status monitoring
- Currently RPKI validation supports IPv4 only (IPv6 RPKI support limited in current datasets)

## UI Components

- IP Addresses section: Displays both IPv4 and IPv6 addresses when available
- Network Information section (always shown): AS number, organization, location
- RPKI Details section (protected sites only): IP prefix, RPKI ASN, max length
- DNSSEC Details section: Shows signing and authentication status with validated record data
- Status section with color-coded text indicators
- Report section (missing protections only): Clipboard reporting functionality for security issues
- Settings section: Cache management controls with timeout configuration and flush option
- All styling via external CSS (popup.css) - no inline styles

## Security Features

### Input Validation
- **IPv6 Validation**: ReDoS-safe regex prevents catastrophic backtracking attacks
- **IPv4 Validation**: Strict format checking with range validation
- **Hostname Validation**: IDN/punycode detection and validation, homograph attack warnings
- **ROA Validation**: Validates prefix format, ASN format, and maxLength ranges
- **DNS Response Validation**: Type-checks all DNS record fields before processing
- **DNSSEC Record Validation**: Validates record structure, data type, and size limits

### Attack Prevention
- **Rate Limiting**: Prevents API abuse with configurable limits per endpoint
  - RPKI: 10 requests/minute
  - DNS: 30 requests/minute
  - IPInfo: 20 requests/minute
- **Integer Overflow Protection**: CIDR prefix length validation (0-32 range)
- **Cache Poisoning Prevention**: Timestamp validation rejects future/negative values
- **Information Disclosure**: Generic error messages hide internal details

### Content Security Policy
- Strict CSP with no `'unsafe-inline'` for scripts or styles
- External stylesheets only
- Limited connect-src to required API endpoints
- No eval or dynamic code execution

### Cross-Browser Compatibility
- Uses `browser` API (Firefox native) with `chrome` API fallback
- Polyfill pattern: `const browserAPI = typeof browser !== 'undefined' ? browser : chrome;`
- Manifest V2 format for Firefox compatibility
- Background script (not service worker) for broader support
- `browser_action` (Firefox) compatible with `action` (Chrome MV3)
- Supported browsers: Firefox 109+, Chrome 88+, Chromium 88+, Edge 88+

## Browser-Specific Implementation

### API Polyfill Pattern
All API calls use the `browserAPI` constant defined at the top of both `background.js` and `popup.js`:

```javascript
const browserAPI = typeof browser !== 'undefined' ? browser : chrome;
```

This provides:
- Native Firefox API support (promise-based `browser.*`)
- Chrome/Chromium API compatibility (callback-based `chrome.*` with promise wrappers)
- Zero runtime overhead (single typeof check at load time)
- Full API compatibility across all supported browsers

### Manifest Differences
- **Firefox**: Uses `browser_action` and `background.scripts` array
- **Chrome**: Compatible with both MV2 and MV3 formats via polyfill
- **Permissions**: Host permissions in main `permissions` array (MV2 style)
- **CSP**: Single string format compatible with both browsers

## Error Handling

- Graceful degradation when APIs are unavailable
- Rate limiting with clear error messages
- Fallback to basic functionality if network info lookup fails
- User-friendly generic error messages prevent information disclosure
- All errors logged internally without exposing sensitive details

## Testing

### Unit Testing Approach
When testing modifications:
1. Test core RPKI validation with known protected/unprotected IPs
2. Verify DNSSEC validation with signed/unsigned domains
3. Test IPv4 and IPv6 DNS resolution separately
4. Validate cache management (set timeout, flush, status check)
5. Test cross-browser compatibility on both Firefox and Chrome

### Manual Testing Checklist
- [ ] Extension loads without errors in Firefox
- [ ] Extension loads without errors in Chrome
- [ ] RPKI check works for protected sites (e.g., cloudflare.com)
- [ ] RPKI check shows "not protected" for unprotected sites
- [ ] DNSSEC validation displays correctly
- [ ] IPv4 addresses resolve and display
- [ ] IPv6 addresses resolve and display (when available)
- [ ] Network information (ASN, org, location) displays
- [ ] Cache settings can be modified
- [ ] Cache can be flushed manually
- [ ] Security reports generate and copy to clipboard
- [ ] Rate limiting prevents excessive API calls
- [ ] Error states display appropriately

### Known Test Sites
- **RPKI Protected**: cloudflare.com, google.com
- **DNSSEC Signed**: cloudflare.com, google.com, ietf.org
- **IPv6 Enabled**: google.com, cloudflare.com, ipv6.google.com
- **Both Protections**: cloudflare.com

## Quick Reference for Common Tasks

### Adding a new API endpoint
1. Add host permission to `manifest.json` permissions array
2. Create rate limiter instance in `background.js` (if needed)
3. Add validation function for API response
4. Implement API call with rate limiting
5. Update error handling
6. Update CLAUDE.md and README.md with new API details

### Modifying the UI
1. Update `popup.html` structure (no inline styles allowed)
2. Add styling to `popup.css`
3. Update `popup.js` DOM manipulation (use safe methods)
4. Test in both Firefox and Chrome
5. Verify CSP compliance

### Adding new cached data
1. Define cache duration constants in `background.js`
2. Implement fetch function with timestamp validation
3. Add cache management handlers
4. Update storage schema if needed
5. Add UI controls in settings section

### Debugging Tips
- **Firefox**: Use Browser Console (Ctrl+Shift+J) for background script logs
- **Chrome**: Use Extension background page console
- Enable verbose logging by adding console.log statements
- Check Network tab for API call failures
- Inspect popup with right-click → Inspect Element

### Security Review Checklist
When adding new features:
- [ ] All user inputs validated and sanitized
- [ ] No inline scripts or styles (CSP compliance)
- [ ] API responses type-checked before use
- [ ] Rate limiting implemented for external calls
- [ ] Error messages don't leak sensitive information
- [ ] No eval() or dynamic code execution
- [ ] Cross-browser API compatibility maintained