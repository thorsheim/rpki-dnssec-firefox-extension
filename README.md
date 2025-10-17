# RPKI & DNSSEC Checker Browser Extension

A secure Firefox extension that checks if the current website's IP address is protected by RPKI (Resource Public Key Infrastructure) and DNSSEC, with comprehensive security hardening against common web vulnerabilities.

## Features

- **RPKI Protection Check**: Verify if a website's IP is protected by RPKI using Cloudflare's authoritative data with validated ROA structures
- **DNSSEC Validation**: Check if domains are signed with DNSSEC with comprehensive record validation
- **IPv6 Support**: Display both IPv4 and IPv6 addresses when available with ReDoS-safe validation
- **Network Ownership Information**: Display AS number, organization name, and geographic location for all websites
- **Real-time DNS Resolution**: Use Google's DNS-over-HTTPS for reliable IPv4 and IPv6 lookup with rate limiting
- **Advanced Cache Management**: 12-hour default cache with configurable timeout (1-96 hours), manual flush option, cache status monitoring, and poisoning prevention
- **Security Reporting**: Clipboard reporting for sites missing RPKI and/or DNSSEC protection
- **Hardened Security**: Comprehensive input validation, rate limiting, and attack prevention
- **Clean Interface**: Color-coded status with comprehensive information:
  - **Green "PROTECTED"** - IP is found in RPKI records with detailed prefix and ASN info
  - **Red "NOT PROTECTED"** - IP is not in RPKI records but still shows network ownership details
  - **Purple "ERROR"** - Error occurred during lookup process

## Installation

### Firefox

1. Download or clone this repository
2. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`
3. Click "Load Temporary Add-on..."
4. Navigate to the extension directory and select `manifest.json`
5. The RPKI & DNSSEC Checker extension should now appear in your toolbar

**Note**: Temporary add-ons in Firefox are removed when you close the browser. For permanent installation, the extension needs to be signed by Mozilla or you can use Firefox Developer Edition/Nightly with `xpinstall.signatures.required` set to `false` in `about:config`.

### Chrome/Chromium (Legacy Support)

The extension is primarily designed for Firefox but maintains compatibility with Chrome:

1. Download or clone this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" in the top right corner
4. Click "Load unpacked" and select the extension directory
5. The RPKI Protection Checker extension should now appear in your toolbar

## Usage

1. Navigate to any website
2. Click the RPKI Protection Checker extension icon in your toolbar
3. The extension will automatically:
   - Display the current website's hostname
   - Resolve both IPv4 and IPv6 addresses using Google's DNS-over-HTTPS service
   - Look up network ownership information (AS number, organization, location)
   - Check the IP against RPKI records from Cloudflare's public API
   - Show comprehensive protection status and network details

## Information Displayed

### For All Websites:
- **Current Website**: The hostname you're visiting
- **IP Addresses**:
  - IPv4 address (when available)
  - IPv6 address (when available and displayed only if found)
- **Network Information**:
  - AS Number (e.g., AS13335)
  - Organization (e.g., Cloudflare, Inc.)
  - Location (City, Region, Country)

### Additionally for RPKI-Protected Websites:
- **RPKI Details**:
  - Protected Prefix (e.g., 104.16.0.0/13)
  - RPKI ASN (AS number from RPKI records)
  - Maximum prefix length (if specified)

### For All Websites:
- **TLS Connection Details**:
  - TLS version with color-coded security indicators
  - Cipher suite information when available
  - Security level assessment
  - Post-Quantum Cryptography detection and highlighting

### For Sites Missing Security Protection:
- **Security Report Button**: One-click email reporting functionality
- **Detailed Analysis**: Comprehensive security assessment including missing protections
- **Actionable Recommendations**: Specific guidance for implementing RPKI and DNSSEC

## How It Works

1. **DNS Resolution**: Uses Google's DNS-over-HTTPS API (`dns.google/resolve`) to resolve both A and AAAA records for IPv4 and IPv6 addresses
2. **Parallel Lookup**: Queries IPv4 and IPv6 simultaneously for better performance
3. **Network Lookup**: Queries IPinfo.io API to get AS number, organization name, and geographic location (supports both IPv4 and IPv6)
4. **RPKI Data**: Fetches the latest RPKI ROA (Route Origin Authorization) data from Cloudflare's public API
5. **Prefix Matching**: Performs CIDR subnet matching to check if the IP address falls within any protected prefixes (currently IPv4 only)
6. **Advanced Caching**: RPKI data is cached for configurable periods (1-96 hours, default 12 hours) with manual flush capability
7. **Cache Management**: Real-time cache status monitoring showing age, validity, and data size
8. **TLS Analysis**: Monitors TLS connections to extract version, cipher suite, and security information
9. **PQC Detection**: Analyzes cipher suites for Post-Quantum Cryptography algorithms using NIST standards
10. **Security Reporting**: Generates detailed email reports for sites missing RPKI/DNSSEC protection
11. **Real-time Display**: Shows comprehensive security assessment including network ownership, RPKI protection, and TLS security

## Technical Details

- Uses Firefox Extension Manifest V2 with strict Content Security Policy
- **Cross-browser compatible** using browser API polyfill pattern:
  - Detects Firefox's native `browser` API or falls back to Chrome's `chrome` API
  - All API calls use `browserAPI` abstraction for compatibility
  - Works on Firefox, Chrome, Chromium, and Edge
- Implements a background script for RPKI data fetching with rate limiting
- Uses DNS-over-HTTPS for both IPv4 (A records) and IPv6 (AAAA records) resolution
- Performs CIDR prefix matching with integer overflow protection
- IPv6 validation using ReDoS-safe regex patterns
- Comprehensive input validation for all external data sources
- Rate limiting on all API endpoints (10-30 requests/minute)
- Graceful fallback when only IPv4 or IPv6 is available

## Security Features

This extension implements defense-in-depth security measures:

### Input Validation
- **ReDoS Prevention**: IPv6 validation uses non-backtracking regex to prevent catastrophic backtracking attacks
- **Type Validation**: All DNS records and API responses are type-checked before processing
- **ROA Validation**: RPKI ROA structures (prefix, ASN, maxLength) validated before use
- **IDN/Punycode Handling**: Internationalized domain names validated with homograph attack detection
- **Integer Overflow Protection**: CIDR prefix lengths validated (0-32 range)

### Attack Prevention
- **Rate Limiting**: Per-endpoint limits prevent API abuse
  - RPKI API: 10 requests/minute
  - DNS API: 30 requests/minute
  - IPInfo API: 20 requests/minute
- **Cache Poisoning Prevention**: Timestamp validation rejects future/negative values
- **Information Disclosure Prevention**: Generic error messages hide internal details
- **DNSSEC Record Validation**: Record data structure, type, and size validated

### Content Security Policy
- No `'unsafe-inline'` for scripts or styles
- External stylesheets only
- Limited `connect-src` to required API endpoints
- No `eval()` or dynamic code execution
- Strict CSP prevents XSS and injection attacks

## Permissions Required

- `activeTab`: To access the current tab's URL
- `storage`: For caching RPKI data
- Host permissions for:
  - `https://rpki.cloudflare.com/*` - To fetch RPKI ROA data
  - `https://dns.google/*` - For DNS-over-HTTPS resolution
  - `https://ipinfo.io/*` - For AS and geolocation lookup

## Files Structure

- `manifest.json` - Extension manifest V2 for Firefox with strict CSP
- `popup.html` - Extension popup UI (no inline styles)
- `popup.css` - External stylesheet for popup UI
- `popup.js` - Popup logic and UI updates with cross-browser API compatibility
- `background.js` - Background script with security validations and rate limiting
- `README.md` - This file
- `CLAUDE.md` - Developer documentation

## Development

To modify the extension:

### Firefox
1. Make your changes to the source files
2. Go to `about:debugging#/runtime/this-firefox`
3. Click "Reload" button on the RPKI & DNSSEC Checker extension
4. Test your changes

### Chrome
1. Make your changes to the source files
2. Go to `chrome://extensions/`
3. Click the reload button on the RPKI Protection Checker extension
4. Test your changes

## Building for Distribution

### Firefox Add-on (Signed)
To distribute on Firefox Add-ons (AMO):
1. Zip all extension files: `manifest.json`, `popup.html`, `popup.css`, `popup.js`, `background.js`
2. Submit to [addons.mozilla.org](https://addons.mozilla.org/developers/)
3. Mozilla will review and sign the extension
4. Signed version can be installed permanently in Firefox

### Chrome Web Store
To distribute on Chrome Web Store:
1. Ensure manifest is compatible (currently using MV2 for cross-browser support)
2. Create a ZIP file of all extension files
3. Submit to [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole)
4. Note: Chrome is moving to Manifest V3; this extension may need updates for store submission

### Self-Hosting
For internal/private distribution:
- **Firefox**: Package as `.xpi` file and distribute (users need to allow unsigned extensions)
- **Chrome**: Distribute as unpacked folder or create a `.crx` file
- Users must enable developer mode to install unsigned extensions

## API Services Used

- **Cloudflare RPKI API** (`https://rpki.cloudflare.com/rpki.json`): Provides authoritative RPKI ROA data
- **Google DNS-over-HTTPS** (`https://dns.google/resolve`): Secure DNS resolution service for both A and AAAA records
- **IPinfo.io** (`https://ipinfo.io/{ip}/json`): AS number, organization, and geolocation data (supports IPv4 and IPv6)

## Privacy & Data Handling

This extension is designed with privacy-first principles:

### What Data is Processed
- Only processes the hostname of the current tab you're actively viewing
- Resolves IP addresses through Google DNS-over-HTTPS
- Queries public RPKI and network information databases

### What is NOT Collected
- No personal browsing information stored or transmitted
- No tracking of browsing history or user behavior
- No telemetry or analytics
- No third-party tracking scripts

### Data Flow
- All API calls made directly from your browser to respective services
- RPKI data cached locally with configurable timeouts (1-96 hours)
- Cache can be manually flushed through settings interface
- No data sent to extension developers or third parties

### Rate Limiting
- Protects your privacy by limiting API queries
- Prevents excessive data collection by external services
- Configurable cache reduces repeated queries

## What is RPKI?

RPKI (Resource Public Key Infrastructure) is a security framework that helps prevent BGP route hijacking attacks. When a network prefix is protected by RPKI:

- It has a cryptographically signed Route Origin Authorization (ROA)
- The ROA specifies which AS (Autonomous System) is authorized to announce that prefix
- This helps prevent malicious actors from hijacking IP ranges and redirecting traffic

**Protected networks** are more resistant to BGP hijacking attacks, while **non-protected networks** may be more vulnerable to routing security threats.

## IPv6 Support

This extension now displays both IPv4 and IPv6 addresses for websites that support dual-stack networking. While IPv6 addresses are shown for informational purposes and network analysis, RPKI protection validation currently focuses on IPv4 addresses as IPv6 RPKI adoption is still developing in the broader internet infrastructure.

Key IPv6 features:
- Displays IPv6 addresses when available (automatically hidden when not found)
- Supports network information lookup for IPv6 addresses
- Validates IPv6 address formats including compressed notation
- Provides complete dual-stack network visibility

## Cache Management

The extension now includes advanced cache management features to balance performance with data freshness:

### Default Settings
- **Cache Duration**: 12 hours (improved from 30 minutes)
- **Configurable Range**: 1 to 96 hours
- **Cache Storage**: Local browser storage for RPKI data

### Cache Controls
Access cache settings by clicking the "Settings" button in the extension popup:

- **View Cache Status**: See if cache is valid, age in hours, last update time, and data size
- **Change Timeout**: Set custom cache duration between 1-96 hours
- **Manual Flush**: Clear cache immediately to force fresh data download
- **Real-time Monitoring**: Live status updates showing cache health

### Benefits
- **Reduced API Calls**: Longer default cache improves performance
- **Customizable**: Set shorter timeouts for frequently changing environments
- **Manual Control**: Force refresh when needed for critical security checks
- **Transparency**: Always know your cache status and data freshness

## DNSSEC Validation

The extension checks DNSSEC (Domain Name System Security Extensions) status:

### What is DNSSEC?
DNSSEC adds cryptographic signatures to DNS records to prevent DNS spoofing and cache poisoning attacks. It provides:
- Authentication of DNS data origin
- Data integrity verification
- Protection against man-in-the-middle attacks

### DNSSEC Checks
- **Signed Status**: Checks for DNSSEC signature records (RRSIG, NSEC, DNSKEY)
- **Authenticated Data**: Validates the AD (Authenticated Data) flag from DNS responses
- **Record Validation**: Verifies DNSSEC record structure, data type, and size
- **DNSKEY Presence**: Confirms DNSKEY records exist for the domain

### Visual Indicators
- Green: DNSSEC signed and authenticated
- Orange: Signed but not fully authenticated
- Red: Not signed or authenticated

## Security Reporting

The extension includes a built-in reporting feature to help improve internet security by identifying sites that lack proper protection:

### When Reports Are Generated
- **Missing RPKI Protection**: When a site's IP addresses are not protected by RPKI
- **Missing DNSSEC Signing**: When a domain is not signed with DNSSEC
- **Both Missing**: When a site lacks both RPKI and DNSSEC protection

### Report Contents
Each security report includes:
- **Site Information**: Hostname, IPv4/IPv6 addresses, AS number, organization, and location
- **Missing Protections**: Detailed analysis of what security measures are absent
- **Security Implications**: Explanation of vulnerabilities and potential attack vectors
- **Recommendations**: Specific steps to implement RPKI and/or DNSSEC
- **Technical Details**: Timestamp and extension version for tracking

### How to Report
1. Visit any website with the extension enabled
2. If protections are missing, a report section will appear automatically
3. Click "📋 Copy Security Report"
4. Report is copied to your clipboard for your own records or submission
5. Share the report as needed to help improve internet security

### Privacy and Data Handling
- **No Data Collection**: Reports are generated locally in your browser
- **User Control**: You choose when and what to copy
- **No Tracking**: The extension doesn't track or store your reporting activity
- **Transparency**: All report contents are visible and remain on your device

## Browser Compatibility

This extension has been designed to work across multiple browsers:

### Fully Supported
- **Firefox** 109.0+ (Primary platform)
- **Chrome** 88+ (via polyfill)
- **Chromium** 88+
- **Microsoft Edge** 88+

### Implementation Notes
- Uses Manifest V2 for broad compatibility
- Browser API polyfill provides seamless cross-browser operation
- No browser-specific features or dependencies
- Identical functionality across all supported browsers

### Known Limitations
- Firefox temporary add-ons require reload after browser restart
- Chrome Manifest V3 features not utilized (using V2 for compatibility)
- TLS details limited by browser extension API restrictions