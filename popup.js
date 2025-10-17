// Popup script for RPKI Protection Checker
// Cross-browser compatibility: Use browser API (Firefox) with chrome fallback
const browserAPI = typeof browser !== 'undefined' ? browser : chrome;

document.addEventListener('DOMContentLoaded', async () => {
  const currentUrlElement = document.getElementById('currentUrl');
  const ipAddressElement = document.getElementById('ipAddress');
  const statusSection = document.getElementById('statusSection');

  try {
    // Initialize settings functionality
    initializeSettings();

    // Get current active tab
    const [tab] = await browserAPI.tabs.query({ active: true, currentWindow: true });

    if (!tab || !tab.url) {
      showError('Unable to get current tab information');
      return;
    }

    const url = new URL(tab.url);
    const hostname = url.hostname;

    // Display current URL
    currentUrlElement.textContent = hostname;

    // Check RPKI protection
    await checkRPKIProtection(hostname);

  } catch (error) {
    console.error('Error in popup:', error);
    showError('Failed to initialize extension');
  }
});

async function checkRPKIProtection(hostname) {
  const ipv4AddressElement = document.getElementById('ipv4Address');
  const ipv6AddressElement = document.getElementById('ipv6Address');
  const statusSection = document.getElementById('statusSection');

  try {
    // Send message to background script
    const response = await browserAPI.runtime.sendMessage({
      action: 'checkRPKI',
      hostname: hostname
    });

    if (!response.success) {
      throw new Error(response.error || 'Unknown error occurred');
    }

    const data = response.data;

    // Update IP addresses
    updateIPAddresses(data);

    // Show network and DNSSEC information (always available)
    showNetworkInfo(data.asInfo);
    showDNSSECInfo(data.dnssec);

    // Update status based on both RPKI and DNSSEC
    updateCombinedStatus(data);

  } catch (error) {
    console.error('Error checking RPKI protection:', error);
    showError(error.message);
  }
}

function updateIPAddresses(data) {
  const ipv4AddressElement = document.getElementById('ipv4Address');
  const ipv6AddressElement = document.getElementById('ipv6Address');

  // Update IPv4 address
  if (data.ipv4) {
    ipv4AddressElement.textContent = `IPv4: ${data.ipv4}`;
  } else {
    ipv4AddressElement.textContent = 'IPv4: Not found';
  }

  // Update IPv6 address
  if (data.ipv6) {
    ipv6AddressElement.textContent = `IPv6: ${data.ipv6}`;
    ipv6AddressElement.classList.remove('ipv6-address-hidden');
  } else {
    ipv6AddressElement.textContent = 'IPv6: Not found';
    ipv6AddressElement.classList.add('ipv6-address-hidden');
  }
}


function showError(message) {
  const statusSection = document.getElementById('statusSection');
  const rpkiDetails = document.getElementById('rpkiDetails');
  const dnssecDetails = document.getElementById('dnssecDetails');
  const networkDetails = document.getElementById('networkDetails');
  const reportSection = document.getElementById('reportSection');
  const ipv4AddressElement = document.getElementById('ipv4Address');
  const ipv6AddressElement = document.getElementById('ipv6Address');

  // Update IP address displays
  ipv4AddressElement.textContent = 'IPv4: Error';
  ipv6AddressElement.textContent = 'IPv6: Error';
  ipv6AddressElement.classList.add('ipv6-address-hidden');

  // Hide details sections
  rpkiDetails.classList.add('hidden');
  dnssecDetails.classList.add('hidden');
  networkDetails.classList.add('hidden');
  reportSection.classList.add('report-section-hidden');

  statusSection.className = 'status-section status-error';
  // Create status elements safely
  statusSection.innerHTML = '';

  const iconDiv = document.createElement('div');
  iconDiv.className = 'status-icon';
  iconDiv.textContent = 'ERROR';

  const textDiv = document.createElement('div');
  textDiv.className = 'status-text';
  textDiv.textContent = 'Error';

  const detailsDiv = document.createElement('div');
  detailsDiv.className = 'status-details';
  detailsDiv.textContent = message; // Safe assignment

  statusSection.appendChild(iconDiv);
  statusSection.appendChild(textDiv);
  statusSection.appendChild(detailsDiv);
}

function showNetworkInfo(asInfo) {
  const networkDetails = document.getElementById('networkDetails');
  const asnInfo = document.getElementById('asnInfo');
  const organizationInfo = document.getElementById('organizationInfo');
  const locationInfo = document.getElementById('locationInfo');

  if (!asInfo) {
    networkDetails.classList.add('hidden');
    return;
  }

  networkDetails.classList.remove('hidden');

  // ASN information - using safe templating
  const asnValue = asInfo.asn ? escapeHtml(String(asInfo.asn)) : 'Unknown';
  setSafeInnerHTML(asnInfo, '<strong>AS Number:</strong> {{value}}', { value: asnValue });

  // Organization information - using safe templating
  const orgValue = asInfo.organization ? escapeHtml(String(asInfo.organization)) : 'Unknown';
  setSafeInnerHTML(organizationInfo, '<strong>Organization:</strong> {{value}}', { value: orgValue });

  // Location information - using safe templating
  const locationParts = [];
  if (asInfo.city) locationParts.push(escapeHtml(String(asInfo.city)));
  if (asInfo.region) locationParts.push(escapeHtml(String(asInfo.region)));
  if (asInfo.country) locationParts.push(escapeHtml(String(asInfo.country)));

  const locationValue = locationParts.length > 0 ? locationParts.join(', ') : 'Unknown';
  setSafeInnerHTML(locationInfo, '<strong>Location:</strong> {{value}}', { value: locationValue });
}

function showDNSSECInfo(dnssecData) {
  const dnssecDetails = document.getElementById('dnssecDetails');
  const dnssecStatusInfo = document.getElementById('dnssecStatusInfo');
  const dnssecAuthInfo = document.getElementById('dnssecAuthInfo');

  if (!dnssecData) {
    dnssecDetails.classList.add('hidden');
    return;
  }

  dnssecDetails.classList.remove('hidden');

  // DNSSEC signing status - using safe templating
  dnssecStatusInfo.innerHTML = '';
  const statusLabel = document.createElement('strong');
  statusLabel.textContent = 'DNSSEC Signed: ';
  dnssecStatusInfo.appendChild(statusLabel);

  const statusValue = document.createElement('span');
  statusValue.textContent = dnssecData.signed ? 'Yes' : 'No';
  statusValue.className = dnssecData.signed ? 'text-protected' : 'text-not-protected';
  dnssecStatusInfo.appendChild(statusValue);

  // Authentication details - using safe DOM manipulation
  dnssecAuthInfo.innerHTML = '';
  const authLabel = document.createElement('strong');
  authLabel.textContent = 'Validation: ';
  dnssecAuthInfo.appendChild(authLabel);

  const authValue = document.createElement('span');
  if (dnssecData.authenticated) {
    authValue.textContent = 'Authenticated';
    authValue.className = 'text-protected';
  } else if (dnssecData.signed) {
    authValue.textContent = 'Signed but not authenticated';
    authValue.className = 'text-warning';
  } else {
    authValue.textContent = 'Not authenticated';
    authValue.className = 'text-not-protected';
  }
  dnssecAuthInfo.appendChild(authValue);
}


function updateCombinedStatus(data) {
  const statusSection = document.getElementById('statusSection');
  const rpkiDetails = document.getElementById('rpkiDetails');
  const reportSection = document.getElementById('reportSection');

  const isRpkiProtected = data.protected;
  const isDnssecSigned = data.dnssec && data.dnssec.signed;

  // Show RPKI details if protected - using safe DOM manipulation
  if (isRpkiProtected) {
    rpkiDetails.classList.remove('hidden');
    const prefixInfo = document.getElementById('prefixInfo');
    const rpkiAsnInfo = document.getElementById('rpkiAsnInfo');

    // Safe prefix info display
    setSafeInnerHTML(prefixInfo, '<strong>Protected Prefix:</strong> {{prefix}}', {
      prefix: escapeHtml(String(data.prefix || 'Unknown'))
    });

    // Safe RPKI ASN info display
    const asnText = data.asn ? `AS${data.asn}` : 'Unknown';
    const maxLengthText = data.maxLength ? ` (Max Length: /${data.maxLength})` : '';
    setSafeInnerHTML(rpkiAsnInfo, '<strong>RPKI ASN:</strong> {{asn}}{{maxLength}}', {
      asn: escapeHtml(asnText),
      maxLength: escapeHtml(maxLengthText)
    });
  } else {
    rpkiDetails.classList.add('hidden');
  }

  // Show report section if missing any protection
  const missingProtections = [];
  if (!isRpkiProtected) missingProtections.push('RPKI');
  if (!isDnssecSigned) missingProtections.push('DNSSEC');

  if (missingProtections.length > 0) {
    showReportSection(data, missingProtections);
  } else {
    reportSection.classList.add('report-section-hidden');
  }

  // Determine combined status
  if (isRpkiProtected && isDnssecSigned) {
    // Both protections active
    statusSection.className = 'status-section status-protected';
    createStatusContent(statusSection, 'FULLY PROTECTED', 'RPKI + DNSSEC Protected',
      'This website has both RPKI route protection and DNSSEC domain signing', '#34a853');
  } else if (isRpkiProtected && !isDnssecSigned) {
    // Only RPKI protection
    statusSection.className = 'status-section status-protected';
    createStatusContent(statusSection, 'RPKI PROTECTED', 'RPKI Protected (No DNSSEC)',
      'Route protected by RPKI but domain is not DNSSEC signed', '#34a853');
  } else if (!isRpkiProtected && isDnssecSigned) {
    // Only DNSSEC protection
    statusSection.className = 'status-section status-loading';
    createStatusContent(statusSection, 'PARTIALLY PROTECTED', 'DNSSEC Only',
      'Domain is DNSSEC signed but route is not RPKI protected', '#ff9800');
  } else {
    // No protection
    statusSection.className = 'status-section status-not-protected';
    createStatusContent(statusSection, 'NOT PROTECTED', 'No RPKI or DNSSEC Protection',
      'This website has neither RPKI route protection nor DNSSEC domain signing', '#ea4335');
  }
}

function createStatusContent(container, iconText, titleText, detailsText, color) {
  container.innerHTML = '';

  const iconDiv = document.createElement('div');
  iconDiv.className = 'status-icon';
  iconDiv.style.color = color;
  iconDiv.style.fontWeight = 'bold';
  iconDiv.style.fontSize = '20px';
  iconDiv.textContent = iconText;

  const textDiv = document.createElement('div');
  textDiv.className = 'status-text';
  textDiv.textContent = titleText;

  const detailsDiv = document.createElement('div');
  detailsDiv.className = 'status-details';
  detailsDiv.textContent = detailsText;

  container.appendChild(iconDiv);
  container.appendChild(textDiv);
  container.appendChild(detailsDiv);
}


function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function createSafeElement(tag, text, className = '') {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  return element;
}

function setSafeInnerHTML(element, template, values = {}) {
  element.innerHTML = '';
  const parts = template.split(/(\{\{[^}]+\}\})/);

  parts.forEach(part => {
    if (part.startsWith('{{') && part.endsWith('}}')) {
      const key = part.slice(2, -2);
      if (values[key] !== undefined) {
        if (typeof values[key] === 'object' && values[key].html) {
          const span = document.createElement('span');
          span.innerHTML = values[key].html;
          element.appendChild(span);
        } else {
          const textNode = document.createTextNode(values[key]);
          element.appendChild(textNode);
        }
      }
    } else {
      if (part.includes('<') && part.includes('>')) {
        const tempDiv = document.createElement('div');
        tempDiv.innerHTML = part;
        while (tempDiv.firstChild) {
          element.appendChild(tempDiv.firstChild);
        }
      } else {
        const textNode = document.createTextNode(part);
        element.appendChild(textNode);
      }
    }
  });
}

// Report section management
function showReportSection(data, missingProtections) {
  const reportSection = document.getElementById('reportSection');
  const reportDetails = document.getElementById('reportDetails');
  const reportButton = document.getElementById('reportButton');

  // Update details text
  const protectionText = missingProtections.join(' and ');
  reportDetails.textContent = `This site lacks ${protectionText} protection. Help improve internet security by reporting this finding.`;

  // Show section
  reportSection.classList.remove('report-section-hidden');

  // Remove existing event listener and add new one
  const newReportButton = reportButton.cloneNode(true);
  reportButton.parentNode.replaceChild(newReportButton, reportButton);

  newReportButton.addEventListener('click', () => {
    generateSecurityReport(data, missingProtections);
  });
}

// Email content sanitization function
function sanitizeEmailContent(input) {
  if (!input || typeof input !== 'string') {
    return 'Unknown';
  }

  // Remove potentially dangerous characters and sequences
  return input
    .replace(/[\r\n\t]/g, ' ')           // Remove line breaks and tabs
    .replace(/[<>]/g, '')                // Remove angle brackets
    .replace(/mailto:/gi, '')            // Remove mailto: protocol
    .replace(/javascript:/gi, '')        // Remove javascript: protocol
    .replace(/data:/gi, '')              // Remove data: protocol
    .replace(/[%]/g, '')                 // Remove percent encoding chars
    .substring(0, 100)                   // Limit length
    .trim();
}

function generateSecurityReport(data, missingProtections) {
  // Create a secure local report instead of hardcoded email
  // This removes the security vulnerability of exposing email addresses

  // Validate input data
  if (!data || !Array.isArray(missingProtections) || missingProtections.length === 0) {
    console.error('Invalid report data provided');
    return;
  }

  // Sanitize protections array
  const validProtections = missingProtections.filter(p => ['RPKI', 'DNSSEC'].includes(p));
  if (validProtections.length === 0) {
    console.error('No valid protection types provided');
    return;
  }

  // Create report data with sanitization
  const reportData = {
    hostname: sanitizeEmailContent(data.hostname || 'Unknown'),
    ipv4: sanitizeEmailContent(data.ipv4 || 'Not found'),
    ipv6: sanitizeEmailContent(data.ipv6 || 'Not found'),
    asn: sanitizeEmailContent(String(data.asInfo?.asn || 'Unknown')),
    organization: sanitizeEmailContent(data.asInfo?.organization || 'Unknown'),
    location: [
      sanitizeEmailContent(data.asInfo?.city || ''),
      sanitizeEmailContent(data.asInfo?.region || ''),
      sanitizeEmailContent(data.asInfo?.country || '')
    ].filter(l => l && l !== 'Unknown').join(', ') || 'Unknown',
    missingProtections: validProtections,
    timestamp: new Date().toISOString()
  };

  // Show secure report dialog for user review
  showSecurityReportDialog(reportData);
}

function showSecurityReportDialog(reportData) {
  // Create a secure report dialog without exposing email addresses
  const reportText = `Security Protection Report

SITE INFORMATION:
- Hostname: ${reportData.hostname}
- IPv4 Address: ${reportData.ipv4}
- IPv6 Address: ${reportData.ipv6}
- AS Number: ${reportData.asn}
- Organization: ${reportData.organization}
- Location: ${reportData.location}

MISSING PROTECTIONS:
${reportData.missingProtections.includes('RPKI') ? '❌ RPKI Protection: This site\'s IP addresses are not protected by RPKI' : ''}
${reportData.missingProtections.includes('DNSSEC') ? '❌ DNSSEC Signing: This domain is not signed with DNSSEC' : ''}

Generated: ${reportData.timestamp}
Extension Version: 1.1`;

  // Copy report to clipboard for user to share securely
  try {
    navigator.clipboard.writeText(reportText).then(() => {
      showMessage('reportStatus', 'Security report copied to clipboard', 'success');
    }).catch(() => {
      // Fallback for older browsers
      const textArea = document.createElement('textarea');
      textArea.value = reportText;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      showMessage('reportStatus', 'Security report copied to clipboard', 'success');
    });
  } catch (error) {
    console.error('Failed to copy report:', error);
    showMessage('reportStatus', 'Please manually copy the report from console log', 'error');
    console.log('SECURITY REPORT:\n', reportText);
  }
}

// Settings management functions
function initializeSettings() {
  const showSettingsBtn = document.getElementById('showSettings');
  const toggleSettingsBtn = document.getElementById('toggleSettings');
  const settingsSection = document.getElementById('settingsSection');
  const updateTimeoutBtn = document.getElementById('updateTimeout');
  const flushCacheBtn = document.getElementById('flushCache');
  const cacheTimeoutInput = document.getElementById('cacheTimeout');

  // Show/hide settings
  showSettingsBtn.addEventListener('click', () => {
    settingsSection.classList.remove('settings-section-hidden');
    showSettingsBtn.textContent = '⚙️ Hide Settings';
    loadCacheSettings();
  });

  toggleSettingsBtn.addEventListener('click', () => {
    settingsSection.classList.add('settings-section-hidden');
    showSettingsBtn.textContent = '⚙️ Settings';
  });

  // Update timeout
  updateTimeoutBtn.addEventListener('click', async () => {
    const hours = parseInt(cacheTimeoutInput.value);
    if (isNaN(hours) || hours < 1 || hours > 96) {
      showMessage('updateTimeoutStatus', 'Invalid timeout value (1-96 hours)', 'error');
      return;
    }

    try {
      const response = await browserAPI.runtime.sendMessage({
        action: 'setCacheTimeout',
        hours: hours
      });

      if (response.success) {
        showMessage('updateTimeoutStatus', `Timeout updated to ${hours} hours`, 'success');
        loadCacheSettings(); // Refresh cache info
      } else {
        showMessage('updateTimeoutStatus', response.error, 'error');
      }
    } catch (error) {
      showMessage('updateTimeoutStatus', 'Failed to update timeout', 'error');
    }
  });

  // Flush cache
  flushCacheBtn.addEventListener('click', async () => {
    try {
      const response = await browserAPI.runtime.sendMessage({
        action: 'flushCache'
      });

      if (response.success) {
        showMessage('flushStatus', 'Cache flushed successfully', 'success');
        loadCacheSettings(); // Refresh cache info
      } else {
        showMessage('flushStatus', response.error, 'error');
      }
    } catch (error) {
      showMessage('flushStatus', 'Failed to flush cache', 'error');
    }
  });
}

async function loadCacheSettings() {
  try {
    const response = await browserAPI.runtime.sendMessage({
      action: 'getCacheSettings'
    });

    if (response.success) {
      const data = response.data;

      // Update timeout input
      document.getElementById('cacheTimeout').value = data.currentTimeoutHours;

      // Update cache status
      const cacheStatus = data.cacheStatus.isValid ?
        `Valid (${data.cacheStatus.ageHours || 0}h old)` : 'Expired/Empty';
      document.getElementById('cacheStatus').textContent = cacheStatus;

      // Update last updated
      const lastUpdated = data.cacheStatus.lastUpdated ?
        new Date(data.cacheStatus.lastUpdated).toLocaleString() : 'Never';
      document.getElementById('cacheLastUpdated').textContent = lastUpdated;

      // Update data size
      document.getElementById('cacheDataSize').textContent =
        `${data.cacheStatus.dataSize} entries`;

    } else {
      console.error('Failed to load cache settings:', response.error);
    }
  } catch (error) {
    console.error('Error loading cache settings:', error);
  }
}

function showMessage(elementId, message, type) {
  const element = document.getElementById(elementId);
  if (!element) {
    // Create status element if it doesn't exist
    const statusElement = document.createElement('span');
    statusElement.id = elementId;
    statusElement.className = 'status-message';

    // Find the button and add status after it
    const targetButton = elementId.includes('updateTimeout') ?
      document.getElementById('updateTimeout') :
      document.getElementById('flushCache');

    if (targetButton) {
      targetButton.parentNode.appendChild(statusElement);
    }
  }

  const statusElement = document.getElementById(elementId);
  if (statusElement) {
    statusElement.textContent = message;
    statusElement.style.color = type === 'success' ? '#34a853' : '#ea4335';

    // Clear message after 3 seconds
    setTimeout(() => {
      statusElement.textContent = '';
    }, 3000);
  }
}