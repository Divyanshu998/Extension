/**
 * PhishGuard AI - Feature Extractor
 * Extracts features from URLs and HTML content for phishing detection
 */

/**
 * Extract features from a URL and HTML content
 * @param {string} url - The URL to analyze
 * @param {string} html - The HTML content to analyze
 * @returns {Object} Extracted features
 */
function extractFeatures(url, html) {
  // Parse URL
  let urlObj;
  try {
    urlObj = new URL(url);
  } catch (error) {
    console.error('Invalid URL:', error);
    return null;
  }
  
  // Extract URL features
  const urlFeatures = extractUrlFeatures(urlObj, url);
  
  // Extract HTML features
  const htmlFeatures = extractHtmlFeatures(html, urlObj.hostname);
  
  // Extract login form features
  const loginFeatures = extractLoginFormFeatures(html, urlObj.hostname);
  
  // Combine all features
  return {
    url: urlFeatures,
    html: htmlFeatures,
    login: loginFeatures
  };
}

/**
 * Extract features from a URL
 * @param {URL} urlObj - Parsed URL object
 * @param {string} rawUrl - Raw URL string
 * @returns {Object} URL features
 */
function extractUrlFeatures(urlObj, rawUrl) {
  const hostname = urlObj.hostname;
  const path = urlObj.pathname;
  
  // Domain features
  const domainParts = hostname.split('.');
  const tld = domainParts.length > 1 ? domainParts[domainParts.length - 1].toLowerCase() : '';
  const domain = domainParts.length > 1 ? domainParts[domainParts.length - 2].toLowerCase() : hostname;
  const subdomains = domainParts.slice(0, -2);
  
  // Count features
  const domainLength = hostname.length;
  const pathLength = path.length;
  const subdomainCount = subdomains.length;
  const dotsCount = (hostname.match(/\./g) || []).length;
  
  // Special character features
  const specialCharsInDomain = (hostname.match(/[^a-zA-Z0-9\.-]/g) || []).length;
  const specialCharsInPath = (path.match(/[^a-zA-Z0-9\/-]/g) || []).length;
  
  // Suspicious patterns
  const hasIPAddress = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
  const hasHexadecimalIP = /0x[0-9a-f]+/i.test(hostname);
  const hasAtSymbol = rawUrl.includes('@');
  const hasTooManySubdomains = subdomainCount > 3;
  const hasDoubleSlash = path.includes('//');
  
  // Brand impersonation
  const popularBrands = [
    'google', 'facebook', 'apple', 'microsoft', 'amazon', 'netflix', 
    'paypal', 'instagram', 'twitter', 'linkedin', 'yahoo', 'gmail',
    'bank', 'chase', 'wellsfargo', 'citi', 'amex', 'visa', 'mastercard'
  ];
  
  const brandMatches = popularBrands.filter(brand => 
    domain.includes(brand) && domain !== brand
  );
  
  const hasBrandImpersonation = brandMatches.length > 0;
  const impersonatedBrands = brandMatches;
  
  // TLD risk categorization
  const highRiskTLDs = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'work', 'date', 'racing'];
  const mediumRiskTLDs = ['info', 'biz', 'site', 'online', 'website', 'space', 'live', 'tech'];
  
  let tldRiskCategory = 'low';
  if (highRiskTLDs.includes(tld)) {
    tldRiskCategory = 'high';
  } else if (mediumRiskTLDs.includes(tld)) {
    tldRiskCategory = 'medium';
  }
  
  // Suspicious keywords in URL
  const suspiciousTerms = [
    'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
    'banking', 'password', 'credential', 'wallet', 'authenticate', 'validation'
  ];
  
  const suspiciousKeywordsCount = suspiciousTerms.filter(term => 
    rawUrl.toLowerCase().includes(term)
  ).length;
  
  return {
    domainLength,
    pathLength,
    subdomainCount,
    dotsCount,
    specialCharsInDomain,
    specialCharsInPath,
    hasIPAddress,
    hasHexadecimalIP,
    hasAtSymbol,
    hasTooManySubdomains,
    hasDoubleSlash,
    hasBrandImpersonation,
    impersonatedBrands,
    tldRiskCategory,
    suspiciousKeywordsCount,
    tld,
    domain
  };
}

/**
 * Extract features from HTML content
 * @param {string} html - HTML content
 * @param {string} hostname - The hostname of the URL
 * @returns {Object} HTML features
 */
function extractHtmlFeatures(html, hostname) {
  // Create a DOM parser
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, 'text/html');
  
  // External resources
  const externalScripts = Array.from(doc.querySelectorAll('script[src]'))
    .filter(script => {
      try {
        const scriptUrl = new URL(script.src, `https://${hostname}`);
        return scriptUrl.hostname !== hostname;
      } catch (e) {
        return false;
      }
    }).length;
  
  const externalStylesheets = Array.from(doc.querySelectorAll('link[rel="stylesheet"]'))
    .filter(link => {
      try {
        const linkUrl = new URL(link.href, `https://${hostname}`);
        return linkUrl.hostname !== hostname;
      } catch (e) {
        return false;
      }
    }).length;
  
  // Iframe detection
  const iframeCount = doc.querySelectorAll('iframe').length;
  const hiddenIframes = Array.from(doc.querySelectorAll('iframe')).filter(iframe => {
    const style = iframe.style;
    return style.display === 'none' || 
           style.visibility === 'hidden' || 
           iframe.width === '0' || 
           iframe.height === '0' ||
           iframe.hasAttribute('hidden');
  }).length;
  
  // Redirect and refresh
  const metaRefresh = doc.querySelector('meta[http-equiv="refresh"]') !== null;
  const jsRedirects = (html.match(/window\.location|location\.href|location\.replace/g) || []).length;
  
  // Obfuscation techniques
  const obfuscatedJS = (html.match(/eval\s*\(|document\.write\s*\(|unescape\s*\(|fromCharCode|String\.fromCharCode/g) || []).length;
  const encodedStrings = (html.match(/\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|%[0-9a-f]{2}/gi) || []).length;
  
  // Hidden elements
  const hiddenElements = Array.from(doc.querySelectorAll('[style]')).filter(el => {
    const style = el.style;
    return style.display === 'none' || 
           style.visibility === 'hidden' || 
           style.opacity === '0' ||
           el.hasAttribute('hidden');
  }).length;
  
  // Favicon
  const favicon = doc.querySelector('link[rel="icon"], link[rel="shortcut icon"]');
  const hasFavicon = favicon !== null;
  
  // Title
  const title = doc.title;
  const hasTitle = title.trim().length > 0;
  
  // Pop-ups
  const popupScripts = (html.match(/alert\s*\(|confirm\s*\(|prompt\s*\(|window\.open\s*\(/g) || []).length;
  
  return {
    externalScripts,
    externalStylesheets,
    iframeCount,
    hiddenIframes,
    metaRefresh,
    jsRedirects,
    obfuscatedJS,
    encodedStrings,
    hiddenElements,
    hasFavicon,
    hasTitle,
    popupScripts
  };
}

/**
 * Extract features specific to login forms
 * @param {string} html - HTML content
 * @param {string} hostname - The hostname of the URL
 * @returns {Object} Login form features
 */
function extractLoginFormFeatures(html, hostname) {
  // Create a DOM parser
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, 'text/html');
  
  // Find all forms
  const forms = Array.from(doc.querySelectorAll('form'));
  
  // Check if any form has password field
  const hasPasswordField = forms.some(form => 
    form.querySelector('input[type="password"]') !== null
  );
  
  // Check if any form has email/username field
  const hasEmailField = forms.some(form => {
    const inputs = Array.from(form.querySelectorAll('input'));
    return inputs.some(input => 
      input.type === 'email' || 
      input.name?.toLowerCase().includes('email') ||
      input.id?.toLowerCase().includes('email') ||
      input.name?.toLowerCase().includes('user') ||
      input.id?.toLowerCase().includes('user')
    );
  });
  
  // Check for external form submission
  const hasExternalFormAction = forms.some(form => {
    if (!form.action) return false;
    
    try {
      const actionUrl = new URL(form.action, `https://${hostname}`);
      return actionUrl.hostname !== hostname;
    } catch (e) {
      return false;
    }
  });
  
  // Check for HTTPS form submission
  const hasInsecureFormAction = forms.some(form => {
    if (!form.action) return false;
    
    try {
      const actionUrl = new URL(form.action, `https://${hostname}`);
      return actionUrl.protocol !== 'https:';
    } catch (e) {
      return false;
    }
  });
  
  // Check for login-related text
  const loginTexts = ['login', 'sign in', 'signin', 'log in', 'username', 'password', 'email'];
  const hasLoginText = loginTexts.some(text => 
    html.toLowerCase().includes(text)
  );
  
  // Count input fields
  const inputFields = forms.reduce((count, form) => 
    count + form.querySelectorAll('input').length, 0
  );
  
  // Check for security indicators
  const hasHttpsIndicator = html.toLowerCase().includes('secure') || 
                           html.toLowerCase().includes('ssl') ||
                           html.toLowerCase().includes('encryption');
  
  // Check for brand logos
  const hasImages = doc.querySelectorAll('img').length > 0;
  
  return {
    formCount: forms.length,
    hasPasswordField,
    hasEmailField,
    hasExternalFormAction,
    hasInsecureFormAction,
    hasLoginText,
    inputFields,
    hasHttpsIndicator,
    hasImages
  };
}

// Export the feature extractor function
return extractFeatures(url, html);