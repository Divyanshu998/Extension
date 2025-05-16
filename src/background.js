/**
 * PhishGuard AI - Background Script
 * Handles URL analysis, model loading, and communication with content scripts
 */

// Configuration
const CONFIG = {
  modelUpdateInterval: 24 * 60 * 60 * 1000, // 24 hours
  threatIntelligenceEndpoint: 'https://api.example.com/threat-intel',
  virusTotalApiKey: 'YOUR_API_KEY', // Replace with actual API key
  cloudModelEndpoint: 'https://api.example.com/phish-detect',
  detectionThresholds: {
    low: 0.3,
    medium: 0.6,
    high: 0.85
  }
};

// State management
let svmModel = null;
let featureExtractor = null;
let threatIntelligenceDB = new Map();
let cachedResults = new Map();

/**
 * Initialize models and threat intelligence
 */
async function initialize() {
  console.log('Initializing PhishGuard AI...');
  
  // Load the lightweight SVM model for on-device processing
  try {
    const modelResponse = await fetch(chrome.runtime.getURL('models/svm_model.json'));
    svmModel = await modelResponse.json();
    console.log('SVM model loaded successfully');
    
    // Load feature extractor
    const featureExtractorResponse = await fetch(chrome.runtime.getURL('lib/feature_extractor.js'));
    const featureExtractorText = await featureExtractorResponse.text();
    featureExtractor = new Function('url', 'html', featureExtractorText);
    
    // Initialize threat intelligence database
    await updateThreatIntelligence();
    
    // Set up periodic updates
    setInterval(updateThreatIntelligence, CONFIG.modelUpdateInterval);
    
    console.log('PhishGuard AI initialized successfully');
  } catch (error) {
    console.error('Failed to initialize PhishGuard AI:', error);
  }
}

/**
 * Update threat intelligence database from remote server
 */
async function updateThreatIntelligence() {
  try {
    const response = await fetch(CONFIG.threatIntelligenceEndpoint);
    const data = await response.json();
    
    // Update local database
    threatIntelligenceDB.clear();
    data.knownPhishingPatterns.forEach(pattern => {
      threatIntelligenceDB.set(pattern.signature, pattern.risk);
    });
    
    console.log(`Threat intelligence updated with ${threatIntelligenceDB.size} patterns`);
  } catch (error) {
    console.error('Failed to update threat intelligence:', error);
  }
}

/**
 * Analyze URL using lexical features
 * @param {string} url - The URL to analyze
 * @returns {Object} Analysis results
 */
function analyzeLexicalFeatures(url) {
  const urlObj = new URL(url);
  
  // Extract lexical features
  const features = {
    domainLength: urlObj.hostname.length,
    pathLength: urlObj.pathname.length,
    queryLength: urlObj.search.length,
    subdomainCount: urlObj.hostname.split('.').length - 1,
    specialCharCount: (url.match(/[^a-zA-Z0-9]/g) || []).length,
    hasIPAddress: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlObj.hostname),
    suspiciousKeywords: checkSuspiciousKeywords(url),
    tldCategory: categorizeTLD(urlObj.hostname)
  };
  
  // Calculate risk score based on lexical features (simplified)
  let riskScore = 0;
  
  if (features.domainLength > 30) riskScore += 0.2;
  if (features.pathLength > 100) riskScore += 0.15;
  if (features.specialCharCount > 10) riskScore += 0.1;
  if (features.hasIPAddress) riskScore += 0.3;
  if (features.suspiciousKeywords) riskScore += 0.25;
  
  return {
    features,
    riskScore: Math.min(riskScore, 1.0)
  };
}

/**
 * Check for suspicious keywords in URL
 * @param {string} url - The URL to check
 * @returns {boolean} Whether suspicious keywords were found
 */
function checkSuspiciousKeywords(url) {
  const suspiciousTerms = [
    'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
    'paypal', 'bank', 'ebay', 'amazon', 'microsoft', 'apple', 'google'
  ];
  
  const urlLower = url.toLowerCase();
  return suspiciousTerms.some(term => 
    urlLower.includes(term) && !urlLower.includes(term + '.com')
  );
}

/**
 * Categorize TLD risk level
 * @param {string} hostname - The hostname to analyze
 * @returns {string} TLD risk category
 */
function categorizeTLD(hostname) {
  const tld = hostname.split('.').pop().toLowerCase();
  
  const highRiskTLDs = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz'];
  const mediumRiskTLDs = ['info', 'biz', 'site', 'online'];
  
  if (highRiskTLDs.includes(tld)) return 'high';
  if (mediumRiskTLDs.includes(tld)) return 'medium';
  return 'low';
}

/**
 * Process HTML content for phishing indicators
 * @param {string} html - The HTML content to analyze
 * @returns {Object} Analysis results
 */
function analyzeHTMLContent(html) {
  // Check for hidden iframes
  const hiddenIframes = (html.match(/<iframe[^>]*style\s*=\s*['"][^'"]*visibility\s*:\s*hidden/g) || []).length;
  
  // Check for suspicious forms
  const passwordInputs = (html.match(/<input[^>]*type\s*=\s*['"]password['"]/g) || []).length;
  const forms = (html.match(/<form[^>]*action\s*=\s*['"](https?:)?\/\//g) || []).length;
  
  // Check for obfuscated JavaScript
  const obfuscatedJS = (html.match(/eval\s*\(|document\.write\s*\(|unescape\s*\(|fromCharCode|String\.fromCharCode/g) || []).length;
  
  // Calculate risk score based on HTML features
  let riskScore = 0;
  
  if (hiddenIframes > 0) riskScore += 0.3;
  if (passwordInputs > 0 && forms > 0) riskScore += 0.2;
  if (obfuscatedJS > 3) riskScore += 0.25;
  
  return {
    features: {
      hiddenIframes,
      passwordInputs,
      forms,
      obfuscatedJS
    },
    riskScore: Math.min(riskScore, 1.0)
  };
}

/**
 * Run on-device SVM model for quick phishing detection
 * @param {Object} features - Combined features from URL and HTML analysis
 * @returns {number} Probability of phishing (0-1)
 */
function runSVMModel(features) {
  // This is a simplified implementation
  // In a real extension, you would use a proper ML library
  
  if (!svmModel) return 0.5; // Default to medium risk if model not loaded
  
  // Convert features to vector format expected by SVM
  const featureVector = [
    features.url.domainLength / 100,
    features.url.specialCharCount / 20,
    features.url.hasIPAddress ? 1 : 0,
    features.url.suspiciousKeywords ? 1 : 0,
    features.html.hiddenIframes > 0 ? 1 : 0,
    features.html.passwordInputs > 0 ? 1 : 0,
    features.html.obfuscatedJS / 10
  ];
  
  // Simple dot product with model weights (simplified SVM prediction)
  let score = svmModel.bias;
  for (let i = 0; i < featureVector.length; i++) {
    score += featureVector[i] * svmModel.weights[i];
  }
  
  // Convert to probability using sigmoid function
  return 1 / (1 + Math.exp(-score));
}

/**
 * Call cloud-based DistilBERT model for more accurate analysis
 * @param {string} url - The URL to analyze
 * @param {string} html - The HTML content to analyze
 * @returns {Promise<Object>} Cloud model results
 */
async function callCloudModel(url, html) {
  try {
    const response = await fetch(CONFIG.cloudModelEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        url,
        html_sample: html.substring(0, 5000) // Send only a sample to reduce payload size
      })
    });
    
    return await response.json();
  } catch (error) {
    console.error('Failed to call cloud model:', error);
    return { probability: 0.5, confidence: 0.5 }; // Default values on error
  }
}

/**
 * Compare results with VirusTotal API
 * @param {string} url - The URL to check
 * @returns {Promise<Object>} VirusTotal results
 */
async function checkVirusTotal(url) {
  try {
    const encodedUrl = encodeURIComponent(url);
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${encodedUrl}`, {
      headers: {
        'x-apikey': CONFIG.virusTotalApiKey
      }
    });
    
    return await response.json();
  } catch (error) {
    console.error('Failed to check VirusTotal:', error);
    return { data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 0 } } } };
  }
}

/**
 * Combine all analysis results and determine final risk level
 * @param {Object} results - All analysis results
 * @returns {Object} Final assessment with risk level and explanation
 */
function determineRiskLevel(results) {
  // Weight different signals
  const weights = {
    lexical: 0.2,
    html: 0.2,
    svm: 0.3,
    cloud: 0.3
  };
  
  // Calculate weighted score
  const weightedScore = 
    results.lexical.riskScore * weights.lexical +
    results.html.riskScore * weights.html +
    results.svm.probability * weights.svm +
    results.cloud.probability * weights.cloud;
  
  // Determine risk level
  let riskLevel;
  if (weightedScore < CONFIG.detectionThresholds.low) {
    riskLevel = 'safe';
  } else if (weightedScore < CONFIG.detectionThresholds.medium) {
    riskLevel = 'suspicious';
  } else {
    riskLevel = 'dangerous';
  }
  
  // Generate explanation
  const riskFactors = [];
  
  if (results.lexical.features.hasIPAddress) {
    riskFactors.push('IP address used in domain');
  }
  
  if (results.lexical.features.suspiciousKeywords) {
    riskFactors.push('Suspicious keywords in URL');
  }
  
  if (results.html.features.hiddenIframes > 0) {
    riskFactors.push(`Hidden iframes detected (${results.html.features.hiddenIframes})`);
  }
  
  if (results.html.features.passwordInputs > 0 && results.lexical.features.suspiciousKeywords) {
    riskFactors.push('Login form on suspicious domain');
  }
  
  if (results.virusTotal && results.virusTotal.data?.attributes?.last_analysis_stats?.malicious > 0) {
    riskFactors.push(`Flagged by ${results.virusTotal.data.attributes.last_analysis_stats.malicious} security vendors`);
  }
  
  return {
    url: results.url,
    riskLevel,
    score: weightedScore,
    riskFactors,
    timestamp: Date.now(),
    detailedResults: results
  };
}

/**
 * Main analysis function that orchestrates the entire detection process
 * @param {string} url - The URL to analyze
 * @param {string} html - The HTML content to analyze
 * @returns {Promise<Object>} Complete analysis results
 */
async function analyzeWebsite(url, html) {
  // Check cache first
  if (cachedResults.has(url)) {
    const cached = cachedResults.get(url);
    if (Date.now() - cached.timestamp < 3600000) { // Cache valid for 1 hour
      return cached;
    }
  }
  
  console.log(`Analyzing website: ${url}`);
  
  // Run all analyses in parallel
  const [lexicalResults, htmlResults, virusTotalResults] = await Promise.all([
    Promise.resolve(analyzeLexicalFeatures(url)),
    Promise.resolve(analyzeHTMLContent(html)),
    checkVirusTotal(url)
  ]);
  
  // Run on-device SVM model
  const combinedFeatures = {
    url: lexicalResults.features,
    html: htmlResults.features
  };
  
  const svmResults = {
    probability: runSVMModel(combinedFeatures)
  };
  
  // If SVM model indicates high risk or is uncertain, call cloud model
  let cloudResults;
  if (svmResults.probability > 0.4) {
    cloudResults = await callCloudModel(url, html);
  } else {
    cloudResults = { probability: 0.1, confidence: 0.9 };
  }
  
  // Combine all results
  const results = {
    url,
    lexical: lexicalResults,
    html: htmlResults,
    svm: svmResults,
    cloud: cloudResults,
    virusTotal: virusTotalResults
  };
  
  // Determine final risk assessment
  const assessment = determineRiskLevel(results);
  
  // Cache results
  cachedResults.set(url, assessment);
  
  // Limit cache size
  if (cachedResults.size > 100) {
    const oldestKey = cachedResults.keys().next().value;
    cachedResults.delete(oldestKey);
  }
  
  return assessment;
}

// Listen for navigation events
chrome.webNavigation.onCommitted.addListener(details => {
  if (details.frameId === 0) { // Main frame only
    // Notify content script to begin analysis
    chrome.tabs.sendMessage(details.tabId, {
      action: 'startAnalysis',
      url: details.url
    });
  }
});

// Listen for messages from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'analyzeWebsite') {
    analyzeWebsite(message.url, message.html)
      .then(results => {
        // Send results back to content script
        chrome.tabs.sendMessage(sender.tab.id, {
          action: 'analysisResults',
          results
        });
        
        // Also update popup if open
        chrome.runtime.sendMessage({
          action: 'updateResults',
          results
        });
        
        sendResponse({ success: true });
      })
      .catch(error => {
        console.error('Analysis failed:', error);
        sendResponse({ success: false, error: error.message });
      });
    
    return true; // Indicates async response
  }
});

// Initialize on extension load
initialize();