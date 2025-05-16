/**
 * PhishGuard AI - Side Panel Script
 * Handles the detailed analysis view in the side panel
 */

// DOM elements
const loadingElement = document.getElementById('loading');
const resultsElement = document.getElementById('results');
const statusIconElement = document.getElementById('status-icon');
const statusTextElement = document.getElementById('status-text');
const urlDisplayElement = document.getElementById('url-display');
const riskFactorsListElement = document.getElementById('risk-factors-list');
const phishguardScoreElement = document.getElementById('phishguard-score');
const virustotalScoreElement = document.getElementById('virustotal-score');
const domainAgeElement = document.getElementById('domain-age');
const sslStatusElement = document.getElementById('ssl-status');
const lexicalFeaturesTableElement = document.getElementById('lexical-features-table');
const htmlFeaturesTableElement = document.getElementById('html-features-table');
const svmMeterFillElement = document.getElementById('svm-meter-fill');
const svmScoreElement = document.getElementById('svm-score');
const cloudMeterFillElement = document.getElementById('cloud-meter-fill');
const cloudScoreElement = document.getElementById('cloud-score');
const visualMeterFillElement = document.getElementById('visual-meter-fill');
const visualScoreElement = document.getElementById('visual-score');
const timestampElement = document.getElementById('timestamp');
const reportButton = document.getElementById('report-btn');
const closeButton = document.getElementById('close-btn');

// Current analysis results
let currentResults = null;

/**
 * Format a timestamp as a readable date string
 * @param {number} timestamp - Timestamp in milliseconds
 * @returns {string} Formatted date string
 */
function formatTimestamp(timestamp) {
  const date = new Date(timestamp);
  return date.toLocaleString();
}

/**
 * Determine impact level based on score
 * @param {number} score - Score between 0 and 1
 * @returns {string} Impact level (low, medium, high)
 */
function getImpactLevel(score) {
  if (score < 0.3) return 'low';
  if (score < 0.7) return 'medium';
  return 'high';
}

/**
 * Create a table row for feature display
 * @param {string} name - Feature name
 * @param {string|number} value - Feature value
 * @param {string} impact - Impact level (low, medium, high)
 * @returns {HTMLTableRowElement} Table row element
 */
function createFeatureRow(name, value, impact) {
  const row = document.createElement('tr');
  
  const nameCell = document.createElement('td');
  nameCell.textContent = name;
  row.appendChild(nameCell);
  
  const valueCell = document.createElement('td');
  valueCell.className = 'feature-value';
  valueCell.textContent = value;
  row.appendChild(valueCell);
  
  const impactCell = document.createElement('td');
  impactCell.className = `feature-impact impact-${impact}`;
  impactCell.textContent = impact.charAt(0).toUpperCase() + impact.slice(1);
  row.appendChild(impactCell);
  
  return row;
}

/**
 * Update the UI with analysis results
 * @param {Object} results - Analysis results
 */
function updateUI(results) {
  // Store results
  currentResults = results;
  
  // Hide loading, show results
  loadingElement.style.display = 'none';
  resultsElement.style.display = 'block';
  
  // Update URL display
  urlDisplayElement.textContent = results.url;
  
  // Update timestamp
  timestampElement.textContent = formatTimestamp(results.timestamp);
  
  // Update status indicator
  statusIconElement.className = 'status-icon';
  
  switch (results.riskLevel) {
    case 'safe':
      statusIconElement.classList.add('status-safe');
      statusIconElement.textContent = '✓';
      statusTextElement.textContent = 'Safe';
      break;
    case 'suspicious':
      statusIconElement.classList.add('status-suspicious');
      statusIconElement.textContent = '!';
      statusTextElement.textContent = 'Suspicious';
      break;
    case 'dangerous':
      statusIconElement.classList.add('status-dangerous');
      statusIconElement.textContent = '!';
      statusTextElement.textContent = 'Dangerous';
      break;
    default:
      statusIconElement.classList.add('status-unknown');
      statusIconElement.textContent = '?';
      statusTextElement.textContent = 'Unknown';
  }
  
  // Update risk factors
  riskFactorsListElement.innerHTML = '';
  
  if (results.riskFactors && results.riskFactors.length > 0) {
    results.riskFactors.forEach(factor => {
      const factorElement = document.createElement('div');
      factorElement.className = 'risk-factor-item';
      factorElement.textContent = factor;
      riskFactorsListElement.appendChild(factorElement);
    });
  } else {
    const noFactorsElement = document.createElement('div');
    noFactorsElement.textContent = 'No significant risk factors detected.';
    riskFactorsListElement.appendChild(noFactorsElement);
  }
  
  // Update scores
  phishguardScoreElement.textContent = `${Math.round(results.score * 100)}%`;
  
  const vtPositives = results.detailedResults?.virusTotal?.data?.attributes?.last_analysis_stats?.malicious || 0;
  const vtTotal = results.detailedResults?.virusTotal?.data?.attributes?.last_analysis_stats?.harmless + vtPositives || 0;
  virustotalScoreElement.textContent = vtTotal > 0 ? `${vtPositives}/${vtTotal}` : 'N/A';
  
  // Update domain info
  domainAgeElement.textContent = results.detailedResults?.domainAge || 'Unknown';
  sslStatusElement.textContent = results.detailedResults?.sslValid ? 'Valid' : 'Invalid or Missing';
  
  // Update lexical features table
  lexicalFeaturesTableElement.innerHTML = '';
  
  const lexicalFeatures = results.detailedResults?.lexical?.features || {};
  
  if (lexicalFeatures.domainLength) {
    const impact = getImpactLevel(lexicalFeatures.domainLength > 30 ? 0.7 : 0.2);
    lexicalFeaturesTableElement.appendChild(createFeatureRow('Domain Length', lexicalFeatures.domainLength, impact));
  }
  
  if (lexicalFeatures.hasIPAddress !== undefined) {
    const impact = lexicalFeatures.hasIPAddress ? 'high' : 'low';
    lexicalFeaturesTableElement.appendChild(createFeatureRow('IP Address in URL', lexicalFeatures.hasIPAddress ? 'Yes' : 'No', impact));
  }
  
  if (lexicalFeatures.specialCharCount !== undefined) {
    const impact = getImpactLevel(lexicalFeatures.specialCharCount > 10 ? 0.8 : lexicalFeatures.specialCharCount > 5 ? 0.5 : 0.2);
    lexicalFeaturesTableElement.appendChild(createFeatureRow('Special Characters', lexicalFeatures.specialCharCount, impact));
  }
  
  if (lexicalFeatures.suspiciousKeywords !== undefined) {
    const impact = lexicalFeatures.suspiciousKeywords ? 'high' : 'low';
    lexicalFeaturesTableElement.appendChild(createFeatureRow('Suspicious Keywords', lexicalFeatures.suspiciousKeywords ? 'Yes' : 'No', impact));
  }
  
  if (lexicalFeatures.tldCategory) {
    const impact = lexicalFeatures.tldCategory === 'high' ? 'high' : lexicalFeatures.tldCategory === 'medium' ? 'medium' : 'low';
    lexicalFeaturesTableElement.appendChild(createFeatureRow('TLD Risk Category', lexicalFeatures.tldCategory, impact));
  }
  
  // Update HTML features table
  htmlFeaturesTableElement.innerHTML = '';
  
  const htmlFeatures = results.detailedResults?.html?.features || {};
  
  if (htmlFeatures.hiddenIframes !== undefined) {
    const impact = htmlFeatures.hiddenIframes > 0 ? 'high' : 'low';
    htmlFeaturesTableElement.appendChild(createFeatureRow('Hidden iframes', htmlFeatures.hiddenIframes, impact));
  }
  
  if (htmlFeatures.passwordInputs !== undefined) {
    const impact = htmlFeatures.passwordInputs > 0 && lexicalFeatures.suspiciousKeywords ? 'high' : 'medium';
    htmlFeaturesTableElement.appendChild(createFeatureRow('Password Inputs', htmlFeatures.passwordInputs, impact));
  }
  
  if (htmlFeatures.forms !== undefined) {
    const impact = htmlFeatures.forms > 0 && lexicalFeatures.suspiciousKeywords ? 'high' : 'medium';
    htmlFeaturesTableElement.appendChild(createFeatureRow('Forms', htmlFeatures.forms, impact));
  }
  
  if (htmlFeatures.obfuscatedJS !== undefined) {
    const impact = htmlFeatures.obfuscatedJS > 3 ? 'high' : htmlFeatures.obfuscatedJS > 0 ? 'medium' : 'low';
    htmlFeaturesTableElement.appendChild(createFeatureRow('Obfuscated JavaScript', htmlFeatures.obfuscatedJS, impact));
  }
  
  // Update model scores
  const svmScore = results.detailedResults?.svm?.probability || 0;
  svmMeterFillElement.style.width = `${svmScore * 100}%`;
  svmMeterFillElement.className = `meter-fill meter-fill-${results.riskLevel}`;
  svmScoreElement.textContent = `${Math.round(svmScore * 100)}%`;
  
  const cloudScore = results.detailedResults?.cloud?.probability || 0;
  cloudMeterFillElement.style.width = `${cloudScore * 100}%`;
  cloudMeterFillElement.className = `meter-fill meter-fill-${results.riskLevel}`;
  cloudScoreElement.textContent = `${Math.round(cloudScore * 100)}%`;
  
  const visualScore = results.detailedResults?.visualSimilarity || 0;
  visualMeterFillElement.style.width = `${visualScore * 100}%`;
  visualMeterFillElement.className = `meter-fill meter-fill-${results.riskLevel}`;
  visualScoreElement.textContent = `${Math.round(visualScore * 100)}%`;
}

/**
 * Report a false detection
 */
function reportFalseDetection() {
  if (!currentResults) return;
  
  const url = encodeURIComponent(currentResults.url);
  const level = encodeURIComponent(currentResults.riskLevel);
  const score = encodeURIComponent(Math.round(currentResults.score * 100));
  
  chrome.tabs.create({
    url: `https://example.com/report-false-detection?url=${url}&level=${level}&score=${score}`
  });
}

/**
 * Close the side panel
 */
function closePanel() {
  // This is a placeholder - in a real extension, you would use chrome.sidePanel.close()
  // which is not available in this prototype
  window.close();
}

// Add event listeners
reportButton.addEventListener('click', reportFalseDetection);
closeButton.addEventListener('click', closePanel);

// Listen for messages from background/popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'updateSidePanel' && message.results) {
    updateUI(message.results);
    sendResponse({ success: true });
  }
  
  return true; // Indicates async response
});

// Request current results when panel opens
document.addEventListener('DOMContentLoaded', () => {
  chrome.runtime.sendMessage({
    action: 'getSidePanelData'
  });
});