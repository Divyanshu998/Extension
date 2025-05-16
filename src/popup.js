/**
 * PhishGuard AI - Popup Script
 * Handles the extension popup UI and interactions
 */

// DOM elements
const loadingElement = document.getElementById('loading');
const resultsElement = document.getElementById('results');
const statusIconElement = document.getElementById('status-icon');
const statusTextElement = document.getElementById('status-text');
const urlDisplayElement = document.getElementById('url-display');
const riskFactorsElement = document.getElementById('risk-factors');
const riskFactorsListElement = document.getElementById('risk-factors-list');
const accuracyMeterFillElement = document.getElementById('accuracy-meter-fill');
const detailsButton = document.getElementById('details-btn');
const reportButton = document.getElementById('report-btn');

// Current analysis results
let currentResults = null;

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
  if (results.riskFactors && results.riskFactors.length > 0) {
    riskFactorsElement.style.display = 'block';
    riskFactorsListElement.innerHTML = '';
    
    results.riskFactors.forEach(factor => {
      const factorElement = document.createElement('div');
      factorElement.className = 'risk-factor-item';
      factorElement.textContent = factor;
      riskFactorsListElement.appendChild(factorElement);
    });
  } else {
    riskFactorsElement.style.display = 'none';
  }
  
  // Update accuracy meter
  const confidenceScore = results.detailedResults?.cloud?.confidence || 0.5;
  accuracyMeterFillElement.style.width = `${confidenceScore * 100}%`;
}

/**
 * Open the side panel with detailed analysis
 */
function openDetailedAnalysis() {
  chrome.runtime.sendMessage({
    action: 'openSidePanel',
    results: currentResults
  });
}

/**
 * Open the report issue form
 */
function reportIssue() {
  const url = currentResults ? encodeURIComponent(currentResults.url) : '';
  const level = currentResults ? encodeURIComponent(currentResults.riskLevel) : 'unknown';
  
  chrome.tabs.create({
    url: `https://example.com/report?url=${url}&level=${level}`
  });
}

// Add event listeners
detailsButton.addEventListener('click', openDetailedAnalysis);
reportButton.addEventListener('click', reportIssue);

// Get current tab information when popup opens
document.addEventListener('DOMContentLoaded', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    const currentTab = tabs[0];
    
    // Request analysis results for current tab
    chrome.runtime.sendMessage({
      action: 'getAnalysisResults',
      tabId: currentTab.id,
      url: currentTab.url
    });
  });
});

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'updateResults') {
    updateUI(message.results);
    sendResponse({ success: true });
  }
  
  return true; // Indicates async response
});