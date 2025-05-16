/**
 * PhishGuard AI - Content Script
 * Runs on web pages to extract content and display warnings
 */

// Configuration
const CONFIG = {
  analysisDelay: 500, // ms to wait after page load before analyzing
  warningBannerDuration: 10000, // ms to show warning banner
  screenshotQuality: 0.7, // JPEG quality for visual analysis
  visualSimilarityThreshold: 0.85 // Threshold for visual similarity detection
};

// State
let isAnalyzing = false;
let currentResults = null;
let warningBanner = null;
let sidePanelButton = null;

/**
 * Extract HTML content and metadata from the current page
 * @returns {Object} Page content and metadata
 */
function extractPageContent() {
  // Get basic page information
  const url = window.location.href;
  const domain = window.location.hostname;
  const title = document.title;
  const html = document.documentElement.outerHTML;
  
  // Extract forms
  const forms = Array.from(document.forms).map(form => ({
    action: form.action,
    method: form.method,
    hasPasswordField: Array.from(form.elements).some(el => el.type === 'password'),
    hasEmailField: Array.from(form.elements).some(el => 
      el.type === 'email' || 
      el.name?.toLowerCase().includes('email') ||
      el.id?.toLowerCase().includes('email')
    )
  }));
  
  // Extract links
  const externalLinks = Array.from(document.links)
    .filter(link => {
      try {
        return new URL(link.href).hostname !== domain;
      } catch (e) {
        return false;
      }
    })
    .map(link => link.href);
  
  // Extract scripts
  const scripts = Array.from(document.scripts)
    .filter(script => script.src)
    .map(script => script.src);
  
  // Extract iframes
  const iframes = Array.from(document.querySelectorAll('iframe'))
    .map(iframe => ({
      src: iframe.src,
      hidden: iframe.style.display === 'none' || 
             iframe.style.visibility === 'hidden' ||
             iframe.width === '0' ||
             iframe.height === '0'
    }));
  
  // Check for login indicators
  const hasLoginForm = forms.some(form => 
    form.hasPasswordField || 
    form.action?.toLowerCase().includes('login') ||
    form.action?.toLowerCase().includes('signin')
  );
  
  return {
    url,
    domain,
    title,
    html,
    metadata: {
      forms,
      externalLinks,
      scripts,
      iframes,
      hasLoginForm
    }
  };
}

/**
 * Capture a screenshot of the visible page for visual analysis
 * @returns {Promise<string>} Base64-encoded screenshot
 */
async function captureVisiblePage() {
  // This is a simplified implementation
  // In a real extension, you would use chrome.tabs.captureVisibleTab
  
  // Create a canvas element
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  
  // Set canvas dimensions to viewport size
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
  
  // Draw the current page to the canvas (simplified)
  // In a real extension, this would use the chrome.tabs.captureVisibleTab API
  ctx.fillStyle = 'white';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  
  try {
    // Use html2canvas library if available (not included in this prototype)
    if (window.html2canvas) {
      const renderedCanvas = await html2canvas(document.body);
      canvas.width = renderedCanvas.width;
      canvas.height = renderedCanvas.height;
      ctx.drawImage(renderedCanvas, 0, 0);
    }
  } catch (error) {
    console.error('Failed to capture page:', error);
  }
  
  // Convert canvas to base64 image
  return canvas.toDataURL('image/jpeg', CONFIG.screenshotQuality);
}

/**
 * Create and show a warning banner based on risk level
 * @param {Object} results - Analysis results
 */
function showWarningBanner(results) {
  // Remove existing banner if present
  if (warningBanner) {
    document.body.removeChild(warningBanner);
  }
  
  // Create banner element
  warningBanner = document.createElement('div');
  warningBanner.id = 'phishguard-warning-banner';
  
  // Set styles based on risk level
  let backgroundColor, textColor, borderColor, icon, message;
  
  switch (results.riskLevel) {
    case 'dangerous':
      backgroundColor = 'rgba(220, 53, 69, 0.95)';
      textColor = '#fff';
      borderColor = '#dc3545';
      icon = '⚠️';
      message = 'Warning: This website has been detected as a potential phishing site.';
      break;
    case 'suspicious':
      backgroundColor = 'rgba(255, 193, 7, 0.95)';
      textColor = '#000';
      borderColor = '#ffc107';
      icon = '⚠️';
      message = 'Caution: This website contains some suspicious elements.';
      break;
    default: // safe
      backgroundColor = 'rgba(40, 167, 69, 0.95)';
      textColor = '#fff';
      borderColor = '#28a745';
      icon = '✓';
      message = 'This website appears to be safe.';
  }
  
  // Set banner styles
  Object.assign(warningBanner.style, {
    position: 'fixed',
    top: '0',
    left: '0',
    right: '0',
    zIndex: '2147483647',
    padding: '10px 20px',
    backgroundColor,
    color: textColor,
    borderBottom: `2px solid ${borderColor}`,
    fontFamily: 'Arial, sans-serif',
    fontSize: '14px',
    textAlign: 'center',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    boxShadow: '0 2px 5px rgba(0, 0, 0, 0.2)',
    transition: 'all 0.3s ease-in-out'
  });
  
  // Create banner content
  warningBanner.innerHTML = `
    <div style="display: flex; align-items: center;">
      <span style="font-size: 20px; margin-right: 10px;">${icon}</span>
      <span>${message}</span>
    </div>
    <div>
      <button id="phishguard-details-btn" style="
        background-color: transparent;
        border: 1px solid ${textColor};
        color: ${textColor};
        padding: 5px 10px;
        border-radius: 3px;
        cursor: pointer;
        margin-right: 10px;
      ">View Details</button>
      <button id="phishguard-close-btn" style="
        background-color: transparent;
        border: none;
        color: ${textColor};
        font-size: 16px;
        cursor: pointer;
      ">×</button>
    </div>
  `;
  
  // Add banner to page
  document.body.insertBefore(warningBanner, document.body.firstChild);
  
  // Add event listeners
  document.getElementById('phishguard-details-btn').addEventListener('click', () => {
    // Open side panel with details
    chrome.runtime.sendMessage({
      action: 'openSidePanel',
      results
    });
  });
  
  document.getElementById('phishguard-close-btn').addEventListener('click', () => {
    document.body.removeChild(warningBanner);
    warningBanner = null;
  });
  
  // Auto-hide banner after duration (for safe sites only)
  if (results.riskLevel === 'safe') {
    setTimeout(() => {
      if (warningBanner && document.body.contains(warningBanner)) {
        warningBanner.style.opacity = '0';
        setTimeout(() => {
          if (warningBanner && document.body.contains(warningBanner)) {
            document.body.removeChild(warningBanner);
            warningBanner = null;
          }
        }, 300);
      }
    }, CONFIG.warningBannerDuration);
  }
}

/**
 * Create a floating button to access the side panel
 */
function createSidePanelButton() {
  if (sidePanelButton) {
    return;
  }
  
  sidePanelButton = document.createElement('div');
  sidePanelButton.id = 'phishguard-panel-btn';
  
  // Set button styles
  Object.assign(sidePanelButton.style, {
    position: 'fixed',
    bottom: '20px',
    right: '20px',
    width: '50px',
    height: '50px',
    borderRadius: '50%',
    backgroundColor: '#4285F4',
    color: '#fff',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    boxShadow: '0 2px 10px rgba(0, 0, 0, 0.2)',
    cursor: 'pointer',
    zIndex: '2147483646',
    fontSize: '24px',
    transition: 'all 0.3s ease'
  });
  
  sidePanelButton.innerHTML = '🛡️';
  sidePanelButton.title = 'PhishGuard AI Protection Status';
  
  // Add hover effect
  sidePanelButton.addEventListener('mouseover', () => {
    sidePanelButton.style.transform = 'scale(1.1)';
  });
  
  sidePanelButton.addEventListener('mouseout', () => {
    sidePanelButton.style.transform = 'scale(1)';
  });
  
  // Add click handler
  sidePanelButton.addEventListener('click', () => {
    chrome.runtime.sendMessage({
      action: 'openSidePanel',
      results: currentResults
    });
  });
  
  // Add to page
  document.body.appendChild(sidePanelButton);
  
  // Update button color based on risk level
  if (currentResults) {
    updateSidePanelButton(currentResults.riskLevel);
  }
}

/**
 * Update the side panel button color based on risk level
 * @param {string} riskLevel - The risk level (safe, suspicious, dangerous)
 */
function updateSidePanelButton(riskLevel) {
  if (!sidePanelButton) {
    createSidePanelButton();
  }
  
  switch (riskLevel) {
    case 'dangerous':
      sidePanelButton.style.backgroundColor = '#dc3545';
      sidePanelButton.innerHTML = '⚠️';
      break;
    case 'suspicious':
      sidePanelButton.style.backgroundColor = '#ffc107';
      sidePanelButton.innerHTML = '⚠️';
      break;
    default: // safe
      sidePanelButton.style.backgroundColor = '#28a745';
      sidePanelButton.innerHTML = '✓';
  }
}

/**
 * Start the analysis process
 */
async function startAnalysis() {
  if (isAnalyzing) return;
  isAnalyzing = true;
  
  try {
    // Extract page content
    const content = extractPageContent();
    
    // Capture screenshot for visual analysis
    const screenshot = await captureVisiblePage();
    
    // Send data to background script for analysis
    chrome.runtime.sendMessage({
      action: 'analyzeWebsite',
      url: content.url,
      html: content.html,
      metadata: content.metadata,
      screenshot
    }, response => {
      if (response && response.success) {
        console.log('Analysis request sent successfully');
      } else {
        console.error('Failed to send analysis request:', response?.error);
      }
      isAnalyzing = false;
    });
  } catch (error) {
    console.error('Error during analysis:', error);
    isAnalyzing = false;
  }
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'startAnalysis') {
    // Delay analysis to ensure page is fully loaded
    setTimeout(startAnalysis, CONFIG.analysisDelay);
    sendResponse({ success: true });
  } else if (message.action === 'analysisResults') {
    // Store results
    currentResults = message.results;
    
    // Show warning banner if risk level is not safe
    if (currentResults.riskLevel !== 'safe') {
      showWarningBanner(currentResults);
    }
    
    // Create or update side panel button
    createSidePanelButton();
    updateSidePanelButton(currentResults.riskLevel);
    
    sendResponse({ success: true });
  }
  
  return true; // Indicates async response
});

// Start analysis when page is loaded
if (document.readyState === 'complete') {
  setTimeout(startAnalysis, CONFIG.analysisDelay);
} else {
  window.addEventListener('load', () => {
    setTimeout(startAnalysis, CONFIG.analysisDelay);
  });
}