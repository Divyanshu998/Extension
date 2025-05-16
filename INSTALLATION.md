# PhishGuard AI - Installation and Testing Guide

This guide will help you install and test the PhishGuard AI browser extension prototype.

## Prerequisites

- Google Chrome or Microsoft Edge browser
- Basic understanding of browser extensions

## Installation Steps

1. **Prepare the extension**
   - Make sure all the files are in the correct structure as shown in the repository
   - Generate icons using the `create_icons.html` file or use your own icons
   - Place the icon files (icon16.png, icon48.png, icon128.png) in the `assets` folder

2. **Load the extension in Chrome/Edge**
   - Open Chrome/Edge and navigate to `chrome://extensions` (Chrome) or `edge://extensions` (Edge)
   - Enable "Developer mode" using the toggle in the top-right corner
   - Click "Load unpacked" button
   - Select the root folder of the PhishGuard AI extension (the folder containing manifest.json)
   - The extension should now appear in your extensions list

3. **Verify installation**
   - You should see the PhishGuard AI icon in your browser toolbar
   - Click on the icon to open the popup interface
   - The extension should show "Analyzing website..." for the current page

## Testing the Extension

### Test with Legitimate Website

1. Navigate to a legitimate banking website (e.g., chase.com, bankofamerica.com)
2. Alternatively, open the included test page: `test_pages/legitimate_bank.html`
3. The extension should analyze the page and show a green "Safe" status
4. Click on the extension icon to see the analysis details

### Test with Simulated Phishing Page

1. Open the included test page: `test_pages/phishing_example.html`
2. The extension should detect suspicious elements and show a warning banner
3. Click "View Details" to see the detailed analysis
4. The side panel should show the risk factors that were detected

### Features to Test

1. **URL Analysis**
   - Navigate to a URL with suspicious patterns (e.g., IP address URLs, excessive subdomains)
   - The extension should detect and highlight these issues

2. **HTML Content Inspection**
   - The phishing example page includes hidden iframes and obfuscated JavaScript
   - The extension should detect these elements and list them as risk factors

3. **Warning System**
   - Verify that the warning banner appears for suspicious pages
   - Check that the traffic light system (green/amber/red) works correctly

4. **Explainability Features**
   - Open the side panel to view detailed analysis
   - Verify that risk factors are clearly explained
   - Check that the confidence metrics are displayed

## Troubleshooting

If the extension doesn't work as expected:

1. **Check the console for errors**
   - Open browser developer tools (F12 or Ctrl+Shift+I)
   - Go to the Console tab
   - Look for any error messages related to the extension

2. **Verify all files are present**
   - Make sure all required files are in the correct locations
   - Check that the manifest.json file is properly formatted

3. **Reload the extension**
   - Go to `chrome://extensions` or `edge://extensions`
   - Find PhishGuard AI and click the refresh icon
   - Reload the page you're testing

4. **Clear browser cache**
   - Sometimes cached resources can interfere with extension functionality
   - Clear your browser cache and reload the extension

## Demo Script

For demonstration purposes, follow the 30-second demo script in `DEMO_SCRIPT.md`:

1. Start by showing the extension icon and explaining its purpose
2. Navigate to a legitimate banking website to show the "Safe" status
3. Navigate to the phishing example page to demonstrate the warning system
4. Show the detailed analysis in the side panel
5. Explain how the AI models work together to detect phishing attempts

## Next Steps

After testing the basic functionality, you can:

1. Modify the code to improve detection accuracy
2. Add additional features or UI improvements
3. Test with more complex phishing examples
4. Implement the cloud-based model component