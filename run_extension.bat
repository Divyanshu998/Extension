@echo off
echo PhishGuard AI Extension Loader
echo =============================
echo.

echo This script will help you load and test the PhishGuard AI extension.
echo.

echo Step 1: Opening the extension loading guide...
start "" "load_extension.html"
echo.

echo Step 2: Would you like to open Chrome with the extensions page? (Y/N)
set /p choice=
if /i "%choice%"=="Y" (
    echo Opening Chrome extensions page...
    start chrome chrome://extensions/
) else (
    echo Please manually open Chrome and navigate to chrome://extensions
)
echo.

echo Step 3: Would you like to open the test pages? (Y/N)
set /p choice=
if /i "%choice%"=="Y" (
    echo Opening test pages...
    start chrome "file://%CD%/test_pages/legitimate_bank.html"
    timeout /t 2 > nul
    start chrome "file://%CD%/test_pages/phishing_example.html"
) else (
    echo You can open the test pages later from the loading guide.
)
echo.

echo PhishGuard AI Extension Loader complete!
echo Follow the instructions in the opened HTML page to load the extension.
echo.

pause