@echo off
echo PhishGuard AI - Test Runner
echo ===========================
echo.

echo Checking extension structure...
if not exist manifest.json (
    echo ERROR: manifest.json not found!
    exit /b 1
)

if not exist src\background.js (
    echo ERROR: background.js not found!
    exit /b 1
)

if not exist src\content.js (
    echo ERROR: content.js not found!
    exit /b 1
)

echo Extension structure looks good!
echo.

echo Checking for test pages...
if not exist test_pages (
    echo Creating test_pages directory...
    mkdir test_pages
)

echo.
echo To test the extension:
echo 1. Load the extension in Chrome/Edge using Developer mode
echo 2. Open the test pages in your browser:
echo    - test_pages\legitimate_bank.html
echo    - test_pages\phishing_example.html
echo 3. Observe the extension's behavior on each page
echo.

echo Would you like to open Chrome with the extension now? (Y/N)
set /p choice=
if /i "%choice%"=="Y" (
    echo Attempting to open Chrome with the extension...
    start chrome --load-extension="%CD%"
) else (
    echo Please follow the instructions in INSTALLATION.md to load the extension manually.
)

echo.
echo Test runner complete!
pause