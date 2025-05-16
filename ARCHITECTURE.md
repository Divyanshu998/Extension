# PhishGuard AI: Architecture Overview

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     PhishGuard AI Extension                      │
└───────────────────────────────┬─────────────────────────────────┘
                                │
           ┌───────────────────┴────────────────────┐
           ▼                                        ▼
┌────────────────────────┐              ┌────────────────────────┐
│   Background Service   │              │    Content Scripts     │
│                        │◄────────────►│                        │
│ - Model Management     │   Messages   │ - Page Analysis        │
│ - Threat Intelligence  │              │ - Warning Display      │
│ - Detection Logic      │              │ - User Interface       │
└──────────┬─────────────┘              └────────────────────────┘
           │
           │
┌──────────▼─────────────────────────────────────────────────────┐
│                        Detection Pipeline                       │
├─────────────────┬─────────────────┬──────────────┬─────────────┤
│  URL Analysis   │  HTML Analysis  │ Visual Model │ Cloud Model │
│                 │                 │              │             │
│ - Domain Age    │ - Hidden iframes│ - Screenshot │ - DistilBERT│
│ - Special Chars │ - Form Analysis │ - CNN Model  │ - NLP Model │
│ - TLD Risk      │ - Obfuscation   │ - 94% Acc.   │ - 96% Acc.  │
└─────────────────┴─────────────────┴──────────────┴─────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Risk Assessment Engine                      │
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │ SVM Model   │    │ Weighted    │    │ Threat Intelligence │  │
│  │ (On-device) │───►│ Aggregation │◄───│ Database            │  │
│  └─────────────┘    └──────┬──────┘    └─────────────────────┘  │
│                            │                                     │
└────────────────────────────┼─────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                       User Interface                             │
├─────────────────┬─────────────────────┬─────────────────────────┤
│  Warning Banner │  Side Panel Details │  Popup Dashboard        │
│  (Traffic Light)│  (Explainability)   │  (Summary & Controls)   │
└─────────────────┴─────────────────────┴─────────────────────────┘
```

## Component Diagram

```
┌───────────────────────────────────────────────────────────────────────┐
│                           Browser Extension                            │
│                                                                       │
│  ┌─────────────────┐      ┌─────────────────┐     ┌─────────────────┐ │
│  │                 │      │                 │     │                 │ │
│  │  background.js  │◄────►│   content.js    │────►│    popup.js     │ │
│  │                 │      │                 │     │                 │ │
│  └────────┬────────┘      └────────┬────────┘     └────────┬────────┘ │
│           │                        │                       │          │
│           │                        │                       │          │
│  ┌────────▼────────┐      ┌────────▼────────┐     ┌────────▼────────┐ │
│  │                 │      │                 │     │                 │ │
│  │  SVM Model      │      │  Feature        │     │  UI Components  │ │
│  │  (On-device)    │◄────►│  Extractor      │     │  (HTML/CSS/JS)  │ │
│  │                 │      │                 │     │                 │ │
│  └────────┬────────┘      └─────────────────┘     └─────────────────┘ │
│           │                                                           │
│           │               ┌─────────────────┐                         │
│           └──────────────►│  Cloud API      │                         │
│                           │  (DistilBERT)   │                         │
│                           │                 │                         │
│                           └─────────────────┘                         │
└───────────────────────────────────────────────────────────────────────┘
```

## Data Flow Diagram

```
┌──────────┐         ┌───────────┐          ┌──────────────┐
│          │         │           │          │              │
│  Website │────────►│  Browser  │─────────►│  Content.js  │
│          │         │           │          │              │
└──────────┘         └───────────┘          └──────┬───────┘
                                                   │
                                                   │ Extract Features
                                                   ▼
┌──────────────────┐          ┌───────────────────────────────┐
│                  │          │                               │
│  Threat Intel    │◄────────►│  Background.js                │
│  Database        │          │  (Detection Pipeline)         │
│                  │          │                               │
└──────────────────┘          └───────────────┬───────────────┘
                                              │
                                              │ If needed
                                              ▼
┌──────────────────┐          ┌───────────────────────────────┐
│                  │          │                               │
│  VirusTotal API  │◄────────►│  Cloud-based DistilBERT Model │
│                  │          │                               │
└──────────────────┘          └───────────────┬───────────────┘
                                              │
                                              │
                                              ▼
┌──────────────────┐          ┌───────────────────────────────┐
│                  │          │                               │
│  User            │◄────────►│  Warning UI + Explainability  │
│                  │          │                               │
└──────────────────┘          └───────────────────────────────┘
```

## Detection Process Flow

1. **URL Analysis**
   - Parse URL components
   - Extract lexical features
   - Check for suspicious patterns
   - Calculate initial risk score

2. **HTML Content Analysis**
   - Scan for hidden elements
   - Detect suspicious forms
   - Identify obfuscated code
   - Analyze external resources

3. **On-device SVM Model**
   - Process combined features
   - Generate preliminary score
   - Make fast initial assessment

4. **Decision Point**
   - If score < threshold: Mark as safe
   - If score > high threshold: Mark as dangerous
   - If uncertain: Proceed to cloud model

5. **Cloud-based DistilBERT Model** (if needed)
   - Send features to API
   - Process with NLP model
   - Return confidence score

6. **Visual Recognition** (for login pages)
   - Capture page screenshot
   - Compare with known templates
   - Detect visual similarities

7. **Risk Assessment**
   - Combine all signals with weights
   - Calculate final risk score
   - Determine risk level (safe/suspicious/dangerous)

8. **User Interface**
   - Display appropriate warning
   - Show risk factors
   - Provide detailed explanation

## Technology Stack

- **Frontend**: HTML, CSS, JavaScript
- **Models**: 
  - SVM (Support Vector Machine) for on-device detection
  - DistilBERT (NLP) for cloud-based analysis
  - CNN (Convolutional Neural Network) for visual recognition
- **APIs**:
  - Chrome Extension API (Manifest V3)
  - VirusTotal API for comparison
  - Custom cloud API for model hosting
- **Storage**:
  - Local storage for caching results
  - IndexedDB for threat intelligence database