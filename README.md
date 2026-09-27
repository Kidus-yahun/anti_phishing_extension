# 🛡️ PhishShield AI - Phishing & Social Engineering Threat Detection Platform

**PhishShield AI** is a multi-layered cybersecurity platform combining an **AI/ML threat detection engine**, an **interactive web dashboard**, and a **real-time browser extension ("PhishShield Browser Guardian")** that actively scans links across all tabs and neutralizes phishing attacks before users can click them.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-green)
![Chrome Extension](https://img.shields.io/badge/Chrome_Extension-Manifest_V3-red)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-ML%20Classifier-orange)
![TailwindCSS](https://img.shields.io/badge/TailwindCSS-Glassmorphic%20UI-06B6D4)

---

## 🌟 Key Features

### 1. 🌐 Real-Time Browser Guardian (Chrome / Edge Extension)
- **Multi-Tab Background Scanning**: Automatically evaluates links across any webpage (like Grammarly) using non-blocking asynchronous batches (`requestAnimationFrame`).
- **Dynamic Content Support**: Uses `MutationObserver` to instantly inspect incoming links in webmail (Gmail, Outlook), social media (X/Twitter, Reddit), and messaging apps.
- **High-Visibility Threat Badges ("Don't Touch It")**: Inserts unmissable, pulsing red warning badges (`⚠️ PHISHING LINK: DO NOT TOUCH`) directly next to flagged links.
- **Active Click Interception**: If a user clicks a malicious link, navigation is immediately blocked, and an unmissable full-screen warning modal appears with threat details and a 1-click **"Stay Safe"** button.
- **Floating Security Pill**: A clean, Grammarly-style corner pill showing the real-time security health of the active tab.

### 2. 🤖 AI/ML Social Engineering NLP Engine
- Machine Learning classifier (`LogisticRegression` + `TF-IDF`) trained on phishing text data.
- Urgency & coercion language analysis (identifying panic-inducing threats, credential harvesting requests, and authority impersonation).

### 3. 🔍 Heuristic URL & Homograph Inspector
- **IDN / Homograph Spoofing Detection**: Identifies Cyrillic/Unicode characters spoofing legitimate domains (e.g. `pаypal.com`).
- **Levenshtein Typosquatting Analyzer**: Flags deceptive typosquatting variants (e.g. `paypa1-security.com`).
- **Anchor Text Mismatch**: Detects when display text claims a trusted domain (`google.com`) but the actual `href` points elsewhere.
- **Structural Analysis**: Flags raw IP hostnames, suspicious TLDs (`.top`, `.xyz`), and URL shorteners.

### 4. ✉️ Email Header Forensic Parser
- Parses RFC822/EML header formats.
- Identifies display name spoofing (e.g., `"PayPal Support" <attacker@random.com>`).
- Checks `From` vs `Return-Path` vs `Reply-To` domain alignment and SPF/DKIM/DMARC flags.

---

## 📁 Directory Structure

```
PhishShield-AI/
├── app/
│   ├── main.py                  # FastAPI application entrypoint & API routes
│   ├── core/
│   │   ├── nlp_engine.py        # ML classifier & urgency NLP heuristic engine
│   │   ├── url_analyzer.py      # Domain, homograph & typosquatting inspector
│   │   ├── header_analyzer.py   # EML header parser & SPF/DKIM mismatch inspector
│   │   └── risk_scorer.py       # Composite threat scoring aggregator
│   ├── models/
│   │   └── phishing_model.pkl   # Trained Scikit-Learn model weights
│   └── templates/
│       └── index.html           # Tailwind CSS glassmorphic web dashboard
├── extension/                   # 🚀 Chrome / Edge Browser Extension (Manifest V3)
│   ├── manifest.json            # Extension Manifest V3 configuration
│   ├── content.js               # Link scanner, badge injector & click interceptor
│   ├── content.css              # High-visibility pulsing badges & warning modal styles
│   ├── heuristics.js            # Client-side zero-latency threat evaluator
│   ├── service-worker.js        # Tab badge counts & background communications
│   ├── test_page.html           # Interactive test lab for testing the extension
│   ├── icons/                   # Real PNG icons (16x16, 48x48, 128x128)
│   └── popup/                   # Extension popup interface & controls
├── samples/
│   ├── phishing_sample.eml      # Sample phishing email header & text
│   └── legitimate_sample.eml    # Sample safe email header & text
├── tests/
│   └── test_detection.py        # Automated test suite
├── train_model.py               # ML training pipeline script
├── requirements.txt             # Python dependencies
└── README.md                    # Documentation
```

---

## 🛠️ How to Install the Browser Extension in Chrome / Edge

1. Open your Chromium-based browser (Google Chrome, Microsoft Edge, Brave, etc.).
2. Navigate to:
   - Chrome: `chrome://extensions`
   - Edge: `edge://extensions`
3. Toggle on **"Developer mode"** in the top-right corner.
4. Click the **"Load unpacked"** button.
5. Select the **`extension`** folder inside this project:
   `C:\Users\Easy Tech\Documents\pro\PhishShield-AI\extension`
6. Pin **PhishShield AI** to your toolbar!

### 🧪 Testing the Extension Immediately
- Double click or open [`extension/test_page.html`](extension/test_page.html) in your browser.
- Watch PhishShield AI automatically flag homograph attacks, typosquatting domains, and deceptive links with pulsing red badges (`⚠️ PHISHING LINK: DO NOT TOUCH`).
- Try clicking any flagged link to see the active full-screen warning modal intercept and block the danger!

---

## 🚀 Running the Python Web Application & API

### 1. Setup Virtual Environment
```bash
cd C:\Users\Easy Tech\Documents\pro\PhishShield-AI

python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate
```

### 2. Install Dependencies & Launch
```bash
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** to use the standalone web dashboard.

---

## 🧪 Running Unit Tests

Run the test suite to verify detection engines:
```bash
python -m pytest tests/test_detection.py
```

---

## 🛡️ License & Educational Disclaimer
This project is developed for educational, defensive cybersecurity, threat intelligence research, and security awareness training purposes.
