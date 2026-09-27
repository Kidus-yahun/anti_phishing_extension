# 🛡️ PhishShield AI - Phishing & Social Engineering Threat Detection Platform

**PhishShield AI** is an AI/ML-powered threat detection engine and interactive web dashboard designed to detect social engineering attacks, phishing emails, IDN homograph domain spoofing, and email authentication failures.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-green)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-ML%20Classifier-orange)
![TailwindCSS](https://img.shields.io/badge/TailwindCSS-Glassmorphic%20UI-06B6D4)

---

## 🌟 Key Features

1. **AI/ML Social Engineering NLP Engine**:
   - Machine Learning classifier (`LogisticRegression` + `TF-IDF`) trained on phishing text data.
   - Urgency & coercion language analysis (identifying panic-inducing threats, credential harvesting requests, and authority impersonation).

2. **Heuristic URL & Homograph Inspector**:
   - **IDN / Homograph Spoofing Detection**: Identifies Cyrillic/Unicode characters spoofing legitimate domains (e.g. `pаypal.com`).
   - **Levenshtein Typosquatting Analyzer**: Flags deceptive typosquatting variants (e.g. `paypa1-security.com`).
   - **Structural Analysis**: Flags raw IP hostnames, suspicious TLDs (`.top`, `.xyz`), URL shorteners, and path manipulation.

3. **Email Header Forensic Parser**:
   - Parses RFC822/EML header formats.
   - Identifies display name spoofing (e.g., `"PayPal Support" <attacker@random.com>`).
   - Checks `From` vs `Return-Path` vs `Reply-To` domain alignment and SPF/DKIM/DMARC flags.

4. **Glassmorphic Web Dashboard**:
   - Built with Tailwind CSS and dark cyber-security design elements.
   - Interactive risk ring (0-100%) with dynamic risk level badges (`SAFE`, `LOW RISK`, `MEDIUM RISK`, `CRITICAL`).
   - 1-Click test presets for rapid evaluation.

---

## 📁 Directory Structure

```
idea/
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

## 🚀 Quick Start & Installation

### 1. Clone & Setup Virtual Environment
```bash
git clone https://github.com/Kidus-yahun/Smart-Bus-Booking.git
cd Smart-Bus-Booking/idea

python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Train Machine Learning Model (Optional)
```bash
python train_model.py
```

### 4. Launch the Web Application
```bash
python -m uvicorn app.main:app --reload --port 8000
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser!

---

## 🧪 Running Unit Tests

Run the test suite to verify detection engines:
```bash
python -m pytest tests/test_detection.py
```

---

## 🛡️ License & Educational Disclaimer
This project is developed for educational, defensive cybersecurity, threat intelligence research, and security awareness training purposes.
