# Contributing to PhishShield AI

Thanks for helping make the web safer. This project accepts contributions of all sizes — from false-positive reports to new detection heuristics.

## Getting started

```bash
git clone https://github.com/Kidus-yahun/anti_phishing_extension.git
cd anti_phishing_extension

python -m venv venv
# Windows
.\venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt
```

### Run the dashboard

```bash
python -m uvicorn app.main:app --reload --port 8000
```

Open http://127.0.0.1:8000

### Load the extension

1. Go to `chrome://extensions`
2. Enable **Developer mode**
3. **Load unpacked** → select the `extension/` folder

### Test it

- **Test Lab (recommended)**: Open `extension/test_lab.html` in your browser (or visit `/test-lab` if running the server). The test lab has 6 categories of simulated attacks including realistic phishing email bodies, a dynamic injection simulator with speed timing, and safe baseline controls.
- **Quick test page**: Open `extension/test_page.html` for a minimal test.
- **Unit tests**: `python -m pytest tests/ -v`

## How to contribute

### 🐛 Report false positives or missed detections

False positives (legitimate sites flagged) and false negatives (phishing sites not caught) are both bugs. Open an issue with:

- The URL or text that was incorrectly classified
- Expected vs actual result
- Screenshots of the badge/modal (if applicable)

### 📧 Add new test scenarios to the Test Lab

The test lab (`extension/test_lab.html`) is our primary QA tool. You can contribute new test scenarios:

1. **Static phishing messages** — Add new simulated email/message bodies in Category 6 with realistic social engineering text and embedded phishing links. Each message should:
   - Use a specific tactic (urgency, impersonation, reward scam, etc.)
   - Contain at least one phishing link (typosquat, IP host, anchor mismatch, etc.)
   - Include a `link-target` span listing the tactics used

2. **Dynamic injection scenarios** — Add new entries to the rotating arrays in `extension/test_lab.js` (chat, email, SMS, or social scenarios). Each scenario needs:
   - A label, message body, phishing URL, and display text
   - Use a different attack vector or brand impersonation each time

3. **Safe baseline links** — Add legitimate URLs to Category 5 that should **never** be flagged. This helps catch regressions.

### 🔍 Improve detection heuristics

Detection logic lives in:

- `extension/heuristics.js` — Client-side structural analysis (homoglyph, typosquat, anchor mismatch, IP host, '@' tricks)
- `app/core/nlp_engine.py` — NLP text analysis (urgency detection, social engineering patterns)
- `app/core/url_analyzer.py` — Server-side URL analysis
- `app/core/header_analyzer.py` — Email header forensics (SPF, DKIM, display name spoofing)

When adding or modifying heuristics:

1. Add matching tests in `tests/test_detection.py`
2. Verify no false positives on Category 5 safe links
3. Keep detection heuristic/ML-based — never hardcode blocklists of domains

### 🌐 Improve the dashboard or extension UI

- Extension popup: `extension/popup.html` + `extension/popup.js`
- Content script styles: `extension/content.css`
- Dashboard: `app/templates/index.html`
- Test lab: `extension/test_lab.html` + `extension/test_lab.js`

All UI changes should follow the existing dark-theme cybersecurity aesthetic.

## Guidelines

- **All contributions must be licensed AGPL-3.0** (same as the project). By submitting you agree your work is released under this license.
- Follow the existing style: conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `ci:`).
- Add or update tests in `tests/` for any detection-logic change.
- Never hardcode blocklists of domains — detection must be heuristic/ML-based.
- False positives are bugs: if a legitimate site was flagged, open an issue with the URL and screenshots.
- Do **not** commit secrets, API keys, model tokens, or `venv/`.
- Keep the test lab's `test_lab.js` free of inline scripts (Manifest V3 CSP compliance).

## Reporting vulnerabilities

Please see [SECURITY.md](SECURITY.md) — do **not** open a public issue for exploitable vulnerabilities.

## Project layout

```
app/core/        # Python engines: NLP, URL, headers, risk scoring
app/models/      # ML model files (phishing_model.pkl)
app/templates/   # Server-rendered HTML (dashboard, test lab)
extension/       # Chrome/Edge Manifest V3 extension
tests/           # Pytest suite (runs in CI on every push)
docs/            # One-pagers, grant applications, design notes
```

### Key files for contributors

| File | Purpose |
|---|---|
| `extension/heuristics.js` | Client-side phishing link detection engine |
| `extension/content.js` | DOM scanner, badge injection, click interception |
| `extension/test_lab.html` | Interactive phishing simulation test page |
| `extension/test_lab.js` | Dynamic injection controller with speed timer |
| `app/core/nlp_engine.py` | NLP + ML text analysis (Laya model integration) |
| `tests/test_detection.py` | Pytest suite — CI must stay green |

## Review process

1. Fork and open a PR against `main`
2. CI must pass (pytest + manifest validation)
3. A maintainer reviews within ~48 hours

Questions? Contact **yahunsewkidus@gmail.com** or open a GitHub Discussion/Issue.
