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

- Extension: open `extension/test_page.html` in your browser
- Unit tests: `python -m pytest tests/ -v`

## Guidelines

- **All contributions must be licensed AGPL-3.0** (same as the project). By submitting you agree your work is released under this license.
- Follow the existing style: conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `ci:`).
- Add or update tests in `tests/` for any detection-logic change.
- Never hardcode blocklists of domains — detection must be heuristic/ML-based.
- False positives are bugs: if a legitimate site was flagged, open an issue with the URL and screenshots.
- Do **not** commit secrets, API keys, model tokens, or `venv/`.

## Reporting vulnerabilities

Please see [SECURITY.md](SECURITY.md) — do **not** open a public issue for exploitable vulnerabilities.

## Project layout

```
app/core/        # Python engines: NLP, URL, headers, risk scoring
extension/       # Chrome/Edge Manifest V3 extension
tests/           # Pytest suite (runs in CI on every push)
docs/            # One-pagers, grant applications, design notes
```

## Review process

1. Fork and open a PR against `main`
2. CI must pass (pytest + manifest validation)
3. A maintainer reviews within ~48 hours

Questions? Contact **yahunsewkidus@gmail.com** or open a GitHub Discussion/Issue.
