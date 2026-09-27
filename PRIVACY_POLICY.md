# Privacy Policy — PhishShield AI

**Last updated:** September 27, 2026

PhishShield AI (the browser extension, web dashboard, and companion API) is built for defensive cybersecurity and security-awareness purposes. This policy describes, precisely, what data is handled and what is not.

## Summary

- **No accounts. No analytics. No third-party trackers. No ads.**
- **No personal data is collected, sold, or shared.**
- All scan results and counters are stored **locally on your device**.
- The only network requests go to the PhishShield backend **you yourself configure** (default: `http://127.0.0.1:8000`, your own machine).

## What the extension stores locally

All state is kept in `chrome.storage.local` on your device:

| Key | Purpose |
| --- | --- |
| `protectionEnabled` | Your on/off toggle for real-time scanning |
| `tab_<id>` | Per-tab count of flagged links (display only) |
| `totalBlockedAllTime` | Your all-time blocked-links counter |
| `apiEndpoint` | The backend URL **you** configured (default: local server) |

Nothing in this list ever leaves your device unless a feature explicitly requires your own backend.

## Network requests

The extension only ever calls endpoints on the address you configured:

- `GET /api/health` — checks whether your backend is reachable
- `POST /api/verify-link` — asks your backend to analyze a link
- `POST /api/analyze` — submits a URL for deep analysis in the dashboard

By default this is `http://127.0.0.1:8000` (localhost) — i.e., **no data leaves your computer**. If you deliberately point the endpoint at a remote server, only the analyzed URL/link text is sent to *that* server.

## What we do NOT do

- No tracking of your browsing history
- No cookies, fingerprints, or device identifiers
- No advertising or affiliate monetization
- No sale or sharing of any data with third parties
- No account system, so no names, emails, or payment data is ever held by PhishShield

## Permissions explanation

| Permission | Why it is needed |
| --- | --- |
| `storage` | Save your settings and counters locally |
| `activeTab`, `tabs` | Scan links in open tabs to flag phishing |
| `<all_urls>` (host) | Inspect links on any page you visit |
| Content script (`content.js`) | Insert warning badges and block malicious clicks |

## The web dashboard & API

The FastAPI dashboard is designed to run **on your own machine**. Any analyzed sample (URLs, EML email headers you paste in) stays in memory on the server you run and is not transmitted anywhere else.

## Children's privacy

PhishShield does not collect personal information from anyone, including children.

## Changes to this policy

Material changes will be announced by updating the `Last updated` date and the project's GitHub repository: <https://github.com/Kidus-yahun/anti_phishing_extension>.

## Contact

Questions about privacy or data handling: **yahunsewkidus@gmail.com** (same contact as our [Security Policy](SECURITY.md)).
