# Chrome Web Store Listing — PhishShield AI

> Last Updated: 2026-10-16

## Store Listing

**Extension Name** [REQUIRED]
PhishShield AI - Real-Time Phishing Protection

**Short Description** [REQUIRED]
Real-time guardian detecting phishing links, Ethiopian bank lookalikes, homograph attacks, and credential scams across all tabs.

**Detailed Description** [REQUIRED]
PhishShield AI is an intelligent real-time browser guardian that shields you against deceptive websites, lookalike phishing domains, and credential harvesting scams.

KEY FEATURES
- Real-Time Tab Risk Badging: See tab safety status at a glance with toolbar badges (Safe, Suspicious, Dangerous).
- Injected Warning Overlay: Blocks dangerous websites using an isolated Shadow DOM warning with "Go back", "Proceed anyway", and "Trust this site" options.
- "Why was this flagged?" Explanations: Clear, transparent security findings displayed in both the warning overlay and popup.
- Link-Hover Destination Inspection: Hover over any link to inspect its real unmasked destination, safety rating, and resolved shortlinks.
- Ethiopian Phishing Protection: Catches lookalike domains of Telebirr, CBE, Awash Bank, Dashen Bank, Ethio Telecom, and Safaricom Ethiopia using Levenshtein distance, Punycode decoding, and mixed-script homograph detection.
- Amharic Credential Scam Detection: Automatically flags urgent credential harvesting phrases near login and payment forms.
- Full Bilingual Support (Amharic & English): Bundled with Noto Sans Ethiopic and an instant language toggle.
- Local Storage & Scan History: View stats on sites checked, threats blocked, and review your recent scan history locally.

HOW TO USE IT
1. Click "Add to Chrome" to install the extension.
2. Browse the web normally. PhishShield AI quietly monitors links and pages in the background.
3. Check the toolbar badge for instant tab risk status.
4. Hover over links to verify destinations before clicking.
5. If an impersonation or credential scam is encountered, PhishShield AI warns you before your credentials can be stolen.

PRIVACY & PERMISSIONS
All structural evaluations, lookalike detection, and scan history remain 100% local on your device in browser storage. Your personal browsing history is never tracked or sold.

SUPPORT & CONTACT
Developer: Kidus Yahun (yahunsewkidus@gmail.com)
Project: AGPL-3.0 Open Source

**Category** [REQUIRED]
Productivity

**Single Purpose** [REQUIRED]
Protects users in real-time from phishing links, brand lookalikes, and credential scams through inline inspection and warnings.

**Primary Language** [REQUIRED]
English

---

## Graphics & Assets

| Asset | Dimensions | Status | Filename |
|---|---|---|---|
| Store Icon [REQUIRED] | 128×128 PNG | ✅ Ready | `extension/icons/icon-128.png` |
| Small Icon | 16×16 PNG | ✅ Ready | `extension/icons/icon-16.png` |
| Medium Icon | 48×48 PNG | ✅ Ready | `extension/icons/icon-48.png` |
| Screenshot 1 [REQUIRED] | 1280×800 | 🟡 Needs capture | Real-time warning overlay with Ethiopian bank detection |
| Screenshot 2 [RECOMMENDED] | 1280×800 | 🟡 Needs capture | Extension popup in Amharic & English |
| Screenshot 3 [RECOMMENDED] | 1280×800 | 🟡 Needs capture | Link-hover inspection tooltip |

---

## Permissions Justification

| Permission | Type | Justification |
|---|---|---|
| `storage` | permissions | Stores protection settings, trusted domains, localized language preference, scan history, and threat counters locally on the user's machine. |
| `activeTab` | permissions | Inspects links and DOM structures on the currently active tab when the extension popup is opened. |
| `tabs` | permissions | Updates toolbar risk status badges per tab and queries active URL to detect lookalike domains. |
| `<all_urls>` | host_permissions | Allows real-time link inspection, Shadow DOM warning overlays, and shortlink expansion on visited websites. |

---

## Privacy & Data Use

### Data Collection
PhishShield AI does NOT collect, sell, or transmit personal data, keystrokes, or private user browsing history to third parties.
- Structural link analysis and lookalike checks execute locally in the browser.
- Scan history and trusted domain lists are stored exclusively in `chrome.storage.local`.

---

## Version History

- **v1.1.0 (2026-10-16)**:
  - Added per-tab toolbar risk status badge (Safe, Suspicious, Dangerous).
  - Added injected warning overlay (Shadow DOM) for risky pages with "Go back", "Proceed anyway", and "Trust this site" buttons.
  - Added "Why was this flagged?" explanation lists in popup and overlay.
  - Added link-hover tooltips showing real destination domain, safety status, and shortlink expansion.
  - Added scan history and stats (`sitesChecked`, `threatsBlocked`) in `chrome.storage`.
  - Added full Amharic and English support (`_locales/am`, `_locales/en`, and instant language toggle) with bundled Noto Sans Ethiopic.
  - Added Ethiopian phishing detection: Levenshtein distance lookalikes for Telebirr, CBE, Awash, Dashen, Ethio Telecom, Safaricom; Amharic scam phrases in login/payment forms; Ethiopic-Latin mixed-script homographs; Punycode decoding; shortlink expansion.
  - Added auto-detection of Amharic pages (lang attribute & Unicode U+1200-U+137F).

- **v1.0.0 (2026-09-27)**:
  - Initial Manifest V3 release with client-side heuristics and Laya System-1 Model support.
