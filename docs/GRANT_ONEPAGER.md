# PhishShield AI — Funding One-Pager

> **Ask:** $1,000–$10,000 (part-time development, 6–12 months) · **License:** AGPL-3.0 · **Repo:** https://github.com/Kidus-yahun/anti_phishing_extension

## 1. The problem

Phishing is the dominant entry point for cybercrime, and it is now **multilingual and regionally targeted**. Africa's fast-growing mobile-money and banking users face phishing lures in **Amharic, Oromo, and other under-served languages** — precisely the languages that mainstream detectors (trained on English threat corpora) handle worst. A user in Addis Ababa receiving a fluently-written Amharic bank lure today has essentially **no free, privacy-respecting tool** that understands it.

## 2. The solution: PhishShield AI

A free, open-source, multi-layered protection stack:

| Layer | What it does |
| --- | --- |
| **Browser guardian (MV3)** | Scans links across all tabs in real time, injects unmissable warning badges, and **intercepts clicks** on confirmed threats |
| **Zero-latency heuristics (client)** | Homograph/IDN spoofing, typosquatting (Levenshtein), anchor-text mismatch, suspicious TLDs — all computed **locally, offline** |
| **Multilingual NLP engine** | Laya System-1 (ModernBERT) sub-500 ms semantic detection of urgency/coercion/impersonation, with an offline TF-IDF fallback classifier |
| **Email header forensics** | Display-name spoofing, From/Return-Path/Reply-To misalignment, SPF/DKIM/DMARC checks |
| **FastAPI dashboard** | Local-only web dashboard + `/api/analyze` endpoint for deeper scans |

**Privacy by design:** no accounts, no analytics, no third-party trackers. All state lives in `chrome.storage.local`; the only network calls go to a backend the user runs themselves. ([PRIVACY_POLICY.md](../PRIVACY_POLICY.md))

## 3. What makes this fundable (differentiation)

1. **Multilingual social-engineering detection.** The Laya engine is multilingual by design — a path to **Amharic/Oromo phishing detection that mainstream tools don't offer**, and a template for other under-served languages.
2. **Offline-first, privacy-preserving.** Works without sending browsing data to the cloud — relevant to the EU's "trust-enhancing technologies" agenda and to users on expensive/intermittent connectivity.
3. **Complete and tested today.** CI (GitHub Actions) runs a pytest threat-engine suite on every push; Manifest-V3 validation is part of the pipeline; security disclosure policy (SECURITY.md) already published.
4. **Defensive, educational, dual-use-safe.** Purely protective: flags and blocks — never automates attacks.

## 4. Current state (Sept 2026)

- ✅ Working extension v1.0.0 (Chrome/Edge, Manifest V3) + web dashboard + Python API
- ✅ Four detection engines implemented & unit-tested (`tests/test_detection.py`)
- ✅ CI pipeline green; SECURITY.md; CONTRIBUTING.md; AGPL-3.0 licensed
- 🔄 Chrome Web Store publication in progress
- 📈 Metrics: [update before submitting — stars, installs, users]

## 5. Roadmap (funded period)

| Milestone | Outcome | Timing |
| --- | --- | --- |
| M1 | Chrome Web Store + Edge Add-ons publication, first 500 users | Month 1–2 |
| M2 | **Amharic/Oromo threat-phrase corpus** + multilingual eval set (published as open data) | Month 2–4 |
| M3 | Server-side API hardening, rate limits, SBOM, dependency audit | Month 3–5 |
| M4 | Independent security review of the extension (click-interception & CSP surface) | Month 5–6 |
| M5 | Freemium launch (free core preserved forever; paid Pro/API funds sustainability) | Month 6–12 |

## 6. Budget ($1,000–$10,000)

| Item | Cost (USD) |
| --- | --- |
| Part-time development, 6 months @ ~10 h/week | 6,000 |
| Amharic/Oromo corpus labeling (student assistants) | 1,200 |
| Cloud backend + model inference costs | 700 |
| Security review / external code audit (lightweight) | 1,500 |
| Chrome Web Store + infrastructure fees | 100 |
| Contingency | 500 |
| **Total** | **10,000** |

*A scaled-down $1,000 tier covers: store fees + model hosting + corpus labeling only (volunteer development).*

## 7. Sustainability (why this isn't a dead end)

1. **Grants** (NLnet NGI call, Alpha-Omega seasonal grants) fund development of the free core.
2. **Freemium:** free real-time protection forever; paid **Pro** (email-header forensics, scan history, custom policies) and **Business API** (rate-limited `/api/analyze` for schools, SMEs, ISPs).
3. **Donations:** GitHub Sponsors / Open Collective.

No user of the free tier will ever be paywalled for core protection.

## 8. Team & contact

Maintainer: **Kidus Yahun** — solo developer, university student, Ethiopia.
Contact: **yahunsewkidus@gmail.com** · https://github.com/Kidus-yahun
