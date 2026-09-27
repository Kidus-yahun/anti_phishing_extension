# NLnet / NGI Zero Proposal Draft — PhishShield AI

**Target call:** NGI open call (Restack / CodeSupply) — **deadline: November 3, 2026 (noon CEST)**
**Portal:** https://nlnet.nl/propose/ · Guide: https://nlnet.nl/commonsfund/guideforapplicants/
**Prep:** attend the *Ask Us Anything* office hour — https://nlnet.nl/office-hour/ (next: Sep 30, 2026) · Webinar Oct 29
**Amount:** first proposal may request up to **€50,000**; recommended ask: **€12,000–€18,000** (6–9 months part-time, cost-recovery basis)

> ⚠️ **Hard eligibility checklist**
> - [x] Software published under a recognized FOSS license in its entirety → **AGPL-3.0** (added Sep 2026)
> - [x] R&D as primary objective (not a commercial product push)
> - [x] Applicant type: individual is explicitly allowed ("anyone can apply")
> - [ ] **European dimension (knock-out criterion)** — see §4; MUST be addressed
> - [ ] Everything below marked `[FILL]` finalized by you

---

## 1. Short proposal title

**PhishShield AI: privacy-preserving, multilingual phishing detection for an open internet**

## 2. Short description (≈150–250 chars — `[FILL: confirm]`)

> A free, open-source browser guardian that detects phishing links in real time — offline, with no tracking — and extends social-engineering detection to under-served languages such as Amharic and Oromo.

## 3. Long description

### Current state
PhishShield AI already exists and works: a Manifest V3 extension, a local FastAPI dashboard, and four detection engines (heuristic URL/homograph inspection, NLP urgency/coercion analysis, email-header forensics, composite risk scoring), covered by a pytest suite and GitHub Actions CI. See [docs/GRANT_ONEPAGER.md](../GRANT_ONEPAGER.md).

### What the grant would fund (deliverables)

| # | Deliverable | Why it matters to NGI |
|---|---|---|
| D1 | Chrome Web Store & Edge publication + telemetry-free usage metrics | Real-world adoption of a privacy-preserving security tool |
| D2 | **Open multilingual phishing-phrase corpus** (Amharic, Oromo, English) published as open data under an open license | Trustworthy, fair security for non-English users; reusable by the whole ecosystem |
| D3 | Multilingual evaluation benchmark comparing Laya-based detection vs. baselines, published openly | Reproducible research, documented false-positive rates |
| D4 | Independent security review of the extension's click-interception & CSP surface + SBOM + dependency audit | Hardens a tool that guards millions of potential users |
| D5 | Documentation, contributor guide, packaging (Edge Add-ons, unpacked builds) | Deployability & community growth |

### Relevance to the topics

- **Restack / trust-enhancing technologies:** client-side security that keeps trust decisions on the user's device; end-user application counterpart of a more trustworthy internet stack.
- **CodeSupply (if applied under this pilot):** deliverable D2 is exactly *democratic access to data sets* — a cybersecurity threat corpus published as open data. `[FILL: verify current CodeSupply scope page before choosing which call to use]`

## 4. European dimension (knock-out — pick & strengthen one) `[FILL]`

1. **Collaboration route (strongest):** name 1–2 EU-based collaborators (security researcher, FOSS group, university lab, or an EU user organisation co-testing the extension). Even a letter of support or a co-signing maintainer works.
2. **NGI-vision route:** argue that protecting end users from phishing anywhere directly serves the EU's open-internet agenda — and commit to EU-facing dissemination (FOSDEM/RIPE lightning talk, EU security mailing lists, translations into EU-minority languages as a stretch goal).
3. **Bridge route:** partner with an EU-based FOSS fiscal host (e.g., an Open Collective collective in Europe) through which parts of the work are coordinated.

> Recommended: **route 1 + route 2 combined.** Ask the office hour (Sep 30) whether route 2 alone has ever succeeded — they are famously honest in office hours.

## 5. Amount & budget estimate (cost-recovery, €)

| Item | € |
|---|---|
| Part-time development & maintenance, 8 months @ ~10 h/wk | 9,600 |
| Multilingual corpus creation (2 student assistants, labeling) | 2,400 |
| Infrastructure (CI, model inference, hosting) | 900 |
| Security review contribution | 1,800 |
| Dissemination (FOSDEM attendance/remote, materials) | 600 |
| **Total ask** | **15,300** |

*Adjust to your real costs — NLnet funds cost recovery, not profit; keep it honest.*

## 6. Planning (months)

- **M1:** store publication, metrics, contributor onboarding
- **M2–M4:** corpus build (D2) + benchmark (D3) — intermediate results published openly
- **M5–M6:** security review (D4), fixes, SBOM
- **M7–M8:** packaging, docs, final report + next-step sustainability (freemium API keeps the free core alive)

## 7. Added value / open internet argument

- Keeps **security decisions local** (no telemetry), aligned with data minimisation.
- Produces **reusable open data & benchmarks** rather than a walled garden.
- Targets **languages & users the market ignores** — open internet means open to all languages.
- AGPL-3.0 guarantees derivatives stay free.

## 8. Open questions before submitting `[FILL]`

- [ ] Does CodeSupply or Restack fit better? (read both theme pages the week of Oct 5)
- [ ] Office hour Sep 30: ask about European-dimension expectations for individual applicants outside Europe
- [ ] Confirm payout mechanics for an individual in Ethiopia (bank transfer details appear only after a proposal is accepted)
- [ ] Register + test the proposal portal early — **don't wait until Nov 3**

---

### Quick facts to reuse

- Repo: https://github.com/Kidus-yahun/anti_phishing_extension
- License: AGPL-3.0 · CI: GitHub Actions · Tests: pytest
- Contact: yahunsewkidus@gmail.com
- One-pager: [docs/GRANT_ONEPAGER.md](../GRANT_ONEPAGER.md)
