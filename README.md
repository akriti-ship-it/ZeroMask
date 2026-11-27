<div align="center">

# 🛡️ ZEROMASK

### Client-Side PII Detection & Sanitization

**Zero network calls. Zero analytics. Zero data egress. 100% in your browser.**

[Live Demo](#quick-start) · [Detection Rules](#detection-engine) · [Redaction Modes](#redaction-modes)

---

</div>

## ⚡ Quick Start

```
Double-click index.html — that's it.
```

No build step. No `npm install`. No server required. Opens from your filesystem.

---

## 🔍 Detection Engine

Six PII detectors with algorithmic validation — not just regex.

| Type | Validation | Example |
|---|---|---|
| **Credit Card** | Luhn (mod-10) + Visa/MC/Amex/Discover/RuPay prefix | `4532 7562 7962 4585` |
| **Aadhaar** | Verhoeff D5 checksum, 12 digits starting 2–9 | `2345 6789 0124` |
| **PAN** | Format + 4th-char entity code (P,C,H,F,A,T,B,L,J,G) | `ABCPK1234F` |
| **Email** | RFC-style pattern with domain TLD check | `jane.doe@company.io` |
| **IP Address** | IPv4 (0–255 octets) + IPv6, filters version strings | `192.168.14.82` |
| **Phone** | Indian (+91/0, starts 6–9) & E.164 international | `+91-98201-44512` |

**Overlap priority:** `CREDIT_CARD > AADHAAR > PAN > EMAIL > IP > PHONE` — no double-redaction.

**Validation filtering:** Numbers that _look_ like cards but fail Luhn? Ignored. 12-digit strings failing Verhoeff? Ignored. `v1.2.3.4`? Not an IP. The rejection count is shown in the UI.

---

## 🎭 Redaction Modes

Switch live between three modes via the segmented control:

**Full Mask** — `[REDACTED:EMAIL]` or `[REDACTED]`

**Partial Mask** — keeps limited context:
| Type | Output |
|---|---|
| Card | `XXXX-XXXX-XXXX-1234` |
| Aadhaar | `XXXX-XXXX-1234` |
| PAN | `ABXXXXXXXF` |
| Phone | `+91-XXXXX-X1234` |
| Email | `j***@domain.com` |
| IP | `192.168.X.X` |

**Pseudonymize** — consistent normalized tokens (`EMAIL_01`, `CARD_01`). Same value always maps to the same ID. Mapping table stays in memory only.

---

## 🏗️ Architecture

```
index.html      →  Semantic UI shell (no frameworks)
styles.css      →  Dark/light theme via CSS custom properties
detectors.js    →  PII scanners + Luhn/Verhoeff validators + overlap resolver
redactor.js     →  Single-pass linear-time redaction engine
samples.js      →  Realistic noisy sample with valid PII + decoys
app.js          →  Live processing, XSS-safe DOM rendering, FileReader, Blob exports
tests.js        →  16 unit tests (Node + browser)
```

---

## 🔒 Privacy

- **Zero outbound requests** — no fonts, CDNs, analytics, or API calls
- **FileReader only** — uploaded files never leave the browser tab
- **XSS-safe** — highlights built with `createTextNode()`, never `innerHTML`
- **Audit exports exclude PII** — only counts, modes, and timestamps
- **Pseudonym mapping** — RAM-only, explicit warning before download

---

## 🧪 Tests

```bash
# Terminal
node tests.js

# Browser
open tests.html
```

16 tests covering Luhn, Verhoeff, all 6 detectors (positive + negative), overlap resolution, all redaction modes, and pseudonym consistency.

---

## 🛠️ Tech

Plain HTML + CSS + vanilla JavaScript. No React, no Tailwind, no Webpack, no npm. System fonts. Inline SVGs. Opens via `file://` protocol.

---

<div align="center">

**Built for hackathons, enterprise demos, and anyone who needs PII scrubbed without trusting a server.**

</div>
