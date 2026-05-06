# 🪪 Advanced OpenID Connect

An interactive Reveal.js presentation: the deep end of **OpenID Connect** — validation edge cases, FAPI 2.0, OpenID Federation 1.0, the EUDI Wallet stack (SIOPv2 + OpenID4VCI + OpenID4VP + ISO mDL), workload OIDC, and the operational patterns for production OPs.

## ▶ [Open the Presentation](https://brendanjameslynskey.github.io/Advanced_OpenID_Connect/)

## 📄 [Markdown Version](presentation.md)

## 📚 [Companion deck — Introduction to OpenID Connect](https://brendanjameslynskey.github.io/Introduction_to_OpenID_Connect/)

---

## Contents

| # | Chapter / Topic | Description |
|---|-----------------|-------------|
| 01 | Title | Hardening · Federation · Wallet-Era · Operational |
| 02 | Topics | The four chapters mapped out |
| 03 | **A1 — Validation Edge Cases** | Clock skew, kid-less tokens, alg confusion, nonce binding, multi-tenant `iss` drift |
| 04 | **A2 — `aud` Wars** | Multi-audience tokens, `azp`, the sibling-app identity-hijacking bug |
| 05 | **A3 — Pairwise Subjects** | Public vs pairwise `sub`, `sector_identifier_uri`, the Sign-in-with-Apple model |
| 06 | **A4 — PAR (RFC 9126)** | Pushed Authorization Requests; integrity + privacy + URL-length wins |
| 07 | **A5 — JAR & JARM** | Signed request objects (RFC 9101) and signed response mode |
| 08 | **A6 — FAPI 2.0** | Security Profile + Message Signing; where it's actually deployed |
| 09 | **A7 — mTLS · `private_key_jwt` · DPoP** | Three sender-constraint mechanisms compared |
| 10 | **A8 — Logout, Properly** | RP-initiated · back-channel · front-channel — when each works |
| 11 | **A9 — Token Exchange** | RFC 8693 / Microsoft OBO; preserving user identity through service chains |
| 12 | **B1 — OpenID Federation 1.0** | Trust chains, entity statements, intermediates, trust marks (Sep 2024) |
| 13 | **B2 — eIDAS 2.0 + EUDI Wallet** | The EU's planned wallet rollout in OIDC terms; LoA Low/Substantial/High |
| 14 | **C1 — SIOPv2 + VCI + VP** | The wallet-era spec triple, with a worked driving-licence presentation |
| 15 | **C2 — ISO mDL** | 18013-5 NFC/BLE proximity + 18013-7 OpenID4VP online; SD-JWT VC vs mDoc |
| 16 | **D1 — Workload OIDC** | GitHub Actions → AWS / GCP, Kubernetes ServiceAccountTokenVolume, trust-policy hygiene |
| 17 | **D2 — Aggregated & Distributed Claims** | The `claims` parameter, `_claim_sources`, validating embedded JWTs |
| 18 | **D3 — Demanding MFA** | `prompt` · `max_age` · `acr_values` · `amr` — and the bug of trusting requested rather than achieved `acr` |
| 19 | **D4 — Observability** | RP-side metrics, OP-side attack indicators, SIEM events worth wiring |
| 20 | **D5 — Migration Playbooks** | SAML→OIDC, monolith→OP, OAuth-only→OIDC |
| 21 | **D6 — Reference Architectures** | UK/Brazil Open Banking, eIDAS, FHIR, EduGAIN, NIST 800-63, B2B SaaS, workload |
| 22 | Summary | Three take-aways and full reference list |

---

## Audience

This deck assumes you already know the OIDC basics — ID tokens, the `openid` scope, discovery, the eight-step ID-token validation, response types, refresh tokens. If any of those are new, start with the [Introduction to OpenID Connect](https://brendanjameslynskey.github.io/Introduction_to_OpenID_Connect/) and the [OAuth series](https://brendanjameslynskey.github.io/OAuth_Primer/) first.

The advanced deck is aimed at:

- engineers building or operating production OPs / RPs;
- architects planning a FAPI 2.0 / EUDI / regulated rollout;
- security teams reviewing an OIDC integration;
- anyone wiring workload identity (CI/CD, Kubernetes, SPIFFE) into a cloud account.

## Slide Controls

| Action | Key |
|--------|-----|
| Next / Previous | `→` `←` or swipe |
| Overview | `Esc` |
| Fullscreen | `F` |
| Export to PDF | Append `?print-pdf` to URL, then print |

## Technology

[Reveal.js 4.6](https://revealjs.com) · [highlight.js](https://highlightjs.org) · Playfair Display + DM Sans + JetBrains Mono · inline SVG diagrams.

Single self-contained `index.html` — no build step, no npm, no dependencies to install.

## See also

- [Introduction to OpenID Connect](https://github.com/BrendanJamesLynskey/Introduction_to_OpenID_Connect) — the foundations this deck builds on.
- [OAuth — A Gentle Primer](https://github.com/BrendanJamesLynskey/OAuth_Primer) — start here if delegated auth is brand-new.
- [Introduction to OAuth](https://github.com/BrendanJamesLynskey/Introduction_to_OAuth) — the OAuth protocol primer.
- [OAuth for MCP Servers](https://github.com/BrendanJamesLynskey/OAuth_for_MCP) — applying OAuth/OIDC to the Model Context Protocol and the provider landscape.
- [Cloud_aaS_05_Cloud_Security](https://github.com/BrendanJamesLynskey/Cloud_aaS_05_Cloud_Security) — the wider zero-trust / workload identity context.

## References

OpenID Connect Core 1.0 · OIDC Discovery · OIDC Dynamic Client Registration · OIDC RP-Initiated / Back-Channel / Front-Channel Logout · CIBA Core 1.0 · SIOPv2 · OpenID for Verifiable Credential Issuance (OpenID4VCI) · OpenID for Verifiable Presentations (OpenID4VP) · OpenID Federation 1.0 (Sep 2024) · FAPI 2.0 Security Profile · FAPI 2.0 Message Signing · ISO/IEC 18013-5 / 18013-7 (mDL) · eIDAS 2.0 Regulation (EU) 2024/1183 · SD-JWT · SD-JWT VC · RFC 7515/7517/7519 (JWS/JWK/JWT) · RFC 7523 (JWT client auth) · RFC 8414 / 8628 / 8693 / 8705 / 8707 · RFC 9068 (JWT AT) · RFC 9101 (JAR) · RFC 9126 (PAR) · RFC 9207 (`iss` param) · RFC 9396 (RAR) · RFC 9449 (DPoP) · RFC 9700 (BCP 240) · RFC 9728 (Protected Resource Metadata) · openid.net/certification

## License

Educational use. Code examples provided as-is.
