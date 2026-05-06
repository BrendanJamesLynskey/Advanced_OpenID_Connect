# Advanced OpenID Connect

**Hardening · Federation · Wallet-Era · Operational**

*The deep end of OpenID Connect: the validation edge cases, the high-security profiles, the federation specs that are actually being deployed in 2026, the wallet-era stack (EUDI / mDL), and the operational patterns for production OPs.*

```
PAR -> JAR / JARM -> DPoP / mTLS -> Trust Chain -> Wallet
```

Harden  |  Federate  |  Issue & Present  |  Operate

---

## Table of Contents

1. [Topics — Four Chapters](#slide-01--topics--four-chapters)
2. [A1 · ID-Token Validation Edge Cases](#slide-02--a1--id-token-validation-edge-cases)
3. [A2 · The `aud` Wars — Multi-Audience & `azp`](#slide-03--a2--the-aud-wars--multi-audience--azp)
4. [A3 · Pairwise & Public Subject Identifiers](#slide-04--a3--pairwise--public-subject-identifiers)
5. [A4 · Pushed Authorization Requests (PAR)](#slide-05--a4--pushed-authorization-requests-par--rfc-9126)
6. [A5 · JAR & JARM — Signed Requests & Responses](#slide-06--a5--jar--jarm--signed-requests--responses)
7. [A6 · FAPI 2.0 — Financial-Grade OIDC](#slide-07--a6--fapi-20--financial-grade-oidc)
8. [A7 · mTLS · `private_key_jwt` · DPoP](#slide-08--a7--mtls--private_key_jwt--dpop)
9. [A8 · Logout, Properly](#slide-09--a8--logout-properly)
10. [A9 · Token Exchange & On-Behalf-Of (RFC 8693)](#slide-10--a9--token-exchange--on-behalf-of-rfc-8693)
11. [B1 · OpenID Federation 1.0 — Trust Chains](#slide-11--b1--openid-federation-10--trust-chains)
12. [B2 · eIDAS 2.0 & the EUDI Wallet Ecosystem](#slide-12--b2--eidas-20--the-eudi-wallet-ecosystem)
13. [C1 · The Wallet Stack — SIOPv2 + VCI + VP](#slide-13--c1--the-wallet-stack--siopv2--vci--vp)
14. [C2 · ISO mDL · The Other Half of the Wallet World](#slide-14--c2--iso-mdl--the-other-half-of-the-wallet-world)
15. [D1 · Workload OIDC Deep Dive](#slide-15--d1--workload-oidc-deep-dive)
16. [D2 · Aggregated & Distributed Claims, the `claims` Parameter](#slide-16--d2--aggregated--distributed-claims-the-claims-parameter)
17. [D3 · Demanding MFA — `prompt`, `max_age`, `acr_values`, `amr`](#slide-17--d3--demanding-mfa--prompt-max_age-acr_values-amr)
18. [D4 · Observability — What to Log, What to Alert On](#slide-18--d4--observability--what-to-log-what-to-alert-on)
19. [D5 · Migration Playbooks](#slide-19--d5--migration-playbooks)
20. [D6 · Reference Architectures by Domain](#slide-20--d6--reference-architectures-by-domain)
21. [Summary & References](#slide-21--summary--references)

---

## Slide 01 — Topics — Four Chapters

### A · Hardening

- The validation edge cases that break in prod
- Audience wars — `aud`, `azp`, multi-audience tokens
- Pairwise / public subject identifiers
- PAR · JAR · JARM · request_uri
- FAPI 2.0 — what it actually requires
- mTLS · `private_key_jwt` · DPoP — beyond bearer
- Logout, properly — RP-initiated · back-channel · front-channel
- Token Exchange & on-behalf-of

### B · Federation

- OpenID Federation 1.0 — trust chains in detail
- Entity statements, trust marks, intermediates
- eIDAS 2.0 + EUDI Wallet ecosystem
- Real-world federations: Open Banking, eHealth, education

### C · Wallet-Era

- SIOPv2 — Self-Issued OPs, who is the IdP now?
- OpenID4VCI — issuing Verifiable Credentials
- OpenID4VP — presenting them
- Mobile Driving Licence (ISO/IEC 18013-5/-7)
- SD-JWT VC and DID-based subjects

### D · Operational

- Workload OIDC deep dive (GHA · GCP · Azure · K8s)
- Aggregated & distributed claims · the `claims` parameter
- UX of MFA — `prompt`, `max_age`, `acr_values`, `amr`
- Observability — what to log, what to alert on
- Migration playbooks — SAML→OIDC, monolith→OP
- Reference architectures by domain

---

## Slide 02 — A1 · ID-Token Validation Edge Cases

Every OIDC implementer learns the eight basic checks (signature, `iss`, `aud`, `exp`, `iat`, `nonce`, `azp`, `at_hash`). The bugs that cost you money live *between* them.

### Clock skew & the ±5-minute lie

- Most libraries default to a 30–60 s leeway. Mobile clients and serverless cold-starts blow that.
- Symptom: intermittent *"token used before `nbf`"* errors at midnight DST changeovers and on freshly-spawned Lambda containers.
- Fix: NTP everywhere, leeway ≤ 60 s, *monitor* for skew. Don't quietly raise leeway to 300 s — you've just created an unsigned-replay window.

### `kid`-less tokens & key roll-over

- OPs publish multiple keys in JWKS. Tokens without a `kid` force the RP to try every key — a CPU-burn DoS surface.
- During roll-over, both old and new keys live in JWKS for ~24 h. RPs that cache JWKS for >24 h fail at the cutover.
- Fix: refuse `kid`-less tokens; cache JWKS 5–60 min; refresh on unknown `kid`; alert if >1 % of tokens trigger a refresh.

### Algorithm confusion

- Per-RP allow-list, not per-OP. `alg=none` permanently rejected.
- HS256 vs RS256 confusion attack: an attacker mints an HS256 token whose secret is *your* public RSA key, copy-pasted from JWKS. Naïve libraries accept it.
- Fix: pin the expected `alg` and the expected key type; never let the token's header pick the verification key class.

### `nonce` binding

- Generated client-side per request, sent on `/authorize`, must be reflected in the ID token.
- Servers that store the `nonce` in a cookie and check it after redirect have a CSRF-on-callback problem if the cookie isn't `SameSite=Lax`.
- Fix: bind `nonce` to the user's session (not a global cookie), validate then delete.

### Multi-tenant `iss` drift

- Microsoft Entra issues per-tenant `iss` URLs. RPs that pin one issuer break for guest users.
- Fix: validate against an issuer template (e.g. `https://login.microsoftonline.com/{tid}/v2.0`) and explicitly check `tid`.

---

## Slide 03 — A2 · The `aud` Wars — Multi-Audience & `azp`

The `aud` claim is permitted to be a string *or* an array. The `azp` (authorized party) claim is required *iff* there is more than one audience. Most bugs in this area come from RPs that don't treat `aud` as *both*.

### The spec rule, plainly

- `aud` MUST contain the RP's client_id.
- If `aud` has more than one value, `azp` MUST be present and equal to the party who started this flow.
- If `aud` has more than one value *and* the RP is not `azp`, the RP MUST NOT trust the token as identity for itself.

### A single-audience token (typical)

```json
{
  "iss":  "https://login.acme.com/",
  "sub":  "user_42",
  "aud":  "client_web_app",
  "exp":  1800003600,
  "iat":  1800000000,
  "nonce":"a7c…",
  "auth_time": 1800000000
}
```

### A multi-audience token (sharing across siblings)

```json
{
  "iss":  "https://login.acme.com/",
  "sub":  "user_42",
  "aud":  ["client_web_app","client_billing_api"],
  "azp":  "client_web_app"
}
```

### The bug that bites

RP *billing_api* receives the multi-audience ID token above and decides: *"my client_id is in `aud`, therefore this is my user logging in."* No — `azp` says the user logged into *web_app*. Promoting that ID-token `sub` to a session in *billing_api* is identity hijacking via a sibling app.

### Four guarded patterns

1. **Single-aud only.** Refuse multi-aud unless you have a specific reason. Most OPs let you turn this off.
2. **If multi-aud,** require `azp` and refuse if `azp != my_client_id`.
3. **Distributed claims** arrive in a different document fetched via `_claim_sources` — they have their own `iss` and `aud`, validate independently.
4. **Aggregated claims** are signed JWTs embedded in the ID token. Validate as if they were standalone tokens.

### Mnemonic

"*`aud` says where the token is welcome; `azp` says who actually walked through the door.*"

---

## Slide 04 — A3 · Pairwise & Public Subject Identifiers

The `sub` claim is the single most consequential identifier in OIDC. The same physical user can intentionally appear with *different* `sub`s to different RPs, depending on the OP's `subject_type` setting.

### Two subject types

- **public** — the same `sub` for that user across every RP at the OP. Easy to correlate; suitable inside one trust boundary.
- **pairwise** — a per-RP pseudonymous `sub`. A user looks like a different identifier to every RP. Required for unlinkability (eIDAS, Apple Sign-In).

### How pairwise actually works

The OP computes `sub = HMAC(seed, sector_id || local_user_id)`. The *sector identifier* groups RPs that share a `sub` namespace.

```
# RP advertises a sector via sector_identifier_uri
GET https://app.example/.well-known/oidc-sector-uris

[
  "https://app.example/cb",
  "https://eu.app.example/cb",
  "https://api.app.example/exchange"
]
```

### When to insist on pairwise

- You're a *public* OP serving many third-party RPs and want to limit cross-app tracking.
- Regulatory privacy regimes (eIDAS LoA High, NHS data sharing, Apple).
- You operate a B2C ecosystem and want one user record but distinct external IDs.

### Common foot-gun

Migrating an OP from `public` to `pairwise` after launch — every existing user changes `sub`, every RP loses its account-binding. Plan a dual-write or a `sub_legacy` claim before you flip.

### Sign in with Apple — the canonical pairwise OP

Apple issues pairwise `sub`s by default; the user can also choose to *hide* their email, in which case Apple inserts a relay address. Different `sub` per-app, no cross-RP correlation possible.

---

## Slide 05 — A4 · Pushed Authorization Requests (PAR) — RFC 9126

Classical OIDC stuffs every authorisation parameter into the front-channel URL. **PAR** instead POSTs them to a back-channel endpoint up-front, gets back a one-time `request_uri`, and uses that on `/authorize`.

```
RP                       OP                  User-Agent
 │                       │                       │
1.├──POST /par  client_auth + all params──▶      │
2.◀──{ request_uri:"urn:…", expires_in:60 }──    │
3.├──redirect user to /authorize?client_id=…&request_uri=urn:…──▶
4.                       ◀──GET /authorize?…request_uri=…──
5.                       ──login + consent → 302 cb?code=…&state=…──▶
```

Front-channel URL now carries only `client_id` + `request_uri` — no parameter tampering by user.

### Why PAR matters

- **Integrity** — the request is authenticated up-front. The user-agent can't tamper with scope, redirect_uri or PKCE challenge.
- **Privacy** — sensitive parameters (claims, login_hint with email) never touch the URL bar / referer / browser history.
- **URL length** — large parameter sets (rich auth requests, claims JSON) don't blow up the GET URL.
- **Required by FAPI 2.0.**

### PAR + JAR — even tighter

Combine PAR with JAR (RFC 9101) and the parameters in the `/par` body are themselves a signed/encrypted JWT (a `request` object). The OP knows the parameters came from the legitimate RP, not just *via* it. That's the FAPI 2.0 baseline.

---

## Slide 06 — A5 · JAR & JARM — Signed Requests & Responses

### JAR — JWT-Secured Authorization Request (RFC 9101)

```json
// the request object — a JWS (often signed with RP's private_key_jwt key)
{
  "iss":  "client_web_app",
  "aud":  "https://op.example",
  "response_type": "code",
  "client_id": "client_web_app",
  "redirect_uri": "https://app/cb",
  "scope": "openid profile email",
  "state": "X9d…",
  "nonce": "a7c…",
  "code_challenge": "e9k…",
  "code_challenge_method": "S256",
  "claims": { "id_token": { "acr": { "essential": true,
                                     "values": ["urn:mfa"] } } }
}

# delivered either as
GET /authorize?request=eyJhbGc…   (by-value)
# or referenced
GET /authorize?request_uri=https://rp/req/abc   (by-reference)
# (PAR is the formal "by-reference" mechanism — preferred)
```

### JARM — JWT-Secured Authorization Response Mode

```
# instead of  ?code=…&state=…
GET /cb?response=eyJhbGciOiJSUzI1NiI…

# decoded payload
{
  "iss":  "https://op.example",
  "aud":  "client_web_app",
  "exp":  1800000300,
  "code": "AUTH_CODE",
  "state": "X9d…"
}
```

- The OP signs the response itself, end-to-end.
- Defeats *response-splitting*, mix-up, and tampered `iss`/`state`.
- Required by FAPI 2.0 alongside PAR.

### When to use what

| Threat | Mitigation |
|---|---|
| Tampered request params | JAR / PAR |
| Tampered response params | JARM |
| Stolen authorisation code | PKCE + sender-constrained tokens |
| Mix-up across multiple OPs | JARM (signed `iss`) + RFC 9207 `iss` param |

---

## Slide 07 — A6 · FAPI 2.0 — Financial-Grade OIDC

**FAPI 2.0** (Final, 2024) is the OpenID Foundation's hardened profile of OAuth/OIDC, originally for Open Banking. It is now also the baseline for several health, government, and high-value B2B ecosystems. It comes in two parts.

### FAPI 2.0 Security Profile (the baseline)

- Authorisation Code only — no Implicit, no Hybrid.
- **PAR** required for all requests.
- **PKCE S256** required.
- Client authentication: **`private_key_jwt`** or **tls_client_auth** — no shared secrets.
- Sender-constrained tokens: **DPoP** or **mTLS** on every API call.
- Strict `redirect_uri` string match.
- Resource Indicators (RFC 8707) on every `/par`.

### FAPI 2.0 Message Signing (the optional add-on)

- Adds end-to-end signing of the request (JAR) and response (JARM) — non-repudiation, not just integrity.
- Mandatory in some ecosystems (Open Banking Brazil, Australia CDR).

### Where it's actually deployed

- **UK Open Banking** — FAPI 1 → FAPI 2.
- **Open Banking Brazil** — FAPI 2 + Message Signing.
- **Australia Consumer Data Right (CDR)**.
- **Saudi Open Banking**, **Open Finance Brazil**, several EU PSD2 sandboxes.
- **Smart Health Card / FHIR** in some jurisdictions.

### Conformance matters

FAPI is *certified*. The OpenID Foundation runs a public conformance suite at `openid.net/certification`. Many ecosystems require a passing certificate before you can register a production client. Don't roll your own.

### If you only know one thing

The FAPI 2.0 cheat-line: **PAR + PKCE + DPoP/mTLS + private_key_jwt + Resource Indicators**. If your stack is missing any of those for a high-value API, you're not FAPI-grade.

---

## Slide 08 — A7 · mTLS · `private_key_jwt` · DPoP

Three different ways to bind a token (or the request that mints it) to a key only the legitimate party controls.

| Mechanism | What it protects | How it works | Operational cost |
|---|---|---|---|
| **`private_key_jwt`** (RFC 7523) | Client → AS authentication on `/token`, `/par`, `/register` | Client signs a short JWT assertion with its private key; AS verifies via JWKS the client published. | Low — RP just hosts a JWKS. Replaces all shared client secrets. |
| **tls_client_auth / mTLS** (RFC 8705) | Client → AS authentication and sender-constrained access tokens | Mutual TLS handshake; AS records cert hash; RS rejects calls whose client cert hash ≠ token's `cnf.x5t#S256`. | Higher — needs PKI, cert rotation, careful TLS termination. |
| **DPoP** (RFC 9449) | Sender-constrained access tokens for any client (browser, mobile, CLI) | Per-request JWS proof signed by client-generated key; token's `cnf.jkt` binds to that key's hash. | Low for clients, moderate for RS (must implement `jti` replay cache, `htm`/`htu` validation). |

### A `private_key_jwt` client assertion

```
POST /token HTTP/1.1
Host: op.example
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTH&code_verifier=…&
client_id=client_web_app&
client_assertion_type=
  urn:ietf:params:oauth:client-assertion-type:jwt-bearer&
client_assertion=eyJhbGc…   ← the JWS

# decoded assertion
{ "iss":"client_web_app", "sub":"client_web_app",
  "aud":"https://op.example/token",
  "jti":"e1b7…", "iat":1800000000, "exp":1800000060 }
```

### Picking one

- **Browser RP** → DPoP for sender-constraint, plus public-client (no shared secret).
- **Backend RP / API gateway** → `private_key_jwt` + DPoP, or mTLS if PKI exists.
- **B2B with mature PKI** → mTLS end-to-end (banking, eIDAS).
- **Mobile app** → DPoP, with the keypair stored in Secure Enclave / Strongbox.

### Antipattern

Stateless reverse-proxies that terminate TLS and forward the request without surfacing the client cert in a header (`X-SSL-Client-Cert` or similar). The RS sees a *different* mTLS endpoint and the cert binding silently drops to nothing.

---

## Slide 09 — A8 · Logout, Properly

"Sign out" in OIDC is *three* different specs. They solve different problems and you usually need more than one.

### RP-Initiated Logout

```
GET /logout?
  id_token_hint=eyJ…&
  post_logout_redirect_uri=https://app/bye&
  state=…
```

- RP sends the user to OP's logout endpoint.
- OP ends the user's session at the OP.
- OP redirects back to the RP's `post_logout_redirect_uri`.
- Local-RP-driven, top-of-funnel. Doesn't notify other RPs.

### Back-Channel Logout

```
POST /backchannel-logout HTTP/1.1
Host: rp.example
Content-Type: application/x-www-form-urlencoded

logout_token=eyJ…  // a signed JWT
                   // events: http://schemas.openid.net/event/backchannel-logout
```

- OP POSTs a logout-event JWT to every RP that registered an endpoint.
- Server-to-server, reliable, behind the user's back.
- RP destroys the user's session in its own store.
- The pattern that actually works at scale.

### Front-Channel Logout

```html
<!-- OP's logout page -->
<iframe src="https://rp1/fcl?iss=…&sid=…">
<iframe src="https://rp2/fcl?iss=…&sid=…">
```

- OP renders one hidden iframe per RP; each iframe nukes its session cookie.
- Browser-only; no server-to-server channel needed.
- Fragile — third-party cookie blocking and CSP can break it silently.
- Use only as a fallback when back-channel isn't available.

### A pattern that actually ends every session

Pair **RP-Initiated** (so the user feels logged out at the OP) with **Back-Channel** (so other RPs are reliably told). Use **Front-Channel** only for legacy RPs that can't host a back-channel endpoint. Always check the `sid`/`events`/`iss` claims on the logout token — and confirm the token came from the OP you actually used.

---

## Slide 10 — A9 · Token Exchange & On-Behalf-Of (RFC 8693)

A user-bearing token at API A, an authenticated request *from* A to downstream API B that needs to preserve the original user identity. Token Exchange is the standardised way; it's also Microsoft's "OBO" flow.

### The exchange

```
POST /token HTTP/1.1
Host: op.example
Authorization: Basic base64(api_a:secret)
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange&

# the inbound token API A received from the user
subject_token=eyJ…   &
subject_token_type=urn:ietf:params:oauth:token-type:access_token&

# (optional) act-on-behalf-of identity
actor_token=eyJ…    &
actor_token_type=urn:ietf:params:oauth:token-type:jwt&

# what API A needs at API B
audience=https://api-b.example&
scope=invoices:read

# response — a token usable by API A to call API B,
# with both 'sub' (the user) and 'act' (API A) preserved
{ "access_token": "eyJ…",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 600 }
```

### Why this matters

- API B can audit: *"user U, acting via API A"*.
- API B can enforce its own scopes for U, regardless of what U granted at A.
- The user's original token isn't replayed — defeats confused-deputy.

### In the resulting token

```json
{ "iss":"op.example",
  "sub":"user_42",         // original user
  "aud":"api-b",
  "scope":"invoices:read",
  "act": { "sub":"api_a" } // who acted on their behalf
}
```

### Naming map

Microsoft *"OBO"*, AWS Cognito *"token vending"*, Auth0 *"token exchange"*, Keycloak *"token exchange feature"* — all RFC 8693 with vendor garnish.

---

## Slide 11 — B1 · OpenID Federation 1.0 — Trust Chains

**OpenID Federation 1.0** (final, Sep 2024) replaces "every RP statically configures every OP" with cryptographically verifiable *trust chains*. It's how you scale OIDC across thousands of organisations.

```
                     ┌──────────────────┐
                     │  Trust Anchor    │  e.g. NHS / eIDAS / EduGAIN
                     └────────┬─────────┘
                  ┌───────────┴────────────┐
        ┌─────────▼─────────┐    ┌─────────▼──────────┐
        │   Intermediate    │    │   Intermediate     │
        │ (one EU country)  │    │ (a hospital trust) │
        └───┬──────────┬────┘    └───┬──────────┬─────┘
            │          │             │          │
       ┌────▼────┐ ┌───▼────┐   ┌────▼────┐ ┌───▼────┐
       │ leaf RP │ │ leaf OP│   │ leaf OP │ │ leaf RP│
       │ (Bank A)│ │(eIDAS) │   │(Trust X)│ │ (FHIR) │
       └─────────┘ └────────┘   └─────────┘ └────────┘
```

Each node publishes a `/.well-known/openid-federation` entity statement signed by its parent. RP follows the chain to the trust anchor.

### Building blocks

- **Entity Statement** — JWT a federation participant publishes about itself + its parent.
- **Subordinate Statement** — JWT a parent publishes about a child (incl. policy clipping).
- **Trust Mark** — third-party signed assertion (e.g. "this RP passed FAPI 2.0 conformance").
- **Metadata Policy** — parent can constrain child's metadata (max TTLs, required signing algs).

### Why now

eIDAS 2.0 / EUDI Wallet, the EU eHealth Network, the Brazilian Open Insurance ecosystem, EduGAIN's OIDC profile — all standardised on Federation 1.0 in late 2024 / 2025 because per-pair pre-registration is intractable at country scale.

---

## Slide 12 — B2 · eIDAS 2.0 & the EUDI Wallet Ecosystem

**eIDAS 2.0** (in force May 2024; member-state rollout to 2026) requires every EU Member State to issue an interoperable **EU Digital Identity Wallet (EUDIW)**. It is the largest planned deployment of OIDC + Verifiable Credentials in the world.

### The architecture (in OIDC terms)

- **PID Provider** = OIDC OP issuing the citizen's Person Identification Data as a Verifiable Credential (often via OpenID4VCI).
- **EUDI Wallet** = a Self-Issued OP (SIOPv2) on the citizen's phone that holds the credentials and presents them on demand.
- **Relying Party** = the bank, employer, gov-service. Talks OpenID4VP to the wallet.
- **Trust Framework** = OpenID Federation 1.0 + EU-managed trust anchors (one per member state).

### Levels of Assurance (LoA)

- **Low** — username/password equivalent. Not enough for most regulated use.
- **Substantial** — the bar for online banking, eHealth, eGovernment portals.
- **High** — required for things like opening a regulated account; needs hardware-bound key on the phone (Secure Enclave / TEE).

### Why a developer outside the EU should still care

- The EU is forcing every "Very Large Online Platform" (DSA) to *accept* EUDI Wallet logins by 2027.
- Apple, Google, Microsoft, Amazon, Meta — and any equivalent-scale non-EU SaaS — must implement the RP side.
- The patterns ratified here (SIOPv2 + OpenID4VP + Federation 1.0) are being copied by Australia (TDIF), Canada (PCTF), Brazil (gov.br), Singapore (Singpass).

### Reference implementations to look at

- **EU Reference Implementation** — github.com/eu-digital-identity-wallet
- **SPID/CIE-OIDC** (Italy) — production OpenID Federation network at scale.
- **Sphereon / Mattr / Procivis** — commercial wallet SDKs.

---

## Slide 13 — C1 · The Wallet Stack — SIOPv2 + VCI + VP

The wallet-era OIDC is three coordinated specs. Each is a small extension of OIDC that swaps "the OP is a server in the cloud" for "the OP is the user's device".

### SIOPv2 — Self-Issued OPs

- A re-skin of OIDC where the wallet on the phone is the OP.
- `iss` = a DID or a JWK thumbprint, not an HTTPS URL.
- Discovery is replaced by static metadata; dynamic registration is replaced by the wallet trusting any RP that asks.
- Solves: "log into a website using nothing but a phone".

### OpenID4VCI — Issuance

- Issuer (gov, university, employer) speaks *this* spec to push a VC into the user's wallet.
- Two flows: *pre-authorised code* (paper letter with a QR — the EU baseline) and *authorisation code* (browser flow).
- Credential format negotiated: **SD-JWT VC**, **mDoc/mDL**, **W3C VC-JWT**.

### OpenID4VP — Presentation

- RP asks the wallet for credentials matching a *presentation_definition* (DIF Presentation Exchange syntax).
- Wallet shows the user the request, gets consent, returns selectively-disclosed claims via **SD-JWT** or **mdoc selective disclosure**.
- The RP never sees claims the user didn't reveal — true minimisation.

### A worked sequence — a bank verifies your driving licence

1. Bank's RP renders a QR encoding an *OpenID4VP* request: "give me `given_name`, `date_of_birth`, `document_number` from a credential of type `org.iso.18013.5.1.mDL`".
2. User scans QR with EUDI Wallet. Wallet matches the request to a stored mDL credential.
3. Wallet shows: *"OakBank wants to see name, DoB, licence number from your driving licence — Allow?"*
4. User approves with biometrics; wallet signs an SD-JWT presentation revealing *only* those three fields.
5. Bank's RP verifies the wallet's signature, checks the issuer's trust chain (OpenID Federation 1.0), accepts.

---

## Slide 14 — C2 · ISO mDL · The Other Half of the Wallet World

Not all wallet-era credentials live in the OIDC tent. The **Mobile Driving Licence** (mDL) is defined by **ISO/IEC 18013-5** (NFC / BLE proximity) and **ISO/IEC 18013-7** (online presentation). Most major US states and many EU/Asia jurisdictions are deploying it.

### Two presentation modes

- **In-person (18013-5)** — over NFC or BLE. Wallet on phone, reader on the bouncer's terminal. No internet required. CBOR + COSE.
- **Online (18013-7)** — over the web. The bridge to OIDC: 18013-7 reuses **OpenID4VP** as its transport.

### Why a backend dev should know about it

- You'll be asked to consume mDL/mDoc credentials presented via OpenID4VP.
- The credential format isn't JSON — it's CBOR-encoded mdoc with COSE signatures. Use a library; do not parse by hand.
- Issuer trust is rooted in *government* root CAs, not the public web PKI.

### SD-JWT VC vs mDoc — when each

|  | SD-JWT VC | mDoc / mDL |
|---|---|---|
| Encoding | JSON / JWT | CBOR / COSE |
| Origin | IETF / OIDF | ISO TC 204 |
| Selective disclosure | SD-JWT | mdoc disclosure |
| Online flow | OpenID4VP | OpenID4VP (18013-7) |
| Offline / proximity | n/a | NFC / BLE (18013-5) |
| EUDI primary | yes | secondary |
| US state DMV primary | secondary | yes |

### The interop reality in 2026

Both formats are being shipped in parallel. Wallets typically support both; RPs that want broad coverage need both verification paths. OpenID4VP is the common online transport.

---

## Slide 15 — D1 · Workload OIDC Deep Dive

OIDC isn't just for human logins. Modern CI/CD and Kubernetes use it to issue *workload* identities — short-lived JWTs that replace long-lived API keys.

### GitHub Actions → AWS

```yaml
# GHA mints an OIDC token
permissions:
  id-token: write
steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123:role/deploy
      aws-region: eu-west-1

# AWS STS verifies via
# https://token.actions.githubusercontent.com/.well-known/jwks
# and assumes the role if the token's
# 'sub' = "repo:org/repo:ref:refs/heads/main"
# matches the role's trust policy
```

### GitHub Actions → GCP

- Workload Identity Pool + Provider; pool trusts `token.actions.githubusercontent.com`.
- Action calls `google-github-actions/auth`; receives a short-lived GCP access token.
- No long-lived service-account JSON keys anywhere in the repo or CI.

### Kubernetes — ServiceAccountTokenVolumeProjection

- Pod mounts a projected token at `/var/run/secrets/tokens/gha` with a configurable `aud`.
- Token is a JWT signed by the cluster's OIDC issuer (`kubectl get --raw /.well-known/openid-configuration`).
- External services (HashiCorp Vault, AWS, GCP) trust the cluster OIDC issuer; no Kubernetes secrets ever leave the cluster.
- This is how SPIRE / SPIFFE bootstraps and how Istio does workload identity.

### Trust-policy hygiene

- Always pin `sub`, not just `iss` + `aud` — otherwise *any* repo at `token.actions.githubusercontent.com` can assume the role.
- Pin `repository_owner` + `repository` + branch / environment.
- Cache JWKS sensibly; rotate IAM role trust if the OIDC issuer rotates keys.

---

## Slide 16 — D2 · Aggregated & Distributed Claims, the `claims` Parameter

### The `claims` request parameter

Most RPs accept whatever default claims the OP sends. The `claims` parameter (OIDC Core §5.5) lets you ask for specific claims, mark them *essential*, and even pin acceptable values.

```
POST /par
claims={
  "id_token": {
    "acr":           { "essential": true,
                       "values": ["urn:mace:incommon:iap:gold"] },
    "auth_time":     { "essential": true },
    "email":         null,
    "email_verified":{ "essential": true, "value": true }
  },
  "userinfo": {
    "given_name":  null,
    "family_name": null,
    "address":     { "essential": true }
  }
}
```

"*Essential*" lets the OP know *"if you can't satisfy this, prompt the user / step up — don't silently issue a weaker assertion."*

### Aggregated claims

The OP embeds a *second* signed JWT inside the ID token, issued by a different authority. Useful when, say, the user's age-of-majority is asserted by a government issuer but their email is asserted by the social OP.

```
// inside the ID token
"_claim_names":   { "age_over_18": "src1" },
"_claim_sources": {
  "src1": { "JWT": "eyJ…signed-by-gov-issuer…" }
}
```

### Distributed claims

Same idea, but instead of an embedded JWT the OP gives you a URL + a token to fetch the claim from a separate authority.

```
"_claim_names":   { "tax_status": "src2" },
"_claim_sources": {
  "src2": {
    "endpoint": "https://hmrc.example/claims/4321",
    "access_token": "eyJ…"
  }
}
```

### Validate them as if they were standalone tokens

Different `iss`, different `aud`, different `exp`. The bug to avoid is treating an aggregated claim as if the parent OP's signature blessed it — only the *inner* issuer can vouch for the inner claim.

---

## Slide 17 — D3 · Demanding MFA — `prompt`, `max_age`, `acr_values`, `amr`

The auth event itself has metadata. These four parameters/claims let an RP demand fresh / strong authentication, and verify it actually happened.

| Parameter / claim | Direction | Job |
|---|---|---|
| `prompt=login` | RP → OP, on `/authorize` | Force re-authentication even if the user has a live SSO session. |
| `prompt=consent` | RP → OP | Force the consent screen even if remembered. |
| `prompt=none` | RP → OP | Silent — fail rather than display UI. Useful for token refresh / SSO check. |
| `max_age=N` | RP → OP | Refuse if the user's last login was more than N seconds ago. |
| `acr_values` | RP → OP | Request a specific *Authentication Context Class* — e.g. `urn:mace:incommon:iap:silver`, or `http://eidas.europa.eu/LoA/high`. |
| `auth_time` | OP → RP, in ID token | Unix time of the actual authentication event. |
| `acr` | OP → RP, in ID token | The class actually achieved (may be lower than requested if the OP couldn't satisfy it). |
| `amr` | OP → RP, in ID token | Array of methods used: e.g. `["pwd","otp"]`, `["pwd","webauthn"]`, `["face","hwk"]`. |

### A typical step-up

```
# user is logged in (with password) but is now trying to
# initiate a £10k transfer. RP forces fresh MFA:
GET /authorize?
  client_id=…&
  scope=openid&
  prompt=login&
  max_age=120&
  acr_values=urn:mace:incommon:iap:gold&
  claims={"id_token":{"acr":{"essential":true,
                             "values":["urn:mace:incommon:iap:gold"]}}}

# resulting ID token must include
"acr": "urn:mace:incommon:iap:gold",
"amr": ["pwd","webauthn"],
"auth_time": 1800002000
```

### The bug to avoid

Sending `acr_values` but *not* verifying the returned `acr` matches. The OP is allowed to step *down*; if you don't check, your "MFA-protected" code path runs after a password-only login.

Always: *request as parameter, demand as essential claim, verify on receipt.*

---

## Slide 18 — D4 · Observability — What to Log, What to Alert On

### RP-side metrics

- **`oidc.token.validate.failure{reason}`** — labelled by `signature`, `aud`, `iss`, `exp`, `nonce`, `kid`, `at_hash`. Spikes in `kid`-failures = key rotation drama.
- **`oidc.jwks.refresh{outcome}`** — alert if more than 1 % of validations trigger a refresh.
- **`oidc.flow.duration_ms`** — quantiles by step (`par` · `authorize` · `token` · `userinfo`). Most outages first show as a token-endpoint p99 climb.
- **`oidc.refresh.reuse_detected`** — every event is a probable token theft.

### RP-side logs (per request)

- `iss`, `sub` (hashed if user-linkable in cold storage), `aud`, `azp`, `scope`, `amr`, `acr`, `auth_time`.
- **Never**: the raw token, the ID token's PII (email, given_name) at INFO level.
- Correlate by `jti` + a flow-id you generate on `/authorize` and propagate through.

### OP-side metrics that catch attacks early

- Authorisation-endpoint **PKCE-mismatch** rate (CSRF/replay attempts).
- Per-client / per-IP **redirect_uri** mismatch — trivial misconfig *or* exfil attempt.
- DCR creation rate per source IP / ASN — abuse vector for open registration.
- Refresh-token reuse alerts (compromise indicator).
- Anomalous `acr` downgrades (the OP is failing to enforce step-up).

### SIEM events worth wiring up

- Logout-token POST failures from the OP (an RP went silent — sessions stay alive).
- Successful `/par` with no follow-up `/authorize` (probing).
- JWKS fetched from outside expected CIDRs.
- Federation entity-statement signature failures (someone is fiddling with the trust chain).

---

## Slide 19 — D5 · Migration Playbooks

### SAML → OIDC

1. Stand up an OIDC OP that *also* brokers the existing SAML IdP — users see no UI change.
2. Migrate one RP at a time to OIDC; OP issues both an OIDC ID token *and* (where needed) a SAML assertion.
3. Map the SAML `NameID` into the OIDC `sub` with care — once-only mapping table.
4. Translate SAML `AuthnContextClassRef` values to OIDC `acr_values`.
5. Decommission the SAML IdP only after every RP is OIDC *and* log audit shows zero SAML assertions for ≥ 30 days.

### Monolith → Federated OPs

1. Carve the user-account service out of the monolith into an OP behind a stable issuer URL.
2. Issue OIDC sessions in parallel with the legacy session cookie; both valid.
3. Migrate one bounded context at a time to consume the OIDC ID token instead of the legacy cookie.
4. Cut the legacy cookie issuance off by date; keep it as *read* for ≥ 1 refresh-token max-lifetime.
5. Adopt PAR + DPoP only after the basic migration is done — don't try to do both in one quarter.

### OAuth-only → OIDC

1. Add the `openid` scope to your existing flows.
2. Have the AS start issuing ID tokens; clients ignore them at first.
3. Move every "who is this user" decision off introspection-of-access-token onto the ID-token `sub`.
4. Add discovery (`/.well-known/openid-configuration`) and start consuming JWKS.
5. Wire up logout (back-channel) and consent UX last.

### Lessons from real migrations

- Estimate "every place where a username is stored" — it's always 5×–10× what you think.
- Don't migrate *and* harden in the same quarter. Do the protocol move first; layer FAPI 2.0 on the stable result.
- Issuer URL is forever. Pick a canonical hostname (`https://login.acme.com/`) before launch — every RP, mobile app, partner integration will pin it.

---

## Slide 20 — D6 · Reference Architectures by Domain

| Domain | Profile | Stack |
|---|---|---|
| **UK Open Banking** | FAPI 1 → FAPI 2 | OIDC OP at the bank · PAR · mTLS · `private_key_jwt` · request objects · UK Trust Framework directory. |
| **Open Banking Brazil** | FAPI 2 + Message Signing | JAR + JARM + DPoP/mTLS · OpenID Federation 1.0 · Brazilian Central Bank as trust anchor. |
| **eIDAS 2.0 / EUDI Wallet** | SIOPv2 + OpenID4VCI + OpenID4VP | PID Provider issues SD-JWT VC into the wallet · RP requests via OpenID4VP · Federation 1.0 trust chain to a national TA. |
| **FHIR / SMART on FHIR** | OAuth 2 + OIDC + scopes like `patient/Observation.read` | OIDC OP + EHR as RS · launch context via launch parameters · sometimes FAPI in regulated jurisdictions. |
| **EduGAIN / Research** | OpenID Federation 1.0 + REFEDS schema | Federation across 5,000+ universities, replacing SAML eduGAIN with OIDC equivalents. |
| **US Government LOA / NIST 800-63** | OIDC + `acr_values` mapped to IAL/AAL | Login.gov / ID.me as OPs · AAL2/AAL3 enforced via `acr_values` + amr. |
| **B2B SaaS multi-tenant** | OIDC OP + SCIM + SAML fallback | WorkOS / Auth0 / Okta CIC as broker · per-tenant identity provider connections · SCIM for provisioning. |
| **Workload identity** | OIDC issuer per platform | GitHub Actions / GCP Workload Identity / Kubernetes ServiceAccountTokenVolume / SPIFFE/SPIRE · short-lived JWTs only. |

---

## Slide 21 — Summary & References

### What we covered

- **Hardening** — validation edge cases, `aud`/`azp`, pairwise subjects, PAR, JAR, JARM, FAPI 2.0, mTLS / `private_key_jwt` / DPoP, three logout specs, Token Exchange.
- **Federation** — OpenID Federation 1.0 trust chains, eIDAS 2.0 + EUDI Wallet, real-world ecosystems.
- **Wallet-era** — SIOPv2 + OpenID4VCI + OpenID4VP, ISO mDL, SD-JWT VC vs mDoc.
- **Operational** — workload OIDC (GHA / GCP / K8s), aggregated/distributed claims, MFA UX (`prompt` / `max_age` / `acr_values` / `amr`), observability, migration playbooks, domain reference architectures.

### Companion decks

- **Introduction to OpenID Connect** — the foundations this deck assumes.
- **OAuth — A Gentle Primer** · **Introduction to OAuth** · **OAuth for MCP Servers** — the OAuth series.

### Three take-aways

1. **Validate `aud` with `azp`.** The single biggest class of OIDC bugs is treating multi-audience tokens as single-audience.
2. **If you handle anything regulated, you're heading for FAPI 2.0.** PAR + JAR/JARM + sender-constrained tokens + `private_key_jwt` — and *certify*, don't self-attest.
3. **The wallet stack is the next battleground.** SIOPv2 + OpenID4VP + Federation 1.0 are the EU baseline; the rest of the world is converging.

### One-line takeaway

The basic protocol is a small spec; production OIDC is the *profiles*. Pick the right profile for your domain (FAPI 2.0, EUDI, workload), and certify it.

### References

OpenID Connect Core 1.0 · OIDC Discovery · OIDC Dynamic Client Registration · OIDC RP-Initiated / Back-Channel / Front-Channel Logout · CIBA Core 1.0 · SIOPv2 · OpenID for Verifiable Credential Issuance (OpenID4VCI) · OpenID for Verifiable Presentations (OpenID4VP) · OpenID Federation 1.0 (Sep 2024) · FAPI 2.0 Security Profile · FAPI 2.0 Message Signing · ISO/IEC 18013-5 / 18013-7 (mDL) · eIDAS 2.0 Regulation (EU) 2024/1183 · SD-JWT (draft-ietf-oauth-selective-disclosure-jwt) · SD-JWT VC · RFC 7515/7517/7519 (JWS/JWK/JWT) · RFC 7523 (JWT client auth) · RFC 8414 / 8628 / 8693 / 8705 / 8707 · RFC 9068 (JWT AT) · RFC 9101 (JAR) · RFC 9126 (PAR) · RFC 9207 (iss param) · RFC 9396 (RAR) · RFC 9449 (DPoP) · RFC 9700 (BCP 240) · RFC 9728 (Protected Resource Metadata) · openid.net/certification
