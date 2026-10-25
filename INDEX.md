# Web Exploitation Skill Set — Router

Don't load every skill into context per target. Load in this order, and only load a vuln-class skill once recon has actually surfaced a matching attack surface for it.

## Fixed Load Order (every target, every session)

1. **`core/offensive-scope-safety`** — ALWAYS FIRST. Parse scope, ROE, set rate limits. Nothing below this line fires a single payload until this has run.
2. **`methodology/offensive-hunter-methodology`** — decide wide vs. narrow mode, pick session focus, load/resume the target's state file.
3. **`recon/offensive-recon`** — run the mapping pipeline appropriate to the mode chosen in step 2. Produces the endpoint/param/role inventory everything below consumes.

## Conditional Load (only if recon surfaced the matching surface)

Match what `offensive-recon`'s output actually contains — don't load a skill speculatively:

| Recon signal | Load |
|---|---|
| Any endpoint with an ID/UUID param, or role-diff showed admin-only endpoints | `web/offensive-idor` |
| Any reflected input in HTML/JS context, any search/comment/profile field | `web/offensive-xss` |
| Any raw SQL-shaped param, ORM-backed filter/search endpoint | `web/offensive-sqli` |
| Any endpoint accepting a URL/callback/webhook param | `web/offensive-ssrf` |
| Any file upload form or avatar/document endpoint | `web/offensive-file-upload` |
| Template-rendering indicators (user input reflected in a rendered page with templating artifacts) | `web/offensive-ssti` |
| XML-accepting endpoints (SOAP, file imports, SVG upload) | `web/offensive-xxe` |
| Serialized object formats in requests (Java, PHP, .NET, Python pickle signatures) | `web/offensive-deserialization` |
| Command-execution-adjacent functionality (file conversion, PDF generation, image processing) | `web/offensive-rce` |
| `/graphql` endpoint found | `web/offensive-graphql` |
| Login/session/SSO present | `auth/offensive-jwt`, `auth/offensive-oauth` |
| Any `redirect`/`next`/`return_url` param | `web/offensive-open-redirect` |
| Multi-step flows: checkout, coupon, invite, transfer | `web/offensive-business-logic`, `web/offensive-race-condition` |
| Repeated params, array-style inputs | `web/offensive-parameter-pollution` |
| Front-end proxy/load balancer chain detected (varying server headers) | `web/offensive-request-smuggling` |
| WAF/CDN fingerprinted in recon | `web/offensive-waf-bypass` |
| REST API with documented or recovered schema | `api/offensive-api-security`, `api/offensive-api-abuse` |

## Before Writing Any Report

Apply the shared evidence standard below regardless of which vuln-class skill found the bug — this is what keeps reports out of the "needs more info" / low-sev-downgrade pile.

### Evidence Standard (every report, every skill)

1. **Exact request** — full HTTP request, headers included, exactly as sent
2. **Exact response** — proving the OTHER user's/role's real data was returned, not just a 200 status
3. **Second-account confirmation** — the data shown genuinely belongs to a different, independently-verifiable account/tenant, not a shared/public resource (see `offensive-idor`'s false-positive filter — the same logic applies to every vuln class, not just IDOR)
4. **Impact statement in attacker terms** — not "IDOR found," but "any authenticated user can read/modify [specific sensitive data] belonging to any other [user/tenant] by changing [specific parameter]"
5. **Chaining check** — before submitting, spend a few minutes on `offensive-hunter-methodology`'s A→B→C pattern: does this bug unlock anything bigger when combined with another finding from this session?
