---
name: offensive-scope-safety
description: "MANDATORY pre-flight check before any active testing. Parses bug bounty program scope/policy, enforces rate limits and destructive-action guardrails, and blocks testing on out-of-scope or explicitly forbidden assets. Use this BEFORE offensive-recon and BEFORE any vuln-class skill fires a payload — an autonomous agent without this check can get an account permanently banned from a platform, void a safe-harbor protection, or cause real service disruption. Never skip this for 'just a quick check.'"
version: 1.0.0
author: Fahim
license: MIT
---

# Scope & Safety Guardrails — Run This First, Every Time

An autonomous agent chaining recon → fuzzing → exploitation without a human re-checking scope on every single request is one bad request away from: testing an out-of-scope acquisition, triggering a destructive action (mass password reset, data deletion, triggering real payments) on a production system, getting rate-limited/IP-banned mid-engagement, or voiding the program's safe-harbor legal protection entirely. This isn't theoretical — accidental scope violations and DoS-via-fuzzing are the #1 reason accounts get banned from HackerOne/Bugcrowd, not finding "too many" bugs.

## Quick Workflow

1. Parse the program's scope definition BEFORE running `offensive-recon` — build an explicit allow-list, not a mental note
2. Parse the program's rules of engagement (ROE) for forbidden techniques, rate limits, and out-of-bounds actions
3. Gate every asset discovered in recon against the allow-list before it's handed to any vuln-class skill
4. Gate every payload category against the ROE's forbidden-techniques list
5. Enforce request-rate ceilings regardless of what the ROE says, as a hard technical floor
6. Treat any destructive/state-changing action as requiring explicit extra confirmation, never auto-fired
7. Log every out-of-scope asset you encounter but don't touch — it's useful for a future scope-expansion report, not something to silently discard

---

## 1. Scope Parsing — Build an Explicit Allow-List

Scope pages use inconsistent formats (wildcard domains, IP ranges, named mobile apps, explicit exclusions). Don't infer from the program name — parse the literal text.

```
Extract and store as structured data, not prose:
{
  "in_scope": ["*.target.com", "api.target.com", "198.51.100.0/24"],
  "explicitly_out_of_scope": ["blog.target.com", "status.target.com", "*.target-support.com"],
  "asset_types_in_scope": ["web", "api"],   // vs mobile, IoT, source code, physical
  "third_party_explicitly_excluded": ["stripe.com", "zendesk.com", "intercom.com"],
  "program_type": "bounty" | "vdp",
  "safe_harbor": true | false
}
```

Common traps:
- `*.target.com` in scope does NOT automatically include acquisitions on different root domains discovered during recon — those need separate confirmation, even if they're clearly the same company
- Subdomains explicitly listed as out-of-scope often host the exact infra most hunters want to attack (status pages, support/helpdesk — these run third-party SaaS that isn't the target's code to begin with, which is usually *why* they're excluded)
- A wildcard scope with specific named exclusions means: check every single asset `offensive-recon` finds against the exclusion list before testing, every time, not just once at the start
- Third-party integrations (payment processors, support widgets, analytics) embedded in an in-scope page are NOT automatically in scope themselves — a bug in Stripe's checkout iframe is Stripe's bug, not the target's, even though it renders on target.com

## 2. Rules of Engagement Parsing

Beyond scope, parse the explicit prohibited-techniques list — these vary per program and override any default assumption from the vuln-class skills:

```
Common ROE restrictions to extract:
- No automated scanning without rate limiting (most programs require this explicitly)
- No testing against production payment/checkout flows with real transactions
- No social engineering / phishing employees
- No physical security testing
- No DoS/DDoS or load testing
- No testing of third-party/vendor-hosted subdomains even if technically resolvable
- Account takeover: must use your OWN test accounts only, never attempt against real user accounts
- Data exfiltration: proof-of-concept only — access ONE record to prove the bug, do not bulk-extract
```

If the ROE forbids automated scanning without "reasonable" rate limiting but doesn't define a number, default to the hard ceiling in section 3 below rather than guessing high.

## 3. Hard Rate-Limit Floor (Applies Regardless of ROE)

Even on programs with no explicit rate limit stated, enforce these as a non-negotiable technical floor to avoid accidental DoS and to avoid WAF-triggered IP bans that burn your testing window:

```
- Subdomain/content discovery (ffuf, gobuster, dirsearch): max 50 req/sec, lower on smaller/startup targets
- Parameter fuzzing (arjun, x8): max 10 req/sec per endpoint
- Mass IDOR/ID enumeration: max 5 req/sec, and cap total range tested (hundreds, not tens of thousands) — if you need more than a few hundred requests to prove the pattern, you've already proven it
- SQLi/time-based blind: avoid SLEEP() values beyond 3-5 seconds, and limit to the minimum requests needed to confirm, never bulk-extract via time-based blind in production
- Any action against a login/auth endpoint: max 5 attempts per account per minute — exceeding this risks locking out real users sharing infra (shared rate limiters, WAF rules) and looks identical to a credential-stuffing attack to the target's SOC
```

If a tool's default settings exceed these, override the tool's defaults explicitly — don't rely on "it'll probably be fine."

## 4. Destructive Action Gate

Any action in this category requires being flagged and held for explicit human confirmation before firing — never let a vuln-class skill auto-execute these as part of a chained workflow:

- Any `DELETE` request or equivalent destructive mutation on a non-test-owned resource
- Password reset / account recovery flows targeting anything other than your own test accounts
- Mass assignment payloads that include `role: admin`, `is_admin: true`, or similar — test on your OWN account first to prove the vector, escalate to a second test account only if needed, never attempt on a real user
- Payment/checkout flow completion with real payment methods — use test-mode/sandbox payment credentials if the program provides them; if it doesn't, stop short of actually completing the transaction and report the logic flaw with a partial PoC
- Any webhook/notification trigger that would send real emails/SMS/push notifications to real users
- File upload payloads beyond proving RCE/execution — do not pivot from confirmed RCE into further lateral movement without explicit scope confirmation that post-exploitation is permitted (most programs do NOT allow this)

## 5. Out-of-Scope Logging (Don't Discard)

When recon surfaces something clearly interesting but out of current scope (an acquisition's subdomain, a third-party integration, an asset type not covered), log it rather than silently dropping it:

```json
{"asset": "legacy-admin.target.com", "reason": "not in current wildcard, found via crt.sh, appears to be same org infra", "action": "flagged, not tested", "date": "..."}
```

This becomes either a scope-expansion request to the program (some triage teams will add it if you ask) or a future lead if the program's scope changes — common after acquisitions get folded in.

## Pre-Flight Checklist (Run Before Every New Target)

- [ ] Allow-list built from the literal scope page, not inferred from company name
- [ ] Explicit exclusions cross-checked against every asset `offensive-recon` returns
- [ ] ROE forbidden-techniques list parsed and cross-checked against planned vuln-class skills
- [ ] Rate limit ceilings set at or below section 3's floor
- [ ] Destructive-action gate active — nothing in section 4's list fires without explicit confirmation
- [ ] Safe-harbor status confirmed (if a program has no explicit safe-harbor language, treat all testing as higher-risk and stay conservative on anything destructive or high-volume)
