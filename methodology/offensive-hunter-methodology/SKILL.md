---
name: offensive-hunter-methodology
description: "Session-level hunting methodology and mindset for bug bounty, synthesized from well-known practitioner approaches (Jason Haddix's Bug Hunter's Methodology, NahamSec's automation-driven recon, Tomnomnom's unix-pipe tool chaining, zseano's developer-mindset logic-bug hunting, and the A→B→C bug-chaining approach popularized by EdOverflow/Inti). Covers wide-vs-narrow scope strategy, mind-mapping targets, when to go manual vs automated, how to find logic bugs tools can't find, and chaining low-severity bugs into high-payout reports. Use at the START of a session or when switching targets to decide HOW to spend your time, before running any vuln-class skill."
version: 1.0.0
author: Fahim
license: MIT
---

# Hunter Methodology — How To Actually Spend Your Time

Tools and payload lists (the other skills in this set) answer "how do I test for X." This skill answers "what should I be doing right now, and why am I not finding anything." That second question is usually the real bottleneck.

## Wide Recon vs. Narrow Recon — Pick Your Mode Per Session

This split (popularized by Jason Haddix's long-running "Bug Hunter's Methodology" talks) is the single highest-leverage mental model for where to spend time:

- **Wide recon** = maximize the number of assets you know about for a target (subdomains, acquisitions, cloud infra, forgotten apps). This is `offensive-recon` sections 1, 2, 7. Do this when a program is new to you, has a large/wildcard scope, or you've hit a wall on the main app.
- **Narrow recon / application analysis** = go deep on ONE asset: every endpoint, every role, every state transition, every piece of business logic. This is `offensive-recon` sections 3–6 applied to a single app, then the vuln-class skills.

Pick ONE mode per session and commit. Switching between them constantly is why hunters burn hours and find nothing — you end up doing a shallow version of both.

**Decision rule:** if you don't have at least 20 "interesting" assets/endpoints logged for a target yet, you're still in wide mode — stop trying to exploit things and keep mapping. If you have more surface than you can test in a week, you're in narrow mode — stop collecting and start testing what you already have.

## Track Your Work Like a Map, Not a Todo List

Haddix's approach: build a literal mind-map per target (tools: XMind, Obsidian, or even a structured directory tree), with one node per host/subdomain, and inside each node the same fixed set of questions every time: what tech stack, what auth model, what's in the JS, what params has it got, what's been tried already, what's the verdict. The point isn't the tool — it's that you ask every target the *same checklist* instead of improvising per-target, so nothing gets skipped and you can resume a target months later without re-doing work.

Minimum viable version for an AI-agent-driven workflow: one state file per target (JSON/markdown) with fields `{host, tech_stack, auth_model, endpoints[], params[], tested[], findings[], last_scanned}`. Update it every session — this is what makes re-running recon (scheduled diffing, see `offensive-recon` section 8) actually valuable instead of starting from zero each time.

## Automate the Boring Part, Think Manually for the Rest

NahamSec's recurring point, and Tomnomnom's whole body of work: the discovery phase (subdomains, alive hosts, URL collection, basic param/vuln-class signal via tools like `gf` patterns) should be a fully automated pipeline you kick off and walk away from — piping tool output straight into the next tool, logging everything, re-running on a cron. You should almost never be manually running `subfinder` then manually copy-pasting into `httpx` then manually copy-pasting into the next tool — chain it in one script, once, and reuse it on every target.

What does NOT get automated: actually reading the responses, understanding what a feature does, and deciding what's interesting. Automation gets you volume; it doesn't get you judgment. The hunters who only run automated scanners and report whatever the scanner flags are competing with every other hunter running the same scanner against the same target — that's the "0 bugs, everyone's using AI now" problem in reverse: the win isn't using more automation than everyone else, it's using automation to buy yourself time to do the manual thinking nobody else bothers with.

## Finding Logic Bugs — Tools Can't Find These, Only You Can

This is zseano's and EdOverflow's territory, and it's where scanner-equipped competitors can't follow you: logic bugs, broken access control, and business-logic flaws don't match a payload signature. The method:

1. **Use every feature as intended first.** Create an account, go through onboarding, use every button, every form, every settings page — as a normal user would. You cannot find a broken workflow if you don't know what the intended workflow is.
2. **Ask "what did the developer assume?" at every step.** Every form field, every state transition, every multi-step flow (checkout, password reset, invite flow, org/team membership, coupon/promo codes) was built by someone who made assumptions about order of operations, who can reach this state, and what the client is allowed to lie about. Your job is to violate exactly one assumption at a time: skip a step, replay a step, do steps out of order, do a step twice, do a step as a different user, do a step after the "end" state.
3. **Specialize instead of spraying.** The "choose one bug class, read the spec, go deep" approach (attributed to researchers like Nicolas Grégoire) consistently outperforms "run every scanner against every target." Pick one mechanism per target session — password reset, OAuth flow, file sharing/permissions, payment/coupon logic, GraphQL mutations — read how it's *supposed* to work (docs, RFC, competitor implementations), then go find where this specific target's implementation deviates.
4. **Diff behavior, not just responses.** Two accounts, two tabs, two tokens. Do the same action as both, compare side by side. Most access-control and logic bugs are found by diffing two parallel sessions, not by staring at one.

## A→B→C Bug Chaining — Why Single Low-Sev Reports Underpay

A pattern that shows up repeatedly in high-payout writeups: a hunter finds a low/info-sev bug (an open redirect, a verbose error leaking an internal hostname, a CORS misconfig, a self-XSS, an IDOR on a low-value object) and instead of reporting it alone, uses it as a stepping stone:

- Open redirect → feeds OAuth `redirect_uri` bypass → account takeover
- Self-XSS → combined with CSRF or clickjacking to force it onto another user → stored/reflected-equivalent impact
- Verbose error/stack trace → reveals internal hostname/path → targets SSRF or internal-only endpoint
- Low-value IDOR → same access-control bug often exists on a high-value object type in the same codebase — test the pattern against every object type, not just the one you found it on
- CORS misreflection → chained with an authenticated endpoint that returns sensitive JSON → full account data exfil

**Practical rule:** every time you find ANY bug, before writing the report ask "what does this let me reach that I couldn't reach before?" and spend 15-30 minutes trying to chain it up before reporting it standalone. Triage teams downgrade isolated low-sev reports constantly (your own stated problem); the same finding written as step 1 of a chain with real impact gets paid and taken seriously.

## Session Checklist

Before starting any target, decide and write down:
- [ ] Wide or narrow mode this session?
- [ ] If narrow: which single mechanism am I specializing in today?
- [ ] Is my recon pipeline from `offensive-recon` already run and logged, or do I need to run it first?
- [ ] What's my mind-map/state file for this target — new or resuming?
- [ ] After finding anything: have I spent 15+ minutes trying to chain it before reporting?
