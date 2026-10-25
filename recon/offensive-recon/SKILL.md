---
name: offensive-recon
description: "Attack surface discovery and reconnaissance for bug bounty and authorized web pentesting. Covers subdomain enumeration, historical/archived URL mining, JS recon and secret extraction, authenticated crawling, hidden parameter discovery, API/GraphQL schema recovery, cloud asset discovery, and content diffing for change detection. Use this BEFORE any vuln-class skill — most 'no bugs found' results come from under-mapped surface, not weak payloads. Run this first on every target."
version: 1.0.0
author: Fahim
license: MIT
---

# Reconnaissance — Attack Surface Mapping Methodology

## Why this comes first

If you're running SQLi/XSS/IDOR payloads and finding nothing, the bottleneck is almost never payload quality — it's that you're testing 5% of the actual attack surface. Most bug bounty programs are hunted by hundreds of people using the same default wordlists against the same obvious endpoints (`/login`, `/api/users`). The bugs that survive are in surface those people never found: old subdomains, JS-only endpoints, forgotten API versions, staging infra, params nobody fuzzes. This skill's job is to find THAT surface. Every vuln-class skill assumes you already have a URL+param pair in hand — this is how you get a long list of good ones instead of 10 obvious ones.

## Quick Workflow

1. Passive subdomain enum → merge from every source, don't trust one tool
2. Resolve + probe for alive hosts, fingerprint tech stack per host
3. Mine historical URLs (wayback/commoncrawl/gau) — old params/endpoints often still work, less tested
4. Crawl + extract JS, pull every endpoint/param/secret/key out of bundled JS
5. Diff JS files over time to catch newly-deployed (unreleased/untested) features
6. Authenticated crawl with 2+ roles to map role-gated endpoints (IDOR/auth-bypass surface)
7. Recover hidden params via mining + brute force
8. Recover API schemas (OpenAPI/GraphQL introspection) even when "hidden"
9. Check cloud/3rd-party asset leakage (buckets, subdomain takeovers, exposed repos)
10. Build a living asset inventory — rerun diffing on a schedule, new surface = new bugs before anyone else sees it

---

## 1. Subdomain Enumeration — Stack Every Source

Single-tool enum is why you overlap with every other hunter. Chain passive sources, then brute, then permute.

```bash
# Passive — merge ALL of these, dedupe at the end, not per-tool
subfinder -d target.com -all -recursive -o subfinder.txt
assetfinder --subs-only target.com > assetfinder.txt
amass enum -passive -d target.com -o amass.txt
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' > crtsh.txt
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' > certspotter.txt
curl -s "https://jldc.me/anubis/subdomains/target.com" | jq -r '.[]' > anubis.txt

# Merge + dedupe
cat *.txt | sort -u > all_subs.txt

# Brute force on top of passive (catches what CT logs/passive sources miss)
puredns bruteforce /opt/wordlists/dns/best-dns-wordlist.txt target.com -r resolvers.txt >> all_subs.txt

# Permutations off known subs (dev-api.target.com, api-v2.target.com, staging2.target.com etc.)
gotator -sub all_subs.txt -perm /opt/wordlists/dns/permutations.txt -depth 1 | dnsx -silent >> all_subs.txt

sort -u all_subs.txt -o all_subs.txt
```

Resolve + probe for alive + fingerprint in one pass:

```bash
cat all_subs.txt | dnsx -silent -a -resp | tee resolved.txt
cat all_subs.txt | httpx -silent -sc -title -tech-detect -ip -cdn -follow-redirects -o alive.txt
```

Flag anything with status 403/401 separately — those are often internal/staging apps accidentally exposed, higher bug density than the main app.

## 2. Historical / Archived URL Mining

This alone finds bugs most hunters skip because they only test live-crawled URLs. Old params, deprecated endpoints, debug routes that still work but were removed from nav.

```bash
# Pull from every archive source
cat alive.txt | waybackurls > wayback.txt
cat alive.txt | gau --threads 5 --subs > gau.txt
cat alive.txt | xargs -I{} curl -s "http://web.archive.org/cdx/search/cdx?url={}/*&output=text&fl=original&collapse=urlkey" >> cdx.txt

cat wayback.txt gau.txt cdx.txt | sort -u > all_urls.txt

# Filter to interesting extensions/patterns — these are high-signal
cat all_urls.txt | grep -Ei '\.(json|xml|yaml|yml|config|cfg|conf|env|bak|backup|old|sql|log|zip|tar|gz|7z)$' > sensitive_files.txt
cat all_urls.txt | grep -Ei '(debug|internal|admin|test|staging|dev|beta|v1|v2|api|swagger|graphql)' > interesting_paths.txt

# Pull params out for fuzzing targets later
cat all_urls.txt | grep '?' | sed 's/.*?//' | sed 's/=.*//;s/&/\n/g' | sort -u > historic_params.txt

# Check which historic URLs STILL respond (old endpoints alive and untested = gold)
cat all_urls.txt | httpx -silent -mc 200,201,204,301,302,401,403 -o live_historic.txt
```

## 3. JS Recon — Endpoints, Params, Secrets, Logic

JS is where the real API surface lives, especially SPAs. Most of the app's actual attack surface is never in a crawled HTML page — it's in bundled/chunked JS calling endpoints that are never linked anywhere.

```bash
# Collect every JS file
cat alive.txt | hakrawler -subs -u | grep '\.js' > js_urls.txt
katana -u target.com -jc -d 5 -o katana_js.txt   # -jc = crawl JS for endpoints

# Pull live JS files down for local analysis
mkdir js_files && cat js_urls.txt | while read url; do
  wget -q -P js_files "$url"
done

# Extract endpoints from JS (use multiple extractors — they catch different patterns)
for f in js_files/*; do
  python3 /opt/tools/LinkFinder/linkfinder.py -i "$f" -o cli >> endpoints_from_js.txt
done
cat js_files/* | grep -oE '"(/[a-zA-Z0-9_\-/.]+)"' | sort -u >> endpoints_from_js.txt

# Secrets/keys — AWS keys, GCP keys, Firebase, Stripe, JWT secrets, hardcoded creds
cat js_files/* | trufflehog filesystem js_files/ --json > secrets.json
cat js_files/* | grep -ioE '(api[_-]?key|secret|token|password|aws_access|private_key)[\"'\'':= ]{1,5}[a-zA-Z0-9/+_-]{16,}' > inline_secrets.txt

# Source maps — if .js.map files exist, you get near-original source (huge win)
cat js_urls.txt | sed 's/$/.map/' | httpx -silent -mc 200 -o sourcemaps.txt
# then: sourcemapper or unwebpack-sourcemap to reconstruct original tree
```

**Diff JS over time.** This is how you find bugs before anyone else: new JS deploy = new feature = new endpoint nobody has tested yet.

```bash
# Run periodically, diff against last run
diff <(cat js_files/*.js | md5sum) previous_run_hashes.txt
# or use a dedicated watcher: js-monitor / BBScope with a cron job
```

## 4. Authenticated, Multi-Role Crawling

Unauthenticated crawl misses the majority of IDOR/BOLA/privilege-escalation surface. If the program is in scope for auth'd testing, crawl with at least two accounts of different privilege levels and diff the reachable endpoint sets.

```bash
# Burp/ZAP authenticated crawl with session handling rules configured per role
# Export both crawls, diff the endpoint lists:
diff <(sort user_a_endpoints.txt) <(sort user_b_endpoints.txt)

# katana with auth header/cookie
katana -u target.com -H "Cookie: session=<low_priv_session>" -d 5 -jc -o low_priv_map.txt
katana -u target.com -H "Cookie: session=<admin_session>" -d 5 -jc -o admin_map.txt
diff low_priv_map.txt admin_map.txt   # endpoints only admin can reach = your IDOR/priv-esc test list
```

Every endpoint only reachable by role B is a candidate: can role A reach it directly by guessing the URL/ID? That's the entire IDOR skill's input list — generate it here, not by guessing.

## 5. Hidden Parameter Discovery

Most apps have far more params than the UI exposes (debug flags, feature flags, admin overrides).

```bash
# Mine from JS + historic URLs (step 2/3) first — free, high signal
# Then brute force against known endpoints
arjun -u https://target.com/api/endpoint -oJ arjun_out.json -t 10

# x8 is faster for large param wordlists against many endpoints
x8 -u https://target.com/api/endpoint -w /opt/wordlists/params/burp-parameter-names.txt

# Common high-value hidden params worth always testing:
# debug, test, admin, internal, bypass, skip_auth, is_admin, role,
# redirect, return_url, next, callback, format, output, source, env
```

## 6. API / GraphQL Schema Recovery

```bash
# REST — check for exposed spec even when not linked in UI
for path in /swagger.json /swagger/v1/swagger.json /api-docs /api/swagger.json \
            /openapi.json /v2/api-docs /api/v1/swagger.json /.well-known/openapi.json; do
  httpx -silent -u "https://target.com$path" -mc 200
done

# GraphQL — introspection often still enabled even when "disabled" in prod UI
curl -s -X POST https://target.com/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name,fields{name}}}}"}' | jq

# If introspection is blocked, clairvoyance/graphql-cop can still reconstruct
# schema via error-based field guessing
python3 clairvoyance.py -o schema.json https://target.com/graphql
```

## 7. Cloud & Third-Party Asset Leakage

```bash
# S3/GCS/Azure bucket discovery from company name + permutations
s3scanner scan -bucket-file bucket_perms.txt
cloud_enum -k target -t 5

# Subdomain takeover check — dangling CNAMEs pointing at unclaimed cloud resources
subzy run --targets all_subs.txt --concurrency 50

# Exposed git repos
cat alive.txt | sed 's/$/\/.git\/config/' | httpx -silent -mc 200 -o exposed_git.txt
# if found: git-dumper to pull full history, grep history for secrets/old endpoints

# GitHub/GitLab recon for leaked internal code, tokens, infra references
trufflehog github --org=target-company --json > github_secrets.json
github-subdomains -d target.com   # subdomains mentioned in public repos/code
```

## 8. Build a Living Inventory, Not a One-Shot Scan

A single recon pass gives you a snapshot that decays the moment the app redeploys. The actual edge over other hunters is re-running steps 1–3 on a schedule and diffing:

```bash
# cron job skeleton — new subdomain, new JS, new endpoint = alert
0 */6 * * * /opt/recon/run_subs.sh target.com | diff - /opt/recon/last_subs.txt && notify
0 */4 * * * /opt/recon/pull_js.sh target.com | diff - /opt/recon/last_js_hashes.txt && notify
```

New asset = untested asset = first-mover advantage on the bug before triage teams or other hunters even see it exists.

---

## Output: What You Hand to the Vuln-Class Skills

By the end of this skill you should have, per target:
- `alive.txt` — all live hosts, fingerprinted
- `live_historic.txt` — old-but-still-live endpoints (high value, low competition)
- `endpoints_from_js.txt` + `secrets.json` — JS-derived API surface + any leaked creds/keys
- `admin_map.txt` vs `low_priv_map.txt` diff — your IDOR/priv-esc candidate list
- `arjun_out.json` / hidden params per endpoint — your injection fuzzing targets
- `schema.json` (GraphQL) / `swagger.json` (REST) — full parameter/type map for API skills
- bucket/takeover/git-exposure findings — often instant, high-severity, zero payload-crafting needed

Feed these into `offensive-sqli`, `offensive-idor`, `offensive-api-abuse`, etc. — now you're fuzzing 10x the surface with the same payload library, which is what actually moves you off 0 bugs.
