# CyberGuard - Phishing Detection & URL Security Analyzer

CyberGuard analyzes URL **text only** using a Python Flask backend and the existing responsive HTML/CSS/vanilla JavaScript dashboard. It returns a transparent heuristic risk score, classification, and explanations. It never visits submitted websites, resolves their domains, or uses external security APIs.

## Features

- HTTP/HTTPS URL validation and transparent 0-100 heuristic scoring with Low/Medium/High classifications.
- Explanations for IP hosts, long URLs, excessive subdomains, suspicious keywords/encoding, punycode, lookalike indicators, and HTTP usage.
- Four responsive views (Dashboard, URL Scanner, Security Analytics, and Scan History) with a shared navy/cyan theme, accessible form errors, loading states, and duplicate-submission prevention.
- Local-development opt-in SQLite history with sanitized origins, pagination, newest-record refresh, saved-record statistics, and confirmed deletion. Public deployment disables all persistent history and deletion.
- Bounded JSON requests, parameterized SQL, literal text rendering, same-origin API access, and mode-specific Host validation.
- Public-mode HTTPS enforcement, Redis-backed scan quotas, security headers, and a production-only Linux Gunicorn entry point.

## Technologies

| Layer | Technologies |
| --- | --- |
| Frontend | HTML5, CSS3, vanilla JavaScript, Fetch API |
| Backend | Python 3.10+, Flask 3.1.x; Gunicorn 26.x on Linux |
| Storage | SQLite for local history only; Redis for public rate-limit counters only |
| Abuse prevention | Flask-Limiter, per-client and aggregate scan quotas |
| Tests | Python unittest; Node.js 22+ and Chrome/Chromium/Edge for browser integration |

Local SQLite requires no separate service and the frontend requires no npm dependencies. Production requires a private Redis service; submitted URLs and analysis results are not stored there.

## Installation and Local Setup

Use Python 3.10 or newer. From this repository in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:CYBERGUARD_ENV = 'development'
.\.venv\Scripts\python.exe app.py
```

Open **http://127.0.0.1:5000**. Keep the server terminal running; press Ctrl+C to stop it. Opening `index.html` directly or serving it with a static HTTP server cannot run the Flask API. If `python` is unavailable, try `py -3` for the first command or use the full path to your installed Python executable.

For macOS/Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python app.py
```

If port 5000 is occupied, run `.\.venv\Scripts\python.exe -m flask --app app run --host 127.0.0.1 --port 5001` and open http://127.0.0.1:5001 instead.

Access the app using `localhost` or `127.0.0.1`; other Host values are rejected. Stop and restart a running Flask process after backend changes. The server runs without automatic reload or debug mode.

Development is the default mode and keeps the local SQLite features. Install updated requirements and restart Flask after this upgrade so `/api/config` is available. Windows installs Flask-Limiter but skips Gunicorn; Linux deployment uses the same source without Windows-specific paths.

The four views share one Flask-served frontend and use bookmarkable links: `/#dashboard`, `/#scanner`, `/#insights` (Security Analytics), and `/#history`. Browser Back and direct-link reloads work without new backend routes. Switching views retains the current analysis and save-history selection; reloading resets the selection to off. Dashboard totals and Analytics risk distribution use the same saved-record statistics.

All views use the theme and spacing variables in `style.css`, shared navigation/footer, and reusable panel, button, badge, and table styles. Icons are bundled locally from Lucide, with attribution in `docs/LUCIDE-LICENSE.txt`; no CDN or runtime icon dependency is required.

## Features and Scoring

Scores sum the triggered rule weights, capped at 100. Low = 0-29, Medium = 30-59, High = 60-100. These are configurable-code heuristics, **not probabilities of phishing**. A score of zero means no configured rules triggered, not that the website is safe.

| Rule | Points | Trigger |
| --- | ---: | --- |
| IP address | 25 | IPv4 or IPv6 host instead of a domain |
| URL length | 10 / 20 | More than 100 / 200 characters; only the higher weight applies |
| Excessive subdomains | 15 | More than 3 estimated subdomains (host labels minus 2) |
| Suspicious keywords | 5 each, max 20 | Unique matches in once-decoded URL text: login, verify, secure, account, update, password, bank, wallet, gift, free |
| Unusual encoding | 20 | At least 5 percent escapes, nested encoding, or encoded delimiters/control characters |
| Punycode | 15 | Internationalized `xn--` host label, including Unicode input converted by IDNA |
| Lookalike indicators | 20 | Mixed Latin/Cyrillic/Greek scripts or selected character substitutions resembling a limited brand list |
| HTTP scheme | 10 | Text specifies HTTP instead of HTTPS; no certificate validation |

URL input may omit the scheme; HTTPS is assumed. HTTP/HTTPS, valid domains, IPv4/IPv6, localhost, and optional ports 1-65535 are accepted. Embedded credentials (including user-info introduced by `@`) are rejected before analysis or storage. `@` in a path is allowed. The original URL text and percent encoding are preserved in the current analysis response. Each triggered rule runs once and includes its point contribution. Dashboard statistics now come from saved database records only; unsaved scans do not change them.

## Production Deployment

Use a Linux host or Linux container with a supported stable Python release, a valid TLS certificate, one reverse proxy, and a private Redis service. Do not use `python app.py`, `flask run`, debug mode, or a reloader for public hosting. `wsgi.py` refuses to start unless production mode is explicitly selected. Gunicorn binds to loopback without `PORT`, or all interfaces on the supplied platform `PORT`; never expose its port directly to untrusted clients when proxy trust is enabled. See the [Flask Gunicorn guidance](https://flask.palletsprojects.com/en/stable/deploying/gunicorn/).

### Environment Configuration

| Variable | Development | Production |
| --- | --- | --- |
| `CYBERGUARD_ENV` | `development` (default) | Must be `production` |
| `CYBERGUARD_PUBLIC_ORIGIN` | Not used | Required HTTPS origin, such as `https://cyberguard.example`, without a path or credentials |
| `CYBERGUARD_PROXY_HOPS` | `0` | `1` only behind one isolated proxy; otherwise `0` |
| `CYBERGUARD_RATE_STORAGE_URI` | Not needed; limits disabled | Required `redis://` or `rediss://` URI for a dedicated private Redis service/database |
| `CYBERGUARD_DATABASE` | Optional SQLite path | Ignored; no SQLite initialization, reads, writes, or deletion |

Production settings force debug off, the 16 KiB body limit, history off, and rate limiting on. Invalid/incomplete configuration fails startup. In-memory quotas are allowed only in automated test configuration, never in a real production startup. Production has no persistent scan data and does not mount or use `instance/`.

### Linux Startup

From the source directory, after provisioning private Redis and TLS:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
export CYBERGUARD_ENV=production
export CYBERGUARD_PUBLIC_ORIGIN=https://cyberguard.example
export CYBERGUARD_PROXY_HOPS=1
export CYBERGUARD_RATE_STORAGE_URI=redis://127.0.0.1:6379/5
.venv/bin/gunicorn --config gunicorn.conf.py --check-config wsgi:application
.venv/bin/gunicorn --config gunicorn.conf.py wsgi:application
```

Replace the example hostname and Redis URI with your infrastructure values. Keep Redis private, authenticated where appropriate, and protected by TLS (`rediss://`) when traffic crosses hosts. Store credentials in the hosting platform's secret manager or a protected service environment file, never in source control or shell commands retained in public logs. All workers/replicas must share the same dedicated Redis quota database. Counter keys contain client IPs and counts, not submitted URLs; configure Redis access/retention accordingly. Do not share or clear this Redis database with unrelated applications.

Run Gunicorn under a non-root service account with a service manager and restricted file permissions. The provided configuration uses one worker/two threads, bounded request headers, worker timeouts/recycling, no reload/debug, and no access log containing request URLs. This is a conservative starting point for Render Free's 512 MB instance, not a measured memory or throughput guarantee. Adjust capacity only after load testing. Gunicorn's automatic forwarded-header interpretation is disabled; `ProxyFix` handles only the explicitly configured single-hop `X-Forwarded-For` and `X-Forwarded-Proto` values.

### Render Configuration

- Build command: `pip install -r requirements.txt` using a supported stable Linux Python release.
- Start command: `gunicorn --config gunicorn.conf.py wsgi`. The module exports `app` for Gunicorn's module-only target and keeps `application` as an alias to the same production Flask instance. The explicit `wsgi:application` target and configured `wsgi_app` also remain supported.
- Render supplies `PORT`; when present, Gunicorn binds to `0.0.0.0:$PORT`. Invalid port values fail startup. Without `PORT`, it retains the loopback binding for the standalone Nginx example.
- Set `CYBERGUARD_ENV=production`, `CYBERGUARD_PUBLIC_ORIGIN=https://YOUR-SERVICE.onrender.com` (or the single canonical custom domain, without a trailing slash), and `CYBERGUARD_RATE_STORAGE_URI` to your dedicated private Redis connection URI in Render's environment settings. Never commit Redis credentials.
- Set `CYBERGUARD_PROXY_HOPS=1` only after verifying that the isolated platform ingress supplies trustworthy rightmost client-IP and HTTPS values. This trusts one value of each header, not an arbitrary proxy chain. A multi-value `X-Forwarded-For` ending in an internal proxy address would merge client quotas. Do not increase trust or accept the first address blindly; request a topology-specific review if Render's actual chain differs.
- Gunicorn must remain unreachable by untrusted clients except through the platform ingress. `X-Forwarded-Host` and `X-Forwarded-Port` remain ignored; Host and exact Origin restrictions are unchanged. Do not use wildcard Host/CORS settings to fix platform routing.
- Before launch, verify Linux startup, memory use under load, live Redis quota behavior, preserved canonical Host, HTTPS detection, and spoofed forwarding-header handling through Render. A plain HTTP health probe will fail the HTTPS requirement; use the platform's TCP check unless a trusted HTTPS-aware HTTP probe is verified.

See [Render port binding requirements](https://render.com/docs/web-services#port-binding) and [compute plans](https://render.com/docs/compute-plans). The local Nginx template is an alternative deployment setup, not a requirement to install Nginx on Render.

`deploy/nginx.conf.example` is a reverse-proxy template, not an installed configuration. Replace its hostname and certificate paths, add your platform's default-host rejection/TLS renewal policies, and validate with `nginx -t` before enabling it. Only expose proxy ports 80/443; firewall Gunicorn and Redis from external clients. The proxy must overwrite (not append) forwarding headers, preserve the Host, and enforce body/time/connection limits. Never use `CYBERGUARD_PROXY_HOPS=1` if clients can reach Gunicorn directly. Other proxy topologies require a separately reviewed configuration. [Flask warns that incorrect ProxyFix trust is a security issue](https://flask.palletsprojects.com/en/stable/deploying/proxy_fix/).

### Public Security and Privacy

- `POST /api/scan`: 10 requests/minute and 120/hour per client IP, plus 1000/hour across the deployment. Invalid scan attempts count too. Requests exceeding a quota receive JSON status 429 with `Retry-After`; the analyzer does not run.
- Redis failure rejects scans with a safe service error; there is no unmetered in-memory fallback. These quotas use shared Redis counters rather than per-worker state. See [Flask-Limiter storage guidance](https://flask-limiter.readthedocs.io/en/stable/).
- `/api/config` exposes only `history_enabled`. The frontend disables saving, refreshing, deletion, and saved-record analytics in public mode while preserving all four views and URL-text scanning.
- GET/DELETE `/api/history` and `save_history: true` receive 403 in production. This remains enforced even if a caller modifies the checkbox or bypasses the frontend.
- HTTPS, the exact configured public Origin, and the configured Host are enforced. CSP, HSTS (one year, without automatic subdomain/preload coverage), frame denial, MIME sniffing protection, referrer policy, resource isolation, and disabled camera/microphone/geolocation permissions apply.
- No submitted website is fetched, resolved, or executed. URLs are processed transiently and returned to the requesting browser. Redis stores quota counters only; no production SQLite history exists. Do not enable body capture, request mirroring, or sensitive request logging in proxies/APM tooling.

### Pre-Launch Verification

On the intended Linux staging environment, run both test suites, Gunicorn's config check, and `nginx -t`. Through the real HTTPS proxy, verify `/api/config` reports `false`, valid scans return scores, the 11th same-IP scan in a minute returns 429, and saving/history/deletion return 403. Stop Redis temporarily and verify scans fail closed. Confirm rate limits are shared across workers/replicas, different real client IPs are correctly distinguished, and spoofed client forwarding headers cannot bypass quotas. Test certificate renewal and verify no application/Redis port is publicly reachable. Unit/browser tests do not replace this infrastructure validation.

## SQLite History Setup and Usage (Local Only)

SQLite is included with Python; no new packages or separate database server are needed. Flask automatically creates `instance/scans.sqlite3` and its schema on startup. This directory, the database, and SQLite sidecar files are excluded from Git. `CYBERGUARD_DATABASE` can override the database path before startup, for example `$env:CYBERGUARD_DATABASE = 'instance/custom-history.sqlite3'` in PowerShell. Keep custom databases and backups in ignored directories.

The **Save Scan to History** checkbox appears directly below the URL input and Scan URL button and defaults to unchecked on each page load. Only requests with the JSON boolean `save_history: true` insert a record; omitted/false values never save. Enabling saving does not retroactively store earlier scans. Each saved record contains a UTC timestamp, a sanitized normalized address, risk score/level, and generated rule explanations. Times appear in the browser's local timezone.

For privacy, stored addresses contain only the lowercased scheme, canonical host (IDNA for Unicode domains), and non-default port. **All paths, query strings, and fragments are removed**, because paths can also contain password-reset and authentication tokens. For example, `https://Example.com:443/reset/private-token?password=secret#session` is stored as `https://example.com`. The risk score and reasons describe the original input, including discarded components; reasons use fixed rule templates and keyword names, never raw parameter values. Consequently, identical stored addresses can have different scores.

The Scan History table lists newest scans first, with date, URL, score, level, and expandable reasons. It uses 20 records per page. Refresh History retrieves uncached saved records and statistics and returns to the first page so the latest saves are visible. **Delete History** requires confirmation, removes all saved scans for this server, and resets statistics. Cancelling leaves records intact. Disabling saving affects future scans and does not delete existing history.

The four statistics report total saved scans, average saved score, saved High risk scans, and saved Medium/High risk scans across all pages. Empty history yields zeros; a history-loading error displays unavailable statistics rather than stale values.

### History Privacy Limitations

The SQLite file is plaintext and history is shared by all users who can reach this server; there is no account authentication or per-user isolation. Hostnames, ports, timestamps, risk indicators, and keyword names may themselves be sensitive. Avoid putting secrets in hostnames or submitting sensitive addresses at all. The original input is still processed in server memory and returned to the current browser for analysis, but it is not saved as a full URL. Normal API access logs do not include JSON bodies.

Deletion uses SQLite secure-delete mode to clear deleted database content, but cannot guarantee erasure from backups, copied files, operating-system caches, or storage snapshots. No automatic retention expiry or encrypted storage is implemented. Keep the app bound to loopback for personal local use; protect the database file and its backups.

## API

`POST /api/scan` accepts an `application/json` object with a `url` string and optional boolean `save_history`:

```json
{"url": "https://example.com/login", "save_history": false}
```

Successful responses contain `url`, `hostname`, `risk_score`, `risk_level`, `reasons` (objects with `rule`, `points`, `explanation`), `raw_score`, `score_cap`, `analysis_type`, `limitation`, and `history_saved`. Local saved results also contain `saved_scan_id` and sanitized `stored_url`. Errors return `{"error": "..."}` with status 400 for invalid JSON/inputs, insecure production requests or untrusted hosts, 403 for disallowed origins or disabled public history, 413 for oversized requests, 415 for unsupported content types, 429 for scan quotas, 503 for unavailable history/rate-limit storage, or 500 for an unexpected internal failure.

`GET /api/config` returns `{"history_enabled": true}` locally or `{"history_enabled": false}` publicly. It never exposes Redis credentials or internal file paths.

- `GET /api/history?limit=20&offset=0` returns `scans`, `total`, `statistics`, `limit`, and `offset`. Limit must be 1-100; offset must be 0-1000000. Unknown or repeated query parameters are rejected. Each scan contains `id`, `scanned_at`, `normalized_url`, `risk_score`, `risk_level`, and `reasons`.
- `DELETE /api/history` requires `Content-Type: application/json` and the exact body `{"confirm": true}`. It returns `{"deleted": N}`. Confirmation is required in both the UI and API.

Database input values and pagination use SQLite parameter placeholders, not string-built SQL. The database module derives analysis from validated URL text, rather than accepting arbitrary stored scores or explanations.

Requests are limited to 16 KiB and URL input to 4096 characters. Spaces, control characters, backslashes, embedded credentials, malformed hosts/ports, unsupported schemes, and malformed percent encoding are rejected. Only frontend assets are exposed; repository source files and databases are not served. Output is inserted using text nodes rather than HTML. The browser sends URL text to the same-origin backend, never to the submitted address.

The Flask Host allowlist accepts only `localhost` and `127.0.0.1`. An explicit browser Origin must exactly match the request scheme, hostname, and port. For example, a page served at `http://localhost:5000` uses that same origin for its API calls; `http://127.0.0.1:5000` is a different origin and is not an interchangeable API target. Both hostnames work when the frontend and API use the same one. Foreign and `null` Origins, cross-site fetches, and cross-origin same-site requests remain rejected; no CORS access is enabled.

Same-origin history GET/HEAD requests may omit Origin. A user-initiated top-level GET/HEAD navigation to the history JSON document is also permitted without Origin when browser metadata indicates `navigate`, `document`, and `Sec-Fetch-User: ?1`; this exception never applies to writes, iframes, or ordinary cross-origin fetches. Origin-free browser writes need same-origin Fetch Metadata or a matching Referer; a foreign/malformed Referer is rejected when Origin is absent. Trusted local CLI requests without browser provenance headers remain supported, so these checks are not authentication.

Frontend API calls use relative URLs with `mode: "same-origin"`, credentials omitted, redirects disallowed, and a same-origin referrer policy. The server also sets `Referrer-Policy: same-origin`, retaining local provenance without sending referrers to other origins. Restart Flask after backend changes and hard-refresh the frontend. Use the Flask URL, not a static Live Server or `file:` preview; changing hostname or port on an API request does not make it same-origin.

## Limitations

**Heuristic analysis cannot guarantee that a website is safe or malicious.** False positives and false negatives are expected. Legitimate URLs often use long paths, authentication keywords, IP addresses, and internationalized domains.

There are no DNS, reputation, certificate, redirect, attachment, or webpage checks. Subdomain counts are approximate because no public suffix list is used. Lookalike checks use selected digit/Cyrillic/Greek substitutions and the names paypal, google, microsoft, apple, amazon, and facebook; they do not detect every homograph or establish brand ownership. Python's standard-library IDNA codec can differ from browser domain parsing; unusual legacy numeric IP spellings are not supported. Percent decoding is bounded to one pass for keyword analysis; nested encoding is flagged separately. The scoring weights are transparent hand-written rules, not a validated machine-learning model.

The development server binds to loopback with debug mode off. Production uses the Linux Gunicorn entry point behind HTTPS and requires operational review of the actual proxy/Redis deployment. There are no external website/security API calls; Redis is trusted infrastructure used only for quota counters. Installation downloads dependencies from PyPI.

There is no authentication or CAPTCHA. Public IP quotas are not an identity system: shared NAT users share limits, distributed attackers can exhaust the aggregate quota, and fixed windows permit boundary bursts. Add edge/WAF connection limits and DDoS protection; app limits cannot stop traffic before it reaches the server. Redis must be monitored, patched, and isolated; its outage intentionally stops scanning. TLS/proxy trust, hosting access controls, and secret management remain deployment responsibilities.

Local history remains shared, unencrypted, and without storage quotas or retention expiry; do not expose development mode publicly. Anyone with local filesystem access can read its SQLite file. Timeouts do not prove a local save/delete did not complete. Dependency ranges are not a complete reproducible lockfile; freeze/audit dependencies for your deployment and keep them updated. Windows tests do not establish Linux Gunicorn/Redis/proxy integration, Firefox/Safari, or every Python version's compatibility. This is not a penetration-test or CVE-audit certification.

Framework references: [Flask request-size configuration](https://flask.palletsprojects.com/en/stable/config/#MAX_CONTENT_LENGTH), [Flask Host validation](https://flask.palletsprojects.com/en/stable/web-security/#host-header-validation), [Flask testing documentation](https://flask.palletsprojects.com/en/stable/testing/), and [Python SQLite parameterized queries](https://docs.python.org/3/library/sqlite3.html#how-to-use-placeholders-to-bind-values-in-sql-queries).

## Tests

Run the automated detector and API tests from the repository root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

On macOS/Linux, replace the executable with `.venv/bin/python`. Tests use temporary isolated databases and safe example domains/documentation IPs; they never fetch submitted URLs or alter your saved history. They cover detector rules, thresholds, validation, database initialization/persistence, opt-in, sanitization, secret exclusion, statistics, pagination, confirmation/deletion, storage failures, and API errors. A network-blocking test prevents DNS/socket use by the detector.

Security regression tests also cover both local hostnames on port 5000, missing Origin on safe requests, exact scheme/host/port checks, forged Host headers, foreign/null Origins, cross-site/same-site Fetch Metadata, referer fallback, SQL injection text, secret exclusion, and private-file/path-traversal requests. Browser tests inspect actual Origin/Fetch Metadata headers and user-initiated history-document navigation, and check that URL, history-reason, and API-error XSS payloads remain text and cannot create executable DOM elements.

Optional browser integration tests require Node.js 22+ and installed Chrome/Chromium (or Edge). After installing the project's `.venv` requirements, run:

```powershell
node tests/browser_test.cjs
```

To repeat the browser suite using `localhost` rather than `127.0.0.1`:

```powershell
$env:CYBERGUARD_TEST_HOST = 'localhost'
node tests/browser_test.cjs
Remove-Item Env:CYBERGUARD_TEST_HOST
```

No npm install or running server is needed. Set `BROWSER_PATH` if your browser is in a custom location. Tests start their own local Flask server on an available port with a temporary database, exercise opt-in saving, privacy, statistics, confirmation/cancellation/deletion, validation, loading/error recovery, and all four views at desktop/tablet/mobile widths, then close the server and browser. They also verify theme colors, active navigation, risk badges, analytics distribution, preserved scan state, direct-link reloads, browser Back, Escape navigation, and reduced motion. They launch a temporary headless browser with its sandbox disabled for trusted local automation. They do not delete or write to your normal history database.

For a manual integration check, scan `https://example.com` (Low, 0), `http://192.0.2.1/login` (Medium, 40), and `http://a.b.c.d.paypa1.example/login/verify/password/account/%2540` (High, 85). Try `not-a-url` or `https://user:secret@example.com` for an inline validation error. The entered addresses are never visited.

To test saving manually, enable **Save Scan to History** and scan `https://example.com/reset/test-token?password=test-secret#test-fragment`. The history table must show only `https://example.com`, while its score still accounts for the original URL. Disable saving and scan again; the saved count must stay unchanged. Click Refresh History to retrieve the latest saved records. Refresh the page: history persists, but the checkbox resets to off. Test Delete History cancellation first, then confirm deletion only when you intend to clear your saved records.

If the option is missing, open the app through its running Flask server (not a `file:` URL or static preview), and hard-refresh the browser with Ctrl+F5. "No saved scans" is expected until a successful scan has been submitted with saving enabled. Changing the checkbox after a scan does not save that earlier result; submit another scan after enabling it.

Production tests exercise disabled SQLite access, forced security settings, HTTPS/Host/Origin enforcement, request limits, per-IP/aggregate quotas, forwarding-header spoofing, trusted-proxy behavior, limiter outage, and no outbound URL/DNS access. They use in-memory test counters, not a live Redis service. Browser tests simulate the public capability response while exercising actual UI scans, navigation, disabled history controls, and absence of history requests; backend production enforcement is separately tested.

Deployment-preparation validation on 2026-10-13: 69 backend tests (17 production-specific) and 142 in-page browser assertions passed on each local hostname, plus public-mode UI, navigation, and request-header checks. JavaScript syntax, `pip check`, and Git whitespace checks passed. Linux Gunicorn, real Redis, TLS certificates, and the proxy template still require validation on the intended hosting platform before launch. No deployment is performed by these tests.

## Screenshots

These screenshots use only isolated test fixtures and documentation IP addresses, not personal scan history.

| View | Desktop (1440px) | Mobile (390px) |
| --- | --- | --- |
| Dashboard | [Desktop dashboard](docs/screenshots/dashboard-1440.png) | [Mobile dashboard](docs/screenshots/dashboard-390.png) |
| Scanner | [Desktop scanner](docs/screenshots/scanner-1440.png) | [Mobile scanner](docs/screenshots/scanner-390.png) |
| Security Analytics | [Desktop analytics](docs/screenshots/insights-1440.png) | [Mobile analytics](docs/screenshots/insights-390.png) |
| Scan history | [Desktop history](docs/screenshots/history-1440.png) | [Mobile history](docs/screenshots/history-390.png) |

![CyberGuard desktop URL scanner](docs/screenshots/scanner-1440.png)

Regenerate screenshots using the isolated browser tests:

```powershell
$env:CYBERGUARD_SCREENSHOT_DIR = 'docs\screenshots'
node tests/browser_test.cjs
Remove-Item Env:CYBERGUARD_SCREENSHOT_DIR
```

## Before Publishing Source

The ignore rules exclude `.venv`, bytecode caches, `instance/`, SQLite `.db`/`.sqlite`/`.sqlite3` files and sidecars, `*.log`, `.env` and `.env.*`, `.envrc`, local AWS credentials, and private `.key`/`.pem` files. Ignore rules do not protect files already tracked by Git or arbitrary secret filenames.

Check the exact files before staging:

```powershell
git status --short --untracked-files=all
git ls-files -ci --exclude-standard
git diff --check
```

The review found no tracked runtime artifacts or obvious private-key/access-token patterns in source candidates. Only source files, tests, documentation, the existing license, and reviewed fixture screenshots are intended for publication. Runtime databases, logs, `.venv/qa` screenshots, and environment files are unnecessary/sensitive artifacts and must stay excluded. This is a working-tree review, not a complete secret scan of Git history. No commit, push, deployment, or publication is performed by setup or tests.

## Project Files

- `app.py`: Flask API, local serving, request limits, and error handling.
- `phishing_detector.py`: URL validation, rules, and scoring.
- `database.py`: SQLite initialization, sanitized storage, history, statistics, and deletion.
- `instance/scans.sqlite3`: local generated history database, excluded from Git.
- `config.py`: validated environment modes and production defaults.
- `wsgi.py`, `gunicorn.conf.py`: production-only entry point and bounded Linux WSGI defaults.
- `deploy/nginx.conf.example`: HTTPS reverse-proxy template requiring infrastructure-specific configuration.
- `requirements.txt`: Flask, Flask-Limiter/Redis and Linux-only Gunicorn dependency ranges.
- `index.html`, `style.css`, `script.js`: existing interface and API integration.
- `tests/`: automated backend tests and optional browser integration tests.
