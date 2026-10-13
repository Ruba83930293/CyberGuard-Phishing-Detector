// Optional integration tests: Node.js 22+ and installed Chrome/Chromium; no npm packages.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");

let baseUrl;
let testServer;
const browserPath = process.env.BROWSER_PATH || [
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "/usr/bin/chromium", "/usr/bin/google-chrome"
].find((candidate) => fs.existsSync(candidate));
assert(browserPath, "Set BROWSER_PATH to an installed Chrome/Chromium executable.");
const profile = fs.mkdtempSync(path.join(os.tmpdir(), "cyberguard-browser-"));
const browser = spawn(browserPath, [
    "--headless", "--no-sandbox", "--disable-gpu", "--disable-software-rasterizer",
    "--disable-background-networking", "--no-first-run", "--no-default-browser-check",
    "--remote-debugging-port=0", `--user-data-dir=${profile}`, "about:blank"
], { stdio: "ignore", windowsHide: true });
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let socket;
let id = 0;
const pending = new Map();
const requests = [];
const requestDetails = new Map();
const requestHeaders = new Map();
const responseDetails = new Map();
const errors = [];

function command(method, params = {}) {
    return new Promise((resolve, reject) => {
        const requestId = ++id;
        const timer = setTimeout(() => { pending.delete(requestId); reject(new Error(`Timeout: ${method}${params.expression ? ': ' + params.expression.slice(0, 160) : ''}`)); }, 15000);
        pending.set(requestId, { resolve, reject, timer });
        socket.send(JSON.stringify({ id: requestId, method, params }));
    });
}

async function evaluate(expression) {
    const result = await command("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    assert(!result.exceptionDetails, JSON.stringify(result.exceptionDetails));
    return result.result.value;
}

async function run() {
    const python = path.resolve(__dirname, "..", ".venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python");
    assert(fs.existsSync(python), "Install the project's .venv and Flask requirements first.");
    testServer = spawn(python, ["-u", "-c", "import sys, threading; from app import app; from werkzeug.serving import make_server; server = make_server('127.0.0.1', 0, app, threaded=True); worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start(); print('http://127.0.0.1:' + str(server.server_port), flush=True); sys.stdin.read(); server.shutdown(); server.server_close(); worker.join()"], {
        cwd: path.resolve(__dirname, ".."),
        env: { ...process.env, CYBERGUARD_DATABASE: path.join(profile, "test-history.sqlite3") },
        stdio: ["pipe", "pipe", "ignore"], windowsHide: true
    });
    testServer.stdout.on("data", (chunk) => {
        const match = chunk.toString().match(/http:\/\/127\.0\.0\.1:\d+/);
        if (match) {
            const host = process.env.CYBERGUARD_TEST_HOST || "127.0.0.1";
            assert(["127.0.0.1", "localhost"].includes(host), "Use a local test host.");
            baseUrl = match[0].replace("127.0.0.1", host);
        }
    });
    for (let attempt = 0; !baseUrl && attempt < 100; attempt++) await delay(100);
    assert(baseUrl, "Isolated Flask test server did not start.");
    const activePortFile = path.join(profile, "DevToolsActivePort");
    for (let attempt = 0; !fs.existsSync(activePortFile) && attempt < 100; attempt++) await delay(100);
    assert(fs.existsSync(activePortFile), "Browser did not start.");
    const port = fs.readFileSync(activePortFile, "utf8").split("\n")[0];
    const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    socket = new WebSocket(targets.find((target) => target.type === "page").webSocketDebuggerUrl);
    await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
    socket.onmessage = (event) => {
        const message = JSON.parse(event.data);
        if (message.id && pending.has(message.id)) {
            const item = pending.get(message.id);
            pending.delete(message.id);
            clearTimeout(item.timer);
            if (message.error) item.reject(new Error(message.error.message));
            else item.resolve(message.result);
        }
        if (message.method === "Network.requestWillBeSent") {
            requests.push(message.params.request.url);
            requestDetails.set(message.params.requestId, message.params.request);
        }
        if (message.method === "Network.requestWillBeSentExtraInfo") {
            requestHeaders.set(message.params.requestId, Object.fromEntries(Object.entries(message.params.headers).map(([name, value]) => [name.toLowerCase(), value])));
        }
        if (message.method === "Network.responseReceived") responseDetails.set(message.params.requestId, message.params.response);
        if (message.method === "Runtime.exceptionThrown") errors.push(message.params.exceptionDetails);
    };
    await command("Page.enable");
    await command("Runtime.enable");
    await command("Network.enable");
    await command("Page.navigate", { url: baseUrl });
    for (let attempt = 0; attempt < 100; attempt++) {
        if (await evaluate("document.readyState === 'complete' && !!document.querySelector('#scanForm')")) break;
        await delay(100);
    }
    async function navigateView(page) {
        await evaluate(`window.location.hash = ${JSON.stringify(page)}`);
        for (let attempt = 0; attempt < 100; attempt++) {
            if (await evaluate(`document.querySelector('[data-page="${page}"]')?.hidden === false`)) return;
            await delay(20);
        }
        throw new Error(`View did not open: ${page}`);
    }
    assert(await evaluate("!document.querySelector('#dashboard').hidden && document.querySelector('#hero-title').textContent === 'Dashboard'"), "Default dashboard did not open");
    assert(await evaluate(`(() => {
        const style = getComputedStyle(document.documentElement);
        return Object.entries({ '--bg': '#071321', '--surface': '#10243B', '--accent': '#22C7E8', '--text': '#E8F2FF', '--muted': '#9CB3C9', '--border': '#243C55' })
            .every(([token, value]) => style.getPropertyValue(token).trim().toUpperCase() === value);
    })()`), "Theme does not match the requested palette");
    assert(await evaluate(`(() => {
        const style = getComputedStyle(document.documentElement);
        const luminance = token => {
            const hex = style.getPropertyValue(token).trim().slice(1);
            const channels = [0, 2, 4].map(i => parseInt(hex.slice(i, i + 2), 16) / 255)
                .map(c => c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
            return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
        };
        return [['--text', '--bg'], ['--text', '--surface'], ['--muted', '--surface'], ['--accent', '--surface'], ['--bg', '--accent']]
            .every(([a, b]) => (Math.max(luminance(a), luminance(b)) + 0.05) / (Math.min(luminance(a), luminance(b)) + 0.05) >= 4.5);
    })()`), "Core text colors do not meet 4.5:1 contrast");
    await navigateView("scanner");
    const result = await evaluate(`(async () => {
        let checks = 0;
        const check = (condition, message) => { if (!condition) throw new Error(message); checks++; };
        const input = document.querySelector('#urlInput');
        const form = document.querySelector('#scanForm');
        const button = form.querySelector('button');
        const error = document.querySelector('#formError');
        const optIn = document.querySelector('#saveHistory');
        const optInLabel = document.querySelector('label[for="saveHistory"]');
        const historyStatus = document.querySelector('#historyStatus');
        const historyError = document.querySelector('#historyError');
        for (let n = 0; historyStatus.textContent === 'Loading history...' && n < 500; n++) await new Promise(r => setTimeout(r, 10));
        check(!optIn.checked, 'History must default to off');
        check(optInLabel.textContent.trim() === 'Save Scan to History', 'Missing requested checkbox label');
        check(form.contains(optIn), 'Saving checkbox is outside the scan form');
        check(optIn.getBoundingClientRect().width >= 20 && optIn.getBoundingClientRect().height >= 20, 'Checkbox is hidden or too small');
        check(document.querySelector('#urlsChecked').textContent === '0', 'Initial history not empty');
        const settle = async () => {
            for (let n = 0; button.disabled && n < 500; n++) await new Promise(r => setTimeout(r, 10));
            check(!button.disabled, 'Button stuck loading');
        };
        const submit = async (value) => {
            input.value = value;
            input.dispatchEvent(new Event('input', { bubbles: true }));
            button.click();
            await settle();
        };
        for (const [url, score, level] of [
            ['https://example.com', 0, 'Low'],
            ['http://192.0.2.1/login', 40, 'Medium'],
            ['http://a.b.c.d.paypa1.example/login/verify/password/account/%2540', 85, 'High']
        ]) {
            await submit(url);
            check(!error.textContent, 'Unexpected API error');
            check(document.querySelector('#resultTitle').textContent === 'Risk score: ' + score + '/100', 'Wrong score');
            check(document.querySelector('#riskLevel').textContent === level, 'Wrong classification');
            check(document.querySelector('#resultCard .badge').classList.contains(({ Low: 'badge-safe', Medium: 'badge-warning', High: 'badge-danger' })[level]), 'Wrong risk badge style');
            check(document.querySelector('#resultSummary').textContent.includes('cannot guarantee'), 'Missing limitation');
            check(document.querySelector('#indicatorList').children.length > 0, 'Missing reasons');
        }
        check(document.querySelector('#urlsChecked').textContent === '0', 'Unsaved scan changed history count');
        check(document.querySelector('#riskCounter').textContent === '0', 'Unsaved scan changed warning count');
        for (const value of ['not-a-url', 'ftp://example.com', 'https://example.com/%ZZ', 'https://user:secret@example.com', '']) {
            await submit(value);
            check(error.textContent.length > 0, 'Missing validation error');
            check(input.getAttribute('aria-invalid') === 'true', 'Missing invalid state');
            check(document.querySelector('#urlsChecked').textContent === '0', 'Error changed counters');
        }
        const originalFetch = window.fetch;
        let release;
        let calls = 0;
        window.fetch = (...args) => {
            check(args[1].mode === 'same-origin', 'API fetch is not restricted to the page origin');
            check(args[1].referrerPolicy === 'same-origin', 'API fetch uses an incompatible referrer policy');
            check(args[1].credentials === 'omit', 'API fetch unexpectedly sends credentials');
            calls++;
            return new Promise(resolve => { release = () => resolve(originalFetch(...args)); });
        };
        input.value = 'https://example.org';
        button.click();
        check(button.disabled && form.getAttribute('aria-busy') === 'true', 'Missing loading state');
        form.requestSubmit();
        check(calls === 1, 'Duplicate request');
        release();
        await settle();
        check(document.querySelector('#urlsChecked').textContent === '0', 'Unsaved recovery changed history');
        window.fetch = () => Promise.reject(new TypeError('Offline'));
        await submit('https://example.com');
        check(error.textContent.includes('Could not reach'), 'Missing server failure message');
        check(!input.hasAttribute('aria-invalid'), 'Network failure marked URL invalid');
        window.fetch = () => Promise.reject(new DOMException('Timeout', 'AbortError'));
        await submit('https://example.com');
        check(error.textContent.includes('timed out'), 'Missing timeout message');
        window.fetch = originalFetch;
        await submit('https://example.com');
        check(!error.textContent, 'Failed recovery after network error');
        check(document.querySelector('#urlsChecked').textContent === '0', 'Wrong recovered count');
        check(button.textContent === 'Scan URL' && !form.hasAttribute('aria-busy'), 'Loading state not reset');
        optInLabel.click();
        check(optIn.checked, 'Clicking the visible label did not enable saving');
        await submit('https://example.com/private-path?token=PRIVATE_VALUE#PRIVATE_FRAGMENT');
        check(document.querySelector('#urlsChecked').textContent === '1', 'Saved count not updated');
        check(document.querySelector('#dashboard [data-stat="total"]').textContent === '1', 'Dashboard count not synchronized');
        check(document.querySelector('#historyRows').textContent.includes('https://example.com'), 'Missing saved row');
        check(!document.querySelector('#historyRows').textContent.includes('PRIVATE'), 'History leaked a secret');
        check(!document.querySelector('#historyRows').textContent.includes('private-path'), 'History leaked a path');
        check(document.querySelector('#saveStatus').textContent.includes('Saved to history'), 'Missing save confirmation');
        await submit('http://192.0.2.1/login');
        check(document.querySelector('#urlsChecked').textContent === '2', 'Second saved scan missing');
        check(document.querySelector('#averageScore').textContent === '20', 'Wrong average saved score');
        check(document.querySelector('#riskCounter').textContent === '1', 'Wrong saved warning count');
        optInLabel.click();
        check(!optIn.checked, 'Clicking the label did not disable saving');
        await submit('https://example.org');
        check(document.querySelector('#urlsChecked').textContent === '2', 'Opt-out persisted a scan');
        const deleteButton = document.querySelector('#deleteHistory');
        const originalConfirm = window.confirm;
        let confirmations = 0;
        window.confirm = () => { confirmations++; return false; };
        deleteButton.click();
        check(confirmations === 1, 'Missing deletion confirmation');
        check(document.querySelector('#urlsChecked').textContent === '2', 'Cancelled deletion changed data');
        window.confirm = () => true;
        deleteButton.click();
        await settle();
        check(document.querySelector('#urlsChecked').textContent === '0', 'Deletion did not clear stats');
        check(document.querySelector('#dashboard [data-stat="total"]').textContent === '0', 'Deletion did not clear dashboard statistics');
        check(document.querySelector('#historyRows').textContent.includes('No saved scans'), 'Missing empty history state');
        check(deleteButton.disabled, 'Empty history deletion still enabled');
        window.confirm = originalConfirm;
        window.fetch = () => Promise.reject(new TypeError('Offline'));
        document.querySelector('#refreshHistory').click();
        for (let n = 0; document.querySelector('#refreshHistory').disabled && n < 500; n++) await new Promise(r => setTimeout(r, 10));
        check(historyError.textContent.includes('Could not load'), 'Missing history failure state');
        window.fetch = originalFetch;
        document.querySelector('#refreshHistory').click();
        for (let n = 0; document.querySelector('#refreshHistory').disabled && n < 500; n++) await new Promise(r => setTimeout(r, 10));
        check(!historyError.textContent, 'History failed to recover');
        for (let n = 0; n < 21; n++) {
            const response = await originalFetch('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'https://example.com/page-' + n, save_history: true }) });
            check(response.ok, 'Pagination seed failed');
        }
        const refresh = document.querySelector('#refreshHistory');
        const waitHistory = async () => {
            for (let n = 0; refresh.disabled && n < 500; n++) await new Promise(r => setTimeout(r, 10));
            check(!refresh.disabled, 'History stayed loading');
        };
        refresh.click();
        await waitHistory();
        check(document.querySelector('#historyRows').children.length === 20, 'Wrong first page size');
        check(document.querySelector('#urlsChecked').textContent === '21', 'Stats used page size instead of total');
        document.querySelector('#historyNext').click();
        await waitHistory();
        check(document.querySelector('#historyRows').children.length === 1, 'Wrong last page size');
        check(!document.querySelector('#historyPrevious').disabled, 'Previous page disabled');
        check(document.querySelector('#historyNext').disabled, 'Next page enabled at end');
        const fresh = await originalFetch('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'https://latest.example/new?token=PRIVATE', save_history: true }) });
        check(fresh.ok, 'External saved scan failed');
        refresh.click();
        await waitHistory();
        check(document.querySelector('#historyRows').children.length === 20, 'Refresh did not return to first page');
        check(document.querySelector('#historyRows').firstChild.textContent.includes('https://latest.example'), 'Refresh did not retrieve newest scan');
        check(document.querySelector('#urlsChecked').textContent === '22', 'Refresh did not update statistics');
        check(document.querySelector('#historyPrevious').disabled, 'Refresh kept old page offset');
        document.querySelector('#historyNext').click();
        await waitHistory();
        check(document.querySelector('#historyRows').children.length === 2, 'Wrong refreshed last page size');
        document.querySelector('#historyPrevious').click();
        await waitHistory();
        check(document.querySelector('#historyRows').children.length === 20, 'Previous page did not load');
        window.confirm = () => true;
        deleteButton.click();
        await settle();
        check(document.querySelector('#urlsChecked').textContent === '0', 'Pagination history did not clear');
        window.confirm = originalConfirm;
        await submit('https://example.com/<svg/onload=alert(1)>');
        check(!error.textContent, 'XSS text analysis failed');
        check(document.querySelector('#reviewedUrl').textContent.includes('<svg/onload=alert(1)>'), 'Submitted text was not rendered literally');
        check(!document.querySelector('#reviewedUrl svg'), 'URL text became an SVG element');
        const attack = '<img src=x onerror=alert(1)>';
        window.fetch = () => Promise.resolve(new Response(JSON.stringify({
            total: 1, statistics: { total: 1, average_score: 0, high: 0, medium: 0 },
            scans: [{ scanned_at: new Date().toISOString(), normalized_url: attack, risk_score: 0, risk_level: 'Low', reasons: [{ points: 0, explanation: attack }] }]
        }), { headers: { 'Content-Type': 'application/json' } }));
        refresh.click();
        await waitHistory();
        check(document.querySelector('#historyRows').textContent.includes(attack), 'History text was not rendered literally');
        check(!document.querySelector('#historyRows img'), 'History text became an image element');
        check(!document.querySelector('#historyRows [onerror]'), 'History installed an event handler');
        window.fetch = () => Promise.resolve(new Response(JSON.stringify({ error: attack }), { status: 400, headers: { 'Content-Type': 'application/json' } }));
        await submit('https://example.com');
        check(error.textContent === attack && !error.querySelector('img'), 'API error rendered HTML');
        window.fetch = originalFetch;
        return checks;
    })()`);
    assert.equal(errors.length, 0, "Browser JavaScript exception");
    await evaluate(`fetch('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'http://192.0.2.1/login?token=PRIVATE_VALUE#PRIVATE_FRAGMENT', save_history: true }) }).then(r => r.json())`);
    await command("Page.reload");
    let reloaded = false;
    for (let attempt = 0; attempt < 100; attempt++) {
        reloaded = await evaluate("document.readyState === 'complete' && document.querySelector('#historyStatus')?.textContent.includes('1 saved scans')");
        if (reloaded) break;
        await delay(100);
    }
    assert(reloaded, "History did not persist after reload");
    assert(await evaluate("!document.querySelector('#saveHistory').checked"), "Saving did not reset to off");
    assert(await evaluate("document.querySelector('#urlsChecked').textContent === '1' && document.querySelector('#riskCounter').textContent === '1'"), "Reloaded statistics incorrect");
    await evaluate("document.querySelector('#urlInput').value = 'http://192.0.2.1/login'; document.querySelector('#scanForm').requestSubmit()");
    let populated = false;
    for (let attempt = 0; attempt < 100; attempt++) {
        populated = await evaluate("document.querySelector('#riskLevel').textContent === 'Medium' && !document.querySelector('#scanForm').hasAttribute('aria-busy')");
        if (populated) break;
        await delay(100);
    }
    assert(populated, "Populated report did not render after reload");
    assert(await evaluate("document.querySelector('#urlsChecked').textContent === '1'"), "Responsive preview saved an opted-out scan");
    assert(requests.every((url) => url.startsWith(new URL(baseUrl).origin + "/")), "Unexpected off-origin request");
    for (const [width, height] of [[1440, 1000], [1024, 900], [768, 1024], [390, 844], [320, 780]]) {
        await command("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: width < 500 });
        await navigateView("scanner");
        assert(await evaluate("document.querySelector('#saveHistory').getBoundingClientRect().width >= 20 && document.querySelector('#saveHistory').getBoundingClientRect().height >= 20 && getComputedStyle(document.querySelector('label[for=saveHistory]')).visibility === 'visible'"), "Saving option is hidden at this viewport");
        assert(await evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "Horizontal overflow");
        assert(await evaluate(`(() => {
            const heading = document.querySelector('#hero-title');
            const style = getComputedStyle(heading);
            const fontSize = parseFloat(style.fontSize);
            return heading.getBoundingClientRect().height <= parseFloat(style.lineHeight) * 2 + 1
                && fontSize <= 32;
        })()`), "Page heading size or line count is incorrect");
        if (width <= 760) {
            assert(await evaluate("parseFloat(getComputedStyle(document.querySelector('#urlInput')).fontSize) >= 16"), "Mobile input text would trigger automatic zoom");
        }
        if (width <= 900) {
            await evaluate("document.querySelector('.nav-toggle').click()");
            assert(await evaluate("document.querySelector('.nav-toggle').getAttribute('aria-expanded') === 'true' && getComputedStyle(document.querySelector('#primary-navigation')).display !== 'none'"), "Mobile navigation did not open");
            await command("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape" });
            assert(await evaluate("document.querySelector('.nav-toggle').getAttribute('aria-expanded') === 'false' && document.activeElement === document.querySelector('.nav-toggle')"), "Escape did not close navigation and restore focus");
            await evaluate("document.querySelector('.nav-toggle').click()");
            await evaluate("document.querySelector('#primary-navigation a').click()");
            assert(await evaluate("document.querySelector('.nav-toggle').getAttribute('aria-expanded') === 'false'"), "Mobile navigation did not close after navigation");
        }
        for (const [page, title] of [["dashboard", "Dashboard"], ["scanner", "URL Scanner"], ["insights", "Security Analytics"], ["history", "Scan History"]]) {
            await navigateView(page);
            assert(await evaluate(`document.querySelectorAll('[data-page]:not([hidden])').length === 1
                && document.querySelector('#hero-title').textContent === ${JSON.stringify(title)}
                && document.querySelector('#primary-navigation a[aria-current=page]').hash === '#${page}'
                && document.querySelectorAll('#primary-navigation a[aria-current=page]').length === 1
                && document.title === ${JSON.stringify(title + " | CyberGuard")}`), `Navigation state incorrect on ${page} at ${width}px`);
            assert(await evaluate("document.documentElement.scrollWidth <= window.innerWidth"), `Horizontal overflow on ${page} at ${width}px`);
            assert(await evaluate(`(() => {
                const heading = document.querySelector('#hero-title');
                const style = getComputedStyle(heading);
                return parseFloat(style.fontSize) <= 32 && heading.getBoundingClientRect().height <= parseFloat(style.lineHeight) * 2 + 1;
            })()`), `Oversized heading on ${page} at ${width}px`);
            assert(await evaluate("document.querySelectorAll('.navbar').length === 1 && document.querySelectorAll('.brand').length === 1 && document.querySelectorAll('.site-footer').length === 1"), "Shared page shell was duplicated");
            assert(await evaluate(`getComputedStyle(document.body).backgroundColor === 'rgb(7, 19, 33)'
                && [...document.querySelector('[data-page="${page}"]').querySelectorAll('.stat-card, .scanner-section, .result-card, .distribution-card, .history-table-wrap')]
                    .every(card => getComputedStyle(card).backgroundColor === 'rgb(16, 36, 59)')`), `Inconsistent surfaces on ${page}`);
            assert(await evaluate("document.querySelector('#resultTitle').textContent === 'Risk score: 40/100' && document.querySelector('#urlInput').value === 'http://192.0.2.1/login' && !document.querySelector('#saveHistory').checked"), "View navigation lost scan state");
            if (page === "insights") {
                assert(await evaluate("document.querySelector('#mediumMeter').value === 1 && document.querySelector('#mediumMeter').max === 1 && document.querySelector('#lowMeter').value === 0 && document.querySelector('#highMeter').value === 0"), "Analytics distribution did not match saved history");
            }
            if (process.env.CYBERGUARD_SCREENSHOT_DIR) {
                fs.mkdirSync(process.env.CYBERGUARD_SCREENSHOT_DIR, { recursive: true });
                await evaluate("document.activeElement.blur(); window.scrollTo({ top: 0, behavior: 'instant' })");
                await delay(200);
                const screenshot = await command("Page.captureScreenshot", { format: "png" });
                fs.writeFileSync(path.join(process.env.CYBERGUARD_SCREENSHOT_DIR, `${page}-${width}.png`), Buffer.from(screenshot.data, "base64"));
            }
        }
    }
    await command("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "reduce" }] });
    assert(await evaluate("getComputedStyle(document.documentElement).scrollBehavior === 'auto' && getComputedStyle(document.querySelector('.button')).transitionDuration === '0s'"), "Reduced motion preference was not respected");
    for (const page of ["dashboard", "scanner", "insights", "history"]) {
        await navigateView(page);
        await command("Page.reload");
        let restored = false;
        for (let attempt = 0; attempt < 100; attempt++) {
            restored = await evaluate(`document.readyState === 'complete' && document.querySelector('[data-page="${page}"]')?.hidden === false && document.querySelector('#urlsChecked')?.textContent === '1'`);
            if (restored) break;
            await delay(20);
        }
        assert(restored, `Direct link/reload did not restore ${page}`);
    }
    await navigateView("scanner");
    await navigateView("history");
    await evaluate("window.history.back()");
    for (let attempt = 0; attempt < 100; attempt++) {
        if (await evaluate("!document.querySelector('[data-page=scanner]').hidden")) break;
        await delay(20);
    }
    assert(await evaluate("!document.querySelector('[data-page=scanner]').hidden && document.querySelector('#hero-title').textContent === 'URL Scanner'"), "Browser Back did not restore the prior view");
    await evaluate("document.querySelector('#hero-title').focus()");
    await command("Input.dispatchKeyEvent", { type: "keyDown", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 });
    await command("Input.dispatchKeyEvent", { type: "keyUp", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 });
    assert(await evaluate("document.activeElement === document.querySelector('#urlInput') && getComputedStyle(document.activeElement).outlineStyle !== 'none'"), "Keyboard navigation did not reach the scanner with a visible focus outline");
    assert(requests.every((url) => url.startsWith(new URL(baseUrl).origin + "/")), "Page navigation made off-origin requests");
    const apiRequests = [...requestDetails.entries()].filter(([, request]) => new URL(request.url).pathname.startsWith('/api/'));
    assert(apiRequests.length > 0, "No real API requests captured");
    for (const [id, request] of apiRequests) {
        const headers = requestHeaders.get(id);
        assert(headers, "API request headers were not captured");
        assert.equal(headers['sec-fetch-site'], 'same-origin', "API request was not same-origin");
        if (headers.origin !== undefined) assert.equal(headers.origin, new URL(baseUrl).origin, "API sent an unexpected/null Origin");
        if (request.method === 'POST' || request.method === 'DELETE') assert.equal(headers.origin, new URL(baseUrl).origin, "Mutation omitted its exact Origin");
    }
    assert(apiRequests.some(([id, request]) => request.method === 'GET' && requestHeaders.get(id).origin === undefined), "Missing Origin-free same-origin GET coverage");
    const sourceUrl = new URL(baseUrl);
    sourceUrl.hostname = sourceUrl.hostname === 'localhost' ? '127.0.0.1' : 'localhost';
    await command("Page.navigate", { url: sourceUrl.origin });
    let sourceLoaded = false;
    for (let attempt = 0; attempt < 100; attempt++) {
        sourceLoaded = await evaluate(`document.readyState === 'complete' && location.origin === ${JSON.stringify(sourceUrl.origin)} && !!document.querySelector('.brand')`);
        if (sourceLoaded) break;
        await delay(20);
    }
    assert(sourceLoaded, "Alternate loopback source page did not load");
    const linkPoint = await evaluate(`(() => {
        const link = document.querySelector('.brand');
        link.href = ${JSON.stringify(baseUrl + '/api/history')};
        const rect = link.getBoundingClientRect();
        return { x: rect.x + rect.width / 2, y: rect.y + rect.height / 2 };
    })()`);
    await command("Input.dispatchMouseEvent", { type: "mousePressed", ...linkPoint, button: "left", clickCount: 1 });
    await command("Input.dispatchMouseEvent", { type: "mouseReleased", ...linkPoint, button: "left", clickCount: 1 });
    let navigationRequest;
    for (let attempt = 0; attempt < 100; attempt++) {
        navigationRequest = [...requestDetails.entries()].find(([id, request]) => request.url === baseUrl + '/api/history'
            && requestHeaders.get(id)?.['sec-fetch-mode'] === 'navigate'
            && requestHeaders.get(id)?.['sec-fetch-site'] === 'cross-site');
        if (navigationRequest && responseDetails.has(navigationRequest[0])) break;
        await delay(20);
    }
    assert(navigationRequest && responseDetails.has(navigationRequest[0]), "History document navigation did not return a response");
    assert.equal(responseDetails.get(navigationRequest[0]).status, 200, "User-initiated cross-site history navigation was incorrectly rejected");
    const historyAfterNavigation = await (await fetch(baseUrl + '/api/history', { signal: AbortSignal.timeout(5000) })).json();
    assert.equal(historyAfterNavigation.total, 1, "Read-only navigation changed the database");
    const navigationHeaders = requestHeaders.get(navigationRequest[0]);
    assert.equal(navigationHeaders['sec-fetch-site'], 'cross-site', "Navigation did not reproduce the failing Fetch Metadata");
    assert.equal(navigationHeaders['sec-fetch-mode'], 'navigate');
    assert.equal(navigationHeaders['sec-fetch-dest'], 'document');
    assert.equal(navigationHeaders['sec-fetch-user'], '?1');
    assert.equal(navigationHeaders.origin, undefined);
    assert.equal(errors.length, 0, "Browser JavaScript exception during responsive checks");
    console.log(`PASS (${new URL(baseUrl).hostname}): ${result} in-page browser assertions plus real Origin/Fetch Metadata headers and user-initiated cross-site GET navigation; all four views at five viewport sizes, exact theme, risk badges, analytics, state preservation, direct links/reload, Back, keyboard navigation and reduced motion; isolated SQLite history, privacy, confirmation, statistics and API failures.`);
}

run().catch((error) => { console.error(error); process.exitCode = 1; }).finally(async () => {
    if (socket && socket.readyState === WebSocket.OPEN) {
        try { await command("Browser.close"); } catch {}
        socket.close();
    }
    browser.kill();
    if (testServer) {
        // Closing stdin lets both the Windows venv launcher and Python exit.
        await new Promise(resolve => {
            const timer = setTimeout(() => { testServer.kill(); resolve(); }, 5000);
            testServer.once('exit', () => { clearTimeout(timer); resolve(); });
            testServer.stdin.end();
        });
    }
    // Chrome may release its profile files shortly after closing.
    await delay(500);
    if (path.dirname(path.resolve(profile)) === path.resolve(os.tmpdir())
            && path.basename(profile).startsWith("cyberguard-browser-")) {
        try { fs.rmSync(profile, { recursive: true, force: true }); } catch {}
    }
});
