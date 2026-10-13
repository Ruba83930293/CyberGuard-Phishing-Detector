function initializeCyberGuard() {
    const scanForm = document.querySelector("#scanForm");
    const urlInput = document.querySelector("#urlInput");
    const formError = document.querySelector("#formError");
    const scanButton = scanForm.querySelector("button[type='submit']");
    const scanButtonLabel = document.querySelector("#scanButtonLabel");
    const navToggle = document.querySelector(".nav-toggle");
    const navLinks = document.querySelector("#primary-navigation");
    const resultCard = document.querySelector("#resultCard");
    const resultBadge = resultCard.querySelector(".badge");
    const saveHistory = document.querySelector("#saveHistory");
    const historyRows = document.querySelector("#historyRows");
    const historyError = document.querySelector("#historyError");
    const historyStatus = document.querySelector("#historyStatus");
    const deleteButton = document.querySelector("#deleteHistory");
    const refreshButton = document.querySelector("#refreshHistory");
    const previousButton = document.querySelector("#historyPrevious");
    const nextButton = document.querySelector("#historyNext");
    let historyOffset = 0;
    let historyVersion = 0;
    let historyLoading = false;
    let deleting = false;
    let savedTotal = 0;
    let scanning = false;

    const pages = {
        dashboard: { title: "Dashboard", description: "An overview of saved URL analyses and your analysis environment." },
        scanner: { title: "URL Scanner", description: "Review URL-text risk indicators with transparent scoring and clear explanations." },
        insights: { title: "Security Analytics", description: "Risk scores and classifications across your saved scan history." },
        history: { title: "Scan History", description: "Review and manage the URL analyses you explicitly chose to save." }
    };

    function closeNavigation() {
        navLinks.classList.remove("is-open");
        navToggle.setAttribute("aria-expanded", "false");
    }

    function showPage(focus = false) {
        const fragment = window.location.hash.slice(1);
        const aliases = { results: "scanner", about: "dashboard", analytics: "insights" };
        const candidate = aliases[fragment] || fragment;
        const page = Object.hasOwn(pages, candidate) ? candidate : "dashboard";
        document.querySelectorAll("[data-page]").forEach((view) => { view.hidden = view.dataset.page !== page; });
        navLinks.querySelectorAll("a").forEach((link) => {
            if (link.hash === `#${page}`) link.setAttribute("aria-current", "page");
            else link.removeAttribute("aria-current");
        });
        const heading = document.querySelector("#hero-title");
        heading.textContent = pages[page].title;
        document.querySelector("#viewDescription").textContent = pages[page].description;
        document.title = `${pages[page].title} | CyberGuard`;
        closeNavigation();
        if (focus) {
            window.scrollTo({ top: 0, behavior: "instant" });
            heading.focus({ preventScroll: true });
            if (fragment === "results" || fragment === "about") document.querySelector(`#${fragment}`).scrollIntoView({ block: "start" });
            if (page !== "scanner" && !historyLoading && !deleting) loadHistory();
        }
    }

    function updateStatistics(stats = null) {
        const values = stats ? {
            ...stats, low: Math.max(0, stats.total - stats.medium - stats.high), flagged: stats.medium + stats.high
        } : null;
        document.querySelectorAll("[data-stat]").forEach((element) => {
            element.textContent = values ? String(values[element.dataset.stat]) : "-";
        });
        for (const level of ["low", "medium", "high"]) {
            const meter = document.querySelector(`#${level}Meter`);
            meter.max = Math.max(1, values?.total || 0);
            meter.value = values?.[level] || 0;
            meter.setAttribute("aria-valuetext", values ? `${values[level]} of ${values.total} saved scans` : "Statistics unavailable");
        }
        document.querySelector("#analyticsStatus").textContent = values
            ? `${values.total} saved scans. Unsaved analyses are not included.`
            : "Statistics unavailable. Refresh Scan History to try again.";
    }

    function riskBadgeClass(level) {
        return ({ Low: "badge-safe", Medium: "badge-warning", High: "badge-danger" })[level] || "badge-neutral";
    }

    async function apiRequest(endpoint, options = {}) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);
        try {
            const response = await fetch(endpoint, {
                ...options, signal: controller.signal, mode: "same-origin", referrerPolicy: "same-origin",
                credentials: "omit", redirect: "error", cache: "no-store"
            });
            const data = await response.json();
            if (!response.ok) {
                const error = new Error(data.error || "Request failed. Please try again.");
                error.status = response.status;
                throw error;
            }
            return data;
        } finally {
            clearTimeout(timeout);
        }
    }

    function updateHistoryControls() {
        deleteButton.disabled = !savedTotal || scanning || historyLoading || deleting;
        refreshButton.disabled = historyLoading || deleting;
        previousButton.disabled = historyLoading || deleting || historyOffset === 0;
        nextButton.disabled = historyLoading || deleting || historyOffset + 20 >= savedTotal;
    }

    async function loadHistory() {
        const version = ++historyVersion;
        historyLoading = true;
        historyError.textContent = "";
        historyStatus.textContent = "Loading history...";
        updateHistoryControls();
        try {
            if (window.location.protocol === "file:") throw new Error("Open the app through the Flask server to load history.");
            const history = await apiRequest(`/api/history?limit=20&offset=${historyOffset}`);
            if (version !== historyVersion) return;
            savedTotal = history.total;
            if (historyOffset && historyOffset >= savedTotal) {
                historyOffset = 0;
                await loadHistory();
                return;
            }
            updateStatistics(history.statistics);
            historyRows.replaceChildren();
            for (const scan of history.scans) {
                const row = document.createElement("tr");
                for (const value of [new Date(scan.scanned_at).toLocaleString(), scan.normalized_url, `${scan.risk_score}/100`]) {
                    const cell = document.createElement("td");
                    cell.textContent = value;
                    row.appendChild(cell);
                }
                const levelCell = document.createElement("td");
                const levelBadge = document.createElement("span");
                levelBadge.className = `badge ${riskBadgeClass(scan.risk_level)}`;
                levelBadge.textContent = scan.risk_level;
                levelCell.appendChild(levelBadge);
                row.appendChild(levelCell);
                const cell = document.createElement("td");
                if (scan.reasons.length) {
                    const details = document.createElement("details");
                    const summary = document.createElement("summary");
                    summary.textContent = `${scan.reasons.length} rules`;
                    const list = document.createElement("ul");
                    scan.reasons.forEach((reason) => {
                        const item = document.createElement("li");
                        item.textContent = `+${reason.points}: ${reason.explanation}`;
                        list.appendChild(item);
                    });
                    details.append(summary, list);
                    cell.appendChild(details);
                } else cell.textContent = "No rules triggered";
                row.appendChild(cell);
                historyRows.appendChild(row);
            }
            if (!history.scans.length) {
                const row = document.createElement("tr");
                const cell = document.createElement("td");
                cell.colSpan = 5;
                cell.textContent = "No saved scans.";
                row.appendChild(cell);
                historyRows.appendChild(row);
            }
            historyStatus.textContent = savedTotal ? `${historyOffset + 1}-${historyOffset + history.scans.length} of ${savedTotal} saved scans` : "0 saved scans";
        } catch (error) {
            if (version !== historyVersion) return;
            historyError.textContent = error.status ? error.message : "Could not load history. Check the Flask server and try Refresh History.";
            historyStatus.textContent = "History unavailable";
            savedTotal = 0;
            historyRows.replaceChildren();
            updateStatistics();
        } finally {
            if (version === historyVersion) {
                historyLoading = false;
                updateHistoryControls();
            }
        }
    }

    function clearError() {
        formError.textContent = "";
        urlInput.removeAttribute("aria-invalid");
    }

    function showError(message, invalidInput = false) {
        formError.textContent = message;
        if (invalidInput) {
            urlInput.setAttribute("aria-invalid", "true");
            urlInput.focus();
        }
    }

    function renderResult(result) {
        resultBadge.className = `badge ${riskBadgeClass(result.risk_level)}`;
        resultBadge.textContent = `${result.risk_level} heuristic risk`;
        document.querySelector("#resultTitle").textContent = `Risk score: ${result.risk_score}/100`;
        document.querySelector("#resultSummary").textContent = result.limitation;
        document.querySelector("#reviewedUrl").textContent = result.url;
        document.querySelector("#riskLevel").textContent = result.risk_level;
        document.querySelector("#scanTime").textContent = new Intl.DateTimeFormat(undefined, {
            hour: "2-digit", minute: "2-digit", second: "2-digit"
        }).format(new Date());
        const indicatorList = document.querySelector("#indicatorList");
        indicatorList.replaceChildren();
        const explanations = result.reasons.map((reason) => `+${reason.points} points: ${reason.explanation}`);
        if (!explanations.length) explanations.push("No configured rules triggered. This does not establish that the website is safe.");
        if (result.raw_score > result.score_cap) explanations.push(`Rule total: ${result.raw_score}; final score capped at ${result.score_cap}.`);
        explanations.forEach((explanation) => {
            const item = document.createElement("li");
            item.textContent = explanation;
            indicatorList.appendChild(item);
        });
        document.querySelector("#saveStatus").textContent = result.history_saved
            ? `Saved to history as ${result.stored_url}. Paths, queries, and fragments were removed.`
            : "Not saved to history.";
        if (!resultCard.closest("[data-page]").hidden) resultCard.scrollIntoView({ behavior: "auto", block: "nearest" });
    }

    scanForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (scanning || deleting) return;
        clearError();
        const value = urlInput.value.trim();
        if (!value || value.length > 4096) {
            showError(value ? "URLs must be at most 4096 characters." : "Enter a website URL.", true);
            return;
        }
        if (window.location.protocol === "file:") {
            showError("Start the Flask server and open http://127.0.0.1:5000 to analyze URLs.");
            return;
        }
        scanning = true;
        scanButton.disabled = true;
        scanButtonLabel.textContent = "Analyzing...";
        scanForm.setAttribute("aria-busy", "true");
        updateHistoryControls();
        try {
            // Send original text to our own API; never fetch the submitted address.
            const result = await apiRequest("/api/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: value, save_history: saveHistory.checked })
            });
            renderResult(result);
            if (result.history_saved) {
                historyOffset = 0;
                await loadHistory();
            }
        } catch (error) {
            showError(error.status ? error.message : error.name === "AbortError" ? "Analysis timed out. Please try again."
                : "Could not reach the analysis API. Check that the Flask server is running.", error.status === 400);
        } finally {
            scanning = false;
            scanButton.disabled = false;
            scanButtonLabel.textContent = "Scan URL";
            scanForm.removeAttribute("aria-busy");
            updateHistoryControls();
        }
    });

    refreshButton.addEventListener("click", () => {
        historyOffset = 0;
        loadHistory();
    });
    previousButton.addEventListener("click", () => { historyOffset = Math.max(0, historyOffset - 20); loadHistory(); });
    nextButton.addEventListener("click", () => { historyOffset += 20; loadHistory(); });
    deleteButton.addEventListener("click", async () => {
        if (scanning || deleting || !savedTotal) return;
        if (!window.confirm("Delete all saved scan history for this server? This cannot be undone.")) return;
        deleting = true;
        scanButton.disabled = true;
        updateHistoryControls();
        historyError.textContent = "";
        try {
            await apiRequest("/api/history", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ confirm: true }) });
            historyOffset = 0;
            await loadHistory();
            if (!historyError.textContent) historyStatus.textContent = `History deleted. ${savedTotal} saved scans now present.`;
        } catch (error) {
            historyError.textContent = error.status ? error.message : "Could not delete history. Refresh to check its current state.";
        } finally {
            deleting = false;
            scanButton.disabled = false;
            updateHistoryControls();
        }
    });

    urlInput.addEventListener("input", clearError);
    navToggle?.addEventListener("click", () => {
        navToggle.setAttribute("aria-expanded", String(navLinks.classList.toggle("is-open")));
    });
    document.addEventListener("click", (event) => {
        if (event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
        const link = event.target.closest?.("a[href^='#']");
        if (!link) return;
        closeNavigation();
        if (link.hash === window.location.hash) showPage(true);
    });
    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && navLinks.classList.contains("is-open")) {
            closeNavigation();
            navToggle.focus();
        }
    });
    window.addEventListener("hashchange", () => showPage(true));
    showPage();
    loadHistory();
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initializeCyberGuard, { once: true });
} else {
    initializeCyberGuard();
}
