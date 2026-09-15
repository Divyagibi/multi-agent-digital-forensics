/**
 * Multi-Agent Digital Forensics - Frontend Application Logic
 * Strictly handles evidence collection and display for Agents 1-5 without score calculations.
 */

const AGENT_METADATA = [
    { id: 1, name: "Domain Identity", desc: "Domain registration, RDAP/WHOIS, age & registrar", implemented: true, endpoint: "/api/agent1" },
    { id: 2, name: "DNS & Infrastructure", desc: "A, AAAA, MX, NS, TXT, CNAME, DNSSEC, CDN & IP", implemented: true, endpoint: "/api/agent2" },
    { id: 3, name: "SSL / HTTPS Security", desc: "TLS version, X509 certificates, cipher suites & HSTS", implemented: true, endpoint: "/api/agent3" },
    { id: 4, name: "Website Content Analysis", desc: "Metadata, company detection, policy pages & broken links", implemented: true, endpoint: "/api/agent4" },
    { id: 5, name: "URL Structure Analysis", desc: "Lexical features, Punycode, homograph & redirects", implemented: true, endpoint: "/api/agent5" },
    { id: 6, name: "Reputation & Threat Intelligence", desc: "VirusTotal, Safe Browsing, PhishTank, OpenPhish, AbuseIPDB, URLHaus & Blocklists", implemented: true, endpoint: "/api/agent6" },
    { id: 7, name: "Technical Fingerprinting", desc: "Web server, CMS, frameworks, JS libraries, analytics, trackers, admin panels & directories", implemented: true, endpoint: "/api/agent7" },
    { id: 8, name: "Website Behavior Analysis", desc: "Automatic redirects, popups, forced downloads, JS indicators, forms & fake login", implemented: true, endpoint: "/api/agent8" },
    { id: 9, name: "Brand Verification", desc: "Logo, favicon, brand name, trademark references, color theme, layout & official domain comparison", implemented: true, endpoint: "/api/agent9" },
    { id: 10, name: "Visual & UI Analysis", desc: "Screenshot, OCR text, trust badges, payment logos, reviews & suspicious UI patterns", implemented: true, endpoint: "/api/agent10" },
    { id: 11, name: "Content Quality Analysis", desc: "Grammar, spelling, AI-generated indicators, duplicate text, unrealistic claims, urgency & scam keywords", implemented: true, endpoint: "/api/agent11" },
    { id: 12, name: "Contact Verification", desc: "Email, phone, physical address, Google Maps, social media, GSTIN/VAT & business registry verification", implemented: true, endpoint: "/api/agent12" },
    { id: 13, name: "External Presence / OSINT", desc: "LinkedIn, Facebook, X/Twitter, Instagram, GitHub, Reddit, News, Reviews & Forums", implemented: true, endpoint: "/api/agent13" },
    { id: 14, name: "Historical Evidence", desc: "Wayback Machine archives, content evolution, ownership & DNS infrastructure timeline", implemented: true, endpoint: "/api/agent14" },
    { id: 15, name: "User Trust Signals", desc: "Trustpilot, Google Reviews, Reddit discussions, scam complaints, consumer forums, testimonials & cross-source corroboration", implemented: true, endpoint: "/api/agent15" },
    { id: 16, name: "Network Security", desc: "Open ports, HTTP & security headers, CSP, CORS configuration, X-Frame-Options & server fingerprinting", implemented: true, endpoint: "/api/agent16" },
    { id: 17, name: "Malware Indicators", desc: "Malicious downloads, suspicious scripts, drive-by patterns, cryptomining & obfuscated JavaScript", implemented: true, endpoint: "/api/agent17" },
    { id: 18, name: "QR Code Analysis", desc: "Decodes QR payloads, extracts embedded URLs, inspects redirect chains, shorteners & parameters", implemented: true, endpoint: "/api/agent18" }
];

// In-memory evidence cache for active session
const agentResults = {};
let currentSelectedAgent = 1;
let currentAnalysisSource = "Direct URL";
let currentDecodedTarget = null;
let currentQrFile = null;
let currentTargetUrl = "https://example.com";
let currentPipelineSession = null;
let currentReportPayload = null;

/**
 * Universal HTML escape helper to prevent XSS / DOM injection
 */
function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Initialize Dashboard
document.addEventListener("DOMContentLoaded", () => {
    renderAgentGrid();
    renderAgentChecklist();
    showAgentDetails(1);

    // Enter key trigger
    const urlInput = document.getElementById("urlInput");
    if (urlInput) {
        urlInput.addEventListener("keypress", (e) => {
            if (e.key === "Enter") {
                startAnalysis();
            }
        });
    }

    // Escape key listener for report modal
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            closeInvestigatorReport();
        }
    });
});

/**
 * Tab switcher between URL and QR upload
 */
function switchInputTab(tab) {
    const tabUrlBtn = document.getElementById("tabUrlBtn");
    const tabQrBtn = document.getElementById("tabQrBtn");
    const urlContainer = document.getElementById("urlInputContainer");
    const qrContainer = document.getElementById("qrUploadContainer");
    const sourceBadge = document.getElementById("inputSourceBadge");

    if (tab === "qr") {
        tabUrlBtn.classList.remove("active");
        tabQrBtn.classList.add("active");
        urlContainer.style.display = "none";
        qrContainer.style.display = "flex";
        sourceBadge.innerText = "QR Code Mode";
        sourceBadge.style.background = "rgba(139, 92, 246, 0.15)";
        sourceBadge.style.color = "#a78bfa";
        sourceBadge.style.borderColor = "rgba(139, 92, 246, 0.3)";
    } else {
        tabQrBtn.classList.remove("active");
        tabUrlBtn.classList.add("active");
        qrContainer.style.display = "none";
        urlContainer.style.display = "flex";
        sourceBadge.innerText = "Direct URL Mode";
        sourceBadge.style.background = "rgba(6, 182, 212, 0.15)";
        sourceBadge.style.color = "var(--accent-cyan)";
        sourceBadge.style.borderColor = "rgba(6, 182, 212, 0.3)";
    }
}

/**
 * QR Drag & Drop and File Selection
 */
function handleQrFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        processSelectedQrFile(file);
    }
}

function handleQrDragOver(event) {
    event.preventDefault();
    event.stopPropagation();
    document.getElementById("qrDropzone").classList.add("dragover");
}

function handleQrDragLeave(event) {
    event.preventDefault();
    event.stopPropagation();
    document.getElementById("qrDropzone").classList.remove("dragover");
}

function handleQrDrop(event) {
    event.preventDefault();
    event.stopPropagation();
    document.getElementById("qrDropzone").classList.remove("dragover");
    if (event.dataTransfer.files && event.dataTransfer.files.length > 0) {
        processSelectedQrFile(event.dataTransfer.files[0]);
    }
}

function processSelectedQrFile(file) {
    currentQrFile = file;
    const dropContent = document.getElementById("qrDropContent");
    const previewArea = document.getElementById("qrPreviewArea");
    const previewImg = document.getElementById("qrPreviewImg");
    const fileNameEl = document.getElementById("qrFileName");
    const analyzeQrBtn = document.getElementById("analyzeQrBtn");

    fileNameEl.innerText = file.name;
    const reader = new FileReader();
    reader.onload = (e) => {
        previewImg.src = e.target.result;
        dropContent.style.display = "none";
        previewArea.style.display = "flex";
        analyzeQrBtn.disabled = false;
    };
    reader.readAsDataURL(file);
}

function clearQrUpload(event) {
    if (event) event.stopPropagation();
    currentQrFile = null;
    document.getElementById("qrFileInput").value = "";
    document.getElementById("qrDropContent").style.display = "flex";
    document.getElementById("qrPreviewArea").style.display = "none";
    document.getElementById("analyzeQrBtn").disabled = true;
    document.getElementById("decodedTargetBanner").style.display = "none";
}

/**
 * QR Decode & Automated Pipeline Trigger
 */
async function startQrAnalysis() {
    if (!currentQrFile) {
        alert("Please select or drop a QR code image.");
        return;
    }

    const systemStatus = document.getElementById("systemStatus");
    const qrStatusText = document.getElementById("qrStatusText");
    const banner = document.getElementById("decodedTargetBanner");
    const bannerUrl = document.getElementById("decodedTargetUrl");
    const analyzeQrBtn = document.getElementById("analyzeQrBtn");

    systemStatus.innerText = "Decoding QR code image...";
    qrStatusText.innerText = "Decoding payload...";
    analyzeQrBtn.disabled = true;

    // Reset Trust score display strictly to non-calculated state
    document.getElementById("trustScore").innerText = "--";
    document.getElementById("trustStatus").innerText = "Evidence Collection Phase";

    try {
        const formData = new FormData();
        formData.append("qr_image", currentQrFile);

        const decodeResp = await fetch("/api/analyze-qr", {
            method: "POST",
            body: formData
        });

        const decodeData = await decodeResp.json();

        if (!decodeResp.ok || !decodeData.success || !decodeData.decoded) {
            qrStatusText.innerText = "Decoding failed";
            systemStatus.innerText = "QR Decoding Failed: " + (decodeData.error || "Unreadable QR");
            alert("QR Decoding Failed: " + (decodeData.error || "Please check the image and try again."));
            analyzeQrBtn.disabled = false;
            return;
        }

        qrStatusText.innerText = "Decoded: " + decodeData.data_type;

        // Check if QR contains a URL
        if (decodeData.is_url && decodeData.target_url) {
            currentAnalysisSource = "QR Code";
            currentDecodedTarget = decodeData.target_url;

            // Show decoded target banner
            bannerUrl.innerText = decodeData.target_url;
            banner.style.display = "flex";
            systemStatus.innerText = `QR Decoded Successfully (${decodeData.target_url}). Running 18 Forensic Agents...`;

            // Run Agent 18 with image
            runAgent18WithImage(currentQrFile, decodeData.target_url);

            // Execute Agents 1–17 on the decoded target URL!
            executePipelineOnTarget(decodeData.target_url, 1, 17);
        } else {
            // QR contains text or non-URL
            currentAnalysisSource = "QR Code (Non-URL)";
            currentDecodedTarget = null;
            bannerUrl.innerText = `Text payload: "${decodeData.payload}"`;
            banner.style.display = "flex";
            systemStatus.innerText = "QR contains plain text rather than a web URL. Agents 1–17 skipped.";

            // Run Agent 18 only
            runAgent18WithImage(currentQrFile, null);
        }

    } catch (err) {
        systemStatus.innerText = "QR processing error: " + err.message;
        qrStatusText.innerText = "Error: " + err.message;
    } finally {
        analyzeQrBtn.disabled = false;
    }
}

async function runAgent18WithImage(imageFile, targetUrl) {
    updateAgentStatus(18, "processing", "Processing");
    try {
        const formData = new FormData();
        formData.append("qr_image", imageFile);
        if (targetUrl) formData.append("url", targetUrl);

        const resp = await fetch("/api/agent18", {
            method: "POST",
            body: formData
        });
        const data = await resp.json();
        agentResults[18] = data;
        updateAgentStatus(18, "completed", "Completed");
        if (currentSelectedAgent === 18) {
            showAgentDetails(18);
        }
    } catch (e) {
        agentResults[18] = {
            agent: "Agent 18",
            status: "error",
            errors: [{ component: "network", error: e.message }],
            evidence: []
        };
        updateAgentStatus(18, "error", "Error");
    }
}

/**
 * Render the 18 agent grid cards.
 */
function renderAgentGrid() {
    const grid = document.getElementById("agentsGrid");
    grid.innerHTML = "";

    AGENT_METADATA.forEach(agent => {
        const card = document.createElement("div");
        card.id = `agent-card-${agent.id}`;
        card.className = `agent-card ${agent.implemented ? "" : "placeholder"} ${agent.id === currentSelectedAgent ? "active" : ""}`;
        
        card.innerHTML = `
            <div class="agent-card-header">
                <div>
                    <div class="agent-title">Agent ${agent.id}: ${agent.name}</div>
                </div>
                <span class="agent-badge">A${String(agent.id).padStart(2, "0")}</span>
            </div>
            <div class="agent-card-footer">
                <div class="status-tag">
                    <span class="dot waiting" id="dot-${agent.id}"></span>
                    <span id="status-${agent.id}">${agent.implemented ? "Waiting" : "Placeholder"}</span>
                </div>
            </div>
        `;

        card.addEventListener("click", () => {
            selectAgent(agent.id);
        });

        grid.appendChild(card);
    });
}

/**
 * Render the agent status list in the right sidebar.
 */
function renderAgentChecklist() {
    const listContainer = document.getElementById("agentChecklist");
    if (!listContainer) return;

    listContainer.innerHTML = "";
    AGENT_METADATA.filter(a => a.implemented).forEach(agent => {
        const item = document.createElement("div");
        item.className = "checklist-item";
        item.innerHTML = `
            <span class="checklist-name">Agent ${agent.id}: ${agent.name}</span>
            <span class="checklist-status" id="sidebar-status-${agent.id}" style="color: var(--text-dim);">Waiting</span>
        `;
        listContainer.appendChild(item);
    });
}

/**
 * Select and display details for a given agent.
 */
function selectAgent(agentId) {
    currentSelectedAgent = agentId;

    // Update active visual card
    document.querySelectorAll(".agent-card").forEach(c => c.classList.remove("active"));
    const activeCard = document.getElementById(`agent-card-${agentId}`);
    if (activeCard) activeCard.classList.add("active");

    showAgentDetails(agentId);
}

/**
 * Display the evidence detail viewer based on currently cached results.
 */
function showAgentDetails(agentId) {
    const meta = AGENT_METADATA.find(a => a.id === agentId);
    const titleEl = document.getElementById("evidenceAgentTitle");
    const subEl = document.getElementById("evidenceAgentSub");
    const badgeEl = document.getElementById("evidenceStatusBadge");
    const contentEl = document.getElementById("evidenceContent");

    titleEl.innerText = `Agent ${meta.id} — ${meta.name}`;
    subEl.innerText = meta.desc;

    if (!meta.implemented) {
        badgeEl.className = "evidence-status-badge";
        badgeEl.innerText = "Reserved (Future)";
        contentEl.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">🔒</div>
                <p><strong>Agent ${meta.id} is reserved for future implementation.</strong></p>
            </div>
        `;
        return;
    }

    const result = agentResults[agentId];

    if (!result) {
        badgeEl.className = "evidence-status-badge";
        badgeEl.innerText = "Waiting for analysis";
        contentEl.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">🔍</div>
                <p>Provide a target URL or QR code above and start analysis to collect evidence for Agent ${agentId}.</p>
            </div>
        `;
        return;
    }

    // Set badge status
    const badgeClass = (result.status === "completed" || result.status === "success") ? "completed" : result.status;
    badgeEl.className = `evidence-status-badge ${badgeClass}`;
    badgeEl.innerText = (result.status || "COMPLETED").toUpperCase();

    try {
        // Render agent-specific evidence layout
        if (agentId === 1) renderAgent1Evidence(result, contentEl);
        else if (agentId === 2) renderAgent2Evidence(result, contentEl);
        else if (agentId === 3) renderAgent3Evidence(result, contentEl);
        else if (agentId === 4) renderAgent4Evidence(result, contentEl);
        else if (agentId === 5) renderAgent5Evidence(result, contentEl);
        else if (agentId === 6) renderAgent6Evidence(result, contentEl);
        else if (agentId === 7) renderAgent7Evidence(result, contentEl);
        else if (agentId === 8) renderAgent8Evidence(result, contentEl);
        else if (agentId === 9) renderAgent9Evidence(result, contentEl);
        else if (agentId === 10) renderAgent10Evidence(result, contentEl);
        else if (agentId === 11) renderAgent11Evidence(result, contentEl);
        else if (agentId === 12) renderAgent12Evidence(result, contentEl);
        else if (agentId === 13) renderAgent13Evidence(result, contentEl);
        else if (agentId === 14) renderAgent14Evidence(result, contentEl);
        else if (agentId === 15) renderAgent15Evidence(result, contentEl);
        else if (agentId === 16) renderAgent16Evidence(result, contentEl);
        else if (agentId === 17) renderAgent17Evidence(result, contentEl);
        else if (agentId === 18) renderAgent18Evidence(result, contentEl);
    } catch (err) {
        console.error(`Error rendering Agent ${agentId} evidence:`, err);
        contentEl.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">⚠️</div>
                <p><strong>Unable to render Agent ${agentId} evidence.</strong></p>
                <p style="font-size: 11px; color: var(--text-dim); margin-top: 4px;">Please check the browser console for details: ${escapeHtml(err.message)}</p>
            </div>
        `;
    }
}

function updateAgentStatus(agentId, statusClass, statusText) {
    setAgentState(agentId, statusClass, statusText);
}

/**
 * Start the forensic analysis across all 18 independent agents for manual URL.
 */
async function startAnalysis() {
    const urlInput = document.getElementById("urlInput");
    const targetUrl = urlInput.value.trim();

    if (!targetUrl) {
        alert("Please enter a valid URL to analyze.");
        return;
    }

    currentAnalysisSource = "Direct URL";
    currentDecodedTarget = targetUrl;
    currentTargetUrl = targetUrl;
    const banner = document.getElementById("decodedTargetBanner");
    if (banner) banner.style.display = "none";

    const reportCta = document.getElementById("reportCtaContainer");
    if (reportCta) reportCta.style.display = "none";

    const systemStatus = document.getElementById("systemStatus");
    if (systemStatus) systemStatus.innerText = "Collecting forensic evidence across all 18 agents...";

    // Reset Trust score display strictly to non-calculated state
    document.getElementById("trustScore").innerText = "--";
    document.getElementById("trustStatus").innerText = "Evidence Collection Phase";

    await executePipelineOnTarget(targetUrl, 1, 18);
}

/**
 * Run pipeline on target URL across specified agent range
 */
async function executePipelineOnTarget(targetUrl, startAgent = 1, endAgent = 18) {
    const analyzeBtn = document.getElementById("analyzeBtn");
    if (analyzeBtn) analyzeBtn.disabled = true;

    // Set agents to processing state
    for (let i = startAgent; i <= endAgent; i++) {
        setAgentState(i, "processing", "Processing");
    }

    // Run agents
    for (let i = startAgent; i <= endAgent; i++) {
        const meta = AGENT_METADATA.find(a => a.id === i);
        if (!meta || !meta.implemented) continue;

        try {
            const response = await fetch(meta.endpoint, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: targetUrl })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const data = await response.json();
            agentResults[i] = data;

            setAgentState(i, "completed", "Completed");

            // Update viewer if currently selected
            if (currentSelectedAgent === i) {
                showAgentDetails(i);
            }
        } catch (error) {
            console.error(`Agent ${i} error:`, error);
            agentResults[i] = {
                agent: `Agent ${i}`,
                status: "error",
                errors: [{ component: `Agent ${i}`, error: error.message }],
                evidence: []
            };
            setAgentState(i, "error", "Error");
            if (currentSelectedAgent === i) {
                showAgentDetails(i);
            }
        }
    }

    if (analyzeBtn) analyzeBtn.disabled = false;
    const systemStatus = document.getElementById("systemStatus");
    if (systemStatus) systemStatus.innerText = "Evidence collection complete across all 18 agents. Click any card to inspect findings or view Final Report.";

    // Reveal Final Investigator Report CTA button
    const reportCta = document.getElementById("reportCtaContainer");
    if (reportCta) reportCta.style.display = "flex";
}

/**
 * Update UI indicators for an agent's state.
 */
function setAgentState(agentId, statusClass, statusText) {
    const dot = document.getElementById(`dot-${agentId}`);
    const statusLabel = document.getElementById(`status-${agentId}`);
    const sidebarStatus = document.getElementById(`sidebar-status-${agentId}`);

    if (dot) dot.className = `dot ${statusClass}`;
    if (statusLabel) statusLabel.innerText = statusText;

    if (sidebarStatus) {
        sidebarStatus.innerText = statusText;
        if (statusClass === "completed") sidebarStatus.style.color = "var(--accent-emerald)";
        else if (statusClass === "processing") sidebarStatus.style.color = "var(--accent-amber)";
        else if (statusClass === "error") sidebarStatus.style.color = "var(--accent-rose)";
        else sidebarStatus.style.color = "var(--text-dim)";
    }
}

// ----------------------------------------------------
// EVIDENCE RENDERERS FOR AGENTS 1 - 5
// ----------------------------------------------------

function renderListItems(items) {
    if (!items || items.length === 0) {
        return `<span style="color: var(--text-dim);">None detected / Empty</span>`;
    }
    if (Array.isArray(items)) {
        return `
            <ul class="evidence-list">
                ${items.map(item => {
                    if (typeof item === "object" && item !== null) {
                        if (item.priority !== undefined && item.exchange) {
                            return `<li><span style="color: var(--accent-cyan); font-weight:600;">[Priority ${item.priority}]</span> ${escapeHtml(item.exchange)}</li>`;
                        }
                        return `<li>${escapeHtml(JSON.stringify(item))}</li>`;
                    }
                    return `<li>${escapeHtml(String(item))}</li>`;
                }).join("")}
            </ul>
        `;
    }
    if (typeof items === "object") {
        const entries = Object.entries(items);
        if (entries.length === 0) return `<span style="color: var(--text-dim);">None detected / Empty</span>`;
        return `
            <ul class="evidence-list">
                ${entries.map(([key, val]) => {
                    const valStr = Array.isArray(val) ? (val.length ? val.join(", ") : "No PTR record") : String(val);
                    return `<li><strong>${escapeHtml(key)}</strong> &rarr; ${escapeHtml(valStr)}</li>`;
                }).join("")}
            </ul>
        `;
    }
    return `<span style="color: var(--text-secondary);">${escapeHtml(String(items))}</span>`;
}

function renderErrorBlock(errors) {
    if (!errors || errors.length === 0) return "";
    return `
        <div class="evidence-card full-width" style="border-color: rgba(239, 68, 68, 0.4); background: rgba(239, 68, 68, 0.05);">
            <div class="evidence-label" style="color: var(--accent-rose);">Captured Non-Fatal Errors / Warnings</div>
            <ul class="evidence-list" style="color: #fca5a5;">
                ${errors.map(e => `<li>${escapeHtml(e)}</li>`).join("")}
            </ul>
        </div>
    `;
}

function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/* AGENT 1: DOMAIN IDENTITY */
function renderAgent1Evidence(result, container) {
    const d = result.data || {};
    container.innerHTML = `
        <div class="evidence-grid">
            <div class="evidence-card">
                <div class="evidence-label">Domain Name</div>
                <div class="evidence-value highlight">${escapeHtml(d.domain_name || "Not Available")}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">Domain Age</div>
                <div class="evidence-value">${d.domain_age_days !== "Not Available" && d.domain_age_days !== undefined ? `${d.domain_age_days} days (${d.domain_age_years} years)` : "Not Available"}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">Registration Date</div>
                <div class="evidence-value">${escapeHtml(d.registration_date || "Not Available")}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">Expiration Date</div>
                <div class="evidence-value">${escapeHtml(d.expiry_date || "Not Available")}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">Registrar</div>
                <div class="evidence-value">${escapeHtml(d.registrar || "Not Available")}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">WHOIS / RDAP Available</div>
                <div class="evidence-value ${d.whois_available ? "success" : "warning"}">${d.whois_available ? "Yes (Queried successfully)" : "Unavailable / Redacted"}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">Registrant Organization</div>
                <div class="evidence-value">${escapeHtml(d.registrant_organization || "Not Available")}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">Registrant Country</div>
                <div class="evidence-value">${escapeHtml(d.registrant_country || "Not Available")}</div>
            </div>
            <div class="evidence-card full-width">
                <div class="evidence-label">Domain Status Codes</div>
                ${renderListItems(d.domain_status)}
            </div>
            ${renderWhoisInformationBlock(d.whois_information)}
            ${renderErrorBlock(result.errors)}
        </div>
    `;
}

function renderWhoisInformationBlock(whoisInfo) {
    if (!whoisInfo || !whoisInfo.whois_available) {
        return `
            <div class="evidence-card full-width">
                <div class="evidence-label">WHOIS / RDAP Information</div>
                <div class="evidence-value" style="color: var(--text-dim);">Not available — RDAP lookup failed or data was redacted</div>
            </div>
        `;
    }
    return `
        <div class="evidence-card full-width">
            <div class="evidence-label">WHOIS / RDAP Information (Structured)</div>
            <table style="width:100%; border-collapse:collapse; font-size:12px; font-family: var(--font-mono); margin-top:8px;">
                <tbody>
                    ${whoisInfoRow("Registration Date",       whoisInfo.registration_date)}
                    ${whoisInfoRow("Expiry Date",             whoisInfo.expiry_date)}
                    ${whoisInfoRow("Registrar",               whoisInfo.registrar)}
                    ${whoisInfoRow("Registrant Organization", whoisInfo.registrant_organization)}
                    ${whoisInfoRow("Registrant Country",      whoisInfo.registrant_country)}
                    ${whoisInfoRow("Domain Status",           Array.isArray(whoisInfo.domain_status) && whoisInfo.domain_status.length > 0 ? whoisInfo.domain_status.join(", ") : "Not Available")}
                </tbody>
            </table>
        </div>
    `;
}

function whoisInfoRow(label, value) {
    const displayVal = (value && value !== "Not Available") ? escapeHtml(String(value)) : `<span style="color: var(--text-dim);">Not Available</span>`;
    return `
        <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
            <td style="padding: 5px 12px 5px 0; color: var(--text-dim); white-space:nowrap; width:40%;">${escapeHtml(label)}</td>
            <td style="padding: 5px 0; color: var(--text-secondary);">${displayVal}</td>
        </tr>
    `;
}

/* AGENT 2: DNS & INFRASTRUCTURE */
function renderAgent2Evidence(result, container) {
    const d = result.data || {};
    const cdn = d.cdn || { detected: false, provider: null, evidence: [] };
    const dnssec = typeof d.dnssec === "object" && d.dnssec !== null ? d.dnssec : { status: d.dnssec || "Not detected" };
    
    // Format hosting provider
    let hostingDisplay = "Not available";
    if (typeof d.hosting_provider === "object" && d.hosting_provider !== null) {
        const hp = d.hosting_provider;
        const parts = [];
        if (hp.organization && hp.organization !== "Not Available") parts.push(hp.organization);
        if (hp.asn && hp.asn !== "Not Available") parts.push(`(${hp.asn})`);
        if (hp.network && hp.network !== "Not Available" && hp.network !== hp.organization) parts.push(`Net: ${hp.network}`);
        if (hp.country && hp.country !== "Not Available") parts.push(`[${hp.country}]`);
        hostingDisplay = parts.length > 0 ? parts.join(" ") : "Not Available";
    } else if (d.hosting_provider) {
        hostingDisplay = String(d.hosting_provider);
    }

    // Format server IPs
    const allIps = Array.isArray(d.server_ips) && d.server_ips.length > 0 ? d.server_ips.join(", ") : (d.server_ip || "Not available");

    container.innerHTML = `
        <div class="evidence-grid">
            <div class="evidence-card">
                <div class="evidence-label">Resolved Server IP (Primary)</div>
                <div class="evidence-value highlight">${escapeHtml(d.server_ip || "Not available")}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">All Resolved Server IPs</div>
                <div class="evidence-value" style="font-size: 12px;">${escapeHtml(allIps)}</div>
            </div>
            <div class="evidence-card full-width">
                <div class="evidence-label">Hosting Provider / Network (IP &amp; ASN RDAP)</div>
                <div class="evidence-value">${escapeHtml(hostingDisplay)}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">CDN Detection</div>
                <div class="evidence-value ${cdn.detected ? "success" : ""}">${cdn.detected ? `Detected: ${escapeHtml(cdn.provider || "CDN")}` : "Not detected"}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">DNSSEC Status</div>
                <div class="evidence-value ${dnssec.status === "Enabled" ? "success" : ""}">${escapeHtml(dnssec.status || "Not detected")}</div>
            </div>
            ${cdn.detected && cdn.evidence && cdn.evidence.length > 0 ? `
                <div class="evidence-card full-width">
                    <div class="evidence-label">CDN Evidence Corroboration</div>
                    ${renderListItems(cdn.evidence)}
                </div>
            ` : ""}
            <div class="evidence-card">
                <div class="evidence-label">A Records (IPv4)</div>
                ${renderListItems(d.a_records)}
            </div>
            <div class="evidence-card">
                <div class="evidence-label">AAAA Records (IPv6)</div>
                ${renderListItems(d.aaaa_records)}
            </div>
            <div class="evidence-card">
                <div class="evidence-label">MX Records (Mail)</div>
                ${renderListItems(d.mx_records)}
            </div>
            <div class="evidence-card">
                <div class="evidence-label">NS Records (Nameservers)</div>
                ${renderListItems(d.ns_records)}
            </div>
            <div class="evidence-card full-width">
                <div class="evidence-label">TXT Records</div>
                ${renderListItems(d.txt_records)}
            </div>
            <div class="evidence-card full-width">
                <div class="evidence-label">CNAME Records</div>
                ${renderListItems(d.cname_records)}
            </div>
            <div class="evidence-card full-width">
                <div class="evidence-label">Reverse DNS (PTR)</div>
                ${renderListItems(d.reverse_dns)}
            </div>
            ${renderErrorBlock(result.errors)}
        </div>
    `;
}

/* AGENT 3: SSL / HTTPS SECURITY */
function renderAgent3Evidence(result, container) {
    const d = result.data || {};
    const cert = d.ssl_certificate || d.certificate || {};
    const hsts = d.hsts || { enabled: false, header: null };
    const ct = d.certificate_transparency || {};
    const val = d.certificate_validation || { trusted: cert.valid, hostname_match: true };
    const chain = d.certificate_chain || { certificates: [] };
    const exp = d.certificate_expiration || {};
    const cipher = typeof d.cipher_suite === "object" && d.cipher_suite !== null ? d.cipher_suite.name : (d.cipher_suite || "Not available");
    const cipherBits = typeof d.cipher_suite === "object" && d.cipher_suite !== null ? d.cipher_suite.bits : (d.cipher_bits || "");

    const httpsAvail = typeof d.https_availability === "object" && d.https_availability !== null ? d.https_availability.available : (d.https_available || false);
    const httpsStatus = typeof d.https_availability === "object" && d.https_availability !== null ? d.https_availability.status : (httpsAvail ? "available" : "unavailable");

    container.innerHTML = `
        <div class="evidence-grid">
            <div class="evidence-card">
                <div class="evidence-label">HTTPS Availability</div>
                <div class="evidence-value ${httpsAvail ? "success" : "danger"}">${httpsAvail ? `Available (${httpsStatus})` : `Unavailable (${httpsStatus})`}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">Certificate Validity &amp; Trust</div>
                <div class="evidence-value ${val.trusted ? "success" : (cert.present ? "warning" : "danger")}">${cert.present ? (val.trusted ? "Valid &amp; Trusted" : "Present (Unverified / Self-Signed / Expired)") : "Not Present"}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">Certificate Authority (CA)</div>
                <div class="evidence-value highlight">${escapeHtml(d.certificate_authority || cert.issuer || "Not available")}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">Days Until Expiration</div>
                <div class="evidence-value">${exp.days_remaining !== undefined && exp.days_remaining !== "Not Available" ? `${exp.days_remaining} days (${exp.status || "valid"})` : (cert.days_until_expiry !== undefined ? `${cert.days_until_expiry} days` : "Not available")}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">Valid From</div>
                <div class="evidence-value">${escapeHtml(cert.valid_from || "Not available")}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">Valid To (Expires At)</div>
                <div class="evidence-value">${escapeHtml(cert.valid_until || cert.valid_to || exp.expires_at || "Not available")}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">TLS Version Negotiated</div>
                <div class="evidence-value highlight">${escapeHtml(d.tls_version || "Not available")}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">Cipher Suite Negotiated</div>
                <div class="evidence-value">${escapeHtml(cipher)} ${cipherBits ? `(${cipherBits} bits)` : ""}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">HSTS (Strict-Transport-Security)</div>
                <div class="evidence-value ${hsts.enabled ? "success" : ""}">${hsts.enabled ? `Enabled (max-age=${hsts.max_age || "N/A"}${hsts.include_subdomains ? ", includeSubDomains" : ""}${hsts.preload ? ", preload" : ""})` : "Not detected"}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">Certificate Transparency (CT / SCT)</div>
                <div class="evidence-value ${ct.found ? "success" : ""}">${ct.found ? `Found (${ct.log_count} embedded SCTs)` : (ct.details || "Not detected")}</div>
            </div>
            <div class="evidence-card full-width">
                <div class="evidence-label">Hostname Verification</div>
                <div class="evidence-value ${val.hostname_match ? "success" : "warning"}">${val.hostname_match ? `Hostname matches certificate SAN / CN` : `Hostname mismatch / Unverified`}</div>
            </div>
            ${chain.certificates && chain.certificates.length > 0 ? `
                <div class="evidence-card full-width">
                    <div class="evidence-label">Certificate Chain Hierarchy (${chain.certificates.length} certificates)</div>
                    <ul class="evidence-list">
                        ${chain.certificates.map(c => `<li><strong>[${c.type.toUpperCase()}]</strong> Subject: ${escapeHtml(c.subject)} &rarr; Issuer: ${escapeHtml(c.issuer)}</li>`).join("")}
                    </ul>
                </div>
            ` : ""}
            <div class="evidence-card full-width">
                <div class="evidence-label">Subject Alternative Names (SAN)</div>
                <div class="evidence-tags">
                    ${(cert.san_names && cert.san_names.length > 0) ? cert.san_names.map(s => `<span class="evidence-tag">${escapeHtml(s)}</span>`).join("") : `<span style="color: var(--text-dim);">None</span>`}
                </div>
            </div>
            <div class="evidence-card full-width">
                <div class="evidence-label">Serial Number, Algorithm &amp; Key Info</div>
                <div class="evidence-value">${escapeHtml(cert.serial_number || "N/A")} | ${escapeHtml(cert.signature_algorithm || "N/A")} | ${escapeHtml(cert.public_key_type || "")} ${cert.public_key_bits ? `(${cert.public_key_bits} bits)` : ""}</div>
            </div>
            ${renderErrorBlock(result.errors)}
        </div>
    `;
}

/* AGENT 4: WEBSITE CONTENT ANALYSIS */
function renderAgent4Evidence(result, container) {
    const d = result.data || {};
    const broken = d.broken_links || [];
    const missing = d.missing_pages || [];

    const titleVal = typeof d.page_title === "object" && d.page_title !== null ? d.page_title.value : (d.page_title || "Not available");
    const metaDescVal = typeof d.meta_description === "object" && d.meta_description !== null ? d.meta_description.value : (d.meta_description || "Not available");
    const keywordsVal = typeof d.keywords === "object" && d.keywords !== null ? (Array.isArray(d.keywords.values) ? d.keywords.values.join(", ") : (d.keywords.value || "None detected")) : (d.keywords || "None detected");
    const langVal = typeof d.language === "object" && d.language !== null ? `${d.language.name || "Unknown"} (${d.language.code || "N/A"}) [Source: ${d.language.source || "N/A"}]` : (d.language || "Not available");
    const compVal = typeof d.company_name === "object" && d.company_name !== null ? (d.company_name.value ? `${d.company_name.value} [Source: ${d.company_name.source || "N/A"}]` : "Not detected") : (d.company_name || "Not detected");

    const policyHelper = (policyObj) => {
        if (typeof policyObj === "object" && policyObj !== null) {
            return { found: policyObj.present, url: policyObj.url };
        }
        return { found: policyObj && policyObj !== "Not detected", url: policyObj };
    };

    const policyItems = [
        { name: "About Us", ...policyHelper(d.about_page) },
        { name: "Contact Page", ...policyHelper(d.contact_page) },
        { name: "Privacy Policy", ...policyHelper(d.privacy_policy) },
        { name: "Terms & Conditions", ...policyHelper(d.terms_conditions) },
        { name: "Refund Policy", ...policyHelper(d.refund_policy) },
        { name: "Shipping Policy", ...policyHelper(d.shipping_policy) },
        { name: "Cookie Policy", ...policyHelper(d.cookie_policy) }
    ];

    container.innerHTML = `
        <div class="evidence-grid">
            <div class="evidence-card full-width">
                <div class="evidence-label">Page Title</div>
                <div class="evidence-value highlight">${escapeHtml(titleVal || "Not available")}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">Detected Organization / Company</div>
                <div class="evidence-value">${escapeHtml(compVal)}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">Website Language</div>
                <div class="evidence-value">${escapeHtml(langVal)}</div>
            </div>
            <div class="evidence-card full-width">
                <div class="evidence-label">Meta Description</div>
                <div class="evidence-value" style="font-family: var(--font-sans); font-weight: normal; font-size: 13px;">${escapeHtml(metaDescVal || "Not available")}</div>
            </div>
            <div class="evidence-card full-width">
                <div class="evidence-label">Keywords Detected</div>
                <div class="evidence-value" style="font-size: 12px;">${escapeHtml(keywordsVal || "None detected")}</div>
            </div>
            <div class="evidence-card full-width">
                <div class="evidence-label">Essential Navigation &amp; Policy Pages</div>
                <div class="evidence-tags">
                    ${policyItems.map(item => `
                        <span class="evidence-tag ${item.found ? "found" : "missing"}">
                            ${item.name}: ${item.found ? `Found (${escapeHtml(item.url || "")})` : "Not Found"}
                        </span>
                    `).join("")}
                </div>
            </div>
            <div class="evidence-card full-width">
                <div class="evidence-label">Missing Expected Standard Pages (${missing.length})</div>
                <div class="evidence-tags">
                    ${missing.length > 0 ? missing.map(m => `<span class="evidence-tag missing">${escapeHtml(m)}</span>`).join("") : `<span class="evidence-tag found">All standard pages detected</span>`}
                </div>
            </div>
            <div class="evidence-card full-width">
                <div class="evidence-label">Broken Internal Links (${broken.length} detected out of ${d.links_checked || 0} links checked)</div>
                ${broken.length > 0 ? `
                    <ul class="evidence-list">
                        ${broken.map(b => `<li><span style="color: var(--accent-rose);">${escapeHtml(b.url)}</span> (Status: ${b.status_code} ${escapeHtml(b.reason)})</li>`).join("")}
                    </ul>
                ` : `<span style="color: var(--accent-emerald); font-size: 12px; font-family: var(--font-mono);">No broken links detected in tested internal sample (${d.links_checked || 0} links checked)</span>`}
            </div>
            ${renderErrorBlock(result.errors)}
        </div>
    `;
}

/* AGENT 5: URL STRUCTURE ANALYSIS */
function renderAgent5Evidence(result, container) {
    const d = result.data || {};

    const urlLenVal = typeof d.url_length === "object" && d.url_length !== null ? (d.url_length.value || 0) : (d.url_length || 0);
    const lenBreakdown = d.length_analysis || {};
    const ipObj = d.ip_instead_of_domain || {};
    const suspCharsObj = d.suspicious_characters || {};
    const suspCharsList = Array.isArray(suspCharsObj.characters) ? suspCharsObj.characters : (Array.isArray(d.suspicious_characters) ? d.suspicious_characters : []);
    const shortener = d.url_shortener || {};
    const puny = d.punycode_domain || d.punycode || {};
    const homo = d.homograph_detection || d.homograph_attack || {};
    const sub = d.subdomain_analysis || {};
    const queryParams = d.query_parameters || {};
    const suspQueryParams = d.suspicious_query_parameters || {};
    const enc = d.encoded_url || d.encoded_characters || {};
    const red = d.redirect_analysis || d.redirects || {};

    container.innerHTML = `
        <div class="evidence-grid">
            <div class="evidence-card full-width">
                <div class="evidence-label">Analyzed URL</div>
                <div class="evidence-value highlight">${escapeHtml(d.original_url || d.raw_url || "")}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">URL Length Breakdown</div>
                <div class="evidence-value">${urlLenVal} chars <span style="font-size: 11px; color: var(--text-dim);">(Host: ${lenBreakdown.hostname_length || 0}, Path: ${lenBreakdown.path_length || 0}, Query: ${lenBreakdown.query_length || 0})</span></div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">IP Address Hostname</div>
                <div class="evidence-value ${ipObj.detected ? "warning" : ""}">${ipObj.detected ? `Yes (${ipObj.ip_version}: ${ipObj.ip})` : "No (Named Domain)"}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">URL Shortener Service</div>
                <div class="evidence-value ${shortener.detected ? "warning" : ""}">${shortener.detected ? `Detected (${shortener.service})` : "Not detected"}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">Punycode (xn--) Domain</div>
                <div class="evidence-value ${puny.detected ? "warning" : ""}">${puny.detected ? `Yes (${(puny.labels || []).join(", ")})` : "No"}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">Homograph Attack Analysis</div>
                <div class="evidence-value ${homo.detected ? "danger" : ""}">${homo.detected ? `Potential Spoofing Detected: ${escapeHtml(homo.reason || "")}` : "No suspicious Unicode/confusable characters detected"}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">Subdomain Depth</div>
                <div class="evidence-value ${sub.excessive_subdomains ? "warning" : ""}">${sub.subdomain_count || 0} prefix levels (${(sub.subdomains || []).join(".") || "None"}) ${sub.excessive_subdomains ? "[Excessive]" : ""}</div>
            </div>
            <div class="evidence-card full-width">
                <div class="evidence-label">Suspicious Characters In URL</div>
                <div class="evidence-value">${suspCharsObj.detected || suspCharsList.length > 0 ? `Detected: ${suspCharsList.join(", ")}` : "None detected"}</div>
            </div>
            <div class="evidence-card full-width">
                <div class="evidence-label">Query Parameters (${queryParams.count || (queryParams.parameters || []).length || 0} params)</div>
                <div class="evidence-value" style="font-size: 12px;">${(queryParams.parameters || []).join(", ") || "None"}</div>
                ${suspQueryParams.detected && suspQueryParams.parameters && suspQueryParams.parameters.length > 0 ? `
                    <ul class="evidence-list" style="margin-top: 8px;">
                        ${suspQueryParams.parameters.map(p => `<li><span style="color: var(--accent-amber); font-weight: 600;">${escapeHtml(p.name)}:</span> ${escapeHtml(p.reason)}</li>`).join("")}
                    </ul>
                ` : ""}
            </div>
            <div class="evidence-card">
                <div class="evidence-label">Percent &amp; Double Encoding</div>
                <div class="evidence-value ${enc.double_encoding ? "warning" : ""}">${enc.detected ? `Found ${((enc.encoded_sequences || enc.sequences) || []).length} sequence(s) (${((enc.encoded_sequences || enc.sequences) || []).join(", ")}) ${enc.double_encoding ? "[Double Encoding Detected]" : ""}` : "None detected"}</div>
            </div>
            <div class="evidence-card">
                <div class="evidence-label">HTTP Redirects</div>
                <div class="evidence-value">${red.redirect_count || 0} hops ${red.multiple_redirects ? "(Multiple redirects)" : ""}</div>
            </div>
            ${red.redirect_chain && red.redirect_chain.length > 0 ? `
                <div class="evidence-card full-width">
                    <div class="evidence-label">Redirect Chain</div>
                    <ul class="evidence-list">
                        ${red.redirect_chain.map(h => `<li>${h.status_code} &rarr; ${escapeHtml(h.location || h.url)}</li>`).join("")}
                        <li><strong>Final URL:</strong> ${escapeHtml(red.final_url)}</li>
                    </ul>
                </div>
            ` : ""}
            ${renderErrorBlock(result.errors)}
        </div>
    `;
}

/* AGENT 6: REPUTATION & THREAT INTELLIGENCE */
function renderAgent6Evidence(result, container) {
    const d = result.data || result;
    const input = result.input || {};
    const vt = result.virustotal || d.virustotal || {};
    const gsb = result.google_safe_browsing || d.google_safe_browsing || {};
    const pt = result.phishtank || d.phishtank || {};
    const op = result.openphish || d.openphish || {};
    const abuse = result.abuseipdb || d.abuseipdb || {};
    const uh = result.urlhaus || d.urlhaus || {};
    const sh = result.spamhaus || d.spamhaus || {};
    const sa = result.scamadviser || d.scamadviser || {};
    const bl = Array.isArray(result.public_blacklists) ? result.public_blacklists : (Array.isArray(d.public_blacklists) ? d.public_blacklists : []);
    const cr = result.community_reputation || d.community_reputation || {};

    const formatStatusBadge = (status) => {
        if (!status) return `<span class="evidence-tag missing">UNKNOWN</span>`;
        const s = status.toLowerCase();
        if (s === "success") return `<span class="evidence-tag found">SUCCESS</span>`;
        if (s === "not_configured") return `<span class="evidence-tag" style="background: rgba(148, 163, 184, 0.12); color: #cbd5e1; border-color: rgba(148, 163, 184, 0.3);">NOT CONFIGURED</span>`;
        if (s === "not_found") return `<span class="evidence-tag" style="background: rgba(59, 130, 246, 0.12); color: #93c5fd; border-color: rgba(59, 130, 246, 0.25);">NOT FOUND</span>`;
        if (s === "unavailable") return `<span class="evidence-tag" style="background: rgba(100, 116, 139, 0.15); color: #94a3b8; border-color: rgba(100, 116, 139, 0.3);">UNAVAILABLE</span>`;
        if (s === "rate_limited") return `<span class="evidence-tag warning">RATE LIMITED</span>`;
        if (s === "timeout") return `<span class="evidence-tag warning">TIMEOUT</span>`;
        return `<span class="evidence-tag missing">${escapeHtml(status.toUpperCase())}</span>`;
    };

    container.innerHTML = `
        <div class="evidence-grid">

            <!-- INPUT SUMMARY CARD -->
            <div class="evidence-card full-width" style="border-left: 3px solid var(--accent-cyan);">
                <div class="evidence-label">Target Investigated</div>
                <div class="evidence-value highlight" style="font-size: 14px;">${escapeHtml(input.url || d.url || "")}</div>
                <div style="font-size: 12px; color: var(--text-dim); margin-top: 4px; font-family: var(--font-mono);">
                    Domain: <strong style="color: var(--text-main);">${escapeHtml(input.domain || d.domain || "N/A")}</strong> | 
                    Resolved IP: <strong style="color: var(--text-main);">${escapeHtml(input.ip || d.ip || "Not resolved")}</strong>
                </div>
            </div>

            <!-- 1. VIRUSTOTAL -->
            <div class="evidence-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <div class="evidence-label" style="margin-bottom: 0;">1. VirusTotal</div>
                    ${formatStatusBadge(vt.status)}
                </div>
                ${vt.status === "success" ? `
                    <div class="evidence-value ${vt.malicious > 0 ? "danger" : "success"}">
                        ${vt.malicious} malicious / ${vt.suspicious} suspicious / ${vt.harmless} harmless (Total: ${vt.total_engines} engines)
                    </div>
                    <div style="font-size: 11px; color: var(--text-dim); margin-top: 4px;">
                        Reputation: ${vt.reputation} | Last Analysis: ${escapeHtml(vt.last_analysis || "N/A")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">
                        ${escapeHtml(vt.message || (vt.status === "not_configured" ? "API key not configured" : "No report available"))}
                    </div>
                `}
            </div>

            <!-- 2. GOOGLE SAFE BROWSING -->
            <div class="evidence-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <div class="evidence-label" style="margin-bottom: 0;">2. Google Safe Browsing</div>
                    ${formatStatusBadge(gsb.status)}
                </div>
                ${gsb.status === "success" ? `
                    <div class="evidence-value ${gsb.threat_detected ? "danger" : "success"}">
                        ${gsb.threat_detected ? "Threat Detected" : "No Threat Detected"}
                    </div>
                    <div class="evidence-tags" style="margin-top: 4px;">
                        ${(gsb.threat_types && gsb.threat_types.length > 0) ? gsb.threat_types.map(t => `<span class="evidence-tag missing">${escapeHtml(t)}</span>`).join("") : `<span class="evidence-tag found">Clean</span>`}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">
                        ${escapeHtml(gsb.message || (gsb.status === "not_configured" ? "API key not configured" : "Service unavailable"))}
                    </div>
                `}
            </div>

            <!-- 3. PHISHTANK -->
            <div class="evidence-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <div class="evidence-label" style="margin-bottom: 0;">3. PhishTank</div>
                    ${formatStatusBadge(pt.status)}
                </div>
                ${pt.status === "success" ? `
                    <div class="evidence-value ${pt.found ? (pt.verified_phishing ? "danger" : "warning") : "success"}">
                        ${pt.found ? `Found in Database (${pt.verified_phishing ? "Verified Phishing" : "Unverified Submission"})` : "Not Found in PhishTank"}
                    </div>
                    ${pt.verification_date ? `<div style="font-size: 11px; color: var(--text-dim); margin-top: 4px;">Verified at: ${escapeHtml(pt.verification_date)}</div>` : ""}
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">
                        ${escapeHtml(pt.message || (pt.status === "not_configured" ? "API key not configured" : "Lookup unavailable"))}
                    </div>
                `}
            </div>

            <!-- 4. OPENPHISH -->
            <div class="evidence-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <div class="evidence-label" style="margin-bottom: 0;">4. OpenPhish</div>
                    ${formatStatusBadge(op.status)}
                </div>
                ${op.status === "success" ? `
                    <div class="evidence-value ${op.found ? "danger" : "success"}">
                        ${op.found ? "Matched OpenPhish Threat Feed" : "Not Found in OpenPhish Feed"}
                    </div>
                    ${op.matched_url ? `<div style="font-size: 11px; color: var(--accent-rose); margin-top: 4px; word-break: break-all;">Match: ${escapeHtml(op.matched_url)}</div>` : ""}
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">
                        ${escapeHtml(op.message || "Feed unavailable")}
                    </div>
                `}
            </div>

            <!-- 5. ABUSEIPDB -->
            <div class="evidence-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <div class="evidence-label" style="margin-bottom: 0;">5. AbuseIPDB (IP Reputation)</div>
                    ${formatStatusBadge(abuse.status)}
                </div>
                ${abuse.status === "success" ? `
                    <div class="evidence-value ${abuse.abuse_confidence_score > 0 ? "warning" : "success"}">
                        Abuse Confidence Score: ${abuse.abuse_confidence_score}% (${abuse.total_reports} reports)
                    </div>
                    <div style="font-size: 11px; color: var(--text-dim); margin-top: 4px;">
                        ISP: ${escapeHtml(abuse.isp || "N/A")} | Type: ${escapeHtml(abuse.usage_type || "N/A")} | Country: ${escapeHtml(abuse.country || "N/A")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">
                        ${escapeHtml(abuse.message || (abuse.status === "not_configured" ? "API key not configured" : "No IP reputation available"))}
                    </div>
                `}
            </div>

            <!-- 6. URLHAUS -->
            <div class="evidence-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <div class="evidence-label" style="margin-bottom: 0;">6. URLHaus (abuse.ch)</div>
                    ${formatStatusBadge(uh.status)}
                </div>
                ${uh.status === "success" ? `
                    <div class="evidence-value ${(uh.url_found || uh.host_found) ? "danger" : "success"}">
                        ${(uh.url_found || uh.host_found) ? `Malware Threat Detected (Threat: ${escapeHtml(uh.threat || "malware")})` : "Clean / Not Listed in URLHaus"}
                    </div>
                    <div style="font-size: 11px; color: var(--text-dim); margin-top: 4px;">
                        URL Listed: ${uh.url_found ? "Yes" : "No"} | Host Listed: ${uh.host_found ? "Yes" : "No"} ${uh.date_added ? `| Added: ${escapeHtml(uh.date_added)}` : ""}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">
                        ${escapeHtml(uh.message || "Lookup unavailable")}
                    </div>
                `}
            </div>

            <!-- 7. SPAMHAUS -->
            <div class="evidence-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <div class="evidence-label" style="margin-bottom: 0;">7. Spamhaus Reputation</div>
                    ${formatStatusBadge(sh.status)}
                </div>
                ${sh.status === "success" ? `
                    <div class="evidence-value ${sh.listed ? "danger" : "success"}">
                        ${sh.listed ? `Listed on Spamhaus (${sh.lists.length} lists)` : "Not Listed on Spamhaus"}
                    </div>
                    ${(sh.lists && sh.lists.length > 0) ? `
                        <ul class="evidence-list" style="margin-top: 4px;">
                            ${sh.lists.map(l => `<li><strong style="color: var(--accent-rose);">${escapeHtml(l.name)}</strong>: ${escapeHtml(l.reason)}</li>`).join("")}
                        </ul>
                    ` : ""}
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">
                        ${escapeHtml(sh.message || (sh.status === "not_configured" ? "Spamhaus DQS key not configured" : "Service unavailable"))}
                    </div>
                `}
            </div>

            <!-- 8. SCAMADVISER -->
            <div class="evidence-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <div class="evidence-label" style="margin-bottom: 0;">8. ScamAdviser</div>
                    ${formatStatusBadge(sa.status)}
                </div>
                ${sa.status === "success" ? `
                    <div class="evidence-value">
                        Trust Indicator: ${sa.trust_score_indicator !== undefined ? `${sa.trust_score_indicator}/100` : "Available"}
                    </div>
                    <div style="font-size: 11px; color: var(--text-dim); margin-top: 4px;">
                        Domain Age: ${sa.domain_age_days ? `${sa.domain_age_days} days` : "N/A"}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">
                        ${escapeHtml(sa.reason || "No permitted API configured")}
                    </div>
                `}
            </div>

            <!-- 9. PUBLIC BLACKLISTS -->
            <div class="evidence-card full-width">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <div class="evidence-label" style="margin-bottom: 0;">9. Public Blacklists &amp; DNSBL Feeds (${bl.length} sources queried)</div>
                    <span class="evidence-tag found">MODULAR ENGINE</span>
                </div>
                ${bl.length > 0 ? `
                    <div style="overflow-x: auto;">
                        <table style="width: 100%; border-collapse: collapse; font-size: 12px; font-family: var(--font-mono);">
                            <thead>
                                <tr style="border-bottom: 1px solid rgba(255,255,255,0.1); color: var(--text-dim); text-align: left;">
                                    <th style="padding: 6px 8px;">Source</th>
                                    <th style="padding: 6px 8px;">Target</th>
                                    <th style="padding: 6px 8px;">Type</th>
                                    <th style="padding: 6px 8px;">Category</th>
                                    <th style="padding: 6px 8px;">Result</th>
                                    <th style="padding: 6px 8px;">Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${bl.map(b => `
                                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
                                        <td style="padding: 5px 8px; font-weight: 600; color: var(--text-main);">${escapeHtml(b.source)}</td>
                                        <td style="padding: 5px 8px; color: var(--text-secondary);">${escapeHtml(b.query)}</td>
                                        <td style="padding: 5px 8px; color: var(--text-dim); text-transform: uppercase;">${escapeHtml(b.type)}</td>
                                        <td style="padding: 5px 8px; color: var(--text-dim);">${escapeHtml(b.category || "reputation")}</td>
                                        <td style="padding: 5px 8px;">
                                            <span class="evidence-tag ${b.listed ? "missing" : "found"}" style="padding: 1px 6px;">
                                                ${b.listed ? "LISTED" : "Clean"}
                                            </span>
                                        </td>
                                        <td style="padding: 5px 8px; color: var(--text-dim);">${escapeHtml(b.source_status || "success")}</td>
                                    </tr>
                                `).join("")}
                            </tbody>
                        </table>
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No DNSBL or public blacklist sources available for this target.</div>
                `}
            </div>

            <!-- 10. COMMUNITY REPUTATION -->
            <div class="evidence-card full-width">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <div class="evidence-label" style="margin-bottom: 0;">10. Community Reputation</div>
                    ${formatStatusBadge(cr.status)}
                </div>
                ${cr.status === "success" ? `
                    <div class="evidence-value">
                        Source: ${escapeHtml(cr.source || "Community Feed")} | Pulses: ${cr.pulse_count || 0} (${cr.community_references || 0} references)
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">
                        ${escapeHtml(cr.reason || "No configured community reputation source")}
                    </div>
                `}
            </div>

            ${renderErrorBlock(result.errors)}
        </div>
    `;
}

/* AGENT 7: TECHNICAL FINGERPRINTING */
function renderAgent7Evidence(result, container) {
    const input = result.input || {};
    const ws = result.web_server || {};
    const cms = result.cms || {};
    const frameworks = Array.isArray(result.frameworks) ? result.frameworks : [];
    const jsLibs = Array.isArray(result.javascript_libraries) ? result.javascript_libraries : [];
    const analytics = Array.isArray(result.analytics) ? result.analytics : [];
    const thirdParty = Array.isArray(result.third_party_services) ? result.third_party_services : [];
    const tracking = Array.isArray(result.tracking_scripts) ? result.tracking_scripts : [];
    const adminPanels = Array.isArray(result.admin_panels) ? result.admin_panels : [];
    const openDirs = Array.isArray(result.open_directories) ? result.open_directories : [];
    const red = result.redirects || { count: 0, chain: [] };

    container.innerHTML = `
        <div class="evidence-grid">

            <!-- INPUT SUMMARY CARD -->
            <div class="evidence-card full-width" style="border-left: 3px solid var(--accent-cyan);">
                <div class="evidence-label">Target Investigated</div>
                <div class="evidence-value highlight" style="font-size: 14px;">${escapeHtml(input.original_url || "")}</div>
                <div style="font-size: 12px; color: var(--text-dim); margin-top: 4px; font-family: var(--font-mono);">
                    Final URL: <strong style="color: var(--text-main);">${escapeHtml(input.final_url || input.original_url || "")}</strong> 
                    ${red.count > 0 ? `(${red.count} redirect hops)` : ""}
                </div>
            </div>

            <!-- 1. WEB SERVER -->
            <div class="evidence-card">
                <div class="evidence-label">1. Web Server Detection</div>
                ${ws.status === "detected" ? `
                    <div class="evidence-value highlight">${escapeHtml(ws.name || "Unknown Server")}</div>
                    <div style="font-size: 11px; color: var(--text-dim); margin-top: 4px;">
                        Version: <strong style="color: var(--text-main);">${escapeHtml(ws.version || "Not exposed / Hidden")}</strong> | 
                        Source: ${escapeHtml(ws.source || "HTTP header")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim);">No server header signature detected</div>
                `}
            </div>

            <!-- 2. CMS DETECTION -->
            <div class="evidence-card">
                <div class="evidence-label">2. Content Management System (CMS)</div>
                ${cms.status === "detected" ? `
                    <div class="evidence-value highlight">${escapeHtml(cms.name || "Detected")}</div>
                    <div style="font-size: 11px; color: var(--text-dim); margin-top: 4px;">
                        Version: <strong style="color: var(--text-main);">${escapeHtml(cms.version || "Not detected")}</strong>
                    </div>
                    ${cms.evidence && cms.evidence.length > 0 ? `
                        <div class="evidence-tags" style="margin-top: 4px;">
                            ${cms.evidence.map(e => `<span class="evidence-tag found">${escapeHtml(e)}</span>`).join("")}
                        </div>
                    ` : ""}
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim);">No standard CMS signature detected</div>
                `}
            </div>

            <!-- 3. FRAMEWORKS -->
            <div class="evidence-card full-width">
                <div class="evidence-label">3. Application Frameworks (${frameworks.length} detected)</div>
                ${frameworks.length > 0 ? `
                    <div class="evidence-tags">
                        ${frameworks.map(f => `
                            <span class="evidence-tag found" style="padding: 4px 10px; font-size: 12px;">
                                <strong>${escapeHtml(f.name)}</strong>${f.version ? ` (${escapeHtml(f.version)})` : ""}
                                ${f.evidence && f.evidence.length > 0 ? `<span style="opacity: 0.7; font-size: 11px;"> [${escapeHtml(f.evidence.join(", "))}]</span>` : ""}
                            </span>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No specific frontend/backend framework signatures detected</div>
                `}
            </div>

            <!-- 4. JAVASCRIPT LIBRARIES -->
            <div class="evidence-card">
                <div class="evidence-label">4. JavaScript Libraries (${jsLibs.length} detected)</div>
                ${jsLibs.length > 0 ? `
                    <ul class="evidence-list">
                        ${jsLibs.map(lib => `
                            <li>
                                <strong style="color: var(--accent-cyan);">${escapeHtml(lib.name)}</strong>
                                ${lib.version ? `<span style="color: var(--text-main);"> v${escapeHtml(lib.version)}</span>` : `<span style="color: var(--text-dim);"> (version not in URL)</span>`}
                            </li>
                        `).join("")}
                    </ul>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">None detected in loaded scripts</div>
                `}
            </div>

            <!-- 5. ANALYTICS SCRIPTS -->
            <div class="evidence-card">
                <div class="evidence-label">5. Analytics Platforms (${analytics.length} detected)</div>
                ${analytics.length > 0 ? `
                    <ul class="evidence-list">
                        ${analytics.map(a => `
                            <li>
                                <strong style="color: var(--accent-emerald);">${escapeHtml(a.name)}</strong>
                                ${a.tracking_id ? `<span style="color: #6ee7b7; font-size: 11px;"> [ID: ${escapeHtml(a.tracking_id)}]</span>` : ""}
                            </li>
                        `).join("")}
                    </ul>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No analytics tags detected</div>
                `}
            </div>

            <!-- 6. THIRD-PARTY SERVICES -->
            <div class="evidence-card">
                <div class="evidence-label">6. Third-Party Services (${thirdParty.length} detected)</div>
                ${thirdParty.length > 0 ? `
                    <ul class="evidence-list">
                        ${thirdParty.map(tp => `
                            <li>
                                <strong>${escapeHtml(tp.name)}</strong>
                                <span style="color: var(--text-dim); font-size: 11px;">(${escapeHtml(tp.category)})</span>
                            </li>
                        `).join("")}
                    </ul>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">None detected</div>
                `}
            </div>

            <!-- 7. TRACKING SCRIPTS -->
            <div class="evidence-card">
                <div class="evidence-label">7. Marketing &amp; Tracking Pixels (${tracking.length} detected)</div>
                ${tracking.length > 0 ? `
                    <ul class="evidence-list">
                        ${tracking.map(t => `
                            <li>
                                <strong style="color: var(--accent-amber);">${escapeHtml(t.name)}</strong>
                                <span style="color: var(--text-dim); font-size: 11px;"> - ${escapeHtml(t.evidence || "script")}</span>
                            </li>
                        `).join("")}
                    </ul>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No marketing tracking pixels detected</div>
                `}
            </div>

            <!-- 8. EXPOSED ADMIN PANELS -->
            <div class="evidence-card full-width">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <div class="evidence-label" style="margin-bottom: 0;">8. Administrative &amp; Login Path Checks (${adminPanels.length} tested paths)</div>
                    <span class="evidence-tag found">PASSIVE SCAN ONLY</span>
                </div>
                <div style="overflow-x: auto;">
                    <table style="width: 100%; border-collapse: collapse; font-size: 12px; font-family: var(--font-mono);">
                        <thead>
                            <tr style="border-bottom: 1px solid rgba(255,255,255,0.1); color: var(--text-dim); text-align: left;">
                                <th style="padding: 6px 8px;">Path</th>
                                <th style="padding: 6px 8px;">HTTP Status</th>
                                <th style="padding: 6px 8px;">Detection Result</th>
                                <th style="padding: 6px 8px;">Final URL</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${adminPanels.map(p => {
                                let tagClass = "found";
                                let tagText = "Not Detected";
                                if (p.detected === true) {
                                    tagClass = "missing";
                                    tagText = "EXPOSED / DETECTED";
                                } else if (p.detected === "possibly_protected") {
                                    tagClass = "warning";
                                    tagText = "POSSIBLY PROTECTED (403/401)";
                                } else if (p.detected === "timeout") {
                                    tagClass = "warning";
                                    tagText = "TIMEOUT";
                                }
                                return `
                                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
                                        <td style="padding: 5px 8px; font-weight: 600; color: var(--text-main);">${escapeHtml(p.path)}</td>
                                        <td style="padding: 5px 8px; color: var(--text-secondary);">${p.status_code !== null && p.status_code !== undefined ? p.status_code : "N/A"}</td>
                                        <td style="padding: 5px 8px;">
                                            <span class="evidence-tag ${tagClass}" style="padding: 1px 6px;">
                                                ${tagText}
                                            </span>
                                        </td>
                                        <td style="padding: 5px 8px; color: var(--text-dim); font-size: 11px;">${escapeHtml(p.final_url || "")}</td>
                                    </tr>
                                `;
                            }).join("")}
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- 9. OPEN DIRECTORIES -->
            <div class="evidence-card full-width">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <div class="evidence-label" style="margin-bottom: 0;">9. Open Directory Listings Check (${openDirs.length} paths inspected)</div>
                    <span class="evidence-tag found">PASSIVE SCAN ONLY</span>
                </div>
                <div style="overflow-x: auto;">
                    <table style="width: 100%; border-collapse: collapse; font-size: 12px; font-family: var(--font-mono);">
                        <thead>
                            <tr style="border-bottom: 1px solid rgba(255,255,255,0.1); color: var(--text-dim); text-align: left;">
                                <th style="padding: 6px 8px;">Path</th>
                                <th style="padding: 6px 8px;">HTTP Status</th>
                                <th style="padding: 6px 8px;">Directory Listing</th>
                                <th style="padding: 6px 8px;">Evidence Notes</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${openDirs.map(d => {
                                let tagClass = "found";
                                let tagText = "No Listing Detected";
                                if (d.directory_listing === true) {
                                    tagClass = "missing";
                                    tagText = "OPEN DIRECTORY DETECTED";
                                } else if (d.directory_listing === "unknown") {
                                    tagClass = "warning";
                                    tagText = "Restricted (403/401)";
                                } else if (d.directory_listing === "timeout") {
                                    tagClass = "warning";
                                    tagText = "Timeout";
                                }
                                return `
                                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
                                        <td style="padding: 5px 8px; font-weight: 600; color: var(--text-main);">${escapeHtml(d.path)}</td>
                                        <td style="padding: 5px 8px; color: var(--text-secondary);">${d.status_code !== null && d.status_code !== undefined ? d.status_code : "N/A"}</td>
                                        <td style="padding: 5px 8px;">
                                            <span class="evidence-tag ${tagClass}" style="padding: 1px 6px;">
                                                ${tagText}
                                            </span>
                                        </td>
                                        <td style="padding: 5px 8px; color: var(--text-dim); font-size: 11px;">${escapeHtml(d.evidence || "Standard response")}</td>
                                    </tr>
                                `;
                            }).join("")}
                        </tbody>
                    </table>
                </div>
            </div>

            ${renderErrorBlock(result.errors)}
        </div>
    `;
}

/* AGENT 8: WEBSITE BEHAVIOR ANALYSIS */
function renderAgent8Evidence(result, container) {
    const input = result.input || {};
    const redirects = result.automatic_redirects || {};
    const popups = result.popups || {};
    const downloads = result.forced_downloads || {};
    const jsIndicators = result.javascript_indicators || {};
    const forms = Array.isArray(result.forms) ? result.forms : [];
    const hiddenForms = Array.isArray(result.hidden_forms) ? result.hidden_forms : [];
    const credHarvesting = result.credential_harvesting_indicators || {};
    const fakeLogin = result.fake_login_indicators || {};

    const clientRedirects = Array.isArray(redirects.client_side_redirects) ? redirects.client_side_redirects : [];
    const forcedFiles = Array.isArray(downloads.downloads) ? downloads.downloads : [];
    const jsList = Array.isArray(jsIndicators.indicators) ? jsIndicators.indicators : [];
    const credList = Array.isArray(credHarvesting.indicators) ? credHarvesting.indicators : [];
    const fakeList = Array.isArray(fakeLogin.indicators) ? fakeLogin.indicators : [];

    container.innerHTML = `
        <div class="evidence-grid">

            <!-- INPUT SUMMARY CARD -->
            <div class="evidence-card full-width" style="border-left: 3px solid var(--accent-cyan);">
                <div class="evidence-label">Target Investigated</div>
                <div class="evidence-value highlight" style="font-size: 14px;">${escapeHtml(input.original_url || "")}</div>
                <div style="font-size: 12px; color: var(--text-dim); margin-top: 4px; font-family: var(--font-mono);">
                    Final URL: <strong style="color: var(--text-main);">${escapeHtml(input.final_url || input.original_url || "")}</strong> 
                    ${redirects.count > 0 ? `(${redirects.count} total redirects)` : ""}
                </div>
            </div>

            <!-- 1. AUTOMATIC REDIRECTS -->
            <div class="evidence-card">
                <div class="evidence-label">1. Automatic Redirects</div>
                <div class="evidence-value ${redirects.detected ? "warning" : "success"}">
                    ${redirects.detected ? `Detected (${redirects.count || 0} redirects)` : "No automatic redirects"}
                </div>
                ${redirects.chain && redirects.chain.length > 1 ? `
                    <div style="font-size: 11px; color: var(--text-dim); margin-top: 4px;">
                        HTTP Chain: ${escapeHtml(redirects.chain.join(" → "))}
                    </div>
                ` : ""}
                ${clientRedirects.length > 0 ? `
                    <div class="evidence-tags" style="margin-top: 4px;">
                        ${clientRedirects.map(cr => `<span class="evidence-tag warning">[${escapeHtml(cr.method)}] ${escapeHtml(cr.target)}</span>`).join("")}
                    </div>
                ` : ""}
            </div>

            <!-- 2. POP-UPS -->
            <div class="evidence-card">
                <div class="evidence-label">2. Pop-up &amp; Overlay Behavior</div>
                <div class="evidence-value ${popups.detected ? "warning" : "success"}">
                    ${popups.detected ? `Detected (${popups.count || popups.evidence.length} triggers)` : "No popups or unexpected windows"}
                </div>
                ${popups.evidence && popups.evidence.length > 0 ? `
                    <ul class="evidence-list" style="margin-top: 4px;">
                        ${popups.evidence.map(e => `<li>${escapeHtml(e)}</li>`).join("")}
                    </ul>
                ` : ""}
            </div>

            <!-- 3. FORCED DOWNLOADS -->
            <div class="evidence-card full-width">
                <div class="evidence-label">3. Forced &amp; Automatic Downloads</div>
                <div class="evidence-value ${downloads.detected ? "danger" : "success"}">
                    ${downloads.detected ? `Attempted (${forcedFiles.length} file triggers)` : "No automatic or forced downloads detected"}
                </div>
                ${forcedFiles.length > 0 ? `
                    <div style="overflow-x: auto; margin-top: 6px;">
                        <table style="width: 100%; border-collapse: collapse; font-size: 12px; font-family: var(--font-mono);">
                            <thead>
                                <tr style="border-bottom: 1px solid rgba(255,255,255,0.1); color: var(--text-dim); text-align: left;">
                                    <th style="padding: 4px 8px;">File Name</th>
                                    <th style="padding: 4px 8px;">Extension</th>
                                    <th style="padding: 4px 8px;">Trigger</th>
                                    <th style="padding: 4px 8px;">Flag</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${forcedFiles.map(f => `
                                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
                                        <td style="padding: 4px 8px; font-weight: 600; color: var(--text-main);">${escapeHtml(f.file_name)}</td>
                                        <td style="padding: 4px 8px; color: var(--text-dim);">${escapeHtml(f.extension || "N/A")}</td>
                                        <td style="padding: 4px 8px; color: var(--text-secondary);">${escapeHtml(f.trigger)}</td>
                                        <td style="padding: 4px 8px;">
                                            <span class="evidence-tag ${f.suspicious_extension ? "missing" : "found"}">
                                                ${f.suspicious_extension ? "SUSPICIOUS EXECUTABLE" : "Standard File"}
                                            </span>
                                        </td>
                                    </tr>
                                `).join("")}
                            </tbody>
                        </table>
                    </div>
                ` : ""}
            </div>

            <!-- 4. MALICIOUS / SUSPICIOUS JS INDICATORS -->
            <div class="evidence-card full-width">
                <div class="evidence-label">4. JavaScript Execution &amp; Obfuscation Indicators</div>
                <div class="evidence-value ${jsIndicators.detected ? "warning" : "success"}">
                    ${jsIndicators.detected ? `Detected (${jsList.length} suspicious patterns)` : "Clean standard JavaScript (no obfuscation or dynamic eval detected)"}
                </div>
                ${jsList.length > 0 ? `
                    <ul class="evidence-list" style="margin-top: 6px;">
                        ${jsList.map(js => `
                            <li>
                                <strong style="color: var(--accent-amber);">${escapeHtml(js.type)}:</strong> 
                                ${escapeHtml(js.evidence)}
                            </li>
                        `).join("")}
                    </ul>
                ` : ""}
            </div>

            <!-- 5. FORM SUBMISSION BEHAVIOR -->
            <div class="evidence-card full-width">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <div class="evidence-label" style="margin-bottom: 0;">5. Form Submission Behavior (${forms.length} forms inspected)</div>
                    <span class="evidence-tag found">PASSIVE STRUCTURE ANALYSIS</span>
                </div>
                ${forms.length > 0 ? `
                    <div style="overflow-x: auto;">
                        <table style="width: 100%; border-collapse: collapse; font-size: 12px; font-family: var(--font-mono);">
                            <thead>
                                <tr style="border-bottom: 1px solid rgba(255,255,255,0.1); color: var(--text-dim); text-align: left;">
                                    <th style="padding: 6px 8px;">#</th>
                                    <th style="padding: 6px 8px;">Action Destination</th>
                                    <th style="padding: 6px 8px;">Method</th>
                                    <th style="padding: 6px 8px;">Origin Target</th>
                                    <th style="padding: 6px 8px;">HTTPS</th>
                                    <th style="padding: 6px 8px;">Password</th>
                                    <th style="padding: 6px 8px;">Fields</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${forms.map(f => `
                                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
                                        <td style="padding: 5px 8px; color: var(--text-dim);">#${f.form_index}</td>
                                        <td style="padding: 5px 8px; font-weight: 600; color: var(--text-main); word-break: break-all;">${escapeHtml(f.action)}</td>
                                        <td style="padding: 5px 8px; color: var(--accent-cyan); font-weight: 600;">${escapeHtml(f.method)}</td>
                                        <td style="padding: 5px 8px;">
                                            <span class="evidence-tag ${f.cross_domain_submission ? "missing" : "found"}">
                                                ${f.cross_domain_submission ? `Cross-Origin (${escapeHtml(f.destination_domain)})` : "Same Origin"}
                                            </span>
                                        </td>
                                        <td style="padding: 5px 8px; color: ${f.uses_https ? "var(--accent-emerald)" : "var(--accent-rose)"};">
                                            ${f.uses_https ? "Yes" : "HTTP (No)"}
                                        </td>
                                        <td style="padding: 5px 8px; color: ${f.has_password_field ? "var(--accent-amber)" : "var(--text-dim)"};">
                                            ${f.has_password_field ? "Yes" : "No"}
                                        </td>
                                        <td style="padding: 5px 8px; color: var(--text-dim); font-size: 11px;">
                                            ${f.field_count} fields (${escapeHtml(f.fields.slice(0, 4).join(", "))}${f.fields.length > 4 ? "..." : ""})
                                        </td>
                                    </tr>
                                `).join("")}
                            </tbody>
                        </table>
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No HTML forms detected on this webpage</div>
                `}
            </div>

            <!-- 6. HIDDEN FORMS & FIELDS -->
            <div class="evidence-card">
                <div class="evidence-label">6. Hidden Forms &amp; Inputs (${hiddenForms.length} forms with hidden fields)</div>
                ${hiddenForms.length > 0 ? `
                    <ul class="evidence-list">
                        ${hiddenForms.map(hf => `
                            <li>
                                <strong>Form #${hf.form_index}:</strong> 
                                ${hf.hidden_field_count} hidden field(s) (${escapeHtml(hf.hidden_fields.join(", "))})
                            </li>
                        `).join("")}
                    </ul>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No hidden input fields detected</div>
                `}
            </div>

            <!-- 7. CREDENTIAL HARVESTING INDICATORS -->
            <div class="evidence-card">
                <div class="evidence-label">7. Credential Harvesting Indicators</div>
                <div class="evidence-value ${credHarvesting.detected ? "warning" : "success"}">
                    ${credHarvesting.detected ? `Detected (${credList.length} indicators)` : "No suspicious credential harvesting indicators"}
                </div>
                ${credList.length > 0 ? `
                    <ul class="evidence-list" style="margin-top: 4px;">
                        ${credList.map(ci => `<li><span style="color: var(--accent-amber);">${escapeHtml(ci)}</span></li>`).join("")}
                    </ul>
                ` : ""}
            </div>

            <!-- 8. FAKE LOGIN PAGE INDICATORS -->
            <div class="evidence-card full-width">
                <div class="evidence-label">8. Fake Login Page &amp; Brand Impersonation Indicators</div>
                <div class="evidence-value ${fakeLogin.potential_fake_login ? "danger" : (fakeLogin.detected ? "warning" : "success")}">
                    ${fakeLogin.potential_fake_login ? "Potential Fake Login Page Indicators Detected" : (fakeLogin.detected ? "Behavioral Indicators Present" : "No fake login page signatures detected")}
                </div>
                ${fakeList.length > 0 ? `
                    <ul class="evidence-list" style="margin-top: 6px;">
                        ${fakeList.map(fi => `<li><strong style="color: var(--accent-rose);">&bull;</strong> ${escapeHtml(fi)}</li>`).join("")}
                    </ul>
                ` : ""}
            </div>

            ${renderErrorBlock(result.errors)}
        </div>
    `;
}

/**
 * Render Evidence Details for Agent 9: Brand Verification
 */
function renderAgent9Evidence(result, container) {
    if (!result || result.status === "error") {
        container.innerHTML = `
            <div class="evidence-grid">
                <div class="evidence-card full-width danger">
                    <div class="evidence-label">Agent 9 Error</div>
                    <div class="evidence-value danger">Failed to execute brand verification analysis</div>
                </div>
                ${renderErrorBlock(result ? result.errors : ["Unknown error"])}
            </div>
        `;
        return;
    }

    const inputData = result.input || {};
    const brandName = result.brand_name_matching || { detected: false, candidate_brands: [] };
    const candidates = brandName.candidate_brands || [];
    const logo = result.logo || { detected: false };
    const logoSim = result.logo_similarity || { status: "not_available", matches: [] };
    const favicon = result.favicon || { detected: false };
    const favSim = result.favicon_similarity || { status: "not_available", matches: [] };
    const colorTheme = result.color_theme || { status: "not_available", dominant_colors: [], matches: [] };
    const dominantColors = colorTheme.dominant_colors || [];
    const layout = result.layout_similarity || { status: "not_available", matches: [] };
    const trademark = result.trademark_matching || { status: "not_available", matches: [] };
    const officialDom = result.official_domain_comparison || { status: "not_available" };
    const brandEvidence = result.brand_evidence || [];

    const primaryBrand = candidates.length > 0 ? candidates[0].brand : (officialDom.candidate_brand || "None Detected");

    container.innerHTML = `
        <div class="evidence-grid">
            <!-- TARGET DOMAIN & PRIMARY BRAND SUMMARY -->
            <div class="evidence-card full-width">
                <div class="evidence-label">Agent 9 &bull; Brand Forensic Identification Summary</div>
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-top: 4px;">
                    <div>
                        <span style="font-size: 13px; color: var(--text-dim);">Candidate Brand:</span>
                        <strong style="font-size: 16px; color: ${primaryBrand !== "None Detected" ? "var(--accent-cyan)" : "var(--text-main)"}; margin-left: 6px;">
                            ${escapeHtml(primaryBrand)}
                        </strong>
                    </div>
                    <div>
                        <span style="font-size: 13px; color: var(--text-dim);">Submitted Domain:</span>
                        <code style="background: rgba(255,255,255,0.06); padding: 2px 6px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-size: 12px;">
                            ${escapeHtml(inputData.domain || inputData.original_url || "N/A")}
                        </code>
                    </div>
                    <div>
                        <span style="font-size: 13px; color: var(--text-dim);">Brand Names Detected:</span>
                        <strong style="margin-left: 6px; color: ${brandName.detected ? "var(--accent-amber)" : "var(--text-dim)"};">
                            ${brandName.detected ? `${candidates.length} Brand(s)` : "None"}
                        </strong>
                    </div>
                </div>
            </div>

            <!-- 1. CANDIDATE BRANDS & NAME MATCHING -->
            <div class="evidence-card ${brandName.detected ? "warning" : ""}">
                <div class="evidence-label">1. Brand Name Matching (${candidates.length} Candidate Brand(s))</div>
                ${candidates.length > 0 ? `
                    <div style="margin-top: 6px; display: flex; flex-direction: column; gap: 8px;">
                        ${candidates.map(cb => `
                            <div style="background: rgba(255,255,255,0.03); padding: 8px 10px; border-radius: 6px; border-left: 3px solid var(--accent-cyan);">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <strong style="color: var(--accent-cyan); font-size: 13px;">${escapeHtml(cb.brand)}</strong>
                                    <span style="font-size: 11px; color: var(--text-dim);">${cb.evidence.length} location(s)</span>
                                </div>
                                <div style="font-size: 11px; color: var(--text-dim); margin-top: 4px;">
                                    Found in: ${escapeHtml(cb.evidence.join(", "))}
                                </div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No recognizable brand names found in page content</div>
                `}
            </div>

            <!-- 2. OFFICIAL DOMAIN COMPARISON -->
            <div class="evidence-card ${officialDom.status === "compared" ? (officialDom.same_domain ? "success" : "danger") : ""}">
                <div class="evidence-label">2. Official Domain Verification</div>
                ${officialDom.status === "compared" ? `
                    <div style="margin-top: 4px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 12px;">
                            <span style="color: var(--text-dim);">Official Reference Domain:</span>
                            <strong>${escapeHtml(officialDom.official_domain || "N/A")}</strong>
                        </div>
                        <div style="display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 12px;">
                            <span style="color: var(--text-dim);">Submitted Target Domain:</span>
                            <code>${escapeHtml(officialDom.submitted_domain || "N/A")}</code>
                        </div>
                        <div style="margin-top: 8px; padding: 6px 10px; border-radius: 4px; font-size: 12px; background: ${officialDom.same_domain ? "rgba(16, 185, 129, 0.15)" : "rgba(239, 68, 68, 0.15)"}; color: ${officialDom.same_domain ? "var(--accent-emerald)" : "var(--accent-rose)"};">
                            ${officialDom.same_domain ? "✓ Domain matches official brand domain" : "⚠ Submitted domain differs from official brand reference"}
                        </div>
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No candidate brand reference available for domain comparison</div>
                `}
            </div>

            <!-- 3. LOGO DETECTION & SIMILARITY -->
            <div class="evidence-card">
                <div class="evidence-label">3. Logo Detection &amp; Visual Similarity</div>
                <div class="evidence-value ${logo.detected ? "info" : ""}">
                    ${logo.detected ? `Logo Detected (${escapeHtml(logo.format || "Image")})` : "No primary logo detected"}
                </div>
                ${logo.detected ? `
                    <div style="margin-top: 6px; font-size: 12px; color: var(--text-dim); line-height: 1.5;">
                        <div><strong>Location:</strong> ${escapeHtml(logo.location || "page body")}</div>
                        <div><strong>Alt text:</strong> ${escapeHtml(logo.alt || "None")}</div>
                        ${logo.dimensions ? `<div><strong>Dimensions:</strong> ${escapeHtml(logo.dimensions)}</div>` : ""}
                        ${logo.url ? `<div style="word-break: break-all; margin-top: 2px;"><strong>Source:</strong> <code>${escapeHtml(logo.url)}</code></div>` : ""}
                    </div>
                ` : ""}

                ${logoSim.matches && logoSim.matches.length > 0 ? `
                    <div style="margin-top: 10px; border-top: 1px solid var(--border-color); padding-top: 8px;">
                        <span style="font-size: 11px; color: var(--text-dim); font-weight: 600;">SIMILARITY MATCHES:</span>
                        ${logoSim.matches.map(m => `
                            <div style="margin-top: 6px;">
                                <div style="display: flex; justify-content: space-between; font-size: 12px;">
                                    <span>${escapeHtml(m.candidate_brand)} Logo Similarity:</span>
                                    <strong style="color: var(--accent-cyan);">${Math.round(m.similarity_score * 100)}% similarity</strong>
                                </div>
                                <div class="progress-bar-container" style="margin-top: 4px; height: 6px; background: rgba(255,255,255,0.06); border-radius: 3px; overflow: hidden;">
                                    <div style="height: 100%; width: ${Math.round(m.similarity_score * 100)}%; background: linear-gradient(90deg, var(--accent-cyan), var(--accent-blue));"></div>
                                </div>
                                <div style="font-size: 11px; color: var(--text-dim); margin-top: 3px;">
                                    ${escapeHtml(m.evidence || m.method)}
                                </div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div style="margin-top: 6px; font-size: 11px; color: var(--text-dim);">
                        Status: ${logoSim.status === "not_available" ? "No reference comparison available" : "Analyzed"}
                    </div>
                `}
            </div>

            <!-- 4. FAVICON DETECTION & SIMILARITY -->
            <div class="evidence-card">
                <div class="evidence-label">4. Favicon Detection &amp; Similarity</div>
                <div class="evidence-value ${favicon.detected ? "info" : ""}">
                    ${favicon.detected ? `Favicon Detected (${escapeHtml(favicon.format || "ICO")})` : "No favicon detected"}
                </div>
                ${favicon.detected && favicon.url ? `
                    <div style="font-size: 11px; color: var(--text-dim); margin-top: 4px; word-break: break-all;">
                        <code>${escapeHtml(favicon.url)}</code>
                    </div>
                ` : ""}

                ${favSim.matches && favSim.matches.length > 0 ? `
                    <div style="margin-top: 10px; border-top: 1px solid var(--border-color); padding-top: 8px;">
                        <span style="font-size: 11px; color: var(--text-dim); font-weight: 600;">FAVICON SIMILARITY:</span>
                        ${favSim.matches.map(fm => `
                            <div style="margin-top: 6px;">
                                <div style="display: flex; justify-content: space-between; font-size: 12px;">
                                    <span>${escapeHtml(fm.candidate_brand)} Favicon:</span>
                                    <strong style="color: var(--accent-cyan);">${Math.round(fm.similarity_score * 100)}% similarity</strong>
                                </div>
                                <div class="progress-bar-container" style="margin-top: 4px; height: 6px; background: rgba(255,255,255,0.06); border-radius: 3px; overflow: hidden;">
                                    <div style="height: 100%; width: ${Math.round(fm.similarity_score * 100)}%; background: linear-gradient(90deg, var(--accent-cyan), var(--accent-emerald));"></div>
                                </div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div style="margin-top: 6px; font-size: 11px; color: var(--text-dim);">
                        Status: ${favSim.status === "not_available" ? "No reference comparison available" : "Analyzed"}
                    </div>
                `}
            </div>

            <!-- 5. COLOR THEME & DOMINANT PALETTE -->
            <div class="evidence-card">
                <div class="evidence-label">5. Color Theme &amp; Dominant Palette (${dominantColors.length} Colors)</div>
                ${dominantColors.length > 0 ? `
                    <div style="display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px;">
                        ${dominantColors.map(color => `
                            <div style="display: flex; align-items: center; gap: 4px; background: rgba(255,255,255,0.04); padding: 3px 6px; border-radius: 4px; border: 1px solid rgba(255,255,255,0.08);">
                                <span style="display: inline-block; width: 14px; height: 14px; border-radius: 3px; background-color: ${escapeHtml(color)}; border: 1px solid rgba(255,255,255,0.2);"></span>
                                <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-dim);">${escapeHtml(color)}</span>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No explicit color palette extracted</div>
                `}

                ${colorTheme.matches && colorTheme.matches.length > 0 ? `
                    <div style="margin-top: 10px; border-top: 1px solid var(--border-color); padding-top: 8px;">
                        <span style="font-size: 11px; color: var(--text-dim); font-weight: 600;">BRAND PALETTE OVERLAP:</span>
                        ${colorTheme.matches.map(cm => `
                            <div style="margin-top: 6px;">
                                <div style="display: flex; justify-content: space-between; font-size: 12px;">
                                    <span>${escapeHtml(cm.candidate_brand)} Palette:</span>
                                    <strong style="color: var(--accent-cyan);">${Math.round(cm.similarity_score * 100)}% similarity</strong>
                                </div>
                                <div style="font-size: 11px; color: var(--text-dim); margin-top: 2px;">
                                    Matched: ${escapeHtml((cm.matched_colors || []).join(", "))}
                                </div>
                            </div>
                        `).join("")}
                    </div>
                ` : ""}
            </div>

            <!-- 6. WEBSITE LAYOUT & STRUCTURE SIMILARITY -->
            <div class="evidence-card">
                <div class="evidence-label">6. Website Layout &amp; DOM Structure</div>
                ${layout.matches && layout.matches.length > 0 ? `
                    <div style="margin-top: 6px;">
                        ${layout.matches.map(lm => `
                            <div>
                                <div style="display: flex; justify-content: space-between; font-size: 12px;">
                                    <span>${escapeHtml(lm.candidate_brand)} Archetype:</span>
                                    <strong style="color: var(--accent-cyan);">${Math.round(lm.similarity_score * 100)}% similarity</strong>
                                </div>
                                <div style="font-size: 11px; color: var(--text-dim); margin-top: 4px;">
                                    Archetype: <code>${escapeHtml(lm.layout_type || "N/A")}</code> (${escapeHtml(lm.method || "DOM structure comparison")})
                                </div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">
                        ${layout.status === "analyzed" ? "Standard web layout structure analyzed" : "Layout comparison not available"}
                    </div>
                `}
            </div>

            <!-- 7. POTENTIAL TRADEMARK REFERENCES -->
            <div class="evidence-card full-width">
                <div class="evidence-label">7. Trademark References &amp; Brand Term Matching</div>
                ${trademark.matches && trademark.matches.length > 0 ? `
                    <div style="overflow-x: auto; margin-top: 6px;">
                        <table style="width: 100%; font-size: 12px; border-collapse: collapse;">
                            <thead>
                                <tr style="border-bottom: 1px solid var(--border-color); text-align: left; color: var(--text-dim);">
                                    <th style="padding: 6px 8px;">Candidate Brand</th>
                                    <th style="padding: 6px 8px;">Matched Term</th>
                                    <th style="padding: 6px 8px;">Match Type</th>
                                    <th style="padding: 6px 8px;">Reference Source</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${trademark.matches.map(tm => `
                                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.03);">
                                        <td style="padding: 6px 8px; font-weight: 600; color: var(--accent-cyan);">${escapeHtml(tm.candidate_brand)}</td>
                                        <td style="padding: 6px 8px;"><code>${escapeHtml(tm.matched_term)}</code></td>
                                        <td style="padding: 6px 8px; color: var(--text-dim);">${escapeHtml(tm.match_type || "name")}</td>
                                        <td style="padding: 6px 8px; color: var(--text-dim); font-size: 11px;">${escapeHtml(tm.source)}</td>
                                    </tr>
                                `).join("")}
                            </tbody>
                        </table>
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No potential trademark matches identified in configured references</div>
                `}
            </div>

            <!-- 8. CONSOLIDATED BRAND FORENSIC EVIDENCE -->
            <div class="evidence-card full-width">
                <div class="evidence-label">8. Consolidated Forensic Brand Evidence (${brandEvidence.length} Observations)</div>
                ${brandEvidence.length > 0 ? `
                    <ul class="evidence-list" style="margin-top: 6px;">
                        ${brandEvidence.map(item => `
                            <li>
                                <strong style="color: var(--accent-cyan);">&bull;</strong>
                                ${escapeHtml(item)}
                            </li>
                        `).join("")}
                    </ul>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No brand impersonation or imitation evidence observed</div>
                `}
            </div>

            ${renderErrorBlock(result.errors)}
        </div>
    `;
}

/**
 * Render Evidence Details for Agent 10: Visual & UI Analysis
 */
function renderAgent10Evidence(result, container) {
    if (!result || result.status === "error") {
        container.innerHTML = `
            <div class="evidence-grid">
                <div class="evidence-card full-width danger">
                    <div class="evidence-label">Agent 10 Error</div>
                    <div class="evidence-value danger">Failed to execute visual and UI analysis</div>
                </div>
                ${renderErrorBlock(result ? result.errors : ["Unknown error"])}
            </div>
        `;
        return;
    }

    const inputData = result.input || {};
    const screenshot = result.screenshot_analysis || { status: "not_available", screenshot_captured: false };
    const ocr = result.ocr || { status: "not_available", text: "", detected_terms: [] };
    const badges = result.trust_badges || { detected: [], suspicious_indicators: [] };
    const payments = result.payment_logos || { detected: [], suspicious_indicators: [] };
    const reviews = result.reviews || { detected: false, review_count_visible: 0, suspicious_indicators: [] };
    const consistency = result.visual_consistency || { status: "not_available", indicators: [] };
    const patterns = result.suspicious_design_patterns || [];
    const evidenceList = result.evidence || [];

    container.innerHTML = `
        <div class="evidence-grid">
            <!-- TARGET DOMAIN & VISUAL FORENSICS SUMMARY -->
            <div class="evidence-card full-width">
                <div class="evidence-label">Agent 10 &bull; Visual &amp; UI Forensic Summary</div>
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-top: 4px;">
                    <div>
                        <span style="font-size: 13px; color: var(--text-dim);">Target Domain:</span>
                        <code style="background: rgba(255,255,255,0.06); padding: 2px 6px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-size: 12px; margin-left: 6px;">
                            ${escapeHtml(inputData.domain || inputData.original_url || "N/A")}
                        </code>
                    </div>
                    <div>
                        <span style="font-size: 13px; color: var(--text-dim);">Screenshot Viewport:</span>
                        <strong style="margin-left: 6px; color: ${screenshot.screenshot_captured ? "var(--accent-emerald)" : "var(--text-dim)"};">
                            ${screenshot.screenshot_captured ? `${screenshot.width}x${screenshot.height}px (Rendered)` : "Not Captured"}
                        </strong>
                    </div>
                    <div>
                        <span style="font-size: 13px; color: var(--text-dim);">OCR Text Status:</span>
                        <strong style="margin-left: 6px; color: ${ocr.status === "completed" ? "var(--accent-cyan)" : "var(--text-dim)"};">
                            ${ocr.status === "completed" ? `Extracted (${(ocr.detected_terms || []).length} key terms)` : (ocr.status || "Not Available")}
                        </strong>
                    </div>
                    <div>
                        <span style="font-size: 13px; color: var(--text-dim);">Suspicious UI Patterns:</span>
                        <strong style="margin-left: 6px; color: ${patterns.length > 0 ? "var(--accent-rose)" : "var(--accent-emerald)"};">
                            ${patterns.length > 0 ? `${patterns.length} Pattern(s)` : "None"}
                        </strong>
                    </div>
                </div>
            </div>

            <!-- 1. SCREENSHOT & RENDERING ANALYSIS -->
            <div class="evidence-card">
                <div class="evidence-label">1. Headless Browser Rendering &amp; Screenshot</div>
                <div class="evidence-value ${screenshot.screenshot_captured ? "success" : "info"}">
                    ${screenshot.screenshot_captured ? `Screenshot Captured (${screenshot.width}x${screenshot.height})` : "Screenshot Not Captured / Browser Headless Mode"}
                </div>
                <div style="font-size: 12px; color: var(--text-dim); margin-top: 6px;">
                    <div><strong>Engine:</strong> Playwright Headless Chromium</div>
                    <div><strong>Status:</strong> ${escapeHtml(screenshot.status || "N/A")}</div>
                    ${screenshot.error ? `<div style="color: var(--accent-amber); margin-top: 2px;"><strong>Notice:</strong> ${escapeHtml(screenshot.error)}</div>` : ""}
                </div>
            </div>

            <!-- 2. OCR VISIBLE TEXT EXTRACTION -->
            <div class="evidence-card">
                <div class="evidence-label">2. OCR Visible Text Analysis</div>
                <div class="evidence-value ${ocr.status === "completed" ? "info" : ""}">
                    ${ocr.status === "completed" ? "Visual Text Extracted via OCR" : "OCR Engine Unavailable / No Screenshot"}
                </div>
                ${ocr.status === "completed" && ocr.detected_terms && ocr.detected_terms.length > 0 ? `
                    <div style="margin-top: 8px;">
                        <span style="font-size: 11px; color: var(--text-dim); font-weight: 600;">DETECTED SECURITY &amp; UI CLAIMS:</span>
                        <div style="display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px;">
                            ${ocr.detected_terms.map(term => `
                                <span style="background: rgba(56, 189, 248, 0.15); color: var(--accent-cyan); padding: 2px 6px; border-radius: 4px; font-size: 11px;">
                                    ${escapeHtml(term)}
                                </span>
                            `).join("")}
                        </div>
                    </div>
                ` : ""}
                ${ocr.text ? `
                    <div style="margin-top: 8px; font-size: 11px; color: var(--text-dim); background: rgba(0,0,0,0.2); padding: 6px; border-radius: 4px; max-height: 60px; overflow-y: auto;">
                        <code>${escapeHtml(ocr.text.slice(0, 200))}${ocr.text.length > 200 ? "..." : ""}</code>
                    </div>
                ` : `
                    <div style="font-size: 11px; color: var(--text-dim); margin-top: 4px;">
                        ${escapeHtml(ocr.error || "Tesseract OCR engine inactive or unconfigured")}
                    </div>
                `}
            </div>

            <!-- 3. TRUST & SECURITY BADGES -->
            <div class="evidence-card">
                <div class="evidence-label">3. Trust Badges &amp; Security Seals (${badges.detected.length} Detected)</div>
                ${badges.detected.length > 0 ? `
                    <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 6px;">
                        ${badges.detected.map(b => {
                            const isSuspicious = b.verification === "potentially_suspicious" || b.verification === "unverified";
                            return `
                                <div style="background: rgba(255,255,255,0.03); padding: 6px 10px; border-radius: 6px; border-left: 3px solid ${isSuspicious ? "var(--accent-amber)" : "var(--accent-emerald)"};">
                                    <div style="display: flex; justify-content: space-between; align-items: center;">
                                        <strong style="font-size: 12px; color: ${isSuspicious ? "var(--accent-amber)" : "var(--accent-emerald)"};">
                                            ${escapeHtml(b.badge_name)}
                                        </strong>
                                        <span style="font-size: 10px; text-transform: uppercase; padding: 2px 6px; border-radius: 3px; background: ${isSuspicious ? "rgba(245, 158, 11, 0.15)" : "rgba(16, 185, 129, 0.15)"}; color: ${isSuspicious ? "var(--accent-amber)" : "var(--accent-emerald)"};">
                                            ${escapeHtml(b.verification)}
                                        </span>
                                    </div>
                                    <div style="font-size: 11px; color: var(--text-dim); margin-top: 2px;">
                                        ${b.link_url ? `Link: <code>${escapeHtml(b.link_url)}</code>` : "Unlinked static graphic"}
                                    </div>
                                </div>
                            `;
                        }).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No security seals or trust badges detected</div>
                `}
                ${badges.suspicious_indicators.length > 0 ? `
                    <div style="margin-top: 8px; font-size: 11px; color: var(--accent-amber);">
                        ${badges.suspicious_indicators.map(ind => `<div>⚠ ${escapeHtml(ind)}</div>`).join("")}
                    </div>
                ` : ""}
            </div>

            <!-- 4. PAYMENT LOGOS & CHECKOUT INTEGRATION -->
            <div class="evidence-card">
                <div class="evidence-label">4. Payment Logos (${payments.detected.length} Detected)</div>
                ${payments.detected.length > 0 ? `
                    <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 6px;">
                        ${payments.detected.map(p => `
                            <div style="background: rgba(255,255,255,0.03); padding: 6px 10px; border-radius: 6px; border-left: 3px solid ${p.has_checkout_integration ? "var(--accent-emerald)" : "var(--accent-amber)"};">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <strong style="font-size: 12px; color: var(--accent-cyan);">${escapeHtml(p.name)}</strong>
                                    <span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: ${p.has_checkout_integration ? "rgba(16, 185, 129, 0.15)" : "rgba(245, 158, 11, 0.15)"}; color: ${p.has_checkout_integration ? "var(--accent-emerald)" : "var(--accent-amber)"};">
                                        ${p.has_checkout_integration ? "Active Checkout Detected" : "Static Visual Logo"}
                                    </span>
                                </div>
                                <div style="font-size: 11px; color: var(--text-dim); margin-top: 2px;">
                                    Source: ${escapeHtml(p.source)}
                                </div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No payment provider logos detected</div>
                `}
            </div>

            <!-- 5. REVIEWS & TESTIMONIALS ANALYSIS -->
            <div class="evidence-card">
                <div class="evidence-label">5. Customer Reviews &amp; Testimonials</div>
                <div class="evidence-value ${reviews.detected ? (reviews.suspicious_indicators.length > 0 ? "warning" : "info") : ""}">
                    ${reviews.detected ? `Reviews Detected (${reviews.review_count_visible} visible elements)` : "No customer reviews or testimonials detected"}
                </div>
                ${reviews.detected ? `
                    <div style="font-size: 12px; color: var(--text-dim); margin-top: 6px;">
                        ${reviews.average_rating_visible ? `<div><strong>Average Rating Displayed:</strong> ${escapeHtml(reviews.average_rating_visible)}</div>` : ""}
                    </div>
                ` : ""}
                ${reviews.suspicious_indicators.length > 0 ? `
                    <ul class="evidence-list" style="margin-top: 6px;">
                        ${reviews.suspicious_indicators.map(ind => `<li style="color: var(--accent-amber);">${escapeHtml(ind)}</li>`).join("")}
                    </ul>
                ` : ""}
            </div>

            <!-- 6. VISUAL CONSISTENCY -->
            <div class="evidence-card">
                <div class="evidence-label">6. Visual Design Consistency</div>
                <div class="evidence-value ${consistency.status === "analyzed" ? "info" : ""}">
                    ${consistency.status === "analyzed" ? "UI Layout & Consistency Analyzed" : "Consistency Not Analyzed"}
                </div>
                ${consistency.indicators.length > 0 ? `
                    <ul class="evidence-list" style="margin-top: 6px;">
                        ${consistency.indicators.map(ind => `<li>${escapeHtml(ind)}</li>`).join("")}
                    </ul>
                ` : ""}
            </div>

            <!-- 7. SUSPICIOUS DESIGN PATTERNS -->
            <div class="evidence-card full-width ${patterns.length > 0 ? "warning" : ""}">
                <div class="evidence-label">7. Suspicious &amp; Deceptive Design Patterns (${patterns.length} Detected)</div>
                ${patterns.length > 0 ? `
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 10px; margin-top: 8px;">
                        ${patterns.map(p => `
                            <div style="background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.2); padding: 10px; border-radius: 6px;">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <strong style="font-size: 12px; text-transform: uppercase; color: var(--accent-rose);">${escapeHtml(p.pattern)}</strong>
                                    <span style="font-size: 10px; color: var(--text-dim);">${escapeHtml(p.source || "UI")}</span>
                                </div>
                                <div style="font-size: 12px; color: var(--text-main); margin-top: 4px;">
                                    ${escapeHtml(p.evidence)}
                                </div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No high-pressure urgency, fear triggers, or deceptive design patterns detected</div>
                `}
            </div>

            <!-- 8. CONSOLIDATED VISUAL FORENSIC EVIDENCE -->
            <div class="evidence-card full-width">
                <div class="evidence-label">8. Consolidated Visual &amp; UI Forensic Evidence (${evidenceList.length} Observations)</div>
                ${evidenceList.length > 0 ? `
                    <ul class="evidence-list" style="margin-top: 6px;">
                        ${evidenceList.map(item => `
                            <li>
                                <strong style="color: var(--accent-cyan);">&bull;</strong>
                                ${escapeHtml(item)}
                            </li>
                        `).join("")}
                    </ul>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No visual anomalies or deceptive UI evidence observed</div>
                `}
            </div>

            ${renderErrorBlock(result.errors)}
        </div>
    `;
}

/**
 * Render Evidence Details for Agent 11: Content Quality Analysis
 */
function renderAgent11Evidence(result, container) {
    if (!result || result.status === "error") {
        container.innerHTML = `
            <div class="evidence-grid">
                <div class="evidence-card full-width danger">
                    <div class="evidence-label">Agent 11 Error</div>
                    <div class="evidence-value danger">Failed to execute content quality analysis</div>
                </div>
                ${renderErrorBlock(result ? result.errors : ["Unknown error"])}
            </div>
        `;
        return;
    }

    const inputData = result.input || {};
    const stats = result.content_statistics || { word_count: 0, sentence_count: 0, paragraph_count: 0, average_sentence_length: 0 };
    const lang = result.language || { detected: "en", confidence: 1.0 };
    const grammar = result.grammar_analysis || { status: "completed", error_count: 0, examples: [] };
    const spelling = result.spelling_analysis || { status: "completed", error_count: 0, examples: [] };
    const aiContent = result.ai_content_analysis || { status: "analyzed", possible_ai_content: false, indicator_strength: "low", indicators: [] };
    const duplicates = result.duplicate_content || { status: "completed", duplicate_sections: [] };
    const similarity = result.content_similarity || { status: "not_available", matches: [] };
    const claims = result.unrealistic_claims || { detected: false, claims: [] };
    const urgency = result.urgency_language || { detected: false, instances: [] };
    const scamKw = result.scam_keywords || { detected: false, matches: [] };
    const evidenceList = result.evidence || [];

    const isNonEnglish = lang.detected && lang.detected !== "en";

    container.innerHTML = `
        <div class="evidence-grid">
            <!-- TARGET DOMAIN & CONTENT QUALITY SUMMARY -->
            <div class="evidence-card full-width">
                <div class="evidence-label">Agent 11 &bull; Content Quality &amp; Linguistic Forensics Summary</div>
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-top: 4px;">
                    <div>
                        <span style="font-size: 13px; color: var(--text-dim);">Target Domain:</span>
                        <code style="background: rgba(255,255,255,0.06); padding: 2px 6px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-size: 12px; margin-left: 6px;">
                            ${escapeHtml(inputData.domain || inputData.original_url || "N/A")}
                        </code>
                    </div>
                    <div>
                        <span style="font-size: 13px; color: var(--text-dim);">Language:</span>
                        <strong style="margin-left: 6px; color: var(--accent-cyan); text-transform: uppercase;">
                            ${escapeHtml(lang.detected || "Unknown")} (${Math.round((lang.confidence || 1.0) * 100)}% conf)
                        </strong>
                    </div>
                    <div>
                        <span style="font-size: 13px; color: var(--text-dim);">Word Count:</span>
                        <strong style="margin-left: 6px; color: var(--text-main);">
                            ${stats.word_count.toLocaleString()} words (${stats.sentence_count} sentences)
                        </strong>
                    </div>
                    <div>
                        <span style="font-size: 13px; color: var(--text-dim);">AI-Like Writing:</span>
                        <strong style="margin-left: 6px; text-transform: uppercase; color: ${aiContent.possible_ai_content ? "var(--accent-amber)" : "var(--accent-emerald)"};">
                            ${escapeHtml(aiContent.indicator_strength || "Low")}
                        </strong>
                    </div>
                </div>
            </div>

            <!-- 1. CONTENT STATISTICS & LANGUAGE -->
            <div class="evidence-card">
                <div class="evidence-label">1. Textual Volume &amp; Corpus Statistics</div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 6px; font-size: 12px;">
                    <div style="background: rgba(255,255,255,0.03); padding: 6px 8px; border-radius: 4px;">
                        <span style="color: var(--text-dim);">Total Words:</span>
                        <strong style="float: right;">${stats.word_count}</strong>
                    </div>
                    <div style="background: rgba(255,255,255,0.03); padding: 6px 8px; border-radius: 4px;">
                        <span style="color: var(--text-dim);">Sentences:</span>
                        <strong style="float: right;">${stats.sentence_count}</strong>
                    </div>
                    <div style="background: rgba(255,255,255,0.03); padding: 6px 8px; border-radius: 4px;">
                        <span style="color: var(--text-dim);">Paragraphs:</span>
                        <strong style="float: right;">${stats.paragraph_count || 0}</strong>
                    </div>
                    <div style="background: rgba(255,255,255,0.03); padding: 6px 8px; border-radius: 4px;">
                        <span style="color: var(--text-dim);">Avg Sent Length:</span>
                        <strong style="float: right;">${stats.average_sentence_length || 0} words</strong>
                    </div>
                </div>
                ${isNonEnglish ? `
                    <div style="margin-top: 8px; font-size: 11px; color: var(--accent-cyan); background: rgba(56, 189, 248, 0.1); padding: 4px 8px; border-radius: 4px;">
                        ℹ Non-English primary language detected (${lang.detected.toUpperCase()}). English spell/grammar filters adjusted.
                    </div>
                ` : ""}
            </div>

            <!-- 2. GRAMMAR ANALYSIS -->
            <div class="evidence-card">
                <div class="evidence-label">2. Grammar Analysis (${grammar.error_count} Irregularities)</div>
                <div class="evidence-value ${grammar.error_count > 0 ? "warning" : "success"}">
                    ${grammar.error_count > 0 ? `${grammar.error_count} Possible Grammatical Irregularities` : "No major grammatical anomalies detected"}
                </div>
                ${grammar.examples && grammar.examples.length > 0 ? `
                    <div style="margin-top: 6px; display: flex; flex-direction: column; gap: 6px;">
                        ${grammar.examples.map(ex => `
                            <div style="background: rgba(245, 158, 11, 0.08); border-left: 3px solid var(--accent-amber); padding: 6px 8px; border-radius: 4px; font-size: 11px;">
                                <div style="color: var(--accent-amber); font-weight: 600;">Issue: ${escapeHtml(ex.issue)}</div>
                                <div style="color: var(--text-dim); margin-top: 2px;">&ldquo;${escapeHtml(ex.text)}&rdquo;</div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div style="font-size: 11px; color: var(--text-dim); margin-top: 4px;">
                        Status: ${escapeHtml(grammar.status || "Completed")}
                    </div>
                `}
            </div>

            <!-- 3. SPELLING ANALYSIS -->
            <div class="evidence-card">
                <div class="evidence-label">3. Spelling Analysis (${spelling.error_count} Errors)</div>
                <div class="evidence-value ${spelling.error_count > 0 ? "warning" : "success"}">
                    ${spelling.error_count > 0 ? `${spelling.error_count} Potential Spelling Mistakes` : "No spelling errors detected"}
                </div>
                ${spelling.examples && spelling.examples.length > 0 ? `
                    <div style="display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px;">
                        ${spelling.examples.map(sp => `
                            <div style="background: rgba(255,255,255,0.04); padding: 4px 8px; border-radius: 4px; font-size: 11px; border: 1px solid rgba(255,255,255,0.08);">
                                <span style="color: var(--accent-rose); font-weight: 600;">${escapeHtml(sp.word)}</span>
                                <span style="color: var(--text-dim); margin-left: 4px;">&rarr; ${escapeHtml((sp.suggestions || []).slice(0, 2).join(", "))}</span>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div style="font-size: 11px; color: var(--text-dim); margin-top: 4px;">
                        Status: ${escapeHtml(spelling.status || "Completed")}
                    </div>
                `}
            </div>

            <!-- 4. AI-GENERATED CONTENT ASSESSMENT -->
            <div class="evidence-card">
                <div class="evidence-label">4. AI-Generated Content Characteristics</div>
                <div class="evidence-value ${aiContent.possible_ai_content ? "info" : ""}">
                    ${aiContent.possible_ai_content ? `Potential AI Patterns (${escapeHtml(aiContent.indicator_strength.toUpperCase())} indicator)` : "Natural Human-Like Content Characteristics"}
                </div>
                ${aiContent.indicators && aiContent.indicators.length > 0 ? `
                    <ul class="evidence-list" style="margin-top: 6px;">
                        ${aiContent.indicators.map(ind => `<li>${escapeHtml(ind)}</li>`).join("")}
                    </ul>
                ` : `
                    <div style="font-size: 11px; color: var(--text-dim); margin-top: 4px;">
                        No formulaic AI transition markers or robotic sentence length uniformity observed.
                    </div>
                `}
                <div style="font-size: 10px; color: var(--text-dim); margin-top: 6px; font-style: italic;">
                    * AI analysis is probabilistic and does not constitute proof of AI-authorship or maliciousness.
                </div>
            </div>

            <!-- 5. DUPLICATE CONTENT & REPEATED SECTIONS -->
            <div class="evidence-card">
                <div class="evidence-label">5. Duplicate Content (${(duplicates.duplicate_sections || []).length} Repeated Sections)</div>
                ${duplicates.duplicate_sections && duplicates.duplicate_sections.length > 0 ? `
                    <div style="display: flex; flex-direction: column; gap: 6px; margin-top: 6px;">
                        ${duplicates.duplicate_sections.map(ds => `
                            <div style="background: rgba(255,255,255,0.03); padding: 6px 8px; border-radius: 4px; font-size: 11px;">
                                <span style="color: var(--accent-amber); font-weight: 600;">Repeated ${ds.occurrences}x:</span>
                                <span style="color: var(--text-dim); margin-left: 4px;">&ldquo;${escapeHtml(ds.text)}&rdquo;</span>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No repeated or duplicated content sections detected</div>
                `}
            </div>

            <!-- 6. CONTENT SIMILARITY / TEMPLATE MATCHING -->
            <div class="evidence-card">
                <div class="evidence-label">6. Content Similarity &amp; Template Matching</div>
                ${similarity.matches && similarity.matches.length > 0 ? `
                    <div style="display: flex; flex-direction: column; gap: 6px; margin-top: 6px;">
                        ${similarity.matches.map(sm => `
                            <div style="background: rgba(239, 68, 68, 0.08); border-left: 3px solid var(--accent-rose); padding: 6px 8px; border-radius: 4px; font-size: 11px;">
                                <div style="display: flex; justify-content: space-between;">
                                    <strong style="color: var(--accent-rose);">${escapeHtml(sm.title || sm.reference)}</strong>
                                    <span style="color: var(--accent-cyan); font-weight: 600;">${Math.round(sm.similarity_score * 100)}% match</span>
                                </div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">
                        ${similarity.status === "analyzed_no_matches" ? "No significant similarity to known deceptive boilerplate templates" : "Similarity analysis completed"}
                    </div>
                `}
            </div>

            <!-- 7. UNREALISTIC CLAIMS & FINANCIAL GUARANTEES -->
            <div class="evidence-card full-width ${claims.detected ? "warning" : ""}">
                <div class="evidence-label">7. Unrealistic Claims &amp; Financial Guarantees (${(claims.claims || []).length} Detected)</div>
                ${claims.detected && claims.claims.length > 0 ? `
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 10px; margin-top: 8px;">
                        ${claims.claims.map(cl => `
                            <div style="background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.2); padding: 10px; border-radius: 6px;">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <strong style="font-size: 12px; color: var(--accent-rose);">${escapeHtml(cl.indicator)}</strong>
                                    <span style="font-size: 10px; text-transform: uppercase; padding: 2px 4px; border-radius: 3px; background: rgba(239, 68, 68, 0.2); color: var(--accent-rose); font-weight: 600;">${escapeHtml(cl.severity)}</span>
                                </div>
                                <div style="font-size: 12px; color: var(--text-main); margin-top: 4px; font-style: italic;">
                                    &ldquo;${escapeHtml(cl.text)}&rdquo;
                                </div>
                                <div style="font-size: 11px; color: var(--text-dim); margin-top: 4px;">
                                    <strong>Observation:</strong> ${escapeHtml(cl.reason)}
                                </div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No unrealistic financial guarantees or exaggerated claims detected</div>
                `}
            </div>

            <!-- 8. URGENCY & SCAM KEYWORDS (COMBINED ROW) -->
            <div class="evidence-card">
                <div class="evidence-label">8. Urgency Language Instances (${(urgency.instances || []).length} Detected)</div>
                ${urgency.detected && urgency.instances.length > 0 ? `
                    <div style="display: flex; flex-direction: column; gap: 6px; margin-top: 6px;">
                        ${urgency.instances.map(ui => `
                            <div style="background: rgba(245, 158, 11, 0.08); border-left: 3px solid var(--accent-amber); padding: 6px 8px; border-radius: 4px; font-size: 11px;">
                                <div style="display: flex; justify-content: space-between;">
                                    <strong style="color: var(--accent-amber);">${escapeHtml(ui.category)}</strong>
                                    <span style="font-size: 10px; color: var(--text-dim); text-transform: uppercase;">${escapeHtml(ui.severity)}</span>
                                </div>
                                <div style="color: var(--text-main); margin-top: 2px;">&ldquo;${escapeHtml(ui.text)}&rdquo;</div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No high-pressure urgency language observed</div>
                `}
            </div>

            <div class="evidence-card">
                <div class="evidence-label">9. Scam Keywords Context Matches (${(scamKw.matches || []).length} Matches)</div>
                ${scamKw.detected && scamKw.matches.length > 0 ? `
                    <div style="display: flex; flex-direction: column; gap: 6px; margin-top: 6px;">
                        ${scamKw.matches.map(kw => `
                            <div style="background: rgba(255,255,255,0.03); padding: 6px 8px; border-radius: 4px; font-size: 11px;">
                                <div style="display: flex; justify-content: space-between;">
                                    <span style="background: rgba(56, 189, 248, 0.15); color: var(--accent-cyan); padding: 1px 5px; border-radius: 3px; font-weight: 600;">
                                        ${escapeHtml(kw.category)}
                                    </span>
                                    <strong style="color: var(--accent-rose);">${escapeHtml(kw.keyword)}</strong>
                                </div>
                                <div style="font-size: 10px; color: var(--text-dim); margin-top: 3px;">
                                    ${escapeHtml(kw.context)}
                                </div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No high-risk scam keyword combinations detected</div>
                `}
            </div>

            <!-- 10. CONSOLIDATED CONTENT FORENSIC EVIDENCE -->
            <div class="evidence-card full-width">
                <div class="evidence-label">10. Consolidated Content Quality Forensic Evidence (${evidenceList.length} Observations)</div>
                ${evidenceList.length > 0 ? `
                    <ul class="evidence-list" style="margin-top: 6px;">
                        ${evidenceList.map(item => `
                            <li>
                                <strong style="color: var(--accent-cyan);">&bull;</strong>
                                ${escapeHtml(item)}
                            </li>
                        `).join("")}
                    </ul>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No content quality or linguistic anomalies observed</div>
                `}
            </div>

            ${renderErrorBlock(result.errors)}
        </div>
    `;
}

/**
 * Render Agent 12: Contact Verification Evidence
 */
function renderAgent12Evidence(result, container) {
    const d = result.data || result || {};
    const bi = d.business_identity || {};
    const emails = d.email_addresses || [];
    const phones = d.phone_numbers || [];
    const addresses = d.physical_addresses || [];
    const gmaps = d.google_maps || {};
    const socials = d.social_media || d.social_media_links || [];
    const taxList = d.tax_registration || d.gst_vat_numbers || [];
    const companyReg = d.company_registration || {};
    const businessReg = d.business_registration || {};
    const crossCheck = d.identity_consistency || d.identity_cross_check || {};
    const matrix = d.contact_availability || d.contact_availability_matrix || {};
    const structured = d.structured_data || {};
    const evidenceList = result.evidence || [];

    // Map registrations from backend company_registration and business_registration
    const registrations = [];
    if (companyReg && (companyReg.found || companyReg.number)) {
        registrations.push({
            type: companyReg.source || "Corporate Registration Number",
            number: companyReg.number,
            jurisdiction: "Corporate Registry",
            is_valid_format: true,
            status: "Declared"
        });
    }
    if (businessReg && businessReg.registration_number && (!companyReg || businessReg.registration_number !== companyReg.number)) {
        registrations.push({
            type: businessReg.source || "Business Registration",
            number: businessReg.registration_number,
            jurisdiction: "Business Registry",
            is_valid_format: true,
            status: "Declared"
        });
    }

    // Map schemas from structured_data
    const schemas = [];
    if (structured && structured.organization_found) {
        schemas.push({ type: "Organization / Corporation", context: "https://schema.org", entity_name: bi.name || bi.declared_name || "Declared Organization" });
    }
    if (structured && structured.local_business_found) {
        schemas.push({ type: "LocalBusiness", context: "https://schema.org", entity_name: bi.name || bi.declared_name || "Local Business" });
    }

    const activeCount = [
        matrix.email || matrix.has_email,
        matrix.phone || matrix.has_phone,
        matrix.physical_address || matrix.has_physical_address,
        matrix.google_maps || matrix.has_google_maps,
        matrix.social_media || matrix.has_social_links,
        matrix.business_registration || matrix.has_business_registration,
        matrix.tax_registration || matrix.has_gst_vat
    ].filter(Boolean).length;

    const matrixBadges = [
        { label: "Email", active: !!(matrix.email || matrix.has_email), icon: "✉️" },
        { label: "Phone", active: !!(matrix.phone || matrix.has_phone), icon: "📞" },
        { label: "Address", active: !!(matrix.physical_address || matrix.has_physical_address), icon: "📍" },
        { label: "Google Maps", active: !!(matrix.google_maps || matrix.has_google_maps), icon: "🗺️" },
        { label: "Socials", active: !!(matrix.social_media || matrix.has_social_links), icon: "🌐" },
        { label: "Business Reg", active: !!(matrix.business_registration || matrix.has_business_registration), icon: "🏢" },
        { label: "GST/VAT", active: !!(matrix.tax_registration || matrix.has_gst_vat), icon: "📑" }
    ];

    container.innerHTML = `
        <div class="evidence-grid">

            <!-- 1. BUSINESS IDENTITY & OVERVIEW -->
            <div class="evidence-card full-width">
                <div class="evidence-label">1. Declared Business Identity &amp; Contact Matrix Overview</div>
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-top: 6px;">
                    <div>
                        <div style="font-size: 18px; font-weight: 700; color: #ffffff;">
                            ${escapeHtml(bi.name || bi.declared_name || "No Business Name Declared")}
                        </div>
                        <div style="font-size: 12px; color: var(--text-dim); margin-top: 2px;">
                            ${(companyReg.number || bi.cin_number) ? `<span style="color: var(--accent-cyan);">CIN / Reg: <strong>${escapeHtml(companyReg.number || bi.cin_number)}</strong></span> &bull; ` : ""}
                            Source: ${escapeHtml(Array.isArray(bi.sources) ? bi.sources.join(", ") : (bi.source || "heuristic / page text"))} &bull; Confidence: ${escapeHtml(bi.confidence || "medium")}
                        </div>
                    </div>
                    <div style="text-align: right;">
                        <span style="font-size: 13px; font-weight: 700; color: ${activeCount >= 3 ? 'var(--accent-emerald)' : 'var(--accent-amber)'}; background: rgba(255,255,255,0.05); padding: 4px 10px; border-radius: 6px; border: 1px solid var(--border-color);">
                            ${activeCount} / 7 Contact Channels Present
                        </span>
                    </div>
                </div>

                <!-- Channel Badges -->
                <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px;">
                    ${matrixBadges.map(b => `
                        <span style="display: inline-flex; align-items: center; gap: 5px; font-size: 11px; padding: 4px 9px; border-radius: 4px; font-weight: 600; background: ${b.active ? 'rgba(16, 185, 129, 0.12)' : 'rgba(255, 255, 255, 0.03)'}; color: ${b.active ? 'var(--accent-emerald)' : 'var(--text-dim)'}; border: 1px solid ${b.active ? 'rgba(16, 185, 129, 0.3)' : 'rgba(255, 255, 255, 0.08)'};">
                            <span>${b.icon}</span> ${escapeHtml(b.label)}: ${b.active ? '✓ Yes' : '✗ No'}
                        </span>
                    `).join("")}
                </div>
            </div>

            <!-- 2. EMAIL ADDRESSES -->
            <div class="evidence-card full-width">
                <div class="evidence-label">2. Extracted Email Addresses (${emails.length} Found)</div>
                ${emails.length > 0 ? `
                    <div style="overflow-x: auto; margin-top: 6px;">
                        <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
                            <thead>
                                <tr style="border-bottom: 1px solid var(--border-color); text-align: left; color: var(--text-dim);">
                                    <th style="padding: 6px 8px;">Email</th>
                                    <th style="padding: 6px 8px;">Domain Match</th>
                                    <th style="padding: 6px 8px;">Provider Type</th>
                                    <th style="padding: 6px 8px;">Location / Source</th>
                                    <th style="padding: 6px 8px;">Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${emails.map(em => `
                                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
                                        <td style="padding: 8px; font-weight: 600; color: var(--accent-cyan); font-family: var(--font-mono);">${escapeHtml(em.email)}</td>
                                        <td style="padding: 8px;">
                                            ${!em.domain_mismatch ? 
                                                `<span style="color: var(--accent-emerald); font-weight: 600;">✓ Matches Site</span>` : 
                                                `<span style="color: var(--accent-amber);">≠ External / Mismatch</span>`}
                                        </td>
                                        <td style="padding: 8px;">
                                            ${em.is_free_provider ? 
                                                `<span style="background: rgba(245, 158, 11, 0.15); color: var(--accent-amber); padding: 2px 6px; border-radius: 3px; font-size: 10px;">Free Webmail</span>` : 
                                                `<span style="background: rgba(16, 185, 129, 0.12); color: var(--accent-emerald); padding: 2px 6px; border-radius: 3px; font-size: 10px;">Custom / Corporate</span>`}
                                        </td>
                                        <td style="padding: 8px; font-size: 11px; color: var(--text-dim);">
                                            ${escapeHtml(em.source || em.location || "Page Body")}
                                        </td>
                                        <td style="padding: 8px;">
                                            <span style="font-size: 10px; text-transform: uppercase; font-weight: 600; color: ${em.domain_mismatch ? 'var(--accent-amber)' : 'var(--accent-emerald)'};">
                                                ${em.is_free_provider ? 'Free Provider' : (em.domain_mismatch ? 'Domain Mismatch' : 'Valid Alignment')}
                                            </span>
                                        </td>
                                    </tr>
                                `).join("")}
                            </tbody>
                        </table>
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px; margin-top: 6px;">No email addresses detected on scanned pages</div>
                `}
            </div>

            <!-- 3. PHONE NUMBERS -->
            <div class="evidence-card full-width">
                <div class="evidence-label">3. Phone Numbers &amp; Normalization (${phones.length} Found)</div>
                ${phones.length > 0 ? `
                    <div style="overflow-x: auto; margin-top: 6px;">
                        <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
                            <thead>
                                <tr style="border-bottom: 1px solid var(--border-color); text-align: left; color: var(--text-dim);">
                                    <th style="padding: 6px 8px;">Raw Input</th>
                                    <th style="padding: 6px 8px;">Normalized Standard</th>
                                    <th style="padding: 6px 8px;">Country</th>
                                    <th style="padding: 6px 8px;">Source</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${phones.map(ph => `
                                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
                                        <td style="padding: 8px; font-family: var(--font-mono);">${escapeHtml(ph.number || ph.raw)}</td>
                                        <td style="padding: 8px; font-weight: 600; color: var(--accent-emerald); font-family: var(--font-mono);">${escapeHtml(ph.normalized || ph.formatted_e164 || ph.number || ph.raw)}</td>
                                        <td style="padding: 8px;">
                                            <span style="background: rgba(56, 189, 248, 0.15); color: var(--accent-cyan); padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600;">
                                                ${escapeHtml(ph.country || ph.region_code || "Identified")}
                                            </span>
                                        </td>
                                        <td style="padding: 8px; font-size: 11px; color: var(--text-dim);">${escapeHtml(ph.source || "Page body")}</td>
                                    </tr>
                                `).join("")}
                            </tbody>
                        </table>
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px; margin-top: 6px;">No telephone numbers detected on scanned pages</div>
                `}
            </div>

            <!-- 4. PHYSICAL ADDRESSES & GOOGLE MAPS (SPLIT ROW) -->
            <div class="evidence-card">
                <div class="evidence-label">4. Physical Addresses (${addresses.length} Found)</div>
                ${addresses.length > 0 ? `
                    <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 6px;">
                        ${addresses.map(addr => `
                            <div style="background: rgba(255,255,255,0.03); padding: 8px 10px; border-radius: 4px; border-left: 3px solid var(--accent-cyan); font-size: 11px;">
                                <div style="font-weight: 600; color: #ffffff;">${escapeHtml(addr.address || addr.address_text)}</div>
                                <div style="font-size: 10px; color: var(--text-dim); margin-top: 4px;">
                                    Source: ${escapeHtml(addr.source || "Page body")}
                                </div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px; margin-top: 6px;">No physical business addresses detected</div>
                `}
            </div>

            <div class="evidence-card">
                <div class="evidence-label">5. Google Maps Presence</div>
                <div style="margin-top: 6px; font-size: 12px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <span>Embedded Map / Links:</span>
                        <strong style="color: ${(gmaps.detected || gmaps.has_embedded_map || gmaps.has_map_link) ? 'var(--accent-emerald)' : 'var(--text-dim)'};">
                            ${(gmaps.detected || gmaps.has_embedded_map || gmaps.has_map_link) ? '✓ Present' : '✗ None'}
                        </strong>
                    </div>
                    ${(gmaps.business_name || gmaps.detected_place_name) ? `
                        <div style="background: rgba(56, 189, 248, 0.08); padding: 6px 8px; border-radius: 4px; margin-top: 6px; font-size: 11px;">
                            <span style="color: var(--text-dim);">Place Name:</span>
                            <strong style="color: var(--accent-cyan); margin-left: 4px;">${escapeHtml(gmaps.business_name || gmaps.detected_place_name)}</strong>
                        </div>
                    ` : ""}
                    ${gmaps.location ? `
                        <div style="font-size: 11px; color: var(--text-dim); margin-top: 6px;">
                            Location: ${escapeHtml(gmaps.location)}
                        </div>
                    ` : ""}
                    ${((gmaps.links || gmaps.map_links || []).length > 0) ? `
                        <div style="margin-top: 8px;">
                            <div style="font-size: 11px; color: var(--text-dim); margin-bottom: 3px;">Map URLs:</div>
                            ${(gmaps.links || gmaps.map_links).slice(0, 2).map(ml => `
                                <div style="font-size: 10px; font-family: var(--font-mono); color: var(--accent-cyan); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                                    ${escapeHtml(ml)}
                                </div>
                            `).join("")}
                        </div>
                    ` : ""}
                </div>
            </div>

            <!-- 6. SOCIAL MEDIA & HANDLES -->
            <div class="evidence-card full-width">
                <div class="evidence-label">6. Social Media Profiles &amp; Handle Consistency (${socials.length} Links)</div>
                ${socials.length > 0 ? `
                    <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-top: 6px;">
                        ${socials.map(soc => `
                            <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--border-color); border-radius: 6px; padding: 8px 12px; font-size: 11px; min-width: 180px; flex: 1;">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <strong style="color: var(--accent-cyan); text-transform: capitalize;">${escapeHtml(soc.platform)}</strong>
                                </div>
                                <div style="font-family: var(--font-mono); font-size: 11px; color: #ffffff; margin-top: 4px;">
                                    @${escapeHtml(soc.handle || "profile")}
                                </div>
                                <div style="margin-top: 4px; display: flex; gap: 6px;">
                                    <span style="color: var(--text-dim); font-size: 10px;">Source: ${escapeHtml(soc.source || "Website Link")}</span>
                                </div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px; margin-top: 6px;">No social media platform profiles identified</div>
                `}
            </div>

            <!-- 7. GST / VAT & BUSINESS REGISTRATIONS (SPLIT ROW) -->
            <div class="evidence-card">
                <div class="evidence-label">7. GST / VAT Identifiers (${taxList.length} Found)</div>
                ${taxList.length > 0 ? `
                    <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 6px;">
                        ${taxList.map(gv => `
                            <div style="background: rgba(255,255,255,0.03); padding: 8px 10px; border-radius: 4px; font-size: 11px; border-left: 3px solid ${gv.format_valid || gv.is_format_valid ? 'var(--accent-emerald)' : 'var(--accent-amber)'};">
                                <div style="display: flex; justify-content: space-between;">
                                    <span style="font-weight: 600; color: var(--accent-cyan); text-transform: uppercase;">${escapeHtml(gv.type)}</span>
                                    <span style="font-size: 10px; text-transform: uppercase; font-weight: 600; color: ${gv.format_valid || gv.is_format_valid ? 'var(--accent-emerald)' : 'var(--accent-amber)'};">
                                        ${(gv.format_valid || gv.is_format_valid) ? 'Valid Format' : 'Non-standard'}
                                    </span>
                                </div>
                                <div style="font-family: var(--font-mono); font-size: 12px; font-weight: 700; color: #ffffff; margin-top: 2px;">
                                    ${escapeHtml(gv.number)}
                                </div>
                                <div style="color: var(--text-dim); font-size: 10px; margin-top: 3px;">
                                    Source: ${escapeHtml(gv.source || "Tax Disclosures")}
                                </div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px; margin-top: 6px;">No GST / VAT numbers detected on website</div>
                `}
            </div>

            <div class="evidence-card">
                <div class="evidence-label">8. Corporate Registration Numbers (${registrations.length} Found)</div>
                ${registrations.length > 0 ? `
                    <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 6px;">
                        ${registrations.map(reg => `
                            <div style="background: rgba(255,255,255,0.03); padding: 8px 10px; border-radius: 4px; font-size: 11px; border-left: 3px solid var(--accent-cyan);">
                                <div style="display: flex; justify-content: space-between;">
                                    <span style="font-weight: 600; color: var(--accent-cyan); text-transform: uppercase;">${escapeHtml(reg.type)}</span>
                                    <span style="font-size: 10px; color: var(--text-dim); text-transform: uppercase;">${escapeHtml(reg.jurisdiction || "Corporate Registry")}</span>
                                </div>
                                <div style="font-family: var(--font-mono); font-size: 12px; font-weight: 700; color: #ffffff; margin-top: 2px;">
                                    ${escapeHtml(reg.number)}
                                </div>
                                <div style="color: var(--text-dim); font-size: 10px; margin-top: 3px;">
                                    Status: <span style="color: var(--accent-emerald);">${escapeHtml(reg.status || "Declared")}</span>
                                </div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px; margin-top: 6px;">No corporate / CIN registration numbers declared</div>
                `}
            </div>

            <!-- 9. IDENTITY CROSS-CHECK & CONSISTENCY -->
            <div class="evidence-card full-width">
                <div class="evidence-label">9. Identity Cross-Check &amp; Correlation Analysis</div>
                <div style="margin-top: 6px; font-size: 12px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <span>Cross-Check Status:</span>
                        <strong style="text-transform: uppercase; color: ${crossCheck.status === 'consistent' ? 'var(--accent-emerald)' : (crossCheck.status === 'inconsistent' ? 'var(--accent-rose)' : 'var(--text-dim)')};">
                            ${escapeHtml(crossCheck.status || 'not_available')}
                        </strong>
                    </div>
                </div>

                ${(crossCheck.conflicts || crossCheck.conflicts_detected || []).length > 0 ? `
                    <div style="margin-top: 10px; background: rgba(244, 63, 94, 0.08); border-left: 3px solid var(--accent-rose); padding: 8px 10px; border-radius: 4px; font-size: 11px;">
                        <strong style="color: var(--accent-rose);">Discrepancies Observed:</strong>
                        <ul style="margin: 4px 0 0 16px; color: var(--text-main);">
                            ${(crossCheck.conflicts || crossCheck.conflicts_detected).map(c => `<li>${escapeHtml(typeof c === 'object' ? (c.note || c.details || JSON.stringify(c)) : String(c))}</li>`).join("")}
                        </ul>
                    </div>
                ` : ""}
            </div>

            <!-- 10. STRUCTURED SCHEMA.ORG ENTITIES (IF ANY) -->
            ${schemas.length > 0 ? `
                <div class="evidence-card full-width">
                    <div class="evidence-label">10. Schema.org Contact &amp; Organization Microdata (${schemas.length} Entities)</div>
                    <div style="display: flex; flex-direction: column; gap: 6px; margin-top: 6px;">
                        ${schemas.map(s => `
                            <div style="background: rgba(56, 189, 248, 0.05); padding: 6px 10px; border-radius: 4px; font-size: 11px;">
                                <div style="display: flex; justify-content: space-between;">
                                    <strong style="color: var(--accent-cyan);">${escapeHtml(s.type)}</strong>
                                    <span style="color: var(--text-dim); font-size: 10px;">${escapeHtml(s.context || "https://schema.org")}</span>
                                </div>
                                <div style="margin-top: 2px; color: var(--text-main);">
                                    ${s.entity_name ? `Name: <strong>${escapeHtml(s.entity_name)}</strong> &bull; ` : ""}
                                    ${s.email ? `Email: <strong>${escapeHtml(s.email)}</strong> &bull; ` : ""}
                                    ${s.telephone ? `Tel: <strong>${escapeHtml(s.telephone)}</strong>` : ""}
                                </div>
                            </div>
                        `).join("")}
                    </div>
                </div>
            ` : ""}

            <!-- 11. CONSOLIDATED FORENSIC EVIDENCE -->
            <div class="evidence-card full-width">
                <div class="evidence-label">11. Consolidated Contact Forensic Evidence (${evidenceList.length} Observations)</div>
                ${evidenceList.length > 0 ? `
                    <ul class="evidence-list" style="margin-top: 6px;">
                        ${evidenceList.map(item => `
                            <li>
                                <strong style="color: var(--accent-cyan);">&bull;</strong>
                                ${escapeHtml(typeof item === 'object' ? (item.finding || JSON.stringify(item)) : String(item))}
                            </li>
                        `).join("")}
                    </ul>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No contact evidence records generated</div>
                `}
            </div>

            ${renderErrorBlock(result.errors)}
        </div>
    `;
}

/**
 * Render Agent 13: External Presence / OSINT Evidence
 */
function renderAgent13Evidence(result, container) {
    const d = result.data || result || {};
    const idObj = d.identity || {};
    const li = d.linkedin || {};
    const fb = d.facebook || {};
    const tw = d.x_twitter || {};
    const ig = d.instagram || {};
    const gh = d.github || {};
    const reddit = d.reddit_mentions || [];
    const news = d.news_articles || [];
    const reviews = d.public_reviews || [];
    const forums = d.forum_discussions || [];
    const consistency = d.external_identity_consistency || {};
    const presence = d.presence_summary || {};
    const context = d.context_summary || {};
    const evidenceList = result.evidence || [];

    const getMatchBadge = (match) => {
        const m = (match || "unknown").toLowerCase();
        if (m === "high") return `<span style="background: rgba(16, 185, 129, 0.2); color: var(--accent-emerald); padding: 2px 6px; border-radius: 4px; font-weight: 700; font-size: 10px;">HIGH MATCH</span>`;
        if (m === "medium") return `<span style="background: rgba(56, 189, 248, 0.2); color: var(--accent-cyan); padding: 2px 6px; border-radius: 4px; font-weight: 700; font-size: 10px;">MEDIUM MATCH</span>`;
        if (m === "low") return `<span style="background: rgba(245, 158, 11, 0.2); color: var(--accent-amber); padding: 2px 6px; border-radius: 4px; font-weight: 700; font-size: 10px;">LOW MATCH</span>`;
        if (m === "mismatch") return `<span style="background: rgba(244, 63, 94, 0.2); color: var(--accent-rose); padding: 2px 6px; border-radius: 4px; font-weight: 700; font-size: 10px;">MISMATCH</span>`;
        return `<span style="background: rgba(255, 255, 255, 0.08); color: var(--text-dim); padding: 2px 6px; border-radius: 4px; font-size: 10px;">UNKNOWN</span>`;
    };

    const getContextBadge = (ctx) => {
        const c = (ctx || "unknown").toLowerCase();
        if (c.includes("scam") || c.includes("fraud") || c.includes("complaint") || c === "negative") {
            return `<span style="background: rgba(244, 63, 94, 0.15); color: var(--accent-rose); padding: 1px 5px; border-radius: 3px; font-size: 10px; font-weight: 600; text-transform: uppercase;">${escapeHtml(ctx)}</span>`;
        }
        if (c.includes("recommend") || c === "positive") {
            return `<span style="background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald); padding: 1px 5px; border-radius: 3px; font-size: 10px; font-weight: 600; text-transform: uppercase;">${escapeHtml(ctx)}</span>`;
        }
        if (c.includes("warning") || c === "mixed") {
            return `<span style="background: rgba(245, 158, 11, 0.15); color: var(--accent-amber); padding: 1px 5px; border-radius: 3px; font-size: 10px; font-weight: 600; text-transform: uppercase;">${escapeHtml(ctx)}</span>`;
        }
        return `<span style="background: rgba(56, 189, 248, 0.12); color: var(--accent-cyan); padding: 1px 5px; border-radius: 3px; font-size: 10px; font-weight: 600; text-transform: uppercase;">${escapeHtml(ctx)}</span>`;
    };

    const socialCards = [
        { platform: "LinkedIn", data: li, icon: "💼" },
        { platform: "Facebook", data: fb, icon: "👥" },
        { platform: "X / Twitter", data: tw, icon: "🐦" },
        { platform: "Instagram", data: ig, icon: "📷" },
        { platform: "GitHub", data: gh, icon: "🐙", isGithub: true },
    ];

    container.innerHTML = `
        <div class="evidence-grid">

            <!-- 1. OSINT TARGET IDENTITY & FOOTPRINT OVERVIEW -->
            <div class="evidence-card full-width">
                <div class="evidence-label">1. Target Identity &amp; OSINT Footprint Overview</div>
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-top: 6px;">
                    <div>
                        <div style="font-size: 18px; font-weight: 700; color: #ffffff;">
                            ${escapeHtml(idObj.company_name || idObj.brand_name || "Unspecified Entity")}
                        </div>
                        <div style="font-size: 12px; color: var(--text-dim); margin-top: 3px;">
                            Domain: <strong style="color: var(--accent-cyan); font-family: var(--font-mono);">${escapeHtml(idObj.domain || "N/A")}</strong>
                            ${idObj.location ? ` &bull; Location: <strong>${escapeHtml(idObj.location)}</strong>` : idObj.country ? ` &bull; Country: <strong>${escapeHtml(idObj.country)}</strong>` : ""}
                            ${idObj.website_title ? ` &bull; Title: &ldquo;${escapeHtml(idObj.website_title)}&rdquo;` : ""}
                        </div>
                    </div>
                    <div style="display: flex; gap: 6px; flex-wrap: wrap;">
                        <span style="font-size: 11px; font-weight: 600; padding: 4px 8px; border-radius: 4px; background: rgba(56, 189, 248, 0.12); color: var(--accent-cyan);">
                            ${presence.social_profiles_found || 0} Social Profiles
                        </span>
                        <span style="font-size: 11px; font-weight: 600; padding: 4px 8px; border-radius: 4px; background: rgba(16, 185, 129, 0.12); color: var(--accent-emerald);">
                            ${presence.news_sources_found || 0} News Sources
                        </span>
                        <span style="font-size: 11px; font-weight: 600; padding: 4px 8px; border-radius: 4px; background: rgba(245, 158, 11, 0.12); color: var(--accent-amber);">
                            ${presence.review_platforms_found || 0} Review Platforms
                        </span>
                        <span style="font-size: 11px; font-weight: 600; padding: 4px 8px; border-radius: 4px; background: rgba(244, 63, 94, 0.12); color: var(--accent-rose);">
                            ${presence.reddit_mentions_found || 0} Reddit Mentions
                        </span>
                    </div>
                </div>
            </div>

            <!-- 2. SOCIAL MEDIA OSINT PROFILES -->
            <div class="evidence-card full-width">
                <div class="evidence-label">2. Public Social Media Presence &amp; Identity Correlation</div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; margin-top: 8px;">
                    ${socialCards.map(sc => {
                        const s = sc.data;
                        return `
                            <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--border-color); border-radius: 6px; padding: 10px 12px; font-size: 11px;">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <strong style="color: #ffffff; font-size: 12px;">${sc.icon} ${sc.platform}</strong>
                                    ${sc.isGithub && !s.relevant ? `<span style="color: var(--text-dim); font-size: 9px;">Not Tech Relevant</span>` : ""}
                                </div>
                                <div style="margin-top: 6px; display: flex; justify-content: space-between; align-items: center;">
                                    <span style="color: var(--text-dim);">Presence:</span>
                                    <strong style="color: ${s.detected ? 'var(--accent-emerald)' : 'var(--text-dim)'};">
                                        ${s.detected ? '✓ Detected' : '✗ Not Found'}
                                    </strong>
                                </div>
                                ${s.detected ? `
                                    <div style="margin-top: 4px; display: flex; justify-content: space-between; align-items: center;">
                                        <span style="color: var(--text-dim);">Identity Match:</span>
                                        ${getMatchBadge(s.identity_match)}
                                    </div>
                                    <div style="margin-top: 4px; display: flex; justify-content: space-between; align-items: center;">
                                        <span style="color: var(--text-dim);">Website Link:</span>
                                        <strong style="color: ${s.website_match ? 'var(--accent-emerald)' : 'var(--accent-amber)'}; font-size: 10px;">
                                            ${s.website_match ? '✓ Matches Domain' : '≠ External / None'}
                                        </strong>
                                    </div>
                                    ${s.profile_url || s.page_url || s.organization_url ? `
                                        <div style="margin-top: 6px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: var(--font-mono); font-size: 10px;">
                                            <a href="${escapeHtml(s.profile_url || s.page_url || s.organization_url)}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-cyan); text-decoration: none;">
                                                🔗 ${escapeHtml(s.profile_url || s.page_url || s.organization_url)}
                                            </a>
                                        </div>
                                    ` : ""}
                                ` : ""}
                            </div>
                        `;
                    }).join("")}
                </div>
            </div>

            <!-- 3. REDDIT MENTIONS -->
            <div class="evidence-card">
                <div class="evidence-label">3. Reddit Public Mentions &amp; Community Threads (${reddit.length} Found)</div>
                ${reddit.length > 0 ? `
                    <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 6px;">
                        ${reddit.map(rd => `
                            <div style="background: rgba(255,255,255,0.03); padding: 8px 10px; border-radius: 4px; font-size: 11px; border-left: 3px solid var(--accent-cyan);">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <strong style="color: var(--accent-cyan); font-family: var(--font-mono);">${escapeHtml(rd.subreddit || "r/reddit")}</strong>
                                    ${getContextBadge(rd.context)}
                                </div>
                                <div style="font-weight: 600; color: #ffffff; margin-top: 4px;">
                                    ${escapeHtml(rd.title)}
                                </div>
                                <div style="color: var(--text-dim); font-size: 10px; margin-top: 3px;">
                                    ${rd.summary ? escapeHtml(rd.summary) : ""}
                                </div>
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 4px; font-size: 9px; color: var(--text-dim);">
                                    <span>${rd.date ? `Date: ${escapeHtml(rd.date)}` : "Date: N/A"}</span>
                                    <a href="${escapeHtml(rd.url)}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-cyan); text-decoration: none;">View Post ↗</a>
                                </div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px; margin-top: 6px;">No public Reddit discussions or threads identified</div>
                `}
            </div>

            <!-- 4. PUBLIC REVIEWS & RATINGS -->
            <div class="evidence-card">
                <div class="evidence-label">4. Public Reviews &amp; Ratings (${reviews.length} Platforms)</div>
                ${reviews.length > 0 ? `
                    <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 6px;">
                        ${reviews.map(rv => `
                            <div style="background: rgba(255,255,255,0.03); padding: 8px 10px; border-radius: 4px; font-size: 11px; border-left: 3px solid var(--accent-amber);">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <strong style="color: #ffffff;">${escapeHtml(rv.platform)}</strong>
                                    ${getContextBadge(rv.general_sentiment)}
                                </div>
                                <div style="display: flex; gap: 12px; margin-top: 4px; font-size: 11px;">
                                    <span>Rating: <strong style="color: var(--accent-amber);">${rv.rating ? `${rv.rating} / 5.0` : 'Not Specified'}</strong></span>
                                    ${rv.review_count ? `<span>Reviews: <strong style="color: var(--text-main);">${rv.review_count.toLocaleString()}</strong></span>` : ""}
                                </div>
                                <div style="margin-top: 4px; font-size: 9px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                                    <a href="${escapeHtml(rv.url)}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-cyan); text-decoration: none;">${escapeHtml(rv.url)} ↗</a>
                                </div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px; margin-top: 6px;">No public customer reviews or directory profiles discovered</div>
                `}
            </div>

            <!-- 5. NEWS ARTICLES & MEDIA COVERAGE -->
            <div class="evidence-card">
                <div class="evidence-label">5. News Articles &amp; Media Coverage (${news.length} Articles)</div>
                ${news.length > 0 ? `
                    <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 6px;">
                        ${news.map(nw => `
                            <div style="background: rgba(255,255,255,0.03); padding: 8px 10px; border-radius: 4px; font-size: 11px; border-left: 3px solid var(--accent-emerald);">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <strong style="color: var(--accent-emerald);">${escapeHtml(nw.publisher || "News Outlet")}</strong>
                                    ${getContextBadge(nw.context)}
                                </div>
                                <div style="font-weight: 600; color: #ffffff; margin-top: 3px;">
                                    ${escapeHtml(nw.title)}
                                </div>
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 4px; font-size: 9px; color: var(--text-dim);">
                                    <span>${nw.published_date ? `Published: ${escapeHtml(nw.published_date)}` : "Date: N/A"}</span>
                                    <a href="${escapeHtml(nw.url)}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-cyan); text-decoration: none;">Read Article ↗</a>
                                </div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px; margin-top: 6px;">No external news media articles or coverage found</div>
                `}
            </div>

            <!-- 6. FORUM DISCUSSIONS -->
            <div class="evidence-card">
                <div class="evidence-label">6. Forum Discussions &amp; Consumer Threads (${forums.length} Found)</div>
                ${forums.length > 0 ? `
                    <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 6px;">
                        ${forums.map(fm => `
                            <div style="background: rgba(255,255,255,0.03); padding: 8px 10px; border-radius: 4px; font-size: 11px;">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <strong style="color: var(--accent-cyan);">${escapeHtml(fm.forum_name)}</strong>
                                    ${getContextBadge(fm.context)}
                                </div>
                                <div style="font-weight: 600; color: #ffffff; margin-top: 3px;">
                                    ${escapeHtml(fm.title)}
                                </div>
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 4px; font-size: 9px; color: var(--text-dim);">
                                    <span>Type: ${escapeHtml(fm.discussion_type || "discussion")}</span>
                                    <a href="${escapeHtml(fm.url)}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-cyan); text-decoration: none;">View Thread ↗</a>
                                </div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px; margin-top: 6px;">No external forum discussion threads detected</div>
                `}
            </div>

            <!-- 7. EXTERNAL IDENTITY CONSISTENCY & CONFLICTS -->
            <div class="evidence-card full-width">
                <div class="evidence-label">7. External Identity Consistency &amp; Cross-Platform Correlation</div>
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-top: 6px;">
                    <div>
                        <span style="font-size: 12px; color: var(--text-dim);">Correlation Status:</span>
                        <strong style="margin-left: 6px; font-size: 13px; text-transform: uppercase; color: ${consistency.status === 'consistent' ? 'var(--accent-emerald)' : consistency.status === 'inconsistent' ? 'var(--accent-rose)' : 'var(--accent-amber)'};">
                            ${escapeHtml(consistency.status || "UNKNOWN")}
                        </strong>
                    </div>
                    <div>
                        <span style="font-size: 12px; color: var(--text-dim);">Matched Sources:</span>
                        <strong style="margin-left: 6px; color: #ffffff;">
                            ${(consistency.matched_sources || []).length > 0 ? escapeHtml(consistency.matched_sources.join(", ")) : "None"}
                        </strong>
                    </div>
                </div>

                ${(consistency.conflicts || []).length > 0 ? `
                    <div style="margin-top: 10px; background: rgba(244, 63, 94, 0.08); border-left: 3px solid var(--accent-rose); padding: 8px 10px; border-radius: 4px; font-size: 11px;">
                        <strong style="color: var(--accent-rose);">Discrepancies Observed:</strong>
                        <ul style="margin: 4px 0 0 16px; color: var(--text-main);">
                            ${consistency.conflicts.map(c => `<li>${escapeHtml(c)}</li>`).join("")}
                        </ul>
                    </div>
                ` : ""}
            </div>

            <!-- 8. CONSOLIDATED OSINT EVIDENCE LOG -->
            <div class="evidence-card full-width">
                <div class="evidence-label">8. Consolidated External OSINT Forensic Evidence (${evidenceList.length} Observations)</div>
                ${evidenceList.length > 0 ? `
                    <ul class="evidence-list" style="margin-top: 6px;">
                        ${evidenceList.map(item => `
                            <li>
                                <strong style="color: var(--accent-cyan);">&bull;</strong>
                                ${escapeHtml(item)}
                            </li>
                        `).join("")}
                    </ul>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No external OSINT evidence records generated</div>
                `}
            </div>

            ${renderErrorBlock(result.errors)}
        </div>
    `;
}

/**
 * Render Agent 14: Historical Evidence
 */
function renderAgent14Evidence(result, container) {
    const d = result.data || result || {};
    const wb = d.wayback_history || {};
    const webHist = d.website_history || {};
    const ownership = d.historical_ownership || {};
    const screenshots = d.historical_screenshots || [];
    const rep = d.historical_reputation || {};
    const dns = d.historical_dns || {};
    const infra = d.infrastructure_history || {};
    const reuse = d.domain_reuse || {};
    const inactive = d.inactive_periods || [];
    const redirects = d.redirect_history || [];
    const inconsistencies = d.historical_inconsistencies || [];
    const masterTimeline = d.timeline || [];
    const evidenceList = result.evidence || [];

    const earliest = wb.earliest_snapshot || {};
    const latest = wb.latest_snapshot || {};

    container.innerHTML = `
        <div class="evidence-grid">

            <!-- 1. WAYBACK MACHINE & ARCHIVE OVERVIEW -->
            <div class="evidence-card full-width">
                <div class="evidence-label">1. Wayback Machine &amp; Archive Overview</div>
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-top: 6px;">
                    <div>
                        <div style="font-size: 18px; font-weight: 700; color: #ffffff;">
                            ${wb.available ? `${wb.snapshot_count.toLocaleString()} Archived Snapshots Found` : "No Wayback Archives Recorded"}
                        </div>
                        <div style="font-size: 12px; color: var(--text-dim); margin-top: 3px;">
                            ${earliest.date ? `Earliest Capture: <strong style="color: var(--accent-cyan);">${escapeHtml(earliest.date)}</strong> &bull; ` : ""}
                            ${latest.date ? `Latest Capture: <strong style="color: var(--accent-emerald);">${escapeHtml(latest.date)}</strong>` : ""}
                        </div>
                    </div>
                    <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                        <span style="font-size: 11px; font-weight: 600; padding: 4px 10px; border-radius: 4px; background: ${wb.available ? 'rgba(16, 185, 129, 0.12)' : 'rgba(255, 255, 255, 0.05)'}; color: ${wb.available ? 'var(--accent-emerald)' : 'var(--text-dim)'}; border: 1px solid ${wb.available ? 'rgba(16, 185, 129, 0.3)' : 'rgba(255, 255, 255, 0.08)'};">
                            Wayback: ${wb.available ? '✓ Available' : '✗ Not Available'}
                        </span>
                        <span style="font-size: 11px; font-weight: 600; padding: 4px 10px; border-radius: 4px; background: ${reuse.possible ? 'rgba(245, 158, 11, 0.12)' : 'rgba(56, 189, 248, 0.12)'}; color: ${reuse.possible ? 'var(--accent-amber)' : 'var(--accent-cyan)'}; border: 1px solid ${reuse.possible ? 'rgba(245, 158, 11, 0.3)' : 'rgba(56, 189, 248, 0.3)'};">
                            Domain Reuse: ${reuse.possible ? '⚠ Possible Prior Reuse' : '○ Continuous Identity'}
                        </span>
                    </div>
                </div>
            </div>

            <!-- 2. MASTER CHRONOLOGICAL LIFECYCLE TIMELINE -->
            <div class="evidence-card full-width">
                <div class="evidence-label">2. Chronological Domain Lifecycle Timeline (${masterTimeline.length} Events)</div>
                ${masterTimeline.length > 0 ? `
                    <div style="position: relative; margin-top: 12px; padding-left: 20px; border-left: 2px solid var(--border-color); display: flex; flex-direction: column; gap: 12px;">
                        ${masterTimeline.map(ev => `
                            <div style="position: relative;">
                                <span style="position: absolute; left: -27px; top: 3px; width: 12px; height: 12px; border-radius: 50%; background: var(--accent-cyan); border: 2px solid var(--bg-card);"></span>
                                <div style="display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap;">
                                    <strong style="color: var(--accent-cyan); font-family: var(--font-mono); font-size: 12px;">${escapeHtml(ev.date || "Past Era")}</strong>
                                    <span style="font-size: 10px; color: var(--text-dim); text-transform: uppercase;">${escapeHtml(ev.source || "Archive")}</span>
                                </div>
                                <div style="font-size: 12px; color: var(--text-main); margin-top: 2px;">
                                    ${escapeHtml(ev.event)}
                                </div>
                                ${ev.url ? `
                                    <div style="margin-top: 2px; font-size: 10px;">
                                        <a href="${escapeHtml(ev.url)}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-cyan); text-decoration: none;">View Archive Snapshot ↗</a>
                                    </div>
                                ` : ""}
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px; margin-top: 6px;">No chronological timeline events available for this domain</div>
                `}
            </div>

            <!-- 3. WEBSITE EVOLUTION & IDENTITY SHIFTS -->
            <div class="evidence-card">
                <div class="evidence-label">3. Business Identity &amp; Content Evolution</div>
                <div style="margin-top: 6px; font-size: 12px;">
                    ${(webHist.identity_changes || []).length > 0 ? `
                        <div style="margin-bottom: 8px;">
                            <strong style="color: var(--accent-amber); font-size: 11px;">Identity Shifts Observed:</strong>
                            <div style="display: flex; flex-direction: column; gap: 6px; margin-top: 4px;">
                                ${webHist.identity_changes.map(ic => `
                                    <div style="background: rgba(245, 158, 11, 0.08); padding: 6px 8px; border-radius: 4px; font-size: 11px; border-left: 3px solid var(--accent-amber);">
                                        <div style="font-weight: 600;">${escapeHtml(ic.from)} &rarr; <span style="color: #ffffff;">${escapeHtml(ic.to)}</span> (${escapeHtml(ic.approximate_date)})</div>
                                        <div style="font-size: 10px; color: var(--text-dim); margin-top: 2px;">${escapeHtml(ic.evidence)}</div>
                                    </div>
                                `).join("")}
                            </div>
                        </div>
                    ` : `
                        <div style="color: var(--text-dim); margin-bottom: 8px;">No major business identity shifts observed in archived snapshots.</div>
                    `}

                    ${(webHist.business_category_changes || []).length > 0 ? `
                        <div>
                            <strong style="color: var(--accent-cyan); font-size: 11px;">Category Changes:</strong>
                            <div style="display: flex; flex-direction: column; gap: 6px; margin-top: 4px;">
                                ${webHist.business_category_changes.map(bc => `
                                    <div style="background: rgba(56, 189, 248, 0.08); padding: 6px 8px; border-radius: 4px; font-size: 11px;">
                                        <div>${escapeHtml(bc.from)} &rarr; <strong>${escapeHtml(bc.to)}</strong> (${escapeHtml(bc.approximate_date)})</div>
                                    </div>
                                `).join("")}
                            </div>
                        </div>
                    ` : ""}
                </div>
            </div>

            <!-- 4. DOMAIN REUSE & PARKED PERIODS -->
            <div class="evidence-card">
                <div class="evidence-label">4. Domain Reuse &amp; Inactivity Analysis</div>
                <div style="margin-top: 6px; font-size: 12px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <span>Possible Domain Reuse:</span>
                        <strong style="color: ${reuse.possible ? 'var(--accent-amber)' : 'var(--accent-emerald)'};">
                            ${reuse.possible ? '⚠ Possible Prior Reuse' : '○ Consistent Origin'}
                        </strong>
                    </div>

                    ${(reuse.evidence || []).length > 0 ? `
                        <div style="background: rgba(245, 158, 11, 0.08); border-left: 3px solid var(--accent-amber); padding: 6px 8px; border-radius: 4px; font-size: 11px; margin-bottom: 8px;">
                            <strong style="color: var(--accent-amber);">Reuse Indicators:</strong>
                            <ul style="margin: 4px 0 0 14px; color: var(--text-main);">
                                ${reuse.evidence.map(e => `<li>${escapeHtml(e)}</li>`).join("")}
                            </ul>
                        </div>
                    ` : ""}

                    ${inactive.length > 0 ? `
                        <div style="margin-top: 6px;">
                            <span style="color: var(--text-dim); font-size: 11px;">Inactive / Parked Eras (${inactive.length}):</span>
                            <div style="display: flex; flex-direction: column; gap: 4px; margin-top: 4px;">
                                ${inactive.map(ia => `
                                    <div style="background: rgba(255,255,255,0.03); padding: 4px 8px; border-radius: 4px; font-size: 11px; display: flex; justify-content: space-between;">
                                        <span>Period: <strong>${escapeHtml(ia.period || ia.date)}</strong></span>
                                        <span style="color: var(--accent-amber);">${escapeHtml(ia.status)}</span>
                                    </div>
                                `).join("")}
                            </div>
                        </div>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No domain parking or inactive placeholders observed.</div>
                    `}
                </div>
            </div>

            <!-- 5. HISTORICAL SCREENSHOTS & SNAPSHOT ARCHIVE -->
            <div class="evidence-card full-width">
                <div class="evidence-label">5. Historical Snapshots &amp; Wayback Archive Access (${screenshots.length} Milestone Captures)</div>
                ${screenshots.length > 0 ? `
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 8px; margin-top: 8px;">
                        ${screenshots.map(sn => `
                            <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--border-color); border-radius: 6px; padding: 8px 10px; font-size: 11px;">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <strong style="color: var(--accent-cyan);">${escapeHtml(sn.year || sn.date)}</strong>
                                    <span style="font-size: 9px; color: var(--text-dim);">${escapeHtml(sn.date)}</span>
                                </div>
                                <div style="margin-top: 6px;">
                                    <a href="${escapeHtml(sn.snapshot_url)}" target="_blank" rel="noopener noreferrer" style="display: inline-block; font-size: 10px; color: var(--accent-cyan); text-decoration: none; background: rgba(56, 189, 248, 0.1); padding: 3px 6px; border-radius: 4px;">
                                        Open Snapshot ↗
                                    </a>
                                </div>
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px; margin-top: 6px;">No historical snapshot captures available</div>
                `}
            </div>

            <!-- 6. HISTORICAL DNS & INFRASTRUCTURE CHANGES -->
            <div class="evidence-card">
                <div class="evidence-label">6. Historical DNS &amp; Infrastructure Transitions</div>
                <div style="margin-top: 6px; font-size: 12px;">
                    ${(infra.ip_changes || []).length > 0 ? `
                        <div style="margin-bottom: 8px;">
                            <strong style="color: var(--accent-cyan); font-size: 11px;">IP Address History:</strong>
                            <div style="display: flex; flex-direction: column; gap: 4px; margin-top: 4px;">
                                ${infra.ip_changes.map(ipc => `
                                    <div style="background: rgba(255,255,255,0.03); padding: 4px 8px; border-radius: 4px; font-size: 11px;">
                                        <code>${escapeHtml(ipc.from)}</code> &rarr; <code>${escapeHtml(ipc.to)}</code> (${escapeHtml(ipc.date)})
                                    </div>
                                `).join("")}
                            </div>
                        </div>
                    ` : ""}

                    ${(infra.nameserver_changes || []).length > 0 ? `
                        <div>
                            <strong style="color: var(--accent-cyan); font-size: 11px;">Nameserver Changes:</strong>
                            <div style="display: flex; flex-direction: column; gap: 4px; margin-top: 4px;">
                                ${infra.nameserver_changes.map(nsc => `
                                    <div style="background: rgba(255,255,255,0.03); padding: 4px 8px; border-radius: 4px; font-size: 11px;">
                                        ${escapeHtml(nsc.from)} &rarr; <strong>${escapeHtml(nsc.to)}</strong> (${escapeHtml(nsc.date)})
                                    </div>
                                `).join("")}
                            </div>
                        </div>
                    ` : ""}

                    ${(infra.ip_changes || []).length === 0 && (infra.nameserver_changes || []).length === 0 ? `
                        <div style="color: var(--text-dim); font-size: 11px;">
                            Historical DNS dataset status: ${dns.available ? 'Available' : 'Public passive baseline / Not available'}
                        </div>
                    ` : ""}
                </div>
            </div>

            <!-- 7. PREVIOUS REPUTATION & HISTORICAL DISCLOSURES -->
            <div class="evidence-card">
                <div class="evidence-label">7. Previous Reputation &amp; Historical Reports</div>
                <div style="margin-top: 6px; font-size: 12px;">
                    <div style="display: flex; gap: 8px; margin-bottom: 8px;">
                        <span style="font-size: 11px; padding: 2px 6px; border-radius: 3px; background: rgba(244, 63, 94, 0.12); color: var(--accent-rose);">
                            ${(rep.negative_reports || []).length} Negative
                        </span>
                        <span style="font-size: 11px; padding: 2px 6px; border-radius: 3px; background: rgba(16, 185, 129, 0.12); color: var(--accent-emerald);">
                            ${(rep.positive_reports || []).length} Positive
                        </span>
                        <span style="font-size: 11px; padding: 2px 6px; border-radius: 3px; background: rgba(255, 255, 255, 0.05); color: var(--text-dim);">
                            ${(rep.neutral_reports || []).length} Neutral
                        </span>
                    </div>

                    ${(rep.reports || []).length > 0 ? `
                        <div style="display: flex; flex-direction: column; gap: 6px;">
                            ${rep.reports.map(rp => `
                                <div style="background: rgba(255,255,255,0.03); padding: 6px 8px; border-radius: 4px; font-size: 11px; border-left: 3px solid ${rp.sentiment === 'negative' ? 'var(--accent-rose)' : 'var(--accent-cyan)'};">
                                    <div style="display: flex; justify-content: space-between;">
                                        <strong style="color: #ffffff;">${escapeHtml(rp.title || "Report")}</strong>
                                        <span style="font-size: 9px; color: var(--text-dim);">${escapeHtml(rp.date || "")}</span>
                                    </div>
                                    <div style="font-size: 10px; color: var(--text-dim); margin-top: 2px;">${escapeHtml(rp.summary || rp.snippet || "")}</div>
                                </div>
                            `).join("")}
                        </div>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No historical security reports or prior negative reputation records found.</div>
                    `}
                </div>
            </div>

            <!-- 8. HISTORICAL INCONSISTENCIES & CLAIMS -->
            ${inconsistencies.length > 0 ? `
                <div class="evidence-card full-width">
                    <div class="evidence-label">8. Historical Inconsistencies &amp; Claim Comparisons (${inconsistencies.length} Observations)</div>
                    <div style="display: flex; flex-direction: column; gap: 6px; margin-top: 6px;">
                        ${inconsistencies.map(inc => `
                            <div style="background: rgba(245, 158, 11, 0.08); border-left: 3px solid var(--accent-amber); padding: 8px 10px; border-radius: 4px; font-size: 11px;">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <strong style="color: var(--accent-amber);">${escapeHtml(inc.claim)}</strong>
                                    <span style="font-size: 9px; text-transform: uppercase; color: var(--text-dim);">${escapeHtml(inc.assessment)}</span>
                                </div>
                                <div style="margin-top: 3px; color: #ffffff;">${escapeHtml(inc.historical_evidence)}</div>
                                <div style="margin-top: 2px; font-size: 10px; color: var(--text-dim);">${escapeHtml(inc.notes || "")}</div>
                            </div>
                        `).join("")}
                    </div>
                </div>
            ` : ""}

            <!-- 9. CONSOLIDATED HISTORICAL EVIDENCE LOG -->
            <div class="evidence-card full-width">
                <div class="evidence-label">9. Consolidated Historical Forensic Evidence (${evidenceList.length} Observations)</div>
                ${evidenceList.length > 0 ? `
                    <ul class="evidence-list" style="margin-top: 6px;">
                        ${evidenceList.map(item => `
                            <li>
                                <strong style="color: var(--accent-cyan);">&bull;</strong>
                                ${escapeHtml(item)}
                            </li>
                        `).join("")}
                    </ul>
                ` : `
                    <div class="evidence-value" style="color: var(--text-dim); font-size: 12px;">No historical forensic evidence records generated</div>
                `}
            </div>

            ${renderErrorBlock(result.errors)}
        </div>
    `;
}

/**
 * Render Evidence Details for Agent 15: User Trust Signals Agent
 */
function renderAgent15Evidence(result, container) {
    const inp = result.input || {};
    const tp = result.trustpilot || {};
    const gr = result.google_reviews || {};
    const reddit = result.reddit || {};
    const summary = result.review_summary || { total: 0, positive: 0, negative: 0, neutral: 0, mixed: 0 };
    const recurring = result.recurring_complaints || [];
    const crossSrc = result.cross_source_patterns || [];
    const posSignals = result.positive_signals || [];
    const negSignals = result.negative_signals || [];
    const scamComplaints = result.scam_complaints || [];
    const testimonials = result.customer_testimonials || [];
    const forums = result.complaint_forums || [];
    const anomalies = result.review_anomalies || [];
    const timeline = result.timeline || [];
    const evidenceList = result.evidence || [];

    const getSentimentBadge = (sent) => {
        const s = (sent || "").toLowerCase();
        if (s === "positive") return `<span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald); font-weight: 600;">POSITIVE</span>`;
        if (s === "negative") return `<span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(244, 63, 94, 0.15); color: var(--accent-rose); font-weight: 600;">NEGATIVE</span>`;
        if (s === "mixed") return `<span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(245, 158, 11, 0.15); color: var(--accent-amber); font-weight: 600;">MIXED</span>`;
        return `<span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(255, 255, 255, 0.08); color: var(--text-dim); font-weight: 600;">${escapeHtml((sent || "NEUTRAL").toUpperCase())}</span>`;
    };

    const getEntityMatchBadge = (match) => {
        const m = (match || "").toLowerCase();
        if (m === "confirmed") return `<span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald);">CONFIRMED MATCH</span>`;
        if (m === "probable") return `<span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(6, 182, 212, 0.15); color: var(--accent-cyan);">PROBABLE MATCH</span>`;
        return `<span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(245, 158, 11, 0.15); color: var(--accent-amber);">UNCERTAIN MATCH</span>`;
    };

    const getVerificationBadge = (ver) => {
        const v = (ver || "").toLowerCase();
        if (v === "verified") return `<span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald);">VERIFIED</span>`;
        if (v === "partially_verified") return `<span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(6, 182, 212, 0.15); color: var(--accent-cyan);">PARTIALLY VERIFIED</span>`;
        if (v === "not_verified") return `<span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(245, 158, 11, 0.15); color: var(--accent-amber);">NOT VERIFIED</span>`;
        return `<span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(255, 255, 255, 0.08); color: var(--text-dim);">NOT AVAILABLE</span>`;
    };

    container.innerHTML = `
        <div class="evidence-grid">

            <!-- 1. TARGET IDENTITY & USER REVIEWS VOLUME SUMMARY -->
            <div class="evidence-card full-width">
                <div class="evidence-label">1. Target Identity &amp; Reputation Summary</div>
                <div style="display: flex; flex-wrap: wrap; gap: 16px; margin-top: 8px; font-size: 12px;">
                    <div><span style="color: var(--text-dim);">Domain:</span> <strong>${escapeHtml(inp.domain || "N/A")}</strong></div>
                    <div><span style="color: var(--text-dim);">Company / Brand:</span> <strong>${escapeHtml(inp.company_name || "N/A")}</strong></div>
                    <div><span style="color: var(--text-dim);">Target URL:</span> <code style="font-size: 11px;">${escapeHtml(inp.original_url || "N/A")}</code></div>
                </div>

                <!-- Review Volume Summary Bar -->
                <div style="margin-top: 14px; background: rgba(255,255,255,0.03); padding: 12px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.06);">
                    <div style="font-size: 11px; text-transform: uppercase; color: var(--text-dim); margin-bottom: 8px; font-weight: 600;">
                        Evidence Volume &amp; Sentiment Breakdown
                    </div>
                    <div style="display: flex; flex-wrap: wrap; gap: 10px;">
                        <div style="background: rgba(255,255,255,0.06); padding: 6px 12px; border-radius: 4px; text-align: center;">
                            <div style="font-size: 16px; font-weight: 700; color: #ffffff;">${summary.total || 0}</div>
                            <div style="font-size: 10px; color: var(--text-dim);">Total Observations</div>
                        </div>
                        <div style="background: rgba(16, 185, 129, 0.1); border-left: 3px solid var(--accent-emerald); padding: 6px 12px; border-radius: 4px; text-align: center;">
                            <div style="font-size: 16px; font-weight: 700; color: var(--accent-emerald);">${summary.positive || 0}</div>
                            <div style="font-size: 10px; color: var(--text-dim);">Positive Reports</div>
                        </div>
                        <div style="background: rgba(244, 63, 94, 0.1); border-left: 3px solid var(--accent-rose); padding: 6px 12px; border-radius: 4px; text-align: center;">
                            <div style="font-size: 16px; font-weight: 700; color: var(--accent-rose);">${summary.negative || 0}</div>
                            <div style="font-size: 10px; color: var(--text-dim);">Negative Reports</div>
                        </div>
                        <div style="background: rgba(245, 158, 11, 0.1); border-left: 3px solid var(--accent-amber); padding: 6px 12px; border-radius: 4px; text-align: center;">
                            <div style="font-size: 16px; font-weight: 700; color: var(--accent-amber);">${summary.mixed || 0}</div>
                            <div style="font-size: 10px; color: var(--text-dim);">Mixed Feedback</div>
                        </div>
                        <div style="background: rgba(255, 255, 255, 0.05); padding: 6px 12px; border-radius: 4px; text-align: center;">
                            <div style="font-size: 16px; font-weight: 700; color: var(--text-dim);">${summary.neutral || 0}</div>
                            <div style="font-size: 10px; color: var(--text-dim);">Inquiries / Neutral</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 2. TRUSTPILOT PROFILE & REPUTATION -->
            <div class="evidence-card">
                <div class="evidence-label">2. Trustpilot Reputation Profile</div>
                <div style="margin-top: 8px; font-size: 12px;">
                    ${tp.available ? `
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                            <div>
                                <span style="font-size: 20px; font-weight: 800; color: ${tp.rating >= 3.8 ? 'var(--accent-emerald)' : (tp.rating <= 2.5 ? 'var(--accent-rose)' : 'var(--accent-amber)')};">
                                    ★ ${tp.rating || "N/A"}
                                </span>
                                <span style="font-size: 11px; color: var(--text-dim);"> / 5.0</span>
                            </div>
                            <div style="font-size: 11px; color: var(--text-dim);">
                                ${tp.review_count ? `${tp.review_count.toLocaleString()} Reviews` : "Review count unavailable"}
                            </div>
                        </div>

                        ${tp.profile_url ? `
                            <div style="margin-bottom: 8px;">
                                <a href="${escapeHtml(tp.profile_url)}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-cyan); font-size: 11px; text-decoration: none;">
                                    View Trustpilot Profile ↗
                                </a>
                            </div>
                        ` : ""}

                        ${(tp.positive_patterns || []).length > 0 ? `
                            <div style="margin-top: 6px; font-size: 11px;">
                                <strong style="color: var(--accent-emerald);">Positive Review Themes:</strong>
                                <ul style="margin: 4px 0 6px 16px; color: var(--text-dim);">
                                    ${tp.positive_patterns.slice(0, 3).map(p => `<li>${escapeHtml(p)}</li>`).join("")}
                                </ul>
                            </div>
                        ` : ""}

                        ${(tp.negative_patterns || []).length > 0 ? `
                            <div style="margin-top: 6px; font-size: 11px;">
                                <strong style="color: var(--accent-rose);">Negative Review Themes:</strong>
                                <ul style="margin: 4px 0 6px 16px; color: var(--text-dim);">
                                    ${tp.negative_patterns.slice(0, 3).map(p => `<li>${escapeHtml(p)}</li>`).join("")}
                                </ul>
                            </div>
                        ` : ""}
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No public Trustpilot profile found or domain not indexed.</div>
                    `}
                </div>
            </div>

            <!-- 3. GOOGLE REVIEWS & BUSINESS PRESENCE -->
            <div class="evidence-card">
                <div class="evidence-label">3. Google Reviews &amp; Business Presence</div>
                <div style="margin-top: 8px; font-size: 12px;">
                    ${gr.available ? `
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                            <div>
                                <span style="font-size: 20px; font-weight: 800; color: ${gr.rating >= 3.8 ? 'var(--accent-emerald)' : (gr.rating <= 2.5 ? 'var(--accent-rose)' : 'var(--accent-amber)')};">
                                    ★ ${gr.rating || "N/A"}
                                </span>
                                <span style="font-size: 11px; color: var(--text-dim);"> / 5.0</span>
                            </div>
                            <div>${getEntityMatchBadge(gr.entity_match)}</div>
                        </div>

                        <div style="font-size: 11px; color: var(--text-dim); margin-bottom: 6px;">
                            <strong>Business:</strong> ${escapeHtml(gr.business_name || "N/A")}
                            ${gr.location ? ` | <span>Location: ${escapeHtml(gr.location)}</span>` : ""}
                            ${gr.review_count ? ` | <span>${gr.review_count.toLocaleString()} Reviews</span>` : ""}
                        </div>

                        ${gr.profile_url ? `
                            <div style="margin-bottom: 8px;">
                                <a href="${escapeHtml(gr.profile_url)}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-cyan); font-size: 11px; text-decoration: none;">
                                    View Google Business Profile ↗
                                </a>
                            </div>
                        ` : ""}

                        ${(gr.positive_themes || []).length > 0 ? `
                            <div style="margin-top: 4px; font-size: 11px; color: var(--accent-emerald);">
                                &bull; ${escapeHtml(gr.positive_themes.join(", "))}
                            </div>
                        ` : ""}
                        ${(gr.negative_themes || []).length > 0 ? `
                            <div style="margin-top: 4px; font-size: 11px; color: var(--accent-rose);">
                                &bull; ${escapeHtml(gr.negative_themes.join(", "))}
                            </div>
                        ` : ""}
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No verified public Google Business profile found for this domain identity.</div>
                    `}
                </div>
            </div>

            <!-- 4. REDDIT COMMUNITY DISCUSSIONS -->
            <div class="evidence-card">
                <div class="evidence-label">4. Reddit Community Discussions (${reddit.discussions_found || 0} Found)</div>
                <div style="margin-top: 8px; font-size: 12px;">
                    ${(reddit.discussions || []).length > 0 ? `
                        <div style="display: flex; gap: 8px; margin-bottom: 8px;">
                            <span style="font-size: 10px; color: var(--accent-emerald);">${reddit.positive_count || 0} Positive</span>
                            <span style="font-size: 10px; color: var(--accent-rose);">${reddit.negative_count || 0} Negative</span>
                            <span style="font-size: 10px; color: var(--text-dim);">${reddit.neutral_count || 0} Neutral</span>
                        </div>

                        <div style="display: flex; flex-direction: column; gap: 6px; max-height: 220px; overflow-y: auto;">
                            ${reddit.discussions.slice(0, 6).map(d => `
                                <div style="background: rgba(255,255,255,0.02); padding: 6px 8px; border-radius: 4px; border-left: 2px solid var(--accent-cyan); font-size: 11px;">
                                    <div style="display: flex; justify-content: space-between; align-items: center;">
                                        <span style="color: var(--accent-cyan); font-weight: 600;">${escapeHtml(d.subreddit)}</span>
                                        <span style="font-size: 9px; color: var(--text-dim);">${escapeHtml(d.date || "")}</span>
                                    </div>
                                    <div style="margin: 2px 0; color: #ffffff;">${escapeHtml(d.title)}</div>
                                    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 4px;">
                                        <div>${getSentimentBadge(d.sentiment)}</div>
                                        <a href="${escapeHtml(d.url)}" target="_blank" rel="noopener noreferrer" style="font-size: 10px; color: var(--text-dim); text-decoration: none;">Link ↗</a>
                                    </div>
                                </div>
                            `).join("")}
                        </div>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No public Reddit discussions or user threads discovered.</div>
                    `}
                </div>
            </div>

            <!-- 5. SCAM COMPLAINTS & GRIEVANCES -->
            <div class="evidence-card">
                <div class="evidence-label">5. Public Scam Complaints (${scamComplaints.length} Records)</div>
                <div style="margin-top: 8px; font-size: 12px;">
                    ${scamComplaints.length > 0 ? `
                        <div style="display: flex; flex-direction: column; gap: 6px; max-height: 220px; overflow-y: auto;">
                            ${scamComplaints.slice(0, 6).map(sc => `
                                <div style="background: rgba(244, 63, 94, 0.06); border-left: 3px solid var(--accent-rose); padding: 6px 8px; border-radius: 4px; font-size: 11px;">
                                    <div style="display: flex; justify-content: space-between; align-items: center;">
                                        <strong style="color: var(--accent-rose);">${escapeHtml((sc.category || "Complaint").replace("_", " ").toUpperCase())}</strong>
                                        <span style="font-size: 9px; color: var(--text-dim);">${escapeHtml(sc.source)}</span>
                                    </div>
                                    <div style="margin-top: 2px; color: #ffffff;">${escapeHtml(sc.complaint_summary || sc.title)}</div>
                                    ${sc.url ? `
                                        <div style="margin-top: 4px; text-align: right;">
                                            <a href="${escapeHtml(sc.url)}" target="_blank" rel="noopener noreferrer" style="font-size: 10px; color: var(--accent-rose); text-decoration: none;">Source Record ↗</a>
                                        </div>
                                    ` : ""}
                                </div>
                            `).join("")}
                        </div>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No public scam allegations or consumer complaints indexed.</div>
                    `}
                </div>
            </div>

            <!-- 6. OFFICIAL WEBSITE TESTIMONIALS (SELF-PUBLISHED) -->
            <div class="evidence-card">
                <div class="evidence-label">6. Official Website Testimonials (${testimonials.length} Found)</div>
                <div style="font-size: 10px; color: var(--accent-amber); margin-bottom: 6px;">
                    ⚠ SELF-PUBLISHED CLAIMS: Testimonials on official website are separated from third-party reviews.
                </div>
                <div style="margin-top: 6px; font-size: 12px;">
                    ${testimonials.length > 0 ? `
                        <div style="display: flex; flex-direction: column; gap: 6px; max-height: 220px; overflow-y: auto;">
                            ${testimonials.map(t => `
                                <div style="background: rgba(255,255,255,0.02); padding: 6px 8px; border-radius: 4px; border-left: 2px solid var(--accent-amber); font-size: 11px;">
                                    <div style="display: flex; justify-content: space-between; align-items: center;">
                                        <strong style="color: #ffffff;">${escapeHtml(t.name || "Customer")}</strong>
                                        ${getVerificationBadge(t.verification)}
                                    </div>
                                    ${t.company ? `<div style="font-size: 10px; color: var(--text-dim);">${escapeHtml(t.company)}</div>` : ""}
                                    <div style="margin-top: 3px; font-style: italic; color: var(--text-dim);">"${escapeHtml(t.testimonial)}"</div>
                                </div>
                            `).join("")}
                        </div>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No testimonial quotes or endorsement blocks detected on target website HTML.</div>
                    `}
                </div>
            </div>

            <!-- 7. COMPLAINT FORUMS & CONSUMER THREADS -->
            <div class="evidence-card">
                <div class="evidence-label">7. Public Complaint Forums (${forums.length} Threads)</div>
                <div style="margin-top: 8px; font-size: 12px;">
                    ${forums.length > 0 ? `
                        <div style="display: flex; flex-direction: column; gap: 6px; max-height: 220px; overflow-y: auto;">
                            ${forums.map(f => `
                                <div style="background: rgba(255,255,255,0.02); padding: 6px 8px; border-radius: 4px; border-left: 2px solid var(--accent-rose); font-size: 11px;">
                                    <div style="display: flex; justify-content: space-between; align-items: center;">
                                        <strong style="color: #ffffff;">${escapeHtml(f.title || "Complaint")}</strong>
                                        <span style="font-size: 9px; color: var(--text-dim);">${escapeHtml(f.platform || "Forum")}</span>
                                    </div>
                                    <div style="margin-top: 2px; color: var(--text-dim);">${escapeHtml(f.summary || "")}</div>
                                    ${f.url ? `
                                        <div style="margin-top: 4px; text-align: right;">
                                            <a href="${escapeHtml(f.url)}" target="_blank" rel="noopener noreferrer" style="font-size: 10px; color: var(--accent-cyan); text-decoration: none;">Forum Thread ↗</a>
                                        </div>
                                    ` : ""}
                                </div>
                            `).join("")}
                        </div>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No consumer grievance threads found on public complaint forums.</div>
                    `}
                </div>
            </div>

            <!-- 8. RECURRING COMPLAINT PATTERNS & CROSS-SOURCE CORROBORATION -->
            <div class="evidence-card full-width">
                <div class="evidence-label">8. Recurring Complaint Patterns &amp; Cross-Source Corroboration</div>
                <div style="margin-top: 8px; font-size: 12px;">
                    ${recurring.length > 0 ? `
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 10px;">
                            ${recurring.map(r => `
                                <div style="background: rgba(244, 63, 94, 0.08); border: 1px solid rgba(244, 63, 94, 0.2); border-radius: 6px; padding: 10px;">
                                    <div style="display: flex; justify-content: space-between; align-items: center;">
                                        <strong style="color: var(--accent-rose); font-size: 13px;">${escapeHtml(r.pattern.replace("_", " ").toUpperCase())}</strong>
                                        <span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(255,255,255,0.08); color: #ffffff;">
                                            ${r.occurrences} Reports
                                        </span>
                                    </div>
                                    <div style="margin-top: 6px; font-size: 11px; color: var(--text-dim);">
                                        <strong>Reported on ${r.unique_sources} Unique Platforms:</strong> ${(r.sources || []).join(", ")}
                                    </div>
                                    <div style="margin-top: 6px; display: flex; justify-content: space-between; align-items: center;">
                                        <span style="font-size: 10px; color: ${r.cross_source_corroboration ? 'var(--accent-emerald)' : 'var(--accent-amber)'}; font-weight: 600;">
                                            ${r.cross_source_corroboration ? '✓ Cross-Source Corroborated' : '○ Single-Source Repetition'}
                                        </span>
                                        <span style="font-size: 9px; color: var(--text-dim); text-transform: uppercase;">Confidence: ${r.confidence}</span>
                                    </div>
                                </div>
                            `).join("")}
                        </div>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No recurring complaint clusters or cross-source corroboration patterns identified.</div>
                    `}
                </div>
            </div>

            <!-- 9. POSITIVE SIGNALS VS NEGATIVE SIGNALS -->
            <div class="evidence-card">
                <div class="evidence-label" style="color: var(--accent-emerald);">9A. Positive Reputation Signals (${posSignals.length})</div>
                <div style="margin-top: 8px; font-size: 12px;">
                    ${posSignals.length > 0 ? `
                        <ul style="margin: 0; padding-left: 16px; color: var(--text-dim); font-size: 11px;">
                            ${posSignals.map(s => `<li style="margin-bottom: 4px;"><strong style="color: var(--accent-emerald);">&bull;</strong> ${escapeHtml(s)}</li>`).join("")}
                        </ul>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No explicit positive reputation signals recorded.</div>
                    `}
                </div>
            </div>

            <div class="evidence-card">
                <div class="evidence-label" style="color: var(--accent-rose);">9B. Negative Reputation Signals (${negSignals.length})</div>
                <div style="margin-top: 8px; font-size: 12px;">
                    ${negSignals.length > 0 ? `
                        <ul style="margin: 0; padding-left: 16px; color: var(--text-dim); font-size: 11px;">
                            ${negSignals.map(s => `<li style="margin-bottom: 4px;"><strong style="color: var(--accent-rose);">&bull;</strong> ${escapeHtml(s)}</li>`).join("")}
                        </ul>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No explicit negative reputation patterns detected.</div>
                    `}
                </div>
            </div>

            <!-- 10. REVIEW ANOMALIES -->
            ${anomalies.length > 0 ? `
                <div class="evidence-card full-width">
                    <div class="evidence-label" style="color: var(--accent-amber);">10. Review Anomalies &amp; Duplication Indicators (${anomalies.length})</div>
                    <div style="margin-top: 6px; display: flex; flex-direction: column; gap: 6px;">
                        ${anomalies.map(a => `
                            <div style="background: rgba(245, 158, 11, 0.08); border-left: 3px solid var(--accent-amber); padding: 6px 8px; border-radius: 4px; font-size: 11px;">
                                <div style="color: var(--accent-amber); font-weight: 600;">${escapeHtml(a.observation)}</div>
                                ${a.snippet ? `<div style="color: var(--text-dim); font-size: 10px; margin-top: 2px;">Snippet: "${escapeHtml(a.snippet)}"</div>` : ""}
                            </div>
                        `).join("")}
                    </div>
                </div>
            ` : ""}

            <!-- 11. EVIDENCE TIMELINE -->
            <div class="evidence-card full-width">
                <div class="evidence-label">11. Reputation Evidence Timeline</div>
                <div style="margin-top: 8px; font-size: 12px;">
                    ${timeline.length > 0 ? `
                        <div style="display: flex; flex-direction: column; gap: 8px;">
                            ${timeline.map(t => `
                                <div style="display: flex; gap: 12px; align-items: baseline; font-size: 11px;">
                                    <span style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-cyan); min-width: 60px;">${escapeHtml(t.period)}</span>
                                    <span style="color: #ffffff;">${escapeHtml(t.summary)}</span>
                                </div>
                            `).join("")}
                        </div>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">Timeline data unavailable or reviews are undated.</div>
                    `}
                </div>
            </div>

            <!-- 12. STANDARDIZED SOURCE EVIDENCE LOG -->
            <div class="evidence-card full-width">
                <div class="evidence-label">12. Traceable Forensic Evidence Log (${evidenceList.length} Observations)</div>
                <div style="margin-top: 8px; font-size: 11px; max-height: 280px; overflow-y: auto;">
                    ${evidenceList.length > 0 ? `
                        <table style="width: 100%; border-collapse: collapse; font-size: 11px; text-align: left;">
                            <thead>
                                <tr style="border-bottom: 1px solid rgba(255,255,255,0.1); color: var(--text-dim);">
                                    <th style="padding: 6px;">Source</th>
                                    <th style="padding: 6px;">Date</th>
                                    <th style="padding: 6px;">Observation</th>
                                    <th style="padding: 6px;">Category</th>
                                    <th style="padding: 6px;">Sentiment</th>
                                    <th style="padding: 6px;">Link</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${evidenceList.map(ev => `
                                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
                                        <td style="padding: 6px; color: var(--accent-cyan); font-weight: 600;">${escapeHtml(ev.source || "N/A")}</td>
                                        <td style="padding: 6px; color: var(--text-dim); font-size: 10px;">${escapeHtml(ev.date || "")}</td>
                                        <td style="padding: 6px; color: #ffffff;">${escapeHtml(ev.observation || "")}</td>
                                        <td style="padding: 6px; color: var(--text-dim);">${escapeHtml(ev.category || "other")}</td>
                                        <td style="padding: 6px;">${getSentimentBadge(ev.sentiment)}</td>
                                        <td style="padding: 6px;">
                                            ${ev.source_url ? `<a href="${escapeHtml(ev.source_url)}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-cyan); text-decoration: none;">↗</a>` : "-"}
                                        </td>
                                    </tr>
                                `).join("")}
                            </tbody>
                        </table>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No evidence log entries collected.</div>
                    `}
                </div>
            </div>

            ${renderErrorBlock(result.errors)}
        </div>
    `;
}

/**
 * Render Evidence Details for Agent 16: Network Security Analysis Agent
 */
function renderAgent16Evidence(result, container) {
    const inp = result.input || {};
    const ports = result.open_ports || {};
    const http = result.http_headers || {};
    const sec = result.security_headers || {};
    const cors = result.cors || {};
    const csp = result.csp || {};
    const xfo = result.x_frame_options || {};
    const xxss = result.x_xss_protection || {};
    const server = result.server_fingerprinting || {};
    const evidenceList = result.evidence || [];

    const getHeaderBadge = (present, valText = "") => {
        if (present) {
            return `<span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald); font-weight: 600;">PRESENT</span>`;
        }
        return `<span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(244, 63, 94, 0.12); color: var(--accent-rose); font-weight: 600;">NOT PRESENT</span>`;
    };

    const getPortStateBadge = (state) => {
        const s = (state || "").toLowerCase();
        if (s === "open") return `<span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald); font-weight: 600;">OPEN</span>`;
        if (s === "filtered") return `<span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(245, 158, 11, 0.15); color: var(--accent-amber); font-weight: 600;">FILTERED</span>`;
        if (s === "closed") return `<span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(255, 255, 255, 0.06); color: var(--text-dim); font-weight: 600;">CLOSED</span>`;
        return `<span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(255, 255, 255, 0.06); color: var(--text-dim);">${escapeHtml(state || "UNKNOWN")}</span>`;
    };

    container.innerHTML = `
        <div class="evidence-grid">

            <!-- 1. TARGET IDENTITY & NETWORK REACHABILITY -->
            <div class="evidence-card full-width">
                <div class="evidence-label">1. Target Identity &amp; Network Reachability</div>
                <div style="display: flex; flex-wrap: wrap; gap: 16px; margin-top: 8px; font-size: 12px;">
                    <div><span style="color: var(--text-dim);">Hostname:</span> <strong>${escapeHtml(inp.hostname || "N/A")}</strong></div>
                    <div><span style="color: var(--text-dim);">Domain:</span> <strong>${escapeHtml(inp.domain || "N/A")}</strong></div>
                    <div><span style="color: var(--text-dim);">Resolved IP:</span> <code style="font-size: 11px;">${escapeHtml(inp.resolved_ip || "Not resolved")}</code></div>
                    <div><span style="color: var(--text-dim);">Scheme:</span> <strong>${escapeHtml((inp.scheme || "https").toUpperCase())}</strong></div>
                </div>

                <!-- Reachability Badges Bar -->
                <div style="display: flex; flex-wrap: wrap; gap: 10px; margin-top: 12px;">
                    <div style="background: rgba(255,255,255,0.03); padding: 8px 12px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.06); display: flex; align-items: center; gap: 8px;">
                        <span style="color: var(--text-dim); font-size: 11px;">HTTPS Reachable:</span>
                        <strong style="color: ${http.https_reachable ? 'var(--accent-emerald)' : 'var(--accent-rose)'}; font-size: 11px;">
                            ${http.https_reachable ? '✓ YES' : '✕ NO'}
                        </strong>
                    </div>
                    <div style="background: rgba(255,255,255,0.03); padding: 8px 12px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.06); display: flex; align-items: center; gap: 8px;">
                        <span style="color: var(--text-dim); font-size: 11px;">HTTP Reachable:</span>
                        <strong style="color: ${http.http_reachable ? 'var(--accent-emerald)' : 'var(--text-dim)'}; font-size: 11px;">
                            ${http.http_reachable ? '✓ YES' : '○ NO'}
                        </strong>
                    </div>
                    <div style="background: rgba(255,255,255,0.03); padding: 8px 12px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.06); display: flex; align-items: center; gap: 8px;">
                        <span style="color: var(--text-dim); font-size: 11px;">HTTP → HTTPS Redirect:</span>
                        <strong style="color: ${http.http_to_https_redirect ? 'var(--accent-emerald)' : 'var(--accent-amber)'}; font-size: 11px;">
                            ${http.http_to_https_redirect ? '✓ YES (Enforced)' : '○ NOT ENFORCED'}
                        </strong>
                    </div>
                </div>
            </div>

            <!-- 2. SAFE OPEN WEB PORTS INSPECTION -->
            <div class="evidence-card">
                <div class="evidence-label">2. Open Ports Inspection (Safe Standard Ports)</div>
                <div style="margin-top: 8px; font-size: 12px;">
                    <table style="width: 100%; border-collapse: collapse; font-size: 11px; text-align: left;">
                        <thead>
                            <tr style="border-bottom: 1px solid rgba(255,255,255,0.1); color: var(--text-dim);">
                                <th style="padding: 6px 4px;">Port</th>
                                <th style="padding: 6px 4px;">Service</th>
                                <th style="padding: 6px 4px;">State</th>
                                <th style="padding: 6px 4px;">Latency</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${Object.keys(ports).length > 0 ? Object.values(ports).map(p => `
                                <tr style="border-bottom: 1px solid rgba(255,255,255,0.03);">
                                    <td style="padding: 6px 4px; font-family: var(--font-mono); font-weight: 600; color: #ffffff;">${p.port}/tcp</td>
                                    <td style="padding: 6px 4px; color: var(--text-dim);">${escapeHtml(p.service_guess || "")}</td>
                                    <td style="padding: 6px 4px;">${getPortStateBadge(p.state)}</td>
                                    <td style="padding: 6px 4px; color: var(--text-dim); font-size: 10px;">${p.response_time_ms ? `${p.response_time_ms} ms` : '-'}</td>
                                </tr>
                            `).join("") : `
                                <tr><td colspan="4" style="padding: 8px; color: var(--text-dim);">Port check results unavailable</td></tr>
                            `}
                        </tbody>
                    </table>
                    <div style="font-size: 10px; color: var(--text-dim); margin-top: 6px;">
                        ℹ Non-aggressive TCP connection checks only. Open ports indicate active service availability.
                    </div>
                </div>
            </div>

            <!-- 3. HTTP RESPONSE & REDIRECT CHAIN -->
            <div class="evidence-card">
                <div class="evidence-label">3. HTTP Response &amp; Headers Metadata</div>
                <div style="margin-top: 8px; font-size: 12px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <div>
                            <span style="color: var(--text-dim); font-size: 11px;">Status Code:</span>
                            <span style="font-size: 14px; font-weight: 700; color: ${http.status_code === 200 ? 'var(--accent-emerald)' : 'var(--accent-amber)'}; margin-left: 6px;">
                                ${http.status_code || "N/A"}
                            </span>
                        </div>
                        <div style="font-size: 11px; color: var(--text-dim);">
                            Redirects: <strong>${http.redirect_count || 0}</strong>
                        </div>
                    </div>

                    ${(http.redirect_chain || []).length > 1 ? `
                        <div style="margin-bottom: 8px; background: rgba(255,255,255,0.02); padding: 6px; border-radius: 4px;">
                            <div style="font-size: 10px; color: var(--text-dim); margin-bottom: 4px;">Redirect Chain:</div>
                            <div style="display: flex; flex-direction: column; gap: 2px;">
                                ${http.redirect_chain.map((url, idx) => `
                                    <div style="font-size: 10px; font-family: var(--font-mono); color: ${idx === http.redirect_chain.length - 1 ? 'var(--accent-cyan)' : 'var(--text-dim)'};">
                                        ${idx + 1}. ${escapeHtml(url)}
                                    </div>
                                `).join("")}
                            </div>
                        </div>
                    ` : ""}

                    <div style="font-size: 11px; color: var(--text-dim);">
                        <div><strong>Final URL:</strong> <code style="font-size: 10px;">${escapeHtml(http.final_url || "")}</code></div>
                    </div>
                </div>
            </div>

            <!-- 4. SECURITY HEADERS AUDIT CHECKLIST -->
            <div class="evidence-card full-width">
                <div class="evidence-label">4. Security Headers Audit</div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 10px; margin-top: 8px; font-size: 12px;">
                    
                    <!-- HSTS -->
                    <div style="background: rgba(255,255,255,0.02); padding: 8px 10px; border-radius: 4px; border-left: 3px solid ${sec.strict_transport_security?.present ? 'var(--accent-emerald)' : 'var(--accent-rose)'};">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <strong style="color: #ffffff;">Strict-Transport-Security (HSTS)</strong>
                            ${getHeaderBadge(sec.strict_transport_security?.present)}
                        </div>
                        ${sec.strict_transport_security?.present ? `
                            <div style="margin-top: 4px; font-size: 11px; color: var(--text-dim);">
                                max-age: <strong>${sec.strict_transport_security.max_age || "N/A"}</strong> | 
                                subdomains: <strong>${sec.strict_transport_security.include_subdomains ? 'Yes' : 'No'}</strong> | 
                                preload: <strong>${sec.strict_transport_security.preload ? 'Yes' : 'No'}</strong>
                            </div>
                        ` : `
                            <div style="margin-top: 4px; font-size: 11px; color: var(--text-dim);">Not configured on HTTP response.</div>
                        `}
                    </div>

                    <!-- CSP -->
                    <div style="background: rgba(255,255,255,0.02); padding: 8px 10px; border-radius: 4px; border-left: 3px solid ${csp.present ? 'var(--accent-emerald)' : 'var(--accent-rose)'};">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <strong style="color: #ffffff;">Content-Security-Policy (CSP)</strong>
                            ${getHeaderBadge(csp.present)}
                        </div>
                        <div style="margin-top: 4px; font-size: 11px; color: var(--text-dim);">
                            ${csp.present ? `${Object.keys(csp.directives || {}).length} Directives defined` : "Header absent."}
                        </div>
                    </div>

                    <!-- X-Frame-Options -->
                    <div style="background: rgba(255,255,255,0.02); padding: 8px 10px; border-radius: 4px; border-left: 3px solid ${xfo.present ? 'var(--accent-emerald)' : 'var(--accent-rose)'};">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <strong style="color: #ffffff;">X-Frame-Options</strong>
                            ${getHeaderBadge(xfo.present)}
                        </div>
                        <div style="margin-top: 4px; font-size: 11px; color: var(--text-dim);">
                            ${xfo.present ? `Value: <strong style="color: var(--accent-cyan);">${escapeHtml(xfo.value)}</strong>` : escapeHtml(xfo.interpretation || "Header absent.")}
                        </div>
                    </div>

                    <!-- X-Content-Type-Options -->
                    <div style="background: rgba(255,255,255,0.02); padding: 8px 10px; border-radius: 4px; border-left: 3px solid ${sec.x_content_type_options?.present ? 'var(--accent-emerald)' : 'var(--accent-rose)'};">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <strong style="color: #ffffff;">X-Content-Type-Options</strong>
                            ${getHeaderBadge(sec.x_content_type_options?.present)}
                        </div>
                        <div style="margin-top: 4px; font-size: 11px; color: var(--text-dim);">
                            ${sec.x_content_type_options?.present ? `Value: <strong>${escapeHtml(sec.x_content_type_options.value)}</strong>` : "Header absent (MIME-sniffing protection not enforced)."}
                        </div>
                    </div>

                    <!-- Referrer-Policy -->
                    <div style="background: rgba(255,255,255,0.02); padding: 8px 10px; border-radius: 4px; border-left: 3px solid ${sec.referrer_policy?.present ? 'var(--accent-emerald)' : 'var(--text-dim)'};">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <strong style="color: #ffffff;">Referrer-Policy</strong>
                            ${getHeaderBadge(sec.referrer_policy?.present)}
                        </div>
                        <div style="margin-top: 4px; font-size: 11px; color: var(--text-dim);">
                            ${sec.referrer_policy?.present ? `Value: <strong>${escapeHtml(sec.referrer_policy.value)}</strong>` : "Header absent."}
                        </div>
                    </div>

                    <!-- Permissions-Policy -->
                    <div style="background: rgba(255,255,255,0.02); padding: 8px 10px; border-radius: 4px; border-left: 3px solid ${sec.permissions_policy?.present ? 'var(--accent-emerald)' : 'var(--text-dim)'};">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <strong style="color: #ffffff;">Permissions-Policy</strong>
                            ${getHeaderBadge(sec.permissions_policy?.present)}
                        </div>
                        <div style="margin-top: 4px; font-size: 11px; color: var(--text-dim);">
                            ${sec.permissions_policy?.present ? `Value: <strong>${escapeHtml(sec.permissions_policy.value)}</strong>` : "Header absent."}
                        </div>
                    </div>

                    <!-- X-XSS-Protection -->
                    <div style="background: rgba(255,255,255,0.02); padding: 8px 10px; border-radius: 4px; border-left: 3px solid ${xxss.present ? 'var(--accent-emerald)' : 'var(--text-dim)'};">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <strong style="color: #ffffff;">X-XSS-Protection</strong>
                            ${getHeaderBadge(xxss.present)}
                        </div>
                        <div style="margin-top: 4px; font-size: 11px; color: var(--text-dim);">
                            ${xxss.present ? `Value: <strong>${escapeHtml(xxss.value)}</strong>` : escapeHtml(xxss.interpretation || "Header absent.")}
                        </div>
                    </div>

                </div>
            </div>

            <!-- 5. CONTENT SECURITY POLICY (CSP) DETAILS -->
            <div class="evidence-card">
                <div class="evidence-label">5. Content Security Policy (CSP) Directives</div>
                <div style="margin-top: 8px; font-size: 12px;">
                    ${csp.present ? `
                        <div style="display: flex; flex-direction: column; gap: 6px; max-height: 220px; overflow-y: auto;">
                            ${Object.entries(csp.directives || {}).map(([dName, dVals]) => `
                                <div style="background: rgba(255,255,255,0.02); padding: 6px 8px; border-radius: 4px; font-size: 11px;">
                                    <strong style="color: var(--accent-cyan); font-family: var(--font-mono);">${escapeHtml(dName)}:</strong>
                                    <span style="color: var(--text-dim); margin-left: 4px;">${escapeHtml(dVals.join(" "))}</span>
                                </div>
                            `).join("")}
                        </div>

                        ${(csp.observations || []).length > 0 ? `
                            <div style="margin-top: 8px; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 6px;">
                                <div style="font-size: 10px; color: var(--text-dim); margin-bottom: 4px;">CSP Observations:</div>
                                <ul style="margin: 0; padding-left: 16px; font-size: 11px; color: var(--text-dim);">
                                    ${csp.observations.map(obs => `<li>${escapeHtml(obs)}</li>`).join("")}
                                </ul>
                            </div>
                        ` : ""}
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No Content-Security-Policy header returned on target HTTP response.</div>
                    `}
                </div>
            </div>

            <!-- 6. CORS & SERVER FINGERPRINTING -->
            <div class="evidence-card">
                <div class="evidence-label">6. CORS &amp; Server Fingerprinting</div>
                <div style="margin-top: 8px; font-size: 12px;">
                    
                    <!-- CORS Summary -->
                    <div style="margin-bottom: 12px;">
                        <strong style="color: #ffffff; font-size: 12px;">CORS Configuration:</strong>
                        <div style="margin-top: 4px; font-size: 11px; color: var(--text-dim);">
                            <div>Access-Control-Allow-Origin: <strong>${escapeHtml(cors.allow_origin || "Not returned")}</strong></div>
                            <div>Allow-Credentials: <strong>${escapeHtml(cors.allow_credentials || "Not specified")}</strong></div>
                            <div>Mode: <span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(255,255,255,0.06);">${escapeHtml(cors.mode || "not_present")}</span></div>
                        </div>
                        ${cors.potential_cors_misconfiguration ? `
                            <div style="margin-top: 6px; background: rgba(244,63,94,0.1); border-left: 3px solid var(--accent-rose); padding: 4px 6px; font-size: 10px; color: var(--accent-rose);">
                                ⚠ Potential CORS misconfiguration: Wildcard origin combined with credentials true.
                            </div>
                        ` : ""}
                    </div>

                    <!-- Server Disclosure -->
                    <div style="border-top: 1px solid rgba(255,255,255,0.06); padding-top: 8px;">
                        <strong style="color: #ffffff; font-size: 12px;">Server Fingerprint &amp; Disclosures:</strong>
                        <div style="margin-top: 4px; font-size: 11px; color: var(--text-dim);">
                            <div>Server: <strong>${escapeHtml(server.server || "Not disclosed")}</strong></div>
                            ${server.powered_by ? `<div>X-Powered-By: <strong>${escapeHtml(server.powered_by)}</strong></div>` : ""}
                            ${server.via ? `<div>Via: <strong>${escapeHtml(server.via)}</strong></div>` : ""}
                        </div>

                        ${(server.version_disclosures || []).length > 0 ? `
                            <div style="margin-top: 6px; font-size: 10px; color: var(--accent-amber);">
                                ℹ Information Disclosure: ${escapeHtml(server.version_disclosures.join(", "))}
                            </div>
                        ` : ""}
                    </div>

                </div>
            </div>

            <!-- 7. STANDARDIZED EVIDENCE LOG -->
            <div class="evidence-card full-width">
                <div class="evidence-label">7. Traceable Forensic Evidence Log (${evidenceList.length} Observations)</div>
                <div style="margin-top: 8px; font-size: 11px; max-height: 280px; overflow-y: auto;">
                    ${evidenceList.length > 0 ? `
                        <table style="width: 100%; border-collapse: collapse; font-size: 11px; text-align: left;">
                            <thead>
                                <tr style="border-bottom: 1px solid rgba(255,255,255,0.1); color: var(--text-dim);">
                                    <th style="padding: 6px;">Category</th>
                                    <th style="padding: 6px;">Evidence Type</th>
                                    <th style="padding: 6px;">Observation</th>
                                    <th style="padding: 6px;">Source</th>
                                    <th style="padding: 6px;">Confidence</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${evidenceList.map(ev => `
                                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
                                        <td style="padding: 6px; color: var(--accent-cyan); font-weight: 600;">${escapeHtml(ev.category || "")}</td>
                                        <td style="padding: 6px; color: var(--text-dim); font-size: 10px;">${escapeHtml(ev.evidence_type || "")}</td>
                                        <td style="padding: 6px; color: #ffffff;">${escapeHtml(ev.observation || "")}</td>
                                        <td style="padding: 6px; color: var(--text-dim);">${escapeHtml(ev.source || "")}</td>
                                        <td style="padding: 6px;">
                                            <span style="font-size: 9px; text-transform: uppercase; padding: 2px 5px; border-radius: 3px; background: rgba(255,255,255,0.06);">
                                                ${escapeHtml(ev.confidence || "high")}
                                            </span>
                                        </td>
                                    </tr>
                                `).join("")}
                            </tbody>
                        </table>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No evidence log entries collected.</div>
                    `}
                </div>
            </div>

            ${renderErrorBlock(result.errors)}
        </div>
    `;
}

/**
 * Render Evidence Details for Agent 17: Malware Indicators Analysis Agent
 */
function renderAgent17Evidence(result, container) {
    const inp = result.input || {};
    const sum = result.summary || {};
    const downloads = result.malicious_downloads || [];
    const suspScripts = result.suspicious_scripts || [];
    const scriptInv = result.script_inventory || [];
    const driveBy = result.drive_by_download_indicators || [];
    const mining = result.cryptocurrency_mining || {};
    const obf = result.obfuscated_javascript || {};
    const extRes = result.external_resources || [];
    const evidenceList = result.evidence || [];

    const getIndicatorBadge = (detected, label = "DETECTED") => {
        if (detected) {
            return `<span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(244, 63, 94, 0.15); color: var(--accent-rose); font-weight: 600;">${label}</span>`;
        }
        return `<span style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald); font-weight: 600;">CLEAN / NONE</span>`;
    };

    container.innerHTML = `
        <div class="evidence-grid">

            <!-- 1. TARGET IDENTITY & MALWARE METRICS SUMMARY -->
            <div class="evidence-card full-width">
                <div class="evidence-label">1. Target Identity &amp; Static Malware Inspection Overview</div>
                <div style="display: flex; flex-wrap: wrap; gap: 16px; margin-top: 8px; font-size: 12px;">
                    <div><span style="color: var(--text-dim);">Hostname:</span> <strong>${escapeHtml(inp.hostname || "N/A")}</strong></div>
                    <div><span style="color: var(--text-dim);">Domain:</span> <strong>${escapeHtml(inp.domain || "N/A")}</strong></div>
                    <div><span style="color: var(--text-dim);">Target URL:</span> <code style="font-size: 11px;">${escapeHtml(inp.original_url || "N/A")}</code></div>
                </div>

                <!-- Metrics Summary Bar -->
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin-top: 14px;">
                    <div style="background: rgba(255,255,255,0.03); padding: 8px 12px; border-radius: 4px; text-align: center; border: 1px solid rgba(255,255,255,0.06);">
                        <div style="font-size: 16px; font-weight: 700; color: #ffffff;">${sum.script_count || 0}</div>
                        <div style="font-size: 10px; color: var(--text-dim);">Scripts Analyzed</div>
                    </div>
                    <div style="background: ${sum.suspicious_script_count > 0 ? 'rgba(244,63,94,0.1)' : 'rgba(255,255,255,0.03)'}; border-left: 3px solid ${sum.suspicious_script_count > 0 ? 'var(--accent-rose)' : 'rgba(255,255,255,0.1)'}; padding: 8px 12px; border-radius: 4px; text-align: center;">
                        <div style="font-size: 16px; font-weight: 700; color: ${sum.suspicious_script_count > 0 ? 'var(--accent-rose)' : 'var(--accent-emerald)'};">
                            ${sum.suspicious_script_count || 0}
                        </div>
                        <div style="font-size: 10px; color: var(--text-dim);">Suspicious Scripts</div>
                    </div>
                    <div style="background: rgba(255,255,255,0.03); padding: 8px 12px; border-radius: 4px; text-align: center; border: 1px solid rgba(255,255,255,0.06);">
                        <div style="font-size: 16px; font-weight: 700; color: #ffffff;">${sum.download_count || 0}</div>
                        <div style="font-size: 10px; color: var(--text-dim);">Downloads Found</div>
                    </div>
                    <div style="background: ${sum.suspicious_download_count > 0 ? 'rgba(244,63,94,0.1)' : 'rgba(255,255,255,0.03)'}; border-left: 3px solid ${sum.suspicious_download_count > 0 ? 'var(--accent-rose)' : 'rgba(255,255,255,0.1)'}; padding: 8px 12px; border-radius: 4px; text-align: center;">
                        <div style="font-size: 16px; font-weight: 700; color: ${sum.suspicious_download_count > 0 ? 'var(--accent-rose)' : 'var(--accent-emerald)'};">
                            ${sum.suspicious_download_count || 0}
                        </div>
                        <div style="font-size: 10px; color: var(--text-dim);">Executable / Suspicious Downloads</div>
                    </div>
                    <div style="background: rgba(255,255,255,0.03); padding: 8px 12px; border-radius: 4px; text-align: center; border: 1px solid rgba(255,255,255,0.06);">
                        <div style="font-size: 16px; font-weight: 700; color: #ffffff;">${sum.iframe_count || 0}</div>
                        <div style="font-size: 10px; color: var(--text-dim);">Iframes</div>
                    </div>
                    <div style="background: rgba(255,255,255,0.03); padding: 8px 12px; border-radius: 4px; text-align: center; border: 1px solid rgba(255,255,255,0.06);">
                        <div style="font-size: 16px; font-weight: 700; color: #ffffff;">${sum.external_resource_count || 0}</div>
                        <div style="font-size: 10px; color: var(--text-dim);">External Resources</div>
                    </div>
                </div>
            </div>

            <!-- 2. MALICIOUS & SUSPICIOUS DOWNLOADS -->
            <div class="evidence-card">
                <div class="evidence-label">2. Malicious &amp; Suspicious Downloads (${downloads.length})</div>
                <div style="margin-top: 8px; font-size: 12px;">
                    ${downloads.length > 0 ? `
                        <div style="display: flex; flex-direction: column; gap: 6px; max-height: 220px; overflow-y: auto;">
                            ${downloads.map(d => `
                                <div style="background: ${d.indicator === 'executable_download' || d.suspicious_filename ? 'rgba(244,63,94,0.08)' : 'rgba(255,255,255,0.02)'}; border-left: 3px solid ${d.indicator === 'executable_download' || d.suspicious_filename ? 'var(--accent-rose)' : 'var(--accent-amber)'}; padding: 6px 8px; border-radius: 4px; font-size: 11px;">
                                    <div style="display: flex; justify-content: space-between; align-items: center;">
                                        <strong style="color: #ffffff;">${escapeHtml(d.filename || "file")}</strong>
                                        <span style="font-size: 9px; padding: 2px 5px; border-radius: 3px; background: rgba(255,255,255,0.08); font-family: var(--font-mono); color: var(--accent-cyan);">
                                            ${escapeHtml((d.extension || "").toUpperCase())}
                                        </span>
                                    </div>
                                    <div style="margin-top: 2px; color: var(--text-dim); font-size: 10px; word-break: break-all;">
                                        ${escapeHtml(d.url)}
                                    </div>
                                    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 4px;">
                                        <span style="font-size: 9px; color: var(--accent-amber);">${escapeHtml(d.indicator)}</span>
                                        ${d.download_attribute ? '<span style="font-size: 9px; color: var(--accent-cyan);">[download attr]</span>' : ''}
                                    </div>
                                </div>
                            `).join("")}
                        </div>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No executable, archive, or automated download links detected on webpage.</div>
                    `}
                </div>
            </div>

            <!-- 3. DRIVE-BY DOWNLOAD INDICATORS -->
            <div class="evidence-card">
                <div class="evidence-label">3. Drive-by Download Indicators (${driveBy.length})</div>
                <div style="margin-top: 8px; font-size: 12px;">
                    ${driveBy.length > 0 ? `
                        <div style="display: flex; flex-direction: column; gap: 6px; max-height: 220px; overflow-y: auto;">
                            ${driveBy.map(db => `
                                <div style="background: rgba(244,63,94,0.08); border-left: 3px solid var(--accent-rose); padding: 8px; border-radius: 4px; font-size: 11px;">
                                    <div style="display: flex; justify-content: space-between; align-items: center;">
                                        <strong style="color: var(--accent-rose);">${escapeHtml((db.indicator || "Pattern").replace(/_/g, " ").toUpperCase())}</strong>
                                        <span style="font-size: 9px; text-transform: uppercase; color: var(--text-dim);">${escapeHtml(db.confidence || "high")}</span>
                                    </div>
                                    <div style="margin-top: 4px; color: #ffffff;">${escapeHtml(db.observation)}</div>
                                    ${db.resource ? `<div style="margin-top: 2px; font-size: 10px; color: var(--text-dim); word-break: break-all;">Target: ${escapeHtml(db.resource)}</div>` : ''}
                                </div>
                            `).join("")}
                        </div>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No static drive-by download signatures (auto-click links, hidden download iframes, meta refreshes) detected.</div>
                    `}
                </div>
            </div>

            <!-- 4. CRYPTOCURRENCY MINING & WEBASSEMBLY -->
            <div class="evidence-card">
                <div class="evidence-label">4. Cryptocurrency Mining &amp; WebAssembly</div>
                <div style="margin-top: 8px; font-size: 12px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <span style="color: var(--text-dim); font-size: 11px;">In-Browser Miner Status:</span>
                        ${getIndicatorBadge(mining.detected, "MINING DETECTED")}
                    </div>

                    ${(mining.indicators || []).length > 0 ? `
                        <div style="display: flex; flex-direction: column; gap: 6px;">
                            ${mining.indicators.map(m => `
                                <div style="background: rgba(255,255,255,0.02); padding: 6px 8px; border-radius: 4px; border-left: 2px solid ${m.type === 'mining_signature' ? 'var(--accent-rose)' : 'var(--accent-cyan)'}; font-size: 11px;">
                                    <div style="color: #ffffff;">${escapeHtml(m.observation)}</div>
                                </div>
                            `).join("")}
                        </div>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No cryptocurrency mining scripts (Coinhive, Stratum pools, Monero miners) found.</div>
                    `}

                    ${mining.webassembly_detected ? `
                        <div style="margin-top: 8px; font-size: 10px; color: var(--accent-cyan); background: rgba(6,182,212,0.08); padding: 4px 6px; border-radius: 3px;">
                            ℹ WebAssembly (.wasm) usage observed.
                        </div>
                    ` : ""}
                </div>
            </div>

            <!-- 5. OBFUSCATED JAVASCRIPT DETECTION -->
            <div class="evidence-card">
                <div class="evidence-label">5. Obfuscated JavaScript Detection</div>
                <div style="margin-top: 8px; font-size: 12px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <span style="color: var(--text-dim); font-size: 11px;">Obfuscation Status:</span>
                        ${getIndicatorBadge(obf.detected, `OBFUSCATION (${(obf.confidence || "MED").toUpperCase()})`)}
                    </div>

                    ${(obf.indicators || []).length > 0 ? `
                        <div style="display: flex; flex-direction: column; gap: 6px;">
                            ${obf.indicators.map(ind => `
                                <div style="background: rgba(245, 158, 11, 0.08); border-left: 2px solid var(--accent-amber); padding: 6px 8px; border-radius: 4px; font-size: 11px;">
                                    <div style="color: #ffffff;">${escapeHtml(ind)}</div>
                                </div>
                            `).join("")}
                        </div>
                        ${(obf.signals || []).length > 0 ? `
                            <div style="margin-top: 6px; font-size: 10px; color: var(--text-dim);">
                                Signals: <strong>${escapeHtml(obf.signals.join(", "))}</strong>
                            </div>
                        ` : ""}
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No multi-signal JavaScript obfuscation patterns (Base64+eval, hex variable arrays, packed code) detected.</div>
                    `}
                </div>
            </div>

            <!-- 6. SUSPICIOUS SCRIPTS INVENTORY -->
            <div class="evidence-card full-width">
                <div class="evidence-label">6. Script Inventory &amp; Suspicious Dynamic Patterns (${suspScripts.length} Suspicious / ${scriptInv.length} Total)</div>
                <div style="margin-top: 8px; font-size: 11px; max-height: 220px; overflow-y: auto;">
                    ${scriptInv.length > 0 ? `
                        <table style="width: 100%; border-collapse: collapse; font-size: 11px; text-align: left;">
                            <thead>
                                <tr style="border-bottom: 1px solid rgba(255,255,255,0.1); color: var(--text-dim);">
                                    <th style="padding: 6px;">Type</th>
                                    <th style="padding: 6px;">Source / Identifier</th>
                                    <th style="padding: 6px;">Domain</th>
                                    <th style="padding: 6px;">Suspicious Signals</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${scriptInv.map(s => `
                                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.03); background: ${s.suspicious ? 'rgba(244,63,94,0.04)' : 'transparent'};">
                                        <td style="padding: 6px; font-family: var(--font-mono); color: var(--accent-cyan);">${escapeHtml(s.type)}</td>
                                        <td style="padding: 6px; color: #ffffff; word-break: break-all;">${escapeHtml(s.source)}</td>
                                        <td style="padding: 6px; color: var(--text-dim);">${escapeHtml(s.domain || "inline")}</td>
                                        <td style="padding: 6px;">
                                            ${s.suspicious ? `
                                                <span style="color: var(--accent-rose); font-weight: 600;">${escapeHtml(s.signals.join(", "))}</span>
                                            ` : `<span style="color: var(--text-dim);">None</span>`}
                                        </td>
                                    </tr>
                                `).join("")}
                            </tbody>
                        </table>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No script tags discovered in target HTML document.</div>
                    `}
                </div>
            </div>

            <!-- 7. STANDARDIZED TRACEABLE EVIDENCE LOG -->
            <div class="evidence-card full-width">
                <div class="evidence-label">7. Traceable Forensic Evidence Log (${evidenceList.length} Observations)</div>
                <div style="margin-top: 8px; font-size: 11px; max-height: 280px; overflow-y: auto;">
                    ${evidenceList.length > 0 ? `
                        <table style="width: 100%; border-collapse: collapse; font-size: 11px; text-align: left;">
                            <thead>
                                <tr style="border-bottom: 1px solid rgba(255,255,255,0.1); color: var(--text-dim);">
                                    <th style="padding: 6px;">Category</th>
                                    <th style="padding: 6px;">Evidence Type</th>
                                    <th style="padding: 6px;">Observation</th>
                                    <th style="padding: 6px;">Source</th>
                                    <th style="padding: 6px;">Confidence</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${evidenceList.map(ev => `
                                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
                                        <td style="padding: 6px; color: var(--accent-cyan); font-weight: 600;">${escapeHtml((ev.category || "").replace(/_/g, " "))}</td>
                                        <td style="padding: 6px; color: var(--text-dim); font-size: 10px;">${escapeHtml(ev.evidence_type || "")}</td>
                                        <td style="padding: 6px; color: #ffffff;">${escapeHtml(ev.observation || "")}</td>
                                        <td style="padding: 6px; color: var(--text-dim);">${escapeHtml(ev.source || "")}</td>
                                        <td style="padding: 6px;">
                                            <span style="font-size: 9px; text-transform: uppercase; padding: 2px 5px; border-radius: 3px; background: rgba(255,255,255,0.06);">
                                                ${escapeHtml(ev.confidence || "high")}
                                            </span>
                                        </td>
                                    </tr>
                                `).join("")}
                            </tbody>
                        </table>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No malware indicator evidence observations recorded.</div>
                    `}
                </div>
            </div>

            ${renderErrorBlock(result.errors)}
        </div>
    `;
}

/**
 * Render Agent 18: QR Code Analysis Evidence Viewer
 */
function renderAgent18Evidence(result, container) {
    const qrDec = result.qr_decoding || {};
    const embeddedUrl = result.embedded_url || {};
    const normUrl = result.url_normalization || {};
    const redir = result.redirect_chain || {};
    const shortener = result.shortened_url || {};
    const hiddenParams = result.hidden_parameters || [];
    const mod = result.modification_analysis || {};
    const errCorr = result.error_correction || {};
    const evidenceList = result.evidence || [];

    const isQrSource = (result.input_type === "qr_image" || currentAnalysisSource.includes("QR"));

    container.innerHTML = `
        <div class="evidence-grid">
            <!-- TARGET & SOURCE SUMMARY BANNER -->
            <div class="evidence-card full-width" style="background: rgba(139, 92, 246, 0.05); border-color: rgba(139, 92, 246, 0.3);">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                    <div>
                        <div style="font-size: 11px; text-transform: uppercase; color: #a78bfa; font-weight: 700; letter-spacing: 0.5px;">
                            Analysis Source: ${isQrSource ? '📷 QR Code Image' : '🔗 Direct URL'}
                        </div>
                        <div style="font-size: 14px; font-weight: 700; color: #ffffff; font-family: var(--font-mono); margin-top: 2px;">
                            ${escapeHtml(result.normalized_url || embeddedUrl.url || result.original_qr_payload || "No URL")}
                        </div>
                    </div>
                    <div style="display: flex; gap: 6px;">
                        <span style="font-size: 11px; padding: 3px 8px; border-radius: 4px; background: rgba(139, 92, 246, 0.15); color: #a78bfa; font-weight: 600;">
                            Type: ${escapeHtml(qrDec.data_type || "URL")}
                        </span>
                        <span style="font-size: 11px; padding: 3px 8px; border-radius: 4px; background: ${qrDec.decoded ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)'}; color: ${qrDec.decoded ? 'var(--accent-emerald)' : 'var(--accent-rose)'}; font-weight: 600;">
                            ${qrDec.decoded ? 'DECODED' : 'DECODING FAILED'}
                        </span>
                    </div>
                </div>
            </div>

            <!-- 1. METRICS OVERVIEW -->
            <div class="evidence-card full-width">
                <div class="evidence-label">1. QR Forensic Summary Metrics</div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin-top: 8px;">
                    <div style="background: rgba(255,255,255,0.03); padding: 8px 12px; border-radius: 4px; text-align: center; border: 1px solid rgba(255,255,255,0.06);">
                        <div style="font-size: 16px; font-weight: 700; color: var(--accent-cyan); font-family: var(--font-mono);">${escapeHtml(qrDec.data_type || "URL")}</div>
                        <div style="font-size: 10px; color: var(--text-dim);">Payload Type</div>
                    </div>
                    <div style="background: rgba(255,255,255,0.03); padding: 8px 12px; border-radius: 4px; text-align: center; border: 1px solid rgba(255,255,255,0.06);">
                        <div style="font-size: 16px; font-weight: 700; color: #ffffff;">${escapeHtml(String(errCorr.version || "N/A"))}</div>
                        <div style="font-size: 10px; color: var(--text-dim);">QR Version</div>
                    </div>
                    <div style="background: rgba(255,255,255,0.03); padding: 8px 12px; border-radius: 4px; text-align: center; border: 1px solid rgba(255,255,255,0.06);">
                        <div style="font-size: 16px; font-weight: 700; color: #ffffff;">${escapeHtml(String(errCorr.level || "Unknown"))}</div>
                        <div style="font-size: 10px; color: var(--text-dim);">Error Correction</div>
                    </div>
                    <div style="background: ${redir.count > 0 ? 'rgba(245,158,11,0.1)' : 'rgba(255,255,255,0.03)'}; border-left: 3px solid ${redir.count > 0 ? 'var(--accent-amber)' : 'rgba(255,255,255,0.1)'}; padding: 8px 12px; border-radius: 4px; text-align: center;">
                        <div style="font-size: 16px; font-weight: 700; color: ${redir.count > 0 ? 'var(--accent-amber)' : '#ffffff'};">${redir.count || 0}</div>
                        <div style="font-size: 10px; color: var(--text-dim);">Redirect Hops</div>
                    </div>
                    <div style="background: ${shortener.detected ? 'rgba(244,63,94,0.1)' : 'rgba(255,255,255,0.03)'}; border-left: 3px solid ${shortener.detected ? 'var(--accent-rose)' : 'rgba(255,255,255,0.1)'}; padding: 8px 12px; border-radius: 4px; text-align: center;">
                        <div style="font-size: 16px; font-weight: 700; color: ${shortener.detected ? 'var(--accent-rose)' : 'var(--accent-emerald)'};">
                            ${shortener.detected ? 'YES' : 'NO'}
                        </div>
                        <div style="font-size: 10px; color: var(--text-dim);">Shortened URL</div>
                    </div>
                    <div style="background: ${hiddenParams.length > 0 ? 'rgba(245,158,11,0.1)' : 'rgba(255,255,255,0.03)'}; border-left: 3px solid ${hiddenParams.length > 0 ? 'var(--accent-amber)' : 'rgba(255,255,255,0.1)'}; padding: 8px 12px; border-radius: 4px; text-align: center;">
                        <div style="font-size: 16px; font-weight: 700; color: ${hiddenParams.length > 0 ? 'var(--accent-amber)' : '#ffffff'};">
                            ${hiddenParams.length}
                        </div>
                        <div style="font-size: 10px; color: var(--text-dim);">Open-Redirect / Encoded Params</div>
                    </div>
                </div>
            </div>

            <!-- 2. QR DECODING & EMBEDDED URL -->
            <div class="evidence-card">
                <div class="evidence-label">2. QR Payload &amp; Embedded URL Extraction</div>
                <div style="margin-top: 8px; font-size: 12px; display: flex; flex-direction: column; gap: 8px;">
                    <div>
                        <span style="color: var(--text-dim); font-size: 11px;">Raw Decoded Payload:</span>
                        <div style="background: rgba(0,0,0,0.3); padding: 8px; border-radius: 4px; font-family: var(--font-mono); font-size: 12px; color: #ffffff; word-break: break-all; margin-top: 3px; border: 1px solid rgba(255,255,255,0.05);">
                            ${escapeHtml(result.original_qr_payload || "None")}
                        </div>
                    </div>
                    <div>
                        <span style="color: var(--text-dim); font-size: 11px;">Target Extracted URL:</span>
                        <div style="background: rgba(6, 182, 212, 0.05); border: 1px solid rgba(6, 182, 212, 0.2); padding: 8px; border-radius: 4px; font-family: var(--font-mono); font-size: 12px; color: var(--accent-cyan); word-break: break-all; margin-top: 3px;">
                            ${escapeHtml(embeddedUrl.url || result.normalized_url || "None")}
                        </div>
                    </div>
                </div>
            </div>

            <!-- 3. URL NORMALIZATION STRUCTURE -->
            <div class="evidence-card">
                <div class="evidence-label">3. URL Normalization Components</div>
                <div style="margin-top: 8px; font-size: 11px;">
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                            <td style="padding: 4px 0; color: var(--text-dim);">Scheme:</td>
                            <td style="padding: 4px 0; color: #ffffff; font-family: var(--font-mono);">${escapeHtml(normUrl.scheme || "https")}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                            <td style="padding: 4px 0; color: var(--text-dim);">Hostname:</td>
                            <td style="padding: 4px 0; color: #ffffff; font-family: var(--font-mono);">${escapeHtml(normUrl.hostname || "N/A")}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                            <td style="padding: 4px 0; color: var(--text-dim);">Registered Domain:</td>
                            <td style="padding: 4px 0; color: var(--accent-cyan); font-family: var(--font-mono);">${escapeHtml(normUrl.domain || "N/A")}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                            <td style="padding: 4px 0; color: var(--text-dim);">Path:</td>
                            <td style="padding: 4px 0; color: #ffffff; font-family: var(--font-mono);">${escapeHtml(normUrl.path || "/")}</td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0; color: var(--text-dim);">Query String:</td>
                            <td style="padding: 4px 0; color: var(--accent-amber); font-family: var(--font-mono); word-break: break-all;">${escapeHtml(normUrl.query || "None")}</td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- 4. HTTP REDIRECT CHAIN TRACE -->
            <div class="evidence-card full-width">
                <div class="evidence-label">4. Safe HTTP Redirect Chain Trace (${redir.count || 0} Hops)</div>
                <div style="margin-top: 8px; font-size: 11px;">
                    ${(redir.urls || []).length > 1 ? `
                        <div style="display: flex; flex-direction: column; gap: 6px;">
                            ${redir.urls.map((u, idx) => `
                                <div style="display: flex; align-items: center; gap: 8px; background: rgba(255,255,255,0.02); padding: 8px 12px; border-radius: 4px; border-left: 3px solid ${idx === 0 ? 'var(--accent-blue)' : (idx === redir.urls.length - 1 ? 'var(--accent-emerald)' : 'var(--accent-amber)')};">
                                    <span style="font-weight: 700; color: var(--text-dim); font-size: 10px; width: 50px;">STEP ${idx + 1}</span>
                                    <span style="font-family: var(--font-mono); color: #ffffff; word-break: break-all; flex: 1;">${escapeHtml(u)}</span>
                                    ${idx === 0 ? '<span style="font-size: 9px; padding: 2px 6px; background: rgba(59,130,246,0.15); color: var(--accent-blue); border-radius: 3px;">INITIAL</span>' : ''}
                                    ${idx === redir.urls.length - 1 ? '<span style="font-size: 9px; padding: 2px 6px; background: rgba(16,185,129,0.15); color: var(--accent-emerald); border-radius: 3px;">FINAL TARGET</span>' : ''}
                                </div>
                            `).join("")}
                        </div>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">Direct destination (no HTTP redirect hops observed).</div>
                    `}
                </div>
            </div>

            <!-- 5. HIDDEN & OPEN-REDIRECT PARAMETERS -->
            <div class="evidence-card">
                <div class="evidence-label">5. Open-Redirect &amp; Hidden Parameter Inspection (${hiddenParams.length})</div>
                <div style="margin-top: 8px; font-size: 11px;">
                    ${hiddenParams.length > 0 ? `
                        <div style="display: flex; flex-direction: column; gap: 6px; max-height: 200px; overflow-y: auto;">
                            ${hiddenParams.map(p => `
                                <div style="background: rgba(245,158,11,0.08); border-left: 3px solid var(--accent-amber); padding: 8px; border-radius: 4px;">
                                    <div style="display: flex; justify-content: space-between; align-items: center;">
                                        <strong style="color: var(--accent-amber); font-family: var(--font-mono);">${escapeHtml(p.parameter_name)}</strong>
                                        <span style="font-size: 9px; text-transform: uppercase; color: var(--text-dim);">${escapeHtml(p.type)}</span>
                                    </div>
                                    <div style="margin-top: 4px; color: #ffffff; font-family: var(--font-mono); font-size: 10px; word-break: break-all;">
                                        Target: ${escapeHtml(p.decoded_value)}
                                    </div>
                                </div>
                            `).join("")}
                        </div>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No suspicious open-redirect keys or Base64 encoded destination parameters found.</div>
                    `}
                </div>
            </div>

            <!-- 6. SHORTENER & MODIFICATION HEURISTICS -->
            <div class="evidence-card">
                <div class="evidence-label">6. Shortener &amp; Visual Modification Heuristics</div>
                <div style="margin-top: 8px; font-size: 11px; display: flex; flex-direction: column; gap: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="color: var(--text-dim);">Shortening Service:</span>
                        ${shortener.detected ? `<span style="color: var(--accent-rose); font-weight: 700;">${escapeHtml(shortener.provider)}</span>` : '<span style="color: var(--accent-emerald);">Standard Domain</span>'}
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="color: var(--text-dim);">QR Visual Alteration:</span>
                        <span style="text-transform: uppercase; color: ${mod.status === 'detected' ? 'var(--accent-rose)' : 'var(--text-muted)'}; font-weight: 600;">
                            ${escapeHtml(mod.status || "Unknown")}
                        </span>
                    </div>
                    ${(mod.indicators || []).length > 0 ? `
                        <div style="background: rgba(255,255,255,0.02); padding: 6px 8px; border-radius: 4px; color: var(--text-dim); font-size: 10px;">
                            ${mod.indicators.map(ind => `<div>• ${escapeHtml(ind)}</div>`).join("")}
                        </div>
                    ` : ""}
                </div>
            </div>

            <!-- 7. STANDARDIZED TRACEABLE EVIDENCE LOG -->
            <div class="evidence-card full-width">
                <div class="evidence-label">7. Traceable Forensic Evidence Log (${evidenceList.length} Observations)</div>
                <div style="margin-top: 8px; font-size: 11px; max-height: 280px; overflow-y: auto;">
                    ${evidenceList.length > 0 ? `
                        <table style="width: 100%; border-collapse: collapse; font-size: 11px; text-align: left;">
                            <thead>
                                                                <th style="padding: 6px;">Evidence Type</th>
                                    <th style="padding: 6px;">Observation</th>
                                    <th style="padding: 6px;">Source</th>
                                    <th style="padding: 6px;">Confidence</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${evidenceList.map(ev => `
                                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
                                        <td style="padding: 6px; color: #a78bfa; font-weight: 600;">${escapeHtml((ev.category || "").replace(/_/g, " "))}</td>
                                        <td style="padding: 6px; color: var(--text-dim); font-size: 10px;">${escapeHtml(ev.evidence_type || "")}</td>
                                        <td style="padding: 6px; color: #ffffff;">${escapeHtml(ev.observation || "")}</td>
                                        <td style="padding: 6px; color: var(--text-dim);">${escapeHtml(ev.source || "")}</td>
                                        <td style="padding: 6px;">
                                            <span style="font-size: 9px; text-transform: uppercase; padding: 2px 5px; border-radius: 3px; background: rgba(255,255,255,0.06);">
                                                ${escapeHtml(ev.confidence || "high")}
                                            </span>
                                        </td>
                                    </tr>
                                `).join("")}
                            </tbody>
                        </table>
                    ` : `
                        <div style="color: var(--text-dim); font-size: 11px;">No QR forensic evidence observations recorded.</div>
                    `}
                </div>
            </div>

            ${renderErrorBlock(result.errors)}
        </div>
    `;
}

/* =====================================================================
   STEP 5C: FINAL INVESTIGATOR REPORT FRONTEND CONTROLLER & RENDERER
   ===================================================================== */

/**
 * Open the Final Investigator Report Modal and initiate generation.
 */
function openInvestigatorReport() {
    const modal = document.getElementById("investigatorReportModal");
    if (!modal) return;

    modal.style.display = "flex";
    document.body.style.overflow = "hidden";

    // Show loading state
    document.getElementById("reportLoadingState").style.display = "flex";
    document.getElementById("reportErrorState").style.display = "none";
    document.getElementById("reportContentContainer").style.display = "none";

    fetchAndRenderReport();
}

/**
 * Close the Final Investigator Report Modal.
 */
function closeInvestigatorReport() {
    const modal = document.getElementById("investigatorReportModal");
    if (!modal) return;
    modal.style.display = "none";
    document.body.style.overflow = "auto";
}

/**
 * Fetch the authoritative InvestigatorReportPayload from /api/report
 */
async function fetchAndRenderReport() {
    const loadingState = document.getElementById("reportLoadingState");
    const errorState = document.getElementById("reportErrorState");
    const contentContainer = document.getElementById("reportContentContainer");
    const errorText = document.getElementById("reportErrorText");

    loadingState.style.display = "flex";
    errorState.style.display = "none";
    contentContainer.style.display = "none";

    const target = currentDecodedTarget || currentTargetUrl || (document.getElementById("urlInput") ? document.getElementById("urlInput").value.trim() : "https://example.com");

    try {
        const response = await fetch("/api/report", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                url: target,
                session: currentPipelineSession
            })
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || `HTTP ${response.status} Failed to generate report.`);
        }

        const reportPayload = await response.json();
        currentReportPayload = reportPayload;

        renderInvestigatorReport(reportPayload);

        loadingState.style.display = "none";
        contentContainer.style.display = "flex";
    } catch (err) {
        console.error("Report generation error:", err);
        loadingState.style.display = "none";
        errorText.innerText = "Final Investigator Report could not be generated: " + err.message;
        errorState.style.display = "flex";
    }
}

/**
 * Render all 10 authoritative report sections into the dossier view.
 */
function renderInvestigatorReport(report) {
    const container = document.getElementById("reportContentContainer");
    if (!container) return;

    const ov = report.overview || {};
    const as = report.assessment || {};
    const target = ov.target || {};

    let html = `
        <!-- SECTION 1: INVESTIGATION OVERVIEW -->
        <section class="report-section" id="reportSecOverview">
            <div class="report-section-header">
                <div class="report-section-title-group">
                    <span class="report-section-number">01</span>
                    <h3 class="report-section-title">Investigation Overview</h3>
                </div>
                <span class="header-badge">ID: ${escapeHtml(ov.investigation_id || "N/A")}</span>
            </div>
            <div class="overview-grid">
                <div class="overview-item">
                    <span class="overview-label">Target URL / Entity</span>
                    <span class="overview-value">${escapeHtml(target.target_url || target.original_input || "N/A")}</span>
                </div>
                <div class="overview-item">
                    <span class="overview-label">Input Modality</span>
                    <span class="overview-value">${escapeHtml(target.input_type || "url").toUpperCase()}</span>
                </div>
                <div class="overview-item">
                    <span class="overview-label">Investigation Timestamp</span>
                    <span class="overview-value">${escapeHtml(ov.investigation_timestamp || "N/A")}</span>
                </div>
                <div class="overview-item">
                    <span class="overview-label">Report Generated At</span>
                    <span class="overview-value">${escapeHtml(report.generated_at || "N/A")}</span>
                </div>
                <div class="overview-item">
                    <span class="overview-label">Pipeline Status</span>
                    <span class="overview-value">${escapeHtml(ov.execution_status || "completed").toUpperCase()}</span>
                </div>
                <div class="overview-item">
                    <span class="overview-label">Telemetry Coverage</span>
                    <span class="overview-value">${Number(report.telemetry_coverage_score || 0).toFixed(1)}% (${(report.observed_dimensions || []).length} / 18 Agents)</span>
                </div>
            </div>
        </section>

        <!-- SECTION 2: FINAL ASSESSMENT HERO -->
        <section class="report-section" id="reportSecAssessment">
            <div class="report-section-header">
                <div class="report-section-title-group">
                    <span class="report-section-number">02</span>
                    <h3 class="report-section-title">Final Assessment &amp; Epistemic Sovereignty</h3>
                </div>
                <span class="verdict-pill verdict-${escapeHtml(as.tce_verdict || 'unknown')}">${escapeHtml((as.tce_verdict || 'unknown').replace(/_/g, ' '))}</span>
            </div>
            <div class="assessment-hero">
                <div class="assessment-axiom-banner">
                    <span class="axiom-badge">⚖️ RISK ≠ TRUST ≠ CONFIDENCE</span>
                    <span class="axiom-sub">Grounding validity verifies citation alignment with evidence; it is not metaphysical truth.</span>
                </div>
                <div class="assessment-metrics-grid">
                    <div class="metric-card">
                        <span class="metric-card-title">TCE Risk Score</span>
                        <span class="metric-card-value" style="color: #f87171;">${as.tce_risk_score !== null && as.tce_risk_score !== undefined ? Number(as.tce_risk_score).toFixed(2) : "--"}</span>
                        <span class="metric-card-sub">Bounded Saturation [0.0 - 100.0]</span>
                    </div>
                    <div class="metric-card">
                        <span class="metric-card-title">TCE Trust Score</span>
                        <span class="metric-card-value" style="color: #34d399;">${as.tce_trust_score !== null && as.tce_trust_score !== undefined ? Number(as.tce_trust_score).toFixed(2) : "--"}</span>
                        <span class="metric-card-sub">Verified Legitimacy [0.0 - 100.0]</span>
                    </div>
                    <div class="metric-card">
                        <span class="metric-card-title">Evidence Confidence (C_ev)</span>
                        <span class="metric-card-value" style="color: var(--accent-cyan);">${as.evidence_confidence !== null && as.evidence_confidence !== undefined ? Number(as.evidence_confidence).toFixed(2) : "--"}</span>
                        <span class="metric-card-sub">Telemetry &amp; Reliability [0 - 100]</span>
                    </div>
                    <div class="metric-card">
                        <span class="metric-card-title">Reasoning Fidelity (C_interp)</span>
                        <span class="metric-card-value" style="color: #a78bfa;">${as.interpretation_confidence !== null && as.interpretation_confidence !== undefined ? Number(as.interpretation_confidence).toFixed(2) : "--"}</span>
                        <span class="metric-card-sub">Citation Grounding [0 - 100]</span>
                    </div>
                    <div class="metric-card">
                        <span class="metric-card-title">Composite Confidence</span>
                        <span class="metric-card-value" style="color: #60a5fa;">${as.composite_confidence !== null && as.composite_confidence !== undefined ? Number(as.composite_confidence).toFixed(2) : "--"}</span>
                        <span class="metric-card-sub">Epistemic Index [0 - 100]</span>
                    </div>
                </div>
                <div class="abstention-callout">
                    <div style="display: flex; flex-direction: column; gap: 2px;">
                        <span class="abstention-label">Workflow Recommendation:</span>
                        <span class="abstention-badge">${escapeHtml(as.abstention_reason || "REVIEW_REQUIRED_LOW_CONFIDENCE")}</span>
                    </div>
                    <div style="font-size: 11px; color: var(--text-dim); text-align: right;">
                        Calibration Status: <strong>${escapeHtml(as.confidence_calibration_status || "UNCALIBRATED_DETERMINISTIC_HEURISTIC")}</strong>
                    </div>
                </div>
            </div>
        </section>

        <!-- SECTION 3: KEY FINDINGS (POLARITY PARTITIONED) -->
        <section class="report-section" id="reportSecFindings">
            <div class="report-section-header">
                <div class="report-section-title-group">
                    <span class="report-section-number">03</span>
                    <h3 class="report-section-title">Key Findings (Polarity Partitioned)</h3>
                </div>
                <span style="font-size: 11px; color: var(--text-dim);">Presentation-Only Deterministic Ordering</span>
            </div>

            <!-- RISK-INCREASING FINDINGS -->
            <div class="findings-group-title risk-inc">
                <span>🔴 Risk-Increasing Findings (${(report.risk_increasing_findings || []).length})</span>
            </div>
            <div class="findings-list">
                ${renderFindingsGroup(report.risk_increasing_findings, "risk-increasing")}
            </div>

            <!-- RISK-REDUCING FINDINGS -->
            <div class="findings-group-title risk-red" style="margin-top: 16px;">
                <span>🟢 Risk-Reducing Findings (${(report.risk_reducing_findings || []).length})</span>
            </div>
            <div class="findings-list">
                ${renderFindingsGroup(report.risk_reducing_findings, "risk-reducing")}
            </div>

            <!-- NEUTRAL OBSERVATIONS -->
            <div class="findings-group-title neutral" style="margin-top: 16px;">
                <span>⚪ Neutral Baseline Telemetry (${(report.neutral_observations || []).length})</span>
            </div>
            <div class="findings-list">
                ${renderFindingsGroup(report.neutral_observations, "neutral")}
            </div>
        </section>

        <!-- SECTION 4: EVIDENCE-BACKED REASONING & GROUNDING (AERE) -->
        <section class="report-section" id="reportSecReasoning">
            <div class="report-section-header">
                <div class="report-section-title-group">
                    <span class="report-section-number">04</span>
                    <h3 class="report-section-title">Evidence-Backed Qualitative Reasoning (AERE)</h3>
                </div>
                <span class="header-badge">Status: ${escapeHtml((report.aere_reasoning_status || "unavailable").toUpperCase())}</span>
            </div>
            <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid #334155; border-radius: 8px; padding: 16px; line-height: 1.6; font-size: 13px;">
                <strong style="color: var(--accent-cyan);">Investigation Summary:</strong>
                <p style="margin-top: 6px; color: var(--text-main);">${escapeHtml(report.investigation_summary || "No investigation summary available.")}</p>
            </div>

            ${(report.detailed_findings && report.detailed_findings.length > 0) ? `
                <div style="margin-top: 12px; display: flex; flex-direction: column; gap: 8px;">
                    <span style="font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--text-dim);">Detailed Findings:</span>
                    ${report.detailed_findings.map(f => `
                        <div class="claim-card">
                            <div class="claim-header">
                                <span class="claim-title">${escapeHtml(f.topic || f.finding_id || "Finding")}</span>
                                <span class="finding-badge ${escapeHtml(f.forensic_significance || 'info')}">${escapeHtml(f.forensic_significance || 'info')}</span>
                            </div>
                            <div style="font-size: 13px; color: var(--text-main);">${escapeHtml(f.summary || "")}</div>
                            <div style="font-size: 12px; color: var(--text-muted); font-style: italic;">${escapeHtml(f.interpretation || "")}</div>
                            <div style="font-size: 11px; color: var(--text-dim);">
                                Grounded Evidence IDs: ${(f.grounded_evidence_ids || []).map(eid => `<a href="javascript:void(0)" class="finding-id-pill" onclick="highlightLineageItem('${escapeHtml(eid)}')">${escapeHtml(eid)}</a>`).join(" ")}
                            </div>
                        </div>
                    `).join("")}
                </div>
            ` : ""}

            <!-- GROUNDED CLAIMS CITATION EVALUATION -->
            <div style="margin-top: 16px; display: flex; flex-direction: column; gap: 10px;">
                <div style="display: flex; align-items: center; justify-content: space-between;">
                    <span style="font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--text-dim);">Citation Grounding Diagnostics:</span>
                    <span style="font-size: 11px; color: var(--text-muted);">Grounded Citation Ratio: <strong>${(Number(report.grounded_citation_ratio || 1.0) * 100).toFixed(1)}%</strong> | Unsubstantiated Claims: <strong>${report.unsubstantiated_claims_count || 0}</strong></span>
                </div>
                ${(report.grounded_claims && report.grounded_claims.length > 0) ? `
                    <div style="display: flex; flex-direction: column; gap: 8px;">
                        ${report.grounded_claims.map(gc => `
                            <div class="claim-card">
                                <div class="claim-header">
                                    <span class="claim-title">[${escapeHtml(gc.claim_id || "CLAIM")}] Section: ${escapeHtml(gc.section || "general")}</span>
                                    <span class="status-badge-${escapeHtml((gc.grounding_status || 'uncertain').toLowerCase())}">${escapeHtml(gc.grounding_status || 'UNCERTAIN')}</span>
                                </div>
                                <div style="font-size: 11px; color: var(--text-dim); display: flex; gap: 8px; flex-wrap: wrap;">
                                    <span>Valid Citations: ${(gc.valid_evidence_ids || []).map(eid => `<a href="javascript:void(0)" class="finding-id-pill" onclick="highlightLineageItem('${escapeHtml(eid)}')">${escapeHtml(eid)}</a>`).join(" ") || "None"}</span>
                                    ${(gc.invalid_evidence_ids && gc.invalid_evidence_ids.length > 0) ? `
                                        <span class="invalid-citation-tag">INVALID CITATIONS: ${(gc.invalid_evidence_ids).map(eid => escapeHtml(eid)).join(", ")}</span>
                                    ` : ""}
                                </div>
                                ${(gc.issues && gc.issues.length > 0) ? `
                                    <div style="font-size: 11px; color: #fca5a5; line-height: 1.4;">
                                        Diagnostic Issues: ${gc.issues.map(iss => escapeHtml(iss)).join("; ")}
                                    </div>
                                ` : ""}
                            </div>
                        `).join("")}
                    </div>
                ` : `
                    <div style="font-size: 12px; color: var(--text-dim);">No claim-level grounding evaluation records emitted.</div>
                `}
            </div>
        </section>

        <!-- SECTION 5: EVIDENCE LINEAGE & AUDIT TRAIL -->
        <section class="report-section" id="reportSecLineage">
            <div class="report-section-header">
                <div class="report-section-title-group">
                    <span class="report-section-number">05</span>
                    <h3 class="report-section-title">Evidence Lineage &amp; Provenance Audit Trail</h3>
                </div>
                <span style="font-size: 11px; color: var(--text-dim);">Active Items: ${report.total_active_evidence_items || 0} | Provenance Gate: ${report.provenance_gate_passed ? "PASSED (G_prov=1)" : "FAILED (G_prov=0)"}</span>
            </div>
            <div class="lineage-table-wrapper">
                <table class="lineage-table">
                    <thead>
                        <tr>
                            <th>Evidence ID</th>
                            <th>Agent / Source</th>
                            <th>Severity</th>
                            <th>Type</th>
                            <th>Strength</th>
                            <th>Polarity</th>
                            <th>TCE Contribution</th>
                            <th>Observation Finding</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${(report.evidence_lineage && report.evidence_lineage.length > 0) ? report.evidence_lineage.map(item => `
                            <tr id="lineage-row-${escapeHtml(item.evidence_id)}">
                                <td style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-cyan);">${escapeHtml(item.evidence_id)}</td>
                                <td>${escapeHtml(item.agent_name || `Agent ${item.agent_id}`)}</td>
                                <td><span class="finding-badge ${escapeHtml(item.severity || 'info')}">${escapeHtml(item.severity || 'info')}</span></td>
                                <td style="color: var(--text-dim);">${escapeHtml(item.evidence_type || 'deterministic')}</td>
                                <td>${Number(item.evidence_strength || 1.0).toFixed(2)}</td>
                                <td style="font-weight: 600; color: ${item.polarity === 'risk_increasing' ? '#f87171' : item.polarity === 'risk_reducing' ? '#34d399' : 'var(--text-dim)'};">${escapeHtml((item.polarity || 'neutral').replace(/_/g, ' '))}</td>
                                <td style="font-family: var(--font-mono); color: var(--accent-cyan);">${item.tce_final_contribution !== null && item.tce_final_contribution !== undefined ? Number(item.tce_final_contribution).toFixed(4) : "Unavailable"}</td>
                                <td style="line-height: 1.4;">${escapeHtml(item.finding || "")}</td>
                            </tr>
                        `).join("") : `
                            <tr><td colspan="8" style="text-align: center; color: var(--text-dim); padding: 20px;">No active evidence items in investigation ledger.</td></tr>
                        `}
                    </tbody>
                </table>
            </div>
        </section>

        <!-- SECTION 6: CONTRADICTIONS & CROSS-AGENT CONFLICTS -->
        <section class="report-section" id="reportSecContradictions">
            <div class="report-section-header">
                <div class="report-section-title-group">
                    <span class="report-section-number">06</span>
                    <h3 class="report-section-title">Contradictions &amp; Evidentiary Conflicts</h3>
                </div>
                <span style="font-size: 11px; color: var(--text-dim);">Penalty Score (Phi_contra): ${Number(report.contradiction_score || 0).toFixed(2)}</span>
            </div>
            ${(report.contradictions && report.contradictions.length > 0) ? `
                <div class="contradictions-box">
                    ${report.contradictions.map(c => `
                        <div class="contradiction-item">
                            <div style="display: flex; align-items: center; justify-content: space-between;">
                                <strong style="color: #fbbf24; font-family: var(--font-mono); font-size: 12px;">${escapeHtml(c.relationship_id || "CONTRADICTION")}</strong>
                                <span style="font-size: 11px; color: var(--text-dim);">${escapeHtml(c.description || "")}</span>
                            </div>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 6px; font-size: 12px;">
                                <div style="background: rgba(0,0,0,0.3); padding: 8px; border-radius: 6px;">
                                    <span style="color: var(--accent-cyan); font-weight: 700;">[${escapeHtml(c.source_evidence_id)}]</span> ${escapeHtml(c.source_agent_name)}:
                                    <div style="color: var(--text-main); margin-top: 2px;">${escapeHtml(c.source_finding)}</div>
                                </div>
                                <div style="background: rgba(0,0,0,0.3); padding: 8px; border-radius: 6px;">
                                    <span style="color: #f87171; font-weight: 700;">[${escapeHtml(c.target_evidence_id)}]</span> ${escapeHtml(c.target_agent_name)}:
                                    <div style="color: var(--text-main); margin-top: 2px;">${escapeHtml(c.target_finding)}</div>
                                </div>
                            </div>
                        </div>
                    `).join("")}
                </div>
            ` : `
                <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 8px; padding: 14px; font-size: 13px; color: #34d399; display: flex; align-items: center; gap: 8px;">
                    <span>✓ No cross-agent contradictory relationships detected in this investigation.</span>
                </div>
            `}
        </section>

        <!-- SECTION 7: TELEMETRY COVERAGE & EVIDENCE GAPS -->
        <section class="report-section" id="reportSecTelemetry">
            <div class="report-section-header">
                <div class="report-section-title-group">
                    <span class="report-section-number">07</span>
                    <h3 class="report-section-title">Telemetry Coverage &amp; Evidence Gaps</h3>
                </div>
                <span style="font-size: 11px; color: var(--text-dim);">18 Operational Agent Dimensions</span>
            </div>
            <div class="telemetry-grid">
                ${renderTelemetryNodes(report)}
            </div>
        </section>

        <!-- SECTION 8: EPISTEMIC CONFIDENCE BREAKDOWN -->
        <section class="report-section" id="reportSecConfidence">
            <div class="report-section-header">
                <div class="report-section-title-group">
                    <span class="report-section-number">08</span>
                    <h3 class="report-section-title">Deterministic Confidence Diagnostics (DHCI)</h3>
                </div>
                <span class="header-badge">UNCALIBRATED_DETERMINISTIC_HEURISTIC</span>
            </div>
            <div class="assessment-metrics-grid">
                <div class="metric-card">
                    <span class="metric-card-title">Telemetry Coverage (Phi_cov)</span>
                    <span class="metric-card-value">${Number(report.telemetry_coverage_score || 0).toFixed(1)}%</span>
                    <span class="metric-card-sub">Active Sensor Span</span>
                </div>
                <div class="metric-card">
                    <span class="metric-card-title">Source Reliability (Phi_rel)</span>
                    <span class="metric-card-value">${Number(report.source_reliability_score || 0).toFixed(1)}%</span>
                    <span class="metric-card-sub">Sensor Type Priors</span>
                </div>
                <div class="metric-card">
                    <span class="metric-card-title">Corroboration (Phi_cor)</span>
                    <span class="metric-card-value">${Number(report.corroboration_score || 0).toFixed(1)}%</span>
                    <span class="metric-card-sub">${report.concordant_cluster_count || 0} / 7 Concordant Clusters</span>
                </div>
                <div class="metric-card">
                    <span class="metric-card-title">Contradiction Penalty (Phi_contra)</span>
                    <span class="metric-card-value" style="color: ${Number(report.contradiction_score || 0) > 0 ? '#fbbf24' : '#ffffff'};">${Number(report.contradiction_score || 0).toFixed(1)}%</span>
                    <span class="metric-card-sub">Evidentiary Conflict Impact</span>
                </div>
            </div>
            ${(report.concordant_clusters && report.concordant_clusters.length > 0) ? `
                <div style="font-size: 11px; color: var(--text-dim); margin-top: 6px;">
                    Active Concordant Clusters: <strong>${report.concordant_clusters.map(c => escapeHtml(c)).join(", ")}</strong>
                </div>
            ` : ""}
        </section>

        <!-- SECTION 9: METHODOLOGICAL DISCLAIMER -->
        <section class="report-section" id="reportSecDisclaimer">
            <div class="report-section-header">
                <div class="report-section-title-group">
                    <span class="report-section-number">09</span>
                    <h3 class="report-section-title">Methodological Disclaimer</h3>
                </div>
                <span style="font-size: 11px; color: var(--text-dim);">Epistemic Principles</span>
            </div>
            <div class="disclaimer-card">
                ${escapeHtml(report.methodological_disclaimer || "This report synthesizes deterministic multi-agent telemetry, non-linear trust/risk calculation (TCE), grounded qualitative reasoning (AERE), and deterministic heuristic confidence indexing. Risk, trust, and confidence represent epistemically distinct dimensions. Grounding validity confirms citation alignment with collected telemetry, not absolute objective truth. Confidence scores are uncalibrated prototype heuristics and must not be interpreted as frequentist or Bayesian probabilities.")}
            </div>
        </section>

        <!-- SECTION 10: HUMAN REVIEW GUIDANCE & PROHIBITED ACTIONS -->
        <section class="report-section" id="reportSecHumanReview">
            <div class="report-section-header">
                <div class="report-section-title-group">
                    <span class="report-section-number">10</span>
                    <h3 class="report-section-title">Human Review Guidance &amp; Operational Boundaries</h3>
                </div>
                <span style="font-size: 11px; color: #f87171; font-weight: 700;">Human-in-the-Loop Sovereign Boundary</span>
            </div>
            <div class="disclaimer-card" style="border-left: 4px solid var(--accent-cyan);">
                <strong style="color: #ffffff;">Human Forensic Analyst Mandate:</strong>
                <p style="margin-top: 4px;">${escapeHtml(report.human_review_guidance || "This report is an advisory artifact intended solely to support human forensic investigators. All findings, contradictions, and telemetry gaps must be reviewed by a qualified human analyst before making any operational, containment, or legal determination.")}</p>
            </div>
            <div class="prohibited-actions-box">
                <span class="prohibited-title">⚠️ Prohibited Autonomous Enforcement Actions:</span>
                <ul class="prohibited-list">
                    ${(report.prohibited_autonomous_actions || [
                        "Automated domain or IP blocking",
                        "Automated account suspension or credential revocation",
                        "Automated infrastructure modification or network routing alterations",
                        "Automated legal takedown requests or external abuse dispatch"
                    ]).map(act => `<li>${escapeHtml(act)}</li>`).join("")}
                </ul>
            </div>
        </section>
    `;

    container.innerHTML = html;
}

/**
 * Helper to render a group of findings with exact presentation ordering.
 */
function renderFindingsGroup(findings, polarityClass) {
    if (!findings || findings.length === 0) {
        return `<div style="font-size: 12px; color: var(--text-dim); padding: 8px 12px; background: rgba(15, 23, 42, 0.4); border-radius: 6px;">No ${polarityClass.replace(/-/g, " ")} findings recorded.</div>`;
    }

    return findings.map(f => `
        <div class="finding-row-card ${polarityClass}">
            <div class="finding-main-info">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <a href="javascript:void(0)" class="finding-id-pill" onclick="highlightLineageItem('${escapeHtml(f.evidence_id)}')" title="View in Evidence Lineage">${escapeHtml(f.evidence_id)}</a>
                    <span style="font-size: 12px; font-weight: 700; color: #ffffff;">${escapeHtml(f.agent_name || `Agent ${f.agent_id}`)}</span>
                    <span class="finding-badge ${escapeHtml(f.severity || 'info')}">${escapeHtml(f.severity || 'info')}</span>
                    ${f.is_duplicate ? `<span style="font-size: 9px; padding: 1px 4px; border-radius: 3px; background: rgba(100,116,139,0.3); color: var(--text-dim);">DUP (${escapeHtml(f.original_evidence_id)})</span>` : ""}
                </div>
                <div class="finding-text">${escapeHtml(f.finding || "")}</div>
                <div class="finding-meta-tags">
                    <span>Type: <strong>${escapeHtml(f.evidence_type || 'deterministic')}</strong></span>
                    <span>Strength: <strong>${Number(f.evidence_strength || 1.0).toFixed(2)}</strong></span>
                    <span>Category: <strong>${escapeHtml(f.category || 'general')}</strong></span>
                </div>
            </div>
            <div style="text-align: right; min-width: 120px;">
                <div style="font-size: 10px; color: var(--text-dim); text-transform: uppercase;">TCE Contribution</div>
                <div class="tce-contrib-tag">${f.tce_contribution !== null && f.tce_contribution !== undefined ? Number(f.tce_contribution).toFixed(4) : "Unavailable"}</div>
            </div>
        </div>
    `).join("");
}

/**
 * Helper to render 18 telemetry nodes.
 */
function renderTelemetryNodes(report) {
    const observed = new Set(report.observed_dimensions || []);
    const gaps = report.inactive_telemetry_gaps || {};

    return AGENT_METADATA.map(agent => {
        const agentKey = `A${agent.id}`;
        const isObserved = observed.has(agentKey) || observed.has(agent.name) || observed.has(String(agent.id));
        const gapReason = gaps[agentKey] || gaps[agent.name] || gaps[String(agent.id)];

        let stateClass = "unobserved";
        let stateLabel = "Telemetry Gap";

        if (isObserved) {
            // Check if active or clean
            const res = agentResults[agent.id];
            if (res && res.evidence && res.evidence.length > 0) {
                stateClass = "active";
                stateLabel = "Active Evidence";
            } else {
                stateClass = "clean";
                stateLabel = "Clean Observation";
            }
        } else {
            stateClass = "unobserved";
            stateLabel = gapReason ? "Inactive / Skipped" : "Unobserved";
        }

        return `
            <div class="telemetry-node ${stateClass}" title="${escapeHtml(gapReason || agent.desc)}">
                <div style="display: flex; flex-direction: column;">
                    <span class="telemetry-name">A${String(agent.id).padStart(2, "0")}: ${escapeHtml(agent.name)}</span>
                    ${gapReason ? `<span style="font-size: 10px; color: var(--text-dim); word-break: break-all;">${escapeHtml(gapReason)}</span>` : ""}
                </div>
                <span class="telemetry-status-pill ${stateClass}">${stateLabel}</span>
            </div>
        `;
    }).join("");
}

/**
 * Scroll to and highlight an evidence item in the Evidence Lineage table.
 */
function highlightLineageItem(evidenceId) {
    const row = document.getElementById(`lineage-row-${evidenceId}`);
    if (!row) return;

    row.scrollIntoView({ behavior: "smooth", block: "center" });
    row.classList.add("highlighted");
    setTimeout(() => {
        row.classList.remove("highlighted");
    }, 2500);
}

/**
 * Export the current InvestigatorReportPayload as a JSON file.
 */
function exportInvestigatorReportJson() {
    if (!currentReportPayload) {
        alert("No report payload available to export.");
        return;
    }

    const jsonStr = JSON.stringify(currentReportPayload, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const invId = (currentReportPayload.overview && currentReportPayload.overview.investigation_id) ? currentReportPayload.overview.investigation_id : "dossier";
    a.href = url;
    a.download = `investigator-report-${invId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Print the report or save as PDF.
 */
function printInvestigatorReport() {
    window.print();
}





