// ============================================================
// RANSOMGUARD MULTI-ENDPOINT DASHBOARD (frontend/app.js)
// Phase 10.5 — Persistent Incident UI & Real LAN Architecture
// ============================================================

console.log("[RansomGuard] app.js v3.1 LAN loaded");

window.onerror = function (message, source, lineno, colno, error) {
    console.error("[GLOBAL JS ERROR]", { message, source, lineno, colno, error });
};

window.addEventListener("unhandledrejection", function (event) {
    console.error("[UNHANDLED PROMISE]", event.reason);
});

let socket = null;
let reconnectTimer = null;
let reconnectAttempts = 0;
let devicesCache = {};
let selectedDeviceId = null;
let activeIncidentsCache = [];
let acknowledgedIncidents = new Set();


function toggleAcknowledgeIncident(alertId) {
    if (acknowledgedIncidents.has(alertId)) {
        acknowledgedIncidents.delete(alertId);
    } else {
        acknowledgedIncidents.add(alertId);
    }
    renderActiveIncidents(activeIncidentsCache);
}


// ============================================================
// SAFE DOM HELPERS
// ============================================================

function getEl(id) {
    const el = document.getElementById(id);
    if (!el) {
        console.warn(`[UI WARNING] Element not found: #${id}`);
    }
    return el;
}

function setText(id, value) {
    const el = getEl(id);
    if (el) {
        el.textContent = value;
    }
}


// ============================================================
// INITIAL DASHBOARD STATE LOAD (Item 16 & Item 17)
// ============================================================

async function loadInitialState() {
    try {
        await Promise.all([
            fetchDevices(),
            fetchActiveIncidents(),
            fetchResolvedIncidents(),
            fetchLogs(),
        ]);
    } catch (err) {
        console.warn("[UI] Error loading initial dashboard state:", err);
    }
}


// ============================================================
// DEVICE MANAGEMENT & OVERVIEW (Item 6, 10, 11)
// ============================================================

async function fetchDevices() {
    try {
        const res = await fetch("/devices");
        if (res.ok) {
            const devices = await res.json();
            updateDevicesOverview(devices);
        }
    } catch (err) {
        console.warn("[UI] Failed to fetch devices:", err);
    }
}

function updateDevicesOverview(devicesList) {
    if (!Array.isArray(devicesList)) return;

    let total = devicesList.length;
    let online = 0;
    let offline = 0;
    let low = 0;
    let medium = 0;
    let high = 0;

    const grid = getEl("devicesGrid");
    if (!grid) return;

    devicesCache = {};

    if (total === 0) {
        grid.innerHTML = '<div class="empty-state">No RansomGuard endpoints connected.</div>';
    } else {
        grid.innerHTML = "";
    }

    devicesList.forEach(dev => {
        devicesCache[dev.device_id] = dev;

        const isOnline = dev.status === "ONLINE";
        if (isOnline) online++;
        else offline++;

        // Determine effective severity (Item 11: Active Incident Overrides Latest Low Packet)
        const activeInc = dev.active_incident;
        const effectiveSev = (dev.effective_severity || dev.current_severity || "LOW").toUpperCase();

        if (effectiveSev === "LOW") low++;
        else if (effectiveSev === "MEDIUM") medium++;
        else high++;

        // Determine CSS state class (Item 10)
        let stateClass = "device-safe";
        if (!isOnline) {
            stateClass = "device-offline";
        } else if (effectiveSev === "CRITICAL") {
            stateClass = "device-critical";
        } else if (effectiveSev === "HIGH") {
            stateClass = "device-threat";
        } else if (effectiveSev === "MEDIUM") {
            stateClass = "device-warning";
        }

        // Build device card
        const card = document.createElement("div");
        card.className = `device-card ${stateClass} ${isOnline ? 'card-online' : 'card-offline'}`;
        if (selectedDeviceId === dev.device_id) {
            card.classList.add("card-selected");
        }

        const shortId = dev.device_id ? (dev.device_id.length > 14 ? dev.device_id.substring(0, 14) + "..." : dev.device_id) : "rg-unk";
        const lastSeenStr = dev.last_seen ? new Date(dev.last_seen * 1000).toLocaleTimeString() : "--:--:--";
        const threatScoreVal = (dev.current_threat_score !== undefined && dev.current_threat_score !== null) ? Number(dev.current_threat_score).toFixed(1) : "0.0";

        let activeBadgeHtml = "";
        if (activeInc) {
            activeBadgeHtml = `<span class="badge-active-inc">🚨 ${escapeHtml(activeInc.severity || 'HIGH')} INCIDENT</span>`;
        }

        card.innerHTML = `
            <div class="dev-card-header">
                <span class="dev-card-hostname">${escapeHtml(dev.hostname)}</span>
                <span class="dev-card-status ${isOnline ? 'badge-online' : 'badge-offline'}">${dev.status}</span>
            </div>
            <div class="dev-card-id">${escapeHtml(shortId)} ${activeBadgeHtml}</div>
            <div class="dev-card-metrics">
                <div><span>OS:</span> <strong>${escapeHtml(dev.os || 'Linux')}</strong></div>
                <div><span>Effective Sev:</span> <strong class="sev-tag-${effectiveSev.toLowerCase()}">${effectiveSev}</strong></div>
                <div><span>Threat Score:</span> <strong>${threatScoreVal}</strong></div>
                <div><span>Last Seen:</span> <span>${lastSeenStr}</span></div>
            </div>
            <div class="dev-card-footer">
                <span>Ver: ${escapeHtml(dev.agent_version || '3.1')}</span>
                <button class="dev-card-btn">Details &rarr;</button>
            </div>
        `;

        card.addEventListener("click", () => {
            selectedDeviceId = dev.device_id;
            fetchAndShowDeviceModal(dev.device_id);
            document.querySelectorAll(".device-card").forEach(c => c.classList.remove("card-selected"));
            card.classList.add("card-selected");
        });

        grid.appendChild(card);
    });

    setText("deviceCountTotal", total);
    setText("deviceCountOnline", online);
    setText("deviceCountOffline", offline);
    setText("deviceCountLow", low);
    setText("deviceCountMedium", medium);
    setText("deviceCountHigh", high);
}


// ============================================================
// 7. ACTIVE INCIDENTS SECTION (Item 7 & Item 26)
// ============================================================

async function fetchActiveIncidents() {
    try {
        const res = await fetch("/incidents/active");
        if (res.ok) {
            const incidents = await res.json();
            activeIncidentsCache = incidents;
            renderActiveIncidents(incidents);
        }
    } catch (err) {
        console.warn("[UI] Failed to fetch active incidents:", err);
    }
}

function renderActiveIncidents(incidents) {
    const grid = getEl("activeIncidentsGrid");
    const badge = getEl("activeIncidentsBadge");
    if (!grid) return;

    if (!Array.isArray(incidents) || incidents.length === 0) {
        grid.innerHTML = `
            <div class="empty-incidents-state">
                <span class="shield-check">🛡️</span>
                <p>No active security incidents detected. All LAN endpoints operating safely.</p>
            </div>
        `;
        if (badge) {
            badge.textContent = "0 OPEN INCIDENTS";
            badge.className = "badge-status-green";
        }
        return;
    }

    if (badge) {
        badge.textContent = `${incidents.length} OPEN INCIDENT${incidents.length > 1 ? 'S' : ''}`;
        badge.className = "badge-status-red";
    }

    grid.innerHTML = "";

    incidents.forEach(inc => {
        const devName = inc.hostname || inc.device_id || "UNKNOWN-DEVICE";
        const openedStr = inc.opened_at ? new Date(inc.opened_at * 1000).toLocaleString() : (inc.timestamp ? new Date(inc.timestamp * 1000).toLocaleString() : "N/A");
        const updatedStr = inc.last_updated_at ? new Date(inc.last_updated_at * 1000).toLocaleTimeString() : "--";
        
        const proc = inc.primary_process || {};
        const procName = proc.process_name || "unknown";
        const procPid = proc.pid !== undefined && proc.pid !== null ? proc.pid : "N/A";
        const attributionConf = proc.attribution_confidence || inc.attribution_confidence || "HIGH";

        const rulesStr = Array.isArray(inc.triggered_rules) && inc.triggered_rules.length > 0 
            ? inc.triggered_rules.join(", ") 
            : "Ransomware Behavioral Pattern";

        const isAck = acknowledgedIncidents.has(inc.alert_id);
        const ackBadgeHtml = isAck ? '<span class="badge-ack">ACKNOWLEDGED</span>' : '<span class="badge-unack">UNACKNOWLEDGED</span>';

        const card = document.createElement("div");
        card.className = `incident-card incident-active-red ${isAck ? 'card-acknowledged' : ''}`;

        card.innerHTML = `
            <div class="inc-header">
                <div class="inc-title">
                    <span class="inc-alert-icon">🚨</span>
                    <div>
                        <h3>${escapeHtml(devName)}</h3>
                        <small class="inc-device-id">ID: ${escapeHtml(inc.device_id)}</small>
                    </div>
                </div>
                <div class="inc-status-group">
                    ${ackBadgeHtml}
                    <span class="inc-status-badge badge-red">${escapeHtml(inc.current_status || 'OPEN')}</span>
                    <button class="inc-ack-btn" onclick="event.stopPropagation(); toggleAcknowledgeIncident('${escapeHtml(inc.alert_id)}')">
                        ${isAck ? 'UNACK' : 'ACKNOWLEDGE'}
                    </button>
                </div>
            </div>

            <div class="inc-body-grid">
                <div><span>Peak Severity:</span> <strong class="txt-high">${escapeHtml(inc.peak_severity || inc.severity || 'HIGH')}</strong></div>
                <div><span>Threat Score:</span> <strong class="txt-high">${Number(inc.peak_score || inc.threat_score || 0).toFixed(1)} / 100</strong></div>
                <div><span>Prediction:</span> <strong>${escapeHtml(inc.prediction || 'ATTACK_SIMULATOR')}</strong></div>
                <div><span>Attribution Conf:</span> <strong>${escapeHtml(attributionConf)}</strong></div>
                <div><span>Process Name:</span> <strong>${escapeHtml(procName)}</strong></div>
                <div><span>Process PID:</span> <strong>${procPid}</strong></div>
                <div><span>Canary Evidence:</span> <strong>${inc.canary_triggered ? 'YES 🐥 (DECOY MODIFIED)' : 'STANDBY'}</strong></div>
                <div><span>Confirmation:</span> <strong>${escapeHtml(inc.confirmation_source || 'HYBRID_DEBOUNCE')}</strong></div>
                <div><span>Opened At:</span> <span>${openedStr}</span></div>
                <div><span>Last Updated:</span> <span>${updatedStr}</span></div>
            </div>

            <div class="inc-rules-bar">
                <span>Triggered Rules:</span> <code>${escapeHtml(rulesStr)}</code>
            </div>
        `;

        grid.appendChild(card);
    });
}


// ============================================================
// 8. RESOLVED INCIDENTS HISTORY (Item 8)
// ============================================================

async function fetchResolvedIncidents() {
    try {
        const res = await fetch("/incidents/resolved?limit=50");
        if (res.ok) {
            const incidents = await res.json();
            renderResolvedIncidents(incidents);
        }
    } catch (err) {
        console.warn("[UI] Failed to fetch resolved incidents:", err);
    }
}

function renderResolvedIncidents(incidents) {
    const grid = getEl("resolvedIncidentsGrid");
    if (!grid) return;

    if (!Array.isArray(incidents) || incidents.length === 0) {
        grid.innerHTML = '<div class="empty-state">No resolved incidents in history.</div>';
        return;
    }

    grid.innerHTML = "";

    incidents.forEach(inc => {
        const devName = inc.hostname || inc.device_id || "UNKNOWN-DEVICE";
        const openedStr = inc.opened_at ? new Date(inc.opened_at * 1000).toLocaleTimeString() : "--:--:--";
        const closedStr = inc.closed_at ? new Date(inc.closed_at * 1000).toLocaleTimeString() : "--:--:--";
        
        let durationStr = "N/A";
        if (inc.opened_at && inc.closed_at) {
            const secs = Math.round(inc.closed_at - inc.opened_at);
            durationStr = secs < 60 ? `${secs}s` : `${Math.floor(secs / 60)}m ${secs % 60}s`;
        }

        const proc = inc.primary_process || {};
        const procName = proc.process_name || "unknown";

        const item = document.createElement("div");
        item.className = "resolved-item";

        item.innerHTML = `
            <div class="resolved-header">
                <strong>[${openedStr} -> ${closedStr}] ${escapeHtml(devName)} (${durationStr})</strong>
                <span class="badge-resolved">CLOSED / RESOLVED</span>
            </div>
            <div class="resolved-details">
                <span>Peak Sev: <strong class="txt-high">${escapeHtml(inc.peak_severity || 'HIGH')}</strong></span>
                <span>Peak Score: <strong>${Number(inc.peak_score || 0).toFixed(1)}</strong></span>
                <span>Process: <strong>${escapeHtml(procName)}</strong></span>
                <span>Confirmation: <span>${escapeHtml(inc.confirmation_source || 'HYBRID_DEBOUNCE')}</span></span>
            </div>
        `;

        grid.appendChild(item);
    });
}


// ============================================================
// 12 - 15. PERSISTENT LIVE LOG SYSTEM (Item 12, 13, 14, 15)
// ============================================================

async function fetchLogs() {
    try {
        const res = await fetch("/logs?limit=100");
        if (res.ok) {
            const logs = await res.json();
            renderLogs(logs);
        }
    } catch (err) {
        console.warn("[UI] Failed to fetch logs:", err);
    }
}

function renderLogs(logs) {
    const container = getEl("eventLog");
    if (!container) return;

    if (!Array.isArray(logs) || logs.length === 0) {
        container.innerHTML = '<div class="log-entry"><span class="log-time">--:--:--</span><span class="log-badge badge-system">SYSTEM</span><span class="log-msg">No logs recorded yet.</span></div>';
        return;
    }

    container.innerHTML = "";

    logs.forEach(log => {
        appendLogEntry(log, false);
    });
}

function appendLogEntry(log, isLive = true) {
    const container = getEl("eventLog");
    if (!container) return;

    const entry = document.createElement("div");
    entry.className = "log-entry";

    let timeStr = "--:--:--";
    if (typeof log.timestamp === "number") {
        timeStr = new Date(log.timestamp * 1000).toLocaleTimeString();
    } else if (typeof log.timestamp === "string") {
        timeStr = log.timestamp.includes("T") ? log.timestamp.split("T")[1].substring(0, 8) : log.timestamp;
    }

    const sevTag = (log.severity || "INFO").toUpperCase();
    const catTag = log.category || "SYSTEM";
    const devStr = log.device_id ? (log.device_id.length > 8 ? log.device_id.substring(0, 8) : log.device_id) : "SERVER";
    const msg = log.message || "";

    entry.innerHTML = `
        <span class="log-time">${timeStr}</span>
        <span class="log-device">${escapeHtml(devStr)}</span>
        <span class="log-badge badge-${sevTag.toLowerCase()}">${sevTag}</span>
        <span class="log-cat">[${escapeHtml(catTag)}]</span>
        <span class="log-msg">${escapeHtml(msg)}</span>
    `;

    if (isLive) {
        container.prepend(entry);
    } else {
        container.appendChild(entry);
    }

    while (container.children.length > 100) {
        container.removeChild(container.lastChild);
    }
}

function addLog(severityTag, message, customTime) {
    appendLogEntry({
        timestamp: customTime || new Date().toISOString(),
        severity: severityTag,
        category: "SYSTEM",
        message: message,
    }, true);
}


// ============================================================
// 9. ALERT TOAST NOTIFICATION (Item 9)
// ============================================================

function showToast(message, type = "HIGH") {
    const container = getEl("toastContainer");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast toast-${type.toLowerCase()}`;
    toast.innerHTML = `
        <span class="toast-icon">🚨</span>
        <span class="toast-msg">${escapeHtml(message)}</span>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add("toast-fadeout");
        setTimeout(() => {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, 500);
    }, 4000);
}


// ============================================================
// 18. DEVICE DETAIL MODAL (Item 18)
// ============================================================

async function fetchAndShowDeviceModal(deviceId) {
    try {
        const [devRes, telemRes, alertRes, logsRes] = await Promise.all([
            fetch(`/devices/${deviceId}`),
            fetch(`/devices/${deviceId}/telemetry?limit=10`),
            fetch(`/devices/${deviceId}/alerts?limit=10`),
            fetch(`/devices/${deviceId}/logs?limit=20`),
        ]);

        if (!devRes.ok) return;

        const dev = await devRes.json();
        const telemetry = telemRes.ok ? await telemRes.json() : [];
        const alerts = alertRes.ok ? await alertRes.json() : [];
        const logs = logsRes.ok ? await logsRes.json() : [];

        renderDeviceModal(dev, telemetry, alerts, logs);
    } catch (err) {
        console.error("[UI] Error loading device details:", err);
    }
}

function renderDeviceModal(dev, telemetry, alerts, logs) {
    setText("modalHostname", dev.hostname);
    setText("modalDeviceId", `Device ID: ${dev.device_id}`);
    setText("modalOs", `${dev.os} (${dev.os_version || 'N/A'})`);
    setText("modalAgentVer", dev.agent_version || "3.1-dev");
    setText("modalModelVer", dev.model_version || "rf_v2");
    setText("modalStatus", dev.status);

    const statusEl = getEl("modalStatus");
    if (statusEl) {
        statusEl.className = dev.status === "ONLINE" ? "txt-online" : "txt-offline";
    }

    setText("modalLastSeen", dev.last_seen ? new Date(dev.last_seen * 1000).toLocaleString() : "N/A");
    setText("modalSeverity", dev.effective_severity || dev.current_severity || "LOW");

    // Active Incident Box in Modal
    const activeBox = getEl("modalActiveIncidentBox");
    if (activeBox) {
        if (dev.active_incident) {
            const inc = dev.active_incident;
            activeBox.innerHTML = `
                <div class="incident-card incident-active-red">
                    <div><strong>🚨 ACTIVE INCIDENT (${escapeHtml(inc.current_status || 'OPEN')})</strong></div>
                    <div>Peak Severity: <strong class="txt-high">${escapeHtml(inc.peak_severity || 'HIGH')}</strong> | Threat Score: ${Number(inc.peak_score || 0).toFixed(1)}</div>
                    <div>Rules: ${(inc.triggered_rules || []).join(", ") || "Ransomware Pattern"}</div>
                </div>
            `;
        } else {
            activeBox.innerHTML = '<div class="empty-state">No active incident for this device.</div>';
        }
    }

    // Populate Process Context
    const latestTelem = telemetry[0] || {};
    const domProc = (alerts[0] && alerts[0].primary_process) || latestTelem.dominant_process || {};
    setText("modalProcName", domProc.process_name || "unknown");
    setText("modalProcPid", domProc.pid !== undefined && domProc.pid !== null ? domProc.pid : "N/A");
    setText("modalProcParent", domProc.parent_process_name || "N/A");
    setText("modalProcUser", domProc.username || "N/A");
    setText("modalProcPath", domProc.executable_path || "N/A");
    setText("modalProcConf", domProc.attribution_confidence || "UNKNOWN");

    // Render latest features in modal
    const modalFeatGrid = getEl("modalFeaturesGrid");
    if (modalFeatGrid) {
        modalFeatGrid.innerHTML = "";
        const feats = latestTelem.features || {};

        const featureKeys = [
            "files_created", "files_modified", "files_deleted", "files_renamed",
            "writes_per_second", "unique_extensions", "unique_directories",
            "extension_change_count", "rename_ratio", "mean_entropy", "entropy_change"
        ];

        featureKeys.forEach(key => {
            const val = feats[key] ?? 0;
            const item = document.createElement("div");
            item.className = "feature-item";
            item.innerHTML = `
                <span class="feature-label">${key}</span>
                <span class="feature-value ${Number(val) > 0 ? 'feature-active' : ''}">${val}</span>
            `;
            modalFeatGrid.appendChild(item);
        });
    }

    // Render logs list in modal
    const modalLogsList = getEl("modalLogsList");
    if (modalLogsList) {
        modalLogsList.innerHTML = "";
        if (!logs || logs.length === 0) {
            modalLogsList.innerHTML = '<div class="empty-state">No logs recorded for this endpoint.</div>';
        } else {
            logs.forEach(l => {
                const item = document.createElement("div");
                item.className = "modal-list-item";
                const timeStr = typeof l.timestamp === "number" ? new Date(l.timestamp * 1000).toLocaleTimeString() : l.timestamp;
                item.innerHTML = `
                    <span>[${timeStr}] <strong>${escapeHtml(l.severity || 'INFO')}</strong> [${escapeHtml(l.category || 'SYSTEM')}] - ${escapeHtml(l.message)}</span>
                `;
                modalLogsList.appendChild(item);
            });
        }
    }

    // Render alerts in modal
    const alertsList = getEl("modalAlertsList");
    if (alertsList) {
        alertsList.innerHTML = "";
        if (!alerts || alerts.length === 0) {
            alertsList.innerHTML = '<div class="empty-state">No alerts recorded for this endpoint.</div>';
        } else {
            alerts.forEach(al => {
                const item = document.createElement("div");
                item.className = "modal-list-item alert-item";
                const timeStr = new Date(al.timestamp * 1000).toLocaleTimeString();
                item.innerHTML = `
                    <div><strong>[${timeStr}] INCIDENT / ALERT ${al.severity}</strong> - Threat Score: ${al.threat_score} (Peak: ${al.peak_score || al.threat_score})</div>
                    <small>Status: <strong>${al.current_status || 'OPEN'}</strong> | Rules: ${(al.triggered_rules || []).join(", ") || "None"}</small>
                `;
                alertsList.appendChild(item);
            });
        }
    }

    const overlay = getEl("deviceModalOverlay");
    if (overlay) overlay.classList.remove("hidden");
}

function closeDeviceModal() {
    const overlay = getEl("deviceModalOverlay");
    if (overlay) overlay.classList.add("hidden");
}


// Setup Modal Close Listener
document.addEventListener("DOMContentLoaded", () => {
    const closeBtn = getEl("modalCloseBtn");
    if (closeBtn) {
        closeBtn.addEventListener("click", closeDeviceModal);
    }
    const overlay = getEl("deviceModalOverlay");
    if (overlay) {
        overlay.addEventListener("click", (e) => {
            if (e.target === overlay) closeDeviceModal();
        });
    }

    // Load initial data on page load
    loadInitialState();
});


// ============================================================
// 17. WEBSOCKET CONNECTION & RECONNECT RECOVERY (Item 17)
// ============================================================

function connectWebSocket() {
    console.log("[WS] Connecting to RansomGuard WebSocket...");

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host || "127.0.0.1:8000";
    const wsUrl = `${protocol}//${host}/ws`;

    try {
        socket = new WebSocket(wsUrl);
    } catch (err) {
        console.error("[WS] Failed to instantiate WebSocket:", err);
        scheduleReconnect();
        return;
    }

    socket.onopen = function () {
        console.log("[WS] Connected successfully to central server!");
        reconnectAttempts = 0;

        setText("connectionStatus", "CENTRAL SERVER ONLINE");
        const dot = getEl("statusDot");
        if (dot) dot.style.background = "#37d67a";

        addLog("SYSTEM", "WebSocket connected. Real LAN multi-endpoint telemetry feed active.");
        
        // Recover state missed during disconnect (Item 17)
        loadInitialState();

        try {
            socket.send("PING");
        } catch (e) {
            console.warn("[WS] Send PING failed:", e);
        }
    };

    socket.onmessage = function (event) {
        try {
            const data = JSON.parse(event.data);
            handleIncomingEvent(data);
        } catch (error) {
            console.error("[WS] Error processing message:", error);
        }
    };

    socket.onclose = function (event) {
        console.warn(`[WS] Connection closed (code ${event.code})`);

        setText("connectionStatus", "RECONNECTING...");
        const dot = getEl("statusDot");
        if (dot) dot.style.background = "#ff5c5c";

        addLog("SYSTEM", "WebSocket disconnected. Retrying...");
        scheduleReconnect();
    };

    socket.onerror = function (error) {
        console.error("[WS] Socket error occurred:", error);
    };
}

function scheduleReconnect() {
    if (reconnectTimer !== null) return;
    reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(2, reconnectAttempts - 1), 10000);
    console.log(`[WS] Scheduling reconnect attempt #${reconnectAttempts} in ${delay}ms`);
    reconnectTimer = setTimeout(function () {
        reconnectTimer = null;
        connectWebSocket();
    }, delay);
}


// ============================================================
// 14. EVENT DISPATCHER & LOG WEBSOCKET BROADCASTS (Item 14)
// ============================================================

function handleIncomingEvent(event) {
    if (!event) return;

    const eventType = event.type;

    if (eventType === "LOG_EVENT") {
        const logData = event.data || event;
        appendLogEntry(logData, true);
    } else if (eventType === "AGENT_REGISTERED") {
        addLog("SYSTEM", `New LAN agent registered: ${event.data.hostname} (${event.device_id})`);
        fetchDevices();
    } else if (eventType === "AGENT_HEARTBEAT") {
        fetchDevices();
    } else if (eventType === "TELEMETRY_UPDATE") {
        fetchDevices();
        if (!selectedDeviceId || selectedDeviceId === event.device_id) {
            updateActiveTelemetryDisplay(event.data);
        }
    } else if (eventType === "ALERT_UPDATE") {
        const al = event.data;
        const devHost = devicesCache[event.device_id]?.hostname || event.device_id;
        showToast(`🚨 ${al.severity} threat detected on ${devHost}`, al.severity);
        fetchDevices();
        fetchActiveIncidents();
        fetchResolvedIncidents();
        if (selectedDeviceId === event.device_id) {
            fetchAndShowDeviceModal(event.device_id);
        }
    } else if (eventType === "DEVICE_OFFLINE") {
        addLog("SYSTEM", `Device ${event.device_id} is now OFFLINE`);
        fetchDevices();
    } else if (eventType === "PREDICTION_UPDATE") {
        updateActiveTelemetryDisplay(event);
    } else if (eventType === "PIPELINE_RESET") {
        addLog("RESET", event.message || "Pipeline state reset.");
        loadInitialState();
    }
}

function updateActiveTelemetryDisplay(data) {
    if (!data) return;

    const deviceId = data.device_id;
    const activeInc = (deviceId && activeIncidentsCache.find(i => i.device_id === deviceId)) || (deviceId && devicesCache[deviceId]?.active_incident);

    // Active incident state overrides latest low telemetry packet (Item 11)
    const rawSeverity = data.severity || "LOW";
    const effectiveSeverity = activeInc ? (activeInc.peak_severity || activeInc.severity || "HIGH") : rawSeverity;
    const effectiveScore = activeInc ? (activeInc.peak_score || activeInc.threat_score || Number(data.threat_score) || 0) : (Number(data.threat_score) || 0);

    setText("threatScore", Number(effectiveScore).toFixed(1));
    setText("severity", `Severity: ${effectiveSeverity}`);

    const isAlert = Boolean(activeInc || data.confirmed_alert || data.debounce?.debounced_alert);
    const badge = getEl("debounceBadge");
    if (badge) {
        if (activeInc) {
            badge.textContent = `Active Incident: ${activeInc.alert_id} 🚨`;
            badge.className = "debounce-badge active-alert";
        } else if (isAlert) {
            badge.textContent = `Confirmed Alert: YES 🚨`;
            badge.className = "debounce-badge active-alert";
        } else if (effectiveSeverity === "HIGH" || effectiveSeverity === "CRITICAL") {
            badge.textContent = `Confirmed Alert: PENDING`;
            badge.className = "debounce-badge pending-alert";
        } else {
            badge.textContent = "Confirmed Alert: NO";
            badge.className = "debounce-badge";
        }
    }

    const circle = getEl("scoreCircle");
    if (circle) {
        if (effectiveSeverity === "CRITICAL" || effectiveSeverity === "HIGH") {
            circle.style.borderColor = "#ff4d4d";
        } else if (effectiveSeverity === "MEDIUM") {
            circle.style.borderColor = "#ffb84d";
        } else {
            circle.style.borderColor = "#37d67a";
        }
    }

    if (activeInc) {
        setText("threatStatus", "ACTIVE SECURITY INCIDENT");
    } else if (isAlert) {
        setText("threatStatus", "CONFIRMED THREAT DETECTED");
    } else if (effectiveSeverity === "HIGH" || effectiveSeverity === "CRITICAL") {
        setText("threatStatus", "SUSPICIOUS ACTIVITY");
    } else {
        setText("threatStatus", "NO ACTIVE THREAT");
    }

    const prediction = data.prediction || "BENIGN";
    setText("prediction", prediction);

    const threatProb = Number(data.threat_probability ?? data.ml?.threat_probability) || 0;
    const benignProb = Number(data.benign_probability ?? data.ml?.benign_probability) || (1.0 - threatProb);
    setText("threatProbability", `${(threatProb * 100).toFixed(1)}%`);
    setText("benignProbability", `${(benignProb * 100).toFixed(1)}%`);

    const ruleScoreVal = Number(data.rule_score ?? data.rules?.rule_score) || 0;
    const triggeredRules = data.triggered_rules || data.rules?.triggered_rules || [];
    setText("ruleScore", ruleScoreVal);
    setText("rulesTriggered", triggeredRules.length);
    setText("ruleCount", `${triggeredRules.length} RULES`);

    const canaryEval = data.canary_eval || {};
    if (canaryEval.primary_canary_event) {
        setText("canaryLastEventType", canaryEval.primary_canary_event.event_type || "MODIFIED");
    } else if (data.canary_event_type) {
        setText("canaryLastEventType", data.canary_event_type);
    }
    const isEarlyConfirm = data.early_confirmation || canaryEval.early_confirmation;
    if (isEarlyConfirm) {
        setText("canaryEarlyConfirmState", "EARLY CONFIRMED 🚨");
    } else {
        setText("canaryEarlyConfirmState", "STANDBY");
    }

    updateRulesList(triggeredRules);
    updateFeaturesDisplay(data.features || {});
}

function updateRulesList(rules) {
    const list = getEl("rulesList");
    if (!list) return;

    list.innerHTML = "";
    if (!rules || rules.length === 0) {
        list.innerHTML = '<div class="empty-state">No rules triggered.</div>';
        return;
    }

    rules.forEach(r => {
        const item = document.createElement("div");
        item.className = "rule-item";
        const ruleName = typeof r === "string" ? r : (r.rule || "RULE");
        item.innerHTML = `<strong>${escapeHtml(ruleName)}</strong>`;
        list.appendChild(item);
    });
}

function updateFeaturesDisplay(features) {
    const keys = [
        "files_created", "files_modified", "files_deleted", "files_renamed",
        "writes_per_second", "unique_extensions", "unique_directories",
        "extension_change_count", "rename_ratio", "mean_entropy", "entropy_change"
    ];

    keys.forEach(k => {
        const el = getEl(`feat_${k}`);
        if (el) {
            const val = features[k] ?? 0;
            if (k.includes("ratio") || k.includes("entropy")) {
                el.textContent = Number(val).toFixed(3);
            } else if (k.includes("second")) {
                el.textContent = Number(val).toFixed(1);
            } else {
                el.textContent = Math.round(val);
            }
            if (Number(val) > 0) el.classList.add("feature-active");
            else el.classList.remove("feature-active");
        }
    });
}

function escapeHtml(str) {
    return String(str || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}


// Start periodic device fetch polling every 5 seconds as fallback
setInterval(fetchDevices, 5000);
setInterval(fetchActiveIncidents, 5000);

console.log("[RansomGuard] Starting multi-endpoint dashboard...");
connectWebSocket();