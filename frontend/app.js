// ============================================================
// RANSOMGUARD REAL-TIME DASHBOARD (frontend/app.js)
// ============================================================

console.log("[RansomGuard] app.js v1.3 loaded");

window.onerror = function (message, source, lineno, colno, error) {
    console.error("[GLOBAL JS ERROR]", { message, source, lineno, colno, error });
};

window.addEventListener("unhandledrejection", function (event) {
    console.error("[UNHANDLED PROMISE]", event.reason);
});

let socket = null;
let reconnectTimer = null;
let messageCount = 0;


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
// WEBSOCKET CONNECTION
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
        console.log("[WS] Connected successfully!");

        setText("connectionStatus", "SYSTEM ONLINE");
        const dot = getEl("statusDot");
        if (dot) dot.style.background = "#37d67a";

        addLog("SYSTEM", "WebSocket connected. Live telemetry bridge active.");

        try {
            socket.send("PING");
        } catch (e) {
            console.warn("[WS] Send PING failed:", e);
        }
    };

    socket.onmessage = function (event) {
        messageCount++;
        try {
            const data = JSON.parse(event.data);
            if (data.type === "PIPELINE_RESET") {
                handlePipelineReset(data);
            } else if (data.type === "CONTAINMENT_UPDATE") {
                handleContainmentUpdate(data);
            } else {
                updateDashboard(data);
            }
        } catch (error) {
            console.error("[WS] Error processing message:", error);
        }
    };

    socket.onclose = function (event) {
        console.warn(`[WS] Connection closed (code ${event.code})`);

        setText("connectionStatus", "RECONNECTING...");
        const dot = getEl("statusDot");
        if (dot) dot.style.background = "#ff5c5c";

        addLog("SYSTEM", "WebSocket disconnected. Attempting reconnect...");
        scheduleReconnect();
    };

    socket.onerror = function (error) {
        console.error("[WS] Socket error occurred:", error);
    };
}


function scheduleReconnect() {
    if (reconnectTimer !== null) return;
    reconnectTimer = setTimeout(function () {
        reconnectTimer = null;
        connectWebSocket();
    }, 2000);
}


// ============================================================
// HANDLE PIPELINE RESET
// ============================================================

function handlePipelineReset(data) {
    setText("threatScore", "0.0");
    setText("threatStatus", "NO ACTIVE THREAT");
    setText("severity", "Severity: LOW");
    
    const badge = getEl("debounceBadge");
    if (badge) {
        badge.textContent = "Confirmed Alert: NO";
        badge.className = "debounce-badge";
    }

    const circle = getEl("scoreCircle");
    if (circle) circle.style.borderColor = "#37d67a";

    setText("prediction", "BENIGN");
    setText("threatProbability", "0.0%");
    setText("benignProbability", "100.0%");

    setText("ruleScore", "0");
    setText("rulesTriggered", "0");
    setText("ruleCount", "0 RULES");

    setText("eventIndicator", "RESET");
    setText("alertIcon", "🧹");
    setText("alertTitle", "Pipeline Reset Executed");
    setText("alertMessage", data.message || "Sliding window and debounce counters cleared.");

    updateRules([]);
    updateFeatures({});

    addLog("RESET", data.message || "Pipeline state cleared for new scenario.");
}


// ============================================================
// HANDLE CONTAINMENT UPDATE
// ============================================================

function handleContainmentUpdate(data) {
    const res = data.result || {};
    const metrics = res.metrics ? res.metrics.metrics : {};

    setText("threatStatus", "SAFE CONTAINMENT EXECUTED 🛡️");
    setText("eventIndicator", "CONTAINED");
    setText("alertIcon", "🛡️");
    setText("alertTitle", "Safe Containment Halted Attack Simulator");

    const ttd = metrics.TTD_confirmed !== undefined ? `${metrics.TTD_confirmed}s` : "N/A";
    const ttc = metrics.TTC !== undefined ? `${metrics.TTC}s` : "N/A";
    const protectedPct = metrics.percentage_files_protected !== undefined ? `${metrics.percentage_files_protected}%` : "100%";

    setText("alertMessage", `Controlled attack simulator safely stopped! TTD: ${ttd} | TTC: ${ttc} | Protected: ${protectedPct}`);

    const badge = getEl("debounceBadge");
    if (badge) {
        badge.textContent = `Containment: CONTAINED 🛡️ (TTD ${ttd}, TTC ${ttc})`;
        badge.className = "debounce-badge active-alert";
    }

    addLog("CONTAINMENT", `Safe simulator containment executed. TTD: ${ttd}, TTC: ${ttc}, Protected: ${protectedPct}`);
}


// ============================================================
// UPDATE DASHBOARD
// ============================================================

function updateDashboard(result) {
    if (!result) return;

    const score = Number(result.threat_score) || 0;
    setText("threatScore", score.toFixed(1));

    const severity = result.severity || "LOW";
    setText("severity", `Severity: ${severity}`);

    const debounce = result.debounce || {};
    const isDebouncedAlert = Boolean(debounce.debounced_alert);
    const debouncedSeverity = debounce.debounced_severity || severity;

    // DEBOUNCE BADGE
    const badge = getEl("debounceBadge");
    if (badge) {
        if (isDebouncedAlert) {
            badge.textContent = `Confirmed Alert: YES 🚨 (${debounce.consecutive_windows || 1}w)`;
            badge.className = "debounce-badge active-alert";
        } else if (severity === "HIGH" || severity === "CRITICAL") {
            badge.textContent = `Confirmed Alert: PENDING (Window 1/${debounce.consecutive_windows || 1})`;
            badge.className = "debounce-badge pending-alert";
        } else {
            badge.textContent = "Confirmed Alert: NO";
            badge.className = "debounce-badge";
        }
    }

    // SCORE CIRCLE COLOR
    const circle = getEl("scoreCircle");
    if (circle) {
        if (debouncedSeverity === "CRITICAL" || debouncedSeverity === "HIGH") {
            circle.style.borderColor = "#ff4d4d";
        } else if (severity === "MEDIUM" || debouncedSeverity === "MEDIUM") {
            circle.style.borderColor = "#ffb84d";
        } else {
            circle.style.borderColor = "#37d67a";
        }
    }

    // CURRENT THREAT STATUS TEXT
    if (isDebouncedAlert) {
        setText("threatStatus", "CONFIRMED THREAT DETECTED");
    } else if (severity === "HIGH" || severity === "CRITICAL" || result.prediction === "THREAT") {
        setText("threatStatus", "SUSPICIOUS ACTIVITY (PENDING)");
    } else {
        setText("threatStatus", "NO ACTIVE THREAT");
    }

    // AI DETECTION
    const prediction = result.prediction || "UNKNOWN";
    setText("prediction", prediction);

    if (result.ml) {
        const threatProb = Number(result.ml.threat_probability) || 0;
        const benignProb = Number(result.ml.benign_probability) || 0;
        setText("threatProbability", `${(threatProb * 100).toFixed(1)}%`);
        setText("benignProbability", `${(benignProb * 100).toFixed(1)}%`);
        if (result.ml.threshold !== undefined) {
            setText("rfThreshold", Number(result.ml.threshold).toFixed(2));
        }
    }

    // RULE ENGINE
    if (result.rules) {
        const ruleScoreVal = Number(result.rules.rule_score) || 0;
        const rulesTriggeredVal = Number(result.rules.rules_triggered) || 0;

        setText("ruleScore", ruleScoreVal);
        setText("rulesTriggered", rulesTriggeredVal);
        setText("ruleCount", `${rulesTriggeredVal} RULE${rulesTriggeredVal === 1 ? "" : "S"}`);

        updateRules(result.rules.triggered_rules || []);
    }

    // CURRENT WINDOW EVENT CARD
    if (isDebouncedAlert) {
        setText("eventIndicator", "CONFIRMED THREAT");
        setText("alertIcon", "🚨");
        setText("alertTitle", "Confirmed Ransomware Alert");
        setText("alertMessage", `Consecutive threat behavior confirmed. Threat Score: ${score.toFixed(1)} | Severity: ${debouncedSeverity}`);
    } else if (severity === "HIGH" || severity === "CRITICAL" || prediction === "THREAT") {
        setText("eventIndicator", "SUSPICIOUS");
        setText("alertIcon", "⚠️");
        setText("alertTitle", "Suspicious Activity Detected");
        setText("alertMessage", `Current window score ${score.toFixed(1)} exceeded threshold. Awaiting confirmation.`);
    } else {
        setText("eventIndicator", "LIVE");
        setText("alertIcon", "🟢");
        setText("alertTitle", "System Monitoring Active");
        setText("alertMessage", "Telemetry window evaluated cleanly. No active threat detected in current window.");
    }

    // BEHAVIORAL TELEMETRY (11 FEATURES)
    const features = result.features || {};
    updateFeatures(features);

    // RECENT DETECTION HISTORY LOG
    const timestampStr = result.timestamp ? new Date(result.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
    const logMsg = `Score: ${score.toFixed(1)} | Raw: ${severity} | Debounced: ${debouncedSeverity} | Pred: ${prediction} | Rules: ${result.rules?.rules_triggered || 0}`;
    addLog(debouncedSeverity, logMsg, timestampStr);
}


// ============================================================
// UPDATE TRIGGERED RULES
// ============================================================

function updateRules(rules) {
    const rulesList = getEl("rulesList");
    if (!rulesList) return;

    rulesList.innerHTML = "";

    if (!rules || rules.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty-state";
        empty.textContent = "No rules triggered in current window.";
        rulesList.appendChild(empty);
        return;
    }

    rules.forEach(function (rule) {
        const ruleElement = document.createElement("div");
        ruleElement.className = "rule-item";

        const ruleName = document.createElement("strong");
        ruleName.textContent = rule.rule || "UNKNOWN_RULE";

        const description = document.createElement("span");
        description.textContent = rule.description || "";

        const points = document.createElement("span");
        points.className = "rule-points";
        points.textContent = `+${rule.points ?? 0}`;

        ruleElement.appendChild(ruleName);
        ruleElement.appendChild(description);
        ruleElement.appendChild(points);

        rulesList.appendChild(ruleElement);
    });
}


// ============================================================
// UPDATE FEATURES DISPLAY (11 CANONICAL FEATURES)
// ============================================================

function updateFeatures(features) {
    const featureMap = {
        "files_created":          { id: "feat_files_created",          fmt: "int" },
        "files_modified":         { id: "feat_files_modified",         fmt: "int" },
        "files_deleted":          { id: "feat_files_deleted",          fmt: "int" },
        "files_renamed":          { id: "feat_files_renamed",          fmt: "int" },
        "writes_per_second":      { id: "feat_writes_per_second",      fmt: "f1"  },
        "unique_extensions":      { id: "feat_unique_extensions",      fmt: "int" },
        "unique_directories":     { id: "feat_unique_directories",     fmt: "int" },
        "extension_change_count": { id: "feat_extension_change_count", fmt: "int" },
        "rename_ratio":           { id: "feat_rename_ratio",           fmt: "f2"  },
        "mean_entropy":           { id: "feat_mean_entropy",           fmt: "f3"  },
        "entropy_change":         { id: "feat_entropy_change",         fmt: "f4"  }
    };

    for (const key in featureMap) {
        const config = featureMap[key];
        const val = features[key] ?? 0;
        const el = getEl(config.id);

        if (!el) continue;

        if (config.fmt === "int") {
            el.textContent = Math.round(val);
        } else if (config.fmt === "f1") {
            el.textContent = Number(val).toFixed(1);
        } else if (config.fmt === "f2") {
            el.textContent = Number(val).toFixed(2);
        } else if (config.fmt === "f3") {
            el.textContent = Number(val).toFixed(3);
        } else if (config.fmt === "f4") {
            el.textContent = Number(val).toFixed(4);
        }

        if (Number(val) > 0) {
            el.classList.add("feature-active");
        } else {
            el.classList.remove("feature-active");
        }
    }
}


// ============================================================
// EVENT LOG (PERSISTENT HISTORY)
// ============================================================

function addLog(severityTag, message, customTime) {
    const eventLog = getEl("eventLog");
    if (!eventLog) return;

    const entry = document.createElement("div");
    entry.className = "log-entry";

    const time = document.createElement("span");
    time.className = "log-time";
    time.textContent = customTime || new Date().toLocaleTimeString();

    const badge = document.createElement("span");
    badge.className = `log-badge badge-${(severityTag || "low").toLowerCase()}`;
    badge.textContent = severityTag || "INFO";

    const msgEl = document.createElement("span");
    msgEl.className = "log-msg";
    msgEl.textContent = message;

    entry.appendChild(time);
    entry.appendChild(badge);
    entry.appendChild(msgEl);

    eventLog.prepend(entry);

    while (eventLog.children.length > 50) {
        eventLog.removeChild(eventLog.lastChild);
    }
}


// ============================================================
// INITIALIZATION
// ============================================================

console.log("[RansomGuard] Starting dashboard connection...");
connectWebSocket();