// ============================================================
// RANSOMGUARD REAL-TIME DASHBOARD
// ============================================================

console.log("[RansomGuard] app.js loaded");

// Global error handling for browser console diagnostics
window.onerror = function (message, source, lineno, colno, error) {
    console.error("[GLOBAL JS ERROR]", {
        message: message,
        source: source,
        lineno: lineno,
        colno: colno,
        error: error
    });
};

window.addEventListener("unhandledrejection", function (event) {
    console.error("[UNHANDLED PROMISE]", event.reason);
});

let socket = null;
let reconnectTimer = null;
let messageCount = 0;


// ============================================================
// SAFE DOM HELPERS (Prevents generic script errors on missing elements)
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

    console.log("[WS] Target URL:", wsUrl);

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
        setText("eventIndicator", "LIVE");

        addLog("WebSocket connected. Live telemetry active.");

        // Heartbeat / initiation message
        try {
            socket.send("PING");
        } catch (e) {
            console.warn("[WS] Send PING failed:", e);
        }
    };

    socket.onmessage = function (event) {
        messageCount++;
        console.log(`[WS] Raw message #${messageCount}:`, event.data);

        try {
            const result = JSON.parse(event.data);
            console.log("[WS] Parsed payload:", result);
            updateDashboard(result);
        } catch (error) {
            console.error("[WS] Error processing message:", error);
        }
    };

    socket.onclose = function (event) {
        console.warn(`[WS] Connection closed (code ${event.code}, reason: ${event.reason || "none"})`);

        setText("connectionStatus", "RECONNECTING...");
        setText("eventIndicator", "OFFLINE");

        addLog("WebSocket disconnected. Attempting reconnect...");
        scheduleReconnect();
    };

    socket.onerror = function (error) {
        console.error("[WS] Socket error occurred:", error);
    };
}


// ============================================================
// SAFE RECONNECT LOGIC
// ============================================================

function scheduleReconnect() {
    if (reconnectTimer !== null) {
        return;
    }

    reconnectTimer = setTimeout(function () {
        reconnectTimer = null;
        connectWebSocket();
    }, 2000);
}


// ============================================================
// UPDATE DASHBOARD
// ============================================================

function updateDashboard(result) {
    if (!result) return;

    // THREAT SCORE
    const score = Number(result.threat_score) || 0;
    setText("threatScore", score.toFixed(1));

    // SEVERITY
    const currentSeverity = result.severity || "LOW";
    setText("severity", `Severity: ${currentSeverity}`);

    // PREDICTION
    const currentPrediction = result.prediction || "UNKNOWN";
    setText("prediction", currentPrediction);

    // ML PROBABILITIES
    if (result.ml) {
        const threatProb = Number(result.ml.threat_probability) || 0;
        const benignProb = Number(result.ml.benign_probability) || 0;
        setText("threatProbability", `${(threatProb * 100).toFixed(1)}%`);
        setText("benignProbability", `${(benignProb * 100).toFixed(1)}%`);
    }

    // RULES
    if (result.rules) {
        const ruleScoreVal = Number(result.rules.rule_score) || 0;
        const rulesTriggeredVal = Number(result.rules.rules_triggered) || 0;

        setText("ruleScore", ruleScoreVal);
        setText("rulesTriggered", rulesTriggeredVal);
        setText("ruleCount", `${rulesTriggeredVal} RULE${rulesTriggeredVal === 1 ? "" : "S"}`);

        updateRules(result.rules.triggered_rules || []);
    }

    // THREAT STATUS & ALERT CARD
    if (currentPrediction === "THREAT" || currentSeverity === "HIGH" || currentSeverity === "CRITICAL") {
        setText("threatStatus", "THREAT DETECTED");
        setText("alertIcon", "🚨");
        setText("alertTitle", "Ransomware-like Activity Detected");
        setText("alertMessage", "Behavioral indicators have exceeded the detection threshold.");
        setText("eventIndicator", "THREAT");
    } else {
        setText("threatStatus", "NO ACTIVE THREAT");
        setText("alertIcon", "🟢");
        setText("alertTitle", "System Monitoring");
        setText("alertMessage", "Telemetry received. No active ransomware-like behavior detected.");
        setText("eventIndicator", "LIVE");
    }

    // FEATURES
    const features = result.features || {};
    updateFeatures(features);

    // EVENT LOG
    const timestampStr = result.timestamp ? new Date(result.timestamp).toLocaleTimeString() : null;
    addLog(`${currentPrediction} | Score: ${score.toFixed(1)} | Severity: ${currentSeverity}`, timestampStr);
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
        empty.textContent = "No rules triggered.";
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
        points.textContent = `+${rule.points ?? 0}`;

        ruleElement.appendChild(ruleName);
        ruleElement.appendChild(description);
        ruleElement.appendChild(points);

        rulesList.appendChild(ruleElement);
    });
}


// ============================================================
// UPDATE FEATURES DISPLAY
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
// EVENT LOG
// ============================================================

function addLog(message, customTime) {
    const eventLog = getEl("eventLog");
    if (!eventLog) return;

    const entry = document.createElement("div");
    entry.className = "log-entry";

    const time = document.createElement("span");
    time.className = "log-time";
    time.textContent = customTime || new Date().toLocaleTimeString();

    const messageElement = document.createElement("span");
    messageElement.textContent = message;

    entry.appendChild(time);
    entry.appendChild(messageElement);

    eventLog.prepend(entry);

    while (eventLog.children.length > 30) {
        eventLog.removeChild(eventLog.lastChild);
    }
}


// ============================================================
// INITIALIZATION
// ============================================================

console.log("[RansomGuard] Starting dashboard connection...");
connectWebSocket();