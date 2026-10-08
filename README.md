# RansomGuard 🛡️

**Behavioral Ransomware Detection & Safe Containment System**

RansomGuard is an open-source, educational cybersecurity hackathon prototype designed to observe, analyze, detect, and safely contain ransomware-like filesystem behavior in real time.

> ⚠️ **SAFETY & RESPONSIBLE DISCLOSURE DISCLAIMER:**  
> This project contains **NO real malware, NO encryption algorithms, NO persistence mechanisms, NO privilege escalation, and NO network propagation**. All simulated file activity is strictly restricted to an isolated sandbox folder (`sandbox/demo_folder`). Safe containment is a **simulated cooperative thread halt** that strictly controls RansomGuard's internal attack simulator.

---

## 🏗️ Multi-Stage System Architecture

```text
                               ┌─────────────────────────────┐
                               │  sandbox/demo_folder        │
                               └──────────────┬──────────────┘
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    │                         │                         │
            ┌───────┴───────┐         ┌───────┴───────┐         ┌───────┴───────┐
            │    Normal     │         │    Benign     │         │  Attack Burst │
            │  Simulator    │         │  Simulator    │         │   Simulator   │
            └───────┬───────┘         └───────┬───────┘         └───────┬───────┘
                    │                         │                         │
                    └─────────────────────────┼─────────────────────────┘
                                              │
                                   ┌──────────┴──────────┐
                                   │ Watchdog Observer   │
                                   └──────────┬──────────┘
                                              │ StructuredEvent
                                   ┌──────────┴──────────┐
                                   │     EventQueue      │
                                   └──────────┬──────────┘
                                              │
                                   ┌──────────┴──────────┐
                                   │ Deduplicator (200ms)│
                                   └──────────┬──────────┘
                                              │
                                   ┌──────────┴──────────┐
                                   │  5s Sliding Window  │
                                   │   (1s Stride)       │
                                   └──────────┬──────────┘
                                              │
                                   ┌──────────┴──────────┐
                                   │ 11-Feature Extractor│
                                   └──────────┬──────────┘
                                              │
                     ┌────────────────────────┴────────────────────────┐
                     │                                                 │
          ┌──────────┴──────────┐                           ┌──────────┴──────────┐
          │    Random Forest    │                           │     Rule Engine     │
          │     Model (v2)      │                           │  (6 Threshold Rules)│
          └──────────┬──────────┘                           └──────────┬──────────┘
                     │ ML Prob                                         │ Rule Score
                     └────────────────────────┬────────────────────────┘
                                              │ (70% ML / 30% Rules)
                                   ┌──────────┴──────────┐
                                   │  Hybrid Threat Score│
                                   └──────────┬──────────┘
                                              │
                                   ┌──────────┴──────────┐
                                   │  Debounce Engine    │
                                   │ (2-Window Confirm)  │
                                   └──────────┬──────────┘
                                              │
                                   ┌──────────┴──────────┐
                                   │ CONFIRMED DETECTION │
                                   └──────────┬──────────┘
                                              │
                     ┌────────────────────────┴────────────────────────┐
                     │                                                 │
          ┌──────────┴──────────┐                           ┌──────────┴──────────┐
          │ WebSocket Broadcast │                           │ ContainmentManager  │
          │  to Live Dashboard  │                           │(Safe Simulator Stop)│
          └─────────────────────┘                           └─────────────────────┘
```

---

## 📊 11 Canonical Behavioral Features Explained

RansomGuard extracts 11 behavioral features per 5-second sliding window:

1. **`files_created`**: Number of new files created. High during benign downloads/extracts, low during purely in-place ransomware encryption.
2. **`files_modified`**: Number of existing files written to. High in both benign bulk editing and ransomware encryption.
3. **`files_deleted`**: Number of files deleted. Indicates destructive wiper behavior.
4. **`files_renamed`**: Number of file rename operations. Elevated during mass extensions changes.
5. **`writes_per_second`**: Write operation frequency. Captures high-rate operational bursts.
6. **`unique_extensions`**: Number of distinct file extensions observed.
7. **`unique_directories`**: Number of distinct directory paths traversed. Indicates lateral directory scanning.
8. **`extension_change_count`**: **Primary Ransomware Indicator.** Counts files renamed to `.locked` / `.crypto` / `.ransom`.
9. **`rename_ratio`**: Ratio of renamed files to total affected files ($\frac{\text{files\_renamed}}{\text{total\_files}}$).
10. **`mean_entropy`**: **Primary Encryption Indicator.** Average Shannon entropy (bits/byte) of written content ($[0.0, 8.0]$ scale). Encrypted content yields entropy $\ge 6.8$.
11. **`entropy_change`**: Relative increase in Shannon entropy compared to pre-operation file state.

> **Why No Single Feature Alone Proves Ransomware:**  
> High write rates occur during benign file copies. High file creation occurs during ZIP extraction. Extension changes occur during file renaming. Only the **hybrid fusion** of high Shannon entropy ($>6.8$), mass extension changes, and ML pattern matching reliably isolates ransomware encryption without false-positive alarms on benign operations.

---

## ⚙️ Hybrid ML & Rule Detection Engine

- **Random Forest Model (v2)**: Trained exclusively on `train.csv` (18 runs / 285 windows). Evaluates 11-dimensional behavioral vectors. Threshold set to `0.20`.
- **Rule Engine**: Evaluates 6 deterministic behavioral rules (`HIGH_WRITE_RATE`, `MASS_FILE_MODIFICATION`, `HIGH_ENTROPY`, `ENTROPY_INCREASE`, `EXTENSION_CHANGES`, `HIGH_RENAME_ACTIVITY`).
- **Hybrid Fusion**: $\text{Threat Score} = (0.70 \times \text{ML Prob} \times 100) + (0.30 \times \text{Rule Score})$.
- **Debounce Engine**: Requires **2 consecutive sliding windows** with raw severity `HIGH` or `CRITICAL` before triggering a **CONFIRMED ALERT** (or immediate bypass if single-window score $\ge 85.0$).

---

## 🛡️ Safe Simulated Containment Architecture

When a debounced **CONFIRMED ALERT** triggers:
1. `ContainmentManager` receives the alert notification.
2. `SimulatorController` issues a cooperative `stop_event.set()` signal.
3. The RansomGuard attack simulator checks `stop_event.is_set()` before performing its next file write/rename and **halts immediately** ($\approx 40\text{ ms}$ latency).
4. Detailed response metrics ($TTD_{raw}, TTD_{confirmed}, TTC$, files affected before detection vs. files protected) are logged to `results/containment/`.

---

## 🚀 Quick Start & Presentation Demo Command

### 1. Setup Environment
```bash
git clone https://github.com/Manmahan-0009/ransomguard.git
cd ransomguard
python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py reset
```

### 2. Launch FastAPI Backend & Dashboard
```bash
python main.py serve
```
Open your browser at `http://127.0.0.1:8000` to access the live dashboard.

### 3. Run Reproducible One-Command Containment Demo
In a separate terminal:
```bash
python main.py demo-containment --speed slow --seed 42
```
*Output*: Resets sandbox, starts Watchdog monitoring, launches attack simulator, detects threat within 1.1s, confirms threat at 2.19s, fires safe containment, halts simulator, and prints full timing & file protection metrics!

---

## 📈 Audited Experimental Results Summary

### 1. Model Verification (Untouched Test Set — 99 Windows)
- **Accuracy**: 1.0000 (100%)
- **Precision**: 1.0000 (100%)
- **Recall**: 1.0000 (100%)
- **F1 Score**: 1.0000 (100%)
- **ROC-AUC**: 1.0000 (100%)

> *Performance Statement*: On the controlled synthetic held-out test set, RansomGuard achieved 100% precision and recall.

### 2. Live Validation Baseline
- **NORMAL**: Max threat score `0.35` (`LOW`), 0 false alerts.
- **BENIGN (High-Activity Burst)**: Max threat score `12.35` (`LOW`), 0 false alerts. (Rules `HIGH_WRITE_RATE` and `MASS_FILE_MODIFICATION` trigger, but score remains LOW due to normal entropy and 0.005 ML probability).
- **ATTACK**: Max threat score `79.00` (`HIGH`), debounced confirmed alert triggered.

### 3. Response Latencies & Protection Metrics

| Metric | Slow Attack (0.4s/file) | Medium Attack (0.1s/file) | Fast Attack (0.02s/file) |
| :--- | :--- | :--- | :--- |
| **$TTD_{raw}$** | **1.104s** | **1.085s** | **1.074s** |
| **$TTD_{confirmed}$** | **2.190s** | **2.148s** | **2.148s** |
| **$TTC$ (Containment Time)** | **0.040s** | **< 0.001s** | **< 0.001s** |
| **Files Affected** | **6 / 20** | 19 / 20 | 19 / 20 |
| **Files Protected** | **14 / 20 (70.0%)** | 1 / 20 (5.0%) | 1 / 20 (5.0%) |

---

## ⚖️ Trade-off Explanation: False-Positive Safety vs. Containment Speed

- **Slow Attack**: RansomGuard detects and confirms threat within 2.19s, halting the attack after only 6 files are affected and saving **70% of candidate files** (14/20).
- **Medium / Fast Attack**: The detector identifies abnormal behavior in **1.08s** ($TTD_{raw}$). However, the 2-window confirmation delay requires **2.15s** ($TTD_{confirmed}$) to prevent false alarms during intense benign activity. At high burst speeds ($<0.05\text{s/file}$), the controlled attack burst completes candidate files before the 2.15s confirmation mark.

---

## 🎯 MITRE ATT&CK Contextual Mapping

| Technique ID | Technique Name | RansomGuard Simulation Mapping |
| :--- | :--- | :--- |
| **T1486** | Data Encrypted for Impact | Simulated via pseudo-random high-entropy byte overwrites + `.locked` extension renaming. |
| **T1083** | File and Directory Discovery | Simulated via recursive directory traversals in normal/benign workloads. |
| **T1074** | Data Staged | Simulated via benign temporary file creations and log compression tasks. |

---

## ⚠️ Explicit System Limitations

1. **Controlled Environment**: Evaluated strictly inside an isolated sandbox directory (`sandbox/demo_folder`).
2. **Confirmation Latency Trade-off**: The 2-window (2.0s) debounce delay eliminates benign false alarms, but allows high-speed bursts to complete prior to confirmation.
3. **Synthetic Behavior**: Evaluates filesystem behavior simulation, not raw malware binaries.
4. **No Arbitrary Process Killing**: Safe containment halts only RansomGuard's internal attack simulator thread.
5. **Filesystem Telemetry Only**: Does not monitor API hooks, memory signatures, or process trees.

---

## 🔮 Future Work & Roadmap

- **Canary Files**: Decoy files placed in monitored directories to trigger zero-delay immediate containment.
- **Process & EDR Telemetry**: Integration with Windows Event Logs / Sysmon / API hooking.
- **Adaptive Confirmation Policy**: Dynamic window confirmation based on combined ML confidence and high-entropy extension changes.
- **Enterprise SOAR/SIEM Integration**: Syslog / CEF alert forwarding.

---

## 🌐 Phase 8 — Multi-Endpoint Agent Architecture

RansomGuard v3 introduces an agent-server architecture allowing distributed monitoring across multiple endpoints/VMs simultaneously from a central dashboard.

```text
SINGLE-ENDPOINT V2:
  Watcher ──> Detector ──> Backend / Dashboard

MULTI-ENDPOINT V3:
  Endpoint A (TEST-VM-01) ─┐
       Local Detection      │
  Endpoint B (TEST-VM-02) ──┼──> Central FastAPI Server ──> SQLite DB ──> Central Dashboard
       Local Detection      │       (Device Registry)     (ransomguard_central.db)
  Endpoint C (TEST-VM-03) ─┘
       Local Detection
```

### Key Architectural Properties
1. **Local Endpoint Inference**: Each agent runs local 11-feature extraction, local Random Forest ML, local rules, and local debounce. Raw filesystem events are never sent across the network.
2. **Periodic Heartbeats**: Agents send POST `/agents/heartbeat` every 10s. Central server marks devices `ONLINE` (last heartbeat $\le 30$s ago) or `OFFLINE` ($> 30$s ago).
3. **Device Identity**: Persistent `device_id` (`rg-<hash>`), hostname, OS, model version saved locally in `agent/device_identity.json`.
4. **Network Resilience**: Detection continues locally uninterrupted if the central server goes offline; agents automatically re-register and resume heartbeats upon reconnection.
5. **Strict Device State Isolation**: Alerts and high severity on Endpoint C do NOT modify device state or threat levels of Endpoint A or B.

### LAN Deployment Example
**Central Server (e.g. `192.168.1.10`):**
```bash
python main.py serve --host 0.0.0.0 --port 8000
```

**Remote Endpoint Agent:**
```bash
python main.py agent --server http://192.168.1.10:8000 --device-name TEST-VM-01
```

### Security Authentication Configuration

RansomGuard requires authentication Bearer tokens for all agent endpoints (`POST /agents/*`).

Set `RANSOMGUARD_AGENT_TOKEN` in your environment:

**Linux / macOS:**
```bash
export RANSOMGUARD_AGENT_TOKEN="your-secure-agent-token-here"
```

**Windows PowerShell:**
```powershell
$env:RANSOMGUARD_AGENT_TOKEN="your-secure-agent-token-here"
```

For development/testing mode:
```bash
export RANSOMGUARD_ENV="development"
```

---

## 🚀 Phase 9 — Process-Aware Endpoint Telemetry

RansomGuard Phase 9 adds process attribution context to answer not just *"WHAT happened on the filesystem"*, but *"WHICH PROCESS caused the activity"*.

### Key Features & Architecture
1. **ProcessContext Layer**: Enriches telemetry without altering the 11 canonical filesystem features.
2. **Attribution Confidence Levels**:
   - `DIRECT`: Exact PID/process context from controlled simulator or OS event provenance.
   - `CORRELATED_HIGH`: Process active in background modifying monitored paths.
   - `CORRELATED_LOW`: Process active in background during sliding window.
   - `UNKNOWN`: Default when PID attribution cannot be verified.
3. **Incident Episode Deduplication**: Converts continuous attack bursts into a single security incident episode (`OPEN` $\rightarrow$ `UPDATED` $\rightarrow$ `CLOSED`) with peak score, peak severity, window count, and triggered rules union.
4. **Lightweight Process Cache**: Refreshed periodically (default `1.5s`) using user-space `psutil` without high CPU overhead or unsafe kernel drivers.
5. **Privacy & Security**: Command line parameters disabled by default (`PROCESS_COMMAND_LINE_ENABLED=false`). No environment variables or file contents transmitted.

### Phase 9 Process Validation Results
Automated validation artifact (`results/process_telemetry_validation_v3_1.json`):
- **Endpoints**: 3 (`TEST-VM-01`, `TEST-VM-02`, `TEST-VM-03`)
- **Attribution Accuracy**: `100% DIRECT` for controlled workloads
- **Incident Episode Count**: `1` (Continuous attack burst deduplicated into 1 incident episode)
- **Performance Overhead**: `< 0.1% CPU`, `< 5MB RSS RAM`, `< 3ms` process cache refresh latency
- **Stage 3 & Model Verification**: `PASS`

---

## 🐥 Phase 10 — Canary / Decoy File Early-Warning Protection

RansomGuard Phase 10 introduces harmless, monitored decoy files ("canaries") to provide early-warning detection when ransomware-like activity interacts with decoy files.

### 💡 What is a Canary File & How Does It Work?
- **Definition**: Harmless synthetic placeholder files (`Financial_Records_2026.xlsx`, `Employee_Backup.docx`, `Customer_Archive.csv`, `Project_Backup.zip`, `Report_Q4_2026.pdf`) placed in monitored directories that normal users rarely modify.
- **Why Use Canaries?**: Fast ransomware attacks can affect files before a standard 2-window debounce detector confirms an alert. When a canary file is touched AND strong behavioral signals agree, RansomGuard raises a high-confidence early-confirmation alert (`CANARY_ASSISTED`).
- **Difference from ML Detection**: Canary signals sit *above* the ML detector as a separate runtime security evidence layer. The canonical 11-feature ML schema and Random Forest model (`rf_v2`) remain 100% unmodified.

### ⏱️ Authoritative Timing Definitions & Harness Reconciliation

To ensure mathematical precision across all policy evaluations, RansomGuard enforces identical, authoritative timing definitions:

- **`attack_start_time`**: Timestamp of the 1st successful ground-truth ransomware operation (`gt_ops[0]["operation_time"]`).
- **`raw_detection_time`**: Timestamp of the 1st 5-second sliding window crossing raw ML/rule severity thresholds (`HIGH` or `CRITICAL`).
- **`standard_confirmed_time`**: Timestamp of the 1st confirmed alert produced by standard 2-window debounce (`confirmation_source == "STANDARD_DEBOUNCE"`).
- **`canary_event_time`**: Timestamp of the 1st valid destructive canary event (`MODIFIED`, `RENAMED`, `DELETED`, `EXTENSION_CHANGED`).
- **`canary_confirmed_time`**: Timestamp of the 1st canary-assisted early confirmed alert (`confirmation_source == "CANARY_ASSISTED"`).
- **`containment_complete_time`**: Timestamp when safe cooperative attack simulator stop is verified.

> **Harness Reconciliation Rationale:**  
> Previous v2/v3 baseline experiments measured $TTD_{raw} \approx 1.087\text{s}$ and $TTD_{confirmed} \approx 2.156\text{s}$ relative to `gt_ops[0]["operation_time"]`. Initial Phase 10 harness iterations measured elapsed wall-clock time starting prior to synchronous simulation launch, which inadvertently included thread setup delay, pre-operation file preparation, and sleep intervals between target writes. The Phase 10 harness now enforces real-time concurrent agent detection and calculates $TTD$ strictly relative to `gt_ops[0]["operation_time"]`.

### 🛡️ Safety & Policy Rules
1. **Canary Event Alone Is NOT Ransomware**: Modifying a canary file without behavioral evidence (`CANARY_ONLY` mode) logs the event and elevates threat severity to `MEDIUM`, but does **NOT** trigger automatic containment or confirmed alerts.
2. **Early-Confirmation Policy (`CANARY_ASSISTED`)**: Requires:
   - Destructive canary event (`MODIFIED`, `RENAMED`, `DELETED`, `EXTENSION_CHANGED`)
   - RF Threat Probability $\ge$ candidate threshold (e.g. `0.45`)
   - At least ONE behavioral ransomware indicator (`extension_changes >= 1`, `mean_entropy >= 6.0`, `HIGH_ENTROPY` rule, or `EXTENSION_CHANGES` rule).
3. **Path Safety & Strict Isolation**: Canaries are restricted to approved sandbox/monitored roots (`.ransomguard_canaries/`). Path traversal (`..`) is strictly blocked.
4. **Sub-Millisecond Processing Overhead**: Canary event lookup uses $O(1)$ path mapping and SHA-256 hash checks with **sub-millisecond measured processing overhead** ($< 0.05\text{ms}$ lookup, $< 0.35\text{ms}$ verification).

### 🛠️ CLI Management Commands
```bash
# Create canary decoy files
python main.py canary-create --count 5

# Check canary integrity status
python main.py canary-status

# Reset and recreate canary files safely
python main.py canary-reset
```

### Phase 10 Validation Artifacts
- **Validation Summary**: [canary_validation_v4.json](file:///d:/KLE/freesome/ransomguard/results/canary_validation_v4.json)
- **Authoritative Policy Comparison**: [canary_policy_comparison_v4_1.json](file:///d:/KLE/freesome/ransomguard/results/canary_policy_comparison_v4_1.json)
- **Executive Summary Table**: [canary_summary_v4_1.json](file:///d:/KLE/freesome/ransomguard/results/canary_summary_v4_1.json)
- **Performance Overhead Benchmark**: [canary_performance_v4.json](file:///d:/KLE/freesome/ransomguard/results/canary_performance_v4.json)

---

## 📜 License
MIT License. Created for educational and research purposes.


