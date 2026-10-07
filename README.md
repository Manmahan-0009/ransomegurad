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

## 📜 License
MIT License. Created for educational and research purposes.
