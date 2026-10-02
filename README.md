# RansomGuard 🛡️

**Stage 1 — Safe Filesystem Simulation & Monitoring**

RansomGuard is an open-source, educational cybersecurity hackathon prototype designed to observe, analyze, and detect ransomware-like behavior on local filesystems.

> ⚠️ **SAFETY NOTE:** This project contains **NO real malware, NO encryption algorithms, NO persistence mechanisms, NO privilege escalation, and NO network propagation**. All simulated file activity is strictly restricted to an isolated sandbox folder (`sandbox/demo_folder`).

---

## 🎯 Current Stage Scope (Stage 1)

### What RansomGuard Currently Does:
- **Isolated Sandbox Management**: Resets a clean demonstration directory (`sandbox/demo_folder`) from template files (`sandbox/templates`).
- **Path-Safety Enforcement**: Every file operation strictly validates destination paths via `utils.sandbox_manager.is_safe_path()` to prevent out-of-sandbox modifications.
- **Real-Time Event Monitoring**: Uses Python `watchdog` to monitor filesystem events (`CREATE`, `MODIFY`, `MOVE`, `DELETE`) with precise timestamps.
- **Harmless Normal User Simulator**: Simulates ordinary, slow user file interactions (low-frequency edits, document creation, renames, temporary file deletions).
- **Benign Ransomware-like Behavior Simulator**: Safely mimics rapid burst file modifications, high-entropy pseudo-random content overwrites, and extension changes (`.locked`).

### What RansomGuard Deliberately Does NOT Do Yet (Planned for Future Stages):
- ❌ No Machine Learning models (Isolation Forest / Random Forest)
- ❌ No 5-second sliding window feature extraction
- ❌ No real-time process containment or file locking
- ❌ No Streamlit / FastAPI web dashboards
- ❌ No eBPF / Kernel probes
- ❌ No external network communication

---

## 📁 Project Directory Architecture

```text
ransomguard/
├── monitoring/
│   ├── __init__.py               # Monitoring package initializer
│   └── watcher.py                # Watchdog real-time event observer
├── simulator/
│   ├── __init__.py               # Simulator package initializer
│   ├── normal_simulator.py       # Simulates slow, ordinary user file actions
│   ├── attack_simulator.py       # Safely simulates ransomware-like burst file actions
│   └── simulator_utils.py        # Shared path-safe filesystem helpers
├── utils/
│   ├── __init__.py               # Utils package initializer
│   └── sandbox_manager.py        # Single source of truth for path safety & sandbox reset
├── sandbox/
│   ├── templates/                # Reference template files & subdirectories
│   └── demo_folder/              # Active simulation sandbox folder
│       └── .gitkeep
├── stage1_selfcheck.py           # Static diagnostic validation tool
├── reset_sandbox.py              # Root reset wrapper script
├── requirements.txt              # Stage 1 dependencies (watchdog)
├── README.md                     # Documentation & setup guide
├── main.py                       # CLI Control Launcher
└── .gitignore                    # Git exclusion rules
```

---

## 🚀 Setup Instructions (Kali Linux / Linux / macOS / Windows)

### 1. Copy or Clone the Project
Transfer the `ransomguard` folder to your target machine (e.g., Kali Linux VM).

```bash
cd ransomguard
```

### 2. Create and Activate Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```
*(On Windows PowerShell: `.\venv\Scripts\Activate.ps1`)*

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🧪 Manual Two-Terminal Test Procedure

### Step 1: Initialize the Sandbox
In any terminal, run:
```bash
python main.py reset
```
*Expected Output:*
```text
[SANDBOX] Reset started
[SANDBOX] Copied 25 template files
[SANDBOX] Ready
```

---

### Step 2: Start the Filesystem Observer (Terminal 1)
Open **Terminal 1** and start the Watchdog monitor:
```bash
python main.py watch
```
*Expected Output:*
```text
==================================================
      RANSOMGUARD WATCHDOG MONITOR ACTIVE        
 Target Directory: /home/kali/ransomguard/sandbox/demo_folder
 Press Ctrl+C to terminate monitor.
==================================================
```

---

### Step 3: Run Normal User Simulation (Terminal 2)
Keep **Terminal 1** running. Open **Terminal 2** and execute:
```bash
python main.py normal --duration 15 --seed 42
```

**Observed Stream in Terminal 1 (Normal Stream):**
> Events arrive **slowly** with gaps of ~2 seconds:
```text
[10:45:02] [WATCHER] MODIFY  report1.txt
[10:45:04] [WATCHER] CREATE  user_note_1_482.txt
[10:45:06] [WATCHER] MOVE    notes1.txt -> notes1_renamed.txt
[10:45:08] [WATCHER] DELETE  user_note_1_482.txt
```

---

### Step 4: Run Ransomware-like Attack Simulator (Terminal 2)
Reset the sandbox in **Terminal 2**:
```bash
python main.py reset
```

Now launch the safe ransomware-like behavior simulator in **Terminal 2**:
```bash
python main.py attack --speed medium --seed 42
```
*(Options for speed: `--speed slow`, `--speed medium`, `--speed fast`)*

**Observed Stream in Terminal 1 (Attack Burst Stream):**
> Events arrive in a **dense, rapid stream** with high modification and `.locked` extension renames:
```text
[10:46:10] [WATCHER] MODIFY  report1.txt
[10:46:10] [WATCHER] MOVE    report1.txt -> report1.txt.locked
[10:46:10] [WATCHER] MODIFY  report2.txt
[10:46:10] [WATCHER] MOVE    report2.txt -> report2.txt.locked
[10:46:11] [WATCHER] MODIFY  data1.csv
[10:46:11] [WATCHER] MOVE    data1.csv -> data1.csv.locked
...
[ATTACK-LIKE] Simulation complete
```

---

## 🛡️ Path Safety & Constraints

Every file operation passes through `utils.sandbox_manager.is_safe_path()`. If a path resolves outside `sandbox/demo_folder`, execution halts immediately with a `RuntimeError`:

```text
[FATAL PATH SAFETY ERROR] Attempted operation outside sandbox!
```

---

## 📋 Stage 1 Completion Verification Checklist

- [ ] Sandbox resets successfully
- [ ] Templates remain unchanged
- [ ] Watcher monitors only demo_folder
- [ ] Normal simulator produces low-frequency events
- [ ] Attack-like simulator produces dense events
- [ ] No operation escapes the sandbox
- [ ] Stage 1 contains no ML/dashboard/network logic
