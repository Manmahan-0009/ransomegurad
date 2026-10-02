# RansomGuard 🛡️

**Stage 1 — Safe Filesystem Simulation & Monitoring**  
**Stage 2 — Event Processing & Behavioral Feature Extraction**

RansomGuard is an open-source, educational cybersecurity hackathon prototype designed to observe, analyze, and detect ransomware-like behavior on local filesystems.

> ⚠️ **SAFETY NOTE:** This project contains **NO real malware, NO encryption algorithms, NO persistence mechanisms, NO privilege escalation, and NO network propagation**. All simulated file activity is strictly restricted to an isolated sandbox folder (`sandbox/demo_folder`).

---

## 🏗️ Architecture Pipeline

### Stage 1 Pipeline (Raw Monitoring)
```text
Normal / Attack-like Simulator → sandbox/demo_folder → Watchdog Observer → Console Log
```

### Stage 2 Pipeline (Behavioral Feature Extraction Engine)
```text
Watchdog Observer 
       ↓
StructuredEvent (event_schema.py)
       ↓
EventQueue (event_queue.py)
       ↓
Deduplication (deduplicator.py, 200ms window)
       ↓
5-second Sliding Window / 1-second Stride (sliding_window.py)
       ↓
Shared Feature Extractor (extractor.py & entropy.py)
       ↓
11-Dimensional Feature Vector printed every second
```

---

## 🎯 Stage 2 Core Concepts Explained

1. **Structured Event (`StructuredEvent`)**: Converts raw OS filesystem notifications into standard dictionary records (`event_time`, `event_type`, `src_path`, `dest_path`, `extension`, `file_size`).
2. **Event Queue (`EventQueue`)**: A non-blocking `queue.Queue` buffer ensuring the Watchdog callback thread returns instantly without being delayed by entropy calculations.
3. **Deduplication (`EventDeduplicator`)**: Filters out repetitive OS modification events emitted within a 200ms burst while preserving critical creation, deletion, and rename sequences.
4. **Sliding Window (`SlidingWindowBuffer`)**: Maintains active events from the preceding 5 seconds and advances every 1 second (stride).
5. **Shannon Entropy (`calculate_file_entropy`)**: Measures byte-level randomness (0.0 to 8.0 bits/byte). Plaintext files typically measure 3.5–5.0; encrypted data measures ~7.9+.
6. **Feature Extractor (`extract_features()`)**: A single, unified function that calculates an 11-dimensional behavioral feature vector from windowed events.

---

## 📊 Feature Vector Definition (`feature_schema_v1.json`)

| Feature Name | Type | Description |
| :--- | :--- | :--- |
| `files_created` | Integer | Count of file creation events in 5s window |
| `files_modified` | Integer | Count of file modification events in 5s window |
| `files_deleted` | Integer | Count of file deletion events in 5s window |
| `files_renamed` | Integer | Count of file rename (`MOVE`) events in 5s window |
| `writes_per_second` | Float | `(files_created + files_modified) / 5.0` |
| `unique_extensions` | Integer | Count of distinct file extensions touched in window |
| `unique_directories` | Integer | Count of distinct parent directories touched in window |
| `extension_change_count` | Integer | Count of renames where source extension != destination extension |
| `rename_ratio` | Float | `files_renamed / total_events` in window |
| `mean_entropy` | Float | Average Shannon entropy (0.0 to 8.0) of created/modified files |
| `entropy_change` | Float | Average entropy delta comparing current file state to baseline |

---

## 📁 Project Directory Architecture

```text
ransomguard/
├── monitoring/
│   ├── __init__.py               # Monitoring package initializer
│   ├── watcher.py                # Watchdog real-time event observer
│   ├── event_schema.py           # Standardized StructuredEvent dataclass
│   ├── event_queue.py            # Non-blocking thread-safe EventQueue
│   └── deduplicator.py           # 200ms event deduplication filter
├── windowing/
│   ├── __init__.py               # Windowing package initializer
│   └── sliding_window.py         # 5-second sliding window / 1-second stride buffer
├── features/
│   ├── __init__.py               # Features package initializer
│   ├── extractor.py              # Shared 11-dimensional feature extractor
│   ├── entropy.py                # Safe Shannon entropy calculator & tracker
│   └── feature_schema_v1.json    # JSON schema defining feature vector specifications
├── simulator/
│   ├── __init__.py               # Simulator package initializer
│   ├── normal_simulator.py       # Low-frequency harmless user action simulator
│   ├── attack_simulator.py       # Safe ransomware-like behavior simulator
│   └── simulator_utils.py        # Path-safe reusable helper functions
├── utils/
│   ├── __init__.py               # Utils package initializer
│   └── sandbox_manager.py        # Single source of truth for path safety & reset logic
├── sandbox/
│   ├── templates/                # Reference template directory
│   └── demo_folder/              # Isolated demo execution directory
│       └── .gitkeep
├── stage1_selfcheck.py           # Stage 1 static diagnostic tool
├── stage2_selfcheck.py           # Stage 2 static diagnostic tool
├── reset_sandbox.py              # Root reset wrapper script
├── requirements.txt              # Project dependencies (watchdog)
├── README.md                     # Documentation & manual test instructions
├── main.py                       # Main CLI Control Launcher
└── .gitignore                    # Git exclusion rules
```

---

## 🚀 Setup Instructions (Kali Linux / Linux / macOS / Windows)

```bash
cd ransomguard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 main.py reset
```

---

## 🧪 Stage 2 Manual Testing Procedure (Two-Terminal Setup)

### Step 1: Start Live Feature Monitor (Terminal 1)
Open **Terminal 1** and start the live feature monitor:
```bash
python main.py features
```
*Console Header:*
```text
==================================================
     RANSOMGUARD LIVE FEATURE MONITOR ACTIVE      
 Target Directory: /path/to/ransomguard/sandbox/demo_folder
 Window: 5.0s | Stride: 1.0s | Dedupe: 200ms
 Press Ctrl+C to terminate monitor.
==================================================
```

---

### Step 2: Run Normal Simulation (Terminal 2)
In **Terminal 2**, run:
```bash
python main.py normal --duration 15 --seed 42
```

**Observed Output in Terminal 1 (Baseline Low-Activity Features):**
```text
[10:45:05] [FEATURE WINDOW]
  files_created            : 1
  files_modified           : 1
  files_deleted            : 0
  files_renamed            : 0
  writes_per_second        : 0.4000
  unique_extensions        : 1
  unique_directories       : 1
  extension_change_count   : 0
  rename_ratio             : 0.0000
  mean_entropy             : 4.1250
  entropy_change           : 0.0000
```

---

### Step 3: Run Ransomware-like Attack Simulation (Terminal 2)
In **Terminal 2**, reset and launch the attack burst:
```bash
python main.py reset
python main.py attack --speed medium --seed 42
```

**Observed Output in Terminal 1 (High-Activity Burst Features):**
```text
[10:46:12] [FEATURE WINDOW]
  files_created            : 0
  files_modified           : 14
  files_deleted            : 0
  files_renamed            : 14
  writes_per_second        : 2.8000
  unique_extensions        : 3
  unique_directories       : 2
  extension_change_count   : 14
  rename_ratio             : 0.5000
  mean_entropy             : 7.9420
  entropy_change           : 3.8170
```

> **Notice the clear contrast:**
> - **Attack Burst**: High `writes_per_second` (2.8+), high `extension_change_count` (14), high `rename_ratio` (0.50), and high `mean_entropy` (~7.94 bits/byte).
> - **Normal Activity**: Low event count, zero extension changes, low entropy.

---

## 📋 Stage 2 Verification Checklist

- [ ] Stage 1 commands (`reset`, `watch`, `normal`, `attack`) continue working without issues.
- [ ] `main.py features` runs without errors.
- [ ] Structured events contain relative paths, event types, extensions, and file sizes.
- [ ] Watchdog callbacks push events to `EventQueue` without blocking.
- [ ] Deduplicator filters repetitive `modified` events within 200ms.
- [ ] Sliding window maintains events from the previous 5 seconds and updates every 1 second.
- [ ] `extract_features()` produces an 11-dimensional feature vector matching `feature_schema_v1.json`.
- [ ] Shannon entropy accurately calculates file randomness (0.0 to 8.0).
- [ ] No Machine Learning classifiers or detection scores added yet.
