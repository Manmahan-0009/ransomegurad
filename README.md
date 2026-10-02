# RansomGuard 🛡️

**Stage 1 — Safe Filesystem Simulation & Monitoring**  
**Stage 2 — Event Processing & Behavioral Feature Extraction**  
**Stage 3 — Automated Labeled Dataset Generation & Split Validation**

RansomGuard is an open-source, educational cybersecurity hackathon prototype designed to observe, analyze, and detect ransomware-like behavior on local filesystems.

> ⚠️ **SAFETY NOTE:** This project contains **NO real malware, NO encryption algorithms, NO persistence mechanisms, NO privilege escalation, and NO network propagation**. All simulated file activity is strictly restricted to an isolated sandbox folder (`sandbox/demo_folder`).

---

## 🏗️ Multi-Stage Architecture Pipeline

```text
STAGE 1: SIMULATION & RAW MONITORING
Normal / Benign / Attack-like Simulators → sandbox/demo_folder → Watchdog Observer

STAGE 2: FEATURE EXTRACTION ENGINE
Watchdog Events → StructuredEvent → EventQueue → Deduplication (200ms) → 5s Sliding Window / 1s Stride → extract_features()

STAGE 3: DATASET GENERATION & SPLITTING PIPELINE
Simulator Run (Pre-Obs → Sim → Post-Obs) → Raw Event JSONL + Metadata + Ground-Truth Ops → Replay through Stage 2 Pipeline → Timestamp-Based Labeling [window_start, window_end) → dataset_v1.csv → Grouped Split by run_id (60/20/20) → train.csv / validation.csv / test.csv
```

---

## 🎯 Stage 3 Rationale & Core Concepts

### 1. Observation Lifecycle vs. Simulator Duration
A critical requirement in Stage 3 is decoupling **simulator execution duration** from **monitoring observation duration**.
If monitoring stops the exact millisecond a rapid simulator finishes (e.g. an attack burst completing in 0.8 seconds), total recorded time is shorter than the 5-second feature window, resulting in 0 generated feature rows!

**Standardized Observation Lifecycle:**
- **0 – 3 sec (`PRE_OBSERVATION_SECONDS = 3.0`)**: Watchdog monitors baseline pre-activity state.
- **3 – ~6 sec**: Simulator executes (normal, benign, or attack-like operations). Attack simulator records ground-truth timestamps immediately prior to each operation.
- **~6 – 11 sec (`POST_OBSERVATION_SECONDS = 5.0`)**: Watchdog continues monitoring after simulator completes.

This observation window guarantees multiple valid 5-second sliding feature windows covering baseline, transition, attack burst, and post-attack behavior.

### 2. Why the `benign` High-Activity Class Matters
Ransomware detectors that rely solely on event counts risk learning the naive heuristic:
> *"High file activity = Ransomware"*

The `benign` simulator (`simulator/benign_simulator.py`) generates harmless, high-frequency activity (bulk file copying, backup-style saves, mass text file creation, normal renames). This teaches future ML classifiers to distinguish between **legitimate high-activity workloads** and **ransomware-like attacks** (which exhibit high entropy and `.locked` extension changes).

### 3. Why Grouped Splitting by `run_id` is Critical
In a 5-second sliding window with a 1-second stride, consecutive windows from the same simulation run overlap heavily (by 80%).
- ❌ **Naive Random Row Splitting**: Results in overlapping windows from the same run being placed into both `train.csv` and `test.csv`, causing severe **data leakage** and unrealistically high test accuracy.
- ✅ **Grouped Splitting by `run_id`**: All window rows derived from a specific `run_id` stay strictly in **ONE** split (`train.csv`, `validation.csv`, or `test.csv`), guaranteeing completely unseen test evaluations. For a 3/3/3 pilot, each split receives exactly 1 normal run, 1 benign run, and 1 attack run.

### 4. Timestamp-Based Window Labeling & Offline Entropy Parity
- `normal` runs: `label = 0` (all windows).
- `benign` runs: `label = 0` (all windows).
- `attack` runs: `label = 1` **ONLY** if at least one ground-truth attack operation timestamp occurred within the window time interval `[window_start, window_end)`.
- **Entropy Parity**: `StructuredEvent` objects store calculated Shannon entropy values live during monitoring. During offline replay, `extract_features()` reuses these persisted entropy values so entropy is never silently lost when files are renamed or deleted on disk.

---

## 📁 Project Directory Architecture

```text
ransomguard/
├── data/
│   ├── raw_events/               # Raw event JSONL logs per run
│   ├── run_metadata/             # Run JSON metadata & ground-truth attack ops
│   ├── datasets/                 # Consolidated dataset_v1.csv
│   └── splits/                   # train.csv, validation.csv, test.csv, split_manifest.json
├── training/
│   ├── __init__.py               # Training package initializer
│   ├── generate_dataset.py       # Automated dataset generator orchestrator (--fresh mode support)
│   ├── run_recorder.py           # Metadata, raw event & ground-truth recorder
│   ├── label_windows.py          # Ground-truth timestamp-based window labeler
│   ├── split_by_run.py           # Grouped stratified train/val/test splitter
│   ├── dataset_validator.py      # Comprehensive dataset sanity validator
│   ├── replay_consistency.py     # Live vs offline replay consistency validator
│   └── verify_stage3.py          # Fast non-destructive Stage 3 quick verification
├── monitoring/
│   ├── __init__.py               # Monitoring package initializer
│   ├── watcher.py                # Watchdog observer (dispatches StructuredEvent objects)
│   ├── event_schema.py           # Standardized StructuredEvent dataclass with entropy fields
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
│   ├── benign_simulator.py       # High-frequency harmless benign workload simulator
│   ├── attack_simulator.py       # Safe ransomware-like behavior simulator & ground-truth recorder
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
├── stage3_selfcheck.py           # Stage 3 static diagnostic tool
├── reset_sandbox.py              # Root reset wrapper script
├── requirements.txt              # Project dependencies (watchdog)
├── README.md                     # Documentation & manual test instructions
├── main.py                       # Main CLI Control Launcher
└── .gitignore                    # Git exclusion rules
```

---

## 🚀 Setup & Testing Instructions (Kali Linux / Linux / Windows)

### 1. Setup Environment
```bash
cd ransomguard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 main.py reset
```

---

### 2. Stage 3 Execution Steps

#### A. Run Stage 3 Static Self-Check
Verifies all Stage 3 files, imports, observation timing constants, and schema alignments statically without executing simulations:
```bash
python3 stage3_selfcheck.py
```

#### B. Generate Fresh 3/3/3 Pilot Dataset
Automates sandbox reset, observation lifecycle (3s pre-obs, simulation, 5s post-obs), raw event recording, Stage 2 feature replay, timestamp labeling, and dataset export:
```bash
python3 main.py generate-data --all --runs-per-class 3 --seed 42 --fresh
```

#### C. Perform Grouped Train/Val/Test Split
Splits `dataset_v1.csv` by `run_id` into `train.csv` (1/1/1), `validation.csv` (1/1/1), and `test.csv` (1/1/1):
```bash
python3 main.py split-data --seed 42
```

#### D. Validate Dataset & Split Consistency
Enforces strict checks (fails if 0 attack rows, 0 positive labels, missing classes, zero-window runs, or data leakage exist):
```bash
python3 main.py validate-data
```

---

### 3. Quick Stage 3 Re-Verification

Use this when Stage 3 was already generated and you only want to confirm:
- Artifacts still exist (raw events, metadata, ground-truth ops for every run)
- Dataset has not changed (SHA-256 fingerprints of dataset_v1.csv, split_manifest.json, feature_schema_v1.json)
- Labels and splits still pass all validator checks
- Replay consistency holds (1 normal, 1 benign, 1 attack run replayed from saved raw events and compared against saved dataset rows)
- Entropy values are present and non-zero
- Window timestamps are ordered and valid
- Attack operation timestamps fall within observation bounds

**No simulators or dataset regeneration are performed.** This is a read-only diagnostic.

```bash
python3 main.py verify-stage3
```

---

## 📋 Stage 3 Acceptance Checklist

- [ ] Stage 1 & 2 commands (`reset`, `watch`, `normal`, `benign`, `attack`, `features`) work cleanly.
- [ ] Observation duration is decoupled from simulation duration (3s pre-observation baseline + 5s post-observation grace period).
- [ ] Every run generates >0 feature window rows.
- [ ] `attack_simulator.py` records ground-truth attack operation timestamps immediately before actions occur.
- [ ] Raw events store persisted `entropy` and `entropy_delta` values to ensure offline replay parity.
- [ ] Replay engine uses the **EXACT** Stage 2 pipeline (`EventDeduplicator` -> `SlidingWindowBuffer` -> `extract_features()`).
- [ ] Window labels are `1` ONLY when ground-truth attack operations occur within `[window_start, window_end)`.
- [ ] `generate-data --fresh` cleanly wipes previous dataset artifacts before generating new ones.
- [ ] `split_by_run.py` splits rows strictly by `run_id` with ZERO data leakage across `train.csv`, `validation.csv`, and `test.csv` (each receiving 1 normal, 1 benign, 1 attack run for pilot).
- [ ] `validate-data` passes all sanity checks and prints explicit counts.
- [ ] `verify-stage3` passes all quick verification checks (fingerprints, artifacts, timestamps, entropy, replay, splits).
- [ ] No Machine Learning models or classifiers trained yet.
