# RansomGuard 🛡️ — 3 to 5 Minute Hackathon Pitch Script

---

### **[0:00 - 0:45] 1. Problem Statement & Motivation**
> *"Good morning, judges. Ransomware is one of the most devastating cyber threats facing organizations today. Traditional signature-based antivirus solutions fail when attackers alter binary obfuscation. Endpoint detection must focus on **behavior** — specifically, how ransomware interacts with the filesystem during encryption. But detecting behavioral anomalies creates a massive challenge: **How do you detect rapid file encryption without triggering false alarms during legitimate high-activity user operations like saving large backups or extracting zip files?**"*

---

### **[0:45 - 1:30] 2. The Solution & Multi-Stage Architecture**
> *"Enter **RansomGuard**. RansomGuard is an automated, real-time behavioral detection and safe containment system built on a multi-stage engineering pipeline:
> 1. **Real-time Filesystem Monitoring**: Watchdog captures filesystem events live.
> 2. **Deduplication & Windowing**: Events are deduplicated over 200ms and buffered into 5-second sliding windows with a 1-second stride.
> 3. **11-Dimensional Feature Extraction**: We measure write rates, directory traversals, rename ratios, extension modifications, and — crucially — **Shannon content entropy**.
> 4. **Hybrid Detection Engine**: We combine a Random Forest classifier with deterministic rule engines in a 70/30 weighted fusion."*

---

### **[1:30 - 2:30] 3. Benign High Activity vs. Ransomware & Live Demo**
> *"Let's look at why hybrid detection matters. Watch what happens during a benign high-activity scenario — like a user compressing logs or backing up files:
> - Write rates spike, triggering `HIGH_WRITE_RATE` and `MASS_FILE_MODIFICATION` rules.
> - But RansomGuard's final threat score stays strictly **LOW (12.35)**. Why? Because file content entropy remains normal, extension-change count is ZERO, and ML confidence stays at 0.005.
>
> Now, let's trigger our controlled ransomware-like burst simulator:
> ```bash
> python main.py demo-containment --speed slow
> ```
> Within **1.1 seconds** ($TTD_{raw}$), the feature vector captures high Shannon entropy ($>7.0$) and `.locked` extension renames.
> After 2 consecutive sliding windows (**2.19 seconds** total), RansomGuard's debounce engine confirms a **HIGH Threat Alert**."*

---

### **[2:30 - 3:30] 4. Safe Containment & Response Metrics**
> *"Upon threat confirmation, RansomGuard's **ContainmentManager** issues a safe containment signal:
> - It signals **only** our controlled attack simulator thread to halt instantly ($\approx 40\text{ ms}$ containment time $TTC$).
> - In our slow attack run, RansomGuard halted the simulator after only 6 files were affected, successfully **saving 70% of target files (14/20)**.
> - On our untouched 99-window test set, RansomGuard achieved **100% precision and 100% recall** without a single false positive."*

---

### **[3:30 - 4:30] 5. Transparent Trade-offs, Limitations & Future Scope**
> *"We believe in transparent engineering. Notice that during ultra-fast bursts ($<0.05\text{s/file}$), the 2-window debounce delay allows files to complete before the 2.15s mark. This represents a fundamental security trade-off: **false-positive resistance versus containment speed**.
>
> **Future Scope**:
> - **Canary Decoy Files**: Placing traps to enable zero-delay immediate containment.
> - **Sysmon / EDR Integration**: Process tree and API-level telemetry.
> 
> RansomGuard demonstrates how hybrid ML and rule-based behavioral scoring can stop ransomware in its tracks. Thank you!"*
