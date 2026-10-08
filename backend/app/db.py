"""
RansomGuard Central SQLite Database Manager (backend/app/db.py)

Manages persistence for devices, telemetry windows, and alerts in data/ransomguard_central.db.
"""

import os
import json
import sqlite3
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple


def get_db_path() -> Path:
    """
    Returns the resolved Path to the SQLite database.
    Prioritizes RANSOMGUARD_DB_PATH environment variable if specified.
    If RANSOMGUARD_ENV is 'test' or 'testing', defaults to data/ransomguard_test.db unless specified.
    Otherwise defaults to production/demo database data/ransomguard_central.db.
    Safety Protection: Throws RuntimeError if RANSOMGUARD_ENV is 'test' and path resolves to production central DB.
    """
    env = os.getenv("RANSOMGUARD_ENV", "production").lower()
    custom_db = os.getenv("RANSOMGUARD_DB_PATH")

    prod_central_db = (Path(__file__).resolve().parents[2] / "data" / "ransomguard_central.db").resolve()

    if custom_db:
        db_path = Path(custom_db).resolve()
    elif env in ("test", "testing"):
        db_path = (Path(__file__).resolve().parents[2] / "data" / "ransomguard_test.db").resolve()
    else:
        db_path = prod_central_db

    # Safety Check: Test mode MUST NEVER use production central DB (Item 5)
    if env in ("test", "testing") and db_path == prod_central_db:
        raise RuntimeError("Test mode cannot use the production/demo database (data/ransomguard_central.db).")

    return db_path


def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection with dict row factory enabled."""
    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def __getattr__(name: str):
    if name == "DB_PATH":
        return get_db_path()
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


def init_db() -> None:
    """Creates database tables if they do not exist, and migrates missing columns."""
    with get_db_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                os TEXT,
                agent_version TEXT,
                model_version TEXT,
                feature_schema_version TEXT,
                registered_at REAL,
                last_seen REAL,
                status TEXT DEFAULT 'ONLINE',
                current_severity TEXT DEFAULT 'LOW',
                current_threat_score REAL DEFAULT 0.0,
                device_mode TEXT DEFAULT 'REAL'
            );

            CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                prediction TEXT,
                threat_probability REAL,
                rule_score INTEGER,
                threat_score REAL,
                severity TEXT,
                features_json TEXT,
                process_json TEXT,
                FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                last_updated_at REAL,
                closed_at REAL,
                severity TEXT NOT NULL,
                threat_score REAL NOT NULL,
                peak_score REAL DEFAULT 0.0,
                peak_severity TEXT,
                window_count INTEGER DEFAULT 1,
                current_status TEXT DEFAULT 'OPEN',
                confirmed INTEGER DEFAULT 1,
                rules_json TEXT,
                containment_status TEXT,
                primary_process_json TEXT,
                process_attribution_confidence TEXT,
                low_streak INTEGER DEFAULT 0,
                FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS process_context (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                telemetry_id INTEGER,
                alert_id TEXT,
                pid INTEGER,
                process_name TEXT,
                executable_path TEXT,
                parent_pid INTEGER,
                parent_process_name TEXT,
                username TEXT,
                attribution_confidence TEXT,
                created_at REAL,
                FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS canaries (
                canary_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_type TEXT,
                created_at REAL,
                baseline_hash TEXT,
                baseline_size INTEGER,
                baseline_entropy REAL,
                enabled INTEGER DEFAULT 1,
                last_verified_at REAL,
                FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS canary_events (
                event_id TEXT PRIMARY KEY,
                canary_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                event_type TEXT NOT NULL,
                old_path TEXT,
                new_path TEXT,
                process_json TEXT,
                attribution_confidence TEXT,
                current_threat_probability REAL,
                current_threat_score REAL,
                current_rule_score INTEGER,
                current_severity TEXT,
                FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS event_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                event_type TEXT,
                message TEXT NOT NULL,
                incident_id TEXT,
                process_name TEXT,
                pid INTEGER,
                metadata_json TEXT,
                FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()

        # Dynamic schema migration for existing SQLite DBs
        migrations = {
            "devices": ["device_mode TEXT DEFAULT 'REAL'"],
            "telemetry": ["process_json TEXT"],
            "alerts": [
                "last_updated_at REAL",
                "closed_at REAL",
                "peak_score REAL DEFAULT 0.0",
                "peak_severity TEXT",
                "window_count INTEGER DEFAULT 1",
                "current_status TEXT DEFAULT 'OPEN'",
                "primary_process_json TEXT",
                "process_attribution_confidence TEXT",
                "early_confirmation INTEGER DEFAULT 0",
                "confirmation_source TEXT DEFAULT 'STANDARD_DEBOUNCE'",
                "canary_triggered INTEGER DEFAULT 0",
                "canary_id TEXT",
                "canary_event_type TEXT",
                "low_streak INTEGER DEFAULT 0",
            ],
        }
        for table, col_defs in migrations.items():
            existing = [row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]
            for col_def in col_defs:
                col_name = col_def.split()[0]
                if col_name not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")
        conn.commit()


# Initialize database schema on module load
init_db()


class CentralDatabase:
    """
    CRUD Data Access Object for RansomGuard Central SQLite DB.
    """

    @staticmethod
    def upsert_device(device_data: Dict[str, Any]) -> Dict[str, Any]:
        hostname = device_data.get("hostname", "UNKNOWN")
        host_upper = hostname.upper()
        is_test_env = os.getenv("RANSOMGUARD_ENV", "").lower() in ("test", "testing")
        is_test_name = any(host_upper.startswith(p) for p in ("TEST-", "BENIGN-", "ATTACK-", "CANARY-TEST-"))
        device_mode = "TEST" if (is_test_env or is_test_name) else "REAL"

        with get_db_connection() as conn:
            conn.execute(
                """
                INSERT INTO devices (
                    device_id, hostname, os, agent_version, model_version,
                    feature_schema_version, registered_at, last_seen, status,
                    current_severity, current_threat_score, device_mode
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    hostname=excluded.hostname,
                    os=excluded.os,
                    agent_version=excluded.agent_version,
                    model_version=excluded.model_version,
                    feature_schema_version=excluded.feature_schema_version,
                    last_seen=excluded.last_seen,
                    status=excluded.status,
                    device_mode=excluded.device_mode
                """,
                (
                    device_data["device_id"],
                    hostname,
                    device_data.get("os", "UNKNOWN"),
                    device_data.get("agent_version", "3.1"),
                    device_data.get("model_version", "rf_v2"),
                    device_data.get("feature_schema_version", "v1"),
                    device_data.get("started_at", time.time()),
                    time.time(),
                    "ONLINE",
                    device_data.get("current_severity", "LOW"),
                    device_data.get("current_threat_score", 0.0),
                    device_mode,
                ),
            )
            conn.commit()
        return CentralDatabase.get_device(device_data["device_id"])

    @staticmethod
    def update_heartbeat(
        device_id: str,
        timestamp: float,
        current_severity: str,
        current_threat_score: float,
        last_prediction: str,
    ) -> bool:
        with get_db_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE devices
                SET last_seen = ?,
                    status = 'ONLINE',
                    current_severity = ?,
                    current_threat_score = ?
                WHERE device_id = ?
                """,
                (timestamp, current_severity, current_threat_score, device_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    @staticmethod
    def update_device_status(device_id: str, status: str) -> None:
        with get_db_connection() as conn:
            conn.execute(
                "UPDATE devices SET status = ? WHERE device_id = ?",
                (status, device_id),
            )
            conn.commit()

    @staticmethod
    def insert_telemetry(data: Dict[str, Any]) -> None:
        features_json = json.dumps(data.get("features", {}))
        proc_data = {
            "dominant_process": data.get("dominant_process"),
            "processes": data.get("processes", []),
        }
        process_json = json.dumps(proc_data)
        now_ts = data.get("timestamp", time.time())

        with get_db_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO telemetry (
                    device_id, timestamp, prediction, threat_probability,
                    rule_score, threat_score, severity, features_json, process_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["device_id"],
                    now_ts,
                    data.get("prediction", "BENIGN"),
                    data.get("threat_probability", 0.0),
                    data.get("rule_score", 0),
                    data.get("threat_score", 0.0),
                    data.get("severity", "LOW"),
                    features_json,
                    process_json,
                ),
            )
            telem_id = cursor.lastrowid
            conn.commit()

            # Insert process context record if present
            dom_proc = data.get("dominant_process")
            if dom_proc and isinstance(dom_proc, dict) and dom_proc.get("pid"):
                conn.execute(
                    """
                    INSERT INTO process_context (
                        device_id, telemetry_id, pid, process_name, executable_path,
                        parent_pid, parent_process_name, username, attribution_confidence, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        data["device_id"],
                        telem_id,
                        dom_proc.get("pid"),
                        dom_proc.get("process_name"),
                        dom_proc.get("executable_path"),
                        dom_proc.get("parent_pid"),
                        dom_proc.get("parent_process_name"),
                        dom_proc.get("username"),
                        dom_proc.get("attribution_confidence", "UNKNOWN"),
                        now_ts,
                    ),
                )
                conn.commit()

    @staticmethod
    def get_active_alert(device_id: str) -> Optional[Dict[str, Any]]:
        """Returns currently OPEN or UPDATED incident alert for device if one exists."""
        with get_db_connection() as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE device_id = ? AND current_status IN ('OPEN', 'UPDATED') ORDER BY timestamp DESC LIMIT 1",
                (device_id,),
            ).fetchone()
            return dict(row) if row else None

    @staticmethod
    def record_incident_alert(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Records or updates an incident alert episode for device (Phase 8.2 & Part 1 Fix 2).
        Single continuous episode -> 1 incident record updated over time.
        """
        device_id = data["device_id"]
        now_ts = data.get("timestamp", time.time())
        new_score = float(data.get("threat_score", 0.0))
        new_severity = str(data.get("severity", "HIGH"))
        new_rules = data.get("triggered_rules", [])
        primary_proc = data.get("primary_process")
        confidence = data.get("process_attribution_confidence", "UNKNOWN")

        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        active = CentralDatabase.get_active_alert(device_id)

        with get_db_connection() as conn:
            if active:
                alert_id = active["alert_id"]
                window_count = int(active.get("window_count") or 1) + 1
                existing_rules = json.loads(active.get("rules_json") or "[]")
                merged_rules = list(dict.fromkeys(existing_rules + new_rules))

                current_peak_score = float(active.get("peak_score") or active["threat_score"])
                peak_score = max(current_peak_score, new_score)

                curr_peak_sev = active.get("peak_severity") or active["severity"]
                if severity_rank.get(new_severity, 0) > severity_rank.get(curr_peak_sev, 0):
                    peak_severity = new_severity
                else:
                    peak_severity = curr_peak_sev

                proc_json = json.dumps(primary_proc) if primary_proc else active.get("primary_process_json")
                proc_conf = confidence if primary_proc else active.get("process_attribution_confidence", "UNKNOWN")

                conn.execute(
                    """
                    UPDATE alerts
                    SET last_updated_at = ?,
                        severity = ?,
                        threat_score = ?,
                        peak_score = ?,
                        peak_severity = ?,
                        window_count = ?,
                        current_status = 'UPDATED',
                        rules_json = ?,
                        containment_status = ?,
                        primary_process_json = ?,
                        process_attribution_confidence = ?,
                        early_confirmation = ?,
                        confirmation_source = ?,
                        canary_triggered = ?,
                        canary_id = ?,
                        canary_event_type = ?,
                        low_streak = 0
                    WHERE alert_id = ?
                    """,
                    (
                        now_ts,
                        new_severity,
                        new_score,
                        peak_score,
                        peak_severity,
                        window_count,
                        json.dumps(merged_rules),
                        data.get("containment_status", active.get("containment_status", "NONE")),
                        proc_json,
                        proc_conf,
                        1 if data.get("early_confirmation") else active.get("early_confirmation", 0),
                        data.get("confirmation_source", active.get("confirmation_source", "STANDARD_DEBOUNCE")),
                        1 if data.get("canary_triggered") else active.get("canary_triggered", 0),
                        data.get("canary_id", active.get("canary_id")),
                        data.get("canary_event_type", active.get("canary_event_type")),
                        alert_id,
                    ),
                )
                conn.execute(
                    "UPDATE devices SET current_severity = ?, current_threat_score = ? WHERE device_id = ?",
                    (new_severity, new_score, device_id),
                )
                conn.commit()
                res = dict(active)
                res["last_updated_at"] = now_ts
                res["severity"] = new_severity
                res["threat_score"] = new_score
                res["peak_score"] = peak_score
                res["peak_severity"] = peak_severity
                res["window_count"] = window_count
                res["current_status"] = "UPDATED"
                res["triggered_rules"] = merged_rules
                res["primary_process"] = primary_proc
                res["low_streak"] = 0
                return res
            else:
                alert_id = data.get("alert_id") or f"inc-{device_id}-{int(now_ts * 1000)}"
                rules_json = json.dumps(new_rules)
                proc_json = json.dumps(primary_proc) if primary_proc else None

                conn.execute(
                    """
                    INSERT INTO alerts (
                        alert_id, device_id, timestamp, last_updated_at, closed_at, severity,
                        threat_score, peak_score, peak_severity, window_count,
                        current_status, confirmed, rules_json, containment_status,
                        primary_process_json, process_attribution_confidence,
                        early_confirmation, confirmation_source, canary_triggered,
                        canary_id, canary_event_type, low_streak
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert_id,
                        device_id,
                        now_ts,
                        now_ts,
                        None,
                        new_severity,
                        new_score,
                        new_score,
                        new_severity,
                        1,
                        "OPEN",
                        1 if data.get("confirmed", True) else 0,
                        rules_json,
                        data.get("containment_status", "NONE"),
                        proc_json,
                        confidence,
                        1 if data.get("early_confirmation") else 0,
                        data.get("confirmation_source", "STANDARD_DEBOUNCE"),
                        1 if data.get("canary_triggered") else 0,
                        data.get("canary_id"),
                        data.get("canary_event_type"),
                        0,
                    ),
                )

                conn.execute(
                    "UPDATE devices SET current_severity = ?, current_threat_score = ? WHERE device_id = ?",
                    (new_severity, new_score, device_id),
                )
                conn.commit()
                data["alert_id"] = alert_id
                data["current_status"] = "OPEN"
                data["window_count"] = 1
                data["peak_score"] = new_score
                data["peak_severity"] = new_severity
                data["low_streak"] = 0
                return data

    @staticmethod
    def process_telemetry_streak(
        device_id: str,
        severity: str,
        timestamp: Optional[float] = None
    ) -> Tuple[Optional[Dict[str, Any]], bool]:
        """
        Updates persistent low_streak on device's active incident.
        Closure rule:
        - LOW / NORMAL telemetry increments low_streak by 1.
        - At low_streak == 3, the active incident is CLOSED.
        - HIGH / CRITICAL / MEDIUM severity telemetry resets low_streak to 0.
        """
        sev_upper = (severity or "LOW").upper()
        active = CentralDatabase.get_active_alert(device_id)
        if not active:
            return None, False

        alert_id = active["alert_id"]
        current_streak = int(active.get("low_streak") or 0)

        with get_db_connection() as conn:
            if sev_upper in ("LOW", "NORMAL"):
                new_streak = current_streak + 1
                if new_streak >= 3:
                    ts = timestamp or time.time()
                    conn.execute(
                        """
                        UPDATE alerts
                        SET current_status = 'CLOSED',
                            closed_at = ?,
                            low_streak = ?
                        WHERE alert_id = ?
                        """,
                        (ts, new_streak, alert_id),
                    )
                    conn.commit()
                    active["current_status"] = "CLOSED"
                    active["closed_at"] = ts
                    active["low_streak"] = new_streak
                    return active, True
                else:
                    conn.execute(
                        "UPDATE alerts SET low_streak = ? WHERE alert_id = ?",
                        (new_streak, alert_id),
                    )
                    conn.commit()
                    active["low_streak"] = new_streak
                    return active, False
            else:
                # HIGH, CRITICAL, or MEDIUM resets low_streak to 0
                conn.execute(
                    "UPDATE alerts SET low_streak = 0 WHERE alert_id = ?",
                    (alert_id,),
                )
                conn.commit()
                active["low_streak"] = 0
                return active, False

    @staticmethod
    def close_active_incident(device_id: str, timestamp: Optional[float] = None) -> bool:
        """Closes any active OPEN/UPDATED incident for device when threat subsides."""
        ts = timestamp or time.time()
        with get_db_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE alerts
                SET current_status = 'CLOSED',
                    closed_at = ?
                WHERE device_id = ? AND current_status IN ('OPEN', 'UPDATED')
                """,
                (ts, device_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    @staticmethod
    def get_devices() -> List[Dict[str, Any]]:
        is_test_env = os.getenv("RANSOMGUARD_ENV", "").lower() in ("test", "testing")
        with get_db_connection() as conn:
            if is_test_env:
                rows = conn.execute("SELECT * FROM devices ORDER BY hostname ASC").fetchall()
            else:
                rows = conn.execute("SELECT * FROM devices WHERE COALESCE(device_mode, 'REAL') != 'TEST' ORDER BY hostname ASC").fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def get_device(device_id: str) -> Optional[Dict[str, Any]]:
        with get_db_connection() as conn:
            row = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            return dict(row) if row else None

    @staticmethod
    def delete_device(device_id: str) -> bool:
        with get_db_connection() as conn:
            cursor = conn.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
            conn.commit()
            return cursor.rowcount > 0

    @staticmethod
    def reset_demo_database() -> Dict[str, int]:
        """
        Clears all runtime tables from the DEMO database (data/ransomguard_central.db) ONLY.
        Does NOT touch datasets, trained models, templates, or code.
        """
        prod_db = (Path(__file__).resolve().parents[2] / "data" / "ransomguard_central.db").resolve()
        if not prod_db.exists():
            return {}

        counts = {}
        with sqlite3.connect(str(prod_db)) as conn:
            for table in ["devices", "alerts", "telemetry", "event_logs", "process_context", "canaries", "canary_events"]:
                try:
                    cur = conn.execute(f"DELETE FROM {table}")
                    counts[table] = cur.rowcount
                except Exception:
                    counts[table] = 0
            conn.commit()
        return counts

    @staticmethod
    def get_telemetry(device_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        with get_db_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM telemetry WHERE device_id = ? ORDER BY timestamp DESC LIMIT ?",
                (device_id, limit),
            ).fetchall()
            res = []
            for r in rows:
                item = dict(r)
                item["features"] = json.loads(item.get("features_json") or "{}")
                proc_info = json.loads(item.get("process_json") or "{}")
                item["dominant_process"] = proc_info.get("dominant_process")
                item["processes"] = proc_info.get("processes", [])
                res.append(item)
            return res

    @staticmethod
    def get_alerts(device_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        with get_db_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE device_id = ? ORDER BY timestamp DESC LIMIT ?",
                (device_id, limit),
            ).fetchall()
            res = []
            for r in rows:
                item = dict(r)
                item["triggered_rules"] = json.loads(item.get("rules_json") or "[]")
                item["primary_process"] = json.loads(item.get("primary_process_json") or "{}") if item.get("primary_process_json") else None
                res.append(item)
            return res

    @staticmethod
    def upsert_canary(canary_data: Dict[str, Any]) -> None:
        with get_db_connection() as conn:
            conn.execute(
                """
                INSERT INTO canaries (
                    canary_id, device_id, file_path, filename, file_type,
                    created_at, baseline_hash, baseline_size, baseline_entropy,
                    enabled, last_verified_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(canary_id) DO UPDATE SET
                    file_path=excluded.file_path,
                    baseline_hash=excluded.baseline_hash,
                    baseline_size=excluded.baseline_size,
                    baseline_entropy=excluded.baseline_entropy,
                    last_verified_at=excluded.last_verified_at
                """,
                (
                    canary_data["canary_id"],
                    canary_data["device_id"],
                    canary_data["file_path"],
                    canary_data["filename"],
                    canary_data.get("file_type", "txt"),
                    canary_data.get("created_at", time.time()),
                    canary_data.get("baseline_hash", ""),
                    canary_data.get("baseline_size", 0),
                    canary_data.get("baseline_entropy", 0.0),
                    1 if canary_data.get("enabled", True) else 0,
                    canary_data.get("last_verified_at", time.time()),
                ),
            )
            conn.commit()

    @staticmethod
    def get_canaries(device_id: str) -> List[Dict[str, Any]]:
        with get_db_connection() as conn:
            rows = conn.execute("SELECT * FROM canaries WHERE device_id = ?", (device_id,)).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def insert_canary_event(event_data: Dict[str, Any]) -> None:
        proc_json = json.dumps(event_data.get("process_context")) if event_data.get("process_context") else None
        with get_db_connection() as conn:
            conn.execute(
                """
                INSERT INTO canary_events (
                    event_id, canary_id, device_id, timestamp, event_type,
                    old_path, new_path, process_json, attribution_confidence,
                    current_threat_probability, current_threat_score,
                    current_rule_score, current_severity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO NOTHING
                """,
                (
                    event_data["event_id"],
                    event_data["canary_id"],
                    event_data["device_id"],
                    event_data.get("timestamp", time.time()),
                    event_data.get("event_type", "MODIFIED"),
                    event_data.get("old_path"),
                    event_data.get("new_path"),
                    proc_json,
                    event_data.get("attribution_confidence", "UNKNOWN"),
                    event_data.get("current_threat_probability", 0.0),
                    event_data.get("current_threat_score", 0.0),
                    event_data.get("current_rule_score", 0),
                    event_data.get("current_severity", "LOW"),
                ),
            )
            conn.commit()

    @staticmethod
    def get_canary_events(device_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        with get_db_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM canary_events WHERE device_id = ? ORDER BY timestamp DESC LIMIT ?",
                (device_id, limit),
            ).fetchall()
            res = []
            for r in rows:
                item = dict(r)
                item["process_context"] = json.loads(item.get("process_json") or "{}") if item.get("process_json") else None
                res.append(item)
            return res

    @staticmethod
    def insert_log(log_data: Dict[str, Any]) -> Dict[str, Any]:
        ts = log_data.get("timestamp", time.time())
        meta_json = json.dumps(log_data.get("metadata", {})) if log_data.get("metadata") else None
        with get_db_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO event_logs (
                    device_id, timestamp, category, severity, event_type,
                    message, incident_id, process_name, pid, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    log_data["device_id"],
                    ts,
                    log_data.get("category", "SYSTEM"),
                    log_data.get("severity", "INFO"),
                    log_data.get("event_type"),
                    log_data.get("message", ""),
                    log_data.get("incident_id"),
                    log_data.get("process_name"),
                    log_data.get("pid"),
                    meta_json,
                ),
            )
            conn.commit()
            log_id = cursor.lastrowid
            log_data["id"] = log_id
            log_data["timestamp"] = ts
            return log_data

    @staticmethod
    def get_logs(
        device_id: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        incident_id: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        query = "SELECT l.*, d.hostname FROM event_logs l LEFT JOIN devices d ON l.device_id = d.device_id WHERE 1=1"
        params = []

        if device_id:
            query += " AND l.device_id = ?"
            params.append(device_id)
        if severity:
            query += " AND l.severity = ?"
            params.append(severity.upper())
        if category:
            query += " AND l.category = ?"
            params.append(category.upper())
        if incident_id:
            query += " AND l.incident_id = ?"
            params.append(incident_id)

        query += " ORDER BY l.timestamp DESC LIMIT ?"
        params.append(limit)

        with get_db_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            res = []
            for r in rows:
                item = dict(r)
                item["metadata"] = json.loads(item.get("metadata_json") or "{}") if item.get("metadata_json") else None
                res.append(item)
            return res

    @staticmethod
    def get_active_incidents(device_id: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT a.*, d.hostname FROM alerts a LEFT JOIN devices d ON a.device_id = d.device_id WHERE a.current_status IN ('OPEN', 'UPDATED')"
        params = []
        if device_id:
            query += " AND a.device_id = ?"
            params.append(device_id)
        query += " ORDER BY a.timestamp DESC"

        with get_db_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            res = []
            for r in rows:
                item = dict(r)
                item["triggered_rules"] = json.loads(item.get("rules_json") or "[]")
                item["primary_process"] = json.loads(item.get("primary_process_json") or "{}") if item.get("primary_process_json") else None
                res.append(item)
            return res

    @staticmethod
    def get_resolved_incidents(device_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        query = "SELECT a.*, d.hostname FROM alerts a LEFT JOIN devices d ON a.device_id = d.device_id WHERE a.current_status = 'CLOSED'"
        params = []
        if device_id:
            query += " AND a.device_id = ?"
            params.append(device_id)
        query += " ORDER BY a.closed_at DESC, a.timestamp DESC LIMIT ?"
        params.append(limit)

        with get_db_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            res = []
            for r in rows:
                item = dict(r)
                item["triggered_rules"] = json.loads(item.get("rules_json") or "[]")
                item["primary_process"] = json.loads(item.get("primary_process_json") or "{}") if item.get("primary_process_json") else None
                res.append(item)
            return res

