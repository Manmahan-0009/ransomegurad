import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import (
    FastAPI,
    HTTPException,
    Header,
    Query,
    WebSocket,
    WebSocketDisconnect,
    Depends,
)
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from .config import config
from .model_service import ModelService
from .rule_engine import RuleEngine
from .threat_score import ThreatScoreEngine
from .debounce import DebounceEngine
from .logger import LivePredictionLogger
from .schemas import (
    FeatureWindow,
    AgentRegistration,
    AgentHeartbeat,
    AgentTelemetry,
    AgentAlert,
)
from .websocket_manager import ConnectionManager
from .device_registry import device_registry
from .db import CentralDatabase
from containment.stopper import containment_manager


# ============================================================
# PATHS & SECURITY CONFIG
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]
FRONTEND_DIR = BASE_DIR / "frontend"

RANSOMGUARD_ENV = os.getenv("RANSOMGUARD_ENV", "production").lower()
EXPECTED_AGENT_TOKEN = os.getenv("RANSOMGUARD_AGENT_TOKEN")

if not EXPECTED_AGENT_TOKEN:
    EXPECTED_AGENT_TOKEN = "rg-dev-secret-token-2026"
    print("[SECURITY] RANSOMGUARD_AGENT_TOKEN missing in environment; using default development token 'rg-dev-secret-token-2026'.")


def verify_agent_auth(authorization: Optional[str] = Header(None)) -> None:
    """
    Validates simple agent authentication Bearer token (Phase 8.24).
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization header format. Expected Bearer <token>")

    token = parts[1]
    if token != EXPECTED_AGENT_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid agent authentication token")



# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="RansomGuard Multi-Endpoint API",
    description="Real-time Ransomware Behavioral Detection & Central Endpoint Management API",
    version="3.0-dev",
)


# ============================================================
# FRONTEND STATIC FILES
# ============================================================

app.mount(
    "/static",
    StaticFiles(directory=FRONTEND_DIR),
    name="static",
)


# ============================================================
# SERVICES
# ============================================================

model_service = ModelService()
rule_engine = RuleEngine()
threat_score_engine = ThreatScoreEngine()
debounce_engine = DebounceEngine()
prediction_logger = LivePredictionLogger()
manager = ConnectionManager()


# ============================================================
# FRONTEND HOME PAGE & FAVICON
# ============================================================

@app.get("/")
def root():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(
        content='<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🛡️</text></svg>',
        media_type="image/svg+xml",
    )


# ============================================================
# API HEALTH & CONFIG
# ============================================================

@app.get("/health")
def health():
    devices = device_registry.get_devices()
    online_count = sum(1 for d in devices if d.get("status") == "ONLINE")
    return {
        "status": "healthy",
        "model_loaded": True,
        "websocket": "available",
        "devices_total": len(devices),
        "devices_online": online_count,
        "containment_enabled": containment_manager.auto_containment_enabled,
        "containment_state": containment_manager.state,
        "config": {
            "model_version": config.model_version,
            "feature_schema_version": config.feature_schema_version,
            "rf_threshold": config.rf_threshold,
            "ml_weight": config.ml_weight,
            "rule_weight": config.rule_weight,
            "min_rename_count": config.min_rename_count,
            "consecutive_windows_required": config.consecutive_windows_required,
        },
    }


# ============================================================
# MULTI-ENDPOINT AGENT APIS (PHASE 8.3 - 8.6)
# ============================================================

@app.post("/agents/register", dependencies=[Depends(verify_agent_auth)])
async def register_agent(reg: AgentRegistration):
    device = device_registry.register_device(reg.model_dump())

    log_rec = CentralDatabase.insert_log({
        "device_id": reg.device_id,
        "category": "AGENT",
        "severity": "INFO",
        "event_type": "AGENT_REGISTERED",
        "message": f"Endpoint agent registered: {device['hostname']} ({device['device_id']})",
    })

    event = {
        "type": "AGENT_REGISTERED",
        "device_id": reg.device_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": device,
    }
    await manager.broadcast(event)

    log_event = {
        "type": "LOG_EVENT",
        "device_id": reg.device_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": log_rec,
    }
    await manager.broadcast(log_event)

    return {
        "status": "registered",
        "registered": True,
        "server_time": time.time(),
        "heartbeat_interval": 10.0,
        "device": device,
    }


@app.post("/agents/heartbeat", dependencies=[Depends(verify_agent_auth)])
async def agent_heartbeat(hb: AgentHeartbeat):
    success = device_registry.update_heartbeat(
        device_id=hb.device_id,
        timestamp=hb.timestamp,
        current_severity=hb.current_severity,
        current_threat_score=hb.current_threat_score,
        last_prediction=hb.last_prediction,
    )

    event = {
        "type": "AGENT_HEARTBEAT",
        "device_id": hb.device_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": hb.model_dump(),
    }
    await manager.broadcast(event)
    return {"status": "ok", "server_time": time.time()}


@app.post("/agents/telemetry", dependencies=[Depends(verify_agent_auth)])
async def agent_telemetry(telem: AgentTelemetry):
    stored = device_registry.record_telemetry(telem.model_dump())
    event = {
        "type": "TELEMETRY_UPDATE",
        "device_id": telem.device_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": telem.model_dump(),
    }
    await manager.broadcast(event)

    # Log HIGH/CRITICAL telemetry detections
    if telem.severity in ("HIGH", "CRITICAL") or telem.prediction == "THREAT":
        log_rec = CentralDatabase.insert_log({
            "device_id": telem.device_id,
            "category": "DETECTION",
            "severity": telem.severity,
            "event_type": "TELEMETRY_THREAT",
            "message": f"Behavioral threat window: score={telem.threat_score:.1f}, pred={telem.prediction}, rules={len(telem.triggered_rules or [])}",
            "process_name": telem.dominant_process.get("process_name") if telem.dominant_process else None,
            "pid": telem.dominant_process.get("pid") if telem.dominant_process else None,
        })
        log_event = {
            "type": "LOG_EVENT",
            "device_id": telem.device_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": log_rec,
        }
        await manager.broadcast(log_event)

    return {"status": "received", "stored": stored}


@app.post("/agents/alerts", dependencies=[Depends(verify_agent_auth)])
async def agent_alert(alert: AgentAlert):
    incident = device_registry.record_alert(alert.model_dump())
    event = {
        "type": "ALERT_UPDATE",
        "device_id": alert.device_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": incident,
    }
    await manager.broadcast(event)

    log_rec = CentralDatabase.insert_log({
        "device_id": alert.device_id,
        "category": "INCIDENT",
        "severity": incident.get("peak_severity") or alert.severity,
        "event_type": "INCIDENT_ALERT",
        "message": f"Security incident alert ({incident.get('current_status')}): alert_id={incident.get('alert_id')} score={incident.get('peak_score'):.1f}",
        "incident_id": incident.get("alert_id"),
        "process_name": incident.get("primary_process", {}).get("process_name") if incident.get("primary_process") else None,
        "pid": incident.get("primary_process", {}).get("pid") if incident.get("primary_process") else None,
    })
    log_event = {
        "type": "LOG_EVENT",
        "device_id": alert.device_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": log_rec,
    }
    await manager.broadcast(log_event)

    return {"status": "recorded", "alert_id": incident.get("alert_id"), "incident": incident}


@app.post("/agents/logs", dependencies=[Depends(verify_agent_auth)])
async def agent_log_endpoint(payload: dict):
    log_record = CentralDatabase.insert_log(payload)
    event = {
        "type": "LOG_EVENT",
        "device_id": log_record["device_id"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": log_record,
    }
    await manager.broadcast(event)
    return {"status": "recorded", "id": log_record.get("id")}



# ============================================================
# CENTRAL DEVICE & INCIDENT APIS (PHASE 8.8 & PHASE 10.5)
# ============================================================

@app.get("/devices")
def get_devices():
    return device_registry.get_devices()


@app.get("/devices/{device_id}")
def get_device_detail(device_id: str):
    dev = device_registry.get_device(device_id)
    if not dev:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    return dev


@app.delete("/devices/{device_id}")
def delete_device(device_id: str):
    dev = device_registry.get_device(device_id)
    if not dev:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    if dev.get("status") == "ONLINE":
        raise HTTPException(status_code=400, detail=f"Cannot delete device {device_id} while it is ONLINE. Stop the agent process first.")

    CentralDatabase.delete_device(device_id)
    return {"status": "success", "message": f"Device {device_id} deleted successfully"}


@app.get("/devices/{device_id}/telemetry")
def get_device_telemetry(device_id: str, limit: int = Query(50, ge=1, le=500)):
    dev = device_registry.get_device(device_id)
    if not dev:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    return device_registry.get_telemetry(device_id, limit=limit)


@app.get("/devices/{device_id}/alerts")
def get_device_alerts(device_id: str, limit: int = Query(50, ge=1, le=500)):
    dev = device_registry.get_device(device_id)
    if not dev:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    return device_registry.get_alerts(device_id, limit=limit)


@app.get("/devices/{device_id}/logs")
def get_device_logs(device_id: str, limit: int = Query(100, ge=1, le=500)):
    dev = device_registry.get_device(device_id)
    if not dev:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    return CentralDatabase.get_logs(device_id=device_id, limit=limit)


@app.get("/incidents/active")
def get_active_incidents(device_id: Optional[str] = Query(None)):
    return CentralDatabase.get_active_incidents(device_id=device_id)


@app.get("/incidents/history")
@app.get("/incidents/resolved")
def get_resolved_incidents(device_id: Optional[str] = Query(None), limit: int = Query(100, ge=1, le=500)):
    return CentralDatabase.get_resolved_incidents(device_id=device_id, limit=limit)


@app.get("/logs")
def get_all_logs(
    device_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    incident_id: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
):
    return CentralDatabase.get_logs(
        device_id=device_id,
        severity=severity,
        category=category,
        incident_id=incident_id,
        limit=limit,
    )


# ============================================================
# RESET PIPELINE STATE ENDPOINT
# ============================================================

@app.post("/reset-pipeline")
@app.post("/clear")
async def reset_pipeline():
    """
    Clears live debounce state and containment state for clean scenario testing.
    """
    debounce_engine.reset()
    containment_manager.reset()

    reset_event = {
        "type": "PIPELINE_RESET",
        "timestamp": datetime.now().isoformat(),
        "message": "Live pipeline, debounce, and containment state cleared.",
    }

    await manager.broadcast(reset_event)
    return {"status": "success", "message": "Live pipeline, debounce, and containment state reset successfully."}


# ============================================================
# CONTAINMENT ENDPOINTS
# ============================================================

@app.get("/containment/status")
def get_containment_status():
    return {
        "auto_containment_enabled": containment_manager.auto_containment_enabled,
        "state": containment_manager.state,
        "current_run_id": containment_manager.current_run_id,
        "last_metrics": containment_manager.last_metrics,
    }


@app.post("/contain")
async def trigger_containment():
    """
    Safely triggers simulated containment to stop ONLY the controlled attack simulator.
    """
    contain_res = containment_manager.execute_containment()
    contain_event = {
        "type": "CONTAINMENT_UPDATE",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "result": contain_res,
    }
    await manager.broadcast(contain_event)

    log_rec = CentralDatabase.insert_log({
        "device_id": "SERVER",
        "category": "CONTAINMENT",
        "severity": "INFO",
        "event_type": "CONTAINMENT_ACTION",
        "message": f"Simulated safe containment executed: state={contain_res.get('state')}",
    })
    log_event = {
        "type": "LOG_EVENT",
        "device_id": "SERVER",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": log_rec,
    }
    await manager.broadcast(log_event)

    return contain_res


@app.post("/agents/canaries")
def register_agent_canary(payload: dict, auth: None = Depends(verify_agent_auth)):
    CentralDatabase.upsert_canary(payload)
    return {"status": "SUCCESS"}


@app.post("/agents/canary-events")
async def record_agent_canary_event(payload: dict, auth: None = Depends(verify_agent_auth)):
    CentralDatabase.insert_canary_event(payload)
    dev_id = payload.get("device_id", "unknown")
    event_type = payload.get("event_type", "MODIFIED")
    log_rec = CentralDatabase.insert_log({
        "device_id": dev_id,
        "category": "CANARY",
        "severity": "MEDIUM",
        "event_type": "CANARY_EVENT",
        "message": f"Canary decoy event ({event_type}): file altered on {dev_id}",
        "process_name": payload.get("process_context", {}).get("process_name") if isinstance(payload.get("process_context"), dict) else None,
        "pid": payload.get("process_context", {}).get("pid") if isinstance(payload.get("process_context"), dict) else None,
    })
    log_event = {
        "type": "LOG_EVENT",
        "device_id": dev_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": log_rec,
    }
    await manager.broadcast(log_event)
    return {"status": "SUCCESS"}


@app.get("/devices/{device_id}/canaries")
def get_device_canaries(device_id: str):
    return CentralDatabase.get_canaries(device_id)


@app.get("/devices/{device_id}/canary-events")
def get_device_canary_events(device_id: str, limit: int = Query(default=50, ge=1, le=500)):
    return CentralDatabase.get_canary_events(device_id, limit=limit)


@app.post("/devices/{device_id}/canaries/reset")
def reset_device_canaries(device_id: str, auth: None = Depends(verify_agent_auth)):
    from canary.canary_manager import canary_manager
    records = canary_manager.reset_canaries(device_id=device_id)
    for rec in records:
        CentralDatabase.upsert_canary(rec.to_dict())
    return {"status": "SUCCESS", "message": f"Reset {len(records)} canaries for device {device_id}"}


# ============================================================
# PREDICTION API (SINGLE-ENDPOINT COMPATIBILITY)
# ============================================================

@app.post("/predict")
async def predict(window: FeatureWindow):
    try:
        features = window.model_dump()
        scenario_id = features.pop("scenario_id", "live")
        window_start = features.pop("window_start", None)
        window_end = features.pop("window_end", None)

        # ML prediction
        ml_result = model_service.predict(features)

        # Rule engine
        rule_result = rule_engine.evaluate(features)

        # Threat score calculation
        score_result = threat_score_engine.calculate(
            threat_probability=ml_result["threat_probability"],
            rule_score=rule_result["rule_score"],
        )

        # Debounce evaluation
        debounce_result = debounce_engine.evaluate(
            threat_score=score_result["threat_score"],
            raw_severity=score_result["severity"],
        )

        # Combined result object
        result = {
            "type": "PREDICTION_UPDATE",
            "timestamp": datetime.now().isoformat(),
            "scenario_id": scenario_id,
            "window_start": window_start,
            "window_end": window_end,
            "prediction": ml_result["prediction"],
            "severity": score_result["severity"],
            "threat_score": score_result["threat_score"],
            "debounce": debounce_result,
            "ml": {
                "benign_probability": ml_result["benign_probability"],
                "threat_probability": ml_result["threat_probability"],
                "threshold": ml_result["threshold"],
            },
            "rules": {
                "rule_score": rule_result["rule_score"],
                "rules_triggered": rule_result["rules_triggered"],
                "triggered_rules": rule_result["triggered_rules"],
            },
            "version_info": {
                "model_version": ml_result.get("model_version", config.model_version),
                "feature_schema_version": ml_result.get("feature_schema_version", config.feature_schema_version),
                "rf_threshold": ml_result["threshold"],
                "ml_weight": config.ml_weight,
                "rule_weight": config.rule_weight,
            },
            "features": features,
        }

        # Safe containment state evaluation
        containment_res = containment_manager.process_prediction_window(result)
        result["containment"] = containment_res

        # Persistent JSONL log
        prediction_logger.log(result)

        # WebSocket broadcast to dashboard
        await manager.broadcast(result)

        if containment_res.get("containment_executed"):
            contain_event = {
                "type": "CONTAINMENT_UPDATE",
                "timestamp": datetime.now().isoformat(),
                "result": containment_res,
            }
            await manager.broadcast(contain_event)

        return result

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )


# ============================================================
# WEBSOCKET
# ============================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    print("WebSocket client connected.")

    try:
        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        print("WebSocket client disconnected.")

    except Exception as error:
        manager.disconnect(websocket)
        print(f"WebSocket connection error: {error}")