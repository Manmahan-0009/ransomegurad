from datetime import datetime
from pathlib import Path

from fastapi import (
    FastAPI,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import config
from .model_service import ModelService
from .rule_engine import RuleEngine
from .threat_score import ThreatScoreEngine
from .debounce import DebounceEngine
from .logger import LivePredictionLogger
from .schemas import FeatureWindow
from .websocket_manager import ConnectionManager
from containment.stopper import containment_manager


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]
FRONTEND_DIR = BASE_DIR / "frontend"


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="RansomGuard API",
    description="Real-time ransomware behavior detection API",
    version="1.4.0",
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
# FRONTEND HOME PAGE
# ============================================================

@app.get("/")
def root():
    return FileResponse(FRONTEND_DIR / "index.html")


# ============================================================
# API HEALTH & CONFIG
# ============================================================

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "model_loaded": True,
        "websocket": "available",
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
        }
    }


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
        "timestamp": datetime.now().isoformat(),
        "result": contain_res,
    }
    await manager.broadcast(contain_event)
    return contain_res


# ============================================================
# PREDICTION API
# ============================================================

@app.post("/predict")
async def predict(window: FeatureWindow):
    try:
        features = window.model_dump()
        scenario_id = features.pop("scenario_id", "live")
        window_start = features.pop("window_start", None)
        window_end = features.pop("window_end", None)

        # -------------------------
        # ML prediction
        # -------------------------
        ml_result = model_service.predict(features)

        # -------------------------
        # Rule engine
        # -------------------------
        rule_result = rule_engine.evaluate(features)

        # -------------------------
        # Threat score calculation
        # -------------------------
        score_result = threat_score_engine.calculate(
            threat_probability=ml_result["threat_probability"],
            rule_score=rule_result["rule_score"],
        )

        # -------------------------
        # Debounce evaluation
        # -------------------------
        debounce_result = debounce_engine.evaluate(
            threat_score=score_result["threat_score"],
            raw_severity=score_result["severity"],
        )

        # -------------------------
        # Final combined result object
        # -------------------------
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

        # -------------------------
        # Evaluate safe containment state
        # -------------------------
        containment_res = containment_manager.process_prediction_window(result)
        result["containment"] = containment_res

        # -------------------------
        # Persistent JSONL log
        # -------------------------
        prediction_logger.log(result)

        # -------------------------
        # WebSocket broadcast to dashboard
        # -------------------------
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