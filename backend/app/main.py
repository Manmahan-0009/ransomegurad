from pathlib import Path

from fastapi import (
    FastAPI,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .model_service import ModelService
from .rule_engine import RuleEngine
from .threat_score import ThreatScoreEngine
from .schemas import FeatureWindow
from .websocket_manager import ConnectionManager


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
    version="1.2.0",
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

manager = ConnectionManager()


# ============================================================
# FRONTEND HOME PAGE
# ============================================================

@app.get("/")
def root():
    return FileResponse(
        FRONTEND_DIR / "index.html"
    )


# ============================================================
# API HEALTH
# ============================================================

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "model_loaded": True,
        "websocket": "available",
    }


# ============================================================
# PREDICTION API
# ============================================================

@app.post("/predict")
async def predict(window: FeatureWindow):

    try:

        features = window.model_dump()

        # -------------------------
        # ML prediction
        # -------------------------

        ml_result = model_service.predict(
            features
        )

        # -------------------------
        # Rule engine
        # -------------------------

        rule_result = rule_engine.evaluate(
            features
        )

        # -------------------------
        # Threat score
        # -------------------------

        score_result = threat_score_engine.calculate(
            threat_probability=ml_result[
                "threat_probability"
            ],
            rule_score=rule_result[
                "rule_score"
            ],
        )

        # -------------------------
        # Final result
        # -------------------------

        result = {

            "prediction":
                ml_result["prediction"],

            "severity":
                score_result["severity"],

            "threat_score":
                score_result["threat_score"],

            "ml": {

                "benign_probability":
                    ml_result[
                        "benign_probability"
                    ],

                "threat_probability":
                    ml_result[
                        "threat_probability"
                    ],

                "threshold":
                    ml_result["threshold"],
            },

            "rules": {

                "rule_score":
                    rule_result["rule_score"],

                "rules_triggered":
                    rule_result[
                        "rules_triggered"
                    ],

                "triggered_rules":
                    rule_result[
                        "triggered_rules"
                    ],
            },

            "features": features,
        }

        # -------------------------
        # Send event to WebSocket
        # -------------------------

        await manager.broadcast(
            result
        )

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
async def websocket_endpoint(
    websocket: WebSocket
):

    await manager.connect(
        websocket
    )

    print(
        "WebSocket client connected."
    )

    try:

        while True:

            await websocket.receive_text()

    except WebSocketDisconnect:

        manager.disconnect(
            websocket
        )

        print(
            "WebSocket client disconnected."
        )

    except Exception as error:

        manager.disconnect(
            websocket
        )

        print(
            f"WebSocket connection error: {error}"
        )