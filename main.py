"""
RansomGuard - Main Control Launcher (main.py)

Command-line entry point for RansomGuard Stage 1, Stage 2, Stage 3 & Stage 4 live detection prototype.
Supports:
- Stage 1: Sandbox reset, raw event watcher, normal & attack simulators
- Stage 2: Live 5s sliding-window behavioral feature extraction
- Stage 3: Benign high-activity simulator, automated dataset generation, run-based splitting, and validation
- Stage 4: Random Forest model training, verification, FastAPI server, live telemetry bridge, pipeline reset
"""

import sys
import time
import argparse
from datetime import datetime
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.sandbox_manager import reset_sandbox, get_demo_dir
from monitoring.watcher import start_monitoring
from monitoring.event_queue import EventQueue
from monitoring.deduplicator import EventDeduplicator
from windowing.sliding_window import SlidingWindowBuffer
from features.extractor import extract_features
from simulator.normal_simulator import run_normal_simulation
from simulator.benign_simulator import run_benign_simulation
from simulator.attack_simulator import run_attack_simulation

from training.generate_dataset import run_dataset_generation
from training.split_by_run import split_dataset_by_run_id
from training.dataset_validator import validate_dataset_and_splits
from training.verify_stage3 import run_stage3_quick_verification


def run_live_feature_monitor(window_seconds: float = 5.0, stride_seconds: float = 1.0, dedupe_ms: float = 200.0) -> None:
    """
    Stage 2 Live Feature Extraction Loop.
    """
    demo_dir = get_demo_dir().resolve()
    print("==================================================")
    print("     RANSOMGUARD LIVE FEATURE MONITOR ACTIVE      ")
    print(f" Target Directory: {demo_dir}")
    print(f" Window: {window_seconds}s | Stride: {stride_seconds}s | Dedupe: {dedupe_ms}ms")
    print(" Press Ctrl+C to terminate monitor.")
    print("==================================================")

    eq = EventQueue()
    deduplicator = EventDeduplicator(dedupe_ms=dedupe_ms)
    window_buffer = SlidingWindowBuffer(window_seconds=window_seconds, stride_seconds=stride_seconds)

    observer = start_monitoring(
        target_dir=demo_dir,
        queue_callback=eq.push,
        print_events=False,
        block=False,
    )

    try:
        while True:
            time.sleep(stride_seconds)
            raw_events = eq.flush()
            kept_events = deduplicator.deduplicate_list(raw_events)
            window_buffer.add_events(kept_events)
            current_window_events = window_buffer.get_current_events()
            feature_vector = extract_features(current_window_events, window_seconds=window_seconds)

            ts = datetime.now().strftime("%H:%M:%S")
            print(f"\n[{ts}] [FEATURE WINDOW]")
            for feat_name, feat_val in feature_vector.items():
                if isinstance(feat_val, float):
                    print(f"  {feat_name:<24} : {feat_val:.4f}")
                else:
                    print(f"  {feat_name:<24} : {feat_val}")
            sys.stdout.flush()

    except KeyboardInterrupt:
        print("\n[MONITOR] Stopping Live Feature Monitor...")
    finally:
        observer.stop()
        observer.join()


def main():
    parser = argparse.ArgumentParser(
        description="RansomGuard - Safe Ransomware-like Simulation, Monitoring & Dataset System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python main.py reset
  python main.py watch
  python main.py normal --duration 15 --seed 42
  python main.py benign --duration 15 --seed 42
  python main.py attack --speed medium --seed 42
  python main.py features
  python main.py generate-data --class all --runs-per-class 3 --seed 42 --fresh
  python main.py split-data --seed 42
  python main.py validate-data
  python main.py verify-stage3
  python main.py reset-pipeline
""",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: reset
    subparsers.add_parser("reset", help="Reset sandbox/demo_folder with clean template copies")

    # Command: watch
    subparsers.add_parser("watch", help="Start Stage 1 real-time raw Watchdog event monitor")

    # Command: features / monitor-features
    features_parser = subparsers.add_parser(
        "features",
        aliases=["monitor-features"],
        help="Start Stage 2 live behavioral feature extractor (5s sliding window, 1s stride)"
    )
    features_parser.add_argument("--window", type=float, default=5.0, help="Sliding window size in seconds (default: 5.0)")
    features_parser.add_argument("--stride", type=float, default=1.0, help="Window stride step in seconds (default: 1.0)")
    features_parser.add_argument("--dedupe-ms", type=float, default=200.0, help="Deduplication ms (default: 200.0)")

    # Command: normal
    normal_parser = subparsers.add_parser("normal", help="Run harmless normal user activity simulator")
    normal_parser.add_argument("--duration", type=float, default=15.0, help="Simulation duration in seconds (default: 15)")
    normal_parser.add_argument("--delay", type=float, default=2.0, help="Delay between actions in seconds (default: 2.0)")
    normal_parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")

    # Command: benign
    benign_parser = subparsers.add_parser("benign", help="Run harmless high-activity benign workload simulator")
    benign_parser.add_argument("--duration", type=float, default=15.0, help="Simulation duration in seconds (default: 15)")
    benign_parser.add_argument("--delay", type=float, default=0.2, help="Delay between actions in seconds (default: 0.2)")
    benign_parser.add_argument("--speed", choices=["slow", "medium", "fast"], default="medium", help="Speed mode (default: medium)")
    benign_parser.add_argument("--max-files", type=int, default=30, help="Max files limit (default: 30)")
    benign_parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")

    # Command: attack
    attack_parser = subparsers.add_parser("attack", help="Run safe ransomware-like burst activity simulator")
    attack_parser.add_argument("--speed", choices=["slow", "medium", "fast"], default="medium", help="Burst speed (default: medium)")
    attack_parser.add_argument("--max-files", type=int, default=20, help="Max files to affect (default: 20)")
    attack_parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    attack_parser.add_argument("--auto-contain", action="store_true", help="Enable safe simulated containment during attack simulation")

    # Command: demo-containment
    contain_demo_parser = subparsers.add_parser("demo-containment", help="Run safe simulated containment demonstration against controlled attack simulator")
    contain_demo_parser.add_argument("--speed", choices=["slow", "medium", "fast"], default="medium", help="Burst speed (default: medium)")
    contain_demo_parser.add_argument("--max-files", type=int, default=20, help="Max files to affect (default: 20)")
    contain_demo_parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")

    # Command: generate-data
    gen_parser = subparsers.add_parser("generate-data", help="Automate dataset generation for normal, benign, and attack runs")
    gen_parser.add_argument("--class", dest="target_class", choices=["normal", "benign", "attack", "all"], default="all", help="Target class (default: all)")
    gen_parser.add_argument("--all", action="store_true", help="Generate runs for all classes")
    gen_parser.add_argument("--runs", type=int, default=3, help="Runs count for single class (default: 3)")
    gen_parser.add_argument("--runs-per-class", type=int, default=3, help="Runs per class when class=all (default: 3)")
    gen_parser.add_argument("--duration", type=float, default=15.0, help="Run duration in seconds (default: 15)")
    gen_parser.add_argument("--seed", type=int, default=42, help="Base random seed (default: 42)")
    gen_parser.add_argument("--fresh", action="store_true", help="Clear previous generated dataset artifacts before running")

    # Command: split-data
    split_parser = subparsers.add_parser("split-data", help="Perform grouped run_id train/validation/test split on dataset_v1.csv")
    split_parser.add_argument("--seed", type=int, default=42, help="Random seed for split reproducibility (default: 42)")

    # Command: validate-data
    subparsers.add_parser("validate-data", help="Validate dataset_v1.csv and split consistency")

    # Command: verify-stage3
    subparsers.add_parser("verify-stage3", help="Quickly verify existing Stage 3 artifacts without running simulations or regenerating data")

    # Command: train
    subparsers.add_parser("train", help="Train Stage 4 Random Forest model using run-grouped splits")

    # Command: verify-model
    subparsers.add_parser("verify-model", help="Verify trained model metrics against untouched test set")

    # Command: reset-pipeline
    subparsers.add_parser("reset-pipeline", aliases=["clear-pipeline"], help="Reset live telemetry bridge window and FastAPI backend debounce state")

    # Command: serve
    serve_parser = subparsers.add_parser(
        "serve",
        aliases=["server"],
        help="Launch FastAPI backend server with REST & WebSocket endpoints"
    )
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port number (default: 8000)")

    # Command: live-detect
    detect_parser = subparsers.add_parser(
        "live-detect",
        aliases=["detect", "bridge"],
        help="Start Stage 2 live telemetry bridge to FastAPI backend"
    )
    detect_parser.add_argument("--api-url", default="http://127.0.0.1:8000/predict", help="Backend API URL (default: http://127.0.0.1:8000/predict)")
    detect_parser.add_argument("--window", type=float, default=5.0, help="Window size in seconds (default: 5.0)")
    detect_parser.add_argument("--stride", type=float, default=1.0, help="Stride step in seconds (default: 1.0)")

    args = parser.parse_args()

    if args.command == "reset":
        reset_sandbox()
    elif args.command == "watch":
        start_monitoring(print_events=True, block=True)
    elif args.command in ["features", "monitor-features"]:
        run_live_feature_monitor(
            window_seconds=args.window,
            stride_seconds=args.stride,
            dedupe_ms=args.dedupe_ms,
        )
    elif args.command == "normal":
        run_normal_simulation(duration=args.duration, delay=args.delay, seed=args.seed)
    elif args.command == "benign":
        run_benign_simulation(duration=args.duration, delay=args.delay, speed=args.speed, max_files=args.max_files, seed=args.seed)
    elif args.command == "attack":
        if getattr(args, "auto_contain", False):
            from containment.run_containment_demo import run_safe_containment_demo
            run_safe_containment_demo(speed=args.speed, max_files=args.max_files, seed=args.seed, auto_contain=True)
        else:
            run_attack_simulation(speed=args.speed, max_files=args.max_files, seed=args.seed)
    elif args.command == "demo-containment":
        from containment.run_containment_demo import run_safe_containment_demo
        run_safe_containment_demo(speed=args.speed, max_files=args.max_files, seed=args.seed, auto_contain=True)
    elif args.command == "generate-data":
        target_cls = "all" if args.all else args.target_class
        runs_cnt = args.runs if (target_cls != "all" and not args.all) else args.runs_per_class
        run_dataset_generation(target_class=target_cls, runs_per_class=runs_cnt, duration=args.duration, seed=args.seed, fresh=args.fresh)
    elif args.command == "split-data":
        split_dataset_by_run_id(seed=args.seed)
    elif args.command == "validate-data":
        validate_dataset_and_splits()
    elif args.command == "verify-stage3":
        run_stage3_quick_verification()
    elif args.command == "train":
        from training.train_model import main as train_main
        train_main()
    elif args.command == "verify-model":
        import subprocess
        subprocess.run([sys.executable, str(PROJECT_ROOT / "training" / "verify_model.py")])
    elif args.command in ["reset-pipeline", "clear-pipeline"]:
        import requests
        try:
            res = requests.post("http://127.0.0.1:8000/reset-pipeline", timeout=2.0)
            if res.status_code == 200:
                print("[SUCCESS] Backend live pipeline and debounce state reset.")
            else:
                print(f"[WARNING] Reset endpoint returned status {res.status_code}: {res.text}")
        except Exception as err:
            print(f"[INFO] Backend unavailable or reset request failed: {err}")
    elif args.command in ["serve", "server"]:
        try:
            import uvicorn
        except ImportError:
            print("\n==================================================")
            print(" [ERROR] The 'uvicorn' package is not installed.")
            print(" Please install it by running:")
            print("     pip install -r requirements.txt")
            print("  or:")
            print("     pip install uvicorn")
            print("==================================================\n")
            sys.exit(1)
        uvicorn.run("backend.app.main:app", host=args.host, port=args.port, reload=True)
    elif args.command in ["live-detect", "detect", "bridge"]:
        from detection.live_telemetry_bridge import start_live_telemetry_bridge
        start_live_telemetry_bridge(api_url=args.api_url, window_seconds=args.window, stride_seconds=args.stride)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
