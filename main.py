"""
RansomGuard - Main Control Launcher (main.py)

Command-line entry point for RansomGuard Stage 1 & Stage 2 prototype.
Supports resetting the sandbox, raw event monitoring, user simulators,
and real-time behavioral feature extraction (5s sliding window).
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
from simulator.attack_simulator import run_attack_simulation


def run_live_feature_monitor(window_seconds: float = 5.0, stride_seconds: float = 1.0, dedupe_ms: float = 200.0) -> None:
    """
    Stage 2 Live Feature Extraction Loop:
    Watchdog -> Structured Event -> Queue -> Deduplication -> 5s Window -> Feature Vector.
    Calculates and prints behavioral features every 1 second.
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

    # Start Watchdog observer in non-blocking background mode
    observer = start_monitoring(
        target_dir=demo_dir,
        queue_callback=eq.push,
        print_events=False,
        block=False,
    )

    try:
        while True:
            time.sleep(stride_seconds)

            # 1. Drain raw events from queue
            raw_events = eq.flush()

            # 2. Deduplicate raw events
            kept_events = deduplicator.deduplicate_list(raw_events)

            # 3. Add kept events to sliding window
            window_buffer.add_events(kept_events)

            # 4. Get active events in current window
            current_window_events = window_buffer.get_current_events()

            # 5. Extract 11-dimensional feature vector
            feature_vector = extract_features(current_window_events, window_seconds=window_seconds)

            # 6. Output formatted feature vector
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
        description="RansomGuard - Safe Ransomware-like Simulation & Feature Extraction System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py reset
  python main.py watch
  python main.py features
  python main.py normal --duration 15 --seed 42
  python main.py attack --speed medium --seed 42
""",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: reset
    subparsers.add_parser("reset", help="Reset sandbox/demo_folder with clean template copies")

    # Command: watch (Stage 1 Raw Event Observer)
    subparsers.add_parser("watch", help="Start Stage 1 real-time raw Watchdog event monitor")

    # Command: features / monitor-features (Stage 2 Live Feature Extraction)
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

    # Command: attack
    attack_parser = subparsers.add_parser("attack", help="Run safe ransomware-like burst activity simulator")
    attack_parser.add_argument("--speed", choices=["slow", "medium", "fast"], default="medium", help="Burst speed (default: medium)")
    attack_parser.add_argument("--max-files", type=int, default=20, help="Max files to affect (default: 20)")
    attack_parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")

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
    elif args.command == "attack":
        run_attack_simulation(speed=args.speed, max_files=args.max_files, seed=args.seed)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
