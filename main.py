"""
RansomGuard - Main Control Launcher (main.py)

Command-line entry point for RansomGuard Stage 1 prototype.
Supports resetting the sandbox, starting the filesystem watcher, 
and running normal or ransomware-like attack simulations.
"""

import sys
import argparse
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.sandbox_manager import reset_sandbox
from monitoring.watcher import start_monitoring
from simulator.normal_simulator import run_normal_simulation
from simulator.attack_simulator import run_attack_simulation


def main():
    parser = argparse.ArgumentParser(
        description="RansomGuard - Safe Ransomware-like Simulation & Monitoring System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py reset
  python main.py watch
  python main.py normal --duration 15 --seed 42
  python main.py attack --speed slow
  python main.py attack --speed medium
  python main.py attack --speed fast --max-files 20 --seed 42
""",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: reset
    subparsers.add_parser("reset", help="Reset sandbox/demo_folder with clean template copies")

    # Command: watch
    subparsers.add_parser("watch", help="Start real-time Watchdog filesystem event monitor")

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
        start_monitoring()
    elif args.command == "normal":
        run_normal_simulation(duration=args.duration, delay=args.delay, seed=args.seed)
    elif args.command == "attack":
        run_attack_simulation(speed=args.speed, max_files=args.max_files, seed=args.seed)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
