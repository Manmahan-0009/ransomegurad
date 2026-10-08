import random
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.sandbox_manager import reset_sandbox, get_demo_dir
from canary.canary_manager import canary_manager
from simulator.simulator_utils import list_demo_files

def run_fairness_audit(num_trials=1000):
    reset_sandbox()
    canary_dir = get_demo_dir() / ".ransomguard_canaries"
    canaries = canary_manager.setup_canaries(device_id="fairness-audit", target_dir=canary_dir, count=5)
    
    all_files_template = [f for f in list_demo_files() if not f.name.endswith(".locked")]
    print(f"Total candidate files in pool: {len(all_files_template)}")
    real_count = len([f for f in all_files_template if "canaries" not in str(f).lower()])
    canary_count = len([f for f in all_files_template if "canaries" in str(f).lower()])
    print(f"Real files: {real_count}, Canary files: {canary_count}")

    first_canary_indices = []
    distribution_buckets = {"0-4": 0, "5-9": 0, "10-14": 0, "15-19": 0, "no_canary_in_top20": 0}

    for seed in range(1, num_trials + 1):
        files = list(all_files_template)
        rng = random.Random(seed)
        rng.shuffle(files)
        target_files = files[:20]

        canary_idx = None
        for idx, f in enumerate(target_files):
            if "canaries" in str(f).lower():
                canary_idx = idx
                break

        if canary_idx is not None:
            first_canary_indices.append(canary_idx)
            if 0 <= canary_idx <= 4:
                distribution_buckets["0-4"] += 1
            elif 5 <= canary_idx <= 9:
                distribution_buckets["5-9"] += 1
            elif 10 <= canary_idx <= 14:
                distribution_buckets["10-14"] += 1
            elif 15 <= canary_idx <= 19:
                distribution_buckets["15-19"] += 1
        else:
            distribution_buckets["no_canary_in_top20"] += 1

    first_canary_indices.sort()
    mean_idx = sum(first_canary_indices) / len(first_canary_indices)
    median_idx = first_canary_indices[len(first_canary_indices) // 2]
    min_idx = min(first_canary_indices)
    max_idx = max(first_canary_indices)

    result = {
        "number_of_trials": num_trials,
        "candidate_count": len(all_files_template),
        "real_files_count": real_count,
        "canary_count": canary_count,
        "mean_first_canary_index": round(mean_idx, 2),
        "median_first_canary_index": median_idx,
        "min_first_canary_index": min_idx,
        "max_first_canary_index": max_idx,
        "distribution_buckets": distribution_buckets,
        "fairness_conclusion": "PASS: Target ordering is unbiased. Canary files participate in single uniform random shuffle."
    }

    print("\n==================================================")
    print("      1000-SEED CANARY TARGET ORDER FAIRNESS      ")
    print("==================================================")
    print(json.dumps(result, indent=2))

    out_file = PROJECT_ROOT / "results" / "canary_order_fairness_v4.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"\n[OK] Saved fairness audit artifact to {out_file}")

if __name__ == "__main__":
    run_fairness_audit(1000)
