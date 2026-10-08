import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from process_telemetry.process_context import ProcessContext, _clean_pid



class TestProcessContext(unittest.TestCase):
    def test_valid_integer_pid(self):
        ctx = ProcessContext(pid=12908, parent_pid=4000, attribution_confidence="DIRECT")
        self.assertEqual(ctx.pid, 12908)
        self.assertEqual(ctx.parent_pid, 4000)
        self.assertEqual(ctx.attribution_confidence, "DIRECT")

    def test_none_pid(self):
        ctx = ProcessContext(pid=None, parent_pid=None)
        self.assertIsNone(ctx.pid)
        self.assertIsNone(ctx.parent_pid)
        self.assertEqual(ctx.attribution_confidence, "UNKNOWN")

    def test_invalid_string_pid_normalization(self):
        ctx = ProcessContext(pid="rg-73b75ee668d5", parent_pid="attack_run_42")
        self.assertIsNone(ctx.pid)
        self.assertIsNone(ctx.parent_pid)

    def test_valid_string_convertible_pid(self):
        ctx = ProcessContext(pid="12908", parent_pid="4000")
        self.assertEqual(ctx.pid, 12908)
        self.assertEqual(ctx.parent_pid, 4000)

    def test_confidence_validation(self):
        ctx = ProcessContext(pid=100, attribution_confidence="INVALID_CONFIDENCE")
        self.assertEqual(ctx.attribution_confidence, "UNKNOWN")

    def test_separate_simulation_identity(self):
        ctx = ProcessContext(
            pid=12908,
            process_name="python.exe",
            simulator_type="attack",
            run_id="attack_seed_42",
            attribution_confidence="DIRECT",
        )
        d = ctx.to_dict()
        self.assertEqual(d["pid"], 12908)
        self.assertEqual(d["process_name"], "python.exe")
        self.assertEqual(d["simulator_type"], "attack")
        self.assertEqual(d["run_id"], "attack_seed_42")


if __name__ == "__main__":
    unittest.main()

