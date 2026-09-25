"""样例驱动的验收测试：只读 samples/，输出写到临时目录。"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "samples")
KEYS = os.path.join(SAMPLES, "keys")
TIMELINES = os.path.join(SAMPLES, "timelines")
EXPECTED = os.path.join(SAMPLES, "expected")

TIMELINE_CASES = ["rotate", "asof", "retire", "revoke", "overlap", "deep", "errors"]
STATE_CASES = ["overlap", "asof"]
PAGE_CASES = ["overlap", "asof", "rotate", "deep"]


def cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "keyturn", *args],
        cwd=ROOT, capture_output=True, text=True,
    )


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


class KeyturnCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def paths(self, name):
        base = os.path.join(self.tmp.name, name)
        return {
            "state": os.path.join(base, "state.json"),
            "store": os.path.join(base, "store"),
            "out": os.path.join(base, "out.txt"),
            "page": os.path.join(base, "page.json"),
        }

    def run_timeline(self, timeline, paths):
        result = cli(
            "run", os.path.join(TIMELINES, timeline), KEYS,
            paths["state"], paths["store"], paths["out"],
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def run_case(self, case, name=None):
        paths = self.paths(name or case)
        self.run_timeline(case + ".txt", paths)
        return paths


class TimelineTests(KeyturnCase):
    def test_timeline_outputs_match_expected(self):
        for case in TIMELINE_CASES:
            with self.subTest(case=case):
                paths = self.run_case(case)
                self.assertEqual(
                    read_bytes(paths["out"]),
                    read_bytes(os.path.join(EXPECTED, case + ".out.txt")),
                )

    def test_state_files_match_expected(self):
        for case in STATE_CASES:
            with self.subTest(case=case):
                paths = self.run_case(case)
                self.assertEqual(
                    read_bytes(paths["state"]),
                    read_bytes(os.path.join(EXPECTED, case + ".state.json")),
                )

    def test_page_json_matches_expected_and_state_untouched(self):
        for case in PAGE_CASES:
            with self.subTest(case=case):
                paths = self.run_case(case)
                with open(os.path.join(EXPECTED, case + ".page.json"),
                          "r", encoding="ascii") as fh:
                    observe_at = json.load(fh)["now"]
                before = read_bytes(paths["state"])
                result = cli("page", paths["state"], str(observe_at), paths["page"])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    read_bytes(paths["page"]),
                    read_bytes(os.path.join(EXPECTED, case + ".page.json")),
                )
                self.assertEqual(read_bytes(paths["state"]), before)

    def test_page_rejects_observation_before_now(self):
        paths = self.run_case("asof")
        result = cli("page", paths["state"], "29", paths["page"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("E_ARG", result.stderr)
        self.assertFalse(os.path.exists(paths["page"]))


class RestartTests(KeyturnCase):
    def test_restart_across_processes(self):
        paths = self.paths("restart")
        out1 = dict(paths, out=os.path.join(self.tmp.name, "restart", "out1.txt"))
        out2 = dict(paths, out=os.path.join(self.tmp.name, "restart", "out2.txt"))
        self.run_timeline("restart-1.txt", out1)
        self.run_timeline("restart-2.txt", out2)
        self.assertEqual(
            read_bytes(out1["out"]),
            read_bytes(os.path.join(EXPECTED, "restart-1.out.txt")),
        )
        self.assertEqual(
            read_bytes(out2["out"]),
            read_bytes(os.path.join(EXPECTED, "restart-2.out.txt")),
        )


class DeterminismTests(KeyturnCase):
    def test_same_sequence_same_result(self):
        first = self.run_case("overlap", name="det-1")
        second = self.run_case("overlap", name="det-2")
        self.assertEqual(read_bytes(first["out"]), read_bytes(second["out"]))
        self.assertEqual(read_bytes(first["state"]), read_bytes(second["state"]))
        names1 = sorted(os.listdir(first["store"]))
        names2 = sorted(os.listdir(second["store"]))
        self.assertEqual(names1, names2)
        for name in names1:
            self.assertEqual(
                read_bytes(os.path.join(first["store"], name)),
                read_bytes(os.path.join(second["store"], name)),
            )


class CiphertextTests(KeyturnCase):
    PLAINTEXTS = {
        "d1": b"alpha", "d2": b"bravo", "d3": b"charlie", "d4": b"delta",
    }

    def test_data_files_carry_version_and_hide_plaintext(self):
        paths = self.run_case("overlap")
        for data_id, plaintext in self.PLAINTEXTS.items():
            with self.subTest(data_id=data_id):
                blob = read_bytes(os.path.join(paths["store"], data_id + ".kt"))
                self.assertTrue(blob.startswith(b"KT1 v"))
                self.assertNotIn(plaintext, blob)


if __name__ == "__main__":
    unittest.main()
