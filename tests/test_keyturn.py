"""Replay every samples/ timeline and compare byte-for-byte with expected/."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "samples")
TIMELINES = os.path.join(SAMPLES, "timelines")
EXPECTED = os.path.join(SAMPLES, "expected")
KEYS = os.path.join(SAMPLES, "keys")

TIMELINE_CASES = ["asof", "deep", "errors", "overlap", "retire", "revoke",
                  "rotate"]
STATE_CASES = ["asof", "overlap"]
PAGE_CASES = {"asof": 400, "deep": 260, "overlap": 8000, "rotate": 900}


def cli(*args):
    proc = subprocess.run(
        [sys.executable, "-m", "keyturn", *args],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    return proc


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


class TimelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def run_case(self, name, state="state.json", store="store", out="out.txt"):
        cli("run", os.path.join(TIMELINES, name + ".txt"), KEYS,
            os.path.join(self.dir, state), os.path.join(self.dir, store),
            os.path.join(self.dir, out))
        return os.path.join(self.dir, out)

    def assert_matches_expected(self, actual_path, expected_name):
        self.assertEqual(read_bytes(actual_path),
                         read_bytes(os.path.join(EXPECTED, expected_name)))

    def test_timelines(self):
        for case in TIMELINE_CASES:
            with self.subTest(case=case):
                out = self.run_case(case, state=case + ".state.json",
                                    store=case + ".store")
                self.assert_matches_expected(out, case + ".out.txt")

    def test_state_files(self):
        for case in STATE_CASES:
            with self.subTest(case=case):
                self.run_case(case, state=case + ".state.json",
                              store=case + ".store")
                self.assert_matches_expected(
                    os.path.join(self.dir, case + ".state.json"),
                    case + ".state.json")

    def test_pages(self):
        for case, moment in PAGE_CASES.items():
            with self.subTest(case=case):
                self.run_case(case, state=case + ".state.json",
                              store=case + ".store")
                page = os.path.join(self.dir, case + ".page.json")
                cli("page", os.path.join(self.dir, case + ".state.json"),
                    str(moment), page)
                self.assert_matches_expected(page, case + ".page.json")

    def test_restart_across_processes(self):
        for name, expected in (("restart-1", "restart-1.out.txt"),
                               ("restart-2", "restart-2.out.txt")):
            out = self.run_case(name, out=name + ".out.txt")
            self.assert_matches_expected(out, expected)

    def test_deterministic_replay(self):
        first = self.run_case("overlap", state="s1.json", store="d1",
                              out="o1.txt")
        second = self.run_case("overlap", state="s2.json", store="d2",
                               out="o2.txt")
        self.assertEqual(read_bytes(first), read_bytes(second))
        self.assertEqual(read_bytes(os.path.join(self.dir, "s1.json")),
                         read_bytes(os.path.join(self.dir, "s2.json")))
        for name in sorted(os.listdir(os.path.join(self.dir, "d1"))):
            self.assertEqual(
                read_bytes(os.path.join(self.dir, "d1", name)),
                read_bytes(os.path.join(self.dir, "d2", name)))

    def test_ciphertext_hides_plaintext(self):
        self.run_case("rotate")
        store = os.path.join(self.dir, "store")
        blobs = b"".join(read_bytes(os.path.join(store, name))
                         for name in os.listdir(store))
        for plaintext in (b"alpha", b"bravo", b"charlie"):
            self.assertNotIn(plaintext, blobs)

    def test_page_rejects_earlier_time(self):
        self.run_case("asof")
        proc = subprocess.run(
            [sys.executable, "-m", "keyturn", "page",
             os.path.join(self.dir, "state.json"), "10",
             os.path.join(self.dir, "page.json")],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("E_ARG", proc.stderr)

    def test_page_does_not_touch_state(self):
        self.run_case("asof")
        state = os.path.join(self.dir, "state.json")
        before = read_bytes(state)
        cli("page", state, "400", os.path.join(self.dir, "page.json"))
        self.assertEqual(before, read_bytes(state))
        view = json.loads(before)
        self.assertEqual(view["versions"][0]["state"], "active")


if __name__ == "__main__":
    unittest.main()
