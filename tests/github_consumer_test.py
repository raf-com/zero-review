import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("github_consumer", ROOT / "scripts" / "github_consumer.py")
consumer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(consumer)


def snapshot():
    head = "b" * 40
    return {
        "repository": "owner/repo",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "pull_request": {"number": 7, "state": "open", "author": {"id": 1, "login": "author"}, "base_sha": "a" * 40, "head_sha": head, "changed_files": 1},
        "files": [{"filename": "src/lib.rs"}],
        "checks": [{"name": "tests / unit", "app": {"slug": "github-actions"}, "workflow_path": ".github/workflows/tests.yml", "event": "pull_request", "head_sha": head, "status": "completed", "conclusion": "success"}],
        "reviews": [{"id": 9, "state": "APPROVED", "commit_id": head, "user": {"id": 2, "login": "reviewer", "type": "User"}}],
        "permissions": {"2": "push"},
    }


class ConsumerTests(unittest.TestCase):
    def setUp(self):
        self.mapping = {"tests": [("tests / unit", "github-actions", ".github/workflows/tests.yml", "pull_request")]}

    def evaluate(self, value):
        return consumer.evaluate_snapshot(value, self.mapping, "owner/repo", 7, "a" * 40, "b" * 40)

    def test_accepts_exact_check_and_current_head_independent_approval(self):
        pr, reviewer, _ = self.evaluate(snapshot())
        self.assertEqual(pr["number"], 7)
        self.assertEqual(reviewer, "reviewer")

    def test_rejects_same_name_from_spoofed_app(self):
        value = snapshot()
        value["checks"][0]["app"]["slug"] = "attacker"
        with self.assertRaisesRegex(consumer.ConsumerError, "exactly once"):
            self.evaluate(value)

    def test_rejects_stale_approval(self):
        value = snapshot()
        value["reviews"][0]["commit_id"] = "c" * 40
        with self.assertRaisesRegex(consumer.ConsumerError, "current-head"):
            self.evaluate(value)

    def test_rejects_incomplete_file_pagination(self):
        value = snapshot()
        value["pull_request"]["changed_files"] = 2
        with self.assertRaisesRegex(consumer.ConsumerError, "pagination"):
            self.evaluate(value)

    def test_evidence_cannot_escape_root(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            candidate = Path(outside) / "evidence.json"
            candidate.write_text(json.dumps(snapshot()), encoding="utf-8")
            with self.assertRaisesRegex(consumer.ConsumerError, "escapes"):
                consumer.verify_evidence_file(Path(root), candidate)

    def test_rejects_non_hex_sha(self):
        value = snapshot()
        value["pull_request"]["head_sha"] = "z" * 40
        with self.assertRaisesRegex(consumer.ConsumerError, "full base/head"):
            self.evaluate(value)

    def test_rejects_untrusted_workflow_with_same_app_and_name(self):
        value = snapshot()
        value["checks"][0]["workflow_path"] = ".github/workflows/attacker.yml"
        with self.assertRaisesRegex(consumer.ConsumerError, "exactly once"):
            self.evaluate(value)

    def test_rejects_cross_repository_replay(self):
        value = snapshot()
        value["repository"] = "other/repo"
        with self.assertRaisesRegex(consumer.ConsumerError, "identity"):
            self.evaluate(value)

    def test_multiple_valid_approvals_selects_latest(self):
        value = snapshot()
        value["reviews"].append({"id": 10, "state": "APPROVED", "commit_id": "b" * 40, "user": {"id": 3, "login": "latest", "type": "User"}})
        value["permissions"]["3"] = "write"
        _, reviewer, _ = self.evaluate(value)
        self.assertEqual(reviewer, "latest")

    def test_rejects_invalid_author_and_identical_shas(self):
        value = snapshot()
        value["pull_request"]["author"]["login"] = " "
        with self.assertRaisesRegex(consumer.ConsumerError, "author"):
            self.evaluate(value)
        value = snapshot()
        value["pull_request"]["base_sha"] = "b" * 40
        with self.assertRaisesRegex(consumer.ConsumerError, "must differ"):
            consumer.evaluate_snapshot(value, self.mapping, "owner/repo", 7, "b" * 40, "b" * 40)

    def test_emitted_packet_passes_rust_v3_validation(self):
        executable = ROOT / "target" / "debug" / ("zero-review.exe" if sys.platform == "win32" else "zero-review")
        if not executable.exists():
            self.skipTest("build zero-review before running the cross-language contract")
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            snapshot_path = work / "snapshot.json"
            map_path = work / "controls.json"
            packet_path = work / "packet.json"
            snapshot_path.write_text(json.dumps(snapshot()), encoding="utf-8")
            map_path.write_text(json.dumps({
                "schema_version": "zero-review.control-check-map.v1",
                "controls": {"tests": [{
                    "name": "tests / unit", "app_slug": "github-actions",
                    "workflow_path": ".github/workflows/tests.yml", "event": "pull_request",
                }]},
            }), encoding="utf-8")
            result = subprocess.run([
                sys.executable, str(ROOT / "scripts" / "github_consumer.py"),
                "--snapshot", str(snapshot_path), "--control-map", str(map_path),
                "--repository", "owner/repo", "--pull-request-number", "7",
                "--base-sha", "a" * 40, "--head-sha", "b" * 40, "--out", str(packet_path),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            validated = subprocess.run([
                str(executable), "validate-review-packet", "--input", str(packet_path),
                "--repository", "owner/repo", "--pull-request-number", "7",
                "--base-sha", "a" * 40, "--head-sha", "b" * 40,
            ], capture_output=True, text=True, check=False)
            self.assertEqual(validated.returncode, 0, validated.stderr)

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symlinks unsupported")
    def test_rejects_symlinked_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            target = root_path / "target.json"
            link = root_path / "link.json"
            target.write_text("{}", encoding="utf-8")
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlink creation is not permitted")
            with self.assertRaisesRegex(consumer.ConsumerError, "symlink"):
                consumer.verify_evidence_file(root_path, link)


if __name__ == "__main__":
    unittest.main()
