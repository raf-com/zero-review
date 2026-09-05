import hashlib
import importlib.util
import subprocess
import tempfile
import unittest
from io import BytesIO
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "release_verify.py"
SPEC = importlib.util.spec_from_file_location("release_verify", MODULE_PATH)
release_verify = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(release_verify)


class Response:
    def __init__(self, body: bytes, url: str, length: str | None = None):
        self.body = BytesIO(body)
        self.url = url
        self.headers = {} if length is None else {"Content-Length": length}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, size=-1):
        return self.body.read(size)

    def geturl(self):
        return self.url


class Opener:
    def __init__(self, response):
        self.response = response
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return self.response


class ReleaseVerifyTest(unittest.TestCase):
    def test_accepts_exact_release_url(self):
        url = "https://github.com/raf-com/zero-review/releases/download/v1.2.3/zero-review.exe"
        self.assertEqual(url, release_verify.validate_release_url(
            url, "raf-com/zero-review", "v1.2.3", "zero-review.exe"
        ))

    def test_rejects_wrong_repository_query_and_http(self):
        cases = [
            "https://github.com/other/zero-review/releases/download/v1/a.exe",
            "https://github.com/raf-com/zero-review/releases/download/v1/a.exe?token=x",
            "http://github.com/raf-com/zero-review/releases/download/v1/a.exe",
        ]
        for url in cases:
            with self.subTest(url=url), self.assertRaises(release_verify.VerificationError):
                release_verify.validate_release_url(url, "raf-com/zero-review", "v1", "a.exe")

    def test_download_hashes_and_atomically_publishes(self):
        body = b"trusted release bytes"
        digest = hashlib.sha256(body).hexdigest()
        final = "https://release-assets.githubusercontent.com/github-production-release-asset/x"
        opener = Opener(Response(body, final, str(len(body))))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "asset.bin"
            size, actual = release_verify.download_and_hash(
                "https://github.com/raf-com/zero-review/releases/download/v1/asset.bin",
                output, digest, 1024, opener,
            )
            self.assertEqual((len(body), digest), (size, actual))
            self.assertEqual(body, output.read_bytes())
            self.assertFalse(output.with_name("asset.bin.part").exists())

    def test_digest_mismatch_removes_partial_output(self):
        opener = Opener(Response(b"wrong", "https://github.com/a/b/releases/download/v1/x"))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "x"
            with self.assertRaises(release_verify.VerificationError):
                release_verify.download_and_hash("https://github.com/a/b/releases/download/v1/x", output, "0" * 64, 100, opener)
            self.assertFalse(output.exists())
            self.assertFalse(output.with_name("x.part").exists())

    def test_rejects_oversize_declared_and_streamed_content(self):
        for length in ("11", None):
            opener = Opener(Response(b"01234567890", "https://github.com/a/b/releases/download/v1/x", length))
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(release_verify.VerificationError):
                    release_verify.download_and_hash(
                        "https://github.com/a/b/releases/download/v1/x", Path(directory) / "x", "0" * 64, 10, opener
                    )

    def test_rejects_response_outside_allowlist(self):
        opener = Opener(Response(b"x", "https://evil.example/x"))
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(release_verify.VerificationError):
            release_verify.download_and_hash(
                "https://github.com/a/b/releases/download/v1/x", Path(directory) / "x",
                hashlib.sha256(b"x").hexdigest(), 10, opener,
            )

    def test_attestation_command_has_bound_expectations(self):
        command = release_verify.attestation_command(
            Path("asset.bin"), "raf-com/zero-review",
            "raf-com/zero-review/.github/workflows/release.yml", "refs/tags/v1.2.3",
        )
        self.assertEqual([
            "gh", "attestation", "verify", "asset.bin", "--repo", "raf-com/zero-review",
            "--signer-workflow", "raf-com/zero-review/.github/workflows/release.yml",
            "--source-ref", "refs/tags/v1.2.3",
        ], command)

    def test_attestation_invocation_is_argv_only_and_fail_closed(self):
        calls = []
        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 1, "", "bad")
        with self.assertRaises(release_verify.VerificationError):
            release_verify.verify_attestation(
                Path("asset.bin"), "raf-com/zero-review",
                "raf-com/zero-review/.github/workflows/release.yml", "refs/tags/v1", runner,
            )
        self.assertEqual(60, calls[0][1]["timeout"])
        self.assertFalse(calls[0][1]["check"])

    def test_rejects_foreign_workflow_and_non_tag_ref(self):
        for workflow, ref in [
            ("evil/repo/.github/workflows/release.yml", "refs/tags/v1"),
            ("raf-com/zero-review/.github/workflows/release.yml", "refs/heads/main"),
        ]:
            with self.assertRaises(release_verify.VerificationError):
                release_verify.attestation_command(Path("x"), "raf-com/zero-review", workflow, ref)


if __name__ == "__main__":
    unittest.main()
