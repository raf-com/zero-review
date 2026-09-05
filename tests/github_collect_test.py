import importlib.util
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("github_collect", ROOT / "scripts" / "github_collect.py")
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class CollectorContractTests(unittest.TestCase):
    def test_rejects_insecure_or_ambiguous_api_bases(self):
        for value in (
            "http://api.github.com", "https://user@api.github.com",
            "https://api.github.com/?redirect=1", "https://api.github.com/#fragment",
            "https://api.github.com/unexpected",
        ):
            with self.subTest(value=value), self.assertRaises(collector.CollectError):
                collector.GitHubClient(value, "token")

    def test_accepts_github_and_enterprise_api_origins(self):
        self.assertEqual(collector.GitHubClient("https://api.github.com", "token").origin, ("https", "api.github.com"))
        self.assertEqual(collector.GitHubClient("https://github.example/api/v3", "token").origin, ("https", "github.example"))

    def test_redirect_handler_never_forwards_request(self):
        handler = collector.NoRedirect()
        request = urllib.request.Request("https://api.github.com/repos/o/r")
        self.assertIsNone(handler.redirect_request(request, None, 302, "Found", {}, "https://attacker.example"))

    def test_pr_identity_requires_complete_typed_fields(self):
        with self.assertRaises(collector.CollectError):
            collector.pr_identity({"number": 1})

    def test_unique_identity_rejects_duplicates(self):
        with self.assertRaisesRegex(collector.CollectError, "ambiguous"):
            collector.require_unique([{"id": 1}, {"id": 1}], "id", "reviews")


if __name__ == "__main__":
    unittest.main()
