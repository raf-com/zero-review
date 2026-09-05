#!/usr/bin/env python3
"""Read-only, fail-closed GitHub snapshot collector for zero-review."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_PAGES = 100
MAX_ITEMS = 10_000
MAX_WORKFLOW_RUNS = 250
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


class CollectError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHubClient:
    def __init__(self, api_base: str, token: str) -> None:
        parsed = urllib.parse.urlsplit(api_base.rstrip("/"))
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/", "/api/v3"}
        ):
            raise CollectError("API base must be an HTTPS origin without credentials")
        self.api_base = api_base.rstrip("/")
        self.origin = (parsed.scheme, parsed.netloc)
        self.opener = urllib.request.build_opener(NoRedirect())
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "zero-review-github-collector/1",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _url(self, path: str, query: dict[str, object] | None = None) -> str:
        if not path.startswith("/"):
            raise CollectError("GitHub API path must be absolute")
        url = self.api_base + path
        return url if not query else url + "?" + urllib.parse.urlencode(query)

    def get(self, url: str) -> tuple[object, dict[str, str]]:
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme, parsed.netloc) != self.origin or parsed.username or parsed.password:
            raise CollectError("pagination escaped the configured GitHub API origin")
        request = urllib.request.Request(url, headers=self.headers, method="GET")
        try:
            with self.opener.open(request, timeout=30) as response:
                final = urllib.parse.urlsplit(response.geturl())
                if (final.scheme, final.netloc) != self.origin:
                    raise CollectError("GitHub API response escaped the configured origin")
                length = response.headers.get("Content-Length")
                if length and int(length) > MAX_RESPONSE_BYTES:
                    raise CollectError("GitHub API response exceeds the byte limit")
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise CollectError("GitHub API response exceeds the byte limit")
                headers = {key.lower(): value for key, value in response.headers.items()}
        except urllib.error.HTTPError as error:
            remaining = error.headers.get("X-RateLimit-Remaining", "unknown")
            reason = "rate limited" if error.code in {403, 429} and remaining == "0" else f"HTTP {error.code}"
            raise CollectError(f"GitHub API request failed: {reason}") from error
        except (urllib.error.URLError, TimeoutError, ValueError) as error:
            raise CollectError(f"GitHub API request failed: {error}") from error
        if headers.get("x-ratelimit-remaining") == "0":
            raise CollectError("GitHub API rate limit exhausted during collection")
        try:
            return json.loads(body), headers
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CollectError("GitHub API returned invalid JSON") from error

    @staticmethod
    def _next_link(value: str | None) -> str | None:
        if not value:
            return None
        relations: dict[str, str] = {}
        for entry in value.split(","):
            match = re.fullmatch(r'\s*<([^>]+)>\s*;\s*rel="([^"]+)"\s*', entry)
            if not match:
                raise CollectError("GitHub pagination Link header is malformed")
            for relation in match.group(2).split():
                if relation in relations:
                    raise CollectError("GitHub pagination relation is ambiguous")
                relations[relation] = match.group(1)
        return relations.get("next")

    def paginated(self, path: str, key: str | None = None, query: dict[str, object] | None = None) -> list[dict]:
        parameters = dict(query or {})
        parameters["per_page"] = 100
        url = self._url(path, parameters)
        items: list[dict] = []
        seen: set[str] = set()
        expected_total: int | None = None
        for _ in range(MAX_PAGES):
            if url in seen:
                raise CollectError("GitHub pagination loop detected")
            seen.add(url)
            payload, headers = self.get(url)
            if key is None:
                page = payload
            else:
                if not isinstance(payload, dict) or not isinstance(payload.get(key), list):
                    raise CollectError(f"GitHub response is missing {key}")
                page = payload[key]
                total = payload.get("total_count")
                if not isinstance(total, int) or total < 0:
                    raise CollectError("GitHub paginated response has invalid total_count")
                if expected_total is None:
                    expected_total = total
                elif expected_total != total:
                    raise CollectError("GitHub collection changed during pagination")
            if not isinstance(page, list) or not all(isinstance(item, dict) for item in page):
                raise CollectError("GitHub paginated response is not an object array")
            items.extend(page)
            if len(items) > MAX_ITEMS:
                raise CollectError("GitHub collection exceeds the item limit")
            url = self._next_link(headers.get("link"))
            if url is None:
                if expected_total is not None and len(items) != expected_total:
                    raise CollectError("GitHub pagination is incomplete")
                return items
        raise CollectError("GitHub collection exceeds the page limit")


def require_object(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise CollectError(f"{label} is not an object")
    return value


def require_unique(items: list[dict], field: str, label: str) -> None:
    values = [item.get(field) for item in items]
    if any(value is None for value in values) or len(set(values)) != len(values):
        raise CollectError(f"{label} identities are missing or ambiguous")


def pr_identity(raw: dict) -> dict:
    base = require_object(raw.get("base"), "pull request base")
    head = require_object(raw.get("head"), "pull request head")
    user = require_object(raw.get("user"), "pull request author")
    result = {
        "number": raw.get("number"), "state": raw.get("state"),
        "author": {"id": user.get("id"), "login": user.get("login")},
        "base_sha": base.get("sha"), "head_sha": head.get("sha"),
        "changed_files": raw.get("changed_files"),
    }
    if not isinstance(result["number"], int) or result["number"] <= 0:
        raise CollectError("pull request number is invalid")
    if result["state"] != "open" or not SHA_RE.fullmatch(str(result["base_sha"])) or not SHA_RE.fullmatch(str(result["head_sha"])):
        raise CollectError("pull request must be open with full base/head SHAs")
    if not isinstance(result["changed_files"], int) or result["changed_files"] < 0:
        raise CollectError("pull request changed_files is invalid")
    if not isinstance(result["author"]["id"], int) or not isinstance(result["author"]["login"], str):
        raise CollectError("pull request author identity is incomplete")
    return result


def collect(args: argparse.Namespace) -> dict:
    if not REPOSITORY_RE.fullmatch(args.repository):
        raise CollectError("repository must be owner/name")
    if args.pull_request_number <= 0 or not SHA_RE.fullmatch(args.base_sha) or not SHA_RE.fullmatch(args.head_sha):
        raise CollectError("trusted PR number and base/head SHAs are required")
    token = os.environ.get(args.token_env)
    if not token or token != token.strip():
        raise CollectError(f"token environment variable {args.token_env} is missing or invalid")
    client = GitHubClient(args.api_base, token)
    repo_path = "/repos/" + urllib.parse.quote(args.repository, safe="/")
    pr_path = f"{repo_path}/pulls/{args.pull_request_number}"
    initial = pr_identity(require_object(client.get(client._url(pr_path))[0], "pull request"))
    expected = (args.pull_request_number, args.base_sha.lower(), args.head_sha.lower())
    actual = (initial["number"], initial["base_sha"].lower(), initial["head_sha"].lower())
    if actual != expected:
        raise CollectError("GitHub pull request does not match trusted inputs")

    files = client.paginated(pr_path + "/files")
    if len(files) != initial["changed_files"]:
        raise CollectError("changed-file pagination is incomplete")
    checks = client.paginated(f"{repo_path}/commits/{args.head_sha}/check-runs", "check_runs")
    reviews = client.paginated(pr_path + "/reviews")
    runs = client.paginated(f"{repo_path}/actions/runs", "workflow_runs", {"head_sha": args.head_sha})
    require_unique(files, "filename", "changed-file")
    require_unique(checks, "id", "check-run")
    require_unique(reviews, "id", "review")
    require_unique(runs, "id", "workflow-run")
    if len(runs) > MAX_WORKFLOW_RUNS:
        raise CollectError("too many workflow runs to correlate safely")

    job_to_run: dict[int, tuple[str, str]] = {}
    for run in runs:
        run_id = run.get("id")
        path, event, run_head = run.get("path"), run.get("event"), run.get("head_sha")
        if not isinstance(run_id, int) or not isinstance(path, str) or not isinstance(event, str) or run_head != args.head_sha:
            raise CollectError("workflow run correlation identity is incomplete")
        for job in client.paginated(f"{repo_path}/actions/runs/{run_id}/jobs", "jobs"):
            check_url = job.get("check_run_url")
            match = re.search(r"/check-runs/(\d+)$", check_url or "")
            if not match:
                raise CollectError("workflow job is missing check-run correlation")
            check_id = int(match.group(1))
            identity = (path, event)
            if check_id in job_to_run:
                raise CollectError("check run has ambiguous workflow correlation")
            job_to_run[check_id] = identity

    projected_checks = []
    for check in checks:
        app = require_object(check.get("app"), "check app")
        correlation = job_to_run.get(check.get("id"))
        if correlation is None:
            raise CollectError("check run lacks workflow-run correlation")
        projected_checks.append({
            "id": check.get("id"), "name": check.get("name"), "head_sha": check.get("head_sha"),
            "status": check.get("status"), "conclusion": check.get("conclusion"),
            "app": {"id": app.get("id"), "slug": app.get("slug")},
            "workflow_path": correlation[0] if correlation else None,
            "event": correlation[1] if correlation else None,
        })

    permissions: dict[str, str] = {}
    identities: dict[int, str] = {}
    for review in reviews:
        user = require_object(review.get("user"), "review user")
        user_id, login = user.get("id"), user.get("login")
        if not isinstance(user_id, int) or not isinstance(login, str) or not login:
            raise CollectError("reviewer identity is incomplete")
        if user_id in identities and identities[user_id] != login:
            raise CollectError("reviewer immutable identity is ambiguous")
        identities[user_id] = login
    for user_id, login in identities.items():
        encoded = urllib.parse.quote(login, safe="")
        permission_raw = require_object(client.get(client._url(f"{repo_path}/collaborators/{encoded}/permission"))[0], "permission")
        permission = permission_raw.get("permission")
        if permission not in {"none", "read", "triage", "write", "maintain", "admin"}:
            raise CollectError("collaborator permission is invalid")
        permissions[str(user_id)] = permission

    final = pr_identity(require_object(client.get(client._url(pr_path))[0], "pull request re-fetch"))
    if final != initial:
        raise CollectError("pull request moved while GitHub state was collected")
    return {
        "repository": args.repository,
        "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "pull_request": final,
        "files": [{"filename": item.get("filename"), "status": item.get("status"), "sha": item.get("sha")} for item in files],
        "checks": projected_checks,
        "reviews": [{
            "id": item.get("id"), "state": item.get("state"), "commit_id": item.get("commit_id"),
            "submitted_at": item.get("submitted_at"),
            "user": {key: (item.get("user") or {}).get(key) for key in ("id", "login", "type")},
        } for item in reviews],
        "permissions": permissions,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pull-request-number", type=int, required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--api-base", default="https://api.github.com")
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    args = parser.parse_args()
    try:
        if args.out.exists() or args.out.is_symlink():
            raise CollectError("output path already exists")
        snapshot = collect(args)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8", newline="\n") as output:
            output.write(json.dumps(snapshot, indent=2) + "\n")
        return 0
    except (CollectError, OSError, TypeError, KeyError) as error:
        print(f"github collector blocked: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
