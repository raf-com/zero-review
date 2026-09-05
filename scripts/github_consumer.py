#!/usr/bin/env python3
"""Fail-closed evaluator for GitHub PR state captured by a trusted collector."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path


class ConsumerError(ValueError):
    pass


def _strict_object(value, allowed: set[str], required: set[str], label: str) -> dict:
    if not isinstance(value, dict):
        raise ConsumerError(f"{label} must be an object")
    unknown = set(value) - allowed
    missing = required - set(value)
    if unknown:
        raise ConsumerError(f"{label} has unknown fields: {sorted(unknown)}")
    if missing:
        raise ConsumerError(f"{label} is missing fields: {sorted(missing)}")
    return value


def load_control_map(path: Path) -> dict[str, list[tuple[str, str, str, str]]]:
    raw = _strict_object(
        json.loads(path.read_text(encoding="utf-8")),
        {"schema_version", "controls"},
        {"schema_version", "controls"},
        "control map",
    )
    if raw["schema_version"] != "zero-review.control-check-map.v1":
        raise ConsumerError("unsupported control map schema")
    if not isinstance(raw["controls"], dict) or not raw["controls"]:
        raise ConsumerError("control map must contain controls")
    result: dict[str, list[tuple[str, str, str, str]]] = {}
    identities: set[tuple[str, str, str, str]] = set()
    for control, entries in raw["controls"].items():
        if not isinstance(control, str) or not control.strip() or control != control.strip() or not isinstance(entries, list) or not entries:
            raise ConsumerError("control IDs and mappings must be non-empty")
        mapped = []
        for entry in entries:
            item = _strict_object(
                entry,
                {"name", "app_slug", "workflow_path", "event"},
                {"name", "app_slug", "workflow_path", "event"},
                "check mapping",
            )
            identity = (item["name"], item["app_slug"], item["workflow_path"], item["event"])
            if not all(isinstance(x, str) and x for x in identity):
                raise ConsumerError("check identity fields must be non-empty strings")
            if identity in identities:
                raise ConsumerError(f"duplicate trusted check identity: {identity}")
            if identity[0] == "zero-review / consumer":
                raise ConsumerError("consumer job cannot depend on itself")
            identities.add(identity)
            mapped.append(identity)
        result[control] = mapped
    return result


def select_approval(snapshot: dict, head_sha: str, author_id: int) -> str:
    latest: dict[int, dict] = {}
    for review in snapshot.get("reviews", []):
        if not isinstance(review, dict) or not isinstance(review.get("id"), int) or review["id"] <= 0:
            raise ConsumerError("review ID must be a positive integer")
        user = review.get("user") or {}
        user_id = user.get("id")
        if not isinstance(user_id, int):
            raise ConsumerError("review is missing immutable reviewer ID")
        if user_id not in latest or review["id"] > latest[user_id]["id"]:
            latest[user_id] = review
    approved = []
    permissions = snapshot.get("permissions", {})
    for user_id, review in latest.items():
        user = review.get("user") or {}
        login = user.get("login")
        if (
            review.get("state") == "APPROVED"
            and review.get("commit_id") == head_sha
            and user_id != author_id
            and user.get("type") != "Bot"
            and permissions.get(str(user_id)) in {"admin", "maintain", "write", "push"}
        ):
            if not isinstance(login, str) or not login.strip() or login != login.strip():
                raise ConsumerError("approved reviewer login is invalid")
            approved.append((review["id"], login))
    if not approved:
        raise ConsumerError("at least one current-head independent authorized approval is required")
    return max(approved)[1]


def evaluate_snapshot(
    snapshot: dict,
    mappings: dict[str, list[tuple[str, str, str, str]]],
    expected_repository: str,
    expected_pr: int,
    expected_base: str,
    expected_head: str,
) -> tuple[dict, str, datetime]:
    _strict_object(
        snapshot,
        {"repository", "captured_at", "pull_request", "files", "checks", "reviews", "permissions"},
        {"repository", "captured_at", "pull_request", "files", "checks", "reviews", "permissions"},
        "snapshot",
    )
    pr = _strict_object(
        snapshot.get("pull_request"),
        {"number", "state", "author", "base_sha", "head_sha", "changed_files"},
        {"number", "state", "author", "base_sha", "head_sha", "changed_files"},
        "pull request",
    )
    if (
        pr["state"] != "open"
        or not isinstance(pr["base_sha"], str)
        or not isinstance(pr["head_sha"], str)
        or not isinstance(pr["number"], int)
        or pr["number"] <= 0
        or len(pr["base_sha"]) != 40
        or len(pr["head_sha"]) != 40
        or any(character not in "0123456789abcdefABCDEF" for character in pr["base_sha"] + pr["head_sha"])
    ):
        raise ConsumerError("pull request must be open with full base/head SHAs")
    if pr["base_sha"].lower() == pr["head_sha"].lower():
        raise ConsumerError("pull request base and head must differ")
    author = pr["author"]
    if (
        not isinstance(author, dict)
        or not isinstance(author.get("id"), int)
        or author["id"] <= 0
        or not isinstance(author.get("login"), str)
        or not author["login"].strip()
        or author["login"] != author["login"].strip()
    ):
        raise ConsumerError("pull request author identity is incomplete")
    if (
        snapshot["repository"] != expected_repository
        or pr["number"] != expected_pr
        or pr["base_sha"].lower() != expected_base.lower()
        or pr["head_sha"].lower() != expected_head.lower()
    ):
        raise ConsumerError("snapshot does not match expected pull-request identity")
    try:
        captured_at = datetime.fromisoformat(snapshot["captured_at"].replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise ConsumerError("snapshot capture time is invalid") from error
    now = datetime.now(timezone.utc)
    if captured_at.tzinfo is None or captured_at > now or (now - captured_at).total_seconds() > 300:
        raise ConsumerError("snapshot is stale or from the future")
    files = snapshot.get("files")
    if not isinstance(files, list) or len(files) != pr["changed_files"]:
        raise ConsumerError("changed-file pagination is incomplete")
    checks = snapshot.get("checks")
    if not isinstance(checks, list):
        raise ConsumerError("checks must be an array")
    for control, identities in mappings.items():
        for name, app_slug, workflow_path, event in identities:
            matches = [
                check for check in checks
                if check.get("name") == name
                and (check.get("app") or {}).get("slug") == app_slug
                and check.get("workflow_path") == workflow_path
                and check.get("event") == event
            ]
            if len(matches) != 1:
                raise ConsumerError(f"{control}: trusted check identity must occur exactly once")
            check = matches[0]
            if check.get("head_sha") != pr["head_sha"] or check.get("status") != "completed" or check.get("conclusion") != "success":
                raise ConsumerError(f"{control}: trusted check is not a current-head success")
    reviewer = select_approval(snapshot, pr["head_sha"], author["id"])
    return pr, reviewer, captured_at


def verify_evidence_file(root: Path, candidate: Path) -> tuple[str, int]:
    root = root.resolve(strict=True)
    if stat.S_ISLNK(candidate.lstat().st_mode):
        raise ConsumerError("evidence must not be a symlink")
    path = candidate.resolve(strict=True)
    if root != path and root not in path.parents:
        raise ConsumerError("evidence path escapes evidence root")
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ConsumerError("evidence must be a regular non-symlink file")
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest(), len(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--control-map", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pull-request-number", type=int, required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.out.exists() or args.out.is_symlink():
            raise ConsumerError("output path already exists")
        started_at = datetime.now(timezone.utc)
        snapshot_bytes = args.snapshot.read_bytes()
        snapshot = json.loads(snapshot_bytes)
        mappings = load_control_map(args.control_map)
        pr, reviewer, captured_at = evaluate_snapshot(
            snapshot, mappings, args.repository, args.pull_request_number, args.base_sha, args.head_sha
        )
        path_digest, path_size = verify_evidence_file(args.snapshot.parent, args.snapshot)
        digest = hashlib.sha256(snapshot_bytes).hexdigest()
        size = len(snapshot_bytes)
        if (digest, size) != (path_digest, path_size):
            raise ConsumerError("snapshot changed while being evaluated")
        completed_at = datetime.now(timezone.utc)
        started = started_at.isoformat().replace("+00:00", "Z")
        completed = completed_at.isoformat().replace("+00:00", "Z")
        captured = captured_at.isoformat().replace("+00:00", "Z")
        executable = Path(sys.executable)
        exe_digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        packet = {
            "schema_version": "zero-review.review-packet.v3",
            "context": {
                "schema_version": "zero-review.pr-context.v1",
                "repository": args.repository,
                "pull_request_number": pr["number"],
                "author": pr["author"]["login"],
                "base_sha": pr["base_sha"],
                "head_sha": pr["head_sha"],
                "captured_at": captured,
            },
            "reviewer": reviewer,
            "disposition": "approve",
            "summary": "Trusted GitHub snapshot satisfied mapped checks and current-head approval.",
            "required_controls": list(mappings),
            "evidence": [{
                "schema_version": "zero-review.evidence.v2", "control_id": control_id,
                "kind": "github-api-snapshot", "status": "verified", "location": str(args.snapshot),
                "sha256": digest, "byte_length": size,
                "command": [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
                "executable_sha256": f"sha256:{exe_digest}", "exit_code": 0,
                "started_at": started, "completed_at": completed,
            } for control_id in mappings],
            "reviewed_at": completed,
        }
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8", newline="\n") as output:
            output.write(json.dumps(packet, indent=2) + "\n")
        return 0
    except (OSError, json.JSONDecodeError, ConsumerError, KeyError, TypeError) as error:
        print(f"github consumer blocked: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
