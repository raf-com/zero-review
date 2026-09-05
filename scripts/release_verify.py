#!/usr/bin/env python3
"""Fail-closed verifier for an immutable GitHub release asset."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable


DEFAULT_MAX_BYTES = 128 * 1024 * 1024
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
REDIRECT_HOSTS = frozenset({
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "github-releases.githubusercontent.com",
})


class VerificationError(ValueError):
    pass


def _safe_component(value: str, label: str) -> str:
    if not value or value in {".", ".."} or "/" in value or "\\" in value:
        raise VerificationError(f"{label} is not a safe path component")
    return value


def validate_release_url(url: str, repository: str, tag: str, asset: str) -> str:
    """Require the canonical, immutable GitHub release asset URL identity."""
    if not REPOSITORY_RE.fullmatch(repository):
        raise VerificationError("repository must be owner/name")
    if not TAG_RE.fullmatch(tag):
        raise VerificationError("tag is invalid")
    _safe_component(asset, "asset")
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.port is not None
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise VerificationError("release URL must be an unadorned HTTPS github.com URL")
    owner, name = repository.split("/", 1)
    expected = "/" + "/".join(
        urllib.parse.quote(part, safe="")
        for part in (owner, name, "releases", "download", tag, asset)
    )
    if parsed.path != expected:
        raise VerificationError("release URL does not match repository, tag, and asset")
    return url


class ReleaseRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Permit redirects only to GitHub's dedicated release-asset origins."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in REDIRECT_HOSTS
            or parsed.port is not None
            or parsed.username
            or parsed.password
        ):
            raise VerificationError("release download redirect escaped the allowlist")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_and_hash(
    url: str,
    output: Path,
    expected_sha256: str,
    max_bytes: int = DEFAULT_MAX_BYTES,
    opener=None,
) -> tuple[int, str]:
    """Download to a temporary sibling and publish only after digest verification."""
    if not SHA256_RE.fullmatch(expected_sha256):
        raise VerificationError("expected SHA-256 must be 64 hexadecimal characters")
    if max_bytes <= 0:
        raise VerificationError("maximum download size must be positive")
    output = output.resolve()
    temporary = output.with_name(output.name + ".part")
    if output.exists() or temporary.exists():
        raise VerificationError("output and temporary paths must not already exist")
    output.parent.mkdir(parents=True, exist_ok=True)
    client = opener or urllib.request.build_opener(ReleaseRedirectHandler())
    request = urllib.request.Request(url, headers={"User-Agent": "zero-review-release-verifier/1"})
    digest = hashlib.sha256()
    size = 0
    try:
        with client.open(request, timeout=30) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname not in ({"github.com"} | REDIRECT_HOSTS):
                raise VerificationError("release download response escaped the allowlist")
            length = response.headers.get("Content-Length")
            if length is not None:
                try:
                    declared = int(length)
                except ValueError as error:
                    raise VerificationError("release asset Content-Length is invalid") from error
                if declared < 0 or declared > max_bytes:
                    raise VerificationError("release asset exceeds the byte limit")
            with temporary.open("xb") as handle:
                while True:
                    chunk = response.read(min(1024 * 1024, max_bytes - size + 1))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > max_bytes:
                        raise VerificationError("release asset exceeds the byte limit")
                    digest.update(chunk)
                    handle.write(chunk)
        actual = digest.hexdigest()
        if actual.lower() != expected_sha256.lower():
            raise VerificationError("release asset SHA-256 does not match")
        os.replace(temporary, output)
        return size, actual
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as error:
        raise VerificationError(f"release download failed: {error}") from error
    finally:
        if temporary.exists():
            temporary.unlink()


def attestation_command(
    asset: Path, repository: str, signer_workflow: str, source_ref: str
) -> list[str]:
    if not REPOSITORY_RE.fullmatch(repository):
        raise VerificationError("repository must be owner/name")
    expected_prefix = repository + "/.github/workflows/"
    if not signer_workflow.startswith(expected_prefix) or signer_workflow.endswith("/"):
        raise VerificationError("signer workflow must identify a workflow in the repository")
    if not source_ref.startswith("refs/tags/") or source_ref == "refs/tags/":
        raise VerificationError("source ref must be a full tag ref")
    return [
        "gh", "attestation", "verify", str(asset),
        "--repo", repository,
        "--signer-workflow", signer_workflow,
        "--source-ref", source_ref,
    ]


def verify_attestation(
    asset: Path,
    repository: str,
    signer_workflow: str,
    source_ref: str,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> None:
    command = attestation_command(asset, repository, signer_workflow, source_ref)
    try:
        completed = runner(command, check=False, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as error:
        raise VerificationError(f"GitHub attestation verification could not run: {error}") from error
    if completed.returncode != 0:
        raise VerificationError("GitHub attestation verification failed")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--url", required=True)
    result.add_argument("--repository", required=True)
    result.add_argument("--tag", required=True)
    result.add_argument("--asset", required=True)
    result.add_argument("--sha256", required=True)
    result.add_argument("--output", required=True, type=Path)
    result.add_argument("--signer-workflow", required=True)
    result.add_argument("--source-ref", required=True)
    result.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        url = validate_release_url(args.url, args.repository, args.tag, args.asset)
        download_and_hash(url, args.output, args.sha256, args.max_bytes)
        verify_attestation(args.output.resolve(), args.repository, args.signer_workflow, args.source_ref)
    except VerificationError as error:
        print(f"release verification failed: {error}", file=sys.stderr)
        return 1
    print(f"release verification passed: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
