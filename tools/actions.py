"""Bind GitHub Actions artifacts to live provider facts without promoting origin checks to release qualification."""

from collections.abc import Callable
import argparse
import base64
import datetime as dt
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import urllib.error
import urllib.request
import zipfile

from tools import verify as v

# Provider responses and compressed artifacts have independent finite budgets.
API = "https://api.github.com"
ARCHIVE = 256 * 1024 * 1024
EXPANDED = 1024 * 1024 * 1024
MEMBERS = 4096


class Redirect(urllib.request.HTTPRedirectHandler):
    """Never forward credentials to an API-supplied redirect or follow an unapproved host."""

    def redirect_request(self, request: urllib.request.Request, response: object, code: int, message: str, headers: object, url: str) -> None:
        """Reject every redirect; this client reads metadata, not temporary artifact URLs."""
        v.reject("actions-api-redirect")


class Client:
    """Read bounded GitHub metadata and retain exact response bytes for later inspection."""

    def __init__(self, token: str, output: Path) -> None:
        """Keep a nonempty token in memory and write only nonsecret response bodies."""
        if not token or any(ord(char) < 33 or ord(char) > 126 for char in token):
            v.reject("actions-token")
        self.token = token
        self.output = output
        self.records = []
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirect())

    def get(self, path: str) -> object:
        """Fetch only a constructed API path, with no automatic retries or redirect traversal."""
        if not re.fullmatch(r"/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_./?=&-]+", path) or ".." in path:
            v.reject("actions-api-path")
        request = urllib.request.Request(
            API + path,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + self.token,
                "User-Agent": "astra-evidence",
                "X-GitHub-Api-Version": "2026-03-10",
            },
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                if response.status != 200:
                    v.reject("actions-api-status", str(response.status))
                body = response.read(v.LIMIT + 1)
        except urllib.error.HTTPError as error:
            # Error response bodies may contain provider diagnostics; do not echo them or request headers.
            v.reject("actions-api-status", str(error.code))
        except (urllib.error.URLError, TimeoutError, OSError):
            v.reject("actions-api-unavailable")
        value = v.decode(body)
        item = v.write_new(self.output / f"response-{len(self.records)}.json", body)
        self.records.append({"endpoint": path, **item})
        return value


def expect(condition: bool, reason: str) -> None:
    """Reject a failed predicate without interpreting missing facts as success."""
    if not condition:
        v.reject("actions-" + reason)


def object_(value: object, reason: str) -> dict:
    """Translate malformed provider object boundaries into a stable rejection."""
    expect(isinstance(value, dict), reason)
    return value


def integer(value: object) -> bool:
    """Distinguish positive provider identifiers from booleans and numeric strings."""
    return type(value) is int and value > 0


def policy(value: object, now: dt.datetime) -> dict:
    """Validate the externally supplied expectation and its finite validity interval."""
    v.schema(value, "actions")
    expect(v.stamp(value["not_before"]) <= now < v.stamp(value["expires_at"]), "policy-time")
    expect(len({job["name"] for job in value["jobs"]}) == len(value["jobs"]), "duplicate-job")
    expect(len({item["id"] for item in value["artifacts"]}) == len(value["artifacts"]), "duplicate-artifact")
    expect(len({item["platform"] for item in value["artifacts"]}) == len(value["artifacts"]), "duplicate-platform")
    for job in value["jobs"]:
        expect(len(set(job["steps"])) == len(job["steps"]), "duplicate-step")
    return value


def run(value: object, expected: dict) -> dict:
    """Bind the exact attempt, workflow, source commit, repository and invoking identities."""
    value = object_(value, "run-shape")
    for key, target in (("id", "run_id"), ("run_attempt", "attempt"), ("workflow_id", "workflow_id")):
        expect(integer(value.get(key)) and value[key] == expected[target], "run-" + key)
    for key in ("head_sha", "head_branch"):
        expect(value.get(key) == expected[key], "run-" + key)
    expect(value.get("path") == expected["workflow_path"], "workflow-path")
    expect(value.get("event") == "workflow_dispatch", "run-event")
    expect(value.get("status") == "completed" and value.get("conclusion") == "success", "run-terminal")
    for name in ("repository", "head_repository"):
        repo = object_(value.get(name), "repository-shape")
        expect(integer(repo.get("id")) and repo["id"] == expected["repository_id"], "repository-id")
        expect(repo.get("full_name") == expected["repository"], "repository-name")
    for name in ("actor", "triggering_actor"):
        actor = object_(value.get(name), "actor-shape")
        expect(integer(actor.get("id")) and actor["id"] == expected[name + "_id"], "actor-id")
    started, updated = v.stamp(value.get("run_started_at", "")), v.stamp(value.get("updated_at", ""))
    expect(v.stamp(expected["not_before"]) <= started <= updated < v.stamp(expected["expires_at"]), "run-time")
    return value


def jobs(get: Callable[[str], object], prefix: str, expected: dict) -> list[dict]:
    """Read the complete attempt-specific job list, rejecting skipped steps, duplicates and unstable pagination."""
    result, total = [], None
    for page in range(1, 42):
        value = object_(get(prefix + f"/jobs?per_page=100&page={page}"), "jobs-shape")
        count = value.get("total_count")
        expect(integer(count) and count <= MEMBERS and (total is None or count == total), "jobs-count")
        total = count
        chunk = value.get("jobs")
        expect(isinstance(chunk, list) and 0 < len(chunk) <= 100, "jobs-page")
        result.extend(chunk)
        expect(len(result) <= total, "jobs-count")
        if len(result) == total:
            break
    expect(len(result) == total, "jobs-incomplete")
    names, ids = set(), set()
    by_name = {job["name"]: job for job in expected["jobs"]}
    expect(len(result) == len(by_name), "jobs-matrix")
    for item in result:
        item = object_(item, "job-shape")
        name = item.get("name")
        expect(isinstance(name, str) and name in by_name and name not in names, "job-name")
        expect(integer(item.get("id")) and item["id"] not in ids, "job-id")
        names.add(name)
        ids.add(item["id"])
        for key, target in (("run_id", "run_id"), ("run_attempt", "attempt")):
            expect(integer(item.get(key)) and item[key] == expected[target], "job-" + key)
        expect(item.get("head_sha") == expected["head_sha"], "job-source")
        expect(item.get("status") == "completed" and item.get("conclusion") == "success", "job-terminal")
        started, ended = v.stamp(item.get("started_at", "")), v.stamp(item.get("completed_at", ""))
        expect(v.stamp(expected["not_before"]) <= started <= ended < v.stamp(expected["expires_at"]), "job-time")
        steps = item.get("steps")
        expect(isinstance(steps, list) and 0 < len(steps) <= MEMBERS, "steps-shape")
        found, numbers = set(), set()
        for step in steps:
            step = object_(step, "step-shape")
            expect(isinstance(step.get("name"), str) and step["name"] not in found, "step-name")
            expect(integer(step.get("number")) and step["number"] not in numbers, "step-number")
            found.add(step["name"])
            numbers.add(step["number"])
            expect(step.get("status") == "completed" and step.get("conclusion") == "success", "step-terminal")
        expect(set(by_name[name]["steps"]) <= found, "steps-required")
    return result


def archive(path: Path, expected: dict, item: dict, metadata: dict) -> dict:
    """Check one bounded ZIP from live provider digest through every sealed file; never extract or execute it."""
    raw = v.read(path, ARCHIVE)
    digest = v.digest(raw)
    expect(metadata.get("digest") == "sha256:" + digest, "archive-digest")
    expect(integer(metadata.get("size_in_bytes")) and metadata["size_in_bytes"] == len(raw), "archive-size")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as container:
            entries = container.infolist()
            expect(0 < len(entries) <= MEMBERS, "archive-count")
            files, names, size = {}, set(), 0
            for entry in entries:
                # ZipInfo normalizes host separators and truncates NULs; validate the wire identity before using it.
                name = entry.orig_filename
                expect(name == entry.filename, "archive-path")
                parsed = PurePosixPath(name)
                expect(bool(name) and "\\" not in name and ":" not in name and not parsed.is_absolute(), "archive-path")
                expect(all(part not in ("", ".", "..") and not part.endswith((".", " ")) for part in name.split("/")), "archive-path")
                expect(not any(ord(char) < 32 for char in name), "archive-path")
                expect(name.casefold() not in names, "archive-duplicate")
                names.add(name.casefold())
                kind = stat.S_IFMT(entry.external_attr >> 16)
                expect(not entry.is_dir() and kind in (0, stat.S_IFREG) and not entry.flag_bits & 1, "archive-entry")
                expect(entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "archive-compression")
                size += entry.file_size
                expect(size <= EXPANDED, "archive-expanded")
                count, checksum = 0, hashlib.sha256()
                data = bytearray() if name == "manifest.json" else None
                with container.open(entry) as stream:
                    while block := stream.read(1024 * 1024):
                        count += len(block)
                        expect(count <= entry.file_size, "archive-entry-size")
                        checksum.update(block)
                        if data is not None:
                            expect(count <= v.LIMIT, "manifest-size")
                            data.extend(block)
                expect(count == entry.file_size, "archive-entry-size")
                files[name] = {"bytes": count, "sha256": checksum.hexdigest(), "data": data}
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError) as error:
        v.reject("actions-archive-invalid", type(error).__name__)
    expect("manifest.json" in files, "manifest-missing")
    manifest = v.decode(files.pop("manifest.json")["data"])
    object_(manifest, "manifest-shape")
    expect(
        set(manifest) == {"schema_version", "repository_id", "run_id", "attempt", "head_sha", "platform", "policy", "source", "collector", "files"},
        "manifest-fields",
    )
    expect(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1, "manifest-version")
    for key in ("repository_id", "run_id", "attempt", "head_sha", "policy", "source", "collector"):
        expect(type(manifest[key]) is type(expected[key]) and manifest[key] == expected[key], "manifest-" + key)
    expect(manifest["platform"] == item["platform"], "manifest-platform")
    declared = manifest["files"]
    expect(isinstance(declared, list) and 0 < len(declared) <= MEMBERS, "manifest-files")
    named = set()
    for record in declared:
        object_(record, "manifest-file")
        expect(set(record) == {"path", "bytes", "sha256"} and isinstance(record["path"], str), "manifest-file-fields")
        name = record["path"]
        expect(name in files and name not in named, "manifest-file-name")
        named.add(name)
        expect(type(record["bytes"]) is int and record["bytes"] == files[name]["bytes"], "manifest-file-size")
        expect(record["sha256"] == files[name]["sha256"], "manifest-file-digest")
    expect(named == set(files), "manifest-extra-files")
    return {"id": item["id"], "platform": item["platform"], "bytes": len(raw), "sha256": digest, "files": declared}


def inspect(get: Callable[[str], object], expected: dict, archives: list[Path], now: dt.datetime) -> dict:
    """Reconcile live provider facts with pinned expectations and locally supplied artifact bytes."""
    policy(expected, now)
    expect(len(archives) == len(expected["artifacts"]), "archive-matrix")
    prefix = "/repos/" + expected["repository"]
    endpoint = prefix + f"/actions/runs/{expected['run_id']}/attempts/{expected['attempt']}"
    before = run(get(endpoint), expected)
    workflow = object_(get(prefix + f"/contents/{expected['workflow_path']}?ref={expected['head_sha']}"), "workflow-shape")
    expect(workflow.get("type") == "file" and workflow.get("path") == expected["workflow_path"] and workflow.get("encoding") == "base64", "workflow-file")
    content = workflow.get("content")
    expect(isinstance(content, str), "workflow-content")
    try:
        raw = base64.b64decode(content.replace("\n", ""), validate=True)
    except ValueError:
        v.reject("actions-workflow-base64")
    expect(v.digest(raw) == expected["workflow_sha256"], "workflow-digest")
    observed = jobs(get, endpoint, expected)
    results = []
    for path, item in zip(archives, expected["artifacts"]):
        artifact = object_(get(prefix + f"/actions/artifacts/{item['id']}"), "artifact-shape")
        expect(integer(artifact.get("id")) and artifact["id"] == item["id"], "artifact-id")
        expect(artifact.get("name") == f"astra-{expected['run_id']}-{expected['attempt']}-{item['platform']}", "artifact-name")
        expect(artifact.get("expired") is False, "artifact-expired")
        expect(v.stamp(artifact.get("created_at", "")) >= v.stamp(before["run_started_at"]), "artifact-created")
        expect(v.stamp(artifact.get("expires_at", "")) > now, "artifact-expired")
        binding = object_(artifact.get("workflow_run"), "artifact-run")
        for key, target in (
            ("id", "run_id"),
            ("repository_id", "repository_id"),
            ("head_repository_id", "repository_id"),
            ("head_sha", "head_sha"),
            ("head_branch", "head_branch"),
        ):
            expect(type(binding.get(key)) is type(expected[target]) and binding[key] == expected[target], "artifact-binding")
        results.append(archive(path, expected, item, artifact))
    after = run(get(endpoint), expected)
    expect(before == after, "run-changed")
    return {
        "schema_version": 1,
        "status": "origin-verified",
        "qualification": "not-evaluated",
        "trust": "provider-origin-only",
        "repository": expected["repository"],
        "run_id": expected["run_id"],
        "attempt": expected["attempt"],
        "jobs": [{"id": job["id"], "name": job["name"]} for job in observed],
        "artifacts": results,
        "remaining": ["protected-policy-approval", "collector-execution-isolation", "native-oracles", "complete-release-gate"],
    }


def main(arguments: list[str] | None = None) -> int:
    """Read Actions metadata only; never dispatch jobs, install dependencies, push code or relabel local evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expectation", type=Path, required=True)
    parser.add_argument("--expectation-sha256", required=True)
    parser.add_argument("--archive", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(arguments)
    try:
        raw = v.read(args.expectation)
        expect(v.digest(raw) == args.expectation_sha256, "expectation-digest")
        expected = policy(v.decode(raw), dt.datetime.now(dt.timezone.utc))
        args.output.mkdir(parents=True, exist_ok=False)
        client = Client(os.environ.get("ASTRA_GITHUB_TOKEN", ""), args.output)
        v.write_new(args.output / "expectation.json", raw)
        try:
            result = inspect(client.get, expected, args.archive, dt.datetime.now(dt.timezone.utc))
        except (v.Invalid, OSError) as error:
            v.write_new(args.output / "result.json", {"status": "blocked", "reason": str(error), "responses": client.records})
            raise
        result.update({"responses": client.records, "expectation_sha256": args.expectation_sha256, "verifier_sha256": v.file_digest(Path(__file__))})
        v.write_new(args.output / "result.json", result)
        print(v.encode(result).decode())
        return 0
    except (v.Invalid, OSError) as error:
        print(str(error), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
