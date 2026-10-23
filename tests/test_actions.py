"""Falsify Actions origin checks with provider-shaped fixtures; none of these fixtures is CI acceptance evidence."""

from collections.abc import Callable
import base64
import copy
import datetime as dt
import io
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from tools import actions as a, verify as v

# Frozen synthetic identities are deliberately separate from any real repository or run.
NOW = dt.datetime(2026, 10, 2, 1, tzinfo=dt.timezone.utc)
ROOT = Path(__file__).resolve().parents[1]


def fixture() -> tuple[dict, dict]:
    """Anchor one exact successful attempt and required step in independently specified provider facts."""
    workflow = b"name: fixture\non: workflow_dispatch\n"
    expected = {
        "schema_version": 1,
        "repository": "fixture/project",
        "repository_id": 15,
        "run_id": 30,
        "attempt": 2,
        "workflow_id": 10,
        "workflow_path": ".github/workflows/assurance.yml",
        "workflow_sha256": v.digest(workflow),
        "head_sha": "a" * 40,
        "head_branch": "main",
        "actor_id": 3,
        "triggering_actor_id": 4,
        "not_before": "2026-10-02T00:00:00Z",
        "expires_at": "2026-10-03T00:00:00Z",
        "policy": "b" * 64,
        "source": "c" * 64,
        "collector": "d" * 64,
        "jobs": [{"name": "Linux collection", "steps": ["Collect"]}],
        "artifacts": [{"id": 90, "platform": "linux-amd64-cgo"}],
    }
    run = {
        "id": 30,
        "run_attempt": 2,
        "workflow_id": 10,
        "path": ".github/workflows/assurance.yml",
        "head_sha": "a" * 40,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "repository": {"id": 15, "full_name": "fixture/project"},
        "head_repository": {"id": 15, "full_name": "fixture/project"},
        "actor": {"id": 3},
        "triggering_actor": {"id": 4},
        "run_started_at": "2026-10-02T00:10:00Z",
        "updated_at": "2026-10-02T00:20:00Z",
    }
    job = {
        "id": 50,
        "run_id": 30,
        "run_attempt": 2,
        "head_sha": "a" * 40,
        "name": "Linux collection",
        "status": "completed",
        "conclusion": "success",
        "started_at": "2026-10-02T00:11:00Z",
        "completed_at": "2026-10-02T00:19:00Z",
        "steps": [{"name": "Collect", "number": 1, "status": "completed", "conclusion": "success"}],
    }
    facts = {
        "run": run,
        "workflow": {"type": "file", "path": expected["workflow_path"], "encoding": "base64", "content": base64.b64encode(workflow).decode()},
        "jobs": {"total_count": 1, "jobs": [job]},
        "artifact": {
            "id": 90,
            "name": "astra-30-2-linux-amd64-cgo",
            "expired": False,
            "created_at": "2026-10-02T00:19:30Z",
            "expires_at": "2026-11-01T00:00:00Z",
            "workflow_run": {"id": 30, "repository_id": 15, "head_repository_id": 15, "head_sha": "a" * 40, "head_branch": "main"},
        },
    }
    return expected, facts


def payload(expected: dict, files: list[tuple[str | zipfile.ZipInfo, bytes]] | None = None, change: Callable[[dict], object] | None = None) -> bytes:
    """Make a ZIP fixture whose declared content can independently disagree with the real member bytes."""
    files = [("record.json", b'{"fixture":true}\n')] if files is None else files
    manifest = {key: expected[key] for key in ("schema_version", "repository_id", "run_id", "attempt", "head_sha", "policy", "source", "collector")}
    manifest.update(
        platform="linux-amd64-cgo",
        files=[{"path": str(name.filename if isinstance(name, zipfile.ZipInfo) else name), "bytes": len(raw), "sha256": v.digest(raw)} for name, raw in files],
    )
    if change:
        change(manifest)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", v.encode(manifest))
        for name, raw in files:
            if isinstance(name, str):
                entry = zipfile.ZipInfo(name)
                # Preserve malformed wire names instead of letting the host repair the counterexample while writing it.
                entry.filename = entry.orig_filename = name
                entry.compress_type = zipfile.ZIP_DEFLATED
                name = entry
            archive.writestr(name, raw)
    return output.getvalue()


class ActionsTests(unittest.TestCase):
    """Check complete origin binding and reject single-axis counterexamples without contacting GitHub."""

    def setUp(self) -> None:
        """Require the actual schema engine before any expected rejection can receive assertion credit."""
        a.policy(fixture()[0], NOW)

    def evaluate(self, expected: dict, facts: dict, raw: bytes | None = None) -> dict:
        """Supply a strict fake endpoint router and a temporary compressed artifact to the real parser."""
        raw = payload(expected) if raw is None else raw
        facts = copy.deepcopy(facts)
        facts["artifact"].update(digest="sha256:" + v.digest(raw), size_in_bytes=len(raw))
        prefix = "/repos/fixture/project"
        endpoints = {
            prefix + "/actions/runs/30/attempts/2": facts["run"],
            prefix + "/actions/runs/30/attempts/2/jobs?per_page=100&page=1": facts["jobs"],
            prefix + "/contents/.github/workflows/assurance.yml?ref=" + "a" * 40: facts["workflow"],
            prefix + "/actions/artifacts/90": facts["artifact"],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.zip"
            path.write_bytes(raw)
            return a.inspect(lambda name: copy.deepcopy(endpoints[name]), expected, [path], NOW)

    def test_origin_is_not_qualification(self) -> None:
        """A complete fixture verifies origin only, never CI isolation or release eligibility."""
        expected, facts = fixture()
        result = self.evaluate(expected, facts)
        self.assertEqual(result["status"], "origin-verified")
        self.assertEqual(result["qualification"], "not-evaluated")
        self.assertEqual(result["trust"], "provider-origin-only")
        self.assertIn("collector-execution-isolation", result["remaining"])
        self.assertEqual(result["artifacts"][0]["files"][0]["sha256"], v.digest(b'{"fixture":true}\n'))
        for name in ("nested/record.json", "カナ.json"):
            with self.subTest(name=name):
                result = self.evaluate(expected, facts, payload(expected, [(name, b"fixture")]))
                self.assertEqual(result["artifacts"][0]["files"][0]["path"], name)

    def test_policy_identity(self) -> None:
        """Unknown fields, invalid windows, duplicate matrix rows and empty obligations are rejected."""
        expected, _ = fixture()
        for field, value in (
            ("extra", True),
            ("attempt", True),
            ("jobs", []),
            ("artifacts", []),
            ("expires_at", "2026-10-01T00:00:00Z"),
            ("not_before", "2026-10-03T00:00:00Z"),
            ("repository", "../escape"),
            ("jobs", expected["jobs"] * 2),
            ("artifacts", expected["artifacts"] * 2),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(v.Invalid):
                a.policy({**expected, field: value}, NOW)

    def test_attempt_and_workflow(self) -> None:
        """Success from another attempt, repository, actor, workflow or commit cannot substitute for the required one."""
        expected, original = fixture()
        for field, value in (
            ("id", 31),
            ("run_attempt", 1),
            ("workflow_id", True),
            ("head_sha", "e" * 40),
            ("head_branch", "other"),
            ("path", ".github/workflows/other.yml"),
            ("event", "pull_request"),
            ("conclusion", "failure"),
            ("status", "in_progress"),
            ("actor", {"id": 99}),
            ("triggering_actor", {"id": 99}),
            ("head_repository", {"id": 99, "full_name": "fixture/project"}),
            ("repository", {"id": 15, "full_name": "other/project"}),
        ):
            facts = copy.deepcopy(original)
            facts["run"][field] = value
            with self.subTest(field=field), self.assertRaises(v.Invalid):
                self.evaluate(expected, facts)
        facts = copy.deepcopy(original)
        facts["workflow"]["content"] = base64.b64encode(b"substituted workflow").decode()
        with self.assertRaisesRegex(v.Invalid, "workflow-digest"):
            self.evaluate(expected, facts)

    def test_job_and_step_matrix(self) -> None:
        """Missing, duplicated, unfinished or skipped required jobs and steps remain failures."""
        expected, original = fixture()
        for field, value in (
            ("id", True),
            ("run_attempt", 1),
            ("name", "other"),
            ("conclusion", "skipped"),
            ("steps", []),
            ("steps", [{"name": "Collect", "number": 1, "status": "completed", "conclusion": "skipped"}]),
            ("steps", [{"name": "other", "number": 1, "status": "completed", "conclusion": "success"}]),
        ):
            facts = copy.deepcopy(original)
            facts["jobs"]["jobs"][0][field] = value
            with self.subTest(field=field), self.assertRaises(v.Invalid):
                self.evaluate(expected, facts)
        for jobs in (
            {"total_count": 0, "jobs": []},
            {"total_count": 2, "jobs": original["jobs"]["jobs"] * 2},
            {"total_count": True, "jobs": original["jobs"]["jobs"]},
        ):
            with self.subTest(jobs=jobs), self.assertRaises(v.Invalid):
                self.evaluate(expected, {**original, "jobs": jobs})

    def test_pagination_and_recheck(self) -> None:
        """Unstable pages and provider changes during inspection cannot yield a sealed origin result."""
        expected, facts = fixture()
        responses = iter([{"total_count": 2, "jobs": facts["jobs"]["jobs"]}, {"total_count": 3, "jobs": facts["jobs"]["jobs"]}])
        with self.assertRaisesRegex(v.Invalid, "jobs-count"):
            a.jobs(lambda _: next(responses), "/fixture", expected)
        responses = iter([{"total_count": 2, "jobs": facts["jobs"]["jobs"]}, {"total_count": 2, "jobs": []}])
        with self.assertRaisesRegex(v.Invalid, "jobs-page"):
            a.jobs(lambda _: next(responses), "/fixture", expected)
        original = a.run
        count = 0

        def changing(value: object, policy: dict) -> dict:
            """Alter only the second provider observation while preserving its individually valid shape."""
            nonlocal count
            count += 1
            result = original(value, policy)
            if count == 2:
                result["updated_at"] = "2026-10-02T00:21:00Z"
            return result

        with patch.object(a, "run", changing), self.assertRaisesRegex(v.Invalid, "run-changed"):
            self.evaluate(expected, facts)

    def test_artifact_binding(self) -> None:
        """Expired artifacts and a successful artifact from an older attempt or fork are not accepted."""
        expected, original = fixture()
        for field, value in (
            ("id", 91),
            ("expired", True),
            ("name", "astra-30-1-linux-amd64-cgo"),
            ("expires_at", "2026-10-01T00:00:00Z"),
            ("created_at", "2026-10-01T00:00:00Z"),
            ("workflow_run", {**original["artifact"]["workflow_run"], "head_repository_id": 99}),
        ):
            facts = copy.deepcopy(original)
            facts["artifact"][field] = value
            with self.subTest(field=field), self.assertRaises(v.Invalid):
                self.evaluate(expected, facts)

    def test_archive_integrity(self) -> None:
        """ZIP digest, native-file manifest, exact source, platform and file set are independent checks."""
        expected, facts = fixture()
        for field, value in (("attempt", 1), ("source", "f" * 64), ("collector", "f" * 64), ("platform", "windows-amd64"), ("files", []), ("extra", 1)):
            raw = payload(expected, change=lambda value_, field=field, value=value: value_.update({field: value}))
            with self.subTest(field=field), self.assertRaises(v.Invalid):
                self.evaluate(expected, facts, raw)
        raw = payload(expected, change=lambda value: value["files"][0].update(sha256="f" * 64))
        with self.assertRaisesRegex(v.Invalid, "manifest-file-digest"):
            self.evaluate(expected, facts, raw)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.zip"
            raw = payload(expected)
            path.write_bytes(raw)
            with self.assertRaisesRegex(v.Invalid, "archive-digest"):
                a.archive(path, expected, expected["artifacts"][0], {"digest": "sha256:" + "0" * 64, "size_in_bytes": len(raw)})
            with self.assertRaisesRegex(v.Invalid, "archive-size"):
                a.archive(path, expected, expected["artifacts"][0], {"digest": "sha256:" + v.digest(raw), "size_in_bytes": len(raw) + 1})

    def test_archive_boundaries(self) -> None:
        """Traversal, aliases, links, encrypted/unsupported members and expansion budgets cannot bypass the parser."""
        expected, facts = fixture()
        for name in ("../escape", "/escape", "C:/escape", "a\\b", "a/./b", "a//b", "record.json ", "a\x01b", "record.json\x00hidden"):
            raw = payload(expected, [(name, b"fixture")])
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                self.assertEqual(archive.infolist()[1].orig_filename, name)
            with self.subTest(name=name), self.assertRaisesRegex(v.Invalid, "archive-path"):
                self.evaluate(expected, facts, raw)
        for name, canonical in (("a\\b", "a/b"), ("record.json\x00hidden", "record.json")):
            # A manifest matching the repaired name must not authorize a different physical member identity.
            raw = payload(expected, [(name, b"fixture")], change=lambda manifest, canonical=canonical: manifest["files"][0].update(path=canonical))
            with self.subTest(name=name, canonical=canonical), self.assertRaisesRegex(v.Invalid, "archive-path"):
                self.evaluate(expected, facts, raw)
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaisesRegex(v.Invalid, "archive-entry"):
            self.evaluate(expected, facts, payload(expected, [(link, b"target")]))
        with self.assertRaisesRegex(v.Invalid, "archive-duplicate"):
            self.evaluate(expected, facts, payload(expected, [("Record.json", b"one"), ("record.json", b"two")]))
        with patch.object(a, "EXPANDED", 1), self.assertRaisesRegex(v.Invalid, "archive-expanded"):
            self.evaluate(expected, facts)
        with patch.object(a, "MEMBERS", 1), self.assertRaisesRegex(v.Invalid, "archive-count"):
            raw = payload(expected)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "a.zip"
                path.write_bytes(raw)
                a.archive(path, expected, expected["artifacts"][0], {"digest": "sha256:" + v.digest(raw), "size_in_bytes": len(raw)})

    def test_transport_boundary(self) -> None:
        """Metadata credentials are never forwarded to redirects, arbitrary hosts, local files or proxy routes."""
        with tempfile.TemporaryDirectory() as directory:
            for token in ("", "secret\nheader", "has space"):
                with self.subTest(token=repr(token)), self.assertRaisesRegex(v.Invalid, "actions-token"):
                    a.Client(token, Path(directory))
            client = a.Client("fixture-token", Path(directory))
            for path in ("https://evil.invalid/", "//evil.invalid/x", "/repos/a/b/../../evil", "/repos/a/b/contents/path#fragment"):
                with self.subTest(path=path), self.assertRaisesRegex(v.Invalid, "api-path"):
                    client.get(path)
            with self.assertRaisesRegex(v.Invalid, "api-redirect"):
                a.Redirect().redirect_request(None, None, 302, "redirect", {}, "https://evil.invalid/")
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
