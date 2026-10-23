"""Falsify Storage's native numeric transcript reader and complete source/range binding without treating synthetic bytes as application evidence."""

import copy
import base64
import json
import datetime as dt
from pathlib import Path
import shutil
import tempfile
import unittest

from tools import numeric, storage_numeric as storage, verify as v

ROOT = Path(__file__).resolve().parents[1]


def configured() -> dict:
    """Read the versioned native selection rather than inventing a permissive parser-only configuration."""
    return next(check for check in v.decode(v.read(ROOT / "development.json"))["checks"] if check["id"] == "storage-numeric")


def encode(rows: list[dict]) -> bytes:
    """Construct parser-control bytes only; no command receipt or actual native success is asserted."""
    return b"".join(
        json.dumps({"Action": "output", "Package": storage.PACKAGE, "Test": "TestNumeric", "Output": "STORAGE-NUMERIC " + json.dumps(row) + "\n"}).encode()
        + b"\n"
        for row in rows
    )


def source_rows() -> list[dict]:
    """Use frozen compiler geometry with deliberately synthetic metadata, never a fabricated native command receipt."""
    policy = storage.manifest(ROOT)
    names = sorted(policy["sources"])
    active = [name for name in names if name != "lock_other.go"]
    source = {"commit": None, "status": "", "files": [{"path": storage.DIRECTORY + "/" + name, "sha256": policy["sources"][name]} for name in names]}
    export = "/fixture/source/build/cache/go/aa/example-d"
    metadata = json.dumps(
        {"ImportPath": storage.PACKAGE, "Dir": "/fixture/source/" + storage.DIRECTORY, "GoFiles": active, "IgnoredGoFiles": ["lock_other.go"], "Export": export}
    ).encode()
    nodes = v.decode(v.read(ROOT / "tests/fixtures/storage-numeric.json"))["nodes"]
    typing = {
        "metadata_sha256": v.digest(metadata),
        "package": storage.PACKAGE,
        "files": [storage.DIRECTORY + "/" + name for name in active],
        "inactive": [storage.DIRECTORY + "/lock_other.go"],
        "results": {},
        "constants": [],
        "exports": {storage.PACKAGE: {"path": export, "sha256": "0" * 64, "bytes": 1}},
    }
    header = {
        "kind": "header",
        "version": 1,
        "source": source,
        "source_sha256": v.digest(json.dumps(source, separators=(",", ":"), ensure_ascii=False).encode()),
        "os": "linux",
        "architecture": "amd64",
        "runtime": policy["runtime_version"],
        "typing": typing,
        "scanned": storage.revision(ROOT)[1],
        "nodes": storage.revision(ROOT)[0],
        "qualification": "not-evaluated",
    }
    return [
        header,
        {"kind": "metadata", "index": 0, "data": base64.b64encode(metadata).decode()},
        *({"kind": "node", "index": index, "value": node} for index, node in enumerate(nodes)),
    ]


def source_encode(rows: list[dict]) -> bytes:
    """Encode output framing only; positive parser controls are not evidence of an executed Go suite."""
    return b"".join(
        (
            json.dumps(
                {
                    "Action": "output",
                    "Package": storage.SOURCE_PACKAGE,
                    "Test": "TestStorageNumbers",
                    "Output": "STORAGE-NUMERIC-SOURCE " + json.dumps(row) + "\n",
                }
            )
            + "\n"
        ).encode()
        for row in rows
    )


class StorageNumericTests(unittest.TestCase):
    """Reject incomplete observations and stale production scope while retaining independent mathematical limits."""

    def test_configuration(self) -> None:
        """Bind method, package, complete selection and positive native exposure exactly."""
        check = configured()
        self.assertIsNone(numeric.configuration(check))
        for key, value in (("numeric", "unknown"), ("component", "unknown"), ("package", "unknown"), ("argv", []), ("expected_tests", []), ("probes", [])):
            altered = copy.deepcopy(check)
            altered[key] = value
            with self.assertRaises(v.Invalid):
                numeric.configuration(altered)
        for value in (0, storage.HITS - 1, True):
            altered = copy.deepcopy(check)
            altered["probes"][0]["minimum_hits"] = value
            with self.assertRaises(v.Invalid):
                numeric.configuration(altered)

    def test_ranges(self) -> None:
        """Use unbounded arithmetic to validate the frozen 64-bit interval and representation assumptions."""
        proof = storage.bounds(ROOT)
        self.assertEqual(proof["allocation_max_bytes"], 2**48)
        self.assertEqual(proof["change_bytes"], 56)
        self.assertEqual(len(proof["sources"]), 11 if storage.revision(ROOT)[0] == 884 else 10)
        self.assertEqual(len(proof["runtime_sources"]), 5)
        for value in proof["interval_upper_bounds"].values():
            self.assertGreaterEqual(value, 0)
            self.assertLess(value, 2**63)
        self.assertEqual(proof["interval_upper_bounds"]["global_replacement_intermediate"], 5 * 2**30)
        self.assertEqual(proof["interval_upper_bounds"]["query_history_limit"], 65537)
        self.assertEqual(proof["floating_operations"], 0)

    def test_proof(self) -> None:
        """Every numerical owner has a complete family and checked arithmetic extrema, including unsigned and slicing relationships."""
        proof = storage.proof(ROOT)
        self.assertEqual(set(proof["owners"]), set(v.decode(v.read(ROOT / storage.DIRECTORY / "numeric-source.json"))["scopes"]))
        self.assertEqual(set(proof["owners"].values()), set(proof["families"]))
        self.assertEqual(len(proof["families"]), 10)
        self.assertEqual(proof["guard_pairs"], 13)
        for name, item in proof["arithmetic"].items():
            self.assertGreaterEqual(item["range"][0], 0, name)
            self.assertLessEqual(item["range"][0], item["range"][1], name)
            self.assertLessEqual(item["range"][1], item.get("maximum", 2**63 - 1), name)
        self.assertEqual(proof["arithmetic"]["version-increment"]["range"][1], 2**64 - 1)
        self.assertEqual(proof["arithmetic"]["entry-header-division"]["divisor"], 8)
        self.assertEqual(proof["arithmetic"]["global-accounting"]["range"], [0, 5 * 2**30])
        for remaining in (0, 1, 7, 8, 65535, 2**32 - 1, 2**48):
            for key in {0, min(65535, remaining), remaining}:
                for value in {0, remaining - key}:
                    self.assertLessEqual(key + value, remaining)
                    self.assertLessEqual(key + value, 2**63 - 1)
        for version in storage.VERSIONS:
            for retained in {0, min(version, 65536)}:
                self.assertGreaterEqual(version - retained, 0)
                self.assertLessEqual(version - retained, 2**64 - 1)

    def test_gate(self) -> None:
        """Absence, failure, unknown status or an exemption at any child cannot satisfy complete numerical qualification."""
        config = v.decode(v.read(ROOT / "development.json"))
        obligations = v.expand(config)
        key = "polaris-storage/DEV-NUMERIC/STORAGE-ASSURANCE/linux-amd64-cgo/full-rule"
        self.assertIs(obligations[key]["aggregate"], True)
        self.assertEqual(obligations[key]["checks"], [])
        _, dependencies = v.dependency_order(obligations)
        required = dependencies[key]
        self.assertEqual(len(required), 4)
        coordinates = {(check, obligations[k]["platform"], obligations[k]["contract"]): "passed" for k in required for check in obligations[k]["checks"]}
        now = dt.datetime.now(dt.timezone.utc)
        # These are synthetic gate states, not reports of native execution or protected trust.
        decision = v.decide(config, coordinates, [], [], now)
        self.assertIn(key, decision["passed"])
        self.assertEqual(decision["status"], "blocked")
        self.assertEqual(decision["exceptions"], [])
        for coordinate in coordinates:
            for state in (None, "failed", "not-run", "unknown", "interrupted", "skipped"):
                altered = dict(coordinates)
                if state is None:
                    del altered[coordinate]
                else:
                    altered[coordinate] = state
                self.assertIn(key, v.decide(config, altered, [], [], now)["missing"])
                self.assertNotIn(key, v.decide(config, altered, [], [], now)["passed"])

    def test_witnesses(self) -> None:
        """Damage every native vector independently; duplicated, missing or reordered data cannot inherit a green aggregate marker."""
        check = configured()
        rows = storage.expected(ROOT)
        self.assertEqual(len(rows), 198)
        self.assertEqual(numeric.observations(encode(rows), check, ROOT), {"STORAGE-NUMERIC": storage.HITS})
        for index in range(len(rows)):
            damaged = rows[:index] + rows[index + 1 :]
            with self.assertRaises(v.Invalid):
                numeric.observations(encode(damaged), check, ROOT)
        for index in range(len(rows)):
            damaged = rows[:index] + [rows[index]] + rows[index:]
            with self.assertRaises(v.Invalid):
                numeric.observations(encode(damaged), check, ROOT)
        for index in range(len(rows) - 1):
            if rows[index] == rows[index + 1]:
                continue
            damaged = list(rows)
            damaged[index], damaged[index + 1] = damaged[index + 1], damaged[index]
            with self.assertRaises(v.Invalid):
                numeric.observations(encode(damaged), check, ROOT)
        for name, replacement in (
            ("representation", {"kind": "representation", "int": 32}),
            ("runtime", {"kind": "runtime", "version": "unknown"}),
            ("codec", {"kind": "codec", "input": 2**64 - 1, "decoded": 2**32 - 1}),
        ):
            damaged = copy.deepcopy(rows)
            index = next(index for index, row in enumerate(rows) if row["kind"] == name)
            damaged[index] = replacement
            with self.assertRaises(v.Invalid):
                numeric.observations(encode(damaged), check, ROOT)

    def test_stream(self) -> None:
        """Reject wrong package/test attribution, absent output and malformed native JSON."""
        check, rows = configured(), storage.expected(ROOT)
        healthy = encode(rows)
        for data in (
            b"",
            healthy[: len(healthy) // 2],
            healthy.replace(storage.PACKAGE.encode(), b"wrong-package"),
            healthy.replace(b"TestNumeric", b"TestOther"),
            b'{"Action":"output"',
        ):
            with self.assertRaises(v.Invalid):
                numeric.observations(data, check, ROOT)

    def test_source(self) -> None:
        """Refuse missing, altered, added or falsely narrowed production files, including inactive code."""
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            root = Path(temporary)
            directory = root / storage.DIRECTORY
            directory.mkdir(parents=True)
            for name in [*storage.manifest(ROOT)["sources"], "numeric.json"]:
                shutil.copyfile(ROOT / storage.DIRECTORY / name, directory / name)
            self.assertEqual(storage.bounds(root)["sources"], storage.bounds(ROOT)["sources"])
            for name in storage.manifest(ROOT)["sources"]:
                path = directory / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n// changed\n")
                with self.assertRaises(v.Invalid):
                    storage.bounds(root)
                path.write_bytes(original)
            added = directory / "extra.go"
            added.write_text("package storage\n", encoding="utf-8")
            with self.assertRaises(v.Invalid):
                storage.bounds(root)
            added.unlink()
            policy = v.decode(v.read(directory / "numeric.json"))
            del policy["sources"]["lock_other.go"]
            (directory / "numeric.json").write_bytes(v.encode(policy))
            with self.assertRaises(v.Invalid):
                storage.bounds(root)

    def test_typed(self) -> None:
        """Reject missing geometry, source/runtime drift, altered node attribution and native metadata corruption."""
        check = next(check for check in v.decode(v.read(ROOT / "development.json"))["checks"] if check["id"] == "storage-numeric-source")
        rows = source_rows()
        self.assertEqual(
            numeric.observations(source_encode(rows), check, ROOT), {"STORAGE-NUMERIC-CONTROLS": 24, "STORAGE-NUMERIC-SOURCE": storage.revision(ROOT)[0]}
        )
        for key, value in (("numeric", "unknown"), ("package", storage.PACKAGE), ("expected_tests", []), ("probes", [])):
            changed = copy.deepcopy(check)
            changed[key] = value
            with self.assertRaises(v.Invalid):
                numeric.configuration(changed)
        for key, value in (
            ("version", True),
            ("os", "windows"),
            ("architecture", "386"),
            ("runtime", "unknown"),
            ("nodes", 0),
            ("scanned", 0),
            ("qualification", "passed"),
        ):
            changed = copy.deepcopy(rows)
            changed[0][key] = value
            with self.assertRaises(v.Invalid):
                numeric.observations(source_encode(changed), check, ROOT)
        for key, value in (
            ("file", "elsewhere.go"),
            ("scope", "unknown"),
            ("kind", "unknown"),
            ("type", "float64"),
            ("text", "changed"),
            ("begin", -1),
            ("line", True),
        ):
            changed = copy.deepcopy(rows)
            changed[2]["value"][key] = value
            with self.assertRaises(v.Invalid):
                numeric.observations(source_encode(changed), check, ROOT)
        for index in range(len(rows)):
            with self.assertRaises(v.Invalid):
                numeric.observations(source_encode(rows[:index] + rows[index + 1 :]), check, ROOT)
        for changed in (rows + [rows[-1]], [rows[0], rows[1], rows[3], rows[2], *rows[4:]], [rows[0], rows[1], None, *rows[2:]]):
            with self.assertRaises(v.Invalid):
                numeric.observations(source_encode(changed), check, ROOT)

    def test_metadata(self) -> None:
        """An updated metadata digest cannot legitimize failed packages, wrong ABI source selection or escaping exports."""
        check = next(check for check in v.decode(v.read(ROOT / "development.json"))["checks"] if check["id"] == "storage-numeric-source")
        rows = source_rows()
        original = json.loads(base64.b64decode(rows[1]["data"]))
        for key, value in (
            ("ImportPath", []),
            ("Error", {}),
            ("DepsErrors", [{}]),
            ("Incomplete", True),
            ("GoFiles", []),
            ("IgnoredGoFiles", []),
            ("Dir", "relative"),
            ("CgoFiles", ["foreign.go"]),
        ):
            changed = copy.deepcopy(rows)
            metadata = {**original, key: value}
            data = json.dumps(metadata).encode()
            changed[0]["typing"]["metadata_sha256"] = v.digest(data)
            changed[1]["data"] = base64.b64encode(data).decode()
            with self.assertRaises(v.Invalid):
                numeric.observations(source_encode(changed), check, ROOT)
        for key, value in (("path", "/outside/export"), ("path", None), ("sha256", None), ("bytes", True), ("bytes", 0)):
            changed = copy.deepcopy(rows)
            changed[0]["typing"]["exports"][storage.PACKAGE][key] = value
            with self.assertRaises(v.Invalid):
                numeric.observations(source_encode(changed), check, ROOT)
