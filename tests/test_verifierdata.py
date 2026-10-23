"""Challenge native verifier evidence adoption; historical fixtures never qualify a later workspace."""

from collections.abc import Callable
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import entry, verifierdata, verify as v

ROOT = Path(__file__).resolve().parents[1]


class VerifierDataTests(unittest.TestCase):
    """Keep physical execution, complete observations and current-source adoption independently mandatory."""

    @classmethod
    def setUpClass(cls) -> None:
        """Load one immutable real parser fixture; do not execute its archived scripts."""
        cls.fixture = v.decode(v.read(ROOT / "tests/fixtures/verifier.json"))
        cls.directory = ROOT / cls.fixture["directory"]
        raw = v.read(cls.directory / "evidence.tar.gz", 16 * 1024**2)
        if v.digest(raw) != cls.fixture["archive_sha256"] or v.file_digest(cls.directory / "sealed.native.json") != cls.fixture["seal_sha256"]:
            v.reject("verifier-test-fixture")
        cls.files = entry.unpack(raw)
        cls.seal = v.decode(v.read(cls.directory / "sealed.native.json"))
        cls.retired = v.decode(v.read(cls.directory / "collector-retired.json"))

    def altered(self, member: str, change: Callable[[dict], object]) -> tuple[dict[str, bytes], dict]:
        """Repair envelope digests so a negative reaches its semantic guard, never a fabricated acceptance."""
        files, seal = dict(self.files), copy.deepcopy(self.seal)
        data = v.decode(files[member])
        change(data)
        files[member] = v.encode(data)
        seal["files"][member] = {"bytes": len(files[member]), "sha256": v.digest(files[member])}
        manifest = v.decode(files["manifest.json"])
        manifest["files"][member] = seal["files"][member]
        files["manifest.json"] = v.encode(manifest)
        seal["files"]["manifest.json"] = {"bytes": len(files["manifest.json"]), "sha256": v.digest(files["manifest.json"])}
        return files, seal

    def test_native(self) -> None:
        """The genuine 206-case fixture supplies all 73 counts and exact exec/retirement/source identities."""
        proof, checked = verifierdata.read(ROOT, self.directory, self.fixture["archive_sha256"], self.fixture["seal_sha256"], self.fixture["retired_sha256"])
        self.assertEqual(proof["cases"], 206)
        self.assertEqual(len(proof["observations"]), 73)
        self.assertEqual(proof["producer_identities"], 3)
        self.assertEqual(proof["duration_ms"], 345990)
        self.assertEqual(
            set(checked),
            {
                (self.directory / name).relative_to(ROOT).as_posix()
                for name in ("evidence.tar.gz", "sealed.native.json", "collector-retired.json", "inputs.json")
            },
        )
        with self.assertRaisesRegex(v.Invalid, "verifier-evidence-pin"):
            verifierdata.read(ROOT, self.directory, "0" * 64, self.fixture["seal_sha256"], self.fixture["retired_sha256"])
        with self.assertRaisesRegex(v.Invalid, "verifier-evidence-boundary"):
            verifierdata.read(ROOT, ROOT.parent, "0" * 64, "0" * 64, "0" * 64)
        if os.name != "nt":
            with tempfile.TemporaryDirectory(prefix="verifier-boundary-", dir=ROOT / "build/results/assurance") as temporary:
                directory = Path(temporary)
                (directory / "evidence.tar.gz").symlink_to(ROOT / "development.json")
                with self.assertRaisesRegex(v.Invalid, "path-symlink"):
                    verifierdata.read(ROOT, directory, "0" * 64, "0" * 64, "0" * 64)

    def test_guards(self) -> None:
        """Complete-looking envelopes still reject failed commands, foreign execs, budgets and unreaped owners."""
        prefix = "commands/verification-python/"
        variants = (
            ("source.native.after.json", lambda row: row["files"].pop(), "native-source-changed"),
            (prefix + "record.json", lambda row: row.update(exit_code=1), "native-command"),
            (prefix + "record.json", lambda row: row.update(cleanup=False), "native-command"),
            (prefix + "exec.native.json", lambda row: row["observed"][0].update(cgroup="/foreign"), "exec-observation"),
            (prefix + "exec.native.json", lambda row: row["observed"][0]["identity"].update(parent=1), "exec-identity"),
            (prefix + "leaf.after.json", lambda row: row.update({"memory.max": "2147483648"}), "native-limits"),
            (prefix + "leaf.after.json", lambda row: row.update({"memory.events": "low 0\nhigh 1\nmax 0\noom 0\n"}), "native-limit-event"),
            ("cleanup.native.json", lambda row: row["retired"].pop(), "producer-cleanup|producer-identity-inventory"),
            ("inputs.json", lambda row: row["check"]["expected_tests"].pop(), "controller-inputs"),
        )
        for member, change, reason in variants:
            files, seal = self.altered(member, change)
            if member == "cleanup.native.json":
                seal["cleanup"] = v.decode(files[member])
            with self.subTest(member=member, reason=reason), self.assertRaisesRegex(v.Invalid, "verifier-(" + reason + ")"):
                verifierdata.inspect(files, seal, self.retired)
        retired = copy.deepcopy(self.retired)
        retired["retired"] = False
        with self.assertRaisesRegex(v.Invalid, "verifier-collector-retirement"):
            verifierdata.inspect(self.files, self.seal, retired)
        stdout_name = prefix + "verification-python.stdout.log"
        lines = self.files[stdout_name].splitlines(keepends=True)
        skipped = list(lines)
        for index, line in enumerate(skipped):
            if line.startswith(b"ASTRA-OBSERVE ") and v.decode(line[len(b"ASTRA-OBSERVE ") :])["event"] == "end":
                event = v.decode(line[len(b"ASTRA-OBSERVE ") :])
                skipped[index] = b"ASTRA-OBSERVE " + json.dumps(event | {"status": "skipped"}, separators=(",", ":")).encode() + b"\n"
                break
        first = next(line for line in lines if line.startswith(b"ASTRA-OBSERVE ") and v.decode(line[len(b"ASTRA-OBSERVE ") :])["event"] == "begin")
        for stream, reason in (
            (b"".join(skipped), "case-status"),
            (b"".join(lines[:-1]), "case-completion"),
            (b"".join(lines[:1] + [first] + lines[1:]), "case-inventory"),
        ):
            # Update both stream and containing record envelopes to reach the case-semantic guard.
            record = v.decode(self.files[prefix + "record.json"])
            record["stdout"] = {"path": "verification-python.stdout.log", "bytes": len(stream), "sha256": v.digest(stream)}
            files, seal = self.altered(prefix + "record.json", lambda value: value.update(record))
            files[stdout_name] = stream
            seal["files"][stdout_name] = {"bytes": len(stream), "sha256": v.digest(stream)}
            manifest = v.decode(files["manifest.json"])
            manifest["files"][stdout_name] = seal["files"][stdout_name]
            files["manifest.json"] = v.encode(manifest)
            seal["files"]["manifest.json"] = {"bytes": len(files["manifest.json"]), "sha256": v.digest(files["manifest.json"])}
            with self.subTest(reason=reason), self.assertRaisesRegex(v.Invalid, "verifier-" + reason):
                verifierdata.inspect(files, seal, self.retired)

    def test_adoption(self) -> None:
        """Only the exact source and declaration can adopt observations; one altered or missing case stays blocking."""
        proof = verifierdata.inspect(self.files, self.seal, self.retired)
        states = verifierdata.observations(proof, proof["source"], proof["check"])
        self.assertEqual(len(states), 73)
        self.assertTrue(all(key[:2] == ("verification-python", "linux-amd64-cgo") and value == "passed" for key, value in states.items()))
        for source, check, reason in (
            (proof["source"] | {"commit": "foreign"}, proof["check"], "source"),
            (proof["source"], proof["check"] | {"expected_tests": proof["check"]["expected_tests"][:-1]}, "check"),
            (v.source(ROOT), proof["check"], "source"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(v.Invalid, "verifier-adoption-" + reason):
                verifierdata.observations(proof, source, check)

    def test_aliases(self) -> None:
        """Explicitly synthetic proofs cannot alias different selections, budgets or case floors."""
        config, _, _ = v.configuration(ROOT / "development.json", ROOT)
        checks = v.unique(config["checks"])
        canonical, target = checks["gap-scope"], checks["admission-gap-scope"]
        proof = {
            "source": {"synthetic": True},
            "check": canonical,
            "cases": len(canonical["expected_tests"]),
            "platform": "linux-amd64-cgo",
            "observations": {"STORAGE-ASSURANCE": 92},
        }
        states, counts = verifierdata.alias(proof, proof["source"], canonical, target)
        self.assertEqual(states, {("admission-gap-scope", "linux-amd64-cgo", "ADMISSION-ASSURANCE"): "passed"})
        self.assertEqual(counts, {"ADMISSION-ASSURANCE": 92})
        for changed in (
            target | {"argv": target["argv"] + ["--other"]},
            target | {"timeout_s": 121},
            target | {"expected_tests": target["expected_tests"][:-1]},
        ):
            with self.subTest(declaration=changed["id"]), self.assertRaisesRegex(v.Invalid, "verifier-alias-declaration"):
                verifierdata.alias(proof, proof["source"], canonical, changed)
        changed = copy.deepcopy(target)
        changed["probes"][0]["minimum_hits"] += 1
        with self.assertRaisesRegex(v.Invalid, "verifier-alias-probe"):
            verifierdata.alias(proof, proof["source"], canonical, changed)
        with self.assertRaisesRegex(v.Invalid, "verifier-alias-check"):
            verifierdata.alias(proof, proof["source"], canonical, checks["gap-gate"])
        with self.assertRaisesRegex(v.Invalid, "verifier-adoption-scope"):
            verifierdata.alias(proof | {"cases": 1}, proof["source"], canonical, target)
        with self.assertRaisesRegex(v.Invalid, "verifier-adoption-source"):
            verifierdata.alias(proof, {"synthetic": False}, canonical, target)

    def test_entries(self) -> None:
        """Pinned manifests bind native source/check identity and reject duplicate or unregistered target sets."""
        config, _, _ = v.configuration(ROOT / "development.json", ROOT)
        check = v.unique(config["checks"])["gap-scope"]
        source = v.source(ROOT)
        # This mocked reader is a parser control only; no synthetic archive crosses the real read boundary.
        proof = {
            "source": source,
            "check": check,
            "cases": 8,
            "platform": "linux-amd64-cgo",
            "observations": {"STORAGE-ASSURANCE": 92},
            "record_sha256": "a" * 64,
            "executed_step": "verification-python",
            "duration_ms": 1,
            "trust": "local",
        }
        row = {
            "check": "gap-scope",
            "directory": "reuse-plan/synthetic-case-proof",
            "targets": ["gap-scope", "admission-gap-scope"],
            "archive_sha256": "a" * 64,
            "seal_sha256": "b" * 64,
            "retired_sha256": "c" * 64,
        }
        with tempfile.TemporaryDirectory(prefix="case-entry-controls-", dir=ROOT / "build/results/assurance") as temporary:
            path = Path(temporary) / "entries.json"
            original = {"version": 1, "source": source, "entries": [row]}
            path.write_bytes(v.encode(original))
            with patch.object(verifierdata, "read", return_value=(proof, {})) as reader:
                observed, reports, checked = verifierdata.entries(ROOT, path, v.file_digest(path), source, config)
                self.assertEqual(len(observed), 2)
                self.assertEqual(set(reports["gap-scope"]["targets"]), set(row["targets"]))
                self.assertEqual(reports["gap-scope"]["executed_step"], "verification-python")
                self.assertIn(path.relative_to(ROOT).as_posix(), checked)
                reader.assert_called_once()
                for rows in (
                    [row, row],
                    [row | {"targets": ["gap-scope", "gap-gate"]}],
                    [row | {"targets": ["gap-scope", "gap-scope"]}],
                    [row | {"check": "verification-python"}],
                ):
                    path.write_bytes(v.encode(original | {"entries": rows}))
                    with self.subTest(entries=rows), self.assertRaises(v.Invalid):
                        verifierdata.entries(ROOT, path, v.file_digest(path), source, config)
                with self.assertRaisesRegex(v.Invalid, "verifier-entries-pin"):
                    verifierdata.entries(ROOT, path, "0" * 64, source, config)

    def test_registration(self) -> None:
        """Only registered empty-environment interpreter declarations with consistent case selectors can be received."""
        config, _, _ = v.configuration(ROOT / "development.json", ROOT)
        eligible = verifierdata.eligible(config)
        self.assertTrue({"verification-python", "gap-scope", "gap-time", "storage-core-mutants", "gap-fault-matrix", "admission-gap-impact"} <= eligible)
        self.assertNotIn("storage-examples", eligible)
        for field, value in (
            ("environment", {"ASTRA_UNREVIEWED": "1"}),
            ("argv", ["python3", "-B", "tools/observe.py", "native", "tests.test_foreign"]),
            ("expected_tests", ["tests.test_foreign.Unregistered.test_current"]),
            ("expected_tests", []),
            ("adapter", "unavailable"),
        ):
            changed = copy.deepcopy(config)
            v.unique(changed["checks"])["gap-time"][field] = value
            with self.subTest(field=field, value=value):
                self.assertNotIn("gap-time", verifierdata.eligible(changed))

    def test_association(self) -> None:
        """A synthetic results-only review cannot hide code, policy, fixture, Git or inventory changes."""
        current = v.source(ROOT)
        before = copy.deepcopy(current)
        v.unique(before["files"], "path")["docs/validation.md"]["sha256"] = "0" * 64
        original = {
            "at": v.utc(),
            "executed": before,
            "after": current,
            "changed_after_interpretation": ["docs/validation.md"],
            "native_application_commands": 0,
        }
        with tempfile.TemporaryDirectory(prefix="association-controls-", dir=ROOT / "build/results/assurance") as temporary:
            path = Path(temporary) / "association.json"
            path.write_bytes(v.encode(original))
            source, report, checked = verifierdata.association(ROOT, path, v.file_digest(path), current)
            self.assertEqual(source, before)
            self.assertEqual(report["executed_source_sha256"], v.digest(v.encode(before)))
            self.assertEqual(report["current_source_sha256"], v.digest(v.encode(current)))
            self.assertEqual(report["changed_paths"], ["docs/validation.md"])
            self.assertEqual(checked, {path.relative_to(ROOT).as_posix(): v.file_digest(path)})
            with self.assertRaisesRegex(v.Invalid, "verifier-association-pin"):
                verifierdata.association(ROOT, path, "f" * 64, current)
            with self.assertRaisesRegex(v.Invalid, "verifier-association-boundary"):
                verifierdata.association(ROOT, ROOT / "development.json", "f" * 64, current)
            changes = [
                lambda row: row["executed"].update(commit="foreign"),
                lambda row: row["executed"].update(status="foreign"),
                lambda row: row["after"].update(commit="foreign"),
                lambda row: row["executed"]["files"].pop(),
                lambda row: row["executed"]["files"].append({"path": "foreign.py", "sha256": "0" * 64}),
                lambda row: row.update(executed=current),
                lambda row: row.update(changed_after_interpretation=[]),
                lambda row: row.update(native_application_commands=1),
                lambda row: row.update(native_application_commands=False),
                lambda row: v.unique(row["executed"]["files"], "path")["docs/validation.md"].update(sha256=None),
            ]
            for name in ("tools/verify.py", "development.json", "tests/fixtures/verifier.json", "docs/features/verification.md"):
                changes.append(lambda row, name=name: v.unique(row["executed"]["files"], "path")[name].update(sha256="f" * 64))
            for index, change in enumerate(changes):
                row = copy.deepcopy(original)
                change(row)
                path.write_bytes(v.encode(row))
                with self.subTest(variant=index), self.assertRaises(v.Invalid):
                    verifierdata.association(ROOT, path, v.file_digest(path), current)
            # A fabricated review does not make the historical native archive match this synthetic source.
            proof = verifierdata.inspect(self.files, self.seal, self.retired)
            with self.assertRaisesRegex(v.Invalid, "verifier-adoption-source"):
                verifierdata.observations(proof, before, proof["check"])
