"""Challenge retained Server qualification without executing application commands or accepting unchecked deltas."""

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import admission, authority, consumers, entry, ingress, installation, profileweights, server, statements, structure, verify as v, watchdog

ROOT = Path(__file__).resolve().parents[1]


def archived_entry_policy(source: dict[str, bytes], validated: tuple) -> tuple:
    """Reuse a validated policy dependency only with the archived Entry declaration and its explicit Go-path difference."""
    policy = copy.deepcopy(validated[0])
    original = next(item for item in v.decode(source["development.json"])["checks"] if item["id"] == "polaris-entry-qualification")
    current = next(item for item in policy["checks"] if item["id"] == "polaris-entry-qualification")
    normalized = copy.deepcopy(original)
    normalized["environment"]["PATH"] = normalized["environment"]["PATH"].replace("/go-1.27.1/bin:", "/go-1.27.2/bin:")
    if normalized != current:
        raise ValueError("Unreviewed historical Entry declaration difference")
    policy["checks"] = [original if item["id"] == "polaris-entry-qualification" else item for item in policy["checks"]]
    return policy, *validated[1:]


def inputs() -> tuple[dict[str, bytes], dict[str, bytes]]:
    """Reconstruct the reviewed predecessor for parser controls, never native application evidence."""
    current = {name: v.read(ROOT / name) for name in {*admission.MATERIAL, "internal/admission/node.go"}}
    original = {
        "internal/admission/identity.go": v.read(ROOT / "tests/fixtures/admission-identity.go.in"),
        "internal/admission/node.go": current["internal/admission/node.go"].replace(
            b"\t\tif err == nil || fatal(err) {\n\t\t\treturn err\n\t\t}\n"
            b"\t\t// Preserve permanent refusals and completed admission, but expose the owner's cancellation cause.\n"
            b"\t\tif ctx.Err() != nil {\n\t\t\treturn ctx.Err()\n\t\t}",
            b"\t\tif err == nil || fatal(err) || ctx.Err() != nil {\n\t\t\treturn err\n\t\t}",
            1,
        ),
    }
    return original, current


class ServerTests(unittest.TestCase):
    """Reject oracle/source co-drift, missing inputs and invented native inventory before crediting old facts."""

    def test_delta(self) -> None:
        """Only the exact acquisition/cancellation revisions preserve the authentication argument."""
        original, current = inputs()
        proof = server.delta(original, current)
        self.assertEqual(proof["original"], {name: admission.SOURCES[name] for name in original})
        self.assertEqual(set(proof["current"]), set(current))
        self.assertEqual(len(proof["unchanged_identity_runtime_sha256"]), 64)
        for name in current:
            for altered in ({key: value for key, value in current.items() if key != name}, {**current, name: current[name] + b"\n"}):
                with self.subTest(name=name), self.assertRaisesRegex(v.Invalid, "server-current-dependency"):
                    server.delta(original, altered)
        for name in original:
            with self.subTest(original=name), self.assertRaisesRegex(v.Invalid, "server-original-dependency"):
                server.delta({**original, name: original[name] + b"\n"}, current)

    def test_sources(self) -> None:
        """Every compiled source, dependency and fixture stays fixed; newly added production code cannot hide."""
        original, current = inputs()
        directories = (structure.SERVER, structure.PACKAGE, "tools/decisions")
        for directory in directories:
            for path in (ROOT / directory).glob("*.go"):
                if path.name.endswith("_test.go") and directory != structure.SERVER:
                    continue
                name = path.relative_to(ROOT).as_posix()
                current[name] = path.read_bytes()
                if name not in admission.MATERIAL or name.endswith("identity.go"):
                    original.setdefault(name, current[name])
        for name in ("go.mod", "go.sum", "dependencies.lock.json", authority.FIXTURE, watchdog.FIXTURE):
            current[name] = original[name] = v.read(ROOT / name)
        exports = b"\n".join(v.encode({"ImportPath": "github.com/eosforge/astra/" + name}) for name in directories)
        proof = server.impact(ROOT, original, current, exports)
        self.assertEqual(proof["directories"], sorted(directories))
        self.assertGreater(len(proof["sources"]), 15)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, data in current.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            self.assertEqual(server.impact(root, original, current, exports), proof)
            for name in (authority.FIXTURE, watchdog.FIXTURE, "polaris/internal/server/stream.go", "internal/admission/directory.go", "go.mod"):
                path = root / name
                path.write_bytes(current[name] + b"\n")
                with self.subTest(name=name), self.assertRaisesRegex(v.Invalid, "server-unreviewed-source-delta"):
                    server.impact(root, original, {**current, name: path.read_bytes()}, exports)
                path.write_bytes(current[name])
            path = root / "polaris/internal/server/extra.go"
            path.write_bytes(b"package server\n")
            with self.assertRaisesRegex(v.Invalid, "server-source-inventory"):
                server.impact(root, original, {**current, "polaris/internal/server/extra.go": path.read_bytes()}, exports)
        for altered in (b"{}", exports + v.encode({"ImportPath": "github.com/eosforge/astra/polaris"})):
            with self.assertRaisesRegex(v.Invalid, "server-production-closure"):
                server.impact(ROOT, original, current, altered)

    def test_archives(self) -> None:
        """Missing/forged archives and escaping or wrong-content references never reach semantic interpretation."""
        with self.assertRaisesRegex(v.Invalid, "server-retained-inventory-or-integrity"):
            server.reconcile(ROOT, {})
        forged = {name: b"{}" for name in server.ARTIFACTS}
        with self.assertRaisesRegex(v.Invalid, "server-retained-inventory-or-integrity"):
            server.reconcile(ROOT, forged)
        data = b"native"
        item = {"path": "proof.json", "bytes": len(data), "sha256": v.digest(data)}
        self.assertEqual(server.reference({"scope/proof.json": data}, "scope/", item), data)
        for path in ("../proof.json", "/proof.json", "a/../proof.json"):
            with self.subTest(path=path), self.assertRaisesRegex(v.Invalid, "server-artifact-path"):
                server.reference({}, "scope/", {**item, "path": path})
        for change in ({"bytes": 0}, {"sha256": "0" * 64}):
            with self.assertRaisesRegex(v.Invalid, "server-artifact-integrity"):
                server.reference({"scope/proof.json": data}, "scope/", {**item, **change})

    def test_entry(self) -> None:
        """Keep current acquisition qualification and both exact predecessor guards independently executable."""
        self.assertEqual(entry.artifacts(ROOT), consumers.ACQUISITION)
        validated_policy = v.configuration(ROOT / "development.json", ROOT)
        historical = {**entry.CURRENT, **{name: sha for name, sha in consumers.ARTIFACTS.items() if "server-batch-consumers-current-1/" in name}}
        with tempfile.TemporaryDirectory() as directory:
            legacy = Path(directory)
            for name, data in {
                installation.PATH: ingress.previous(v.read(ROOT / installation.PATH))[0],
                "internal/admission/identity.go": v.read(ROOT / "internal/admission/identity.go"),
            }.items():
                path = legacy / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            self.assertEqual(len(entry.artifacts(legacy)), 6)
            (legacy / "internal/admission/identity.go").write_bytes(v.read(ROOT / "tests/fixtures/admission-identity.go.in"))
            self.assertEqual(entry.artifacts(legacy), entry.ARCHIVES)
        self.assertEqual(entry.filename("entry-closure"), "entry-closure.tar.gz")
        self.assertEqual(entry.filename("reuse-plan/material-2/sealed.native.json"), "reuse-plan/material-2/sealed.native.json")
        with self.assertRaisesRegex(v.Invalid, "entry-input-inventory"):
            entry.reconcile(ROOT, {name: b"{}" for name in entry.ARCHIVES})
        directories = (structure.ENTRY, structure.PACKAGE, "tools/decisions")
        current = {path.relative_to(ROOT).as_posix(): path.read_bytes() for name in directories for path in (ROOT / name).glob("*.go")}
        current.update({name: v.read(ROOT / name) for name in ("go.mod", "go.sum", "dependencies.lock.json")})
        frozen = {name: v.digest(data) for name, data in current.items() if name not in admission.MATERIAL or name.endswith("identity.go")}
        frozen["internal/admission/identity.go"] = admission.SOURCES["internal/admission/identity.go"]
        frozen["internal/admission/node.go"] = admission.SOURCES["internal/admission/node.go"]
        exports = b"\n".join(v.encode({"ImportPath": "github.com/eosforge/astra/" + name}) for name in directories)
        files = {"inputs.json": v.encode({"files": frozen}), entry.PREFIX + "typed/exports/exports.stdout.log": exports}
        with self.assertRaisesRegex(v.Invalid, "entry-source-inventory"):
            entry.sources(ROOT, files)
        proof = entry.sources(ROOT, files, current=current)
        self.assertEqual(proof, {name: v.digest(data) for name, data in current.items()})
        missing = {name: data for name, data in current.items() if name != "internal/admission/file_linux.go"}
        with self.assertRaisesRegex(v.Invalid, "entry-current-regression-source"):
            entry.sources(ROOT, files, current=missing)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, data in current.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            for name in ("polaris/main.go", "polaris/main_test.go", "internal/admission/directory.go"):
                path = root / name
                path.write_bytes(current[name] + b"\n")
                with self.subTest(name=name), self.assertRaisesRegex(v.Invalid, "entry-source-drift"):
                    entry.sources(root, files, current={**current, name: path.read_bytes()})
                path.write_bytes(current[name])
            path = root / "internal/admission/unreviewed.go"
            path.write_bytes(b"package admission\n")
            with self.assertRaisesRegex(v.Invalid, "entry-source-inventory"):
                entry.sources(root, files, current={**current, "internal/admission/unreviewed.go": path.read_bytes()})
        artifacts = {name: v.read(ROOT / "build/results/assurance" / name, 32 * 1024**2) for name in historical}
        name, digest = next(iter(entry.CURRENT.items()))
        facts = consumers.unpack(artifacts[name], digest)
        source, _, outputs = consumers.native(facts, "entry-current-1", commands=entry.COMMANDS, prefix="source/build/commands/entry/")
        with tempfile.TemporaryDirectory() as directory:
            frozen = Path(directory)
            for name, data in source.items():
                path = frozen / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            # Validate today's full policy on today's source; the historical whole-policy schema has retired forms.
            frozen_policy = archived_entry_policy(source, validated_policy)
            self.assertNotEqual(frozen_policy[0], validated_policy[0])
            self.assertEqual(len(entry.artifacts(frozen)), 2)
            self.assertEqual(set(entry.artifacts(frozen)), set(entry.CURRENT) | {"reuse-plan/server-batch-consumers-current-1/native/evidence.tar.gz"})

            def policy(path: Path, root: Path) -> tuple[dict, dict, dict[str, str]]:
                """Inject only the already validated policy input; every native/source/semantic guard still executes."""
                self.assertEqual(path, frozen / "development.json")
                self.assertEqual(root, frozen)
                self.assertEqual(v.read(path), source["development.json"])
                return frozen_policy

            with patch.object(v, "configuration", side_effect=policy):
                result = entry.renew(frozen, artifacts)
                for name in artifacts:
                    with self.subTest(archive=name), self.assertRaisesRegex(v.Invalid, "entry-current-archive-integrity"):
                        entry.renew(frozen, {**artifacts, name: b"{}"})
        self.assertEqual(result["status"], "complete-under-assumptions")
        self.assertEqual((result["statements"]["hit"], result["independence"]["supported"]), (135, 26))
        self.assertEqual(result["current_native"]["test_cases"], 50)
        self.assertEqual((result["current_native"]["trace_processes"], result["current_native"]["control_processes"]), (4, 4))
        _, reused, _, _ = consumers.load(artifacts, "server-batch-consumers-current-1")
        exports = outputs["typed/exports"]
        maintenance = "polaris/internal/storage/maintenance.go"
        self.assertTrue((ROOT / maintenance).is_file())
        self.assertNotIn(maintenance, source)
        with self.assertRaisesRegex(v.Invalid, "entry-current-archive-integrity"):
            entry.renew(ROOT, artifacts)
        current_archives = {name: v.read(ROOT / "build/results/assurance" / name, 32 * 1024**2) for name in entry.MAINTENANCE}
        with patch.object(entry, "artifacts", return_value=entry.MAINTENANCE):
            with self.assertRaisesRegex(v.Invalid, "entry-current-input-inventory"):
                entry.renew(ROOT, current_archives)
        current_archives = {name: v.read(ROOT / "build/results/assurance" / name, 64 * 1024**2) for name in consumers.LEGACY_ACQUISITION}
        name, digest = next(iter(consumers.LEGACY_ACQUISITION.items()))
        acquired_files = consumers.unpack(current_archives[name], digest)
        acquired_source, _, _ = consumers.acquired(acquired_files)
        with tempfile.TemporaryDirectory() as directory:
            frozen = Path(directory)
            for path, data in acquired_source.items():
                target = frozen / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            frozen_policy = archived_entry_policy(acquired_source, validated_policy)

            def acquired_policy(path: Path, root: Path) -> tuple[dict, dict, dict[str, str]]:
                """Interpret only this exact archived source with its original Entry declaration."""
                self.assertEqual(path, frozen / "development.json")
                self.assertEqual(root, frozen)
                self.assertEqual(v.read(path), acquired_source["development.json"])
                return frozen_policy

            with patch.object(v, "configuration", side_effect=acquired_policy):
                qualified = entry.renew(frozen, current_archives)
        with patch.object(entry, "artifacts", return_value=consumers.LEGACY_ACQUISITION), self.assertRaisesRegex(v.Invalid, "entry-current-source-drift"):
            entry.renew(ROOT, current_archives)
        with self.assertRaisesRegex(v.Invalid, "entry-current-archive-integrity"):
            entry.renew(ROOT, current_archives)
        self.assertEqual((qualified["statements"]["hit"], qualified["independence"]["supported"]), (135, 26))
        self.assertEqual(qualified["current_native"]["test_cases"], 50)
        for name, raw in current_archives.items():
            with self.subTest(current_archive=name), self.assertRaisesRegex(v.Invalid, "entry-current-archive-integrity"):
                entry.renew(ROOT, {name: raw[:-1]})
        name, digest = next(iter(consumers.LEGACY_ACQUISITION.items()))
        acquired_files = consumers.unpack(current_archives[name], digest)
        acquired_inputs = v.decode(acquired_files["inputs.json"])
        for command in acquired_inputs["commands"]:
            path = command["stage"].removeprefix("build/") + "/record.json"
            record = v.decode(acquired_files[path])
            record["complete"] = False
            with self.subTest(incomplete_current_command=command["id"]), self.assertRaisesRegex(v.Invalid, "consumers-acquisition-completion"):
                consumers.acquired({**acquired_files, path: v.encode(record)})
        with self.assertRaisesRegex(v.Invalid, "entry-current-input-inventory"):
            entry.bindings(ROOT, source, reused, exports)
        names = (
            "polaris/main.go",
            "polaris/main_test.go",
            installation.PATH,
            "polaris/internal/storage/transaction_test.go",
            "tools/decisions/typing.go",
            "tools/decisions/runtime.go.in",
            "go.sum",
        )
        names += (next(name for name in result["dependencies"] if name.endswith(".proto")),)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in result["dependencies"]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(source[name])
            self.assertEqual(entry.bindings(root, source, reused, exports), result["dependencies"])
            for name in names:
                for first, second in (({**source, name: source[name] + b"\n"}, reused), (source, {**reused, name: reused[name] + b"\n"})):
                    with self.subTest(binding=name), self.assertRaisesRegex(v.Invalid, "entry-current-source-drift"):
                        entry.bindings(root, first, second, exports)
            for name in names:
                path = root / name
                path.write_bytes(source[name] + b"\n")
                with self.subTest(workspace=name), self.assertRaisesRegex(v.Invalid, "entry-current-source-drift"):
                    entry.bindings(root, source, reused, exports)
                path.write_bytes(source[name])
            path = root / "polaris/unreviewed.go"
            path.write_bytes(b"package main\n")
            with self.assertRaisesRegex(v.Invalid, "entry-current-input-inventory"):
                entry.bindings(root, source, reused, exports)
            path.unlink()
            path = root / "proto/unreviewed.proto"
            path.write_bytes(b'syntax = "proto3";\n')
            with self.assertRaisesRegex(v.Invalid, "entry-current-protocol-inventory"):
                entry.bindings(root, source, reused, exports)
        for modified in (b"{}", exports + v.encode({"ImportPath": "github.com/eosforge/astra/unreviewed", "Incomplete": True})):
            with self.subTest(imports=v.digest(modified)), self.assertRaisesRegex(v.Invalid, "entry-current-import-closure"):
                entry.bindings(ROOT, source, reused, modified)

        # Current compiler observations and fixed obligations have separate, exact source-bound denominators.
        upgraded = {name: v.read(ROOT / "build/results/assurance" / name, 64 * 1024**2) for name in consumers.ACQUISITION}
        upgraded_name, upgraded_sha = next(iter(consumers.ACQUISITION.items()))
        facts = consumers.unpack(upgraded[upgraded_name], upgraded_sha)
        acquired_source, records, _ = consumers.acquired(facts)
        self.assertEqual(consumers.compiler(facts), "1.27.2")
        self.assertEqual(len(records), 18)
        qualified = entry.renew(ROOT, upgraded)
        self.assertEqual((qualified["statements"]["hit"], qualified["statements"]["raw"], qualified["independence"]["supported"]), (100, 101, 26))
        self.assertEqual(qualified["statements"]["compiler_weights"]["obligations"], {"statements": 136, "statements_hit": 135})
        server_qualified = ingress.reconcile(ROOT, upgraded)
        self.assertEqual(server_qualified["status"], "complete-under-assumptions")
        self.assertEqual(server_qualified["statements"]["raw"], {"statements": 591, "statements_hit": 591})
        self.assertEqual(server_qualified["statements"]["compiler_weights"]["obligations"], {"statements": 659, "statements_hit": 659})
        self.assertEqual(server_qualified["independence"]["supported_conditions"], 213)
        profile = facts["commands/entry-race/coverage.out"]
        lines = profile.decode().splitlines()
        for index, line in enumerate(lines[1:], 1):
            span, weight, count = line.rsplit(" ", 2)
            if int(weight) and int(count):
                lines[index] = span + " " + weight + " 0"
                break
        else:
            self.fail("Native Entry profile has no reached statements")
        partial = ("\n".join(lines) + "\n").encode()
        single = entry.counters(ROOT, [profile], compiler="1.27.2")
        combined = entry.counters(ROOT, [profile, partial], compiler="1.27.2")
        self.assertEqual(combined["compiler_weights"], single["compiler_weights"])
        self.assertEqual((combined["raw"], combined["hit"]), (101, 100))
        for package, member in (("polaris", "commands/entry-race/coverage.out"), ("polaris/internal/server", "commands/server/coverage.profile")):
            selected = {name: {"data": data} for name, data in acquired_source.items() if name.startswith(package + "/") and name.endswith(".go")}
            if package == "polaris":
                selected = {"polaris/main.go": selected["polaris/main.go"]}
            _, blocks, _ = statements.profile(facts[member], selected, {"github.com/eosforge/astra/" + name: name for name in selected})
            for index in range(len(blocks)):
                changed = copy.deepcopy(blocks)
                changed[index]["statements"] += 1
                with self.subTest(weight=package, block=index), self.assertRaisesRegex(v.Invalid, "profile-weights-geometry"):
                    profileweights.reconcile(ROOT, package, changed)
            for changed in (blocks[:-1], blocks + blocks[:1], blocks[::-1]):
                with self.subTest(shape=package, count=len(changed)), self.assertRaisesRegex(v.Invalid, "profile-weights-geometry"):
                    profileweights.reconcile(ROOT, package, changed)
            for index, block in enumerate(blocks):
                if not block["count"] or not block["statements"]:
                    continue
                changed = copy.deepcopy(blocks)
                changed[index]["count"] = 0
                proof = profileweights.reconcile(ROOT, package, changed)
                self.assertLess(proof["native"]["statements_hit"], proof["native"]["statements"] - (1 if package == "polaris" else 0))
                self.assertLess(proof["obligations"]["statements_hit"], proof["obligations"]["statements"] - (1 if package == "polaris" else 0))
                if package == "polaris":
                    data = (
                        "mode: atomic\n"
                        + "\n".join(
                            "github.com/eosforge/astra/"
                            + row["file"]
                            + ":"
                            + str(row["span"][0])
                            + "."
                            + str(row["span"][1])
                            + ","
                            + str(row["span"][2])
                            + "."
                            + str(row["span"][3])
                            + " "
                            + str(row["statements"])
                            + " "
                            + str(row["count"])
                            for row in changed
                        )
                        + "\n"
                    )
                    with self.subTest(uncovered_entry=index), self.assertRaisesRegex(v.Invalid, "entry-profile-uncovered"):
                        entry.counters(ROOT, [data.encode()], compiler="1.27.2")
        with self.assertRaisesRegex(v.Invalid, "entry-profile-compiler"):
            entry.counters(ROOT, [], compiler="1.27.3")
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            for name in (*v.decode(v.read(ROOT / profileweights.FIXTURE))["source_sha256"], profileweights.FIXTURE, "development.json", "go.mod"):
                path = temporary / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(v.read(ROOT / name))
            self.assertEqual(consumers.acquisition(temporary), consumers.ACQUISITION)
            (temporary / "go.mod").write_bytes(source["go.mod"])
            self.assertEqual(consumers.acquisition(temporary), consumers.ACQUISITION)
            policy = v.decode(v.read(temporary / "development.json"))
            check = next(item for item in policy["checks"] if item["id"] == "polaris-entry-qualification")
            check["environment"]["PATH"] = check["environment"]["PATH"].replace("/go-1.27.2/", "/go-1.27.3/")
            (temporary / "development.json").write_bytes(v.encode(policy))
            with self.assertRaisesRegex(v.Invalid, "consumers-acquisition-compiler"):
                consumers.acquisition(temporary)
            (temporary / "polaris/main.go").write_bytes(v.read(ROOT / "polaris/main.go") + b"\n")
            with self.assertRaisesRegex(v.Invalid, "profile-weights-source"):
                entry.counters(temporary, [facts["commands/entry-race/coverage.out"]], compiler="1.27.2")
            (temporary / profileweights.FIXTURE).write_bytes(b"{}\n")
            with self.assertRaisesRegex(v.Invalid, "profile-weights-model"):
                entry.counters(temporary, [facts["commands/entry-race/coverage.out"]], compiler="1.27.2")


if __name__ == "__main__":
    unittest.main()
