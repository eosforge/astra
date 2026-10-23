"""Verify native Storage mutation coverage and reject altered provenance without repeating Go campaigns."""

import ast
import copy
from pathlib import Path
import tempfile
import unittest

from tools import entry, idle, independence, sensitivity, verify as v


class SensitivityTests(unittest.TestCase):
    """Keep original failures visible while qualifying exactly the unchanged finite operator denominator."""

    def test_current(self) -> None:
        """Assert each authenticated kill, preserving the first campaign's actual nonzero exit and five misses."""
        root = Path(__file__).resolve().parents[1]
        result = sensitivity.reconcile(root)
        current = idle.current(root)
        self.assertEqual((result["reused"], result["supplemented"], len(result["cells"])), (5, 101, 106) if current else (94, 5, 99))
        for name, cell in result["cells"].items():
            with self.subTest(mutant=name):
                self.assertEqual(cell["status"], "killed")
                self.assertEqual(cell["source_sha256"], v.file_digest(root / cell["file"]))
        if current:
            self.assertEqual(set(result["campaigns"]), set(sensitivity.CURRENT))
            self.assertTrue(all(item["exit_code"] == 0 for item in result["campaigns"].values()))
            self.assertEqual(result["invalid_original"], ["version-size"])
            self.assertEqual(result["campaigns"]["storage-idle-core-current-1"]["failures"], ["version-size:invalid"])
            self.assertEqual(result["cells"]["version-size"]["campaign"], "storage-version-boundary-current-2")
        else:
            original = result["campaigns"]["storage-core-current-3"]
            self.assertEqual(original["exit_code"], 2)
            self.assertEqual(set(original["failures"]), {name + ":survived" for name in sensitivity.SURVIVORS})

    def test_integrity(self) -> None:
        """Corrupt each archive and its seal independently; neither may acquire qualification credit."""
        root = Path(__file__).resolve().parents[1]
        artifacts = {}
        current = idle.current(root)
        for name in sensitivity.CURRENT if current else sensitivity.ORIGINS:
            directory = root / sensitivity.BASE / name / "native"
            artifacts[name] = (v.read(directory / "evidence.tar.gz", sensitivity.MAXIMUM), v.decode(v.read(directory / "sealed.native.json")))
        for name in artifacts:
            for target in ("archive", "member", "trust"):
                changed = copy.deepcopy(artifacts)
                data, seal = changed[name]
                if target == "archive":
                    changed[name] = (data + b"corrupt", seal)
                elif target == "member":
                    if current:
                        seal["cleanup"]["original_exit_code"] = 1
                    else:
                        seal["files"]["inputs.json"]["sha256"] = "0" * 64
                else:
                    seal["trust"] = "release"
                with self.subTest(campaign=name, target=target), self.assertRaises(v.Invalid):
                    sensitivity.reconcile(root, changed)

    def test_current_controls(self) -> None:
        """Reject damaged native commands and semantic counterexamples without executing an application again."""
        root = Path(__file__).resolve().parents[1]
        files, _, _ = sensitivity.acquired(root, "storage-idle-core-current-1")
        inputs = v.decode(files["inputs.json"])
        owner = v.decode(files["controller.json"])
        check = next(item for item in inputs["auxiliary"] if item["id"] == "current-core-mutants")
        prefix = "source/build/commands/current-core-mutants/"
        self.assertEqual(sensitivity.command(files, prefix, check, owner)[0]["exit_code"], 0)
        for key, value in (
            ("complete", False),
            ("cleanup", False),
            ("exit_code", 1),
            ("termination", "timeout"),
            ("duration_ms", 1200001),
            ("executable_sha256", "0" * 64),
        ):
            changed = dict(files)
            record = v.decode(changed[prefix + "record.json"])
            record[key] = value
            changed[prefix + "record.json"] = v.encode(record)
            with self.subTest(command=key), self.assertRaises(v.Invalid):
                sensitivity.command(changed, prefix, check, owner)
        for key, value in (("boot_id", "0" * 36), ("cwd", "/outside"), ("argv", ["python3", "unrelated.py"])):
            changed = dict(files)
            process = v.decode(changed[prefix + check["id"] + ".process.json"])
            process[key] = value
            changed[prefix + check["id"] + ".process.json"] = v.encode(process)
            with self.subTest(process=key), self.assertRaises(v.Invalid):
                sensitivity.command(changed, prefix, check, owner)
        child = next(name for name in files if name.endswith("maintenance-child.stdout.log"))
        data = files[child]
        test = "TestMaintenanceContext"
        witness = sensitivity.WITNESSES["maintenance-child"]
        self.assertIsNone(sensitivity.failure(data, test, witness))
        for before, after in (
            (witness, "unrelated"),
            (witness, "panic: " + witness),
            ('"OutputType":"error"', '"OutputType":"frame"'),
            (witness, "WARNING: DATA RACE " + witness),
        ):
            with self.subTest(counterexample=after), self.assertRaises(v.Invalid):
                sensitivity.failure(data.replace(before.encode(), after.encode()), test, witness)

    def test_sources(self) -> None:
        """Reject an added Go oracle and changed production bytes even when external archives remain intact."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / sensitivity.PACKAGE
            package.mkdir(parents=True)
            for name, data in {"go.mod": b"module example\n", "go.sum": b"", sensitivity.PACKAGE + "store.go": b"package storage\n"}.items():
                (root / name).write_bytes(data)
            inputs = {"files": {path.relative_to(root).as_posix(): v.file_digest(path) for path in root.rglob("*") if path.is_file()}}
            sensitivity.sources(root, inputs)
            # A native-qualified added case does not change old oracles; its bytes and every original input stay fixed.
            compatibility = package / "compatibility_test.go"
            compatibility.write_bytes(v.read(Path(__file__).resolve().parents[1] / sensitivity.PACKAGE / compatibility.name))
            self.assertIsNone(sensitivity.sources(root, inputs))
            compatibility.write_bytes(v.read(compatibility) + b"\n")
            with self.assertRaisesRegex(v.Invalid, "storage-compatibility-source"):
                sensitivity.sources(root, inputs)
            compatibility.unlink()
            (package / "store.go").write_bytes(b"package changed\n")
            with self.assertRaisesRegex(v.Invalid, "storage-sensitivity-source:"):
                sensitivity.sources(root, inputs)
            (package / "store.go").write_bytes(b"package storage\n")
            (package / "extra_test.go").write_bytes(b"package storage\n")
            with self.assertRaisesRegex(v.Invalid, "storage-sensitivity-source-inventory"):
                sensitivity.sources(root, inputs)

    def test_producer_scope(self) -> None:
        """Keep historical producer bytes separate from current package, dependency and fixture inputs."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            material = {
                "go.mod": b"module example\n",
                "go.sum": b"dependency\n",
                sensitivity.PACKAGE + "store.go": b"package storage\n",
                "tests/fixtures/storage.go.in": b"package storage\n",
                "tools/assurance.py": b"# historical planner\n",
                "tools/delivery.py": b"# historical delivery reader\n",
                sensitivity.PACKAGE + "numeric.json": b"uninvoked range ledger\n",
                sensitivity.PACKAGE + "core-mutations.json": b"consumed mutation declaration\n",
                sensitivity.PACKAGE + "testdata/schema.sql": b"consumed SQL fixture\n",
            }
            for name, data in material.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            inputs = {"files": {name: v.digest(data) for name, data in material.items()}}
            for name in ("tools/assurance.py", "tools/delivery.py", sensitivity.PACKAGE + "numeric.json"):
                (root / name).write_bytes(b"# unrelated current interpreter\n")
            sensitivity.sources(root, inputs)
            for name in (
                "go.mod",
                "go.sum",
                sensitivity.PACKAGE + "store.go",
                "tests/fixtures/storage.go.in",
                sensitivity.PACKAGE + "core-mutations.json",
                sensitivity.PACKAGE + "testdata/schema.sql",
            ):
                with self.subTest(input=name):
                    (root / name).write_bytes(material[name] + b"changed\n")
                    with self.assertRaisesRegex(v.Invalid, "storage-sensitivity-source:"):
                        sensitivity.sources(root, inputs)
                    (root / name).write_bytes(material[name])
            (root / sensitivity.PACKAGE / "extra_test.go").write_bytes(b"package storage\n")
            with self.assertRaisesRegex(v.Invalid, "storage-sensitivity-source-inventory"):
                sensitivity.sources(root, inputs)

        # Scope changes remain acceptable only when every other command and Go mutation rule is unchanged.
        build = b"def main():\n    run([go, '-C', SOURCE, 'test', '-mod=readonly', '-count=1', '-p', cases, '-parallel', 1, './...'], env)\n"
        scoped = build.replace(b"'./...'", b"'./internal/...', './polaris/...', './astrolabe/...'")
        self.assertIsNone(independence.helper("tools/build.py", build, scoped))
        self.assertIsNone(independence.helper("tools/build.py", build, b"# Independent SDK scope\n" + scoped))
        for altered in (
            scoped.replace(b"'./internal/...', ", b""),
            scoped.replace(b"'./polaris/...', ", b""),
            scoped.replace(b", './astrolabe/...'", b""),
            scoped.replace(b"'./astrolabe/...'", b"'./astrolabe/...', './comet/go/...'"),
            scoped.replace(b"'-count=1'", b"'-count=0'"),
            scoped.replace(b"'-mod=readonly'", b"'-mod=mod'"),
            scoped.replace(b"'-parallel', 1", b"'-parallel', 16"),
            scoped.replace(b"], env)", b"], unsafe())"),
            scoped.replace(b"def main", b"def unrelated"),
            scoped + b"    publish()\n",
            scoped + scoped.split(b"\n", 1)[1],
            build,
        ):
            with self.subTest(build=altered), self.assertRaises(v.Invalid):
                independence.helper("tools/build.py", build, altered)
        with self.assertRaises(v.Invalid):
            independence.helper("tools/build.py", scoped, scoped)

        cpp = b"def cpp_run(manifest, directory, output, root):\n    return 1\n"
        main = (
            b"def main(arguments=None):\n"
            b"    parser = argparse.ArgumentParser()\n"
            b"    args = parser.parse_args(arguments)\n"
            b"    if isinstance(manifest, dict) and manifest.get('engine') == 'cpp':\n"
            b"        return cpp_run(manifest, args.build.resolve(), output, root)\n"
            b"    return go_run(manifest)\n"
        )
        option = b"    parser.add_argument('--prune', action='store_true', help=\"Remove only successful C++ attempts' drained, rebuildable objects and programs\")\n"
        guard = b"    if args.prune:\n        v.reject('mutation-prune-cpp-required')\n"
        updated = cpp.replace(b"root):", b"root, *, prune=False):").replace(b"return 1", b"return 2") + main
        updated = updated.replace(b"    args =", option + b"    args =")
        updated = updated.replace(b"output, root)", b"output, root, prune=args.prune)").replace(b"    return go_run", guard + b"    return go_run")
        self.assertIsNone(independence.helper("tools/mutate.py", cpp + main, updated))
        for altered in (
            updated.replace(b"return go_run(manifest)", b"return None"),
            updated.replace(b"'engine') == 'cpp'", b"'engine') != 'cpp'"),
            updated.replace(b"prune=args.prune", b"prune=unsafe()"),
            updated.replace(b"prune=False", b"prune=unsafe()"),
            updated.replace(b"def cpp_run", b"@unsafe\ndef cpp_run"),
            updated.replace(option, option + option),
            updated.replace(guard, b""),
            updated.replace(b"v.reject('mutation-prune-cpp-required')", b"pass"),
            updated + b"UNREVIEWED = unsafe()\n",
        ):
            with self.subTest(mutation=altered), self.assertRaises(v.Invalid):
                independence.helper("tools/mutate.py", cpp + main, altered)
        additions = next(
            node
            for node in ast.parse(v.read(Path(__file__).resolve().parents[1] / "tools/storage.py")).body
            if isinstance(node, ast.FunctionDef) and node.name == "additions"
        )
        original = b"def sources(root, files, inputs, exports):\n    actual = files\n    return actual\n"
        for name, call in (("tools/storage.py", b"additions(root, original)"), ("tools/sensitivity.py", b"storage.additions(root, names)")):
            prefix = (ast.unparse(additions) + "\n").encode() if name == "tools/storage.py" else b""
            projected = prefix + original.replace(b"    return actual", b"    actual -= " + call + b"\n    return actual")
            self.assertIsNone(independence.helper(name, original, projected))
            for altered in (
                projected.replace(b"return actual", b"return None"),
                projected.replace(b"actual -=", b"actual ="),
                projected.replace(call, call + b" | unsafe()"),
                projected.replace(b"    actual -= " + call + b"\n", b""),
                projected + b"UNREVIEWED = unsafe()\n",
            ):
                with self.subTest(source=name, altered=altered), self.assertRaises(v.Invalid):
                    independence.helper(name, original, altered)
            if name == "tools/storage.py":
                altered = projected.replace(b"return {name}", b"return set()")
                with self.assertRaises(v.Invalid):
                    independence.helper(name, original, altered)

    def test_interface(self) -> None:
        """Use the historical validator's own positive context; changed parser, schema and oracle bytes still refuse reuse."""
        original = Path(__file__).resolve().parents[1]
        packed = v.read(original / "build/results/assurance" / idle.SOURCE, 64 * 1024**2)
        self.assertEqual(v.digest(packed), idle.ARTIFACTS[idle.SOURCE])
        frozen = entry.unpack(packed)
        certificate = independence.BASE.rstrip("/").split("/")[-1]
        facts = {certificate + "/received.json": v.encode({"source": {"files": []}}), "current-source/tests/test_structure.py": b""}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("tools/verify.py", "tools/schemas/development.schema.json"):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(frozen[name])
            (root / "tests").mkdir()
            (root / "tests/test_structure.py").write_bytes(b"")
            independence.sources(root, facts)
            path = root / "tools/schemas/development.schema.json"
            schema = v.decode(v.read(path))
            for field in ("unknown-adapter", "duplicate-adapter", "duplicate-repair", "duplicate-rollback", "minimum", "required", "unknown-field"):
                changed = copy.deepcopy(schema)
                variant = changed["properties"]["checks"]["items"]["oneOf"][-1]
                if field == "unknown-adapter":
                    variant["properties"]["adapter"]["enum"].append("unreviewed")
                elif field == "duplicate-adapter":
                    variant["properties"]["adapter"]["enum"].append("storage-delivery")
                elif field == "duplicate-repair":
                    variant["properties"]["adapter"]["enum"].append("admission-repair")
                elif field == "duplicate-rollback":
                    variant["properties"]["adapter"]["enum"].append("storage-repair")
                elif field == "minimum":
                    variant["properties"]["log_bytes"]["minimum"] = 1
                elif field == "required":
                    variant["required"].remove("argv")
                else:
                    changed["unreviewed"] = True
                path.write_bytes(v.encode(changed))
                with self.subTest(change=field), self.assertRaisesRegex(v.Invalid, "storage-independence-schema-source"):
                    independence.sources(root, facts)
            path.write_bytes(v.encode(schema))
            validator = root / "tools/verify.py"
            validator.write_bytes(v.read(validator) + b"\nUNREVIEWED = True\n")
            with self.assertRaisesRegex(v.Invalid, "storage-independence-validator-source"):
                independence.sources(root, facts)
            validator.write_bytes(frozen["tools/verify.py"])
            retained = independence.ancestry(independence.artifacts(original, historical=True))
            facts["current-source/tests/test_structure.py"] = retained["current-source/tests/test_structure.py"]
            # This retained guard cannot automatically qualify later schema/parser or test revisions.
            current = frozen["tests/test_structure.py"]
            oracle = root / "tests/test_structure.py"
            oracle.write_bytes(current)
            fixture = root / "tests/fixtures/qualification.json"
            fixture.parent.mkdir(parents=True)
            fixture.write_bytes(v.read(original / "tests/fixtures/qualification.json"))
            self.assertIsNone(independence.sources(root, facts))
            for target in ("policy", "native", "fixture"):
                changed = ast.parse(current)
                if target == "policy":
                    owner = next(node for node in changed.body if isinstance(node, ast.ClassDef) and node.name == "StructureTests")
                    method = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "test_fixed_obligations")
                    method.body[1] = ast.Pass()
                elif target == "native":
                    old = ast.parse(facts["current-source/tests/test_structure.py"])
                    owner = next(node for node in old.body if isinstance(node, ast.ClassDef))
                    method = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name != "test_fixed_obligations")
                    owner = next(node for node in changed.body if isinstance(node, ast.ClassDef) and node.name == owner.name)
                    method = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == method.name)
                    method.body[1] = ast.Pass()
                else:
                    fixture.write_bytes(b"{}")
                oracle.write_text(ast.unparse(changed), encoding="utf-8")
                with self.subTest(oracle=target), self.assertRaisesRegex(v.Invalid, "storage-independence-oracle-"):
                    independence.sources(root, facts)
                oracle.write_bytes(current)
                fixture.write_bytes(v.read(original / "tests/fixtures/qualification.json"))
        # Synthetic projections never supply product credit; the native caller separately pins the original archive and source bytes.
        baseline = b"LIMIT = 12\ndef unpack(data):\n    return data\ndef reconcile(root):\n    return 1\n"
        updated = baseline.replace(b"return 1", b"return 2") + b"CURRENT = {'archive': 'digest'}\nCOMMANDS = ('exports',)\n"
        self.assertIsNone(independence.helper("tools/entry.py", baseline, updated))
        for altered in (
            updated.replace(b"LIMIT = 12", b"LIMIT = 13"),
            updated.replace(b"return data", b"return b'changed'"),
            updated.replace(b"CURRENT = {'archive': 'digest'}", b"CURRENT = unknown()"),
            updated.replace(b"def reconcile", b"@unknown\ndef reconcile"),
            updated.replace(b"def reconcile(root)", b"def reconcile(root=unknown())"),
        ):
            with self.assertRaises(v.Invalid):
                independence.helper("tools/entry.py", baseline, altered)
        server = b"ARTIFACTS = {}\ndef reconcile(root):\n    return 1\ndef reference(data):\n    return data\n"
        self.assertIsNone(independence.helper("tools/server.py", server, server.replace(b"return 1", b"return 2")))
        with self.assertRaises(v.Invalid):
            independence.helper("tools/server.py", server, server.replace(b"return data", b"return b'changed'"))
        legacy = b"SERVER = 'server'\ndef revision(root, package):\n    return package\ndef load(root, retained_server):\n    if retained_server:\n        reader, expected = server, server.ARTIFACTS\n    return root\n"
        branch = b"    if package == SERVER and v.file_digest(root / SERVER / 'authority.go') == '76348643eb6b779fe7bd42fb2e438439d247367739c7a523b898ff872dbbc481':\n        return 'server'\n"
        extended = legacy.replace(b"    return package", branch + b"    return package").replace(b"server.ARTIFACTS", b"server.artifacts(root)")
        self.assertIsNone(independence.helper("tools/structure.py", legacy, extended))
        for altered in (
            extended.replace(b"return package", b"return 'changed'"),
            extended.replace(b"return root", b"return None"),
            extended.replace(b"if retained_server:", b"if not retained_server:"),
            extended.replace(b"package == SERVER", b"package != SERVER"),
        ):
            with self.assertRaises(v.Invalid):
                independence.helper("tools/structure.py", legacy, altered)
        with self.assertRaises(v.Invalid):
            independence.helper("unreviewed.py", baseline, baseline)
