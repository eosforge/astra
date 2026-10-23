"""Challenge Boolean evidence reconciliation with literal traces, exhaustive small truth tables and corrupted native bundles."""

import copy
import itertools
import json
import shutil
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import logic, verify as v


class LogicTests(unittest.TestCase):
    """Synthetic runner records validate the importer itself; real native campaigns supply project evidence."""

    def setUp(self) -> None:
        """Build one source-bound conjunction, its raw short-circuit observations and a complete native event sequence."""
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "source"
        self.root.mkdir()
        self.code = b"package unit\nfunc Rule(a, b bool) bool { return a && b }\n"
        begin = self.code.index(b"a && b")

        def at(offset: int) -> dict[str, int]:
            """Encode actual byte-based source coordinates for the literal fixture."""
            return {"offset": offset, "line": 2, "column": offset - self.code.index(b"func") + 1}

        self.decision = {
            "id": f"unit/rule.go:{begin}",
            "kind": "return",
            "text": "a && b",
            "begin": at(begin),
            "end": at(begin + 6),
            "tree": [{"kind": "atom", "atom": 0}, {"kind": "atom", "atom": 1}, {"kind": "and", "children": [0, 1]}],
            "root": 2,
            "atoms": [{"text": name, "begin": at(offset), "end": at(offset + 1)} for name, offset in (("a", begin), ("b", begin + 5))],
        }
        self.file = {"file": "unit/rule.go", "sha256": v.digest(self.code), "functions": [], "decisions": [self.decision], "controls": []}
        self.manifest = {
            "version": 1,
            "source_sha256": "0" * 64,
            "qualification": "not-evaluated",
            "basis": "synthetic diagnostic fixture",
            "files": [self.file],
            "observed": [self.decision["id"]],
        }
        self.receipt = {
            "pid": 10,
            "code": 0,
            "rows": [
                {"id": self.decision["id"], "values": vector, "result": result, "hits": count}
                for vector, result, count in (("10", False, 7), ("21", False, 3), ("22", True, 5))
            ],
        }

    def events(self, receipts: list[dict] | None = None) -> bytes:
        """Frame process observations inside a complete synthetic go-test JSON stream, including split output chunks."""
        receipts = [self.receipt] if receipts is None else receipts
        stream = "".join("GO-DECISIONS " + json.dumps(receipt) + "\n" for receipt in receipts)
        middle = len(stream) // 2
        values = [
            {"Action": "start"},
            {"Action": "run", "Test": "TestRule"},
            {"Action": "output", "Test": "TestRule", "Output": stream[:middle]},
            {"Action": "output", "Test": "TestRule", "Output": stream[middle:]},
            {"Action": "pass", "Test": "TestRule"},
            {"Action": "pass"},
        ]
        return b"\n".join(json.dumps(dict(value, Package="example.org/fixture/unit")).encode() for value in values) + b"\n"

    def summarize(self, manifest: dict | None = None, events: bytes | None = None, **options: int) -> dict:
        """Use the public core reconciler without native-runner bypasses."""
        return logic.summary(
            self.manifest if manifest is None else manifest, self.events() if events is None else events, "example.org/fixture/unit", 1, **options
        )

    def test_literal_pairs(self) -> None:
        """Masked operands remain unknown in concrete witnesses, and native counts cannot create extra rows."""
        result = self.summarize()
        self.assertEqual(result["qualification"], "not-evaluated")
        self.assertEqual(result["totals"], {"roots": 1, "observed": 1, "both": 1, "atoms": 2, "candidates": 2, "search_incomplete": 0})
        self.assertEqual(result["decisions"][0]["atoms"][0]["candidate"], {"false": "10", "true": "22"})
        self.assertEqual(result["decisions"][0]["atoms"][1]["candidate"], {"false": "21", "true": "22"})
        # A skipped B may depend on A's concrete input; guessing B=true would fabricate independence for A.
        self.assertIsNone(result["decisions"][0]["atoms"][0]["independent"])
        self.assertEqual(result["decisions"][0]["atoms"][1]["independent"], {"false": "21", "true": "22", "fixed": "20"})
        self.assertEqual(result["independence"]["criterion"], "universal-common-cube-v1")
        self.assertEqual(result["independence"]["pairs"], 1)
        self.assertEqual(result["independence"]["search_incomplete"], 0)
        self.assertEqual([row["hits"] for row in result["decisions"][0]["vectors"]], [7, 3, 5])
        other = copy.deepcopy(self.receipt)
        other["pid"] = 11
        merged = self.summarize(events=self.events([self.receipt, other]))
        self.assertEqual(merged["process_receipts"], 2)
        self.assertEqual([row["hits"] for row in merged["decisions"][0]["vectors"]], [14, 6, 10])
        self.assertEqual(merged["independence"]["pairs"], 1)

    def test_missing_and_budget(self) -> None:
        """A root with both outcomes can lack a condition witness; exhausted search never counts as completion."""
        receipt = copy.deepcopy(self.receipt)
        receipt["rows"].pop(1)
        result = self.summarize(events=self.events([receipt]))
        self.assertEqual(result["totals"]["both"], 1)
        self.assertEqual(result["totals"]["candidates"], 1)
        self.assertIsNone(result["decisions"][0]["atoms"][1]["candidate"])
        limited = self.summarize(budget=1)
        self.assertEqual(limited["pair_comparisons"], 1)
        self.assertEqual(limited["totals"]["search_incomplete"], 1)
        self.assertEqual(limited["totals"]["candidates"], 1)
        empty = self.summarize(budget=0)
        self.assertEqual(empty["totals"]["candidates"], 0)
        self.assertEqual(empty["totals"]["search_incomplete"], 1)
        self.assertEqual(result["independence"]["pairs"], 0)
        limited = self.summarize(independence_budget=1)
        self.assertEqual(limited["independence"]["comparisons"], 1)
        self.assertEqual(limited["independence"]["search_incomplete"], 1)
        self.assertEqual(limited["independence"]["pairs"], 0)
        empty = self.summarize(independence_budget=0)
        self.assertEqual(empty["totals"]["candidates"], 2)
        self.assertEqual(empty["independence"]["pairs"], 0)
        self.assertEqual(empty["independence"]["search_incomplete"], 1)
        for value in (-1, True, 1.0):
            with self.subTest(value=value), self.assertRaises(v.Invalid):
                self.summarize(budget=value)
            with self.subTest(independence_budget=value), self.assertRaises(v.Invalid):
                self.summarize(independence_budget=value)

    def test_unsupported_and_unseen(self) -> None:
        """Uninstrumented roots and separate controls retain their denominator instead of disappearing."""
        manifest = copy.deepcopy(self.manifest)
        extra = copy.deepcopy(self.decision)
        extra["begin"]["offset"] += 1
        extra["atoms"][0]["begin"]["offset"] += 1
        extra["atoms"][0]["end"]["offset"] += 1
        extra["id"] = f"unit/rule.go:{extra['begin']['offset']}"
        extra["kind"] = "boolean"
        manifest["files"][0]["decisions"].append(extra)
        manifest["files"][0]["controls"] = [{"kind": "defer", "begin": self.decision["begin"], "end": self.decision["end"]}]
        result = self.summarize(manifest=manifest)
        self.assertEqual(result["totals"]["roots"], 2)
        self.assertEqual(result["totals"]["observed"], 1)
        self.assertEqual(result["totals"]["atoms"], 4)
        self.assertFalse(result["decisions"][1]["instrumented"])
        self.assertEqual(result["decisions"][1]["vectors"], [])
        self.assertEqual(result["controls"], [{"file": "unit/rule.go", "controls": manifest["files"][0]["controls"]}])

    def test_truth_tables(self) -> None:
        """Independent Python formulas generate native-order traces for every assignment of three small trees."""
        trees = [
            ([{"kind": "atom", "atom": 0}, {"kind": "not", "children": [0]}], 1, lambda read: not read(0)),
            (
                [
                    {"kind": "atom", "atom": 0},
                    {"kind": "atom", "atom": 1},
                    {"kind": "or", "children": [0, 1]},
                    {"kind": "atom", "atom": 2},
                    {"kind": "and", "children": [2, 3]},
                ],
                3,
                lambda read: (read(0) or read(1)) and read(2),
            ),
            (
                [
                    {"kind": "atom", "atom": 0},
                    {"kind": "atom", "atom": 1},
                    {"kind": "and", "children": [0, 1]},
                    {"kind": "atom", "atom": 2},
                    {"kind": "atom", "atom": 3},
                    {"kind": "and", "children": [3, 4]},
                    {"kind": "or", "children": [2, 5]},
                ],
                4,
                lambda read: (read(0) and read(1)) or (read(2) and read(3)),
            ),
        ]
        for tree, count, formula in trees:
            with self.subTest(tree=tree):
                decision = {"tree": tree, "root": len(tree) - 1, "atoms": [{}] * count}
                rows = {}
                completions = {}
                for assignment in itertools.product((False, True), repeat=count):
                    vector = ["0"] * count

                    def read(index: int) -> bool:
                        """Record each independently executed formula operand once, leaving skipped operands unknown."""
                        self.assertEqual(vector[index], "0")
                        vector[index] = "2" if assignment[index] else "1"
                        return assignment[index]

                    outcome = formula(read)
                    key = ("".join(vector), outcome)
                    rows[key] = rows.get(key, 0) + 1
                    completions.setdefault(key, set()).add(assignment)
                    self.assertEqual(logic.evaluate(decision, key[0]), outcome)
                witnesses, _, complete = logic.candidates(decision, rows, 1000)
                self.assertTrue(complete)
                self.assertEqual(set(witnesses), set(range(count)))
                for index, pair in witnesses.items():
                    # A full truth-table witness independently validates the candidate's compatible masking.
                    pairs = itertools.product(completions[(pair["false"], False)], completions[(pair["true"], True)])
                    self.assertTrue(any([i for i in range(count) if left[i] != right[i]] == [index] for left, right in pairs))
                # The oracle enumerates complete assignments, independently of the production three-valued algebra.
                for partial in itertools.product("012", repeat=count):
                    outcomes = {
                        formula(lambda i: assignment[i])
                        for assignment in itertools.product((False, True), repeat=count)
                        if all(value == "0" or (value == "2") == assignment[i] for i, value in enumerate(partial))
                    }
                    expected = next(iter(outcomes)) if len(outcomes) == 1 else None
                    self.assertIs(logic.cube(decision, partial), expected)
                proofs, _, complete = logic.candidates(decision, rows, 1000, certify=True)
                self.assertTrue(complete)
                self.assertTrue(proofs)
                for index, proof in proofs.items():
                    self.assertIn((proof["false"], False), rows)
                    self.assertIn((proof["true"], True), rows)
                    self.assertNotEqual(proof["false"][index], proof["true"][index])
                    self.assertNotIn("0", (proof["false"][index], proof["true"][index]))
                    expected = "".join(a if a == b and i != index else "0" for i, (a, b) in enumerate(zip(proof["false"], proof["true"])))
                    self.assertEqual(proof["fixed"], expected)
                    hits = 0
                    for assignment in itertools.product((False, True), repeat=count):
                        if any(value != "0" and (value == "2") != assignment[i] for i, value in enumerate(proof["fixed"])):
                            continue
                        for outcome in (False, True):
                            concrete = list(assignment)
                            concrete[index] = proof["true" if outcome else "false"][index] == "2"
                            self.assertIs(formula(lambda i: concrete[i]), outcome)
                            hits += 1
                    self.assertGreater(hits, 0)

    def test_tree_rejections(self) -> None:
        """Malformed coordinates, cycles, shared nodes, reversed operands and invented roots are rejected."""
        mutations = [
            lambda m: m.update(version=True),
            lambda m: m.update(extra=1),
            lambda m: m.update(observed=[]),
            lambda m: m["observed"].append(m["observed"][0]),
            lambda m: m["files"].append(copy.deepcopy(m["files"][0])),
            lambda m: m["files"][0].update(file="../escape.go"),
            lambda m: m["files"][0]["decisions"][0].update(root=True),
            lambda m: m["files"][0]["decisions"][0]["begin"].update(offset=-1),
            lambda m: m["files"][0]["decisions"][0]["tree"][2].update(children=[0, 2]),
            lambda m: m["files"][0]["decisions"][0]["tree"][2].update(children=[1, 0]),
            lambda m: m["files"][0]["decisions"][0]["tree"][2].update(children=[0, 0]),
            lambda m: m["files"][0]["decisions"][0]["tree"][0].update(atom=True),
            lambda m: m["files"][0]["decisions"][0]["tree"][1].update(atom=0),
            lambda m: m["files"][0]["decisions"][0]["atoms"][1]["begin"].update(offset=0),
            lambda m: m["files"][0]["decisions"][0]["tree"].append({"kind": "atom", "atom": 0}),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                manifest = copy.deepcopy(self.manifest)
                mutate(manifest)
                with self.assertRaises(v.Invalid):
                    self.summarize(manifest=manifest)

    def test_receipt_rejections(self) -> None:
        """False outcomes, impossible short circuits, duplicate/failing processes and invented counts cannot pass."""
        mutations = [
            lambda r: r.update(code=1),
            lambda r: r.update(pid=True),
            lambda r: r.update(rows=[]),
            lambda r: r["rows"].append(copy.deepcopy(r["rows"][0])),
            lambda r: r["rows"][0].update(id="invented"),
            lambda r: r["rows"][0].update(values="00"),
            lambda r: r["rows"][0].update(values="12"),
            lambda r: r["rows"][0].update(values="3"),
            lambda r: r["rows"][0].update(result=True),
            lambda r: r["rows"][0].update(result=0),
            lambda r: r["rows"][0].update(hits=True),
            lambda r: r["rows"][0].update(hits=0),
            lambda r: r["rows"][0].update(hits=2**64),
            lambda r: r["rows"][0].update(extra="forged"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                receipt = copy.deepcopy(self.receipt)
                mutate(receipt)
                with self.assertRaises(v.Invalid):
                    self.summarize(events=self.events([receipt]))
        with self.assertRaises(v.Invalid):
            self.summarize(events=self.events([self.receipt, self.receipt]))
        data = self.events()
        for changed in (
            data[: len(data) // 2],
            data.replace(b'"Action": "pass"', b'"Action": "skip"', 1),
            data.replace(b'"Action": "pass"', b'"Action": "fail"', 1),
            data.replace(b'\\"pid\\": 10', b'\\"pid\\": 10, \\"pid\\": 11'),
            data + data,
        ):
            with self.subTest(data=changed[-60:]), self.assertRaises(v.Invalid):
                self.summarize(events=changed)

    def typed_manifest(self) -> dict:
        """Describe explicit synthetic type facts for importer self-checks, never a native compiler claim."""
        manifest = copy.deepcopy(self.manifest)
        manifest.update(
            version=2,
            typing={
                "metadata_sha256": "2" * 64,
                "package": "example.org/fixture/unit",
                "files": ["unit/rule.go"],
                "inactive": [],
                "results": {self.decision["id"]: "bool"},
                "constants": [],
                "exports": {},
            },
        )
        return manifest

    def test_typed_inventory(self) -> None:
        """Typed runtime roots may be observed; constants and inactive stubs preserve their explicit denominator."""
        manifest = self.typed_manifest()
        manifest["typing"]["results"][self.decision["id"]] = "Flag"
        result = self.summarize(manifest=manifest)
        self.assertEqual(result["totals"]["candidates"], 2)
        self.assertEqual(result["qualification"], "not-evaluated")
        extra = copy.deepcopy(self.decision)
        extra["begin"]["offset"] += 1
        extra["atoms"][0]["begin"]["offset"] += 1
        extra["atoms"][0]["end"]["offset"] += 1
        extra["id"] = f"unit/rule.go:{extra['begin']['offset']}"
        extra["kind"] = "boolean"
        manifest["files"][0]["decisions"].append(extra)
        manifest["typing"]["results"][extra["id"]] = "alias.Flag"
        manifest["observed"].append(extra["id"])
        receipt = copy.deepcopy(self.receipt)
        receipt["rows"].extend([dict(row, id=extra["id"]) for row in self.receipt["rows"]])
        result = self.summarize(manifest=manifest, events=self.events([receipt]))
        self.assertEqual(result["totals"]["roots"], 2)
        self.assertEqual(result["totals"]["observed"], 2)
        self.assertTrue(result["decisions"][1]["instrumented"])
        manifest["typing"]["constants"].append(extra["id"])
        del manifest["typing"]["results"][extra["id"]]
        manifest["observed"].pop()
        result = self.summarize(manifest=manifest)
        self.assertEqual(result["totals"]["roots"], 2)
        self.assertEqual(result["totals"]["observed"], 1)
        self.assertFalse(result["decisions"][1]["instrumented"])
        self.assertEqual(result["decisions"][1]["vectors"], [])
        manifest["files"].append({"file": "unit/stub.go", "sha256": "3" * 64, "functions": [], "decisions": [], "controls": []})
        manifest["typing"]["inactive"].append("unit/stub.go")
        self.assertEqual(len(logic.inventory(manifest)), 2)
        # Portable bundle inspection validates foreign-host path syntax; native import still binds local bytes.
        manifest["typing"]["exports"] = {"dependency": {"path": "/native/build/cache/go/export.a", "sha256": "4" * 64, "bytes": 1}}
        self.assertEqual(len(logic.inventory(manifest)), 2)

    def test_typed_rejection(self) -> None:
        """Typed annotations cannot hide mandatory roots, inactive decisions, invented types or malformed archive facts."""
        mutations = [
            lambda m: m.update(version=3),
            lambda m: m["typing"].update(extra=1),
            lambda m: m["typing"].update(metadata_sha256="changed"),
            lambda m: m["typing"].update(package=""),
            lambda m: m["typing"].update(files=[]),
            lambda m: m["typing"]["files"].append("unit/rule.go"),
            lambda m: m["typing"].update(inactive=["unit/rule.go"]),
            lambda m: m["typing"].update(files=["unit/missing.go"]),
            lambda m: m["typing"].update(results={}),
            lambda m: m["typing"]["results"].update(invented="bool"),
            lambda m: m["typing"].update(constants=[self.decision["id"]]),
            lambda m: m["typing"].update(constants=["invented"]),
            lambda m: m["typing"]["results"].update({self.decision["id"]: "bool; panic(1)"}),
            lambda m: m["typing"]["results"].update({self.decision["id"]: None}),
            lambda m: m["typing"].update(exports={"dependency": {"path": "relative.a", "sha256": "1" * 64, "bytes": 1}}),
            lambda m: m["typing"].update(exports={"dependency": {"path": str(self.base / "archive.a"), "sha256": "changed", "bytes": 1}}),
            lambda m: m["typing"].update(exports={"dependency": {"path": str(self.base / "archive.a"), "sha256": "1" * 64, "bytes": True}}),
            lambda m: m["typing"].update(exports={"dependency": {"path": str(self.base / "archive.a"), "sha256": "1" * 64, "bytes": 0}}),
            lambda m: m["typing"].update(exports={"dependency": {"path": str(self.base / "archive.a"), "sha256": "1" * 64, "bytes": 64 * 1024**2 + 1}}),
            lambda m: m["typing"].update(exports={"dependency": {"path": str(self.base / "archive.a"), "sha256": "1" * 64, "bytes": 1, "extra": 1}}),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                manifest = self.typed_manifest()
                mutate(manifest)
                with self.assertRaises(v.Invalid):
                    self.summarize(manifest=manifest)

    def bundle(self, typed: bool = False) -> tuple[Path, dict, dict]:
        """Create hash-bound synthetic runner facts and overlay files without claiming a real Go execution."""
        directory = self.base / "bundle"
        directory.mkdir()
        source_files = {"go.mod": b"module example.org/fixture\n", "unit/rule.go": self.code, "unit/rule_test.go": b"package unit\n"}
        for name, data in source_files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        source = {"commit": None, "status": "synthetic", "files": [{"path": name, "sha256": v.digest(data)} for name, data in source_files.items()]}
        source_data = v.encode(source)
        source_path = self.base / "source.json"
        source_path.write_bytes(source_data)
        manifest = copy.deepcopy(self.manifest)
        manifest["source_sha256"] = v.digest(source_data)
        collection = {key: manifest[key] for key in ("version", "source_sha256", "qualification", "basis", "files")}
        collection.update(generated=[], tests=["unit/rule_test.go"])
        generated = self.root / "build/overlay"
        generated.mkdir(parents=True)
        replaced, references = {}, {}
        for name in ("rule.go", "zz_astra_probe.go", "zz_astra_probe_test.go"):
            data = self.code if name == "rule.go" else b"package unit\n"
            (generated / name).write_bytes(data)
            replaced[str(self.root / "unit" / name)] = str(generated / name)
            references["unit/" + name] = v.write_new(directory / name, data)
        overlay_data = v.encode({"Replace": replaced})
        (generated / "overlay.json").write_bytes(overlay_data)
        (generated / "trace.json").write_bytes(v.encode(manifest))
        metadata = {
            "Dir": str(self.root / "unit"),
            "ImportPath": "example.org/fixture/unit",
            "Module": {"Dir": str(self.root), "Path": "example.org/fixture", "Main": True},
            "GoFiles": ["rule.go", "zz_astra_probe.go"],
            "TestGoFiles": ["rule_test.go", "zz_astra_probe_test.go"],
        }
        commands = {
            "collector": (
                ["go", "run", "-p=2", "./tools/decisions", "-root", str(self.root), "-source", str(source_path), "-trace", "unit", "-output", str(generated)],
                v.encode(collection),
            ),
            "packages": (["go", "list", "-json", "-overlay=" + str(generated / "overlay.json"), "./unit"], v.encode(metadata)),
            "tests": (["go", "test", "-json", "-count=1", "-p=2", "-timeout=60s", "-overlay=" + str(generated / "overlay.json"), "./unit"], self.events()),
        }
        if typed:
            archive = self.root / "build/cache/go/fixture.a"
            archive.parent.mkdir(parents=True)
            archive.write_bytes(b"synthetic archive binding fixture; native gc compatibility is checked by Go tests")
            exports = v.encode({"Dir": str(self.root / "unit"), "Name": "unit", "ImportPath": "example.org/fixture/unit", "GoFiles": ["rule.go"]})
            exports += v.encode({"Name": "dependency", "ImportPath": "example.org/dependency", "Export": str(archive)})
            native_metadata = self.root / "build/native-export.json"
            native_metadata.write_bytes(exports)
            manifest["version"] = 2
            manifest["typing"] = self.typed_manifest()["typing"]
            manifest["typing"]["metadata_sha256"] = v.digest(exports)
            manifest["typing"]["exports"] = {
                "example.org/dependency": {"path": str(archive), "sha256": v.file_digest(archive), "bytes": archive.stat().st_size}
            }
            (generated / "trace.json").write_bytes(v.encode(manifest))
            commands["collector"][0].extend(["-export", str(native_metadata)])
            commands = {"exports": (["go", "list", "-deps", "-export", "-json", "./unit"], exports), **commands}
        bundle = {
            "version": 2 if typed else 1,
            "directory": "unit",
            "source": v.write_new(directory / "source.json", source_data),
            "trace": v.write_new(directory / "trace.json", manifest),
            "overlay": v.write_new(directory / "overlay.json", overlay_data),
            "generated": references,
        }
        for index, (name, (argv, stream)) in enumerate(commands.items()):
            folder = directory / name
            folder.mkdir()
            stdout = v.write_new(folder / "stdout.json", stream)
            stderr = v.write_new(folder / "stderr.txt", b"")
            v.write_new(folder / (name + ".process.json"), {"argv": argv, "cwd": str(self.root)})
            record = {
                "id": name,
                "argv": argv,
                "exit_code": 0,
                "complete": True,
                "cleanup": True,
                "termination": "exited",
                "started_at": f"2026-10-03T00:00:0{index*2}Z",
                "finished_at": f"2026-10-03T00:00:0{index*2+1}Z",
                "stdout": stdout,
                "stderr": stderr,
                "platform": "synthetic",
                "executable_sha256": "1" * 64,
                "resolved_environment": {"GOPROXY": "off"},
            }
            reference = v.write_new(folder / "record.json", record)
            reference["path"] = name + "/record.json"
            bundle[name] = reference
        v.write_new(directory / "bundle.json", bundle)
        return directory, source, bundle

    def test_complete_bundle(self) -> None:
        """All linked evidence is checked before exclusive output creation; an existing result cannot be overwritten."""
        directory, source, _ = self.bundle()
        output = self.base / "result"
        with patch.object(v, "source", return_value=source), patch("builtins.print"):
            before = {path: path.read_bytes() for path in self.base.rglob("*") if path.is_file()}
            loaded = logic.load(directory, self.root)
            self.assertEqual(loaded["source_sha256"], v.digest(v.encode(source)))
            self.assertEqual(loaded["events"], self.events())
            self.assertEqual(before, {path: path.read_bytes() for path in self.base.rglob("*") if path.is_file()})
            self.assertEqual(logic.collect(directory, self.root, output), 0)
            with self.assertRaises(FileExistsError):
                logic.collect(directory, self.root, output)
        result = v.decode((output / "summary.json").read_bytes())
        self.assertEqual(result["totals"]["candidates"], 2)
        self.assertEqual(result["inputs"]["trust"], "local")
        self.assertEqual(result["qualification"], "not-evaluated")

    def test_control_bundle(self) -> None:
        """The shared loader binds control-mode commands and generated bytes without substituting Boolean observations."""
        self.code = b"package unit\nfunc Rule(){for {return}}\n"
        start, stop = self.code.index(b"for "), self.code.rfind(b"}")

        def point(offset: int) -> dict[str, int]:
            """Keep exact coordinates for the fixture's single unconditional loop."""
            return {"offset": offset, "line": 2, "column": offset - self.code.index(b"func") + 1}

        edge = {"id": f"unit/rule.go:{start}", "parent": f"unit/rule.go:{start}", "kind": "loop", "begin": point(start), "end": point(stop)}
        self.manifest.update(
            files=[
                {
                    "file": "unit/rule.go",
                    "sha256": v.digest(self.code),
                    "functions": [],
                    "decisions": [],
                    "controls": [{key: edge[key] for key in ("kind", "begin", "end")}],
                }
            ],
            observed=[edge["id"]],
            edges=[edge],
        )
        self.receipt["rows"] = [{"id": edge["id"], "values": "21", "result": False, "hits": 1}]
        directory, source, bundle = self.bundle()
        generated = self.root / "build/overlay"
        manifest = v.decode((directory / "trace.json").read_bytes())
        bundle["trace"] = v.write_new(directory / "flow.json", manifest)
        (generated / "flow.json").write_bytes(v.encode(manifest))
        for name in ("collector", "tests"):
            parent = directory / name
            record = v.decode((parent / "record.json").read_bytes())
            if name == "collector":
                record["argv"].append("-controls")
                (parent / "collector.process.json").write_bytes(v.encode({"argv": record["argv"], "cwd": str(self.root)}))
            else:
                data = (parent / "stdout.json").read_bytes().replace(b"GO-DECISIONS ", b"GO-CONTROLS ")
                (parent / "stdout.json").write_bytes(data)
                record["stdout"].update(bytes=len(data), sha256=v.digest(data))
            data = v.encode(record)
            (parent / "record.json").write_bytes(data)
            bundle[name].update(bytes=len(data), sha256=v.digest(data))
        (directory / "bundle.json").write_bytes(v.encode(bundle))
        with patch.object(v, "source", return_value=source):
            loaded = logic.load(directory, self.root, controls=True)
            self.assertEqual(loaded["result"]["processes"], 1)
            self.assertEqual(loaded["result"]["without_body"], [])
            self.assertEqual(loaded["result"]["edges"][0]["vectors"], {"21": 1})
            with self.assertRaises(v.Invalid):
                logic.load(directory, self.root)
            (generated / "rule.go").write_bytes(b"changed")
            with self.assertRaisesRegex(v.Invalid, "logic-overlay-drift"):
                logic.load(directory, self.root, controls=True)

    def test_typed_bundle(self) -> None:
        """Native export identity, source selection, execution order and consumed bytes are mandatory before import."""
        directory, source, bundle = self.bundle(typed=True)
        output = self.base / "typed-result"
        with patch.object(v, "source", return_value=source), patch("builtins.print"):
            self.assertEqual(logic.collect(directory, self.root, output), 0)
        result = v.decode((output / "summary.json").read_bytes())
        self.assertEqual(result["qualification"], "not-evaluated")
        self.assertEqual(result["typing"]["metadata_sha256"], v.file_digest(self.root / "build/native-export.json"))
        self.assertEqual(result["totals"]["candidates"], 2)
        original = {p: p.read_bytes() for p in self.base.rglob("*") if p.is_file()}
        for point in (
            "archive",
            "metadata",
            "selection",
            "incomplete",
            "duplicate",
            "missing-export",
            "export-path",
            "version",
            "command",
            "compiler",
            "environment",
            "order",
        ):
            with self.subTest(point=point):
                for path, data in original.items():
                    path.write_bytes(data)
                changed = copy.deepcopy(bundle)
                if point == "archive":
                    (self.root / "build/cache/go/fixture.a").write_bytes(b"changed")
                elif point == "metadata":
                    (self.root / "build/native-export.json").write_bytes(b"changed")
                elif point == "version":
                    changed["version"] = 1
                    del changed["exports"]
                elif point in {"selection", "incomplete", "duplicate", "missing-export", "export-path"}:
                    path = directory / "exports/stdout.json"
                    metadata = logic.statements.stream(path.read_bytes())
                    if point == "selection":
                        metadata[0]["GoFiles"] = ["missing.go"]
                    elif point == "incomplete":
                        metadata[0]["Incomplete"] = True
                    elif point == "duplicate":
                        metadata.append(metadata[0])
                    elif point == "missing-export":
                        metadata.pop()
                    else:
                        metadata[1]["Export"] = str(self.base / "outside.a")
                    data = b"".join(v.encode(value) for value in metadata)
                    path.write_bytes(data)
                    (self.root / "build/native-export.json").write_bytes(data)
                    manifest = v.decode((directory / "trace.json").read_bytes())
                    manifest["typing"]["metadata_sha256"] = v.digest(data)
                    (directory / "trace.json").write_bytes(v.encode(manifest))
                    (self.root / "build/overlay/trace.json").write_bytes(v.encode(manifest))
                    changed["trace"].update(bytes=len(v.encode(manifest)), sha256=v.digest(v.encode(manifest)))
                    record = v.decode((directory / "exports/record.json").read_bytes())
                    record["stdout"].update(bytes=len(data), sha256=v.digest(data))
                    data = v.encode(record)
                    (directory / "exports/record.json").write_bytes(data)
                    changed["exports"].update(bytes=len(data), sha256=v.digest(data))
                else:
                    path = directory / "exports/record.json"
                    record = v.decode(path.read_bytes())
                    if point == "command":
                        record["argv"].remove("-export")
                        (directory / "exports/exports.process.json").write_bytes(v.encode({"argv": record["argv"], "cwd": str(self.root)}))
                    elif point == "compiler":
                        record["executable_sha256"] = "changed"
                    elif point == "environment":
                        record["resolved_environment"]["GOARCH"] = "wrong"
                    else:
                        record["finished_at"] = "2026-10-03T00:00:03Z"
                    data = v.encode(record)
                    path.write_bytes(data)
                    changed["exports"].update(bytes=len(data), sha256=v.digest(data))
                (directory / "bundle.json").write_bytes(v.encode(changed))
                rejected = self.base / ("typed-rejected-" + point)
                with patch.object(v, "source", return_value=source), self.assertRaises(v.Invalid):
                    logic.collect(directory, self.root, rejected)
                self.assertFalse(rejected.exists())

    def test_bundle_rejection(self) -> None:
        """Tampered bytes, silently narrowed native commands, changed environment and missing build files remain failures."""
        directory, source, bundle = self.bundle()
        original = {p: p.read_bytes() for p in self.base.rglob("*") if p.is_file()}
        for point in ("source", "overlay", "trace", "test-command", "environment", "compiler", "truncated", "selection", "denominator", "workspace"):
            with self.subTest(point=point):
                for path, data in original.items():
                    path.write_bytes(data)
                changed = copy.deepcopy(bundle)
                if point == "source":
                    (self.root / "unit/rule.go").write_bytes(b"changed")
                elif point == "overlay":
                    (self.root / "build/overlay/rule.go").write_bytes(b"changed")
                elif point == "trace":
                    (directory / "trace.json").write_bytes(b"{}")
                elif point in {"test-command", "environment", "compiler"}:
                    path = directory / "tests/record.json"
                    record = v.decode(path.read_bytes())
                    if point == "test-command":
                        record["argv"].insert(2, "-run=TestRule")
                        (directory / "tests/tests.process.json").write_bytes(v.encode({"argv": record["argv"], "cwd": str(self.root)}))
                    elif point == "environment":
                        record["resolved_environment"]["GOMAXPROCS"] = "99"
                    else:
                        record["executable_sha256"] = "2" * 64
                    data = v.encode(record)
                    path.write_bytes(data)
                    changed["tests"].update(bytes=len(data), sha256=v.digest(data))
                elif point in {"truncated", "selection", "denominator"}:
                    name = {"truncated": "tests", "selection": "packages", "denominator": "collector"}[point]
                    path = directory / name / "stdout.json"
                    if point == "truncated":
                        data = path.read_bytes()[:-20]
                    else:
                        value = v.decode(path.read_bytes())
                        if point == "selection":
                            value["TestGoFiles"].remove("rule_test.go")
                        else:
                            value["files"] = []
                        data = v.encode(value)
                    path.write_bytes(data)
                    record_path = directory / name / "record.json"
                    record = v.decode(record_path.read_bytes())
                    record["stdout"].update(bytes=len(data), sha256=v.digest(data))
                    data = v.encode(record)
                    record_path.write_bytes(data)
                    changed[name].update(bytes=len(data), sha256=v.digest(data))
                (directory / "bundle.json").write_bytes(v.encode(changed))
                output = self.base / ("rejected-" + point)
                with patch.object(v, "source", return_value={} if point == "workspace" else source), self.assertRaises(v.Invalid):
                    logic.collect(directory, self.root, output)
                self.assertFalse(output.exists())


class PartitionTests(unittest.TestCase):
    """Keep inactive geometry without allowing forged native-platform or nested-module observations."""

    def fixture(self, *, nested: bool = False) -> dict:
        """Extend the existing explicitly synthetic native bundle with one compiler-inactive source."""
        fixture = LogicTests("test_literal_pairs")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        directory, source, bundle = fixture.bundle(typed=True)
        manifest = v.decode((directory / "trace.json").read_bytes())
        inactive = b"//go:build ignore\n\n" + fixture.code.replace(b"return", b"defer func(){}(); return")

        def at(offset: int) -> dict[str, int]:
            """Use the actual independent fixture bytes for every recorded position."""
            return {"offset": offset, "line": inactive[:offset].count(b"\n") + 1, "column": offset - inactive.rfind(b"\n", 0, offset)}

        begin = inactive.index(b"a && b")
        decision = copy.deepcopy(fixture.decision)
        decision.update(id=f"unit/inactive.go:{begin}", begin=at(begin), end=at(begin + 6))
        for atom, offset in zip(decision["atoms"], (begin, begin + 5)):
            atom.update(begin=at(offset), end=at(offset + 1))
        start = inactive.index(b"defer")
        manifest["files"].append(
            {
                "file": "unit/inactive.go",
                "sha256": v.digest(inactive),
                "functions": [],
                "decisions": [decision],
                "controls": [{"kind": "defer", "begin": at(start), "end": at(start + len(b"defer func(){}()"))}],
            }
        )
        manifest.update(version=3, partition="native-go-files")
        manifest["typing"]["inactive"] = ["unit/inactive.go"]
        bundle.update(version=3, partition="native-go-files")
        source["files"].append({"path": "unit/inactive.go", "sha256": v.digest(inactive)})
        (fixture.root / "unit/inactive.go").write_bytes(inactive)
        generated = fixture.root / "build/overlay"
        (generated / "inactive.go").write_bytes(inactive)
        overlay = v.decode((directory / "overlay.json").read_bytes())
        overlay["Replace"][str(fixture.root / "unit/inactive.go")] = str(generated / "inactive.go")
        bundle["generated"]["unit/inactive.go"] = {"path": "inactive.go"}
        (directory / "inactive.go").write_bytes(inactive)
        records = {name: v.decode((directory / name / "record.json").read_bytes()) for name in ("exports", "collector", "packages", "tests")}
        # These remain synthetic reader inputs; the explicit platform pair exercises native identity binding.
        for record in records.values():
            record.update(platform="linux-amd64", resolved_environment={"GOPROXY": "off", "GOOS": "linux", "GOARCH": "amd64"})
        streams = {name: (directory / name / "stdout.json").read_bytes() for name in records}
        collection = v.decode(streams["collector"])
        metadata = v.decode(streams["packages"])
        metadata["IgnoredGoFiles"] = ["inactive.go"]
        exports = logic.statements.stream(streams["exports"])
        exports[0]["IgnoredGoFiles"] = ["inactive.go"]
        records["collector"]["argv"].append("-partition")
        if nested:
            module = b"module example.org/native\n"
            (fixture.root / "unit/go.mod").write_bytes(module)
            source["files"].append({"path": "unit/go.mod", "sha256": v.digest(module)})
            manifest["typing"]["package"] = "example.org/native"
            exports[0]["ImportPath"] = "example.org/native"
            exports[0]["Module"] = {"Dir": str(fixture.root / "unit"), "Path": "example.org/native", "Main": True}
            metadata.update(ImportPath="example.org/native", Module=exports[0]["Module"])
            streams["tests"] = streams["tests"].replace(b"example.org/fixture/unit", b"example.org/native")
            for name in ("exports", "packages", "tests"):
                records[name]["argv"][1:1] = ["-C", "unit"]
                records[name]["argv"][-1] = "."
        else:
            exports[0]["Module"] = {"Dir": str(fixture.root), "Path": "example.org/fixture", "Main": True}
        case = {
            "fixture": fixture,
            "directory": directory,
            "source": source,
            "bundle": bundle,
            "manifest": manifest,
            "collection": collection,
            "metadata": metadata,
            "exports": exports,
            "records": records,
            "streams": streams,
            "overlay": overlay,
            "inactive_id": decision["id"],
        }
        self.persist(case)
        return case

    def persist(self, case: dict) -> None:
        """Rebind only synthetic test artifacts so semantic corruptions cannot hide behind stale hash failures."""
        fixture, directory, bundle, manifest = (case[key] for key in ("fixture", "directory", "bundle", "manifest"))

        def bind(path: Path, data: bytes) -> dict[str, str | int]:
            """Retain literal bytes and refresh their reference inside this disposable reader fixture."""
            path.write_bytes(data)
            return {"path": path.relative_to(directory).as_posix(), "bytes": len(data), "sha256": v.digest(data)}

        source_data = v.encode(case["source"])
        (fixture.base / "source.json").write_bytes(source_data)
        bundle["source"] = bind(directory / "source.json", source_data)
        manifest["source_sha256"] = v.digest(source_data)
        exports = b"".join(v.encode(row) for row in case["exports"])
        (fixture.root / "build/native-export.json").write_bytes(exports)
        manifest["typing"]["metadata_sha256"] = v.digest(exports)
        case["collection"].update(source_sha256=v.digest(source_data), files=copy.deepcopy(manifest["files"]))
        case["streams"].update(exports=exports, collector=v.encode(case["collection"]), packages=v.encode(case["metadata"]))
        bundle["trace"] = bind(directory / "trace.json", v.encode(manifest))
        (fixture.root / "build/overlay/trace.json").write_bytes(v.encode(manifest))
        bundle["overlay"] = bind(directory / "overlay.json", v.encode(case["overlay"]))
        (fixture.root / "build/overlay/overlay.json").write_bytes(v.encode(case["overlay"]))
        for name, reference in bundle["generated"].items():
            path = directory / reference["path"]
            data = path.read_bytes()
            bundle["generated"][name] = bind(path, data)
            (fixture.root / "build/overlay" / Path(name).name).write_bytes(data)
        for name, record in case["records"].items():
            folder = directory / name
            data = case["streams"][name]
            (folder / "stdout.json").write_bytes(data)
            record["stdout"].update(bytes=len(data), sha256=v.digest(data))
            (folder / (name + ".process.json")).write_bytes(v.encode({"argv": record["argv"], "cwd": str(fixture.root)}))
            bundle[name] = bind(folder / "record.json", v.encode(record))
        (directory / "bundle.json").write_bytes(v.encode(bundle))

    def load(self, case: dict) -> dict:
        """Require the strict public reader; source mocking labels these as importer controls, never native execution."""
        with patch.object(v, "source", return_value=case["source"]):
            return logic.load(case["directory"], case["fixture"].root)

    def test_partition_inventory(self) -> None:
        """Inactive roots and controls keep their denominator while only active roots receive vectors."""
        case = self.fixture()
        fixture = case["fixture"]
        try:
            result = fixture.summarize(manifest=case["manifest"])
        except v.Invalid as cause:
            self.fail(f"explicit platform inventory rejected: {cause}")
        self.assertEqual(result["qualification"], "not-evaluated")
        self.assertEqual(result["totals"]["roots"], 2)
        self.assertEqual(result["totals"]["observed"], 1)
        inactive = next(row for row in result["decisions"] if row["id"] == case["inactive_id"])
        self.assertFalse(inactive["instrumented"])
        self.assertEqual(inactive["vectors"], [])
        old = copy.deepcopy(case["manifest"])
        old["version"] = 2
        del old["partition"]
        with self.assertRaises(v.Invalid):
            fixture.summarize(manifest=old)

    def test_partition_root_bundle(self) -> None:
        """The opt-in format retains the existing root-module command identity and raw-only result."""
        case = self.fixture()
        try:
            loaded = self.load(case)
        except v.Invalid as cause:
            self.fail(f"explicit root-module partition bundle rejected: {cause}")
        self.assertEqual(loaded["result"]["totals"]["roots"], 2)
        self.assertEqual(loaded["result"]["totals"]["observed"], 1)
        self.assertEqual(loaded["result"]["typing"]["inactive"], ["unit/inactive.go"])
        for options in ({"controls": True}, {"schedule": True}):
            with self.subTest(options=options), patch.object(v, "source", return_value=case["source"]), self.assertRaises(v.Invalid):
                logic.load(case["directory"], case["fixture"].root, **options)

    def test_partition_nested_bundle(self) -> None:
        """A bound standalone module has its own native import identity and exact go -C command shape."""
        case = self.fixture(nested=True)
        try:
            loaded = self.load(case)
        except v.Invalid as cause:
            self.fail(f"explicit standalone-module partition bundle rejected: {cause}")
        self.assertEqual(loaded["result"]["typing"]["package"], "example.org/native")
        self.assertEqual(loaded["result"]["qualification"], "not-evaluated")
        self.assertEqual(len(loaded["records"]), 4)

    def test_partition_inactive_rejection(self) -> None:
        """Inactive claims, source loss, changed copies and export or selection tampering cannot acquire evidence."""
        for point in ("type", "constant", "observed", "hit", "omission", "copy", "metadata", "archive", "missing-export", "partition", "version"):
            with self.subTest(point=point):
                case = self.fixture()
                manifest, identity = case["manifest"], case["inactive_id"]
                if point == "type":
                    manifest["typing"]["results"][identity] = "bool"
                    manifest["observed"].append(identity)
                elif point == "constant":
                    manifest["files"][1]["decisions"][0]["kind"] = "boolean"
                    manifest["typing"]["constants"].append(identity)
                elif point == "observed":
                    manifest["observed"].append(identity)
                elif point == "hit":
                    receipt = copy.deepcopy(case["fixture"].receipt)
                    receipt["rows"].append(dict(receipt["rows"][0], id=identity))
                    case["streams"]["tests"] = case["fixture"].events([receipt])
                elif point == "omission":
                    manifest["files"].pop()
                    manifest["typing"]["inactive"] = []
                elif point == "copy":
                    (case["directory"] / "inactive.go").write_bytes(b"package unit\n")
                elif point == "metadata":
                    case["exports"][0]["IgnoredGoFiles"] = []
                elif point == "archive":
                    (case["fixture"].root / "build/cache/go/fixture.a").write_bytes(b"altered")
                elif point == "missing-export":
                    case["exports"].pop()
                elif point == "partition":
                    manifest["partition"] = "inferred"
                else:
                    del manifest["partition"]
                self.persist(case)
                with self.assertRaises(v.Invalid):
                    self.load(case)

    def test_partition_nested_rejection(self) -> None:
        """Closed native module commands reject aliases, hooks, extra packages and an unbound module identity."""
        for point in (
            "alias",
            "escape",
            "absolute",
            "extra-package",
            "exec",
            "duplicate",
            "no-c",
            "module",
            "unowned-module",
            "native-module",
            "export-command",
            "collector",
        ):
            with self.subTest(point=point):
                case = self.fixture(nested=True)
                arguments = case["records"]["tests"]["argv"]
                if point in {"alias", "escape", "absolute"}:
                    arguments[2] = {"alias": "./unit", "escape": "../unit", "absolute": str(case["fixture"].root / "unit")}[point]
                elif point == "extra-package":
                    arguments.append("./...")
                elif point == "exec":
                    arguments.insert(-1, "-exec=helper")
                elif point == "duplicate":
                    arguments.insert(-1, "-count=1")
                elif point == "no-c":
                    del arguments[1:3]
                elif point == "module":
                    (case["fixture"].root / "unit/go.mod").write_bytes(b"module example.org/other\n")
                elif point == "unowned-module":
                    case["source"]["files"] = [row for row in case["source"]["files"] if row["path"] != "unit/go.mod"]
                elif point == "native-module":
                    case["metadata"]["Module"]["Dir"] = str(case["fixture"].root)
                elif point == "export-command":
                    case["records"]["exports"]["argv"][-1] = "./..."
                else:
                    case["records"]["collector"]["argv"].remove("-partition")
                self.persist(case)
                with self.assertRaises(v.Invalid):
                    self.load(case)

    def test_partition_selection(self) -> None:
        """Named subsets require an exact command and exact top-level completions without hiding inactive roots."""
        for nested in (False, True):
            with self.subTest(nested=nested):
                case = self.fixture(nested=nested)
                case["bundle"]["selection"] = ["TestRule"]
                case["records"]["tests"]["argv"].insert(-1, "-run=^(TestRule)$")
                self.persist(case)
                result = self.load(case)["result"]
                self.assertEqual(result["selection"], {"basis": "explicit-subset", "tests": ["TestRule"]})
                self.assertEqual(result["totals"]["roots"], 2)
                self.assertEqual(result["qualification"], "not-evaluated")
        # Match the executor's three native temporary aliases to each original command folder.
        for nested in (False, True):
            for point in ("valid", "missing", "foreign", "mismatch", "outside", "other-environment"):
                with self.subTest(windows=nested, temporary=point):
                    case = self.fixture(nested=nested)
                    location = case["fixture"].root / "build/native-bundle"
                    shutil.copytree(case["directory"], location)
                    case["directory"] = location
                    for name, record in case["records"].items():
                        temporary = str(location / name / "tmp")
                        record["platform"] = "windows-amd64"
                        record["resolved_environment"].update(GOOS="windows", TMPDIR=temporary, TMP=temporary, TEMP=temporary)
                    environment = case["records"]["tests"]["resolved_environment"]
                    if point == "missing":
                        del environment["TEMP"]
                    elif point == "foreign":
                        environment.update({name: str(location / "collector/tmp") for name in ("TMPDIR", "TMP", "TEMP")})
                    elif point == "mismatch":
                        environment["TMP"] = str(location / "other")
                    elif point == "outside":
                        environment.update({name: str(case["fixture"].base / "outside/tmp") for name in ("TMPDIR", "TMP", "TEMP")})
                    elif point == "other-environment":
                        environment["GOMAXPROCS"] = "99"
                    self.persist(case)
                    if point == "valid":
                        result = self.load(case)["result"]
                        self.assertEqual(result["totals"]["roots"], 2)
                        self.assertEqual(result["qualification"], "not-evaluated")
                    else:
                        with self.assertRaises(v.Invalid):
                            self.load(case)
        for point in (
            "empty",
            "type",
            "duplicate",
            "unsorted",
            "pattern",
            "subtest",
            "extra",
            "missing",
            "flag",
            "unbound",
            "legacy",
            "platform",
            "architecture",
            "identity",
        ):
            with self.subTest(point=point):
                case = self.fixture(nested=True)
                case["bundle"]["selection"] = ["TestRule"]
                arguments = case["records"]["tests"]["argv"]
                arguments.insert(-1, "-run=^(TestRule)$")
                selections = {
                    "empty": [],
                    "type": "TestRule",
                    "duplicate": ["TestRule", "TestRule"],
                    "unsorted": ["TestRule", "TestAbsent"],
                    "pattern": ["Test.*"],
                    "subtest": ["TestRule/child"],
                    "extra": ["TestAbsent", "TestRule"],
                    "missing": ["TestAbsent"],
                }
                if point in selections:
                    case["bundle"]["selection"] = selections[point]
                    if point in {"extra", "missing"}:
                        arguments[-2] = "-run=^(" + "|".join(selections[point]) + ")$"
                elif point == "flag":
                    arguments[-2] = "-run=TestRule"
                elif point == "unbound":
                    del case["bundle"]["selection"]
                elif point == "legacy":
                    case["bundle"]["version"] = 2
                    del case["bundle"]["partition"]
                else:
                    for record in case["records"].values():
                        if point == "platform":
                            del record["resolved_environment"]["GOOS"]
                        elif point == "architecture":
                            record["resolved_environment"]["GOARCH"] = "arm64"
                        else:
                            record["platform"] = "windows-amd64"
                self.persist(case)
                with self.assertRaises(v.Invalid):
                    self.load(case)
