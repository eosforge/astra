"""Challenge control receipt framing, source binding, declared scope and impossible loop observations."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from tools import flow, structure, verify as v


class FlowTests(unittest.TestCase):
    """Use synthetic native-shaped input only to test the interpreter, never as application evidence."""

    def setUp(self) -> None:
        """Bind a small, independent control alphabet to physical source bytes."""
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = b"package example\nfunc F(c chan int){for {return}; select {case <-c: return; default: return}}\n"
        (self.root / "state.go").write_bytes(self.source)
        self.digest = "a" * 64

        def point(offset: int) -> dict[str, int]:
            """Derive exact original byte coordinates independently of the Go producer."""
            return {"offset": offset, "line": self.source[:offset].count(b"\n") + 1, "column": offset - self.source.rfind(b"\n", 0, offset)}

        def region(kind: str, start: int, stop: int) -> dict:
            """Describe the bounded fixture's literal source intervals."""
            return {"kind": kind, "begin": point(start), "end": point(stop)}

        loop = self.source.index(b"for ")
        select = self.source.index(b"select ")
        case = self.source.index(b"case ")
        default = self.source.index(b"default:")
        controls = [region("loop", loop, self.source.index(b"};") + 1), region("select", select, len(self.source) - 2)]
        edges = []
        for item, parent in (
            (controls[0], loop),
            (region("select-arm", case, default - 2), select),
            (region("select-arm", default, len(self.source) - 3), select),
        ):
            edges.append({"id": "state.go:" + str(item["begin"]["offset"]), "parent": "state.go:" + str(parent), **item})
        self.manifest = {
            "version": 1,
            "source_sha256": self.digest,
            "qualification": "not-evaluated",
            "basis": "synthetic parser fixture",
            "files": [{"file": "state.go", "sha256": v.digest(self.source), "functions": [], "decisions": [], "controls": controls}],
            "edges": edges,
            "observed": [edge["id"] for edge in edges],
        }
        self.receipt = {
            "pid": 1,
            "code": 0,
            "rows": [{"id": edge["id"], "values": "21" if edge["kind"] == "loop" else "2", "result": edge["kind"] != "loop", "hits": 1} for edge in edges],
        }

    def stream(self, receipt: dict | None = None) -> bytes:
        """Frame one process receipt inside complete native Go test events."""
        events = [
            {"Action": "start"},
            {"Action": "run", "Test": "TestFlow"},
            {"Action": "pass", "Test": "TestFlow"},
            {"Action": "output", "Output": "GO-CONTROLS " + json.dumps(receipt or self.receipt) + "\n"},
            {"Action": "pass"},
        ]
        return b"\n".join(json.dumps(dict(event, Package="example")).encode() for event in events) + b"\n"

    def report(self, manifest: dict | None = None, data: bytes | None = None) -> dict:
        """Run the public reader with explicit original source and native package identity."""
        return flow.summary(manifest or self.manifest, data or self.stream(), "example", 1, self.root, self.digest)

    def test_observations(self) -> None:
        """Preserve observed counts while leaving structural qualification undecided."""
        result = self.report()
        self.assertEqual(result["processes"], 1)
        self.assertEqual(result["qualification"], "not-evaluated")
        self.assertEqual(result["unobserved"], [])
        self.assertEqual(result["without_body"], [])
        self.assertEqual(result["without_exhaustion"], [])
        self.assertEqual([edge["vectors"] for edge in result["edges"]], [{"21": 1}, {"2": 1}, {"2": 1}])
        receipt = copy.deepcopy(self.receipt)
        receipt["rows"].pop()
        self.assertEqual(self.report(data=self.stream(receipt))["unobserved"], [self.manifest["observed"][-1]])

    def test_binding(self) -> None:
        """Missing loops, altered coordinates, fields or original bytes cannot retain a valid binding."""
        for change in (
            lambda m: m.update(source_sha256="b" * 64),
            lambda m: m.update(extra=True),
            lambda m: m["edges"][0]["begin"].update(line=99),
            lambda m: m["edges"].pop(0),
            lambda m: m["observed"].pop(),
        ):
            manifest = copy.deepcopy(self.manifest)
            change(manifest)
            with self.assertRaises(v.Invalid):
                self.report(manifest=manifest)
        (self.root / "state.go").write_bytes(self.source + b"\n")
        with self.assertRaises(v.Invalid):
            self.report()

    def test_vectors(self) -> None:
        """An unconditional loop cannot exhaust; zero/Boolean counts and duplicate observations are invalid."""
        for change in (
            lambda r: r["rows"][0].update(values="22", result=True),
            lambda r: r["rows"][1].update(result=False),
            lambda r: r["rows"][1].update(hits=0),
            lambda r: r["rows"][1].update(hits=True),
            lambda r: r["rows"].append(r["rows"][0]),
            lambda r: r["rows"][0].update(id="unknown"),
            lambda r: r.update(rows=[]),
        ):
            receipt = copy.deepcopy(self.receipt)
            change(receipt)
            with self.assertRaises(v.Invalid):
                self.report(data=self.stream(receipt))

    def test_terminals(self) -> None:
        """Failed, truncated, duplicated and marker-free process output cannot supply a completion."""
        for change in (lambda r: r.update(code=1), lambda r: r.update(pid=True), lambda r: r.update(extra=1)):
            receipt = copy.deepcopy(self.receipt)
            change(receipt)
            with self.assertRaises(v.Invalid):
                self.report(data=self.stream(receipt))
        raw = self.stream()
        lines = raw.splitlines(keepends=True)
        for data in (b"".join(lines[:-1]), b"".join(lines[:4] + lines[3:]), raw.replace(b"GO-CONTROLS ", b"IGNORED ")):
            with self.assertRaises(v.Invalid):
                self.report(data=data)

    def test_switches(self) -> None:
        """Explicit value/type arms retain their own parents and never become loop-exhaustion observations."""
        for kind, argument, expression, cases in (
            ("switch", "int", "v", "1, 2"),
            ("type-switch", "any", "v.(type)", "int, string"),
        ):
            self.source = f"package example\nfunc F(v {argument}){{switch {expression} {{case {cases}: return; default: return}}}}\n".encode()
            (self.root / "state.go").write_bytes(self.source)

            def point(offset: int) -> dict[str, int]:
                """Bind original bytes rather than copying collector-generated coordinates."""
                return {"offset": offset, "line": self.source[:offset].count(b"\n") + 1, "column": offset - self.source.rfind(b"\n", 0, offset)}

            start, first, last = (self.source.index(value) for value in (b"switch ", b"case ", b"default:"))
            parent = f"state.go:{start}"
            control = {"kind": kind, "begin": point(start), "end": point(len(self.source) - 2)}
            edges = [
                {
                    "id": f"state.go:{begin}",
                    "kind": "switch-arm" if kind == "switch" else "type-arm",
                    "parent": parent,
                    "begin": point(begin),
                    "end": point(end),
                }
                for begin, end in ((first, last - 2), (last, len(self.source) - 3))
            ]
            self.manifest["files"] = [{"file": "state.go", "sha256": v.digest(self.source), "functions": [], "decisions": [], "controls": [control]}]
            self.manifest["edges"], self.manifest["observed"] = edges, [edge["id"] for edge in edges]
            self.receipt["rows"] = [{"id": edge["id"], "values": "2", "result": True, "hits": 1} for edge in edges]
            report = self.report()
            self.assertEqual(report["unobserved"], [])
            self.assertEqual(report["without_exhaustion"], [])
            ledger = structure.controls(report)
            self.assertEqual((ledger["required"], ledger["observed"], ledger["missing"]), (2, 2, []))
            missing = copy.deepcopy(self.receipt)
            missing["rows"].pop()
            self.assertEqual(self.report(data=self.stream(missing))["unobserved"], [edges[-1]["id"]])
            for replacement in ("select-arm", "type-arm" if kind == "switch" else "switch-arm"):
                manifest = copy.deepcopy(self.manifest)
                manifest["edges"][0]["kind"] = replacement
                with self.assertRaises(v.Invalid):
                    self.report(manifest=manifest)
            for values, result in (("21", False), ("12", True), ("2", False)):
                receipt = copy.deepcopy(self.receipt)
                receipt["rows"][0].update(values=values, result=result)
                with self.assertRaises(v.Invalid):
                    self.report(data=self.stream(receipt))


if __name__ == "__main__":
    unittest.main()
