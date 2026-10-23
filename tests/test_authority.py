"""Challenge concrete authority pairs, source binding, lifecycle completeness and fixture generation."""

import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest

from tools import authority, ingress, installation, structure, verify as v


def stream(rows: list[dict] | None = None) -> list[dict]:
    """Build synthetic parser inputs only; these records never stand in for a native run."""
    events = [{"Action": "start"}, {"Action": "run", "Test": "TestPredicates"}]
    for row in authority.expected() if rows is None else rows:
        events.append({"Action": "output", "Test": "TestPredicates", "Output": "predicates_test.go:30: AUTHORITY-PREDICATES " + json.dumps(row) + "\n"})
    for row in authority.guarded():
        events.append({"Action": "output", "Test": "TestPredicates", "Output": "predicates_test.go:31: AUTHORITY-GUARDED " + json.dumps(row) + "\n"})
    for row in ({"valid": False, "send_calls": 0, "remote": False, "retired": True}, {"valid": True, "send_calls": 1, "remote": True, "retired": True}):
        events.append({"Action": "output", "Test": "TestPredicates", "Output": "predicates_test.go:32: AUTHORITY-AUTHENTICATION " + json.dumps(row) + "\n"})
    events += [{"Action": "pass", "Test": "TestPredicates"}, {"Action": "pass"}]
    return [{"Package": authority.PACKAGE, **event} for event in events]


def encoded(events: list[dict]) -> bytes:
    """Preserve separate native-shaped lines, including malformed adversarial variants."""
    return b"".join(json.dumps(row).encode() + b"\n" for row in events)


class AuthorityTests(unittest.TestCase):
    """Keep input-pair proofs distinct from execution coverage and incomplete package output."""

    def setUp(self) -> None:
        """Copy only immutable source dependencies into a fresh isolated parser workspace."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.origin = Path(authority.__file__).resolve().parents[1]
        for name in (
            *("polaris/internal/server/" + name for name in authority.SOURCES),
            authority.FIXTURE,
            *(name.removeprefix("astra/") for name in structure.SERVER_DEPENDENCIES),
        ):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            # Historical authentication proofs retain their original dependency, never the current acquisition revision.
            source = self.origin / ("tests/fixtures/admission-identity.go.in" if name == "internal/admission/identity.go" else name)
            data = source.read_bytes()
            if name == installation.PATH and v.digest(data) == installation.SOURCE:
                data, _ = ingress.previous(data)
            path.write_bytes(data)
        self.output = self.root / "build/pairs"

    def test_axioms(self) -> None:
        """Every pair changes exactly one total input predicate and crosses a public boundary."""
        rows = authority.expected()
        self.assertEqual(len(rows), 56)
        self.assertEqual(
            [row["guard"] for row in rows],
            ["dependencies"] * 2
            + ["budget"] * 2
            + ["scope"] * 2
            + ["key"] * 4
            + ["frame"] * 2
            + ["window"] * 3
            + ["release"] * 2
            + ["ready"] * 2
            + ["inventory"] * 2
            + ["ack"] * 2
            + ["floor"] * 2
            + ["sent"] * 2
            + ["assessment"] * 2
            + ["authority"] * 3
            + ["repair"] * 3
            + ["batch"] * 3
            + ["commit-scope"]
            + ["hello"] * 2
            + ["snapshot-prefix", "updates-prefix"]
            + ["payload"] * 3
            + ["batch-position", "packet", "ack"]
            + ["deadline"] * 2
            + ["prepared", "initial", "probe", "suffix", "manifest-prefix"],
        )
        for row in rows:
            self.assertTrue(authority.independent(row))
            first, second = (authority.operands(row["guard"], row[side]["input"]) for side in ("before", "after"))
            self.assertEqual([index for index, (before, after) in enumerate(zip(first, second, strict=True)) if before != after], [row["condition"]])
            self.assertNotEqual(authority.decision(row["guard"], first), authority.decision(row["guard"], second))
            altered = copy.deepcopy(row)
            altered["after"] = copy.deepcopy(altered["before"])
            self.assertFalse(authority.independent(altered))
        self.assertEqual(rows[2]["before"]["input"]["budget"], 1048576 + 3 * 128 + 2097152)
        self.assertEqual(rows[8]["after"]["input"]["key"], "/w==")
        self.assertEqual(rows[9]["after"]["input"]["key"], "AA==")
        self.assertEqual([row["before"]["input"] for row in rows[10:12]], [1024, 8388608])
        self.assertEqual(authority.operands("window", {"count": 0, "cost": 8388609}), (False, False, True))
        self.assertEqual(authority.operands("window", {"count": 1, "cost": 8388609}), (True, False, True))
        self.assertEqual(authority.vector(rows[17], "before"), {"values": [False, False], "result": True})
        self.assertEqual(authority.vector(rows[17], "after"), {"values": [True, False], "result": False})
        self.assertEqual(authority.vector(rows[19], "before"), {"values": [False, True], "result": False})
        self.assertEqual(authority.vector(rows[19], "after"), {"values": [True, True], "result": True})
        self.assertEqual(authority.vector(rows[21], "before"), {"values": [True, False, False], "result": True})
        self.assertEqual(authority.vector(rows[21], "after"), {"values": [True, True, False], "result": False})
        self.assertEqual(authority.vector(rows[29], "before"), {"values": [False, False, False], "result": True})
        self.assertEqual(authority.vector(rows[29], "after"), {"values": [True, False, False], "result": False})
        self.assertEqual(authority.vector(rows[32], "before"), {"values": [False, False, False], "result": False})
        self.assertEqual(authority.vector(rows[32], "after"), {"values": [True, False, False], "result": True})
        self.assertEqual(authority.vector(rows[35], "after"), {"values": [True, False, False, False, False], "result": True})
        self.assertEqual(authority.vector(rows[38], "after"), {"values": [False, True, False], "result": True})
        self.assertEqual(authority.vector(rows[40], "after"), {"values": [False, False, True, False], "result": True})
        for row in rows[41:43]:
            self.assertEqual(authority.vector(row, "before"), {"values": [False, True], "result": False})
            self.assertEqual(authority.vector(row, "after"), {"values": [True, True], "result": True})
            for field, value in (("bytes", 262143), ("maximum", 1024)):
                with self.assertRaises(ValueError):
                    authority.operands(row["guard"], {**row["before"]["input"], field: value})
        self.assertEqual([len(value) for value in authority.payloads()], [8192, 8193, 3, 4, 0])
        for index, values in ((43, [False, True, True, True]), (44, [True, False, True, True]), (45, [True, True, False, True])):
            self.assertEqual(authority.vector(rows[index], "before"), {"values": [True] * 4, "result": True})
            self.assertEqual(authority.vector(rows[index], "after"), {"values": values, "result": False})
        self.assertEqual(authority.vector(rows[46], "after"), {"values": [False, False], "result": True})
        self.assertEqual(authority.vector(rows[47], "after"), {"values": [True, True], "result": True})
        self.assertEqual(authority.vector(rows[48], "after"), {"values": [False, True, False], "result": True})
        self.assertEqual(authority.vector(rows[49], "before"), {"values": [True, False, False], "result": False})
        self.assertEqual(authority.vector(rows[49], "after"), {"values": [False, False, False], "result": True})
        self.assertEqual(authority.vector(rows[50], "after"), {"values": [True, True, False], "result": True})
        self.assertEqual(authority.vector(rows[51], "before"), {"values": [False, True], "result": False})
        self.assertEqual(authority.vector(rows[51], "after"), {"values": [True, True], "result": True})
        self.assertEqual(authority.vector(rows[52], "before"), {"values": [False, False], "result": True})
        self.assertEqual(authority.vector(rows[52], "after"), {"values": [True, False], "result": False})
        self.assertEqual(authority.vector(rows[53], "after"), {"values": [False, True], "result": False})
        self.assertEqual(authority.vector(rows[54], "before"), {"values": [True, True, True], "result": True})
        self.assertEqual(authority.vector(rows[54], "after"), {"values": [True, False, True], "result": False})
        self.assertEqual(authority.vector(rows[55], "before"), {"values": [False, True], "result": False})
        self.assertEqual(authority.vector(rows[55], "after"), {"values": [True, True], "result": True})
        for value in (None, 1, "true"):
            with self.assertRaises(ValueError):
                authority.operands("suffix", value)
            with self.assertRaises(ValueError):
                authority.operands("manifest-prefix", value)
        for input in ({"present": True, "seconds": 31}, {"present": 1, "seconds": 5}, {"present": True, "seconds": False}):
            with self.assertRaises(ValueError):
                authority.operands("deadline", input)
        for raw in (b"\xff", b"\x0a\x01\x02", b"\x0a\x02\x01"):
            with self.assertRaises(ValueError):
                authority.operands("payload", base64.b64encode(raw).decode())
        with self.assertRaises(ValueError):
            authority.operands("unknown", {})

    def test_pairs(self) -> None:
        """Exact observations cannot be replaced by counts, reordered rows or numerically equal foreign types."""
        result = authority.observations(encoded(stream()), self.root)
        self.assertEqual(len(result["pairs"]), 56)
        self.assertEqual(len(result["guarded"]), 8)
        self.assertEqual(
            [row["before"]["values"] for row in result["guarded"]],
            [[False] * 5, [False] * 3, [False] * 2, [False] * 2, [False] * 2, [False] * 4, [True] * 2, [True] * 3],
        )
        self.assertEqual(
            [row["after"]["values"] for row in result["guarded"]],
            [
                [False, True, None, None, None],
                [True, None, None],
                [True, None],
                [True, None],
                [True, None],
                [True, None, None, None],
                [False, None],
                [False, None, True],
            ],
        )
        self.assertEqual(result["qualification"], "not-evaluated")
        self.assertEqual(result["pairs"][8]["before"], {"values": [False, False, True, False], "result": False})
        self.assertEqual(result["pairs"][8]["after"], {"values": [False, False, False, False], "result": True})
        rows = authority.expected()
        for altered in ([], rows[:-1], rows + [rows[0]], list(reversed(rows))):
            with self.subTest(length=len(altered)), self.assertRaises(v.Invalid):
                authority.observations(encoded(stream(altered)), self.root)
        for path, value in (
            (("condition",), False),
            (("condition",), 0.0),
            (("extra",), "unexpected"),
            (("before", "accepted"), 1),
            (("after", "accepted"), True),
            (("after", "input", "directory"), False),
        ):
            altered = copy.deepcopy(rows)
            target = altered[0]
            for field in path[:-1]:
                target = target[field]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaisesRegex(v.Invalid, "authority-pairs-inputs"):
                authority.observations(encoded(stream(altered)), self.root)
        events = stream()
        indices = [i for i, event in enumerate(events) if "AUTHORITY-GUARDED " in event.get("Output", "")]
        for index in indices:
            for change in ("missing", "duplicate", "foreign", "wrong-input", "wrong-result"):
                altered = copy.deepcopy(events)
                if change == "missing":
                    del altered[index]
                elif change == "duplicate":
                    altered.insert(index, copy.deepcopy(altered[index]))
                else:
                    row = json.loads(altered[index]["Output"].split("AUTHORITY-GUARDED ")[1])
                    if change == "foreign":
                        row["guard"] = "unlisted"
                    elif change == "wrong-input":
                        row["after"]["present"] = True
                    else:
                        row["after"]["accepted"] = True
                    altered[index]["Output"] = "AUTHORITY-GUARDED " + json.dumps(row) + "\n"
                with self.subTest(index=index, change=change), self.assertRaises(v.Invalid):
                    authority.observations(encoded(altered), self.root)

    def test_source(self) -> None:
        """Every guarded production source or preparation-budget dependency invalidates old semantic bindings."""
        for name in authority.SOURCES:
            path = self.root / "polaris/internal/server" / name
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            with self.subTest(source=name), self.assertRaisesRegex(v.Invalid, "authority-pairs-source"):
                authority.observations(encoded(stream()), self.root)
            path.write_bytes(original)

    def test_authentication(self) -> None:
        """A reviewed call-path exclusion needs pinned concrete dependencies and cannot hide a counterexample."""
        decision = {
            "id": "polaris/internal/server/stream.go:9185",
            "text": "transfer.remote != nil && !transfer.owner.node.Directory().Current(transfer.remote)",
        }
        observed = {"vectors": [{"values": "21", "result": True, "hits": 1}, {"values": "22", "result": False, "hits": 2}]}
        proof = authority.authentication(self.root, decision, observed)
        self.assertEqual(proof["condition"], 0)
        self.assertEqual(proof["reason"], "authenticated-send")
        self.assertIn("data races or memory corruption", proof["invalidated_by"])
        dependency = self.root / "internal/admission/identity.go"
        original = dependency.read_bytes()
        dependency.write_bytes((self.origin / "internal/admission/identity.go").read_bytes())
        with self.assertRaisesRegex(v.Invalid, "authority-authentication-dependency"):
            authority.authentication(self.root, decision, observed)
        dependency.write_bytes(original)
        for vectors in ([], [{"values": "10", "result": False, "hits": 1}], [{"values": "22", "hits": 0}], [{"values": "21", "hits": True}]):
            with self.subTest(vectors=vectors), self.assertRaisesRegex(v.Invalid, "authority-authentication-contradiction"):
                authority.authentication(self.root, decision, {"vectors": vectors})
        for field in ("id", "text"):
            with self.assertRaisesRegex(v.Invalid, "authority-authentication-binding"):
                authority.authentication(self.root, {**decision, field: decision[field] + " "}, observed)
        for name in structure.SERVER_DEPENDENCIES:
            path = self.root / name.removeprefix("astra/")
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            with self.assertRaisesRegex(v.Invalid, "authority-authentication-dependency"):
                authority.authentication(self.root, decision, observed)
            path.write_bytes(original)
        events = stream()
        indices = [i for i, event in enumerate(events) if "AUTHORITY-AUTHENTICATION " in event.get("Output", "")]
        self.assertEqual(len(indices), 2)
        for index in indices:
            for change in ("missing", "duplicate", "send", "remote", "retirement", "extra", "type"):
                altered = copy.deepcopy(events)
                if change == "missing":
                    del altered[index]
                elif change == "duplicate":
                    altered.insert(index, altered[index])
                else:
                    row = json.loads(altered[index]["Output"].split("AUTHORITY-AUTHENTICATION ")[1])
                    if change == "send":
                        row["send_calls"] += 1
                    elif change == "remote":
                        row["remote"] = not row["remote"]
                    elif change == "retirement":
                        row["retired"] = False
                    elif change == "extra":
                        row["extra"] = 1
                    else:
                        row["send_calls"] = bool(row["send_calls"])
                    altered[index]["Output"] = "AUTHORITY-AUTHENTICATION " + json.dumps(row) + "\n"
                with self.subTest(index=index, change=change), self.assertRaises(v.Invalid):
                    authority.observations(encoded(altered), self.root)

    def test_projection(self) -> None:
        """Projection preserves known-but-skipped values and rejects evaluation of undefined fields."""
        for kind, first, expected in (("and", False, "10"), ("or", True, "20")):
            decision = {
                "atoms": [{}, {}],
                "tree": [{"kind": "atom", "atom": 0}, {"kind": "atom", "atom": 1}, {"kind": kind, "children": [0, 1]}],
                "root": 2,
            }
            self.assertEqual(authority.project(decision, [first, None]), (expected, first))
            self.assertEqual(authority.project(decision, [first, not first]), (expected, first))
            with self.assertRaisesRegex(v.Invalid, "authority-projection-undefined"):
                authority.project(decision, [not first, None])
            for values in ([first], [first, 1], [first, "false"], (first, True)):
                with self.subTest(values=values), self.assertRaisesRegex(v.Invalid, "authority-projection-values"):
                    authority.project(decision, values)
            decision["tree"].append({"kind": "not", "children": [2]})
            decision["root"] = 3
            self.assertEqual(authority.project(decision, [first, None]), (expected, not first))

    def test_short_circuit(self) -> None:
        """Only registered undefined-field domains qualify; actual masks and every fixed value remain necessary."""
        cases = (
            (
                "batch-null",
                "authority.go",
                4888,
                1,
                "complete || page == nil || page.Scope == nil || page.Version == 0 || len(page.Changes) == 0",
                [False] * 5,
                [False, True, None, None, None],
                "11111",
                "12000",
            ),
            (
                "commit-null",
                "authority.go",
                5882,
                0,
                "request == nil || request.Scope == nil || (request.Change == nil) == (len(request.Changes) == 0)",
                [False] * 3,
                [True, None, None],
                "111",
                "200",
            ),
            ("batch-erase", "authority.go", 6822, 0, "action == nil || action.Erase == nil", [False] * 2, [True, None], "11", "20"),
            ("single-erase", "authority.go", 7882, 0, "action == nil || action.Erase == nil", [False] * 2, [True, None], "11", "20"),
            ("position-null", "stream.go", 10972, 0, "position == nil || position.Scope == nil", [False] * 2, [True, None], "11", "20"),
            (
                "hello-null",
                "stream.go",
                12087,
                0,
                "hello == nil || hello.ProtocolMajor != 1 || hello.MaxFrameBytes < 1024 || hello.MaxFrameBytes > 8<<20",
                [False] * 4,
                [True, None, None, None],
                "1111",
                "2000",
            ),
            ("ack-null", "stream.go", 22725, 0, "position != nil && position.Scope != nil", [True] * 2, [False, None], "22", "10"),
            (
                "suffix-end",
                "stream.go",
                16442,
                0,
                "begin < len(events) && events[begin].Scope == scope && len(changes) < 128",
                [True] * 3,
                [False, None, True],
                "222",
                "100",
            ),
        )
        self.assertEqual({row[0] for row in cases}, set(authority.GUARDED))
        for guard, name, offset, target, text, before, after, first, second in cases:
            kind = "and" if guard in ("ack-null", "suffix-end") else "or"
            atoms = [{"text": part} for part in text.split(" && " if kind == "and" else " || ")]
            tree = [{"kind": "atom", "atom": 0}]
            for index in range(1, len(atoms)):
                parent = len(tree) - 1
                tree.extend([{"kind": "atom", "atom": index}, {"kind": kind, "children": [parent, parent + 1]}])
            decision = {"id": f"polaris/internal/server/{name}:{offset}", "text": text, "atoms": atoms, "tree": tree, "root": len(tree) - 1}
            pair = {
                "decision": decision["id"],
                "condition": target,
                "before": {"values": before, "result": kind == "and"},
                "after": {"values": after, "result": kind != "and"},
            }
            actual = {(first, kind == "and"), (second, kind != "and")}
            proof = authority.correlate_pair(decision, pair, actual, guard=guard)
            self.assertEqual(proof["criterion"], "defined-domain-short-circuit-v1")
            self.assertEqual(proof["native_vectors"], [{"values": first, "result": kind == "and"}, {"values": second, "result": kind != "and"}])
            self.assertEqual(proof["before"]["values"], before)
            self.assertEqual(proof["after"]["values"], after)
            for observations in (set(), {next(iter(actual))}):
                with self.subTest(guard=guard), self.assertRaisesRegex(v.Invalid, "authority-pair-native-witness"):
                    authority.correlate_pair(decision, pair, observations, guard=guard)
            for selected in (None, "foreign"):
                with self.subTest(guard=guard, selected=selected), self.assertRaises(v.Invalid):
                    authority.correlate_pair(decision, pair, actual, guard=selected)
            for change in ("result", "condition", "undefined", "field", "identity", "extra"):
                altered = copy.deepcopy(pair)
                if change == "result":
                    altered["after"]["result"] = kind == "and"
                elif change == "condition":
                    altered["condition"] = False
                elif change == "undefined":
                    altered["after"]["values"][after.index(None)] = kind == "and"
                elif change == "field":
                    altered["before"]["values"][-1] = kind != "and"
                elif change == "identity":
                    altered["decision"] += "0"
                else:
                    altered["extra"] = "borrowed"
                with self.subTest(guard=guard, change=change), self.assertRaises(v.Invalid):
                    authority.correlate_pair(decision, altered, actual, guard=guard)
            with self.assertRaisesRegex(v.Invalid, "authority-pair-undefined-binding"):
                authority.correlate_pair({**decision, "text": text + " "}, pair, actual, guard=guard)

    def test_coupling(self) -> None:
        """A correlated Boolean cannot masquerade as an absent field; total pairs still need single-condition effects."""
        decision = {
            "id": "polaris/internal/server/stream.go:22725",
            "text": "x > 0 && x > 1",
            "atoms": [{"text": "x > 0"}, {"text": "x > 1"}],
            "tree": [{"kind": "atom", "atom": 0}, {"kind": "atom", "atom": 1}, {"kind": "and", "children": [0, 1]}],
            "root": 2,
        }
        pair = {
            "decision": decision["id"],
            "condition": 0,
            "before": {"values": [False, False], "result": False},
            "after": {"values": [True, True], "result": True},
        }
        actual = {("10", False), ("22", True)}
        with self.assertRaisesRegex(v.Invalid, "authority-pair-coupled-change"):
            authority.correlate_pair(decision, pair, actual)
        forged = {**pair, "before": {"values": [True, True], "result": True}, "after": {"values": [False, None], "result": False}}
        with self.assertRaisesRegex(v.Invalid, "authority-pair-undefined-binding"):
            authority.correlate_pair(decision, forged, actual, guard="ack-null")
        # The positive control uses independent Boolean inputs, not the impossible x>1 while x<=0.
        decision = {**decision, "text": "a && b", "atoms": [{"text": "a"}, {"text": "b"}]}
        pair["before"]["values"] = [False, True]
        result = authority.correlate_pair(decision, pair, actual)
        self.assertEqual(result["criterion"], "total-input-single-condition-v1")
        self.assertIsNone(result["undefined_domain"])
        pair["condition"] = 1
        with self.assertRaises(v.Invalid):
            authority.correlate_pair(decision, pair, actual)
        with self.assertRaisesRegex(v.Invalid, "authority-correlation-forest"):
            authority.correlate(self.root, {"version": 2, "files": []}, b"", 1, {})

    def test_lifecycle(self) -> None:
        """Missing, repeated, reordered, failed or borrowed native terminals cannot become pair evidence."""
        original = stream()
        changes = [
            original[1:],
            original[:-1],
            original[:-2] + original[-1:],
            [original[1], original[0], *original[2:]],
            original + [original[-1]],
            [original[0], *original],
        ]
        for index, field, value in (
            (0, "Package", "other"),
            (0, "Test", "TestPredicates"),
            (1, "Test", "Other"),
            (1, "Action", "pass"),
            (2, "Test", "Other"),
            (2, "Action", "bench"),
            (-2, "Action", "fail"),
            (-2, "Action", "skip"),
            (-1, "Action", "fail"),
        ):
            altered = copy.deepcopy(original)
            altered[index][field] = value
            changes.append(altered)
        changes.append([*original[:-1], original[2], original[-1]])
        for index, altered in enumerate(changes):
            with self.subTest(case=index), self.assertRaises(v.Invalid):
                authority.observations(encoded(altered), self.root)

    def test_stream(self) -> None:
        """Fragmented witnesses retain their owner; truncation, overflow and foreign marker placement fail."""
        original = stream()
        fragmented = []
        for row in original:
            if row["Action"] == "output":
                value = row["Output"]
                fragmented.extend([{**row, "Output": value[:42]}, {**row, "Output": value[42:]}])
            else:
                fragmented.append(row)
        self.assertEqual(authority.observations(encoded(fragmented), self.root), authority.observations(encoded(original), self.root))
        for value in (original[-3]["Output"].rstrip("\n"), "x" * 65537, "AUTHORITY-PREDICATES AUTHORITY-PREDICATES {}\n", None):
            altered = copy.deepcopy(original)
            altered[-3]["Output"] = value
            with self.subTest(output=str(value)[:20]), self.assertRaises(v.Invalid):
                authority.observations(encoded(altered), self.root)
        altered = copy.deepcopy(original)
        del altered[2]["Test"]
        with self.assertRaises(v.Invalid):
            authority.observations(encoded(altered), self.root)

    def test_process(self) -> None:
        """Native timeout, cancellation, nonzero exit and runtime diagnostics override otherwise complete witnesses."""
        record = {"complete": True, "cleanup": True, "termination": "exited", "exit_code": 0}
        data = encoded(stream())
        self.assertEqual(len(authority.outcome(data, b"", record, self.root)["pairs"]), 56)
        for field, value in (("complete", False), ("cleanup", False), ("termination", "timeout"), ("exit_code", 1), ("exit_code", False)):
            with self.subTest(field=field, value=value), self.assertRaises(v.Invalid):
                authority.outcome(data, b"", {**record, field: value}, self.root)
        for text in (b"WARNING: DATA RACE", b"panic:", b"fatal error:"):
            with self.subTest(text=text), self.assertRaises(v.Invalid):
                authority.outcome(data, text, record, self.root)

    def test_generation(self) -> None:
        """Generated fixtures do not replace production code or escape the owned build tree."""
        for output in (self.root, self.root / "build", self.root / "build/../outside"):
            with self.subTest(output=output), self.assertRaises(v.Invalid):
                authority.generate(self.root, output)
        virtual = self.root / "polaris/internal/server/predicates_test.go"
        virtual.write_bytes(b"package server\n")
        with self.assertRaisesRegex(v.Invalid, "authority-pairs-existing-test"):
            authority.generate(self.root, self.output)
        virtual.unlink()
        result = authority.generate(self.root, self.output)
        self.assertEqual(result["pairs"], authority.expected())
        self.assertEqual(v.decode(v.read(self.output / "overlay.json")), {"Replace": {str(virtual): str(self.output / "predicates.go.txt")}})
        self.assertEqual(v.read(self.output / "predicates.go.txt"), v.read(self.root / authority.FIXTURE))
        with self.assertRaises(FileExistsError):
            authority.generate(self.root, self.output)
        for name in result["files"]:
            path = self.output / name
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            with self.subTest(file=name), self.assertRaisesRegex(v.Invalid, "authority-pairs-overlay-drift"):
                authority.inspect(self.root, self.output)
            path.write_bytes(original)
        for profile in authority.PROFILES:
            command = authority.command(self.output, profile)
            self.assertIn("-run=^TestPredicates$", command)
            self.assertEqual("-race" in command, profile == "race")
        with self.assertRaises(v.Invalid):
            authority.command(self.output, "unknown")

    def test_registration(self) -> None:
        """The bounded campaign and all eight adversarial controls remain registered for current acceptance."""
        config = v.decode(v.read(self.origin / "development.json"))
        step = next(step for step in config["campaigns"][0]["steps"] if step["id"] == "authority-pairs")
        self.assertEqual(step["argv"], ["{python}", "-B", "tools/authority.py", "--root", "{root}", "--output", "{run}/authority-inputs", "--run"])
        self.assertEqual(step["timeout_s"], 700)
        self.assertEqual(step["requires"], [])
        check = next(check for check in config["checks"] if check["id"] == "verification-python")
        self.assertIn("tests.test_authority", check["argv"])
        expected = {"tests.test_authority.AuthorityTests." + name for name in dir(type(self)) if name.startswith("test_")}
        self.assertTrue(expected <= set(check["expected_tests"]))
