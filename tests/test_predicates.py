"""Challenge input independence, complete native observations and source binding of the format-predicate oracle."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from tools import admission, admissioncompiler, authority, entry, materials, predicates, structure, verify as v

ROOT = Path(__file__).resolve().parents[1]


def configured() -> dict:
    """Read the exact registered capability without manufacturing a native run."""
    return next(c for c in v.decode(v.read(ROOT / "development.json"))["checks"] if c["id"] == "admission-predicates")


def populate(root: Path) -> None:
    """Restore exact historical fixture bytes for controls of the frozen independence reader."""
    for relative in predicates.FIXTURES:
        source = "tests/fixtures/admission-fault.go.in" if relative == "internal/admission/fault_linux_amd64_test.go" else relative
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / source).read_bytes())


def encode(rows: list[dict], name: str = "TestPredicates") -> bytes:
    """Supply deliberately synthetic parser controls, never runtime facts."""
    package = configured()["package"]
    return b"".join(
        json.dumps(
            {
                "Action": "output",
                "Package": package,
                "Test": name,
                "Output": "predicates_test.go:1: ADMISSION-PREDICATES " + json.dumps(row) + "\n",
            }
        ).encode()
        + b"\n"
        for row in rows
    )


def fixture_stream() -> bytes:
    """Frame synthetic counter/matrix receipts for parser controls; these never provide native qualification."""
    package = configured()["package"]
    events = []
    for name, counters in predicates.COUNTERS.items():
        for contract, hits in counters:
            events.append({"Test": name, "Output": "ASTRA-CONTRACT " + json.dumps({"contract": contract, "hits": hits}) + "\n"})
    for fault in materials.FAULTS:
        for slot in range(5):
            for phase in range(3):
                events.append({"Test": "TestLoadFault", "Output": "ADMISSION-IDENTITY-FAULT " + json.dumps(materials.expected(fault, slot, phase)) + "\n"})
    return b"".join(json.dumps({**row, "Action": "output", "Package": package}).encode() + b"\n" for row in events)


class PredicateTests(unittest.TestCase):
    """Keep reference axioms separate from native evidence and reject altered denominators."""

    def test_dependencies(self) -> None:
        """Native package closure rejects changed/new fixtures and locks, while unrelated tests have no effect."""
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            values = {
                "internal/admission/identity.go": b"production",
                "internal/admission/identity_test.go": b"fixture",
                "internal/generated/message.go": b"dependency",
                "tools/decisions/main.go": b"collector",
                "go.mod": b"module",
                "go.sum": b"sums",
                "dependencies.lock.json": b"locks",
            }
            for relative, data in values.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            inputs = {key: v.digest(data) for key, data in values.items()}
            packages = [{"ImportPath": "github.com/eosforge/astra/" + part} for part in ("internal/admission", "internal/generated")]
            self.assertEqual(predicates.sources(root, inputs, packages), inputs)
            (root / "unrelated_test.go").write_bytes(b"unrelated")
            self.assertEqual(predicates.sources(root, inputs, packages), inputs)
            for relative, data in values.items():
                (root / relative).write_bytes(data + b"changed")
                with self.subTest(source=relative), self.assertRaisesRegex(v.Invalid, "predicates-input-drift"):
                    predicates.sources(root, inputs, packages)
                (root / relative).write_bytes(data)
            extra = root / "internal/admission/added_test.go"
            extra.write_bytes(b"new fixture")
            with self.assertRaisesRegex(v.Invalid, "predicates-input-inventory"):
                predicates.sources(root, inputs, packages)
            extra.unlink()
            (root / "internal/admission/identity_test.go").unlink()
            with self.assertRaisesRegex(v.Invalid, "predicates-input-inventory"):
                predicates.sources(root, inputs, packages)
            for rows in (packages[1:], [{**packages[0], "TestImports": ["github.com/eosforge/astra/missing"]}, packages[1]]):
                with self.subTest(packages=rows), self.assertRaisesRegex(v.Invalid, "predicates-input-dependencies"):
                    predicates.sources(root, inputs, rows)

    def test_acquisition(self) -> None:
        """Only reviewed coordinates migrate; the split kind guard cannot borrow the former restat proof."""
        self.assertEqual(predicates.coordinate("internal/admission/identity.go:1719", acquisition=True), "internal/admission/identity.go:1722")
        for offset in (1988, 2006, 1234):
            with self.assertRaisesRegex(v.Invalid, "predicates-unreviewed-coordinate"):
                predicates.coordinate("internal/admission/identity.go:" + str(offset), acquisition=True)
        pairs = predicates.witnesses(acquisition=True)
        self.assertEqual(len(pairs), 36)
        self.assertTrue(any(row["decision"] == "internal/admission/identity.go:6384" for row in pairs))
        boundaries = predicates.boundaries(acquisition=True)
        self.assertEqual(len(boundaries), 54)
        self.assertEqual([r["pair"]["condition"] for r in boundaries if r["pair"]["decision"].endswith(":2223")], [0, 1])
        self.assertFalse(any(r["pair"]["decision"].endswith((":1988", ":2006")) for r in boundaries))
        guards = predicates.guards(acquisition=True)
        row = next(r["pair"] for r in guards if r["pair"]["decision"] == "internal/admission/identity.go:2006")
        self.assertEqual(row["before"], {"values": [False, True, True], "result": False})
        self.assertEqual(row["after"], {"values": [True, None, None], "result": True})
        self.assertEqual(predicates.fixtures(ROOT, fixture_stream(), acquisition=True)["fault_cells"], 120)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            populate(root)
            with self.assertRaisesRegex(v.Invalid, "predicates-fixture-drift"):
                predicates.fixtures(root, fixture_stream(), acquisition=True)
        archives = {name: v.read(ROOT / "build/results/assurance/reuse-plan" / name / "evidence.tar.gz", 16 * 1024**2) for name in admissioncompiler.ARTIFACTS}
        result = predicates.reconcile(ROOT, archives)
        self.assertEqual(result["compiler"], "1.27.2")
        self.assertEqual(result["application_commands"], 0)
        self.assertEqual(result["compiler_exports_reused"], 0)
        self.assertEqual(result["independence"]["raw_conditions"], 185)
        self.assertEqual(result["independence"]["supported_conditions"], 165)
        self.assertEqual(result["independence"]["qualified_denominator"], 165)
        self.assertEqual(result["independence"]["qualified_unresolved"], [])
        result = predicates.reconcile(ROOT, archives, structural=True)
        self.assertEqual(result["status"], "complete-under-assumptions")
        self.assertEqual(result["statements"]["raw"], {"blocks": 209, "statements": 287, "statements_hit": 284})
        self.assertEqual(result["statements"]["compiler_weights"]["obligations"], {"statements": 289, "statements_hit": 286})
        self.assertEqual(result["boolean"]["totals"]["roots"]["observed"], 158)
        self.assertEqual(result["boolean"]["totals"]["atoms"]["observed"], 357)
        self.assertEqual(result["controls"]["observed"], 28)
        files = entry.unpack(archives[admissioncompiler.GEOMETRY])
        first = admissioncompiler.PREFIX + "coverage/"
        changes = [
            ("source.native.after.json", ("commit",), "forged", "source"),
            ("terminal.json", ("errors",), ["failed"], "owner"),
            ("terminal.json", ("whole_resources", "memory.max"), "4294967296", "resources"),
            ("cleanup.native.json", ("remaining_owned",), [{"pid": 1}], "owner"),
            ("cache-return.json", ("inode",), 0, "cache"),
            (first + "record.json", ("toolchain", "CC", "sha256"), "0" * 64, "command"),
            (first + "request.json", ("timeout_s",), 241, "command"),
            (first + "record.json", ("environment", "GOPROXY"), "https://example.invalid", "command"),
            (first + "leaf.after.json", ("pids.events",), "max 1", "command"),
            (first + "exec.native.json", ("observed", 0, "executable"), "/usr/bin/go", "command"),
        ]
        for member, fields, value, reason in changes:
            changed = v.decode(files[member])
            target = changed
            for field in fields[:-1]:
                target = target[field]
            target[fields[-1]] = value
            with self.subTest(member=member, fields=fields), self.assertRaisesRegex(v.Invalid, "admission-compiler-" + reason):
                admissioncompiler.receipt(ROOT, {**files, member: v.encode(changed)})
        extra = entry.unpack(archives[admissioncompiler.PAIRS])
        request = v.decode(extra["commands/acquisition-pairs/request.json"])
        request["log_bytes"] *= 2
        with self.assertRaisesRegex(v.Invalid, "admission-compiler-command"):
            admissioncompiler.receipt(ROOT, {**extra, "commands/acquisition-pairs/request.json": v.encode(request)}, pairs=True)
        with tempfile.TemporaryDirectory() as temporary:
            shadow = Path(temporary)
            for name, data in entry.unpack(files["source.tar.gz"]).items():
                target = shadow / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            admissioncompiler.receipt(shadow, files)
            added = shadow / "internal/admission/unreviewed_test.go"
            added.write_bytes(b"package admission\n")
            with self.assertRaisesRegex(v.Invalid, "admission-compiler-source"):
                admissioncompiler.receipt(shadow, files)
            added.unlink()
            removed = shadow / "internal/admission/file_other.go"
            removed.unlink()
            with self.assertRaisesRegex(v.Invalid, "admission-compiler-source"):
                admissioncompiler.receipt(shadow, files)

    def test_metadata(self) -> None:
        """Synthetic controls reject changed inode predicates, missing observations and inflated counters."""
        rows = [{"regular": regular, "same_file": True, "accepted": regular, "read": regular, "closed": True} for regular in (True, False)]

        def stream(values: list[dict], hits: int = 12) -> bytes:
            """Encode metadata observations and their hit count as attributed Go test output."""
            outputs = ["ADMISSION-METADATA " + json.dumps(value) for value in values]
            outputs.append("ASTRA-CONTRACT " + json.dumps({"contract": "ADMISSION-METADATA", "hits": hits}))
            return b"".join(
                json.dumps({"Action": "output", "Package": configured()["package"], "Test": "TestLoadMetadata", "Output": value + "\n"}).encode() + b"\n"
                for value in outputs
            )

        self.assertEqual(predicates.metadata_observations(stream(rows)), rows)
        foreign = (
            json.dumps(
                {
                    "Action": "output",
                    "Package": configured()["package"],
                    "Test": "TestAdmissionEdges",
                    "Output": 'ASTRA-CONTRACT {"contract":"ADMISSION-EDGE","hits":20}\n',
                }
            ).encode()
            + b"\n"
        )
        self.assertEqual(predicates.metadata_observations(stream(rows) + foreign), rows)
        with self.assertRaisesRegex(v.Invalid, "equality-test"):
            predicates.metadata_observations(stream(rows).replace(b'"TestLoadMetadata"', b'"TestAdmissionEdges"'))
        for values in (rows[:1], rows[::-1], rows + rows[:1]):
            with self.assertRaises(v.Invalid):
                predicates.metadata_observations(stream(values))
        for field in rows[0]:
            for value in (not rows[1][field], int(rows[1][field]), None):
                changed = copy.deepcopy(rows)
                changed[1][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(v.Invalid):
                    predicates.metadata_observations(stream(changed))
        for hits in (0, 11, 13, True):
            with self.assertRaises(v.Invalid):
                predicates.metadata_observations(stream(rows, hits))

    def test_configuration(self) -> None:
        """Selection, scope and successful assertion budgets are exact rather than user-provided claims."""
        check = configured()
        predicates.configuration(check)
        for key, value in (
            ("decisions", "unknown"),
            ("component", "unknown"),
            ("package", "unknown"),
            ("argv", check["argv"] + ["-short"]),
            ("expected_tests", []),
            ("probes", []),
        ):
            changed = copy.deepcopy(check)
            changed[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(v.Invalid, "predicates-configuration"):
                predicates.configuration(changed)
        for count in (0, 50, 73, True, 74.0):
            changed = copy.deepcopy(check)
            changed["probes"][0]["minimum_hits"] = count
            with self.subTest(count=count), self.assertRaisesRegex(v.Invalid, "predicates-configuration"):
                predicates.configuration(changed)

    def test_axioms(self) -> None:
        """Independently check each alphabet/range truth vector and each changed member-format field."""
        rows = predicates.expected()
        self.assertEqual(len(rows), 31)
        for row in rows:
            before, after = row["before"], row["after"]
            self.assertIsNot(before["result"], after["result"])
            condition = row["condition"]
            if row["function"] == "Name":
                if condition < 2:
                    vectors = [(len(value) == 0, len(value) > 64) for value in (before["input"], after["input"])]
                else:
                    vectors = [
                        (c >= "a", c <= "z", c >= "A", c <= "Z", c >= "0", c <= "9", c == ".", c == "_", c == "-") for c in (before["input"], after["input"])
                    ]
                    condition -= 2
                self.assertEqual([i for i, (a, b) in enumerate(zip(*vectors)) if a != b], [condition])
                alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
                for sample in (before, after):
                    value = sample["input"]
                    self.assertEqual(sample["result"], 1 <= len(value) <= 64 and all(c in alphabet for c in value))
            elif row["function"] == "Role":
                self.assertEqual(before["input"], 0)
                self.assertEqual(after["input"], condition + 1)
            elif row["function"] == "NewDirectory":
                values = (before["input"], after["input"])
                vectors = [
                    (
                        not value["identity"],
                        value["galaxy"] == "",
                        value["role"] not in (1, 2, 3, 4),
                        value["role"] == 2,
                        value["maximum"] < 1,
                        value["maximum"] > 16384,
                    )
                    for value in values
                ]
                self.assertEqual([i for i, (a, b) in enumerate(zip(*vectors)) if a != b], [condition])
                self.assertEqual(
                    [field for field in values[0] if values[0][field] != values[1][field]],
                    [("identity", "galaxy", "role", "role", "maximum", "maximum")[condition]],
                )
                self.assertFalse(any(vectors[0]))
                self.assertTrue(any(vectors[1]))
            else:
                if condition == 0:
                    self.assertIsNone(after["input"])
                    continue
                fields = ("galaxy", "group", "id", "id", "id", "epoch", "role", "principal", "advertise")
                self.assertEqual([field for field in before["input"] if before["input"][field] != after["input"].get(field)], [fields[condition - 1]])
        self.assertEqual(rows[20]["after"]["input"]["id"], "/w==")
        self.assertEqual(rows[24]["after"]["input"]["advertise"], "127.0.0.1:0")
        pairs = predicates.witnesses()
        self.assertEqual(len(pairs), 36)
        self.assertEqual(len({(row["decision"], row["condition"]) for row in pairs}), 36)
        for row in pairs:
            before, after = (row[side]["values"] for side in ("before", "after"))
            self.assertTrue(all(type(value) is bool for vector in (before, after) for value in vector))
            self.assertEqual([index for index, (left, right) in enumerate(zip(before, after, strict=True)) if left != right], [row["condition"]])
            for side in ("before", "after"):
                vector = row[side]["values"]
                offset = int(row["decision"].split(":")[-1])
                if offset == 6972:
                    result = not (vector[0] and vector[1] or vector[2] and vector[3] or vector[4] and vector[5] or any(vector[6:]))
                elif offset == 6195:
                    result = vector[0] or not vector[1] or not vector[2] or vector[3] or vector[4] or not vector[5] or vector[6] or not vector[7] or vector[8]
                elif offset == 925:
                    result = vector[0] or not vector[1] or not vector[2] or any(vector[3:])
                elif offset == 6403:
                    result = all(vector)
                else:
                    result = any(vector)
                self.assertIs(row[side]["result"], result)
            self.assertIsNot(row["before"]["result"], row["after"]["result"])
        self.assertEqual([row["condition"] for row in pairs if row["decision"].endswith(":6195")], list(range(1, 9)))
        self.assertEqual([row["condition"] for row in pairs if row["decision"].endswith(":6403")], list(range(2, 9)))
        boundaries = predicates.boundaries()
        self.assertEqual(len(boundaries), 55)
        self.assertEqual(len({(row["pair"]["decision"], row["pair"]["condition"]) for row in boundaries}), 55)
        for row in boundaries:
            pair = row["pair"]
            before, after = (pair[side]["values"] for side in ("before", "after"))
            self.assertEqual([index for index, (left, right) in enumerate(zip(before, after, strict=True)) if left != right], [pair["condition"]])
            self.assertIn(row["test"], set(predicates.COUNTERS) | {"TestSharedVectors", "TestDirectoryBoundaries"})
            self.assertTrue(row["basis"])
            for side in ("before", "after"):
                vector = pair[side]["values"]
                self.assertTrue(all(type(value) is bool for value in vector))
                offset = int(pair["decision"].split(":")[-1])
                if offset == 1678:
                    result = not vector[0] or vector[1] or all(vector[2:5]) or vector[5] and vector[6] or any(vector[7:])
                elif offset == 2397:
                    result = vector[0] and not vector[1] or any(vector[2:4]) or all(vector[4:])
                elif offset == 3434:
                    result = vector[0] or vector[1] and not vector[2] or any(vector[3:5]) or all(vector[5:])
                elif offset == 3897:
                    result = vector[0] and any(vector[1:])
                elif offset == 4042:
                    result = vector[0] or not vector[1] or vector[2] or all(vector[3:])
                elif offset == 1191:
                    result = vector[0] or vector[1] or not vector[2] or not vector[3] or vector[4] and vector[5]
                elif offset in (4423, 4231):
                    result = any(vector[:-1]) or not vector[-1]
                elif offset == 4493:
                    result = vector[0] or vector[1] or not vector[2] or vector[3] or vector[4]
                elif offset == 1988:
                    result = vector[0] or not vector[1] or any(vector[2:])
                else:
                    result = any(vector)
                self.assertIs(pair[side]["result"], result)
        guards = predicates.guards()
        self.assertEqual(len(guards), 9)
        self.assertEqual(len({(row["pair"]["decision"], row["pair"]["condition"]) for row in guards}), 9)
        for row in guards:
            pair = row["pair"]
            before, after = (pair[side]["values"] for side in ("before", "after"))
            self.assertTrue(all(type(value) is bool for value in before))
            self.assertIsNot(before[pair["condition"]], after[pair["condition"]])
            self.assertIsNot(pair["before"]["result"], pair["after"]["result"])
            self.assertIn(None, after)
            self.assertEqual([i for i, (left, right) in enumerate(zip(before, after, strict=True)) if right is not None and left != right], [pair["condition"]])
            if pair["decision"].endswith(":6403"):
                self.assertEqual(after[2:], [None] * 7)
                self.assertIs(after[1 - pair["condition"]], True)

    def test_pairs(self) -> None:
        """Missing, duplicated, reordered, Boolean-forged and changed-input observations cannot qualify."""
        rows, check = predicates.expected(), configured()
        with self.assertRaisesRegex(v.Invalid, "defense-source-scope"):
            predicates.independence(ROOT, {"files": []}, encode(rows), ["TestPredicates"], dependency={})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in admission.SOURCES:
                source = "tests/fixtures/admission-identity.go.in" if relative == "internal/admission/identity.go" else relative
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / source).read_bytes())
            with self.assertRaisesRegex(v.Invalid, "predicates-forest"):
                predicates.independence(root, {"files": []}, encode(rows), ["TestPredicates"], dependency={})
        self.assertEqual(predicates.observations(encode(rows), check, ROOT), {"ADMISSION-PREDICATES": 74})
        for altered in ([], rows[:-1], rows + [rows[0]], list(reversed(rows))):
            with self.assertRaises(v.Invalid):
                predicates.observations(encode(altered), check, ROOT)
        for path, value in (
            (("condition",), False),
            (("condition",), 0.0),
            (("extra",), 1),
            (("before", "result"), 1),
            (("after", "result"), True),
            (("after", "input"), "b"),
        ):
            altered = copy.deepcopy(rows)
            target = altered[0]
            for field in path[:-1]:
                target = target[field]
            target[path[-1]] = value
            with self.assertRaisesRegex(v.Invalid, "predicates-pairs"):
                predicates.observations(encode(altered), check, ROOT)
        # Opposite outcomes alone cannot prove either condition in x > 0 && x > 1.
        for kind in ("and", "or"):
            decision = {
                "id": "synthetic:0",
                "atoms": [{}, {}],
                "tree": [{"kind": "atom", "atom": 0}, {"kind": "atom", "atom": 1}, {"kind": kind, "children": [0, 1]}],
                "root": 2,
            }
            pair = {
                "decision": decision["id"],
                "condition": 0,
                "before": {"values": [False, False], "result": False},
                "after": {"values": [True, True], "result": True},
            }
            observed = {authority.project(decision, pair[side]["values"]) for side in ("before", "after")}
            with self.subTest(kind=kind), self.assertRaisesRegex(v.Invalid, "predicates-pair-coupled"):
                predicates.mask(decision, pair, observed)
        decision = {
            "id": "synthetic:1",
            "atoms": [{}, {}, {}],
            "tree": [
                {"kind": "atom", "atom": 0},
                {"kind": "atom", "atom": 1},
                {"kind": "atom", "atom": 2},
                {"kind": "and", "children": [1, 2]},
                {"kind": "or", "children": [0, 3]},
            ],
            "root": 4,
        }
        pair = {
            "decision": decision["id"],
            "condition": 0,
            "before": {"values": [False, True, False], "result": False},
            "after": {"values": [True, False, False], "result": True},
        }
        observed = {authority.project(decision, pair[side]["values"]) for side in ("before", "after")}
        proof = predicates.mask(decision, pair, observed)
        self.assertEqual(proof["criterion"], "concrete-common-cube-v1")
        self.assertEqual(proof["fixed"], "001")
        with self.assertRaisesRegex(v.Invalid, "authority-pair-native-witness"):
            predicates.mask(decision, pair, {authority.project(decision, pair["before"]["values"])})
        pair["before"]["values"] = [False, False, False]
        pair["after"]["values"] = [True, True, True]
        observed = {authority.project(decision, pair[side]["values"]) for side in ("before", "after")}
        with self.assertRaisesRegex(v.Invalid, "predicates-pair-coupled"):
            predicates.mask(decision, pair, observed)

        def edge_stream(items: list[dict], hits: int = 20) -> bytes:
            """Construct synthetic edge parser challenges, never application evidence."""
            package = check["package"]
            output = ["ADMISSION-EDGE " + json.dumps(row) for row in items]
            output.append("ASTRA-CONTRACT " + json.dumps({"contract": "ADMISSION-EDGE", "hits": hits}))
            return b"".join(
                json.dumps({"Action": "output", "Package": package, "Test": "TestAdmissionEdges", "Output": row + "\n"}).encode() + b"\n" for row in output
            )

        inputs = predicates.edge_inputs()
        self.assertEqual(predicates.edge_observations(edge_stream(inputs), ROOT), inputs)
        self.assertEqual([row["accepted"] for row in inputs], [True, False, True, False])
        self.assertEqual(inputs[0]["candidate"]["id"], inputs[1]["candidate"]["id"])
        self.assertEqual(inputs[2]["partial"], inputs[3]["partial"])
        self.assertIsNone(inputs[3]["returned"])
        for changed in (inputs[:-1], list(reversed(inputs))):
            with self.assertRaisesRegex(v.Invalid, "predicates-edge-inputs"):
                predicates.edge_observations(edge_stream(changed), ROOT)
        with self.assertRaisesRegex(v.Invalid, "equality-row-budget"):
            predicates.edge_observations(edge_stream(inputs + inputs[:1]), ROOT)
        for index, field, value in (
            (0, "accepted", 1),
            (1, "snapshot", inputs[0]["snapshot"]),
            (3, "input", inputs[2]["input"]),
            (3, "returned", inputs[3]["partial"]),
        ):
            changed = copy.deepcopy(inputs)
            changed[index][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "predicates-edge-inputs"):
                predicates.edge_observations(edge_stream(changed), ROOT)
        for hits in (0, 19, True):
            with self.subTest(hits=hits), self.assertRaisesRegex(v.Invalid, "predicates-edge-counter"):
                predicates.edge_observations(edge_stream(inputs, hits), ROOT)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = root / "tests/fixtures/admission.go.in"
            path.parent.mkdir(parents=True)
            path.write_bytes((ROOT / "tests/fixtures/admission.go.in").read_bytes() + b"\n")
            with self.assertRaisesRegex(v.Invalid, "predicates-edge-source"):
                predicates.edge_observations(edge_stream(inputs), root)

        # An error implies a second OR guard; removing that implication restores an independent pair.
        decision = {
            "id": "synthetic:coupling",
            "atoms": [{}, {}],
            "tree": [{"kind": "atom", "atom": 0}, {"kind": "atom", "atom": 1}, {"kind": "or", "children": [0, 1]}],
            "root": 2,
        }
        proof = predicates.symbolic(decision, 0, lambda values: not values[0] or values[1])
        self.assertEqual(proof["total"], 4)
        self.assertEqual(len(proof["allowed"]), 3)
        self.assertEqual(proof["relaxed_witness"], {"false": "11", "true": "21", "fixed": "01"})
        for relation in (lambda _: True, lambda _: False, lambda values: not values[0]):
            with self.assertRaisesRegex(v.Invalid, "predicates-coupling-vacuous"):
                predicates.symbolic(decision, 0, relation)
        with self.assertRaisesRegex(v.Invalid, "predicates-coupling-independent"):
            predicates.symbolic(decision, 0, lambda values: not values[1] or values[0])
        self.assertEqual(len(predicates.relations()), 7)
        self.assertEqual(len({(name, atom) for name, atom, *_ in predicates.relations()}), 7)

    def test_stream(self) -> None:
        """Native fragmentation is accepted; foreign ownership, overflow, truncation and repeated markers fail."""
        check = configured()
        events = [v.decode(line) for line in encode(predicates.expected()).splitlines()]
        split = []
        for event in events:
            output = event["Output"]
            split.extend([{**event, "Output": output[:34]}, {**event, "Output": output[34:]}])
        raw = lambda values: b"".join(json.dumps(e).encode() + b"\n" for e in values)
        self.assertEqual(predicates.observations(raw(split), check, ROOT), {"ADMISSION-PREDICATES": 74})
        for field, value in (
            ("Test", "Other"),
            ("Package", "Other"),
            ("Output", events[-1]["Output"].rstrip("\n")),
            ("Output", "x" * 65537),
            ("Output", events[-1]["Output"].replace("ADMISSION-PREDICATES ", "ADMISSION-PREDICATES ADMISSION-PREDICATES ")),
        ):
            altered = copy.deepcopy(events)
            altered[-1][field] = value
            with self.assertRaises(v.Invalid):
                predicates.observations(raw(altered), check, ROOT)
        fixture = fixture_stream()
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        root = Path(workspace.name)
        populate(root)
        self.assertEqual(predicates.fixtures(root, fixture)["fault_cells"], 120)
        rows = [v.decode(line) for line in fixture.splitlines()]
        for changed, reason in ((rows[1:], "counter"), (rows[:-1], "faults")):
            with self.assertRaisesRegex(v.Invalid, "predicates-fixture-" + reason):
                predicates.fixtures(root, raw(changed))
        altered = copy.deepcopy(rows)
        altered[0]["Output"] = altered[0]["Output"].replace('"hits": 117', '"hits": true')
        self.assertNotEqual(altered, rows)
        with self.assertRaisesRegex(v.Invalid, "predicates-fixture-counter"):
            predicates.fixtures(root, raw(altered))
        altered = copy.deepcopy(rows)
        altered[-1]["Output"] = altered[-1]["Output"].replace('"closed": 5', '"closed": 4')
        self.assertNotEqual(altered, rows)
        with self.assertRaisesRegex(v.Invalid, "predicates-fixture-faults"):
            predicates.fixtures(root, raw(altered))

    def test_source(self) -> None:
        """Source changes invalidate all otherwise correct pairs; no source identity is inferred from a commit alone."""
        with self.assertRaisesRegex(v.Invalid, "predicates-archive-inventory"):
            predicates.reconcile(ROOT, {})
        with self.assertRaisesRegex(v.Invalid, "predicates-archive-integrity"):
            predicates.reconcile(ROOT, {name: b"forged" for name in predicates.archives(ROOT)})
        self.assertEqual(predicates.archives(ROOT), admissioncompiler.ARTIFACTS)
        with self.assertRaisesRegex(v.Invalid, "predicates-archive-inventory"):
            predicates.reconcile(ROOT, {name: b"forged" for name in predicates.ARCHIVES})
        with self.assertRaisesRegex(v.Invalid, "predicates-archive-inventory"):
            predicates.reconcile(ROOT, {}, structural=True)
        with self.assertRaisesRegex(v.Invalid, "predicates-archive-inventory"):
            predicates.reconcile(ROOT, {name: b"forged" for name in predicates.REPAIRED}, structural=True)
        with tempfile.TemporaryDirectory() as name, self.assertRaisesRegex(v.Invalid, "predicates-structure-source"):
            predicates.reconcile(Path(name), {}, structural=True)
        with self.assertRaisesRegex(v.Invalid, "predicates-dependency-scope"):
            predicates.domains({}, {}, {})
        with self.assertRaisesRegex(v.Invalid, "predicates-dependency-drift"):
            predicates.domains({}, {}, {name: b"" for name in structure.DEPENDENCIES})
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = root / "internal/admission/identity.go"
            path.parent.mkdir(parents=True)
            for relative in admission.MATERIAL:
                (root / relative).write_bytes((ROOT / relative).read_bytes())
            directory = root / "internal/admission/directory.go"
            directory.write_bytes((ROOT / "internal/admission/directory.go").read_bytes())
            self.assertEqual(predicates.observations(encode(predicates.expected()), configured(), root), {"ADMISSION-PREDICATES": 74})
            for relative in admission.MATERIAL:
                source = root / relative
                original = source.read_bytes()
                for replacement in (None, original + b"\n"):
                    if replacement is None:
                        source.unlink()
                    else:
                        source.write_bytes(replacement)
                    with self.subTest(source=relative, missing=replacement is None), self.assertRaises(v.Invalid):
                        predicates.observations(encode(predicates.expected()), configured(), root)
                    source.write_bytes(original)
            directory.write_bytes(directory.read_bytes() + b"\n")
            with self.assertRaisesRegex(v.Invalid, "predicates-source"):
                predicates.observations(encode(predicates.expected()), configured(), root)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            populate(root)
            self.assertEqual(predicates.fixtures(root, fixture_stream())["sources"], predicates.FIXTURES)
            with self.assertRaisesRegex(v.Invalid, "predicates-fixture-drift"):
                predicates.fixtures(ROOT, fixture_stream())
            for relative in predicates.FIXTURES:
                path = root / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.subTest(source=relative), self.assertRaisesRegex(v.Invalid, "predicates-fixture-drift"):
                    predicates.fixtures(root, fixture_stream())
                path.write_bytes(original)
