"""Challenge Admission model reconstruction with independent axioms and explicitly synthetic malformed evidence."""

import copy
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from tools import admission, models, verify as v

ROOT = Path(__file__).resolve().parents[1]


def configured() -> dict:
    """Use the actual registered capability and complete test inventory."""
    return next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "admission-model")


def pack(value: object) -> bytes:
    """Keep each synthetic JSON event on exactly one line."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def sample() -> dict[str, list[dict]]:
    """Produce synthetic parser inputs; their agreement with the parser is not native application evidence."""
    return {kind: [row[0] if kind == "pair" else row for row in admission.expected(kind)] for kind in admission.KINDS}


def encode(rows: dict[str, list[dict]]) -> bytes:
    """Encode explicitly synthetic public observations with their actual declared native ownership."""
    package = configured()["package"]
    return b"".join(
        pack(
            {
                "Package": package,
                "Action": "output",
                "Test": admission.KINDS[kind][0],
                "Output": "model_test.go:1: ADMISSION-MODEL " + pack({"kind": kind, "value": row}).decode() + "\n",
            }
        )
        + b"\n"
        for kind, values in rows.items()
        for row in values
    )


class AdmissionTests(unittest.TestCase):
    """Separate format rejection, oracle axioms, complete domains, source binding and gate dispatch."""

    def test_configuration(self) -> None:
        """Refuse a different model, narrowed native command, missing tests or weakened probe denominators."""
        check = configured()
        models.configuration(check)
        for key, value in (("model", "other"), ("argv", check["argv"] + ["-run=TestNodeModel"]), ("expected_tests", check["expected_tests"][:-1])):
            changed = copy.deepcopy(check)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(v.Invalid):
                admission.configuration(changed)
        for name in admission.PROBES:
            for mode in ("absent", "duplicate", "zero", "boolean", "float", "other-test"):
                changed = copy.deepcopy(check)
                probe = next(p for p in changed["probes"] if p["contract"] == name)
                if mode == "absent":
                    changed["probes"].remove(probe)
                elif mode == "duplicate":
                    changed["probes"].append(copy.deepcopy(probe))
                elif mode == "other-test":
                    probe["test"] = "TestNodeState"
                else:
                    probe["minimum_hits"] = {"zero": 0, "boolean": True, "float": float(probe["minimum_hits"])}[mode]
                with self.subTest(name=name, mode=mode), self.assertRaisesRegex(v.Invalid, "admission-model-configuration"):
                    admission.configuration(changed)

    def test_axioms(self) -> None:
        """Anchor arithmetic and protocol clauses to literal results independently of generated parser samples."""
        for state, action, capacity, expected in (
            ((2, 0), 1, 1, ((2, 0), True)),
            ((2, 0), 9, 1, ((2, 0), False)),
            ((1, 0), 4, 1, ((1, 0), False)),
            ((0, 0), 6, 2, ((1, 2), True)),
            ((2, 1), 0, 2, ((2, 1), True)),
            ((1, 1), 17, 2, ((1, 1), False)),
        ):
            self.assertEqual(admission.directory(state, action, capacity), expected)
        for ready, epoch, action, expected in (
            (False, 0, 3, (False, 0, 1, 0, 0)),
            (False, 0, 0, (True, 1, 0, 1, 0)),
            (False, 2, 0, (False, 2, 2, 1, 0)),
            (True, 2, 0, (True, 2, 0, 0, 0)),
            (True, 2, 3, (True, 2, 3, 0, 1)),
            (True, 1, 6, (True, 1, 2, 0, 1)),
            (True, 1, 7, (True, 2, 0, 0, 0)),
            (True, 2, 8, (True, 2, 3, 0, 0)),
        ):
            self.assertEqual(admission.publication(ready, epoch, action), expected)
        self.assertEqual(
            admission.retry(3, False, 0, 9),
            {"role": 3, "refresh": False, "prefix": 0, "suffix": 9, "calls": 1, "delays": None, "callbacks": None, "result": 0, "admitted": True},
        )
        saturated = admission.retry(4, False, 7, 0)
        self.assertEqual(
            saturated["delays"], [500000000, 1000000000, 2000000000, 4000000000, 8000000000, 16000000000, 30000000000, 30000000000, 30000000000, 30000000000]
        )
        self.assertEqual((saturated["calls"], saturated["result"], saturated["admitted"]), (10, 1, False))
        reset = admission.retry(3, True, 0, 3)
        self.assertEqual(reset["delays"], [30000000000, 60000000000, 30000000000, 60000000000])
        self.assertEqual(reset["callbacks"], [14, 0, 14])
        self.assertEqual(
            admission.member(2, index=1),
            {
                "galaxy": "alpha",
                "id": "bm9kZS0wMS0wMg==",
                "principal": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=",
                "advertise": "127.0.0.1:7401",
                "epoch": 2,
                "role": 1,
                "group": "default",
            },
        )

    def test_domain(self) -> None:
        """Every kind has its full independent count, identities and type-sensitive reconciliation."""
        rows = sample()
        self.assertEqual({name: len(values) for name, values in rows.items()}, {"directory": 11664, "pair": 3240, "retry": 594, "publication": 4374})
        self.assertEqual(
            admission.reconcile(rows),
            {
                "ADMISSION-FINITE": 306026,
                "ADMISSION-ASSURANCE": 306026,
                "ADMISSION-SCHEDULE": 35161,
                "ADMISSION-NODE-FINITE": 12971,
                "ADMISSION-NODE-TRANSITIONS": 39417,
            },
        )
        for kind in admission.KINDS:
            for changed in ([], rows[kind][:-1], rows[kind] + rows[kind][:1]):
                with self.subTest(kind=kind, count=len(changed)), self.assertRaisesRegex(v.Invalid, "admission-model-domain"):
                    admission.domain(kind, changed)
        for kind in admission.KINDS:
            changed = dict(rows)
            del changed[kind]
            with self.subTest(kind=kind), self.assertRaisesRegex(v.Invalid, "admission-model-domains"):
                admission.reconcile(changed)

    def test_histories(self) -> None:
        """Unchanged counts cannot conceal a repeated, swapped, forged or semantically illegal observation."""
        for kind, rows in sample().items():
            for change in ("repeat", "swap", "missing", "extra", "boolean", "float", "value"):
                changed = list(rows)
                if change == "repeat":
                    changed[1] = changed[0]
                elif change == "swap":
                    changed[0], changed[1] = changed[1], changed[0]
                else:
                    row = changed[0] = copy.deepcopy(changed[0])
                    key = "capacity" if kind in {"directory", "pair"} else "role"
                    if change == "missing":
                        del row[key]
                    elif change == "extra":
                        row["undeclared"] = True
                    else:
                        row[key] = {"boolean": True, "float": float(row[key]), "value": 999}[change]
                with self.subTest(kind=kind, change=change), self.assertRaisesRegex(v.Invalid, "admission-model-history"):
                    admission.domain(kind, changed)
        rows = sample()["pair"]
        opposite = [row[1] for row in admission.expected("pair")]
        admission.domain("pair", opposite)
        self.assertNotEqual(rows, opposite)
        wrong = copy.deepcopy(rows[0])
        wrong["accepted"] = [False, False]
        with self.assertRaisesRegex(v.Invalid, "admission-model-history"):
            admission.domain("pair", [wrong] + rows[1:])

    def test_stream(self) -> None:
        """Require exact owners and bounded, complete model lines even when native stdout fragments them."""
        first = {"retry": [next(admission.expected("retry"))]}
        raw = encode(first)
        event = json.loads(raw)
        split = copy.deepcopy(event)
        split["Output"], event["Output"] = event["Output"][:31], event["Output"][31:]
        self.assertEqual(admission.frames(pack(split) + b"\n" + pack(event) + b"\n", configured()["package"])["retry"], first["retry"])
        for key, value, reason in (
            ("Package", "foreign", "package"),
            ("Test", "TestNodeState", "test"),
            ("Output", 5, "output"),
            ("Output", "x" * 65537, "line-budget"),
        ):
            changed = json.loads(raw)
            changed[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(v.Invalid, "admission-model-" + reason):
                admission.frames(pack(changed) + b"\n", configured()["package"])
        changed = json.loads(raw)
        changed["Output"] = "ADMISSION-MODEL " + changed["Output"]
        with self.assertRaisesRegex(v.Invalid, "admission-model-marker"):
            admission.frames(pack(changed) + b"\n", configured()["package"])
        changed = json.loads(raw)
        changed["Output"] = changed["Output"].rstrip("\n")
        with self.assertRaisesRegex(v.Invalid, "admission-model-truncated"):
            admission.frames(pack(changed) + b"\n", configured()["package"])
        for item in ({"kind": "unknown", "value": {}}, {"kind": [], "value": {}}, {"kind": "retry"}, {"kind": "retry", "value": {}, "other": 1}):
            changed = json.loads(raw)
            changed["Output"] = "ADMISSION-MODEL " + pack(item).decode() + "\n"
            with self.subTest(item=item), self.assertRaisesRegex(v.Invalid, "admission-model-shape"):
                admission.frames(pack(changed) + b"\n", configured()["package"])
        with self.assertRaisesRegex(v.Invalid, "admission-model-row-budget"):
            admission.frames(raw * 595, configured()["package"])

    def test_source(self) -> None:
        """Changed modeled source, protocol fields or newly owned production files invalidate the frozen domain."""
        check, raw = configured(), encode(sample())
        self.assertEqual(models.observations(raw, check, ROOT)["ADMISSION-NODE-TRANSITIONS"], 39417)
        selected = {**admission.SOURCES, **admission.MATERIAL}
        self.assertEqual(admission.scope(ROOT), selected)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for relative in selected:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / relative).read_bytes())
            for relative in selected:
                path = root / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.subTest(source=relative), self.assertRaisesRegex(v.Invalid, "admission-model-source"):
                    admission.observations(raw, check, root)
                path.write_bytes(original)
            for relative in admission.MATERIAL:
                if relative.endswith("identity.go"):
                    continue
                path = root / relative
                original = path.read_bytes()
                path.unlink()
                with self.subTest(missing=relative), self.assertRaisesRegex(v.Invalid, "admission-model-source-scope"):
                    admission.observations(raw, check, root)
                path.write_bytes(original)
            # The current load body cannot borrow the legacy scope by omitting both acquisition adapters.
            for relative in admission.MATERIAL:
                if not relative.endswith("identity.go"):
                    (root / relative).unlink()
            with self.assertRaisesRegex(v.Invalid, "admission-model-source"):
                admission.observations(raw, check, root)
            identity = root / "internal/admission/identity.go"
            identity.write_bytes((ROOT / "tests/fixtures/admission-identity.go.in").read_bytes())
            self.assertEqual(admission.scope(root), admission.SOURCES)
            self.assertEqual(admission.observations(raw, check, root)["ADMISSION-NODE-TRANSITIONS"], 39417)
            for relative in admission.MATERIAL:
                if not relative.endswith("identity.go"):
                    (root / relative).write_bytes((ROOT / relative).read_bytes())
            with self.assertRaisesRegex(v.Invalid, "admission-model-source"):
                admission.observations(raw, check, root)
            identity.write_bytes((ROOT / "internal/admission/identity.go").read_bytes())
            extra = root / "internal/admission/extra.go"
            extra.write_text("package admission\n")
            with self.assertRaisesRegex(v.Invalid, "admission-model-source-scope"):
                admission.observations(raw, check, root)

    def test_revisions(self) -> None:
        """Bind compatibility to the exact cancellation-only edit; unrelated bytes cannot inherit either version."""
        relative = "internal/admission/node.go"
        latest = (ROOT / relative).read_bytes()
        after = (
            b"\t\tif err == nil || fatal(err) {\n\t\t\treturn err\n\t\t}\n"
            b"\t\t// Preserve permanent refusals and completed admission, but expose the owner's cancellation cause.\n"
            b"\t\tif ctx.Err() != nil {\n\t\t\treturn ctx.Err()\n\t\t}"
        )
        before = b"\t\tif err == nil || fatal(err) || ctx.Err() != nil {\n\t\t\treturn err\n\t\t}"
        self.assertEqual(latest.count(after), 1)
        original = latest.replace(after, before)
        self.assertEqual(v.digest(original), admission.SOURCES[relative])
        self.assertEqual(v.digest(latest), admission.NODE)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / relative
            path.parent.mkdir(parents=True)
            for value in (original, latest):
                path.write_bytes(value)
                self.assertTrue(admission.matches(root, relative))
                path.write_bytes(value + b"\n")
                self.assertFalse(admission.matches(root, relative))

    def test_gate(self) -> None:
        """Positive summary markers and complete native-shaped cases cannot stand in for missing model histories."""
        check = configured()
        events = [{"Package": check["package"], "Action": "start"}]
        for test in check["expected_tests"]:
            events.append({"Package": check["package"], "Action": "run", "Test": test})
            for probe in check["probes"]:
                if probe["test"] == test:
                    events.append(
                        {
                            "Package": check["package"],
                            "Action": "output",
                            "Test": test,
                            "Output": "ASTRA-CONTRACT " + pack({"contract": probe["contract"], "hits": probe["minimum_hits"]}).decode() + "\n",
                        }
                    )
            events.append({"Package": check["package"], "Action": "pass", "Test": test})
        events.append({"Package": check["package"], "Action": "pass"})
        raw = b"".join(pack(event) + b"\n" for event in events)
        self.assertEqual(v.go_observations(raw, check)[1], [])
        with self.assertRaisesRegex(v.Invalid, "admission-model-domain"):
            v.parse_observations(raw, check, ROOT)
        config = v.decode(v.read(ROOT / "development.json"))
        obligations = v.expand(config)
        parent = "admission/DEV-MODEL/ADMISSION-ASSURANCE/linux-amd64-cgo/finite-model"
        item = obligations[parent]
        self.assertEqual(item["checks"], ["admission-model"])
        self.assertEqual(
            item["requires"],
            [
                {"rule": "DEV-MODEL", "contract": "ADMISSION-FINITE", "scenario": "two-principal-finite"},
                {"rule": "DEV-CONTRACT", "contract": "ADMISSION-SCHEDULE", "scenario": "two-operation-linearization"},
                {"rule": "DEV-MODEL", "contract": "ADMISSION-NODE-FINITE", "scenario": "loop-state-domain"},
                {"rule": "DEV-MODEL", "contract": "ADMISSION-NODE-TRANSITIONS", "scenario": "publication-state-domain"},
            ],
        )
        # Synthetic policy states test composition only; they are never persisted as native evidence.
        passed = {("admission-model", "linux-amd64-cgo", contract): "passed" for contract in admission.PROBES}
        now = dt.datetime.now(dt.timezone.utc)
        result = v.decide(config, passed, [], [], now)
        self.assertIn(parent, result["passed"])
        self.assertIn("admission/DEV-MODEL/ADMISSION-ASSURANCE/linux-amd64-cgo/full-rule", result["missing"])
        self.assertEqual(result["status"], "blocked")
        for key in passed:
            changed = dict(passed)
            del changed[key]
            with self.subTest(contract=key[2]):
                self.assertIn(parent, v.decide(config, changed, [], [], now)["missing"])

    def test_full_model(self) -> None:
        """Complete model qualification requires each finite domain, native complement and independent sensitivity result."""
        config = v.decode(v.read(ROOT / "development.json"))
        obligations = v.expand(config)
        parent = "admission/DEV-MODEL/ADMISSION-ASSURANCE/linux-amd64-cgo/full-rule"
        item = obligations[parent]
        self.assertIs(item["aggregate"], True)
        self.assertEqual(item["checks"], [])
        self.assertEqual(
            {(r["rule"], r["contract"], r["scenario"]) for r in item["requires"]},
            {
                ("DEV-MODEL", "ADMISSION-ASSURANCE", "finite-model"),
                ("DEV-NUMERIC", "ADMISSION-ASSURANCE", "full-rule"),
                ("DEV-CORE", "ADMISSION-OWNERSHIP", "message-ownership"),
                ("DEV-ASYNC", "ADMISSION-NODE-SCHEDULE", "admission-overlap"),
                ("DEV-MATRIX", "ADMISSION-NODE-TRANSPORT", "tls-generated-rpc"),
                ("DEV-ASYNC", "ADMISSION-NODE-DRAIN", "native-cancellation"),
                ("DEV-ORACLE", "ADMISSION-DRAIN-SENSITIVITY", "cancellation-mutations"),
                ("DEV-ORACLE", "ADMISSION-NODE-SENSITIVITY", "targeted-mutations"),
                ("DEV-COVERAGE", "ADMISSION-SAME", "member-equality"),
                ("DEV-ORACLE", "ADMISSION-SAME-SENSITIVITY", "member-equality-mutations"),
                ("DEV-CONTRACT", "ADMISSION-CONFLICTS", "identity-conflicts"),
                ("DEV-SECURITY", "ADMISSION-CREDENTIALS", "signed-boundaries"),
                ("DEV-ORACLE", "ADMISSION-CONFLICT-SENSITIVITY", "directory-boundary-mutations"),
            },
        )
        _, required = v.dependency_order(obligations)
        pending, closure = [parent], set()
        while pending:
            key = pending.pop()
            if key not in closure:
                closure.add(key)
                pending.extend(required[key])
        observed = {(check, obligations[key]["platform"], obligations[key]["contract"]): "passed" for key in closure for check in obligations[key]["checks"]}
        now = dt.datetime.now(dt.timezone.utc)
        result = v.decide(config, observed, [], [], now)
        self.assertIn(parent, result["passed"])
        self.assertEqual(result["status"], "blocked")
        for key in observed:
            altered = dict(observed)
            del altered[key]
            with self.subTest(contract=key[2]):
                self.assertIn(parent, v.decide(config, altered, [], [], now)["missing"])
