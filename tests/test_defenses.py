"""Attack conditional defense accounting with synthetic counters, dependency fixtures and source drift."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import admission, defenses, profileweights, verify as v

ROOT = Path(__file__).resolve().parents[1]
# The reviewed compiler geometry has normalized synthetic hits; this fixture is never native evidence.
PROFILE = (ROOT / "tests/fixtures/admission.cover").read_bytes()
DEPENDENCIES = {name: ("synthetic dependency: " + name).encode() for name in defenses.DEPENDENCIES}


def populate(root: Path) -> None:
    """Pair historical compiler counters with their exact historical identity implementation."""
    for name in admission.SOURCES:
        source = ROOT / ("tests/fixtures/admission-identity.go.in" if name == "internal/admission/identity.go" else name)
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())


def reconcile(parent: bytes = PROFILE, child: bytes = PROFILE, root: Path | None = None) -> dict:
    """Test reconciliation independently of installed toolchains; real collection must supply the pinned source bytes."""
    if root is None:
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory)
            populate(selected)
            return reconcile(parent, child, selected)
    with patch.object(defenses, "DEPENDENCIES", {name: v.digest(data) for name, data in DEPENDENCIES.items()}):
        return defenses.reconcile(parent, child, root, DEPENDENCIES)


class DefenseTests(unittest.TestCase):
    """Unexecuted defenses retain zero hits, and assumptions never silently absorb a new uncovered block."""

    def test_accounting(self) -> None:
        """Keep raw and conditional denominators separate, without issuing branch, MC/DC or gate qualification."""
        result = reconcile()
        self.assertEqual(result["status"], "explained")
        self.assertEqual(result["qualification"], "not-evaluated")
        self.assertEqual(result["raw"], {"blocks": 205, "statements": 282, "statements_hit": 279})
        self.assertEqual(result["reachable_under_assumptions"], {"statements": 279, "statements_hit": 279})
        self.assertEqual(
            [(b["file"], b["span"], b["count"]) for b in result["unhit"]],
            [
                ("internal/admission/identity.go", [83, 3, 84, 1], 0),
                ("internal/admission/node.go", [47, 3, 48, 1], 0),
                ("internal/admission/node.go", [51, 3, 52, 1], 0),
            ],
        )
        self.assertEqual(result["unexplained"], [])
        self.assertEqual([d["id"] for d in result["defenses"]], ["parsed-leaf", "validated-directory", "random-return"])
        self.assertTrue(all(d["assumption"] and d["invalidated_by"] for d in result["defenses"]))
        self.assertEqual(result["sources"], {**admission.SOURCES, "internal/admission/node.go": admission.NODE})
        self.assertEqual(result["profiles"], [{"bytes": len(PROFILE), "sha256": v.digest(PROFILE)}] * 2)

    def test_acquisition(self) -> None:
        """New geometry includes acquisition errors, binds the inactive fallback and preserves every zero-hit defense."""
        data = (ROOT / "tests/fixtures/admission-acquisition.cover").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in {**admission.SOURCES, **admission.MATERIAL}:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / name).read_bytes())
            with patch.object(defenses, "DEPENDENCIES", {name: v.digest(raw) for name, raw in DEPENDENCIES.items()}):
                result = defenses.reconcile(data, data, root, DEPENDENCIES, acquisition=True)
                self.assertEqual(result["raw"], {"blocks": 209, "statements": 289, "statements_hit": 286})
                self.assertEqual(result["status"], "explained")
                self.assertEqual(result["qualification"], "not-evaluated")
                self.assertEqual(result["unexplained"], [])
                self.assertEqual(result["defenses"][0]["span"], [89, 3, 90, 1])
                self.assertIn("internal/admission/file_other.go", result["sources"])
                self.assertNotIn("internal/admission/file_other.go", defenses.sources(root, acquisition=True))
                for parent, child in ((PROFILE, data), (data, PROFILE)):
                    # Historical spans can already be invalid in the current file before shape reconciliation.
                    with self.assertRaisesRegex(v.Invalid, "go-profile-position|defense-profile-denominator"):
                        defenses.reconcile(parent, child, root, DEPENDENCIES, acquisition=True)
                reweighted = data.replace(b"31.2,31.121 1 1", b"31.2,31.121 2 1")
                self.assertNotEqual(reweighted, data)
                with self.assertRaisesRegex(v.Invalid, "defense-profile-denominator"):
                    defenses.reconcile(reweighted, data, root, DEPENDENCIES, acquisition=True)
                missed = data.replace(b"31.2,31.121 1 1", b"31.2,31.121 1 0")
                self.assertNotEqual(missed, data)
                result = defenses.reconcile(missed, missed, root, DEPENDENCIES, acquisition=True)
                self.assertEqual(result["status"], "incomplete")
                self.assertEqual(result["raw"]["statements_hit"], 285)
                forged = data.replace(b"identity.go:89.3,90.1 1 0", b"identity.go:89.3,90.1 1 1")
                self.assertNotEqual(forged, data)
                with self.assertRaisesRegex(v.Invalid, "defense-assumption-contradicted"):
                    defenses.reconcile(forged, data, root, DEPENDENCIES, acquisition=True)
                fixture = root / profileweights.ADMISSION_FIXTURE
                fixture.parent.mkdir(parents=True, exist_ok=True)
                fixture.write_bytes(v.read(ROOT / profileweights.ADMISSION_FIXTURE))
                model = v.decode(fixture.read_bytes())["packages"]["internal/admission"]["blocks"]
                # Independently derived model weights with synthetic hits exercise accounting only.
                current = b"mode: set\n" + b"".join(
                    (
                        "github.com/eosforge/astra/"
                        + block["file"]
                        + ":%d.%d,%d.%d %d %d\n"
                        % (
                            *block["span"],
                            block["current"],
                            int(
                                (block["file"], tuple(block["span"]))
                                not in {
                                    ("internal/admission/identity.go", (89, 3, 90, 1)),
                                    ("internal/admission/node.go", (47, 3, 48, 1)),
                                    ("internal/admission/node.go", (51, 3, 52, 1)),
                                }
                            ),
                        )
                    ).encode()
                    for block in model
                )
                result = defenses.reconcile(current, current, root, DEPENDENCIES, acquisition=True, compiler="1.27.2")
                self.assertEqual(result["raw"], {"blocks": 209, "statements": 287, "statements_hit": 284})
                self.assertEqual(result["compiler_weights"]["obligations"], {"statements": 289, "statements_hit": 286})
                self.assertEqual(result["reachable_under_assumptions"], {"statements": 284, "statements_hit": 284})
                self.assertEqual(result["unexplained"], [])
                self.assertEqual(result["qualification"], "not-evaluated")
                for compiler in ("1.27.1", "unknown"):
                    with self.subTest(compiler=compiler), self.assertRaises(v.Invalid):
                        defenses.reconcile(current, current, root, DEPENDENCIES, acquisition=True, compiler=compiler)
                with self.assertRaisesRegex(v.Invalid, "profile-weights-geometry"):
                    defenses.reconcile(data, current, root, DEPENDENCIES, acquisition=True, compiler="1.27.2")
                fixture.write_bytes(fixture.read_bytes() + b"\n")
                with self.assertRaisesRegex(v.Invalid, "profile-weights-model"):
                    defenses.reconcile(current, current, root, DEPENDENCIES, acquisition=True, compiler="1.27.2")
            for name in admission.MATERIAL:
                path = root / name
                original = path.read_bytes()
                path.write_bytes(original + b"// changed source\n")
                with self.assertRaisesRegex(v.Invalid, "defense-source-drift"):
                    defenses.sources(root, acquisition=True)
                path.unlink()
                with self.assertRaisesRegex(v.Invalid, "defense-source-scope"):
                    defenses.sources(root, acquisition=True)
                path.write_bytes(original)

    def test_revisions(self) -> None:
        """Bind each compiler geometry to its exact source; historical counters cannot qualify the repaired branch."""
        old = (ROOT / "tests/fixtures/admission-legacy.cover").read_bytes()
        with self.assertRaises(v.Invalid):
            reconcile(old, old)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            populate(root)
            path = root / "internal/admission/node.go"
            current = path.read_bytes()
            removed = b"\n\t\t// Preserve permanent refusals and completed admission, but expose the owner's cancellation cause.\n\t\tif ctx.Err() != nil {\n\t\t\treturn ctx.Err()\n\t\t}"
            self.assertEqual(current.count(removed), 1)
            original = current.replace(removed, b"").replace(b"if err == nil || fatal(err) {", b"if err == nil || fatal(err) || ctx.Err() != nil {", 1)
            self.assertEqual(v.digest(original), admission.SOURCES["internal/admission/node.go"])
            path.write_bytes(original)
            result = reconcile(old, old, root)
            self.assertEqual(result["raw"], {"blocks": 203, "statements": 280, "statements_hit": 277})
            self.assertEqual(result["sources"], admission.SOURCES)
            with self.assertRaises(v.Invalid):
                reconcile(PROFILE, PROFILE, root)
            with self.assertRaises(v.Invalid):
                reconcile(old, PROFILE, root)

    def test_denominator(self) -> None:
        """Missing, repeated, moved or reweighted native blocks invalidate the fixed geometry on either side."""
        lines = PROFILE.splitlines(keepends=True)
        changes = [
            b"".join(lines[:-1]),
            PROFILE + lines[1],
            PROFILE.replace(b"31.2,31.121 1 1", b"31.2,31.121 2 1"),
            PROFILE.replace(b"mode: set", b"mode: count"),
            PROFILE.replace(b"31.2,31.121", b"31.3,31.121"),
        ]
        for data in changes:
            self.assertNotEqual(data, PROFILE)
            for parent, child in ((data, PROFILE), (PROFILE, data)):
                with self.assertRaises(v.Invalid):
                    reconcile(parent, child)

    def test_unexplained(self) -> None:
        """A newly missed reachable statement cannot inherit an existing defense's source justification."""
        data = PROFILE.replace(b"31.2,31.121 1 1", b"31.2,31.121 1 0")
        self.assertNotEqual(data, PROFILE)
        result = reconcile(data, data)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["raw"]["statements_hit"], 278)
        self.assertEqual(result["reachable_under_assumptions"], {"statements": 279, "statements_hit": 278})
        self.assertEqual(len(result["unhit"]), 4)
        self.assertEqual(result["unexplained"], [{"file": "internal/admission/directory.go", "span": [31, 2, 31, 121], "statements": 1, "count": 0}])
        for name, span in (("identity.go", "83.3,84.1"), ("node.go", "47.3,48.1"), ("node.go", "51.3,52.1")):
            anchor = (name + ":" + span + " 1 0").encode()
            changed = PROFILE.replace(anchor, anchor[:-1] + b"1")
            self.assertNotEqual(changed, PROFILE)
            with self.assertRaisesRegex(v.Invalid, "defense-assumption-contradicted"):
                reconcile(changed, PROFILE)

    def test_union(self) -> None:
        """Matching parent/child modes allow union, while atomic event totals never inflate statement coverage."""
        parent = PROFILE.replace(b"31.2,31.121 1 1", b"31.2,31.121 1 0")
        child = b"\n".join([b"mode: set"] + [line.rsplit(b" ", 1)[0] + b" 0" for line in PROFILE.splitlines()[1:]]) + b"\n"
        child = child.replace(b"31.2,31.121 1 0", b"31.2,31.121 1 1")
        self.assertEqual(reconcile(parent, child)["raw"], {"blocks": 205, "statements": 282, "statements_hit": 279})
        atomic = PROFILE.replace(b"mode: set", b"mode: atomic")
        atomic = b"\n".join([b"mode: atomic"] + [line[:-1] + b"999" if line.endswith(b" 1") else line for line in atomic.splitlines()[1:]]) + b"\n"
        self.assertEqual(reconcile(atomic, atomic)["raw"]["statements_hit"], 279)
        with self.assertRaisesRegex(v.Invalid, "defense-profile-mode"):
            reconcile(PROFILE, atomic)

    def test_dependencies(self) -> None:
        """Only exact dependency bytes with the complete expected inventory may support conditional reasoning."""
        expected = {name: v.digest(data) for name, data in DEPENDENCIES.items()}
        with patch.object(defenses, "DEPENDENCIES", expected):
            self.assertEqual(defenses.dependencies(DEPENDENCIES), {name: {"bytes": len(data), "sha256": expected[name]} for name, data in DEPENDENCIES.items()})
            for name in DEPENDENCIES:
                for value in (DEPENDENCIES[name] + b"changed", DEPENDENCIES[name][:-1], "not bytes"):
                    with self.assertRaisesRegex(v.Invalid, "defense-dependency-drift"):
                        defenses.dependencies({**DEPENDENCIES, name: value})
                with self.assertRaisesRegex(v.Invalid, "defense-dependency-scope"):
                    defenses.dependencies({key: data for key, data in DEPENDENCIES.items() if key != name})
            with self.assertRaisesRegex(v.Invalid, "defense-dependency-scope"):
                defenses.dependencies({**DEPENDENCIES, "other.go": b"extra"})

    def test_sources(self) -> None:
        """A changed guard, representation or unlisted production file invalidates the entire source argument."""
        with self.assertRaisesRegex(v.Invalid, "defense-source-scope"):
            defenses.sources(ROOT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            populate(root)
            self.assertEqual(set(defenses.sources(root)), {"internal/admission/node.go", "internal/admission/directory.go", "internal/admission/identity.go"})
            for name in admission.SOURCES:
                target = root / name
                original = target.read_bytes()
                target.write_bytes(original + b"// changed assumption\n")
                with self.assertRaisesRegex(v.Invalid, "defense-source-drift"):
                    defenses.sources(root)
                target.write_bytes(original)
            (root / "internal/admission/extra.go").write_text("package admission\n", encoding="utf-8")
            with self.assertRaisesRegex(v.Invalid, "defense-source-scope"):
                defenses.sources(root)
