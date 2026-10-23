"""Challenge the current Server evidence's reversible scope, guarded pairs and historical separation."""

from pathlib import Path
import tempfile
import unittest

from tools import authority, consumers, idle, ingress, installation, server, structure, verify as v

ROOT = Path(__file__).resolve().parents[1]


class IngressTests(unittest.TestCase):
    """Reject source drift and missing native witnesses without executing an application or fabricating its evidence."""

    def test_offsets(self) -> None:
        """Every moved authority predicate retains the same text at its reversible current offset."""
        current = v.read(ROOT / installation.PATH)
        original, inserted = ingress.previous(current)
        self.assertEqual(v.digest(original), installation.ORIGINAL)
        self.assertEqual(len(inserted), 2)
        for name, offset, text in authority.GUARDS.values():
            if name == "authority.go":
                fragment = text.encode()
                mapped = ingress.shifted(offset, inserted)
                self.assertEqual(original[offset : offset + len(fragment)], fragment)
                self.assertEqual(current[mapped : mapped + len(fragment)], fragment)
        self.assertEqual(ingress.shifted(0, inserted), 0)

    def test_source(self) -> None:
        """An extra edit or altered batch admission rule cannot be absorbed into the reviewed delta."""
        current = v.read(ROOT / installation.PATH)
        for data in (b"", current + b"\n", current.replace(b'change.Key == ""', b'change.Key != ""', 1)):
            with self.subTest(sha=v.digest(data)), self.assertRaisesRegex(v.Invalid, "ingress-current-source"):
                ingress.previous(data)

    def test_authentication(self) -> None:
        """Only the exact loading revision carries the unchanged runtime authentication assumption."""
        before, after = (v.read(ROOT / name) for name in ("tests/fixtures/admission-identity.go.in", "internal/admission/identity.go"))
        self.assertEqual(len(server.authentication(before, after)), 64)
        for old, new in ((before + b"\n", after), (before, after + b"\n"), (after, before)):
            with self.subTest(old=v.digest(old)), self.assertRaisesRegex(v.Invalid, "server-identity-source"):
                server.authentication(old, new)

    def test_nil(self) -> None:
        """Missing short-circuit operands are undefined, and a skipped Key can never become an executed hit."""
        guard = {
            "text": 'change == nil || change.Key == ""',
            "atoms": [{"text": "change == nil"}, {"text": 'change.Key == ""'}],
            "tree": [{"kind": "atom", "atom": 0}, {"kind": "atom", "atom": 1}, {"kind": "or", "children": [0, 1]}],
            "root": 2,
        }
        valid = {("11", False), ("20", True)}
        proof = ingress.nil_pair(guard, valid)
        self.assertIsNone(proof["witness"]["after"][1])
        self.assertEqual(proof["witness"]["native_vectors"], [("11", False), ("20", True)])
        for observed in (set(), {("11", False)}, {("20", True)}, {("11", False), ("21", True)}, {("12", True), ("20", True)}):
            with self.subTest(observed=observed), self.assertRaisesRegex(v.Invalid, "ingress-nil-native-pair"):
                ingress.nil_pair(guard, observed)
        with self.assertRaisesRegex(v.Invalid, "ingress-nil-guard"):
            ingress.nil_pair({**guard, "text": "true"}, valid)

    def test_versions(self) -> None:
        """Current native counts do not replace the historical source's frozen denominator or evidence catalog."""
        original, _ = ingress.previous(v.read(ROOT / installation.PATH))
        self.assertEqual(server.artifacts(ROOT), consumers.ACQUISITION)
        self.assertEqual(ingress.archives(ROOT), consumers.ACQUISITION)
        self.assertNotIn(ingress.ARTIFACT, ingress.MAINTENANCE)
        self.assertEqual(structure.revision(ROOT, structure.SERVER)["counts"], [659, 329, 430, 95])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / installation.PATH
            path.parent.mkdir(parents=True)
            path.write_bytes(original)
            self.assertEqual(server.artifacts(root), server.ARTIFACTS)
            self.assertEqual(structure.revision(root, structure.SERVER)["counts"], [648, 325, 424, 93])
            path.write_bytes(v.read(ROOT / installation.PATH))
            self.assertEqual(server.artifacts(root), {ingress.ARTIFACT: ingress.ARCHIVE})
            for name in idle.SOURCES:
                dependency = root / name
                dependency.parent.mkdir(parents=True, exist_ok=True)
                dependency.write_bytes(v.read(ROOT / name))
            self.assertEqual(server.artifacts(root), ingress.MAINTENANCE)
            backup = root / idle.BACKUP_FILE
            backup.write_bytes(v.read(ROOT / idle.BACKUP_FILE))
            for name in ("development.json", "go.mod"):
                (root / name).write_bytes(v.read(ROOT / name))
            self.assertEqual(server.artifacts(root), consumers.ACQUISITION)
            backup.unlink()
            self.assertEqual(server.artifacts(root), ingress.MAINTENANCE)
            for name in idle.SOURCES:
                dependency = root / name
                dependency.write_bytes(v.read(ROOT / name) + b"changed")
                with self.subTest(dependency=name):
                    self.assertEqual(server.artifacts(root), {ingress.ARTIFACT: ingress.ARCHIVE})
                dependency.write_bytes(v.read(ROOT / name))

    def test_archives(self) -> None:
        """A named or hash-mismatched report cannot substitute for the pinned native archive."""
        for artifacts in ({}, {ingress.ARTIFACT: b"{}"}, {ingress.ARTIFACT: b"{}", "extra": b"{}"}, {name: b"{}" for name in ingress.MAINTENANCE}):
            with self.subTest(keys=list(artifacts)), self.assertRaisesRegex(v.Invalid, "ingress-archive"):
                ingress.reconcile(ROOT, artifacts)
        with self.assertRaisesRegex(v.Invalid, "consumers-archive-integrity"):
            consumers.unpack(b"{}", "0" * 64)
