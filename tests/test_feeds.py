"""Challenge pure feed witnesses with synthetic masks; these unit fixtures provide no native Storage credit."""

import copy
from pathlib import Path
import unittest
from unittest.mock import patch

from tools import storage, storage_numeric as numeric, verify as v

ROOT = Path(__file__).resolve().parents[1]


class FeedsTests(unittest.TestCase):
    """Require complete inputs, exact source predicates and both native mask shapes for each independent effect."""

    def setUp(self) -> None:
        """Load explicitly synthetic decision vectors and the independent fixed numeric corpus."""
        fixture = v.decode(v.read(ROOT / "tests/fixtures/storage-feeds.json"))
        self.decisions = fixture["decisions"]
        self.native = {key: [(values, result) for values, result in rows] for key, rows in fixture["vectors"].items()}
        self.rows = numeric.expected(ROOT)

    def receive(self, rows: list[dict] | None = None, *, decisions: dict | None = None, native: dict | None = None) -> list[dict]:
        """Exercise witness reconstruction separately from the already tested native log parser."""
        with (
            patch.object(storage.logic, "inventory", return_value=self.decisions if decisions is None else decisions),
            patch.object(storage.logic, "observe", return_value=(self.native if native is None else native, {})),
        ):
            return storage.feeds(ROOT, {}, b"", self.rows if rows is None else rows)

    def test_pairs(self) -> None:
        """Public admission and bounded queue growth supply four specified distinct single-condition effects."""
        pairs = self.receive()
        expected = {(numeric.DIRECTORY + "/feed.go:1615", index) for index in range(3)} | {(numeric.DIRECTORY + "/feed.go:4062", 0)}
        self.assertEqual({(row["decision"], row["condition"]) for row in pairs}, expected)
        self.assertEqual(len(pairs), 4)
        for row in pairs:
            self.assertNotEqual(row["before"]["result"], row["after"]["result"])
            self.assertEqual(row["criterion"], "total-input-single-condition-v1")
            self.assertEqual(row["inputs_sha256"], v.digest(v.encode(self.rows)))
            self.assertTrue(row["input_rows"]["before"] and row["input_rows"]["after"])
        queue = next(row for row in pairs if row["decision"].endswith("4062"))
        for side in ("before", "after"):
            self.assertFalse(queue[side]["values"][1], "Item-count witnesses must hold byte pressure false on both sides.")

    def test_inputs(self) -> None:
        """Changed, partial, reordered or type-confused actual histories must never inherit an old proof."""
        for index, row in enumerate(self.rows):
            changed = copy.deepcopy(self.rows)
            changed[index]["unreported"] = 1
            with self.subTest(index=index), self.assertRaisesRegex(v.Invalid, "storage-feed-fixture-inputs"):
                self.receive(changed)
        for changed in ([], self.rows[:-1], list(reversed(self.rows)), self.rows + [self.rows[-1]]):
            with self.subTest(length=len(changed)), self.assertRaisesRegex(v.Invalid, "storage-feed-fixture-inputs"):
                self.receive(changed)
        index = next(index for index, row in enumerate(self.rows) if row["kind"] == "subscription" and row["limit"] == 1)
        for value in (True, 1.0, "1", None):
            changed = copy.deepcopy(self.rows)
            changed[index]["limit"] = value
            with self.subTest(value=value), self.assertRaisesRegex(v.Invalid, "storage-feed-fixture-inputs"):
                self.receive(changed)
        index = next(
            index for index, row in enumerate(self.rows) if row["kind"] == "feed-cost" and row["limit"] == 262 and row["items"] == 1 and row["step"] == 1
        )
        for field, value in (("bytes", 0), ("queued", 0), ("refused", True)):
            changed = copy.deepcopy(self.rows)
            changed[index][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "storage-feed-fixture-inputs"):
                self.receive(changed)

    def test_masks(self) -> None:
        """A valid input corpus cannot replace missing reached predicates or fabricate either observed side."""
        pairs = self.receive()
        for identity in self.native:
            with self.subTest(identity=identity), self.assertRaises(v.Invalid):
                self.receive(native={**self.native, identity: []})
            used = {(side["values"], side["result"]) for row in pairs if row["decision"] == identity for side in row["native_vectors"]}
            self.assertTrue(used)
            for values in used:
                changed = {**self.native, identity: [value for value in self.native[identity] if value != values]}
                with self.subTest(identity=identity, values=values), self.assertRaises(v.Invalid):
                    self.receive(native=changed)

    def test_sources(self) -> None:
        """Neither a changed pinned fixture nor a same-ID predicate replacement may qualify original witnesses."""
        with patch.object(storage.v, "file_digest", return_value="0" * 64), self.assertRaisesRegex(v.Invalid, "storage-feed-fixture-inputs"):
            self.receive()
        for identity in self.decisions:
            changed = copy.deepcopy(self.decisions)
            changed[identity]["text"] += " || true"
            with self.subTest(identity=identity), self.assertRaisesRegex(v.Invalid, "storage-feed-source-decision"):
                self.receive(decisions=changed)
            with self.subTest(identity=identity), self.assertRaisesRegex(v.Invalid, "storage-feed-source-decision"):
                self.receive(decisions={key: value for key, value in self.decisions.items() if key != identity})


if __name__ == "__main__":
    unittest.main()
