"""Challenge finite-model parsing and independent format axioms; synthetic streams are never product evidence."""

import base64
import copy
import datetime as dt
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from tools import almanac, catalog, comet, command, ephemeris, ledger, models, projection, store
from tools import verify as v

ROOT = Path(__file__).resolve().parents[1]


def check() -> dict:
    """Read the actual registered model command without inventing a reduced acceptance policy."""
    config = v.decode(v.read(ROOT / "development.json"))
    return next(item for item in config["checks"] if item["id"] == "storage-examples")


def output(name: str, text: str) -> bytes:
    """Encode one synthetic Output fragment solely for parser boundary tests."""
    return json.dumps({"Action": "output", "Test": name, "Output": text}, separators=(",", ":")).encode() + b"\n"


def cpp_output(text: str, hits: int = 1, name: str = "cpp_store_model", tests: dict[str, int] | None = None) -> bytes:
    """Encode synthetic parser-only XML and terminals; this helper never executes or certifies C++ code."""
    suite = ET.Element("testsuite")
    counts = {name: hits} if tests is None else {**tests, name: hits}
    events = [{"event": "start", "engine": "ctest"}]
    for test, count in counts.items():
        case = ET.SubElement(suite, "testcase", name=test)
        ET.SubElement(case, "system-out").text = (text if test == name else "") + "ASTRA-CHECKS " + json.dumps({"hits": count}) + "\n"
        events += [{"event": "begin", "test": test}, {"event": "end", "test": test, "status": "passed", "hits": count}]
    xml = ET.tostring(suite, encoding="unicode")
    events.append({"event": "complete", "cases": len(counts)})
    encode = lambda event: b"ASTRA-OBSERVE " + json.dumps(event).encode() + b"\n"
    return encode(events[0]) + b"ASTRA-CTEST " + json.dumps(xml).encode() + b"\n" + b"".join(encode(event) for event in events[1:])


class ModelTests(unittest.TestCase):
    """Anchor the independent model and reject absent, malformed or falsely attributed observations."""

    def test_vectors(self) -> None:
        """Match all nine request encodings to literal AB02 specification vectors, independently of Go."""
        # Literal page-stream commitments distinguish complete publication, private pages and retained roots.
        empty = [1, "star-model", "routes", "main", "", "ready", False, 0, []]
        complete = [2, "star-model", "routes", "main", "", "ready", False, 2, [["a", "A"], ["b", "B"]]]
        value, hits = projection.trace([3, 6, 5, 4], 0)
        self.assertEqual(value["initial"], empty)
        self.assertEqual(hits, 167)
        self.assertEqual(
            value["states"][0], {"operation": 3, "receipts": [["partial", empty], ["complete", complete]], "current": complete, "retained": [empty]}
        )
        self.assertEqual([state["current"] for state in value["states"]], [complete] * 4)
        self.assertEqual(
            [[receipt[0] for receipt in state["receipts"]] for state in value["states"]],
            [["partial", "complete"], ["partial", "protocol"], ["version"], ["partial"]],
        )
        self.assertEqual(value["states"][-1]["retained"], [empty, complete, complete, complete])
        self.assertEqual(projection.trace([0, 0, 0, 0], 0)[1], 113)
        expected = (
            "4142303200000000000000010001000000000061",
            "414230320000000000000001000100000001006101",
            "4142303200000000000000010001000000000062",
            "414230320000000000000001000100000001006201",
            "4142303200000000000000010001000000000161",
            "4142303200000000000000010001000000000162",
            "4142303200000000000000020001000000000061000100000001006201",
            "41423032000000000000000200010000000001610001000000000062",
            "4142303200000000000000020001000000010061010001000000000162",
        )
        self.assertEqual(len(models.ACTIONS), len(expected))
        for action, vector in zip(models.ACTIONS, expected):
            with self.subTest(action=action):
                self.assertEqual(base64.b64decode(models.batch(action), validate=True).hex(), vector)
        for kind, actions, expected in (
            (0, [0], [["string:", 0, 0, 0, False, "", ""]]),
            (1, [0], [["string:", 1, 0, 0, False, "", ""]]),
            (2, [1], [["bool:false", 0, 0, 1, False, "", ""]]),
            (3, [1], [["bool:true", 0, 0, 1, False, "", ""]]),
            (1, [3], [["rejected", 0, 1, 0, True, "", ""]]),
            (1, [4], [["panic", 0, 1, 0, True, "", ""]]),
            (0, [2], [["panic", 0, 0, 0, True, "", ""]]),
            (1, [5], [["ok", 0, 1, 0, True, "", "duplicate option"]]),
            (1, [2, 2], [["ok", 0, 1, 0, True, "", ""], ["duplicate option", 0, 1, 0, True, "", ""]]),
            (3, [1, 2], [["bool:true", 0, 0, 1, False, "", ""], ["ok", 0, 1, 1, True, "\0µ🙂", ""]]),
        ):
            with self.subTest(kind=kind, actions=actions):
                self.assertEqual(command.history(actions, kind), expected)
        # Literal map/log axioms independently anchor same-tick expiry, empty assignment and no-op erase.
        state = store.State()
        state.apply(4)
        self.assertEqual(state.snapshot(), [0, []])
        state.apply(2)
        self.assertEqual(state.snapshot(), [1, [["b", [], None]]])
        state.apply(1)
        state.apply(6)
        self.assertEqual(state.snapshot(), [3, [["a", [2], 1001000000], ["b", [7], 1001000000]]])
        state.apply(7)
        self.assertEqual(state.version, 3)
        state.apply(5)
        self.assertEqual(state.snapshot(), [4, []])
        self.assertEqual(state.floor, 2)
        self.assertEqual(
            state.replay(),
            [
                [0, True, 4, []],
                [1, True, 4, []],
                [2, False, 4, [[3, "b", [7], 1001000000, False], [4, "a", None, None, True], [4, "b", None, None, True]]],
                [3, False, 4, [[4, "a", None, None, True], [4, "b", None, None, True]]],
                [4, False, 4, []],
                [5, True, 4, []],
            ],
        )
        # Literal Member, admission and rollback axioms do not borrow native Identity encoding.
        identity = [
            "alpha",
            "attempt-0",
            "0100000000000000000000000000000000000000000000000000000000000000",
            ["127.0.0.1", 7401, False, False],
            1,
            "star",
            "default",
        ]
        self.assertEqual(ledger.member(0, "attempt-0", 1), identity)
        state = ledger.State(1)
        actual, hits = state.step(0, 0)
        self.assertEqual(hits, 12)
        self.assertEqual(actual["outcome"], "ok")
        self.assertEqual(actual["prepare"], [identity, [[identity[2], identity]]])
        self.assertEqual(actual["credentials"], [[identity, True, [[identity[2], identity]]]])
        self.assertEqual(state.step(1, 1)[0]["outcome"], "capacity")
        self.assertEqual(state.step(2, 2)[0]["outcome"], "ok")
        self.assertEqual(len(state.requests), 1)
        self.assertEqual(state.members, {0: ("attempt-0", 1)})
        for operation, outcome in ((4, "configuration"), (5, "throw"), (6, "reopen")):
            state = ledger.State(2)
            actual, hits = state.step(operation, 0)
            self.assertEqual(actual["outcome"], outcome)
            self.assertEqual(hits, 2 if operation == 6 else 5)
            self.assertEqual((state.members, state.requests, state.first, state.credentials, state.frozen), ({}, {}, [None, None], [], []))
            self.assertEqual(actual["prepared"], operation == 5)
            self.assertEqual(actual["threw"], operation == 5)
        # Authority reset, erase and same-position retry are literal axioms, not native-derived expectations.
        state = almanac.State()
        self.assertEqual(state.snapshot(), [0, 0, 0, []])
        self.assertEqual(state.step(6), "version")
        self.assertIs(state.step(1), True)
        self.assertEqual(state.snapshot(), [1, 1, 1, [["b", []]]])
        self.assertIs(state.step(6), False)
        self.assertIs(state.step(3), True)
        self.assertEqual(state.snapshot(), [2, 1, 2, [["a", [2]]]])
        self.assertEqual(state.replay()[1], [1, [2, [[2, "a", [2]], [2, "b", None]]]])
        self.assertIs(state.step(7), True)
        self.assertEqual(state.snapshot(), [5, 1, 2, [["a", [9]]]])
        self.assertEqual(state.replay(), [[index, "history"] for index in range(5)] + [[5, [5, []]], [6, "version"]])
        self.assertIs(state.step(1), True)
        before = copy.deepcopy(state)
        self.assertEqual(state.step(8), "capacity")
        self.assertEqual(state, before)
        for operation in (4, 5):
            self.assertEqual(state.step(operation), "input" if operation == 4 else "version")
            self.assertEqual(state, before)
        # Literal Catalog lease/floor and atomic recovery axioms do not consult native transitions.
        state = catalog.State()
        self.assertEqual(state.step(2), "ok")
        self.assertEqual(state.snapshot(), [1, [["b", 1, []]]])
        self.assertEqual(state.source(), [1, [["model", "catalog", "b", 1, [], 2_000_000_000]]])
        self.assertEqual(state.step(3), "ok")
        self.assertEqual(state.snapshot(), [3, [["a", 2, [2]], ["b", 2, [2]]]])
        self.assertEqual(state.replay(state.ordered())[2], [2, "history"])
        self.assertTrue(state.log(state.replay(state.ordered())))
        self.assertEqual(state.step(7), "tick")
        self.assertEqual(state.snapshot(), [5, []])
        self.assertEqual(state.source(), [3, [["model", "catalog", "a", 2, None, None], ["model", "catalog", "b", 2, None, None]]])
        self.assertEqual(state.step(5), "ended")
        self.assertEqual(state.step(0), "version")
        before = copy.deepcopy(state)
        self.assertEqual(state.step(8), "input")
        self.assertEqual(state, before)
        self.assertEqual(len(state.exports), 3)
        self.assertEqual(state.exports[0], [1, "model", "catalog", "b", "record", [1, [], 2_000_000_000]])
        # Unordered expiry permits either whole key order, but all suffixes must use that same order.
        ordered = state.ordered()
        ordered[-2][1], ordered[-1][1] = ordered[-1][1], ordered[-2][1]
        replay = copy.deepcopy(state.replay(ordered))
        self.assertTrue(state.log(replay))
        replay[4][1][0][1] = "b" if replay[4][1][0][1] == "a" else "a"
        self.assertFalse(state.log(replay))
        # Fixed registration values and separate sequence/lease axioms are literal, not native state.
        state = ephemeris.State.create()
        self.assertEqual(state.snapshot(), [2, [[0, [3], [1]], [1, [4], [2]]]])
        self.assertEqual(
            state.source(),
            [2, [["model", "ephemeris", 0, [[3], [1], 2_000_000_000, 0, 0, 1000, 1]], ["model", "ephemeris", 1, [[4], [2], 2_000_000_000, 0, 0, 1000, 1]]]],
        )
        # Four outer checks, six live-row checks, then 9/5/1/1 checks for cursors 0/1/2/future.
        self.assertEqual(state.verify_hits([]), 26)
        for operation in (0, 3):
            self.assertEqual(state.step(operation), "ok")
        self.assertEqual((state.cursor, state.position), (2, 4))
        before = copy.deepcopy(state)
        self.assertEqual(state.step(0), "ok")
        self.assertEqual(state, before)
        self.assertEqual(state.step(1), "ok")
        self.assertEqual(state.step(2), "obsolete")
        self.assertEqual(state.snapshot(), [3, [[0, [3], [2]], [1, [4], [2]]]])
        self.assertEqual(state.step(7), "ok")
        self.assertEqual(state.records[0][3:5], (2, 2))
        self.assertEqual(state.step(6), "tick")
        self.assertEqual((state.now, state.position), (1_500_000_000, 6))
        self.assertEqual(state.step(0), "obsolete")
        self.assertEqual(state.step(6), "tick")
        self.assertEqual((state.snapshot(), state.source()), ([5, []], [8, []]))
        self.assertEqual(state.step(8), "ended")
        replay, exported = copy.deepcopy(state.replay(state.ordered())), state.exported()
        self.assertTrue(state.log(replay))
        self.assertTrue(state.export_log(exported, replay))
        self.assertEqual(exported[-2:], [[7, "model", "ephemeris", 0, "erase", None], [8, "model", "ephemeris", 1, "erase", None]])
        # Either expiry order is permitted, but independently valid source/visible orders cannot be mixed.
        ordered = state.ordered()
        ordered[-2][1], ordered[-1][1] = ordered[-1][1], ordered[-2][1]
        reversed_replay = state.replay(ordered)
        self.assertTrue(state.log(reversed_replay))
        self.assertFalse(state.export_log(exported, reversed_replay))
        exported[-2][3], exported[-1][3] = exported[-1][3], exported[-2][3]
        self.assertTrue(state.export_log(exported, reversed_replay))
        for operation, outcome in ((8, "input"), (2, "ok"), (0, "conflict"), (4, "ok"), (5, "ok"), (4, "ended")):
            if operation == 8:
                state = ephemeris.State.create()
            self.assertEqual(state.step(operation), outcome)
        self.assertEqual(state.records[0][1], (2,))

        # Literal SDK ownership/active/retained/weak-lifetime axioms are independent of native Core internals.
        state = comet.State([1, 2])
        self.assertEqual(state.snapshot(), {"core": [1, False, False, [], []], "items": []})
        self.assertEqual(state.step(0, 1), "ok")
        self.assertEqual(state.step(0, 2), "busy")
        self.assertEqual(state.snapshot(), {"core": [2, False, False, [1], [1]], "items": [[1, True, True, False, False], [2, True, False, False, False]]})
        self.assertEqual(state.step(2, 3), "none")
        self.assertEqual(state.step(0, 4), "ok")
        state.step(2, 5)
        self.assertEqual(state.step(0, 6), "busy")
        self.assertEqual(state.snapshot()["core"], [1, False, False, [1, 4], [1, 4]])
        state.step(3, 7)
        self.assertEqual(state.step(0, 8), "ok")
        self.assertEqual(state.snapshot()["core"], [2, False, False, [4, 8], [4, 8]])
        before = copy.deepcopy(state.snapshot())
        state.step(5, 9)
        self.assertEqual(state.snapshot(), before)
        state.step(4, 10)
        self.assertEqual(state.snapshot()["core"], before["core"])
        state.step(4, 11)
        state.step(4, 12)
        self.assertEqual(state.snapshot()["core"], [2, False, False, [0, 8], [0, 8]])
        self.assertEqual(state.step(1, 13), "ok")
        self.assertEqual(state.snapshot()["core"], [3, False, False, [8, 13], [8, 13]])
        state.step(7, 14)
        self.assertEqual(state.owners, 2)
        state.step(7, 15)
        self.assertEqual(state.owners, 2)
        state.step(6, 16)
        self.assertEqual(state.step(0, 17), "closed")
        self.assertEqual(state.snapshot()["core"], [2, True, True, [8, 13], [8, 13]])
        state = comet.State([1, 2])
        state.step(0, 1)
        state.step(7, 2)
        self.assertFalse(state.closing)
        state.step(4, 3)
        self.assertEqual(state.snapshot(), {"core": [0, True, True, [0], [0]], "items": []})
        self.assertEqual(state.step(8, 4), "idle")

    def test_history(self) -> None:
        """Preserve versioned ordered batches, empty values, erasures and the two-batch retention floor."""
        snapshot, history = models.state([(0, 1), (-1, 0), (1, -1)], "finite", 4, retained=2)
        self.assertEqual(snapshot, {"Sector": "finite", "Spectrum": "4", "Version": 3, "Records": [{"Key": "a", "Value": "AQ=="}]})
        self.assertEqual(history["Version"], 3)
        self.assertEqual([item["Version"] for item in history["Changes"]], [2, 3])
        self.assertEqual([item["Key"] for item in history["Changes"]], ["", ""])
        self.assertEqual([item["Erase"] for item in history["Changes"]], [False, False])
        self.assertEqual(
            [base64.b64decode(item["Value"]).hex() for item in history["Changes"]],
            ["41423032000000000000000200010000000001610001000000000062", "4142303200000000000000020001000000010061010001000000000162"],
        )
        state, frozen = almanac.State(), []
        self.assertEqual(almanac.transition(state, frozen, 0)[1], 10)
        self.assertEqual(almanac.transition(state, frozen, 0)[1], 14)
        seed = almanac.initial(0)
        receipts, prefixes = almanac.candidate(seed, [0, 0], (0, 1))
        actual = {
            "ordinal": 0,
            "prefix": 0,
            "operations": [0, 0],
            "initial": [seed.snapshot(), seed.replay()],
            "receipts": receipts,
            "current": prefixes[-1].snapshot(),
            "replay": prefixes[-1].replay(),
            "frozen": [prefixes[0].snapshot()] * 16 + [prefixes[1].snapshot()] * 16 + [prefixes[2].snapshot()] * 32,
        }
        self.assertEqual(actual["receipts"], [True, False])
        self.assertEqual(almanac.pair(actual, 0), 300)
        for field, value in (("ordinal", True), ("operations", [0, 1]), ("receipts", [True, True]), ("replay", []), ("frozen", actual["frozen"][:-1])):
            changed = copy.deepcopy(actual)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(v.Invalid):
                almanac.pair(changed, 0)
        changed = copy.deepcopy(actual)
        changed["frozen"][-1] = prefixes[0].snapshot()
        with self.assertRaisesRegex(v.Invalid, "almanac-model-joint-serialization"):
            almanac.pair(changed, 0)
        # Opposite writer order cannot lend a prefix to the order fixed by these receipts and final root.
        receipts, prefixes = almanac.candidate(seed, [0, 1], (0, 1))
        other = almanac.candidate(seed, [0, 1], (1, 0))[1]
        actual.update(
            ordinal=1,
            operations=[0, 1],
            receipts=receipts,
            current=prefixes[-1].snapshot(),
            replay=prefixes[-1].replay(),
            frozen=[seed.snapshot()] * 32 + [prefixes[-1].snapshot()] * 32,
        )
        self.assertGreater(almanac.pair(actual, 1), 0)
        actual["frozen"][32] = other[1].snapshot()
        with self.assertRaisesRegex(v.Invalid, "almanac-model-joint-serialization"):
            almanac.pair(actual, 1)
        state, frozen = store.State(), []
        first, hits = store.transition(state, frozen, 0)
        self.assertEqual(hits, 10)

        seed = ephemeris.initial(0)
        receipts, prefixes = ephemeris.candidate(seed, [0, 0], (0, 1))
        final = prefixes[-1]
        initial = {"current": seed.snapshot(), "source": seed.source(), "exports": seed.exported(), "replay": seed.replay(seed.ordered()), "frozen": []}
        actual = {
            "ordinal": 0,
            "prefix": 0,
            "operations": [0, 0],
            "created": ephemeris.CREATED,
            "initial": initial,
            "receipts": receipts,
            "current": final.snapshot(),
            "source": final.source(),
            "exports": final.exported(),
            "replay": final.replay(final.ordered()),
            "frozen": [seed.snapshot()] * 32 + [final.snapshot()] * 32,
        }
        self.assertEqual(ephemeris.pair(actual, 0), 418)
        for field, value in (
            ("ordinal", True),
            ("operations", [0, 1]),
            ("created", []),
            ("receipts", ["ok", "conflict"]),
            ("exports", []),
            ("replay", []),
            ("frozen", actual["frozen"][:-1]),
        ):
            changed = copy.deepcopy(actual)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(v.Invalid):
                ephemeris.pair(changed, 0)
        receipts, prefixes = ephemeris.candidate(seed, [0, 2], (0, 1))
        final = prefixes[-1]
        actual.update(
            ordinal=2,
            operations=[0, 2],
            receipts=receipts,
            current=final.snapshot(),
            source=final.source(),
            exports=final.exported(),
            replay=final.replay(final.ordered()),
            frozen=[seed.snapshot()] * 64,
        )
        self.assertGreater(ephemeris.pair(actual, 2), 0)
        actual["frozen"][-1] = ephemeris.candidate(seed, [0, 2], (1, 0))[1][-1].snapshot()
        with self.assertRaisesRegex(v.Invalid, "ephemeris-model-joint-serialization"):
            ephemeris.pair(actual, 2)

        seed = catalog.initial(0)
        receipts, prefixes = catalog.candidate(seed, [0, 0], (0, 1))
        final = prefixes[-1]
        initial = {"current": seed.snapshot(), "source": seed.source(), "exports": seed.exports, "replay": seed.replay(seed.ordered()), "frozen": []}
        actual = {
            "ordinal": 0,
            "prefix": 0,
            "operations": [0, 0],
            "initial": initial,
            "receipts": receipts,
            "current": final.snapshot(),
            "source": final.source(),
            "exports": final.exports,
            "replay": final.replay(final.ordered()),
            "frozen": [seed.snapshot()] * 32 + [final.snapshot()] * 32,
        }
        self.assertEqual(actual["receipts"], ["ok", "ok"])
        self.assertEqual(catalog.pair(actual, 0), 212)
        for field, value in (
            ("ordinal", True),
            ("operations", [0, 1]),
            ("receipts", ["ok", "conflict"]),
            ("exports", []),
            ("replay", []),
            ("frozen", actual["frozen"][:-1]),
        ):
            changed = copy.deepcopy(actual)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(v.Invalid):
                catalog.pair(changed, 0)
        # Conflict receipts fix a single writer order; a root from the opposite winner is inadmissible.
        receipts, prefixes = catalog.candidate(seed, [0, 6], (0, 1))
        final = prefixes[-1]
        actual.update(
            ordinal=6,
            operations=[0, 6],
            receipts=receipts,
            current=final.snapshot(),
            source=final.source(),
            exports=final.exports,
            replay=final.replay(final.ordered()),
            frozen=[seed.snapshot()] * 32 + [final.snapshot()] * 32,
        )
        self.assertGreater(catalog.pair(actual, 6), 0)
        actual["frozen"][-1] = catalog.candidate(seed, [0, 6], (1, 0))[1][-1].snapshot()
        with self.assertRaisesRegex(v.Invalid, "catalog-model-joint-serialization"):
            catalog.pair(actual, 6)
        # Same-version publication/renewal share a final root, but only one order explains exported TTLs.
        seed = catalog.initial(1)
        receipts, prefixes = catalog.candidate(seed, [0, 4], (1, 0))
        forward = catalog.candidate(seed, [0, 4], (0, 1))[1][-1]
        final = prefixes[-1]
        self.assertEqual(final.source(), forward.source())
        self.assertNotEqual(final.exports, forward.exports)
        self.assertEqual(
            final.exports[1:], [[2, "model", "catalog", "a", "renew", [1, [1], 3_000_000_000]], [3, "model", "catalog", "a", "record", [1, [1], 3_000_000_000]]]
        )
        initial = {"current": seed.snapshot(), "source": seed.source(), "exports": seed.exports, "replay": seed.replay(seed.ordered()), "frozen": []}
        actual.update(
            ordinal=68,
            prefix=1,
            operations=[0, 4],
            initial=initial,
            receipts=receipts,
            current=final.snapshot(),
            source=final.source(),
            exports=final.exports,
            replay=final.replay(final.ordered()),
            frozen=[seed.snapshot()] * 64,
        )
        self.assertEqual(catalog.pair(actual, 68), 277)
        actual["exports"][1][5][2] = 4_000_000_000
        with self.assertRaisesRegex(v.Invalid, "catalog-model-joint-serialization"):
            catalog.pair(actual, 68)
        self.assertEqual(first["current"], [1, [["a", [1], None]]])
        self.assertEqual(first["frozen"], [[0, []]])
        second, _ = store.transition(state, frozen, 1)
        self.assertEqual(first["current"], [1, [["a", [1], None]]])
        self.assertEqual(first["frozen"], [[0, []]])
        self.assertEqual(second["frozen"], [[0, []], [1, [["a", [1], None]]]])
        state = ledger.State(2)
        first, _ = state.step(0, 0)
        second, _ = state.step(0, 1)
        self.assertEqual(first["frozen"][0][0][1][1:2], ["attempt-0"])
        self.assertEqual(second["credentials"][0][1:], [False, None])
        self.assertEqual(second["credentials"][1][1], True)
        self.assertEqual(second["credentials"][1][0][4], 2)
        self.assertEqual(state.step(2, 2)[0]["outcome"], "conflict")
        reopened, hits = state.step(6, 3)
        self.assertEqual(reopened["credentials"], second["credentials"])
        self.assertEqual(reopened["frozen"], second["frozen"])
        self.assertEqual(hits, 10)

        # One actual admission order must explain receipts, final state and every locked prefix together.
        seed = comet.State([2, 1])
        receipts, prefixes = comet.candidate(seed, [0, 0], 1, (0, 1))
        actual = {
            "ordinal": 24,
            "limits": [2, 1],
            "prefix": [],
            "operations": [0, 0],
            "initial": {"core": [1, False, False, [], []]},
            "receipts": receipts,
            "current": prefixes[-1].snapshot(),
            "samples": [prefixes[0].snapshot(intents=False)] * 16 + [prefixes[1].snapshot(intents=False)] * 16 + [prefixes[2].snapshot(intents=False)] * 32,
        }
        self.assertEqual(receipts, ["ok", "ok"])
        self.assertEqual(
            actual["current"], {"core": [3, False, False, [1, 2], [1, 2]], "items": [[1, True, True, False, False], [2, True, True, False, False]]}
        )
        comet.pair(actual, 24)
        self.assertTrue(comet.assessment(actual, receipts, prefixes))
        reverse, alternate = comet.candidate(seed, [0, 0], 1, (1, 0))
        self.assertEqual(reverse, receipts)
        for field, value, cause in (
            ("ordinal", 24.0, "pair-input"),
            ("prefix", [0], "pair-input"),
            ("operations", [False, 0], "pair-input"),
            ("receipts", ["ok", "busy"], "joint-serialization"),
            ("current", alternate[-1].snapshot(), "joint-serialization"),
            ("samples", actual["samples"][:-1], "pair-observations"),
            ("samples", [alternate[1].snapshot(intents=False)] * 64, "joint-serialization"),
            ("samples", [prefixes[2].snapshot(intents=False), prefixes[0].snapshot(intents=False)] + actual["samples"][2:], "joint-serialization"),
        ):
            modified = copy.deepcopy(actual)
            modified[field] = value
            with self.subTest(field=field, cause=cause), self.assertRaisesRegex(v.Invalid, "comet-model-" + cause):
                comet.pair(modified, 24)
        for field in ("owners", "items", "queue"):
            modified = copy.deepcopy(actual)
            if field == "owners":
                modified["current"]["core"][0] = 4
            elif field == "items":
                modified["current"]["items"] = []
            else:
                modified["current"]["core"][4] = [2, 1]
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "comet-model-joint-serialization"):
                comet.pair(modified, 24)

    def test_projection(self) -> None:
        """Normalize only nil/empty public slices; versions, fields and ordered changes remain exact."""
        self.assertTrue(models.same({"Records": None, "Changes": None, "Value": None}, {"Records": [], "Changes": [], "Value": ""}))
        for actual, expected in [(True, 1), (1.0, 1), ({}, {"Value": ""}), ([1, 2], [2, 1]), (None, []), ({"Erase": True}, {"Erase": 1})]:
            with self.subTest(actual=actual), self.assertRaisesRegex(v.Invalid, "model-value"):
                models.require(actual, expected, "value")
            with self.subTest(actual=actual), self.assertRaisesRegex(v.Invalid, "store-model-value"):
                store.require(actual, expected, "value")
            with self.subTest(actual=actual), self.assertRaisesRegex(v.Invalid, "ledger-model-value"):
                ledger.require(actual, expected, "value")
            with self.subTest(actual=actual), self.assertRaisesRegex(v.Invalid, "almanac-model-value"):
                almanac.require(actual, expected, "value")
            with self.subTest(actual=actual), self.assertRaisesRegex(v.Invalid, "catalog-model-value"):
                catalog.require(actual, expected, "value")
            with self.subTest(actual=actual), self.assertRaisesRegex(v.Invalid, "projection-model-value"):
                projection.require(actual, expected, "value")

    def test_configuration(self) -> None:
        """Reject changes to the bound algorithm, package, command, domain tests and oracle budgets."""
        original = check()
        models.configuration(original)
        self.assertEqual(
            {item["test"] for item in original["probes"] if item["contract"] == "STORAGE-ASSURANCE"},
            {
                "TestFinite",
                "TestCompatibility",
                "TestCompatibility/single",
                "TestCompatibility/batch",
                "TestCompatibility/unknown",
                "TestCompatibility/truncated",
            },
        )
        with self.assertRaisesRegex(v.Invalid, "model-configuration"):
            models.configuration({**original, "probes": original["probes"] + [original["probes"][0]]})
        with self.assertRaisesRegex(v.Invalid, "model-configuration"):
            models.configuration(
                {**original, "probes": [item for item in original["probes"] if (item["contract"], item["test"]) != ("STORAGE-ASSURANCE", "TestFinite")]}
            )
        for field, value in [
            ("model", "other"),
            ("component", "admission-directory"),
            ("package", "other/storage"),
            ("expected_tests", ["TestFinite", "TestSchedules"]),
            ("argv", original["argv"][:-2] + ["-run=TestFinite", original["argv"][-1]]),
            ("probes", [item for item in original["probes"] if item["contract"] != "STORAGE-ORACLE"]),
        ]:
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "model-configuration"):
                modified = copy.deepcopy(original)
                modified[field] = value
                models.configuration(modified)
        config = v.decode(v.read(ROOT / "development.json"))
        for identifier in ("comet-native", "comet-windows"):
            original = next(item for item in config["checks"] if item["id"] == identifier)
            projection.configuration(original)
            if identifier == "comet-windows":
                self.assertEqual(original["expected_tests"][-2:], ["cpp_comet_options", "cpp_comet_core_model"])
                for name in ("cpp_comet_options", "cpp_comet_core_model"):
                    modified = copy.deepcopy(original)
                    modified["expected_tests"].remove(name)
                    with self.subTest(missing=name), self.assertRaisesRegex(v.Invalid, "projection-model-configuration"):
                        projection.configuration(modified)
            for mode in ("session", "input", "protocol"):
                name = "cpp_comet_authentication_" + mode
                for field, value in (
                    ("expected_tests", [test for test in original["expected_tests"] if test != name]),
                    ("probes", [probe for probe in original["probes"] if probe["test"] != name]),
                ):
                    modified = copy.deepcopy(original)
                    modified[field] = value
                    with self.subTest(identifier=identifier, mode=mode, field=field), self.assertRaisesRegex(v.Invalid, "projection-model-configuration"):
                        projection.configuration(modified)
            for field, value in (
                ("model", "other"),
                ("id", "comet-core-model"),
                ("platforms", ["windows-amd64" if identifier == "comet-native" else "linux-amd64-cgo"]),
                ("expected_tests", ["cpp_comet_projection"]),
                ("expected_tests", original["expected_tests"][:-1]),
                ("probes", original["probes"][:-1]),
                ("argv", original["argv"][:-2]),
                ("timeout_s", 3601),
                ("log_bytes", 64 * 1024**2),
            ):
                modified = copy.deepcopy(original)
                modified[field] = value
                with self.subTest(identifier=identifier, field=field), self.assertRaisesRegex(v.Invalid, "projection-model-configuration"):
                    projection.configuration(modified)
        for identifier in ("command-boundaries", "command-structure-race"):
            original = next(item for item in config["checks"] if item["id"] == identifier)
            command.configuration(original)
            for field, value in (("model", "other"), ("faults", "other"), ("expected_tests", original["expected_tests"][:-1])):
                modified = copy.deepcopy(original)
                modified[field] = value
                with self.subTest(field=field), self.assertRaises(v.Invalid):
                    command.configuration(modified)
            for contract, test, minimum in (("COMMAND-MODEL", "TestModel", 6220), ("COMMAND-MODEL-CONTROLS", "TestModelOracle", 10)):
                self.assertIn({"contract": contract, "test": test, "minimum_hits": minimum}, original["probes"])
                for field, value in (("test", "TestNumeric"), ("minimum_hits", minimum - 1), ("minimum_hits", minimum + 1)):
                    modified = copy.deepcopy(original)
                    next(item for item in modified["probes"] if item["contract"] == contract)[field] = value
                    with self.subTest(contract=contract, field=field), self.assertRaisesRegex(v.Invalid, "command-structure-configuration"):
                        command.configuration(modified)
        original = next(item for item in config["checks"] if item["id"] == "common-finite-model")
        store.configuration(original)
        for field, value in (
            ("model", "other"),
            ("component", "star"),
            ("platforms", ["windows-amd64"]),
            ("argv", original["argv"][:-2]),
            ("expected_tests", ["cpp_store"]),
            ("probes", [{"contract": "COMMON-ASSURANCE", "minimum_hits": 2, "test": "cpp_store_model"}]),
        ):
            modified = copy.deepcopy(original)
            modified[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "store-model-configuration"):
                store.configuration(modified)
        original = next(item for item in config["checks"] if item["id"] == "pulsar-finite-model")
        ledger.configuration(original)
        for field, value in (
            ("model", "other"),
            ("component", "common"),
            ("platforms", ["windows-amd64"]),
            ("argv", original["argv"][:-2]),
            ("expected_tests", ["cpp_pulsar_ledger"]),
            ("probes", [{"contract": "PULSAR-ASSURANCE", "minimum_hits": 2, "test": "cpp_pulsar_model"}]),
        ):
            modified = copy.deepcopy(original)
            modified[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "ledger-model-configuration"):
                ledger.configuration(modified)
        original = next(item for item in config["checks"] if item["id"] == "almanac-finite-model")
        almanac.configuration(original)
        for field, value in (
            ("model", "other"),
            ("component", "common"),
            ("platforms", ["windows-amd64"]),
            ("argv", original["argv"][:-2]),
            ("expected_tests", ["cpp_almanac"]),
            ("probes", [{"contract": "STAR-ASSURANCE", "minimum_hits": 2, "test": "cpp_almanac_model"}]),
        ):
            modified = copy.deepcopy(original)
            modified[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "almanac-model-configuration"):
                almanac.configuration(modified)
        original = next(item for item in config["checks"] if item["id"] == "catalog-finite-model")
        catalog.configuration(original)
        for field, value in (
            ("model", "other"),
            ("component", "common"),
            ("platforms", ["windows-amd64"]),
            ("argv", original["argv"][:-2]),
            ("expected_tests", ["cpp_catalog_state"]),
            ("probes", [{"contract": "STAR-ASSURANCE", "minimum_hits": 2, "test": "cpp_catalog_model"}]),
        ):
            modified = copy.deepcopy(original)
            modified[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "catalog-model-configuration"):
                catalog.configuration(modified)
        original = next(item for item in config["checks"] if item["id"] == "ephemeris-finite-model")
        ephemeris.configuration(original)
        for field, value in (
            ("model", "other"),
            ("component", "common"),
            ("platforms", ["windows-amd64"]),
            ("argv", original["argv"][:-2]),
            ("expected_tests", ["cpp_ephemeris_state"]),
            ("probes", [{"contract": "STAR-ASSURANCE", "minimum_hits": 2, "test": "cpp_ephemeris_model"}]),
        ):
            modified = copy.deepcopy(original)
            modified[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "ephemeris-model-configuration"):
                ephemeris.configuration(modified)

        finite = "star/DEV-MODEL/STAR-ASSURANCE/linux-amd64-cgo/finite-model"
        full = "star/DEV-MODEL/STAR-ASSURANCE/linux-amd64-cgo/full-rule"
        required = ["almanac-finite-model", "catalog-finite-model", "ephemeris-finite-model"]
        self.assertEqual(v.expand(config)[finite]["checks"], required)
        self.assertEqual(v.expand(config)[full]["checks"], ["star-qualification"])
        # Preserve the current denominator, including the registered benchmark gates and backup prerequisites.
        self.assertEqual(len(v.expand(config)), 1370)
        self.assertIn("polaris-storage/DEV-RETRY/STORAGE-RETRY-IDENTITY/linux-amd64-cgo/intent-window-grid", v.expand(config))
        self.assertIn("polaris-storage/DEV-NUMERIC/STORAGE-ASSURANCE/linux-amd64-cgo/full-rule", v.expand(config))
        self.assertIn("polaris-storage/DEV-ASYNC/STORAGE-LIFETIME/linux-amd64-cgo/controlled-close", v.expand(config))
        self.assertIn("polaris-storage/DEV-STOP/STORAGE-TERMINATION/linux-amd64-cgo/close-receipt-grid", v.expand(config))
        self.assertIn("polaris-storage/DEV-ASYNC/STORAGE-DRAINING/linux-amd64-cgo/cancelled-native-rollback", v.expand(config))
        self.assertIn("polaris-storage/DEV-FAULT/STORAGE-BORROWING/linux-amd64-cgo/refused-connection-acquisition", v.expand(config))
        now = dt.datetime(2026, 10, 5, tzinfo=dt.timezone.utc)
        observations = {(identifier, "linux-amd64-cgo", "STAR-ASSURANCE"): "passed" for identifier in required}
        gate = v.decide(config, observations, [], [], now)
        self.assertIn(finite, gate["passed"])
        self.assertIn(full, gate["missing"])
        self.assertEqual(gate["status"], "blocked")
        for identifier in required:
            key = identifier, "linux-amd64-cgo", "STAR-ASSURANCE"
            for state in (None, "failed", "unknown", "not-run", "interrupted", "wrong-platform", "wrong-contract"):
                modified = dict(observations)
                if state is None:
                    del modified[key]
                elif state == "wrong-platform":
                    del modified[key]
                    modified[(identifier, "windows-amd64", "STAR-ASSURANCE")] = "passed"
                elif state == "wrong-contract":
                    del modified[key]
                    modified[(identifier, "linux-amd64-cgo", "PULSAR-ASSURANCE")] = "passed"
                else:
                    modified[key] = state
                with self.subTest(identifier=identifier, state=state):
                    gate = v.decide(config, modified, [], [], now)
                    self.assertIn(finite, gate["missing"])
                    self.assertNotIn(finite, gate["passed"])
                    self.assertIn(full, gate["missing"])
                    self.assertEqual(gate["status"], "blocked")

        original = next(item for item in config["checks"] if item["id"] == "comet-core-model")
        models.configuration(original)
        for field, value in (
            ("model", "other"),
            ("id", "comet-qualification"),
            ("component", "star"),
            ("platforms", ["linux-amd64-cgo"]),
            ("platforms", ["windows-amd64"]),
            ("argv", original["argv"][:-2]),
            ("expected_tests", ["cpp_comet_admission"]),
            ("probes", [{"contract": "COMET-ASSURANCE", "minimum_hits": 2, "test": "cpp_comet_core_model"}]),
        ):
            modified = copy.deepcopy(original)
            modified[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "comet-model-configuration"):
                comet.configuration(modified)
        for platform in ("linux-amd64-cgo", "windows-amd64"):
            partial = v.decide(config, {("comet-core-model", platform, "COMET-ASSURANCE"): "passed"}, [], [], now)
            for contract, scenario, checks in (
                ("COMET-PROJECTION-MODEL", "finite-model-domain", ["comet-native" if platform == "linux-amd64-cgo" else "comet-windows"]),
                ("COMET-ASSURANCE", "full-rule", ["comet-qualification"]),
            ):
                key = "comet/DEV-MODEL/" + contract + "/" + platform + "/" + scenario
                self.assertEqual(v.expand(config)[key]["checks"], checks)
                self.assertIn(key, partial["missing"])
                self.assertNotIn(key, partial["passed"])
            self.assertEqual(partial["status"], "blocked")

    def test_schema(self) -> None:
        """The formal closed schema rejects unknown algorithms, fields and nonstring model identities."""
        original = v.decode(v.read(ROOT / "development.json"))
        v.schema(original, "development")
        for field, value in [("model", "other"), ("model", None), ("model", True), ("oracle", "storage-commit-v1")]:
            modified = copy.deepcopy(original)
            target = next(item for item in modified["checks"] if item["id"] == "storage-examples")
            target[field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(v.Invalid, "schema-invalid"):
                v.schema(modified, "development")
        for identifier in (
            "common-finite-model",
            "pulsar-finite-model",
            "almanac-finite-model",
            "catalog-finite-model",
            "ephemeris-finite-model",
            "comet-core-model",
            "comet-native",
            "comet-windows",
        ):
            for value in ("other", None, True):
                modified = copy.deepcopy(original)
                next(item for item in modified["checks"] if item["id"] == identifier)["model"] = value
                with self.subTest(identifier=identifier, value=value), self.assertRaisesRegex(v.Invalid, "schema-invalid"):
                    v.schema(modified, "development")

    def test_fragments(self) -> None:
        """Reassemble test-owned fragments, retaining envelope identity and rejecting unfinished markers."""
        marker = '    modeltrace_test.go:80: ASTRA-MODEL {"model":"storage-commit-v1","event":"step","value":{}}\n'
        raw = output("TestFinite", marker[:47]) + output("TestSchedules", "unrelated\n") + output("TestFinite", marker[47:])
        self.assertEqual(models.frames(raw), {"TestFinite": [{"model": "storage-commit-v1", "event": "step", "value": {}}], "TestSchedules": []})
        for text, name, cause in [
            (marker, "TestOracle", "model-test-identity"),
            (marker.replace("storage-commit-v1", "other"), "TestFinite", "model-frame-shape"),
            (marker.replace('"value":{}', '"value":{},"extra":true'), "TestFinite", "model-frame-shape"),
            (marker.rstrip("\n"), "TestFinite", "model-incomplete-line"),
            ("x" * (128 * 1024 + 1), "TestFinite", "model-line-budget"),
        ]:
            with self.subTest(cause=cause), self.assertRaisesRegex(v.Invalid, cause):
                models.frames(output(name, text))
        marker = 'model_test.go:1: ASTRA-COMMAND-MODEL {"kind":1,"history":[],"states":[]}\n'
        self.assertEqual(
            command.frames(output("TestModel", marker[:30]) + output("TestParse", "other\n") + output("TestModel", marker[30:])),
            [{"kind": 1, "history": [], "states": []}],
        )
        for text, name, cause in (
            (marker, "TestNumeric", "test-identity"),
            (marker.replace('"kind":1', '"kind":true'), "TestModel", "kind"),
            (marker.replace('"history":[]', '"history":[6]'), "TestModel", "actions"),
            (marker.replace('"history":[]', '"history":[true]'), "TestModel", "actions"),
            (marker.replace('"states":[]', '"states":[],"extra":0'), "TestModel", "frame-shape"),
            (marker.rstrip("\n"), "TestModel", "incomplete-line"),
            ("x" * (128 * 1024 + 1), "TestModel", "line-budget"),
        ):
            with self.subTest(cause=cause), self.assertRaisesRegex(v.Invalid, "command-model-" + cause):
                command.frames(output(name, text))
        for raw, cause in ((b"null\n", "envelope"), (b'{"Action":"output","Test":"TestModel","Output":null}\n', "output")):
            with self.subTest(cause=cause), self.assertRaisesRegex(v.Invalid, "command-model-" + cause):
                command.frames(raw)
        registered = next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "common-finite-model")
        row = {"model": "store-state-v1", "event": "history", "value": {}}
        line = "ASTRA-MODEL " + json.dumps(row) + "\n"
        self.assertEqual(len(store.frames(cpp_output(line * 4098), registered)), 4098)
        for raw, cause in (
            (cpp_output(line * 4097), "domain-incomplete"),
            (cpp_output(line * 4099), "frame-budget"),
            (cpp_output(line * 4098, name="cpp_store"), "case"),
            (cpp_output(line.replace("store-state-v1", "other")), "frame"),
            (cpp_output(" " + line), "line"),
            (cpp_output(line.rstrip("\n")), "line"),
            (cpp_output("ASTRA-MODEL " + "x" * (64 * 1024) + "\n"), "line"),
            (b"", "native-missing"),
        ):
            with self.subTest(cause=cause), self.assertRaisesRegex(v.Invalid, "store-model-" + cause):
                store.frames(raw, registered)
        registered = next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "pulsar-finite-model")
        line = "ASTRA-MODEL " + json.dumps({"model": "ledger-state-v1", "event": "history", "value": {}}) + "\n"
        encoded = lambda text, name="cpp_pulsar_model": cpp_output(text, name=name)
        self.assertEqual(len(ledger.frames(encoded(line * 688), registered)), 688)
        for raw, cause in (
            (encoded(line * 687), "domain-incomplete"),
            (encoded(line * 689), "frame-budget"),
            (encoded(line * 688, "cpp_pulsar_ledger"), "case"),
            (encoded(line.replace("ledger-state-v1", "other")), "frame"),
            (encoded(" " + line), "line"),
            (encoded(line.rstrip("\n")), "line"),
            (encoded("ASTRA-MODEL " + "x" * (64 * 1024) + "\n"), "line"),
            (b"", "native-missing"),
        ):
            with self.subTest(cause=cause), self.assertRaisesRegex(v.Invalid, "ledger-model-" + cause):
                ledger.frames(raw, registered)
        registered = next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "almanac-finite-model")
        line = "ASTRA-MODEL " + json.dumps({"model": "almanac-state-v1", "event": "history", "value": {}}) + "\n"
        encoded = lambda text, name="cpp_almanac_model": cpp_output(text, name=name)
        self.assertEqual(len(almanac.frames(encoded(line * 6819), registered)), 6819)
        for raw, cause in (
            (encoded(line * 6818), "domain-incomplete"),
            (encoded(line * 6820), "frame-budget"),
            (encoded(line * 6819, "cpp_almanac"), "case"),
            (encoded(line.replace("almanac-state-v1", "other")), "frame"),
            (encoded(" " + line), "line"),
            (encoded(line.rstrip("\n")), "line"),
            (encoded("ASTRA-MODEL " + "x" * (64 * 1024) + "\n"), "line"),
            (b"", "native-missing"),
        ):
            with self.subTest(cause=cause), self.assertRaisesRegex(v.Invalid, "almanac-model-" + cause):
                almanac.frames(raw, registered)
        registered = next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "catalog-finite-model")
        line = "ASTRA-MODEL " + json.dumps({"model": "catalog-state-v1", "event": "history", "value": {}}) + "\n"
        encoded = lambda text, name="cpp_catalog_model": cpp_output(text, name=name)
        self.assertEqual(len(catalog.frames(encoded(line * 6819), registered)), 6819)
        for raw, cause in (
            (encoded(line * 6818), "domain-incomplete"),
            (encoded(line * 6820), "frame-budget"),
            (encoded(line * 6819, "cpp_catalog_state"), "case"),
            (encoded(line.replace("catalog-state-v1", "other")), "frame"),
            (encoded(" " + line), "line"),
            (encoded(line.rstrip("\n")), "line"),
            (encoded("ASTRA-MODEL " + "x" * (64 * 1024) + "\n"), "line"),
            (b"", "native-missing"),
        ):
            with self.subTest(cause=cause), self.assertRaisesRegex(v.Invalid, "catalog-model-" + cause):
                catalog.frames(raw, registered)
        registered = next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "ephemeris-finite-model")
        line = "ASTRA-MODEL " + json.dumps({"model": "ephemeris-state-v1", "event": "history", "value": {}}) + "\n"
        encoded = lambda text, name="cpp_ephemeris_model": cpp_output(text, name=name)
        self.assertEqual(len(ephemeris.frames(encoded(line * 6819), registered)), 6819)
        for raw, cause in (
            (encoded(line * 6818), "domain-incomplete"),
            (encoded(line * 6820), "frame-budget"),
            (encoded(line * 6819, "cpp_ephemeris_state"), "case"),
            (encoded(line.replace("ephemeris-state-v1", "other")), "frame"),
            (encoded(" " + line), "line"),
            (encoded(line.rstrip("\n")), "line"),
            (encoded("ASTRA-MODEL " + "x" * (64 * 1024) + "\n"), "line"),
            (b"", "native-missing"),
        ):
            with self.subTest(cause=cause), self.assertRaisesRegex(v.Invalid, "ephemeris-model-" + cause):
                ephemeris.frames(raw, registered)

        registered = next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "comet-core-model")
        line = "ASTRA-MODEL " + json.dumps({"model": "comet-core-v1", "event": "history", "value": {}}) + "\n"
        encoded = lambda text, name="cpp_comet_core_model": cpp_output(text, name=name)
        self.assertEqual(len(comet.frames(encoded(line * 13176), registered)), 13176)
        for raw, cause in (
            (encoded(line * 13175), "domain-incomplete"),
            (encoded(line * 13177), "frame-budget"),
            (encoded(line * 13176, "cpp_comet_admission"), "case"),
            (encoded(line.replace("comet-core-v1", "other")), "frame"),
            (encoded(" " + line), "line"),
            (encoded(line.rstrip("\n")), "line"),
            (encoded("ASTRA-MODEL " + "x" * (64 * 1024) + "\n"), "line"),
            (b"", "native-missing"),
        ):
            with self.subTest(cause=cause), self.assertRaisesRegex(v.Invalid, "comet-model-" + cause):
                comet.frames(raw, registered)

    def test_nonvacuity(self) -> None:
        """Even native-shaped passing tests and sufficient counters cannot qualify a missing finite trace."""
        registered = check()
        package = registered["package"]
        events = [{"Action": "start", "Package": package}]
        for name in registered["expected_tests"]:
            events.append({"Action": "run", "Package": package, "Test": name})
            for probe in registered["probes"]:
                if probe["test"] == name:
                    marker = {"contract": probe["contract"], "hits": probe["minimum_hits"]}
                    events.append({"Action": "output", "Package": package, "Test": name, "Output": "ASTRA-CONTRACT " + json.dumps(marker) + "\n"})
            events.append({"Action": "pass", "Package": package, "Test": name})
        events.append({"Action": "pass", "Package": package})
        raw = b"".join(json.dumps(item, separators=(",", ":")).encode() + b"\n" for item in events)
        self.assertEqual(v.go_observations(raw, registered)[1], [])
        with self.assertRaisesRegex(v.Invalid, "model-domain-incomplete"):
            v.parse_observations(raw, registered)
        # Stub only semantic readers to isolate count attribution; this synthetic stream earns no product evidence.
        with patch.object(models, "observations", return_value={"STORAGE-ASSURANCE": 2187}), patch("tools.retry.recovery") as recovery:
            observed, failures = v.parse_observations(raw, registered)
            self.assertEqual(observed["STORAGE-ASSURANCE"], 2273)
            self.assertEqual(failures, [])
            recovery.assert_called_once_with(raw, registered, ROOT)
            for name, count, rejected in (("TestFinite", 2188, True), ("TestFinite", 2186, False), ("TestCompatibility/batch", 29, False)):
                changed = copy.deepcopy(events)
                target = next(row for row in changed if row.get("Test") == name and row["Action"] == "output" and '"STORAGE-ASSURANCE"' in row["Output"])
                target["Output"] = "ASTRA-CONTRACT " + json.dumps({"contract": "STORAGE-ASSURANCE", "hits": count}) + "\n"
                data = b"".join(json.dumps(item, separators=(",", ":")).encode() + b"\n" for item in changed)
                with self.subTest(test=name, count=count):
                    if rejected:
                        with self.assertRaisesRegex(v.Invalid, "model-observation-mismatch"):
                            v.parse_observations(data, registered)
                    else:
                        self.assertIn("probe-budget:STORAGE-ASSURANCE", v.parse_observations(data, registered)[1])
        events[-1]["Action"] = "fail"
        observed, failures = v.parse_observations(b"".join(json.dumps(item, separators=(",", ":")).encode() + b"\n" for item in events), registered)
        self.assertIn("fail:" + package, failures)
        self.assertIn("STORAGE-ASSURANCE", observed)
        registered = next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "command-boundaries")
        rows = [{"kind": kind, "history": actions, "states": command.history(actions, kind)} for kind, actions in command.domain()]
        self.assertEqual(len(rows), 6220)
        self.assertEqual(sum(len(row["history"]) for row in rows), 23640)

        def encoded(rows: list[dict]) -> bytes:
            """Native-shaped synthetic frames exercise only the importer; they never become acceptance evidence."""
            return b"".join(output("TestModel", "ASTRA-COMMAND-MODEL " + json.dumps(row, separators=(",", ":")) + "\n") for row in rows)

        self.assertEqual(command.observations(encoded(rows), registered, ROOT), {"COMMAND-MODEL": 6220, "COMMAND-MODEL-CONTROLS": 10})
        for incomplete in ([], rows[:-1]):
            with self.assertRaisesRegex(v.Invalid, "command-model-domain-incomplete"):
                command.observations(encoded(incomplete), registered, ROOT)
        for kind, actions, field, wrong in (
            (1, [3], 4, False),
            (1, [4], 0, "ok"),
            (1, [5], 6, "ok"),
            (1, [0, 2], 5, "normalized"),
            (0, [0], 1, False),
            (2, [1], 0, "bool:true"),
        ):
            modified = copy.deepcopy(rows)
            target = next(row for row in modified if row["kind"] == kind and row["history"] == actions)
            target["states"][-1][field] = wrong
            with self.subTest(kind=kind, actions=actions), self.assertRaisesRegex(v.Invalid, "command-model-value"):
                command.observations(encoded(modified), registered, ROOT)
        modified = copy.deepcopy(rows)
        modified[1], modified[2] = modified[2], modified[1]
        with self.assertRaisesRegex(v.Invalid, "command-model-value"):
            command.observations(encoded(modified), registered, ROOT)
        registered = next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "common-finite-model")
        raw = cpp_output("", hits=1000000)
        self.assertEqual(v.case_observations(raw, registered), ({"COMMON-ASSURANCE": 1000000}, []))
        with self.assertRaisesRegex(v.Invalid, "store-model-domain-incomplete"):
            v.parse_observations(raw, registered, ROOT)
        registered = next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "almanac-finite-model")
        raw = cpp_output("", hits=1000000, name="cpp_almanac_model")
        self.assertEqual(v.case_observations(raw, registered), ({"STAR-ASSURANCE": 1000000}, []))
        with self.assertRaisesRegex(v.Invalid, "almanac-model-domain-incomplete"):
            v.parse_observations(raw, registered, ROOT)
        registered = next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "catalog-finite-model")
        raw = cpp_output("", hits=1000000, name="cpp_catalog_model")
        self.assertEqual(v.case_observations(raw, registered), ({"STAR-ASSURANCE": 1000000}, []))
        with self.assertRaisesRegex(v.Invalid, "catalog-model-domain-incomplete"):
            v.parse_observations(raw, registered, ROOT)
        registered = next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "pulsar-finite-model")
        raw = cpp_output("", hits=1000000, name="cpp_pulsar_model")
        self.assertEqual(v.case_observations(raw, registered), ({"PULSAR-ASSURANCE": 1000000}, []))
        with self.assertRaisesRegex(v.Invalid, "ledger-model-domain-incomplete"):
            v.parse_observations(raw, registered, ROOT)
        registered = next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "ephemeris-finite-model")
        raw = cpp_output("", hits=1000000, name="cpp_ephemeris_model")
        self.assertEqual(v.case_observations(raw, registered), ({"STAR-ASSURANCE": 1000000}, []))
        with self.assertRaisesRegex(v.Invalid, "ephemeris-model-domain-incomplete"):
            v.parse_observations(raw, registered, ROOT)
        registered = next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "comet-core-model")
        raw = cpp_output("", hits=1000000, name="cpp_comet_core_model")
        self.assertEqual(v.case_observations(raw, registered), ({"COMET-ASSURANCE": 1000000}, []))
        with self.assertRaisesRegex(v.Invalid, "comet-model-domain-incomplete"):
            v.parse_observations(raw, registered, ROOT)

        # Both existing full platform suites must still pass; these generated streams test the importer alone.
        for identifier in ("comet-native", "comet-windows"):
            registered = next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == identifier)
            counts = {
                name: max((probe["minimum_hits"] for probe in registered["probes"] if probe["test"] == name), default=1)
                for name in registered["expected_tests"]
            }
            rows = [{"model": "comet-projection-v1", "event": "start", "value": {**projection.DOMAIN, "before": 42}}]
            total = 2
            for ordinal in range(2401):
                remaining, operations = ordinal, []
                for _ in range(4):
                    operations.append(remaining % 7)
                    remaining //= 7
                value, hits = projection.trace(operations, ordinal)
                total += hits
                rows.append({"model": "comet-projection-v1", "event": "history", "value": value})
            rows.append({"model": "comet-projection-v1", "event": "finish", "value": {"histories": 2401, "transitions": 9604, "checks": total}})

            def encoded_projection(frames: list[dict], *, hits: int = 42 + total, selected: dict[str, int] = counts) -> bytes:
                """Synthetic complete XML challenges parsing, without substituting for any native C++ receipt."""
                text = "".join("ASTRA-MODEL " + json.dumps(row, separators=(",", ":")) + "\n" for row in frames)
                return cpp_output(text, hits=hits, name="cpp_comet_projection", tests=selected)

            raw = encoded_projection(rows)
            observed, failures = v.parse_observations(raw, registered, ROOT)
            self.assertEqual(failures, [])
            self.assertEqual(observed, v.case_observations(raw, registered)[0])
            with self.assertRaisesRegex(v.Invalid, "projection-model-domain-incomplete"):
                v.parse_observations(encoded_projection([]), registered, ROOT)
            with self.assertRaisesRegex(v.Invalid, "projection-model-counter"):
                v.parse_observations(encoded_projection(rows, hits=41 + total), registered, ROOT)
            missing = {name: hits for name, hits in counts.items() if name != registered["expected_tests"][0]}
            with self.assertRaisesRegex(v.Invalid, "projection-model-case-failed"):
                projection.observations(encoded_projection(rows, selected=missing), registered, ROOT)
            if identifier == "comet-windows":
                for name in ("cpp_comet_options", "cpp_comet_core_model"):
                    with self.subTest(missing=name), self.assertRaisesRegex(v.Invalid, "projection-model-case-failed"):
                        projection.observations(
                            encoded_projection(rows, selected={test: hits for test, hits in counts.items() if test != name}), registered, ROOT
                        )
            for position, field, wrong in ((0, "before", True), (0, "operations", 8), (1, "ordinal", False), (-1, "checks", total - 1)):
                modified = list(rows)
                modified[position] = copy.deepcopy(rows[position])
                modified[position]["value"][field] = wrong
                with self.subTest(platform=identifier, field=field), self.assertRaises(v.Invalid):
                    v.parse_observations(encoded_projection(modified), registered, ROOT)
            for field in ("value", "version", "partial", "receipt", "retained", "error", "extra"):
                modified = list(rows)
                position = 4 if field == "partial" else 7 if field == "receipt" else 2
                modified[position] = copy.deepcopy(rows[position])
                target = modified[position]["value"]["states"][0]
                if field == "value":
                    target["current"][-1][0][1] = "B"
                elif field == "version":
                    target["current"][0] = True
                elif field == "partial":
                    target["receipts"][0][1][-1] = [["a", "private"]]
                elif field == "receipt":
                    target["receipts"][-1][0] = "complete"
                elif field == "retained":
                    target["retained"][0][0] = 9
                elif field == "error":
                    target["current"][6] = True
                else:
                    target["invented"] = True
                with self.subTest(platform=identifier, field=field), self.assertRaisesRegex(v.Invalid, "projection-model-history"):
                    v.parse_observations(encoded_projection(modified), registered, ROOT)
            for frames in (rows[:-1], rows + [rows[-1]], [rows[0], rows[2], rows[1], *rows[3:]]):
                with self.subTest(platform=identifier, count=len(frames)), self.assertRaises(v.Invalid):
                    v.parse_observations(encoded_projection(frames), registered, ROOT)
