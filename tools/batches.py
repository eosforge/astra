"""Reconstruct fixed AB02 wire and public batch-input predicates independently of production results."""

import base64
import binascii

from tools import authority, logic, storage, structure, verify as v

ROOTS = {
    "admission": structure.STORAGE + "/batch.go:730",
    "header": structure.STORAGE + "/batch.go:1756",
    "count": structure.STORAGE + "/batch.go:2025",
    "length": structure.STORAGE + "/batch.go:2379",
    "entry": structure.STORAGE + "/batch.go:2699",
}
EXPRESSIONS = {
    "admission": "!validChange(change) || seen[change.Key] || change.Version != 0 && change.Version != version",
    "header": 'change.Erase || len(data) < 12 || string(data[:4]) != "AB02"',
    "count": "count == 0 || count > uint64(len(data)/8)",
    "length": "key > len(data) || uint64(length) > uint64(len(data)-key) || erase > 1",
    "entry": "!validChange(entry) || seen[entry.Key]",
}


def valid(key: bytes, value: bytes, erased: bool) -> bool:
    """Specify the ordinary entry contract: bounded valid text, bounded payload and exclusive deletion."""
    return all(storage.text_input(key, 1024)) and len(value) <= 2**20 and (not erased or len(value) == 0)


def vectors(frame: dict) -> tuple[list[tuple[str, list[bool]]], bool]:
    """Return only predicates reached by the published format/input grammar; no prefix or skipped value becomes an observation."""
    logic.fields(frame, ("kind", "name", "input", "refused"), "batches-frame")
    if not isinstance(frame["name"], str) or type(frame["refused"]) is not bool:
        v.reject("batches-identity")
    value, result, seen = frame["input"], [], set()
    if frame["kind"] == "encode":
        logic.fields(value, ("scope", "version", "changes"), "batches-encode")
        logic.fields(value["scope"], ("Sector", "Spectrum"), "batches-scope")
        if value["scope"] != {"Sector": "input", "Spectrum": frame["name"]}:
            v.reject("batches-scope-domain")
        if type(value["version"]) is not int or value["version"] != 1 or not isinstance(value["changes"], list) or not value["changes"]:
            v.reject("batches-encode-domain")
        for change in value["changes"]:
            logic.fields(change, ("Version", "Key", "Value", "Erase"), "batches-change")
            if (
                not isinstance(change["Key"], str)
                or type(change["Version"]) is not int
                or not 0 <= change["Version"] < 2**64
                or type(change["Erase"]) is not bool
                or change["Value"] is not None
                and not isinstance(change["Value"], str)
            ):
                v.reject("batches-change-type")
            try:
                payload = b"" if change["Value"] is None else base64.b64decode(change["Value"], validate=True)
                key = change["Key"].encode("utf-8")
            except (ValueError, binascii.Error, UnicodeError):
                v.reject("batches-change-encoding")
            values = [valid(key, payload, change["Erase"]), key in seen, change["Version"] != 0, change["Version"] != value["version"]]
            result.append((ROOTS["admission"], values))
            if not values[0] or values[1] or values[2] and values[3]:
                return result, True
            seen.add(key)
        return result, False
    if frame["kind"] != "decode":
        v.reject("batches-kind")
    logic.fields(value, ("wire", "erase", "version"), "batches-wire")
    if not isinstance(value["wire"], str) or type(value["erase"]) is not bool or type(value["version"]) is not int or value["version"] != 1:
        v.reject("batches-wire-type")
    try:
        data = bytes.fromhex(value["wire"])
    except ValueError:
        v.reject("batches-wire-encoding")
    if data.hex() != value["wire"] or len(data) < 4:
        v.reject("batches-wire-domain")
    values = [value["erase"], len(data) < 12, data[:4] != b"AB02"]
    result.append((ROOTS["header"], values))
    if any(values):
        return result, True
    count, body = int.from_bytes(data[4:12], "big"), data[12:]
    values = [count == 0, count > len(body) // 8]
    result.append((ROOTS["count"], values))
    if any(values):
        return result, True
    for _ in range(count):
        if len(body) < 7:
            v.reject("batches-unregistered-short-entry")
        key, size, erased = int.from_bytes(body[:2], "big"), int.from_bytes(body[2:6], "big"), body[6]
        body = body[7:]
        values = [key > len(body), size > (len(body) - key) % 2**64, erased > 1]
        result.append((ROOTS["length"], values))
        if any(values):
            return result, True
        text, payload = body[:key], body[key : key + size]
        values = [valid(text, payload, erased == 1), text in seen]
        result.append((ROOTS["entry"], values))
        if not values[0] or values[1]:
            return result, True
        seen.add(text)
        body = body[key + size :]
    return result, bool(body)


def observations(trace: dict, events: bytes, frames: list[dict]) -> list[dict]:
    """Require all fixed inputs, independent outcomes and actual masks before admitting nine known missing coordinates."""
    names = {
        "decode": {"valid", "erase", "short", "count-zero", "key-bounds", "value-bounds", "invalid-entry", "duplicate"},
        "encode": {"valid", "invalid-key", "duplicate", "entry-version"},
    }
    observed = {kind: set() for kind in names}
    decisions = logic.inventory(trace)
    if any(identity not in decisions or decisions[identity]["text"] != EXPRESSIONS[kind] for kind, identity in ROOTS.items()):
        v.reject("batches-source-decision")
    native, _ = logic.observe(trace, events, "github.com/eosforge/astra/" + structure.STORAGE, 247)
    values = {identity: [] for identity in ROOTS.values()}
    if not isinstance(frames, list) or len(frames) != 12:
        v.reject("batches-input-count")
    for frame in frames:
        logic.fields(frame, ("kind", "name", "input", "refused"), "batches-frame")
        kind, name = frame["kind"], frame["name"]
        if not isinstance(kind, str) or not isinstance(name, str) or kind not in names or name not in names[kind] or name in observed[kind]:
            v.reject("batches-input-identity")
        observed[kind].add(name)
        predicted, refused = vectors(frame)
        if refused != frame["refused"]:
            v.reject("batches-input-outcome")
        for identity, inputs in predicted:
            mask, outcome = authority.project(decisions[identity], inputs)
            if (mask, outcome) not in native[identity]:
                v.reject("batches-native-mask")
            values[identity].append({"values": inputs, "result": outcome, "input": v.digest(v.encode(frame)), "name": kind + "/" + name})
    if observed != names:
        v.reject("batches-input-domain")
    proofs = []
    required = {ROOTS["admission"]: (0, 1, 2), ROOTS["header"]: (0, 1), ROOTS["count"]: (0,), ROOTS["length"]: (0, 1), ROOTS["entry"]: (0,)}
    for identity, conditions in required.items():
        for target in conditions:
            pair = None
            for first in values[identity]:
                for second in values[identity]:
                    if (
                        first["result"] == second["result"]
                        or first["values"][target] == second["values"][target]
                        or any(a != b for index, (a, b) in enumerate(zip(first["values"], second["values"], strict=True)) if index != target)
                    ):
                        continue
                    pair = (first, second)
                    break
                if pair is not None:
                    break
            if pair is None:
                v.reject("batches-independent-input-missing", identity + "/" + str(target))
            before, after = pair
            proof = authority.correlate_pair(
                decisions[identity],
                {
                    "decision": identity,
                    "condition": target,
                    "before": {key: before[key] for key in ("values", "result")},
                    "after": {key: after[key] for key in ("values", "result")},
                },
                set(native[identity]),
            )
            proofs.append(
                {
                    **proof,
                    "inputs": [before["input"], after["input"]],
                    "cases": [before["name"], after["name"]],
                    "basis": "Fixed native AB02 vectors and complete public batch arguments, independent bounded-text/framing/endian/duplicate/version predicates and original same-production masks. Semantic skipped values never acquire native hit credit.",
                }
            )
    return proofs
