"""Bind Admission's three unhit statement defenses to explicit source and dependency assumptions."""

from pathlib import Path

from tools import admission, profileweights, statements, verify as v

DEPENDENCIES = {
    "crypto/tls/tls.go": "129436075e241ae7ce82a67b46df876b500887edf3564e95887a697e440cf75f",
    "crypto/x509/parser.go": "562e995707d4358ecf558a0d4dd035fe6bfa20add6fe57fdf74277f6478cfedc",
    "crypto/rand/rand.go": "7c289648d453d0bdca0f05091d00bb86c94b69637080c748ff3d3476677521ac",
}
# Frozen compiler geometry, including all zero-weight blocks; changing it requires a new review.
DENOMINATOR = "9b3e2846a26a56ec3ce8e3a8df85c27dfda58d5f14d55a4a670d4d94f57f3985"
CURRENT = "ad104c8014e3db7ee14b039da8f359257d359fb6001767d24744a0a3db8236ca"
ACQUISITION = "bdbf2ac34d5afe9d55fbe774391e8a2a3fe6cac0a0806a671f6908cc4bb81271"
DEFENSES = (
    {
        "id": "parsed-leaf",
        "file": "internal/admission/identity.go",
        "span": [83, 3, 84, 1],
        "statements": 1,
        "assumption": "Successful X509KeyPair already parsed the identical private leaf DER with the same deterministic parser and stable process settings.",
        "invalidated_by": "Changed TLS/parser behavior, mutated certificate bytes, changing process settings or memory corruption.",
    },
    {
        "id": "validated-directory",
        "file": "internal/admission/node.go",
        "span": [47, 3, 48, 1],
        "statements": 1,
        "assumption": "Open already validated the same nonnil identity, galaxy and Polaris/Astrolabe role; fixed capacity 16384 satisfies every NewDirectory guard.",
        "invalidated_by": "Changed validation order, constructor preconditions, role values, argument ownership or memory corruption.",
    },
    {
        "id": "random-return",
        "file": "internal/admission/node.go",
        "span": [51, 3, 52, 1],
        "statements": 1,
        "assumption": "The pinned crypto/rand.Read returns len(b), nil on success and irrecoverably terminates on entropy failure; no nonnil error returns.",
        "invalidated_by": "Changed random implementation or unsupported runtime patching; entropy failure still terminates and is not successful recovery.",
    },
)


def sources(root: Path, *, acquisition: bool = False) -> dict[str, dict]:
    """Require every owned production file and the generated role representation to retain its reviewed bytes."""
    owned = {p.relative_to(root).as_posix() for p in (root / "internal/admission").rglob("*.go") if not p.name.endswith("_test.go")}
    selected = {**admission.SOURCES, **admission.MATERIAL, "internal/admission/node.go": admission.NODE} if acquisition else admission.SOURCES
    expected = {name for name in selected if name.startswith("internal/admission/")}
    if owned != expected:
        v.reject("defense-source-scope")
    result = {}
    for name in selected:
        data = v.read(v.inside(root, name))
        if not admission.matches(root, name, selected):
            v.reject("defense-source-drift", name)
        # The platform fallback is still source-bound; Linux never supplies imaginary hits for it.
        if name in owned and name != "internal/admission/file_other.go":
            result[name] = {"data": data}
    return result


def dependencies(values: dict[str, bytes]) -> dict[str, dict]:
    """Check actual dependency bytes; names, reported versions and copied hashes alone are insufficient."""
    if set(values) != set(DEPENDENCIES):
        v.reject("defense-dependency-scope")
    result = {}
    for name, digest in DEPENDENCIES.items():
        data = values[name]
        if not isinstance(data, bytes) or len(data) > statements.LIMIT or v.digest(data) != digest:
            v.reject("defense-dependency-drift", name)
        result[name] = {"bytes": len(data), "sha256": digest}
    return result


def reconcile(parent: bytes, child: bytes, root: Path, dependency: dict[str, bytes], *, acquisition: bool = False, compiler: str = "1.27.1") -> dict:
    """Retain raw hit counts and conditional explanations without converting unhit statements into execution or gate passes."""
    files = sources(root, acquisition=acquisition)
    if compiler not in {"1.27.1", "1.27.2"} or compiler == "1.27.2" and not acquisition:
        v.reject("defense-profile-compiler")
    selected = {**admission.SOURCES, **admission.MATERIAL} if acquisition else admission.SOURCES
    identity = {name: v.file_digest(v.inside(root, name)) for name in selected}
    denominator = ACQUISITION if acquisition else CURRENT if identity["internal/admission/node.go"] == admission.NODE else DENOMINATOR
    defenses = [{**item, "span": [89, 3, 90, 1] if acquisition and item["id"] == "parsed-leaf" else item["span"].copy()} for item in DEFENSES]
    pinned = dependencies(dependency)
    selected = {"github.com/eosforge/astra/" + name: name for name in files}
    profiles = []
    for data in (parent, child):
        mode, blocks, records = statements.profile(data, files, selected)
        shape = [{key: block[key] for key in ("file", "span", "statements")} for block in blocks]
        geometry = v.digest(v.encode(shape))
        if compiler == "1.27.2":
            weights = profileweights.reconcile(root, "internal/admission", blocks)
            geometry = weights["shape_sha256"]["1.27.1"]
        if mode not in ("set", "atomic") or records != len(blocks) or geometry != denominator:
            v.reject("defense-profile-denominator")
        profiles.append((mode, blocks))
    if profiles[0][0] != profiles[1][0]:
        v.reject("defense-profile-mode")
    blocks = [{**left, "count": max(left["count"], right["count"])} for left, right in zip(profiles[0][1], profiles[1][1])]
    expected = {(item["file"], tuple(item["span"])): item for item in defenses}
    for block in blocks:
        key = (block["file"], tuple(block["span"]))
        if key in expected and block["count"]:
            v.reject("defense-assumption-contradicted", expected[key]["id"])
    unhit = [block for block in blocks if block["statements"] and not block["count"]]
    # Extra real gaps stay visible and cannot be discharged by a nearby defense or a matching grand total.
    explained = [block for block in unhit if (block["file"], tuple(block["span"])) in expected]
    missing = [block for block in unhit if (block["file"], tuple(block["span"])) not in expected]
    raw = sum(block["statements"] for block in blocks)
    hit = sum(block["statements"] for block in blocks if block["count"])
    result = {
        "status": "incomplete" if missing else "explained",
        "qualification": "not-evaluated",
        "unit": "native statement coverage with conditional source reasoning; not branch or MC/DC qualification",
        "sources": identity,
        "dependencies": pinned,
        "profiles": [{"bytes": len(data), "sha256": v.digest(data)} for data in (parent, child)],
        "mode": profiles[0][0],
        "raw": {"blocks": len(blocks), "statements": raw, "statements_hit": hit},
        "reachable_under_assumptions": {"statements": raw - sum(block["statements"] for block in explained), "statements_hit": hit},
        "unhit": unhit,
        "unexplained": missing,
        "defenses": defenses,
    }
    if compiler == "1.27.2":
        result["compiler_weights"] = profileweights.reconcile(root, "internal/admission", blocks)
    return result
