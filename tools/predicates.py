"""Bind format and directory-constructor input pairs to native outcomes and fixed source semantics."""

from collections.abc import Callable
import base64
import copy
import itertools
from pathlib import Path, PurePosixPath

from tools import admission, equality, verify as v

SOURCE = "37e195bcb9412502763e761740705d08e4ec57cd038d911f13068a97ec6e3612"
DIRECTORY = "935437c56a04d51978c2d2508b0c09b8f1dc51f03e58a6af089f926858ec068b"
HITS = 74
EDGE = "eee04d4802e2808f20485b17d890c5d50311f3be0d08f2157516d7b196d3410a"
METADATA = "55b76eb2e81a27631ed3515ceb948dfd31329edc67c2b68bbf602e5137ac30a2"
# Retained native facts are admitted by their reviewed archive identity, never by a caller's summary.
ARCHIVES = {
    "admission-structure": "e2e7c5a6d4e30f7be9575bd73a9e47e90608fb865674b22ca93e07c91710da94",
    "admission-edges": "76e396c3e17f244804311c01f97f31d541ca9078aa22be0059ea709feeaf8307",
}
REPAIRED = {
    "material-geometry": "f9f7864ae4c3a5b5c8d181a70467aef9d669d48bcefcda40c705e2bcc3a25f25",
    "material-conditions": "7eb9e5df1eb64ab518b3f2a3ca4e010b3e932490c11d3ed45322aaaa7d4866db",
}
# Fixed fixture bodies and public data establish the inputs of unconditional native cases.
# Their complete native terminals and counters are required separately; source text alone is not execution.
FIXTURES = {
    "internal/admission/node_test.go": "de38eef43b626ba8fc519946c36c2a6dde2a2390fbbee5b9c1650f63e53b4ae6",
    "internal/admission/boundaries_test.go": "455b7c6deee83d169a4ce053440147428165590c235df720b8fd649cc079f494",
    "internal/admission/identity_test.go": "97593a81f1e68124baf57857f5085c67e45b98534ea23ce5a625155f85b145d1",
    "internal/admission/fault_linux_amd64_test.go": "9657ff13d0c3796cf32f5588d51943334f78f895e2c2cdde9df230a03cdfd3b2",
    "internal/admission/model_test.go": "770fbaa5a6480e787627c700a3b476ad330449906033dd495829854d81079ab1",
    "internal/admission/directory_test.go": "646f0af54950a9ca3008377bfa1f8f83b321652cc88871018decaa3977a9ab01",
    "internal/admission/loops_test.go": "9666deff8d35ba5e2becdd58931ccd468eefb092cb0b6b990e8e8ebcdd61e438",
    "internal/admission/loading_linux_amd64_test.go": "ae2040e552af80e050423ed5fc81f567de4c54415b3f88c955661dc769a16e86",
    "tests/fixtures/admission-v1.json": "c4ae12e156e14c65a1f10f5b800d0f06998509c1b4861b16ac8658a24192e64a",
    "tests/fixtures/star-a/ca.pem": "127a3ebb3c92a844de44431ad50da1071cae5a3db0c115bc355f3bc03261523d",
    "tests/fixtures/star-a/cert.pem": "c6974a734b101ea832a036942ed126a2493e324f67f61151cb51b09cc3b67bd5",
    "tests/fixtures/star-a/key.pem": "906944f5643b812ac1f66dc1490e57c524e257a50fcd00d66af3e33b1f4d983b",
    "tests/fixtures/star-a/admission.pub": "bb06ecd5754692faf9ea21efdec3ebd59b03cbb2062a85861169ad0786282676",
    "tests/fixtures/star-a/login.json": "d26c51fde5791bbf24f6ecec4c47dc87dea36cf13c8d2213c22297ee524b8da0",
}
COUNTERS = {
    "TestDirectoryConflicts": [("ADMISSION-CONFLICTS", 117)],
    "TestDirectoryModel": [("ADMISSION-FINITE", 306026), ("ADMISSION-ASSURANCE", 306026)],
    "TestNodeJoin": [("ADMISSION-NODE-RETRY", 16)],
    "TestNodeModel": [("ADMISSION-NODE-FINITE", 12971)],
    "TestLoadBoundaries": [("ADMISSION-IDENTITY-FILES", 29)],
    "TestNodeOpen": [("ADMISSION-NODE-RESOLVER", 8), ("ADMISSION-NODE-OPEN", 18)],
    "TestNodeState": [("ADMISSION-NODE-STATE", 10)],
    "TestNodeRegistration": [("ADMISSION-NODE-REGISTER", 170)],
    "TestNodePause": [("ADMISSION-NODE-PAUSE", 10)],
    "TestAdmissionCredentials": [("ADMISSION-CREDENTIALS", 56)],
    "TestIdentityRules": [("ADMISSION-IDENTITY-RULES", 306)],
    "TestLoadFault": [("ADMISSION-IDENTITY-FAULT", 1501)],
}


def coordinate(identity: str, *, acquisition: bool = False) -> str:
    """Relocate only reviewed unchanged predicates; the replaced file guard requires new witnesses."""
    if not acquisition or not identity.startswith("internal/admission/identity.go:"):
        return identity
    offset = int(identity.rsplit(":", 1)[1])
    if offset == 1719:
        return "internal/admission/identity.go:1722"
    if offset not in {2348, 2561, 2854, 3855, 4042, 4397, 4493, 5648, 5942, 6195, 6614, 6882, 6972, 7355}:
        v.reject("predicates-unreviewed-coordinate", identity)
    return "internal/admission/identity.go:" + str(offset + 189)


def archives(root: Path) -> dict[str, str]:
    """Select reviewed retained facts without making an old source catalog qualify a new implementation."""
    if admission.matches(root, "internal/admission/identity.go", admission.MATERIAL):
        from tools import admissioncompiler

        return admissioncompiler.ARTIFACTS if admissioncompiler.upgraded(root) else REPAIRED
    return ARCHIVES


def sources(root: Path, inputs: dict[str, str], packages: list[dict]) -> dict[str, str]:
    """Bind native Admission imports, all package fixtures/platform files, locks and collector inputs."""
    module = "github.com/eosforge/astra/"
    directories = {row["ImportPath"][len(module) :] for row in packages if row["ImportPath"].startswith(module)}
    target = next((row for row in packages if row["ImportPath"] == module + "internal/admission"), None)
    if target is None:
        v.reject("predicates-input-dependencies")
    imports = target.get("Imports", []) + target.get("TestImports", []) + target.get("XTestImports", [])
    if any(name[len(module) :] not in directories for name in imports if name.startswith(module)):
        v.reject("predicates-input-dependencies")
    directories.add("tools/decisions")
    selected = (
        lambda name: name.endswith(".go") and PurePosixPath(name).parent.as_posix() in directories or name in {"go.mod", "go.sum", "dependencies.lock.json"}
    )
    expected = {name: digest for name, digest in inputs.items() if selected(name)}
    actual = {path.relative_to(root).as_posix() for name in directories for path in v.inside(root, name).glob("*.go")}
    actual.update(("go.mod", "go.sum", "dependencies.lock.json"))
    if actual != set(expected):
        v.reject("predicates-input-inventory")
    for name, digest in expected.items():
        if v.file_digest(v.inside(root, name)) != digest:
            v.reject("predicates-input-drift", name)
    return expected


def configuration(check: dict) -> None:
    """Keep the four-function scope, exact native selection and successful assertion budget fixed."""
    if (
        check.get("decisions") != "admission-predicates-v2"
        or check["component"] != "admission"
        or check["package"] != "github.com/eosforge/astra/internal/admission"
        or check["argv"] != ["go", "test", "-json", "-count=1", "-parallel=1", "-p=4", "-timeout=180s", "-run=^TestPredicates$", "./internal/admission"]
        or check["expected_tests"] != ["TestPredicates"]
        or v.encode(check["probes"]) != v.encode([{"contract": "ADMISSION-PREDICATES", "test": "TestPredicates", "minimum_hits": HITS}])
    ):
        v.reject("predicates-configuration")


def expected() -> list[dict]:
    """Derive exact semantic witnesses from the public alphabet, enumerated roles and member format contract."""
    rows = []
    names = [("a", ""), ("a" * 64, "a" * 65), ("a", "`"), ("z", "{"), ("A", "@"), ("Z", "["), ("0", "/"), ("9", ":"), (".", "/"), ("_", "^"), ("-", "/")]
    for function, pairs in (("Name", names), ("Role", [(0, value) for value in (1, 2, 3, 4)])):
        for condition, (before, after) in enumerate(pairs):
            rows.append(
                {
                    "function": function,
                    "condition": condition,
                    "before": {"input": before, "result": function == "Name"},
                    "after": {"input": after, "result": function != "Name"},
                }
            )
    changes = [
        ("galaxy", ""),
        ("group", ""),
        ("id", ""),
        ("id", base64.b64encode(b"a" * 129).decode()),
        ("id", "/w=="),
        ("epoch", 0),
        ("role", 0),
        ("principal", base64.b64encode(bytes([1] * 31)).decode()),
        ("advertise", "127.0.0.1:0"),
    ]
    for condition in range(10):
        before = equality.member()
        after = copy.deepcopy(before) if condition else None
        if condition:
            field, value = changes[condition - 1]
            # encoding/json omits protobuf fields carrying their zero value.
            if value in ("", 0):
                del after[field]
            else:
                after[field] = value
        rows.append({"function": "Valid", "condition": condition, "before": {"input": before, "result": True}, "after": {"input": after, "result": False}})
    for condition, (field, value) in enumerate((("identity", False), ("galaxy", ""), ("role", 0), ("role", 2), ("maximum", 0), ("maximum", 16385))):
        before = {"identity": True, "galaxy": "alpha", "role": 3, "maximum": 16384 if condition == 5 else 1}
        after = {**before, field: value}
        rows.append(
            {"function": "NewDirectory", "condition": condition, "before": {"input": before, "result": True}, "after": {"input": after, "result": False}}
        )
    return rows


def observations(data: bytes, check: dict, root: Path) -> dict[str, int]:
    """Accept all thirty-one real pairs, never summaries, substituted inputs or changed production guards."""
    configuration(check)
    identity = v.inside(root, "internal/admission/identity.go")
    if not identity.is_file() or v.file_digest(identity) != SOURCE:
        # Load's acquisition repair leaves these public predicates unchanged. Require the
        # complete reviewed repair, without advancing the historical compiler coordinates below.
        if any(not admission.matches(root, name, admission.MATERIAL) for name in admission.MATERIAL):
            v.reject("predicates-source")
    directory = v.inside(root, "internal/admission/directory.go")
    if not directory.is_file() or v.file_digest(directory) != DIRECTORY:
        v.reject("predicates-source")
    rows = equality.frames(data, check["package"], test="TestPredicates", marker="ADMISSION-PREDICATES ", maximum=31)
    if v.encode(rows) != v.encode(expected()):
        v.reject("predicates-pairs")
    return {"ADMISSION-PREDICATES": HITS}


def witnesses(*, acquisition: bool = False) -> list[dict]:
    """Derive total-input condition pairs from fixed public-input axioms, without completing nil fields."""
    rows = []
    for item in expected():
        function, condition = item["function"], item["condition"]
        values = [item[side]["input"] for side in ("before", "after")]
        if function == "Name":
            if condition < 2:
                identity = "internal/admission/identity.go:6882"
                vectors = [[len(value) == 0, len(value) > 64] for value in values]
            else:
                identity, condition = "internal/admission/identity.go:6972", condition - 2
                vectors = [[c >= "a", c <= "z", c >= "A", c <= "Z", c >= "0", c <= "9", c == ".", c == "_", c == "-"] for c in values]
        elif function == "Role":
            identity = "internal/admission/identity.go:6614"
            vectors = [[value == role for role in (1, 2, 3, 4)] for value in values]
        elif function == "NewDirectory":
            identity = "internal/admission/directory.go:925"
            vectors = [
                [
                    not value["identity"],
                    bool(value["galaxy"]),
                    value["role"] in (1, 2, 3, 4),
                    value["role"] == 2,
                    value["maximum"] < 1,
                    value["maximum"] > 16384,
                ]
                for value in values
            ]
        else:
            # A nil member has undefined fields. Endpoint is a separate decision, not an operand of this guard.
            if condition in (0, 9):
                continue
            identity = "internal/admission/identity.go:6195"
            vectors = []
            for value in values:
                key = base64.b64decode(value.get("id", ""), validate=True)
                try:
                    key.decode("utf-8")
                    valid = True
                except UnicodeDecodeError:
                    valid = False
                vectors.append(
                    [
                        False,
                        bool(value.get("galaxy")),
                        bool(value.get("group")),
                        not key,
                        len(key) > 128,
                        valid,
                        not value.get("epoch"),
                        value.get("role") in (1, 2, 3, 4),
                        len(base64.b64decode(value["principal"], validate=True)) != 32,
                    ]
                )
        rows.append(
            {
                "decision": coordinate(identity, acquisition=acquisition),
                "condition": condition,
                **{
                    side: {"values": vector, "result": item[side]["result"] if function == "Role" else not item[side]["result"]}
                    for side, vector in zip(("before", "after"), vectors, strict=True)
                },
            }
        )
    for condition in range(2, 9):
        item = equality.expected(condition)
        rows.append(
            {
                "decision": "internal/admission/directory.go:6403",
                "condition": condition,
                **{
                    side: {
                        "values": [True, True] + [item[side]["a"][field] == item[side]["b"][field] for field in equality.FIELDS],
                        "result": item[side]["result"],
                    }
                    for side in ("before", "after")
                },
            }
        )
    return rows


def fixtures(root: Path, events: bytes, *, acquisition: bool = False) -> dict:
    """Bind literal fixture inputs to completed native cases, exact counters and the complete file-fault matrix."""
    from tools import materials

    selected_fixtures = dict(FIXTURES)
    if acquisition:
        selected_fixtures["internal/admission/fault_linux_amd64_test.go"] = "9442a26e59b8cae0f1db11c0b9cb4862346b358ddb2d7a7e8d56b21152e72e8c"
    for name, digest in selected_fixtures.items():
        if v.file_digest(v.inside(root, name)) != digest:
            v.reject("predicates-fixture-drift", name)
    selected = {name: [] for name in COUNTERS}
    for line in events.splitlines():
        item = v.decode(line)
        if item.get("Test") in selected:
            selected[item["Test"]].append(line + b"\n")
    streams = {name: b"".join(parts) for name, parts in selected.items()}
    package = "github.com/eosforge/astra/internal/admission"
    for name, wanted in COUNTERS.items():
        rows = equality.frames(streams[name], package, test=name, marker="ASTRA-CONTRACT ", maximum=len(wanted))
        if v.encode(rows) != v.encode([{"contract": contract, "hits": hits} for contract, hits in wanted]):
            v.reject("predicates-fixture-counter", name)
    rows = equality.frames(streams["TestLoadFault"], package, test="TestLoadFault", marker="ADMISSION-IDENTITY-FAULT ", maximum=120)
    wanted = [materials.expected(fault, slot, phase) for fault in materials.FAULTS for slot in range(5) for phase in range(3)]
    if v.encode(rows) != v.encode(wanted):
        v.reject("predicates-fixture-faults")
    return {"sources": selected_fixtures, "counters": COUNTERS, "fault_cells": len(rows)}


def boundaries(*, acquisition: bool = False) -> list[dict]:
    """Describe fixed, executed input pairs whose nontarget total predicates stay equal.

    These are source-bound input semantics, not extra native operand hits. Cases involving
    undefined nil fields, coupled changes or an unproven decoder result are omitted.
    """
    groups = (
        (
            "directory.go:1678",
            [True, False, False, True, True, False, False, False, False],
            (2,),
            False,
            "TestNodeModel",
            "An Astrolabe member is installed by its Astrolabe Node; TestDirectoryBoundaries rejects an Astrolabe at a Polaris directory. Other predicate values stay fixed.",
        ),
        (
            "directory.go:3897",
            [False, False, True],
            (0,),
            False,
            "TestDirectoryConflicts",
            "Fresh same-principal replacement versus scenario 5's other principal reusing the endpoint; both IDs differ from the retained member.",
        ),
        (
            "identity.go:2348",
            [False, False],
            (0,),
            False,
            "TestLoadBoundaries",
            "Scenario 6 replaces only admission.pub with 31 bytes; the unchanged login fixture remains valid.",
        ),
        (
            "directory.go:1678",
            [True, False, True, False, True, False, False, False, False],
            (1, 3),
            False,
            "TestDirectoryModel",
            "First valid Star versus the same member with foreign galaxy or Planet role; nil previous ID sorts before every valid nonempty ID.",
        ),
        (
            "directory.go:1678",
            [True, False, True, True, False, False, False, False, False],
            (4,),
            False,
            "TestDirectoryBoundaries",
            "First Polaris versus first Astrolabe at a Polaris directory; both roles are valid and neither is Star.",
        ),
        (
            "directory.go:1678",
            [True, False, True, False, True, True, False, False, False],
            (6, 7),
            False,
            "TestDirectoryConflicts",
            "Distinct ordered Stars from the finite model versus reversed IDs from TestDirectoryBoundaries or duplicate principal from conflict scenario 6; addresses stay distinct.",
        ),
        (
            "directory.go:2397",
            [True, True, False, False, False, True],
            (1,),
            False,
            "TestDirectoryConflicts",
            "Identical retry versus an equal-epoch Group change; ID, role and endpoint stay identical.",
        ),
        (
            "directory.go:2397",
            [False, False, False, False, True, False],
            (2, 3),
            False,
            "TestDirectoryConflicts",
            "Fresh replacement versus independent role or endpoint changes, retaining its newer epoch and different ID.",
        ),
        (
            "directory.go:2934",
            [False, False],
            (0,),
            False,
            "TestDirectoryConflicts",
            "Distinct members versus a new principal with the retained member's endpoint and a different ID, conflict scenario 5.",
        ),
        (
            "directory.go:3434",
            [False, True, True, False, False, False, True],
            (2,),
            False,
            "TestDirectoryConflicts",
            "Identical handshake retry versus an equal-epoch Group change; all other compared fields remain equal.",
        ),
        (
            "directory.go:3434",
            [False, False, False, False, False, True, False],
            (3, 4),
            False,
            "TestDirectoryConflicts",
            "Fresh handshake replacement versus independent role or endpoint changes, retaining its newer epoch and different ID.",
        ),
        (
            "directory.go:3897",
            [True, False, False],
            (1,),
            False,
            "TestDirectoryConflicts",
            "A second principal from the finite model versus conflict scenario 4 reusing the known ID; its endpoint remains distinct.",
        ),
        (
            "identity.go:4042",
            [False, True, False, False, True],
            (2, 3),
            False,
            "TestIdentityRules",
            "First username key versus repeated username or unknown alias; successful string-token parsing is unchanged.",
        ),
        ("node.go:6316", [False, False], (0,), False, "TestNodeJoin", "Transient Unavailable versus successful registration; neither error is fatal."),
        # Open's public argument cases keep the other arguments unchanged, including role predicates.
        (
            "node.go:1191",
            [False, False, True, True, False, True],
            range(5),
            False,
            "TestNodeOpen",
            "Valid Polaris arguments versus invalid advertise, nil identity, empty galaxy/group and Star role; the other role inequality stays true.",
        ),
        ("node.go:3379", [False, False], range(2), False, "TestNodeState", "Fresh outgoing metadata versus exactly one existing admission/signature value."),
        (
            "node.go:4231",
            [False, False, False, False, False, True],
            range(1, 6),
            False,
            "TestNodeRegistration",
            "Healthy recovery versus separately signed galaxy, role, group, advertise or principal changes; all members remain structurally valid.",
        ),
        (
            "node.go:7928",
            [False] * 5,
            range(5),
            False,
            "TestNodePause",
            "Nil error versus ErrIdentity and each of the four distinct permanent gRPC status codes.",
        ),
        (
            "directory.go:4423",
            [False, False, True],
            range(1, 3),
            False,
            "TestAdmissionCredentials",
            "Healthy signed Star versus a signed beta galaxy or Astrolabe role, preserving signature and member validity.",
        ),
        (
            "directory.go:5204",
            [False, False],
            range(2),
            False,
            "TestAdmissionCredentials",
            "One credential and one signature versus deleting exactly one metadata value.",
        ),
        (
            "identity.go:5648",
            [False, False, False],
            range(2),
            False,
            "TestIdentityRules",
            "Bounded nonempty signed member payload versus empty or 1025-byte signed payload; all signatures have exactly 64 bytes.",
        ),
        (
            "identity.go:7355",
            [False] * 7,
            range(1, 7),
            False,
            "TestSharedVectors",
            "127.0.0.1:7443 versus leading-zero port, zero port, unspecified, multicast, mapped IPv4 and zoned IPv6; each address parses, and all other endpoint predicates retain their values.",
        ),
        (
            "identity.go:4493",
            [False, False, True, False, False],
            (0, 2, 3, 4),
            False,
            "TestIdentityRules",
            "Complete two-field login versus a trailing object, invalid username, empty password or 1025-byte password; all other fields and decoder completion properties are fixed.",
        ),
        (
            "identity.go:1988",
            [False, True, False, False, False],
            (1, 2, 3),
            False,
            "TestLoadFault",
            "Disarmed native-file recovery versus restat, read or close injection; nonnil stat metadata, bounded data and unrelated error results remain unchanged.",
        ),
    )
    result = []
    for name, baseline, conditions, outcome, test, basis in groups:
        if acquisition and name == "identity.go:1988":
            # The new pre-read guard is separate. Existing restat wraps FileInfo, which also
            # changes SameFile's concrete-type result, so it cannot prove kind independence.
            name, baseline, conditions = "identity.go:2223", [False, False, False], (0, 1)
            basis = "Validated unchanged native metadata followed by independent read or close injection; payload size and the other error remain fixed."
            identity = "internal/admission/" + name
        else:
            identity = coordinate("internal/admission/" + name, acquisition=acquisition)
        for condition in conditions:
            changed = baseline.copy()
            changed[condition] = not changed[condition]
            result.append(
                {
                    "pair": {
                        "decision": identity,
                        "condition": condition,
                        "before": {"values": baseline.copy(), "result": outcome},
                        "after": {"values": changed, "result": not outcome},
                    },
                    "test": test,
                    "basis": basis,
                }
            )
    return result


def guards(*, acquisition: bool = False) -> list[dict]:
    """Describe only source-bound nil guards; an absent dereference has no Boolean value."""
    cases = (
        (
            "directory.go:1678",
            0,
            [True, False, True, False, True, False, False, False, False],
            [False, None, True, None, None, False, None, None, None],
            False,
            "TestDirectoryModel",
            "First valid Star versus nil; directory role and index remain defined, while every member field is absent.",
        ),
        ("directory.go:2299", 0, [False, False], [True, None], False, "TestDirectoryModel", "Absent incoming member has no Epoch."),
        ("directory.go:4423", 0, [False, False, True], [True, None, None], False, "TestAdmissionCredentials", "Rejected signature returns a nil member."),
        ("directory.go:6403", 0, [True] * 9, [False, True] + [None] * 7, True, "TestSame", "Nil left member has no comparable fields."),
        ("directory.go:6403", 1, [True] * 9, [True, False] + [None] * 7, True, "TestSame", "Nil right member has no comparable fields."),
        ("identity.go:1719", 0, [False, True], [True, None], False, "TestLoadFault", "Injected Lstat error returns nil metadata."),
        (
            "identity.go:1988",
            0,
            [False, True, False, False, False],
            [True, None, False, False, False],
            False,
            "TestLoadFault",
            "Injected Stat error returns nil metadata; the same native file still completes its bounded read and close.",
        ),
        (
            "identity.go:6195",
            0,
            [False, True, True, False, False, True, False, True, False],
            [True] + [None] * 8,
            False,
            "TestPredicates",
            "Nil member has no format fields; the native predicate pair explicitly retains both inputs.",
        ),
        (
            "node.go:4231",
            0,
            [False, False, False, False, False, True],
            [True] + [None] * 5,
            False,
            "TestNodeRegistration",
            "Signature refusal returns nil instead of a registered member; subsequent healthy recovery supplies the defined side.",
        ),
    )
    result = []
    for name, condition, before, after, result_value, test, basis in cases:
        if acquisition and name == "identity.go:1988":
            identity = "internal/admission/identity.go:2006"
            before, after = [False, True, True], [True, None, None]
            basis = "Injected Stat error returns nil metadata and prevents reading; native recovery retains regular metadata and the same inode."
        else:
            identity = coordinate("internal/admission/" + name, acquisition=acquisition)
        result.append(
            {
                "pair": {
                    "decision": identity,
                    "condition": condition,
                    "before": {"values": before, "result": result_value},
                    "after": {"values": after, "result": not result_value},
                },
                "test": test,
                "basis": basis,
            }
        )
    return result


def guarded(decisions: dict, observed: dict, *, acquisition: bool = False) -> list[dict]:
    """Certify the nine fixed nil-input pairs, never arbitrary caller-supplied masking."""
    from tools import authority, logic

    proofs = []
    for row in guards(acquisition=acquisition):
        pair = row["pair"]
        decision, target = decisions[pair["decision"]], pair["condition"]
        before, after = (pair[side]["values"] for side in ("before", "after"))
        vectors = []
        for side in ("before", "after"):
            vector, result = authority.project(decision, pair[side]["values"])
            if (vector, result) not in observed[decision["id"]] or vector[target] == "0" or result != pair[side]["result"]:
                v.reject("predicates-guard-native-witness", decision["id"])
            vectors.append({"values": vector, "result": result})
        if (
            any(type(value) is not bool for value in before)
            or type(after[target]) is not bool
            or before[target] == after[target]
            or not any(value is None for value in after)
            or any(left != right for index, (left, right) in enumerate(zip(before, after, strict=True)) if index != target and right is not None)
        ):
            v.reject("predicates-guard-domain", decision["id"])
        completed = [left if right is None else right for left, right in zip(before, after, strict=True)]
        for values, side in ((before, "before"), (completed, "after")):
            if logic.cube(decision, "".join("2" if value else "1" for value in values)) != pair[side]["result"]:
                v.reject("predicates-guard-completion", decision["id"])
        proofs.append({**row, "criterion": "defined-domain-short-circuit-v1", "native_vectors": vectors})
    return proofs


def masking() -> list[dict]:
    """Retain two concrete epoch comparisons whose other changed predicates are universally masked."""
    cases = (
        (
            "directory.go:2397",
            0,
            [False, False, False, False, True, False],
            [True, False, False, False, False, False],
            "TestDirectoryReplacement",
            "A newer different ID is accepted; an equal-epoch different ID is rejected. Both role and address agree, and both IDs differ, masking the changed greater-than comparison.",
        ),
        (
            "directory.go:3434",
            0,
            [False, False, False, False, False, True, False],
            [True, False, False, False, False, False, False],
            "TestDirectoryReplacement",
            "A newer different ID is accepted; the older different ID is subsequently rejected. Unequal epochs and IDs mask the changed greater-than comparison.",
        ),
    )
    return [
        {
            "pair": {
                "decision": "internal/admission/" + name,
                "condition": condition,
                "before": {"values": before, "result": False},
                "after": {"values": after, "result": True},
            },
            "test": test,
            "basis": basis,
        }
        for name, condition, before, after, test, basis in cases
    ]


def mask(decision: dict, pair: dict, observed: set) -> dict:
    """Prove opposite outcomes for every completion of all changed nontarget concrete values."""
    from tools import authority, logic

    try:
        return authority.correlate_pair(decision, pair, observed)
    except v.Invalid as error:
        if str(error).split(":", 1)[0] != "authority-pair-coupled-change":
            raise
    before, after = (pair[side]["values"] for side in ("before", "after"))
    fixed = ["0"] * len(before)
    for index, (left, right) in enumerate(zip(before, after, strict=True)):
        if left == right:
            fixed[index] = "2" if left else "1"
    fixed[pair["condition"]] = "0"
    for side in ("before", "after"):
        values = fixed.copy()
        values[pair["condition"]] = "2" if pair[side]["values"][pair["condition"]] else "1"
        if logic.cube(decision, values) is not pair[side]["result"]:
            v.reject("predicates-pair-coupled", decision["id"])
    return {
        **pair,
        "criterion": "concrete-common-cube-v1",
        "fixed": "".join(fixed),
        "native_vectors": [dict(zip(("values", "result"), authority.project(decision, pair[side]["values"]))) for side in ("before", "after")],
    }


def edge_inputs() -> list[dict]:
    """Anchor the two new edge pairs to literal identities and the documented Member wire fields."""
    old = {
        "galaxy": "alpha",
        "id": base64.b64encode(b"node-01-01").decode(),
        "principal": base64.b64encode(bytes(31) + b"\x01").decode(),
        "advertise": "127.0.0.1:7401",
        "epoch": 1,
        "role": 1,
        "group": "default",
    }
    rows = []
    for epoch in (2, 1):
        candidate = {**old, "epoch": epoch, "id": base64.b64encode(b"node-01-02").decode()}
        rows.append(
            {"kind": "epoch", "old": old.copy(), "candidate": candidate, "accepted": epoch == 2, "snapshot": [(candidate if epoch == 2 else old).copy()]}
        )
    # Tags 1, 2, 3, 4, 5, 7 and 8; byte zero is an illegal trailing field tag.
    wire = b"\x0a\x05alpha\x12\x0anode-01-01\x1a\x20" + bytes(31) + b"\x01\x22\x0e127.0.0.1:7401\x28\x01\x38\x01\x42\x07default"
    for malformed in (False, True):
        rows.append(
            {
                "kind": "wire",
                "input": base64.b64encode(wire + (b"\x00" if malformed else b"")).decode(),
                "malformed": malformed,
                "partial": old.copy(),
                "accepted": not malformed,
                "returned": None if malformed else old.copy(),
            }
        )
    return rows


def edge_observations(data: bytes, root: Path) -> list[dict]:
    """Require exact public inputs, complete snapshots and all twenty executed edge assertions."""
    if v.file_digest(root / "tests/fixtures/admission.go.in") != EDGE:
        v.reject("predicates-edge-source")
    package, test = "github.com/eosforge/astra/internal/admission", "TestAdmissionEdges"
    rows = equality.frames(data, package, test=test, marker="ADMISSION-EDGE ", maximum=4)
    if v.encode(rows) != v.encode(edge_inputs()):
        v.reject("predicates-edge-inputs")
    # The shared marker belongs to each test separately; the unique input marker above
    # still checks the entire package stream and rejects observations from another test.
    selected = b"\n".join(line for line in data.splitlines() if v.decode(line).get("Test") == test)
    counters = equality.frames(selected, package, test=test, marker="ASTRA-CONTRACT ", maximum=1)
    if v.encode(counters) != v.encode([{"contract": "ADMISSION-EDGE", "hits": 20}]):
        v.reject("predicates-edge-counter")
    return rows


def edges(root: Path, trace: dict, events: bytes, *, acquisition: bool = False) -> dict:
    """Qualify fixed incremental pairs; provenance and archive retirement remain caller obligations."""
    from tools import authority, defenses, logic, structure

    defenses.sources(root, acquisition=acquisition)
    if v.digest(v.encode(trace["files"])) != structure.domain(acquisition=acquisition)["forest"]:
        v.reject("predicates-forest")
    tests = ["TestAdmissionEdges", "TestLoadMetadata"] if acquisition else ["TestAdmissionEdges"]
    structure.terminals(events, tests)
    inputs = edge_observations(events, root)
    observed, processes = logic.observe(trace, events, "github.com/eosforge/astra/internal/admission", len(tests))
    if processes != 1:
        v.reject("predicates-edge-processes")
    decisions = logic.inventory(trace)
    pairs = []
    for name, target, before, after in (
        ("directory.go:3434", 1, [False, False, False, False, False, True, False], [False, True, False, False, False, False, False]),
        ("identity.go:5942", 0, [False, True], [True, True]),
    ):
        identity = coordinate("internal/admission/" + name, acquisition=acquisition)
        pair = {"decision": identity, "condition": target, "before": {"values": before, "result": False}, "after": {"values": after, "result": True}}
        pairs.append(mask(decisions[identity], pair, set(observed[identity])))
    if acquisition:
        if v.file_digest(root / "tests/fixtures/admission-metadata.go.in") != METADATA:
            v.reject("predicates-metadata-source")
        inputs = {"edge": inputs, "metadata": metadata_observations(events)}
        identity = "internal/admission/identity.go:2006"
        pair = {
            "decision": identity,
            "condition": 1,
            "before": {"values": [False, True, True], "result": False},
            "after": {"values": [False, False, True], "result": True},
        }
        pairs.append(authority.correlate_pair(decisions[identity], pair, set(observed[identity])))
    return {
        "pairs": pairs,
        "inputs": inputs,
        "processes": processes,
        "qualification": "three-concrete-input-pairs-only" if acquisition else "two-concrete-input-pairs-only",
    }


def metadata_observations(events: bytes) -> list[dict]:
    """Require the native fixture to retain stat success/inode equality, suppress reads and close both handles."""
    package, test = "github.com/eosforge/astra/internal/admission", "TestLoadMetadata"
    rows = equality.frames(events, package, test=test, marker="ADMISSION-METADATA ", maximum=2)
    expected_rows = [{"regular": regular, "same_file": True, "accepted": regular, "read": regular, "closed": True} for regular in (True, False)]
    if v.encode(rows) != v.encode(expected_rows):
        v.reject("predicates-metadata-inputs")
    selected = b"\n".join(line for line in events.splitlines() if v.decode(line).get("Test") == test)
    counters = equality.frames(selected, package, test=test, marker="ASTRA-CONTRACT ", maximum=1)
    if v.encode(counters) != v.encode([{"contract": "ADMISSION-METADATA", "hits": 12}]):
        v.reject("predicates-metadata-counter")
    return rows


def domains(decisions: dict, observed: dict, dependency: dict[str, bytes], *, acquisition: bool = False) -> dict:
    """Bind existing reachability proofs to real dependency bytes and reject native contradictions."""
    from tools import logic, structure

    if not isinstance(dependency, dict) or set(dependency) != set(structure.DEPENDENCIES):
        v.reject("predicates-dependency-scope")
    for name, digest in structure.DEPENDENCIES.items():
        if not isinstance(dependency[name], bytes) or v.digest(dependency[name]) != digest:
            v.reject("predicates-dependency-drift", name)
    assumptions = structure.domain(acquisition=acquisition)["assumptions"]
    outcomes = structure.boolean(decisions, observed, assumptions)
    if outcomes["missing"]:
        v.reject("predicates-domain-outcomes")
    literals, conditional, bindings = [], [], {}
    for identity, decision in decisions.items():
        if decision["kind"] == "return" and decision["text"] in {"true", "false"}:
            literals.append({"decision": identity, "condition": 0, "reason": "literal-return-not-variable"})
    for identity, atom, impossible, reason in assumptions:
        conditional.append({"decision": identity, "condition": atom, "outcome": impossible, "reason": reason, **structure.REASONS[reason]})
        bindings.setdefault(identity, {})[atom] = "1" if impossible else "2"
    proofs = []
    for identity, fixed in bindings.items():
        # Substitution is justified only for an atom whose evaluated opposite outcome is impossible.
        # Filled characters are a reduced decision's algebraic values, never new native operand hits.
        originals = {}
        for vector, result in observed[identity]:
            reduced = "".join(fixed.get(index, value) if value == "0" else value for index, value in enumerate(vector))
            originals.setdefault((reduced, result), []).append(vector)
        witnesses, _, complete = logic.candidates(decisions[identity], originals, logic.COMPARISONS, certify=True)
        if not complete:
            v.reject("predicates-domain-budget")
        for atom, pair in witnesses.items():
            if atom in fixed:
                v.reject("predicates-domain-fictitious-hit")
            native = [min(originals[pair[side], outcome]) for side, outcome in (("false", False), ("true", True))]
            if any(vector[atom] == "0" for vector in native):
                v.reject("predicates-domain-unobserved-target")
            proofs.append(
                {
                    "decision": identity,
                    "condition": atom,
                    "criterion": "source-reduced-common-cube-v1",
                    "witness": pair,
                    "substitutions": {str(index): value == "2" for index, value in fixed.items()},
                    "native_vectors": [{"values": vector, "result": outcome} for vector, outcome in zip(native, (False, True), strict=True)],
                }
            )
    return {
        "literal_exclusions": literals,
        "domain_exclusions": conditional,
        "pairs": proofs,
        "dependencies": {name: {"bytes": len(data), "sha256": v.digest(data)} for name, data in dependency.items()},
    }


def relations() -> tuple:
    """Overapproximate possible predicate values using seven source-bound implications.

    Unmentioned values remain free. These implications constrain symbolic values;
    they neither manufacture native evaluations nor make failed operations pass.
    """
    return (
        (
            "directory.go:1678",
            5,
            lambda values: not values[0] or values[5] or not values[6],
            "A valid first member has a nonempty ID and nil predecessor, so Compare(previous, ID) is negative.",
            "TestDirectoryBoundaries",
        ),
        (
            "directory.go:2397",
            4,
            lambda values: values[0] != values[4] and (not values[1] or values[0]),
            "The earlier older-epoch branch continues. Equal and newer are complements here; same implies equal epochs.",
            "TestDirectoryConflicts",
        ),
        (
            "directory.go:3434",
            5,
            lambda values: sum(values[index] for index in (0, 1, 5)) == 1 and (not values[2] or values[1]),
            "Unsigned stable epochs satisfy trichotomy, and same requires equal epochs while the directory lock is held.",
            "TestDirectoryConflicts",
        ),
        (
            "identity.go:3855",
            0,
            lambda values: not values[0] or values[1],
            "Every error return of the pinned Decoder.Token returns nil, which differs from the opening object delimiter.",
            "TestIdentityRules",
        ),
        (
            "identity.go:4042",
            0,
            lambda values: not values[0] or not values[1],
            "Every error return of the pinned Decoder.Token returns nil, so the string type assertion cannot succeed.",
            "TestIdentityRules",
        ),
        (
            "identity.go:4493",
            1,
            lambda values: not values[1] or not values[2] or values[3],
            "The sole production caller creates an empty Identity. Both nonempty fields require both accepted keys; missing keys leave an invalid name or empty password.",
            "TestIdentity",
        ),
        (
            "identity.go:7355",
            0,
            lambda values: not values[0] or values[2],
            "Every error return of the pinned ParseAddrPort returns the zero AddrPort, whose port is zero.",
            "TestSharedVectors",
        ),
    )


def symbolic(decision: dict, target: int, relation: Callable[[tuple[bool, ...]], bool]) -> dict:
    """Exhaust a finite Boolean overapproximation and require a counterexample after removing its constraint."""
    from tools import logic

    if not 1 <= len(decision["atoms"]) <= 9 or type(target) is not int or not 0 <= target < len(decision["atoms"]):
        v.reject("predicates-coupling-scope", decision["id"])
    total, allowed = {}, {}
    for values in itertools.product((False, True), repeat=len(decision["atoms"])):
        vector = "".join("2" if value else "1" for value in values)
        outcome = logic.cube(decision, vector)
        total[vector, outcome] = 1
        if relation(values):
            allowed[vector, outcome] = 1
    if (
        not allowed
        or len(allowed) == len(total)
        or {outcome for _, outcome in allowed} != {False, True}
        or {vector[target] for vector, _ in allowed} != {"1", "2"}
    ):
        v.reject("predicates-coupling-vacuous", decision["id"])

    def witness(rows: dict[tuple[str, bool], int]) -> tuple[dict[str, str] | None, int]:
        """Search both single changes and changes masked under every completion of the common cube."""
        comparisons = 0
        for left, outcome in rows:
            if outcome:
                continue
            for right, result in rows:
                if not result or left[target] == right[target]:
                    continue
                comparisons += 1
                if comparisons > logic.COMPARISONS:
                    v.reject("predicates-coupling-budget", decision["id"])
                fixed = [a if a == b else "0" for a, b in zip(left, right, strict=True)]
                fixed[target] = "0"
                before, after = fixed.copy(), fixed.copy()
                before[target], after[target] = left[target], right[target]
                if logic.cube(decision, before) is False and logic.cube(decision, after) is True:
                    return {"false": left, "true": right, "fixed": "".join(fixed)}, comparisons
        return None, comparisons

    found, comparisons = witness(allowed)
    if found is not None:
        v.reject("predicates-coupling-independent", decision["id"])
    relaxed, _ = witness(total)
    if relaxed is None:
        v.reject("predicates-coupling-countercontrol", decision["id"])
    return {"total": len(total), "allowed": allowed, "comparisons": comparisons, "relaxed_witness": relaxed}


def coupling(root: Path, trace: dict, observed: dict, dependency: dict[str, bytes], *, acquisition: bool = False) -> dict:
    """Explain impossible common-cube pairs under explicit source assumptions, without counting them as hits."""
    from tools import defenses, logic, structure

    defenses.sources(root, acquisition=acquisition)
    if v.digest(v.encode(trace["files"])) != structure.domain(acquisition=acquisition)["forest"]:
        v.reject("predicates-forest")
    required = {**structure.DEPENDENCIES, "net/netip/netip.go": "32295f4761825d8c6fdade4dad093b08683bdd1945010bee8a90a298e18cf208"}
    if set(dependency) != set(required):
        v.reject("predicates-coupling-dependencies")
    for name, digest in required.items():
        if not isinstance(dependency[name], bytes) or v.digest(dependency[name]) != digest:
            v.reject("predicates-coupling-dependency-drift", name)
    decisions = logic.inventory(trace)
    proofs = []
    for name, target, relation, reason, test in relations():
        identity = coordinate("internal/admission/" + name, acquisition=acquisition)
        decision = decisions[identity]
        report = symbolic(decision, target, relation)
        values = observed.get(identity, {})
        if {outcome for _, outcome in values} != {False, True} or {vector[target] for vector, _ in values} - {"0"} != {"1", "2"}:
            v.reject("predicates-coupling-native-boundaries", identity)
        for vector, outcome in values:
            if not any(
                result == outcome and all(value == "0" or value == total[index] for index, value in enumerate(vector)) for total, result in report["allowed"]
            ):
                v.reject("predicates-coupling-contradicted", identity)
        proofs.append(
            {
                "decision": identity,
                "condition": target,
                "assumption": reason,
                "boundary_test": test,
                "criterion": "no-universal-common-cube-pair-in-source-overapproximation-v1",
                "raw_assignments": report["total"],
                "allowed_assignments": len(report["allowed"]),
                "comparisons": report["comparisons"],
                "table_sha256": v.digest(v.encode([[vector, result] for vector, result in report["allowed"]])),
                "unconstrained_counterexample": report["relaxed_witness"],
                "native_vectors": len(values),
                "invalidated_by": "Changed owned source/call graph/ownership, dependency bytes, predicate geometry, memory corruption or contradictory observations.",
            }
        )
    return {
        "proofs": proofs,
        "dependencies": {name: v.digest(data) for name, data in dependency.items()},
        "qualification": "conditional-source-coupling-only; not executed independent pairs or whole-component qualification",
    }


def disposition(decisions: dict, unresolved: list, *, acquisition: bool = False) -> list[dict]:
    """Separate fixed literals and existing reachability assumptions without deleting raw obligations."""
    from tools import structure

    assumptions = {(identity, atom): (outcome, reason) for identity, atom, outcome, reason in structure.domain(acquisition=acquisition)["assumptions"]}
    result = []
    for identity, atom in unresolved:
        decision = decisions[identity]
        row = {"decision": identity, "condition": atom, "kind": "input-or-coupling-proof-required"}
        if decision["text"] in {"true", "false"} and len(decision["atoms"]) == 1 and decision["atoms"][0]["text"] == decision["text"]:
            row.update(kind="literal-return", value=decision["text"] == "true")
        elif (identity, atom) in assumptions:
            outcome, reason = assumptions[identity, atom]
            row.update(kind="source-assumption", outcome=outcome, assumption_id=reason, **structure.REASONS[reason])
        result.append(row)
    return result


def reconcile(root: Path, archives: dict[str, bytes], *, structural: bool = False) -> dict:
    """Qualify retained Admission condition evidence without starting any application command.

    Archive pins bind the previously reviewed native commands, environments, overlays,
    dependencies and retirement facts. Current Go inputs and fixtures must still match.
    The outer gate owns trust, policy and whole-system qualification separately.
    """
    from tools import entry, logic, structure

    if admission.matches(root, "internal/admission/identity.go", admission.MATERIAL):
        from tools import admissioncompiler

        if admissioncompiler.upgraded(root):
            return admissioncompiler.reconcile(root, archives, structural=structural)
        return repaired(root, archives, structural=structural)
    if structural:
        v.reject("predicates-structure-source")
    if set(archives) != set(ARCHIVES):
        v.reject("predicates-archive-inventory")
    for name, data in archives.items():
        if v.digest(data) != ARCHIVES[name]:
            v.reject("predicates-archive-integrity", name)
    old = entry.retained(archives["admission-structure"], ARCHIVES["admission-structure"])
    # The small incremental archive has an external seal, unlike entry.retained's internal manifest.
    # Its fixed archive hash above binds every byte, including native records and full streams.
    extra = entry.unpack(archives["admission-edges"])
    inputs = v.decode(old["inputs.json"])
    frozen = entry.unpack(old["inputs.tar.gz"])
    if v.digest(old["inputs.tar.gz"]) != inputs["archive_sha256"] or {name: v.digest(data) for name, data in frozen.items()} != inputs["files"]:
        v.reject("predicates-input-archive")
    selected = lambda name: name.endswith(".go") or name in {"go.mod", "go.sum", "dependencies.lock.json"}
    sources = {name: digest for name, digest in inputs["files"].items() if selected(name)}
    if sources != {row["path"]: row["sha256"] for row in v.source(root)["files"] if selected(row["path"])}:
        v.reject("predicates-input-drift")
    if any(inputs["files"].get(name) != digest for name, digest in FIXTURES.items()) or extra["fixture.go.in"] != v.read(
        root / "tests/fixtures/admission.go.in"
    ):
        v.reject("predicates-fixture-drift")
    owner, process, cleanup, terminal = (
        v.decode(extra[name]) for name in ("controller.json", "command/admission-edges.process.json", "cleanup.native.json", "terminal.json")
    )
    if (
        cleanup["service"]["InvocationID"] != owner["invocation_id"]
        or any(cleanup["service"][key] != value for key, value in {"MainPID": "0", "SubState": "exited", "ExecMainStatus": "0", "ControlGroup": ""}.items())
        or not owner["boot_id"] == process["boot_id"] == cleanup["boot_id"]
        or process["identity"]["parent"] != owner["identity"]["pid"]
        or cleanup["retired"] != [owner["identity"], process["identity"]]
        or terminal["errors"]
        or terminal["remaining_owned"]
        or terminal["interrupted"] is not False
        or terminal["source_unchanged"] is not True
        or terminal["pins_unchanged"] is not True
    ):
        v.reject("predicates-native-retirement")
    prefix = "source/build/commands/admission-structure/structure/"
    trace = v.decode(old[prefix + "typed/overlay/trace.json"])
    events = old[prefix + "typed/tests/tests.stdout.log"]
    incremental = extra["command/admission-edges.stdout.log"]
    check = next(row for row in v.decode(frozen["development.json"])["checks"] if row["id"] == "admission-structure")
    dependency = {name: old[prefix + "_dependencies/" + name] for name in structure.DEPENDENCIES}
    report = independence(root, trace, events, check["native_tests"], dependency=dependency)
    added = edges(root, trace, incremental)
    coordinates = {(row["decision"], row["condition"]) for row in added["pairs"]}
    missing = {tuple(row) for row in report["qualified_unresolved"]}
    if not coordinates.issubset(missing):
        v.reject("predicates-increment-overlap")
    package = "github.com/eosforge/astra/internal/admission"
    observed, owners = logic.observe(trace, events, package, len(check["native_tests"]))
    more, count = logic.observe(trace, incremental, package, 1)
    if owners != 2 or count != 1:
        v.reject("predicates-process-count")
    # Merge validated observations, never concatenate event streams or synthesize native terminals.
    for identity, values in more.items():
        for key, hits in values.items():
            target = observed.setdefault(identity, {})
            target[key] = target.get(key, 0) + hits
    coupled = coupling(root, trace, observed, {**dependency, "net/netip/netip.go": extra["dependencies/net/netip/netip.go"]})
    exclusions = {(row["decision"], row["condition"]) for row in coupled["proofs"]}
    if missing - coordinates != exclusions or coordinates & exclusions:
        v.reject("predicates-coupling-scope-gap")
    report.update(
        status="complete-under-assumptions",
        supported_conditions=report["supported_conditions"] + len(coordinates),
        additional_conditions=report["additional_conditions"] + len(coordinates),
        qualified_denominator=report["qualified_denominator"] - len(exclusions),
        qualified_unresolved=[],
        additional_pairs=added,
        coupling=coupled,
    )
    report["unresolved"] = [row for row in report["unresolved"] if tuple(row) not in coordinates]
    report["disposition"] = [row for row in report["disposition"] if (row["decision"], row["condition"]) not in coordinates]
    for row in report["disposition"]:
        if (row["decision"], row["condition"]) in exclusions:
            row["kind"] = "source-coupling"
    report["basis"] = (
        "Retained native traces and two incremental executed pairs support 164 of 184 raw conditions. "
        "Seven literal returns, six reachability assumptions and seven finite source-coupling proofs are separate exclusions, never native hits. "
        "Only the Linux MC/DC obligation may consume this conditional local result; other component, trust and release obligations remain independent."
    )
    if report["supported_conditions"] != report["qualified_denominator"]:
        v.reject("predicates-qualified-gap")
    return {
        "status": report["status"],
        "independence": report,
        "archives": dict(ARCHIVES),
        "sources": sources,
        "application_commands": 0,
        "qualification": "local retained Linux condition evidence under declared assumptions; not CI or release approval",
    }


def repaired(root: Path, archives: dict[str, bytes], *, structural: bool = False) -> dict:
    """Reconcile the acquisition repair's sealed native geometry and three incremental input pairs.

    Fixed archive identities bind previously reviewed commands, tools, overlays and environment.
    The original collector's postcollection refusal stays failed; only its eight successful
    child commands contribute native observations to this independent local evaluation.
    """
    from tools import entry, logic, statements, structure

    if set(archives) != set(REPAIRED):
        v.reject("predicates-archive-inventory")
    files = {}
    for name, digest in REPAIRED.items():
        if v.digest(archives[name]) != digest:
            v.reject("predicates-archive-integrity", name)
        files[name] = entry.unpack(archives[name])
    geometry, extra = (files[name] for name in REPAIRED)
    original = "/home/ubuntu/verdandi/astra/build/results/assurance/reuse-material-geometry/source"
    incremental = "/home/ubuntu/verdandi/astra/build/results/assurance/reuse-acquisition-pairs-3/source"
    for data, cwd, expected_errors in ((geometry, original, ["AssertionError: "]), (extra, incremental, [])):
        terminal, cleanup, owner = (v.decode(data[name]) for name in ("terminal.json", "cleanup.native.json", "controller.json"))
        if (
            terminal["errors"] != expected_errors
            or terminal["interrupted"] is not False
            or terminal["remaining_owned"]
            or terminal["source_unchanged"] is not True
            or terminal["pins_unchanged"] is not True
            or cleanup["boot_id"] != owner["boot_id"]
            or owner["identity"] not in cleanup["retired"]
            or cleanup["service"]["MainPID"] != "0"
            or cleanup["service"]["ControlGroup"]
        ):
            v.reject("predicates-native-retirement")
        for name, raw in data.items():
            if not name.endswith(".process.json"):
                continue
            process = v.decode(raw)
            if process["boot_id"] != owner["boot_id"] or process["cwd"] != cwd or process["identity"] not in cleanup["retired"]:
                v.reject("predicates-native-process", name)

    def command(data: dict, name: str, arguments: list[str], exit_code: int = 0) -> bytes:
        """Preserve original statuses and require complete native streams for the exact selected command."""
        record = v.decode(data[name + "/record.json"])
        v.schema(record, "evidence", ("properties", "checks", "items"))
        if (
            record["argv"] != arguments
            or record["exit_code"] != exit_code
            or record["termination"] != "exited"
            or record["complete"] is not True
            or record["cleanup"] is not True
            or record["platform"] != structure.PLATFORM
        ):
            v.reject("predicates-native-command", name)
        for channel in ("stdout", "stderr"):
            item = record[channel]
            raw = data[name + "/" + item["path"]]
            if item["bytes"] != len(raw) or item["sha256"] != v.digest(raw):
                v.reject("predicates-native-stream", name)
        return data[name + "/" + record["stdout"]["path"]]

    prefix = "source/build/commands/admission-structure/structure/"
    streams = {
        name: command(geometry, prefix + name, [value.replace("{root}", original) for value in argv])
        for name, argv, _ in structure.plan(PurePosixPath(original + "/build/commands/admission-structure/structure"))
    }
    outer = "source/build/commands/admission-structure"
    check = v.decode(geometry[outer + "/plan.json"])
    command(geometry, outer, check["argv"], 2)
    extra_path = "source/build/commands/acquisition-pairs"
    arguments = [
        "/home/ubuntu/verdandi/build/tools/go-1.27.1/bin/go",
        "test",
        "-json",
        "-count=1",
        "-p=2",
        "-parallel=2",
        "-timeout=60s",
        "-run=^(TestAdmissionEdges|TestLoadMetadata)$",
        "-overlay=" + incremental + "/build/commands/acquisition-pairs/overlay.json",
        "./internal/admission",
    ]
    added_events = command(extra, extra_path, arguments)
    # Native imports plus every file in those packages bind production, fixtures, platform
    # alternatives and the collector. Unrelated package additions cannot alter this campaign.
    bindings = sources(root, v.decode(geometry["inputs.json"])["files"], statements.stream(streams["typed/exports"]))
    supplement = v.decode(extra["inputs.json"])
    # This supplement consumes the frozen overlay instead of executing its collector.
    # Collector files remain bound by the geometry campaign and exact trace comparison below.
    if any(supplement["production"].get(name) != digest for name, digest in bindings.items() if not name.startswith("tools/decisions/")):
        v.reject("predicates-increment-source")
    for name, digest in (("admission.go.in", EDGE), ("admission-metadata.go.in", METADATA)):
        if v.digest(extra[name]) != digest or v.file_digest(root / "tests/fixtures" / name) != digest or supplement["fixtures"].get(name) != digest:
            v.reject("predicates-fixture-drift", name)
    trace_data = geometry[prefix + "typed/overlay/trace.json"]
    if extra["trace.json"] != trace_data:
        v.reject("predicates-increment-geometry")
    trace = v.decode(trace_data)
    dependency = {name: geometry[prefix + "_dependencies/" + name] for name in structure.DEPENDENCIES}
    events = streams["typed/tests"]
    if structural:
        parent, child = (geometry[prefix + name] for name in ("coverage.profile", "resolver.profile"))
        structure.terminals(streams["coverage"], check["native_tests"])
        if structure.resolver(streams["coverage"]) != child:
            v.reject("predicates-resolver-binding")
        result = structure.reconcile(
            root=root,
            source_sha256=trace["source_sha256"],
            tests=check["native_tests"],
            profiles=(parent, child),
            dependency=dependency,
            trace=trace,
            boolean_events=events,
            control=v.decode(geometry[prefix + "control/overlay/flow.json"]),
            control_events=streams["control/tests"],
        )
        result.update(
            archives=dict(REPAIRED),
            sources=bindings,
            application_commands=0,
            original_collector_exit_code=2,
            qualification="Local current-source Linux structure under declared assumptions; not whole-rule, CI or release approval",
        )
        return result
    report = qualified(root, trace, events, check["native_tests"], dependency, added_events, extra["netip.go"])
    return {
        "status": report["status"],
        "independence": report,
        "archives": dict(REPAIRED),
        "sources": bindings,
        "application_commands": 0,
        "original_collector_exit_code": 2,
        "qualification": "Local current-source Linux MC/DC under declared assumptions; not whole-component, CI or release approval",
    }


def qualified(root: Path, trace: dict, events: bytes, tests: list[str], dependency: dict[str, bytes], added_events: bytes, netip: bytes) -> dict:
    """Apply the unchanged acquisition condition proof to either authenticated compiler campaign."""
    from tools import logic

    report = independence(root, trace, events, tests, dependency=dependency, acquisition=True)
    added = edges(root, trace, added_events, acquisition=True)
    coordinates = {(row["decision"], row["condition"]) for row in added["pairs"]}
    missing = {tuple(row) for row in report["qualified_unresolved"]}
    if len(coordinates) != 3 or not coordinates.issubset(missing):
        v.reject("predicates-increment-overlap")
    package = "github.com/eosforge/astra/internal/admission"
    observed, owners = logic.observe(trace, events, package, len(tests))
    more, count = logic.observe(trace, added_events, package, 2)
    if owners != 2 or count != 1:
        v.reject("predicates-process-count")
    for identity, values in more.items():
        for key, hits in values.items():
            target = observed.setdefault(identity, {})
            target[key] = target.get(key, 0) + hits
    coupled = coupling(root, trace, observed, {**dependency, "net/netip/netip.go": netip}, acquisition=True)
    exclusions = {(row["decision"], row["condition"]) for row in coupled["proofs"]}
    if missing - coordinates != exclusions or coordinates & exclusions:
        v.reject("predicates-coupling-scope-gap")
    report.update(
        status="complete-under-assumptions",
        supported_conditions=report["supported_conditions"] + len(coordinates),
        additional_conditions=report["additional_conditions"] + len(coordinates),
        qualified_denominator=report["qualified_denominator"] - len(exclusions),
        qualified_unresolved=[],
        additional_pairs=added,
        coupling=coupled,
    )
    report["unresolved"] = [row for row in report["unresolved"] if tuple(row) not in coordinates]
    report["disposition"] = [row for row in report["disposition"] if (row["decision"], row["condition"]) not in coordinates]
    for row in report["disposition"]:
        if (row["decision"], row["condition"]) in exclusions:
            row["kind"] = "source-coupling"
    if report["raw_conditions"] != 185 or report["supported_conditions"] != 165 or report["qualified_denominator"] != 165:
        v.reject("predicates-qualified-gap")
    report["basis"] = (
        "165 supported conditions among 185 raw conditions. Seven literals, six reachability assumptions and seven source-coupling proofs remain separate exclusions. Metadata-kind injection changes only a private FileInfo copy and does not claim physical filesystem kind mutation."
    )
    return report


def independence(root: Path, trace: dict, events: bytes, tests: list[str], *, dependency: dict[str, bytes], acquisition: bool = False) -> dict:
    """Combine retained semantic pairs and native traces, preserving every unresolved condition.

    The caller verifies native command, archive, toolchain and retirement provenance.
    This interpretation cannot grant component, CI or release qualification.
    """
    from tools import admission, authority, defenses, logic, structure

    defenses.sources(root, acquisition=acquisition)
    legacy = not acquisition and v.file_digest(root / "internal/admission/node.go") == admission.SOURCES["internal/admission/node.go"]
    if v.digest(v.encode(trace["files"])) != structure.domain(legacy=legacy, acquisition=acquisition)["forest"]:
        v.reject("predicates-forest")
    structure.terminals(events, tests)
    required = set(COUNTERS) | {"TestPredicates", "TestSame", "TestSharedVectors", "TestDirectoryBoundaries", "TestDirectoryReplacement"}
    if not required.issubset(tests):
        v.reject("predicates-fixture-selection")
    package = "github.com/eosforge/astra/internal/admission"
    for test, marker, expected_rows in (
        ("TestPredicates", "ADMISSION-PREDICATES ", expected()),
        ("TestSame", "ADMISSION-SAME ", [equality.expected(index) for index in range(9)]),
    ):
        actual = equality.frames(events, package, test=test, marker=marker, maximum=len(expected_rows))
        if v.encode(actual) != v.encode(expected_rows):
            v.reject("predicates-native-pairs", test)
    fixture_proof = fixtures(root, events, acquisition=acquisition)
    decisions = logic.inventory(trace)
    observed, processes = logic.observe(trace, events, package, len(tests))
    report = logic.summary(trace, events, package, len(tests))
    if report["independence"]["search_incomplete"]:
        v.reject("predicates-search-incomplete")
    supported = {(row["id"], atom["index"]) for row in report["decisions"] for atom in row["atoms"] if atom["independent"] is not None}
    prior = len(supported)
    proofs = []
    for pair in witnesses(acquisition=acquisition):
        identity = pair["decision"]
        proofs.append(authority.correlate_pair(decisions[identity], pair, set(observed[identity])))
        supported.add((identity, pair["condition"]))
    boundary_proofs = []
    for row in boundaries(acquisition=acquisition):
        pair = row["pair"]
        identity = pair["decision"]
        boundary_proofs.append({**authority.correlate_pair(decisions[identity], pair, set(observed[identity])), "test": row["test"], "basis": row["basis"]})
        supported.add((identity, pair["condition"]))
    guard_proofs = guarded(decisions, observed, acquisition=acquisition)
    supported.update((row["pair"]["decision"], row["pair"]["condition"]) for row in guard_proofs)
    masked = []
    for row in masking():
        pair = row["pair"]
        identity = pair["decision"]
        masked.append({**mask(decisions[identity], pair, set(observed[identity])), "test": row["test"], "basis": row["basis"]})
        supported.add((identity, pair["condition"]))
    domain = domains(decisions, observed, dependency, acquisition=acquisition)
    supported.update((row["decision"], row["condition"]) for row in domain["pairs"])
    excluded = {(row["decision"], row["condition"]) for row in domain["literal_exclusions"] + domain["domain_exclusions"]}
    if supported & excluded:
        v.reject("predicates-domain-credited-exclusion")
    unresolved = sorted({(identity, index) for identity, decision in decisions.items() for index in range(len(decision["atoms"]))} - supported)
    missing = sorted(set(unresolved) - excluded)
    return {
        "qualification": "scoped-local-evidence-only",
        "status": "incomplete" if missing else "complete-under-declared-domains",
        "raw_conditions": report["totals"]["atoms"],
        "trace_supported": prior,
        "supported_conditions": len(supported),
        "additional_conditions": len(supported) - prior,
        "process_receipts": processes,
        "concrete_pairs": proofs,
        "fixture_pairs": boundary_proofs,
        "guard_pairs": guard_proofs,
        "masked_pairs": masked,
        "domains": domain,
        "qualified_denominator": report["totals"]["atoms"] - len(excluded),
        "qualified_unresolved": missing,
        "fixture_provenance": fixture_proof,
        "unresolved": unresolved,
        "disposition": disposition(decisions, unresolved, acquisition=acquisition),
        "basis": "Concrete input and nil-domain pairs require fixed executed fixtures and both native masks. Changed nontarget values require universal-cube proof, never arbitrary Boolean completion. Seven literals and six preexisting source assumptions are separately qualified against actual dependency bytes and native contradictions; the raw denominator and unsupported coordinates remain intact. This report grants no component or release pass.",
    }
