"""Replay the frozen local Storage qualification through a source-bound gate adapter."""

import argparse
import ast
import os
from pathlib import Path
import sys

# Direct execution and the gate use the same owned helpers and error type.
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from tools import entry, logic, retention, storage, structure, verify as v

# A retained qualification is accepted only with its actual runner receipt and complete native ancestry.
BASE = "reuse-plan/storage-retention-pairs-current-1/"
ARCHIVE = "3f838ccc3ec4f0795454bbed0af11491426fbe6b083083f145bca895415c5802"
SEAL = "97bacf672414c86ba6b09074a2f4909c9ad066de5553ece5c18c0ca2db13128c"
ORIGIN = {
    BASE + "local-evidence.tar.gz": ARCHIVE,
    BASE + "local.sealed.json": SEAL,
}
NATIVE = "45e05e6068ea1a3f636d045a211edee587ed7b292a70f28bbd5a8a05e5621dad"
MAXIMUM = 64 * 1024**2

# Only adapter-dispatch functions change here; the factual parser and remaining validator stay frozen.
DISPATCH = {"configuration", "parse_observations", "coverage", "bundle", "execute", "collect"}
CORE = "42d4840a375ffc747b38e180aaeaead76a1443229077ff38538117ee91db9096"
SCHEMA = "2cce5d0dce3a28ac906d2c7af5143101777b37efe21d348f1bffeae638e7aa4a"


def configuration(check: dict, native: dict) -> None:
    """Bind the sole Linux obligation, original inventory and bounded replay command."""
    structure.configuration(native)
    expected = {
        **native,
        "id": "storage-independence",
        "adapter": "storage-independence",
        "argv": ["python3", "-B", "tools/independence.py", "--collect"],
        "expected_tests": ["independence"],
        "native_tests": native["native_tests"] + ["TestRetentionInputs", "TestRetentionInputs/backlog", "TestRetentionInputs/count"],
        "probes": [{"contract": "STORAGE-ASSURANCE", "test": "independence", "minimum_hits": 273 if len(native["native_tests"]) in {257, 259} else 271}],
        "timeout_s": 120,
    }
    if check != expected:
        v.reject("storage-independence-policy")


def ancestry(artifacts: dict[str, bytes]) -> dict[str, bytes]:
    """Authenticate the closed archive graph without executing archived scripts or extracting paths."""
    pending = dict(ORIGIN)
    verified = {}
    certificates = {}
    while pending:
        name, digest = pending.popitem()
        if name in verified:
            if verified[name] != digest:
                v.reject("storage-independence-reference-conflict", name)
            continue
        data = artifacts.get(name)
        if not isinstance(data, bytes) or v.digest(data) != digest:
            v.reject("storage-independence-artifact", name)
        verified[name] = digest
        if len(verified) > 256 or sum(len(artifacts[key]) for key in verified) > 512 * 1024**2:
            v.reject("storage-independence-ancestry-bound")
        if not name.endswith("local-evidence.tar.gz"):
            continue
        parent = name.removesuffix("local-evidence.tar.gz")
        sealed = parent + "local.sealed.json"
        seal_data = artifacts.get(sealed)
        expected_seal = pending.get(sealed, verified.get(sealed))
        if seal_data is None or expected_seal is None or v.digest(seal_data) != expected_seal:
            v.reject("storage-independence-seal", sealed)
        files = storage.retained(data, v.decode(seal_data), digest)
        certificate = parent.rstrip("/").split("/")[-1]
        requirements = v.decode(files[certificate + "/required-artifacts.json"])
        if not isinstance(requirements.get("files"), dict):
            v.reject("storage-independence-references")
        for key, value in requirements["files"].items():
            if not isinstance(key, str) or not isinstance(value, str) or not key.startswith("reuse-plan/") or ".." in key.split("/"):
                v.reject("storage-independence-reference")
            if key in pending and pending[key] != value or key in verified and verified[key] != value:
                v.reject("storage-independence-reference-conflict", key)
            pending[key] = value
        certificates[parent] = files
    if set(artifacts) != set(verified):
        v.reject("storage-independence-extra-artifact")
    return certificates[BASE]


def artifacts(root: Path, *, historical: bool = False) -> dict[str, bytes]:
    """Read only hash-authorized ancestors from the existing evidence directory."""
    directory = root / "build/results/assurance"
    values = {}
    pending = dict(ORIGIN)
    while pending:
        name, digest = pending.popitem()
        if name in values:
            if v.digest(values[name]) != digest:
                v.reject("storage-independence-reference-conflict", name)
            continue
        data = v.read(v.inside(directory, name), MAXIMUM)
        if v.digest(data) != digest:
            v.reject("storage-independence-artifact", name)
        values[name] = data
        if len(values) > 256 or sum(map(len, values.values())) > 512 * 1024**2:
            v.reject("storage-independence-ancestry-bound")
        if name.endswith("local-evidence.tar.gz"):
            parent = name.removesuffix("local-evidence.tar.gz")
            sealed = parent + "local.sealed.json"
            seal_data = values.get(sealed)
            if seal_data is None:
                seal_data = v.read(v.inside(directory, sealed), MAXIMUM)
                if sealed not in pending or v.digest(seal_data) != pending[sealed]:
                    v.reject("storage-independence-seal", sealed)
            files = storage.retained(data, v.decode(seal_data), digest)
            certificate = parent.rstrip("/").split("/")[-1]
            for key, expected in v.decode(files[certificate + "/required-artifacts.json"])["files"].items():
                if key in pending and pending[key] != expected or key in values and v.digest(values[key]) != expected:
                    v.reject("storage-independence-reference-conflict", key)
                pending[key] = expected
    ancestry(values)
    from tools import idle

    if not historical and idle.current(root):
        values.update(idle.artifacts(root))
    return values


def schema(data: bytes) -> None:
    """Allow only the reviewed evidence-adapter enum extensions of the unchanged closed schema."""
    value = v.decode(data)
    if v.digest(v.encode(value)) == SCHEMA:
        return
    try:
        adapters = value["properties"]["checks"]["items"]["oneOf"][-1]["properties"]["adapter"]["enum"]
    except (KeyError, IndexError, TypeError):
        v.reject("storage-independence-schema-source")
    if not isinstance(adapters, list):
        v.reject("storage-independence-schema-source")
    for name in ("storage-delivery", "admission-repair", "storage-repair"):
        if adapters.count(name) > 1:
            v.reject("storage-independence-schema-source")
        if name in adapters:
            adapters.remove(name)
    if v.digest(v.encode(value)) != SCHEMA:
        v.reject("storage-independence-schema-source")


def helper(name: str, original: bytes, current: bytes) -> None:
    """Preserve Storage interpretation across reviewed service-scope and unrelated domain extensions."""
    if name not in {"tools/build.py", "tools/entry.py", "tools/mutate.py", "tools/sensitivity.py", "tools/server.py", "tools/storage.py", "tools/structure.py"}:
        v.reject("storage-independence-helper-scope", name)
    before, after = (ast.parse(data) for data in (original, current))
    excluded = {
        "tools/build.py": set(),
        "tools/entry.py": {"artifacts", "renew", "reconcile", "bindings"},
        "tools/mutate.py": {"cpp_run"},
        "tools/sensitivity.py": set(),
        "tools/server.py": {"artifacts", "reconcile", "authentication", "delta"},
        "tools/storage.py": {"additions"},
        "tools/structure.py": set(),
    }[name]
    if name == "tools/storage.py":
        additions = [node for node in after.body if isinstance(node, ast.FunctionDef) and node.name == "additions"]
        if (
            len(additions) != 1
            or any(isinstance(node, ast.FunctionDef) and node.name == "additions" for node in before.body)
            or v.digest(ast.dump(additions[0], include_attributes=False).encode()) != "1246ffefea68a67e8945fc06cd1cac7f45c9515a2f5c1f80b6a067b29fa3d386"
        ):
            v.reject("storage-independence-helper-source", name)
    for tree in (before, after):
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in excluded:
                eager = node.args.defaults + [item for item in node.args.kw_defaults if item is not None]
                eager += [item.annotation for item in node.args.posonlyargs + node.args.args + node.args.kwonlyargs if item.annotation is not None]
                if node.returns is not None:
                    eager.append(node.returns)
                if node.decorator_list or any(isinstance(item, ast.Call) for expression in eager for item in ast.walk(expression)):
                    v.reject("storage-independence-helper-import", name)
        tree.body = [node for node in tree.body if not (isinstance(node, ast.FunctionDef) and node.name in excluded)]
    if name in {"tools/storage.py", "tools/sensitivity.py"}:
        sources = [node for node in after.body if isinstance(node, ast.FunctionDef) and node.name == "sources"]
        expected = ast.dump(
            ast.parse("actual -= additions(root, original)" if name == "tools/storage.py" else "actual -= storage.additions(root, names)").body[0],
            include_attributes=False,
        )
        matches = [index for index, node in enumerate(sources[0].body) if ast.dump(node, include_attributes=False) == expected] if len(sources) == 1 else []
        if len(matches) != 1:
            v.reject("storage-independence-helper-source", name)
        sources[0].body.pop(matches[0])
    if name == "tools/build.py":
        prior = ast.parse("run([go, '-C', SOURCE, 'test', '-mod=readonly', '-count=1', '-p', cases, '-parallel', 1, './...'], env)", mode="eval").body
        scoped = ast.parse(
            "run([go, '-C', SOURCE, 'test', '-mod=readonly', '-count=1', '-p', cases, '-parallel', 1, './internal/...', './polaris/...', './astrolabe/...'], env)",
            mode="eval",
        ).body
        for tree, expected in ((before, prior), (after, scoped)):
            main = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"]
            matches = (
                [node for node in ast.walk(main[0]) if ast.dump(node, include_attributes=False) == ast.dump(expected, include_attributes=False)]
                if len(main) == 1
                else []
            )
            if len(matches) != 1:
                v.reject("storage-independence-helper-source", name)
            if tree is after:
                matches[0].args[0].elts[-3:] = [ast.Constant(value="./...")]
    if name == "tools/mutate.py":
        main = [node for node in after.body if isinstance(node, ast.FunctionDef) and node.name == "main"]
        if len(main) != 1:
            v.reject("storage-independence-helper-source", name)
        replacements = (
            (
                "parser.add_argument('--prune', action='store_true', help=\"Remove only successful C++ attempts' drained, rebuildable objects and programs\")",
                None,
            ),
            ("if args.prune:\n    v.reject('mutation-prune-cpp-required')", None),
            (
                "if isinstance(manifest, dict) and manifest.get('engine') == 'cpp':\n    return cpp_run(manifest, args.build.resolve(), output, root, prune=args.prune)",
                "if isinstance(manifest, dict) and manifest.get('engine') == 'cpp':\n    return cpp_run(manifest, args.build.resolve(), output, root)",
            ),
        )
        for expected, replacement in replacements:
            expected = ast.dump(ast.parse(expected).body[0], include_attributes=False)
            matches = [index for index, node in enumerate(main[0].body) if ast.dump(node, include_attributes=False) == expected]
            if len(matches) != 1:
                v.reject("storage-independence-helper-source", name)
            if replacement is None:
                main[0].body.pop(matches[0])
            else:
                main[0].body[matches[0]] = ast.parse(replacement).body[0]
    if name == "tools/entry.py":
        for tree in (before, after):
            retained = []
            for node in tree.body:
                if (
                    isinstance(node, ast.Assign)
                    and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id in {"CURRENT", "COMMANDS"}
                ):
                    try:
                        ast.literal_eval(node.value)
                    except (ValueError, TypeError, SyntaxError):
                        v.reject("storage-independence-helper-import", name)
                    continue
                retained.append(node)
            tree.body = retained
    if name == "tools/structure.py":
        guard = ast.parse(
            'package == SERVER and v.file_digest(root / SERVER / "authority.go") == "76348643eb6b779fe7bd42fb2e438439d247367739c7a523b898ff872dbbc481"',
            mode="eval",
        ).body

        class Project(ast.NodeTransformer):
            """Preserve every Storage branch; normalize only two explicitly Server-guarded calls."""

            def visit_If(self, node: ast.If) -> ast.AST | list[ast.AST] | None:
                """Remove the recognized retirement guard and replace retained-server artifact lookups."""
                if ast.dump(node.test, include_attributes=False) == ast.dump(guard, include_attributes=False):
                    return node.orelse
                if isinstance(node.test, ast.Name) and node.test.id == "retained_server":
                    branch = ast.Module(body=node.body, type_ignores=[])

                    class Catalog(ast.NodeTransformer):
                        """Replace dynamic artifact discovery in the retained-server source adapter."""

                        def visit_Call(self, call: ast.Call) -> ast.AST | list[ast.AST] | None:
                            """Replace the recognized artifact lookup with the retained static catalog."""
                            if ast.dump(call, include_attributes=False) == ast.dump(
                                ast.parse("server.artifacts(root)", mode="eval").body, include_attributes=False
                            ):
                                return ast.Attribute(value=ast.Name(id="server", ctx=ast.Load()), attr="ARTIFACTS", ctx=ast.Load())
                            return self.generic_visit(call)

                    node.body = Catalog().visit(branch).body
                return self.generic_visit(node)

        after = Project().visit(after)
    if ast.dump(before, include_attributes=False) != ast.dump(after, include_attributes=False):
        v.reject("storage-independence-helper-source", name)


def sources(root: Path, files: dict[str, bytes], original: dict[str, bytes] | None = None) -> None:
    """Freeze product, native tests and proof helpers; append-only gate controls cannot weaken prior tests."""
    certificate = BASE.rstrip("/").split("/")[-1]
    validator = ast.parse(v.read(root / "tools/verify.py"))
    validator.body = [node for node in validator.body if not (isinstance(node, ast.FunctionDef) and node.name in DISPATCH)]
    if v.digest(ast.dump(validator, include_attributes=False).encode()) != CORE:
        v.reject("storage-independence-validator-source")
    schema(v.read(root / "tools/schemas/development.schema.json"))
    source = v.decode(files[certificate + "/received.json"])["source"]["files"]
    for row in source:
        name = row["path"]
        if name.startswith((retention.PACKAGE + "/", "tools/", "tests/fixtures/storage", "tests/fixtures/retention")) and name not in {
            "tools/verify.py",
            "tools/schemas/development.schema.json",
            # Neither tool participates in the frozen Storage proof. The actual proof helpers
            # remain byte-bound below, and all original producers remain archive-bound.
            "tools/assurance.py",
            "tools/delivery.py",
        }:
            if v.file_digest(v.inside(root, name)) != row["sha256"]:
                if original is None or name not in original or v.digest(original[name]) != row["sha256"]:
                    v.reject("storage-independence-source", name)
                helper(name, original[name], v.read(v.inside(root, name)))
    migrations = {
        # The current owner adds 21 observed statements and ten native cases. All earlier negative controls remain.
        (
            "StructureTests",
            "test_native_denominator",
            "3763d7f491b2ce8a7bba390f0142ef6c98808cf35117d2478b4782104d90ff83",
            "33675951b4a64ca8acf7dde0028ab6aead15a28729bb230a9121322d44b6df00",
        ): "d1af60e9d6a432f0e0d1cf1a9eaf8b9bab13cdbfdb2e3ccc824a8ab246e0e890",
        (
            "AdapterTests",
            "test_configuration",
            "fe3531f2edad824a56b7bb56796bbe5ed79f082387884d660492e1a6e75554b9",
            "676dca0a49a37dee7a8f022cfb40e3e28ae951f23a9dbdf9b286bb01c263d3fd",
        ): "d1af60e9d6a432f0e0d1cf1a9eaf8b9bab13cdbfdb2e3ccc824a8ab246e0e890",
        # The compatibility prerequisite is the 51st reviewed migration; the original object ledger stays intact.
        (
            "StructureTests",
            "test_fixed_obligations",
            "089bad7d8e713aba748155d7133d97efbc91e8f449d18d22dd1e7d6c0fb02c26",
            "744731fe320d416001b2cfb05c12e57e9244d359c8f9e558ae4a6f6e6db412a6",
        ): "d1af60e9d6a432f0e0d1cf1a9eaf8b9bab13cdbfdb2e3ccc824a8ab246e0e890",
        (
            "EntryTests",
            "test_policy",
            "9db9395d1612b8c5fa105fd77004fa615d41b692434b16c44076797dcbd7e240",
            "9eb7dc04604ff659fe87caf9c2a512a4a62c33fd374643fc1f4e84d70c2ea3fb",
        ): "d1af60e9d6a432f0e0d1cf1a9eaf8b9bab13cdbfdb2e3ccc824a8ab246e0e890",
        (
            "StructureTests",
            "test_fixed_obligations",
            "089bad7d8e713aba748155d7133d97efbc91e8f449d18d22dd1e7d6c0fb02c26",
            "203ed833dd84d72dbfaa5ab89dd87e7528ddf89dc20cb2f0544c51cd0ef22f5f",
        ): "271b87269dccc2a16ba60167c5b66dbdcf0122505f1528e121c00bbebcf4b809",
        (
            "StructureTests",
            "test_fixed_obligations",
            "089bad7d8e713aba748155d7133d97efbc91e8f449d18d22dd1e7d6c0fb02c26",
            "0a2c724331b5c472627381d2f4acb09c3e151b6f06da0650c9bf291347048b24",
        ): "e31372992c64a88b70c1e06e70a2427f9b29942c195fb53e13d7a30b197eae76",
        (
            "EntryTests",
            "test_policy",
            "9db9395d1612b8c5fa105fd77004fa615d41b692434b16c44076797dcbd7e240",
            "0f09a24b23272ecdfa964f71f1f5dc92cf45aab888b91bbd28b8fa2a7cfa52bb",
        ): "e31372992c64a88b70c1e06e70a2427f9b29942c195fb53e13d7a30b197eae76",
        (
            "ServerTests",
            "test_counters",
            "5fc23aee33f98a56032e57f6a36d81cb11731611354bbbbea452f7d11eaea12b",
            "f9ea70c503344751feba35c1477461774e8090a4b14a774d2bc767faf51f8e1b",
        ): (
            "e31372992c64a88b70c1e06e70a2427f9b29942c195fb53e13d7a30b197eae76",
            "9c26ac40256a2a2cf8b269a920950dee2f202d8f5f56384e4592662595bec5ca",
            "b815dfbc04d4b4ccbae38f1ed7b9c487a649e745e693f3f01bda68b3ee9071dd",
            "d1af60e9d6a432f0e0d1cf1a9eaf8b9bab13cdbfdb2e3ccc824a8ab246e0e890",
        ),
        (
            "StructureTests",
            "test_fixed_obligations",
            "089bad7d8e713aba748155d7133d97efbc91e8f449d18d22dd1e7d6c0fb02c26",
            "b16b35ce4de0cc9b909d1d8dbd6f22829783b82e5d03e6b73d9acdaf9f6a4cc8",
        ): "9c26ac40256a2a2cf8b269a920950dee2f202d8f5f56384e4592662595bec5ca",
        (
            "EntryTests",
            "test_policy",
            "9db9395d1612b8c5fa105fd77004fa615d41b692434b16c44076797dcbd7e240",
            "561b92d75a8124e225b0e873c341126574bb495f322e67a948d90ec5329c62cc",
        ): "9c26ac40256a2a2cf8b269a920950dee2f202d8f5f56384e4592662595bec5ca",
        (
            "StructureTests",
            "test_fixed_obligations",
            "089bad7d8e713aba748155d7133d97efbc91e8f449d18d22dd1e7d6c0fb02c26",
            "ea9b165cf979170283f12ebf0b32747eecd7c6d042506300bf5e09fc5e262392",
        ): "b815dfbc04d4b4ccbae38f1ed7b9c487a649e745e693f3f01bda68b3ee9071dd",
        (
            "EntryTests",
            "test_policy",
            "9db9395d1612b8c5fa105fd77004fa615d41b692434b16c44076797dcbd7e240",
            "2e64669ad5fdd0a374a6b326545dee732c359976dcac51dcffd2d7466a18eec8",
        ): "b815dfbc04d4b4ccbae38f1ed7b9c487a649e745e693f3f01bda68b3ee9071dd",
    }
    old = ast.parse(files["current-source/tests/test_structure.py"])
    current = ast.parse(v.read(root / "tests/test_structure.py"))
    for before in old.body:
        if not isinstance(before, ast.ClassDef):
            continue
        after = next((node for node in current.body if isinstance(node, ast.ClassDef) and node.name == before.name), None)
        if after is None:
            v.reject("storage-independence-oracle-class")
        for method in before.body:
            if isinstance(method, ast.FunctionDef):
                newer = next((node for node in after.body if isinstance(node, ast.FunctionDef) and node.name == method.name), None)
                if newer is None or len(newer.body) < len(method.body):
                    v.reject("storage-independence-oracle-method")
                # Exact policy-ledger and Server-only fixture migrations preserve every Storage oracle assertion.
                migration = (
                    before.name,
                    method.name,
                    v.digest(ast.dump(method, include_attributes=False).encode()),
                    v.digest(ast.dump(newer, include_attributes=False).encode()),
                )
                if migration in migrations:
                    approved = migrations[migration]
                    if v.file_digest(root / "tests/fixtures/qualification.json") not in (approved if isinstance(approved, tuple) else (approved,)):
                        v.reject("storage-independence-oracle-policy")
                    continue
                newer.body = newer.body[: len(method.body)]
                if ast.dump(method, include_attributes=False) != ast.dump(newer, include_attributes=False):
                    v.reject("storage-independence-oracle-weakened")


def reconcile(root: Path, artifacts: dict[str, bytes]) -> dict:
    """Recompute residual proofs and geometry, reusing the pinned successful qualification of 265 coordinates."""
    from tools import idle

    if idle.current(root):
        return idle.reconcile(root, artifacts)
    local = ancestry(artifacts)
    native = storage.retained(artifacts[BASE + "native/evidence.tar.gz"], v.decode(artifacts[BASE + "native/sealed.native.json"]), NATIVE)
    original_source = entry.unpack(native["source.tar.gz"])
    source_inputs = v.decode(native["inputs.json"])
    if (
        v.digest(native["source.tar.gz"]) != source_inputs["source_archive_sha256"]
        or {name: v.digest(data) for name, data in original_source.items()} != source_inputs["files"]
    ):
        v.reject("storage-independence-helper-archive")
    sources(root, local, original_source)
    certificate = BASE.rstrip("/").split("/")[-1] + "/"
    received = v.decode(local[certificate + "received.json"])
    record = v.decode(local[certificate + "reception/record.json"])
    if (
        record["exit_code"] != 0
        or record["complete"] is not True
        or record["cleanup"] is not True
        or record["termination"] != "exited"
        or record["platform"] != "windows-amd64"
        or record["executable_sha256"] != "80da2dbc9aca9420877223d6bf9ec0f5d9fd066a79ed65a3e3870037ff4e03e8"
        or v.digest(local[certificate + "receive.py"]) != "4ce765e6af8a659bc3cb921f0f4d8c13dfe01f5df9a6b703ec5aed8152157a56"
    ):
        v.reject("storage-independence-qualification-receipt")
    output = storage.reference(local, certificate + "reception/", record["stdout"])
    if storage.reference(local, certificate + "reception/", record["stderr"]) or ast.literal_eval(output.decode()) != {
        "raw": 279,
        "qualified": 271,
        "supported": 271,
        "excluded": 8,
        "unresolved": 0,
        "native_assertions": 16,
        "control_assertions": 1140,
        "whole_system": "blocked",
    }:
        v.reject("storage-independence-qualification-output")
    structural = storage.reconcile(root, {name: artifacts[name] for name in storage.ARTIFACTS})
    original = storage.retained(artifacts[storage.BASE + "evidence.tar.gz"], v.decode(artifacts[storage.BASE + "sealed.native.json"]), storage.ARCHIVE)
    bundle = v.decode(original[storage.PREFIX + "bundle.json"])
    typed = v.decode(storage.reference(original, storage.PREFIX, bundle["typed"]))
    trace = v.decode(storage.reference(original, storage.PREFIX + "typed/", typed["trace"]))
    native_record = v.decode(original[storage.PREFIX + "typed/tests/record.json"])
    events = storage.reference(original, storage.PREFIX + "typed/tests/", native_record["stdout"])
    decisions = logic.inventory(trace)
    observed, _ = logic.observe(trace, events, "github.com/eosforge/astra/" + retention.PACKAGE, 247)
    inputs = v.decode(native["inputs.json"])
    prefix = "source/build/commands/independence/"
    native_record = v.decode(native[prefix + "record.json"])
    data = storage.reference(native, prefix, native_record["stdout"])
    storage.reference(native, prefix, native_record["stderr"])
    hits, failures = v.go_observations(data, inputs["consumer_checks"]["independence"])
    if failures or hits != {"STORAGE-RETENTION-INPUTS": 16} or native_record["exit_code"] != 0 or native_record["cleanup"] is not True:
        v.reject("storage-independence-native-inputs")
    frames = []
    for line in data.splitlines():
        event = v.decode(line)
        if event.get("Action") == "output" and event.get("Output", "").startswith("STORAGE-RETENTION-INPUT "):
            frame = v.decode(event["Output"].removeprefix("STORAGE-RETENTION-INPUT ").encode())
            if frame["test"] != event.get("Test"):
                v.reject("storage-independence-input-owner")
            frames.append(frame)
    dependencies = {name: native["dependencies/" + name] for name in v.decode(native["dependencies.native.json"])}
    proof = retention.residual(decisions, observed, frames, retention.sources(root, dependencies))
    previous = storage.retained(
        artifacts["reuse-plan/storage-returns-current-1/local-evidence.tar.gz"],
        v.decode(artifacts["reuse-plan/storage-returns-current-1/local.sealed.json"]),
        "d3be8e6f71aef043059592eb383e40fa3fb4a5c7b219cb0805f58b5b13f72ecd",
    )
    prior = v.decode(previous["storage-returns-current-1/received.json"])
    remaining = {(row["decision"], row["condition"]) for row in prior["unresolved"]}
    supported = {(row["decision"], row["condition"]) for row in proof["pairs"]}
    excluded = {(row["decision"], row["condition"]) for row in proof["exclusions"]}
    coordinates = {(name, index) for name, decision in decisions.items() for index in range(len(decision["atoms"]))}
    if (
        len(coordinates) != 279
        or len(coordinates - remaining) != 265
        or prior["supported_conditions"] != 265
        or remaining != supported | excluded
        or supported & excluded
        or len(supported) != 6
        or len(excluded) != 8
        or len(coordinates - excluded) != 271
        or received["new_pairs"] != proof["pairs"]
        or received["exclusions"] != proof["exclusions"]
    ):
        v.reject("storage-independence-partition")
    return {
        "source_sha256": structural["source_sha256"],
        "raw_conditions": len(coordinates),
        "supported_conditions": len(coordinates - remaining | supported),
        "qualified_denominator": len(coordinates - excluded),
        "reused_conditions": len(coordinates - remaining),
        "exclusions": proof["exclusions"],
        "new_pairs": proof["pairs"],
        "trust": "local",
        "platform": structure.PLATFORM,
        "basis": "Frozen successful local qualification plus recomputed native geometry and residual proofs; unrelated product and release obligations receive no credit.",
    }


def load(directory: Path, root: Path) -> dict:
    """Resolve only owned bundle members before independently replaying the qualification."""
    bundle = v.decode(v.read(directory / "bundle.json"))
    logic.fields(bundle, ("version", "retained"), "storage-independence-bundle")
    if bundle["version"] != 1 or not isinstance(bundle["retained"], dict):
        v.reject("storage-independence-bundle-version")
    artifacts = {}
    for name, item in bundle["retained"].items():
        if item.get("path") != "retained/" + name:
            v.reject("storage-independence-bundle-path")
        artifacts[name] = v.reference(directory, item, MAXIMUM)
    return reconcile(root, artifacts)


def observations(data: bytes, check: dict, root: Path, evidence: dict | None) -> tuple[dict, list]:
    """Credit one Linux MC/DC coordinate only after bundle, record and source agree."""
    native = next(item for item in v.decode(v.read(root / "development.json"))["checks"] if item["id"] == "storage-structure")
    configuration(check, native)
    if evidence is None:
        v.reject("storage-independence-evidence-missing")
    directory, record = evidence["directory"], evidence["record"]
    raw = structure.reference(directory, record["structure"], "structure/bundle.json")
    receipt = v.decode(data)
    logic.fields(receipt, ("bundle_sha256", "source_sha256", "qualification_sha256"), "storage-independence-receipt")
    if receipt["bundle_sha256"] != v.digest(raw):
        v.reject("storage-independence-receipt-binding")
    result = load(directory / "structure", root)
    if receipt["source_sha256"] != result["source_sha256"] or receipt["qualification_sha256"] != v.digest(v.encode(result)):
        v.reject("storage-independence-receipt-source")
    return {"STORAGE-ASSURANCE": result["supported_conditions"]}, []


def collect(root: Path, directory: Path) -> int:
    """Attach existing artifacts by hard link; no application, compiler or network command runs."""
    retained = artifacts(root)
    result = reconcile(root, retained)
    directory.mkdir(parents=True, exist_ok=False)
    references = {}
    for name, data in retained.items():
        target = v.inside(directory, "retained/" + name)
        target.parent.mkdir(parents=True, exist_ok=True)
        os.link(v.inside(root / "build/results/assurance", name), target)
        references[name] = structure.artifact(directory, target)
        if references[name]["sha256"] != v.digest(data):
            v.reject("storage-independence-source-raced")
    bundle = {"version": 1, "retained": references}
    v.write_new(directory / "bundle.json", bundle)
    print(
        v.encode(
            {"bundle_sha256": v.digest(v.encode(bundle)), "source_sha256": result["source_sha256"], "qualification_sha256": v.digest(v.encode(result))}
        ).decode()
    )
    return 0


def main() -> int:
    """Execute only the registered bounded retained-evidence adapter."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collect", action="store_true", required=True)
    parser.parse_args()
    try:
        config, _, _ = v.configuration(ROOT / "development.json", ROOT)
        check = next(check for check in config["checks"] if check["id"] == "storage-independence")
        native = next(check for check in config["checks"] if check["id"] == "storage-structure")
        configuration(check, native)
        if not os.environ.get("TMPDIR"):
            v.reject("storage-independence-output-missing")
        return collect(ROOT, Path(os.environ["TMPDIR"]).parent / "structure")
    except (OSError, v.Invalid, KeyError, TypeError, ValueError, StopIteration) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
