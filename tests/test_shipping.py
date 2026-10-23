"""Falsify streaming evidence, native ownership and actual linker closure without claiming synthetic execution."""

import copy
import io
import json
from pathlib import Path
import tempfile
import tarfile
import unittest

from tests.test_delivery import refresh_fixture
from tools import delivery, shipping, verify as v


def packed(rows: list[tuple[str, bytes, bytes]]) -> bytes:
    """Create literal archive parser controls, including unsafe names and non-file members."""
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:gz") as stream:
        for name, raw, kind in rows:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(raw) if kind == tarfile.REGTYPE else 0
            member.mode = 0o755
            if kind == tarfile.SYMTYPE:
                member.linkname = "outside"
            stream.addfile(member, io.BytesIO(raw) if kind == tarfile.REGTYPE else None)
    return result.getvalue()


def inspected() -> dict[str, bytes]:
    """Describe a retired read owner as a reader control, never a genuine process observation."""
    script = b"fixture read owner"
    identity = {"pid": 7, "start_ticks": "13", "boot_id": "fixture-boot"}
    inputs = {"driver_sha256": v.digest(script), "boot_id": "fixture-boot", "unit": "fixture.service", "expected": {"/input": "a" * 64}}
    owner = {
        "identity": identity,
        "inputs_sha256": v.digest(v.encode(inputs)),
        "driver_sha256": v.digest(script),
        "limits": {"memory.max": "268435456", "memory.swap.max": "0", "cpu.max": "100000 100000", "pids.max": "32"},
    }
    terminal = {"identity": identity, "complete": True, "errors": []}
    facts = {"checked": inputs["expected"], "unchanged_after": True}
    observation = {
        "state": {"MainPID": "0", "ControlGroup": "", "ExecMainStatus": "0", "Result": "success"},
        "terminal": terminal,
        "retirement": {"identity": identity, "current_start_ticks": None},
        "journal": [{"MESSAGE": "fixture.service: Deactivated successfully."}],
    }
    files = {
        "run.py": script,
        "inputs.json": v.encode(inputs),
        "owner.native.json": v.encode(owner),
        "facts.native.json": v.encode(facts),
        "terminal.native.json": v.encode(terminal),
        "observation.native.json": v.encode(observation),
    }
    return manifested(files)


def manifested(files: dict[str, bytes]) -> dict[str, bytes]:
    """Recompute fixture integrity so semantic mutations cannot be rejected only by an unrelated checksum."""
    files = {name: raw for name, raw in files.items() if name != "manifest.json"}
    return {
        **files,
        "manifest.json": v.encode({"trust": "local", "files": {name: {"bytes": len(raw), "sha256": v.digest(raw)} for name, raw in files.items()}}),
    }


def linked() -> tuple[dict, dict, dict, dict, dict]:
    """Use distinct literal source/link relationships; an unlinked oracle deliberately lacks a test filename suffix."""
    root, build, consumer, destination = "/source", "/source/build/release", "/source/build/consumer", "/delivery"
    source = {
        "star/src/runtime.cpp": "a" * 64,
        "comet/cpp/src/sdk.cpp": "b" * 64,
        "tests/delivery/main.cpp": "c" * 64,
        "star/tests/oracle.cpp": "d" * 64,
        "CMakeLists.txt": "e" * 64,
    }
    files, rows, commands = {}, [], {"production": [], "consumer": []}
    selected = [
        ("production", "CMakeFiles/runtime.dir/runtime.cpp.o", "star/src/runtime.cpp"),
        ("production", "comet/cpp/CMakeFiles/comet.dir/sdk.cpp.o", "comet/cpp/src/sdk.cpp"),
        ("production", "CMakeFiles/oracle.dir/oracle.cpp.o", "star/tests/oracle.cpp"),
        ("consumer", "CMakeFiles/consumer.dir/main.cpp.o", "tests/delivery/main.cpp"),
    ]
    for label, path, name in selected:
        directory = build if label == "production" else consumer
        raw = (path + ": " + root + "/" + name + "\n").encode()
        files["metadata/" + label + "/" + path + ".d"] = raw
        rows.append({"build": label, "path": path + ".d", "sha256": v.digest(raw), "files": {root + "/" + name: source[name]}})
        commands[label].append({"directory": directory, "file": root + "/" + name, "command": "g++ -c " + root + "/" + name + " -o " + path})
    for name in ("star", "planet", "pulsar"):
        files["metadata/production/CMakeFiles/" + name + ".dir/link.txt"] = (
            "g++ CMakeFiles/runtime.dir/runtime.cpp.o -o " + name + " comet/cpp/libcomet.a /deps/vendor.a\n"
        ).encode()
    for name in ("consumer", "comet_batch_test", "comet_mesh_probe", "comet_process_probe"):
        files["metadata/consumer/CMakeFiles/" + name + ".dir/link.txt"] = (
            "g++ CMakeFiles/consumer.dir/main.cpp.o -o " + name + " /delivery/candidate/lib/libcomet.a\n"
        ).encode()
    link = b"/usr/bin/ar qc libcomet.a CMakeFiles/comet.dir/sdk.cpp.o\n/usr/bin/ranlib libcomet.a\n"
    files["metadata/production/comet/cpp/CMakeFiles/comet.dir/link.txt"] = link
    for label, values in commands.items():
        files["metadata/" + label + "/compile_commands.json"] = v.encode(values)
    files["compiled-inputs.native.json"] = v.encode(rows)
    files["products.native.json"] = v.encode({destination + "/candidate/bin/star": "f" * 64})
    files["protected.native.json"] = v.encode({"/deps/vendor.a": "9" * 64})
    native = {
        "metadata": {},
        "aliases": {},
        "checked": {**{root + "/" + name: sha for name, sha in source.items()}, build + "/comet/cpp/libcomet.a": "8" * 64, "/deps/vendor.a": "9" * 64},
        "archive_members": {build + "/comet/cpp/CMakeFiles/comet.dir/sdk.cpp.o": {"member": "sdk.cpp.o", "sha256": "7" * 64}},
    }
    inputs = {"root": root, "build": build, "consumer": consumer, "files": source}
    return files, inputs, native, dict(source), {"lib/libcomet.a": "8" * 64}


def acquired_fixture() -> tuple[dict[str, bytes], set[str], str, str]:
    """Declare a literal successful current-format parser history, including multiline native output."""
    files = refresh_fixture()
    owner, terminal, cleanup = (v.decode(files[name]) for name in ("controller.json", "terminal.json", "cleanup.native.json"))
    names = {row["id"] for row in terminal["completed"]}
    terminal["records"] = {}
    terminal["resources"] = {"memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n"}
    for name in names:
        prefix = "source/build/commands/" + name + "/"
        files[prefix + "request.json"] = v.encode({"argv": v.decode(files[prefix + "record.json"])["argv"]})
        terminal["records"][name] = {"record_sha256": v.digest(files[prefix + "record.json"])}
    cleanup["failed"] = False
    boot, invocation = owner["boot_id"], owner["invocation_id"]
    unit = "fixture-current-install.service"
    lines = json.dumps(terminal, indent=2).splitlines()
    journal = [{"_PID": str(owner["identity"]["pid"]), "MESSAGE": line} for line in lines]
    journal += [{"_PID": "1", "MESSAGE": unit + ": Deactivated successfully."}]
    for row in journal:
        row.update(_BOOT_ID=boot.replace("-", ""), INVOCATION_ID=invocation)
    files["terminal.json"], files["cleanup.native.json"] = v.encode(terminal), v.encode(cleanup)
    files["journal.native.jsonl"] = b"\n".join(json.dumps(row).encode() for row in journal) + b"\n"
    return files, names, unit, boot


def built_fixture() -> tuple[shipping.Archive, dict[str, str]]:
    """Reach the Go source gate with literal reader-control facts, without claiming an executed build."""
    data = {"go.mod": b"root manifest", "polaris/main.go": b"root service", "comet/go/go.mod": b"sdk manifest", "comet/go/client.go": b"sdk client"}
    current = {name: v.digest(raw) for name, raw in data.items()}
    script = b"literal build reader fixture"
    inputs = {"run_sha256": v.digest(script), "linux_go": shipping.RENEWED_GO, "linux_go_sha256": shipping.RENEWED_COMPILER, "files": current}
    identity = {"pid": 7, "start_ticks": "13"}
    worker = {"inputs_sha256": v.digest(v.encode(inputs)), "script_sha256": inputs["run_sha256"], "identity": identity}
    terminal = {"errors": [], "interrupted": False, "remaining_owned": []}
    files = {
        "inputs.json": v.encode(inputs),
        "run.py": script,
        "source.tar.gz": packed([(name, raw, tarfile.REGTYPE) for name, raw in data.items()]),
        "cleanup.native.json": v.encode({"unit": {"MainPID": "0", "ControlGroup": ""}, "retired": [identity]}),
    }
    for selection in ("root-ordinary", "sdk-ordinary"):
        files[selection + "-owner.json"] = v.encode(worker)
        files[selection + "-result.json"] = v.encode({})
        files[selection + "-terminal.json"] = v.encode(terminal)
    return shipping.Archive(files, {}, {}, {}, {}), current


class Shipping(unittest.TestCase):
    """Reject scope substitution, missing link edges, source drift and incomplete native provenance."""

    def test_streams_products_without_retaining_them(self) -> None:
        """Stream oversized products into digests while retaining only bounded build metadata."""
        payload = b"\x7fELF" + b"x" * (2 * 1024**2)
        raw = packed([("candidate/bin/program", payload, tarfile.REGTYPE), ("metadata.json", b"{}", tarfile.REGTYPE)])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.tar.gz"
            path.write_bytes(raw)
            actual = shipping.archive(path, v.digest(raw))
        self.assertEqual(actual.hashes["candidate/bin/program"], v.digest(payload))
        self.assertEqual(actual.sizes["candidate/bin/program"], len(payload))
        self.assertNotIn("candidate/bin/program", actual.files)
        self.assertEqual(actual.files, {"metadata.json": b"{}"})
        trace = "source/build/commands/root-ordinary-test/test.stdout.log"
        build = "source/build/commands/root-ordinary-polaris-metadata/metadata.stdout.log"
        # This independent fixture exceeds only metadata retention; every byte must still be authenticated.
        oversized = b"trace" * (4 * 1024**2)
        raw = packed([(trace, oversized, tarfile.REGTYPE), (build, b"recorded build metadata", tarfile.REGTYPE)])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "build-evidence.tar.gz"
            path.write_bytes(raw)
            with self.assertRaisesRegex(v.Invalid, "shipping-metadata-size"):
                shipping.archive(path, v.digest(raw))
            selected = shipping.archive(path, v.digest(raw), builds=True)
            self.assertEqual(selected.hashes[trace], v.digest(oversized))
            self.assertEqual(selected.sizes[trace], len(oversized))
            self.assertNotIn(trace, selected.files)
            self.assertEqual(selected.files[build], b"recorded build metadata")
            with self.assertRaisesRegex(v.Invalid, "shipping-archive-policy"):
                shipping.archive(path, v.digest(raw), builds=1)

    def test_rejects_archive_aliases_duplicates_types_and_untrusted_bytes(self) -> None:
        """Reject unsafe archive entries, digest mismatches, and damaged current acquisitions."""
        cases = [
            [("../outside", b"", tarfile.REGTYPE)],
            [("/absolute", b"", tarfile.REGTYPE)],
            [("a\\b", b"", tarfile.REGTYPE)],
            [("same", b"1", tarfile.REGTYPE), ("same", b"2", tarfile.REGTYPE)],
            [("link", b"", tarfile.SYMTYPE)],
        ]
        for rows in cases:
            with self.subTest(rows=rows), tempfile.TemporaryDirectory() as directory:
                raw = packed(rows)
                path = Path(directory) / "evidence.tar.gz"
                path.write_bytes(raw)
                with self.assertRaises(v.Invalid):
                    shipping.archive(path, v.digest(raw))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.tar.gz"
            path.write_bytes(packed([("safe", b"value", tarfile.REGTYPE)]))
            with self.assertRaisesRegex(v.Invalid, "shipping-archive"):
                shipping.archive(path, "0" * 64)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / shipping.PREFIX / next(iter(shipping.RENEWED))
            path.parent.mkdir(parents=True)
            path.write_bytes(b"damaged current acquisition")
            self.assertTrue(shipping.current(root))
            with self.assertRaisesRegex(v.Invalid, "shipping-archive"):
                delivery.reconcile(root)

    def test_unlinked_drift_is_reported_without_qualifying_the_oracle(self) -> None:
        """Report drift outside the linked closure without granting that source oracle credit."""
        files, inputs, native, current, candidate = linked()
        current["star/tests/oracle.cpp"] = "0" * 64
        actual = shipping.closure(files, inputs, native, current, candidate)
        self.assertEqual(actual["linked_units"], 3)
        self.assertEqual(actual["unlinked_drift"], {"star/tests/oracle.cpp": {"original": "d" * 64, "current": "0" * 64}})
        self.assertNotIn("star/tests/oracle.cpp", actual["project_inputs"])

    def test_rejects_linked_source_or_build_configuration_drift(self) -> None:
        """Reject linked source or build drift, including added and removed Go inputs."""
        for name in ("star/src/runtime.cpp", "comet/cpp/src/sdk.cpp", "tests/delivery/main.cpp", "CMakeLists.txt"):
            with self.subTest(name=name):
                files, inputs, native, current, candidate = linked()
                current[name] = "0" * 64
                with self.assertRaises(v.Invalid):
                    shipping.closure(files, inputs, native, current, candidate)
        # A one-way digest comparison misses deletions; require the source-gate rejection in both module modes.
        for selection, product, deleted, added in (
            ("root-ordinary", "polaris", "polaris/main.go", "polaris/added.go"),
            ("sdk-ordinary", "comet-go-system-ordinary", "comet/go/client.go", "comet/go/added_test.go"),
        ):
            built, current = built_fixture()
            for mutation, changed in (
                ("delete", {name: sha for name, sha in current.items() if name != deleted}),
                ("add", current | {added: "0" * 64}),
            ):
                with self.subTest(selection=selection, mutation=mutation), self.assertRaisesRegex(v.Invalid, "shipping-renewed-build-source"):
                    shipping.product(built, selection, product, changed)

    def test_rejects_missing_objects_and_unpinned_libraries(self) -> None:
        """Reject closures missing object, library, archive-member, or response-file evidence."""
        for operation in ("object", "library", "archive", "member", "response"):
            with self.subTest(operation=operation):
                files, inputs, native, current, candidate = linked()
                if operation == "object":
                    rows = v.decode(files["compiled-inputs.native.json"])
                    files["compiled-inputs.native.json"] = v.encode(rows[1:])
                elif operation == "library":
                    files["protected.native.json"] = v.encode({})
                elif operation == "archive":
                    native["checked"][inputs["build"] + "/comet/cpp/libcomet.a"] = "0" * 64
                elif operation == "member":
                    native["archive_members"] = {}
                else:
                    files["metadata/production/CMakeFiles/star.dir/link.txt"] = b"g++ @hidden CMakeFiles/runtime.dir/runtime.cpp.o -o star\n"
                with self.assertRaises(v.Invalid):
                    shipping.closure(files, inputs, native, current, candidate)

    def test_recomputes_inspection_integrity_and_native_retirement(self) -> None:
        """Recompute inspection integrity and reject changed native process retirement evidence."""
        files = inspected()
        inputs, facts = shipping.inspection(files)
        self.assertEqual(facts["checked"], inputs["expected"])
        for name, field, value in (
            ("facts.native.json", "unchanged_after", False),
            ("facts.native.json", "checked", {}),
            ("terminal.native.json", "errors", ["failure"]),
            ("owner.native.json", "limits", {}),
        ):
            with self.subTest(name=name, field=field):
                changed = copy.deepcopy(files)
                item = v.decode(changed[name])
                item[field] = value
                changed[name] = v.encode(item)
                with self.assertRaises(v.Invalid):
                    shipping.inspection(manifested(changed))
        changed = dict(files)
        observation = v.decode(changed["observation.native.json"])
        observation["retirement"]["current_start_ticks"] = "13"
        changed["observation.native.json"] = v.encode(observation)
        with self.assertRaisesRegex(v.Invalid, "shipping-inspection"):
            shipping.inspection(manifested(changed))

    def test_rejects_original_command_or_parent_failure_substitution(self) -> None:
        """Reject substituted command outcomes, ownership, output, or parent campaign evidence."""
        files = refresh_fixture()
        terminal = v.decode(files["terminal.json"])
        names = {row["id"] for row in terminal["completed"]}
        terminal["completed"] = {row["id"]: {key: value for key, value in row.items() if key != "id"} for row in terminal["completed"]}
        files["terminal.json"] = v.encode(terminal)
        journal = [v.decode(row) for row in files["journal.native.jsonl"].splitlines()]
        journal[1]["MESSAGE"] = json.dumps({"at": "fixture", **terminal})
        terminal = {"at": "fixture", **terminal}
        files["terminal.json"] = v.encode(terminal)
        files["journal.native.jsonl"] = b"\n".join(json.dumps(row).encode() for row in journal)
        for name in names:
            prefix = "source/build/commands/" + name + "/"
            files[prefix + "request.json"] = v.encode({"argv": v.decode(files[prefix + "record.json"])["argv"]})
        self.assertEqual(set(shipping.campaign(files, "source/build/commands/", names)), names)
        for mutation in ("errors", "owner", "retirement", "stdout"):
            with self.subTest(mutation=mutation):
                changed = dict(files)
                name = sorted(names)[0]
                prefix = "source/build/commands/" + name + "/"
                if mutation == "errors":
                    item = v.decode(changed["terminal.json"])
                    item["errors"] = ["unexpected"]
                    changed["terminal.json"] = v.encode(item)
                elif mutation == "owner":
                    item = v.decode(changed[prefix + name + ".process.json"])
                    item["identity"]["parent"] = 999
                    changed[prefix + name + ".process.json"] = v.encode(item)
                elif mutation == "retirement":
                    item = v.decode(changed["cleanup.native.json"])
                    item["retired"] = item["retired"][1:]
                    changed["cleanup.native.json"] = v.encode(item)
                else:
                    changed[prefix + "stdout.log"] = b"untrusted output"
                with self.assertRaises(v.Invalid):
                    shipping.campaign(changed, "source/build/commands/", names)
        files, names, unit, boot = acquired_fixture()
        self.assertEqual(set(shipping.native(files, "source/build/commands/", names, unit=unit, boot=boot)), names)
        for mutation in ("errors", "memory", "parent", "retirement", "journal-exit", "journal-terminal", "boot"):
            with self.subTest(current=mutation):
                changed = dict(files)
                if mutation in {"errors", "memory"}:
                    item = v.decode(changed["terminal.json"])
                    if mutation == "errors":
                        item["errors"] = ["child failed"]
                    else:
                        item["resources"]["memory.events"] = "max 1\n"
                    changed["terminal.json"] = v.encode(item)
                elif mutation == "parent":
                    path = "source/build/commands/" + sorted(names)[0] + "/" + sorted(names)[0] + ".process.json"
                    item = v.decode(changed[path])
                    item["identity"]["parent"] = 999
                    changed[path] = v.encode(item)
                elif mutation == "retirement":
                    item = v.decode(changed["cleanup.native.json"])
                    item["retired"] = item["retired"][1:]
                    changed["cleanup.native.json"] = v.encode(item)
                else:
                    journal = [v.decode(line) for line in changed["journal.native.jsonl"].splitlines()]
                    if mutation == "journal-exit":
                        journal.pop()
                    elif mutation == "journal-terminal":
                        journal[0]["MESSAGE"] = "[]"
                        journal = [journal[0], journal[-1]]
                    else:
                        journal[0]["_BOOT_ID"] = "0" * 32
                    changed["journal.native.jsonl"] = b"\n".join(json.dumps(row).encode() for row in journal)
                with self.assertRaises(v.Invalid):
                    shipping.native(changed, "source/build/commands/", names, unit=unit, boot=boot)
        with self.assertRaisesRegex(v.Invalid, "shipping-native-format"):
            shipping.native(files, "source/build/commands/", names, unit=unit, boot=boot, flat=1)


if __name__ == "__main__":
    unittest.main()
