"""Reject altered Astrolabe provenance and vacuous input proofs without running an application."""

import copy
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import astrolabe, authority, entry, logic, verify as v


def events(tests: list[str]) -> bytes:
    """Create a synthetic complete package lifecycle; these lines are not native evidence."""
    package = astrolabe.MODULE + "astrolabe"
    rows = [{"Package": package, "Action": "start"}]
    for name in tests:
        rows.extend({"Package": package, "Action": action, "Test": name} for action in ("run", "pass"))
    rows.append({"Package": package, "Action": "pass"})
    return b"".join(json.dumps(row).encode() + b"\n" for row in rows)


def children() -> list[dict]:
    """Supply synthetic joined child observations inside their parent and subtest lifecycles."""
    package = astrolabe.MODULE + "astrolabe"
    rows = [{"Action": "start"}, {"Action": "run", "Test": "TestProcess"}]
    for index, (name, (code, signal, calls)) in enumerate(astrolabe.EXITS.items()):
        receipt = {
            "case": name,
            "pid": 100 + index,
            "start_ticks": str(10 + index),
            "boot_id": "boot",
            "signal": signal,
            "exit_code": code,
            "calls": calls,
            "reaped": True,
        }
        rows.extend(
            {"Test": "TestProcess/" + name, **event}
            for event in (
                {"Action": "run"},
                {"Action": "output", "Output": "    process_test.go:170: ASTROLABE-PROCESS " + json.dumps(receipt) + "\n"},
                {"Action": "pass"},
            )
        )
    rows.extend(({"Action": "pass", "Test": "TestProcess"}, {"Action": "pass"}))
    return [{"Package": package, **row} for row in rows]


def native() -> dict[str, bytes]:
    """Supply an explicitly synthetic minimal native carrier for provenance rejection tests."""
    identity = {"pid": 100, "start_ticks": 10}
    owner = {"script_sha256": v.digest(b"runner"), "identity": identity, "boot_id": "boot", "invocation_id": "job"}
    cleanup = {
        "retired": [identity],
        "boot_id": "boot",
        "service": {"InvocationID": "job", "MainPID": "0", "ControlGroup": "", "ExecMainStatus": "0", "SubState": "exited"},
    }
    terminal = {
        "errors": [],
        "remaining_owned": [],
        "interrupted": False,
        "source_unchanged": True,
        "pins_unchanged": True,
        "resources": {"memory.events": "max 0\noom 0\noom_kill 0\noom_group_kill 0"},
    }
    return {
        "run.py": b"runner",
        **{name + ".json": v.encode(value) for name, value in (("controller", owner), ("cleanup.native", cleanup), ("terminal", terminal))},
    }


def archive(files: dict[str, bytes]) -> tuple[bytes, dict]:
    """Wrap synthetic members and their byte ledger without granting them a registered archive identity."""
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as stream:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            stream.addfile(member, io.BytesIO(data))
    data = output.getvalue()
    seal = {
        "archive_sha256": v.digest(data),
        "bytes": len(data),
        "trust": "local",
        "files": {name: {"bytes": len(value), "sha256": v.digest(value)} for name, value in files.items()},
    }
    return data, seal


class AstrolabeTests(unittest.TestCase):
    """Preserve native identities, complete scope and the distinction between observations and proofs."""

    def test_archive(self) -> None:
        """A byte digest, member ledger and local trust declaration must all agree."""
        files = native()
        data, seal = archive(files)
        self.assertEqual(astrolabe.retained(data, seal, v.digest(data)), files)
        for field, value in (("archive_sha256", "0" * 64), ("bytes", len(data) - 1), ("trust", "release")):
            changed = copy.deepcopy(seal)
            changed[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "astrolabe-archive-integrity"):
                astrolabe.retained(data, changed, v.digest(data))
        changed = copy.deepcopy(seal)
        del changed["files"]["run.py"]
        with self.assertRaisesRegex(v.Invalid, "astrolabe-archive-inventory"):
            astrolabe.retained(data, changed, v.digest(data))
        changed = copy.deepcopy(seal)
        changed["files"]["run.py"]["bytes"] += 1
        with self.assertRaisesRegex(v.Invalid, "astrolabe-member-integrity"):
            astrolabe.retained(data, changed, v.digest(data))
        with self.assertRaisesRegex(v.Invalid, "astrolabe-archive-integrity"):
            astrolabe.retained(data + b"extra", seal, v.digest(data))
        changed = {key: value for key, value in seal.items() if key != "trust"}
        changed["qualification"] = "Native Astrolabe structure batch only; independent interpretation required"
        with self.assertRaisesRegex(v.Invalid, "astrolabe-archive-integrity"):
            astrolabe.retained(data, changed, v.digest(data))

        # Synthetic artifact bytes exercise the parser, never native application facts.
        files = {name: name.encode() for name in astrolabe.artifacts()}
        pins = {name: v.digest(value) for name, value in files.items()}
        with patch.object(astrolabe, "artifacts", return_value=pins):
            self.assertEqual(astrolabe.materials(files), files)
            for changed in ({}, {**files, "unexpected": b"extra"}, {**files, next(iter(files)): "not bytes"}):
                with self.assertRaisesRegex(v.Invalid, "astrolabe-retained-inventory"):
                    astrolabe.materials(changed)
            for name in files:
                with self.subTest(artifact=name), self.assertRaisesRegex(v.Invalid, "astrolabe-retained-integrity"):
                    astrolabe.materials({**files, name: files[name] + b"changed"})
            with patch.object(entry, "LIMIT", max(map(len, files.values()))), self.assertRaisesRegex(v.Invalid, "astrolabe-retained-capacity"):
                astrolabe.materials(files)
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                for name, value in files.items():
                    path = directory / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(value)
                self.assertEqual(astrolabe.materials(directory), files)

    def test_retirement(self) -> None:
        """A retired PID alone cannot hide a different owner, failed command or changed source."""
        # Only the pinned dependency-copy failure permits reuse of a successful child command.
        files = native()
        cleanup = v.decode(files["cleanup.native.json"])
        cleanup["service"].update(ExecMainStatus="2", SubState="failed")
        files["cleanup.native.json"] = v.encode(cleanup)
        terminal = v.decode(files["terminal.json"])
        terminal["errors"] = [
            "FileNotFoundError: [Errno 2] No such file or directory: '/home/ubuntu/verdandi/astra/build/results/assurance/reuse-material-endpoints-2/dependencies/go/errors/errors.go'"
        ]
        files["terminal.json"] = v.encode(terminal)
        data, seal = archive(files)
        with patch.dict(astrolabe.ARCHIVES, {"material-endpoints-2": v.digest(data)}):
            self.assertEqual(astrolabe.retained(data, seal, v.digest(data)), files)
        for replacement in ([], ["application failure"], terminal["errors"] + ["another failure"]):
            files["terminal.json"] = v.encode({**terminal, "errors": replacement})
            data, seal = archive(files)
            with patch.dict(astrolabe.ARCHIVES, {"material-endpoints-2": v.digest(data)}), self.assertRaisesRegex(v.Invalid, "astrolabe-native-retirement"):
                astrolabe.retained(data, seal, v.digest(data))
        for name, field, value in (
            ("controller", "script_sha256", "0" * 64),
            ("controller", "boot_id", "another-boot"),
            ("controller", "identity", {"pid": 100, "start_ticks": 11}),
            ("controller", "invocation_id", "another-job"),
            ("cleanup.native", "retired", []),
            ("terminal", "errors", ["failed"]),
            ("terminal", "remaining_owned", [100]),
            ("terminal", "interrupted", True),
            ("terminal", "source_unchanged", False),
            ("terminal", "pins_unchanged", False),
        ):
            files = native()
            record = v.decode(files[name + ".json"])
            record[field] = value
            files[name + ".json"] = v.encode(record)
            data, seal = archive(files)
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "astrolabe-native-retirement"):
                astrolabe.retained(data, seal, v.digest(data))
        for field, value in (("MainPID", "100"), ("ControlGroup", "/still-owned"), ("ExecMainStatus", "1"), ("SubState", "running")):
            files = native()
            record = v.decode(files["cleanup.native.json"])
            record["service"][field] = value
            files["cleanup.native.json"] = v.encode(record)
            data, seal = archive(files)
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "astrolabe-native-retirement"):
                astrolabe.retained(data, seal, v.digest(data))

    def test_resources(self) -> None:
        """Exhausted or missing resource counters cannot become a valid local observation."""
        for name in ("max", "oom", "oom_kill", "oom_group_kill"):
            for value in ("1", None):
                files = native()
                record = v.decode(files["terminal.json"])
                rows = dict(row.split() for row in record["resources"]["memory.events"].splitlines())
                if value is None:
                    del rows[name]
                else:
                    rows[name] = value
                record["resources"]["memory.events"] = "\n".join(key + " " + count for key, count in rows.items())
                files["terminal.json"] = v.encode(record)
                data, seal = archive(files)
                with self.subTest(counter=name, value=value), self.assertRaisesRegex(v.Invalid, "astrolabe-resource-failure"):
                    astrolabe.retained(data, seal, v.digest(data))

    def test_terminals(self) -> None:
        """Required names, native lifecycle and actual package selection jointly prevent empty passes."""
        package = astrolabe.MODULE + "astrolabe"
        data = events(["TestOne", "TestTwo"])
        self.assertEqual(astrolabe.terminals(data, package, ["TestOne", "TestTwo"]), data)
        for expected in ([], ["TestOne"], ["TestOne", "TestTwo", "TestMissing"], ["TestOne", "TestOne"]):
            with self.subTest(expected=expected), self.assertRaisesRegex(v.Invalid, "astrolabe-test-inventory"):
                astrolabe.terminals(data, package, expected)
        for source, replacement in ((b'"pass"', b'"skip"'), (b'"pass"', b'"fail"'), (b'"run"', b'"output"')):
            with self.subTest(replacement=replacement), self.assertRaises(v.Invalid):
                astrolabe.terminals(data.replace(source, replacement, 1), package, ["TestOne", "TestTwo"])
        with self.assertRaisesRegex(v.Invalid, "astrolabe-test-inventory"):
            astrolabe.terminals(data, package + "-different", ["TestOne", "TestTwo"])

    def test_command(self) -> None:
        """Complete output, exact child ownership and pinned execution inputs are jointly required."""
        files = native()
        tool = {"path": "/tools/go", "sha256": astrolabe.GO}
        record = {
            "id": "typed",
            "argv": [tool["path"], "test", "./astrolabe"],
            "exit_code": 0,
            "complete": True,
            "cleanup": True,
            "termination": "exited",
            "platform": "linux-amd64-cgo",
            "started_at": "2026-10-09T00:00:00Z",
            "finished_at": "2026-10-09T00:00:01Z",
            "resolved_environment": {"GOCACHE": "/source/build/cache/go"},
            "executable": tool["path"],
            "executable_sha256": tool["sha256"],
            "toolchain": {"go": tool},
        }
        for channel in ("stdout", "stderr"):
            data = channel.encode()
            record[channel] = {"path": channel + ".log", "bytes": len(data), "sha256": v.digest(data)}
            files["command/" + channel + ".log"] = data
        child = {"argv": record["argv"], "identity": {"pid": 100, "start_ticks": 10}, "boot_id": "boot", "cwd": "/source"}
        files["command/record.json"] = v.encode(record)
        files["command/typed.process.json"] = v.encode(child)
        files["preflight.json"] = v.encode({"pins": {tool["path"]: tool["sha256"]}})
        self.assertEqual(astrolabe.command(files, "command/"), (record, b"stdout"))
        for field, value in (
            ("exit_code", 1),
            ("complete", False),
            ("cleanup", False),
            ("termination", "timeout"),
            ("platform", "windows-amd64"),
            ("finished_at", "2026-10-08T23:59:59Z"),
            ("argv", ["different"]),
            ("executable_sha256", "b" * 64),
            ("toolchain", {"go": {**tool, "sha256": "b" * 64}}),
            ("resolved_environment", {"GOCACHE": "/source/build/cache/go", "GOEXPERIMENT": "nojsonv2"}),
        ):
            changed = {**files, "command/record.json": v.encode({**record, field: value})}
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "astrolabe-native-command"):
                astrolabe.command(changed, "command/")
        for field, value in (("identity", {"pid": 100, "start_ticks": 11}), ("boot_id", "new"), ("cwd", "/other")):
            changed = {**files, "command/typed.process.json": v.encode({**child, field: value})}
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "astrolabe-native-command"):
                astrolabe.command(changed, "command/")
        for channel in ("stdout", "stderr"):
            changed = {**files, "command/" + channel + ".log": b"altered"}
            with self.subTest(channel=channel), self.assertRaisesRegex(v.Invalid, "astrolabe-native-stream"):
                astrolabe.command(changed, "command/")

        # Synthetic dependency selection exercises provenance, not library semantics.
        prefix = "source/build/commands/dependencies/"
        names = ["encoding/json", "strings", "crypto/rand", "google.golang.org/grpc", "google.golang.org/protobuf/proto"]
        packages = [{"ImportPath": name, "GoFiles": ["v2_decode.go", "v2_stream.go"] if name == "encoding/json" else []} for name in names]
        extra, seal = archive({"encoding/json/v2_stream.go": b"synthetic-json"})
        seal["go_sha256"] = astrolabe.GO
        expected = {"dependencies/go/strings/strings.go": b"synthetic-strings", "dependencies/go/encoding/json/v2_stream.go": b"synthetic-json"}
        digest = v.digest(v.encode({name: v.digest(data) for name, data in sorted(expected.items())}))
        selected = {key.replace("command/", prefix, 1): value for key, value in files.items()}
        selected["dependencies/go/strings/strings.go"] = b"synthetic-strings"
        args = ["go", "list", "-json", *names]
        child = {**child, "argv": args}
        selected[prefix + "typed.process.json"] = v.encode(child)
        record = {**record, "argv": args}

        def selection(values: list[dict]) -> dict[str, bytes]:
            """Keep synthetic stream digests honest so selection errors reach their intended boundary."""
            output = b"\n".join(v.encode(value) for value in values)
            receipt = {**record, "stdout": {"path": "stdout.log", "bytes": len(output), "sha256": v.digest(output)}}
            return {**selected, prefix + "stdout.log": output, prefix + "record.json": v.encode(receipt)}

        selected = selection(packages)
        with patch.object(astrolabe, "EXTRA", v.digest(extra)), patch.object(astrolabe, "DEPENDENCIES", digest):
            self.assertEqual(astrolabe.dependencies(selected, extra, seal), expected)
            for field, value in (("archive_sha256", "0" * 64), ("go_sha256", "0" * 64)):
                with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "astrolabe-dependency-archive"):
                    astrolabe.dependencies(selected, extra, {**seal, field: value})
            with self.assertRaisesRegex(v.Invalid, "astrolabe-dependency-archive"):
                astrolabe.dependencies(selected, extra + b"changed", seal)
            with self.assertRaisesRegex(v.Invalid, "astrolabe-dependency-members"):
                astrolabe.dependencies(selected, extra, {**seal, "files": {}})
            with self.assertRaisesRegex(v.Invalid, "astrolabe-defense-dependencies"):
                astrolabe.dependencies({**selected, "dependencies/go/strings/strings.go": b"changed"}, extra, seal)
            with self.assertRaisesRegex(v.Invalid, "astrolabe-defense-dependencies"):
                astrolabe.dependencies({k: d for k, d in selected.items() if k != "dependencies/go/strings/strings.go"}, extra, seal)
            with self.assertRaisesRegex(v.Invalid, "astrolabe-dependency-overlap"):
                astrolabe.dependencies({**selected, "dependencies/go/encoding/json/v2_stream.go": b"replacement"}, extra, seal)
            for values, reason in (
                (packages[:-1], "selection"),
                (packages + [packages[0]], "packages"),
                ([{**packages[0], "Error": {"Err": "failed"}}, *packages[1:]], "packages"),
                ([{**packages[0], "GoFiles": ["decode.go", "stream.go"]}, *packages[1:]], "selection"),
                ([{**packages[0], "GoFiles": ["v2_decode.go", "v2_stream.go", "decode.go"]}, *packages[1:]], "selection"),
            ):
                with self.subTest(reason=reason), self.assertRaisesRegex(v.Invalid, "astrolabe-dependency-" + reason):
                    astrolabe.dependencies(selection(values), extra, seal)
            altered = selection(packages)
            bad = {**record, "argv": ["go", "list", "-json", "encoding/json"]}
            bad["stdout"] = v.decode(altered[prefix + "record.json"])["stdout"]
            altered[prefix + "record.json"] = v.encode(bad)
            altered[prefix + "typed.process.json"] = v.encode({**child, "argv": bad["argv"]})
            with self.assertRaisesRegex(v.Invalid, "astrolabe-dependency-command"):
                astrolabe.dependencies(altered, extra, seal)

        # These synthetic Go files test selection and provenance, not the library claims themselves.
        names = [
            "crypto/internal/fips140/pbkdf2",
            "crypto/internal/fips140only",
            "crypto/pbkdf2",
            "errors",
            "mime",
            "net/url",
            "os",
            "strconv",
            "time",
            "internal/strconv",
            "crypto/internal/fips140hash",
            "crypto/sha256",
            "context",
            "crypto/internal/boring",
            "crypto/internal/fips140/sha256",
            "crypto/internal/fips140/hmac",
        ]
        packages = [{"ImportPath": name, "Standard": True, "Dir": "/src/" + name, "GoFiles": ["source.go"]} for name in names]
        contents = {name + "/source.go": name.encode() for name in names}
        extra, seal = archive({name: data for name, data in contents.items() if name.rsplit("/", 1)[0] in names[-7:]})
        seal.update({"go_sha256": astrolabe.GO, "application_commands_executed": 0})
        expected = {"dependencies/go/" + name: data for name, data in contents.items()}
        digest = v.digest(v.encode({name: v.digest(data) for name, data in sorted(expected.items())}))
        carrier = {key.replace("command/", "command/exports/", 1): value for key, value in files.items()}
        carrier.update({name: data for name, data in expected.items() if name.removeprefix("dependencies/go/").rsplit("/", 1)[0] in names[:-7]})
        record = v.decode(files["command/record.json"])
        record["argv"] = ["go", "list", "-deps", "-export", "-json", "-p=2", "./astrolabe", "./astrolabe/internal/web"]
        carrier["command/exports/typed.process.json"] = v.encode({**child, "argv": record["argv"]})

        def libraries(values: list[dict]) -> tuple[dict[str, bytes], dict]:
            """Reseal synthetic export streams so each hostile selection reaches the semantic check."""
            output = b"\n".join(v.encode(value) for value in values)
            receipt = {**record, "stdout": {"path": "stdout.log", "bytes": len(output), "sha256": v.digest(output)}}
            return {**carrier, "command/exports/stdout.log": output, "command/exports/record.json": v.encode(receipt)}, {
                **seal,
                "exports_sha256": v.digest(output),
            }

        selected, metadata = libraries(packages)
        with patch.object(astrolabe, "LIBRARY_ARCHIVE", v.digest(extra)), patch.object(astrolabe, "LIBRARIES", digest):
            self.assertEqual(astrolabe.libraries(selected, extra, metadata), expected)
            for field, value in (("archive_sha256", "0" * 64), ("go_sha256", "0" * 64), ("bytes", 0), ("trust", "ci"), ("application_commands_executed", 1)):
                with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "astrolabe-library-archive"):
                    astrolabe.libraries(selected, extra, {**metadata, field: value})
            with self.assertRaisesRegex(v.Invalid, "astrolabe-library-archive"):
                astrolabe.libraries(selected, extra + b"changed", metadata)
            for field, value, reason in (("files", {}, "members"), ("exports_sha256", "0" * 64, "exports")):
                with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "astrolabe-library-" + reason):
                    astrolabe.libraries(selected, extra, {**metadata, field: value})
            name = "dependencies/go/errors/source.go"
            for altered, reason in (
                ({**selected, name: b"changed"}, "source"),
                ({k: d for k, d in selected.items() if k != name}, "inventory"),
                ({**selected, "dependencies/go/context/source.go": b"overlap"}, "overlap"),
            ):
                with self.subTest(reason=reason), self.assertRaisesRegex(v.Invalid, "astrolabe-library-" + reason):
                    astrolabe.libraries(altered, extra, metadata)
            for values, reason in (
                (packages[:-1], "inventory"),
                (packages + [packages[0]], "packages"),
                ([{**packages[0], "DepsErrors": [{"Err": "failure"}]}, *packages[1:]], "packages"),
            ):
                altered, info = libraries(values)
                with self.subTest(reason=reason), self.assertRaisesRegex(v.Invalid, "astrolabe-library-" + reason):
                    astrolabe.libraries(altered, extra, info)
            for field, value in (
                ("Standard", False),
                ("Dir", "/foreign"),
                ("GoFiles", []),
                ("GoFiles", ["source.go", "source.go"]),
                ("GoFiles", ["../source.go"]),
                ("GoFiles", ["source.c"]),
            ):
                altered, info = libraries([{**packages[0], field: value}, *packages[1:]])
                with self.subTest(field=field, value=value), self.assertRaisesRegex(v.Invalid, "astrolabe-library-selection"):
                    astrolabe.libraries(altered, extra, info)
            changed = {**record, "argv": ["go", "list", "-json", "os"]}
            changed["stdout"] = v.decode(selected["command/exports/record.json"])["stdout"]
            altered = {
                **selected,
                "command/exports/record.json": v.encode(changed),
                "command/exports/typed.process.json": v.encode({**child, "argv": changed["argv"]}),
            }
            with self.assertRaisesRegex(v.Invalid, "astrolabe-library-command"):
                astrolabe.libraries(altered, extra, metadata)

    def test_processes(self) -> None:
        """Reject missing, duplicated, misowned or changed native exits; correctly reassemble split output."""
        encode = lambda rows: b"".join(json.dumps(row).encode() + b"\n" for row in rows)
        rows = children()
        receipts = astrolabe.processes(encode(rows), "boot")
        self.assertEqual(set(receipts), set(astrolabe.EXITS))
        position = next(i for i, row in enumerate(rows) if row.get("Test") == "TestProcess/usage" and row["Action"] == "output")
        original = rows[position]
        split = copy.deepcopy(rows)
        line = original["Output"]
        split[position : position + 1] = [{**original, "Output": part} for part in (line[:25], line[25:80], line[80:])]
        self.assertEqual(astrolabe.processes(encode(split), "boot"), receipts)
        for field, value in (
            ("pid", 0),
            ("pid", True),
            ("start_ticks", "0"),
            ("start_ticks", "012"),
            ("start_ticks", 12),
            ("start_ticks", "９"),
            ("start_ticks", "1" * 21),
            ("reaped", False),
            ("reaped", 1),
            ("boot_id", "different"),
            ("signal", 15),
            ("signal", False),
            ("exit_code", 0),
            ("calls", 1),
            ("case", "unknown"),
            ("case", "help"),
            ("case", []),
            ("extra", True),
        ):
            changed = copy.deepcopy(rows)
            receipt = {**receipts["usage"], field: value}
            changed[position]["Output"] = "ASTROLABE-PROCESS " + json.dumps(receipt) + "\n"
            with self.subTest(field=field, value=value), self.assertRaisesRegex(v.Invalid, "astrolabe-process-receipt"):
                astrolabe.processes(encode(changed), "boot")
        for replacement in ([], [original, original], [{**original, "Test": "TestProcess"}]):
            changed = copy.deepcopy(rows)
            changed[position : position + 1] = replacement
            with self.subTest(replacement=replacement), self.assertRaisesRegex(v.Invalid, "astrolabe-process-"):
                astrolabe.processes(encode(changed), "boot")
        changed = copy.deepcopy(rows)
        changed[position]["Output"] = "ASTROLABE-PROCESS " + json.dumps({**receipts["usage"], "pid": 100, "start_ticks": "10"}) + "\n"
        with self.assertRaisesRegex(v.Invalid, "astrolabe-process-inventory"):
            astrolabe.processes(encode(changed), "boot")
        with self.assertRaisesRegex(v.Invalid, "astrolabe-process-receipt"):
            astrolabe.processes(encode(rows), "another-boot")

    def test_exits(self) -> None:
        """Unique fatal branches can supplement decisions without fabricating compiler hits or MC/DC pairs."""
        trace = v.decode(v.read(Path(__file__).with_name("fixtures") / "astrolabe.json"))["traces"][0]
        receipts = astrolabe.processes(b"".join(json.dumps(row).encode() + b"\n" for row in children()), "boot")
        rows = {"astrolabe/main.go:8577": {("1", False): 3}, "astrolabe/main.go:8844": {("10", False): 3}}
        before = copy.deepcopy(rows)
        proofs = astrolabe.exits(trace, rows, receipts)
        self.assertEqual(rows, before)
        self.assertEqual([(p["values"], p["result"]) for p in proofs], [("2", True), ("21", True)])
        self.assertEqual(proofs[0]["independent"], [{"condition": 0, "false": "1", "true": "2", "fixed": "0"}])
        self.assertEqual(proofs[1]["independent"], [])
        self.assertEqual([r["case"] for r in proofs[1]["receipts"]], ["startup", "refusal"])
        library = {"synthetic-source": b"test-only nil-error semantics"}
        digest = v.digest(v.encode({name: v.digest(data) for name, data in library.items()}))
        with patch.object(astrolabe, "LIBRARIES", digest):
            derived = astrolabe.exits(trace, rows, receipts, library)[1]["independent"]
            self.assertEqual(len(derived), 1)
            self.assertEqual(derived[0]["condition"], 0)
            self.assertEqual(derived[0]["native_vectors"], [{"values": "10", "result": False}, {"values": "21", "result": True}])
            self.assertEqual(derived[0]["before"]["values"], [False, False])
            self.assertEqual(derived[0]["after"]["values"], [True, False])
            self.assertEqual(rows, before)
            for changed in ({}, {"synthetic-source": b"altered"}):
                with self.assertRaisesRegex(v.Invalid, "astrolabe-exit-libraries"):
                    astrolabe.exits(trace, rows, receipts, changed)
            with self.assertRaisesRegex(v.Invalid, "authority-pair-native-witness"):
                astrolabe.exits(trace, {**rows, "astrolabe/main.go:8844": {("22", False): 1}}, receipts, library)
        for identity in rows:
            with self.subTest(identity=identity), self.assertRaisesRegex(v.Invalid, "astrolabe-exit-witness"):
                astrolabe.exits(trace, {**rows, identity: {}}, receipts)
        trace["files"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(v.Invalid, "astrolabe-exit-source"):
            astrolabe.exits(trace, rows, receipts)

    def test_sources(self) -> None:
        """A new, removed or modified Go input invalidates reuse even when the commit is unchanged."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            names = ["astrolabe/main.go", *("internal/fixture/" + str(i) + ".go" for i in range(145))]
            files = {name: v.digest(name.encode()) for name in names}
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(name.encode())
            plan = {"files": files, "reused_go_inputs": files}
            self.assertEqual(astrolabe.sources(root, plan), files)
            added = root / "astrolabe/hidden.go"
            added.write_bytes(b"additional source")
            with self.assertRaisesRegex(v.Invalid, "astrolabe-source-inventory"):
                astrolabe.sources(root, plan)
            added.unlink()
            added = root / "internal/fixture/hidden.go"
            added.write_bytes(b"new dependency source")
            with self.assertRaisesRegex(v.Invalid, "astrolabe-source-inventory"):
                astrolabe.sources(root, plan)
            added.unlink()
            (root / names[-1]).write_bytes(b"same commit, changed dependency")
            with self.assertRaisesRegex(v.Invalid, "astrolabe-source-drift"):
                astrolabe.sources(root, plan)

        fixture = v.decode(v.read(Path(__file__).with_name("fixtures") / "astrolabe.json"))
        dependency = {"synthetic-source": b"not an application dependency"}
        digest = v.digest(v.encode({name: v.digest(data) for name, data in dependency.items()}))
        count = 0
        with patch.object(astrolabe, "DEPENDENCIES", digest), patch.object(astrolabe, "LIBRARIES", digest):
            for trace in fixture["traces"]:
                decisions, rows = logic.inventory(trace), {}
                for _, coordinates, _, _, _ in (*astrolabe.DEFENSES, *astrolabe.LIBRARY_DEFENSES):
                    for identity, target, impossible in coordinates:
                        if identity in decisions:
                            values = [False] * len(decisions[identity]["atoms"])
                            values[target] = not impossible
                            rows[identity] = {authority.project(decisions[identity], values): 1}
                proofs = astrolabe.defenses(trace, rows, dependency, dependency)
                count += len(proofs)
                for proof in proofs:
                    identity, target = proof["decision"], proof["condition"]
                    self.assertNotEqual(proof["impossible_outcome"], proof["observed_outcome"])
                    self.assertTrue(proof["anchors"] and proof["assumption"] and proof["invalidated_by"])
                    for replacement, reason in (
                        ({}, "unobserved"),
                        ({("0" * len(decisions[identity]["atoms"]), False): 1}, "unobserved"),
                        ({key: 0 for key in rows[identity]}, "hits"),
                    ):
                        with self.subTest(identity=identity, reason=reason), self.assertRaisesRegex(v.Invalid, "astrolabe-defense-" + reason):
                            astrolabe.defenses(trace, {**rows, identity: replacement}, dependency, dependency)
                    values = [False] * len(decisions[identity]["atoms"])
                    values[target] = proof["impossible_outcome"]
                    changed = {**rows[identity], authority.project(decisions[identity], values): 1}
                    with self.assertRaisesRegex(v.Invalid, "astrolabe-defense-contradicted"):
                        astrolabe.defenses(trace, {**rows, identity: changed}, dependency, dependency)
                for changed in ({}, {"synthetic-source": b"altered"}, {**dependency, "unexpected": b"extra"}):
                    with self.assertRaisesRegex(v.Invalid, "astrolabe-defense-dependencies"):
                        astrolabe.defenses(trace, rows, changed, dependency)
                    if any(identity in decisions for _, coordinates, *_ in astrolabe.LIBRARY_DEFENSES for identity, *_ in coordinates):
                        with self.assertRaisesRegex(v.Invalid, "astrolabe-defense-libraries"):
                            astrolabe.defenses(trace, rows, dependency, changed)
                changed = copy.deepcopy(trace)
                changed["files"][0]["sha256"] = "0" * 64
                with self.assertRaisesRegex(v.Invalid, "astrolabe-defense-forest"):
                    astrolabe.defenses(changed, rows, dependency, dependency)
        self.assertEqual(count, 13)
        trace = fixture["traces"][1]
        identity = "astrolabe/internal/bridge/metrics.go:10909"
        rows = {identity: {("10", True): 1, ("21", False): 1, ("22", True): 1}}
        tests = {"TestMetricDirectory", "TestMetricReplacement"}
        with patch.object(astrolabe, "MEMBERS", {name: v.digest(data) for name, data in dependency.items()}):
            proof = astrolabe.members(trace, rows, tests, dependency)
            self.assertEqual((proof["condition"], proof["total"], proof["allowed"]), (0, 4, 3))
            self.assertTrue(proof["anchors"] and proof["assumption"] and proof["invalidated_by"])
            for changed in ({}, {"synthetic-source": b"changed"}, {**dependency, "additional": b"unexpected"}):
                with self.assertRaisesRegex(v.Invalid, "astrolabe-member-source"):
                    astrolabe.members(trace, rows, tests, changed)
            for test in tests:
                with self.assertRaisesRegex(v.Invalid, "astrolabe-member-tests"):
                    astrolabe.members(trace, rows, tests - {test}, dependency)
            for changed, reason in (
                ({}, "observations"),
                ({("21", False): 1}, "observations"),
                ({("10", True): 0}, "hits"),
                ({**rows[identity], ("11", True): 1}, "contradiction"),
            ):
                with self.assertRaisesRegex(v.Invalid, "astrolabe-member-" + reason):
                    astrolabe.members(trace, {identity: changed}, tests, dependency)
            changed = copy.deepcopy(trace)
            changed["files"][0]["sha256"] = "0" * 64
            with self.assertRaisesRegex(v.Invalid, "astrolabe-member-source"):
                astrolabe.members(changed, rows, tests, dependency)

        trace = fixture["traces"][0]
        identity = "astrolabe/main.go:8844"
        rows = {identity: {("10", False): 3}}
        original = copy.deepcopy(rows)
        receipts = astrolabe.processes(b"".join(json.dumps(row).encode() + b"\n" for row in children()), "boot")
        with (
            patch.object(astrolabe, "STARTUP", {name: v.digest(data) for name, data in dependency.items()}),
            patch.object(astrolabe, "DEPENDENCIES", digest),
            patch.object(astrolabe, "LIBRARIES", digest),
        ):
            terminal = astrolabe.exits(trace, {**rows, "astrolabe/main.go:8577": {("1", False): 3}}, receipts, dependency)
            proof = astrolabe.cancellation(trace, rows, terminal, dependency, dependency, dependency)
            self.assertEqual((proof["condition"], proof["impossible_outcome"], proof["observed_outcome"]), (1, True, False))
            self.assertTrue(proof["anchors"] and proof["assumption"] and proof["invalidated_by"])
            self.assertEqual(rows, original)
            for changed in ({}, {"synthetic-source": b"changed"}, {**dependency, "additional": b"unexpected"}):
                with self.assertRaisesRegex(v.Invalid, "astrolabe-cancellation-source"):
                    astrolabe.cancellation(trace, rows, terminal, changed, dependency, dependency)
                for dependencies in ((changed, dependency), (dependency, changed)):
                    with self.assertRaisesRegex(v.Invalid, "astrolabe-cancellation-dependencies"):
                        astrolabe.cancellation(trace, rows, terminal, dependency, *dependencies)
            for changed, reason in (({}, "observations"), ({("10", False): 0}, "hits"), ({("22", False): 1}, "contradiction")):
                with self.assertRaisesRegex(v.Invalid, "astrolabe-cancellation-" + reason):
                    astrolabe.cancellation(trace, {identity: changed}, terminal, dependency, dependency, dependency)
            for changed in ([], terminal[:1], terminal + terminal[1:], [{**terminal[1], "values": "22"}], [{**terminal[1], "receipts": []}]):
                with self.assertRaisesRegex(v.Invalid, "astrolabe-cancellation-observations"):
                    astrolabe.cancellation(trace, rows, changed, dependency, dependency, dependency)
            changed = copy.deepcopy(trace)
            changed["files"][0]["sha256"] = "0" * 64
            with self.assertRaisesRegex(v.Invalid, "astrolabe-cancellation-source"):
                astrolabe.cancellation(changed, rows, terminal, dependency, dependency, dependency)

        # A report-shaped parser fixture checks the fixed denominator, not application truth.
        config = v.decode(v.read(Path(__file__).resolve().parents[1] / "development.json"))
        selected = next(check["native_tests"] for check in config["checks"] if check["id"] == "astrolabe-independence")
        report = {"scope": {}, "source_inputs": {str(i): "synthetic" for i in range(157)}, "application_commands_executed": 0}
        for package, (roots, atoms, supported, coupled, defended, controls) in astrolabe.GEOMETRY.items():
            report["scope"][package] = {
                "roots": roots,
                "atoms": atoms,
                "supported_conditions": supported,
                "proofs": {"source_coupling": [None] * coupled, "source_defenses": [None] * defended},
                "controls": {"required": controls, "observed": controls, "missing": []},
                "unresolved_conditions": [],
                "unobserved_edges": [],
                "native_tests": [name.split(":", 1)[1] for name in selected if name.split(":", 1)[0] == package],
            }
        original = copy.deepcopy(report)
        result = astrolabe.qualify(report)
        self.assertEqual(report, original)
        self.assertEqual(result["status"], "complete-under-assumptions")
        self.assertEqual(result["native_tests"], selected)
        self.assertEqual(
            result["independence"], {"roots": 184, "raw_conditions": 366, "supported_conditions": 334, "source_coupling": 18, "source_defenses": 14}
        )
        for name, value in (("scope", {}), ("source_inputs", {}), ("application_commands_executed", 1)):
            with self.subTest(scope=name), self.assertRaisesRegex(v.Invalid, "astrolabe-component-scope"):
                astrolabe.qualify({**report, name: value})
        for package in astrolabe.GEOMETRY:
            for name in ("roots", "atoms", "supported_conditions"):
                changed = copy.deepcopy(report)
                changed["scope"][package][name] -= 1
                with self.subTest(package=package, denominator=name), self.assertRaisesRegex(v.Invalid, "astrolabe-component-denominator"):
                    astrolabe.qualify(changed)
            for name in ("source_coupling", "source_defenses"):
                changed = copy.deepcopy(report)
                changed["scope"][package]["proofs"][name].append(None)
                with self.subTest(package=package, exclusions=name), self.assertRaisesRegex(v.Invalid, "astrolabe-component-denominator"):
                    astrolabe.qualify(changed)
            for name in ("unresolved_conditions", "unobserved_edges"):
                changed = copy.deepcopy(report)
                changed["scope"][package][name] = ["missing"]
                with self.subTest(package=package, missing=name), self.assertRaisesRegex(v.Invalid, "astrolabe-component-uncovered"):
                    astrolabe.qualify(changed)
            changed = copy.deepcopy(report)
            changed["scope"][package]["controls"]["observed"] -= 1
            with self.assertRaisesRegex(v.Invalid, "astrolabe-component-uncovered"):
                astrolabe.qualify(changed)
            changed = copy.deepcopy(report)
            changed["scope"][package]["native_tests"].pop()
            with self.assertRaisesRegex(v.Invalid, "astrolabe-native-inventory"):
                astrolabe.qualify(changed)

    def test_pairs(self) -> None:
        """Finite input pairs retain fixed nontarget predicates and require both native-shaped masks."""
        fixture = v.decode(v.read(Path(__file__).with_name("fixtures") / "astrolabe.json"))
        dependency = {"synthetic-source": b"test-only selected JSON implementation"}
        digest = v.digest(v.encode({name: v.digest(data) for name, data in dependency.items()}))
        self.enterContext(patch.object(astrolabe, "DEPENDENCIES", digest))
        self.enterContext(patch.object(astrolabe, "LIBRARIES", digest))
        count = guards = masks = coupled = 0
        for trace in fixture["traces"]:
            decisions = logic.inventory(trace)
            rows, executed = {}, set()
            package = trace["typing"]["package"].removeprefix(astrolabe.MODULE)
            for declaration in (*astrolabe.PAIRS, *astrolabe.MASKS, *(row[:5] for row in astrolabe.GUARDS)):
                suffix, target, before, after, names = declaration
                identity = package + "/" + suffix
                if identity not in decisions:
                    continue
                if declaration in astrolabe.PAIRS:
                    self.assertEqual([i for i, pair in enumerate(zip(before, after, strict=True)) if pair[0] != pair[1]], [target])
                values = rows.setdefault(identity, {})
                for side in (before, after):
                    values[authority.project(decisions[identity], list(side))] = 1
                executed.update(names)
            coupling = "astrolabe/internal/bridge/backend.go:3412"
            if coupling in decisions:
                rows[coupling] = {("11", False): 1, ("12", True): 1, ("20", True): 1}
                executed.add("TestSelection")
            boundaries = {
                "astrolabe/internal/web/almanac.go:10373": {("2111", False): 1, ("1000", True): 1, ("2200", True): 1},
                "astrolabe/internal/bridge/metrics.go:5285": {("1101", False): 1, ("2000", True): 1},
                "astrolabe/internal/web/almanac.go:4802": {("111", False): 1, ("200", True): 1},
                "astrolabe/internal/web/credentials.go:1872": {("111", False): 1, ("200", True): 1},
                "astrolabe/internal/web/server.go:2931": {("111", False): 1, ("200", True): 1},
                "astrolabe/internal/web/account.go:3594": {("122", False): 1, ("200", True): 1},
                "astrolabe/internal/bridge/metrics.go:1585": {("11", False): 1, ("12", True): 1, ("20", True): 1},
                "astrolabe/internal/bridge/metrics.go:1900": {("1211", False): 1, ("2000", True): 1},
                "astrolabe/internal/bridge/metrics.go:2776": {("11", False): 1, ("20", True): 1},
                "astrolabe/internal/web/account.go:1338": {("11", False): 1, ("12", True): 1, ("20", True): 1},
                "astrolabe/internal/web/account.go:1519": {("1211", False): 1, ("2000", True): 1},
                "astrolabe/internal/web/account.go:1648": {("111", False): 1, ("112", True): 1, ("200", True): 1},
                "astrolabe/internal/web/account.go:2199": {("11", False): 1, ("20", True): 1},
                "astrolabe/internal/bridge/backend.go:6309": {("112", False): 1, ("120", True): 1, ("200", True): 1},
                "astrolabe/internal/web/server.go:5359": {("10", False): 1, ("21", False): 1, ("22", True): 1},
                "astrolabe/internal/web/almanac.go:11485": {("110", True): 1, ("121", True): 1, ("122", False): 1, ("200", True): 1},
            }
            for identity, values in boundaries.items():
                if identity in decisions:
                    rows.setdefault(identity, {}).update(values)
            executed.update(
                test for identity, _, _, test, _ in (*astrolabe.RELATIONS, *astrolabe.COUPLINGS, *astrolabe.LIBRARY_COUPLINGS) if identity in decisions
            )
            report = astrolabe.conditions(trace, rows, executed, dependency, dependency)
            count += len(report["input_pairs"])
            guards += len(report["guarded_pairs"])
            masks += len(report["masked_pairs"])
            coupled += len(report["source_coupling"])
            for proof in report["input_pairs"]:
                self.assertEqual(proof["criterion"], "total-input-single-condition-v1")
                self.assertNotEqual(proof["before"]["result"], proof["after"]["result"])
                altered = copy.deepcopy(rows)
                del altered[proof["decision"]][authority.project(decisions[proof["decision"]], proof["after"]["values"])]
                with self.assertRaisesRegex(v.Invalid, "authority-pair-native-witness"):
                    astrolabe.conditions(trace, altered, executed, dependency, dependency)
            for proof in report["guarded_pairs"]:
                self.assertEqual(proof["criterion"], "defined-domain-short-circuit-v1")
                self.assertNotEqual(proof["before"]["result"], proof["after"]["result"])
                self.assertTrue(any(v is None for side in ("before", "after") for v in proof[side]["values"]))
                for side in ("before", "after"):
                    altered = copy.deepcopy(rows)
                    del altered[proof["decision"]][authority.project(decisions[proof["decision"]], proof[side]["values"])]
                    with self.assertRaisesRegex(v.Invalid, "astrolabe-guard-native-witness"):
                        astrolabe.partial(decisions, altered, executed, package)
                with self.assertRaisesRegex(v.Invalid, "astrolabe-guard-tests"):
                    astrolabe.partial(decisions, rows, executed - set(proof["tests"]), package)
            for proof in report["masked_pairs"]:
                self.assertEqual(proof["criterion"], "concrete-common-cube-v1")
                self.assertNotEqual(proof["before"]["result"], proof["after"]["result"])
            if coupling in decisions:
                proof = next(p for p in report["source_coupling"] if p["decision"] == coupling)
                self.assertEqual((proof["total"], proof["allowed"]), (4, 3))
                self.assertEqual(proof["relaxed_witness"], {"false": "11", "true": "21", "fixed": "01"})
                for replacement in ({}, {("11", False): 1}, {("12", True): 1, ("20", True): 1}):
                    with self.subTest(replacement=replacement), self.assertRaisesRegex(v.Invalid, "astrolabe-coupling-empty"):
                        astrolabe.conditions(trace, {**rows, coupling: replacement}, executed, dependency, dependency)
                # A changed jointly defined field is not a partial-domain independence proof.
                first = next(row for row in astrolabe.GUARDS if row[0] == "backend.go:3917" and row[1] == 0)
                with patch.object(astrolabe, "GUARDS", (first[:3] + ((False, False, None),) + first[4:],)):
                    with self.assertRaisesRegex(v.Invalid, "astrolabe-guard-domain"):
                        astrolabe.partial(decisions, rows, executed, package)
            for missing in (None, {}, {"synthetic-source": b"changed"}):
                if any(identity in decisions for identity, *_ in astrolabe.COUPLINGS):
                    with self.assertRaisesRegex(v.Invalid, "astrolabe-coupling-dependencies"):
                        astrolabe.conditions(trace, rows, executed, missing, dependency)
                if any(identity in decisions for identity, *_ in astrolabe.LIBRARY_COUPLINGS):
                    with self.assertRaisesRegex(v.Invalid, "astrolabe-coupling-libraries"):
                        astrolabe.conditions(trace, rows, executed, dependency, missing)
            impossible = {
                "astrolabe/internal/web/almanac.go:10373": ("1111", True),
                "astrolabe/internal/bridge/metrics.go:5285": ("2111", True),
                "astrolabe/internal/web/almanac.go:4802": ("211", True),
                "astrolabe/internal/web/credentials.go:1872": ("211", True),
                "astrolabe/internal/web/server.go:2931": ("211", True),
                "astrolabe/internal/web/account.go:3594": ("222", True),
                "astrolabe/internal/bridge/metrics.go:1585": ("21", True),
                "astrolabe/internal/bridge/metrics.go:1900": ("2211", True),
                "astrolabe/internal/bridge/metrics.go:2776": ("21", True),
                "astrolabe/internal/web/account.go:1338": ("21", True),
                "astrolabe/internal/web/account.go:1519": ("2211", True),
                "astrolabe/internal/web/account.go:1648": ("211", True),
                "astrolabe/internal/web/account.go:2199": ("21", True),
                coupling: ("21", True),
                "astrolabe/internal/bridge/backend.go:6309": ("212", True),
                "astrolabe/internal/web/server.go:5359": ("12", False),
                "astrolabe/internal/web/almanac.go:11485": ("112", True),
            }
            for proof in report["source_coupling"]:
                self.assertTrue(proof["relaxed_witness"])
                altered = copy.deepcopy(rows)
                altered[proof["decision"]][impossible[proof["decision"]]] = 1
                with self.assertRaisesRegex(v.Invalid, "astrolabe-coupling-contradicted"):
                    astrolabe.conditions(trace, altered, executed, dependency, dependency)
            changed = copy.deepcopy(trace)
            changed["files"][0]["sha256"] = "0" * 64
            with self.assertRaisesRegex(v.Invalid, "astrolabe-condition-forest"):
                astrolabe.conditions(changed, rows, executed, dependency, dependency)
        self.assertEqual((count, guards, masks, coupled), (134, 22, 9, 17))
        original = b"select { case <-parent.Done(): cancel(); case result = <-serving: close(done) }"
        changed = original.replace(b"case <-parent.Done():", b"case <-servingpoint(parent.Done(), server, serving):")
        self.assertIsNone(astrolabe.checkpoint(original, changed))
        for candidate in (original, changed.replace(b"cancel();", b""), changed.replace(b"result = <-serving", b"<-serving"), changed + b"\n"):
            with self.assertRaisesRegex(v.Invalid, "astrolabe-serving-checkpoint"):
                astrolabe.checkpoint(original, candidate)
        with self.assertRaisesRegex(v.Invalid, "astrolabe-serving-checkpoint"):
            astrolabe.checkpoint(original + original, changed + changed)

    def test_merge(self) -> None:
        """A native hit union preserves geometry and weights, with only the reviewed empty-arm shift permitted."""
        original = [
            {"file": "astrolabe/main.go", "span": [1, 1, 2, 1], "statements": 2, "count": 3},
            {"file": "astrolabe/main.go", "span": [153, 23, 153, 23], "statements": 0, "count": 0},
        ]
        addition = copy.deepcopy(original)
        addition[0]["count"] = 5
        frozen = copy.deepcopy(original)
        self.assertEqual(astrolabe.merge(original, addition)[0]["count"], 5)
        self.assertEqual(original, frozen)
        for candidate, reason in (
            (addition[:-1], "inventory"),
            (addition + addition[:1], "duplicates"),
            ([{**addition[0], "statements": 3}, addition[1]], "weights"),
            ([{**addition[0], "span": [1, 2, 2, 1]}, addition[1]], "inventory"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(v.Invalid, "astrolabe-statement-" + reason):
                astrolabe.merge(original, candidate)
        shifted = [addition[0], {**addition[1], "span": [153, 44, 153, 44]}]
        joined = astrolabe.merge(original, shifted, checkpoint=True)
        self.assertEqual(joined[1]["span"], original[1]["span"])
        self.assertEqual(joined[0]["count"], 5)
        with self.assertRaisesRegex(v.Invalid, "astrolabe-statement-checkpoint"):
            astrolabe.merge(original, addition, checkpoint=True)
        with self.assertRaisesRegex(v.Invalid, "astrolabe-statement-empty-weight"):
            astrolabe.merge(original, [shifted[0], {**shifted[1], "statements": 1}], checkpoint=True)
        source = b"select { case <-parent.Done(): cancel(); case result = <-refresh: close(done) }"
        changed = source.replace(b"case <-parent.Done():", b"case <-checkpoint(parent.Done(), refresh):")
        self.assertIsNone(astrolabe.checkpoint(source, changed, stopping=True))
        for candidate in (source, changed + b"\n", changed.replace(b"close(done)", b"")):
            with self.assertRaisesRegex(v.Invalid, "astrolabe-stop-checkpoint"):
                astrolabe.checkpoint(source, candidate, stopping=True)
        with self.assertRaisesRegex(v.Invalid, "astrolabe-serving-checkpoint"):
            astrolabe.checkpoint(source, changed)

    def test_outcomes(self) -> None:
        """Terminal inferences and impossible outcomes cannot be counted as compiler observations."""
        decisions = [
            {"id": "both", "outcomes": [False, True], "atoms": [{"index": 0, "outcomes": ["1", "2"]}]},
            {"id": "exit", "outcomes": [False], "atoms": [{"index": 0, "outcomes": ["1"]}]},
            {"id": "defense", "outcomes": [False], "atoms": [{"index": 0, "outcomes": ["1"]}]},
        ]
        scope = {
            "decisions": decisions,
            "terminal_decisions": [{"decision": "exit", "result": True, "values": "2"}],
            "proofs": {"source_defenses": [{"decision": "defense", "condition": 0, "impossible_outcome": True}]},
        }
        result = astrolabe.outcomes({"scope": {"synthetic": scope}})
        self.assertEqual([result[key] for key in ("raw_roots", "raw_atoms", "native_roots", "native_atoms")], [6, 6, 4, 4])
        self.assertEqual(result["inferred_roots"], [("exit", True)])
        self.assertEqual(result["inferred_atoms"], [("exit", 0, "2")])
        self.assertEqual(result["excluded_roots"], [("defense", True)])
        self.assertEqual(result["excluded_atoms"], [("defense", 0, "2")])
        for field in ("terminal_decisions", "proofs"):
            changed = copy.deepcopy(scope)
            changed[field] = [] if field == "terminal_decisions" else {"source_defenses": []}
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "astrolabe-structure-outcomes"):
                astrolabe.outcomes({"scope": {"synthetic": changed}})
        for edit, reason in (
            (lambda item: item["decisions"][0]["outcomes"].append(True), "root"),
            (lambda item: item["decisions"][0]["outcomes"].append("true"), "root"),
            (lambda item: item["decisions"][0]["atoms"][0]["outcomes"].append("0"), "atom"),
            (lambda item: item["decisions"][0]["atoms"][0].update(index=1), "atom"),
            (lambda item: item["terminal_decisions"].extend(item["terminal_decisions"]), "terminal"),
            (lambda item: item["terminal_decisions"][0].update(values="22"), "terminal"),
        ):
            changed = copy.deepcopy(scope)
            edit(changed)
            with self.subTest(reason=reason), self.assertRaisesRegex(v.Invalid, "astrolabe-structure-" + reason):
                astrolabe.outcomes({"scope": {"synthetic": changed}})

    def test_structure(self) -> None:
        """Qualification requires the complete fixed native denominator and keeps inference/exclusion accounting separate."""
        config = v.decode(v.read(Path(__file__).resolve().parents[1] / "development.json"))
        selected = next(check["native_tests"] for check in config["checks"] if check["id"] == "astrolabe-independence")
        report = {"scope": {}, "source_inputs": {str(i): "synthetic" for i in range(157)}, "application_commands_executed": 0}
        for package, (roots, atoms, supported, coupled, defended, controls) in astrolabe.GEOMETRY.items():
            report["scope"][package] = {
                "roots": roots,
                "atoms": atoms,
                "supported_conditions": supported,
                "proofs": {"source_coupling": [None] * coupled, "source_defenses": [None] * defended},
                "controls": {"required": controls, "observed": controls, "missing": []},
                "unresolved_conditions": [],
                "unobserved_edges": [],
                "native_tests": [name.split(":", 1)[1] for name in selected if name.split(":", 1)[0] == package],
            }
        report["statements"] = {"raw": 825, "native_observed": 818, "conditional_excluded": 7, "geometry_sha256": astrolabe.STATEMENTS}
        report["structural_outcomes"] = {
            "raw_roots": 368,
            "raw_atoms": 732,
            "native_roots": 361,
            "native_atoms": 715,
            **{key: [None] * size for key, size in (("inferred_roots", 2), ("inferred_atoms", 3), ("excluded_roots", 5), ("excluded_atoms", 14))},
        }
        original = copy.deepcopy(report)
        result = astrolabe.qualify(report, structural=True)
        self.assertEqual(result["qualification"], "local-component-structure")
        self.assertEqual(result["structure"]["native_observations"], 1967)
        self.assertEqual(result["structure"]["native_counts"], [818, 361, 715, 73])
        self.assertEqual(report, original)
        self.assertEqual(astrolabe.qualify(report)["qualification"], "local-component-mcdc")
        for field in ("raw", "native_observed", "conditional_excluded"):
            changed = copy.deepcopy(report)
            changed["statements"][field] += 1
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "astrolabe-structure-denominator"):
                astrolabe.qualify(changed, structural=True)
        for field in ("raw_roots", "raw_atoms", "native_roots", "native_atoms"):
            changed = copy.deepcopy(report)
            changed["structural_outcomes"][field] += 1
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "astrolabe-structure-denominator"):
                astrolabe.qualify(changed, structural=True)
        for field in ("inferred_roots", "inferred_atoms", "excluded_roots", "excluded_atoms"):
            changed = copy.deepcopy(report)
            changed["structural_outcomes"][field] = changed["structural_outcomes"][field][:-1]
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "astrolabe-structure-denominator"):
                astrolabe.qualify(changed, structural=True)
        self.assertEqual(len(astrolabe.artifacts()), 27)
        self.assertEqual(len(astrolabe.artifacts(structural=True)), 29)
        self.assertEqual(astrolabe.artifacts(structural=True)["material-2/evidence.tar.gz"], astrolabe.BASELINE)


if __name__ == "__main__":
    unittest.main()
