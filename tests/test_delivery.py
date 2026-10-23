"""Falsify candidate-tree and loader observations; synthetic files are reader controls, never distributed binaries."""

import copy
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import tarfile
import unittest
from unittest.mock import patch

from tools import delivery, entry, installation, shipping, verify as v


def elf() -> bytes:
    """Supply only a header-shaped negative-control fixture, without impersonating a runnable native application."""
    data = bytearray(64)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 2, 62, 1)
    struct.pack_into("<H", data, 52, 64)
    return bytes(data)


def loader() -> bytes:
    """Fix literal GNU tag observations independently of the production parser."""
    return b"""Dynamic section at offset 0xabc contains 4 entries:
 0x0000000000000001 (NEEDED) Shared library: [libstdc++.so.6]
 0x0000000000000001 (NEEDED) Shared library: [libgcc_s.so.1]
 0x000000000000001d (RUNPATH) Library runpath: [$ORIGIN/../lib]
 0x0000000000000000 (NULL) 0x0
"""


def fixture(root: Path) -> dict[str, str]:
    """Construct the fixed minimum tree; digests are input facts, not application execution evidence."""
    names = (
        {"bin/" + name for name in delivery.PROGRAMS}
        | {"lib/" + name for name in delivery.RUNTIMES}
        | {"include/comet/" + name + ".hpp" for name in delivery.HEADERS}
        | {"lib/cmake/Comet/" + name for name in delivery.EXPORTS}
        | {"lib/libcomet.a", "share/astra/LICENSE", "share/comet/LICENSE", "share/astra/licenses/gcc-runtime/COPYING.RUNTIME"}
    )
    files = {}
    for name in sorted(names):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(elf() if name.startswith("bin/") or name in {"lib/" + n for n in delivery.RUNTIMES} else b"fixture\n")
        path.chmod(0o755 if name.startswith("bin/") else 0o644)
        files[name] = v.file_digest(path)
    return files


def campaign_fixture() -> dict[str, bytes]:
    """Model a retired packaging failure for reader controls, without pretending that an application ran."""
    source, script = b"reader fixture", b"fixture runner"
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        member = tarfile.TarInfo("fixture.txt")
        member.size = len(source)
        archive.addfile(member, io.BytesIO(source))
    boot, invocation = "11111111-1111-1111-1111-111111111111", "a" * 32
    inputs = {"boot_id": boot, "run_sha256": v.digest(script), "source_archive_sha256": v.digest(stream.getvalue()), "files": {"fixture.txt": v.digest(source)}}
    identity = {"pid": 7, "parent": 1, "session": 7, "start_ticks": "13", "state": "R"}
    owner = {
        "boot_id": boot,
        "identity": identity,
        "inputs_sha256": v.digest(v.encode(inputs)),
        "script_sha256": v.digest(script),
        "cwd": "/owned/storage-delivery-current-4",
        "invocation_id": invocation,
        "argv": ["/owned/storage-delivery-current-4/run.py"],
    }
    terminal = {
        "errors": ["AssertionError: "],
        "interrupted": False,
        "remaining_owned": [],
        "protected_unchanged": True,
        "products_unchanged": False,
        "completed": [],
    }
    cleanup = {
        "boot_id": boot,
        "retired": [identity],
        "source_verified": 1,
        "original_exit_code": 2,
        "cache_inode": 713912,
        "unit": {"MainPID": "0", "ControlGroup": "", "InvocationID": "", "ExecMainStatus": "0"},
    }
    journal = [
        {"_BOOT_ID": boot.replace("-", ""), "INVOCATION_ID": invocation, "MESSAGE": message}
        for message in (
            "Started astra-storage-delivery-current-4.service - fixture",
            json.dumps(terminal),
            "Main process exited, code=exited, status=2/INVALIDARGUMENT",
        )
    ]
    return {
        "inputs.json": v.encode(inputs),
        "controller.json": v.encode(owner),
        "cleanup.native.json": v.encode(cleanup),
        "terminal.json": v.encode(terminal),
        "run.py": script,
        "source.tar.gz": stream.getvalue(),
        "journal.native.jsonl": b"\n".join(json.dumps(row).encode() for row in journal) + b"\n",
    }


def refresh_fixture(*, star: bool = False) -> dict[str, bytes]:
    """Model native refresh lifecycle facts for falsification, without claiming any product execution."""
    files = campaign_fixture()
    owner, terminal, cleanup = (v.decode(files[name]) for name in ("controller.json", "terminal.json", "cleanup.native.json"))
    version = 7 if star else 6
    owner["cwd"] = "/owned/storage-delivery-current-" + str(version)
    owner["argv"] = ["/usr/bin/python3", "-B", owner["cwd"] + "/run.py"]
    terminal.update(errors=[], products_unchanged=True)
    cleanup["original_exit_code"] = 0
    names = (
        [
            "install-prerequisite",
            "cpp-install",
            "loader-star",
            "resolved-star",
            "resolved-comet-mesh-probe",
            "resolved-comet-process-probe",
            "candidate-cluster",
        ]
        if star
        else [
            "go-build-polaris",
            "modules-polaris",
            "loader-polaris",
            "consumer-graph",
            "resolved-comet-mesh-probe",
            "resolved-comet-process-probe",
            "candidate-cluster",
        ]
    )
    if star:
        inputs = v.decode(files["inputs.json"])
        inputs.update(warm_files=inputs["files"], warm_root="/owned/warm")
        files["inputs.json"] = v.encode(inputs)
        owner["inputs_sha256"] = v.digest(files["inputs.json"])
        terminal["lock_released"] = True
    for index, name in enumerate(names):
        prefix = "source/build/commands/" + name + "/"
        record = {
            "id": name,
            "platform": "linux-amd64-cgo",
            "argv": ["fixture", name],
            "environment": {},
            "resolved_environment": {},
            "executable": "/fixture",
            "executable_sha256": "0" * 64,
            "toolchain": {"command": {"path": "/fixture", "sha256": "0" * 64}},
            "duration_ms": 1,
            "exit_code": 0,
            "termination": "exited",
            "complete": True,
            "cleanup": True,
            "started_at": "2026-10-09T00:00:00Z",
            "finished_at": "2026-10-09T00:00:01Z",
            "stdout": {"path": "stdout.log", "bytes": 0, "sha256": v.digest(b"")},
            "stderr": {"path": "stderr.log", "bytes": 0, "sha256": v.digest(b"")},
        }
        identity = {"pid": 20 + index, "parent": owner["identity"]["pid"], "session": 20 + index, "start_ticks": str(30 + index), "state": "R"}
        process = {"identity": identity, "boot_id": owner["boot_id"], "cwd": "/owned/warm" if star else owner["cwd"] + "/source", "argv": record["argv"]}
        files.update(
            {
                prefix + "record.json": v.encode(record),
                prefix + name + ".process.json": v.encode(process),
                prefix + "stdout.log": b"",
                prefix + "stderr.log": b"",
            }
        )
        cleanup["retired"].append(identity)
        terminal["completed"].append({"id": name, **{key: record[key] for key in ("exit_code", "duration_ms", "complete", "cleanup", "termination")}})
    for name, value in (("controller.json", owner), ("terminal.json", terminal), ("cleanup.native.json", cleanup)):
        files[name] = v.encode(value)
    rows = [
        {"_BOOT_ID": owner["boot_id"].replace("-", ""), "INVOCATION_ID": owner["invocation_id"], "MESSAGE": message}
        for message in (
            f"Started astra-storage-delivery-current-{version}.service - fixture",
            json.dumps(terminal),
            f"astra-storage-delivery-current-{version}.service: Deactivated successfully.",
        )
    ]
    files["journal.native.jsonl"] = b"\n".join(json.dumps(row).encode() for row in rows) + b"\n"
    files["cache-return.native.json"] = v.encode({"boot_id": owner["boot_id"], "owner": owner["identity"], "inode": 713912, "remaining_owned": []})
    return files


def installed_fixture() -> tuple[dict, dict]:
    """Provide literal donor/refresh relationships; header-shaped bytes are not installation evidence."""
    before = {"bin/polaris": b"old-polaris", **{"fixture/" + str(index): b"unchanged" for index in range(50)}}
    after = {**before, "bin/polaris": b"new-polaris"}
    old_candidate, new_candidate = ({name: v.digest(raw) for name, raw in tree.items()} for tree in (before, after))
    prior = {"files": {installation.PATH: installation.ORIGINAL}, "relevant": {installation.PATH: installation.ORIGINAL}, "cpp_production": {}}
    old = {
        "inputs.json": v.encode(prior),
        "candidate-manifest.json": v.encode(old_candidate),
        "cleanup.native.json": v.encode({"retired": ["fixture-owner"]}),
        "consumers.json": v.encode({name: {"sha256": v.digest(name.encode())} for name in ("comet_mesh_probe", "comet_process_probe")}),
        **{"fixture/bin/" + name: name.encode() for name in ("comet_mesh_probe", "comet_process_probe")},
    }
    plan = {
        "files": {installation.PATH: installation.SOURCE},
        "relevant": {installation.PATH: installation.SOURCE},
        "cpp_production": {},
        "donor": {
            "archive_sha256": delivery.CURRENT[5],
            "candidate": old_candidate,
            "source": prior["files"],
            "retirement": v.decode(old["cleanup.native.json"]),
        },
    }
    current = {
        **old,
        "inputs.json": v.encode(plan),
        "candidate-manifest.json": v.encode(new_candidate),
        "partial-candidate.native.json": v.encode(new_candidate),
        "reused-installed.native.json": v.encode(
            {
                "donor_archive_sha256": delivery.CURRENT[5],
                "unchanged_files": list(set(after) - {"bin/polaris"}),
                "unchanged_cpp_inputs": 0,
                "rebuilt": {"bin/polaris": new_candidate["bin/polaris"]},
            }
        ),
        **{"candidate/" + name: raw for name, raw in after.items()},
    }
    return current, old


def replacement_fixture() -> tuple[dict, dict]:
    """Keep fifty literal peer artifacts fixed while modeling one separately installed Star replacement."""
    previous, _ = installed_fixture()
    prior = v.decode(previous["inputs.json"])
    prior["cpp_production"] = {installation.STAR: installation.BEFORE}
    previous["inputs.json"] = v.encode(prior)
    before = v.decode(previous["candidate-manifest.json"])
    before["bin/star"] = before.pop("fixture/0")
    previous["candidate-manifest.json"] = v.encode(before)
    plan = {
        "donor_archive_sha256": installation.ARCHIVE,
        "build_archive_sha256": installation.BUILD,
        "donor_products": before,
        "relevant": prior["relevant"],
        "cpp_production": {installation.STAR: installation.AFTER},
        "source_delta": {installation.STAR: {"before": installation.BEFORE, "after": installation.AFTER}},
        "warm_files": {**prior["relevant"], installation.STAR: installation.AFTER},
        "warm_root": "/owned/warm",
    }
    after = {**before, "bin/star": v.digest(b"new-star")}
    scripts = {name: b"synthetic installation instructions" for name in ("cmake_install.cmake", "comet/cpp/cmake_install.cmake")}
    current = {
        "inputs.json": v.encode(plan),
        "controller.json": v.encode({"cwd": "/owned/storage-delivery-current-7"}),
        "candidate-manifest.json": v.encode(after),
        "candidate/bin/star": b"new-star",
        "installed.native.json": v.encode({"bin/star": after["bin/star"]}),
        "consumers.json": previous["consumers.json"],
        "install-scripts.native.json": v.encode({"/owned/warm/build/cmake/release/" + name: v.digest(raw) for name, raw in scripts.items()}),
        "install-manifest.native.txt": b"/owned/storage-delivery-current-7/stage/bin/star\n",
        **{"installer/" + name: raw for name, raw in scripts.items()},
    }
    return current, previous


class DeliveryTests(unittest.TestCase):
    """Reject replaced artifacts, incomplete inventories, private paths and nonportable native loader state."""

    def test_adapter(self) -> None:
        """A declaration or forged summary cannot replace independent native reconciliation."""
        config = v.decode(v.read(v.ROOT / "development.json"))
        check = next(c for c in config["checks"] if c["id"] == delivery.CHECK["id"])
        self.assertEqual(check, delivery.CHECK)
        self.assertIsNone(delivery.configuration(check))
        for key, value in (
            ("platforms", ["windows-amd64"]),
            ("expected_tests", ["polaris"]),
            ("native_tests", ["polaris"]),
            ("argv", ["python3", "-c", "pass"]),
        ):
            changed = copy.deepcopy(check)
            changed[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(v.Invalid, "delivery-configuration"):
                delivery.configuration(changed)
        report = {"fixture": "reader dispatch only"}
        with patch.object(delivery, "reconcile", return_value=report) as native:
            self.assertEqual(v.parse_observations(v.encode(report), check, v.ROOT), ({"ADMISSION-ASSURANCE": 2}, []))
            native.assert_called_once_with(v.ROOT)
            with self.assertRaisesRegex(v.Invalid, "delivery-observation-mismatch"):
                v.parse_observations(v.encode({"passed": True}), check, v.ROOT)
        for error in (FileNotFoundError("fixture"), KeyError("missing"), TypeError("shape"), v.Invalid("delivery-source-drift")):
            with patch.object(delivery, "reconcile", side_effect=error), self.assertRaises(v.Invalid):
                v.parse_observations(v.encode(report), check, v.ROOT)
        with self.assertRaisesRegex(v.Invalid, "delivery-execution-platform"):
            v.execute(check, v.ROOT, v.ROOT / "build/unused-control", "windows-amd64")

    def test_storage(self) -> None:
        """Storage requires its actual sole consumer and Linux/CGO boundary, with independently recomputed facts."""
        check = copy.deepcopy(delivery.STORAGE)
        self.assertIsNone(delivery.configuration(check))
        report = {"fixture": "parser dispatch only"}
        with patch.object(delivery, "reconcile", return_value=report) as reader:
            self.assertEqual(v.parse_observations(v.encode(report), check, v.ROOT), ({"STORAGE-ASSURANCE": 1}, []))
            reader.assert_called_once_with(v.ROOT, component="polaris-storage")
            with self.assertRaisesRegex(v.Invalid, "delivery-observation-mismatch"):
                v.parse_observations(v.encode({"passed": True}), check, v.ROOT)
        for key, value in (
            ("platforms", ["windows-amd64"]),
            ("native_tests", []),
            ("native_tests", ["astrolabe"]),
            ("component", "admission"),
            ("argv", check["argv"][:-2]),
        ):
            changed = {**check, key: value}
            with self.subTest(key=key, value=value), self.assertRaisesRegex(v.Invalid, "delivery-configuration"):
                delivery.configuration(changed)
        with self.assertRaisesRegex(v.Invalid, "delivery-execution-platform"):
            v.execute(check, v.ROOT, v.ROOT / "build/unused-storage", "windows-amd64")

    def test_campaign(self) -> None:
        """The original failure, source snapshot and retired owner cannot be rewritten into successful evidence."""
        files = campaign_fixture()
        self.assertEqual(delivery.campaign(files, 4), {})
        controls = [
            ("inputs.json", "boot_id", "different-boot"),
            ("inputs.json", "run_sha256", "0" * 64),
            ("inputs.json", "source_archive_sha256", "0" * 64),
            ("inputs.json", "files", {}),
            ("controller.json", "inputs_sha256", "0" * 64),
            ("controller.json", "script_sha256", "0" * 64),
            ("controller.json", "argv", ["wrong-runner"]),
            ("controller.json", "cwd", "/owned/storage-delivery-current-3"),
            ("cleanup.native.json", "boot_id", "different-boot"),
            ("cleanup.native.json", "retired", []),
            ("cleanup.native.json", "source_verified", 0),
            ("cleanup.native.json", "original_exit_code", 0),
            ("cleanup.native.json", "cache_inode", 1),
            ("terminal.json", "errors", []),
            ("terminal.json", "interrupted", True),
            ("terminal.json", "remaining_owned", [7]),
            ("terminal.json", "protected_unchanged", False),
            ("terminal.json", "products_unchanged", True),
            ("terminal.json", "completed", [{"id": "unobserved"}]),
        ]
        for name, key, value in controls:
            changed = {**files, name: v.encode({**v.decode(files[name]), key: value})}
            with self.subTest(name=name, key=key), self.assertRaises(v.Invalid):
                delivery.campaign(changed, 4)
        for key, value in (("MainPID", "7"), ("ControlGroup", "/active"), ("InvocationID", "wrong")):
            cleanup = v.decode(files["cleanup.native.json"])
            cleanup["unit"][key] = value
            with self.subTest(key=key), self.assertRaises(v.Invalid):
                delivery.campaign({**files, "cleanup.native.json": v.encode(cleanup)}, 4)
        extra = {**files, "source/build/commands/control-plane-delivery/forged/record.json": b"{}"}
        with self.assertRaisesRegex(v.Invalid, "delivery-current-commands"):
            delivery.campaign(extra, 4)
        refreshed = refresh_fixture()
        self.assertEqual(set(delivery.campaign(refreshed, 6)), set(delivery.COMMANDS[6]))
        for suffix, key, value in (("record.json", "complete", False), ("record.json", "exit_code", 1), ("candidate-cluster.process.json", "boot_id", "wrong")):
            name = "source/build/commands/candidate-cluster/" + suffix
            changed = {**refreshed, name: v.encode({**v.decode(refreshed[name]), key: value})}
            with self.subTest(suffix=suffix, key=key), self.assertRaises(v.Invalid):
                delivery.campaign(changed, 6)
        name = "source/build/commands/candidate-cluster/candidate-cluster.process.json"
        process = v.decode(refreshed[name])
        for key, value in (("parent", 99), ("start_ticks", "999")):
            changed = {**process, "identity": {**process["identity"], key: value}}
            with self.subTest(identity=key), self.assertRaisesRegex(v.Invalid, "delivery-current-owner"):
                delivery.campaign({**refreshed, name: v.encode(changed)}, 6)
        with self.assertRaisesRegex(v.Invalid, "delivery-native-stream"):
            delivery.campaign({**refreshed, "source/build/commands/candidate-cluster/stdout.log": b"replaced"}, 6)
        installed = refresh_fixture(star=True)
        self.assertEqual(set(delivery.campaign(installed, 7)), set(delivery.COMMANDS[7]))
        for key, value in (("lock_released", False), ("protected_unchanged", False), ("products_unchanged", False)):
            changed = {**v.decode(installed["terminal.json"]), key: value}
            with self.subTest(star_terminal=key), self.assertRaisesRegex(v.Invalid, "delivery-current-lifecycle"):
                delivery.campaign({**installed, "terminal.json": v.encode(changed)}, 7)
        path = "source/build/commands/cpp-install/cpp-install.process.json"
        changed = {**v.decode(installed[path]), "cwd": "/wrong/warm"}
        with self.assertRaisesRegex(v.Invalid, "delivery-current-owner"):
            delivery.campaign({**installed, path: v.encode(changed)}, 7)
        with self.assertRaisesRegex(v.Invalid, "entry-archive-invalid"):
            delivery.campaign({**installed, "source.tar.gz": campaign_fixture()["source.tar.gz"].replace(b"\x1f", b"\x00", 1)}, 7)

    def test_journal(self) -> None:
        """Neither a collected unit nor a consistent summary can replace the original boot/invocation-bound outcome."""
        files = campaign_fixture()
        rows = [v.decode(row) for row in files["journal.native.jsonl"].splitlines()]
        controls = [[], rows[1:], rows[:-1], [rows[0], rows[-1]]]
        for key in ("_BOOT_ID", "INVOCATION_ID", "MESSAGE"):
            changed = copy.deepcopy(rows)
            changed[0][key] = "wrong"
            controls.append(changed)
        for index, changed in enumerate(controls):
            raw = b"\n".join(json.dumps(row).encode() for row in changed)
            with self.subTest(control=index), self.assertRaises(v.Invalid):
                delivery.campaign({**files, "journal.native.jsonl": raw}, 4)

    def test_selection(self) -> None:
        """Current storage never falls back to stale delivery; archive replacement and unknown components fail closed."""
        with patch.object(v, "read", return_value=b"replaced archive"), self.assertRaisesRegex(v.Invalid, "delivery-current-archive"):
            delivery.compose(v.ROOT)
        with patch.object(v, "read", return_value=b"replaced archive"), self.assertRaisesRegex(v.Invalid, "installation-refresh-archive"):
            installation.refresh(v.ROOT, {}, {})
        current, previous = replacement_fixture()
        self.assertEqual(installation.replacement(current, previous), v.decode(current["inputs.json"]))
        for key, value in (
            ("donor_archive_sha256", "0" * 64),
            ("build_archive_sha256", "0" * 64),
            ("cpp_production", {}),
            ("source_delta", {}),
            ("warm_files", {}),
        ):
            plan = {**v.decode(current["inputs.json"]), key: value}
            with self.subTest(replacement_source=key), self.assertRaisesRegex(v.Invalid, "installation-refresh-source"):
                installation.replacement({**current, "inputs.json": v.encode(plan)}, previous)
        for key, value in (("candidate/bin/star", b"other"), ("installed.native.json", b"{}"), ("consumers.json", b"{}")):
            with self.subTest(replacement_product=key), self.assertRaisesRegex(v.Invalid, "installation-refresh-products"):
                installation.replacement({**current, key: value}, previous)
        manifest = v.decode(current["candidate-manifest.json"])
        for change in (lambda data: data.pop("bin/polaris"), lambda data: data.update({"bin/polaris": "0" * 64})):
            altered = dict(manifest)
            change(altered)
            with self.assertRaisesRegex(v.Invalid, "installation-refresh-products"):
                installation.replacement({**current, "candidate-manifest.json": v.encode(altered)}, previous)
        for key, value in (
            ("installer/cmake_install.cmake", b"changed"),
            ("install-manifest.native.txt", b"/other/star\n"),
            ("install-scripts.native.json", b"{}"),
        ):
            with self.subTest(installer=key), self.assertRaisesRegex(v.Invalid, "installation-refresh-installer"):
                installation.replacement({**current, key: value}, previous)
        with (
            patch.object(shipping, "current", return_value=False),
            patch.object(v, "file_digest", return_value=delivery.CURRENT_SOURCE),
            patch.object(delivery, "compose", side_effect=v.Invalid("selected-current")) as reader,
        ):
            for component in ("admission", "polaris-storage"):
                with self.assertRaisesRegex(v.Invalid, "selected-current"):
                    delivery.reconcile(v.ROOT, component=component)
            self.assertEqual(reader.call_count, 2)
        with (
            patch.object(shipping, "current", return_value=False),
            patch.object(v, "file_digest", return_value="0" * 64),
            patch.object(delivery, "collection") as old,
        ):
            with self.assertRaisesRegex(v.Invalid, "delivery-storage-source"):
                delivery.reconcile(v.ROOT, component="polaris-storage")
            old.assert_not_called()
        with self.assertRaisesRegex(v.Invalid, "delivery-component"):
            delivery.reconcile(v.ROOT, component="unregistered")
        with patch.object(v, "read", return_value=b"replaced refresh"), self.assertRaisesRegex(v.Invalid, "installation-archive"):
            installation.load(v.ROOT)
        with patch.object(v, "file_digest", return_value="0" * 64), self.assertRaisesRegex(v.Invalid, "installation-source"):
            installation.reconcile(v.ROOT, {}, {}, b"", {})
        merged = installation.merge(
            {"command/candidate-cluster/logs/old-sequence.log": b"old", "command/go-build/record.json": b"original build", "original/old-stream": b"retain"},
            {"source/build/commands/candidate-cluster/logs/new-sequence.log": b"new"},
        )
        self.assertNotIn("command/candidate-cluster/logs/old-sequence.log", merged)
        self.assertEqual(merged["command/candidate-cluster/logs/new-sequence.log"], b"new")
        self.assertEqual(merged["command/go-build/record.json"], b"original build")
        self.assertEqual(merged["original/old-stream"], b"retain")
        current, previous = installed_fixture()
        self.assertEqual(installation.handoff(current, previous), v.decode(current["inputs.json"]))
        for field, key, value in (
            ("donor", "archive_sha256", "0" * 64),
            ("donor", "retirement", {}),
            ("donor", "source", {}),
            ("donor", "candidate", {}),
            ("relevant", installation.PATH, "0" * 64),
            ("cpp_production", "extra.cpp", "0" * 64),
            ("files", installation.PATH, "0" * 64),
        ):
            plan = v.decode(current["inputs.json"])
            plan[field][key] = value
            with self.subTest(field=field, key=key), self.assertRaisesRegex(v.Invalid, "installation-handoff"):
                installation.handoff({**current, "inputs.json": v.encode(plan)}, previous)
        for name, raw in (("candidate/bin/polaris", b"substitution"), ("candidate/extra", b"unexpected product"), ("partial-candidate.native.json", b"{}")):
            with self.subTest(product=name), self.assertRaisesRegex(v.Invalid, "installation-products"):
                installation.handoff({**current, name: raw}, previous)
        for key, value in (("unchanged_files", []), ("rebuilt", {}), ("unchanged_cpp_inputs", 1)):
            reused = {**v.decode(current["reused-installed.native.json"]), key: value}
            with self.subTest(reuse=key), self.assertRaisesRegex(v.Invalid, "installation-reuse"):
                installation.handoff({**current, "reused-installed.native.json": v.encode(reused)}, previous)
        with self.assertRaisesRegex(v.Invalid, "installation-probe-identity"):
            installation.handoff({**current, "fixture/bin/comet_mesh_probe": b"changed fixture"}, previous)
        refreshed = refresh_fixture()
        refreshed["manifest.json"] = v.encode(
            {"trust": "local", "files": {name: {"bytes": len(raw), "sha256": v.digest(raw)} for name, raw in refreshed.items()}}
        )
        original_unpack = entry.unpack
        original_read = v.read
        with (
            patch.object(v, "read", side_effect=lambda path, *args: b"reader fixture" if Path(path).name == "evidence.tar.gz" else original_read(path, *args)),
            patch.object(installation, "ARCHIVE", v.digest(b"reader fixture")),
            patch("tools.entry.unpack", side_effect=lambda data: refreshed if data == b"reader fixture" else original_unpack(data)),
        ):
            self.assertEqual(installation.load(v.ROOT), refreshed)
            for key, value in (("boot_id", "wrong"), ("owner", {}), ("inode", 1), ("remaining_owned", [7])):
                changed = {**v.decode(refreshed["cache-return.native.json"]), key: value}
                mutated = {**refreshed, "cache-return.native.json": v.encode(changed)}
                mutated["manifest.json"] = v.encode(
                    {
                        "trust": "local",
                        "files": {name: {"bytes": len(raw), "sha256": v.digest(raw)} for name, raw in mutated.items() if name != "manifest.json"},
                    }
                )
                with (
                    self.subTest(cache=key),
                    patch("tools.entry.unpack", side_effect=lambda data: mutated if data == b"reader fixture" else original_unpack(data)),
                    self.assertRaisesRegex(v.Invalid, "installation-cache"),
                ):
                    installation.load(v.ROOT)
            with patch("tools.entry.unpack", return_value={**refreshed, "run.py": b"changed"}), self.assertRaisesRegex(v.Invalid, "installation-integrity"):
                installation.load(v.ROOT)
            bad = {**refreshed, "manifest.json": v.encode({"trust": "local", "files": {}})}
            with patch("tools.entry.unpack", return_value=bad), self.assertRaisesRegex(v.Invalid, "installation-members"):
                installation.load(v.ROOT)

    def test_receipt(self) -> None:
        """Synthetic native-shaped records expose incomplete execution and independent stream replacement."""
        raw = b"fixture output\n"
        item = {"path": "stdout.log", "bytes": len(raw), "sha256": v.digest(raw)}
        record = {
            "id": "fixture",
            "platform": "linux-amd64-cgo",
            "argv": ["fixture"],
            "environment": {},
            "resolved_environment": {},
            "executable": "/fixture",
            "executable_sha256": "0" * 64,
            "toolchain": {"command": {"path": "/fixture", "sha256": "0" * 64}},
            "duration_ms": 1,
            "exit_code": 0,
            "termination": "exited",
            "complete": True,
            "cleanup": True,
            "started_at": "2026-10-09T00:00:00Z",
            "finished_at": "2026-10-09T00:00:01Z",
            "stdout": item,
            "stderr": {"path": "stderr.log", "bytes": 0, "sha256": v.digest(b"")},
        }
        files = {"command/record.json": v.encode(record), "command/stdout.log": raw, "command/stderr.log": b""}
        self.assertEqual(delivery.receipt(files, "command/"), (record, raw))
        for key, value in (
            ("platform", "windows-amd64"),
            ("complete", False),
            ("cleanup", False),
            ("exit_code", 1),
            ("termination", "timeout"),
            ("finished_at", "2026-10-08T00:00:00Z"),
        ):
            changed = {**record, key: value}
            with self.subTest(key=key), self.assertRaisesRegex(v.Invalid, "delivery-native-incomplete"):
                delivery.receipt({**files, "command/record.json": v.encode(changed)}, "command/")
        for name in ("stdout", "stderr"):
            with self.subTest(channel=name), self.assertRaisesRegex(v.Invalid, "delivery-native-stream"):
                delivery.receipt({**files, "command/" + name + ".log": b"replaced"}, "command/")

    def test_collection(self) -> None:
        """A current combined collection must retain source, tool, command and retired-owner bindings."""
        pin = "a" * 64
        source = b"synthetic source archive"
        plan = {
            "files": {"fixture.go": "b" * 64},
            "prior_archive_sha256": delivery.ARCHIVES["evidence.tar.gz"],
            "source_archive_sha256": v.digest(source),
        }
        records = {
            "consumer-graph": {
                "argv": ["go", "list", "-json", "./..."],
                "resolved_environment": {"GOFLAGS": "-mod=readonly"},
                "executable": "/go",
                "executable_sha256": pin,
            },
            "go-build": {"argv": ["go", "build"], "executable_sha256": pin},
        }
        facts = {
            "inputs.json": v.encode(plan),
            "preflight.json": v.encode({"pins": {"/go": pin}}),
            "cleanup.native.json": v.encode({"boot_id": "boot", "retired": ["graph-owner", "build-owner"]}),
            "source.tar.gz": source,
        }
        for name, identity in (("consumer-graph", "graph-owner"), ("go-build", "build-owner")):
            facts[f"command/{name}/{name}.process.json"] = v.encode({"identity": identity, "boot_id": "boot", "argv": records[name]["argv"]})

        def receipt(data: dict[str, bytes], prefix: str) -> tuple[dict, bytes]:
            """Isolate collection binding from separately tested native-record and archive parsers."""
            self.assertEqual(data, facts)
            return records[prefix.split("/")[1]], b"synthetic package stream"

        with (
            patch("tools.admission.matches", return_value=True),
            patch.object(delivery, "retained", side_effect=lambda data, digest: facts if digest == delivery.MATERIAL else self.fail("wrong archive")),
            patch.object(delivery, "receipt", side_effect=receipt),
            patch.object(v, "read", return_value=b"synthetic archive boundary"),
        ):
            result = delivery.collection(Path("fixture"))
            self.assertEqual(
                result,
                (facts, {"source": plan["files"], "go_sha256": pin}, b"synthetic package stream", {"material-delivery/evidence.tar.gz": delivery.MATERIAL}),
            )
            original = copy.deepcopy(facts)
            for name, updates in (
                ("inputs.json", {"prior_archive_sha256": "0" * 64}),
                ("inputs.json", {"source_archive_sha256": "0" * 64}),
                ("preflight.json", {"pins": {"/go": "0" * 64}}),
            ):
                facts[name] = v.encode({**v.decode(original[name]), **updates})
                with self.subTest(name=name, updates=updates), self.assertRaisesRegex(v.Invalid, "delivery-inventory-binding"):
                    delivery.collection(Path("fixture"))
                facts[name] = original[name]
            facts["source.tar.gz"] = source + b"changed"
            with self.assertRaisesRegex(v.Invalid, "delivery-inventory-binding"):
                delivery.collection(Path("fixture"))
            facts["source.tar.gz"] = source
            for key, value in (("boot_id", "other"), ("identity", "other"), ("argv", ["other"])):
                name = "command/consumer-graph/consumer-graph.process.json"
                facts[name] = v.encode({**v.decode(original[name]), key: value})
                with self.subTest(key=key), self.assertRaisesRegex(v.Invalid, "delivery-native-owner"):
                    delivery.collection(Path("fixture"))
                facts[name] = original[name]
            for name, key, value in (
                ("consumer-graph", "argv", ["go", "list", "./astrolabe"]),
                ("consumer-graph", "resolved_environment", {"GOFLAGS": ""}),
                ("consumer-graph", "executable_sha256", "0" * 64),
                ("go-build", "executable_sha256", "0" * 64),
            ):
                previous = records[name][key]
                records[name][key] = value
                # Match the synthetic child argv so the command-domain refusal is independently reached.
                owner = f"command/{name}/{name}.process.json"
                facts[owner] = v.encode({**v.decode(original[owner]), "argv": records[name]["argv"]})
                with self.subTest(name=name, key=key), self.assertRaisesRegex(v.Invalid, "delivery-inventory-binding"):
                    delivery.collection(Path("fixture"))
                records[name][key] = previous
                facts[owner] = original[owner]

    def test_retirement(self) -> None:
        """Archive integrity precedes parsing; success requires the exact retired controller and empty group."""
        raw = b"synthetic archive boundary"
        owner = {"invocation_id": "invocation", "boot_id": "boot", "identity": ["fixture", "identity"]}
        state = {"InvocationID": "invocation", "MainPID": "0", "SubState": "exited", "ExecMainStatus": "0", "ControlGroup": ""}
        cleanup = {"service": state, "boot_id": "boot", "retired": [owner["identity"]]}
        files = {"controller.json": v.encode(owner), "cleanup.native.json": v.encode(cleanup)}
        with patch("tools.entry.unpack", return_value=files) as unpack:
            with self.assertRaisesRegex(v.Invalid, "delivery-archive-integrity"):
                delivery.retained(raw, "0" * 64)
            unpack.assert_not_called()
            self.assertEqual(delivery.retained(raw, v.digest(raw)), files)
            for key, value in (("InvocationID", "other"), ("MainPID", "1"), ("SubState", "running"), ("ExecMainStatus", "1"), ("ControlGroup", "/live")):
                changed = {**cleanup, "service": {**state, key: value}}
                unpack.return_value = {**files, "cleanup.native.json": v.encode(changed)}
                with self.subTest(key=key), self.assertRaisesRegex(v.Invalid, "delivery-native-retirement"):
                    delivery.retained(raw, v.digest(raw))
            for change in ({"boot_id": "new-boot"}, {"retired": []}):
                unpack.return_value = {**files, "cleanup.native.json": v.encode({**cleanup, **change})}
                with self.subTest(change=change), self.assertRaisesRegex(v.Invalid, "delivery-native-retirement"):
                    delivery.retained(raw, v.digest(raw))

    def test_consumers(self) -> None:
        """Transitive consumers cannot hide behind an adapter, test edge or a disconnected package."""
        module = "github.com/eosforge/astra/"
        rows = [
            {"ImportPath": module + "internal/admission", "Name": "admission", "Imports": ["context"]},
            {"ImportPath": module + "bridge", "Name": "bridge", "Imports": [module + "internal/admission"]},
            {"ImportPath": module + "polaris", "Name": "main", "Imports": [module + "internal/admission"]},
            {"ImportPath": module + "astrolabe", "Name": "main", "Imports": [module + "bridge"]},
            {"ImportPath": module + "unrelated", "Name": "main", "TestImports": [module + "internal/admission"]},
        ]

        def read(values: list[dict]) -> dict:
            """Encode a literal synthetic module graph, never a native application receipt."""
            return delivery.consumers(b"\n".join(v.encode(row) for row in values), "internal/admission", ("polaris", "astrolabe"))

        expected = {"polaris": ["internal/admission", "polaris"], "astrolabe": ["astrolabe", "bridge", "internal/admission"]}
        result = read(rows)
        self.assertEqual(result["consumers"], expected)
        self.assertEqual(result["packages"], 5)
        self.assertEqual(read(list(reversed(rows))), result)
        for index in range(4):
            changed = copy.deepcopy(rows)
            changed.pop(index)
            with self.subTest(missing=index), self.assertRaises(v.Invalid):
                read(changed)
        changed = copy.deepcopy(rows)
        changed[3]["Imports"] = []
        with self.assertRaisesRegex(v.Invalid, "delivery-consumer-matrix"):
            read(changed)
        changed = copy.deepcopy(rows)
        changed[-1]["Imports"] = [module + "bridge"]
        with self.assertRaisesRegex(v.Invalid, "delivery-consumer-matrix"):
            read(changed)
        changed = copy.deepcopy(rows)
        changed[0]["Imports"] = [module + "bridge"]
        with self.assertRaisesRegex(v.Invalid, "delivery-consumer-cycle"):
            read(changed)
        changed = copy.deepcopy(rows)
        changed += [{"ImportPath": module + "cycle", "Name": "cycle", "Imports": [module + "cycle"]}]
        with self.assertRaisesRegex(v.Invalid, "delivery-consumer-cycle"):
            read(changed)

    def test_consumer_rejections(self) -> None:
        """Reject malformed policy, duplicate/foreign packages, test variants and incomplete native streams."""
        module = "github.com/eosforge/astra/"
        rows = [
            {"ImportPath": module + "internal/admission", "Name": "admission"},
            {"ImportPath": module + "polaris", "Name": "main", "Imports": [module + "internal/admission"]},
        ]
        raw = b"\n".join(v.encode(row) for row in rows)
        for package, expected in (
            ("../admission", ("polaris",)),
            ("internal/admission", ()),
            ("internal/admission", ("polaris", "polaris")),
            ("internal/admission", ("../polaris",)),
        ):
            with self.subTest(package=package, expected=expected), self.assertRaises(v.Invalid):
                delivery.consumers(raw, package, expected)
        for change in (
            {"ImportPath": "other.example/foreign"},
            {"ImportPath": module + "../foreign"},
            {"Name": ""},
            {"Name": None},
            {"Error": {"Err": "broken"}},
            {"DepsErrors": ["broken"]},
            {"Incomplete": True},
            {"ForTest": module + "polaris"},
            {"Imports": "context"},
            {"Imports": [None]},
            {"Imports": ["context", "context"]},
        ):
            changed = copy.deepcopy(rows)
            changed[0].update(change)
            with self.subTest(change=change), self.assertRaises(v.Invalid):
                delivery.consumers(b"\n".join(v.encode(row) for row in changed), "internal/admission", ("polaris",))
        for data in (b"", b"{}", raw[:-2], raw + v.encode(rows[0]), b'{"ImportPath":"a","ImportPath":"b"}'):
            with self.subTest(data=data[:48]), self.assertRaises(v.Invalid):
                delivery.consumers(data, "internal/admission", ("polaris",))

    def test_header(self) -> None:
        """Platform, class, endian, type, version and header length all have independently failing controls."""
        self.assertIsNone(delivery.header(elf()))
        for offset, value in ((0, 0), (4, 1), (5, 2), (6, 0), (16, 1), (18, 183), (20, 0), (52, 63)):
            data = bytearray(elf())
            data[offset] = value
            with self.subTest(offset=offset), self.assertRaises(v.Invalid):
                delivery.header(bytes(data))
        for data in (b"", elf()[:-1], elf() + b"x"):
            with self.subTest(length=len(data)), self.assertRaises(v.Invalid):
                delivery.header(data)

    def test_loader(self) -> None:
        """Relative loading, complete runtime requirements and system-only libraries cannot be replaced by a green marker."""
        self.assertEqual(delivery.dynamic(loader(), cpp=True), {"needed": ["libgcc_s.so.1", "libstdc++.so.6"], "runpath": "$ORIGIN/../lib", "soname": None})
        self.assertEqual(delivery.dynamic(b"There is no dynamic section in this file.\n", cpp=False)["needed"], [])
        # CGO's native resolver belongs to the platform C runtime, independently of the supplied C++ runtime.
        resolver = b"""Dynamic section at offset 0xabc contains 3 entries:
 0x0000000000000001 (NEEDED) Shared library: [libresolv.so.2]
 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]
 0x0000000000000000 (NULL) 0x0
"""
        self.assertEqual(delivery.dynamic(resolver, cpp=False), {"needed": ["libc.so.6", "libresolv.so.2"], "runpath": None, "soname": None})
        for old, new in (
            (b"$ORIGIN/../lib", b"/home/ubuntu/private"),
            (b"$ORIGIN/../lib", b"$ORIGIN/../lib:"),
            (b"RUNPATH", b"RPATH"),
            (b"libgcc_s.so.1", b"libunknown.so"),
            (b"libgcc_s.so.1", b"libstdc++.so.6"),
            (b"Shared library:", b"Unexpected:"),
            (b"Dynamic section", b"Truncated section"),
        ):
            with self.subTest(old=old), self.assertRaises(v.Invalid):
                delivery.dynamic(loader().replace(old, new), cpp=True)
        for data in (b"", b"\xff", loader() + b"\x00", b"There is no dynamic section in this file.\n", loader().replace(b"libstdc++.so.6", b"libc.so.6")):
            with self.subTest(data=data[:20]), self.assertRaises(v.Invalid):
                delivery.dynamic(data, cpp=True)
        with self.assertRaises(v.Invalid):
            delivery.dynamic(loader() + loader().splitlines(keepends=True)[3], cpp=True)
        resolved = b"libstdc++.so.6 => /owned/fixture/bin/../lib/libstdc++.so.6 (0x1234)\nlibgcc_s.so.1 => /owned/fixture/bin/../lib/libgcc_s.so.1 (0x5678)\n"
        self.assertIsNone(installation.resolution(resolved, "/owned/fixture/lib"))
        self.assertIsNone(installation.resolution(resolved.replace(b"bin/../", b""), "/owned/fixture/lib"))
        for data in (
            b"",
            b"\xff",
            resolved.replace(b"bin/../lib", b"bin/../../lib"),
            resolved.replace(b"/owned/fixture", b"/other/fixture"),
            resolved + resolved.splitlines(keepends=True)[0],
            resolved.splitlines(keepends=True)[0],
            resolved + b"libunknown.so => not found\n",
        ):
            with self.subTest(resolution=data[:25]), self.assertRaisesRegex(v.Invalid, "installation-refresh-resolution"):
                installation.resolution(data, "/owned/fixture/lib")

    def test_sequence(self) -> None:
        """Missing, repeated, reordered or unconfirmed phases cannot turn partial recovery into a completed sequence."""
        events = []
        for cycle in range(3):
            events.extend(
                [
                    {"event": "mesh_progress", "round": cycle * 10000000 + 1},
                    {"event": "mesh_replicated", "rounds": 2, "records": 48},
                    {"event": "mesh_ready", "cycle": cycle, "star": cycle},
                    {"event": "mesh_failover", "cycle": cycle, "star": cycle},
                    {"event": "mesh_recovered", "cycle": cycle, "star": cycle},
                ]
            )
        events.extend(
            [
                {"event": "mesh_steady", "cycles": 3},
                {"event": "mesh_progress", "round": 30000001},
                {"event": "mesh_progress", "round": 30000100},
                {"event": "mesh_replicated", "rounds": 100, "records": 48},
                {"event": "mesh_sequence_completed", "cycles": 3},
            ]
        )

        def encode(values: list[dict]) -> bytes:
            """Keep literal expected phases independent from the reader's internal grammar."""
            return b"".join((json.dumps(value) + "\n").encode() for value in values)

        self.assertEqual(delivery.sequence(encode(events)), {"cycles": 3, "pre_fault_rounds": [2, 2, 2], "steady_rounds": 100, "records_per_domain": 48})
        resident = [{**row, "workers": 96} if row["event"] == "mesh_progress" else dict(row) for row in events]
        self.assertEqual(delivery.sequence(encode(resident)), delivery.sequence(encode(events)))
        for workers in (0, 95, 97, True, 96.0, "96", None):
            changed = copy.deepcopy(resident)
            changed[0]["workers"] = workers
            with self.subTest(workers=workers), self.assertRaisesRegex(v.Invalid, "delivery-sequence-progress"):
                delivery.sequence(encode(changed))
        for index in (0, 5):
            changed = copy.deepcopy(resident)
            del changed[index]["workers"]
            with self.subTest(mixed=index), self.assertRaisesRegex(v.Invalid, "delivery-sequence-progress"):
                delivery.sequence(encode(changed))
        small = [
            dict(row, workers=6) if row["event"] == "mesh_progress" else dict(row, records=3) if row["event"] == "mesh_replicated" else row for row in resident
        ]
        self.assertEqual(delivery.sequence(encode(small), records=3)["records_per_domain"], 3)
        for index in range(len(events)):
            if index == 17:
                continue  # Intermediate progress frequency is diagnostic; the initial progress of each phase is required.
            with self.subTest(missing=index), self.assertRaises(v.Invalid):
                delivery.sequence(encode(events[:index] + events[index + 1 :]))
            with self.subTest(duplicate=index), self.assertRaises(v.Invalid):
                delivery.sequence(encode(events[:index] + events[index : index + 1] + events[index:]))
        for index, key, value in (
            (1, "records", 47),
            (1, "records", True),
            (1, "rounds", 0),
            (1, "rounds", True),
            (2, "star", 2),
            (2, "cycle", True),
            (15, "cycles", 2),
            (18, "rounds", 99),
            (17, "round", 30000001),
            (17, "round", 40000000),
            (17, "round", True),
            (19, "cycles", True),
            (19, "event", "passed"),
        ):
            changed = copy.deepcopy(events)
            changed[index][key] = value
            with self.subTest(index=index, key=key), self.assertRaises(v.Invalid):
                delivery.sequence(encode(changed))
        with self.assertRaises(v.Invalid):
            delivery.sequence(encode(events)[:-1])
        with self.assertRaises(v.Invalid):
            delivery.sequence(encode(events) + b"{}\n")
        with self.assertRaises(v.Invalid):
            delivery.sequence(encode(events), records=0)
        # Recovery metadata is independent of the sequence grammar and cannot substitute a new SDK or binary.
        metadata = [
            {
                "event": "started",
                "persistent": True,
                "records": 16,
                "steady": 0,
                "faults": 0,
                "interval": 0,
                "binaries": {name: name for name in ("star", "pulsar", "polaris", "astrolabe", "comet_mesh_probe", "comet_process_probe")},
            },
            *[{"event": "recovered", "cycle": cycle + 1, "star": cycle, "sdk_pid": 7} for cycle in range(3)],
            {"event": "steady", "sdk_pid": 7},
            {"event": "completed", "cycles": 3},
        ]
        facts = {
            "recovery/events.jsonl": encode(metadata),
            "controller.json": v.encode({"cwd": "/owned"}),
            "candidate-manifest.json": v.encode({"bin/" + name: name for name in ("star", "pulsar", "polaris", "astrolabe")}),
            "consumers.json": v.encode({name: {"sha256": name} for name in ("comet_mesh_probe", "comet_process_probe")}),
        }
        record = {
            "argv": [
                "/usr/bin/python3",
                "-B",
                "tests/soak.py",
                "--binaries",
                "/owned/fixture/bin",
                "--output",
                "/owned/recovery",
                "--installed",
                "--persistent",
                "--fault-seconds",
                "0",
                "--steady-seconds",
                "0",
                "--interval",
                "0",
                "--records",
                "16",
            ],
            "resolved_environment": {"PATH": "/usr/bin:/bin"},
        }
        with patch.object(delivery, "receipt", return_value=(record, b"fixture")):
            self.assertIsNone(installation.recovery(facts))
            for index, key, value in (
                (0, "persistent", False),
                (0, "records", 1),
                (0, "steady", 7200),
                (0, "binaries", {}),
                (1, "star", 2),
                (2, "cycle", 1),
                (3, "sdk_pid", 8),
                (4, "sdk_pid", 8),
                (5, "cycles", 2),
                (5, "event", "failed"),
            ):
                changed = copy.deepcopy(metadata)
                changed[index][key] = value
                with self.subTest(metadata=key, index=index), self.assertRaises(v.Invalid):
                    installation.recovery({**facts, "recovery/events.jsonl": encode(changed)})
            for changed in ([], metadata[:-1], metadata[:2] + metadata[3:], metadata + [metadata[-1]]):
                with self.subTest(rows=len(changed)), self.assertRaises(v.Invalid):
                    installation.recovery({**facts, "recovery/events.jsonl": encode(changed)})
            for key, value in (("argv", record["argv"][:-2]), ("resolved_environment", {"PATH": "/private"})):
                with (
                    self.subTest(command=key),
                    patch.object(delivery, "receipt", return_value=({**record, key: value}, b"fixture")),
                    self.assertRaises(v.Invalid),
                ):
                    installation.recovery(facts)
        changed = copy.deepcopy(events)
        changed[2], changed[3] = changed[3], changed[2]
        with self.assertRaises(v.Invalid):
            delivery.sequence(encode(changed))

    def test_residence(self) -> None:
        """Require a complete fixed cohort and effective exposure; growth is reported rather than silently accepted."""
        owners = [{"pid": 10, "started": 100, "log": "sdk.log"}, {"pid": 20, "started": 200, "log": "star.log"}]
        policy = {"seconds": 20, "windows": [[0, 10], [10, 20]], "owners": owners, "maximum_gap": 5, "minimum_samples": 2}
        events = [{"event": "steady", "elapsed": 100, "seconds": 20, "sdk_pid": 10}]
        for index, elapsed in enumerate((101, 106, 111, 116)):
            events.append(
                {"event": "sample", "elapsed": elapsed, "processes": [{**owner, "rss": 1000 + 100 * index, "fds": 7, "threads": 3} for owner in owners]}
            )
        events.append({"event": "sample", "elapsed": 120, "processes": []})
        events.append({"event": "completed", "elapsed": 121})

        def encode(rows: list[dict]) -> bytes:
            """Preserve exact fixture ordering and explicit line completion."""
            return b"".join(json.dumps(row).encode() + b"\n" for row in rows)

        result = delivery.residence(encode(events), **policy)
        self.assertEqual(result["qualification"], "descriptive-only")
        self.assertEqual(result["steady_seconds"], 20)
        self.assertEqual(result["steady_samples"], 4)
        self.assertEqual([row["samples"] for row in result["windows"]], [2, 2])
        self.assertEqual(result["windows"][0]["observed_seconds"], [1, 6])
        self.assertEqual(result["windows"][1]["observed_seconds"], [11, 16])
        self.assertEqual(result["windows"][0]["processes"][0]["rss"], {"first": 1000, "last": 1100, "minimum": 1000, "maximum": 1100, "net_change": 100})
        self.assertEqual(result["windows"][1]["processes"][1]["threads"]["net_change"], 0)
        self.assertEqual(policy["owners"], owners)
        for index in (0, 1, 2, 3, 4, 6):
            with self.subTest(missing=index), self.assertRaises(v.Invalid):
                delivery.residence(encode(events[:index] + events[index + 1 :]), **policy)
            with self.subTest(duplicate=index), self.assertRaises(v.Invalid):
                delivery.residence(encode(events[:index] + events[index : index + 1] + events[index:]), **policy)
        for index, key, value in (
            (0, "seconds", True),
            (0, "seconds", 19),
            (0, "sdk_pid", True),
            (0, "sdk_pid", 30),
            (1, "elapsed", True),
            (1, "elapsed", 106),
            (2, "elapsed", 109),
            (4, "elapsed", 114.5),
            (1, "processes", []),
            (1, "processes", {}),
            (1, "event", "sampling_exit"),
            (6, "elapsed", 119),
            (6, "event", "failed"),
            (6, "event", "interrupted"),
            (6, "event", "unknown"),
        ):
            changed = copy.deepcopy(events)
            changed[index][key] = value
            with self.subTest(index=index, key=key, value=value), self.assertRaises(v.Invalid):
                delivery.residence(encode(changed), **policy)
        for key, value in (("pid", 20), ("pid", 30), ("started", 101), ("log", "other.log"), ("rss", 0), ("fds", True), ("threads", -1), ("rss", 2**63)):
            changed = copy.deepcopy(events)
            changed[2]["processes"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(v.Invalid):
                delivery.residence(encode(changed), **policy)
        for key, values in {
            "seconds": (0, True, 86401),
            "windows": ([], [[0, 9], [10, 20]], [[0, 21]], [[0, 10]], [[0, True], [1, 20]]),
            "owners": ([], owners + owners[:1], [{**owners[0], "started": True}], [{**owners[0], "extra": 1}]),
            "maximum_gap": (0, True, float("nan"), float("inf"), 11),
            "minimum_samples": (True, 1, 3),
        }.items():
            for value in values:
                with self.subTest(policy=key, value=value), self.assertRaises(v.Invalid):
                    delivery.residence(encode(events), **{**policy, key: value})
        for data in (b"", b"{}\n", b"[]\n", encode(events)[:-1], encode(events) + b"{}\n"):
            with self.subTest(data=data[:32]), self.assertRaises(v.Invalid):
                delivery.residence(data, **policy)
        changed = copy.deepcopy(events)
        changed[2]["processes"][0]["rss"] = 900
        self.assertEqual(delivery.residence(encode(changed), **policy)["windows"][0]["processes"][0]["rss"]["net_change"], -100)

        exposure = {**policy, "seconds": 30, "windows": [[0, 10], [10, 20], [20, 30]]}
        trace = [{"event": "steady", "elapsed": 100, "seconds": 30, "sdk_pid": 10}]
        for index in range(6):
            trace.append(
                {"event": "sample", "elapsed": 101 + 5 * index, "processes": [{**owner, "rss": 1000 + 100 * index, "fds": 7, "threads": 3} for owner in owners]}
            )
        trace.extend([{"event": "sample", "elapsed": 130, "processes": []}, {"event": "completed", "elapsed": 131}])
        limits = {
            "warmup": 1,
            "processes": [
                {**owner, "rss": {"maximum": 1500, "rise": 300}, "fds": {"maximum": 7, "rise": 0}, "threads": {"maximum": 3, "rise": 0}} for owner in owners
            ],
        }
        frozen = copy.deepcopy(limits)
        bounded = delivery.bounds(encode(trace), policy=limits, **exposure)
        self.assertEqual(bounded["status"], "passed")
        self.assertEqual(bounded["qualification"], "declared-finite-bounds-only")
        self.assertEqual(bounded["violations"], [])
        self.assertEqual(bounded["policy_sha256"], v.digest(v.encode(limits)))
        self.assertEqual(bounded["processes"][0]["rss"], {"maximum": 1500, "rise": 300, "limits": {"maximum": 1500, "rise": 300}})
        self.assertEqual(bounded["processes"][1]["fds"]["rise"], 0)
        self.assertEqual(limits, frozen)
        for owner in range(2):
            for field, peak in (("rss", 1501), ("fds", 8), ("threads", 4)):
                for index in range(1, 7):
                    changed = copy.deepcopy(trace)
                    changed[index]["processes"][owner][field] = peak
                    result = delivery.bounds(encode(changed), policy=limits, **exposure)
                    with self.subTest(owner=owner, field=field, sample=index):
                        self.assertEqual(result["status"], "failed")
                        self.assertIn(
                            {"pid": owners[owner]["pid"], "field": field, "kind": "maximum", "observed": peak, "limit": peak - 1}, result["violations"]
                        )
        for field, peak in (("rss", 1401), ("fds", 8), ("threads", 4)):
            changed, allowed = copy.deepcopy(trace), copy.deepcopy(limits)
            for index in range(1, 7):
                changed[index]["processes"][0][field] = 1000 if field == "rss" else peak - 1
            changed[4]["processes"][0][field] = peak  # The peak disappears before completion but must still fail the rise budget.
            allowed["processes"][0][field]["maximum"] = peak + 1
            result = delivery.bounds(encode(changed), policy=allowed, **exposure)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(
                result["violations"],
                [{"pid": 10, "field": field, "kind": "rise", "observed": 401 if field == "rss" else 1, "limit": 300 if field == "rss" else 0}],
            )
        changed = copy.deepcopy(trace)
        changed[2]["processes"][0]["rss"] = 1500  # Warmup is excluded only from rise, not from absolute limits.
        self.assertEqual(delivery.bounds(encode(changed), policy=limits, **exposure)["status"], "passed")
        changed[6]["processes"][0]["rss"] = 1100
        result = delivery.bounds(encode(changed), policy=limits, **exposure)
        self.assertEqual(result["residence"]["windows"][2]["processes"][0]["rss"]["net_change"], -300)
        self.assertEqual(result["processes"][0]["rss"]["rise"], 200)
        variants = [None, {}, {**limits, "extra": 0}, {**limits, "processes": []}, {**limits, "processes": limits["processes"][:1]}]
        variants.extend({**limits, "warmup": value} for value in (-1, 2, True, 1.0, "1"))
        for key, value in (("pid", True), ("pid", 30), ("started", 101), ("log", "other.log"), ("extra", 0)):
            changed = copy.deepcopy(limits)
            changed["processes"][0][key] = value
            variants.append(changed)
        variants.append({**limits, "processes": [limits["processes"][0]] * 2})
        for field in ("rss", "fds", "threads"):
            for value in (
                None,
                {},
                {"maximum": 0, "rise": 0},
                {"maximum": True, "rise": 0},
                {"maximum": 2**63, "rise": 0},
                {"maximum": 10, "rise": -1},
                {"maximum": 10, "rise": 10},
                {"maximum": 10, "rise": False},
                {"maximum": 10.0, "rise": 0},
                {"maximum": 10, "rise": 0, "extra": 0},
            ):
                changed = copy.deepcopy(limits)
                changed["processes"][0][field] = value
                variants.append(changed)
        for variant in variants:
            with self.subTest(bounds=variant), self.assertRaises(v.Invalid):
                delivery.bounds(encode(trace), policy=variant, **exposure)
        for data in (b"", encode(trace)[:-1], encode(trace[:-1]), encode(trace + trace[-1:])):
            with self.subTest(trace=data[:32]), self.assertRaises(v.Invalid):
                delivery.bounds(data, policy=limits, **exposure)
        with self.assertRaises(v.Invalid):
            delivery.bounds(encode(events), policy=limits, **policy)
        reordered = {**limits, "processes": list(reversed(limits["processes"]))}
        self.assertEqual(delivery.bounds(encode(trace), policy=reordered, **exposure)["processes"], bounded["processes"])
        immediate = {**limits, "warmup": 0}
        self.assertEqual(delivery.bounds(encode(trace), policy=immediate, **exposure)["status"], "failed")
        bounded["processes"][0]["rss"]["limits"]["rise"] = 0
        self.assertEqual(limits, frozen)

    @unittest.skipUnless(os.name == "posix", "Linux candidate ownership and executable modes")
    def test_inventory(self) -> None:
        """Only an exact bounded tree passes; adding a private key or omitting/replacing any manifest item fails."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = fixture(root)
            original = delivery.inventory(root, expected, forbidden=["/private/build"])
            self.assertEqual(original["files"].keys(), expected.keys())
            self.assertGreater(original["bytes"], 0)
            for name in sorted(expected):
                changed = copy.deepcopy(expected)
                changed[name] = "0" * 64
                with self.subTest(name=name), self.assertRaises(v.Invalid):
                    delivery.inventory(root, changed, forbidden=[])
            for changed in ({}, {**expected, "bin/private-key.pem": "0" * 64}, {n: x for n, x in expected.items() if n != "bin/star"}):
                with self.subTest(count=len(changed)), self.assertRaises(v.Invalid):
                    delivery.inventory(root, changed, forbidden=[])
            extra = root / "secret.pem"
            extra.write_text("fixture", encoding="utf-8")
            with self.assertRaises(v.Invalid):
                delivery.inventory(root, expected, forbidden=[])
            extra.unlink()
            path = root / "bin/star"
            path.chmod(0o644)
            with self.assertRaises(v.Invalid):
                delivery.inventory(root, expected, forbidden=[])
            path.chmod(0o777)
            with self.assertRaises(v.Invalid):
                delivery.inventory(root, expected, forbidden=[])
            path.chmod(0o755)
            link = root / "alias"
            link.symlink_to(path)
            with self.assertRaises(v.Invalid):
                delivery.inventory(root, expected, forbidden=[])
            link.unlink()
            path.unlink()
            with self.assertRaises(v.Invalid):
                delivery.inventory(root, expected, forbidden=[])

    @unittest.skipUnless(os.name == "posix", "Linux candidate ownership and executable modes")
    def test_export(self) -> None:
        """Even a correctly hashed export is rejected when it leaks a declared private build root."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = fixture(root)
            path = root / "lib/cmake/Comet/CometTargets.cmake"
            path.write_text('set(path "/private/build/libcomet.a")\n', encoding="utf-8")
            expected[path.relative_to(root).as_posix()] = v.file_digest(path)
            with self.assertRaises(v.Invalid):
                delivery.inventory(root, expected, forbidden=["/private/build"])


# Native maintenance supplement controls below never start a compiler, server or SDK process.
class MaintenanceTests(unittest.TestCase):
    """Require the current one-product installation and keep all preceding archived products/source facts bound."""

    @classmethod
    def setUpClass(cls) -> None:
        """Read each fixed native archive once; controls alter private dictionary views only."""
        from tools import entry

        cls.files = {}
        for number, digest in ((7, installation.REFRESH), (8, installation.MAINTENANCE)):
            raw = v.read(v.ROOT / f"build/results/assurance/reuse-plan/storage-delivery-current-{number}/native/evidence.tar.gz", 128 * 1024**2)
            if v.digest(raw) != digest:
                v.reject("maintenance-fixture-archive")
            cls.files[number] = entry.unpack(raw)
        # Campaign 7 retains only the changed Star; the real composition carries unchanged probe bytes from 6.
        raw = v.read(v.ROOT / "build/results/assurance/reuse-plan" / installation.NAME, 128 * 1024**2)
        if v.digest(raw) != installation.ARCHIVE:
            v.reject("maintenance-fixture-archive")
        inherited = entry.unpack(raw)
        for name in ("comet_mesh_probe", "comet_process_probe"):
            path = "fixture/bin/" + name
            cls.files[7][path] = inherited[path]

    def test_current(self) -> None:
        """Recompute both shipping consumer deliveries against the current complete source inventory."""
        storage = delivery.reconcile(v.ROOT, component="polaris-storage")
        admission = delivery.reconcile(v.ROOT)
        self.assertEqual(set(storage["consumers"]), {"polaris"})
        self.assertEqual(set(admission["consumers"]), {"polaris", "astrolabe"})
        renewed = (v.ROOT / shipping.PREFIX / next(iter(shipping.RENEWED))).exists()
        expected_sha = (
            "79049b75d0de12b895070483be278ae9668373cd1fe8330564f8434646db98dc"
            if renewed
            else "8f81b5c6ecb27e189f251150df1f3b489471fdc9016833d4002b93e52fb3379c"
        )
        self.assertEqual(storage["consumers"]["polaris"]["sha256"], expected_sha)
        self.assertEqual(admission["consumers"]["polaris"], storage["consumers"]["polaris"])
        expected_archives = (
            shipping.RENEWED | {name: shipping.ARCHIVES[name] for name in (next(iter(shipping.ARCHIVES)), list(shipping.ARCHIVES)[4])}
            if renewed
            else shipping.ARCHIVES
        )
        self.assertEqual(storage["archives"], expected_archives)
        self.assertEqual(storage["installation"]["cpp"]["linked_units"], 82)
        self.assertEqual(len(storage["installation"]["candidate"]), 51)
        self.assertEqual(storage["trust"], "local")
        self.assertIn("polaris/internal/storage/maintenance.go", storage["source"])

    def test_campaign(self) -> None:
        """Require the native seven-command inventory and its real retired owners."""
        files = self.files[8]
        self.assertEqual(set(delivery.campaign(files, 8)), set(delivery.COMMANDS[8]))
        for field, value in (
            ("errors", ["failed"]),
            ("interrupted", True),
            ("remaining_owned", [1]),
            ("products_unchanged", False),
            ("protected_unchanged", False),
            ("completed", []),
        ):
            terminal = {**v.decode(files["terminal.json"]), field: value}
            with self.subTest(terminal=field), self.assertRaisesRegex(v.Invalid, "delivery-current-lifecycle"):
                delivery.campaign({**files, "terminal.json": v.encode(terminal)}, 8)

    def test_source(self) -> None:
        """An undeclared source/fixture change or changed donor cannot borrow the current rebuild."""
        current, previous = self.files[8], self.files[7]
        plan = installation.supplement(current, previous)
        self.assertEqual(plan, v.decode(current["inputs.json"]))
        for field, key in (
            ("relevant", "polaris/internal/storage/store.go"),
            ("relevant", "polaris/internal/storage/maintenance.go"),
            ("files", "polaris/internal/storage/maintenance_test.go"),
            ("cpp_production", installation.STAR),
            ("donor", "archive_sha256"),
        ):
            changed = copy.deepcopy(plan)
            changed[field][key] = "0" * 64
            with self.subTest(field=field, key=key), self.assertRaisesRegex(v.Invalid, "installation-maintenance-source"):
                installation.supplement({**current, "inputs.json": v.encode(changed)}, previous)
        for field, value in (("source_delta", {}), ("relevant", {**plan["relevant"], "polaris/internal/storage/other.go": "0" * 64})):
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "installation-maintenance-source"):
                installation.supplement({**current, "inputs.json": v.encode({**plan, field: value})}, previous)

    def test_products(self) -> None:
        """Only Polaris may be replaced; another changed file or unbound probe invalidates reuse."""
        current, previous = self.files[8], self.files[7]
        candidate = v.decode(current["candidate-manifest.json"])
        for key, value in (
            ("candidate/bin/polaris", b"changed"),
            ("candidate/bin/star", b"extra"),
            ("consumers.json", b"{}"),
            ("partial-candidate.native.json", b"{}"),
        ):
            with self.subTest(key=key), self.assertRaisesRegex(v.Invalid, "installation-maintenance-products"):
                installation.supplement({**current, key: value}, previous)
        for name in ("bin/star", "bin/astrolabe", "lib/libcomet.a", "share/astra/LICENSE"):
            with self.subTest(name=name), self.assertRaisesRegex(v.Invalid, "installation-maintenance-products"):
                installation.supplement({**current, "candidate-manifest.json": v.encode({**candidate, name: "0" * 64})}, previous)
        with self.assertRaisesRegex(v.Invalid, "installation-maintenance-probe"):
            installation.supplement({**current, "fixture/bin/comet_mesh_probe": b"changed"}, previous)

    def test_reuse(self) -> None:
        """Missing peers, duplicate ledger rows or false rebuild claims cannot preserve the 50-file handoff."""
        current, previous = self.files[8], self.files[7]
        reused = v.decode(current["reused-installed.native.json"])
        for field, value in (
            ("donor_archive_sha256", "0" * 64),
            ("unchanged_files", reused["unchanged_files"][:-1]),
            ("unchanged_files", reused["unchanged_files"] + reused["unchanged_files"][:1]),
            ("unchanged_cpp_inputs", 163),
            ("rebuilt", {}),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "installation-maintenance-reuse"):
                installation.supplement({**current, "reused-installed.native.json": v.encode({**reused, field: value})}, previous)


if __name__ == "__main__":
    unittest.main(verbosity=2)
