"""Check offline probe rejection and optional C++ switch integration; execution requires separate test authorization."""

import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("astra_profile", Path(__file__).resolve().parents[1] / "tools/profile.py")
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)


class Format(unittest.TestCase):
    """Check format and completeness boundaries without services or a compiler toolchain."""

    def setUp(self) -> None:
        # Keep temporary files under project build output, away from system tools and runtime directories.
        """Own a temporary probe file and a known static site identity for each case."""
        root = profile.ROOT / "build" / "profile-tests"
        root.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "1.profile"
        self.site = profile.identify("example")
        self.sites = {self.site: {"name": "example"}}

    def write(
        self, records: list[tuple[int, ...]], *, missed: int = 0, errors: int = 0, cpu: int = 0, version: int = 1, selected: int = 255, seconds: int = 0
    ) -> None:
        """Use one fixed block whose zero tail slots represent unused per-thread reservations."""
        reserved = [0] * 7 if version == 1 else [selected, seconds, *([0] * 5)]
        header = profile.HEADER.pack(profile.MAGIC, version, 80, 64, 64, missed, errors, 1, cpu, *reserved)
        entries = b"".join(profile.ENTRY.pack(*record) for record in records)
        self.path.write_bytes(header + entries + bytes((64 - len(records)) * 80))

    def record(self, **changes: int) -> tuple[int, ...]:
        """Construct a valid probe record with explicit field overrides for boundary cases."""
        fields = dict(start=100, elapsed=100, own=70, cpu=0, exclusive=0, id=1, parent=0, site=self.site, value=0, thread=1, flags=0)
        fields.update(changes)
        return tuple(fields.values())

    def test_nested_and_holes(self) -> None:
        """Count nested spans and unused reserved slots without charging child time to the parent twice."""
        self.write([self.record(), self.record(start=110, elapsed=30, own=30, id=2, parent=1)])
        result = profile.analyze(self.path, self.sites)
        self.assertTrue(result["complete"])
        self.assertEqual(result["spans"], 2)
        self.assertEqual(result["unused_slots"], 62)
        self.assertEqual(result["groups"][0]["own_ns"]["sum"], 70)

    def test_counter_and_async(self) -> None:
        """Keep counters and asynchronous intervals distinct from synchronous spans."""
        self.write(
            [
                self.record(),
                self.record(start=110, elapsed=0, own=0, id=0, parent=1, value=17, flags=2),
                self.record(start=300, elapsed=50, own=50, id=0, flags=4),
            ]
        )
        result = profile.analyze(self.path, self.sites)
        self.assertEqual((result["counters"], result["intervals"]), (1, 1))

    def test_cpu_mode(self) -> None:
        """Report thread CPU observations only when the file enables CPU sampling."""
        self.write([self.record(cpu=90, exclusive=50, flags=1)], cpu=1)
        result = profile.analyze(self.path, self.sites)
        self.assertEqual(result["groups"][0]["cpu_ns"]["sum"], 90)

    def test_signed_and_selection(self) -> None:
        """Decode signed clock values, selected features, and raw observation order from v2 files."""
        self.sites[self.site]["name"] = "clock.test.offset"
        self.write(
            [self.record(), self.record(start=110, elapsed=0, own=0, id=0, parent=1, value=(1 << 64) - 17, flags=10)], version=2, selected=9, seconds=300
        )
        events = []
        result = profile.analyze(self.path, self.sites, clock=events.append)
        self.assertEqual(result["functions"], ["clock", "replication"])
        self.assertEqual(result["seconds"], 300)
        signed = next(group for group in result["groups"] if group["kind"] == "value")
        self.assertEqual((signed["values"]["min"], signed["values"]["max"]), (-17, -17))
        self.assertEqual(len(events), 1)
        self.assertEqual((events[0]["span"], events[0]["observed_ns"], events[0]["value"]), (1, 110, -17))

    def test_invalid_selection(self) -> None:
        """Reject unsupported versions, feature bits, and capture durations."""
        for change in ({"selected": 0}, {"selected": 256}, {"seconds": 86401}, {"version": 3}):
            with self.subTest(change=change):
                self.write([self.record()], **({"version": 2} | change))
                with self.assertRaises(ValueError):
                    profile.analyze(self.path, self.sites)

    def test_drop_and_clock_error(self) -> None:
        """Mark evidence incomplete when the header reports dropped records or clock errors."""
        for field in ("missed", "errors"):
            with self.subTest(field=field):
                self.write([self.record()], **{field: 1})
                self.assertFalse(profile.analyze(self.path, self.sites)["complete"])

    def test_invalid_record(self) -> None:
        """Reject malformed IDs, flags, timing, and source identities."""
        for change in ({"id": 9}, {"flags": 8}, {"flags": 10}, {"own": 101}, {"cpu": 1}, {"parent": 1}, {"site": 0}, {"thread": 0}):
            with self.subTest(change=change):
                self.write([self.record(**change)])
                with self.assertRaises(ValueError):
                    profile.analyze(self.path, self.sites)

    def test_invalid_parent(self) -> None:
        """Reject child spans outside their parent's time or thread boundaries."""
        for change in ({"start": 50}, {"thread": 2}, {"elapsed": 101}):
            with self.subTest(change=change):
                self.write([self.record(), self.record(id=2, parent=1, **change)])
                with self.assertRaises(ValueError):
                    profile.analyze(self.path, self.sites)

    def test_truncated(self) -> None:
        """Reject absent or truncated probe data instead of reporting an empty successful capture."""
        for data in (b"", bytes(128)):
            self.path.write_bytes(data)
            with self.assertRaises(ValueError):
                profile.analyze(self.path, self.sites)

    def test_quantiles_and_hash(self) -> None:
        """Check fixed hash vectors and order statistics without claiming sufficient tail samples."""
        self.assertEqual(profile.identify(""), 14695981039346656037)
        self.assertEqual(profile.identify("hello"), 0xA430D84680AABD0B)
        result = profile.distribution([10, 1, 5])
        self.assertEqual((result["p50"], result["p99"]), (5, 10))
        self.assertFalse(result["tail_samples_sufficient"])


def binaries(enabled: Path, disabled: Path, root: Path) -> None:
    """Run existing CMake test artifacts without building or downloading; isolate scenarios and parse only after exit."""
    sites = profile.inventory(profile.ROOT)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("ASTRA_PROFILE_")}
    with tempfile.TemporaryDirectory(prefix="profile-", dir=root) as directory:

        def run(name: str, binary: Path, mode: str = "normal", **settings: str | None) -> list[dict]:
            """Run one existing probe binary in isolated output storage, then parse its completed files."""
            destination = Path(directory) / name
            destination.mkdir()
            env = dict(environment, ASTRA_PROFILE_DIR=str(destination), ASTRA_PROFILE_SAMPLE="1", ASTRA_PROFILE_MIB="1", ASTRA_PROFILE_CPU="0")
            env.update(settings)
            for key in tuple(env):
                if env[key] is None:
                    del env[key]
            subprocess.run([str(binary), mode], check=True, timeout=30, env=env, capture_output=True, text=True)
            return [profile.analyze(path, sites) for path in destination.glob("*.profile")]

        if run("disabled", disabled):
            raise AssertionError("Disabled macros created a file")
        # Disabled binaries must omit probe names and initialization errors, independent of Release optimization of runtime branches.
        raw = disabled.read_bytes()
        if b"ASTRA_PROFILE_DIR" in raw or b"profile.test.work" in raw:
            raise AssertionError("Disabled binary retains probe strings")
        if run("unset", enabled, ASTRA_PROFILE_DIR=None):
            raise AssertionError("Unset directory created records")
        if run("invalid", enabled, ASTRA_PROFILE_SAMPLE="0"):
            raise AssertionError("Invalid sampling accepted")
        for index, groups in enumerate(("", "clock,", ",clock", "clock,clock", "clock,unknown", "all,clock", "clock, core")):
            if run(f"invalid-group-{index}", enabled, mode="groups", ASTRA_PROFILE_GROUPS=groups):
                raise AssertionError("Invalid group selection accepted")
        for index, seconds in enumerate(("", "-1", "86401", "x")):
            if run(f"invalid-seconds-{index}", enabled, mode="groups", ASTRA_PROFILE_SECONDS=seconds):
                raise AssertionError("Invalid recording window accepted")
        selected = run("clock", enabled, mode="groups", ASTRA_PROFILE_GROUPS="clock")
        if len(selected) != 1 or not selected[0]["complete"] or selected[0]["functions"] != ["clock"] or selected[0]["spans"] != 1:
            raise AssertionError("Clock-only sampling leaked unrelated spans or lost its filtered parent")
        groups = {group["name"]: group for group in selected[0]["groups"]}
        if set(groups) != {"clock.test.sample", "clock.test.offset", "clock.test.bound"}:
            raise AssertionError("Clock-only recording leaked other functional groups")
        if groups["clock.test.offset"]["values"]["min"] != -17 or groups["clock.test.offset"]["values"]["max"] != 23:
            raise AssertionError("Signed clock offsets changed")
        if groups["clock.test.bound"]["values"]["min"] != -(1 << 63) or groups["clock.test.bound"]["values"]["max"] != (1 << 63) - 1:
            raise AssertionError("Signed diagnostic boundaries changed")
        combined = run("combined", enabled, mode="groups", ASTRA_PROFILE_GROUPS="clock,core,replication")
        if len(combined) != 1 or not combined[0]["complete"] or combined[0]["spans"] != 3:
            raise AssertionError("Combined groups lost nesting")
        window = run("window", enabled, mode="window", ASTRA_PROFILE_GROUPS="clock", ASTRA_PROFILE_SECONDS="1")
        if len(window) != 1 or not window[0]["complete"] or {group["name"] for group in window[0]["groups"]} != {"clock.test.before"}:
            raise AssertionError("Expired recording window continued collecting")
        normal = run("normal", enabled)
        if len(normal) != 1 or not normal[0]["complete"] or normal[0]["spans"] != 402 or normal[0]["counters"] != 81 or normal[0]["intervals"] != 1:
            raise AssertionError("Nested/thread/unwind record accounting changed")
        cpu = run("cpu", enabled, ASTRA_PROFILE_CPU="1")
        if len(cpu) != 1 or not cpu[0]["complete"] or not cpu[0]["cpu"]:
            raise AssertionError("CPU recording failed")
        sampled = run("sampled", enabled, ASTRA_PROFILE_SAMPLE="4")
        if len(sampled) != 1 or not sampled[0]["complete"] or not 0 < sampled[0]["spans"] < normal[0]["spans"]:
            raise AssertionError("Sampling did not retain whole trees")
        phase = run("phase", enabled, mode="phase", ASTRA_PROFILE_SAMPLE="64")
        if len(phase) != 1 or not phase[0]["complete"] or {group["name"] for group in phase[0]["groups"]} != {"profile.test.first", "profile.test.second"}:
            raise AssertionError("Sampling aliases a fixed alternating call sequence")
        full = run("full", enabled, mode="overflow")
        if len(full) != 1 or full[0]["complete"] or not full[0]["missed"]:
            raise AssertionError("Bounded recording did not report overflow")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enabled", type=Path)
    parser.add_argument("--disabled", type=Path)
    parser.add_argument("--temporary-root", type=Path)
    options = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Format))
    if not result.wasSuccessful():
        raise SystemExit(1)
    if options.enabled or options.disabled:
        if not (options.enabled and options.disabled and options.temporary_root):
            parser.error("both binaries and temporary root are required")
        binaries(options.enabled, options.disabled, options.temporary_root)
