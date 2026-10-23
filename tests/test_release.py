"""Verify release navigation and complete offline inputs without changing maintained source metadata."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

# Load the release entry without running a preparation, build or publication phase.
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("astra_release", ROOT / ".github/scripts/release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseDocumentationTests(unittest.TestCase):
    """Use independent miniature inputs to verify source identity, package links and license preparation."""

    def setUp(self) -> None:
        """Own a fresh local fixture and restore every patched release input after the case."""
        temporary = ROOT / "build/tmp"
        temporary.mkdir(parents=True, exist_ok=True)
        directory = tempfile.TemporaryDirectory(prefix="astra-release-docs-", dir=temporary)
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        for name, value in (("ROOT", self.root), ("DOCUMENTS", ("README.md", "docs/README.md", "LICENSE"))):
            replacement = patch.object(release, name, value)
            replacement.start()
            self.addCleanup(replacement.stop)

    def write(self, name: str, text: str) -> None:
        """Create only the declared source input beneath the owned fixture."""
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_navigation_and_source_identity(self) -> None:
        """Preserve bundled, external and anchor links; omitted targets bind to the requested tag without modifying source."""
        original = (
            "[guide](docs/README.md#start)\n"
            "[license](LICENSE)\n"
            "[tests](tests/README.md?plain=1#models)\n"
            "[code](source%20files/)\n"
            "[web](https://example.org/guide)\n"
            "[anchor](#local)\n"
        )
        self.write("README.md", original)
        self.write("docs/README.md", "# Start\n[home](../README.md)\n")
        self.write("LICENSE", "Test license input\n")
        self.write("tests/README.md", "# Models\n")
        self.write("source files/unit.go", "package fixture\n")
        rendered = release.documentation("README.md", "v0.2.0")
        self.assertEqual(
            rendered,
            "[guide](docs/README.md#start)\n"
            "[license](LICENSE)\n"
            "[tests](https://github.com/eosforge/astra/blob/v0.2.0/tests/README.md?plain=1#models)\n"
            "[code](https://github.com/eosforge/astra/tree/v0.2.0/source%20files)\n"
            "[web](https://example.org/guide)\n"
            "[anchor](#local)\n",
        )
        self.assertEqual(release.documentation("docs/README.md", "v0.2.0"), "# Start\n[home](../README.md)\n")
        self.assertEqual((self.root / "README.md").read_text(encoding="utf-8"), original)

    def test_missing_and_escaping_targets(self) -> None:
        """Refuse a missing local file and a path outside the declared source tree instead of publishing broken links."""
        for target in ("missing.md", "../outside.md"):
            with self.subTest(target=target):
                self.write("README.md", f"[invalid]({target})\n")
                with self.assertRaises(RuntimeError):
                    release.documentation("README.md", "v0.2.0")

    def test_complete_graph_without_checksum_changes(self) -> None:
        """Prepare graph-only license sources in an empty cache, retaining the checkout's exact checksums."""
        go = shutil.which("go")
        if go is None:
            self.skipTest("The native module-cache counterexample requires an existing Go toolchain")
        proxy = self.root / "proxy"
        cache = self.root / "build"
        release.isolate(cache)

        def publish(name: str, requirements: str = "") -> None:
            """Provide a tiny immutable module through a local file proxy, without external downloads."""
            module = "example.invalid/" + name
            version = "v1.0.0"
            directory = proxy / module / "@v"
            directory.mkdir(parents=True)
            content = "module " + module + "\n\ngo 1.20\n" + requirements
            (directory / (version + ".mod")).write_text(content, encoding="utf-8")
            (directory / (version + ".info")).write_text(json.dumps({"Version": version, "Time": "2000-01-01T00:00:00Z"}), encoding="utf-8")
            with zipfile.ZipFile(directory / (version + ".zip"), "w") as archive:
                for path, value in (("go.mod", content), ("source.go", "package source\n"), ("LICENSE", "Fixture license: " + name + "\n")):
                    archive.writestr(module + "@" + version + "/" + path, value)

        publish("notice")
        publish("direct", "\nrequire example.invalid/notice v1.0.0\n")
        self.write("go.mod", "module example.invalid/main\n\ngo 1.20\n\nrequire example.invalid/direct v1.0.0\n")
        env = dict(os.environ)
        env.update(
            GOTOOLCHAIN="local",
            GOPROXY=proxy.as_uri(),
            GOSUMDB="off",
            GOWORK="off",
            GOENV="off",
            GOFLAGS="-mod=readonly",
            CGO_ENABLED="0",
            GOPATH=str(cache / "deps/go"),
            GOMODCACHE=str(cache / "deps/go/pkg/mod"),
            GOCACHE=str(cache / "cache/go"),
        )
        initial = subprocess.run([go, "mod", "download"], cwd=self.root, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(initial.returncode, 0, initial.stdout + initial.stderr)
        original = {name: (self.root / name).read_bytes() for name in ("go.mod", "go.sum")}
        lookup = [go, "-C", str(cache), "mod", "download", "-json", "example.invalid/notice@v1.0.0"]
        absent = subprocess.run(lookup, cwd=self.root, env={**env, "GOPROXY": "off"}, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(absent.returncode, 0)
        self.assertIn("module lookup disabled by GOPROXY=off", absent.stdout)
        with patch.object(release, "CACHE", cache), patch.object(release, "GO", Path(go)):
            release.modules(self.root, env)
        self.assertEqual({name: (self.root / name).read_bytes() for name in original}, original)
        available = subprocess.run(lookup, cwd=self.root, env={**env, "GOPROXY": "off"}, capture_output=True, text=True, timeout=30)
        self.assertEqual(available.returncode, 0, available.stdout + available.stderr)
        directory = Path(json.loads(available.stdout)["Dir"])
        self.assertEqual((directory / "LICENSE").read_text(encoding="utf-8"), "Fixture license: notice\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
