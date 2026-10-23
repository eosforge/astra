"""Prepare explicit CI dependencies, build offline, and package the Linux source tag."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from urllib.parse import quote, unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.paths import isolate

CACHE = ROOT / "build"
PREFIX = CACHE / "deps/astra/linux-gcc16/install"
GO = CACHE / "tools/go-1.27.2/bin/go"
COMPILER = CACHE / "tools/gcc-16.2.0"
OUTPUT = CACHE / "cmake/release"
GO_ARCHIVE = "go1.27.2.linux-amd64.tar.gz"
GO_SHA256 = "ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5"
SQLITE_ARCHIVE = "sqlite-amalgamation-3530400.zip"
SQLITE_SHA256 = "1e71ddf93849c6a6ecf58b827c0692073d2dd7ee40196158068f7b29f422e87d"
SERVICES = ("star", "pulsar", "polaris", "astrolabe")
DOCUMENTS = (
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "docs/README.md",
    "docs/architecture.md",
    "docs/build.md",
    "docs/deployment.md",
    "docs/releases.md",
    "docs/troubleshooting.md",
    "star/README.md",
    "pulsar/README.md",
    "polaris/README.md",
    "astrolabe/README.md",
    "comet/cpp/README.md",
    "comet/go/README.md",
    "proto/README.md",
    "LICENSE",
    "comet/go/LICENSE",
)


def run(*arguments: object, env: dict[str, str] | None = None, capture: bool = True) -> str:
    """Execute fixed argument lists and preserve native failures."""
    command = [str(value) for value in arguments]
    print("Running: " + subprocess.list2cmdline(command), flush=True)
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE if capture else None, check=True)
    return result.stdout or ""


def digest(path: Path) -> str:
    """Hash actual artifact bytes."""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def download(url: str, destination: Path, expected: str) -> None:
    """Download only a named, checksum-pinned input during explicit preparation."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        temporary = destination.with_suffix(".partial")
        with urllib.request.urlopen(url, timeout=120) as response, temporary.open("wb") as stream:
            shutil.copyfileobj(response, stream)
        if digest(temporary) != expected:
            raise RuntimeError("Download checksum mismatch: " + destination.name)
        temporary.replace(destination)
    if digest(destination) != expected:
        raise RuntimeError("Cached checksum mismatch: " + destination.name)


def environment(*, online: bool = False) -> dict[str, str]:
    """Keep tool paths and Go caches local; only preparation permits module downloads."""
    result = dict(os.environ)
    result.update(
        PATH=os.pathsep.join((str(GO.parent), str(COMPILER / "bin"), str(PREFIX / "bin"), result["PATH"])),
        LD_LIBRARY_PATH=str(COMPILER / "lib64"),
        CC=str(COMPILER / "bin/gcc"),
        CXX=str(COMPILER / "bin/g++"),
        GOPATH=str(CACHE / "deps/go"),
        GOMODCACHE=str(CACHE / "deps/go/pkg/mod"),
        GOCACHE=str(CACHE / "cache/go"),
        GOTOOLCHAIN="local",
        GOWORK="off",
        GOPROXY="https://proxy.golang.org" if online else "off",
        GOSUMDB="sum.golang.org" if online else "off",
        GOFLAGS="-mod=readonly",
        CGO_ENABLED="1",
        GOMAXPROCS="2",
        CMAKE_BUILD_PARALLEL_LEVEL="2",
    )
    return result


def modules(folder: Path, env: dict[str, str]) -> None:
    """Acquire the complete license graph without extending the checkout's maintained checksum files."""
    with tempfile.TemporaryDirectory(prefix="go-modules-", dir=CACHE) as directory:
        staging = Path(directory)
        for name in ("go.mod", "go.sum"):
            shutil.copy2(folder / name, staging / name)
        run(GO, "-C", staging, "mod", "download", "all", env=env, capture=False)


def prepare() -> None:
    """Acquire the approved compiler mapping, Go, SQLite, C++ sources and Go modules."""
    isolate(CACHE)
    if run("g++", "-dumpfullversion").strip() != "16.2.0":
        raise RuntimeError("The pinned GCC container must provide GCC 16.2.0")
    (COMPILER / "bin").mkdir(parents=True, exist_ok=True)
    for name in ("gcc", "g++"):
        target = COMPILER / "bin" / name
        if not target.exists():
            target.symlink_to(shutil.which(name) or "/missing-compiler")
    runtime = Path(run("g++", "-print-file-name=libstdc++.so.6").strip()).resolve()
    if not (COMPILER / "lib64").exists():
        (COMPILER / "lib64").symlink_to(runtime.parent, target_is_directory=True)
    archive = CACHE / "downloads" / GO_ARCHIVE
    download("https://go.dev/dl/" + GO_ARCHIVE, archive, GO_SHA256)
    if not GO.exists():
        with tarfile.open(archive) as bundle:
            bundle.extractall(CACHE / "tools", filter="data")
        (CACHE / "tools/go").rename(GO.parent.parent)
    env = environment(online=True)
    if "go1.27.2" not in run(GO, "version", env=env):
        raise RuntimeError("The prepared Go toolchain version differs from the build contract")
    download(
        "https://www.sqlite.org/2026/" + SQLITE_ARCHIVE,
        CACHE / "deps/common/downloads/fetchcontent/sqlite" / SQLITE_ARCHIVE,
        SQLITE_SHA256,
    )
    run("python3", "tools/prepare_dependencies.py", "fetch", env=env, capture=False)
    try:
        run("python3", "tools/prepare_dependencies.py", "build", "--profile", "release", "--jobs", "2", env=env, capture=False)
    except subprocess.CalledProcessError:
        logs = sorted((PREFIX.parent / "build").glob("*/build.log"), key=lambda path: path.stat().st_mtime)
        if logs:
            print(logs[-1].read_text(errors="replace")[-16000:], flush=True)
        raise
    for folder in (ROOT, ROOT / "comet/go"):
        modules(folder, env)


def build() -> None:
    """Compile delivered targets only, without building tests or starting services."""
    env = environment()
    print(
        run(
            "cmake",
            "-S",
            ROOT,
            "-B",
            OUTPUT,
            "-DCMAKE_BUILD_TYPE=Release",
            "-DBUILD_TESTING=OFF",
            "-DCMAKE_C_COMPILER=" + env["CC"],
            "-DCMAKE_CXX_COMPILER=" + env["CXX"],
            "-DCMAKE_PREFIX_PATH=" + str(PREFIX),
            "-DFETCHCONTENT_FULLY_DISCONNECTED=ON",
            "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF",
            "-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF",
            env=env,
            capture=False,
        ),
        flush=True,
    )
    run("cmake", "--build", OUTPUT, "--parallel", "2", "--target", "star", "pulsar", "comet", env=env, capture=False)
    for service in ("polaris", "astrolabe"):
        run(GO, "build", "-mod=readonly", "-p", "2", "-trimpath", "-o", OUTPUT / service, "./" + service, env=env, capture=False)


def licenses(stage: Path) -> None:
    """Include native and Go module license/notice files from the acquired inputs."""
    target = stage / "share/astra/licenses"
    lock = json.loads((ROOT / "dependencies.lock.json").read_text())
    for item in lock["sources"]:
        source = CACHE / "deps/astra/src" / (item["name"] + "-" + item["commit"])
        found = [p for p in source.iterdir() if p.is_file() and p.name.upper().startswith(("LICENSE", "COPYING", "NOTICE"))]
        if not found:
            raise RuntimeError("Missing native dependency license: " + item["name"])
        for path in found:
            folder = target / item["name"]
            folder.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, folder / path.name)
    modules = run(GO, "list", "-m", "-json", "all", env=environment()).strip()
    decoder = json.JSONDecoder()
    while modules:
        module, consumed = decoder.raw_decode(modules)
        modules = modules[consumed:].lstrip()
        if module.get("Main"):
            continue
        directory = module.get("Dir")
        if not directory:
            # Graph-only modules may omit Dir when their sums are outside the main module's required set.
            # Resolve their already acquired bytes offline from the independent cache module.
            isolate(CACHE)
            cached = json.loads(run(GO, "-C", CACHE, "mod", "download", "-json", module["Path"] + "@" + module["Version"], env=environment()))
            directory = cached["Dir"]
        source = Path(directory)
        found = [p for p in source.iterdir() if p.is_file() and p.name.upper().startswith(("LICENSE", "COPYING", "NOTICE", "PATENTS"))]
        if not found:
            raise RuntimeError("Missing Go module license: " + module["Path"])
        folder = target / "go" / (module["Path"] + "@" + module["Version"])
        folder.mkdir(parents=True, exist_ok=True)
        for path in found:
            shutil.copy2(path, folder / path.name)
    folder = target / "go-runtime"
    folder.mkdir(parents=True, exist_ok=True)
    for name in ("LICENSE", "PATENTS"):
        shutil.copy2(GO.parent.parent / name, folder / name)
    (target / "sqlite.txt").write_text("SQLite is dedicated to the public domain. See https://www.sqlite.org/copyright.html\n", encoding="utf-8")


def documentation(relative: str, tag: str) -> str:
    """Render package-only source links while preserving navigation between included guides.

    Repository Markdown keeps relative links. Targets outside DOCUMENTS refer to the exact source tag in a binary package; the source files are never
    rewritten. Reject missing or escaping local targets before publishing a package with broken navigation.
    """
    source = ROOT / relative

    def link(match: re.Match[str]) -> str:
        """Resolve a local target against its source guide, retaining its query and fragment."""
        target = urlsplit(match[2])
        if target.scheme or target.netloc or not target.path:
            return match[0]
        path = (source.parent / unquote(target.path)).resolve()
        try:
            name = path.relative_to(ROOT).as_posix()
        except ValueError as error:
            raise RuntimeError("Documentation target escapes source: " + match[2]) from error
        if not path.exists():
            raise RuntimeError("Missing documentation target: " + name)
        if name in DOCUMENTS:
            return match[0]
        kind = "tree" if path.is_dir() else "blob"
        url = "https://github.com/eosforge/astra/" + kind + "/" + quote(tag, safe="") + "/" + quote(name, safe="/")
        if target.query:
            url += "?" + target.query
        if target.fragment:
            url += "#" + target.fragment
        return match[1] + url + match[3]

    return re.sub(r"(?<!!)(\[[^\]]+\]\()([^\s)]+)(\))", link, source.read_text(encoding="utf-8"))


def package(tag: str) -> None:
    """Validate tag identity, install, inspect native linkage and emit auditable assets."""
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise RuntimeError("Expected a stable vMAJOR.MINOR.PATCH source tag")
    commit = run("git", "rev-parse", "HEAD").strip()
    if run("git", "rev-parse", "refs/tags/" + tag + "^{commit}").strip() != commit:
        raise RuntimeError("Checkout differs from the requested source tag")
    module_tag = "comet/go/" + tag
    if run("git", "rev-parse", "refs/tags/" + module_tag + "^{commit}").strip() != commit:
        raise RuntimeError("Go module tag differs from the requested source tag")
    name = "astra-" + tag[1:] + "-linux-x86_64"
    stage = CACHE / "package" / name
    if stage.exists():
        raise RuntimeError("Package staging directory already exists; preserve it for inspection")
    print(run("cmake", "--install", OUTPUT, "--prefix", stage, env=environment()), flush=True)
    for service in ("polaris", "astrolabe"):
        shutil.copy2(OUTPUT / service, stage / "bin" / service)
    # Keep included guides navigable offline and point omitted source targets at this exact tag.
    for relative in DOCUMENTS:
        destination = stage / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.suffix == ".md":
            destination.write_text(documentation(relative, tag), encoding="utf-8", newline="\n")
        else:
            shutil.copy2(ROOT / relative, destination)
    licenses(stage)
    linkage = {}
    clean = dict(os.environ)
    clean.pop("LD_LIBRARY_PATH", None)
    for service in SERVICES:
        path = stage / "bin" / service
        details = run("ldd", path, env=clean)
        print(details, flush=True)
        if "not found" in details:
            raise RuntimeError("Unresolved installed dependency: " + service)
        for line in details.splitlines():
            fields = line.split()
            if fields and fields[0] in ("libstdc++.so.6", "libgcc_s.so.1"):
                if len(fields) < 3 or fields[1] != "=>":
                    raise RuntimeError("Unexpected compiler runtime linkage: " + line)
                # The loader may retain bin/../lib; compare actual files rather than path spellings.
                expected = (stage / "lib" / fields[0]).resolve(strict=True)
                if Path(fields[2]).resolve(strict=True) != expected:
                    raise RuntimeError("Compiler runtime outside package for " + service + ": " + line)
        linkage[service] = details.replace(str(stage), "$PACKAGE")
    files = {str(p.relative_to(stage)): digest(p) for p in sorted(stage.rglob("*")) if p.is_file()}
    receipt = {
        "tag": tag,
        "go_module_tag": module_tag,
        "commit": commit,
        "platform": "linux-x86_64",
        "gcc": run(COMPILER / "bin/g++", "-dumpfullversion").strip(),
        "go": run(GO, "version").strip(),
        "libc": run("getconf", "GNU_LIBC_VERSION").strip(),
        "os_release": Path("/etc/os-release").read_text(),
        "files": files,
        "linkage": linkage,
        "validation": "Compilation and installed linkage inspection only; no product services or tests were run.",
    }
    artifacts = CACHE / "release"
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "build-manifest.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    epoch = run("git", "show", "-s", "--format=%ct", "HEAD").strip()
    archive = artifacts / (name + ".tar.gz")
    print(run("tar", "--sort=name", "--mtime=@" + epoch, "--owner=0", "--group=0", "--numeric-owner", "-czf", archive, "-C", stage.parent, name), flush=True)
    (artifacts / "SHA256SUMS").write_text(
        "".join(digest(path) + "  " + path.name + "\n" for path in (archive, artifacts / "build-manifest.json")), encoding="utf-8"
    )


def main() -> None:
    """Dispatch only the explicitly selected release phase."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "build", "package"))
    parser.add_argument("--tag", default=os.environ.get("RELEASE_TAG", ""))
    options = parser.parse_args()
    if options.phase == "prepare":
        prepare()
    elif options.phase == "build":
        build()
    else:
        package(options.tag)


if __name__ == "__main__":
    main()
