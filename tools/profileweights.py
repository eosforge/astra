"""Keep native compiler statement counts separate from fixed, source-bound coverage obligations."""

from pathlib import Path

from tools import verify as v

FIXTURE = "tests/fixtures/polarisweights.json"
MODEL = "3d52fa2efa10283637cfe2977095ee7475b1cc0e08ddbe2bbeb744dd755e1331"
STORAGE_FIXTURE = "tests/fixtures/storageweights.json"
STORAGE_MODEL = "17e906f805642ed13cd5ec36f02e31ac174f1a65b1fd91e3c92fca04f414f87b"
ADMISSION_FIXTURE = "tests/fixtures/admissionweights.json"
ADMISSION_MODEL = "9be0574495702bbea6d795477f93a9c6ca03bf2e5a00442483a3d734ac7b1b8b"


def reconcile(root: Path, package: str, blocks: list[dict]) -> dict:
    """Require the complete compiler-specific shape before projecting unchanged block obligations."""
    fixture, identity = (
        (STORAGE_FIXTURE, STORAGE_MODEL)
        if package == "polaris/internal/storage"
        else (ADMISSION_FIXTURE, ADMISSION_MODEL) if package == "internal/admission" else (FIXTURE, MODEL)
    )
    raw = v.read(root / fixture)
    if v.digest(raw) != identity:
        v.reject("profile-weights-model")
    model = v.decode(raw)
    if package not in model["packages"] or model["version"] != 1:
        v.reject("profile-weights-package")
    expected = model["packages"][package]
    names = {row["file"] for row in expected["blocks"]}
    if any(v.file_digest(root / name) != model["source_sha256"][name] for name in names):
        v.reject("profile-weights-source")
    shape = [{key: row[key] for key in ("file", "span", "statements")} for row in blocks]
    if v.digest(v.encode(shape)) != expected["shape_sha256"]["1.27.2"] or len(blocks) != len(expected["blocks"]):
        v.reject("profile-weights-geometry")
    native_raw = native_hit = legacy_raw = legacy_hit = 0
    for observed, fixed in zip(blocks, expected["blocks"], strict=True):
        if observed["file"] != fixed["file"] or observed["span"] != fixed["span"] or observed["statements"] != fixed["current"]:
            v.reject("profile-weights-block")
        native_raw += observed["statements"]
        legacy_raw += fixed["legacy"]
        if observed["count"]:
            native_hit += observed["statements"]
            legacy_hit += fixed["legacy"]
    return {
        "compiler": "1.27.2",
        "model_sha256": identity,
        "blocks": len(blocks),
        "native": {"statements": native_raw, "statements_hit": native_hit},
        "obligations": {"statements": legacy_raw, "statements_hit": legacy_hit},
        "shape_sha256": expected["shape_sha256"],
        "basis": "Native counts retain Go 1.27.2 weights. Fixed obligations retain their original weights on every identical source block; only actual current counters supply hits. This projection changes no required block, exclusion, MC/DC condition or policy threshold.",
    }
