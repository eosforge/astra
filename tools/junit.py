"""Transport complete native JUnit bytes within fixed log limits, with bounded lossless expansion."""

import base64
import binascii
import xml.etree.ElementTree as ET
import zlib

from tools import verify as v

# Each native case retains its existing 32 MiB limit; the decoded suite has a separate finite ceiling.
CASE = 32 * 1024**2
SUITE = 128 * 1024**2


def xml(data: bytes, expected: list[str], maximum: int, *, exact: bool = True) -> ET.Element:
    """Reject oversized, escaped or foreign XML before trusting any native assertion observations."""
    if not data or len(data) > maximum or b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        v.reject("ctest-xml-budget-or-entity")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        v.reject("ctest-xml", str(error))
    if root.tag != "testsuite" or any(case.tag != "testcase" for case in root):
        v.reject("ctest-xml-root-or-case")
    names = [case.get("name") for case in root]
    if len(set(names)) != len(names) or any(not name for name in names) or exact and (len(names) != len(expected) or set(names) != set(expected)):
        v.reject("ctest-case-selection")
    for case in root:
        if len(ET.tostring(case, encoding="utf-8")) > CASE:
            v.reject("ctest-case-budget")
    return root


def payload(data: bytes, expected: list[str]) -> dict:
    """Compress original native bytes, never translating or dropping testcase output."""
    xml(data, expected, min(SUITE, CASE * len(expected)))
    return {
        "format": "ctest-zlib-v1",
        "bytes": len(data),
        "sha256": v.digest(data),
        "cases": len(expected),
        "data": base64.b64encode(zlib.compress(data)).decode("ascii"),
    }


def decode(value: object, expected: list[str], log_bytes: int, *, exact: bool = True) -> ET.Element:
    """Bind native byte count, digest and complete case selection while rejecting bombs and trailing data."""
    if isinstance(value, str):
        return xml(value.encode("utf-8"), expected, CASE, exact=exact)
    if (
        not isinstance(value, dict)
        or set(value) != {"format", "bytes", "sha256", "cases", "data"}
        or value["format"] != "ctest-zlib-v1"
        or type(value["bytes"]) is not int
        or not 0 < value["bytes"] <= min(SUITE, CASE * len(expected))
        or type(value["cases"]) is not int
        or not 0 < value["cases"] <= len(expected)
        or exact
        and value["cases"] != len(expected)
        or not isinstance(value["data"], str)
        or len(value["data"]) > log_bytes
        or not isinstance(value["sha256"], str)
    ):
        v.reject("ctest-payload-shape")
    try:
        packed = base64.b64decode(value["data"], validate=True)
        stream = zlib.decompressobj()
        data = stream.decompress(packed, value["bytes"] + 1)
    except (ValueError, binascii.Error, zlib.error) as error:
        v.reject("ctest-payload-codec", str(error))
    if not stream.eof or stream.unused_data or stream.unconsumed_tail or len(data) != value["bytes"] or v.digest(data) != value["sha256"]:
        v.reject("ctest-payload-integrity")
    root = xml(data, expected, min(SUITE, CASE * len(expected)), exact=exact)
    if len(root) != value["cases"]:
        v.reject("ctest-payload-case-count")
    return root


def document(data: bytes, check: dict) -> ET.Element:
    """Select exactly one complete native envelope from an immutable process stream."""
    rows = [line[len(b"ASTRA-CTEST ") :] for line in data.splitlines() if line.startswith(b"ASTRA-CTEST ")]
    if len(rows) != 1:
        v.reject("ctest-payload-count")
    return decode(v.decode(rows[0], maximum=check["log_bytes"]), check["expected_tests"], check["log_bytes"])


def cases(root: ET.Element) -> dict:
    """Apply the original assertion/status reader independently to every bounded native testcase."""
    from tools.observe import ctest_cases

    result = {}
    for case in root:
        one = ET.Element("testsuite")
        one.append(case)
        observed = ctest_cases(ET.tostring(one, encoding="utf-8"))
        if set(result) & set(observed):
            v.reject("ctest-case-duplicate")
        result.update(observed)
    return result
