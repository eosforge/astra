"""Reconcile sealed Astrolabe diagnostics without compiling or executing the application."""

from pathlib import Path, PurePosixPath
import base64
import json
import tempfile

from tools import authority, entry, flow, logic, predicates, statements, structure, verify as v

# Each archive fixes original commands, test inputs and native output, not an asserted report.
ARCHIVES = {
    "astrolabe-structure": "fb977284214717f2124e8180f3708d7047807a9e7ece7677d8aea1ce63e3ba9f",
    "astrolabe-structure/supplement": "590d1098e195bf44878449c8d83533a30a894984bed8cf8abe532128d27236f1",
    "astrolabe-structure/process": "b24f1362b32dc89d07ad5326e2fce9ed5a8bd89df757eb57266649645f398e6a",
    "astrolabe-structure/faults": "9eb158e1bb6377e0a4e226b4b745fef86ac95d41e30da31fb8aaa6fa28b807e9",
    "material-stop": "7e3ae1d81bb7d936e7bab7b66275ff7b725d95b363e20e90e978eee8507e0363",
    "material-account": "d780647dd4927351d759741cd0205ff82c18325ee850862b03fb36359d9516de",
    "material-boundaries-2": "eae3c52cc52148ceda39a8a717081ffdae9d4a84e7908506b35a0f5f921d115b",
    "admission-structure": "e2e7c5a6d4e30f7be9575bd73a9e47e90608fb865674b22ca93e07c91710da94",
    "material-isolation": "0e6e7a0ca3babfa2ca0a2252167d223abf09cf6504b6f8a15c2dc2b57ba5394d",
    "material-endpoints-2": "874ced35b623f128caa1585577dce89bc232c1c13fb308b222c9c2b24e4413de",
    "material-endpoints-3": "e1c95bdf28526808cb1e497449de1893dfc4cc8a9cd2989ffb7eb3ec1479c35f",
    "material-epoch": "dccb0fb26a49aca5fb368e6dd646866d333fdf3cfffe7b0fe8e2fe2e4c0d5792",
}
MODULE = "github.com/eosforge/astra/"
ACCOUNT = "astrolabe/internal/web/account.go"
GO = "30969f97169d7f43fe6a085873d75613adc21e30818a8c61d95bd27275df4624"
EXTRA = "46a01ca5ba7f598c125abcd26d784932156eaf32de9a0e9e015011098864a983"
DEPENDENCIES = "61380f0fa73ddf911f7a0960b40bb8c8e4cb82af3cd1ada4dac570c29e068503"
LIBRARY_ARCHIVE = "677547dc4df45c52aa1df2c9e1150be74ccb545638a2588f67eae4f71dcf4902"
LIBRARIES = "c236815e8e77891b33e62869c369b178ab050a5d87c8cafdb6918d773615c470"
PACKAGES = ("astrolabe", "astrolabe/internal/bridge", "astrolabe/internal/web")
FORESTS = (
    "91e3111b345c9dd44049193431139c2bd2288e6a172cc9c6cda01ae6dbe712ea",
    "8f691def0f4263b20a09dcdef864be51d969d7e3a1eab6fd1d3e9cab61e14245",
    "889b20bdd78f0a4c5f0e69467ee79fdd9b42ffe0c712485d6b764685ca015c1c",
)
PROCESS = "53f077319f62613f6c1e99a9848699ce4068e3e1de264ee604b9b1edb1c0e30a"
MEMBERS = {
    "internal/admission/identity.go": "d172cc85f0e6a6099699b0c4a3cea3813cbf5e7e04d7be23ffca464be56ea09b",
    "internal/admission/directory.go": "935437c56a04d51978c2d2508b0c09b8f1dc51f03e58a6af089f926858ec068b",
}
STARTUP = {
    "astrolabe/main.go": "65714bc8a0275fc231cc5f94befbb7bf742f5fa067a45d4a5edc2d887ad21680",
    "astrolabe/internal/bridge/metrics.go": "e9268cd0982707a1c5d4772dcca771aefbe51fc486a3ad446691806b02eb9358",
    "astrolabe/internal/web/account.go": "cfa8821c360ba4a4dc123d3ab781b0485cb3e102dd78482cc085aa42ae838514",
    "astrolabe/internal/web/server.go": "5dbd6e4eb4a185664e759b466bd8d78609fd7ad1afa21f19bbe8c397d7740446",
    "internal/admission/node.go": "375da6dfab3ad7e58f8314e339c271e4ab3a8b50050a53cec765b2980249148c",
    **MEMBERS,
}
EXITS = {
    "help": (0, 0, 0),
    "usage": (2, 0, 0),
    "startup": (1, 0, 0),
    "refusal": (1, 0, 1),
    "terminate": (0, 15, 1),
    "interrupt": (0, 2, 1),
    "pending": (0, 15, 1),
}
# Package-qualified test names keep equal names in different packages distinct.
TESTS = "54450be9a21816b89e2dd0700043e30d0652091f6f8e92719de4bf4a061636f4"
# Current-source Race counters are independent of the older typed/control campaigns.
BASELINE = "f2dcea7cb9821aba7a0fd91583d4f1051efc56fe17173563a855f40ceb335ddc"
STATEMENTS = "0335de2bedec3cacdd46d2f6047983a8977bb35f44e1cffb30012a0611e750d3"
UNHIT = (
    ("fixed-channel-options", "astrolabe/internal/bridge/backend.go", (96, 3, 98, 1), 2),
    ("nonempty-fields", "astrolabe/internal/bridge/metrics.go", (110, 4, 110, 12), 1),
    ("validated-raw-array", ACCOUNT, (62, 5, 63, 1), 1),
    ("fresh-bytes-message", "astrolabe/internal/web/credentials.go", (61, 4, 63, 1), 2),
    ("entropy-return", "astrolabe/internal/web/session.go", (28, 4, 29, 1), 1),
)
GEOMETRY = {
    "astrolabe": (21, 38, 37, 0, 1, 7),
    "astrolabe/internal/bridge": (62, 102, 90, 7, 5, 22),
    "astrolabe/internal/web": (101, 226, 207, 11, 8, 44),
}

# These conditional source arguments are exclusions, never execution or independence hits.
DEFENSES = (
    (
        "fixed-channel-options",
        (("astrolabe/internal/bridge/backend.go:4689", 0, True),),
        ("grpc/clientconn.go:183", "grpc/clientconn.go:480", "grpc/clientconn.go:1821", "grpc/clientconn.go:1940", "grpc/dialoptions.go:719"),
        "Validated canonical numeric endpoints form a valid explicit passthrough target. The linked resolver is registered, TLS credentials are nonnil, and no bundle, default service config or conflicting authority is supplied. NewClient performs no network I/O; its returned-error guards are false.",
        "Changed admission validation, constructor/global options, resolver registration, unsupported runtime patching or memory corruption. Later network failures remain reachable.",
    ),
    (
        "nonempty-fields",
        (("astrolabe/internal/bridge/metrics.go:4891", 0, True),),
        ("go/strings/strings.go:365", "go/strings/strings.go:1089", "go/unicode/graphic.go:128"),
        "TrimSpace and Fields use the same ASCII/Unicode whitespace predicate. After the preceding empty-line guard, the immutable local string contains a non-whitespace rune; Fields cannot be empty.",
        "Changed whitespace implementation, removed preceding guard or unsafe mutation of the local string.",
    ),
    (
        "validated-raw-array",
        ((ACCOUNT + ":1943", 0, True),),
        (
            "go/encoding/json/v2_stream.go:74",
            "go/encoding/json/v2_decode.go:110",
            "go/encoding/json/jsontext/value.go:244",
            "go/encoding/json/v2/arshal_default.go:1465",
        ),
        "Decoder validates and privately copies a complete RawMessage. A value beginning with [ is an array; decoding the same bytes with the same V1 options into []RawMessage has no element type restriction or greater nesting depth. RawMessage copies every valid value.",
        "Changed JSON implementation/options, target type, byte ownership or call order. Fatal allocation failure is not a returned JSON error.",
    ),
    (
        "fresh-bytes-message",
        (("astrolabe/internal/web/credentials.go:2514", 0, True),),
        (
            "protobuf/proto/encode.go:174",
            "protobuf/internal/impl/encode.go:148",
            "protobuf/internal/impl/codec_gen.go:5477",
            "internal/generated/orbit/orbit.pb.go:171",
        ),
        "A fresh generated proto3 Credential has only an optional bytes field of length 1..4096, with no required fields, unknown bytes, nested messages or custom marshaler. The pinned bytes encoder returns nil. Clearing the secret occurs only after Marshal returns.",
        "Changed schema, descriptor, encoder/options, aliasing or memory safety. Fatal allocation failure is not a recoverable encoding error.",
    ),
    (
        "entropy-return",
        (("astrolabe/internal/web/session.go:1254", 0, True),),
        ("go/crypto/rand/rand.go:63",),
        "The pinned crypto/rand.Read fills the buffer and returns nil, or fatally terminates on entropy failure, including an error from a substituted Reader.",
        "Changed random implementation or unsupported runtime patching. Entropy failure is not claimed recoverable.",
    ),
    (
        "object-key",
        (("astrolabe/internal/bridge/metrics.go:1900", 1, False), (ACCOUNT + ":1519", 1, False)),
        ("go/encoding/json/v2_stream.go:220", "go/encoding/json/v2_stream.go:272", "go/encoding/json/jsontext/state.go:268"),
        "The decoder owns an open object and has consumed each prior complete value. More admits another key only before the object closes. At a key position jsontext rejects literal, number and opening-container tokens; successful Token therefore returns a string. An earlier token error short-circuits the type predicate and supplies no false type hit.",
        "Changed decoder state/options, token/value sequencing, private byte ownership, JSON implementation or memory safety.",
    ),
    (
        "object-close",
        (("astrolabe/internal/bridge/metrics.go:2776", 1, True), (ACCOUNT + ":2199", 1, True)),
        ("go/encoding/json/v2_stream.go:272", "go/encoding/json/jsontext/decode.go:632", "go/encoding/json/jsontext/state.go:318"),
        "After complete key/value pairs, More ends at a closing delimiter or EOF. ReadToken rejects an array close while the object is open; EOF/error short-circuits the comparison. A successful final token must be the object's } delimiter.",
        "Changed More/Token behavior, object stack, call order, byte ownership or memory safety. Malformed/truncated input still returns an error.",
    ),
    (
        "nonempty-raw",
        ((ACCOUNT + ":1648", 1, True),),
        ("go/encoding/json/v2_stream.go:74", "go/encoding/json/jsontext/decode.go:729", "go/encoding/json/jsontext/value.go:244"),
        "Successful Decode first reads one complete JSON value and copies it into the private RawMessage. Every valid value has nonzero encoded length, including null; an empty or whitespace-only input fails before the length predicate is evaluated.",
        "Changed decoder or RawMessage implementation, target type, input ownership, call order or memory safety.",
    ),
)


def variants(identity: str, before: tuple[bool, ...], reference: str, cases: dict[int, str]) -> tuple:
    """Expand reviewed literal-input cases that change exactly one total predicate."""
    return tuple(
        (identity, target, before, tuple(not value if index == target else value for index, value in enumerate(before)), (reference, test))
        for target, test in cases.items()
    )


# These fixed literal fixtures vary total input predicates. Skipped predicates
# remain source-defined values, never additional runtime observations. Malformed
# decimal input changes several predicates and is not a ParseUint-error pair.
PAIRS = (
    # Zero expiry is a valid explicit logical time; absence alone changes admission.
    *variants("session.go:2550", (True, True), "TestSessionEpoch/present", {0: "TestSessionEpoch/missing"}),
    # Literal endpoint cases keep the unrelated deployment and payload predicates fixed.
    *variants(
        "main.go:3778",
        (False, False, True, True, False, False, False, False, True, True, False, False, True, False),
        "TestPublicOrigin/valid",
        {0: "TestPublicOrigin/invalid"},
    ),
    *variants("main.go:8049", (False, False), "TestLifecycle/refusal", {1: "TestServingStop"}),
    *variants("almanac.go:1842", (False, True, False, False, False), "TestQuerySize/valid", {2: "TestQuerySize/extra"}),
    *variants("server.go:11604", (False, False), "TestMediaSuffix/valid", {0: "TestMediaSuffix/invalid"}),
    *variants("session.go:3816", (False, False), "TestCookies/lax", {0: "TestCookies/empty"}),
    # Unknown trailing fields preserve the preceding successfully decoded scalar fields.
    *variants("account.go:4074", (False, True), "TestAccountSuffix/valid", {0: "TestAccountSuffix/unknown"}),
    *variants("almanac.go:3306", (False, True, True), "TestCommit", {0: "TestInputField/almanac-unknown"}),
    *variants("server.go:9209", (False, False, False, False, False), "TestSessionAdmission/capacity", {0: "TestSessionInput/unknown"}),
    # Complete decoded prefixes keep length predicates fixed on malformed suffixes.
    *variants("account.go:4338", (False, False, False, False), "TestAccountSuffix/valid", {0: "TestAccountSuffix/salt", 1: "TestAccountSuffix/hash"}),
    *variants("credentials.go:2293", (False, False, False), "TestCredentials", {0: "TestInputField/credential-suffix"}),
    *variants("almanac.go:10756", (True, False, False, False), "TestSnapshotScope/credential", {1: "TestSnapshotScope/suffix"}),
    *variants(
        "almanac.go:10756", (True, False, False, False), "TestCredentialRead", {0: "TestLoadFailures/credential-key", 2: "TestLoadFailures/credential-empty"}
    ),
    *variants("almanac.go:3531", (True, False, False, False, False, False), "TestBatchCommit", {2: "TestInputField/batch-key"}),
    *variants("almanac.go:10641", (True, True), "TestSnapshotScope/credential", {0: "TestSnapshotScope/sector", 1: "TestSnapshotScope/spectrum"}),
    # Empty requests have no unary change; the retained successful batch also has none.
    *variants("backend.go:7142", (False, False, False), "TestTransport", {1: "TestEmptyCommit"}),
    *variants("metrics.go:9008", (False, False), "TestMappedRole/ROLE_STAR", {0: "TestMappedRole/ROLE_POLARIS"}),
    *variants("metrics.go:11012", (False, False, False), "TestCachedFailure/fresh", {0: "TestCachedFailure/failed"}),
    # The unrelated allowlist name is compared before or after matching items.
    *variants("account.go:1832", (False, False), "TestArrayNames/last", {0: "TestArrayNames/first"}),
    *variants("server.go:5924", (True, False, True, True, True), "TestHeadOrigin/HEAD", {1: "TestHeadOrigin/POST"}),
    # Retained callbacks distinguish cancellation from a real admission refusal.
    ("main.go:8049", 0, (False, False), (True, False), ("TestLifecycle/refusal", "TestStopResult")),
    # Duplicate keys retain the same token kind and a dictionary below its field limit.
    *variants("account.go:1519", (False, True, False, False), "TestObject/scalar-fields", {2: "TestObject/duplicate"}),
    # ParseQuery discards the malformed x=%ZZ pair; its remaining map is empty.
    *variants("almanac.go:1842", (False, False, True, True, True), "TestInventory/valid", {0: "TestSnapshot"}),
    *variants("almanac.go:1842", (False, True, False, False, False), "TestSnapshot", {3: "TestSnapshot"}),
    # The erase-only and dual-action inputs both retain a nonnil true erase flag.
    *variants("almanac.go:3980", (True, False, False, True, True), "TestBatchCommit", {2: "TestCommit"}),
    # Version getters are nil-safe: nil and explicit zero both compare equal to the initial local zero.
    *variants("almanac.go:9744", (False, False, True, True, False, False, False, False, True, False), "TestLoadFailures/zero", {4: "TestLoadFailures/version"}),
    # These are second callbacks: both have started, matching versions and empty completion pages.
    *variants(
        "almanac.go:9744",
        (False, False, True, True, False, False, True, False, True, True),
        "TestSnapshot",
        {5: "TestLoadFailures/after-complete", 7: "TestSnapshot"},
    ),
    # The first after-complete page and the empty refusal have identical headers and no entries.
    *variants(
        "almanac.go:9744", (False, False, True, True, False, False, False, True, True, True), "TestLoadFailures/after-complete", {8: "TestLoadFailures/empty"}
    ),
    ("almanac.go:3306", 1, (False, True, True), (False, False, True), ("TestRefusal/sector-empty",)),
    ("almanac.go:3306", 2, (False, True, True), (False, True, False), ("TestRefusal/spectrum-empty",)),
    ("almanac.go:2225", 1, (True, True), (True, False), ("TestSnapshot", "TestRefusal/query-spectrum-empty")),
    ("almanac.go:3531", 1, (True, False, False, False, False, False), (True, True, False, False, False, False), ("TestBatchCommit",)),
    ("almanac.go:3531", 3, (True, False, False, False, False, False), (True, False, False, True, False, False), ("TestBatchCommit", "TestRefusal/batch-value")),
    ("almanac.go:3531", 4, (True, False, False, False, False, False), (True, False, False, False, True, False), ("TestBatchCommit", "TestRefusal/batch-erase")),
    ("almanac.go:3531", 5, (True, False, False, False, False, False), (True, False, False, False, False, True), ("TestBatchCommit",)),
    ("almanac.go:4802", 1, (False, False, False), (False, True, False), ("TestRefusal/version-zero",)),
    ("credentials.go:1872", 1, (False, False, False), (False, True, False), ("TestCredentials", "TestRefusal/credential-version-zero")),
    ("credentials.go:2293", 2, (False, False, False), (False, False, True), ("TestCredentials", "TestRefusal/credential-secret-overflow")),
    ("backend.go:10433", 0, (False, False), (True, False), ("TestObservation",)),
    ("backend.go:10685", 0, (False, False), (True, False), ("TestObservation",)),
    ("metrics.go:11012", 1, (False, False, False), (False, True, False), ("TestClosedView",)),
    # Fixed deployment fields are total even when an earlier validation short-circuits.
    *variants(
        "main.go:3778",
        (False, False, True, True, False, False, False, False, False, True, False, True, False, True),
        "TestOptions/minimum",
        {
            1: "TestOptions/positional",
            2: "TestOptions/galaxy",
            3: "TestOptions/group",
            4: "TestOptions/identity",
            5: "TestOptions/account",
            6: "TestOptions/below",
            7: "TestOptions/above",
        },
    ),
    *variants(
        "main.go:3778",
        (False, False, True, True, False, False, False, False, True, True, False, False, True, False),
        "TestOptions/plain",
        {10: "TestOptions/plain-crosssite"},
    ),
    *variants("main.go:4507", (False, False, False), "TestOptions/origins-limit", {0: "TestOptions/origins-empty", 1: "TestOptions/origins-duplicate"}),
    # Successful URL parsing retains all other decoded fields; parser errors are not projected as valid URLs.
    *variants(
        "metrics.go:2221",
        (False, True, False, False, False, False, False, False, False, False),
        "TestTargets/valid",
        {
            2: "TestTargets/scheme",
            3: "TestTargets/path",
            4: "TestTargets/escaped",
            5: "TestTargets/query",
            6: "TestTargets/empty-query",
            7: "TestTargets/fragment",
            8: "TestTargets/user",
        },
    ),
    *variants("metrics.go:2221", (False, False, True, False, False, False, False, False, False, False), "TestMetricTargets", {1: "TestTargets/scheme"}),
    *variants("metrics.go:4792", (False, False), "TestMetricValues/valid", {0: "TestMetricValues/comments"}),
    *variants("metrics.go:5285", (False, False, True, False), "TestMetricValues/valid", {1: "TestMetricValues/binary"}),
    *variants("metrics.go:5285", (False, True, False, False), "TestMetricValues/valid", {2: "TestMetricValues/binary"}),
    *variants("metrics.go:9826", (False, False, False), "TestScrape/valid", {0: "TestScrape/status", 1: "TestScrape/duplicate"}),
    # Nullable constructor arguments are tested only by equality; neither side dereferences them.
    *variants(
        "server.go:3783",
        (False, False, False, False, False, False, False, True),
        "TestVerification",
        {0: "TestVerification", 1: "TestVerification", 5: "TestOriginLimit/33"},
    ),
    # The duplicate-origin case reaches this guard with Secure=false and fails only in the subsequent loop.
    *variants(
        "server.go:3783",
        (False, False, False, False, False, False, False, False),
        "TestVerification",
        {2: "TestVerification", 3: "TestVerification", 4: "TestVerification", 6: "TestVerification"},
    ),
    *variants(
        "server.go:7763",
        (True, True, True, True, False),
        "TestPreflight/unknown-method",
        {1: "TestPreflight/get", 2: "TestPreflight/post", 3: "TestPreflight/delete"},
    ),
    *variants("server.go:8221", (True, True, True), "TestPreflight/header", {0: "TestPreflight/empty-fields", 1: "TestPreflight/post"}),
    *variants(
        "server.go:9209",
        (False, False, False, False, False),
        "TestLogin",
        {1: "TestSessionInput/username-empty", 2: "TestSessionInput/username-overflow", 3: "TestSessionInput/password-empty"},
    ),
    *variants("account.go:4338", (False, False, False, False), "TestAccountFile/valid", {2: "TestAccountFile/salt-short"}),
    *variants("almanac.go:6492", (False, False, True, True, False), "TestReceipt/valid", {2: "TestReceipt/sector", 3: "TestReceipt/spectrum"}),
    # Selection and pagination fixtures keep the backend open and vary one local predicate.
    *variants("backend.go:4062", (False, False), "TestSelection", {0: "TestSelection"}),
    *variants("backend.go:7618", (False, True), "TestTransport/large-total", {0: "TestTransport/large-total"}),
    # Parsing/framing failures preserve the complete preceding sample or a bounded response body.
    *variants("metrics.go:4998", (False, False), "TestMetricValues/valid", {0: "TestMetricValues/columns"}),
    *variants("metrics.go:5535", (False, False), "TestMetricValues/valid", {0: "TestMetricValues/scanner"}),
    *variants("metrics.go:10183", (False, False), "TestScrape/valid", {0: "TestScrape/truncated"}),
    *variants("metrics.go:8144", (True, False), "TestMetricFreshness", {0: "TestMetricReplacement"}),
    # Owned handle fixtures verify successful stat/identity, physical close and healthy recovery separately.
    *variants("account.go:3594", (False, True, True), "TestAccountMetadata", {1: "TestAccountMetadata"}),
    *variants("account.go:3871", (False, False, False), "TestAccountAcquisition/read", {0: "TestAccountAcquisition/read"}),
    *variants("account.go:3871", (False, False, False), "TestAccountAcquisition/close", {1: "TestAccountAcquisition/close"}),
    *variants("account.go:4912", (True, True, True), "TestAccount", {1: "TestAccount"}),
    # Literal text and decoded bytes have total predicates even when an earlier validation rejects them.
    *variants(
        "almanac.go:765", (True, True, True, False), "TestSnapshot", {0: "TestRefusal/key-empty", 1: "TestRefusal/query-spectrum-overflow", 2: "TestSnapshot"}
    ),
    *variants("almanac.go:2225", (True, True), "TestSnapshot", {0: "TestSnapshot"}),
    *variants("almanac.go:4369", (False, False), "TestValueBoundary/single/byte", {0: "TestValueBoundary/single/encoding"}),
    *variants("almanac.go:7416", (False, True, False), "TestInventory/valid", {1: "TestInventory/incomplete"}),
    *variants("almanac.go:7841", (False, False, True, True, False), "TestInventory/valid", {2: "TestInventory/sector", 3: "TestInventory/spectrum"}),
    # First-page fixtures retain nonnil scope/version/value objects; no skipped nil dereference is assigned a value.
    *variants(
        "almanac.go:9744",
        (False, False, True, True, False, False, False, True, True, False),
        "TestLoadFailures/disconnected",
        {2: "TestLoadFailures/sector", 3: "TestLoadFailures/spectrum"},
    ),
    *variants("almanac.go:10202", (False, True, False, False), "TestLoadFailures/disconnected", {1: "TestLoadFailures/key"}),
    *variants("almanac.go:10202", (False, True, False, False), "TestLoadFailures/duplicate", {2: "TestLoadFailures/duplicate"}),
    *variants("almanac.go:10373", (True, False, False, False), "TestLoadFailures/disconnected", {2: "TestLoadFailures/value"}),
    *variants("almanac.go:11485", (False, True, True), "TestSnapshot", {0: "TestLoadFailures/late-error"}),
    *variants("almanac.go:11569", (False, False), "TestLoadFailures/late-error", {0: "TestLoadFailures/missing-complete"}),
    # Successfully parsed origins retain all URL fields. Parse errors and opaque URLs need separate domain arguments.
    *variants(
        "server.go:2265",
        (False, False, True, False, False, False, False, False, False, False),
        "TestVerification",
        {
            1: "TestVerification",
            3: "TestVerification",
            4: "TestVerification",
            5: "TestVerification",
            7: "TestVerification",
            8: "TestVerification",
            6: "TestOrigin",
        },
    ),
    *variants("server.go:2265", (False, True, False, False, False, False, False, False, False, False), "TestVerification", {2: "TestVerification"}),
    *variants("server.go:2683", (False, False), "TestVerification", {0: "TestVerification"}),
    *variants("server.go:2931", (False, False, False), "TestVerification", {1: "TestVerification"}),
    *variants("server.go:3110", (True, False, False, False), "TestRouting/nodes", {1: "TestVerification"}),
    *variants("server.go:4185", (False, False), "TestVerification", {0: "TestVerification"}),
    # HTTP method and header fixtures never mutate admission policy or consume a backend write.
    *variants("server.go:5559", (False, False), "TestRouting/no-origin", {0: "TestRouting/origin"}),
    *variants(
        "server.go:5924", (True, True, True, False, False), "TestRouting/session-method", {2: "TestRouting/write-origin", 3: "TestRouting/write-duplicate"}
    ),
    *variants("server.go:5924", (False, True, False, False, False), "TestRouting/no-origin", {0: "TestRouting/write-origin"}),
    *variants("server.go:7763", (True, False, True, True, False), "TestPreflight/get", {0: "TestPreflight/missing-origin"}),
    # Both creations use the same explicit timestamp, so expiry cannot masquerade as reclaimed capacity.
    *variants("session.go:1619", (False, False), "TestSessions", {0: "TestSessions"}),
    *variants("metrics.go:1251", (False, False), "TestTargets/valid", {0: "TestTargets/directory"}),
    *variants("metrics.go:1900", (False, True, False, False), "TestTargets/valid", {2: "TestTargets/value"}),
    *variants("almanac.go:3980", (True, False, False, True, True), "TestBatchCommit", {1: "TestBatchCommit"}),
    *variants("credentials.go:1477", (False, True, False, True, True), "TestCredentials", {2: "TestCredentials"}),
    *variants("credentials.go:2293", (False, False, False), "TestCredentials", {1: "TestCredentials"}),
)

# Only these reviewed inputs admit undefined fields. Nil-safe methods and skipped
# decoder side effects are still defined operations, not arbitrary null operands.
GUARDS = (
    (
        "credentials.go:1477",
        0,
        (False, True, False, False, None),
        (True, True, False, False, None),
        ("TestCredentials", "TestInputField/credential-unknown"),
        "The decoded key and secret precede the unknown field. Erase stays nil on both sides; its dereference is undefined and masked by the false nonnil test.",
    ),
    (
        "backend.go:3917",
        0,
        (True, True, True),
        (False, True, None),
        ("TestSelection",),
        "An initial backend has no target; the incoming authority remains present.",
    ),
    (
        "backend.go:3917",
        1,
        (True, True, True),
        (True, False, None),
        ("TestSelection",),
        "Ambiguity clears the selected member while the prior target is still present.",
    ),
    ("backend.go:6309", 1, (False, False, True), (False, True, None), ("TestSelection",), "Ambiguity removes the current target without closing the backend."),
    (
        "backend.go:7142",
        0,
        (False, False, False),
        (True, None, None),
        ("TestTransport/split", "TestCommitInput/nil"),
        "A nil request has neither Changes nor Change fields.",
    ),
    (
        "metrics.go:2221",
        0,
        (False, True, False, False, False, False, False, False, False, False),
        (True,) + (None,) * 9,
        ("TestTargets/valid", "TestTargets/url"),
        "Invalid URL syntax returns no parsed URL object.",
    ),
    (
        "server.go:2265",
        0,
        (False, False, True, False, False, False, False, False, False, False),
        (True,) + (None,) * 9,
        ("TestRouting/nodes", "TestRouting/origin-syntax"),
        "The rejected :// origin has no parsed URL object.",
    ),
    (
        "account.go:3337",
        0,
        (False, True),
        (True, None),
        ("TestAccountFile/valid", "TestAccountFile/missing"),
        "Lstat on the missing path returns nil FileInfo, with no Mode method result.",
    ),
    (
        "almanac.go:6492",
        0,
        (False, False, True, True, False),
        (True, None, None, None, None),
        ("TestReceipt/valid", "TestReceipt/nil"),
        "A nil receipt has neither Scope nor Version fields.",
    ),
    (
        "almanac.go:6492",
        1,
        (False, False, True, True, False),
        (False, True, None, None, False),
        ("TestReceipt/valid", "TestReceipt/scope"),
        "A missing receipt scope removes only its sector/spectrum fields; version stays seven.",
    ),
    (
        "almanac.go:7416",
        0,
        (False, True, False),
        (True, None, None),
        ("TestInventory/valid", "TestInventory/nil"),
        "A nil inventory has no completeness or position fields.",
    ),
    (
        "almanac.go:7841",
        0,
        (False, False, True, True, False),
        (True, None, None, None, None),
        ("TestInventory/valid", "TestInventory/entry"),
        "A nil position cannot supply a scope or the composite key used for duplicate detection.",
    ),
    (
        "almanac.go:7841",
        1,
        (False, False, True, True, False),
        (False, True, None, None, None),
        ("TestInventory/valid", "TestInventory/scope"),
        "A missing position scope has no sector/spectrum or composite duplicate key.",
    ),
    (
        "almanac.go:9744",
        0,
        (False, False, True, True, False, False, False, False, True, False),
        (True, None, None, None, None, False, False, False, None, None),
        ("TestLoadFailures/zero", "TestLoadFailures/nil"),
        "The zero-version first page passes this guard. GetVersion is nil-safe and returns zero on both inputs; local state remains unstarted/incomplete.",
    ),
    (
        "almanac.go:9744",
        1,
        (False, False, True, True, False, False, False, True, True, False),
        (False, True, None, None, False, False, False, True, True, False),
        ("TestLoadFailures/disconnected", "TestLoadFailures/scope"),
        "Only scope fields disappear; first-page version, completeness, entries and local state are unchanged.",
    ),
    (
        "almanac.go:10202",
        0,
        (False, True, False, False),
        (True, None, None, False),
        ("TestLoadFailures/disconnected", "TestLoadFailures/entry"),
        "A nil entry has no key; the empty seen map retains its defined size.",
    ),
    (
        "almanac.go:10373",
        1,
        (True, False, False, False),
        (True, True, None, False),
        ("TestLoadFailures/disconnected", "TestLoadFailures/nil-action"),
        "A typed nil value wrapper preserves successful type assertion and page version but has no payload field.",
    ),
    (
        "session.go:3293",
        0,
        (False, False),
        (True, None),
        ("TestRouting/nodes", "TestRouting/missing-session"),
        "Removing the sole cookie leaves an empty slice with no element zero.",
    ),
    (
        "almanac.go:3980",
        3,
        (True, False, False, True, False),
        (True, False, False, False, None),
        ("TestRefusal/erase-false",),
        "False erase versus healthy value action preserves the exclusive-action predicate; only the latter has no erase pointee.",
    ),
    (
        "credentials.go:1477",
        3,
        (False, True, False, True, False),
        (False, True, False, False, None),
        ("TestCredentials",),
        "False erase versus healthy secret input has the same exclusive-action shape but no erase pointee on the secret input.",
    ),
    (
        "almanac.go:3980",
        0,
        (True, False, False, False, None),
        (False, False, False, False, None),
        ("TestRefusal/key-empty",),
        "Only key validity changes; the value action has no erase pointee on either side.",
    ),
    (
        "credentials.go:1477",
        1,
        (False, True, False, False, None),
        (False, False, False, False, None),
        ("TestCredentials", "TestRefusal/credential-key-empty"),
        "Only key validity changes; secret inputs have no erase pointee on either side.",
    ),
)

# The other occurrence of plain/HTTPS changes too, but the fixed surrounding
# operands mask it on both sides. The common-cube checker must prove that fact.
MASKS = (
    # Changing scheme changes two predicates; the other port comparison masks the nontarget occurrence.
    ("server.go:3110", 0, (True, True, False, False), (False, True, True, False), ("TestOriginPort/https-443", "TestOriginPort/http-443")),
    ("server.go:3110", 2, (False, False, True, True), (True, False, False, True), ("TestOriginPort/http-80", "TestOriginPort/https-80")),
    # Both occurrences of plain change, but the later one is masked by a valid HTTPS origin.
    (
        "main.go:3778",
        8,
        (False, False, True, True, False, False, False, False, False, False, False, True, False, True),
        (False, False, True, True, False, False, False, False, True, False, False, True, True, True),
        ("TestRemote/tls", "TestRemote/plain"),
    ),
    (
        "almanac.go:1842",
        1,
        (False, False, True, True, True),
        (False, True, True, False, True),
        ("TestInventory/valid", "TestSnapshot"),
    ),
    (
        "almanac.go:3531",
        0,
        (False, True, True, True, False, False),
        (True, True, False, False, False, False),
        ("TestRefusal/version-zero", "TestBatchCommit"),
    ),
    (
        "almanac.go:9744",
        6,
        (False, False, True, True, False, False, False, True, True, False),
        (False, False, True, True, False, False, True, True, True, True),
        ("TestLoadFailures/disconnected", "TestLoadFailures/changed"),
    ),
    (
        "main.go:3778",
        9,
        (False, False, True, True, False, False, False, False, True, True, False, False, True, False),
        (False, False, True, True, False, False, False, False, True, False, False, True, True, True),
        ("TestOptions/plain", "TestOptions/remote-plain"),
    ),
    (
        "main.go:3778",
        11,
        (False, False, True, True, False, False, False, False, True, True, True, True, True, True),
        (False, False, True, True, False, False, False, False, True, True, True, False, True, False),
        ("TestOptions/secure-crosssite", "TestOptions/plain-crosssite"),
    ),
    (
        "main.go:3778",
        12,
        (False, False, True, True, False, False, False, False, True, True, False, False, True, False),
        (False, False, True, True, False, False, False, False, False, True, False, False, False, False),
        ("TestOptions/plain", "TestOptions/tls-public"),
    ),
)

# Each relation overapproximates source state, so proving no independent pair
# does not depend on enumerating the test suite or calling an absent field.
RELATIONS = (
    (
        "astrolabe/internal/web/almanac.go:10373",
        0,
        lambda x: x[0] or x[1],
        "TestLoadFailures/erase",
        "The checked assertion to *comet.Entry_Value returns a nil pointer when ok is false. The local pointer is not reassigned before the OR; its inaccessible Value field is overapproximated by both values, never evaluated.",
    ),
    (
        "astrolabe/internal/bridge/backend.go:3412",
        0,
        lambda x: not x[0] or x[1],
        "TestSelection",
        "At the local OR, multiple implies a previously assigned nonnil member. Both locals are initialized together, updated only in this loop, and never escape.",
    ),
    (
        "astrolabe/internal/bridge/backend.go:6309",
        0,
        lambda x: not x[0] or x[1],
        "TestTransportReplacement",
        "Close sets closed and clears target under the same mutex; replace never publishes a target after closure. begin captures both under its read lock. The absent member predicate is overapproximated by both Boolean values.",
    ),
    (
        "astrolabe/internal/web/server.go:5359",
        0,
        lambda x: x[0] or not x[1],
        "TestRouting/origin-syntax",
        "Origin errors return an empty string. New accepts only normalized nonempty origins, and the private allowlist has no later writes. Failed parsing therefore cannot select an allowed origin.",
    ),
    (
        "astrolabe/internal/web/almanac.go:11485",
        1,
        lambda x: not x[2] or x[1],
        "TestLoadFailures/no-page",
        "started and complete begin false. Sequential Load callbacks set started before assigning complete, and neither is reset; complete therefore implies started.",
    ),
)


# These exclusions require the selected JSON implementation, not only application source.
COUPLINGS = (
    (
        "astrolabe/internal/bridge/metrics.go:1585",
        0,
        lambda x: not x[0] or x[1],
        "TestTargets/empty",
        "Every nonnil Token error returns a nil token, which differs from the opening delimiter. Changing the error necessarily changes or retains the rejecting delimiter predicate.",
    ),
    (
        "astrolabe/internal/bridge/metrics.go:1900",
        0,
        lambda x: not x[0] or not x[1],
        "TestTargets/key",
        "A Token error returns nil, so the string type assertion is false. All later predicates are overapproximated; no independence is claimed from this coupled refusal.",
    ),
    (
        "astrolabe/internal/bridge/metrics.go:2776",
        0,
        lambda x: not x[0] or x[1],
        "TestTargets/ending",
        "A closing Token error returns nil, which cannot equal the expected object delimiter.",
    ),
    (
        "astrolabe/internal/web/account.go:1338",
        0,
        lambda x: not x[0] or x[1],
        "TestObject/empty",
        "Every nonnil opening Token error returns nil, so the delimiter comparison also rejects.",
    ),
    (
        "astrolabe/internal/web/account.go:1519",
        0,
        lambda x: not x[0] or not x[1],
        "TestObject/key",
        "A key Token error returns nil, so the string type assertion is false, independently of the dictionary size or prior keys.",
    ),
    (
        "astrolabe/internal/web/account.go:1648",
        0,
        lambda x: not x[0] or x[1],
        "TestObject/value",
        "The RawMessage starts nil. Decode returns before assigning it on a ReadValue syntax failure; a valid RawMessage has no semantic conversion failure. Therefore Decode failure implies zero length. The unavailable first-byte predicate is overapproximated by both values, never read.",
    ),
    (
        "astrolabe/internal/web/account.go:2199",
        0,
        lambda x: not x[0] or x[1],
        "TestObject/truncated",
        "A closing Token error returns nil, which differs from the expected object delimiter.",
    ),
)


# These relations additionally require the installed Linux standard-library selection.
LIBRARY_COUPLINGS = (
    (
        "astrolabe/internal/bridge/metrics.go:5285",
        0,
        lambda x: not x[0] or x[3],
        "TestMetricValues/negative",
        "ParseUint uses base 10 and 64 bits. Syntax failure returns zero, whose canonical string 0 parses successfully; range failure returns the maximum, whose canonical string also parses successfully. Every returned error therefore implies the original string differs from FormatUint, independently of the binary/value predicates.",
    ),
    (
        "astrolabe/internal/web/almanac.go:4802",
        0,
        lambda x: not x[0] or x[2],
        "TestRefusal/version-invalid",
        "With base 10 and 64 bits, ParseUint errors return zero or the maximum. Either value's canonical decimal string parses successfully, so a returned error implies the unchanged original version string differs from FormatUint.",
    ),
    (
        "astrolabe/internal/web/credentials.go:1872",
        0,
        lambda x: not x[0] or x[2],
        "TestRefusal/credential-version-invalid",
        "With base 10 and 64 bits, ParseUint errors return zero or the maximum. Either value's canonical decimal string parses successfully, so a returned error implies the unchanged original version string differs from FormatUint.",
    ),
    (
        "astrolabe/internal/web/server.go:2931",
        0,
        lambda x: not x[0] or x[2],
        "TestVerification",
        "With base 10 and 16 bits, ParseUint errors return zero or 65535. Both canonical strings parse successfully at that width; a returned error implies the original port string differs from FormatUint. No invalid base or width is supplied.",
    ),
    (
        "astrolabe/internal/web/account.go:3594",
        0,
        lambda x: not x[0] or not x[2],
        "TestAccountAcquisition/stat",
        "LoadAccount's production acquisition returns *os.File. The selected Unix Stat returns nil FileInfo on every error; SameFile(before, nil) is false. The undefined Mode call is overapproximated by both values. This does not constrain arbitrary injected accountFile implementations returning nonnil info together with an error.",
    ),
)
LIBRARY_ANCHORS = {
    **{
        identity: ("go/strconv/number.go:104", "go/strconv/number.go:202", "go/internal/strconv/atoi.go:49", "go/internal/strconv/itoa.go:12")
        for identity, *_ in LIBRARY_COUPLINGS[:-1]
    },
    ACCOUNT + ":3594": ("astrolabe/internal/web/account.go:96", "internal/admission/file_linux.go:11", "go/os/stat_unix.go:15", "go/os/types.go:69"),
}
LIBRARY_DEFENSES = (
    (
        "fixed-pbkdf-parameters",
        ((ACCOUNT + ":4912", 0, False),),
        (
            "astrolabe/internal/web/account.go:142",
            "go/crypto/pbkdf2/pbkdf2.go:40",
            "go/crypto/internal/fips140/pbkdf2/pbkdf2.go:23",
            "go/crypto/internal/fips140only/fips140only.go:21",
            "go/crypto/internal/fips140hash/hash.go:23",
            "go/crypto/sha256/sha256.go:34",
            "go/crypto/internal/boring/notboring.go:16",
            "go/crypto/internal/fips140/sha256/sha256.go:149",
            "go/crypto/internal/fips140/hmac/hmac.go:79",
        ),
        "The account arrays fix salt length at 16 and key length at 32; iterations are 600000. The selected non-Boring SHA-256 returns an approved *sha256.Digest with Size 32, preserved by UnwrapNew and HMAC. Key length is positive, 32+32 cannot overflow, and one block is below 2^32-1. FIPS-only salt/key/hash guards also pass. All possible returned-error branches in the pinned PBKDF implementation are therefore false; normal return supplies nil error independently of password content.",
        "Changed array types, parameters, hash constructor/selection, PBKDF implementation or memory safety. Allocation failure, panic and fatal crypto self-test failure are not successful returns with an error value; this is no reliability exemption for those failures.",
    ),
    (
        "opaque-metrics-url",
        (("astrolabe/internal/bridge/metrics.go:2221", 9, True),),
        ("go/net/url/url.go:443", "go/net/url/url.go:464", "astrolabe/internal/bridge/metrics.go:63"),
        "Parse allocates a zero URL. Its only opaque return occurs before Path assignment, leaving Path empty. A nonempty Opaque is therefore rejected by the earlier Path != /metrics operand and cannot be evaluated true at the later Opaque operand.",
        "Changed URL parser, entry API, preceding validation, operand order, pointer ownership or memory safety. Invalid opaque inputs remain rejected, not accepted or counted as executed opaque-true observations.",
    ),
    (
        "opaque-origin-url",
        (("astrolabe/internal/web/server.go:2265", 9, True),),
        ("go/net/url/url.go:443", "go/net/url/url.go:464", "go/net/url/url.go:1193", "astrolabe/internal/web/server.go:56"),
        "Parse's opaque return leaves Host empty. Hostname then returns empty, so the earlier empty-host operand rejects before Opaque can be evaluated true. The freshly parsed URL is private and is not changed between predicates.",
        "Changed URL parser or Hostname, entry API, preceding validation, operand order, pointer ownership or memory safety. This is an evaluated-outcome exclusion, not a claim that opaque input cannot arrive.",
    ),
)


def partial(decisions: dict, rows: dict, executed: set[str], package: str) -> list[dict]:
    """Correlate only registered partial inputs, preserving every jointly defined nontarget predicate."""
    result = []
    for suffix, target, before, after, tests, basis in GUARDS:
        identity = package + "/" + suffix
        if identity not in decisions:
            continue
        if not set(tests) <= executed:
            v.reject("astrolabe-guard-tests", identity)
        decision = decisions[identity]
        if (
            type(before[target]) is not bool
            or type(after[target]) is not bool
            or before[target] == after[target]
            or not any(value is None for side in (before, after) for value in side)
            or any(a != b for i, (a, b) in enumerate(zip(before, after, strict=True)) if i != target and a is not None and b is not None)
        ):
            v.reject("astrolabe-guard-domain", identity)
        pair, vectors = {}, []
        for name, values, other in (("before", before, after), ("after", after, before)):
            vector, outcome = authority.project(decision, list(values))
            if (vector, outcome) not in rows[identity] or vector[target] == "0":
                v.reject("astrolabe-guard-native-witness", identity)
            # Filling from the other defined side is algebra, never a fabricated field read.
            # When both sides are undefined the cube must hold for every Boolean completion.
            completed = [other[i] if value is None else value for i, value in enumerate(values)]
            cube = "".join("0" if value is None else "2" if value else "1" for value in completed)
            if logic.cube(decision, cube) is not outcome:
                v.reject("astrolabe-guard-completion", identity)
            pair[name] = {"values": list(values), "result": outcome}
            vectors.append({"values": vector, "result": outcome})
        if pair["before"]["result"] == pair["after"]["result"]:
            v.reject("astrolabe-guard-no-effect", identity)
        result.append(
            {
                "decision": identity,
                "condition": target,
                **pair,
                "criterion": "defined-domain-short-circuit-v1",
                "native_vectors": vectors,
                "tests": list(tests),
                "basis": basis,
            }
        )
    return result


def conditions(trace: dict, rows: dict, executed: set[str], dependency: dict[str, bytes] | None = None, library: dict[str, bytes] | None = None) -> dict:
    """Verify source-bound total, partial and masked pairs, with explicit coupling limits."""
    package = trace["typing"]["package"].removeprefix(MODULE)
    if package not in PACKAGES or v.digest(v.encode(trace["files"])) != FORESTS[PACKAGES.index(package)]:
        v.reject("astrolabe-condition-forest")
    decisions = logic.inventory(trace)
    proofs = []
    for suffix, target, before, after, tests in PAIRS:
        identity = package + "/" + suffix
        if identity not in decisions:
            continue
        if not set(tests) <= executed:
            v.reject("astrolabe-pair-tests", identity)
        decision = decisions[identity]
        pair = {
            "decision": identity,
            "condition": target,
            "before": {"values": list(before), "result": authority.project(decision, list(before))[1]},
            "after": {"values": list(after), "result": authority.project(decision, list(after))[1]},
        }
        proof = authority.correlate_pair(decision, pair, set(rows[identity]))
        proofs.append({**proof, "tests": list(tests), "basis": "Frozen literal fixture inputs; independently projected onto original native masks."})
    masked = []
    for suffix, target, before, after, tests in MASKS:
        identity = package + "/" + suffix
        if identity not in decisions:
            continue
        if not set(tests) <= executed:
            v.reject("astrolabe-mask-tests", identity)
        decision = decisions[identity]
        pair = {
            "decision": identity,
            "condition": target,
            **{
                name: {"values": list(values), "result": authority.project(decision, list(values))[1]}
                for name, values in (("before", before), ("after", after))
            },
        }
        masked.append({**predicates.mask(decision, pair, set(rows[identity])), "tests": list(tests)})
    coupled = []
    dependent = {row[0] for row in COUPLINGS}
    if dependent & decisions.keys() and (
        dependency is None or v.digest(v.encode({name: v.digest(data) for name, data in sorted(dependency.items())})) != DEPENDENCIES
    ):
        v.reject("astrolabe-coupling-dependencies")
    if LIBRARY_ANCHORS.keys() & decisions.keys() and (
        library is None or v.digest(v.encode({name: v.digest(data) for name, data in sorted(library.items())})) != LIBRARIES
    ):
        v.reject("astrolabe-coupling-libraries")
    for identity, target, relation, test, reason in (*RELATIONS, *COUPLINGS, *LIBRARY_COUPLINGS):
        if identity not in decisions:
            continue
        if test not in executed:
            v.reject("astrolabe-coupling-tests")
        decision = decisions[identity]
        proof = predicates.symbolic(decision, target, relation)
        if {result for _, result in rows[identity]} != {False, True} or {values[target] for values, _ in rows[identity]} - {"0"} != {"1", "2"}:
            v.reject("astrolabe-coupling-empty")
        for observed, outcome in rows[identity]:
            if not any(result == outcome and all(a == "0" or a == b for a, b in zip(observed, values, strict=True)) for values, result in proof["allowed"]):
                v.reject("astrolabe-coupling-contradicted")
        coupled.append(
            {
                "decision": identity,
                "condition": target,
                "criterion": "no-universal-common-cube-pair-in-source-overapproximation-v1",
                "assumption": reason,
                "invalidated_by": "Changed initialization, validation, assignment order, synchronization, callback sequencing, production file acquisition, ownership, selected library implementation/options or memory safety.",
                "total": proof["total"],
                "allowed": len(proof["allowed"]),
                "comparisons": proof["comparisons"],
                "relaxed_witness": proof["relaxed_witness"],
                "table_sha256": v.digest(v.encode([{"values": values, "result": result} for values, result in sorted(proof["allowed"])])),
                "tests": [test],
                **(
                    {
                        "dependencies_sha256": DEPENDENCIES,
                        "anchors": ["go/encoding/json/v2_stream.go:74", "go/encoding/json/v2_stream.go:220", "go/encoding/json/v2/arshal_default.go:1465"],
                    }
                    if identity in dependent
                    else {}
                ),
                **({"dependencies_sha256": LIBRARIES, "anchors": list(LIBRARY_ANCHORS[identity])} if identity in LIBRARY_ANCHORS else {}),
            }
        )
    return {"input_pairs": proofs, "guarded_pairs": partial(decisions, rows, executed, package), "masked_pairs": masked, "source_coupling": coupled}


def defenses(trace: dict, rows: dict, dependency: dict[str, bytes], library: dict[str, bytes] | None = None) -> list[dict]:
    """Keep source-bound impossible outcomes explicit and reject any contradictory native observation."""
    package = trace["typing"]["package"].removeprefix(MODULE)
    if package not in PACKAGES or v.digest(v.encode(trace["files"])) != FORESTS[PACKAGES.index(package)]:
        v.reject("astrolabe-defense-forest")
    if v.digest(v.encode({name: v.digest(data) for name, data in sorted(dependency.items())})) != DEPENDENCIES:
        v.reject("astrolabe-defense-dependencies")
    decisions, result = logic.inventory(trace), []
    selected = {identity for _, coordinates, *_ in LIBRARY_DEFENSES for identity, _, _ in coordinates}
    if selected & decisions.keys() and (library is None or v.digest(v.encode({name: v.digest(data) for name, data in sorted(library.items())})) != LIBRARIES):
        v.reject("astrolabe-defense-libraries")
    for name, coordinates, anchors, assumption, invalidated in (*DEFENSES, *LIBRARY_DEFENSES):
        for identity, target, impossible in coordinates:
            if identity not in decisions:
                continue
            actual = rows.get(identity, {})
            if any(type(hits) is not int or hits <= 0 for hits in actual.values()):
                v.reject("astrolabe-defense-hits", identity)
            observed = {values[target] for values, _ in actual} - {"0"}
            forbidden = "2" if impossible else "1"
            if forbidden in observed:
                v.reject("astrolabe-defense-contradicted", identity)
            if observed != {"1" if impossible else "2"}:
                v.reject("astrolabe-defense-unobserved", identity)
            result.append(
                {
                    "decision": identity,
                    "condition": target,
                    "id": name,
                    "criterion": "source-dependency-impossible-evaluated-outcome-v1",
                    "impossible_outcome": impossible,
                    "observed_outcome": not impossible,
                    "anchors": list(anchors),
                    "assumption": assumption,
                    "invalidated_by": invalidated,
                    "dependencies_sha256": LIBRARIES if identity in selected else DEPENDENCIES,
                }
            )
    return result


def members(trace: dict, rows: dict, executed: set[str], source: dict[str, bytes]) -> dict:
    """Bound the missing-metric relation to admitted, nonempty member identities."""
    if v.digest(v.encode(trace["files"])) != FORESTS[1] or {name: v.digest(data) for name, data in source.items()} != MEMBERS:
        v.reject("astrolabe-member-source")
    tests = {"TestMetricDirectory", "TestMetricReplacement"}
    if not tests <= executed:
        v.reject("astrolabe-member-tests")
    identity = "astrolabe/internal/bridge/metrics.go:10909"
    decision = logic.inventory(trace)[identity]
    actual = rows.get(identity, {})
    if any(type(hits) is not int or hits <= 0 for hits in actual.values()):
        v.reject("astrolabe-member-hits")
    if {outcome for _, outcome in actual} != {False, True} or {mask[0] for mask, _ in actual} - {"0"} != {"1", "2"}:
        v.reject("astrolabe-member-observations")
    proof = predicates.symbolic(decision, 0, lambda x: x[0] or x[1])
    for observed, outcome in actual:
        if not any(result == outcome and all(a == "0" or a == b for a, b in zip(observed, values, strict=True)) for values, result in proof["allowed"]):
            v.reject("astrolabe-member-contradiction")
    return {
        "decision": identity,
        "condition": 0,
        "criterion": "no-universal-common-cube-pair-in-source-overapproximation-v1",
        "assumption": "Backend nodes are initialized empty and published only by Update from Directory.Members through describe. Install calls Valid and Verify calls Identity.Verify before observe; both reject empty Id. Private directory records and returned messages retain protobuf Clone ownership. describe copies Id into an immutable string. A missing metric is its zero value with empty ID, so absence implies value.ID differs from the admitted nonempty current.ID. Metrics reads the directory and map under the same read lock.",
        "invalidated_by": "Changed member validation, directory mutation paths, protobuf Clone ownership, backend projection/publication, synchronization, direct private test-state injection or memory safety. The claim applies to admitted production states, not arbitrary private structs.",
        "anchors": [
            "internal/admission/identity.go:155",
            "internal/admission/identity.go:174",
            "internal/admission/directory.go:38",
            "internal/admission/directory.go:82",
            "internal/admission/directory.go:109",
            "internal/admission/directory.go:141",
            "astrolabe/internal/bridge/backend.go:43",
            "astrolabe/internal/bridge/backend.go:49",
            "astrolabe/internal/bridge/backend.go:240",
        ],
        "sources": MEMBERS,
        "tests": sorted(tests),
        "total": proof["total"],
        "allowed": len(proof["allowed"]),
        "comparisons": proof["comparisons"],
        "relaxed_witness": proof["relaxed_witness"],
        "table_sha256": v.digest(v.encode([{"values": values, "result": result} for values, result in sorted(proof["allowed"])])),
    }


def cancellation(trace: dict, rows: dict, terminal: list[dict], source: dict[str, bytes], dependency: dict[str, bytes], library: dict[str, bytes]) -> dict:
    """Keep the entry's normalized-cancellation defense separate from native condition hits."""
    if v.digest(v.encode(trace["files"])) != FORESTS[0] or {name: v.digest(data) for name, data in source.items()} != STARTUP:
        v.reject("astrolabe-cancellation-source")
    for values, expected in ((dependency, DEPENDENCIES), (library, LIBRARIES)):
        if v.digest(v.encode({name: v.digest(data) for name, data in sorted(values.items())})) != expected:
            v.reject("astrolabe-cancellation-dependencies")
    identity = "astrolabe/main.go:8844"
    actual = rows.get(identity, {})
    if any(type(hits) is not int or hits <= 0 for hits in actual.values()):
        v.reject("astrolabe-cancellation-hits")
    if set(actual) - {("10", False), ("21", True)}:
        v.reject("astrolabe-cancellation-contradiction")
    joined = [item for item in terminal if item["decision"] == identity]
    if (
        ("10", False) not in actual
        or len(joined) != 1
        or joined[0]["values"] != "21"
        or joined[0]["result"] is not True
        or {item["case"] for item in joined[0]["receipts"]} != {"startup", "refusal"}
    ):
        v.reject("astrolabe-cancellation-observations")
    return {
        "decision": identity,
        "condition": 1,
        "id": "normalized-entry-cancellation",
        "criterion": "source-dependency-impossible-evaluated-outcome-v1",
        "impossible_outcome": True,
        "observed_outcome": False,
        "anchors": [
            "astrolabe/main.go:88",
            "astrolabe/main.go:168",
            "astrolabe/main.go:190",
            "astrolabe/internal/bridge/metrics.go:29",
            "astrolabe/internal/web/account.go:26",
            "astrolabe/internal/web/account.go:100",
            "astrolabe/internal/web/server.go:85",
            "internal/admission/identity.go:23",
            "internal/admission/node.go:38",
            "internal/admission/directory.go:32",
            "grpc/clientconn.go:183",
            "grpc/clientconn.go:480",
            "grpc/clientconn.go:1821",
            "grpc/clientconn.go:1940",
            "go/net/url/url.go:475",
            "go/errors/wrap.go:45",
            "go/context/context.go:168",
        ],
        "assumption": "Targets, identity/account loading and handler construction translate every startup failure to distinct errors.New values or their fixed non-cancellation sentinels; listener failure is also translated. Open returns those identity sentinels or NewClient errors. The pinned non-I/O NewClient returns only URL syntax errors, credential sentinels or non-wrapping formatted configuration/authority errors; none wraps or equals context.Canceled. After startup, run checks every selected result with errors.Is(result, context.Canceled) before returning it and translates a match to nil. The same immutable error and sentinel are tested at entry, so a nonnil return cannot newly match cancellation. This argument assumes stable error classification in the selected concrete stdlib/gRPC implementations and no mutation of sentinels or runtime hooks.",
        "invalidated_by": "Changed return translation, constructor or URL/error implementation, custom/stateful Is or Unwrap, mutable error ownership, sentinel reassignment, global dial hooks, unsupported runtime patching or memory safety. Panics/fatal exits are not normal returns and gain no reliability exemption. A source assumption is not an executed cancellation-true branch.",
        "sources": STARTUP,
        "dependencies_sha256": DEPENDENCIES,
        "libraries_sha256": LIBRARIES,
        "native_vectors": [{"values": "10", "result": False}, {"values": "21", "result": True, "origin": "joined-child-exit"}],
    }


def retained(data: bytes, seal: dict, expected: str) -> dict[str, bytes]:
    """Verify a known local archive, its complete member ledger and native terminal ownership."""
    legacy = (
        expected in tuple(ARCHIVES.values())[:4]
        and set(seal) == {"archive_sha256", "bytes", "files", "qualification"}
        and seal["qualification"] == "Native Astrolabe structure batch only; independent interpretation required"
    )
    if v.digest(data) != expected or seal.get("archive_sha256") != expected or seal.get("bytes") != len(data) or not (seal.get("trust") == "local" or legacy):
        v.reject("astrolabe-archive-integrity")
    files = entry.unpack(data)
    if not isinstance(seal.get("files"), dict) or files.keys() != seal["files"].keys():
        v.reject("astrolabe-archive-inventory")
    if any(seal["files"][name] != {"bytes": len(content), "sha256": v.digest(content)} for name, content in files.items()):
        v.reject("astrolabe-member-integrity")
    owner, cleanup, terminal = (v.decode(files[name + ".json"]) for name in ("controller", "cleanup.native", "terminal"))
    service = cleanup["service"]
    # This exact archive has a successful ordinary command followed by a collector failure.
    # Preserve the failed enclosing result; only its independently checked command may be reused.
    failed = expected == ARCHIVES["material-endpoints-2"]
    error = "FileNotFoundError: [Errno 2] No such file or directory: '/home/ubuntu/verdandi/astra/build/results/assurance/reuse-material-endpoints-2/dependencies/go/errors/errors.go'"
    if (
        owner["script_sha256"] != v.digest(files["run.py"])
        or owner["identity"] not in cleanup["retired"]
        or owner["boot_id"] != cleanup["boot_id"]
        or service["InvocationID"] not in {"", owner["invocation_id"]}
        or service["MainPID"] != "0"
        or service["ControlGroup"] != ""
        or service["ExecMainStatus"] != ("2" if failed else "0")
        or service["SubState"] != ("failed" if failed else "dead" if expected == ARCHIVES["material-stop"] else "exited")
        or terminal["errors"] != ([error] if failed else [])
        or terminal["remaining_owned"]
        or terminal["interrupted"] is not False
        or terminal["source_unchanged"] is not True
        or terminal["pins_unchanged"] is not True
    ):
        v.reject("astrolabe-native-retirement")
    events = dict(row.split() for row in terminal["resources"]["memory.events"].splitlines())
    if any(events.get(key) != "0" for key in ("max", "oom", "oom_kill", "oom_group_kill")):
        v.reject("astrolabe-resource-failure")
    return files


def command(files: dict[str, bytes], prefix: str) -> tuple[dict, bytes]:
    """Bind original arguments, clocks, environment, toolchain, complete streams and retired identity."""
    record = v.decode(files[prefix + "record.json"])
    child = v.decode(files[prefix + record["id"] + ".process.json"])
    cleanup, preflight = (v.decode(files[name + ".json"]) for name in ("cleanup.native", "preflight"))
    if (
        record["exit_code"] != 0
        or record["complete"] is not True
        or record["cleanup"] is not True
        or record["termination"] != "exited"
        or record["platform"] != "linux-amd64-cgo"
        or record["executable_sha256"] != GO
        or record["resolved_environment"].get("GOEXPERIMENT", "") != ""
        or v.stamp(record["finished_at"]) < v.stamp(record["started_at"])
        or child["argv"] != record["argv"]
        or child["identity"] not in cleanup["retired"]
        or child["boot_id"] != cleanup["boot_id"]
        or child["cwd"] != str(PurePosixPath(record["resolved_environment"]["GOCACHE"]).parents[2])
        or record["executable_sha256"] != preflight["pins"].get(record["executable"])
        or any(item["sha256"] != preflight["pins"].get(item["path"]) for item in record["toolchain"].values())
    ):
        v.reject("astrolabe-native-command", prefix)
    for channel in ("stdout", "stderr"):
        ref = record[channel]
        data = files[prefix + ref["path"]]
        if len(data) != ref["bytes"] or v.digest(data) != ref["sha256"]:
            v.reject("astrolabe-native-stream", channel)
    return record, files[prefix + record["stdout"]["path"]]


def dependencies(native: dict[str, bytes], data: bytes, seal: dict) -> dict[str, bytes]:
    """Read pinned dependency bytes and bind the JSON implementation to actual native package selection."""
    if v.digest(data) != EXTRA or seal.get("archive_sha256") != EXTRA or seal.get("go_sha256") != GO:
        v.reject("astrolabe-dependency-archive")
    extra = entry.unpack(data)
    if seal.get("files") != {name: {"bytes": len(value), "sha256": v.digest(value)} for name, value in extra.items()}:
        v.reject("astrolabe-dependency-members")
    record, output = command(native, "source/build/commands/dependencies/")
    names = ["encoding/json", "strings", "crypto/rand", "google.golang.org/grpc", "google.golang.org/protobuf/proto"]
    if record["argv"] != ["go", "list", "-json", *names]:
        v.reject("astrolabe-dependency-command")
    decoder, packages, text = json.JSONDecoder(), {}, output.decode("utf-8").strip()
    while text:
        item, end = decoder.raw_decode(text)
        if item["ImportPath"] in packages or item.get("Error") or item.get("DepsErrors"):
            v.reject("astrolabe-dependency-packages")
        packages[item["ImportPath"]] = item
        text = text[end:].lstrip()
    if (
        packages.keys() != set(names)
        or not {"v2_decode.go", "v2_stream.go"} <= set(packages["encoding/json"]["GoFiles"])
        or {"decode.go", "stream.go"} & set(packages["encoding/json"]["GoFiles"])
    ):
        v.reject("astrolabe-dependency-selection")
    result = {name: value for name, value in native.items() if name.startswith("dependencies/")}
    additions = {"dependencies/go/" + name: value for name, value in extra.items()}
    if result.keys() & additions.keys():
        v.reject("astrolabe-dependency-overlap")
    result.update(additions)
    if v.digest(v.encode({name: v.digest(value) for name, value in sorted(result.items())})) != DEPENDENCIES:
        v.reject("astrolabe-defense-dependencies")
    return result


def libraries(native: dict[str, bytes], data: bytes, seal: dict) -> dict[str, bytes]:
    """Bind installed library bytes to the exact active files in the retained native import graph."""
    if (
        v.digest(data) != LIBRARY_ARCHIVE
        or seal.get("archive_sha256") != LIBRARY_ARCHIVE
        or seal.get("go_sha256") != GO
        or seal.get("bytes") != len(data)
        or seal.get("trust") != "local"
        or seal.get("application_commands_executed") != 0
    ):
        v.reject("astrolabe-library-archive")
    extra = entry.unpack(data)
    if seal.get("files") != {name: {"bytes": len(value), "sha256": v.digest(value)} for name, value in extra.items()}:
        v.reject("astrolabe-library-members")
    record, output = command(native, "command/exports/")
    if record["argv"] != ["go", "list", "-deps", "-export", "-json", "-p=2", "./astrolabe", "./astrolabe/internal/web"]:
        v.reject("astrolabe-library-command")
    if seal.get("exports_sha256") != v.digest(output):
        v.reject("astrolabe-library-exports")
    names = {
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
    }
    additions = {"dependencies/go/" + name: value for name, value in extra.items()}
    result = {name: value for name, value in native.items() if name.startswith("dependencies/")}
    if result.keys() & additions.keys():
        v.reject("astrolabe-library-overlap")
    result.update(additions)
    decoder, packages, expected, text = json.JSONDecoder(), set(), set(), output.decode("utf-8").strip()
    while text:
        item, end = decoder.raw_decode(text)
        name = item["ImportPath"]
        if name in packages or item.get("Error") or item.get("DepsErrors"):
            v.reject("astrolabe-library-packages")
        packages.add(name)
        if name in names:
            if item.get("Standard") is not True or item.get("Dir") != str(PurePosixPath(record["executable"]).parents[1] / "src" / name):
                v.reject("astrolabe-library-selection")
            active = item.get("GoFiles")
            if not isinstance(active, list) or not active or len(set(active)) != len(active):
                v.reject("astrolabe-library-selection")
            for filename in active:
                if not isinstance(filename, str) or PurePosixPath(filename).name != filename or not filename.endswith(".go"):
                    v.reject("astrolabe-library-selection")
                expected.add("dependencies/go/" + name + "/" + filename)
        text = text[end:].lstrip()
    if not names <= packages or expected != result.keys():
        v.reject("astrolabe-library-inventory")
    if v.digest(v.encode({name: v.digest(value) for name, value in sorted(result.items())})) != LIBRARIES:
        v.reject("astrolabe-library-source")
    return result


def terminals(data: bytes, package: str, expected: list[str]) -> bytes:
    """Select original package lines and require all independently frozen named terminals."""
    lines = [(line, v.decode(line)) for line in data.splitlines()]
    selected = [(line, event) for line, event in lines if event.get("Package") == package]
    result = b"\n".join(line for line, _ in selected) + b"\n"
    passed = [event["Test"] for _, event in selected if event.get("Action") == "pass" and "Test" in event]
    if not expected or len(set(expected)) != len(expected) or sorted(passed) != sorted(expected):
        v.reject("astrolabe-test-inventory")
    statements.terminals(result, {package: {"tests": len(expected)}})
    return result


def processes(data: bytes, boot: str) -> dict:
    """Read seven joined child receipts from complete native test lifecycles, including split output events."""
    expected = ["TestProcess", *("TestProcess/" + name for name in EXITS)]
    events = terminals(data, MODULE + "astrolabe", expected)
    outputs, receipts = {}, {}
    for line in events.splitlines():
        event = v.decode(line)
        if event.get("Action") == "output":
            name = event.get("Test", "")
            outputs[name] = outputs.get(name, "") + event.get("Output", "")
    for name, output in outputs.items():
        for line in output.splitlines():
            if "ASTROLABE-PROCESS " not in line:
                continue
            receipt = v.decode(line.split("ASTROLABE-PROCESS ", 1)[1].encode())
            if not isinstance(receipt, dict):
                v.reject("astrolabe-process-receipt", name)
            case = receipt.get("case")
            ticks = receipt.get("start_ticks")
            if (
                set(receipt) != {"case", "pid", "start_ticks", "boot_id", "signal", "exit_code", "reaped", "calls"}
                or not isinstance(case, str)
                or case not in EXITS
                or case in receipts
                or name != "TestProcess/" + case
                or receipt["boot_id"] != boot
                or not boot
                or receipt["reaped"] is not True
                or any(type(receipt[field]) is not int for field in ("pid", "exit_code", "signal", "calls"))
                or receipt["pid"] <= 0
                or not isinstance(ticks, str)
                or not ticks.isascii()
                or not ticks.isdecimal()
                or len(ticks) > 20
                or ticks.startswith("0")
                or (receipt["exit_code"], receipt["signal"], receipt["calls"]) != EXITS[case]
            ):
                v.reject("astrolabe-process-receipt", name)
            receipts[case] = receipt
    if set(receipts) != set(EXITS) or len({(r["pid"], r["start_ticks"]) for r in receipts.values()}) != len(EXITS):
        v.reject("astrolabe-process-inventory")
    return receipts


def exits(trace: dict, rows: dict, receipts: dict, library: dict[str, bytes] | None = None) -> list[dict]:
    """Infer unique terminal branches from the pinned entry without adding compiler hits or skipped operand values."""
    if v.digest(v.encode(trace["files"])) != FORESTS[0] or set(receipts) != set(EXITS):
        v.reject("astrolabe-exit-source")
    if library is not None and v.digest(v.encode({name: v.digest(data) for name, data in sorted(library.items())})) != LIBRARIES:
        v.reject("astrolabe-exit-libraries")
    decisions = logic.inventory(trace)
    result = []
    for suffix, mask, cases in (("8577", "2", ("usage",)), ("8844", "21", ("startup", "refusal"))):
        identity = "astrolabe/main.go:" + suffix
        decision = decisions[identity]
        observed = set(rows[identity])
        if not any(outcome is False for _, outcome in observed) or logic.cube(decision, mask) is not True:
            v.reject("astrolabe-exit-witness", identity)
        # These are source-correlated terminal observations, not execution counters.
        pairs, _, complete = logic.candidates(decision, observed | {(mask, True)}, logic.COMPARISONS, certify=True)
        if not complete:
            v.reject("astrolabe-proof-budget")
        result.append(
            {
                "decision": identity,
                "values": mask,
                "result": True,
                "receipts": [receipts[name] for name in cases],
                "independent": [{"condition": index, **pair} for index, pair in sorted(pairs.items())],
                "basis": "Pinned main has one os.Exit(2) parameter branch and one os.Exit(1) fatal branch. The pinned joined-child fixture verifies native wait status and the fatal structured log. Compiler counters remain unchanged.",
            }
        )
        if suffix == "8844" and library is not None:
            pair = authority.correlate_pair(
                decision,
                {
                    "decision": identity,
                    "condition": 0,
                    "before": {"values": [False, False], "result": False},
                    "after": {"values": [True, False], "result": True},
                },
                observed | {(mask, True)},
            )
            result[-1]["independent"].append(
                {
                    **pair,
                    "dependencies_sha256": LIBRARIES,
                    "anchors": ["go/errors/wrap.go:45", "go/context/context.go:168"],
                    "basis": "The recorded nil-error native mask is 10. The pinned errors.Is(nil, context.Canceled) is false because the canonical cancellation sentinel is nonnil. The fatal true mask 21 is independently derived from the joined startup/refusal child exits above. This source-defined skipped value is not a compiler hit.",
                    "invalidated_by": "Changed error helper, mutable cancellation sentinel, entry branches, child fixture, runtime patching or memory safety.",
                }
            )
    return result


def sources(root: Path, plan: dict) -> dict[str, str]:
    """Pin the current Go dependency closure, new cases and overlays without invalidating evidence for prose edits."""
    selected = {
        name: digest
        for name, digest in plan["files"].items()
        if name in plan["reused_go_inputs"]
        or name.startswith("astrolabe/")
        and name.endswith(".go")
        or name in {"tests/fixtures/account-metadata.go.in", "tests/fixtures/astrolabe-stop.go.in", "tests/fixtures/astrolabe-serving.go.in"}
    }
    directories = {PurePosixPath(name).parent.as_posix() for name in selected if name.endswith(".go")}
    owned = {p.relative_to(root).as_posix() for name in directories for p in v.inside(root, name).glob("*.go")}
    owned.update(p.relative_to(root).as_posix() for p in (root / "astrolabe").rglob("*.go"))
    if owned != {name for name in selected if name.endswith(".go")} or len(plan["reused_go_inputs"]) != 146:
        v.reject("astrolabe-source-inventory")
    for name, digest in selected.items():
        if v.file_digest(v.inside(root, name)) != digest:
            v.reject("astrolabe-source-drift", name)
    return selected


def checkpoint(original: bytes, instrumented: bytes, *, stopping: bool = False) -> None:
    """Permit only the single reviewed select-expression checkpoint, preserving every original arm."""
    before = b"case <-parent.Done():"
    after = b"case <-checkpoint(parent.Done(), refresh):" if stopping else b"case <-servingpoint(parent.Done(), server, serving):"
    if original.count(before) != 1 or instrumented != original.replace(before, after):
        v.reject("astrolabe-stop-checkpoint" if stopping else "astrolabe-serving-checkpoint")


def endpoints(native: dict[str, bytes], raced: dict[str, bytes]) -> tuple[dict, dict]:
    """Join successful commands across a preserved collector failure using identical frozen source bytes."""
    plan = v.decode(native["inputs.json"])
    if native["inputs.json"] != raced["inputs.json"] or native["source.tar.gz"] != raced["source.tar.gz"] or native["source.json"] != raced["source.json"]:
        v.reject("astrolabe-endpoint-inputs")
    if v.digest(native["source.json"]) != plan["source_sha256"] or v.digest(native["source.tar.gz"]) != plan["source_archive_sha256"]:
        v.reject("astrolabe-endpoint-integrity")
    source = entry.unpack(native["source.tar.gz"])
    if {name: v.digest(data) for name, data in source.items()} != plan["files"]:
        v.reject("astrolabe-endpoint-source")
    records = {mode: command(raced if mode == "ordinary" else native, "command/" + mode + "/") for mode in ("ordinary", "typed", "controls")}
    selection = "-run=^(" + "|".join(plan["parents"]) + ")$"
    for mode, (record, output) in records.items():
        cwd = PurePosixPath(record["resolved_environment"]["GOCACHE"]).parents[2]
        base = cwd.parent
        overlay = str(base / ("ordinary/overlay.json" if mode == "ordinary" else mode + "/combined.json"))
        expected = [
            "go",
            "test",
            "-json",
            *(["-race"] if mode == "ordinary" else []),
            "-count=1",
            "-p=2",
            "-parallel=1",
            "-timeout=120s",
            "-overlay=" + overlay,
            selection,
            "./astrolabe",
            "./astrolabe/internal/web",
        ]
        if record["argv"] != expected or not 0 < record["duration_ms"] < 3600000:
            v.reject("astrolabe-endpoint-profile")
        for package, tests in plan["expected"].items():
            terminals(output, package, tests)
        carrier = raced if mode == "ordinary" else native
        replacement = v.decode(carrier[str(PurePosixPath(overlay).relative_to(base))])["Replace"]
        main = str(cwd / "astrolabe/main.go")
        target = "ordinary/main.go" if mode == "ordinary" else mode + "/main-serving.go"
        if replacement.get(main) != str(base / target) or replacement.get(str(cwd / "astrolabe/serving_test.go")) != str(
            cwd / "tests/fixtures/astrolabe-serving.go.in"
        ):
            v.reject("astrolabe-endpoint-overlay")
        checkpoint(source["astrolabe/main.go"] if mode == "ordinary" else carrier[mode + "/0/main.go"], carrier[target])
        if mode == "ordinary":
            if len(replacement) != 2:
                v.reject("astrolabe-endpoint-overlay")
        else:
            original = {}
            for index in (0, 1):
                original.update(v.decode(carrier[f"{mode}/{index}/overlay.json"])["Replace"])
            original[main] = str(base / target)
            original[str(cwd / "astrolabe/serving_test.go")] = str(cwd / "tests/fixtures/astrolabe-serving.go.in")
            if replacement != original:
                v.reject("astrolabe-endpoint-overlay")
    return plan, records


def epoch(native: dict[str, bytes]) -> tuple[dict, dict]:
    """Require the exact logical-time fixture, ordinary Race and unchanged diagnostic overlays."""
    plan = v.decode(native["inputs.json"])
    if v.digest(native["source.json"]) != plan["source_sha256"] or v.digest(native["source.tar.gz"]) != plan["source_archive_sha256"]:
        v.reject("astrolabe-epoch-integrity")
    source = entry.unpack(native["source.tar.gz"])
    if {name: v.digest(data) for name, data in source.items()} != plan["files"]:
        v.reject("astrolabe-epoch-source")
    package = MODULE + "astrolabe/internal/web"
    expected = ["TestSessionEpoch", "TestSessionEpoch/missing", "TestSessionEpoch/present"]
    if plan["parents"] != ["TestSessionEpoch"] or plan["expected"] != {package: expected}:
        v.reject("astrolabe-epoch-selection")
    records = {mode: command(native, "command/" + mode + "/") for mode in ("ordinary", "typed", "controls")}
    for mode, (record, output) in records.items():
        cwd = PurePosixPath(record["resolved_environment"]["GOCACHE"]).parents[2]
        base = cwd.parent
        args = ["go", "test", "-json"]
        if mode == "ordinary":
            args += ["-race", "-covermode=atomic", "-coverprofile=" + str(base / "ordinary.cover")]
        args += ["-count=1", "-p=2", "-parallel=1", "-timeout=60s"]
        if mode != "ordinary":
            args += ["-overlay=" + str(base / mode / "combined.json")]
            if v.decode(native[mode + "/combined.json"]) != v.decode(native[mode + "/0/overlay.json"]):
                v.reject("astrolabe-epoch-overlay")
        args += ["-run=^TestSessionEpoch$", "./astrolabe/internal/web"]
        if record["argv"] != args or not 0 < record["duration_ms"] < 60000:
            v.reject("astrolabe-epoch-profile")
        terminals(output, package, expected)
    return plan, records


def combine(trace: dict, controls: dict, typed: bytes, controlled: bytes, tests: list[str], root: Path, rows: dict, edges: dict) -> None:
    """Union native masks at identical compiler coordinates while preserving unobserved operands as zero."""
    package = trace["typing"]["package"]
    values, _ = logic.observe(trace, terminals(typed, package, tests), package, len(tests))
    for identity, vectors in values.items():
        destination = rows.setdefault(identity, {})
        for key, hits in vectors.items():
            destination[key] = destination.get(key, 0) + hits
    report = flow.summary(controls, terminals(controlled, package, tests), package, len(tests), root, controls["source_sha256"])
    for edge in report["edges"]:
        prior = edges.setdefault(edge["id"], {**edge, "vectors": {}})
        if {k: x for k, x in prior.items() if k != "vectors"} != {k: x for k, x in edge.items() if k != "vectors"}:
            v.reject("astrolabe-control-geometry")
        for key, hits in edge["vectors"].items():
            prior["vectors"][key] = prior["vectors"].get(key, 0) + hits


def inventory(
    trace: dict,
    rows: dict,
    edges: dict,
    executed: set[str],
    terminal: list[dict] | None = None,
    dependency: dict[str, bytes] | None = None,
    library: dict[str, bytes] | None = None,
    membership: dict[str, bytes] | None = None,
    startup: dict[str, bytes] | None = None,
) -> dict:
    """Expose the complete denominator, certified pairs and remaining gaps without granting a gate pass."""
    terminal = terminal or []
    decisions = []
    for identity, decision in logic.inventory(trace).items():
        actual = rows[identity]
        pairs, _, complete = logic.candidates(decision, actual, logic.COMPARISONS, certify=True)
        if not complete:
            v.reject("astrolabe-proof-budget")
        decisions.append(
            {
                "id": identity,
                "text": decision["text"],
                "outcomes": sorted({result for _, result in actual}),
                "vectors": [{"values": key[0], "result": key[1], "hits": hits} for key, hits in sorted(actual.items())],
                "atoms": [
                    {
                        "index": index,
                        "text": atom["text"],
                        "outcomes": sorted({vector[index] for vector, _ in actual} - {"0"}),
                        "independent": pairs.get(index),
                    }
                    for index, atom in enumerate(decision["atoms"])
                ],
            }
        )
    extra = conditions(trace, rows, executed, dependency, library)
    if membership is not None:
        extra["source_coupling"].append(members(trace, rows, executed, membership))
    extra["source_defenses"] = defenses(trace, rows, dependency, library) if dependency is not None else []
    if startup is not None:
        extra["source_defenses"].append(cancellation(trace, rows, terminal, startup, dependency, library))
    supported = {(d["id"], a["index"]) for d in decisions for a in d["atoms"] if a["independent"] is not None}
    supported.update((p["decision"], p["condition"]) for p in extra["input_pairs"])
    supported.update((p["decision"], p["condition"]) for kind in ("guarded_pairs", "masked_pairs") for p in extra[kind])
    supported.update((p["decision"], pair["condition"]) for p in terminal for pair in p["independent"])
    excluded = {(p["decision"], p["condition"]) for p in extra["source_coupling"]}
    excluded.update((p["decision"], p["condition"]) for p in extra["source_defenses"])
    if supported & excluded:
        v.reject("astrolabe-condition-overlap")
    branch = structure.controls(
        {
            "edges": list(edges.values()),
            "without_empty": [key for key, edge in edges.items() if edge["kind"] in {"range", "for"} and "12" not in edge["vectors"]],
        }
    )
    return {
        "files": {file["file"]: file["sha256"] for file in trace["files"]},
        "roots": len(decisions),
        "both": sum(len(d["outcomes"]) == 2 for d in decisions),
        "atoms": sum(len(d["atoms"]) for d in decisions),
        "independent": sum(a["independent"] is not None for d in decisions for a in d["atoms"]),
        "decisions": decisions,
        "edges": list(edges.values()),
        "unobserved_edges": [key for key, edge in edges.items() if not edge["vectors"]],
        "controls": branch,
        "proofs": extra,
        "terminal_decisions": list(terminal),
        "supported_conditions": len(supported),
        "unresolved_conditions": [
            {"decision": d["id"], "condition": a["index"], "text": a["text"]}
            for d in decisions
            for a in d["atoms"]
            if (d["id"], a["index"]) not in supported | excluded
        ],
    }


def acquisition(root: Path, data: bytes, seal: dict) -> tuple[dict[str, bytes], dict, bytes]:
    """Bind the current-source Race campaign's own format, without relaxing older collector schemas."""
    if v.digest(data) != BASELINE or seal.get("archive_sha256") != BASELINE or seal.get("bytes") != len(data) or seal.get("trust") != "local":
        v.reject("astrolabe-acquisition-integrity")
    files = entry.unpack(data)
    if set(files) != set(seal.get("files", {})) or any(
        seal["files"][name] != {"bytes": len(content), "sha256": v.digest(content)} for name, content in files.items()
    ):
        v.reject("astrolabe-acquisition-members")
    owner, cleanup, terminal, preflight, inputs = (
        v.decode(files[name + ".json"]) for name in ("controller", "cleanup.native", "terminal", "preflight", "inputs")
    )
    service = cleanup["service"]
    if (
        owner["script_sha256"] != v.digest(files["run.py"])
        or owner["identity"] not in cleanup["retired"]
        or owner["boot_id"] != cleanup["boot_id"]
        or service["InvocationID"] != owner["invocation_id"]
        or any(service[key] != value for key, value in {"MainPID": "0", "ControlGroup": "", "ExecMainStatus": "0", "SubState": "exited"}.items())
        or terminal["errors"]
        or terminal["remaining_owned"]
        or terminal["interrupted"] is not False
        or terminal["source_unchanged"] is not True
    ):
        v.reject("astrolabe-acquisition-owner")
    resource = dict(line.split() for line in terminal["resources"]["memory.events"].splitlines())
    if any(resource.get(key) != "0" for key in ("max", "oom", "oom_kill", "oom_group_kill")):
        v.reject("astrolabe-acquisition-resources")
    for name, digest in inputs["files"].items():
        if name.endswith(".go") or name in {"go.mod", "go.sum", "dependencies.lock.json"}:
            if v.digest(files["source/" + name]) != digest or v.file_digest(v.inside(root, name)) != digest:
                v.reject("astrolabe-acquisition-source", name)
    prefix = "source/build/commands/acquisition-green/"
    record = v.decode(files[prefix + "record.json"])
    v.schema(record, "evidence", ("properties", "checks", "items"))
    child = v.decode(files[prefix + record["id"] + ".process.json"])
    original = "/home/ubuntu/verdandi/astra/build/results/assurance/reuse-material-2/source"
    if (
        record["argv"]
        != [
            "go",
            "test",
            "-json",
            "-race",
            "-count=1",
            "-p=2",
            "-parallel=1",
            "-timeout=180s",
            "-covermode=atomic",
            "-coverprofile=" + original + "/build/commands/acquisition-green/affected.cover",
            "./internal/admission",
            "./astrolabe/...",
            "./polaris/...",
        ]
        or record["exit_code"] != 0
        or record["complete"] is not True
        or record["cleanup"] is not True
        or record["termination"] != "exited"
        or record["platform"] != "linux-amd64-cgo"
        or record["executable_sha256"] != GO
        or record["executable_sha256"] != preflight["tools"].get(record["executable"])
        or any(item["sha256"] != preflight["tools"].get(item["path"]) for item in record["toolchain"].values())
        or child["identity"] not in cleanup["retired"]
        or child["boot_id"] != cleanup["boot_id"]
        or child["cwd"] != original
        or child["argv"] != record["argv"]
        or v.stamp(record["finished_at"]) < v.stamp(record["started_at"])
    ):
        v.reject("astrolabe-acquisition-command")
    for channel in ("stdout", "stderr"):
        ref = record[channel]
        raw = files[prefix + ref["path"]]
        if ref["bytes"] != len(raw) or ref["sha256"] != v.digest(raw):
            v.reject("astrolabe-acquisition-stream")
    stream = files[prefix + record["stdout"]["path"]]
    events = [v.decode(line) for line in stream.splitlines()]
    if any(row.get("Action") in {"fail", "skip"} for row in events):
        v.reject("astrolabe-acquisition-lifecycle")
    packages = {MODULE + name for name in (*PACKAGES, "internal/admission", "polaris", "polaris/internal/server", "polaris/internal/storage")}
    if {row.get("Package") for row in events} != packages or {
        row["Package"] for row in events if row.get("Action") == "pass" and "Test" not in row
    } != packages:
        v.reject("astrolabe-acquisition-packages")
    for package in packages:
        tests = [row["Test"] for row in events if row.get("Package") == package and row.get("Action") == "pass" and "Test" in row]
        terminals(stream, package, tests)
    return files, record, stream


def merge(primary: list[dict], addition: list[dict], *, checkpoint: bool = False) -> list[dict]:
    """Union only hit presence at exact compiler coordinates; a known empty select arm may move columns."""
    shape = lambda rows: {(row["file"], tuple(row["span"])): row["statements"] for row in rows}
    before, after = shape(primary), shape(addition)
    if len(before) != len(primary) or len(after) != len(addition):
        v.reject("astrolabe-statement-duplicates")
    removed, added = set(before) - set(after), set(after) - set(before)
    if checkpoint:
        if removed != {("astrolabe/main.go", (153, 23, 153, 23))} or added != {("astrolabe/main.go", (153, 44, 153, 44))}:
            v.reject("astrolabe-statement-checkpoint")
        if any(before[key] for key in removed) or any(after[key] for key in added):
            v.reject("astrolabe-statement-empty-weight")
    elif removed or added:
        v.reject("astrolabe-statement-inventory")
    if any(before[key] != after[key] for key in set(before) & set(after)):
        v.reject("astrolabe-statement-weights")
    index = {(row["file"], tuple(row["span"])): row for row in addition}
    return [{**row, "count": max(row["count"], index.get((row["file"], tuple(row["span"])), row)["count"])} for row in primary]


def counters(root: Path, baseline: dict[str, bytes], stream: bytes, stop: dict[str, bytes], report: dict) -> dict:
    """Reconstruct all current statement blocks, normal-exit child profiles and the bounded scheduling supplement."""
    inputs = v.decode(baseline["inputs.json"])
    files = {name: {"data": baseline["source/" + name]} for name in inputs["files"] if name.endswith(".go") and not name.endswith("_test.go")}
    selected = {MODULE + name: name for name in files}
    raw = baseline["source/build/commands/acquisition-green/affected.cover"]
    mode, blocks, _ = statements.profile(raw, files, selected)
    owned = [row for row in blocks if row["file"].startswith("astrolabe/")]
    shape = [{key: row[key] for key in ("file", "span", "statements")} for row in owned]
    expected = {name for item in report["scope"].values() for name in item["files"]}
    if mode != "atomic" or {row["file"] for row in owned} != expected or v.digest(v.encode(shape)) != STATEMENTS:
        v.reject("astrolabe-statement-denominator")
    events = []
    for line in stream.splitlines():
        row = v.decode(line)
        if row.get("Package") == MODULE + "astrolabe" and ("Test" not in row or row["Test"] == "TestProcess" or row["Test"].startswith("TestProcess/")):
            events.append((line, row))
    projected = b"\n".join(line for line, _ in events) + b"\n"
    boot = v.decode(baseline["controller.json"])["boot_id"]
    children = processes(projected, boot)
    outputs = {}
    for _, event in events:
        if event.get("Action") == "output":
            name = event.get("Test", "")
            outputs[name] = outputs.get(name, "") + event.get("Output", "")
    profiles = {}
    for name, output in outputs.items():
        for line in output.splitlines():
            if "ASTROLABE-ENTRY-PROFILE " in line:
                if name in profiles or not name.startswith("TestProcess/"):
                    v.reject("astrolabe-statement-child-owner")
                profiles[name] = base64.b64decode(line.split("ASTROLABE-ENTRY-PROFILE ", 1)[1].strip(), validate=True)
    if set(profiles) != {"TestProcess/" + name for name, values in EXITS.items() if values[0] == 0}:
        v.reject("astrolabe-statement-child-inventory")
    main = [row for row in owned if row["file"] == "astrolabe/main.go"]
    for data in profiles.values():
        kind, rows, _ = statements.profile(data, files, selected)
        if kind != "atomic" or any(row["file"] != "astrolabe/main.go" for row in rows):
            v.reject("astrolabe-statement-child-profile")
        main = merge(main, rows)
    baseline_hit = sum(row["statements"] for row in owned if row["count"])
    main_before = {tuple(row["span"]): row for row in main}
    original = files["astrolabe/main.go"]["data"]
    patched = stop["ordinary/main.go"]
    checkpoint(original, patched, stopping=True)
    ordinary, _ = command(stop, "source/build/commands/ordinary/")
    if not all(flag in ordinary["argv"] for flag in ("-race", "-count=1", "-covermode=atomic", "-run=^(TestStopBody|TestStopResult)$")):
        v.reject("astrolabe-statement-stop-command")
    kind, supplement, _ = statements.profile(
        stop["source/build/commands/ordinary/stop.cover"], {"astrolabe/main.go": {"data": patched}}, {MODULE + "astrolabe/main.go": "astrolabe/main.go"}
    )
    if kind != "atomic":
        v.reject("astrolabe-statement-stop-profile")
    main = merge(main, supplement, checkpoint=True)
    joined = {tuple(row["span"]): row for row in main}
    owned = [joined[tuple(row["span"])] if row["file"] == "astrolabe/main.go" else row for row in owned]
    missing = [row for row in owned if row["statements"] and not row["count"]]
    if {(row["file"], tuple(row["span"]), row["statements"]) for row in missing} != {(name, span, weight) for _, name, span, weight in UNHIT}:
        v.reject("astrolabe-statement-uncovered")
    proofs = {p["id"]: p for item in report["scope"].values() for p in item["proofs"]["source_defenses"]}
    if any(name not in proofs or proofs[name]["impossible_outcome"] is not True for name, *_ in UNHIT):
        v.reject("astrolabe-statement-defense")
    return {
        "raw": sum(row["statements"] for row in owned),
        "native_observed": sum(row["statements"] for row in owned if row["count"]),
        "original_parent_observed": baseline_hit,
        "ordinary_child_additions": sum(row["statements"] for row in main_before.values() if row["count"])
        - sum(row["statements"] for row in blocks if row["file"] == "astrolabe/main.go" and row["count"]),
        "checkpoint_additions": [row for row in main if row["statements"] and row["count"] and not main_before[tuple(row["span"])]["count"]],
        "conditional_excluded": sum(row["statements"] for row in missing),
        "unhit": [{"id": name, "file": path, "span": list(span), "statements": weight, "proof": proofs[name]} for name, path, span, weight in UNHIT],
        "geometry_sha256": STATEMENTS,
        "profile_sha256": v.digest(raw),
        "child_profiles": {name: v.digest(data) for name, data in profiles.items()},
        "child_receipts": children,
        "blocks": owned,
        "boundary": "Only matching native compiler-block hit presence is joined. Seven source-bound defense statements remain unexecuted; the scheduling checkpoint changes only the empty parent arm's columns.",
    }


def outcomes(report: dict) -> dict:
    """Keep native root/operand outcomes, terminal inferences and impossible evaluated outcomes separate."""
    raw_roots = raw_atoms = native_roots = native_atoms = 0
    missing_roots, missing_atoms, inferred_roots, inferred_atoms = set(), set(), set(), set()
    excluded_atoms, excluded_roots = set(), set()
    for scope in report["scope"].values():
        terminals = {item["decision"]: item for item in scope["terminal_decisions"]}
        if len(terminals) != len(scope["terminal_decisions"]):
            v.reject("astrolabe-structure-terminal")
        for decision in scope["decisions"]:
            identity = decision["id"]
            roots = set(decision["outcomes"])
            if any(type(value) is not bool for value in roots) or len(roots) != len(decision["outcomes"]):
                v.reject("astrolabe-structure-root")
            raw_roots += 2
            native_roots += len(roots)
            values = terminals.get(identity)
            if values:
                if (
                    type(values["result"]) is not bool
                    or len(values["values"]) != len(decision["atoms"])
                    or any(value not in "012" for value in values["values"])
                ):
                    v.reject("astrolabe-structure-terminal")
                inferred_roots.update((identity, value) for value in {values["result"]} - roots)
                roots.add(values["result"])
            missing_roots.update((identity, value) for value in {False, True} - roots)
            for ordinal, atom in enumerate(decision["atoms"]):
                index = atom["index"]
                observed = set(atom["outcomes"])
                if index != ordinal or not observed <= {"1", "2"} or len(observed) != len(atom["outcomes"]):
                    v.reject("astrolabe-structure-atom")
                raw_atoms += 2
                native_atoms += len(observed)
                if values and values["values"][index] != "0":
                    derived = values["values"][index]
                    inferred_atoms.update((identity, index, value) for value in {derived} - observed)
                    observed.add(derived)
                missing_atoms.update((identity, index, value) for value in {"1", "2"} - observed)
        for proof in scope["proofs"]["source_defenses"]:
            excluded_atoms.add((proof["decision"], proof["condition"], "2" if proof["impossible_outcome"] else "1"))
            decision = next(item for item in scope["decisions"] if item["id"] == proof["decision"])
            if len(decision["atoms"]) == 1:
                excluded_roots.add((decision["id"], proof["impossible_outcome"]))
    if missing_atoms != excluded_atoms or missing_roots != excluded_roots:
        v.reject("astrolabe-structure-outcomes")
    return {
        "raw_roots": raw_roots,
        "raw_atoms": raw_atoms,
        "native_roots": native_roots,
        "native_atoms": native_atoms,
        "inferred_roots": sorted(inferred_roots),
        "inferred_atoms": sorted(inferred_atoms),
        "excluded_roots": sorted(excluded_roots),
        "excluded_atoms": sorted(excluded_atoms),
    }


def artifacts(*, structural: bool = False) -> dict[str, str | None]:
    """Name every retained byte input; seals are verified against their pinned native archives."""
    return {
        **{name + "/evidence.tar.gz": digest for name, digest in ARCHIVES.items()},
        **{name + "/sealed.native.json": None for name in ARCHIVES if name != "admission-structure"},
        "material-stop/dependency-extra.tar.gz": EXTRA,
        "material-stop/dependency-extra.json": None,
        "material-crypto/sources.tar.gz": LIBRARY_ARCHIVE,
        "material-crypto/sources.json": None,
        **({"material-2/evidence.tar.gz": BASELINE, "material-2/sealed.native.json": None} if structural else {}),
    }


def materials(directory: Path | dict[str, bytes], *, structural: bool = False) -> dict[str, bytes]:
    """Consume bounded verified bytes directly, avoiding a second path lookup after artifact validation."""
    expected = artifacts(structural=structural)
    if isinstance(directory, dict):
        if set(directory) != set(expected) or any(not isinstance(data, bytes) or len(data) > entry.LIMIT for data in directory.values()):
            v.reject("astrolabe-retained-inventory")
        files = directory
    else:
        files = {name: v.read(v.inside(directory, name), entry.LIMIT) for name in expected}
    if sum(map(len, files.values())) > entry.LIMIT:
        v.reject("astrolabe-retained-capacity")
    for name, digest in expected.items():
        if digest is not None and v.digest(files[name]) != digest:
            v.reject("astrolabe-retained-integrity", name)
    return files


def qualify(report: dict, *, structural: bool = False) -> dict:
    """Qualify one reviewed dimension after native reconciliation; other obligations stay open."""
    if set(report["scope"]) != set(GEOMETRY) or report["application_commands_executed"] != 0 or len(report["source_inputs"]) != 157:
        v.reject("astrolabe-component-scope")
    tests = []
    for package, geometry in GEOMETRY.items():
        item = report["scope"][package]
        actual = (
            item["roots"],
            item["atoms"],
            item["supported_conditions"],
            len(item["proofs"]["source_coupling"]),
            len(item["proofs"]["source_defenses"]),
            item["controls"]["required"],
        )
        if actual != geometry:
            v.reject("astrolabe-component-denominator", package)
        if item["unresolved_conditions"] or item["unobserved_edges"] or item["controls"]["missing"] or item["controls"]["observed"] != geometry[-1]:
            v.reject("astrolabe-component-uncovered", package)
        tests.extend(package + ":" + name for name in item["native_tests"])
    tests.sort()
    if len(tests) != 468 or v.digest(v.encode(tests)) != TESTS:
        v.reject("astrolabe-native-inventory")
    result = {
        **report,
        "status": "complete-under-assumptions",
        "qualification": "local-component-mcdc",
        "native_tests": tests,
        "independence": {"roots": 184, "raw_conditions": 366, "supported_conditions": 334, "source_coupling": 18, "source_defenses": 14},
        "boundary": "Local source-bound MC/DC only. Exclusions are not execution hits. Structural, mutation, fault, delivery, protected CI and release obligations remain independent.",
    }
    if structural:
        counters, boolean = report["statements"], report["structural_outcomes"]
        counts = [
            counters["native_observed"],
            boolean["native_roots"],
            boolean["native_atoms"],
            sum(item["controls"]["observed"] for item in report["scope"].values()),
        ]
        if (
            counts != [818, 361, 715, 73]
            or [counters["raw"], boolean["raw_roots"], boolean["raw_atoms"]] != [825, 368, 732]
            or counters["conditional_excluded"] != 7
            or counters["geometry_sha256"] != STATEMENTS
            or [len(boolean[key]) for key in ("inferred_roots", "inferred_atoms", "excluded_roots", "excluded_atoms")] != [2, 3, 5, 14]
        ):
            v.reject("astrolabe-structure-denominator")
        result.update(
            qualification="local-component-structure",
            structure={"native_counts": counts, "native_observations": sum(counts), "terminal_inferences": 5, "excluded": [7, 5, 14]},
            boundary="Local source-bound structure only. The 1,967 observations are native statement/root/operand/control hits; five terminal inferences and all impossible-outcome assumptions remain separate. Mutation, faults, delivery, protected CI and release are independent.",
        )
    return result


def reconcile(root: Path, directory: Path | dict[str, bytes], *, structural: bool = False) -> dict:
    """Replay the reviewed component campaigns; source mutation never inherits the predecessor's coordinates."""
    files = materials(directory, structural=structural)
    facts = {}
    for name, digest in ARCHIVES.items():
        raw = files[name + "/evidence.tar.gz"]
        if name == "admission-structure":
            if v.digest(raw) != digest:
                v.reject("astrolabe-historical-inputs")
            facts[name] = entry.unpack(raw)
        else:
            facts[name] = retained(raw, v.decode(files[name + "/sealed.native.json"]), digest)
    latest, account, stop = (facts[name] for name in ("material-boundaries-2", "material-account", "material-stop"))
    addition = facts["material-isolation"]
    added = v.decode(addition["inputs.json"])
    endpoint = facts["material-endpoints-3"]
    endpoint_plan, endpoint_records = endpoints(endpoint, facts["material-endpoints-2"])
    timed = facts["material-epoch"]
    timed_plan, timed_records = epoch(timed)
    dependency = dependencies(stop, files["material-stop/dependency-extra.tar.gz"], v.decode(files["material-stop/dependency-extra.json"]))
    library = libraries(endpoint, files["material-crypto/sources.tar.gz"], v.decode(files["material-crypto/sources.json"]))
    plan = v.decode(latest["inputs.json"])
    identity = sources(root, timed_plan)
    if any(identity.get(name) != digest for prior in (added, endpoint_plan) for name, digest in prior["files"].items() if name in identity):
        v.reject("astrolabe-endpoint-prior-inputs")
    for native in (account, latest, addition):
        declared = v.decode(native["inputs.json"])
        if v.digest(native["source.json"]) != declared["source_sha256"] or v.digest(native["source.tar.gz"]) != declared["source_archive_sha256"]:
            v.reject("astrolabe-input-integrity")
    old = [facts[name] for name in list(ARCHIVES)[:4]]
    plans = [v.decode(native["inputs.json"]) for native in old]
    for declared in plans:
        frozen = {item["path"]: item["sha256"] for item in declared["windows_source"]["files"]}
        frozen.update({name: item["sha256"] for name, item in declared["fixtures"].items()})
        for name, digest in frozen.items():
            # The reviewed process fixture later added child profile collection.
            # No total-input proof below relies on TestProcess or its helper.
            if name.startswith("astrolabe/") and name.endswith("_test.go") and name != "astrolabe/process_test.go" and identity.get(name) != digest:
                v.reject("astrolabe-fixture-drift", name)
    historic = entry.unpack(facts["admission-structure"]["inputs.tar.gz"])
    previous = {name: data for name, data in historic.items() if name.startswith("astrolabe/") and name.endswith(".go") and not name.endswith("_test.go")}
    if len(previous) != 8:
        v.reject("astrolabe-historical-scope")
    process = old[2]
    fixture = plans[2]["fixtures"]["astrolabe/process_test.go"]
    if fixture["sha256"] != PROCESS or v.digest(process[fixture["file"]]) != PROCESS or identity.get("astrolabe/process_test.go") != PROCESS:
        v.reject("astrolabe-process-fixture")
    boot = v.decode(process["controller.json"])["boot_id"]
    process_records = {name: processes(command(process, "command/" + name + "/")[1], boot) for name in ("ordinary", "typed", "controls")}
    reports = {}
    (root / "build").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=root / "build", prefix="astrolabe-reader-") as temporary:
        historical = Path(temporary)
        for name, data in previous.items():
            path = v.inside(historical, name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        for index, package in enumerate(PACKAGES):
            trace = v.decode(old[0][f"typed/{index}/trace.json"])
            controls = v.decode(old[0][f"controls/{index}/flow.json"])
            for file in trace["files"]:
                if v.digest(previous[file["file"]]) != file["sha256"] or file["file"] != ACCOUNT and v.file_digest(root / file["file"]) != file["sha256"]:
                    v.reject("astrolabe-retained-source")
            rows, edges, executed = {}, {}, set()
            for native, declared in zip(old, plans, strict=True):
                expected = declared["expected"].get(MODULE + package)
                if expected:
                    combine(trace, controls, command(native, "command/typed/")[1], command(native, "command/controls/")[1], expected, historical, rows, edges)
                    executed.update(expected)
            if index == 0:
                if v.decode(stop["typed/trace.json"]) != trace or v.decode(stop["controls/flow.json"]) != controls:
                    v.reject("astrolabe-stop-geometry")
                expected = ["TestStopBody", "TestStopResult", *("TestStopResult/" + str(i) for i in range(32))]
                executed.update(expected)
                combine(
                    trace,
                    controls,
                    command(stop, "source/build/commands/typed/")[1],
                    command(stop, "source/build/commands/controls/")[1],
                    expected,
                    historical,
                    rows,
                    edges,
                )
            if index == 2:
                rows = {key: value for key, value in rows.items() if not key.startswith(ACCOUNT + ":")}
                edges = {key: value for key, value in edges.items() if not key.startswith(ACCOUNT + ":")}
                current, current_controls = v.decode(account["typed/trace.json"]), v.decode(account["controls/flow.json"])
                if any(
                    before["file"] != after["file"] or before["file"] != ACCOUNT and before != after
                    for before, after in zip(trace["files"], current["files"], strict=True)
                ):
                    v.reject("astrolabe-account-geometry")
                trace, controls = current, current_controls
                expected = v.decode(account["inputs.json"])["expected"]
                executed.update(expected)
                combine(trace, controls, command(account, "command/typed/")[1], command(account, "command/controls/")[1], expected, root, rows, edges)
            if index:
                current, current_controls = v.decode(latest[f"typed/{index - 1}/trace.json"]), v.decode(latest[f"controls/{index - 1}/flow.json"])
                if (
                    current["files"] != trace["files"]
                    or current_controls["files"] != controls["files"]
                    or current["source_sha256"] != plan["source_sha256"]
                    or current_controls["source_sha256"] != plan["source_sha256"]
                    or current["typing"]["metadata_sha256"] != v.digest(command(latest, "command/exports/")[1])
                    or current["typing"]["package"] != MODULE + package
                    or current["typing"]["files"] != trace["typing"]["files"]
                ):
                    v.reject("astrolabe-current-geometry")
                typed, controlled = (command(latest, "command/" + name + "/") for name in ("typed", "controls"))
                # The closed-view fixture's untouched age predicate stays false
                # only while the whole native command remains below its TTL.
                if any(not 0 < record["duration_ms"] < 15000 for record, _ in (typed, controlled)):
                    v.reject("astrolabe-closed-view-age")
                combine(
                    current,
                    current_controls,
                    typed[1],
                    controlled[1],
                    plan["expected"][MODULE + package],
                    root,
                    rows,
                    edges,
                )
                executed.update(plan["expected"][MODULE + package])
            current = v.decode(addition[f"typed/{index}/trace.json"])
            current_controls = v.decode(addition[f"controls/{index}/flow.json"])
            if (
                current["files"] != trace["files"]
                or current_controls["files"] != controls["files"]
                or current["source_sha256"] != added["source_sha256"]
                or current_controls["source_sha256"] != added["source_sha256"]
                or current["typing"]["metadata_sha256"] != v.digest(command(addition, "command/exports/")[1])
                or current["typing"]["package"] != MODULE + package
                or current["typing"]["files"] != trace["typing"]["files"]
            ):
                v.reject("astrolabe-supplement-geometry")
            expected = added["expected"][MODULE + package]
            records = {mode: command(addition, "command/" + mode + "/") for mode in ("ordinary", "typed", "controls")}
            for mode, (record, output) in records.items():
                terminals(output, MODULE + package, expected)
                if ("-race" in record["argv"]) != (mode == "ordinary") or not 0 < record["duration_ms"] < 15000:
                    v.reject("astrolabe-supplement-profile")
            combine(current, current_controls, records["typed"][1], records["controls"][1], expected, root, rows, edges)
            executed.update(expected)
            if index != 1:
                number = 0 if index == 0 else 1
                current = v.decode(endpoint[f"typed/{number}/trace.json"])
                current_controls = v.decode(endpoint[f"controls/{number}/flow.json"])
                if (
                    current["files"] != trace["files"]
                    or current_controls["files"] != controls["files"]
                    or current["source_sha256"] != endpoint_plan["source_sha256"]
                    or current_controls["source_sha256"] != endpoint_plan["source_sha256"]
                    or current["typing"]["metadata_sha256"] != v.digest(command(endpoint, "command/exports/")[1])
                    or current["typing"]["package"] != MODULE + package
                    or current["typing"]["files"] != trace["typing"]["files"]
                ):
                    v.reject("astrolabe-endpoint-geometry")
                expected = endpoint_plan["expected"][MODULE + package]
                combine(current, current_controls, endpoint_records["typed"][1], endpoint_records["controls"][1], expected, root, rows, edges)
                executed.update(expected)
            if v.digest(v.encode(trace["files"])) != FORESTS[index]:
                v.reject("astrolabe-forest-denominator")
            if index == 2:
                current, current_controls = v.decode(timed["typed/0/trace.json"]), v.decode(timed["controls/0/flow.json"])
                if (
                    current["files"] != trace["files"]
                    or current_controls["files"] != controls["files"]
                    or current["source_sha256"] != timed_plan["source_sha256"]
                    or current_controls["source_sha256"] != timed_plan["source_sha256"]
                    or current["typing"]["metadata_sha256"] != v.digest(command(timed, "command/exports/")[1])
                    or current["typing"]["package"] != MODULE + package
                    or current["typing"]["files"] != trace["typing"]["files"]
                ):
                    v.reject("astrolabe-epoch-geometry")
                expected = timed_plan["expected"][MODULE + package]
                combine(current, current_controls, timed_records["typed"][1], timed_records["controls"][1], expected, root, rows, edges)
                executed.update(expected)
            reports[package] = inventory(
                trace,
                rows,
                edges,
                executed,
                exits(trace, rows, process_records["typed"], library) if index == 0 else (),
                dependency,
                library,
                {name: v.read(root / name) for name in MEMBERS} if index == 1 else None,
                {name: v.read(root / name) for name in STARTUP} if index == 0 else None,
            )
            reports[package]["native_tests"] = sorted(executed)
    report = {
        "qualification": "not-evaluated",
        "application_commands_executed": 0,
        "archives": ARCHIVES,
        "dependency_archive": EXTRA,
        "dependencies": {name: v.digest(data) for name, data in sorted(dependency.items())},
        "library_archive": LIBRARY_ARCHIVE,
        "libraries": {name: v.digest(data) for name, data in sorted(library.items())},
        "source_inputs": identity,
        "process_receipts": process_records,
        "scope": reports,
        "boundary": "Retained local diagnostics only. Original source and command identities remain unchanged. Missing paths, input proofs, source assumptions and formal qualification remain explicit; no component or release pass is inferred.",
    }
    if structural:
        baseline, _, stream = acquisition(root, files["material-2/evidence.tar.gz"], v.decode(files["material-2/sealed.native.json"]))
        report["statements"] = counters(root, baseline, stream, stop, report)
        report["structural_outcomes"] = outcomes(report)
    return report
