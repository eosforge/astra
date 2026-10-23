// Verify SDK configuration admission and bounded CA files without starting a network or control loop.
#include "check.hpp"
#include "core.hpp"
#include "utf8.hpp"

#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

namespace {
using namespace std::chrono_literals;

/// Supply one valid anonymous plaintext input; each case starts independently from this public configuration.
comet::Client::Options options() {
    comet::Client::Options value;
    value.endpoints = {"127.0.0.1:1"};
    value.auth = false;
    value.tls = false;
    return value;
}

/// Check real local admission, stable rejection effects and absence of private transport/control-loop activity.
void observe(std::string_view name, comet::Client::Options value, bool accepted) {

    const auto before = astra::test::checks.hits.load(); // Native successful assertions are emitted separately from case outcomes.
    const auto prepared = comet::detail::Core::prepare(value);
    CHECK(prepared.has_value() == accepted);
    if (prepared) {
        const auto schedule = (*prepared)->schedule();
        CHECK(schedule.directory == 0 && schedule.ready == 0 && schedule.polled == 0);
        CHECK(!(*prepared)->stopped());
    } else {
        CHECK(prepared.error().code == comet::Error::Code::Input && prepared.error().effect == comet::Error::Effect::Unapplied);
        CHECK(prepared.error().instance.empty() && !prepared.error().version && prepared.error().retry == 0ms);
        const auto opened = comet::Client::open(std::move(value)); // Rejected public inputs must stop before asynchronous startup too.
        CHECK(!opened && opened.error().code == comet::Error::Code::Input && opened.error().effect == comet::Error::Effect::Unapplied);
        CHECK(opened.error().instance.empty() && !opened.error().version && opened.error().retry == 0ms);
    }
    std::cout << "COMET-OPTIONS {\"case\":\"" << name << "\",\"accepted\":" << (prepared ? "true" : "false") << ",\"hits\":" << astra::test::checks.hits.load() - before << "}\n";
}

/// Change exactly one input field from an independently accepted baseline before requiring local rejection.
template <class Change>
void reject(std::string_view name, Change change, comet::Client::Options value = options()) {

    observe(std::string(name) + "-baseline", value, true);
    change(value);
    observe(name, std::move(value), false);
}

/// Exercise literal documented size limits rather than deriving expected outcomes from production predicates.
void capacity() {

    // Each field is varied independently; maximum values must not allocate the declared payload budget.
    struct Bound {
        /// Case identity, not a production rule name.
        std::string_view name;
        /// One public numeric option changed by this group.
        std::size_t comet::Client::Options::* field;
        /// Minimum, default and maximum accepted values from the public contract.
        std::array<std::size_t, 3> valid;
        /// Immediate boundary violations and representation maximum.
        std::array<std::size_t, 3> invalid;
    };

    const std::array bounds{
        Bound{"readers", &comet::Client::Options::readers, {1, 64, 4096}, {0, 4097, std::numeric_limits<std::size_t>::max()}},
        Bound{"beacons", &comet::Client::Options::beacons, {1, 1024, 65536}, {0, 65537, std::numeric_limits<std::size_t>::max()}},
        Bound{"bytes", &comet::Client::Options::bytes, {16384, 268435456, 4294967296ULL}, {16383, 4294967297ULL, std::numeric_limits<std::size_t>::max()}}};
    for (const auto& bound : bounds) {
        for (std::size_t index = 0; index < bound.valid.size(); ++index) {
            auto value = options();
            value.*bound.field = bound.valid[index];
            observe(std::string(bound.name) + "-valid-" + std::to_string(index), std::move(value), true);
        }
        for (std::size_t index = 0; index < bound.invalid.size(); ++index) {
            reject(std::string(bound.name) + "-invalid-" + std::to_string(index), [&bound, index](auto& value) { value.*bound.field = bound.invalid[index]; });
        }
    }

    // Duration input includes both immediate neighbors and the largest signed millisecond representation.
    for (const auto timeout : {1ms, 3000ms, 60000ms}) {
        auto value = options();
        value.timeout = timeout;
        observe("timeout-valid-" + std::to_string(timeout.count()), std::move(value), true);
    }
    for (const auto timeout : {-1ms, 0ms, 60001ms, std::chrono::milliseconds::max()}) {
        reject("timeout-invalid-" + std::to_string(timeout.count()), [timeout](auto& value) { value.timeout = timeout; });
    }
}

/// Reject empty, excessive, duplicate, malformed and normalization-equivalent destinations independently.
void endpoints() {

    observe("endpoint-one", options(), true);
    auto value = options();
    value.endpoints.clear();
    for (unsigned index = 0; index < 64; ++index) {
        value.endpoints.push_back("127.0.0.1:" + std::to_string(index + 1));
    }
    observe("endpoint-64", value, true);
    reject("endpoint-65", [](auto& next) { next.endpoints.push_back("127.0.0.1:65"); }, value);
    reject("endpoint-empty", [](auto& next) { next.endpoints.clear(); });
    reject("endpoint-duplicate", [](auto& next) { next.endpoints.push_back(next.endpoints.front()); });
    reject("endpoint-normalized-duplicate", [](auto& next) { next.endpoints = {"[::1]:1", "[0:0:0:0:0:0:0:1]:1"}; });
    for (const auto endpoint : {"", "127.0.0.1", ":1", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:-1", "127.0.0.1:1x", "-host:1", "host-:1", "host..name:1"}) {
        reject("endpoint-invalid-" + std::to_string(std::string_view(endpoint).size()) + '-' + std::string(endpoint), [endpoint](auto& next) { next.endpoints = {endpoint}; });
    }
    value.endpoints = {"localhost:1", "[::1]:65535"};
    observe("endpoint-dns-ipv6", std::move(value), true);
}

/// Vary each authentication operand while preserving the other valid inputs and the selected authentication mode.
void authentication() {

    auto value = options();
    value.auth = true;
    value.key = "k";
    value.secret = {0}; // Secrets are opaque bytes; a single zero byte is still present material.
    observe("auth-minimum", value, true);
    reject("auth-key-empty", [](auto& next) { next.key.clear(); }, value);
    reject("auth-key-129", [](auto& next) { next.key.assign(129, 'k'); }, value);
    reject("auth-key-nul", [](auto& next) { next.key = std::string("k\0x", 3); }, value);
    reject("auth-key-utf8", [](auto& next) { next.key = std::string("\xc0\x80", 2); }, value);
    reject("auth-secret-empty", [](auto& next) { next.secret.clear(); }, value);
    reject("auth-secret-4097", [](auto& next) { next.secret.assign(4097, 0x80); }, value);
    value.key.assign(128, 'k');
    value.secret.assign(4096, 0xff);
    observe("auth-maximum", value, true);
    value.key = std::string("\xe7\x94\xa8\xe6\x88\xb7", 6);
    observe("auth-unicode", std::move(value), true);

    reject("anonymous-key", [](auto& next) { next.key = "k"; });
    reject("anonymous-secret", [](auto& next) { next.secret = {0}; });
    reject("plaintext-ca", [](auto& next) { next.ca = "unused.pem"; });
    value = options();
    value.tls = true; // Local credential preparation may use system trust, but never dials this endpoint.
    observe("tls-system-roots", std::move(value), true);
}

/// Exercise the SDK-linked decoder through real credential admission without starting asynchronous work.
void keys() {

    auto value = options();
    value.auth = true;
    value.secret = {0};
    std::size_t cases = 0;
    for (const auto& text : astra::test::texts) {
        value.key = text.bytes;
        observe("key-encoding-" + std::to_string(cases++), value, text.accepted);
    }
    CHECK(cases == 38);

    // Literal boundary bytes anchor the independent encoder before the SDK accepts each legal scalar.
    for (const auto& [scalar, bytes] : astra::test::scalars) {
        CHECK(astra::test::encoded(scalar) == bytes);
        value.key = bytes;
        observe("key-scalar-" + std::to_string(scalar), value, true);
    }
    std::cout << "COMET-UTF8 {\"literal_cases\":" << cases << ",\"scalar_boundaries\":" << astra::test::scalars.size() << "}\n";
}

/// Own exactly one generated file in a freshly claimed child of the runner's temporary directory.
class Files {
public:
    Files() : root_(std::filesystem::temp_directory_path() / "comet-options"), file_(root_ / "ca.pem") {
        CHECK(std::filesystem::create_directory(root_));
    }

    ~Files() {
        std::error_code error; // Fallback unwinding removes only paths this fixture successfully claimed.
        std::filesystem::remove(file_, error);
        std::filesystem::remove(root_, error);
    }

    Files(const Files&) = delete;
    Files& operator=(const Files&) = delete;

    /// Return the claimed directory for a nonregular-input case.
    const std::filesystem::path& root() const noexcept {
        return root_;
    }

    /// Replace only this fixture's generated file, checking the complete write before CA admission.
    const std::filesystem::path& write(std::string_view content) const {
        std::ofstream output(file_, std::ios::binary | std::ios::trunc);
        CHECK(output.is_open());
        output.write(content.data(), static_cast<std::streamsize>(content.size()));
        output.close();
        CHECK(!output.fail() && std::filesystem::file_size(file_) == content.size());
        return file_;
    }

    /// Verify successful resource retirement before reporting the test complete.
    void finish() const {
        CHECK(std::filesystem::remove(file_));
        CHECK(std::filesystem::remove(root_));
    }

private:
    /// Fresh directory ownership prevents deleting preexisting files from another test.
    const std::filesystem::path root_;
    /// Only generated path this fixture may replace or remove.
    const std::filesystem::path file_;
};

/// Test real filesystem rejection and inclusive CA byte limits using the existing public certificate fixture.
void certificates(const std::filesystem::path& certificate) {

    Files files;
    std::ifstream input(certificate, std::ios::binary); // Read only explicitly supplied public fixture material.
    CHECK(input.is_open());
    std::string pem((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    CHECK(!input.bad() && !pem.empty() && pem.size() < 1048576 && pem.find("PRIVATE KEY") == std::string::npos);
    auto value = options();
    value.tls = true;
    value.ca = certificate;
    observe("ca-public", value, true);
    reject("ca-missing", [&files](auto& next) { next.ca = files.root() / "missing.pem"; }, value);
    reject("ca-directory", [&files](auto& next) { next.ca = files.root(); }, value);
    reject("ca-empty", [&files](auto& next) { next.ca = files.write({}); }, value);
    reject("ca-private-key", [&files](auto& next) { next.ca = files.write("-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n"); }, value);
    reject("ca-mixed-private-key", [&files, &pem](auto& next) { next.ca = files.write(pem + "\nPRIVATE KEY\n"); }, value);

    pem.resize(1048576, '\n'); // Trailing PEM whitespace reaches the exact inclusive public file limit.
    value.ca = files.write(pem);
    observe("ca-1048576", value, true);
    pem.push_back('\n');
    value.ca = files.write(pem);
    observe("ca-1048577", std::move(value), false);
    files.finish();
}
} // namespace

/// Run bounded local inputs only; the caller supplies an existing public CA fixture, not trust-store changes.
int main(int argc, char** argv) {

    try {
        CHECK(argc == 2);
        capacity();
        endpoints();
        authentication();
        keys();
        certificates(argv[1]);
        CHECK(std::cout.good());
        std::cout << "COMET-OPTIONS complete\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
