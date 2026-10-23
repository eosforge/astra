// Verify page assembly and atomic publication of SDK projected views.
#include "check.hpp"
#include "duplicates.hpp"
#include "projection.hpp"

#include <atomic>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <thread>
#include <tuple>
#include <vector>

namespace {
using comet::detail::Projection;
using Reply = proto::comet::v1::AlmanacWatchReply;

/// Constructs actual generated messages; complete fields appear only when complete=true.
Reply page(proto::comet::v1::Mode mode, bool complete = false, std::uint64_t version = 0, std::string instance = "star-test") {
    Reply reply;
    reply.set_mode(mode);
    reply.set_complete(complete);
    if (complete) {
        reply.set_instance(std::move(instance));
        reply.set_version(version);
    }
    return reply;
}

/// Complete Set chooses the correct oneof branch even for an empty value.
void set(Reply& reply, std::string key, std::string value = {}) {
    auto* change = reply.add_changes();
    change->set_key(std::move(key));
    change->set_value(std::move(value));
}

/// Atomic publication and independent old-View lifetime; partial snapshots and deltas stay out of current reads.
void lifecycle() {

    comet::Reader::View held;
    {
        Projection projection({"routes", "main"}, {}, 65536, 1000);
        CHECK(!projection.view(comet::Reader::State::Waiting).version());
        projection.begin();
        auto first = page(proto::comet::v1::MODE_RESET);
        set(first, "first", "before");
        auto partial = projection.accept(first);
        CHECK(partial && !*partial && !projection.view(comet::Reader::State::Waiting).version());
        auto last = page(proto::comet::v1::MODE_RESET, true, 1);
        set(last, "empty");
        auto completed = projection.accept(last);
        CHECK(completed && *completed);
        held = **completed;
        CHECK(held.version() == 1 && held.size() == 2 && held.find("empty") && held.find("empty")->empty());
        auto update = page(proto::comet::v1::MODE_APPLY, true, 2);
        set(update, "first", "after");
        auto changed = projection.accept(update);
        CHECK(changed && *changed && (**changed).find("first") != held.find("first"));
        CHECK((**changed).find("empty") == held.find("empty"));
        auto erase = page(proto::comet::v1::MODE_APPLY, true, 3);
        erase.add_changes()->set_key("first");
        erase.mutable_changes(0)->mutable_erase();
        CHECK(projection.accept(erase));
        CHECK(!projection.view(comet::Reader::State::Ready).find("first"));
        CHECK(held.state() == comet::Reader::State::Ready);
    }
    CHECK(held.find("first") && std::string(held.find("first")->begin(), held.find("first")->end()) == "before");
    std::size_t records{}; // Callback can traverse contents after every SDK object is destroyed.
    held.each([&](std::string_view key, const comet::Value& value) { CHECK(!key.empty() && value); ++records; });
    CHECK(records == 2);

    // Traversal owns the old root through all callbacks; resetting the original View preserves current and subsequent Key/Value borrows.
    records = 0;
    held.each([&](std::string_view key, const comet::Value& value) {
        held = {};
        CHECK((key == "first" && std::string(value->begin(), value->end()) == "before") || (key == "empty" && value->empty()));
        ++records;
    });
    CHECK(records == 2 && !held.version());
}

/// Cross-page duplicates, invalid fields, and mode or instance changes discard the entire batch without corrupting the complete version.
void malformed() {

    Projection projection({"routes", "main"}, {}, 65536, 1000);
    projection.begin();
    auto empty = page(proto::comet::v1::MODE_RESET, true, 1);
    CHECK(projection.accept(empty));
    for (unsigned scenario = 0; scenario < 8; ++scenario) {
        projection.begin("star-test");
        auto candidate = page(proto::comet::v1::MODE_RESET);
        set(candidate, "kept", "private");
        CHECK(projection.accept(candidate));
        auto bad = page(proto::comet::v1::MODE_RESET, true, 2);
        switch (scenario) {
        case 0:
            set(bad, "kept");
            break;
        case 1:
            bad.set_mode(proto::comet::v1::MODE_APPLY);
            break;
        case 2:
            bad.clear_version();
            break;
        case 3:
            bad.set_instance("different");
            break;
        case 4:
            bad.add_changes()->set_key("no-action");
            break;
        case 5:
            bad.add_changes()->mutable_erase();
            break;
        case 6:
            bad.set_version(0);
            break;
        case 7:
            set(bad, std::string("bad\0key", 7));
            break;
        }
        const auto rejected = projection.accept(bad);
        CHECK(!rejected && rejected.error().code == (scenario == 6 ? comet::Error::Code::Version : comet::Error::Code::Protocol));
        CHECK(projection.view(comet::Reader::State::Stale).version() == 1 && projection.view(comet::Reader::State::Stale).size() == 0);
        CHECK(!projection.accept(empty)); // An invalid stream cannot append more pages after failure.
    }
}

/// Almanac retains its authority floor across Stars; same-instance empty apply may confirm an already-caught-up position on initial recovery.
void versions() {

    Projection projection({"routes", "main"}, "key", 65536, 16);
    projection.begin();
    CHECK(!projection.accept(page(proto::comet::v1::MODE_APPLY, true, 1)));
    projection.begin("first");
    CHECK(projection.accept(page(proto::comet::v1::MODE_RESET, true, 5, "first")));
    projection.begin("second");
    const auto behind = projection.accept(page(proto::comet::v1::MODE_RESET, true, 4, "second"));
    CHECK(!behind && behind.error().code == comet::Error::Code::Version && projection.repair(behind.error().code));
    CHECK(projection.view(comet::Reader::State::Stale).version() == 5 && projection.resume());
    projection.begin("second");
    CHECK(projection.accept(page(proto::comet::v1::MODE_RESET, true, 5, "second")));
    projection.begin("second");
    CHECK(projection.accept(page(proto::comet::v1::MODE_APPLY, true, 5, "second")));
    CHECK(!projection.accept(page(proto::comet::v1::MODE_APPLY, true, 5, "second")));
    projection.begin("second");
    auto wrong = page(proto::comet::v1::MODE_RESET, true, 6, "second");
    set(wrong, "another-key");
    CHECK(!projection.accept(wrong));
    CHECK(projection.view(comet::Reader::State::Stale).version() == 5);
}

/// Final capacity is independent of replacement order; Set before Delete must not reject a valid equal-capacity replacement.
void capacity() {

    Projection projection({"routes", "main"}, {}, 32768, 1);
    projection.begin();
    auto initial = page(proto::comet::v1::MODE_RESET, true, 1);
    set(initial, "old", "value");
    CHECK(projection.accept(initial));
    auto update = page(proto::comet::v1::MODE_APPLY, true, 2);
    set(update, "new", "value");
    auto* erased = update.add_changes();
    erased->set_key("old");
    erased->mutable_erase();
    CHECK(projection.accept(update));
    CHECK(projection.view(comet::Reader::State::Ready).size() == 1);
    auto large = page(proto::comet::v1::MODE_APPLY, true, 3);
    set(large, "new", std::string(65537, 'x'));
    const auto failed = projection.accept(large);
    CHECK(!failed && failed.error().code == comet::Error::Code::Limit);
    CHECK(projection.view(comet::Reader::State::Stale).version() == 2);
}

/// Reject shared-budget growth before publication; discarding preparation retains only old-root charges, and destruction returns to zero.
void sharedBudget() {

    std::size_t held{}; // Models bytes committed to this Reading by the shared Client, not handle size.
    bool blocked{};     // Other objects consume further growth capacity; shrinking and zeroing must still succeed.
    {
        Projection projection({"routes", "main"}, {}, 65536, 128, [&](std::size_t bytes) noexcept {
            if (blocked && bytes > held) {
                return false;
            }
            held = bytes;
            return true;
        });
        projection.begin();
        auto initial = page(proto::comet::v1::MODE_RESET, true, 1);
        set(initial, "old", "value");
        CHECK(projection.accept(initial));
        const auto original = held; // Contents, root, pages, nodes, and buckets all incur controlled charges.
        CHECK(original > 8);
        blocked = true;
        auto next = page(proto::comet::v1::MODE_APPLY, true, 2);
        set(next, "new", "value");
        const auto rejected = projection.accept(next);
        CHECK(!rejected && rejected.error().code == comet::Error::Code::Limit);
        CHECK(held == original && projection.view(comet::Reader::State::Stale).version() == 1);
    }
    CHECK(held == 0);
}

/// Published pages never change; concurrent reads and final old-root release need neither Client locks nor read-completion barriers.
void concurrent() {

    Projection projection({"routes", "main"}, {}, 1024 * 1024, 4096);
    projection.begin();
    auto initial = page(proto::comet::v1::MODE_RESET, true, 1);
    for (unsigned index = 0; index < 2000; ++index) {
        set(initial, "key-" + std::to_string(index), "original");
    }
    auto result = projection.accept(initial);
    CHECK(result && *result);
    auto held = **result; // Move only immutable views into reader threads; Projection remains single-writer.
    std::atomic_bool valid{true};
    std::jthread reader([held, &valid] {
        for (unsigned pass = 0; pass < 100; ++pass) {
            held.each([&valid](std::string_view, const comet::Value& value) { if (!value || std::string(value->begin(), value->end()) != "original") { valid = false; } });
        }
    });
    for (std::uint64_t version = 2; version < 200; ++version) {
        auto delta = page(proto::comet::v1::MODE_APPLY, true, version);
        set(delta, "key-" + std::to_string(version), "changed");
        CHECK(projection.accept(delta));
    }
    reader.join();
    CHECK(valid && held.size() == 2000 && held.version() == 1);
}

using Map = std::map<std::string, std::string>;

/// Encode actual public observations only; the independent interpreter owns all expected transitions.
class Observation {
public:
    /// Capture complete public metadata and content without borrowing the native draft or expected dictionary.
    static std::string view(const comet::Reader::View& view) {

        std::ostringstream output;
        output << '[';
        if (const auto version = view.version()) {
            output << *version;
        } else {
            output << "null";
        }
        for (const auto* value : {&view.instance(), &view.scope().sector, &view.scope().spectrum, &view.target()}) {
            output << ',';
            text(output, *value);
        }
        output << ',';
        text(output, state(view.state()));
        output << ',' << (view.error() ? "true" : "false") << ',' << view.size() << ",[";

        // Traversal order is not a public commitment; preserve each actual value in a canonical ordered dictionary.
        std::map<std::string, std::optional<std::string>> actual;
        view.each([&actual](std::string_view key, const comet::Value& value) { actual.emplace(key, value ? std::optional{std::string(value->begin(), value->end())} : std::nullopt); });
        bool first = true;
        for (const auto& [key, value] : actual) {
            if (!first) {
                output << ',';
            }
            first = false;
            output << '[';
            text(output, key);
            output << ',';
            if (value) {
                text(output, *value);
            } else {
                output << "null";
            }
            output << ']';
        }
        output << "]]";
        return output.str();
    }

    /// Classify the actual native result, including absence of a completed publication.
    static std::string_view result(const comet::Result<std::optional<comet::Reader::View>>& result) {
        if (result) {
            return *result ? "complete" : "partial";
        }
        return result.error().code == comet::Error::Code::Version ? "version" : result.error().code == comet::Error::Code::Protocol ? "protocol"
                                                                                                                                    : "unexpected-error";
    }

private:
    /// Keep all public states distinct instead of silently coercing a corrupted value to ready.
    static std::string_view state(comet::Reader::State state) {
        switch (state) {
        case comet::Reader::State::Waiting:
            return "waiting";
        case comet::Reader::State::Ready:
            return "ready";
        case comet::Reader::State::Stale:
            return "stale";
        case comet::Reader::State::Failed:
            return "failed";
        case comet::Reader::State::Closed:
            return "closed";
        }
        return "unexpected-state";
    }

    /// Emit JSON text faithfully, including control bytes, without introducing a serialization dependency.
    static void text(std::ostream& output, std::string_view value) {

        constexpr std::string_view digits = "0123456789abcdef";
        output << '"';
        for (const auto byte : value) {
            const auto code = static_cast<unsigned char>(byte);
            if (byte == '"' || byte == '\\') {
                output << '\\' << byte;
            } else if (code < 32) {
                output << "\\u00" << digits[code >> 4] << digits[code & 15];
            } else {
                output << byte;
            }
        }
        output << '"';
    }
};

// Compare public content and metadata with an independent dictionary, including every retained root.
void modelView(const comet::Reader::View& view, const Map& expected, std::uint64_t version) {
    CHECK(view.version() == version && view.instance() == "star-model" && view.state() == comet::Reader::State::Ready);
    CHECK(view.scope().sector == "routes" && view.scope().spectrum == "main" && view.target().empty() && !view.error());
    Map actual;
    view.each([&actual](std::string_view key, const comet::Value& value) {
        CHECK(value);
        CHECK(actual.emplace(key, std::string(value->begin(), value->end())).second);
    });
    CHECK(view.size() == expected.size() && actual == expected);
    for (const auto& key : {"a", "b", "absent"}) {
        const auto found = expected.find(key);
        const auto value = view.find(key);
        CHECK(found == expected.end() ? !value : value && std::string(value->begin(), value->end()) == found->second);
    }
}

// Enumerate all bounded stream histories without reusing production parsing, drafts or version predicates.
void model() {

    const auto before = astra::test::checks.hits.load(std::memory_order_relaxed);
    std::cout << "ASTRA-MODEL {\"model\":\"comet-projection-v1\",\"event\":\"start\",\"value\":{\"histories\":2401,\"depth\":4,\"operations\":7,\"pruning\":0,\"before\":" << before << "}}\n";
    unsigned histories{}, transitions{};
    const auto first = page(proto::comet::v1::MODE_RESET, true, 1, "star-model");
    for (unsigned number = 0; number < 2401; ++number) {
        Projection projection({"routes", "main"}, {}, 65536, 16);
        projection.begin("star-model");
        CHECK(projection.accept(first));
        std::cout << "ASTRA-MODEL {\"model\":\"comet-projection-v1\",\"event\":\"history\",\"value\":{\"ordinal\":" << number << ",\"initial\":" << Observation::view(projection.view(comet::Reader::State::Ready)) << ",\"states\":[";
        Map expected;
        std::uint64_t version = 1;
        std::vector<std::tuple<comet::Reader::View, Map, std::uint64_t>> retained;
        auto remaining = number;
        for (unsigned depth = 0; depth < 4; ++depth) {
            const auto operation = remaining % 7;
            remaining /= 7;
            if (depth) {
                std::cout << ',';
            }
            std::cout << "{\"operation\":" << operation << ",\"receipts\":[";
            retained.emplace_back(projection.view(comet::Reader::State::Ready), expected, version);
            projection.begin("star-model");
            auto candidate = expected;
            auto reply = page(operation == 0 || operation == 5 ? proto::comet::v1::MODE_RESET : proto::comet::v1::MODE_APPLY, true, version + 1, "star-model");
            switch (operation) {
            case 0:
                candidate.clear();
                break;
            case 1:
                set(reply, "a", "A");
                candidate.insert_or_assign("a", "A");
                break;
            case 2:
                reply.add_changes()->set_key("a");
                reply.mutable_changes(0)->mutable_erase();
                candidate.erase("a");
                break;
            case 3:
            case 6: {
                auto partial = page(proto::comet::v1::MODE_APPLY);
                set(partial, "a", "A");
                const auto accepted = projection.accept(partial);
                CHECK(accepted && !*accepted);
                modelView(projection.view(comet::Reader::State::Ready), expected, version);
                std::cout << "[\"" << Observation::result(accepted) << "\"," << Observation::view(projection.view(comet::Reader::State::Ready)) << "],";
                set(reply, operation == 3 ? "b" : "a", "B");
                candidate.insert_or_assign("a", "A");
                candidate.insert_or_assign("b", "B");
                break;
            }
            case 4: {
                auto partial = page(proto::comet::v1::MODE_RESET);
                set(partial, "a", "discarded");
                const auto accepted = projection.accept(partial);
                CHECK(accepted && !*accepted);
                modelView(projection.view(comet::Reader::State::Ready), expected, version);
                std::cout << "[\"" << Observation::result(accepted) << "\"," << Observation::view(projection.view(comet::Reader::State::Ready)) << "]";
                projection.begin("star-model");
                break;
            }
            case 5:
                reply.set_version(version - 1);
                break;
            }
            if (operation != 4) {
                const auto accepted = projection.accept(reply);
                if (operation == 5 || operation == 6) {
                    CHECK(!accepted && accepted.error().code == (operation == 5 ? comet::Error::Code::Version : comet::Error::Code::Protocol));
                } else {
                    CHECK(accepted && *accepted);
                    expected = std::move(candidate);
                    ++version;
                    modelView(**accepted, expected, version);
                }
                std::cout << "[\"" << Observation::result(accepted) << "\"," << Observation::view(projection.view(comet::Reader::State::Ready)) << "]";
            }
            modelView(projection.view(comet::Reader::State::Ready), expected, version);
            std::cout << "],\"current\":" << Observation::view(projection.view(comet::Reader::State::Ready)) << ",\"retained\":[";
            bool firstRetained = true;
            for (const auto& [view, content, cursor] : retained) {
                modelView(view, content, cursor);
                if (!firstRetained) {
                    std::cout << ',';
                }
                firstRetained = false;
                std::cout << Observation::view(view);
            }
            std::cout << "]}";
            ++transitions;
        }
        std::cout << "]}}\n";
        ++histories;
    }
    CHECK(histories == 2401 && transitions == 9604);
    std::cout << "COMET-PROJECTION-MODEL histories=" << histories << " transitions=" << transitions << " depth=4 operations=7 pruning=0\n";
    CHECK(std::cout.good());
    std::cout << "ASTRA-MODEL {\"model\":\"comet-projection-v1\",\"event\":\"finish\",\"value\":{\"histories\":" << histories << ",\"transitions\":" << transitions << ",\"checks\":" << astra::test::checks.hits.load(std::memory_order_relaxed) - before << "}}\n";
}
} // namespace

/// Runs local projection validation, concurrency, and model cases.
int main() {
    try {
        lifecycle();
        malformed();
        versions();
        capacity();
        comet::test::duplicates<Projection>([](auto& change, std::string_view key) { change.set_key(key); change.mutable_erase(); }); // Almanac error precedence and cross-page atomicity.
        sharedBudget();
        concurrent();
        model();
        std::cout << "Comet projection tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
