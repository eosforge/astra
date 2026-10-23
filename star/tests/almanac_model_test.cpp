// Exhaust bounded authoritative histories against an independent map/log model, including atomic batches and preserved views.
#include "almanac.hpp"
#include "check.hpp"

#include <algorithm>
#include <array>
#include <barrier>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <tuple>

namespace {
using astra::Almanac;
using Map = std::map<std::string, Almanac::Buffer>;
using Change = std::tuple<std::uint64_t, std::string, std::optional<Almanac::Buffer>>;

// Only protocol-visible state appears in this model; no production index, draft or history helper is reused.
struct Model {
    /// Keep independent authoritative key/value contents for comparison with the real Almanac.
    Map values;
    /// Track the model's current authority version without consulting production state.
    std::uint64_t version{};
    /// Record the installed full-baseline version from which model replay starts.
    std::uint64_t baseline{};
    /// Retain independent model changes after the baseline for contiguous replay checks.
    std::vector<Change> history;
};

// Build a public input, independently of the expected map/log representation.
Almanac::Change change(std::string key, std::optional<Almanac::Buffer> value, std::uint64_t version) {
    return {std::make_shared<const std::string>(std::move(key)), value ? std::make_shared<const Almanac::Buffer>(std::move(*value)) : nullptr, version};
}

// Materialize a view without borrowing the current object or comparing production pointer layouts.
Map values(const Almanac::View& view) {
    Map result;
    view.each([&](const std::string& key, const Almanac::Value& value) {
        CHECK(value && result.emplace(key, *value).second);
    });
    return result;
}

// Check complete roots, accounting and every old/ahead cursor, including frozen pre-reset roots.
void verify(const Almanac& book, const Model& model, const auto& frozen) {
    const auto view = book.view();
    CHECK(view && view->version() == model.version && values(*view) == model.values);
    std::size_t bytes{};
    for (const auto& [key, value] : model.values) {
        bytes += key.size() + value.size();
    }
    CHECK(view->size() == model.values.size() && view->bytes() == bytes);
    for (const auto& [old, expected] : frozen) {
        CHECK(values(old) == expected);
    }
    for (std::uint64_t since = 0; since <= model.version + 1; ++since) {
        const auto replay = book.replay(since);
        if (since > model.version) {
            CHECK(!replay && replay.error() == Almanac::Error::Version);
        } else if (since < model.baseline) {
            CHECK(!replay && replay.error() == Almanac::Error::History);
        } else {
            CHECK(replay && replay->version == model.version);
            std::vector<Change> expected, received;
            for (const auto& item : model.history) {
                if (std::get<0>(item) > since) {
                    expected.push_back(item);
                }
            }
            for (const auto& item : replay->changes) {
                received.emplace_back(item.version, *item.key, item.value ? std::optional(*item.value) : std::nullopt);
            }
            std::ranges::sort(expected);
            std::ranges::sort(received);
            CHECK(received == expected);
        }
    }
}

// Nine operations include explicit duplicate, gap, retry, replacement and capacity failures; all failures preserve the model.
std::expected<bool, Almanac::Error> step(Almanac& book, Model& model, unsigned operation) {
    const auto version = model.version + 1;
    std::expected<bool, Almanac::Error> result;
    if (operation == 4) {
        result = book.apply(version, {change("a", Almanac::Buffer{1}, version), change("a", {}, version)}, 1 << 20);
        CHECK(!result && result.error() == Almanac::Error::Input);
    } else if (operation == 5) {
        result = book.apply(version + 1, "a", Almanac::Buffer{1});
        CHECK(result == std::unexpected(Almanac::Error::Version));
    } else if (operation == 6) {
        result = book.apply(model.version, "a", Almanac::Buffer{99});
        if (model.version) {
            CHECK(result == false);
        } else {
            CHECK(result == std::unexpected(Almanac::Error::Version));
        }
    } else if (operation == 7) {
        auto draft = book.prepare(model.version + 3);
        CHECK(draft.set("a", {9}));
        result = book.reset(std::move(draft));
        CHECK(result == true);
        model.values = {{"a", {9}}};
        model.version += 3;
        model.baseline = model.version;
        model.history.clear();
    } else {
        std::vector<std::pair<std::string, std::optional<Almanac::Buffer>>> changes;
        if (operation == 3) {
            changes = {{"a", Almanac::Buffer{2}}, {"b", std::nullopt}};
        } else {
            changes = {{operation == 8 ? "c" : operation == 1 ? "b"
                                                              : "a",
                        operation == 2 ? std::nullopt : std::optional(operation == 1 ? Almanac::Buffer{} : Almanac::Buffer{1})}};
        }
        auto candidate = model.values;
        for (const auto& [key, value] : changes) {
            if (value) {
                candidate[key] = *value;
            } else {
                candidate.erase(key);
            }
        }
        if (operation == 3) {
            result = book.apply(version, {change("a", Almanac::Buffer{2}, version), change("b", {}, version)}, 1 << 20);
        } else {
            result = book.apply(version, changes[0].first, changes[0].second);
        }
        if (candidate.size() > 2) {
            CHECK(!result && result.error() == Almanac::Error::Capacity);
        } else {
            CHECK(result == true);
            model.values = std::move(candidate);
            model.version = version;
            for (auto& [key, value] : changes) {
                model.history.emplace_back(version, std::move(key), std::move(value));
            }
        }
    }
    return result;
}

// Emit actual public bytes without calling the reference model or adding assertion-counting traversals.
void payload(std::ostream& output, const Almanac::Buffer& value) {
    output << '[';
    for (std::size_t index = 0; index < value.size(); ++index) {
        output << (index ? "," : "") << static_cast<unsigned>(value[index]);
    }
    output << ']';
}

// Every key in this fixed input domain is one ASCII letter; no arbitrary string codec is involved.
void snapshot(std::ostream& output, const Almanac::View& root) {
    output << '[' << root.version() << ',' << root.size() << ',' << root.bytes() << ",[";
    Map records;
    root.each([&records](const auto& key, const auto& value) { records.emplace(key, *value); });
    bool separator{};
    for (const auto& [key, value] : records) {
        output << (separator ? "," : "") << "[\"" << key << "\",";
        payload(output, value);
        output << ']';
        separator = true;
    }
    output << "]]";
}

// Stable native errors remain separate from successful true/false acknowledgments.
const char* error(Almanac::Error value) {
    switch (value) {
    case Almanac::Error::Input:
        return "input";
    case Almanac::Error::Capacity:
        return "capacity";
    case Almanac::Error::Duplicate:
        return "duplicate";
    case Almanac::Error::Version:
        return "version";
    case Almanac::Error::Unready:
        return "unready";
    case Almanac::Error::History:
        return "history";
    }
    throw std::logic_error("Unknown Almanac error");
}

// Record the actual native return once, retaining a retry acknowledgment distinct from a new commit.
void receipt(std::ostream& output, const std::expected<bool, Almanac::Error>& result) {
    if (result) {
        output << (*result ? "true" : "false");
    } else {
        output << '"' << error(result.error()) << '"';
    }
}

// Read all native cursor results; sort only the unspecified order of keys within an authority version.
void replay(std::ostream& output, const Almanac& book) {
    output << '[';
    const auto version = book.view()->version();
    for (std::uint64_t since = 0; since <= version + 1; ++since) {
        output << (since ? "," : "") << '[' << since << ',';
        const auto result = book.replay(since);
        if (!result) {
            output << '"' << error(result.error()) << '"';
        } else {
            output << '[' << result->version << ",[";
            std::vector<Change> records;
            for (const auto& row : result->changes) {
                records.emplace_back(row.version, *row.key, row.value ? std::optional(*row.value) : std::nullopt);
            }
            std::ranges::sort(records);
            bool separator{};
            for (const auto& [position, key, value] : records) {
                output << (separator ? "," : "") << '[' << position << ",\"" << key << "\",";
                if (value) {
                    payload(output, *value);
                } else {
                    output << "null";
                }
                output << ']';
                separator = true;
            }
            output << "]]";
        }
        output << ']';
    }
    output << ']';
}

// Only completed native observations enter a frame; aggregate summaries cannot replace its contents.
void frame(std::string_view event, const std::string& value) {
    std::cout << "ASTRA-MODEL {\"model\":\"almanac-state-v1\",\"event\":\"" << event << "\",\"value\":" << value << "}\n";
}

/// One immutable request, with its authority version fixed before concurrent execution.
struct Input {
    /// Full replacement rather than a consecutive incremental commit.
    bool reset{};
    /// Absolute authority position; concurrent writers do not read and increment it independently.
    std::uint64_t version{};
    /// Distinct keys and their optional complete values.
    std::vector<std::pair<std::string, std::optional<Almanac::Buffer>>> changes;
};

// Build fixed requests including duplicate positions, gaps, reset races and a third-key capacity boundary.
Input input(unsigned operation, std::uint64_t version) {
    switch (operation) {
    case 0:
        return {false, version + 1, {{"a", Almanac::Buffer{1}}}};
    case 1:
        return {false, version + 1, {{"b", Almanac::Buffer{}}}};
    case 2:
        return {false, version + 1, {{"a", Almanac::Buffer{2}}, {"b", Almanac::Buffer{2}}}};
    case 3:
        return {false, version + 1, {{"a", std::nullopt}, {"b", std::nullopt}}};
    case 4:
        return {true, version + 2, {{"a", Almanac::Buffer{9}}, {"b", Almanac::Buffer{9}}}};
    case 5:
        return {false, version + 2, {{"a", Almanac::Buffer{3}}}};
    case 6:
        return {false, version, {{"a", Almanac::Buffer{99}}}};
    default:
        return {false, version + 1, {{"c", Almanac::Buffer{1}}}};
    }
}

// Apply documented authority rules to the plain map and complete log, without production helpers.
std::expected<bool, Almanac::Error> apply(Model& model, const Input& request) {

    if (!request.reset && !request.version) {
        return std::unexpected(Almanac::Error::Version);
    }
    if (request.reset && request.version < model.version) {
        return std::unexpected(Almanac::Error::Version);
    }
    if (request.version <= model.version) {
        return false;
    }
    if (!request.reset && request.version != model.version + 1) {
        return std::unexpected(Almanac::Error::Version);
    }

    auto candidate = request.reset ? Map{} : model.values;
    for (const auto& [key, value] : request.changes) {
        if (value) {
            candidate[key] = *value;
        } else {
            candidate.erase(key);
        }
    }
    if (candidate.size() > 2) {
        return std::unexpected(Almanac::Error::Capacity);
    }
    model.values = std::move(candidate);
    model.version = request.version;
    if (request.reset) {
        model.baseline = request.version;
        model.history.clear();
    } else {
        for (const auto& [key, value] : request.changes) {
            model.history.emplace_back(request.version, key, value);
        }
    }
    return true;
}

// Exercise actual public single-key, batch and replacement boundaries with the same immutable request.
std::expected<bool, Almanac::Error> apply(Almanac& book, const Input& request) {

    if (request.reset) {
        auto draft = book.prepare(request.version);
        for (const auto& [key, value] : request.changes) {
            CHECK(value);
            CHECK(draft.set(key, *value));
        }
        return book.reset(std::move(draft));
    }
    if (request.changes.size() == 1) {
        return book.apply(request.version, request.changes[0].first, request.changes[0].second);
    }
    std::vector<Almanac::Change> changes;
    for (const auto& [key, value] : request.changes) {
        changes.push_back(change(key, value, request.version));
    }
    return book.apply(request.version, std::move(changes), 1 << 20);
}

// Candidate selection includes complete replay results, rather than accepting equal final maps alone.
bool matches(const Almanac& book, const Model& model) {

    const auto root = book.view();
    if (!root || root->version() != model.version || values(*root) != model.values) {
        return false;
    }
    for (std::uint64_t since = 0; since <= model.version; ++since) {
        const auto replay = book.replay(since);
        if (since < model.baseline) {
            if (replay || replay.error() != Almanac::Error::History) {
                return false;
            }
            continue;
        }
        if (!replay || replay->version != model.version) {
            return false;
        }
        std::vector<Change> actual, expected;
        for (const auto& item : replay->changes) {
            actual.emplace_back(item.version, *item.key, item.value ? std::optional(*item.value) : std::nullopt);
        }
        for (const auto& item : model.history) {
            if (std::get<0>(item) > since) {
                expected.push_back(item);
            }
        }
        std::ranges::sort(actual);
        std::ranges::sort(expected);
        if (actual != expected) {
            return false;
        }
    }
    return true;
}

// Every frozen root must be a monotonic prefix of one jointly consistent serialization.
bool prefixes(const auto& frozen, const Model& initial, const Model& middle, const Model& final) {

    auto previous = initial.version;
    for (const auto& root : frozen) {
        if (root.version() < previous) {
            return false;
        }
        previous = root.version();
        const auto content = values(root);
        if (!((root.version() == initial.version && content == initial.values) || (root.version() == middle.version && content == middle.values) || (root.version() == final.version && content == final.values))) {
            return false;
        }
    }
    return true;
}

// Enumerate all pairs and admissible serial orders; the fixture supplies no synchronization inside production paths.
void concurrent() {

    unsigned histories{}, snapshots{};
    for (unsigned prefix = 0; prefix < 4; ++prefix) {
        for (unsigned left = 0; left < 8; ++left) {
            for (unsigned right = 0; right < 8; ++right) {
                Almanac book({.records = 2});
                CHECK(book.reset(book.prepare(0)) == true);
                Model initial;
                // step already asserts each setup receipt; only the later overlapping writers need returned observations.
                if (prefix == 1) {
                    (void)step(book, initial, 0);
                }
                if (prefix >= 2) {
                    (void)step(book, initial, 3);
                }
                if (prefix == 3) {
                    (void)step(book, initial, 7);
                }

                std::ostringstream trace;
                trace << "{\"ordinal\":" << histories << ",\"prefix\":" << prefix << ",\"operations\":[" << left << ',' << right << "],\"initial\":[";
                snapshot(trace, *book.view());
                trace << ',';
                replay(trace, book);
                trace << ']';

                const std::array<Input, 2> requests{input(left, initial.version), input(right, initial.version)};
                Model forward = initial, reverse = initial;
                std::array<std::expected<bool, Almanac::Error>, 2> first, second, actual;
                first[0] = apply(forward, requests[0]);
                const auto forwardMiddle = forward;
                first[1] = apply(forward, requests[1]);
                second[1] = apply(reverse, requests[1]);
                const auto reverseMiddle = reverse;
                second[0] = apply(reverse, requests[0]);

                // Joined writers own distinct result slots; only the reader owns the frozen-root vector.
                std::array<std::exception_ptr, 3> errors;
                std::vector<Almanac::View> frozen;
                frozen.reserve(64);
                std::barrier start(3);
                auto write = [&book, &requests, &actual, &errors, &start](unsigned index) {
                    start.arrive_and_wait();
                    try {
                        actual[index] = apply(book, requests[index]);
                    } catch (...) {
                        errors[index] = std::current_exception();
                    }
                };
                std::jthread writer(write, 0), other(write, 1);
                std::jthread reader([&book, &frozen, &errors, &start] {
                    start.arrive_and_wait();
                    try {
                        for (unsigned index = 0; index < 64; ++index) {
                            const auto root = book.view();
                            CHECK(root);
                            frozen.push_back(*root);
                        }
                    } catch (...) {
                        errors[2] = std::current_exception();
                    }
                });
                writer.join();
                other.join();
                reader.join();
                for (const auto& error : errors) {
                    if (error) {
                        std::rethrow_exception(error);
                    }
                }

                CHECK(frozen.size() == 64);
                const bool ordered = actual == first && matches(book, forward) && prefixes(frozen, initial, forwardMiddle, forward);
                CHECK(ordered || (actual == second && matches(book, reverse) && prefixes(frozen, initial, reverseMiddle, reverse)));
                const auto& selected = ordered ? forward : reverse;
                const std::vector<std::pair<Almanac::View, Map>> none;
                verify(book, selected, none);
                const std::array<Model, 3> allowed{initial, ordered ? forwardMiddle : reverseMiddle, selected};
                for (const auto& root : frozen) {
                    const auto content = values(root);
                    CHECK(std::ranges::any_of(allowed, [&root, &content](const auto& model) { return root.version() == model.version && content == model.values; }));
                    std::size_t bytes{};
                    for (const auto& [key, value] : content) {
                        bytes += key.size() + value.size();
                    }
                    CHECK(root.size() == content.size() && root.bytes() == bytes);
                    ++snapshots;
                }
                trace << ",\"receipts\":[";
                receipt(trace, actual[0]);
                trace << ',';
                receipt(trace, actual[1]);
                trace << "],\"current\":";
                snapshot(trace, *book.view());
                trace << ",\"replay\":";
                replay(trace, book);
                trace << ",\"frozen\":[";
                for (std::size_t index = 0; index < frozen.size(); ++index) {
                    trace << (index ? "," : "");
                    snapshot(trace, frozen[index]);
                }
                trace << "]}";
                frame("pair", trace.str());
                ++histories;
            }
        }
    }
    CHECK(histories == 256 && snapshots == 16384);
    std::cout << "ALMANAC-CONCURRENCY histories=" << histories << " snapshots=" << snapshots << " starts=4 operations=8 serializations=2 internal-schedules=not-enumerated\n";
}
} // namespace

// Enumerate 9^4 histories without pruning; concurrency, network framing and memory allocation failures have separate tests.
int main() {
    try {
        frame("start", "{\"keys\":[\"a\",\"b\",\"c\"],\"operations\":9,\"depth\":4,\"histories\":6561,\"capacity\":2,\"pruning\":0,\"pairs\":256,\"starts\":4,\"pair_operations\":8,\"reads\":64,\"serializations\":2}");
        for (unsigned history = 0; history < 6561; ++history) {
            Almanac book({.records = 2});
            CHECK(book.reset(book.prepare(0)) == true);
            Model model;
            std::vector<std::pair<Almanac::View, Map>> frozen;
            std::ostringstream trace;
            trace << "{\"ordinal\":" << history << ",\"states\":[";
            auto remaining = history;
            for (unsigned depth = 0; depth < 4; ++depth) {
                frozen.emplace_back(book.view().value(), model.values);
                const auto operation = remaining % 9;
                const auto result = step(book, model, operation);
                remaining /= 9;
                verify(book, model, frozen);
                trace << (depth ? "," : "") << "{\"operation\":" << operation << ",\"receipt\":";
                receipt(trace, result);
                trace << ",\"current\":";
                snapshot(trace, *book.view());
                trace << ",\"frozen\":[";
                for (std::size_t index = 0; index < frozen.size(); ++index) {
                    trace << (index ? "," : "");
                    snapshot(trace, frozen[index].first);
                }
                trace << "],\"replay\":";
                replay(trace, book);
                trace << '}';
            }
            trace << "]}";
            frame("history", trace.str());
        }
        std::cout << "ALMANAC-MODEL histories=6561 transitions=26244 depth=4 operations=9 pruning=0\n";
        concurrent();
        frame("finish", "{\"histories\":6561,\"transitions\":26244,\"pairs\":256,\"snapshots\":16384}");
        std::cout.flush();
        CHECK(std::cout.good());
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
