// Exhaust local Catalog histories against independent maps, visible logs and source-position registers.
#include "catalog_state.hpp"
#include "check.hpp"

#include <algorithm>
#include <array>
#include <barrier>
#include <exception>
#include <iostream>
#include <map>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <tuple>

namespace {
using namespace std::chrono_literals;
using State = astra::Catalog::State;
using Buffer = astra::Catalog::Buffer;
using Time = astra::Clock::Time;
using Content = std::pair<std::uint64_t, Buffer>;
using Map = std::map<std::string, Content>;
using Change = std::pair<std::string, std::optional<Content>>;
const astra::Scope scope{"model", "catalog"};

// The independent ledger retains business floors after expiry and records whole visible batches.
struct Record {
    /// Retain the last accepted business version even when the visible body has expired.
    std::uint64_t version{};
    /// Distinguish an absent body watermark from an owned payload containing zero bytes.
    std::optional<Buffer> body;
    /// Keep the absolute controlled expiry time when a live body has a deadline.
    std::optional<Time> deadline;

    bool operator==(const Record&) const = default;
};

/// Model one retained history range, including whether its changes form an atomic batch.
struct Batch {
    /// Record inclusive first and last visible cursor positions for one complete model batch.
    std::uint64_t first{}, last{};
    /// Own the ordered logical changes used to derive replay expectations.
    std::vector<Change> changes;
    /// True requires a complete batch boundary; false permits individual expiry deletions.
    bool atomic{};
};

/// Independent ordered-map reference for records, expiry, retained history, and reader progress.
struct Model {
    /// Track independent Catalog bodies, retained versions, and deadlines by key.
    std::map<std::string, Record> records;
    /// Retain completed model batches for public-cursor replay checks.
    std::vector<Batch> history;
    /// Advance controlled business time explicitly, starting at one second.
    Time now{1s};
    /// Track exported source position and visible change cursor independently.
    std::uint64_t position{}, cursor{};

    // Keep only public content in the view; a floor is a known version rather than an empty payload.
    Map view() const {
        Map result;
        for (const auto& [key, record] : records) {
            if (record.body) {
                result.emplace(key, Content{record.version, *record.body});
            }
        }
        return result;
    }

    // The public cursor counts changed keys, while its replay boundaries retain each complete batch.
    void commit(std::vector<Change> changes, bool atomic = true) {
        if (!changes.empty()) {
            const auto first = cursor + 1;
            cursor += changes.size();
            history.push_back({first, cursor, std::move(changes), atomic});
        }
    }

    // Local expiry clears each body and emits a visible deletion without creating an exported source event.
    void expire() {
        std::vector<Change> changes;
        for (auto& [key, record] : records) {
            if (record.deadline && *record.deadline <= now) {
                record.body.reset();
                record.deadline.reset();
                changes.emplace_back(key, std::nullopt);
            }
        }
        // Individual local deletions permit either key order, including replay from between those deletions.
        commit(std::move(changes), false);
    }

    // Validate every requested key before applying any candidate; no production transition helper is used.
    std::optional<State::Error> apply(const std::vector<std::pair<std::string, Buffer>>& entries, std::uint64_t version, bool renewal) {
        for (const auto& [key, body] : entries) {
            const auto found = records.find(key);
            if (renewal) {
                if (found != records.end() && found->second.version != version) {
                    return State::Error::Version;
                }
                if (found == records.end() || !found->second.body) {
                    return State::Error::Ended;
                }
            } else if (found != records.end()) {
                if (version < found->second.version) {
                    return State::Error::Version;
                }
                if (version == found->second.version && found->second.body && *found->second.body != body) {
                    return State::Error::Conflict;
                }
            }
        }
        std::vector<Change> changes;
        for (const auto& [key, body] : entries) {
            auto& record = records[key];
            if (!renewal && (!record.body || record.version != version || *record.body != body)) {
                changes.emplace_back(key, Content{version, body});
            }
            const auto deadline = now + (renewal ? 2s : 1s);
            if (record.version == version && record.deadline) {
                record.deadline = std::max(*record.deadline, deadline);
            } else {
                record.deadline = deadline;
            }
            record.version = version;
            if (!renewal) {
                record.body = body;
            }
            ++position;
        }
        commit(std::move(changes));
        return {};
    }
};

// Copy public records rather than compare page layouts or shared-pointer identities.
Map view(const State::Projection::View& root) {
    Map result;
    root.each([&result](const auto& key, const auto& item) { CHECK(item.value && result.emplace(key, Content{item.version, *item.value}).second); });
    return result;
}

// Reconcile complete native state, every frozen public root and every available replay boundary.
void verify(State& state, const Model& model, const auto& frozen) {
    const auto root = state.capture(scope);
    CHECK(root && root->version() == model.cursor && view(*root) == model.view());
    const auto source = state.source();
    CHECK(source.position() == model.position && source.size() == model.records.size());
    std::map<std::string, Record> received;
    source.each([&received](const auto& address, const auto& key, const auto& row) {
        CHECK(address == scope);
        received.emplace(key, Record{row.version, row.value ? std::optional(*row.value) : std::nullopt, row.deadline});
    });
    CHECK(received.size() == model.records.size());
    for (const auto& [key, row] : model.records) {
        const auto& actual = received.at(key);
        CHECK(actual.version == row.version && actual.body == row.body && actual.deadline == row.deadline);
    }
    const auto exports = state.events(0);
    CHECK(exports && exports->size() == model.position);
    for (const auto& [old, expected, cursor] : frozen) {
        CHECK(old.version() == cursor && view(old) == expected);
    }
    for (std::uint64_t since = 0; since <= model.cursor + 1; ++since) {
        const auto replay = state.changes(scope, since);
        const bool middle = std::ranges::any_of(model.history, [since](const auto& batch) { return batch.atomic && since >= batch.first && since < batch.last; });
        if (since > model.cursor) {
            CHECK(!replay && replay.error() == State::Error::Input);
        } else if (middle) {
            CHECK(!replay && replay.error() == State::Error::History);
        } else {
            CHECK(replay);
            std::vector<Change> actual;
            for (const auto& event : *replay) {
                CHECK(event.version == since + actual.size() + 1);
                actual.emplace_back(event.name->key, event.record ? std::optional(Content{event.record->version, *event.record->value}) : std::nullopt);
            }
            CHECK(actual.size() == model.cursor - since);
            std::size_t offset{};
            for (const auto& batch : model.history) {
                if (batch.last <= since) {
                    continue;
                }
                const auto count = batch.last - std::max(since, batch.first - 1);
                auto expected = batch.changes;
                CHECK(offset <= actual.size() && count <= actual.size() - offset);
                const auto part = std::span(actual).subspan(offset, count);
                std::vector<Change> segment(part.begin(), part.end());
                std::ranges::sort(expected);
                std::ranges::sort(segment);
                // A partial unordered expiry group may retain either subset; atomic groups must be complete.
                CHECK(std::ranges::includes(expected, segment));
                if (since < batch.first) {
                    CHECK(segment == expected);
                }
                offset += count;
            }
        }
    }
}

// Share only input decoding; the reference model does not call production transitions or comparison helpers.
struct Input {
    /// Own the proposed key/payload pairs, including deliberate duplicate-key inputs.
    std::vector<std::pair<std::string, Buffer>> entries;
    /// Supply the business version used by both the model and production request.
    std::uint64_t version{};
    /// Select renewal behavior and deliberate structural invalidity independently.
    bool renewal{}, invalid{};
};

Input input(unsigned operation) {

    Input result{.entries = {}, .version = operation == 1 || operation == 3 || operation == 5 ? 2u : 1u, .renewal = operation == 4 || operation == 5, .invalid = operation == 8};
    if (operation == 3 || operation == 5) {
        result.entries = {{"a", {2}}, {"b", {2}}};
    } else if (operation == 8) {
        result.entries = {{"a", {1}}, {"a", {1}}};
    } else {
        result.entries = {{operation == 2 ? "b" : "a", operation == 2 ? Buffer{} : Buffer{static_cast<std::uint8_t>(operation == 1 || operation == 6 ? 2 : 1)}}};
    }
    return result;
}

std::optional<State::Error> apply(Model& model, const Input& input) {
    return input.invalid ? std::optional(State::Error::Input) : model.apply(input.entries, input.version, input.renewal);
}

std::optional<State::Error> apply(State& state, const Input& input) {

    std::vector<State::Entry> request;
    for (const auto& [key, body] : input.entries) {
        request.push_back({key, input.renewal ? nullptr : std::make_shared<const Buffer>(body)});
    }
    const auto result = state.publish(scope, request, input.version, input.renewal ? 2000 : 1000, input.renewal);
    return result ? std::nullopt : std::optional(result.error());
}

// Nine inputs cover single/batch writes, same-version conflicts, renewals, complete expiry and duplicate rejection.
std::optional<State::Error> step(State& state, Model& model, unsigned operation) {

    if (operation == 7) {
        model.now += 1s;
        model.expire();
        state.tick();
        return {};
    }
    const auto request = input(operation);
    const auto expected = apply(model, request);
    const auto actual = apply(state, request);
    CHECK(actual == expected);
    return actual;
}

// Encode actual public bytes without reference-model helpers or extra counting traversals.
void payload(std::ostream& output, const Buffer& value) {
    output << '[';
    for (std::size_t index = 0; index < value.size(); ++index) {
        output << (index ? "," : "") << static_cast<unsigned>(value[index]);
    }
    output << ']';
}

// Fixed keys are ASCII letters; roots are sorted by key without exposing native page layout.
void snapshot(std::ostream& output, const State::Projection::View& root) {
    output << '[' << root.version() << ",[";
    Map records;
    root.each([&records](const auto& key, const auto& item) { records.emplace(key, Content{item.version, *item.value}); });
    bool separator{};
    for (const auto& [key, item] : records) {
        output << (separator ? "," : "") << "[\"" << key << "\"," << item.first << ',';
        payload(output, item.second);
        output << ']';
        separator = true;
    }
    output << "]]";
}

// Stable native errors remain distinguishable from a successful acknowledgment or an explicit tick.
const char* error(State::Error value) {
    switch (value) {
    case State::Error::Input:
        return "input";
    case State::Error::Clock:
        return "clock";
    case State::Error::Ended:
        return "ended";
    case State::Error::Version:
        return "version";
    case State::Error::Conflict:
        return "conflict";
    case State::Error::Exhausted:
        return "exhausted";
    case State::Error::Capacity:
        return "capacity";
    case State::Error::History:
        return "history";
    }
    throw std::logic_error("Unknown Catalog error");
}

// Source event form is observable replication policy rather than a numeric enum ordinal.
const char* form(State::Source::Form value) {
    switch (value) {
    case State::Source::Form::Record:
        return "record";
    case State::Source::Form::Data:
        return "data";
    case State::Source::Form::Renew:
        return "renew";
    case State::Source::Form::Erase:
        return "erase";
    }
    throw std::logic_error("Unknown Catalog source form");
}

// A missing body is an expired floor; it must never be serialized as an empty live payload.
void record(std::ostream& output, const Record& row) {
    output << '[' << row.version << ',';
    if (row.body) {
        payload(output, *row.body);
    } else {
        output << "null";
    }
    output << ',';
    if (row.deadline) {
        output << std::chrono::duration_cast<std::chrono::nanoseconds>(row.deadline->time_since_epoch()).count();
    } else {
        output << "null";
    }
    output << ']';
}

// Observe every native cursor suffix in its real order and retain the native atomic boundary markers.
void replay(std::ostream& output, State& state, std::uint64_t cursor) {
    output << '[';
    for (std::uint64_t since = 0; since <= cursor + 1; ++since) {
        output << (since ? "," : "") << '[' << since << ',';
        const auto events = state.changes(scope, since);
        if (!events) {
            output << '"' << error(events.error()) << '"';
        } else {
            output << '[';
            bool separator{};
            for (const auto& event : *events) {
                output << (separator ? "," : "") << '[' << event.version << ",\"" << event.name->key << "\",";
                if (event.record) {
                    output << '[' << event.record->version << ',';
                    payload(output, *event.record->value);
                    output << ']';
                } else {
                    output << "null";
                }
                output << ',' << event.first << ',' << event.last << ']';
                separator = true;
            }
            output << ']';
        }
        output << ']';
    }
    output << ']';
}

// Keep the complete source state and exported facts separate from the visible projection's cursor.
void trace(std::ostream& output, State& state, const auto& frozen) {
    const auto root = state.capture(scope);
    if (!root) {
        throw std::logic_error("Catalog capture failed");
    }
    output << "\"current\":";
    snapshot(output, *root);
    const auto source = state.source();
    std::map<std::tuple<std::string, std::string, std::string>, Record> records;
    source.each([&records](const auto& address, const auto& key, const auto& row) { records.emplace(std::tuple{address.sector, address.spectrum, key}, Record{row.version, row.value ? std::optional(*row.value) : std::nullopt, row.deadline}); });
    output << ",\"source\":[" << source.position() << ",[";
    bool separator{};
    for (const auto& [address, row] : records) {
        output << (separator ? "," : "") << "[\"" << std::get<0>(address) << "\",\"" << std::get<1>(address) << "\",\"" << std::get<2>(address) << "\",";
        std::ostringstream item;
        record(item, row);
        const auto body = item.str();
        output << body.substr(1, body.size() - 2) << ']';
        separator = true;
    }
    output << "]],\"exports\":[";
    const auto exports = state.events(0);
    if (!exports) {
        throw std::logic_error("Catalog export failed");
    }
    separator = false;
    for (const auto& event : *exports) {
        output << (separator ? "," : "") << '[' << event.position << ",\"" << event.name->scope->sector << "\",\"" << event.name->scope->spectrum << "\",\"" << event.name->key << "\",\"" << form(event.form) << "\",";
        if (event.record) {
            record(output, Record{event.record->version, event.record->value ? std::optional(*event.record->value) : std::nullopt, event.record->deadline});
        } else {
            output << "null";
        }
        output << ']';
        separator = true;
    }
    output << "],\"replay\":";
    replay(output, state, root->version());
    output << ",\"frozen\":[";
    separator = false;
    for (const auto& old : frozen) {
        output << (separator ? "," : "");
        snapshot(output, old);
        separator = true;
    }
    output << ']';
}

// Actual observations, never a reference-model winner or expected state, enter the bounded envelope.
void frame(std::string_view event, const std::string& value) {
    std::cout << "ASTRA-MODEL {\"model\":\"catalog-state-v1\",\"event\":\"" << event << "\",\"value\":" << value << "}\n";
}

// Select a legal serialization by complete native state and log, not just the last payload or error code.
bool matches(State& state, const Model& model) {

    const auto root = state.capture(scope);
    if (!root || root->version() != model.cursor || view(*root) != model.view()) {
        return false;
    }
    const auto source = state.source();
    std::map<std::string, Record> records;
    source.each([&records](const auto& address, const auto& key, const auto& row) {
        CHECK(address == scope);
        records.emplace(key, Record{row.version, row.value ? std::optional(*row.value) : std::nullopt, row.deadline});
    });
    if (source.position() != model.position || records != model.records) {
        return false;
    }
    const auto events = state.changes(scope, 0);
    if (!events || events->size() != model.cursor) {
        return false;
    }
    std::vector<Change> changes;
    for (const auto& event : *events) {
        if (event.version != changes.size() + 1) {
            return false;
        }
        changes.emplace_back(event.name->key, event.record ? std::optional(Content{event.record->version, *event.record->value}) : std::nullopt);
    }
    for (const auto& batch : model.history) {
        auto expected = batch.changes;
        const auto part = std::span(changes).subspan(batch.first - 1, batch.last - batch.first + 1);
        std::vector<Change> actual(part.begin(), part.end());
        std::ranges::sort(expected);
        std::ranges::sort(actual);
        if (actual != expected) {
            return false;
        }
    }
    // Equal final payloads/log entries can have different atomic boundaries; reconcile every cursor before choosing an order.
    for (std::uint64_t since = 0; since <= model.cursor; ++since) {
        const auto replay = state.changes(scope, since);
        const bool middle = std::ranges::any_of(model.history, [since](const auto& batch) { return batch.atomic && since >= batch.first && since < batch.last; });
        if (middle ? replay.has_value() || replay.error() != State::Error::History : !replay || replay->size() != model.cursor - since) {
            return false;
        }
    }
    return true;
}

// All captured roots must belong to the same candidate history, rather than borrowing prefixes from opposite orders.
bool prefixes(const auto& frozen, const Model& initial, const Model& middle, const Model& final) {

    std::uint64_t previous = initial.cursor;
    for (const auto& root : frozen) {
        if (root.version() < previous) {
            return false;
        }
        previous = root.version();
        const auto content = view(root);
        if (!((root.version() == initial.cursor && content == initial.view()) || (root.version() == middle.cursor && content == middle.view()) || (root.version() == final.cursor && content == final.view()))) {
            return false;
        }
    }
    return true;
}

// Exhaust operation pairs at four starting states; a start barrier permits overlap without changing production locks.
void concurrent() {

    unsigned histories{}, snapshots{};
    const std::array<unsigned, 8> operations{0, 1, 2, 3, 4, 5, 6, 8};
    for (unsigned prefix = 0; prefix < 4; ++prefix) {
        for (const auto left : operations) {
            for (const auto right : operations) {
                Model initial;
                State state([&initial] { return std::optional(astra::Clock::Reading{.time = initial.now, .ready = true}); }, {});
                if (prefix == 1) {
                    (void)step(state, initial, 0);
                }
                if (prefix >= 2) {
                    (void)step(state, initial, 3);
                }
                if (prefix == 3) {
                    (void)step(state, initial, 7);
                }

                // Setup receipts are asserted by step; retain actual initial reads before writer overlap.
                const std::vector<State::Projection::View> empty;
                std::ostringstream observation;
                observation << "{\"ordinal\":" << histories << ",\"prefix\":" << prefix << ",\"operations\":[" << left << ',' << right << "],\"initial\":{";
                trace(observation, state, empty);
                observation << '}';

                const std::array<Input, 2> requests{input(left), input(right)};
                Model forward = initial, reverse = initial;
                std::array<std::optional<State::Error>, 2> first, second, actual;
                first[0] = apply(forward, requests[0]);
                const auto forwardMiddle = forward;
                first[1] = apply(forward, requests[1]);
                second[1] = apply(reverse, requests[1]);
                const auto reverseMiddle = reverse;
                second[0] = apply(reverse, requests[0]);

                // Distinct output slots and joined lifetimes prevent the fixture from introducing its own data race.
                std::array<std::exception_ptr, 3> errors;
                std::vector<State::Projection::View> frozen;
                frozen.reserve(64);
                std::barrier start(3);
                auto write = [&state, &requests, &actual, &errors, &start](unsigned index) {
                    start.arrive_and_wait();
                    try {
                        actual[index] = apply(state, requests[index]);
                    } catch (...) {
                        errors[index] = std::current_exception();
                    }
                };
                std::jthread writer(write, 0), other(write, 1);
                std::jthread reader([&state, &frozen, &errors, &start] {
                    start.arrive_and_wait();
                    try {
                        for (unsigned index = 0; index < 64; ++index) {
                            const auto root = state.capture(scope);
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
                const bool ordered = actual == first && matches(state, forward) && prefixes(frozen, initial, forwardMiddle, forward);
                CHECK(ordered || (actual == second && matches(state, reverse) && prefixes(frozen, initial, reverseMiddle, reverse)));
                const std::vector<std::tuple<State::Projection::View, Map, std::uint64_t>> none;
                verify(state, ordered ? forward : reverse, none);
                const std::array<Model, 3> allowed{initial, ordered ? forwardMiddle : reverseMiddle, ordered ? forward : reverse};
                for (const auto& root : frozen) {
                    const auto content = view(root);
                    CHECK(std::ranges::any_of(allowed, [&root, &content](const auto& model) { return root.version() == model.cursor && content == model.view(); }));
                    ++snapshots;
                }
                observation << ",\"receipts\":[\"" << (actual[0] ? error(*actual[0]) : "ok") << "\",\"" << (actual[1] ? error(*actual[1]) : "ok") << "\"],";
                trace(observation, state, frozen);
                observation << '}';
                frame("pair", observation.str());
                ++histories;
            }
        }
    }
    CHECK(histories == 256 && snapshots == 16384);
    std::cout << "CATALOG-CONCURRENCY histories=" << histories << " snapshots=" << snapshots << " starts=4 operations=8 serializations=2 internal-schedules=not-enumerated\n";
}
} // namespace

// No pruning, sleeps, real network or implementation-derived expected states appear in this finite domain.
int main() {
    unsigned histories{}, transitions{};
    try {
        frame("start", "{\"keys\":[\"a\",\"b\"],\"operations\":9,\"depth\":4,\"histories\":6561,\"pruning\":0,\"pairs\":256,\"starts\":4,\"pair_operations\":8,\"reads\":64,\"serializations\":2}");
        for (unsigned number = 0; number < 6561; ++number) {
            Model model;
            State state([&model] { return std::optional(astra::Clock::Reading{.time = model.now, .ready = true}); }, {});
            std::vector<std::tuple<State::Projection::View, Map, std::uint64_t>> frozen;
            std::vector<State::Projection::View> roots;
            std::ostringstream observation;
            observation << "{\"ordinal\":" << number << ",\"states\":[";
            auto remaining = number;
            for (unsigned depth = 0; depth < 4; ++depth) {
                frozen.emplace_back(*state.capture(scope), model.view(), model.cursor);
                roots.push_back(std::get<0>(frozen.back()));
                const auto operation = remaining % 9;
                const auto actual = step(state, model, operation);
                remaining /= 9;
                verify(state, model, frozen);
                observation << (depth ? "," : "") << "{\"operation\":" << operation << ",\"receipt\":\"" << (operation == 7 ? "tick" : actual ? error(*actual)
                                                                                                                                              : "ok")
                            << "\",\"now\":" << std::chrono::duration_cast<std::chrono::nanoseconds>(model.now.time_since_epoch()).count() << ',';
                trace(observation, state, roots);
                observation << '}';
                ++transitions;
            }
            observation << "]}";
            frame("history", observation.str());
            ++histories;
        }
        CHECK(histories == 6561 && transitions == 26244);
        std::cout << "CATALOG-MODEL histories=" << histories << " transitions=" << transitions << " depth=4 operations=9 pruning=0\n";
        concurrent();
        frame("finish", "{\"histories\":6561,\"transitions\":26244,\"pairs\":256,\"snapshots\":16384}");
        std::cout.flush();
        CHECK(std::cout.good());
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "CATALOG-MODEL histories=" << histories << " transitions=" << transitions << ' ' << error.what() << '\n';
        return 1;
    }
}
