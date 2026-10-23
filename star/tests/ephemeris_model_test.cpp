// Exhaust local Ephemeris histories against independent payload, deadline and sequence registers.
#include "check.hpp"
#include "ephemeris_state.hpp"

#include <algorithm>
#include <array>
#include <barrier>
#include <exception>
#include <iostream>
#include <map>
#include <span>
#include <sstream>
#include <thread>
#include <tuple>

namespace {
using namespace std::chrono_literals;
using State = astra::Ephemeris::State;
using Buffer = astra::Ephemeris::Buffer;
using Time = astra::Clock::Time;
using Content = std::pair<Buffer, Buffer>;
using Map = std::map<std::string, Content>;
using Change = std::pair<std::string, std::optional<Content>>;
const astra::Scope scope{"model", "ephemeris"};

// Only observable local records appear here; no source tree, agenda, ownership index or transition is reused.
struct Record {
    /// Own fixed Attr and current Data bytes independently in the reference model.
    Buffer attr, data;
    /// Keep the registration's absolute controlled expiry time.
    Time deadline;
    /// Track update and renewal orders separately so one cannot advance the other.
    std::uint64_t update{}, renewal{};

    bool operator==(const Record&) const = default;
};

// Expiry order is unspecified; retain its exact cursor interval and complete deletion set.
struct Batch {
    /// Record inclusive cursor bounds for a complete visible change batch.
    std::uint64_t first{}, last{};
    /// Own the model's visible registration changes for replay comparison.
    std::vector<Change> changes;
};

/// Independent reference state for Ephemeris records, retained batches, and version progress.
struct Model {
    /// Track independent registration payloads, orders, and deadlines by UUID.
    std::map<std::string, Record> records;
    /// Retain model change batches without sharing production transition helpers.
    std::vector<Batch> history;
    /// Advance controlled business time explicitly, starting at one second.
    Time now{1s};
    /// Track exported and visible cursors, initially two for the two seeded registrations.
    std::uint64_t position{2}, cursor{2};

    void commit(std::vector<Change> changes) {
        if (!changes.empty()) {
            const auto first = cursor + 1;
            cursor += changes.size();
            history.push_back({first, cursor, std::move(changes)});
        }
    }

    // Each authoritative local expiry exports an ending; no update or renewal can revive the absent record.
    void expire() {
        std::vector<Change> changes;
        for (auto entry = records.begin(); entry != records.end();) {
            if (entry->second.deadline <= now) {
                changes.emplace_back(entry->first, std::nullopt);
                entry = records.erase(entry);
                ++position;
            } else {
                ++entry;
            }
        }
        commit(std::move(changes));
    }

    // Public views contain fixed attributes and the latest complete data, independently of native sequences.
    Map view() const {
        Map result;
        for (const auto& [key, row] : records) {
            result.emplace(key, Content{row.attr, row.data});
        }
        return result;
    }

    // New update/renewal orders advance independently; identical orders acknowledge without extending a lease.
    std::optional<State::Error> apply(const std::string& key, unsigned kind, std::uint64_t order, const Buffer& data) {
        const auto found = records.find(key);
        if (found == records.end()) {
            return State::Error::Ended;
        }
        auto& row = found->second;
        if (kind == 2) {
            records.erase(found);
            ++position;
            commit({{key, std::nullopt}});
            return {};
        }
        if (order == 0) {
            return State::Error::Input;
        }
        auto& previous = kind == 1 ? row.renewal : row.update;
        if (order < previous) {
            return State::Error::Obsolete;
        }
        if (order == previous) {
            if (kind == 0 && data != row.data) {
                return State::Error::Conflict;
            }
            return {};
        }
        previous = order;
        row.deadline = std::max(row.deadline, now + 1s);
        ++position;
        if (kind == 0 && data != row.data) {
            row.data = data;
            commit({{key, Content{row.attr, data}}});
        }
        return {};
    }
};

// Payload copies make frozen-root checks independent of the production sharing implementation.
Map view(const State::Projection::View& root) {
    Map result;
    root.each([&result](const auto& key, const auto& row) { CHECK(row.attr && row.data && result.emplace(key, Content{*row.attr, *row.data}).second); });
    return result;
}

// Reconcile native registers and public content, every frozen root and the complete exported source prefix.
void verify(State& state, const Model& model, const auto& frozen) {
    const auto root = state.capture(scope);
    CHECK(root && root->version() == model.cursor && view(*root) == model.view());
    const auto source = state.source();
    CHECK(source.position() == model.position && source.size() == model.records.size());
    std::map<std::string, Record> received;
    source.each([&received](const auto& address, const auto& key, const auto& row) {
        CHECK(address == scope && row.attr && row.data && row.ttl == 1000 && row.generation == 1);
        received.emplace(key, Record{*row.attr, *row.data, row.deadline, row.update, row.renewal});
    });
    CHECK(received.size() == model.records.size());
    for (const auto& [key, row] : model.records) {
        const auto& actual = received.at(key);
        CHECK(actual.attr == row.attr && actual.data == row.data && actual.deadline == row.deadline && actual.update == row.update && actual.renewal == row.renewal);
    }
    const auto exported = state.events(0);
    CHECK(exported && exported->size() == model.position);
    for (const auto& [old, expected, cursor] : frozen) {
        CHECK(old.version() == cursor && view(old) == expected);
    }
    for (std::uint64_t since = 0; since <= model.cursor + 1; ++since) {
        const auto replay = state.changes(scope, since);
        if (since > model.cursor) {
            CHECK(!replay && replay.error() == State::Error::Input);
            continue;
        }
        CHECK(replay && replay->size() == model.cursor - since);
        std::vector<Change> actual;
        for (const auto& event : *replay) {
            CHECK(event.version == since + actual.size() + 1);
            actual.emplace_back(event.name->key, event.record ? std::optional(Content{*event.record->attr, *event.record->data}) : std::nullopt);
        }
        std::size_t offset{};
        for (const auto& batch : model.history) {
            if (batch.last <= since) {
                continue;
            }
            const auto count = batch.last - std::max(since, batch.first - 1);
            CHECK(offset <= actual.size() && count <= actual.size() - offset);
            const auto part = std::span(actual).subspan(offset, count);
            std::vector<Change> segment(part.begin(), part.end());
            auto expected = batch.changes;
            std::ranges::sort(segment);
            std::ranges::sort(expected);
            CHECK(std::ranges::includes(expected, segment));
            if (since < batch.first) {
                CHECK(segment == expected);
            }
            offset += count;
        }
    }
}

// This decoder declares inputs only; reference transitions remain independent of production state/layout.
struct Input {
    /// Select one of two synthetic principals and the update, renewal, or removal operation.
    unsigned principal{}, kind{};
    /// Supply the operation-specific order, including deliberately invalid zero.
    std::uint64_t order{};
    /// Own the candidate Data bytes supplied to update cases.
    Buffer body;
};

Input input(unsigned operation) {
    const unsigned principal = operation == 4 || operation == 5 ? 1 : 0;
    const unsigned kind = operation == 3 || operation == 7 ? 1 : operation == 5 ? 2
                                                                                : 0;
    const std::uint64_t order = operation == 8 ? 0 : operation == 1 || operation == 7 ? 2
                                                                                      : 1;
    const Buffer body = operation == 4 ? Buffer{} : Buffer{static_cast<std::uint8_t>(operation == 1 || operation == 2 ? 2 : 1)};
    return {principal, kind, order, body};
}

std::optional<State::Error> apply(Model& model, const auto& keys, const Input& request) {
    return model.apply(keys[request.principal], request.kind, request.order, request.body);
}

std::optional<State::Error> apply(State& state, const auto& keys, const auto& capabilities, const Input& request) {

    const auto& key = keys[request.principal];
    const auto& capability = capabilities[request.principal];
    const auto result = request.kind == 2   ? state.remove(scope, key, 1, capability)
                        : request.kind == 1 ? state.renew(scope, key, request.order, 1, capability)
                                            : state.update(scope, key, std::make_shared<const Buffer>(request.body), request.order, 1, capability);
    return result ? std::nullopt : std::optional(result.error());
}

// Nine operations retain separate update/renewal orders, stale/conflicting retries, removal and virtual expiry.
std::optional<State::Error> step(State& state, Model& model, const auto& keys, const auto& capabilities, unsigned operation) {

    if (operation == 6) {
        model.now += 500ms;
        model.expire();
        state.tick();
        return {};
    }
    const auto request = input(operation);
    const auto expected = apply(model, keys, request);
    const auto actual = apply(state, keys, capabilities, request);
    CHECK(actual == expected);
    return actual;
}

// Create two opaque fixed-capability inputs and anchor their visible creation logs without sharing transition logic.
auto initialize(State& state, Model& model, const auto& keys, const auto& capabilities, const auto& attributes) {

    std::array<State::Receipt, 2> receipts;
    for (unsigned index = 0; index < keys.size(); ++index) {
        const Buffer body{static_cast<std::uint8_t>(index + 1)};
        const auto created = state.create(scope, std::make_shared<const Buffer>(attributes[index]), std::make_shared<const Buffer>(body), 1000, keys[index], 1, 0, capabilities[index]);
        CHECK(created && created->uuid == keys[index] && created->order == 0 && created->generation == 1 && created->ttl == 1000 && *created->data == body);
        receipts[index] = *created;
        model.records.emplace(keys[index], Record{attributes[index], body, model.now + 1s});
        model.history.push_back({index + 1u, index + 1u, {{keys[index], Content{attributes[index], body}}}});
    }
    return receipts;
}

// Encode opaque binary UUID inputs as fixed hexadecimal text, without deriving expected identities.
void key(std::ostream& output, std::string_view value, bool compact = true) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string encoded;
    encoded.reserve(value.size() * 2);
    for (const char item : value) {
        const auto byte = static_cast<unsigned char>(item);
        encoded.append({digits[byte >> 4], digits[byte & 15]});
    }
    if (compact && encoded == "04beceaf988446038c15a7eab10d1dd1") {
        output << 0;
    } else if (compact && encoded == "f710824f3f6d40eea6d946de1329ee16") {
        output << 1;
    } else {
        output << '"' << encoded << '"';
    }
}

// Actual immutable payload bytes are copied into observations without assertion-counting traversals.
void payload(std::ostream& output, const Buffer& value) {
    output << '[';
    for (std::size_t index = 0; index < value.size(); ++index) {
        output << (index ? "," : "") << static_cast<unsigned>(value[index]);
    }
    output << ']';
}

// Preserve fixed Attr separately from Data and retain the public content cursor.
void snapshot(std::ostream& output, const State::Projection::View& root) {
    output << '[' << root.version() << ",[";
    Map records;
    root.each([&records](const auto& name, const auto& row) { records.emplace(name, Content{*row.attr, *row.data}); });
    bool separator{};
    for (const auto& [name, row] : records) {
        output << (separator ? "," : "") << '[';
        key(output, name);
        output << ',';
        payload(output, row.first);
        output << ',';
        payload(output, row.second);
        output << ']';
        separator = true;
    }
    output << "]]";
}

// Stable error names retain ended/input precedence and independent sequence conflicts.
const char* error(State::Error value) {
    switch (value) {
    case State::Error::Input:
        return "input";
    case State::Error::Clock:
        return "clock";
    case State::Error::Ended:
        return "ended";
    case State::Error::Obsolete:
        return "obsolete";
    case State::Error::Conflict:
        return "conflict";
    case State::Error::Exhausted:
        return "exhausted";
    case State::Error::Capacity:
        return "capacity";
    case State::Error::History:
        return "history";
    }
    throw std::logic_error("Unknown Ephemeris error");
}

// Exported form distinguishes creation, dynamic update, renewal and authoritative ending.
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
    throw std::logic_error("Unknown Ephemeris source form");
}

// Complete native records include both independent orders and immutable TTL/generation.
void record(std::ostream& output, const astra::Ephemeris::Record& row) {
    output << '[';
    payload(output, *row.attr);
    output << ',';
    payload(output, *row.data);
    output << ',' << std::chrono::duration_cast<std::chrono::nanoseconds>(row.deadline.time_since_epoch()).count() << ',' << row.update << ',' << row.renewal << ',' << row.ttl << ',' << row.generation << ']';
}

// Every suffix retains its actual source-independent visible order and native event boundaries.
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
                output << (separator ? "," : "") << '[' << event.version << ',';
                key(output, event.name->key);
                output << ',';
                if (event.record) {
                    output << '[';
                    payload(output, *event.record->attr);
                    output << ',';
                    payload(output, *event.record->data);
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

// Observe actual complete source/public state only after writers stop; preserved roots remain immutable.
void trace(std::ostream& output, State& state, const auto& frozen) {
    const auto root = state.capture(scope);
    if (!root) {
        throw std::logic_error("Ephemeris capture failed");
    }
    output << "\"current\":";
    snapshot(output, *root);
    const auto source = state.source();
    std::map<std::tuple<std::string, std::string, std::string>, astra::Ephemeris::Record> records;
    source.each([&records](const auto& address, const auto& name, const auto& row) { records.emplace(std::tuple{address.sector, address.spectrum, name}, row); });
    output << ",\"source\":[" << source.position() << ",[";
    bool separator{};
    for (const auto& [address, row] : records) {
        output << (separator ? "," : "") << "[\"" << std::get<0>(address) << "\",\"" << std::get<1>(address) << "\",";
        key(output, std::get<2>(address));
        output << ',';
        record(output, row);
        output << ']';
        separator = true;
    }
    output << "]],\"exports\":[";
    const auto exported = state.events(0);
    if (!exported) {
        throw std::logic_error("Ephemeris export failed");
    }
    separator = false;
    for (const auto& event : *exported) {
        output << (separator ? "," : "") << '[' << event.position << ",\"" << event.name->scope->sector << "\",\"" << event.name->scope->spectrum << "\",";
        key(output, event.name->key);
        output << ",\"" << form(event.form) << "\",";
        if (event.record) {
            record(output, *event.record);
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

// Retain actual creation receipts separately from complete state observations.
void created(std::ostream& output, const auto& receipts) {
    output << '[';
    bool separator{};
    for (const auto& receipt : receipts) {
        output << (separator ? "," : "") << '[';
        key(output, receipt.uuid, false);
        output << ',' << receipt.order << ',' << receipt.generation << ',' << receipt.ttl << ',';
        payload(output, *receipt.data);
        output << ']';
        separator = true;
    }
    output << ']';
}

// Bounded complete frames carry actual observations; no expected state or chosen serialization is emitted.
void frame(std::string_view event, std::string_view value) {
    std::cout << "ASTRA-MODEL {\"model\":\"ephemeris-state-v1\",\"event\":\"" << event << "\",\"value\":" << value << "}\n";
}

// Compare complete source registers and ordered visible logs after both writers stop.
bool matches(State& state, const Model& model) {

    const auto root = state.capture(scope);
    if (!root || root->version() != model.cursor || view(*root) != model.view()) {
        return false;
    }
    const auto source = state.source();
    std::map<std::string, Record> records;
    source.each([&records](const auto& address, const auto& key, const auto& row) {
        CHECK(address == scope && row.attr && row.data && row.ttl == 1000 && row.generation == 1);
        records.emplace(key, Record{*row.attr, *row.data, row.deadline, row.update, row.renewal});
    });
    if (source.position() != model.position || records != model.records) {
        return false;
    }
    const auto replay = state.changes(scope, 0);
    if (!replay || replay->size() != model.cursor) {
        return false;
    }
    std::vector<Change> changes;
    for (const auto& event : *replay) {
        if (event.version != changes.size() + 1) {
            return false;
        }
        changes.emplace_back(event.name->key, event.record ? std::optional(Content{*event.record->attr, *event.record->data}) : std::nullopt);
    }
    for (const auto& batch : model.history) {
        const auto part = std::span(changes).subspan(batch.first - 1, batch.last - batch.first + 1);
        auto expected = batch.changes;
        std::vector<Change> actual(part.begin(), part.end());
        std::ranges::sort(expected);
        std::ranges::sort(actual);
        if (actual != expected) {
            return false;
        }
    }
    return true;
}

// Snapshot observations must share one serialization with the recorded results and native registers.
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

// Enumerate pairs against both legal serializations; native overlapping schedules are sampled, not exhaustively proved.
void concurrent(const auto& keys, const auto& capabilities, const auto& attributes) {

    unsigned histories{}, snapshots{};
    const std::array<unsigned, 8> operations{0, 1, 2, 3, 4, 5, 7, 8};
    for (unsigned prefix = 0; prefix < 4; ++prefix) {
        for (const auto left : operations) {
            for (const auto right : operations) {
                Model initial;
                State state([&initial] { return std::optional(astra::Clock::Reading{.time = initial.now, .ready = true}); }, {});
                const auto receipts = initialize(state, initial, keys, capabilities, attributes);
                if (prefix == 1) {
                    (void)step(state, initial, keys, capabilities, 0);
                }
                if (prefix == 2) {
                    (void)step(state, initial, keys, capabilities, 1);
                    (void)step(state, initial, keys, capabilities, 7);
                }
                if (prefix == 3) {
                    (void)step(state, initial, keys, capabilities, 5);
                }

                std::ostringstream observation;
                observation << "{\"ordinal\":" << histories << ",\"prefix\":" << prefix << ",\"operations\":[" << left << ',' << right << "],\"created\":";
                created(observation, receipts);
                observation << ",\"initial\":{";
                const std::vector<State::Projection::View> empty;
                trace(observation, state, empty);
                observation << '}';

                const std::array<Input, 2> requests{input(left), input(right)};
                Model forward = initial, reverse = initial;
                std::array<std::optional<State::Error>, 2> first, second, actual;
                first[0] = apply(forward, keys, requests[0]);
                const auto forwardMiddle = forward;
                first[1] = apply(forward, keys, requests[1]);
                second[1] = apply(reverse, keys, requests[1]);
                const auto reverseMiddle = reverse;
                second[0] = apply(reverse, keys, requests[0]);

                std::array<std::exception_ptr, 3> errors;
                std::vector<State::Projection::View> frozen;
                frozen.reserve(64);
                std::barrier start(3);
                auto write = [&state, &keys, &capabilities, &requests, &actual, &errors, &start](unsigned index) {
                    start.arrive_and_wait();
                    try {
                        actual[index] = apply(state, keys, capabilities, requests[index]);
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
    std::cout << "EPHEMERIS-CONCURRENCY histories=" << histories << " snapshots=" << snapshots << " starts=4 operations=8 serializations=2 internal-schedules=not-enumerated\n";
}
} // namespace

// Fixed capabilities supply opaque deterministic API identifiers; identity derivation is outside this model's oracle.
int main() {
    unsigned histories{}, transitions{};
    try {
        const std::array<std::string, 2> capabilities{std::string(32, 'a'), std::string(32, 'b')};
        const std::array<Buffer, 2> attributes{Buffer{3}, Buffer{4}};
        std::array<std::string, 2> keys;
        for (unsigned index = 0; index < keys.size(); ++index) {
            keys[index] = astra::Ephemeris::identity(scope, std::make_shared<const Buffer>(attributes[index]), 1000, capabilities[index]);
        }
        CHECK(keys[0] != keys[1]);
        std::ostringstream domain;
        domain << "{\"keys\":[";
        key(domain, keys[0], false);
        domain << ',';
        key(domain, keys[1], false);
        domain << "],\"operations\":9,\"depth\":4,\"histories\":6561,\"pruning\":0,\"pairs\":256,\"starts\":4,\"pair_operations\":8,\"reads\":64,\"serializations\":2}";
        frame("start", domain.str());
        for (unsigned number = 0; number < 6561; ++number) {
            Model model;
            State state([&model] { return std::optional(astra::Clock::Reading{.time = model.now, .ready = true}); }, {});
            const auto receipts = initialize(state, model, keys, capabilities, attributes);
            std::vector<std::tuple<State::Projection::View, Map, std::uint64_t>> frozen;
            std::vector<State::Projection::View> roots;
            std::ostringstream observation;
            observation << "{\"ordinal\":" << number << ",\"created\":";
            created(observation, receipts);
            observation << ",\"initial\":{";
            trace(observation, state, roots);
            observation << "},\"states\":[";
            auto remaining = number;
            for (unsigned depth = 0; depth < 4; ++depth) {
                frozen.emplace_back(*state.capture(scope), model.view(), model.cursor);
                roots.push_back(std::get<0>(frozen.back()));
                const auto operation = remaining % 9;
                const auto actual = step(state, model, keys, capabilities, operation);
                remaining /= 9;
                verify(state, model, frozen);
                observation << (depth ? "," : "") << "{\"operation\":" << operation << ",\"receipt\":\"" << (operation == 6 ? "tick" : actual ? error(*actual)
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
        std::cout << "EPHEMERIS-MODEL histories=" << histories << " transitions=" << transitions << " depth=4 operations=9 pruning=0\n";
        concurrent(keys, capabilities, attributes);
        frame("finish", "{\"histories\":6561,\"transitions\":26244,\"pairs\":256,\"snapshots\":16384}");
        std::cout.flush();
        CHECK(std::cout.good());
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "EPHEMERIS-MODEL histories=" << histories << " transitions=" << transitions << ' ' << error.what() << '\n';
        return 1;
    }
}
