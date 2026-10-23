// Exhaust every length-four history in a bounded independent Store model, including retained snapshots and TTL batches.
#include "check.hpp"
#include "store.hpp"

#include <algorithm>
#include <array>
#include <deque>
#include <iostream>
#include <map>
#include <optional>
#include <tuple>
#include <vector>

namespace {
using namespace std::chrono_literals;
using Buffer = astra::Store::Buffer;
using Time = astra::Clock::Time;
using Record = std::pair<Buffer, std::optional<Time>>;
using Map = std::map<std::string, Record>;
using Change = std::tuple<std::uint64_t, std::string, std::optional<Buffer>, std::optional<Time>>;

// This ordinary map/log model contains no Store, index, wheel, timer nodes or production transition helpers.
struct Model {
    /// Keep independent model contents keyed by the test address.
    Map values;
    /// Track the model commit version independently of production implementation counters.
    std::uint64_t version{};
    /// Record the earliest retained model history boundary used to reject stale replay requests.
    std::uint64_t oldest{};
    /// Use controlled business time, initially one second, for deterministic expiry.
    Time now{1s};
    /// Retain complete model change batches for independent replay expectations.
    std::deque<std::vector<Change>> history;

    // Commit a complete independent batch and retain exactly the last two committed batches.
    void commit(std::vector<Change> changes) {
        ++version;
        for (auto& change : changes) {
            std::get<0>(change) = version;
        }
        history.push_back(std::move(changes));
        if (history.size() > 2) {
            oldest = std::get<0>(history.front().front());
            history.pop_front();
        }
    }

    // Apply one of eight predeclared operations using only map and log semantics.
    void step(unsigned operation) {
        if (operation == 3 || operation == 4) {
            const std::string key = operation == 3 ? "a" : "b";
            if (values.erase(key)) {
                commit({{0, key, {}, {}}});
            }
        } else if (operation == 5 || operation == 7) {
            if (operation == 5) {
                now += 1ms;
            }
            std::vector<Change> changes;
            for (auto entry = values.begin(); entry != values.end();) {
                if (entry->second.second && *entry->second.second <= now) {
                    changes.emplace_back(0, entry->first, std::nullopt, std::nullopt);
                    entry = values.erase(entry);
                } else {
                    ++entry;
                }
            }
            if (!changes.empty()) {
                commit(std::move(changes));
            }
        } else {
            const std::string key = operation < 2 ? "a" : "b";
            const Buffer body = operation == 2 ? Buffer{} : Buffer{static_cast<std::uint8_t>(operation + 1)};
            const std::optional<Time> deadline = operation == 1 || operation == 6 ? std::optional(now + 1ms) : std::nullopt;
            values[key] = {body, deadline};
            commit({{0, key, body, deadline}});
        }
    }
};

// Compare all complete values and deadlines without depending on native container order or pointer identity.
Map values(const astra::Store::Snapshot& snapshot) {
    Map result;
    for (const auto& [key, record] : snapshot.data) {
        CHECK(record.value);
        result.emplace(key, Record{*record.value, record.deadline});
    }
    return result;
}

// Verify current state, every cursor and every previously frozen root after each transition.
void verify(astra::Store& store, const Model& model, const auto& frozen) {
    CHECK(store.version() == model.version);
    const auto snapshot = store.snapshot();
    CHECK(snapshot->version == model.version && values(*snapshot) == model.values);
    for (const auto& [view, expected] : frozen) {
        CHECK(values(*view) == expected);
    }
    for (std::uint64_t since = 0; since <= model.version + 1; ++since) {
        const auto actual = store.extract(since);
        const bool stale = since < model.oldest || since > model.version;
        CHECK(actual.stale == stale && actual.version == model.version);
        std::vector<Change> expected, received;
        if (!stale) {
            for (const auto& batch : model.history) {
                if (std::get<0>(batch.front()) > since) {
                    expected.insert(expected.end(), batch.begin(), batch.end());
                }
            }
        }
        for (const auto& change : actual.deltas) {
            received.emplace_back(change.version, change.key, change.value ? std::optional(*change.value) : std::nullopt, change.deadline);
        }
        std::ranges::sort(expected);
        std::ranges::sort(received);
        CHECK(received == expected);
    }
}

/// Encode actual public payload bytes; a missing pointer remains different from a legal empty value.
void payload(const astra::Store::Value& value) {

    if (!value) {
        std::cout << "null";
        return;
    }
    std::cout << '[';
    for (std::size_t i = 0; i < value->size(); ++i) {
        std::cout << (i ? "," : "") << static_cast<unsigned>((*value)[i]);
    }
    std::cout << ']';
}

/// Encode the sole absolute deadline in nanoseconds without sampling a physical clock.
void deadline(const std::optional<Time>& value) {
    if (value) {
        std::cout << value->time_since_epoch().count();
    } else {
        std::cout << "null";
    }
}

/// Serialize a native captured view in canonical key order, without reading the reference model.
void snapshot(const astra::Store::Snapshot& value) {

    std::map<std::string, astra::Index::Record> ordered(value.data.begin(), value.data.end());
    std::cout << '[' << value.version << ",[";
    bool comma = false;
    for (const auto& [key, record] : ordered) {
        std::cout << (comma ? "," : "") << "[\"" << key << "\",";
        payload(record.value);
        std::cout << ',';
        deadline(record.deadline);
        std::cout << ']';
        comma = true;
    }
    std::cout << "]]";
}

/// Retain every actual current/frozen snapshot and extraction cursor for independent gate reconstruction.
void observe(astra::Store& store, unsigned operation, const auto& frozen) {

    const auto version = store.version();
    std::cout << "{\"operation\":" << operation << ",\"version\":" << version << ",\"current\":";
    snapshot(*store.snapshot());
    std::cout << ",\"frozen\":[";
    for (std::size_t i = 0; i < frozen.size(); ++i) {
        std::cout << (i ? "," : "");
        snapshot(*frozen[i].first);
    }

    std::cout << "],\"replay\":[";
    for (std::uint64_t since = 0; since <= version + 1; ++since) {
        auto result = store.extract(since);
        std::ranges::sort(result.deltas, {}, [](const auto& value) { return std::pair(value.version, value.key); });
        std::cout << (since ? "," : "") << '[' << since << ',' << (result.stale ? "true" : "false") << ',' << result.version << ",[";
        for (std::size_t i = 0; i < result.deltas.size(); ++i) {
            const auto& change = result.deltas[i];
            std::cout << (i ? "," : "") << '[' << change.version << ",\"" << change.key << "\",";
            payload(change.value);
            std::cout << ',';
            deadline(change.deadline);
            std::cout << ',' << (change.deleted ? "true" : "false") << ']';
        }
        std::cout << "]]";
    }
    std::cout << "]}";
}
} // namespace

// Enumerate 8^4 histories with no pruning; no wall-clock waits, network or randomized scheduling are part of this domain.
int main() {
    try {
        std::cout << "ASTRA-MODEL {\"model\":\"store-state-v1\",\"event\":\"start\",\"value\":{\"keys\":[\"a\",\"b\"],\"operations\":8,\"depth\":4,\"histories\":4096,\"capacity\":2,\"initial_ns\":1000000000,\"tick_ns\":1000000,\"retention\":\"maximum\",\"pruning\":0}}\n";
        for (unsigned history = 0; history < 4096; ++history) {
            // This domain tests capacity eviction, not elapsed-age eviction; injected tick timestamps start at zero.
            astra::Store store(2, astra::Steady::duration::max(), 1ms, Time(1s));
            Model model;
            std::vector<std::pair<std::shared_ptr<const astra::Store::Snapshot>, Map>> frozen;
            auto remaining = history;
            std::cout << "ASTRA-MODEL {\"model\":\"store-state-v1\",\"event\":\"history\",\"value\":{\"ordinal\":" << history << ",\"states\":[";
            for (unsigned depth = 0; depth < 4; ++depth) {
                const auto operation = remaining % 8;
                remaining /= 8;
                frozen.emplace_back(store.snapshot(), model.values);
                model.step(operation);
                if (operation == 3 || operation == 4) {
                    store.remove(operation == 3 ? "a" : "b");
                } else if (operation == 5 || operation == 7) {
                    store.tick(model.now, astra::Steady::time_point{});
                } else {
                    const std::string key = operation < 2 ? "a" : "b";
                    const auto& record = model.values.at(key);
                    store.put(key, record.first, record.second);
                }
                verify(store, model, frozen);
                std::cout << (depth ? "," : "");
                observe(store, operation, frozen);
            }
            std::cout << "]}}\n";
        }
        std::cout << "ASTRA-MODEL {\"model\":\"store-state-v1\",\"event\":\"finish\",\"value\":{\"histories\":4096,\"transitions\":16384}}\n";
        std::cout << "STORE-MODEL histories=4096 transitions=16384 depth=4 operations=8 pruning=0\n";
        std::cout.flush();
        CHECK(std::cout.good());
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
