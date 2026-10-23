// Exercise public SDK writes and cross-node observations against a real multi-Star fixture.
#include "batch.hpp"
#include <comet/client.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <fstream>
#include <iostream>
#include <limits>
#include <source_location>
#include <stdexcept>
#include <thread>

namespace {
using namespace std::chrono_literals;

/// Reads fixture-private secrets only; APISECRET never enters command-line arguments or logs.
std::vector<std::uint8_t> secret(const std::filesystem::path& path) {
    const auto size = std::filesystem::file_size(path);
    if (!std::filesystem::is_regular_file(path) || size == 0 || size > 4096) {
        throw std::runtime_error("Invalid private fixture file");
    }
    std::ifstream file(path, std::ios::binary);
    std::vector<std::uint8_t> value(static_cast<std::size_t>(size));
    if (!file.read(reinterpret_cast<char*>(value.data()), static_cast<std::streamsize>(size)) || file.peek() != std::char_traits<char>::eof()) {
        throw std::runtime_error("Cannot read fixture credential");
    }
    return value;
}

/// Creates an actual native Client; producer may fail over, while two observers pin Stars to verify replication.
comet::Client open(std::vector<std::string> endpoints, const std::filesystem::path& ca, const std::vector<std::uint8_t>& credential) {
    comet::Client::Options options;
    options.endpoints = std::move(endpoints);
    options.ca = ca;
    options.key = "integration";
    options.secret = credential;
    auto result = comet::Client::open(std::move(options));
    if (!result) {
        throw std::runtime_error("Cannot construct native mesh client");
    }
    return std::move(*result);
}

/// Waits for test-owned observable state outside SDK callbacks; deadlines fail explicitly instead of creating unbounded stress.
void until(auto&& predicate, std::chrono::seconds limit = 45s, const std::source_location location = std::source_location::current()) {
    const auto deadline = std::chrono::steady_clock::now() + limit;
    while (!predicate()) {
        if (std::chrono::steady_clock::now() >= deadline) {
            throw std::runtime_error("Native mesh state did not converge at line " + std::to_string(location.line()));
        }
        std::this_thread::sleep_for(20ms);
    }
}

/// Each owner closes and drains independently; exceptional paths cannot leave gRPC callbacks borrowing a destroyed probe stack.
struct Cleanup {
    /// Actual Client declared before the guard.
    comet::Client& client;

    ~Cleanup() {
        client.close();
        if (!client.wait(5s)) {
            std::terminate();
        }
    }
};

/// Require an actual confirmed SDK receipt after the resident batch has drained.
auto completed(auto& result) {
    if (!result) {
        throw std::runtime_error("Native mesh operation was not confirmed");
    }
    return std::move(*result);
}

/// Checks complete version and payload plus fixed Attr and current Data; stale contents do not prove recovery.
bool visible(const comet::Subscriber& subscriber, const comet::Observer& observer, std::string_view uuid, std::uint64_t version, const std::vector<std::uint8_t>& value, const std::vector<std::uint8_t>& data) {
    const auto catalog = subscriber.watch();
    const auto services = observer.select();
    const auto publication = catalog.find("key");
    const auto registration = services.find(uuid);
    return catalog.state() == comet::Subscriber::State::Ready && services.state() == comet::Observer::State::Ready && publication && publication->version == version && *publication->value == value && registration && *registration->attr == std::vector<std::uint8_t>{'a', 't', 't', 'r'} && *registration->data == data;
}

/// Keep the same writers, identities, version evidence and watch handles across every fault.
struct Workload {
    explicit Workload(std::size_t copies) : publishers(3 * copies), beacons(3 * copies), versions(3 * copies), identities(3 * copies), workers(6 * copies) {} // Fixed capacity before any network admission.

    /// One persistent business writer per key.
    std::vector<comet::Publisher> publishers;
    /// Original logical registrations survive node recovery.
    std::vector<comet::Beacon> beacons;
    /// Fixed-node views retain their actual reconnect lifecycle.
    std::array<comet::Subscriber, 3> subscribers;
    /// Each view checks all three sources.
    std::array<comet::Observer, 3> observers;
    /// Last confirmed receipt per key, preserved across stages.
    std::vector<std::uint64_t> versions;
    /// First UUID per Beacon, never replaced after failure.
    std::vector<std::string> identities;
    /// Partial construction cannot be mistaken for a complete fixture.
    bool initialized{};
    /// One resident thread per synchronous writer, retired before the borrowed handles.
    comet::test::Batch workers;

    /// Drain the original writers and verify deletion on all original observation handles.
    void close() {
        for (std::size_t index = 0; index < publishers.size(); ++index) {
            publishers[index].close();
            beacons[index].close();
            if (!publishers[index].wait(5s) || !beacons[index].wait(5s)) {
                throw std::runtime_error("Three-source writer cleanup timed out");
            }
        }
        until([&] {
            for (std::size_t index = 0; index < subscribers.size(); ++index) {
                if (subscribers[index].watch().size() != 0 || observers[index].select().size() != 0) {
                    return false;
                }
            }
            return true;
        },
              15s);
    }
};

// Three fixed admission endpoints verify all nine replication routes; zero duration still exercises two rounds.
void replication(const std::array<comet::Client*, 3>& clients, Workload& workload, std::chrono::seconds seconds, std::uint64_t base, bool continuous = false, bool finish = true) {

    // Each node owns copies (1..16) Keys or UUIDs in one Scope; interleaved numbering gives adjacent Keys different sources.
    const comet::Scope scope{"mesh", "parallel"};
    auto& [publishers, beacons, subscribers, observers, versions, identities, initialized, workers] = workload; // All handles and oracle history retain their original ownership.
    const auto records = publishers.size();                                                                     // At most 48 records in each domain.
    std::array<std::string, 3> instances;                                                                       // Three distinct admission Stars; verify both write receipts and view ownership.
    const std::vector<std::uint8_t> attr{'a', 't', 't', 'r'};                                                   // Bytewise reference for immutable attributes.
    if (!initialized) {
        for (std::size_t index = 0; index < records; ++index) {
            auto publisher = clients[index % clients.size()]->publisher(scope);
            auto beacon = clients[index % clients.size()]->beacon(scope, attr, {}, 3000ms, 1000ms);
            if (!publisher || !beacon) {
                throw std::runtime_error("Cannot create three-source writers");
            }
            publishers[index] = std::move(*publisher);
            beacons[index] = std::move(*beacon);
        }
        for (std::size_t index = 0; index < clients.size(); ++index) {
            auto subscriber = clients[index]->subscriber(scope);
            auto observer = clients[index]->observer(scope);
            if (!subscriber || !observer) {
                throw std::runtime_error("Cannot create three-source replication objects");
            }
            subscribers[index] = std::move(*subscriber);
            observers[index] = std::move(*observer);
        }
        initialized = true;
    }
    until([&] {
        for (const auto& beacon : beacons) {
            const auto state = beacon.state(); // One consistent state snapshot without mixing identities from separate reads.
            if (state.phase != comet::Beacon::Phase::Ready || !state.identity) {
                return false;
            }
        }
        return true;
    });
    for (std::size_t index = 0; index < records; ++index) {
        const auto identity = *beacons[index].state().identity; // Confirmed entry identity; binary UUIDs may contain NUL.
        if (identities[index].empty()) {
            identities[index] = identity.uuid;
        } else if (identities[index] != identity.uuid) {
            throw std::runtime_error("Persistent Beacon changed its logical UUID");
        }
        if (index < clients.size()) {
            instances[index] = identity.instance;
        } else if (identity.instance != instances[index % clients.size()]) {
            throw std::runtime_error("Fixed client changed admission during setup");
        }
    }
    if (instances[0] == instances[1] || instances[0] == instances[2] || instances[1] == instances[2]) {
        throw std::runtime_error("Three writers were not admitted by three distinct Stars");
    }

    // Test threads call synchronous Catalog API concurrently; Catalog and Beacon both receive local writes at all three entries.
    const auto deadline = std::chrono::steady_clock::now() + seconds; // Finite monotonic budget, unaffected by wall-clock rollback.
    std::uint64_t version = base;                                     // Preserve monotonic content versions across probes; TTL deletion does not remove source watermarks.
    do {
        if (version == std::numeric_limits<std::uint64_t>::max()) {
            throw std::runtime_error("Mesh version exhausted");
        }
        ++version;
        std::vector<std::vector<std::uint8_t>> values(records);                             // Complete 2 KiB payload encodes source and version to reject stale values.
        std::vector<comet::Result<comet::Publisher::Receipt>> writes(records);              // Each resident publisher thread produces exactly one receipt.
        std::vector<comet::Result<comet::Beacon::Receipt>> updates(records);                // Beacon writes remain concurrently in flight with Catalog writes.
        std::vector<std::array<std::chrono::steady_clock::time_point, 2>> timings(records); // Batch retirement synchronizes the diagnostic read.
        for (std::size_t index = 0; index < records; ++index) {
            values[index].assign(2048, static_cast<std::uint8_t>(index));
            for (unsigned byte = 0; byte < sizeof(version); ++byte) {
                values[index][byte] = static_cast<std::uint8_t>(version >> (byte * 8));
            }
        }
        workers.run([&](std::size_t slot) {
            const auto index = slot / 2; // Alternate Catalog and Beacon slots for every original record.
            if (slot % 2 == 0) {
                timings[index][0] = std::chrono::steady_clock::now();
                writes[index] = publishers[index].update(std::to_string(index), values[index], 3000ms, 10s);
                timings[index][1] = std::chrono::steady_clock::now();
            } else {
                updates[index] = beacons[index].update(values[index], 10s);
            }
        });
        for (std::size_t index = 0; index < records; ++index) {
            const auto publication = completed(writes[index]);   // Actual in-memory commit receipt, not task admission.
            const auto registration = completed(updates[index]); // Fixed entry and UUID remain unchanged during the normal phase.
            if (publication.instance != instances[index % clients.size()] || publication.version <= versions[index] || registration.identity.instance != instances[index % clients.size()] || registration.identity.uuid != identities[index]) {
                throw std::runtime_error("Three-source commit changed its owner or identity");
            }
            versions[index] = publication.version;
        }
        const auto observed = std::chrono::steady_clock::now(); // Retain the first complete observation independently of the eventual failure-time state.
        const std::array initial = {subscribers[0].watch(), subscribers[1].watch(), subscribers[2].watch()};
        try {
            until([&] {
                for (std::size_t target = 0; target < clients.size(); ++target) {
                    const auto catalog = subscribers[target].watch(); // Complete Catalog view at the current target.
                    const auto services = observers[target].select(); // Complete Ephemeris view at the current target.
                    if (catalog.state() != comet::Subscriber::State::Ready || services.state() != comet::Observer::State::Ready || catalog.instance() != instances[target] || services.instance() != instances[target] || catalog.size() != records || services.size() != records) {
                        return false;
                    }
                    for (std::size_t source = 0; source < records; ++source) {
                        const auto publication = catalog.find(std::to_string(source)); // Check exact source Keys, not equal counts alone.
                        const auto registration = services.find(identities[source]);   // Check exact UUID and complete Attr and Data.
                        if (!publication || publication->version != versions[source] || *publication->value != values[source] || !registration || *registration->attr != attr || *registration->data != values[source]) {
                            return false;
                        }
                    }
                }
                return true;
            });
        } catch (...) {
            // Retain bounded oracle diagnostics without publishing credentials or application payloads.
            const auto elapsed = [](auto point) { return std::chrono::duration_cast<std::chrono::microseconds>(point.time_since_epoch()).count(); };
            std::cerr << "Mesh timing base=" << base << " round=" << version << " observed_us=" << elapsed(observed) << " failed_us=" << elapsed(std::chrono::steady_clock::now()) << '\n';
            for (std::size_t source = 0; source < records; ++source) {
                std::cerr << "Mesh write source=" << source << " begin_us=" << elapsed(timings[source][0]) << " completed_us=" << elapsed(timings[source][1]) << " ttl_ms=3000 expected=" << versions[source] << '\n';
            }
            for (std::size_t target = 0; target < clients.size(); ++target) {
                std::cerr << "Mesh initial target=" << target << " catalog=" << static_cast<int>(initial[target].state()) << "/" << initial[target].size() << " owner=" << (initial[target].instance() == instances[target]) << '\n';
                for (std::size_t source = 0; source < records; ++source) {
                    const auto publication = initial[target].find(std::to_string(source));
                    if (!publication || publication->version != versions[source] || *publication->value != values[source]) {
                        std::cerr << "Mesh initial source=" << source << " expected=" << versions[source] << " observed=" << (publication ? publication->version : 0) << " value=" << (publication && *publication->value == values[source]) << '\n';
                    }
                }
                const auto catalog = subscribers[target].watch();
                const auto services = observers[target].select();
                std::cerr << "Mesh target=" << target << " base=" << base << " catalog=" << static_cast<int>(catalog.state()) << "/" << catalog.size() << " services=" << static_cast<int>(services.state()) << "/" << services.size() << " catalog_owner=" << (catalog.instance() == instances[target]) << " services_owner=" << (services.instance() == instances[target]) << '\n';
                for (std::size_t source = 0; source < records; ++source) {
                    const auto publication = catalog.find(std::to_string(source));
                    const auto registration = services.find(identities[source]);
                    const bool value = publication && *publication->value == values[source];
                    const bool data = registration && *registration->attr == attr && *registration->data == values[source];
                    if (!publication || publication->version != versions[source] || !value || !data) {
                        std::cerr << "Mesh source=" << source << " expected=" << versions[source] << " observed=" << (publication ? publication->version : 0) << " value=" << value << " registration=" << static_cast<bool>(registration) << " data=" << data << '\n';
                    }
                }
            }
            throw;
        }
        if (version == base + 1) {
            // Catalog has no automatic renewal and expires across three nodes; silent Beacon renewals keep registration alive.
            const auto services = observers[0].select(); // Retain the projection cursor; Renew creates no Data event.
            until([&] { return std::ranges::all_of(subscribers, [](const auto& item) { return item.watch().state() == comet::Subscriber::State::Ready && item.watch().size() == 0; }); });
            if (observers[0].select().version() != services.version() || observers[0].select().size() != records) {
                throw std::runtime_error("Beacon renewal lost or changed its projection");
            }
        }
        if (version % 100 == 0 || version == base + 1) {
            std::cout << "{\"event\":\"mesh_progress\",\"round\":" << version << ",\"workers\":" << 2 * records << "}" << std::endl;
        }
        std::this_thread::sleep_for(100ms);
    } while (continuous || version < base + 2 || std::chrono::steady_clock::now() < deadline);

    if (finish) {
        workload.close();
    }
    std::cout << "{\"event\":\"mesh_replicated\",\"rounds\":" << version - base << ",\"records\":" << records << "}" << std::endl;
}

/// Match the fixture's prescribed authority history, including a present empty value.
bool authority(const comet::Reader& reader, std::uint64_t version, const std::vector<std::uint8_t>& value) {
    const auto view = reader.load(); // One immutable snapshot owns both version and content.
    const auto found = view.find("key");
    return view.state() == comet::Reader::State::Ready && view.version() == version && view.size() == 1 && found && *found == value;
}

/// Check one forced loss with the existing writer and the fixture's exact authority baseline.
void recovery(comet::Client& producer, const std::array<comet::Client*, 3>& peers, std::uint64_t cycle, std::uint64_t version, const std::vector<std::uint8_t>& value) {

    auto& first = *peers[0]; // The failed node; the other two remain available throughout relocation.
    auto& second = *peers[1];
    auto& third = *peers[2];
    const comet::Scope scope{"mesh", "main"};
    auto firstCatalog = first.subscriber(scope), secondCatalog = second.subscriber(scope), thirdCatalog = third.subscriber(scope);
    auto firstServices = first.observer(scope), secondServices = second.observer(scope), thirdServices = third.observer(scope);
    auto firstAlmanac = first.reader({"integration", "main"}), secondAlmanac = second.reader({"integration", "main"});
    auto publisher = producer.publisher(scope);
    auto beacon = producer.beacon(scope, {'a', 't', 't', 'r'}, {'o', 'n', 'e'}, 3000ms, 1000ms);
    if (!firstCatalog || !secondCatalog || !thirdCatalog || !firstServices || !secondServices || !thirdServices || !firstAlmanac || !secondAlmanac || !publisher || !beacon) {
        throw std::runtime_error("Cannot create native mesh objects");
    }
    until([&] { return authority(*firstAlmanac, version, value) && authority(*secondAlmanac, version, value); });
    const std::vector<std::uint8_t> one{'o', 'n', 'e'}, two{'t', 'w', 'o'};
    const auto initial = publisher->update("key", one, 3000ms, 10s); // Admission confirmation version is separate from the business test round number.
    if (!initial) {
        throw std::runtime_error("Initial Catalog update failed");
    }
    until([&] { const auto state = beacon->state(); return state.phase == comet::Beacon::Phase::Ready && state.identity.has_value(); });
    const auto original = *beacon->state().identity;
    until([&] { return visible(*firstCatalog, *firstServices, original.uuid, initial->version, one, one) && visible(*secondCatalog, *secondServices, original.uuid, initial->version, one, one) && visible(*thirdCatalog, *thirdServices, original.uuid, initial->version, one, one); });
    std::cout << "{\"event\":\"mesh_ready\",\"cycle\":" << cycle << ",\"star\":" << cycle % 3 << "}" << std::endl; // Outer harness kills the original authority Star here without removing registration first.

    until([&] { const auto state = beacon->state(); return state.phase == comet::Beacon::Phase::Ready && state.identity && state.identity->instance != original.instance && state.identity->uuid == original.uuid; }, 60s);
    const auto replacement = *beacon->state().identity;
    const auto moved = publisher->update("key", two, 3000ms, 10s); // An explicit call restores the Key after failover, without background replay.
    if (!moved) {
        throw std::runtime_error("Catalog update after relocation failed");
    }
    if (!beacon->update(two, 10s)) {
        throw std::runtime_error("Beacon update was not confirmed");
    }
    until([&] { return visible(*secondCatalog, *secondServices, replacement.uuid, moved->version, two, two) && visible(*thirdCatalog, *thirdServices, replacement.uuid, moved->version, two, two) && secondServices->select().size() == 1 && thirdServices->select().size() == 1; });
    std::cout << "{\"event\":\"mesh_failover\",\"cycle\":" << cycle << ",\"star\":" << cycle % 3 << "}" << std::endl; // Outer harness restarts Star A on its original port; Pulsar issues a newer identity.

    until([&] {
        return firstServices->select().state() == comet::Observer::State::Ready && firstServices->select().find(replacement.uuid).has_value() && firstServices->select().instance() != original.instance && authority(*firstAlmanac, version, value);
    },
          75s);
    if (!authority(*secondAlmanac, version, value)) {
        throw std::runtime_error("Almanac authority baseline was not retained");
    }
    const auto emptied = publisher->update("key", {}, 3000ms, 10s); // Republish an empty value; old TTL may expire normally while awaiting restart.
    if (!emptied) {
        throw std::runtime_error("Empty Catalog update failed");
    }
    until([&] { return visible(*firstCatalog, *firstServices, replacement.uuid, emptied->version, {}, two) && visible(*secondCatalog, *secondServices, replacement.uuid, emptied->version, {}, two) && visible(*thirdCatalog, *thirdServices, replacement.uuid, emptied->version, {}, two); });
    publisher->close();
    beacon->close();
    if (!publisher->wait(5s) || !beacon->wait(5s)) {
        throw std::runtime_error("Native mesh writers did not clean up");
    }
    until([&] { return !firstCatalog->watch().find("key") && !secondCatalog->watch().find("key") && !firstServices->select().find(replacement.uuid) && !secondServices->select().find(replacement.uuid) && !thirdServices->select().find(replacement.uuid) && !thirdCatalog->watch().find("key"); }, 15s);
    if (producer.exceptions() != 0 || first.exceptions() != 0 || second.exceptions() != 0 || third.exceptions() != 0) {
        throw std::runtime_error("Native mesh callback failed");
    }
    std::cout << "{\"event\":\"mesh_recovered\",\"cycle\":" << cycle << ",\"star\":" << cycle % 3 << "}" << std::endl;
}
} // namespace

/// Outer Python harness kills or restarts Star A from phase events; probe uses public Comet APIs without internal replication or management Stubs.
int main(int count, char** arguments) {

    try {
        std::uint64_t version = 4;         // Legacy fixtures prescribe v4 with one present empty value.
        std::vector<std::uint8_t> value{}; // Combined fixtures pass their explicit final write history.
        if (count >= 5 && std::string_view(arguments[count - 4]) == "--authority-version" && std::string_view(arguments[count - 2]) == "--authority-value") {
            const std::string_view input(arguments[count - 3]), data(arguments[count - 1]);
            const auto parsed = std::from_chars(input.data(), input.data() + input.size(), version);
            if (parsed.ec != std::errc{} || parsed.ptr != input.data() + input.size() || version == 0 || data.size() > 4096) {
                throw std::runtime_error("Invalid fixture authority baseline");
            }
            value.assign(data.begin(), data.end());
            count -= 4;
        }
        if (count != 6 && count != 8 && count != 9 && count != 10 && count != 12) {
            throw std::runtime_error("Expected three endpoints, CA and secret file");
        }
        std::uint64_t seconds{}; // Defaults to basic acceptance; long runs may add 0..604800 seconds and failure or steady mode.
        std::size_t copies = 1;  // Ordinary acceptance uses one item per node; long runs may request 1..16 explicitly.
        std::uint64_t base{};    // Long-run rounds use disjoint content-version ranges without adding Scopes to hide resident-memory growth.
        const bool sequence = count == 12 && std::string_view(arguments[7]) == "sequence";
        if (count == 12 && !sequence) {
            throw std::runtime_error("Extended mesh arguments require sequence mode");
        }
        const bool steady = count >= 8 && std::string_view(arguments[7]) == "steady";
        const bool continuous = steady && std::string_view(arguments[6]) == "forever"; // Only explicit steady forever has no overall limit; each RPC and convergence step retains a failure deadline.
        if (count >= 8) {
            const std::string_view input(arguments[6]); // Reject negative durations, trailing garbage, and overflow.
            const auto parsed = std::from_chars(input.data(), input.data() + input.size(), seconds);
            if ((!continuous && (parsed.ec != std::errc{} || parsed.ptr != input.data() + input.size() || seconds > 604800)) || (!steady && !sequence && std::string_view(arguments[7]) != "failure")) {
                throw std::runtime_error("Invalid mesh duration or mode");
            }
        }
        if (count >= 9) {
            const std::string_view input(arguments[8]); // Strict decimal entry count; reject zero or values above SDK budget.
            const auto parsed = std::from_chars(input.data(), input.data() + input.size(), copies);
            if (parsed.ec != std::errc{} || parsed.ptr != input.data() + input.size() || copies < 1 || copies > 16) {
                throw std::runtime_error("Invalid per-Star record count");
            }
        }
        if (count >= 10) {
            const std::string_view input(arguments[9]); // 0..604800 rounds with ten million versions each; 100 ms throttling cannot cross ranges within a week.
            const auto parsed = std::from_chars(input.data(), input.data() + input.size(), base);
            if (parsed.ec != std::errc{} || parsed.ptr != input.data() + input.size() || base > 604800) {
                throw std::runtime_error("Invalid mesh cycle");
            }
            base *= 10000000;
        }
        std::uint64_t residence = 0; // Validate the full sequence budget before opening any network client.
        bool unlimited = false;
        if (sequence) {
            std::uint64_t faults = 0; // Persistent mode always performs exactly one forced loss per Star.
            const std::string_view faultInput(arguments[10]), steadyInput(arguments[11]);
            const auto parsedFaults = std::from_chars(faultInput.data(), faultInput.data() + faultInput.size(), faults);
            const auto parsedSteady = std::from_chars(steadyInput.data(), steadyInput.data() + steadyInput.size(), residence);
            unlimited = steadyInput == "forever";
            if (base != 0 || seconds > 3600 || parsedFaults.ec != std::errc{} || parsedFaults.ptr != faultInput.data() + faultInput.size() || faults != 0 || (!unlimited && (parsedSteady.ec != std::errc{} || parsedSteady.ptr != steadyInput.data() + steadyInput.size() || residence > 604800 || 3 * seconds + residence > 604800))) {
                throw std::runtime_error("Invalid mesh sequence budgets");
            }
        }
        const auto credential = secret(arguments[5]);
        auto producer = open({arguments[1], arguments[2]}, arguments[4], credential);
        const Cleanup producerCleanup{producer};
        auto first = open({arguments[1]}, arguments[4], credential);
        const Cleanup firstCleanup{first};
        auto second = open({arguments[2]}, arguments[4], credential);
        const Cleanup secondCleanup{second};
        auto third = open({arguments[3]}, arguments[4], credential); // Third observer is pinned; it cannot fail over to the writer node and claim replication.
        const Cleanup thirdCleanup{third};
        Workload workload(copies); // Declared after its Clients so every activity closes before its host is drained.
        if (sequence) {
            auto next = open({arguments[2], arguments[3]}, arguments[4], credential);
            const Cleanup nextCleanup{next};
            auto last = open({arguments[3], arguments[1]}, arguments[4], credential);
            const Cleanup lastCleanup{last};
            const std::array<comet::Client*, 3> peers{&first, &second, &third}; // Created once; no Client is reconstructed in the loop or steady phase.
            const std::array<comet::Client*, 3> producers{&producer, &next, &last};
            std::uint64_t cycle = 0; // Each fault rotates to its own original admission endpoint.
            do {
                replication(peers, workload, std::chrono::seconds(seconds), cycle * 10000000, false, false);
                const auto index = cycle % peers.size();
                recovery(*producers[index], {peers[index], peers[(index + 1) % peers.size()], peers[(index + 2) % peers.size()]}, cycle, version, value);
                ++cycle;
            } while (cycle < 3);
            std::cout << "{\"event\":\"mesh_steady\",\"cycles\":" << cycle << "}" << std::endl;
            if (unlimited || residence) {
                replication(peers, workload, std::chrono::seconds(residence), cycle * 10000000, unlimited);
            } else {
                // Zero residence still verifies all original handles after the final Star restart.
                replication(peers, workload, 0s, cycle * 10000000);
            }
            for (const auto* client : {&producer, &next, &last, &first, &second, &third}) {
                if (client->exceptions()) {
                    throw std::runtime_error("Persistent mesh callback failed");
                }
            }
            std::cout << "{\"event\":\"mesh_sequence_completed\",\"cycles\":" << cycle << "}" << std::endl;
            return 0;
        }
        replication({&first, &second, &third}, workload, std::chrono::seconds(seconds), base, continuous);
        if (steady) {
            if (first.exceptions() || second.exceptions() || third.exceptions()) {
                throw std::runtime_error("Steady workload callback failed");
            }
            return 0;
        }
        recovery(producer, {&first, &second, &third}, base / 10000000, version, value);
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
