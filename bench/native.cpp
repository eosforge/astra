// Measure native domain-state operations without starting network services.
#include "catalog_state.hpp"
#include "ephemeris_state.hpp"
#include "measure.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
using namespace std::chrono_literals;

/// Fix business time to isolate expiry; a separate Agenda case measures catch-up, not clock-service performance.
auto reading() {
    return std::optional(astra::Clock::Reading{.time = astra::Clock::Time(1s), .ready = true});
}

/// Measure current production Catalog/Ephemeris implementations rather than the frozen generic Store.
void run(std::size_t count, std::size_t bytes) {

    const astra::Scope scope{"measure", "native"};
    const auto value = std::make_shared<const astra::Catalog::Buffer>(bytes, 42); // Share immutable payloads allocated outside the window.
    const auto other = std::make_shared<const astra::Catalog::Buffer>(bytes, 43); // Alternate payloads to force real Update changes.
    std::vector<std::string> keys(count);                                         // Prepare names outside timing.
    std::vector<std::uint64_t> versions(count, 1);                                // Each key has an independent content version starting at one.
    astra::Catalog::State catalog(reading, astra::Catalog::State::Limits{});
    astra::Ephemeris::State ephemeris(reading, astra::Ephemeris::State::Limits{});
    for (std::size_t index = 0; index < count; ++index) {
        keys[index] = "key-" + std::to_string(index);
        Measure::require(catalog.publish(scope, keys[index], value, 1, 600000).has_value());
    }

    Measure::run("catalog.find", 20000, [&](std::size_t index) { const auto found = catalog.find(scope, keys[index % count]); Measure::require(found && found->record && found->record->value->size() == bytes); });
    Measure::run("catalog.capture", 20000, [&](std::size_t) { const auto view = catalog.capture(scope); Measure::require(view && view->size() == count); });
    Measure::run("catalog.publish", 20000, [&](std::size_t index) { const auto slot = index % count; const auto version = ++versions[slot]; Measure::require(catalog.publish(scope, keys[slot], version % 2 ? value : other, version, 600000).has_value()); });

    // Measure repeated changes with a retained View, then verify the old root remains readable.
    const auto frozen = catalog.capture(scope);
    Measure::require(frozen.has_value());
    Measure::run("catalog.publish_with_view", 20000, [&](std::size_t index) { const auto slot = index % count; const auto version = ++versions[slot]; Measure::require(catalog.publish(scope, keys[slot], version % 2 ? value : other, version, 600000).has_value()); });
    std::size_t visited{};
    frozen->each([&](const auto&, const auto&) { ++visited; });
    Measure::require(visited == count);

    // Time Create separately, including its real random UUID generation; subsequent update/renew reuse the UUID.
    std::vector<std::string> identities(count);
    Measure::run("ephemeris.create", count, [&](std::size_t index) { auto result = ephemeris.create(scope, value, value, 600000); Measure::require(result.has_value()); identities[index] = std::move(result->uuid); });
    Measure::run("ephemeris.update", 20000, [&](std::size_t index) { Measure::require(ephemeris.update(scope, identities[index % count], index / count % 2 ? value : other, index + 1).has_value()); });
    Measure::run("ephemeris.renew", 20000, [&](std::size_t index) { Measure::require(ephemeris.renew(scope, identities[index % count], index + 1).has_value()); });
    Measure::run("ephemeris.find", 20000, [&](std::size_t index) { const auto found = ephemeris.find(scope, identities[index % count]); Measure::require(found && found->record); });

    // Full source recovery includes private Draft construction, atomic installation and receiver destruction, separately from constant-time capture.
    const auto source = catalog.source(); // Freeze a complete source rather than deriving artificial remote facts from a merged projection.
    Measure::run("catalog.recover", 5, [&](std::size_t) {
        astra::Catalog::State receiver(reading, {}); // Use a fresh receiver each time to avoid a same-version shortcut.
        Measure::require(receiver.admit("source").has_value());
        auto draft = receiver.prepare("source", source.position());
        Measure::require(draft.has_value());
        source.each([&](const auto& address, const auto& key, const auto& record) { Measure::require(draft->set(address, key, record).has_value()); });
        Measure::require(receiver.replace("source", std::move(*draft)).has_value());
        const auto view = receiver.capture(scope);
        Measure::require(view && view->size() == count);
    });
}

/// Idle send preparation checks every source TTL; vary the number of live sources to measure scaling.
void sources() {
    for (const auto count : {0, 7, 31}) {
        astra::Catalog::State state(reading, {}); // Use independent source containers and unchanged production replica limits.
        const astra::Scope scope{"measure", "sources"};
        const auto value = std::make_shared<const astra::Catalog::Buffer>(16, 1);
        for (int index = 0; index < count; ++index) {
            const auto id = "source-" + std::to_string(index);
            Measure::require(state.admit(id).has_value());
            Measure::require(state.apply(id, 1, scope, id, {1, value, astra::Clock::Time(600s)}, astra::Catalog::State::Source::Form::Record).has_value());
        }
        Measure::run("catalog.idle_sources_" + std::to_string(count), 20000, [&](std::size_t) { Measure::require(state.deliver(0, 256, 65536).has_value()); });
    }
}

/// Measure long empty-wheel catch-up using the actual implementation rather than an assumed bound.
void advance() {
    for (const auto hours : {1, 24, 168}) {
        astra::Agenda agenda(astra::Clock::Time(1s)); // Start each duration with a fresh wheel.
        Measure::run("agenda.hours_" + std::to_string(hours), 1, [&](std::size_t) { agenda.advance(astra::Clock::Time(1s + std::chrono::hours(hours)), [](auto*, auto) { throw std::runtime_error("Empty agenda fired"); }); });
    }
}
} // namespace

/// Accept bounded production-capacity record/payload sizes; failures return nonzero without fabricated successful output.
int main(int count, char** arguments) {
    try {
        Measure::require(count == 3);
        const auto records = Measure::number(arguments[1], 1, 10000), bytes = Measure::number(arguments[2], 1, 4096);
        run(records, bytes);
        sources();
        advance();
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
