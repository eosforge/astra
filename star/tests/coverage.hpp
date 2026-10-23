// Provide source-coverage fixtures and assertions for replication tests.
#pragma once
#include "check.hpp"
#include <astra/clock.hpp>
#include <astra/scope.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <utility>

namespace {
/// Abandon recovery after two Scopes, then install again without losing earlier coverage; both domains use the same source order.
template <typename Domain>
void coverage(typename Domain::Record old, typename Domain::Record newer, std::array<std::string, 3> keys) {

    using State = typename Domain::State;
    using namespace std::chrono_literals;
    State state([] { return std::optional(astra::Clock::Reading{.time = astra::Clock::Time(1s), .ready = true}); }, {});
    const std::array<astra::Scope, 3> scopes{{{"a", "main"}, {"b", "main"}, {"c", "main"}}}; // Recovery advances Scopes in address order.
    CHECK(state.admit("peer"));
    for (std::size_t index = 0; index < scopes.size(); ++index) {
        CHECK(state.apply("peer", index + 1, scopes[index], keys[index], old, State::Source::Form::Record));
    }
    {
        auto draft = state.prepare("peer", 6);
        CHECK(draft);
        for (std::size_t index = 0; index < scopes.size(); ++index) {
            CHECK(draft->set(scopes[index], keys[index], newer));
        }
        auto task = state.restore("peer", std::move(*draft));
        CHECK(task && task->step() == false && task->step() == false);
        CHECK(state.received("peer") == 3); // Two installed Scopes cannot impersonate full-source confirmation.
    }
    const auto first = state.capture(scopes[0]), second = state.capture(scopes[1]); // Old suffixes must not advance newly published content cursors.
    CHECK(first && second);
    CHECK(state.covered("peer", 4, scopes[0], keys[0]) == true);
    CHECK(state.apply("peer", 5, scopes[1], keys[1], old, State::Source::Form::Record));
    CHECK(state.capture(scopes[0])->version() == first->version() && state.capture(scopes[1])->version() == second->version());
    CHECK(state.apply("peer", 6, scopes[2], keys[2], newer, State::Source::Form::Record));
    CHECK(state.received("peer") == 6 && state.prepare("peer", 6)); // Reclaim coverage when the contiguous prefix catches up.
}

/// The 128-target repair quota spans Scopes. Existing targets update in place; failure cannot advance contiguous source position.
template <typename Domain>
void capacity(typename Domain::Record record) {

    using State = typename Domain::State; // Use real domain committers, not a copied coverage implementation.
    using namespace std::chrono_literals;
    State state([] { return std::optional(astra::Clock::Reading{.time = astra::Clock::Time(1s), .ready = true}); }, {}); // Fixed usable time prevents expiration while filling capacity.
    const std::array<astra::Scope, 2> scopes{{{"a", "main"}, {"b", "main"}}};                                            // Different Scopes of one source share the target quota.
    std::array<std::string, 129> keys;                                                                                   // One extra target tests rejection after filling the budget.
    // Catalog targets are decimal keys; Ephemeris uses valid UUIDs from the real generator.
    for (std::size_t index = 0; index < keys.size(); ++index) {
        if constexpr (requires { Domain::uuid(); }) {
            keys[index] = Domain::uuid();
        } else {
            keys[index] = std::to_string(index);
        }
    }
    CHECK(state.admit("peer"));

    for (std::size_t index = 0; index < 128; ++index) {
        CHECK(state.repair("peer", index + 2, scopes[index % 2], keys[index], record));
    }
    CHECK(state.received("peer") == 0);                                          // Targeted repair cannot skip other targets' history.
    CHECK(state.repair("peer", 200, scopes[0], keys[0], record));                // Updating an existing target consumes no extra slot.
    const auto denied = state.repair("peer", 201, scopes[1], keys[128], record); // Target 129 must fail the source-wide quota.
    CHECK(!denied && denied.error() == State::Error::Capacity);
    CHECK(state.received("peer") == 0 && !state.replica("peer", scopes[1], keys[128])->has_value());
    CHECK(state.apply("peer", 1, scopes[0], keys[0], record, State::Source::Form::Record)); // Covered old events still confirm in contiguous order.
    CHECK(state.received("peer") == 1);
}
} // namespace
