// Provide duplicate-delivery fixtures for SDK stream and projection checks.
#pragma once
#include "check.hpp"
#include "comet.pb.h"
#include <comet/types.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <initializer_list>
#include <string_view>

namespace comet::test {
/// Shared cross-page deduplication boundary: duplicates at capacity are protocol errors, new Keys are capacity errors; neither publishes a partial batch.
/// erase fills the domain's Key and Delete branch; each Policy uses its actual generated messages and installer.
template <class Policy>
void duplicates(auto&& erase, const std::array<std::string_view, 3>& keys = {"key-alpha-0001", "key-alpha-0002", "key-alpha-0003"}) {

    std::array<std::size_t, 2> peaks{}; // Compare preparation charges for the same missing Delete in single-page and cross-page complete batches.
    for (const bool split : {false, true}) {
        std::size_t peak{}; // Records only peaks observed by the shared budget, without reading installer internals.
        Policy projection({"test", "dedup"}, {}, 32768, 1, [&](std::size_t bytes) noexcept { peak = std::max(peak, bytes); return true; });
        projection.begin("star-test");
        typename Policy::Reply initial; // Empty baselines permit idempotent Delete of an unknown Key.
        initial.set_mode(proto::comet::v1::MODE_RESET);
        initial.set_complete(true);
        initial.set_instance("star-test");
        initial.set_version(1);
        CHECK(projection.accept(initial));
        peak = 0;

        typename Policy::Reply page; // With split=true, the first item arrives early and the final page only confirms the complete position.
        page.set_mode(proto::comet::v1::MODE_APPLY);
        if (!split) {
            page.set_complete(true);
            page.set_instance("star-test");
            page.set_version(2);
        }
        erase(*page.add_changes(), keys[0]);
        const auto first = projection.accept(page);
        CHECK(first && static_cast<bool>(*first) == !split);
        if (split) {
            page.clear_changes();
            page.set_complete(true);
            page.set_instance("star-test");
            page.set_version(2);
            const auto completed = projection.accept(page);
            CHECK(completed && *completed);
        }
        peaks[static_cast<std::size_t>(split)] = peak;
        CHECK(projection.view(Policy::API::State::Ready).version() == 2);

        // Completion frees deduplication state; the same Key may appear in the next batch.
        page.clear_changes();
        page.set_version(3);
        erase(*page.add_changes(), keys[0]);
        const auto next = projection.accept(page);
        CHECK(next && *next && (**next).version() == 3);

        // A single-item final page does not make the whole batch unique; reject cross-page duplicates below capacity and retain the old root.
        page.clear_version();
        page.clear_instance();
        page.set_complete(false);
        CHECK(projection.accept(page));
        page.set_complete(true);
        page.set_instance("star-test");
        page.set_version(4);
        const auto repeated = projection.accept(page);
        CHECK(!repeated && repeated.error().code == comet::Error::Code::Protocol);
        CHECK(projection.view(Policy::API::State::Stale).version() == 3);
    }
    CHECK(peaks[0] < peaks[1]); // Single-item batches allocate no deduplication set; cross-page batches still charge owned names and buckets.

    for (const bool repeated : {true, false}) {
        Policy projection({"test", "dedup"}, {}, 32768, 1); // Final capacity is one item; batches may atomically replace two distinct Keys.
        projection.begin("star-test");
        typename Policy::Reply initial; // Install a complete empty version-one baseline before accepting deltas.
        initial.set_mode(proto::comet::v1::MODE_RESET);
        initial.set_complete(true);
        initial.set_instance("star-test");
        initial.set_version(1);
        CHECK(projection.accept(initial));

        typename Policy::Reply head; // Two missing Deletes add no records but fill this batch's deduplication capacity.
        head.set_mode(proto::comet::v1::MODE_APPLY);
        erase(*head.add_changes(), keys[0]);
        erase(*head.add_changes(), keys[1]);
        const auto partial = projection.accept(head);
        CHECK(partial && !*partial);
        typename Policy::Reply tail; // Final page repeats an old Key or submits a third Key, without requiring logical-record overflow first.
        tail.set_mode(proto::comet::v1::MODE_APPLY);
        tail.set_complete(true);
        tail.set_instance("star-test");
        tail.set_version(2);
        erase(*tail.add_changes(), keys[repeated ? 0 : 2]);
        const auto rejected = projection.accept(tail);
        CHECK(!rejected && rejected.error().code == (repeated ? comet::Error::Code::Protocol : comet::Error::Code::Limit));
        CHECK(projection.view(Policy::API::State::Stale).version() == 1 && projection.view(Policy::API::State::Stale).size() == 0);

        // Failure discarded candidate and deduplication state; the next stream may confirm the old complete position with a valid empty batch.
        projection.begin("star-test");
        initial.set_mode(proto::comet::v1::MODE_APPLY);
        CHECK(projection.accept(initial));
    }
}
} // namespace comet::test
