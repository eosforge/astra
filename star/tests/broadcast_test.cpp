// Verify shared watch-page delivery and retained-resource accounting.
#include "broadcast.hpp"
#include "catalog_edition.hpp"
#include "check.hpp"
#include "ephemeris_edition.hpp"
#include "progress.hpp"
#include "watch_kernel.hpp"

#include <algorithm>
#include <iostream>
#include <limits>
#include <map>
#include <stdexcept>
#include <unordered_set>

namespace {
using namespace std::chrono_literals;
using astra::Catalog;
using astra::Clock;
using astra::Ephemeris;
using astra::Scope;

/// gRPC-independent scheduling fields. Release ownership only after both intrusive indices detach.
struct Pending : std::enable_shared_from_this<Pending> {
    /// Ready membership, initially false.
    bool queued{};
    /// Ready successor, independent of in-flight links.
    Pending* next{};
    /// Simulated pending network write; false prevents timeout reawakening.
    std::atomic_bool busy{true};
    /// Write deadline; zero is already due. Single-thread fixture models publication under both locks.
    std::chrono::steady_clock::time_point deadline{};
    /// Initially empty in-flight links.
    astra::Watch<Pending>::Link flight;
};

/// Repeated enqueue, arbitrary unlink, timeout, and residual ready notification after cancellation preserve lifetime.
void scheduling() {

    astra::Watch<Pending> queue;
    auto first = std::make_shared<Pending>();
    auto middle = std::make_shared<Pending>();
    auto last = std::make_shared<Pending>();
    const auto now = std::chrono::steady_clock::now(); // Fixed monotonic baseline without actual sleep.
    auto deadline = now;
    unsigned wakes{};
    auto wake = [&] { ++wakes; }; // Wake records notification without reentering queue.
    static_assert(noexcept(queue.write(*first)) && noexcept(queue.settle(*first)));
    CHECK(queue.idle() && !queue.pop());

    for (const auto& stream : {first, middle, last}) {
        CHECK(queue.enqueue(*stream));
        CHECK(!queue.enqueue(*stream));
        queue.write(*stream);
        queue.write(*stream);
    }
    CHECK(queue.pop() == first && queue.pop() == middle && queue.pop() == last && queue.idle());
    CHECK(queue.enqueue(*first)); // A new callback after pop must requeue despite earlier notifications.
    CHECK(!queue.enqueue(*first) && queue.pop() == first && queue.idle());
    queue.settle(*middle);
    queue.settle(*middle); // Repeated cleanup cannot unlink a neighbor.
    queue.sweep(now, deadline, wake);
    CHECK(wakes == 1 && queue.pop() == last && queue.pop() == first && queue.idle());
    queue.sweep(now, deadline, wake);
    CHECK(wakes == 1 && queue.idle());

    queue.settle(*last);
    queue.settle(*first);
    queue.sweep(now + 1s, deadline, wake);
    CHECK(wakes == 1 && queue.idle());
    queue.write(*middle);
    middle->busy.store(false);
    queue.sweep(now + 2s, deadline, wake);
    CHECK(wakes == 1 && queue.idle());
    middle->busy.store(true);
    queue.sweep(now + 3s, deadline, wake);
    queue.settle(*middle);   // OnDone detaches in-flight state but preserves ready work for owner cleanup.
    auto held = queue.pop(); // Pop retains strong ownership independently of later owner-index deletion.
    middle.reset();
    CHECK(held && !held->queued && !held->next && !held->flight.previous && !held->flight.next);
    CHECK(queue.idle());
    CHECK(!astra::Watch<Pending>::exceeds(3, 4, 7));
    CHECK(astra::Watch<Pending>::exceeds(8, 0, 7));
    CHECK(astra::Watch<Pending>::exceeds(1, std::numeric_limits<std::size_t>::max(), 7));
}

/// Timeout scans wake only due in-flight writes; ordinary callbacks enqueue before deadlines without waiting for fallback.
void deadlines() {

    astra::Watch<Pending> queue;
    auto first = std::make_shared<Pending>(), second = std::make_shared<Pending>();
    const auto now = std::chrono::steady_clock::now();
    auto scan = now;  // Scan eligibility time is independent of individual stream deadlines.
    unsigned wakes{}; // Counts scan wakeups only, not simulated network callbacks.
    auto wake = [&] { ++wakes; };
    first->deadline = now + 2s;
    second->deadline = now + 4s;
    queue.write(*first);
    queue.write(*second);

    queue.sweep(now, scan, wake);
    queue.sweep(now + 1s, scan, wake);
    CHECK(wakes == 0 && queue.idle());
    CHECK(queue.enqueue(*second) && queue.pop() == second);
    queue.sweep(now + 2s, scan, wake);
    CHECK(wakes == 1 && queue.pop() == first && queue.idle());
    queue.settle(*first);

    second->busy.store(false); // Published WriteDone still linked in flight must not schedule again.
    queue.sweep(now + 4s, scan, wake);
    CHECK(wakes == 1 && queue.idle());
    queue.settle(*second);
    second->deadline = now + 8s; // The next write on a reused node adopts a fresh deadline.
    second->busy.store(true);
    queue.write(*second);
    queue.sweep(now + 5s, scan, wake);
    CHECK(wakes == 1 && queue.idle());
    queue.sweep(now + 8s, scan, wake);
    CHECK(wakes == 2 && queue.pop() == second && queue.idle());
    queue.settle(*second);
}

/// Bounded combined Scope/ready scheduling: empty queue, duplicate notifications, FIFO, fairness, and cancellation lifetime.
void dispatch() {

    astra::Watch<Pending> queue;
    astra::Progress<Pending> progress;
    astra::Progress<Pending>::Group one, two;
    auto first = std::make_shared<Pending>();
    auto second = std::make_shared<Pending>();
    one.streams.emplace(first.get(), first);
    two.streams.emplace(second.get(), second);
    static_assert(noexcept(queue.pop(progress)));
    CHECK(!queue.pop(progress));

    // Progress alone returns a stream in the current scheduling call, not the next pump.
    progress.publish(one, 1, false);
    CHECK(queue.idle() && progress.pending());
    CHECK(queue.pop(progress) == first);
    CHECK(queue.idle() && !progress.pending());

    // Body/progress for the same ready stream coalesce without a duplicate later notification.
    queue.enqueue(*first);
    progress.publish(one, 2, false);
    CHECK(queue.pop(progress) == first);
    CHECK(!queue.pop(progress) && !first->queued);

    // Other ready streams keep FIFO priority; one progress item cannot jump to queue head.
    queue.enqueue(*second);
    progress.publish(one, 3, false);
    CHECK(queue.pop(progress) == second);
    CHECK(first->queued && !progress.pending());
    CHECK(queue.pop(progress) == first && queue.idle());

    // One allowance advances one Scope; new commits queue behind other pending Scopes.
    progress.publish(one, 4, false);
    progress.publish(two, 1, false);
    CHECK(queue.pop(progress) == first && progress.pending());
    progress.publish(one, 5, false);
    CHECK(queue.pop(progress) == second && progress.pending());
    CHECK(queue.pop(progress) == first && !progress.pending());

    // Unscheduled cancelled streams detach directly; popped streams retain strong ownership through later index deletion.
    progress.publish(two, 2, false);
    progress.erase(two, second.get());
    CHECK(!queue.pop(progress));
    progress.publish(one, 6, true);
    auto held = queue.pop(progress);
    std::weak_ptr<Pending> lifetime = first;
    progress.erase(one, first.get());
    first.reset();
    CHECK(held && !lifetime.expired() && queue.idle() && !progress.pending());
    CHECK(!held->queued && !held->next);
    held.reset();
    CHECK(lifetime.expired());
}

/// Scope rotation depends only on ownership indices, covering fairness, cancellation, and commits arriving mid-pass.
void progress() {

    using Queue = astra::Progress<unsigned>; // Fixture payload has no writing/done fields, preventing I/O-state coupling.
    Queue queue;
    Queue::Group zero; // Complete empty-Scope version zero still counts as an observed notification.
    queue.publish(zero, 0, true);
    CHECK(zero.covers(0) && !queue.pending());
    queue.publish(zero, 1, false);
    CHECK(zero.covers(0) && !queue.pending());

    Queue::Group large, small;
    for (unsigned index = 0; index < 3; ++index) {
        auto stream = std::make_shared<unsigned>(index);
        large.streams.emplace(stream.get(), stream);
    }
    auto solitary = std::make_shared<unsigned>(9); // Small Scopes cannot be starved by a larger Scope's remaining consumers.
    small.streams.emplace(solitary.get(), solitary);
    queue.publish(large, 10, false);
    queue.publish(small, 40, false);
    CHECK(!large.covers(8) && large.covers(9) && small.covers(39));
    auto* first = queue.take(); // Pointer order affects only within-Scope scheduling; assertions do not depend on allocator addresses.
    CHECK(first && large.streams.contains(first));
    CHECK(queue.take() == solitary.get());

    queue.publish(large, 11, false); // An already scheduled consumer still receives newer commits arriving during the pass.
    std::map<unsigned*, unsigned> observed;
    for (unsigned remaining = 8; queue.pending(); --remaining) {
        CHECK(remaining != 0); // Queue drains without a subsequent application write.
        auto* stream = queue.take();
        CHECK(stream && large.streams.contains(stream));
        ++observed[stream];
    }
    CHECK(observed.size() == 3 && observed[first] == 1 && queue.take() == nullptr);
    CHECK(large.covers(10));

    queue.publish(large, 12, false);
    queue.publish(small, 41, false);
    queue.erase(large, large.streams.begin()->first); // Removing the next scan target must advance safely.
    queue.erase(small, solitary.get());               // Deleting the final tail stream permits immediate Scope destruction.
    while (!large.streams.empty()) {
        queue.erase(large, large.streams.begin()->first);
    }
    CHECK(!queue.pending() && queue.take() == nullptr);

    queue.publish(small, 43, false); // Missing version 42 is a gap even for filtered targets.
    CHECK(!small.covers(41) && small.covers(43));
    queue.publish(small, 44, true); // Only a baseline after the replacement boundary permits apply.
    CHECK(!small.covers(43) && small.covers(44));
    queue.publish(small, UINT64_MAX, true);
    CHECK(small.covers(UINT64_MAX) && !small.covers(UINT64_MAX - 1));
    CHECK(!queue.pending()); // Empty Scopes update progress scalars without entering notification queues.
}

/// Immutable application bytes; empty payloads are valid records.
Catalog::Value bytes(std::string_view value) {
    return std::make_shared<const Catalog::Buffer>(value.begin(), value.end());
}

/// Real domain paging across multiple pages/readers, independent positions, and page reclamation; identical bodies do not imply shared network completion.
template <typename Domain>
void pages(auto&& write) {

    using Edition = typename Domain::Edition;
    using Batch = astra::Broadcast<Edition>;
    typename Domain::State state([] { return std::optional(Clock::Reading{.time = Clock::Time(1s), .ready = true}); }, {});
    const Scope scope{"shared", "main"}; // 600 rows force three pages with overlapping slow/fast reader use.
    for (unsigned index = 0; index < 600; ++index) {
        CHECK(write(state, scope, index));
    }
    auto view = state.capture(scope);
    CHECK(view && view->size() == 600);
    Batch batch(Edition(std::move(*view)), std::nullopt, "");
    CHECK(batch.matches(std::nullopt, 600, "") && !batch.matches(0, 600, "") && !batch.matches(std::nullopt, 599, "") && !batch.matches(std::nullopt, 600, "other"));
    auto rejected = batch.begin(); // First preparation failure leaves an empty weak slot; later success is not reconstruction after release.
    bool invalid{};
    try {
        static_cast<void>(batch.next(rejected, 0, ""));
    } catch (const std::invalid_argument&) {
        invalid = true;
    }
    CHECK(invalid && !rejected.complete() && batch.misses() == 0 && batch.rebuilds() == 0);

    auto first = batch.begin(), second = batch.begin(), slow = batch.begin();
    auto one = batch.next(first, 0, "star");
    auto same = batch.next(second, 0, "star");
    CHECK(one == same && one->message.changes_size() == 256 && !first.complete() && !second.complete());
    CHECK(one->bytes == one->message.ByteSizeLong());
    auto middle = batch.next(first, 1, "star");
    CHECK(middle->message.changes_size() == 256 && !first.complete());
    auto end = batch.next(first, 2, "star");
    CHECK(first.complete() && !second.complete() && end->message.complete() && end->message.changes_size() == 88);
    auto lagged = batch.next(slow, 0, "star"); // Later page slots cannot replace a still-used first page.
    CHECK(lagged == one);
    CHECK(batch.next(second, 1, "star") == middle && !second.complete());
    auto secondEnd = batch.next(second, 2, "star");
    CHECK(second.complete() && secondEnd == end);
    CHECK(batch.misses() == 3 && batch.rebuilds() == 0); // First construction/interleaved cache hits do not count as reconstruction.
    const auto encoded = end->message.SerializeAsString();
    std::weak_ptr<const typename Batch::Page> released = secondEnd;
    secondEnd.reset();
    end.reset();
    CHECK(released.expired()); // Weak caching does not retain complete pages after final consumer release.
    CHECK(batch.next(slow, 1, "star") == middle);
    auto rebuilt = batch.next(slow, 2, "star"); // A surviving slot with released body reconstructs from this reader's own position.
    CHECK(rebuilt->message.SerializeAsString() == encoded && slow.complete());
    auto retry = batch.begin(); // Sending completion preserves the fixed starting point for later baseline readers.
    auto replay = batch.next(retry, 0, "star");
    CHECK(replay == one && !retry.complete());
    CHECK(batch.misses() == 4 && batch.hits() == 6 && batch.rebuilds() == 1); // Three initial pages plus one reconstruction; six other accesses are weak-cache hits.

    released = rebuilt;
    rebuilt.reset();
    CHECK(released.expired());
    CHECK(batch.next(retry, 1, "star") == middle);
    const auto repeated = batch.next(retry, 2, "star");
    CHECK(repeated->message.SerializeAsString() == encoded && retry.complete());
    CHECK(batch.misses() == 5 && batch.hits() == 7 && batch.rebuilds() == 2);
}

/// Binary 2 KiB bodies exercise byte-budget paging; cache hits preserve NULs, every item, and correct page content.
void payload() {

    using Edition = Catalog::Edition;
    Catalog::State state([] { return std::optional(Clock::Reading{.time = Clock::Time(1s), .ready = true}); }, {});
    const Scope scope{"payload", "main"}; // 384 rows exceed the byte target before the 256-row limit.
    std::string value(2048, '\0');
    for (std::size_t index = 0; index < value.size(); ++index) {
        value[index] = static_cast<char>(index % 256);
    }
    const auto content = bytes(value);
    for (unsigned index = 0; index < 384; ++index) {
        CHECK(state.publish(scope, std::to_string(index), content, 1, 1000));
    }
    auto captured = state.capture(scope);
    CHECK(captured && captured->size() == 384);
    astra::Broadcast<Edition> batch(Edition(std::move(*captured)), std::nullopt, "");
    auto first = batch.begin(), second = batch.begin(); // Streams independently adopt complete positions; one return cannot imply another stream's network completion.
    std::unordered_set<std::string> seen;               // Check each key exactly once, not only message counts.
    std::size_t offset{};
    while (!first.complete()) {
        const auto page = batch.next(first, offset, "star");
        CHECK(page == batch.next(second, offset++, "star"));
        CHECK(page->bytes <= 256 * 1024 && page->message.changes_size() > 0);
        for (const auto& change : page->message.changes()) {
            CHECK(change.has_value() && change.value() == value && change.version() == 1 && seen.insert(change.key()).second);
        }
    }
    CHECK(offset >= 4 && seen.size() == 384 && second.complete());
}

/// Both real policies cover empty targets, copied positions, oversized soft-target rows, hard-budget rejection, and invalid batches.
template <typename Domain>
void boundaries(std::string key, auto&& content) {

    using Edition = typename Domain::Edition;
    using Projection = typename Domain::State::Projection;
    Edition missing(key, typename Projection::Point{.name = {}, .record = {}, .version = 7});
    const auto empty = missing.next("star"); // Exact missing targets still retain the captured complete cursor.
    CHECK(empty.complete() && empty.version() == 7 && empty.changes().empty());

    Edition zero(key, typename Projection::Point{.name = {}, .record = content(bytes("")), .version = 7});
    auto copy = zero; // Shared source with independently copied cursor; failure preserves original position.
    bool invalid{};
    try {
        static_cast<void>(zero.next(""));
    } catch (const std::invalid_argument&) {
        invalid = true;
    }
    CHECK(invalid && !zero.complete());
    const auto present = zero.next("star");
    CHECK(present.complete() && present.changes_size() == 1 && !copy.complete());
    CHECK(present.SerializeAsString() == copy.next("star").SerializeAsString());

    Edition large(key, typename Projection::Point{.name = {}, .record = content(bytes(std::string(1024 * 1024, 'x'))), .version = 8});
    const auto page = large.next("star"); // A valid single row above the soft target must progress as one page.
    CHECK(page.complete() && page.changes_size() == 1 && page.ByteSizeLong() > 256 * 1024 && page.ByteSizeLong() < 8 * 1024 * 1024);
    Edition oversized(key, typename Projection::Point{.name = {}, .record = content(bytes(std::string(9 * 1024 * 1024, 'x'))), .version = 9});
    bool exceeded{}; // Even with an intentionally broken upper payload limit, the hard page budget rejects without completing the cursor.
    try {
        static_cast<void>(oversized.next("star"));
    } catch (const std::length_error&) {
        exceeded = true;
    }
    CHECK(exceeded && !oversized.complete() && oversized.version() == 9);

    bool rejected{}; // Validate whole batches before exact filtering so malformed unnamed events cannot disappear.
    try {
        Edition damaged(1, std::vector<typename Projection::Event>(1), key);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    CHECK(rejected);
}

/// Shared compaction must preserve Ephemeris Attr baselines rather than applying Catalog's last-value rule.
void collapse() {

    const Scope scope{"collapse", "main"};
    Catalog::State catalog([] { return std::optional(Clock::Reading{.time = Clock::Time(1s), .ready = true}); }, {});
    CHECK(catalog.publish(scope, "key", bytes("old"), 10, 1000));
    CHECK(catalog.publish(scope, "other", bytes("separate"), 3, 1000));
    CHECK(catalog.publish(scope, "key", bytes("new"), 20, 1000));
    auto changes = catalog.changes(scope, 0); // Deliberately reversed input is ordered by key/cursor before compaction.
    CHECK(changes && changes->size() == 3);
    std::ranges::reverse(*changes);
    Catalog::Edition exact(3, *changes, "key"), unrelated(3, *changes, "missing");
    const auto value = exact.next("star");
    CHECK(value.complete() && value.version() == 3 && value.changes_size() == 1);
    CHECK(value.changes(0).key() == "key" && value.changes(0).version() == 20 && value.changes(0).value() == "new");
    const auto empty = unrelated.next("star");
    CHECK(empty.complete() && empty.version() == 3 && empty.changes().empty());

    Catalog::Edition combined(3, *changes); // Interleaved keys still retain every final value after sorting and same-key compaction.
    const auto ordered = combined.next("star");
    CHECK(ordered.complete() && ordered.version() == 3 && ordered.changes_size() == 2);
    CHECK(ordered.changes(0).key() == "key" && ordered.changes(0).value() == "new" && ordered.changes(0).version() == 20);
    CHECK(ordered.changes(1).key() == "other" && ordered.changes(1).value() == "separate" && ordered.changes(1).version() == 3);

    Ephemeris::State ephemeris([] { return std::optional(Clock::Reading{.time = Clock::Time(1s), .ready = true}); }, {});
    const auto record = ephemeris.create(scope, bytes("fixed"), bytes("old"), 1000);
    CHECK(record && ephemeris.update(scope, record->uuid, bytes("new"), 1));
    auto events = ephemeris.changes(scope, 0);
    CHECK(events && events->size() == 2);
    std::ranges::reverse(*events);
    Ephemeris::Edition full(2, std::move(*events)); // Create followed by Data still emits complete Attr/Data.
    CHECK(ephemeris.remove(scope, record->uuid));   // Later deletion cannot mutate already frozen content.
    const auto captured = full.next("star");
    CHECK(captured.changes_size() == 1 && captured.changes(0).has_record());
    CHECK(captured.changes(0).record().attr() == "fixed" && captured.changes(0).record().data() == "new");
    events = ephemeris.changes(scope, 0);
    CHECK(events && events->size() == 3);
    Ephemeris::Edition removed(3, std::move(*events));
    const auto erased = removed.next("star");
    CHECK(erased.complete() && erased.version() == 3 && erased.changes_size() == 1 && erased.changes(0).has_erase());
}

/// Same UUID/end version can require different actions for different cursor intervals; never reuse data-only solely by end version.
void delta() {

    Ephemeris::State state([] { return std::optional(Clock::Reading{.time = Clock::Time(1s), .ready = true}); }, {});
    const Scope scope{"delta", "main"};
    const auto record = state.create(scope, bytes("fixed"), bytes("old"), 1000);
    CHECK(record && state.update(scope, record->uuid, bytes("new"), 1));
    auto all = state.changes(scope, 0), changes = state.changes(scope, 1);
    CHECK(all && changes);
    astra::Broadcast<Ephemeris::Edition> baseline(Ephemeris::Edition(2, std::move(*all)), 0, "");
    astra::Broadcast<Ephemeris::Edition> update(Ephemeris::Edition(2, std::move(*changes)), 1, "");
    CHECK(!baseline.matches(1, 2, "") && update.matches(1, 2, ""));
    CHECK(update.prefix(1, 3, "") && !update.prefix(0, 3, "") && !update.prefix(2, 3, "") && !update.prefix(1, 1, "") && !update.prefix(1, 3, record->uuid));
    auto first = baseline.begin(), second = update.begin(), other = update.begin();
    const auto full = baseline.next(first, 0, "star");
    const auto data = update.next(second, 0, "star");
    CHECK(full->message.changes(0).has_record() && data->message.changes(0).has_data());
    CHECK(data == update.next(other, 0, "star"));

    // Repeated consumption after completion must fail even on cache hits.
    bool rejected{};
    try {
        static_cast<void>(update.next(second, 1, "star"));
    } catch (const std::logic_error&) {
        rejected = true;
    }
    CHECK(rejected);
}

/// Unknown exact target gets its own valid empty reset cache, separate from whole Scope and other targets.
void empty() {

    using Edition = Catalog::Edition;
    astra::Broadcast<Edition> batch(Edition("missing", {}), std::nullopt, "missing");
    auto first = batch.begin(), second = batch.begin();
    bool rejected{}; // Noncontiguous page numbers cannot cause sparse cache growth or consume the valid first page on failure.
    try {
        static_cast<void>(batch.next(first, std::numeric_limits<std::size_t>::max(), "star"));
    } catch (const std::logic_error&) {
        rejected = true;
    }
    CHECK(rejected && !first.complete());
    const auto page = batch.next(first, 0, "star");
    CHECK(page->message.complete() && page->message.changes_size() == 0 && first.complete());
    CHECK(batch.next(second, 0, "star") == page && second.complete());
    CHECK(!batch.matches(std::nullopt, 0, "") && !batch.matches(std::nullopt, 0, "another"));
}
} // namespace

/// Component-only scheduling/paging; RPC cases cover real cancellation, slow consumers, and in-flight pages.
int main() {

    try {
        pages<Catalog>([](auto& state, const Scope& scope, unsigned index) { return state.publish(scope, std::to_string(index), bytes("value"), 1, 1000); });
        pages<Ephemeris>([](auto& state, const Scope& scope, unsigned) { return state.create(scope, bytes("attr"), bytes("data"), 1000); });
        scheduling();
        deadlines();
        dispatch();
        progress();
        payload();
        boundaries<Catalog>("key", [](Catalog::Value value) { return Catalog::State::Content{1, std::move(value)}; });
        boundaries<Ephemeris>(std::string("\x00\x11\x22\x33\x44\x55\x46\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff", 16), [](Ephemeris::Value value) { return Ephemeris::State::Content{bytes("fixed"), std::move(value)}; });
        collapse();
        delta();
        empty();
        std::cout << "Shared publication: ok\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
