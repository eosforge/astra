// Verify endpoint eligibility, ordering, and selection across connection changes.
#include "check.hpp"
#include "duplicates.hpp"
#include "selection.hpp"

#include <iostream>
#include <stdexcept>
#include <string_view>

namespace {
using comet::Observer;
using comet::detail::Selection;
using Reply = proto::comet::v1::EphemerisWatchReply;
/// Two fixed valid binary UUIDs, independent of random generation.
constexpr std::string_view first("\0\0\0\0\0\0\x40\0\x80\0\0\0\0\0\0\x01", 16);
/// Fixed version and variant bits; remaining bits distinguish identities.
constexpr std::string_view second("\0\0\0\0\0\0\x40\0\x80\0\0\0\0\0\0\x02", 16);
/// Third distinct Key for deduplication-capacity cases.
constexpr std::string_view third("\0\0\0\0\0\0\x40\0\x80\0\0\0\0\0\0\x03", 16);

/// Actual generated messages; noncomplete pages carry no installable position.
Reply page(proto::comet::v1::Mode mode, bool complete = true, std::uint64_t version = 1, std::string instance = "star-a") {
    Reply result;
    result.set_mode(mode);
    result.set_complete(complete);
    if (complete) {
        result.set_version(version);
        result.set_instance(std::move(instance));
    }
    return result;
}

/// Complete records remain present with both fields empty; empty payload is not Delete.
void record(Reply& page, std::string_view uuid, std::string attr = {}, std::string data = {}) {
    auto* change = page.add_changes();
    change->set_uuid(uuid);
    change->mutable_record()->set_attr(std::move(attr));
    change->mutable_record()->set_data(std::move(data));
}

/// Data-only contains no Attr; immutable attributes must come from the existing complete view.
void data(Reply& page, std::string_view uuid, std::string value = {}) {
    auto* change = page.add_changes();
    change->set_uuid(uuid);
    change->set_data(std::move(value));
}

/// Only complete final pages install; frequent Data shares Attr, and old Views outlive Selection.
void lifecycle() {

    Observer::View held;
    CHECK(held.scope().sector.empty() && held.scope().spectrum.empty() && held.target().empty());
    {
        Selection selection({"service", "main"}, {}, 65536, 100);
        selection.begin("star-a");
        auto head = page(proto::comet::v1::MODE_RESET, false);
        record(head, first, std::string(8, static_cast<char>(0xff)), "old");
        auto accepted = selection.accept(head);
        CHECK(accepted && !*accepted && !selection.view(Observer::State::Waiting).version());
        auto tail = page(proto::comet::v1::MODE_RESET);
        record(tail, second);
        accepted = selection.accept(tail);
        CHECK(accepted && *accepted && (**accepted).size() == 2);
        held = **accepted;
        CHECK(held.find(second)->attr->empty() && held.find(second)->data->empty());
        auto update = page(proto::comet::v1::MODE_APPLY, true, 2);
        data(update, first);
        accepted = selection.accept(update);
        CHECK(accepted && *accepted);
        CHECK((**accepted).find(first)->attr == held.find(first)->attr);
        CHECK((**accepted).find(first)->data->empty() && !held.find(first)->data->empty());
        auto complete = page(proto::comet::v1::MODE_APPLY, true, 3);
        record(complete, first, std::string(8, static_cast<char>(0xff)), "new");
        CHECK(selection.accept(complete)); // High-bit Attr bytes compare exactly even with signed char.
        auto erase = page(proto::comet::v1::MODE_APPLY, true, 4);
        erase.add_changes()->set_uuid(first);
        erase.mutable_changes(0)->mutable_erase();
        CHECK(selection.accept(erase));
        CHECK(!selection.view(Observer::State::Ready).find(first));
    }
    CHECK(held.find(first) && held.find(first)->data->size() == 3);
    CHECK(held.scope().sector == "service" && held.scope().spectrum == "main" && held.target().empty());
    std::size_t count{}; // Complete traversal remains possible after network and projection objects disappear.
    held.each([&](std::string_view uuid, const Observer::Record& value) { CHECK(Selection::valid(uuid) && value.attr && value.data); ++count; });
    CHECK(count == 2);

    // Replacing the original View in a callback must preserve current UUID, Attr, Data, and subsequent records.
    count = 0;
    held.each([&](std::string_view uuid, const Observer::Record& value) {
        held = {};
        CHECK((uuid == first && value.data->size() == 3) || (uuid == second && value.data->empty()));
        CHECK(value.attr);
        ++count;
    });
    CHECK(count == 2 && !held.version());
    CHECK(held.scope().sector.empty() && held.scope().spectrum.empty() && held.target().empty());
}

/// Missing Attr publishes no partial record and permits only one versionless snapshot fallback, even after a later successful baseline.
void repair() {

    Selection selection({"service", "main"}, {}, 65536, 100);
    selection.begin("star-a");
    CHECK(selection.accept(page(proto::comet::v1::MODE_RESET)));
    auto missing = page(proto::comet::v1::MODE_APPLY, true, 2);
    data(missing, first, "partial");
    auto result = selection.accept(missing);
    CHECK(!result && result.error().code == comet::Error::Code::History);
    CHECK(selection.view(Observer::State::Stale).version() == 1 && selection.view(Observer::State::Stale).size() == 0);
    CHECK(selection.repair(result.error().code) && !selection.resume());
    selection.begin("star-a");
    CHECK(!selection.accept(page(proto::comet::v1::MODE_APPLY, true, 2))); // Forced snapshots reject apply based on old contents.
    selection.begin("star-a");
    auto reset = page(proto::comet::v1::MODE_RESET, true, 2);
    record(reset, first);
    CHECK(selection.accept(reset) && selection.resume());
    auto repeated = page(proto::comet::v1::MODE_APPLY, true, 3);
    data(repeated, second);
    result = selection.accept(repeated);
    CHECK(!result && !selection.repair(result.error().code));
    CHECK(selection.view(Observer::State::Stale).version() == 2);
}

/// Cursors belong to actual Stars; a new Star may replace at a lower local cursor, while the same Star cannot regress.
void identity() {

    Selection selection({"service", "main"}, {}, 65536, 100);
    selection.begin("star-a");
    auto old = page(proto::comet::v1::MODE_RESET, true, 100);
    record(old, first);
    CHECK(selection.accept(old));
    selection.begin("star-a");
    CHECK(!selection.accept(page(proto::comet::v1::MODE_RESET, true, 99)));
    selection.begin("star-b");
    auto reset = page(proto::comet::v1::MODE_RESET, true, 1, "star-b");
    record(reset, second);
    CHECK(selection.accept(reset));
    auto view = selection.view(Observer::State::Ready);
    CHECK(view.instance() == "star-b" && view.version() == 1 && !view.find(first) && view.find(second));
    selection.begin("star-c");
    CHECK(!selection.accept(page(proto::comet::v1::MODE_APPLY, true, 2, "star-c")));
}

/// Malformed batches and visible-budget failures cannot publish earlier prepared valid records.
void malformed() {

    for (unsigned scenario = 0; scenario < 8; ++scenario) {
        Selection selection({"service", "main"}, {}, 65536, 100);
        selection.begin("star-a");
        auto base = page(proto::comet::v1::MODE_RESET);
        record(base, first, "fixed");
        CHECK(selection.accept(base));
        auto bad = page(proto::comet::v1::MODE_APPLY, true, 2);
        switch (scenario) {
        case 0:
            record(bad, first, "changed");
            break;
        case 1:
            data(bad, "invalid");
            break;
        case 2:
            data(bad, first);
            data(bad, first);
            break;
        case 3:
            bad.add_changes()->set_uuid(first);
            break;
        case 4:
            data(bad, first);
            bad.set_version(0);
            break;
        case 5:
            data(bad, first);
            bad.clear_instance();
            break;
        case 6:
            data(bad, first, std::string(65536, 'x'));
            break;
        case 7:
            data(bad, first);
            bad.set_mode(proto::comet::v1::MODE_RESET);
            break;
        }
        CHECK(!selection.accept(bad));
        CHECK(selection.view(Observer::State::Ready).version() == 1 && selection.view(Observer::State::Ready).find(first)->data->empty());
    }
    Selection exact({"service", "main"}, std::string(first), 65536, 100);
    CHECK(exact.view(Observer::State::Waiting).target() == first);
    exact.begin("star-a");
    auto wrong = page(proto::comet::v1::MODE_RESET);
    record(wrong, second);
    CHECK(!exact.accept(wrong));
    for (auto mode : {proto::comet::v1::MODE_RESET, proto::comet::v1::MODE_APPLY}) {
        Selection empty({"service", "main"}, {}, 65536, 100);
        empty.begin("star-a");
        auto missing = page(mode);
        data(missing, first);
        CHECK(!empty.accept(missing)); // reset forbids data; initial apply lacks a complete baseline.
    }
}

/// Incomplete network batches preserve other Keys' new estimates; late writes using old authority or estimate generations fail.
void estimates() {

    std::size_t charged{}; // Checks rollback and destructor release; successful reservation is not successful publication.
    Observer::Pool held;   // Only this pool retains the roots after the installer leaves its scope.
    {
        Selection selection({"service", "main"}, {}, 65536, 10, [&](std::size_t bytes) noexcept { charged = bytes; return true; });
        selection.begin("star-a");
        auto initial = page(proto::comet::v1::MODE_RESET);
        record(initial, first, "attr", "one");
        record(initial, second, "attr", "two");
        CHECK(selection.accept(initial));
        const auto pool = selection.pool({});
        const auto one = pool.find(first)->record().data;
        const auto two = pool.find(second)->record().data;
        const auto local = std::make_shared<const std::vector<std::uint8_t>>(3, 7);
        CHECK(selection.estimate(first, one, one, local));
        CHECK(selection.estimate(first, one, one, local).error().code == comet::Error::Code::Conflict);
        auto head = page(proto::comet::v1::MODE_APPLY, false);
        data(head, first, "new");
        CHECK(selection.accept(head));
        CHECK(selection.estimate(second, two, two, local)); // Independent local update to another Key during the in-flight batch.
        CHECK(selection.accept(page(proto::comet::v1::MODE_APPLY, true, 2)));
        CHECK(selection.pool({}).find(second)->record().data == local);
        CHECK(selection.pool({}).find(first)->record().data != local);
        CHECK(selection.estimate(first, one, local, local).error().code == comet::Error::Code::Obsolete);
        auto same = page(proto::comet::v1::MODE_APPLY, true, 3);
        data(same, second, "two"); // A new authority write ends the old estimate generation even with identical bytes.
        CHECK(selection.accept(same));
        CHECK(selection.estimate(second, two, local, local).error().code == comet::Error::Code::Obsolete);
        CHECK(*selection.pool({}).find(second)->record().data == *two);
        CHECK(pool.find(first)->record().data == one && charged > 0); // Background changes preserve old pool ownership and contents.
        held = pool;
    }
    CHECK(charged == 0);

    // User exceptions propagate once and cannot alter the detached pool or either record.
    CHECK(held.size() == 2);
    const auto left = held.find(first)->record().data; // Payload owners do not retain the table roots.
    const auto right = held.find(second)->record().data;
    unsigned calls{};
    bool rejected{};
    try {
        held.each([&calls](Observer::Item) {
            ++calls;
            throw std::runtime_error("pool callback");
        });
    } catch (const std::runtime_error& error) {
        CHECK(std::string_view(error.what()) == "pool callback");
        rejected = true;
    }
    CHECK(rejected && calls == 1 && held.size() == 2);
    CHECK(held.find(first)->record().data == left && held.find(second)->record().data == right);

    // Iteration must pin both roots when its callback drops their last external pool owner.
    unsigned seen{}; // A bit per literal fixture identity also rejects duplicate visits.
    held.each([&held, &seen, &left, &right](Observer::Item item) {
        held = {};
        CHECK(item.id() == first || item.id() == second);
        const unsigned bit = item.id() == first ? 1 : 2;
        CHECK((seen & bit) == 0 && item.record().data == (bit == 1 ? left : right));
        CHECK(item.record().attr);
        seen |= bit;
    });
    CHECK(seen == 3 && held.size() == 0 && !held.find(first));
    held.each([](Observer::Item) { CHECK(false); }); // An empty pool must invoke no callback.
}

/// Shared-budget rejection for a local candidate preserves the previous estimate, authority data, and charges.
void capacity() {

    bool reject{}; // Reject growth only; all returns remain allowed.
    std::size_t charged{};
    {
        Selection selection({"service", "main"}, {}, 65536, 10, [&](std::size_t bytes) noexcept {
            if (reject && bytes > charged) {
                return false;
            }
            charged = bytes;
            return true;
        });
        selection.begin("star-a");
        auto initial = page(proto::comet::v1::MODE_RESET);
        record(initial, first, "attr", "one");
        CHECK(selection.accept(initial));
        const auto authority = selection.pool({}).find(first)->record().data;
        const auto before = charged;
        const auto local = std::make_shared<const std::vector<std::uint8_t>>(32, 7);
        reject = true;
        const auto result = selection.estimate(first, authority, authority, local);
        CHECK(!result && result.error().code == comet::Error::Code::Limit && charged == before);
        CHECK(selection.pool({}).find(first)->record().data == authority);
        reject = false;
        CHECK(selection.estimate(first, authority, authority, local));
        CHECK(selection.pool({}).find(first)->record().data == local);
    }
    CHECK(charged == 0);
}

} // namespace

int main() {
    try {
        capacity();
        estimates();
        lifecycle();
        repair();
        identity();
        malformed();
        comet::test::duplicates<Selection>([](auto& change, std::string_view key) { change.set_uuid(key); change.mutable_erase(); }, {first, second, third}); // Ephemeris uses binary UUIDs; ordinary-Key coverage alone is insufficient.
        std::cout << "Ephemeris selection cases passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
