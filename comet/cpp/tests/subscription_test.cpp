// Verify streaming SDK subscription recovery and visible-state consistency.
#include "check.hpp"
#include "duplicates.hpp"
#include "subscription.hpp"

#include <iostream>

namespace {
using comet::Subscriber;
using comet::detail::Subscription;
using Reply = proto::comet::v1::CatalogWatchReply;

/// Actual generated messages deliberately use different business versions and local view cursors.
Reply page(proto::comet::v1::Mode mode, std::uint64_t cursor, std::string instance = "star-a") {
    Reply result;
    result.set_mode(mode);
    result.set_complete(true);
    result.set_version(cursor);
    result.set_instance(std::move(instance));
    return result;
}

/// Zero-byte value is an explicit present action, distinct from deletion.
void value(Reply& page, std::string key, std::uint64_t version, std::string text) {
    auto* item = page.add_changes();
    item->set_key(std::move(key));
    item->set_version(version);
    item->set_value(std::move(text));
}

/// A new Star may replace the complete view with lower cursor and content versions; old views remain complete without per-Key mixing.
void lifecycle() {

    Subscriber::View held;
    CHECK(held.scope().sector.empty() && held.scope().spectrum.empty());
    {
        Subscription subscription({"dynamic", "main"}, {}, 65536, 10);
        subscription.begin("star-a");
        auto initial = page(proto::comet::v1::MODE_RESET, 20);
        value(initial, "left", 100, "one");
        value(initial, "right", 7, "");
        auto received = subscription.accept(initial);
        CHECK(received && *received && (**received).version() == 20);
        held = **received;
        CHECK(held.find("right")->value->empty());
        auto update = page(proto::comet::v1::MODE_APPLY, 21);
        value(update, "left", 1000, "two");
        CHECK(subscription.accept(update));
        auto erase = page(proto::comet::v1::MODE_APPLY, 22);
        auto* item = erase.add_changes();
        item->set_key("right");
        item->mutable_erase();
        CHECK(subscription.accept(erase));
        CHECK(!subscription.view(Subscriber::State::Ready).find("right"));

        subscription.begin("star-b");
        auto replacement = page(proto::comet::v1::MODE_RESET, 1, "star-b");
        value(replacement, "left", 5, "older");
        received = subscription.accept(replacement);
        CHECK(received && *received && (**received).version() == 1 && (**received).size() == 1);
        CHECK((**received).find("left")->version == 5 && !((**received).find("right")));
        auto rollback = page(proto::comet::v1::MODE_APPLY, 0, "star-b");
        CHECK(!subscription.accept(rollback)); // Same-instance view cursor cannot regress.
    }
    std::size_t count{}; // Application views remain traversable after installer destruction.
    held.each([&](std::string_view key, const Subscriber::Record& record) { CHECK(!key.empty() && record.version > 0 && record.value); ++count; });
    CHECK(count == 2 && held.find("left")->version == 100);
    CHECK(held.scope().sector == "dynamic" && held.scope().spectrum == "main");

    // Retain no second View; resetting the original handle inside a callback must still traverse both records.
    count = 0;
    held.each([&](std::string_view key, const Subscriber::Record& record) {
        held = {};
        CHECK((key == "left" && record.version == 100) || (key == "right" && record.version == 7));
        CHECK(record.value);
        ++count;
    });
    CHECK(count == 2 && !held.version());
    CHECK(held.scope().sector.empty() && held.scope().spectrum.empty());
}

/// Unversioned values, versioned Deletes, cross-page duplicates, and incomplete-page failures cannot publish partial batches or replace the old root.
void malformed() {

    Subscription subscription({"dynamic", "main"}, {}, 65536, 2);
    subscription.begin("star-a");
    auto initial = page(proto::comet::v1::MODE_RESET, 1);
    value(initial, "key", 1, "initial");
    CHECK(subscription.accept(initial));
    auto zero = page(proto::comet::v1::MODE_APPLY, 2);
    value(zero, "key", 0, "invalid");
    const auto rejected = subscription.accept(zero);
    CHECK(!rejected);
    CHECK(!subscription.repair(rejected.error().code)); // Catalog protocol errors must not enable unlimited snapshot repair.
    CHECK(subscription.view(Subscriber::State::Failed).find("key")->version == 1);
    subscription.begin("star-a");
    auto erased = page(proto::comet::v1::MODE_APPLY, 2);
    auto* item = erased.add_changes();
    item->set_key("key");
    item->set_version(1);
    item->mutable_erase();
    CHECK(!subscription.accept(erased));

    subscription.begin("star-a");
    auto head = page(proto::comet::v1::MODE_RESET, 3);
    head.set_complete(false);
    head.clear_version();
    head.clear_instance();
    value(head, "key", 2, "partial");
    const auto accepted = subscription.accept(head);
    CHECK(accepted && !*accepted && subscription.view(Subscriber::State::Stale).find("key")->version == 1);
    auto tail = page(proto::comet::v1::MODE_RESET, 3);
    value(tail, "key", 3, "duplicate");
    CHECK(!subscription.accept(tail));
    CHECK(subscription.view(Subscriber::State::Failed).find("key")->version == 1);
}
} // namespace

/// Pure installation cases consume generated messages without starting gRPC or reading physical time.
int main() {
    try {
        lifecycle();
        malformed();
        comet::test::duplicates<Subscription>([](auto& change, std::string_view key) { change.set_key(key); change.mutable_erase(); }); // Catalog Delete carries no business version.
        std::cout << "Catalog subscription tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
