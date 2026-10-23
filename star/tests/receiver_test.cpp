// Verify authoritative-stream reception without partial visible snapshot replacement.
#include "check.hpp"
#include "receiver.hpp"

#include <iostream>

namespace {
/// Declares one initial Scope/minimum version in a complete plan frame.
proto::polaris::v1::Packet plan(std::uint64_t version) {
    proto::polaris::v1::Packet packet;
    auto* page = packet.mutable_plan();
    page->set_complete(true);
    auto* position = page->add_positions();
    position->mutable_scope()->set_sector("a");
    position->mutable_scope()->set_spectrum("s");
    position->set_version(version);
    return packet;
}

/// One Set snapshot page; empty key means empty page. Every page carries version, but only complete installs.
proto::polaris::v1::Packet snapshot(std::uint64_t version, bool complete, std::string key) {

    proto::polaris::v1::Packet packet;
    auto* page = packet.mutable_snapshot();
    page->mutable_scope()->set_sector("a");
    page->mutable_scope()->set_spectrum("s");
    page->set_version(version);
    page->set_complete(complete);
    if (!key.empty()) {
        auto* entry = page->add_entries(); // Empty Set remains distinct from missing action.
        entry->set_key(std::move(key));
        entry->set_value("");
    }
    return packet;
}

/// One ordered single-key patch, later modified explicitly to exercise version/action boundaries.
proto::polaris::v1::Packet update(std::uint64_t version) {
    proto::polaris::v1::Packet packet;
    auto* page = packet.mutable_updates();
    page->mutable_scope()->set_sector("a");
    page->mutable_scope()->set_spectrum("s");
    auto* patch = page->add_patches();
    patch->set_version(version);
    patch->mutable_change()->set_key("key");
    patch->mutable_change()->set_value("changed");
    return packet;
}

/// Partial disconnection preserves old state; reconnect reports only installed versions and queues ACK after complete installation.
void snapshots() {

    astra::Library library;
    astra::Access access; // One Library shares the same Access across streams.
    const astra::Scope scope{"a", "s"};
    {
        astra::Receiver receiver(library, access);
        CHECK(receiver.next()->inventory().complete()); // Even an empty process sends explicit complete inventory.
        CHECK(receiver.receive(plan(4)));
        CHECK(receiver.receive(snapshot(4, false, "key")));
        CHECK(!receiver.next() && !library.find(scope));
    }

    astra::Receiver receiver(library, access); // Partial candidate state cannot carry into the next stream.
    CHECK(receiver.next()->inventory().positions().empty());
    CHECK(receiver.receive(plan(4)));
    CHECK(receiver.receive(snapshot(4, false, "key")));
    CHECK(receiver.receive(snapshot(4, true, "other")));
    CHECK(library.find(scope)->view()->size() == 2);
    CHECK(receiver.next()->acknowledged().version() == 4);
    CHECK(receiver.receive(update(5)));
    CHECK(receiver.receive(update(6)));
    CHECK(receiver.next()->acknowledged().version() == 6 && !receiver.next());
    proto::polaris::v1::Packet ready; // Server ready still requires local installed-version verification.
    ready.mutable_ready();
    CHECK(receiver.receive(ready) && receiver.ready());
    CHECK(!receiver.receive(update(8)) && !receiver.ready());
    CHECK(!receiver.receive(update(7))); // First failure seals the stream; later pages cannot silently repair it.
    CHECK(library.find(scope)->usage().version == 6);
}

/// Duplicate keys, mixed versions, and empty-baseline failures install no candidate prefix.
void invalid() {

    for (unsigned scenario = 0; scenario < 4; ++scenario) {
        astra::Library library;
        astra::Access access;
        astra::Receiver receiver(library, access);
        static_cast<void>(receiver.next());
        CHECK(receiver.receive(plan(2)));
        CHECK(receiver.receive(snapshot(2, false, "key")));
        auto final = snapshot(scenario == 1 ? 3 : 2, true, scenario == 0 ? "key" : "other");
        if (scenario == 2) {
            final.mutable_snapshot()->clear_version();
        }
        if (scenario == 3) {
            final.mutable_snapshot()->mutable_entries(0)->mutable_erase();
        }
        CHECK(!receiver.receive(final));
        CHECK(!library.find({"a", "s"}));
    }

    astra::Library library;
    astra::Access access;
    astra::Receiver receiver(library, access);
    static_cast<void>(receiver.next());
    CHECK(receiver.receive(plan(0)));
    CHECK(receiver.receive(snapshot(0, true, "")));
    const auto ack = receiver.next(); // Explicit zero still receives ACK and cannot mean no baseline.
    CHECK(ack && ack->has_acknowledged() && ack->acknowledged().version() == 0);
    CHECK(library.find({"a", "s"})->usage().version == 0);
}

/// Large paged baselines preserve the old root until the final page, without incremental page visibility.
void largeSnapshot() {

    astra::Library library;
    astra::Access access;
    astra::Receiver receiver(library, access);
    CHECK(receiver.next());
    CHECK(receiver.receive(plan(1)));
    CHECK(receiver.receive(snapshot(1, true, "old")));
    CHECK(receiver.next()->acknowledged().version() == 1);
    const auto book = library.find({"a", "s"});
    const auto old = book->view(); // Pin the old complete snapshot and verify later root publication cannot mutate it.

    for (unsigned index = 0; index < 257; ++index) { // Pages total more than 8 MiB; only the final page is complete.
        auto page = snapshot(2, index == 256, std::to_string(index));
        page.mutable_snapshot()->mutable_entries(0)->set_value(std::string(40 * 1024, 'v'));
        CHECK(receiver.receive(page));
        if (index != 256) {
            CHECK(book->view()->version() == 1 && book->view()->size() == 1);
            CHECK(book->find("old")->value && !receiver.next());
        }
    }
    CHECK(book->view()->version() == 2 && book->view()->size() == 257);
    CHECK(!book->find("old")->value && old->version() == 1 && old->size() == 1);
    CHECK(receiver.next()->acknowledged().version() == 2);
}
} // namespace

int main() {
    {
        astra::Library library; // One 257-key patch exceeds 2 MiB, confirmed as one authoritative version only after complete installation.
        astra::Access access;
        astra::Receiver receiver(library, access);
        CHECK(receiver.next());
        CHECK(receiver.receive(plan(0)));
        CHECK(receiver.receive(snapshot(0, true, "")));
        CHECK(receiver.next());
        auto packet = update(1);
        auto* patch = packet.mutable_updates()->mutable_patches(0);
        patch->clear_change();
        for (unsigned index = 0; index < 257; ++index) {
            auto* entry = patch->add_changes();
            entry->set_key(std::to_string(index));
            entry->set_value(std::string(8192, 'v'));
        }
        CHECK(receiver.receive(packet));
        const auto book = library.find({"a", "s"});
        CHECK(book->view()->size() == 257 && book->view()->version() == 1);
        CHECK(receiver.next()->acknowledged().version() == 1);
        patch->set_version(2);
        patch->mutable_changes(1)->set_key("0"); // Duplicate keys cannot let the first item commit early.
        CHECK(!receiver.receive(packet));
        CHECK(book->view()->version() == 1 && book->replay(0)->changes.size() == 257);
    }
    snapshots();
    largeSnapshot();
    invalid();
    {
        // At minimum negotiated capacity, every inventory page progresses without omissions or oversized encoding.
        astra::Library library;
        astra::Access access;
        for (unsigned index = 0; index < 20; ++index) {
            auto draft = library.prepare({std::string(128, 's'), std::string(120, 'p') + std::to_string(index)}, index);
            CHECK(draft && library.reset(std::move(*draft)));
        }
        astra::Receiver receiver(library, access);
        std::size_t count{};
        std::size_t pages{};
        bool complete{};
        while (const auto packet = receiver.next(1024)) {
            CHECK(!complete && packet->ByteSizeLong() <= 1024 && !packet->inventory().positions().empty());
            count += static_cast<std::size_t>(packet->inventory().positions_size());
            ++pages;
            complete = packet->inventory().complete();
        }
        CHECK(complete && count == 20 && pages > 1);
    }
    std::cout << "Almanac receiver checks passed\n";
}
