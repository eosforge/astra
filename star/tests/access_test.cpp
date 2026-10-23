// Verify credential validation and public authorization boundaries.
#include "access.hpp"
#include "check.hpp"
#include "orbit.pb.h"
#include "receiver.hpp"

#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <thread>

namespace {
using astra::Access;
using astra::Almanac;

/// Private draft with binary SECRET, never treated as UTF-8 or NUL-terminated text.
Access::Draft prepare(std::uint8_t value = 1) {
    Access::Draft draft; // Every call creates a fresh credential-snapshot identity.
    CHECK(draft.set("first", {0, value, 255}));
    CHECK(draft.set("second", {2}));
    return draft;
}

/// Models an already committed backing store; Receiver separately verifies real Library ordering.
std::expected<bool, Almanac::Error> committed() {
    return true;
}

/// Checks a valid session. Retained references do not extend authorization, and close immediately removes the token.
std::shared_ptr<Access::Session> login(Access& access, std::uint8_t value = 1) {
    const Almanac::Buffer secret{0, value, 255};
    const auto session = access.open("first", secret);
    CHECK(session && (*session)->token().size() == 32 && access.enter((*session)->token()));
    return *session;
}

/// Revoked Sessions still count until their real streams finish; repeated close cannot affect later logins.
void lifecycle() {

    Access access(2);
    CHECK(access.reset(prepare(), committed));
    const auto first = login(access);
    const auto second = login(access);
    CHECK(first->token() != second->token());
    CHECK(access.open("first", Almanac::Buffer{0, 1, 255}).error() == Access::Error::Capacity);
    CHECK(!access.open("first", Almanac::Buffer{0, 1}));
    CHECK(!access.open("missing", Almanac::Buffer{2}));
    CHECK(!access.open("first", {}));
    CHECK(!access.open(std::string(129, 'k'), Almanac::Buffer{2}));
    CHECK(!access.enter(""));
    CHECK(!access.enter(std::string(32, 'x')));
    access.close(first);
    CHECK(first->stopped().stop_requested() && !access.enter(first->token()));
    const auto third = login(access);
    access.close(first);
    CHECK(access.enter(second->token()) && access.enter(third->token()));
    access.close(second);
    access.close(third);
}

/// Incremental changes revoke only changed accounts; a full new snapshot revokes old sessions even with identical bytes.
void replacement() {

    Access access;
    CHECK(access.reset(prepare(), committed));
    const auto first = login(access);
    const auto second = *access.open("second", Almanac::Buffer{2});
    CHECK(access.apply("first", Almanac::Buffer{0, 1, 255}, committed));
    CHECK(access.enter(first->token()) && !first->stopped().stop_requested());
    CHECK(access.apply("first", Almanac::Buffer{0, 3, 255}, committed));
    CHECK(!access.enter(first->token()) && first->stopped().stop_requested());
    CHECK(access.enter(second->token()));
    const auto current = login(access, 3);
    CHECK(access.apply("first", std::nullopt, committed));
    CHECK(!access.enter(current->token()));
    CHECK(access.apply("first", Almanac::Buffer{0, 3, 255}, committed));
    CHECK(!access.enter(current->token()));
    const auto recreated = login(access, 3);
    CHECK(!*access.reset(prepare(), [] { return std::expected<bool, Almanac::Error>(false); }));
    CHECK(access.enter(recreated->token()) && access.enter(second->token()));
    CHECK(access.reset(prepare(3), committed));
    CHECK(!access.enter(recreated->token()) && !access.enter(second->token()));
    CHECK(recreated->stopped().stop_requested() && second->stopped().stop_requested());
    const auto renewed = login(access, 3);
    CHECK(access.enter(renewed->token()));
}

/// Preparation/commit failure preserves authorization. Off-lock cancellation may log in again or reclaim an old Session.
void failures() {

    Access access;
    CHECK(access.reset(prepare(), committed));
    const auto original = login(access);
    const auto failed = [] { return std::expected<bool, Almanac::Error>(std::unexpected(Almanac::Error::Capacity)); };
    CHECK(!access.apply("first", Almanac::Buffer{4}, failed));
    CHECK(!access.reset(prepare(4), failed));
    CHECK(access.enter(original->token()) && !original->stopped().stop_requested());
    bool threw{};
    try {
        static_cast<void>(access.apply("first", Almanac::Buffer{4}, []() -> std::expected<bool, Almanac::Error> { throw std::bad_alloc{}; }));
    } catch (const std::bad_alloc&) {
        threw = true;
    }
    CHECK(threw && access.enter(original->token()));
    std::shared_ptr<Access::Session> current;
    std::stop_callback callback(original->stopped(), [&] {
        access.close(original);
        current = login(access, 5);
    });
    CHECK(access.apply("first", Almanac::Buffer{0, 5, 255}, committed));
    CHECK(current && access.enter(current->token()) && !access.enter(original->token()));
}

/// Rotation waits while final commit holds shared Permit; afterward the same token cannot acquire permission again.
void ordering() {

    Access access;
    CHECK(access.reset(prepare(), committed));
    const auto session = login(access);
    std::promise<void> started; // Synchronizes only these two fixture threads, independently of network timing.
    auto arrival = started.get_future();
    std::atomic_bool installed{};
    std::jthread writer;
    {
        const auto permit = access.enter(session->token());
        CHECK(permit);
        writer = std::jthread([&] {
            started.set_value();
            const auto result = access.apply("first", Almanac::Buffer{9}, committed);
            installed.store(result && *result, std::memory_order_release);
        });
        CHECK(arrival.wait_for(std::chrono::seconds(2)) == std::future_status::ready);
        CHECK(!installed.load(std::memory_order_acquire));
    }
    writer.join();
    CHECK(installed.load(std::memory_order_acquire) && !access.enter(session->token()));
}

/// Real internal snapshot pages share a fixed authoritative version; login index changes only after complete.
proto::polaris::v1::Packet snapshot(std::uint64_t version, bool complete, std::string key) {

    proto::polaris::v1::Packet packet;
    auto* page = packet.mutable_snapshot();
    page->mutable_scope()->set_sector("__auth");
    page->mutable_scope()->set_spectrum("comet");
    page->set_version(version);
    page->set_complete(complete);
    if (!key.empty()) {
        proto::orbit::v1::Credential credential;
        credential.set_secret(std::string("\0\1\xff", 3));
        auto* entry = page->add_entries();
        entry->set_key(std::move(key));
        entry->set_value(credential.SerializeAsString());
    }
    return packet;
}

/// Receiver must publish backing version and login index together; reconnect failure cannot revive old Sessions.
void receiving() {

    astra::Library library;
    Access access;
    astra::Receiver receiver(library, access);
    static_cast<void>(receiver.next());
    proto::polaris::v1::Packet plan; // An empty initial plan permits later dynamic internal-Scope creation.
    plan.mutable_plan()->set_complete(true);
    CHECK(receiver.receive(plan));
    CHECK(receiver.receive(snapshot(1, false, "first")));
    CHECK(!library.find({"__auth", "comet"}) && !access.open("first", Almanac::Buffer{0, 1, 255}));
    CHECK(receiver.receive(snapshot(1, true, "")));
    const auto session = login(access);
    CHECK(library.find({"__auth", "comet"})->usage().version == 1);
    CHECK(receiver.receive(snapshot(1, true, "first")));
    CHECK(access.enter(session->token()));
    CHECK(receiver.receive(snapshot(3, true, "first")));
    CHECK(!access.enter(session->token()) && library.find({"__auth", "comet"})->usage().version == 3);
    const auto current = login(access);
    auto invalid = snapshot(4, true, "first"); // Reject invalid SECRET before publishing any new version.
    invalid.mutable_snapshot()->mutable_entries(0)->set_value("");
    CHECK(!receiver.receive(invalid));
    CHECK(access.enter(current->token()) && library.find({"__auth", "comet"})->usage().version == 3);
}
} // namespace

int main() {
    try {
        lifecycle();
        replacement();
        failures();
        ordering();
        receiving();
        std::cout << "PASS business access lifecycle and credential installation\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
