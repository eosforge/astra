// Verify validation and staged publication of incoming native source state.
#include "check.hpp"
#include "fixture.hpp"
#include "intake.hpp"

#include <grpcpp/server_builder.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <utility>

using namespace astra;

namespace {
/// Real TLS protocol scenarios without replacing production receiving state or gRPC callbacks.
enum class Scenario {
    /// Paged baseline, contiguous suffix, Probe, and complete-installation confirmation.
    Complete,
    /// Star-only identity cannot publish authoritative Almanac.
    Role,
    /// Corrupt raw credential signature rejects the initial snapshot.
    Signature,
    /// Disconnect after partial baseline must leave Library unchanged.
    Interrupted,
    /// Post-baseline version gap closes the stream while preserving the installed version.
    Gap,
    /// A higher epoch of the same deployment may replace a stale directory target.
    Replacement
};

/// Public fixture identity with real loopback endpoint, selected Star/Polaris role, and default epoch one.
Member member(const Endpoint& endpoint, Member::Role role, std::uint64_t epoch = 1) {
    return Member{"alpha", role == Member::Role::Polaris ? "polaris-" + std::to_string(epoch) : "star-instance", *Principal::parse(std::string(64, role == Member::Role::Polaris ? 'a' : 'b')), endpoint, {epoch}, role, "default"};
}

/// Signs raw Hello with public test materials, without deployment private keys.
proto::astra::v1::Hello hello(const Member& value) {

    proto::orbit::v1::Member encoded;
    encoded.set_galaxy(value.galaxy);
    encoded.set_id(value.id);
    encoded.set_principal(value.principal.bytes.data(), value.principal.bytes.size());
    encoded.set_advertise(value.address.text());
    encoded.set_epoch(value.epoch.value);
    encoded.set_role(Identity::role(value.role));
    encoded.set_group(value.group);
    proto::astra::v1::Hello result;
    result.set_protocol_major(1);
    result.set_max_frame_bytes(1024); // Advertise a small receive limit to prevent the client from assuming 256 KiB inventory pages.
    result.set_admission(encoded.SerializeAsString());
    result.set_admission_signature(test::sign(result.admission()));
    return result;
}

/// Bounded test-only synchronous service; production Polaris remains Go. Client cancellation must unblock reads.
class Authority final : public proto::polaris::v1::Almanac::Service {
public:
    /// Fixed scenario; construction starts no thread and mutates no Library.
    explicit Authority(Scenario scene) : scene_(scene) {}

    /// Greeting set before client startup, read-only afterward.
    proto::astra::v1::Hello greeting;
    /// Counts actual inventory rows and verifies cumulative ACK/Probe against real messages.
    std::atomic_size_t received{};
    /// True only when the complete normal exchange finishes.
    std::atomic_bool verified{};
    /// Handler assertion failures return fixed errors and publish a flag to the main test thread.
    std::atomic_bool failed{};

    /// Context/stream are handler-local borrows; exceptions never cross the gRPC boundary.
    grpc::Status Open(grpc::ServerContext*, grpc::ServerReaderWriter<proto::polaris::v1::Packet, proto::polaris::v1::Packet>* stream) override {

        try {
            proto::polaris::v1::Packet packet;
            CHECK(stream->Read(&packet) && packet.has_hello());
            packet.Clear();
            *packet.mutable_hello() = greeting;
            CHECK(stream->Write(packet));
            if (scene_ == Scenario::Role || scene_ == Scenario::Signature) {
                while (stream->Read(&packet)) {}
                return grpc::Status::OK;
            }

            // Accumulate inventory until complete, not merely the first empty/nonempty page.
            proto::polaris::v1::Inventory inventory;
            do {
                CHECK(stream->Read(&packet) && packet.has_inventory() && packet.ByteSizeLong() <= 1024);
                for (const auto& position : packet.inventory().positions()) {
                    *inventory.add_positions() = position;
                    ++received;
                }
            } while (!packet.inventory().complete());
            packet.Clear();
            *packet.mutable_plan() = inventory;
            auto* required = packet.mutable_plan()->add_positions();
            required->mutable_scope()->set_sector("a");
            required->mutable_scope()->set_spectrum("s");
            required->set_version(1);
            packet.mutable_plan()->set_complete(true);
            CHECK(stream->Write(packet));

            // First page is incomplete; disconnection must leave a/s absent.
            packet.Clear();
            auto* page = packet.mutable_snapshot();
            page->mutable_scope()->set_sector("a");
            page->mutable_scope()->set_spectrum("s");
            page->set_version(1);
            auto* record = page->add_entries();
            record->set_key("key");
            record->set_value("original");
            CHECK(stream->Write(packet));
            if (scene_ == Scenario::Interrupted) {
                return {grpc::StatusCode::UNAVAILABLE, "Owned test interruption"};
            }
            page->clear_entries();
            page->set_complete(true);
            CHECK(stream->Write(packet));
            CHECK(stream->Read(&packet) && packet.has_acknowledged() && packet.acknowledged().version() == 1);

            // Apply changes only after a complete baseline; gap changes version deterministically without network reordering.
            packet.Clear();
            auto* updates = packet.mutable_updates();
            updates->mutable_scope()->set_sector("a");
            updates->mutable_scope()->set_spectrum("s");
            auto* patch = updates->add_patches();
            patch->set_version(scene_ == Scenario::Gap ? 3 : 2);
            patch->mutable_change()->set_key("key");
            patch->mutable_change()->set_value("updated");
            CHECK(stream->Write(packet));
            if (scene_ == Scenario::Gap) {
                while (stream->Read(&packet)) {}
                return grpc::Status::OK;
            }
            packet.Clear();
            packet.mutable_probe();
            CHECK(stream->Write(packet));
            // ACK and Probe inventories may interleave; assert actual versions/completeness without assuming send order.
            bool acknowledged{}, complete{};
            std::size_t positions{};
            while (!acknowledged || !complete) {
                CHECK(stream->Read(&packet) && packet.ByteSizeLong() <= 1024);
                if (packet.has_acknowledged()) {
                    CHECK(packet.acknowledged().version() == 2);
                    acknowledged = true;
                } else {
                    CHECK(packet.has_inventory());
                    for (const auto& position : packet.inventory().positions()) {
                        if (position.scope().sector() == "a") {
                            CHECK(position.version() == 2);
                        }
                        ++positions;
                    }
                    complete = packet.inventory().complete();
                }
            }
            CHECK(positions == static_cast<std::size_t>(inventory.positions_size()) + 1);
            verified = true;
            packet.Clear();
            packet.mutable_ready();
            CHECK(stream->Write(packet));
            while (stream->Read(&packet)) {} // Keep the long stream until cancellation; EOF is not ready.
            return grpc::Status::OK;
        } catch (...) {
            failed = true;
            return {grpc::StatusCode::INTERNAL, "Owned test assertion failed"};
        }
    }

private:
    /// Fix the authority fault scenario for the lifetime of this isolated service.
    const Scenario scene_;
};

/// Owns allocated listener, client Reactor, and native Library, draining real I/O before destruction.
struct Fixture {
    /// Data constructed before Intake and destroyed after services/client completion.
    Library library;
    /// Library's sole Access index, updated by Receiver with internal credentials.
    Access access;
    /// Test handler outlives its registered Server.
    Authority authority;
    /// Allocated-port listener independent of deployed Pulsar/Polaris.
    std::unique_ptr<grpc::Server> server;
    /// Sole client owner; never destroyed before OnDone.
    std::unique_ptr<Intake> intake;

    /// Preinstalls count valid empty Scopes for small-frame inventory paging, default zero.
    Fixture(Scenario scene, unsigned count = 0) : authority(scene) {

        for (unsigned index = 0; index < count; ++index) {
            auto draft = library.prepare({std::string(128, 's'), std::string(120, 'p') + std::to_string(index)}, 0);
            CHECK(draft && library.reset(std::move(*draft)));
        }
        const auto identity = Identity::load(std::filesystem::path(ASTRA_FIXTURES) / "star-a", *Endpoint::parse("127.0.0.1:7443"));
        CHECK(identity);
        grpc::ServerBuilder builder;
        builder.RegisterService(&authority);
        int port{};
        builder.AddListeningPort("127.0.0.1:0", (*identity)->serverCredentials(), &port);
        server = builder.BuildAndStart();
        CHECK(server && port > 0);
        try {
            const auto endpoint = *Endpoint::parse("127.0.0.1:" + std::to_string(port));
            const auto target = member(endpoint, Member::Role::Polaris);
            auto remote = target;
            if (scene == Scenario::Role) {
                remote.role = Member::Role::Star;
            } else if (scene == Scenario::Replacement) {
                remote = member(endpoint, Member::Role::Polaris, 2);
            }
            authority.greeting = hello(remote);
            if (scene == Scenario::Signature) {
                authority.greeting.mutable_admission_signature()->front() ^= 1;
            }
            intake = std::make_unique<Intake>(*identity, hello(member(*Endpoint::parse("127.0.0.1:7443"), Member::Role::Star)), target, library, access, [] {});
        } catch (...) {
            // Incomplete Fixture construction skips its destructor; explicitly drain an already started listener on failure.
            server->Shutdown();
            server->Wait();
            throw;
        }
    }

    /// Failure still cancels/drains; cleanup timeout terminates nonzero rather than leaving dangling Reactor borrows.
    ~Fixture() {

        if (intake) {
            intake->cancel();
            const auto deadline = Steady::now() + std::chrono::seconds(7);
            while (!intake->done() && Steady::now() < deadline) {
                intake->pump(Steady::now());
                std::this_thread::sleep_for(Milliseconds(1));
            }
            if (!intake->done()) {
                std::_Exit(3);
            }
            intake.reset();
        }
        if (server) {
            server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(2));
            server->Wait();
        }
    }

    /// Pump real callbacks for at most seven seconds until ready/final closure.
    void wait() {

        const auto deadline = Steady::now() + std::chrono::seconds(7);
        while (!intake->ready() && !intake->done() && Steady::now() < deadline) {
            intake->pump(Steady::now());
            std::this_thread::sleep_for(Milliseconds(1));
        }
        CHECK(intake->ready() || intake->done());
    }
};
} // namespace

int main() {

    try {
        for (const auto scenario : {Scenario::Complete, Scenario::Replacement}) {
            Fixture fixture(scenario, 20);
            fixture.wait();
            CHECK(fixture.intake->ready() && fixture.authority.verified && !fixture.authority.failed && fixture.authority.received == 20);
            CHECK(!fixture.intake->error()); // A successful authenticated stream has no local cancellation cause.
            CHECK(fixture.intake->target().epoch.value == (scenario == Scenario::Replacement ? 2 : 1));
            const auto point = fixture.library.find({"a", "s"})->find("key");
            CHECK(point && point->version == 2 && std::string(point->value->begin(), point->value->end()) == "updated");
        }
        for (const auto scenario : {Scenario::Role, Scenario::Signature, Scenario::Interrupted, Scenario::Gap}) {
            Fixture fixture(scenario);
            fixture.wait();
            CHECK(!fixture.intake->ready() && fixture.intake->done());
            const auto book = fixture.library.find({"a", "s"});
            CHECK(scenario == Scenario::Gap ? book && book->usage().version == 1 : !book);
        }
        {
            Fixture fixture(Scenario::Complete);
            CHECK(!fixture.intake->error());
            fixture.intake->cancel(); // A bound Reactor not yet StartCalled must still complete normally.
            CHECK(fixture.intake->error() == Status::Code::Cancelled);
            fixture.intake->cancel(Status::Code::Internal); // Repeated cancellation must retain the original cause.
            CHECK(fixture.intake->error() == Status::Code::Cancelled);
            fixture.wait();
            CHECK(fixture.intake->done() && !fixture.intake->ready());
            CHECK(fixture.intake->error() == Status::Code::Cancelled);
        }
        std::cout << "PASS TLS Almanac intake, negotiated inventory, replacement, partial reset and cancellation\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
