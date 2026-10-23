// Verify Hello, Ping/Pong, and session I/O ownership across completion and cancellation.
#include "check.hpp"
#include "fixture.hpp"
#include "grpc_session.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace astra;

namespace {

/// Signs test credentials with repository-public keys, without reading deployment identities.
std::shared_ptr<proto::astra::v1::Hello> hello(const Identity& identity) {

    // Owned signed test Member matching public fixture fields.
    proto::orbit::v1::Member member;
    member.set_galaxy("alpha");
    member.set_group("default");
    member.set_id("00000001000040008000000000000000");
    member.set_advertise("127.0.0.1:7443");
    const auto digest = identity.principal(member.galaxy(), member.advertise());
    member.set_principal(digest.bytes.data(), digest.bytes.size());
    member.set_epoch(1);
    member.set_role(proto::orbit::v1::ROLE_STAR);
    // Shared immutable Hello uses actual test signatures for Session verification.
    auto result = std::make_shared<proto::astra::v1::Hello>();
    result->set_protocol_major(protocolMajor);
    result->set_max_frame_bytes(4096);
    result->set_admission(member.SerializeAsString());
    result->set_admission_signature(test::sign(result->admission()));
    return result;
}

/// Records identity installation after authentication only; core_test independently covers role rules.
struct Recorder final : Policy {
    /// Successful accept count, initially zero, proving business identity is not installed before handshake.
    unsigned installations{};

    /// Recording policy does not validate directories; unused parameters satisfy Policy while separate cases test roles.
    Result<void> initialize(const Member&, std::span<const Member>) override {
        return {};
    }

    /// Increments installation count and returns no displaced Sessions; does not model replacement.
    Result<std::vector<Generation>> accept(const Member&, Policy::Direction, Generation, const std::optional<Member>&) override {
        ++installations;
        return std::vector<Generation>{};
    }

    /// No-op closure hook; fixture observes installation timing without maintaining topology.
    void closed(Generation, std::optional<Status::Code>, Steady::time_point) override {}

    /// Returns no dial target to isolate Session units.
    std::optional<Member> due(Steady::time_point) override {
        return {};
    }

    /// Ignores dial failure; core_test covers backoff.
    void failed(const Member&, Status::Code, Steady::time_point) override {}

    /// No control-plane refresh; always false.
    bool needsRefresh(Steady::time_point) override {
        return false;
    }

    /// Empty diagnostic snapshot; installations is this fixture's observable result.
    Policy::State status() const override {
        return {};
    }
};

/// Controls callback ordering to reproduce stalled writes and deadline races deterministically.
struct Manual final : Session {
    using Session::Session;
    /// Borrows the sole in-flight receive buffer; deliver clears it immediately after publishing completion.
    proto::astra::v1::SessionPacket* receiving{};
    /// Assertion-only copy of the latest submitted write, without transport ownership semantics.
    proto::astra::v1::SessionPacket lastWrite;
    /// Read, write, finish, start, and forced-cancel counts, initially zero.
    unsigned reads{}, writes{}, finishes{}, calls{}, forced{};
    /// Initially ready; stalled outbound cases explicitly set false.
    bool ready = true;
    /// Defaults to immediate simulated RPC completion; false separates Finish from OnDone.
    bool finishImmediately = true;

    /// Publishes final success to Session only when explicitly requested by the case.
    void complete() {
        completed(grpc::Status::OK);
    }

    /// Returns controlled readiness without querying network state.
    bool transportReady() const override {
        return ready;
    }

    /// Swaps owned packet into the sole in-flight receive buffer and publishes completion; asserts if no read was submitted.
    void deliver(proto::astra::v1::SessionPacket packet) {

        CHECK(receiving);
        receiving->Swap(&packet);
        receiving = nullptr;
        readDone(true);
    }

    /// Publishes successful write completion so Session may reuse its send buffer.
    void acknowledge() {
        writeDone(true);
    }

    /// Completes the sole read with EOF during send preparation; leaves no old pointer for later deliver.
    void eof() {
        CHECK(receiving);
        receiving = nullptr;
        readDone(false);
    }

    /// Publishes initial metadata completion to permit later sends.
    void acknowledgeMetadata() {
        metadataDone(true);
    }

    /// Fixture-specific start hook counts or does nothing, without actual RPC creation.
    void beginCall() override {
        ++calls;
    }

    /// Borrows packet receive storage for delivery; must not overwrite an in-flight buffer.
    void beginRead(proto::astra::v1::SessionPacket* packet) override {

        CHECK(!receiving);
        receiving = packet;
        ++reads;
    }

    /// Records a write for manual or worker completion without synchronously calling Session back.
    void beginWrite(const proto::astra::v1::SessionPacket* packet) override {
        lastWrite = *packet;
        ++writes;
    }

    /// Receives cancellation requests; controlled fixture counts force, while concurrent fixture owns no actual cancelable network.
    void requestCancel(bool force) override {
        forced += force;
    }

    /// Records or ignores simulated transport finish without modeling external gRPC lifetime.
    void finishCall(Status::Code) override {

        ++finishes;
        if (finishImmediately) {
            complete();
        }
    }
};

/// Interleaves events during send preparation to test Session buffer handoff only, not replication algorithms.
struct Preparation final : Session::Data {
    /// Optional synchronous action during prepare; empty means no interleaving.
    std::function<void()> action;
    /// Sole candidate packet, handed off only by take.
    proto::astra::v1::SessionPacket outbound;
    /// Last received test sequence from Repair.trigger; initially zero.
    std::uint64_t received{};
    /// Preparation and actual-submit counts check that failures do not advance sending.
    unsigned preparations{}, taken{};
    /// True injects business rejection; defaults to acceptance.
    bool rejected{};

    /// Requires contiguous receive sequences without retaining field borrows, detecting overwrite or repeated consumption next round.
    Result<void> receive(const proto::astra::v1::SessionPacket& packet, Steady::time_point) override {

        CHECK(packet.has_repair() && packet.repair().trigger() == received + 1);
        if (rejected) {
            return Status::protocol("Test receive rejection");
        }
        received = packet.repair().trigger();
        return {};
    }

    /// Interleaves completion before returning the exclusive candidate; action may throw to exercise cancellation rollback.
    Result<const proto::astra::v1::SessionPacket*> prepare(Steady::time_point) override {

        ++preparations;
        if (action) {
            action();
        }
        outbound.mutable_repair()->set_trigger(1);
        return &outbound;
    }

    /// Called only immediately before StartWrite; cancellation must not consume the candidate.
    proto::astra::v1::SessionPacket take() override {
        ++taken;
        return std::move(outbound);
    }

    /// Fixed readiness omits initial business synchronization without changing transport-handoff rules.
    bool ready() const noexcept override {
        return true;
    }
};

/// Creates Ping/Pong with id; response defaults false and callers may inject invalid sequences.
proto::astra::v1::SessionPacket ping(std::uint64_t id, bool response = false) {

    // Owns the heartbeat branch independently of inputs.
    proto::astra::v1::SessionPacket result;
    if (response) {
        result.mutable_pong()->set_request_id(id);
    } else {
        result.mutable_ping()->set_request_id(id);
    }
    return result;
}

/// Another thread delivers actual read callbacks, checking prior buffer consumption before each resubmission.
/// Does not mutate gRPC internals or rely on sleep to hit race windows.
class Concurrent final : public Session {
public:
    /// Retains greeting, copies config into Session, and starts a delivery worker that hands buffers off through callbacks only.
    Concurrent(const Config& config, std::shared_ptr<const proto::astra::v1::Hello> greeting) : Session(config, Policy::Direction::Inbound, {8}, greeting, std::nullopt, [] {}), worker_([this, greeting](std::stop_token stop) { run(stop, *greeting); }) {}

    /// Explicit metadata completion permits subsequent sends in the concurrent fixture.
    void ready() {
        metadataDone(true);
    }

    /// Atomic delivered count supplies the bounded completion predicate.
    unsigned delivered() const {
        return delivered_.load();
    }

private:
    /// Sole worker closure retains greeting; jthread destruction requests stop.
    void run(std::stop_token stop, const proto::astra::v1::Hello& greeting) {

        unsigned acknowledged{}; // Completed response-write count enforces one receipt per simulated request.
        while (!stop.stop_requested()) {
            // Complete the control-loop response write before allowing another peer Ping.
            if (writing_.exchange(false)) {
                writeDone(true);
                ++acknowledged;
            }

            // Read/write receipts impose realistic backpressure instead of an unlimited sender flooding four control slots.
            if (acknowledged < delivered_.load()) {
                std::this_thread::yield();
                continue;
            }

            // Exclusively takes the published receive buffer; first packet is Hello, later packets use distinct Ping IDs.
            if (auto* packet = reading_.exchange(nullptr)) {
                if (delivered_ == 0) {
                    packet->mutable_hello()->CopyFrom(greeting);
                } else {
                    packet->mutable_ping()->set_request_id(delivered_ + 1);
                }
                readDone(true);
                ++delivered_;
            }

            // Yields while idle so the control loop can submit reads or writes.
            std::this_thread::yield();
        }
    }

    /// Fixture-specific start hook counts or does nothing, without actual RPC creation.
    void beginCall() override {}

    /// Borrows packet receive storage for delivery; must not overwrite an in-flight buffer.
    void beginRead(proto::astra::v1::SessionPacket* packet) override {
        CHECK(packet->ByteSizeLong() == 0);
        CHECK(reading_.exchange(packet) == nullptr);
    }

    /// Records a write for manual or worker completion without synchronously calling Session back.
    void beginWrite(const proto::astra::v1::SessionPacket*) override {
        CHECK(!writing_.exchange(true));
    }

    /// Receives cancellation requests; controlled fixture counts force, while concurrent fixture owns no actual cancelable network.
    void requestCancel(bool) override {}

    /// Records or ignores simulated transport finish without modeling external gRPC lifetime.
    void finishCall(Status::Code) override {}

    /// Atomic handoff of the sole read-buffer pointer; null means no newly submitted read.
    std::atomic<proto::astra::v1::SessionPacket*> reading_{};
    /// True from write submission to worker confirmation; initially false.
    std::atomic_bool writing_{};
    /// Cross-thread read-completion count, initially zero; Hello first, then nonzero Ping sequences.
    std::atomic_uint delivered_{};
    /// Declared last so worker stops and joins before derived members or Session are destroyed.
    std::jthread worker_;
};

} // namespace

/// Reports exceptions as nonzero process failure; assertions remain active under NDEBUG.
int main() {

    try {
        // Public test identity; loading failure asserts without reading deployment credentials.
        auto identity = Identity::load(std::filesystem::path(ASTRA_FIXTURES) / "star-a", *Endpoint::parse("127.0.0.1:7443"));
        CHECK(identity);
        // Reusable valid signed Hello outlives every Session in this scenario.
        const auto greeting = hello(**identity);
        // Short heartbeat/Pong budgets with explicit test-controlled advancement time.
        Config config;
        config.heartbeatInterval = Milliseconds(20);
        config.pongTimeout = Milliseconds(50);
        // Shared monotonic origin; explicit offsets check exact deadline boundaries.
        const auto now = Steady::now();
        Recorder policy;
        // Borrows policy, identity, now, and greeting to perform consistent handshake setup for each independent Session.
        const auto start = [&](Manual& session) {
            session.pump(policy, **identity, now);
            CHECK(session.writes == 0);
            session.acknowledgeMetadata();
            // Owned Hello packet moved into receive storage.
            proto::astra::v1::SessionPacket packet;
            packet.mutable_hello()->CopyFrom(*greeting);
            session.deliver(std::move(packet));
            session.pump(policy, **identity, now);
            CHECK(session.installed());
            CHECK(session.lastWrite.has_hello());
            session.acknowledge();
        };
        {
            Manual session(config, Policy::Direction::Inbound, {1}, greeting, std::nullopt, [] {});
            session.cancel(Status::Code::Timeout);
            session.cancel(Status::Code::Identity);
            CHECK(session.error() == Status::Code::Timeout);
            session.pump(policy, **identity, now);
            CHECK(session.done() && session.calls == 0 && session.reads == 0 && session.writes == 0 && session.finishes == 1);
            session.cancel();
            CHECK(session.error() == Status::Code::Timeout);
        }
        {
            Manual session(config, Policy::Direction::Inbound, {2}, greeting, std::nullopt, [] {});
            start(session);
            session.pump(policy, **identity, now + Milliseconds(20));
            CHECK(session.lastWrite.has_ping());
            // Sent Ping ID for constructing mismatched or matching-but-late Pong replies.
            const auto id = session.lastWrite.ping().request_id();
            session.acknowledge();
            session.deliver(ping(id + 1, true));
            session.pump(policy, **identity, now + Milliseconds(60));
            CHECK(!session.done());
            // Matching Pong exactly at the original deadline still times out; stale replies cannot extend it.
            session.deliver(ping(id, true));
            session.pump(policy, **identity, now + Milliseconds(70));
            CHECK(session.done() && session.error() == Status::Code::Timeout);
        }
        {
            Manual session(config, Policy::Direction::Inbound, {3}, greeting, std::nullopt, [] {});
            start(session);
            // Keep reading during stalled writes; overload must fail explicitly rather than hiding Pong by stopping reads.
            for (std::uint64_t id = 1; id <= 6; ++id) {
                session.deliver(ping(id));
                session.pump(policy, **identity, now + Milliseconds(1));
            }
            CHECK(session.error() == Status::Code::Capacity && !session.done());
            // Write count captured at overload; cancellation must stop further queued sends.
            const auto writes = session.writes;
            session.acknowledge();
            session.pump(policy, **identity, now + Milliseconds(2));
            CHECK(session.done() && session.writes == writes && session.finishes == 1);
        }
        {
            Manual session(config, Policy::Direction::Inbound, {4}, greeting, std::nullopt, [] {});
            start(session);
            session.deliver(ping(1));
            session.pump(policy, **identity, now + Milliseconds(1));
            session.pump(policy, **identity, now + Milliseconds(51));
            CHECK(session.error() == Status::Code::Timeout);
            session.pump(policy, **identity, Steady::now() + Milliseconds(300));
            CHECK(session.forced == 1);
            session.acknowledge();
            session.pump(policy, **identity, Steady::now() + Milliseconds(301));
            CHECK(session.done());
        }
        {
            // A later queued Pong retains its shorter deadline during stalled headers, independent of Hello's deadline.
            Manual session(config, Policy::Direction::Inbound, {5}, greeting, std::nullopt, [] {});
            session.pump(policy, **identity, now);
            // Owned Hello packet moved into receive storage.
            proto::astra::v1::SessionPacket packet;
            packet.mutable_hello()->CopyFrom(*greeting);
            session.deliver(std::move(packet));
            session.pump(policy, **identity, now);
            session.deliver(ping(1));
            session.pump(policy, **identity, now + Milliseconds(1));
            session.pump(policy, **identity, now + Milliseconds(51));
            CHECK(session.error() == Status::Code::Timeout && session.writes == 0);
            session.acknowledgeMetadata();
            session.pump(policy, **identity, now + Milliseconds(52));
            CHECK(session.done());
        }
        {
            // Do not send Hello before dialing completes; deadline expiry still starts and drains the bound client call.
            Manual session(config, Policy::Direction::Outbound, {6}, greeting, std::nullopt, [] {});
            session.ready = false;
            session.pump(policy, **identity, now);
            CHECK(session.calls == 0 && session.writes == 0);
            session.pump(policy, **identity, Steady::now() + config.connectTimeout);
            CHECK(session.done() && session.error() == Status::Code::Timeout && session.calls == 1 && session.writes == 0);
        }
        CHECK(policy.installations == 4);
        {
            // After first-packet consumption, rearm before preparing sends; a second packet arriving during preparation waits for the next round.
            Manual session(config, Policy::Direction::Inbound, {9}, greeting, std::nullopt, [] {});
            start(session);
            auto data = std::make_unique<Preparation>(); // Session takes sole ownership of this test collaborator.
            auto* preparing = data.get();                // Borrows within Session lifetime for handoff-count checks only.
            data->action = [&] {
                CHECK(session.receiving);
                proto::astra::v1::SessionPacket next; // Models a newly arrived frame; callback performs no business processing.
                next.mutable_repair()->set_trigger(2);
                session.deliver(std::move(next));
            };
            session.bind(std::move(data));
            proto::astra::v1::SessionPacket packet; // This pump round consumes the first frame.
            packet.mutable_repair()->set_trigger(1);
            session.deliver(std::move(packet));
            const auto reads = session.reads; // Previous count; at most one new read slot per round.
            session.pump(policy, **identity, now);
            CHECK(preparing->received == 1 && preparing->preparations == 1 && preparing->taken == 1);
            CHECK(session.reads == reads + 1 && !session.receiving);
            preparing->action = {}; // Next round consumes only the ready second frame; in-flight write prevents another preparation.
            session.pump(policy, **identity, now);
            CHECK(preparing->received == 2 && preparing->preparations == 1 && session.receiving);
            CHECK(session.reads == reads + 2 && !session.error());
            session.cancel();
            session.eof();
            session.acknowledge();
            session.pump(policy, **identity, now);
            CHECK(session.done() && preparing->taken == 1);
        }
        {
            // Business rejection forbids prefetch and preparation/handoff of a new send candidate.
            Manual session(config, Policy::Direction::Inbound, {10}, greeting, std::nullopt, [] {});
            start(session);
            auto data = std::make_unique<Preparation>(); // Injects an explicit protocol error.
            auto* preparing = data.get();                // Borrows the collaborator still owned by Session only.
            data->rejected = true;
            session.bind(std::move(data));
            proto::astra::v1::SessionPacket packet; // Valid transport frame rejected by the business collaborator.
            packet.mutable_repair()->set_trigger(1);
            session.deliver(std::move(packet));
            const auto reads = session.reads; // Submitted-read count before rejection; must remain unchanged afterward.
            session.pump(policy, **identity, now);
            CHECK(session.done() && session.error() == Status::Code::Protocol && session.reads == reads);
            CHECK(!session.receiving && preparing->preparations == 0 && preparing->taken == 0);
        }
        {
            // Read failure during prepare rejects final candidate handoff; next round closes without overwriting EOF.
            Manual session(config, Policy::Direction::Inbound, {11}, greeting, std::nullopt, [] {});
            start(session);
            auto data = std::make_unique<Preparation>(); // Owned by Session until destruction after closure.
            auto* preparing = data.get();                // Observes whether EOF prevents candidate handoff.
            data->action = [&] { session.eof(); };       // Publishes asynchronous read failure during encoding outside the lock.
            session.bind(std::move(data));
            proto::astra::v1::SessionPacket packet; // Current complete message; EOF belongs to the next read.
            packet.mutable_repair()->set_trigger(1);
            session.deliver(std::move(packet));
            session.pump(policy, **identity, now);
            CHECK(!session.receiving && preparing->received == 1 && preparing->taken == 0);
            session.pump(policy, **identity, now);
            CHECK(session.done() && session.error() == Status::Code::Transport && preparing->preparations == 1);
        }
        {
            // Send-preparation exceptions may leave a new read in flight; drain closure without duplicate Finish or candidate handoff.
            Manual session(config, Policy::Direction::Inbound, {12}, greeting, std::nullopt, [] {});
            start(session);
            session.finishImmediately = false;
            auto data = std::make_unique<Preparation>(); // Injects allocation failure during send preparation.
            auto* preparing = data.get();                // Observes post-exception candidate count without extending collaborator lifetime.
            data->action = [&] { CHECK(session.receiving); throw std::bad_alloc(); };
            session.bind(std::move(data));
            proto::astra::v1::SessionPacket packet; // Successful packet processing precedes the injected send-preparation exception.
            packet.mutable_repair()->set_trigger(1);
            session.deliver(std::move(packet));
            session.pump(policy, **identity, now);
            CHECK(session.error() == Status::Code::Capacity && session.receiving && session.finishes == 1);
            CHECK(preparing->taken == 0);
            const auto reads = session.reads; // Already canceling; later read failure cannot rearm.
            session.eof();
            session.pump(policy, **identity, now);
            CHECK(!session.done() && session.finishes == 1 && session.reads == reads);
            session.complete();
            CHECK(session.done());
        }
        {
            // Finish submission is not OnDone; pending reads or stalled final status still require bounded forced cancellation.
            Manual session(config, Policy::Direction::Inbound, {7}, greeting, std::nullopt, [] {});
            session.finishImmediately = false;
            session.cancel();
            session.pump(policy, **identity, Steady::now());
            CHECK(session.finishes == 1 && !session.done());
            session.pump(policy, **identity, Steady::now() + Milliseconds(300));
            CHECK(session.forced == 1 && session.finishes == 1);
            session.complete();
            CHECK(session.done());
        }
        {
            Concurrent session(config, greeting);
            session.pump(policy, **identity, now);
            session.ready();
            // Ten-second hang-prevention budget; actual delivered count remains the completion criterion.
            const auto deadline = Steady::now() + std::chrono::seconds(10);
            while (session.delivered() < 50000 && Steady::now() < deadline) {
                session.pump(policy, **identity, now);
                // On concurrent baseline failure, logs first close reason and delivered count to distinguish protocol failure from throughput timeout.
                if (const auto error = session.error()) {
                    throw std::runtime_error("Concurrent session error=" + std::to_string(static_cast<unsigned>(*error)) + ", delivered=" + std::to_string(session.delivered()));
                }
                std::this_thread::yield();
            }
            CHECK(session.delivered() >= 50000);
        }
        std::cout << "PASS cancellation, deadlines, bounded queue, receive/send overlap and concurrent handoff\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
