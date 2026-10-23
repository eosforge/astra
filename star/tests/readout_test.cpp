// Verify public Almanac read delivery and consistent snapshot boundaries.
#include "check.hpp"
#include "identity.hpp"
#include "readout.hpp"

#include <grpcpp/create_channel.h>
#include <grpcpp/server_builder.h>

#include <condition_variable>
#include <iostream>
#include <memory>
#include <string_view>
#include <thread>

namespace {
using astra::Almanac;
using astra::Readout;

/// Private loopback TLS fixture; pausing its control thread creates deterministic commits during paging.
class Fixture {
public:
    /// Protects pump scheduling only; Library commits still notify independently while paused.
    std::mutex control;
    /// Condition-variable mutex, without holding control while waiting.
    std::mutex sleep;
    /// Callbacks/new commits wake one shared control thread.
    std::condition_variable_any changed;
    /// Bounded native routing; stop writes after borrowed Readout destruction.
    astra::Library library;
    /// Real login core outlives every Watch.
    astra::Access access;
    /// Fixed actual fixture instance; anonymous mode still forbids __.
    astra::Gateway gateway;
    /// Real CallbackService without per-subscription threads.
    Readout readout;
    /// Listener owned only by this fixture.
    std::unique_ptr<grpc::Server> server;
    /// Public fixture CA verifies the server certificate.
    std::shared_ptr<grpc::Channel> channel;
    /// Independent RPC context per Watch.
    std::unique_ptr<proto::comet::v1::Almanac::Stub> stub;
    /// One service worker, stopped/joined only after network draining.
    std::jthread worker;

    /// History zero tests active snapshot suffixes independently of retention; explicit limits exercise slow-stream/capacity boundaries.
    explicit Fixture(bool auth = false, std::size_t history = 1000, Readout::Limits limits = {}) : library([history] { astra::Library::Limits value; value.scope.history = history; return value; }(), [this](const astra::Scope& scope, const Almanac::Change& change) noexcept { readout.changed(scope, change); }), gateway(access, "star-test", auth), readout(library, gateway, [this] { changed.notify_all(); }, limits) {

        const auto identity = astra::Identity::load(std::filesystem::path(ASTRA_FIXTURES) / "star-a", *astra::Endpoint::parse("127.0.0.1:7443"));
        CHECK(identity);
        grpc::ServerBuilder builder; // Public listener registers only Gateway/Almanac.
        builder.RegisterService(&gateway);
        builder.RegisterService(&readout);
        builder.SetMaxSendMessageSize(8 * 1024 * 1024);
        builder.SetMaxReceiveMessageSize(8 * 1024 * 1024);
        int port{};
        builder.AddListeningPort("127.0.0.1:0", (*identity)->serverCredentials(), &port);
        server = builder.BuildAndStart();
        CHECK(server && port > 0);
        try {
            channel = grpc::CreateChannel("127.0.0.1:" + std::to_string(port), (*identity)->channelCredentials());
            stub = proto::comet::v1::Almanac::NewStub(channel);
            gateway.ready();
            worker = std::jthread([this](std::stop_token stop) {
                while (!stop.stop_requested()) {
                    {
                        const std::lock_guard lock(control);
                        readout.pump(std::chrono::steady_clock::now());
                    }
                    std::unique_lock lock(sleep);
                    changed.wait_for(lock, stop, std::chrono::milliseconds(2), [] { return false; });
                }
            });
        } catch (...) {
            server->Shutdown();
            server->Wait();
            throw;
        }
    }

    /// Clients clean up first; exceptions still cancel Server while the shared loop reclaims OnDone.
    ~Fixture() {
        gateway.stop();
        readout.stop();
        server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(3));
        server->Wait();
        worker.request_stop();
        changed.notify_all();
        worker.join();
        readout.pump(std::chrono::steady_clock::now(), 65536);
    }

    /// Deterministic complete authority baseline; small values make count the main paging limit.
    void fill(std::uint64_t version = 1, unsigned count = 1) {
        auto draft = library.prepare({"routes", "main"}, version);
        CHECK(draft);
        for (unsigned index = 0; index < count; ++index) {
            CHECK(draft->set("key-" + std::to_string(index), {static_cast<std::uint8_t>(index % 251)}));
        }
        CHECK(library.reset(std::move(*draft)));
    }
};

/// Unique client RPC owner; partial snapshots/assertion failure still cancel/Finish without leaking server resources.
class Watching {
public:
    /// Stable context address/lifetime, never reused across streams.
    grpc::ClientContext context;
    /// One final Finish before destruction.
    std::unique_ptr<grpc::ClientReader<proto::comet::v1::AlmanacWatchReply>> stream;

    /// Version has presence. Default instance matches; send it only with a version.
    Watching(Fixture& fixture, std::string target = {}, std::optional<std::uint64_t> version = {}, std::string instance = "star-test", std::string sector = "routes", std::string token = {}) {

        context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(8));
        if (!token.empty()) {
            context.AddMetadata("comet-session-bin", std::move(token));
        }
        proto::comet::v1::WatchRequest request;
        request.mutable_scope()->set_sector(std::move(sector));
        request.mutable_scope()->set_spectrum("main");
        request.set_target(std::move(target));
        if (version) {
            request.set_version(*version);
            request.set_instance(std::move(instance));
        }
        stream = fixture.stub->Watch(&context, request);
    }

    /// Cancel only this RPC, preserving shared Channel and other subscriptions.
    ~Watching() {
        if (stream) {
            context.TryCancel();
            static_cast<void>(stream->Finish());
        }
    }

    /// Reads one page; EOF is not a valid empty complete batch.
    proto::comet::v1::AlmanacWatchReply page() {
        proto::comet::v1::AlmanacWatchReply reply;
        CHECK(stream->Read(&reply));
        CHECK(reply.complete() == reply.has_version());
        CHECK(reply.complete() == !reply.instance().empty());
        return reply;
    }

    /// Reads one complete small-result batch, optionally continuing after an already consumed first page.
    proto::comet::v1::AlmanacWatchReply complete() {
        for (unsigned page = 0; page < 1000; ++page) {
            auto reply = this->page();
            if (reply.complete()) {
                return reply;
            }
        }
        throw std::runtime_error("Watch did not finish a bounded batch");
    }

    /// Expected rejection/cancellation must reach EOF, then one Finish yields its real final status.
    grpc::Status rejected() {
        proto::comet::v1::AlmanacWatchReply reply;
        CHECK(!stream->Read(&reply));
        const auto status = stream->Finish();
        stream.reset();
        CHECK(!status.ok());
        std::cerr << "READOUT-REJECT code=" << status.error_code() << '\n'; // Preserve the actual rejection without logging metadata or credentials.
        return status;
    }
};

/// Bounded waiting synchronizes fixture callbacks only, without adding production polling.
void eventually(auto&& condition) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!condition()) {
        CHECK(std::chrono::steady_clock::now() < deadline);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

/// Absent Scope/exact target still has complete zero/current position; emptiness cannot imply unready.
void baselines() {

    Fixture fixture;
    {
        Watching absent(fixture);
        const auto page = absent.complete();
        CHECK(page.version() == 0 && page.changes().empty() && page.mode() == proto::comet::v1::MODE_RESET);
    }
    fixture.fill();
    Watching exact(fixture, "missing");
    CHECK(exact.complete().changes().empty());
    CHECK(fixture.library.apply({"routes", "main"}, 2, "other", Almanac::Buffer{}));
    const auto unrelated = exact.complete();
    CHECK(unrelated.mode() == proto::comet::v1::MODE_APPLY && unrelated.version() == 2 && unrelated.changes().empty());
    CHECK(fixture.library.apply({"routes", "main"}, 3, "missing", Almanac::Buffer{}));
    const auto created = exact.complete();
    CHECK(created.version() == 3 && created.changes_size() == 1 && created.changes(0).action_case() == proto::comet::v1::AlmanacChange::kValue && created.changes(0).value().empty());
    CHECK(fixture.library.apply({"routes", "main"}, 4, "missing", std::nullopt));
    const auto erased = exact.complete();
    CHECK(erased.version() == 4 && erased.changes_size() == 1 && erased.changes(0).action_case() == proto::comet::v1::AlmanacChange::kErase);
}

/// Collect bodies only for exact hits; unrelated subscribers still receive empty apply progress.
void fanout() {

    Fixture fixture;
    fixture.fill();
    std::vector<std::unique_ptr<Watching>> watches;
    for (unsigned index = 0; index < 8; ++index) {
        watches.push_back(std::make_unique<Watching>(fixture, "probe-" + std::to_string(index)));
    }
    auto hit = std::make_unique<Watching>(fixture, "wanted");
    for (const auto& watch : watches) {
        CHECK(watch->complete().changes().empty());
    }
    CHECK(hit->complete().changes().empty());
    const auto before = fixture.readout.delivery();
    CHECK(fixture.library.apply({"routes", "main"}, 2, "wanted", Almanac::Buffer{1}));
    const auto after = fixture.readout.delivery();
    CHECK(after.scans == before.scans + 1 && after.matched == before.matched + 1); // Visit one matching stream; pump advances eight unrelated subscriptions outside the commit lock.
    const auto matched = hit->complete();                                          // Counters alone cannot prove success; receive real business pages too.
    CHECK(matched.mode() == proto::comet::v1::MODE_APPLY && matched.version() == 2 && matched.changes_size() == 1 && matched.changes(0).key() == "wanted");
    for (const auto& watch : watches) {
        const auto empty = watch->complete();
        CHECK(empty.mode() == proto::comet::v1::MODE_APPLY && empty.version() == 2 && empty.changes().empty());
    }
}

/// Apply requires same instance/complete history; Almanac authoritative minimum never regresses across instances.
void recovery() {

    Fixture fixture;
    fixture.fill();
    CHECK(fixture.library.apply({"routes", "main"}, 2, "key-0", Almanac::Buffer{7}));
    {
        Watching resumed(fixture, {}, 1);
        const auto page = resumed.complete();
        CHECK(page.mode() == proto::comet::v1::MODE_APPLY && page.version() == 2 && page.changes_size() == 1);
    }
    {
        Watching moved(fixture, {}, 1, "another-star");
        CHECK(moved.complete().mode() == proto::comet::v1::MODE_RESET);
    }
    {
        Watching caught(fixture, {}, 2);
        const auto page = caught.complete();
        CHECK(page.mode() == proto::comet::v1::MODE_APPLY && page.changes().empty());
    }
    {
        Watching ahead(fixture, {}, 3, "another-star");
        CHECK(ahead.rejected().error_code() == grpc::StatusCode::UNAVAILABLE);
    }
    Fixture forgotten(false, 0);
    forgotten.fill();
    CHECK(forgotten.library.apply({"routes", "main"}, 2, "key-0", Almanac::Buffer{8}));
    Watching reset(forgotten, {}, 1);
    CHECK(reset.complete().mode() == proto::comet::v1::MODE_RESET);
}

/// After the first page, pause pump, discard ordinary history, and overwrite one key repeatedly. Active suffix must remain complete with final actions.
void suffix() {

    Fixture fixture(false, 0);
    fixture.fill(1, 600);
    std::unique_lock pause(fixture.control); // Pause sends only; gRPC write callbacks still run.
    Watching watch(fixture);
    eventually([&] { return !fixture.readout.empty(); });
    fixture.readout.pump(std::chrono::steady_clock::now(), 1);
    const auto first = watch.page();
    CHECK(!first.complete() && first.mode() == proto::comet::v1::MODE_RESET);
    for (std::uint64_t version = 2; version <= 101; ++version) {
        CHECK(fixture.library.apply({"routes", "main"}, version, "key-0", Almanac::Buffer{static_cast<std::uint8_t>(version)}));
    }
    CHECK(fixture.library.apply({"routes", "main"}, 102, "key-1", std::nullopt));
    CHECK(fixture.library.apply({"routes", "main"}, 103, "added", Almanac::Buffer{}));
    pause.unlock();
    CHECK(watch.complete().version() == 1);
    const auto delta = watch.complete();
    CHECK(delta.mode() == proto::comet::v1::MODE_APPLY && delta.version() == 103 && delta.changes_size() == 3);
    std::map<std::string, const proto::comet::v1::AlmanacChange*> changes;
    for (const auto& change : delta.changes()) {
        CHECK(changes.emplace(change.key(), &change).second);
    }
    CHECK(changes.at("key-0")->value() == std::string(1, static_cast<char>(101)));
    CHECK(changes.at("key-1")->action_case() == proto::comet::v1::AlmanacChange::kErase);
    CHECK(changes.at("added")->action_case() == proto::comet::v1::AlmanacChange::kValue && changes.at("added")->value().empty());
}

/// Single-lookup insertion/replacement preserves final actions and exact budgets without overwriting neighboring keys.
void coalescing() {

    Fixture fixture(false, 0); // Zero history forces pending active suffix ownership.
    fixture.fill();
    Watching watch(fixture);
    CHECK(watch.complete().version() == 1);
    {
        const std::lock_guard pause(fixture.control);
        std::uint64_t version = 1;
        for (const auto key : {"b", "d", "a", "c", "e"}) {
            CHECK(fixture.library.apply({"routes", "main"}, ++version, key, Almanac::Buffer(10, 1)));
        }
        CHECK(fixture.library.apply({"routes", "main"}, ++version, "c", Almanac::Buffer(20, 2)));
        CHECK(fixture.library.apply({"routes", "main"}, ++version, "b", std::nullopt));
        CHECK(fixture.library.apply({"routes", "main"}, ++version, "a", Almanac::Buffer{}));
    }

    const auto delta = watch.complete(); // Five final actions distinguish deletion from empty bodies.
    CHECK(delta.mode() == proto::comet::v1::MODE_APPLY && delta.version() == 9 && delta.changes_size() == 5);
    CHECK(delta.changes(0).key() == "a" && delta.changes(0).has_value() && delta.changes(0).value().empty());
    CHECK(delta.changes(1).key() == "b" && delta.changes(1).has_erase());
    CHECK(delta.changes(2).key() == "c" && delta.changes(2).value() == std::string(20, '\2'));
    CHECK(delta.changes(3).key() == "d" && delta.changes(3).value() == std::string(10, '\1'));
    CHECK(delta.changes(4).key() == "e" && delta.changes(4).value() == std::string(10, '\1'));
}

// A baseline exceeding the whole-stream budget must report overload before any page is sent.
void budget() {

    Readout::Limits limits;
    limits.bytes = limits.pending = 4096;
    Fixture fixture(false, 0, limits);
    auto draft = fixture.library.prepare({"routes", "main"}, 1); // A new scope needs a complete authority baseline before it accepts deltas.
    CHECK(draft);
    CHECK(draft->set("large", Almanac::Buffer(8192, 1)));
    CHECK(fixture.library.reset(std::move(*draft)));
    Watching watch(fixture);
    CHECK(watch.rejected().error_code() == grpc::StatusCode::RESOURCE_EXHAUSTED);
    eventually([&] { return fixture.readout.empty(); });
    const auto book = fixture.library.find({"routes", "main"});
    CHECK(book && book->usage().version == 1); // Rejection releases the stream without changing authoritative data.
}

/// New baseline replacement cannot enter old apply; budget overflow cannot produce false complete.
void discontinuity() {

    Fixture fixture;
    fixture.fill();
    Watching watch(fixture);
    CHECK(watch.complete().version() == 1);
    fixture.fill(10);
    CHECK(watch.rejected().error_code() == grpc::StatusCode::OUT_OF_RANGE);

    {
        Fixture broken; // Missing upstream notification version remains a gap even when the exact target does not match.
        broken.fill();
        Watching exact(broken, "missing");
        CHECK(exact.complete().version() == 1);
        {
            const std::lock_guard pause(broken.control); // Collect both notifications before sending, independently of thread timing.
            const auto key = std::make_shared<const std::string>("unrelated");
            broken.readout.changed({"routes", "main"}, {.key = key, .value = {}, .version = 2});
            broken.readout.changed({"routes", "main"}, {.key = key, .value = {}, .version = 4});
        }
        CHECK(exact.rejected().error_code() == grpc::StatusCode::OUT_OF_RANGE);
    }

    Readout::Limits limits; // Small compaction budget deterministically triggers resource failure.
    limits.pending = 4096;
    Fixture limited(false, 0, limits);
    limited.fill();
    Watching slow(limited);
    CHECK(slow.complete().version() == 1);
    CHECK(limited.library.apply({"routes", "main"}, 2, "large", Almanac::Buffer(4096, 1)));
    CHECK(slow.rejected().error_code() == grpc::StatusCode::RESOURCE_EXHAUSTED);
}

/// Anonymous mode still denies internal data; invalid recovery/oversized targets fail before preparation.
void boundaries() {

    Fixture fixture;
    {
        Watching internal(fixture, {}, {}, {}, "__auth");
        CHECK(internal.rejected().error_code() == grpc::StatusCode::INVALID_ARGUMENT);
    }
    {
        Watching invalid(fixture, {}, 0, "");
        CHECK(invalid.rejected().error_code() == grpc::StatusCode::INVALID_ARGUMENT);
    }
    {
        Watching large(fixture, std::string(1025, 'k'));
        CHECK(large.rejected().error_code() == grpc::StatusCode::INVALID_ARGUMENT);
    }
    Readout::Limits limits;
    limits.streams = 1;
    Fixture one(false, 1000, limits);
    {
        Watching first(one);
        CHECK(first.complete().version() == 0);
        Watching second(one);
        CHECK(second.rejected().error_code() == grpc::StatusCode::RESOURCE_EXHAUSTED);
    }
    eventually([&] { return one.readout.empty(); });
    for (unsigned turn = 0; turn < 40; ++turn) {
        {
            Watching next(one);
            CHECK(next.complete().version() == 0);
        }
        eventually([&] { return one.readout.empty(); });
    }
}

/// Idle Watch follows Session revocation immediately, without later writes or periodic scans.
void revocation() {

    Fixture fixture(true);
    astra::Access::Draft draft;
    CHECK(draft.set("application", {1, 2, 3}));
    CHECK(fixture.access.reset(std::move(draft), [] { return std::expected<bool, Almanac::Error>(true); }));
    const Almanac::Buffer secret{1, 2, 3};
    auto session = fixture.access.open("application", secret);
    CHECK(session);
    Watching watch(fixture, {}, {}, {}, "routes", std::string((*session)->token()));
    CHECK(watch.complete().version() == 0);
    fixture.access.close(*session);
    static_cast<void>(watch.rejected());
    eventually([&] { return fixture.readout.empty(); });
}
} // namespace

/// Failure diagnostics contain assertions only, without credentials or deployment material.
int main(int argc, char* argv[]) {
    try {
        if (argc > 1) {
            CHECK(argc == 2 && std::string_view(argv[1]) == "budget");
            budget();
            std::cout << "Almanac readout budget test passed\n";
            return 0;
        }
        budget();
        baselines();
        fanout();
        recovery();
        suffix();
        coalescing();
        discontinuity();
        boundaries();
        revocation();
        std::cout << "Almanac readout tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
