// Standalone SDK synchronous-publish contract tests using existing gRPC dependencies, without linking C++26 Star.
#include "check.hpp"
#include "comet.grpc.pb.h"
#include "publishing.hpp"
#include <comet/client.hpp>

#include <grpcpp/server_builder.h>

#include <atomic>
#include <future>
#include <iostream>
#include <latch>
#include <limits>
#include <map>
#include <mutex>
#include <thread>

namespace {
using namespace std::chrono_literals;

/// Models version races and lost confirmations; actual Star atomic-commit acceptance remains a separate Linux check.
class Catalog final : public proto::comet::v1::Catalog::CallbackService {
public:
    /// Query request count; initially zero.
    std::atomic_uint queries{};
    /// Commit request count; initially zero.
    std::atomic_uint writes{};
    /// Number of explicit version conflicts to inject.
    std::atomic_uint conflicts{};
    /// Next commit applies but loses confirmation.
    std::atomic_bool lost{};
    /// Next Query omits entries to exercise protocol rejection.
    std::atomic_bool malformed{};
    /// Next Query models a legacy service without Query support.
    std::atomic_bool unsupported{};
    /// Next Query is delayed to exercise the total deadline.
    std::atomic_bool slowQuery{};
    /// Next commit is delayed to exercise concurrency and cancellation.
    std::atomic_bool slowWrite{};
    /// Delayed commit entered the server; explicit synchronization point.
    std::atomic_bool entered{};
    /// Next commit pauses at a fixed server boundary until the fixture releases it.
    std::atomic_bool paused{};
    /// SDK must not call Renew.
    std::atomic_uint renewals{};

    /// Fixed instance and per-Key watermarks in request order; unknown Keys return zero.
    grpc::ServerUnaryReactor* Query(grpc::CallbackServerContext* context, const proto::comet::v1::CatalogQueryRequest* request, proto::comet::v1::CatalogQueryReply* reply) override {
        ++queries;
        if (unsupported.exchange(false)) {
            return finish(*context, {grpc::StatusCode::UNIMPLEMENTED, "Query unavailable"});
        }
        if (slowQuery.exchange(false)) {
            std::this_thread::sleep_for(200ms);
        }
        reply->set_instance("publisher-test");
        if (!malformed.exchange(false)) {
            const std::lock_guard lock(mutex_);
            for (const auto& key : request->keys()) {
                auto* row = reply->add_entries(); // Each requested Key has an independent watermark.
                row->set_key(key);
                row->set_version(versions_[key]);
            }
        }
        return finish(*context, grpc::Status::OK);
    }

    /// One RPC synchronously replaces the batch watermarks; faults occur at explicit precommit or preconfirmation boundaries.
    grpc::ServerUnaryReactor* Publish(grpc::CallbackServerContext* context, const proto::comet::v1::PublishRequest* request, proto::comet::v1::PublishReply* reply) override {

        ++writes;
        if (paused.exchange(false)) {
            entered.store(true);
            released_.wait(); // Case-local gate; Fixture destruction releases it too, without fixed sleeps.
        }
        if (slowWrite.exchange(false)) {
            entered.store(true);
            std::this_thread::sleep_for(200ms);
        }
        const std::lock_guard lock(mutex_);
        if (conflicts.load() != 0) {
            --conflicts;
            for (const auto& entry : request->entries()) {
                versions_[entry.key()] = request->version() + 10;
            }
            proto::comet::v1::Failure failure; // Explicitly proves the whole batch uncommitted, permitting the SDK's single repair.
            failure.set_reason(proto::comet::v1::REASON_VERSION);
            failure.set_effect(proto::comet::v1::EFFECT_UNAPPLIED);
            context->AddTrailingMetadata("comet-error-bin", failure.SerializeAsString());
            return finish(*context, {grpc::StatusCode::FAILED_PRECONDITION, "Version conflict"});
        }
        for (const auto& entry : request->entries()) {
            versions_[entry.key()] = request->version();
        }
        if (lost.exchange(false)) {
            return finish(*context, {grpc::StatusCode::DEADLINE_EXCEEDED, "Confirmation lost"});
        }
        reply->set_instance("publisher-test");
        reply->set_version(request->version());
        return finish(*context, grpc::Status::OK);
    }

    /// Counts Renew only; automatic renewal makes the contract test fail.
    grpc::ServerUnaryReactor* Renew(grpc::CallbackServerContext* context, const proto::comet::v1::CatalogRenewRequest*, proto::comet::v1::Empty*) override {
        ++renewals;
        return finish(*context, grpc::Status::OK);
    }

    /// Injects the process's saved version upper bound without a public SDK version argument.
    void version(std::string key, std::uint64_t version) {
        const std::lock_guard lock(mutex_);
        versions_[std::move(key)] = version;
    }

    void resume() {
        if (!resumed_.exchange(true)) {
            released_.count_down();
        }
    } // Idempotently releases one pause; normal completion and exceptional cleanup may both call it.

private:
    /// Initially blocked; at most one deterministic pause per Fixture.
    std::latch released_{1};
    /// Prevents repeated cleanup from counting down below zero.
    std::atomic_bool resumed_{};

    /// gRPC owns the default reactor entirely; request and reply are not borrowed after return.
    static grpc::ServerUnaryReactor* finish(grpc::CallbackServerContext& context, grpc::Status status) {
        auto* reactor = context.DefaultReactor(); // Server cleans up after actual RPC completion.
        reactor->Finish(std::move(status));
        return reactor;
    }

    /// Protects only fixture watermarks, without modeling client locks.
    std::mutex mutex_;
    /// Initially empty; independent Keys may share a version.
    std::map<std::string, std::uint64_t> versions_;
};

/// Own a loopback Catalog and its Client with fixture-scoped startup and shutdown.
class Fixture {
public:
    /// Controlled service on an independent loopback port.
    Catalog catalog;
    /// Test roles share this Client.
    comet::Client client;

    /// Uses no existing deployment, certificate download, or new dependency.
    Fixture() {
        grpc::ServerBuilder builder;
        int port{}; // Kernel-allocated port, isolated from parallel cases.
        builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
        builder.RegisterService(&catalog);
        server_ = builder.BuildAndStart();
        CHECK(server_ && port > 0);
        comet::Client::Options options; // Only this isolated loopback fixture explicitly disables TLS and login.
        options.auth = false;
        options.tls = false;
        endpoint_ = "127.0.0.1:" + std::to_string(port);
        options.endpoints = {endpoint_};
        auto opened = comet::Client::open(std::move(options));
        CHECK(opened);
        client = std::move(*opened);
    }

    /// Cancel and drain client calls before stopping Server; no background thread may access the test stack afterward.
    ~Fixture() {
        catalog.resume(); // Even if the case fails, the server cannot wait indefinitely for test signals.
        if (control_) {
            control_->close();
            if (!control_->wait(3s)) {
                std::terminate();
            }
        }
        client.close();
        if (!client.wait(3s)) {
            std::terminate();
        }
        server_->Shutdown(std::chrono::system_clock::now() + 3s);
        server_->Wait();
    }

    /// Scheduling-race cases alone access the existing private core; public SDK API remains unchanged.
    std::shared_ptr<comet::detail::Core> control() {
        comet::Client::Options options; // Same isolated loopback service as the public Client, with an independent lifecycle.
        options.auth = false;
        options.tls = false;
        options.endpoints = {endpoint_};
        auto prepared = comet::detail::Core::prepare(std::move(options));
        CHECK(prepared);
        control_ = *prepared;
        control_->start();
        return control_;
    }

private:
    /// Kernel-allocated isolated loopback port lets focused cases reuse the controlled service.
    std::string endpoint_;
    /// Started only for scheduling races; fixture closes explicitly.
    std::shared_ptr<comet::detail::Core> control_;
    /// Destroy the service after all callbacks finish.
    std::unique_ptr<grpc::Server> server_;
};

/// Internal versions cover known watermarks, unknown commits, and new-object initialization, without background publication or renewal.
void versions() {

    Fixture fixture;
    auto publisher = fixture.client.publisher({"service", "main"});
    CHECK(publisher);
    const auto value = std::make_shared<const std::vector<std::uint8_t>>(1, 7); // Two Keys share a complete immutable payload.
    const auto first = publisher->update({{"a", value}, {"b", value}}, 1s);
    CHECK(first && first->version == 1);
    fixture.catalog.conflicts.store(1);
    const auto repaired = publisher->update("a", {8}, 1s);
    CHECK(repaired && repaired->version == 13);
    fixture.catalog.lost.store(true);
    const auto lost = publisher->update("a", {9}, 1s);
    CHECK(!lost && lost.error().effect == comet::Error::Effect::Unknown);
    const auto writes = fixture.catalog.writes.load(); // Capture actual request count when the error returns.
    std::this_thread::sleep_for(450ms);                // Bounded negative window exceeds the former TTL/3 recovery period.
    CHECK(fixture.catalog.writes.load() == writes && fixture.catalog.renewals.load() == 0);
    auto restarted = fixture.client.publisher({"service", "main"});
    CHECK(restarted);
    const auto next = restarted->update("a", {}, 2s);
    CHECK(next && next->version == 15);
}

/// Invalid protocol, version overflow, and repeated conflicts cause no endless repair or extra business calls.
void failures() {

    Fixture fixture;
    auto publisher = fixture.client.publisher({"service", "main"});
    CHECK(publisher);
    fixture.catalog.unsupported.store(true);
    const auto unsupported = publisher->update("a", {1}, 1s); // Legacy services without Query must not become retryable transport errors.
    CHECK(!unsupported && unsupported.error().code == comet::Error::Code::Protocol && unsupported.error().effect == comet::Error::Effect::Unapplied);
    CHECK(fixture.catalog.writes.load() == 0);
    fixture.catalog.malformed.store(true);
    const auto malformed = publisher->update("a", {1}, 1s);
    CHECK(!malformed && malformed.error().code == comet::Error::Code::Protocol && fixture.catalog.writes.load() == 0);
    fixture.catalog.version("a", std::numeric_limits<std::uint64_t>::max());
    const auto exhausted = publisher->update("a", {1}, 1s);
    CHECK(!exhausted && exhausted.error().code == comet::Error::Code::Limit && fixture.catalog.writes.load() == 0);
    fixture.catalog.conflicts.store(2);
    const auto conflict = publisher->update("b", {1}, 1s);
    CHECK(!conflict && conflict.error().code == comet::Error::Code::Version && conflict.error().effect == comet::Error::Effect::Unapplied);
    CHECK(fixture.catalog.writes.load() == 2);

    // Continuous local writes also check UINT64_MAX; cached baselines must not bypass Query's overflow protection.
    auto final = fixture.client.publisher({"final", "main"});
    fixture.catalog.version("final", std::numeric_limits<std::uint64_t>::max() - 1);
    CHECK(final);
    const auto last = final->update("final", {}, 1s);
    CHECK(last && last->version == std::numeric_limits<std::uint64_t>::max());
    const auto queries = fixture.catalog.queries.load(); // A valid baseline exists; reject this attempt locally.
    const auto overflow = final->update("final", {}, 1s);
    CHECK(!overflow && overflow.error().code == comet::Error::Code::Limit);
    CHECK(fixture.catalog.queries.load() == queries && fixture.catalog.writes.load() == 3);
}

/// Query consumes the call deadline; concurrent same-object calls return busy, and close cancels waits without closing Client.
void cancellation() {

    Fixture fixture;
    auto publisher = fixture.client.publisher({"service", "main"});
    CHECK(publisher);
    CHECK(publisher->update("ready", {}, 1s));         // First confirm anonymous connection readiness so the short deadline covers actual Query work.
    const auto before = fixture.catalog.writes.load(); // Read-only Query timeout must not increase business commits.
    fixture.catalog.slowQuery.store(true);
    const auto timeout = publisher->update("a", {1}, 1s, 30ms);
    CHECK(!timeout && timeout.error().code == comet::Error::Code::Timeout && timeout.error().effect == comet::Error::Effect::Unapplied);
    CHECK(fixture.catalog.writes.load() == before);
    fixture.catalog.slowWrite.store(true);
    auto pending = std::async(std::launch::async, [&] { return publisher->update("a", {2}, 1s); }); // Concurrency is created explicitly by the test.
    const auto deadline = std::chrono::steady_clock::now() + 3s;                                    // Observe actual server RPC entry instead of relying on timing races.
    while (!fixture.catalog.entered.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(1ms);
    }
    CHECK(fixture.catalog.entered.load());
    const auto busy = publisher->update("b", {3}, 1s);
    CHECK(!busy && busy.error().code == comet::Error::Code::Busy);
    publisher->close();
    const auto cancelled = pending.get();
    CHECK(!cancelled && cancelled.error().effect == comet::Error::Effect::Unknown && publisher->wait(3s));
    auto other = fixture.client.publisher({"service", "other"});
    CHECK(other); // Closing a child leaves the shared Client open; cancellation need not prove remote noncommit.
}

/// Reordering the same Key set initializes once; a changed set or unknown confirmation requires another Query.
void baseline() {

    Fixture fixture;
    auto publisher = fixture.client.publisher({"baseline", "main"});
    CHECK(publisher);
    auto value = std::make_shared<const std::vector<std::uint8_t>>(1, 3);  // Fixed immutable test payload.
    const std::weak_ptr<const std::vector<std::uint8_t>> released = value; // SDK retains no business payload after return.
    const auto first = publisher->update({{"a", value}, {"b", value}}, 1s);
    const auto second = publisher->update({{"b", value}, {"a", value}}, 2s);
    CHECK(first && first->version == 1 && second && second->version == 2);
    value.reset();
    CHECK(released.expired());
    CHECK(fixture.catalog.queries.load() == 1 && fixture.catalog.writes.load() == 2);
    const auto changed = publisher->update("c", {}, 1s); // Changing the Key set reinitializes while preserving this object's allocated high watermark.
    CHECK(changed && changed->version == 3);
    CHECK(fixture.catalog.queries.load() == 2);
    fixture.catalog.lost.store(true);
    CHECK(!publisher->update("c", {1}, 1s));
    CHECK(fixture.catalog.queries.load() == 2);
    const auto recovered = publisher->update("c", {2}, 1s); // Query again after an unknown outcome; never reuse an unconfirmed baseline.
    CHECK(recovered && recovered->version == 5);
    CHECK(fixture.catalog.queries.load() == 3);
    CHECK(!publisher->wait(std::chrono::milliseconds::min())); // Tiny timeouts check immediately without overflowing clock conversion.
    publisher->close();
    CHECK(publisher->wait(std::chrono::milliseconds::max())); // Huge timeouts still respect the completion predicate and cannot wrap to negative deadlines.
}

/// Inject an earlier empty control-round snapshot; a new call must still finish using the current valid binding.
void scheduling() {

    Fixture fixture;
    const auto core = fixture.control(); // Fixture closes the extra core on exceptional exit.
    core->start();                       // Repeated start cannot create overlapping control rounds on one Alarm.
    auto publisher = core->publisher({"schedule", "main"});
    CHECK(publisher);
    const auto body = std::make_shared<const std::vector<std::uint8_t>>(1, 1);
    fixture.catalog.paused.store(true);
    auto pending = std::async(std::launch::async, [&] { return (*publisher)->update({{"key", body}}, 1s, 3s); });
    const auto deadline = std::chrono::steady_clock::now() + 3s; // Wait for actual RPC entry at the pause boundary instead of guessing connection readiness.
    while (!fixture.catalog.entered.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(1ms);
    }
    CHECK(fixture.catalog.entered.load());
    (*publisher)->poll({}, {}, {}, false); // Old round's empty snapshot does not imply the current Core is unbound.
    fixture.catalog.resume();
    CHECK(pending.get());
    (*publisher)->close();
    CHECK((*publisher)->wait(3s));
}

/// User callback occupies the sole control round; Client::close must directly cancel another thread's synchronous Publish.
void shutdown() {

    Fixture fixture;
    auto publisher = fixture.client.publisher({"shutdown", "main"});
    CHECK(publisher && publisher->update("key", {}, 1s));
    fixture.catalog.paused.store(true);
    auto pending = std::async(std::launch::async, [&] { return publisher->update("key", {2}, 1s); });
    const auto deadline = std::chrono::steady_clock::now() + 3s; // First ensure an actual Publish is pending.
    while (!fixture.catalog.entered.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(1ms);
    }
    CHECK(fixture.catalog.entered.load());

    // promise is destroyed before Fixture so failed assertions unblock wait; callback borrows no test-stack objects.
    const auto entered = std::make_shared<std::promise<void>>();
    auto notified = entered->get_future();
    std::promise<void> release;
    comet::Subscriber::Options options;
    options.changed = [entered, released = release.get_future().share()](comet::Subscriber::View) {
        entered->set_value();
        released.wait();
    };
    auto subscriber = fixture.client.subscriber({"shutdown", "main"}, {}, std::move(options));
    CHECK(subscriber && notified.wait_for(3s) == std::future_status::ready);
    fixture.client.close();
    const auto stopped = pending.wait_for(500ms); // Shorter than the original three-second RPC deadline while callback still occupies the control round.
    release.set_value();
    CHECK(stopped == std::future_status::ready);
    const auto result = pending.get();
    CHECK(!result && result.error().code == comet::Error::Code::Closed && result.error().effect == comet::Error::Effect::Unknown);
}

} // namespace

/// Runs publication versions, renewal scheduling, failure, and cancellation cases.
int main() {
    try {
        versions();
        baseline();
        scheduling();
        shutdown();
        failures();
        cancellation();
        std::cout << "Synchronous Catalog publisher cases passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
