// Verify public Beacon publication, renewal, and cancellation behavior.
#include "check.hpp"
#include "core.hpp"
#include "ephemeris_service.hpp"
#include "identity.hpp"
#include <comet/client.hpp>

#include <grpcpp/server_builder.h>

#include <atomic>
#include <condition_variable>
#include <future>
#include <iostream>
#include <source_location>
#include <thread>

namespace {
using namespace std::chrono_literals;
using astra::Ephemeris;

/// Injects lost or delayed receipts after actual native commits, retaining production server rules.
class Faults final : public proto::comet::v1::Ephemeris::CallbackService {
public:
    /// Next Create commits, then returns an uncertain timeout exactly once.
    std::atomic_bool loseCreate{};
    /// Delay initial registration receipt after commit to cover factory deadline and cancellation.
    std::atomic_bool holdCreate{};
    /// Actual Create count; closure must not retry initial registration implicitly.
    std::atomic_uint creates{};
    /// Next Data commits, then returns an uncertain timeout exactly once.
    std::atomic_bool loseUpdate{};
    /// Next Renew commits, then returns an uncertain timeout exactly once.
    std::atomic_bool loseRenew{};
    /// Delay only the response; handlers never wait for network or test conditions.
    std::atomic_bool holdUpdate{};
    /// Actual received Update count, including retries with fixed order.
    std::atomic_uint updates{};
    /// Actual received Renew count; SDK ready state is not success evidence.
    std::atomic_uint renewals{};
    /// Unexpected native-commit or identity failures are asserted explicitly on the test thread.
    std::atomic_bool valid{true};
    /// Data request has acquired an actual in-flight RPC.
    std::atomic_bool held{};
    /// Real source, projection, and timing wheel.
    Ephemeris::State& state;
    /// Same login and Ready entry as the public service.
    astra::Gateway& gateway;
    /// Injects business time only; SDK lease time remains unchanged.
    std::atomic<std::int64_t>& time;
    /// Operations without injected faults use production handlers directly.
    Ephemeris::Service service;

    Faults(Ephemeris::State& state, astra::Gateway& gateway, std::atomic<std::int64_t>& time) : state(state), gateway(gateway), time(time), service(state, gateway) {} /// Construction starts no threads.

    /// Cleanup can always finish the delayed default unary reactor; no pointer survives Server::Wait.
    void release() {
        const std::lock_guard lock(mutex_);
        if (pending_) {
            std::exchange(pending_, nullptr)->Finish(grpc::Status::OK);
        }
    }

    grpc::ServerUnaryReactor* Create(grpc::CallbackServerContext* context, const proto::comet::v1::CreateRequest* request, proto::comet::v1::CreateReply* reply) override {

        ++creates;
        const bool lost = loseCreate.exchange(false);
        const bool delayed = holdCreate.exchange(false);
        if (!lost && !delayed) {
            return service.Create(context, request, reply);
        }
        auto permit = gateway.enter(*context);
        const astra::Scope scope{request->scope().sector(), request->scope().spectrum()};
        auto attr = bytes(request->attr());
        const auto capability = Ephemeris::capability(); // Fault fixture commits current capabilities and generations too, without legacy registration fallback.
        const auto id = Ephemeris::identity(scope, attr, request->ttl_ms(), capability);
        if (!permit || request->generation() != 1 || !request->uuid().empty()) {
            valid.store(false);
            return finish(context, grpc::Status(grpc::StatusCode::INTERNAL, "Unexpected Create injection"));
        }
        auto result = state.create(scope, std::move(attr), bytes(request->data()), request->ttl_ms(), id, 1, 0, capability);
        if (!result) {
            valid.store(false);
            return finish(context, grpc::Status(grpc::StatusCode::INTERNAL, "Create injection failed"));
        }
        if (lost) {
            return finish(context, grpc::Status(grpc::StatusCode::DEADLINE_EXCEEDED, "Injected loss after Create commit")); // Attach no unapplied detail.
        }
        reply->set_instance(gateway.instance());
        reply->set_uuid(result->uuid);
        reply->set_capability(capability);
        reply->set_generation(result->generation);
        reply->set_order(result->order);
        reply->set_ttl_ms(result->ttl);
        reply->set_data(result->data->data(), result->data->size());
        const std::lock_guard lock(mutex_);
        pending_ = context->DefaultReactor();
        held = true;
        return pending_;
    }

    grpc::ServerUnaryReactor* Update(grpc::CallbackServerContext* context, const proto::comet::v1::UpdateRequest* request, proto::comet::v1::UpdateReply* reply) override {
        ++updates;
        const bool lost = loseUpdate.exchange(false); // Consume each fault once; subsequent real retries succeed.
        const bool delayed = holdUpdate.exchange(false);
        if (!lost && !delayed) {
            return service.Update(context, request, reply);
        }
        auto permit = gateway.enter(*context);
        auto result = state.update({request->scope().sector(), request->scope().spectrum()}, request->uuid(), bytes(request->data()), request->order(), request->generation(), request->capability());
        if (!permit || !result) {
            valid.store(false);
        }
        if (lost) {
            return finish(context, grpc::Status(grpc::StatusCode::DEADLINE_EXCEEDED, "Injected loss after Data commit"));
        }
        reply->set_order(request->order());
        const std::lock_guard lock(mutex_);
        pending_ = context->DefaultReactor(); // gRPC retains request and response until Finish; this test does not access them meanwhile.
        held.store(true);
        return pending_;
    }

    grpc::ServerUnaryReactor* Renew(grpc::CallbackServerContext* context, const proto::comet::v1::RenewRequest* request, proto::comet::v1::RenewReply* reply) override {
        ++renewals;
        auto permit = gateway.enter(*context);
        auto result = state.renew({request->scope().sector(), request->scope().spectrum()}, request->uuid(), request->order(), request->generation(), request->capability());
        if (!permit || !result) {
            valid.store(false);
        }
        const bool lost = loseRenew.exchange(false);
        if (lost) {
            time.fetch_add(100'000'000); // Advance business time by 100 ms while registration remains valid.
            return finish(context, grpc::Status(grpc::StatusCode::DEADLINE_EXCEEDED, "Injected loss after Renew commit"));
        }
        reply->set_order(request->order());
        return finish(context, grpc::Status::OK);
    }

    grpc::ServerUnaryReactor* Remove(grpc::CallbackServerContext* context, const proto::comet::v1::RemoveRequest* request, proto::comet::v1::Empty* reply) override {
        return service.Remove(context, request, reply);
    } // Removal still uses all production validation.

    grpc::ServerWriteReactor<proto::comet::v1::EphemerisWatchReply>* Watch(grpc::CallbackServerContext* context, const proto::comet::v1::WatchRequest* request) override {
        return service.Watch(context, request);
    } // Downstream contains no fabricated content.

private:
    static Ephemeris::Value bytes(const std::string& value) {
        return std::make_shared<const Ephemeris::Buffer>(value.begin(), value.end());
    } // Retains actual immutable payloads in the test.

    static grpc::ServerUnaryReactor* finish(grpc::CallbackServerContext* context, const grpc::Status& status) {
        auto* reactor = context->DefaultReactor();
        reactor->Finish(status);
        return reactor;
    } // gRPC releases the default reactor.

    /// Protects fault records and delayed completion pointers only.
    std::mutex mutex_;
    /// Sole delayed response; release clears it to prevent duplicate Finish.
    grpc::ServerUnaryReactor* pending_{};
};

/// Own an isolated gateway, fault service, and client with an explicitly controlled clock.
class Fixture {
public:
    /// Explicitly controlled, nonadvancing clock input for actual State.
    std::atomic<std::int64_t> time{1'000'000'000};
    /// Anonymous public configuration also uses the production Gateway.
    astra::Access access;
    /// Injects transport outcomes only; separate real cases cover admission.
    astra::Gateway gateway{access, "star-fault", false};
    /// Use the fixture-controlled nanosecond clock for the real Ephemeris state under test.
    Ephemeris::State state{[this] { return std::optional(astra::Clock::Reading{.time = astra::Clock::Time(std::chrono::nanoseconds(time.load())), .ready = true}); }, {}};
    /// Combines actual state and production handlers.
    Faults faults{state, gateway, time};
    /// Await actual cleanup after final closure before destroying the server.
    comet::Client client;

    Fixture() {
        auto credentials = astra::Identity::external(std::filesystem::path(ASTRA_FIXTURES) / "star-a");
        CHECK(credentials);
        grpc::ServerBuilder builder;
        int port{}; // Independent port, without touching deployed services.
        builder.AddListeningPort("127.0.0.1:0", *credentials, &port);
        builder.RegisterService(&gateway);
        builder.RegisterService(&faults);
        server_ = builder.BuildAndStart();
        CHECK(server_ && port > 0);
        endpoint_ = "127.0.0.1:" + std::to_string(port);
        try {
            worker_ = std::jthread([this](std::stop_token stop) {
                while (!stop.stop_requested()) {
                    faults.service.pump(std::chrono::steady_clock::now());
                    std::unique_lock lock(mutex_);
                    changed_.wait_for(lock, stop, 2ms, [] { return false; });
                }
            });
            gateway.ready();
            auto opened = comet::Client::open(options());
            CHECK(opened);
            client = std::move(*opened);
        } catch (...) {
            stop();
            throw;
        }
    }

    ~Fixture() {
        stop();
    } // Also handles assertion failure without leaving requests that hold raw reactor pointers.

    /// Return isolated connection inputs for public and deliberately unstarted private clients.
    comet::Client::Options options() const {
        comet::Client::Options result;
        result.auth = false;
        result.endpoints = {endpoint_};
        result.ca = std::filesystem::path(ASTRA_FIXTURES) / "star-a" / "ca.pem";
        result.timeout = 500ms;
        return result;
    }

private:
    void stop() {
        faults.release();
        client.close();
        if (!client.wait(5s)) {
            std::terminate();
        }
        gateway.stop();
        faults.service.stop();
        server_->Shutdown(std::chrono::system_clock::now() + 2s);
        server_->Wait();
        if (worker_.joinable()) {
            worker_.request_stop();
            changed_.notify_all();
            worker_.join();
        }
        faults.service.pump(std::chrono::steady_clock::now(), 65536);
    }

    /// Kernel-assigned address, valid only while this fixture owns the server.
    std::string endpoint_;
    /// Dedicated control-loop wait lock.
    std::mutex mutex_;
    /// Stop wakes the loop immediately.
    std::condition_variable_any changed_;
    /// Close while workers can still drain callbacks.
    std::unique_ptr<grpc::Server> server_;
    /// One test control thread per service, not per registration.
    std::jthread worker_;
};

/// Wait for observable facts for at most five seconds each; fixed long sleeps are not success evidence.
void eventually(auto&& condition, const std::source_location& caller = std::source_location::current()) {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!condition()) {
        if (std::chrono::steady_clock::now() >= deadline) {
            std::cerr << "BEACON-WAIT " << caller.file_name() << ':' << caller.line() << '\n';
        }
        CHECK(std::chrono::steady_clock::now() < deadline);
        std::this_thread::sleep_for(1ms);
    }
}

void lost() {

    Fixture fixture;
    fixture.faults.loseCreate.store(true);
    auto rejected = fixture.client.beacon({"service", "main"}, {1}, {2}, 1s, 100ms);
    CHECK(!rejected && rejected.error().effect == comet::Error::Effect::Unknown);
    CHECK(fixture.state.source().size() == 1); // An orphan with a lost initial receipt expires by TTL only; SDK does not retry the initial Create.
    auto beacon = fixture.client.beacon({"service", "main"}, {1}, {2}, 1s, 100ms);
    CHECK(beacon && fixture.state.source().size() == 2);
    fixture.faults.loseUpdate.store(true);
    const auto result = beacon->update(std::vector<std::uint8_t>{3});
    CHECK(!result && result.error().code == comet::Error::Code::Timeout && result.error().effect == comet::Error::Effect::Unknown);
    const auto before = fixture.faults.renewals.load();
    eventually([&] { return fixture.faults.renewals.load() >= before + 2; });
    CHECK(fixture.faults.updates.load() == 1); // Maintenance has advanced without replaying failed Data.
    std::uint64_t order{};
    const auto identity = *beacon->state().identity;
    fixture.state.source().each([&](const astra::Scope&, std::string_view uuid, const Ephemeris::Record& record) { if (uuid == identity.uuid) { order = record.update; CHECK(*record.data == Ephemeris::Buffer{3}); } });
    CHECK(order == 1);
    fixture.faults.loseRenew.store(true);
    const auto previous = fixture.faults.renewals.load();
    eventually([&] { return fixture.faults.renewals.load() >= previous + 2; });
    CHECK(fixture.faults.valid.load());
}

void independent() {

    Fixture fixture;
    auto beacon = fixture.client.beacon({"service", "main"}, {}, {}, 1s, 100ms);
    CHECK(beacon);
    eventually([&] { return beacon->state().phase == comet::Beacon::Phase::Ready; });
    fixture.faults.holdUpdate.store(true);
    auto update = std::async(std::launch::async, [&] { return beacon->update(std::vector<std::uint8_t>{4}); });

    /// Release the delayed reactor before asynchronous result destruction can wait on it.
    struct Release {
        /// Return the reactor before future destruction waits, even on assertion failure.
        Faults& faults;

        ~Release() {
            faults.release();
        }
    } release{fixture.faults};

    eventually([&] { return fixture.faults.held.load(); });
    const auto before = fixture.faults.renewals.load();
    eventually([&] { return fixture.faults.renewals.load() > before; });
    CHECK(update.wait_for(0ms) == std::future_status::timeout); // Actual Renew still arrives while Data remains unfinished.
    fixture.faults.release();
    CHECK(update.wait_for(3s) == std::future_status::ready && update.get());
    CHECK(fixture.faults.valid.load());
}

/// Delay business sampling to verify manual updates invalidate late results while real Renew continues.
void sampling() {

    /// Coordinate entry, release, and completion of one deliberately blocked sampling callback.
    struct Gate {
        /// Explicitly releases the first executing sample.
        std::promise<void> exit;
        /// Share the callback-exit gate with every waiter without consuming the underlying promise.
        std::shared_future<void> ready = exit.get_future().share();
        /// Worker entered user code.
        std::atomic_bool entered{};
        /// User code observed the release signal.
        std::atomic_bool left{};
        /// Block the first sample only; later samples throw without committing content.
        std::atomic_uint calls{};
    };

    auto gate = std::make_shared<Gate>(); // Callback retains itself without raw stack references on assertion failure.
    Fixture fixture;
    auto beacon = fixture.client.beacon({"service", "main"}, {}, {1}, 1s, 100ms);
    CHECK(beacon);

    /// Release a blocked sampler before SDK teardown, including assertion failures.
    struct Release {
        /// Unblock before SDK cleanup waits on exceptional exits.
        std::shared_ptr<Gate> gate;

        ~Release() {
            if (gate) {
                gate->exit.set_value();
            }
        }
    } release{gate};

    CHECK(beacon->tick(1ms, [gate]() -> comet::Value {
        if (gate->calls.fetch_add(1) == 0) {
            gate->entered = true;
            gate->ready.wait();
            gate->left = true;
            return std::make_shared<const std::vector<std::uint8_t>>(1, 2);
        }
        throw std::runtime_error("Sampling failed");
    }));
    eventually([&] { return gate->entered.load(); });
    const auto previous = fixture.faults.renewals.load();
    CHECK(beacon->update(std::vector<std::uint8_t>{3}));
    eventually([&] { return fixture.faults.renewals.load() > previous; });
    gate->exit.set_value();
    release.gate.reset();
    eventually([&] { return gate->left.load() && gate->calls.load() >= 2 && fixture.client.exceptions() > 0; });
    CHECK(beacon->tick(1s, {})); // Only the manual update invalidates the first late value; enable later work afterward.
    beacon->destroy();
    CHECK(beacon->wait(3s) && fixture.faults.updates.load() == 1);
    CHECK(!beacon->tick(1ms, [] { return comet::Value{}; }));
}

/// Synchronous Update completes while a notification blocks in user code; results do not await observer return.
void notification() {

    auto gate = std::make_shared<std::promise<void>>();
    auto ready = gate->get_future().share();
    std::atomic_bool entered{}; // Flag outlives Fixture destruction and callback draining.
    Fixture fixture;
    auto beacon = fixture.client.beacon({"service", "main"}, {}, {}, 1s, 100ms);
    CHECK(beacon);

    /// Signal callback completion before subsequent owners wait during exceptional cleanup.
    struct Release {
        /// Retain the promise released by guard teardown so blocked test callbacks can finish.
        std::shared_ptr<std::promise<void>> gate;

        ~Release() {
            gate->set_value();
        } // Release any started callback regardless of assertion outcome.
    } release{gate};

    CHECK(beacon->changed([ready, &entered](comet::Beacon::State) { entered = true; ready.wait(); }));
    eventually([&] { return entered.load(); });
    CHECK(beacon->update(std::vector<std::uint8_t>{7}, 500ms));
    CHECK(beacon->changed({})); // Replacing an executing callback must not destroy its storage.
}

/// Committed calls with delayed receipts expire or cancel; SDK neither caches nor retries unknown results, and close drains actual callbacks.
void cancellation() {

    for (const bool cancel : {false, true}) { // Use independent fixtures without reusing closed objects or error state.
        Fixture fixture;
        auto beacon = fixture.client.beacon({"service", "cancel"}, {}, {1}, 1s, 100ms);
        CHECK(beacon);
        fixture.faults.holdUpdate = true;
        auto update = std::async(std::launch::async, [&] { return beacon->update(std::vector<std::uint8_t>{2}, cancel ? 3s : 200ms); });

        /// Release a delayed acknowledgment before the request future and service fixture are destroyed.
        struct Release {
            /// Failure paths also finish delayed receipts before future or Fixture waits.
            Faults& faults;

            ~Release() {
                faults.release();
            }
        } release{fixture.faults};

        eventually([&] { return fixture.faults.held.load(); });
        if (cancel) {
            beacon->destroy();
        }
        CHECK(update.wait_for(2s) == std::future_status::ready);
        const auto result = update.get();
        CHECK(!result && result.error().code == (cancel ? comet::Error::Code::Closed : comet::Error::Code::Timeout));
        CHECK(result.error().effect == comet::Error::Effect::Unknown);
        fixture.faults.release();
        beacon->destroy();
        CHECK(beacon->wait(3s) && fixture.faults.updates.load() == 1);
    }
}

/// Notification removes itself and capture destruction reenters the handle; cleanup must release business captures outside internal locks.
void captures() {

    std::atomic_uint released{}, forbidden{}; // Constructed before Fixture and destroyed after all callbacks.
    Fixture fixture;
    auto opened = fixture.client.beacon({"service", "captures"}, {}, {}, 1s, 100ms);
    CHECK(opened);
    auto beacon = std::make_shared<comet::Beacon>(std::move(*opened));

    /// Retain a Beacon during callback capture and observe safe reentry when that capture is released.
    struct Capture {
        /// Executing callback retains the handle.
        std::shared_ptr<comet::Beacon> owner;
        /// Borrow the counter proving callback-capture destruction actually completed.
        std::atomic_uint& released;
        /// Borrow the counter recording forbidden operations attempted during capture destruction.
        std::atomic_uint& forbidden;

        ~Capture() {
            static_cast<void>(owner->state());
            try {
                static_cast<void>(owner->wait(0ms));
            } catch (const std::logic_error&) {
                ++forbidden;
            }
            ++released;
        }
    };

    CHECK(beacon->changed([capture = std::make_shared<Capture>(beacon, released, forbidden)](comet::Beacon::State) {
        CHECK(capture->owner->changed({}));
    }));
    eventually([&] { return released.load() == 1; });
    for (const bool fails : {false, true}) {
        CHECK(beacon->tick(1ms, [capture = std::make_shared<Capture>(beacon, released, forbidden), fails]() -> comet::Value {
            CHECK(capture->owner->tick(1s, {})); // Remove itself before either return or throw.
            if (fails) {
                throw std::runtime_error("Sampling failure");
            }
            return {}; // A replaced sample sends no payload.
        }));
        eventually([&] { return released.load() == (fails ? 3U : 2U); });
    }
    beacon->destroy();
    CHECK(beacon->wait(3s) && forbidden.load() == 3 && fixture.client.exceptions() == 1);
}

/// A connection that cannot advance must exhaust the factory deadline without submitting or retrying.
void pending() {

    Fixture fixture;
    auto prepared = comet::detail::Core::prepare(fixture.options());
    CHECK(prepared);
    const auto core = *prepared; // Withhold start to make the pre-connection schedule deterministic.

    /// Start and drain the deliberately unstarted Core before dependent activities disappear.
    struct Stop {
        /// Outlive every unstarted activity and drain its final control turn.
        std::shared_ptr<comet::detail::Core> core;

        ~Stop() {
            core->start();
            core->close();
            if (!core->wait(3s)) {
                std::terminate();
            }
        }
    } stop{core};

    comet::Beacon::Options options;
    options.timeout = 200ms;
    const auto deadline = std::chrono::steady_clock::now() + options.timeout;
    const auto value = std::make_shared<const std::vector<std::uint8_t>>();
    const auto result = core->beacon({"service", "pending"}, value, value, 1s, 100ms, std::move(options), deadline);
    CHECK(!result && result.error().code == comet::Error::Code::Timeout);
    CHECK(result.error().effect == comet::Error::Effect::Unapplied);
    CHECK(std::chrono::steady_clock::now() >= deadline);
    CHECK(fixture.faults.creates.load() == 0 && !fixture.faults.held.load());
}

/// After connection setup, timeout or close must cancel an already committed first registration.
void initial() {

    for (const bool cancel : {false, true}) {
        Fixture fixture;
        // Client::open is asynchronous. Establish the same unary channel before the post-commit fault.
        auto warm = fixture.client.beacon({"service", "warm"}, {}, {}, 1s, 100ms);
        CHECK(warm);
        warm->destroy();
        CHECK(warm->wait(3s));
        const auto creates = fixture.faults.creates.load();
        CHECK(creates == 1);
        fixture.faults.holdCreate = true;
        auto create = std::async(std::launch::async, [&] {
            comet::Beacon::Options options;
            options.timeout = cancel ? 3s : 200ms;
            return fixture.client.beacon({"service", "initial"}, {}, {1}, 1s, 100ms, std::move(options));
        });

        /// Release the reactor on every exit before awaiting the outstanding update.
        struct Release {
            /// Finish the reactor before awaiting future, including exceptional paths.
            Faults& faults;

            ~Release() {
                faults.release();
            }
        } release{fixture.faults};

        eventually([&] {
            if (!fixture.faults.held.load() && create.wait_for(0ms) == std::future_status::ready) {
                const auto result = create.get();
                std::cerr << "BEACON-EARLY creates=" << fixture.faults.creates.load() << " valid=" << fixture.faults.valid.load() << " success=" << result.has_value();
                if (!result) {
                    std::cerr << " code=" << static_cast<int>(result.error().code) << " effect=" << static_cast<int>(result.error().effect);
                }
                std::cerr << '\n';
                CHECK(false); // The post-commit fault was not installed; preserve the actual earlier result.
            }
            return fixture.faults.held.load();
        });
        if (cancel) {
            fixture.client.close();
        }
        CHECK(create.wait_for(2s) == std::future_status::ready);
        const auto result = create.get();
        CHECK(!result && result.error().code == (cancel ? comet::Error::Code::Closed : comet::Error::Code::Timeout));
        CHECK(result.error().effect == comet::Error::Effect::Unknown);
        fixture.faults.release();
        fixture.client.close();
        CHECK(fixture.client.wait(3s) && fixture.faults.creates.load() == creates + 1 && fixture.faults.valid.load());
    }
}

} // namespace

int main() {
    try {
        std::cerr << "BEACON-CASE pending\n";
        pending();
        std::cerr << "BEACON-CASE initial\n";
        initial();
        std::cerr << "BEACON-CASE captures\n";
        captures();
        std::cerr << "BEACON-CASE cancellation\n";
        cancellation();
        std::cerr << "BEACON-CASE sampling\n";
        sampling();
        std::cerr << "BEACON-CASE notification\n";
        notification();
        std::cerr << "BEACON-CASE lost\n";
        lost();
        std::cerr << "BEACON-CASE independent\n";
        independent();
        std::cout << "Beacon RPC fault cases passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
