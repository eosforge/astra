// Verify Catalog's public TLS RPC boundaries, atomic refusals, and complete Watch batches.
#include "catalog_service.hpp"
#include "check.hpp"
#include "identity.hpp"

#include <grpcpp/create_channel.h>
#include <grpcpp/server_builder.h>

#include <array>
#include <atomic>
#include <chrono>
#include <concepts>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <expected>
#include <filesystem>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace {
using namespace std::chrono_literals;
using astra::Catalog;
using astra::Clock;

/// Own one real public server and a manually advanced business clock.
class Fixture {
public:
    /// Inject only the owned clock callback; transport threads retain normal allocation behavior.
    enum class Failure {
        /// Return the configured business reading.
        None,
        /// Throw before a native state operation can prepare its mutation.
        Allocation,
        /// Propagate an unexpected callback failure to the public exception boundary.
        Exception
    };

    /// Select a deterministic unary failure while the background pump is paused.
    std::atomic<Failure> failure{Failure::None};
    /// Serialize pump calls with deterministic fixture pauses.
    std::mutex control;
    /// Protect the cancellable pump wait, independently of business locks.
    std::mutex sleep;
    /// Wake the pump immediately on shutdown.
    std::condition_variable_any changed;
    /// Business time in Unix nanoseconds; advancing it never sleeps.
    std::atomic<std::int64_t> now{1'000'000'000};
    /// Model loss of local clock qualification.
    std::atomic_bool ready{true};
    /// Use the production credential and permit lifecycle.
    astra::Access access;
    /// Supply a stable, observable process instance.
    astra::Gateway gateway{access, "star-test"};
    /// Keep native source, projection, history, and deadlines under test.
    Catalog::State state;
    /// Serve the real generated Catalog interface.
    Catalog::Service service;
    /// Hold the authenticated fixture identity until drain.
    std::shared_ptr<astra::Access::Session> session;
    /// Own the independently allocated listening endpoint.
    std::unique_ptr<grpc::Server> server;
    /// Retain transport ownership until the server finishes.
    std::shared_ptr<grpc::Channel> channel;
    /// Invoke production handlers through TLS and generated messages.
    std::unique_ptr<proto::comet::v1::Catalog::Stub> stub;
    /// Drive all Watch streams with one joined worker.
    std::jthread worker;
    /// Record completed teardown so explicit stop and destruction share one owner.
    bool stopped{};

    /// Install public fixture credentials; never read deployment secrets.
    explicit Fixture(Catalog::State::Limits limits = {}, std::ptrdiff_t maximum = 128) : state([this] {
                                                                                             switch (failure.load()) {
                                                                                             case Failure::Allocation:
                                                                                                 throw std::bad_alloc();
                                                                                             case Failure::Exception:
                                                                                                 throw std::runtime_error("Fixture clock failure");
                                                                                             case Failure::None:
                                                                                                 break;
                                                                                             }
                                                                                             return std::optional(Clock::Reading{.time = Clock::Time(std::chrono::nanoseconds(now.load())), .ready = ready.load(), .synchronized = false});
                                                                                         },
                                                                                               limits),
                                                                                         service(state, gateway, maximum) {

        astra::Access::Draft accounts;
        CHECK(accounts.set("application", {1, 2, 3}));
        CHECK(access.reset(std::move(accounts), [] { return std::expected<bool, astra::Almanac::Error>(true); }));
        const std::array<std::uint8_t, 3> secret{1, 2, 3};
        auto opened = access.open("application", secret);
        CHECK(opened);
        session = std::move(*opened);
        const auto identity = astra::Identity::load(std::filesystem::path(ASTRA_FIXTURES) / "star-a", *astra::Endpoint::parse("127.0.0.1:7443"));
        CHECK(identity);
        grpc::ServerBuilder builder;
        builder.SetMaxReceiveMessageSize(4 * 1024 * 1024);
        builder.RegisterService(&gateway);
        builder.RegisterService(&service);
        int port{}; // An ephemeral port isolates this server from every other test.
        builder.AddListeningPort("127.0.0.1:0", (*identity)->serverCredentials(), &port);
        server = builder.BuildAndStart();
        CHECK(server && port > 0);
        try {
            channel = grpc::CreateChannel("127.0.0.1:" + std::to_string(port), (*identity)->channelCredentials());
            stub = proto::comet::v1::Catalog::NewStub(channel);
            gateway.ready();
            worker = std::jthread([this](std::stop_token stop) {
                while (!stop.stop_requested()) {
                    {
                        const std::lock_guard lock(control);
                        service.pump(std::chrono::steady_clock::now());
                    }
                    std::unique_lock lock(sleep);
                    changed.wait_for(lock, stop, 2ms, [] { return false; });
                }
            });
        } catch (...) {
            server->Shutdown();
            server->Wait();
            throw;
        }
    }

    /// Drain service callbacks before destroying their shared state.
    ~Fixture() {
        stop();
    }

    /// Stop admission, drain native callbacks, join the pump, and retire its final completions.
    void stop() {

        if (stopped) {
            return;
        }
        gateway.stop();
        service.stop();
        access.close(session);
        server->Shutdown(std::chrono::system_clock::now() + 3s);
        server->Wait();
        worker.request_stop();
        changed.notify_all();
        worker.join();
        service.pump(std::chrono::steady_clock::now(), 65536);
        stopped = true;
    }

    /// Give each unary request its own finite transport deadline.
    void prepare(grpc::ClientContext& context, bool token = true) const {
        context.set_deadline(std::chrono::system_clock::now() + 3s);
        if (token) {
            context.AddMetadata("comet-session-bin", std::string(session->token()));
        }
    }

    /// Construct a valid scalar request; initial Publish may omit instance.
    static proto::comet::v1::PublishRequest publish() {
        proto::comet::v1::PublishRequest request;
        request.mutable_scope()->set_sector("service");
        request.mutable_scope()->set_spectrum("main");
        request.set_key("first");
        request.set_value("old");
        request.set_version(7);
        request.set_ttl_ms(1000);
        return request;
    }

    /// Construct a complete two-key update with shared version and TTL.
    static proto::comet::v1::PublishRequest batch() {
        auto request = publish();
        request.clear_key();
        request.clear_value();
        for (const auto* key : {"first", "second"}) {
            auto* entry = request.add_entries();
            entry->set_key(key);
            entry->set_value("old");
        }
        return request;
    }

    /// Renew the established two-key batch against its exact instance.
    static proto::comet::v1::CatalogRenewRequest renew() {
        proto::comet::v1::CatalogRenewRequest request;
        *request.mutable_scope() = publish().scope();
        request.set_instance("star-test");
        request.set_version(7);
        request.set_ttl_ms(2000);
        request.add_keys("first");
        request.add_keys("second");
        return request;
    }

    /// Confirm receipt identity and content version, not merely RPC success.
    void accept(const proto::comet::v1::PublishRequest& request) {
        grpc::ClientContext context;
        prepare(context);
        proto::comet::v1::PublishReply reply;
        CHECK(stub->Publish(&context, request, &reply).ok());
        CHECK(reply.instance() == "star-test" && reply.version() == request.version());
    }

    /// Compare complete source facts, including deadlines and absent bodies.
    using Facts = std::map<std::tuple<std::string, std::string, std::string>, std::tuple<std::uint64_t, std::optional<Catalog::Buffer>, std::optional<Clock::Time>>>;

    /// Materialize immutable captured facts for equality across a rejected RPC.
    static Facts facts(const Catalog::State::Source::View& view) {
        Facts result;
        view.each([&result](const astra::Scope& scope, std::string_view key, const Catalog::Record& record) {
            result.emplace(std::tuple(scope.sector, scope.spectrum, std::string(key)), std::tuple(record.version, record.value ? std::optional(*record.value) : std::nullopt, record.deadline));
        });
        return result;
    }

    /// Compare visible content independently of source storage and lease metadata.
    static auto contents(const Catalog::State::Projection::View& view) {
        std::map<std::string, std::pair<std::uint64_t, Catalog::Buffer>> result;
        view.each([&result](std::string_view key, const Catalog::State::Content& record) {
            CHECK(record.value);
            CHECK(result.emplace(key, std::pair(record.version, *record.value)).second);
        });
        return result;
    }

    /// Decode the actual stable trailing failure without interpreting error text.
    static proto::comet::v1::Failure detail(const grpc::ClientContext& context, proto::comet::v1::Reason reason) {
        const auto found = context.GetServerTrailingMetadata().find("comet-error-bin");
        CHECK(found != context.GetServerTrailingMetadata().end());
        proto::comet::v1::Failure result;
        CHECK(result.ParseFromArray(found->second.data(), static_cast<int>(found->second.size())));
        CHECK(result.reason() == reason && result.effect() == proto::comet::v1::EFFECT_UNAPPLIED && result.instance() == "star-test");
        return result;
    }

    /// Require every definitive refusal to preserve all native facts and its cursor.
    template <typename Request>
    void reject(const Request& request, grpc::StatusCode code, proto::comet::v1::Reason reason, bool bounds = false, bool token = true) {

        const auto projection = state.capture({"service", "main"});
        CHECK(projection.has_value() == ready.load());
        const auto before = state.source();
        const auto contents = facts(before);
        grpc::ClientContext context;
        prepare(context, token);
        grpc::Status status;
        if constexpr (std::same_as<Request, proto::comet::v1::PublishRequest>) {
            proto::comet::v1::PublishReply reply;
            status = stub->Publish(&context, request, &reply);
        } else if constexpr (std::same_as<Request, proto::comet::v1::CatalogRenewRequest>) {
            proto::comet::v1::Empty reply;
            status = stub->Renew(&context, request, &reply);
        } else {
            proto::comet::v1::CatalogQueryReply reply;
            status = stub->Query(&context, request, &reply);
        }
        CHECK(status.error_code() == code);
        const auto detail = Fixture::detail(context, reason);
        CHECK(detail.ttl_min_ms() == (bounds ? 1000 : 0) && detail.ttl_max_ms() == (bounds ? 600000 : 0));

        const auto after = state.source();
        CHECK(after.position() == before.position() && after.size() == before.size() && after.bytes() == before.bytes());
        CHECK(facts(after) == contents && facts(before) == contents);
        if (projection) {
            const auto current = state.capture({"service", "main"});
            CHECK(current && current->version() == projection->version() && current->size() == projection->size());
            CHECK(Fixture::contents(*current) == Fixture::contents(*projection));
        }
    }
};

/// Verify scalar empty values, ordered floor queries, explicit renewal, and expiry.
void lifecycle() {

    Fixture fixture;
    auto request = Fixture::publish();
    request.clear_value(); // Empty bytes are a present value, not a deletion.
    fixture.accept(request);
    auto view = fixture.state.capture({"service", "main"});
    CHECK(view && view->size() == 1 && view->version() == 1);
    view->each([](std::string_view key, const Catalog::State::Content& value) { CHECK(key == "first" && value.version == 7 && value.value && value.value->empty()); });

    auto renewal = Fixture::renew();
    renewal.clear_keys();
    renewal.set_key("first");
    grpc::ClientContext renew;
    fixture.prepare(renew);
    proto::comet::v1::Empty empty;
    CHECK(fixture.stub->Renew(&renew, renewal, &empty).ok());
    fixture.now = 2'000'000'000;
    CHECK(fixture.state.capture({"service", "main"})->size() == 1);
    fixture.now = 3'000'000'000;
    CHECK(fixture.state.capture({"service", "main"})->size() == 0);

    proto::comet::v1::CatalogQueryRequest query;
    *query.mutable_scope() = request.scope();
    query.add_keys("unknown");
    query.add_keys("first");
    grpc::ClientContext context;
    fixture.prepare(context);
    proto::comet::v1::CatalogQueryReply reply;
    CHECK(fixture.stub->Query(&context, query, &reply).ok());
    CHECK(reply.instance() == "star-test" && reply.entries_size() == 2);
    CHECK(reply.entries(0).key() == "unknown" && reply.entries(0).version() == 0);
    CHECK(reply.entries(1).key() == "first" && reply.entries(1).version() == 7);
    fixture.reject(renewal, grpc::StatusCode::NOT_FOUND, proto::comet::v1::REASON_ENDED);
    CHECK(view->size() == 1 && view->version() == 1); // The captured pre-expiry root is immutable.
    std::cout << "ASTRA-CATALOG {\"group\":\"lifecycle\",\"cases\":1}\n";
}

/// Attack each static Publish boundary without changing the other valid fields.
void publishing() {

    Fixture fixture;
    fixture.accept(Fixture::batch());
    for (int index = 0; index < 21; ++index) {
        auto request = Fixture::batch();
        auto code = grpc::StatusCode::INVALID_ARGUMENT;
        auto reason = proto::comet::v1::REASON_INPUT;
        bool bounds = false;
        switch (index) {
        case 0:
            request.set_key("mixed");
            break;
        case 1:
            request.set_value("mixed");
            break;
        case 2:
            for (int key = 2; key < 129; ++key) {
                request.add_entries()->set_key(std::to_string(key));
            }
            break;
        case 3:
            request.set_version(0);
            break;
        case 4:
            request.set_ttl_ms(999);
            bounds = true;
            break;
        case 5:
            request.set_ttl_ms(600001);
            bounds = true;
            break;
        case 6:
            request.mutable_entries(1)->clear_key();
            break;
        case 7:
            request.mutable_entries(1)->set_key(std::string(1025, 'k'));
            break;
        case 8:
            request.mutable_entries(1)->set_key(std::string("k\0z", 3));
            break;
        case 9:
            request.mutable_entries(1)->set_key(std::string(1023, 'k') + "\xC3\xA9");
            break;
        case 10:
            request.mutable_entries(1)->set_key("first");
            break;
        case 11:
            request.mutable_entries(1)->set_value(std::string(1024 * 1024 + 1, 'v'));
            code = grpc::StatusCode::RESOURCE_EXHAUSTED;
            reason = proto::comet::v1::REASON_LIMIT;
            break;
        case 12:
            for (auto& entry : *request.mutable_entries()) {
                entry.set_value(std::string(512 * 1024, 'v'));
            }
            code = grpc::StatusCode::RESOURCE_EXHAUSTED;
            reason = proto::comet::v1::REASON_LIMIT;
            break;
        case 13:
            request.mutable_entries(1)->set_value(std::string(2 * 1024 * 1024, 'v'));
            break;
        case 14:
            request = Fixture::publish();
            request.clear_key();
            break;
        case 15:
            request = Fixture::publish();
            request.set_version(0);
            break;
        case 16:
            request = Fixture::publish();
            request.set_value(std::string(1024 * 1024 + 1, 'v'));
            code = grpc::StatusCode::RESOURCE_EXHAUSTED;
            reason = proto::comet::v1::REASON_LIMIT;
            break;
        case 17:
            request = Fixture::publish();
            request.set_ttl_ms(999);
            bounds = true;
            break;
        case 18:
            request = Fixture::publish();
            request.set_ttl_ms(600001);
            bounds = true;
            break;
        case 19:
            request.set_version(6);
            code = grpc::StatusCode::FAILED_PRECONDITION;
            reason = proto::comet::v1::REASON_VERSION;
            break;
        case 20:
            request.mutable_entries(1)->set_value("conflict");
            code = grpc::StatusCode::FAILED_PRECONDITION;
            reason = proto::comet::v1::REASON_VERSION;
            break;
        }
        fixture.reject(request, code, reason, bounds);
        std::cout << "ASTRA-CATALOG {\"group\":\"publish\",\"case\":" << index << "}\n";
    }
}

/// Verify renewal rejects the whole batch, including an absent final target.
void renewing() {

    Fixture fixture;
    fixture.accept(Fixture::batch());
    for (int index = 0; index < 12; ++index) {
        auto request = Fixture::renew();
        auto code = grpc::StatusCode::INVALID_ARGUMENT;
        auto reason = proto::comet::v1::REASON_INPUT;
        bool bounds = false;
        switch (index) {
        case 0:
            request.set_key("mixed");
            break;
        case 1:
            for (int key = 2; key < 129; ++key) {
                request.add_keys(std::to_string(key));
            }
            break;
        case 2:
            request.set_version(0);
            break;
        case 3:
            request.set_ttl_ms(999);
            bounds = true;
            break;
        case 4:
            request.set_ttl_ms(600001);
            bounds = true;
            break;
        case 5:
            request.set_keys(1, "");
            break;
        case 6:
            request.set_keys(1, "first");
            break;
        case 7:
            request.set_keys(1, std::string(1025, 'k'));
            break;
        case 8:
            request.set_keys(1, std::string(2 * 1024 * 1024, 'k'));
            break;
        case 9:
            request.set_keys(1, "absent");
            code = grpc::StatusCode::NOT_FOUND;
            reason = proto::comet::v1::REASON_ENDED;
            break;
        case 10:
            request.set_version(8);
            code = grpc::StatusCode::FAILED_PRECONDITION;
            reason = proto::comet::v1::REASON_VERSION;
            break;
        case 11:
            request.clear_keys();
            break;
        }
        fixture.reject(request, code, reason, bounds);
        std::cout << "ASTRA-CATALOG {\"group\":\"renew\",\"case\":" << index << "}\n";
    }

    grpc::ClientContext context;
    fixture.prepare(context);
    proto::comet::v1::Empty reply;
    CHECK(fixture.stub->Renew(&context, Fixture::renew(), &reply).ok());
    const auto source = fixture.state.source();
    CHECK(source.size() == 2);
    source.each([](const astra::Scope&, std::string_view, const Catalog::Record& record) { CHECK(record.deadline == Clock::Time(3s)); });
}

/// Accept the exact key-count and aggregate byte limits without clamping either.
void limits() {

    Fixture fixture;
    auto request = Fixture::batch();
    request.clear_entries();
    std::size_t names{}; // Account every key byte in the one-MiB batch limit.
    for (int index = 0; index < 128; ++index) {
        auto* entry = request.add_entries();
        entry->set_key(std::to_string(index));
        names += entry->key().size();
    }
    request.mutable_entries(0)->set_value(std::string(1024 * 1024 - names, 'v'));
    request.set_ttl_ms(600000);
    fixture.accept(request);
    const auto view = fixture.state.capture({"service", "main"});
    CHECK(view && view->size() == 128 && view->version() == 128);
    const auto contents = Fixture::contents(*view);
    CHECK(contents.at("0").second.size() == 1024 * 1024 - names);
    for (int index = 1; index < 128; ++index) {
        CHECK(contents.at(std::to_string(index)).second.empty());
    }

    proto::comet::v1::CatalogQueryRequest query;
    *query.mutable_scope() = request.scope();
    for (int index = 127; index >= 0; --index) {
        query.add_keys(std::to_string(index));
    }
    grpc::ClientContext context;
    fixture.prepare(context);
    proto::comet::v1::CatalogQueryReply reply;
    CHECK(fixture.stub->Query(&context, query, &reply).ok());
    CHECK(reply.entries_size() == 128 && reply.instance() == "star-test");
    for (int index = 0; index < 128; ++index) {
        CHECK(reply.entries(index).key() == std::to_string(127 - index) && reply.entries(index).version() == 7);
    }
    std::cout << "ASTRA-CATALOG {\"group\":\"limits\",\"cases\":1}\n";
}

/// Check authorization, scope/instance fences, and the Query key denominator.
void admission() {

    Fixture fixture;
    fixture.accept(Fixture::batch());
    auto publish = Fixture::publish();
    publish.set_version(8);
    fixture.reject(publish, grpc::StatusCode::UNAUTHENTICATED, proto::comet::v1::REASON_SESSION, false, false);
    publish.set_instance("old-star");
    fixture.reject(publish, grpc::StatusCode::FAILED_PRECONDITION, proto::comet::v1::REASON_INSTANCE);
    publish.clear_instance();
    publish.mutable_scope()->set_sector("__private");
    fixture.reject(publish, grpc::StatusCode::PERMISSION_DENIED, proto::comet::v1::REASON_DENIED);
    publish.mutable_scope()->set_sector("");
    fixture.reject(publish, grpc::StatusCode::INVALID_ARGUMENT, proto::comet::v1::REASON_INPUT);
    publish.mutable_scope()->set_sector("service");
    publish.mutable_scope()->set_spectrum(std::string(129, 's'));
    fixture.reject(publish, grpc::StatusCode::INVALID_ARGUMENT, proto::comet::v1::REASON_INPUT);
    *publish.mutable_scope() = Fixture::publish().scope();
    fixture.ready = false;
    fixture.reject(publish, grpc::StatusCode::UNAVAILABLE, proto::comet::v1::REASON_CLOCK);
    fixture.ready = true;

    auto renewal = Fixture::renew();
    renewal.clear_instance();
    fixture.reject(renewal, grpc::StatusCode::FAILED_PRECONDITION, proto::comet::v1::REASON_INSTANCE);
    for (int index = 0; index < 5; ++index) {
        proto::comet::v1::CatalogQueryRequest query;
        *query.mutable_scope() = Fixture::publish().scope();
        switch (index) {
        case 0:
            break;
        case 1:
            for (int key = 0; key < 129; ++key) {
                query.add_keys(std::to_string(key));
            }
            break;
        case 2:
            query.add_keys("first");
            query.add_keys("first");
            break;
        case 3:
            query.add_keys("");
            break;
        case 4:
            query.add_keys(std::string(1025, 'k'));
            break;
        }
        fixture.reject(query, grpc::StatusCode::INVALID_ARGUMENT, proto::comet::v1::REASON_INPUT);
        std::cout << "ASTRA-CATALOG {\"group\":\"query\",\"case\":" << index << "}\n";
    }
    fixture.access.close(fixture.session);
    fixture.reject(publish, grpc::StatusCode::UNAUTHENTICATED, proto::comet::v1::REASON_SESSION);
    std::cout << "ASTRA-CATALOG {\"group\":\"admission\",\"cases\":8}\n";
}

/// Reject illegal concurrency at construction and exercise both valid endpoints.
void configuration() {

    astra::Access access;
    astra::Gateway gateway(access, "configuration");
    Catalog::State state([] { return std::optional(Clock::Reading{.time = Clock::Time(1s), .ready = true}); }, {});
    for (const auto maximum : {-1, 0, 65537}) {
        bool rejected = false;
        try {
            auto service = std::make_unique<Catalog::Service>(state, gateway, maximum);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        CHECK(rejected);
    }
    for (const auto maximum : {1, 128, 65536}) {
        auto service = std::make_unique<Catalog::Service>(state, gateway, maximum);
        CHECK(service->empty());
        service->stop();
        service->pump(std::chrono::steady_clock::now());
        CHECK(service->empty());
    }
    std::cout << "ASTRA-CATALOG {\"group\":\"configuration\",\"cases\":6}\n";
}

/// Query admission and scalar renewal retain the same stable rejection and atomicity contracts.
void refusals() {

    Fixture fixture;
    fixture.accept(Fixture::batch());
    proto::comet::v1::CatalogQueryRequest query;
    *query.mutable_scope() = Fixture::publish().scope();
    query.add_keys("first");
    fixture.reject(query, grpc::StatusCode::UNAUTHENTICATED, proto::comet::v1::REASON_SESSION, false, false);
    query.set_instance("old-star");
    fixture.reject(query, grpc::StatusCode::FAILED_PRECONDITION, proto::comet::v1::REASON_INSTANCE);
    query.clear_instance();
    query.mutable_scope()->set_sector("__private");
    fixture.reject(query, grpc::StatusCode::PERMISSION_DENIED, proto::comet::v1::REASON_DENIED);

    for (int index = 0; index < 5; ++index) {
        auto request = Fixture::renew();
        request.clear_keys();
        request.set_key("first");
        switch (index) {
        case 0:
            request.set_version(0);
            break;
        case 1:
            request.set_ttl_ms(999);
            break;
        case 2:
            request.set_ttl_ms(600001);
            break;
        case 3:
            request.set_key(std::string(1025, 'k'));
            break;
        case 4:
            request.set_key(std::string("k\0z", 3));
            break;
        }
        fixture.reject(request, grpc::StatusCode::INVALID_ARGUMENT, proto::comet::v1::REASON_INPUT, index == 1 || index == 2);
    }
    std::cout << "ASTRA-CATALOG {\"group\":\"refusals\",\"cases\":8}\n";
}

/// Reject native quota exhaustion without retaining a partial batch or poisoned admission slot.
void capacity() {

    {
        Catalog::State::Limits limits;
        limits.scopes = 0;
        Fixture fixture(limits);
        fixture.reject(Fixture::publish(), grpc::StatusCode::RESOURCE_EXHAUSTED, proto::comet::v1::REASON_LIMIT);
    }
    {
        Catalog::State::Limits limits;
        limits.source.records = 1;
        Fixture fixture(limits, 1);
        fixture.accept(Fixture::publish());
        auto request = Fixture::batch();
        request.set_version(8);
        for (auto& entry : *request.mutable_entries()) {
            entry.set_value("new");
        }
        fixture.reject(request, grpc::StatusCode::RESOURCE_EXHAUSTED, proto::comet::v1::REASON_LIMIT);
        auto scalar = Fixture::publish();
        scalar.set_version(8);
        scalar.set_value("recovered");
        fixture.accept(scalar);
        CHECK(fixture.state.source().size() == 1);
    }
    std::cout << "ASTRA-CATALOG {\"group\":\"capacity\",\"cases\":2}\n";
}

/// Absolute deadline overflow is a definitive unapplied limit, never a wrapped or unlimited lease.
void exhaustion() {

    Fixture fixture;
    fixture.now = std::numeric_limits<std::int64_t>::max() - 500'000'000;
    fixture.reject(Fixture::publish(), grpc::StatusCode::OUT_OF_RANGE, proto::comet::v1::REASON_LIMIT);
    fixture.reject(Fixture::batch(), grpc::StatusCode::OUT_OF_RANGE, proto::comet::v1::REASON_LIMIT);
    CHECK(fixture.state.source().size() == 0 && fixture.state.source().position() == 0);
    std::cout << "ASTRA-CATALOG {\"group\":\"exhaustion\",\"cases\":2}\n";
}

/// Exception responses preserve unknown effect and release the sole unary slot for healthy recovery.
void exceptions() {

    Fixture fixture({}, 1);
    fixture.accept(Fixture::batch());
    const std::lock_guard lock(fixture.control); // Only the RPC under test can consume the injected clock failure.
    for (int index = 0; index < 2; ++index) {
        const auto before = fixture.state.source();
        const auto facts = Fixture::facts(before);
        auto request = Fixture::publish();
        request.set_version(8 + static_cast<std::uint64_t>(index));
        request.set_value("recovered");
        grpc::ClientContext context;
        fixture.prepare(context);
        proto::comet::v1::PublishReply reply;
        fixture.failure = index == 0 ? Fixture::Failure::Allocation : Fixture::Failure::Exception;
        const auto result = fixture.stub->Publish(&context, request, &reply);
        fixture.failure = Fixture::Failure::None;
        CHECK(result.error_code() == (index == 0 ? grpc::StatusCode::RESOURCE_EXHAUSTED : grpc::StatusCode::INTERNAL));
        CHECK(context.GetServerTrailingMetadata().find("comet-error-bin") == context.GetServerTrailingMetadata().end());
        const auto after = fixture.state.source();
        CHECK(after.position() == before.position() && after.size() == before.size() && after.bytes() == before.bytes());
        CHECK(Fixture::facts(after) == facts && Fixture::facts(before) == facts);
        fixture.accept(request);
        CHECK(fixture.state.source().position() == before.position() + 1);
        CHECK(Fixture::facts(before) == facts);
        std::cout << "ASTRA-CATALOG {\"group\":\"exceptions\",\"case\":" << index << "}\n";
    }
}

/// Own a Watch through cancellation and terminal receipt.
class Watching {
public:
    /// Remain alive until Finish observes all transport callbacks.
    grpc::ClientContext context;
    /// Read complete Catalog updates from the actual network stream.
    std::unique_ptr<grpc::ClientReader<proto::comet::v1::CatalogWatchReply>> stream;
    /// Finish is observed once, whether explicit or during cancellation cleanup.
    std::optional<grpc::Status> status;

    /// Subscribe to the same instance and Scope as the writer.
    explicit Watching(Fixture& fixture) {
        fixture.prepare(context);
        proto::comet::v1::WatchRequest request;
        *request.mutable_scope() = Fixture::publish().scope();
        request.set_instance("star-test");
        stream = fixture.stub->Watch(&context, request);
    }

    /// Drain this stream while the fixture pump still lives.
    ~Watching() {
        if (!status) {
            context.TryCancel();
            static_cast<void>(finish());
        }
    }

    /// Cache the terminal transport result without requesting client cancellation first.
    const grpc::Status& finish() {
        if (!status) {
            status = stream->Finish();
        }
        return *status;
    }

    /// These two tiny records must arrive as one complete atomic page.
    proto::comet::v1::CatalogWatchReply next() {
        proto::comet::v1::CatalogWatchReply reply;
        CHECK(stream->Read(&reply) && reply.complete() && reply.has_version() && reply.instance() == "star-test");
        return reply;
    }
};

/// Observe complete old/new snapshots and network batches at one Star.
void streaming() {

    Fixture fixture;
    Watching watch(fixture);
    const auto empty = watch.next();
    CHECK(empty.mode() == proto::comet::v1::MODE_RESET && empty.changes_size() == 0 && empty.version() == 0);
    fixture.accept(Fixture::batch());
    const auto introduced = watch.next();
    CHECK(introduced.mode() == proto::comet::v1::MODE_APPLY && introduced.changes_size() == 2 && introduced.version() == 2);
    const auto frozen = fixture.state.source();
    const auto old = Fixture::facts(frozen);
    auto update = Fixture::batch();
    update.set_version(8);
    for (auto& entry : *update.mutable_entries()) {
        entry.set_value("new");
    }
    fixture.accept(update);
    const auto changed = watch.next();
    CHECK(changed.mode() == proto::comet::v1::MODE_APPLY && changed.changes_size() == 2 && changed.version() == 4);
    for (const auto* page : {&introduced, &changed}) {
        std::map<std::string, std::pair<std::uint64_t, std::string>> actual;
        for (const auto& change : page->changes()) {
            CHECK(change.has_value());
            CHECK(actual.emplace(change.key(), std::pair(change.version(), change.value())).second);
        }
        const bool first = page == &introduced;
        const std::map<std::string, std::pair<std::uint64_t, std::string>> expected{{"first", {first ? 7 : 8, first ? "old" : "new"}}, {"second", {first ? 7 : 8, first ? "old" : "new"}}};
        CHECK(actual == expected);
    }
    CHECK(Fixture::facts(frozen) == old && Fixture::facts(fixture.state.source()) != old);
    Watching snapshot(fixture);
    const auto reset = snapshot.next();
    CHECK(reset.mode() == proto::comet::v1::MODE_RESET && reset.changes_size() == 2 && reset.version() == 4);
    std::map<std::string, std::pair<std::uint64_t, std::string>> restored;
    for (const auto& change : reset.changes()) {
        CHECK(change.has_value() && change.version() == 8 && change.value() == "new");
        CHECK(restored.emplace(change.key(), std::pair(change.version(), change.value())).second);
    }
    const std::map<std::string, std::pair<std::uint64_t, std::string>> expected{{"first", {8, "new"}}, {"second", {8, "new"}}};
    CHECK(restored == expected);
    std::cout << "ASTRA-CATALOG {\"group\":\"streaming\",\"cases\":1}\n";
}

/// Stop old streams on explicit shutdown or failed maintenance, and drain every server-owned callback.
void cleanup() {

    for (int index = 0; index < 2; ++index) {
        Fixture fixture;
        CHECK(fixture.service.empty());
        fixture.accept(Fixture::batch());
        Watching watch(fixture);
        const auto initial = watch.next();
        CHECK(initial.mode() == proto::comet::v1::MODE_RESET && initial.changes_size() == 2 && initial.version() == 2);
        CHECK(!fixture.service.empty());
        const auto before = fixture.state.source();
        const auto facts = Fixture::facts(before);
        {
            const std::lock_guard lock(fixture.control);
            if (index == 0) {
                fixture.service.stop();
            } else {
                fixture.ready = false;
            }
            fixture.service.pump(std::chrono::steady_clock::now());
        }
        proto::comet::v1::CatalogWatchReply reply;
        CHECK(!watch.stream->Read(&reply));
        CHECK(watch.finish().error_code() == (index == 0 ? grpc::StatusCode::CANCELLED : grpc::StatusCode::RESOURCE_EXHAUSTED));
        static_cast<void>(Fixture::detail(watch.context, index == 0 ? proto::comet::v1::REASON_SESSION : proto::comet::v1::REASON_BUSY));
        CHECK(Fixture::facts(fixture.state.source()) == facts && Fixture::facts(before) == facts);
        if (index == 1) {
            fixture.ready = true;
            Watching recovered(fixture);
            const auto reset = recovered.next();
            CHECK(reset.mode() == proto::comet::v1::MODE_RESET && reset.version() == 2 && reset.changes_size() == 2);
            std::map<std::string, std::pair<std::uint64_t, std::string>> actual;
            for (const auto& change : reset.changes()) {
                CHECK(change.has_value());
                CHECK(actual.emplace(change.key(), std::pair(change.version(), change.value())).second);
            }
            const std::map<std::string, std::pair<std::uint64_t, std::string>> expected{{"first", {7, "old"}}, {"second", {7, "old"}}};
            CHECK(actual == expected);
        }
        fixture.stop();
        CHECK(fixture.service.empty());
        fixture.stop();
        CHECK(fixture.service.empty());
        std::cout << "ASTRA-CATALOG {\"group\":\"cleanup\",\"case\":" << index << "}\n";
    }
}
} // namespace

/// Preserve failing assertions and expose every completed boundary group.
int main() {
    try {
        lifecycle();
        publishing();
        renewing();
        limits();
        admission();
        streaming();
        configuration();
        refusals();
        capacity();
        exhaustion();
        exceptions();
        cleanup();
        std::cout << "PASS Catalog public RPC boundaries and atomic batches\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
