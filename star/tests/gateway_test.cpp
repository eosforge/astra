// Verify public SDK gateway admission and RPC lifecycle boundaries.
#include "check.hpp"
#include "gateway.hpp"
#include "identity.hpp"

#include <grpcpp/create_channel.h>
#include <grpcpp/server_builder.h>

#include <iostream>

namespace {
using astra::Access;
using astra::Almanac;
using astra::Gateway;

/// Probe uses real Gateway metadata/final Permit without implementing fake Catalog storage.
class Probe final : public proto::comet::v1::Catalog::CallbackService {
public:
    /// Gateway outlives every Probe RPC.
    explicit Probe(Gateway& gateway) : gateway_(gateway) {}

    /// Only a live valid token returns instance. Other RPCs on the Channel inherit no permission.
    grpc::ServerUnaryReactor* Publish(grpc::CallbackServerContext* context, const proto::comet::v1::PublishRequest*, proto::comet::v1::PublishReply* reply) override {

        auto* reactor = context->DefaultReactor();
        auto permit = gateway_.enter(*context); // Retain Permit through simulated commit without rechecking SECRET.
        if (!permit) {
            reactor->Finish(permit.error());
        } else {
            reply->set_instance(gateway_.instance());
            reactor->Finish(grpc::Status::OK);
        }
        return reactor;
    }

private:
    /// Borrow the real gateway while the probe exercises its authorization boundary.
    Gateway& gateway_;
};

/// Private real TLS Server/Channel on allocated loopback ports, independent of deployment services.
class Fixture {
public:
    /// Real authorization with matching Gateway quota; constructed before Server and released after it.
    Access access;
    /// Logical-stream service, login enabled and explicitly opened by the fixture.
    Gateway gateway;
    /// Unary metadata-only Probe service.
    Probe probe;
    /// Owned listener released only after draining.
    std::unique_ptr<grpc::Server> server;
    /// Real Channel using public local certificate fixtures for TLS verification.
    std::shared_ptr<grpc::Channel> channel;
    /// Generated Stubs share Channel but submit session metadata independently per RPC.
    std::unique_ptr<proto::comet::v1::Gateway::Stub> login;
    /// Unary Stub whose reply confirms authorization only.
    std::unique_ptr<proto::comet::v1::Catalog::Stub> catalog;

    /// Explicit auth/capacity/readiness cases retain real certificate validation.
    explicit Fixture(bool auth = true, std::size_t maximum = 4, bool readiness = true) : access(maximum), gateway(access, "star-test", auth, static_cast<std::ptrdiff_t>(maximum)), probe(gateway) {

        Access::Draft draft; // Valid account SECRET includes NUL.
        CHECK(draft.set("application", {0, 1, 255}));
        CHECK(access.reset(std::move(draft), [] { return std::expected<bool, Almanac::Error>(true); }));
        const auto identity = astra::Identity::load(std::filesystem::path(ASTRA_FIXTURES) / "star-a", *astra::Endpoint::parse("127.0.0.1:7443"));
        CHECK(identity);
        grpc::ServerBuilder builder; // Register only public services/Probe, without Orbit/Pulse.
        builder.RegisterService(&gateway);
        builder.RegisterService(&probe);
        int port{};
        builder.AddListeningPort("127.0.0.1:0", (*identity)->serverCredentials(), &port);
        server = builder.BuildAndStart();
        CHECK(server && port > 0);
        try {
            channel = grpc::CreateChannel("127.0.0.1:" + std::to_string(port), (*identity)->channelCredentials());
            login = proto::comet::v1::Gateway::NewStub(channel);
            catalog = proto::comet::v1::Catalog::NewStub(channel);
            if (readiness) {
                gateway.ready();
            }
        } catch (...) {
            server->Shutdown();
            server->Wait();
            throw;
        }
    }

    /// Stop logical streams before bounded Server shutdown, independently of client destruction.
    ~Fixture() {
        gateway.stop();
        server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(3));
        server->Wait();
    }

    /// Independent requests exercise missing/duplicate/wrong-length tokens and require parseable failure details.
    grpc::Status call(std::initializer_list<std::string_view> tokens = {}) {

        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(3));
        for (const auto token : tokens) {
            context.AddMetadata("comet-session-bin", std::string(token));
        }
        proto::comet::v1::PublishRequest request; // Probe isolates session permission without interpreting application bodies.
        proto::comet::v1::PublishReply reply;
        const auto status = catalog->Publish(&context, request, &reply);
        if (status.ok()) {
            CHECK(reply.instance() == "star-test");
        } else {
            const auto details = context.GetServerTrailingMetadata().find("comet-error-bin");
            CHECK(details != context.GetServerTrailingMetadata().end());
            proto::comet::v1::Failure failure;
            CHECK(failure.ParseFromArray(details->second.data(), static_cast<int>(details->second.size())));
            CHECK(failure.effect() == proto::comet::v1::EFFECT_UNAPPLIED && failure.instance() == "star-test");
        }
        return status;
    }
};

/// Unique long-lived client RPC owner; exception cleanup cancels/finishes without leaving an active server session.
class Login {
public:
    /// Stable context address; Login cannot move it.
    grpc::ClientContext context;
    /// Sole server stream until finish/destruction.
    std::unique_ptr<grpc::ClientReader<proto::comet::v1::SessionReply>> stream;
    /// Confirmed raw token/actual instance, absent before successful receipt.
    proto::comet::v1::SessionReply reply;
    /// Actual first-response receipt; default messages cannot imply authentication success.
    bool accepted{};

    /// Wrong SECRET must reject without consuming active-session capacity.
    explicit Login(Fixture& fixture, bool correct = true) {
        context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(8));
        proto::comet::v1::SessionRequest request; // Password appears only in the initial request, never retransmitted on the long stream.
        request.set_key("application");
        request.set_secret(correct ? std::string("\0\1\xff", 3) : "wrong");
        stream = fixture.login->Session(&context, request);
        accepted = stream->Read(&reply);
    }

    /// Cancel only this RPC, preserving other logins/unary calls on the shared Channel.
    ~Login() {
        if (stream) {
            context.TryCancel();
            static_cast<void>(stream->Finish());
        }
    }

    /// Finish once after EOF/explicit cancellation; destruction cannot repeat it.
    grpc::Status finish() {
        const auto status = stream->Finish();
        stream.reset();
        return status;
    }
};

/// Login/unary use separate contexts and require exactly one still-valid token.
void metadata() {

    Fixture fixture;
    Login rejected(fixture, false);
    CHECK(!rejected.accepted && rejected.finish().error_code() == grpc::StatusCode::UNAUTHENTICATED);
    Login active(fixture);
    CHECK(active.accepted && active.reply.instance() == "star-test" && active.reply.session().size() == 32);
    CHECK(fixture.call().error_code() == grpc::StatusCode::UNAUTHENTICATED);
    CHECK(fixture.call({"short"}).error_code() == grpc::StatusCode::UNAUTHENTICATED);
    CHECK(fixture.call({active.reply.session(), active.reply.session()}).error_code() == grpc::StatusCode::UNAUTHENTICATED);
    CHECK(fixture.call({active.reply.session()}).ok());
    active.context.TryCancel();
    CHECK(!active.finish().ok());
}

/// Rotation blocks old writes before OnDone; late old cleanup cannot revoke new sessions after full replacement.
void revocation() {

    Fixture fixture;
    Login previous(fixture);
    CHECK(previous.accepted);
    CHECK(fixture.access.apply("application", Almanac::Buffer{2}, [] { return std::expected<bool, Almanac::Error>(true); }));
    CHECK(fixture.call({previous.reply.session()}).error_code() == grpc::StatusCode::UNAUTHENTICATED);
    proto::comet::v1::SessionReply extra; // Session sends no second successful confirmation.
    CHECK(!previous.stream->Read(&extra));
    CHECK(!previous.finish().ok());
    Access::Draft restored;
    CHECK(restored.set("application", {0, 1, 255}));
    CHECK(fixture.access.reset(std::move(restored), [] { return std::expected<bool, Almanac::Error>(true); }));
    Login current(fixture);
    CHECK(current.accepted && fixture.call({current.reply.session()}).ok());
    fixture.gateway.stop();
    CHECK(!current.stream->Read(&extra));
    CHECK(!current.finish().ok());
    fixture.gateway.ready(); // Stop is permanent even if ready is called later.
    CHECK(fixture.call({current.reply.session()}).error_code() == grpc::StatusCode::UNAVAILABLE);
}

/// Anonymous mode issues no fake session. Idle Sessions consume capacity; unready services reject login/business calls.
void modes() {

    {
        Fixture fixture(false);
        Login login(fixture);
        CHECK(!login.accepted && login.finish().error_code() == grpc::StatusCode::FAILED_PRECONDITION);
        CHECK(fixture.call().ok());
    }
    {
        Fixture fixture(true, 1);
        Login first(fixture);
        CHECK(first.accepted);
        Login second(fixture);
        CHECK(!second.accepted && second.finish().error_code() == grpc::StatusCode::RESOURCE_EXHAUSTED);
        CHECK(fixture.call({first.reply.session()}).ok());
    }
    {
        Fixture fixture(true, 4, false);
        Login login(fixture);
        CHECK(!login.accepted && login.finish().error_code() == grpc::StatusCode::UNAVAILABLE);
        CHECK(fixture.call().error_code() == grpc::StatusCode::UNAVAILABLE);
    }
}
} // namespace

int main() {
    try {
        metadata();
        revocation();
        modes();
        std::cout << "PASS business gateway TLS sessions and cleanup\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
