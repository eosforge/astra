// Verify admission RPC ownership, request validation, and completion boundaries.
#include "admission.hpp"
#include "check.hpp"
#include "fixture.hpp"

#include <grpcpp/server_builder.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

using namespace astra;

namespace {

/// Fault scenarios local to one fixture; numeric values are test selectors, not wire encodings.
enum class Scenario {
    /// Lost initial registration receipt; retries must preserve this startup's idempotency key.
    LostReply,
    /// Directory exceeds role capacity; admission must reject it.
    ExcessiveMembers,
    /// Signed identity belongs to another process; binding verification must reject it.
    WrongIdentity,
    /// Cancel an in-flight registration and verify result plus callback draining.
    Cancellation,
    /// Reply exceeds transport receive cap.
    OversizedReply,
    /// A smaller configured response cap must affect the actual gRPC Channel.
    ReplyLimit,
    /// Oversized request must not reach the registration handler.
    RequestLimit,
    /// Member lacks valid identity fields; validate each directory entry.
    EmptyMember,
    /// Nonempty Pulse endpoint must validate before reaching the sampling thread.
    InvalidPulse,
    /// Registration blocks until deadline to exercise unary timeout cleanup.
    RegistrationDeadline,
    /// Refresh returns another instance after success; local identity must stay fixed.
    ChangedIdentity,
    /// Explicit directory credential revocation differs from transient control-plane disconnection.
    Revoked,
    /// Temporary List outage retains registered identity without automatic login.
    DirectoryOutage,
    /// Certificate SAN mismatches the target address.
    WrongSan,
    /// Certificate issuer is untrusted by the client.
    UntrustedRoot,
    /// Certificate is expired.
    ExpiredCertificate
};

/// Actual TLS/gRPC service varies replies and deadlines without copying Admission's retry state machine.
class Authority final : public proto::orbit::v1::Admission::Service {
public:
    /// Retains shared identity and fixed scenario; changes responses only.
    Authority(std::shared_ptr<Identity> identity, Scenario scenario) : identity_(std::move(identity)), scenario_(scenario) {}

    /// Actual handler-entry count, initially zero, for retry and transport-rejection checks.
    std::atomic_uint registrations{};
    /// Initially false; true if any retry changes the startup idempotency key.
    std::atomic_bool requestChanged{};
    /// Read-only request count, separate from password logins.
    std::atomic_uint queries{};

    /// Borrows context/request/response for this handler only; scenario controls reply or cancellation wait.
    grpc::Status Register(grpc::ServerContext* context, const proto::orbit::v1::RegistrationRequest* request, proto::orbit::v1::RegistrationResponse* response) override {

        // One-based actual attempt count selects first lost receipt or later identity replacement.
        const auto attempt = ++registrations;
        // RPCs may use different workers; protect observed request keys with a short lock, without deriving instance IDs from requests.
        {
            // Protects only test-observed requests against concurrent handlers.
            std::lock_guard lock(mutex_);
            if (requestId_.empty()) {
                requestId_ = request->request_id();
            }
            if (request->request_id().size() != 32 || requestId_ != request->request_id()) {
                requestChanged = true;
            }
        }
        if (scenario_ == Scenario::Cancellation || scenario_ == Scenario::RegistrationDeadline) {
            while (!context->IsCancelled()) {
                std::this_thread::sleep_for(Milliseconds(1));
            }
            return grpc::Status(grpc::StatusCode::CANCELLED, "Test cancelled");
        }
        if (scenario_ == Scenario::LostReply && attempt == 1) {
            return grpc::Status(grpc::StatusCode::UNAVAILABLE, "Simulated reply loss after registration");
        }

        // Independent response identity matches the requested deployment except for the injected fault.
        proto::orbit::v1::Member member;
        member.set_galaxy(request->galaxy());
        member.set_advertise(request->advertise());
        member.set_id("issued/session:α/42");
        member.set_role(request->role());
        member.set_group(scenario_ == Scenario::WrongIdentity ? "wrong" : request->group());
        member.set_epoch(1);
        const auto digest = identity_->principal(member.galaxy(), member.advertise());
        member.set_principal(digest.bytes.data(), digest.bytes.size());
        response->set_admission(member.SerializeAsString());
        response->set_signature(test::sign(response->admission()));
        {
            // Retains the first issued Member; List copies it without creating another startup identity.
            std::lock_guard lock(mutex_);
            current_ = member;
        }
        for (unsigned n = 0; n < (scenario_ == Scenario::ExcessiveMembers ? 5U : 1U); ++n) {
            response->add_members()->CopyFrom(member);
        }
        if (scenario_ == Scenario::OversizedReply) {
            response->mutable_members(0)->set_group(std::string(2 * 1024 * 1024, 'x'));
        } else if (scenario_ == Scenario::ReplyLimit) {
            response->mutable_members(0)->set_group(std::string(2048, 'x'));
        } else if (scenario_ == Scenario::EmptyMember) {
            response->mutable_members(0)->Clear();
        } else if (scenario_ == Scenario::InvalidPulse) {
            response->set_pulse_endpoint("not-an-endpoint");
        }
        return grpc::Status::OK;
    }

    /// Post-registration refresh uses credential metadata and an empty request; faults change only this read result.
    grpc::Status List(grpc::ServerContext* context, const proto::orbit::v1::DirectoryRequest*, proto::orbit::v1::DirectoryResponse* response) override {

        ++queries;
        std::lock_guard lock(mutex_);
        const auto& metadata = context->client_metadata();
        const auto admission = metadata.find("astra-admission-bin");
        const auto signature = metadata.find("astra-signature-bin");
        const auto encoded = current_.SerializeAsString();
        const auto signedValue = test::sign(encoded);
        if (metadata.count("astra-admission-bin") != 1 || metadata.count("astra-signature-bin") != 1 || admission == metadata.end() || signature == metadata.end() || std::string_view(admission->second.data(), admission->second.size()) != encoded || std::string_view(signature->second.data(), signature->second.size()) != signedValue) {
            return {grpc::StatusCode::UNAUTHENTICATED, "Invalid test directory credential"};
        }
        if (scenario_ == Scenario::Revoked) {
            return {grpc::StatusCode::UNAUTHENTICATED, "Replaced test identity"};
        }
        if (scenario_ == Scenario::DirectoryOutage) {
            return {grpc::StatusCode::UNAVAILABLE, "Directory temporarily unavailable"};
        }
        *response->add_members() = current_;
        if (scenario_ == Scenario::ChangedIdentity) {
            response->mutable_members(0)->set_id("other-instance");
        }
        return grpc::Status::OK;
    }

private:
    /// Protects cross-RPC requestId_ only; never held while awaiting cancellation.
    std::mutex mutex_;
    /// First request's 32-byte startup key, initially empty; later requests compare against it.
    std::string requestId_;
    /// First issued Member, protected by mutex_ across handlers.
    proto::orbit::v1::Member current_;
    /// Shared test identity retains digest material throughout handler lifetime.
    std::shared_ptr<Identity> identity_;
    /// Fixed read-only scenario, never switched between concurrent RPCs.
    Scenario scenario_;
};

/// Own an authority, loopback server, and admission client in safe shutdown order.
struct Fixture {
    /// Constructed before and destroyed after server, covering all handler borrows.
    Authority authority;
    /// Owns this case's dynamic-port listener; Shutdown/Wait precede handler destruction.
    std::unique_ptr<grpc::Server> server;
    /// Owns the admission state machine; cancel and consume final completion before destruction.
    std::unique_ptr<Admission> client;

    /// Creates local TLS fixture and client for scenario, using public identities and an OS-allocated port.
    Fixture(std::shared_ptr<Identity> identity, Scenario scenario) : authority(identity, scenario) {

        // Creates this fixture's TLS server only, without touching other listeners.
        grpc::ServerBuilder builder;
        builder.RegisterService(&authority);
        // Receives a positive OS-allocated port instead of sharing fixed ports.
        int port = 0;
        // Normally 127.0.0.1; wrong_san uses certificate-unauthorized 127.0.0.2.
        const std::string address = scenario == Scenario::WrongSan ? "127.0.0.2" : "127.0.0.1";
        // Valid credentials by default; TLS-failure cases explicitly substitute invalid material.
        auto credentials = identity->serverCredentials();
        if (scenario == Scenario::UntrustedRoot || scenario == Scenario::ExpiredCertificate) {
            // Test server bypasses its startup validation to verify the client still rejects invalid TLS certificates.
            const auto fixtures = std::filesystem::path(ASTRA_FIXTURES);
            // Selects repository-public expired or untrusted certificate directories only.
            const auto directory = scenario == Scenario::ExpiredCertificate ? fixtures / "expired" : fixtures / "untrusted";
            // Fixed certificate filename from the selected fixture, without external path input.
            const auto certificate = scenario == Scenario::ExpiredCertificate ? "cert.pem" : "certificate.pem";
            // Matching public test private-key filename.
            const auto key = scenario == Scenario::ExpiredCertificate ? "key.pem" : "private-key.pem";
            // Allows invalid TLS material in the test server only; production startup checks stay intact.
            grpc::SslServerCredentialsOptions options;
            options.pem_key_cert_pairs.push_back({test::read(directory / key), test::read(directory / certificate)});
            credentials = grpc::SslServerCredentials(options);
        }
        builder.AddListeningPort(address + ":0", credentials, &port);
        server = builder.BuildAndStart();
        CHECK(server && port > 0);
        // Client configuration targets this temporary service with scenario-specific capacity or deadlines.
        Config config;
        config.galaxy = "alpha";
        config.advertise = *Endpoint::parse("127.0.0.1:7443");
        config.pulsar = address + ":" + std::to_string(port);
        config.maxMembers = 4;
        if (scenario == Scenario::ReplyLimit) {
            config.maxAdmissionResponseBytes = 1024;
        } else if (scenario == Scenario::RequestLimit) {
            config.maxAdmissionRequestBytes = 1;
        }
        if (scenario == Scenario::WrongSan || scenario == Scenario::UntrustedRoot || scenario == Scenario::ExpiredCertificate) {
            config.connectTimeout = Milliseconds(300);
        }
        client = std::make_unique<Admission>(config, identity, [] {});
    }

    /// Cancel and drain owned RPC before closing listener; failure exits nonzero immediately rather than destroying borrowed requests.
    ~Fixture() {

        // Assertion failure also cancels and drains owned RPC before request destruction.
        if (client) {
            client->cancel();
            // Monotonic hard limit prevents cleanup or polling from hanging after assertion failure.
            const auto deadline = Steady::now() + std::chrono::seconds(7);
            while (client->pending() && Steady::now() < deadline) {
                static_cast<void>(client->poll());
                std::this_thread::sleep_for(Milliseconds(1));
            }
            if (client->pending()) {
                std::_Exit(3);
            }
        }
        if (server) {
            server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(2));
            server->Wait();
        }
    }

    /// Advances client for at most seven seconds, returning one attempt result or throwing on timeout.
    Result<Admission::Joined> result() {

        // Monotonic hard limit prevents cleanup or polling from hanging after assertion failure.
        const auto deadline = Steady::now() + std::chrono::seconds(7);
        while (Steady::now() < deadline) {
            if (auto value = client->poll()) {
                return std::move(*value);
            }
            std::this_thread::sleep_for(Milliseconds(1));
        }
        throw std::runtime_error("Admission test exceeded deadline");
    }
};

} // namespace

/// Reports exceptions as nonzero process failure; assertions remain active under NDEBUG.
int main() {

    try {
        // Public star-a identity is the trusted baseline for independent TLS scenarios.
        auto identity = Identity::load(std::filesystem::path(ASTRA_FIXTURES) / "star-a", *Endpoint::parse("127.0.0.1:7443"));
        CHECK(identity);
        for (auto scenario : {Scenario::WrongSan, Scenario::UntrustedRoot, Scenario::ExpiredCertificate}) {
            Fixture fixture(*identity, scenario);
            fixture.client->begin(0);
            CHECK(!fixture.result());
            CHECK(fixture.authority.registrations == 0);
        }
        {
            Fixture fixture(*identity, Scenario::LostReply);
            fixture.client->begin(0);
            // First lost receipt returns transport failure; retry reuses the startup request.
            auto first = fixture.result();
            CHECK(!first && first.error().code == Status::Code::Transport);
            fixture.client->begin(0);
            // Retry admission result; old control planes need not supply Pulse.
            const auto joined = fixture.result();
            CHECK(joined && joined->pulseEndpoint.empty());
            CHECK(fixture.authority.registrations == 2 && !fixture.authority.requestChanged);
            fixture.client->begin(0);
            const auto refreshed = fixture.result(); // Successful registration refresh resubmits neither password nor startup key.
            CHECK(refreshed && refreshed->local == joined->local);
            CHECK(fixture.authority.registrations == 2 && fixture.authority.queries == 1 && !fixture.client->revoked());
        }
        {
            Fixture fixture(*identity, Scenario::ChangedIdentity);
            fixture.client->begin(0);
            CHECK(fixture.result());
            fixture.client->begin(1);
            // Refresh identity replacement must return identity failure and preserve the original identity.
            auto changed = fixture.result();
            CHECK(!changed && changed.error().code == Status::Code::Identity);
            CHECK(!fixture.authority.requestChanged && fixture.authority.registrations == 1 && fixture.authority.queries == 1 && !fixture.client->revoked());
        }
        for (const auto scenario : {Scenario::Revoked, Scenario::DirectoryOutage}) {
            Fixture fixture(*identity, scenario);
            fixture.client->begin(0);
            CHECK(fixture.result());
            fixture.client->begin(0);
            CHECK(!fixture.result());
            CHECK(fixture.client->revoked() == (scenario == Scenario::Revoked));
            CHECK(fixture.authority.registrations == 1 && fixture.authority.queries == 1);
        }
        for (auto scenario : {Scenario::ExcessiveMembers, Scenario::WrongIdentity, Scenario::OversizedReply, Scenario::EmptyMember, Scenario::ReplyLimit, Scenario::RequestLimit, Scenario::InvalidPulse}) {
            Fixture fixture(*identity, scenario);
            fixture.client->begin(0);
            // Complete scenario result checked against its specific expected error category.
            auto result = fixture.result();
            CHECK(!result);
            // Distinguishes capacity from identity failures; arbitrary failure is insufficient.
            const bool capacity = scenario == Scenario::ExcessiveMembers || scenario == Scenario::OversizedReply || scenario == Scenario::ReplyLimit || scenario == Scenario::RequestLimit;
            CHECK(result.error().code == (capacity ? Status::Code::Capacity : Status::Code::Identity));
            if (scenario == Scenario::RequestLimit) {
                CHECK(fixture.authority.registrations == 0);
            }
        }
        for (auto scenario : {Scenario::RegistrationDeadline}) {
            Fixture fixture(*identity, scenario);
            // Start of the whole attempt; successful connection must not reset total handshake budget.
            const auto start = Steady::now();
            fixture.client->begin(0);
            // Complete scenario result checked against its specific expected error category.
            auto result = fixture.result();
            CHECK(!result && result.error().code == Status::Code::Timeout);
            // Registration still has a total deadline after connection succeeds.
            CHECK(Steady::now() - start < Milliseconds(6500));
            CHECK(fixture.authority.registrations == 1U);
        }
        {
            Fixture fixture(*identity, Scenario::Cancellation);
            fixture.client->begin(0);
            // Monotonic hard limit prevents cleanup or polling from hanging after assertion failure.
            const auto deadline = Steady::now() + std::chrono::seconds(3);
            while (fixture.authority.registrations == 0 && Steady::now() < deadline) {
                CHECK(!fixture.client->poll());
                std::this_thread::sleep_for(Milliseconds(1));
            }
            CHECK(fixture.authority.registrations == 1);
            fixture.client->cancel();
            // Complete scenario result checked against its specific expected error category.
            auto result = fixture.result();
            CHECK(!result && result.error().code == Status::Code::Cancelled);
        }
        std::cout << "PASS single RPC and retained startup request, reply limits, identity mismatch and in-flight cancellation\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
