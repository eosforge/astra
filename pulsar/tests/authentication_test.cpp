// Verify authority refusal, four-slot KDF ownership and cancellation through owned TLS calls.
#include "authority.hpp"
#include "orbit.grpc.pb.h"
#include "pulsar_test.hpp"

#include <grpc/support/time.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/server_builder.h>
#include <openssl/curve25519.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <condition_variable>
#include <future>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace astra;
using namespace std::chrono_literals;

namespace {
/// Coordinate real KDF calls; only explicit native failure injection changes their return value.
class Derivation {
public:
    /// Select real computation, a controlled in-flight barrier, or a failed native result.
    enum class Mode {
        /// Execute the unchanged PBKDF2 primitive and return its actual result.
        Real,
        /// Retain the real digest from a separately accepted credential for the failure counterexample.
        Known,
        /// Hold admitted computations until the owner releases the barrier.
        Held,
        /// Compute the real digest, then return failure to test fail-closed classification.
        Failed,
    };

    /// Begin a new isolated scenario only after every earlier primitive has returned.
    void arm(Mode mode = Mode::Real) {
        const std::lock_guard lock(mutex_);
        CHECK(active_ == 0);
        mode_ = mode;
        open_ = false;
        calls_ = failures_ = 0;
        valid_ = true;
        expired_ = false;
    }

    /// Record actual entry and wait at a bounded barrier, without throwing across the C ABI.
    Mode enter(bool valid) {

        std::unique_lock lock(mutex_);
        ++calls_;
        ++active_;
        valid_ = valid_ && valid;
        changed_.notify_all();
        if (mode_ == Mode::Held && !changed_.wait_for(lock, 30s, [&] { return open_; })) {
            expired_ = true;
        }
        return mode_;
    }

    /// Record completed primitives and deliberately injected native failures.
    void leave(Mode mode, int result, const std::uint8_t* output) {
        const std::lock_guard lock(mutex_);
        valid_ = valid_ && result == 1;
        if (mode == Mode::Known) {
            std::copy_n(output, expected_.size(), expected_.begin());
            known_ = true;
        } else if (mode == Mode::Failed) {
            valid_ = valid_ && known_ && std::equal(expected_.begin(), expected_.end(), output);
        }
        --active_;
        failures_ += mode == Mode::Failed;
        changed_.notify_all();
    }

    /// Require exactly the declared number of simultaneous admitted primitives.
    void wait(unsigned count) {
        std::unique_lock lock(mutex_);
        CHECK(changed_.wait_for(lock, 30s, [&] { return active_ >= count; }));
        CHECK(active_ == count && calls_ == count && !expired_ && valid_);
    }

    /// Release all borrowed calls before their contexts, threads or service can be destroyed.
    void release() {
        const std::lock_guard lock(mutex_);
        open_ = true;
        changed_.notify_all();
    }

    /// Check both the exercised primitive count and complete resource return.
    void verify(unsigned calls, unsigned failures = 0) {
        const std::lock_guard lock(mutex_);
        CHECK(calls_ == calls && failures_ == failures && active_ == 0 && !expired_ && valid_);
    }

private:
    /// Protect scenario counters and the test-only primitive barrier.
    std::mutex mutex_;
    /// Notify actual entry, release and retirement rather than sleeping to guess progress.
    std::condition_variable changed_;
    /// Current scenario; the owner changes it only when no primitive remains in flight.
    Mode mode_ = Mode::Real;
    /// Whether held primitives may continue computing their real digest.
    bool open_{};
    /// Whether every call retained SHA256/600000 and the 16/32-byte salt/output sizes.
    bool valid_ = true;
    /// A barrier deadline is a fixture failure, never successful scheduling evidence.
    bool expired_{};
    /// The retained digest is from public fixture credentials accepted before fault injection.
    std::array<std::uint8_t, 32> expected_{};
    /// No matching-output failure claim is valid until the independent baseline has executed.
    bool known_{};
    /// Actual entries, outstanding computations and injected native failures.
    unsigned calls_{}, active_{}, failures_{};
};

/// The isolated executable owns one primitive scheduler; shipping binaries do not link these wrappers.
Derivation derivation;
/// Restrict signature failure injection to the calling test thread, excluding TLS workers.
thread_local bool failSigning{};
/// Count deliberate signing failures without inspecting or reporting private material.
thread_local unsigned signingFailures{};

/// Expose authentication through a real server context while retaining its pre-transport result.
class Service final : public proto::orbit::v1::Admission::Service {
public:
    /// Borrow the immutable authority until every owned handler has drained.
    explicit Service(const Authority& authority) : authority_(authority) {}

    /// Preserve the actual authority status separately from client-side cancellation.
    grpc::Status Register(grpc::ServerContext* context, const proto::orbit::v1::RegistrationRequest* request, proto::orbit::v1::RegistrationResponse*) override {

        const auto name = request->request_id();
        {
            std::unique_lock lock(mutex_);
            contexts_.emplace(name, context);
            changed_.notify_all();
            if (!changed_.wait_for(lock, 30s, [&] { return !held_; })) {
                expired_ = true;
            }
        }

        // The result is observed before gRPC can replace it with a transport cancellation.
        const auto status = authority_.authenticate(*context, *request);
        {
            const std::lock_guard lock(mutex_);
            results_.emplace(name, status.error_code());
            contexts_.erase(name);
            changed_.notify_all();
        }
        return status;
    }

    /// Hold the next handler before authority entry to test the first cancellation boundary.
    void hold() {
        const std::lock_guard lock(mutex_);
        CHECK(contexts_.empty());
        held_ = true;
    }

    /// Release handlers before shutting down their shared server.
    void release() {
        const std::lock_guard lock(mutex_);
        held_ = false;
        changed_.notify_all();
    }

    /// Wait until a real handler owns the named request context.
    void entered(const std::string& name) {
        std::unique_lock lock(mutex_);
        CHECK(changed_.wait_for(lock, 30s, [&] { return contexts_.contains(name); }));
        CHECK(!expired_);
    }

    /// Observe cancellation on the server before releasing either controlled barrier.
    void cancelled(const std::string& name) {

        const auto limit = std::chrono::steady_clock::now() + 10s;
        while (std::chrono::steady_clock::now() < limit) {
            {
                const std::lock_guard lock(mutex_);
                const auto found = contexts_.find(name);
                CHECK(found != contexts_.end());
                if (found->second->IsCancelled()) {
                    return;
                }
            }
            std::this_thread::yield();
        }
        CHECK(false && "Server did not observe the owned cancellation");
    }

    /// Check handler retirement and the authority's exact result, not just the client status.
    void finished(const std::string& name, grpc::StatusCode expected) {
        std::unique_lock lock(mutex_);
        CHECK(changed_.wait_for(lock, 30s, [&] { return results_.contains(name); }));
        CHECK(!contexts_.contains(name) && results_.at(name) == expected && !expired_);
        results_.erase(name);
    }

private:
    /// The fixture owns this immutable authority beyond the service and all handlers.
    const Authority& authority_;
    /// Protect borrowed contexts, completed statuses and the pre-authentication barrier.
    std::mutex mutex_;
    /// Notify native handler entry and completion to the controlling test thread.
    std::condition_variable changed_;
    /// Live contexts keyed by unique public scenario name; borrowing ends before handler return.
    std::map<std::string, grpc::ServerContext*> contexts_;
    /// Actual authority results waiting for the independent scenario oracle.
    std::map<std::string, grpc::StatusCode> results_;
    /// The next handler may be paused before any password or permit work.
    bool held_{};
    /// An expired fixture wait must invalidate every later completion observation.
    bool expired_{};
};

/// Own one finite RPC, cancelling and joining before releasing its context and buffers.
class Call {
public:
    /// Copy the input and start one TLS request using a stub that outlives this object.
    Call(proto::orbit::v1::Admission::Stub& stub, Service& service, proto::orbit::v1::RegistrationRequest request) : service_(service), request_(std::move(request)) {
        context_.set_deadline(gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC), gpr_time_from_seconds(45, GPR_TIMESPAN)));
        result_ = std::async(std::launch::async, [&stub, this] { return stub.Register(&context_, request_, &response_); });
    }

    /// Unwind both test barriers before joining, including after an assertion fails.
    ~Call() {
        context_.TryCancel();
        derivation.release();
        service_.release();
        if (result_.valid()) {
            result_.wait();
        }
    }

    /// Request cancellation without pretending that server-side cleanup is already complete.
    void cancel() {
        context_.TryCancel();
    }

    /// Require the exact transport result, a drained handler and no partially issued credential.
    void finish(grpc::StatusCode expected) {
        CHECK(result_.wait_for(45s) == std::future_status::ready);
        CHECK(result_.get().error_code() == expected);
        CHECK(response_.admission().empty() && response_.signature().empty() && response_.members_size() == 0);
        service_.finished(request_.request_id(), expected);
    }

private:
    /// Keep the service's barriers reachable until every local call has joined.
    Service& service_;
    /// Each call independently owns its request, response, context and asynchronous completion.
    proto::orbit::v1::RegistrationRequest request_;
    /// Own the registration response while the asynchronous client request is in flight.
    proto::orbit::v1::RegistrationResponse response_;
    /// Own client deadline and cancellation state until the request future completes.
    grpc::ClientContext context_;
    /// Join the actual registration RPC and retain its transport result.
    std::future<grpc::Status> result_;
};

/// Own the endpoint and TLS stub without altering deployed listeners or authority files.
class Fixture {
public:
    /// Build a service with enough workers to observe the fifth refusal while four KDFs are held.
    explicit Fixture(const Authority& authority) : service(authority) {

        const auto loaded = Identity::load(std::filesystem::path(ASTRA_FIXTURES) / "star-a", *Endpoint::parse("127.0.0.1:7443"));
        CHECK(loaded);
        identity_ = *loaded;
        grpc::ServerBuilder builder;
        builder.RegisterService(&service);
        builder.AddChannelArgument("grpc.so_reuseport", 0);
        builder.SetMaxReceiveMessageSize(4096);
        builder.SetSyncServerOption(grpc::ServerBuilder::SyncServerOption::MAX_POLLERS, 8);
        grpc::ResourceQuota quota;
        quota.Resize(16 * 1024 * 1024);
        quota.SetMaxThreads(16);
        builder.SetResourceQuota(quota);
        int port = 0;
        builder.AddListeningPort("127.0.0.1:0", authority.identity().serverCredentials(), &port);
        server_ = builder.BuildAndStart();
        CHECK(server_ && port > 0);
        stub = proto::orbit::v1::Admission::NewStub(grpc::CreateChannel("127.0.0.1:" + std::to_string(port), identity_->channelCredentials()));
    }

    /// Release all injected waits, stop admission and drain handlers before authority destruction.
    ~Fixture() {
        derivation.release();
        service.release();
        if (server_) {
            server_->Shutdown(std::chrono::system_clock::now() + 5s);
            server_->Wait();
        }
    }

    /// Use only public fixture credentials and a stable nonsecret scenario identity.
    proto::orbit::v1::RegistrationRequest request(std::string_view name) const {
        proto::orbit::v1::RegistrationRequest request;
        request.set_username(identity_->username());
        request.set_password(identity_->password());
        request.set_role(proto::orbit::v1::ROLE_STAR);
        request.set_request_id(std::string(name));
        return request;
    }

    /// Direct access is limited to the test's scheduling and result oracle.
    Service service;
    /// The owned TLS stub remains alive until every Call has finished.
    std::unique_ptr<proto::orbit::v1::Admission::Stub> stub;

private:
    /// Keep public client material alive while channels use its credential provider.
    std::shared_ptr<Identity> identity_;
    /// Own the ephemeral listener and all server workers, draining them in the destructor.
    std::unique_ptr<grpc::Server> server_;
};

/// Emit a stable scenario name only after its independent assertions and cleanup pass.
void observed(std::string_view name) {
    std::cout << "PULSAR-AUTHENTICATION {\"case\":\"" << name << "\"}\n";
}

/// Check malformed inputs before any KDF, and unchanged real KDF behavior for valid-shaped inputs.
void requests(Fixture& fixture) {

    for (const auto name : {"empty-name", "long-name", "invalid-name", "nul-name", "empty-password", "long-password"}) {
        auto request = fixture.request(name);
        if (std::string_view(name) == "empty-name") {
            request.clear_username();
        } else if (std::string_view(name) == "long-name") {
            request.set_username(std::string(65, 'a'));
        } else if (std::string_view(name) == "invalid-name") {
            request.set_username("not/allowed");
        } else if (std::string_view(name) == "nul-name") {
            request.set_username(std::string("bad\0name", 8));
        } else if (std::string_view(name) == "empty-password") {
            request.clear_password();
        } else {
            request.set_password(std::string(1025, 'p'));
        }
        derivation.arm();
        Call call(*fixture.stub, fixture.service, std::move(request));
        call.finish(grpc::StatusCode::UNAUTHENTICATED);
        derivation.verify(0);
        observed(name);
    }

    for (const auto name : {"valid", "wrong-password", "missing-account", "password-boundary", "name-boundary", "denied-role", "unknown-role", "kdf-failure", "after-kdf-failure"}) {
        auto request = fixture.request(name);
        auto expected = grpc::StatusCode::OK;
        const auto failed = std::string_view(name) == "kdf-failure";
        if (std::string_view(name) == "wrong-password" || std::string_view(name) == "password-boundary") {
            request.set_password(std::string(std::string_view(name) == "password-boundary" ? 1024 : 1, 'p'));
            expected = grpc::StatusCode::UNAUTHENTICATED;
        } else if (std::string_view(name) == "missing-account" || std::string_view(name) == "name-boundary") {
            request.set_username(std::string(std::string_view(name) == "name-boundary" ? 64 : 1, 'z'));
            expected = grpc::StatusCode::UNAUTHENTICATED;
        } else if (std::string_view(name) == "denied-role" || std::string_view(name) == "unknown-role") {
            request.set_role(std::string_view(name) == "denied-role" ? proto::orbit::v1::ROLE_PLANET : static_cast<proto::orbit::v1::Role>(999));
            expected = grpc::StatusCode::PERMISSION_DENIED;
        } else if (failed) {
            expected = grpc::StatusCode::UNAUTHENTICATED;
        }
        derivation.arm(failed ? Derivation::Mode::Failed : std::string_view(name) == "valid" ? Derivation::Mode::Known
                                                                                             : Derivation::Mode::Real);
        Call call(*fixture.stub, fixture.service, std::move(request));
        call.finish(expected);
        derivation.verify(1, failed ? 1 : 0);
        observed(name);
    }
}

/// Force cancellation on both sides of the real KDF and verify each permit is returned.
void cancellation(Fixture& fixture) {

    for (const auto before : {true, false}) {
        const std::string name = before ? "cancel-before-kdf" : "cancel-after-kdf";
        derivation.arm(before ? Derivation::Mode::Real : Derivation::Mode::Held);
        if (before) {
            fixture.service.hold();
        }
        {
            Call call(*fixture.stub, fixture.service, fixture.request(name));
            fixture.service.entered(name);
            if (!before) {
                derivation.wait(1);
            }
            call.cancel();
            fixture.service.cancelled(name);
            derivation.release();
            fixture.service.release();
            call.finish(grpc::StatusCode::CANCELLED);
        }
        derivation.verify(before ? 0 : 1);
        observed(name);
    }
}

/// All four permits must be reusable after success, native failure and cancelled computation.
void capacity(Fixture& fixture, std::string_view scenario, bool cancel) {

    const std::string name(scenario);
    derivation.arm(Derivation::Mode::Held);
    std::vector<std::unique_ptr<Call>> calls;
    for (unsigned index = 0; index != 4; ++index) {
        calls.push_back(std::make_unique<Call>(*fixture.stub, fixture.service, fixture.request(name + '-' + std::to_string(index))));
    }
    derivation.wait(4);
    {
        Call refused(*fixture.stub, fixture.service, fixture.request(name + "-refused"));
        refused.finish(grpc::StatusCode::RESOURCE_EXHAUSTED);
        // Keep the held cohort alive while checking rejection; the fifth request must never enter KDF.
        derivation.wait(4);
        if (cancel) {
            calls[0]->cancel();
            fixture.service.cancelled(name + "-0");
        }
        derivation.release();
    }
    for (unsigned index = 0; index != calls.size(); ++index) {
        calls[index]->finish(cancel && index == 0 ? grpc::StatusCode::CANCELLED : grpc::StatusCode::OK);
    }
    calls.clear();
    derivation.verify(4);
    observed(name);
}
} // namespace

/// Linker-provided original primitive with the exact installed BoringSSL declaration.
extern "C" decltype(PKCS5_PBKDF2_HMAC) __real_PKCS5_PBKDF2_HMAC;
/// Linker-provided original signing function, untouched outside an explicit test injection.
extern "C" decltype(ED25519_sign) __real_ED25519_sign;

/// Preserve real password work and parameters; the controlled failure occurs after producing the correct digest.
extern "C" int __wrap_PKCS5_PBKDF2_HMAC(const char* password, std::size_t passwordLength, const std::uint8_t* salt, std::size_t saltLength, std::uint32_t iterations, const EVP_MD* digest, std::size_t length, std::uint8_t* output) {
    const auto mode = derivation.enter(saltLength == 16 && iterations == 600000 && digest == EVP_sha256() && length == 32);
    const auto result = __real_PKCS5_PBKDF2_HMAC(password, passwordLength, salt, saltLength, iterations, digest, length, output);
    derivation.leave(mode, result, output);
    return mode == Derivation::Mode::Failed ? 0 : result;
}

/// Fail only the owned main-thread signing operation; TLS worker signatures keep their real implementation.
extern "C" int __wrap_ED25519_sign(std::uint8_t* signature, const std::uint8_t* message, std::size_t length, const std::uint8_t* key) {
    if (failSigning) {
        ++signingFailures;
        return 0;
    }
    return __real_ED25519_sign(signature, message, length, key);
}

namespace astra::test {
/// Exercise bounded real scalar-allocation failures independently of the TLS scheduling cases.
void allocation();
} // namespace astra::test

/// Keep native injections inside this Linux executable and drain RPCs before unloading authority state.
int main(int argc, char** argv) {

    try {
        if (argc == 2 && std::string_view(argv[1]) == "allocation") {
            test::allocation();
            return 0;
        }
        CHECK(argc == 1);
        const auto endpoint = *Endpoint::parse("127.0.0.1:7443");
        auto authority = Authority::load(std::filesystem::path(ASTRA_FIXTURES) / "pulsar", endpoint, endpoint);
        CHECK(authority && *authority);
        Fixture fixture(**authority);
        requests(fixture);
        cancellation(fixture);
        capacity(fixture, "capacity-success", false);
        capacity(fixture, "capacity-cancel", true);
        capacity(fixture, "capacity-reused", false);

        // Signing failure must throw before publication; a subsequent real signature must still verify.
        const proto::orbit::v1::Member member;
        proto::orbit::v1::RegistrationResponse response;
        failSigning = true;
        bool refused = false;
        try {
            (*authority)->sign(member, response);
        } catch (const std::runtime_error& error) {
            refused = std::string_view(error.what()) == "Admission signing failed";
        }
        failSigning = false;
        CHECK(refused && signingFailures == 1 && response.signature().empty());
        observed("signing-failure");
        (*authority)->sign(member, response);
        const auto key = test::read(std::filesystem::path(ASTRA_FIXTURES) / "pulsar/admission.pub");
        const auto bytes = std::string(admissionSignatureDomain) + '\0' + response.admission();
        CHECK(key.size() == 32 && response.signature().size() == 64);
        CHECK(ED25519_verify(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size(), reinterpret_cast<const std::uint8_t*>(response.signature().data()), reinterpret_cast<const std::uint8_t*>(key.data())) == 1);
        observed("after-signing-failure");
        test::allocation();
        std::cout << "PULSAR-AUTHENTICATION {\"complete\":true}\n";
        return 0;
    } catch (const std::exception& error) {
        failSigning = false;
        std::cerr << error.what() << '\n';
        return 1;
    }
}
