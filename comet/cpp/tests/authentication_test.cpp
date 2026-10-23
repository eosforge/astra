// Replay a login completion arriving after session inspection but before idle-reader selection.
#include "check.hpp"
#include "core.hpp"
#include "observing.hpp"
#include "reading.hpp"
#include "subscribing.hpp"

#include <grpcpp/server_builder.h>

#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <string_view>
#include <thread>

namespace comet::detail {
/// Drive private control phases while native RPC callbacks retain their normal synchronization.
class Probe {
public:
    /// Advance connection establishment without starting an uncontrolled Alarm loop.
    static void dial(const std::shared_ptr<Core>& core) {
        static_cast<void>(core->dial(std::chrono::steady_clock::now()));
    }

    /// Consume the preceding wake before inspecting Session, as the control loop does.
    static void session(const std::shared_ptr<Core>& core) {

        {
            const std::lock_guard lock(core->mutex_);
            core->awakened_ = false;
        }
        static_cast<void>(core->session(std::chrono::steady_clock::now()));
    }

    /// Wait for the next native read/final callback without advancing Session again.
    static bool wake(const std::shared_ptr<Core>& core) {
        std::unique_lock lock(core->mutex_);
        return core->condition_.wait_for(lock, std::chrono::seconds(5), [&core] { return core->awakened_; });
    }

    /// Stage the reachable directory result: the wake was consumed before its login result.
    static void consume(const std::shared_ptr<Core>& core) {
        const std::lock_guard lock(core->mutex_);
        CHECK(!core->running_ && !core->scheduled_ && !core->binding_ && !core->blocked_);
        CHECK(core->refresh_ && core->awakened_ && core->login_);
        core->refresh_ = false;
        core->ready_.clear();
        core->due_ = Core::Time::max();
    }

    /// Resume the actual control loop; subsequent scheduling and cleanup are unmodified.
    static void tick(const std::shared_ptr<Core>& core) {
        core->tick();
    }

    /// Observe a completed control round, not merely receipt of a transport notification.
    static bool settled(const std::shared_ptr<Core>& core, Error::Code code) {
        const std::lock_guard lock(core->mutex_);
        return !core->running_ && core->blocked_ && core->blocked_->code == code;
    }
};
} // namespace comet::detail

namespace {
using namespace std::chrono_literals;

/// Bound transport setup waits without using elapsed time as the correctness oracle.
void eventually(auto&& condition) {
    const auto limit = std::chrono::steady_clock::now() + 5s;
    while (!condition()) {
        CHECK(std::chrono::steady_clock::now() < limit);
        std::this_thread::sleep_for(1ms);
    }
}

/// Hold the first response until the test has inspected the still-pending Session.
class Gateway final : public proto::comet::v1::Gateway::Service {
public:
    /// Select a terminal status or a malformed first confirmation; no business RPC is accepted.
    explicit Gateway(std::string_view mode) : mode_(mode) {}

    /// Keep request ownership inside the synchronous handler until its bounded gate is released.
    grpc::Status Session(grpc::ServerContext*, const proto::comet::v1::SessionRequest*, grpc::ServerWriter<proto::comet::v1::SessionReply>* writer) override {

        std::unique_lock lock(mutex_);
        entered_ = true;
        changed_.notify_all();
        if (!changed_.wait_for(lock, 5s, [this] { return released_; })) {
            return {grpc::StatusCode::DEADLINE_EXCEEDED, "Unreleased test gate"};
        }
        lock.unlock();

        if (mode_ == "protocol") {
            const proto::comet::v1::SessionReply invalid;
            if (!writer->Write(invalid)) {
                return {grpc::StatusCode::CANCELLED, "Test response cancelled"};
            }
            return grpc::Status::OK;
        }
        return {mode_ == "session" ? grpc::StatusCode::UNAUTHENTICATED : grpc::StatusCode::INVALID_ARGUMENT, "Controlled login rejection"};
    }

    /// Report actual receipt of the unique attempt before the test releases its response.
    bool entered() const {
        const std::lock_guard lock(mutex_);
        return entered_;
    }

    /// Release both successful execution and exceptional fixture teardown.
    void release() {
        const std::lock_guard lock(mutex_);
        released_ = true;
        changed_.notify_all();
    }

private:
    /// Borrow the case name for this fixture's lifetime.
    const std::string_view mode_;
    /// Protect the two one-way transport gates.
    mutable std::mutex mutex_;
    /// Wake the bounded synchronous handler.
    std::condition_variable changed_;
    /// The server has entered its first Session call.
    bool entered_{};
    /// The test has allowed the first response to complete.
    bool released_{};
};

/// Drain the client before destroying its independent loopback server, including assertion failures.
class Fixture {
public:
    /// Bind an ephemeral port and preserve the SDK's default operation deadline.
    explicit Fixture(std::string_view mode) : gateway(mode) {

        grpc::ServerBuilder builder;
        builder.RegisterService(&gateway);
        int port{};
        builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
        server_ = builder.BuildAndStart();
        CHECK(server_ && port > 0);

        comet::Client::Options options;
        options.endpoints = {"127.0.0.1:" + std::to_string(port)};
        options.auth = true;
        options.tls = false;
        options.key = "test";
        options.secret = {42};
        const auto prepared = comet::detail::Core::prepare(std::move(options));
        CHECK(prepared);
        core = *prepared;
    }

    /// Join actual callback completion; no failed test leaves an orphan client or blocked handler.
    ~Fixture() {

        gateway.release();
        if (core) {
            core->close();
            if (!started_) {
                comet::detail::Probe::tick(core);
            }
            if (!core->wait(5s)) {
                std::terminate();
            }
        }
        server_->Shutdown(std::chrono::system_clock::now() + 2s);
        server_->Wait();
    }

    /// Hand the already-staged phase back to the ordinary Alarm-controlled runtime.
    void start() {
        started_ = true;
        comet::detail::Probe::tick(core);
    }

    /// Transport gate; it outlives the server and all client callbacks.
    Gateway gateway;
    /// Real shared SDK state, never patched with a fabricated login result.
    std::shared_ptr<comet::detail::Core> core;

private:
    /// Destroy the server only after its handlers and client have drained.
    std::unique_ptr<grpc::Server> server_;
    /// Prevent a second manual control entry after normal scheduling has begun.
    bool started_{};
};

/// A consumed pre-transition wake must not strand any idle domain after a permanent login error.
void rejection(std::string_view mode) {

    Fixture fixture(mode);
    const auto reader = fixture.core->reader({"routes", "main"}, {}, {});
    const auto subscriber = fixture.core->subscriber({"routes", "main"}, {}, {});
    const auto observer = fixture.core->observer({"routes", "main"}, {}, {});
    CHECK(reader && subscriber && observer);
    eventually([&] {
        comet::detail::Probe::dial(fixture.core);
        return fixture.gateway.entered();
    });

    // These are the real idle poll results of a directory pass before authentication completes.
    const auto now = std::chrono::steady_clock::now();
    CHECK((*reader)->poll(now, {}, {}, false) == comet::detail::Core::Time::max());
    CHECK((*subscriber)->poll(now, {}, {}, false) == comet::detail::Core::Time::max());
    CHECK((*observer)->poll(now, {}, {}, false) == comet::detail::Core::Time::max());
    CHECK((*reader)->load().state() == comet::Reader::State::Waiting);
    CHECK((*subscriber)->load().state() == comet::Subscriber::State::Waiting);
    CHECK((*observer)->load().state() == comet::Observer::State::Waiting);

    comet::detail::Probe::session(fixture.core);
    fixture.gateway.release();
    CHECK(comet::detail::Probe::wake(fixture.core));
    if (mode != "protocol") {
        // Consume EOF to release the native read hold, then wait for the real OnDone callback.
        comet::detail::Probe::session(fixture.core);
        CHECK(comet::detail::Probe::wake(fixture.core));
    }
    comet::detail::Probe::consume(fixture.core);
    std::cout << "COMET-AUTH consumed " << mode << std::endl;
    fixture.start();

    const auto code = mode == "session" ? comet::Error::Code::Session : mode == "input" ? comet::Error::Code::Input
                                                                                        : comet::Error::Code::Protocol;
    eventually([&] { return comet::detail::Probe::settled(fixture.core, code); });
    const auto first = (*reader)->load();
    const auto second = (*subscriber)->load();
    const auto third = (*observer)->load();
    CHECK(first.state() == comet::Reader::State::Failed && first.error() && first.error()->code == code);
    CHECK(second.state() == comet::Subscriber::State::Failed && second.error() && second.error()->code == code);
    CHECK(third.state() == comet::Observer::State::Failed && third.error() && third.error()->code == code);
    CHECK(!first.version() && !second.version() && !third.version());
    CHECK(fixture.core->exceptions() == 0);
    std::cout << "COMET-AUTH passed " << mode << std::endl;
}
} // namespace

/// Isolate each controlled interleaving so one failure cannot prevent the other observations.
int main(int argc, char** argv) {
    try {
        CHECK(argc == 2);
        const std::string_view mode(argv[1]);
        CHECK(mode == "session" || mode == "input" || mode == "protocol");
        rejection(mode);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
