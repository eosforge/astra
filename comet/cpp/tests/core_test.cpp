// Force last-owner destruction at each Core inspection boundary and verify safe reentry.
#include "check.hpp"
#include "core.hpp"

#include <atomic>
#include <functional>
#include <iostream>
#include <latch>
#include <string_view>
#include <thread>

namespace comet::detail {
// Access private control steps without starting a network, adding hooks, or relaxing checks.
class Probe {
public:
    static Result<void> accept(const std::shared_ptr<Core>& core, const std::shared_ptr<Activity>& object) {
        return core->accept(object);
    }

    static void session(const std::shared_ptr<Core>& core) {
        core->closing_ = true;
        static_cast<void>(core->session(std::chrono::steady_clock::now()));
    }

    static void tick(const std::shared_ptr<Core>& core, bool closing, bool ready) {
        core->closing_ = closing;
        core->refresh_ = !ready;
        core->due_ = ready ? Core::Time::max() : Core::Time{};
        core->retry_ = Core::Time::max(); // Exercise ownership only; no transport is created.
        core->tick();
    }
};
} // namespace comet::detail

namespace {
using namespace std::chrono_literals;

// A native latch makes the inspected reference become the last owner before inspection returns.
struct Gate {
    /// Inspector holds its temporary strong reference.
    std::latch entered{1};
    /// External owner has been reset by a joined worker.
    std::latch released{1};
    /// Exactly one forced ownership transition is required.
    std::atomic_uint hits{};
    /// Destruction must complete after locking Core again.
    std::atomic_uint destroyed{};

    void pause() {
        ++hits;
        std::cout << "COMET-HOLD entered" << std::endl;
        entered.count_down();
        released.wait();
    }
};

// This private activity models user capture destruction; its destructor reenters a locked Core query.
class Item final : public comet::detail::Activity {
public:
    Item(std::shared_ptr<comet::detail::Core> core, Gate* gate, unsigned point, bool count = false) : core_(std::move(core)), gate_(gate), point_(point), count_(count) {}

    ~Item() override {
        static_cast<void>(core_->schedule());
        if (gate_) {
            ++gate_->destroyed;
            std::cout << "COMET-HOLD destroyed" << std::endl;
        }
    }

    bool closed() const noexcept override {
        if (count_ && closed_.fetch_add(1) == 0) {
            gate_->pause();
        }
        return false;
    }

    bool finished() const noexcept override {
        const auto step = finished_.fetch_add(1) + 1;
        if (!count_ && gate_ && step == point_) {
            gate_->pause();
        }
        return gate_ && !count_ ? step >= point_ : done_.load();
    }

    bool streaming() const noexcept override {
        return true;
    }

    std::chrono::steady_clock::time_point poll(std::chrono::steady_clock::time_point, const std::shared_ptr<const comet::detail::Binding>&, const std::optional<comet::Error>&, bool) override {
        if (action) {
            action();
        }
        done_.store(true);
        return std::chrono::steady_clock::time_point::max();
    }

    std::function<void()> action; // Only the completion case admits an object during a control callback.

private:
    /// Reentry target outlives every forced destruction.
    const std::shared_ptr<comet::detail::Core> core_;
    /// Borrowed until the releasing worker is joined.
    Gate* const gate_;
    /// Finished-check ordinal at which external ownership ends.
    const unsigned point_;
    /// Admission counting probes closed() instead.
    const bool count_;
    /// Native inspection order, independent of real time.
    mutable std::atomic_uint finished_{};
    /// Admission's first live-object count is the selected boundary.
    mutable std::atomic_uint closed_{};
    /// The foreground callback has actually returned.
    std::atomic_bool done_{};
};

// Each boundary runs in its own CTest process, so the old deadlock cannot contaminate another case.
void boundary(std::string_view name) {

    comet::Client::Options options;
    options.endpoints = {"127.0.0.1:1"};
    options.auth = false;
    options.tls = false;
    auto prepared = comet::detail::Core::prepare(std::move(options));
    CHECK(prepared);
    const auto core = *prepared;
    Gate gate;
    const bool count = name == "count";
    const unsigned point = name == "directory" || name == "ready" ? 2 : 1;
    auto object = std::make_shared<Item>(core, &gate, point, count);
    const std::weak_ptr<Item> held = object;
    std::shared_ptr<Item> foreground;
    std::shared_ptr<Item> replacement;
    if (name == "complete") {
        foreground = std::make_shared<Item>(core, nullptr, 0);
        foreground->action = [core, held] {
            const auto next = held.lock();
            CHECK(next && comet::detail::Probe::accept(core, next));
            core->close(); // The actual final directory contains an object absent from this round's polling snapshot.
        };
        CHECK(comet::detail::Probe::accept(core, foreground));
    } else {
        CHECK(comet::detail::Probe::accept(core, object));
    }
    if (name == "retired" || count) {
        replacement = std::make_shared<Item>(core, nullptr, 0);
    }

    std::cout << "COMET-HOLD boundary " << name << std::endl;
    std::jthread releasing([&] {
        gate.entered.wait();
        object.reset();
        std::cout << "COMET-HOLD released" << std::endl;
        gate.released.count_down();
    });
    if (replacement) {
        CHECK(comet::detail::Probe::accept(core, replacement));
    } else if (name == "session") {
        comet::detail::Probe::session(core);
    } else {
        comet::detail::Probe::tick(core, name != "complete", name == "ready");
    }
    releasing.join();
    CHECK(gate.hits.load() == 1 && gate.destroyed.load() == 1 && held.expired());

    foreground.reset();
    replacement.reset();
    core->close();
    comet::detail::Probe::tick(core, true, false);
    CHECK(core->wait(0ms) && core->exceptions() == 0);
    std::cout << "COMET-HOLD passed " << name << std::endl;
}
} // namespace

// Select only a declared inspection boundary; CTest owns the failure timeout and child process.
int main(int argc, char** argv) {
    try {
        CHECK(argc == 2);
        const std::string_view name(argv[1]);
        CHECK(name == "retired" || name == "count" || name == "session" || name == "directory" || name == "ready" || name == "complete");
        boundary(name);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
