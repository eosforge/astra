// Verify that real Core resource claims delay close completion until their matching return, without starting transport.
#include "check.hpp"
#include "core.hpp"

#include <chrono>
#include <exception>
#include <iostream>
#include <memory>
#include <string_view>
#include <utility>

namespace comet::detail {
/// Exercise existing lifecycle operations through the already declared test friend; no production fields or hooks are changed.
class Probe {
public:
    /// Claim exactly one real resource in the selected domain before closing its owner.
    static bool claim(const std::shared_ptr<Core>& core, unsigned domain) {
        switch (domain) {
        case 0:
            return core->claim();
        case 1:
            return core->outgoing(false, false);
        case 2:
            return core->outgoing(true, false);
        case 3:
            return core->outgoing(false, true);
        default:
            return core->admitting();
        }
    }

    /// Return the same resource once, using the actual completion operation rather than editing a counter.
    static void release(const std::shared_ptr<Core>& core, unsigned domain) noexcept {
        switch (domain) {
        case 0:
            core->relinquish();
            break;
        case 1:
            core->returning(false, false);
            break;
        case 2:
            core->returning(true, false);
            break;
        case 3:
            core->returning(false, true);
            break;
        default:
            core->settled();
            break;
        }
        core->wake();
    }

    /// The first and only explicit control step occurs after close, so it cannot start any dial or RPC.
    static void step(const std::shared_ptr<Core>& core) {
        core->tick();
    }
};
} // namespace comet::detail

namespace {
using namespace std::chrono_literals;

/// A live claim must not be mistaken for cancellation intent; return it even after a rejected assertion.
class Claim {
public:
    /// Own one existing Core claim through the refusal and recovery observations.
    Claim(std::shared_ptr<comet::detail::Core> core, unsigned domain) : core_(std::move(core)), domain_(domain) {
        CHECK(comet::detail::Probe::claim(core_, domain_));
    }

    /// Prevent an assertion failure from leaking a claim into a scheduled close callback.
    ~Claim() {
        release();
    }

    /// Matching completion is idempotent in this guard, without claiming the underlying return operation is idempotent.
    void release() noexcept {
        if (held_) {
            held_ = false;
            comet::detail::Probe::release(core_, domain_);
        }
    }

private:
    /// Keep the actual owner alive until the matching native return has completed.
    const std::shared_ptr<comet::detail::Core> core_;
    /// Domain selected from the fixed five-entry contract alphabet.
    const unsigned domain_;
    /// Only this guard owns the one pending return.
    bool held_ = true;
};

/// Apply the same externally stated drain contract to each independent resource class.
void scenario(unsigned domain, std::string_view name) {

    std::cout << "COMET-DRAIN {\"case\":\"" << name << "\",\"begin\":true}\n"
              << std::flush;
    comet::Client::Options options;
    options.endpoints = {"127.0.0.1:1"};
    options.auth = false;
    options.tls = false;
    auto prepared = comet::detail::Core::prepare(std::move(options));
    CHECK(prepared);
    const auto core = std::move(*prepared);
    Claim pending(core, domain);
    core->close();
    CHECK(core->stopped());
    comet::detail::Probe::step(core);
    CHECK(!core->wait(0ms));
    pending.release();
    CHECK(core->wait(3s));
    CHECK(core->exceptions() == 0);
    std::cout << "COMET-DRAIN {\"case\":\"" << name << "\",\"blocked_while_claimed\":true,\"completed_after_return\":true}\n"
              << std::flush;
}
} // namespace

/// Select the complete new five-domain fixture or its single unary counterexample for the fixed mutant.
int main(int argc, char** argv) {
    try {
        CHECK(argc == 2);
        const std::string_view selected(argv[1]);
        CHECK(selected == "all" || selected == "unary");
        constexpr std::string_view names[] = {"watch", "unary", "maintenance", "recovery", "admission"};
        for (unsigned domain = 0; domain < 5; ++domain) {
            if (selected == "all" || names[domain] == selected) {
                scenario(domain, names[domain]);
            }
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
