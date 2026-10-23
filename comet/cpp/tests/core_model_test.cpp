// Emit complete bounded Core admission/ownership histories for an independent oracle, without starting transport.
#include "check.hpp"
#include "core.hpp"

#include <array>
#include <barrier>
#include <chrono>
#include <cstddef>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace comet::detail {
/// Observe the real admission boundary through the existing test friend, without changing production behavior.
class Probe {
public:
    /// One locked Core observation; fixture ownership keeps every nonexpired address alive during conversion.
    struct State {
        /// Actual directory order, including null expired weak references.
        std::array<const Activity*, 32> directory{};
        /// Actual pending order, including null expired weak references.
        std::array<const Activity*, 32> queue{};
        /// Number of used directory entries.
        std::size_t entries{};
        /// Number of used pending entries.
        std::size_t pending{};
        /// Initial Client owner plus admitted application owners not yet returned.
        std::size_t owners{};
        /// Irreversible admission gate.
        bool closing{};
        /// Cross-object published stop gate, read while holding the same admission lock.
        bool stopped{};
    };

    /// Execute the actual production transition; candidates remain owned on both success and refusal.
    static Result<void> accept(const std::shared_ptr<Core>& core, const std::shared_ptr<Activity>& activity) {
        return core->accept(activity);
    }

    /// Capture bookkeeping under its real lock; no scheduler, clock step or artificial expected value is introduced.
    static State state(const std::shared_ptr<Core>& core) {

        const std::lock_guard lock(core->mutex_);
        State value;
        CHECK(core->readers_.size() <= value.directory.size() && core->ready_.size() <= value.queue.size());
        value.entries = core->readers_.size();
        value.pending = core->ready_.size();
        value.owners = core->owners_;
        value.closing = core->closing_;
        value.stopped = core->stopped();
        for (std::size_t index = 0; index < value.entries; ++index) {
            value.directory[index] = core->readers_[index].lock().get();
        }
        for (std::size_t index = 0; index < value.pending; ++index) {
            value.queue[index] = core->ready_[index].lock().get();
        }
        return value;
    }
};
} // namespace comet::detail

namespace {
/// Mimic only an application's one-time owner return and independent cleanup completion, never a real RPC.
class Item final : public comet::detail::Activity {
public:
    /// Bind a stable input identity before admission; streaming and automatic writes consume different quotas.
    Item(std::shared_ptr<comet::detail::Core> core, std::size_t id, bool streaming) : core_(std::move(core)), id_(id), streaming_(streaming) {}

    /// Dropping an accepted application intent returns its owner exactly once.
    ~Item() override {
        stop();
    }

    /// Record actual admission after its successful return; refusal never creates a release obligation.
    void admitted() noexcept {
        admitted_ = true;
    }

    /// Stop intent independently of cleanup; repeated calls have no further ownership effect.
    void stop() noexcept {
        if (admitted_ && !closed_) {
            closed_ = true;
            core_->release();
        }
    }

    /// Publish cleanup only after returning an accepted owner.
    void finish() noexcept {
        stop();
        finished_ = true;
    }

    /// Stable identity derives from the input position, never an allocator address.
    std::size_t id() const noexcept {
        return id_;
    }

    /// Read fixture intent only on the serial thread or after both admission workers have joined.
    bool admitted() const noexcept {
        return admitted_;
    }

    bool closed() const noexcept override {
        return closed_;
    }

    bool finished() const noexcept override {
        return finished_;
    }

    bool streaming() const noexcept override {
        return streaming_;
    }

    /// Any accidental control-loop start invalidates this transport-free fixture.
    std::chrono::steady_clock::time_point poll(std::chrono::steady_clock::time_point, const std::shared_ptr<const comet::detail::Binding>&, const std::optional<comet::Error>&, bool) override {
        throw std::logic_error("Core model must not start transport or control work");
    }

private:
    /// Target remains alive through the application's final release.
    const std::shared_ptr<comet::detail::Core> core_;
    /// One-based input identity, bounded by the fixed fixture slots.
    const std::size_t id_;
    /// Independent admission domain.
    const bool streaming_;
    /// Set only by the successful native admission return.
    bool admitted_{};
    /// Accepted application owner has been returned.
    bool closed_{};
    /// Eligible for directory and pending-queue removal at the next admission.
    bool finished_{};
};

/// Own one prepared, unstarted Core and every candidate used by this bounded history.
class Fixture {
public:
    /// Copy of actual bookkeeping; IDs remain valid even after the fixture later drops an object.
    struct State {
        /// Actual directory identities; zero denotes an expired weak reference.
        std::array<std::size_t, 32> directory{};
        /// Actual pending identities with the same expired-reference convention.
        std::array<std::size_t, 32> queue{};
        /// Used directory slots.
        std::size_t entries{};
        /// Used pending slots.
        std::size_t pending{};
        /// Actual application owner count.
        std::size_t owners{};
        /// Actual admission gate.
        bool closing{};
        /// Actual cross-object stop gate.
        bool stopped{};
    };

    /// Prepare asymmetric capacities through the normal production factory, without calling start.
    explicit Fixture(const std::array<std::size_t, 2>& limits) {

        comet::Client::Options options;
        options.endpoints = {"127.0.0.1:1"};
        options.auth = false;
        options.tls = false;
        options.readers = limits[0];
        options.beacons = limits[1];
        auto result = comet::detail::Core::prepare(std::move(options));
        CHECK(result);
        core_ = std::move(*result);
    }

    /// Finish fixture intents and release the original Client owner; no asynchronous task was ever started.
    ~Fixture() {
        for (const auto& item : items_) {
            if (item) {
                item->finish();
            }
        }
        release();
        core_->close();
    }

    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;

    /// Prepare a candidate before parallel work; all worker inputs and address mappings are then immutable.
    std::shared_ptr<Item> prepare(std::size_t id, bool streaming) {
        auto item = std::make_shared<Item>(core_, id, streaming);
        items_.at(id - 1) = item;
        return item;
    }

    /// Keep the real error category and application-effect classification, rejecting unknown values in the reader.
    std::string_view accept(const std::shared_ptr<Item>& item) {
        const auto result = comet::detail::Probe::accept(core_, item);
        if (result) {
            item->admitted();
            return "ok";
        }
        if (result.error().effect != comet::Error::Effect::Unapplied) {
            return "invalid-effect";
        }
        switch (result.error().code) {
        case comet::Error::Code::Busy:
            return "busy";
        case comet::Error::Code::Closed:
            return "closed";
        default:
            return "invalid-code";
        }
    }

    /// Apply one input; selection always uses the oldest qualifying live candidate, including refused candidates for drop/wake.
    std::string_view step(unsigned operation, std::size_t id) {

        if (operation < 2) {
            return accept(prepare(id, operation == 0));
        }
        if (operation == 6) {
            core_->close();
        } else if (operation == 7) {
            release();
        } else if (operation == 8) {
            const auto schedule = core_->schedule();
            return schedule.directory == 0 && schedule.ready == 0 && schedule.polled == 0 ? "idle" : "invalid-schedule";
        } else {
            for (auto& item : items_) {
                if (!item || (operation == 2 && (!std::as_const(*item).admitted() || item->closed())) || (operation == 3 && (!std::as_const(*item).admitted() || item->finished()))) {
                    continue;
                }
                if (operation == 2) {
                    item->stop();
                } else if (operation == 3) {
                    item->finish();
                } else if (operation == 4) {
                    item.reset();
                } else {
                    core_->wake(item.get());
                }
                break;
            }
        }
        return "none";
    }

    /// Read actual Core state without touching worker-written application intent flags.
    State state() const {

        const auto native = comet::detail::Probe::state(core_);
        State value;
        value.entries = native.entries;
        value.pending = native.pending;
        value.owners = native.owners;
        value.closing = native.closing;
        value.stopped = native.stopped;
        for (std::size_t index = 0; index < value.entries; ++index) {
            value.directory[index] = identity(native.directory[index]);
        }
        for (std::size_t index = 0; index < value.pending; ++index) {
            value.queue[index] = identity(native.queue[index]);
        }
        return value;
    }

    /// Emit a complete actual serial observation; fixture flags are accessed only after worker join.
    void emit(std::ostream& output) const {

        emit(output, state());
        output << ",\"items\":[";
        bool separator{};
        for (const auto& item : items_) {
            if (!item) {
                continue;
            }
            if (std::exchange(separator, true)) {
                output << ',';
            }
            output << '[' << item->id() << ',' << item->streaming() << ',' << std::as_const(*item).admitted() << ',' << item->closed() << ',' << item->finished() << ']';
        }
        output << ']';
    }

    /// Serialize every bookkeeping field and ordered weak-reference identity, without computing expected state.
    static void emit(std::ostream& output, const State& state) {

        output << "\"core\":[" << state.owners << ',' << state.closing << ',' << state.stopped << ",[";
        for (std::size_t index = 0; index < state.entries; ++index) {
            if (index) {
                output << ',';
            }
            output << state.directory[index];
        }
        output << "],[";
        for (std::size_t index = 0; index < state.pending; ++index) {
            if (index) {
                output << ',';
            }
            output << state.queue[index];
        }
        output << "]]";
    }

private:
    /// Convert only immutable held identities; unknown nonexpired addresses cannot be silently accepted.
    std::size_t identity(const comet::detail::Activity* activity) const {
        if (!activity) {
            return 0;
        }
        for (const auto& item : items_) {
            if (item.get() == activity) {
                return item->id();
            }
        }
        return 999;
    }

    /// Return the initial application owner at most once, independently of explicit Core close.
    void release() noexcept {
        if (std::exchange(owned_, false)) {
            core_->release();
        }
    }

    /// Prepared target; no control loop, Alarm callback or RPC has been started.
    std::shared_ptr<comet::detail::Core> core_;
    /// Live candidates in input order; expired weak slots remain observable in Core until actual pruning.
    std::array<std::shared_ptr<Item>, 32> items_{};
    /// The original Client application's one-time release obligation.
    bool owned_ = true;
};

/// Emit a whole serial history including its initial state, each receipt and complete post-state.
void history(std::string_view event, std::size_t ordinal, const std::array<std::size_t, 2>& limits, const auto& operations) {

    Fixture fixture(limits);
    std::cout << "ASTRA-MODEL {\"model\":\"comet-core-v1\",\"event\":\"" << event << "\",\"value\":{\"ordinal\":" << ordinal << ",\"limits\":[" << limits[0] << ',' << limits[1] << "],\"initial\":{";
    fixture.emit(std::cout);
    std::cout << "},\"states\":[";
    std::size_t position{};
    for (const auto operation : operations) {
        if (position) {
            std::cout << ',';
        }
        const auto outcome = fixture.step(operation, ++position);
        std::cout << "{\"operation\":" << operation << ",\"receipt\":\"" << outcome << "\",";
        fixture.emit(std::cout);
        std::cout << '}';
    }
    std::cout << "]}}\n";
}

/// Observe two overlapping native admissions and ordered locked reads; both workers finish before fixture flags are read.
void pair(std::size_t ordinal, const std::array<std::size_t, 2>& limits, const auto& prefix, const std::array<unsigned, 2>& operations) {

    Fixture fixture(limits);
    std::size_t position{};
    for (const auto operation : prefix) {
        fixture.step(operation, ++position);
    }
    // Stable candidates are installed before workers start; readers never access their changing admitted flags.
    const std::array candidates{fixture.prepare(position + 1, operations[0] == 0), fixture.prepare(position + 2, operations[1] == 0)};
    const auto initial = fixture.state();
    std::array<Fixture::State, 64> samples;
    std::array<std::string_view, 2> receipts;
    std::barrier start(3);
    const auto writer = [&fixture, &candidates, &receipts, &start](std::size_t index) {
        start.arrive_and_wait();
        receipts[index] = fixture.accept(candidates[index]);
    };
    std::jthread left(writer, 0);
    std::jthread right(writer, 1);
    start.arrive_and_wait();
    for (auto& sample : samples) {
        sample = fixture.state();
    }
    left.join();
    right.join();
    std::cout << "ASTRA-MODEL {\"model\":\"comet-core-v1\",\"event\":\"pair\",\"value\":{\"ordinal\":" << ordinal << ",\"limits\":[" << limits[0] << ',' << limits[1] << "],\"initial\":{";
    Fixture::emit(std::cout, initial);
    std::cout << "},\"prefix\":[";
    bool preceding{};
    for (const auto operation : prefix) {
        if (std::exchange(preceding, true)) {
            std::cout << ',';
        }
        std::cout << operation;
    }
    std::cout << "],\"operations\":[" << operations[0] << ',' << operations[1] << "],\"receipts\":[\"" << receipts[0] << "\",\"" << receipts[1] << "\"],\"current\":{";
    fixture.emit(std::cout);
    std::cout << "},\"samples\":[";
    bool separator{};
    for (const auto& sample : samples) {
        if (std::exchange(separator, true)) {
            std::cout << ',';
        }
        std::cout << '{';
        Fixture::emit(std::cout, sample);
        std::cout << '}';
    }
    std::cout << "]}}\n";
}
} // namespace

/// Exhaust the frozen input domain and four retained-quota controls; no history is selected or pruned after execution.
int main() {
    try {
        // Keep the process-wide library initialized while every history still creates and destroys its own Core.
        // This unset alarm owns no callback, connection or target state; its destructor releases the library after all fixtures drain.
        const grpc::Alarm library;
        std::cout << std::boolalpha;
        std::cout << "ASTRA-MODEL {\"model\":\"comet-core-v1\",\"event\":\"start\",\"value\":{\"limits\":[[1,2],[2,1]],\"operations\":9,\"depth\":4,\"histories\":13122,\"pruning\":0,\"controls\":4,\"prefixes\":[[],[0],[1],[0,2],[1,2],[0,3]],\"pairs\":48,\"reads\":64,\"serializations\":2}}\n";
        const std::array<std::array<std::size_t, 2>, 2> limits{{{1, 2}, {2, 1}}};
        std::size_t ordinal{};
        for (const auto& limit : limits) {
            for (std::size_t index = 0; index < 6561; ++index) {
                std::array<unsigned, 4> operations;
                auto remaining = index;
                for (auto& operation : operations) {
                    operation = static_cast<unsigned>(remaining % 9);
                    remaining /= 9;
                }
                history("history", ordinal++, limit, operations);
            }
        }
        ordinal = 0;
        for (const auto& limit : limits) {
            for (const auto operation : {0U, 1U}) {
                // All accepted intents close before another wave; retained cleanup capacity must still refuse overflow.
                const auto capacity = limit[operation];
                std::vector<unsigned> operations;
                for (unsigned wave = 0; wave < 2; ++wave) {
                    operations.insert(operations.end(), capacity, operation);
                    operations.insert(operations.end(), capacity, 2U);
                }
                operations.insert(operations.end(), {operation, 3U, operation, 5U, 7U});
                history("control", ordinal++, limit, operations);
            }
        }
        ordinal = 0;
        const std::array<std::vector<unsigned>, 6> prefixes{{{}, {0}, {1}, {0, 2}, {1, 2}, {0, 3}}};
        for (const auto& limit : limits) {
            for (const auto& prefix : prefixes) {
                for (const auto left : {0U, 1U}) {
                    for (const auto right : {0U, 1U}) {
                        pair(ordinal++, limit, prefix, {left, right});
                    }
                }
            }
        }
        std::cout << "ASTRA-MODEL {\"model\":\"comet-core-v1\",\"event\":\"finish\",\"value\":{\"histories\":13122,\"transitions\":52488,\"controls\":4,\"control_transitions\":44,\"pairs\":48,\"reads\":3072}}\n";
        CHECK(std::cout.good());
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
