// Expose Ephemeris observations and their snapshot lifecycle to SDK consumers.
#pragma once
#include "types.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace comet {
namespace detail {
class Selection;
class Core;
template <class Policy>
class Watching;
using Observing = Watching<Selection>;
struct Registrations;
struct Estimates;
} // namespace detail
class Client;

/// Continuously read one Ephemeris scope, separating private network state from application-owned immutable Views.
class Observer {
public:
    /// Each exposed registration is complete; Attr and Data are shared independently so Data updates do not copy Attr.
    struct Record {
        /// Fixed registration attributes; a non-null owner of zero bytes is valid.
        Value attr;
        /// Last completely installed Data, excluding TTL, source group and internal renewal order.
        Value data;
    };
    /// State captured by load/callback; later state changes cannot mutate retained Views.
    enum class State {
        /// No complete registration baseline has been installed.
        Waiting,
        /// Latest batch completely installed, with no known current-stream failure.
        Ready,
        /// Last complete contents retained while connection or recovery is unfinished.
        Stale,
        /// Permanent input/capacity/protocol failure pauses automatic recovery.
        Failed,
        /// Local activity stopped; retained contents remain readable.
        Closed
    };

    /// Lightweight owning view independent of Observer/Client lifetime, without writable containers or generated protocol types.
    class View {
    public:
        /// A default View is waiting, with no complete version or bound scope.
        View() = default;
        /// Return the state captured with this View; a default View is waiting.
        State state() const noexcept;
        /// Original fixed binding; both fields are empty by default.
        const Scope& scope() const noexcept;
        /// Empty selects the complete Scope; otherwise select this exact UUID.
        const std::string& target() const noexcept;
        /// Star for the last complete batch; empty before readiness.
        const std::string& instance() const noexcept;
        /// Available only after a complete installation; an explicit zero is a valid baseline.
        std::optional<std::uint64_t> version() const noexcept;
        /// Return the record count in this immutable snapshot, or zero when empty.
        std::size_t size() const noexcept;
        /// Bounded diagnostic for this state, empty on success.
        const std::optional<Error>& error() const noexcept;
        /// Exact local lookup; missing returns an empty optional without RPCs or insertion.
        std::optional<Record> find(std::string_view uuid) const;

        /// Synchronously borrow stable UUID/Value arguments. Callbacks may throw or reenter; copy Value ownership to retain data.
        /// Traverse fixed contents even if the callback reassigns the original View, without allocating std::function.
        void each(auto&& reader) const {
            auto callback = [&reader](std::string_view key, const Record& value) { std::invoke(reader, key, value); };
            visit(&callback, [](void* context, std::string_view key, const Record& value) { (*static_cast<decltype(callback)*>(context))(key, value); });
        }

    private:
        friend class detail::Selection;
        template <class Policy>
        friend class detail::Watching;
        /// Nonowning type-erasure bridge; context and visitor live only for this synchronous call.
        void visit(void* context, void (*visitor)(void*, std::string_view, const Record&)) const;
        /// Share complete read-only content without keeping the core, RPC context or application callbacks alive.
        std::shared_ptr<const detail::Registrations> contents_;
        /// Separate captured state from content so disconnects neither copy the container nor mutate old state.
        State state_ = State::Waiting;
        /// Binding remains queryable before readiness; View copies allocate only these two bounded fields.
        Scope scope_;
        /// Own the exact selected UUID; empty means the complete bound Scope.
        std::string target_;
        /// Retain the diagnostic captured with this View; absence means no state error.
        std::optional<Error> error_;
    };

    class Pool;

    /// Owning selected record; local adjustment must match both the authority generation and previous estimate.
    class Item {
    public:
        /// Borrow the selected UUID until this Item is replaced or destroyed.
        const std::string& id() const noexcept {
            return id_;
        }

        /// Complete attributes and current selection estimate may outlive stop.
        const Record& record() const noexcept {
            return record_;
        }

        /// Adjust only the local estimate; newer authority data or concurrent adjustments win, without RPCs.
        Result<void> update(Value data);
        /// Move an owned value of at most 1 MiB.
        Result<void> update(std::vector<std::uint8_t> data);

    private:
        friend class Pool;
        friend class Observer;
        /// Own the selected UUID independently of network and pool lifetimes.
        std::string id_;
        /// Retain complete attributes and the current local Data estimate for this selection.
        Record record_;
        /// Authority-generation token, independently of business versions.
        Value authority_;
        /// Old views do not extend subscription lifetime.
        std::weak_ptr<detail::Observing> owner_;
    };

    /// Stable pool snapshot for selectors to query/traverse outside SDK locks and optionally sample using application indexes.
    class Pool {
    public:
        /// Return the record count in this immutable snapshot, or zero when empty.
        std::size_t size() const noexcept;
        /// Lookup overlays local estimates from the same generation.
        std::optional<Item> find(std::string_view id) const;

        /// Traverse this fixed pool without a global write lock.
        void each(auto&& reader) const {
            auto callback = [&reader](Item item) { std::invoke(reader, std::move(item)); };
            visit(&callback, [](void* context, Item item) { (*static_cast<decltype(callback)*>(context))(std::move(item)); });
        }

    private:
        friend class detail::Selection;
        /// Borrow callback context synchronously only.
        void visit(void* context, void (*visitor)(void*, Item)) const;
        /// Share the immutable authority registrations underlying this fixed pool snapshot.
        std::shared_ptr<const detail::Registrations> contents_;
        /// Share local estimates from the same captured authority generation.
        std::shared_ptr<const detail::Estimates> estimates_;
        /// Recheck object liveness before applying an adjustment.
        std::weak_ptr<detail::Observing> owner_;
    };

    /// Return errors when unready/stopped and nullopt when no candidate exists; selectors may adjust estimates outside SDK locks.
    Result<std::optional<Item>> one(auto&& selector) const {
        auto callback = [&selector](const Pool& pool) { return std::invoke(selector, pool); };
        return choose(&callback, [](void* context, const Pool& pool) -> std::optional<Item> { return (*static_cast<decltype(callback)*>(context))(pool); });
    }

    /// Stop this object, retaining delivered memory but refusing further pool changes.
    void stop() noexcept;

    /// Bound installed Ephemeris projections and configure serial installation notifications.
    struct Options {
        /// Conservative per-object installed-content/container budget, default 64 MiB, with a bounded replacement peak for private candidates.
        std::size_t bytes = 64 * 1024 * 1024;
        /// At most 65536 records per complete projection; exceeding the bound stops recovery instead of repeatedly downloading the same snapshot.
        std::size_t records = 65536;
        /// Notify serially after installation and outside SDK locks; return promptly. Nonblocking close is permitted.
        std::move_only_function<void(View)> changed;
    };

    /// Empty handles own no activity; factory handles are move-only so recovery ownership cannot be duplicated.
    Observer() = default;
    /// Transfer activity ownership to this handle, leaving the source empty.
    Observer(Observer&&) noexcept;
    /// Close the previous activity before taking ownership; self-assignment leaves the handle unchanged.
    Observer& operator=(Observer&&) noexcept;
    /// Keep one owner of Ephemeris observation activity; copying is forbidden.
    Observer(const Observer&) = delete;
    /// Keep one owner of Ephemeris observation activity; copying is forbidden.
    Observer& operator=(const Observer&) = delete;
    /// Close without waiting for network or joining threads in the destructor.
    ~Observer();
    /// Return last complete contents and captured state without issuing a request.
    View select() const;
    /// Stop only this object idempotently, leaving other objects on the shared Client active.
    void close() noexcept;
    /// Wait for local cleanup without implicit close; forbidden inside SDK callbacks.
    bool wait(std::chrono::milliseconds timeout) const;

private:
    friend class Client;
    /// Run selectors outside locks and validate selected-object ownership.
    Result<std::optional<Item>> choose(void* context, std::optional<Item> (*selector)(void*, const Pool&)) const;
    /// Private network state follows the application handle, not the lifetime of old Views.
    explicit Observer(std::shared_ptr<detail::Observing> observing);
    /// Own the private observation activity; default and moved-from handles are empty.
    std::shared_ptr<detail::Observing> observing_;
};
} // namespace comet
