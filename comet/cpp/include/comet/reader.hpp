// Expose authoritative Almanac reading through the public SDK.
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

namespace comet {
namespace detail {
class Projection;
class Core;
template <class Policy>
class Watching;
using Reading = Watching<Projection>;
struct Contents;
} // namespace detail
class Client;

/// Continuously reads an Almanac range; network state is separate from application-owned immutable views.
class Reader {
public:
    /// Local state captured by load or callback; existing views never change.
    enum class State {
        /// No complete authority baseline has been installed.
        Waiting,
        /// The latest batch is complete and the stream has no known failure.
        Ready,
        /// Retains the last complete contents while connecting or recovering.
        Stale,
        /// A permanent input, capacity, or protocol error suspends recovery.
        Failed,
        /// Local work has stopped; retained contents remain readable.
        Closed
    };

    /// Owning immutable view that outlives Reader and Client, without mutable containers or generated types.
    class View {
    public:
        /// Defaults to waiting, with no complete version or bound range.
        View() = default;
        /// State when this view was obtained; defaults to waiting.
        State state() const noexcept;
        /// Original fixed binding; defaults to two empty fields.
        const Scope& scope() const noexcept;
        /// Empty selects the whole Scope; otherwise selects one exact Key.
        const std::string& target() const noexcept;
        /// Star of the last complete batch; empty until ready.
        const std::string& instance() const noexcept;
        /// Present only after complete installation; zero is a valid baseline.
        std::optional<std::uint64_t> version() const noexcept;
        /// Record count in the last complete projection; defaults to zero.
        std::size_t size() const noexcept;
        /// Bounded diagnostic for this state; empty on success.
        const std::optional<Error>& error() const noexcept;
        /// Local exact lookup; returns null for a missing key without RPC or insertion.
        Value find(std::string_view key) const;

        /// Synchronously borrows stable keys and values. Visitors may throw or reenter; copy Value ownership to retain data.
        /// Pins contents for the traversal even if the caller reassigns the View; the bridge allocates no std::function.
        void each(auto&& reader) const {
            auto callback = [&reader](std::string_view key, const Value& value) { std::invoke(reader, key, value); };
            visit(&callback, [](void* context, std::string_view key, const Value& value) { (*static_cast<decltype(callback)*>(context))(key, value); });
        }

    private:
        friend class detail::Projection;
        template <class Policy>
        friend class detail::Watching;
        /// Non-owning type-erased bridge; context and visitor live only for this synchronous call.
        void visit(void* context, void (*visitor)(void*, std::string_view, const Value&)) const;
        /// Shared immutable contents own no network core, RPC context, or application callback.
        std::shared_ptr<const detail::Contents> contents_;
        /// State is separate from contents; disconnects neither copy the map nor change old views.
        State state_ = State::Waiting;
        /// Binding remains queryable before readiness; copying allocates only these two bounded fields.
        Scope scope_;
        /// Own the selected Almanac key; empty means the complete bound Scope.
        std::string target_;
        /// Empty when this state has no error.
        std::optional<Error> error_;
    };

    /// Owns a complete immutable dictionary; lookup and traversal do not copy the map.
    using Map = View;
    /// Current state and diagnostic, without waiting for RPC.
    View state() const;
    /// Replaces the state callback and schedules the current state immediately.
    Result<void> changed(std::move_only_function<void(View)> callback);
    /// Complete Scope map; an empty callback removes the subscription.
    Result<void> watch(std::move_only_function<void(Map)> callback);
    /// Complete exact-Key baseline and subsequent changes; owns the Key storage.
    Result<void> watch(std::move_only_function<void(std::string, std::optional<Value>)> callback);
    /// Idempotently stops this object; delivered values may be retained.
    void stop() noexcept;

    /// Bound installed Almanac projections and configure serial installation notifications.
    struct Options {
        /// Conservative per-object content and container budget, 64 MiB by default; private replacements have a separate bounded peak.
        std::size_t bytes = 64 * 1024 * 1024;
        /// At most 65536 records per complete projection; overflow stops recovery instead of repeatedly requesting the snapshot.
        std::size_t records = 65536;
        /// Runs after installation and SDK unlock. Notifications are serial per object; return promptly. Nonblocking close is allowed.
        std::move_only_function<void(View)> changed;
    };

    /// An empty handle owns no work; factory handles are move-only so recovery responsibility cannot be copied.
    Reader() = default;
    /// Transfer activity ownership to this handle, leaving the source empty.
    Reader(Reader&&) noexcept;
    /// Close the previous activity before taking ownership; self-assignment leaves the handle unchanged.
    Reader& operator=(Reader&&) noexcept;
    /// Keep one owner of Almanac read activity; copying is forbidden.
    Reader(const Reader&) = delete;
    /// Keep one owner of Almanac read activity; copying is forbidden.
    Reader& operator=(const Reader&) = delete;
    /// Nonblocking close; destruction does not wait for network work or join threads.
    ~Reader();
    /// Latest complete contents and current state, without issuing requests.
    View load() const;
    /// Idempotently stops this object without closing other objects sharing the Client.
    void close() noexcept;
    /// Waits only for local cleanup; forbidden in SDK callbacks and does not imply close.
    bool wait(std::chrono::milliseconds timeout) const;

private:
    friend class Client;
    /// Application handles are separate from network state; retained views do not keep subscriptions active.
    explicit Reader(std::shared_ptr<detail::Reading> reading);
    /// Empty for default or moved-from handles.
    std::shared_ptr<detail::Reading> reading_;
};
} // namespace comet
