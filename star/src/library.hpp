// Retain authoritative Almanac views and history for consistent downstream delivery.
#pragma once
#include "almanac.hpp"
#include <astra/scope.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

namespace astra {
/// Almanac Sector/Spectrum routing. One Polaris installer serializes writes; ordinary readers hold only short index locks.
/// Contains no dynamic sources; Catalog/Ephemeris are not stored in a unified Store.
class Library {
public:
    /// Deployment limits for current content/history, excluding physical memory held by external old Views.
    struct Limits {
        /// Complete-group count, positive, default 4096. Empty groups retain installed versions and consume one slot.
        std::size_t scopes = 4096;
        /// Total current Almanac key/value bytes, default 256 MiB.
        std::size_t bytes = 256 * 1024 * 1024;
        /// Total retained logical history bytes, default 64 MiB; zero disables incremental history.
        std::size_t history = 64 * 1024 * 1024;
        /// Per-group native limits; defaults in Almanac::Limits.
        Almanac::Limits scope;
    };

    /// Complete installed Scope position; version zero is a valid empty baseline.
    struct Position {
        /// Owned Sector/Spectrum address, usable independently of Library.
        Scope scope;
        /// Authoritative Scope version, without local commit counts.
        std::uint64_t version{};
    };

    /// Receiver-exclusive private snapshot candidate, fillable across pages without copying or mutating installed content.
    class Draft {
    public:
        /// Owns each key/value and charges successful preparation. Failure preserves previous entries; allocation errors propagate to receiving.
        std::expected<void, Almanac::Error> set(std::string key, Almanac::Buffer value);
        /// Borrows the fixed candidate Scope until candidate destruction.
        const Scope& scope() const noexcept;
        /// Fixed authoritative version, required on every page.
        std::uint64_t version() const noexcept;
        /// Transfers unique recovery ownership; moved-from candidates cannot set/install.
        Draft(Draft&&) noexcept = default;

        /// Keep one owner of privately prepared candidate state; copying is forbidden.
        Draft(const Draft&) = delete;

    private:
        friend class Library;
        /// Library-only construction. Owner identifies the route; Scope/version/limits fix the recovery boundary.
        Draft(const Library* owner, Scope scope, std::uint64_t version, std::shared_ptr<Almanac> book);
        /// Route identity compared only, never dereferenced; candidates cannot move across Libraries.
        const Library* owner_;
        /// Validated address fixed with version_.
        Scope scope_;
        /// Pending full-width unsigned version; zero permits only empty content.
        std::uint64_t version_;
        /// Owns the target native object, including a new Scope not yet in routing.
        std::shared_ptr<Almanac> book_;
        /// Native COW preparation; failure/disconnection discards only this candidate.
        Almanac::Draft draft_;
        /// Successfully prepared logical key/value bytes.
        std::size_t bytes_{};
    };

    /// Creates empty routing without claiming a complete Polaris inventory.
    Library();
    /// Fixed deployment limits; invalid values throw invalid_argument. Starts no threads or network operations.
    /// Changed runs serially under writer_ after successful commit; empty change.key means full replacement. Must neither reenter Library nor throw.
    /// Callback only enqueues bounded work; no encoding, network wait, or Access lock. Active subscriptions must not depend on retained history.
    using Notify = std::move_only_function<void(const Scope&, const Almanac::Change&) noexcept>;
    /// Create an empty scope library; invalid capacity relationships throw invalid_argument before publication.
    explicit Library(Limits limits, Notify changed = {});
    /// Shared read-only native group; absent/invalid address returns null without creating an empty Scope.
    std::shared_ptr<const Almanac> find(const Scope& scope) const;
    /// Creates an off-lock candidate, rejecting versions below the installed version. Outer synchronization limits preparation to one candidate.
    std::expected<Draft, Almanac::Error> prepare(Scope scope, std::uint64_t version);
    /// Installs the complete candidate with global accounting; true=new commit, false=same-version replay.
    std::expected<bool, Almanac::Error> reset(Draft&& draft);
    /// Single-key mutation of an existing complete Scope; never creates a version-zero baseline for a missing Scope.
    std::expected<bool, Almanac::Error> apply(const Scope& scope, std::uint64_t version, std::string key, std::optional<Almanac::Buffer> value);
    /// Same accounting/notification boundary as single-key writes, with one envelope for the complete batch.
    std::expected<bool, Almanac::Error> apply(const Scope& scope, std::uint64_t version, std::vector<Almanac::Change> changes);
    /// Stable inventory of complete positions, serialized with installation; copies no content and borrows no routing nodes.
    std::vector<Position> positions() const;

private:
    /// Internal writable object, mutated only under writer_; public reads never expose write permission.
    std::shared_ptr<Almanac> locate(const Scope& scope) const;
    /// Fixed limits; existing groups never change rules at runtime.
    const Limits limits_;
    /// Fixed commit receiver; empty callback means no network observer.
    Notify changed_;
    /// Short installation/position-capture lock, excluding network and snapshot preparation; point readers never take it.
    mutable std::mutex writer_;
    /// Protects routing insertion/lookup only; existing-group commits do not take it.
    mutable std::shared_mutex mutex_;
    /// Ordered Sector/Spectrum index; stable shared groups own their synchronization independently.
    std::map<std::string, std::map<std::string, std::shared_ptr<Almanac>, std::less<>>, std::less<>> books_;
    /// Three counters protected by writer_, initially zero and updated only after successful installation.
    std::size_t scopes_{};
    /// Current logical key/value bytes across groups, excluding old views.
    std::size_t bytes_{};
    /// Retained logical history across groups, reduced with per-Scope contiguous-prefix eviction.
    std::size_t history_{};
};
} // namespace astra
