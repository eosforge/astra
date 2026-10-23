// Own exclusive source-preparation access without holding the domain commit lock while waiting.
#pragma once
#include <astra/profile.hpp>

#include <memory>
#include <mutex>
#include <shared_mutex>
#include <utility>

namespace astra {
/// Exclusive preparation for one remote source. Lifetime is independent of the domain directory; waiting never retains the shared commit lock.
template <typename Replica>
class Borrowing {
public:
    /// Caller holds domain; owner comes from its protected directory. Null means the source is absent.
    Borrowing(std::shared_ptr<Replica> owner, std::unique_lock<std::shared_mutex>& domain) : owner_(std::move(owner)) {

        if (!owner_) {
            return;
        }
        lock_ = std::unique_lock(owner_->mutex, std::try_to_lock);
        if (!lock_.owns_lock()) {
            outside(domain, [&] { ASTRA_PROFILE_SCOPE("star.borrowing.wait.source"); lock_.lock(); }); // Allow local RPC commits while waiting for remote preparation.
        }
    }

    /// Transfer source ownership and its exclusive preparation lock as one guard.
    Borrowing(Borrowing&&) noexcept = default;
    /// Keep one owner of exclusive source-preparation lock; copying is forbidden.
    Borrowing(const Borrowing&) = delete;
    /// Keep one owner of exclusive source-preparation lock; copying is forbidden.
    Borrowing& operator=(const Borrowing&) = delete;

    /// Release the source mutex before ownership, so a retired source's locked mutex cannot be destroyed.
    ~Borrowing() = default;

    /// Borrow only during this guard; after reacquiring domain, the caller must recheck directory identity.
    Replica* get() const noexcept {
        return owner_.get();
    }

    /// Runs private preparation without accessing the shared domain, restoring domain on both normal and exceptional exit.
    /// Construct the private candidate outside action; never publish projections, deadlines, or accounting while domain is unlocked.
    static void outside(std::unique_lock<std::shared_mutex>& domain, auto&& action) {

        ASTRA_PROFILE_SCOPE("star.borrowing.outside");
        domain.unlock();
        try {
            ASTRA_PROFILE_SCOPE("star.borrowing.prepare");
            std::forward<decltype(action)>(action)();
        } catch (...) {
            ASTRA_PROFILE_SCOPE("star.borrowing.wait.domain.failure");
            domain.lock();
            throw;
        }
        ASTRA_PROFILE_SCOPE("star.borrowing.wait.domain");
        domain.lock();
    }

private:
    /// Ownership precedes lock construction and is released last; never retain directory iterators across unlock.
    std::shared_ptr<Replica> owner_;
    /// Serializes one source without blocking other-source preparation or local commits.
    std::unique_lock<std::mutex> lock_;
};
} // namespace astra
