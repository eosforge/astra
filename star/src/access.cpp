// Validate public access credentials and authorization against authoritative Star state.
#include "access.hpp"

#include <astra/scope.hpp>

#include <openssl/mem.h>
#include <openssl/rand.h>

#include <stdexcept>

namespace astra {
/// Shared scope authorization state whose revocation cancels retained session snapshots.
struct Access::Group {
    /// Authorization state, accessed only under the Access lock; delayed cancellation cannot replace this check.
    bool active = true;
    /// Old-snapshot cancellation; request_stop runs only after releasing Access.
    std::stop_source stop;
};

/// Account credential snapshot and revocation source shared by admitted sessions.
struct Access::Account {
    /// Immutable parsed SECRET, without writable aliases to incoming requests.
    Almanac::Buffer secret;

    /// Mark this credential snapshot usable until replacement or revocation, under the access lock.
    bool active = true;
    /// Account rotation/deletion cancellation; never runs external callbacks under business locks.
    std::stop_source stop;
};

Access::Access(std::size_t maximum) : maximum_(maximum), group_(std::make_shared<Group>()) {
    if (maximum == 0 || maximum > 65536) {
        throw std::invalid_argument("Invalid business session capacity");
    }
}

Access::~Access() {
    group_->active = false;
    group_->stop.request_stop();
}

Access::Draft::Draft() : group_(std::make_shared<Group>()) {}

bool Access::Draft::set(std::string key, Almanac::Buffer secret) {

    if (!group_ || !Access::valid(key, secret) || accounts_.size() >= 65536 || accounts_.contains(key)) {
        return false;
    }
    // Prepare every node and payload privately so failure leaves the installed login table unchanged.
    auto account = std::make_shared<Account>();
    account->secret = std::move(secret);
    accounts_.emplace(std::move(key), std::move(account));
    return true;
}

bool Access::valid(std::string_view key, std::span<const std::uint8_t> secret) noexcept {
    return Scope::text(key, 128) && !secret.empty() && secret.size() <= 4096;
}

bool Access::equal(std::span<const std::uint8_t> left, std::span<const std::uint8_t> right) noexcept {
    return left.size() == right.size() && CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

std::size_t Access::Hash::operator()(std::string_view value) const noexcept {
    return std::hash<std::string_view>{}(value);
}

void Access::Session::Relay::operator()() const noexcept {
    target.request_stop();
}

Access::Session::Session(std::string token, std::shared_ptr<Account> account, std::shared_ptr<Group> group) : token_(std::move(token)), account_(std::move(account)), group_(std::move(group)), accountStop_(account_->stop.get_token(), Relay{stop_}), groupStop_(group_->stop.get_token(), Relay{stop_}) {}

std::string_view Access::Session::token() const noexcept {
    return token_;
}

std::stop_token Access::Session::stopped() const noexcept {
    return stop_.get_token();
}

Access::Permit::Permit(std::shared_lock<std::shared_mutex> lock, std::stop_token stopped) : lock_(std::move(lock)), stopped_(std::move(stopped)) {}

std::stop_token Access::Permit::stopped() const noexcept {
    return stopped_;
}

std::expected<bool, Almanac::Error> Access::reset(Draft&& draft, Commit commit) {

    if (!draft.group_ || !commit) {
        return std::unexpected(Almanac::Error::Input);
    }
    // Invalidate the old group before unlocking; later logins use the new group and cannot receive stale cancellation.
    {
        const std::unique_lock guard(mutex_);
        const auto result = commit();
        if (!result || !*result) {
            return result;
        }
        group_->active = false;
        group_.swap(draft.group_);
        accounts_.swap(draft.accounts_);
    }
    draft.group_->stop.request_stop();
    draft.group_.reset();
    draft.accounts_.clear();
    return true;
}

std::expected<bool, Almanac::Error> Access::apply(std::string key, std::optional<Almanac::Buffer> secret, Commit commit) {

    if (!Scope::text(key, 128) || (secret && !valid(key, *secret)) || !commit) {
        return std::unexpected(Almanac::Error::Input);
    }
    // Preallocate replacement nodes so node-handle transfer cannot allocate after the durable draft commits.
    std::map<std::string, std::shared_ptr<Account>, std::less<>> prepared;
    if (secret) {
        auto account = std::make_shared<Account>(); // Allocate stop state before commit too.
        account->secret = std::move(*secret);
        prepared.emplace(key, std::move(account));
    }
    // Keep retired state beyond the lock; cancellation may reenter close or login.
    std::shared_ptr<Account> retired;
    {
        const std::unique_lock guard(mutex_);
        const auto previous = accounts_.find(key); // Decide same-value Set from the current locked value, not a stale observation.
        const bool unchanged = secret && previous != accounts_.end() && equal(previous->second->secret, prepared.begin()->second->secret);
        if (secret && previous == accounts_.end() && accounts_.size() >= 65536) {
            return std::unexpected(Almanac::Error::Capacity);
        }
        const auto result = commit(); // Failure or replay preserves credentials and existing Sessions.
        if (!result || !*result || unchanged) {
            return result;
        }
        if (previous != accounts_.end()) {
            retired = std::move(previous->second);
            retired->active = false;
            accounts_.erase(previous);
        }
        if (secret) {
            accounts_.insert(prepared.extract(prepared.begin()));
        }
    }
    if (retired) {
        retired->stop.request_stop();
    }
    return true;
}

std::expected<std::shared_ptr<Access::Session>, Access::Error> Access::open(std::string_view key, std::span<const std::uint8_t> secret) {

    if (!valid(key, secret)) {
        return std::unexpected(Error::Denied);
    }
    // Only randomness generation occurs outside the lock. Final comparison and installation share one exclusive boundary, preventing stale login after rotation.
    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        std::string token(32, '\0');
        if (RAND_bytes(reinterpret_cast<unsigned char*>(token.data()), token.size()) != 1) {
            return std::unexpected(Error::Random);
        }
        const std::unique_lock guard(mutex_);
        const auto account = accounts_.find(key);
        if (account == accounts_.end() || !equal(account->second->secret, secret)) {
            return std::unexpected(Error::Denied);
        }
        if (sessions_.size() >= maximum_) {
            return std::unexpected(Error::Capacity);
        }
        if (sessions_.contains(token)) {
            continue;
        }
        // Install stop forwarding only in the current valid group, which cannot be revoked concurrently under this lock.
        auto session = std::shared_ptr<Session>(new Session(token, account->second, group_));
        sessions_.emplace(std::move(token), session);
        return session;
    }
    return std::unexpected(Error::Random);
}

std::expected<Access::Permit, Access::Error> Access::enter(std::string_view token) const {

    if (token.size() != 32) {
        return std::unexpected(Error::Denied);
    }
    std::shared_lock guard(mutex_); // Transfer the held lock to Permit without releasing it on return.
    const auto session = sessions_.find(token);
    if (session == sessions_.end() || !session->second->account_->active || !session->second->group_->active) {
        return std::unexpected(Error::Denied);
    }
    return Permit(std::move(guard), session->second->stopped());
}

void Access::close(const std::shared_ptr<Session>& session) {

    if (!session) {
        return;
    }
    {
        const std::unique_lock guard(mutex_);
        const auto existing = sessions_.find(session->token_);
        if (existing == sessions_.end() || existing->second != session) {
            return;
        }
        sessions_.erase(existing);
    }
    session->stop_.request_stop();
}
} // namespace astra
