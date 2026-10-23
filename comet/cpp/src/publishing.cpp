// Manage private Catalog writes and their completion and cancellation state.
#include "publishing.hpp"

#include <astra/scope.hpp>

#include <grpc/support/time.h>

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace comet::detail {
Publishing::Publishing(std::shared_ptr<Core> core, Scope scope) : core_(std::move(core)), scope_(std::move(scope)) {}

Publishing::~Publishing() {
    discard();
}

Publishing::Call::Call(Publishing& owner) : shutdown(owner.core_->shutdown_.get_token(), Cancel{&context}), cancellation(owner.cancellation_.get_token(), Cancel{&context}) {}

void Publishing::discard() noexcept {
    std::vector<std::string>{}.swap(keys_);
    std::string{}.swap(instance_);
    confirmed_.reset();
    static_cast<void>(core_->resize(bytes_, 0));
    bytes_ = 0;
}

Error Publishing::error(Error::Code code, Error::Effect effect) {
    return Error{code, effect, {}, {}, {}};
}

Publishing::Operation::~Operation() {

    // Reclaim only after this stack-owned RPC returns; TryCancel is not network completion.
    if (claimed) {
        owner.core_->returning(false, false);
    }
    if (admitted) {
        owner.core_->settled();
    }
    static_cast<void>(owner.core_->resize(bytes, 0));
    {
        const std::lock_guard lock(owner.mutex_);
        if (!confirmed) {
            owner.confirmed_.reset();
        }
        if (owner.closed()) {
            owner.discard();
        }
        owner.cancellation_ = std::stop_source{std::nostopstate};
        owner.binding_.reset();
        owner.active_ = false;
    }
    owner.condition_.notify_all();
    owner.core_->wake(&owner);
}

Result<void> Publishing::prepare(grpc::ClientContext& context, const std::shared_ptr<const Binding>& binding, Core::Time deadline) {

    // Query, commit, and repair share one deadline; later steps cannot redirect after an instance change.
    if (closed() || core_->stopped()) {
        return std::unexpected(error(Error::Code::Closed));
    }
    if (!core_->current(binding)) {
        return std::unexpected(error(Error::Code::Instance));
    }
    const auto remaining = std::chrono::duration_cast<std::chrono::nanoseconds>(deadline - std::chrono::steady_clock::now()).count(); // Remaining nanoseconds without resetting the budget.
    if (remaining <= 0) {
        return std::unexpected(error(Error::Code::Timeout));
    }
    context.set_deadline(gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC), gpr_time_from_nanos(remaining, GPR_TIMESPAN)));
    if (!binding->session.empty()) {
        context.AddMetadata("comet-session-bin", binding->session);
    }

    if (closed() || core_->stopped()) {
        return std::unexpected(error(Error::Code::Closed));
    }
    if (cancellation_.stop_requested()) {
        return std::unexpected(error(Error::Code::Instance));
    }
    return {};
}

Result<std::uint64_t> Publishing::query(const std::shared_ptr<const Binding>& binding, const std::vector<Publisher::Entry>& entries, Core::Time deadline, std::string& instance) {

    // Query includes relevant Keys only, without fetching Scope contents or payloads; it has no business side effects.
    proto::comet::v1::CatalogQueryRequest request;
    proto::comet::v1::CatalogQueryReply reply;
    Call call(*this); // Stopped tokens cancel immediately; unregister callbacks before destroying context.
    request.set_instance(instance);
    request.mutable_scope()->set_sector(scope_.sector);
    request.mutable_scope()->set_spectrum(scope_.spectrum);
    for (const auto& entry : entries) {
        request.add_keys(entry.key);
    }
    if (auto prepared = prepare(call.context, binding, deadline); !prepared) {
        return std::unexpected(prepared.error());
    }
    const auto status = binding->catalog->Query(&call.context, request, &reply); // Blocks the application thread, not the Core control round.
    if (!status.ok()) {
        auto failure = Core::failure(status, call.context); // Failed Query never submits the original business batch.
        failure.effect = Error::Effect::Unapplied;
        if (closed() || core_->stopped()) {
            failure.code = Error::Code::Closed;
        }
        if (failure.code == Error::Code::Session || failure.code == Error::Code::Transport || failure.code == Error::Code::Instance) {
            core_->lost(binding, failure);
        }
        return std::unexpected(std::move(failure));
    }

    // Reject missing, reordered, extra Keys and instance drift so an invalid baseline cannot drive writes.
    if (!astra::Scope::text(reply.instance(), 128) || (!instance.empty() && reply.instance() != instance) || reply.entries_size() != static_cast<int>(entries.size())) {
        return std::unexpected(error(Error::Code::Protocol));
    }
    std::uint64_t maximum = issued_; // Versions consumed by unknown outcomes cannot be reused.
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const auto& row = reply.entries(static_cast<int>(index)); // Response entries must match the request one for one.
        if (row.key() != entries[index].key) {
            return std::unexpected(error(Error::Code::Protocol));
        }
        maximum = std::max(maximum, row.version());
    }
    if (maximum == std::numeric_limits<std::uint64_t>::max()) {
        return std::unexpected(error(Error::Code::Limit));
    }
    instance = reply.instance();
    return maximum + 1;
}

Result<Publisher::Receipt> Publishing::update(std::vector<Publisher::Entry> entries, std::chrono::milliseconds ttl, std::chrono::milliseconds timeout) {

    // Reject oversized timeouts before addition; valid calls share one deadline starting at local preparation.
    if (timeout.count() <= 0 || timeout > std::chrono::minutes(1) || ttl < std::chrono::seconds(1) || ttl > std::chrono::minutes(10) || entries.empty() || entries.size() > 128) {
        return std::unexpected(error(Error::Code::Input));
    }
    const auto deadline = std::chrono::steady_clock::now() + timeout; // Absolute monotonic deadline includes authentication and Query.
    if (closed() || core_->stopped()) {
        return std::unexpected(error(Error::Code::Closed));
    }
    if (Core::notifying()) {
        return std::unexpected(error(Error::Code::Busy));
    }
    std::size_t bytes{}; // Bound each entry before adding bounded Key and payload lengths, avoiding overflow.
    std::size_t names{}; // Keys also occur in Query and the local baseline; charge their encoding separately.
    for (const auto& entry : entries) {
        if (!astra::Scope::text(entry.key, 1024) || !entry.value || entry.value->size() > 1024 * 1024) {
            return std::unexpected(error(Error::Code::Input));
        }
        names += entry.key.size();
        bytes += entry.key.size() + entry.value->size();
        if (bytes > 1024 * 1024) {
            return std::unexpected(error(Error::Code::Input));
        }
    }

    // Consume the moved-in container; in-place sorting normalizes Keys without per-Key tree allocations.
    std::ranges::sort(entries, {}, &Publisher::Entry::key);
    if (std::ranges::adjacent_find(entries, {}, &Publisher::Entry::key) != entries.end()) {
        return std::unexpected(error(Error::Code::Input));
    }

    // One synchronous call per object, without replacement, merging, or queuing; strong ownership spans actual network lifetime.
    const auto owned = shared_from_this();
    std::stop_source cancellation; // Allocate before publishing active_ so exceptions cannot leave the busy flag set.
    {
        const std::lock_guard lock(mutex_);
        if (closed() || core_->stopped()) {
            return std::unexpected(error(Error::Code::Closed));
        }
        if (active_) {
            return std::unexpected(error(Error::Code::Busy));
        }
        cancellation_ = std::move(cancellation);
        active_ = true;
    }
    Operation operation(*this); // Every exit from here returns acquired resources exactly once.
    if (!core_->admitting()) {
        return std::unexpected(error(Error::Code::Busy));
    }
    operation.admitted = true;
    const auto reserved = 3 * bytes + 3 * names + entries.size() * 768 + 8192; // Bounded conservative budget for payload, request, reply, and next Key baseline.
    if (!core_->resize(0, reserved)) {
        return std::unexpected(error(Error::Code::Busy));
    }
    operation.bytes = reserved;
    auto selected = core_->acquire(deadline, closed_); // Initial authentication consumes the original deadline too.
    if (!selected) {
        return std::unexpected(selected.error());
    }
    const auto binding = *selected; // Target is fixed for the whole call; failover affects later explicit calls only.
    {
        const std::lock_guard lock(mutex_);
        binding_ = binding;
    }
    if (!core_->outgoing(false, false)) {
        return std::unexpected(error(Error::Code::Busy));
    }
    operation.claimed = true;

    // Reuse a confirmed watermark for the same binding and exact Key set; Query again after target or set changes or failure.
    const bool initialized = confirmed_.lock() == binding && std::ranges::equal(keys_, entries, {}, {}, &Publisher::Entry::key);
    std::string instance = initialized ? instance_ : binding->instance; // The first Query confirms the instance for anonymous access.
    std::vector<std::string> keys;                                      // Prepare the next Key baseline only when its set changes; retain no business payload.
    if (!initialized) {
        keys.reserve(entries.size());
        for (const auto& entry : entries) {
            keys.push_back(entry.key);
        }
    }

    // Encode payload once; the sole conflict repair changes versions only, without copying the batch on retries.
    proto::comet::v1::PublishRequest request;
    request.mutable_scope()->set_sector(scope_.sector);
    request.mutable_scope()->set_spectrum(scope_.spectrum);
    request.set_ttl_ms(static_cast<std::uint32_t>(ttl.count()));
    for (const auto& entry : entries) {
        auto* row = request.add_entries(); // One atomic batch, never split into per-Key writes.
        row->set_key(entry.key);
        row->set_value(entry.value->data(), entry.value->size());
    }
    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        std::uint64_t version{}; // Allow one repair only after a version conflict explicitly proves that the entire batch was not committed.
        if (!initialized || attempt != 0) {
            auto queried = query(binding, entries, deadline, instance);
            if (!queried) {
                return std::unexpected(queried.error());
            }
            version = *queried;
        } else {
            if (issued_ == std::numeric_limits<std::uint64_t>::max()) {
                return std::unexpected(error(Error::Code::Limit));
            }
            version = issued_ + 1;
        }
        Publisher::Receipt receipt{instance, version}; // Prepare potentially allocating receipt text before commit.
        std::size_t retained{};                        // Check next metadata storage before commit, without assuming reserve gives an exact capacity.
        if (!initialized) {
            retained = keys.capacity() * sizeof(std::string) + instance.capacity() + 1;
            for (const auto& key : keys) {
                retained += key.capacity() + 1;
            }
            if (retained > operation.bytes) {
                return std::unexpected(error(Error::Code::Busy));
            }
        }
        request.set_instance(instance);
        request.set_version(version);
        proto::comet::v1::PublishReply reply;
        Call call(*this); // Both stop sources act directly on this RPC without borrowing object-owned raw pointers.
        if (auto prepared = prepare(call.context, binding, deadline); !prepared) {
            return std::unexpected(prepared.error());
        }
        issued_ = version; // Consume before sending; an unknown outcome cannot reuse the version with different Data.
        const auto status = binding->catalog->Publish(&call.context, request, &reply);
        if (status.ok()) {
            if (reply.instance() != instance || reply.version() != version) {
                return std::unexpected(error(Error::Code::Protocol, Error::Effect::Unknown));
            }
            if (!initialized) {
                discard();
                keys_ = std::move(keys);
                instance_ = std::move(instance);
                bytes_ = retained;
                operation.bytes -= bytes_; // Transfer reserved budget to bounded metadata without competing for quota after successful commit.
            }
            confirmed_ = binding;
            operation.confirmed = true;
            core_->recovered(binding);
            return receipt;
        }
        auto failure = Core::failure(status, call.context); // Trust only structured error evidence of unapplied status.
        if (closed() || core_->stopped()) {
            failure.code = Error::Code::Closed; // Local cancellation does not trigger shared Client transport failover.
        }
        if (attempt == 0 && failure.code == Error::Code::Version && failure.effect == Error::Effect::Unapplied) {
            continue;
        }
        if (failure.code == Error::Code::Session || failure.code == Error::Code::Transport || failure.code == Error::Code::Instance) {
            core_->lost(binding, failure);
        }
        return std::unexpected(std::move(failure));
    }
    return std::unexpected(error(Error::Code::Internal));
}

bool Publishing::closed() const noexcept {
    return closed_.load(std::memory_order_acquire);
}

bool Publishing::finished() const noexcept {
    const std::lock_guard lock(mutex_);
    return closed() && !active_;
}

void Publishing::close() noexcept {

    bool first;                                      // Decrement application ownership once; never enter Core under the object lock.
    std::stop_source cancellation{std::nostopstate}; // Snapshot references this operation only; invoke callbacks outside the object lock.
    {
        const std::lock_guard lock(mutex_);
        first = !closed_.exchange(true, std::memory_order_acq_rel);
        cancellation = cancellation_;
        if (!active_) {
            discard();
        }
    }
    cancellation.request_stop();
    if (first) {
        core_->release();
    }
    condition_.notify_all();
    core_->wake(this);
}

bool Publishing::wait(std::chrono::milliseconds timeout) const {
    if (Core::notifying()) {
        throw std::logic_error("Cannot wait inside an SDK callback");
    }
    std::unique_lock lock(mutex_); // Waits for actual calls to drain without implicitly closing.
    return condition_.wait_until(lock, Core::deadline(timeout), [this] { return closed() && !active_; });
}

Core::Time Publishing::poll(Core::Time, const std::shared_ptr<const Binding>&, const std::optional<Error>&, bool closing) {

    if (closing) {
        close();
    }
    std::shared_ptr<const Binding> binding; // Check the current actual call, not an older control-round binding snapshot.
    std::stop_source cancellation{std::nostopstate};
    {
        const std::lock_guard lock(mutex_);
        binding = binding_;
        cancellation = cancellation_;
    }
    if (binding && !core_->current(binding)) {
        cancellation.request_stop(); // Enter Core outside the object lock; cancel only the old operation even if a new call started.
    }
    return Core::Time::max();
}

} // namespace comet::detail

namespace comet {
Publisher::Publisher(std::shared_ptr<detail::Publishing> publishing) : publishing_(std::move(publishing)) {}

Publisher::Publisher(Publisher&&) noexcept = default;

Publisher& Publisher::operator=(Publisher&& other) noexcept {
    if (this != &other) {
        close();
        publishing_ = std::move(other.publishing_);
    }
    return *this;
}

Publisher::~Publisher() {
    close();
}

Result<Publisher::Receipt> Publisher::update(std::vector<Entry> entries, std::chrono::milliseconds ttl, std::chrono::milliseconds timeout) {
    return publishing_ ? publishing_->update(std::move(entries), ttl, timeout) : Result<Receipt>(std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}}));
}

Result<Publisher::Receipt> Publisher::update(std::string key, std::vector<std::uint8_t> data, std::chrono::milliseconds ttl, std::chrono::milliseconds timeout) {
    std::vector<Entry> entries; // Avoid initializer_list copying an already moved Key.
    entries.push_back({std::move(key), std::make_shared<const std::vector<std::uint8_t>>(std::move(data))});
    return update(std::move(entries), ttl, timeout);
}

void Publisher::close() noexcept {
    if (publishing_) {
        publishing_->close();
    }
}

bool Publisher::wait(std::chrono::milliseconds timeout) const {
    return !publishing_ || publishing_->wait(timeout);
}
} // namespace comet
