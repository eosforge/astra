// Adapt public Catalog subscriptions to the private streaming reader lifecycle.
#include "subscribing.hpp"

namespace comet::detail {
/// Catalog-only network instantiation keeps gRPC templates out of public headers.
template class Watching<Subscription>;
} // namespace comet::detail

namespace comet {
/// Subscriber takes ownership of subscription intent; null means closed.
/// subscribing is the implementation; moving invalidates the source.
Subscriber::Subscriber(std::shared_ptr<detail::Subscribing> subscribing) : subscribing_(std::move(subscribing)) {}

/// Move construction transfers subscription ownership.
Subscriber::Subscriber(Subscriber&&) noexcept = default;

/// Move assignment closes the previous subscription before transfer; self-assignment is safe.
/// other is the source object, invalidated by the move.
Subscriber& Subscriber::operator=(Subscriber&& other) noexcept {
    if (this != &other) {
        close();
        subscribing_ = std::move(other.subscribing_);
    }
    return *this;
}

/// Destruction closes the subscription without waiting for in-flight pages.
Subscriber::~Subscriber() {
    close();
}

/// Subscriber::watch returns the current snapshot, or an empty view without a subscription.
Subscriber::View Subscriber::watch() const {
    return subscribing_ ? subscribing_->load() : View{};
}

/// Subscriber::close stops the subscription idempotently without waiting for the control round.
void Subscriber::close() noexcept {
    if (subscribing_) {
        subscribing_->close();
    }
}

/// Subscriber::wait awaits cleanup and returns false on timeout; forbidden in callbacks.
bool Subscriber::wait(std::chrono::milliseconds timeout) const {
    return !subscribing_ || subscribing_->wait(timeout);
}
} // namespace comet

namespace comet {
Subscriber::View Subscriber::state() const {
    return watch();
}

void Subscriber::stop() noexcept {
    close();
}

Result<void> Subscriber::changed(std::move_only_function<void(View)> callback) {
    return subscribing_ ? subscribing_->changed(std::move(callback)) : Result<void>(std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}}));
}

Result<void> Subscriber::watch(std::move_only_function<void(Map)> callback) {
    if (!subscribing_) {
        return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
    }
    if (!callback) {
        return subscribing_->watch({}, false);
    }
    return subscribing_->watch([callback = std::move(callback)](View view) mutable { callback(Map(std::move(view))); }, false);
}

Result<void> Subscriber::watch(std::move_only_function<void(std::string, std::optional<Value>)> callback) {
    if (!subscribing_) {
        return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
    }
    if (!callback) {
        return subscribing_->watch({}, true);
    }
    return subscribing_->watch([callback = std::move(callback)](View view) mutable {
        auto key = view.target();
        const auto record = view.find(key);
        auto value = (record ? record->value : Value{});
        callback(std::move(key), value ? std::optional<Value>(std::move(value)) : std::nullopt);
    },
                               true);
}
} // namespace comet
