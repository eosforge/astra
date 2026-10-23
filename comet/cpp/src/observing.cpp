// Adapt public Ephemeris observations to the private streaming reader lifecycle.
#include "observing.hpp"

namespace comet::detail {
/// Reuses the network lifecycle and installs complete Ephemeris registrations.
template class Watching<Selection>;
} // namespace comet::detail

namespace comet {
/// Observer takes ownership of observation intent; null means closed.
/// observing is the implementation; moving invalidates the source.
Observer::Observer(std::shared_ptr<detail::Observing> observing) : observing_(std::move(observing)) {}

/// Move construction transfers observation ownership.
Observer::Observer(Observer&&) noexcept = default;

/// Move assignment closes the previous observation before transfer; self-assignment is safe.
/// other is the source object.
Observer& Observer::operator=(Observer&& other) noexcept {
    if (this != &other) {
        close();
        observing_ = std::move(other.observing_);
    }
    return *this;
}

/// Destruction closes observation without waiting for in-flight pages.
Observer::~Observer() {
    close();
}

/// Observer::select returns the current snapshot, or an empty view without an observation.
Observer::View Observer::select() const {
    return observing_ ? observing_->load() : View{};
}

/// Observer::close stops observation idempotently without waiting for the control round.
void Observer::close() noexcept {
    if (observing_) {
        observing_->close();
    }
}

/// Observer::wait awaits cleanup and returns false on timeout; forbidden in callbacks.
bool Observer::wait(std::chrono::milliseconds timeout) const {
    return !observing_ || observing_->wait(timeout);
}
} // namespace comet

namespace comet {
void Observer::stop() noexcept {
    close();
}

Result<std::optional<Observer::Item>> Observer::choose(void* context, std::optional<Item> (*selector)(void*, const Pool&)) const {

    const auto owner = observing_;
    if (!owner) {
        return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
    }
    auto pool = owner->pool();
    if (!pool) {
        return std::unexpected(pool.error());
    }
    auto selected = selector(context, *pool); // Synchronous application code runs without SDK locks; exceptions propagate to the caller.
    if (owner->load().state() == State::Closed) {
        return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
    }
    if (selected && selected->owner_.lock() != owner) {
        return std::unexpected(Error{Error::Code::Input, Error::Effect::Unapplied, {}, {}, {}});
    }
    return selected;
}

Result<void> Observer::Item::update(std::vector<std::uint8_t> data) {
    if (data.size() > 1024 * 1024) {
        return std::unexpected(Error{Error::Code::Input, Error::Effect::Unapplied, {}, {}, {}});
    }
    return update(std::make_shared<const std::vector<std::uint8_t>>(std::move(data)));
}

Result<void> Observer::Item::update(Value data) {

    if (!data || data->size() > 1024 * 1024) {
        return std::unexpected(Error{Error::Code::Input, Error::Effect::Unapplied, {}, {}, {}});
    }
    const auto owner = owner_.lock();
    if (!owner) {
        return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
    }
    auto result = owner->estimate(id_, authority_, record_.data, data);
    if (result) {
        record_.data = std::move(data);
    }
    return result;
}
} // namespace comet
