// Adapt public Almanac reads to the private streaming reader lifecycle.
#include "reading.hpp"

namespace comet::detail {
/// Almanac-only network instantiation keeps gRPC templates out of public headers.
template class Watching<Projection>;
} // namespace comet::detail

namespace comet {
/// Reader takes ownership of reading intent; null means closed.
/// reading is the implementation; moving invalidates the source.
Reader::Reader(std::shared_ptr<detail::Reading> reading) : reading_(std::move(reading)) {}

/// Move construction transfers reading ownership.
Reader::Reader(Reader&&) noexcept = default;

/// Move assignment closes the previous reader before transfer; self-assignment is safe.
/// other is the source object.
Reader& Reader::operator=(Reader&& other) noexcept {
    if (this != &other) {
        close();
        reading_ = std::move(other.reading_);
    }
    return *this;
}

/// Destruction closes reading without waiting for in-flight pages.
Reader::~Reader() {
    close();
}

/// Reader::load returns the current snapshot, or an empty view without a reader.
Reader::View Reader::load() const {
    return reading_ ? reading_->load() : View{};
}

/// Reader::close stops reading idempotently without waiting for the control round.
void Reader::close() noexcept {
    if (reading_) {
        reading_->close();
    }
}

/// Reader::wait awaits cleanup and returns false on timeout; forbidden in callbacks.
bool Reader::wait(std::chrono::milliseconds timeout) const {
    return !reading_ || reading_->wait(timeout);
}
} // namespace comet

namespace comet {
Reader::View Reader::state() const {
    return load();
}

void Reader::stop() noexcept {
    close();
}

Result<void> Reader::changed(std::move_only_function<void(View)> callback) {
    return reading_ ? reading_->changed(std::move(callback)) : Result<void>(std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}}));
}

Result<void> Reader::watch(std::move_only_function<void(Map)> callback) {
    if (!reading_) {
        return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
    }
    if (!callback) {
        return reading_->watch({}, false);
    }
    return reading_->watch([callback = std::move(callback)](View view) mutable { callback(Map(std::move(view))); }, false);
}

Result<void> Reader::watch(std::move_only_function<void(std::string, std::optional<Value>)> callback) {
    if (!reading_) {
        return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
    }
    if (!callback) {
        return reading_->watch({}, true);
    }
    return reading_->watch([callback = std::move(callback)](View view) mutable {
        auto key = view.target();

        auto value = view.find(key);
        callback(std::move(key), value ? std::optional<Value>(std::move(value)) : std::nullopt);
    },
                           true);
}
} // namespace comet
