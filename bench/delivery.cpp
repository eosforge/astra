// Implement benchmark delivery confirmation and failure publication.
#include "delivery.hpp"

#include "measure.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <ranges>
#include <utility>

Delivery::Delivery(std::vector<std::string> keys, std::size_t writers, std::size_t watchers, std::size_t bytes, std::size_t attr) : keys_(std::move(keys)), writers_(writers), bytes_(bytes), attr_(attr), slots_(std::make_unique<Slot[]>(writers)) {
    for (std::size_t index = 0; index < writers_; ++index) {
        slots_[index].seen.resize(watchers); // Allocate fixed capacity before the receive hot path.
    }
}

void Delivery::receive(std::size_t watcher, const comet::Subscriber::View& view) {
    // A partial View cannot acknowledge a business operation.
    if (view.state() != comet::Subscriber::State::Ready || view.size() != keys_.size()) {
        return;
    }

    for (std::size_t index = 0; index < writers_; ++index) {
        const auto record = view.find(keys_[index]);
        if (!record || record->value->size() != bytes_ || record->version == 0 || !std::ranges::all_of(*record->value | std::views::drop(sizeof(std::uint64_t)), [](auto byte) { return byte == 42; })) {
            fail();
            return;
        }
        accept(index, watcher, sequence(*record->value)); // Application sequence numbers are independent of protocol versions used by SDK queries or conflict repair.
    }
}

void Delivery::receive(std::size_t watcher, const comet::Observer::View& view) {
    if (view.state() != comet::Observer::State::Ready || view.size() != keys_.size()) {
        return;
    }

    for (std::size_t index = 0; index < writers_; ++index) {
        const auto record = view.find(keys_[index]); // The UUID must remain fixed for the scenario; unexpected registration cannot acknowledge the original request.
        if (!record || record->data->size() != bytes_ || record->attr->size() != attr_ || !std::ranges::all_of(*record->data | std::views::drop(sizeof(std::uint64_t)), [](auto byte) { return byte == 42; }) || !std::ranges::all_of(*record->attr, [](auto byte) { return byte == 17; })) {
            fail();
            return;
        }
        accept(index, watcher, sequence(*record->data));
    }
}

void Delivery::wait(std::size_t writer, std::uint64_t version) {
    auto& slot = slots_[writer]; // Each writer owns one wait slot; Watch callbacks may update distinct seen entries concurrently.
    std::unique_lock lock(slot.gate);
    Measure::require(slot.changed.wait_for(lock, std::chrono::seconds(5), [&] { return failed_.load() || std::ranges::all_of(slot.seen, [&](auto observed) { return observed == version; }); }));
    Measure::require(!failed_.load());
}

std::uint64_t Delivery::sequence(const std::vector<std::uint8_t>& bytes) noexcept {
    std::uint64_t result{};
    std::memcpy(&result, bytes.data(), sizeof(result));
    return result;
}

void Delivery::accept(std::size_t writer, std::size_t watcher, std::uint64_t version) {
    auto& slot = slots_[writer];
    const std::lock_guard lock(slot.gate);
    if (slot.seen[watcher] != version) {
        slot.seen[watcher] = version;
        slot.changed.notify_one();
    }
}

void Delivery::fail() {
    failed_.store(true);
    for (std::size_t index = 0; index < writers_; ++index) {
        const std::lock_guard lock(slots_[index].gate);
        slots_[index].changed.notify_one();
    }
}
