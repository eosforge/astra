// Page a frozen Almanac projection without rereading mutable state during delivery.
#include "edition.hpp"

#include <astra/profile.hpp>

#include <algorithm>
#include <memory>
#include <ranges>
#include <stdexcept>
#include <string>
#include <tuple>

namespace astra {
Edition::Edition() = default;

Edition::Edition(Almanac::View view) : version_(view.version()), bytes_(view.bytes()) {
    data_.emplace<Almanac::View>(std::move(view));
}

Edition::Edition(std::string key, Almanac::Point point) : version_(point.version), bytes_(point.value ? key.size() + point.value->size() : 0) {
    data_.emplace<Point>(std::move(key), std::move(point.value));
}

Edition::Edition(Almanac::Replay replay, std::string_view target) : mode_(proto::comet::v1::MODE_APPLY), version_(replay.version) {

    // Exact Watch retains the last relevant change; even an empty projection confirms consumption of the complete frozen interval.
    if (!target.empty()) {
        const auto last = std::ranges::find_if(replay.changes | std::views::reverse, [target](const Almanac::Change& change) { return *change.key == target; });
        if (last != replay.changes.rend()) {
            bytes_ = last->bytes();
            data_.emplace<std::vector<Almanac::Change>>(1, *last);
        }
        return;
    }

    // Native state already established continuity. Sort by key/version and compact final actions in place, without another hash table or Buffer copy.
    const auto order = [](const Almanac::Change& change) { return std::tie(*change.key, change.version); }; // Compare key/version through references, without copying strings or separately retesting equal keys.
    if (!std::ranges::is_sorted(replay.changes, {}, order)) {
        std::ranges::sort(replay.changes, {}, order); // The active collector's ordered unique suffix skips sorting; replay history may contain interleaved keys.
    }
    std::size_t kept{}; // Compacted prefix length; input order selects the highest version for each key.
    for (std::size_t first = 0; first < replay.changes.size();) {
        auto last = first; // Final same-key item; native history guarantees strictly increasing versions.
        while (last + 1 < replay.changes.size() && *replay.changes[last + 1].key == *replay.changes[first].key) {
            ++last;
        }
        bytes_ += replay.changes[last].bytes();
        if (kept != last) {
            replay.changes[kept] = std::move(replay.changes[last]);
        }
        ++kept;
        first = last + 1;
    }
    bytes_ += (replay.changes.capacity() - kept) * sizeof(Almanac::Change);
    replay.changes.resize(kept);
    data_.emplace<std::vector<Almanac::Change>>(std::move(replay.changes));
}

bool Edition::append(proto::comet::v1::AlmanacWatchReply& page, std::size_t& bytes, std::string_view key, const Almanac::Value& value) {

    // Conservatively include nested field/length overhead; repeated whole-page ByteSizeLong would make traversal quadratic.
    constexpr std::size_t hard = 8 * 1024 * 1024; // Same hard page limit as dynamic-domain paging.
    if (key.size() > hard || (value && value->size() > hard)) {
        throw std::length_error("Almanac record exceeds message budget");
    }
    const auto cost = key.size() + (value ? value->size() : 0) + 32;
    if (bytes >= hard || cost > hard - bytes) {
        throw std::length_error("Almanac record exceeds message budget");
    }
    if (page.changes_size() != 0 && (page.changes_size() >= 256 || cost > 256 * 1024 - std::min(bytes, std::size_t{256 * 1024}))) {
        return false;
    }
    auto change = std::make_unique<proto::comet::v1::AlmanacChange>();
    change->set_allocated_key(new std::string(key));
    if (value) {
        change->set_allocated_value(new std::string(value->begin(), value->end()));
    } else {
        change->set_allocated_erase(new proto::comet::v1::Empty);
    }
    // Prepare heap messages before publishing generated oneof tags or repeated-field ownership.
    page.mutable_changes()->AddAllocated(change.get());
    static_cast<void>(change.release());
    bytes += cost;
    return true;
}

proto::comet::v1::AlmanacWatchReply Edition::next(std::string_view instance) {

    ASTRA_PROFILE_SCOPE("star.edition.Edition.next");

    if (complete_) {
        throw std::logic_error("Almanac edition already completed");
    }
    if (instance.empty() || instance.size() > 128) {
        throw std::invalid_argument("Invalid Almanac serving instance");
    }
    proto::comet::v1::AlmanacWatchReply page; // Returns an owned page without sharing writable content with the next encoding.
    page.set_mode(mode_);
    std::size_t bytes = instance.size() + 64; // Reserve worst-case final control fields even on intermediate pages.
    std::size_t count{};                      // Advance offset_ only after complete page construction; failure preserves position.
    bool finished = true;                     // Empty baseline/apply still emits an explicit complete frame.
    if (const auto* view = std::get_if<Almanac::View>(&data_)) {
        count = view->page(offset_, 256, [&](const std::string& key, const Almanac::Value& value) { return append(page, bytes, key, value); });
        finished = offset_ + count == view->size();
    } else if (const auto* point = std::get_if<Point>(&data_)) {
        if (point->value) {
            static_cast<void>(append(page, bytes, point->key, point->value));
            count = 1;
        }
    } else if (const auto* changes = std::get_if<std::vector<Almanac::Change>>(&data_)) {
        while (offset_ + count < changes->size()) {
            const auto& change = (*changes)[offset_ + count]; // Borrow frozen final actions without querying the mutable group again.
            if (!append(page, bytes, *change.key, change.value)) {
                break;
            }
            ++count;
        }
        finished = offset_ + count == changes->size();
    }
    if (finished) {
        page.set_complete(true);
        page.set_version(version_);
        page.set_allocated_instance(new std::string(instance)); // A failed allocation cannot leave a stale presence bit.
    }
    offset_ += count;
    complete_ = finished;
    return page;
}

bool Edition::complete() const noexcept {
    return complete_;
}

std::uint64_t Edition::version() const noexcept {
    return version_;
}

std::size_t Edition::bytes() const noexcept {
    return bytes_;
}
} // namespace astra
