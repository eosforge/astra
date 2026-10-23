// Adapt Ephemeris fields for shared snapshot and delta encoding without owning cursor state.
#include "ephemeris_edition.hpp"

#include <memory>
#include <string>

namespace astra {
Ephemeris::State::Projection::Event Ephemeris::Encoding::merge(const State::Projection::Event& previous, State::Projection::Event current) noexcept {
    if (current.record && (!previous.record || !previous.data)) {
        current.data = false;
    }
    return current;
}

void Ephemeris::Encoding::append(Reply& page, std::string_view key, const Content* record, bool data) {

    auto change = std::make_unique<proto::comet::v1::EphemerisChange>();
    change->set_allocated_uuid(new std::string(key));
    if (!record) {
        change->set_allocated_erase(new proto::comet::v1::Empty);
    } else if (data) {
        change->set_allocated_data(new std::string(record->data->begin(), record->data->end()));
    } else {
        auto complete = std::make_unique<proto::comet::v1::EphemerisChange::Record>();
        complete->set_allocated_attr(new std::string(record->attr->begin(), record->attr->end()));
        complete->set_allocated_data(new std::string(record->data->begin(), record->data->end()));
        change->set_allocated_record(complete.release()); // Install the oneof tag only after its heap message exists.
    }

    // Heap-to-heap transfer cannot clone; keep ownership until any repeated-field growth succeeds.
    page.mutable_changes()->AddAllocated(change.get());
    static_cast<void>(change.release());
}
} // namespace astra
