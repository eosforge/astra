// Adapt Catalog fields for shared snapshot and delta encoding without owning cursor state.
#include "catalog_edition.hpp"

#include <memory>
#include <string>

namespace astra {
Catalog::State::Projection::Event Catalog::Encoding::merge(const State::Projection::Event& previous, State::Projection::Event current) noexcept {
    static_cast<void>(previous); // Catalog increments always carry full bodies, without Attr-baseline hints.
    return current;
}

void Catalog::Encoding::append(Reply& page, std::string_view key, const Content* record, bool data) {

    static_cast<void>(data); // Catalog always carries a complete value.
    auto change = std::make_unique<proto::comet::v1::CatalogChange>();
    change->set_allocated_key(new std::string(key));
    if (!record) {
        change->set_allocated_erase(new proto::comet::v1::Empty);
    } else {
        change->set_version(record->version);
        change->set_allocated_value(new std::string(record->value->begin(), record->value->end()));
    }

    // Both objects are heap-owned. Prepare before repeated-field growth; failed allocation leaves no partial row.
    page.mutable_changes()->AddAllocated(change.get());
    static_cast<void>(change.release());
}
} // namespace astra
