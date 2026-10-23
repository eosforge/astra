// Maintain copy-on-write SDK record views and staged update publication.
#pragma once
#include <astra/profile.hpp>

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace comet::detail {
/// Private SDK paged dictionary; a complete batch copies at most its affected 256 pages, not the whole table per change.
/// Published pages are never written or reused by use_count; old Views release without accessing destroyed network state.
/// Record exposes bytes() and overhead for payload and object costs; domains share storage without merging version or record semantics.
template <class Record>
class Table {
    /// Hash owned and borrowed key representations through the same string-view bytes.
    struct Hash {
        /// string_view lookup does not construct a temporary string.
        using is_transparent = void;

        /// Hash owned and borrowed keys by identical string-view bytes without allocating.
        std::size_t operator()(std::string_view key) const noexcept {
            return std::hash<std::string_view>{}(key);
        }
    };

    /// Lookup map for one immutable page.
    using Page = std::unordered_map<std::string, Record, Hash, std::equal_to<>>;

    /// Conservative page header, shared control block, and bucket storage, excluding Keys and records charged by bytes_ and size_.
    static std::size_t measure(const Page& page) noexcept {
        return sizeof(Page) + 32 + page.bucket_count() * sizeof(void*);
    }

    /// Root copies exactly 256 shared references; empty pages need no allocation.
    std::array<std::shared_ptr<const Page>, 256> pages_{};
    /// Complete record count, maintained without a full-table scan.
    std::size_t size_{};
    /// Logical Key and Record bytes, not allocator usage or RSS.
    std::size_t bytes_{};
    /// Sum of nonempty page headers and buckets; immutable after publication and zero for an empty table.
    std::size_t overhead_{};

public:
    /// Empty uninstalled container, without version or business-role semantics.
    Table() = default;
    /// Standard shared-root copy and move; later candidates cannot modify read-only pages.
    Table(const Table&) = default;
    /// Transfer read-only page ownership and accounting without modifying shared page contents.
    Table(Table&&) noexcept = default;
    /// Share immutable pages and copy their accounting; later drafts keep published pages unchanged.
    Table& operator=(const Table&) = default;
    /// Transfer read-only page ownership and accounting without modifying shared page contents.
    Table& operator=(Table&&) noexcept = default;

    /// Returns complete entry count in O(1).
    std::size_t size() const noexcept {
        return size_;
    }

    /// Returns complete logical bytes in O(1).
    std::size_t bytes() const noexcept {
        return bytes_;
    }

    /// Conservatively charges pages, buckets, nodes, and payload control blocks for this layout; not an allocator or RSS hard limit.
    std::size_t footprint() const noexcept {
        return bytes_ + sizeof(Table) + size_ * (sizeof(typename Page::value_type) + Record::overhead + 32) + overhead_;
    }

    /// Returns a borrowed record kept alive by this Table; null if missing.
    const Record* find(std::string_view key) const {
        const auto& page = pages_[Hash{}(key) & 255];
        if (!page) {
            return nullptr;
        }
        const auto entry = page->find(key);
        return entry == page->end() ? nullptr : &entry->second;
    }

    /// Traverses stable page order without promising lexical order; reader borrows immutable Keys and Records.
    void each(auto&& reader) const {
        for (const auto& page : pages_) {
            if (page) {
                for (const auto& [key, record] : *page) {
                    reader(key, record);
                }
            }
        }
    }

    /// Exclusive preparation for a complete batch; callers discard the entire Draft on failure without publishing partial pages or counts.
    class Draft {
    public:
        /// Captures an existing read-only root; reset uses an empty Table and apply shares the old root.
        explicit Draft(const Table& base) : pages_(base.pages_), size_(base.size_), bytes_(base.bytes_), overhead_(base.overhead_) {}

        /// Transfers a candidate within one recovery task.
        Draft(Draft&&) noexcept = default;
        /// Prevents writers from sharing writable pages.
        Draft(const Draft&) = delete;

        /// Includes this batch's unpublished changes.
        std::size_t size() const noexcept {
            return size_;
        }

        /// Used by the caller to enforce local view budgets.
        std::size_t bytes() const noexcept {
            return bytes_;
        }

        /// Charges private root and changed-page references, including old shared pages, rather than Buffer bytes alone.
        std::size_t footprint() const noexcept {
            return bytes_ + sizeof(Draft) + size_ * (sizeof(typename Page::value_type) + Record::overhead + 32) + overhead_;
        }

        /// Borrows key for this call; copies into page-owned storage only on insertion. Replacing an existing Key reallocates no name.
        /// Record owns or shares its payload; other entries copy only on the page's first change.
        void set(std::string_view key, Record record) {

            ASTRA_PROFILE_SCOPE("comet.cpp.table.set");

            // Check single-record arithmetic before page copying so invalid lengths allocate no page.
            const auto payload = record.bytes(); // Record reports its payload only; charge Key separately.
            if (payload > SIZE_MAX - key.size()) {
                throw std::length_error("View record size overflow");
            }
            const auto cost = key.size() + payload;

            // slot selects the hash page; old and previous capture the record and logical size before replacement.
            const auto slot = Hash{}(key) & 255;
            auto& page = edit(slot);
            const auto old = page.find(key);
            const auto previous = old == page.end() ? 0 : old->first.size() + old->second.bytes();
            if (cost > SIZE_MAX - (bytes_ - previous)) {
                throw std::length_error("View byte count overflow");
            }

            // Reuse the existing iterator instead of repeating string hashing and lookup in insert_or_assign.
            // Only insertion may grow buckets; callers still discard the whole candidate on any exception.
            if (old != page.end()) {
                old->second = std::move(record);
            } else {
                const auto before = measure(page); // Measure one page without scanning the other 255.
                page.emplace(std::string(key), std::move(record));
                overhead_ = overhead_ - before + measure(page);
                ++size_;
            }
            bytes_ = bytes_ - previous + cost;
        }

        /// Missing Delete changes nothing and copies no empty page; reclaim empty pages instead of retaining historical buckets.
        void erase(std::string_view key) {

            ASTRA_PROFILE_SCOPE("comet.cpp.table.erase");

            // A missing original Key creates no changed page; exclusive pages use one find rather than contains followed by find.
            const auto slot = Hash{}(key) & 255;
            if (!dirty_[slot] && (!pages_[slot] || !pages_[slot]->contains(key))) {
                return;
            }

            // erase preserves unordered_map bucket count; charge empty pages until finish actually releases ownership.
            auto& page = edit(slot);
            const auto found = page.find(key);
            if (found == page.end()) {
                return;
            }
            bytes_ -= found->first.size() + found->second.bytes();
            --size_;
            page.erase(found);
        }

        /// Publishes read-only pages and consumes the candidate; set, erase, and finish are then forbidden.
        Table finish() && {

            ASTRA_PROFILE_SCOPE("comet.cpp.table.finish");

            // Transfer the old root first, then process only four occupancy words and their changed pages.
            Table result;
            result.pages_ = std::move(pages_);
            for (std::size_t group = 0; group < changed_.size(); ++group) {
                auto bits = changed_[group]; // Each set bit denotes an exclusively prepared page; clearing traversal bits leaves the original bitmap unchanged.
                while (bits != 0) {
                    const auto slot = group * 64 + static_cast<std::size_t>(std::countr_zero(bits)); // Range 0..255.
                    auto& page = dirty_[slot];                                                       // A set bit guarantees a page exists, even after its final Key was deleted.
                    if (page->empty()) {
                        overhead_ -= measure(*page);
                        result.pages_[slot].reset();
                        page.reset();
                    } else {
                        result.pages_[slot] = std::move(page);
                    }
                    bits &= bits - 1;
                }
            }

            // Published charges exclude freed empty pages; lookup and old snapshots never borrow Draft.
            result.size_ = size_;
            result.bytes_ = bytes_;
            result.overhead_ = overhead_;
            return result;
        }

    private:
        /// Copy only the first affected page; writable pointers never escape to old Tables or public Views.
        Page& edit(std::size_t slot) {

            ASTRA_PROFILE_SCOPE("comet.cpp.table.edit");
            if (!dirty_[slot]) {
                // Hash-map copies need not preserve bucket count; replace old charges with the new page's actual storage.
                auto page = pages_[slot] ? std::make_shared<Page>(*pages_[slot]) : std::make_shared<Page>();
                overhead_ = overhead_ - (pages_[slot] ? measure(*pages_[slot]) : 0) + measure(*page);
                dirty_[slot] = std::move(page);
                changed_[slot / 64] |= std::uint64_t{1} << (slot % 64);
            }
            return *dirty_[slot];
        }

        /// Read-only shared original root; candidates may be destroyed independently.
        std::array<std::shared_ptr<const Page>, 256> pages_;
        /// Exclusively owned changed pages with no external writable aliases.
        std::array<std::shared_ptr<Page>, 256> dirty_{};
        /// 256-page change bitmap avoids a dynamic index or per-page null checks.
        std::array<std::uint64_t, 4> changed_{};
        /// Prepared record count.
        std::size_t size_{};
        /// Prepared logical Key and payload bytes.
        std::size_t bytes_{};
        /// Candidate page-header and bucket sum, including unpublished empty changed pages.
        std::size_t overhead_{};
    };
};
} // namespace comet::detail
