// Provide persistent page storage and staged updates shared by owned indexes.
#pragma once
#include <astra/profile.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace astra {
/// Capture and writes use the owning state lock; readers synchronize completion through that lock, then release View outside it, including exceptions.
/// This establishes read completion before shared pages become exclusive again; use_count alone is not a read/write barrier.
/// prepare may allocate without changing logical contents; set and erase commit without allocation.
/// Reuse free slots by page occupancy and reclaim empty pages; depth at most 15, without space proportional to historical deletes.
template <typename Item, typename Name = std::string>
class Pages {
    /// Allocation-free commit requires nonthrowing record moves; page-copy construction may still fail allocation.
    static_assert(std::is_nothrow_move_assignable_v<Item>);

public:
    /// Owns opaque payload bytes; empty Buffer is valid.
    using Buffer = std::vector<std::uint8_t>;
    /// Shared immutable payload ownership; null denotes an unoccupied internal row only.
    using Value = std::shared_ptr<const Buffer>;
    /// Shared immutable Key ownership avoids reallocating long names on path copies.
    using Key = std::shared_ptr<const Name>;

    /// Native record type; page index interprets neither payload, version, nor TTL.
    using Record = Item;

private:
    /// used counts live subtree entries for O(1) empty-subtree detection and reclamation.
    struct Node {
        /// Current live subtree record count, initially zero; prepared empty pages do not increment it.
        std::size_t used{};
    };

    /// 64-entry page shares Key ownership; replacements reuse long Keys while old views retain their own Values.
    struct Row {
        /// Occupied row owns one slot and shares Key text; null denotes a free row.
        Key key;
        /// Payload and deadline at the Key's version; old Views retain the previous record.
        Record record;
    };

    /// Terminal radix page with a fixed row array and occupancy bitmap for reusable slots.
    struct Leaf : Node {
        /// Bitmap finds a free slot in O(1), updated with used during nonthrowing commit.
        std::uint64_t occupied{};
        /// Fixed 64 rows addressed by the slot's low six bits; empty rows are never returned.
        std::array<Row, 64> rows;
    };

    /// Internal page has 16 children; shared_ptr preserves derived deleters without polymorphic Node access.
    struct Branch : Node {
        /// Fixed 16 shared children, null if unallocated; top level uses four only.
        std::array<std::shared_ptr<Node>, 16> children;
    };

public:
    /// View owns root and depth, copied under the state lock in O(1); live Views force later writes to copy modified paths.
    class View {
    public:
        /// Returns captured live count without traversal; query only during this View's lifetime.
        std::size_t size() const noexcept {
            return root_ ? root_->used : 0;
        }

        /// reader borrows stable Key/Value references; traversal and final release occur outside the owning state lock.
        /// On reader exceptions, caller still performs read-completion synchronization; exceptions never become partial success.
        void each(auto&& reader) const {
            visit(root_.get(), height_, reader);
        }

        /// Visits at most maximum live entries starting at offset; reader true consumes the item, false pauses before it.
        /// Returns consumed count without changing View; subtree counts skip prefixes instead of rescanning prior pages.
        /// offset must be in 0..size; maximum zero permits an empty-page query. Exceptions discard this page and preserve the old position.
        std::size_t page(std::size_t offset, std::size_t maximum, auto&& reader) const {

            ASTRA_PROFILE_SCOPE("common.pages.page");

            if (offset > size()) {
                throw std::out_of_range("Snapshot page position exceeds view");
            }
            std::size_t consumed{}; // Entries accepted by reader for this page, excluding a rejected current item.
            if (maximum != 0) {
                static_cast<void>(slice(root_.get(), height_, offset, maximum, consumed, reader));
            }
            return consumed;
        }

    private:
        friend class Pages;
        /// Captured immutable root, possibly empty; retains old pages until View release.
        std::shared_ptr<const Node> root_;
        /// Captured height 0..15, with zero denoting a leaf; independent of later index changes.
        unsigned height_{};
    };

    /// Captures stable index root without allocation; caller captures its business version under the same lock.
    View capture() const noexcept {

        // Copies root ownership and height only, without copying Keys/Values or traversing nodes.
        View result;
        result.root_ = root_;
        result.height_ = height_;
        return result;
    }

    /// New Keys reuse existing free slots; grow only when full so delete/recreate cycles cannot accumulate sparse pages indefinitely.
    std::uint64_t next() const {

        if (height_ < 15 && root_ && root_->used == (std::uint64_t{1} << (6 + height_ * 4))) {
            return std::uint64_t{1} << (6 + height_ * 4);
        }

        // Lowest available slot; UINT64_MAX is an exhaustion sentinel, never a business slot.
        const auto slot = vacant(root_.get(), height_, 0);
        if (slot == UINT64_MAX) {
            throw std::overflow_error("Store snapshot slot exhausted");
        }
        return slot;
    }

    /// One slot lookup borrows Key ownership and native record; two null pointers if absent. Borrows cannot cross later prepare or commit.
    std::pair<const Key*, const Record*> find(std::uint64_t slot) const noexcept {

        if (height_ < 15 && (slot >> (6 + height_ * 4)) != 0) {
            return {};
        }
        const auto* node = root_.get(); // Read-only path lookup without capturing root or incrementing shared references.
        for (auto level = height_; node && level != 0; --level) {
            node = static_cast<const Branch*>(node)->children[branch(slot, level)].get();
        }
        if (!node) {
            return {};
        }
        const auto& row = static_cast<const Leaf*>(node)->rows[slot & 63]; // Leaf row for this stable slot.
        return row.key ? std::pair<const Key*, const Record*>{&row.key, &row.record} : std::pair<const Key*, const Record*>{};
    }

    /// Native-record-only lookup hides page layout; caller still holds owning-state protection.
    const Record* at(std::uint64_t slot) const noexcept {
        return find(slot).second;
    }

    /// Creates or copies the full path to slot; failure may leave equivalent private pages but preserves current and captured logical contents.
    void prepare(std::uint64_t slot) {

        ASTRA_PROFILE_SCOPE("common.pages.prepare");

        // Level 15 covers all uint64 slots; never shift by or beyond the bit width.
        while (height_ < 15 && (slot >> (6 + height_ * 4)) != 0) {
            // Allocate parent before commit; child zero preserves every existing slot number.
            auto parent = std::make_shared<Branch>();
            parent->children[0] = root_;
            parent->used = root_ ? root_->used : 0;
            root_ = std::move(parent);
            ++height_;
        }

        // Borrows each shared-pointer link; do not modify business records before full path privatization.
        auto* link = &root_;
        // Descends internal levels 1..15; leaf level zero is handled after the loop.
        for (auto level = height_; level != 0; --level) {
            privatePage<Branch>(*link);
            link = &static_cast<Branch&>(**link).children[branch(slot, level)];
        }
        privatePage<Leaf>(*link);
    }

    /// Commits after prepare; non-null key denotes insertion, while replacement passes an empty Key and reuses original text.
    void set(std::uint64_t slot, Key key, Record record) noexcept {

        ASTRA_PROFILE_SCOPE("common.pages.set");

        // Only newly occupied slots increment ancestor used counts and set occupancy bits.
        const bool added = static_cast<bool>(key);
        // Borrows prepared private pages; addresses remain stable during allocation-free commit.
        auto* node = root_.get();
        // Descends internal levels 1..15; leaf level zero is handled after the loop.
        for (auto level = height_; level != 0; --level) {
            node->used += added;
            node = static_cast<Branch*>(node)->children[branch(slot, level)].get();
        }

        // Level-zero leaf matching height_'s path structure.
        auto& leaf = static_cast<Leaf&>(*node);
        // Borrows the row selected by slot's low six bits, range 0..63.
        auto& row = leaf.rows[slot & 63];
        assert(added == !row.key);
        node->used += added;
        if (added) {
            row.key = std::move(key);
            leaf.occupied |= std::uint64_t{1} << (slot & 63);
        }
        row.record = std::move(record);
    }

    /// Deletes a prepared live slot, reclaiming empty subtrees along its path without scanning other pages or allocating free lists.
    void erase(std::uint64_t slot) noexcept {

        ASTRA_PROFILE_SCOPE("common.pages.erase");

        remove(root_, height_, slot);
        if (!root_) {
            height_ = 0;
        }
        while (root_ && height_ != 0) {
            // Borrows root children; acquire an independent promoted-child reference before shrinking the root.
            const auto& children = static_cast<const Branch&>(*root_).children;
            // Only child zero can be promoted unchanged; other positions encode high slot bits. Counts exclude ordinary multibranch roots first.
            if (!children[0] || children[0]->used != root_->used) {
                break;
            }

            // prepare may leave uncommitted empty paths; used alone cannot justify discarding them.
            if (std::ranges::any_of(children.begin() + 1, children.end(), [](const auto& child) { return child != nullptr; })) {
                break;
            }

            // Acquire ownership before releasing old root; never move links still shared with old Views. Promotion allocates nothing.
            auto child = children[0];
            root_ = std::move(child);
            --height_;
        }
    }

private:
    /// Clone only pages shared with old views or other parents; exclusive pages commit in place without reallocating whole paths.
    template <typename Page>
    static void privatePage(std::shared_ptr<Node>& link) {

        if (!link) {
            ASTRA_PROFILE_COUNT("common.pages.allocate_bytes", sizeof(Page));
            link = std::make_shared<Page>();
        } else if (link.use_count() != 1) {
            ASTRA_PROFILE_COUNT("common.pages.clone_bytes", sizeof(Page));
            link = std::make_shared<Page>(static_cast<const Page&>(*link));
        }
    }

    /// Level 1..15 selects four slot bits; caller guarantees depth matches node type.
    static unsigned branch(std::uint64_t slot, unsigned level) noexcept {
        return static_cast<unsigned>((slot >> (6 + (level - 1) * 4)) & 15);
    }

    /// Skip full subtrees by live counts; inspect at most 16 links per level, without scanning Keys or tombstones.
    static std::uint64_t vacant(const Node* node, unsigned level, std::uint64_t prefix) noexcept {

        if (!node) {
            return prefix;
        }
        if (level == 0) {
            // One free bit denotes an available slot; zero means full. Never select a bit from zero.
            const auto free = ~static_cast<const Leaf*>(node)->occupied;
            return free ? prefix | static_cast<std::uint64_t>(std::countr_zero(free)) : UINT64_MAX;
        }

        // Child low-bit width, 6..62 by level; all shifts remain below 64.
        const auto shift = 6 + (level - 1) * 4;
        // Borrows child array and uses used to skip full subtrees without leaf scans.
        const auto& children = static_cast<const Branch*>(node)->children;
        // Top level has only four links within the 64-bit slot domain; prevent shifted truncation and wrap.
        for (unsigned child = 0; child < (level == 15 ? 4U : 16U); ++child) {
            if (!children[child] || children[child]->used < (std::uint64_t{1} << shift)) {
                return vacant(children[child].get(), level - 1, prefix | (static_cast<std::uint64_t>(child) << shift));
            }
        }
        return UINT64_MAX;
    }

    /// prepare made this live path private; clear the leaf and decrement ancestors without touching other subtrees.
    static void remove(std::shared_ptr<Node>& link, unsigned level, std::uint64_t slot) noexcept {

        assert(link && link->used != 0);
        if (level == 0) {
            // Private leaf; deletion changes only target row and its occupancy bit.
            auto& leaf = static_cast<Leaf&>(*link);
            // Row must be live; clear references and occupancy before reclaiming empty ancestors.
            auto& row = leaf.rows[slot & 63];
            assert(row.key);
            row = {};
            leaf.occupied &= ~(std::uint64_t{1} << (slot & 63));
        } else {
            remove(static_cast<Branch&>(*link).children[branch(slot, level)], level - 1, slot);
        }
        if (--link->used == 0) {
            link.reset();
        }
    }

    /// Visits live entries by increasing slot; reader may throw. View retains pages without accessing mutable owning-state nodes.
    static void visit(const Node* node, unsigned level, auto& reader) {

        if (!node || node->used == 0) {
            return;
        }
        if (level == 0) {
            // Borrows leaf rows sequentially, invoking reader for occupied rows only; View bounds borrow lifetime.
            for (const auto& row : static_cast<const Leaf*>(node)->rows) {
                if (row.key) {
                    reader(*row.key, row.record);
                }
            }
        } else {
            // Borrows children in order and skips empty subtrees without changing pages during traversal.
            for (const auto& child : static_cast<const Branch*>(node)->children) {
                visit(child.get(), level - 1, reader);
            }
        }
    }

    /// Bounded ordered read: skip counts live entries to skip, remaining is page capacity, and consumed increments only after reader accepts.
    /// False means full page or reader pause; captured root is unchanged and leaf shifts stay in 0..63.
    static bool slice(const Node* node, unsigned level, std::size_t& skip, std::size_t& remaining, std::size_t& consumed, auto& reader) {

        if (!node || node->used == 0) {
            return true;
        }
        if (skip >= node->used) {
            skip -= node->used;
            return true;
        }
        if (level != 0) {
            for (const auto& child : static_cast<const Branch*>(node)->children) {
                if (!slice(child.get(), level - 1, skip, remaining, consumed, reader)) {
                    return false;
                }
            }
            return true;
        }

        const auto& leaf = *static_cast<const Leaf*>(node); // Captured fixed leaf, independent of the current mutable index.
        auto occupied = leaf.occupied;                      // Scan occupied bits only, without traversing historical maximum empty slots.
        while (occupied) {
            const auto slot = static_cast<unsigned>(std::countr_zero(occupied));
            occupied &= occupied - 1;
            if (skip != 0) {
                --skip;
                continue;
            }
            const auto& row = leaf.rows[slot]; // Borrowed references live only during reader invocation.
            if (!reader(*row.key, row.record)) {
                return false;
            }
            ++consumed;
            if (--remaining == 0) {
                return false;
            }
        }
        return true;
    }

    /// Owning writer accesses root_ only under its state lock; View references keep read pages immutable.
    std::shared_ptr<Node> root_;
    /// Current height 0..15, zero for empty tree; deletion shrinks only while preserving slots and prepared paths.
    unsigned height_{};
};
} // namespace astra
