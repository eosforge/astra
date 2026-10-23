// Track scope notification progress while callers retain commit-lock and stream ownership.
#pragma once
#include <cassert>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>

namespace astra {
/// Scope progress and bounded notification rotation. Caller always holds event-index lock; no internal locking, node allocation, or Stream I/O-state access.
template <typename Stream>
class Progress {
public:
    /// Initially empty queue, without external group ownership.
    Progress() = default;
    /// Keep one owner of intrusive scheduling links; copying is forbidden.
    Progress(const Progress&) = delete;
    /// Keep one owner of intrusive scheduling links; copying is forbidden.
    Progress& operator=(const Progress&) = delete;

    /// Embedded in stable routing groups, reclaimed with the final stream; never copy queued links.
    struct Group {
        /// RPC ownership index; erase must go through Progress to preserve scan position.
        std::map<Stream*, std::shared_ptr<Stream>> streams;
        /// First notification while this group exists; absent before any commit, with zero a valid version.
        std::optional<std::uint64_t> first;
        /// Collected Scope end version, independent of per-stream send completion.
        std::uint64_t version{};
        /// Latest replacement/gap boundary; older baselines cannot claim contiguous apply.
        std::optional<std::uint64_t> reset;

        /// Empty group begins outside notification rotation.
        Group() = default;
        /// Keep one owner of notification membership and scheduling links; copying is forbidden.
        Group(const Group&) = delete;
        /// Keep one owner of notification membership and scheduling links; copying is forbidden.
        Group& operator=(const Group&) = delete;

        /// Baseline is frozen or confirmed position; an initial gap or newer reset requires rebuilding it.
        bool covers(std::uint64_t baseline) const noexcept {
            return (!reset || *reset <= baseline) && (!first || baseline == UINT64_MAX || *first <= baseline + 1);
        }

    private:
        friend class Progress;
        /// Present when queued, pointing to the next stream to schedule; erase adjusts it.
        std::optional<typename decltype(streams)::iterator> cursor_;
        /// Scope version when this pass starts; commits arriving mid-pass schedule another round without lost wakeups.
        std::uint64_t through_{};
        /// Intrusive predecessor; null at head or when unqueued.
        Group* previous_{};
        /// Intrusive successor; null at tail or when unqueued.
        Group* next_{};
    };

    /// Collects a commit position and schedules Scope notification. Replacement denotes a baseline; continuity is checked before target filtering.
    void publish(Group& group, std::uint64_t version, bool replacement) noexcept {

        if (replacement || (group.first && (group.version == UINT64_MAX || version != group.version + 1))) {
            group.reset = version;
        }
        if (!group.first) {
            group.first = version;
        }
        group.version = version;

        // One queue position per Scope; consecutive writes update scalars without new allocation or subscription scans.
        if (!group.cursor_ && !group.streams.empty()) {
            group.cursor_ = group.streams.begin();
            group.through_ = version;
            append(group);
        }
    }

    /// Returns a still-owned stream; caller enqueues under the same index lock and never retains a raw pointer across unlock.
    Stream* take() noexcept {

        if (!head_) {
            return nullptr;
        }
        auto& group = *head_;                   // Queue head has an unvisited active stream.
        auto* stream = (*group.cursor_)->first; // Inspect only indices, not writing/done I/O fields.
        ++*group.cursor_;
        detach(group);

        // Rotate Scope to tail per stream so large Scopes or continuous writes cannot starve others.
        if (*group.cursor_ == group.streams.end()) {
            finish(group);
        } else {
            append(group);
        }
        return stream;
    }

    /// Removes RPC ownership, including failed registration rollback. Caller cleans target indices and retains necessary local strong ownership.
    void erase(Group& group, Stream* stream) noexcept {

        const auto found = group.streams.find(stream); // Failed registration may not yet be in the owning index.
        if (found == group.streams.end()) {
            return;
        }
        if (group.cursor_ && *group.cursor_ == found) {
            ++*group.cursor_;
        }
        group.streams.erase(found);

        if (group.cursor_ && *group.cursor_ == group.streams.end()) {
            detach(group);
            finish(group);
        }
    }

    /// Read only under index lock; remaining work wakes the existing loop without waiting for another update.
    bool pending() const noexcept {
        return head_ != nullptr;
    }

private:
    /// After a pass, check newly arrived versions. Empty groups stay unqueued and may be destroyed immediately.
    void finish(Group& group) noexcept {
        if (!group.streams.empty() && group.through_ != group.version) {
            group.cursor_ = group.streams.begin();
            group.through_ = group.version;
            append(group);
        } else {
            group.cursor_.reset();
        }
    }

    /// Append a detached nonempty group without allocation; caller already set cursor.
    void append(Group& group) noexcept {

        assert(group.cursor_ && *group.cursor_ != group.streams.end());
        group.previous_ = tail_;
        group.next_ = nullptr;

        if (tail_) {
            tail_->next_ = &group;
        } else {
            head_ = &group;
        }
        tail_ = &group;
    }

    /// Constant-time unlink without changing the next-stream position.
    void detach(Group& group) noexcept {

        if (group.previous_) {
            group.previous_->next_ = group.next_;
        } else {
            head_ = group.next_;
        }

        if (group.next_) {
            group.next_->previous_ = group.previous_;
        } else {
            tail_ = group.previous_;
        }
        group.previous_ = group.next_ = nullptr;
    }

    /// Pending-Scope head, initially null; outer routing owns Groups.
    Group* head_{};
    /// Tail, null exactly when head_ is null.
    Group* tail_{};
};
} // namespace astra
