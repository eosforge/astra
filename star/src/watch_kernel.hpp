// Coordinate bounded watch I/O progress, deadlines, and cancellation ownership.
#pragma once
#include "progress.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <stdexcept>

namespace astra {
/// Allocation-free scheduling index shared by Downstream/Readout, serialized by the owner's mutex.
/// Owning stream index outlives ready/in-flight membership. Pop returns strong ownership; settle precedes final ownership removal.
template <class Stream>
class Watch {
public:
    /// Per-stream intrusive in-flight links, independent of queued/next ready links and without heap nodes.
    struct Link {
        /// In-flight predecessor; null means head or unlinked, distinguished by Watch::active_.
        Stream* previous{};
        /// In-flight successor; null means tail or unlinked.
        Stream* next{};
    };

    /// Borrows existing domain limits without duplicate defaults; what is a fixed construction diagnostic.
    template <class Limits>
    static void validate(const Limits& limits, const char* what) {
        if (limits.streams == 0 || limits.streams > 65536 || limits.bytes == 0 || limits.pending == 0 || limits.pending > limits.bytes || limits.timeout.count() <= 0) {
            throw std::invalid_argument(what);
        }
    }

    /// Used/cost/hard are bytes. Reject exceeded limits before hard-used subtraction; does not mutate accounting.
    static bool exceeds(std::size_t used, std::size_t cost, std::size_t hard) noexcept {
        return used > hard || cost > hard - used;
    }

    /// Owner index retains stream. True means newly queued; false means already queued so wakeups may coalesce.
    /// Allocation-free without stream I/O locking. Publish callback state under its own lock before enqueue, even when notifications coalesce.
    bool enqueue(Stream& stream) noexcept {

        if (stream.queued) {
            return false;
        }

        stream.queued = true;
        if (tail_) {
            tail_->next = &stream;
        } else {
            head_ = &stream;
        }
        tail_ = &stream;
        return true;
    }

    /// Null for an empty queue; retain strong ownership before pop so the caller may safely acquire I/O after index unlock.
    std::shared_ptr<Stream> pop() noexcept {

        if (!head_) {
            return {};
        }

        auto held = head_->shared_from_this(); // Existing owner supplies the control block; no new allocation.
        head_ = head_->next;
        if (!head_) {
            tail_ = nullptr;
        }
        held->queued = false;
        held->next = nullptr;
        return held;
    }

    /// Transfer at most one Scope notification then pop ready work under one index lock, preserving FIFO and Scope rotation.
    /// Coalesce already-ready streams; even an initially empty ready queue processes progress in this pump call.
    std::shared_ptr<Stream> pop(Progress<Stream>& progress) noexcept {

        if (auto* stream = progress.take()) { // Scope index retains raw pointers; no borrow crosses unlock.
            enqueue(*stream);
        }

        return pop();
    }

    /// Tests only ready work; in-flight streams await callbacks or low-frequency timeout scans without busy looping.
    bool idle() const noexcept {
        return head_ == nullptr;
    }

    /// Links before StartWrite, idempotently, without allocation or exceptions.
    void write(Stream& stream) noexcept {
        if (&stream != active_ && !stream.flight.previous) {
            stream.flight.next = active_;
            if (active_) {
                active_->flight.previous = &stream;
            }
            active_ = &stream;
        }
    }

    /// Unlinks after consuming WriteDone or during final reclamation; safe if already unlinked and preserves ready notifications.
    void settle(Stream& stream) noexcept {

        if (&stream != active_ && !stream.flight.previous) {
            return;
        }

        if (stream.flight.previous) {
            stream.flight.previous->flight.next = stream.flight.next;
        } else {
            active_ = stream.flight.next;
        }
        if (stream.flight.next) {
            stream.flight.next->flight.previous = stream.flight.previous;
        }
        stream.flight = {};
    }

    /// Steady-clock time/deadlines. Once-per-second scan visits in-flight streams only; busy is callback-published atomic state and wake must not reenter index lock.
    /// Deadline writers hold both I/O/index locks; scanning holds index only and never waits on I/O in reverse order.
    template <class Wake>
    void sweep(std::chrono::steady_clock::time_point now, std::chrono::steady_clock::time_point& deadline, Wake&& wake) {

        if (now < deadline) {
            return;
        }

        // Borrow in-flight nodes; enqueue modifies separate ready links without invalidating traversal.
        for (auto* stream = active_; stream; stream = stream->flight.next) {
            if (now >= stream->deadline && stream->busy.load(std::memory_order_acquire)) {
                enqueue(*stream);
            }
        }
        deadline = now + std::chrono::seconds(1);
        if (!idle()) {
            wake();
        }
    }

private:
    /// Ready head, initially null; caller index owns every node.
    Stream* head_{};
    /// Ready tail, null exactly with head_; O(1) append.
    Stream* tail_{};
    /// In-flight head, initially null; arbitrary unlink is O(1).
    Stream* active_{};
};
} // namespace astra
