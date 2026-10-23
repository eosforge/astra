// Schedule expiry from caller-supplied time without owning threads or reading a clock.
#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <stdexcept>
#include <utility>

namespace astra {

/// Levels and Bits define wheel depth and slot bits. Single-threaded, or externally serialize every operation and node destruction with one lock.
/// tick advances one logical unit; same-tick callbacks have no order guarantee. No clock reads, empty-slot skipping, or per-tick callback cap.
template <std::size_t Levels = 5, std::size_t Bits = 8>
requires(Levels > 0 && Bits > 0 && Bits <= 10 && Levels <= 64 / Bits)
class Wheel {
    /// At most 1024 slots per level and 64 total index bits, preventing invalid shifts and unexpectedly huge arrays.
    static constexpr std::size_t slots_ = std::size_t{1} << Bits;
    /// Slot-index mask replaces modulo; slots is always a power of two.
    static constexpr std::uint64_t mask_ = slots_ - 1;

public:
    /// Maximum relative delay without overflow levels; total bits 1..64 implies legal right shifts 0..63.
    static constexpr std::uint64_t limit = std::numeric_limits<std::uint64_t>::max() >> (64 - Levels * Bits);

    /// Intrusive business timer hook belongs to at most one Wheel, has a stable linked address, and owns no business data.
    struct Node {
        /// Creates an unscheduled node without allocation; expiry is meaningful only after successful scheduling.
        Node() noexcept = default;

        /// Whichever of Node/Wheel dies first detaches links; callbacks may destroy current or not-yet-fired nodes.
        ~Node() {
            Wheel::cancel(*this);
        }

        /// Links contain other objects' addresses, so nodes cannot copy or move; business containers must preserve addresses.
        Node(const Node&) = delete;
        /// Forbids copying links and aliasing the same predecessor slot.
        Node& operator=(const Node&) = delete;
        /// Forbids changing node address, even while currently unscheduled.
        Node(Node&&) = delete;
        /// Move assignment cannot replace live link storage.
        Node& operator=(Node&&) = delete;

        /// Reports membership in a slot or ready queue; borrowed state requires the same serialized access as other operations.
        [[nodiscard]] bool scheduled() const noexcept {
            return pprev_ != nullptr;
        }

    private:
        friend class Wheel;
        /// Next node in the bucket, without ownership of its lifetime.
        Node* next_{};
        /// Pointer that references this node: slot head, ready_, or predecessor next_; enables O(1) unlinking.
        Node** pprev_{};
        /// Absolute due tick in this Wheel's logical time; unsigned arithmetic permits uint64_t wrap.
        std::uint64_t deadline_{};
    };

    /// Creates an empty wheel at initialTick, independent of system clocks and other Wheels.
    explicit Wheel(std::uint64_t initialTick = 0) noexcept : clock_(initialTick) {}

    /// Detaches hooks without callbacks or node destruction; destroying this Wheel within its tick callback is forbidden.
    ~Wheel() {

        detach(ready_);
        for (auto& level : wheels_) {
            for (auto& head : level) {
                detach(head);
            }
        }
    }

    /// Nodes borrow slot-head and ready_ addresses, so even empty Wheels cannot copy or move.
    Wheel(const Wheel&) = delete;
    /// Forbids copying slot-head addresses and node links.
    Wheel& operator=(const Wheel&) = delete;
    /// Forbids movement while nodes may borrow current slot-head addresses.
    Wheel(Wheel&&) = delete;
    /// Forbids replacing or moving Wheel storage referenced by nodes.
    Wheel& operator=(Wheel&&) = delete;

    /// Delay above limit returns false and preserves scheduling; success cancels prior scheduling and permits serialized transfer between Wheels.
    [[nodiscard]] bool schedule(Node& node, std::uint64_t delay) noexcept {

        if (delay > limit) {
            return false;
        }
        cancel(node);
        node.deadline_ = clock_ + std::max(delay, std::uint64_t{1});
        insert(node);
        return true;
    }

    /// Cancels node on any Wheel; unscheduled is a no-op. No allocation, user code, or expiry-value change.
    static void cancel(Node& node) noexcept {

        if (node.pprev_ == nullptr) {
            return;
        }
        *node.pprev_ = node.next_;
        if (node.next_ != nullptr) {
            node.next_->pprev_ = node.pprev_;
        }
        node.pprev_ = nullptr;
        node.next_ = nullptr;
    }

    /// Returns advanced logical ticks with uint64_t wrap; callbacks observe this due tick, not the next one.
    [[nodiscard]] std::uint64_t now() const noexcept {
        return clock_;
    }

    /// Invokes a Node*-accepting callback without copying it or erasing through std::function.
    /// Unlinks before invocation; callback may cancel, reschedule, or destroy any Node, but not this Wheel.
    /// Exceptions propagate: current callback is consumed, remaining nodes stay cancelable and are drained before the next tick advances.
    /// Recursive tick on this Wheel throws logic_error without advancing; other Wheels remain independent.
    template <typename F>
    requires std::invocable<F&, Node*>
    void tick(F&& fire) {

        // Restores reentrancy state on normal or exceptional exit; this is not a thread-synchronization primitive.
        Guard guard(busy_);
        drain(fire);
        ++clock_;

        // Cascade only when lower bits clear, from highest level down so newly lowered nodes may continue descending this tick.
        // Highest level to advance; countr_zero(0) is 64 and covers clock wrap correctly.
        for (auto level = std::min(Levels - 1, static_cast<std::size_t>(std::countr_zero(clock_)) / Bits); level > 0; --level) {
            // Takes the whole upper bucket without callbacks or exceptions, avoiding per-node maintenance of obsolete backward links.
            // Bucket detachment is O(1); reclassification still visits every bucket node.
            auto* bucket = std::exchange(wheels_[level][(clock_ >> (level * Bits)) & mask_], nullptr);
            while (bucket != nullptr) {
                // Save successor before reclassification because insert overwrites node links.
                auto* node = bucket;
                bucket = node->next_;
                insert(*node);
            }
        }

        // Move the due bucket under member ready_ so exceptions cannot leave hooks pointing to a stack variable.
        ready_ = std::exchange(wheels_[0][clock_ & mask_], nullptr);
        if (ready_ != nullptr) {
            ready_->pprev_ = &ready_;
        }
        drain(fire);
    }

private:
    /// Allocation-free stack guard prevents recursive advancement of this Wheel only.
    struct Guard {
        /// Borrows the Wheel reentrancy flag; lifetime remains strictly within tick.
        bool& flag;

        /// If already entered, throw without clearing true; outer guard owns restoration.
        explicit Guard(bool& value) : flag(value) {

            if (std::exchange(flag, true)) {
                throw std::logic_error("Wheel::tick cannot reenter the same wheel");
            }
        }

        /// Restores the flag during exception unwinding without touching nodes or callbacks.
        ~Guard() {
            flag = false;
        }

        /// Forbids duplicate restoration of one borrowed flag.
        Guard(const Guard&) = delete;
        /// Assignment cannot overwrite an active restoration responsibility.
        Guard& operator=(const Guard&) = delete;
    };

    /// Inserts a detached node after schedule bounds checking or cascade reclassification.
    void insert(Node& node) noexcept {

        // Modulo-2^64 remaining ticks within limit; zero expires in the lowest level this tick.
        const auto remaining = node.deadline_ - clock_;
        // Highest set bit selects level; setting the low bit routes zero to the lowest level without changing nonzero highest bits.
        const auto level = static_cast<std::size_t>(std::bit_width(remaining | 1) - 1) / Bits;
        // Stable destination slot head; both head and node addresses remain fixed while linked.
        auto& head = wheels_[level][(node.deadline_ >> (level * Bits)) & mask_];
        node.next_ = head;
        node.pprev_ = &head;
        if (head != nullptr) {
            head->pprev_ = &node.next_;
        }
        head = &node;
    }

    /// Detach one node at a time from member queue; never retain next across a callback that may cancel or destroy it.
    template <typename F>
    void drain(F& fire) {

        while (ready_ != nullptr) {
            // Borrow ends at callback invocation; never access afterward, permitting self-destruction or rescheduling.
            // Pop the known head and repair successor links before user code so the remaining queue is already valid.
            auto* node = ready_;
            ready_ = node->next_;
            if (ready_ != nullptr) {
                ready_->pprev_ = &ready_;
            }
            node->pprev_ = nullptr;
            node->next_ = nullptr;
            std::invoke(fire, node);
        }
    }

    /// Detaches every node under head without ending node lifetimes; destructor path allocates nothing and cannot throw.
    static void detach(Node*& head) noexcept {

        // Takes the full list; no callbacks during cleanup, so clearing hooks needs no intermediate backward-link maintenance.
        auto* node = std::exchange(head, nullptr);
        while (node != nullptr) {
            // Save successor before clearing hooks, only for this callback-free destruction walk.
            auto* next = node->next_;
            node->pprev_ = nullptr;
            node->next_ = nullptr;
            node = next;
        }
    }

    /// Wheel logical clock, advanced by tick only after draining the callback queue.
    std::uint64_t clock_{};
    /// Due nodes awaiting invocation share one stable head across callbacks and exceptional exits.
    Node* ready_{};
    /// Blocks callback recursion; external serialization remains required, without an owner pointer per node.
    bool busy_{};
    /// Fixed zero-initialized slot heads; Wheel borrows Nodes and only detaches them on destruction.
    std::array<std::array<Node*, slots_>, Levels> wheels_{};
};

} // namespace astra
