// Provide optional bounded probes for synchronous spans, asynchronous intervals, and numeric observations.
#pragma once

// CMake propagates diagnostic switches. Disabled probes do not evaluate arguments or add timers, symbols, TLS, or runtime branches.
#if defined(ASTRA_PROFILE) && ASTRA_PROFILE
#include <chrono>
#include <cstdint>
#include <string_view>

namespace astra {
/// Diagnostic builds only; records elapsed spans rather than inferred CPU time, without payloads, Keys, or credentials.
class Profile {
    /// Private recording storage; spans retain only a non-owning pointer until process exit.
    class Storage;

public:
    /// Classifies fixed sites at compile time; hot paths compare bits without string scans or matches.
    struct Site {
        /// Fixed-name FNV-1a, matching the offline catalog.
        std::uint64_t id;
        /// Sole owning feature, with bit position matching Header::groups.
        std::uint64_t group;
    };

    /// Same-thread synchronous RAII span; finish in stack order, without coroutine suspension or transfer to another thread.
    class Span {
    public:
        /// site is a compile-time hash of fixed text, without credentials, addresses, or payloads.
        explicit Span(Site site) noexcept;

        /// Exceptional exits finish spans too. Copy and move are forbidden to preserve the TLS stack and prevent duplicate records.
        ~Span() {
            finish();
        }

        /// Copying would create a second owner of one TLS stack entry and record slot.
        Span(const Span&) = delete;
        /// Reassignment cannot transfer an active stack entry or its pending record.
        Span& operator=(const Span&) = delete;

        /// Early finish measures stages such as lock acquisition; later destruction does nothing and leaves the measured lock's lifetime unchanged.
        void finish() noexcept;

        /// Fixed names are processed at compile time without hot-path string formatting.
        static consteval Site label(std::string_view name) noexcept {

            // clock covers infrequent calibration diagnostics; frequent Clock::now cost belongs to core so business reads do not flood focused collection.
            std::uint64_t group = 64;
            if (name.starts_with("clock.") || name.starts_with("common.pulse_client.") || name.starts_with("common.clock.Filter.") || name.starts_with("common.clock.Clock.observe") || name.starts_with("common.clock.Clock.publish") || name.starts_with("pulsar.pulse.")) {
                group = 1;
            } else if (name.starts_with("comet.")) {
                group = 32;
            } else if (name.starts_with("profile.test.")) {
                group = 128;
            } else if (name.starts_with("star.downstream.") || name.starts_with("star.readout.") || name.starts_with("star.broadcast.") || name.starts_with("star.edition.") || name.starts_with("star.pagination.")) {
                group = 16;
            } else if (name.starts_with("star.exchange.") || name.starts_with("star.dispatch.") || name.starts_with("star.landing.") || name.starts_with("star.receiver.") || name.starts_with("star.intake.") || name.starts_with("star.restore.") || name.find("_replica.") != name.npos || name.starts_with("common.grpc_session.") || name.starts_with("common.session.")) {
                group = 8;
            } else if (name.starts_with("star.catalog_service.") || name.starts_with("star.ephemeris_service.") || name.starts_with("star.gateway.")) {
                group = 4;
            } else if (name.starts_with("star.") || name.starts_with("common.pages.")) {
                group = 2;
            }
            return {identify(name), group};
        }

        /// Asynchronous markers inherit entry sampling without passing TLS parent objects across threads.
        static bool sampled() noexcept {
            return current_ && current_->id_;
        }

        /// Counts follow the sampled call tree only; value is an existing byte, item, or hit count, not an estimated total.
        static void count(Site site, std::uint64_t value, bool signedValue = false) noexcept;

    private:
        /// Selected features only, including unsampled parents to prevent children from resampling.
        inline static thread_local Span* current_{};
        /// Per-thread noncryptographic sampling state; zero means uninitialized.
        inline static thread_local std::uint32_t random_{};
        /// Previous scope on this thread; initially no parent.
        Span* parent_{};
        /// Null when recording is disabled; does not own the mapping.
        Storage* output_{};
        /// Fixed-name ID.
        std::uint64_t site_{};
        /// Zero if unsampled; otherwise process-unique ID.
        std::uint64_t id_{};
        /// Monotonic start in nanoseconds.
        std::uint64_t start_{};
        /// Optional CPU start in nanoseconds.
        std::uint64_t cpu_{};
        /// Total elapsed time of completed direct children.
        std::uint64_t children_{};
        /// Total CPU time of completed direct children.
        std::uint64_t consumed_{};
        /// True only while entered on the thread stack; cleared by finish.
        bool open_{};

        /// Fixed periodic modulo sampling can align with alternating Runtime wait/work phases and miss one class indefinitely.
        /// Top-level xorshift32 uses three shift/XOR groups without allocation, shared atomics, or random-device calls.
        /// Nonzero period is 2^32-1; negligible modulo bias is unsuitable for security or exact-total extrapolation.
        static bool select(std::uint64_t interval) noexcept;
    };

    /// Completion-to-consumption diagnostic timestamp; caller's existing business lock pairs mark and consume without added atomics.
    class Stamp {
    public:
        /// Inherits synchronous-entry sampling. Each new event replaces the completed marker without history or allocation.
        void mark() noexcept {
            start_ = Span::sampled() ? now() : 0;
        }

        /// Another thread may consume under the caller's shared lock/publication boundary; interval is neither this thread's CPU time nor a synchronous child.
        void consume(Site site) noexcept;

    private:
        /// Zero means unsampled or consumed; not business state.
        std::uint64_t start_{};
    };

private:
    /// Process-wide fixed mapping exists only for enabled diagnostics, absent from ordinary builds.
    static Storage& storage() noexcept;

    /// Monotonic nanoseconds measure spans only, never business time or leases.
    static std::uint64_t now() noexcept {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    /// All events share a cached thread ID, requiring at most one syscall per thread.
    static std::uint32_t thread() noexcept;

    /// Actual thread CPU nanoseconds; failures increment the header error count instead of appearing as zero cost.
    static std::uint64_t cpu(Storage& output) noexcept;

    /// Computes fixed-name IDs at compile time; never hashes business data.
    static constexpr std::uint64_t identify(std::string_view name) noexcept {
        std::uint64_t value = 14695981039346656037ULL;
        for (const char item : name) {
            value ^= static_cast<unsigned char>(item);
            value *= 1099511628211ULL;
        }
        return value;
    }
};
} // namespace astra

/// Unique names are joined only by the preprocessor; disabled probes evaluate no arguments and add no business ABI.
#define ASTRA_PROFILE_JOIN_INNER(left, right) left##right
#define ASTRA_PROFILE_JOIN(left, right) ASTRA_PROFILE_JOIN_INNER(left, right)
#define ASTRA_PROFILE_SCOPE(name)                                         \
    const ::astra::Profile::Span ASTRA_PROFILE_JOIN(profile_, __LINE__) { \
        ::astra::Profile::Span::label(name)                               \
    }
#define ASTRA_PROFILE_BEGIN(token, name)    \
    ::astra::Profile::Span token {          \
        ::astra::Profile::Span::label(name) \
    }
#define ASTRA_PROFILE_END(token) token.finish()
#define ASTRA_PROFILE_COUNT(name, value) ::astra::Profile::Span::count(::astra::Profile::Span::label(name), static_cast<std::uint64_t>(value))
#define ASTRA_PROFILE_VALUE(name, value) ::astra::Profile::Span::count(::astra::Profile::Span::label(name), static_cast<std::uint64_t>(static_cast<std::int64_t>(value)), true)
#define ASTRA_PROFILE_STAMP(token) ::astra::Profile::Stamp token
#define ASTRA_PROFILE_MARK(token) token.mark()
#define ASTRA_PROFILE_CONSUME(token, name) token.consume(::astra::Profile::Span::label(name))
#else
#define ASTRA_PROFILE_SCOPE(name) ((void)0)
#define ASTRA_PROFILE_BEGIN(token, name) ((void)0)
#define ASTRA_PROFILE_END(token) ((void)0)
#define ASTRA_PROFILE_COUNT(name, value) ((void)0)
#define ASTRA_PROFILE_VALUE(name, value) ((void)0)
#define ASTRA_PROFILE_STAMP(token) static_assert(true)
#define ASTRA_PROFILE_MARK(token) ((void)0)
#define ASTRA_PROFILE_CONSUME(token, name) ((void)0)
#endif
