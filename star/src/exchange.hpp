// Exchange per-source replication and recovery data between admitted Star peers.
#pragma once
#include "dispatch.hpp"
#include "grpc_session.hpp"
#include "landing.hpp"

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <type_traits>

namespace astra {
/// One authenticated stream for both dynamic source domains. Only Runtime's control thread accesses replication state.
class Exchange final : public Session::Data {
public:
    /// Single gRPC stream message; Session prioritizes keepalive.
    using Packet = proto::astra::v1::SessionPacket;

    /// Cross-stream recovery-buffer budget, counted only by the control thread. Native domain data and gRPC decoding have separate budgets.
    struct Budget {
        /// Reserved encoded backlog and full-candidate workspace bytes.
        std::size_t used{};
        /// Process-wide replication recovery workspace limit.
        std::size_t maximum = 256 * 1024 * 1024;
        /// Capacity failure preserves accounting.
        bool acquire(std::size_t bytes) noexcept;
        /// Release only this owner's acquired allowance.
        void release(std::size_t bytes) noexcept;
    };

    /// Runtime already verified peer identity/epoch and admitted it to both domains. Capacity is the negotiated packet limit.
    Exchange(Catalog::State& catalog, Ephemeris::State& ephemeris, std::string peer, Budget& budget, std::size_t capacity, Steady::time_point now);
    /// Releases private partial snapshots/backlog; installed source facts retain their original TTL.
    ~Exchange() override;
    /// Bounded structural validation and complete-prefix installation.
    Result<void> receive(const Packet& packet, Steady::time_point now) override;
    /// Control messages first, with fair domain-tail scheduling.
    Result<const Packet*> prepare(Steady::time_point now) override;
    /// Transfers the sole packet immediately before StartWrite, without another send queue.
    Packet take() override;
    /// Both initial domain targets are installed.
    bool ready() const noexcept override;
    /// Complete candidate still has Scope work and can advance immediately.
    bool pending() const noexcept override;

private:
    /// Shared recovery mechanics; State retains native domain merge rules rather than a unified KV model.
    template <typename Domain>
    class Pipe {
    public:
        using State = typename Domain::State;
        using Changes = std::conditional_t<std::same_as<Domain, Catalog>, proto::astra::v1::CatalogChanges, proto::astra::v1::EphemerisChanges>;
        using Snapshot = typename Landing<Domain>::Page;
        using Delta = std::conditional_t<std::same_as<Domain, Catalog>, proto::astra::v1::CatalogDelta, proto::astra::v1::EphemerisDelta>;
        /// Explicit wire domain.
        static constexpr auto domain = std::same_as<Domain, Catalog> ? proto::astra::v1::DOMAIN_CATALOG : proto::astra::v1::DOMAIN_EPHEMERIS;

        /// State/budget outlive the stream; outer Exchange owns stable peer text.
        Pipe(State& state, const std::string& peer, Budget& budget, std::size_t capacity, Steady::time_point now);
        /// Returns every domain candidate/backlog reservation.
        ~Pipe();
        /// Validates whole packets before installing facts as a contiguous prefix.
        Result<void> changes(const Changes& changes, Steady::time_point now);
        /// Only complete permits native group/watermark/projection installation.
        Result<void> snapshot(const Snapshot& page, Steady::time_point now);
        /// Verifies correlation; R cannot skip other targets.
        Result<void> repaired(const proto::astra::v1::Repaired& reply, Steady::time_point now);
        /// Answers exact queries from the native local source.
        Result<void> repair(const proto::astra::v1::Repair& request, Packet& response);
        /// Recovery requests, ACKs, and repair requests precede source-tail sends.
        Result<const Packet*> prepare(Steady::time_point now);
        /// Dispatch advances sent position only on gRPC handoff.
        Packet take();
        /// Accepts one recovery starting point per stream/domain.
        Result<void> resume(std::uint64_t position);
        /// ACK confirms only fully dispatched boundaries.
        bool acknowledge(std::uint64_t position);
        /// Once the initial head is installed, later writes cannot revoke startup completion.
        bool ready() const noexcept;
        /// Reply priority cannot bypass this domain's recovery deadline.
        bool expired(Steady::time_point now) const noexcept;

        /// Reports only locally advanceable work; network waiting cannot cause a busy loop.
        bool pending() const noexcept {
            return recovery_.has_value();
        }

    private:
        /// Backlog accumulates only during targeted repair, retaining packets and offsets without per-key body copies.
        struct Pending {
            /// Immutable source packet retaining unprocessed original commits.
            Changes message;
            /// Next commit index, 0..entries_size.
            int offset{};
            /// Acquired budget returned after full consumption or disconnection.
            std::size_t bytes{};
        };

        /// Maps native rejection to fixed stream errors without payloads or peer diagnostics.
        static Status failure(typename State::Error error);
        /// Catalog key or Ephemeris UUID, without text conversion.
        static const std::string& key(const Delta& delta);
        /// Advances only complete-field contiguous facts.
        Result<void> drain(Steady::time_point now);
        /// False means queued for the sole repair wait.
        Result<bool> apply(const Delta& delta, Steady::time_point now);
        /// One active repair per domain; queue budget bounds remaining facts.
        Result<void> missing(const Delta& delta, Steady::time_point now);
        /// Discards private receive work without changing confirmed source roots.
        void clear() noexcept;
        /// Coalesces latest ACK instead of queuing one receipt per fact.
        void acknowledge();

        /// Native committer without network ownership.
        State& state_;
        /// Authenticated source ID with stable outer-owned lifetime.
        const std::string& peer_;
        /// Runtime-wide recovery workspace budget.
        Budget& budget_;
        /// Sends only local facts, never received replicas.
        Dispatch<Domain> dispatch_;
        /// At most 64 packets and 8 MiB charged bytes.
        std::deque<Pending> pending_;
        /// Charged queue bytes.
        std::size_t bytes_{};
        /// At most one private full candidate per domain.
        std::optional<Landing<Domain>> landing_;
        /// Post-receive installation task, at most one Scope per control round.
        std::optional<typename State::Recovery> recovery_;
        /// Full candidates reserve 64 MiB to bound concurrent preparation across streams.
        std::size_t workspace_{};
        /// Blocked target and trigger position, not a global task ID.
        std::optional<proto::astra::v1::Repair> repair_;
        /// At most one control packet; data stays in Dispatch.
        std::optional<Packet> packet_;
        /// Latest installed contiguous position, with duplicate notifications coalesced.
        std::optional<std::uint64_t> acknowledgement_;
        /// Initial packet's source target for the startup barrier.
        std::optional<std::uint64_t> target_;
        /// Installed contiguous position, distinct from targeted repair R.
        std::uint64_t received_{};
        /// Received complete prefix/baseline, possibly ahead of received_ while packets queue.
        std::uint64_t seen_{};
        /// 30-second no-progress deadline for initial recovery, partial snapshots, or repair.
        Steady::time_point deadline_;
        /// Cleared after the first domain recovery request is sent.
        bool resume_ = true;
        /// Peer recovery request received, permitting Dispatch to send data.
        bool opened_{};
        /// Current repair handed to gRPC; prevents repeated requests each round.
        bool requested_{};
        /// Whether prepare borrows from Dispatch, directing take handoff.
        bool dispatched_{};
    };

    /// Repair replies bounded by count and bytes; high-priority control still obeys the sole in-flight write.
    struct Response {
        /// Complete reply from one local-source capture boundary.
        Packet packet;
        /// Shared budget reserved during retention.
        std::size_t bytes{};
    };

    /// Declared before both Pipes so it releases last.
    std::string peer_;
    /// Runtime-owned and outlives all Sessions.
    Budget& budget_;
    /// Negotiated hard limit, at most 8 MiB by default.
    const std::size_t capacity_;
    /// Independent domain position/baseline/repair state.
    Pipe<Catalog> catalog_;
    /// Source sequence independent of Catalog.
    Pipe<Ephemeris> ephemeris_;
    /// At most eight replies and 16 MiB total, without a permanent per-key cache.
    std::deque<Response> responses_;
    /// Current response charge.
    std::size_t responseBytes_{};
    /// Domain round-robin 0/1, initially Catalog.
    unsigned turn_{};
    /// Prepared packet source: 0=none, 1/2=domain, 3=repair reply.
    unsigned selected_{};
};
} // namespace astra
