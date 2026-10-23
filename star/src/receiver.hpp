// Receive authoritative Almanac state without exposing incomplete replacement snapshots.
#pragma once
#include "access.hpp"
#include "library.hpp"
#include "polaris.pb.h"
#include <astra/types.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace astra {
/// Business state for one verified Polaris stream, serialized by its receiver task. Reconnection creates a new Receiver.
/// Library survives streams; disconnection drops only partial candidates and pending ACKs, preserving installed data.
class Receiver {
public:
    /// Output/Access outlive receiver. The same Library always pairs with the same Access; no network requests here.
    Receiver(Library& output, Access& access);
    /// Accepts one post-handshake frame; failure rejects later frames. Fixed error categories, with allocation failure allowed to reach the RPC boundary.
    Result<void> receive(const proto::polaris::v1::Packet& packet);
    /// Next bounded control frame. Maximum is negotiated 1024 bytes..8 MiB, default 256 KiB; invalid limits throw.
    /// Inventory pages precede ACKs; coalesce each Scope's ACK to its latest value. Empty means no message.
    std::optional<proto::polaris::v1::Packet> next(std::size_t maximum = 256 * 1024);
    /// True after initial ready and complete local installation of the whole inventory; not a liveness guarantee.
    bool ready() const noexcept;

private:
    /// Protocol dispatch after the stream failure gate, called only by receive.
    Result<void> process(const proto::polaris::v1::Packet& packet);
    /// Strict single-key validation; snapshots forbid Delete and internal credentials decode complete bodies before installation.
    static bool valid(const Scope& scope, const proto::comet::v1::AlmanacChange& change, bool snapshot);
    /// Maps native errors without keys, SECRET, or stored bodies.
    static Result<void> failure(Almanac::Error error);
    /// Collects initial plan metadata, fixed after complete and never below installed local versions.
    Result<void> plan(const proto::polaris::v1::Inventory& page);
    /// One group candidate at a time with fixed Scope/version per page; complete atomically installs and queues ACK.
    Result<void> snapshot(const proto::polaris::v1::Snapshot& page);
    /// Validates packet structure/continuity before applying commits; failure preserves successful complete prefixes.
    Result<void> updates(const proto::polaris::v1::Updates& page);
    /// Records only actual installation, never page receipt or preparation start.
    void acknowledge(const Scope& scope, std::uint64_t version);
    /// Cross-stream Almanac routing; borrows objects, not Map nodes.
    Library& output_;
    /// Login table shares internal-credential commit boundaries across streams; business-RPC lifetime is managed elsewhere.
    Access& access_;
    /// Fixed initial Scopes/minimum positions, at most 4096; install no data before complete receipt.
    std::map<Scope, std::uint64_t> plan_;
    /// Latest pending cumulative ACK per Scope, bounded by valid local Scopes.
    std::map<Scope, std::uint64_t> acknowledgements_;
    /// Stable initial/Probe positions, separate from live versions to avoid duplicate/missing pages.
    std::optional<std::vector<Library::Position>> inventory_;
    /// Consumed inventory items, reset per new inventory.
    std::size_t position_{};
    /// Sole unpublished snapshot candidate; cannot continue across streams.
    std::optional<Library::Draft> draft_;
    /// Parsed index only for __auth/comet, installed/discarded with draft_.
    std::optional<Access::Draft> credentials_;
    /// Initial inventory complete; rejects later plan declarations.
    bool planned_{};
    /// Initial business installation complete, triggered only by an actual ready frame.
    bool ready_{};
    /// First protocol/capacity failure permanently closes receiving; later pages on this stream are forbidden.
    bool failed_{};
};
} // namespace astra
