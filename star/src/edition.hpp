// Page a frozen Almanac projection without rereading mutable state during delivery.
#pragma once
#include "almanac.hpp"
#include "comet.pb.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace astra {
/// Frozen Almanac downstream projection; paging neither rereads mutable groups nor copies the whole Map per Watch.
/// One sending task. Construct the next page only after gRPC releases the previous one; final complete determines recovery position.
class Edition {
public:
    /// Fixed full root in reset mode; Almanac already performed O(1) capture, without recounting here.
    explicit Edition(Almanac::View view);
    /// Fixed complete point lookup. Missing values form a valid empty reset; entry validates key.
    Edition(std::string key, Almanac::Point point);
    /// Fixed contiguous-history endpoint, compacted to final actions per key; nonempty target filters to one exact key.
    explicit Edition(Almanac::Replay replay, std::string_view target = {});
    /// Version-zero empty reset for a Scope absent from the confirmed authority inventory, without creating persistent state.
    Edition();
    /// Transfers frozen root/history ownership without copying paging state or large payloads.
    Edition(Edition&&) noexcept = default;

    /// Keep one owner of one sending task's paging cursor; copying is forbidden.
    Edition(const Edition&) = delete;
    /// Targets at most 256 KiB or 256 records per page. One larger valid record may occupy a page, within the 8 MiB hard limit.
    /// Fixed Star instance appears only on the last page. Calling after completion throws logic_error; failure preserves page position.
    proto::comet::v1::AlmanacWatchReply next(std::string_view instance);
    /// Final page constructed, without implying completed Write or client installation.
    bool complete() const noexcept;
    /// Fixed completion position; stream advances only after the last page writes successfully.
    std::uint64_t version() const noexcept;
    /// Conservative retained snapshot/history bytes, not new allocation size or process RSS.
    std::size_t bytes() const noexcept;

private:
    /// Exact reset retains only one key and immutable value, without the full root. Null value means missing.
    struct Point {
        /// Exact text key without formatted path concatenation.
        std::string key;
        /// Complete content fixed by point lookup; null means absent at capture.
        Almanac::Value value;
    };

    /// Appends a complete operation. Soft target returns false without consuming it; a single hard-limit violation throws length_error.
    static bool append(proto::comet::v1::AlmanacWatchReply& page, std::size_t& bytes, std::string_view key, const Almanac::Value& value);
    /// Mutually exclusive empty baseline, full root, point, and frozen history; source never changes within a batch.
    std::variant<std::monostate, Almanac::View, Point, std::vector<Almanac::Change>> data_;
    /// Fixed batch mode, initially empty reset.
    proto::comet::v1::Mode mode_ = proto::comet::v1::MODE_RESET;
    /// Authoritative position captured with the fixed data, initially zero.
    std::uint64_t version_{};
    /// Successfully constructed item count; next failure leaves it unchanged.
    std::size_t offset_{};
    /// Conservative frozen content/key/history-reference charge, initially zero.
    std::size_t bytes_{};
    /// Whether the complete page has been produced, initially false.
    bool complete_{};
};
} // namespace astra
