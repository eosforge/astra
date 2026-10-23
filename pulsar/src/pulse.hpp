// Serve clock synchronization samples from the calibrated Pulsar reference.
#pragma once
#include "authority.hpp"
#include "ledger.hpp"
#include "physical_clock.hpp"
#include "pulsar.grpc.pb.h"

#include <semaphore>

namespace astra {
class Pulse final : public proto::pulsar::v1::Pulse::CallbackService {
public:
    /// Borrows authority, ledger, and clock for the service and every Reactor's lifetime; starts no sampling thread.
    Pulse(const Authority& authority, const Ledger& ledger, const Source& clock);
    /// Returns a Reactor reclaimed by OnDone. Network waits occupy no thread; stream lifetime is limited to three monotonic seconds.
    grpc::ServerBidiReactor<proto::pulsar::v1::Ping, proto::pulsar::v1::Pong>* Bounce(grpc::CallbackServerContext* context) override;

private:
    /// Sampling runs independently; callbacks read short-lock clock snapshots without querying system calibration.
    const Source& clock_;
    /// Borrows verification material; Pulse never performs password authentication or credential signing.
    const Authority& authority_;
    /// Current identity reads use atomic snapshots outside the registration writer lock.
    const Ledger& ledger_;
    /// At most 64 sampling streams, bounding the active set even with slow clients.
    std::counting_semaphore<64> streams_{64};
};
} // namespace astra
