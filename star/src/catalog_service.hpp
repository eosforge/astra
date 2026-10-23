// Translate public Catalog RPCs into native state operations and owned stream lifecycles.
#pragma once
#include "catalog_state.hpp"
#include "gateway.hpp"

#include <chrono>
#include <cstddef>
#include <expected>
#include <functional>
#include <memory>
#include <new>
#include <optional>
#include <semaphore>
#include <string>
#include <string_view>

namespace astra {
/// Public Catalog writes using logical Session and native State. Registered only on the separate Comet port, without peer-source input.
class Catalog::Service final : public proto::comet::v1::Catalog::CallbackService {
public:
    /// State/Gateway outlive all RPCs. Maximum concurrent synchronous preparations: 1..65536, default 128.
    Service(State& state, Gateway& gateway, std::ptrdiff_t maximum = 128);
    /// Runtime supplies a shared loop wakeup without per-connection threads.
    Service(State& state, Gateway& gateway, std::function<void()> wake, std::ptrdiff_t maximum = 128);
    /// Destroy only after Server drains all calls; owns no per-connection thread or background task.
    ~Service() override;
    /// Same control thread pumps expiration and at most 32 ready Watches. Failure ends old streams instead of claiming catch-up.
    void pump(std::chrono::steady_clock::time_point now, std::size_t maximum = 32);
    /// Parent first stops Gateway write admission, then stop/pump until empty and drain Server.
    void stop() noexcept;
    /// All Watch OnDone callbacks are reclaimed; Server::Wait completes unary cleanup.
    bool empty() const;
    /// Shares fixed State/Gateway; reset and contiguous apply publish only on complete.
    grpc::ServerWriteReactor<proto::comet::v1::CatalogWatchReply>* Watch(grpc::CallbackServerContext* context, const proto::comet::v1::WatchRequest* request) override;
    /// Per-key watermarks known to this Star, for SDK initialization and one explicit conflict repair.
    grpc::ServerUnaryReactor* Query(grpc::CallbackServerContext* context, const proto::comet::v1::CatalogQueryRequest* request, proto::comet::v1::CatalogQueryReply* reply) override;
    /// Complete single-key body and positive content version; initial Publish may omit instance.
    grpc::ServerUnaryReactor* Publish(grpc::CallbackServerContext* context, const proto::comet::v1::PublishRequest* request, proto::comet::v1::PublishReply* reply) override;
    /// Explicit TTL renews only a live complete source record at this instance; missing/expired records fail.
    grpc::ServerUnaryReactor* Renew(grpc::CallbackServerContext* context, const proto::comet::v1::CatalogRenewRequest* request, proto::comet::v1::Empty* reply) override;

private:
    /// Covers only bounded synchronous preparation/commit, without retaining a slot during long network waits.
    struct Slot {
        /// Borrow the acquired snapshot semaphore so this guard can return one permit.
        std::counting_semaphore<65536>& slots;

        /// Return the acquired snapshot permit on normal and exceptional exits.
        ~Slot() {
            slots.release();
        }
    };

    /// gRPC owns the unary reactor. Exceptions report unknown effect so post-commit failures cannot falsely claim unapplied.
    /// Work allocates response buffers before actual commit. Finish runs after releasing permits, outside the Access lock.
    template <typename F>
    grpc::ServerUnaryReactor* execute(grpc::CallbackServerContext& context, F&& work) {

        auto* reactor = context.DefaultReactor();
        grpc::Status status;
        try {
            if (!slots_.try_acquire()) {
                status = gateway_.error(context, grpc::StatusCode::RESOURCE_EXHAUSTED, proto::comet::v1::REASON_BUSY, "Catalog admission is busy");
            } else {
                const Slot slot{slots_};
                status = work(); // Work acquires and retains Access::Permit at the final boundary.
            }
        } catch (const std::bad_alloc&) {
            status = grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Catalog preparation failed");
        } catch (...) {
            status = grpc::Status(grpc::StatusCode::INTERNAL, "Catalog processing failed");
        }
        reactor->Finish(status);
        return reactor;
    }

    /// Final login, input, and instance checks; explicitly rejected attempts have not committed.
    std::expected<std::optional<Access::Permit>, grpc::Status> enter(grpc::CallbackServerContext& context, std::string_view instance, const proto::comet::v1::Scope& scope, bool initial) const;
    /// Validate static Scope limits before copying strings to bound memory for rejected input.
    grpc::Status address(grpc::CallbackServerContext& context, const proto::comet::v1::Scope& scope) const;
    /// Maps native errors to stable public reason/effect without remote diagnostics or request payloads.
    grpc::Status error(grpc::CallbackServerContext& context, State::Error error) const;
    /// Static TTL rejection includes the legal range; no dynamic Inspect/Limits handshake.
    grpc::Status ttl(grpc::CallbackServerContext& context) const;
    /// At most 1 MiB per Buffer. Copy once into immutable native storage after validation; never store the Proto message.
    static Value copy(const std::string& value);
    /// Actual local-source/projection committer.
    State& state_;
    /// Current instance and long-lived login identity, without repeated SECRET comparison.
    Gateway& gateway_;
    /// Concurrent unary preparations; not a hard bound on all network memory.
    std::counting_semaphore<65536> slots_;
    /// Active feed collector; drain all network callbacks before destruction.
    std::unique_ptr<Feed> feed_;
};
} // namespace astra
