// Translate public Ephemeris RPCs into native state operations and owned stream lifecycles.
#include "ephemeris_service.hpp"

#include "ephemeris_feed.hpp"
#include <astra/profile.hpp>

#include <cstring>

namespace astra {
Ephemeris::Service::Service(State& state, Gateway& gateway, std::ptrdiff_t maximum) : Service(state, gateway, [] {}, maximum) {}

Ephemeris::Service::Service(State& state, Gateway& gateway, std::function<void()> wake, std::ptrdiff_t maximum) : state_(state), gateway_(gateway), slots_(maximum >= 1 && maximum <= 65536 ? maximum : throw std::invalid_argument("Invalid Ephemeris concurrency")), feed_(std::make_unique<Feed>(state, gateway, std::move(wake))) {}

Ephemeris::Service::~Service() = default;

void Ephemeris::Service::pump(std::chrono::steady_clock::time_point now, std::size_t maximum) {
    try {
        state_.tick(); // One shared control loop advances the local source; no per-Watch timer.
    } catch (...) {
        feed_->invalidate(); // Expiration failure ends the caught-up guarantee while preserving complete committed state for recovery.
    }
    feed_->pump(now, maximum);
}

void Ephemeris::Service::stop() noexcept {
    feed_->stop();
}

bool Ephemeris::Service::empty() const {
    return feed_->empty();
}

Downstream<Ephemeris>::Delivery Ephemeris::Service::delivery() const {
    return feed_->delivery();
}

grpc::ServerWriteReactor<proto::comet::v1::EphemerisWatchReply>* Ephemeris::Service::Watch(grpc::CallbackServerContext* context, const proto::comet::v1::WatchRequest* request) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_service.Ephemeris.Service.Watch");
    return feed_->Watch(context, request);
}

Ephemeris::Value Ephemeris::Service::copy(const std::string& value) {
    auto buffer = std::make_shared<Buffer>(value.size()); // Creates the sole mutable payload owner; no writable alias survives return.
    if (!value.empty()) {
        std::memcpy(buffer->data(), value.data(), value.size());
    }
    return buffer;
}

std::expected<std::optional<Access::Permit>, grpc::Status> Ephemeris::Service::enter(grpc::CallbackServerContext& context, std::string_view instance, const proto::comet::v1::Scope& scope, bool initial) const {

    ASTRA_PROFILE_SCOPE("star.ephemeris_service.Ephemeris.Service.enter");

    auto permit = gateway_.enter(context); // One logical identity check spans all native commits.
    if (!permit) {
        return std::unexpected(permit.error());
    }
    if ((!initial && instance.empty()) || (!instance.empty() && instance != gateway_.instance())) {
        return std::unexpected(gateway_.error(context, grpc::StatusCode::FAILED_PRECONDITION, proto::comet::v1::REASON_INSTANCE, "Unexpected Star instance"));
    }
    if (auto checked = address(context, scope); !checked.ok()) {
        return std::unexpected(std::move(checked));
    }
    if (context.IsCancelled()) {
        return std::unexpected(gateway_.error(context, grpc::StatusCode::CANCELLED, proto::comet::v1::REASON_BUSY, "Request cancelled before admission"));
    }
    return permit;
}

grpc::Status Ephemeris::Service::address(grpc::CallbackServerContext& context, const proto::comet::v1::Scope& scope) const {
    if (!Scope::text(scope.sector(), 128) || !Scope::text(scope.spectrum(), 128)) {
        return gateway_.error(context, grpc::StatusCode::INVALID_ARGUMENT, proto::comet::v1::REASON_INPUT, "Invalid Ephemeris scope");
    }
    if (scope.sector().starts_with("__")) {
        return gateway_.error(context, grpc::StatusCode::PERMISSION_DENIED, proto::comet::v1::REASON_DENIED, "Internal scopes are not public");
    }
    return grpc::Status::OK;
}

grpc::Status Ephemeris::Service::error(grpc::CallbackServerContext& context, State::Error value) const {

    using Code = grpc::StatusCode;
    using Reason = proto::comet::v1::Reason;
    Code code = Code::INVALID_ARGUMENT; // Default to invalid native input; never infer reasons from error strings.
    Reason reason = proto::comet::v1::REASON_INPUT;
    switch (value) {
    case State::Error::Input:
        break;
    case State::Error::Clock:
        code = Code::UNAVAILABLE;
        reason = proto::comet::v1::REASON_CLOCK;
        break;
    case State::Error::Ended:
        code = Code::NOT_FOUND;
        reason = proto::comet::v1::REASON_ENDED;
        break;
    case State::Error::Obsolete:
        code = Code::FAILED_PRECONDITION;
        reason = proto::comet::v1::REASON_OBSOLETE;
        break;
    case State::Error::Conflict:
        code = Code::FAILED_PRECONDITION;
        reason = proto::comet::v1::REASON_CONFLICT;
        break;
    case State::Error::Exhausted:
        code = Code::OUT_OF_RANGE;
        reason = proto::comet::v1::REASON_LIMIT;
        break;
    case State::Error::Capacity:
        code = Code::RESOURCE_EXHAUSTED;
        reason = proto::comet::v1::REASON_LIMIT;
        break;
    case State::Error::History:
        code = Code::FAILED_PRECONDITION;
        reason = proto::comet::v1::REASON_HISTORY;
        break;
    }
    return gateway_.error(context, code, reason, "Ephemeris request was not applied");
}

grpc::Status Ephemeris::Service::ttl(grpc::CallbackServerContext& context) const {

    proto::comet::v1::Failure failure; // One bounded static rejection detail, without duplicate metadata.
    failure.set_reason(proto::comet::v1::REASON_INPUT);
    failure.set_effect(proto::comet::v1::EFFECT_UNAPPLIED);
    failure.set_ttl_min_ms(1000);
    failure.set_ttl_max_ms(600000);
    failure.set_instance(gateway_.instance());
    context.AddTrailingMetadata("comet-error-bin", failure.SerializeAsString());
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "TTL must be between 1000 and 600000 milliseconds");
}

grpc::ServerUnaryReactor* Ephemeris::Service::Create(grpc::CallbackServerContext* context, const proto::comet::v1::CreateRequest* request, proto::comet::v1::CreateReply* reply) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_service.Ephemeris.Service.Create");
    return execute(*context, [&] {
        // Check field limits first and copy large bodies before final permission, so revocation need not wait for preparation.
        if (auto checked = address(*context, request->scope()); !checked.ok()) {
            return checked;
        }
        if (request->attr().size() > 1024 * 1024 || request->data().size() > 1024 * 1024) {
            return error(*context, State::Error::Capacity);
        }
        if (request->ttl_ms() < 1000 || request->ttl_ms() > 600000) {
            return ttl(*context);
        }
        if ((request->generation() == 0 && (!request->uuid().empty() || !request->capability().empty() || request->order())) || (request->generation() && ((request->uuid().empty() && (request->generation() != 1 || !request->capability().empty() || request->order())) || (!request->uuid().empty() && (!Ephemeris::valid(request->uuid()) || request->capability().size() != 32))))) {
            return error(*context, State::Error::Input);
        }
        auto attr = copy(request->attr());
        auto data = copy(request->data());
        reply->set_instance(gateway_.instance());
        auto* uuid = reply->mutable_uuid(); // Allocate response strings before commit; success only swaps UUID storage.
        const Scope scope{request->scope().sector(), request->scope().spectrum()};
        auto permit = enter(*context, request->instance(), request->scope(), true);
        if (!permit) {
            return permit.error();
        }

        auto capability = request->capability();
        auto identity = request->uuid();
        if (request->generation() && identity.empty()) {
            capability = Ephemeris::capability();
            identity = Ephemeris::identity(scope, attr, request->ttl_ms(), capability);
        }
        reply->set_capability(capability);
        auto* restored = reply->mutable_data();
        restored->reserve(1024 * 1024); // Target may know a higher Data order; reserve the maximum legal receipt size before commit.
        auto result = state_.create(scope, std::move(attr), std::move(data), request->ttl_ms(), std::move(identity), request->generation(), request->order(), capability);
        if (!result) {
            return error(*context, result.error());
        }
        uuid->swap(result->uuid);
        reply->set_ttl_ms(result->ttl);
        reply->set_generation(result->generation);
        reply->set_order(result->order);
        restored->assign(reinterpret_cast<const char*>(result->data->data()), result->data->size());
        return grpc::Status::OK;
    });
}

grpc::ServerUnaryReactor* Ephemeris::Service::Update(grpc::CallbackServerContext* context, const proto::comet::v1::UpdateRequest* request, proto::comet::v1::UpdateReply* reply) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_service.Ephemeris.Service.Update");
    return execute(*context, [&] {
        if (auto checked = address(*context, request->scope()); !checked.ok()) {
            return checked;
        }
        if (request->data().size() > 1024 * 1024) {
            return error(*context, State::Error::Capacity);
        }
        if (!Ephemeris::valid(request->uuid()) || request->order() == 0) {
            return error(*context, State::Error::Input);
        }
        auto data = copy(request->data()); // Only payload copy for this call; later state/history share immutable references.
        const Scope scope{request->scope().sector(), request->scope().spectrum()};
        auto permit = enter(*context, request->instance(), request->scope(), false);
        if (!permit) {
            return permit.error();
        }

        auto result = state_.update(scope, request->uuid(), std::move(data), request->order(), request->generation(), request->capability());
        if (!result) {
            return error(*context, result.error());
        }
        reply->set_order(request->order());
        return grpc::Status::OK;
    });
}

grpc::ServerUnaryReactor* Ephemeris::Service::Renew(grpc::CallbackServerContext* context, const proto::comet::v1::RenewRequest* request, proto::comet::v1::RenewReply* reply) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_service.Ephemeris.Service.Renew");
    return execute(*context, [&] {
        if (auto checked = address(*context, request->scope()); !checked.ok()) {
            return checked;
        }
        if (!Ephemeris::valid(request->uuid()) || request->order() == 0) {
            return error(*context, State::Error::Input);
        }
        const Scope scope{request->scope().sector(), request->scope().spectrum()};
        auto permit = enter(*context, request->instance(), request->scope(), false);
        if (!permit) {
            return permit.error();
        }
        auto result = state_.renew(scope, request->uuid(), request->order(), request->generation(), request->capability());
        if (!result) {
            return error(*context, result.error());
        }
        reply->set_order(request->order());
        return grpc::Status::OK;
    });
}

grpc::ServerUnaryReactor* Ephemeris::Service::Remove(grpc::CallbackServerContext* context, const proto::comet::v1::RemoveRequest* request, proto::comet::v1::Empty*) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_service.Ephemeris.Service.Remove");
    return execute(*context, [&] {
        if (auto checked = address(*context, request->scope()); !checked.ok()) {
            return checked;
        }
        if (!Ephemeris::valid(request->uuid())) {
            return error(*context, State::Error::Input);
        }
        const Scope scope{request->scope().sector(), request->scope().spectrum()};
        auto permit = enter(*context, request->instance(), request->scope(), false);
        if (!permit) {
            return permit.error();
        }
        const auto result = state_.remove(scope, request->uuid(), request->generation(), request->capability());
        return result ? grpc::Status::OK : error(*context, result.error());
    });
}
} // namespace astra
