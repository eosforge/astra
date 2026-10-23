// Translate public Catalog RPCs into native state operations and owned stream lifecycles.
#include "catalog_service.hpp"

#include "catalog_feed.hpp"
#include <astra/profile.hpp>

#include <array>
#include <cstring>

namespace astra {
Catalog::Service::Service(State& state, Gateway& gateway, std::ptrdiff_t maximum) : Service(state, gateway, [] {}, maximum) {}

Catalog::Service::Service(State& state, Gateway& gateway, std::function<void()> wake, std::ptrdiff_t maximum) : state_(state), gateway_(gateway), slots_(maximum >= 1 && maximum <= 65536 ? maximum : throw std::invalid_argument("Invalid Catalog concurrency")), feed_(std::make_unique<Feed>(state, gateway, std::move(wake))) {}

Catalog::Service::~Service() = default;

void Catalog::Service::pump(std::chrono::steady_clock::time_point now, std::size_t maximum) {
    try {
        state_.tick(); // One shared control loop advances the local source; no per-Watch timer.
    } catch (...) {
        feed_->invalidate(); // Expiration failure ends the caught-up guarantee while preserving complete committed state for recovery.
    }
    feed_->pump(now, maximum);
}

void Catalog::Service::stop() noexcept {
    feed_->stop();
}

bool Catalog::Service::empty() const {
    return feed_->empty();
}

grpc::ServerWriteReactor<proto::comet::v1::CatalogWatchReply>* Catalog::Service::Watch(grpc::CallbackServerContext* context, const proto::comet::v1::WatchRequest* request) {

    ASTRA_PROFILE_SCOPE("star.catalog_service.Catalog.Service.Watch");
    return feed_->Watch(context, request);
}

Catalog::Value Catalog::Service::copy(const std::string& value) {
    auto buffer = std::make_shared<Buffer>(value.size()); // Creates the sole mutable payload owner; no writable alias survives return.
    if (!value.empty()) {
        std::memcpy(buffer->data(), value.data(), value.size());
    }
    return buffer;
}

grpc::ServerUnaryReactor* Catalog::Service::Query(grpc::CallbackServerContext* context, const proto::comet::v1::CatalogQueryRequest* request, proto::comet::v1::CatalogQueryReply* reply) {

    return execute(*context, [&] {
        // Uses write authentication/instance checks and rejects internal Scopes or unbounded key lists.
        auto permit = enter(*context, request->instance(), request->scope(), true);
        if (!permit) {
            return permit.error();
        }
        if (request->keys_size() < 1 || request->keys_size() > 128) {
            return error(*context, State::Error::Input);
        }
        std::array<std::string_view, 128> names;
        auto keys = std::span(names).first(static_cast<std::size_t>(request->keys_size()));
        for (std::size_t index = 0; index < keys.size(); ++index) {
            keys[index] = request->keys(static_cast<int>(index));
        }

        // Query retained highest watermarks, including expired bodies; emit one entry per requested key.
        const auto versions = state_.versions({request->scope().sector(), request->scope().spectrum()}, keys);
        if (!versions) {
            return error(*context, versions.error());
        }
        reply->set_instance(gateway_.instance());
        for (std::size_t index = 0; index < keys.size(); ++index) {
            auto* entry = reply->add_entries();
            entry->set_key(keys[index].data(), keys[index].size());
            entry->set_version((*versions)[index]);
        }
        return grpc::Status::OK;
    });
}

std::expected<std::optional<Access::Permit>, grpc::Status> Catalog::Service::enter(grpc::CallbackServerContext& context, std::string_view instance, const proto::comet::v1::Scope& scope, bool initial) const {

    ASTRA_PROFILE_SCOPE("star.catalog_service.Catalog.Service.enter");

    auto permit = gateway_.enter(context);
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

grpc::Status Catalog::Service::address(grpc::CallbackServerContext& context, const proto::comet::v1::Scope& scope) const {
    if (!Scope::text(scope.sector(), 128) || !Scope::text(scope.spectrum(), 128)) {
        return gateway_.error(context, grpc::StatusCode::INVALID_ARGUMENT, proto::comet::v1::REASON_INPUT, "Invalid Catalog scope");
    }
    if (scope.sector().starts_with("__")) {
        return gateway_.error(context, grpc::StatusCode::PERMISSION_DENIED, proto::comet::v1::REASON_DENIED, "Internal scopes are not public");
    }
    return grpc::Status::OK;
}

grpc::Status Catalog::Service::error(grpc::CallbackServerContext& context, State::Error value) const {

    using Code = grpc::StatusCode;
    using Reason = proto::comet::v1::Reason;
    Code code = Code::INVALID_ARGUMENT;
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
    case State::Error::Version:
        code = Code::FAILED_PRECONDITION;
        reason = proto::comet::v1::REASON_VERSION;
        break;
    case State::Error::Conflict:
        code = Code::FAILED_PRECONDITION;
        reason = proto::comet::v1::REASON_VERSION; // Equal-version differing content is an unapplied batch version conflict that explicit query can resolve.
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
    return gateway_.error(context, code, reason, "Catalog request was not applied");
}

grpc::Status Catalog::Service::ttl(grpc::CallbackServerContext& context) const {

    proto::comet::v1::Failure failure;
    failure.set_reason(proto::comet::v1::REASON_INPUT);
    failure.set_effect(proto::comet::v1::EFFECT_UNAPPLIED);
    failure.set_ttl_min_ms(1000);
    failure.set_ttl_max_ms(600000);
    failure.set_instance(gateway_.instance());
    context.AddTrailingMetadata("comet-error-bin", failure.SerializeAsString());
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "TTL must be between 1000 and 600000 milliseconds");
}

grpc::ServerUnaryReactor* Catalog::Service::Publish(grpc::CallbackServerContext* context, const proto::comet::v1::PublishRequest* request, proto::comet::v1::PublishReply* reply) {

    ASTRA_PROFILE_SCOPE("star.catalog_service.Catalog.Service.Publish");
    return execute(*context, [&] {
        // Validate limits before copying fields, then prepare one immutable payload and bounded response.
        auto permit = enter(*context, request->instance(), request->scope(), true); // Authenticate before copying application bodies.
        if (!permit) {
            return permit.error();
        }
        if (!request->entries().empty()) {
            if (!request->key().empty() || !request->value().empty() || request->entries_size() > 128 || request->version() == 0 || request->ByteSizeLong() > 2 * 1024 * 1024) {
                return error(*context, State::Error::Input);
            }
            if (request->ttl_ms() < 1000 || request->ttl_ms() > 600000) {
                return ttl(*context);
            }
            std::size_t bytes{}; // Check individual and total batch lengths before allocating payloads.
            for (const auto& entry : request->entries()) {
                if (!Scope::text(entry.key(), 1024)) {
                    return error(*context, State::Error::Input);
                }
                if (entry.value().size() > 1024 * 1024) {
                    return error(*context, State::Error::Capacity);
                }
                bytes += entry.key().size() + entry.value().size();
                if (bytes > 1024 * 1024) {
                    return error(*context, State::Error::Capacity);
                }
            }
            std::vector<State::Entry> entries; // Convert the complete request to immutable values before one atomic commit.
            entries.reserve(static_cast<std::size_t>(request->entries_size()));
            for (const auto& entry : request->entries()) {
                entries.push_back({entry.key(), copy(entry.value())});
            }
            reply->set_instance(gateway_.instance());
            const Scope scope{request->scope().sector(), request->scope().spectrum()};
            if (auto result = state_.publish(scope, entries, request->version(), request->ttl_ms()); !result) {
                return error(*context, result.error());
            }
            reply->set_version(request->version());
            return grpc::Status::OK;
        }
        if (!Scope::text(request->key(), 1024) || request->version() == 0) {
            return error(*context, State::Error::Input);
        }
        if (request->value().size() > 1024 * 1024) {
            return error(*context, State::Error::Capacity);
        }
        if (request->ttl_ms() < 1000 || request->ttl_ms() > 600000) {
            return ttl(*context);
        }
        auto value = copy(request->value());
        reply->set_instance(gateway_.instance());
        const Scope scope{request->scope().sector(), request->scope().spectrum()};

        const auto result = state_.publish(scope, request->key(), std::move(value), request->version(), request->ttl_ms());
        if (!result) {
            return error(*context, result.error());
        }
        reply->set_version(request->version());
        return grpc::Status::OK;
    });
}

grpc::ServerUnaryReactor* Catalog::Service::Renew(grpc::CallbackServerContext* context, const proto::comet::v1::CatalogRenewRequest* request, proto::comet::v1::Empty*) {

    ASTRA_PROFILE_SCOPE("star.catalog_service.Catalog.Service.Renew");
    return execute(*context, [&] {
        auto permit = enter(*context, request->instance(), request->scope(), false);
        if (!permit) {
            return permit.error();
        }
        if (!request->keys().empty()) {
            if (!request->key().empty() || request->keys_size() > 128 || request->version() == 0 || request->ByteSizeLong() > 2 * 1024 * 1024) {
                return error(*context, State::Error::Input);
            }
            if (request->ttl_ms() < 1000 || request->ttl_ms() > 600000) {
                return ttl(*context);
            }
            std::vector<State::Entry> entries; // Renew atomically; any missing key prevents extending the rest.
            entries.reserve(static_cast<std::size_t>(request->keys_size()));
            for (const auto& key : request->keys()) {
                if (!Scope::text(key, 1024)) {
                    return error(*context, State::Error::Input);
                }
                entries.push_back({key, {}});
            }
            const Scope scope{request->scope().sector(), request->scope().spectrum()};
            const auto result = state_.publish(scope, entries, request->version(), request->ttl_ms(), true);
            return result ? grpc::Status::OK : error(*context, result.error());
        }
        if (!Scope::text(request->key(), 1024) || request->version() == 0) {
            return error(*context, State::Error::Input);
        }
        if (request->ttl_ms() < 1000 || request->ttl_ms() > 600000) {
            return ttl(*context);
        }
        const Scope scope{request->scope().sector(), request->scope().spectrum()};
        const auto result = state_.renew(scope, request->key(), request->version(), request->ttl_ms());
        return result ? grpc::Status::OK : error(*context, result.error());
    });
}
} // namespace astra
