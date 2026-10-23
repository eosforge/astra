// Issue signed membership responses from validated authority and ledger state.
#include "issuer.hpp"

#include <astra/profile.hpp>

#include <google/protobuf/repeated_ptr_field.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <memory>
#include <stdexcept>

namespace astra {
namespace {
/// Append to a private heap-owned response without exposing a partially allocated repeated element.
void append(google::protobuf::RepeatedPtrField<proto::orbit::v1::Member>& members, proto::orbit::v1::Member value) {

    // Both callers use stack responses and heap members; allocate the element and capacity before insertion.
    auto owned = std::make_unique<proto::orbit::v1::Member>(std::move(value));
    members.Reserve(members.size() + 1);

    // Matching null arenas and reserved capacity make ownership transfer nonallocating.
    members.AddAllocated(owned.get());
    static_cast<void>(owned.release());
}

/// Matches Go candidate selection: prefer four local-group and four remote Stars, fill shortages, and return at most eight.
std::vector<const Member*> candidates(const Ledger::Members& members, const Member& local, std::uint32_t round) {

    // Pointers borrow this stable directory and remain within the registration preparation callback.
    std::vector<const Member*> stars;
    for (const auto& [key, member] : members) {
        static_cast<void>(key);
        if (member.role == Member::Role::Star || local.role == Member::Role::Astrolabe || (member.role == Member::Role::Polaris && local.role != Member::Role::Planet)) {
            stars.push_back(&member);
        }
    }
    std::ranges::sort(stars, {}, [](const Member* item) -> const Id& { return item->id; });
    if (local.role != Member::Role::Planet) {
        return stars;
    }

    std::vector<const Member*> nearby, remote;
    for (const auto* member : stars) {
        (member->group == local.group ? nearby : remote).push_back(member);
    }

    const auto principal = local.principal.text();

    std::array<std::uint8_t, 32> hash{};
    SHA256(reinterpret_cast<const std::uint8_t*>(principal.data()), principal.size(), hash.data());
    // The first eight digest bytes form a big-endian rotation seed, not cryptographic randomness.
    std::uint64_t seed = 0;
    for (unsigned i = 0; i < 8; ++i) {
        seed = (seed << 8) | hash[i];
    }

    const auto rotate = [&](auto& pool) {
        if (!pool.empty()) {
            // Keep deterministic rotation identical to Go; selection distributes entry points without promising random or fair sampling.
            const auto offset = static_cast<std::size_t>((seed + static_cast<std::uint64_t>(round) * 4) % pool.size());
            std::ranges::rotate(pool, pool.begin() + static_cast<std::ptrdiff_t>(offset));
        }
    };
    rotate(nearby);
    rotate(remote);

    auto remoteCount = std::min(std::size_t{4}, remote.size());

    const auto localCount = std::min(nearby.size(), 8 - remoteCount);
    remoteCount = std::min(remote.size(), 8 - localCount);
    nearby.resize(localCount);
    remote.resize(remoteCount);
    std::ranges::sort(nearby, {}, [](const Member* member) -> const Id& { return member->id; });
    std::ranges::sort(remote, {}, [](const Member* member) -> const Id& { return member->id; });
    nearby.insert(nearby.end(), remote.begin(), remote.end());
    return nearby;
}

/// Maps internal failures to stable gRPC codes without sending diagnostic details.
grpc::Status rejected(const Status& error) {

    auto code = grpc::StatusCode::UNAVAILABLE;
    switch (error.code) {
    case Status::Code::Configuration:
        code = grpc::StatusCode::INVALID_ARGUMENT;
        break;
    case Status::Code::Conflict:
        code = grpc::StatusCode::ABORTED;
        break;
    case Status::Code::Capacity:
        code = grpc::StatusCode::RESOURCE_EXHAUSTED;
        break;
    default:
        break;
    }
    return grpc::Status(code, "Registration rejected");
}
} // namespace

Issuer::Issuer(std::string galaxy, std::string pulseEndpoint, const Authority& authority, Ledger& ledger) : galaxy_(std::move(galaxy)), pulseEndpoint_(std::move(pulseEndpoint)), authority_(authority), ledger_(ledger) {}

grpc::Status Issuer::Register(grpc::ServerContext* context, const proto::orbit::v1::RegistrationRequest* request, proto::orbit::v1::RegistrationResponse* response) {

    ASTRA_PROFILE_SCOPE("pulsar.issuer.Issuer.Register");

    try {
        // Only Planet permits a nonzero candidate rotation round.
        const auto role = Identity::role(request->role());
        if (request->ByteSizeLong() > 4096 || request->request_id().size() != 32 || !role || (*role != Member::Role::Planet && request->candidate_round() != 0)) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid registration bounds or role");
        }
        if (auto authenticated = authority_.authenticate(*context, *request); !authenticated.ok()) {
            return authenticated;
        }

        // Require canonical endpoint text after parsing to reject address aliases.
        const auto address = Endpoint::parse(request->advertise());
        if (request->galaxy() != galaxy_ || !address || address->text() != request->advertise() || !Member::validName(request->group())) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid registration target");
        }

        // The issuer generates a cryptographically random identity independently of client-controlled request_id.
        Principal random, principal;
        if (RAND_bytes(random.bytes.data(), random.bytes.size()) != 1) {
            throw std::runtime_error("Identity entropy unavailable");
        }

        // NUL separators keep account, Galaxy, and endpoint boundaries unambiguous.
        const auto fingerprint = request->username() + '\0' + galaxy_ + '\0' + request->advertise();
        SHA256(reinterpret_cast<const std::uint8_t*>(fingerprint.data()), fingerprint.size(), principal.bytes.data());

        Member candidate{galaxy_, "p_" + random.text(), principal, *address, {}, *role, request->group()};
        // Prepare the complete response before durable commit. Swap allocates nothing afterward, and send failure permits retrying the same request.
        proto::orbit::v1::RegistrationResponse prepared;
        try {
            // Prepare only private response data while the ledger serializes its commit boundary.
            const auto committed = ledger_.registerMember(std::move(candidate), request->request_id(), [&](const Member& local, const auto& members) {
                if (context->IsCancelled()) {
                    throw std::runtime_error("Registration cancelled");
                }
                authority_.sign(Identity::encode(local), prepared);
                if (local.role == Member::Role::Star) {
                    prepared.set_pulse_endpoint(pulseEndpoint_);
                }
                for (const auto* member : candidates(members, local, request->candidate_round())) {
                    append(*prepared.mutable_members(), Identity::encode(*member));
                }
                if (prepared.ByteSizeLong() > 8 * 1024 * 1024) {
                    throw std::runtime_error("Registration response capacity exceeded");
                }
            });
            if (!committed) {
                return rejected(committed.error());
            }
            response->Swap(&prepared);
            return grpc::Status::OK;
        } catch (...) {
            // Generated mutations may leave presence inconsistent; restore all fields before destruction.
            prepared.clear_members();
            prepared.clear_admission();
            prepared.clear_signature();
            prepared.clear_pulse_endpoint();
            throw;
        }
    } catch (const std::bad_alloc&) {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Registration resources unavailable");
    } catch (...) {
        return grpc::Status(context->IsCancelled() ? grpc::StatusCode::CANCELLED : grpc::StatusCode::INTERNAL, "Registration unavailable");
    }
}

grpc::Status Issuer::List(grpc::ServerContext* context, const proto::orbit::v1::DirectoryRequest* request, proto::orbit::v1::DirectoryResponse* response) {

    ASTRA_PROFILE_SCOPE("pulsar.issuer.Issuer.List");

    try {
        if (request->ByteSizeLong() != 0) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Directory request must be empty");
        }

        // Require exactly one credential in the RPC's initial metadata to avoid duplicate-key ambiguity.
        const auto& metadata = context->client_metadata();
        if (metadata.count("astra-admission-bin") != 1 || metadata.count("astra-signature-bin") != 1) {
            return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Current admission required");
        }
        // Verify the original admission/signature bytes without re-encoding.
        const auto admission = metadata.find("astra-admission-bin")->second;
        const auto signature = metadata.find("astra-signature-bin")->second;

        const auto member = authority_.identity().verify({reinterpret_cast<const std::uint8_t*>(admission.data()), admission.size()}, {reinterpret_cast<const std::uint8_t*>(signature.data()), signature.size()});
        if (!member || member->galaxy != galaxy_ || member->role == Member::Role::Planet) {
            return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Directory admission rejected");
        }
        // Use one snapshot for identity verification and returned directory, avoiding epochs from separate atomic loads.
        const auto snapshot = ledger_.snapshot(*member);
        if (!snapshot) {
            return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Admission no longer current");
        }

        // Prepare the complete bounded response before exposing any directory content.
        proto::orbit::v1::DirectoryResponse prepared;
        try {
            // Count each encoded member plus its conservative tag/length bound without rescanning the response.
            std::size_t bytes{};
            for (const auto* item : candidates(*snapshot, *member, 0)) {
                if (context->IsCancelled()) {
                    return grpc::Status(grpc::StatusCode::CANCELLED, "Directory cancelled");
                }
                auto encoded = Identity::encode(*item);
                bytes += encoded.ByteSizeLong() + 6;
                if (bytes > 8 * 1024 * 1024) {
                    return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Directory response exceeds capacity");
                }
                append(*prepared.mutable_members(), std::move(encoded));
            }
            response->Swap(&prepared);
            return grpc::Status::OK;
        } catch (...) {
            // A failed repeated-field insertion must not reach the generated destructor with stale presence.
            prepared.clear_members();
            throw;
        }
    } catch (const std::bad_alloc&) {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Directory resources unavailable");
    } catch (...) {
        return grpc::Status(grpc::StatusCode::INTERNAL, "Directory unavailable");
    }
}
} // namespace astra
