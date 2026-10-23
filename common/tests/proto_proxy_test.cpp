// Verify reflected configuration mapping at the generated-protocol boundary.
#include "check.hpp"
#include <astra/proto_proxy.hpp>

#include <google/protobuf/arena.h>

#include <iostream>
#include <type_traits>

namespace {
/// Instantiates every proxy field so missing generated APIs cannot remain hidden in unused templates.
void testFieldsAndOneof() {

    // Chains scalar/signature assignments into Hello, reused as a oneof source.
    proto::astra::v1::Hello hello;
    astra::mutate(hello).protocolMajor(1U).protocolMinor(0U).maxFrameBytes(4096U).admission("body").admissionSignature("signature");
    CHECK(hello.protocol_major() == 1 && hello.max_frame_bytes() == 4096 && hello.admission() == "body");
    // Explicit heartbeat request sequence; proxy must preserve message type.
    proto::astra::v1::Ping ping;
    // Independent reply with a different sequence distinguishes Ping/Pong branches.
    proto::astra::v1::Pong pong;
    // Explicit rejection message checks oneof transitions and enum forwarding.
    proto::astra::v1::ProtocolError error;
    astra::mutate(ping).requestId(std::uint64_t{9});
    astra::mutate(pong).requestId(std::uint64_t{10});
    astra::mutate(error).code(proto::astra::v1::PROTOCOL_ERROR_CODE_UNAUTHORIZED);
    // Switches Hello, Ping, Pong, and rejection in turn, clearing the preceding branch.
    proto::astra::v1::SessionPacket packet;
    astra::mutate(packet).hello(hello);
    CHECK(packet.has_hello() && packet.hello().admission_signature() == "signature");
    astra::mutate(packet).ping(ping);
    CHECK(packet.has_ping() && !packet.has_hello() && packet.ping().request_id() == 9);
    astra::mutate(packet).pong(pong);
    CHECK(packet.has_pong() && packet.pong().request_id() == 10);
    astra::mutate(packet).rejection(error);
    CHECK(packet.has_rejection() && packet.rejection().code() == error.code());
    // Local send nanoseconds for checking unchanged Pong echo.
    proto::pulsar::v1::Ping pulsePing;
    // Sets server timestamps, uncertainty, and synchronization eligibility together.
    proto::pulsar::v1::Pong pulsePong;
    astra::mutate(pulsePing).t0(std::uint64_t{10});
    astra::mutate(pulsePong).t0(std::uint64_t{10}).t1(std::uint64_t{20}).t2(std::uint64_t{21}).uncertaintyNanoseconds(std::uint64_t{2000}).synchronized(true).precisionNanoseconds(std::uint64_t{1000});
    // Actual encode/decode result checks bytes beyond template instantiation.
    proto::pulsar::v1::Pong decodedPulse;
    CHECK(decodedPulse.ParseFromString(pulsePong.SerializeAsString()));
    CHECK(decodedPulse.t0() == pulsePing.t0() && decodedPulse.precision_ns() == 1000 && decodedPulse.uncertainty_ns() == 2000 && decodedPulse.synchronized());
}

/// Cross-Arena copy must survive source destruction; proxies never take caller pointers with set_allocated.
void testRegistrationAndArena() {

    // Outlives source Arena; Member collection must own independent contents.
    proto::orbit::v1::RegistrationResponse response;
    {
        // Owns source Members in this scope only; destinations cannot retain its borrows after exit.
        google::protobuf::Arena arena;
        // Arena-owned Member with all topology fields populated within source scope.
        auto* member = google::protobuf::Arena::Create<proto::orbit::v1::Member>(&arena);
        astra::mutate(*member).galaxy("alpha").id("issued/1").principal("digest").advertise("127.0.0.1:7443").epoch(std::uint64_t{1}).role(proto::orbit::v1::ROLE_STAR).group("local");
        // Owned Member copies; repeated-field reassignment replaces rather than appends.
        google::protobuf::RepeatedPtrField<proto::orbit::v1::Member> members;
        *members.Add() = *member;
        astra::mutate(response).members(members).members(members).admission("admission").signature("signature");
    }
    CHECK(response.members_size() == 1 && response.members(0).galaxy() == "alpha" && response.members(0).id() == "issued/1");
    // Covers account, role, group, and binary startup key, including every registration adapter field.
    proto::orbit::v1::RegistrationRequest request;
    astra::mutate(request).galaxy("alpha").advertise("127.0.0.1:7443").role(proto::orbit::v1::ROLE_STAR).group("local").candidateRound(2U).username("user").password("password").requestId(std::string(32, 'r'));
    // Actual serialization round trip checks field bytes beyond chain-expression compilation.
    const auto serialized = request.SerializeAsString();
    // Independently decoded message compared against original fields for forwarding/ownership.
    proto::orbit::v1::RegistrationRequest decoded;
    CHECK(decoded.ParseFromString(serialized));
    CHECK(decoded.galaxy() == "alpha" && decoded.candidate_round() == 2 && decoded.request_id().size() == 32);
    CHECK(decoded.username() == "user" && decoded.password() == "password");
}

/// Proxies return lightweight borrows by value; intermediate destruction must not leave returned proxies dangling while the original message lives.
void testProxyLifetime() {

    // Shared target message outlives temporary and named proxies.
    proto::astra::v1::Ping message;
    static_assert(std::is_trivially_copy_constructible_v<astra::Mutator<proto::astra::v1::Ping>>);
    static_assert(!std::is_reference_v<decltype(astra::mutate(message).requestId(std::uint64_t{1}))>);
    // Extends the returned proxy value's lifetime, without referencing a destroyed intermediate.
    auto&& edit = astra::mutate(message).requestId(std::uint64_t{1});
    edit.requestId(std::uint64_t{2});
    CHECK(message.request_id() == 2);
    // Receives the lambda-local proxy result by value; original message remains valid outside.
    const auto returned = [&] {
        // Stack proxy borrows message only and may die after returning a field-call result.
        auto local = astra::mutate(message);
        return local.requestId(std::uint64_t{3});
    }();
    // Copying a lightweight proxy continues modifying the original message without copying Protobuf contents.
    auto next = returned;
    next.requestId(std::uint64_t{4});
    CHECK(message.request_id() == 4);
    // Named proxy chains must match temporary-chain writes.
    auto named = astra::mutate(message);
    named.requestId(std::uint64_t{5}).requestId(std::uint64_t{6});
    CHECK(message.request_id() == 6);
}

/// Cross-Arena destinations follow Protobuf ownership and remain complete after source destruction.
void testTargetArena() {

    // Outer target Arena outlives inner source creation and destruction.
    google::protobuf::Arena destination;
    // Destination-owned oneof; later branch changes cannot borrow released source storage.
    auto* packet = google::protobuf::Arena::Create<proto::astra::v1::SessionPacket>(&destination);
    // Destination-owned repeated message accepts cross-Arena move input.
    auto* response = google::protobuf::Arena::Create<proto::orbit::v1::RegistrationResponse>(&destination);
    {
        // Inner input Arena; scope exit forces destination independence checks.
        google::protobuf::Arena source;
        // Source-owned Hello; Protobuf determines necessary cross-Arena copy without pointer theft by the proxy.
        auto* hello = google::protobuf::Arena::Create<proto::astra::v1::Hello>(&source);
        astra::mutate(*hello).admission(std::string(128, 'a'));
        astra::mutate(*packet).hello(std::move(*hello));
        // Source-owned Members forwarded to longer-lived response's repeated field.
        auto* members = google::protobuf::Arena::Create<proto::orbit::v1::RegistrationResponse>(&source);
        members->add_members()->set_id("source/member");
        astra::mutate(*response).members(std::move(*members->mutable_members()));
    }
    CHECK(packet->has_hello() && packet->hello().admission() == std::string(128, 'a'));
    CHECK(response->members_size() == 1 && response->members(0).id() == "source/member");
    // Explicit heartbeat request sequence; proxy must preserve message type.
    proto::astra::v1::Ping ping;
    ping.set_request_id(7);
    astra::mutate(*packet).ping(std::move(ping));
    CHECK(packet->has_ping() && !packet->has_hello() && packet->ping().request_id() == 7);
}
} // namespace

/// Checks remain active in Release and require no listener or external service.
int main() {

    try {
        testFieldsAndOneof();
        testRegistrationAndArena();
        testProxyLifetime();
        testTargetArena();
        std::cout << "Proto proxy scalar, oneof, repeated and Arena tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
