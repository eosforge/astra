// Exercise real RPC behavior for explicitly owned process fixtures.
#include "admission.hpp"
#include "astra.grpc.pb.h"
#include "check.hpp"

#include <grpcpp/create_channel.h>
#include <openssl/rand.h>

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace astra;

namespace {

/// Owns one synchronous RPC; scope exit cancels and obtains final status so no blocking stream is abandoned.
struct Stream {
    /// Call deadline/cancellation context outlives the stream.
    grpc::ClientContext context;
    /// Exclusively owned stream; current test thread performs all I/O sequentially.
    std::unique_ptr<grpc::ClientReaderWriter<proto::astra::v1::SessionPacket, proto::astra::v1::SessionPacket>> io;
    /// Initially false; set after Finish to prevent duplicate destructor completion.
    bool finished{};

    /// Borrows stub to create a stream bounded by 15 s, without taking Stub ownership.
    explicit Stream(proto::astra::v1::StarTransport::Stub& stub) {
        context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(15));
        io = stub.OpenSession(&context);
    }

    /// Nonthrowing cleanup reclaims unfinished streams on normal or exceptional exits.
    ~Stream() {

        if (!finished) {
            context.TryCancel();
            static_cast<void>(io->Finish());
        }
    }

    /// Cancels and awaits completion; only destruction is allowed afterward.
    void finish() {

        context.TryCancel();
        static_cast<void>(io->Finish());
        finished = true;
    }

    /// Sends hello and verifies remote identity; message storage remains local to this call.
    bool hello(const proto::astra::v1::Hello& hello, const Identity& identity) {

        // Exclusive I/O buffer, reused only after synchronous operations return.
        proto::astra::v1::SessionPacket message;
        message.mutable_hello()->CopyFrom(hello);
        if (!io->Write(message) || !io->Read(&message)) {
            return false;
        }

        // Borrows response admission bytes within message lifetime.
        auto admission = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(message.hello().admission().data()), message.hello().admission().size());
        // Borrows response signature for verification with admission, then discards it.
        auto sig = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(message.hello().admission_signature().data()), message.hello().admission_signature().size());
        // Checks the public v1 contract independently so matching wrong probe/server constants cannot establish interoperability.
        return message.has_hello() && message.hello().protocol_major() == 1 && identity.verify(admission, sig).has_value();
    }

    /// Sends nonzero id and answers reverse Ping; reads at most 20 packets and returns false without matching Pong.
    bool ping(std::uint64_t id) {

        // Exclusive I/O buffer, reused only after synchronous operations return.
        proto::astra::v1::SessionPacket message;
        message.mutable_ping()->set_request_id(id);
        if (!io->Write(message)) {
            return false;
        }

        // Read count capped at 20 so unrelated Ping cannot prolong the loop indefinitely.
        for (unsigned received = 0; received < 20 && io->Read(&message); ++received) {
            if (message.has_pong() && message.pong().request_id() == id) {
                return true;
            }
            if (message.has_ping()) {
                // Response to the current reverse Ping, without mutating the received message.
                proto::astra::v1::SessionPacket reply;
                reply.mutable_pong()->set_request_id(message.ping().request_id());
                if (!io->Write(reply)) {
                    return false;
                }
            }
        }
        return false;
    }
};

/// Registers the test node at Pulsar with advertise, verifies signatures, and returns an owning Hello.
proto::astra::v1::Hello admit(const Identity& identity, const std::string& pulsar, const std::string& advertise) {

    // Shared public-fixture TLS Channel retained by Stub through calls.
    auto channel = grpc::CreateChannel(pulsar, identity.channelCredentials());
    // Owned generated Stub, without cross-process sharing.
    auto stub = proto::orbit::v1::Admission::NewStub(channel);
    // Owned registration fields bound to a random per-startup request ID.
    proto::orbit::v1::RegistrationRequest request;
    request.set_username(identity.username());
    request.set_password(identity.password());
    request.set_galaxy("alpha");
    request.set_advertise(advertise);
    // 32-byte startup request ID, initially zero then filled by BoringSSL.
    std::string requestId(32, '\0');
    CHECK(RAND_bytes(reinterpret_cast<unsigned char*>(requestId.data()), requestId.size()) == 1);
    request.set_request_id(std::move(requestId));
    request.set_role(proto::orbit::v1::ROLE_STAR);
    request.set_group("default");
    // Call deadline/cancellation context outlives the stream.
    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
    // Owned synchronous response, not reused before verification.
    proto::orbit::v1::RegistrationResponse response;
    CHECK(stub->Register(&context, request, &response).ok());
    // Borrows response admission bytes within message lifetime.
    auto admission = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(response.admission().data()), response.admission().size());
    // Borrows response signature for verification with admission, then discards it.
    auto sig = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(response.signature().data()), response.signature().size());
    CHECK(identity.verify(admission, sig).has_value());
    // Copies admission and signature so returned Hello borrows no response storage.
    proto::astra::v1::Hello hello;
    hello.set_protocol_major(protocolMajor);
    hello.set_max_frame_bytes(4096);
    hello.set_admission(response.admission());
    hello.set_admission_signature(response.signature());
    return hello;
}

} // namespace

/// Reports exceptions as nonzero process failure; assertions remain active under NDEBUG.
int main(int argc, char** argv) {

    try {
        CHECK(argc == 5);
        // Local advertised endpoint parsed from argument four; invalid input fails the probe.
        auto endpoint = Endpoint::parse(argv[4]);
        CHECK(endpoint);
        // Identity directory from argument three, validated against advertised-endpoint authorization.
        auto identity = Identity::load(argv[3], *endpoint);
        CHECK(identity);
        // Shared valid credential reused by this probe's successive streams.
        const auto hello = admit(**identity, argv[1], argv[4]);
        // Shared public-fixture TLS Channel retained by Stub through calls.
        auto channel = grpc::CreateChannel(argv[2], (*identity)->channelCredentials());
        // Owned generated Stub, without cross-process sharing.
        auto stub = proto::astra::v1::StarTransport::NewStub(channel);
        {
            // TLS/RPC without Hello must reveal no bearer and must close after the application handshake budget.
            Stream silent(*stub);
            // Exclusive I/O buffer, reused only after synchronous operations return.
            proto::astra::v1::SessionPacket message;
            // Local monotonic scenario start measures duration only, not business expiry.
            const auto started = Steady::now();
            CHECK(!silent.io->Read(&message));
            CHECK(Steady::now() - started < std::chrono::seconds(8));
        }

        // Retained valid active stream; duplicate credentials must not displace it.
        Stream first(*stub);
        CHECK(first.hello(hello, **identity));
        CHECK(first.ping(41));
        {
            // Concurrent stream with identical credentials must be rejected.
            Stream duplicate(*stub);
            CHECK(!duplicate.hello(hello, **identity));
            CHECK(!duplicate.ping(42));
        }
        CHECK(first.ping(43));
        {
            // Force an independent subchannel to ensure separate connections cannot bypass the active logical-Session index.
            grpc::ChannelArguments arguments;
            arguments.SetInt("grpc.use_local_subchannel_pool", 1);
            // Independent subchannel prevents connection reuse from concealing credential-index defects.
            auto isolated = grpc::CreateCustomChannel(argv[2], (*identity)->channelCredentials(), arguments);
            // Generated Session Stub on the independent Channel.
            auto isolatedStub = proto::astra::v1::StarTransport::NewStub(isolated);
            // Concurrent stream with identical credentials must be rejected.
            Stream duplicate(*isolatedStub);
            CHECK(!duplicate.hello(hello, **identity));
        }
        CHECK(first.ping(45));
        {
            // One outstanding probe at a time, answering server Ping while measuring control RTT; no unimplemented business-data simulation.
            std::vector<double> samples;
            samples.reserve(500);
            // 520 probe indices with 20 warmups and distinct request IDs.
            for (std::uint64_t i = 0; i < 520; ++i) {
                // Monotonic start for this Ping.
                const auto start = Steady::now();
                CHECK(first.ping(1000 + i));
                if (i >= 20) {
                    samples.push_back(std::chrono::duration<double, std::micro>(Steady::now() - start).count());
                }
            }
            std::ranges::sort(samples);
            std::cout << "{\"control_rtt_us\":{\"samples\":" << samples.size() << ",\"p50\":" << samples[249] << ",\"p95\":" << samples[474] << ",\"p99\":" << samples[494] << ",\"max\":" << samples.back() << "}}\n";
        }
        first.finish();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        {
            // Reuses valid credentials only after the previous stream drains; installation must succeed again.
            Stream next(*stub);
            CHECK(next.hello(hello, **identity));
            CHECK(next.ping(44));
            next.finish();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        // Selects invalid protocol version, signature, frame limit, or oversized credential.
        for (unsigned mutation = 0; mutation < 4; ++mutation) {
            // Valid Hello copy with only the scenario field changed.
            auto invalid = hello;
            if (mutation == 0) {
                invalid.set_protocol_major(2);
            } else if (mutation == 1) {
                (*invalid.mutable_admission_signature())[0] ^= 1;
            } else if (mutation == 2) {
                invalid.set_max_frame_bytes(1);
            } else {
                invalid.set_admission(std::string(5000, 'x'));
            }

            // Owns this invalid-handshake RPC and cleans it up at exit.
            Stream bad(*stub);
            CHECK(!bad.hello(invalid, **identity));
            CHECK(!bad.ping(50 + mutation));
        }
        {
            // A peer writing Ping without reading replies must neither cause unbounded server queues nor prevent shutdown.
            Stream slow(*stub);
            CHECK(slow.hello(hello, **identity));
            // Exclusive I/O buffer, reused only after synchronous operations return.
            proto::astra::v1::SessionPacket message;
            // Local monotonic scenario start measures duration only, not business expiry.
            const auto started = Steady::now();
            // Successful write sequence count, initially zero; 100000 bounds the probe itself.
            std::uint64_t sent = 0;
            while (sent < 100000) {
                message.mutable_ping()->set_request_id(++sent);
                if (!slow.io->Write(message)) {
                    break;
                }
            }
            CHECK(sent < 100000 && Steady::now() - started < std::chrono::seconds(10));
            std::cout << "{\"slow_reader\":{\"attempted_pings\":" << sent << ",\"close_ms\":" << std::chrono::duration_cast<Milliseconds>(Steady::now() - started).count() << "}}\n";
        }
        std::cout << "PASS silent Hello deadline, logical session reuse, duplicate fencing, Ping/Pong, rejection without credential disclosure\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
