// Verify public Pulsar RPC admission and synchronization behavior with owned fixtures.
#include "pulsar_test.hpp"
#include "pulse_client.hpp"
#include "server.hpp"
#include "store.hpp"

#include <grpc/support/time.h>
#include <grpcpp/create_channel.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cstdint>
#include <iostream>
#include <limits>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <thread>

using namespace astra;
using namespace std::chrono_literals;

#if defined(__linux__)
namespace astra::test {
/// Verify controlled Pulse clock refusals through the separately owned TLS fixture.
void pulse();
/// Verify admission preparation, cancellation and real database refusal boundaries.
void issuer();
} // namespace astra::test
#endif

namespace {

/// Owns an authenticated stream that becomes idle. A separate subchannel prevents HTTP/2 stream limits from serializing this fixture.
struct Idle {

    /// Own cancellation and deadlines for the deliberately idle Pulse stream.
    grpc::ClientContext context;

    /// Retain the Pulse stub for the complete idle-stream lifetime.
    std::unique_ptr<proto::pulsar::v1::Pulse::Stub> stub;

    /// Own the idle bidirectional stream until cancellation and Finish complete.
    std::unique_ptr<grpc::ClientReaderWriter<proto::pulsar::v1::Ping, proto::pulsar::v1::Pong>> stream;

    /// Prevent a second Finish after the idle stream has already been drained.
    bool finished{};

    Idle(const std::string& endpoint, const Identity& identity, const proto::astra::v1::Hello& hello, bool longDeadline = false) {

        if (longDeadline) {
            context.set_deadline(gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC), gpr_time_from_seconds(3600, GPR_TIMESPAN)));
        }
        context.AddMetadata("astra-admission-bin", hello.admission());
        context.AddMetadata("astra-signature-bin", hello.admission_signature());

        grpc::ChannelArguments arguments;
        arguments.SetInt("grpc.use_local_subchannel_pool", 1);
        stub = proto::pulsar::v1::Pulse::NewStub(grpc::CreateCustomChannel(endpoint, identity.channelCredentials(), arguments));
        stream = stub->Bounce(&context);
    }

    /// Cancel and drain unfinished streams, including exception paths.
    ~Idle() {

        if (!finished) {
            context.TryCancel();
            static_cast<void>(stream->Finish());
        }
    }

    /// Receive a real Pong before going idle to establish that the server accepted the stream.
    void ping() {

        proto::pulsar::v1::Ping ping;

        proto::pulsar::v1::Pong pong;
        ping.set_t0(static_cast<std::uint64_t>(elapsedNanoseconds(Clock::Elapsed::now())));
        CHECK(stream->Write(ping) && stream->Read(&pong));
        CHECK(pong.t0() == ping.t0() && pong.precision_ns() >= 1 && pong.precision_ns() <= 20'000'000);
        CHECK(pong.synchronized() && pong.t2() >= pong.t1() && pong.t1() >= 1'800'000'000'000'000'000ULL);
    }

    /// Do not half-close; only the server's monotonic deadline may end this stream. CTest separately bounds the whole case.
    grpc::Status waitExpiry() {

        proto::pulsar::v1::Pong pong;
        CHECK(!stream->Read(&pong));

        auto status = stream->Finish();
        finished = true;
        return status;
    }
};

/// Own one fixture identity and admission stub for a loopback RPC client.
struct Client {

    /// Retain the public test identity used to authenticate this admission client.
    std::shared_ptr<Identity> identity;

    /// Own the admission stub bound to this isolated test server.
    std::unique_ptr<proto::orbit::v1::Admission::Stub> stub;

    /// Load the named public fixture, defaulting to star-a, and connect to the owned endpoint.
    explicit Client(const std::string& endpoint, std::string_view fixture = "star-a") {
        auto loaded = Identity::load(std::filesystem::path(ASTRA_FIXTURES) / fixture, *Endpoint::parse("127.0.0.1:7443"));
        CHECK(loaded);
        identity = std::move(*loaded);
        stub = proto::orbit::v1::Admission::NewStub(grpc::CreateChannel(endpoint, identity->channelCredentials()));
    }

    proto::orbit::v1::RegistrationRequest request(char startup, std::uint16_t port = 7443) const {

        proto::orbit::v1::RegistrationRequest request;
        request.set_username(identity->username());
        request.set_password(identity->password());
        request.set_galaxy("alpha");
        request.set_group("default");
        request.set_role(proto::orbit::v1::ROLE_STAR);
        request.set_advertise("127.0.0.1:" + std::to_string(port));
        request.set_request_id(std::string(32, startup));
        return request;
    }

    /// Uses a fresh context and ten-second deadline, returning the actual final status for assertions.
    grpc::Status call(const proto::orbit::v1::RegistrationRequest& request, proto::orbit::v1::RegistrationResponse& response) {

        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + 10s);
        response.Clear();
        return stub->Register(&context, request, &response);
    }

    /// Queries with existing raw credentials; duplicate creates repeated-metadata rejection input.
    grpc::Status list(std::string_view admission, std::string_view signature, proto::orbit::v1::DirectoryResponse& response, bool duplicate = false) {

        grpc::ClientContext context;
        context.set_deadline(gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC), gpr_time_from_seconds(3, GPR_TIMESPAN)));
        if (!admission.empty()) {
            context.AddMetadata("astra-admission-bin", std::string(admission));
            context.AddMetadata("astra-signature-bin", std::string(signature));
            if (duplicate) {
                context.AddMetadata("astra-admission-bin", std::string(admission));
            }
        }

        const proto::orbit::v1::DirectoryRequest request;
        response.Clear();
        return stub->List(&context, request, &response);
    }
};

/// Exercise one independently scheduled candidate layout against literal group/round vectors.
static void candidates(unsigned selected) {

    /// Each layout fixes the complete ordered result for rounds 0, 1, 2 and UINT32_MAX.
    struct Case {
        /// Number of known Stars in the requesting Planet's group.
        unsigned near;
        /// Number of known Stars in a distinct group.
        unsigned far;
        /// Independently calculated, sorted-within-group wire IDs; an empty pool is a valid result.
        std::array<std::string_view, 4> expected;
    };

    // Literal vectors use SHA-256("planets" + NUL + "alpha" + NUL + "127.0.0.1:7900").
    // Hashing that lowercase principal text gives the big-endian seed 18093214737444147755.
    // No production selector or runtime hash constructs these expected lists.
    const std::array layouts{
        Case{0, 0, {"", "", "", ""}},
        Case{0, 3, {"r_01 r_02 r_03", "r_01 r_02 r_03", "r_01 r_02 r_03", "r_01 r_02 r_03"}},
        Case{3, 0, {"n_01 n_02 n_03", "n_01 n_02 n_03", "n_01 n_02 n_03", "n_01 n_02 n_03"}},
        Case{2, 8, {"n_01 n_02 r_01 r_04 r_05 r_06 r_07 r_08", "n_01 n_02 r_01 r_02 r_03 r_04 r_05 r_08", "n_01 n_02 r_01 r_04 r_05 r_06 r_07 r_08", "n_01 n_02 r_01 r_02 r_03 r_04 r_05 r_08"}},
        Case{8, 2, {"n_01 n_04 n_05 n_06 n_07 n_08 r_01 r_02", "n_01 n_02 n_03 n_04 n_05 n_08 r_01 r_02", "n_01 n_04 n_05 n_06 n_07 n_08 r_01 r_02", "n_01 n_02 n_03 n_04 n_05 n_08 r_01 r_02"}},
        Case{6, 6, {"n_01 n_02 n_03 n_06 r_01 r_02 r_03 r_06", "n_01 n_04 n_05 n_06 r_01 r_04 r_05 r_06", "n_02 n_03 n_04 n_05 r_02 r_03 r_04 r_05", "n_01 n_02 n_03 n_06 r_01 r_02 r_03 r_06"}},
        Case{1, 1, {"n_01 r_01", "n_01 r_01", "n_01 r_01", "n_01 r_01"}}};
    const std::array<std::uint32_t, 4> rounds{0, 1, 2, std::numeric_limits<std::uint32_t>::max()};
    // Public fixture materials stay read-only; each layout owns its own durable membership database.
    const auto endpoint = *Endpoint::parse("127.0.0.1:0", true);
    auto loaded = Authority::load(std::filesystem::path(ASTRA_FIXTURES) / "pulsar", endpoint, endpoint);
    CHECK(loaded);
    const auto& authority = **loaded;

    CHECK(selected < layouts.size());
    for (const auto& layout : std::span(layouts).subspan(selected, 1)) {
        test::Directory directory;
        Server::Config config;
        config.listen = endpoint;
        config.pulseListen = endpoint;
        config.galaxy = "alpha";
        config.identity = std::filesystem::path(ASTRA_FIXTURES) / "pulsar";
        config.state = directory.path / "membership.db";
        config.starts = 128;
        // Capture only known committed records; their principal order intentionally reverses their ID order.
        std::map<std::string, Member, std::less<>> members;
        {
            Ledger ledger(config.state, config.galaxy, authority.keyId(), config.maximum, config.starts, true);
            const auto add = [&ledger, &members](unsigned index, Member::Role role, std::string id, std::string group) {
                auto value = test::member(index, role);
                value.principal.bytes[0] = static_cast<std::uint8_t>(64 - index);
                value.id = std::move(id);
                value.group = std::move(group);
                CHECK(ledger.registerMember(std::move(value), std::string(32, static_cast<char>('A' + index)), [&members](const Member& local, const auto&) { CHECK(members.emplace(local.id, local).second); }));
            };
            unsigned index = 0;
            for (unsigned count = 1; count <= layout.near; ++count) {
                add(++index, Member::Role::Star, "n_0" + std::to_string(count), "default");
            }
            for (unsigned count = 1; count <= layout.far; ++count) {
                add(++index, Member::Role::Star, "r_0" + std::to_string(count), "remote");
            }
            add(++index, Member::Role::Polaris, "control", "default");
            add(++index, Member::Role::Astrolabe, "management", "remote");
            add(++index, Member::Role::Planet, "other-planet", "default");
        }

        // No Pulse reference is needed for admission; use the existing injectable provider without changing host time.
        Server server(config, []() -> std::optional<Clock::Estimate> { return std::nullopt; });
        server.start();
        Client client(server.admissionEndpoint(), "planet-a");
        auto request = client.request('z', 7900);
        request.set_role(proto::orbit::v1::ROLE_PLANET);
        proto::orbit::v1::RegistrationResponse response;
        std::string admission, signature;

        /// Compare every encoded field to an independently retained committed value.
        const auto equal = [](const proto::orbit::v1::Member& actual, const Member& expected) {
            const auto principal = std::string(reinterpret_cast<const char*>(expected.principal.bytes.data()), expected.principal.bytes.size());
            CHECK(actual.galaxy() == "alpha" && actual.id() == expected.id && actual.principal() == principal);
            CHECK(actual.advertise() == "127.0.0.1:" + std::to_string(expected.address.port) && actual.epoch() == 1 && actual.group() == expected.group);
            switch (expected.role) {
            case Member::Role::Star:
                CHECK(actual.role() == proto::orbit::v1::ROLE_STAR);
                break;
            case Member::Role::Polaris:
                CHECK(actual.role() == proto::orbit::v1::ROLE_POLARIS);
                break;
            case Member::Role::Astrolabe:
                CHECK(actual.role() == proto::orbit::v1::ROLE_ASTROLABE);
                break;
            case Member::Role::Planet:
                CHECK(actual.role() == proto::orbit::v1::ROLE_PLANET);
                break;
            }
        };
        for (std::size_t index = 0; index < rounds.size(); ++index) {
            request.set_candidate_round(rounds[index]);
            CHECK(client.call(request, response).ok());
            CHECK(response.pulse_endpoint().empty() && response.members_size() <= 8 && response.signature().size() == 64);
            proto::orbit::v1::Member local;
            CHECK(local.ParseFromString(response.admission()) && local.epoch() == 1 && local.role() == proto::orbit::v1::ROLE_PLANET);
            CHECK(local.galaxy() == "alpha" && local.advertise() == "127.0.0.1:7900" && local.group() == "default");
            CHECK(local.principal() == std::string("\xa4\x00\x34\x36\x6f\xdf\x54\xfd\x68\xbb\x77\x23\x25\xae\xb0\xbf\xd5\xb1\x63\x6a\xfe\x3c\x62\x7f\x87\x8b\x92\x28\xd8\x8b\x71\xed", 32));
            if (index == 0) {
                admission = response.admission();
                signature = response.signature();
                Member expected{"alpha", local.id(), *Principal::parse("a40034366fdf54fd68bb772325aeb0bfd5b1636afe3c627f878b9228d88b71ed"), *Endpoint::parse("127.0.0.1:7900"), {1}, Member::Role::Planet, "default"};
                const auto id = expected.id;
                CHECK(members.emplace(id, std::move(expected)).second);
            } else {
                CHECK(response.admission() == admission && response.signature() == signature);
            }

            // Join the actual wire IDs, preserving duplicates and order; compare with the complete literal vector.
            std::string actual;
            for (const auto& member : response.members()) {
                if (!actual.empty()) {
                    actual += ' ';
                }
                actual += member.id();
                CHECK(members.contains(member.id()) && members.at(member.id()).role == Member::Role::Star);
                equal(member, members.at(member.id()));
            }
            std::cout << "ASTRA-CANDIDATES {\"near\":" << layout.near << ",\"remote\":" << layout.far << ",\"round\":" << rounds[index] << ",\"ids\":\"" << actual << "\"}\n";
            CHECK(actual == layout.expected[index]);
        }

        // A signed Planet can register and refresh candidates, but cannot read an infrastructure directory.
        proto::orbit::v1::DirectoryResponse responseList;
        CHECK(client.list(admission, signature, responseList).error_code() == grpc::StatusCode::UNAUTHENTICATED && responseList.members_size() == 0);
        const auto unchanged = [&client, &request, &response, &admission, &signature] {
            CHECK(client.call(request, response).ok());
            CHECK(response.admission() == admission && response.signature() == signature);
        };
        auto changed = request;
        changed.set_group("remote");
        CHECK(client.call(changed, response).error_code() == grpc::StatusCode::ABORTED && response.admission().empty() && response.members_size() == 0);
        unchanged();
        // Non-Planet requests reject a nonzero candidate round before any registration can commit.
        changed = request;
        changed.set_role(proto::orbit::v1::ROLE_STAR);
        CHECK(client.call(changed, response).error_code() == grpc::StatusCode::INVALID_ARGUMENT && response.members_size() == 0);
        unchanged();

        // Directory selection has separate full-role rules; real signed metadata exercises the public RPC boundary.
        for (const auto role : {Member::Role::Star, Member::Role::Polaris, Member::Role::Astrolabe}) {
            const auto selected = std::ranges::find_if(members, [role](const auto& item) { return item.second.role == role; });
            if (selected == members.end()) {
                CHECK(role == Member::Role::Star && layout.near + layout.far == 0);
                continue;
            }
            const auto& reader = selected->second;
            proto::orbit::v1::RegistrationResponse token;
            authority.sign(Identity::encode(reader), token);
            CHECK(client.list(token.admission(), token.signature(), responseList).ok());
            auto expected = members.begin();
            for (const auto& value : responseList.members()) {
                while (expected != members.end() && reader.role != Member::Role::Astrolabe && expected->second.role != Member::Role::Star && expected->second.role != Member::Role::Polaris) {
                    ++expected;
                }
                CHECK(expected != members.end() && value.id() == expected->first);
                equal(value, expected->second);
                ++expected;
            }
            while (expected != members.end() && reader.role != Member::Role::Astrolabe && expected->second.role != Member::Role::Star && expected->second.role != Member::Role::Polaris) {
                ++expected;
            }
            CHECK(expected == members.end());
        }
        server.stop();
    }
}

/// Requires a fresh synchronized sample newer than after, within 15 monotonic seconds.
static Clock::Reading waitClock(const Clock& clock, ElapsedTime after = {}) {

    const auto deadline = Steady::now() + 15s;
    while (Steady::now() < deadline) {

        if (auto value = clock.now(); value && value->synchronized && value->sampled > after) {
            return *value;
        }
        std::this_thread::sleep_for(10ms);
    }
    throw std::runtime_error("Star did not calibrate within deadline");
}

} // namespace

int main(int argc, char** argv) {

    try {
        // Each candidate layout owns a CTest deadline; keep the real password work and every oracle intact.
        if (argc == 2) {
            const std::string_view argument(argv[1]);
#if defined(__linux__)
            if (argument == "pulse") {
                test::pulse();
                return 0;
            }
            if (argument == "issuer") {
                test::issuer();
                return 0;
            }
#endif
            unsigned selected{};
            const auto [end, error] = std::from_chars(argument.data(), argument.data() + argument.size(), selected);
            CHECK(error == std::errc{} && end == argument.data() + argument.size());
            candidates(selected);
            return 0;
        }
        CHECK(argc == 1);
#if defined(__linux__)
        test::pulse();
        test::issuer();
#endif

        test::Directory directory;

        Server::Config config;
        config.listen = *Endpoint::parse("127.0.0.1:0", true);
        config.pulseListen = *Endpoint::parse("127.0.0.1:0", true);
        config.galaxy = "alpha";
        config.identity = std::filesystem::path(ASTRA_FIXTURES) / "pulsar";
        config.state = directory.path / "membership.db";
        config.initialize = true;
        // Inject a private reference for RPC tests without depending on host network synchronization or changing the system clock.
        std::atomic_bool sourceAvailable{false};

        const auto provider = [&]() -> std::optional<Clock::Estimate> {
            if (!sourceAvailable.load()) {
                return std::nullopt;
            }

            const auto local = Clock::Elapsed::now();
            return Clock::Estimate{Clock::Time(1'800'000'000s) + local.time_since_epoch(), local, 1000, 0};
        };

        auto server = std::make_unique<Server>(config, provider);
        server->start();
        // Restart of the same database restores only; initialization permission does not follow reused Config.
        config.initialize = false;
        config.listen = *Endpoint::parse(server->admissionEndpoint());
        config.pulseListen = *Endpoint::parse(server->pulseEndpoint());
        CHECK(config.listen != config.pulseListen);
        {
            // Reject invalid configuration and a second listener on the same port even with a different ledger.
            const auto parse = [](std::initializer_list<std::string_view> args) { return Server::Config::parse({args.begin(), args.size()}); };
            CHECK(parse({"--listen=127.0.0.1:0", "--pulse-listen=127.0.0.1:0", "--galaxy=alpha"}));
            CHECK(!parse({"--listen=127.0.0.1:1", "--pulse-listen=127.0.0.1:1", "--galaxy=alpha"}));
            CHECK(!parse({"--listen=0.0.0.0:0", "--pulse-listen=127.0.0.1:0", "--galaxy=alpha"}));
            CHECK(!parse({"--listen=127.0.0.1:0", "--pulse-listen=127.0.0.1:0", "--galaxy=alpha", "--galaxy=alpha"}));
            CHECK(!parse({"--listen=127.0.0.1:0", "--pulse-listen=127.0.0.1:0", "--galaxy=alpha", "--max-starts=0"}));
            CHECK(!parse({"--listen=127.0.0.1:0", "--galaxy=alpha"}));
            CHECK(!parse({"--listen=127.0.0.1:0", "--pulse-listen=127.0.0.1:0", "--galaxy=alpha", "--init=1"}));
            CHECK(!parse({"--listen=127.0.0.1:0", "--pulse-listen=127.0.0.1:0", "--galaxy=alpha", "--init=true", "--init=false"}));

            const auto initialized = parse({"--listen=127.0.0.1:0", "--pulse-listen=127.0.0.1:0", "--galaxy=alpha", "--init=true"});
            CHECK(initialized && initialized->initialize);

            auto duplicateConfig = config;
            duplicateConfig.state = directory.path / "duplicate.db";
            duplicateConfig.initialize = true;

            bool refused = false;
            try {

                Server duplicate(duplicateConfig);
                duplicate.start();
            } catch (const std::exception&) {
                refused = true;
            }
            CHECK(refused);
        }

        Client client(server->admissionEndpoint());
        // Clear each response so successful fields cannot leak into later failure assertions.
        proto::orbit::v1::RegistrationResponse response;

        auto first = client.request('a');
        CHECK(client.call(first, response).ok());
        CHECK(response.members_size() == 1 && response.pulse_endpoint() == server->pulseEndpoint());

        const auto original = response.admission();

        const auto originalSignature = response.signature();
        CHECK(client.call(client.request('b', 7444), response).ok());
        CHECK(client.call(first, response).ok());
        CHECK(response.admission() == original && response.members_size() == 2);
        CHECK(response.members(0).id() < response.members(1).id());

        proto::orbit::v1::DirectoryResponse directoryResponse;
        CHECK(client.list(original, originalSignature, directoryResponse).ok());
        CHECK(directoryResponse.members_size() == 2 && directoryResponse.members(0).id() < directoryResponse.members(1).id());
        CHECK(client.list({}, {}, directoryResponse).error_code() == grpc::StatusCode::UNAUTHENTICATED);
        CHECK(client.list(original, std::string(64, '\0'), directoryResponse).error_code() == grpc::StatusCode::UNAUTHENTICATED);
        CHECK(client.list(original, originalSignature, directoryResponse, true).error_code() == grpc::StatusCode::UNAUTHENTICATED);

        auto bad = first;
        bad.set_password("not-the-fixture-password");
        CHECK(client.call(bad, response).error_code() == grpc::StatusCode::UNAUTHENTICATED);
        bad = first;
        bad.set_username("missing-account");
        CHECK(client.call(bad, response).error_code() == grpc::StatusCode::UNAUTHENTICATED);
        bad = first;
        bad.set_role(proto::orbit::v1::ROLE_PLANET);
        CHECK(client.call(bad, response).error_code() == grpc::StatusCode::PERMISSION_DENIED);
        bad = first;
        bad.set_galaxy("other");
        CHECK(client.call(bad, response).error_code() == grpc::StatusCode::INVALID_ARGUMENT);
        bad = first;
        bad.set_advertise("127.0.0.1:7445");
        CHECK(client.call(bad, response).error_code() == grpc::StatusCode::ABORTED);
        bad = first;
        bad.set_request_id("short");
        CHECK(client.call(bad, response).error_code() == grpc::StatusCode::INVALID_ARGUMENT);

        // A new startup for the same deployment replaces the old instance; the old startup request cannot regain credentials.
        auto replacement = client.request('c');
        CHECK(client.call(replacement, response).ok());

        proto::orbit::v1::Member member;
        CHECK(member.ParseFromString(response.admission()) && member.epoch() == 2);

        auto hello = std::make_shared<proto::astra::v1::Hello>();
        hello->set_admission(response.admission());
        hello->set_admission_signature(response.signature());

        const auto committed = response.admission();
        CHECK(client.call(first, response).error_code() == grpc::StatusCode::ABORTED);
        CHECK(client.list(original, originalSignature, directoryResponse).error_code() == grpc::StatusCode::UNAUTHENTICATED);
        CHECK(client.list(hello->admission(), hello->admission_signature(), directoryResponse).ok());
        CHECK(directoryResponse.members_size() == 2);

        auto pulseStub = proto::pulsar::v1::Pulse::NewStub(grpc::CreateChannel(server->pulseEndpoint(), client.identity->channelCredentials()));
        // Reject both forged signatures and genuine superseded credentials, beyond successful TLS setup.
        const auto rejectCredential = [&](const std::string& admission, const std::string& signature) {
            grpc::ClientContext context;
            context.set_deadline(std::chrono::system_clock::now() + 2s);
            context.AddMetadata("astra-admission-bin", admission);
            context.AddMetadata("astra-signature-bin", signature);

            auto stream = pulseStub->Bounce(&context);

            proto::pulsar::v1::Pong pong;
            static_cast<void>(stream->WritesDone());
            CHECK(!stream->Read(&pong));
            CHECK(stream->Finish().error_code() == grpc::StatusCode::PERMISSION_DENIED);
        };
        rejectCredential(original, originalSignature);
        rejectCredential(hello->admission(), std::string(64, '\0'));
        {

            grpc::ClientContext context;
            context.set_deadline(std::chrono::system_clock::now() + 2s);

            auto stream = pulseStub->Bounce(&context);

            proto::pulsar::v1::Pong pong;
            static_cast<void>(stream->WritesDone());
            CHECK(!stream->Read(&pong));
            CHECK(stream->Finish().error_code() == grpc::StatusCode::UNAUTHENTICATED);
        }

        // Unavailable system time must not block admission, but sampling with valid credentials must fail explicitly.
        {

            grpc::ClientContext context;
            context.set_deadline(std::chrono::system_clock::now() + 2s);
            context.AddMetadata("astra-admission-bin", hello->admission());
            context.AddMetadata("astra-signature-bin", hello->admission_signature());

            auto stream = pulseStub->Bounce(&context);

            proto::pulsar::v1::Ping ping;
            ping.set_t0(static_cast<std::uint64_t>(elapsedNanoseconds(Clock::Elapsed::now())));

            proto::pulsar::v1::Pong pong;
            CHECK(stream->Write(ping));
            CHECK(!stream->Read(&pong));
            static_cast<void>(stream->WritesDone());
            CHECK(stream->Finish().error_code() == grpc::StatusCode::UNAVAILABLE);
        }
        sourceAvailable.store(true);

        const auto referenceDeadline = Steady::now() + 10s;
        while (Steady::now() < referenceDeadline) {

            if (const auto time = server->time(); time && time->synchronized) {
                break;
            }
            std::this_thread::sleep_for(10ms);
        }
        CHECK(server->time() && server->time()->synchronized);
        {
            // Unsigned protocol coordinates beyond the signed local-counter range must be rejected before offset arithmetic.
            Idle invalid(server->pulseEndpoint(), *client.identity, *hello);

            proto::pulsar::v1::Ping ping;

            proto::pulsar::v1::Pong pong;
            ping.set_t0(UINT64_MAX);
            CHECK(invalid.stream->Write(ping));
            CHECK(!invalid.stream->Read(&pong));

            const auto status = invalid.stream->Finish();
            invalid.finished = true;
            CHECK(status.error_code() == grpc::StatusCode::INVALID_ARGUMENT);
        }
        {
            // Exactly eight successful replies end the stream normally, without a ninth request or client deadline.
            Idle complete(server->pulseEndpoint(), *client.identity, *hello);

            for (unsigned sample = 0; sample < 8; ++sample) {
                complete.ping();
            }

            proto::pulsar::v1::Pong extra;
            CHECK(!complete.stream->Read(&extra));

            const auto status = complete.stream->Finish();
            complete.finished = true;
            CHECK(status.ok());
        }

        // No client deadline or an excessive deadline must still permit server-owned reclamation.
        for (const auto longDeadline : {false, true}) {

            Idle idle(server->pulseEndpoint(), *client.identity, *hello, longDeadline);
            idle.ping();

            const auto start = Steady::now();
            CHECK(idle.waitExpiry().error_code() == grpc::StatusCode::CANCELLED);
            CHECK(Steady::now() - start < 10s);
        }
        {
            // New Pulse and independent Register calls must complete with multiple idle streams. This is not a throughput or latency benchmark.
            std::vector<std::unique_ptr<Idle>> idle;

            for (unsigned i = 0; i < 24; ++i) {

                auto stream = std::make_unique<Idle>(server->pulseEndpoint(), *client.identity, *hello);
                stream->ping();
                idle.push_back(std::move(stream));
            }
            CHECK(client.call(replacement, response).ok());

            Idle active(server->pulseEndpoint(), *client.identity, *hello);
            active.ping();
            // Concurrent cancellation exercises Alarm/OnDone handoff; later sampling proves quota reuse.
        }

        Clock clock;
        {

            Sampler synchronizer(server->pulseEndpoint(), client.identity, hello, clock);

            const auto before = waitClock(clock);
            CHECK(before.rttNanoseconds <= 200'000'000 && before.time >= Clock::Time(1'800'000'000s));
            // A deadline obtained through network synchronization must continue expiring during Pulsar downtime without renewing TTL.
            Store store;
            store.tick(before.time);

            const auto deadline = before.deadlineAfter(2s);
            CHECK(deadline);
            store.put("expires-during-outage", {1}, *deadline);
            // Retain an immutable pre-expiration snapshot to detect mutation during cleanup.
            const auto snapshot = store.snapshot();

            const auto previousSample = before.sampled;
            sourceAvailable.store(false);
            // First withdraw only the physical reference. Pulse must not present an advancing old clock as a fresh trusted sample.
            const auto outageDeadline = Steady::now() + 10s;
            while (Steady::now() < outageDeadline && clock.now()->synchronized) {
                std::this_thread::sleep_for(10ms);
            }
            CHECK(server->time() && server->time()->ready && !server->time()->synchronized);
            // Past sample freshness, local writes must still obtain finite deadlines.
            const auto offline = clock.now();
            CHECK(offline && offline->ready && !offline->synchronized && offline->time > before.time);
            store.tick(offline->time);
            CHECK(store.snapshot()->data.empty() && store.version() == 2);
            CHECK(snapshot->data.at("expires-during-outage").deadline == *deadline);
            // Recovery must preserve the deadline created while disconnected rather than renew it from receipt time.
            const auto created = offline->deadlineAfter(30s);
            CHECK(created);
            store.put("accepted-during-outage", {2}, *created);
            server->stop();
            server.reset();

            const auto beforeRestart = clock.now()->time;
            sourceAvailable.store(true);
            server = std::make_unique<Server>(config, provider);
            server->start();
            // Recovery requires a newer sample and must retain the same Star clock without time regression.
            const auto recovered = waitClock(clock, previousSample);
            CHECK(recovered.time >= beforeRestart);
            store.tick(recovered.time);
            CHECK(store.snapshot()->data.size() == 1 && store.version() == 3);
            CHECK(store.snapshot()->data.at("accepted-during-outage").deadline == *created);
            CHECK(!store.snapshot()->data.contains("expires-during-outage"));
            // Retry registration at the same endpoint after restart to verify durable identity and directory recovery.
            Client restored(server->admissionEndpoint());
            CHECK(restored.call(replacement, response).ok());
            CHECK(response.admission() == committed && response.members_size() == 2);
            CHECK(restored.call(first, response).error_code() == grpc::StatusCode::ABORTED);
            synchronizer.stop();
        }
        CHECK(clock.now() && clock.now()->ready && !clock.now()->synchronized);
        CHECK(clock.now()->deadlineAfter(1s));
        server->stop();
        server->stop();
        std::cout << "PASS Pulsar TLS/password admission, current topology, signed Pulse, restart recovery and Star clock reconnect\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
