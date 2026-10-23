// Verify that a real SQLite sync refusal prevents registration publication and permits recovery after reopening.
#include "authority.hpp"
#include "database_fault.hpp"
#include "issuer.hpp"
#include "pulsar_test.hpp"

#include <exception>
#include <filesystem>
#include <iostream>
#include <string>

/// Preserve the refusal, retained snapshot and successful reopen observations in one owned database lifetime.
int main() {
    try {
        // Public fixture identities provide real signing and authentication without starting a listener.
        const auto endpoint = astra::Endpoint::parse("127.0.0.1:7443");
        CHECK(endpoint);
        const auto authority = astra::Authority::load(std::filesystem::path(ASTRA_FIXTURES) / "pulsar", *endpoint, *endpoint);
        const auto identity = astra::Identity::load(std::filesystem::path(ASTRA_FIXTURES) / "star-a", *endpoint);
        CHECK(authority && identity);
        // The local VFS model and temporary directory outlive both database owners.
        astra::test::Directory directory;
        astra::test::Fault fault;
        const auto database = directory.path / "commit.db";
        proto::orbit::v1::RegistrationRequest request;
        request.set_username((*identity)->username());
        request.set_password((*identity)->password());
        request.set_galaxy("alpha");
        request.set_group("default");
        request.set_advertise("127.0.0.1:7443");
        request.set_role(proto::orbit::v1::ROLE_STAR);
        request.set_request_id(std::string(32, 's'));
        astra::Member original;
        {
            // Establish one committed registration and retain its immutable snapshot before the injected sync failure.
            astra::Ledger ledger(database, "alpha", (*authority)->keyId(), 2, 8, true);
            astra::Issuer issuer("alpha", "127.0.0.1:7442", **authority, ledger);
            grpc::ServerContext healthyContext;
            proto::orbit::v1::RegistrationResponse healthy;
            CHECK(issuer.Register(&healthyContext, &request, &healthy).ok());
            proto::orbit::v1::Member encoded;
            CHECK(encoded.ParseFromString(healthy.admission()));
            const auto member = astra::decodeMember(encoded);
            CHECK(member);
            original = *member;
            const auto retained = ledger.snapshot(original);
            CHECK(retained && retained->size() == 1);

            request.set_request_id(std::string(32, 'f'));
            fault.arm(SQLITE_IOERR_FSYNC, true);
            grpc::ServerContext failedContext;
            proto::orbit::v1::RegistrationResponse rejected;
            const auto status = issuer.Register(&failedContext, &request, &rejected);
            fault.clear();
            CHECK(fault.hits() == 1);
            std::cout << "PULSAR-COMMIT {\"sync_refusals\":" << fault.hits() << ",\"status\":" << static_cast<int>(status.error_code()) << ",\"response_bytes\":" << rejected.ByteSizeLong() << "}\n"
                      << std::flush;
            CHECK(status.error_code() == grpc::StatusCode::UNAVAILABLE && rejected.ByteSizeLong() == 0);
            CHECK(ledger.snapshot(original) == retained && retained->size() == 1);
        }

        // Recovery must inspect the same real file after the failed owner and its statements have closed.
        astra::Ledger recovered(database, "alpha", (*authority)->keyId(), 2, 8, false);
        CHECK(recovered.current(original));
        astra::Issuer issuer("alpha", "127.0.0.1:7442", **authority, recovered);
        request.set_request_id(std::string(32, 'r'));
        grpc::ServerContext recoveredContext;
        proto::orbit::v1::RegistrationResponse response;
        CHECK(issuer.Register(&recoveredContext, &request, &response).ok());
        proto::orbit::v1::Member encoded;
        CHECK(encoded.ParseFromString(response.admission()));
        const auto replacement = astra::decodeMember(encoded);
        CHECK(replacement && replacement->epoch.value == original.epoch.value + 1 && recovered.current(*replacement));
        std::cout << "PULSAR-COMMIT {\"reopened_original\":true,\"subsequent_registration\":true}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
