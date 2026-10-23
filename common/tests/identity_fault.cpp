// Refuse declared dependency calls only during owned thread-local test operations.
#include "check.hpp"
#include "fixture.hpp"

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/stack.h>
#include <openssl/x509.h>

#include <array>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <ios>
#include <new>
#include <string>
#include <string_view>
#include <unistd.h>

namespace {

// Thread-local observations affect only this test's initiating thread and never own the borrowed crypto objects.
struct Probe {
    /// One independently injectable cryptographic allocation or verification boundary.
    enum class Site {
        /// Leave every dependency call on its real path; initial and retired probe state.
        None,
        /// Refuse one selected in-memory BIO stream allocation.
        Bio,
        /// Refuse creation of the certificate trust store.
        Store,
        /// Refuse insertion of a parsed root certificate without retaining it.
        Root,
        /// Refuse intermediate-chain stack allocation after root parsing completes.
        Chain,
        /// Refuse insertion of the actual intermediate certificate into its chain.
        Push,
        /// Refuse allocation of the certificate verification context.
        Context,
        /// Refuse verification-context initialization while preserving context ownership.
        Init,
        /// Refuse binding the expected IP address to verification parameters.
        Address,
        /// Return failure from dependency certificate verification.
        Verify,
        /// Throw from one scalar allocation during the pure identity encoder.
        Allocate
    };

    /// One selected API refusal; disabled outside its acquisition.
    Site site = Site::None;
    /// Successful matching calls before the selected refusal.
    unsigned remaining = 0;
    /// A missed or repeated injection fails the oracle.
    unsigned hits = 0;
    /// Core creates roots, certificates and private-key streams in this order.
    unsigned streams = 0;
    /// Real parser results from the actual certificate stream.
    unsigned certificates = 0;
    /// Borrow the root stream until this load finishes.
    BIO* roots = nullptr;
    /// Borrow the distinct certificate stream.
    BIO* chain = nullptr;
    /// Second real certificate passed to the intermediate stack.
    X509* intermediate = nullptr;
    /// Root EOF identifies the subsequent stack-allocation boundary.
    bool parsed = false;

    // Refusal never allocates, throws, or spreads to a later matching call.
    bool take(Site current) noexcept {

        if (current != site || hits) {
            return false;
        }
        if (remaining) {
            --remaining;
            return false;
        }
        ++hits;
        return true;
    }
};

thread_local Probe probe; // Other library threads retain the disabled default probe.

} // namespace

// GNU ld supplies the original entry points; decltype preserves the installed BoringSSL prototypes.
extern "C" {
decltype(BIO_new_mem_buf) __real_BIO_new_mem_buf;
decltype(X509_STORE_new) __real_X509_STORE_new;
decltype(X509_STORE_add_cert) __real_X509_STORE_add_cert;
decltype(PEM_read_bio_X509) __real_PEM_read_bio_X509;
decltype(OPENSSL_sk_new_null) __real_OPENSSL_sk_new_null;
decltype(OPENSSL_sk_push) __real_OPENSSL_sk_push;
decltype(X509_STORE_CTX_new) __real_X509_STORE_CTX_new;
decltype(X509_STORE_CTX_init) __real_X509_STORE_CTX_init;
decltype(X509_VERIFY_PARAM_set1_ip_asc) __real_X509_VERIFY_PARAM_set1_ip_asc;
decltype(X509_verify_cert) __real_X509_verify_cert;
void* __real__Znwm(std::size_t size);
}

// GNU's scalar-new symbol keeps the real allocator and affects only one armed encoding call on this thread.
extern "C" void* __wrap__Znwm(std::size_t size) {
    if (probe.take(Probe::Site::Allocate)) {
        throw std::bad_alloc();
    }
    return __real__Znwm(size);
}

// Fail one selected stream call and retain real stream identities for the two chain cases.
extern "C" BIO* __wrap_BIO_new_mem_buf(const void* bytes, int length) {

    auto* result = probe.take(Probe::Site::Bio) ? nullptr : __real_BIO_new_mem_buf(bytes, length);
    if (probe.site == Probe::Site::Chain || probe.site == Probe::Site::Push) {
        if (probe.streams == 0) {
            probe.roots = result;
        } else if (probe.streams == 1) {
            probe.chain = result;
        }
        ++probe.streams;
    }
    return result;
}

// A failed factory returns no object and changes no preceding ownership.
extern "C" X509_STORE* __wrap_X509_STORE_new() {
    return probe.take(Probe::Site::Store) ? nullptr : __real_X509_STORE_new();
}

// Refused insertion does not retain the certificate reference acquired by a successful real insertion.
extern "C" int __wrap_X509_STORE_add_cert(X509_STORE* store, X509* certificate) {
    return probe.take(Probe::Site::Root) ? 0 : __real_X509_STORE_add_cert(store, certificate);
}

// Real parsing supplies root EOF and the exact intermediate pointer; no parser result is fabricated.
extern "C" X509* __wrap_PEM_read_bio_X509(BIO* input, X509** certificate, pem_password_cb* callback, void* context) {

    auto* result = __real_PEM_read_bio_X509(input, certificate, callback, context);
    if (probe.site == Probe::Site::Chain || probe.site == Probe::Site::Push) {
        if (input == probe.roots && !result) {
            probe.parsed = true;
        }
        if (input == probe.chain && result && ++probe.certificates == 2) {
            probe.intermediate = result;
        }
    }
    return result;
}

// Earlier parser stacks remain real; only the intermediate stack after root parsing may refuse allocation.
extern "C" OPENSSL_STACK* __wrap_OPENSSL_sk_new_null() {
    return probe.parsed && probe.take(Probe::Site::Chain) ? nullptr : __real_OPENSSL_sk_new_null();
}

// Match the parsed intermediate so the production rollback must release its own preceding up_ref.
extern "C" std::size_t __wrap_OPENSSL_sk_push(OPENSSL_STACK* stack, void* value) {
    return probe.intermediate && value == probe.intermediate && probe.take(Probe::Site::Push) ? 0 : __real_OPENSSL_sk_push(stack, value);
}

// Context allocation failure leaves the preceding certificate owners reclaimable.
extern "C" X509_STORE_CTX* __wrap_X509_STORE_CTX_new() {
    return probe.take(Probe::Site::Context) ? nullptr : __real_X509_STORE_CTX_new();
}

// Refused initialization leaves the real context to its normal destructor.
extern "C" int __wrap_X509_STORE_CTX_init(X509_STORE_CTX* context, X509_STORE* store, X509* certificate, STACK_OF(X509) * chain) {
    return probe.take(Probe::Site::Init) ? 0 : __real_X509_STORE_CTX_init(context, store, certificate, chain);
}

// Address binding may refuse allocation for a valid IP without changing the host address or clock.
extern "C" int __wrap_X509_VERIFY_PARAM_set1_ip_asc(X509_VERIFY_PARAM* parameters, const char* address) {
    return probe.take(Probe::Site::Address) ? 0 : __real_X509_VERIFY_PARAM_set1_ip_asc(parameters, address);
}

// Dependency verification errors must not publish a partially prepared identity.
extern "C" int __wrap_X509_verify_cert(X509_STORE_CTX* context) {
    return probe.take(Probe::Site::Verify) ? 0 : __real_X509_verify_cert(context);
}

namespace astra::test {
namespace {

// Enumerate scalar allocation failures in the pure encoder, keeping the caller's member and all allocator ownership intact.
unsigned encoding() {

    Member member{"alpha", "encoding", {}, *Endpoint::parse("127.0.0.1:7443"), Member::Epoch{37}, Member::Role::Star, "local"};
    member.principal.bytes.fill(7);
    const auto before = member; // Freeze every caller-owned field before a fault can occur.
    CHECK(member.validate());
    CHECK(Identity::encode(member).id() == "encoding"); // Initialize lazy dependency state outside the operation's allocation sequence.
    unsigned failures = 0;                              // Every preceding allocation ordinal must throw exactly once.
    bool completed = false;                             // A full successful operation terminates the finite enumeration.
    for (unsigned position = 0; position < 64; ++position) {
        probe = Probe{.site = Probe::Site::Allocate, .remaining = position};
        try {
            const auto encoded = Identity::encode(member);
            const auto hits = probe.hits;
            probe = {}; // Disarm before assertions, output, destruction, or the next operation.
            CHECK(hits == 0);
            CHECK(member == before);
            CHECK(encoded.galaxy() == "alpha");
            CHECK(encoded.id() == "encoding");
            CHECK(encoded.principal() == std::string(32, '\x07'));
            CHECK(encoded.advertise() == "127.0.0.1:7443");
            CHECK(encoded.epoch() == 37);
            CHECK(encoded.role() == proto::orbit::v1::ROLE_STAR);
            CHECK(encoded.group() == "local");
            completed = true;
            break;
        } catch (const std::bad_alloc&) {
            const auto hits = probe.hits;
            probe = {};
            CHECK(hits == 1);
            CHECK(member == before);
            ++failures;
        } catch (...) {
            probe = {};
            throw;
        }
    }
    CHECK(completed && failures > 0);
    return failures;
}

} // namespace

// The caller owns the complete public credential directory; restore every changed file before returning.
void credentials(const std::filesystem::path& directory) {

    const auto fixtures = std::filesystem::path(ASTRA_FIXTURES) / "star-a"; // Repository material remains read-only.
    const auto endpoint = *Endpoint::parse("127.0.0.1:7443");               // Fixed, independently declared fixture SAN.
    const auto retained = Identity::load(directory, endpoint);              // Previously published identity must survive every refusal.
    CHECK(retained);
    const auto principal = (*retained)->principal("alpha", endpoint.text()); // Freeze the prior deployment identity.
    const auto certificate = read(fixtures / "cert.pem");                    // Preserve the original leaf bytes for final restoration.
    {
        std::ofstream output(directory / "cert.pem", std::ios::binary | std::ios::trunc);
        output << certificate << read(fixtures / "ca.pem"); // A complete second certificate exercises real chain retention.
        output.close();
        CHECK(output);
    }
    CHECK(Identity::loadServer(directory, endpoint));

    /// Bind one dependency refusal to its required error category and diagnostic boundary.
    struct Case {
        /// Documented dependency refusal, not arbitrary state corruption.
        Probe::Site site;
        /// BIO cases isolate each independently allocated stream.
        unsigned position;
        /// Required owning error category.
        Status::Code code;
        /// Require the intended boundary rather than any failure.
        std::string_view reason;
    };

    const std::array cases = {
        Case{Probe::Site::Bio, 0, Status::Code::Internal, "Cannot allocate certificate validation context"},
        Case{Probe::Site::Bio, 1, Status::Code::Internal, "Cannot allocate certificate validation context"},
        Case{Probe::Site::Bio, 2, Status::Code::Internal, "Cannot allocate certificate validation context"},
        Case{Probe::Site::Bio, 3, Status::Code::Identity, "Cannot prepare TLS certificate provider"},
        Case{Probe::Site::Bio, 4, Status::Code::Identity, "Cannot prepare TLS certificate provider"},
        Case{Probe::Site::Bio, 5, Status::Code::Identity, "Cannot prepare TLS certificate provider"},
        Case{Probe::Site::Store, 0, Status::Code::Internal, "Cannot allocate certificate validation context"},
        Case{Probe::Site::Root, 0, Status::Code::Identity, "Invalid trust root"},
        Case{Probe::Site::Chain, 0, Status::Code::Internal, "Cannot allocate certificate chain"},
        Case{Probe::Site::Push, 0, Status::Code::Internal, "Cannot retain certificate chain"},
        Case{Probe::Site::Context, 0, Status::Code::Identity, "Local certificate does not authorize the advertised endpoint"},
        Case{Probe::Site::Init, 0, Status::Code::Identity, "Local certificate does not authorize the advertised endpoint"},
        Case{Probe::Site::Address, 0, Status::Code::Identity, "Local certificate does not authorize the advertised endpoint"},
        Case{Probe::Site::Verify, 0, Status::Code::Identity, "Local certificate does not authorize the advertised endpoint"},
    };
    for (const auto& item : cases) {
        probe = Probe{.site = item.site, .remaining = item.position};
        const auto refused = Identity::loadServer(directory, endpoint); // Consume exactly one API refusal in this acquisition.
        const auto hits = probe.hits;
        probe = {};
        CHECK(hits == 1);
        CHECK(!refused && refused.error().code == item.code && refused.error().message == item.reason);
        CHECK(Identity::loadServer(directory, endpoint));
        CHECK((*retained)->principal("alpha", endpoint.text()) == principal);
    }
    for (unsigned position = 0; position < 2; ++position) {
        probe = Probe{.site = Probe::Site::Bio, .remaining = position};
        const auto refused = Identity::external(directory); // Public TLS acquires two separate streams.
        const auto hits = probe.hits;
        probe = {};
        CHECK(hits == 1);
        CHECK(!refused && refused.error().code == Status::Code::Internal && refused.error().message == "Cannot prepare public TLS material");
        CHECK(Identity::external(directory));
    }

    const auto path = directory / "login.json";                           // Only this owned file's permissions change.
    const auto permissions = std::filesystem::status(path).permissions(); // Restore the original mode exactly.
    CHECK(geteuid() != 0);                                                // Root execution cannot establish unprivileged refusal.
    std::filesystem::permissions(path, std::filesystem::perms::none);
    const auto refused = Identity::load(directory, endpoint);
    std::filesystem::permissions(path, permissions);
    CHECK(!refused && refused.error().code == Status::Code::Identity && refused.error().message == "Cannot read bounded identity file");
    CHECK(Identity::load(directory, endpoint));
    {
        std::ofstream output(directory / "cert.pem", std::ios::binary | std::ios::trunc);
        output << certificate;
        output.close();
        CHECK(output);
    }
    CHECK(Identity::load(directory, endpoint));
    const Identity empty; // Public default construction has no provider and must refuse server credentials safely.
    CHECK(!empty.serverCredentials());
    const auto failures = encoding(); // ASan/LSan observes cleanup after every partially built message.
    std::fprintf(stdout, "ASTRA-IDENTITY-FAULTS {\"dependencies\":%zu,\"allocation_failures\":%u,\"allocation_completions\":1}\n", cases.size() + 2, failures);
}

} // namespace astra::test
