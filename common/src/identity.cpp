// Loads and validates X.509/Ed25519 identity material with BoringSSL, parses login JSON, and constructs gRPC credentials.

#include "identity.hpp"

#include <grpcpp/security/tls_credentials_options.h>
#include <openssl/curve25519.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <yyjson.h>

#include <algorithm>
#include <fstream>

namespace astra {
namespace {
/// Reads bounded regular credential files, checking both metadata and actual bytes; never includes file contents in errors.
Result<std::string> readIdentity(const std::filesystem::path& path) {

    // Receives nonthrowing metadata-query errors; initially clear and checked after each query.
    std::error_code error;
    // Require a regular file no larger than 16384 bytes.
    if (!std::filesystem::is_regular_file(path, error) || error || std::filesystem::file_size(path, error) > 16384 || error) {
        return Status::identity("Identity file must be regular and at most 16 KiB");
    }

    // Owns a read-only stream and bounds actual reads independently of earlier file size.
    std::ifstream file(path, std::ios::binary);

    std::string bytes(16385, '\0');
    file.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));

    if (file.bad() || (!file.eof() && file.fail()) || file.gcount() > 16384) {
        return Status::identity("Cannot read bounded identity file");
    }

    bytes.resize(static_cast<std::size_t>(file.gcount()));
    return bytes;
}

/// Before Pulsar registration, validate advertised server identity: certificate chain, purpose, IP SAN, and matching private key.
Result<void> validateCertificate(const std::string& ca, const std::string& cert, const std::string& key, const Endpoint& endpoint) {

    bssl::UniquePtr<BIO> roots(BIO_new_mem_buf(ca.data(), static_cast<int>(ca.size())));
    bssl::UniquePtr<BIO> certificates(BIO_new_mem_buf(cert.data(), static_cast<int>(cert.size())));
    bssl::UniquePtr<BIO> privateBytes(BIO_new_mem_buf(key.data(), static_cast<int>(key.size())));
    bssl::UniquePtr<X509_STORE> store(X509_STORE_new());

    if (!roots || !certificates || !privateBytes || !store) {
        return Status::internal("Cannot allocate certificate validation context");
    }

    std::vector<bssl::UniquePtr<X509>> chain;
    while (auto* item = PEM_read_bio_X509(certificates.get(), nullptr, nullptr, nullptr)) {
        chain.emplace_back(item);
    }

    bssl::UniquePtr<EVP_PKEY> privateKey(PEM_read_bio_PrivateKey(privateBytes.get(), nullptr, nullptr, nullptr));

    // Successfully loaded CA roots, initially zero; TLS requires at least one.
    std::size_t rootCount = 0;

    while (auto* item = PEM_read_bio_X509(roots.get(), nullptr, nullptr, nullptr)) {
        bssl::UniquePtr<X509> root(item);
        if (X509_STORE_add_cert(store.get(), root.get()) != 1) {
            return Status::identity("Invalid trust root");
        }
        ++rootCount;
    }

    // Require a nonempty chain, at least one root, a parsed private key, and a matching leaf certificate.
    if (chain.empty() || rootCount == 0 || !privateKey || X509_check_private_key(chain[0].get(), privateKey.get()) != 1) {
        return Status::identity("Invalid certificate or matching private key");
    }

    // stack retains certificate references through up_ref; declare validation context afterward so destruction order is safe.
    bssl::UniquePtr<STACK_OF(X509)> intermediates(sk_X509_new_null());
    if (!intermediates) {
        return Status::internal("Cannot allocate certificate chain");
    }

    for (std::size_t i = 1; i < chain.size(); ++i) {
        X509_up_ref(chain[i].get());
        if (!sk_X509_push(intermediates.get(), chain[i].get())) {
            X509_free(chain[i].get());
            return Status::internal("Cannot retain certificate chain");
        }
    }

    // Owned verification context borrows leaf/intermediate chain, then restricts server purpose and expected IP SAN.
    bssl::UniquePtr<X509_STORE_CTX> context(X509_STORE_CTX_new());
    if (!context || X509_STORE_CTX_init(context.get(), store.get(), chain[0].get(), intermediates.get()) != 1 || X509_STORE_CTX_set_purpose(context.get(), X509_PURPOSE_SSL_SERVER) != 1 || X509_VERIFY_PARAM_set1_ip_asc(X509_STORE_CTX_get0_param(context.get()), endpoint.host.c_str()) != 1 || X509_verify_cert(context.get()) != 1) {
        return Status::identity("Local certificate does not authorize the advertised endpoint");
    }

    // Clear borrowed relationships before destroying the temporary chain.
    X509_STORE_CTX_cleanup(context.get());
    return {};
}
} // namespace

/// Converts protocol roles explicitly; unknown values return identity failure.
Result<Member::Role> Identity::role(proto::orbit::v1::Role value) {
    switch (value) {
    case proto::orbit::v1::ROLE_STAR:
        return Member::Role::Star;
    case proto::orbit::v1::ROLE_PLANET:
        return Member::Role::Planet;
    case proto::orbit::v1::ROLE_POLARIS:
        return Member::Role::Polaris;
    case proto::orbit::v1::ROLE_ASTROLABE:
        return Member::Role::Astrolabe;
    default:
        return Status::identity("Unknown infrastructure role");
    }
}

proto::orbit::v1::Role Identity::role(Member::Role value) {
    switch (value) {
    case Member::Role::Star:
        return proto::orbit::v1::ROLE_STAR;
    case Member::Role::Planet:
        return proto::orbit::v1::ROLE_PLANET;
    case Member::Role::Polaris:
        return proto::orbit::v1::ROLE_POLARIS;
    case Member::Role::Astrolabe:
        return proto::orbit::v1::ROLE_ASTROLABE;
    }
    return proto::orbit::v1::ROLE_UNSPECIFIED;
}

proto::orbit::v1::Member Identity::encode(const Member& member) {
    // The message owns its fields; prepare no caller-visible state until encoding completes.
    proto::orbit::v1::Member result;
    try {
        result.set_galaxy(member.galaxy);
        result.set_id(member.id);
        result.set_principal(member.principal.bytes.data(), member.principal.bytes.size());
        result.set_advertise(member.address.text());
        result.set_epoch(member.epoch.value);
        result.set_role(role(member.role));
        result.set_group(member.group);
    } catch (...) {
        // Generated setters mark presence before allocation. Clear each string without allocating so destruction sees consistent fields.
        result.clear_galaxy();
        result.clear_id();
        result.clear_principal();
        result.clear_advertise();
        result.clear_group();
        throw;
    }
    return result;
}

/// Converts generated Member to an owned value with format and boundary validation.
Result<Member> decodeMember(const proto::orbit::v1::Member& value) {

    // Borrows the opaque generated ID only during conversion; returned Member owns its copy.
    const auto& id = value.id();
    // Requires raw 32-byte deployment digest, rejecting hexadecimal or other encoding aliases.
    Principal principal;
    if (value.principal().size() != principal.bytes.size()) {
        return Status::identity("Invalid encoded member");
    }
    std::ranges::copy(value.principal(), principal.bytes.begin());
    // Canonical reachable numeric endpoint, without wildcard or zero port.
    auto address = Endpoint::parse(value.advertise());

    // Explicit role conversion must succeed before any Member is formed.
    const auto role = Identity::role(value.role());
    if (!Member::validId(id) || !address || address->text() != value.advertise() || !role) {
        return Status::identity("Invalid encoded member");
    }

    Member result{value.galaxy(), id, principal, *address, Member::Epoch{value.epoch()}, *role, value.group()};

    if (auto valid = result.validate(); !valid) {
        return std::unexpected(valid.error());
    }
    return result;
}

/// Loads fixed identity files and publishes only fully validated shared material.
Result<std::shared_ptr<Identity>> Identity::load(const std::filesystem::path& directory, const Endpoint& advertise) {

    // TLS and admission public key are validated before adding login material.
    auto loaded = loadServer(directory, advertise);
    if (!loaded) {
        return std::unexpected(loaded.error());
    }

    // Unpublished shared Identity; return only after login fields pass validation.
    auto result = *loaded;
    // Owned bounded login JSON; never include contents in logs or exception text.
    auto login = readIdentity(directory / "login.json");
    if (!login) {
        return std::unexpected(login.error());
    }

    // Accept exactly two unique string fields; errors contain neither unknown input nor passwords.

    std::unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)> document(yyjson_read(login->data(), login->size(), 0), yyjson_doc_free);
    // Borrows document's JSON root, possibly null on parse failure; check object type first.
    auto* object = document ? yyjson_doc_get_root(document.get()) : nullptr;
    if (!yyjson_is_obj(object) || yyjson_obj_size(object) != 2) {
        return Status::identity("login.json requires username and password");
    }

    // Initially false; each username/password field is accepted once and unknown keys are rejected.
    bool seenUser = false, seenPassword = false;
    // Traverses this login object without owning or extending JSON-document lifetime.
    yyjson_obj_iter iterator = yyjson_obj_iter_with(object);
    while (auto* field = yyjson_obj_iter_next(&iterator)) {
        // Borrows current field value; verify string type before copying bytes.
        auto* value = yyjson_obj_iter_get_val(field);
        // Borrows the full field-name bytes; embedded NUL must not truncate an invalid key.
        const std::string_view name(yyjson_get_str(field), yyjson_get_len(field));

        if (!yyjson_is_str(value)) {
            return Status::identity("Login fields must be strings");
        }

        if (name == "username" && !seenUser) {
            result->username_.assign(yyjson_get_str(value), yyjson_get_len(value));
            seenUser = true;
        }

        else if (name == "password" && !seenPassword) {
            result->password_.assign(yyjson_get_str(value), yyjson_get_len(value));
            seenPassword = true;
        } else {
            return Status::identity("Unknown or duplicate login field");
        }
    }

    if (!Member::validName(result->username_) || result->password_.empty() || result->password_.size() > 1024) {
        return Status::identity("Invalid login field bounds");
    }
    return result;
}

Result<std::shared_ptr<Identity>> Identity::loadServer(const std::filesystem::path& directory, const Endpoint& advertise) {

    // Read fixed files and validate local TLS before publishing Identity; invalid material exposes no partial object.
    auto ca = readIdentity(directory / "ca.pem");
    // Owned PEM chain with leaf first, used only for credential validation and loading.
    auto cert = readIdentity(directory / "cert.pem");
    // Owned PEM private key; never printed in diagnostics.
    auto key = readIdentity(directory / "key.pem");
    // Fixed 32-byte admission verification key, separate from TLS roots.
    auto authority = readIdentity(directory / "admission.pub");

    if (!ca || !cert || !key || !authority || authority->size() != 32) {
        return Status::identity("Missing or invalid identity materials");
    }

    if (auto valid = validateCertificate(*ca, *cert, *key, advertise); !valid) {
        return std::unexpected(valid.error());
    }

    // Create only after all material validates; publish to network threads only once Provider is ready.
    auto result = std::make_shared<Identity>();

    std::copy(authority->begin(), authority->end(), result->authority_.begin());

    result->provider_ = std::make_shared<grpc::experimental::InMemoryCertificateProvider>();
    // Owns key and certificate chain until transfer to the gRPC Provider, which retains their lifetime.
    std::vector<grpc::experimental::IdentityKeyOrSignerCertPair> pair{{*key, *cert}};
    if (!result->provider_->UpdateRoot(*ca).ok() || !result->provider_->UpdateIdentityKeyCertPair(std::move(pair)).ok() || !result->provider_->ValidateCredentials().ok()) {
        return Status::identity("Cannot prepare TLS certificate provider");
    }

    return result;
}

/// Returns the deployment SHA-256 digest from username, Galaxy, and canonical endpoint.
Principal Identity::principal(std::string_view cluster, std::string_view endpoint) const {

    // Hash input is username + NUL + cluster + NUL + endpoint.
    std::string input = username_;
    input += '\0';
    input += cluster;
    input += '\0';
    input += endpoint;
    // Digest initially zero; return after SHA256 fills it completely, without exposing temporary input storage.
    Principal result;

    SHA256(reinterpret_cast<const std::uint8_t*>(input.data()), input.size(), result.bytes.data());
    return result;
}

/// Verifies raw signed Admission bytes before decoding an owned Member.
Result<Member> Identity::verify(std::span<const std::uint8_t> value, std::span<const std::uint8_t> signature) const {

    if (value.size() > 1024 || signature.size() != 64) {
        return Status::identity("Invalid admission credential bounds");
    }

    // Signature input is protocol domain, terminating NUL, and raw value bytes, matching issuer encoding exactly.
    std::string input(admissionSignatureDomain);
    input += '\0';
    input.append(reinterpret_cast<const char*>(value.data()), value.size());

    if (ED25519_verify(reinterpret_cast<const std::uint8_t*>(input.data()), input.size(), signature.data(), authority_.data()) != 1) {
        return Status::identity("Invalid admission signature");
    }

    // Parse only the authenticated bytes, keeping the generated message private until conversion completes.
    proto::orbit::v1::Member member;
    try {
        if (!member.ParseFromArray(value.data(), static_cast<int>(value.size()))) {
            return Status::identity("Invalid signed member encoding");
        }
        return decodeMember(member);
    } catch (...) {
        // Parsing may unwind before flushing cached presence bits; restore strings and scalar defaults.
        member.clear_galaxy();
        member.clear_id();
        member.clear_principal();
        member.clear_advertise();
        member.clear_epoch();
        member.clear_role();
        member.clear_group();
        throw;
    }
}

/// Creates strict TLS 1.3 client credentials.
std::shared_ptr<grpc::ChannelCredentials> Identity::channelCredentials() const {

    // Verify server certificate and target hostname with fixed TLS 1.3, without loading a client certificate.
    grpc::experimental::TlsChannelCredentialsOptions options;
    options.set_root_certificate_provider(provider_);
    options.set_verify_server_certs(true);
    options.set_check_call_host(true);
    options.set_min_tls_version(TLS1_3);
    options.set_max_tls_version(TLS1_3);
    return grpc::experimental::TlsCredentials(options);
}

/// Creates strict TLS 1.3 server credentials without requesting client certificates.
std::shared_ptr<grpc::ServerCredentials> Identity::serverCredentials() const {

    // Provider-derived server options; failure returns null credentials for the listener boundary to handle.
    auto result = grpc::experimental::TlsServerCredentialsOptions::Create(provider_);
    if (!result.ok()) {
        return nullptr;
    }
    result->set_min_tls_version(TLS1_3);
    result->set_max_tls_version(TLS1_3);

    result->set_cert_request_type(GRPC_SSL_DONT_REQUEST_CLIENT_CERTIFICATE);
    return grpc::experimental::TlsServerCredentials(*result);
}

Result<std::shared_ptr<grpc::ServerCredentials>> Identity::external(const std::filesystem::path& directory) {

    auto certificate = readIdentity(directory / "cert.pem"); // Bounded complete public chain; server needs no client CA.
    auto key = readIdentity(directory / "key.pem");          // Private key enters this listener's provider only, without export or logging.
    if (!certificate || !key) {
        return Status::identity("Cannot read public TLS material");
    }
    bssl::UniquePtr<BIO> certificates(BIO_new_mem_buf(certificate->data(), static_cast<int>(certificate->size())));
    bssl::UniquePtr<BIO> keys(BIO_new_mem_buf(key->data(), static_cast<int>(key->size())));
    if (!certificates || !keys) {
        return Status::internal("Cannot prepare public TLS material");
    }
    bssl::UniquePtr<X509> leaf(PEM_read_bio_X509(certificates.get(), nullptr, nullptr, nullptr));
    bssl::UniquePtr<EVP_PKEY> privateKey(PEM_read_bio_PrivateKey(keys.get(), nullptr, nullptr, nullptr));
    if (!leaf || !privateKey || X509_check_private_key(leaf.get(), privateKey.get()) != 1 || X509_check_purpose(leaf.get(), X509_PURPOSE_SSL_SERVER, 0) != 1 || X509_cmp_current_time(X509_get0_notBefore(leaf.get())) >= 0 || X509_cmp_current_time(X509_get0_notAfter(leaf.get())) <= 0) {
        return Status::identity("Invalid public TLS certificate or private key");
    }

    // Validate every remaining PEM certificate so a valid leaf cannot hide corrupt/truncated intermediates; install no client trust roots.
    while (BIO_ctrl_pending(certificates.get()) != 0) {
        char* bytes{}; // Borrows unread BIO memory only before this parsing step.
        const auto length = BIO_get_mem_data(certificates.get(), &bytes);
        const auto tail = std::string_view(bytes, static_cast<std::size_t>(length));
        const auto first = tail.find_first_not_of(" \t\r\n"); // Permit whitespace between and after PEM blocks, but no arbitrary noncertificate text.
        if (first == std::string_view::npos) {
            break;
        }
        if (!tail.substr(first).starts_with("-----BEGIN CERTIFICATE-----")) {
            return Status::identity("Invalid public TLS certificate chain");
        }
        const bssl::UniquePtr<X509> intermediate(PEM_read_bio_X509(certificates.get(), nullptr, nullptr, nullptr));
        if (!intermediate) {
            return Status::identity("Invalid public TLS certificate chain");
        }
    }

    std::vector<grpc::experimental::IdentityKeyOrSignerCertPair> pair{{std::move(*key), std::move(*certificate)}}; // Transfers independent certificate-chain ownership to the provider.
    auto provider = std::make_shared<grpc::experimental::InMemoryCertificateProvider>();
    // Material is already validated. gRPC 1.84 ValidateCredentials requires initialized roots, while UpdateRoot forbids an empty set.
    // Public one-way TLS installs identity only, without fabricated unused client roots.
    if (!provider->UpdateIdentityKeyCertPair(std::move(pair)).ok()) {
        return Status::identity("Cannot load public TLS certificate chain");
    }
    auto options = grpc::experimental::TlsServerCredentialsOptions::Create(provider);
    if (!options.ok()) {
        return Status::identity("Cannot initialize public TLS");
    }
    options->set_min_tls_version(TLS1_3);
    options->set_max_tls_version(TLS1_3);
    options->set_cert_request_type(GRPC_SSL_DONT_REQUEST_CLIENT_CERTIFICATE);
    auto credentials = grpc::experimental::TlsServerCredentials(*options); // Credentials retain the provider independently of local variables.
    if (!credentials) {
        return Status::identity("Cannot initialize public TLS credentials");
    }
    return credentials;
}

/// Borrows the admission username under the Identity lifetime contract.
const std::string& Identity::username() const {
    return username_;
}

/// Borrows the admission password under the Identity lifetime contract.
const std::string& Identity::password() const {
    return password_;
}
} // namespace astra
