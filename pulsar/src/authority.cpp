// Coordinate membership authority and admitted role state for the Pulsar service.
#include "authority.hpp"

#include <openssl/crypto.h>
#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <yyjson.h>

#include <algorithm>
#include <bitset>
#include <fstream>
#include <stdexcept>

namespace astra {
namespace {
/// Reads bounded regular files; errors exclude paths and secret material.
std::string material(const std::filesystem::path& path) {

    if (!std::filesystem::is_regular_file(path) || std::filesystem::file_size(path) > 16384) {
        throw std::runtime_error("Invalid authority material");
    }

    std::ifstream input(path, std::ios::binary);
    // Read one extra byte to detect growth beyond the limit.
    std::string bytes(16385, '\0');
    input.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (input.bad() || (!input.eof() && input.fail()) || input.gcount() > 16384) {
        throw std::runtime_error("Cannot read authority material");
    }
    bytes.resize(static_cast<std::size_t>(input.gcount()));
    return bytes;
}

/// Returns a JSON string view, valid only while the document lives; nonstrings yield an empty view.
std::string_view text(yyjson_val* value) {
    return yyjson_is_str(value) ? std::string_view(yyjson_get_str(value), yyjson_get_len(value)) : std::string_view{};
}

/// Decodes fixed-width hexadecimal, accepting uppercase as Go account files do.
bool unhex(std::string_view value, std::span<std::uint8_t> output) {

    if (value.size() != output.size() * 2) {
        return false;
    }
    for (std::size_t i = 0; i < value.size(); ++i) {

        const auto c = value[i];
        const int digit = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10
                                                       : c >= 'A' && c <= 'F'   ? c - 'A' + 10
                                                                                : -1;
        if (digit < 0) {
            return false;
        }
        output[i / 2] = static_cast<std::uint8_t>((static_cast<unsigned>(output[i / 2]) << 4) | static_cast<unsigned>(digit));
    }
    return true;
}
} // namespace

Result<std::unique_ptr<Authority>> Authority::load(const std::filesystem::path& directory, const Endpoint& admission, const Endpoint& pulse) {

    try {

        auto identity = Identity::loadServer(directory, admission);
        // The same certificate must authorize both admission and time endpoints.
        auto pulseIdentity = Identity::loadServer(directory, pulse);
        if (!identity || !pulseIdentity) {
            return Status::identity("Invalid Pulsar TLS identity");
        }

        auto result = std::unique_ptr<Authority>(new Authority);
        result->identity_ = *identity;
        // Load the PKCS#8 Ed25519 seed and verify its derived public key against admission.pub.
        auto signing = material(directory / "admission.key");
        bssl::UniquePtr<BIO> input(BIO_new_mem_buf(signing.data(), static_cast<int>(signing.size())));
        bssl::UniquePtr<EVP_PKEY> key(input ? PEM_read_bio_PrivateKey(input.get(), nullptr, nullptr, nullptr) : nullptr);
        // Cleanse the private seed after deriving the public key.
        std::array<std::uint8_t, 32> seed{}, pub{};

        auto length = seed.size();
        if (!key || EVP_PKEY_id(key.get()) != EVP_PKEY_ED25519 || EVP_PKEY_get_raw_private_key(key.get(), seed.data(), &length) != 1 || length != seed.size()) {
            return Status::identity("Invalid Ed25519 signing key");
        }
        ED25519_keypair_from_seed(pub.data(), result->privateKey_.data(), seed.data());
        SHA256(pub.data(), pub.size(), result->keyId_.bytes.data());
        OPENSSL_cleanse(seed.data(), seed.size());
        OPENSSL_cleanse(signing.data(), signing.size());

        const auto publicKey = material(directory / "admission.pub");
        if (publicKey.size() != pub.size() || CRYPTO_memcmp(pub.data(), publicKey.data(), pub.size()) != 0) {
            return Status::identity("Admission key pair does not match");
        }

        // Reject unknown and duplicate fields to keep authorization identical across implementations.
        auto bytes = material(directory / "accounts.json");
        std::unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)> doc(yyjson_read(bytes.data(), bytes.size(), 0), yyjson_doc_free);

        auto* root = doc ? yyjson_doc_get_root(doc.get()) : nullptr;
        if (!yyjson_is_arr(root) || yyjson_arr_size(root) == 0 || yyjson_arr_size(root) > 64) {
            return Status::identity("Invalid account collection");
        }

        std::size_t index{}, maximum{};

        yyjson_val* entry{};
        yyjson_arr_foreach(root, index, maximum, entry) {

            if (!yyjson_is_obj(entry) || yyjson_obj_size(entry) != 4) {
                return Status::identity("Invalid account fields");
            }

            Account account;
            // Track exactly one occurrence of each required field.
            std::bitset<4> seen;

            auto fields = yyjson_obj_iter_with(entry);
            while (auto* field = yyjson_obj_iter_next(&fields)) {

                const auto name = text(field);

                auto* value = yyjson_obj_iter_get_val(field);

                std::size_t slot = 4;
                if (name == "username") {
                    slot = 0;
                    account.username = text(value);
                    if (!Member::validName(account.username)) {
                        return Status::identity("Invalid account name");
                    }
                } else if (name == "salt") {
                    slot = 1;
                    if (!unhex(text(value), account.salt)) {
                        return Status::identity("Invalid account salt");
                    }
                } else if (name == "hash") {
                    slot = 2;
                    if (!unhex(text(value), account.hash)) {
                        return Status::identity("Invalid account hash");
                    }
                } else if (name == "roles") {
                    slot = 3;
                    if (!yyjson_is_arr(value) || yyjson_arr_size(value) == 0 || yyjson_arr_size(value) > 4) {
                        return Status::identity("Invalid account roles");
                    }

                    std::size_t roleIndex{}, roleMaximum{};

                    yyjson_val* role{};
                    yyjson_arr_foreach(value, roleIndex, roleMaximum, role) {

                        // Independent internal role bits; zero is invalid, and Protobuf enum values are not reused.
                        const auto bit = text(role) == "star" ? 1U : text(role) == "planet"  ? 2U
                                                                 : text(role) == "polaris"   ? 4U
                                                                 : text(role) == "astrolabe" ? 8U
                                                                                             : 0U;
                        if (bit == 0 || (account.roles & bit) != 0) {
                            return Status::identity("Invalid account role");
                        }
                        account.roles |= bit;
                    }
                }
                if (slot == 4 || seen.test(slot)) {
                    return Status::identity("Unknown or duplicate account field");
                }
                seen.set(slot);
            }
            if (!seen.all() || std::ranges::any_of(result->accounts_, [&](const auto& item) { return item.username == account.username; })) {
                return Status::identity("Duplicate or incomplete account");
            }
            result->accounts_.push_back(std::move(account));
        }
        return result;
    } catch (...) {
        return Status::identity("Cannot load Pulsar authority");
    }
}

Authority::~Authority() {
    OPENSSL_cleanse(privateKey_.data(), privateKey_.size());
}

grpc::Status Authority::authenticate(grpc::ServerContext& context, const proto::orbit::v1::RegistrationRequest& request) const {

    if (context.IsCancelled()) {
        return grpc::Status(grpc::StatusCode::CANCELLED, "Registration cancelled");
    }
    if (!Member::validName(request.username()) || request.password().empty() || request.password().size() > 1024) {
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Invalid login");
    }
    if (!passwords_.try_acquire()) {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Authentication capacity reached");
    }

    /// Return the KDF permit on every exit; do not hold it across the registration lock.
    struct Permit {

        /// Borrow the acquired admission-work semaphore; guard destruction returns one slot.
        std::counting_semaphore<4>& slots;

        ~Permit() {
            slots.release();
        }
    } permit{passwords_};

    const auto found = std::ranges::find(accounts_, request.username(), &Account::username);
    // Unknown accounts perform the same KDF with a fixed-size dummy salt and digest.
    const Account dummy;

    const auto& account = found == accounts_.end() ? dummy : *found;
    // Cleanse the derived digest after comparison without retaining a plaintext password copy.
    std::array<std::uint8_t, 32> derived{};
    // KDF success is required even if the digest comparison happens to match.
    const auto ok = PKCS5_PBKDF2_HMAC(request.password().data(), request.password().size(), account.salt.data(), account.salt.size(), 600000, EVP_sha256(), derived.size(), derived.data());

    const auto matches = CRYPTO_memcmp(derived.data(), account.hash.data(), derived.size()) == 0;
    OPENSSL_cleanse(derived.data(), derived.size());
    if (context.IsCancelled()) {
        return grpc::Status(grpc::StatusCode::CANCELLED, "Registration cancelled");
    }
    if (ok != 1 || !matches || found == accounts_.end()) {
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Invalid login");
    }

    const auto role = request.role() == proto::orbit::v1::ROLE_STAR ? 1U : request.role() == proto::orbit::v1::ROLE_PLANET  ? 2U
                                                                       : request.role() == proto::orbit::v1::ROLE_POLARIS   ? 4U
                                                                       : request.role() == proto::orbit::v1::ROLE_ASTROLABE ? 8U
                                                                                                                            : 0U;
    return (account.roles & role) != 0 ? grpc::Status::OK : grpc::Status(grpc::StatusCode::PERMISSION_DENIED, "Role not authorized");
}

void Authority::sign(const proto::orbit::v1::Member& member, proto::orbit::v1::RegistrationResponse& response) const {

    try {
        if (!member.SerializeToString(response.mutable_admission())) {
            throw std::runtime_error("Admission encoding failed");
        }

        // Bind the protocol domain, separator and original admission bytes exactly as verification does.
        const auto input = std::string(admissionSignatureDomain) + '\0' + response.admission();
        std::string signature(64, '\0');
        if (ED25519_sign(reinterpret_cast<std::uint8_t*>(signature.data()), reinterpret_cast<const std::uint8_t*>(input.data()), input.size(), privateKey_.data()) != 1) {
            throw std::runtime_error("Admission signing failed");
        }
        response.set_signature(std::move(signature));
    } catch (...) {
        // Generated setters mark presence before allocating; clear each owned field before destruction.
        response.clear_admission();
        response.clear_signature();
        throw;
    }
}

const Identity& Authority::identity() const {
    return *identity_;
}

/// Returns the signing public key's SHA-256 digest as owned hexadecimal text.
std::string Authority::keyId() const {
    return keyId_.text();
}
} // namespace astra
