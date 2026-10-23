// Own public Pulsar test directories and member construction.
#include "pulsar_test.hpp"

namespace astra::test {
Directory::Directory() {
    auto name = (std::filesystem::current_path() / "pulsar-test-XXXXXX").string();

    const auto result = ::mkdtemp(name.data());
    if (!result) {
        throw std::runtime_error("Cannot create owned test directory");
    }
    path = result;
}

Directory::~Directory() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
}

Member member(unsigned index, Member::Role role) {
    Principal principal;
    principal.bytes[0] = static_cast<std::uint8_t>(index);
    return Member{"alpha", "node-" + std::to_string(index), principal, *Endpoint::parse("127.0.0.1:" + std::to_string(7400 + index)), {}, role, "default"};
}
} // namespace astra::test
