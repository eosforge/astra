// Trigger selected language-contract paths so the harness can verify their exact diagnostics and termination.
#include <string_view>
#include <vector>

// Negative cases run in isolated Linux child processes; driver disables core dumps and checks termination signal plus diagnostic.
int main(int argc, char** argv) {

    if (argc != 2) {
        return 2;
    }

    // Borrows the sole mode argument selecting valid, contract-failure, or STL-bounds child behavior.
    const std::string_view mode(argv[1]);
    // Seven in valid mode, otherwise zero, for deterministic contract failure.
    const auto value = mode == "valid" ? 7 : 0;
    if (mode == "valid" || mode == "contract") {
        contract_assert(value == 7);
        return 0;
    }
    if (mode == "stl") {
        // One-element vector; argc two intentionally indexes out of bounds to check STL hardening.
        const std::vector<int> values{7};
        return values[static_cast<std::size_t>(argc)];
    }
    return 2;
}
