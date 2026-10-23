// Initialize the owning Star process and then transfer admission, control and shutdown to its runtime.
#include "memory.hpp"
#include "topology.hpp"
#include <astra/runtime.hpp>

#include <iostream>

/// Configure process-local resources before creating runtime threads, then run the fixed Star role with the supplied arguments.
/// Return zero after orderly exit, one for startup/runtime failure, or two for invalid command-line input.
int main(int argc, char** argv) {

    if (!astra::memory::prepare()) {
        std::cerr << "Cannot configure allocator arenas\n";
        return 1;
    }

    return astra::runNode(argc, argv, astra::Member::Role::Star, astra::makeStar);
}
